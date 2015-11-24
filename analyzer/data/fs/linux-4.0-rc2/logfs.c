/*
 * fs/logfs/compr.c	- compression routines
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 */
#include "logfs.h"
#include <linux/vmalloc.h>
#include <linux/zlib.h>
#include "../../inc/__fss.h"

#define COMPR_LEVEL 3

static DEFINE_MUTEX(compr_mutex);
static struct z_stream_s stream;

int logfs_compress(void *in, void *out, size_t inlen, size_t outlen)
{
	int err, ret;

	ret = -EIO;
	mutex_lock(&compr_mutex);
	err = zlib_deflateInit(&stream, COMPR_LEVEL);
	if (err != Z_OK)
		goto error;

	stream.next_in = in;
	stream.avail_in = inlen;
	stream.total_in = 0;
	stream.next_out = out;
	stream.avail_out = outlen;
	stream.total_out = 0;

	err = zlib_deflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END)
		goto error;

	err = zlib_deflateEnd(&stream);
	if (err != Z_OK)
		goto error;

	if (stream.total_out >= stream.total_in)
		goto error;

	ret = stream.total_out;
error:
	mutex_unlock(&compr_mutex);
	return ret;
}

int logfs_uncompress(void *in, void *out, size_t inlen, size_t outlen)
{
	int err, ret;

	ret = -EIO;
	mutex_lock(&compr_mutex);
	err = zlib_inflateInit(&stream);
	if (err != Z_OK)
		goto error;

	stream.next_in = in;
	stream.avail_in = inlen;
	stream.total_in = 0;
	stream.next_out = out;
	stream.avail_out = outlen;
	stream.total_out = 0;

	err = zlib_inflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END)
		goto error;

	err = zlib_inflateEnd(&stream);
	if (err != Z_OK)
		goto error;

	ret = 0;
error:
	mutex_unlock(&compr_mutex);
	return ret;
}

int __init logfs_compr_init(void)
{
	size_t size = max(zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL),
			zlib_inflate_workspacesize());
	stream.workspace = vmalloc(size);
	if (!stream.workspace)
		return -ENOMEM;
	return 0;
}

void logfs_compr_exit(void)
{
	vfree(stream.workspace);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/compr.c */
/************************************************************/
/*
 * fs/logfs/dir.c	- directory-related code
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 */
// #include "logfs.h"
#include <linux/slab.h>
#include "../../inc/__fss.h"

/*
 * Atomic dir operations
 *
 * Directory operations are by default not atomic.  Dentries and Inodes are
 * created/removed/altered in separate operations.  Therefore we need to do
 * a small amount of journaling.
 *
 * Create, link, mkdir, mknod and symlink all share the same function to do
 * the work: __logfs_create.  This function works in two atomic steps:
 * 1. allocate inode (remember in journal)
 * 2. allocate dentry (clear journal)
 *
 * As we can only get interrupted between the two, when the inode we just
 * created is simply stored in the anchor.  On next mount, if we were
 * interrupted, we delete the inode.  From a users point of view the
 * operation never happened.
 *
 * Unlink and rmdir also share the same function: unlink.  Again, this
 * function works in two atomic steps
 * 1. remove dentry (remember inode in journal)
 * 2. unlink inode (clear journal)
 *
 * And again, on the next mount, if we were interrupted, we delete the inode.
 * From a users point of view the operation succeeded.
 *
 * Rename is the real pain to deal with, harder than all the other methods
 * combined.  Depending on the circumstances we can run into three cases.
 * A "target rename" where the target dentry already existed, a "local
 * rename" where both parent directories are identical or a "cross-directory
 * rename" in the remaining case.
 *
 * Local rename is atomic, as the old dentry is simply rewritten with a new
 * name.
 *
 * Cross-directory rename works in two steps, similar to __logfs_create and
 * logfs_unlink:
 * 1. Write new dentry (remember old dentry in journal)
 * 2. Remove old dentry (clear journal)
 *
 * Here we remember a dentry instead of an inode.  On next mount, if we were
 * interrupted, we delete the dentry.  From a users point of view, the
 * operation succeeded.
 *
 * Target rename works in three atomic steps:
 * 1. Attach old inode to new dentry (remember old dentry and new inode)
 * 2. Remove old dentry (still remember the new inode)
 * 3. Remove victim inode
 *
 * Here we remember both an inode an a dentry.  If we get interrupted
 * between steps 1 and 2, we delete both the dentry and the inode.  If
 * we get interrupted between steps 2 and 3, we delete just the inode.
 * In either case, the remaining objects are deleted on next mount.  From
 * a users point of view, the operation succeeded.
 */

static int write_dir(struct inode *dir, struct logfs_disk_dentry *dd,
		loff_t pos)
{
	return logfs_inode_write(dir, dd, sizeof(*dd), pos, WF_LOCK, NULL);
}

static int write_inode(struct inode *inode)
{
	return __logfs_write_inode(inode, NULL, WF_LOCK);
}

static s64 dir_seek_data(struct inode *inode, s64 pos)
{
	s64 new_pos = logfs_seek_data(inode, pos);

	return max(pos, new_pos - 1);
}

static int beyond_eof(struct inode *inode, loff_t bix)
{
	loff_t pos = bix << inode->i_sb->s_blocksize_bits;
	return pos >= i_size_read(inode);
}

/*
 * Prime value was chosen to be roughly 256 + 26.  r5 hash uses 11,
 * so short names (len <= 9) don't even occupy the complete 32bit name
 * space.  A prime >256 ensures short names quickly spread the 32bit
 * name space.  Add about 26 for the estimated amount of information
 * of each character and pick a prime nearby, preferably a bit-sparse
 * one.
 */
static u32 hash_32_dir_c(const char *s, int len, u32 seed)
{
	u32 hash = seed;
	int i;

	for (i = 0; i < len; i++)
		hash = hash * 293 + s[i];
	return hash;
}

/*
 * We have to satisfy several conflicting requirements here.  Small
 * directories should stay fairly compact and not require too many
 * indirect blocks.  The number of possible locations for a given hash
 * should be small to make lookup() fast.  And we should try hard not
 * to overflow the 32bit name space or nfs and 32bit host systems will
 * be unhappy.
 *
 * So we use the following scheme.  First we reduce the hash to 0..15
 * and try a direct block.  If that is occupied we reduce the hash to
 * 16..255 and try an indirect block.  Same for 2x and 3x indirect
 * blocks.  Lastly we reduce the hash to 0x800_0000 .. 0xffff_ffff,
 * but use buckets containing eight entries instead of a single one.
 *
 * Using 16 entries should allow for a reasonable amount of hash
 * collisions, so the 32bit name space can be packed fairly tight
 * before overflowing.  Oh and currently we don't overflow but return
 * and error.
 *
 * How likely are collisions?  Doing the appropriate math is beyond me
 * and the Bronstein textbook.  But running a test program to brute
 * force collisions for a couple of days showed that on average the
 * first collision occurs after 598M entries, with 290M being the
 * smallest result.  Obviously 21 entries could already cause a
 * collision if all entries are carefully chosen.
 */
static pgoff_t hash_index(u32 hash, int round)
{
	u32 i0_blocks = I0_BLOCKS;
	u32 i1_blocks = I1_BLOCKS;
	u32 i2_blocks = I2_BLOCKS;
	u32 i3_blocks = I3_BLOCKS;

	switch (round) {
	case 0:
		return hash % i0_blocks;
	case 1:
		return i0_blocks + hash % (i1_blocks - i0_blocks);
	case 2:
		return i1_blocks + hash % (i2_blocks - i1_blocks);
	case 3:
		return i2_blocks + hash % (i3_blocks - i2_blocks);
	case 4 ... 19:
		return i3_blocks + 16 * (hash % (((1<<31) - i3_blocks) / 16))
			+ round - 4;
	}
	BUG();
}

static struct page *logfs_get_dd_page(struct inode *dir, struct dentry *dentry)
{
	struct qstr *name = &dentry->d_name;
	struct page *page;
	struct logfs_disk_dentry *dd;
	u32 hash = hash_32_dir_c(name->name, name->len, 0);
	pgoff_t index;
	int round;

	if (name->len > LOGFS_MAX_NAMELEN)
		return ERR_PTR(-ENAMETOOLONG);

	for (round = 0; round < 20; round++) {
		index = hash_index(hash, round);

		if (beyond_eof(dir, index))
			return NULL;
		if (!logfs_exist_block(dir, index))
			continue;
		page = read_cache_page(dir->i_mapping, index,
				(filler_t *)logfs_readpage, NULL);
		if (IS_ERR(page))
			return page;
		dd = kmap_atomic(page);
		BUG_ON(dd->namelen == 0);

		if (name->len != be16_to_cpu(dd->namelen) ||
				memcmp(name->name, dd->name, name->len)) {
			kunmap_atomic(dd);
			page_cache_release(page);
			continue;
		}

		kunmap_atomic(dd);
		return page;
	}
	return NULL;
}

static int logfs_remove_inode(struct inode *inode)
{
	int ret;

	drop_nlink(inode);
	ret = write_inode(inode);
	LOGFS_BUG_ON(ret, inode->i_sb);
	return ret;
}

static void abort_transaction(struct inode *inode, struct logfs_transaction *ta)
{
	if (logfs_inode(inode)->li_block)
		logfs_inode(inode)->li_block->ta = NULL;
	kfree(ta);
}

static int logfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct logfs_super *super = logfs_super(dir->i_sb);
	struct inode *inode = dentry->d_inode;
	struct logfs_transaction *ta;
	struct page *page;
	pgoff_t index;
	int ret;

	ta = kzalloc(sizeof(*ta), GFP_KERNEL);
	if (!ta)
		return -ENOMEM;

	ta->state = UNLINK_1;
	ta->ino = inode->i_ino;

	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;

	page = logfs_get_dd_page(dir, dentry);
	if (!page) {
		kfree(ta);
		return -ENOENT;
	}
	if (IS_ERR(page)) {
		kfree(ta);
		return PTR_ERR(page);
	}
	index = page->index;
	page_cache_release(page);

	mutex_lock(&super->s_dirop_mutex);
	logfs_add_transaction(dir, ta);

	ret = logfs_delete(dir, index, NULL);
	if (!ret)
		ret = write_inode(dir);

	if (ret) {
		abort_transaction(dir, ta);
		printk(KERN_ERR"LOGFS: unable to delete inode\n");
		goto out;
	}

	ta->state = UNLINK_2;
	logfs_add_transaction(inode, ta);
	ret = logfs_remove_inode(inode);
out:
	mutex_unlock(&super->s_dirop_mutex);
	return ret;
}

static inline int logfs_empty_dir(struct inode *dir)
{
	u64 data;

	data = logfs_seek_data(dir, 0) << dir->i_sb->s_blocksize_bits;
	return data >= i_size_read(dir);
}

static int logfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	if (!logfs_empty_dir(inode))
		return -ENOTEMPTY;

	return logfs_unlink(dir, dentry);
}

/* FIXME: readdir currently has it's own dir_walk code.  I don't see a good
 * way to combine the two copies */
static int logfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	loff_t pos;
	struct page *page;
	struct logfs_disk_dentry *dd;

	if (ctx->pos < 0)
		return -EINVAL;

	if (!dir_emit_dots(file, ctx))
		return 0;

	pos = ctx->pos - 2;
	BUG_ON(pos < 0);
	for (;; pos++, ctx->pos++) {
		bool full;
		if (beyond_eof(dir, pos))
			break;
		if (!logfs_exist_block(dir, pos)) {
			/* deleted dentry */
			pos = dir_seek_data(dir, pos);
			continue;
		}
		page = read_cache_page(dir->i_mapping, pos,
				(filler_t *)logfs_readpage, NULL);
		if (IS_ERR(page))
			return PTR_ERR(page);
		dd = kmap(page);
		BUG_ON(dd->namelen == 0);

		full = !dir_emit(ctx, (char *)dd->name,
				be16_to_cpu(dd->namelen),
				be64_to_cpu(dd->ino), dd->type);
		kunmap(page);
		page_cache_release(page);
		if (full)
			break;
	}
	return 0;
}

static void logfs_set_name(struct logfs_disk_dentry *dd, struct qstr *name)
{
	dd->namelen = cpu_to_be16(name->len);
	memcpy(dd->name, name->name, name->len);
}

static struct dentry *logfs_lookup(struct inode *dir, struct dentry *dentry,
		unsigned int flags)
{
	struct page *page;
	struct logfs_disk_dentry *dd;
	pgoff_t index;
	u64 ino = 0;
	struct inode *inode;

	page = logfs_get_dd_page(dir, dentry);
	if (IS_ERR(page))
		return ERR_CAST(page);
	if (!page) {
		d_add(dentry, NULL);
		return NULL;
	}
	index = page->index;
	dd = kmap_atomic(page);
	ino = be64_to_cpu(dd->ino);
	kunmap_atomic(dd);
	page_cache_release(page);

	inode = logfs_iget(dir->i_sb, ino);
	if (IS_ERR(inode))
		printk(KERN_ERR"LogFS: Cannot read inode #%llx for dentry (%lx, %lx)n",
				ino, dir->i_ino, index);
	return d_splice_alias(inode, dentry);
}

static void grow_dir(struct inode *dir, loff_t index)
{
	index = (index + 1) << dir->i_sb->s_blocksize_bits;
	if (i_size_read(dir) < index)
		i_size_write(dir, index);
}

static int logfs_write_dir(struct inode *dir, struct dentry *dentry,
		struct inode *inode)
{
	struct page *page;
	struct logfs_disk_dentry *dd;
	u32 hash = hash_32_dir_c(dentry->d_name.name, dentry->d_name.len, 0);
	pgoff_t index;
	int round, err;

	for (round = 0; round < 20; round++) {
		index = hash_index(hash, round);

		if (logfs_exist_block(dir, index))
			continue;
		page = find_or_create_page(dir->i_mapping, index, GFP_KERNEL);
		if (!page)
			return -ENOMEM;

		dd = kmap_atomic(page);
		memset(dd, 0, sizeof(*dd));
		dd->ino = cpu_to_be64(inode->i_ino);
		dd->type = logfs_type(inode);
		logfs_set_name(dd, &dentry->d_name);
		kunmap_atomic(dd);

		err = logfs_write_buf(dir, page, WF_LOCK);
		unlock_page(page);
		page_cache_release(page);
		if (!err)
			grow_dir(dir, index);
		return err;
	}
	/* FIXME: Is there a better return value?  In most cases neither
	 * the filesystem nor the directory are full.  But we have had
	 * too many collisions for this particular hash and no fallback.
	 */
	return -ENOSPC;
}

static int __logfs_create(struct inode *dir, struct dentry *dentry,
		struct inode *inode, const char *dest, long destlen)
{
	struct logfs_super *super = logfs_super(dir->i_sb);
	struct logfs_inode *li = logfs_inode(inode);
	struct logfs_transaction *ta;
	int ret;

	ta = kzalloc(sizeof(*ta), GFP_KERNEL);
	if (!ta) {
		drop_nlink(inode);
		iput(inode);
		return -ENOMEM;
	}

	ta->state = CREATE_1;
	ta->ino = inode->i_ino;
	mutex_lock(&super->s_dirop_mutex);
	logfs_add_transaction(inode, ta);

	if (dest) {
		/* symlink */
		ret = logfs_inode_write(inode, dest, destlen, 0, WF_LOCK, NULL);
		if (!ret)
			ret = write_inode(inode);
	} else {
		/* creat/mkdir/mknod */
		ret = write_inode(inode);
	}
	if (ret) {
		abort_transaction(inode, ta);
		li->li_flags |= LOGFS_IF_STILLBORN;
		/* FIXME: truncate symlink */
		drop_nlink(inode);
		iput(inode);
		goto out;
	}

	ta->state = CREATE_2;
	logfs_add_transaction(dir, ta);
	ret = logfs_write_dir(dir, dentry, inode);
	/* sync directory */
	if (!ret)
		ret = write_inode(dir);

	if (ret) {
		logfs_del_transaction(dir, ta);
		ta->state = CREATE_2;
		logfs_add_transaction(inode, ta);
		logfs_remove_inode(inode);
		iput(inode);
		goto out;
	}
	d_instantiate(dentry, inode);
out:
	mutex_unlock(&super->s_dirop_mutex);
	return ret;
}

static int logfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;

	/*
	 * FIXME: why do we have to fill in S_IFDIR, while the mode is
	 * correct for mknod, creat, etc.?  Smells like the vfs *should*
	 * do it for us but for some reason fails to do so.
	 */
	inode = logfs_new_inode(dir, S_IFDIR | mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &logfs_dir_iops;
	inode->i_fop = &logfs_dir_fops;

	return __logfs_create(dir, dentry, inode, NULL, 0);
}

static int logfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	struct inode *inode;

	inode = logfs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &logfs_reg_iops;
	inode->i_fop = &logfs_reg_fops;
	inode->i_mapping->a_ops = &logfs_reg_aops;

	return __logfs_create(dir, dentry, inode, NULL, 0);
}

static int logfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		dev_t rdev)
{
	struct inode *inode;

	if (dentry->d_name.len > LOGFS_MAX_NAMELEN)
		return -ENAMETOOLONG;

	inode = logfs_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	init_special_inode(inode, mode, rdev);

	return __logfs_create(dir, dentry, inode, NULL, 0);
}

static int logfs_symlink(struct inode *dir, struct dentry *dentry,
		const char *target)
{
	struct inode *inode;
	size_t destlen = strlen(target) + 1;

	if (destlen > dir->i_sb->s_blocksize)
		return -ENAMETOOLONG;

	inode = logfs_new_inode(dir, S_IFLNK | 0777);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	inode->i_op = &logfs_symlink_iops;
	inode->i_mapping->a_ops = &logfs_reg_aops;

	return __logfs_create(dir, dentry, inode, target, destlen);
}

static int logfs_link(struct dentry *old_dentry, struct inode *dir,
		struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;

	inode->i_ctime = dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	ihold(inode);
	inc_nlink(inode);
	mark_inode_dirty_sync(inode);

	return __logfs_create(dir, dentry, inode, NULL, 0);
}

static int logfs_get_dd(struct inode *dir, struct dentry *dentry,
		struct logfs_disk_dentry *dd, loff_t *pos)
{
	struct page *page;
	void *map;

	page = logfs_get_dd_page(dir, dentry);
	if (IS_ERR(page))
		return PTR_ERR(page);
	*pos = page->index;
	map = kmap_atomic(page);
	memcpy(dd, map, sizeof(*dd));
	kunmap_atomic(map);
	page_cache_release(page);
	return 0;
}

static int logfs_delete_dd(struct inode *dir, loff_t pos)
{
	/*
	 * Getting called with pos somewhere beyond eof is either a goofup
	 * within this file or means someone maliciously edited the
	 * (crc-protected) journal.
	 */
	BUG_ON(beyond_eof(dir, pos));
	dir->i_ctime = dir->i_mtime = CURRENT_TIME;
	log_dir(" Delete dentry (%lx, %llx)\n", dir->i_ino, pos);
	return logfs_delete(dir, pos, NULL);
}

/*
 * Cross-directory rename, target does not exist.  Just a little nasty.
 * Create a new dentry in the target dir, then remove the old dentry,
 * all the while taking care to remember our operation in the journal.
 */
static int logfs_rename_cross(struct inode *old_dir, struct dentry *old_dentry,
			      struct inode *new_dir, struct dentry *new_dentry)
{
	struct logfs_super *super = logfs_super(old_dir->i_sb);
	struct logfs_disk_dentry dd;
	struct logfs_transaction *ta;
	loff_t pos;
	int err;

	/* 1. locate source dd */
	err = logfs_get_dd(old_dir, old_dentry, &dd, &pos);
	if (err)
		return err;

	ta = kzalloc(sizeof(*ta), GFP_KERNEL);
	if (!ta)
		return -ENOMEM;

	ta->state = CROSS_RENAME_1;
	ta->dir = old_dir->i_ino;
	ta->pos = pos;

	/* 2. write target dd */
	mutex_lock(&super->s_dirop_mutex);
	logfs_add_transaction(new_dir, ta);
	err = logfs_write_dir(new_dir, new_dentry, old_dentry->d_inode);
	if (!err)
		err = write_inode(new_dir);

	if (err) {
		super->s_rename_dir = 0;
		super->s_rename_pos = 0;
		abort_transaction(new_dir, ta);
		goto out;
	}

	/* 3. remove source dd */
	ta->state = CROSS_RENAME_2;
	logfs_add_transaction(old_dir, ta);
	err = logfs_delete_dd(old_dir, pos);
	if (!err)
		err = write_inode(old_dir);
	LOGFS_BUG_ON(err, old_dir->i_sb);
out:
	mutex_unlock(&super->s_dirop_mutex);
	return err;
}

static int logfs_replace_inode(struct inode *dir, struct dentry *dentry,
		struct logfs_disk_dentry *dd, struct inode *inode)
{
	loff_t pos;
	int err;

	err = logfs_get_dd(dir, dentry, dd, &pos);
	if (err)
		return err;
	dd->ino = cpu_to_be64(inode->i_ino);
	dd->type = logfs_type(inode);

	err = write_dir(dir, dd, pos);
	if (err)
		return err;
	log_dir("Replace dentry (%lx, %llx) %s -> %llx\n", dir->i_ino, pos,
			dd->name, be64_to_cpu(dd->ino));
	return write_inode(dir);
}

/* Target dentry exists - the worst case.  We need to attach the source
 * inode to the target dentry, then remove the orphaned target inode and
 * source dentry.
 */
static int logfs_rename_target(struct inode *old_dir, struct dentry *old_dentry,
			       struct inode *new_dir, struct dentry *new_dentry)
{
	struct logfs_super *super = logfs_super(old_dir->i_sb);
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	int isdir = S_ISDIR(old_inode->i_mode);
	struct logfs_disk_dentry dd;
	struct logfs_transaction *ta;
	loff_t pos;
	int err;

	BUG_ON(isdir != S_ISDIR(new_inode->i_mode));
	if (isdir) {
		if (!logfs_empty_dir(new_inode))
			return -ENOTEMPTY;
	}

	/* 1. locate source dd */
	err = logfs_get_dd(old_dir, old_dentry, &dd, &pos);
	if (err)
		return err;

	ta = kzalloc(sizeof(*ta), GFP_KERNEL);
	if (!ta)
		return -ENOMEM;

	ta->state = TARGET_RENAME_1;
	ta->dir = old_dir->i_ino;
	ta->pos = pos;
	ta->ino = new_inode->i_ino;

	/* 2. attach source inode to target dd */
	mutex_lock(&super->s_dirop_mutex);
	logfs_add_transaction(new_dir, ta);
	err = logfs_replace_inode(new_dir, new_dentry, &dd, old_inode);
	if (err) {
		super->s_rename_dir = 0;
		super->s_rename_pos = 0;
		super->s_victim_ino = 0;
		abort_transaction(new_dir, ta);
		goto out;
	}

	/* 3. remove source dd */
	ta->state = TARGET_RENAME_2;
	logfs_add_transaction(old_dir, ta);
	err = logfs_delete_dd(old_dir, pos);
	if (!err)
		err = write_inode(old_dir);
	LOGFS_BUG_ON(err, old_dir->i_sb);

	/* 4. remove target inode */
	ta->state = TARGET_RENAME_3;
	logfs_add_transaction(new_inode, ta);
	err = logfs_remove_inode(new_inode);

out:
	mutex_unlock(&super->s_dirop_mutex);
	return err;
}

static int logfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry)
{
	if (new_dentry->d_inode)
		return logfs_rename_target(old_dir, old_dentry,
					   new_dir, new_dentry);
	return logfs_rename_cross(old_dir, old_dentry, new_dir, new_dentry);
}

/* No locking done here, as this is called before .get_sb() returns. */
int logfs_replay_journal(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct inode *inode;
	u64 ino, pos;
	int err;

	if (super->s_victim_ino) {
		/* delete victim inode */
		ino = super->s_victim_ino;
		printk(KERN_INFO"LogFS: delete unmapped inode #%llx\n", ino);
		inode = logfs_iget(sb, ino);
		if (IS_ERR(inode))
			goto fail;

		LOGFS_BUG_ON(i_size_read(inode) > 0, sb);
		super->s_victim_ino = 0;
		err = logfs_remove_inode(inode);
		iput(inode);
		if (err) {
			super->s_victim_ino = ino;
			goto fail;
		}
	}
	if (super->s_rename_dir) {
		/* delete old dd from rename */
		ino = super->s_rename_dir;
		pos = super->s_rename_pos;
		printk(KERN_INFO"LogFS: delete unbacked dentry (%llx, %llx)\n",
				ino, pos);
		inode = logfs_iget(sb, ino);
		if (IS_ERR(inode))
			goto fail;

		super->s_rename_dir = 0;
		super->s_rename_pos = 0;
		err = logfs_delete_dd(inode, pos);
		iput(inode);
		if (err) {
			super->s_rename_dir = ino;
			super->s_rename_pos = pos;
			goto fail;
		}
	}
	return 0;
fail:
	LOGFS_BUG(sb);
	return -EIO;
}

const struct inode_operations logfs_symlink_iops = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
};

const struct inode_operations logfs_dir_iops = {
	.create		= logfs_create,
	.link		= logfs_link,
	.lookup		= logfs_lookup,
	.mkdir		= logfs_mkdir,
	.mknod		= logfs_mknod,
	.rename		= logfs_rename,
	.rmdir		= logfs_rmdir,
	.symlink	= logfs_symlink,
	.unlink		= logfs_unlink,
};
const struct file_operations logfs_dir_fops = {
	.fsync		= logfs_fsync,
	.unlocked_ioctl	= logfs_ioctl,
	.iterate	= logfs_readdir,
	.read		= generic_read_dir,
	.llseek		= default_llseek,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/dir.c */
/************************************************************/
/*
 * fs/logfs/file.c	- prepare_write, commit_write and friends
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 */
// #include "logfs.h"
#include <linux/sched.h>
#include <linux/writeback.h>
#include "../../inc/__fss.h"

static int logfs_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct page *page;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	if ((len == PAGE_CACHE_SIZE) || PageUptodate(page))
		return 0;
	if ((pos & PAGE_CACHE_MASK) >= i_size_read(inode)) {
		unsigned start = pos & (PAGE_CACHE_SIZE - 1);
		unsigned end = start + len;

		/* Reading beyond i_size is simple: memset to zero */
		zero_user_segments(page, 0, start, end, PAGE_CACHE_SIZE);
		return 0;
	}
	return logfs_readpage_nolock(page);
}

static int logfs_write_end(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned copied, struct page *page,
		void *fsdata)
{
	struct inode *inode = mapping->host;
	pgoff_t index = page->index;
	unsigned start = pos & (PAGE_CACHE_SIZE - 1);
	unsigned end = start + copied;
	int ret = 0;

	BUG_ON(PAGE_CACHE_SIZE != inode->i_sb->s_blocksize);
	BUG_ON(page->index > I3_BLOCKS);

	if (copied < len) {
		/*
		 * Short write of a non-initialized paged.  Just tell userspace
		 * to retry the entire page.
		 */
		if (!PageUptodate(page)) {
			copied = 0;
			goto out;
		}
	}
	if (copied == 0)
		goto out; /* FIXME: do we need to update inode? */

	if (i_size_read(inode) < (index << PAGE_CACHE_SHIFT) + end) {
		i_size_write(inode, (index << PAGE_CACHE_SHIFT) + end);
		mark_inode_dirty_sync(inode);
	}

	SetPageUptodate(page);
	if (!PageDirty(page)) {
		if (!get_page_reserve(inode, page))
			__set_page_dirty_nobuffers(page);
		else
			ret = logfs_write_buf(inode, page, WF_LOCK);
	}
out:
	unlock_page(page);
	page_cache_release(page);
	return ret ? ret : copied;
}

int logfs_readpage(struct file *file, struct page *page)
{
	int ret;

	ret = logfs_readpage_nolock(page);
	unlock_page(page);
	return ret;
}

/* Clear the page's dirty flag in the radix tree. */
/* TODO: mucking with PageWriteback is silly.  Add a generic function to clear
 * the dirty bit from the radix tree for filesystems that don't have to wait
 * for page writeback to finish (i.e. any compressing filesystem).
 */
static void clear_radix_tree_dirty(struct page *page)
{
	BUG_ON(PagePrivate(page) || page->private);
	set_page_writeback(page);
	end_page_writeback(page);
}

static int __logfs_writepage(struct page *page)
{
	struct inode *inode = page->mapping->host;
	int err;

	err = logfs_write_buf(inode, page, WF_LOCK);
	if (err)
		set_page_dirty(page);
	else
		clear_radix_tree_dirty(page);
	unlock_page(page);
	return err;
}

static int logfs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	loff_t i_size = i_size_read(inode);
	pgoff_t end_index = i_size >> PAGE_CACHE_SHIFT;
	unsigned offset;
	u64 bix;
	level_t level;

	log_file("logfs_writepage(%lx, %lx, %p)\n", inode->i_ino, page->index,
			page);

	logfs_unpack_index(page->index, &bix, &level);

	/* Indirect blocks are never truncated */
	if (level != 0)
		return __logfs_writepage(page);

	/*
	 * TODO: everything below is a near-verbatim copy of nobh_writepage().
	 * The relevant bits should be factored out after logfs is merged.
	 */

	/* Is the page fully inside i_size? */
	if (bix < end_index)
		return __logfs_writepage(page);

	 /* Is the page fully outside i_size? (truncate in progress) */
	offset = i_size & (PAGE_CACHE_SIZE-1);
	if (bix > end_index || offset == 0) {
		unlock_page(page);
		return 0; /* don't care */
	}

	/*
	 * The page straddles i_size.  It must be zeroed out on each and every
	 * writepage invokation because it may be mmapped.  "A file is mapped
	 * in multiples of the page size.  For a file that is not a multiple of
	 * the  page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	zero_user_segment(page, offset, PAGE_CACHE_SIZE);
	return __logfs_writepage(page);
}

static void logfs_invalidatepage(struct page *page, unsigned int offset,
				 unsigned int length)
{
	struct logfs_block *block = logfs_block(page);

	if (block->reserved_bytes) {
		struct super_block *sb = page->mapping->host->i_sb;
		struct logfs_super *super = logfs_super(sb);

		super->s_dirty_pages -= block->reserved_bytes;
		block->ops->free_block(sb, block);
		BUG_ON(bitmap_weight(block->alias_map, LOGFS_BLOCK_FACTOR));
	} else
		move_page_to_btree(page);
	BUG_ON(PagePrivate(page) || page->private);
}

static int logfs_releasepage(struct page *page, gfp_t only_xfs_uses_this)
{
	return 0; /* None of these are easy to release */
}


long logfs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(file);
	struct logfs_inode *li = logfs_inode(inode);
	unsigned int oldflags, flags;
	int err;

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		flags = li->li_flags & LOGFS_FL_USER_VISIBLE;
		return put_user(flags, (int __user *)arg);
	case FS_IOC_SETFLAGS:
		if (IS_RDONLY(inode))
			return -EROFS;

		if (!inode_owner_or_capable(inode))
			return -EACCES;

		err = get_user(flags, (int __user *)arg);
		if (err)
			return err;

		mutex_lock(&inode->i_mutex);
		oldflags = li->li_flags;
		flags &= LOGFS_FL_USER_MODIFIABLE;
		flags |= oldflags & ~LOGFS_FL_USER_MODIFIABLE;
		li->li_flags = flags;
		mutex_unlock(&inode->i_mutex);

		inode->i_ctime = CURRENT_TIME;
		mark_inode_dirty_sync(inode);
		return 0;

	default:
		return -ENOTTY;
	}
}

int logfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct super_block *sb = file->f_mapping->host->i_sb;
	struct inode *inode = file->f_mapping->host;
	int ret;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;

	mutex_lock(&inode->i_mutex);
	logfs_get_wblocks(sb, NULL, WF_LOCK);
	logfs_write_anchor(sb);
	logfs_put_wblocks(sb, NULL, WF_LOCK);
	mutex_unlock(&inode->i_mutex);

	return 0;
}

static int logfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int err = 0;

	err = inode_change_ok(inode, attr);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_SIZE) {
		err = logfs_truncate(inode, attr->ia_size);
		if (err)
			return err;
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations logfs_reg_iops = {
	.setattr	= logfs_setattr,
};

const struct file_operations logfs_reg_fops = {
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.fsync		= logfs_fsync,
	.unlocked_ioctl	= logfs_ioctl,
	.llseek		= generic_file_llseek,
	.mmap		= generic_file_readonly_mmap,
	.open		= generic_file_open,
	.read		= new_sync_read,
	.write		= new_sync_write,
};

const struct address_space_operations logfs_reg_aops = {
	.invalidatepage	= logfs_invalidatepage,
	.readpage	= logfs_readpage,
	.releasepage	= logfs_releasepage,
	.set_page_dirty	= __set_page_dirty_nobuffers,
	.writepage	= logfs_writepage,
	.writepages	= generic_writepages,
	.write_begin	= logfs_write_begin,
	.write_end	= logfs_write_end,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/file.c */
/************************************************************/
/*
 * fs/logfs/gc.c	- garbage collection code
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 */
// #include "logfs.h"
// #include <linux/sched.h>
// #include <linux/slab.h>

/*
 * Wear leveling needs to kick in when the difference between low erase
 * counts and high erase counts gets too big.  A good value for "too big"
 * may be somewhat below 10% of maximum erase count for the device.
 * Why not 397, to pick a nice round number with no specific meaning? :)
 *
 * WL_RATELIMIT is the minimum time between two wear level events.  A huge
 * number of segments may fulfil the requirements for wear leveling at the
 * same time.  If that happens we don't want to cause a latency from hell,
 * but just gently pick one segment every so often and minimize overhead.
 */
#define WL_DELTA 397
#define WL_RATELIMIT 100
#define MAX_OBJ_ALIASES	2600
#define SCAN_RATIO 512	/* number of scanned segments per gc'd segment */
#define LIST_SIZE 64	/* base size of candidate lists */
#define SCAN_ROUNDS 128	/* maximum number of complete medium scans */
#define SCAN_ROUNDS_HIGH 4 /* maximum number of higher-level scans */

static int no_free_segments(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);

	return super->s_free_list.count;
}

/* journal has distance -1, top-most ifile layer distance 0 */
static u8 root_distance(struct super_block *sb, gc_level_t __gc_level)
{
	struct logfs_super *super = logfs_super(sb);
	u8 gc_level = (__force u8)__gc_level;

	switch (gc_level) {
	case 0: /* fall through */
	case 1: /* fall through */
	case 2: /* fall through */
	case 3:
		/* file data or indirect blocks */
		return super->s_ifile_levels + super->s_iblock_levels - gc_level;
	case 6: /* fall through */
	case 7: /* fall through */
	case 8: /* fall through */
	case 9:
		/* inode file data or indirect blocks */
		return super->s_ifile_levels - (gc_level - 6);
	default:
		printk(KERN_ERR"LOGFS: segment of unknown level %x found\n",
				gc_level);
		WARN_ON(1);
		return super->s_ifile_levels + super->s_iblock_levels;
	}
}

static int segment_is_reserved(struct super_block *sb, u32 segno)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_area *area;
	void *reserved;
	int i;

	/* Some segments are reserved.  Just pretend they were all valid */
	reserved = btree_lookup32(&super->s_reserved_segments, segno);
	if (reserved)
		return 1;

	/* Currently open segments */
	for_each_area(i) {
		area = super->s_area[i];
		if (area->a_is_open && area->a_segno == segno)
			return 1;
	}

	return 0;
}

static void logfs_mark_segment_bad(struct super_block *sb, u32 segno)
{
	BUG();
}

/*
 * Returns the bytes consumed by valid objects in this segment.  Object headers
 * are counted, the segment header is not.
 */
static u32 logfs_valid_bytes(struct super_block *sb, u32 segno, u32 *ec,
		gc_level_t *gc_level)
{
	struct logfs_segment_entry se;
	u32 ec_level;

	logfs_get_segment_entry(sb, segno, &se);
	if (se.ec_level == cpu_to_be32(BADSEG) ||
			se.valid == cpu_to_be32(RESERVED))
		return RESERVED;

	ec_level = be32_to_cpu(se.ec_level);
	*ec = ec_level >> 4;
	*gc_level = GC_LEVEL(ec_level & 0xf);
	return be32_to_cpu(se.valid);
}

static void logfs_cleanse_block(struct super_block *sb, u64 ofs, u64 ino,
		u64 bix, gc_level_t gc_level)
{
	struct inode *inode;
	int err, cookie;

	inode = logfs_safe_iget(sb, ino, &cookie);
	err = logfs_rewrite_block(inode, bix, ofs, gc_level, 0);
	BUG_ON(err);
	logfs_safe_iput(inode, cookie);
}

static u32 logfs_gc_segment(struct super_block *sb, u32 segno)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_segment_header sh;
	struct logfs_object_header oh;
	u64 ofs, ino, bix;
	u32 seg_ofs, logical_segno, cleaned = 0;
	int err, len, valid;
	gc_level_t gc_level;

	LOGFS_BUG_ON(segment_is_reserved(sb, segno), sb);

	btree_insert32(&super->s_reserved_segments, segno, (void *)1, GFP_NOFS);
	err = wbuf_read(sb, dev_ofs(sb, segno, 0), sizeof(sh), &sh);
	BUG_ON(err);
	gc_level = GC_LEVEL(sh.level);
	logical_segno = be32_to_cpu(sh.segno);
	if (sh.crc != logfs_crc32(&sh, sizeof(sh), 4)) {
		logfs_mark_segment_bad(sb, segno);
		cleaned = -1;
		goto out;
	}

	for (seg_ofs = LOGFS_SEGMENT_HEADERSIZE;
			seg_ofs + sizeof(oh) < super->s_segsize; ) {
		ofs = dev_ofs(sb, logical_segno, seg_ofs);
		err = wbuf_read(sb, dev_ofs(sb, segno, seg_ofs), sizeof(oh),
				&oh);
		BUG_ON(err);

		if (!memchr_inv(&oh, 0xff, sizeof(oh)))
			break;

		if (oh.crc != logfs_crc32(&oh, sizeof(oh) - 4, 4)) {
			logfs_mark_segment_bad(sb, segno);
			cleaned = super->s_segsize - 1;
			goto out;
		}

		ino = be64_to_cpu(oh.ino);
		bix = be64_to_cpu(oh.bix);
		len = sizeof(oh) + be16_to_cpu(oh.len);
		valid = logfs_is_valid_block(sb, ofs, ino, bix, gc_level);
		if (valid == 1) {
			logfs_cleanse_block(sb, ofs, ino, bix, gc_level);
			cleaned += len;
		} else if (valid == 2) {
			/* Will be invalid upon journal commit */
			cleaned += len;
		}
		seg_ofs += len;
	}
out:
	btree_remove32(&super->s_reserved_segments, segno);
	return cleaned;
}

static struct gc_candidate *add_list(struct gc_candidate *cand,
		struct candidate_list *list)
{
	struct rb_node **p = &list->rb_tree.rb_node;
	struct rb_node *parent = NULL;
	struct gc_candidate *cur;
	int comp;

	cand->list = list;
	while (*p) {
		parent = *p;
		cur = rb_entry(parent, struct gc_candidate, rb_node);

		if (list->sort_by_ec)
			comp = cand->erase_count < cur->erase_count;
		else
			comp = cand->valid < cur->valid;

		if (comp)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&cand->rb_node, parent, p);
	rb_insert_color(&cand->rb_node, &list->rb_tree);

	if (list->count <= list->maxcount) {
		list->count++;
		return NULL;
	}
	cand = rb_entry(rb_last(&list->rb_tree), struct gc_candidate, rb_node);
	rb_erase(&cand->rb_node, &list->rb_tree);
	cand->list = NULL;
	return cand;
}

static void remove_from_list(struct gc_candidate *cand)
{
	struct candidate_list *list = cand->list;

	rb_erase(&cand->rb_node, &list->rb_tree);
	list->count--;
}

static void free_candidate(struct super_block *sb, struct gc_candidate *cand)
{
	struct logfs_super *super = logfs_super(sb);

	btree_remove32(&super->s_cand_tree, cand->segno);
	kfree(cand);
}

u32 get_best_cand(struct super_block *sb, struct candidate_list *list, u32 *ec)
{
	struct gc_candidate *cand;
	u32 segno;

	BUG_ON(list->count == 0);

	cand = rb_entry(rb_first(&list->rb_tree), struct gc_candidate, rb_node);
	remove_from_list(cand);
	segno = cand->segno;
	if (ec)
		*ec = cand->erase_count;
	free_candidate(sb, cand);
	return segno;
}

/*
 * We have several lists to manage segments with.  The reserve_list is used to
 * deal with bad blocks.  We try to keep the best (lowest ec) segments on this
 * list.
 * The free_list contains free segments for normal usage.  It usually gets the
 * second pick after the reserve_list.  But when the free_list is running short
 * it is more important to keep the free_list full than to keep a reserve.
 *
 * Segments that are not free are put onto a per-level low_list.  If we have
 * to run garbage collection, we pick a candidate from there.  All segments on
 * those lists should have at least some free space so GC will make progress.
 *
 * And last we have the ec_list, which is used to pick segments for wear
 * leveling.
 *
 * If all appropriate lists are full, we simply free the candidate and forget
 * about that segment for a while.  We have better candidates for each purpose.
 */
static void __add_candidate(struct super_block *sb, struct gc_candidate *cand)
{
	struct logfs_super *super = logfs_super(sb);
	u32 full = super->s_segsize - LOGFS_SEGMENT_RESERVE;

	if (cand->valid == 0) {
		/* 100% free segments */
		log_gc_noisy("add reserve segment %x (ec %x) at %llx\n",
				cand->segno, cand->erase_count,
				dev_ofs(sb, cand->segno, 0));
		cand = add_list(cand, &super->s_reserve_list);
		if (cand) {
			log_gc_noisy("add free segment %x (ec %x) at %llx\n",
					cand->segno, cand->erase_count,
					dev_ofs(sb, cand->segno, 0));
			cand = add_list(cand, &super->s_free_list);
		}
	} else {
		/* good candidates for Garbage Collection */
		if (cand->valid < full)
			cand = add_list(cand, &super->s_low_list[cand->dist]);
		/* good candidates for wear leveling,
		 * segments that were recently written get ignored */
		if (cand)
			cand = add_list(cand, &super->s_ec_list);
	}
	if (cand)
		free_candidate(sb, cand);
}

static int add_candidate(struct super_block *sb, u32 segno, u32 valid, u32 ec,
		u8 dist)
{
	struct logfs_super *super = logfs_super(sb);
	struct gc_candidate *cand;

	cand = kmalloc(sizeof(*cand), GFP_NOFS);
	if (!cand)
		return -ENOMEM;

	cand->segno = segno;
	cand->valid = valid;
	cand->erase_count = ec;
	cand->dist = dist;

	btree_insert32(&super->s_cand_tree, segno, cand, GFP_NOFS);
	__add_candidate(sb, cand);
	return 0;
}

static void remove_segment_from_lists(struct super_block *sb, u32 segno)
{
	struct logfs_super *super = logfs_super(sb);
	struct gc_candidate *cand;

	cand = btree_lookup32(&super->s_cand_tree, segno);
	if (cand) {
		remove_from_list(cand);
		free_candidate(sb, cand);
	}
}

static void scan_segment(struct super_block *sb, u32 segno)
{
	u32 valid, ec = 0;
	gc_level_t gc_level = 0;
	u8 dist;

	if (segment_is_reserved(sb, segno))
		return;

	remove_segment_from_lists(sb, segno);
	valid = logfs_valid_bytes(sb, segno, &ec, &gc_level);
	if (valid == RESERVED)
		return;

	dist = root_distance(sb, gc_level);
	add_candidate(sb, segno, valid, ec, dist);
}

static struct gc_candidate *first_in_list(struct candidate_list *list)
{
	if (list->count == 0)
		return NULL;
	return rb_entry(rb_first(&list->rb_tree), struct gc_candidate, rb_node);
}

/*
 * Find the best segment for garbage collection.  Main criterion is
 * the segment requiring the least effort to clean.  Secondary
 * criterion is to GC on the lowest level available.
 *
 * So we search the least effort segment on the lowest level first,
 * then move up and pick another segment iff is requires significantly
 * less effort.  Hence the LOGFS_MAX_OBJECTSIZE in the comparison.
 */
static struct gc_candidate *get_candidate(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int i, max_dist;
	struct gc_candidate *cand = NULL, *this;

	max_dist = min(no_free_segments(sb), LOGFS_NO_AREAS - 1);

	for (i = max_dist; i >= 0; i--) {
		this = first_in_list(&super->s_low_list[i]);
		if (!this)
			continue;
		if (!cand)
			cand = this;
		if (this->valid + LOGFS_MAX_OBJECTSIZE <= cand->valid)
			cand = this;
	}
	return cand;
}

static int __logfs_gc_once(struct super_block *sb, struct gc_candidate *cand)
{
	struct logfs_super *super = logfs_super(sb);
	gc_level_t gc_level;
	u32 cleaned, valid, segno, ec;
	u8 dist;

	if (!cand) {
		log_gc("GC attempted, but no candidate found\n");
		return 0;
	}

	segno = cand->segno;
	dist = cand->dist;
	valid = logfs_valid_bytes(sb, segno, &ec, &gc_level);
	free_candidate(sb, cand);
	log_gc("GC segment #%02x at %llx, %x required, %x free, %x valid, %llx free\n",
			segno, (u64)segno << super->s_segshift,
			dist, no_free_segments(sb), valid,
			super->s_free_bytes);
	cleaned = logfs_gc_segment(sb, segno);
	log_gc("GC segment #%02x complete - now %x valid\n", segno,
			valid - cleaned);
	BUG_ON(cleaned != valid);
	return 1;
}

static int logfs_gc_once(struct super_block *sb)
{
	struct gc_candidate *cand;

	cand = get_candidate(sb);
	if (cand)
		remove_from_list(cand);
	return __logfs_gc_once(sb, cand);
}

/* returns 1 if a wrap occurs, 0 otherwise */
static int logfs_scan_some(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	u32 segno;
	int i, ret = 0;

	segno = super->s_sweeper;
	for (i = SCAN_RATIO; i > 0; i--) {
		segno++;
		if (segno >= super->s_no_segs) {
			segno = 0;
			ret = 1;
			/* Break out of the loop.  We want to read a single
			 * block from the segment size on next invocation if
			 * SCAN_RATIO is set to match block size
			 */
			break;
		}

		scan_segment(sb, segno);
	}
	super->s_sweeper = segno;
	return ret;
}

/*
 * In principle, this function should loop forever, looking for GC candidates
 * and moving data.  LogFS is designed in such a way that this loop is
 * guaranteed to terminate.
 *
 * Limiting the loop to some iterations serves purely to catch cases when
 * these guarantees have failed.  An actual endless loop is an obvious bug
 * and should be reported as such.
 */
static void __logfs_gc_pass(struct super_block *sb, int target)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_block *block;
	int round, progress, last_progress = 0;

	/*
	 * Doing too many changes to the segfile at once would result
	 * in a large number of aliases.  Write the journal before
	 * things get out of hand.
	 */
	if (super->s_shadow_tree.no_shadowed_segments >= MAX_OBJ_ALIASES)
		logfs_write_anchor(sb);

	if (no_free_segments(sb) >= target &&
			super->s_no_object_aliases < MAX_OBJ_ALIASES)
		return;

	log_gc("__logfs_gc_pass(%x)\n", target);
	for (round = 0; round < SCAN_ROUNDS; ) {
		if (no_free_segments(sb) >= target)
			goto write_alias;

		/* Sync in-memory state with on-medium state in case they
		 * diverged */
		logfs_write_anchor(sb);
		round += logfs_scan_some(sb);
		if (no_free_segments(sb) >= target)
			goto write_alias;
		progress = logfs_gc_once(sb);
		if (progress)
			last_progress = round;
		else if (round - last_progress > 2)
			break;
		continue;

		/*
		 * The goto logic is nasty, I just don't know a better way to
		 * code it.  GC is supposed to ensure two things:
		 * 1. Enough free segments are available.
		 * 2. The number of aliases is bounded.
		 * When 1. is achieved, we take a look at 2. and write back
		 * some alias-containing blocks, if necessary.  However, after
		 * each such write we need to go back to 1., as writes can
		 * consume free segments.
		 */
write_alias:
		if (super->s_no_object_aliases < MAX_OBJ_ALIASES)
			return;
		if (list_empty(&super->s_object_alias)) {
			/* All aliases are still in btree */
			return;
		}
		log_gc("Write back one alias\n");
		block = list_entry(super->s_object_alias.next,
				struct logfs_block, alias_list);
		block->ops->write_block(block);
		/*
		 * To round off the nasty goto logic, we reset round here.  It
		 * is a safety-net for GC not making any progress and limited
		 * to something reasonably small.  If incremented it for every
		 * single alias, the loop could terminate rather quickly.
		 */
		round = 0;
	}
	LOGFS_BUG(sb);
}

static int wl_ratelimit(struct super_block *sb, u64 *next_event)
{
	struct logfs_super *super = logfs_super(sb);

	if (*next_event < super->s_gec) {
		*next_event = super->s_gec + WL_RATELIMIT;
		return 0;
	}
	return 1;
}

static void logfs_wl_pass(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct gc_candidate *wl_cand, *free_cand;

	if (wl_ratelimit(sb, &super->s_wl_gec_ostore))
		return;

	wl_cand = first_in_list(&super->s_ec_list);
	if (!wl_cand)
		return;
	free_cand = first_in_list(&super->s_free_list);
	if (!free_cand)
		return;

	if (wl_cand->erase_count < free_cand->erase_count + WL_DELTA) {
		remove_from_list(wl_cand);
		__logfs_gc_once(sb, wl_cand);
	}
}

/*
 * The journal needs wear leveling as well.  But moving the journal is an
 * expensive operation so we try to avoid it as much as possible.  And if we
 * have to do it, we move the whole journal, not individual segments.
 *
 * Ratelimiting is not strictly necessary here, it mainly serves to avoid the
 * calculations.  First we check whether moving the journal would be a
 * significant improvement.  That means that a) the current journal segments
 * have more wear than the future journal segments and b) the current journal
 * segments have more wear than normal ostore segments.
 * Rationale for b) is that we don't have to move the journal if it is aging
 * less than the ostore, even if the reserve segments age even less (they are
 * excluded from wear leveling, after all).
 * Next we check that the superblocks have less wear than the journal.  Since
 * moving the journal requires writing the superblocks, we have to protect the
 * superblocks even more than the journal.
 *
 * Also we double the acceptable wear difference, compared to ostore wear
 * leveling.  Journal data is read and rewritten rapidly, comparatively.  So
 * soft errors have much less time to accumulate and we allow the journal to
 * be a bit worse than the ostore.
 */
static void logfs_journal_wl_pass(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct gc_candidate *cand;
	u32 min_journal_ec = -1, max_reserve_ec = 0;
	int i;

	if (wl_ratelimit(sb, &super->s_wl_gec_journal))
		return;

	if (super->s_reserve_list.count < super->s_no_journal_segs) {
		/* Reserve is not full enough to move complete journal */
		return;
	}

	journal_for_each(i)
		if (super->s_journal_seg[i])
			min_journal_ec = min(min_journal_ec,
					super->s_journal_ec[i]);
	cand = rb_entry(rb_first(&super->s_free_list.rb_tree),
			struct gc_candidate, rb_node);
	max_reserve_ec = cand->erase_count;
	for (i = 0; i < 2; i++) {
		struct logfs_segment_entry se;
		u32 segno = seg_no(sb, super->s_sb_ofs[i]);
		u32 ec;

		logfs_get_segment_entry(sb, segno, &se);
		ec = be32_to_cpu(se.ec_level) >> 4;
		max_reserve_ec = max(max_reserve_ec, ec);
	}

	if (min_journal_ec > max_reserve_ec + 2 * WL_DELTA) {
		do_logfs_journal_wl_pass(sb);
	}
}

void logfs_gc_pass(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);

	//BUG_ON(mutex_trylock(&logfs_super(sb)->s_w_mutex));
	/* Write journal before free space is getting saturated with dirty
	 * objects.
	 */
	if (super->s_dirty_used_bytes + super->s_dirty_free_bytes
			+ LOGFS_MAX_OBJECTSIZE >= super->s_free_bytes)
		logfs_write_anchor(sb);
	__logfs_gc_pass(sb, super->s_total_levels);
	logfs_wl_pass(sb);
	logfs_journal_wl_pass(sb);
}

static int check_area(struct super_block *sb, int i)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_area *area = super->s_area[i];
	gc_level_t gc_level;
	u32 cleaned, valid, ec;
	u32 segno = area->a_segno;
	u64 ofs = dev_ofs(sb, area->a_segno, area->a_written_bytes);

	if (!area->a_is_open)
		return 0;

	if (super->s_devops->can_write_buf(sb, ofs) == 0)
		return 0;

	printk(KERN_INFO"LogFS: Possibly incomplete write at %llx\n", ofs);
	/*
	 * The device cannot write back the write buffer.  Most likely the
	 * wbuf was already written out and the system crashed at some point
	 * before the journal commit happened.  In that case we wouldn't have
	 * to do anything.  But if the crash happened before the wbuf was
	 * written out correctly, we must GC this segment.  So assume the
	 * worst and always do the GC run.
	 */
	area->a_is_open = 0;
	valid = logfs_valid_bytes(sb, segno, &ec, &gc_level);
	cleaned = logfs_gc_segment(sb, segno);
	if (cleaned != valid)
		return -EIO;
	return 0;
}

int logfs_check_areas(struct super_block *sb)
{
	int i, err;

	for_each_area(i) {
		err = check_area(sb, i);
		if (err)
			return err;
	}
	return 0;
}

static void logfs_init_candlist(struct candidate_list *list, int maxcount,
		int sort_by_ec)
{
	list->count = 0;
	list->maxcount = maxcount;
	list->sort_by_ec = sort_by_ec;
	list->rb_tree = RB_ROOT;
}

int logfs_init_gc(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int i;

	btree_init_mempool32(&super->s_cand_tree, super->s_btree_pool);
	logfs_init_candlist(&super->s_free_list, LIST_SIZE + SCAN_RATIO, 1);
	logfs_init_candlist(&super->s_reserve_list,
			super->s_bad_seg_reserve, 1);
	for_each_area(i)
		logfs_init_candlist(&super->s_low_list[i], LIST_SIZE, 0);
	logfs_init_candlist(&super->s_ec_list, LIST_SIZE, 1);
	return 0;
}

static void logfs_cleanup_list(struct super_block *sb,
		struct candidate_list *list)
{
	struct gc_candidate *cand;

	while (list->count) {
		cand = rb_entry(list->rb_tree.rb_node, struct gc_candidate,
				rb_node);
		remove_from_list(cand);
		free_candidate(sb, cand);
	}
	BUG_ON(list->rb_tree.rb_node);
}

void logfs_cleanup_gc(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int i;

	if (!super->s_free_list.count)
		return;

	/*
	 * FIXME: The btree may still contain a single empty node.  So we
	 * call the grim visitor to clean up that mess.  Btree code should
	 * do it for us, really.
	 */
	btree_grim_visitor32(&super->s_cand_tree, 0, NULL);
	logfs_cleanup_list(sb, &super->s_free_list);
	logfs_cleanup_list(sb, &super->s_reserve_list);
	for_each_area(i)
		logfs_cleanup_list(sb, &super->s_low_list[i]);
	logfs_cleanup_list(sb, &super->s_ec_list);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/gc.c */
/************************************************************/
/*
 * fs/logfs/inode.c	- inode handling code
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 */
// #include "logfs.h"
// #include <linux/slab.h>
// #include <linux/writeback.h>
#include <linux/backing-dev.h>
#include "../../inc/__fss.h"

/*
 * How soon to reuse old inode numbers?  LogFS doesn't store deleted inodes
 * on the medium.  It therefore also lacks a method to store the previous
 * generation number for deleted inodes.  Instead a single generation number
 * is stored which will be used for new inodes.  Being just a 32bit counter,
 * this can obvious wrap relatively quickly.  So we only reuse inodes if we
 * know that a fair number of inodes can be created before we have to increment
 * the generation again - effectively adding some bits to the counter.
 * But being too aggressive here means we keep a very large and very sparse
 * inode file, wasting space on indirect blocks.
 * So what is a good value?  Beats me.  64k seems moderately bad on both
 * fronts, so let's use that for now...
 *
 * NFS sucks, as everyone already knows.
 */
#define INOS_PER_WRAP (0x10000)

/*
 * Logfs' requirement to read inodes for garbage collection makes life a bit
 * harder.  GC may have to read inodes that are in I_FREEING state, when they
 * are being written out - and waiting for GC to make progress, naturally.
 *
 * So we cannot just call iget() or some variant of it, but first have to check
 * whether the inode in question might be in I_FREEING state.  Therefore we
 * maintain our own per-sb list of "almost deleted" inodes and check against
 * that list first.  Normally this should be at most 1-2 entries long.
 *
 * Also, inodes have logfs-specific reference counting on top of what the vfs
 * does.  When .destroy_inode is called, normally the reference count will drop
 * to zero and the inode gets deleted.  But if GC accessed the inode, its
 * refcount will remain nonzero and final deletion will have to wait.
 *
 * As a result we have two sets of functions to get/put inodes:
 * logfs_safe_iget/logfs_safe_iput	- safe to call from GC context
 * logfs_iget/iput			- normal version
 */
static struct kmem_cache *logfs_inode_cache;

static DEFINE_SPINLOCK(logfs_inode_lock);

static void logfs_inode_setops(struct inode *inode)
{
	switch (inode->i_mode & S_IFMT) {
	case S_IFDIR:
		inode->i_op = &logfs_dir_iops;
		inode->i_fop = &logfs_dir_fops;
		inode->i_mapping->a_ops = &logfs_reg_aops;
		break;
	case S_IFREG:
		inode->i_op = &logfs_reg_iops;
		inode->i_fop = &logfs_reg_fops;
		inode->i_mapping->a_ops = &logfs_reg_aops;
		break;
	case S_IFLNK:
		inode->i_op = &logfs_symlink_iops;
		inode->i_mapping->a_ops = &logfs_reg_aops;
		break;
	case S_IFSOCK:	/* fall through */
	case S_IFBLK:	/* fall through */
	case S_IFCHR:	/* fall through */
	case S_IFIFO:
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		break;
	default:
		BUG();
	}
}

static struct inode *__logfs_iget(struct super_block *sb, ino_t ino)
{
	struct inode *inode = iget_locked(sb, ino);
	int err;

	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	err = logfs_read_inode(inode);
	if (err || inode->i_nlink == 0) {
		/* inode->i_nlink == 0 can be true when called from
		 * block validator */
		/* set i_nlink to 0 to prevent caching */
		clear_nlink(inode);
		logfs_inode(inode)->li_flags |= LOGFS_IF_ZOMBIE;
		iget_failed(inode);
		if (!err)
			err = -ENOENT;
		return ERR_PTR(err);
	}

	logfs_inode_setops(inode);
	unlock_new_inode(inode);
	return inode;
}

struct inode *logfs_iget(struct super_block *sb, ino_t ino)
{
	BUG_ON(ino == LOGFS_INO_MASTER);
	BUG_ON(ino == LOGFS_INO_SEGFILE);
	return __logfs_iget(sb, ino);
}

/*
 * is_cached is set to 1 if we hand out a cached inode, 0 otherwise.
 * this allows logfs_iput to do the right thing later
 */
struct inode *logfs_safe_iget(struct super_block *sb, ino_t ino, int *is_cached)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_inode *li;

	if (ino == LOGFS_INO_MASTER)
		return super->s_master_inode;
	if (ino == LOGFS_INO_SEGFILE)
		return super->s_segfile_inode;

	spin_lock(&logfs_inode_lock);
	list_for_each_entry(li, &super->s_freeing_list, li_freeing_list)
		if (li->vfs_inode.i_ino == ino) {
			li->li_refcount++;
			spin_unlock(&logfs_inode_lock);
			*is_cached = 1;
			return &li->vfs_inode;
		}
	spin_unlock(&logfs_inode_lock);

	*is_cached = 0;
	return __logfs_iget(sb, ino);
}

static void logfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(logfs_inode_cache, logfs_inode(inode));
}

static void __logfs_destroy_inode(struct inode *inode)
{
	struct logfs_inode *li = logfs_inode(inode);

	BUG_ON(li->li_block);
	list_del(&li->li_freeing_list);
	call_rcu(&inode->i_rcu, logfs_i_callback);
}

static void __logfs_destroy_meta_inode(struct inode *inode)
{
	struct logfs_inode *li = logfs_inode(inode);
	BUG_ON(li->li_block);
	call_rcu(&inode->i_rcu, logfs_i_callback);
}

static void logfs_destroy_inode(struct inode *inode)
{
	struct logfs_inode *li = logfs_inode(inode);

	if (inode->i_ino < LOGFS_RESERVED_INOS) {
		/*
		 * The reserved inodes are never destroyed unless we are in
		 * unmont path.
		 */
		__logfs_destroy_meta_inode(inode);
		return;
	}

	BUG_ON(list_empty(&li->li_freeing_list));
	spin_lock(&logfs_inode_lock);
	li->li_refcount--;
	if (li->li_refcount == 0)
		__logfs_destroy_inode(inode);
	spin_unlock(&logfs_inode_lock);
}

void logfs_safe_iput(struct inode *inode, int is_cached)
{
	if (inode->i_ino == LOGFS_INO_MASTER)
		return;
	if (inode->i_ino == LOGFS_INO_SEGFILE)
		return;

	if (is_cached) {
		logfs_destroy_inode(inode);
		return;
	}

	iput(inode);
}

static void logfs_init_inode(struct super_block *sb, struct inode *inode)
{
	struct logfs_inode *li = logfs_inode(inode);
	int i;

	li->li_flags	= 0;
	li->li_height	= 0;
	li->li_used_bytes = 0;
	li->li_block	= NULL;
	i_uid_write(inode, 0);
	i_gid_write(inode, 0);
	inode->i_size	= 0;
	inode->i_blocks	= 0;
	inode->i_ctime	= CURRENT_TIME;
	inode->i_mtime	= CURRENT_TIME;
	li->li_refcount = 1;
	INIT_LIST_HEAD(&li->li_freeing_list);

	for (i = 0; i < LOGFS_EMBEDDED_FIELDS; i++)
		li->li_data[i] = 0;

	return;
}

static struct inode *logfs_alloc_inode(struct super_block *sb)
{
	struct logfs_inode *li;

	li = kmem_cache_alloc(logfs_inode_cache, GFP_NOFS);
	if (!li)
		return NULL;
	logfs_init_inode(sb, &li->vfs_inode);
	return &li->vfs_inode;
}

/*
 * In logfs inodes are written to an inode file.  The inode file, like any
 * other file, is managed with a inode.  The inode file's inode, aka master
 * inode, requires special handling in several respects.  First, it cannot be
 * written to the inode file, so it is stored in the journal instead.
 *
 * Secondly, this inode cannot be written back and destroyed before all other
 * inodes have been written.  The ordering is important.  Linux' VFS is happily
 * unaware of the ordering constraint and would ordinarily destroy the master
 * inode at umount time while other inodes are still in use and dirty.  Not
 * good.
 *
 * So logfs makes sure the master inode is not written until all other inodes
 * have been destroyed.  Sadly, this method has another side-effect.  The VFS
 * will notice one remaining inode and print a frightening warning message.
 * Worse, it is impossible to judge whether such a warning was caused by the
 * master inode or any other inodes have leaked as well.
 *
 * Our attempt of solving this is with logfs_new_meta_inode() below.  Its
 * purpose is to create a new inode that will not trigger the warning if such
 * an inode is still in use.  An ugly hack, no doubt.  Suggections for
 * improvement are welcome.
 *
 * AV: that's what ->put_super() is for...
 */
struct inode *logfs_new_meta_inode(struct super_block *sb, u64 ino)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_mode = S_IFREG;
	inode->i_ino = ino;
	inode->i_data.a_ops = &logfs_reg_aops;
	mapping_set_gfp_mask(&inode->i_data, GFP_NOFS);

	return inode;
}

struct inode *logfs_read_meta_inode(struct super_block *sb, u64 ino)
{
	struct inode *inode;
	int err;

	inode = logfs_new_meta_inode(sb, ino);
	if (IS_ERR(inode))
		return inode;

	err = logfs_read_inode(inode);
	if (err) {
		iput(inode);
		return ERR_PTR(err);
	}
	logfs_inode_setops(inode);
	return inode;
}

static int logfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int ret;
	long flags = WF_LOCK;

	/* Can only happen if creat() failed.  Safe to skip. */
	if (logfs_inode(inode)->li_flags & LOGFS_IF_STILLBORN)
		return 0;

	ret = __logfs_write_inode(inode, NULL, flags);
	LOGFS_BUG_ON(ret, inode->i_sb);
	return ret;
}

/* called with inode->i_lock held */
static int logfs_drop_inode(struct inode *inode)
{
	struct logfs_super *super = logfs_super(inode->i_sb);
	struct logfs_inode *li = logfs_inode(inode);

	spin_lock(&logfs_inode_lock);
	list_move(&li->li_freeing_list, &super->s_freeing_list);
	spin_unlock(&logfs_inode_lock);
	return generic_drop_inode(inode);
}

static void logfs_set_ino_generation(struct super_block *sb,
		struct inode *inode)
{
	struct logfs_super *super = logfs_super(sb);
	u64 ino;

	mutex_lock(&super->s_journal_mutex);
	ino = logfs_seek_hole(super->s_master_inode, super->s_last_ino + 1);
	super->s_last_ino = ino;
	super->s_inos_till_wrap--;
	if (super->s_inos_till_wrap < 0) {
		super->s_last_ino = LOGFS_RESERVED_INOS;
		super->s_generation++;
		super->s_inos_till_wrap = INOS_PER_WRAP;
	}
	inode->i_ino = ino;
	inode->i_generation = super->s_generation;
	mutex_unlock(&super->s_journal_mutex);
}

struct inode *logfs_new_inode(struct inode *dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	logfs_init_inode(sb, inode);

	/* inherit parent flags */
	logfs_inode(inode)->li_flags |=
		logfs_inode(dir)->li_flags & LOGFS_FL_INHERITED;

	inode->i_mode = mode;
	logfs_set_ino_generation(sb, inode);

	inode_init_owner(inode, dir, mode);
	logfs_inode_setops(inode);
	insert_inode_hash(inode);

	return inode;
}

static void logfs_init_once(void *_li)
{
	struct logfs_inode *li = _li;
	int i;

	li->li_flags = 0;
	li->li_used_bytes = 0;
	li->li_refcount = 1;
	for (i = 0; i < LOGFS_EMBEDDED_FIELDS; i++)
		li->li_data[i] = 0;
	inode_init_once(&li->vfs_inode);
}

static int logfs_sync_fs(struct super_block *sb, int wait)
{
	logfs_get_wblocks(sb, NULL, WF_LOCK);
	logfs_write_anchor(sb);
	logfs_put_wblocks(sb, NULL, WF_LOCK);
	return 0;
}

static void logfs_put_super(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	/* kill the meta-inodes */
	iput(super->s_segfile_inode);
	iput(super->s_master_inode);
	iput(super->s_mapping_inode);
}

const struct super_operations logfs_super_operations = {
	.alloc_inode	= logfs_alloc_inode,
	.destroy_inode	= logfs_destroy_inode,
	.evict_inode	= logfs_evict_inode,
	.drop_inode	= logfs_drop_inode,
	.put_super	= logfs_put_super,
	.write_inode	= logfs_write_inode,
	.statfs		= logfs_statfs,
	.sync_fs	= logfs_sync_fs,
};

int logfs_init_inode_cache(void)
{
	logfs_inode_cache = kmem_cache_create("logfs_inode_cache",
			sizeof(struct logfs_inode), 0, SLAB_RECLAIM_ACCOUNT,
			logfs_init_once);
	if (!logfs_inode_cache)
		return -ENOMEM;
	return 0;
}

void logfs_destroy_inode_cache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(logfs_inode_cache);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/inode.c */
/************************************************************/
/*
 * fs/logfs/journal.c	- journal handling code
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 */
// #include "logfs.h"
// #include <linux/slab.h>

static void logfs_calc_free(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	u64 reserve, no_segs = super->s_no_segs;
	s64 free;
	int i;

	/* superblock segments */
	no_segs -= 2;
	super->s_no_journal_segs = 0;
	/* journal */
	journal_for_each(i)
		if (super->s_journal_seg[i]) {
			no_segs--;
			super->s_no_journal_segs++;
		}

	/* open segments plus one extra per level for GC */
	no_segs -= 2 * super->s_total_levels;

	free = no_segs * (super->s_segsize - LOGFS_SEGMENT_RESERVE);
	free -= super->s_used_bytes;
	/* just a bit extra */
	free -= super->s_total_levels * 4096;

	/* Bad blocks are 'paid' for with speed reserve - the filesystem
	 * simply gets slower as bad blocks accumulate.  Until the bad blocks
	 * exceed the speed reserve - then the filesystem gets smaller.
	 */
	reserve = super->s_bad_segments + super->s_bad_seg_reserve;
	reserve *= super->s_segsize - LOGFS_SEGMENT_RESERVE;
	reserve = max(reserve, super->s_speed_reserve);
	free -= reserve;
	if (free < 0)
		free = 0;

	super->s_free_bytes = free;
}

static void reserve_sb_and_journal(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct btree_head32 *head = &super->s_reserved_segments;
	int i, err;

	err = btree_insert32(head, seg_no(sb, super->s_sb_ofs[0]), (void *)1,
			GFP_KERNEL);
	BUG_ON(err);

	err = btree_insert32(head, seg_no(sb, super->s_sb_ofs[1]), (void *)1,
			GFP_KERNEL);
	BUG_ON(err);

	journal_for_each(i) {
		if (!super->s_journal_seg[i])
			continue;
		err = btree_insert32(head, super->s_journal_seg[i], (void *)1,
				GFP_KERNEL);
		BUG_ON(err);
	}
}

static void read_dynsb(struct super_block *sb,
		struct logfs_je_dynsb *dynsb)
{
	struct logfs_super *super = logfs_super(sb);

	super->s_gec		= be64_to_cpu(dynsb->ds_gec);
	super->s_sweeper	= be64_to_cpu(dynsb->ds_sweeper);
	super->s_victim_ino	= be64_to_cpu(dynsb->ds_victim_ino);
	super->s_rename_dir	= be64_to_cpu(dynsb->ds_rename_dir);
	super->s_rename_pos	= be64_to_cpu(dynsb->ds_rename_pos);
	super->s_used_bytes	= be64_to_cpu(dynsb->ds_used_bytes);
	super->s_generation	= be32_to_cpu(dynsb->ds_generation);
}

static void read_anchor(struct super_block *sb,
		struct logfs_je_anchor *da)
{
	struct logfs_super *super = logfs_super(sb);
	struct inode *inode = super->s_master_inode;
	struct logfs_inode *li = logfs_inode(inode);
	int i;

	super->s_last_ino = be64_to_cpu(da->da_last_ino);
	li->li_flags	= 0;
	li->li_height	= da->da_height;
	i_size_write(inode, be64_to_cpu(da->da_size));
	li->li_used_bytes = be64_to_cpu(da->da_used_bytes);

	for (i = 0; i < LOGFS_EMBEDDED_FIELDS; i++)
		li->li_data[i] = be64_to_cpu(da->da_data[i]);
}

static void read_erasecount(struct super_block *sb,
		struct logfs_je_journal_ec *ec)
{
	struct logfs_super *super = logfs_super(sb);
	int i;

	journal_for_each(i)
		super->s_journal_ec[i] = be32_to_cpu(ec->ec[i]);
}

static int read_area(struct super_block *sb, struct logfs_je_area *a)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_area *area = super->s_area[a->gc_level];
	u64 ofs;
	u32 writemask = ~(super->s_writesize - 1);

	if (a->gc_level >= LOGFS_NO_AREAS)
		return -EIO;
	if (a->vim != VIM_DEFAULT)
		return -EIO; /* TODO: close area and continue */

	area->a_used_bytes = be32_to_cpu(a->used_bytes);
	area->a_written_bytes = area->a_used_bytes & writemask;
	area->a_segno = be32_to_cpu(a->segno);
	if (area->a_segno)
		area->a_is_open = 1;

	ofs = dev_ofs(sb, area->a_segno, area->a_written_bytes);
	if (super->s_writesize > 1)
		return logfs_buf_recover(area, ofs, a + 1, super->s_writesize);
	else
		return logfs_buf_recover(area, ofs, NULL, 0);
}

static void *unpack(void *from, void *to)
{
	struct logfs_journal_header *jh = from;
	void *data = from + sizeof(struct logfs_journal_header);
	int err;
	size_t inlen, outlen;

	inlen = be16_to_cpu(jh->h_len);
	outlen = be16_to_cpu(jh->h_datalen);

	if (jh->h_compr == COMPR_NONE)
		memcpy(to, data, inlen);
	else {
		err = logfs_uncompress(data, to, inlen, outlen);
		BUG_ON(err);
	}
	return to;
}

static int __read_je_header(struct super_block *sb, u64 ofs,
		struct logfs_journal_header *jh)
{
	struct logfs_super *super = logfs_super(sb);
	size_t bufsize = max_t(size_t, sb->s_blocksize, super->s_writesize)
		+ MAX_JOURNAL_HEADER;
	u16 type, len, datalen;
	int err;

	/* read header only */
	err = wbuf_read(sb, ofs, sizeof(*jh), jh);
	if (err)
		return err;
	type = be16_to_cpu(jh->h_type);
	len = be16_to_cpu(jh->h_len);
	datalen = be16_to_cpu(jh->h_datalen);
	if (len > sb->s_blocksize)
		return -EIO;
	if ((type < JE_FIRST) || (type > JE_LAST))
		return -EIO;
	if (datalen > bufsize)
		return -EIO;
	return 0;
}

static int __read_je_payload(struct super_block *sb, u64 ofs,
		struct logfs_journal_header *jh)
{
	u16 len;
	int err;

	len = be16_to_cpu(jh->h_len);
	err = wbuf_read(sb, ofs + sizeof(*jh), len, jh + 1);
	if (err)
		return err;
	if (jh->h_crc != logfs_crc32(jh, len + sizeof(*jh), 4)) {
		/* Old code was confused.  It forgot about the header length
		 * and stopped calculating the crc 16 bytes before the end
		 * of data - ick!
		 * FIXME: Remove this hack once the old code is fixed.
		 */
		if (jh->h_crc == logfs_crc32(jh, len, 4))
			WARN_ON_ONCE(1);
		else
			return -EIO;
	}
	return 0;
}

/*
 * jh needs to be large enough to hold the complete entry, not just the header
 */
static int __read_je(struct super_block *sb, u64 ofs,
		struct logfs_journal_header *jh)
{
	int err;

	err = __read_je_header(sb, ofs, jh);
	if (err)
		return err;
	return __read_je_payload(sb, ofs, jh);
}

static int read_je(struct super_block *sb, u64 ofs)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_journal_header *jh = super->s_compressed_je;
	void *scratch = super->s_je;
	u16 type, datalen;
	int err;

	err = __read_je(sb, ofs, jh);
	if (err)
		return err;
	type = be16_to_cpu(jh->h_type);
	datalen = be16_to_cpu(jh->h_datalen);

	switch (type) {
	case JE_DYNSB:
		read_dynsb(sb, unpack(jh, scratch));
		break;
	case JE_ANCHOR:
		read_anchor(sb, unpack(jh, scratch));
		break;
	case JE_ERASECOUNT:
		read_erasecount(sb, unpack(jh, scratch));
		break;
	case JE_AREA:
		err = read_area(sb, unpack(jh, scratch));
		break;
	case JE_OBJ_ALIAS:
		err = logfs_load_object_aliases(sb, unpack(jh, scratch),
				datalen);
		break;
	default:
		WARN_ON_ONCE(1);
		return -EIO;
	}
	return err;
}

static int logfs_read_segment(struct super_block *sb, u32 segno)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_journal_header *jh = super->s_compressed_je;
	u64 ofs, seg_ofs = dev_ofs(sb, segno, 0);
	u32 h_ofs, last_ofs = 0;
	u16 len, datalen, last_len = 0;
	int i, err;

	/* search for most recent commit */
	for (h_ofs = 0; h_ofs < super->s_segsize; h_ofs += sizeof(*jh)) {
		ofs = seg_ofs + h_ofs;
		err = __read_je_header(sb, ofs, jh);
		if (err)
			continue;
		if (jh->h_type != cpu_to_be16(JE_COMMIT))
			continue;
		err = __read_je_payload(sb, ofs, jh);
		if (err)
			continue;
		len = be16_to_cpu(jh->h_len);
		datalen = be16_to_cpu(jh->h_datalen);
		if ((datalen > sizeof(super->s_je_array)) ||
				(datalen % sizeof(__be64)))
			continue;
		last_ofs = h_ofs;
		last_len = datalen;
		h_ofs += ALIGN(len, sizeof(*jh)) - sizeof(*jh);
	}
	/* read commit */
	if (last_ofs == 0)
		return -ENOENT;
	ofs = seg_ofs + last_ofs;
	log_journal("Read commit from %llx\n", ofs);
	err = __read_je(sb, ofs, jh);
	BUG_ON(err); /* We should have caught it in the scan loop already */
	if (err)
		return err;
	/* uncompress */
	unpack(jh, super->s_je_array);
	super->s_no_je = last_len / sizeof(__be64);
	/* iterate over array */
	for (i = 0; i < super->s_no_je; i++) {
		err = read_je(sb, be64_to_cpu(super->s_je_array[i]));
		if (err)
			return err;
	}
	super->s_journal_area->a_segno = segno;
	return 0;
}

static u64 read_gec(struct super_block *sb, u32 segno)
{
	struct logfs_segment_header sh;
	__be32 crc;
	int err;

	if (!segno)
		return 0;
	err = wbuf_read(sb, dev_ofs(sb, segno, 0), sizeof(sh), &sh);
	if (err)
		return 0;
	crc = logfs_crc32(&sh, sizeof(sh), 4);
	if (crc != sh.crc) {
		WARN_ON(sh.gec != cpu_to_be64(0xffffffffffffffffull));
		/* Most likely it was just erased */
		return 0;
	}
	return be64_to_cpu(sh.gec);
}

static int logfs_read_journal(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	u64 gec[LOGFS_JOURNAL_SEGS], max;
	u32 segno;
	int i, max_i;

	max = 0;
	max_i = -1;
	journal_for_each(i) {
		segno = super->s_journal_seg[i];
		gec[i] = read_gec(sb, super->s_journal_seg[i]);
		if (gec[i] > max) {
			max = gec[i];
			max_i = i;
		}
	}
	if (max_i == -1)
		return -EIO;
	/* FIXME: Try older segments in case of error */
	return logfs_read_segment(sb, super->s_journal_seg[max_i]);
}

/*
 * First search the current segment (outer loop), then pick the next segment
 * in the array, skipping any zero entries (inner loop).
 */
static void journal_get_free_segment(struct logfs_area *area)
{
	struct logfs_super *super = logfs_super(area->a_sb);
	int i;

	journal_for_each(i) {
		if (area->a_segno != super->s_journal_seg[i])
			continue;

		do {
			i++;
			if (i == LOGFS_JOURNAL_SEGS)
				i = 0;
		} while (!super->s_journal_seg[i]);

		area->a_segno = super->s_journal_seg[i];
		area->a_erase_count = ++(super->s_journal_ec[i]);
		log_journal("Journal now at %x (ec %x)\n", area->a_segno,
				area->a_erase_count);
		return;
	}
	BUG();
}

static void journal_get_erase_count(struct logfs_area *area)
{
	/* erase count is stored globally and incremented in
	 * journal_get_free_segment() - nothing to do here */
}

static int journal_erase_segment(struct logfs_area *area)
{
	struct super_block *sb = area->a_sb;
	union {
		struct logfs_segment_header sh;
		unsigned char c[ALIGN(sizeof(struct logfs_segment_header), 16)];
	} u;
	u64 ofs;
	int err;

	err = logfs_erase_segment(sb, area->a_segno, 1);
	if (err)
		return err;

	memset(&u, 0, sizeof(u));
	u.sh.pad = 0;
	u.sh.type = SEG_JOURNAL;
	u.sh.level = 0;
	u.sh.segno = cpu_to_be32(area->a_segno);
	u.sh.ec = cpu_to_be32(area->a_erase_count);
	u.sh.gec = cpu_to_be64(logfs_super(sb)->s_gec);
	u.sh.crc = logfs_crc32(&u.sh, sizeof(u.sh), 4);

	/* This causes a bug in segment.c.  Not yet. */
	//logfs_set_segment_erased(sb, area->a_segno, area->a_erase_count, 0);

	ofs = dev_ofs(sb, area->a_segno, 0);
	area->a_used_bytes = sizeof(u);
	logfs_buf_write(area, ofs, &u, sizeof(u));
	return 0;
}

static size_t __logfs_write_header(struct logfs_super *super,
		struct logfs_journal_header *jh, size_t len, size_t datalen,
		u16 type, u8 compr)
{
	jh->h_len	= cpu_to_be16(len);
	jh->h_type	= cpu_to_be16(type);
	jh->h_datalen	= cpu_to_be16(datalen);
	jh->h_compr	= compr;
	jh->h_pad[0]	= 'H';
	jh->h_pad[1]	= 'E';
	jh->h_pad[2]	= 'A';
	jh->h_pad[3]	= 'D';
	jh->h_pad[4]	= 'R';
	jh->h_crc	= logfs_crc32(jh, len + sizeof(*jh), 4);
	return ALIGN(len, 16) + sizeof(*jh);
}

static size_t logfs_write_header(struct logfs_super *super,
		struct logfs_journal_header *jh, size_t datalen, u16 type)
{
	size_t len = datalen;

	return __logfs_write_header(super, jh, len, datalen, type, COMPR_NONE);
}

static inline size_t logfs_journal_erasecount_size(struct logfs_super *super)
{
	return LOGFS_JOURNAL_SEGS * sizeof(__be32);
}

static void *logfs_write_erasecount(struct super_block *sb, void *_ec,
		u16 *type, size_t *len)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_je_journal_ec *ec = _ec;
	int i;

	journal_for_each(i)
		ec->ec[i] = cpu_to_be32(super->s_journal_ec[i]);
	*type = JE_ERASECOUNT;
	*len = logfs_journal_erasecount_size(super);
	return ec;
}

static void account_shadow(void *_shadow, unsigned long _sb, u64 ignore,
		size_t ignore2)
{
	struct logfs_shadow *shadow = _shadow;
	struct super_block *sb = (void *)_sb;
	struct logfs_super *super = logfs_super(sb);

	/* consume new space */
	super->s_free_bytes	  -= shadow->new_len;
	super->s_used_bytes	  += shadow->new_len;
	super->s_dirty_used_bytes -= shadow->new_len;

	/* free up old space */
	super->s_free_bytes	  += shadow->old_len;
	super->s_used_bytes	  -= shadow->old_len;
	super->s_dirty_free_bytes -= shadow->old_len;

	logfs_set_segment_used(sb, shadow->old_ofs, -shadow->old_len);
	logfs_set_segment_used(sb, shadow->new_ofs, shadow->new_len);

	log_journal("account_shadow(%llx, %llx, %x) %llx->%llx %x->%x\n",
			shadow->ino, shadow->bix, shadow->gc_level,
			shadow->old_ofs, shadow->new_ofs,
			shadow->old_len, shadow->new_len);
	mempool_free(shadow, super->s_shadow_pool);
}

static void account_shadows(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct inode *inode = super->s_master_inode;
	struct logfs_inode *li = logfs_inode(inode);
	struct shadow_tree *tree = &super->s_shadow_tree;

	btree_grim_visitor64(&tree->new, (unsigned long)sb, account_shadow);
	btree_grim_visitor64(&tree->old, (unsigned long)sb, account_shadow);
	btree_grim_visitor32(&tree->segment_map, 0, NULL);
	tree->no_shadowed_segments = 0;

	if (li->li_block) {
		/*
		 * We never actually use the structure, when attached to the
		 * master inode.  But it is easier to always free it here than
		 * to have checks in several places elsewhere when allocating
		 * it.
		 */
		li->li_block->ops->free_block(sb, li->li_block);
	}
	BUG_ON((s64)li->li_used_bytes < 0);
}

static void *__logfs_write_anchor(struct super_block *sb, void *_da,
		u16 *type, size_t *len)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_je_anchor *da = _da;
	struct inode *inode = super->s_master_inode;
	struct logfs_inode *li = logfs_inode(inode);
	int i;

	da->da_height	= li->li_height;
	da->da_last_ino = cpu_to_be64(super->s_last_ino);
	da->da_size	= cpu_to_be64(i_size_read(inode));
	da->da_used_bytes = cpu_to_be64(li->li_used_bytes);
	for (i = 0; i < LOGFS_EMBEDDED_FIELDS; i++)
		da->da_data[i] = cpu_to_be64(li->li_data[i]);
	*type = JE_ANCHOR;
	*len = sizeof(*da);
	return da;
}

static void *logfs_write_dynsb(struct super_block *sb, void *_dynsb,
		u16 *type, size_t *len)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_je_dynsb *dynsb = _dynsb;

	dynsb->ds_gec		= cpu_to_be64(super->s_gec);
	dynsb->ds_sweeper	= cpu_to_be64(super->s_sweeper);
	dynsb->ds_victim_ino	= cpu_to_be64(super->s_victim_ino);
	dynsb->ds_rename_dir	= cpu_to_be64(super->s_rename_dir);
	dynsb->ds_rename_pos	= cpu_to_be64(super->s_rename_pos);
	dynsb->ds_used_bytes	= cpu_to_be64(super->s_used_bytes);
	dynsb->ds_generation	= cpu_to_be32(super->s_generation);
	*type = JE_DYNSB;
	*len = sizeof(*dynsb);
	return dynsb;
}

static void write_wbuf(struct super_block *sb, struct logfs_area *area,
		void *wbuf)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	u64 ofs;
	pgoff_t index;
	int page_ofs;
	struct page *page;

	ofs = dev_ofs(sb, area->a_segno,
			area->a_used_bytes & ~(super->s_writesize - 1));
	index = ofs >> PAGE_SHIFT;
	page_ofs = ofs & (PAGE_SIZE - 1);

	page = find_or_create_page(mapping, index, GFP_NOFS);
	BUG_ON(!page);
	memcpy(wbuf, page_address(page) + page_ofs, super->s_writesize);
	unlock_page(page);
}

static void *logfs_write_area(struct super_block *sb, void *_a,
		u16 *type, size_t *len)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_area *area = super->s_area[super->s_sum_index];
	struct logfs_je_area *a = _a;

	a->vim = VIM_DEFAULT;
	a->gc_level = super->s_sum_index;
	a->used_bytes = cpu_to_be32(area->a_used_bytes);
	a->segno = cpu_to_be32(area->a_segno);
	if (super->s_writesize > 1)
		write_wbuf(sb, area, a + 1);

	*type = JE_AREA;
	*len = sizeof(*a) + super->s_writesize;
	return a;
}

static void *logfs_write_commit(struct super_block *sb, void *h,
		u16 *type, size_t *len)
{
	struct logfs_super *super = logfs_super(sb);

	*type = JE_COMMIT;
	*len = super->s_no_je * sizeof(__be64);
	return super->s_je_array;
}

static size_t __logfs_write_je(struct super_block *sb, void *buf, u16 type,
		size_t len)
{
	struct logfs_super *super = logfs_super(sb);
	void *header = super->s_compressed_je;
	void *data = header + sizeof(struct logfs_journal_header);
	ssize_t compr_len, pad_len;
	u8 compr = COMPR_ZLIB;

	if (len == 0)
		return logfs_write_header(super, header, 0, type);

	compr_len = logfs_compress(buf, data, len, sb->s_blocksize);
	if (compr_len < 0 || type == JE_ANCHOR) {
		memcpy(data, buf, len);
		compr_len = len;
		compr = COMPR_NONE;
	}

	pad_len = ALIGN(compr_len, 16);
	memset(data + compr_len, 0, pad_len - compr_len);

	return __logfs_write_header(super, header, compr_len, len, type, compr);
}

static s64 logfs_get_free_bytes_journal_c(struct logfs_area *area, size_t *bytes,
		int must_pad)
{
	u32 writesize = logfs_super(area->a_sb)->s_writesize;
	s32 ofs;
	int ret;

	ret = logfs_open_area(area, *bytes);
	if (ret)
		return -EAGAIN;

	ofs = area->a_used_bytes;
	area->a_used_bytes += *bytes;

	if (must_pad) {
		area->a_used_bytes = ALIGN(area->a_used_bytes, writesize);
		*bytes = area->a_used_bytes - ofs;
	}

	return dev_ofs(area->a_sb, area->a_segno, ofs);
}

static int logfs_write_je_buf(struct super_block *sb, void *buf, u16 type,
		size_t buf_len)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_area *area = super->s_journal_area;
	struct logfs_journal_header *jh = super->s_compressed_je;
	size_t len;
	int must_pad = 0;
	s64 ofs;

	len = __logfs_write_je(sb, buf, type, buf_len);
	if (jh->h_type == cpu_to_be16(JE_COMMIT))
		must_pad = 1;

	ofs = logfs_get_free_bytes_journal_c(area, &len, must_pad);
	if (ofs < 0)
		return ofs;
	logfs_buf_write(area, ofs, super->s_compressed_je, len);
	BUG_ON(super->s_no_je >= MAX_JOURNAL_ENTRIES);
	super->s_je_array[super->s_no_je++] = cpu_to_be64(ofs);
	return 0;
}

static int logfs_write_je(struct super_block *sb,
		void* (*write)(struct super_block *sb, void *scratch,
			u16 *type, size_t *len))
{
	void *buf;
	size_t len;
	u16 type;

	buf = write(sb, logfs_super(sb)->s_je, &type, &len);
	return logfs_write_je_buf(sb, buf, type, len);
}

int write_alias_journal(struct super_block *sb, u64 ino, u64 bix,
		level_t level, int child_no, __be64 val)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_obj_alias *oa = super->s_je;
	int err = 0, fill = super->s_je_fill;

	log_aliases("logfs_write_obj_aliases #%x(%llx, %llx, %x, %x) %llx\n",
			fill, ino, bix, level, child_no, be64_to_cpu(val));
	oa[fill].ino = cpu_to_be64(ino);
	oa[fill].bix = cpu_to_be64(bix);
	oa[fill].val = val;
	oa[fill].level = (__force u8)level;
	oa[fill].child_no = cpu_to_be16(child_no);
	fill++;
	if (fill >= sb->s_blocksize / sizeof(*oa)) {
		err = logfs_write_je_buf(sb, oa, JE_OBJ_ALIAS, sb->s_blocksize);
		fill = 0;
	}

	super->s_je_fill = fill;
	return err;
}

static int logfs_write_obj_aliases(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int err;

	log_journal("logfs_write_obj_aliases: %d aliases to write\n",
			super->s_no_object_aliases);
	super->s_je_fill = 0;
	err = logfs_write_obj_aliases_pagecache(sb);
	if (err)
		return err;

	if (super->s_je_fill)
		err = logfs_write_je_buf(sb, super->s_je, JE_OBJ_ALIAS,
				super->s_je_fill
				* sizeof(struct logfs_obj_alias));
	return err;
}

/*
 * Write all journal entries.  The goto logic ensures that all journal entries
 * are written whenever a new segment is used.  It is ugly and potentially a
 * bit wasteful, but robustness is more important.  With this we can *always*
 * erase all journal segments except the one containing the most recent commit.
 */
void logfs_write_anchor(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_area *area = super->s_journal_area;
	int i, err;

	if (!(super->s_flags & LOGFS_SB_FLAG_DIRTY))
		return;
	super->s_flags &= ~LOGFS_SB_FLAG_DIRTY;

	BUG_ON(super->s_flags & LOGFS_SB_FLAG_SHUTDOWN);
	mutex_lock(&super->s_journal_mutex);

	/* Do this first or suffer corruption */
	logfs_sync_segments(sb);
	account_shadows(sb);

again:
	super->s_no_je = 0;
	for_each_area(i) {
		if (!super->s_area[i]->a_is_open)
			continue;
		super->s_sum_index = i;
		err = logfs_write_je(sb, logfs_write_area);
		if (err)
			goto again;
	}
	err = logfs_write_obj_aliases(sb);
	if (err)
		goto again;
	err = logfs_write_je(sb, logfs_write_erasecount);
	if (err)
		goto again;
	err = logfs_write_je(sb, __logfs_write_anchor);
	if (err)
		goto again;
	err = logfs_write_je(sb, logfs_write_dynsb);
	if (err)
		goto again;
	/*
	 * Order is imperative.  First we sync all writes, including the
	 * non-committed journal writes.  Then we write the final commit and
	 * sync the current journal segment.
	 * There is a theoretical bug here.  Syncing the journal segment will
	 * write a number of journal entries and the final commit.  All these
	 * are written in a single operation.  If the device layer writes the
	 * data back-to-front, the commit will precede the other journal
	 * entries, leaving a race window.
	 * Two fixes are possible.  Preferred is to fix the device layer to
	 * ensure writes happen front-to-back.  Alternatively we can insert
	 * another logfs_sync_area() super->s_devops->sync() combo before
	 * writing the commit.
	 */
	/*
	 * On another subject, super->s_devops->sync is usually not necessary.
	 * Unless called from sys_sync or friends, a barrier would suffice.
	 */
	super->s_devops->sync(sb);
	err = logfs_write_je(sb, logfs_write_commit);
	if (err)
		goto again;
	log_journal("Write commit to %llx\n",
			be64_to_cpu(super->s_je_array[super->s_no_je - 1]));
	logfs_sync_area(area);
	BUG_ON(area->a_used_bytes != area->a_written_bytes);
	super->s_devops->sync(sb);

	mutex_unlock(&super->s_journal_mutex);
	return;
}

void do_logfs_journal_wl_pass(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_area *area = super->s_journal_area;
	struct btree_head32 *head = &super->s_reserved_segments;
	u32 segno, ec;
	int i, err;

	log_journal("Journal requires wear-leveling.\n");
	/* Drop old segments */
	journal_for_each(i)
		if (super->s_journal_seg[i]) {
			btree_remove32(head, super->s_journal_seg[i]);
			logfs_set_segment_unreserved(sb,
					super->s_journal_seg[i],
					super->s_journal_ec[i]);
			super->s_journal_seg[i] = 0;
			super->s_journal_ec[i] = 0;
		}
	/* Get new segments */
	for (i = 0; i < super->s_no_journal_segs; i++) {
		segno = get_best_cand(sb, &super->s_reserve_list, &ec);
		super->s_journal_seg[i] = segno;
		super->s_journal_ec[i] = ec;
		logfs_set_segment_reserved(sb, segno);
		err = btree_insert32(head, segno, (void *)1, GFP_NOFS);
		BUG_ON(err); /* mempool should prevent this */
		err = logfs_erase_segment(sb, segno, 1);
		BUG_ON(err); /* FIXME: remount-ro would be nicer */
	}
	/* Manually move journal_area */
	freeseg(sb, area->a_segno);
	area->a_segno = super->s_journal_seg[0];
	area->a_is_open = 0;
	area->a_used_bytes = 0;
	/* Write journal */
	logfs_write_anchor(sb);
	/* Write superblocks */
	err = logfs_write_sb(sb);
	BUG_ON(err);
}

static const struct logfs_area_ops journal_area_ops = {
	.get_free_segment	= journal_get_free_segment,
	.get_erase_count	= journal_get_erase_count,
	.erase_segment		= journal_erase_segment,
};

int logfs_init_journal(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	size_t bufsize = max_t(size_t, sb->s_blocksize, super->s_writesize)
		+ MAX_JOURNAL_HEADER;
	int ret = -ENOMEM;

	mutex_init(&super->s_journal_mutex);
	btree_init_mempool32(&super->s_reserved_segments, super->s_btree_pool);

	super->s_je = kzalloc(bufsize, GFP_KERNEL);
	if (!super->s_je)
		return ret;

	super->s_compressed_je = kzalloc(bufsize, GFP_KERNEL);
	if (!super->s_compressed_je)
		return ret;

	super->s_master_inode = logfs_new_meta_inode(sb, LOGFS_INO_MASTER);
	if (IS_ERR(super->s_master_inode))
		return PTR_ERR(super->s_master_inode);

	ret = logfs_read_journal(sb);
	if (ret)
		return -EIO;

	reserve_sb_and_journal(sb);
	logfs_calc_free(sb);

	super->s_journal_area->a_ops = &journal_area_ops;
	return 0;
}

void logfs_cleanup_journal(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);

	btree_grim_visitor32(&super->s_reserved_segments, 0, NULL);

	kfree(super->s_compressed_je);
	kfree(super->s_je);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/journal.c */
/************************************************************/
/*
 * fs/logfs/readwrite.c
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 *
 *
 * Actually contains five sets of very similar functions:
 * read		read blocks from a file
 * seek_hole	find next hole
 * seek_data	find next data block
 * valid	check whether a block still belongs to a file
 * write	write blocks to a file
 * delete	delete a block (for directories and ifile)
 * rewrite	move existing blocks of a file to a new location (gc helper)
 * truncate	truncate a file
 */
// #include "logfs.h"
// #include <linux/sched.h>
// #include <linux/slab.h>

static u64 adjust_bix(u64 bix, level_t level)
{
	switch (level) {
	case 0:
		return bix;
	case LEVEL(1):
		return max_t(u64, bix, I0_BLOCKS);
	case LEVEL(2):
		return max_t(u64, bix, I1_BLOCKS);
	case LEVEL(3):
		return max_t(u64, bix, I2_BLOCKS);
	case LEVEL(4):
		return max_t(u64, bix, I3_BLOCKS);
	case LEVEL(5):
		return max_t(u64, bix, I4_BLOCKS);
	default:
		WARN_ON(1);
		return bix;
	}
}

static inline u64 maxbix(u8 height)
{
	return 1ULL << (LOGFS_BLOCK_BITS * height);
}

/**
 * The inode address space is cut in two halves.  Lower half belongs to data
 * pages, upper half to indirect blocks.  If the high bit (INDIRECT_BIT) is
 * set, the actual block index (bix) and level can be derived from the page
 * index.
 *
 * The lowest three bits of the block index are set to 0 after packing and
 * unpacking.  Since the lowest n bits (9 for 4KiB blocksize) are ignored
 * anyway this is harmless.
 */
#define ARCH_SHIFT	(BITS_PER_LONG - 32)
#define INDIRECT_BIT	(0x80000000UL << ARCH_SHIFT)
#define LEVEL_SHIFT	(28 + ARCH_SHIFT)
static inline pgoff_t first_indirect_block(void)
{
	return INDIRECT_BIT | (1ULL << LEVEL_SHIFT);
}

pgoff_t logfs_pack_index(u64 bix, level_t level)
{
	pgoff_t index;

	BUG_ON(bix >= INDIRECT_BIT);
	if (level == 0)
		return bix;

	index  = INDIRECT_BIT;
	index |= (__force long)level << LEVEL_SHIFT;
	index |= bix >> ((__force u8)level * LOGFS_BLOCK_BITS);
	return index;
}

void logfs_unpack_index(pgoff_t index, u64 *bix, level_t *level)
{
	u8 __level;

	if (!(index & INDIRECT_BIT)) {
		*bix = index;
		*level = 0;
		return;
	}

	__level = (index & ~INDIRECT_BIT) >> LEVEL_SHIFT;
	*level = LEVEL(__level);
	*bix = (index << (__level * LOGFS_BLOCK_BITS)) & ~INDIRECT_BIT;
	*bix = adjust_bix(*bix, *level);
	return;
}
#undef ARCH_SHIFT
#undef INDIRECT_BIT
#undef LEVEL_SHIFT

/*
 * Time is stored as nanoseconds since the epoch.
 */
static struct timespec be64_to_timespec(__be64 betime)
{
	return ns_to_timespec(be64_to_cpu(betime));
}

static __be64 timespec_to_be64(struct timespec tsp)
{
	return cpu_to_be64((u64)tsp.tv_sec * NSEC_PER_SEC + tsp.tv_nsec);
}

static void logfs_disk_to_inode(struct logfs_disk_inode *di, struct inode*inode)
{
	struct logfs_inode *li = logfs_inode(inode);
	int i;

	inode->i_mode	= be16_to_cpu(di->di_mode);
	li->li_height	= di->di_height;
	li->li_flags	= be32_to_cpu(di->di_flags);
	i_uid_write(inode, be32_to_cpu(di->di_uid));
	i_gid_write(inode, be32_to_cpu(di->di_gid));
	inode->i_size	= be64_to_cpu(di->di_size);
	logfs_set_blocks(inode, be64_to_cpu(di->di_used_bytes));
	inode->i_atime	= be64_to_timespec(di->di_atime);
	inode->i_ctime	= be64_to_timespec(di->di_ctime);
	inode->i_mtime	= be64_to_timespec(di->di_mtime);
	set_nlink(inode, be32_to_cpu(di->di_refcount));
	inode->i_generation = be32_to_cpu(di->di_generation);

	switch (inode->i_mode & S_IFMT) {
	case S_IFSOCK:	/* fall through */
	case S_IFBLK:	/* fall through */
	case S_IFCHR:	/* fall through */
	case S_IFIFO:
		inode->i_rdev = be64_to_cpu(di->di_data[0]);
		break;
	case S_IFDIR:	/* fall through */
	case S_IFREG:	/* fall through */
	case S_IFLNK:
		for (i = 0; i < LOGFS_EMBEDDED_FIELDS; i++)
			li->li_data[i] = be64_to_cpu(di->di_data[i]);
		break;
	default:
		BUG();
	}
}

static void logfs_inode_to_disk(struct inode *inode, struct logfs_disk_inode*di)
{
	struct logfs_inode *li = logfs_inode(inode);
	int i;

	di->di_mode	= cpu_to_be16(inode->i_mode);
	di->di_height	= li->li_height;
	di->di_pad	= 0;
	di->di_flags	= cpu_to_be32(li->li_flags);
	di->di_uid	= cpu_to_be32(i_uid_read(inode));
	di->di_gid	= cpu_to_be32(i_gid_read(inode));
	di->di_size	= cpu_to_be64(i_size_read(inode));
	di->di_used_bytes = cpu_to_be64(li->li_used_bytes);
	di->di_atime	= timespec_to_be64(inode->i_atime);
	di->di_ctime	= timespec_to_be64(inode->i_ctime);
	di->di_mtime	= timespec_to_be64(inode->i_mtime);
	di->di_refcount	= cpu_to_be32(inode->i_nlink);
	di->di_generation = cpu_to_be32(inode->i_generation);

	switch (inode->i_mode & S_IFMT) {
	case S_IFSOCK:	/* fall through */
	case S_IFBLK:	/* fall through */
	case S_IFCHR:	/* fall through */
	case S_IFIFO:
		di->di_data[0] = cpu_to_be64(inode->i_rdev);
		break;
	case S_IFDIR:	/* fall through */
	case S_IFREG:	/* fall through */
	case S_IFLNK:
		for (i = 0; i < LOGFS_EMBEDDED_FIELDS; i++)
			di->di_data[i] = cpu_to_be64(li->li_data[i]);
		break;
	default:
		BUG();
	}
}

static void __logfs_set_blocks(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct logfs_inode *li = logfs_inode(inode);

	inode->i_blocks = ULONG_MAX;
	if (li->li_used_bytes >> sb->s_blocksize_bits < ULONG_MAX)
		inode->i_blocks = ALIGN(li->li_used_bytes, 512) >> 9;
}

void logfs_set_blocks(struct inode *inode, u64 bytes)
{
	struct logfs_inode *li = logfs_inode(inode);

	li->li_used_bytes = bytes;
	__logfs_set_blocks(inode);
}

static void prelock_page(struct super_block *sb, struct page *page, int lock)
{
	struct logfs_super *super = logfs_super(sb);

	BUG_ON(!PageLocked(page));
	if (lock) {
		BUG_ON(PagePreLocked(page));
		SetPagePreLocked(page);
	} else {
		/* We are in GC path. */
		if (PagePreLocked(page))
			super->s_lock_count++;
		else
			SetPagePreLocked(page);
	}
}

static void preunlock_page(struct super_block *sb, struct page *page, int lock)
{
	struct logfs_super *super = logfs_super(sb);

	BUG_ON(!PageLocked(page));
	if (lock)
		ClearPagePreLocked(page);
	else {
		/* We are in GC path. */
		BUG_ON(!PagePreLocked(page));
		if (super->s_lock_count)
			super->s_lock_count--;
		else
			ClearPagePreLocked(page);
	}
}

/*
 * Logfs is prone to an AB-BA deadlock where one task tries to acquire
 * s_write_mutex with a locked page and GC tries to get that page while holding
 * s_write_mutex.
 * To solve this issue logfs will ignore the page lock iff the page in question
 * is waiting for s_write_mutex.  We annotate this fact by setting PG_pre_locked
 * in addition to PG_locked.
 */
void logfs_get_wblocks(struct super_block *sb, struct page *page, int lock)
{
	struct logfs_super *super = logfs_super(sb);

	if (page)
		prelock_page(sb, page, lock);

	if (lock) {
		mutex_lock(&super->s_write_mutex);
		logfs_gc_pass(sb);
		/* FIXME: We also have to check for shadowed space
		 * and mempool fill grade */
	}
}

void logfs_put_wblocks(struct super_block *sb, struct page *page, int lock)
{
	struct logfs_super *super = logfs_super(sb);

	if (page)
		preunlock_page(sb, page, lock);
	/* Order matters - we must clear PG_pre_locked before releasing
	 * s_write_mutex or we could race against another task. */
	if (lock)
		mutex_unlock(&super->s_write_mutex);
}

static struct page *logfs_get_read_page(struct inode *inode, u64 bix,
		level_t level)
{
	return find_or_create_page(inode->i_mapping,
			logfs_pack_index(bix, level), GFP_NOFS);
}

static void logfs_put_read_page(struct page *page)
{
	unlock_page(page);
	page_cache_release(page);
}

static void logfs_lock_write_page(struct page *page)
{
	int loop = 0;

	while (unlikely(!trylock_page(page))) {
		if (loop++ > 0x1000) {
			/* Has been observed once so far... */
			printk(KERN_ERR "stack at %p\n", &loop);
			BUG();
		}
		if (PagePreLocked(page)) {
			/* Holder of page lock is waiting for us, it
			 * is safe to use this page. */
			break;
		}
		/* Some other process has this page locked and has
		 * nothing to do with us.  Wait for it to finish.
		 */
		schedule();
	}
	BUG_ON(!PageLocked(page));
}

static struct page *logfs_get_write_page(struct inode *inode, u64 bix,
		level_t level)
{
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index = logfs_pack_index(bix, level);
	struct page *page;
	int err;

repeat:
	page = find_get_page(mapping, index);
	if (!page) {
		page = __page_cache_alloc(GFP_NOFS);
		if (!page)
			return NULL;
		err = add_to_page_cache_lru(page, mapping, index, GFP_NOFS);
		if (unlikely(err)) {
			page_cache_release(page);
			if (err == -EEXIST)
				goto repeat;
			return NULL;
		}
	} else logfs_lock_write_page(page);
	BUG_ON(!PageLocked(page));
	return page;
}

static void logfs_unlock_write_page(struct page *page)
{
	if (!PagePreLocked(page))
		unlock_page(page);
}

static void logfs_put_write_page(struct page *page)
{
	logfs_unlock_write_page(page);
	page_cache_release(page);
}

static struct page *logfs_get_page(struct inode *inode, u64 bix, level_t level,
		int rw)
{
	if (rw == READ)
		return logfs_get_read_page(inode, bix, level);
	else
		return logfs_get_write_page(inode, bix, level);
}

static void logfs_put_page(struct page *page, int rw)
{
	if (rw == READ)
		logfs_put_read_page(page);
	else
		logfs_put_write_page(page);
}

static unsigned long __get_bits(u64 val, int skip, int no)
{
	u64 ret = val;

	ret >>= skip * no;
	ret <<= 64 - no;
	ret >>= 64 - no;
	return ret;
}

static unsigned long get_bits(u64 val, level_t skip)
{
	return __get_bits(val, (__force int)skip, LOGFS_BLOCK_BITS);
}

static inline void init_shadow_tree(struct super_block *sb,
		struct shadow_tree *tree)
{
	struct logfs_super *super = logfs_super(sb);

	btree_init_mempool64(&tree->new, super->s_btree_pool);
	btree_init_mempool64(&tree->old, super->s_btree_pool);
}

static void indirect_write_block(struct logfs_block *block)
{
	struct page *page;
	struct inode *inode;
	int ret;

	page = block->page;
	inode = page->mapping->host;
	logfs_lock_write_page(page);
	ret = logfs_write_buf(inode, page, 0);
	logfs_unlock_write_page(page);
	/*
	 * This needs some rework.  Unless you want your filesystem to run
	 * completely synchronously (you don't), the filesystem will always
	 * report writes as 'successful' before the actual work has been
	 * done.  The actual work gets done here and this is where any errors
	 * will show up.  And there isn't much we can do about it, really.
	 *
	 * Some attempts to fix the errors (move from bad blocks, retry io,...)
	 * have already been done, so anything left should be either a broken
	 * device or a bug somewhere in logfs itself.  Being relatively new,
	 * the odds currently favor a bug, so for now the line below isn't
	 * entirely tasteles.
	 */
	BUG_ON(ret);
}

static void inode_write_block(struct logfs_block *block)
{
	struct inode *inode;
	int ret;

	inode = block->inode;
	if (inode->i_ino == LOGFS_INO_MASTER)
		logfs_write_anchor(inode->i_sb);
	else {
		ret = __logfs_write_inode(inode, NULL, 0);
		/* see indirect_write_block comment */
		BUG_ON(ret);
	}
}

/*
 * This silences a false, yet annoying gcc warning.  I hate it when my editor
 * jumps into bitops.h each time I recompile this file.
 * TODO: Complain to gcc folks about this and upgrade compiler.
 */
static unsigned long fnb_readwrite_c(const unsigned long *addr,
		unsigned long size, unsigned long offset)
{
	return find_next_bit(addr, size, offset);
}

static __be64 inode_val0(struct inode *inode)
{
	struct logfs_inode *li = logfs_inode(inode);
	u64 val;

	/*
	 * Explicit shifting generates good code, but must match the format
	 * of the structure.  Add some paranoia just in case.
	 */
	BUILD_BUG_ON(offsetof(struct logfs_disk_inode, di_mode) != 0);
	BUILD_BUG_ON(offsetof(struct logfs_disk_inode, di_height) != 2);
	BUILD_BUG_ON(offsetof(struct logfs_disk_inode, di_flags) != 4);

	val =	(u64)inode->i_mode << 48 |
		(u64)li->li_height << 40 |
		(u64)li->li_flags;
	return cpu_to_be64(val);
}

static int inode_write_alias(struct super_block *sb,
		struct logfs_block *block, write_alias_t *write_one_alias)
{
	struct inode *inode = block->inode;
	struct logfs_inode *li = logfs_inode(inode);
	unsigned long pos;
	u64 ino , bix;
	__be64 val;
	level_t level;
	int err;

	for (pos = 0; ; pos++) {
		pos = fnb_readwrite_c(block->alias_map, LOGFS_BLOCK_FACTOR, pos);
		if (pos >= LOGFS_EMBEDDED_FIELDS + INODE_POINTER_OFS)
			return 0;

		switch (pos) {
		case INODE_HEIGHT_OFS:
			val = inode_val0(inode);
			break;
		case INODE_USED_OFS:
			val = cpu_to_be64(li->li_used_bytes);
			break;
		case INODE_SIZE_OFS:
			val = cpu_to_be64(i_size_read(inode));
			break;
		case INODE_POINTER_OFS ... INODE_POINTER_OFS + LOGFS_EMBEDDED_FIELDS - 1:
			val = cpu_to_be64(li->li_data[pos - INODE_POINTER_OFS]);
			break;
		default:
			BUG();
		}

		ino = LOGFS_INO_MASTER;
		bix = inode->i_ino;
		level = LEVEL(0);
		err = write_one_alias(sb, ino, bix, level, pos, val);
		if (err)
			return err;
	}
}

static int indirect_write_alias(struct super_block *sb,
		struct logfs_block *block, write_alias_t *write_one_alias)
{
	unsigned long pos;
	struct page *page = block->page;
	u64 ino , bix;
	__be64 *child, val;
	level_t level;
	int err;

	for (pos = 0; ; pos++) {
		pos = fnb_readwrite_c(block->alias_map, LOGFS_BLOCK_FACTOR, pos);
		if (pos >= LOGFS_BLOCK_FACTOR)
			return 0;

		ino = page->mapping->host->i_ino;
		logfs_unpack_index(page->index, &bix, &level);
		child = kmap_atomic(page);
		val = child[pos];
		kunmap_atomic(child);
		err = write_one_alias(sb, ino, bix, level, pos, val);
		if (err)
			return err;
	}
}

int logfs_write_obj_aliases_pagecache(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_block *block;
	int err;

	list_for_each_entry(block, &super->s_object_alias, alias_list) {
		err = block->ops->write_alias(sb, block, write_alias_journal);
		if (err)
			return err;
	}
	return 0;
}

void __free_block(struct super_block *sb, struct logfs_block *block)
{
	BUG_ON(!list_empty(&block->item_list));
	list_del(&block->alias_list);
	mempool_free(block, logfs_super(sb)->s_block_pool);
}

static void inode_free_block(struct super_block *sb, struct logfs_block *block)
{
	struct inode *inode = block->inode;

	logfs_inode(inode)->li_block = NULL;
	__free_block(sb, block);
}

static void indirect_free_block(struct super_block *sb,
		struct logfs_block *block)
{
	struct page *page = block->page;

	if (PagePrivate(page)) {
		ClearPagePrivate(page);
		page_cache_release(page);
		set_page_private(page, 0);
	}
	__free_block(sb, block);
}


static struct logfs_block_ops inode_block_ops = {
	.write_block = inode_write_block,
	.free_block = inode_free_block,
	.write_alias = inode_write_alias,
};

struct logfs_block_ops indirect_block_ops = {
	.write_block = indirect_write_block,
	.free_block = indirect_free_block,
	.write_alias = indirect_write_alias,
};

struct logfs_block *__alloc_block(struct super_block *sb,
		u64 ino, u64 bix, level_t level)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_block *block;

	block = mempool_alloc(super->s_block_pool, GFP_NOFS);
	memset(block, 0, sizeof(*block));
	INIT_LIST_HEAD(&block->alias_list);
	INIT_LIST_HEAD(&block->item_list);
	block->sb = sb;
	block->ino = ino;
	block->bix = bix;
	block->level = level;
	return block;
}

static void alloc_inode_block(struct inode *inode)
{
	struct logfs_inode *li = logfs_inode(inode);
	struct logfs_block *block;

	if (li->li_block)
		return;

	block = __alloc_block(inode->i_sb, LOGFS_INO_MASTER, inode->i_ino, 0);
	block->inode = inode;
	li->li_block = block;
	block->ops = &inode_block_ops;
}

void initialize_block_counters(struct page *page, struct logfs_block *block,
		__be64 *array, int page_is_empty)
{
	u64 ptr;
	int i, start;

	block->partial = 0;
	block->full = 0;
	start = 0;
	if (page->index < first_indirect_block()) {
		/* Counters are pointless on level 0 */
		return;
	}
	if (page->index == first_indirect_block()) {
		/* Skip unused pointers */
		start = I0_BLOCKS;
		block->full = I0_BLOCKS;
	}
	if (!page_is_empty) {
		for (i = start; i < LOGFS_BLOCK_FACTOR; i++) {
			ptr = be64_to_cpu(array[i]);
			if (ptr)
				block->partial++;
			if (ptr & LOGFS_FULLY_POPULATED)
				block->full++;
		}
	}
}

static void alloc_data_block(struct inode *inode, struct page *page)
{
	struct logfs_block *block;
	u64 bix;
	level_t level;

	if (PagePrivate(page))
		return;

	logfs_unpack_index(page->index, &bix, &level);
	block = __alloc_block(inode->i_sb, inode->i_ino, bix, level);
	block->page = page;

	SetPagePrivate(page);
	page_cache_get(page);
	set_page_private(page, (unsigned long) block);

	block->ops = &indirect_block_ops;
}

static void alloc_indirect_block(struct inode *inode, struct page *page,
		int page_is_empty)
{
	struct logfs_block *block;
	__be64 *array;

	if (PagePrivate(page))
		return;

	alloc_data_block(inode, page);

	block = logfs_block(page);
	array = kmap_atomic(page);
	initialize_block_counters(page, block, array, page_is_empty);
	kunmap_atomic(array);
}

static void block_set_pointer(struct page *page, int index, u64 ptr)
{
	struct logfs_block *block = logfs_block(page);
	__be64 *array;
	u64 oldptr;

	BUG_ON(!block);
	array = kmap_atomic(page);
	oldptr = be64_to_cpu(array[index]);
	array[index] = cpu_to_be64(ptr);
	kunmap_atomic(array);
	SetPageUptodate(page);

	block->full += !!(ptr & LOGFS_FULLY_POPULATED)
		- !!(oldptr & LOGFS_FULLY_POPULATED);
	block->partial += !!ptr - !!oldptr;
}

static u64 block_get_pointer(struct page *page, int index)
{
	__be64 *block;
	u64 ptr;

	block = kmap_atomic(page);
	ptr = be64_to_cpu(block[index]);
	kunmap_atomic(block);
	return ptr;
}

static int logfs_read_empty(struct page *page)
{
	zero_user_segment(page, 0, PAGE_CACHE_SIZE);
	return 0;
}

static int logfs_read_direct(struct inode *inode, struct page *page)
{
	struct logfs_inode *li = logfs_inode(inode);
	pgoff_t index = page->index;
	u64 block;

	block = li->li_data[index];
	if (!block)
		return logfs_read_empty(page);

	return logfs_segment_read(inode, page, block, index, 0);
}

static int logfs_read_loop(struct inode *inode, struct page *page,
		int rw_context)
{
	struct logfs_inode *li = logfs_inode(inode);
	u64 bix, bofs = li->li_data[INDIRECT_INDEX];
	level_t level, target_level;
	int ret;
	struct page *ipage;

	logfs_unpack_index(page->index, &bix, &target_level);
	if (!bofs)
		return logfs_read_empty(page);

	if (bix >= maxbix(li->li_height))
		return logfs_read_empty(page);

	for (level = LEVEL(li->li_height);
			(__force u8)level > (__force u8)target_level;
			level = SUBLEVEL(level)){
		ipage = logfs_get_page(inode, bix, level, rw_context);
		if (!ipage)
			return -ENOMEM;

		ret = logfs_segment_read(inode, ipage, bofs, bix, level);
		if (ret) {
			logfs_put_read_page(ipage);
			return ret;
		}

		bofs = block_get_pointer(ipage, get_bits(bix, SUBLEVEL(level)));
		logfs_put_page(ipage, rw_context);
		if (!bofs)
			return logfs_read_empty(page);
	}

	return logfs_segment_read(inode, page, bofs, bix, 0);
}

static int logfs_read_block(struct inode *inode, struct page *page,
		int rw_context)
{
	pgoff_t index = page->index;

	if (index < I0_BLOCKS)
		return logfs_read_direct(inode, page);
	return logfs_read_loop(inode, page, rw_context);
}

static int logfs_exist_loop(struct inode *inode, u64 bix)
{
	struct logfs_inode *li = logfs_inode(inode);
	u64 bofs = li->li_data[INDIRECT_INDEX];
	level_t level;
	int ret;
	struct page *ipage;

	if (!bofs)
		return 0;
	if (bix >= maxbix(li->li_height))
		return 0;

	for (level = LEVEL(li->li_height); level != 0; level = SUBLEVEL(level)) {
		ipage = logfs_get_read_page(inode, bix, level);
		if (!ipage)
			return -ENOMEM;

		ret = logfs_segment_read(inode, ipage, bofs, bix, level);
		if (ret) {
			logfs_put_read_page(ipage);
			return ret;
		}

		bofs = block_get_pointer(ipage, get_bits(bix, SUBLEVEL(level)));
		logfs_put_read_page(ipage);
		if (!bofs)
			return 0;
	}

	return 1;
}

int logfs_exist_block(struct inode *inode, u64 bix)
{
	struct logfs_inode *li = logfs_inode(inode);

	if (bix < I0_BLOCKS)
		return !!li->li_data[bix];
	return logfs_exist_loop(inode, bix);
}

static u64 seek_holedata_direct(struct inode *inode, u64 bix, int data)
{
	struct logfs_inode *li = logfs_inode(inode);

	for (; bix < I0_BLOCKS; bix++)
		if (data ^ (li->li_data[bix] == 0))
			return bix;
	return I0_BLOCKS;
}

static u64 seek_holedata_loop(struct inode *inode, u64 bix, int data)
{
	struct logfs_inode *li = logfs_inode(inode);
	__be64 *rblock;
	u64 increment, bofs = li->li_data[INDIRECT_INDEX];
	level_t level;
	int ret, slot;
	struct page *page;

	BUG_ON(!bofs);

	for (level = LEVEL(li->li_height); level != 0; level = SUBLEVEL(level)) {
		increment = 1 << (LOGFS_BLOCK_BITS * ((__force u8)level-1));
		page = logfs_get_read_page(inode, bix, level);
		if (!page)
			return bix;

		ret = logfs_segment_read(inode, page, bofs, bix, level);
		if (ret) {
			logfs_put_read_page(page);
			return bix;
		}

		slot = get_bits(bix, SUBLEVEL(level));
		rblock = kmap_atomic(page);
		while (slot < LOGFS_BLOCK_FACTOR) {
			if (data && (rblock[slot] != 0))
				break;
			if (!data && !(be64_to_cpu(rblock[slot]) & LOGFS_FULLY_POPULATED))
				break;
			slot++;
			bix += increment;
			bix &= ~(increment - 1);
		}
		if (slot >= LOGFS_BLOCK_FACTOR) {
			kunmap_atomic(rblock);
			logfs_put_read_page(page);
			return bix;
		}
		bofs = be64_to_cpu(rblock[slot]);
		kunmap_atomic(rblock);
		logfs_put_read_page(page);
		if (!bofs) {
			BUG_ON(data);
			return bix;
		}
	}
	return bix;
}

/**
 * logfs_seek_hole - find next hole starting at a given block index
 * @inode:		inode to search in
 * @bix:		block index to start searching
 *
 * Returns next hole.  If the file doesn't contain any further holes, the
 * block address next to eof is returned instead.
 */
u64 logfs_seek_hole(struct inode *inode, u64 bix)
{
	struct logfs_inode *li = logfs_inode(inode);

	if (bix < I0_BLOCKS) {
		bix = seek_holedata_direct(inode, bix, 0);
		if (bix < I0_BLOCKS)
			return bix;
	}

	if (!li->li_data[INDIRECT_INDEX])
		return bix;
	else if (li->li_data[INDIRECT_INDEX] & LOGFS_FULLY_POPULATED)
		bix = maxbix(li->li_height);
	else if (bix >= maxbix(li->li_height))
		return bix;
	else {
		bix = seek_holedata_loop(inode, bix, 0);
		if (bix < maxbix(li->li_height))
			return bix;
		/* Should not happen anymore.  But if some port writes semi-
		 * corrupt images (as this one used to) we might run into it.
		 */
		WARN_ON_ONCE(bix == maxbix(li->li_height));
	}

	return bix;
}

static u64 __logfs_seek_data(struct inode *inode, u64 bix)
{
	struct logfs_inode *li = logfs_inode(inode);

	if (bix < I0_BLOCKS) {
		bix = seek_holedata_direct(inode, bix, 1);
		if (bix < I0_BLOCKS)
			return bix;
	}

	if (bix < maxbix(li->li_height)) {
		if (!li->li_data[INDIRECT_INDEX])
			bix = maxbix(li->li_height);
		else
			return seek_holedata_loop(inode, bix, 1);
	}

	return bix;
}

/**
 * logfs_seek_data - find next data block after a given block index
 * @inode:		inode to search in
 * @bix:		block index to start searching
 *
 * Returns next data block.  If the file doesn't contain any further data
 * blocks, the last block in the file is returned instead.
 */
u64 logfs_seek_data(struct inode *inode, u64 bix)
{
	struct super_block *sb = inode->i_sb;
	u64 ret, end;

	ret = __logfs_seek_data(inode, bix);
	end = i_size_read(inode) >> sb->s_blocksize_bits;
	if (ret >= end)
		ret = max(bix, end);
	return ret;
}

static int logfs_is_valid_direct(struct logfs_inode *li, u64 bix, u64 ofs)
{
	return pure_ofs(li->li_data[bix]) == ofs;
}

static int __logfs_is_valid_loop(struct inode *inode, u64 bix,
		u64 ofs, u64 bofs)
{
	struct logfs_inode *li = logfs_inode(inode);
	level_t level;
	int ret;
	struct page *page;

	for (level = LEVEL(li->li_height); level != 0; level = SUBLEVEL(level)){
		page = logfs_get_write_page(inode, bix, level);
		BUG_ON(!page);

		ret = logfs_segment_read(inode, page, bofs, bix, level);
		if (ret) {
			logfs_put_write_page(page);
			return 0;
		}

		bofs = block_get_pointer(page, get_bits(bix, SUBLEVEL(level)));
		logfs_put_write_page(page);
		if (!bofs)
			return 0;

		if (pure_ofs(bofs) == ofs)
			return 1;
	}
	return 0;
}

static int logfs_is_valid_loop(struct inode *inode, u64 bix, u64 ofs)
{
	struct logfs_inode *li = logfs_inode(inode);
	u64 bofs = li->li_data[INDIRECT_INDEX];

	if (!bofs)
		return 0;

	if (bix >= maxbix(li->li_height))
		return 0;

	if (pure_ofs(bofs) == ofs)
		return 1;

	return __logfs_is_valid_loop(inode, bix, ofs, bofs);
}

static int __logfs_is_valid_block(struct inode *inode, u64 bix, u64 ofs)
{
	struct logfs_inode *li = logfs_inode(inode);

	if ((inode->i_nlink == 0) && atomic_read(&inode->i_count) == 1)
		return 0;

	if (bix < I0_BLOCKS)
		return logfs_is_valid_direct(li, bix, ofs);
	return logfs_is_valid_loop(inode, bix, ofs);
}

/**
 * logfs_is_valid_block - check whether this block is still valid
 *
 * @sb:		superblock
 * @ofs:	block physical offset
 * @ino:	block inode number
 * @bix:	block index
 * @gc_level:	block level
 *
 * Returns 0 if the block is invalid, 1 if it is valid and 2 if it will
 * become invalid once the journal is written.
 */
int logfs_is_valid_block(struct super_block *sb, u64 ofs, u64 ino, u64 bix,
		gc_level_t gc_level)
{
	struct logfs_super *super = logfs_super(sb);
	struct inode *inode;
	int ret, cookie;

	/* Umount closes a segment with free blocks remaining.  Those
	 * blocks are by definition invalid. */
	if (ino == -1)
		return 0;

	LOGFS_BUG_ON((u64)(u_long)ino != ino, sb);

	inode = logfs_safe_iget(sb, ino, &cookie);
	if (IS_ERR(inode))
		goto invalid;

	ret = __logfs_is_valid_block(inode, bix, ofs);
	logfs_safe_iput(inode, cookie);
	if (ret)
		return ret;

invalid:
	/* Block is nominally invalid, but may still sit in the shadow tree,
	 * waiting for a journal commit.
	 */
	if (btree_lookup64(&super->s_shadow_tree.old, ofs))
		return 2;
	return 0;
}

int logfs_readpage_nolock(struct page *page)
{
	struct inode *inode = page->mapping->host;
	int ret = -EIO;

	ret = logfs_read_block(inode, page, READ);

	if (ret) {
		ClearPageUptodate(page);
		SetPageError(page);
	} else {
		SetPageUptodate(page);
		ClearPageError(page);
	}
	flush_dcache_page(page);

	return ret;
}

static int logfs_reserve_bytes(struct inode *inode, int bytes)
{
	struct logfs_super *super = logfs_super(inode->i_sb);
	u64 available = super->s_free_bytes + super->s_dirty_free_bytes
			- super->s_dirty_used_bytes - super->s_dirty_pages;

	if (!bytes)
		return 0;

	if (available < bytes)
		return -ENOSPC;

	if (available < bytes + super->s_root_reserve &&
			!capable(CAP_SYS_RESOURCE))
		return -ENOSPC;

	return 0;
}

int get_page_reserve(struct inode *inode, struct page *page)
{
	struct logfs_super *super = logfs_super(inode->i_sb);
	struct logfs_block *block = logfs_block(page);
	int ret;

	if (block && block->reserved_bytes)
		return 0;

	logfs_get_wblocks(inode->i_sb, page, WF_LOCK);
	while ((ret = logfs_reserve_bytes(inode, 6 * LOGFS_MAX_OBJECTSIZE)) &&
			!list_empty(&super->s_writeback_list)) {
		block = list_entry(super->s_writeback_list.next,
				struct logfs_block, alias_list);
		block->ops->write_block(block);
	}
	if (!ret) {
		alloc_data_block(inode, page);
		block = logfs_block(page);
		block->reserved_bytes += 6 * LOGFS_MAX_OBJECTSIZE;
		super->s_dirty_pages += 6 * LOGFS_MAX_OBJECTSIZE;
		list_move_tail(&block->alias_list, &super->s_writeback_list);
	}
	logfs_put_wblocks(inode->i_sb, page, WF_LOCK);
	return ret;
}

/*
 * We are protected by write lock.  Push victims up to superblock level
 * and release transaction when appropriate.
 */
/* FIXME: This is currently called from the wrong spots. */
static void logfs_handle_transaction(struct inode *inode,
		struct logfs_transaction *ta)
{
	struct logfs_super *super = logfs_super(inode->i_sb);

	if (!ta)
		return;
	logfs_inode(inode)->li_block->ta = NULL;

	if (inode->i_ino != LOGFS_INO_MASTER) {
		BUG(); /* FIXME: Yes, this needs more thought */
		/* just remember the transaction until inode is written */
		//BUG_ON(logfs_inode(inode)->li_transaction);
		//logfs_inode(inode)->li_transaction = ta;
		return;
	}

	switch (ta->state) {
	case CREATE_1: /* fall through */
	case UNLINK_1:
		BUG_ON(super->s_victim_ino);
		super->s_victim_ino = ta->ino;
		break;
	case CREATE_2: /* fall through */
	case UNLINK_2:
		BUG_ON(super->s_victim_ino != ta->ino);
		super->s_victim_ino = 0;
		/* transaction ends here - free it */
		kfree(ta);
		break;
	case CROSS_RENAME_1:
		BUG_ON(super->s_rename_dir);
		BUG_ON(super->s_rename_pos);
		super->s_rename_dir = ta->dir;
		super->s_rename_pos = ta->pos;
		break;
	case CROSS_RENAME_2:
		BUG_ON(super->s_rename_dir != ta->dir);
		BUG_ON(super->s_rename_pos != ta->pos);
		super->s_rename_dir = 0;
		super->s_rename_pos = 0;
		kfree(ta);
		break;
	case TARGET_RENAME_1:
		BUG_ON(super->s_rename_dir);
		BUG_ON(super->s_rename_pos);
		BUG_ON(super->s_victim_ino);
		super->s_rename_dir = ta->dir;
		super->s_rename_pos = ta->pos;
		super->s_victim_ino = ta->ino;
		break;
	case TARGET_RENAME_2:
		BUG_ON(super->s_rename_dir != ta->dir);
		BUG_ON(super->s_rename_pos != ta->pos);
		BUG_ON(super->s_victim_ino != ta->ino);
		super->s_rename_dir = 0;
		super->s_rename_pos = 0;
		break;
	case TARGET_RENAME_3:
		BUG_ON(super->s_rename_dir);
		BUG_ON(super->s_rename_pos);
		BUG_ON(super->s_victim_ino != ta->ino);
		super->s_victim_ino = 0;
		kfree(ta);
		break;
	default:
		BUG();
	}
}

/*
 * Not strictly a reservation, but rather a check that we still have enough
 * space to satisfy the write.
 */
static int logfs_reserve_blocks(struct inode *inode, int blocks)
{
	return logfs_reserve_bytes(inode, blocks * LOGFS_MAX_OBJECTSIZE);
}

struct write_control {
	u64 ofs;
	long flags;
};

static struct logfs_shadow *alloc_shadow(struct inode *inode, u64 bix,
		level_t level, u64 old_ofs)
{
	struct logfs_super *super = logfs_super(inode->i_sb);
	struct logfs_shadow *shadow;

	shadow = mempool_alloc(super->s_shadow_pool, GFP_NOFS);
	memset(shadow, 0, sizeof(*shadow));
	shadow->ino = inode->i_ino;
	shadow->bix = bix;
	shadow->gc_level = expand_level(inode->i_ino, level);
	shadow->old_ofs = old_ofs & ~LOGFS_FULLY_POPULATED;
	return shadow;
}

static void free_shadow(struct inode *inode, struct logfs_shadow *shadow)
{
	struct logfs_super *super = logfs_super(inode->i_sb);

	mempool_free(shadow, super->s_shadow_pool);
}

static void mark_segment(struct shadow_tree *tree, u32 segno)
{
	int err;

	if (!btree_lookup32(&tree->segment_map, segno)) {
		err = btree_insert32(&tree->segment_map, segno, (void *)1,
				GFP_NOFS);
		BUG_ON(err);
		tree->no_shadowed_segments++;
	}
}

/**
 * fill_shadow_tree - Propagate shadow tree changes due to a write
 * @inode:	Inode owning the page
 * @page:	Struct page that was written
 * @shadow:	Shadow for the current write
 *
 * Writes in logfs can result in two semi-valid objects.  The old object
 * is still valid as long as it can be reached by following pointers on
 * the medium.  Only when writes propagate all the way up to the journal
 * has the new object safely replaced the old one.
 *
 * To handle this problem, a struct logfs_shadow is used to represent
 * every single write.  It is attached to the indirect block, which is
 * marked dirty.  When the indirect block is written, its shadows are
 * handed up to the next indirect block (or inode).  Untimately they
 * will reach the master inode and be freed upon journal commit.
 *
 * This function handles a single step in the propagation.  It adds the
 * shadow for the current write to the tree, along with any shadows in
 * the page's tree, in case it was an indirect block.  If a page is
 * written, the inode parameter is left NULL, if an inode is written,
 * the page parameter is left NULL.
 */
static void fill_shadow_tree(struct inode *inode, struct page *page,
		struct logfs_shadow *shadow)
{
	struct logfs_super *super = logfs_super(inode->i_sb);
	struct logfs_block *block = logfs_block(page);
	struct shadow_tree *tree = &super->s_shadow_tree;

	if (PagePrivate(page)) {
		if (block->alias_map)
			super->s_no_object_aliases -= bitmap_weight(
					block->alias_map, LOGFS_BLOCK_FACTOR);
		logfs_handle_transaction(inode, block->ta);
		block->ops->free_block(inode->i_sb, block);
	}
	if (shadow) {
		if (shadow->old_ofs)
			btree_insert64(&tree->old, shadow->old_ofs, shadow,
					GFP_NOFS);
		else
			btree_insert64(&tree->new, shadow->new_ofs, shadow,
					GFP_NOFS);

		super->s_dirty_used_bytes += shadow->new_len;
		super->s_dirty_free_bytes += shadow->old_len;
		mark_segment(tree, shadow->old_ofs >> super->s_segshift);
		mark_segment(tree, shadow->new_ofs >> super->s_segshift);
	}
}

static void logfs_set_alias(struct super_block *sb, struct logfs_block *block,
		long child_no)
{
	struct logfs_super *super = logfs_super(sb);

	if (block->inode && block->inode->i_ino == LOGFS_INO_MASTER) {
		/* Aliases in the master inode are pointless. */
		return;
	}

	if (!test_bit(child_no, block->alias_map)) {
		set_bit(child_no, block->alias_map);
		super->s_no_object_aliases++;
	}
	list_move_tail(&block->alias_list, &super->s_object_alias);
}

/*
 * Object aliases can and often do change the size and occupied space of a
 * file.  So not only do we have to change the pointers, we also have to
 * change inode->i_size and li->li_used_bytes.  Which is done by setting
 * another two object aliases for the inode itself.
 */
static void set_iused(struct inode *inode, struct logfs_shadow *shadow)
{
	struct logfs_inode *li = logfs_inode(inode);

	if (shadow->new_len == shadow->old_len)
		return;

	alloc_inode_block(inode);
	li->li_used_bytes += shadow->new_len - shadow->old_len;
	__logfs_set_blocks(inode);
	logfs_set_alias(inode->i_sb, li->li_block, INODE_USED_OFS);
	logfs_set_alias(inode->i_sb, li->li_block, INODE_SIZE_OFS);
}

static int logfs_write_i0(struct inode *inode, struct page *page,
		struct write_control *wc)
{
	struct logfs_shadow *shadow;
	u64 bix;
	level_t level;
	int full, err = 0;

	logfs_unpack_index(page->index, &bix, &level);
	if (wc->ofs == 0)
		if (logfs_reserve_blocks(inode, 1))
			return -ENOSPC;

	shadow = alloc_shadow(inode, bix, level, wc->ofs);
	if (wc->flags & WF_WRITE)
		err = logfs_segment_write(inode, page, shadow);
	if (wc->flags & WF_DELETE)
		logfs_segment_delete(inode, shadow);
	if (err) {
		free_shadow(inode, shadow);
		return err;
	}

	set_iused(inode, shadow);
	full = 1;
	if (level != 0) {
		alloc_indirect_block(inode, page, 0);
		full = logfs_block(page)->full == LOGFS_BLOCK_FACTOR;
	}
	fill_shadow_tree(inode, page, shadow);
	wc->ofs = shadow->new_ofs;
	if (wc->ofs && full)
		wc->ofs |= LOGFS_FULLY_POPULATED;
	return 0;
}

static int logfs_write_direct(struct inode *inode, struct page *page,
		long flags)
{
	struct logfs_inode *li = logfs_inode(inode);
	struct write_control wc = {
		.ofs = li->li_data[page->index],
		.flags = flags,
	};
	int err;

	alloc_inode_block(inode);

	err = logfs_write_i0(inode, page, &wc);
	if (err)
		return err;

	li->li_data[page->index] = wc.ofs;
	logfs_set_alias(inode->i_sb, li->li_block,
			page->index + INODE_POINTER_OFS);
	return 0;
}

static int ptr_change(u64 ofs, struct page *page)
{
	struct logfs_block *block = logfs_block(page);
	int empty0, empty1, full0, full1;

	empty0 = ofs == 0;
	empty1 = block->partial == 0;
	if (empty0 != empty1)
		return 1;

	/* The !! is necessary to shrink result to int */
	full0 = !!(ofs & LOGFS_FULLY_POPULATED);
	full1 = block->full == LOGFS_BLOCK_FACTOR;
	if (full0 != full1)
		return 1;
	return 0;
}

static int __logfs_write_rec(struct inode *inode, struct page *page,
		struct write_control *this_wc,
		pgoff_t bix, level_t target_level, level_t level)
{
	int ret, page_empty = 0;
	int child_no = get_bits(bix, SUBLEVEL(level));
	struct page *ipage;
	struct write_control child_wc = {
		.flags = this_wc->flags,
	};

	ipage = logfs_get_write_page(inode, bix, level);
	if (!ipage)
		return -ENOMEM;

	if (this_wc->ofs) {
		ret = logfs_segment_read(inode, ipage, this_wc->ofs, bix, level);
		if (ret)
			goto out;
	} else if (!PageUptodate(ipage)) {
		page_empty = 1;
		logfs_read_empty(ipage);
	}

	child_wc.ofs = block_get_pointer(ipage, child_no);

	if ((__force u8)level-1 > (__force u8)target_level)
		ret = __logfs_write_rec(inode, page, &child_wc, bix,
				target_level, SUBLEVEL(level));
	else
		ret = logfs_write_i0(inode, page, &child_wc);

	if (ret)
		goto out;

	alloc_indirect_block(inode, ipage, page_empty);
	block_set_pointer(ipage, child_no, child_wc.ofs);
	/* FIXME: first condition seems superfluous */
	if (child_wc.ofs || logfs_block(ipage)->partial)
		this_wc->flags |= WF_WRITE;
	/* the condition on this_wc->ofs ensures that we won't consume extra
	 * space for indirect blocks in the future, which we cannot reserve */
	if (!this_wc->ofs || ptr_change(this_wc->ofs, ipage))
		ret = logfs_write_i0(inode, ipage, this_wc);
	else
		logfs_set_alias(inode->i_sb, logfs_block(ipage), child_no);
out:
	logfs_put_write_page(ipage);
	return ret;
}

static int logfs_write_rec(struct inode *inode, struct page *page,
		pgoff_t bix, level_t target_level, long flags)
{
	struct logfs_inode *li = logfs_inode(inode);
	struct write_control wc = {
		.ofs = li->li_data[INDIRECT_INDEX],
		.flags = flags,
	};
	int ret;

	alloc_inode_block(inode);

	if (li->li_height > (__force u8)target_level)
		ret = __logfs_write_rec(inode, page, &wc, bix, target_level,
				LEVEL(li->li_height));
	else
		ret = logfs_write_i0(inode, page, &wc);
	if (ret)
		return ret;

	if (li->li_data[INDIRECT_INDEX] != wc.ofs) {
		li->li_data[INDIRECT_INDEX] = wc.ofs;
		logfs_set_alias(inode->i_sb, li->li_block,
				INDIRECT_INDEX + INODE_POINTER_OFS);
	}
	return ret;
}

void logfs_add_transaction(struct inode *inode, struct logfs_transaction *ta)
{
	alloc_inode_block(inode);
	logfs_inode(inode)->li_block->ta = ta;
}

void logfs_del_transaction(struct inode *inode, struct logfs_transaction *ta)
{
	struct logfs_block *block = logfs_inode(inode)->li_block;

	if (block && block->ta)
		block->ta = NULL;
}

static int grow_inode(struct inode *inode, u64 bix, level_t level)
{
	struct logfs_inode *li = logfs_inode(inode);
	u8 height = (__force u8)level;
	struct page *page;
	struct write_control wc = {
		.flags = WF_WRITE,
	};
	int err;

	BUG_ON(height > 5 || li->li_height > 5);
	while (height > li->li_height || bix >= maxbix(li->li_height)) {
		page = logfs_get_write_page(inode, I0_BLOCKS + 1,
				LEVEL(li->li_height + 1));
		if (!page)
			return -ENOMEM;
		logfs_read_empty(page);
		alloc_indirect_block(inode, page, 1);
		block_set_pointer(page, 0, li->li_data[INDIRECT_INDEX]);
		err = logfs_write_i0(inode, page, &wc);
		logfs_put_write_page(page);
		if (err)
			return err;
		li->li_data[INDIRECT_INDEX] = wc.ofs;
		wc.ofs = 0;
		li->li_height++;
		logfs_set_alias(inode->i_sb, li->li_block, INODE_HEIGHT_OFS);
	}
	return 0;
}

static int __logfs_write_buf(struct inode *inode, struct page *page, long flags)
{
	struct logfs_super *super = logfs_super(inode->i_sb);
	pgoff_t index = page->index;
	u64 bix;
	level_t level;
	int err;

	flags |= WF_WRITE | WF_DELETE;
	inode->i_ctime = inode->i_mtime = CURRENT_TIME;

	logfs_unpack_index(index, &bix, &level);
	if (logfs_block(page) && logfs_block(page)->reserved_bytes)
		super->s_dirty_pages -= logfs_block(page)->reserved_bytes;

	if (index < I0_BLOCKS)
		return logfs_write_direct(inode, page, flags);

	bix = adjust_bix(bix, level);
	err = grow_inode(inode, bix, level);
	if (err)
		return err;
	return logfs_write_rec(inode, page, bix, level, flags);
}

int logfs_write_buf(struct inode *inode, struct page *page, long flags)
{
	struct super_block *sb = inode->i_sb;
	int ret;

	logfs_get_wblocks(sb, page, flags & WF_LOCK);
	ret = __logfs_write_buf(inode, page, flags);
	logfs_put_wblocks(sb, page, flags & WF_LOCK);
	return ret;
}

static int __logfs_delete(struct inode *inode, struct page *page)
{
	long flags = WF_DELETE;
	int err;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME;

	if (page->index < I0_BLOCKS)
		return logfs_write_direct(inode, page, flags);
	err = grow_inode(inode, page->index, 0);
	if (err)
		return err;
	return logfs_write_rec(inode, page, page->index, 0, flags);
}

int logfs_delete(struct inode *inode, pgoff_t index,
		struct shadow_tree *shadow_tree)
{
	struct super_block *sb = inode->i_sb;
	struct page *page;
	int ret;

	page = logfs_get_read_page(inode, index, 0);
	if (!page)
		return -ENOMEM;

	logfs_get_wblocks(sb, page, 1);
	ret = __logfs_delete(inode, page);
	logfs_put_wblocks(sb, page, 1);

	logfs_put_read_page(page);

	return ret;
}

int logfs_rewrite_block(struct inode *inode, u64 bix, u64 ofs,
		gc_level_t gc_level, long flags)
{
	level_t level = shrink_level(gc_level);
	struct page *page;
	int err;

	page = logfs_get_write_page(inode, bix, level);
	if (!page)
		return -ENOMEM;

	err = logfs_segment_read(inode, page, ofs, bix, level);
	if (!err) {
		if (level != 0)
			alloc_indirect_block(inode, page, 0);
		err = logfs_write_buf(inode, page, flags);
		if (!err && shrink_level(gc_level) == 0) {
			/* Rewrite cannot mark the inode dirty but has to
			 * write it immediately.
			 * Q: Can't we just create an alias for the inode
			 * instead?  And if not, why not?
			 */
			if (inode->i_ino == LOGFS_INO_MASTER)
				logfs_write_anchor(inode->i_sb);
			else {
				err = __logfs_write_inode(inode, page, flags);
			}
		}
	}
	logfs_put_write_page(page);
	return err;
}

static int truncate_data_block(struct inode *inode, struct page *page,
		u64 ofs, struct logfs_shadow *shadow, u64 size)
{
	loff_t pageofs = page->index << inode->i_sb->s_blocksize_bits;
	u64 bix;
	level_t level;
	int err;

	/* Does truncation happen within this page? */
	if (size <= pageofs || size - pageofs >= PAGE_SIZE)
		return 0;

	logfs_unpack_index(page->index, &bix, &level);
	BUG_ON(level != 0);

	err = logfs_segment_read(inode, page, ofs, bix, level);
	if (err)
		return err;

	zero_user_segment(page, size - pageofs, PAGE_CACHE_SIZE);
	return logfs_segment_write(inode, page, shadow);
}

static int logfs_truncate_i0(struct inode *inode, struct page *page,
		struct write_control *wc, u64 size)
{
	struct logfs_shadow *shadow;
	u64 bix;
	level_t level;
	int err = 0;

	logfs_unpack_index(page->index, &bix, &level);
	BUG_ON(level != 0);
	shadow = alloc_shadow(inode, bix, level, wc->ofs);

	err = truncate_data_block(inode, page, wc->ofs, shadow, size);
	if (err) {
		free_shadow(inode, shadow);
		return err;
	}

	logfs_segment_delete(inode, shadow);
	set_iused(inode, shadow);
	fill_shadow_tree(inode, page, shadow);
	wc->ofs = shadow->new_ofs;
	return 0;
}

static int logfs_truncate_direct(struct inode *inode, u64 size)
{
	struct logfs_inode *li = logfs_inode(inode);
	struct write_control wc;
	struct page *page;
	int e;
	int err;

	alloc_inode_block(inode);

	for (e = I0_BLOCKS - 1; e >= 0; e--) {
		if (size > (e+1) * LOGFS_BLOCKSIZE)
			break;

		wc.ofs = li->li_data[e];
		if (!wc.ofs)
			continue;

		page = logfs_get_write_page(inode, e, 0);
		if (!page)
			return -ENOMEM;
		err = logfs_segment_read(inode, page, wc.ofs, e, 0);
		if (err) {
			logfs_put_write_page(page);
			return err;
		}
		err = logfs_truncate_i0(inode, page, &wc, size);
		logfs_put_write_page(page);
		if (err)
			return err;

		li->li_data[e] = wc.ofs;
	}
	return 0;
}

/* FIXME: these need to become per-sb once we support different blocksizes */
static u64 __logfs_step[] = {
	1,
	I1_BLOCKS,
	I2_BLOCKS,
	I3_BLOCKS,
};

static u64 __logfs_start_index[] = {
	I0_BLOCKS,
	I1_BLOCKS,
	I2_BLOCKS,
	I3_BLOCKS
};

static inline u64 logfs_step(level_t level)
{
	return __logfs_step[(__force u8)level];
}

static inline u64 logfs_factor(u8 level)
{
	return __logfs_step[level] * LOGFS_BLOCKSIZE;
}

static inline u64 logfs_start_index(level_t level)
{
	return __logfs_start_index[(__force u8)level];
}

static void logfs_unpack_raw_index(pgoff_t index, u64 *bix, level_t *level)
{
	logfs_unpack_index(index, bix, level);
	if (*bix <= logfs_start_index(SUBLEVEL(*level)))
		*bix = 0;
}

static int __logfs_truncate_rec(struct inode *inode, struct page *ipage,
		struct write_control *this_wc, u64 size)
{
	int truncate_happened = 0;
	int e, err = 0;
	u64 bix, child_bix, next_bix;
	level_t level;
	struct page *page;
	struct write_control child_wc = { /* FIXME: flags */ };

	logfs_unpack_raw_index(ipage->index, &bix, &level);
	err = logfs_segment_read(inode, ipage, this_wc->ofs, bix, level);
	if (err)
		return err;

	for (e = LOGFS_BLOCK_FACTOR - 1; e >= 0; e--) {
		child_bix = bix + e * logfs_step(SUBLEVEL(level));
		next_bix = child_bix + logfs_step(SUBLEVEL(level));
		if (size > next_bix * LOGFS_BLOCKSIZE)
			break;

		child_wc.ofs = pure_ofs(block_get_pointer(ipage, e));
		if (!child_wc.ofs)
			continue;

		page = logfs_get_write_page(inode, child_bix, SUBLEVEL(level));
		if (!page)
			return -ENOMEM;

		if ((__force u8)level > 1)
			err = __logfs_truncate_rec(inode, page, &child_wc, size);
		else
			err = logfs_truncate_i0(inode, page, &child_wc, size);
		logfs_put_write_page(page);
		if (err)
			return err;

		truncate_happened = 1;
		alloc_indirect_block(inode, ipage, 0);
		block_set_pointer(ipage, e, child_wc.ofs);
	}

	if (!truncate_happened) {
		printk("ineffectual truncate (%lx, %lx, %llx)\n", inode->i_ino, ipage->index, size);
		return 0;
	}

	this_wc->flags = WF_DELETE;
	if (logfs_block(ipage)->partial)
		this_wc->flags |= WF_WRITE;

	return logfs_write_i0(inode, ipage, this_wc);
}

static int logfs_truncate_rec(struct inode *inode, u64 size)
{
	struct logfs_inode *li = logfs_inode(inode);
	struct write_control wc = {
		.ofs = li->li_data[INDIRECT_INDEX],
	};
	struct page *page;
	int err;

	alloc_inode_block(inode);

	if (!wc.ofs)
		return 0;

	page = logfs_get_write_page(inode, 0, LEVEL(li->li_height));
	if (!page)
		return -ENOMEM;

	err = __logfs_truncate_rec(inode, page, &wc, size);
	logfs_put_write_page(page);
	if (err)
		return err;

	if (li->li_data[INDIRECT_INDEX] != wc.ofs)
		li->li_data[INDIRECT_INDEX] = wc.ofs;
	return 0;
}

static int __logfs_truncate(struct inode *inode, u64 size)
{
	int ret;

	if (size >= logfs_factor(logfs_inode(inode)->li_height))
		return 0;

	ret = logfs_truncate_rec(inode, size);
	if (ret)
		return ret;

	return logfs_truncate_direct(inode, size);
}

/*
 * Truncate, by changing the segment file, can consume a fair amount
 * of resources.  So back off from time to time and do some GC.
 * 8 or 2048 blocks should be well within safety limits even if
 * every single block resided in a different segment.
 */
#define TRUNCATE_STEP	(8 * 1024 * 1024)
int logfs_truncate(struct inode *inode, u64 target)
{
	struct super_block *sb = inode->i_sb;
	u64 size = i_size_read(inode);
	int err = 0;

	size = ALIGN(size, TRUNCATE_STEP);
	while (size > target) {
		if (size > TRUNCATE_STEP)
			size -= TRUNCATE_STEP;
		else
			size = 0;
		if (size < target)
			size = target;

		logfs_get_wblocks(sb, NULL, 1);
		err = __logfs_truncate(inode, size);
		if (!err)
			err = __logfs_write_inode(inode, NULL, 0);
		logfs_put_wblocks(sb, NULL, 1);
	}

	if (!err) {
		err = inode_newsize_ok(inode, target);
		if (err)
			goto out;

		truncate_setsize(inode, target);
	}

 out:
	/* I don't trust error recovery yet. */
	WARN_ON(err);
	return err;
}

static void move_page_to_inode(struct inode *inode, struct page *page)
{
	struct logfs_inode *li = logfs_inode(inode);
	struct logfs_block *block = logfs_block(page);

	if (!block)
		return;

	log_blockmove("move_page_to_inode(%llx, %llx, %x)\n",
			block->ino, block->bix, block->level);
	BUG_ON(li->li_block);
	block->ops = &inode_block_ops;
	block->inode = inode;
	li->li_block = block;

	block->page = NULL;
	if (PagePrivate(page)) {
		ClearPagePrivate(page);
		page_cache_release(page);
		set_page_private(page, 0);
	}
}

static void move_inode_to_page(struct page *page, struct inode *inode)
{
	struct logfs_inode *li = logfs_inode(inode);
	struct logfs_block *block = li->li_block;

	if (!block)
		return;

	log_blockmove("move_inode_to_page(%llx, %llx, %x)\n",
			block->ino, block->bix, block->level);
	BUG_ON(PagePrivate(page));
	block->ops = &indirect_block_ops;
	block->page = page;

	if (!PagePrivate(page)) {
		SetPagePrivate(page);
		page_cache_get(page);
		set_page_private(page, (unsigned long) block);
	}

	block->inode = NULL;
	li->li_block = NULL;
}

int logfs_read_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct logfs_super *super = logfs_super(sb);
	struct inode *master_inode = super->s_master_inode;
	struct page *page;
	struct logfs_disk_inode *di;
	u64 ino = inode->i_ino;

	if (ino << sb->s_blocksize_bits > i_size_read(master_inode))
		return -ENODATA;
	if (!logfs_exist_block(master_inode, ino))
		return -ENODATA;

	page = read_cache_page(master_inode->i_mapping, ino,
			(filler_t *)logfs_readpage, NULL);
	if (IS_ERR(page))
		return PTR_ERR(page);

	di = kmap_atomic(page);
	logfs_disk_to_inode(di, inode);
	kunmap_atomic(di);
	move_page_to_inode(inode, page);
	page_cache_release(page);
	return 0;
}

/* Caller must logfs_put_write_page(page); */
static struct page *inode_to_page(struct inode *inode)
{
	struct inode *master_inode = logfs_super(inode->i_sb)->s_master_inode;
	struct logfs_disk_inode *di;
	struct page *page;

	BUG_ON(inode->i_ino == LOGFS_INO_MASTER);

	page = logfs_get_write_page(master_inode, inode->i_ino, 0);
	if (!page)
		return NULL;

	di = kmap_atomic(page);
	logfs_inode_to_disk(inode, di);
	kunmap_atomic(di);
	move_inode_to_page(page, inode);
	return page;
}

static int do_write_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct inode *master_inode = logfs_super(sb)->s_master_inode;
	loff_t size = (inode->i_ino + 1) << inode->i_sb->s_blocksize_bits;
	struct page *page;
	int err;

	BUG_ON(inode->i_ino == LOGFS_INO_MASTER);
	/* FIXME: lock inode */

	if (i_size_read(master_inode) < size)
		i_size_write(master_inode, size);

	/* TODO: Tell vfs this inode is clean now */

	page = inode_to_page(inode);
	if (!page)
		return -ENOMEM;

	/* FIXME: transaction is part of logfs_block now.  Is that enough? */
	err = logfs_write_buf(master_inode, page, 0);
	if (err)
		move_page_to_inode(inode, page);

	logfs_put_write_page(page);
	return err;
}

static void logfs_mod_segment_entry(struct super_block *sb, u32 segno,
		int write,
		void (*change_se)(struct logfs_segment_entry *, long),
		long arg)
{
	struct logfs_super *super = logfs_super(sb);
	struct inode *inode;
	struct page *page;
	struct logfs_segment_entry *se;
	pgoff_t page_no;
	int child_no;

	page_no = segno >> (sb->s_blocksize_bits - 3);
	child_no = segno & ((sb->s_blocksize >> 3) - 1);

	inode = super->s_segfile_inode;
	page = logfs_get_write_page(inode, page_no, 0);
	BUG_ON(!page); /* FIXME: We need some reserve page for this case */
	if (!PageUptodate(page))
		logfs_read_block(inode, page, WRITE);

	if (write)
		alloc_indirect_block(inode, page, 0);
	se = kmap_atomic(page);
	change_se(se + child_no, arg);
	if (write) {
		logfs_set_alias(sb, logfs_block(page), child_no);
		BUG_ON((int)be32_to_cpu(se[child_no].valid) > super->s_segsize);
	}
	kunmap_atomic(se);

	logfs_put_write_page(page);
}

static void __get_segment_entry(struct logfs_segment_entry *se, long _target)
{
	struct logfs_segment_entry *target = (void *)_target;

	*target = *se;
}

void logfs_get_segment_entry(struct super_block *sb, u32 segno,
		struct logfs_segment_entry *se)
{
	logfs_mod_segment_entry(sb, segno, 0, __get_segment_entry, (long)se);
}

static void __set_segment_used(struct logfs_segment_entry *se, long increment)
{
	u32 valid;

	valid = be32_to_cpu(se->valid);
	valid += increment;
	se->valid = cpu_to_be32(valid);
}

void logfs_set_segment_used(struct super_block *sb, u64 ofs, int increment)
{
	struct logfs_super *super = logfs_super(sb);
	u32 segno = ofs >> super->s_segshift;

	if (!increment)
		return;

	logfs_mod_segment_entry(sb, segno, 1, __set_segment_used, increment);
}

static void __set_segment_erased(struct logfs_segment_entry *se, long ec_level)
{
	se->ec_level = cpu_to_be32(ec_level);
}

void logfs_set_segment_erased(struct super_block *sb, u32 segno, u32 ec,
		gc_level_t gc_level)
{
	u32 ec_level = ec << 4 | (__force u8)gc_level;

	logfs_mod_segment_entry(sb, segno, 1, __set_segment_erased, ec_level);
}

static void __set_segment_reserved(struct logfs_segment_entry *se, long ignore)
{
	se->valid = cpu_to_be32(RESERVED);
}

void logfs_set_segment_reserved(struct super_block *sb, u32 segno)
{
	logfs_mod_segment_entry(sb, segno, 1, __set_segment_reserved, 0);
}

static void __set_segment_unreserved(struct logfs_segment_entry *se,
		long ec_level)
{
	se->valid = 0;
	se->ec_level = cpu_to_be32(ec_level);
}

void logfs_set_segment_unreserved(struct super_block *sb, u32 segno, u32 ec)
{
	u32 ec_level = ec << 4;

	logfs_mod_segment_entry(sb, segno, 1, __set_segment_unreserved,
			ec_level);
}

int __logfs_write_inode(struct inode *inode, struct page *page, long flags)
{
	struct super_block *sb = inode->i_sb;
	int ret;

	logfs_get_wblocks(sb, page, flags & WF_LOCK);
	ret = do_write_inode(inode);
	logfs_put_wblocks(sb, page, flags & WF_LOCK);
	return ret;
}

static int do_delete_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct inode *master_inode = logfs_super(sb)->s_master_inode;
	struct page *page;
	int ret;

	page = logfs_get_write_page(master_inode, inode->i_ino, 0);
	if (!page)
		return -ENOMEM;

	move_inode_to_page(page, inode);

	logfs_get_wblocks(sb, page, 1);
	ret = __logfs_delete(master_inode, page);
	logfs_put_wblocks(sb, page, 1);

	logfs_put_write_page(page);
	return ret;
}

/*
 * ZOMBIE inodes have already been deleted before and should remain dead,
 * if it weren't for valid checking.  No need to kill them again here.
 */
void logfs_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct logfs_inode *li = logfs_inode(inode);
	struct logfs_block *block = li->li_block;
	struct page *page;

	if (!inode->i_nlink) {
		if (!(li->li_flags & LOGFS_IF_ZOMBIE)) {
			li->li_flags |= LOGFS_IF_ZOMBIE;
			if (i_size_read(inode) > 0)
				logfs_truncate(inode, 0);
			do_delete_inode(inode);
		}
	}
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	/* Cheaper version of write_inode.  All changes are concealed in
	 * aliases, which are moved back.  No write to the medium happens.
	 */
	/* Only deleted files may be dirty at this point */
	BUG_ON(inode->i_state & I_DIRTY && inode->i_nlink);
	if (!block)
		return;
	if ((logfs_super(sb)->s_flags & LOGFS_SB_FLAG_SHUTDOWN)) {
		block->ops->free_block(inode->i_sb, block);
		return;
	}

	page = inode_to_page(inode);
	BUG_ON(!page); /* FIXME: Use emergency page */
	logfs_put_write_page(page);
}

void btree_write_block(struct logfs_block *block)
{
	struct inode *inode;
	struct page *page;
	int err, cookie;

	inode = logfs_safe_iget(block->sb, block->ino, &cookie);
	page = logfs_get_write_page(inode, block->bix, block->level);

	err = logfs_readpage_nolock(page);
	BUG_ON(err);
	BUG_ON(!PagePrivate(page));
	BUG_ON(logfs_block(page) != block);
	err = __logfs_write_buf(inode, page, 0);
	BUG_ON(err);
	BUG_ON(PagePrivate(page) || page->private);

	logfs_put_write_page(page);
	logfs_safe_iput(inode, cookie);
}

/**
 * logfs_inode_write - write inode or dentry objects
 *
 * @inode:		parent inode (ifile or directory)
 * @buf:		object to write (inode or dentry)
 * @count:		object size
 * @bix:		block index
 * @flags:		write flags
 * @shadow_tree:	shadow below this inode
 *
 * FIXME: All caller of this put a 200-300 byte variable on the stack,
 * only to call here and do a memcpy from that stack variable.  A good
 * example of wasted performance and stack space.
 */
int logfs_inode_write(struct inode *inode, const void *buf, size_t count,
		loff_t bix, long flags, struct shadow_tree *shadow_tree)
{
	loff_t pos = bix << inode->i_sb->s_blocksize_bits;
	int err;
	struct page *page;
	void *pagebuf;

	BUG_ON(pos & (LOGFS_BLOCKSIZE-1));
	BUG_ON(count > LOGFS_BLOCKSIZE);
	page = logfs_get_write_page(inode, bix, 0);
	if (!page)
		return -ENOMEM;

	pagebuf = kmap_atomic(page);
	memcpy(pagebuf, buf, count);
	flush_dcache_page(page);
	kunmap_atomic(pagebuf);

	if (i_size_read(inode) < pos + LOGFS_BLOCKSIZE)
		i_size_write(inode, pos + LOGFS_BLOCKSIZE);

	err = logfs_write_buf(inode, page, flags);
	logfs_put_write_page(page);
	return err;
}

int logfs_open_segfile(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct inode *inode;

	inode = logfs_read_meta_inode(sb, LOGFS_INO_SEGFILE);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	super->s_segfile_inode = inode;
	return 0;
}

int logfs_init_rw(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int min_fill = 3 * super->s_no_blocks;

	INIT_LIST_HEAD(&super->s_object_alias);
	INIT_LIST_HEAD(&super->s_writeback_list);
	mutex_init(&super->s_write_mutex);
	super->s_block_pool = mempool_create_kmalloc_pool(min_fill,
			sizeof(struct logfs_block));
	super->s_shadow_pool = mempool_create_kmalloc_pool(min_fill,
			sizeof(struct logfs_shadow));
	return 0;
}

void logfs_cleanup_rw(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);

	logfs_mempool_destroy(super->s_block_pool);
	logfs_mempool_destroy(super->s_shadow_pool);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/readwrite.c */
/************************************************************/
/*
 * fs/logfs/segment.c	- Handling the Object Store
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 *
 * Object store or ostore makes up the complete device with exception of
 * the superblock and journal areas.  Apart from its own metadata it stores
 * three kinds of objects: inodes, dentries and blocks, both data and indirect.
 */
// #include "logfs.h"
// #include <linux/slab.h>

static int logfs_mark_segment_bad_segment_c(struct super_block *sb, u32 segno)
{
	struct logfs_super *super = logfs_super(sb);
	struct btree_head32 *head = &super->s_reserved_segments;
	int err;

	err = btree_insert32(head, segno, (void *)1, GFP_NOFS);
	if (err)
		return err;
	logfs_super(sb)->s_bad_segments++;
	/* FIXME: write to journal */
	return 0;
}

int logfs_erase_segment(struct super_block *sb, u32 segno, int ensure_erase)
{
	struct logfs_super *super = logfs_super(sb);

	super->s_gec++;

	return super->s_devops->erase(sb, (u64)segno << super->s_segshift,
			super->s_segsize, ensure_erase);
}

static s64 logfs_get_free_bytes(struct logfs_area *area, size_t bytes)
{
	s32 ofs;

	logfs_open_area(area, bytes);

	ofs = area->a_used_bytes;
	area->a_used_bytes += bytes;
	BUG_ON(area->a_used_bytes >= logfs_super(area->a_sb)->s_segsize);

	return dev_ofs(area->a_sb, area->a_segno, ofs);
}

static struct page *get_mapping_page(struct super_block *sb, pgoff_t index,
		int use_filler)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	filler_t *filler = super->s_devops->readpage;
	struct page *page;

	BUG_ON(mapping_gfp_mask(mapping) & __GFP_FS);
	if (use_filler)
		page = read_cache_page(mapping, index, filler, sb);
	else {
		page = find_or_create_page(mapping, index, GFP_NOFS);
		if (page)
			unlock_page(page);
	}
	return page;
}

int __logfs_buf_write(struct logfs_area *area, u64 ofs, void *buf, size_t len,
		int use_filler)
{
	pgoff_t index = ofs >> PAGE_SHIFT;
	struct page *page;
	long offset = ofs & (PAGE_SIZE-1);
	long copylen;

	/* Only logfs_wbuf_recover may use len==0 */
	BUG_ON(!len && !use_filler);
	do {
		copylen = min((ulong)len, PAGE_SIZE - offset);

		page = get_mapping_page(area->a_sb, index, use_filler);
		if (IS_ERR(page))
			return PTR_ERR(page);
		BUG_ON(!page); /* FIXME: reserve a pool */
		SetPageUptodate(page);
		memcpy(page_address(page) + offset, buf, copylen);

		if (!PagePrivate(page)) {
			SetPagePrivate(page);
			page_cache_get(page);
		}
		page_cache_release(page);

		buf += copylen;
		len -= copylen;
		offset = 0;
		index++;
	} while (len);
	return 0;
}

static void pad_partial_page(struct logfs_area *area)
{
	struct super_block *sb = area->a_sb;
	struct page *page;
	u64 ofs = dev_ofs(sb, area->a_segno, area->a_used_bytes);
	pgoff_t index = ofs >> PAGE_SHIFT;
	long offset = ofs & (PAGE_SIZE-1);
	u32 len = PAGE_SIZE - offset;

	if (len % PAGE_SIZE) {
		page = get_mapping_page(sb, index, 0);
		BUG_ON(!page); /* FIXME: reserve a pool */
		memset(page_address(page) + offset, 0xff, len);
		if (!PagePrivate(page)) {
			SetPagePrivate(page);
			page_cache_get(page);
		}
		page_cache_release(page);
	}
}

static void pad_full_pages(struct logfs_area *area)
{
	struct super_block *sb = area->a_sb;
	struct logfs_super *super = logfs_super(sb);
	u64 ofs = dev_ofs(sb, area->a_segno, area->a_used_bytes);
	u32 len = super->s_segsize - area->a_used_bytes;
	pgoff_t index = PAGE_CACHE_ALIGN(ofs) >> PAGE_CACHE_SHIFT;
	pgoff_t no_indizes = len >> PAGE_CACHE_SHIFT;
	struct page *page;

	while (no_indizes) {
		page = get_mapping_page(sb, index, 0);
		BUG_ON(!page); /* FIXME: reserve a pool */
		SetPageUptodate(page);
		memset(page_address(page), 0xff, PAGE_CACHE_SIZE);
		if (!PagePrivate(page)) {
			SetPagePrivate(page);
			page_cache_get(page);
		}
		page_cache_release(page);
		index++;
		no_indizes--;
	}
}

/*
 * bdev_writeseg will write full pages.  Memset the tail to prevent data leaks.
 * Also make sure we allocate (and memset) all pages for final writeout.
 */
static void pad_wbuf(struct logfs_area *area, int final)
{
	pad_partial_page(area);
	if (final)
		pad_full_pages(area);
}

/*
 * We have to be careful with the alias tree.  Since lookup is done by bix,
 * it needs to be normalized, so 14, 15, 16, etc. all match when dealing with
 * indirect blocks.  So always use it through accessor functions.
 */
static void *alias_tree_lookup(struct super_block *sb, u64 ino, u64 bix,
		level_t level)
{
	struct btree_head128 *head = &logfs_super(sb)->s_object_alias_tree;
	pgoff_t index = logfs_pack_index(bix, level);

	return btree_lookup128(head, ino, index);
}

static int alias_tree_insert(struct super_block *sb, u64 ino, u64 bix,
		level_t level, void *val)
{
	struct btree_head128 *head = &logfs_super(sb)->s_object_alias_tree;
	pgoff_t index = logfs_pack_index(bix, level);

	return btree_insert128(head, ino, index, val, GFP_NOFS);
}

static int btree_write_alias(struct super_block *sb, struct logfs_block *block,
		write_alias_t *write_one_alias)
{
	struct object_alias_item *item;
	int err;

	list_for_each_entry(item, &block->item_list, list) {
		err = write_alias_journal(sb, block->ino, block->bix,
				block->level, item->child_no, item->val);
		if (err)
			return err;
	}
	return 0;
}

static struct logfs_block_ops btree_block_ops = {
	.write_block	= btree_write_block,
	.free_block	= __free_block,
	.write_alias	= btree_write_alias,
};

int logfs_load_object_aliases(struct super_block *sb,
		struct logfs_obj_alias *oa, int count)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_block *block;
	struct object_alias_item *item;
	u64 ino, bix;
	level_t level;
	int i, err;

	super->s_flags |= LOGFS_SB_FLAG_OBJ_ALIAS;
	count /= sizeof(*oa);
	for (i = 0; i < count; i++) {
		item = mempool_alloc(super->s_alias_pool, GFP_NOFS);
		if (!item)
			return -ENOMEM;
		memset(item, 0, sizeof(*item));

		super->s_no_object_aliases++;
		item->val = oa[i].val;
		item->child_no = be16_to_cpu(oa[i].child_no);

		ino = be64_to_cpu(oa[i].ino);
		bix = be64_to_cpu(oa[i].bix);
		level = LEVEL(oa[i].level);

		log_aliases("logfs_load_object_aliases(%llx, %llx, %x, %x) %llx\n",
				ino, bix, level, item->child_no,
				be64_to_cpu(item->val));
		block = alias_tree_lookup(sb, ino, bix, level);
		if (!block) {
			block = __alloc_block(sb, ino, bix, level);
			block->ops = &btree_block_ops;
			err = alias_tree_insert(sb, ino, bix, level, block);
			BUG_ON(err); /* mempool empty */
		}
		if (test_and_set_bit(item->child_no, block->alias_map)) {
			printk(KERN_ERR"LogFS: Alias collision detected\n");
			return -EIO;
		}
		list_move_tail(&block->alias_list, &super->s_object_alias);
		list_add(&item->list, &block->item_list);
	}
	return 0;
}

static void kill_alias(void *_block, unsigned long ignore0,
		u64 ignore1, u64 ignore2, size_t ignore3)
{
	struct logfs_block *block = _block;
	struct super_block *sb = block->sb;
	struct logfs_super *super = logfs_super(sb);
	struct object_alias_item *item;

	while (!list_empty(&block->item_list)) {
		item = list_entry(block->item_list.next, typeof(*item), list);
		list_del(&item->list);
		mempool_free(item, super->s_alias_pool);
	}
	block->ops->free_block(sb, block);
}

static int obj_type(struct inode *inode, level_t level)
{
	if (level == 0) {
		if (S_ISDIR(inode->i_mode))
			return OBJ_DENTRY;
		if (inode->i_ino == LOGFS_INO_MASTER)
			return OBJ_INODE;
	}
	return OBJ_BLOCK;
}

static int obj_len(struct super_block *sb, int obj_type)
{
	switch (obj_type) {
	case OBJ_DENTRY:
		return sizeof(struct logfs_disk_dentry);
	case OBJ_INODE:
		return sizeof(struct logfs_disk_inode);
	case OBJ_BLOCK:
		return sb->s_blocksize;
	default:
		BUG();
	}
}

static int __logfs_segment_write(struct inode *inode, void *buf,
		struct logfs_shadow *shadow, int type, int len, int compr)
{
	struct logfs_area *area;
	struct super_block *sb = inode->i_sb;
	s64 ofs;
	struct logfs_object_header h;
	int acc_len;

	if (shadow->gc_level == 0)
		acc_len = len;
	else
		acc_len = obj_len(sb, type);

	area = get_area(sb, shadow->gc_level);
	ofs = logfs_get_free_bytes(area, len + LOGFS_OBJECT_HEADERSIZE);
	LOGFS_BUG_ON(ofs <= 0, sb);
	/*
	 * Order is important.  logfs_get_free_bytes(), by modifying the
	 * segment file, may modify the content of the very page we're about
	 * to write now.  Which is fine, as long as the calculated crc and
	 * written data still match.  So do the modifications _before_
	 * calculating the crc.
	 */

	h.len	= cpu_to_be16(len);
	h.type	= type;
	h.compr	= compr;
	h.ino	= cpu_to_be64(inode->i_ino);
	h.bix	= cpu_to_be64(shadow->bix);
	h.crc	= logfs_crc32(&h, sizeof(h) - 4, 4);
	h.data_crc = logfs_crc32(buf, len, 0);

	logfs_buf_write(area, ofs, &h, sizeof(h));
	logfs_buf_write(area, ofs + LOGFS_OBJECT_HEADERSIZE, buf, len);

	shadow->new_ofs = ofs;
	shadow->new_len = acc_len + LOGFS_OBJECT_HEADERSIZE;

	return 0;
}

static s64 logfs_segment_write_compress(struct inode *inode, void *buf,
		struct logfs_shadow *shadow, int type, int len)
{
	struct super_block *sb = inode->i_sb;
	void *compressor_buf = logfs_super(sb)->s_compressed_je;
	ssize_t compr_len;
	int ret;

	mutex_lock(&logfs_super(sb)->s_journal_mutex);
	compr_len = logfs_compress(buf, compressor_buf, len, len);

	if (compr_len >= 0) {
		ret = __logfs_segment_write(inode, compressor_buf, shadow,
				type, compr_len, COMPR_ZLIB);
	} else {
		ret = __logfs_segment_write(inode, buf, shadow, type, len,
				COMPR_NONE);
	}
	mutex_unlock(&logfs_super(sb)->s_journal_mutex);
	return ret;
}

/**
 * logfs_segment_write - write data block to object store
 * @inode:		inode containing data
 *
 * Returns an errno or zero.
 */
int logfs_segment_write(struct inode *inode, struct page *page,
		struct logfs_shadow *shadow)
{
	struct super_block *sb = inode->i_sb;
	struct logfs_super *super = logfs_super(sb);
	int do_compress, type, len;
	int ret;
	void *buf;

	super->s_flags |= LOGFS_SB_FLAG_DIRTY;
	BUG_ON(super->s_flags & LOGFS_SB_FLAG_SHUTDOWN);
	do_compress = logfs_inode(inode)->li_flags & LOGFS_IF_COMPRESSED;
	if (shadow->gc_level != 0) {
		/* temporarily disable compression for indirect blocks */
		do_compress = 0;
	}

	type = obj_type(inode, shrink_level(shadow->gc_level));
	len = obj_len(sb, type);
	buf = kmap(page);
	if (do_compress)
		ret = logfs_segment_write_compress(inode, buf, shadow, type,
				len);
	else
		ret = __logfs_segment_write(inode, buf, shadow, type, len,
				COMPR_NONE);
	kunmap(page);

	log_segment("logfs_segment_write(%llx, %llx, %x) %llx->%llx %x->%x\n",
			shadow->ino, shadow->bix, shadow->gc_level,
			shadow->old_ofs, shadow->new_ofs,
			shadow->old_len, shadow->new_len);
	/* this BUG_ON did catch a locking bug.  useful */
	BUG_ON(!(shadow->new_ofs & (super->s_segsize - 1)));
	return ret;
}

int wbuf_read(struct super_block *sb, u64 ofs, size_t len, void *buf)
{
	pgoff_t index = ofs >> PAGE_SHIFT;
	struct page *page;
	long offset = ofs & (PAGE_SIZE-1);
	long copylen;

	while (len) {
		copylen = min((ulong)len, PAGE_SIZE - offset);

		page = get_mapping_page(sb, index, 1);
		if (IS_ERR(page))
			return PTR_ERR(page);
		memcpy(buf, page_address(page) + offset, copylen);
		page_cache_release(page);

		buf += copylen;
		len -= copylen;
		offset = 0;
		index++;
	}
	return 0;
}

/*
 * The "position" of indirect blocks is ambiguous.  It can be the position
 * of any data block somewhere behind this indirect block.  So we need to
 * normalize the positions through logfs_block_mask() before comparing.
 */
static int check_pos(struct super_block *sb, u64 pos1, u64 pos2, level_t level)
{
	return	(pos1 & logfs_block_mask(sb, level)) !=
		(pos2 & logfs_block_mask(sb, level));
}

#if 0
static int read_seg_header(struct super_block *sb, u64 ofs,
		struct logfs_segment_header *sh)
{
	__be32 crc;
	int err;

	err = wbuf_read(sb, ofs, sizeof(*sh), sh);
	if (err)
		return err;
	crc = logfs_crc32(sh, sizeof(*sh), 4);
	if (crc != sh->crc) {
		printk(KERN_ERR"LOGFS: header crc error at %llx: expected %x, "
				"got %x\n", ofs, be32_to_cpu(sh->crc),
				be32_to_cpu(crc));
		return -EIO;
	}
	return 0;
}
#endif

static int read_obj_header(struct super_block *sb, u64 ofs,
		struct logfs_object_header *oh)
{
	__be32 crc;
	int err;

	err = wbuf_read(sb, ofs, sizeof(*oh), oh);
	if (err)
		return err;
	crc = logfs_crc32(oh, sizeof(*oh) - 4, 4);
	if (crc != oh->crc) {
		printk(KERN_ERR"LOGFS: header crc error at %llx: expected %x, "
				"got %x\n", ofs, be32_to_cpu(oh->crc),
				be32_to_cpu(crc));
		return -EIO;
	}
	return 0;
}

static void move_btree_to_page(struct inode *inode, struct page *page,
		__be64 *data)
{
	struct super_block *sb = inode->i_sb;
	struct logfs_super *super = logfs_super(sb);
	struct btree_head128 *head = &super->s_object_alias_tree;
	struct logfs_block *block;
	struct object_alias_item *item, *next;

	if (!(super->s_flags & LOGFS_SB_FLAG_OBJ_ALIAS))
		return;

	block = btree_remove128(head, inode->i_ino, page->index);
	if (!block)
		return;

	log_blockmove("move_btree_to_page(%llx, %llx, %x)\n",
			block->ino, block->bix, block->level);
	list_for_each_entry_safe(item, next, &block->item_list, list) {
		data[item->child_no] = item->val;
		list_del(&item->list);
		mempool_free(item, super->s_alias_pool);
	}
	block->page = page;

	if (!PagePrivate(page)) {
		SetPagePrivate(page);
		page_cache_get(page);
		set_page_private(page, (unsigned long) block);
	}
	block->ops = &indirect_block_ops;
	initialize_block_counters(page, block, data, 0);
}

/*
 * This silences a false, yet annoying gcc warning.  I hate it when my editor
 * jumps into bitops.h each time I recompile this file.
 * TODO: Complain to gcc folks about this and upgrade compiler.
 */
static unsigned long fnb(const unsigned long *addr,
		unsigned long size, unsigned long offset)
{
	return find_next_bit(addr, size, offset);
}

void move_page_to_btree(struct page *page)
{
	struct logfs_block *block = logfs_block(page);
	struct super_block *sb = block->sb;
	struct logfs_super *super = logfs_super(sb);
	struct object_alias_item *item;
	unsigned long pos;
	__be64 *child;
	int err;

	if (super->s_flags & LOGFS_SB_FLAG_SHUTDOWN) {
		block->ops->free_block(sb, block);
		return;
	}
	log_blockmove("move_page_to_btree(%llx, %llx, %x)\n",
			block->ino, block->bix, block->level);
	super->s_flags |= LOGFS_SB_FLAG_OBJ_ALIAS;

	for (pos = 0; ; pos++) {
		pos = fnb(block->alias_map, LOGFS_BLOCK_FACTOR, pos);
		if (pos >= LOGFS_BLOCK_FACTOR)
			break;

		item = mempool_alloc(super->s_alias_pool, GFP_NOFS);
		BUG_ON(!item); /* mempool empty */
		memset(item, 0, sizeof(*item));

		child = kmap_atomic(page);
		item->val = child[pos];
		kunmap_atomic(child);
		item->child_no = pos;
		list_add(&item->list, &block->item_list);
	}
	block->page = NULL;

	if (PagePrivate(page)) {
		ClearPagePrivate(page);
		page_cache_release(page);
		set_page_private(page, 0);
	}
	block->ops = &btree_block_ops;
	err = alias_tree_insert(block->sb, block->ino, block->bix, block->level,
			block);
	BUG_ON(err); /* mempool empty */
	ClearPageUptodate(page);
}

static int __logfs_segment_read(struct inode *inode, void *buf,
		u64 ofs, u64 bix, level_t level)
{
	struct super_block *sb = inode->i_sb;
	void *compressor_buf = logfs_super(sb)->s_compressed_je;
	struct logfs_object_header oh;
	__be32 crc;
	u16 len;
	int err, block_len;

	block_len = obj_len(sb, obj_type(inode, level));
	err = read_obj_header(sb, ofs, &oh);
	if (err)
		goto out_err;

	err = -EIO;
	if (be64_to_cpu(oh.ino) != inode->i_ino
			|| check_pos(sb, be64_to_cpu(oh.bix), bix, level)) {
		printk(KERN_ERR"LOGFS: (ino, bix) don't match at %llx: "
				"expected (%lx, %llx), got (%llx, %llx)\n",
				ofs, inode->i_ino, bix,
				be64_to_cpu(oh.ino), be64_to_cpu(oh.bix));
		goto out_err;
	}

	len = be16_to_cpu(oh.len);

	switch (oh.compr) {
	case COMPR_NONE:
		err = wbuf_read(sb, ofs + LOGFS_OBJECT_HEADERSIZE, len, buf);
		if (err)
			goto out_err;
		crc = logfs_crc32(buf, len, 0);
		if (crc != oh.data_crc) {
			printk(KERN_ERR"LOGFS: uncompressed data crc error at "
					"%llx: expected %x, got %x\n", ofs,
					be32_to_cpu(oh.data_crc),
					be32_to_cpu(crc));
			goto out_err;
		}
		break;
	case COMPR_ZLIB:
		mutex_lock(&logfs_super(sb)->s_journal_mutex);
		err = wbuf_read(sb, ofs + LOGFS_OBJECT_HEADERSIZE, len,
				compressor_buf);
		if (err) {
			mutex_unlock(&logfs_super(sb)->s_journal_mutex);
			goto out_err;
		}
		crc = logfs_crc32(compressor_buf, len, 0);
		if (crc != oh.data_crc) {
			printk(KERN_ERR"LOGFS: compressed data crc error at "
					"%llx: expected %x, got %x\n", ofs,
					be32_to_cpu(oh.data_crc),
					be32_to_cpu(crc));
			mutex_unlock(&logfs_super(sb)->s_journal_mutex);
			goto out_err;
		}
		err = logfs_uncompress(compressor_buf, buf, len, block_len);
		mutex_unlock(&logfs_super(sb)->s_journal_mutex);
		if (err) {
			printk(KERN_ERR"LOGFS: uncompress error at %llx\n", ofs);
			goto out_err;
		}
		break;
	default:
		LOGFS_BUG(sb);
		err = -EIO;
		goto out_err;
	}
	return 0;

out_err:
	logfs_set_ro(sb);
	printk(KERN_ERR"LOGFS: device is read-only now\n");
	LOGFS_BUG(sb);
	return err;
}

/**
 * logfs_segment_read - read data block from object store
 * @inode:		inode containing data
 * @buf:		data buffer
 * @ofs:		physical data offset
 * @bix:		block index
 * @level:		block level
 *
 * Returns 0 on success or a negative errno.
 */
int logfs_segment_read(struct inode *inode, struct page *page,
		u64 ofs, u64 bix, level_t level)
{
	int err;
	void *buf;

	if (PageUptodate(page))
		return 0;

	ofs &= ~LOGFS_FULLY_POPULATED;

	buf = kmap(page);
	err = __logfs_segment_read(inode, buf, ofs, bix, level);
	if (!err) {
		move_btree_to_page(inode, page, buf);
		SetPageUptodate(page);
	}
	kunmap(page);
	log_segment("logfs_segment_read(%lx, %llx, %x) %llx (%d)\n",
			inode->i_ino, bix, level, ofs, err);
	return err;
}

int logfs_segment_delete(struct inode *inode, struct logfs_shadow *shadow)
{
	struct super_block *sb = inode->i_sb;
	struct logfs_super *super = logfs_super(sb);
	struct logfs_object_header h;
	u16 len;
	int err;

	super->s_flags |= LOGFS_SB_FLAG_DIRTY;
	BUG_ON(super->s_flags & LOGFS_SB_FLAG_SHUTDOWN);
	BUG_ON(shadow->old_ofs & LOGFS_FULLY_POPULATED);
	if (!shadow->old_ofs)
		return 0;

	log_segment("logfs_segment_delete(%llx, %llx, %x) %llx->%llx %x->%x\n",
			shadow->ino, shadow->bix, shadow->gc_level,
			shadow->old_ofs, shadow->new_ofs,
			shadow->old_len, shadow->new_len);
	err = read_obj_header(sb, shadow->old_ofs, &h);
	LOGFS_BUG_ON(err, sb);
	LOGFS_BUG_ON(be64_to_cpu(h.ino) != inode->i_ino, sb);
	LOGFS_BUG_ON(check_pos(sb, shadow->bix, be64_to_cpu(h.bix),
				shrink_level(shadow->gc_level)), sb);

	if (shadow->gc_level == 0)
		len = be16_to_cpu(h.len);
	else
		len = obj_len(sb, h.type);
	shadow->old_len = len + sizeof(h);
	return 0;
}

void freeseg(struct super_block *sb, u32 segno)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	struct page *page;
	u64 ofs, start, end;

	start = dev_ofs(sb, segno, 0);
	end = dev_ofs(sb, segno + 1, 0);
	for (ofs = start; ofs < end; ofs += PAGE_SIZE) {
		page = find_get_page(mapping, ofs >> PAGE_SHIFT);
		if (!page)
			continue;
		if (PagePrivate(page)) {
			ClearPagePrivate(page);
			page_cache_release(page);
		}
		page_cache_release(page);
	}
}

int logfs_open_area(struct logfs_area *area, size_t bytes)
{
	struct super_block *sb = area->a_sb;
	struct logfs_super *super = logfs_super(sb);
	int err, closed = 0;

	if (area->a_is_open && area->a_used_bytes + bytes <= super->s_segsize)
		return 0;

	if (area->a_is_open) {
		u64 ofs = dev_ofs(sb, area->a_segno, area->a_written_bytes);
		u32 len = super->s_segsize - area->a_written_bytes;

		log_gc("logfs_close_area(%x)\n", area->a_segno);
		pad_wbuf(area, 1);
		super->s_devops->writeseg(area->a_sb, ofs, len);
		freeseg(sb, area->a_segno);
		closed = 1;
	}

	area->a_used_bytes = 0;
	area->a_written_bytes = 0;
again:
	area->a_ops->get_free_segment(area);
	area->a_ops->get_erase_count(area);

	log_gc("logfs_open_area(%x, %x)\n", area->a_segno, area->a_level);
	err = area->a_ops->erase_segment(area);
	if (err) {
		printk(KERN_WARNING "LogFS: Error erasing segment %x\n",
				area->a_segno);
		logfs_mark_segment_bad_segment_c(sb, area->a_segno);
		goto again;
	}
	area->a_is_open = 1;
	return closed;
}

void logfs_sync_area(struct logfs_area *area)
{
	struct super_block *sb = area->a_sb;
	struct logfs_super *super = logfs_super(sb);
	u64 ofs = dev_ofs(sb, area->a_segno, area->a_written_bytes);
	u32 len = (area->a_used_bytes - area->a_written_bytes);

	if (super->s_writesize)
		len &= ~(super->s_writesize - 1);
	if (len == 0)
		return;
	pad_wbuf(area, 0);
	super->s_devops->writeseg(sb, ofs, len);
	area->a_written_bytes += len;
}

void logfs_sync_segments(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int i;

	for_each_area(i)
		logfs_sync_area(super->s_area[i]);
}

/*
 * Pick a free segment to be used for this area.  Effectively takes a
 * candidate from the free list (not really a candidate anymore).
 */
static void ostore_get_free_segment(struct logfs_area *area)
{
	struct super_block *sb = area->a_sb;
	struct logfs_super *super = logfs_super(sb);

	if (super->s_free_list.count == 0) {
		printk(KERN_ERR"LOGFS: ran out of free segments\n");
		LOGFS_BUG(sb);
	}

	area->a_segno = get_best_cand(sb, &super->s_free_list, NULL);
}

static void ostore_get_erase_count(struct logfs_area *area)
{
	struct logfs_segment_entry se;
	u32 ec_level;

	logfs_get_segment_entry(area->a_sb, area->a_segno, &se);
	BUG_ON(se.ec_level == cpu_to_be32(BADSEG) ||
			se.valid == cpu_to_be32(RESERVED));

	ec_level = be32_to_cpu(se.ec_level);
	area->a_erase_count = (ec_level >> 4) + 1;
}

static int ostore_erase_segment(struct logfs_area *area)
{
	struct super_block *sb = area->a_sb;
	struct logfs_segment_header sh;
	u64 ofs;
	int err;

	err = logfs_erase_segment(sb, area->a_segno, 0);
	if (err)
		return err;

	sh.pad = 0;
	sh.type = SEG_OSTORE;
	sh.level = (__force u8)area->a_level;
	sh.segno = cpu_to_be32(area->a_segno);
	sh.ec = cpu_to_be32(area->a_erase_count);
	sh.gec = cpu_to_be64(logfs_super(sb)->s_gec);
	sh.crc = logfs_crc32(&sh, sizeof(sh), 4);

	logfs_set_segment_erased(sb, area->a_segno, area->a_erase_count,
			area->a_level);

	ofs = dev_ofs(sb, area->a_segno, 0);
	area->a_used_bytes = sizeof(sh);
	logfs_buf_write(area, ofs, &sh, sizeof(sh));
	return 0;
}

static const struct logfs_area_ops ostore_area_ops = {
	.get_free_segment	= ostore_get_free_segment,
	.get_erase_count	= ostore_get_erase_count,
	.erase_segment		= ostore_erase_segment,
};

static void free_area(struct logfs_area *area)
{
	if (area)
		freeseg(area->a_sb, area->a_segno);
	kfree(area);
}

void free_areas(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int i;

	for_each_area(i)
		free_area(super->s_area[i]);
	free_area(super->s_journal_area);
}

static struct logfs_area *alloc_area(struct super_block *sb)
{
	struct logfs_area *area;

	area = kzalloc(sizeof(*area), GFP_KERNEL);
	if (!area)
		return NULL;

	area->a_sb = sb;
	return area;
}

static void map_invalidatepage(struct page *page, unsigned int o,
			       unsigned int l)
{
	return;
}

static int map_releasepage(struct page *page, gfp_t g)
{
	/* Don't release these pages */
	return 0;
}

static const struct address_space_operations mapping_aops = {
	.invalidatepage = map_invalidatepage,
	.releasepage	= map_releasepage,
	.set_page_dirty = __set_page_dirty_nobuffers,
};

int logfs_init_mapping(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping;
	struct inode *inode;

	inode = logfs_new_meta_inode(sb, LOGFS_INO_MAPPING);
	if (IS_ERR(inode))
		return PTR_ERR(inode);
	super->s_mapping_inode = inode;
	mapping = inode->i_mapping;
	mapping->a_ops = &mapping_aops;
	/* Would it be possible to use __GFP_HIGHMEM as well? */
	mapping_set_gfp_mask(mapping, GFP_NOFS);
	return 0;
}

int logfs_init_areas(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int i = -1;

	super->s_alias_pool = mempool_create_kmalloc_pool(600,
			sizeof(struct object_alias_item));
	if (!super->s_alias_pool)
		return -ENOMEM;

	super->s_journal_area = alloc_area(sb);
	if (!super->s_journal_area)
		goto err;

	for_each_area(i) {
		super->s_area[i] = alloc_area(sb);
		if (!super->s_area[i])
			goto err;
		super->s_area[i]->a_level = GC_LEVEL(i);
		super->s_area[i]->a_ops = &ostore_area_ops;
	}
	btree_init_mempool128(&super->s_object_alias_tree,
			super->s_btree_pool);
	return 0;

err:
	for (i--; i >= 0; i--)
		free_area(super->s_area[i]);
	free_area(super->s_journal_area);
	logfs_mempool_destroy(super->s_alias_pool);
	return -ENOMEM;
}

void logfs_cleanup_areas(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);

	btree_grim_visitor128(&super->s_object_alias_tree, 0, kill_alias);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/segment.c */
/************************************************************/
/*
 * fs/logfs/super.c
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 *
 * Generally contains mount/umount code and also serves as a dump area for
 * any functions that don't fit elsewhere and neither justify a file of their
 * own.
 */
// #include "logfs.h"
#include <linux/bio.h>
// #include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/mtd/mtd.h>
#include <linux/statfs.h>
#include <linux/buffer_head.h>
#include "../../inc/__fss.h"

static DEFINE_MUTEX(emergency_mutex);
static struct page *emergency_page;

struct page *emergency_read_begin(struct address_space *mapping, pgoff_t index)
{
	filler_t *filler = (filler_t *)mapping->a_ops->readpage;
	struct page *page;
	int err;

	page = read_cache_page(mapping, index, filler, NULL);
	if (page)
		return page;

	/* No more pages available, switch to emergency page */
	printk(KERN_INFO"Logfs: Using emergency page\n");
	mutex_lock(&emergency_mutex);
	err = filler(NULL, emergency_page);
	if (err) {
		mutex_unlock(&emergency_mutex);
		printk(KERN_EMERG"Logfs: Error reading emergency page\n");
		return ERR_PTR(err);
	}
	return emergency_page;
}

void emergency_read_end(struct page *page)
{
	if (page == emergency_page)
		mutex_unlock(&emergency_mutex);
	else
		page_cache_release(page);
}

static void dump_segfile(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_segment_entry se;
	u32 segno;

	for (segno = 0; segno < super->s_no_segs; segno++) {
		logfs_get_segment_entry(sb, segno, &se);
		printk("%3x: %6x %8x", segno, be32_to_cpu(se.ec_level),
				be32_to_cpu(se.valid));
		if (++segno < super->s_no_segs) {
			logfs_get_segment_entry(sb, segno, &se);
			printk(" %6x %8x", be32_to_cpu(se.ec_level),
					be32_to_cpu(se.valid));
		}
		if (++segno < super->s_no_segs) {
			logfs_get_segment_entry(sb, segno, &se);
			printk(" %6x %8x", be32_to_cpu(se.ec_level),
					be32_to_cpu(se.valid));
		}
		if (++segno < super->s_no_segs) {
			logfs_get_segment_entry(sb, segno, &se);
			printk(" %6x %8x", be32_to_cpu(se.ec_level),
					be32_to_cpu(se.valid));
		}
		printk("\n");
	}
}

/*
 * logfs_crash_dump - dump debug information to device
 *
 * The LogFS superblock only occupies part of a segment.  This function will
 * write as much debug information as it can gather into the spare space.
 */
void logfs_crash_dump(struct super_block *sb)
{
	dump_segfile(sb);
}

/*
 * FIXME: There should be a reserve for root, similar to ext2.
 */
int logfs_statfs(struct dentry *dentry, struct kstatfs *stats)
{
	struct super_block *sb = dentry->d_sb;
	struct logfs_super *super = logfs_super(sb);

	stats->f_type		= LOGFS_MAGIC_U32;
	stats->f_bsize		= sb->s_blocksize;
	stats->f_blocks		= super->s_size >> LOGFS_BLOCK_BITS >> 3;
	stats->f_bfree		= super->s_free_bytes >> sb->s_blocksize_bits;
	stats->f_bavail		= super->s_free_bytes >> sb->s_blocksize_bits;
	stats->f_files		= 0;
	stats->f_ffree		= 0;
	stats->f_namelen	= LOGFS_MAX_NAMELEN;
	return 0;
}

static int logfs_sb_set(struct super_block *sb, void *_super)
{
	struct logfs_super *super = _super;

	sb->s_fs_info = super;
	sb->s_mtd = super->s_mtd;
	sb->s_bdev = super->s_bdev;
#ifdef CONFIG_BLOCK
	if (sb->s_bdev)
		sb->s_bdi = &bdev_get_queue(sb->s_bdev)->backing_dev_info;
#endif
#ifdef CONFIG_MTD
	if (sb->s_mtd)
		sb->s_bdi = sb->s_mtd->backing_dev_info;
#endif
	return 0;
}

static int logfs_sb_test(struct super_block *sb, void *_super)
{
	struct logfs_super *super = _super;
	struct mtd_info *mtd = super->s_mtd;

	if (mtd && sb->s_mtd == mtd)
		return 1;
	if (super->s_bdev && sb->s_bdev == super->s_bdev)
		return 1;
	return 0;
}

static void set_segment_header(struct logfs_segment_header *sh, u8 type,
		u8 level, u32 segno, u32 ec)
{
	sh->pad = 0;
	sh->type = type;
	sh->level = level;
	sh->segno = cpu_to_be32(segno);
	sh->ec = cpu_to_be32(ec);
	sh->gec = cpu_to_be64(segno);
	sh->crc = logfs_crc32(sh, LOGFS_SEGMENT_HEADERSIZE, 4);
}

static void logfs_write_ds(struct super_block *sb, struct logfs_disk_super *ds,
		u32 segno, u32 ec)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_segment_header *sh = &ds->ds_sh;
	int i;

	memset(ds, 0, sizeof(*ds));
	set_segment_header(sh, SEG_SUPER, 0, segno, ec);

	ds->ds_ifile_levels	= super->s_ifile_levels;
	ds->ds_iblock_levels	= super->s_iblock_levels;
	ds->ds_data_levels	= super->s_data_levels; /* XXX: Remove */
	ds->ds_segment_shift	= super->s_segshift;
	ds->ds_block_shift	= sb->s_blocksize_bits;
	ds->ds_write_shift	= super->s_writeshift;
	ds->ds_filesystem_size	= cpu_to_be64(super->s_size);
	ds->ds_segment_size	= cpu_to_be32(super->s_segsize);
	ds->ds_bad_seg_reserve	= cpu_to_be32(super->s_bad_seg_reserve);
	ds->ds_feature_incompat	= cpu_to_be64(super->s_feature_incompat);
	ds->ds_feature_ro_compat= cpu_to_be64(super->s_feature_ro_compat);
	ds->ds_feature_compat	= cpu_to_be64(super->s_feature_compat);
	ds->ds_feature_flags	= cpu_to_be64(super->s_feature_flags);
	ds->ds_root_reserve	= cpu_to_be64(super->s_root_reserve);
	ds->ds_speed_reserve	= cpu_to_be64(super->s_speed_reserve);
	journal_for_each(i)
		ds->ds_journal_seg[i] = cpu_to_be32(super->s_journal_seg[i]);
	ds->ds_magic		= cpu_to_be64(LOGFS_MAGIC);
	ds->ds_crc = logfs_crc32(ds, sizeof(*ds),
			LOGFS_SEGMENT_HEADERSIZE + 12);
}

static int write_one_sb(struct super_block *sb,
		struct page *(*find_sb)(struct super_block *sb, u64 *ofs))
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_disk_super *ds;
	struct logfs_segment_entry se;
	struct page *page;
	u64 ofs;
	u32 ec, segno;
	int err;

	page = find_sb(sb, &ofs);
	if (!page)
		return -EIO;
	ds = page_address(page);
	segno = seg_no(sb, ofs);
	logfs_get_segment_entry(sb, segno, &se);
	ec = be32_to_cpu(se.ec_level) >> 4;
	ec++;
	logfs_set_segment_erased(sb, segno, ec, 0);
	logfs_write_ds(sb, ds, segno, ec);
	err = super->s_devops->write_sb(sb, page);
	page_cache_release(page);
	return err;
}

int logfs_write_sb(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	int err;

	/* First superblock */
	err = write_one_sb(sb, super->s_devops->find_first_sb);
	if (err)
		return err;

	/* Last superblock */
	err = write_one_sb(sb, super->s_devops->find_last_sb);
	if (err)
		return err;
	return 0;
}

static int ds_cmp(const void *ds0, const void *ds1)
{
	size_t len = sizeof(struct logfs_disk_super);

	/* We know the segment headers differ, so ignore them */
	len -= LOGFS_SEGMENT_HEADERSIZE;
	ds0 += LOGFS_SEGMENT_HEADERSIZE;
	ds1 += LOGFS_SEGMENT_HEADERSIZE;
	return memcmp(ds0, ds1, len);
}

static int logfs_recover_sb(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct logfs_disk_super _ds0, *ds0 = &_ds0;
	struct logfs_disk_super _ds1, *ds1 = &_ds1;
	int err, valid0, valid1;

	/* read first superblock */
	err = wbuf_read(sb, super->s_sb_ofs[0], sizeof(*ds0), ds0);
	if (err)
		return err;
	/* read last superblock */
	err = wbuf_read(sb, super->s_sb_ofs[1], sizeof(*ds1), ds1);
	if (err)
		return err;
	valid0 = logfs_check_ds(ds0) == 0;
	valid1 = logfs_check_ds(ds1) == 0;

	if (!valid0 && valid1) {
		printk(KERN_INFO"First superblock is invalid - fixing.\n");
		return write_one_sb(sb, super->s_devops->find_first_sb);
	}
	if (valid0 && !valid1) {
		printk(KERN_INFO"Last superblock is invalid - fixing.\n");
		return write_one_sb(sb, super->s_devops->find_last_sb);
	}
	if (valid0 && valid1 && ds_cmp(ds0, ds1)) {
		printk(KERN_INFO"Superblocks don't match - fixing.\n");
		return logfs_write_sb(sb);
	}
	/* If neither is valid now, something's wrong.  Didn't we properly
	 * check them before?!? */
	BUG_ON(!valid0 && !valid1);
	return 0;
}

static int logfs_make_writeable(struct super_block *sb)
{
	int err;

	err = logfs_open_segfile(sb);
	if (err)
		return err;

	/* Repair any broken superblock copies */
	err = logfs_recover_sb(sb);
	if (err)
		return err;

	/* Check areas for trailing unaccounted data */
	err = logfs_check_areas(sb);
	if (err)
		return err;

	/* Do one GC pass before any data gets dirtied */
	logfs_gc_pass(sb);

	/* after all initializations are done, replay the journal
	 * for rw-mounts, if necessary */
	err = logfs_replay_journal(sb);
	if (err)
		return err;

	return 0;
}

static int logfs_get_sb_final(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct inode *rootdir;
	int err;

	/* root dir */
	rootdir = logfs_iget(sb, LOGFS_INO_ROOT);
	if (IS_ERR(rootdir))
		goto fail;

	sb->s_root = d_make_root(rootdir);
	if (!sb->s_root)
		goto fail;

	/* at that point we know that ->put_super() will be called */
	super->s_erase_page = alloc_pages(GFP_KERNEL, 0);
	if (!super->s_erase_page)
		return -ENOMEM;
	memset(page_address(super->s_erase_page), 0xFF, PAGE_SIZE);

	/* FIXME: check for read-only mounts */
	err = logfs_make_writeable(sb);
	if (err) {
		__free_page(super->s_erase_page);
		return err;
	}

	log_super("LogFS: Finished mounting\n");
	return 0;

fail:
	iput(super->s_master_inode);
	iput(super->s_segfile_inode);
	iput(super->s_mapping_inode);
	return -EIO;
}

int logfs_check_ds(struct logfs_disk_super *ds)
{
	struct logfs_segment_header *sh = &ds->ds_sh;

	if (ds->ds_magic != cpu_to_be64(LOGFS_MAGIC))
		return -EINVAL;
	if (sh->crc != logfs_crc32(sh, LOGFS_SEGMENT_HEADERSIZE, 4))
		return -EINVAL;
	if (ds->ds_crc != logfs_crc32(ds, sizeof(*ds),
				LOGFS_SEGMENT_HEADERSIZE + 12))
		return -EINVAL;
	return 0;
}

static struct page *find_super_block(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct page *first, *last;

	first = super->s_devops->find_first_sb(sb, &super->s_sb_ofs[0]);
	if (!first || IS_ERR(first))
		return NULL;
	last = super->s_devops->find_last_sb(sb, &super->s_sb_ofs[1]);
	if (!last || IS_ERR(last)) {
		page_cache_release(first);
		return NULL;
	}

	if (!logfs_check_ds(page_address(first))) {
		page_cache_release(last);
		return first;
	}

	/* First one didn't work, try the second superblock */
	if (!logfs_check_ds(page_address(last))) {
		page_cache_release(first);
		return last;
	}

	/* Neither worked, sorry folks */
	page_cache_release(first);
	page_cache_release(last);
	return NULL;
}

static int __logfs_read_sb(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);
	struct page *page;
	struct logfs_disk_super *ds;
	int i;

	page = find_super_block(sb);
	if (!page)
		return -EINVAL;

	ds = page_address(page);
	super->s_size = be64_to_cpu(ds->ds_filesystem_size);
	super->s_root_reserve = be64_to_cpu(ds->ds_root_reserve);
	super->s_speed_reserve = be64_to_cpu(ds->ds_speed_reserve);
	super->s_bad_seg_reserve = be32_to_cpu(ds->ds_bad_seg_reserve);
	super->s_segsize = 1 << ds->ds_segment_shift;
	super->s_segmask = (1 << ds->ds_segment_shift) - 1;
	super->s_segshift = ds->ds_segment_shift;
	sb->s_blocksize = 1 << ds->ds_block_shift;
	sb->s_blocksize_bits = ds->ds_block_shift;
	super->s_writesize = 1 << ds->ds_write_shift;
	super->s_writeshift = ds->ds_write_shift;
	super->s_no_segs = super->s_size >> super->s_segshift;
	super->s_no_blocks = super->s_segsize >> sb->s_blocksize_bits;
	super->s_feature_incompat = be64_to_cpu(ds->ds_feature_incompat);
	super->s_feature_ro_compat = be64_to_cpu(ds->ds_feature_ro_compat);
	super->s_feature_compat = be64_to_cpu(ds->ds_feature_compat);
	super->s_feature_flags = be64_to_cpu(ds->ds_feature_flags);

	journal_for_each(i)
		super->s_journal_seg[i] = be32_to_cpu(ds->ds_journal_seg[i]);

	super->s_ifile_levels = ds->ds_ifile_levels;
	super->s_iblock_levels = ds->ds_iblock_levels;
	super->s_data_levels = ds->ds_data_levels;
	super->s_total_levels = super->s_ifile_levels + super->s_iblock_levels
		+ super->s_data_levels;
	page_cache_release(page);
	return 0;
}

static int logfs_read_sb(struct super_block *sb, int read_only)
{
	struct logfs_super *super = logfs_super(sb);
	int ret;

	super->s_btree_pool = mempool_create(32, btree_alloc, btree_free, NULL);
	if (!super->s_btree_pool)
		return -ENOMEM;

	btree_init_mempool64(&super->s_shadow_tree.new, super->s_btree_pool);
	btree_init_mempool64(&super->s_shadow_tree.old, super->s_btree_pool);
	btree_init_mempool32(&super->s_shadow_tree.segment_map,
			super->s_btree_pool);

	ret = logfs_init_mapping(sb);
	if (ret)
		return ret;

	ret = __logfs_read_sb(sb);
	if (ret)
		return ret;

	if (super->s_feature_incompat & ~LOGFS_FEATURES_INCOMPAT)
		return -EIO;
	if ((super->s_feature_ro_compat & ~LOGFS_FEATURES_RO_COMPAT) &&
			!read_only)
		return -EIO;

	ret = logfs_init_rw(sb);
	if (ret)
		return ret;

	ret = logfs_init_areas(sb);
	if (ret)
		return ret;

	ret = logfs_init_gc(sb);
	if (ret)
		return ret;

	ret = logfs_init_journal(sb);
	if (ret)
		return ret;

	return 0;
}

static void logfs_kill_sb(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);

	log_super("LogFS: Start unmounting\n");
	/* Alias entries slow down mount, so evict as many as possible */
	sync_filesystem(sb);
	logfs_write_anchor(sb);
	free_areas(sb);

	/*
	 * From this point on alias entries are simply dropped - and any
	 * writes to the object store are considered bugs.
	 */
	log_super("LogFS: Now in shutdown\n");
	generic_shutdown_super(sb);
	super->s_flags |= LOGFS_SB_FLAG_SHUTDOWN;

	BUG_ON(super->s_dirty_used_bytes || super->s_dirty_free_bytes);

	logfs_cleanup_gc(sb);
	logfs_cleanup_journal(sb);
	logfs_cleanup_areas(sb);
	logfs_cleanup_rw(sb);
	if (super->s_erase_page)
		__free_page(super->s_erase_page);
	super->s_devops->put_device(super);
	logfs_mempool_destroy(super->s_btree_pool);
	logfs_mempool_destroy(super->s_alias_pool);
	kfree(super);
	log_super("LogFS: Finished unmounting\n");
}

static struct dentry *logfs_get_sb_device(struct logfs_super *super,
		struct file_system_type *type, int flags)
{
	struct super_block *sb;
	int err = -ENOMEM;
	static int mount_count;

	log_super("LogFS: Start mount %x\n", mount_count++);

	err = -EINVAL;
	sb = sget(type, logfs_sb_test, logfs_sb_set, flags | MS_NOATIME, super);
	if (IS_ERR(sb)) {
		super->s_devops->put_device(super);
		kfree(super);
		return ERR_CAST(sb);
	}

	if (sb->s_root) {
		/* Device is already in use */
		super->s_devops->put_device(super);
		kfree(super);
		return dget(sb->s_root);
	}

	/*
	 * sb->s_maxbytes is limited to 8TB.  On 32bit systems, the page cache
	 * only covers 16TB and the upper 8TB are used for indirect blocks.
	 * On 64bit system we could bump up the limit, but that would make
	 * the filesystem incompatible with 32bit systems.
	 */
	sb->s_maxbytes	= (1ull << 43) - 1;
	sb->s_max_links = LOGFS_LINK_MAX;
	sb->s_op	= &logfs_super_operations;

	err = logfs_read_sb(sb, sb->s_flags & MS_RDONLY);
	if (err)
		goto err1;

	sb->s_flags |= MS_ACTIVE;
	err = logfs_get_sb_final(sb);
	if (err) {
		deactivate_locked_super(sb);
		return ERR_PTR(err);
	}
	return dget(sb->s_root);

err1:
	/* no ->s_root, no ->put_super() */
	iput(super->s_master_inode);
	iput(super->s_segfile_inode);
	iput(super->s_mapping_inode);
	deactivate_locked_super(sb);
	return ERR_PTR(err);
}

static struct dentry *logfs_mount(struct file_system_type *type, int flags,
		const char *devname, void *data)
{
	ulong mtdnr;
	struct logfs_super *super;
	int err;

	super = kzalloc(sizeof(*super), GFP_KERNEL);
	if (!super)
		return ERR_PTR(-ENOMEM);

	mutex_init(&super->s_dirop_mutex);
	mutex_init(&super->s_object_alias_mutex);
	INIT_LIST_HEAD(&super->s_freeing_list);

	if (!devname)
		err = logfs_get_sb_bdev(super, type, devname);
	else if (strncmp(devname, "mtd", 3))
		err = logfs_get_sb_bdev(super, type, devname);
	else {
		char *garbage;
		mtdnr = simple_strtoul(devname+3, &garbage, 0);
		if (*garbage)
			err = -EINVAL;
		else
			err = logfs_get_sb_mtd(super, mtdnr);
	}

	if (err) {
		kfree(super);
		return ERR_PTR(err);
	}

	return logfs_get_sb_device(super, type, flags);
}

static struct file_system_type logfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "logfs",
	.mount		= logfs_mount,
	.kill_sb	= logfs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,

};
MODULE_ALIAS_FS("logfs");

static int __init logfs_init(void)
{
	int ret;

	emergency_page = alloc_pages(GFP_KERNEL, 0);
	if (!emergency_page)
		return -ENOMEM;

	ret = logfs_compr_init();
	if (ret)
		goto out1;

	ret = logfs_init_inode_cache();
	if (ret)
		goto out2;

	ret = register_filesystem(&logfs_fs_type);
	if (!ret)
		return 0;
	logfs_destroy_inode_cache();
out2:
	logfs_compr_exit();
out1:
	__free_pages(emergency_page, 0);
	return ret;
}

static void __exit logfs_exit(void)
{
	unregister_filesystem(&logfs_fs_type);
	logfs_destroy_inode_cache();
	logfs_compr_exit();
	__free_pages(emergency_page, 0);
}

module_init(logfs_init);
module_exit(logfs_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Joern Engel <joern@logfs.org>");
MODULE_DESCRIPTION("scalable flash filesystem");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/super.c */
/************************************************************/
/*
 * fs/logfs/dev_bdev.c	- Device access methods for block devices
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 */
// #include "logfs.h"
// #include <linux/bio.h>
// #include <linux/blkdev.h>
// #include <linux/buffer_head.h>
#include <linux/gfp.h>
#include <linux/prefetch.h>
#include "../../inc/__fss.h"

#define PAGE_OFS(ofs) ((ofs) & (PAGE_SIZE-1))

static int sync_request(struct page *page, struct block_device *bdev, int rw)
{
	struct bio bio;
	struct bio_vec bio_vec;

	bio_init(&bio);
	bio.bi_max_vecs = 1;
	bio.bi_io_vec = &bio_vec;
	bio_vec.bv_page = page;
	bio_vec.bv_len = PAGE_SIZE;
	bio_vec.bv_offset = 0;
	bio.bi_vcnt = 1;
	bio.bi_bdev = bdev;
	bio.bi_iter.bi_sector = page->index * (PAGE_SIZE >> 9);
	bio.bi_iter.bi_size = PAGE_SIZE;

	return submit_bio_wait(rw, &bio);
}

static int bdev_readpage(void *_sb, struct page *page)
{
	struct super_block *sb = _sb;
	struct block_device *bdev = logfs_super(sb)->s_bdev;
	int err;

	err = sync_request(page, bdev, READ);
	if (err) {
		ClearPageUptodate(page);
		SetPageError(page);
	} else {
		SetPageUptodate(page);
		ClearPageError(page);
	}
	unlock_page(page);
	return err;
}

static DECLARE_WAIT_QUEUE_HEAD(wq);

static void writeseg_end_io(struct bio *bio, int err)
{
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags);
	struct bio_vec *bvec;
	int i;
	struct super_block *sb = bio->bi_private;
	struct logfs_super *super = logfs_super(sb);

	BUG_ON(!uptodate); /* FIXME: Retry io or write elsewhere */
	BUG_ON(err);

	bio_for_each_segment_all(bvec, bio, i) {
		end_page_writeback(bvec->bv_page);
		page_cache_release(bvec->bv_page);
	}
	bio_put(bio);
	if (atomic_dec_and_test(&super->s_pending_writes))
		wake_up(&wq);
}

static int __bdev_writeseg(struct super_block *sb, u64 ofs, pgoff_t index,
		size_t nr_pages)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	struct bio *bio;
	struct page *page;
	unsigned int max_pages;
	int i;

	max_pages = min(nr_pages, (size_t) bio_get_nr_vecs(super->s_bdev));

	bio = bio_alloc(GFP_NOFS, max_pages);
	BUG_ON(!bio);

	for (i = 0; i < nr_pages; i++) {
		if (i >= max_pages) {
			/* Block layer cannot split bios :( */
			bio->bi_vcnt = i;
			bio->bi_iter.bi_size = i * PAGE_SIZE;
			bio->bi_bdev = super->s_bdev;
			bio->bi_iter.bi_sector = ofs >> 9;
			bio->bi_private = sb;
			bio->bi_end_io = writeseg_end_io;
			atomic_inc(&super->s_pending_writes);
			submit_bio(WRITE, bio);

			ofs += i * PAGE_SIZE;
			index += i;
			nr_pages -= i;
			i = 0;

			bio = bio_alloc(GFP_NOFS, max_pages);
			BUG_ON(!bio);
		}
		page = find_lock_page(mapping, index + i);
		BUG_ON(!page);
		bio->bi_io_vec[i].bv_page = page;
		bio->bi_io_vec[i].bv_len = PAGE_SIZE;
		bio->bi_io_vec[i].bv_offset = 0;

		BUG_ON(PageWriteback(page));
		set_page_writeback(page);
		unlock_page(page);
	}
	bio->bi_vcnt = nr_pages;
	bio->bi_iter.bi_size = nr_pages * PAGE_SIZE;
	bio->bi_bdev = super->s_bdev;
	bio->bi_iter.bi_sector = ofs >> 9;
	bio->bi_private = sb;
	bio->bi_end_io = writeseg_end_io;
	atomic_inc(&super->s_pending_writes);
	submit_bio(WRITE, bio);
	return 0;
}

static void bdev_writeseg(struct super_block *sb, u64 ofs, size_t len)
{
	struct logfs_super *super = logfs_super(sb);
	int head;

	BUG_ON(super->s_flags & LOGFS_SB_FLAG_RO);

	if (len == 0) {
		/* This can happen when the object fit perfectly into a
		 * segment, the segment gets written per sync and subsequently
		 * closed.
		 */
		return;
	}
	head = ofs & (PAGE_SIZE - 1);
	if (head) {
		ofs -= head;
		len += head;
	}
	len = PAGE_ALIGN(len);
	__bdev_writeseg(sb, ofs, ofs >> PAGE_SHIFT, len >> PAGE_SHIFT);
}


static void erase_end_io(struct bio *bio, int err) 
{ 
	const int uptodate = test_bit(BIO_UPTODATE, &bio->bi_flags); 
	struct super_block *sb = bio->bi_private; 
	struct logfs_super *super = logfs_super(sb); 

	BUG_ON(!uptodate); /* FIXME: Retry io or write elsewhere */ 
	BUG_ON(err); 
	BUG_ON(bio->bi_vcnt == 0); 
	bio_put(bio); 
	if (atomic_dec_and_test(&super->s_pending_writes))
		wake_up(&wq); 
} 

static int do_erase(struct super_block *sb, u64 ofs, pgoff_t index,
		size_t nr_pages)
{
	struct logfs_super *super = logfs_super(sb);
	struct bio *bio;
	unsigned int max_pages;
	int i;

	max_pages = min(nr_pages, (size_t) bio_get_nr_vecs(super->s_bdev));

	bio = bio_alloc(GFP_NOFS, max_pages);
	BUG_ON(!bio);

	for (i = 0; i < nr_pages; i++) {
		if (i >= max_pages) {
			/* Block layer cannot split bios :( */
			bio->bi_vcnt = i;
			bio->bi_iter.bi_size = i * PAGE_SIZE;
			bio->bi_bdev = super->s_bdev;
			bio->bi_iter.bi_sector = ofs >> 9;
			bio->bi_private = sb;
			bio->bi_end_io = erase_end_io;
			atomic_inc(&super->s_pending_writes);
			submit_bio(WRITE, bio);

			ofs += i * PAGE_SIZE;
			index += i;
			nr_pages -= i;
			i = 0;

			bio = bio_alloc(GFP_NOFS, max_pages);
			BUG_ON(!bio);
		}
		bio->bi_io_vec[i].bv_page = super->s_erase_page;
		bio->bi_io_vec[i].bv_len = PAGE_SIZE;
		bio->bi_io_vec[i].bv_offset = 0;
	}
	bio->bi_vcnt = nr_pages;
	bio->bi_iter.bi_size = nr_pages * PAGE_SIZE;
	bio->bi_bdev = super->s_bdev;
	bio->bi_iter.bi_sector = ofs >> 9;
	bio->bi_private = sb;
	bio->bi_end_io = erase_end_io;
	atomic_inc(&super->s_pending_writes);
	submit_bio(WRITE, bio);
	return 0;
}

static int bdev_erase(struct super_block *sb, loff_t to, size_t len,
		int ensure_write)
{
	struct logfs_super *super = logfs_super(sb);

	BUG_ON(to & (PAGE_SIZE - 1));
	BUG_ON(len & (PAGE_SIZE - 1));

	if (super->s_flags & LOGFS_SB_FLAG_RO)
		return -EROFS;

	if (ensure_write) {
		/*
		 * Object store doesn't care whether erases happen or not.
		 * But for the journal they are required.  Otherwise a scan
		 * can find an old commit entry and assume it is the current
		 * one, travelling back in time.
		 */
		do_erase(sb, to, to >> PAGE_SHIFT, len >> PAGE_SHIFT);
	}

	return 0;
}

static void bdev_sync(struct super_block *sb)
{
	struct logfs_super *super = logfs_super(sb);

	wait_event(wq, atomic_read(&super->s_pending_writes) == 0);
}

static struct page *bdev_find_first_sb(struct super_block *sb, u64 *ofs)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	filler_t *filler = bdev_readpage;

	*ofs = 0;
	return read_cache_page(mapping, 0, filler, sb);
}

static struct page *bdev_find_last_sb(struct super_block *sb, u64 *ofs)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	filler_t *filler = bdev_readpage;
	u64 pos = (super->s_bdev->bd_inode->i_size & ~0xfffULL) - 0x1000;
	pgoff_t index = pos >> PAGE_SHIFT;

	*ofs = pos;
	return read_cache_page(mapping, index, filler, sb);
}

static int bdev_write_sb(struct super_block *sb, struct page *page)
{
	struct block_device *bdev = logfs_super(sb)->s_bdev;

	/* Nothing special to do for block devices. */
	return sync_request(page, bdev, WRITE);
}

static void bdev_put_device(struct logfs_super *s)
{
	blkdev_put(s->s_bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
}

static int bdev_can_write_buf(struct super_block *sb, u64 ofs)
{
	return 0;
}

static const struct logfs_device_ops bd_devops = {
	.find_first_sb	= bdev_find_first_sb,
	.find_last_sb	= bdev_find_last_sb,
	.write_sb	= bdev_write_sb,
	.readpage	= bdev_readpage,
	.writeseg	= bdev_writeseg,
	.erase		= bdev_erase,
	.can_write_buf	= bdev_can_write_buf,
	.sync		= bdev_sync,
	.put_device	= bdev_put_device,
};

int logfs_get_sb_bdev(struct logfs_super *p, struct file_system_type *type,
		const char *devname)
{
	struct block_device *bdev;

	bdev = blkdev_get_by_path(devname, FMODE_READ|FMODE_WRITE|FMODE_EXCL,
				  type);
	if (IS_ERR(bdev))
		return PTR_ERR(bdev);

	if (MAJOR(bdev->bd_dev) == MTD_BLOCK_MAJOR) {
		int mtdnr = MINOR(bdev->bd_dev);
		blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
		return logfs_get_sb_mtd(p, mtdnr);
	}

	p->s_bdev = bdev;
	p->s_mtd = NULL;
	p->s_devops = &bd_devops;
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/dev_bdev.c */
/************************************************************/
/*
 * fs/logfs/dev_mtd.c	- Device access methods for MTD
 *
 * As should be obvious for Linux kernel code, license is GPLv2
 *
 * Copyright (c) 2005-2008 Joern Engel <joern@logfs.org>
 */
// #include "logfs.h"
#include <linux/completion.h>
#include <linux/mount.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

#define PAGE_OFS(ofs) ((ofs) & (PAGE_SIZE-1))

static int logfs_mtd_read(struct super_block *sb, loff_t ofs, size_t len,
			void *buf)
{
	struct mtd_info *mtd = logfs_super(sb)->s_mtd;
	size_t retlen;
	int ret;

	ret = mtd_read(mtd, ofs, len, &retlen, buf);
	BUG_ON(ret == -EINVAL);
	if (ret)
		return ret;

	/* Not sure if we should loop instead. */
	if (retlen != len)
		return -EIO;

	return 0;
}

static int loffs_mtd_write(struct super_block *sb, loff_t ofs, size_t len,
			void *buf)
{
	struct logfs_super *super = logfs_super(sb);
	struct mtd_info *mtd = super->s_mtd;
	size_t retlen;
	loff_t page_start, page_end;
	int ret;

	if (super->s_flags & LOGFS_SB_FLAG_RO)
		return -EROFS;

	BUG_ON((ofs >= mtd->size) || (len > mtd->size - ofs));
	BUG_ON(ofs != (ofs >> super->s_writeshift) << super->s_writeshift);
	BUG_ON(len > PAGE_CACHE_SIZE);
	page_start = ofs & PAGE_CACHE_MASK;
	page_end = PAGE_CACHE_ALIGN(ofs + len) - 1;
	ret = mtd_write(mtd, ofs, len, &retlen, buf);
	if (ret || (retlen != len))
		return -EIO;

	return 0;
}

/*
 * For as long as I can remember (since about 2001) mtd->erase has been an
 * asynchronous interface lacking the first driver to actually use the
 * asynchronous properties.  So just to prevent the first implementor of such
 * a thing from breaking logfs in 2350, we do the usual pointless dance to
 * declare a completion variable and wait for completion before returning
 * from logfs_mtd_erase().  What an exercise in futility!
 */
static void logfs_erase_callback(struct erase_info *ei)
{
	complete((struct completion *)ei->priv);
}

static int logfs_mtd_erase_mapping(struct super_block *sb, loff_t ofs,
				size_t len)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	struct page *page;
	pgoff_t index = ofs >> PAGE_SHIFT;

	for (index = ofs >> PAGE_SHIFT; index < (ofs + len) >> PAGE_SHIFT; index++) {
		page = find_get_page(mapping, index);
		if (!page)
			continue;
		memset(page_address(page), 0xFF, PAGE_SIZE);
		page_cache_release(page);
	}
	return 0;
}

static int logfs_mtd_erase(struct super_block *sb, loff_t ofs, size_t len,
		int ensure_write)
{
	struct mtd_info *mtd = logfs_super(sb)->s_mtd;
	struct erase_info ei;
	DECLARE_COMPLETION_ONSTACK(complete);
	int ret;

	BUG_ON(len % mtd->erasesize);
	if (logfs_super(sb)->s_flags & LOGFS_SB_FLAG_RO)
		return -EROFS;

	memset(&ei, 0, sizeof(ei));
	ei.mtd = mtd;
	ei.addr = ofs;
	ei.len = len;
	ei.callback = logfs_erase_callback;
	ei.priv = (long)&complete;
	ret = mtd_erase(mtd, &ei);
	if (ret)
		return -EIO;

	wait_for_completion(&complete);
	if (ei.state != MTD_ERASE_DONE)
		return -EIO;
	return logfs_mtd_erase_mapping(sb, ofs, len);
}

static void logfs_mtd_sync(struct super_block *sb)
{
	struct mtd_info *mtd = logfs_super(sb)->s_mtd;

	mtd_sync(mtd);
}

static int logfs_mtd_readpage(void *_sb, struct page *page)
{
	struct super_block *sb = _sb;
	int err;

	err = logfs_mtd_read(sb, page->index << PAGE_SHIFT, PAGE_SIZE,
			page_address(page));
	if (err == -EUCLEAN || err == -EBADMSG) {
		/* -EBADMSG happens regularly on power failures */
		err = 0;
		/* FIXME: force GC this segment */
	}
	if (err) {
		ClearPageUptodate(page);
		SetPageError(page);
	} else {
		SetPageUptodate(page);
		ClearPageError(page);
	}
	unlock_page(page);
	return err;
}

static struct page *logfs_mtd_find_first_sb(struct super_block *sb, u64 *ofs)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	filler_t *filler = logfs_mtd_readpage;
	struct mtd_info *mtd = super->s_mtd;

	*ofs = 0;
	while (mtd_block_isbad(mtd, *ofs)) {
		*ofs += mtd->erasesize;
		if (*ofs >= mtd->size)
			return NULL;
	}
	BUG_ON(*ofs & ~PAGE_MASK);
	return read_cache_page(mapping, *ofs >> PAGE_SHIFT, filler, sb);
}

static struct page *logfs_mtd_find_last_sb(struct super_block *sb, u64 *ofs)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	filler_t *filler = logfs_mtd_readpage;
	struct mtd_info *mtd = super->s_mtd;

	*ofs = mtd->size - mtd->erasesize;
	while (mtd_block_isbad(mtd, *ofs)) {
		*ofs -= mtd->erasesize;
		if (*ofs <= 0)
			return NULL;
	}
	*ofs = *ofs + mtd->erasesize - 0x1000;
	BUG_ON(*ofs & ~PAGE_MASK);
	return read_cache_page(mapping, *ofs >> PAGE_SHIFT, filler, sb);
}

static int __logfs_mtd_writeseg(struct super_block *sb, u64 ofs, pgoff_t index,
		size_t nr_pages)
{
	struct logfs_super *super = logfs_super(sb);
	struct address_space *mapping = super->s_mapping_inode->i_mapping;
	struct page *page;
	int i, err;

	for (i = 0; i < nr_pages; i++) {
		page = find_lock_page(mapping, index + i);
		BUG_ON(!page);

		err = loffs_mtd_write(sb, page->index << PAGE_SHIFT, PAGE_SIZE,
					page_address(page));
		unlock_page(page);
		page_cache_release(page);
		if (err)
			return err;
	}
	return 0;
}

static void logfs_mtd_writeseg(struct super_block *sb, u64 ofs, size_t len)
{
	struct logfs_super *super = logfs_super(sb);
	int head;

	if (super->s_flags & LOGFS_SB_FLAG_RO)
		return;

	if (len == 0) {
		/* This can happen when the object fit perfectly into a
		 * segment, the segment gets written per sync and subsequently
		 * closed.
		 */
		return;
	}
	head = ofs & (PAGE_SIZE - 1);
	if (head) {
		ofs -= head;
		len += head;
	}
	len = PAGE_ALIGN(len);
	__logfs_mtd_writeseg(sb, ofs, ofs >> PAGE_SHIFT, len >> PAGE_SHIFT);
}

static void logfs_mtd_put_device(struct logfs_super *s)
{
	put_mtd_device(s->s_mtd);
}

static int logfs_mtd_can_write_buf(struct super_block *sb, u64 ofs)
{
	struct logfs_super *super = logfs_super(sb);
	void *buf;
	int err;

	buf = kmalloc(super->s_writesize, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	err = logfs_mtd_read(sb, ofs, super->s_writesize, buf);
	if (err)
		goto out;
	if (memchr_inv(buf, 0xff, super->s_writesize))
		err = -EIO;
	kfree(buf);
out:
	return err;
}

static const struct logfs_device_ops mtd_devops = {
	.find_first_sb	= logfs_mtd_find_first_sb,
	.find_last_sb	= logfs_mtd_find_last_sb,
	.readpage	= logfs_mtd_readpage,
	.writeseg	= logfs_mtd_writeseg,
	.erase		= logfs_mtd_erase,
	.can_write_buf	= logfs_mtd_can_write_buf,
	.sync		= logfs_mtd_sync,
	.put_device	= logfs_mtd_put_device,
};

int logfs_get_sb_mtd(struct logfs_super *s, int mtdnr)
{
	struct mtd_info *mtd = get_mtd_device(NULL, mtdnr);
	if (IS_ERR(mtd))
		return PTR_ERR(mtd);

	s->s_bdev = NULL;
	s->s_mtd = mtd;
	s->s_devops = &mtd_devops;
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/logfs/dev_mtd.c */
/************************************************************/
