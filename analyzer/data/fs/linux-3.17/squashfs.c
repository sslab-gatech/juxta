/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * block.c
 */

/*
 * This file implements the low-level routines to read and decompress
 * datablocks and metadata blocks.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/buffer_head.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs.h"
#include "decompressor.h"
#include "page_actor.h"

/*
 * Read the metadata block length, this is stored in the first two
 * bytes of the metadata block.
 */
static struct buffer_head *get_block_length(struct super_block *sb,
			u64 *cur_index, int *offset, int *length)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	struct buffer_head *bh;

	bh = sb_bread(sb, *cur_index);
	if (bh == NULL)
		return NULL;

	if (msblk->devblksize - *offset == 1) {
		*length = (unsigned char) bh->b_data[*offset];
		put_bh(bh);
		bh = sb_bread(sb, ++(*cur_index));
		if (bh == NULL)
			return NULL;
		*length |= (unsigned char) bh->b_data[0] << 8;
		*offset = 1;
	} else {
		*length = (unsigned char) bh->b_data[*offset] |
			(unsigned char) bh->b_data[*offset + 1] << 8;
		*offset += 2;

		if (*offset == msblk->devblksize) {
			put_bh(bh);
			bh = sb_bread(sb, ++(*cur_index));
			if (bh == NULL)
				return NULL;
			*offset = 0;
		}
	}

	return bh;
}


/*
 * Read and decompress a metadata block or datablock.  Length is non-zero
 * if a datablock is being read (the size is stored elsewhere in the
 * filesystem), otherwise the length is obtained from the first two bytes of
 * the metadata block.  A bit in the length field indicates if the block
 * is stored uncompressed in the filesystem (usually because compression
 * generated a larger block - this does occasionally happen with compression
 * algorithms).
 */
int squashfs_read_data(struct super_block *sb, u64 index, int length,
		u64 *next_index, struct squashfs_page_actor *output)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	struct buffer_head **bh;
	int offset = index & ((1 << msblk->devblksize_log2) - 1);
	u64 cur_index = index >> msblk->devblksize_log2;
	int bytes, compressed, b = 0, k = 0, avail, i;

	bh = kcalloc(((output->length + msblk->devblksize - 1)
		>> msblk->devblksize_log2) + 1, sizeof(*bh), GFP_KERNEL);
	if (bh == NULL)
		return -ENOMEM;

	if (length) {
		/*
		 * Datablock.
		 */
		bytes = -offset;
		compressed = SQUASHFS_COMPRESSED_BLOCK(length);
		length = SQUASHFS_COMPRESSED_SIZE_BLOCK(length);
		if (next_index)
			*next_index = index + length;

		TRACE("Block @ 0x%llx, %scompressed size %d, src size %d\n",
			index, compressed ? "" : "un", length, output->length);

		if (length < 0 || length > output->length ||
				(index + length) > msblk->bytes_used)
			goto read_failure;

		for (b = 0; bytes < length; b++, cur_index++) {
			bh[b] = sb_getblk(sb, cur_index);
			if (bh[b] == NULL)
				goto block_release;
			bytes += msblk->devblksize;
		}
		ll_rw_block(READ, b, bh);
	} else {
		/*
		 * Metadata block.
		 */
		if ((index + 2) > msblk->bytes_used)
			goto read_failure;

		bh[0] = get_block_length(sb, &cur_index, &offset, &length);
		if (bh[0] == NULL)
			goto read_failure;
		b = 1;

		bytes = msblk->devblksize - offset;
		compressed = SQUASHFS_COMPRESSED(length);
		length = SQUASHFS_COMPRESSED_SIZE(length);
		if (next_index)
			*next_index = index + length + 2;

		TRACE("Block @ 0x%llx, %scompressed size %d\n", index,
				compressed ? "" : "un", length);

		if (length < 0 || length > output->length ||
					(index + length) > msblk->bytes_used)
			goto block_release;

		for (; bytes < length; b++) {
			bh[b] = sb_getblk(sb, ++cur_index);
			if (bh[b] == NULL)
				goto block_release;
			bytes += msblk->devblksize;
		}
		ll_rw_block(READ, b - 1, bh + 1);
	}

	for (i = 0; i < b; i++) {
		wait_on_buffer(bh[i]);
		if (!buffer_uptodate(bh[i]))
			goto block_release;
	}

	if (compressed) {
		length = squashfs_decompress(msblk, bh, b, offset, length,
			output);
		if (length < 0)
			goto read_failure;
	} else {
		/*
		 * Block is uncompressed.
		 */
		int in, pg_offset = 0;
		void *data = squashfs_first_page(output);

		for (bytes = length; k < b; k++) {
			in = min(bytes, msblk->devblksize - offset);
			bytes -= in;
			while (in) {
				if (pg_offset == PAGE_CACHE_SIZE) {
					data = squashfs_next_page(output);
					pg_offset = 0;
				}
				avail = min_t(int, in, PAGE_CACHE_SIZE -
						pg_offset);
				memcpy(data + pg_offset, bh[k]->b_data + offset,
						avail);
				in -= avail;
				pg_offset += avail;
				offset += avail;
			}
			offset = 0;
			put_bh(bh[k]);
		}
		squashfs_finish_page(output);
	}

	kfree(bh);
	return length;

block_release:
	for (; k < b; k++)
		put_bh(bh[k]);

read_failure:
	ERROR("squashfs_read_data failed to read block 0x%llx\n",
					(unsigned long long) index);
	kfree(bh);
	return -EIO;
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/block.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * cache.c
 */

/*
 * Blocks in Squashfs are compressed.  To avoid repeatedly decompressing
 * recently accessed data Squashfs uses two small metadata and fragment caches.
 *
 * This file implements a generic cache implementation used for both caches,
 * plus functions layered ontop of the generic cache implementation to
 * access the metadata and fragment caches.
 *
 * To avoid out of memory and fragmentation issues with vmalloc the cache
 * uses sequences of kmalloced PAGE_CACHE_SIZE buffers.
 *
 * It should be noted that the cache is not used for file datablocks, these
 * are decompressed and cached in the page-cache in the normal way.  The
 * cache is only used to temporarily cache fragment and metadata blocks
 * which have been read as as a result of a metadata (i.e. inode or
 * directory) or fragment access.  Because metadata and fragments are packed
 * together into blocks (to gain greater compression) the read of a particular
 * piece of metadata or fragment will retrieve other metadata/fragments which
 * have been packed with it, these because of locality-of-reference may be read
 * in the near future. Temporarily caching them ensures they are available for
 * near future access without requiring an additional read and decompress.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/pagemap.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs.h"
// #include "page_actor.h"

/*
 * Look-up block in cache, and increment usage count.  If not in cache, read
 * and decompress it from disk.
 */
struct squashfs_cache_entry *squashfs_cache_get(struct super_block *sb,
	struct squashfs_cache *cache, u64 block, int length)
{
	int i, n;
	struct squashfs_cache_entry *entry;

	spin_lock(&cache->lock);

	while (1) {
		for (i = cache->curr_blk, n = 0; n < cache->entries; n++) {
			if (cache->entry[i].block == block) {
				cache->curr_blk = i;
				break;
			}
			i = (i + 1) % cache->entries;
		}

		if (n == cache->entries) {
			/*
			 * Block not in cache, if all cache entries are used
			 * go to sleep waiting for one to become available.
			 */
			if (cache->unused == 0) {
				cache->num_waiters++;
				spin_unlock(&cache->lock);
				wait_event(cache->wait_queue, cache->unused);
				spin_lock(&cache->lock);
				cache->num_waiters--;
				continue;
			}

			/*
			 * At least one unused cache entry.  A simple
			 * round-robin strategy is used to choose the entry to
			 * be evicted from the cache.
			 */
			i = cache->next_blk;
			for (n = 0; n < cache->entries; n++) {
				if (cache->entry[i].refcount == 0)
					break;
				i = (i + 1) % cache->entries;
			}

			cache->next_blk = (i + 1) % cache->entries;
			entry = &cache->entry[i];

			/*
			 * Initialise chosen cache entry, and fill it in from
			 * disk.
			 */
			cache->unused--;
			entry->block = block;
			entry->refcount = 1;
			entry->pending = 1;
			entry->num_waiters = 0;
			entry->error = 0;
			spin_unlock(&cache->lock);

			entry->length = squashfs_read_data(sb, block, length,
				&entry->next_index, entry->actor);

			spin_lock(&cache->lock);

			if (entry->length < 0)
				entry->error = entry->length;

			entry->pending = 0;

			/*
			 * While filling this entry one or more other processes
			 * have looked it up in the cache, and have slept
			 * waiting for it to become available.
			 */
			if (entry->num_waiters) {
				spin_unlock(&cache->lock);
				wake_up_all(&entry->wait_queue);
			} else
				spin_unlock(&cache->lock);

			goto out;
		}

		/*
		 * Block already in cache.  Increment refcount so it doesn't
		 * get reused until we're finished with it, if it was
		 * previously unused there's one less cache entry available
		 * for reuse.
		 */
		entry = &cache->entry[i];
		if (entry->refcount == 0)
			cache->unused--;
		entry->refcount++;

		/*
		 * If the entry is currently being filled in by another process
		 * go to sleep waiting for it to become available.
		 */
		if (entry->pending) {
			entry->num_waiters++;
			spin_unlock(&cache->lock);
			wait_event(entry->wait_queue, !entry->pending);
		} else
			spin_unlock(&cache->lock);

		goto out;
	}

out:
	TRACE("Got %s %d, start block %lld, refcount %d, error %d\n",
		cache->name, i, entry->block, entry->refcount, entry->error);

	if (entry->error)
		ERROR("Unable to read %s cache entry [%llx]\n", cache->name,
							block);
	return entry;
}


/*
 * Release cache entry, once usage count is zero it can be reused.
 */
void squashfs_cache_put(struct squashfs_cache_entry *entry)
{
	struct squashfs_cache *cache = entry->cache;

	spin_lock(&cache->lock);
	entry->refcount--;
	if (entry->refcount == 0) {
		cache->unused++;
		/*
		 * If there's any processes waiting for a block to become
		 * available, wake one up.
		 */
		if (cache->num_waiters) {
			spin_unlock(&cache->lock);
			wake_up(&cache->wait_queue);
			return;
		}
	}
	spin_unlock(&cache->lock);
}

/*
 * Delete cache reclaiming all kmalloced buffers.
 */
void squashfs_cache_delete(struct squashfs_cache *cache)
{
	int i, j;

	if (cache == NULL)
		return;

	for (i = 0; i < cache->entries; i++) {
		if (cache->entry[i].data) {
			for (j = 0; j < cache->pages; j++)
				kfree(cache->entry[i].data[j]);
			kfree(cache->entry[i].data);
		}
		kfree(cache->entry[i].actor);
	}

	kfree(cache->entry);
	kfree(cache);
}


/*
 * Initialise cache allocating the specified number of entries, each of
 * size block_size.  To avoid vmalloc fragmentation issues each entry
 * is allocated as a sequence of kmalloced PAGE_CACHE_SIZE buffers.
 */
struct squashfs_cache *squashfs_cache_init(char *name, int entries,
	int block_size)
{
	int i, j;
	struct squashfs_cache *cache = kzalloc(sizeof(*cache), GFP_KERNEL);

	if (cache == NULL) {
		ERROR("Failed to allocate %s cache\n", name);
		return NULL;
	}

	cache->entry = kcalloc(entries, sizeof(*(cache->entry)), GFP_KERNEL);
	if (cache->entry == NULL) {
		ERROR("Failed to allocate %s cache\n", name);
		goto cleanup;
	}

	cache->curr_blk = 0;
	cache->next_blk = 0;
	cache->unused = entries;
	cache->entries = entries;
	cache->block_size = block_size;
	cache->pages = block_size >> PAGE_CACHE_SHIFT;
	cache->pages = cache->pages ? cache->pages : 1;
	cache->name = name;
	cache->num_waiters = 0;
	spin_lock_init(&cache->lock);
	init_waitqueue_head(&cache->wait_queue);

	for (i = 0; i < entries; i++) {
		struct squashfs_cache_entry *entry = &cache->entry[i];

		init_waitqueue_head(&cache->entry[i].wait_queue);
		entry->cache = cache;
		entry->block = SQUASHFS_INVALID_BLK;
		entry->data = kcalloc(cache->pages, sizeof(void *), GFP_KERNEL);
		if (entry->data == NULL) {
			ERROR("Failed to allocate %s cache entry\n", name);
			goto cleanup;
		}

		for (j = 0; j < cache->pages; j++) {
			entry->data[j] = kmalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
			if (entry->data[j] == NULL) {
				ERROR("Failed to allocate %s buffer\n", name);
				goto cleanup;
			}
		}

		entry->actor = squashfs_page_actor_init(entry->data,
						cache->pages, 0);
		if (entry->actor == NULL) {
			ERROR("Failed to allocate %s cache entry\n", name);
			goto cleanup;
		}
	}

	return cache;

cleanup:
	squashfs_cache_delete(cache);
	return NULL;
}


/*
 * Copy up to length bytes from cache entry to buffer starting at offset bytes
 * into the cache entry.  If there's not length bytes then copy the number of
 * bytes available.  In all cases return the number of bytes copied.
 */
int squashfs_copy_data(void *buffer, struct squashfs_cache_entry *entry,
		int offset, int length)
{
	int remaining = length;

	if (length == 0)
		return 0;
	else if (buffer == NULL)
		return min(length, entry->length - offset);

	while (offset < entry->length) {
		void *buff = entry->data[offset / PAGE_CACHE_SIZE]
				+ (offset % PAGE_CACHE_SIZE);
		int bytes = min_t(int, entry->length - offset,
				PAGE_CACHE_SIZE - (offset % PAGE_CACHE_SIZE));

		if (bytes >= remaining) {
			memcpy(buffer, buff, remaining);
			remaining = 0;
			break;
		}

		memcpy(buffer, buff, bytes);
		buffer += bytes;
		remaining -= bytes;
		offset += bytes;
	}

	return length - remaining;
}


/*
 * Read length bytes from metadata position <block, offset> (block is the
 * start of the compressed block on disk, and offset is the offset into
 * the block once decompressed).  Data is packed into consecutive blocks,
 * and length bytes may require reading more than one block.
 */
int squashfs_read_metadata(struct super_block *sb, void *buffer,
		u64 *block, int *offset, int length)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int bytes, res = length;
	struct squashfs_cache_entry *entry;

	TRACE("Entered squashfs_read_metadata [%llx:%x]\n", *block, *offset);

	while (length) {
		entry = squashfs_cache_get(sb, msblk->block_cache, *block, 0);
		if (entry->error) {
			res = entry->error;
			goto error;
		} else if (*offset >= entry->length) {
			res = -EIO;
			goto error;
		}

		bytes = squashfs_copy_data(buffer, entry, *offset, length);
		if (buffer)
			buffer += bytes;
		length -= bytes;
		*offset += bytes;

		if (*offset == entry->length) {
			*block = entry->next_index;
			*offset = 0;
		}

		squashfs_cache_put(entry);
	}

	return res;

error:
	squashfs_cache_put(entry);
	return res;
}


/*
 * Look-up in the fragmment cache the fragment located at <start_block> in the
 * filesystem.  If necessary read and decompress it from disk.
 */
struct squashfs_cache_entry *squashfs_get_fragment(struct super_block *sb,
				u64 start_block, int length)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;

	return squashfs_cache_get(sb, msblk->fragment_cache, start_block,
		length);
}


/*
 * Read and decompress the datablock located at <start_block> in the
 * filesystem.  The cache is used here to avoid duplicating locking and
 * read/decompress code.
 */
struct squashfs_cache_entry *squashfs_get_datablock(struct super_block *sb,
				u64 start_block, int length)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;

	return squashfs_cache_get(sb, msblk->read_page, start_block, length);
}


/*
 * Read a filesystem table (uncompressed sequence of bytes) from disk
 */
void *squashfs_read_table(struct super_block *sb, u64 block, int length)
{
	int pages = (length + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	int i, res;
	void *table, *buffer, **data;
	struct squashfs_page_actor *actor;

	table = buffer = kmalloc(length, GFP_KERNEL);
	if (table == NULL)
		return ERR_PTR(-ENOMEM);

	data = kcalloc(pages, sizeof(void *), GFP_KERNEL);
	if (data == NULL) {
		res = -ENOMEM;
		goto failed;
	}

	actor = squashfs_page_actor_init(data, pages, length);
	if (actor == NULL) {
		res = -ENOMEM;
		goto failed2;
	}

	for (i = 0; i < pages; i++, buffer += PAGE_CACHE_SIZE)
		data[i] = buffer;

	res = squashfs_read_data(sb, block, length |
		SQUASHFS_COMPRESSED_BIT_BLOCK, NULL, actor);

	kfree(data);
	kfree(actor);

	if (res < 0)
		goto failed;

	return table;

failed2:
	kfree(data);
failed:
	kfree(table);
	return ERR_PTR(res);
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/cache.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * dir.c
 */

/*
 * This file implements code to read directories from disk.
 *
 * See namei.c for a description of directory organisation on disk.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/slab.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
#include "squashfs_fs_i.h"
// #include "squashfs.h"

static const unsigned char squashfs_filetype_table[] = {
	DT_UNKNOWN, DT_DIR, DT_REG, DT_LNK, DT_BLK, DT_CHR, DT_FIFO, DT_SOCK
};

/*
 * Lookup offset (f_pos) in the directory index, returning the
 * metadata block containing it.
 *
 * If we get an error reading the index then return the part of the index
 * (if any) we have managed to read - the index isn't essential, just
 * quicker.
 */
static int get_dir_index_using_offset(struct super_block *sb,
	u64 *next_block, int *next_offset, u64 index_start, int index_offset,
	int i_count, u64 f_pos)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int err, i, index, length = 0;
	unsigned int size;
	struct squashfs_dir_index dir_index;

	TRACE("Entered get_dir_index_using_offset, i_count %d, f_pos %lld\n",
					i_count, f_pos);

	/*
	 * Translate from external f_pos to the internal f_pos.  This
	 * is offset by 3 because we invent "." and ".." entries which are
	 * not actually stored in the directory.
	 */
	if (f_pos <= 3)
		return f_pos;
	f_pos -= 3;

	for (i = 0; i < i_count; i++) {
		err = squashfs_read_metadata(sb, &dir_index, &index_start,
				&index_offset, sizeof(dir_index));
		if (err < 0)
			break;

		index = le32_to_cpu(dir_index.index);
		if (index > f_pos)
			/*
			 * Found the index we're looking for.
			 */
			break;

		size = le32_to_cpu(dir_index.size) + 1;

		/* size should never be larger than SQUASHFS_NAME_LEN */
		if (size > SQUASHFS_NAME_LEN)
			break;

		err = squashfs_read_metadata(sb, NULL, &index_start,
				&index_offset, size);
		if (err < 0)
			break;

		length = index;
		*next_block = le32_to_cpu(dir_index.start_block) +
					msblk->directory_table;
	}

	*next_offset = (length + *next_offset) % SQUASHFS_METADATA_SIZE;

	/*
	 * Translate back from internal f_pos to external f_pos.
	 */
	return length + 3;
}


static int squashfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	u64 block = squashfs_i(inode)->start + msblk->directory_table;
	int offset = squashfs_i(inode)->offset, length, err;
	unsigned int inode_number, dir_count, size, type;
	struct squashfs_dir_header dirh;
	struct squashfs_dir_entry *dire;

	TRACE("Entered squashfs_readdir [%llx:%x]\n", block, offset);

	dire = kmalloc(sizeof(*dire) + SQUASHFS_NAME_LEN + 1, GFP_KERNEL);
	if (dire == NULL) {
		ERROR("Failed to allocate squashfs_dir_entry\n");
		goto finish;
	}

	/*
	 * Return "." and  ".." entries as the first two filenames in the
	 * directory.  To maximise compression these two entries are not
	 * stored in the directory, and so we invent them here.
	 *
	 * It also means that the external f_pos is offset by 3 from the
	 * on-disk directory f_pos.
	 */
	while (ctx->pos < 3) {
		char *name;
		int i_ino;

		if (ctx->pos == 0) {
			name = ".";
			size = 1;
			i_ino = inode->i_ino;
		} else {
			name = "..";
			size = 2;
			i_ino = squashfs_i(inode)->parent;
		}

		if (!dir_emit(ctx, name, size, i_ino,
				squashfs_filetype_table[1]))
			goto finish;

		ctx->pos += size;
	}

	length = get_dir_index_using_offset(inode->i_sb, &block, &offset,
				squashfs_i(inode)->dir_idx_start,
				squashfs_i(inode)->dir_idx_offset,
				squashfs_i(inode)->dir_idx_cnt,
				ctx->pos);

	while (length < i_size_read(inode)) {
		/*
		 * Read directory header
		 */
		err = squashfs_read_metadata(inode->i_sb, &dirh, &block,
					&offset, sizeof(dirh));
		if (err < 0)
			goto failed_read;

		length += sizeof(dirh);

		dir_count = le32_to_cpu(dirh.count) + 1;

		if (dir_count > SQUASHFS_DIR_COUNT)
			goto failed_read;

		while (dir_count--) {
			/*
			 * Read directory entry.
			 */
			err = squashfs_read_metadata(inode->i_sb, dire, &block,
					&offset, sizeof(*dire));
			if (err < 0)
				goto failed_read;

			size = le16_to_cpu(dire->size) + 1;

			/* size should never be larger than SQUASHFS_NAME_LEN */
			if (size > SQUASHFS_NAME_LEN)
				goto failed_read;

			err = squashfs_read_metadata(inode->i_sb, dire->name,
					&block, &offset, size);
			if (err < 0)
				goto failed_read;

			length += sizeof(*dire) + size;

			if (ctx->pos >= length)
				continue;

			dire->name[size] = '\0';
			inode_number = le32_to_cpu(dirh.inode_number) +
				((short) le16_to_cpu(dire->inode_number));
			type = le16_to_cpu(dire->type);

			if (type > SQUASHFS_MAX_DIR_TYPE)
				goto failed_read;

			if (!dir_emit(ctx, dire->name, size,
					inode_number,
					squashfs_filetype_table[type]))
				goto finish;

			ctx->pos = length;
		}
	}

finish:
	kfree(dire);
	return 0;

failed_read:
	ERROR("Unable to read directory block [%llx:%x]\n", block, offset);
	kfree(dire);
	return 0;
}


const struct file_operations squashfs_dir_ops = {
	.read = generic_read_dir,
	.iterate = squashfs_readdir,
	.llseek = default_llseek,
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/dir.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * export.c
 */

/*
 * This file implements code to make Squashfs filesystems exportable (NFS etc.)
 *
 * The export code uses an inode lookup table to map inode numbers passed in
 * filehandles to an inode location on disk.  This table is stored compressed
 * into metadata blocks.  A second index table is used to locate these.  This
 * second index table for speed of access (and because it is small) is read at
 * mount time and cached in memory.
 *
 * The inode lookup table is used only by the export code, inode disk
 * locations are directly encoded in directories, enabling direct access
 * without an intermediate lookup for all operations except the export ops.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
#include <linux/dcache.h>
#include <linux/exportfs.h>
// #include <linux/slab.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs_fs_i.h"
// #include "squashfs.h"

/*
 * Look-up inode number (ino) in table, returning the inode location.
 */
static long long squashfs_inode_lookup(struct super_block *sb, int ino_num)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int blk = SQUASHFS_LOOKUP_BLOCK(ino_num - 1);
	int offset = SQUASHFS_LOOKUP_BLOCK_OFFSET(ino_num - 1);
	u64 start = le64_to_cpu(msblk->inode_lookup_table[blk]);
	__le64 ino;
	int err;

	TRACE("Entered squashfs_inode_lookup, inode_number = %d\n", ino_num);

	err = squashfs_read_metadata(sb, &ino, &start, &offset, sizeof(ino));
	if (err < 0)
		return err;

	TRACE("squashfs_inode_lookup, inode = 0x%llx\n",
		(u64) le64_to_cpu(ino));

	return le64_to_cpu(ino);
}


static struct dentry *squashfs_export_iget(struct super_block *sb,
	unsigned int ino_num)
{
	long long ino;
	struct dentry *dentry = ERR_PTR(-ENOENT);

	TRACE("Entered squashfs_export_iget\n");

	ino = squashfs_inode_lookup(sb, ino_num);
	if (ino >= 0)
		dentry = d_obtain_alias(squashfs_iget(sb, ino, ino_num));

	return dentry;
}


static struct dentry *squashfs_fh_to_dentry(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	if ((fh_type != FILEID_INO32_GEN && fh_type != FILEID_INO32_GEN_PARENT)
			|| fh_len < 2)
		return NULL;

	return squashfs_export_iget(sb, fid->i32.ino);
}


static struct dentry *squashfs_fh_to_parent(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	if (fh_type != FILEID_INO32_GEN_PARENT || fh_len < 4)
		return NULL;

	return squashfs_export_iget(sb, fid->i32.parent_ino);
}


static struct dentry *squashfs_get_parent(struct dentry *child)
{
	struct inode *inode = child->d_inode;
	unsigned int parent_ino = squashfs_i(inode)->parent;

	return squashfs_export_iget(inode->i_sb, parent_ino);
}


/*
 * Read uncompressed inode lookup table indexes off disk into memory
 */
__le64 *squashfs_read_inode_lookup_table(struct super_block *sb,
		u64 lookup_table_start, u64 next_table, unsigned int inodes)
{
	unsigned int length = SQUASHFS_LOOKUP_BLOCK_BYTES(inodes);
	__le64 *table;

	TRACE("In read_inode_lookup_table, length %d\n", length);

	/* Sanity check values */

	/* there should always be at least one inode */
	if (inodes == 0)
		return ERR_PTR(-EINVAL);

	/* length bytes should not extend into the next table - this check
	 * also traps instances where lookup_table_start is incorrectly larger
	 * than the next table start
	 */
	if (lookup_table_start + length > next_table)
		return ERR_PTR(-EINVAL);

	table = squashfs_read_table(sb, lookup_table_start, length);

	/*
	 * table[0] points to the first inode lookup table metadata block,
	 * this should be less than lookup_table_start
	 */
	if (!IS_ERR(table) && le64_to_cpu(table[0]) >= lookup_table_start) {
		kfree(table);
		return ERR_PTR(-EINVAL);
	}

	return table;
}


const struct export_operations squashfs_export_ops = {
	.fh_to_dentry = squashfs_fh_to_dentry,
	.fh_to_parent = squashfs_fh_to_parent,
	.get_parent = squashfs_get_parent
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/export.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * file.c
 */

/*
 * This file contains code for handling regular files.  A regular file
 * consists of a sequence of contiguous compressed blocks, and/or a
 * compressed fragment block (tail-end packed block).   The compressed size
 * of each datablock is stored in a block list contained within the
 * file inode (itself stored in one or more compressed metadata blocks).
 *
 * To speed up access to datablocks when reading 'large' files (256 Mbytes or
 * larger), the code implements an index cache that caches the mapping from
 * block index to datablock location on disk.
 *
 * The index cache allows Squashfs to handle large files (up to 1.75 TiB) while
 * retaining a simple and space-efficient block list on disk.  The cache
 * is split into slots, caching up to eight 224 GiB files (128 KiB blocks).
 * Larger files use multiple slots, with 1.75 TiB files using all 8 slots.
 * The index cache is designed to be memory efficient, and by default uses
 * 16 KiB.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
#include <linux/kernel.h>
// #include <linux/slab.h>
// #include <linux/string.h>
// #include <linux/pagemap.h>
#include <linux/mutex.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs_fs_i.h"
// #include "squashfs.h"

/*
 * Locate cache slot in range [offset, index] for specified inode.  If
 * there's more than one return the slot closest to index.
 */
static struct meta_index *locate_meta_index(struct inode *inode, int offset,
				int index)
{
	struct meta_index *meta = NULL;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	int i;

	mutex_lock(&msblk->meta_index_mutex);

	TRACE("locate_meta_index: index %d, offset %d\n", index, offset);

	if (msblk->meta_index == NULL)
		goto not_allocated;

	for (i = 0; i < SQUASHFS_META_SLOTS; i++) {
		if (msblk->meta_index[i].inode_number == inode->i_ino &&
				msblk->meta_index[i].offset >= offset &&
				msblk->meta_index[i].offset <= index &&
				msblk->meta_index[i].locked == 0) {
			TRACE("locate_meta_index: entry %d, offset %d\n", i,
					msblk->meta_index[i].offset);
			meta = &msblk->meta_index[i];
			offset = meta->offset;
		}
	}

	if (meta)
		meta->locked = 1;

not_allocated:
	mutex_unlock(&msblk->meta_index_mutex);

	return meta;
}


/*
 * Find and initialise an empty cache slot for index offset.
 */
static struct meta_index *empty_meta_index(struct inode *inode, int offset,
				int skip)
{
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	struct meta_index *meta = NULL;
	int i;

	mutex_lock(&msblk->meta_index_mutex);

	TRACE("empty_meta_index: offset %d, skip %d\n", offset, skip);

	if (msblk->meta_index == NULL) {
		/*
		 * First time cache index has been used, allocate and
		 * initialise.  The cache index could be allocated at
		 * mount time but doing it here means it is allocated only
		 * if a 'large' file is read.
		 */
		msblk->meta_index = kcalloc(SQUASHFS_META_SLOTS,
			sizeof(*(msblk->meta_index)), GFP_KERNEL);
		if (msblk->meta_index == NULL) {
			ERROR("Failed to allocate meta_index\n");
			goto failed;
		}
		for (i = 0; i < SQUASHFS_META_SLOTS; i++) {
			msblk->meta_index[i].inode_number = 0;
			msblk->meta_index[i].locked = 0;
		}
		msblk->next_meta_index = 0;
	}

	for (i = SQUASHFS_META_SLOTS; i &&
			msblk->meta_index[msblk->next_meta_index].locked; i--)
		msblk->next_meta_index = (msblk->next_meta_index + 1) %
			SQUASHFS_META_SLOTS;

	if (i == 0) {
		TRACE("empty_meta_index: failed!\n");
		goto failed;
	}

	TRACE("empty_meta_index: returned meta entry %d, %p\n",
			msblk->next_meta_index,
			&msblk->meta_index[msblk->next_meta_index]);

	meta = &msblk->meta_index[msblk->next_meta_index];
	msblk->next_meta_index = (msblk->next_meta_index + 1) %
			SQUASHFS_META_SLOTS;

	meta->inode_number = inode->i_ino;
	meta->offset = offset;
	meta->skip = skip;
	meta->entries = 0;
	meta->locked = 1;

failed:
	mutex_unlock(&msblk->meta_index_mutex);
	return meta;
}


static void release_meta_index(struct inode *inode, struct meta_index *meta)
{
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	mutex_lock(&msblk->meta_index_mutex);
	meta->locked = 0;
	mutex_unlock(&msblk->meta_index_mutex);
}


/*
 * Read the next n blocks from the block list, starting from
 * metadata block <start_block, offset>.
 */
static long long read_indexes(struct super_block *sb, int n,
				u64 *start_block, int *offset)
{
	int err, i;
	long long block = 0;
	__le32 *blist = kmalloc(PAGE_CACHE_SIZE, GFP_KERNEL);

	if (blist == NULL) {
		ERROR("read_indexes: Failed to allocate block_list\n");
		return -ENOMEM;
	}

	while (n) {
		int blocks = min_t(int, n, PAGE_CACHE_SIZE >> 2);

		err = squashfs_read_metadata(sb, blist, start_block,
				offset, blocks << 2);
		if (err < 0) {
			ERROR("read_indexes: reading block [%llx:%x]\n",
				*start_block, *offset);
			goto failure;
		}

		for (i = 0; i < blocks; i++) {
			int size = le32_to_cpu(blist[i]);
			block += SQUASHFS_COMPRESSED_SIZE_BLOCK(size);
		}
		n -= blocks;
	}

	kfree(blist);
	return block;

failure:
	kfree(blist);
	return err;
}


/*
 * Each cache index slot has SQUASHFS_META_ENTRIES, each of which
 * can cache one index -> datablock/blocklist-block mapping.  We wish
 * to distribute these over the length of the file, entry[0] maps index x,
 * entry[1] maps index x + skip, entry[2] maps index x + 2 * skip, and so on.
 * The larger the file, the greater the skip factor.  The skip factor is
 * limited to the size of the metadata cache (SQUASHFS_CACHED_BLKS) to ensure
 * the number of metadata blocks that need to be read fits into the cache.
 * If the skip factor is limited in this way then the file will use multiple
 * slots.
 */
static inline int calculate_skip(int blocks)
{
	int skip = blocks / ((SQUASHFS_META_ENTRIES + 1)
		 * SQUASHFS_META_INDEXES);
	return min(SQUASHFS_CACHED_BLKS - 1, skip + 1);
}


/*
 * Search and grow the index cache for the specified inode, returning the
 * on-disk locations of the datablock and block list metadata block
 * <index_block, index_offset> for index (scaled to nearest cache index).
 */
static int fill_meta_index(struct inode *inode, int index,
		u64 *index_block, int *index_offset, u64 *data_block)
{
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	int skip = calculate_skip(i_size_read(inode) >> msblk->block_log);
	int offset = 0;
	struct meta_index *meta;
	struct meta_entry *meta_entry;
	u64 cur_index_block = squashfs_i(inode)->block_list_start;
	int cur_offset = squashfs_i(inode)->offset;
	u64 cur_data_block = squashfs_i(inode)->start;
	int err, i;

	/*
	 * Scale index to cache index (cache slot entry)
	 */
	index /= SQUASHFS_META_INDEXES * skip;

	while (offset < index) {
		meta = locate_meta_index(inode, offset + 1, index);

		if (meta == NULL) {
			meta = empty_meta_index(inode, offset + 1, skip);
			if (meta == NULL)
				goto all_done;
		} else {
			offset = index < meta->offset + meta->entries ? index :
				meta->offset + meta->entries - 1;
			meta_entry = &meta->meta_entry[offset - meta->offset];
			cur_index_block = meta_entry->index_block +
				msblk->inode_table;
			cur_offset = meta_entry->offset;
			cur_data_block = meta_entry->data_block;
			TRACE("get_meta_index: offset %d, meta->offset %d, "
				"meta->entries %d\n", offset, meta->offset,
				meta->entries);
			TRACE("get_meta_index: index_block 0x%llx, offset 0x%x"
				" data_block 0x%llx\n", cur_index_block,
				cur_offset, cur_data_block);
		}

		/*
		 * If necessary grow cache slot by reading block list.  Cache
		 * slot is extended up to index or to the end of the slot, in
		 * which case further slots will be used.
		 */
		for (i = meta->offset + meta->entries; i <= index &&
				i < meta->offset + SQUASHFS_META_ENTRIES; i++) {
			int blocks = skip * SQUASHFS_META_INDEXES;
			long long res = read_indexes(inode->i_sb, blocks,
					&cur_index_block, &cur_offset);

			if (res < 0) {
				if (meta->entries == 0)
					/*
					 * Don't leave an empty slot on read
					 * error allocated to this inode...
					 */
					meta->inode_number = 0;
				err = res;
				goto failed;
			}

			cur_data_block += res;
			meta_entry = &meta->meta_entry[i - meta->offset];
			meta_entry->index_block = cur_index_block -
				msblk->inode_table;
			meta_entry->offset = cur_offset;
			meta_entry->data_block = cur_data_block;
			meta->entries++;
			offset++;
		}

		TRACE("get_meta_index: meta->offset %d, meta->entries %d\n",
				meta->offset, meta->entries);

		release_meta_index(inode, meta);
	}

all_done:
	*index_block = cur_index_block;
	*index_offset = cur_offset;
	*data_block = cur_data_block;

	/*
	 * Scale cache index (cache slot entry) to index
	 */
	return offset * SQUASHFS_META_INDEXES * skip;

failed:
	release_meta_index(inode, meta);
	return err;
}


/*
 * Get the on-disk location and compressed size of the datablock
 * specified by index.  Fill_meta_index() does most of the work.
 */
static int read_blocklist(struct inode *inode, int index, u64 *block)
{
	u64 start;
	long long blks;
	int offset;
	__le32 size;
	int res = fill_meta_index(inode, index, &start, &offset, block);

	TRACE("read_blocklist: res %d, index %d, start 0x%llx, offset"
		       " 0x%x, block 0x%llx\n", res, index, start, offset,
			*block);

	if (res < 0)
		return res;

	/*
	 * res contains the index of the mapping returned by fill_meta_index(),
	 * this will likely be less than the desired index (because the
	 * meta_index cache works at a higher granularity).  Read any
	 * extra block indexes needed.
	 */
	if (res < index) {
		blks = read_indexes(inode->i_sb, index - res, &start, &offset);
		if (blks < 0)
			return (int) blks;
		*block += blks;
	}

	/*
	 * Read length of block specified by index.
	 */
	res = squashfs_read_metadata(inode->i_sb, &size, &start, &offset,
			sizeof(size));
	if (res < 0)
		return res;
	return le32_to_cpu(size);
}

/* Copy data into page cache  */
void squashfs_copy_cache(struct page *page, struct squashfs_cache_entry *buffer,
	int bytes, int offset)
{
	struct inode *inode = page->mapping->host;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	void *pageaddr;
	int i, mask = (1 << (msblk->block_log - PAGE_CACHE_SHIFT)) - 1;
	int start_index = page->index & ~mask, end_index = start_index | mask;

	/*
	 * Loop copying datablock into pages.  As the datablock likely covers
	 * many PAGE_CACHE_SIZE pages (default block size is 128 KiB) explicitly
	 * grab the pages from the page cache, except for the page that we've
	 * been called to fill.
	 */
	for (i = start_index; i <= end_index && bytes > 0; i++,
			bytes -= PAGE_CACHE_SIZE, offset += PAGE_CACHE_SIZE) {
		struct page *push_page;
		int avail = buffer ? min_t(int, bytes, PAGE_CACHE_SIZE) : 0;

		TRACE("bytes %d, i %d, available_bytes %d\n", bytes, i, avail);

		push_page = (i == page->index) ? page :
			grab_cache_page_nowait(page->mapping, i);

		if (!push_page)
			continue;

		if (PageUptodate(push_page))
			goto skip_page;

		pageaddr = kmap_atomic(push_page);
		squashfs_copy_data(pageaddr, buffer, offset, avail);
		memset(pageaddr + avail, 0, PAGE_CACHE_SIZE - avail);
		kunmap_atomic(pageaddr);
		flush_dcache_page(push_page);
		SetPageUptodate(push_page);
skip_page:
		unlock_page(push_page);
		if (i != page->index)
			page_cache_release(push_page);
	}
}

/* Read datablock stored packed inside a fragment (tail-end packed block) */
static int squashfs_readpage_fragment(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	struct squashfs_cache_entry *buffer = squashfs_get_fragment(inode->i_sb,
		squashfs_i(inode)->fragment_block,
		squashfs_i(inode)->fragment_size);
	int res = buffer->error;

	if (res)
		ERROR("Unable to read page, block %llx, size %x\n",
			squashfs_i(inode)->fragment_block,
			squashfs_i(inode)->fragment_size);
	else
		squashfs_copy_cache(page, buffer, i_size_read(inode) &
			(msblk->block_size - 1),
			squashfs_i(inode)->fragment_offset);

	squashfs_cache_put(buffer);
	return res;
}

static int squashfs_readpage_sparse(struct page *page, int index, int file_end)
{
	struct inode *inode = page->mapping->host;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	int bytes = index == file_end ?
			(i_size_read(inode) & (msblk->block_size - 1)) :
			 msblk->block_size;

	squashfs_copy_cache(page, NULL, bytes, 0);
	return 0;
}

static int squashfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	int index = page->index >> (msblk->block_log - PAGE_CACHE_SHIFT);
	int file_end = i_size_read(inode) >> msblk->block_log;
	int res;
	void *pageaddr;

	TRACE("Entered squashfs_readpage, page index %lx, start block %llx\n",
				page->index, squashfs_i(inode)->start);

	if (page->index >= ((i_size_read(inode) + PAGE_CACHE_SIZE - 1) >>
					PAGE_CACHE_SHIFT))
		goto out;

	if (index < file_end || squashfs_i(inode)->fragment_block ==
					SQUASHFS_INVALID_BLK) {
		u64 block = 0;
		int bsize = read_blocklist(inode, index, &block);
		if (bsize < 0)
			goto error_out;

		if (bsize == 0)
			res = squashfs_readpage_sparse(page, index, file_end);
		else
			res = squashfs_readpage_block(page, block, bsize);
	} else
		res = squashfs_readpage_fragment(page);

	if (!res)
		return 0;

error_out:
	SetPageError(page);
out:
	pageaddr = kmap_atomic(page);
	memset(pageaddr, 0, PAGE_CACHE_SIZE);
	kunmap_atomic(pageaddr);
	flush_dcache_page(page);
	if (!PageError(page))
		SetPageUptodate(page);
	unlock_page(page);

	return 0;
}


const struct address_space_operations squashfs_aops = {
	.readpage = squashfs_readpage
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/file.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * fragment.c
 */

/*
 * This file implements code to handle compressed fragments (tail-end packed
 * datablocks).
 *
 * Regular files contain a fragment index which is mapped to a fragment
 * location on disk and compressed size using a fragment lookup table.
 * Like everything in Squashfs this fragment lookup table is itself stored
 * compressed into metadata blocks.  A second index table is used to locate
 * these.  This second index table for speed of access (and because it
 * is small) is read at mount time and cached in memory.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/slab.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs.h"

/*
 * Look-up fragment using the fragment index table.  Return the on disk
 * location of the fragment and its compressed size
 */
int squashfs_frag_lookup(struct super_block *sb, unsigned int fragment,
				u64 *fragment_block)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int block = SQUASHFS_FRAGMENT_INDEX(fragment);
	int offset = SQUASHFS_FRAGMENT_INDEX_OFFSET(fragment);
	u64 start_block = le64_to_cpu(msblk->fragment_index[block]);
	struct squashfs_fragment_entry fragment_entry;
	int size;

	size = squashfs_read_metadata(sb, &fragment_entry, &start_block,
					&offset, sizeof(fragment_entry));
	if (size < 0)
		return size;

	*fragment_block = le64_to_cpu(fragment_entry.start_block);
	size = le32_to_cpu(fragment_entry.size);

	return size;
}


/*
 * Read the uncompressed fragment lookup table indexes off disk into memory
 */
__le64 *squashfs_read_fragment_index_table(struct super_block *sb,
	u64 fragment_table_start, u64 next_table, unsigned int fragments)
{
	unsigned int length = SQUASHFS_FRAGMENT_INDEX_BYTES(fragments);
	__le64 *table;

	/*
	 * Sanity check, length bytes should not extend into the next table -
	 * this check also traps instances where fragment_table_start is
	 * incorrectly larger than the next table start
	 */
	if (fragment_table_start + length > next_table)
		return ERR_PTR(-EINVAL);

	table = squashfs_read_table(sb, fragment_table_start, length);

	/*
	 * table[0] points to the first fragment table metadata block, this
	 * should be less than fragment_table_start
	 */
	if (!IS_ERR(table) && le64_to_cpu(table[0]) >= fragment_table_start) {
		kfree(table);
		return ERR_PTR(-EINVAL);
	}

	return table;
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/fragment.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * id.c
 */

/*
 * This file implements code to handle uids and gids.
 *
 * For space efficiency regular files store uid and gid indexes, which are
 * converted to 32-bit uids/gids using an id look up table.  This table is
 * stored compressed into metadata blocks.  A second index table is used to
 * locate these.  This second index table for speed of access (and because it
 * is small) is read at mount time and cached in memory.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/slab.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs.h"

/*
 * Map uid/gid index into real 32-bit uid/gid using the id look up table
 */
int squashfs_get_id(struct super_block *sb, unsigned int index,
					unsigned int *id)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int block = SQUASHFS_ID_BLOCK(index);
	int offset = SQUASHFS_ID_BLOCK_OFFSET(index);
	u64 start_block = le64_to_cpu(msblk->id_table[block]);
	__le32 disk_id;
	int err;

	err = squashfs_read_metadata(sb, &disk_id, &start_block, &offset,
							sizeof(disk_id));
	if (err < 0)
		return err;

	*id = le32_to_cpu(disk_id);
	return 0;
}


/*
 * Read uncompressed id lookup table indexes from disk into memory
 */
__le64 *squashfs_read_id_index_table(struct super_block *sb,
		u64 id_table_start, u64 next_table, unsigned short no_ids)
{
	unsigned int length = SQUASHFS_ID_BLOCK_BYTES(no_ids);
	__le64 *table;

	TRACE("In read_id_index_table, length %d\n", length);

	/* Sanity check values */

	/* there should always be at least one id */
	if (no_ids == 0)
		return ERR_PTR(-EINVAL);

	/*
	 * length bytes should not extend into the next table - this check
	 * also traps instances where id_table_start is incorrectly larger
	 * than the next table start
	 */
	if (id_table_start + length > next_table)
		return ERR_PTR(-EINVAL);

	table = squashfs_read_table(sb, id_table_start, length);

	/*
	 * table[0] points to the first id lookup table metadata block, this
	 * should be less than id_table_start
	 */
	if (!IS_ERR(table) && le64_to_cpu(table[0]) >= id_table_start) {
		kfree(table);
		return ERR_PTR(-EINVAL);
	}

	return table;
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/id.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * inode.c
 */

/*
 * This file implements code to create and read inodes from disk.
 *
 * Inodes in Squashfs are identified by a 48-bit inode which encodes the
 * location of the compressed metadata block containing the inode, and the byte
 * offset into that block where the inode is placed (<block, offset>).
 *
 * To maximise compression there are different inodes for each file type
 * (regular file, directory, device, etc.), the inode contents and length
 * varying with the type.
 *
 * To further maximise compression, two types of regular file inode and
 * directory inode are defined: inodes optimised for frequently occurring
 * regular files and directories, and extended types where extra
 * information has to be stored.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
#include <linux/xattr.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs_fs_i.h"
// #include "squashfs.h"
#include "xattr.h"

/*
 * Initialise VFS inode with the base inode information common to all
 * Squashfs inode types.  Sqsh_ino contains the unswapped base inode
 * off disk.
 */
static int squashfs_new_inode(struct super_block *sb, struct inode *inode,
				struct squashfs_base_inode *sqsh_ino)
{
	uid_t i_uid;
	gid_t i_gid;
	int err;

	err = squashfs_get_id(sb, le16_to_cpu(sqsh_ino->uid), &i_uid);
	if (err)
		return err;

	err = squashfs_get_id(sb, le16_to_cpu(sqsh_ino->guid), &i_gid);
	if (err)
		return err;

	i_uid_write(inode, i_uid);
	i_gid_write(inode, i_gid);
	inode->i_ino = le32_to_cpu(sqsh_ino->inode_number);
	inode->i_mtime.tv_sec = le32_to_cpu(sqsh_ino->mtime);
	inode->i_atime.tv_sec = inode->i_mtime.tv_sec;
	inode->i_ctime.tv_sec = inode->i_mtime.tv_sec;
	inode->i_mode = le16_to_cpu(sqsh_ino->mode);
	inode->i_size = 0;

	return err;
}


struct inode *squashfs_iget(struct super_block *sb, long long ino,
				unsigned int ino_number)
{
	struct inode *inode = iget_locked(sb, ino_number);
	int err;

	TRACE("Entered squashfs_iget\n");

	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	err = squashfs_read_inode(inode, ino);
	if (err) {
		iget_failed(inode);
		return ERR_PTR(err);
	}

	unlock_new_inode(inode);
	return inode;
}


/*
 * Initialise VFS inode by reading inode from inode table (compressed
 * metadata).  The format and amount of data read depends on type.
 */
int squashfs_read_inode(struct inode *inode, long long ino)
{
	struct super_block *sb = inode->i_sb;
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	u64 block = SQUASHFS_INODE_BLK(ino) + msblk->inode_table;
	int err, type, offset = SQUASHFS_INODE_OFFSET(ino);
	union squashfs_inode squashfs_ino;
	struct squashfs_base_inode *sqshb_ino = &squashfs_ino.base;
	int xattr_id = SQUASHFS_INVALID_XATTR;

	TRACE("Entered squashfs_read_inode\n");

	/*
	 * Read inode base common to all inode types.
	 */
	err = squashfs_read_metadata(sb, sqshb_ino, &block,
				&offset, sizeof(*sqshb_ino));
	if (err < 0)
		goto failed_read;

	err = squashfs_new_inode(sb, inode, sqshb_ino);
	if (err)
		goto failed_read;

	block = SQUASHFS_INODE_BLK(ino) + msblk->inode_table;
	offset = SQUASHFS_INODE_OFFSET(ino);

	type = le16_to_cpu(sqshb_ino->inode_type);
	switch (type) {
	case SQUASHFS_REG_TYPE: {
		unsigned int frag_offset, frag;
		int frag_size;
		u64 frag_blk;
		struct squashfs_reg_inode *sqsh_ino = &squashfs_ino.reg;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
							sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		frag = le32_to_cpu(sqsh_ino->fragment);
		if (frag != SQUASHFS_INVALID_FRAG) {
			frag_offset = le32_to_cpu(sqsh_ino->offset);
			frag_size = squashfs_frag_lookup(sb, frag, &frag_blk);
			if (frag_size < 0) {
				err = frag_size;
				goto failed_read;
			}
		} else {
			frag_blk = SQUASHFS_INVALID_BLK;
			frag_size = 0;
			frag_offset = 0;
		}

		set_nlink(inode, 1);
		inode->i_size = le32_to_cpu(sqsh_ino->file_size);
		inode->i_fop = &generic_ro_fops;
		inode->i_mode |= S_IFREG;
		inode->i_blocks = ((inode->i_size - 1) >> 9) + 1;
		squashfs_i(inode)->fragment_block = frag_blk;
		squashfs_i(inode)->fragment_size = frag_size;
		squashfs_i(inode)->fragment_offset = frag_offset;
		squashfs_i(inode)->start = le32_to_cpu(sqsh_ino->start_block);
		squashfs_i(inode)->block_list_start = block;
		squashfs_i(inode)->offset = offset;
		inode->i_data.a_ops = &squashfs_aops;

		TRACE("File inode %x:%x, start_block %llx, block_list_start "
			"%llx, offset %x\n", SQUASHFS_INODE_BLK(ino),
			offset, squashfs_i(inode)->start, block, offset);
		break;
	}
	case SQUASHFS_LREG_TYPE: {
		unsigned int frag_offset, frag;
		int frag_size;
		u64 frag_blk;
		struct squashfs_lreg_inode *sqsh_ino = &squashfs_ino.lreg;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
							sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		frag = le32_to_cpu(sqsh_ino->fragment);
		if (frag != SQUASHFS_INVALID_FRAG) {
			frag_offset = le32_to_cpu(sqsh_ino->offset);
			frag_size = squashfs_frag_lookup(sb, frag, &frag_blk);
			if (frag_size < 0) {
				err = frag_size;
				goto failed_read;
			}
		} else {
			frag_blk = SQUASHFS_INVALID_BLK;
			frag_size = 0;
			frag_offset = 0;
		}

		xattr_id = le32_to_cpu(sqsh_ino->xattr);
		set_nlink(inode, le32_to_cpu(sqsh_ino->nlink));
		inode->i_size = le64_to_cpu(sqsh_ino->file_size);
		inode->i_op = &squashfs_inode_ops;
		inode->i_fop = &generic_ro_fops;
		inode->i_mode |= S_IFREG;
		inode->i_blocks = (inode->i_size -
				le64_to_cpu(sqsh_ino->sparse) + 511) >> 9;

		squashfs_i(inode)->fragment_block = frag_blk;
		squashfs_i(inode)->fragment_size = frag_size;
		squashfs_i(inode)->fragment_offset = frag_offset;
		squashfs_i(inode)->start = le64_to_cpu(sqsh_ino->start_block);
		squashfs_i(inode)->block_list_start = block;
		squashfs_i(inode)->offset = offset;
		inode->i_data.a_ops = &squashfs_aops;

		TRACE("File inode %x:%x, start_block %llx, block_list_start "
			"%llx, offset %x\n", SQUASHFS_INODE_BLK(ino),
			offset, squashfs_i(inode)->start, block, offset);
		break;
	}
	case SQUASHFS_DIR_TYPE: {
		struct squashfs_dir_inode *sqsh_ino = &squashfs_ino.dir;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
				sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		set_nlink(inode, le32_to_cpu(sqsh_ino->nlink));
		inode->i_size = le16_to_cpu(sqsh_ino->file_size);
		inode->i_op = &squashfs_dir_inode_ops;
		inode->i_fop = &squashfs_dir_ops;
		inode->i_mode |= S_IFDIR;
		squashfs_i(inode)->start = le32_to_cpu(sqsh_ino->start_block);
		squashfs_i(inode)->offset = le16_to_cpu(sqsh_ino->offset);
		squashfs_i(inode)->dir_idx_cnt = 0;
		squashfs_i(inode)->parent = le32_to_cpu(sqsh_ino->parent_inode);

		TRACE("Directory inode %x:%x, start_block %llx, offset %x\n",
				SQUASHFS_INODE_BLK(ino), offset,
				squashfs_i(inode)->start,
				le16_to_cpu(sqsh_ino->offset));
		break;
	}
	case SQUASHFS_LDIR_TYPE: {
		struct squashfs_ldir_inode *sqsh_ino = &squashfs_ino.ldir;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
				sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		xattr_id = le32_to_cpu(sqsh_ino->xattr);
		set_nlink(inode, le32_to_cpu(sqsh_ino->nlink));
		inode->i_size = le32_to_cpu(sqsh_ino->file_size);
		inode->i_op = &squashfs_dir_inode_ops;
		inode->i_fop = &squashfs_dir_ops;
		inode->i_mode |= S_IFDIR;
		squashfs_i(inode)->start = le32_to_cpu(sqsh_ino->start_block);
		squashfs_i(inode)->offset = le16_to_cpu(sqsh_ino->offset);
		squashfs_i(inode)->dir_idx_start = block;
		squashfs_i(inode)->dir_idx_offset = offset;
		squashfs_i(inode)->dir_idx_cnt = le16_to_cpu(sqsh_ino->i_count);
		squashfs_i(inode)->parent = le32_to_cpu(sqsh_ino->parent_inode);

		TRACE("Long directory inode %x:%x, start_block %llx, offset "
				"%x\n", SQUASHFS_INODE_BLK(ino), offset,
				squashfs_i(inode)->start,
				le16_to_cpu(sqsh_ino->offset));
		break;
	}
	case SQUASHFS_SYMLINK_TYPE:
	case SQUASHFS_LSYMLINK_TYPE: {
		struct squashfs_symlink_inode *sqsh_ino = &squashfs_ino.symlink;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
				sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		set_nlink(inode, le32_to_cpu(sqsh_ino->nlink));
		inode->i_size = le32_to_cpu(sqsh_ino->symlink_size);
		inode->i_op = &squashfs_symlink_inode_ops;
		inode->i_data.a_ops = &squashfs_symlink_aops;
		inode->i_mode |= S_IFLNK;
		squashfs_i(inode)->start = block;
		squashfs_i(inode)->offset = offset;

		if (type == SQUASHFS_LSYMLINK_TYPE) {
			__le32 xattr;

			err = squashfs_read_metadata(sb, NULL, &block,
						&offset, inode->i_size);
			if (err < 0)
				goto failed_read;
			err = squashfs_read_metadata(sb, &xattr, &block,
						&offset, sizeof(xattr));
			if (err < 0)
				goto failed_read;
			xattr_id = le32_to_cpu(xattr);
		}

		TRACE("Symbolic link inode %x:%x, start_block %llx, offset "
				"%x\n", SQUASHFS_INODE_BLK(ino), offset,
				block, offset);
		break;
	}
	case SQUASHFS_BLKDEV_TYPE:
	case SQUASHFS_CHRDEV_TYPE: {
		struct squashfs_dev_inode *sqsh_ino = &squashfs_ino.dev;
		unsigned int rdev;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
				sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		if (type == SQUASHFS_CHRDEV_TYPE)
			inode->i_mode |= S_IFCHR;
		else
			inode->i_mode |= S_IFBLK;
		set_nlink(inode, le32_to_cpu(sqsh_ino->nlink));
		rdev = le32_to_cpu(sqsh_ino->rdev);
		init_special_inode(inode, inode->i_mode, new_decode_dev(rdev));

		TRACE("Device inode %x:%x, rdev %x\n",
				SQUASHFS_INODE_BLK(ino), offset, rdev);
		break;
	}
	case SQUASHFS_LBLKDEV_TYPE:
	case SQUASHFS_LCHRDEV_TYPE: {
		struct squashfs_ldev_inode *sqsh_ino = &squashfs_ino.ldev;
		unsigned int rdev;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
				sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		if (type == SQUASHFS_LCHRDEV_TYPE)
			inode->i_mode |= S_IFCHR;
		else
			inode->i_mode |= S_IFBLK;
		xattr_id = le32_to_cpu(sqsh_ino->xattr);
		inode->i_op = &squashfs_inode_ops;
		set_nlink(inode, le32_to_cpu(sqsh_ino->nlink));
		rdev = le32_to_cpu(sqsh_ino->rdev);
		init_special_inode(inode, inode->i_mode, new_decode_dev(rdev));

		TRACE("Device inode %x:%x, rdev %x\n",
				SQUASHFS_INODE_BLK(ino), offset, rdev);
		break;
	}
	case SQUASHFS_FIFO_TYPE:
	case SQUASHFS_SOCKET_TYPE: {
		struct squashfs_ipc_inode *sqsh_ino = &squashfs_ino.ipc;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
				sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		if (type == SQUASHFS_FIFO_TYPE)
			inode->i_mode |= S_IFIFO;
		else
			inode->i_mode |= S_IFSOCK;
		set_nlink(inode, le32_to_cpu(sqsh_ino->nlink));
		init_special_inode(inode, inode->i_mode, 0);
		break;
	}
	case SQUASHFS_LFIFO_TYPE:
	case SQUASHFS_LSOCKET_TYPE: {
		struct squashfs_lipc_inode *sqsh_ino = &squashfs_ino.lipc;

		err = squashfs_read_metadata(sb, sqsh_ino, &block, &offset,
				sizeof(*sqsh_ino));
		if (err < 0)
			goto failed_read;

		if (type == SQUASHFS_LFIFO_TYPE)
			inode->i_mode |= S_IFIFO;
		else
			inode->i_mode |= S_IFSOCK;
		xattr_id = le32_to_cpu(sqsh_ino->xattr);
		inode->i_op = &squashfs_inode_ops;
		set_nlink(inode, le32_to_cpu(sqsh_ino->nlink));
		init_special_inode(inode, inode->i_mode, 0);
		break;
	}
	default:
		ERROR("Unknown inode type %d in squashfs_iget!\n", type);
		return -EINVAL;
	}

	if (xattr_id != SQUASHFS_INVALID_XATTR && msblk->xattr_id_table) {
		err = squashfs_xattr_lookup(sb, xattr_id,
					&squashfs_i(inode)->xattr_count,
					&squashfs_i(inode)->xattr_size,
					&squashfs_i(inode)->xattr);
		if (err < 0)
			goto failed_read;
		inode->i_blocks += ((squashfs_i(inode)->xattr_size - 1) >> 9)
				+ 1;
	} else
		squashfs_i(inode)->xattr_count = 0;

	return 0;

failed_read:
	ERROR("Unable to read inode 0x%llx\n", ino);
	return err;
}


const struct inode_operations squashfs_inode_ops = {
	.getxattr = generic_getxattr,
	.listxattr = squashfs_listxattr
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/inode.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * namei.c
 */

/*
 * This file implements code to do filename lookup in directories.
 *
 * Like inodes, directories are packed into compressed metadata blocks, stored
 * in a directory table.  Directories are accessed using the start address of
 * the metablock containing the directory and the offset into the
 * decompressed block (<block, offset>).
 *
 * Directories are organised in a slightly complex way, and are not simply
 * a list of file names.  The organisation takes advantage of the
 * fact that (in most cases) the inodes of the files will be in the same
 * compressed metadata block, and therefore, can share the start block.
 * Directories are therefore organised in a two level list, a directory
 * header containing the shared start block value, and a sequence of directory
 * entries, each of which share the shared start block.  A new directory header
 * is written once/if the inode start block changes.  The directory
 * header/directory entry list is repeated as many times as necessary.
 *
 * Directories are sorted, and can contain a directory index to speed up
 * file lookup.  Directory indexes store one entry per metablock, each entry
 * storing the index/filename mapping to the first directory header
 * in each metadata block.  Directories are sorted in alphabetical order,
 * and at lookup the index is scanned linearly looking for the first filename
 * alphabetically larger than the filename being looked up.  At this point the
 * location of the metadata block the filename is in has been found.
 * The general idea of the index is ensure only one metadata block needs to be
 * decompressed to do a lookup irrespective of the length of the directory.
 * This scheme has the advantage that it doesn't require extra memory overhead
 * and doesn't require much extra storage on disk.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/slab.h>
// #include <linux/string.h>
// #include <linux/dcache.h>
// #include <linux/xattr.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs_fs_i.h"
// #include "squashfs.h"
// #include "xattr.h"

/*
 * Lookup name in the directory index, returning the location of the metadata
 * block containing it, and the directory index this represents.
 *
 * If we get an error reading the index then return the part of the index
 * (if any) we have managed to read - the index isn't essential, just
 * quicker.
 */
static int get_dir_index_using_name(struct super_block *sb,
			u64 *next_block, int *next_offset, u64 index_start,
			int index_offset, int i_count, const char *name,
			int len)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int i, length = 0, err;
	unsigned int size;
	struct squashfs_dir_index *index;
	char *str;

	TRACE("Entered get_dir_index_using_name, i_count %d\n", i_count);

	index = kmalloc(sizeof(*index) + SQUASHFS_NAME_LEN * 2 + 2, GFP_KERNEL);
	if (index == NULL) {
		ERROR("Failed to allocate squashfs_dir_index\n");
		goto out;
	}

	str = &index->name[SQUASHFS_NAME_LEN + 1];
	strncpy(str, name, len);
	str[len] = '\0';

	for (i = 0; i < i_count; i++) {
		err = squashfs_read_metadata(sb, index, &index_start,
					&index_offset, sizeof(*index));
		if (err < 0)
			break;


		size = le32_to_cpu(index->size) + 1;
		if (size > SQUASHFS_NAME_LEN)
			break;

		err = squashfs_read_metadata(sb, index->name, &index_start,
					&index_offset, size);
		if (err < 0)
			break;

		index->name[size] = '\0';

		if (strcmp(index->name, str) > 0)
			break;

		length = le32_to_cpu(index->index);
		*next_block = le32_to_cpu(index->start_block) +
					msblk->directory_table;
	}

	*next_offset = (length + *next_offset) % SQUASHFS_METADATA_SIZE;
	kfree(index);

out:
	/*
	 * Return index (f_pos) of the looked up metadata block.  Translate
	 * from internal f_pos to external f_pos which is offset by 3 because
	 * we invent "." and ".." entries which are not actually stored in the
	 * directory.
	 */
	return length + 3;
}


static struct dentry *squashfs_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	const unsigned char *name = dentry->d_name.name;
	int len = dentry->d_name.len;
	struct inode *inode = NULL;
	struct squashfs_sb_info *msblk = dir->i_sb->s_fs_info;
	struct squashfs_dir_header dirh;
	struct squashfs_dir_entry *dire;
	u64 block = squashfs_i(dir)->start + msblk->directory_table;
	int offset = squashfs_i(dir)->offset;
	int err, length;
	unsigned int dir_count, size;

	TRACE("Entered squashfs_lookup [%llx:%x]\n", block, offset);

	dire = kmalloc(sizeof(*dire) + SQUASHFS_NAME_LEN + 1, GFP_KERNEL);
	if (dire == NULL) {
		ERROR("Failed to allocate squashfs_dir_entry\n");
		return ERR_PTR(-ENOMEM);
	}

	if (len > SQUASHFS_NAME_LEN) {
		err = -ENAMETOOLONG;
		goto failed;
	}

	length = get_dir_index_using_name(dir->i_sb, &block, &offset,
				squashfs_i(dir)->dir_idx_start,
				squashfs_i(dir)->dir_idx_offset,
				squashfs_i(dir)->dir_idx_cnt, name, len);

	while (length < i_size_read(dir)) {
		/*
		 * Read directory header.
		 */
		err = squashfs_read_metadata(dir->i_sb, &dirh, &block,
				&offset, sizeof(dirh));
		if (err < 0)
			goto read_failure;

		length += sizeof(dirh);

		dir_count = le32_to_cpu(dirh.count) + 1;

		if (dir_count > SQUASHFS_DIR_COUNT)
			goto data_error;

		while (dir_count--) {
			/*
			 * Read directory entry.
			 */
			err = squashfs_read_metadata(dir->i_sb, dire, &block,
					&offset, sizeof(*dire));
			if (err < 0)
				goto read_failure;

			size = le16_to_cpu(dire->size) + 1;

			/* size should never be larger than SQUASHFS_NAME_LEN */
			if (size > SQUASHFS_NAME_LEN)
				goto data_error;

			err = squashfs_read_metadata(dir->i_sb, dire->name,
					&block, &offset, size);
			if (err < 0)
				goto read_failure;

			length += sizeof(*dire) + size;

			if (name[0] < dire->name[0])
				goto exit_lookup;

			if (len == size && !strncmp(name, dire->name, len)) {
				unsigned int blk, off, ino_num;
				long long ino;
				blk = le32_to_cpu(dirh.start_block);
				off = le16_to_cpu(dire->offset);
				ino_num = le32_to_cpu(dirh.inode_number) +
					(short) le16_to_cpu(dire->inode_number);
				ino = SQUASHFS_MKINODE(blk, off);

				TRACE("calling squashfs_iget for directory "
					"entry %s, inode  %x:%x, %d\n", name,
					blk, off, ino_num);

				inode = squashfs_iget(dir->i_sb, ino, ino_num);
				goto exit_lookup;
			}
		}
	}

exit_lookup:
	kfree(dire);
	return d_splice_alias(inode, dentry);

data_error:
	err = -EIO;

read_failure:
	ERROR("Unable to read directory block [%llx:%x]\n",
		squashfs_i(dir)->start + msblk->directory_table,
		squashfs_i(dir)->offset);
failed:
	kfree(dire);
	return ERR_PTR(err);
}


const struct inode_operations squashfs_dir_inode_ops = {
	.lookup = squashfs_lookup,
	.getxattr = generic_getxattr,
	.listxattr = squashfs_listxattr
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/namei.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * super.c
 */

/*
 * This file implements code to read the superblock, read and initialise
 * in-memory structures at mount time, and all the VFS glue code to register
 * the filesystem.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/slab.h>
// #include <linux/mutex.h>
// #include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/magic.h>
// #include <linux/xattr.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs_fs_i.h"
// #include "squashfs.h"
// #include "decompressor.h"
// #include "xattr.h"

static struct file_system_type squashfs_fs_type;
static const struct super_operations squashfs_super_ops;

static const struct squashfs_decompressor *supported_squashfs_filesystem(short
	major, short minor, short id)
{
	const struct squashfs_decompressor *decompressor;

	if (major < SQUASHFS_MAJOR) {
		ERROR("Major/Minor mismatch, older Squashfs %d.%d "
			"filesystems are unsupported\n", major, minor);
		return NULL;
	} else if (major > SQUASHFS_MAJOR || minor > SQUASHFS_MINOR) {
		ERROR("Major/Minor mismatch, trying to mount newer "
			"%d.%d filesystem\n", major, minor);
		ERROR("Please update your kernel\n");
		return NULL;
	}

	decompressor = squashfs_lookup_decompressor(id);
	if (!decompressor->supported) {
		ERROR("Filesystem uses \"%s\" compression. This is not "
			"supported\n", decompressor->name);
		return NULL;
	}

	return decompressor;
}


static int squashfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct squashfs_sb_info *msblk;
	struct squashfs_super_block *sblk = NULL;
	char b[BDEVNAME_SIZE];
	struct inode *root;
	long long root_inode;
	unsigned short flags;
	unsigned int fragments;
	u64 lookup_table_start, xattr_id_table_start, next_table;
	int err;

	TRACE("Entered squashfs_fill_superblock\n");

	sb->s_fs_info = kzalloc(sizeof(*msblk), GFP_KERNEL);
	if (sb->s_fs_info == NULL) {
		ERROR("Failed to allocate squashfs_sb_info\n");
		return -ENOMEM;
	}
	msblk = sb->s_fs_info;

	msblk->devblksize = sb_min_blocksize(sb, SQUASHFS_DEVBLK_SIZE);
	msblk->devblksize_log2 = ffz(~msblk->devblksize);

	mutex_init(&msblk->meta_index_mutex);

	/*
	 * msblk->bytes_used is checked in squashfs_read_table to ensure reads
	 * are not beyond filesystem end.  But as we're using
	 * squashfs_read_table here to read the superblock (including the value
	 * of bytes_used) we need to set it to an initial sensible dummy value
	 */
	msblk->bytes_used = sizeof(*sblk);
	sblk = squashfs_read_table(sb, SQUASHFS_START, sizeof(*sblk));

	if (IS_ERR(sblk)) {
		ERROR("unable to read squashfs_super_block\n");
		err = PTR_ERR(sblk);
		sblk = NULL;
		goto failed_mount;
	}

	err = -EINVAL;

	/* Check it is a SQUASHFS superblock */
	sb->s_magic = le32_to_cpu(sblk->s_magic);
	if (sb->s_magic != SQUASHFS_MAGIC) {
		if (!silent)
			ERROR("Can't find a SQUASHFS superblock on %s\n",
						bdevname(sb->s_bdev, b));
		goto failed_mount;
	}

	/* Check the MAJOR & MINOR versions and lookup compression type */
	msblk->decompressor = supported_squashfs_filesystem(
			le16_to_cpu(sblk->s_major),
			le16_to_cpu(sblk->s_minor),
			le16_to_cpu(sblk->compression));
	if (msblk->decompressor == NULL)
		goto failed_mount;

	/* Check the filesystem does not extend beyond the end of the
	   block device */
	msblk->bytes_used = le64_to_cpu(sblk->bytes_used);
	if (msblk->bytes_used < 0 || msblk->bytes_used >
			i_size_read(sb->s_bdev->bd_inode))
		goto failed_mount;

	/* Check block size for sanity */
	msblk->block_size = le32_to_cpu(sblk->block_size);
	if (msblk->block_size > SQUASHFS_FILE_MAX_SIZE)
		goto failed_mount;

	/*
	 * Check the system page size is not larger than the filesystem
	 * block size (by default 128K).  This is currently not supported.
	 */
	if (PAGE_CACHE_SIZE > msblk->block_size) {
		ERROR("Page size > filesystem block size (%d).  This is "
			"currently not supported!\n", msblk->block_size);
		goto failed_mount;
	}

	/* Check block log for sanity */
	msblk->block_log = le16_to_cpu(sblk->block_log);
	if (msblk->block_log > SQUASHFS_FILE_MAX_LOG)
		goto failed_mount;

	/* Check that block_size and block_log match */
	if (msblk->block_size != (1 << msblk->block_log))
		goto failed_mount;

	/* Check the root inode for sanity */
	root_inode = le64_to_cpu(sblk->root_inode);
	if (SQUASHFS_INODE_OFFSET(root_inode) > SQUASHFS_METADATA_SIZE)
		goto failed_mount;

	msblk->inode_table = le64_to_cpu(sblk->inode_table_start);
	msblk->directory_table = le64_to_cpu(sblk->directory_table_start);
	msblk->inodes = le32_to_cpu(sblk->inodes);
	flags = le16_to_cpu(sblk->flags);

	TRACE("Found valid superblock on %s\n", bdevname(sb->s_bdev, b));
	TRACE("Inodes are %scompressed\n", SQUASHFS_UNCOMPRESSED_INODES(flags)
				? "un" : "");
	TRACE("Data is %scompressed\n", SQUASHFS_UNCOMPRESSED_DATA(flags)
				? "un" : "");
	TRACE("Filesystem size %lld bytes\n", msblk->bytes_used);
	TRACE("Block size %d\n", msblk->block_size);
	TRACE("Number of inodes %d\n", msblk->inodes);
	TRACE("Number of fragments %d\n", le32_to_cpu(sblk->fragments));
	TRACE("Number of ids %d\n", le16_to_cpu(sblk->no_ids));
	TRACE("sblk->inode_table_start %llx\n", msblk->inode_table);
	TRACE("sblk->directory_table_start %llx\n", msblk->directory_table);
	TRACE("sblk->fragment_table_start %llx\n",
		(u64) le64_to_cpu(sblk->fragment_table_start));
	TRACE("sblk->id_table_start %llx\n",
		(u64) le64_to_cpu(sblk->id_table_start));

	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_flags |= MS_RDONLY;
	sb->s_op = &squashfs_super_ops;

	err = -ENOMEM;

	msblk->block_cache = squashfs_cache_init("metadata",
			SQUASHFS_CACHED_BLKS, SQUASHFS_METADATA_SIZE);
	if (msblk->block_cache == NULL)
		goto failed_mount;

	/* Allocate read_page block */
	msblk->read_page = squashfs_cache_init("data",
		squashfs_max_decompressors(), msblk->block_size);
	if (msblk->read_page == NULL) {
		ERROR("Failed to allocate read_page block\n");
		goto failed_mount;
	}

	msblk->stream = squashfs_decompressor_setup(sb, flags);
	if (IS_ERR(msblk->stream)) {
		err = PTR_ERR(msblk->stream);
		msblk->stream = NULL;
		goto failed_mount;
	}

	/* Handle xattrs */
	sb->s_xattr = squashfs_xattr_handlers;
	xattr_id_table_start = le64_to_cpu(sblk->xattr_id_table_start);
	if (xattr_id_table_start == SQUASHFS_INVALID_BLK) {
		next_table = msblk->bytes_used;
		goto allocate_id_index_table;
	}

	/* Allocate and read xattr id lookup table */
	msblk->xattr_id_table = squashfs_read_xattr_id_table(sb,
		xattr_id_table_start, &msblk->xattr_table, &msblk->xattr_ids);
	if (IS_ERR(msblk->xattr_id_table)) {
		ERROR("unable to read xattr id index table\n");
		err = PTR_ERR(msblk->xattr_id_table);
		msblk->xattr_id_table = NULL;
		if (err != -ENOTSUPP)
			goto failed_mount;
	}
	next_table = msblk->xattr_table;

allocate_id_index_table:
	/* Allocate and read id index table */
	msblk->id_table = squashfs_read_id_index_table(sb,
		le64_to_cpu(sblk->id_table_start), next_table,
		le16_to_cpu(sblk->no_ids));
	if (IS_ERR(msblk->id_table)) {
		ERROR("unable to read id index table\n");
		err = PTR_ERR(msblk->id_table);
		msblk->id_table = NULL;
		goto failed_mount;
	}
	next_table = le64_to_cpu(msblk->id_table[0]);

	/* Handle inode lookup table */
	lookup_table_start = le64_to_cpu(sblk->lookup_table_start);
	if (lookup_table_start == SQUASHFS_INVALID_BLK)
		goto handle_fragments;

	/* Allocate and read inode lookup table */
	msblk->inode_lookup_table = squashfs_read_inode_lookup_table(sb,
		lookup_table_start, next_table, msblk->inodes);
	if (IS_ERR(msblk->inode_lookup_table)) {
		ERROR("unable to read inode lookup table\n");
		err = PTR_ERR(msblk->inode_lookup_table);
		msblk->inode_lookup_table = NULL;
		goto failed_mount;
	}
	next_table = le64_to_cpu(msblk->inode_lookup_table[0]);

	sb->s_export_op = &squashfs_export_ops;

handle_fragments:
	fragments = le32_to_cpu(sblk->fragments);
	if (fragments == 0)
		goto check_directory_table;

	msblk->fragment_cache = squashfs_cache_init("fragment",
		SQUASHFS_CACHED_FRAGMENTS, msblk->block_size);
	if (msblk->fragment_cache == NULL) {
		err = -ENOMEM;
		goto failed_mount;
	}

	/* Allocate and read fragment index table */
	msblk->fragment_index = squashfs_read_fragment_index_table(sb,
		le64_to_cpu(sblk->fragment_table_start), next_table, fragments);
	if (IS_ERR(msblk->fragment_index)) {
		ERROR("unable to read fragment index table\n");
		err = PTR_ERR(msblk->fragment_index);
		msblk->fragment_index = NULL;
		goto failed_mount;
	}
	next_table = le64_to_cpu(msblk->fragment_index[0]);

check_directory_table:
	/* Sanity check directory_table */
	if (msblk->directory_table > next_table) {
		err = -EINVAL;
		goto failed_mount;
	}

	/* Sanity check inode_table */
	if (msblk->inode_table >= msblk->directory_table) {
		err = -EINVAL;
		goto failed_mount;
	}

	/* allocate root */
	root = new_inode(sb);
	if (!root) {
		err = -ENOMEM;
		goto failed_mount;
	}

	err = squashfs_read_inode(root, root_inode);
	if (err) {
		make_bad_inode(root);
		iput(root);
		goto failed_mount;
	}
	insert_inode_hash(root);

	sb->s_root = d_make_root(root);
	if (sb->s_root == NULL) {
		ERROR("Root inode create failed\n");
		err = -ENOMEM;
		goto failed_mount;
	}

	TRACE("Leaving squashfs_fill_super\n");
	kfree(sblk);
	return 0;

failed_mount:
	squashfs_cache_delete(msblk->block_cache);
	squashfs_cache_delete(msblk->fragment_cache);
	squashfs_cache_delete(msblk->read_page);
	squashfs_decompressor_destroy(msblk);
	kfree(msblk->inode_lookup_table);
	kfree(msblk->fragment_index);
	kfree(msblk->id_table);
	kfree(msblk->xattr_id_table);
	kfree(sb->s_fs_info);
	sb->s_fs_info = NULL;
	kfree(sblk);
	return err;
}


static int squashfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct squashfs_sb_info *msblk = dentry->d_sb->s_fs_info;
	u64 id = huge_encode_dev(dentry->d_sb->s_bdev->bd_dev);

	TRACE("Entered squashfs_statfs\n");

	buf->f_type = SQUASHFS_MAGIC;
	buf->f_bsize = msblk->block_size;
	buf->f_blocks = ((msblk->bytes_used - 1) >> msblk->block_log) + 1;
	buf->f_bfree = buf->f_bavail = 0;
	buf->f_files = msblk->inodes;
	buf->f_ffree = 0;
	buf->f_namelen = SQUASHFS_NAME_LEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}


static int squashfs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	*flags |= MS_RDONLY;
	return 0;
}


static void squashfs_put_super(struct super_block *sb)
{
	if (sb->s_fs_info) {
		struct squashfs_sb_info *sbi = sb->s_fs_info;
		squashfs_cache_delete(sbi->block_cache);
		squashfs_cache_delete(sbi->fragment_cache);
		squashfs_cache_delete(sbi->read_page);
		squashfs_decompressor_destroy(sbi);
		kfree(sbi->id_table);
		kfree(sbi->fragment_index);
		kfree(sbi->meta_index);
		kfree(sbi->inode_lookup_table);
		kfree(sbi->xattr_id_table);
		kfree(sb->s_fs_info);
		sb->s_fs_info = NULL;
	}
}


static struct dentry *squashfs_mount(struct file_system_type *fs_type,
				int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, squashfs_fill_super);
}


static struct kmem_cache *squashfs_inode_cachep;


static void init_once(void *foo)
{
	struct squashfs_inode_info *ei = foo;

	inode_init_once(&ei->vfs_inode);
}


static int __init init_inodecache(void)
{
	squashfs_inode_cachep = kmem_cache_create("squashfs_inode_cache",
		sizeof(struct squashfs_inode_info), 0,
		SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT, init_once);

	return squashfs_inode_cachep ? 0 : -ENOMEM;
}


static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(squashfs_inode_cachep);
}


static int __init init_squashfs_fs(void)
{
	int err = init_inodecache();

	if (err)
		return err;

	err = register_filesystem(&squashfs_fs_type);
	if (err) {
		destroy_inodecache();
		return err;
	}

	pr_info("version 4.0 (2009/01/31) Phillip Lougher\n");

	return 0;
}


static void __exit exit_squashfs_fs(void)
{
	unregister_filesystem(&squashfs_fs_type);
	destroy_inodecache();
}


static struct inode *squashfs_alloc_inode(struct super_block *sb)
{
	struct squashfs_inode_info *ei =
		kmem_cache_alloc(squashfs_inode_cachep, GFP_KERNEL);

	return ei ? &ei->vfs_inode : NULL;
}


static void squashfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(squashfs_inode_cachep, squashfs_i(inode));
}

static void squashfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, squashfs_i_callback);
}


static struct file_system_type squashfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "squashfs",
	.mount = squashfs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV
};
MODULE_ALIAS_FS("squashfs");

static const struct super_operations squashfs_super_ops = {
	.alloc_inode = squashfs_alloc_inode,
	.destroy_inode = squashfs_destroy_inode,
	.statfs = squashfs_statfs,
	.put_super = squashfs_put_super,
	.remount_fs = squashfs_remount
};

module_init(init_squashfs_fs);
module_exit(exit_squashfs_fs);
MODULE_DESCRIPTION("squashfs 4.0, a compressed read-only filesystem");
MODULE_AUTHOR("Phillip Lougher <phillip@squashfs.org.uk>");
MODULE_LICENSE("GPL");
/************************************************************/
/* ../linux-3.17/fs/squashfs/super.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * symlink.c
 */

/*
 * This file implements code to handle symbolic links.
 *
 * The data contents of symbolic links are stored inside the symbolic
 * link inode within the inode table.  This allows the normally small symbolic
 * link to be compressed as part of the inode table, achieving much greater
 * compression than if the symbolic link was compressed individually.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/kernel.h>
// #include <linux/string.h>
// #include <linux/pagemap.h>
// #include <linux/xattr.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs_fs_i.h"
// #include "squashfs.h"
// #include "xattr.h"

static int squashfs_symlink_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int index = page->index << PAGE_CACHE_SHIFT;
	u64 block = squashfs_i(inode)->start;
	int offset = squashfs_i(inode)->offset;
	int length = min_t(int, i_size_read(inode) - index, PAGE_CACHE_SIZE);
	int bytes, copied;
	void *pageaddr;
	struct squashfs_cache_entry *entry;

	TRACE("Entered squashfs_symlink_readpage, page index %ld, start block "
			"%llx, offset %x\n", page->index, block, offset);

	/*
	 * Skip index bytes into symlink metadata.
	 */
	if (index) {
		bytes = squashfs_read_metadata(sb, NULL, &block, &offset,
								index);
		if (bytes < 0) {
			ERROR("Unable to read symlink [%llx:%x]\n",
				squashfs_i(inode)->start,
				squashfs_i(inode)->offset);
			goto error_out;
		}
	}

	/*
	 * Read length bytes from symlink metadata.  Squashfs_read_metadata
	 * is not used here because it can sleep and we want to use
	 * kmap_atomic to map the page.  Instead call the underlying
	 * squashfs_cache_get routine.  As length bytes may overlap metadata
	 * blocks, we may need to call squashfs_cache_get multiple times.
	 */
	for (bytes = 0; bytes < length; offset = 0, bytes += copied) {
		entry = squashfs_cache_get(sb, msblk->block_cache, block, 0);
		if (entry->error) {
			ERROR("Unable to read symlink [%llx:%x]\n",
				squashfs_i(inode)->start,
				squashfs_i(inode)->offset);
			squashfs_cache_put(entry);
			goto error_out;
		}

		pageaddr = kmap_atomic(page);
		copied = squashfs_copy_data(pageaddr + bytes, entry, offset,
								length - bytes);
		if (copied == length - bytes)
			memset(pageaddr + length, 0, PAGE_CACHE_SIZE - length);
		else
			block = entry->next_index;
		kunmap_atomic(pageaddr);
		squashfs_cache_put(entry);
	}

	flush_dcache_page(page);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;

error_out:
	SetPageError(page);
	unlock_page(page);
	return 0;
}


const struct address_space_operations squashfs_symlink_aops = {
	.readpage = squashfs_symlink_readpage
};

const struct inode_operations squashfs_symlink_inode_ops = {
	.readlink = generic_readlink,
	.follow_link = page_follow_link_light,
	.put_link = page_put_link,
	.getxattr = generic_getxattr,
	.listxattr = squashfs_listxattr
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/symlink.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * decompressor.c
 */

#include <linux/types.h>
// #include <linux/mutex.h>
// #include <linux/slab.h>
// #include <linux/buffer_head.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "decompressor.h"
// #include "squashfs.h"
// #include "page_actor.h"

/*
 * This file (and decompressor.h) implements a decompressor framework for
 * Squashfs, allowing multiple decompressors to be easily supported
 */

static const struct squashfs_decompressor squashfs_lzma_unsupported_comp_ops = {
	NULL, NULL, NULL, NULL, LZMA_COMPRESSION, "lzma", 0
};

#ifndef CONFIG_SQUASHFS_LZO
static const struct squashfs_decompressor squashfs_lzo_comp_ops = {
	NULL, NULL, NULL, NULL, LZO_COMPRESSION, "lzo", 0
};
#endif

#ifndef CONFIG_SQUASHFS_XZ
static const struct squashfs_decompressor squashfs_xz_comp_ops = {
	NULL, NULL, NULL, NULL, XZ_COMPRESSION, "xz", 0
};
#endif

#ifndef CONFIG_SQUASHFS_ZLIB
static const struct squashfs_decompressor squashfs_zlib_comp_ops = {
	NULL, NULL, NULL, NULL, ZLIB_COMPRESSION, "zlib", 0
};
#endif

static const struct squashfs_decompressor squashfs_unknown_comp_ops = {
	NULL, NULL, NULL, NULL, 0, "unknown", 0
};

static const struct squashfs_decompressor *decompressor[] = {
	&squashfs_zlib_comp_ops,
	&squashfs_lzo_comp_ops,
	&squashfs_xz_comp_ops,
	&squashfs_lzma_unsupported_comp_ops,
	&squashfs_unknown_comp_ops
};


const struct squashfs_decompressor *squashfs_lookup_decompressor(int id)
{
	int i;

	for (i = 0; decompressor[i]->id; i++)
		if (id == decompressor[i]->id)
			break;

	return decompressor[i];
}


static void *get_comp_opts(struct super_block *sb, unsigned short flags)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	void *buffer = NULL, *comp_opts;
	struct squashfs_page_actor *actor = NULL;
	int length = 0;

	/*
	 * Read decompressor specific options from file system if present
	 */
	if (SQUASHFS_COMP_OPTS(flags)) {
		buffer = kmalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
		if (buffer == NULL) {
			comp_opts = ERR_PTR(-ENOMEM);
			goto out;
		}

		actor = squashfs_page_actor_init(&buffer, 1, 0);
		if (actor == NULL) {
			comp_opts = ERR_PTR(-ENOMEM);
			goto out;
		}

		length = squashfs_read_data(sb,
			sizeof(struct squashfs_super_block), 0, NULL, actor);

		if (length < 0) {
			comp_opts = ERR_PTR(length);
			goto out;
		}
	}

	comp_opts = squashfs_comp_opts(msblk, buffer, length);

out:
	kfree(actor);
	kfree(buffer);
	return comp_opts;
}


void *squashfs_decompressor_setup(struct super_block *sb, unsigned short flags)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	void *stream, *comp_opts = get_comp_opts(sb, flags);

	if (IS_ERR(comp_opts))
		return comp_opts;

	stream = squashfs_decompressor_create(msblk, comp_opts);
	if (IS_ERR(stream))
		kfree(comp_opts);

	return stream;
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/decompressor.c */
/************************************************************/
/*
 * Copyright (c) 2013
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See
 * the COPYING file in the top-level directory.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/kernel.h>
// #include <linux/slab.h>
// #include <linux/string.h>
// #include <linux/pagemap.h>
// #include <linux/mutex.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs_fs_i.h"
// #include "squashfs.h"
// #include "page_actor.h"

static int squashfs_read_cache(struct page *target_page, u64 block, int bsize,
	int pages, struct page **page);

/* Read separately compressed datablock directly into page cache */
int squashfs_readpage_block(struct page *target_page, u64 block, int bsize)

{
	struct inode *inode = target_page->mapping->host;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;

	int file_end = (i_size_read(inode) - 1) >> PAGE_CACHE_SHIFT;
	int mask = (1 << (msblk->block_log - PAGE_CACHE_SHIFT)) - 1;
	int start_index = target_page->index & ~mask;
	int end_index = start_index | mask;
	int i, n, pages, missing_pages, bytes, res = -ENOMEM;
	struct page **page;
	struct squashfs_page_actor *actor;
	void *pageaddr;

	if (end_index > file_end)
		end_index = file_end;

	pages = end_index - start_index + 1;

	page = kmalloc_array(pages, sizeof(void *), GFP_KERNEL);
	if (page == NULL)
		return res;

	/*
	 * Create a "page actor" which will kmap and kunmap the
	 * page cache pages appropriately within the decompressor
	 */
	actor = squashfs_page_actor_init_special(page, pages, 0);
	if (actor == NULL)
		goto out;

	/* Try to grab all the pages covered by the Squashfs block */
	for (missing_pages = 0, i = 0, n = start_index; i < pages; i++, n++) {
		page[i] = (n == target_page->index) ? target_page :
			grab_cache_page_nowait(target_page->mapping, n);

		if (page[i] == NULL) {
			missing_pages++;
			continue;
		}

		if (PageUptodate(page[i])) {
			unlock_page(page[i]);
			page_cache_release(page[i]);
			page[i] = NULL;
			missing_pages++;
		}
	}

	if (missing_pages) {
		/*
		 * Couldn't get one or more pages, this page has either
		 * been VM reclaimed, but others are still in the page cache
		 * and uptodate, or we're racing with another thread in
		 * squashfs_readpage also trying to grab them.  Fall back to
		 * using an intermediate buffer.
		 */
		res = squashfs_read_cache(target_page, block, bsize, pages,
								page);
		if (res < 0)
			goto mark_errored;

		goto out;
	}

	/* Decompress directly into the page cache buffers */
	res = squashfs_read_data(inode->i_sb, block, bsize, NULL, actor);
	if (res < 0)
		goto mark_errored;

	/* Last page may have trailing bytes not filled */
	bytes = res % PAGE_CACHE_SIZE;
	if (bytes) {
		pageaddr = kmap_atomic(page[pages - 1]);
		memset(pageaddr + bytes, 0, PAGE_CACHE_SIZE - bytes);
		kunmap_atomic(pageaddr);
	}

	/* Mark pages as uptodate, unlock and release */
	for (i = 0; i < pages; i++) {
		flush_dcache_page(page[i]);
		SetPageUptodate(page[i]);
		unlock_page(page[i]);
		if (page[i] != target_page)
			page_cache_release(page[i]);
	}

	kfree(actor);
	kfree(page);

	return 0;

mark_errored:
	/* Decompression failed, mark pages as errored.  Target_page is
	 * dealt with by the caller
	 */
	for (i = 0; i < pages; i++) {
		if (page[i] == NULL || page[i] == target_page)
			continue;
		flush_dcache_page(page[i]);
		SetPageError(page[i]);
		unlock_page(page[i]);
		page_cache_release(page[i]);
	}

out:
	kfree(actor);
	kfree(page);
	return res;
}


static int squashfs_read_cache(struct page *target_page, u64 block, int bsize,
	int pages, struct page **page)
{
	struct inode *i = target_page->mapping->host;
	struct squashfs_cache_entry *buffer = squashfs_get_datablock(i->i_sb,
						 block, bsize);
	int bytes = buffer->length, res = buffer->error, n, offset = 0;
	void *pageaddr;

	if (res) {
		ERROR("Unable to read page, block %llx, size %x\n", block,
			bsize);
		goto out;
	}

	for (n = 0; n < pages && bytes > 0; n++,
			bytes -= PAGE_CACHE_SIZE, offset += PAGE_CACHE_SIZE) {
		int avail = min_t(int, bytes, PAGE_CACHE_SIZE);

		if (page[n] == NULL)
			continue;

		pageaddr = kmap_atomic(page[n]);
		squashfs_copy_data(pageaddr, buffer, offset, avail);
		memset(pageaddr + avail, 0, PAGE_CACHE_SIZE - avail);
		kunmap_atomic(pageaddr);
		flush_dcache_page(page[n]);
		SetPageUptodate(page[n]);
		unlock_page(page[n]);
		if (page[n] != target_page)
			page_cache_release(page[n]);
	}

out:
	squashfs_cache_put(buffer);
	return res;
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/file_direct.c */
/************************************************************/
/*
 * Copyright (c) 2013
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See
 * the COPYING file in the top-level directory.
 */

// #include <linux/kernel.h>
// #include <linux/slab.h>
// #include <linux/pagemap.h>
// #include "page_actor.h"

/*
 * This file contains implementations of page_actor for decompressing into
 * an intermediate buffer, and for decompressing directly into the
 * page cache.
 *
 * Calling code should avoid sleeping between calls to squashfs_first_page()
 * and squashfs_finish_page().
 */

/* Implementation of page_actor for decompressing into intermediate buffer */
static void *cache_first_page(struct squashfs_page_actor *actor)
{
	actor->next_page = 1;
	return actor->buffer[0];
}

static void *cache_next_page(struct squashfs_page_actor *actor)
{
	if (actor->next_page == actor->pages)
		return NULL;

	return actor->buffer[actor->next_page++];
}

static void cache_finish_page(struct squashfs_page_actor *actor)
{
	/* empty */
}

struct squashfs_page_actor *squashfs_page_actor_init(void **buffer,
	int pages, int length)
{
	struct squashfs_page_actor *actor = kmalloc(sizeof(*actor), GFP_KERNEL);

	if (actor == NULL)
		return NULL;

	actor->length = length ? : pages * PAGE_CACHE_SIZE;
	actor->buffer = buffer;
	actor->pages = pages;
	actor->next_page = 0;
	actor->squashfs_first_page = cache_first_page;
	actor->squashfs_next_page = cache_next_page;
	actor->squashfs_finish_page = cache_finish_page;
	return actor;
}

/* Implementation of page_actor for decompressing directly into page cache. */
static void *direct_first_page(struct squashfs_page_actor *actor)
{
	actor->next_page = 1;
	return actor->pageaddr = kmap_atomic(actor->page[0]);
}

static void *direct_next_page(struct squashfs_page_actor *actor)
{
	if (actor->pageaddr)
		kunmap_atomic(actor->pageaddr);

	return actor->pageaddr = actor->next_page == actor->pages ? NULL :
		kmap_atomic(actor->page[actor->next_page++]);
}

static void direct_finish_page(struct squashfs_page_actor *actor)
{
	if (actor->pageaddr)
		kunmap_atomic(actor->pageaddr);
}

struct squashfs_page_actor *squashfs_page_actor_init_special(struct page **page,
	int pages, int length)
{
	struct squashfs_page_actor *actor = kmalloc(sizeof(*actor), GFP_KERNEL);

	if (actor == NULL)
		return NULL;

	actor->length = length ? : pages * PAGE_CACHE_SIZE;
	actor->page = page;
	actor->pages = pages;
	actor->next_page = 0;
	actor->pageaddr = NULL;
	actor->squashfs_first_page = direct_first_page;
	actor->squashfs_next_page = direct_next_page;
	actor->squashfs_finish_page = direct_finish_page;
	return actor;
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/page_actor.c */
/************************************************************/
/*
 * Copyright (c) 2013
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This work is licensed under the terms of the GNU GPL, version 2. See
 * the COPYING file in the top-level directory.
 */

// #include <linux/types.h>
// #include <linux/slab.h>
#include <linux/percpu.h>
// #include <linux/buffer_head.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "decompressor.h"
// #include "squashfs.h"

/*
 * This file implements multi-threaded decompression using percpu
 * variables, one thread per cpu core.
 */

struct squashfs_stream {
	void		*stream;
};

void *squashfs_decompressor_create(struct squashfs_sb_info *msblk,
						void *comp_opts)
{
	struct squashfs_stream *stream;
	struct squashfs_stream __percpu *percpu;
	int err, cpu;

	percpu = alloc_percpu(struct squashfs_stream);
	if (percpu == NULL)
		return ERR_PTR(-ENOMEM);

	for_each_possible_cpu(cpu) {
		stream = per_cpu_ptr(percpu, cpu);
		stream->stream = msblk->decompressor->init(msblk, comp_opts);
		if (IS_ERR(stream->stream)) {
			err = PTR_ERR(stream->stream);
			goto out;
		}
	}

	kfree(comp_opts);
	return (__force void *) percpu;

out:
	for_each_possible_cpu(cpu) {
		stream = per_cpu_ptr(percpu, cpu);
		if (!IS_ERR_OR_NULL(stream->stream))
			msblk->decompressor->free(stream->stream);
	}
	free_percpu(percpu);
	return ERR_PTR(err);
}

void squashfs_decompressor_destroy(struct squashfs_sb_info *msblk)
{
	struct squashfs_stream __percpu *percpu =
			(struct squashfs_stream __percpu *) msblk->stream;
	struct squashfs_stream *stream;
	int cpu;

	if (msblk->stream) {
		for_each_possible_cpu(cpu) {
			stream = per_cpu_ptr(percpu, cpu);
			msblk->decompressor->free(stream->stream);
		}
		free_percpu(percpu);
	}
}

int squashfs_decompress(struct squashfs_sb_info *msblk, struct buffer_head **bh,
	int b, int offset, int length, struct squashfs_page_actor *output)
{
	struct squashfs_stream __percpu *percpu =
			(struct squashfs_stream __percpu *) msblk->stream;
	struct squashfs_stream *stream = get_cpu_ptr(percpu);
	int res = msblk->decompressor->decompress(msblk, stream->stream, bh, b,
		offset, length, output);
	put_cpu_ptr(stream);

	if (res < 0)
		ERROR("%s decompression failed, data probably corrupt\n",
			msblk->decompressor->name);

	return res;
}

int squashfs_max_decompressors(void)
{
	return num_possible_cpus();
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/decompressor_multi_percpu.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2010
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * xattr.c
 */

// #include <linux/init.h>
// #include <linux/module.h>
// #include <linux/string.h>
// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/xattr.h>
// #include <linux/slab.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs_fs_i.h"
// #include "squashfs.h"

static const struct xattr_handler *squashfs_xattr_handler(int);

ssize_t squashfs_listxattr(struct dentry *d, char *buffer,
	size_t buffer_size)
{
	struct inode *inode = d->d_inode;
	struct super_block *sb = inode->i_sb;
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	u64 start = SQUASHFS_XATTR_BLK(squashfs_i(inode)->xattr)
						 + msblk->xattr_table;
	int offset = SQUASHFS_XATTR_OFFSET(squashfs_i(inode)->xattr);
	int count = squashfs_i(inode)->xattr_count;
	size_t rest = buffer_size;
	int err;

	/* check that the file system has xattrs */
	if (msblk->xattr_id_table == NULL)
		return -EOPNOTSUPP;

	/* loop reading each xattr name */
	while (count--) {
		struct squashfs_xattr_entry entry;
		struct squashfs_xattr_val val;
		const struct xattr_handler *handler;
		int name_size, prefix_size = 0;

		err = squashfs_read_metadata(sb, &entry, &start, &offset,
							sizeof(entry));
		if (err < 0)
			goto failed;

		name_size = le16_to_cpu(entry.size);
		handler = squashfs_xattr_handler(le16_to_cpu(entry.type));
		if (handler)
			prefix_size = handler->list(d, buffer, rest, NULL,
				name_size, handler->flags);
		if (prefix_size) {
			if (buffer) {
				if (prefix_size + name_size + 1 > rest) {
					err = -ERANGE;
					goto failed;
				}
				buffer += prefix_size;
			}
			err = squashfs_read_metadata(sb, buffer, &start,
				&offset, name_size);
			if (err < 0)
				goto failed;
			if (buffer) {
				buffer[name_size] = '\0';
				buffer += name_size + 1;
			}
			rest -= prefix_size + name_size + 1;
		} else  {
			/* no handler or insuffficient privileges, so skip */
			err = squashfs_read_metadata(sb, NULL, &start,
				&offset, name_size);
			if (err < 0)
				goto failed;
		}


		/* skip remaining xattr entry */
		err = squashfs_read_metadata(sb, &val, &start, &offset,
						sizeof(val));
		if (err < 0)
			goto failed;

		err = squashfs_read_metadata(sb, NULL, &start, &offset,
						le32_to_cpu(val.vsize));
		if (err < 0)
			goto failed;
	}
	err = buffer_size - rest;

failed:
	return err;
}


static int squashfs_xattr_get(struct inode *inode, int name_index,
	const char *name, void *buffer, size_t buffer_size)
{
	struct super_block *sb = inode->i_sb;
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	u64 start = SQUASHFS_XATTR_BLK(squashfs_i(inode)->xattr)
						 + msblk->xattr_table;
	int offset = SQUASHFS_XATTR_OFFSET(squashfs_i(inode)->xattr);
	int count = squashfs_i(inode)->xattr_count;
	int name_len = strlen(name);
	int err, vsize;
	char *target = kmalloc(name_len, GFP_KERNEL);

	if (target == NULL)
		return  -ENOMEM;

	/* loop reading each xattr name */
	for (; count; count--) {
		struct squashfs_xattr_entry entry;
		struct squashfs_xattr_val val;
		int type, prefix, name_size;

		err = squashfs_read_metadata(sb, &entry, &start, &offset,
							sizeof(entry));
		if (err < 0)
			goto failed;

		name_size = le16_to_cpu(entry.size);
		type = le16_to_cpu(entry.type);
		prefix = type & SQUASHFS_XATTR_PREFIX_MASK;

		if (prefix == name_index && name_size == name_len)
			err = squashfs_read_metadata(sb, target, &start,
						&offset, name_size);
		else
			err = squashfs_read_metadata(sb, NULL, &start,
						&offset, name_size);
		if (err < 0)
			goto failed;

		if (prefix == name_index && name_size == name_len &&
					strncmp(target, name, name_size) == 0) {
			/* found xattr */
			if (type & SQUASHFS_XATTR_VALUE_OOL) {
				__le64 xattr_val;
				u64 xattr;
				/* val is a reference to the real location */
				err = squashfs_read_metadata(sb, &val, &start,
						&offset, sizeof(val));
				if (err < 0)
					goto failed;
				err = squashfs_read_metadata(sb, &xattr_val,
					&start, &offset, sizeof(xattr_val));
				if (err < 0)
					goto failed;
				xattr = le64_to_cpu(xattr_val);
				start = SQUASHFS_XATTR_BLK(xattr) +
							msblk->xattr_table;
				offset = SQUASHFS_XATTR_OFFSET(xattr);
			}
			/* read xattr value */
			err = squashfs_read_metadata(sb, &val, &start, &offset,
							sizeof(val));
			if (err < 0)
				goto failed;

			vsize = le32_to_cpu(val.vsize);
			if (buffer) {
				if (vsize > buffer_size) {
					err = -ERANGE;
					goto failed;
				}
				err = squashfs_read_metadata(sb, buffer, &start,
					 &offset, vsize);
				if (err < 0)
					goto failed;
			}
			break;
		}

		/* no match, skip remaining xattr entry */
		err = squashfs_read_metadata(sb, &val, &start, &offset,
							sizeof(val));
		if (err < 0)
			goto failed;
		err = squashfs_read_metadata(sb, NULL, &start, &offset,
						le32_to_cpu(val.vsize));
		if (err < 0)
			goto failed;
	}
	err = count ? vsize : -ENODATA;

failed:
	kfree(target);
	return err;
}


/*
 * User namespace support
 */
static size_t squashfs_user_list(struct dentry *d, char *list, size_t list_size,
	const char *name, size_t name_len, int type)
{
	if (list && XATTR_USER_PREFIX_LEN <= list_size)
		memcpy(list, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN);
	return XATTR_USER_PREFIX_LEN;
}

static int squashfs_user_get(struct dentry *d, const char *name, void *buffer,
	size_t size, int type)
{
	if (name[0] == '\0')
		return  -EINVAL;

	return squashfs_xattr_get(d->d_inode, SQUASHFS_XATTR_USER, name,
		buffer, size);
}

static const struct xattr_handler squashfs_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= squashfs_user_list,
	.get	= squashfs_user_get
};

/*
 * Trusted namespace support
 */
static size_t squashfs_trusted_list(struct dentry *d, char *list,
	size_t list_size, const char *name, size_t name_len, int type)
{
	if (!capable(CAP_SYS_ADMIN))
		return 0;

	if (list && XATTR_TRUSTED_PREFIX_LEN <= list_size)
		memcpy(list, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN);
	return XATTR_TRUSTED_PREFIX_LEN;
}

static int squashfs_trusted_get(struct dentry *d, const char *name,
	void *buffer, size_t size, int type)
{
	if (name[0] == '\0')
		return  -EINVAL;

	return squashfs_xattr_get(d->d_inode, SQUASHFS_XATTR_TRUSTED, name,
		buffer, size);
}

static const struct xattr_handler squashfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= squashfs_trusted_list,
	.get	= squashfs_trusted_get
};

/*
 * Security namespace support
 */
static size_t squashfs_security_list(struct dentry *d, char *list,
	size_t list_size, const char *name, size_t name_len, int type)
{
	if (list && XATTR_SECURITY_PREFIX_LEN <= list_size)
		memcpy(list, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN);
	return XATTR_SECURITY_PREFIX_LEN;
}

static int squashfs_security_get(struct dentry *d, const char *name,
	void *buffer, size_t size, int type)
{
	if (name[0] == '\0')
		return  -EINVAL;

	return squashfs_xattr_get(d->d_inode, SQUASHFS_XATTR_SECURITY, name,
		buffer, size);
}

static const struct xattr_handler squashfs_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.list	= squashfs_security_list,
	.get	= squashfs_security_get
};

static const struct xattr_handler *squashfs_xattr_handler(int type)
{
	if (type & ~(SQUASHFS_XATTR_PREFIX_MASK | SQUASHFS_XATTR_VALUE_OOL))
		/* ignore unrecognised type */
		return NULL;

	switch (type & SQUASHFS_XATTR_PREFIX_MASK) {
	case SQUASHFS_XATTR_USER:
		return &squashfs_xattr_user_handler;
	case SQUASHFS_XATTR_TRUSTED:
		return &squashfs_xattr_trusted_handler;
	case SQUASHFS_XATTR_SECURITY:
		return &squashfs_xattr_security_handler;
	default:
		/* ignore unrecognised type */
		return NULL;
	}
}

const struct xattr_handler *squashfs_xattr_handlers[] = {
	&squashfs_xattr_user_handler,
	&squashfs_xattr_trusted_handler,
	&squashfs_xattr_security_handler,
	NULL
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/xattr.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2010
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * xattr_id.c
 */

/*
 * This file implements code to map the 32-bit xattr id stored in the inode
 * into the on disk location of the xattr data.
 */

// #include <linux/fs.h>
// #include <linux/vfs.h>
// #include <linux/slab.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs.h"
// #include "xattr.h"

/*
 * Map xattr id using the xattr id look up table
 */
int squashfs_xattr_lookup(struct super_block *sb, unsigned int index,
		int *count, unsigned int *size, unsigned long long *xattr)
{
	struct squashfs_sb_info *msblk = sb->s_fs_info;
	int block = SQUASHFS_XATTR_BLOCK(index);
	int offset = SQUASHFS_XATTR_BLOCK_OFFSET(index);
	u64 start_block = le64_to_cpu(msblk->xattr_id_table[block]);
	struct squashfs_xattr_id id;
	int err;

	err = squashfs_read_metadata(sb, &id, &start_block, &offset,
							sizeof(id));
	if (err < 0)
		return err;

	*xattr = le64_to_cpu(id.xattr);
	*size = le32_to_cpu(id.size);
	*count = le32_to_cpu(id.count);
	return 0;
}


/*
 * Read uncompressed xattr id lookup table indexes from disk into memory
 */
__le64 *squashfs_read_xattr_id_table(struct super_block *sb, u64 start,
		u64 *xattr_table_start, int *xattr_ids)
{
	unsigned int len;
	struct squashfs_xattr_id_table *id_table;

	id_table = squashfs_read_table(sb, start, sizeof(*id_table));
	if (IS_ERR(id_table))
		return (__le64 *) id_table;

	*xattr_table_start = le64_to_cpu(id_table->xattr_table_start);
	*xattr_ids = le32_to_cpu(id_table->xattr_ids);
	kfree(id_table);

	/* Sanity check values */

	/* there is always at least one xattr id */
	if (*xattr_ids == 0)
		return ERR_PTR(-EINVAL);

	/* xattr_table should be less than start */
	if (*xattr_table_start >= start)
		return ERR_PTR(-EINVAL);

	len = SQUASHFS_XATTR_BLOCK_BYTES(*xattr_ids);

	TRACE("In read_xattr_index_table, length %d\n", len);

	return squashfs_read_table(sb, start + sizeof(*id_table), len);
}
/************************************************************/
/* ../linux-3.17/fs/squashfs/xattr_id.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2010 LG Electronics
 * Chan Jeong <chan.jeong@lge.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * lzo_wrapper.c
 */

// #include <linux/mutex.h>
// #include <linux/buffer_head.h>
// #include <linux/slab.h>
// #include <linux/vmalloc.h>
#include <linux/lzo.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs.h"
// #include "decompressor.h"
// #include "page_actor.h"

struct squashfs_lzo {
	void	*input;
	void	*output;
};

static void *lzo_init(struct squashfs_sb_info *msblk, void *buff)
{
	int block_size = max_t(int, msblk->block_size, SQUASHFS_METADATA_SIZE);

	struct squashfs_lzo *stream = kzalloc(sizeof(*stream), GFP_KERNEL);
	if (stream == NULL)
		goto failed;
	stream->input = vmalloc(block_size);
	if (stream->input == NULL)
		goto failed;
	stream->output = vmalloc(block_size);
	if (stream->output == NULL)
		goto failed2;

	return stream;

failed2:
	vfree(stream->input);
failed:
	ERROR("Failed to allocate lzo workspace\n");
	kfree(stream);
	return ERR_PTR(-ENOMEM);
}


static void lzo_free(void *strm)
{
	struct squashfs_lzo *stream = strm;

	if (stream) {
		vfree(stream->input);
		vfree(stream->output);
	}
	kfree(stream);
}


static int lzo_uncompress(struct squashfs_sb_info *msblk, void *strm,
	struct buffer_head **bh, int b, int offset, int length,
	struct squashfs_page_actor *output)
{
	struct squashfs_lzo *stream = strm;
	void *buff = stream->input, *data;
	int avail, i, bytes = length, res;
	size_t out_len = output->length;

	for (i = 0; i < b; i++) {
		avail = min(bytes, msblk->devblksize - offset);
		memcpy(buff, bh[i]->b_data + offset, avail);
		buff += avail;
		bytes -= avail;
		offset = 0;
		put_bh(bh[i]);
	}

	res = lzo1x_decompress_safe(stream->input, (size_t)length,
					stream->output, &out_len);
	if (res != LZO_E_OK)
		goto failed;

	res = bytes = (int)out_len;
	data = squashfs_first_page(output);
	buff = stream->output;
	while (data) {
		if (bytes <= PAGE_CACHE_SIZE) {
			memcpy(data, buff, bytes);
			break;
		} else {
			memcpy(data, buff, PAGE_CACHE_SIZE);
			buff += PAGE_CACHE_SIZE;
			bytes -= PAGE_CACHE_SIZE;
			data = squashfs_next_page(output);
		}
	}
	squashfs_finish_page(output);

	return res;

failed:
	return -EIO;
}

const struct squashfs_decompressor squashfs_lzo_comp_ops = {
	.init = lzo_init,
	.free = lzo_free,
	.decompress = lzo_uncompress,
	.id = LZO_COMPRESSION,
	.name = "lzo",
	.supported = 1
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/lzo_wrapper.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * xz_wrapper.c
 */


// #include <linux/mutex.h>
// #include <linux/buffer_head.h>
// #include <linux/slab.h>
#include <linux/xz.h>
#include <linux/bitops.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs.h"
// #include "decompressor.h"
// #include "page_actor.h"

struct squashfs_xz {
	struct xz_dec *state;
	struct xz_buf buf;
};

struct disk_comp_opts {
	__le32 dictionary_size;
	__le32 flags;
};

struct comp_opts {
	int dict_size;
};

static void *squashfs_xz_comp_opts(struct squashfs_sb_info *msblk,
	void *buff, int len)
{
	struct disk_comp_opts *comp_opts = buff;
	struct comp_opts *opts;
	int err = 0, n;

	opts = kmalloc(sizeof(*opts), GFP_KERNEL);
	if (opts == NULL) {
		err = -ENOMEM;
		goto out2;
	}

	if (comp_opts) {
		/* check compressor options are the expected length */
		if (len < sizeof(*comp_opts)) {
			err = -EIO;
			goto out;
		}

		opts->dict_size = le32_to_cpu(comp_opts->dictionary_size);

		/* the dictionary size should be 2^n or 2^n+2^(n+1) */
		n = ffs(opts->dict_size) - 1;
		if (opts->dict_size != (1 << n) && opts->dict_size != (1 << n) +
						(1 << (n + 1))) {
			err = -EIO;
			goto out;
		}
	} else
		/* use defaults */
		opts->dict_size = max_t(int, msblk->block_size,
							SQUASHFS_METADATA_SIZE);

	return opts;

out:
	kfree(opts);
out2:
	return ERR_PTR(err);
}


static void *squashfs_xz_init(struct squashfs_sb_info *msblk, void *buff)
{
	struct comp_opts *comp_opts = buff;
	struct squashfs_xz *stream;
	int err;

	stream = kmalloc(sizeof(*stream), GFP_KERNEL);
	if (stream == NULL) {
		err = -ENOMEM;
		goto failed;
	}

	stream->state = xz_dec_init(XZ_PREALLOC, comp_opts->dict_size);
	if (stream->state == NULL) {
		kfree(stream);
		err = -ENOMEM;
		goto failed;
	}

	return stream;

failed:
	ERROR("Failed to initialise xz decompressor\n");
	return ERR_PTR(err);
}


static void squashfs_xz_free(void *strm)
{
	struct squashfs_xz *stream = strm;

	if (stream) {
		xz_dec_end(stream->state);
		kfree(stream);
	}
}


static int squashfs_xz_uncompress(struct squashfs_sb_info *msblk, void *strm,
	struct buffer_head **bh, int b, int offset, int length,
	struct squashfs_page_actor *output)
{
	enum xz_ret xz_err;
	int avail, total = 0, k = 0;
	struct squashfs_xz *stream = strm;

	xz_dec_reset(stream->state);
	stream->buf.in_pos = 0;
	stream->buf.in_size = 0;
	stream->buf.out_pos = 0;
	stream->buf.out_size = PAGE_CACHE_SIZE;
	stream->buf.out = squashfs_first_page(output);

	do {
		if (stream->buf.in_pos == stream->buf.in_size && k < b) {
			avail = min(length, msblk->devblksize - offset);
			length -= avail;
			stream->buf.in = bh[k]->b_data + offset;
			stream->buf.in_size = avail;
			stream->buf.in_pos = 0;
			offset = 0;
		}

		if (stream->buf.out_pos == stream->buf.out_size) {
			stream->buf.out = squashfs_next_page(output);
			if (stream->buf.out != NULL) {
				stream->buf.out_pos = 0;
				total += PAGE_CACHE_SIZE;
			}
		}

		xz_err = xz_dec_run(stream->state, &stream->buf);

		if (stream->buf.in_pos == stream->buf.in_size && k < b)
			put_bh(bh[k++]);
	} while (xz_err == XZ_OK);

	squashfs_finish_page(output);

	if (xz_err != XZ_STREAM_END || k < b)
		goto out;

	return total + stream->buf.out_pos;

out:
	for (; k < b; k++)
		put_bh(bh[k]);

	return -EIO;
}

const struct squashfs_decompressor squashfs_xz_comp_ops = {
	.init = squashfs_xz_init,
	.comp_opts = squashfs_xz_comp_opts,
	.free = squashfs_xz_free,
	.decompress = squashfs_xz_uncompress,
	.id = XZ_COMPRESSION,
	.name = "xz",
	.supported = 1
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/xz_wrapper.c */
/************************************************************/
/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * zlib_wrapper.c
 */


// #include <linux/mutex.h>
// #include <linux/buffer_head.h>
// #include <linux/slab.h>
#include <linux/zlib.h>
// #include <linux/vmalloc.h>

// #include "squashfs_fs.h"
// #include "squashfs_fs_sb.h"
// #include "squashfs.h"
// #include "decompressor.h"
// #include "page_actor.h"

static void *zlib_init(struct squashfs_sb_info *dummy, void *buff)
{
	z_stream *stream = kmalloc(sizeof(z_stream), GFP_KERNEL);
	if (stream == NULL)
		goto failed;
	stream->workspace = vmalloc(zlib_inflate_workspacesize());
	if (stream->workspace == NULL)
		goto failed;

	return stream;

failed:
	ERROR("Failed to allocate zlib workspace\n");
	kfree(stream);
	return ERR_PTR(-ENOMEM);
}


static void zlib_free(void *strm)
{
	z_stream *stream = strm;

	if (stream)
		vfree(stream->workspace);
	kfree(stream);
}


static int zlib_uncompress(struct squashfs_sb_info *msblk, void *strm,
	struct buffer_head **bh, int b, int offset, int length,
	struct squashfs_page_actor *output)
{
	int zlib_err, zlib_init = 0, k = 0;
	z_stream *stream = strm;

	stream->avail_out = PAGE_CACHE_SIZE;
	stream->next_out = squashfs_first_page(output);
	stream->avail_in = 0;

	do {
		if (stream->avail_in == 0 && k < b) {
			int avail = min(length, msblk->devblksize - offset);
			length -= avail;
			stream->next_in = bh[k]->b_data + offset;
			stream->avail_in = avail;
			offset = 0;
		}

		if (stream->avail_out == 0) {
			stream->next_out = squashfs_next_page(output);
			if (stream->next_out != NULL)
				stream->avail_out = PAGE_CACHE_SIZE;
		}

		if (!zlib_init) {
			zlib_err = zlib_inflateInit(stream);
			if (zlib_err != Z_OK) {
				squashfs_finish_page(output);
				goto out;
			}
			zlib_init = 1;
		}

		zlib_err = zlib_inflate(stream, Z_SYNC_FLUSH);

		if (stream->avail_in == 0 && k < b)
			put_bh(bh[k++]);
	} while (zlib_err == Z_OK);

	squashfs_finish_page(output);

	if (zlib_err != Z_STREAM_END)
		goto out;

	zlib_err = zlib_inflateEnd(stream);
	if (zlib_err != Z_OK)
		goto out;

	if (k < b)
		goto out;

	return stream->total_out;

out:
	for (; k < b; k++)
		put_bh(bh[k]);

	return -EIO;
}

const struct squashfs_decompressor squashfs_zlib_comp_ops = {
	.init = zlib_init,
	.free = zlib_free,
	.decompress = zlib_uncompress,
	.id = ZLIB_COMPRESSION,
	.name = "zlib",
	.supported = 1
};
/************************************************************/
/* ../linux-3.17/fs/squashfs/zlib_wrapper.c */
/************************************************************/
