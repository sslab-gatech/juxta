/*
 *  linux/fs/hfs/bitmap.c
 *
 * Copyright (C) 1996-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * Based on GPLed code Copyright (C) 1995  Michael Dreher
 *
 * This file contains the code to modify the volume bitmap:
 * search/set/clear bits.
 */

#include "hfs_fs.h"
#include "../../inc/__fss.h"

/*
 * hfs_find_zero_bit()
 *
 * Description:
 *  Given a block of memory, its length in bits, and a starting bit number,
 *  determine the number of the first zero bits (in left-to-right ordering)
 *  in that range.
 *
 *  Returns >= 'size' if no zero bits are found in the range.
 *
 *  Accesses memory in 32-bit aligned chunks of 32-bits and thus
 *  may read beyond the 'size'th bit.
 */
static u32 hfs_find_set_zero_bits(__be32 *bitmap, u32 size, u32 offset, u32 *max)
{
	__be32 *curr, *end;
	u32 mask, start, len, n;
	__be32 val;
	int i;

	len = *max;
	if (!len)
		return size;

	curr = bitmap + (offset / 32);
	end = bitmap + ((size + 31) / 32);

	/* scan the first partial u32 for zero bits */
	val = *curr;
	if (~val) {
		n = be32_to_cpu(val);
		i = offset % 32;
		mask = (1U << 31) >> i;
		for (; i < 32; mask >>= 1, i++) {
			if (!(n & mask))
				goto found;
		}
	}

	/* scan complete u32s for the first zero bit */
	while (++curr < end) {
		val = *curr;
		if (~val) {
			n = be32_to_cpu(val);
			mask = 1 << 31;
			for (i = 0; i < 32; mask >>= 1, i++) {
				if (!(n & mask))
					goto found;
			}
		}
	}
	return size;

found:
	start = (curr - bitmap) * 32 + i;
	if (start >= size)
		return start;
	/* do any partial u32 at the start */
	len = min(size - start, len);
	while (1) {
		n |= mask;
		if (++i >= 32)
			break;
		mask >>= 1;
		if (!--len || n & mask)
			goto done;
	}
	if (!--len)
		goto done;
	*curr++ = cpu_to_be32(n);
	/* do full u32s */
	while (1) {
		n = be32_to_cpu(*curr);
		if (len < 32)
			break;
		if (n) {
			len = 32;
			break;
		}
		*curr++ = cpu_to_be32(0xffffffff);
		len -= 32;
	}
	/* do any partial u32 at end */
	mask = 1U << 31;
	for (i = 0; i < len; i++) {
		if (n & mask)
			break;
		n |= mask;
		mask >>= 1;
	}
done:
	*curr = cpu_to_be32(n);
	*max = (curr - bitmap) * 32 + i - start;
	return start;
}

/*
 * hfs_vbm_search_free()
 *
 * Description:
 *   Search for 'num_bits' consecutive cleared bits in the bitmap blocks of
 *   the hfs MDB. 'mdb' had better be locked or the returned range
 *   may be no longer free, when this functions returns!
 *   XXX Currently the search starts from bit 0, but it should start with
 *   the bit number stored in 's_alloc_ptr' of the MDB.
 * Input Variable(s):
 *   struct hfs_mdb *mdb: Pointer to the hfs MDB
 *   u16 *num_bits: Pointer to the number of cleared bits
 *     to search for
 * Output Variable(s):
 *   u16 *num_bits: The number of consecutive clear bits of the
 *     returned range. If the bitmap is fragmented, this will be less than
 *     requested and it will be zero, when the disk is full.
 * Returns:
 *   The number of the first bit of the range of cleared bits which has been
 *   found. When 'num_bits' is zero, this is invalid!
 * Preconditions:
 *   'mdb' points to a "valid" (struct hfs_mdb).
 *   'num_bits' points to a variable of type (u16), which contains
 *	the number of cleared bits to find.
 * Postconditions:
 *   'num_bits' is set to the length of the found sequence.
 */
u32 hfs_vbm_search_free(struct super_block *sb, u32 goal, u32 *num_bits)
{
	void *bitmap;
	u32 pos;

	/* make sure we have actual work to perform */
	if (!*num_bits)
		return 0;

	mutex_lock(&HFS_SB(sb)->bitmap_lock);
	bitmap = HFS_SB(sb)->bitmap;

	pos = hfs_find_set_zero_bits(bitmap, HFS_SB(sb)->fs_ablocks, goal, num_bits);
	if (pos >= HFS_SB(sb)->fs_ablocks) {
		if (goal)
			pos = hfs_find_set_zero_bits(bitmap, goal, 0, num_bits);
		if (pos >= HFS_SB(sb)->fs_ablocks) {
			*num_bits = pos = 0;
			goto out;
		}
	}

	hfs_dbg(BITMAP, "alloc_bits: %u,%u\n", pos, *num_bits);
	HFS_SB(sb)->free_ablocks -= *num_bits;
	hfs_bitmap_dirty(sb);
out:
	mutex_unlock(&HFS_SB(sb)->bitmap_lock);
	return pos;
}


/*
 * hfs_clear_vbm_bits()
 *
 * Description:
 *   Clear the requested bits in the volume bitmap of the hfs filesystem
 * Input Variable(s):
 *   struct hfs_mdb *mdb: Pointer to the hfs MDB
 *   u16 start: The offset of the first bit
 *   u16 count: The number of bits
 * Output Variable(s):
 *   None
 * Returns:
 *    0: no error
 *   -1: One of the bits was already clear.  This is a strange
 *	 error and when it happens, the filesystem must be repaired!
 *   -2: One or more of the bits are out of range of the bitmap.
 * Preconditions:
 *   'mdb' points to a "valid" (struct hfs_mdb).
 * Postconditions:
 *   Starting with bit number 'start', 'count' bits in the volume bitmap
 *   are cleared. The affected bitmap blocks are marked "dirty", the free
 *   block count of the MDB is updated and the MDB is marked dirty.
 */
int hfs_clear_vbm_bits(struct super_block *sb, u16 start, u16 count)
{
	__be32 *curr;
	u32 mask;
	int i, len;

	/* is there any actual work to be done? */
	if (!count)
		return 0;

	hfs_dbg(BITMAP, "clear_bits: %u,%u\n", start, count);
	/* are all of the bits in range? */
	if ((start + count) > HFS_SB(sb)->fs_ablocks)
		return -2;

	mutex_lock(&HFS_SB(sb)->bitmap_lock);
	/* bitmap is always on a 32-bit boundary */
	curr = HFS_SB(sb)->bitmap + (start / 32);
	len = count;

	/* do any partial u32 at the start */
	i = start % 32;
	if (i) {
		int j = 32 - i;
		mask = 0xffffffffU << j;
		if (j > count) {
			mask |= 0xffffffffU >> (i + count);
			*curr &= cpu_to_be32(mask);
			goto out;
		}
		*curr++ &= cpu_to_be32(mask);
		count -= j;
	}

	/* do full u32s */
	while (count >= 32) {
		*curr++ = 0;
		count -= 32;
	}
	/* do any partial u32 at end */
	if (count) {
		mask = 0xffffffffU >> count;
		*curr &= cpu_to_be32(mask);
	}
out:
	HFS_SB(sb)->free_ablocks += len;
	mutex_unlock(&HFS_SB(sb)->bitmap_lock);
	hfs_bitmap_dirty(sb);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/bitmap.c */
/************************************************************/
/*
 *  linux/fs/hfs/bfind.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Search routines for btrees
 */

#include <linux/slab.h>
#include "btree.h"
#include "../../inc/__fss.h"

int hfs_find_init(struct hfs_btree *tree, struct hfs_find_data *fd)
{
	void *ptr;

	fd->tree = tree;
	fd->bnode = NULL;
	ptr = kmalloc(tree->max_key_len * 2 + 4, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	fd->search_key = ptr;
	fd->key = ptr + tree->max_key_len + 2;
	hfs_dbg(BNODE_REFS, "find_init: %d (%p)\n",
		tree->cnid, __builtin_return_address(0));
	mutex_lock(&tree->tree_lock);
	return 0;
}

void hfs_find_exit(struct hfs_find_data *fd)
{
	hfs_bnode_put(fd->bnode);
	kfree(fd->search_key);
	hfs_dbg(BNODE_REFS, "find_exit: %d (%p)\n",
		fd->tree->cnid, __builtin_return_address(0));
	mutex_unlock(&fd->tree->tree_lock);
	fd->tree = NULL;
}

/* Find the record in bnode that best matches key (not greater than...)*/
int __hfs_brec_find(struct hfs_bnode *bnode, struct hfs_find_data *fd)
{
	int cmpval;
	u16 off, len, keylen;
	int rec;
	int b, e;
	int res;

	b = 0;
	e = bnode->num_recs - 1;
	res = -ENOENT;
	do {
		rec = (e + b) / 2;
		len = hfs_brec_lenoff(bnode, rec, &off);
		keylen = hfs_brec_keylen(bnode, rec);
		if (keylen == 0) {
			res = -EINVAL;
			goto fail;
		}
		hfs_bnode_read(bnode, fd->key, off, keylen);
		cmpval = bnode->tree->keycmp(fd->key, fd->search_key);
		if (!cmpval) {
			e = rec;
			res = 0;
			goto done;
		}
		if (cmpval < 0)
			b = rec + 1;
		else
			e = rec - 1;
	} while (b <= e);
	if (rec != e && e >= 0) {
		len = hfs_brec_lenoff(bnode, e, &off);
		keylen = hfs_brec_keylen(bnode, e);
		if (keylen == 0) {
			res = -EINVAL;
			goto fail;
		}
		hfs_bnode_read(bnode, fd->key, off, keylen);
	}
done:
	fd->record = e;
	fd->keyoffset = off;
	fd->keylength = keylen;
	fd->entryoffset = off + keylen;
	fd->entrylength = len - keylen;
fail:
	return res;
}

/* Traverse a B*Tree from the root to a leaf finding best fit to key */
/* Return allocated copy of node found, set recnum to best record */
int hfs_brec_find(struct hfs_find_data *fd)
{
	struct hfs_btree *tree;
	struct hfs_bnode *bnode;
	u32 nidx, parent;
	__be32 data;
	int height, res;

	tree = fd->tree;
	if (fd->bnode)
		hfs_bnode_put(fd->bnode);
	fd->bnode = NULL;
	nidx = tree->root;
	if (!nidx)
		return -ENOENT;
	height = tree->depth;
	res = 0;
	parent = 0;
	for (;;) {
		bnode = hfs_bnode_find(tree, nidx);
		if (IS_ERR(bnode)) {
			res = PTR_ERR(bnode);
			bnode = NULL;
			break;
		}
		if (bnode->height != height)
			goto invalid;
		if (bnode->type != (--height ? HFS_NODE_INDEX : HFS_NODE_LEAF))
			goto invalid;
		bnode->parent = parent;

		res = __hfs_brec_find(bnode, fd);
		if (!height)
			break;
		if (fd->record < 0)
			goto release;

		parent = nidx;
		hfs_bnode_read(bnode, &data, fd->entryoffset, 4);
		nidx = be32_to_cpu(data);
		hfs_bnode_put(bnode);
	}
	fd->bnode = bnode;
	return res;

invalid:
	pr_err("inconsistency in B*Tree (%d,%d,%d,%u,%u)\n",
	       height, bnode->height, bnode->type, nidx, parent);
	res = -EIO;
release:
	hfs_bnode_put(bnode);
	return res;
}

int hfs_brec_read(struct hfs_find_data *fd, void *rec, int rec_len)
{
	int res;

	res = hfs_brec_find(fd);
	if (res)
		return res;
	if (fd->entrylength > rec_len)
		return -EINVAL;
	hfs_bnode_read(fd->bnode, rec, fd->entryoffset, fd->entrylength);
	return 0;
}

int hfs_brec_goto(struct hfs_find_data *fd, int cnt)
{
	struct hfs_btree *tree;
	struct hfs_bnode *bnode;
	int idx, res = 0;
	u16 off, len, keylen;

	bnode = fd->bnode;
	tree = bnode->tree;

	if (cnt < 0) {
		cnt = -cnt;
		while (cnt > fd->record) {
			cnt -= fd->record + 1;
			fd->record = bnode->num_recs - 1;
			idx = bnode->prev;
			if (!idx) {
				res = -ENOENT;
				goto out;
			}
			hfs_bnode_put(bnode);
			bnode = hfs_bnode_find(tree, idx);
			if (IS_ERR(bnode)) {
				res = PTR_ERR(bnode);
				bnode = NULL;
				goto out;
			}
		}
		fd->record -= cnt;
	} else {
		while (cnt >= bnode->num_recs - fd->record) {
			cnt -= bnode->num_recs - fd->record;
			fd->record = 0;
			idx = bnode->next;
			if (!idx) {
				res = -ENOENT;
				goto out;
			}
			hfs_bnode_put(bnode);
			bnode = hfs_bnode_find(tree, idx);
			if (IS_ERR(bnode)) {
				res = PTR_ERR(bnode);
				bnode = NULL;
				goto out;
			}
		}
		fd->record += cnt;
	}

	len = hfs_brec_lenoff(bnode, fd->record, &off);
	keylen = hfs_brec_keylen(bnode, fd->record);
	if (keylen == 0) {
		res = -EINVAL;
		goto out;
	}
	fd->keyoffset = off;
	fd->keylength = keylen;
	fd->entryoffset = off + keylen;
	fd->entrylength = len - keylen;
	hfs_bnode_read(bnode, fd->key, off, keylen);
out:
	fd->bnode = bnode;
	return res;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/bfind.c */
/************************************************************/
/*
 *  linux/fs/hfs/bnode.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handle basic btree node operations
 */

#include <linux/pagemap.h>
// #include <linux/slab.h>
#include <linux/swap.h>
#include "../../inc/__fss.h"

// #include "btree.h"

void hfs_bnode_read(struct hfs_bnode *node, void *buf,
		int off, int len)
{
	struct page *page;

	off += node->page_offset;
	page = node->page[0];

	memcpy(buf, kmap(page) + off, len);
	kunmap(page);
}

u16 hfs_bnode_read_u16(struct hfs_bnode *node, int off)
{
	__be16 data;
	// optimize later...
	hfs_bnode_read(node, &data, off, 2);
	return be16_to_cpu(data);
}

u8 hfs_bnode_read_u8(struct hfs_bnode *node, int off)
{
	u8 data;
	// optimize later...
	hfs_bnode_read(node, &data, off, 1);
	return data;
}

void hfs_bnode_read_key(struct hfs_bnode *node, void *key, int off)
{
	struct hfs_btree *tree;
	int key_len;

	tree = node->tree;
	if (node->type == HFS_NODE_LEAF ||
	    tree->attributes & HFS_TREE_VARIDXKEYS)
		key_len = hfs_bnode_read_u8(node, off) + 1;
	else
		key_len = tree->max_key_len + 1;

	hfs_bnode_read(node, key, off, key_len);
}

void hfs_bnode_write(struct hfs_bnode *node, void *buf, int off, int len)
{
	struct page *page;

	off += node->page_offset;
	page = node->page[0];

	memcpy(kmap(page) + off, buf, len);
	kunmap(page);
	set_page_dirty(page);
}

void hfs_bnode_write_u16(struct hfs_bnode *node, int off, u16 data)
{
	__be16 v = cpu_to_be16(data);
	// optimize later...
	hfs_bnode_write(node, &v, off, 2);
}

void hfs_bnode_write_u8(struct hfs_bnode *node, int off, u8 data)
{
	// optimize later...
	hfs_bnode_write(node, &data, off, 1);
}

void hfs_bnode_clear(struct hfs_bnode *node, int off, int len)
{
	struct page *page;

	off += node->page_offset;
	page = node->page[0];

	memset(kmap(page) + off, 0, len);
	kunmap(page);
	set_page_dirty(page);
}

void hfs_bnode_copy(struct hfs_bnode *dst_node, int dst,
		struct hfs_bnode *src_node, int src, int len)
{
	struct hfs_btree *tree;
	struct page *src_page, *dst_page;

	hfs_dbg(BNODE_MOD, "copybytes: %u,%u,%u\n", dst, src, len);
	if (!len)
		return;
	tree = src_node->tree;
	src += src_node->page_offset;
	dst += dst_node->page_offset;
	src_page = src_node->page[0];
	dst_page = dst_node->page[0];

	memcpy(kmap(dst_page) + dst, kmap(src_page) + src, len);
	kunmap(src_page);
	kunmap(dst_page);
	set_page_dirty(dst_page);
}

void hfs_bnode_move(struct hfs_bnode *node, int dst, int src, int len)
{
	struct page *page;
	void *ptr;

	hfs_dbg(BNODE_MOD, "movebytes: %u,%u,%u\n", dst, src, len);
	if (!len)
		return;
	src += node->page_offset;
	dst += node->page_offset;
	page = node->page[0];
	ptr = kmap(page);
	memmove(ptr + dst, ptr + src, len);
	kunmap(page);
	set_page_dirty(page);
}

void hfs_bnode_dump(struct hfs_bnode *node)
{
	struct hfs_bnode_desc desc;
	__be32 cnid;
	int i, off, key_off;

	hfs_dbg(BNODE_MOD, "bnode: %d\n", node->this);
	hfs_bnode_read(node, &desc, 0, sizeof(desc));
	hfs_dbg(BNODE_MOD, "%d, %d, %d, %d, %d\n",
		be32_to_cpu(desc.next), be32_to_cpu(desc.prev),
		desc.type, desc.height, be16_to_cpu(desc.num_recs));

	off = node->tree->node_size - 2;
	for (i = be16_to_cpu(desc.num_recs); i >= 0; off -= 2, i--) {
		key_off = hfs_bnode_read_u16(node, off);
		hfs_dbg_cont(BNODE_MOD, " %d", key_off);
		if (i && node->type == HFS_NODE_INDEX) {
			int tmp;

			if (node->tree->attributes & HFS_TREE_VARIDXKEYS)
				tmp = (hfs_bnode_read_u8(node, key_off) | 1) + 1;
			else
				tmp = node->tree->max_key_len + 1;
			hfs_dbg_cont(BNODE_MOD, " (%d,%d",
				     tmp, hfs_bnode_read_u8(node, key_off));
			hfs_bnode_read(node, &cnid, key_off + tmp, 4);
			hfs_dbg_cont(BNODE_MOD, ",%d)", be32_to_cpu(cnid));
		} else if (i && node->type == HFS_NODE_LEAF) {
			int tmp;

			tmp = hfs_bnode_read_u8(node, key_off);
			hfs_dbg_cont(BNODE_MOD, " (%d)", tmp);
		}
	}
	hfs_dbg_cont(BNODE_MOD, "\n");
}

void hfs_bnode_unlink(struct hfs_bnode *node)
{
	struct hfs_btree *tree;
	struct hfs_bnode *tmp;
	__be32 cnid;

	tree = node->tree;
	if (node->prev) {
		tmp = hfs_bnode_find(tree, node->prev);
		if (IS_ERR(tmp))
			return;
		tmp->next = node->next;
		cnid = cpu_to_be32(tmp->next);
		hfs_bnode_write(tmp, &cnid, offsetof(struct hfs_bnode_desc, next), 4);
		hfs_bnode_put(tmp);
	} else if (node->type == HFS_NODE_LEAF)
		tree->leaf_head = node->next;

	if (node->next) {
		tmp = hfs_bnode_find(tree, node->next);
		if (IS_ERR(tmp))
			return;
		tmp->prev = node->prev;
		cnid = cpu_to_be32(tmp->prev);
		hfs_bnode_write(tmp, &cnid, offsetof(struct hfs_bnode_desc, prev), 4);
		hfs_bnode_put(tmp);
	} else if (node->type == HFS_NODE_LEAF)
		tree->leaf_tail = node->prev;

	// move down?
	if (!node->prev && !node->next) {
		printk(KERN_DEBUG "hfs_btree_del_level\n");
	}
	if (!node->parent) {
		tree->root = 0;
		tree->depth = 0;
	}
	set_bit(HFS_BNODE_DELETED, &node->flags);
}

static inline int hfs_bnode_hash(u32 num)
{
	num = (num >> 16) + num;
	num += num >> 8;
	return num & (NODE_HASH_SIZE - 1);
}

struct hfs_bnode *hfs_bnode_findhash(struct hfs_btree *tree, u32 cnid)
{
	struct hfs_bnode *node;

	if (cnid >= tree->node_count) {
		pr_err("request for non-existent node %d in B*Tree\n", cnid);
		return NULL;
	}

	for (node = tree->node_hash[hfs_bnode_hash(cnid)];
	     node; node = node->next_hash) {
		if (node->this == cnid) {
			return node;
		}
	}
	return NULL;
}

static struct hfs_bnode *__hfs_bnode_create(struct hfs_btree *tree, u32 cnid)
{
	struct super_block *sb;
	struct hfs_bnode *node, *node2;
	struct address_space *mapping;
	struct page *page;
	int size, block, i, hash;
	loff_t off;

	if (cnid >= tree->node_count) {
		pr_err("request for non-existent node %d in B*Tree\n", cnid);
		return NULL;
	}

	sb = tree->inode->i_sb;
	size = sizeof(struct hfs_bnode) + tree->pages_per_bnode *
		sizeof(struct page *);
	node = kzalloc(size, GFP_KERNEL);
	if (!node)
		return NULL;
	node->tree = tree;
	node->this = cnid;
	set_bit(HFS_BNODE_NEW, &node->flags);
	atomic_set(&node->refcnt, 1);
	hfs_dbg(BNODE_REFS, "new_node(%d:%d): 1\n",
		node->tree->cnid, node->this);
	init_waitqueue_head(&node->lock_wq);
	spin_lock(&tree->hash_lock);
	node2 = hfs_bnode_findhash(tree, cnid);
	if (!node2) {
		hash = hfs_bnode_hash(cnid);
		node->next_hash = tree->node_hash[hash];
		tree->node_hash[hash] = node;
		tree->node_hash_cnt++;
	} else {
		spin_unlock(&tree->hash_lock);
		kfree(node);
		wait_event(node2->lock_wq, !test_bit(HFS_BNODE_NEW, &node2->flags));
		return node2;
	}
	spin_unlock(&tree->hash_lock);

	mapping = tree->inode->i_mapping;
	off = (loff_t)cnid * tree->node_size;
	block = off >> PAGE_CACHE_SHIFT;
	node->page_offset = off & ~PAGE_CACHE_MASK;
	for (i = 0; i < tree->pages_per_bnode; i++) {
		page = read_mapping_page(mapping, block++, NULL);
		if (IS_ERR(page))
			goto fail;
		if (PageError(page)) {
			page_cache_release(page);
			goto fail;
		}
		page_cache_release(page);
		node->page[i] = page;
	}

	return node;
fail:
	set_bit(HFS_BNODE_ERROR, &node->flags);
	return node;
}

void hfs_bnode_unhash(struct hfs_bnode *node)
{
	struct hfs_bnode **p;

	hfs_dbg(BNODE_REFS, "remove_node(%d:%d): %d\n",
		node->tree->cnid, node->this, atomic_read(&node->refcnt));
	for (p = &node->tree->node_hash[hfs_bnode_hash(node->this)];
	     *p && *p != node; p = &(*p)->next_hash)
		;
	BUG_ON(!*p);
	*p = node->next_hash;
	node->tree->node_hash_cnt--;
}

/* Load a particular node out of a tree */
struct hfs_bnode *hfs_bnode_find(struct hfs_btree *tree, u32 num)
{
	struct hfs_bnode *node;
	struct hfs_bnode_desc *desc;
	int i, rec_off, off, next_off;
	int entry_size, key_size;

	spin_lock(&tree->hash_lock);
	node = hfs_bnode_findhash(tree, num);
	if (node) {
		hfs_bnode_get(node);
		spin_unlock(&tree->hash_lock);
		wait_event(node->lock_wq, !test_bit(HFS_BNODE_NEW, &node->flags));
		if (test_bit(HFS_BNODE_ERROR, &node->flags))
			goto node_error;
		return node;
	}
	spin_unlock(&tree->hash_lock);
	node = __hfs_bnode_create(tree, num);
	if (!node)
		return ERR_PTR(-ENOMEM);
	if (test_bit(HFS_BNODE_ERROR, &node->flags))
		goto node_error;
	if (!test_bit(HFS_BNODE_NEW, &node->flags))
		return node;

	desc = (struct hfs_bnode_desc *)(kmap(node->page[0]) + node->page_offset);
	node->prev = be32_to_cpu(desc->prev);
	node->next = be32_to_cpu(desc->next);
	node->num_recs = be16_to_cpu(desc->num_recs);
	node->type = desc->type;
	node->height = desc->height;
	kunmap(node->page[0]);

	switch (node->type) {
	case HFS_NODE_HEADER:
	case HFS_NODE_MAP:
		if (node->height != 0)
			goto node_error;
		break;
	case HFS_NODE_LEAF:
		if (node->height != 1)
			goto node_error;
		break;
	case HFS_NODE_INDEX:
		if (node->height <= 1 || node->height > tree->depth)
			goto node_error;
		break;
	default:
		goto node_error;
	}

	rec_off = tree->node_size - 2;
	off = hfs_bnode_read_u16(node, rec_off);
	if (off != sizeof(struct hfs_bnode_desc))
		goto node_error;
	for (i = 1; i <= node->num_recs; off = next_off, i++) {
		rec_off -= 2;
		next_off = hfs_bnode_read_u16(node, rec_off);
		if (next_off <= off ||
		    next_off > tree->node_size ||
		    next_off & 1)
			goto node_error;
		entry_size = next_off - off;
		if (node->type != HFS_NODE_INDEX &&
		    node->type != HFS_NODE_LEAF)
			continue;
		key_size = hfs_bnode_read_u8(node, off) + 1;
		if (key_size >= entry_size /*|| key_size & 1*/)
			goto node_error;
	}
	clear_bit(HFS_BNODE_NEW, &node->flags);
	wake_up(&node->lock_wq);
	return node;

node_error:
	set_bit(HFS_BNODE_ERROR, &node->flags);
	clear_bit(HFS_BNODE_NEW, &node->flags);
	wake_up(&node->lock_wq);
	hfs_bnode_put(node);
	return ERR_PTR(-EIO);
}

void hfs_bnode_free(struct hfs_bnode *node)
{
	//int i;

	//for (i = 0; i < node->tree->pages_per_bnode; i++)
	//	if (node->page[i])
	//		page_cache_release(node->page[i]);
	kfree(node);
}

struct hfs_bnode *hfs_bnode_create(struct hfs_btree *tree, u32 num)
{
	struct hfs_bnode *node;
	struct page **pagep;
	int i;

	spin_lock(&tree->hash_lock);
	node = hfs_bnode_findhash(tree, num);
	spin_unlock(&tree->hash_lock);
	if (node) {
		pr_crit("new node %u already hashed?\n", num);
		WARN_ON(1);
		return node;
	}
	node = __hfs_bnode_create(tree, num);
	if (!node)
		return ERR_PTR(-ENOMEM);
	if (test_bit(HFS_BNODE_ERROR, &node->flags)) {
		hfs_bnode_put(node);
		return ERR_PTR(-EIO);
	}

	pagep = node->page;
	memset(kmap(*pagep) + node->page_offset, 0,
	       min((int)PAGE_CACHE_SIZE, (int)tree->node_size));
	set_page_dirty(*pagep);
	kunmap(*pagep);
	for (i = 1; i < tree->pages_per_bnode; i++) {
		memset(kmap(*++pagep), 0, PAGE_CACHE_SIZE);
		set_page_dirty(*pagep);
		kunmap(*pagep);
	}
	clear_bit(HFS_BNODE_NEW, &node->flags);
	wake_up(&node->lock_wq);

	return node;
}

void hfs_bnode_get(struct hfs_bnode *node)
{
	if (node) {
		atomic_inc(&node->refcnt);
		hfs_dbg(BNODE_REFS, "get_node(%d:%d): %d\n",
			node->tree->cnid, node->this,
			atomic_read(&node->refcnt));
	}
}

/* Dispose of resources used by a node */
void hfs_bnode_put(struct hfs_bnode *node)
{
	if (node) {
		struct hfs_btree *tree = node->tree;
		int i;

		hfs_dbg(BNODE_REFS, "put_node(%d:%d): %d\n",
			node->tree->cnid, node->this,
			atomic_read(&node->refcnt));
		BUG_ON(!atomic_read(&node->refcnt));
		if (!atomic_dec_and_lock(&node->refcnt, &tree->hash_lock))
			return;
		for (i = 0; i < tree->pages_per_bnode; i++) {
			if (!node->page[i])
				continue;
			mark_page_accessed(node->page[i]);
		}

		if (test_bit(HFS_BNODE_DELETED, &node->flags)) {
			hfs_bnode_unhash(node);
			spin_unlock(&tree->hash_lock);
			hfs_bmap_free(node);
			hfs_bnode_free(node);
			return;
		}
		spin_unlock(&tree->hash_lock);
	}
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/bnode.c */
/************************************************************/
/*
 *  linux/fs/hfs/brec.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handle individual btree records
 */

// #include "btree.h"

static struct hfs_bnode *hfs_bnode_split(struct hfs_find_data *fd);
static int hfs_brec_update_parent(struct hfs_find_data *fd);
static int hfs_btree_inc_height(struct hfs_btree *tree);

/* Get the length and offset of the given record in the given node */
u16 hfs_brec_lenoff(struct hfs_bnode *node, u16 rec, u16 *off)
{
	__be16 retval[2];
	u16 dataoff;

	dataoff = node->tree->node_size - (rec + 2) * 2;
	hfs_bnode_read(node, retval, dataoff, 4);
	*off = be16_to_cpu(retval[1]);
	return be16_to_cpu(retval[0]) - *off;
}

/* Get the length of the key from a keyed record */
u16 hfs_brec_keylen(struct hfs_bnode *node, u16 rec)
{
	u16 retval, recoff;

	if (node->type != HFS_NODE_INDEX && node->type != HFS_NODE_LEAF)
		return 0;

	if ((node->type == HFS_NODE_INDEX) &&
	   !(node->tree->attributes & HFS_TREE_VARIDXKEYS)) {
		if (node->tree->attributes & HFS_TREE_BIGKEYS)
			retval = node->tree->max_key_len + 2;
		else
			retval = node->tree->max_key_len + 1;
	} else {
		recoff = hfs_bnode_read_u16(node, node->tree->node_size - (rec + 1) * 2);
		if (!recoff)
			return 0;
		if (node->tree->attributes & HFS_TREE_BIGKEYS) {
			retval = hfs_bnode_read_u16(node, recoff) + 2;
			if (retval > node->tree->max_key_len + 2) {
				pr_err("keylen %d too large\n", retval);
				retval = 0;
			}
		} else {
			retval = (hfs_bnode_read_u8(node, recoff) | 1) + 1;
			if (retval > node->tree->max_key_len + 1) {
				pr_err("keylen %d too large\n", retval);
				retval = 0;
			}
		}
	}
	return retval;
}

int hfs_brec_insert(struct hfs_find_data *fd, void *entry, int entry_len)
{
	struct hfs_btree *tree;
	struct hfs_bnode *node, *new_node;
	int size, key_len, rec;
	int data_off, end_off;
	int idx_rec_off, data_rec_off, end_rec_off;
	__be32 cnid;

	tree = fd->tree;
	if (!fd->bnode) {
		if (!tree->root)
			hfs_btree_inc_height(tree);
		fd->bnode = hfs_bnode_find(tree, tree->leaf_head);
		if (IS_ERR(fd->bnode))
			return PTR_ERR(fd->bnode);
		fd->record = -1;
	}
	new_node = NULL;
	key_len = (fd->search_key->key_len | 1) + 1;
again:
	/* new record idx and complete record size */
	rec = fd->record + 1;
	size = key_len + entry_len;

	node = fd->bnode;
	hfs_bnode_dump(node);
	/* get last offset */
	end_rec_off = tree->node_size - (node->num_recs + 1) * 2;
	end_off = hfs_bnode_read_u16(node, end_rec_off);
	end_rec_off -= 2;
	hfs_dbg(BNODE_MOD, "insert_rec: %d, %d, %d, %d\n",
		rec, size, end_off, end_rec_off);
	if (size > end_rec_off - end_off) {
		if (new_node)
			panic("not enough room!\n");
		new_node = hfs_bnode_split(fd);
		if (IS_ERR(new_node))
			return PTR_ERR(new_node);
		goto again;
	}
	if (node->type == HFS_NODE_LEAF) {
		tree->leaf_count++;
		mark_inode_dirty(tree->inode);
	}
	node->num_recs++;
	/* write new last offset */
	hfs_bnode_write_u16(node, offsetof(struct hfs_bnode_desc, num_recs), node->num_recs);
	hfs_bnode_write_u16(node, end_rec_off, end_off + size);
	data_off = end_off;
	data_rec_off = end_rec_off + 2;
	idx_rec_off = tree->node_size - (rec + 1) * 2;
	if (idx_rec_off == data_rec_off)
		goto skip;
	/* move all following entries */
	do {
		data_off = hfs_bnode_read_u16(node, data_rec_off + 2);
		hfs_bnode_write_u16(node, data_rec_off, data_off + size);
		data_rec_off += 2;
	} while (data_rec_off < idx_rec_off);

	/* move data away */
	hfs_bnode_move(node, data_off + size, data_off,
		       end_off - data_off);

skip:
	hfs_bnode_write(node, fd->search_key, data_off, key_len);
	hfs_bnode_write(node, entry, data_off + key_len, entry_len);
	hfs_bnode_dump(node);

	if (new_node) {
		/* update parent key if we inserted a key
		 * at the start of the first node
		 */
		if (!rec && new_node != node)
			hfs_brec_update_parent(fd);

		hfs_bnode_put(fd->bnode);
		if (!new_node->parent) {
			hfs_btree_inc_height(tree);
			new_node->parent = tree->root;
		}
		fd->bnode = hfs_bnode_find(tree, new_node->parent);

		/* create index data entry */
		cnid = cpu_to_be32(new_node->this);
		entry = &cnid;
		entry_len = sizeof(cnid);

		/* get index key */
		hfs_bnode_read_key(new_node, fd->search_key, 14);
		__hfs_brec_find(fd->bnode, fd);

		hfs_bnode_put(new_node);
		new_node = NULL;

		if (tree->attributes & HFS_TREE_VARIDXKEYS)
			key_len = fd->search_key->key_len + 1;
		else {
			fd->search_key->key_len = tree->max_key_len;
			key_len = tree->max_key_len + 1;
		}
		goto again;
	}

	if (!rec)
		hfs_brec_update_parent(fd);

	return 0;
}

int hfs_brec_remove(struct hfs_find_data *fd)
{
	struct hfs_btree *tree;
	struct hfs_bnode *node, *parent;
	int end_off, rec_off, data_off, size;

	tree = fd->tree;
	node = fd->bnode;
again:
	rec_off = tree->node_size - (fd->record + 2) * 2;
	end_off = tree->node_size - (node->num_recs + 1) * 2;

	if (node->type == HFS_NODE_LEAF) {
		tree->leaf_count--;
		mark_inode_dirty(tree->inode);
	}
	hfs_bnode_dump(node);
	hfs_dbg(BNODE_MOD, "remove_rec: %d, %d\n",
		fd->record, fd->keylength + fd->entrylength);
	if (!--node->num_recs) {
		hfs_bnode_unlink(node);
		if (!node->parent)
			return 0;
		parent = hfs_bnode_find(tree, node->parent);
		if (IS_ERR(parent))
			return PTR_ERR(parent);
		hfs_bnode_put(node);
		node = fd->bnode = parent;

		__hfs_brec_find(node, fd);
		goto again;
	}
	hfs_bnode_write_u16(node, offsetof(struct hfs_bnode_desc, num_recs), node->num_recs);

	if (rec_off == end_off)
		goto skip;
	size = fd->keylength + fd->entrylength;

	do {
		data_off = hfs_bnode_read_u16(node, rec_off);
		hfs_bnode_write_u16(node, rec_off + 2, data_off - size);
		rec_off -= 2;
	} while (rec_off >= end_off);

	/* fill hole */
	hfs_bnode_move(node, fd->keyoffset, fd->keyoffset + size,
		       data_off - fd->keyoffset - size);
skip:
	hfs_bnode_dump(node);
	if (!fd->record)
		hfs_brec_update_parent(fd);
	return 0;
}

static struct hfs_bnode *hfs_bnode_split(struct hfs_find_data *fd)
{
	struct hfs_btree *tree;
	struct hfs_bnode *node, *new_node, *next_node;
	struct hfs_bnode_desc node_desc;
	int num_recs, new_rec_off, new_off, old_rec_off;
	int data_start, data_end, size;

	tree = fd->tree;
	node = fd->bnode;
	new_node = hfs_bmap_alloc(tree);
	if (IS_ERR(new_node))
		return new_node;
	hfs_bnode_get(node);
	hfs_dbg(BNODE_MOD, "split_nodes: %d - %d - %d\n",
		node->this, new_node->this, node->next);
	new_node->next = node->next;
	new_node->prev = node->this;
	new_node->parent = node->parent;
	new_node->type = node->type;
	new_node->height = node->height;

	if (node->next)
		next_node = hfs_bnode_find(tree, node->next);
	else
		next_node = NULL;

	if (IS_ERR(next_node)) {
		hfs_bnode_put(node);
		hfs_bnode_put(new_node);
		return next_node;
	}

	size = tree->node_size / 2 - node->num_recs * 2 - 14;
	old_rec_off = tree->node_size - 4;
	num_recs = 1;
	for (;;) {
		data_start = hfs_bnode_read_u16(node, old_rec_off);
		if (data_start > size)
			break;
		old_rec_off -= 2;
		if (++num_recs < node->num_recs)
			continue;
		/* panic? */
		hfs_bnode_put(node);
		hfs_bnode_put(new_node);
		if (next_node)
			hfs_bnode_put(next_node);
		return ERR_PTR(-ENOSPC);
	}

	if (fd->record + 1 < num_recs) {
		/* new record is in the lower half,
		 * so leave some more space there
		 */
		old_rec_off += 2;
		num_recs--;
		data_start = hfs_bnode_read_u16(node, old_rec_off);
	} else {
		hfs_bnode_put(node);
		hfs_bnode_get(new_node);
		fd->bnode = new_node;
		fd->record -= num_recs;
		fd->keyoffset -= data_start - 14;
		fd->entryoffset -= data_start - 14;
	}
	new_node->num_recs = node->num_recs - num_recs;
	node->num_recs = num_recs;

	new_rec_off = tree->node_size - 2;
	new_off = 14;
	size = data_start - new_off;
	num_recs = new_node->num_recs;
	data_end = data_start;
	while (num_recs) {
		hfs_bnode_write_u16(new_node, new_rec_off, new_off);
		old_rec_off -= 2;
		new_rec_off -= 2;
		data_end = hfs_bnode_read_u16(node, old_rec_off);
		new_off = data_end - size;
		num_recs--;
	}
	hfs_bnode_write_u16(new_node, new_rec_off, new_off);
	hfs_bnode_copy(new_node, 14, node, data_start, data_end - data_start);

	/* update new bnode header */
	node_desc.next = cpu_to_be32(new_node->next);
	node_desc.prev = cpu_to_be32(new_node->prev);
	node_desc.type = new_node->type;
	node_desc.height = new_node->height;
	node_desc.num_recs = cpu_to_be16(new_node->num_recs);
	node_desc.reserved = 0;
	hfs_bnode_write(new_node, &node_desc, 0, sizeof(node_desc));

	/* update previous bnode header */
	node->next = new_node->this;
	hfs_bnode_read(node, &node_desc, 0, sizeof(node_desc));
	node_desc.next = cpu_to_be32(node->next);
	node_desc.num_recs = cpu_to_be16(node->num_recs);
	hfs_bnode_write(node, &node_desc, 0, sizeof(node_desc));

	/* update next bnode header */
	if (next_node) {
		next_node->prev = new_node->this;
		hfs_bnode_read(next_node, &node_desc, 0, sizeof(node_desc));
		node_desc.prev = cpu_to_be32(next_node->prev);
		hfs_bnode_write(next_node, &node_desc, 0, sizeof(node_desc));
		hfs_bnode_put(next_node);
	} else if (node->this == tree->leaf_tail) {
		/* if there is no next node, this might be the new tail */
		tree->leaf_tail = new_node->this;
		mark_inode_dirty(tree->inode);
	}

	hfs_bnode_dump(node);
	hfs_bnode_dump(new_node);
	hfs_bnode_put(node);

	return new_node;
}

static int hfs_brec_update_parent(struct hfs_find_data *fd)
{
	struct hfs_btree *tree;
	struct hfs_bnode *node, *new_node, *parent;
	int newkeylen, diff;
	int rec, rec_off, end_rec_off;
	int start_off, end_off;

	tree = fd->tree;
	node = fd->bnode;
	new_node = NULL;
	if (!node->parent)
		return 0;

again:
	parent = hfs_bnode_find(tree, node->parent);
	if (IS_ERR(parent))
		return PTR_ERR(parent);
	__hfs_brec_find(parent, fd);
	hfs_bnode_dump(parent);
	rec = fd->record;

	/* size difference between old and new key */
	if (tree->attributes & HFS_TREE_VARIDXKEYS)
		newkeylen = (hfs_bnode_read_u8(node, 14) | 1) + 1;
	else
		fd->keylength = newkeylen = tree->max_key_len + 1;
	hfs_dbg(BNODE_MOD, "update_rec: %d, %d, %d\n",
		rec, fd->keylength, newkeylen);

	rec_off = tree->node_size - (rec + 2) * 2;
	end_rec_off = tree->node_size - (parent->num_recs + 1) * 2;
	diff = newkeylen - fd->keylength;
	if (!diff)
		goto skip;
	if (diff > 0) {
		end_off = hfs_bnode_read_u16(parent, end_rec_off);
		if (end_rec_off - end_off < diff) {

			printk(KERN_DEBUG "splitting index node...\n");
			fd->bnode = parent;
			new_node = hfs_bnode_split(fd);
			if (IS_ERR(new_node))
				return PTR_ERR(new_node);
			parent = fd->bnode;
			rec = fd->record;
			rec_off = tree->node_size - (rec + 2) * 2;
			end_rec_off = tree->node_size - (parent->num_recs + 1) * 2;
		}
	}

	end_off = start_off = hfs_bnode_read_u16(parent, rec_off);
	hfs_bnode_write_u16(parent, rec_off, start_off + diff);
	start_off -= 4;	/* move previous cnid too */

	while (rec_off > end_rec_off) {
		rec_off -= 2;
		end_off = hfs_bnode_read_u16(parent, rec_off);
		hfs_bnode_write_u16(parent, rec_off, end_off + diff);
	}
	hfs_bnode_move(parent, start_off + diff, start_off,
		       end_off - start_off);
skip:
	hfs_bnode_copy(parent, fd->keyoffset, node, 14, newkeylen);
	if (!(tree->attributes & HFS_TREE_VARIDXKEYS))
		hfs_bnode_write_u8(parent, fd->keyoffset, newkeylen - 1);
	hfs_bnode_dump(parent);

	hfs_bnode_put(node);
	node = parent;

	if (new_node) {
		__be32 cnid;

		fd->bnode = hfs_bnode_find(tree, new_node->parent);
		/* create index key and entry */
		hfs_bnode_read_key(new_node, fd->search_key, 14);
		cnid = cpu_to_be32(new_node->this);

		__hfs_brec_find(fd->bnode, fd);
		hfs_brec_insert(fd, &cnid, sizeof(cnid));
		hfs_bnode_put(fd->bnode);
		hfs_bnode_put(new_node);

		if (!rec) {
			if (new_node == node)
				goto out;
			/* restore search_key */
			hfs_bnode_read_key(node, fd->search_key, 14);
		}
	}

	if (!rec && node->parent)
		goto again;
out:
	fd->bnode = node;
	return 0;
}

static int hfs_btree_inc_height(struct hfs_btree *tree)
{
	struct hfs_bnode *node, *new_node;
	struct hfs_bnode_desc node_desc;
	int key_size, rec;
	__be32 cnid;

	node = NULL;
	if (tree->root) {
		node = hfs_bnode_find(tree, tree->root);
		if (IS_ERR(node))
			return PTR_ERR(node);
	}
	new_node = hfs_bmap_alloc(tree);
	if (IS_ERR(new_node)) {
		hfs_bnode_put(node);
		return PTR_ERR(new_node);
	}

	tree->root = new_node->this;
	if (!tree->depth) {
		tree->leaf_head = tree->leaf_tail = new_node->this;
		new_node->type = HFS_NODE_LEAF;
		new_node->num_recs = 0;
	} else {
		new_node->type = HFS_NODE_INDEX;
		new_node->num_recs = 1;
	}
	new_node->parent = 0;
	new_node->next = 0;
	new_node->prev = 0;
	new_node->height = ++tree->depth;

	node_desc.next = cpu_to_be32(new_node->next);
	node_desc.prev = cpu_to_be32(new_node->prev);
	node_desc.type = new_node->type;
	node_desc.height = new_node->height;
	node_desc.num_recs = cpu_to_be16(new_node->num_recs);
	node_desc.reserved = 0;
	hfs_bnode_write(new_node, &node_desc, 0, sizeof(node_desc));

	rec = tree->node_size - 2;
	hfs_bnode_write_u16(new_node, rec, 14);

	if (node) {
		/* insert old root idx into new root */
		node->parent = tree->root;
		if (node->type == HFS_NODE_LEAF ||
		    tree->attributes & HFS_TREE_VARIDXKEYS)
			key_size = hfs_bnode_read_u8(node, 14) + 1;
		else
			key_size = tree->max_key_len + 1;
		hfs_bnode_copy(new_node, 14, node, 14, key_size);

		if (!(tree->attributes & HFS_TREE_VARIDXKEYS)) {
			key_size = tree->max_key_len + 1;
			hfs_bnode_write_u8(new_node, 14, tree->max_key_len);
		}
		key_size = (key_size + 1) & -2;
		cnid = cpu_to_be32(node->this);
		hfs_bnode_write(new_node, &cnid, 14 + key_size, 4);

		rec -= 2;
		hfs_bnode_write_u16(new_node, rec, 14 + key_size + 4);

		hfs_bnode_put(node);
	}
	hfs_bnode_put(new_node);
	mark_inode_dirty(tree->inode);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/brec.c */
/************************************************************/
/*
 *  linux/fs/hfs/btree.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handle opening/closing btree
 */

// #include <linux/pagemap.h>
// #include <linux/slab.h>
#include <linux/log2.h>
#include "../../inc/__fss.h"

// #include "btree.h"

/* Get a reference to a B*Tree and do some initial checks */
struct hfs_btree *hfs_btree_open(struct super_block *sb, u32 id, btree_keycmp keycmp)
{
	struct hfs_btree *tree;
	struct hfs_btree_header_rec *head;
	struct address_space *mapping;
	struct page *page;
	unsigned int size;

	tree = kzalloc(sizeof(*tree), GFP_KERNEL);
	if (!tree)
		return NULL;

	mutex_init(&tree->tree_lock);
	spin_lock_init(&tree->hash_lock);
	/* Set the correct compare function */
	tree->sb = sb;
	tree->cnid = id;
	tree->keycmp = keycmp;

	tree->inode = iget_locked(sb, id);
	if (!tree->inode)
		goto free_tree;
	BUG_ON(!(tree->inode->i_state & I_NEW));
	{
	struct hfs_mdb *mdb = HFS_SB(sb)->mdb;
	HFS_I(tree->inode)->flags = 0;
	mutex_init(&HFS_I(tree->inode)->extents_lock);
	switch (id) {
	case HFS_EXT_CNID:
		hfs_inode_read_fork(tree->inode, mdb->drXTExtRec, mdb->drXTFlSize,
				    mdb->drXTFlSize, be32_to_cpu(mdb->drXTClpSiz));
		if (HFS_I(tree->inode)->alloc_blocks >
					HFS_I(tree->inode)->first_blocks) {
			pr_err("invalid btree extent records\n");
			unlock_new_inode(tree->inode);
			goto free_inode;
		}

		tree->inode->i_mapping->a_ops = &hfs_btree_aops;
		break;
	case HFS_CAT_CNID:
		hfs_inode_read_fork(tree->inode, mdb->drCTExtRec, mdb->drCTFlSize,
				    mdb->drCTFlSize, be32_to_cpu(mdb->drCTClpSiz));

		if (!HFS_I(tree->inode)->first_blocks) {
			pr_err("invalid btree extent records (0 size)\n");
			unlock_new_inode(tree->inode);
			goto free_inode;
		}

		tree->inode->i_mapping->a_ops = &hfs_btree_aops;
		break;
	default:
		BUG();
	}
	}
	unlock_new_inode(tree->inode);

	mapping = tree->inode->i_mapping;
	page = read_mapping_page(mapping, 0, NULL);
	if (IS_ERR(page))
		goto free_inode;

	/* Load the header */
	head = (struct hfs_btree_header_rec *)(kmap(page) + sizeof(struct hfs_bnode_desc));
	tree->root = be32_to_cpu(head->root);
	tree->leaf_count = be32_to_cpu(head->leaf_count);
	tree->leaf_head = be32_to_cpu(head->leaf_head);
	tree->leaf_tail = be32_to_cpu(head->leaf_tail);
	tree->node_count = be32_to_cpu(head->node_count);
	tree->free_nodes = be32_to_cpu(head->free_nodes);
	tree->attributes = be32_to_cpu(head->attributes);
	tree->node_size = be16_to_cpu(head->node_size);
	tree->max_key_len = be16_to_cpu(head->max_key_len);
	tree->depth = be16_to_cpu(head->depth);

	size = tree->node_size;
	if (!is_power_of_2(size))
		goto fail_page;
	if (!tree->node_count)
		goto fail_page;
	switch (id) {
	case HFS_EXT_CNID:
		if (tree->max_key_len != HFS_MAX_EXT_KEYLEN) {
			pr_err("invalid extent max_key_len %d\n",
			       tree->max_key_len);
			goto fail_page;
		}
		break;
	case HFS_CAT_CNID:
		if (tree->max_key_len != HFS_MAX_CAT_KEYLEN) {
			pr_err("invalid catalog max_key_len %d\n",
			       tree->max_key_len);
			goto fail_page;
		}
		break;
	default:
		BUG();
	}

	tree->node_size_shift = ffs(size) - 1;
	tree->pages_per_bnode = (tree->node_size + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	kunmap(page);
	page_cache_release(page);
	return tree;

fail_page:
	page_cache_release(page);
free_inode:
	tree->inode->i_mapping->a_ops = &hfs_aops;
	iput(tree->inode);
free_tree:
	kfree(tree);
	return NULL;
}

/* Release resources used by a btree */
void hfs_btree_close(struct hfs_btree *tree)
{
	struct hfs_bnode *node;
	int i;

	if (!tree)
		return;

	for (i = 0; i < NODE_HASH_SIZE; i++) {
		while ((node = tree->node_hash[i])) {
			tree->node_hash[i] = node->next_hash;
			if (atomic_read(&node->refcnt))
				pr_err("node %d:%d still has %d user(s)!\n",
				       node->tree->cnid, node->this,
				       atomic_read(&node->refcnt));
			hfs_bnode_free(node);
			tree->node_hash_cnt--;
		}
	}
	iput(tree->inode);
	kfree(tree);
}

void hfs_btree_write(struct hfs_btree *tree)
{
	struct hfs_btree_header_rec *head;
	struct hfs_bnode *node;
	struct page *page;

	node = hfs_bnode_find(tree, 0);
	if (IS_ERR(node))
		/* panic? */
		return;
	/* Load the header */
	page = node->page[0];
	head = (struct hfs_btree_header_rec *)(kmap(page) + sizeof(struct hfs_bnode_desc));

	head->root = cpu_to_be32(tree->root);
	head->leaf_count = cpu_to_be32(tree->leaf_count);
	head->leaf_head = cpu_to_be32(tree->leaf_head);
	head->leaf_tail = cpu_to_be32(tree->leaf_tail);
	head->node_count = cpu_to_be32(tree->node_count);
	head->free_nodes = cpu_to_be32(tree->free_nodes);
	head->attributes = cpu_to_be32(tree->attributes);
	head->depth = cpu_to_be16(tree->depth);

	kunmap(page);
	set_page_dirty(page);
	hfs_bnode_put(node);
}

static struct hfs_bnode *hfs_bmap_new_bmap(struct hfs_bnode *prev, u32 idx)
{
	struct hfs_btree *tree = prev->tree;
	struct hfs_bnode *node;
	struct hfs_bnode_desc desc;
	__be32 cnid;

	node = hfs_bnode_create(tree, idx);
	if (IS_ERR(node))
		return node;

	if (!tree->free_nodes)
		panic("FIXME!!!");
	tree->free_nodes--;
	prev->next = idx;
	cnid = cpu_to_be32(idx);
	hfs_bnode_write(prev, &cnid, offsetof(struct hfs_bnode_desc, next), 4);

	node->type = HFS_NODE_MAP;
	node->num_recs = 1;
	hfs_bnode_clear(node, 0, tree->node_size);
	desc.next = 0;
	desc.prev = 0;
	desc.type = HFS_NODE_MAP;
	desc.height = 0;
	desc.num_recs = cpu_to_be16(1);
	desc.reserved = 0;
	hfs_bnode_write(node, &desc, 0, sizeof(desc));
	hfs_bnode_write_u16(node, 14, 0x8000);
	hfs_bnode_write_u16(node, tree->node_size - 2, 14);
	hfs_bnode_write_u16(node, tree->node_size - 4, tree->node_size - 6);

	return node;
}

struct hfs_bnode *hfs_bmap_alloc(struct hfs_btree *tree)
{
	struct hfs_bnode *node, *next_node;
	struct page **pagep;
	u32 nidx, idx;
	unsigned off;
	u16 off16;
	u16 len;
	u8 *data, byte, m;
	int i;

	while (!tree->free_nodes) {
		struct inode *inode = tree->inode;
		u32 count;
		int res;

		res = hfs_extend_file(inode);
		if (res)
			return ERR_PTR(res);
		HFS_I(inode)->phys_size = inode->i_size =
				(loff_t)HFS_I(inode)->alloc_blocks *
				HFS_SB(tree->sb)->alloc_blksz;
		HFS_I(inode)->fs_blocks = inode->i_size >>
					  tree->sb->s_blocksize_bits;
		inode_set_bytes(inode, inode->i_size);
		count = inode->i_size >> tree->node_size_shift;
		tree->free_nodes = count - tree->node_count;
		tree->node_count = count;
	}

	nidx = 0;
	node = hfs_bnode_find(tree, nidx);
	if (IS_ERR(node))
		return node;
	len = hfs_brec_lenoff(node, 2, &off16);
	off = off16;

	off += node->page_offset;
	pagep = node->page + (off >> PAGE_CACHE_SHIFT);
	data = kmap(*pagep);
	off &= ~PAGE_CACHE_MASK;
	idx = 0;

	for (;;) {
		while (len) {
			byte = data[off];
			if (byte != 0xff) {
				for (m = 0x80, i = 0; i < 8; m >>= 1, i++) {
					if (!(byte & m)) {
						idx += i;
						data[off] |= m;
						set_page_dirty(*pagep);
						kunmap(*pagep);
						tree->free_nodes--;
						mark_inode_dirty(tree->inode);
						hfs_bnode_put(node);
						return hfs_bnode_create(tree, idx);
					}
				}
			}
			if (++off >= PAGE_CACHE_SIZE) {
				kunmap(*pagep);
				data = kmap(*++pagep);
				off = 0;
			}
			idx += 8;
			len--;
		}
		kunmap(*pagep);
		nidx = node->next;
		if (!nidx) {
			printk(KERN_DEBUG "create new bmap node...\n");
			next_node = hfs_bmap_new_bmap(node, idx);
		} else
			next_node = hfs_bnode_find(tree, nidx);
		hfs_bnode_put(node);
		if (IS_ERR(next_node))
			return next_node;
		node = next_node;

		len = hfs_brec_lenoff(node, 0, &off16);
		off = off16;
		off += node->page_offset;
		pagep = node->page + (off >> PAGE_CACHE_SHIFT);
		data = kmap(*pagep);
		off &= ~PAGE_CACHE_MASK;
	}
}

void hfs_bmap_free(struct hfs_bnode *node)
{
	struct hfs_btree *tree;
	struct page *page;
	u16 off, len;
	u32 nidx;
	u8 *data, byte, m;

	hfs_dbg(BNODE_MOD, "btree_free_node: %u\n", node->this);
	tree = node->tree;
	nidx = node->this;
	node = hfs_bnode_find(tree, 0);
	if (IS_ERR(node))
		return;
	len = hfs_brec_lenoff(node, 2, &off);
	while (nidx >= len * 8) {
		u32 i;

		nidx -= len * 8;
		i = node->next;
		hfs_bnode_put(node);
		if (!i) {
			/* panic */;
			pr_crit("unable to free bnode %u. bmap not found!\n",
				node->this);
			return;
		}
		node = hfs_bnode_find(tree, i);
		if (IS_ERR(node))
			return;
		if (node->type != HFS_NODE_MAP) {
			/* panic */;
			pr_crit("invalid bmap found! (%u,%d)\n",
				node->this, node->type);
			hfs_bnode_put(node);
			return;
		}
		len = hfs_brec_lenoff(node, 0, &off);
	}
	off += node->page_offset + nidx / 8;
	page = node->page[off >> PAGE_CACHE_SHIFT];
	data = kmap(page);
	off &= ~PAGE_CACHE_MASK;
	m = 1 << (~nidx & 7);
	byte = data[off];
	if (!(byte & m)) {
		pr_crit("trying to free free bnode %u(%d)\n",
			node->this, node->type);
		kunmap(page);
		hfs_bnode_put(node);
		return;
	}
	data[off] = byte & ~m;
	set_page_dirty(page);
	kunmap(page);
	hfs_bnode_put(node);
	tree->free_nodes++;
	mark_inode_dirty(tree->inode);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/btree.c */
/************************************************************/
/*
 *  linux/fs/hfs/catalog.c
 *
 * Copyright (C) 1995-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains the functions related to the catalog B-tree.
 *
 * Cache code shamelessly stolen from
 *     linux/fs/inode.c Copyright (C) 1991, 1992  Linus Torvalds
 *     re-shamelessly stolen Copyright (C) 1997 Linus Torvalds
 */

// #include "hfs_fs.h"
// #include "btree.h"

/*
 * hfs_cat_build_key()
 *
 * Given the ID of the parent and the name build a search key.
 */
void hfs_cat_build_key(struct super_block *sb, btree_key *key, u32 parent, struct qstr *name)
{
	key->cat.reserved = 0;
	key->cat.ParID = cpu_to_be32(parent);
	if (name) {
		hfs_asc2mac(sb, &key->cat.CName, name);
		key->key_len = 6 + key->cat.CName.len;
	} else {
		memset(&key->cat.CName, 0, sizeof(struct hfs_name));
		key->key_len = 6;
	}
}

static int hfs_cat_build_record(hfs_cat_rec *rec, u32 cnid, struct inode *inode)
{
	__be32 mtime = hfs_mtime();

	memset(rec, 0, sizeof(*rec));
	if (S_ISDIR(inode->i_mode)) {
		rec->type = HFS_CDR_DIR;
		rec->dir.DirID = cpu_to_be32(cnid);
		rec->dir.CrDat = mtime;
		rec->dir.MdDat = mtime;
		rec->dir.BkDat = 0;
		rec->dir.UsrInfo.frView = cpu_to_be16(0xff);
		return sizeof(struct hfs_cat_dir);
	} else {
		/* init some fields for the file record */
		rec->type = HFS_CDR_FIL;
		rec->file.Flags = HFS_FIL_USED | HFS_FIL_THD;
		if (!(inode->i_mode & S_IWUSR))
			rec->file.Flags |= HFS_FIL_LOCK;
		rec->file.FlNum = cpu_to_be32(cnid);
		rec->file.CrDat = mtime;
		rec->file.MdDat = mtime;
		rec->file.BkDat = 0;
		rec->file.UsrWds.fdType = HFS_SB(inode->i_sb)->s_type;
		rec->file.UsrWds.fdCreator = HFS_SB(inode->i_sb)->s_creator;
		return sizeof(struct hfs_cat_file);
	}
}

static int hfs_cat_build_thread(struct super_block *sb,
				hfs_cat_rec *rec, int type,
				u32 parentid, struct qstr *name)
{
	rec->type = type;
	memset(rec->thread.reserved, 0, sizeof(rec->thread.reserved));
	rec->thread.ParID = cpu_to_be32(parentid);
	hfs_asc2mac(sb, &rec->thread.CName, name);
	return sizeof(struct hfs_cat_thread);
}

/*
 * create_entry()
 *
 * Add a new file or directory to the catalog B-tree and
 * return a (struct hfs_cat_entry) for it in '*result'.
 */
int hfs_cat_create(u32 cnid, struct inode *dir, struct qstr *str, struct inode *inode)
{
	struct hfs_find_data fd;
	struct super_block *sb;
	union hfs_cat_rec entry;
	int entry_size;
	int err;

	hfs_dbg(CAT_MOD, "create_cat: %s,%u(%d)\n",
		str->name, cnid, inode->i_nlink);
	if (dir->i_size >= HFS_MAX_VALENCE)
		return -ENOSPC;

	sb = dir->i_sb;
	err = hfs_find_init(HFS_SB(sb)->cat_tree, &fd);
	if (err)
		return err;

	hfs_cat_build_key(sb, fd.search_key, cnid, NULL);
	entry_size = hfs_cat_build_thread(sb, &entry, S_ISDIR(inode->i_mode) ?
			HFS_CDR_THD : HFS_CDR_FTH,
			dir->i_ino, str);
	err = hfs_brec_find(&fd);
	if (err != -ENOENT) {
		if (!err)
			err = -EEXIST;
		goto err2;
	}
	err = hfs_brec_insert(&fd, &entry, entry_size);
	if (err)
		goto err2;

	hfs_cat_build_key(sb, fd.search_key, dir->i_ino, str);
	entry_size = hfs_cat_build_record(&entry, cnid, inode);
	err = hfs_brec_find(&fd);
	if (err != -ENOENT) {
		/* panic? */
		if (!err)
			err = -EEXIST;
		goto err1;
	}
	err = hfs_brec_insert(&fd, &entry, entry_size);
	if (err)
		goto err1;

	dir->i_size++;
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(dir);
	hfs_find_exit(&fd);
	return 0;

err1:
	hfs_cat_build_key(sb, fd.search_key, cnid, NULL);
	if (!hfs_brec_find(&fd))
		hfs_brec_remove(&fd);
err2:
	hfs_find_exit(&fd);
	return err;
}

/*
 * hfs_cat_compare()
 *
 * Description:
 *   This is the comparison function used for the catalog B-tree.  In
 *   comparing catalog B-tree entries, the parent id is the most
 *   significant field (compared as unsigned ints).  The name field is
 *   the least significant (compared in "Macintosh lexical order",
 *   see hfs_strcmp() in string.c)
 * Input Variable(s):
 *   struct hfs_cat_key *key1: pointer to the first key to compare
 *   struct hfs_cat_key *key2: pointer to the second key to compare
 * Output Variable(s):
 *   NONE
 * Returns:
 *   int: negative if key1<key2, positive if key1>key2, and 0 if key1==key2
 * Preconditions:
 *   key1 and key2 point to "valid" (struct hfs_cat_key)s.
 * Postconditions:
 *   This function has no side-effects
 */
int hfs_cat_keycmp(const btree_key *key1, const btree_key *key2)
{
	__be32 k1p, k2p;

	k1p = key1->cat.ParID;
	k2p = key2->cat.ParID;

	if (k1p != k2p)
		return be32_to_cpu(k1p) < be32_to_cpu(k2p) ? -1 : 1;

	return hfs_strcmp(key1->cat.CName.name, key1->cat.CName.len,
			  key2->cat.CName.name, key2->cat.CName.len);
}

/* Try to get a catalog entry for given catalog id */
// move to read_super???
int hfs_cat_find_brec(struct super_block *sb, u32 cnid,
		      struct hfs_find_data *fd)
{
	hfs_cat_rec rec;
	int res, len, type;

	hfs_cat_build_key(sb, fd->search_key, cnid, NULL);
	res = hfs_brec_read(fd, &rec, sizeof(rec));
	if (res)
		return res;

	type = rec.type;
	if (type != HFS_CDR_THD && type != HFS_CDR_FTH) {
		pr_err("found bad thread record in catalog\n");
		return -EIO;
	}

	fd->search_key->cat.ParID = rec.thread.ParID;
	len = fd->search_key->cat.CName.len = rec.thread.CName.len;
	if (len > HFS_NAMELEN) {
		pr_err("bad catalog namelength\n");
		return -EIO;
	}
	memcpy(fd->search_key->cat.CName.name, rec.thread.CName.name, len);
	return hfs_brec_find(fd);
}


/*
 * hfs_cat_delete()
 *
 * Delete the indicated file or directory.
 * The associated thread is also removed unless ('with_thread'==0).
 */
int hfs_cat_delete(u32 cnid, struct inode *dir, struct qstr *str)
{
	struct super_block *sb;
	struct hfs_find_data fd;
	struct list_head *pos;
	int res, type;

	hfs_dbg(CAT_MOD, "delete_cat: %s,%u\n", str ? str->name : NULL, cnid);
	sb = dir->i_sb;
	res = hfs_find_init(HFS_SB(sb)->cat_tree, &fd);
	if (res)
		return res;

	hfs_cat_build_key(sb, fd.search_key, dir->i_ino, str);
	res = hfs_brec_find(&fd);
	if (res)
		goto out;

	type = hfs_bnode_read_u8(fd.bnode, fd.entryoffset);
	if (type == HFS_CDR_FIL) {
		struct hfs_cat_file file;
		hfs_bnode_read(fd.bnode, &file, fd.entryoffset, sizeof(file));
		if (be32_to_cpu(file.FlNum) == cnid) {
#if 0
			hfs_free_fork(sb, &file, HFS_FK_DATA);
#endif
			hfs_free_fork(sb, &file, HFS_FK_RSRC);
		}
	}

	list_for_each(pos, &HFS_I(dir)->open_dir_list) {
		struct hfs_readdir_data *rd =
			list_entry(pos, struct hfs_readdir_data, list);
		if (fd.tree->keycmp(fd.search_key, (void *)&rd->key) < 0)
			rd->file->f_pos--;
	}

	res = hfs_brec_remove(&fd);
	if (res)
		goto out;

	hfs_cat_build_key(sb, fd.search_key, cnid, NULL);
	res = hfs_brec_find(&fd);
	if (!res) {
		res = hfs_brec_remove(&fd);
		if (res)
			goto out;
	}

	dir->i_size--;
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(dir);
	res = 0;
out:
	hfs_find_exit(&fd);

	return res;
}

/*
 * hfs_cat_move()
 *
 * Rename a file or directory, possibly to a new directory.
 * If the destination exists it is removed and a
 * (struct hfs_cat_entry) for it is returned in '*result'.
 */
int hfs_cat_move(u32 cnid, struct inode *src_dir, struct qstr *src_name,
		 struct inode *dst_dir, struct qstr *dst_name)
{
	struct super_block *sb;
	struct hfs_find_data src_fd, dst_fd;
	union hfs_cat_rec entry;
	int entry_size, type;
	int err;

	hfs_dbg(CAT_MOD, "rename_cat: %u - %lu,%s - %lu,%s\n",
		cnid, src_dir->i_ino, src_name->name,
		dst_dir->i_ino, dst_name->name);
	sb = src_dir->i_sb;
	err = hfs_find_init(HFS_SB(sb)->cat_tree, &src_fd);
	if (err)
		return err;
	dst_fd = src_fd;

	/* find the old dir entry and read the data */
	hfs_cat_build_key(sb, src_fd.search_key, src_dir->i_ino, src_name);
	err = hfs_brec_find(&src_fd);
	if (err)
		goto out;
	if (src_fd.entrylength > sizeof(entry) || src_fd.entrylength < 0) {
		err = -EIO;
		goto out;
	}

	hfs_bnode_read(src_fd.bnode, &entry, src_fd.entryoffset,
			    src_fd.entrylength);

	/* create new dir entry with the data from the old entry */
	hfs_cat_build_key(sb, dst_fd.search_key, dst_dir->i_ino, dst_name);
	err = hfs_brec_find(&dst_fd);
	if (err != -ENOENT) {
		if (!err)
			err = -EEXIST;
		goto out;
	}

	err = hfs_brec_insert(&dst_fd, &entry, src_fd.entrylength);
	if (err)
		goto out;
	dst_dir->i_size++;
	dst_dir->i_mtime = dst_dir->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(dst_dir);

	/* finally remove the old entry */
	hfs_cat_build_key(sb, src_fd.search_key, src_dir->i_ino, src_name);
	err = hfs_brec_find(&src_fd);
	if (err)
		goto out;
	err = hfs_brec_remove(&src_fd);
	if (err)
		goto out;
	src_dir->i_size--;
	src_dir->i_mtime = src_dir->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(src_dir);

	type = entry.type;
	if (type == HFS_CDR_FIL && !(entry.file.Flags & HFS_FIL_THD))
		goto out;

	/* remove old thread entry */
	hfs_cat_build_key(sb, src_fd.search_key, cnid, NULL);
	err = hfs_brec_find(&src_fd);
	if (err)
		goto out;
	err = hfs_brec_remove(&src_fd);
	if (err)
		goto out;

	/* create new thread entry */
	hfs_cat_build_key(sb, dst_fd.search_key, cnid, NULL);
	entry_size = hfs_cat_build_thread(sb, &entry, type == HFS_CDR_FIL ? HFS_CDR_FTH : HFS_CDR_THD,
					dst_dir->i_ino, dst_name);
	err = hfs_brec_find(&dst_fd);
	if (err != -ENOENT) {
		if (!err)
			err = -EEXIST;
		goto out;
	}
	err = hfs_brec_insert(&dst_fd, &entry, entry_size);
out:
	hfs_bnode_put(dst_fd.bnode);
	hfs_find_exit(&src_fd);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/catalog.c */
/************************************************************/
/*
 *  linux/fs/hfs/dir.c
 *
 * Copyright (C) 1995-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains directory-related functions independent of which
 * scheme is being used to represent forks.
 *
 * Based on the minix file system code, (C) 1991, 1992 by Linus Torvalds
 */

// #include "hfs_fs.h"
// #include "btree.h"

/*
 * hfs_lookup()
 */
static struct dentry *hfs_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	hfs_cat_rec rec;
	struct hfs_find_data fd;
	struct inode *inode = NULL;
	int res;

	res = hfs_find_init(HFS_SB(dir->i_sb)->cat_tree, &fd);
	if (res)
		return ERR_PTR(res);
	hfs_cat_build_key(dir->i_sb, fd.search_key, dir->i_ino, &dentry->d_name);
	res = hfs_brec_read(&fd, &rec, sizeof(rec));
	if (res) {
		hfs_find_exit(&fd);
		if (res == -ENOENT) {
			/* No such entry */
			inode = NULL;
			goto done;
		}
		return ERR_PTR(res);
	}
	inode = hfs_iget(dir->i_sb, &fd.search_key->cat, &rec);
	hfs_find_exit(&fd);
	if (!inode)
		return ERR_PTR(-EACCES);
done:
	d_add(dentry, inode);
	return NULL;
}

/*
 * hfs_readdir
 */
static int hfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	int len, err;
	char strbuf[HFS_MAX_NAMELEN];
	union hfs_cat_rec entry;
	struct hfs_find_data fd;
	struct hfs_readdir_data *rd;
	u16 type;

	if (ctx->pos >= inode->i_size)
		return 0;

	err = hfs_find_init(HFS_SB(sb)->cat_tree, &fd);
	if (err)
		return err;
	hfs_cat_build_key(sb, fd.search_key, inode->i_ino, NULL);
	err = hfs_brec_find(&fd);
	if (err)
		goto out;

	if (ctx->pos == 0) {
		/* This is completely artificial... */
		if (!dir_emit_dot(file, ctx))
			goto out;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		if (fd.entrylength > sizeof(entry) || fd.entrylength < 0) {
			err = -EIO;
			goto out;
		}

		hfs_bnode_read(fd.bnode, &entry, fd.entryoffset, fd.entrylength);
		if (entry.type != HFS_CDR_THD) {
			pr_err("bad catalog folder thread\n");
			err = -EIO;
			goto out;
		}
		//if (fd.entrylength < HFS_MIN_THREAD_SZ) {
		//	pr_err("truncated catalog thread\n");
		//	err = -EIO;
		//	goto out;
		//}
		if (!dir_emit(ctx, "..", 2,
			    be32_to_cpu(entry.thread.ParID), DT_DIR))
			goto out;
		ctx->pos = 2;
	}
	if (ctx->pos >= inode->i_size)
		goto out;
	err = hfs_brec_goto(&fd, ctx->pos - 1);
	if (err)
		goto out;

	for (;;) {
		if (be32_to_cpu(fd.key->cat.ParID) != inode->i_ino) {
			pr_err("walked past end of dir\n");
			err = -EIO;
			goto out;
		}

		if (fd.entrylength > sizeof(entry) || fd.entrylength < 0) {
			err = -EIO;
			goto out;
		}

		hfs_bnode_read(fd.bnode, &entry, fd.entryoffset, fd.entrylength);
		type = entry.type;
		len = hfs_mac2asc(sb, strbuf, &fd.key->cat.CName);
		if (type == HFS_CDR_DIR) {
			if (fd.entrylength < sizeof(struct hfs_cat_dir)) {
				pr_err("small dir entry\n");
				err = -EIO;
				goto out;
			}
			if (!dir_emit(ctx, strbuf, len,
				    be32_to_cpu(entry.dir.DirID), DT_DIR))
				break;
		} else if (type == HFS_CDR_FIL) {
			if (fd.entrylength < sizeof(struct hfs_cat_file)) {
				pr_err("small file entry\n");
				err = -EIO;
				goto out;
			}
			if (!dir_emit(ctx, strbuf, len,
				    be32_to_cpu(entry.file.FlNum), DT_REG))
				break;
		} else {
			pr_err("bad catalog entry type %d\n", type);
			err = -EIO;
			goto out;
		}
		ctx->pos++;
		if (ctx->pos >= inode->i_size)
			goto out;
		err = hfs_brec_goto(&fd, 1);
		if (err)
			goto out;
	}
	rd = file->private_data;
	if (!rd) {
		rd = kmalloc(sizeof(struct hfs_readdir_data), GFP_KERNEL);
		if (!rd) {
			err = -ENOMEM;
			goto out;
		}
		file->private_data = rd;
		rd->file = file;
		list_add(&rd->list, &HFS_I(inode)->open_dir_list);
	}
	memcpy(&rd->key, &fd.key, sizeof(struct hfs_cat_key));
out:
	hfs_find_exit(&fd);
	return err;
}

static int hfs_dir_release(struct inode *inode, struct file *file)
{
	struct hfs_readdir_data *rd = file->private_data;
	if (rd) {
		mutex_lock(&inode->i_mutex);
		list_del(&rd->list);
		mutex_unlock(&inode->i_mutex);
		kfree(rd);
	}
	return 0;
}

/*
 * hfs_create()
 *
 * This is the create() entry in the inode_operations structure for
 * regular HFS directories.  The purpose is to create a new file in
 * a directory and return a corresponding inode, given the inode for
 * the directory and the name (and its length) of the new file.
 */
static int hfs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		      bool excl)
{
	struct inode *inode;
	int res;

	inode = hfs_new_inode(dir, &dentry->d_name, mode);
	if (!inode)
		return -ENOSPC;

	res = hfs_cat_create(inode->i_ino, dir, &dentry->d_name, inode);
	if (res) {
		clear_nlink(inode);
		hfs_delete_inode(inode);
		iput(inode);
		return res;
	}
	d_instantiate(dentry, inode);
	mark_inode_dirty(inode);
	return 0;
}

/*
 * hfs_mkdir()
 *
 * This is the mkdir() entry in the inode_operations structure for
 * regular HFS directories.  The purpose is to create a new directory
 * in a directory, given the inode for the parent directory and the
 * name (and its length) of the new directory.
 */
static int hfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	int res;

	inode = hfs_new_inode(dir, &dentry->d_name, S_IFDIR | mode);
	if (!inode)
		return -ENOSPC;

	res = hfs_cat_create(inode->i_ino, dir, &dentry->d_name, inode);
	if (res) {
		clear_nlink(inode);
		hfs_delete_inode(inode);
		iput(inode);
		return res;
	}
	d_instantiate(dentry, inode);
	mark_inode_dirty(inode);
	return 0;
}

/*
 * hfs_remove()
 *
 * This serves as both unlink() and rmdir() in the inode_operations
 * structure for regular HFS directories.  The purpose is to delete
 * an existing child, given the inode for the parent directory and
 * the name (and its length) of the existing directory.
 *
 * HFS does not have hardlinks, so both rmdir and unlink set the
 * link count to 0.  The only difference is the emptiness check.
 */
static int hfs_remove(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int res;

	if (S_ISDIR(inode->i_mode) && inode->i_size != 2)
		return -ENOTEMPTY;
	res = hfs_cat_delete(inode->i_ino, dir, &dentry->d_name);
	if (res)
		return res;
	clear_nlink(inode);
	inode->i_ctime = CURRENT_TIME_SEC;
	hfs_delete_inode(inode);
	mark_inode_dirty(inode);
	return 0;
}

/*
 * hfs_rename()
 *
 * This is the rename() entry in the inode_operations structure for
 * regular HFS directories.  The purpose is to rename an existing
 * file or directory, given the inode for the current directory and
 * the name (and its length) of the existing file/directory and the
 * inode for the new directory and the name (and its length) of the
 * new file/directory.
 * XXX: how do you handle must_be dir?
 */
static int hfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	int res;

	/* Unlink destination if it already exists */
	if (new_dentry->d_inode) {
		res = hfs_remove(new_dir, new_dentry);
		if (res)
			return res;
	}

	res = hfs_cat_move(old_dentry->d_inode->i_ino,
			   old_dir, &old_dentry->d_name,
			   new_dir, &new_dentry->d_name);
	if (!res)
		hfs_cat_build_key(old_dir->i_sb,
				  (btree_key *)&HFS_I(old_dentry->d_inode)->cat_key,
				  new_dir->i_ino, &new_dentry->d_name);
	return res;
}

const struct file_operations hfs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= hfs_readdir,
	.llseek		= generic_file_llseek,
	.release	= hfs_dir_release,
};

const struct inode_operations hfs_dir_inode_operations = {
	.create		= hfs_create,
	.lookup		= hfs_lookup,
	.unlink		= hfs_remove,
	.mkdir		= hfs_mkdir,
	.rmdir		= hfs_remove,
	.rename		= hfs_rename,
	.setattr	= hfs_inode_setattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/dir.c */
/************************************************************/
/*
 *  linux/fs/hfs/extent.c
 *
 * Copyright (C) 1995-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains the functions related to the extents B-tree.
 */

// #include <linux/pagemap.h>

// #include "hfs_fs.h"
// #include "btree.h"

/*================ File-local functions ================*/

/*
 * build_key
 */
static void hfs_ext_build_key(hfs_btree_key *key, u32 cnid, u16 block, u8 type)
{
	key->key_len = 7;
	key->ext.FkType = type;
	key->ext.FNum = cpu_to_be32(cnid);
	key->ext.FABN = cpu_to_be16(block);
}

/*
 * hfs_ext_compare()
 *
 * Description:
 *   This is the comparison function used for the extents B-tree.  In
 *   comparing extent B-tree entries, the file id is the most
 *   significant field (compared as unsigned ints); the fork type is
 *   the second most significant field (compared as unsigned chars);
 *   and the allocation block number field is the least significant
 *   (compared as unsigned ints).
 * Input Variable(s):
 *   struct hfs_ext_key *key1: pointer to the first key to compare
 *   struct hfs_ext_key *key2: pointer to the second key to compare
 * Output Variable(s):
 *   NONE
 * Returns:
 *   int: negative if key1<key2, positive if key1>key2, and 0 if key1==key2
 * Preconditions:
 *   key1 and key2 point to "valid" (struct hfs_ext_key)s.
 * Postconditions:
 *   This function has no side-effects */
int hfs_ext_keycmp(const btree_key *key1, const btree_key *key2)
{
	__be32 fnum1, fnum2;
	__be16 block1, block2;

	fnum1 = key1->ext.FNum;
	fnum2 = key2->ext.FNum;
	if (fnum1 != fnum2)
		return be32_to_cpu(fnum1) < be32_to_cpu(fnum2) ? -1 : 1;
	if (key1->ext.FkType != key2->ext.FkType)
		return key1->ext.FkType < key2->ext.FkType ? -1 : 1;

	block1 = key1->ext.FABN;
	block2 = key2->ext.FABN;
	if (block1 == block2)
		return 0;
	return be16_to_cpu(block1) < be16_to_cpu(block2) ? -1 : 1;
}

/*
 * hfs_ext_find_block
 *
 * Find a block within an extent record
 */
static u16 hfs_ext_find_block(struct hfs_extent *ext, u16 off)
{
	int i;
	u16 count;

	for (i = 0; i < 3; ext++, i++) {
		count = be16_to_cpu(ext->count);
		if (off < count)
			return be16_to_cpu(ext->block) + off;
		off -= count;
	}
	/* panic? */
	return 0;
}

static int hfs_ext_block_count(struct hfs_extent *ext)
{
	int i;
	u16 count = 0;

	for (i = 0; i < 3; ext++, i++)
		count += be16_to_cpu(ext->count);
	return count;
}

static u16 hfs_ext_lastblock(struct hfs_extent *ext)
{
	int i;

	ext += 2;
	for (i = 0; i < 2; ext--, i++)
		if (ext->count)
			break;
	return be16_to_cpu(ext->block) + be16_to_cpu(ext->count);
}

static int __hfs_ext_write_extent(struct inode *inode, struct hfs_find_data *fd)
{
	int res;

	hfs_ext_build_key(fd->search_key, inode->i_ino, HFS_I(inode)->cached_start,
			  HFS_IS_RSRC(inode) ?  HFS_FK_RSRC : HFS_FK_DATA);
	res = hfs_brec_find(fd);
	if (HFS_I(inode)->flags & HFS_FLG_EXT_NEW) {
		if (res != -ENOENT)
			return res;
		hfs_brec_insert(fd, HFS_I(inode)->cached_extents, sizeof(hfs_extent_rec));
		HFS_I(inode)->flags &= ~(HFS_FLG_EXT_DIRTY|HFS_FLG_EXT_NEW);
	} else {
		if (res)
			return res;
		hfs_bnode_write(fd->bnode, HFS_I(inode)->cached_extents, fd->entryoffset, fd->entrylength);
		HFS_I(inode)->flags &= ~HFS_FLG_EXT_DIRTY;
	}
	return 0;
}

int hfs_ext_write_extent(struct inode *inode)
{
	struct hfs_find_data fd;
	int res = 0;

	if (HFS_I(inode)->flags & HFS_FLG_EXT_DIRTY) {
		res = hfs_find_init(HFS_SB(inode->i_sb)->ext_tree, &fd);
		if (res)
			return res;
		res = __hfs_ext_write_extent(inode, &fd);
		hfs_find_exit(&fd);
	}
	return res;
}

static inline int __hfs_ext_read_extent(struct hfs_find_data *fd, struct hfs_extent *extent,
					u32 cnid, u32 block, u8 type)
{
	int res;

	hfs_ext_build_key(fd->search_key, cnid, block, type);
	fd->key->ext.FNum = 0;
	res = hfs_brec_find(fd);
	if (res && res != -ENOENT)
		return res;
	if (fd->key->ext.FNum != fd->search_key->ext.FNum ||
	    fd->key->ext.FkType != fd->search_key->ext.FkType)
		return -ENOENT;
	if (fd->entrylength != sizeof(hfs_extent_rec))
		return -EIO;
	hfs_bnode_read(fd->bnode, extent, fd->entryoffset, sizeof(hfs_extent_rec));
	return 0;
}

static inline int __hfs_ext_cache_extent(struct hfs_find_data *fd, struct inode *inode, u32 block)
{
	int res;

	if (HFS_I(inode)->flags & HFS_FLG_EXT_DIRTY) {
		res = __hfs_ext_write_extent(inode, fd);
		if (res)
			return res;
	}

	res = __hfs_ext_read_extent(fd, HFS_I(inode)->cached_extents, inode->i_ino,
				    block, HFS_IS_RSRC(inode) ? HFS_FK_RSRC : HFS_FK_DATA);
	if (!res) {
		HFS_I(inode)->cached_start = be16_to_cpu(fd->key->ext.FABN);
		HFS_I(inode)->cached_blocks = hfs_ext_block_count(HFS_I(inode)->cached_extents);
	} else {
		HFS_I(inode)->cached_start = HFS_I(inode)->cached_blocks = 0;
		HFS_I(inode)->flags &= ~(HFS_FLG_EXT_DIRTY|HFS_FLG_EXT_NEW);
	}
	return res;
}

static int hfs_ext_read_extent(struct inode *inode, u16 block)
{
	struct hfs_find_data fd;
	int res;

	if (block >= HFS_I(inode)->cached_start &&
	    block < HFS_I(inode)->cached_start + HFS_I(inode)->cached_blocks)
		return 0;

	res = hfs_find_init(HFS_SB(inode->i_sb)->ext_tree, &fd);
	if (!res) {
		res = __hfs_ext_cache_extent(&fd, inode, block);
		hfs_find_exit(&fd);
	}
	return res;
}

static void hfs_dump_extent(struct hfs_extent *extent)
{
	int i;

	hfs_dbg(EXTENT, "   ");
	for (i = 0; i < 3; i++)
		hfs_dbg_cont(EXTENT, " %u:%u",
			     be16_to_cpu(extent[i].block),
			     be16_to_cpu(extent[i].count));
	hfs_dbg_cont(EXTENT, "\n");
}

static int hfs_add_extent(struct hfs_extent *extent, u16 offset,
			  u16 alloc_block, u16 block_count)
{
	u16 count, start;
	int i;

	hfs_dump_extent(extent);
	for (i = 0; i < 3; extent++, i++) {
		count = be16_to_cpu(extent->count);
		if (offset == count) {
			start = be16_to_cpu(extent->block);
			if (alloc_block != start + count) {
				if (++i >= 3)
					return -ENOSPC;
				extent++;
				extent->block = cpu_to_be16(alloc_block);
			} else
				block_count += count;
			extent->count = cpu_to_be16(block_count);
			return 0;
		} else if (offset < count)
			break;
		offset -= count;
	}
	/* panic? */
	return -EIO;
}

static int hfs_free_extents(struct super_block *sb, struct hfs_extent *extent,
			    u16 offset, u16 block_nr)
{
	u16 count, start;
	int i;

	hfs_dump_extent(extent);
	for (i = 0; i < 3; extent++, i++) {
		count = be16_to_cpu(extent->count);
		if (offset == count)
			goto found;
		else if (offset < count)
			break;
		offset -= count;
	}
	/* panic? */
	return -EIO;
found:
	for (;;) {
		start = be16_to_cpu(extent->block);
		if (count <= block_nr) {
			hfs_clear_vbm_bits(sb, start, count);
			extent->block = 0;
			extent->count = 0;
			block_nr -= count;
		} else {
			count -= block_nr;
			hfs_clear_vbm_bits(sb, start + count, block_nr);
			extent->count = cpu_to_be16(count);
			block_nr = 0;
		}
		if (!block_nr || !i)
			return 0;
		i--;
		extent--;
		count = be16_to_cpu(extent->count);
	}
}

int hfs_free_fork(struct super_block *sb, struct hfs_cat_file *file, int type)
{
	struct hfs_find_data fd;
	u32 total_blocks, blocks, start;
	u32 cnid = be32_to_cpu(file->FlNum);
	struct hfs_extent *extent;
	int res, i;

	if (type == HFS_FK_DATA) {
		total_blocks = be32_to_cpu(file->PyLen);
		extent = file->ExtRec;
	} else {
		total_blocks = be32_to_cpu(file->RPyLen);
		extent = file->RExtRec;
	}
	total_blocks /= HFS_SB(sb)->alloc_blksz;
	if (!total_blocks)
		return 0;

	blocks = 0;
	for (i = 0; i < 3; extent++, i++)
		blocks += be16_to_cpu(extent[i].count);

	res = hfs_free_extents(sb, extent, blocks, blocks);
	if (res)
		return res;
	if (total_blocks == blocks)
		return 0;

	res = hfs_find_init(HFS_SB(sb)->ext_tree, &fd);
	if (res)
		return res;
	do {
		res = __hfs_ext_read_extent(&fd, extent, cnid, total_blocks, type);
		if (res)
			break;
		start = be16_to_cpu(fd.key->ext.FABN);
		hfs_free_extents(sb, extent, total_blocks - start, total_blocks);
		hfs_brec_remove(&fd);
		total_blocks = start;
	} while (total_blocks > blocks);
	hfs_find_exit(&fd);

	return res;
}

/*
 * hfs_get_block
 */
int hfs_get_block(struct inode *inode, sector_t block,
		  struct buffer_head *bh_result, int create)
{
	struct super_block *sb;
	u16 dblock, ablock;
	int res;

	sb = inode->i_sb;
	/* Convert inode block to disk allocation block */
	ablock = (u32)block / HFS_SB(sb)->fs_div;

	if (block >= HFS_I(inode)->fs_blocks) {
		if (block > HFS_I(inode)->fs_blocks || !create)
			return -EIO;
		if (ablock >= HFS_I(inode)->alloc_blocks) {
			res = hfs_extend_file(inode);
			if (res)
				return res;
		}
	} else
		create = 0;

	if (ablock < HFS_I(inode)->first_blocks) {
		dblock = hfs_ext_find_block(HFS_I(inode)->first_extents, ablock);
		goto done;
	}

	mutex_lock(&HFS_I(inode)->extents_lock);
	res = hfs_ext_read_extent(inode, ablock);
	if (!res)
		dblock = hfs_ext_find_block(HFS_I(inode)->cached_extents,
					    ablock - HFS_I(inode)->cached_start);
	else {
		mutex_unlock(&HFS_I(inode)->extents_lock);
		return -EIO;
	}
	mutex_unlock(&HFS_I(inode)->extents_lock);

done:
	map_bh(bh_result, sb, HFS_SB(sb)->fs_start +
	       dblock * HFS_SB(sb)->fs_div +
	       (u32)block % HFS_SB(sb)->fs_div);

	if (create) {
		set_buffer_new(bh_result);
		HFS_I(inode)->phys_size += sb->s_blocksize;
		HFS_I(inode)->fs_blocks++;
		inode_add_bytes(inode, sb->s_blocksize);
		mark_inode_dirty(inode);
	}
	return 0;
}

int hfs_extend_file(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	u32 start, len, goal;
	int res;

	mutex_lock(&HFS_I(inode)->extents_lock);
	if (HFS_I(inode)->alloc_blocks == HFS_I(inode)->first_blocks)
		goal = hfs_ext_lastblock(HFS_I(inode)->first_extents);
	else {
		res = hfs_ext_read_extent(inode, HFS_I(inode)->alloc_blocks);
		if (res)
			goto out;
		goal = hfs_ext_lastblock(HFS_I(inode)->cached_extents);
	}

	len = HFS_I(inode)->clump_blocks;
	start = hfs_vbm_search_free(sb, goal, &len);
	if (!len) {
		res = -ENOSPC;
		goto out;
	}

	hfs_dbg(EXTENT, "extend %lu: %u,%u\n", inode->i_ino, start, len);
	if (HFS_I(inode)->alloc_blocks == HFS_I(inode)->first_blocks) {
		if (!HFS_I(inode)->first_blocks) {
			hfs_dbg(EXTENT, "first extents\n");
			/* no extents yet */
			HFS_I(inode)->first_extents[0].block = cpu_to_be16(start);
			HFS_I(inode)->first_extents[0].count = cpu_to_be16(len);
			res = 0;
		} else {
			/* try to append to extents in inode */
			res = hfs_add_extent(HFS_I(inode)->first_extents,
					     HFS_I(inode)->alloc_blocks,
					     start, len);
			if (res == -ENOSPC)
				goto insert_extent;
		}
		if (!res) {
			hfs_dump_extent(HFS_I(inode)->first_extents);
			HFS_I(inode)->first_blocks += len;
		}
	} else {
		res = hfs_add_extent(HFS_I(inode)->cached_extents,
				     HFS_I(inode)->alloc_blocks -
				     HFS_I(inode)->cached_start,
				     start, len);
		if (!res) {
			hfs_dump_extent(HFS_I(inode)->cached_extents);
			HFS_I(inode)->flags |= HFS_FLG_EXT_DIRTY;
			HFS_I(inode)->cached_blocks += len;
		} else if (res == -ENOSPC)
			goto insert_extent;
	}
out:
	mutex_unlock(&HFS_I(inode)->extents_lock);
	if (!res) {
		HFS_I(inode)->alloc_blocks += len;
		mark_inode_dirty(inode);
		if (inode->i_ino < HFS_FIRSTUSER_CNID)
			set_bit(HFS_FLG_ALT_MDB_DIRTY, &HFS_SB(sb)->flags);
		set_bit(HFS_FLG_MDB_DIRTY, &HFS_SB(sb)->flags);
		hfs_mark_mdb_dirty(sb);
	}
	return res;

insert_extent:
	hfs_dbg(EXTENT, "insert new extent\n");
	res = hfs_ext_write_extent(inode);
	if (res)
		goto out;

	memset(HFS_I(inode)->cached_extents, 0, sizeof(hfs_extent_rec));
	HFS_I(inode)->cached_extents[0].block = cpu_to_be16(start);
	HFS_I(inode)->cached_extents[0].count = cpu_to_be16(len);
	hfs_dump_extent(HFS_I(inode)->cached_extents);
	HFS_I(inode)->flags |= HFS_FLG_EXT_DIRTY|HFS_FLG_EXT_NEW;
	HFS_I(inode)->cached_start = HFS_I(inode)->alloc_blocks;
	HFS_I(inode)->cached_blocks = len;

	res = 0;
	goto out;
}

void hfs_file_truncate(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct hfs_find_data fd;
	u16 blk_cnt, alloc_cnt, start;
	u32 size;
	int res;

	hfs_dbg(INODE, "truncate: %lu, %Lu -> %Lu\n",
		inode->i_ino, (long long)HFS_I(inode)->phys_size,
		inode->i_size);
	if (inode->i_size > HFS_I(inode)->phys_size) {
		struct address_space *mapping = inode->i_mapping;
		void *fsdata;
		struct page *page;

		/* XXX: Can use generic_cont_expand? */
		size = inode->i_size - 1;
		res = pagecache_write_begin(NULL, mapping, size+1, 0,
				AOP_FLAG_UNINTERRUPTIBLE, &page, &fsdata);
		if (!res) {
			res = pagecache_write_end(NULL, mapping, size+1, 0, 0,
					page, fsdata);
		}
		if (res)
			inode->i_size = HFS_I(inode)->phys_size;
		return;
	} else if (inode->i_size == HFS_I(inode)->phys_size)
		return;
	size = inode->i_size + HFS_SB(sb)->alloc_blksz - 1;
	blk_cnt = size / HFS_SB(sb)->alloc_blksz;
	alloc_cnt = HFS_I(inode)->alloc_blocks;
	if (blk_cnt == alloc_cnt)
		goto out;

	mutex_lock(&HFS_I(inode)->extents_lock);
	res = hfs_find_init(HFS_SB(sb)->ext_tree, &fd);
	if (res) {
		mutex_unlock(&HFS_I(inode)->extents_lock);
		/* XXX: We lack error handling of hfs_file_truncate() */
		return;
	}
	while (1) {
		if (alloc_cnt == HFS_I(inode)->first_blocks) {
			hfs_free_extents(sb, HFS_I(inode)->first_extents,
					 alloc_cnt, alloc_cnt - blk_cnt);
			hfs_dump_extent(HFS_I(inode)->first_extents);
			HFS_I(inode)->first_blocks = blk_cnt;
			break;
		}
		res = __hfs_ext_cache_extent(&fd, inode, alloc_cnt);
		if (res)
			break;
		start = HFS_I(inode)->cached_start;
		hfs_free_extents(sb, HFS_I(inode)->cached_extents,
				 alloc_cnt - start, alloc_cnt - blk_cnt);
		hfs_dump_extent(HFS_I(inode)->cached_extents);
		if (blk_cnt > start) {
			HFS_I(inode)->flags |= HFS_FLG_EXT_DIRTY;
			break;
		}
		alloc_cnt = start;
		HFS_I(inode)->cached_start = HFS_I(inode)->cached_blocks = 0;
		HFS_I(inode)->flags &= ~(HFS_FLG_EXT_DIRTY|HFS_FLG_EXT_NEW);
		hfs_brec_remove(&fd);
	}
	hfs_find_exit(&fd);
	mutex_unlock(&HFS_I(inode)->extents_lock);

	HFS_I(inode)->alloc_blocks = blk_cnt;
out:
	HFS_I(inode)->phys_size = inode->i_size;
	HFS_I(inode)->fs_blocks = (inode->i_size + sb->s_blocksize - 1) >> sb->s_blocksize_bits;
	inode_set_bytes(inode, HFS_I(inode)->fs_blocks << sb->s_blocksize_bits);
	mark_inode_dirty(inode);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/extent.c */
/************************************************************/
/*
 *  linux/fs/hfs/inode.c
 *
 * Copyright (C) 1995-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains inode-related functions which do not depend on
 * which scheme is being used to represent forks.
 *
 * Based on the minix file system code, (C) 1991, 1992 by Linus Torvalds
 */

// #include <linux/pagemap.h>
#include <linux/mpage.h>
#include <linux/sched.h>
#include <linux/aio.h>
#include "../../inc/__fss.h"

// #include "hfs_fs.h"
// #include "btree.h"

static const struct file_operations hfs_file_operations;
static const struct inode_operations hfs_file_inode_operations;

/*================ Variable-like macros ================*/

#define HFS_VALID_MODE_BITS  (S_IFREG | S_IFDIR | S_IRWXUGO)

static int hfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, hfs_get_block, wbc);
}

static int hfs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, hfs_get_block);
}

static void hfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		hfs_file_truncate(inode);
	}
}

static int hfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	*pagep = NULL;
	ret = cont_write_begin(file, mapping, pos, len, flags, pagep, fsdata,
				hfs_get_block,
				&HFS_I(mapping->host)->phys_size);
	if (unlikely(ret))
		hfs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t hfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, hfs_get_block);
}

static int hfs_releasepage(struct page *page, gfp_t mask)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct hfs_btree *tree;
	struct hfs_bnode *node;
	u32 nidx;
	int i, res = 1;

	switch (inode->i_ino) {
	case HFS_EXT_CNID:
		tree = HFS_SB(sb)->ext_tree;
		break;
	case HFS_CAT_CNID:
		tree = HFS_SB(sb)->cat_tree;
		break;
	default:
		BUG();
		return 0;
	}

	if (!tree)
		return 0;

	if (tree->node_size >= PAGE_CACHE_SIZE) {
		nidx = page->index >> (tree->node_size_shift - PAGE_CACHE_SHIFT);
		spin_lock(&tree->hash_lock);
		node = hfs_bnode_findhash(tree, nidx);
		if (!node)
			;
		else if (atomic_read(&node->refcnt))
			res = 0;
		if (res && node) {
			hfs_bnode_unhash(node);
			hfs_bnode_free(node);
		}
		spin_unlock(&tree->hash_lock);
	} else {
		nidx = page->index << (PAGE_CACHE_SHIFT - tree->node_size_shift);
		i = 1 << (PAGE_CACHE_SHIFT - tree->node_size_shift);
		spin_lock(&tree->hash_lock);
		do {
			node = hfs_bnode_findhash(tree, nidx++);
			if (!node)
				continue;
			if (atomic_read(&node->refcnt)) {
				res = 0;
				break;
			}
			hfs_bnode_unhash(node);
			hfs_bnode_free(node);
		} while (--i && nidx < tree->node_count);
		spin_unlock(&tree->hash_lock);
	}
	return res ? try_to_free_buffers(page) : 0;
}

static ssize_t hfs_direct_IO(int rw, struct kiocb *iocb,
		struct iov_iter *iter, loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file_inode(file)->i_mapping->host;
	size_t count = iov_iter_count(iter);
	ssize_t ret;

	ret = blockdev_direct_IO(rw, iocb, inode, iter, offset, hfs_get_block);

	/*
	 * In case of error extending write may have instantiated a few
	 * blocks outside i_size. Trim these off again.
	 */
	if (unlikely((rw & WRITE) && ret < 0)) {
		loff_t isize = i_size_read(inode);
		loff_t end = offset + count;

		if (end > isize)
			hfs_write_failed(mapping, end);
	}

	return ret;
}

static int hfs_writepages(struct address_space *mapping,
			  struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, hfs_get_block);
}

const struct address_space_operations hfs_btree_aops = {
	.readpage	= hfs_readpage,
	.writepage	= hfs_writepage,
	.write_begin	= hfs_write_begin,
	.write_end	= generic_write_end,
	.bmap		= hfs_bmap,
	.releasepage	= hfs_releasepage,
};

const struct address_space_operations hfs_aops = {
	.readpage	= hfs_readpage,
	.writepage	= hfs_writepage,
	.write_begin	= hfs_write_begin,
	.write_end	= generic_write_end,
	.bmap		= hfs_bmap,
	.direct_IO	= hfs_direct_IO,
	.writepages	= hfs_writepages,
};

/*
 * hfs_new_inode
 */
struct inode *hfs_new_inode(struct inode *dir, struct qstr *name, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = new_inode(sb);
	if (!inode)
		return NULL;

	mutex_init(&HFS_I(inode)->extents_lock);
	INIT_LIST_HEAD(&HFS_I(inode)->open_dir_list);
	hfs_cat_build_key(sb, (btree_key *)&HFS_I(inode)->cat_key, dir->i_ino, name);
	inode->i_ino = HFS_SB(sb)->next_id++;
	inode->i_mode = mode;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	set_nlink(inode, 1);
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME_SEC;
	HFS_I(inode)->flags = 0;
	HFS_I(inode)->rsrc_inode = NULL;
	HFS_I(inode)->fs_blocks = 0;
	if (S_ISDIR(mode)) {
		inode->i_size = 2;
		HFS_SB(sb)->folder_count++;
		if (dir->i_ino == HFS_ROOT_CNID)
			HFS_SB(sb)->root_dirs++;
		inode->i_op = &hfs_dir_inode_operations;
		inode->i_fop = &hfs_dir_operations;
		inode->i_mode |= S_IRWXUGO;
		inode->i_mode &= ~HFS_SB(inode->i_sb)->s_dir_umask;
	} else if (S_ISREG(mode)) {
		HFS_I(inode)->clump_blocks = HFS_SB(sb)->clumpablks;
		HFS_SB(sb)->file_count++;
		if (dir->i_ino == HFS_ROOT_CNID)
			HFS_SB(sb)->root_files++;
		inode->i_op = &hfs_file_inode_operations;
		inode->i_fop = &hfs_file_operations;
		inode->i_mapping->a_ops = &hfs_aops;
		inode->i_mode |= S_IRUGO|S_IXUGO;
		if (mode & S_IWUSR)
			inode->i_mode |= S_IWUGO;
		inode->i_mode &= ~HFS_SB(inode->i_sb)->s_file_umask;
		HFS_I(inode)->phys_size = 0;
		HFS_I(inode)->alloc_blocks = 0;
		HFS_I(inode)->first_blocks = 0;
		HFS_I(inode)->cached_start = 0;
		HFS_I(inode)->cached_blocks = 0;
		memset(HFS_I(inode)->first_extents, 0, sizeof(hfs_extent_rec));
		memset(HFS_I(inode)->cached_extents, 0, sizeof(hfs_extent_rec));
	}
	insert_inode_hash(inode);
	mark_inode_dirty(inode);
	set_bit(HFS_FLG_MDB_DIRTY, &HFS_SB(sb)->flags);
	hfs_mark_mdb_dirty(sb);

	return inode;
}

void hfs_delete_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	hfs_dbg(INODE, "delete_inode: %lu\n", inode->i_ino);
	if (S_ISDIR(inode->i_mode)) {
		HFS_SB(sb)->folder_count--;
		if (HFS_I(inode)->cat_key.ParID == cpu_to_be32(HFS_ROOT_CNID))
			HFS_SB(sb)->root_dirs--;
		set_bit(HFS_FLG_MDB_DIRTY, &HFS_SB(sb)->flags);
		hfs_mark_mdb_dirty(sb);
		return;
	}
	HFS_SB(sb)->file_count--;
	if (HFS_I(inode)->cat_key.ParID == cpu_to_be32(HFS_ROOT_CNID))
		HFS_SB(sb)->root_files--;
	if (S_ISREG(inode->i_mode)) {
		if (!inode->i_nlink) {
			inode->i_size = 0;
			hfs_file_truncate(inode);
		}
	}
	set_bit(HFS_FLG_MDB_DIRTY, &HFS_SB(sb)->flags);
	hfs_mark_mdb_dirty(sb);
}

void hfs_inode_read_fork(struct inode *inode, struct hfs_extent *ext,
			 __be32 __log_size, __be32 phys_size, u32 clump_size)
{
	struct super_block *sb = inode->i_sb;
	u32 log_size = be32_to_cpu(__log_size);
	u16 count;
	int i;

	memcpy(HFS_I(inode)->first_extents, ext, sizeof(hfs_extent_rec));
	for (count = 0, i = 0; i < 3; i++)
		count += be16_to_cpu(ext[i].count);
	HFS_I(inode)->first_blocks = count;

	inode->i_size = HFS_I(inode)->phys_size = log_size;
	HFS_I(inode)->fs_blocks = (log_size + sb->s_blocksize - 1) >> sb->s_blocksize_bits;
	inode_set_bytes(inode, HFS_I(inode)->fs_blocks << sb->s_blocksize_bits);
	HFS_I(inode)->alloc_blocks = be32_to_cpu(phys_size) /
				     HFS_SB(sb)->alloc_blksz;
	HFS_I(inode)->clump_blocks = clump_size / HFS_SB(sb)->alloc_blksz;
	if (!HFS_I(inode)->clump_blocks)
		HFS_I(inode)->clump_blocks = HFS_SB(sb)->clumpablks;
}

struct hfs_iget_data {
	struct hfs_cat_key *key;
	hfs_cat_rec *rec;
};

static int hfs_test_inode(struct inode *inode, void *data)
{
	struct hfs_iget_data *idata = data;
	hfs_cat_rec *rec;

	rec = idata->rec;
	switch (rec->type) {
	case HFS_CDR_DIR:
		return inode->i_ino == be32_to_cpu(rec->dir.DirID);
	case HFS_CDR_FIL:
		return inode->i_ino == be32_to_cpu(rec->file.FlNum);
	default:
		BUG();
		return 1;
	}
}

/*
 * hfs_read_inode
 */
static int hfs_read_inode(struct inode *inode, void *data)
{
	struct hfs_iget_data *idata = data;
	struct hfs_sb_info *hsb = HFS_SB(inode->i_sb);
	hfs_cat_rec *rec;

	HFS_I(inode)->flags = 0;
	HFS_I(inode)->rsrc_inode = NULL;
	mutex_init(&HFS_I(inode)->extents_lock);
	INIT_LIST_HEAD(&HFS_I(inode)->open_dir_list);

	/* Initialize the inode */
	inode->i_uid = hsb->s_uid;
	inode->i_gid = hsb->s_gid;
	set_nlink(inode, 1);

	if (idata->key)
		HFS_I(inode)->cat_key = *idata->key;
	else
		HFS_I(inode)->flags |= HFS_FLG_RSRC;
	HFS_I(inode)->tz_secondswest = sys_tz.tz_minuteswest * 60;

	rec = idata->rec;
	switch (rec->type) {
	case HFS_CDR_FIL:
		if (!HFS_IS_RSRC(inode)) {
			hfs_inode_read_fork(inode, rec->file.ExtRec, rec->file.LgLen,
					    rec->file.PyLen, be16_to_cpu(rec->file.ClpSize));
		} else {
			hfs_inode_read_fork(inode, rec->file.RExtRec, rec->file.RLgLen,
					    rec->file.RPyLen, be16_to_cpu(rec->file.ClpSize));
		}

		inode->i_ino = be32_to_cpu(rec->file.FlNum);
		inode->i_mode = S_IRUGO | S_IXUGO;
		if (!(rec->file.Flags & HFS_FIL_LOCK))
			inode->i_mode |= S_IWUGO;
		inode->i_mode &= ~hsb->s_file_umask;
		inode->i_mode |= S_IFREG;
		inode->i_ctime = inode->i_atime = inode->i_mtime =
				hfs_m_to_utime(rec->file.MdDat);
		inode->i_op = &hfs_file_inode_operations;
		inode->i_fop = &hfs_file_operations;
		inode->i_mapping->a_ops = &hfs_aops;
		break;
	case HFS_CDR_DIR:
		inode->i_ino = be32_to_cpu(rec->dir.DirID);
		inode->i_size = be16_to_cpu(rec->dir.Val) + 2;
		HFS_I(inode)->fs_blocks = 0;
		inode->i_mode = S_IFDIR | (S_IRWXUGO & ~hsb->s_dir_umask);
		inode->i_ctime = inode->i_atime = inode->i_mtime =
				hfs_m_to_utime(rec->dir.MdDat);
		inode->i_op = &hfs_dir_inode_operations;
		inode->i_fop = &hfs_dir_operations;
		break;
	default:
		make_bad_inode(inode);
	}
	return 0;
}

/*
 * __hfs_iget()
 *
 * Given the MDB for a HFS filesystem, a 'key' and an 'entry' in
 * the catalog B-tree and the 'type' of the desired file return the
 * inode for that file/directory or NULL.  Note that 'type' indicates
 * whether we want the actual file or directory, or the corresponding
 * metadata (AppleDouble header file or CAP metadata file).
 */
struct inode *hfs_iget(struct super_block *sb, struct hfs_cat_key *key, hfs_cat_rec *rec)
{
	struct hfs_iget_data data = { key, rec };
	struct inode *inode;
	u32 cnid;

	switch (rec->type) {
	case HFS_CDR_DIR:
		cnid = be32_to_cpu(rec->dir.DirID);
		break;
	case HFS_CDR_FIL:
		cnid = be32_to_cpu(rec->file.FlNum);
		break;
	default:
		return NULL;
	}
	inode = iget5_locked(sb, cnid, hfs_test_inode, hfs_read_inode, &data);
	if (inode && (inode->i_state & I_NEW))
		unlock_new_inode(inode);
	return inode;
}

void hfs_inode_write_fork(struct inode *inode, struct hfs_extent *ext,
			  __be32 *log_size, __be32 *phys_size)
{
	memcpy(ext, HFS_I(inode)->first_extents, sizeof(hfs_extent_rec));

	if (log_size)
		*log_size = cpu_to_be32(inode->i_size);
	if (phys_size)
		*phys_size = cpu_to_be32(HFS_I(inode)->alloc_blocks *
					 HFS_SB(inode->i_sb)->alloc_blksz);
}

int hfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct inode *main_inode = inode;
	struct hfs_find_data fd;
	hfs_cat_rec rec;
	int res;

	hfs_dbg(INODE, "hfs_write_inode: %lu\n", inode->i_ino);
	res = hfs_ext_write_extent(inode);
	if (res)
		return res;

	if (inode->i_ino < HFS_FIRSTUSER_CNID) {
		switch (inode->i_ino) {
		case HFS_ROOT_CNID:
			break;
		case HFS_EXT_CNID:
			hfs_btree_write(HFS_SB(inode->i_sb)->ext_tree);
			return 0;
		case HFS_CAT_CNID:
			hfs_btree_write(HFS_SB(inode->i_sb)->cat_tree);
			return 0;
		default:
			BUG();
			return -EIO;
		}
	}

	if (HFS_IS_RSRC(inode))
		main_inode = HFS_I(inode)->rsrc_inode;

	if (!main_inode->i_nlink)
		return 0;

	if (hfs_find_init(HFS_SB(main_inode->i_sb)->cat_tree, &fd))
		/* panic? */
		return -EIO;

	fd.search_key->cat = HFS_I(main_inode)->cat_key;
	if (hfs_brec_find(&fd))
		/* panic? */
		goto out;

	if (S_ISDIR(main_inode->i_mode)) {
		if (fd.entrylength < sizeof(struct hfs_cat_dir))
			/* panic? */;
		hfs_bnode_read(fd.bnode, &rec, fd.entryoffset,
			   sizeof(struct hfs_cat_dir));
		if (rec.type != HFS_CDR_DIR ||
		    be32_to_cpu(rec.dir.DirID) != inode->i_ino) {
		}

		rec.dir.MdDat = hfs_u_to_mtime(inode->i_mtime);
		rec.dir.Val = cpu_to_be16(inode->i_size - 2);

		hfs_bnode_write(fd.bnode, &rec, fd.entryoffset,
			    sizeof(struct hfs_cat_dir));
	} else if (HFS_IS_RSRC(inode)) {
		hfs_bnode_read(fd.bnode, &rec, fd.entryoffset,
			       sizeof(struct hfs_cat_file));
		hfs_inode_write_fork(inode, rec.file.RExtRec,
				     &rec.file.RLgLen, &rec.file.RPyLen);
		hfs_bnode_write(fd.bnode, &rec, fd.entryoffset,
				sizeof(struct hfs_cat_file));
	} else {
		if (fd.entrylength < sizeof(struct hfs_cat_file))
			/* panic? */;
		hfs_bnode_read(fd.bnode, &rec, fd.entryoffset,
			   sizeof(struct hfs_cat_file));
		if (rec.type != HFS_CDR_FIL ||
		    be32_to_cpu(rec.file.FlNum) != inode->i_ino) {
		}

		if (inode->i_mode & S_IWUSR)
			rec.file.Flags &= ~HFS_FIL_LOCK;
		else
			rec.file.Flags |= HFS_FIL_LOCK;
		hfs_inode_write_fork(inode, rec.file.ExtRec, &rec.file.LgLen, &rec.file.PyLen);
		rec.file.MdDat = hfs_u_to_mtime(inode->i_mtime);

		hfs_bnode_write(fd.bnode, &rec, fd.entryoffset,
			    sizeof(struct hfs_cat_file));
	}
out:
	hfs_find_exit(&fd);
	return 0;
}

static struct dentry *hfs_file_lookup(struct inode *dir, struct dentry *dentry,
				      unsigned int flags)
{
	struct inode *inode = NULL;
	hfs_cat_rec rec;
	struct hfs_find_data fd;
	int res;

	if (HFS_IS_RSRC(dir) || strcmp(dentry->d_name.name, "rsrc"))
		goto out;

	inode = HFS_I(dir)->rsrc_inode;
	if (inode)
		goto out;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	res = hfs_find_init(HFS_SB(dir->i_sb)->cat_tree, &fd);
	if (res) {
		iput(inode);
		return ERR_PTR(res);
	}
	fd.search_key->cat = HFS_I(dir)->cat_key;
	res = hfs_brec_read(&fd, &rec, sizeof(rec));
	if (!res) {
		struct hfs_iget_data idata = { NULL, &rec };
		hfs_read_inode(inode, &idata);
	}
	hfs_find_exit(&fd);
	if (res) {
		iput(inode);
		return ERR_PTR(res);
	}
	HFS_I(inode)->rsrc_inode = dir;
	HFS_I(dir)->rsrc_inode = inode;
	igrab(dir);
	hlist_add_fake(&inode->i_hash);
	mark_inode_dirty(inode);
out:
	d_add(dentry, inode);
	return NULL;
}

void hfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (HFS_IS_RSRC(inode) && HFS_I(inode)->rsrc_inode) {
		HFS_I(HFS_I(inode)->rsrc_inode)->rsrc_inode = NULL;
		iput(HFS_I(inode)->rsrc_inode);
	}
}

static int hfs_file_open(struct inode *inode, struct file *file)
{
	if (HFS_IS_RSRC(inode))
		inode = HFS_I(inode)->rsrc_inode;
	atomic_inc(&HFS_I(inode)->opencnt);
	return 0;
}

static int hfs_file_release(struct inode *inode, struct file *file)
{
	//struct super_block *sb = inode->i_sb;

	if (HFS_IS_RSRC(inode))
		inode = HFS_I(inode)->rsrc_inode;
	if (atomic_dec_and_test(&HFS_I(inode)->opencnt)) {
		mutex_lock(&inode->i_mutex);
		hfs_file_truncate(inode);
		//if (inode->i_flags & S_DEAD) {
		//	hfs_delete_cat(inode->i_ino, HFSPLUS_SB(sb).hidden_dir, NULL);
		//	hfs_delete_inode(inode);
		//}
		mutex_unlock(&inode->i_mutex);
	}
	return 0;
}

/*
 * hfs_notify_change()
 *
 * Based very closely on fs/msdos/inode.c by Werner Almesberger
 *
 * This is the notify_change() field in the super_operations structure
 * for HFS file systems.  The purpose is to take that changes made to
 * an inode and apply then in a filesystem-dependent manner.  In this
 * case the process has a few of tasks to do:
 *  1) prevent changes to the i_uid and i_gid fields.
 *  2) map file permissions to the closest allowable permissions
 *  3) Since multiple Linux files can share the same on-disk inode under
 *     HFS (for instance the data and resource forks of a file) a change
 *     to permissions must be applied to all other in-core inodes which
 *     correspond to the same HFS file.
 */

int hfs_inode_setattr(struct dentry *dentry, struct iattr * attr)
{
	struct inode *inode = dentry->d_inode;
	struct hfs_sb_info *hsb = HFS_SB(inode->i_sb);
	int error;

	error = inode_change_ok(inode, attr); /* basic permission checks */
	if (error)
		return error;

	/* no uig/gid changes and limit which mode bits can be set */
	if (((attr->ia_valid & ATTR_UID) &&
	     (!uid_eq(attr->ia_uid, hsb->s_uid))) ||
	    ((attr->ia_valid & ATTR_GID) &&
	     (!gid_eq(attr->ia_gid, hsb->s_gid))) ||
	    ((attr->ia_valid & ATTR_MODE) &&
	     ((S_ISDIR(inode->i_mode) &&
	       (attr->ia_mode != inode->i_mode)) ||
	      (attr->ia_mode & ~HFS_VALID_MODE_BITS)))) {
		return hsb->s_quiet ? 0 : error;
	}

	if (attr->ia_valid & ATTR_MODE) {
		/* Only the 'w' bits can ever change and only all together. */
		if (attr->ia_mode & S_IWUSR)
			attr->ia_mode = inode->i_mode | S_IWUGO;
		else
			attr->ia_mode = inode->i_mode & ~S_IWUGO;
		attr->ia_mode &= S_ISDIR(inode->i_mode) ? ~hsb->s_dir_umask: ~hsb->s_file_umask;
	}

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		inode_dio_wait(inode);

		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		hfs_file_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

static int hfs_file_fsync(struct file *filp, loff_t start, loff_t end,
			  int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	struct super_block * sb;
	int ret, err;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;
	mutex_lock(&inode->i_mutex);

	/* sync the inode to buffers */
	ret = write_inode_now(inode, 0);

	/* sync the superblock to buffers */
	sb = inode->i_sb;
	flush_delayed_work(&HFS_SB(sb)->mdb_work);
	/* .. finally sync the buffers to disk */
	err = sync_blockdev(sb->s_bdev);
	if (!ret)
		ret = err;
	mutex_unlock(&inode->i_mutex);
	return ret;
}

static const struct file_operations hfs_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.splice_read	= generic_file_splice_read,
	.fsync		= hfs_file_fsync,
	.open		= hfs_file_open,
	.release	= hfs_file_release,
};

static const struct inode_operations hfs_file_inode_operations = {
	.lookup		= hfs_file_lookup,
	.setattr	= hfs_inode_setattr,
	.setxattr	= hfs_setxattr,
	.getxattr	= hfs_getxattr,
	.listxattr	= hfs_listxattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/inode.c */
/************************************************************/
/*
 *  linux/fs/hfs/attr.c
 *
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Export hfs data via xattr
 */


#include <linux/fs.h>
#include <linux/xattr.h>
#include "../../inc/__fss.h"

// #include "hfs_fs.h"
// #include "btree.h"

int hfs_setxattr(struct dentry *dentry, const char *name,
		 const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct hfs_find_data fd;
	hfs_cat_rec rec;
	struct hfs_cat_file *file;
	int res;

	if (!S_ISREG(inode->i_mode) || HFS_IS_RSRC(inode))
		return -EOPNOTSUPP;

	res = hfs_find_init(HFS_SB(inode->i_sb)->cat_tree, &fd);
	if (res)
		return res;
	fd.search_key->cat = HFS_I(inode)->cat_key;
	res = hfs_brec_find(&fd);
	if (res)
		goto out;
	hfs_bnode_read(fd.bnode, &rec, fd.entryoffset,
			sizeof(struct hfs_cat_file));
	file = &rec.file;

	if (!strcmp(name, "hfs.type")) {
		if (size == 4)
			memcpy(&file->UsrWds.fdType, value, 4);
		else
			res = -ERANGE;
	} else if (!strcmp(name, "hfs.creator")) {
		if (size == 4)
			memcpy(&file->UsrWds.fdCreator, value, 4);
		else
			res = -ERANGE;
	} else
		res = -EOPNOTSUPP;
	if (!res)
		hfs_bnode_write(fd.bnode, &rec, fd.entryoffset,
				sizeof(struct hfs_cat_file));
out:
	hfs_find_exit(&fd);
	return res;
}

ssize_t hfs_getxattr(struct dentry *dentry, const char *name,
			 void *value, size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct hfs_find_data fd;
	hfs_cat_rec rec;
	struct hfs_cat_file *file;
	ssize_t res = 0;

	if (!S_ISREG(inode->i_mode) || HFS_IS_RSRC(inode))
		return -EOPNOTSUPP;

	if (size) {
		res = hfs_find_init(HFS_SB(inode->i_sb)->cat_tree, &fd);
		if (res)
			return res;
		fd.search_key->cat = HFS_I(inode)->cat_key;
		res = hfs_brec_find(&fd);
		if (res)
			goto out;
		hfs_bnode_read(fd.bnode, &rec, fd.entryoffset,
				sizeof(struct hfs_cat_file));
	}
	file = &rec.file;

	if (!strcmp(name, "hfs.type")) {
		if (size >= 4) {
			memcpy(value, &file->UsrWds.fdType, 4);
			res = 4;
		} else
			res = size ? -ERANGE : 4;
	} else if (!strcmp(name, "hfs.creator")) {
		if (size >= 4) {
			memcpy(value, &file->UsrWds.fdCreator, 4);
			res = 4;
		} else
			res = size ? -ERANGE : 4;
	} else
		res = -ENODATA;
out:
	if (size)
		hfs_find_exit(&fd);
	return res;
}

#define HFS_ATTRLIST_SIZE (sizeof("hfs.creator")+sizeof("hfs.type"))

ssize_t hfs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	struct inode *inode = dentry->d_inode;

	if (!S_ISREG(inode->i_mode) || HFS_IS_RSRC(inode))
		return -EOPNOTSUPP;

	if (!buffer || !size)
		return HFS_ATTRLIST_SIZE;
	if (size < HFS_ATTRLIST_SIZE)
		return -ERANGE;
	strcpy(buffer, "hfs.type");
	strcpy(buffer + sizeof("hfs.type"), "hfs.creator");

	return HFS_ATTRLIST_SIZE;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/attr.c */
/************************************************************/
/*
 *  linux/fs/hfs/mdb.c
 *
 * Copyright (C) 1995-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains functions for reading/writing the MDB.
 */

#include <linux/cdrom.h>
#include <linux/genhd.h>
#include <linux/nls.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

// #include "hfs_fs.h"
// #include "btree.h"

/*================ File-local data types ================*/

/*
 * The HFS Master Directory Block (MDB).
 *
 * Also known as the Volume Information Block (VIB), this structure is
 * the HFS equivalent of a superblock.
 *
 * Reference: _Inside Macintosh: Files_ pages 2-59 through 2-62
 *
 * modified for HFS Extended
 */

static int hfs_get_last_session(struct super_block *sb,
				sector_t *start, sector_t *size)
{
	struct cdrom_multisession ms_info;
	struct cdrom_tocentry te;
	int res;

	/* default values */
	*start = 0;
	*size = sb->s_bdev->bd_inode->i_size >> 9;

	if (HFS_SB(sb)->session >= 0) {
		te.cdte_track = HFS_SB(sb)->session;
		te.cdte_format = CDROM_LBA;
		res = ioctl_by_bdev(sb->s_bdev, CDROMREADTOCENTRY, (unsigned long)&te);
		if (!res && (te.cdte_ctrl & CDROM_DATA_TRACK) == 4) {
			*start = (sector_t)te.cdte_addr.lba << 2;
			return 0;
		}
		pr_err("invalid session number or type of track\n");
		return -EINVAL;
	}
	ms_info.addr_format = CDROM_LBA;
	res = ioctl_by_bdev(sb->s_bdev, CDROMMULTISESSION, (unsigned long)&ms_info);
	if (!res && ms_info.xa_flag)
		*start = (sector_t)ms_info.addr.lba << 2;
	return 0;
}

/*
 * hfs_mdb_get()
 *
 * Build the in-core MDB for a filesystem, including
 * the B-trees and the volume bitmap.
 */
int hfs_mdb_get(struct super_block *sb)
{
	struct buffer_head *bh;
	struct hfs_mdb *mdb, *mdb2;
	unsigned int block;
	char *ptr;
	int off2, len, size, sect;
	sector_t part_start, part_size;
	loff_t off;
	__be16 attrib;

	/* set the device driver to 512-byte blocks */
	size = sb_min_blocksize(sb, HFS_SECTOR_SIZE);
	if (!size)
		return -EINVAL;

	if (hfs_get_last_session(sb, &part_start, &part_size))
		return -EINVAL;
	while (1) {
		/* See if this is an HFS filesystem */
		bh = sb_bread512(sb, part_start + HFS_MDB_BLK, mdb);
		if (!bh)
			goto out;

		if (mdb->drSigWord == cpu_to_be16(HFS_SUPER_MAGIC))
			break;
		brelse(bh);

		/* check for a partition block
		 * (should do this only for cdrom/loop though)
		 */
		if (hfs_part_find(sb, &part_start, &part_size))
			goto out;
	}

	HFS_SB(sb)->alloc_blksz = size = be32_to_cpu(mdb->drAlBlkSiz);
	if (!size || (size & (HFS_SECTOR_SIZE - 1))) {
		pr_err("bad allocation block size %d\n", size);
		goto out_bh;
	}

	size = min(HFS_SB(sb)->alloc_blksz, (u32)PAGE_SIZE);
	/* size must be a multiple of 512 */
	while (size & (size - 1))
		size -= HFS_SECTOR_SIZE;
	sect = be16_to_cpu(mdb->drAlBlSt) + part_start;
	/* align block size to first sector */
	while (sect & ((size - 1) >> HFS_SECTOR_SIZE_BITS))
		size >>= 1;
	/* align block size to weird alloc size */
	while (HFS_SB(sb)->alloc_blksz & (size - 1))
		size >>= 1;
	brelse(bh);
	if (!sb_set_blocksize(sb, size)) {
		pr_err("unable to set blocksize to %u\n", size);
		goto out;
	}

	bh = sb_bread512(sb, part_start + HFS_MDB_BLK, mdb);
	if (!bh)
		goto out;
	if (mdb->drSigWord != cpu_to_be16(HFS_SUPER_MAGIC))
		goto out_bh;

	HFS_SB(sb)->mdb_bh = bh;
	HFS_SB(sb)->mdb = mdb;

	/* These parameters are read from the MDB, and never written */
	HFS_SB(sb)->part_start = part_start;
	HFS_SB(sb)->fs_ablocks = be16_to_cpu(mdb->drNmAlBlks);
	HFS_SB(sb)->fs_div = HFS_SB(sb)->alloc_blksz >> sb->s_blocksize_bits;
	HFS_SB(sb)->clumpablks = be32_to_cpu(mdb->drClpSiz) /
				 HFS_SB(sb)->alloc_blksz;
	if (!HFS_SB(sb)->clumpablks)
		HFS_SB(sb)->clumpablks = 1;
	HFS_SB(sb)->fs_start = (be16_to_cpu(mdb->drAlBlSt) + part_start) >>
			       (sb->s_blocksize_bits - HFS_SECTOR_SIZE_BITS);

	/* These parameters are read from and written to the MDB */
	HFS_SB(sb)->free_ablocks = be16_to_cpu(mdb->drFreeBks);
	HFS_SB(sb)->next_id = be32_to_cpu(mdb->drNxtCNID);
	HFS_SB(sb)->root_files = be16_to_cpu(mdb->drNmFls);
	HFS_SB(sb)->root_dirs = be16_to_cpu(mdb->drNmRtDirs);
	HFS_SB(sb)->file_count = be32_to_cpu(mdb->drFilCnt);
	HFS_SB(sb)->folder_count = be32_to_cpu(mdb->drDirCnt);

	/* TRY to get the alternate (backup) MDB. */
	sect = part_start + part_size - 2;
	bh = sb_bread512(sb, sect, mdb2);
	if (bh) {
		if (mdb2->drSigWord == cpu_to_be16(HFS_SUPER_MAGIC)) {
			HFS_SB(sb)->alt_mdb_bh = bh;
			HFS_SB(sb)->alt_mdb = mdb2;
		} else
			brelse(bh);
	}

	if (!HFS_SB(sb)->alt_mdb) {
		pr_warn("unable to locate alternate MDB\n");
		pr_warn("continuing without an alternate MDB\n");
	}

	HFS_SB(sb)->bitmap = (__be32 *)__get_free_pages(GFP_KERNEL, PAGE_SIZE < 8192 ? 1 : 0);
	if (!HFS_SB(sb)->bitmap)
		goto out;

	/* read in the bitmap */
	block = be16_to_cpu(mdb->drVBMSt) + part_start;
	off = (loff_t)block << HFS_SECTOR_SIZE_BITS;
	size = (HFS_SB(sb)->fs_ablocks + 8) / 8;
	ptr = (u8 *)HFS_SB(sb)->bitmap;
	while (size) {
		bh = sb_bread(sb, off >> sb->s_blocksize_bits);
		if (!bh) {
			pr_err("unable to read volume bitmap\n");
			goto out;
		}
		off2 = off & (sb->s_blocksize - 1);
		len = min((int)sb->s_blocksize - off2, size);
		memcpy(ptr, bh->b_data + off2, len);
		brelse(bh);
		ptr += len;
		off += len;
		size -= len;
	}

	HFS_SB(sb)->ext_tree = hfs_btree_open(sb, HFS_EXT_CNID, hfs_ext_keycmp);
	if (!HFS_SB(sb)->ext_tree) {
		pr_err("unable to open extent tree\n");
		goto out;
	}
	HFS_SB(sb)->cat_tree = hfs_btree_open(sb, HFS_CAT_CNID, hfs_cat_keycmp);
	if (!HFS_SB(sb)->cat_tree) {
		pr_err("unable to open catalog tree\n");
		goto out;
	}

	attrib = mdb->drAtrb;
	if (!(attrib & cpu_to_be16(HFS_SB_ATTRIB_UNMNT))) {
		pr_warn("filesystem was not cleanly unmounted, running fsck.hfs is recommended.  mounting read-only.\n");
		sb->s_flags |= MS_RDONLY;
	}
	if ((attrib & cpu_to_be16(HFS_SB_ATTRIB_SLOCK))) {
		pr_warn("filesystem is marked locked, mounting read-only.\n");
		sb->s_flags |= MS_RDONLY;
	}
	if (!(sb->s_flags & MS_RDONLY)) {
		/* Mark the volume uncleanly unmounted in case we crash */
		attrib &= cpu_to_be16(~HFS_SB_ATTRIB_UNMNT);
		attrib |= cpu_to_be16(HFS_SB_ATTRIB_INCNSTNT);
		mdb->drAtrb = attrib;
		be32_add_cpu(&mdb->drWrCnt, 1);
		mdb->drLsMod = hfs_mtime();

		mark_buffer_dirty(HFS_SB(sb)->mdb_bh);
		sync_dirty_buffer(HFS_SB(sb)->mdb_bh);
	}

	return 0;

out_bh:
	brelse(bh);
out:
	hfs_mdb_put(sb);
	return -EIO;
}

/*
 * hfs_mdb_commit()
 *
 * Description:
 *   This updates the MDB on disk.
 *   It does not check, if the superblock has been modified, or
 *   if the filesystem has been mounted read-only. It is mainly
 *   called by hfs_sync_fs() and flush_mdb().
 * Input Variable(s):
 *   struct hfs_mdb *mdb: Pointer to the hfs MDB
 *   int backup;
 * Output Variable(s):
 *   NONE
 * Returns:
 *   void
 * Preconditions:
 *   'mdb' points to a "valid" (struct hfs_mdb).
 * Postconditions:
 *   The HFS MDB and on disk will be updated, by copying the possibly
 *   modified fields from the in memory MDB (in native byte order) to
 *   the disk block buffer.
 *   If 'backup' is non-zero then the alternate MDB is also written
 *   and the function doesn't return until it is actually on disk.
 */
void hfs_mdb_commit(struct super_block *sb)
{
	struct hfs_mdb *mdb = HFS_SB(sb)->mdb;

	if (sb->s_flags & MS_RDONLY)
		return;

	lock_buffer(HFS_SB(sb)->mdb_bh);
	if (test_and_clear_bit(HFS_FLG_MDB_DIRTY, &HFS_SB(sb)->flags)) {
		/* These parameters may have been modified, so write them back */
		mdb->drLsMod = hfs_mtime();
		mdb->drFreeBks = cpu_to_be16(HFS_SB(sb)->free_ablocks);
		mdb->drNxtCNID = cpu_to_be32(HFS_SB(sb)->next_id);
		mdb->drNmFls = cpu_to_be16(HFS_SB(sb)->root_files);
		mdb->drNmRtDirs = cpu_to_be16(HFS_SB(sb)->root_dirs);
		mdb->drFilCnt = cpu_to_be32(HFS_SB(sb)->file_count);
		mdb->drDirCnt = cpu_to_be32(HFS_SB(sb)->folder_count);

		/* write MDB to disk */
		mark_buffer_dirty(HFS_SB(sb)->mdb_bh);
	}

	/* write the backup MDB, not returning until it is written.
	 * we only do this when either the catalog or extents overflow
	 * files grow. */
	if (test_and_clear_bit(HFS_FLG_ALT_MDB_DIRTY, &HFS_SB(sb)->flags) &&
	    HFS_SB(sb)->alt_mdb) {
		hfs_inode_write_fork(HFS_SB(sb)->ext_tree->inode, mdb->drXTExtRec,
				     &mdb->drXTFlSize, NULL);
		hfs_inode_write_fork(HFS_SB(sb)->cat_tree->inode, mdb->drCTExtRec,
				     &mdb->drCTFlSize, NULL);

		lock_buffer(HFS_SB(sb)->alt_mdb_bh);
		memcpy(HFS_SB(sb)->alt_mdb, HFS_SB(sb)->mdb, HFS_SECTOR_SIZE);
		HFS_SB(sb)->alt_mdb->drAtrb |= cpu_to_be16(HFS_SB_ATTRIB_UNMNT);
		HFS_SB(sb)->alt_mdb->drAtrb &= cpu_to_be16(~HFS_SB_ATTRIB_INCNSTNT);
		unlock_buffer(HFS_SB(sb)->alt_mdb_bh);

		mark_buffer_dirty(HFS_SB(sb)->alt_mdb_bh);
		sync_dirty_buffer(HFS_SB(sb)->alt_mdb_bh);
	}

	if (test_and_clear_bit(HFS_FLG_BITMAP_DIRTY, &HFS_SB(sb)->flags)) {
		struct buffer_head *bh;
		sector_t block;
		char *ptr;
		int off, size, len;

		block = be16_to_cpu(HFS_SB(sb)->mdb->drVBMSt) + HFS_SB(sb)->part_start;
		off = (block << HFS_SECTOR_SIZE_BITS) & (sb->s_blocksize - 1);
		block >>= sb->s_blocksize_bits - HFS_SECTOR_SIZE_BITS;
		size = (HFS_SB(sb)->fs_ablocks + 7) / 8;
		ptr = (u8 *)HFS_SB(sb)->bitmap;
		while (size) {
			bh = sb_bread(sb, block);
			if (!bh) {
				pr_err("unable to read volume bitmap\n");
				break;
			}
			len = min((int)sb->s_blocksize - off, size);

			lock_buffer(bh);
			memcpy(bh->b_data + off, ptr, len);
			unlock_buffer(bh);

			mark_buffer_dirty(bh);
			brelse(bh);
			block++;
			off = 0;
			ptr += len;
			size -= len;
		}
	}
	unlock_buffer(HFS_SB(sb)->mdb_bh);
}

void hfs_mdb_close(struct super_block *sb)
{
	/* update volume attributes */
	if (sb->s_flags & MS_RDONLY)
		return;
	HFS_SB(sb)->mdb->drAtrb |= cpu_to_be16(HFS_SB_ATTRIB_UNMNT);
	HFS_SB(sb)->mdb->drAtrb &= cpu_to_be16(~HFS_SB_ATTRIB_INCNSTNT);
	mark_buffer_dirty(HFS_SB(sb)->mdb_bh);
}

/*
 * hfs_mdb_put()
 *
 * Release the resources associated with the in-core MDB.  */
void hfs_mdb_put(struct super_block *sb)
{
	if (!HFS_SB(sb))
		return;
	/* free the B-trees */
	hfs_btree_close(HFS_SB(sb)->ext_tree);
	hfs_btree_close(HFS_SB(sb)->cat_tree);

	/* free the buffers holding the primary and alternate MDBs */
	brelse(HFS_SB(sb)->mdb_bh);
	brelse(HFS_SB(sb)->alt_mdb_bh);

	unload_nls(HFS_SB(sb)->nls_io);
	unload_nls(HFS_SB(sb)->nls_disk);

	free_pages((unsigned long)HFS_SB(sb)->bitmap, PAGE_SIZE < 8192 ? 1 : 0);
	kfree(HFS_SB(sb));
	sb->s_fs_info = NULL;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/mdb.c */
/************************************************************/
/*
 *  linux/fs/hfs/part_tbl.c
 *
 * Copyright (C) 1996-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * Original code to handle the new style Mac partition table based on
 * a patch contributed by Holger Schemel (aeglos@valinor.owl.de).
 */

// #include "hfs_fs.h"

/*
 * The new style Mac partition map
 *
 * For each partition on the media there is a physical block (512-byte
 * block) containing one of these structures.  These blocks are
 * contiguous starting at block 1.
 */
struct new_pmap {
	__be16	pmSig;		/* signature */
	__be16	reSigPad;	/* padding */
	__be32	pmMapBlkCnt;	/* partition blocks count */
	__be32	pmPyPartStart;	/* physical block start of partition */
	__be32	pmPartBlkCnt;	/* physical block count of partition */
	u8	pmPartName[32];	/* (null terminated?) string
				   giving the name of this
				   partition */
	u8	pmPartType[32];	/* (null terminated?) string
				   giving the type of this
				   partition */
	/* a bunch more stuff we don't need */
} __packed;

/*
 * The old style Mac partition map
 *
 * The partition map consists for a 2-byte signature followed by an
 * array of these structures.  The map is terminated with an all-zero
 * one of these.
 */
struct old_pmap {
	__be16		pdSig;	/* Signature bytes */
	struct 	old_pmap_entry {
		__be32	pdStart;
		__be32	pdSize;
		__be32	pdFSID;
	}	pdEntry[42];
} __packed;

/*
 * hfs_part_find()
 *
 * Parse the partition map looking for the
 * start and length of the 'part'th HFS partition.
 */
int hfs_part_find(struct super_block *sb,
		  sector_t *part_start, sector_t *part_size)
{
	struct buffer_head *bh;
	__be16 *data;
	int i, size, res;

	res = -ENOENT;
	bh = sb_bread512(sb, *part_start + HFS_PMAP_BLK, data);
	if (!bh)
		return -EIO;

	switch (be16_to_cpu(*data)) {
	case HFS_OLD_PMAP_MAGIC:
	  {
		struct old_pmap *pm;
		struct old_pmap_entry *p;

		pm = (struct old_pmap *)bh->b_data;
		p = pm->pdEntry;
		size = 42;
		for (i = 0; i < size; p++, i++) {
			if (p->pdStart && p->pdSize &&
			    p->pdFSID == cpu_to_be32(0x54465331)/*"TFS1"*/ &&
			    (HFS_SB(sb)->part < 0 || HFS_SB(sb)->part == i)) {
				*part_start += be32_to_cpu(p->pdStart);
				*part_size = be32_to_cpu(p->pdSize);
				res = 0;
			}
		}
		break;
	  }
	case HFS_NEW_PMAP_MAGIC:
	  {
		struct new_pmap *pm;

		pm = (struct new_pmap *)bh->b_data;
		size = be32_to_cpu(pm->pmMapBlkCnt);
		for (i = 0; i < size;) {
			if (!memcmp(pm->pmPartType,"Apple_HFS", 9) &&
			    (HFS_SB(sb)->part < 0 || HFS_SB(sb)->part == i)) {
				*part_start += be32_to_cpu(pm->pmPyPartStart);
				*part_size = be32_to_cpu(pm->pmPartBlkCnt);
				res = 0;
				break;
			}
			brelse(bh);
			bh = sb_bread512(sb, *part_start + HFS_PMAP_BLK + ++i, pm);
			if (!bh)
				return -EIO;
			if (pm->pmSig != cpu_to_be16(HFS_NEW_PMAP_MAGIC))
				break;
		}
		break;
	  }
	}
	brelse(bh);

	return res;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/part_tbl.c */
/************************************************************/
/*
 *  linux/fs/hfs/string.c
 *
 * Copyright (C) 1995-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains the string comparison function for the
 * Macintosh character set.
 *
 * The code in this file is derived from code which is copyright
 * 1986, 1989, 1990 by Abacus Research and Development, Inc. (ARDI)
 * It is used here by the permission of ARDI's president Cliff Matthews.
 */

// #include "hfs_fs.h"
#include <linux/dcache.h>
#include "../../inc/__fss.h"

/*================ File-local variables ================*/

/*
 * unsigned char caseorder[]
 *
 * Defines the lexical ordering of characters on the Macintosh
 *
 * Composition of the 'casefold' and 'order' tables from ARDI's code
 * with the entry for 0x20 changed to match that for 0xCA to remove
 * special case for those two characters.
 */
static unsigned char caseorder[256] = {
	0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
	0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,
	0x20,0x22,0x23,0x28,0x29,0x2A,0x2B,0x2C,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
	0x37,0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x40,0x41,0x42,0x43,0x44,0x45,0x46,
	0x47,0x48,0x57,0x59,0x5D,0x5F,0x66,0x68,0x6A,0x6C,0x72,0x74,0x76,0x78,0x7A,0x7E,
	0x8C,0x8E,0x90,0x92,0x95,0x97,0x9E,0xA0,0xA2,0xA4,0xA7,0xA9,0xAA,0xAB,0xAC,0xAD,
	0x4E,0x48,0x57,0x59,0x5D,0x5F,0x66,0x68,0x6A,0x6C,0x72,0x74,0x76,0x78,0x7A,0x7E,
	0x8C,0x8E,0x90,0x92,0x95,0x97,0x9E,0xA0,0xA2,0xA4,0xA7,0xAF,0xB0,0xB1,0xB2,0xB3,
	0x4A,0x4C,0x5A,0x60,0x7B,0x7F,0x98,0x4F,0x49,0x51,0x4A,0x4B,0x4C,0x5A,0x60,0x63,
	0x64,0x65,0x6E,0x6F,0x70,0x71,0x7B,0x84,0x85,0x86,0x7F,0x80,0x9A,0x9B,0x9C,0x98,
	0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0x94,0xBB,0xBC,0xBD,0xBE,0xBF,0xC0,0x4D,0x81,
	0xC1,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xCB,0x55,0x8A,0xCC,0x4D,0x81,
	0xCD,0xCE,0xCF,0xD0,0xD1,0xD2,0xD3,0x26,0x27,0xD4,0x20,0x49,0x4B,0x80,0x82,0x82,
	0xD5,0xD6,0x24,0x25,0x2D,0x2E,0xD7,0xD8,0xA6,0xD9,0xDA,0xDB,0xDC,0xDD,0xDE,0xDF,
	0xE0,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xEB,0xEC,0xED,0xEE,0xEF,
	0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF
};

/*================ Global functions ================*/

/*
 * Hash a string to an integer in a case-independent way
 */
int hfs_hash_dentry(const struct dentry *dentry, struct qstr *this)
{
	const unsigned char *name = this->name;
	unsigned int hash, len = this->len;

	if (len > HFS_NAMELEN)
		len = HFS_NAMELEN;

	hash = init_name_hash();
	for (; len; len--)
		hash = partial_name_hash(caseorder[*name++], hash);
	this->hash = end_name_hash(hash);
	return 0;
}

/*
 * Compare two strings in the HFS filename character ordering
 * Returns positive, negative, or zero, not just 0 or (+/-)1
 *
 * Equivalent to ARDI's call:
 *	ROMlib_RelString(s1+1, s2+1, true, false, (s1[0]<<16) | s2[0])
 */
int hfs_strcmp(const unsigned char *s1, unsigned int len1,
	       const unsigned char *s2, unsigned int len2)
{
	int len, tmp;

	len = (len1 > len2) ? len2 : len1;

	while (len--) {
		tmp = (int)caseorder[*(s1++)] - (int)caseorder[*(s2++)];
		if (tmp)
			return tmp;
	}
	return len1 - len2;
}

/*
 * Test for equality of two strings in the HFS filename character ordering.
 * return 1 on failure and 0 on success
 */
int hfs_compare_dentry(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	const unsigned char *n1, *n2;

	if (len >= HFS_NAMELEN) {
		if (name->len < HFS_NAMELEN)
			return 1;
		len = HFS_NAMELEN;
	} else if (len != name->len)
		return 1;

	n1 = str;
	n2 = name->name;
	while (len--) {
		if (caseorder[*n1++] != caseorder[*n2++])
			return 1;
	}
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/string.c */
/************************************************************/
/*
 *  linux/fs/hfs/super.c
 *
 * Copyright (C) 1995-1997  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains hfs_read_super(), some of the super_ops and
 * init_hfs_fs() and exit_hfs_fs().  The remaining super_ops are in
 * inode.c since they deal with inodes.
 *
 * Based on the minix file system code, (C) 1991, 1992 by Linus Torvalds
 */

#include <linux/module.h>
#include <linux/blkdev.h>
#include <linux/mount.h>
#include <linux/init.h>
// #include <linux/nls.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
// #include <linux/slab.h>
#include <linux/vfs.h>
#include "../../inc/__fss.h"

// #include "hfs_fs.h"
// #include "btree.h"

static struct kmem_cache *hfs_inode_cachep;

MODULE_LICENSE("GPL");

static int hfs_sync_fs(struct super_block *sb, int wait)
{
	hfs_mdb_commit(sb);
	return 0;
}

/*
 * hfs_put_super()
 *
 * This is the put_super() entry in the super_operations structure for
 * HFS filesystems.  The purpose is to release the resources
 * associated with the superblock sb.
 */
static void hfs_put_super(struct super_block *sb)
{
	cancel_delayed_work_sync(&HFS_SB(sb)->mdb_work);
	hfs_mdb_close(sb);
	/* release the MDB's resources */
	hfs_mdb_put(sb);
}

static void flush_mdb(struct work_struct *work)
{
	struct hfs_sb_info *sbi;
	struct super_block *sb;

	sbi = container_of(work, struct hfs_sb_info, mdb_work.work);
	sb = sbi->sb;

	spin_lock(&sbi->work_lock);
	sbi->work_queued = 0;
	spin_unlock(&sbi->work_lock);

	hfs_mdb_commit(sb);
}

void hfs_mark_mdb_dirty(struct super_block *sb)
{
	struct hfs_sb_info *sbi = HFS_SB(sb);
	unsigned long delay;

	if (sb->s_flags & MS_RDONLY)
		return;

	spin_lock(&sbi->work_lock);
	if (!sbi->work_queued) {
		delay = msecs_to_jiffies(dirty_writeback_interval * 10);
		queue_delayed_work(system_long_wq, &sbi->mdb_work, delay);
		sbi->work_queued = 1;
	}
	spin_unlock(&sbi->work_lock);
}

/*
 * hfs_statfs()
 *
 * This is the statfs() entry in the super_operations structure for
 * HFS filesystems.  The purpose is to return various data about the
 * filesystem.
 *
 * changed f_files/f_ffree to reflect the fs_ablock/free_ablocks.
 */
static int hfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type = HFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = (u32)HFS_SB(sb)->fs_ablocks * HFS_SB(sb)->fs_div;
	buf->f_bfree = (u32)HFS_SB(sb)->free_ablocks * HFS_SB(sb)->fs_div;
	buf->f_bavail = buf->f_bfree;
	buf->f_files = HFS_SB(sb)->fs_ablocks;
	buf->f_ffree = HFS_SB(sb)->free_ablocks;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = HFS_NAMELEN;

	return 0;
}

static int hfs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	*flags |= MS_NODIRATIME;
	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		return 0;
	if (!(*flags & MS_RDONLY)) {
		if (!(HFS_SB(sb)->mdb->drAtrb & cpu_to_be16(HFS_SB_ATTRIB_UNMNT))) {
			pr_warn("filesystem was not cleanly unmounted, running fsck.hfs is recommended.  leaving read-only.\n");
			sb->s_flags |= MS_RDONLY;
			*flags |= MS_RDONLY;
		} else if (HFS_SB(sb)->mdb->drAtrb & cpu_to_be16(HFS_SB_ATTRIB_SLOCK)) {
			pr_warn("filesystem is marked locked, leaving read-only.\n");
			sb->s_flags |= MS_RDONLY;
			*flags |= MS_RDONLY;
		}
	}
	return 0;
}

static int hfs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct hfs_sb_info *sbi = HFS_SB(root->d_sb);

	if (sbi->s_creator != cpu_to_be32(0x3f3f3f3f))
		seq_printf(seq, ",creator=%.4s", (char *)&sbi->s_creator);
	if (sbi->s_type != cpu_to_be32(0x3f3f3f3f))
		seq_printf(seq, ",type=%.4s", (char *)&sbi->s_type);
	seq_printf(seq, ",uid=%u,gid=%u",
			from_kuid_munged(&init_user_ns, sbi->s_uid),
			from_kgid_munged(&init_user_ns, sbi->s_gid));
	if (sbi->s_file_umask != 0133)
		seq_printf(seq, ",file_umask=%o", sbi->s_file_umask);
	if (sbi->s_dir_umask != 0022)
		seq_printf(seq, ",dir_umask=%o", sbi->s_dir_umask);
	if (sbi->part >= 0)
		seq_printf(seq, ",part=%u", sbi->part);
	if (sbi->session >= 0)
		seq_printf(seq, ",session=%u", sbi->session);
	if (sbi->nls_disk)
		seq_printf(seq, ",codepage=%s", sbi->nls_disk->charset);
	if (sbi->nls_io)
		seq_printf(seq, ",iocharset=%s", sbi->nls_io->charset);
	if (sbi->s_quiet)
		seq_printf(seq, ",quiet");
	return 0;
}

static struct inode *hfs_alloc_inode(struct super_block *sb)
{
	struct hfs_inode_info *i;

	i = kmem_cache_alloc(hfs_inode_cachep, GFP_KERNEL);
	return i ? &i->vfs_inode : NULL;
}

static void hfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(hfs_inode_cachep, HFS_I(inode));
}

static void hfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, hfs_i_callback);
}

static const struct super_operations hfs_super_operations = {
	.alloc_inode	= hfs_alloc_inode,
	.destroy_inode	= hfs_destroy_inode,
	.write_inode	= hfs_write_inode,
	.evict_inode	= hfs_evict_inode,
	.put_super	= hfs_put_super,
	.sync_fs	= hfs_sync_fs,
	.statfs		= hfs_statfs,
	.remount_fs     = hfs_remount,
	.show_options	= hfs_show_options,
};

enum {
	opt_uid, opt_gid, opt_umask, opt_file_umask, opt_dir_umask,
	opt_part, opt_session, opt_type, opt_creator, opt_quiet,
	opt_codepage, opt_iocharset,
	opt_err
};

static const match_table_t tokens = {
	{ opt_uid, "uid=%u" },
	{ opt_gid, "gid=%u" },
	{ opt_umask, "umask=%o" },
	{ opt_file_umask, "file_umask=%o" },
	{ opt_dir_umask, "dir_umask=%o" },
	{ opt_part, "part=%u" },
	{ opt_session, "session=%u" },
	{ opt_type, "type=%s" },
	{ opt_creator, "creator=%s" },
	{ opt_quiet, "quiet" },
	{ opt_codepage, "codepage=%s" },
	{ opt_iocharset, "iocharset=%s" },
	{ opt_err, NULL }
};

static inline int match_fourchar(substring_t *arg, u32 *result)
{
	if (arg->to - arg->from != 4)
		return -EINVAL;
	memcpy(result, arg->from, 4);
	return 0;
}

/*
 * parse_options()
 *
 * adapted from linux/fs/msdos/inode.c written 1992,93 by Werner Almesberger
 * This function is called by hfs_read_super() to parse the mount options.
 */
static int parse_options(char *options, struct hfs_sb_info *hsb)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int tmp, token;

	/* initialize the sb with defaults */
	hsb->s_uid = current_uid();
	hsb->s_gid = current_gid();
	hsb->s_file_umask = 0133;
	hsb->s_dir_umask = 0022;
	hsb->s_type = hsb->s_creator = cpu_to_be32(0x3f3f3f3f);	/* == '????' */
	hsb->s_quiet = 0;
	hsb->part = -1;
	hsb->session = -1;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case opt_uid:
			if (match_int(&args[0], &tmp)) {
				pr_err("uid requires an argument\n");
				return 0;
			}
			hsb->s_uid = make_kuid(current_user_ns(), (uid_t)tmp);
			if (!uid_valid(hsb->s_uid)) {
				pr_err("invalid uid %d\n", tmp);
				return 0;
			}
			break;
		case opt_gid:
			if (match_int(&args[0], &tmp)) {
				pr_err("gid requires an argument\n");
				return 0;
			}
			hsb->s_gid = make_kgid(current_user_ns(), (gid_t)tmp);
			if (!gid_valid(hsb->s_gid)) {
				pr_err("invalid gid %d\n", tmp);
				return 0;
			}
			break;
		case opt_umask:
			if (match_octal(&args[0], &tmp)) {
				pr_err("umask requires a value\n");
				return 0;
			}
			hsb->s_file_umask = (umode_t)tmp;
			hsb->s_dir_umask = (umode_t)tmp;
			break;
		case opt_file_umask:
			if (match_octal(&args[0], &tmp)) {
				pr_err("file_umask requires a value\n");
				return 0;
			}
			hsb->s_file_umask = (umode_t)tmp;
			break;
		case opt_dir_umask:
			if (match_octal(&args[0], &tmp)) {
				pr_err("dir_umask requires a value\n");
				return 0;
			}
			hsb->s_dir_umask = (umode_t)tmp;
			break;
		case opt_part:
			if (match_int(&args[0], &hsb->part)) {
				pr_err("part requires an argument\n");
				return 0;
			}
			break;
		case opt_session:
			if (match_int(&args[0], &hsb->session)) {
				pr_err("session requires an argument\n");
				return 0;
			}
			break;
		case opt_type:
			if (match_fourchar(&args[0], &hsb->s_type)) {
				pr_err("type requires a 4 character value\n");
				return 0;
			}
			break;
		case opt_creator:
			if (match_fourchar(&args[0], &hsb->s_creator)) {
				pr_err("creator requires a 4 character value\n");
				return 0;
			}
			break;
		case opt_quiet:
			hsb->s_quiet = 1;
			break;
		case opt_codepage:
			if (hsb->nls_disk) {
				pr_err("unable to change codepage\n");
				return 0;
			}
			p = match_strdup(&args[0]);
			if (p)
				hsb->nls_disk = load_nls(p);
			if (!hsb->nls_disk) {
				pr_err("unable to load codepage \"%s\"\n", p);
				kfree(p);
				return 0;
			}
			kfree(p);
			break;
		case opt_iocharset:
			if (hsb->nls_io) {
				pr_err("unable to change iocharset\n");
				return 0;
			}
			p = match_strdup(&args[0]);
			if (p)
				hsb->nls_io = load_nls(p);
			if (!hsb->nls_io) {
				pr_err("unable to load iocharset \"%s\"\n", p);
				kfree(p);
				return 0;
			}
			kfree(p);
			break;
		default:
			return 0;
		}
	}

	if (hsb->nls_disk && !hsb->nls_io) {
		hsb->nls_io = load_nls_default();
		if (!hsb->nls_io) {
			pr_err("unable to load default iocharset\n");
			return 0;
		}
	}
	hsb->s_dir_umask &= 0777;
	hsb->s_file_umask &= 0577;

	return 1;
}

/*
 * hfs_read_super()
 *
 * This is the function that is responsible for mounting an HFS
 * filesystem.	It performs all the tasks necessary to get enough data
 * from the disk to read the root inode.  This includes parsing the
 * mount options, dealing with Macintosh partitions, reading the
 * superblock and the allocation bitmap blocks, calling
 * hfs_btree_init() to get the necessary data about the extents and
 * catalog B-trees and, finally, reading the root inode into memory.
 */
static int hfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct hfs_sb_info *sbi;
	struct hfs_find_data fd;
	hfs_cat_rec rec;
	struct inode *root_inode;
	int res;

	sbi = kzalloc(sizeof(struct hfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sbi->sb = sb;
	sb->s_fs_info = sbi;
	spin_lock_init(&sbi->work_lock);
	INIT_DELAYED_WORK(&sbi->mdb_work, flush_mdb);

	res = -EINVAL;
	if (!parse_options((char *)data, sbi)) {
		pr_err("unable to parse mount options\n");
		goto bail;
	}

	sb->s_op = &hfs_super_operations;
	sb->s_flags |= MS_NODIRATIME;
	mutex_init(&sbi->bitmap_lock);

	res = hfs_mdb_get(sb);
	if (res) {
		if (!silent)
			pr_warn("can't find a HFS filesystem on dev %s\n",
				hfs_mdb_name(sb));
		res = -EINVAL;
		goto bail;
	}

	/* try to get the root inode */
	res = hfs_find_init(HFS_SB(sb)->cat_tree, &fd);
	if (res)
		goto bail_no_root;
	res = hfs_cat_find_brec(sb, HFS_ROOT_CNID, &fd);
	if (!res) {
		if (fd.entrylength > sizeof(rec) || fd.entrylength < 0) {
			res =  -EIO;
			goto bail;
		}
		hfs_bnode_read(fd.bnode, &rec, fd.entryoffset, fd.entrylength);
	}
	if (res) {
		hfs_find_exit(&fd);
		goto bail_no_root;
	}
	res = -EINVAL;
	root_inode = hfs_iget(sb, &fd.search_key->cat, &rec);
	hfs_find_exit(&fd);
	if (!root_inode)
		goto bail_no_root;

	sb->s_d_op = &hfs_dentry_operations;
	res = -ENOMEM;
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root)
		goto bail_no_root;

	/* everything's okay */
	return 0;

bail_no_root:
	pr_err("get root inode failed\n");
bail:
	hfs_mdb_put(sb);
	return res;
}

static struct dentry *hfs_mount(struct file_system_type *fs_type,
		      int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, hfs_fill_super);
}

static struct file_system_type hfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "hfs",
	.mount		= hfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("hfs");

static void hfs_init_once(void *p)
{
	struct hfs_inode_info *i = p;

	inode_init_once(&i->vfs_inode);
}

static int __init init_hfs_fs(void)
{
	int err;

	hfs_inode_cachep = kmem_cache_create("hfs_inode_cache",
		sizeof(struct hfs_inode_info), 0, SLAB_HWCACHE_ALIGN,
		hfs_init_once);
	if (!hfs_inode_cachep)
		return -ENOMEM;
	err = register_filesystem(&hfs_fs_type);
	if (err)
		kmem_cache_destroy(hfs_inode_cachep);
	return err;
}

static void __exit exit_hfs_fs(void)
{
	unregister_filesystem(&hfs_fs_type);

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(hfs_inode_cachep);
}

module_init(init_hfs_fs)
module_exit(exit_hfs_fs)
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/super.c */
/************************************************************/
/*
 *  linux/fs/hfs/sysdep.c
 *
 * Copyright (C) 1996  Paul H. Hargrove
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains the code to do various system dependent things.
 */

#include <linux/namei.h>
// #include "hfs_fs.h"
#include "../../inc/__fss.h"

/* dentry case-handling: just lowercase everything */

static int hfs_revalidate_dentry(struct dentry *dentry, unsigned int flags)
{
	struct inode *inode;
	int diff;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	inode = dentry->d_inode;
	if(!inode)
		return 1;

	/* fix up inode on a timezone change */
	diff = sys_tz.tz_minuteswest * 60 - HFS_I(inode)->tz_secondswest;
	if (diff) {
		inode->i_ctime.tv_sec += diff;
		inode->i_atime.tv_sec += diff;
		inode->i_mtime.tv_sec += diff;
		HFS_I(inode)->tz_secondswest += diff;
	}
	return 1;
}

const struct dentry_operations hfs_dentry_operations =
{
	.d_revalidate	= hfs_revalidate_dentry,
	.d_hash		= hfs_hash_dentry,
	.d_compare	= hfs_compare_dentry,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/sysdep.c */
/************************************************************/
/*
 *  linux/fs/hfs/trans.c
 *
 * Copyright (C) 1995-1997  Paul H. Hargrove
 * This file may be distributed under the terms of the GNU General Public License.
 *
 * This file contains routines for converting between the Macintosh
 * character set and various other encodings.  This includes dealing
 * with ':' vs. '/' as the path-element separator.
 */

#include <linux/types.h>
// #include <linux/nls.h>
#include "../../inc/__fss.h"

// #include "hfs_fs.h"

/*================ Global functions ================*/

/*
 * hfs_mac2asc()
 *
 * Given a 'Pascal String' (a string preceded by a length byte) in
 * the Macintosh character set produce the corresponding filename using
 * the 'trivial' name-mangling scheme, returning the length of the
 * mangled filename.  Note that the output string is not NULL
 * terminated.
 *
 * The name-mangling works as follows:
 * The character '/', which is illegal in Linux filenames is replaced
 * by ':' which never appears in HFS filenames.	 All other characters
 * are passed unchanged from input to output.
 */
int hfs_mac2asc(struct super_block *sb, char *out, const struct hfs_name *in)
{
	struct nls_table *nls_disk = HFS_SB(sb)->nls_disk;
	struct nls_table *nls_io = HFS_SB(sb)->nls_io;
	const char *src;
	char *dst;
	int srclen, dstlen, size;

	src = in->name;
	srclen = in->len;
	if (srclen > HFS_NAMELEN)
		srclen = HFS_NAMELEN;
	dst = out;
	dstlen = HFS_MAX_NAMELEN;
	if (nls_io) {
		wchar_t ch;

		while (srclen > 0) {
			if (nls_disk) {
				size = nls_disk->char2uni(src, srclen, &ch);
				if (size <= 0) {
					ch = '?';
					size = 1;
				}
				src += size;
				srclen -= size;
			} else {
				ch = *src++;
				srclen--;
			}
			if (ch == '/')
				ch = ':';
			size = nls_io->uni2char(ch, dst, dstlen);
			if (size < 0) {
				if (size == -ENAMETOOLONG)
					goto out;
				*dst = '?';
				size = 1;
			}
			dst += size;
			dstlen -= size;
		}
	} else {
		char ch;

		while (--srclen >= 0)
			*dst++ = (ch = *src++) == '/' ? ':' : ch;
	}
out:
	return dst - out;
}

/*
 * hfs_asc2mac()
 *
 * Given an ASCII string (not null-terminated) and its length,
 * generate the corresponding filename in the Macintosh character set
 * using the 'trivial' name-mangling scheme, returning the length of
 * the mangled filename.  Note that the output string is not NULL
 * terminated.
 *
 * This routine is a inverse to hfs_mac2triv().
 * A ':' is replaced by a '/'.
 */
void hfs_asc2mac(struct super_block *sb, struct hfs_name *out, struct qstr *in)
{
	struct nls_table *nls_disk = HFS_SB(sb)->nls_disk;
	struct nls_table *nls_io = HFS_SB(sb)->nls_io;
	const char *src;
	char *dst;
	int srclen, dstlen, size;

	src = in->name;
	srclen = in->len;
	dst = out->name;
	dstlen = HFS_NAMELEN;
	if (nls_io) {
		wchar_t ch;

		while (srclen > 0) {
			size = nls_io->char2uni(src, srclen, &ch);
			if (size < 0) {
				ch = '?';
				size = 1;
			}
			src += size;
			srclen -= size;
			if (ch == ':')
				ch = '/';
			if (nls_disk) {
				size = nls_disk->uni2char(ch, dst, dstlen);
				if (size < 0) {
					if (size == -ENAMETOOLONG)
						goto out;
					*dst = '?';
					size = 1;
				}
				dst += size;
				dstlen -= size;
			} else {
				*dst++ = ch > 0xff ? '?' : ch;
				dstlen--;
			}
		}
	} else {
		char ch;

		if (dstlen > srclen)
			dstlen = srclen;
		while (--dstlen >= 0)
			*dst++ = (ch = *src++) == ':' ? '/' : ch;
	}
out:
	out->len = dst - (char *)out->name;
	dstlen = HFS_NAMELEN - out->len;
	while (--dstlen >= 0)
		*dst++ = 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfs/trans.c */
/************************************************************/
