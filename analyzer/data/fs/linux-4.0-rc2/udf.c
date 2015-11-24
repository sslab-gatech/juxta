/*
 * balloc.c
 *
 * PURPOSE
 *	Block allocation handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 *
 *  (C) 1999-2001 Ben Fennema
 *  (C) 1999 Stelias Computing Inc
 *
 * HISTORY
 *
 *  02/24/99 blf  Created.
 *
 */

#include "udfdecl.h"
#include "../../inc/__fss.h"

#include <linux/buffer_head.h>
#include <linux/bitops.h>
#include "../../inc/__fss.h"

#include "udf_i.h"
#include "udf_sb.h"
#include "../../inc/__fss.h"

#define udf_clear_bit	__test_and_clear_bit_le
#define udf_set_bit	__test_and_set_bit_le
#define udf_test_bit	test_bit_le
#define udf_find_next_one_bit	find_next_bit_le

static int read_block_bitmap(struct super_block *sb,
			     struct udf_bitmap *bitmap, unsigned int block,
			     unsigned long bitmap_nr)
{
	struct buffer_head *bh = NULL;
	int retval = 0;
	struct kernel_lb_addr loc;

	loc.logicalBlockNum = bitmap->s_extPosition;
	loc.partitionReferenceNum = UDF_SB(sb)->s_partition;

	bh = udf_tread(sb, udf_get_lb_pblock(sb, &loc, block));
	if (!bh)
		retval = -EIO;

	bitmap->s_block_bitmap[bitmap_nr] = bh;
	return retval;
}

static int __load_block_bitmap(struct super_block *sb,
			       struct udf_bitmap *bitmap,
			       unsigned int block_group)
{
	int retval = 0;
	int nr_groups = bitmap->s_nr_groups;

	if (block_group >= nr_groups) {
		udf_debug("block_group (%d) > nr_groups (%d)\n",
			  block_group, nr_groups);
	}

	if (bitmap->s_block_bitmap[block_group]) {
		return block_group;
	} else {
		retval = read_block_bitmap(sb, bitmap, block_group,
					   block_group);
		if (retval < 0)
			return retval;
		return block_group;
	}
}

static inline int load_block_bitmap(struct super_block *sb,
				    struct udf_bitmap *bitmap,
				    unsigned int block_group)
{
	int slot;

	slot = __load_block_bitmap(sb, bitmap, block_group);

	if (slot < 0)
		return slot;

	if (!bitmap->s_block_bitmap[slot])
		return -EIO;

	return slot;
}

static void udf_add_free_space(struct super_block *sb, u16 partition, u32 cnt)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct logicalVolIntegrityDesc *lvid;

	if (!sbi->s_lvid_bh)
		return;

	lvid = (struct logicalVolIntegrityDesc *)sbi->s_lvid_bh->b_data;
	le32_add_cpu(&lvid->freeSpaceTable[partition], cnt);
	udf_updated_lvid(sb);
}

static void udf_bitmap_free_blocks(struct super_block *sb,
				   struct udf_bitmap *bitmap,
				   struct kernel_lb_addr *bloc,
				   uint32_t offset,
				   uint32_t count)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct buffer_head *bh = NULL;
	struct udf_part_map *partmap;
	unsigned long block;
	unsigned long block_group;
	unsigned long bit;
	unsigned long i;
	int bitmap_nr;
	unsigned long overflow;

	mutex_lock(&sbi->s_alloc_mutex);
	partmap = &sbi->s_partmaps[bloc->partitionReferenceNum];
	if (bloc->logicalBlockNum + count < count ||
	    (bloc->logicalBlockNum + count) > partmap->s_partition_len) {
		udf_debug("%d < %d || %d + %d > %d\n",
			  bloc->logicalBlockNum, 0,
			  bloc->logicalBlockNum, count,
			  partmap->s_partition_len);
		goto error_return;
	}

	block = bloc->logicalBlockNum + offset +
		(sizeof(struct spaceBitmapDesc) << 3);

	do {
		overflow = 0;
		block_group = block >> (sb->s_blocksize_bits + 3);
		bit = block % (sb->s_blocksize << 3);

		/*
		* Check to see if we are freeing blocks across a group boundary.
		*/
		if (bit + count > (sb->s_blocksize << 3)) {
			overflow = bit + count - (sb->s_blocksize << 3);
			count -= overflow;
		}
		bitmap_nr = load_block_bitmap(sb, bitmap, block_group);
		if (bitmap_nr < 0)
			goto error_return;

		bh = bitmap->s_block_bitmap[bitmap_nr];
		for (i = 0; i < count; i++) {
			if (udf_set_bit(bit + i, bh->b_data)) {
				udf_debug("bit %ld already set\n", bit + i);
				udf_debug("byte=%2x\n",
					  ((char *)bh->b_data)[(bit + i) >> 3]);
			}
		}
		udf_add_free_space(sb, sbi->s_partition, count);
		mark_buffer_dirty(bh);
		if (overflow) {
			block += count;
			count = overflow;
		}
	} while (overflow);

error_return:
	mutex_unlock(&sbi->s_alloc_mutex);
}

static int udf_bitmap_prealloc_blocks(struct super_block *sb,
				      struct udf_bitmap *bitmap,
				      uint16_t partition, uint32_t first_block,
				      uint32_t block_count)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	int alloc_count = 0;
	int bit, block, block_group, group_start;
	int nr_groups, bitmap_nr;
	struct buffer_head *bh;
	__u32 part_len;

	mutex_lock(&sbi->s_alloc_mutex);
	part_len = sbi->s_partmaps[partition].s_partition_len;
	if (first_block >= part_len)
		goto out;

	if (first_block + block_count > part_len)
		block_count = part_len - first_block;

	do {
		nr_groups = udf_compute_nr_groups(sb, partition);
		block = first_block + (sizeof(struct spaceBitmapDesc) << 3);
		block_group = block >> (sb->s_blocksize_bits + 3);
		group_start = block_group ? 0 : sizeof(struct spaceBitmapDesc);

		bitmap_nr = load_block_bitmap(sb, bitmap, block_group);
		if (bitmap_nr < 0)
			goto out;
		bh = bitmap->s_block_bitmap[bitmap_nr];

		bit = block % (sb->s_blocksize << 3);

		while (bit < (sb->s_blocksize << 3) && block_count > 0) {
			if (!udf_clear_bit(bit, bh->b_data))
				goto out;
			block_count--;
			alloc_count++;
			bit++;
			block++;
		}
		mark_buffer_dirty(bh);
	} while (block_count > 0);

out:
	udf_add_free_space(sb, partition, -alloc_count);
	mutex_unlock(&sbi->s_alloc_mutex);
	return alloc_count;
}

static int udf_bitmap_new_block(struct super_block *sb,
				struct udf_bitmap *bitmap, uint16_t partition,
				uint32_t goal, int *err)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	int newbit, bit = 0, block, block_group, group_start;
	int end_goal, nr_groups, bitmap_nr, i;
	struct buffer_head *bh = NULL;
	char *ptr;
	int newblock = 0;

	*err = -ENOSPC;
	mutex_lock(&sbi->s_alloc_mutex);

repeat:
	if (goal >= sbi->s_partmaps[partition].s_partition_len)
		goal = 0;

	nr_groups = bitmap->s_nr_groups;
	block = goal + (sizeof(struct spaceBitmapDesc) << 3);
	block_group = block >> (sb->s_blocksize_bits + 3);
	group_start = block_group ? 0 : sizeof(struct spaceBitmapDesc);

	bitmap_nr = load_block_bitmap(sb, bitmap, block_group);
	if (bitmap_nr < 0)
		goto error_return;
	bh = bitmap->s_block_bitmap[bitmap_nr];
	ptr = memscan((char *)bh->b_data + group_start, 0xFF,
		      sb->s_blocksize - group_start);

	if ((ptr - ((char *)bh->b_data)) < sb->s_blocksize) {
		bit = block % (sb->s_blocksize << 3);
		if (udf_test_bit(bit, bh->b_data))
			goto got_block;

		end_goal = (bit + 63) & ~63;
		bit = udf_find_next_one_bit(bh->b_data, end_goal, bit);
		if (bit < end_goal)
			goto got_block;

		ptr = memscan((char *)bh->b_data + (bit >> 3), 0xFF,
			      sb->s_blocksize - ((bit + 7) >> 3));
		newbit = (ptr - ((char *)bh->b_data)) << 3;
		if (newbit < sb->s_blocksize << 3) {
			bit = newbit;
			goto search_back;
		}

		newbit = udf_find_next_one_bit(bh->b_data,
					       sb->s_blocksize << 3, bit);
		if (newbit < sb->s_blocksize << 3) {
			bit = newbit;
			goto got_block;
		}
	}

	for (i = 0; i < (nr_groups * 2); i++) {
		block_group++;
		if (block_group >= nr_groups)
			block_group = 0;
		group_start = block_group ? 0 : sizeof(struct spaceBitmapDesc);

		bitmap_nr = load_block_bitmap(sb, bitmap, block_group);
		if (bitmap_nr < 0)
			goto error_return;
		bh = bitmap->s_block_bitmap[bitmap_nr];
		if (i < nr_groups) {
			ptr = memscan((char *)bh->b_data + group_start, 0xFF,
				      sb->s_blocksize - group_start);
			if ((ptr - ((char *)bh->b_data)) < sb->s_blocksize) {
				bit = (ptr - ((char *)bh->b_data)) << 3;
				break;
			}
		} else {
			bit = udf_find_next_one_bit(bh->b_data,
						    sb->s_blocksize << 3,
						    group_start << 3);
			if (bit < sb->s_blocksize << 3)
				break;
		}
	}
	if (i >= (nr_groups * 2)) {
		mutex_unlock(&sbi->s_alloc_mutex);
		return newblock;
	}
	if (bit < sb->s_blocksize << 3)
		goto search_back;
	else
		bit = udf_find_next_one_bit(bh->b_data, sb->s_blocksize << 3,
					    group_start << 3);
	if (bit >= sb->s_blocksize << 3) {
		mutex_unlock(&sbi->s_alloc_mutex);
		return 0;
	}

search_back:
	i = 0;
	while (i < 7 && bit > (group_start << 3) &&
	       udf_test_bit(bit - 1, bh->b_data)) {
		++i;
		--bit;
	}

got_block:
	newblock = bit + (block_group << (sb->s_blocksize_bits + 3)) -
		(sizeof(struct spaceBitmapDesc) << 3);

	if (!udf_clear_bit(bit, bh->b_data)) {
		udf_debug("bit already cleared for block %d\n", bit);
		goto repeat;
	}

	mark_buffer_dirty(bh);

	udf_add_free_space(sb, partition, -1);
	mutex_unlock(&sbi->s_alloc_mutex);
	*err = 0;
	return newblock;

error_return:
	*err = -EIO;
	mutex_unlock(&sbi->s_alloc_mutex);
	return 0;
}

static void udf_table_free_blocks(struct super_block *sb,
				  struct inode *table,
				  struct kernel_lb_addr *bloc,
				  uint32_t offset,
				  uint32_t count)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct udf_part_map *partmap;
	uint32_t start, end;
	uint32_t elen;
	struct kernel_lb_addr eloc;
	struct extent_position oepos, epos;
	int8_t etype;
	int i;
	struct udf_inode_info *iinfo;

	mutex_lock(&sbi->s_alloc_mutex);
	partmap = &sbi->s_partmaps[bloc->partitionReferenceNum];
	if (bloc->logicalBlockNum + count < count ||
	    (bloc->logicalBlockNum + count) > partmap->s_partition_len) {
		udf_debug("%d < %d || %d + %d > %d\n",
			  bloc->logicalBlockNum, 0,
			  bloc->logicalBlockNum, count,
			  partmap->s_partition_len);
		goto error_return;
	}

	iinfo = UDF_I(table);
	udf_add_free_space(sb, sbi->s_partition, count);

	start = bloc->logicalBlockNum + offset;
	end = bloc->logicalBlockNum + offset + count - 1;

	epos.offset = oepos.offset = sizeof(struct unallocSpaceEntry);
	elen = 0;
	epos.block = oepos.block = iinfo->i_location;
	epos.bh = oepos.bh = NULL;

	while (count &&
	       (etype = udf_next_aext(table, &epos, &eloc, &elen, 1)) != -1) {
		if (((eloc.logicalBlockNum +
			(elen >> sb->s_blocksize_bits)) == start)) {
			if ((0x3FFFFFFF - elen) <
					(count << sb->s_blocksize_bits)) {
				uint32_t tmp = ((0x3FFFFFFF - elen) >>
							sb->s_blocksize_bits);
				count -= tmp;
				start += tmp;
				elen = (etype << 30) |
					(0x40000000 - sb->s_blocksize);
			} else {
				elen = (etype << 30) |
					(elen +
					(count << sb->s_blocksize_bits));
				start += count;
				count = 0;
			}
			udf_write_aext(table, &oepos, &eloc, elen, 1);
		} else if (eloc.logicalBlockNum == (end + 1)) {
			if ((0x3FFFFFFF - elen) <
					(count << sb->s_blocksize_bits)) {
				uint32_t tmp = ((0x3FFFFFFF - elen) >>
						sb->s_blocksize_bits);
				count -= tmp;
				end -= tmp;
				eloc.logicalBlockNum -= tmp;
				elen = (etype << 30) |
					(0x40000000 - sb->s_blocksize);
			} else {
				eloc.logicalBlockNum = start;
				elen = (etype << 30) |
					(elen +
					(count << sb->s_blocksize_bits));
				end -= count;
				count = 0;
			}
			udf_write_aext(table, &oepos, &eloc, elen, 1);
		}

		if (epos.bh != oepos.bh) {
			i = -1;
			oepos.block = epos.block;
			brelse(oepos.bh);
			get_bh(epos.bh);
			oepos.bh = epos.bh;
			oepos.offset = 0;
		} else {
			oepos.offset = epos.offset;
		}
	}

	if (count) {
		/*
		 * NOTE: we CANNOT use udf_add_aext here, as it can try to
		 * allocate a new block, and since we hold the super block
		 * lock already very bad things would happen :)
		 *
		 * We copy the behavior of udf_add_aext, but instead of
		 * trying to allocate a new block close to the existing one,
		 * we just steal a block from the extent we are trying to add.
		 *
		 * It would be nice if the blocks were close together, but it
		 * isn't required.
		 */

		int adsize;
		struct short_ad *sad = NULL;
		struct long_ad *lad = NULL;
		struct allocExtDesc *aed;

		eloc.logicalBlockNum = start;
		elen = EXT_RECORDED_ALLOCATED |
			(count << sb->s_blocksize_bits);

		if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
			adsize = sizeof(struct short_ad);
		else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
			adsize = sizeof(struct long_ad);
		else {
			brelse(oepos.bh);
			brelse(epos.bh);
			goto error_return;
		}

		if (epos.offset + (2 * adsize) > sb->s_blocksize) {
			unsigned char *sptr, *dptr;
			int loffset;

			brelse(oepos.bh);
			oepos = epos;

			/* Steal a block from the extent being free'd */
			epos.block.logicalBlockNum = eloc.logicalBlockNum;
			eloc.logicalBlockNum++;
			elen -= sb->s_blocksize;

			epos.bh = udf_tread(sb,
					udf_get_lb_pblock(sb, &epos.block, 0));
			if (!epos.bh) {
				brelse(oepos.bh);
				goto error_return;
			}
			aed = (struct allocExtDesc *)(epos.bh->b_data);
			aed->previousAllocExtLocation =
				cpu_to_le32(oepos.block.logicalBlockNum);
			if (epos.offset + adsize > sb->s_blocksize) {
				loffset = epos.offset;
				aed->lengthAllocDescs = cpu_to_le32(adsize);
				sptr = iinfo->i_ext.i_data + epos.offset
								- adsize;
				dptr = epos.bh->b_data +
					sizeof(struct allocExtDesc);
				memcpy(dptr, sptr, adsize);
				epos.offset = sizeof(struct allocExtDesc) +
						adsize;
			} else {
				loffset = epos.offset + adsize;
				aed->lengthAllocDescs = cpu_to_le32(0);
				if (oepos.bh) {
					sptr = oepos.bh->b_data + epos.offset;
					aed = (struct allocExtDesc *)
						oepos.bh->b_data;
					le32_add_cpu(&aed->lengthAllocDescs,
							adsize);
				} else {
					sptr = iinfo->i_ext.i_data +
								epos.offset;
					iinfo->i_lenAlloc += adsize;
					mark_inode_dirty(table);
				}
				epos.offset = sizeof(struct allocExtDesc);
			}
			if (sbi->s_udfrev >= 0x0200)
				udf_new_tag(epos.bh->b_data, TAG_IDENT_AED,
					    3, 1, epos.block.logicalBlockNum,
					    sizeof(struct tag));
			else
				udf_new_tag(epos.bh->b_data, TAG_IDENT_AED,
					    2, 1, epos.block.logicalBlockNum,
					    sizeof(struct tag));

			switch (iinfo->i_alloc_type) {
			case ICBTAG_FLAG_AD_SHORT:
				sad = (struct short_ad *)sptr;
				sad->extLength = cpu_to_le32(
					EXT_NEXT_EXTENT_ALLOCDECS |
					sb->s_blocksize);
				sad->extPosition =
					cpu_to_le32(epos.block.logicalBlockNum);
				break;
			case ICBTAG_FLAG_AD_LONG:
				lad = (struct long_ad *)sptr;
				lad->extLength = cpu_to_le32(
					EXT_NEXT_EXTENT_ALLOCDECS |
					sb->s_blocksize);
				lad->extLocation =
					cpu_to_lelb(epos.block);
				break;
			}
			if (oepos.bh) {
				udf_update_tag(oepos.bh->b_data, loffset);
				mark_buffer_dirty(oepos.bh);
			} else {
				mark_inode_dirty(table);
			}
		}

		/* It's possible that stealing the block emptied the extent */
		if (elen) {
			udf_write_aext(table, &epos, &eloc, elen, 1);

			if (!epos.bh) {
				iinfo->i_lenAlloc += adsize;
				mark_inode_dirty(table);
			} else {
				aed = (struct allocExtDesc *)epos.bh->b_data;
				le32_add_cpu(&aed->lengthAllocDescs, adsize);
				udf_update_tag(epos.bh->b_data, epos.offset);
				mark_buffer_dirty(epos.bh);
			}
		}
	}

	brelse(epos.bh);
	brelse(oepos.bh);

error_return:
	mutex_unlock(&sbi->s_alloc_mutex);
	return;
}

static int udf_table_prealloc_blocks(struct super_block *sb,
				     struct inode *table, uint16_t partition,
				     uint32_t first_block, uint32_t block_count)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	int alloc_count = 0;
	uint32_t elen, adsize;
	struct kernel_lb_addr eloc;
	struct extent_position epos;
	int8_t etype = -1;
	struct udf_inode_info *iinfo;

	if (first_block >= sbi->s_partmaps[partition].s_partition_len)
		return 0;

	iinfo = UDF_I(table);
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		adsize = sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		adsize = sizeof(struct long_ad);
	else
		return 0;

	mutex_lock(&sbi->s_alloc_mutex);
	epos.offset = sizeof(struct unallocSpaceEntry);
	epos.block = iinfo->i_location;
	epos.bh = NULL;
	eloc.logicalBlockNum = 0xFFFFFFFF;

	while (first_block != eloc.logicalBlockNum &&
	       (etype = udf_next_aext(table, &epos, &eloc, &elen, 1)) != -1) {
		udf_debug("eloc=%d, elen=%d, first_block=%d\n",
			  eloc.logicalBlockNum, elen, first_block);
		; /* empty loop body */
	}

	if (first_block == eloc.logicalBlockNum) {
		epos.offset -= adsize;

		alloc_count = (elen >> sb->s_blocksize_bits);
		if (alloc_count > block_count) {
			alloc_count = block_count;
			eloc.logicalBlockNum += alloc_count;
			elen -= (alloc_count << sb->s_blocksize_bits);
			udf_write_aext(table, &epos, &eloc,
					(etype << 30) | elen, 1);
		} else
			udf_delete_aext(table, epos, eloc,
					(etype << 30) | elen);
	} else {
		alloc_count = 0;
	}

	brelse(epos.bh);

	if (alloc_count)
		udf_add_free_space(sb, partition, -alloc_count);
	mutex_unlock(&sbi->s_alloc_mutex);
	return alloc_count;
}

static int udf_table_new_block(struct super_block *sb,
			       struct inode *table, uint16_t partition,
			       uint32_t goal, int *err)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	uint32_t spread = 0xFFFFFFFF, nspread = 0xFFFFFFFF;
	uint32_t newblock = 0, adsize;
	uint32_t elen, goal_elen = 0;
	struct kernel_lb_addr eloc, uninitialized_var(goal_eloc);
	struct extent_position epos, goal_epos;
	int8_t etype;
	struct udf_inode_info *iinfo = UDF_I(table);

	*err = -ENOSPC;

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		adsize = sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		adsize = sizeof(struct long_ad);
	else
		return newblock;

	mutex_lock(&sbi->s_alloc_mutex);
	if (goal >= sbi->s_partmaps[partition].s_partition_len)
		goal = 0;

	/* We search for the closest matching block to goal. If we find
	   a exact hit, we stop. Otherwise we keep going till we run out
	   of extents. We store the buffer_head, bloc, and extoffset
	   of the current closest match and use that when we are done.
	 */
	epos.offset = sizeof(struct unallocSpaceEntry);
	epos.block = iinfo->i_location;
	epos.bh = goal_epos.bh = NULL;

	while (spread &&
	       (etype = udf_next_aext(table, &epos, &eloc, &elen, 1)) != -1) {
		if (goal >= eloc.logicalBlockNum) {
			if (goal < eloc.logicalBlockNum +
					(elen >> sb->s_blocksize_bits))
				nspread = 0;
			else
				nspread = goal - eloc.logicalBlockNum -
					(elen >> sb->s_blocksize_bits);
		} else {
			nspread = eloc.logicalBlockNum - goal;
		}

		if (nspread < spread) {
			spread = nspread;
			if (goal_epos.bh != epos.bh) {
				brelse(goal_epos.bh);
				goal_epos.bh = epos.bh;
				get_bh(goal_epos.bh);
			}
			goal_epos.block = epos.block;
			goal_epos.offset = epos.offset - adsize;
			goal_eloc = eloc;
			goal_elen = (etype << 30) | elen;
		}
	}

	brelse(epos.bh);

	if (spread == 0xFFFFFFFF) {
		brelse(goal_epos.bh);
		mutex_unlock(&sbi->s_alloc_mutex);
		return 0;
	}

	/* Only allocate blocks from the beginning of the extent.
	   That way, we only delete (empty) extents, never have to insert an
	   extent because of splitting */
	/* This works, but very poorly.... */

	newblock = goal_eloc.logicalBlockNum;
	goal_eloc.logicalBlockNum++;
	goal_elen -= sb->s_blocksize;

	if (goal_elen)
		udf_write_aext(table, &goal_epos, &goal_eloc, goal_elen, 1);
	else
		udf_delete_aext(table, goal_epos, goal_eloc, goal_elen);
	brelse(goal_epos.bh);

	udf_add_free_space(sb, partition, -1);

	mutex_unlock(&sbi->s_alloc_mutex);
	*err = 0;
	return newblock;
}

void udf_free_blocks(struct super_block *sb, struct inode *inode,
		     struct kernel_lb_addr *bloc, uint32_t offset,
		     uint32_t count)
{
	uint16_t partition = bloc->partitionReferenceNum;
	struct udf_part_map *map = &UDF_SB(sb)->s_partmaps[partition];

	if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_BITMAP) {
		udf_bitmap_free_blocks(sb, map->s_uspace.s_bitmap,
				       bloc, offset, count);
	} else if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_TABLE) {
		udf_table_free_blocks(sb, map->s_uspace.s_table,
				      bloc, offset, count);
	} else if (map->s_partition_flags & UDF_PART_FLAG_FREED_BITMAP) {
		udf_bitmap_free_blocks(sb, map->s_fspace.s_bitmap,
				       bloc, offset, count);
	} else if (map->s_partition_flags & UDF_PART_FLAG_FREED_TABLE) {
		udf_table_free_blocks(sb, map->s_fspace.s_table,
				      bloc, offset, count);
	}

	if (inode) {
		inode_sub_bytes(inode,
				((sector_t)count) << sb->s_blocksize_bits);
	}
}

inline int udf_prealloc_blocks(struct super_block *sb,
			       struct inode *inode,
			       uint16_t partition, uint32_t first_block,
			       uint32_t block_count)
{
	struct udf_part_map *map = &UDF_SB(sb)->s_partmaps[partition];
	sector_t allocated;

	if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_BITMAP)
		allocated = udf_bitmap_prealloc_blocks(sb,
						       map->s_uspace.s_bitmap,
						       partition, first_block,
						       block_count);
	else if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_TABLE)
		allocated = udf_table_prealloc_blocks(sb,
						      map->s_uspace.s_table,
						      partition, first_block,
						      block_count);
	else if (map->s_partition_flags & UDF_PART_FLAG_FREED_BITMAP)
		allocated = udf_bitmap_prealloc_blocks(sb,
						       map->s_fspace.s_bitmap,
						       partition, first_block,
						       block_count);
	else if (map->s_partition_flags & UDF_PART_FLAG_FREED_TABLE)
		allocated = udf_table_prealloc_blocks(sb,
						      map->s_fspace.s_table,
						      partition, first_block,
						      block_count);
	else
		return 0;

	if (inode && allocated > 0)
		inode_add_bytes(inode, allocated << sb->s_blocksize_bits);
	return allocated;
}

inline int udf_new_block(struct super_block *sb,
			 struct inode *inode,
			 uint16_t partition, uint32_t goal, int *err)
{
	struct udf_part_map *map = &UDF_SB(sb)->s_partmaps[partition];
	int block;

	if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_BITMAP)
		block = udf_bitmap_new_block(sb,
					     map->s_uspace.s_bitmap,
					     partition, goal, err);
	else if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_TABLE)
		block = udf_table_new_block(sb,
					    map->s_uspace.s_table,
					    partition, goal, err);
	else if (map->s_partition_flags & UDF_PART_FLAG_FREED_BITMAP)
		block = udf_bitmap_new_block(sb,
					     map->s_fspace.s_bitmap,
					     partition, goal, err);
	else if (map->s_partition_flags & UDF_PART_FLAG_FREED_TABLE)
		block = udf_table_new_block(sb,
					    map->s_fspace.s_table,
					    partition, goal, err);
	else {
		*err = -EIO;
		return 0;
	}
	if (inode && block)
		inode_add_bytes(inode, sb->s_blocksize);
	return block;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/balloc.c */
/************************************************************/
/*
 * dir.c
 *
 * PURPOSE
 *  Directory handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 *
 *  (C) 1998-2004 Ben Fennema
 *
 * HISTORY
 *
 *  10/05/98 dgb  Split directory operations into its own file
 *                Implemented directory reads via do_udf_readdir
 *  10/06/98      Made directory operations work!
 *  11/17/98      Rewrote directory to support ICBTAG_FLAG_AD_LONG
 *  11/25/98 blf  Rewrote directory handling (readdir+lookup) to support reading
 *                across blocks.
 *  12/12/98      Split out the lookup code to namei.c. bulk of directory
 *                code now in directory.c:udf_fileident_read.
 */

// #include "udfdecl.h"

#include <linux/string.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
// #include <linux/buffer_head.h>
#include "../../inc/__fss.h"

// #include "udf_i.h"
// #include "udf_sb.h"


static int udf_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *dir = file_inode(file);
	struct udf_inode_info *iinfo = UDF_I(dir);
	struct udf_fileident_bh fibh = { .sbh = NULL, .ebh = NULL};
	struct fileIdentDesc *fi = NULL;
	struct fileIdentDesc cfi;
	int block, iblock;
	loff_t nf_pos;
	int flen;
	unsigned char *fname = NULL;
	unsigned char *nameptr;
	uint16_t liu;
	uint8_t lfi;
	loff_t size = udf_ext0_offset(dir) + dir->i_size;
	struct buffer_head *tmp, *bha[16];
	struct kernel_lb_addr eloc;
	uint32_t elen;
	sector_t offset;
	int i, num, ret = 0;
	struct extent_position epos = { NULL, 0, {0, 0} };
	struct super_block *sb = dir->i_sb;

	if (ctx->pos == 0) {
		if (!dir_emit_dot(file, ctx))
			return 0;
		ctx->pos = 1;
	}
	nf_pos = (ctx->pos - 1) << 2;
	if (nf_pos >= size)
		goto out;

	fname = kmalloc(UDF_NAME_LEN, GFP_NOFS);
	if (!fname) {
		ret = -ENOMEM;
		goto out;
	}

	if (nf_pos == 0)
		nf_pos = udf_ext0_offset(dir);

	fibh.soffset = fibh.eoffset = nf_pos & (sb->s_blocksize - 1);
	if (iinfo->i_alloc_type != ICBTAG_FLAG_AD_IN_ICB) {
		if (inode_bmap(dir, nf_pos >> sb->s_blocksize_bits,
		    &epos, &eloc, &elen, &offset)
		    != (EXT_RECORDED_ALLOCATED >> 30)) {
			ret = -ENOENT;
			goto out;
		}
		block = udf_get_lb_pblock(sb, &eloc, offset);
		if ((++offset << sb->s_blocksize_bits) < elen) {
			if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
				epos.offset -= sizeof(struct short_ad);
			else if (iinfo->i_alloc_type ==
					ICBTAG_FLAG_AD_LONG)
				epos.offset -= sizeof(struct long_ad);
		} else {
			offset = 0;
		}

		if (!(fibh.sbh = fibh.ebh = udf_tread(sb, block))) {
			ret = -EIO;
			goto out;
		}

		if (!(offset & ((16 >> (sb->s_blocksize_bits - 9)) - 1))) {
			i = 16 >> (sb->s_blocksize_bits - 9);
			if (i + offset > (elen >> sb->s_blocksize_bits))
				i = (elen >> sb->s_blocksize_bits) - offset;
			for (num = 0; i > 0; i--) {
				block = udf_get_lb_pblock(sb, &eloc, offset + i);
				tmp = udf_tgetblk(sb, block);
				if (tmp && !buffer_uptodate(tmp) && !buffer_locked(tmp))
					bha[num++] = tmp;
				else
					brelse(tmp);
			}
			if (num) {
				ll_rw_block(READA, num, bha);
				for (i = 0; i < num; i++)
					brelse(bha[i]);
			}
		}
	}

	while (nf_pos < size) {
		struct kernel_lb_addr tloc;

		ctx->pos = (nf_pos >> 2) + 1;

		fi = udf_fileident_read(dir, &nf_pos, &fibh, &cfi, &epos, &eloc,
					&elen, &offset);
		if (!fi)
			goto out;

		liu = le16_to_cpu(cfi.lengthOfImpUse);
		lfi = cfi.lengthFileIdent;

		if (fibh.sbh == fibh.ebh) {
			nameptr = fi->fileIdent + liu;
		} else {
			int poffset;	/* Unpaded ending offset */

			poffset = fibh.soffset + sizeof(struct fileIdentDesc) + liu + lfi;

			if (poffset >= lfi) {
				nameptr = (char *)(fibh.ebh->b_data + poffset - lfi);
			} else {
				nameptr = fname;
				memcpy(nameptr, fi->fileIdent + liu,
				       lfi - poffset);
				memcpy(nameptr + lfi - poffset,
				       fibh.ebh->b_data, poffset);
			}
		}

		if ((cfi.fileCharacteristics & FID_FILE_CHAR_DELETED) != 0) {
			if (!UDF_QUERY_FLAG(sb, UDF_FLAG_UNDELETE))
				continue;
		}

		if ((cfi.fileCharacteristics & FID_FILE_CHAR_HIDDEN) != 0) {
			if (!UDF_QUERY_FLAG(sb, UDF_FLAG_UNHIDE))
				continue;
		}

		if (cfi.fileCharacteristics & FID_FILE_CHAR_PARENT) {
			if (!dir_emit_dotdot(file, ctx))
				goto out;
			continue;
		}

		flen = udf_get_filename(sb, nameptr, lfi, fname, UDF_NAME_LEN);
		if (!flen)
			continue;

		tloc = lelb_to_cpu(cfi.icb.extLocation);
		iblock = udf_get_lb_pblock(sb, &tloc, 0);
		if (!dir_emit(ctx, fname, flen, iblock, DT_UNKNOWN))
			goto out;
	} /* end while */

	ctx->pos = (nf_pos >> 2) + 1;

out:
	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);
	brelse(epos.bh);
	kfree(fname);

	return ret;
}

/* readdir and lookup functions */
const struct file_operations udf_dir_operations = {
	.llseek			= generic_file_llseek,
	.read			= generic_read_dir,
	.iterate		= udf_readdir,
	.unlocked_ioctl		= udf_ioctl,
	.fsync			= generic_file_fsync,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/dir.c */
/************************************************************/
/*
 * file.c
 *
 * PURPOSE
 *  File handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *  This file is distributed under the terms of the GNU General Public
 *  License (GPL). Copies of the GPL can be obtained from:
 *    ftp://prep.ai.mit.edu/pub/gnu/GPL
 *  Each contributing author retains all rights to their own work.
 *
 *  (C) 1998-1999 Dave Boynton
 *  (C) 1998-2004 Ben Fennema
 *  (C) 1999-2000 Stelias Computing Inc
 *
 * HISTORY
 *
 *  10/02/98 dgb  Attempt to integrate into udf.o
 *  10/07/98      Switched to using generic_readpage, etc., like isofs
 *                And it works!
 *  12/06/98 blf  Added udf_file_read. uses generic_file_read for all cases but
 *                ICBTAG_FLAG_AD_IN_ICB.
 *  04/06/99      64 bit file handling on 32 bit systems taken from ext2 file.c
 *  05/12/99      Preliminary file write support
 */

// #include "udfdecl.h"
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
// #include <linux/string.h> /* memset */
#include <linux/capability.h>
// #include <linux/errno.h>
#include <linux/pagemap.h>
// #include <linux/buffer_head.h>
#include <linux/aio.h>
#include "../../inc/__fss.h"

// #include "udf_i.h"
// #include "udf_sb.h"

static void __udf_adinicb_readpage(struct page *page)
{
	struct inode *inode = page->mapping->host;
	char *kaddr;
	struct udf_inode_info *iinfo = UDF_I(inode);

	kaddr = kmap(page);
	memcpy(kaddr, iinfo->i_ext.i_data + iinfo->i_lenEAttr, inode->i_size);
	memset(kaddr + inode->i_size, 0, PAGE_CACHE_SIZE - inode->i_size);
	flush_dcache_page(page);
	SetPageUptodate(page);
	kunmap(page);
}

static int udf_adinicb_readpage(struct file *file, struct page *page)
{
	BUG_ON(!PageLocked(page));
	__udf_adinicb_readpage(page);
	unlock_page(page);

	return 0;
}

static int udf_adinicb_writepage(struct page *page,
				 struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	char *kaddr;
	struct udf_inode_info *iinfo = UDF_I(inode);

	BUG_ON(!PageLocked(page));

	kaddr = kmap(page);
	memcpy(iinfo->i_ext.i_data + iinfo->i_lenEAttr, kaddr, inode->i_size);
	mark_inode_dirty(inode);
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);

	return 0;
}

static int udf_adinicb_write_begin(struct file *file,
			struct address_space *mapping, loff_t pos,
			unsigned len, unsigned flags, struct page **pagep,
			void **fsdata)
{
	struct page *page;

	if (WARN_ON_ONCE(pos >= PAGE_CACHE_SIZE))
		return -EIO;
	page = grab_cache_page_write_begin(mapping, 0, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	if (!PageUptodate(page) && len != PAGE_CACHE_SIZE)
		__udf_adinicb_readpage(page);
	return 0;
}

static ssize_t udf_adinicb_direct_IO(int rw, struct kiocb *iocb,
				     struct iov_iter *iter,
				     loff_t offset)
{
	/* Fallback to buffered I/O. */
	return 0;
}

const struct address_space_operations udf_adinicb_aops = {
	.readpage	= udf_adinicb_readpage,
	.writepage	= udf_adinicb_writepage,
	.write_begin	= udf_adinicb_write_begin,
	.write_end	= simple_write_end,
	.direct_IO	= udf_adinicb_direct_IO,
};

static ssize_t udf_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	ssize_t retval;
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	int err, pos;
	size_t count = iocb->ki_nbytes;
	struct udf_inode_info *iinfo = UDF_I(inode);

	mutex_lock(&inode->i_mutex);
	down_write(&iinfo->i_data_sem);
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
		if (file->f_flags & O_APPEND)
			pos = inode->i_size;
		else
			pos = iocb->ki_pos;

		if (inode->i_sb->s_blocksize <
				(udf_file_entry_alloc_offset(inode) +
						pos + count)) {
			err = udf_expand_file_adinicb(inode);
			if (err) {
				mutex_unlock(&inode->i_mutex);
				udf_debug("udf_expand_adinicb: err=%d\n", err);
				return err;
			}
		} else {
			if (pos + count > inode->i_size)
				iinfo->i_lenAlloc = pos + count;
			else
				iinfo->i_lenAlloc = inode->i_size;
			up_write(&iinfo->i_data_sem);
		}
	} else
		up_write(&iinfo->i_data_sem);

	retval = __generic_file_write_iter(iocb, from);
	mutex_unlock(&inode->i_mutex);

	if (retval > 0) {
		ssize_t err;

		mark_inode_dirty(inode);
		err = generic_write_sync(file, iocb->ki_pos - retval, retval);
		if (err < 0)
			retval = err;
	}

	return retval;
}

long udf_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	long old_block, new_block;
	int result = -EINVAL;

	if (inode_permission(inode, MAY_READ) != 0) {
		udf_debug("no permission to access inode %lu\n", inode->i_ino);
		result = -EPERM;
		goto out;
	}

	if (!arg) {
		udf_debug("invalid argument to udf_ioctl\n");
		result = -EINVAL;
		goto out;
	}

	switch (cmd) {
	case UDF_GETVOLIDENT:
		if (copy_to_user((char __user *)arg,
				 UDF_SB(inode->i_sb)->s_volume_ident, 32))
			result = -EFAULT;
		else
			result = 0;
		goto out;
	case UDF_RELOCATE_BLOCKS:
		if (!capable(CAP_SYS_ADMIN)) {
			result = -EPERM;
			goto out;
		}
		if (get_user(old_block, (long __user *)arg)) {
			result = -EFAULT;
			goto out;
		}
		result = udf_relocate_blocks(inode->i_sb,
						old_block, &new_block);
		if (result == 0)
			result = put_user(new_block, (long __user *)arg);
		goto out;
	case UDF_GETEASIZE:
		result = put_user(UDF_I(inode)->i_lenEAttr, (int __user *)arg);
		goto out;
	case UDF_GETEABLOCK:
		result = copy_to_user((char __user *)arg,
				      UDF_I(inode)->i_ext.i_data,
				      UDF_I(inode)->i_lenEAttr) ? -EFAULT : 0;
		goto out;
	}

out:
	return result;
}

static int udf_release_file(struct inode *inode, struct file *filp)
{
	if (filp->f_mode & FMODE_WRITE &&
	    atomic_read(&inode->i_writecount) == 1) {
		/*
		 * Grab i_mutex to avoid races with writes changing i_size
		 * while we are running.
		 */
		mutex_lock(&inode->i_mutex);
		down_write(&UDF_I(inode)->i_data_sem);
		udf_discard_prealloc(inode);
		udf_truncate_tail_extent(inode);
		up_write(&UDF_I(inode)->i_data_sem);
		mutex_unlock(&inode->i_mutex);
	}
	return 0;
}

const struct file_operations udf_file_operations = {
	.read			= new_sync_read,
	.read_iter		= generic_file_read_iter,
	.unlocked_ioctl		= udf_ioctl,
	.open			= generic_file_open,
	.mmap			= generic_file_mmap,
	.write			= new_sync_write,
	.write_iter		= udf_file_write_iter,
	.release		= udf_release_file,
	.fsync			= generic_file_fsync,
	.splice_read		= generic_file_splice_read,
	.llseek			= generic_file_llseek,
};

static int udf_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = udf_setsize(inode, attr->ia_size);
		if (error)
			return error;
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations udf_file_inode_operations = {
	.setattr		= udf_setattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/file.c */
/************************************************************/
/*
 * ialloc.c
 *
 * PURPOSE
 *	Inode allocation handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 *
 *  (C) 1998-2001 Ben Fennema
 *
 * HISTORY
 *
 *  02/24/99 blf  Created.
 *
 */

// #include "udfdecl.h"
// #include <linux/fs.h>
#include <linux/sched.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

// #include "udf_i.h"
// #include "udf_sb.h"

void udf_free_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct logicalVolIntegrityDescImpUse *lvidiu = udf_sb_lvidiu(sb);

	if (lvidiu) {
		mutex_lock(&sbi->s_alloc_mutex);
		if (S_ISDIR(inode->i_mode))
			le32_add_cpu(&lvidiu->numDirs, -1);
		else
			le32_add_cpu(&lvidiu->numFiles, -1);
		udf_updated_lvid(sb);
		mutex_unlock(&sbi->s_alloc_mutex);
	}

	udf_free_blocks(sb, NULL, &UDF_I(inode)->i_location, 0, 1);
}

struct inode *udf_new_inode(struct inode *dir, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct inode *inode;
	int block;
	uint32_t start = UDF_I(dir)->i_location.logicalBlockNum;
	struct udf_inode_info *iinfo;
	struct udf_inode_info *dinfo = UDF_I(dir);
	struct logicalVolIntegrityDescImpUse *lvidiu;
	int err;

	inode = new_inode(sb);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	iinfo = UDF_I(inode);
	if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_USE_EXTENDED_FE)) {
		iinfo->i_efe = 1;
		if (UDF_VERS_USE_EXTENDED_FE > sbi->s_udfrev)
			sbi->s_udfrev = UDF_VERS_USE_EXTENDED_FE;
		iinfo->i_ext.i_data = kzalloc(inode->i_sb->s_blocksize -
					    sizeof(struct extendedFileEntry),
					    GFP_KERNEL);
	} else {
		iinfo->i_efe = 0;
		iinfo->i_ext.i_data = kzalloc(inode->i_sb->s_blocksize -
					    sizeof(struct fileEntry),
					    GFP_KERNEL);
	}
	if (!iinfo->i_ext.i_data) {
		iput(inode);
		return ERR_PTR(-ENOMEM);
	}

	err = -ENOSPC;
	block = udf_new_block(dir->i_sb, NULL,
			      dinfo->i_location.partitionReferenceNum,
			      start, &err);
	if (err) {
		iput(inode);
		return ERR_PTR(err);
	}

	lvidiu = udf_sb_lvidiu(sb);
	if (lvidiu) {
		iinfo->i_unique = lvid_get_unique_id(sb);
		inode->i_generation = iinfo->i_unique;
		mutex_lock(&sbi->s_alloc_mutex);
		if (S_ISDIR(mode))
			le32_add_cpu(&lvidiu->numDirs, 1);
		else
			le32_add_cpu(&lvidiu->numFiles, 1);
		udf_updated_lvid(sb);
		mutex_unlock(&sbi->s_alloc_mutex);
	}

	inode_init_owner(inode, dir, mode);

	iinfo->i_location.logicalBlockNum = block;
	iinfo->i_location.partitionReferenceNum =
				dinfo->i_location.partitionReferenceNum;
	inode->i_ino = udf_get_lb_pblock(sb, &iinfo->i_location, 0);
	inode->i_blocks = 0;
	iinfo->i_lenEAttr = 0;
	iinfo->i_lenAlloc = 0;
	iinfo->i_use = 0;
	iinfo->i_checkpoint = 1;
	if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_USE_AD_IN_ICB))
		iinfo->i_alloc_type = ICBTAG_FLAG_AD_IN_ICB;
	else if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_USE_SHORT_AD))
		iinfo->i_alloc_type = ICBTAG_FLAG_AD_SHORT;
	else
		iinfo->i_alloc_type = ICBTAG_FLAG_AD_LONG;
	inode->i_mtime = inode->i_atime = inode->i_ctime =
		iinfo->i_crtime = current_fs_time(inode->i_sb);
	if (unlikely(insert_inode_locked(inode) < 0)) {
		make_bad_inode(inode);
		iput(inode);
		return ERR_PTR(-EIO);
	}
	mark_inode_dirty(inode);

	return inode;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/ialloc.c */
/************************************************************/
/*
 * inode.c
 *
 * PURPOSE
 *  Inode handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *  This file is distributed under the terms of the GNU General Public
 *  License (GPL). Copies of the GPL can be obtained from:
 *    ftp://prep.ai.mit.edu/pub/gnu/GPL
 *  Each contributing author retains all rights to their own work.
 *
 *  (C) 1998 Dave Boynton
 *  (C) 1998-2004 Ben Fennema
 *  (C) 1999-2000 Stelias Computing Inc
 *
 * HISTORY
 *
 *  10/04/98 dgb  Added rudimentary directory functions
 *  10/07/98      Fully working udf_block_map! It works!
 *  11/25/98      bmap altered to better support extents
 *  12/06/98 blf  partition support in udf_iget, udf_block_map
 *                and udf_read_inode
 *  12/12/98      rewrote udf_block_map to handle next extents and descs across
 *                block boundaries (which is not actually allowed)
 *  12/20/98      added support for strategy 4096
 *  03/07/99      rewrote udf_block_map (again)
 *                New funcs, inode_bmap, udf_next_aext
 *  04/19/99      Support for writing device EA's for major/minor #
 */

// #include "udfdecl.h"
// #include <linux/mm.h>
#include <linux/module.h>
// #include <linux/pagemap.h>
// #include <linux/buffer_head.h>
#include <linux/writeback.h>
// #include <linux/slab.h>
#include <linux/crc-itu-t.h>
#include <linux/mpage.h>
// #include <linux/aio.h>
#include "../../inc/__fss.h"

// #include "udf_i.h"
// #include "udf_sb.h"

MODULE_AUTHOR("Ben Fennema");
MODULE_DESCRIPTION("Universal Disk Format Filesystem");
MODULE_LICENSE("GPL");

#define EXTENT_MERGE_SIZE 5

static umode_t udf_convert_permissions(struct fileEntry *);
static int udf_update_inode(struct inode *, int);
static int udf_sync_inode(struct inode *inode);
static int udf_alloc_i_data(struct inode *inode, size_t size);
static sector_t inode_getblk(struct inode *, sector_t, int *, int *);
static int8_t udf_insert_aext(struct inode *, struct extent_position,
			      struct kernel_lb_addr, uint32_t);
static void udf_split_extents(struct inode *, int *, int, int,
			      struct kernel_long_ad[EXTENT_MERGE_SIZE], int *);
static void udf_prealloc_extents(struct inode *, int, int,
				 struct kernel_long_ad[EXTENT_MERGE_SIZE], int *);
static void udf_merge_extents(struct inode *,
			      struct kernel_long_ad[EXTENT_MERGE_SIZE], int *);
static void udf_update_extents(struct inode *,
			       struct kernel_long_ad[EXTENT_MERGE_SIZE], int, int,
			       struct extent_position *);
static int udf_get_block(struct inode *, sector_t, struct buffer_head *, int);

static void __udf_clear_extent_cache(struct inode *inode)
{
	struct udf_inode_info *iinfo = UDF_I(inode);

	if (iinfo->cached_extent.lstart != -1) {
		brelse(iinfo->cached_extent.epos.bh);
		iinfo->cached_extent.lstart = -1;
	}
}

/* Invalidate extent cache */
static void udf_clear_extent_cache(struct inode *inode)
{
	struct udf_inode_info *iinfo = UDF_I(inode);

	spin_lock(&iinfo->i_extent_cache_lock);
	__udf_clear_extent_cache(inode);
	spin_unlock(&iinfo->i_extent_cache_lock);
}

/* Return contents of extent cache */
static int udf_read_extent_cache(struct inode *inode, loff_t bcount,
				 loff_t *lbcount, struct extent_position *pos)
{
	struct udf_inode_info *iinfo = UDF_I(inode);
	int ret = 0;

	spin_lock(&iinfo->i_extent_cache_lock);
	if ((iinfo->cached_extent.lstart <= bcount) &&
	    (iinfo->cached_extent.lstart != -1)) {
		/* Cache hit */
		*lbcount = iinfo->cached_extent.lstart;
		memcpy(pos, &iinfo->cached_extent.epos,
		       sizeof(struct extent_position));
		if (pos->bh)
			get_bh(pos->bh);
		ret = 1;
	}
	spin_unlock(&iinfo->i_extent_cache_lock);
	return ret;
}

/* Add extent to extent cache */
static void udf_update_extent_cache(struct inode *inode, loff_t estart,
				    struct extent_position *pos, int next_epos)
{
	struct udf_inode_info *iinfo = UDF_I(inode);

	spin_lock(&iinfo->i_extent_cache_lock);
	/* Invalidate previously cached extent */
	__udf_clear_extent_cache(inode);
	if (pos->bh)
		get_bh(pos->bh);
	memcpy(&iinfo->cached_extent.epos, pos,
	       sizeof(struct extent_position));
	iinfo->cached_extent.lstart = estart;
	if (next_epos)
		switch (iinfo->i_alloc_type) {
		case ICBTAG_FLAG_AD_SHORT:
			iinfo->cached_extent.epos.offset -=
			sizeof(struct short_ad);
			break;
		case ICBTAG_FLAG_AD_LONG:
			iinfo->cached_extent.epos.offset -=
			sizeof(struct long_ad);
		}
	spin_unlock(&iinfo->i_extent_cache_lock);
}

void udf_evict_inode(struct inode *inode)
{
	struct udf_inode_info *iinfo = UDF_I(inode);
	int want_delete = 0;

	if (!inode->i_nlink && !is_bad_inode(inode)) {
		want_delete = 1;
		udf_setsize(inode, 0);
		udf_update_inode(inode, IS_SYNC(inode));
	}
	truncate_inode_pages_final(&inode->i_data);
	invalidate_inode_buffers(inode);
	clear_inode(inode);
	if (iinfo->i_alloc_type != ICBTAG_FLAG_AD_IN_ICB &&
	    inode->i_size != iinfo->i_lenExtents) {
		udf_warn(inode->i_sb, "Inode %lu (mode %o) has inode size %llu different from extent length %llu. Filesystem need not be standards compliant.\n",
			 inode->i_ino, inode->i_mode,
			 (unsigned long long)inode->i_size,
			 (unsigned long long)iinfo->i_lenExtents);
	}
	kfree(iinfo->i_ext.i_data);
	iinfo->i_ext.i_data = NULL;
	udf_clear_extent_cache(inode);
	if (want_delete) {
		udf_free_inode(inode);
	}
}

static void udf_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;
	struct udf_inode_info *iinfo = UDF_I(inode);
	loff_t isize = inode->i_size;

	if (to > isize) {
		truncate_pagecache(inode, isize);
		if (iinfo->i_alloc_type != ICBTAG_FLAG_AD_IN_ICB) {
			down_write(&iinfo->i_data_sem);
			udf_clear_extent_cache(inode);
			udf_truncate_extents(inode);
			up_write(&iinfo->i_data_sem);
		}
	}
}

static int udf_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, udf_get_block, wbc);
}

static int udf_writepages(struct address_space *mapping,
			struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, udf_get_block);
}

static int udf_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, udf_get_block);
}

static int udf_readpages(struct file *file, struct address_space *mapping,
			struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, udf_get_block);
}

static int udf_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep, udf_get_block);
	if (unlikely(ret))
		udf_write_failed(mapping, pos + len);
	return ret;
}

static ssize_t udf_direct_IO(int rw, struct kiocb *iocb,
			     struct iov_iter *iter,
			     loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	size_t count = iov_iter_count(iter);
	ssize_t ret;

	ret = blockdev_direct_IO(rw, iocb, inode, iter, offset, udf_get_block);
	if (unlikely(ret < 0 && (rw & WRITE)))
		udf_write_failed(mapping, offset + count);
	return ret;
}

static sector_t udf_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, udf_get_block);
}

const struct address_space_operations udf_aops = {
	.readpage	= udf_readpage,
	.readpages	= udf_readpages,
	.writepage	= udf_writepage,
	.writepages	= udf_writepages,
	.write_begin	= udf_write_begin,
	.write_end	= generic_write_end,
	.direct_IO	= udf_direct_IO,
	.bmap		= udf_bmap,
};

/*
 * Expand file stored in ICB to a normal one-block-file
 *
 * This function requires i_data_sem for writing and releases it.
 * This function requires i_mutex held
 */
int udf_expand_file_adinicb(struct inode *inode)
{
	struct page *page;
	char *kaddr;
	struct udf_inode_info *iinfo = UDF_I(inode);
	int err;
	struct writeback_control udf_wbc = {
		.sync_mode = WB_SYNC_NONE,
		.nr_to_write = 1,
	};

	WARN_ON_ONCE(!mutex_is_locked(&inode->i_mutex));
	if (!iinfo->i_lenAlloc) {
		if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_USE_SHORT_AD))
			iinfo->i_alloc_type = ICBTAG_FLAG_AD_SHORT;
		else
			iinfo->i_alloc_type = ICBTAG_FLAG_AD_LONG;
		/* from now on we have normal address_space methods */
		inode->i_data.a_ops = &udf_aops;
		up_write(&iinfo->i_data_sem);
		mark_inode_dirty(inode);
		return 0;
	}
	/*
	 * Release i_data_sem so that we can lock a page - page lock ranks
	 * above i_data_sem. i_mutex still protects us against file changes.
	 */
	up_write(&iinfo->i_data_sem);

	page = find_or_create_page(inode->i_mapping, 0, GFP_NOFS);
	if (!page)
		return -ENOMEM;

	if (!PageUptodate(page)) {
		kaddr = kmap(page);
		memset(kaddr + iinfo->i_lenAlloc, 0x00,
		       PAGE_CACHE_SIZE - iinfo->i_lenAlloc);
		memcpy(kaddr, iinfo->i_ext.i_data + iinfo->i_lenEAttr,
			iinfo->i_lenAlloc);
		flush_dcache_page(page);
		SetPageUptodate(page);
		kunmap(page);
	}
	down_write(&iinfo->i_data_sem);
	memset(iinfo->i_ext.i_data + iinfo->i_lenEAttr, 0x00,
	       iinfo->i_lenAlloc);
	iinfo->i_lenAlloc = 0;
	if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_USE_SHORT_AD))
		iinfo->i_alloc_type = ICBTAG_FLAG_AD_SHORT;
	else
		iinfo->i_alloc_type = ICBTAG_FLAG_AD_LONG;
	/* from now on we have normal address_space methods */
	inode->i_data.a_ops = &udf_aops;
	up_write(&iinfo->i_data_sem);
	err = inode->i_data.a_ops->writepage(page, &udf_wbc);
	if (err) {
		/* Restore everything back so that we don't lose data... */
		lock_page(page);
		kaddr = kmap(page);
		down_write(&iinfo->i_data_sem);
		memcpy(iinfo->i_ext.i_data + iinfo->i_lenEAttr, kaddr,
		       inode->i_size);
		kunmap(page);
		unlock_page(page);
		iinfo->i_alloc_type = ICBTAG_FLAG_AD_IN_ICB;
		inode->i_data.a_ops = &udf_adinicb_aops;
		up_write(&iinfo->i_data_sem);
	}
	page_cache_release(page);
	mark_inode_dirty(inode);

	return err;
}

struct buffer_head *udf_expand_dir_adinicb(struct inode *inode, int *block,
					   int *err)
{
	int newblock;
	struct buffer_head *dbh = NULL;
	struct kernel_lb_addr eloc;
	uint8_t alloctype;
	struct extent_position epos;

	struct udf_fileident_bh sfibh, dfibh;
	loff_t f_pos = udf_ext0_offset(inode);
	int size = udf_ext0_offset(inode) + inode->i_size;
	struct fileIdentDesc cfi, *sfi, *dfi;
	struct udf_inode_info *iinfo = UDF_I(inode);

	if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_USE_SHORT_AD))
		alloctype = ICBTAG_FLAG_AD_SHORT;
	else
		alloctype = ICBTAG_FLAG_AD_LONG;

	if (!inode->i_size) {
		iinfo->i_alloc_type = alloctype;
		mark_inode_dirty(inode);
		return NULL;
	}

	/* alloc block, and copy data to it */
	*block = udf_new_block(inode->i_sb, inode,
			       iinfo->i_location.partitionReferenceNum,
			       iinfo->i_location.logicalBlockNum, err);
	if (!(*block))
		return NULL;
	newblock = udf_get_pblock(inode->i_sb, *block,
				  iinfo->i_location.partitionReferenceNum,
				0);
	if (!newblock)
		return NULL;
	dbh = udf_tgetblk(inode->i_sb, newblock);
	if (!dbh)
		return NULL;
	lock_buffer(dbh);
	memset(dbh->b_data, 0x00, inode->i_sb->s_blocksize);
	set_buffer_uptodate(dbh);
	unlock_buffer(dbh);
	mark_buffer_dirty_inode(dbh, inode);

	sfibh.soffset = sfibh.eoffset =
			f_pos & (inode->i_sb->s_blocksize - 1);
	sfibh.sbh = sfibh.ebh = NULL;
	dfibh.soffset = dfibh.eoffset = 0;
	dfibh.sbh = dfibh.ebh = dbh;
	while (f_pos < size) {
		iinfo->i_alloc_type = ICBTAG_FLAG_AD_IN_ICB;
		sfi = udf_fileident_read(inode, &f_pos, &sfibh, &cfi, NULL,
					 NULL, NULL, NULL);
		if (!sfi) {
			brelse(dbh);
			return NULL;
		}
		iinfo->i_alloc_type = alloctype;
		sfi->descTag.tagLocation = cpu_to_le32(*block);
		dfibh.soffset = dfibh.eoffset;
		dfibh.eoffset += (sfibh.eoffset - sfibh.soffset);
		dfi = (struct fileIdentDesc *)(dbh->b_data + dfibh.soffset);
		if (udf_write_fi(inode, sfi, dfi, &dfibh, sfi->impUse,
				 sfi->fileIdent +
					le16_to_cpu(sfi->lengthOfImpUse))) {
			iinfo->i_alloc_type = ICBTAG_FLAG_AD_IN_ICB;
			brelse(dbh);
			return NULL;
		}
	}
	mark_buffer_dirty_inode(dbh, inode);

	memset(iinfo->i_ext.i_data + iinfo->i_lenEAttr, 0,
		iinfo->i_lenAlloc);
	iinfo->i_lenAlloc = 0;
	eloc.logicalBlockNum = *block;
	eloc.partitionReferenceNum =
				iinfo->i_location.partitionReferenceNum;
	iinfo->i_lenExtents = inode->i_size;
	epos.bh = NULL;
	epos.block = iinfo->i_location;
	epos.offset = udf_file_entry_alloc_offset(inode);
	udf_add_aext(inode, &epos, &eloc, inode->i_size, 0);
	/* UniqueID stuff */

	brelse(epos.bh);
	mark_inode_dirty(inode);
	return dbh;
}

static int udf_get_block(struct inode *inode, sector_t block,
			 struct buffer_head *bh_result, int create)
{
	int err, new;
	sector_t phys = 0;
	struct udf_inode_info *iinfo;

	if (!create) {
		phys = udf_block_map(inode, block);
		if (phys)
			map_bh(bh_result, inode->i_sb, phys);
		return 0;
	}

	err = -EIO;
	new = 0;
	iinfo = UDF_I(inode);

	down_write(&iinfo->i_data_sem);
	if (block == iinfo->i_next_alloc_block + 1) {
		iinfo->i_next_alloc_block++;
		iinfo->i_next_alloc_goal++;
	}

	udf_clear_extent_cache(inode);
	phys = inode_getblk(inode, block, &err, &new);
	if (!phys)
		goto abort;

	if (new)
		set_buffer_new(bh_result);
	map_bh(bh_result, inode->i_sb, phys);

abort:
	up_write(&iinfo->i_data_sem);
	return err;
}

static struct buffer_head *udf_getblk(struct inode *inode, long block,
				      int create, int *err)
{
	struct buffer_head *bh;
	struct buffer_head dummy;

	dummy.b_state = 0;
	dummy.b_blocknr = -1000;
	*err = udf_get_block(inode, block, &dummy, create);
	if (!*err && buffer_mapped(&dummy)) {
		bh = sb_getblk(inode->i_sb, dummy.b_blocknr);
		if (buffer_new(&dummy)) {
			lock_buffer(bh);
			memset(bh->b_data, 0x00, inode->i_sb->s_blocksize);
			set_buffer_uptodate(bh);
			unlock_buffer(bh);
			mark_buffer_dirty_inode(bh, inode);
		}
		return bh;
	}

	return NULL;
}

/* Extend the file by 'blocks' blocks, return the number of extents added */
static int udf_do_extend_file(struct inode *inode,
			      struct extent_position *last_pos,
			      struct kernel_long_ad *last_ext,
			      sector_t blocks)
{
	sector_t add;
	int count = 0, fake = !(last_ext->extLength & UDF_EXTENT_LENGTH_MASK);
	struct super_block *sb = inode->i_sb;
	struct kernel_lb_addr prealloc_loc = {};
	int prealloc_len = 0;
	struct udf_inode_info *iinfo;
	int err;

	/* The previous extent is fake and we should not extend by anything
	 * - there's nothing to do... */
	if (!blocks && fake)
		return 0;

	iinfo = UDF_I(inode);
	/* Round the last extent up to a multiple of block size */
	if (last_ext->extLength & (sb->s_blocksize - 1)) {
		last_ext->extLength =
			(last_ext->extLength & UDF_EXTENT_FLAG_MASK) |
			(((last_ext->extLength & UDF_EXTENT_LENGTH_MASK) +
			  sb->s_blocksize - 1) & ~(sb->s_blocksize - 1));
		iinfo->i_lenExtents =
			(iinfo->i_lenExtents + sb->s_blocksize - 1) &
			~(sb->s_blocksize - 1);
	}

	/* Last extent are just preallocated blocks? */
	if ((last_ext->extLength & UDF_EXTENT_FLAG_MASK) ==
						EXT_NOT_RECORDED_ALLOCATED) {
		/* Save the extent so that we can reattach it to the end */
		prealloc_loc = last_ext->extLocation;
		prealloc_len = last_ext->extLength;
		/* Mark the extent as a hole */
		last_ext->extLength = EXT_NOT_RECORDED_NOT_ALLOCATED |
			(last_ext->extLength & UDF_EXTENT_LENGTH_MASK);
		last_ext->extLocation.logicalBlockNum = 0;
		last_ext->extLocation.partitionReferenceNum = 0;
	}

	/* Can we merge with the previous extent? */
	if ((last_ext->extLength & UDF_EXTENT_FLAG_MASK) ==
					EXT_NOT_RECORDED_NOT_ALLOCATED) {
		add = ((1 << 30) - sb->s_blocksize -
			(last_ext->extLength & UDF_EXTENT_LENGTH_MASK)) >>
			sb->s_blocksize_bits;
		if (add > blocks)
			add = blocks;
		blocks -= add;
		last_ext->extLength += add << sb->s_blocksize_bits;
	}

	if (fake) {
		udf_add_aext(inode, last_pos, &last_ext->extLocation,
			     last_ext->extLength, 1);
		count++;
	} else
		udf_write_aext(inode, last_pos, &last_ext->extLocation,
				last_ext->extLength, 1);

	/* Managed to do everything necessary? */
	if (!blocks)
		goto out;

	/* All further extents will be NOT_RECORDED_NOT_ALLOCATED */
	last_ext->extLocation.logicalBlockNum = 0;
	last_ext->extLocation.partitionReferenceNum = 0;
	add = (1 << (30-sb->s_blocksize_bits)) - 1;
	last_ext->extLength = EXT_NOT_RECORDED_NOT_ALLOCATED |
				(add << sb->s_blocksize_bits);

	/* Create enough extents to cover the whole hole */
	while (blocks > add) {
		blocks -= add;
		err = udf_add_aext(inode, last_pos, &last_ext->extLocation,
				   last_ext->extLength, 1);
		if (err)
			return err;
		count++;
	}
	if (blocks) {
		last_ext->extLength = EXT_NOT_RECORDED_NOT_ALLOCATED |
			(blocks << sb->s_blocksize_bits);
		err = udf_add_aext(inode, last_pos, &last_ext->extLocation,
				   last_ext->extLength, 1);
		if (err)
			return err;
		count++;
	}

out:
	/* Do we have some preallocated blocks saved? */
	if (prealloc_len) {
		err = udf_add_aext(inode, last_pos, &prealloc_loc,
				   prealloc_len, 1);
		if (err)
			return err;
		last_ext->extLocation = prealloc_loc;
		last_ext->extLength = prealloc_len;
		count++;
	}

	/* last_pos should point to the last written extent... */
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		last_pos->offset -= sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		last_pos->offset -= sizeof(struct long_ad);
	else
		return -EIO;

	return count;
}

static int udf_extend_file(struct inode *inode, loff_t newsize)
{

	struct extent_position epos;
	struct kernel_lb_addr eloc;
	uint32_t elen;
	int8_t etype;
	struct super_block *sb = inode->i_sb;
	sector_t first_block = newsize >> sb->s_blocksize_bits, offset;
	int adsize;
	struct udf_inode_info *iinfo = UDF_I(inode);
	struct kernel_long_ad extent;
	int err;

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		adsize = sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		adsize = sizeof(struct long_ad);
	else
		BUG();

	etype = inode_bmap(inode, first_block, &epos, &eloc, &elen, &offset);

	/* File has extent covering the new size (could happen when extending
	 * inside a block)? */
	if (etype != -1)
		return 0;
	if (newsize & (sb->s_blocksize - 1))
		offset++;
	/* Extended file just to the boundary of the last file block? */
	if (offset == 0)
		return 0;

	/* Truncate is extending the file by 'offset' blocks */
	if ((!epos.bh && epos.offset == udf_file_entry_alloc_offset(inode)) ||
	    (epos.bh && epos.offset == sizeof(struct allocExtDesc))) {
		/* File has no extents at all or has empty last
		 * indirect extent! Create a fake extent... */
		extent.extLocation.logicalBlockNum = 0;
		extent.extLocation.partitionReferenceNum = 0;
		extent.extLength = EXT_NOT_RECORDED_NOT_ALLOCATED;
	} else {
		epos.offset -= adsize;
		etype = udf_next_aext(inode, &epos, &extent.extLocation,
				      &extent.extLength, 0);
		extent.extLength |= etype << 30;
	}
	err = udf_do_extend_file(inode, &epos, &extent, offset);
	if (err < 0)
		goto out;
	err = 0;
	iinfo->i_lenExtents = newsize;
out:
	brelse(epos.bh);
	return err;
}

static sector_t inode_getblk(struct inode *inode, sector_t block,
			     int *err, int *new)
{
	struct kernel_long_ad laarr[EXTENT_MERGE_SIZE];
	struct extent_position prev_epos, cur_epos, next_epos;
	int count = 0, startnum = 0, endnum = 0;
	uint32_t elen = 0, tmpelen;
	struct kernel_lb_addr eloc, tmpeloc;
	int c = 1;
	loff_t lbcount = 0, b_off = 0;
	uint32_t newblocknum, newblock;
	sector_t offset = 0;
	int8_t etype;
	struct udf_inode_info *iinfo = UDF_I(inode);
	int goal = 0, pgoal = iinfo->i_location.logicalBlockNum;
	int lastblock = 0;
	bool isBeyondEOF;

	*err = 0;
	*new = 0;
	prev_epos.offset = udf_file_entry_alloc_offset(inode);
	prev_epos.block = iinfo->i_location;
	prev_epos.bh = NULL;
	cur_epos = next_epos = prev_epos;
	b_off = (loff_t)block << inode->i_sb->s_blocksize_bits;

	/* find the extent which contains the block we are looking for.
	   alternate between laarr[0] and laarr[1] for locations of the
	   current extent, and the previous extent */
	do {
		if (prev_epos.bh != cur_epos.bh) {
			brelse(prev_epos.bh);
			get_bh(cur_epos.bh);
			prev_epos.bh = cur_epos.bh;
		}
		if (cur_epos.bh != next_epos.bh) {
			brelse(cur_epos.bh);
			get_bh(next_epos.bh);
			cur_epos.bh = next_epos.bh;
		}

		lbcount += elen;

		prev_epos.block = cur_epos.block;
		cur_epos.block = next_epos.block;

		prev_epos.offset = cur_epos.offset;
		cur_epos.offset = next_epos.offset;

		etype = udf_next_aext(inode, &next_epos, &eloc, &elen, 1);
		if (etype == -1)
			break;

		c = !c;

		laarr[c].extLength = (etype << 30) | elen;
		laarr[c].extLocation = eloc;

		if (etype != (EXT_NOT_RECORDED_NOT_ALLOCATED >> 30))
			pgoal = eloc.logicalBlockNum +
				((elen + inode->i_sb->s_blocksize - 1) >>
				 inode->i_sb->s_blocksize_bits);

		count++;
	} while (lbcount + elen <= b_off);

	b_off -= lbcount;
	offset = b_off >> inode->i_sb->s_blocksize_bits;
	/*
	 * Move prev_epos and cur_epos into indirect extent if we are at
	 * the pointer to it
	 */
	udf_next_aext(inode, &prev_epos, &tmpeloc, &tmpelen, 0);
	udf_next_aext(inode, &cur_epos, &tmpeloc, &tmpelen, 0);

	/* if the extent is allocated and recorded, return the block
	   if the extent is not a multiple of the blocksize, round up */

	if (etype == (EXT_RECORDED_ALLOCATED >> 30)) {
		if (elen & (inode->i_sb->s_blocksize - 1)) {
			elen = EXT_RECORDED_ALLOCATED |
				((elen + inode->i_sb->s_blocksize - 1) &
				 ~(inode->i_sb->s_blocksize - 1));
			udf_write_aext(inode, &cur_epos, &eloc, elen, 1);
		}
		brelse(prev_epos.bh);
		brelse(cur_epos.bh);
		brelse(next_epos.bh);
		newblock = udf_get_lb_pblock(inode->i_sb, &eloc, offset);
		return newblock;
	}

	/* Are we beyond EOF? */
	if (etype == -1) {
		int ret;
		isBeyondEOF = true;
		if (count) {
			if (c)
				laarr[0] = laarr[1];
			startnum = 1;
		} else {
			/* Create a fake extent when there's not one */
			memset(&laarr[0].extLocation, 0x00,
				sizeof(struct kernel_lb_addr));
			laarr[0].extLength = EXT_NOT_RECORDED_NOT_ALLOCATED;
			/* Will udf_do_extend_file() create real extent from
			   a fake one? */
			startnum = (offset > 0);
		}
		/* Create extents for the hole between EOF and offset */
		ret = udf_do_extend_file(inode, &prev_epos, laarr, offset);
		if (ret < 0) {
			brelse(prev_epos.bh);
			brelse(cur_epos.bh);
			brelse(next_epos.bh);
			*err = ret;
			return 0;
		}
		c = 0;
		offset = 0;
		count += ret;
		/* We are not covered by a preallocated extent? */
		if ((laarr[0].extLength & UDF_EXTENT_FLAG_MASK) !=
						EXT_NOT_RECORDED_ALLOCATED) {
			/* Is there any real extent? - otherwise we overwrite
			 * the fake one... */
			if (count)
				c = !c;
			laarr[c].extLength = EXT_NOT_RECORDED_NOT_ALLOCATED |
				inode->i_sb->s_blocksize;
			memset(&laarr[c].extLocation, 0x00,
				sizeof(struct kernel_lb_addr));
			count++;
		}
		endnum = c + 1;
		lastblock = 1;
	} else {
		isBeyondEOF = false;
		endnum = startnum = ((count > 2) ? 2 : count);

		/* if the current extent is in position 0,
		   swap it with the previous */
		if (!c && count != 1) {
			laarr[2] = laarr[0];
			laarr[0] = laarr[1];
			laarr[1] = laarr[2];
			c = 1;
		}

		/* if the current block is located in an extent,
		   read the next extent */
		etype = udf_next_aext(inode, &next_epos, &eloc, &elen, 0);
		if (etype != -1) {
			laarr[c + 1].extLength = (etype << 30) | elen;
			laarr[c + 1].extLocation = eloc;
			count++;
			startnum++;
			endnum++;
		} else
			lastblock = 1;
	}

	/* if the current extent is not recorded but allocated, get the
	 * block in the extent corresponding to the requested block */
	if ((laarr[c].extLength >> 30) == (EXT_NOT_RECORDED_ALLOCATED >> 30))
		newblocknum = laarr[c].extLocation.logicalBlockNum + offset;
	else { /* otherwise, allocate a new block */
		if (iinfo->i_next_alloc_block == block)
			goal = iinfo->i_next_alloc_goal;

		if (!goal) {
			if (!(goal = pgoal)) /* XXX: what was intended here? */
				goal = iinfo->i_location.logicalBlockNum + 1;
		}

		newblocknum = udf_new_block(inode->i_sb, inode,
				iinfo->i_location.partitionReferenceNum,
				goal, err);
		if (!newblocknum) {
			brelse(prev_epos.bh);
			brelse(cur_epos.bh);
			brelse(next_epos.bh);
			*err = -ENOSPC;
			return 0;
		}
		if (isBeyondEOF)
			iinfo->i_lenExtents += inode->i_sb->s_blocksize;
	}

	/* if the extent the requsted block is located in contains multiple
	 * blocks, split the extent into at most three extents. blocks prior
	 * to requested block, requested block, and blocks after requested
	 * block */
	udf_split_extents(inode, &c, offset, newblocknum, laarr, &endnum);

#ifdef UDF_PREALLOCATE
	/* We preallocate blocks only for regular files. It also makes sense
	 * for directories but there's a problem when to drop the
	 * preallocation. We might use some delayed work for that but I feel
	 * it's overengineering for a filesystem like UDF. */
	if (S_ISREG(inode->i_mode))
		udf_prealloc_extents(inode, c, lastblock, laarr, &endnum);
#endif

	/* merge any continuous blocks in laarr */
	udf_merge_extents(inode, laarr, &endnum);

	/* write back the new extents, inserting new extents if the new number
	 * of extents is greater than the old number, and deleting extents if
	 * the new number of extents is less than the old number */
	udf_update_extents(inode, laarr, startnum, endnum, &prev_epos);

	brelse(prev_epos.bh);
	brelse(cur_epos.bh);
	brelse(next_epos.bh);

	newblock = udf_get_pblock(inode->i_sb, newblocknum,
				iinfo->i_location.partitionReferenceNum, 0);
	if (!newblock) {
		*err = -EIO;
		return 0;
	}
	*new = 1;
	iinfo->i_next_alloc_block = block;
	iinfo->i_next_alloc_goal = newblocknum;
	inode->i_ctime = current_fs_time(inode->i_sb);

	if (IS_SYNC(inode))
		udf_sync_inode(inode);
	else
		mark_inode_dirty(inode);

	return newblock;
}

static void udf_split_extents(struct inode *inode, int *c, int offset,
			      int newblocknum,
			      struct kernel_long_ad laarr[EXTENT_MERGE_SIZE],
			      int *endnum)
{
	unsigned long blocksize = inode->i_sb->s_blocksize;
	unsigned char blocksize_bits = inode->i_sb->s_blocksize_bits;

	if ((laarr[*c].extLength >> 30) == (EXT_NOT_RECORDED_ALLOCATED >> 30) ||
	    (laarr[*c].extLength >> 30) ==
				(EXT_NOT_RECORDED_NOT_ALLOCATED >> 30)) {
		int curr = *c;
		int blen = ((laarr[curr].extLength & UDF_EXTENT_LENGTH_MASK) +
			    blocksize - 1) >> blocksize_bits;
		int8_t etype = (laarr[curr].extLength >> 30);

		if (blen == 1)
			;
		else if (!offset || blen == offset + 1) {
			laarr[curr + 2] = laarr[curr + 1];
			laarr[curr + 1] = laarr[curr];
		} else {
			laarr[curr + 3] = laarr[curr + 1];
			laarr[curr + 2] = laarr[curr + 1] = laarr[curr];
		}

		if (offset) {
			if (etype == (EXT_NOT_RECORDED_ALLOCATED >> 30)) {
				udf_free_blocks(inode->i_sb, inode,
						&laarr[curr].extLocation,
						0, offset);
				laarr[curr].extLength =
					EXT_NOT_RECORDED_NOT_ALLOCATED |
					(offset << blocksize_bits);
				laarr[curr].extLocation.logicalBlockNum = 0;
				laarr[curr].extLocation.
						partitionReferenceNum = 0;
			} else
				laarr[curr].extLength = (etype << 30) |
					(offset << blocksize_bits);
			curr++;
			(*c)++;
			(*endnum)++;
		}

		laarr[curr].extLocation.logicalBlockNum = newblocknum;
		if (etype == (EXT_NOT_RECORDED_NOT_ALLOCATED >> 30))
			laarr[curr].extLocation.partitionReferenceNum =
				UDF_I(inode)->i_location.partitionReferenceNum;
		laarr[curr].extLength = EXT_RECORDED_ALLOCATED |
			blocksize;
		curr++;

		if (blen != offset + 1) {
			if (etype == (EXT_NOT_RECORDED_ALLOCATED >> 30))
				laarr[curr].extLocation.logicalBlockNum +=
								offset + 1;
			laarr[curr].extLength = (etype << 30) |
				((blen - (offset + 1)) << blocksize_bits);
			curr++;
			(*endnum)++;
		}
	}
}

static void udf_prealloc_extents(struct inode *inode, int c, int lastblock,
				 struct kernel_long_ad laarr[EXTENT_MERGE_SIZE],
				 int *endnum)
{
	int start, length = 0, currlength = 0, i;

	if (*endnum >= (c + 1)) {
		if (!lastblock)
			return;
		else
			start = c;
	} else {
		if ((laarr[c + 1].extLength >> 30) ==
					(EXT_NOT_RECORDED_ALLOCATED >> 30)) {
			start = c + 1;
			length = currlength =
				(((laarr[c + 1].extLength &
					UDF_EXTENT_LENGTH_MASK) +
				inode->i_sb->s_blocksize - 1) >>
				inode->i_sb->s_blocksize_bits);
		} else
			start = c;
	}

	for (i = start + 1; i <= *endnum; i++) {
		if (i == *endnum) {
			if (lastblock)
				length += UDF_DEFAULT_PREALLOC_BLOCKS;
		} else if ((laarr[i].extLength >> 30) ==
				(EXT_NOT_RECORDED_NOT_ALLOCATED >> 30)) {
			length += (((laarr[i].extLength &
						UDF_EXTENT_LENGTH_MASK) +
				    inode->i_sb->s_blocksize - 1) >>
				    inode->i_sb->s_blocksize_bits);
		} else
			break;
	}

	if (length) {
		int next = laarr[start].extLocation.logicalBlockNum +
			(((laarr[start].extLength & UDF_EXTENT_LENGTH_MASK) +
			  inode->i_sb->s_blocksize - 1) >>
			  inode->i_sb->s_blocksize_bits);
		int numalloc = udf_prealloc_blocks(inode->i_sb, inode,
				laarr[start].extLocation.partitionReferenceNum,
				next, (UDF_DEFAULT_PREALLOC_BLOCKS > length ?
				length : UDF_DEFAULT_PREALLOC_BLOCKS) -
				currlength);
		if (numalloc) 	{
			if (start == (c + 1))
				laarr[start].extLength +=
					(numalloc <<
					 inode->i_sb->s_blocksize_bits);
			else {
				memmove(&laarr[c + 2], &laarr[c + 1],
					sizeof(struct long_ad) * (*endnum - (c + 1)));
				(*endnum)++;
				laarr[c + 1].extLocation.logicalBlockNum = next;
				laarr[c + 1].extLocation.partitionReferenceNum =
					laarr[c].extLocation.
							partitionReferenceNum;
				laarr[c + 1].extLength =
					EXT_NOT_RECORDED_ALLOCATED |
					(numalloc <<
					 inode->i_sb->s_blocksize_bits);
				start = c + 1;
			}

			for (i = start + 1; numalloc && i < *endnum; i++) {
				int elen = ((laarr[i].extLength &
						UDF_EXTENT_LENGTH_MASK) +
					    inode->i_sb->s_blocksize - 1) >>
					    inode->i_sb->s_blocksize_bits;

				if (elen > numalloc) {
					laarr[i].extLength -=
						(numalloc <<
						 inode->i_sb->s_blocksize_bits);
					numalloc = 0;
				} else {
					numalloc -= elen;
					if (*endnum > (i + 1))
						memmove(&laarr[i],
							&laarr[i + 1],
							sizeof(struct long_ad) *
							(*endnum - (i + 1)));
					i--;
					(*endnum)--;
				}
			}
			UDF_I(inode)->i_lenExtents +=
				numalloc << inode->i_sb->s_blocksize_bits;
		}
	}
}

static void udf_merge_extents(struct inode *inode,
			      struct kernel_long_ad laarr[EXTENT_MERGE_SIZE],
			      int *endnum)
{
	int i;
	unsigned long blocksize = inode->i_sb->s_blocksize;
	unsigned char blocksize_bits = inode->i_sb->s_blocksize_bits;

	for (i = 0; i < (*endnum - 1); i++) {
		struct kernel_long_ad *li /*l[i]*/ = &laarr[i];
		struct kernel_long_ad *lip1 /*l[i plus 1]*/ = &laarr[i + 1];

		if (((li->extLength >> 30) == (lip1->extLength >> 30)) &&
			(((li->extLength >> 30) ==
				(EXT_NOT_RECORDED_NOT_ALLOCATED >> 30)) ||
			((lip1->extLocation.logicalBlockNum -
			  li->extLocation.logicalBlockNum) ==
			(((li->extLength & UDF_EXTENT_LENGTH_MASK) +
			blocksize - 1) >> blocksize_bits)))) {

			if (((li->extLength & UDF_EXTENT_LENGTH_MASK) +
				(lip1->extLength & UDF_EXTENT_LENGTH_MASK) +
				blocksize - 1) & ~UDF_EXTENT_LENGTH_MASK) {
				lip1->extLength = (lip1->extLength -
						  (li->extLength &
						   UDF_EXTENT_LENGTH_MASK) +
						   UDF_EXTENT_LENGTH_MASK) &
							~(blocksize - 1);
				li->extLength = (li->extLength &
						 UDF_EXTENT_FLAG_MASK) +
						(UDF_EXTENT_LENGTH_MASK + 1) -
						blocksize;
				lip1->extLocation.logicalBlockNum =
					li->extLocation.logicalBlockNum +
					((li->extLength &
						UDF_EXTENT_LENGTH_MASK) >>
						blocksize_bits);
			} else {
				li->extLength = lip1->extLength +
					(((li->extLength &
						UDF_EXTENT_LENGTH_MASK) +
					 blocksize - 1) & ~(blocksize - 1));
				if (*endnum > (i + 2))
					memmove(&laarr[i + 1], &laarr[i + 2],
						sizeof(struct long_ad) *
						(*endnum - (i + 2)));
				i--;
				(*endnum)--;
			}
		} else if (((li->extLength >> 30) ==
				(EXT_NOT_RECORDED_ALLOCATED >> 30)) &&
			   ((lip1->extLength >> 30) ==
				(EXT_NOT_RECORDED_NOT_ALLOCATED >> 30))) {
			udf_free_blocks(inode->i_sb, inode, &li->extLocation, 0,
					((li->extLength &
					  UDF_EXTENT_LENGTH_MASK) +
					 blocksize - 1) >> blocksize_bits);
			li->extLocation.logicalBlockNum = 0;
			li->extLocation.partitionReferenceNum = 0;

			if (((li->extLength & UDF_EXTENT_LENGTH_MASK) +
			     (lip1->extLength & UDF_EXTENT_LENGTH_MASK) +
			     blocksize - 1) & ~UDF_EXTENT_LENGTH_MASK) {
				lip1->extLength = (lip1->extLength -
						   (li->extLength &
						   UDF_EXTENT_LENGTH_MASK) +
						   UDF_EXTENT_LENGTH_MASK) &
						   ~(blocksize - 1);
				li->extLength = (li->extLength &
						 UDF_EXTENT_FLAG_MASK) +
						(UDF_EXTENT_LENGTH_MASK + 1) -
						blocksize;
			} else {
				li->extLength = lip1->extLength +
					(((li->extLength &
						UDF_EXTENT_LENGTH_MASK) +
					  blocksize - 1) & ~(blocksize - 1));
				if (*endnum > (i + 2))
					memmove(&laarr[i + 1], &laarr[i + 2],
						sizeof(struct long_ad) *
						(*endnum - (i + 2)));
				i--;
				(*endnum)--;
			}
		} else if ((li->extLength >> 30) ==
					(EXT_NOT_RECORDED_ALLOCATED >> 30)) {
			udf_free_blocks(inode->i_sb, inode,
					&li->extLocation, 0,
					((li->extLength &
						UDF_EXTENT_LENGTH_MASK) +
					 blocksize - 1) >> blocksize_bits);
			li->extLocation.logicalBlockNum = 0;
			li->extLocation.partitionReferenceNum = 0;
			li->extLength = (li->extLength &
						UDF_EXTENT_LENGTH_MASK) |
						EXT_NOT_RECORDED_NOT_ALLOCATED;
		}
	}
}

static void udf_update_extents(struct inode *inode,
			       struct kernel_long_ad laarr[EXTENT_MERGE_SIZE],
			       int startnum, int endnum,
			       struct extent_position *epos)
{
	int start = 0, i;
	struct kernel_lb_addr tmploc;
	uint32_t tmplen;

	if (startnum > endnum) {
		for (i = 0; i < (startnum - endnum); i++)
			udf_delete_aext(inode, *epos, laarr[i].extLocation,
					laarr[i].extLength);
	} else if (startnum < endnum) {
		for (i = 0; i < (endnum - startnum); i++) {
			udf_insert_aext(inode, *epos, laarr[i].extLocation,
					laarr[i].extLength);
			udf_next_aext(inode, epos, &laarr[i].extLocation,
				      &laarr[i].extLength, 1);
			start++;
		}
	}

	for (i = start; i < endnum; i++) {
		udf_next_aext(inode, epos, &tmploc, &tmplen, 0);
		udf_write_aext(inode, epos, &laarr[i].extLocation,
			       laarr[i].extLength, 1);
	}
}

struct buffer_head *udf_bread(struct inode *inode, int block,
			      int create, int *err)
{
	struct buffer_head *bh = NULL;

	bh = udf_getblk(inode, block, create, err);
	if (!bh)
		return NULL;

	if (buffer_uptodate(bh))
		return bh;

	ll_rw_block(READ, 1, &bh);

	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		return bh;

	brelse(bh);
	*err = -EIO;
	return NULL;
}

int udf_setsize(struct inode *inode, loff_t newsize)
{
	int err;
	struct udf_inode_info *iinfo;
	int bsize = 1 << inode->i_blkbits;

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	      S_ISLNK(inode->i_mode)))
		return -EINVAL;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;

	iinfo = UDF_I(inode);
	if (newsize > inode->i_size) {
		down_write(&iinfo->i_data_sem);
		if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
			if (bsize <
			    (udf_file_entry_alloc_offset(inode) + newsize)) {
				err = udf_expand_file_adinicb(inode);
				if (err)
					return err;
				down_write(&iinfo->i_data_sem);
			} else {
				iinfo->i_lenAlloc = newsize;
				goto set_size;
			}
		}
		err = udf_extend_file(inode, newsize);
		if (err) {
			up_write(&iinfo->i_data_sem);
			return err;
		}
set_size:
		truncate_setsize(inode, newsize);
		up_write(&iinfo->i_data_sem);
	} else {
		if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
			down_write(&iinfo->i_data_sem);
			udf_clear_extent_cache(inode);
			memset(iinfo->i_ext.i_data + iinfo->i_lenEAttr + newsize,
			       0x00, bsize - newsize -
			       udf_file_entry_alloc_offset(inode));
			iinfo->i_lenAlloc = newsize;
			truncate_setsize(inode, newsize);
			up_write(&iinfo->i_data_sem);
			goto update_time;
		}
		err = block_truncate_page(inode->i_mapping, newsize,
					  udf_get_block);
		if (err)
			return err;
		down_write(&iinfo->i_data_sem);
		udf_clear_extent_cache(inode);
		truncate_setsize(inode, newsize);
		udf_truncate_extents(inode);
		up_write(&iinfo->i_data_sem);
	}
update_time:
	inode->i_mtime = inode->i_ctime = current_fs_time(inode->i_sb);
	if (IS_SYNC(inode))
		udf_sync_inode(inode);
	else
		mark_inode_dirty(inode);
	return 0;
}

/*
 * Maximum length of linked list formed by ICB hierarchy. The chosen number is
 * arbitrary - just that we hopefully don't limit any real use of rewritten
 * inode on write-once media but avoid looping for too long on corrupted media.
 */
#define UDF_MAX_ICB_NESTING 1024

static int udf_read_inode(struct inode *inode, bool hidden_inode)
{
	struct buffer_head *bh = NULL;
	struct fileEntry *fe;
	struct extendedFileEntry *efe;
	uint16_t ident;
	struct udf_inode_info *iinfo = UDF_I(inode);
	struct udf_sb_info *sbi = UDF_SB(inode->i_sb);
	struct kernel_lb_addr *iloc = &iinfo->i_location;
	unsigned int link_count;
	unsigned int indirections = 0;
	int bs = inode->i_sb->s_blocksize;
	int ret = -EIO;

reread:
	if (iloc->logicalBlockNum >=
	    sbi->s_partmaps[iloc->partitionReferenceNum].s_partition_len) {
		udf_debug("block=%d, partition=%d out of range\n",
			  iloc->logicalBlockNum, iloc->partitionReferenceNum);
		return -EIO;
	}

	/*
	 * Set defaults, but the inode is still incomplete!
	 * Note: get_new_inode() sets the following on a new inode:
	 *      i_sb = sb
	 *      i_no = ino
	 *      i_flags = sb->s_flags
	 *      i_state = 0
	 * clean_inode(): zero fills and sets
	 *      i_count = 1
	 *      i_nlink = 1
	 *      i_op = NULL;
	 */
	bh = udf_read_ptagged(inode->i_sb, iloc, 0, &ident);
	if (!bh) {
		udf_err(inode->i_sb, "(ino %ld) failed !bh\n", inode->i_ino);
		return -EIO;
	}

	if (ident != TAG_IDENT_FE && ident != TAG_IDENT_EFE &&
	    ident != TAG_IDENT_USE) {
		udf_err(inode->i_sb, "(ino %ld) failed ident=%d\n",
			inode->i_ino, ident);
		goto out;
	}

	fe = (struct fileEntry *)bh->b_data;
	efe = (struct extendedFileEntry *)bh->b_data;

	if (fe->icbTag.strategyType == cpu_to_le16(4096)) {
		struct buffer_head *ibh;

		ibh = udf_read_ptagged(inode->i_sb, iloc, 1, &ident);
		if (ident == TAG_IDENT_IE && ibh) {
			struct kernel_lb_addr loc;
			struct indirectEntry *ie;

			ie = (struct indirectEntry *)ibh->b_data;
			loc = lelb_to_cpu(ie->indirectICB.extLocation);

			if (ie->indirectICB.extLength) {
				brelse(ibh);
				memcpy(&iinfo->i_location, &loc,
				       sizeof(struct kernel_lb_addr));
				if (++indirections > UDF_MAX_ICB_NESTING) {
					udf_err(inode->i_sb,
						"too many ICBs in ICB hierarchy"
						" (max %d supported)\n",
						UDF_MAX_ICB_NESTING);
					goto out;
				}
				brelse(bh);
				goto reread;
			}
		}
		brelse(ibh);
	} else if (fe->icbTag.strategyType != cpu_to_le16(4)) {
		udf_err(inode->i_sb, "unsupported strategy type: %d\n",
			le16_to_cpu(fe->icbTag.strategyType));
		goto out;
	}
	if (fe->icbTag.strategyType == cpu_to_le16(4))
		iinfo->i_strat4096 = 0;
	else /* if (fe->icbTag.strategyType == cpu_to_le16(4096)) */
		iinfo->i_strat4096 = 1;

	iinfo->i_alloc_type = le16_to_cpu(fe->icbTag.flags) &
							ICBTAG_FLAG_AD_MASK;
	iinfo->i_unique = 0;
	iinfo->i_lenEAttr = 0;
	iinfo->i_lenExtents = 0;
	iinfo->i_lenAlloc = 0;
	iinfo->i_next_alloc_block = 0;
	iinfo->i_next_alloc_goal = 0;
	if (fe->descTag.tagIdent == cpu_to_le16(TAG_IDENT_EFE)) {
		iinfo->i_efe = 1;
		iinfo->i_use = 0;
		ret = udf_alloc_i_data(inode, bs -
					sizeof(struct extendedFileEntry));
		if (ret)
			goto out;
		memcpy(iinfo->i_ext.i_data,
		       bh->b_data + sizeof(struct extendedFileEntry),
		       bs - sizeof(struct extendedFileEntry));
	} else if (fe->descTag.tagIdent == cpu_to_le16(TAG_IDENT_FE)) {
		iinfo->i_efe = 0;
		iinfo->i_use = 0;
		ret = udf_alloc_i_data(inode, bs - sizeof(struct fileEntry));
		if (ret)
			goto out;
		memcpy(iinfo->i_ext.i_data,
		       bh->b_data + sizeof(struct fileEntry),
		       bs - sizeof(struct fileEntry));
	} else if (fe->descTag.tagIdent == cpu_to_le16(TAG_IDENT_USE)) {
		iinfo->i_efe = 0;
		iinfo->i_use = 1;
		iinfo->i_lenAlloc = le32_to_cpu(
				((struct unallocSpaceEntry *)bh->b_data)->
				 lengthAllocDescs);
		ret = udf_alloc_i_data(inode, bs -
					sizeof(struct unallocSpaceEntry));
		if (ret)
			goto out;
		memcpy(iinfo->i_ext.i_data,
		       bh->b_data + sizeof(struct unallocSpaceEntry),
		       bs - sizeof(struct unallocSpaceEntry));
		return 0;
	}

	ret = -EIO;
	read_lock(&sbi->s_cred_lock);
	i_uid_write(inode, le32_to_cpu(fe->uid));
	if (!uid_valid(inode->i_uid) ||
	    UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_UID_IGNORE) ||
	    UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_UID_SET))
		inode->i_uid = UDF_SB(inode->i_sb)->s_uid;

	i_gid_write(inode, le32_to_cpu(fe->gid));
	if (!gid_valid(inode->i_gid) ||
	    UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_GID_IGNORE) ||
	    UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_GID_SET))
		inode->i_gid = UDF_SB(inode->i_sb)->s_gid;

	if (fe->icbTag.fileType != ICBTAG_FILE_TYPE_DIRECTORY &&
			sbi->s_fmode != UDF_INVALID_MODE)
		inode->i_mode = sbi->s_fmode;
	else if (fe->icbTag.fileType == ICBTAG_FILE_TYPE_DIRECTORY &&
			sbi->s_dmode != UDF_INVALID_MODE)
		inode->i_mode = sbi->s_dmode;
	else
		inode->i_mode = udf_convert_permissions(fe);
	inode->i_mode &= ~sbi->s_umask;
	read_unlock(&sbi->s_cred_lock);

	link_count = le16_to_cpu(fe->fileLinkCount);
	if (!link_count) {
		if (!hidden_inode) {
			ret = -ESTALE;
			goto out;
		}
		link_count = 1;
	}
	set_nlink(inode, link_count);

	inode->i_size = le64_to_cpu(fe->informationLength);
	iinfo->i_lenExtents = inode->i_size;

	if (iinfo->i_efe == 0) {
		inode->i_blocks = le64_to_cpu(fe->logicalBlocksRecorded) <<
			(inode->i_sb->s_blocksize_bits - 9);

		if (!udf_disk_stamp_to_time(&inode->i_atime, fe->accessTime))
			inode->i_atime = sbi->s_record_time;

		if (!udf_disk_stamp_to_time(&inode->i_mtime,
					    fe->modificationTime))
			inode->i_mtime = sbi->s_record_time;

		if (!udf_disk_stamp_to_time(&inode->i_ctime, fe->attrTime))
			inode->i_ctime = sbi->s_record_time;

		iinfo->i_unique = le64_to_cpu(fe->uniqueID);
		iinfo->i_lenEAttr = le32_to_cpu(fe->lengthExtendedAttr);
		iinfo->i_lenAlloc = le32_to_cpu(fe->lengthAllocDescs);
		iinfo->i_checkpoint = le32_to_cpu(fe->checkpoint);
	} else {
		inode->i_blocks = le64_to_cpu(efe->logicalBlocksRecorded) <<
		    (inode->i_sb->s_blocksize_bits - 9);

		if (!udf_disk_stamp_to_time(&inode->i_atime, efe->accessTime))
			inode->i_atime = sbi->s_record_time;

		if (!udf_disk_stamp_to_time(&inode->i_mtime,
					    efe->modificationTime))
			inode->i_mtime = sbi->s_record_time;

		if (!udf_disk_stamp_to_time(&iinfo->i_crtime, efe->createTime))
			iinfo->i_crtime = sbi->s_record_time;

		if (!udf_disk_stamp_to_time(&inode->i_ctime, efe->attrTime))
			inode->i_ctime = sbi->s_record_time;

		iinfo->i_unique = le64_to_cpu(efe->uniqueID);
		iinfo->i_lenEAttr = le32_to_cpu(efe->lengthExtendedAttr);
		iinfo->i_lenAlloc = le32_to_cpu(efe->lengthAllocDescs);
		iinfo->i_checkpoint = le32_to_cpu(efe->checkpoint);
	}
	inode->i_generation = iinfo->i_unique;

	/*
	 * Sanity check length of allocation descriptors and extended attrs to
	 * avoid integer overflows
	 */
	if (iinfo->i_lenEAttr > bs || iinfo->i_lenAlloc > bs)
		goto out;
	/* Now do exact checks */
	if (udf_file_entry_alloc_offset(inode) + iinfo->i_lenAlloc > bs)
		goto out;
	/* Sanity checks for files in ICB so that we don't get confused later */
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
		/*
		 * For file in ICB data is stored in allocation descriptor
		 * so sizes should match
		 */
		if (iinfo->i_lenAlloc != inode->i_size)
			goto out;
		/* File in ICB has to fit in there... */
		if (inode->i_size > bs - udf_file_entry_alloc_offset(inode))
			goto out;
	}

	switch (fe->icbTag.fileType) {
	case ICBTAG_FILE_TYPE_DIRECTORY:
		inode->i_op = &udf_dir_inode_operations;
		inode->i_fop = &udf_dir_operations;
		inode->i_mode |= S_IFDIR;
		inc_nlink(inode);
		break;
	case ICBTAG_FILE_TYPE_REALTIME:
	case ICBTAG_FILE_TYPE_REGULAR:
	case ICBTAG_FILE_TYPE_UNDEF:
	case ICBTAG_FILE_TYPE_VAT20:
		if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
			inode->i_data.a_ops = &udf_adinicb_aops;
		else
			inode->i_data.a_ops = &udf_aops;
		inode->i_op = &udf_file_inode_operations;
		inode->i_fop = &udf_file_operations;
		inode->i_mode |= S_IFREG;
		break;
	case ICBTAG_FILE_TYPE_BLOCK:
		inode->i_mode |= S_IFBLK;
		break;
	case ICBTAG_FILE_TYPE_CHAR:
		inode->i_mode |= S_IFCHR;
		break;
	case ICBTAG_FILE_TYPE_FIFO:
		init_special_inode(inode, inode->i_mode | S_IFIFO, 0);
		break;
	case ICBTAG_FILE_TYPE_SOCKET:
		init_special_inode(inode, inode->i_mode | S_IFSOCK, 0);
		break;
	case ICBTAG_FILE_TYPE_SYMLINK:
		inode->i_data.a_ops = &udf_symlink_aops;
		inode->i_op = &udf_symlink_inode_operations;
		inode->i_mode = S_IFLNK | S_IRWXUGO;
		break;
	case ICBTAG_FILE_TYPE_MAIN:
		udf_debug("METADATA FILE-----\n");
		break;
	case ICBTAG_FILE_TYPE_MIRROR:
		udf_debug("METADATA MIRROR FILE-----\n");
		break;
	case ICBTAG_FILE_TYPE_BITMAP:
		udf_debug("METADATA BITMAP FILE-----\n");
		break;
	default:
		udf_err(inode->i_sb, "(ino %ld) failed unknown file type=%d\n",
			inode->i_ino, fe->icbTag.fileType);
		goto out;
	}
	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		struct deviceSpec *dsea =
			(struct deviceSpec *)udf_get_extendedattr(inode, 12, 1);
		if (dsea) {
			init_special_inode(inode, inode->i_mode,
				MKDEV(le32_to_cpu(dsea->majorDeviceIdent),
				      le32_to_cpu(dsea->minorDeviceIdent)));
			/* Developer ID ??? */
		} else
			goto out;
	}
	ret = 0;
out:
	brelse(bh);
	return ret;
}

static int udf_alloc_i_data(struct inode *inode, size_t size)
{
	struct udf_inode_info *iinfo = UDF_I(inode);
	iinfo->i_ext.i_data = kmalloc(size, GFP_KERNEL);

	if (!iinfo->i_ext.i_data) {
		udf_err(inode->i_sb, "(ino %ld) no free memory\n",
			inode->i_ino);
		return -ENOMEM;
	}

	return 0;
}

static umode_t udf_convert_permissions(struct fileEntry *fe)
{
	umode_t mode;
	uint32_t permissions;
	uint32_t flags;

	permissions = le32_to_cpu(fe->permissions);
	flags = le16_to_cpu(fe->icbTag.flags);

	mode =	((permissions) & S_IRWXO) |
		((permissions >> 2) & S_IRWXG) |
		((permissions >> 4) & S_IRWXU) |
		((flags & ICBTAG_FLAG_SETUID) ? S_ISUID : 0) |
		((flags & ICBTAG_FLAG_SETGID) ? S_ISGID : 0) |
		((flags & ICBTAG_FLAG_STICKY) ? S_ISVTX : 0);

	return mode;
}

int udf_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return udf_update_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
}

static int udf_sync_inode(struct inode *inode)
{
	return udf_update_inode(inode, 1);
}

static int udf_update_inode(struct inode *inode, int do_sync)
{
	struct buffer_head *bh = NULL;
	struct fileEntry *fe;
	struct extendedFileEntry *efe;
	uint64_t lb_recorded;
	uint32_t udfperms;
	uint16_t icbflags;
	uint16_t crclen;
	int err = 0;
	struct udf_sb_info *sbi = UDF_SB(inode->i_sb);
	unsigned char blocksize_bits = inode->i_sb->s_blocksize_bits;
	struct udf_inode_info *iinfo = UDF_I(inode);

	bh = udf_tgetblk(inode->i_sb,
			udf_get_lb_pblock(inode->i_sb, &iinfo->i_location, 0));
	if (!bh) {
		udf_debug("getblk failure\n");
		return -ENOMEM;
	}

	lock_buffer(bh);
	memset(bh->b_data, 0, inode->i_sb->s_blocksize);
	fe = (struct fileEntry *)bh->b_data;
	efe = (struct extendedFileEntry *)bh->b_data;

	if (iinfo->i_use) {
		struct unallocSpaceEntry *use =
			(struct unallocSpaceEntry *)bh->b_data;

		use->lengthAllocDescs = cpu_to_le32(iinfo->i_lenAlloc);
		memcpy(bh->b_data + sizeof(struct unallocSpaceEntry),
		       iinfo->i_ext.i_data, inode->i_sb->s_blocksize -
					sizeof(struct unallocSpaceEntry));
		use->descTag.tagIdent = cpu_to_le16(TAG_IDENT_USE);
		use->descTag.tagLocation =
				cpu_to_le32(iinfo->i_location.logicalBlockNum);
		crclen = sizeof(struct unallocSpaceEntry) +
				iinfo->i_lenAlloc - sizeof(struct tag);
		use->descTag.descCRCLength = cpu_to_le16(crclen);
		use->descTag.descCRC = cpu_to_le16(crc_itu_t(0, (char *)use +
							   sizeof(struct tag),
							   crclen));
		use->descTag.tagChecksum = udf_tag_checksum(&use->descTag);

		goto out;
	}

	if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_UID_FORGET))
		fe->uid = cpu_to_le32(-1);
	else
		fe->uid = cpu_to_le32(i_uid_read(inode));

	if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_GID_FORGET))
		fe->gid = cpu_to_le32(-1);
	else
		fe->gid = cpu_to_le32(i_gid_read(inode));

	udfperms = ((inode->i_mode & S_IRWXO)) |
		   ((inode->i_mode & S_IRWXG) << 2) |
		   ((inode->i_mode & S_IRWXU) << 4);

	udfperms |= (le32_to_cpu(fe->permissions) &
		    (FE_PERM_O_DELETE | FE_PERM_O_CHATTR |
		     FE_PERM_G_DELETE | FE_PERM_G_CHATTR |
		     FE_PERM_U_DELETE | FE_PERM_U_CHATTR));
	fe->permissions = cpu_to_le32(udfperms);

	if (S_ISDIR(inode->i_mode) && inode->i_nlink > 0)
		fe->fileLinkCount = cpu_to_le16(inode->i_nlink - 1);
	else
		fe->fileLinkCount = cpu_to_le16(inode->i_nlink);

	fe->informationLength = cpu_to_le64(inode->i_size);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		struct regid *eid;
		struct deviceSpec *dsea =
			(struct deviceSpec *)udf_get_extendedattr(inode, 12, 1);
		if (!dsea) {
			dsea = (struct deviceSpec *)
				udf_add_extendedattr(inode,
						     sizeof(struct deviceSpec) +
						     sizeof(struct regid), 12, 0x3);
			dsea->attrType = cpu_to_le32(12);
			dsea->attrSubtype = 1;
			dsea->attrLength = cpu_to_le32(
						sizeof(struct deviceSpec) +
						sizeof(struct regid));
			dsea->impUseLength = cpu_to_le32(sizeof(struct regid));
		}
		eid = (struct regid *)dsea->impUse;
		memset(eid, 0, sizeof(struct regid));
		strcpy(eid->ident, UDF_ID_DEVELOPER);
		eid->identSuffix[0] = UDF_OS_CLASS_UNIX;
		eid->identSuffix[1] = UDF_OS_ID_LINUX;
		dsea->majorDeviceIdent = cpu_to_le32(imajor(inode));
		dsea->minorDeviceIdent = cpu_to_le32(iminor(inode));
	}

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
		lb_recorded = 0; /* No extents => no blocks! */
	else
		lb_recorded =
			(inode->i_blocks + (1 << (blocksize_bits - 9)) - 1) >>
			(blocksize_bits - 9);

	if (iinfo->i_efe == 0) {
		memcpy(bh->b_data + sizeof(struct fileEntry),
		       iinfo->i_ext.i_data,
		       inode->i_sb->s_blocksize - sizeof(struct fileEntry));
		fe->logicalBlocksRecorded = cpu_to_le64(lb_recorded);

		udf_time_to_disk_stamp(&fe->accessTime, inode->i_atime);
		udf_time_to_disk_stamp(&fe->modificationTime, inode->i_mtime);
		udf_time_to_disk_stamp(&fe->attrTime, inode->i_ctime);
		memset(&(fe->impIdent), 0, sizeof(struct regid));
		strcpy(fe->impIdent.ident, UDF_ID_DEVELOPER);
		fe->impIdent.identSuffix[0] = UDF_OS_CLASS_UNIX;
		fe->impIdent.identSuffix[1] = UDF_OS_ID_LINUX;
		fe->uniqueID = cpu_to_le64(iinfo->i_unique);
		fe->lengthExtendedAttr = cpu_to_le32(iinfo->i_lenEAttr);
		fe->lengthAllocDescs = cpu_to_le32(iinfo->i_lenAlloc);
		fe->checkpoint = cpu_to_le32(iinfo->i_checkpoint);
		fe->descTag.tagIdent = cpu_to_le16(TAG_IDENT_FE);
		crclen = sizeof(struct fileEntry);
	} else {
		memcpy(bh->b_data + sizeof(struct extendedFileEntry),
		       iinfo->i_ext.i_data,
		       inode->i_sb->s_blocksize -
					sizeof(struct extendedFileEntry));
		efe->objectSize = cpu_to_le64(inode->i_size);
		efe->logicalBlocksRecorded = cpu_to_le64(lb_recorded);

		if (iinfo->i_crtime.tv_sec > inode->i_atime.tv_sec ||
		    (iinfo->i_crtime.tv_sec == inode->i_atime.tv_sec &&
		     iinfo->i_crtime.tv_nsec > inode->i_atime.tv_nsec))
			iinfo->i_crtime = inode->i_atime;

		if (iinfo->i_crtime.tv_sec > inode->i_mtime.tv_sec ||
		    (iinfo->i_crtime.tv_sec == inode->i_mtime.tv_sec &&
		     iinfo->i_crtime.tv_nsec > inode->i_mtime.tv_nsec))
			iinfo->i_crtime = inode->i_mtime;

		if (iinfo->i_crtime.tv_sec > inode->i_ctime.tv_sec ||
		    (iinfo->i_crtime.tv_sec == inode->i_ctime.tv_sec &&
		     iinfo->i_crtime.tv_nsec > inode->i_ctime.tv_nsec))
			iinfo->i_crtime = inode->i_ctime;

		udf_time_to_disk_stamp(&efe->accessTime, inode->i_atime);
		udf_time_to_disk_stamp(&efe->modificationTime, inode->i_mtime);
		udf_time_to_disk_stamp(&efe->createTime, iinfo->i_crtime);
		udf_time_to_disk_stamp(&efe->attrTime, inode->i_ctime);

		memset(&(efe->impIdent), 0, sizeof(struct regid));
		strcpy(efe->impIdent.ident, UDF_ID_DEVELOPER);
		efe->impIdent.identSuffix[0] = UDF_OS_CLASS_UNIX;
		efe->impIdent.identSuffix[1] = UDF_OS_ID_LINUX;
		efe->uniqueID = cpu_to_le64(iinfo->i_unique);
		efe->lengthExtendedAttr = cpu_to_le32(iinfo->i_lenEAttr);
		efe->lengthAllocDescs = cpu_to_le32(iinfo->i_lenAlloc);
		efe->checkpoint = cpu_to_le32(iinfo->i_checkpoint);
		efe->descTag.tagIdent = cpu_to_le16(TAG_IDENT_EFE);
		crclen = sizeof(struct extendedFileEntry);
	}
	if (iinfo->i_strat4096) {
		fe->icbTag.strategyType = cpu_to_le16(4096);
		fe->icbTag.strategyParameter = cpu_to_le16(1);
		fe->icbTag.numEntries = cpu_to_le16(2);
	} else {
		fe->icbTag.strategyType = cpu_to_le16(4);
		fe->icbTag.numEntries = cpu_to_le16(1);
	}

	if (S_ISDIR(inode->i_mode))
		fe->icbTag.fileType = ICBTAG_FILE_TYPE_DIRECTORY;
	else if (S_ISREG(inode->i_mode))
		fe->icbTag.fileType = ICBTAG_FILE_TYPE_REGULAR;
	else if (S_ISLNK(inode->i_mode))
		fe->icbTag.fileType = ICBTAG_FILE_TYPE_SYMLINK;
	else if (S_ISBLK(inode->i_mode))
		fe->icbTag.fileType = ICBTAG_FILE_TYPE_BLOCK;
	else if (S_ISCHR(inode->i_mode))
		fe->icbTag.fileType = ICBTAG_FILE_TYPE_CHAR;
	else if (S_ISFIFO(inode->i_mode))
		fe->icbTag.fileType = ICBTAG_FILE_TYPE_FIFO;
	else if (S_ISSOCK(inode->i_mode))
		fe->icbTag.fileType = ICBTAG_FILE_TYPE_SOCKET;

	icbflags =	iinfo->i_alloc_type |
			((inode->i_mode & S_ISUID) ? ICBTAG_FLAG_SETUID : 0) |
			((inode->i_mode & S_ISGID) ? ICBTAG_FLAG_SETGID : 0) |
			((inode->i_mode & S_ISVTX) ? ICBTAG_FLAG_STICKY : 0) |
			(le16_to_cpu(fe->icbTag.flags) &
				~(ICBTAG_FLAG_AD_MASK | ICBTAG_FLAG_SETUID |
				ICBTAG_FLAG_SETGID | ICBTAG_FLAG_STICKY));

	fe->icbTag.flags = cpu_to_le16(icbflags);
	if (sbi->s_udfrev >= 0x0200)
		fe->descTag.descVersion = cpu_to_le16(3);
	else
		fe->descTag.descVersion = cpu_to_le16(2);
	fe->descTag.tagSerialNum = cpu_to_le16(sbi->s_serial_number);
	fe->descTag.tagLocation = cpu_to_le32(
					iinfo->i_location.logicalBlockNum);
	crclen += iinfo->i_lenEAttr + iinfo->i_lenAlloc - sizeof(struct tag);
	fe->descTag.descCRCLength = cpu_to_le16(crclen);
	fe->descTag.descCRC = cpu_to_le16(crc_itu_t(0, (char *)fe + sizeof(struct tag),
						  crclen));
	fe->descTag.tagChecksum = udf_tag_checksum(&fe->descTag);

out:
	set_buffer_uptodate(bh);
	unlock_buffer(bh);

	/* write the data blocks */
	mark_buffer_dirty(bh);
	if (do_sync) {
		sync_dirty_buffer(bh);
		if (buffer_write_io_error(bh)) {
			udf_warn(inode->i_sb, "IO error syncing udf inode [%08lx]\n",
				 inode->i_ino);
			err = -EIO;
		}
	}
	brelse(bh);

	return err;
}

struct inode *__udf_iget(struct super_block *sb, struct kernel_lb_addr *ino,
			 bool hidden_inode)
{
	unsigned long block = udf_get_lb_pblock(sb, ino, 0);
	struct inode *inode = iget_locked(sb, block);
	int err;

	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (!(inode->i_state & I_NEW))
		return inode;

	memcpy(&UDF_I(inode)->i_location, ino, sizeof(struct kernel_lb_addr));
	err = udf_read_inode(inode, hidden_inode);
	if (err < 0) {
		iget_failed(inode);
		return ERR_PTR(err);
	}
	unlock_new_inode(inode);

	return inode;
}

int udf_add_aext(struct inode *inode, struct extent_position *epos,
		 struct kernel_lb_addr *eloc, uint32_t elen, int inc)
{
	int adsize;
	struct short_ad *sad = NULL;
	struct long_ad *lad = NULL;
	struct allocExtDesc *aed;
	uint8_t *ptr;
	struct udf_inode_info *iinfo = UDF_I(inode);

	if (!epos->bh)
		ptr = iinfo->i_ext.i_data + epos->offset -
			udf_file_entry_alloc_offset(inode) +
			iinfo->i_lenEAttr;
	else
		ptr = epos->bh->b_data + epos->offset;

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		adsize = sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		adsize = sizeof(struct long_ad);
	else
		return -EIO;

	if (epos->offset + (2 * adsize) > inode->i_sb->s_blocksize) {
		unsigned char *sptr, *dptr;
		struct buffer_head *nbh;
		int err, loffset;
		struct kernel_lb_addr obloc = epos->block;

		epos->block.logicalBlockNum = udf_new_block(inode->i_sb, NULL,
						obloc.partitionReferenceNum,
						obloc.logicalBlockNum, &err);
		if (!epos->block.logicalBlockNum)
			return -ENOSPC;
		nbh = udf_tgetblk(inode->i_sb, udf_get_lb_pblock(inode->i_sb,
								 &epos->block,
								 0));
		if (!nbh)
			return -EIO;
		lock_buffer(nbh);
		memset(nbh->b_data, 0x00, inode->i_sb->s_blocksize);
		set_buffer_uptodate(nbh);
		unlock_buffer(nbh);
		mark_buffer_dirty_inode(nbh, inode);

		aed = (struct allocExtDesc *)(nbh->b_data);
		if (!UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_STRICT))
			aed->previousAllocExtLocation =
					cpu_to_le32(obloc.logicalBlockNum);
		if (epos->offset + adsize > inode->i_sb->s_blocksize) {
			loffset = epos->offset;
			aed->lengthAllocDescs = cpu_to_le32(adsize);
			sptr = ptr - adsize;
			dptr = nbh->b_data + sizeof(struct allocExtDesc);
			memcpy(dptr, sptr, adsize);
			epos->offset = sizeof(struct allocExtDesc) + adsize;
		} else {
			loffset = epos->offset + adsize;
			aed->lengthAllocDescs = cpu_to_le32(0);
			sptr = ptr;
			epos->offset = sizeof(struct allocExtDesc);

			if (epos->bh) {
				aed = (struct allocExtDesc *)epos->bh->b_data;
				le32_add_cpu(&aed->lengthAllocDescs, adsize);
			} else {
				iinfo->i_lenAlloc += adsize;
				mark_inode_dirty(inode);
			}
		}
		if (UDF_SB(inode->i_sb)->s_udfrev >= 0x0200)
			udf_new_tag(nbh->b_data, TAG_IDENT_AED, 3, 1,
				    epos->block.logicalBlockNum, sizeof(struct tag));
		else
			udf_new_tag(nbh->b_data, TAG_IDENT_AED, 2, 1,
				    epos->block.logicalBlockNum, sizeof(struct tag));
		switch (iinfo->i_alloc_type) {
		case ICBTAG_FLAG_AD_SHORT:
			sad = (struct short_ad *)sptr;
			sad->extLength = cpu_to_le32(EXT_NEXT_EXTENT_ALLOCDECS |
						     inode->i_sb->s_blocksize);
			sad->extPosition =
				cpu_to_le32(epos->block.logicalBlockNum);
			break;
		case ICBTAG_FLAG_AD_LONG:
			lad = (struct long_ad *)sptr;
			lad->extLength = cpu_to_le32(EXT_NEXT_EXTENT_ALLOCDECS |
						     inode->i_sb->s_blocksize);
			lad->extLocation = cpu_to_lelb(epos->block);
			memset(lad->impUse, 0x00, sizeof(lad->impUse));
			break;
		}
		if (epos->bh) {
			if (!UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_STRICT) ||
			    UDF_SB(inode->i_sb)->s_udfrev >= 0x0201)
				udf_update_tag(epos->bh->b_data, loffset);
			else
				udf_update_tag(epos->bh->b_data,
						sizeof(struct allocExtDesc));
			mark_buffer_dirty_inode(epos->bh, inode);
			brelse(epos->bh);
		} else {
			mark_inode_dirty(inode);
		}
		epos->bh = nbh;
	}

	udf_write_aext(inode, epos, eloc, elen, inc);

	if (!epos->bh) {
		iinfo->i_lenAlloc += adsize;
		mark_inode_dirty(inode);
	} else {
		aed = (struct allocExtDesc *)epos->bh->b_data;
		le32_add_cpu(&aed->lengthAllocDescs, adsize);
		if (!UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_STRICT) ||
				UDF_SB(inode->i_sb)->s_udfrev >= 0x0201)
			udf_update_tag(epos->bh->b_data,
					epos->offset + (inc ? 0 : adsize));
		else
			udf_update_tag(epos->bh->b_data,
					sizeof(struct allocExtDesc));
		mark_buffer_dirty_inode(epos->bh, inode);
	}

	return 0;
}

void udf_write_aext(struct inode *inode, struct extent_position *epos,
		    struct kernel_lb_addr *eloc, uint32_t elen, int inc)
{
	int adsize;
	uint8_t *ptr;
	struct short_ad *sad;
	struct long_ad *lad;
	struct udf_inode_info *iinfo = UDF_I(inode);

	if (!epos->bh)
		ptr = iinfo->i_ext.i_data + epos->offset -
			udf_file_entry_alloc_offset(inode) +
			iinfo->i_lenEAttr;
	else
		ptr = epos->bh->b_data + epos->offset;

	switch (iinfo->i_alloc_type) {
	case ICBTAG_FLAG_AD_SHORT:
		sad = (struct short_ad *)ptr;
		sad->extLength = cpu_to_le32(elen);
		sad->extPosition = cpu_to_le32(eloc->logicalBlockNum);
		adsize = sizeof(struct short_ad);
		break;
	case ICBTAG_FLAG_AD_LONG:
		lad = (struct long_ad *)ptr;
		lad->extLength = cpu_to_le32(elen);
		lad->extLocation = cpu_to_lelb(*eloc);
		memset(lad->impUse, 0x00, sizeof(lad->impUse));
		adsize = sizeof(struct long_ad);
		break;
	default:
		return;
	}

	if (epos->bh) {
		if (!UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_STRICT) ||
		    UDF_SB(inode->i_sb)->s_udfrev >= 0x0201) {
			struct allocExtDesc *aed =
				(struct allocExtDesc *)epos->bh->b_data;
			udf_update_tag(epos->bh->b_data,
				       le32_to_cpu(aed->lengthAllocDescs) +
				       sizeof(struct allocExtDesc));
		}
		mark_buffer_dirty_inode(epos->bh, inode);
	} else {
		mark_inode_dirty(inode);
	}

	if (inc)
		epos->offset += adsize;
}

int8_t udf_next_aext(struct inode *inode, struct extent_position *epos,
		     struct kernel_lb_addr *eloc, uint32_t *elen, int inc)
{
	int8_t etype;

	while ((etype = udf_current_aext(inode, epos, eloc, elen, inc)) ==
	       (EXT_NEXT_EXTENT_ALLOCDECS >> 30)) {
		int block;
		epos->block = *eloc;
		epos->offset = sizeof(struct allocExtDesc);
		brelse(epos->bh);
		block = udf_get_lb_pblock(inode->i_sb, &epos->block, 0);
		epos->bh = udf_tread(inode->i_sb, block);
		if (!epos->bh) {
			udf_debug("reading block %d failed!\n", block);
			return -1;
		}
	}

	return etype;
}

int8_t udf_current_aext(struct inode *inode, struct extent_position *epos,
			struct kernel_lb_addr *eloc, uint32_t *elen, int inc)
{
	int alen;
	int8_t etype;
	uint8_t *ptr;
	struct short_ad *sad;
	struct long_ad *lad;
	struct udf_inode_info *iinfo = UDF_I(inode);

	if (!epos->bh) {
		if (!epos->offset)
			epos->offset = udf_file_entry_alloc_offset(inode);
		ptr = iinfo->i_ext.i_data + epos->offset -
			udf_file_entry_alloc_offset(inode) +
			iinfo->i_lenEAttr;
		alen = udf_file_entry_alloc_offset(inode) +
							iinfo->i_lenAlloc;
	} else {
		if (!epos->offset)
			epos->offset = sizeof(struct allocExtDesc);
		ptr = epos->bh->b_data + epos->offset;
		alen = sizeof(struct allocExtDesc) +
			le32_to_cpu(((struct allocExtDesc *)epos->bh->b_data)->
							lengthAllocDescs);
	}

	switch (iinfo->i_alloc_type) {
	case ICBTAG_FLAG_AD_SHORT:
		sad = udf_get_fileshortad(ptr, alen, &epos->offset, inc);
		if (!sad)
			return -1;
		etype = le32_to_cpu(sad->extLength) >> 30;
		eloc->logicalBlockNum = le32_to_cpu(sad->extPosition);
		eloc->partitionReferenceNum =
				iinfo->i_location.partitionReferenceNum;
		*elen = le32_to_cpu(sad->extLength) & UDF_EXTENT_LENGTH_MASK;
		break;
	case ICBTAG_FLAG_AD_LONG:
		lad = udf_get_filelongad(ptr, alen, &epos->offset, inc);
		if (!lad)
			return -1;
		etype = le32_to_cpu(lad->extLength) >> 30;
		*eloc = lelb_to_cpu(lad->extLocation);
		*elen = le32_to_cpu(lad->extLength) & UDF_EXTENT_LENGTH_MASK;
		break;
	default:
		udf_debug("alloc_type = %d unsupported\n", iinfo->i_alloc_type);
		return -1;
	}

	return etype;
}

static int8_t udf_insert_aext(struct inode *inode, struct extent_position epos,
			      struct kernel_lb_addr neloc, uint32_t nelen)
{
	struct kernel_lb_addr oeloc;
	uint32_t oelen;
	int8_t etype;

	if (epos.bh)
		get_bh(epos.bh);

	while ((etype = udf_next_aext(inode, &epos, &oeloc, &oelen, 0)) != -1) {
		udf_write_aext(inode, &epos, &neloc, nelen, 1);
		neloc = oeloc;
		nelen = (etype << 30) | oelen;
	}
	udf_add_aext(inode, &epos, &neloc, nelen, 1);
	brelse(epos.bh);

	return (nelen >> 30);
}

int8_t udf_delete_aext(struct inode *inode, struct extent_position epos,
		       struct kernel_lb_addr eloc, uint32_t elen)
{
	struct extent_position oepos;
	int adsize;
	int8_t etype;
	struct allocExtDesc *aed;
	struct udf_inode_info *iinfo;

	if (epos.bh) {
		get_bh(epos.bh);
		get_bh(epos.bh);
	}

	iinfo = UDF_I(inode);
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		adsize = sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		adsize = sizeof(struct long_ad);
	else
		adsize = 0;

	oepos = epos;
	if (udf_next_aext(inode, &epos, &eloc, &elen, 1) == -1)
		return -1;

	while ((etype = udf_next_aext(inode, &epos, &eloc, &elen, 1)) != -1) {
		udf_write_aext(inode, &oepos, &eloc, (etype << 30) | elen, 1);
		if (oepos.bh != epos.bh) {
			oepos.block = epos.block;
			brelse(oepos.bh);
			get_bh(epos.bh);
			oepos.bh = epos.bh;
			oepos.offset = epos.offset - adsize;
		}
	}
	memset(&eloc, 0x00, sizeof(struct kernel_lb_addr));
	elen = 0;

	if (epos.bh != oepos.bh) {
		udf_free_blocks(inode->i_sb, inode, &epos.block, 0, 1);
		udf_write_aext(inode, &oepos, &eloc, elen, 1);
		udf_write_aext(inode, &oepos, &eloc, elen, 1);
		if (!oepos.bh) {
			iinfo->i_lenAlloc -= (adsize * 2);
			mark_inode_dirty(inode);
		} else {
			aed = (struct allocExtDesc *)oepos.bh->b_data;
			le32_add_cpu(&aed->lengthAllocDescs, -(2 * adsize));
			if (!UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_STRICT) ||
			    UDF_SB(inode->i_sb)->s_udfrev >= 0x0201)
				udf_update_tag(oepos.bh->b_data,
						oepos.offset - (2 * adsize));
			else
				udf_update_tag(oepos.bh->b_data,
						sizeof(struct allocExtDesc));
			mark_buffer_dirty_inode(oepos.bh, inode);
		}
	} else {
		udf_write_aext(inode, &oepos, &eloc, elen, 1);
		if (!oepos.bh) {
			iinfo->i_lenAlloc -= adsize;
			mark_inode_dirty(inode);
		} else {
			aed = (struct allocExtDesc *)oepos.bh->b_data;
			le32_add_cpu(&aed->lengthAllocDescs, -adsize);
			if (!UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_STRICT) ||
			    UDF_SB(inode->i_sb)->s_udfrev >= 0x0201)
				udf_update_tag(oepos.bh->b_data,
						epos.offset - adsize);
			else
				udf_update_tag(oepos.bh->b_data,
						sizeof(struct allocExtDesc));
			mark_buffer_dirty_inode(oepos.bh, inode);
		}
	}

	brelse(epos.bh);
	brelse(oepos.bh);

	return (elen >> 30);
}

int8_t inode_bmap(struct inode *inode, sector_t block,
		  struct extent_position *pos, struct kernel_lb_addr *eloc,
		  uint32_t *elen, sector_t *offset)
{
	unsigned char blocksize_bits = inode->i_sb->s_blocksize_bits;
	loff_t lbcount = 0, bcount =
	    (loff_t) block << blocksize_bits;
	int8_t etype;
	struct udf_inode_info *iinfo;

	iinfo = UDF_I(inode);
	if (!udf_read_extent_cache(inode, bcount, &lbcount, pos)) {
		pos->offset = 0;
		pos->block = iinfo->i_location;
		pos->bh = NULL;
	}
	*elen = 0;
	do {
		etype = udf_next_aext(inode, pos, eloc, elen, 1);
		if (etype == -1) {
			*offset = (bcount - lbcount) >> blocksize_bits;
			iinfo->i_lenExtents = lbcount;
			return -1;
		}
		lbcount += *elen;
	} while (lbcount <= bcount);
	/* update extent cache */
	udf_update_extent_cache(inode, lbcount - *elen, pos, 1);
	*offset = (bcount + *elen - lbcount) >> blocksize_bits;

	return etype;
}

long udf_block_map(struct inode *inode, sector_t block)
{
	struct kernel_lb_addr eloc;
	uint32_t elen;
	sector_t offset;
	struct extent_position epos = {};
	int ret;

	down_read(&UDF_I(inode)->i_data_sem);

	if (inode_bmap(inode, block, &epos, &eloc, &elen, &offset) ==
						(EXT_RECORDED_ALLOCATED >> 30))
		ret = udf_get_lb_pblock(inode->i_sb, &eloc, offset);
	else
		ret = 0;

	up_read(&UDF_I(inode)->i_data_sem);
	brelse(epos.bh);

	if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_VARCONV))
		return udf_fixed_to_variable(ret);
	else
		return ret;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/inode.c */
/************************************************************/
/*
 * lowlevel.c
 *
 * PURPOSE
 *  Low Level Device Routines for the UDF filesystem
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 *
 *  (C) 1999-2001 Ben Fennema
 *
 * HISTORY
 *
 *  03/26/99 blf  Created.
 */

// #include "udfdecl.h"

#include <linux/blkdev.h>
#include <linux/cdrom.h>
// #include <linux/uaccess.h>
#include "../../inc/__fss.h"

// #include "udf_sb.h"

unsigned int udf_get_last_session(struct super_block *sb)
{
	struct cdrom_multisession ms_info;
	unsigned int vol_desc_start;
	struct block_device *bdev = sb->s_bdev;
	int i;

	vol_desc_start = 0;
	ms_info.addr_format = CDROM_LBA;
	i = ioctl_by_bdev(bdev, CDROMMULTISESSION, (unsigned long)&ms_info);

	if (i == 0) {
		udf_debug("XA disk: %s, vol_desc_start=%d\n",
			  ms_info.xa_flag ? "yes" : "no", ms_info.addr.lba);
		if (ms_info.xa_flag) /* necessary for a valid ms_info.addr */
			vol_desc_start = ms_info.addr.lba;
	} else {
		udf_debug("CDROMMULTISESSION not supported: rc=%d\n", i);
	}
	return vol_desc_start;
}

unsigned long udf_get_last_block(struct super_block *sb)
{
	struct block_device *bdev = sb->s_bdev;
	unsigned long lblock = 0;

	/*
	 * ioctl failed or returned obviously bogus value?
	 * Try using the device size...
	 */
	if (ioctl_by_bdev(bdev, CDROM_LAST_WRITTEN, (unsigned long) &lblock) ||
	    lblock == 0)
		lblock = bdev->bd_inode->i_size >> sb->s_blocksize_bits;

	if (lblock)
		return lblock - 1;
	else
		return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/lowlevel.c */
/************************************************************/
/*
 * namei.c
 *
 * PURPOSE
 *      Inode name handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *      This file is distributed under the terms of the GNU General Public
 *      License (GPL). Copies of the GPL can be obtained from:
 *              ftp://prep.ai.mit.edu/pub/gnu/GPL
 *      Each contributing author retains all rights to their own work.
 *
 *  (C) 1998-2004 Ben Fennema
 *  (C) 1999-2000 Stelias Computing Inc
 *
 * HISTORY
 *
 *  12/12/98 blf  Created. Split out the lookup code from dir.c
 *  04/19/99 blf  link, mknod, symlink support
 */

// #include "udfdecl.h"

// #include "udf_i.h"
// #include "udf_sb.h"
// #include <linux/string.h>
// #include <linux/errno.h>
// #include <linux/mm.h>
// #include <linux/slab.h>
// #include <linux/buffer_head.h>
// #include <linux/sched.h>
// #include <linux/crc-itu-t.h>
#include <linux/exportfs.h>
#include "../../inc/__fss.h"

static inline int udf_match(int len1, const unsigned char *name1, int len2,
			    const unsigned char *name2)
{
	if (len1 != len2)
		return 0;

	return !memcmp(name1, name2, len1);
}

int udf_write_fi(struct inode *inode, struct fileIdentDesc *cfi,
		 struct fileIdentDesc *sfi, struct udf_fileident_bh *fibh,
		 uint8_t *impuse, uint8_t *fileident)
{
	uint16_t crclen = fibh->eoffset - fibh->soffset - sizeof(struct tag);
	uint16_t crc;
	int offset;
	uint16_t liu = le16_to_cpu(cfi->lengthOfImpUse);
	uint8_t lfi = cfi->lengthFileIdent;
	int padlen = fibh->eoffset - fibh->soffset - liu - lfi -
		sizeof(struct fileIdentDesc);
	int adinicb = 0;

	if (UDF_I(inode)->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
		adinicb = 1;

	offset = fibh->soffset + sizeof(struct fileIdentDesc);

	if (impuse) {
		if (adinicb || (offset + liu < 0)) {
			memcpy((uint8_t *)sfi->impUse, impuse, liu);
		} else if (offset >= 0) {
			memcpy(fibh->ebh->b_data + offset, impuse, liu);
		} else {
			memcpy((uint8_t *)sfi->impUse, impuse, -offset);
			memcpy(fibh->ebh->b_data, impuse - offset,
				liu + offset);
		}
	}

	offset += liu;

	if (fileident) {
		if (adinicb || (offset + lfi < 0)) {
			memcpy((uint8_t *)sfi->fileIdent + liu, fileident, lfi);
		} else if (offset >= 0) {
			memcpy(fibh->ebh->b_data + offset, fileident, lfi);
		} else {
			memcpy((uint8_t *)sfi->fileIdent + liu, fileident,
				-offset);
			memcpy(fibh->ebh->b_data, fileident - offset,
				lfi + offset);
		}
	}

	offset += lfi;

	if (adinicb || (offset + padlen < 0)) {
		memset((uint8_t *)sfi->padding + liu + lfi, 0x00, padlen);
	} else if (offset >= 0) {
		memset(fibh->ebh->b_data + offset, 0x00, padlen);
	} else {
		memset((uint8_t *)sfi->padding + liu + lfi, 0x00, -offset);
		memset(fibh->ebh->b_data, 0x00, padlen + offset);
	}

	crc = crc_itu_t(0, (uint8_t *)cfi + sizeof(struct tag),
		      sizeof(struct fileIdentDesc) - sizeof(struct tag));

	if (fibh->sbh == fibh->ebh) {
		crc = crc_itu_t(crc, (uint8_t *)sfi->impUse,
			      crclen + sizeof(struct tag) -
			      sizeof(struct fileIdentDesc));
	} else if (sizeof(struct fileIdentDesc) >= -fibh->soffset) {
		crc = crc_itu_t(crc, fibh->ebh->b_data +
					sizeof(struct fileIdentDesc) +
					fibh->soffset,
			      crclen + sizeof(struct tag) -
					sizeof(struct fileIdentDesc));
	} else {
		crc = crc_itu_t(crc, (uint8_t *)sfi->impUse,
			      -fibh->soffset - sizeof(struct fileIdentDesc));
		crc = crc_itu_t(crc, fibh->ebh->b_data, fibh->eoffset);
	}

	cfi->descTag.descCRC = cpu_to_le16(crc);
	cfi->descTag.descCRCLength = cpu_to_le16(crclen);
	cfi->descTag.tagChecksum = udf_tag_checksum(&cfi->descTag);

	if (adinicb || (sizeof(struct fileIdentDesc) <= -fibh->soffset)) {
		memcpy((uint8_t *)sfi, (uint8_t *)cfi,
			sizeof(struct fileIdentDesc));
	} else {
		memcpy((uint8_t *)sfi, (uint8_t *)cfi, -fibh->soffset);
		memcpy(fibh->ebh->b_data, (uint8_t *)cfi - fibh->soffset,
		       sizeof(struct fileIdentDesc) + fibh->soffset);
	}

	if (adinicb) {
		mark_inode_dirty(inode);
	} else {
		if (fibh->sbh != fibh->ebh)
			mark_buffer_dirty_inode(fibh->ebh, inode);
		mark_buffer_dirty_inode(fibh->sbh, inode);
	}
	return 0;
}

static struct fileIdentDesc *udf_find_entry(struct inode *dir,
					    const struct qstr *child,
					    struct udf_fileident_bh *fibh,
					    struct fileIdentDesc *cfi)
{
	struct fileIdentDesc *fi = NULL;
	loff_t f_pos;
	int block, flen;
	unsigned char *fname = NULL;
	unsigned char *nameptr;
	uint8_t lfi;
	uint16_t liu;
	loff_t size;
	struct kernel_lb_addr eloc;
	uint32_t elen;
	sector_t offset;
	struct extent_position epos = {};
	struct udf_inode_info *dinfo = UDF_I(dir);
	int isdotdot = child->len == 2 &&
		child->name[0] == '.' && child->name[1] == '.';
	struct super_block *sb = dir->i_sb;

	size = udf_ext0_offset(dir) + dir->i_size;
	f_pos = udf_ext0_offset(dir);

	fibh->sbh = fibh->ebh = NULL;
	fibh->soffset = fibh->eoffset = f_pos & (sb->s_blocksize - 1);
	if (dinfo->i_alloc_type != ICBTAG_FLAG_AD_IN_ICB) {
		if (inode_bmap(dir, f_pos >> sb->s_blocksize_bits, &epos,
		    &eloc, &elen, &offset) != (EXT_RECORDED_ALLOCATED >> 30))
			goto out_err;
		block = udf_get_lb_pblock(sb, &eloc, offset);
		if ((++offset << sb->s_blocksize_bits) < elen) {
			if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
				epos.offset -= sizeof(struct short_ad);
			else if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
				epos.offset -= sizeof(struct long_ad);
		} else
			offset = 0;

		fibh->sbh = fibh->ebh = udf_tread(sb, block);
		if (!fibh->sbh)
			goto out_err;
	}

	fname = kmalloc(UDF_NAME_LEN, GFP_NOFS);
	if (!fname)
		goto out_err;

	while (f_pos < size) {
		fi = udf_fileident_read(dir, &f_pos, fibh, cfi, &epos, &eloc,
					&elen, &offset);
		if (!fi)
			goto out_err;

		liu = le16_to_cpu(cfi->lengthOfImpUse);
		lfi = cfi->lengthFileIdent;

		if (fibh->sbh == fibh->ebh) {
			nameptr = fi->fileIdent + liu;
		} else {
			int poffset;	/* Unpaded ending offset */

			poffset = fibh->soffset + sizeof(struct fileIdentDesc) +
					liu + lfi;

			if (poffset >= lfi)
				nameptr = (uint8_t *)(fibh->ebh->b_data +
						      poffset - lfi);
			else {
				nameptr = fname;
				memcpy(nameptr, fi->fileIdent + liu,
					lfi - poffset);
				memcpy(nameptr + lfi - poffset,
					fibh->ebh->b_data, poffset);
			}
		}

		if ((cfi->fileCharacteristics & FID_FILE_CHAR_DELETED) != 0) {
			if (!UDF_QUERY_FLAG(sb, UDF_FLAG_UNDELETE))
				continue;
		}

		if ((cfi->fileCharacteristics & FID_FILE_CHAR_HIDDEN) != 0) {
			if (!UDF_QUERY_FLAG(sb, UDF_FLAG_UNHIDE))
				continue;
		}

		if ((cfi->fileCharacteristics & FID_FILE_CHAR_PARENT) &&
		    isdotdot)
			goto out_ok;

		if (!lfi)
			continue;

		flen = udf_get_filename(sb, nameptr, lfi, fname, UDF_NAME_LEN);
		if (flen && udf_match(flen, fname, child->len, child->name))
			goto out_ok;
	}

out_err:
	fi = NULL;
	if (fibh->sbh != fibh->ebh)
		brelse(fibh->ebh);
	brelse(fibh->sbh);
out_ok:
	brelse(epos.bh);
	kfree(fname);

	return fi;
}

static struct dentry *udf_lookup(struct inode *dir, struct dentry *dentry,
				 unsigned int flags)
{
	struct inode *inode = NULL;
	struct fileIdentDesc cfi;
	struct udf_fileident_bh fibh;

	if (dentry->d_name.len > UDF_NAME_LEN - 2)
		return ERR_PTR(-ENAMETOOLONG);

#ifdef UDF_RECOVERY
	/* temporary shorthand for specifying files by inode number */
	if (!strncmp(dentry->d_name.name, ".B=", 3)) {
		struct kernel_lb_addr lb = {
			.logicalBlockNum = 0,
			.partitionReferenceNum =
				simple_strtoul(dentry->d_name.name + 3,
						NULL, 0),
		};
		inode = udf_iget(dir->i_sb, lb);
		if (IS_ERR(inode))
			return inode;
	} else
#endif /* UDF_RECOVERY */

	if (udf_find_entry(dir, &dentry->d_name, &fibh, &cfi)) {
		struct kernel_lb_addr loc;

		if (fibh.sbh != fibh.ebh)
			brelse(fibh.ebh);
		brelse(fibh.sbh);

		loc = lelb_to_cpu(cfi.icb.extLocation);
		inode = udf_iget(dir->i_sb, &loc);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}

	return d_splice_alias(inode, dentry);
}

static struct fileIdentDesc *udf_add_entry(struct inode *dir,
					   struct dentry *dentry,
					   struct udf_fileident_bh *fibh,
					   struct fileIdentDesc *cfi, int *err)
{
	struct super_block *sb = dir->i_sb;
	struct fileIdentDesc *fi = NULL;
	unsigned char *name = NULL;
	int namelen;
	loff_t f_pos;
	loff_t size = udf_ext0_offset(dir) + dir->i_size;
	int nfidlen;
	uint8_t lfi;
	uint16_t liu;
	int block;
	struct kernel_lb_addr eloc;
	uint32_t elen = 0;
	sector_t offset;
	struct extent_position epos = {};
	struct udf_inode_info *dinfo;

	fibh->sbh = fibh->ebh = NULL;
	name = kmalloc(UDF_NAME_LEN, GFP_NOFS);
	if (!name) {
		*err = -ENOMEM;
		goto out_err;
	}

	if (dentry) {
		if (!dentry->d_name.len) {
			*err = -EINVAL;
			goto out_err;
		}
		namelen = udf_put_filename(sb, dentry->d_name.name, name,
						 dentry->d_name.len);
		if (!namelen) {
			*err = -ENAMETOOLONG;
			goto out_err;
		}
	} else {
		namelen = 0;
	}

	nfidlen = (sizeof(struct fileIdentDesc) + namelen + 3) & ~3;

	f_pos = udf_ext0_offset(dir);

	fibh->soffset = fibh->eoffset = f_pos & (dir->i_sb->s_blocksize - 1);
	dinfo = UDF_I(dir);
	if (dinfo->i_alloc_type != ICBTAG_FLAG_AD_IN_ICB) {
		if (inode_bmap(dir, f_pos >> dir->i_sb->s_blocksize_bits, &epos,
		    &eloc, &elen, &offset) != (EXT_RECORDED_ALLOCATED >> 30)) {
			block = udf_get_lb_pblock(dir->i_sb,
					&dinfo->i_location, 0);
			fibh->soffset = fibh->eoffset = sb->s_blocksize;
			goto add;
		}
		block = udf_get_lb_pblock(dir->i_sb, &eloc, offset);
		if ((++offset << dir->i_sb->s_blocksize_bits) < elen) {
			if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
				epos.offset -= sizeof(struct short_ad);
			else if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
				epos.offset -= sizeof(struct long_ad);
		} else
			offset = 0;

		fibh->sbh = fibh->ebh = udf_tread(dir->i_sb, block);
		if (!fibh->sbh) {
			*err = -EIO;
			goto out_err;
		}

		block = dinfo->i_location.logicalBlockNum;
	}

	while (f_pos < size) {
		fi = udf_fileident_read(dir, &f_pos, fibh, cfi, &epos, &eloc,
					&elen, &offset);

		if (!fi) {
			*err = -EIO;
			goto out_err;
		}

		liu = le16_to_cpu(cfi->lengthOfImpUse);
		lfi = cfi->lengthFileIdent;

		if ((cfi->fileCharacteristics & FID_FILE_CHAR_DELETED) != 0) {
			if (((sizeof(struct fileIdentDesc) +
					liu + lfi + 3) & ~3) == nfidlen) {
				cfi->descTag.tagSerialNum = cpu_to_le16(1);
				cfi->fileVersionNum = cpu_to_le16(1);
				cfi->fileCharacteristics = 0;
				cfi->lengthFileIdent = namelen;
				cfi->lengthOfImpUse = cpu_to_le16(0);
				if (!udf_write_fi(dir, cfi, fi, fibh, NULL,
						  name))
					goto out_ok;
				else {
					*err = -EIO;
					goto out_err;
				}
			}
		}
	}

add:
	f_pos += nfidlen;

	if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB &&
	    sb->s_blocksize - fibh->eoffset < nfidlen) {
		brelse(epos.bh);
		epos.bh = NULL;
		fibh->soffset -= udf_ext0_offset(dir);
		fibh->eoffset -= udf_ext0_offset(dir);
		f_pos -= udf_ext0_offset(dir);
		if (fibh->sbh != fibh->ebh)
			brelse(fibh->ebh);
		brelse(fibh->sbh);
		fibh->sbh = fibh->ebh =
				udf_expand_dir_adinicb(dir, &block, err);
		if (!fibh->sbh)
			goto out_err;
		epos.block = dinfo->i_location;
		epos.offset = udf_file_entry_alloc_offset(dir);
		/* Load extent udf_expand_dir_adinicb() has created */
		udf_current_aext(dir, &epos, &eloc, &elen, 1);
	}

	/* Entry fits into current block? */
	if (sb->s_blocksize - fibh->eoffset >= nfidlen) {
		fibh->soffset = fibh->eoffset;
		fibh->eoffset += nfidlen;
		if (fibh->sbh != fibh->ebh) {
			brelse(fibh->sbh);
			fibh->sbh = fibh->ebh;
		}

		if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
			block = dinfo->i_location.logicalBlockNum;
			fi = (struct fileIdentDesc *)
					(dinfo->i_ext.i_data +
					 fibh->soffset -
					 udf_ext0_offset(dir) +
					 dinfo->i_lenEAttr);
		} else {
			block = eloc.logicalBlockNum +
					((elen - 1) >>
						dir->i_sb->s_blocksize_bits);
			fi = (struct fileIdentDesc *)
				(fibh->sbh->b_data + fibh->soffset);
		}
	} else {
		/* Round up last extent in the file */
		elen = (elen + sb->s_blocksize - 1) & ~(sb->s_blocksize - 1);
		if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
			epos.offset -= sizeof(struct short_ad);
		else if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
			epos.offset -= sizeof(struct long_ad);
		udf_write_aext(dir, &epos, &eloc, elen, 1);
		dinfo->i_lenExtents = (dinfo->i_lenExtents + sb->s_blocksize
					- 1) & ~(sb->s_blocksize - 1);

		fibh->soffset = fibh->eoffset - sb->s_blocksize;
		fibh->eoffset += nfidlen - sb->s_blocksize;
		if (fibh->sbh != fibh->ebh) {
			brelse(fibh->sbh);
			fibh->sbh = fibh->ebh;
		}

		block = eloc.logicalBlockNum + ((elen - 1) >>
						dir->i_sb->s_blocksize_bits);
		fibh->ebh = udf_bread(dir,
				f_pos >> dir->i_sb->s_blocksize_bits, 1, err);
		if (!fibh->ebh)
			goto out_err;
		/* Extents could have been merged, invalidate our position */
		brelse(epos.bh);
		epos.bh = NULL;
		epos.block = dinfo->i_location;
		epos.offset = udf_file_entry_alloc_offset(dir);

		if (!fibh->soffset) {
			/* Find the freshly allocated block */
			while (udf_next_aext(dir, &epos, &eloc, &elen, 1) ==
				(EXT_RECORDED_ALLOCATED >> 30))
				;
			block = eloc.logicalBlockNum + ((elen - 1) >>
					dir->i_sb->s_blocksize_bits);
			brelse(fibh->sbh);
			fibh->sbh = fibh->ebh;
			fi = (struct fileIdentDesc *)(fibh->sbh->b_data);
		} else {
			fi = (struct fileIdentDesc *)
				(fibh->sbh->b_data + sb->s_blocksize +
					fibh->soffset);
		}
	}

	memset(cfi, 0, sizeof(struct fileIdentDesc));
	if (UDF_SB(sb)->s_udfrev >= 0x0200)
		udf_new_tag((char *)cfi, TAG_IDENT_FID, 3, 1, block,
			    sizeof(struct tag));
	else
		udf_new_tag((char *)cfi, TAG_IDENT_FID, 2, 1, block,
			    sizeof(struct tag));
	cfi->fileVersionNum = cpu_to_le16(1);
	cfi->lengthFileIdent = namelen;
	cfi->lengthOfImpUse = cpu_to_le16(0);
	if (!udf_write_fi(dir, cfi, fi, fibh, NULL, name)) {
		dir->i_size += nfidlen;
		if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
			dinfo->i_lenAlloc += nfidlen;
		else {
			/* Find the last extent and truncate it to proper size */
			while (udf_next_aext(dir, &epos, &eloc, &elen, 1) ==
				(EXT_RECORDED_ALLOCATED >> 30))
				;
			elen -= dinfo->i_lenExtents - dir->i_size;
			if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
				epos.offset -= sizeof(struct short_ad);
			else if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
				epos.offset -= sizeof(struct long_ad);
			udf_write_aext(dir, &epos, &eloc, elen, 1);
			dinfo->i_lenExtents = dir->i_size;
		}

		mark_inode_dirty(dir);
		goto out_ok;
	} else {
		*err = -EIO;
		goto out_err;
	}

out_err:
	fi = NULL;
	if (fibh->sbh != fibh->ebh)
		brelse(fibh->ebh);
	brelse(fibh->sbh);
out_ok:
	brelse(epos.bh);
	kfree(name);
	return fi;
}

static int udf_delete_entry(struct inode *inode, struct fileIdentDesc *fi,
			    struct udf_fileident_bh *fibh,
			    struct fileIdentDesc *cfi)
{
	cfi->fileCharacteristics |= FID_FILE_CHAR_DELETED;

	if (UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_STRICT))
		memset(&(cfi->icb), 0x00, sizeof(struct long_ad));

	return udf_write_fi(inode, cfi, fi, fibh, NULL, NULL);
}

static int udf_add_nondir(struct dentry *dentry, struct inode *inode)
{
	struct udf_inode_info *iinfo = UDF_I(inode);
	struct inode *dir = dentry->d_parent->d_inode;
	struct udf_fileident_bh fibh;
	struct fileIdentDesc cfi, *fi;
	int err;

	fi = udf_add_entry(dir, dentry, &fibh, &cfi, &err);
	if (unlikely(!fi)) {
		inode_dec_link_count(inode);
		unlock_new_inode(inode);
		iput(inode);
		return err;
	}
	cfi.icb.extLength = cpu_to_le32(inode->i_sb->s_blocksize);
	cfi.icb.extLocation = cpu_to_lelb(iinfo->i_location);
	*(__le32 *)((struct allocDescImpUse *)cfi.icb.impUse)->impUse =
		cpu_to_le32(iinfo->i_unique & 0x00000000FFFFFFFFUL);
	udf_write_fi(dir, &cfi, fi, &fibh, NULL, NULL);
	if (UDF_I(dir)->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
		mark_inode_dirty(dir);
	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);
	unlock_new_inode(inode);
	d_instantiate(dentry, inode);

	return 0;
}

static int udf_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		      bool excl)
{
	struct inode *inode = udf_new_inode(dir, mode);

	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (UDF_I(inode)->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
		inode->i_data.a_ops = &udf_adinicb_aops;
	else
		inode->i_data.a_ops = &udf_aops;
	inode->i_op = &udf_file_inode_operations;
	inode->i_fop = &udf_file_operations;
	mark_inode_dirty(inode);

	return udf_add_nondir(dentry, inode);
}

static int udf_tmpfile(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode = udf_new_inode(dir, mode);

	if (IS_ERR(inode))
		return PTR_ERR(inode);

	if (UDF_I(inode)->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
		inode->i_data.a_ops = &udf_adinicb_aops;
	else
		inode->i_data.a_ops = &udf_aops;
	inode->i_op = &udf_file_inode_operations;
	inode->i_fop = &udf_file_operations;
	mark_inode_dirty(inode);
	d_tmpfile(dentry, inode);
	unlock_new_inode(inode);
	return 0;
}

static int udf_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		     dev_t rdev)
{
	struct inode *inode;

	if (!old_valid_dev(rdev))
		return -EINVAL;

	inode = udf_new_inode(dir, mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	init_special_inode(inode, mode, rdev);
	return udf_add_nondir(dentry, inode);
}

static int udf_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct udf_fileident_bh fibh;
	struct fileIdentDesc cfi, *fi;
	int err;
	struct udf_inode_info *dinfo = UDF_I(dir);
	struct udf_inode_info *iinfo;

	inode = udf_new_inode(dir, S_IFDIR | mode);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	iinfo = UDF_I(inode);
	inode->i_op = &udf_dir_inode_operations;
	inode->i_fop = &udf_dir_operations;
	fi = udf_add_entry(inode, NULL, &fibh, &cfi, &err);
	if (!fi) {
		inode_dec_link_count(inode);
		unlock_new_inode(inode);
		iput(inode);
		goto out;
	}
	set_nlink(inode, 2);
	cfi.icb.extLength = cpu_to_le32(inode->i_sb->s_blocksize);
	cfi.icb.extLocation = cpu_to_lelb(dinfo->i_location);
	*(__le32 *)((struct allocDescImpUse *)cfi.icb.impUse)->impUse =
		cpu_to_le32(dinfo->i_unique & 0x00000000FFFFFFFFUL);
	cfi.fileCharacteristics =
			FID_FILE_CHAR_DIRECTORY | FID_FILE_CHAR_PARENT;
	udf_write_fi(inode, &cfi, fi, &fibh, NULL, NULL);
	brelse(fibh.sbh);
	mark_inode_dirty(inode);

	fi = udf_add_entry(dir, dentry, &fibh, &cfi, &err);
	if (!fi) {
		clear_nlink(inode);
		mark_inode_dirty(inode);
		unlock_new_inode(inode);
		iput(inode);
		goto out;
	}
	cfi.icb.extLength = cpu_to_le32(inode->i_sb->s_blocksize);
	cfi.icb.extLocation = cpu_to_lelb(iinfo->i_location);
	*(__le32 *)((struct allocDescImpUse *)cfi.icb.impUse)->impUse =
		cpu_to_le32(iinfo->i_unique & 0x00000000FFFFFFFFUL);
	cfi.fileCharacteristics |= FID_FILE_CHAR_DIRECTORY;
	udf_write_fi(dir, &cfi, fi, &fibh, NULL, NULL);
	inc_nlink(dir);
	mark_inode_dirty(dir);
	unlock_new_inode(inode);
	d_instantiate(dentry, inode);
	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);
	err = 0;

out:
	return err;
}

static int empty_dir(struct inode *dir)
{
	struct fileIdentDesc *fi, cfi;
	struct udf_fileident_bh fibh;
	loff_t f_pos;
	loff_t size = udf_ext0_offset(dir) + dir->i_size;
	int block;
	struct kernel_lb_addr eloc;
	uint32_t elen;
	sector_t offset;
	struct extent_position epos = {};
	struct udf_inode_info *dinfo = UDF_I(dir);

	f_pos = udf_ext0_offset(dir);
	fibh.soffset = fibh.eoffset = f_pos & (dir->i_sb->s_blocksize - 1);

	if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
		fibh.sbh = fibh.ebh = NULL;
	else if (inode_bmap(dir, f_pos >> dir->i_sb->s_blocksize_bits,
			      &epos, &eloc, &elen, &offset) ==
					(EXT_RECORDED_ALLOCATED >> 30)) {
		block = udf_get_lb_pblock(dir->i_sb, &eloc, offset);
		if ((++offset << dir->i_sb->s_blocksize_bits) < elen) {
			if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
				epos.offset -= sizeof(struct short_ad);
			else if (dinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
				epos.offset -= sizeof(struct long_ad);
		} else
			offset = 0;

		fibh.sbh = fibh.ebh = udf_tread(dir->i_sb, block);
		if (!fibh.sbh) {
			brelse(epos.bh);
			return 0;
		}
	} else {
		brelse(epos.bh);
		return 0;
	}

	while (f_pos < size) {
		fi = udf_fileident_read(dir, &f_pos, &fibh, &cfi, &epos, &eloc,
					&elen, &offset);
		if (!fi) {
			if (fibh.sbh != fibh.ebh)
				brelse(fibh.ebh);
			brelse(fibh.sbh);
			brelse(epos.bh);
			return 0;
		}

		if (cfi.lengthFileIdent &&
		    (cfi.fileCharacteristics & FID_FILE_CHAR_DELETED) == 0) {
			if (fibh.sbh != fibh.ebh)
				brelse(fibh.ebh);
			brelse(fibh.sbh);
			brelse(epos.bh);
			return 0;
		}
	}

	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);
	brelse(epos.bh);

	return 1;
}

static int udf_rmdir(struct inode *dir, struct dentry *dentry)
{
	int retval;
	struct inode *inode = dentry->d_inode;
	struct udf_fileident_bh fibh;
	struct fileIdentDesc *fi, cfi;
	struct kernel_lb_addr tloc;

	retval = -ENOENT;
	fi = udf_find_entry(dir, &dentry->d_name, &fibh, &cfi);
	if (!fi)
		goto out;

	retval = -EIO;
	tloc = lelb_to_cpu(cfi.icb.extLocation);
	if (udf_get_lb_pblock(dir->i_sb, &tloc, 0) != inode->i_ino)
		goto end_rmdir;
	retval = -ENOTEMPTY;
	if (!empty_dir(inode))
		goto end_rmdir;
	retval = udf_delete_entry(dir, fi, &fibh, &cfi);
	if (retval)
		goto end_rmdir;
	if (inode->i_nlink != 2)
		udf_warn(inode->i_sb, "empty directory has nlink != 2 (%d)\n",
			 inode->i_nlink);
	clear_nlink(inode);
	inode->i_size = 0;
	inode_dec_link_count(dir);
	inode->i_ctime = dir->i_ctime = dir->i_mtime =
						current_fs_time(dir->i_sb);
	mark_inode_dirty(dir);

end_rmdir:
	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);

out:
	return retval;
}

static int udf_unlink(struct inode *dir, struct dentry *dentry)
{
	int retval;
	struct inode *inode = dentry->d_inode;
	struct udf_fileident_bh fibh;
	struct fileIdentDesc *fi;
	struct fileIdentDesc cfi;
	struct kernel_lb_addr tloc;

	retval = -ENOENT;
	fi = udf_find_entry(dir, &dentry->d_name, &fibh, &cfi);
	if (!fi)
		goto out;

	retval = -EIO;
	tloc = lelb_to_cpu(cfi.icb.extLocation);
	if (udf_get_lb_pblock(dir->i_sb, &tloc, 0) != inode->i_ino)
		goto end_unlink;

	if (!inode->i_nlink) {
		udf_debug("Deleting nonexistent file (%lu), %d\n",
			  inode->i_ino, inode->i_nlink);
		set_nlink(inode, 1);
	}
	retval = udf_delete_entry(dir, fi, &fibh, &cfi);
	if (retval)
		goto end_unlink;
	dir->i_ctime = dir->i_mtime = current_fs_time(dir->i_sb);
	mark_inode_dirty(dir);
	inode_dec_link_count(inode);
	inode->i_ctime = dir->i_ctime;
	retval = 0;

end_unlink:
	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);

out:
	return retval;
}

static int udf_symlink(struct inode *dir, struct dentry *dentry,
		       const char *symname)
{
	struct inode *inode = udf_new_inode(dir, S_IFLNK | S_IRWXUGO);
	struct pathComponent *pc;
	const char *compstart;
	struct extent_position epos = {};
	int eoffset, elen = 0;
	uint8_t *ea;
	int err;
	int block;
	unsigned char *name = NULL;
	int namelen;
	struct udf_inode_info *iinfo;
	struct super_block *sb = dir->i_sb;

	if (IS_ERR(inode))
		return PTR_ERR(inode);

	iinfo = UDF_I(inode);
	down_write(&iinfo->i_data_sem);
	name = kmalloc(UDF_NAME_LEN, GFP_NOFS);
	if (!name) {
		err = -ENOMEM;
		goto out_no_entry;
	}

	inode->i_data.a_ops = &udf_symlink_aops;
	inode->i_op = &udf_symlink_inode_operations;

	if (iinfo->i_alloc_type != ICBTAG_FLAG_AD_IN_ICB) {
		struct kernel_lb_addr eloc;
		uint32_t bsize;

		block = udf_new_block(sb, inode,
				iinfo->i_location.partitionReferenceNum,
				iinfo->i_location.logicalBlockNum, &err);
		if (!block)
			goto out_no_entry;
		epos.block = iinfo->i_location;
		epos.offset = udf_file_entry_alloc_offset(inode);
		epos.bh = NULL;
		eloc.logicalBlockNum = block;
		eloc.partitionReferenceNum =
				iinfo->i_location.partitionReferenceNum;
		bsize = sb->s_blocksize;
		iinfo->i_lenExtents = bsize;
		udf_add_aext(inode, &epos, &eloc, bsize, 0);
		brelse(epos.bh);

		block = udf_get_pblock(sb, block,
				iinfo->i_location.partitionReferenceNum,
				0);
		epos.bh = udf_tgetblk(sb, block);
		lock_buffer(epos.bh);
		memset(epos.bh->b_data, 0x00, bsize);
		set_buffer_uptodate(epos.bh);
		unlock_buffer(epos.bh);
		mark_buffer_dirty_inode(epos.bh, inode);
		ea = epos.bh->b_data + udf_ext0_offset(inode);
	} else
		ea = iinfo->i_ext.i_data + iinfo->i_lenEAttr;

	eoffset = sb->s_blocksize - udf_ext0_offset(inode);
	pc = (struct pathComponent *)ea;

	if (*symname == '/') {
		do {
			symname++;
		} while (*symname == '/');

		pc->componentType = 1;
		pc->lengthComponentIdent = 0;
		pc->componentFileVersionNum = 0;
		elen += sizeof(struct pathComponent);
	}

	err = -ENAMETOOLONG;

	while (*symname) {
		if (elen + sizeof(struct pathComponent) > eoffset)
			goto out_no_entry;

		pc = (struct pathComponent *)(ea + elen);

		compstart = symname;

		do {
			symname++;
		} while (*symname && *symname != '/');

		pc->componentType = 5;
		pc->lengthComponentIdent = 0;
		pc->componentFileVersionNum = 0;
		if (compstart[0] == '.') {
			if ((symname - compstart) == 1)
				pc->componentType = 4;
			else if ((symname - compstart) == 2 &&
					compstart[1] == '.')
				pc->componentType = 3;
		}

		if (pc->componentType == 5) {
			namelen = udf_put_filename(sb, compstart, name,
						   symname - compstart);
			if (!namelen)
				goto out_no_entry;

			if (elen + sizeof(struct pathComponent) + namelen >
					eoffset)
				goto out_no_entry;
			else
				pc->lengthComponentIdent = namelen;

			memcpy(pc->componentIdent, name, namelen);
		}

		elen += sizeof(struct pathComponent) + pc->lengthComponentIdent;

		if (*symname) {
			do {
				symname++;
			} while (*symname == '/');
		}
	}

	brelse(epos.bh);
	inode->i_size = elen;
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
		iinfo->i_lenAlloc = inode->i_size;
	else
		udf_truncate_tail_extent(inode);
	mark_inode_dirty(inode);
	up_write(&iinfo->i_data_sem);

	err = udf_add_nondir(dentry, inode);
out:
	kfree(name);
	return err;

out_no_entry:
	up_write(&iinfo->i_data_sem);
	inode_dec_link_count(inode);
	unlock_new_inode(inode);
	iput(inode);
	goto out;
}

static int udf_link(struct dentry *old_dentry, struct inode *dir,
		    struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	struct udf_fileident_bh fibh;
	struct fileIdentDesc cfi, *fi;
	int err;

	fi = udf_add_entry(dir, dentry, &fibh, &cfi, &err);
	if (!fi) {
		return err;
	}
	cfi.icb.extLength = cpu_to_le32(inode->i_sb->s_blocksize);
	cfi.icb.extLocation = cpu_to_lelb(UDF_I(inode)->i_location);
	if (UDF_SB(inode->i_sb)->s_lvid_bh) {
		*(__le32 *)((struct allocDescImpUse *)cfi.icb.impUse)->impUse =
			cpu_to_le32(lvid_get_unique_id(inode->i_sb));
	}
	udf_write_fi(dir, &cfi, fi, &fibh, NULL, NULL);
	if (UDF_I(dir)->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
		mark_inode_dirty(dir);

	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);
	inc_nlink(inode);
	inode->i_ctime = current_fs_time(inode->i_sb);
	mark_inode_dirty(inode);
	ihold(inode);
	d_instantiate(dentry, inode);

	return 0;
}

/* Anybody can rename anything with this: the permission checks are left to the
 * higher-level routines.
 */
static int udf_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct udf_fileident_bh ofibh, nfibh;
	struct fileIdentDesc *ofi = NULL, *nfi = NULL, *dir_fi = NULL;
	struct fileIdentDesc ocfi, ncfi;
	struct buffer_head *dir_bh = NULL;
	int retval = -ENOENT;
	struct kernel_lb_addr tloc;
	struct udf_inode_info *old_iinfo = UDF_I(old_inode);

	ofi = udf_find_entry(old_dir, &old_dentry->d_name, &ofibh, &ocfi);
	if (ofi) {
		if (ofibh.sbh != ofibh.ebh)
			brelse(ofibh.ebh);
		brelse(ofibh.sbh);
	}
	tloc = lelb_to_cpu(ocfi.icb.extLocation);
	if (!ofi || udf_get_lb_pblock(old_dir->i_sb, &tloc, 0)
	    != old_inode->i_ino)
		goto end_rename;

	nfi = udf_find_entry(new_dir, &new_dentry->d_name, &nfibh, &ncfi);
	if (nfi) {
		if (!new_inode) {
			if (nfibh.sbh != nfibh.ebh)
				brelse(nfibh.ebh);
			brelse(nfibh.sbh);
			nfi = NULL;
		}
	}
	if (S_ISDIR(old_inode->i_mode)) {
		int offset = udf_ext0_offset(old_inode);

		if (new_inode) {
			retval = -ENOTEMPTY;
			if (!empty_dir(new_inode))
				goto end_rename;
		}
		retval = -EIO;
		if (old_iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
			dir_fi = udf_get_fileident(
					old_iinfo->i_ext.i_data -
					  (old_iinfo->i_efe ?
					   sizeof(struct extendedFileEntry) :
					   sizeof(struct fileEntry)),
					old_inode->i_sb->s_blocksize, &offset);
		} else {
			dir_bh = udf_bread(old_inode, 0, 0, &retval);
			if (!dir_bh)
				goto end_rename;
			dir_fi = udf_get_fileident(dir_bh->b_data,
					old_inode->i_sb->s_blocksize, &offset);
		}
		if (!dir_fi)
			goto end_rename;
		tloc = lelb_to_cpu(dir_fi->icb.extLocation);
		if (udf_get_lb_pblock(old_inode->i_sb, &tloc, 0) !=
				old_dir->i_ino)
			goto end_rename;
	}
	if (!nfi) {
		nfi = udf_add_entry(new_dir, new_dentry, &nfibh, &ncfi,
				    &retval);
		if (!nfi)
			goto end_rename;
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
	 * rename.
	 */
	old_inode->i_ctime = current_fs_time(old_inode->i_sb);
	mark_inode_dirty(old_inode);

	/*
	 * ok, that's it
	 */
	ncfi.fileVersionNum = ocfi.fileVersionNum;
	ncfi.fileCharacteristics = ocfi.fileCharacteristics;
	memcpy(&(ncfi.icb), &(ocfi.icb), sizeof(struct long_ad));
	udf_write_fi(new_dir, &ncfi, nfi, &nfibh, NULL, NULL);

	/* The old fid may have moved - find it again */
	ofi = udf_find_entry(old_dir, &old_dentry->d_name, &ofibh, &ocfi);
	udf_delete_entry(old_dir, ofi, &ofibh, &ocfi);

	if (new_inode) {
		new_inode->i_ctime = current_fs_time(new_inode->i_sb);
		inode_dec_link_count(new_inode);
	}
	old_dir->i_ctime = old_dir->i_mtime = current_fs_time(old_dir->i_sb);
	mark_inode_dirty(old_dir);

	if (dir_fi) {
		dir_fi->icb.extLocation = cpu_to_lelb(UDF_I(new_dir)->i_location);
		udf_update_tag((char *)dir_fi,
				(sizeof(struct fileIdentDesc) +
				le16_to_cpu(dir_fi->lengthOfImpUse) + 3) & ~3);
		if (old_iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB)
			mark_inode_dirty(old_inode);
		else
			mark_buffer_dirty_inode(dir_bh, old_inode);

		inode_dec_link_count(old_dir);
		if (new_inode)
			inode_dec_link_count(new_inode);
		else {
			inc_nlink(new_dir);
			mark_inode_dirty(new_dir);
		}
	}

	if (ofi) {
		if (ofibh.sbh != ofibh.ebh)
			brelse(ofibh.ebh);
		brelse(ofibh.sbh);
	}

	retval = 0;

end_rename:
	brelse(dir_bh);
	if (nfi) {
		if (nfibh.sbh != nfibh.ebh)
			brelse(nfibh.ebh);
		brelse(nfibh.sbh);
	}

	return retval;
}

static struct dentry *udf_get_parent(struct dentry *child)
{
	struct kernel_lb_addr tloc;
	struct inode *inode = NULL;
	struct qstr dotdot = QSTR_INIT("..", 2);
	struct fileIdentDesc cfi;
	struct udf_fileident_bh fibh;

	if (!udf_find_entry(child->d_inode, &dotdot, &fibh, &cfi))
		return ERR_PTR(-EACCES);

	if (fibh.sbh != fibh.ebh)
		brelse(fibh.ebh);
	brelse(fibh.sbh);

	tloc = lelb_to_cpu(cfi.icb.extLocation);
	inode = udf_iget(child->d_inode->i_sb, &tloc);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	return d_obtain_alias(inode);
}


static struct dentry *udf_nfs_get_inode(struct super_block *sb, u32 block,
					u16 partref, __u32 generation)
{
	struct inode *inode;
	struct kernel_lb_addr loc;

	if (block == 0)
		return ERR_PTR(-ESTALE);

	loc.logicalBlockNum = block;
	loc.partitionReferenceNum = partref;
	inode = udf_iget(sb, &loc);

	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return d_obtain_alias(inode);
}

static struct dentry *udf_fh_to_dentry(struct super_block *sb,
				       struct fid *fid, int fh_len, int fh_type)
{
	if ((fh_len != 3 && fh_len != 5) ||
	    (fh_type != FILEID_UDF_WITH_PARENT &&
	     fh_type != FILEID_UDF_WITHOUT_PARENT))
		return NULL;

	return udf_nfs_get_inode(sb, fid->udf.block, fid->udf.partref,
			fid->udf.generation);
}

static struct dentry *udf_fh_to_parent(struct super_block *sb,
				       struct fid *fid, int fh_len, int fh_type)
{
	if (fh_len != 5 || fh_type != FILEID_UDF_WITH_PARENT)
		return NULL;

	return udf_nfs_get_inode(sb, fid->udf.parent_block,
				 fid->udf.parent_partref,
				 fid->udf.parent_generation);
}
static int udf_encode_fh(struct inode *inode, __u32 *fh, int *lenp,
			 struct inode *parent)
{
	int len = *lenp;
	struct kernel_lb_addr location = UDF_I(inode)->i_location;
	struct fid *fid = (struct fid *)fh;
	int type = FILEID_UDF_WITHOUT_PARENT;

	if (parent && (len < 5)) {
		*lenp = 5;
		return FILEID_INVALID;
	} else if (len < 3) {
		*lenp = 3;
		return FILEID_INVALID;
	}

	*lenp = 3;
	fid->udf.block = location.logicalBlockNum;
	fid->udf.partref = location.partitionReferenceNum;
	fid->udf.parent_partref = 0;
	fid->udf.generation = inode->i_generation;

	if (parent) {
		location = UDF_I(parent)->i_location;
		fid->udf.parent_block = location.logicalBlockNum;
		fid->udf.parent_partref = location.partitionReferenceNum;
		fid->udf.parent_generation = inode->i_generation;
		*lenp = 5;
		type = FILEID_UDF_WITH_PARENT;
	}

	return type;
}

const struct export_operations udf_export_ops = {
	.encode_fh	= udf_encode_fh,
	.fh_to_dentry   = udf_fh_to_dentry,
	.fh_to_parent   = udf_fh_to_parent,
	.get_parent     = udf_get_parent,
};

const struct inode_operations udf_dir_inode_operations = {
	.lookup				= udf_lookup,
	.create				= udf_create,
	.link				= udf_link,
	.unlink				= udf_unlink,
	.symlink			= udf_symlink,
	.mkdir				= udf_mkdir,
	.rmdir				= udf_rmdir,
	.mknod				= udf_mknod,
	.rename				= udf_rename,
	.tmpfile			= udf_tmpfile,
};
const struct inode_operations udf_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/namei.c */
/************************************************************/
/*
 * partition.c
 *
 * PURPOSE
 *      Partition handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *      This file is distributed under the terms of the GNU General Public
 *      License (GPL). Copies of the GPL can be obtained from:
 *              ftp://prep.ai.mit.edu/pub/gnu/GPL
 *      Each contributing author retains all rights to their own work.
 *
 *  (C) 1998-2001 Ben Fennema
 *
 * HISTORY
 *
 * 12/06/98 blf  Created file.
 *
 */

// #include "udfdecl.h"
// #include "udf_sb.h"
// #include "udf_i.h"

// #include <linux/fs.h>
// #include <linux/string.h>
// #include <linux/buffer_head.h>
#include <linux/mutex.h>
#include "../../inc/__fss.h"

uint32_t udf_get_pblock(struct super_block *sb, uint32_t block,
			uint16_t partition, uint32_t offset)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct udf_part_map *map;
	if (partition >= sbi->s_partitions) {
		udf_debug("block=%d, partition=%d, offset=%d: invalid partition\n",
			  block, partition, offset);
		return 0xFFFFFFFF;
	}
	map = &sbi->s_partmaps[partition];
	if (map->s_partition_func)
		return map->s_partition_func(sb, block, partition, offset);
	else
		return map->s_partition_root + block + offset;
}

uint32_t udf_get_pblock_virt15(struct super_block *sb, uint32_t block,
			       uint16_t partition, uint32_t offset)
{
	struct buffer_head *bh = NULL;
	uint32_t newblock;
	uint32_t index;
	uint32_t loc;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct udf_part_map *map;
	struct udf_virtual_data *vdata;
	struct udf_inode_info *iinfo = UDF_I(sbi->s_vat_inode);

	map = &sbi->s_partmaps[partition];
	vdata = &map->s_type_specific.s_virtual;

	if (block > vdata->s_num_entries) {
		udf_debug("Trying to access block beyond end of VAT (%d max %d)\n",
			  block, vdata->s_num_entries);
		return 0xFFFFFFFF;
	}

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
		loc = le32_to_cpu(((__le32 *)(iinfo->i_ext.i_data +
			vdata->s_start_offset))[block]);
		goto translate;
	}
	index = (sb->s_blocksize - vdata->s_start_offset) / sizeof(uint32_t);
	if (block >= index) {
		block -= index;
		newblock = 1 + (block / (sb->s_blocksize / sizeof(uint32_t)));
		index = block % (sb->s_blocksize / sizeof(uint32_t));
	} else {
		newblock = 0;
		index = vdata->s_start_offset / sizeof(uint32_t) + block;
	}

	loc = udf_block_map(sbi->s_vat_inode, newblock);

	bh = sb_bread(sb, loc);
	if (!bh) {
		udf_debug("get_pblock(UDF_VIRTUAL_MAP:%p,%d,%d) VAT: %d[%d]\n",
			  sb, block, partition, loc, index);
		return 0xFFFFFFFF;
	}

	loc = le32_to_cpu(((__le32 *)bh->b_data)[index]);

	brelse(bh);

translate:
	if (iinfo->i_location.partitionReferenceNum == partition) {
		udf_debug("recursive call to udf_get_pblock!\n");
		return 0xFFFFFFFF;
	}

	return udf_get_pblock(sb, loc,
			      iinfo->i_location.partitionReferenceNum,
			      offset);
}

inline uint32_t udf_get_pblock_virt20(struct super_block *sb, uint32_t block,
				      uint16_t partition, uint32_t offset)
{
	return udf_get_pblock_virt15(sb, block, partition, offset);
}

uint32_t udf_get_pblock_spar15(struct super_block *sb, uint32_t block,
			       uint16_t partition, uint32_t offset)
{
	int i;
	struct sparingTable *st = NULL;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct udf_part_map *map;
	uint32_t packet;
	struct udf_sparing_data *sdata;

	map = &sbi->s_partmaps[partition];
	sdata = &map->s_type_specific.s_sparing;
	packet = (block + offset) & ~(sdata->s_packet_len - 1);

	for (i = 0; i < 4; i++) {
		if (sdata->s_spar_map[i] != NULL) {
			st = (struct sparingTable *)
					sdata->s_spar_map[i]->b_data;
			break;
		}
	}

	if (st) {
		for (i = 0; i < le16_to_cpu(st->reallocationTableLen); i++) {
			struct sparingEntry *entry = &st->mapEntry[i];
			u32 origLoc = le32_to_cpu(entry->origLocation);
			if (origLoc >= 0xFFFFFFF0)
				break;
			else if (origLoc == packet)
				return le32_to_cpu(entry->mappedLocation) +
					((block + offset) &
						(sdata->s_packet_len - 1));
			else if (origLoc > packet)
				break;
		}
	}

	return map->s_partition_root + block + offset;
}

int udf_relocate_blocks(struct super_block *sb, long old_block, long *new_block)
{
	struct udf_sparing_data *sdata;
	struct sparingTable *st = NULL;
	struct sparingEntry mapEntry;
	uint32_t packet;
	int i, j, k, l;
	struct udf_sb_info *sbi = UDF_SB(sb);
	u16 reallocationTableLen;
	struct buffer_head *bh;
	int ret = 0;

	mutex_lock(&sbi->s_alloc_mutex);
	for (i = 0; i < sbi->s_partitions; i++) {
		struct udf_part_map *map = &sbi->s_partmaps[i];
		if (old_block > map->s_partition_root &&
		    old_block < map->s_partition_root + map->s_partition_len) {
			sdata = &map->s_type_specific.s_sparing;
			packet = (old_block - map->s_partition_root) &
						~(sdata->s_packet_len - 1);

			for (j = 0; j < 4; j++)
				if (sdata->s_spar_map[j] != NULL) {
					st = (struct sparingTable *)
						sdata->s_spar_map[j]->b_data;
					break;
				}

			if (!st) {
				ret = 1;
				goto out;
			}

			reallocationTableLen =
					le16_to_cpu(st->reallocationTableLen);
			for (k = 0; k < reallocationTableLen; k++) {
				struct sparingEntry *entry = &st->mapEntry[k];
				u32 origLoc = le32_to_cpu(entry->origLocation);

				if (origLoc == 0xFFFFFFFF) {
					for (; j < 4; j++) {
						int len;
						bh = sdata->s_spar_map[j];
						if (!bh)
							continue;

						st = (struct sparingTable *)
								bh->b_data;
						entry->origLocation =
							cpu_to_le32(packet);
						len =
						  sizeof(struct sparingTable) +
						  reallocationTableLen *
						  sizeof(struct sparingEntry);
						udf_update_tag((char *)st, len);
						mark_buffer_dirty(bh);
					}
					*new_block = le32_to_cpu(
							entry->mappedLocation) +
						     ((old_block -
							map->s_partition_root) &
						     (sdata->s_packet_len - 1));
					ret = 0;
					goto out;
				} else if (origLoc == packet) {
					*new_block = le32_to_cpu(
							entry->mappedLocation) +
						     ((old_block -
							map->s_partition_root) &
						     (sdata->s_packet_len - 1));
					ret = 0;
					goto out;
				} else if (origLoc > packet)
					break;
			}

			for (l = k; l < reallocationTableLen; l++) {
				struct sparingEntry *entry = &st->mapEntry[l];
				u32 origLoc = le32_to_cpu(entry->origLocation);

				if (origLoc != 0xFFFFFFFF)
					continue;

				for (; j < 4; j++) {
					bh = sdata->s_spar_map[j];
					if (!bh)
						continue;

					st = (struct sparingTable *)bh->b_data;
					mapEntry = st->mapEntry[l];
					mapEntry.origLocation =
							cpu_to_le32(packet);
					memmove(&st->mapEntry[k + 1],
						&st->mapEntry[k],
						(l - k) *
						sizeof(struct sparingEntry));
					st->mapEntry[k] = mapEntry;
					udf_update_tag((char *)st,
						sizeof(struct sparingTable) +
						reallocationTableLen *
						sizeof(struct sparingEntry));
					mark_buffer_dirty(bh);
				}
				*new_block =
					le32_to_cpu(
					      st->mapEntry[k].mappedLocation) +
					((old_block - map->s_partition_root) &
					 (sdata->s_packet_len - 1));
				ret = 0;
				goto out;
			}

			ret = 1;
			goto out;
		} /* if old_block */
	}

	if (i == sbi->s_partitions) {
		/* outside of partitions */
		/* for now, fail =) */
		ret = 1;
	}

out:
	mutex_unlock(&sbi->s_alloc_mutex);
	return ret;
}

static uint32_t udf_try_read_meta(struct inode *inode, uint32_t block,
					uint16_t partition, uint32_t offset)
{
	struct super_block *sb = inode->i_sb;
	struct udf_part_map *map;
	struct kernel_lb_addr eloc;
	uint32_t elen;
	sector_t ext_offset;
	struct extent_position epos = {};
	uint32_t phyblock;

	if (inode_bmap(inode, block, &epos, &eloc, &elen, &ext_offset) !=
						(EXT_RECORDED_ALLOCATED >> 30))
		phyblock = 0xFFFFFFFF;
	else {
		map = &UDF_SB(sb)->s_partmaps[partition];
		/* map to sparable/physical partition desc */
		phyblock = udf_get_pblock(sb, eloc.logicalBlockNum,
			map->s_partition_num, ext_offset + offset);
	}

	brelse(epos.bh);
	return phyblock;
}

uint32_t udf_get_pblock_meta25(struct super_block *sb, uint32_t block,
				uint16_t partition, uint32_t offset)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct udf_part_map *map;
	struct udf_meta_data *mdata;
	uint32_t retblk;
	struct inode *inode;

	udf_debug("READING from METADATA\n");

	map = &sbi->s_partmaps[partition];
	mdata = &map->s_type_specific.s_metadata;
	inode = mdata->s_metadata_fe ? : mdata->s_mirror_fe;

	/* We shouldn't mount such media... */
	BUG_ON(!inode);
	retblk = udf_try_read_meta(inode, block, partition, offset);
	if (retblk == 0xFFFFFFFF && mdata->s_metadata_fe) {
		udf_warn(sb, "error reading from METADATA, trying to read from MIRROR\n");
		if (!(mdata->s_flags & MF_MIRROR_FE_LOADED)) {
			mdata->s_mirror_fe = udf_find_metadata_inode_efe(sb,
				mdata->s_mirror_file_loc, map->s_partition_num);
			mdata->s_flags |= MF_MIRROR_FE_LOADED;
		}

		inode = mdata->s_mirror_fe;
		if (!inode)
			return 0xFFFFFFFF;
		retblk = udf_try_read_meta(inode, block, partition, offset);
	}

	return retblk;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/partition.c */
/************************************************************/
/*
 * super.c
 *
 * PURPOSE
 *  Super block routines for the OSTA-UDF(tm) filesystem.
 *
 * DESCRIPTION
 *  OSTA-UDF(tm) = Optical Storage Technology Association
 *  Universal Disk Format.
 *
 *  This code is based on version 2.00 of the UDF specification,
 *  and revision 3 of the ECMA 167 standard [equivalent to ISO 13346].
 *    http://www.osta.org/
 *    http://www.ecma.ch/
 *    http://www.iso.org/
 *
 * COPYRIGHT
 *  This file is distributed under the terms of the GNU General Public
 *  License (GPL). Copies of the GPL can be obtained from:
 *    ftp://prep.ai.mit.edu/pub/gnu/GPL
 *  Each contributing author retains all rights to their own work.
 *
 *  (C) 1998 Dave Boynton
 *  (C) 1998-2004 Ben Fennema
 *  (C) 2000 Stelias Computing Inc
 *
 * HISTORY
 *
 *  09/24/98 dgb  changed to allow compiling outside of kernel, and
 *                added some debugging.
 *  10/01/98 dgb  updated to allow (some) possibility of compiling w/2.0.34
 *  10/16/98      attempting some multi-session support
 *  10/17/98      added freespace count for "df"
 *  11/11/98 gr   added novrs option
 *  11/26/98 dgb  added fileset,anchor mount options
 *  12/06/98 blf  really hosed things royally. vat/sparing support. sequenced
 *                vol descs. rewrote option handling based on isofs
 *  12/20/98      find the free space bitmap (if it exists)
 */

// #include "udfdecl.h"

// #include <linux/blkdev.h>
// #include <linux/slab.h>
// #include <linux/kernel.h>
// #include <linux/module.h>
#include <linux/parser.h>
#include <linux/stat.h>
// #include <linux/cdrom.h>
#include <linux/nls.h>
// #include <linux/buffer_head.h>
#include <linux/vfs.h>
#include <linux/vmalloc.h>
// #include <linux/errno.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/bitmap.h>
// #include <linux/crc-itu-t.h>
#include <linux/log2.h>
#include <asm/byteorder.h>
#include "../../inc/__fss.h"

// #include "udf_sb.h"
// #include "udf_i.h"

#include <linux/init.h>
// #include <linux/uaccess.h>
#include "../../inc/__fss.h"

#define VDS_POS_PRIMARY_VOL_DESC	0
#define VDS_POS_UNALLOC_SPACE_DESC	1
#define VDS_POS_LOGICAL_VOL_DESC	2
#define VDS_POS_PARTITION_DESC		3
#define VDS_POS_IMP_USE_VOL_DESC	4
#define VDS_POS_VOL_DESC_PTR		5
#define VDS_POS_TERMINATING_DESC	6
#define VDS_POS_LENGTH			7

#define UDF_DEFAULT_BLOCKSIZE 2048

#define VSD_FIRST_SECTOR_OFFSET		32768
#define VSD_MAX_SECTOR_OFFSET		0x800000

enum { UDF_MAX_LINKS = 0xffff };

/* These are the "meat" - everything else is stuffing */
static int udf_fill_super(struct super_block *, void *, int);
static void udf_put_super(struct super_block *);
static int udf_sync_fs(struct super_block *, int);
static int udf_remount_fs(struct super_block *, int *, char *);
static void udf_load_logicalvolint(struct super_block *, struct kernel_extent_ad);
static int udf_find_fileset(struct super_block *, struct kernel_lb_addr *,
			    struct kernel_lb_addr *);
static void udf_load_fileset(struct super_block *, struct buffer_head *,
			     struct kernel_lb_addr *);
static void udf_open_lvid(struct super_block *);
static void udf_close_lvid(struct super_block *);
static unsigned int udf_count_free(struct super_block *);
static int udf_statfs(struct dentry *, struct kstatfs *);
static int udf_show_options(struct seq_file *, struct dentry *);

struct logicalVolIntegrityDescImpUse *udf_sb_lvidiu(struct super_block *sb)
{
	struct logicalVolIntegrityDesc *lvid;
	unsigned int partnum;
	unsigned int offset;

	if (!UDF_SB(sb)->s_lvid_bh)
		return NULL;
	lvid = (struct logicalVolIntegrityDesc *)UDF_SB(sb)->s_lvid_bh->b_data;
	partnum = le32_to_cpu(lvid->numOfPartitions);
	if ((sb->s_blocksize - sizeof(struct logicalVolIntegrityDescImpUse) -
	     offsetof(struct logicalVolIntegrityDesc, impUse)) /
	     (2 * sizeof(uint32_t)) < partnum) {
		udf_err(sb, "Logical volume integrity descriptor corrupted "
			"(numOfPartitions = %u)!\n", partnum);
		return NULL;
	}
	/* The offset is to skip freeSpaceTable and sizeTable arrays */
	offset = partnum * 2 * sizeof(uint32_t);
	return (struct logicalVolIntegrityDescImpUse *)&(lvid->impUse[offset]);
}

/* UDF filesystem type */
static struct dentry *udf_mount(struct file_system_type *fs_type,
		      int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, udf_fill_super);
}

static struct file_system_type udf_fstype = {
	.owner		= THIS_MODULE,
	.name		= "udf",
	.mount		= udf_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("udf");

static struct kmem_cache *udf_inode_cachep;

static struct inode *udf_alloc_inode(struct super_block *sb)
{
	struct udf_inode_info *ei;
	ei = kmem_cache_alloc(udf_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;

	ei->i_unique = 0;
	ei->i_lenExtents = 0;
	ei->i_next_alloc_block = 0;
	ei->i_next_alloc_goal = 0;
	ei->i_strat4096 = 0;
	init_rwsem(&ei->i_data_sem);
	ei->cached_extent.lstart = -1;
	spin_lock_init(&ei->i_extent_cache_lock);

	return &ei->vfs_inode;
}

static void udf_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(udf_inode_cachep, UDF_I(inode));
}

static void udf_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, udf_i_callback);
}

static void init_once(void *foo)
{
	struct udf_inode_info *ei = (struct udf_inode_info *)foo;

	ei->i_ext.i_data = NULL;
	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	udf_inode_cachep = kmem_cache_create("udf_inode_cache",
					     sizeof(struct udf_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT |
						 SLAB_MEM_SPREAD),
					     init_once);
	if (!udf_inode_cachep)
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
	kmem_cache_destroy(udf_inode_cachep);
}

/* Superblock operations */
static const struct super_operations udf_sb_ops = {
	.alloc_inode	= udf_alloc_inode,
	.destroy_inode	= udf_destroy_inode,
	.write_inode	= udf_write_inode,
	.evict_inode	= udf_evict_inode,
	.put_super	= udf_put_super,
	.sync_fs	= udf_sync_fs,
	.statfs		= udf_statfs,
	.remount_fs	= udf_remount_fs,
	.show_options	= udf_show_options,
};

struct udf_options {
	unsigned char novrs;
	unsigned int blocksize;
	unsigned int session;
	unsigned int lastblock;
	unsigned int anchor;
	unsigned int volume;
	unsigned short partition;
	unsigned int fileset;
	unsigned int rootdir;
	unsigned int flags;
	umode_t umask;
	kgid_t gid;
	kuid_t uid;
	umode_t fmode;
	umode_t dmode;
	struct nls_table *nls_map;
};

static int __init init_udf_fs(void)
{
	int err;

	err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&udf_fstype);
	if (err)
		goto out;

	return 0;

out:
	destroy_inodecache();

out1:
	return err;
}

static void __exit exit_udf_fs(void)
{
	unregister_filesystem(&udf_fstype);
	destroy_inodecache();
}

module_init(init_udf_fs)
module_exit(exit_udf_fs)

static int udf_sb_alloc_partition_maps(struct super_block *sb, u32 count)
{
	struct udf_sb_info *sbi = UDF_SB(sb);

	sbi->s_partmaps = kcalloc(count, sizeof(struct udf_part_map),
				  GFP_KERNEL);
	if (!sbi->s_partmaps) {
		udf_err(sb, "Unable to allocate space for %d partition maps\n",
			count);
		sbi->s_partitions = 0;
		return -ENOMEM;
	}

	sbi->s_partitions = count;
	return 0;
}

static void udf_sb_free_bitmap(struct udf_bitmap *bitmap)
{
	int i;
	int nr_groups = bitmap->s_nr_groups;
	int size = sizeof(struct udf_bitmap) + (sizeof(struct buffer_head *) *
						nr_groups);

	for (i = 0; i < nr_groups; i++)
		if (bitmap->s_block_bitmap[i])
			brelse(bitmap->s_block_bitmap[i]);

	if (size <= PAGE_SIZE)
		kfree(bitmap);
	else
		vfree(bitmap);
}

static void udf_free_partition(struct udf_part_map *map)
{
	int i;
	struct udf_meta_data *mdata;

	if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_TABLE)
		iput(map->s_uspace.s_table);
	if (map->s_partition_flags & UDF_PART_FLAG_FREED_TABLE)
		iput(map->s_fspace.s_table);
	if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_BITMAP)
		udf_sb_free_bitmap(map->s_uspace.s_bitmap);
	if (map->s_partition_flags & UDF_PART_FLAG_FREED_BITMAP)
		udf_sb_free_bitmap(map->s_fspace.s_bitmap);
	if (map->s_partition_type == UDF_SPARABLE_MAP15)
		for (i = 0; i < 4; i++)
			brelse(map->s_type_specific.s_sparing.s_spar_map[i]);
	else if (map->s_partition_type == UDF_METADATA_MAP25) {
		mdata = &map->s_type_specific.s_metadata;
		iput(mdata->s_metadata_fe);
		mdata->s_metadata_fe = NULL;

		iput(mdata->s_mirror_fe);
		mdata->s_mirror_fe = NULL;

		iput(mdata->s_bitmap_fe);
		mdata->s_bitmap_fe = NULL;
	}
}

static void udf_sb_free_partitions(struct super_block *sb)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	int i;
	if (sbi->s_partmaps == NULL)
		return;
	for (i = 0; i < sbi->s_partitions; i++)
		udf_free_partition(&sbi->s_partmaps[i]);
	kfree(sbi->s_partmaps);
	sbi->s_partmaps = NULL;
}

static int udf_show_options(struct seq_file *seq, struct dentry *root)
{
	struct super_block *sb = root->d_sb;
	struct udf_sb_info *sbi = UDF_SB(sb);

	if (!UDF_QUERY_FLAG(sb, UDF_FLAG_STRICT))
		seq_puts(seq, ",nostrict");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_BLOCKSIZE_SET))
		seq_printf(seq, ",bs=%lu", sb->s_blocksize);
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UNHIDE))
		seq_puts(seq, ",unhide");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UNDELETE))
		seq_puts(seq, ",undelete");
	if (!UDF_QUERY_FLAG(sb, UDF_FLAG_USE_AD_IN_ICB))
		seq_puts(seq, ",noadinicb");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_USE_SHORT_AD))
		seq_puts(seq, ",shortad");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UID_FORGET))
		seq_puts(seq, ",uid=forget");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UID_IGNORE))
		seq_puts(seq, ",uid=ignore");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_GID_FORGET))
		seq_puts(seq, ",gid=forget");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_GID_IGNORE))
		seq_puts(seq, ",gid=ignore");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UID_SET))
		seq_printf(seq, ",uid=%u", from_kuid(&init_user_ns, sbi->s_uid));
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_GID_SET))
		seq_printf(seq, ",gid=%u", from_kgid(&init_user_ns, sbi->s_gid));
	if (sbi->s_umask != 0)
		seq_printf(seq, ",umask=%ho", sbi->s_umask);
	if (sbi->s_fmode != UDF_INVALID_MODE)
		seq_printf(seq, ",mode=%ho", sbi->s_fmode);
	if (sbi->s_dmode != UDF_INVALID_MODE)
		seq_printf(seq, ",dmode=%ho", sbi->s_dmode);
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_SESSION_SET))
		seq_printf(seq, ",session=%u", sbi->s_session);
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_LASTBLOCK_SET))
		seq_printf(seq, ",lastblock=%u", sbi->s_last_block);
	if (sbi->s_anchor != 0)
		seq_printf(seq, ",anchor=%u", sbi->s_anchor);
	/*
	 * volume, partition, fileset and rootdir seem to be ignored
	 * currently
	 */
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UTF8))
		seq_puts(seq, ",utf8");
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_NLS_MAP) && sbi->s_nls_map)
		seq_printf(seq, ",iocharset=%s", sbi->s_nls_map->charset);

	return 0;
}

/*
 * udf_parse_options
 *
 * PURPOSE
 *	Parse mount options.
 *
 * DESCRIPTION
 *	The following mount options are supported:
 *
 *	gid=		Set the default group.
 *	umask=		Set the default umask.
 *	mode=		Set the default file permissions.
 *	dmode=		Set the default directory permissions.
 *	uid=		Set the default user.
 *	bs=		Set the block size.
 *	unhide		Show otherwise hidden files.
 *	undelete	Show deleted files in lists.
 *	adinicb		Embed data in the inode (default)
 *	noadinicb	Don't embed data in the inode
 *	shortad		Use short ad's
 *	longad		Use long ad's (default)
 *	nostrict	Unset strict conformance
 *	iocharset=	Set the NLS character set
 *
 *	The remaining are for debugging and disaster recovery:
 *
 *	novrs		Skip volume sequence recognition
 *
 *	The following expect a offset from 0.
 *
 *	session=	Set the CDROM session (default= last session)
 *	anchor=		Override standard anchor location. (default= 256)
 *	volume=		Override the VolumeDesc location. (unused)
 *	partition=	Override the PartitionDesc location. (unused)
 *	lastblock=	Set the last block of the filesystem/
 *
 *	The following expect a offset from the partition root.
 *
 *	fileset=	Override the fileset block location. (unused)
 *	rootdir=	Override the root directory location. (unused)
 *		WARNING: overriding the rootdir to a non-directory may
 *		yield highly unpredictable results.
 *
 * PRE-CONDITIONS
 *	options		Pointer to mount options string.
 *	uopts		Pointer to mount options variable.
 *
 * POST-CONDITIONS
 *	<return>	1	Mount options parsed okay.
 *	<return>	0	Error parsing mount options.
 *
 * HISTORY
 *	July 1, 1997 - Andrew E. Mileski
 *	Written, tested, and released.
 */

enum {
	Opt_novrs, Opt_nostrict, Opt_bs, Opt_unhide, Opt_undelete,
	Opt_noadinicb, Opt_adinicb, Opt_shortad, Opt_longad,
	Opt_gid, Opt_uid, Opt_umask, Opt_session, Opt_lastblock,
	Opt_anchor, Opt_volume, Opt_partition, Opt_fileset,
	Opt_rootdir, Opt_utf8, Opt_iocharset,
	Opt_err, Opt_uforget, Opt_uignore, Opt_gforget, Opt_gignore,
	Opt_fmode, Opt_dmode
};

static const match_table_t tokens = {
	{Opt_novrs,	"novrs"},
	{Opt_nostrict,	"nostrict"},
	{Opt_bs,	"bs=%u"},
	{Opt_unhide,	"unhide"},
	{Opt_undelete,	"undelete"},
	{Opt_noadinicb,	"noadinicb"},
	{Opt_adinicb,	"adinicb"},
	{Opt_shortad,	"shortad"},
	{Opt_longad,	"longad"},
	{Opt_uforget,	"uid=forget"},
	{Opt_uignore,	"uid=ignore"},
	{Opt_gforget,	"gid=forget"},
	{Opt_gignore,	"gid=ignore"},
	{Opt_gid,	"gid=%u"},
	{Opt_uid,	"uid=%u"},
	{Opt_umask,	"umask=%o"},
	{Opt_session,	"session=%u"},
	{Opt_lastblock,	"lastblock=%u"},
	{Opt_anchor,	"anchor=%u"},
	{Opt_volume,	"volume=%u"},
	{Opt_partition,	"partition=%u"},
	{Opt_fileset,	"fileset=%u"},
	{Opt_rootdir,	"rootdir=%u"},
	{Opt_utf8,	"utf8"},
	{Opt_iocharset,	"iocharset=%s"},
	{Opt_fmode,     "mode=%o"},
	{Opt_dmode,     "dmode=%o"},
	{Opt_err,	NULL}
};

static int udf_parse_options(char *options, struct udf_options *uopt,
			     bool remount)
{
	char *p;
	int option;

	uopt->novrs = 0;
	uopt->partition = 0xFFFF;
	uopt->session = 0xFFFFFFFF;
	uopt->lastblock = 0;
	uopt->anchor = 0;
	uopt->volume = 0xFFFFFFFF;
	uopt->rootdir = 0xFFFFFFFF;
	uopt->fileset = 0xFFFFFFFF;
	uopt->nls_map = NULL;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		unsigned n;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_novrs:
			uopt->novrs = 1;
			break;
		case Opt_bs:
			if (match_int(&args[0], &option))
				return 0;
			n = option;
			if (n != 512 && n != 1024 && n != 2048 && n != 4096)
				return 0;
			uopt->blocksize = n;
			uopt->flags |= (1 << UDF_FLAG_BLOCKSIZE_SET);
			break;
		case Opt_unhide:
			uopt->flags |= (1 << UDF_FLAG_UNHIDE);
			break;
		case Opt_undelete:
			uopt->flags |= (1 << UDF_FLAG_UNDELETE);
			break;
		case Opt_noadinicb:
			uopt->flags &= ~(1 << UDF_FLAG_USE_AD_IN_ICB);
			break;
		case Opt_adinicb:
			uopt->flags |= (1 << UDF_FLAG_USE_AD_IN_ICB);
			break;
		case Opt_shortad:
			uopt->flags |= (1 << UDF_FLAG_USE_SHORT_AD);
			break;
		case Opt_longad:
			uopt->flags &= ~(1 << UDF_FLAG_USE_SHORT_AD);
			break;
		case Opt_gid:
			if (match_int(args, &option))
				return 0;
			uopt->gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(uopt->gid))
				return 0;
			uopt->flags |= (1 << UDF_FLAG_GID_SET);
			break;
		case Opt_uid:
			if (match_int(args, &option))
				return 0;
			uopt->uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(uopt->uid))
				return 0;
			uopt->flags |= (1 << UDF_FLAG_UID_SET);
			break;
		case Opt_umask:
			if (match_octal(args, &option))
				return 0;
			uopt->umask = option;
			break;
		case Opt_nostrict:
			uopt->flags &= ~(1 << UDF_FLAG_STRICT);
			break;
		case Opt_session:
			if (match_int(args, &option))
				return 0;
			uopt->session = option;
			if (!remount)
				uopt->flags |= (1 << UDF_FLAG_SESSION_SET);
			break;
		case Opt_lastblock:
			if (match_int(args, &option))
				return 0;
			uopt->lastblock = option;
			if (!remount)
				uopt->flags |= (1 << UDF_FLAG_LASTBLOCK_SET);
			break;
		case Opt_anchor:
			if (match_int(args, &option))
				return 0;
			uopt->anchor = option;
			break;
		case Opt_volume:
			if (match_int(args, &option))
				return 0;
			uopt->volume = option;
			break;
		case Opt_partition:
			if (match_int(args, &option))
				return 0;
			uopt->partition = option;
			break;
		case Opt_fileset:
			if (match_int(args, &option))
				return 0;
			uopt->fileset = option;
			break;
		case Opt_rootdir:
			if (match_int(args, &option))
				return 0;
			uopt->rootdir = option;
			break;
		case Opt_utf8:
			uopt->flags |= (1 << UDF_FLAG_UTF8);
			break;
#ifdef CONFIG_UDF_NLS
		case Opt_iocharset:
			uopt->nls_map = load_nls(args[0].from);
			uopt->flags |= (1 << UDF_FLAG_NLS_MAP);
			break;
#endif
		case Opt_uignore:
			uopt->flags |= (1 << UDF_FLAG_UID_IGNORE);
			break;
		case Opt_uforget:
			uopt->flags |= (1 << UDF_FLAG_UID_FORGET);
			break;
		case Opt_gignore:
			uopt->flags |= (1 << UDF_FLAG_GID_IGNORE);
			break;
		case Opt_gforget:
			uopt->flags |= (1 << UDF_FLAG_GID_FORGET);
			break;
		case Opt_fmode:
			if (match_octal(args, &option))
				return 0;
			uopt->fmode = option & 0777;
			break;
		case Opt_dmode:
			if (match_octal(args, &option))
				return 0;
			uopt->dmode = option & 0777;
			break;
		default:
			pr_err("bad mount option \"%s\" or missing value\n", p);
			return 0;
		}
	}
	return 1;
}

static int udf_remount_fs(struct super_block *sb, int *flags, char *options)
{
	struct udf_options uopt;
	struct udf_sb_info *sbi = UDF_SB(sb);
	int error = 0;
	struct logicalVolIntegrityDescImpUse *lvidiu = udf_sb_lvidiu(sb);

	sync_filesystem(sb);
	if (lvidiu) {
		int write_rev = le16_to_cpu(lvidiu->minUDFWriteRev);
		if (write_rev > UDF_MAX_WRITE_VERSION && !(*flags & MS_RDONLY))
			return -EACCES;
	}

	uopt.flags = sbi->s_flags;
	uopt.uid   = sbi->s_uid;
	uopt.gid   = sbi->s_gid;
	uopt.umask = sbi->s_umask;
	uopt.fmode = sbi->s_fmode;
	uopt.dmode = sbi->s_dmode;

	if (!udf_parse_options(options, &uopt, true))
		return -EINVAL;

	write_lock(&sbi->s_cred_lock);
	sbi->s_flags = uopt.flags;
	sbi->s_uid   = uopt.uid;
	sbi->s_gid   = uopt.gid;
	sbi->s_umask = uopt.umask;
	sbi->s_fmode = uopt.fmode;
	sbi->s_dmode = uopt.dmode;
	write_unlock(&sbi->s_cred_lock);

	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		goto out_unlock;

	if (*flags & MS_RDONLY)
		udf_close_lvid(sb);
	else
		udf_open_lvid(sb);

out_unlock:
	return error;
}

/* Check Volume Structure Descriptors (ECMA 167 2/9.1) */
/* We also check any "CD-ROM Volume Descriptor Set" (ECMA 167 2/8.3.1) */
static loff_t udf_check_vsd(struct super_block *sb)
{
	struct volStructDesc *vsd = NULL;
	loff_t sector = VSD_FIRST_SECTOR_OFFSET;
	int sectorsize;
	struct buffer_head *bh = NULL;
	int nsr02 = 0;
	int nsr03 = 0;
	struct udf_sb_info *sbi;

	sbi = UDF_SB(sb);
	if (sb->s_blocksize < sizeof(struct volStructDesc))
		sectorsize = sizeof(struct volStructDesc);
	else
		sectorsize = sb->s_blocksize;

	sector += (sbi->s_session << sb->s_blocksize_bits);

	udf_debug("Starting at sector %u (%ld byte sectors)\n",
		  (unsigned int)(sector >> sb->s_blocksize_bits),
		  sb->s_blocksize);
	/* Process the sequence (if applicable). The hard limit on the sector
	 * offset is arbitrary, hopefully large enough so that all valid UDF
	 * filesystems will be recognised. There is no mention of an upper
	 * bound to the size of the volume recognition area in the standard.
	 *  The limit will prevent the code to read all the sectors of a
	 * specially crafted image (like a bluray disc full of CD001 sectors),
	 * potentially causing minutes or even hours of uninterruptible I/O
	 * activity. This actually happened with uninitialised SSD partitions
	 * (all 0xFF) before the check for the limit and all valid IDs were
	 * added */
	for (; !nsr02 && !nsr03 && sector < VSD_MAX_SECTOR_OFFSET;
	     sector += sectorsize) {
		/* Read a block */
		bh = udf_tread(sb, sector >> sb->s_blocksize_bits);
		if (!bh)
			break;

		/* Look for ISO  descriptors */
		vsd = (struct volStructDesc *)(bh->b_data +
					      (sector & (sb->s_blocksize - 1)));

		if (!strncmp(vsd->stdIdent, VSD_STD_ID_CD001,
				    VSD_STD_ID_LEN)) {
			switch (vsd->structType) {
			case 0:
				udf_debug("ISO9660 Boot Record found\n");
				break;
			case 1:
				udf_debug("ISO9660 Primary Volume Descriptor found\n");
				break;
			case 2:
				udf_debug("ISO9660 Supplementary Volume Descriptor found\n");
				break;
			case 3:
				udf_debug("ISO9660 Volume Partition Descriptor found\n");
				break;
			case 255:
				udf_debug("ISO9660 Volume Descriptor Set Terminator found\n");
				break;
			default:
				udf_debug("ISO9660 VRS (%u) found\n",
					  vsd->structType);
				break;
			}
		} else if (!strncmp(vsd->stdIdent, VSD_STD_ID_BEA01,
				    VSD_STD_ID_LEN))
			; /* nothing */
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_TEA01,
				    VSD_STD_ID_LEN)) {
			brelse(bh);
			break;
		} else if (!strncmp(vsd->stdIdent, VSD_STD_ID_NSR02,
				    VSD_STD_ID_LEN))
			nsr02 = sector;
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_NSR03,
				    VSD_STD_ID_LEN))
			nsr03 = sector;
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_BOOT2,
				    VSD_STD_ID_LEN))
			; /* nothing */
		else if (!strncmp(vsd->stdIdent, VSD_STD_ID_CDW02,
				    VSD_STD_ID_LEN))
			; /* nothing */
		else {
			/* invalid id : end of volume recognition area */
			brelse(bh);
			break;
		}
		brelse(bh);
	}

	if (nsr03)
		return nsr03;
	else if (nsr02)
		return nsr02;
	else if (!bh && sector - (sbi->s_session << sb->s_blocksize_bits) ==
			VSD_FIRST_SECTOR_OFFSET)
		return -1;
	else
		return 0;
}

static int udf_find_fileset(struct super_block *sb,
			    struct kernel_lb_addr *fileset,
			    struct kernel_lb_addr *root)
{
	struct buffer_head *bh = NULL;
	long lastblock;
	uint16_t ident;
	struct udf_sb_info *sbi;

	if (fileset->logicalBlockNum != 0xFFFFFFFF ||
	    fileset->partitionReferenceNum != 0xFFFF) {
		bh = udf_read_ptagged(sb, fileset, 0, &ident);

		if (!bh) {
			return 1;
		} else if (ident != TAG_IDENT_FSD) {
			brelse(bh);
			return 1;
		}

	}

	sbi = UDF_SB(sb);
	if (!bh) {
		/* Search backwards through the partitions */
		struct kernel_lb_addr newfileset;

/* --> cvg: FIXME - is it reasonable? */
		return 1;

		for (newfileset.partitionReferenceNum = sbi->s_partitions - 1;
		     (newfileset.partitionReferenceNum != 0xFFFF &&
		      fileset->logicalBlockNum == 0xFFFFFFFF &&
		      fileset->partitionReferenceNum == 0xFFFF);
		     newfileset.partitionReferenceNum--) {
			lastblock = sbi->s_partmaps
					[newfileset.partitionReferenceNum]
						.s_partition_len;
			newfileset.logicalBlockNum = 0;

			do {
				bh = udf_read_ptagged(sb, &newfileset, 0,
						      &ident);
				if (!bh) {
					newfileset.logicalBlockNum++;
					continue;
				}

				switch (ident) {
				case TAG_IDENT_SBD:
				{
					struct spaceBitmapDesc *sp;
					sp = (struct spaceBitmapDesc *)
								bh->b_data;
					newfileset.logicalBlockNum += 1 +
						((le32_to_cpu(sp->numOfBytes) +
						  sizeof(struct spaceBitmapDesc)
						  - 1) >> sb->s_blocksize_bits);
					brelse(bh);
					break;
				}
				case TAG_IDENT_FSD:
					*fileset = newfileset;
					break;
				default:
					newfileset.logicalBlockNum++;
					brelse(bh);
					bh = NULL;
					break;
				}
			} while (newfileset.logicalBlockNum < lastblock &&
				 fileset->logicalBlockNum == 0xFFFFFFFF &&
				 fileset->partitionReferenceNum == 0xFFFF);
		}
	}

	if ((fileset->logicalBlockNum != 0xFFFFFFFF ||
	     fileset->partitionReferenceNum != 0xFFFF) && bh) {
		udf_debug("Fileset at block=%d, partition=%d\n",
			  fileset->logicalBlockNum,
			  fileset->partitionReferenceNum);

		sbi->s_partition = fileset->partitionReferenceNum;
		udf_load_fileset(sb, bh, root);
		brelse(bh);
		return 0;
	}
	return 1;
}

/*
 * Load primary Volume Descriptor Sequence
 *
 * Return <0 on error, 0 on success. -EAGAIN is special meaning next sequence
 * should be tried.
 */
static int udf_load_pvoldesc(struct super_block *sb, sector_t block)
{
	struct primaryVolDesc *pvoldesc;
	struct ustr *instr, *outstr;
	struct buffer_head *bh;
	uint16_t ident;
	int ret = -ENOMEM;

	instr = kmalloc(sizeof(struct ustr), GFP_NOFS);
	if (!instr)
		return -ENOMEM;

	outstr = kmalloc(sizeof(struct ustr), GFP_NOFS);
	if (!outstr)
		goto out1;

	bh = udf_read_tagged(sb, block, block, &ident);
	if (!bh) {
		ret = -EAGAIN;
		goto out2;
	}

	if (ident != TAG_IDENT_PVD) {
		ret = -EIO;
		goto out_bh;
	}

	pvoldesc = (struct primaryVolDesc *)bh->b_data;

	if (udf_disk_stamp_to_time(&UDF_SB(sb)->s_record_time,
			      pvoldesc->recordingDateAndTime)) {
#ifdef UDFFS_DEBUG
		struct timestamp *ts = &pvoldesc->recordingDateAndTime;
		udf_debug("recording time %04u/%02u/%02u %02u:%02u (%x)\n",
			  le16_to_cpu(ts->year), ts->month, ts->day, ts->hour,
			  ts->minute, le16_to_cpu(ts->typeAndTimezone));
#endif
	}

	if (!udf_build_ustr(instr, pvoldesc->volIdent, 32))
		if (udf_CS0toUTF8(outstr, instr)) {
			strncpy(UDF_SB(sb)->s_volume_ident, outstr->u_name,
				outstr->u_len > 31 ? 31 : outstr->u_len);
			udf_debug("volIdent[] = '%s'\n",
				  UDF_SB(sb)->s_volume_ident);
		}

	if (!udf_build_ustr(instr, pvoldesc->volSetIdent, 128))
		if (udf_CS0toUTF8(outstr, instr))
			udf_debug("volSetIdent[] = '%s'\n", outstr->u_name);

	ret = 0;
out_bh:
	brelse(bh);
out2:
	kfree(outstr);
out1:
	kfree(instr);
	return ret;
}

struct inode *udf_find_metadata_inode_efe(struct super_block *sb,
					u32 meta_file_loc, u32 partition_num)
{
	struct kernel_lb_addr addr;
	struct inode *metadata_fe;

	addr.logicalBlockNum = meta_file_loc;
	addr.partitionReferenceNum = partition_num;

	metadata_fe = udf_iget_special(sb, &addr);

	if (IS_ERR(metadata_fe)) {
		udf_warn(sb, "metadata inode efe not found\n");
		return metadata_fe;
	}
	if (UDF_I(metadata_fe)->i_alloc_type != ICBTAG_FLAG_AD_SHORT) {
		udf_warn(sb, "metadata inode efe does not have short allocation descriptors!\n");
		iput(metadata_fe);
		return ERR_PTR(-EIO);
	}

	return metadata_fe;
}

static int udf_load_metadata_files(struct super_block *sb, int partition)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct udf_part_map *map;
	struct udf_meta_data *mdata;
	struct kernel_lb_addr addr;
	struct inode *fe;

	map = &sbi->s_partmaps[partition];
	mdata = &map->s_type_specific.s_metadata;

	/* metadata address */
	udf_debug("Metadata file location: block = %d part = %d\n",
		  mdata->s_meta_file_loc, map->s_partition_num);

	fe = udf_find_metadata_inode_efe(sb, mdata->s_meta_file_loc,
					 map->s_partition_num);
	if (IS_ERR(fe)) {
		/* mirror file entry */
		udf_debug("Mirror metadata file location: block = %d part = %d\n",
			  mdata->s_mirror_file_loc, map->s_partition_num);

		fe = udf_find_metadata_inode_efe(sb, mdata->s_mirror_file_loc,
						 map->s_partition_num);

		if (IS_ERR(fe)) {
			udf_err(sb, "Both metadata and mirror metadata inode efe can not found\n");
			return PTR_ERR(fe);
		}
		mdata->s_mirror_fe = fe;
	} else
		mdata->s_metadata_fe = fe;


	/*
	 * bitmap file entry
	 * Note:
	 * Load only if bitmap file location differs from 0xFFFFFFFF (DCN-5102)
	*/
	if (mdata->s_bitmap_file_loc != 0xFFFFFFFF) {
		addr.logicalBlockNum = mdata->s_bitmap_file_loc;
		addr.partitionReferenceNum = map->s_partition_num;

		udf_debug("Bitmap file location: block = %d part = %d\n",
			  addr.logicalBlockNum, addr.partitionReferenceNum);

		fe = udf_iget_special(sb, &addr);
		if (IS_ERR(fe)) {
			if (sb->s_flags & MS_RDONLY)
				udf_warn(sb, "bitmap inode efe not found but it's ok since the disc is mounted read-only\n");
			else {
				udf_err(sb, "bitmap inode efe not found and attempted read-write mount\n");
				return PTR_ERR(fe);
			}
		} else
			mdata->s_bitmap_fe = fe;
	}

	udf_debug("udf_load_metadata_files Ok\n");
	return 0;
}

static void udf_load_fileset(struct super_block *sb, struct buffer_head *bh,
			     struct kernel_lb_addr *root)
{
	struct fileSetDesc *fset;

	fset = (struct fileSetDesc *)bh->b_data;

	*root = lelb_to_cpu(fset->rootDirectoryICB.extLocation);

	UDF_SB(sb)->s_serial_number = le16_to_cpu(fset->descTag.tagSerialNum);

	udf_debug("Rootdir at block=%d, partition=%d\n",
		  root->logicalBlockNum, root->partitionReferenceNum);
}

int udf_compute_nr_groups(struct super_block *sb, u32 partition)
{
	struct udf_part_map *map = &UDF_SB(sb)->s_partmaps[partition];
	return DIV_ROUND_UP(map->s_partition_len +
			    (sizeof(struct spaceBitmapDesc) << 3),
			    sb->s_blocksize * 8);
}

static struct udf_bitmap *udf_sb_alloc_bitmap(struct super_block *sb, u32 index)
{
	struct udf_bitmap *bitmap;
	int nr_groups;
	int size;

	nr_groups = udf_compute_nr_groups(sb, index);
	size = sizeof(struct udf_bitmap) +
		(sizeof(struct buffer_head *) * nr_groups);

	if (size <= PAGE_SIZE)
		bitmap = kzalloc(size, GFP_KERNEL);
	else
		bitmap = vzalloc(size); /* TODO: get rid of vzalloc */

	if (bitmap == NULL)
		return NULL;

	bitmap->s_nr_groups = nr_groups;
	return bitmap;
}

static int udf_fill_partdesc_info(struct super_block *sb,
		struct partitionDesc *p, int p_index)
{
	struct udf_part_map *map;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct partitionHeaderDesc *phd;

	map = &sbi->s_partmaps[p_index];

	map->s_partition_len = le32_to_cpu(p->partitionLength); /* blocks */
	map->s_partition_root = le32_to_cpu(p->partitionStartingLocation);

	if (p->accessType == cpu_to_le32(PD_ACCESS_TYPE_READ_ONLY))
		map->s_partition_flags |= UDF_PART_FLAG_READ_ONLY;
	if (p->accessType == cpu_to_le32(PD_ACCESS_TYPE_WRITE_ONCE))
		map->s_partition_flags |= UDF_PART_FLAG_WRITE_ONCE;
	if (p->accessType == cpu_to_le32(PD_ACCESS_TYPE_REWRITABLE))
		map->s_partition_flags |= UDF_PART_FLAG_REWRITABLE;
	if (p->accessType == cpu_to_le32(PD_ACCESS_TYPE_OVERWRITABLE))
		map->s_partition_flags |= UDF_PART_FLAG_OVERWRITABLE;

	udf_debug("Partition (%d type %x) starts at physical %d, block length %d\n",
		  p_index, map->s_partition_type,
		  map->s_partition_root, map->s_partition_len);

	if (strcmp(p->partitionContents.ident, PD_PARTITION_CONTENTS_NSR02) &&
	    strcmp(p->partitionContents.ident, PD_PARTITION_CONTENTS_NSR03))
		return 0;

	phd = (struct partitionHeaderDesc *)p->partitionContentsUse;
	if (phd->unallocSpaceTable.extLength) {
		struct kernel_lb_addr loc = {
			.logicalBlockNum = le32_to_cpu(
				phd->unallocSpaceTable.extPosition),
			.partitionReferenceNum = p_index,
		};
		struct inode *inode;

		inode = udf_iget_special(sb, &loc);
		if (IS_ERR(inode)) {
			udf_debug("cannot load unallocSpaceTable (part %d)\n",
				  p_index);
			return PTR_ERR(inode);
		}
		map->s_uspace.s_table = inode;
		map->s_partition_flags |= UDF_PART_FLAG_UNALLOC_TABLE;
		udf_debug("unallocSpaceTable (part %d) @ %ld\n",
			  p_index, map->s_uspace.s_table->i_ino);
	}

	if (phd->unallocSpaceBitmap.extLength) {
		struct udf_bitmap *bitmap = udf_sb_alloc_bitmap(sb, p_index);
		if (!bitmap)
			return -ENOMEM;
		map->s_uspace.s_bitmap = bitmap;
		bitmap->s_extPosition = le32_to_cpu(
				phd->unallocSpaceBitmap.extPosition);
		map->s_partition_flags |= UDF_PART_FLAG_UNALLOC_BITMAP;
		udf_debug("unallocSpaceBitmap (part %d) @ %d\n",
			  p_index, bitmap->s_extPosition);
	}

	if (phd->partitionIntegrityTable.extLength)
		udf_debug("partitionIntegrityTable (part %d)\n", p_index);

	if (phd->freedSpaceTable.extLength) {
		struct kernel_lb_addr loc = {
			.logicalBlockNum = le32_to_cpu(
				phd->freedSpaceTable.extPosition),
			.partitionReferenceNum = p_index,
		};
		struct inode *inode;

		inode = udf_iget_special(sb, &loc);
		if (IS_ERR(inode)) {
			udf_debug("cannot load freedSpaceTable (part %d)\n",
				  p_index);
			return PTR_ERR(inode);
		}
		map->s_fspace.s_table = inode;
		map->s_partition_flags |= UDF_PART_FLAG_FREED_TABLE;
		udf_debug("freedSpaceTable (part %d) @ %ld\n",
			  p_index, map->s_fspace.s_table->i_ino);
	}

	if (phd->freedSpaceBitmap.extLength) {
		struct udf_bitmap *bitmap = udf_sb_alloc_bitmap(sb, p_index);
		if (!bitmap)
			return -ENOMEM;
		map->s_fspace.s_bitmap = bitmap;
		bitmap->s_extPosition = le32_to_cpu(
				phd->freedSpaceBitmap.extPosition);
		map->s_partition_flags |= UDF_PART_FLAG_FREED_BITMAP;
		udf_debug("freedSpaceBitmap (part %d) @ %d\n",
			  p_index, bitmap->s_extPosition);
	}
	return 0;
}

static void udf_find_vat_block(struct super_block *sb, int p_index,
			       int type1_index, sector_t start_block)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct udf_part_map *map = &sbi->s_partmaps[p_index];
	sector_t vat_block;
	struct kernel_lb_addr ino;
	struct inode *inode;

	/*
	 * VAT file entry is in the last recorded block. Some broken disks have
	 * it a few blocks before so try a bit harder...
	 */
	ino.partitionReferenceNum = type1_index;
	for (vat_block = start_block;
	     vat_block >= map->s_partition_root &&
	     vat_block >= start_block - 3; vat_block--) {
		ino.logicalBlockNum = vat_block - map->s_partition_root;
		inode = udf_iget_special(sb, &ino);
		if (!IS_ERR(inode)) {
			sbi->s_vat_inode = inode;
			break;
		}
	}
}

static int udf_load_vat(struct super_block *sb, int p_index, int type1_index)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct udf_part_map *map = &sbi->s_partmaps[p_index];
	struct buffer_head *bh = NULL;
	struct udf_inode_info *vati;
	uint32_t pos;
	struct virtualAllocationTable20 *vat20;
	sector_t blocks = sb->s_bdev->bd_inode->i_size >> sb->s_blocksize_bits;

	udf_find_vat_block(sb, p_index, type1_index, sbi->s_last_block);
	if (!sbi->s_vat_inode &&
	    sbi->s_last_block != blocks - 1) {
		pr_notice("Failed to read VAT inode from the last recorded block (%lu), retrying with the last block of the device (%lu).\n",
			  (unsigned long)sbi->s_last_block,
			  (unsigned long)blocks - 1);
		udf_find_vat_block(sb, p_index, type1_index, blocks - 1);
	}
	if (!sbi->s_vat_inode)
		return -EIO;

	if (map->s_partition_type == UDF_VIRTUAL_MAP15) {
		map->s_type_specific.s_virtual.s_start_offset = 0;
		map->s_type_specific.s_virtual.s_num_entries =
			(sbi->s_vat_inode->i_size - 36) >> 2;
	} else if (map->s_partition_type == UDF_VIRTUAL_MAP20) {
		vati = UDF_I(sbi->s_vat_inode);
		if (vati->i_alloc_type != ICBTAG_FLAG_AD_IN_ICB) {
			pos = udf_block_map(sbi->s_vat_inode, 0);
			bh = sb_bread(sb, pos);
			if (!bh)
				return -EIO;
			vat20 = (struct virtualAllocationTable20 *)bh->b_data;
		} else {
			vat20 = (struct virtualAllocationTable20 *)
							vati->i_ext.i_data;
		}

		map->s_type_specific.s_virtual.s_start_offset =
			le16_to_cpu(vat20->lengthHeader);
		map->s_type_specific.s_virtual.s_num_entries =
			(sbi->s_vat_inode->i_size -
				map->s_type_specific.s_virtual.
					s_start_offset) >> 2;
		brelse(bh);
	}
	return 0;
}

/*
 * Load partition descriptor block
 *
 * Returns <0 on error, 0 on success, -EAGAIN is special - try next descriptor
 * sequence.
 */
static int udf_load_partdesc(struct super_block *sb, sector_t block)
{
	struct buffer_head *bh;
	struct partitionDesc *p;
	struct udf_part_map *map;
	struct udf_sb_info *sbi = UDF_SB(sb);
	int i, type1_idx;
	uint16_t partitionNumber;
	uint16_t ident;
	int ret;

	bh = udf_read_tagged(sb, block, block, &ident);
	if (!bh)
		return -EAGAIN;
	if (ident != TAG_IDENT_PD) {
		ret = 0;
		goto out_bh;
	}

	p = (struct partitionDesc *)bh->b_data;
	partitionNumber = le16_to_cpu(p->partitionNumber);

	/* First scan for TYPE1, SPARABLE and METADATA partitions */
	for (i = 0; i < sbi->s_partitions; i++) {
		map = &sbi->s_partmaps[i];
		udf_debug("Searching map: (%d == %d)\n",
			  map->s_partition_num, partitionNumber);
		if (map->s_partition_num == partitionNumber &&
		    (map->s_partition_type == UDF_TYPE1_MAP15 ||
		     map->s_partition_type == UDF_SPARABLE_MAP15))
			break;
	}

	if (i >= sbi->s_partitions) {
		udf_debug("Partition (%d) not found in partition map\n",
			  partitionNumber);
		ret = 0;
		goto out_bh;
	}

	ret = udf_fill_partdesc_info(sb, p, i);
	if (ret < 0)
		goto out_bh;

	/*
	 * Now rescan for VIRTUAL or METADATA partitions when SPARABLE and
	 * PHYSICAL partitions are already set up
	 */
	type1_idx = i;
#ifdef UDFFS_DEBUG
	map = NULL; /* supress 'maybe used uninitialized' warning */
#endif
	for (i = 0; i < sbi->s_partitions; i++) {
		map = &sbi->s_partmaps[i];

		if (map->s_partition_num == partitionNumber &&
		    (map->s_partition_type == UDF_VIRTUAL_MAP15 ||
		     map->s_partition_type == UDF_VIRTUAL_MAP20 ||
		     map->s_partition_type == UDF_METADATA_MAP25))
			break;
	}

	if (i >= sbi->s_partitions) {
		ret = 0;
		goto out_bh;
	}

	ret = udf_fill_partdesc_info(sb, p, i);
	if (ret < 0)
		goto out_bh;

	if (map->s_partition_type == UDF_METADATA_MAP25) {
		ret = udf_load_metadata_files(sb, i);
		if (ret < 0) {
			udf_err(sb, "error loading MetaData partition map %d\n",
				i);
			goto out_bh;
		}
	} else {
		/*
		 * If we have a partition with virtual map, we don't handle
		 * writing to it (we overwrite blocks instead of relocating
		 * them).
		 */
		if (!(sb->s_flags & MS_RDONLY)) {
			ret = -EACCES;
			goto out_bh;
		}
		ret = udf_load_vat(sb, i, type1_idx);
		if (ret < 0)
			goto out_bh;
	}
	ret = 0;
out_bh:
	/* In case loading failed, we handle cleanup in udf_fill_super */
	brelse(bh);
	return ret;
}

static int udf_load_sparable_map(struct super_block *sb,
				 struct udf_part_map *map,
				 struct sparablePartitionMap *spm)
{
	uint32_t loc;
	uint16_t ident;
	struct sparingTable *st;
	struct udf_sparing_data *sdata = &map->s_type_specific.s_sparing;
	int i;
	struct buffer_head *bh;

	map->s_partition_type = UDF_SPARABLE_MAP15;
	sdata->s_packet_len = le16_to_cpu(spm->packetLength);
	if (!is_power_of_2(sdata->s_packet_len)) {
		udf_err(sb, "error loading logical volume descriptor: "
			"Invalid packet length %u\n",
			(unsigned)sdata->s_packet_len);
		return -EIO;
	}
	if (spm->numSparingTables > 4) {
		udf_err(sb, "error loading logical volume descriptor: "
			"Too many sparing tables (%d)\n",
			(int)spm->numSparingTables);
		return -EIO;
	}

	for (i = 0; i < spm->numSparingTables; i++) {
		loc = le32_to_cpu(spm->locSparingTable[i]);
		bh = udf_read_tagged(sb, loc, loc, &ident);
		if (!bh)
			continue;

		st = (struct sparingTable *)bh->b_data;
		if (ident != 0 ||
		    strncmp(st->sparingIdent.ident, UDF_ID_SPARING,
			    strlen(UDF_ID_SPARING)) ||
		    sizeof(*st) + le16_to_cpu(st->reallocationTableLen) >
							sb->s_blocksize) {
			brelse(bh);
			continue;
		}

		sdata->s_spar_map[i] = bh;
	}
	map->s_partition_func = udf_get_pblock_spar15;
	return 0;
}

static int udf_load_logicalvol(struct super_block *sb, sector_t block,
			       struct kernel_lb_addr *fileset)
{
	struct logicalVolDesc *lvd;
	int i, offset;
	uint8_t type;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct genericPartitionMap *gpm;
	uint16_t ident;
	struct buffer_head *bh;
	unsigned int table_len;
	int ret;

	bh = udf_read_tagged(sb, block, block, &ident);
	if (!bh)
		return -EAGAIN;
	BUG_ON(ident != TAG_IDENT_LVD);
	lvd = (struct logicalVolDesc *)bh->b_data;
	table_len = le32_to_cpu(lvd->mapTableLength);
	if (table_len > sb->s_blocksize - sizeof(*lvd)) {
		udf_err(sb, "error loading logical volume descriptor: "
			"Partition table too long (%u > %lu)\n", table_len,
			sb->s_blocksize - sizeof(*lvd));
		ret = -EIO;
		goto out_bh;
	}

	ret = udf_sb_alloc_partition_maps(sb, le32_to_cpu(lvd->numPartitionMaps));
	if (ret)
		goto out_bh;

	for (i = 0, offset = 0;
	     i < sbi->s_partitions && offset < table_len;
	     i++, offset += gpm->partitionMapLength) {
		struct udf_part_map *map = &sbi->s_partmaps[i];
		gpm = (struct genericPartitionMap *)
				&(lvd->partitionMaps[offset]);
		type = gpm->partitionMapType;
		if (type == 1) {
			struct genericPartitionMap1 *gpm1 =
				(struct genericPartitionMap1 *)gpm;
			map->s_partition_type = UDF_TYPE1_MAP15;
			map->s_volumeseqnum = le16_to_cpu(gpm1->volSeqNum);
			map->s_partition_num = le16_to_cpu(gpm1->partitionNum);
			map->s_partition_func = NULL;
		} else if (type == 2) {
			struct udfPartitionMap2 *upm2 =
						(struct udfPartitionMap2 *)gpm;
			if (!strncmp(upm2->partIdent.ident, UDF_ID_VIRTUAL,
						strlen(UDF_ID_VIRTUAL))) {
				u16 suf =
					le16_to_cpu(((__le16 *)upm2->partIdent.
							identSuffix)[0]);
				if (suf < 0x0200) {
					map->s_partition_type =
							UDF_VIRTUAL_MAP15;
					map->s_partition_func =
							udf_get_pblock_virt15;
				} else {
					map->s_partition_type =
							UDF_VIRTUAL_MAP20;
					map->s_partition_func =
							udf_get_pblock_virt20;
				}
			} else if (!strncmp(upm2->partIdent.ident,
						UDF_ID_SPARABLE,
						strlen(UDF_ID_SPARABLE))) {
				ret = udf_load_sparable_map(sb, map,
					(struct sparablePartitionMap *)gpm);
				if (ret < 0)
					goto out_bh;
			} else if (!strncmp(upm2->partIdent.ident,
						UDF_ID_METADATA,
						strlen(UDF_ID_METADATA))) {
				struct udf_meta_data *mdata =
					&map->s_type_specific.s_metadata;
				struct metadataPartitionMap *mdm =
						(struct metadataPartitionMap *)
						&(lvd->partitionMaps[offset]);
				udf_debug("Parsing Logical vol part %d type %d  id=%s\n",
					  i, type, UDF_ID_METADATA);

				map->s_partition_type = UDF_METADATA_MAP25;
				map->s_partition_func = udf_get_pblock_meta25;

				mdata->s_meta_file_loc   =
					le32_to_cpu(mdm->metadataFileLoc);
				mdata->s_mirror_file_loc =
					le32_to_cpu(mdm->metadataMirrorFileLoc);
				mdata->s_bitmap_file_loc =
					le32_to_cpu(mdm->metadataBitmapFileLoc);
				mdata->s_alloc_unit_size =
					le32_to_cpu(mdm->allocUnitSize);
				mdata->s_align_unit_size =
					le16_to_cpu(mdm->alignUnitSize);
				if (mdm->flags & 0x01)
					mdata->s_flags |= MF_DUPLICATE_MD;

				udf_debug("Metadata Ident suffix=0x%x\n",
					  le16_to_cpu(*(__le16 *)
						      mdm->partIdent.identSuffix));
				udf_debug("Metadata part num=%d\n",
					  le16_to_cpu(mdm->partitionNum));
				udf_debug("Metadata part alloc unit size=%d\n",
					  le32_to_cpu(mdm->allocUnitSize));
				udf_debug("Metadata file loc=%d\n",
					  le32_to_cpu(mdm->metadataFileLoc));
				udf_debug("Mirror file loc=%d\n",
					  le32_to_cpu(mdm->metadataMirrorFileLoc));
				udf_debug("Bitmap file loc=%d\n",
					  le32_to_cpu(mdm->metadataBitmapFileLoc));
				udf_debug("Flags: %d %d\n",
					  mdata->s_flags, mdm->flags);
			} else {
				udf_debug("Unknown ident: %s\n",
					  upm2->partIdent.ident);
				continue;
			}
			map->s_volumeseqnum = le16_to_cpu(upm2->volSeqNum);
			map->s_partition_num = le16_to_cpu(upm2->partitionNum);
		}
		udf_debug("Partition (%d:%d) type %d on volume %d\n",
			  i, map->s_partition_num, type, map->s_volumeseqnum);
	}

	if (fileset) {
		struct long_ad *la = (struct long_ad *)&(lvd->logicalVolContentsUse[0]);

		*fileset = lelb_to_cpu(la->extLocation);
		udf_debug("FileSet found in LogicalVolDesc at block=%d, partition=%d\n",
			  fileset->logicalBlockNum,
			  fileset->partitionReferenceNum);
	}
	if (lvd->integritySeqExt.extLength)
		udf_load_logicalvolint(sb, leea_to_cpu(lvd->integritySeqExt));
	ret = 0;
out_bh:
	brelse(bh);
	return ret;
}

/*
 * udf_load_logicalvolint
 *
 */
static void udf_load_logicalvolint(struct super_block *sb, struct kernel_extent_ad loc)
{
	struct buffer_head *bh = NULL;
	uint16_t ident;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct logicalVolIntegrityDesc *lvid;

	while (loc.extLength > 0 &&
	       (bh = udf_read_tagged(sb, loc.extLocation,
				     loc.extLocation, &ident)) &&
	       ident == TAG_IDENT_LVID) {
		sbi->s_lvid_bh = bh;
		lvid = (struct logicalVolIntegrityDesc *)bh->b_data;

		if (lvid->nextIntegrityExt.extLength)
			udf_load_logicalvolint(sb,
				leea_to_cpu(lvid->nextIntegrityExt));

		if (sbi->s_lvid_bh != bh)
			brelse(bh);
		loc.extLength -= sb->s_blocksize;
		loc.extLocation++;
	}
	if (sbi->s_lvid_bh != bh)
		brelse(bh);
}

/*
 * Process a main/reserve volume descriptor sequence.
 *   @block		First block of first extent of the sequence.
 *   @lastblock		Lastblock of first extent of the sequence.
 *   @fileset		There we store extent containing root fileset
 *
 * Returns <0 on error, 0 on success. -EAGAIN is special - try next descriptor
 * sequence
 */
static noinline int udf_process_sequence(
		struct super_block *sb,
		sector_t block, sector_t lastblock,
		struct kernel_lb_addr *fileset)
{
	struct buffer_head *bh = NULL;
	struct udf_vds_record vds[VDS_POS_LENGTH];
	struct udf_vds_record *curr;
	struct generic_desc *gd;
	struct volDescPtr *vdp;
	bool done = false;
	uint32_t vdsn;
	uint16_t ident;
	long next_s = 0, next_e = 0;
	int ret;

	memset(vds, 0, sizeof(struct udf_vds_record) * VDS_POS_LENGTH);

	/*
	 * Read the main descriptor sequence and find which descriptors
	 * are in it.
	 */
	for (; (!done && block <= lastblock); block++) {

		bh = udf_read_tagged(sb, block, block, &ident);
		if (!bh) {
			udf_err(sb,
				"Block %llu of volume descriptor sequence is corrupted or we could not read it\n",
				(unsigned long long)block);
			return -EAGAIN;
		}

		/* Process each descriptor (ISO 13346 3/8.3-8.4) */
		gd = (struct generic_desc *)bh->b_data;
		vdsn = le32_to_cpu(gd->volDescSeqNum);
		switch (ident) {
		case TAG_IDENT_PVD: /* ISO 13346 3/10.1 */
			curr = &vds[VDS_POS_PRIMARY_VOL_DESC];
			if (vdsn >= curr->volDescSeqNum) {
				curr->volDescSeqNum = vdsn;
				curr->block = block;
			}
			break;
		case TAG_IDENT_VDP: /* ISO 13346 3/10.3 */
			curr = &vds[VDS_POS_VOL_DESC_PTR];
			if (vdsn >= curr->volDescSeqNum) {
				curr->volDescSeqNum = vdsn;
				curr->block = block;

				vdp = (struct volDescPtr *)bh->b_data;
				next_s = le32_to_cpu(
					vdp->nextVolDescSeqExt.extLocation);
				next_e = le32_to_cpu(
					vdp->nextVolDescSeqExt.extLength);
				next_e = next_e >> sb->s_blocksize_bits;
				next_e += next_s;
			}
			break;
		case TAG_IDENT_IUVD: /* ISO 13346 3/10.4 */
			curr = &vds[VDS_POS_IMP_USE_VOL_DESC];
			if (vdsn >= curr->volDescSeqNum) {
				curr->volDescSeqNum = vdsn;
				curr->block = block;
			}
			break;
		case TAG_IDENT_PD: /* ISO 13346 3/10.5 */
			curr = &vds[VDS_POS_PARTITION_DESC];
			if (!curr->block)
				curr->block = block;
			break;
		case TAG_IDENT_LVD: /* ISO 13346 3/10.6 */
			curr = &vds[VDS_POS_LOGICAL_VOL_DESC];
			if (vdsn >= curr->volDescSeqNum) {
				curr->volDescSeqNum = vdsn;
				curr->block = block;
			}
			break;
		case TAG_IDENT_USD: /* ISO 13346 3/10.8 */
			curr = &vds[VDS_POS_UNALLOC_SPACE_DESC];
			if (vdsn >= curr->volDescSeqNum) {
				curr->volDescSeqNum = vdsn;
				curr->block = block;
			}
			break;
		case TAG_IDENT_TD: /* ISO 13346 3/10.9 */
			vds[VDS_POS_TERMINATING_DESC].block = block;
			if (next_e) {
				block = next_s;
				lastblock = next_e;
				next_s = next_e = 0;
			} else
				done = true;
			break;
		}
		brelse(bh);
	}
	/*
	 * Now read interesting descriptors again and process them
	 * in a suitable order
	 */
	if (!vds[VDS_POS_PRIMARY_VOL_DESC].block) {
		udf_err(sb, "Primary Volume Descriptor not found!\n");
		return -EAGAIN;
	}
	ret = udf_load_pvoldesc(sb, vds[VDS_POS_PRIMARY_VOL_DESC].block);
	if (ret < 0)
		return ret;

	if (vds[VDS_POS_LOGICAL_VOL_DESC].block) {
		ret = udf_load_logicalvol(sb,
					  vds[VDS_POS_LOGICAL_VOL_DESC].block,
					  fileset);
		if (ret < 0)
			return ret;
	}

	if (vds[VDS_POS_PARTITION_DESC].block) {
		/*
		 * We rescan the whole descriptor sequence to find
		 * partition descriptor blocks and process them.
		 */
		for (block = vds[VDS_POS_PARTITION_DESC].block;
		     block < vds[VDS_POS_TERMINATING_DESC].block;
		     block++) {
			ret = udf_load_partdesc(sb, block);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

/*
 * Load Volume Descriptor Sequence described by anchor in bh
 *
 * Returns <0 on error, 0 on success
 */
static int udf_load_sequence(struct super_block *sb, struct buffer_head *bh,
			     struct kernel_lb_addr *fileset)
{
	struct anchorVolDescPtr *anchor;
	sector_t main_s, main_e, reserve_s, reserve_e;
	int ret;

	anchor = (struct anchorVolDescPtr *)bh->b_data;

	/* Locate the main sequence */
	main_s = le32_to_cpu(anchor->mainVolDescSeqExt.extLocation);
	main_e = le32_to_cpu(anchor->mainVolDescSeqExt.extLength);
	main_e = main_e >> sb->s_blocksize_bits;
	main_e += main_s;

	/* Locate the reserve sequence */
	reserve_s = le32_to_cpu(anchor->reserveVolDescSeqExt.extLocation);
	reserve_e = le32_to_cpu(anchor->reserveVolDescSeqExt.extLength);
	reserve_e = reserve_e >> sb->s_blocksize_bits;
	reserve_e += reserve_s;

	/* Process the main & reserve sequences */
	/* responsible for finding the PartitionDesc(s) */
	ret = udf_process_sequence(sb, main_s, main_e, fileset);
	if (ret != -EAGAIN)
		return ret;
	udf_sb_free_partitions(sb);
	ret = udf_process_sequence(sb, reserve_s, reserve_e, fileset);
	if (ret < 0) {
		udf_sb_free_partitions(sb);
		/* No sequence was OK, return -EIO */
		if (ret == -EAGAIN)
			ret = -EIO;
	}
	return ret;
}

/*
 * Check whether there is an anchor block in the given block and
 * load Volume Descriptor Sequence if so.
 *
 * Returns <0 on error, 0 on success, -EAGAIN is special - try next anchor
 * block
 */
static int udf_check_anchor_block(struct super_block *sb, sector_t block,
				  struct kernel_lb_addr *fileset)
{
	struct buffer_head *bh;
	uint16_t ident;
	int ret;

	if (UDF_QUERY_FLAG(sb, UDF_FLAG_VARCONV) &&
	    udf_fixed_to_variable(block) >=
	    sb->s_bdev->bd_inode->i_size >> sb->s_blocksize_bits)
		return -EAGAIN;

	bh = udf_read_tagged(sb, block, block, &ident);
	if (!bh)
		return -EAGAIN;
	if (ident != TAG_IDENT_AVDP) {
		brelse(bh);
		return -EAGAIN;
	}
	ret = udf_load_sequence(sb, bh, fileset);
	brelse(bh);
	return ret;
}

/*
 * Search for an anchor volume descriptor pointer.
 *
 * Returns < 0 on error, 0 on success. -EAGAIN is special - try next set
 * of anchors.
 */
static int udf_scan_anchors(struct super_block *sb, sector_t *lastblock,
			    struct kernel_lb_addr *fileset)
{
	sector_t last[6];
	int i;
	struct udf_sb_info *sbi = UDF_SB(sb);
	int last_count = 0;
	int ret;

	/* First try user provided anchor */
	if (sbi->s_anchor) {
		ret = udf_check_anchor_block(sb, sbi->s_anchor, fileset);
		if (ret != -EAGAIN)
			return ret;
	}
	/*
	 * according to spec, anchor is in either:
	 *     block 256
	 *     lastblock-256
	 *     lastblock
	 *  however, if the disc isn't closed, it could be 512.
	 */
	ret = udf_check_anchor_block(sb, sbi->s_session + 256, fileset);
	if (ret != -EAGAIN)
		return ret;
	/*
	 * The trouble is which block is the last one. Drives often misreport
	 * this so we try various possibilities.
	 */
	last[last_count++] = *lastblock;
	if (*lastblock >= 1)
		last[last_count++] = *lastblock - 1;
	last[last_count++] = *lastblock + 1;
	if (*lastblock >= 2)
		last[last_count++] = *lastblock - 2;
	if (*lastblock >= 150)
		last[last_count++] = *lastblock - 150;
	if (*lastblock >= 152)
		last[last_count++] = *lastblock - 152;

	for (i = 0; i < last_count; i++) {
		if (last[i] >= sb->s_bdev->bd_inode->i_size >>
				sb->s_blocksize_bits)
			continue;
		ret = udf_check_anchor_block(sb, last[i], fileset);
		if (ret != -EAGAIN) {
			if (!ret)
				*lastblock = last[i];
			return ret;
		}
		if (last[i] < 256)
			continue;
		ret = udf_check_anchor_block(sb, last[i] - 256, fileset);
		if (ret != -EAGAIN) {
			if (!ret)
				*lastblock = last[i];
			return ret;
		}
	}

	/* Finally try block 512 in case media is open */
	return udf_check_anchor_block(sb, sbi->s_session + 512, fileset);
}

/*
 * Find an anchor volume descriptor and load Volume Descriptor Sequence from
 * area specified by it. The function expects sbi->s_lastblock to be the last
 * block on the media.
 *
 * Return <0 on error, 0 if anchor found. -EAGAIN is special meaning anchor
 * was not found.
 */
static int udf_find_anchor(struct super_block *sb,
			   struct kernel_lb_addr *fileset)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	sector_t lastblock = sbi->s_last_block;
	int ret;

	ret = udf_scan_anchors(sb, &lastblock, fileset);
	if (ret != -EAGAIN)
		goto out;

	/* No anchor found? Try VARCONV conversion of block numbers */
	UDF_SET_FLAG(sb, UDF_FLAG_VARCONV);
	lastblock = udf_variable_to_fixed(sbi->s_last_block);
	/* Firstly, we try to not convert number of the last block */
	ret = udf_scan_anchors(sb, &lastblock, fileset);
	if (ret != -EAGAIN)
		goto out;

	lastblock = sbi->s_last_block;
	/* Secondly, we try with converted number of the last block */
	ret = udf_scan_anchors(sb, &lastblock, fileset);
	if (ret < 0) {
		/* VARCONV didn't help. Clear it. */
		UDF_CLEAR_FLAG(sb, UDF_FLAG_VARCONV);
	}
out:
	if (ret == 0)
		sbi->s_last_block = lastblock;
	return ret;
}

/*
 * Check Volume Structure Descriptor, find Anchor block and load Volume
 * Descriptor Sequence.
 *
 * Returns < 0 on error, 0 on success. -EAGAIN is special meaning anchor
 * block was not found.
 */
static int udf_load_vrs(struct super_block *sb, struct udf_options *uopt,
			int silent, struct kernel_lb_addr *fileset)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	loff_t nsr_off;
	int ret;

	if (!sb_set_blocksize(sb, uopt->blocksize)) {
		if (!silent)
			udf_warn(sb, "Bad block size\n");
		return -EINVAL;
	}
	sbi->s_last_block = uopt->lastblock;
	if (!uopt->novrs) {
		/* Check that it is NSR02 compliant */
		nsr_off = udf_check_vsd(sb);
		if (!nsr_off) {
			if (!silent)
				udf_warn(sb, "No VRS found\n");
			return 0;
		}
		if (nsr_off == -1)
			udf_debug("Failed to read sector at offset %d. "
				  "Assuming open disc. Skipping validity "
				  "check\n", VSD_FIRST_SECTOR_OFFSET);
		if (!sbi->s_last_block)
			sbi->s_last_block = udf_get_last_block(sb);
	} else {
		udf_debug("Validity check skipped because of novrs option\n");
	}

	/* Look for anchor block and load Volume Descriptor Sequence */
	sbi->s_anchor = uopt->anchor;
	ret = udf_find_anchor(sb, fileset);
	if (ret < 0) {
		if (!silent && ret == -EAGAIN)
			udf_warn(sb, "No anchor found\n");
		return ret;
	}
	return 0;
}

static void udf_open_lvid(struct super_block *sb)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct buffer_head *bh = sbi->s_lvid_bh;
	struct logicalVolIntegrityDesc *lvid;
	struct logicalVolIntegrityDescImpUse *lvidiu;

	if (!bh)
		return;
	lvid = (struct logicalVolIntegrityDesc *)bh->b_data;
	lvidiu = udf_sb_lvidiu(sb);
	if (!lvidiu)
		return;

	mutex_lock(&sbi->s_alloc_mutex);
	lvidiu->impIdent.identSuffix[0] = UDF_OS_CLASS_UNIX;
	lvidiu->impIdent.identSuffix[1] = UDF_OS_ID_LINUX;
	udf_time_to_disk_stamp(&lvid->recordingDateAndTime,
				CURRENT_TIME);
	lvid->integrityType = cpu_to_le32(LVID_INTEGRITY_TYPE_OPEN);

	lvid->descTag.descCRC = cpu_to_le16(
		crc_itu_t(0, (char *)lvid + sizeof(struct tag),
			le16_to_cpu(lvid->descTag.descCRCLength)));

	lvid->descTag.tagChecksum = udf_tag_checksum(&lvid->descTag);
	mark_buffer_dirty(bh);
	sbi->s_lvid_dirty = 0;
	mutex_unlock(&sbi->s_alloc_mutex);
	/* Make opening of filesystem visible on the media immediately */
	sync_dirty_buffer(bh);
}

static void udf_close_lvid(struct super_block *sb)
{
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct buffer_head *bh = sbi->s_lvid_bh;
	struct logicalVolIntegrityDesc *lvid;
	struct logicalVolIntegrityDescImpUse *lvidiu;

	if (!bh)
		return;
	lvid = (struct logicalVolIntegrityDesc *)bh->b_data;
	lvidiu = udf_sb_lvidiu(sb);
	if (!lvidiu)
		return;

	mutex_lock(&sbi->s_alloc_mutex);
	lvidiu->impIdent.identSuffix[0] = UDF_OS_CLASS_UNIX;
	lvidiu->impIdent.identSuffix[1] = UDF_OS_ID_LINUX;
	udf_time_to_disk_stamp(&lvid->recordingDateAndTime, CURRENT_TIME);
	if (UDF_MAX_WRITE_VERSION > le16_to_cpu(lvidiu->maxUDFWriteRev))
		lvidiu->maxUDFWriteRev = cpu_to_le16(UDF_MAX_WRITE_VERSION);
	if (sbi->s_udfrev > le16_to_cpu(lvidiu->minUDFReadRev))
		lvidiu->minUDFReadRev = cpu_to_le16(sbi->s_udfrev);
	if (sbi->s_udfrev > le16_to_cpu(lvidiu->minUDFWriteRev))
		lvidiu->minUDFWriteRev = cpu_to_le16(sbi->s_udfrev);
	lvid->integrityType = cpu_to_le32(LVID_INTEGRITY_TYPE_CLOSE);

	lvid->descTag.descCRC = cpu_to_le16(
			crc_itu_t(0, (char *)lvid + sizeof(struct tag),
				le16_to_cpu(lvid->descTag.descCRCLength)));

	lvid->descTag.tagChecksum = udf_tag_checksum(&lvid->descTag);
	/*
	 * We set buffer uptodate unconditionally here to avoid spurious
	 * warnings from mark_buffer_dirty() when previous EIO has marked
	 * the buffer as !uptodate
	 */
	set_buffer_uptodate(bh);
	mark_buffer_dirty(bh);
	sbi->s_lvid_dirty = 0;
	mutex_unlock(&sbi->s_alloc_mutex);
	/* Make closing of filesystem visible on the media immediately */
	sync_dirty_buffer(bh);
}

u64 lvid_get_unique_id(struct super_block *sb)
{
	struct buffer_head *bh;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct logicalVolIntegrityDesc *lvid;
	struct logicalVolHeaderDesc *lvhd;
	u64 uniqueID;
	u64 ret;

	bh = sbi->s_lvid_bh;
	if (!bh)
		return 0;

	lvid = (struct logicalVolIntegrityDesc *)bh->b_data;
	lvhd = (struct logicalVolHeaderDesc *)lvid->logicalVolContentsUse;

	mutex_lock(&sbi->s_alloc_mutex);
	ret = uniqueID = le64_to_cpu(lvhd->uniqueID);
	if (!(++uniqueID & 0xFFFFFFFF))
		uniqueID += 16;
	lvhd->uniqueID = cpu_to_le64(uniqueID);
	mutex_unlock(&sbi->s_alloc_mutex);
	mark_buffer_dirty(bh);

	return ret;
}

static int udf_fill_super(struct super_block *sb, void *options, int silent)
{
	int ret = -EINVAL;
	struct inode *inode = NULL;
	struct udf_options uopt;
	struct kernel_lb_addr rootdir, fileset;
	struct udf_sb_info *sbi;

	uopt.flags = (1 << UDF_FLAG_USE_AD_IN_ICB) | (1 << UDF_FLAG_STRICT);
	uopt.uid = INVALID_UID;
	uopt.gid = INVALID_GID;
	uopt.umask = 0;
	uopt.fmode = UDF_INVALID_MODE;
	uopt.dmode = UDF_INVALID_MODE;

	sbi = kzalloc(sizeof(struct udf_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;

	mutex_init(&sbi->s_alloc_mutex);

	if (!udf_parse_options((char *)options, &uopt, false))
		goto parse_options_failure;

	if (uopt.flags & (1 << UDF_FLAG_UTF8) &&
	    uopt.flags & (1 << UDF_FLAG_NLS_MAP)) {
		udf_err(sb, "utf8 cannot be combined with iocharset\n");
		goto parse_options_failure;
	}
#ifdef CONFIG_UDF_NLS
	if ((uopt.flags & (1 << UDF_FLAG_NLS_MAP)) && !uopt.nls_map) {
		uopt.nls_map = load_nls_default();
		if (!uopt.nls_map)
			uopt.flags &= ~(1 << UDF_FLAG_NLS_MAP);
		else
			udf_debug("Using default NLS map\n");
	}
#endif
	if (!(uopt.flags & (1 << UDF_FLAG_NLS_MAP)))
		uopt.flags |= (1 << UDF_FLAG_UTF8);

	fileset.logicalBlockNum = 0xFFFFFFFF;
	fileset.partitionReferenceNum = 0xFFFF;

	sbi->s_flags = uopt.flags;
	sbi->s_uid = uopt.uid;
	sbi->s_gid = uopt.gid;
	sbi->s_umask = uopt.umask;
	sbi->s_fmode = uopt.fmode;
	sbi->s_dmode = uopt.dmode;
	sbi->s_nls_map = uopt.nls_map;
	rwlock_init(&sbi->s_cred_lock);

	if (uopt.session == 0xFFFFFFFF)
		sbi->s_session = udf_get_last_session(sb);
	else
		sbi->s_session = uopt.session;

	udf_debug("Multi-session=%d\n", sbi->s_session);

	/* Fill in the rest of the superblock */
	sb->s_op = &udf_sb_ops;
	sb->s_export_op = &udf_export_ops;

	sb->s_magic = UDF_SUPER_MAGIC;
	sb->s_time_gran = 1000;

	if (uopt.flags & (1 << UDF_FLAG_BLOCKSIZE_SET)) {
		ret = udf_load_vrs(sb, &uopt, silent, &fileset);
	} else {
		uopt.blocksize = bdev_logical_block_size(sb->s_bdev);
		ret = udf_load_vrs(sb, &uopt, silent, &fileset);
		if (ret == -EAGAIN && uopt.blocksize != UDF_DEFAULT_BLOCKSIZE) {
			if (!silent)
				pr_notice("Rescanning with blocksize %d\n",
					  UDF_DEFAULT_BLOCKSIZE);
			brelse(sbi->s_lvid_bh);
			sbi->s_lvid_bh = NULL;
			uopt.blocksize = UDF_DEFAULT_BLOCKSIZE;
			ret = udf_load_vrs(sb, &uopt, silent, &fileset);
		}
	}
	if (ret < 0) {
		if (ret == -EAGAIN) {
			udf_warn(sb, "No partition found (1)\n");
			ret = -EINVAL;
		}
		goto error_out;
	}

	udf_debug("Lastblock=%d\n", sbi->s_last_block);

	if (sbi->s_lvid_bh) {
		struct logicalVolIntegrityDescImpUse *lvidiu =
							udf_sb_lvidiu(sb);
		uint16_t minUDFReadRev;
		uint16_t minUDFWriteRev;

		if (!lvidiu) {
			ret = -EINVAL;
			goto error_out;
		}
		minUDFReadRev = le16_to_cpu(lvidiu->minUDFReadRev);
		minUDFWriteRev = le16_to_cpu(lvidiu->minUDFWriteRev);
		if (minUDFReadRev > UDF_MAX_READ_VERSION) {
			udf_err(sb, "minUDFReadRev=%x (max is %x)\n",
				minUDFReadRev,
				UDF_MAX_READ_VERSION);
			ret = -EINVAL;
			goto error_out;
		} else if (minUDFWriteRev > UDF_MAX_WRITE_VERSION &&
			   !(sb->s_flags & MS_RDONLY)) {
			ret = -EACCES;
			goto error_out;
		}

		sbi->s_udfrev = minUDFWriteRev;

		if (minUDFReadRev >= UDF_VERS_USE_EXTENDED_FE)
			UDF_SET_FLAG(sb, UDF_FLAG_USE_EXTENDED_FE);
		if (minUDFReadRev >= UDF_VERS_USE_STREAMS)
			UDF_SET_FLAG(sb, UDF_FLAG_USE_STREAMS);
	}

	if (!sbi->s_partitions) {
		udf_warn(sb, "No partition found (2)\n");
		ret = -EINVAL;
		goto error_out;
	}

	if (sbi->s_partmaps[sbi->s_partition].s_partition_flags &
			UDF_PART_FLAG_READ_ONLY &&
	    !(sb->s_flags & MS_RDONLY)) {
		ret = -EACCES;
		goto error_out;
	}

	if (udf_find_fileset(sb, &fileset, &rootdir)) {
		udf_warn(sb, "No fileset found\n");
		ret = -EINVAL;
		goto error_out;
	}

	if (!silent) {
		struct timestamp ts;
		udf_time_to_disk_stamp(&ts, sbi->s_record_time);
		udf_info("Mounting volume '%s', timestamp %04u/%02u/%02u %02u:%02u (%x)\n",
			 sbi->s_volume_ident,
			 le16_to_cpu(ts.year), ts.month, ts.day,
			 ts.hour, ts.minute, le16_to_cpu(ts.typeAndTimezone));
	}
	if (!(sb->s_flags & MS_RDONLY))
		udf_open_lvid(sb);

	/* Assign the root inode */
	/* assign inodes by physical block number */
	/* perhaps it's not extensible enough, but for now ... */
	inode = udf_iget(sb, &rootdir);
	if (IS_ERR(inode)) {
		udf_err(sb, "Error in udf_iget, block=%d, partition=%d\n",
		       rootdir.logicalBlockNum, rootdir.partitionReferenceNum);
		ret = PTR_ERR(inode);
		goto error_out;
	}

	/* Allocate a dentry for the root inode */
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		udf_err(sb, "Couldn't allocate root dentry\n");
		ret = -ENOMEM;
		goto error_out;
	}
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	sb->s_max_links = UDF_MAX_LINKS;
	return 0;

error_out:
	iput(sbi->s_vat_inode);
parse_options_failure:
#ifdef CONFIG_UDF_NLS
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_NLS_MAP))
		unload_nls(sbi->s_nls_map);
#endif
	if (!(sb->s_flags & MS_RDONLY))
		udf_close_lvid(sb);
	brelse(sbi->s_lvid_bh);
	udf_sb_free_partitions(sb);
	kfree(sbi);
	sb->s_fs_info = NULL;

	return ret;
}

void _udf_err(struct super_block *sb, const char *function,
	      const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	pr_err("error (device %s): %s: %pV", sb->s_id, function, &vaf);

	va_end(args);
}

void _udf_warn(struct super_block *sb, const char *function,
	       const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);

	vaf.fmt = fmt;
	vaf.va = &args;

	pr_warn("warning (device %s): %s: %pV", sb->s_id, function, &vaf);

	va_end(args);
}

static void udf_put_super(struct super_block *sb)
{
	struct udf_sb_info *sbi;

	sbi = UDF_SB(sb);

	iput(sbi->s_vat_inode);
#ifdef CONFIG_UDF_NLS
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_NLS_MAP))
		unload_nls(sbi->s_nls_map);
#endif
	if (!(sb->s_flags & MS_RDONLY))
		udf_close_lvid(sb);
	brelse(sbi->s_lvid_bh);
	udf_sb_free_partitions(sb);
	mutex_destroy(&sbi->s_alloc_mutex);
	kfree(sb->s_fs_info);
	sb->s_fs_info = NULL;
}

static int udf_sync_fs(struct super_block *sb, int wait)
{
	struct udf_sb_info *sbi = UDF_SB(sb);

	mutex_lock(&sbi->s_alloc_mutex);
	if (sbi->s_lvid_dirty) {
		/*
		 * Blockdevice will be synced later so we don't have to submit
		 * the buffer for IO
		 */
		mark_buffer_dirty(sbi->s_lvid_bh);
		sbi->s_lvid_dirty = 0;
	}
	mutex_unlock(&sbi->s_alloc_mutex);

	return 0;
}

static int udf_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct udf_sb_info *sbi = UDF_SB(sb);
	struct logicalVolIntegrityDescImpUse *lvidiu;
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	lvidiu = udf_sb_lvidiu(sb);
	buf->f_type = UDF_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = sbi->s_partmaps[sbi->s_partition].s_partition_len;
	buf->f_bfree = udf_count_free(sb);
	buf->f_bavail = buf->f_bfree;
	buf->f_files = (lvidiu != NULL ? (le32_to_cpu(lvidiu->numFiles) +
					  le32_to_cpu(lvidiu->numDirs)) : 0)
			+ buf->f_bfree;
	buf->f_ffree = buf->f_bfree;
	buf->f_namelen = UDF_NAME_LEN - 2;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	return 0;
}

static unsigned int udf_count_free_bitmap(struct super_block *sb,
					  struct udf_bitmap *bitmap)
{
	struct buffer_head *bh = NULL;
	unsigned int accum = 0;
	int index;
	int block = 0, newblock;
	struct kernel_lb_addr loc;
	uint32_t bytes;
	uint8_t *ptr;
	uint16_t ident;
	struct spaceBitmapDesc *bm;

	loc.logicalBlockNum = bitmap->s_extPosition;
	loc.partitionReferenceNum = UDF_SB(sb)->s_partition;
	bh = udf_read_ptagged(sb, &loc, 0, &ident);

	if (!bh) {
		udf_err(sb, "udf_count_free failed\n");
		goto out;
	} else if (ident != TAG_IDENT_SBD) {
		brelse(bh);
		udf_err(sb, "udf_count_free failed\n");
		goto out;
	}

	bm = (struct spaceBitmapDesc *)bh->b_data;
	bytes = le32_to_cpu(bm->numOfBytes);
	index = sizeof(struct spaceBitmapDesc); /* offset in first block only */
	ptr = (uint8_t *)bh->b_data;

	while (bytes > 0) {
		u32 cur_bytes = min_t(u32, bytes, sb->s_blocksize - index);
		accum += bitmap_weight((const unsigned long *)(ptr + index),
					cur_bytes * 8);
		bytes -= cur_bytes;
		if (bytes) {
			brelse(bh);
			newblock = udf_get_lb_pblock(sb, &loc, ++block);
			bh = udf_tread(sb, newblock);
			if (!bh) {
				udf_debug("read failed\n");
				goto out;
			}
			index = 0;
			ptr = (uint8_t *)bh->b_data;
		}
	}
	brelse(bh);
out:
	return accum;
}

static unsigned int udf_count_free_table(struct super_block *sb,
					 struct inode *table)
{
	unsigned int accum = 0;
	uint32_t elen;
	struct kernel_lb_addr eloc;
	int8_t etype;
	struct extent_position epos;

	mutex_lock(&UDF_SB(sb)->s_alloc_mutex);
	epos.block = UDF_I(table)->i_location;
	epos.offset = sizeof(struct unallocSpaceEntry);
	epos.bh = NULL;

	while ((etype = udf_next_aext(table, &epos, &eloc, &elen, 1)) != -1)
		accum += (elen >> table->i_sb->s_blocksize_bits);

	brelse(epos.bh);
	mutex_unlock(&UDF_SB(sb)->s_alloc_mutex);

	return accum;
}

static unsigned int udf_count_free(struct super_block *sb)
{
	unsigned int accum = 0;
	struct udf_sb_info *sbi;
	struct udf_part_map *map;

	sbi = UDF_SB(sb);
	if (sbi->s_lvid_bh) {
		struct logicalVolIntegrityDesc *lvid =
			(struct logicalVolIntegrityDesc *)
			sbi->s_lvid_bh->b_data;
		if (le32_to_cpu(lvid->numOfPartitions) > sbi->s_partition) {
			accum = le32_to_cpu(
					lvid->freeSpaceTable[sbi->s_partition]);
			if (accum == 0xFFFFFFFF)
				accum = 0;
		}
	}

	if (accum)
		return accum;

	map = &sbi->s_partmaps[sbi->s_partition];
	if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_BITMAP) {
		accum += udf_count_free_bitmap(sb,
					       map->s_uspace.s_bitmap);
	}
	if (map->s_partition_flags & UDF_PART_FLAG_FREED_BITMAP) {
		accum += udf_count_free_bitmap(sb,
					       map->s_fspace.s_bitmap);
	}
	if (accum)
		return accum;

	if (map->s_partition_flags & UDF_PART_FLAG_UNALLOC_TABLE) {
		accum += udf_count_free_table(sb,
					      map->s_uspace.s_table);
	}
	if (map->s_partition_flags & UDF_PART_FLAG_FREED_TABLE) {
		accum += udf_count_free_table(sb,
					      map->s_fspace.s_table);
	}

	return accum;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/super.c */
/************************************************************/
/*
 * truncate.c
 *
 * PURPOSE
 *	Truncate handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 *
 *  (C) 1999-2004 Ben Fennema
 *  (C) 1999 Stelias Computing Inc
 *
 * HISTORY
 *
 *  02/24/99 blf  Created.
 *
 */

// #include "udfdecl.h"
// #include <linux/fs.h>
// #include <linux/mm.h>
// #include <linux/buffer_head.h>

// #include "udf_i.h"
// #include "udf_sb.h"

static void extent_trunc(struct inode *inode, struct extent_position *epos,
			 struct kernel_lb_addr *eloc, int8_t etype, uint32_t elen,
			 uint32_t nelen)
{
	struct kernel_lb_addr neloc = {};
	int last_block = (elen + inode->i_sb->s_blocksize - 1) >>
		inode->i_sb->s_blocksize_bits;
	int first_block = (nelen + inode->i_sb->s_blocksize - 1) >>
		inode->i_sb->s_blocksize_bits;

	if (nelen) {
		if (etype == (EXT_NOT_RECORDED_ALLOCATED >> 30)) {
			udf_free_blocks(inode->i_sb, inode, eloc, 0,
					last_block);
			etype = (EXT_NOT_RECORDED_NOT_ALLOCATED >> 30);
		} else
			neloc = *eloc;
		nelen = (etype << 30) | nelen;
	}

	if (elen != nelen) {
		udf_write_aext(inode, epos, &neloc, nelen, 0);
		if (last_block - first_block > 0) {
			if (etype == (EXT_RECORDED_ALLOCATED >> 30))
				mark_inode_dirty(inode);

			if (etype != (EXT_NOT_RECORDED_NOT_ALLOCATED >> 30))
				udf_free_blocks(inode->i_sb, inode, eloc,
						first_block,
						last_block - first_block);
		}
	}
}

/*
 * Truncate the last extent to match i_size. This function assumes
 * that preallocation extent is already truncated.
 */
void udf_truncate_tail_extent(struct inode *inode)
{
	struct extent_position epos = {};
	struct kernel_lb_addr eloc;
	uint32_t elen, nelen;
	uint64_t lbcount = 0;
	int8_t etype = -1, netype;
	int adsize;
	struct udf_inode_info *iinfo = UDF_I(inode);

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB ||
	    inode->i_size == iinfo->i_lenExtents)
		return;
	/* Are we going to delete the file anyway? */
	if (inode->i_nlink == 0)
		return;

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		adsize = sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		adsize = sizeof(struct long_ad);
	else
		BUG();

	/* Find the last extent in the file */
	while ((netype = udf_next_aext(inode, &epos, &eloc, &elen, 1)) != -1) {
		etype = netype;
		lbcount += elen;
		if (lbcount > inode->i_size) {
			if (lbcount - inode->i_size >= inode->i_sb->s_blocksize)
				udf_warn(inode->i_sb,
					 "Too long extent after EOF in inode %u: i_size: %lld lbcount: %lld extent %u+%u\n",
					 (unsigned)inode->i_ino,
					 (long long)inode->i_size,
					 (long long)lbcount,
					 (unsigned)eloc.logicalBlockNum,
					 (unsigned)elen);
			nelen = elen - (lbcount - inode->i_size);
			epos.offset -= adsize;
			extent_trunc(inode, &epos, &eloc, etype, elen, nelen);
			epos.offset += adsize;
			if (udf_next_aext(inode, &epos, &eloc, &elen, 1) != -1)
				udf_err(inode->i_sb,
					"Extent after EOF in inode %u\n",
					(unsigned)inode->i_ino);
			break;
		}
	}
	/* This inode entry is in-memory only and thus we don't have to mark
	 * the inode dirty */
	iinfo->i_lenExtents = inode->i_size;
	brelse(epos.bh);
}

void udf_discard_prealloc(struct inode *inode)
{
	struct extent_position epos = { NULL, 0, {0, 0} };
	struct kernel_lb_addr eloc;
	uint32_t elen;
	uint64_t lbcount = 0;
	int8_t etype = -1, netype;
	int adsize;
	struct udf_inode_info *iinfo = UDF_I(inode);

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB ||
	    inode->i_size == iinfo->i_lenExtents)
		return;

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		adsize = sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		adsize = sizeof(struct long_ad);
	else
		adsize = 0;

	epos.block = iinfo->i_location;

	/* Find the last extent in the file */
	while ((netype = udf_next_aext(inode, &epos, &eloc, &elen, 1)) != -1) {
		etype = netype;
		lbcount += elen;
	}
	if (etype == (EXT_NOT_RECORDED_ALLOCATED >> 30)) {
		epos.offset -= adsize;
		lbcount -= elen;
		extent_trunc(inode, &epos, &eloc, etype, elen, 0);
		if (!epos.bh) {
			iinfo->i_lenAlloc =
				epos.offset -
				udf_file_entry_alloc_offset(inode);
			mark_inode_dirty(inode);
		} else {
			struct allocExtDesc *aed =
				(struct allocExtDesc *)(epos.bh->b_data);
			aed->lengthAllocDescs =
				cpu_to_le32(epos.offset -
					    sizeof(struct allocExtDesc));
			if (!UDF_QUERY_FLAG(inode->i_sb, UDF_FLAG_STRICT) ||
			    UDF_SB(inode->i_sb)->s_udfrev >= 0x0201)
				udf_update_tag(epos.bh->b_data, epos.offset);
			else
				udf_update_tag(epos.bh->b_data,
					       sizeof(struct allocExtDesc));
			mark_buffer_dirty_inode(epos.bh, inode);
		}
	}
	/* This inode entry is in-memory only and thus we don't have to mark
	 * the inode dirty */
	iinfo->i_lenExtents = lbcount;
	brelse(epos.bh);
}

static void udf_update_alloc_ext_desc(struct inode *inode,
				      struct extent_position *epos,
				      u32 lenalloc)
{
	struct super_block *sb = inode->i_sb;
	struct udf_sb_info *sbi = UDF_SB(sb);

	struct allocExtDesc *aed = (struct allocExtDesc *) (epos->bh->b_data);
	int len = sizeof(struct allocExtDesc);

	aed->lengthAllocDescs =	cpu_to_le32(lenalloc);
	if (!UDF_QUERY_FLAG(sb, UDF_FLAG_STRICT) || sbi->s_udfrev >= 0x0201)
		len += lenalloc;

	udf_update_tag(epos->bh->b_data, len);
	mark_buffer_dirty_inode(epos->bh, inode);
}

/*
 * Truncate extents of inode to inode->i_size. This function can be used only
 * for making file shorter. For making file longer, udf_extend_file() has to
 * be used.
 */
void udf_truncate_extents(struct inode *inode)
{
	struct extent_position epos;
	struct kernel_lb_addr eloc, neloc = {};
	uint32_t elen, nelen = 0, indirect_ext_len = 0, lenalloc;
	int8_t etype;
	struct super_block *sb = inode->i_sb;
	sector_t first_block = inode->i_size >> sb->s_blocksize_bits, offset;
	loff_t byte_offset;
	int adsize;
	struct udf_inode_info *iinfo = UDF_I(inode);

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_SHORT)
		adsize = sizeof(struct short_ad);
	else if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_LONG)
		adsize = sizeof(struct long_ad);
	else
		BUG();

	etype = inode_bmap(inode, first_block, &epos, &eloc, &elen, &offset);
	byte_offset = (offset << sb->s_blocksize_bits) +
		(inode->i_size & (sb->s_blocksize - 1));
	if (etype == -1) {
		/* We should extend the file? */
		WARN_ON(byte_offset);
		return;
	}
	epos.offset -= adsize;
	extent_trunc(inode, &epos, &eloc, etype, elen, byte_offset);
	epos.offset += adsize;
	if (byte_offset)
		lenalloc = epos.offset;
	else
		lenalloc = epos.offset - adsize;

	if (!epos.bh)
		lenalloc -= udf_file_entry_alloc_offset(inode);
	else
		lenalloc -= sizeof(struct allocExtDesc);

	while ((etype = udf_current_aext(inode, &epos, &eloc,
					 &elen, 0)) != -1) {
		if (etype == (EXT_NEXT_EXTENT_ALLOCDECS >> 30)) {
			udf_write_aext(inode, &epos, &neloc, nelen, 0);
			if (indirect_ext_len) {
				/* We managed to free all extents in the
				 * indirect extent - free it too */
				BUG_ON(!epos.bh);
				udf_free_blocks(sb, NULL, &epos.block,
						0, indirect_ext_len);
			} else if (!epos.bh) {
				iinfo->i_lenAlloc = lenalloc;
				mark_inode_dirty(inode);
			} else
				udf_update_alloc_ext_desc(inode,
						&epos, lenalloc);
			brelse(epos.bh);
			epos.offset = sizeof(struct allocExtDesc);
			epos.block = eloc;
			epos.bh = udf_tread(sb,
					udf_get_lb_pblock(sb, &eloc, 0));
			if (elen)
				indirect_ext_len =
					(elen + sb->s_blocksize - 1) >>
					sb->s_blocksize_bits;
			else
				indirect_ext_len = 1;
		} else {
			extent_trunc(inode, &epos, &eloc, etype, elen, 0);
			epos.offset += adsize;
		}
	}

	if (indirect_ext_len) {
		BUG_ON(!epos.bh);
		udf_free_blocks(sb, NULL, &epos.block, 0, indirect_ext_len);
	} else if (!epos.bh) {
		iinfo->i_lenAlloc = lenalloc;
		mark_inode_dirty(inode);
	} else
		udf_update_alloc_ext_desc(inode, &epos, lenalloc);
	iinfo->i_lenExtents = inode->i_size;

	brelse(epos.bh);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/truncate.c */
/************************************************************/
/*
 * symlink.c
 *
 * PURPOSE
 *	Symlink handling routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 *
 *  (C) 1998-2001 Ben Fennema
 *  (C) 1999 Stelias Computing Inc
 *
 * HISTORY
 *
 *  04/16/99 blf  Created.
 *
 */

// #include "udfdecl.h"
// #include <linux/uaccess.h>
// #include <linux/errno.h>
// #include <linux/fs.h>
#include <linux/time.h>
// #include <linux/mm.h>
// #include <linux/stat.h>
// #include <linux/pagemap.h>
// #include <linux/buffer_head.h>
// #include "udf_i.h"
#include "../../inc/__fss.h"

static int udf_pc_to_char(struct super_block *sb, unsigned char *from,
			  int fromlen, unsigned char *to, int tolen)
{
	struct pathComponent *pc;
	int elen = 0;
	int comp_len;
	unsigned char *p = to;

	/* Reserve one byte for terminating \0 */
	tolen--;
	while (elen < fromlen) {
		pc = (struct pathComponent *)(from + elen);
		elen += sizeof(struct pathComponent);
		switch (pc->componentType) {
		case 1:
			/*
			 * Symlink points to some place which should be agreed
 			 * upon between originator and receiver of the media. Ignore.
			 */
			if (pc->lengthComponentIdent > 0) {
				elen += pc->lengthComponentIdent;
				break;
			}
			/* Fall through */
		case 2:
			if (tolen == 0)
				return -ENAMETOOLONG;
			p = to;
			*p++ = '/';
			tolen--;
			break;
		case 3:
			if (tolen < 3)
				return -ENAMETOOLONG;
			memcpy(p, "../", 3);
			p += 3;
			tolen -= 3;
			break;
		case 4:
			if (tolen < 2)
				return -ENAMETOOLONG;
			memcpy(p, "./", 2);
			p += 2;
			tolen -= 2;
			/* that would be . - just ignore */
			break;
		case 5:
			elen += pc->lengthComponentIdent;
			if (elen > fromlen)
				return -EIO;
			comp_len = udf_get_filename(sb, pc->componentIdent,
						    pc->lengthComponentIdent,
						    p, tolen);
			p += comp_len;
			tolen -= comp_len;
			if (tolen == 0)
				return -ENAMETOOLONG;
			*p++ = '/';
			tolen--;
			break;
		}
	}
	if (p > to + 1)
		p[-1] = '\0';
	else
		p[0] = '\0';
	return 0;
}

static int udf_symlink_filler(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct buffer_head *bh = NULL;
	unsigned char *symlink;
	int err;
	unsigned char *p = kmap(page);
	struct udf_inode_info *iinfo;
	uint32_t pos;

	/* We don't support symlinks longer than one block */
	if (inode->i_size > inode->i_sb->s_blocksize) {
		err = -ENAMETOOLONG;
		goto out_unmap;
	}

	iinfo = UDF_I(inode);
	pos = udf_block_map(inode, 0);

	down_read(&iinfo->i_data_sem);
	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
		symlink = iinfo->i_ext.i_data + iinfo->i_lenEAttr;
	} else {
		bh = sb_bread(inode->i_sb, pos);

		if (!bh) {
			err = -EIO;
			goto out_unlock_inode;
		}

		symlink = bh->b_data;
	}

	err = udf_pc_to_char(inode->i_sb, symlink, inode->i_size, p, PAGE_SIZE);
	brelse(bh);
	if (err)
		goto out_unlock_inode;

	up_read(&iinfo->i_data_sem);
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;

out_unlock_inode:
	up_read(&iinfo->i_data_sem);
	SetPageError(page);
out_unmap:
	kunmap(page);
	unlock_page(page);
	return err;
}

/*
 * symlinks can't do much...
 */
const struct address_space_operations udf_symlink_aops = {
	.readpage		= udf_symlink_filler,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/symlink.c */
/************************************************************/
/*
 * directory.c
 *
 * PURPOSE
 *	Directory related functions
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 */

// #include "udfdecl.h"
// #include "udf_i.h"

// #include <linux/fs.h>
// #include <linux/string.h>
// #include <linux/buffer_head.h>

struct fileIdentDesc *udf_fileident_read(struct inode *dir, loff_t *nf_pos,
					 struct udf_fileident_bh *fibh,
					 struct fileIdentDesc *cfi,
					 struct extent_position *epos,
					 struct kernel_lb_addr *eloc, uint32_t *elen,
					 sector_t *offset)
{
	struct fileIdentDesc *fi;
	int i, num, block;
	struct buffer_head *tmp, *bha[16];
	struct udf_inode_info *iinfo = UDF_I(dir);

	fibh->soffset = fibh->eoffset;

	if (iinfo->i_alloc_type == ICBTAG_FLAG_AD_IN_ICB) {
		fi = udf_get_fileident(iinfo->i_ext.i_data -
				       (iinfo->i_efe ?
					sizeof(struct extendedFileEntry) :
					sizeof(struct fileEntry)),
				       dir->i_sb->s_blocksize,
				       &(fibh->eoffset));
		if (!fi)
			return NULL;

		*nf_pos += fibh->eoffset - fibh->soffset;

		memcpy((uint8_t *)cfi, (uint8_t *)fi,
		       sizeof(struct fileIdentDesc));

		return fi;
	}

	if (fibh->eoffset == dir->i_sb->s_blocksize) {
		int lextoffset = epos->offset;
		unsigned char blocksize_bits = dir->i_sb->s_blocksize_bits;

		if (udf_next_aext(dir, epos, eloc, elen, 1) !=
		    (EXT_RECORDED_ALLOCATED >> 30))
			return NULL;

		block = udf_get_lb_pblock(dir->i_sb, eloc, *offset);

		(*offset)++;

		if ((*offset << blocksize_bits) >= *elen)
			*offset = 0;
		else
			epos->offset = lextoffset;

		brelse(fibh->sbh);
		fibh->sbh = fibh->ebh = udf_tread(dir->i_sb, block);
		if (!fibh->sbh)
			return NULL;
		fibh->soffset = fibh->eoffset = 0;

		if (!(*offset & ((16 >> (blocksize_bits - 9)) - 1))) {
			i = 16 >> (blocksize_bits - 9);
			if (i + *offset > (*elen >> blocksize_bits))
				i = (*elen >> blocksize_bits)-*offset;
			for (num = 0; i > 0; i--) {
				block = udf_get_lb_pblock(dir->i_sb, eloc,
							  *offset + i);
				tmp = udf_tgetblk(dir->i_sb, block);
				if (tmp && !buffer_uptodate(tmp) &&
						!buffer_locked(tmp))
					bha[num++] = tmp;
				else
					brelse(tmp);
			}
			if (num) {
				ll_rw_block(READA, num, bha);
				for (i = 0; i < num; i++)
					brelse(bha[i]);
			}
		}
	} else if (fibh->sbh != fibh->ebh) {
		brelse(fibh->sbh);
		fibh->sbh = fibh->ebh;
	}

	fi = udf_get_fileident(fibh->sbh->b_data, dir->i_sb->s_blocksize,
			       &(fibh->eoffset));

	if (!fi)
		return NULL;

	*nf_pos += fibh->eoffset - fibh->soffset;

	if (fibh->eoffset <= dir->i_sb->s_blocksize) {
		memcpy((uint8_t *)cfi, (uint8_t *)fi,
		       sizeof(struct fileIdentDesc));
	} else if (fibh->eoffset > dir->i_sb->s_blocksize) {
		int lextoffset = epos->offset;

		if (udf_next_aext(dir, epos, eloc, elen, 1) !=
		    (EXT_RECORDED_ALLOCATED >> 30))
			return NULL;

		block = udf_get_lb_pblock(dir->i_sb, eloc, *offset);

		(*offset)++;

		if ((*offset << dir->i_sb->s_blocksize_bits) >= *elen)
			*offset = 0;
		else
			epos->offset = lextoffset;

		fibh->soffset -= dir->i_sb->s_blocksize;
		fibh->eoffset -= dir->i_sb->s_blocksize;

		fibh->ebh = udf_tread(dir->i_sb, block);
		if (!fibh->ebh)
			return NULL;

		if (sizeof(struct fileIdentDesc) > -fibh->soffset) {
			int fi_len;

			memcpy((uint8_t *)cfi, (uint8_t *)fi, -fibh->soffset);
			memcpy((uint8_t *)cfi - fibh->soffset,
			       fibh->ebh->b_data,
			       sizeof(struct fileIdentDesc) + fibh->soffset);

			fi_len = (sizeof(struct fileIdentDesc) +
				  cfi->lengthFileIdent +
				  le16_to_cpu(cfi->lengthOfImpUse) + 3) & ~3;

			*nf_pos += fi_len - (fibh->eoffset - fibh->soffset);
			fibh->eoffset = fibh->soffset + fi_len;
		} else {
			memcpy((uint8_t *)cfi, (uint8_t *)fi,
			       sizeof(struct fileIdentDesc));
		}
	}
	return fi;
}

struct fileIdentDesc *udf_get_fileident(void *buffer, int bufsize, int *offset)
{
	struct fileIdentDesc *fi;
	int lengthThisIdent;
	uint8_t *ptr;
	int padlen;

	if ((!buffer) || (!offset)) {
		udf_debug("invalidparms, buffer=%p, offset=%p\n",
			  buffer, offset);
		return NULL;
	}

	ptr = buffer;

	if ((*offset > 0) && (*offset < bufsize))
		ptr += *offset;
	fi = (struct fileIdentDesc *)ptr;
	if (fi->descTag.tagIdent != cpu_to_le16(TAG_IDENT_FID)) {
		udf_debug("0x%x != TAG_IDENT_FID\n",
			  le16_to_cpu(fi->descTag.tagIdent));
		udf_debug("offset: %u sizeof: %lu bufsize: %u\n",
			  *offset, (unsigned long)sizeof(struct fileIdentDesc),
			  bufsize);
		return NULL;
	}
	if ((*offset + sizeof(struct fileIdentDesc)) > bufsize)
		lengthThisIdent = sizeof(struct fileIdentDesc);
	else
		lengthThisIdent = sizeof(struct fileIdentDesc) +
			fi->lengthFileIdent + le16_to_cpu(fi->lengthOfImpUse);

	/* we need to figure padding, too! */
	padlen = lengthThisIdent % UDF_NAME_PAD;
	if (padlen)
		lengthThisIdent += (UDF_NAME_PAD - padlen);
	*offset = *offset + lengthThisIdent;

	return fi;
}

struct short_ad *udf_get_fileshortad(uint8_t *ptr, int maxoffset, uint32_t *offset,
			      int inc)
{
	struct short_ad *sa;

	if ((!ptr) || (!offset)) {
		pr_err("%s: invalidparms\n", __func__);
		return NULL;
	}

	if ((*offset + sizeof(struct short_ad)) > maxoffset)
		return NULL;
	else {
		sa = (struct short_ad *)ptr;
		if (sa->extLength == 0)
			return NULL;
	}

	if (inc)
		*offset += sizeof(struct short_ad);
	return sa;
}

struct long_ad *udf_get_filelongad(uint8_t *ptr, int maxoffset, uint32_t *offset, int inc)
{
	struct long_ad *la;

	if ((!ptr) || (!offset)) {
		pr_err("%s: invalidparms\n", __func__);
		return NULL;
	}

	if ((*offset + sizeof(struct long_ad)) > maxoffset)
		return NULL;
	else {
		la = (struct long_ad *)ptr;
		if (la->extLength == 0)
			return NULL;
	}

	if (inc)
		*offset += sizeof(struct long_ad);
	return la;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/directory.c */
/************************************************************/
/*
 * misc.c
 *
 * PURPOSE
 *	Miscellaneous routines for the OSTA-UDF(tm) filesystem.
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 *
 *  (C) 1998 Dave Boynton
 *  (C) 1998-2004 Ben Fennema
 *  (C) 1999-2000 Stelias Computing Inc
 *
 * HISTORY
 *
 *  04/19/99 blf  partial support for reading/writing specific EA's
 */

// #include "udfdecl.h"

// #include <linux/fs.h>
// #include <linux/string.h>
// #include <linux/buffer_head.h>
// #include <linux/crc-itu-t.h>

// #include "udf_i.h"
// #include "udf_sb.h"

struct buffer_head *udf_tgetblk(struct super_block *sb, int block)
{
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_VARCONV))
		return sb_getblk(sb, udf_fixed_to_variable(block));
	else
		return sb_getblk(sb, block);
}

struct buffer_head *udf_tread(struct super_block *sb, int block)
{
	if (UDF_QUERY_FLAG(sb, UDF_FLAG_VARCONV))
		return sb_bread(sb, udf_fixed_to_variable(block));
	else
		return sb_bread(sb, block);
}

struct genericFormat *udf_add_extendedattr(struct inode *inode, uint32_t size,
					   uint32_t type, uint8_t loc)
{
	uint8_t *ea = NULL, *ad = NULL;
	int offset;
	uint16_t crclen;
	struct udf_inode_info *iinfo = UDF_I(inode);

	ea = iinfo->i_ext.i_data;
	if (iinfo->i_lenEAttr) {
		ad = iinfo->i_ext.i_data + iinfo->i_lenEAttr;
	} else {
		ad = ea;
		size += sizeof(struct extendedAttrHeaderDesc);
	}

	offset = inode->i_sb->s_blocksize - udf_file_entry_alloc_offset(inode) -
		iinfo->i_lenAlloc;

	/* TODO - Check for FreeEASpace */

	if (loc & 0x01 && offset >= size) {
		struct extendedAttrHeaderDesc *eahd;
		eahd = (struct extendedAttrHeaderDesc *)ea;

		if (iinfo->i_lenAlloc)
			memmove(&ad[size], ad, iinfo->i_lenAlloc);

		if (iinfo->i_lenEAttr) {
			/* check checksum/crc */
			if (eahd->descTag.tagIdent !=
					cpu_to_le16(TAG_IDENT_EAHD) ||
			    le32_to_cpu(eahd->descTag.tagLocation) !=
					iinfo->i_location.logicalBlockNum)
				return NULL;
		} else {
			struct udf_sb_info *sbi = UDF_SB(inode->i_sb);

			size -= sizeof(struct extendedAttrHeaderDesc);
			iinfo->i_lenEAttr +=
				sizeof(struct extendedAttrHeaderDesc);
			eahd->descTag.tagIdent = cpu_to_le16(TAG_IDENT_EAHD);
			if (sbi->s_udfrev >= 0x0200)
				eahd->descTag.descVersion = cpu_to_le16(3);
			else
				eahd->descTag.descVersion = cpu_to_le16(2);
			eahd->descTag.tagSerialNum =
					cpu_to_le16(sbi->s_serial_number);
			eahd->descTag.tagLocation = cpu_to_le32(
					iinfo->i_location.logicalBlockNum);
			eahd->impAttrLocation = cpu_to_le32(0xFFFFFFFF);
			eahd->appAttrLocation = cpu_to_le32(0xFFFFFFFF);
		}

		offset = iinfo->i_lenEAttr;
		if (type < 2048) {
			if (le32_to_cpu(eahd->appAttrLocation) <
					iinfo->i_lenEAttr) {
				uint32_t aal =
					le32_to_cpu(eahd->appAttrLocation);
				memmove(&ea[offset - aal + size],
					&ea[aal], offset - aal);
				offset -= aal;
				eahd->appAttrLocation =
						cpu_to_le32(aal + size);
			}
			if (le32_to_cpu(eahd->impAttrLocation) <
					iinfo->i_lenEAttr) {
				uint32_t ial =
					le32_to_cpu(eahd->impAttrLocation);
				memmove(&ea[offset - ial + size],
					&ea[ial], offset - ial);
				offset -= ial;
				eahd->impAttrLocation =
						cpu_to_le32(ial + size);
			}
		} else if (type < 65536) {
			if (le32_to_cpu(eahd->appAttrLocation) <
					iinfo->i_lenEAttr) {
				uint32_t aal =
					le32_to_cpu(eahd->appAttrLocation);
				memmove(&ea[offset - aal + size],
					&ea[aal], offset - aal);
				offset -= aal;
				eahd->appAttrLocation =
						cpu_to_le32(aal + size);
			}
		}
		/* rewrite CRC + checksum of eahd */
		crclen = sizeof(struct extendedAttrHeaderDesc) - sizeof(struct tag);
		eahd->descTag.descCRCLength = cpu_to_le16(crclen);
		eahd->descTag.descCRC = cpu_to_le16(crc_itu_t(0, (char *)eahd +
						sizeof(struct tag), crclen));
		eahd->descTag.tagChecksum = udf_tag_checksum(&eahd->descTag);
		iinfo->i_lenEAttr += size;
		return (struct genericFormat *)&ea[offset];
	}
	if (loc & 0x02)
		;

	return NULL;
}

struct genericFormat *udf_get_extendedattr(struct inode *inode, uint32_t type,
					   uint8_t subtype)
{
	struct genericFormat *gaf;
	uint8_t *ea = NULL;
	uint32_t offset;
	struct udf_inode_info *iinfo = UDF_I(inode);

	ea = iinfo->i_ext.i_data;

	if (iinfo->i_lenEAttr) {
		struct extendedAttrHeaderDesc *eahd;
		eahd = (struct extendedAttrHeaderDesc *)ea;

		/* check checksum/crc */
		if (eahd->descTag.tagIdent !=
				cpu_to_le16(TAG_IDENT_EAHD) ||
		    le32_to_cpu(eahd->descTag.tagLocation) !=
				iinfo->i_location.logicalBlockNum)
			return NULL;

		if (type < 2048)
			offset = sizeof(struct extendedAttrHeaderDesc);
		else if (type < 65536)
			offset = le32_to_cpu(eahd->impAttrLocation);
		else
			offset = le32_to_cpu(eahd->appAttrLocation);

		while (offset < iinfo->i_lenEAttr) {
			gaf = (struct genericFormat *)&ea[offset];
			if (le32_to_cpu(gaf->attrType) == type &&
					gaf->attrSubtype == subtype)
				return gaf;
			else
				offset += le32_to_cpu(gaf->attrLength);
		}
	}

	return NULL;
}

/*
 * udf_read_tagged
 *
 * PURPOSE
 *	Read the first block of a tagged descriptor.
 *
 * HISTORY
 *	July 1, 1997 - Andrew E. Mileski
 *	Written, tested, and released.
 */
struct buffer_head *udf_read_tagged(struct super_block *sb, uint32_t block,
				    uint32_t location, uint16_t *ident)
{
	struct tag *tag_p;
	struct buffer_head *bh = NULL;
	u8 checksum;

	/* Read the block */
	if (block == 0xFFFFFFFF)
		return NULL;

	bh = udf_tread(sb, block);
	if (!bh) {
		udf_err(sb, "read failed, block=%u, location=%d\n",
			block, location);
		return NULL;
	}

	tag_p = (struct tag *)(bh->b_data);

	*ident = le16_to_cpu(tag_p->tagIdent);

	if (location != le32_to_cpu(tag_p->tagLocation)) {
		udf_debug("location mismatch block %u, tag %u != %u\n",
			  block, le32_to_cpu(tag_p->tagLocation), location);
		goto error_out;
	}

	/* Verify the tag checksum */
	checksum = udf_tag_checksum(tag_p);
	if (checksum != tag_p->tagChecksum) {
		udf_err(sb, "tag checksum failed, block %u: 0x%02x != 0x%02x\n",
			block, checksum, tag_p->tagChecksum);
		goto error_out;
	}

	/* Verify the tag version */
	if (tag_p->descVersion != cpu_to_le16(0x0002U) &&
	    tag_p->descVersion != cpu_to_le16(0x0003U)) {
		udf_err(sb, "tag version 0x%04x != 0x0002 || 0x0003, block %u\n",
			le16_to_cpu(tag_p->descVersion), block);
		goto error_out;
	}

	/* Verify the descriptor CRC */
	if (le16_to_cpu(tag_p->descCRCLength) + sizeof(struct tag) > sb->s_blocksize ||
	    le16_to_cpu(tag_p->descCRC) == crc_itu_t(0,
					bh->b_data + sizeof(struct tag),
					le16_to_cpu(tag_p->descCRCLength)))
		return bh;

	udf_debug("Crc failure block %d: crc = %d, crclen = %d\n", block,
		  le16_to_cpu(tag_p->descCRC),
		  le16_to_cpu(tag_p->descCRCLength));
error_out:
	brelse(bh);
	return NULL;
}

struct buffer_head *udf_read_ptagged(struct super_block *sb,
				     struct kernel_lb_addr *loc,
				     uint32_t offset, uint16_t *ident)
{
	return udf_read_tagged(sb, udf_get_lb_pblock(sb, loc, offset),
			       loc->logicalBlockNum + offset, ident);
}

void udf_update_tag(char *data, int length)
{
	struct tag *tptr = (struct tag *)data;
	length -= sizeof(struct tag);

	tptr->descCRCLength = cpu_to_le16(length);
	tptr->descCRC = cpu_to_le16(crc_itu_t(0, data + sizeof(struct tag), length));
	tptr->tagChecksum = udf_tag_checksum(tptr);
}

void udf_new_tag(char *data, uint16_t ident, uint16_t version, uint16_t snum,
		 uint32_t loc, int length)
{
	struct tag *tptr = (struct tag *)data;
	tptr->tagIdent = cpu_to_le16(ident);
	tptr->descVersion = cpu_to_le16(version);
	tptr->tagSerialNum = cpu_to_le16(snum);
	tptr->tagLocation = cpu_to_le32(loc);
	udf_update_tag(data, length);
}

u8 udf_tag_checksum(const struct tag *t)
{
	u8 *data = (u8 *)t;
	u8 checksum = 0;
	int i;
	for (i = 0; i < sizeof(struct tag); ++i)
		if (i != 4) /* position of checksum */
			checksum += data[i];
	return checksum;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/misc.c */
/************************************************************/
/* Copyright (C) 1993, 1994, 1995, 1996, 1997 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Paul Eggert (eggert@twinsun.com).

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/*
 * dgb 10/02/98: ripped this from glibc source to help convert timestamps
 *               to unix time
 *     10/04/98: added new table-based lookup after seeing how ugly
 *               the gnu code is
 * blf 09/27/99: ripped out all the old code and inserted new table from
 *		 John Brockmeyer (without leap second corrections)
 *		 rewrote udf_stamp_to_time and fixed timezone accounting in
 *		 udf_time_to_stamp.
 */

/*
 * We don't take into account leap seconds. This may be correct or incorrect.
 * For more NIST information (especially dealing with leap seconds), see:
 * http://www.boulder.nist.gov/timefreq/pubs/bulletin/leapsecond.htm
 */

// #include "udfdecl.h"

#include <linux/types.h>
// #include <linux/kernel.h>
#include "../../inc/__fss.h"

#define EPOCH_YEAR 1970

#ifndef __isleap
/* Nonzero if YEAR is a leap year (every 4 years,
   except every 100th isn't, and every 400th is).  */
#define	__isleap(year)	\
  ((year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0))
#endif

/* How many days come before each month (0-12).  */
static const unsigned short int __mon_yday[2][13] = {
	/* Normal years.  */
	{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365},
	/* Leap years.  */
	{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335, 366}
};

#define MAX_YEAR_SECONDS	69
#define SPD			0x15180	/*3600*24 */
#define SPY(y, l, s)		(SPD * (365 * y + l) + s)

static time_t year_seconds[MAX_YEAR_SECONDS] = {
/*1970*/ SPY(0,   0, 0), SPY(1,   0, 0), SPY(2,   0, 0), SPY(3,   1, 0),
/*1974*/ SPY(4,   1, 0), SPY(5,   1, 0), SPY(6,   1, 0), SPY(7,   2, 0),
/*1978*/ SPY(8,   2, 0), SPY(9,   2, 0), SPY(10,  2, 0), SPY(11,  3, 0),
/*1982*/ SPY(12,  3, 0), SPY(13,  3, 0), SPY(14,  3, 0), SPY(15,  4, 0),
/*1986*/ SPY(16,  4, 0), SPY(17,  4, 0), SPY(18,  4, 0), SPY(19,  5, 0),
/*1990*/ SPY(20,  5, 0), SPY(21,  5, 0), SPY(22,  5, 0), SPY(23,  6, 0),
/*1994*/ SPY(24,  6, 0), SPY(25,  6, 0), SPY(26,  6, 0), SPY(27,  7, 0),
/*1998*/ SPY(28,  7, 0), SPY(29,  7, 0), SPY(30,  7, 0), SPY(31,  8, 0),
/*2002*/ SPY(32,  8, 0), SPY(33,  8, 0), SPY(34,  8, 0), SPY(35,  9, 0),
/*2006*/ SPY(36,  9, 0), SPY(37,  9, 0), SPY(38,  9, 0), SPY(39, 10, 0),
/*2010*/ SPY(40, 10, 0), SPY(41, 10, 0), SPY(42, 10, 0), SPY(43, 11, 0),
/*2014*/ SPY(44, 11, 0), SPY(45, 11, 0), SPY(46, 11, 0), SPY(47, 12, 0),
/*2018*/ SPY(48, 12, 0), SPY(49, 12, 0), SPY(50, 12, 0), SPY(51, 13, 0),
/*2022*/ SPY(52, 13, 0), SPY(53, 13, 0), SPY(54, 13, 0), SPY(55, 14, 0),
/*2026*/ SPY(56, 14, 0), SPY(57, 14, 0), SPY(58, 14, 0), SPY(59, 15, 0),
/*2030*/ SPY(60, 15, 0), SPY(61, 15, 0), SPY(62, 15, 0), SPY(63, 16, 0),
/*2034*/ SPY(64, 16, 0), SPY(65, 16, 0), SPY(66, 16, 0), SPY(67, 17, 0),
/*2038*/ SPY(68, 17, 0)
};

#define SECS_PER_HOUR	(60 * 60)
#define SECS_PER_DAY	(SECS_PER_HOUR * 24)

struct timespec *
udf_disk_stamp_to_time(struct timespec *dest, struct timestamp src)
{
	int yday;
	u16 typeAndTimezone = le16_to_cpu(src.typeAndTimezone);
	u16 year = le16_to_cpu(src.year);
	uint8_t type = typeAndTimezone >> 12;
	int16_t offset;

	if (type == 1) {
		offset = typeAndTimezone << 4;
		/* sign extent offset */
		offset = (offset >> 4);
		if (offset == -2047) /* unspecified offset */
			offset = 0;
	} else
		offset = 0;

	if ((year < EPOCH_YEAR) ||
	    (year >= EPOCH_YEAR + MAX_YEAR_SECONDS)) {
		return NULL;
	}
	dest->tv_sec = year_seconds[year - EPOCH_YEAR];
	dest->tv_sec -= offset * 60;

	yday = ((__mon_yday[__isleap(year)][src.month - 1]) + src.day - 1);
	dest->tv_sec += (((yday * 24) + src.hour) * 60 + src.minute) * 60 + src.second;
	dest->tv_nsec = 1000 * (src.centiseconds * 10000 +
			src.hundredsOfMicroseconds * 100 + src.microseconds);
	return dest;
}

struct timestamp *
udf_time_to_disk_stamp(struct timestamp *dest, struct timespec ts)
{
	long int days, rem, y;
	const unsigned short int *ip;
	int16_t offset;

	offset = -sys_tz.tz_minuteswest;

	if (!dest)
		return NULL;

	dest->typeAndTimezone = cpu_to_le16(0x1000 | (offset & 0x0FFF));

	ts.tv_sec += offset * 60;
	days = ts.tv_sec / SECS_PER_DAY;
	rem = ts.tv_sec % SECS_PER_DAY;
	dest->hour = rem / SECS_PER_HOUR;
	rem %= SECS_PER_HOUR;
	dest->minute = rem / 60;
	dest->second = rem % 60;
	y = 1970;

#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))

	while (days < 0 || days >= (__isleap(y) ? 366 : 365)) {
		long int yg = y + days / 365 - (days % 365 < 0);

		/* Adjust DAYS and Y to match the guessed year.  */
		days -= ((yg - y) * 365
			 + LEAPS_THRU_END_OF(yg - 1)
			 - LEAPS_THRU_END_OF(y - 1));
		y = yg;
	}
	dest->year = cpu_to_le16(y);
	ip = __mon_yday[__isleap(y)];
	for (y = 11; days < (long int)ip[y]; --y)
		continue;
	days -= ip[y];
	dest->month = y + 1;
	dest->day = days + 1;

	dest->centiseconds = ts.tv_nsec / 10000000;
	dest->hundredsOfMicroseconds = (ts.tv_nsec / 1000 -
					dest->centiseconds * 10000) / 100;
	dest->microseconds = (ts.tv_nsec / 1000 - dest->centiseconds * 10000 -
			      dest->hundredsOfMicroseconds * 100);
	return dest;
}

/* EOF */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/udftime.c */
/************************************************************/
/*
 * unicode.c
 *
 * PURPOSE
 *	Routines for converting between UTF-8 and OSTA Compressed Unicode.
 *      Also handles filename mangling
 *
 * DESCRIPTION
 *	OSTA Compressed Unicode is explained in the OSTA UDF specification.
 *		http://www.osta.org/
 *	UTF-8 is explained in the IETF RFC XXXX.
 *		ftp://ftp.internic.net/rfc/rfcxxxx.txt
 *
 * COPYRIGHT
 *	This file is distributed under the terms of the GNU General Public
 *	License (GPL). Copies of the GPL can be obtained from:
 *		ftp://prep.ai.mit.edu/pub/gnu/GPL
 *	Each contributing author retains all rights to their own work.
 */

// #include "udfdecl.h"

// #include <linux/kernel.h>
// #include <linux/string.h>	/* for memset */
// #include <linux/nls.h>
// #include <linux/crc-itu-t.h>
// #include <linux/slab.h>

// #include "udf_sb.h"

static int udf_translate_to_linux(uint8_t *, int, uint8_t *, int, uint8_t *,
				  int);

static int udf_char_to_ustr(struct ustr *dest, const uint8_t *src, int strlen)
{
	if ((!dest) || (!src) || (!strlen) || (strlen > UDF_NAME_LEN - 2))
		return 0;

	memset(dest, 0, sizeof(struct ustr));
	memcpy(dest->u_name, src, strlen);
	dest->u_cmpID = 0x08;
	dest->u_len = strlen;

	return strlen;
}

/*
 * udf_build_ustr
 */
int udf_build_ustr(struct ustr *dest, dstring *ptr, int size)
{
	int usesize;

	if (!dest || !ptr || !size)
		return -1;
	BUG_ON(size < 2);

	usesize = min_t(size_t, ptr[size - 1], sizeof(dest->u_name));
	usesize = min(usesize, size - 2);
	dest->u_cmpID = ptr[0];
	dest->u_len = usesize;
	memcpy(dest->u_name, ptr + 1, usesize);
	memset(dest->u_name + usesize, 0, sizeof(dest->u_name) - usesize);

	return 0;
}

/*
 * udf_build_ustr_exact
 */
static int udf_build_ustr_exact(struct ustr *dest, dstring *ptr, int exactsize)
{
	if ((!dest) || (!ptr) || (!exactsize))
		return -1;

	memset(dest, 0, sizeof(struct ustr));
	dest->u_cmpID = ptr[0];
	dest->u_len = exactsize - 1;
	memcpy(dest->u_name, ptr + 1, exactsize - 1);

	return 0;
}

/*
 * udf_ocu_to_utf8
 *
 * PURPOSE
 *	Convert OSTA Compressed Unicode to the UTF-8 equivalent.
 *
 * PRE-CONDITIONS
 *	utf			Pointer to UTF-8 output buffer.
 *	ocu			Pointer to OSTA Compressed Unicode input buffer
 *				of size UDF_NAME_LEN bytes.
 * 				both of type "struct ustr *"
 *
 * POST-CONDITIONS
 *	<return>		Zero on success.
 *
 * HISTORY
 *	November 12, 1997 - Andrew E. Mileski
 *	Written, tested, and released.
 */
int udf_CS0toUTF8(struct ustr *utf_o, const struct ustr *ocu_i)
{
	const uint8_t *ocu;
	uint8_t cmp_id, ocu_len;
	int i;

	ocu_len = ocu_i->u_len;
	if (ocu_len == 0) {
		memset(utf_o, 0, sizeof(struct ustr));
		return 0;
	}

	cmp_id = ocu_i->u_cmpID;
	if (cmp_id != 8 && cmp_id != 16) {
		memset(utf_o, 0, sizeof(struct ustr));
		pr_err("unknown compression code (%d) stri=%s\n",
		       cmp_id, ocu_i->u_name);
		return 0;
	}

	ocu = ocu_i->u_name;
	utf_o->u_len = 0;
	for (i = 0; (i < ocu_len) && (utf_o->u_len <= (UDF_NAME_LEN - 3));) {

		/* Expand OSTA compressed Unicode to Unicode */
		uint32_t c = ocu[i++];
		if (cmp_id == 16)
			c = (c << 8) | ocu[i++];

		/* Compress Unicode to UTF-8 */
		if (c < 0x80U)
			utf_o->u_name[utf_o->u_len++] = (uint8_t)c;
		else if (c < 0x800U) {
			utf_o->u_name[utf_o->u_len++] =
						(uint8_t)(0xc0 | (c >> 6));
			utf_o->u_name[utf_o->u_len++] =
						(uint8_t)(0x80 | (c & 0x3f));
		} else {
			utf_o->u_name[utf_o->u_len++] =
						(uint8_t)(0xe0 | (c >> 12));
			utf_o->u_name[utf_o->u_len++] =
						(uint8_t)(0x80 |
							  ((c >> 6) & 0x3f));
			utf_o->u_name[utf_o->u_len++] =
						(uint8_t)(0x80 | (c & 0x3f));
		}
	}
	utf_o->u_cmpID = 8;

	return utf_o->u_len;
}

/*
 *
 * udf_utf8_to_ocu
 *
 * PURPOSE
 *	Convert UTF-8 to the OSTA Compressed Unicode equivalent.
 *
 * DESCRIPTION
 *	This routine is only called by udf_lookup().
 *
 * PRE-CONDITIONS
 *	ocu			Pointer to OSTA Compressed Unicode output
 *				buffer of size UDF_NAME_LEN bytes.
 *	utf			Pointer to UTF-8 input buffer.
 *	utf_len			Length of UTF-8 input buffer in bytes.
 *
 * POST-CONDITIONS
 *	<return>		Zero on success.
 *
 * HISTORY
 *	November 12, 1997 - Andrew E. Mileski
 *	Written, tested, and released.
 */
static int udf_UTF8toCS0(dstring *ocu, struct ustr *utf, int length)
{
	unsigned c, i, max_val, utf_char;
	int utf_cnt, u_len;

	memset(ocu, 0, sizeof(dstring) * length);
	ocu[0] = 8;
	max_val = 0xffU;

try_again:
	u_len = 0U;
	utf_char = 0U;
	utf_cnt = 0U;
	for (i = 0U; i < utf->u_len; i++) {
		c = (uint8_t)utf->u_name[i];

		/* Complete a multi-byte UTF-8 character */
		if (utf_cnt) {
			utf_char = (utf_char << 6) | (c & 0x3fU);
			if (--utf_cnt)
				continue;
		} else {
			/* Check for a multi-byte UTF-8 character */
			if (c & 0x80U) {
				/* Start a multi-byte UTF-8 character */
				if ((c & 0xe0U) == 0xc0U) {
					utf_char = c & 0x1fU;
					utf_cnt = 1;
				} else if ((c & 0xf0U) == 0xe0U) {
					utf_char = c & 0x0fU;
					utf_cnt = 2;
				} else if ((c & 0xf8U) == 0xf0U) {
					utf_char = c & 0x07U;
					utf_cnt = 3;
				} else if ((c & 0xfcU) == 0xf8U) {
					utf_char = c & 0x03U;
					utf_cnt = 4;
				} else if ((c & 0xfeU) == 0xfcU) {
					utf_char = c & 0x01U;
					utf_cnt = 5;
				} else {
					goto error_out;
				}
				continue;
			} else {
				/* Single byte UTF-8 character (most common) */
				utf_char = c;
			}
		}

		/* Choose no compression if necessary */
		if (utf_char > max_val) {
			if (max_val == 0xffU) {
				max_val = 0xffffU;
				ocu[0] = (uint8_t)0x10U;
				goto try_again;
			}
			goto error_out;
		}

		if (max_val == 0xffffU)
			ocu[++u_len] = (uint8_t)(utf_char >> 8);
		ocu[++u_len] = (uint8_t)(utf_char & 0xffU);
	}

	if (utf_cnt) {
error_out:
		ocu[++u_len] = '?';
		printk(KERN_DEBUG pr_fmt("bad UTF-8 character\n"));
	}

	ocu[length - 1] = (uint8_t)u_len + 1;

	return u_len + 1;
}

static int udf_CS0toNLS(struct nls_table *nls, struct ustr *utf_o,
			const struct ustr *ocu_i)
{
	const uint8_t *ocu;
	uint8_t cmp_id, ocu_len;
	int i, len;


	ocu_len = ocu_i->u_len;
	if (ocu_len == 0) {
		memset(utf_o, 0, sizeof(struct ustr));
		return 0;
	}

	cmp_id = ocu_i->u_cmpID;
	if (cmp_id != 8 && cmp_id != 16) {
		memset(utf_o, 0, sizeof(struct ustr));
		pr_err("unknown compression code (%d) stri=%s\n",
		       cmp_id, ocu_i->u_name);
		return 0;
	}

	ocu = ocu_i->u_name;
	utf_o->u_len = 0;
	for (i = 0; (i < ocu_len) && (utf_o->u_len <= (UDF_NAME_LEN - 3));) {
		/* Expand OSTA compressed Unicode to Unicode */
		uint32_t c = ocu[i++];
		if (cmp_id == 16)
			c = (c << 8) | ocu[i++];

		len = nls->uni2char(c, &utf_o->u_name[utf_o->u_len],
				    UDF_NAME_LEN - utf_o->u_len);
		/* Valid character? */
		if (len >= 0)
			utf_o->u_len += len;
		else
			utf_o->u_name[utf_o->u_len++] = '?';
	}
	utf_o->u_cmpID = 8;

	return utf_o->u_len;
}

static int udf_NLStoCS0(struct nls_table *nls, dstring *ocu, struct ustr *uni,
			int length)
{
	int len;
	unsigned i, max_val;
	uint16_t uni_char;
	int u_len;

	memset(ocu, 0, sizeof(dstring) * length);
	ocu[0] = 8;
	max_val = 0xffU;

try_again:
	u_len = 0U;
	for (i = 0U; i < uni->u_len; i++) {
		len = nls->char2uni(&uni->u_name[i], uni->u_len - i, &uni_char);
		if (!len)
			continue;
		/* Invalid character, deal with it */
		if (len < 0) {
			len = 1;
			uni_char = '?';
		}

		if (uni_char > max_val) {
			max_val = 0xffffU;
			ocu[0] = (uint8_t)0x10U;
			goto try_again;
		}

		if (max_val == 0xffffU)
			ocu[++u_len] = (uint8_t)(uni_char >> 8);
		ocu[++u_len] = (uint8_t)(uni_char & 0xffU);
		i += len - 1;
	}

	ocu[length - 1] = (uint8_t)u_len + 1;
	return u_len + 1;
}

int udf_get_filename(struct super_block *sb, uint8_t *sname, int slen,
		     uint8_t *dname, int dlen)
{
	struct ustr *filename, *unifilename;
	int len = 0;

	filename = kmalloc(sizeof(struct ustr), GFP_NOFS);
	if (!filename)
		return 0;

	unifilename = kmalloc(sizeof(struct ustr), GFP_NOFS);
	if (!unifilename)
		goto out1;

	if (udf_build_ustr_exact(unifilename, sname, slen))
		goto out2;

	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UTF8)) {
		if (!udf_CS0toUTF8(filename, unifilename)) {
			udf_debug("Failed in udf_get_filename: sname = %s\n",
				  sname);
			goto out2;
		}
	} else if (UDF_QUERY_FLAG(sb, UDF_FLAG_NLS_MAP)) {
		if (!udf_CS0toNLS(UDF_SB(sb)->s_nls_map, filename,
				  unifilename)) {
			udf_debug("Failed in udf_get_filename: sname = %s\n",
				  sname);
			goto out2;
		}
	} else
		goto out2;

	len = udf_translate_to_linux(dname, dlen,
				     filename->u_name, filename->u_len,
				     unifilename->u_name, unifilename->u_len);
out2:
	kfree(unifilename);
out1:
	kfree(filename);
	return len;
}

int udf_put_filename(struct super_block *sb, const uint8_t *sname,
		     uint8_t *dname, int flen)
{
	struct ustr unifilename;
	int namelen;

	if (!udf_char_to_ustr(&unifilename, sname, flen))
		return 0;

	if (UDF_QUERY_FLAG(sb, UDF_FLAG_UTF8)) {
		namelen = udf_UTF8toCS0(dname, &unifilename, UDF_NAME_LEN);
		if (!namelen)
			return 0;
	} else if (UDF_QUERY_FLAG(sb, UDF_FLAG_NLS_MAP)) {
		namelen = udf_NLStoCS0(UDF_SB(sb)->s_nls_map, dname,
					&unifilename, UDF_NAME_LEN);
		if (!namelen)
			return 0;
	} else
		return 0;

	return namelen;
}

#define ILLEGAL_CHAR_MARK	'_'
#define EXT_MARK		'.'
#define CRC_MARK		'#'
#define EXT_SIZE 		5
/* Number of chars we need to store generated CRC to make filename unique */
#define CRC_LEN			5

static int udf_translate_to_linux(uint8_t *newName, int newLen,
				  uint8_t *udfName, int udfLen,
				  uint8_t *fidName, int fidNameLen)
{
	int index, newIndex = 0, needsCRC = 0;
	int extIndex = 0, newExtIndex = 0, hasExt = 0;
	unsigned short valueCRC;
	uint8_t curr;

	if (udfName[0] == '.' &&
	    (udfLen == 1 || (udfLen == 2 && udfName[1] == '.'))) {
		needsCRC = 1;
		newIndex = udfLen;
		memcpy(newName, udfName, udfLen);
	} else {
		for (index = 0; index < udfLen; index++) {
			curr = udfName[index];
			if (curr == '/' || curr == 0) {
				needsCRC = 1;
				curr = ILLEGAL_CHAR_MARK;
				while (index + 1 < udfLen &&
						(udfName[index + 1] == '/' ||
						 udfName[index + 1] == 0))
					index++;
			}
			if (curr == EXT_MARK &&
					(udfLen - index - 1) <= EXT_SIZE) {
				if (udfLen == index + 1)
					hasExt = 0;
				else {
					hasExt = 1;
					extIndex = index;
					newExtIndex = newIndex;
				}
			}
			if (newIndex < newLen)
				newName[newIndex++] = curr;
			else
				needsCRC = 1;
		}
	}
	if (needsCRC) {
		uint8_t ext[EXT_SIZE];
		int localExtIndex = 0;

		if (hasExt) {
			int maxFilenameLen;
			for (index = 0;
			     index < EXT_SIZE && extIndex + index + 1 < udfLen;
			     index++) {
				curr = udfName[extIndex + index + 1];

				if (curr == '/' || curr == 0) {
					needsCRC = 1;
					curr = ILLEGAL_CHAR_MARK;
					while (extIndex + index + 2 < udfLen &&
					      (index + 1 < EXT_SIZE &&
						(udfName[extIndex + index + 2] == '/' ||
						 udfName[extIndex + index + 2] == 0)))
						index++;
				}
				ext[localExtIndex++] = curr;
			}
			maxFilenameLen = newLen - CRC_LEN - localExtIndex;
			if (newIndex > maxFilenameLen)
				newIndex = maxFilenameLen;
			else
				newIndex = newExtIndex;
		} else if (newIndex > newLen - CRC_LEN)
			newIndex = newLen - CRC_LEN;
		newName[newIndex++] = CRC_MARK;
		valueCRC = crc_itu_t(0, fidName, fidNameLen);
		newName[newIndex++] = hex_asc_upper_hi(valueCRC >> 8);
		newName[newIndex++] = hex_asc_upper_lo(valueCRC >> 8);
		newName[newIndex++] = hex_asc_upper_hi(valueCRC);
		newName[newIndex++] = hex_asc_upper_lo(valueCRC);

		if (hasExt) {
			newName[newIndex++] = EXT_MARK;
			for (index = 0; index < localExtIndex; index++)
				newName[newIndex++] = ext[index];
		}
	}

	return newIndex;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/udf/unicode.c */
/************************************************************/
