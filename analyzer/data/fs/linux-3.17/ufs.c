/*
 *  linux/fs/ufs/balloc.c
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 * UFS2 write support Evgeniy Dushistov <dushistov@mail.ru>, 2007
 */

#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/capability.h>
#include <linux/bitops.h>
#include <asm/byteorder.h>

#include "ufs_fs.h"
#include "ufs.h"
#include "swab.h"
#include "util.h"

#define INVBLOCK ((u64)-1L)

static u64 ufs_add_fragments(struct inode *, u64, unsigned, unsigned);
static u64 ufs_alloc_fragments(struct inode *, unsigned, u64, unsigned, int *);
static u64 ufs_alloccg_block(struct inode *, struct ufs_cg_private_info *, u64, int *);
static u64 ufs_bitmap_search (struct super_block *, struct ufs_cg_private_info *, u64, unsigned);
static unsigned char ufs_fragtable_8fpb[], ufs_fragtable_other[];
static void ufs_clusteracct(struct super_block *, struct ufs_cg_private_info *, unsigned, int);

/*
 * Free 'count' fragments from fragment number 'fragment'
 */
void ufs_free_fragments(struct inode *inode, u64 fragment, unsigned count)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	struct ufs_cylinder_group * ucg;
	unsigned cgno, bit, end_bit, bbase, blkmap, i;
	u64 blkno;

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;

	UFSD("ENTER, fragment %llu, count %u\n",
	     (unsigned long long)fragment, count);

	if (ufs_fragnum(fragment) + count > uspi->s_fpg)
		ufs_error (sb, "ufs_free_fragments", "internal error");

	lock_ufs(sb);

	cgno = ufs_dtog(uspi, fragment);
	bit = ufs_dtogd(uspi, fragment);
	if (cgno >= uspi->s_ncg) {
		ufs_panic (sb, "ufs_free_fragments", "freeing blocks are outside device");
		goto failed;
	}

	ucpi = ufs_load_cylinder (sb, cgno);
	if (!ucpi)
		goto failed;
	ucg = ubh_get_ucg (UCPI_UBH(ucpi));
	if (!ufs_cg_chkmagic(sb, ucg)) {
		ufs_panic (sb, "ufs_free_fragments", "internal error, bad magic number on cg %u", cgno);
		goto failed;
	}

	end_bit = bit + count;
	bbase = ufs_blknum (bit);
	blkmap = ubh_blkmap (UCPI_UBH(ucpi), ucpi->c_freeoff, bbase);
	ufs_fragacct (sb, blkmap, ucg->cg_frsum, -1);
	for (i = bit; i < end_bit; i++) {
		if (ubh_isclr (UCPI_UBH(ucpi), ucpi->c_freeoff, i))
			ubh_setbit (UCPI_UBH(ucpi), ucpi->c_freeoff, i);
		else
			ufs_error (sb, "ufs_free_fragments",
				   "bit already cleared for fragment %u", i);
	}

	fs32_add(sb, &ucg->cg_cs.cs_nffree, count);
	uspi->cs_total.cs_nffree += count;
	fs32_add(sb, &UFS_SB(sb)->fs_cs(cgno).cs_nffree, count);
	blkmap = ubh_blkmap (UCPI_UBH(ucpi), ucpi->c_freeoff, bbase);
	ufs_fragacct(sb, blkmap, ucg->cg_frsum, 1);

	/*
	 * Trying to reassemble free fragments into block
	 */
	blkno = ufs_fragstoblks (bbase);
	if (ubh_isblockset(UCPI_UBH(ucpi), ucpi->c_freeoff, blkno)) {
		fs32_sub(sb, &ucg->cg_cs.cs_nffree, uspi->s_fpb);
		uspi->cs_total.cs_nffree -= uspi->s_fpb;
		fs32_sub(sb, &UFS_SB(sb)->fs_cs(cgno).cs_nffree, uspi->s_fpb);
		if ((UFS_SB(sb)->s_flags & UFS_CG_MASK) == UFS_CG_44BSD)
			ufs_clusteracct (sb, ucpi, blkno, 1);
		fs32_add(sb, &ucg->cg_cs.cs_nbfree, 1);
		uspi->cs_total.cs_nbfree++;
		fs32_add(sb, &UFS_SB(sb)->fs_cs(cgno).cs_nbfree, 1);
		if (uspi->fs_magic != UFS2_MAGIC) {
			unsigned cylno = ufs_cbtocylno (bbase);

			fs16_add(sb, &ubh_cg_blks(ucpi, cylno,
						  ufs_cbtorpos(bbase)), 1);
			fs32_add(sb, &ubh_cg_blktot(ucpi, cylno), 1);
		}
	}

	ubh_mark_buffer_dirty (USPI_UBH(uspi));
	ubh_mark_buffer_dirty (UCPI_UBH(ucpi));
	if (sb->s_flags & MS_SYNCHRONOUS)
		ubh_sync_block(UCPI_UBH(ucpi));
	ufs_mark_sb_dirty(sb);

	unlock_ufs(sb);
	UFSD("EXIT\n");
	return;

failed:
	unlock_ufs(sb);
	UFSD("EXIT (FAILED)\n");
	return;
}

/*
 * Free 'count' fragments from fragment number 'fragment' (free whole blocks)
 */
void ufs_free_blocks(struct inode *inode, u64 fragment, unsigned count)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	struct ufs_cylinder_group * ucg;
	unsigned overflow, cgno, bit, end_bit, i;
	u64 blkno;

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;

	UFSD("ENTER, fragment %llu, count %u\n",
	     (unsigned long long)fragment, count);

	if ((fragment & uspi->s_fpbmask) || (count & uspi->s_fpbmask)) {
		ufs_error (sb, "ufs_free_blocks", "internal error, "
			   "fragment %llu, count %u\n",
			   (unsigned long long)fragment, count);
		goto failed;
	}

	lock_ufs(sb);

do_more:
	overflow = 0;
	cgno = ufs_dtog(uspi, fragment);
	bit = ufs_dtogd(uspi, fragment);
	if (cgno >= uspi->s_ncg) {
		ufs_panic (sb, "ufs_free_blocks", "freeing blocks are outside device");
		goto failed_unlock;
	}
	end_bit = bit + count;
	if (end_bit > uspi->s_fpg) {
		overflow = bit + count - uspi->s_fpg;
		count -= overflow;
		end_bit -= overflow;
	}

	ucpi = ufs_load_cylinder (sb, cgno);
	if (!ucpi)
		goto failed_unlock;
	ucg = ubh_get_ucg (UCPI_UBH(ucpi));
	if (!ufs_cg_chkmagic(sb, ucg)) {
		ufs_panic (sb, "ufs_free_blocks", "internal error, bad magic number on cg %u", cgno);
		goto failed_unlock;
	}

	for (i = bit; i < end_bit; i += uspi->s_fpb) {
		blkno = ufs_fragstoblks(i);
		if (ubh_isblockset(UCPI_UBH(ucpi), ucpi->c_freeoff, blkno)) {
			ufs_error(sb, "ufs_free_blocks", "freeing free fragment");
		}
		ubh_setblock(UCPI_UBH(ucpi), ucpi->c_freeoff, blkno);
		if ((UFS_SB(sb)->s_flags & UFS_CG_MASK) == UFS_CG_44BSD)
			ufs_clusteracct (sb, ucpi, blkno, 1);

		fs32_add(sb, &ucg->cg_cs.cs_nbfree, 1);
		uspi->cs_total.cs_nbfree++;
		fs32_add(sb, &UFS_SB(sb)->fs_cs(cgno).cs_nbfree, 1);

		if (uspi->fs_magic != UFS2_MAGIC) {
			unsigned cylno = ufs_cbtocylno(i);

			fs16_add(sb, &ubh_cg_blks(ucpi, cylno,
						  ufs_cbtorpos(i)), 1);
			fs32_add(sb, &ubh_cg_blktot(ucpi, cylno), 1);
		}
	}

	ubh_mark_buffer_dirty (USPI_UBH(uspi));
	ubh_mark_buffer_dirty (UCPI_UBH(ucpi));
	if (sb->s_flags & MS_SYNCHRONOUS)
		ubh_sync_block(UCPI_UBH(ucpi));

	if (overflow) {
		fragment += count;
		count = overflow;
		goto do_more;
	}

	ufs_mark_sb_dirty(sb);
	unlock_ufs(sb);
	UFSD("EXIT\n");
	return;

failed_unlock:
	unlock_ufs(sb);
failed:
	UFSD("EXIT (FAILED)\n");
	return;
}

/*
 * Modify inode page cache in such way:
 * have - blocks with b_blocknr equal to oldb...oldb+count-1
 * get - blocks with b_blocknr equal to newb...newb+count-1
 * also we suppose that oldb...oldb+count-1 blocks
 * situated at the end of file.
 *
 * We can come here from ufs_writepage or ufs_prepare_write,
 * locked_page is argument of these functions, so we already lock it.
 */
static void ufs_change_blocknr(struct inode *inode, sector_t beg,
			       unsigned int count, sector_t oldb,
			       sector_t newb, struct page *locked_page)
{
	const unsigned blks_per_page =
		1 << (PAGE_CACHE_SHIFT - inode->i_blkbits);
	const unsigned mask = blks_per_page - 1;
	struct address_space * const mapping = inode->i_mapping;
	pgoff_t index, cur_index, last_index;
	unsigned pos, j, lblock;
	sector_t end, i;
	struct page *page;
	struct buffer_head *head, *bh;

	UFSD("ENTER, ino %lu, count %u, oldb %llu, newb %llu\n",
	      inode->i_ino, count,
	     (unsigned long long)oldb, (unsigned long long)newb);

	BUG_ON(!locked_page);
	BUG_ON(!PageLocked(locked_page));

	cur_index = locked_page->index;
	end = count + beg;
	last_index = end >> (PAGE_CACHE_SHIFT - inode->i_blkbits);
	for (i = beg; i < end; i = (i | mask) + 1) {
		index = i >> (PAGE_CACHE_SHIFT - inode->i_blkbits);

		if (likely(cur_index != index)) {
			page = ufs_get_locked_page(mapping, index);
			if (!page)/* it was truncated */
				continue;
			if (IS_ERR(page)) {/* or EIO */
				ufs_error(inode->i_sb, __func__,
					  "read of page %llu failed\n",
					  (unsigned long long)index);
				continue;
			}
		} else
			page = locked_page;

		head = page_buffers(page);
		bh = head;
		pos = i & mask;
		for (j = 0; j < pos; ++j)
			bh = bh->b_this_page;


		if (unlikely(index == last_index))
			lblock = end & mask;
		else
			lblock = blks_per_page;

		do {
			if (j >= lblock)
				break;
			pos = (i - beg) + j;

			if (!buffer_mapped(bh))
					map_bh(bh, inode->i_sb, oldb + pos);
			if (!buffer_uptodate(bh)) {
				ll_rw_block(READ, 1, &bh);
				wait_on_buffer(bh);
				if (!buffer_uptodate(bh)) {
					ufs_error(inode->i_sb, __func__,
						  "read of block failed\n");
					break;
				}
			}

			UFSD(" change from %llu to %llu, pos %u\n",
			     (unsigned long long)(pos + oldb),
			     (unsigned long long)(pos + newb), pos);

			bh->b_blocknr = newb + pos;
			unmap_underlying_metadata(bh->b_bdev,
						  bh->b_blocknr);
			mark_buffer_dirty(bh);
			++j;
			bh = bh->b_this_page;
		} while (bh != head);

		if (likely(cur_index != index))
			ufs_put_locked_page(page);
 	}
	UFSD("EXIT\n");
}

static void ufs_clear_frags(struct inode *inode, sector_t beg, unsigned int n,
			    int sync)
{
	struct buffer_head *bh;
	sector_t end = beg + n;

	for (; beg < end; ++beg) {
		bh = sb_getblk(inode->i_sb, beg);
		lock_buffer(bh);
		memset(bh->b_data, 0, inode->i_sb->s_blocksize);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		unlock_buffer(bh);
		if (IS_SYNC(inode) || sync)
			sync_dirty_buffer(bh);
		brelse(bh);
	}
}

u64 ufs_new_fragments(struct inode *inode, void *p, u64 fragment,
			   u64 goal, unsigned count, int *err,
			   struct page *locked_page)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_super_block_first * usb1;
	unsigned cgno, oldcount, newcount;
	u64 tmp, request, result;

	UFSD("ENTER, ino %lu, fragment %llu, goal %llu, count %u\n",
	     inode->i_ino, (unsigned long long)fragment,
	     (unsigned long long)goal, count);

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;
	usb1 = ubh_get_usb_first(uspi);
	*err = -ENOSPC;

	lock_ufs(sb);
	tmp = ufs_data_ptr_to_cpu(sb, p);

	if (count + ufs_fragnum(fragment) > uspi->s_fpb) {
		ufs_warning(sb, "ufs_new_fragments", "internal warning"
			    " fragment %llu, count %u",
			    (unsigned long long)fragment, count);
		count = uspi->s_fpb - ufs_fragnum(fragment);
	}
	oldcount = ufs_fragnum (fragment);
	newcount = oldcount + count;

	/*
	 * Somebody else has just allocated our fragments
	 */
	if (oldcount) {
		if (!tmp) {
			ufs_error(sb, "ufs_new_fragments", "internal error, "
				  "fragment %llu, tmp %llu\n",
				  (unsigned long long)fragment,
				  (unsigned long long)tmp);
			unlock_ufs(sb);
			return INVBLOCK;
		}
		if (fragment < UFS_I(inode)->i_lastfrag) {
			UFSD("EXIT (ALREADY ALLOCATED)\n");
			unlock_ufs(sb);
			return 0;
		}
	}
	else {
		if (tmp) {
			UFSD("EXIT (ALREADY ALLOCATED)\n");
			unlock_ufs(sb);
			return 0;
		}
	}

	/*
	 * There is not enough space for user on the device
	 */
	if (!capable(CAP_SYS_RESOURCE) && ufs_freespace(uspi, UFS_MINFREE) <= 0) {
		unlock_ufs(sb);
		UFSD("EXIT (FAILED)\n");
		return 0;
	}

	if (goal >= uspi->s_size)
		goal = 0;
	if (goal == 0)
		cgno = ufs_inotocg (inode->i_ino);
	else
		cgno = ufs_dtog(uspi, goal);

	/*
	 * allocate new fragment
	 */
	if (oldcount == 0) {
		result = ufs_alloc_fragments (inode, cgno, goal, count, err);
		if (result) {
			ufs_cpu_to_data_ptr(sb, p, result);
			*err = 0;
			UFS_I(inode)->i_lastfrag =
				max(UFS_I(inode)->i_lastfrag, fragment + count);
			ufs_clear_frags(inode, result + oldcount,
					newcount - oldcount, locked_page != NULL);
		}
		unlock_ufs(sb);
		UFSD("EXIT, result %llu\n", (unsigned long long)result);
		return result;
	}

	/*
	 * resize block
	 */
	result = ufs_add_fragments(inode, tmp, oldcount, newcount);
	if (result) {
		*err = 0;
		UFS_I(inode)->i_lastfrag = max(UFS_I(inode)->i_lastfrag,
						fragment + count);
		ufs_clear_frags(inode, result + oldcount, newcount - oldcount,
				locked_page != NULL);
		unlock_ufs(sb);
		UFSD("EXIT, result %llu\n", (unsigned long long)result);
		return result;
	}

	/*
	 * allocate new block and move data
	 */
	switch (fs32_to_cpu(sb, usb1->fs_optim)) {
	    case UFS_OPTSPACE:
		request = newcount;
		if (uspi->s_minfree < 5 || uspi->cs_total.cs_nffree
		    > uspi->s_dsize * uspi->s_minfree / (2 * 100))
			break;
		usb1->fs_optim = cpu_to_fs32(sb, UFS_OPTTIME);
		break;
	    default:
		usb1->fs_optim = cpu_to_fs32(sb, UFS_OPTTIME);

	    case UFS_OPTTIME:
		request = uspi->s_fpb;
		if (uspi->cs_total.cs_nffree < uspi->s_dsize *
		    (uspi->s_minfree - 2) / 100)
			break;
		usb1->fs_optim = cpu_to_fs32(sb, UFS_OPTTIME);
		break;
	}
	result = ufs_alloc_fragments (inode, cgno, goal, request, err);
	if (result) {
		ufs_clear_frags(inode, result + oldcount, newcount - oldcount,
				locked_page != NULL);
		ufs_change_blocknr(inode, fragment - oldcount, oldcount,
				   uspi->s_sbbase + tmp,
				   uspi->s_sbbase + result, locked_page);
		ufs_cpu_to_data_ptr(sb, p, result);
		*err = 0;
		UFS_I(inode)->i_lastfrag = max(UFS_I(inode)->i_lastfrag,
						fragment + count);
		unlock_ufs(sb);
		if (newcount < request)
			ufs_free_fragments (inode, result + newcount, request - newcount);
		ufs_free_fragments (inode, tmp, oldcount);
		UFSD("EXIT, result %llu\n", (unsigned long long)result);
		return result;
	}

	unlock_ufs(sb);
	UFSD("EXIT (FAILED)\n");
	return 0;
}

static u64 ufs_add_fragments(struct inode *inode, u64 fragment,
			     unsigned oldcount, unsigned newcount)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	struct ufs_cylinder_group * ucg;
	unsigned cgno, fragno, fragoff, count, fragsize, i;

	UFSD("ENTER, fragment %llu, oldcount %u, newcount %u\n",
	     (unsigned long long)fragment, oldcount, newcount);

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;
	count = newcount - oldcount;

	cgno = ufs_dtog(uspi, fragment);
	if (fs32_to_cpu(sb, UFS_SB(sb)->fs_cs(cgno).cs_nffree) < count)
		return 0;
	if ((ufs_fragnum (fragment) + newcount) > uspi->s_fpb)
		return 0;
	ucpi = ufs_load_cylinder (sb, cgno);
	if (!ucpi)
		return 0;
	ucg = ubh_get_ucg (UCPI_UBH(ucpi));
	if (!ufs_cg_chkmagic(sb, ucg)) {
		ufs_panic (sb, "ufs_add_fragments",
			"internal error, bad magic number on cg %u", cgno);
		return 0;
	}

	fragno = ufs_dtogd(uspi, fragment);
	fragoff = ufs_fragnum (fragno);
	for (i = oldcount; i < newcount; i++)
		if (ubh_isclr (UCPI_UBH(ucpi), ucpi->c_freeoff, fragno + i))
			return 0;
	/*
	 * Block can be extended
	 */
	ucg->cg_time = cpu_to_fs32(sb, get_seconds());
	for (i = newcount; i < (uspi->s_fpb - fragoff); i++)
		if (ubh_isclr (UCPI_UBH(ucpi), ucpi->c_freeoff, fragno + i))
			break;
	fragsize = i - oldcount;
	if (!fs32_to_cpu(sb, ucg->cg_frsum[fragsize]))
		ufs_panic (sb, "ufs_add_fragments",
			"internal error or corrupted bitmap on cg %u", cgno);
	fs32_sub(sb, &ucg->cg_frsum[fragsize], 1);
	if (fragsize != count)
		fs32_add(sb, &ucg->cg_frsum[fragsize - count], 1);
	for (i = oldcount; i < newcount; i++)
		ubh_clrbit (UCPI_UBH(ucpi), ucpi->c_freeoff, fragno + i);

	fs32_sub(sb, &ucg->cg_cs.cs_nffree, count);
	fs32_sub(sb, &UFS_SB(sb)->fs_cs(cgno).cs_nffree, count);
	uspi->cs_total.cs_nffree -= count;

	ubh_mark_buffer_dirty (USPI_UBH(uspi));
	ubh_mark_buffer_dirty (UCPI_UBH(ucpi));
	if (sb->s_flags & MS_SYNCHRONOUS)
		ubh_sync_block(UCPI_UBH(ucpi));
	ufs_mark_sb_dirty(sb);

	UFSD("EXIT, fragment %llu\n", (unsigned long long)fragment);

	return fragment;
}

#define UFS_TEST_FREE_SPACE_CG \
	ucg = (struct ufs_cylinder_group *) UFS_SB(sb)->s_ucg[cgno]->b_data; \
	if (fs32_to_cpu(sb, ucg->cg_cs.cs_nbfree)) \
		goto cg_found; \
	for (k = count; k < uspi->s_fpb; k++) \
		if (fs32_to_cpu(sb, ucg->cg_frsum[k])) \
			goto cg_found;

static u64 ufs_alloc_fragments(struct inode *inode, unsigned cgno,
			       u64 goal, unsigned count, int *err)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	struct ufs_cylinder_group * ucg;
	unsigned oldcg, i, j, k, allocsize;
	u64 result;

	UFSD("ENTER, ino %lu, cgno %u, goal %llu, count %u\n",
	     inode->i_ino, cgno, (unsigned long long)goal, count);

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;
	oldcg = cgno;

	/*
	 * 1. searching on preferred cylinder group
	 */
	UFS_TEST_FREE_SPACE_CG

	/*
	 * 2. quadratic rehash
	 */
	for (j = 1; j < uspi->s_ncg; j *= 2) {
		cgno += j;
		if (cgno >= uspi->s_ncg)
			cgno -= uspi->s_ncg;
		UFS_TEST_FREE_SPACE_CG
	}

	/*
	 * 3. brute force search
	 * We start at i = 2 ( 0 is checked at 1.step, 1 at 2.step )
	 */
	cgno = (oldcg + 1) % uspi->s_ncg;
	for (j = 2; j < uspi->s_ncg; j++) {
		cgno++;
		if (cgno >= uspi->s_ncg)
			cgno = 0;
		UFS_TEST_FREE_SPACE_CG
	}

	UFSD("EXIT (FAILED)\n");
	return 0;

cg_found:
	ucpi = ufs_load_cylinder (sb, cgno);
	if (!ucpi)
		return 0;
	ucg = ubh_get_ucg (UCPI_UBH(ucpi));
	if (!ufs_cg_chkmagic(sb, ucg))
		ufs_panic (sb, "ufs_alloc_fragments",
			"internal error, bad magic number on cg %u", cgno);
	ucg->cg_time = cpu_to_fs32(sb, get_seconds());

	if (count == uspi->s_fpb) {
		result = ufs_alloccg_block (inode, ucpi, goal, err);
		if (result == INVBLOCK)
			return 0;
		goto succed;
	}

	for (allocsize = count; allocsize < uspi->s_fpb; allocsize++)
		if (fs32_to_cpu(sb, ucg->cg_frsum[allocsize]) != 0)
			break;

	if (allocsize == uspi->s_fpb) {
		result = ufs_alloccg_block (inode, ucpi, goal, err);
		if (result == INVBLOCK)
			return 0;
		goal = ufs_dtogd(uspi, result);
		for (i = count; i < uspi->s_fpb; i++)
			ubh_setbit (UCPI_UBH(ucpi), ucpi->c_freeoff, goal + i);
		i = uspi->s_fpb - count;

		fs32_add(sb, &ucg->cg_cs.cs_nffree, i);
		uspi->cs_total.cs_nffree += i;
		fs32_add(sb, &UFS_SB(sb)->fs_cs(cgno).cs_nffree, i);
		fs32_add(sb, &ucg->cg_frsum[i], 1);
		goto succed;
	}

	result = ufs_bitmap_search (sb, ucpi, goal, allocsize);
	if (result == INVBLOCK)
		return 0;
	for (i = 0; i < count; i++)
		ubh_clrbit (UCPI_UBH(ucpi), ucpi->c_freeoff, result + i);

	fs32_sub(sb, &ucg->cg_cs.cs_nffree, count);
	uspi->cs_total.cs_nffree -= count;
	fs32_sub(sb, &UFS_SB(sb)->fs_cs(cgno).cs_nffree, count);
	fs32_sub(sb, &ucg->cg_frsum[allocsize], 1);

	if (count != allocsize)
		fs32_add(sb, &ucg->cg_frsum[allocsize - count], 1);

succed:
	ubh_mark_buffer_dirty (USPI_UBH(uspi));
	ubh_mark_buffer_dirty (UCPI_UBH(ucpi));
	if (sb->s_flags & MS_SYNCHRONOUS)
		ubh_sync_block(UCPI_UBH(ucpi));
	ufs_mark_sb_dirty(sb);

	result += cgno * uspi->s_fpg;
	UFSD("EXIT3, result %llu\n", (unsigned long long)result);
	return result;
}

static u64 ufs_alloccg_block(struct inode *inode,
			     struct ufs_cg_private_info *ucpi,
			     u64 goal, int *err)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_cylinder_group * ucg;
	u64 result, blkno;

	UFSD("ENTER, goal %llu\n", (unsigned long long)goal);

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;
	ucg = ubh_get_ucg(UCPI_UBH(ucpi));

	if (goal == 0) {
		goal = ucpi->c_rotor;
		goto norot;
	}
	goal = ufs_blknum (goal);
	goal = ufs_dtogd(uspi, goal);

	/*
	 * If the requested block is available, use it.
	 */
	if (ubh_isblockset(UCPI_UBH(ucpi), ucpi->c_freeoff, ufs_fragstoblks(goal))) {
		result = goal;
		goto gotit;
	}

norot:
	result = ufs_bitmap_search (sb, ucpi, goal, uspi->s_fpb);
	if (result == INVBLOCK)
		return INVBLOCK;
	ucpi->c_rotor = result;
gotit:
	blkno = ufs_fragstoblks(result);
	ubh_clrblock (UCPI_UBH(ucpi), ucpi->c_freeoff, blkno);
	if ((UFS_SB(sb)->s_flags & UFS_CG_MASK) == UFS_CG_44BSD)
		ufs_clusteracct (sb, ucpi, blkno, -1);

	fs32_sub(sb, &ucg->cg_cs.cs_nbfree, 1);
	uspi->cs_total.cs_nbfree--;
	fs32_sub(sb, &UFS_SB(sb)->fs_cs(ucpi->c_cgx).cs_nbfree, 1);

	if (uspi->fs_magic != UFS2_MAGIC) {
		unsigned cylno = ufs_cbtocylno((unsigned)result);

		fs16_sub(sb, &ubh_cg_blks(ucpi, cylno,
					  ufs_cbtorpos((unsigned)result)), 1);
		fs32_sub(sb, &ubh_cg_blktot(ucpi, cylno), 1);
	}

	UFSD("EXIT, result %llu\n", (unsigned long long)result);

	return result;
}

static unsigned ubh_scanc(struct ufs_sb_private_info *uspi,
			  struct ufs_buffer_head *ubh,
			  unsigned begin, unsigned size,
			  unsigned char *table, unsigned char mask)
{
	unsigned rest, offset;
	unsigned char *cp;


	offset = begin & ~uspi->s_fmask;
	begin >>= uspi->s_fshift;
	for (;;) {
		if ((offset + size) < uspi->s_fsize)
			rest = size;
		else
			rest = uspi->s_fsize - offset;
		size -= rest;
		cp = ubh->bh[begin]->b_data + offset;
		while ((table[*cp++] & mask) == 0 && --rest)
			;
		if (rest || !size)
			break;
		begin++;
		offset = 0;
	}
	return (size + rest);
}

/*
 * Find a block of the specified size in the specified cylinder group.
 * @sp: pointer to super block
 * @ucpi: pointer to cylinder group info
 * @goal: near which block we want find new one
 * @count: specified size
 */
static u64 ufs_bitmap_search(struct super_block *sb,
			     struct ufs_cg_private_info *ucpi,
			     u64 goal, unsigned count)
{
	/*
	 * Bit patterns for identifying fragments in the block map
	 * used as ((map & mask_arr) == want_arr)
	 */
	static const int mask_arr[9] = {
		0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff
	};
	static const int want_arr[9] = {
		0x0, 0x2, 0x6, 0xe, 0x1e, 0x3e, 0x7e, 0xfe, 0x1fe
	};
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	struct ufs_cylinder_group *ucg;
	unsigned start, length, loc;
	unsigned pos, want, blockmap, mask, end;
	u64 result;

	UFSD("ENTER, cg %u, goal %llu, count %u\n", ucpi->c_cgx,
	     (unsigned long long)goal, count);

	ucg = ubh_get_ucg(UCPI_UBH(ucpi));

	if (goal)
		start = ufs_dtogd(uspi, goal) >> 3;
	else
		start = ucpi->c_frotor >> 3;

	length = ((uspi->s_fpg + 7) >> 3) - start;
	loc = ubh_scanc(uspi, UCPI_UBH(ucpi), ucpi->c_freeoff + start, length,
		(uspi->s_fpb == 8) ? ufs_fragtable_8fpb : ufs_fragtable_other,
		1 << (count - 1 + (uspi->s_fpb & 7)));
	if (loc == 0) {
		length = start + 1;
		loc = ubh_scanc(uspi, UCPI_UBH(ucpi), ucpi->c_freeoff, length,
				(uspi->s_fpb == 8) ? ufs_fragtable_8fpb :
				ufs_fragtable_other,
				1 << (count - 1 + (uspi->s_fpb & 7)));
		if (loc == 0) {
			ufs_error(sb, "ufs_bitmap_search",
				  "bitmap corrupted on cg %u, start %u,"
				  " length %u, count %u, freeoff %u\n",
				  ucpi->c_cgx, start, length, count,
				  ucpi->c_freeoff);
			return INVBLOCK;
		}
		start = 0;
	}
	result = (start + length - loc) << 3;
	ucpi->c_frotor = result;

	/*
	 * found the byte in the map
	 */

	for (end = result + 8; result < end; result += uspi->s_fpb) {
		blockmap = ubh_blkmap(UCPI_UBH(ucpi), ucpi->c_freeoff, result);
		blockmap <<= 1;
		mask = mask_arr[count];
		want = want_arr[count];
		for (pos = 0; pos <= uspi->s_fpb - count; pos++) {
			if ((blockmap & mask) == want) {
				UFSD("EXIT, result %llu\n",
				     (unsigned long long)result);
				return result + pos;
 			}
			mask <<= 1;
			want <<= 1;
 		}
 	}

	ufs_error(sb, "ufs_bitmap_search", "block not in map on cg %u\n",
		  ucpi->c_cgx);
	UFSD("EXIT (FAILED)\n");
	return INVBLOCK;
}

static void ufs_clusteracct(struct super_block * sb,
	struct ufs_cg_private_info * ucpi, unsigned blkno, int cnt)
{
	struct ufs_sb_private_info * uspi;
	int i, start, end, forw, back;

	uspi = UFS_SB(sb)->s_uspi;
	if (uspi->s_contigsumsize <= 0)
		return;

	if (cnt > 0)
		ubh_setbit(UCPI_UBH(ucpi), ucpi->c_clusteroff, blkno);
	else
		ubh_clrbit(UCPI_UBH(ucpi), ucpi->c_clusteroff, blkno);

	/*
	 * Find the size of the cluster going forward.
	 */
	start = blkno + 1;
	end = start + uspi->s_contigsumsize;
	if ( end >= ucpi->c_nclusterblks)
		end = ucpi->c_nclusterblks;
	i = ubh_find_next_zero_bit (UCPI_UBH(ucpi), ucpi->c_clusteroff, end, start);
	if (i > end)
		i = end;
	forw = i - start;

	/*
	 * Find the size of the cluster going backward.
	 */
	start = blkno - 1;
	end = start - uspi->s_contigsumsize;
	if (end < 0 )
		end = -1;
	i = ubh_find_last_zero_bit (UCPI_UBH(ucpi), ucpi->c_clusteroff, start, end);
	if ( i < end)
		i = end;
	back = start - i;

	/*
	 * Account for old cluster and the possibly new forward and
	 * back clusters.
	 */
	i = back + forw + 1;
	if (i > uspi->s_contigsumsize)
		i = uspi->s_contigsumsize;
	fs32_add(sb, (__fs32*)ubh_get_addr(UCPI_UBH(ucpi), ucpi->c_clustersumoff + (i << 2)), cnt);
	if (back > 0)
		fs32_sub(sb, (__fs32*)ubh_get_addr(UCPI_UBH(ucpi), ucpi->c_clustersumoff + (back << 2)), cnt);
	if (forw > 0)
		fs32_sub(sb, (__fs32*)ubh_get_addr(UCPI_UBH(ucpi), ucpi->c_clustersumoff + (forw << 2)), cnt);
}


static unsigned char ufs_fragtable_8fpb[] = {
	0x00, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x04, 0x01, 0x01, 0x01, 0x03, 0x02, 0x03, 0x04, 0x08,
	0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0x05, 0x02, 0x03, 0x03, 0x02, 0x04, 0x05, 0x08, 0x10,
	0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0x05, 0x01, 0x01, 0x01, 0x03, 0x03, 0x03, 0x05, 0x09,
	0x02, 0x03, 0x03, 0x02, 0x03, 0x03, 0x02, 0x06, 0x04, 0x05, 0x05, 0x06, 0x08, 0x09, 0x10, 0x20,
	0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0x05, 0x01, 0x01, 0x01, 0x03, 0x03, 0x03, 0x05, 0x09,
	0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0x05, 0x03, 0x03, 0x03, 0x03, 0x05, 0x05, 0x09, 0x11,
	0x02, 0x03, 0x03, 0x02, 0x03, 0x03, 0x02, 0x06, 0x03, 0x03, 0x03, 0x03, 0x02, 0x03, 0x06, 0x0A,
	0x04, 0x05, 0x05, 0x06, 0x05, 0x05, 0x06, 0x04, 0x08, 0x09, 0x09, 0x0A, 0x10, 0x11, 0x20, 0x40,
	0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0x05, 0x01, 0x01, 0x01, 0x03, 0x03, 0x03, 0x05, 0x09,
	0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0x05, 0x03, 0x03, 0x03, 0x03, 0x05, 0x05, 0x09, 0x11,
	0x01, 0x01, 0x01, 0x03, 0x01, 0x01, 0x03, 0x05, 0x01, 0x01, 0x01, 0x03, 0x03, 0x03, 0x05, 0x09,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x07, 0x05, 0x05, 0x05, 0x07, 0x09, 0x09, 0x11, 0x21,
	0x02, 0x03, 0x03, 0x02, 0x03, 0x03, 0x02, 0x06, 0x03, 0x03, 0x03, 0x03, 0x02, 0x03, 0x06, 0x0A,
	0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x07, 0x02, 0x03, 0x03, 0x02, 0x06, 0x07, 0x0A, 0x12,
	0x04, 0x05, 0x05, 0x06, 0x05, 0x05, 0x06, 0x04, 0x05, 0x05, 0x05, 0x07, 0x06, 0x07, 0x04, 0x0C,
	0x08, 0x09, 0x09, 0x0A, 0x09, 0x09, 0x0A, 0x0C, 0x10, 0x11, 0x11, 0x12, 0x20, 0x21, 0x40, 0x80,
};

static unsigned char ufs_fragtable_other[] = {
	0x00, 0x16, 0x16, 0x2A, 0x16, 0x16, 0x26, 0x4E, 0x16, 0x16, 0x16, 0x3E, 0x2A, 0x3E, 0x4E, 0x8A,
	0x16, 0x16, 0x16, 0x3E, 0x16, 0x16, 0x36, 0x5E, 0x16, 0x16, 0x16, 0x3E, 0x3E, 0x3E, 0x5E, 0x9E,
	0x16, 0x16, 0x16, 0x3E, 0x16, 0x16, 0x36, 0x5E, 0x16, 0x16, 0x16, 0x3E, 0x3E, 0x3E, 0x5E, 0x9E,
	0x2A, 0x3E, 0x3E, 0x2A, 0x3E, 0x3E, 0x2E, 0x6E, 0x3E, 0x3E, 0x3E, 0x3E, 0x2A, 0x3E, 0x6E, 0xAA,
	0x16, 0x16, 0x16, 0x3E, 0x16, 0x16, 0x36, 0x5E, 0x16, 0x16, 0x16, 0x3E, 0x3E, 0x3E, 0x5E, 0x9E,
	0x16, 0x16, 0x16, 0x3E, 0x16, 0x16, 0x36, 0x5E, 0x16, 0x16, 0x16, 0x3E, 0x3E, 0x3E, 0x5E, 0x9E,
	0x26, 0x36, 0x36, 0x2E, 0x36, 0x36, 0x26, 0x6E, 0x36, 0x36, 0x36, 0x3E, 0x2E, 0x3E, 0x6E, 0xAE,
	0x4E, 0x5E, 0x5E, 0x6E, 0x5E, 0x5E, 0x6E, 0x4E, 0x5E, 0x5E, 0x5E, 0x7E, 0x6E, 0x7E, 0x4E, 0xCE,
	0x16, 0x16, 0x16, 0x3E, 0x16, 0x16, 0x36, 0x5E, 0x16, 0x16, 0x16, 0x3E, 0x3E, 0x3E, 0x5E, 0x9E,
	0x16, 0x16, 0x16, 0x3E, 0x16, 0x16, 0x36, 0x5E, 0x16, 0x16, 0x16, 0x3E, 0x3E, 0x3E, 0x5E, 0x9E,
	0x16, 0x16, 0x16, 0x3E, 0x16, 0x16, 0x36, 0x5E, 0x16, 0x16, 0x16, 0x3E, 0x3E, 0x3E, 0x5E, 0x9E,
	0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x7E, 0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x7E, 0xBE,
	0x2A, 0x3E, 0x3E, 0x2A, 0x3E, 0x3E, 0x2E, 0x6E, 0x3E, 0x3E, 0x3E, 0x3E, 0x2A, 0x3E, 0x6E, 0xAA,
	0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x7E,	0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x3E, 0x7E, 0xBE,
	0x4E, 0x5E, 0x5E, 0x6E, 0x5E, 0x5E, 0x6E, 0x4E, 0x5E, 0x5E, 0x5E, 0x7E, 0x6E, 0x7E, 0x4E, 0xCE,
	0x8A, 0x9E, 0x9E, 0xAA, 0x9E, 0x9E, 0xAE, 0xCE, 0x9E, 0x9E, 0x9E, 0xBE, 0xAA, 0xBE, 0xCE, 0x8A,
};
/************************************************************/
/* ../linux-3.17/fs/ufs/balloc.c */
/************************************************************/
/*
 *  linux/fs/ufs/cylinder.c
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 *  ext2 - inode (block) bitmap caching inspired
 */

// #include <linux/fs.h>
// #include <linux/time.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/bitops.h>

// #include <asm/byteorder.h>

// #include "ufs_fs.h"
// #include "ufs.h"
// #include "swab.h"
// #include "util.h"

/*
 * Read cylinder group into cache. The memory space for ufs_cg_private_info
 * structure is already allocated during ufs_read_super.
 */
static void ufs_read_cylinder (struct super_block * sb,
	unsigned cgno, unsigned bitmap_nr)
{
	struct ufs_sb_info * sbi = UFS_SB(sb);
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	struct ufs_cylinder_group * ucg;
	unsigned i, j;

	UFSD("ENTER, cgno %u, bitmap_nr %u\n", cgno, bitmap_nr);
	uspi = sbi->s_uspi;
	ucpi = sbi->s_ucpi[bitmap_nr];
	ucg = (struct ufs_cylinder_group *)sbi->s_ucg[cgno]->b_data;

	UCPI_UBH(ucpi)->fragment = ufs_cgcmin(cgno);
	UCPI_UBH(ucpi)->count = uspi->s_cgsize >> sb->s_blocksize_bits;
	/*
	 * We have already the first fragment of cylinder group block in buffer
	 */
	UCPI_UBH(ucpi)->bh[0] = sbi->s_ucg[cgno];
	for (i = 1; i < UCPI_UBH(ucpi)->count; i++)
		if (!(UCPI_UBH(ucpi)->bh[i] = sb_bread(sb, UCPI_UBH(ucpi)->fragment + i)))
			goto failed;
	sbi->s_cgno[bitmap_nr] = cgno;

	ucpi->c_cgx	= fs32_to_cpu(sb, ucg->cg_cgx);
	ucpi->c_ncyl	= fs16_to_cpu(sb, ucg->cg_ncyl);
	ucpi->c_niblk	= fs16_to_cpu(sb, ucg->cg_niblk);
	ucpi->c_ndblk	= fs32_to_cpu(sb, ucg->cg_ndblk);
	ucpi->c_rotor	= fs32_to_cpu(sb, ucg->cg_rotor);
	ucpi->c_frotor	= fs32_to_cpu(sb, ucg->cg_frotor);
	ucpi->c_irotor	= fs32_to_cpu(sb, ucg->cg_irotor);
	ucpi->c_btotoff	= fs32_to_cpu(sb, ucg->cg_btotoff);
	ucpi->c_boff	= fs32_to_cpu(sb, ucg->cg_boff);
	ucpi->c_iusedoff = fs32_to_cpu(sb, ucg->cg_iusedoff);
	ucpi->c_freeoff	= fs32_to_cpu(sb, ucg->cg_freeoff);
	ucpi->c_nextfreeoff = fs32_to_cpu(sb, ucg->cg_nextfreeoff);
	ucpi->c_clustersumoff = fs32_to_cpu(sb, ucg->cg_u.cg_44.cg_clustersumoff);
	ucpi->c_clusteroff = fs32_to_cpu(sb, ucg->cg_u.cg_44.cg_clusteroff);
	ucpi->c_nclusterblks = fs32_to_cpu(sb, ucg->cg_u.cg_44.cg_nclusterblks);
	UFSD("EXIT\n");
	return;

failed:
	for (j = 1; j < i; j++)
		brelse (sbi->s_ucg[j]);
	sbi->s_cgno[bitmap_nr] = UFS_CGNO_EMPTY;
	ufs_error (sb, "ufs_read_cylinder", "can't read cylinder group block %u", cgno);
}

/*
 * Remove cylinder group from cache, doesn't release memory
 * allocated for cylinder group (this is done at ufs_put_super only).
 */
void ufs_put_cylinder (struct super_block * sb, unsigned bitmap_nr)
{
	struct ufs_sb_info * sbi = UFS_SB(sb);
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	struct ufs_cylinder_group * ucg;
	unsigned i;

	UFSD("ENTER, bitmap_nr %u\n", bitmap_nr);

	uspi = sbi->s_uspi;
	if (sbi->s_cgno[bitmap_nr] == UFS_CGNO_EMPTY) {
		UFSD("EXIT\n");
		return;
	}
	ucpi = sbi->s_ucpi[bitmap_nr];
	ucg = ubh_get_ucg(UCPI_UBH(ucpi));

	if (uspi->s_ncg > UFS_MAX_GROUP_LOADED && bitmap_nr >= sbi->s_cg_loaded) {
		ufs_panic (sb, "ufs_put_cylinder", "internal error");
		return;
	}
	/*
	 * rotor is not so important data, so we put it to disk
	 * at the end of working with cylinder
	 */
	ucg->cg_rotor = cpu_to_fs32(sb, ucpi->c_rotor);
	ucg->cg_frotor = cpu_to_fs32(sb, ucpi->c_frotor);
	ucg->cg_irotor = cpu_to_fs32(sb, ucpi->c_irotor);
	ubh_mark_buffer_dirty (UCPI_UBH(ucpi));
	for (i = 1; i < UCPI_UBH(ucpi)->count; i++) {
		brelse (UCPI_UBH(ucpi)->bh[i]);
	}

	sbi->s_cgno[bitmap_nr] = UFS_CGNO_EMPTY;
	UFSD("EXIT\n");
}

/*
 * Find cylinder group in cache and return it as pointer.
 * If cylinder group is not in cache, we will load it from disk.
 *
 * The cache is managed by LRU algorithm.
 */
struct ufs_cg_private_info * ufs_load_cylinder (
	struct super_block * sb, unsigned cgno)
{
	struct ufs_sb_info * sbi = UFS_SB(sb);
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	unsigned cg, i, j;

	UFSD("ENTER, cgno %u\n", cgno);

	uspi = sbi->s_uspi;
	if (cgno >= uspi->s_ncg) {
		ufs_panic (sb, "ufs_load_cylinder", "internal error, high number of cg");
		return NULL;
	}
	/*
	 * Cylinder group number cg it in cache and it was last used
	 */
	if (sbi->s_cgno[0] == cgno) {
		UFSD("EXIT\n");
		return sbi->s_ucpi[0];
	}
	/*
	 * Number of cylinder groups is not higher than UFS_MAX_GROUP_LOADED
	 */
	if (uspi->s_ncg <= UFS_MAX_GROUP_LOADED) {
		if (sbi->s_cgno[cgno] != UFS_CGNO_EMPTY) {
			if (sbi->s_cgno[cgno] != cgno) {
				ufs_panic (sb, "ufs_load_cylinder", "internal error, wrong number of cg in cache");
				UFSD("EXIT (FAILED)\n");
				return NULL;
			}
			else {
				UFSD("EXIT\n");
				return sbi->s_ucpi[cgno];
			}
		} else {
			ufs_read_cylinder (sb, cgno, cgno);
			UFSD("EXIT\n");
			return sbi->s_ucpi[cgno];
		}
	}
	/*
	 * Cylinder group number cg is in cache but it was not last used,
	 * we will move to the first position
	 */
	for (i = 0; i < sbi->s_cg_loaded && sbi->s_cgno[i] != cgno; i++);
	if (i < sbi->s_cg_loaded && sbi->s_cgno[i] == cgno) {
		cg = sbi->s_cgno[i];
		ucpi = sbi->s_ucpi[i];
		for (j = i; j > 0; j--) {
			sbi->s_cgno[j] = sbi->s_cgno[j-1];
			sbi->s_ucpi[j] = sbi->s_ucpi[j-1];
		}
		sbi->s_cgno[0] = cg;
		sbi->s_ucpi[0] = ucpi;
	/*
	 * Cylinder group number cg is not in cache, we will read it from disk
	 * and put it to the first position
	 */
	} else {
		if (sbi->s_cg_loaded < UFS_MAX_GROUP_LOADED)
			sbi->s_cg_loaded++;
		else
			ufs_put_cylinder (sb, UFS_MAX_GROUP_LOADED-1);
		ucpi = sbi->s_ucpi[sbi->s_cg_loaded - 1];
		for (j = sbi->s_cg_loaded - 1; j > 0; j--) {
			sbi->s_cgno[j] = sbi->s_cgno[j-1];
			sbi->s_ucpi[j] = sbi->s_ucpi[j-1];
		}
		sbi->s_ucpi[0] = ucpi;
		ufs_read_cylinder (sb, cgno, 0);
	}
	UFSD("EXIT\n");
	return sbi->s_ucpi[0];
}
/************************************************************/
/* ../linux-3.17/fs/ufs/cylinder.c */
/************************************************************/
/*
 *  linux/fs/ufs/ufs_dir.c
 *
 * Copyright (C) 1996
 * Adrian Rodriguez (adrian@franklins-tower.rutgers.edu)
 * Laboratory for Computer Science Research Computing Facility
 * Rutgers, The State University of New Jersey
 *
 * swab support by Francois-Rene Rideau <fare@tunes.org> 19970406
 *
 * 4.4BSD (FreeBSD) support added on February 1st 1998 by
 * Niels Kristian Bech Jensen <nkbj@image.dk> partially based
 * on code by Martin von Loewis <martin@mira.isdn.cs.tu-berlin.de>.
 *
 * Migration to usage of "page cache" on May 2006 by
 * Evgeniy Dushistov <dushistov@mail.ru> based on ext2 code base.
 */

// #include <linux/time.h>
// #include <linux/fs.h>
#include <linux/swap.h>

// #include "ufs_fs.h"
// #include "ufs.h"
// #include "swab.h"
// #include "util.h"

/*
 * NOTE! unlike strncmp, ufs_match returns 1 for success, 0 for failure.
 *
 * len <= UFS_MAXNAMLEN and de != NULL are guaranteed by caller.
 */
static inline int ufs_match(struct super_block *sb, int len,
		const unsigned char *name, struct ufs_dir_entry *de)
{
	if (len != ufs_get_de_namlen(sb, de))
		return 0;
	if (!de->d_ino)
		return 0;
	return !memcmp(name, de->d_name, len);
}

static int ufs_commit_chunk(struct page *page, loff_t pos, unsigned len)
{
	struct address_space *mapping = page->mapping;
	struct inode *dir = mapping->host;
	int err = 0;

	dir->i_version++;
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

static inline void ufs_put_page(struct page *page)
{
	kunmap(page);
	page_cache_release(page);
}

static inline unsigned long ufs_dir_pages(struct inode *inode)
{
	return (inode->i_size+PAGE_CACHE_SIZE-1)>>PAGE_CACHE_SHIFT;
}

ino_t ufs_inode_by_name(struct inode *dir, const struct qstr *qstr)
{
	ino_t res = 0;
	struct ufs_dir_entry *de;
	struct page *page;

	de = ufs_find_entry(dir, qstr, &page);
	if (de) {
		res = fs32_to_cpu(dir->i_sb, de->d_ino);
		ufs_put_page(page);
	}
	return res;
}


/* Releases the page */
void ufs_set_link(struct inode *dir, struct ufs_dir_entry *de,
		  struct page *page, struct inode *inode)
{
	loff_t pos = page_offset(page) +
			(char *) de - (char *) page_address(page);
	unsigned len = fs16_to_cpu(dir->i_sb, de->d_reclen);
	int err;

	lock_page(page);
	err = ufs_prepare_chunk(page, pos, len);
	BUG_ON(err);

	de->d_ino = cpu_to_fs32(dir->i_sb, inode->i_ino);
	ufs_set_de_type(dir->i_sb, de, inode->i_mode);

	err = ufs_commit_chunk(page, pos, len);
	ufs_put_page(page);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(dir);
}


static void ufs_check_page(struct page *page)
{
	struct inode *dir = page->mapping->host;
	struct super_block *sb = dir->i_sb;
	char *kaddr = page_address(page);
	unsigned offs, rec_len;
	unsigned limit = PAGE_CACHE_SIZE;
	const unsigned chunk_mask = UFS_SB(sb)->s_uspi->s_dirblksize - 1;
	struct ufs_dir_entry *p;
	char *error;

	if ((dir->i_size >> PAGE_CACHE_SHIFT) == page->index) {
		limit = dir->i_size & ~PAGE_CACHE_MASK;
		if (limit & chunk_mask)
			goto Ebadsize;
		if (!limit)
			goto out;
	}
	for (offs = 0; offs <= limit - UFS_DIR_REC_LEN(1); offs += rec_len) {
		p = (struct ufs_dir_entry *)(kaddr + offs);
		rec_len = fs16_to_cpu(sb, p->d_reclen);

		if (rec_len < UFS_DIR_REC_LEN(1))
			goto Eshort;
		if (rec_len & 3)
			goto Ealign;
		if (rec_len < UFS_DIR_REC_LEN(ufs_get_de_namlen(sb, p)))
			goto Enamelen;
		if (((offs + rec_len - 1) ^ offs) & ~chunk_mask)
			goto Espan;
		if (fs32_to_cpu(sb, p->d_ino) > (UFS_SB(sb)->s_uspi->s_ipg *
						  UFS_SB(sb)->s_uspi->s_ncg))
			goto Einumber;
	}
	if (offs != limit)
		goto Eend;
out:
	SetPageChecked(page);
	return;

	/* Too bad, we had an error */

Ebadsize:
	ufs_error(sb, "ufs_check_page",
		  "size of directory #%lu is not a multiple of chunk size",
		  dir->i_ino
	);
	goto fail;
Eshort:
	error = "rec_len is smaller than minimal";
	goto bad_entry;
Ealign:
	error = "unaligned directory entry";
	goto bad_entry;
Enamelen:
	error = "rec_len is too small for name_len";
	goto bad_entry;
Espan:
	error = "directory entry across blocks";
	goto bad_entry;
Einumber:
	error = "inode out of bounds";
bad_entry:
	ufs_error (sb, "ufs_check_page", "bad entry in directory #%lu: %s - "
		   "offset=%lu, rec_len=%d, name_len=%d",
		   dir->i_ino, error, (page->index<<PAGE_CACHE_SHIFT)+offs,
		   rec_len, ufs_get_de_namlen(sb, p));
	goto fail;
Eend:
	p = (struct ufs_dir_entry *)(kaddr + offs);
	ufs_error(sb, __func__,
		   "entry in directory #%lu spans the page boundary"
		   "offset=%lu",
		   dir->i_ino, (page->index<<PAGE_CACHE_SHIFT)+offs);
fail:
	SetPageChecked(page);
	SetPageError(page);
}

static struct page *ufs_get_page(struct inode *dir, unsigned long n)
{
	struct address_space *mapping = dir->i_mapping;
	struct page *page = read_mapping_page(mapping, n, NULL);
	if (!IS_ERR(page)) {
		kmap(page);
		if (!PageChecked(page))
			ufs_check_page(page);
		if (PageError(page))
			goto fail;
	}
	return page;

fail:
	ufs_put_page(page);
	return ERR_PTR(-EIO);
}

/*
 * Return the offset into page `page_nr' of the last valid
 * byte in that page, plus one.
 */
static unsigned
ufs_last_byte(struct inode *inode, unsigned long page_nr)
{
	unsigned last_byte = inode->i_size;

	last_byte -= page_nr << PAGE_CACHE_SHIFT;
	if (last_byte > PAGE_CACHE_SIZE)
		last_byte = PAGE_CACHE_SIZE;
	return last_byte;
}

static inline struct ufs_dir_entry *
ufs_next_entry(struct super_block *sb, struct ufs_dir_entry *p)
{
	return (struct ufs_dir_entry *)((char *)p +
					fs16_to_cpu(sb, p->d_reclen));
}

struct ufs_dir_entry *ufs_dotdot(struct inode *dir, struct page **p)
{
	struct page *page = ufs_get_page(dir, 0);
	struct ufs_dir_entry *de = NULL;

	if (!IS_ERR(page)) {
		de = ufs_next_entry(dir->i_sb,
				    (struct ufs_dir_entry *)page_address(page));
		*p = page;
	}
	return de;
}

/*
 *	ufs_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the page in which the entry was found, and the entry itself
 * (as a parameter - res_dir). Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 */
struct ufs_dir_entry *ufs_find_entry(struct inode *dir, const struct qstr *qstr,
				     struct page **res_page)
{
	struct super_block *sb = dir->i_sb;
	const unsigned char *name = qstr->name;
	int namelen = qstr->len;
	unsigned reclen = UFS_DIR_REC_LEN(namelen);
	unsigned long start, n;
	unsigned long npages = ufs_dir_pages(dir);
	struct page *page = NULL;
	struct ufs_inode_info *ui = UFS_I(dir);
	struct ufs_dir_entry *de;

	UFSD("ENTER, dir_ino %lu, name %s, namlen %u\n", dir->i_ino, name, namelen);

	if (npages == 0 || namelen > UFS_MAXNAMLEN)
		goto out;

	/* OFFSET_CACHE */
	*res_page = NULL;

	start = ui->i_dir_start_lookup;

	if (start >= npages)
		start = 0;
	n = start;
	do {
		char *kaddr;
		page = ufs_get_page(dir, n);
		if (!IS_ERR(page)) {
			kaddr = page_address(page);
			de = (struct ufs_dir_entry *) kaddr;
			kaddr += ufs_last_byte(dir, n) - reclen;
			while ((char *) de <= kaddr) {
				if (de->d_reclen == 0) {
					ufs_error(dir->i_sb, __func__,
						  "zero-length directory entry");
					ufs_put_page(page);
					goto out;
				}
				if (ufs_match(sb, namelen, name, de))
					goto found;
				de = ufs_next_entry(sb, de);
			}
			ufs_put_page(page);
		}
		if (++n >= npages)
			n = 0;
	} while (n != start);
out:
	return NULL;

found:
	*res_page = page;
	ui->i_dir_start_lookup = n;
	return de;
}

/*
 *	Parent is locked.
 */
int ufs_add_link(struct dentry *dentry, struct inode *inode)
{
	struct inode *dir = dentry->d_parent->d_inode;
	const unsigned char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct super_block *sb = dir->i_sb;
	unsigned reclen = UFS_DIR_REC_LEN(namelen);
	const unsigned int chunk_size = UFS_SB(sb)->s_uspi->s_dirblksize;
	unsigned short rec_len, name_len;
	struct page *page = NULL;
	struct ufs_dir_entry *de;
	unsigned long npages = ufs_dir_pages(dir);
	unsigned long n;
	char *kaddr;
	loff_t pos;
	int err;

	UFSD("ENTER, name %s, namelen %u\n", name, namelen);

	/*
	 * We take care of directory expansion in the same loop.
	 * This code plays outside i_size, so it locks the page
	 * to protect that region.
	 */
	for (n = 0; n <= npages; n++) {
		char *dir_end;

		page = ufs_get_page(dir, n);
		err = PTR_ERR(page);
		if (IS_ERR(page))
			goto out;
		lock_page(page);
		kaddr = page_address(page);
		dir_end = kaddr + ufs_last_byte(dir, n);
		de = (struct ufs_dir_entry *)kaddr;
		kaddr += PAGE_CACHE_SIZE - reclen;
		while ((char *)de <= kaddr) {
			if ((char *)de == dir_end) {
				/* We hit i_size */
				name_len = 0;
				rec_len = chunk_size;
				de->d_reclen = cpu_to_fs16(sb, chunk_size);
				de->d_ino = 0;
				goto got_it;
			}
			if (de->d_reclen == 0) {
				ufs_error(dir->i_sb, __func__,
					  "zero-length directory entry");
				err = -EIO;
				goto out_unlock;
			}
			err = -EEXIST;
			if (ufs_match(sb, namelen, name, de))
				goto out_unlock;
			name_len = UFS_DIR_REC_LEN(ufs_get_de_namlen(sb, de));
			rec_len = fs16_to_cpu(sb, de->d_reclen);
			if (!de->d_ino && rec_len >= reclen)
				goto got_it;
			if (rec_len >= name_len + reclen)
				goto got_it;
			de = (struct ufs_dir_entry *) ((char *) de + rec_len);
		}
		unlock_page(page);
		ufs_put_page(page);
	}
	BUG();
	return -EINVAL;

got_it:
	pos = page_offset(page) +
			(char*)de - (char*)page_address(page);
	err = ufs_prepare_chunk(page, pos, rec_len);
	if (err)
		goto out_unlock;
	if (de->d_ino) {
		struct ufs_dir_entry *de1 =
			(struct ufs_dir_entry *) ((char *) de + name_len);
		de1->d_reclen = cpu_to_fs16(sb, rec_len - name_len);
		de->d_reclen = cpu_to_fs16(sb, name_len);

		de = de1;
	}

	ufs_set_de_namlen(sb, de, namelen);
	memcpy(de->d_name, name, namelen + 1);
	de->d_ino = cpu_to_fs32(sb, inode->i_ino);
	ufs_set_de_type(sb, de, inode->i_mode);

	err = ufs_commit_chunk(page, pos, rec_len);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;

	mark_inode_dirty(dir);
	/* OFFSET_CACHE */
out_put:
	ufs_put_page(page);
out:
	return err;
out_unlock:
	unlock_page(page);
	goto out_put;
}

static inline unsigned
ufs_validate_entry(struct super_block *sb, char *base,
		   unsigned offset, unsigned mask)
{
	struct ufs_dir_entry *de = (struct ufs_dir_entry*)(base + offset);
	struct ufs_dir_entry *p = (struct ufs_dir_entry*)(base + (offset&mask));
	while ((char*)p < (char*)de) {
		if (p->d_reclen == 0)
			break;
		p = ufs_next_entry(sb, p);
	}
	return (char *)p - base;
}


/*
 * This is blatantly stolen from ext2fs
 */
static int
ufs_readdir(struct file *file, struct dir_context *ctx)
{
	loff_t pos = ctx->pos;
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	unsigned int offset = pos & ~PAGE_CACHE_MASK;
	unsigned long n = pos >> PAGE_CACHE_SHIFT;
	unsigned long npages = ufs_dir_pages(inode);
	unsigned chunk_mask = ~(UFS_SB(sb)->s_uspi->s_dirblksize - 1);
	int need_revalidate = file->f_version != inode->i_version;
	unsigned flags = UFS_SB(sb)->s_flags;

	UFSD("BEGIN\n");

	if (pos > inode->i_size - UFS_DIR_REC_LEN(1))
		return 0;

	for ( ; n < npages; n++, offset = 0) {
		char *kaddr, *limit;
		struct ufs_dir_entry *de;

		struct page *page = ufs_get_page(inode, n);

		if (IS_ERR(page)) {
			ufs_error(sb, __func__,
				  "bad page in #%lu",
				  inode->i_ino);
			ctx->pos += PAGE_CACHE_SIZE - offset;
			return -EIO;
		}
		kaddr = page_address(page);
		if (unlikely(need_revalidate)) {
			if (offset) {
				offset = ufs_validate_entry(sb, kaddr, offset, chunk_mask);
				ctx->pos = (n<<PAGE_CACHE_SHIFT) + offset;
			}
			file->f_version = inode->i_version;
			need_revalidate = 0;
		}
		de = (struct ufs_dir_entry *)(kaddr+offset);
		limit = kaddr + ufs_last_byte(inode, n) - UFS_DIR_REC_LEN(1);
		for ( ;(char*)de <= limit; de = ufs_next_entry(sb, de)) {
			if (de->d_reclen == 0) {
				ufs_error(sb, __func__,
					"zero-length directory entry");
				ufs_put_page(page);
				return -EIO;
			}
			if (de->d_ino) {
				unsigned char d_type = DT_UNKNOWN;

				UFSD("filldir(%s,%u)\n", de->d_name,
				      fs32_to_cpu(sb, de->d_ino));
				UFSD("namlen %u\n", ufs_get_de_namlen(sb, de));

				if ((flags & UFS_DE_MASK) == UFS_DE_44BSD)
					d_type = de->d_u.d_44.d_type;

				if (!dir_emit(ctx, de->d_name,
					       ufs_get_de_namlen(sb, de),
					       fs32_to_cpu(sb, de->d_ino),
					       d_type)) {
					ufs_put_page(page);
					return 0;
				}
			}
			ctx->pos += fs16_to_cpu(sb, de->d_reclen);
		}
		ufs_put_page(page);
	}
	return 0;
}


/*
 * ufs_delete_entry deletes a directory entry by merging it with the
 * previous entry.
 */
int ufs_delete_entry(struct inode *inode, struct ufs_dir_entry *dir,
		     struct page * page)
{
	struct super_block *sb = inode->i_sb;
	char *kaddr = page_address(page);
	unsigned from = ((char*)dir - kaddr) & ~(UFS_SB(sb)->s_uspi->s_dirblksize - 1);
	unsigned to = ((char*)dir - kaddr) + fs16_to_cpu(sb, dir->d_reclen);
	loff_t pos;
	struct ufs_dir_entry *pde = NULL;
	struct ufs_dir_entry *de = (struct ufs_dir_entry *) (kaddr + from);
	int err;

	UFSD("ENTER\n");

	UFSD("ino %u, reclen %u, namlen %u, name %s\n",
	      fs32_to_cpu(sb, de->d_ino),
	      fs16_to_cpu(sb, de->d_reclen),
	      ufs_get_de_namlen(sb, de), de->d_name);

	while ((char*)de < (char*)dir) {
		if (de->d_reclen == 0) {
			ufs_error(inode->i_sb, __func__,
				  "zero-length directory entry");
			err = -EIO;
			goto out;
		}
		pde = de;
		de = ufs_next_entry(sb, de);
	}
	if (pde)
		from = (char*)pde - (char*)page_address(page);

	pos = page_offset(page) + from;
	lock_page(page);
	err = ufs_prepare_chunk(page, pos, to - from);
	BUG_ON(err);
	if (pde)
		pde->d_reclen = cpu_to_fs16(sb, to - from);
	dir->d_ino = 0;
	err = ufs_commit_chunk(page, pos, to - from);
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);
out:
	ufs_put_page(page);
	UFSD("EXIT\n");
	return err;
}

int ufs_make_empty(struct inode * inode, struct inode *dir)
{
	struct super_block * sb = dir->i_sb;
	struct address_space *mapping = inode->i_mapping;
	struct page *page = grab_cache_page(mapping, 0);
	const unsigned int chunk_size = UFS_SB(sb)->s_uspi->s_dirblksize;
	struct ufs_dir_entry * de;
	char *base;
	int err;

	if (!page)
		return -ENOMEM;

	err = ufs_prepare_chunk(page, 0, chunk_size);
	if (err) {
		unlock_page(page);
		goto fail;
	}

	kmap(page);
	base = (char*)page_address(page);
	memset(base, 0, PAGE_CACHE_SIZE);

	de = (struct ufs_dir_entry *) base;

	de->d_ino = cpu_to_fs32(sb, inode->i_ino);
	ufs_set_de_type(sb, de, inode->i_mode);
	ufs_set_de_namlen(sb, de, 1);
	de->d_reclen = cpu_to_fs16(sb, UFS_DIR_REC_LEN(1));
	strcpy (de->d_name, ".");
	de = (struct ufs_dir_entry *)
		((char *)de + fs16_to_cpu(sb, de->d_reclen));
	de->d_ino = cpu_to_fs32(sb, dir->i_ino);
	ufs_set_de_type(sb, de, dir->i_mode);
	de->d_reclen = cpu_to_fs16(sb, chunk_size - UFS_DIR_REC_LEN(1));
	ufs_set_de_namlen(sb, de, 2);
	strcpy (de->d_name, "..");
	kunmap(page);

	err = ufs_commit_chunk(page, 0, chunk_size);
fail:
	page_cache_release(page);
	return err;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
int ufs_empty_dir(struct inode * inode)
{
	struct super_block *sb = inode->i_sb;
	struct page *page = NULL;
	unsigned long i, npages = ufs_dir_pages(inode);

	for (i = 0; i < npages; i++) {
		char *kaddr;
		struct ufs_dir_entry *de;
		page = ufs_get_page(inode, i);

		if (IS_ERR(page))
			continue;

		kaddr = page_address(page);
		de = (struct ufs_dir_entry *)kaddr;
		kaddr += ufs_last_byte(inode, i) - UFS_DIR_REC_LEN(1);

		while ((char *)de <= kaddr) {
			if (de->d_reclen == 0) {
				ufs_error(inode->i_sb, __func__,
					"zero-length directory entry: "
					"kaddr=%p, de=%p\n", kaddr, de);
				goto not_empty;
			}
			if (de->d_ino) {
				u16 namelen=ufs_get_de_namlen(sb, de);
				/* check for . and .. */
				if (de->d_name[0] != '.')
					goto not_empty;
				if (namelen > 2)
					goto not_empty;
				if (namelen < 2) {
					if (inode->i_ino !=
					    fs32_to_cpu(sb, de->d_ino))
						goto not_empty;
				} else if (de->d_name[1] != '.')
					goto not_empty;
			}
			de = ufs_next_entry(sb, de);
		}
		ufs_put_page(page);
	}
	return 1;

not_empty:
	ufs_put_page(page);
	return 0;
}

const struct file_operations ufs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= ufs_readdir,
	.fsync		= generic_file_fsync,
	.llseek		= generic_file_llseek,
};
/************************************************************/
/* ../linux-3.17/fs/ufs/dir.c */
/************************************************************/
/*
 *  linux/fs/ufs/file.c
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 *  from
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
 *  ext2 fs regular file handling primitives
 */

// #include <linux/fs.h>

// #include "ufs_fs.h"
// #include "ufs.h"

/*
 * We have mostly NULL's here: the current defaults are ok for
 * the ufs filesystem.
 */

const struct file_operations ufs_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.open           = generic_file_open,
	.fsync		= generic_file_fsync,
	.splice_read	= generic_file_splice_read,
};
/************************************************************/
/* ../linux-3.17/fs/ufs/file.c */
/************************************************************/
/*
 *  linux/fs/ufs/ialloc.c
 *
 * Copyright (c) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 *  from
 *
 *  linux/fs/ext2/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by
 *  Stephen Tweedie (sct@dcs.ed.ac.uk), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * UFS2 write support added by
 * Evgeniy Dushistov <dushistov@mail.ru>, 2007
 */

// #include <linux/fs.h>
// #include <linux/time.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/buffer_head.h>
#include <linux/sched.h>
// #include <linux/bitops.h>
// #include <asm/byteorder.h>

// #include "ufs_fs.h"
// #include "ufs.h"
// #include "swab.h"
// #include "util.h"

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 *
 * HOWEVER: we must make sure that we get no aliases,
 * which means that we have to call "clear_inode()"
 * _before_ we mark the inode not in use in the inode
 * bitmaps. Otherwise a newly created file might use
 * the same inode number (not actually the same pointer
 * though), and then we'd have two inodes sharing the
 * same inode number and space on the harddisk.
 */
void ufs_free_inode (struct inode * inode)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	struct ufs_cylinder_group * ucg;
	int is_directory;
	unsigned ino, cg, bit;

	UFSD("ENTER, ino %lu\n", inode->i_ino);

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;

	ino = inode->i_ino;

	lock_ufs(sb);

	if (!((ino > 1) && (ino < (uspi->s_ncg * uspi->s_ipg )))) {
		ufs_warning(sb, "ufs_free_inode", "reserved inode or nonexistent inode %u\n", ino);
		unlock_ufs(sb);
		return;
	}

	cg = ufs_inotocg (ino);
	bit = ufs_inotocgoff (ino);
	ucpi = ufs_load_cylinder (sb, cg);
	if (!ucpi) {
		unlock_ufs(sb);
		return;
	}
	ucg = ubh_get_ucg(UCPI_UBH(ucpi));
	if (!ufs_cg_chkmagic(sb, ucg))
		ufs_panic (sb, "ufs_free_fragments", "internal error, bad cg magic number");

	ucg->cg_time = cpu_to_fs32(sb, get_seconds());

	is_directory = S_ISDIR(inode->i_mode);

	if (ubh_isclr (UCPI_UBH(ucpi), ucpi->c_iusedoff, bit))
		ufs_error(sb, "ufs_free_inode", "bit already cleared for inode %u", ino);
	else {
		ubh_clrbit (UCPI_UBH(ucpi), ucpi->c_iusedoff, bit);
		if (ino < ucpi->c_irotor)
			ucpi->c_irotor = ino;
		fs32_add(sb, &ucg->cg_cs.cs_nifree, 1);
		uspi->cs_total.cs_nifree++;
		fs32_add(sb, &UFS_SB(sb)->fs_cs(cg).cs_nifree, 1);

		if (is_directory) {
			fs32_sub(sb, &ucg->cg_cs.cs_ndir, 1);
			uspi->cs_total.cs_ndir--;
			fs32_sub(sb, &UFS_SB(sb)->fs_cs(cg).cs_ndir, 1);
		}
	}

	ubh_mark_buffer_dirty (USPI_UBH(uspi));
	ubh_mark_buffer_dirty (UCPI_UBH(ucpi));
	if (sb->s_flags & MS_SYNCHRONOUS)
		ubh_sync_block(UCPI_UBH(ucpi));

	ufs_mark_sb_dirty(sb);
	unlock_ufs(sb);
	UFSD("EXIT\n");
}

/*
 * Nullify new chunk of inodes,
 * BSD people also set ui_gen field of inode
 * during nullification, but we not care about
 * that because of linux ufs do not support NFS
 */
static void ufs2_init_inodes_chunk(struct super_block *sb,
				   struct ufs_cg_private_info *ucpi,
				   struct ufs_cylinder_group *ucg)
{
	struct buffer_head *bh;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	sector_t beg = uspi->s_sbbase +
		ufs_inotofsba(ucpi->c_cgx * uspi->s_ipg +
			      fs32_to_cpu(sb, ucg->cg_u.cg_u2.cg_initediblk));
	sector_t end = beg + uspi->s_fpb;

	UFSD("ENTER cgno %d\n", ucpi->c_cgx);

	for (; beg < end; ++beg) {
		bh = sb_getblk(sb, beg);
		lock_buffer(bh);
		memset(bh->b_data, 0, sb->s_blocksize);
		set_buffer_uptodate(bh);
		mark_buffer_dirty(bh);
		unlock_buffer(bh);
		if (sb->s_flags & MS_SYNCHRONOUS)
			sync_dirty_buffer(bh);
		brelse(bh);
	}

	fs32_add(sb, &ucg->cg_u.cg_u2.cg_initediblk, uspi->s_inopb);
	ubh_mark_buffer_dirty(UCPI_UBH(ucpi));
	if (sb->s_flags & MS_SYNCHRONOUS)
		ubh_sync_block(UCPI_UBH(ucpi));

	UFSD("EXIT\n");
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory's block
 * group to find a free inode.
 */
struct inode *ufs_new_inode(struct inode *dir, umode_t mode)
{
	struct super_block * sb;
	struct ufs_sb_info * sbi;
	struct ufs_sb_private_info * uspi;
	struct ufs_cg_private_info * ucpi;
	struct ufs_cylinder_group * ucg;
	struct inode * inode;
	unsigned cg, bit, i, j, start;
	struct ufs_inode_info *ufsi;
	int err = -ENOSPC;

	UFSD("ENTER\n");

	/* Cannot create files in a deleted directory */
	if (!dir || !dir->i_nlink)
		return ERR_PTR(-EPERM);
	sb = dir->i_sb;
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	ufsi = UFS_I(inode);
	sbi = UFS_SB(sb);
	uspi = sbi->s_uspi;

	lock_ufs(sb);

	/*
	 * Try to place the inode in its parent directory
	 */
	i = ufs_inotocg(dir->i_ino);
	if (sbi->fs_cs(i).cs_nifree) {
		cg = i;
		goto cg_found;
	}

	/*
	 * Use a quadratic hash to find a group with a free inode
	 */
	for ( j = 1; j < uspi->s_ncg; j <<= 1 ) {
		i += j;
		if (i >= uspi->s_ncg)
			i -= uspi->s_ncg;
		if (sbi->fs_cs(i).cs_nifree) {
			cg = i;
			goto cg_found;
		}
	}

	/*
	 * That failed: try linear search for a free inode
	 */
	i = ufs_inotocg(dir->i_ino) + 1;
	for (j = 2; j < uspi->s_ncg; j++) {
		i++;
		if (i >= uspi->s_ncg)
			i = 0;
		if (sbi->fs_cs(i).cs_nifree) {
			cg = i;
			goto cg_found;
		}
	}

	goto failed;

cg_found:
	ucpi = ufs_load_cylinder (sb, cg);
	if (!ucpi) {
		err = -EIO;
		goto failed;
	}
	ucg = ubh_get_ucg(UCPI_UBH(ucpi));
	if (!ufs_cg_chkmagic(sb, ucg))
		ufs_panic (sb, "ufs_new_inode", "internal error, bad cg magic number");

	start = ucpi->c_irotor;
	bit = ubh_find_next_zero_bit (UCPI_UBH(ucpi), ucpi->c_iusedoff, uspi->s_ipg, start);
	if (!(bit < uspi->s_ipg)) {
		bit = ubh_find_first_zero_bit (UCPI_UBH(ucpi), ucpi->c_iusedoff, start);
		if (!(bit < start)) {
			ufs_error (sb, "ufs_new_inode",
			    "cylinder group %u corrupted - error in inode bitmap\n", cg);
			err = -EIO;
			goto failed;
		}
	}
	UFSD("start = %u, bit = %u, ipg = %u\n", start, bit, uspi->s_ipg);
	if (ubh_isclr (UCPI_UBH(ucpi), ucpi->c_iusedoff, bit))
		ubh_setbit (UCPI_UBH(ucpi), ucpi->c_iusedoff, bit);
	else {
		ufs_panic (sb, "ufs_new_inode", "internal error");
		err = -EIO;
		goto failed;
	}

	if (uspi->fs_magic == UFS2_MAGIC) {
		u32 initediblk = fs32_to_cpu(sb, ucg->cg_u.cg_u2.cg_initediblk);

		if (bit + uspi->s_inopb > initediblk &&
		    initediblk < fs32_to_cpu(sb, ucg->cg_u.cg_u2.cg_niblk))
			ufs2_init_inodes_chunk(sb, ucpi, ucg);
	}

	fs32_sub(sb, &ucg->cg_cs.cs_nifree, 1);
	uspi->cs_total.cs_nifree--;
	fs32_sub(sb, &sbi->fs_cs(cg).cs_nifree, 1);

	if (S_ISDIR(mode)) {
		fs32_add(sb, &ucg->cg_cs.cs_ndir, 1);
		uspi->cs_total.cs_ndir++;
		fs32_add(sb, &sbi->fs_cs(cg).cs_ndir, 1);
	}
	ubh_mark_buffer_dirty (USPI_UBH(uspi));
	ubh_mark_buffer_dirty (UCPI_UBH(ucpi));
	if (sb->s_flags & MS_SYNCHRONOUS)
		ubh_sync_block(UCPI_UBH(ucpi));
	ufs_mark_sb_dirty(sb);

	inode->i_ino = cg * uspi->s_ipg + bit;
	inode_init_owner(inode, dir, mode);
	inode->i_blocks = 0;
	inode->i_generation = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME_SEC;
	ufsi->i_flags = UFS_I(dir)->i_flags;
	ufsi->i_lastfrag = 0;
	ufsi->i_shadow = 0;
	ufsi->i_osync = 0;
	ufsi->i_oeftflag = 0;
	ufsi->i_dir_start_lookup = 0;
	memset(&ufsi->i_u1, 0, sizeof(ufsi->i_u1));
	insert_inode_hash(inode);
	mark_inode_dirty(inode);

	if (uspi->fs_magic == UFS2_MAGIC) {
		struct buffer_head *bh;
		struct ufs2_inode *ufs2_inode;

		/*
		 * setup birth date, we do it here because of there is no sense
		 * to hold it in struct ufs_inode_info, and lose 64 bit
		 */
		bh = sb_bread(sb, uspi->s_sbbase + ufs_inotofsba(inode->i_ino));
		if (!bh) {
			ufs_warning(sb, "ufs_read_inode",
				    "unable to read inode %lu\n",
				    inode->i_ino);
			err = -EIO;
			goto fail_remove_inode;
		}
		lock_buffer(bh);
		ufs2_inode = (struct ufs2_inode *)bh->b_data;
		ufs2_inode += ufs_inotofsbo(inode->i_ino);
		ufs2_inode->ui_birthtime = cpu_to_fs64(sb, CURRENT_TIME.tv_sec);
		ufs2_inode->ui_birthnsec = cpu_to_fs32(sb, CURRENT_TIME.tv_nsec);
		mark_buffer_dirty(bh);
		unlock_buffer(bh);
		if (sb->s_flags & MS_SYNCHRONOUS)
			sync_dirty_buffer(bh);
		brelse(bh);
	}
	unlock_ufs(sb);

	UFSD("allocating inode %lu\n", inode->i_ino);
	UFSD("EXIT\n");
	return inode;

fail_remove_inode:
	unlock_ufs(sb);
	clear_nlink(inode);
	iput(inode);
	UFSD("EXIT (FAILED): err %d\n", err);
	return ERR_PTR(err);
failed:
	unlock_ufs(sb);
	make_bad_inode(inode);
	iput (inode);
	UFSD("EXIT (FAILED): err %d\n", err);
	return ERR_PTR(err);
}
/************************************************************/
/* ../linux-3.17/fs/ufs/ialloc.c */
/************************************************************/
/*
 *  linux/fs/ufs/inode.c
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 *  from
 *
 *  linux/fs/ext2/inode.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Goal-directed block allocation by Stephen Tweedie (sct@dcs.ed.ac.uk), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include <asm/uaccess.h>

#include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/time.h>
// #include <linux/stat.h>
// #include <linux/string.h>
#include <linux/mm.h>
// #include <linux/buffer_head.h>
#include <linux/writeback.h>

// #include "ufs_fs.h"
// #include "ufs.h"
// #include "swab.h"
// #include "util.h"

static u64 ufs_frag_map(struct inode *inode, sector_t frag, bool needs_lock);

static int ufs_block_to_path(struct inode *inode, sector_t i_block, sector_t offsets[4])
{
	struct ufs_sb_private_info *uspi = UFS_SB(inode->i_sb)->s_uspi;
	int ptrs = uspi->s_apb;
	int ptrs_bits = uspi->s_apbshift;
	const long direct_blocks = UFS_NDADDR,
		indirect_blocks = ptrs,
		double_blocks = (1 << (ptrs_bits * 2));
	int n = 0;


	UFSD("ptrs=uspi->s_apb = %d,double_blocks=%ld \n",ptrs,double_blocks);
	if (i_block < direct_blocks) {
		offsets[n++] = i_block;
	} else if ((i_block -= direct_blocks) < indirect_blocks) {
		offsets[n++] = UFS_IND_BLOCK;
		offsets[n++] = i_block;
	} else if ((i_block -= indirect_blocks) < double_blocks) {
		offsets[n++] = UFS_DIND_BLOCK;
		offsets[n++] = i_block >> ptrs_bits;
		offsets[n++] = i_block & (ptrs - 1);
	} else if (((i_block -= double_blocks) >> (ptrs_bits * 2)) < ptrs) {
		offsets[n++] = UFS_TIND_BLOCK;
		offsets[n++] = i_block >> (ptrs_bits * 2);
		offsets[n++] = (i_block >> ptrs_bits) & (ptrs - 1);
		offsets[n++] = i_block & (ptrs - 1);
	} else {
		ufs_warning(inode->i_sb, "ufs_block_to_path", "block > big");
	}
	return n;
}

/*
 * Returns the location of the fragment from
 * the beginning of the filesystem.
 */

static u64 ufs_frag_map(struct inode *inode, sector_t frag, bool needs_lock)
{
	struct ufs_inode_info *ufsi = UFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	u64 mask = (u64) uspi->s_apbmask>>uspi->s_fpbshift;
	int shift = uspi->s_apbshift-uspi->s_fpbshift;
	sector_t offsets[4], *p;
	int depth = ufs_block_to_path(inode, frag >> uspi->s_fpbshift, offsets);
	u64  ret = 0L;
	__fs32 block;
	__fs64 u2_block = 0L;
	unsigned flags = UFS_SB(sb)->s_flags;
	u64 temp = 0L;

	UFSD(": frag = %llu  depth = %d\n", (unsigned long long)frag, depth);
	UFSD(": uspi->s_fpbshift = %d ,uspi->s_apbmask = %x, mask=%llx\n",
		uspi->s_fpbshift, uspi->s_apbmask,
		(unsigned long long)mask);

	if (depth == 0)
		return 0;

	p = offsets;

	if (needs_lock)
		lock_ufs(sb);
	if ((flags & UFS_TYPE_MASK) == UFS_TYPE_UFS2)
		goto ufs2;

	block = ufsi->i_u1.i_data[*p++];
	if (!block)
		goto out;
	while (--depth) {
		struct buffer_head *bh;
		sector_t n = *p++;

		bh = sb_bread(sb, uspi->s_sbbase + fs32_to_cpu(sb, block)+(n>>shift));
		if (!bh)
			goto out;
		block = ((__fs32 *) bh->b_data)[n & mask];
		brelse (bh);
		if (!block)
			goto out;
	}
	ret = (u64) (uspi->s_sbbase + fs32_to_cpu(sb, block) + (frag & uspi->s_fpbmask));
	goto out;
ufs2:
	u2_block = ufsi->i_u1.u2_i_data[*p++];
	if (!u2_block)
		goto out;


	while (--depth) {
		struct buffer_head *bh;
		sector_t n = *p++;


		temp = (u64)(uspi->s_sbbase) + fs64_to_cpu(sb, u2_block);
		bh = sb_bread(sb, temp +(u64) (n>>shift));
		if (!bh)
			goto out;
		u2_block = ((__fs64 *)bh->b_data)[n & mask];
		brelse(bh);
		if (!u2_block)
			goto out;
	}
	temp = (u64)uspi->s_sbbase + fs64_to_cpu(sb, u2_block);
	ret = temp + (u64) (frag & uspi->s_fpbmask);

out:
	if (needs_lock)
		unlock_ufs(sb);
	return ret;
}

/**
 * ufs_inode_getfrag() - allocate new fragment(s)
 * @inode: pointer to inode
 * @fragment: number of `fragment' which hold pointer
 *   to new allocated fragment(s)
 * @new_fragment: number of new allocated fragment(s)
 * @required: how many fragment(s) we require
 * @err: we set it if something wrong
 * @phys: pointer to where we save physical number of new allocated fragments,
 *   NULL if we allocate not data(indirect blocks for example).
 * @new: we set it if we allocate new block
 * @locked_page: for ufs_new_fragments()
 */
static struct buffer_head *
ufs_inode_getfrag(struct inode *inode, u64 fragment,
		  sector_t new_fragment, unsigned int required, int *err,
		  long *phys, int *new, struct page *locked_page)
{
	struct ufs_inode_info *ufsi = UFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	struct buffer_head * result;
	unsigned blockoff, lastblockoff;
	u64 tmp, goal, lastfrag, block, lastblock;
	void *p, *p2;

	UFSD("ENTER, ino %lu, fragment %llu, new_fragment %llu, required %u, "
	     "metadata %d\n", inode->i_ino, (unsigned long long)fragment,
	     (unsigned long long)new_fragment, required, !phys);

        /* TODO : to be done for write support
        if ( (flags & UFS_TYPE_MASK) == UFS_TYPE_UFS2)
             goto ufs2;
         */

	block = ufs_fragstoblks (fragment);
	blockoff = ufs_fragnum (fragment);
	p = ufs_get_direct_data_ptr(uspi, ufsi, block);

	goal = 0;

repeat:
	tmp = ufs_data_ptr_to_cpu(sb, p);

	lastfrag = ufsi->i_lastfrag;
	if (tmp && fragment < lastfrag) {
		if (!phys) {
			result = sb_getblk(sb, uspi->s_sbbase + tmp + blockoff);
			if (tmp == ufs_data_ptr_to_cpu(sb, p)) {
				UFSD("EXIT, result %llu\n",
				     (unsigned long long)tmp + blockoff);
				return result;
			}
			brelse (result);
			goto repeat;
		} else {
			*phys = uspi->s_sbbase + tmp + blockoff;
			return NULL;
		}
	}

	lastblock = ufs_fragstoblks (lastfrag);
	lastblockoff = ufs_fragnum (lastfrag);
	/*
	 * We will extend file into new block beyond last allocated block
	 */
	if (lastblock < block) {
		/*
		 * We must reallocate last allocated block
		 */
		if (lastblockoff) {
			p2 = ufs_get_direct_data_ptr(uspi, ufsi, lastblock);
			tmp = ufs_new_fragments(inode, p2, lastfrag,
						ufs_data_ptr_to_cpu(sb, p2),
						uspi->s_fpb - lastblockoff,
						err, locked_page);
			if (!tmp) {
				if (lastfrag != ufsi->i_lastfrag)
					goto repeat;
				else
					return NULL;
			}
			lastfrag = ufsi->i_lastfrag;

		}
		tmp = ufs_data_ptr_to_cpu(sb,
					 ufs_get_direct_data_ptr(uspi, ufsi,
								 lastblock));
		if (tmp)
			goal = tmp + uspi->s_fpb;
		tmp = ufs_new_fragments (inode, p, fragment - blockoff,
					 goal, required + blockoff,
					 err,
					 phys != NULL ? locked_page : NULL);
	} else if (lastblock == block) {
	/*
	 * We will extend last allocated block
	 */
		tmp = ufs_new_fragments(inode, p, fragment -
					(blockoff - lastblockoff),
					ufs_data_ptr_to_cpu(sb, p),
					required +  (blockoff - lastblockoff),
					err, phys != NULL ? locked_page : NULL);
	} else /* (lastblock > block) */ {
	/*
	 * We will allocate new block before last allocated block
	 */
		if (block) {
			tmp = ufs_data_ptr_to_cpu(sb,
						 ufs_get_direct_data_ptr(uspi, ufsi, block - 1));
			if (tmp)
				goal = tmp + uspi->s_fpb;
		}
		tmp = ufs_new_fragments(inode, p, fragment - blockoff,
					goal, uspi->s_fpb, err,
					phys != NULL ? locked_page : NULL);
	}
	if (!tmp) {
		if ((!blockoff && ufs_data_ptr_to_cpu(sb, p)) ||
		    (blockoff && lastfrag != ufsi->i_lastfrag))
			goto repeat;
		*err = -ENOSPC;
		return NULL;
	}

	if (!phys) {
		result = sb_getblk(sb, uspi->s_sbbase + tmp + blockoff);
	} else {
		*phys = uspi->s_sbbase + tmp + blockoff;
		result = NULL;
		*err = 0;
		*new = 1;
	}

	inode->i_ctime = CURRENT_TIME_SEC;
	if (IS_SYNC(inode))
		ufs_sync_inode (inode);
	mark_inode_dirty(inode);
	UFSD("EXIT, result %llu\n", (unsigned long long)tmp + blockoff);
	return result;

     /* This part : To be implemented ....
        Required only for writing, not required for READ-ONLY.
ufs2:

	u2_block = ufs_fragstoblks(fragment);
	u2_blockoff = ufs_fragnum(fragment);
	p = ufsi->i_u1.u2_i_data + block;
	goal = 0;

repeat2:
	tmp = fs32_to_cpu(sb, *p);
	lastfrag = ufsi->i_lastfrag;

     */
}

/**
 * ufs_inode_getblock() - allocate new block
 * @inode: pointer to inode
 * @bh: pointer to block which hold "pointer" to new allocated block
 * @fragment: number of `fragment' which hold pointer
 *   to new allocated block
 * @new_fragment: number of new allocated fragment
 *  (block will hold this fragment and also uspi->s_fpb-1)
 * @err: see ufs_inode_getfrag()
 * @phys: see ufs_inode_getfrag()
 * @new: see ufs_inode_getfrag()
 * @locked_page: see ufs_inode_getfrag()
 */
static struct buffer_head *
ufs_inode_getblock(struct inode *inode, struct buffer_head *bh,
		  u64 fragment, sector_t new_fragment, int *err,
		  long *phys, int *new, struct page *locked_page)
{
	struct super_block *sb = inode->i_sb;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	struct buffer_head * result;
	unsigned blockoff;
	u64 tmp, goal, block;
	void *p;

	block = ufs_fragstoblks (fragment);
	blockoff = ufs_fragnum (fragment);

	UFSD("ENTER, ino %lu, fragment %llu, new_fragment %llu, metadata %d\n",
	     inode->i_ino, (unsigned long long)fragment,
	     (unsigned long long)new_fragment, !phys);

	result = NULL;
	if (!bh)
		goto out;
	if (!buffer_uptodate(bh)) {
		ll_rw_block (READ, 1, &bh);
		wait_on_buffer (bh);
		if (!buffer_uptodate(bh))
			goto out;
	}
	if (uspi->fs_magic == UFS2_MAGIC)
		p = (__fs64 *)bh->b_data + block;
	else
		p = (__fs32 *)bh->b_data + block;
repeat:
	tmp = ufs_data_ptr_to_cpu(sb, p);
	if (tmp) {
		if (!phys) {
			result = sb_getblk(sb, uspi->s_sbbase + tmp + blockoff);
			if (tmp == ufs_data_ptr_to_cpu(sb, p))
				goto out;
			brelse (result);
			goto repeat;
		} else {
			*phys = uspi->s_sbbase + tmp + blockoff;
			goto out;
		}
	}

	if (block && (uspi->fs_magic == UFS2_MAGIC ?
		      (tmp = fs64_to_cpu(sb, ((__fs64 *)bh->b_data)[block-1])) :
		      (tmp = fs32_to_cpu(sb, ((__fs32 *)bh->b_data)[block-1]))))
		goal = tmp + uspi->s_fpb;
	else
		goal = bh->b_blocknr + uspi->s_fpb;
	tmp = ufs_new_fragments(inode, p, ufs_blknum(new_fragment), goal,
				uspi->s_fpb, err, locked_page);
	if (!tmp) {
		if (ufs_data_ptr_to_cpu(sb, p))
			goto repeat;
		goto out;
	}


	if (!phys) {
		result = sb_getblk(sb, uspi->s_sbbase + tmp + blockoff);
	} else {
		*phys = uspi->s_sbbase + tmp + blockoff;
		*new = 1;
	}

	mark_buffer_dirty(bh);
	if (IS_SYNC(inode))
		sync_dirty_buffer(bh);
	inode->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);
	UFSD("result %llu\n", (unsigned long long)tmp + blockoff);
out:
	brelse (bh);
	UFSD("EXIT\n");
	return result;
}

/**
 * ufs_getfrag_block() - `get_block_t' function, interface between UFS and
 * readpage, writepage and so on
 */

int ufs_getfrag_block(struct inode *inode, sector_t fragment, struct buffer_head *bh_result, int create)
{
	struct super_block * sb = inode->i_sb;
	struct ufs_sb_info * sbi = UFS_SB(sb);
	struct ufs_sb_private_info * uspi = sbi->s_uspi;
	struct buffer_head * bh;
	int ret, err, new;
	unsigned long ptr,phys;
	u64 phys64 = 0;
	bool needs_lock = (sbi->mutex_owner != current);

	if (!create) {
		phys64 = ufs_frag_map(inode, fragment, needs_lock);
		UFSD("phys64 = %llu\n", (unsigned long long)phys64);
		if (phys64)
			map_bh(bh_result, sb, phys64);
		return 0;
	}

        /* This code entered only while writing ....? */

	err = -EIO;
	new = 0;
	ret = 0;
	bh = NULL;

	if (needs_lock)
		lock_ufs(sb);

	UFSD("ENTER, ino %lu, fragment %llu\n", inode->i_ino, (unsigned long long)fragment);
	if (fragment >
	    ((UFS_NDADDR + uspi->s_apb + uspi->s_2apb + uspi->s_3apb)
	     << uspi->s_fpbshift))
		goto abort_too_big;

	err = 0;
	ptr = fragment;

	/*
	 * ok, these macros clean the logic up a bit and make
	 * it much more readable:
	 */
#define GET_INODE_DATABLOCK(x) \
	ufs_inode_getfrag(inode, x, fragment, 1, &err, &phys, &new,\
			  bh_result->b_page)
#define GET_INODE_PTR(x) \
	ufs_inode_getfrag(inode, x, fragment, uspi->s_fpb, &err, NULL, NULL,\
			  bh_result->b_page)
#define GET_INDIRECT_DATABLOCK(x) \
	ufs_inode_getblock(inode, bh, x, fragment,	\
			  &err, &phys, &new, bh_result->b_page)
#define GET_INDIRECT_PTR(x) \
	ufs_inode_getblock(inode, bh, x, fragment,	\
			  &err, NULL, NULL, NULL)

	if (ptr < UFS_NDIR_FRAGMENT) {
		bh = GET_INODE_DATABLOCK(ptr);
		goto out;
	}
	ptr -= UFS_NDIR_FRAGMENT;
	if (ptr < (1 << (uspi->s_apbshift + uspi->s_fpbshift))) {
		bh = GET_INODE_PTR(UFS_IND_FRAGMENT + (ptr >> uspi->s_apbshift));
		goto get_indirect;
	}
	ptr -= 1 << (uspi->s_apbshift + uspi->s_fpbshift);
	if (ptr < (1 << (uspi->s_2apbshift + uspi->s_fpbshift))) {
		bh = GET_INODE_PTR(UFS_DIND_FRAGMENT + (ptr >> uspi->s_2apbshift));
		goto get_double;
	}
	ptr -= 1 << (uspi->s_2apbshift + uspi->s_fpbshift);
	bh = GET_INODE_PTR(UFS_TIND_FRAGMENT + (ptr >> uspi->s_3apbshift));
	bh = GET_INDIRECT_PTR((ptr >> uspi->s_2apbshift) & uspi->s_apbmask);
get_double:
	bh = GET_INDIRECT_PTR((ptr >> uspi->s_apbshift) & uspi->s_apbmask);
get_indirect:
	bh = GET_INDIRECT_DATABLOCK(ptr & uspi->s_apbmask);

#undef GET_INODE_DATABLOCK
#undef GET_INODE_PTR
#undef GET_INDIRECT_DATABLOCK
#undef GET_INDIRECT_PTR

out:
	if (err)
		goto abort;
	if (new)
		set_buffer_new(bh_result);
	map_bh(bh_result, sb, phys);
abort:
	if (needs_lock)
		unlock_ufs(sb);

	return err;

abort_too_big:
	ufs_warning(sb, "ufs_get_block", "block > big");
	goto abort;
}

static int ufs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page,ufs_getfrag_block,wbc);
}

static int ufs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page,ufs_getfrag_block);
}

int ufs_prepare_chunk(struct page *page, loff_t pos, unsigned len)
{
	return __block_write_begin(page, pos, len, ufs_getfrag_block);
}

static void ufs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size)
		truncate_pagecache(inode, inode->i_size);
}

static int ufs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	ret = block_write_begin(mapping, pos, len, flags, pagep,
				ufs_getfrag_block);
	if (unlikely(ret))
		ufs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t ufs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,ufs_getfrag_block);
}

const struct address_space_operations ufs_aops = {
	.readpage = ufs_readpage,
	.writepage = ufs_writepage,
	.write_begin = ufs_write_begin,
	.write_end = generic_write_end,
	.bmap = ufs_bmap
};

static void ufs_set_inode_ops(struct inode *inode)
{
	if (S_ISREG(inode->i_mode)) {
		inode->i_op = &ufs_file_inode_operations;
		inode->i_fop = &ufs_file_operations;
		inode->i_mapping->a_ops = &ufs_aops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &ufs_dir_inode_operations;
		inode->i_fop = &ufs_dir_operations;
		inode->i_mapping->a_ops = &ufs_aops;
	} else if (S_ISLNK(inode->i_mode)) {
		if (!inode->i_blocks)
			inode->i_op = &ufs_fast_symlink_inode_operations;
		else {
			inode->i_op = &ufs_symlink_inode_operations;
			inode->i_mapping->a_ops = &ufs_aops;
		}
	} else
		init_special_inode(inode, inode->i_mode,
				   ufs_get_inode_dev(inode->i_sb, UFS_I(inode)));
}

static int ufs1_read_inode(struct inode *inode, struct ufs_inode *ufs_inode)
{
	struct ufs_inode_info *ufsi = UFS_I(inode);
	struct super_block *sb = inode->i_sb;
	umode_t mode;

	/*
	 * Copy data to the in-core inode.
	 */
	inode->i_mode = mode = fs16_to_cpu(sb, ufs_inode->ui_mode);
	set_nlink(inode, fs16_to_cpu(sb, ufs_inode->ui_nlink));
	if (inode->i_nlink == 0) {
		ufs_error (sb, "ufs_read_inode", "inode %lu has zero nlink\n", inode->i_ino);
		return -1;
	}

	/*
	 * Linux now has 32-bit uid and gid, so we can support EFT.
	 */
	i_uid_write(inode, ufs_get_inode_uid(sb, ufs_inode));
	i_gid_write(inode, ufs_get_inode_gid(sb, ufs_inode));

	inode->i_size = fs64_to_cpu(sb, ufs_inode->ui_size);
	inode->i_atime.tv_sec = fs32_to_cpu(sb, ufs_inode->ui_atime.tv_sec);
	inode->i_ctime.tv_sec = fs32_to_cpu(sb, ufs_inode->ui_ctime.tv_sec);
	inode->i_mtime.tv_sec = fs32_to_cpu(sb, ufs_inode->ui_mtime.tv_sec);
	inode->i_mtime.tv_nsec = 0;
	inode->i_atime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	inode->i_blocks = fs32_to_cpu(sb, ufs_inode->ui_blocks);
	inode->i_generation = fs32_to_cpu(sb, ufs_inode->ui_gen);
	ufsi->i_flags = fs32_to_cpu(sb, ufs_inode->ui_flags);
	ufsi->i_shadow = fs32_to_cpu(sb, ufs_inode->ui_u3.ui_sun.ui_shadow);
	ufsi->i_oeftflag = fs32_to_cpu(sb, ufs_inode->ui_u3.ui_sun.ui_oeftflag);


	if (S_ISCHR(mode) || S_ISBLK(mode) || inode->i_blocks) {
		memcpy(ufsi->i_u1.i_data, &ufs_inode->ui_u2.ui_addr,
		       sizeof(ufs_inode->ui_u2.ui_addr));
	} else {
		memcpy(ufsi->i_u1.i_symlink, ufs_inode->ui_u2.ui_symlink,
		       sizeof(ufs_inode->ui_u2.ui_symlink) - 1);
		ufsi->i_u1.i_symlink[sizeof(ufs_inode->ui_u2.ui_symlink) - 1] = 0;
	}
	return 0;
}

static int ufs2_read_inode(struct inode *inode, struct ufs2_inode *ufs2_inode)
{
	struct ufs_inode_info *ufsi = UFS_I(inode);
	struct super_block *sb = inode->i_sb;
	umode_t mode;

	UFSD("Reading ufs2 inode, ino %lu\n", inode->i_ino);
	/*
	 * Copy data to the in-core inode.
	 */
	inode->i_mode = mode = fs16_to_cpu(sb, ufs2_inode->ui_mode);
	set_nlink(inode, fs16_to_cpu(sb, ufs2_inode->ui_nlink));
	if (inode->i_nlink == 0) {
		ufs_error (sb, "ufs_read_inode", "inode %lu has zero nlink\n", inode->i_ino);
		return -1;
	}

        /*
         * Linux now has 32-bit uid and gid, so we can support EFT.
         */
	i_uid_write(inode, fs32_to_cpu(sb, ufs2_inode->ui_uid));
	i_gid_write(inode, fs32_to_cpu(sb, ufs2_inode->ui_gid));

	inode->i_size = fs64_to_cpu(sb, ufs2_inode->ui_size);
	inode->i_atime.tv_sec = fs64_to_cpu(sb, ufs2_inode->ui_atime);
	inode->i_ctime.tv_sec = fs64_to_cpu(sb, ufs2_inode->ui_ctime);
	inode->i_mtime.tv_sec = fs64_to_cpu(sb, ufs2_inode->ui_mtime);
	inode->i_atime.tv_nsec = fs32_to_cpu(sb, ufs2_inode->ui_atimensec);
	inode->i_ctime.tv_nsec = fs32_to_cpu(sb, ufs2_inode->ui_ctimensec);
	inode->i_mtime.tv_nsec = fs32_to_cpu(sb, ufs2_inode->ui_mtimensec);
	inode->i_blocks = fs64_to_cpu(sb, ufs2_inode->ui_blocks);
	inode->i_generation = fs32_to_cpu(sb, ufs2_inode->ui_gen);
	ufsi->i_flags = fs32_to_cpu(sb, ufs2_inode->ui_flags);
	/*
	ufsi->i_shadow = fs32_to_cpu(sb, ufs_inode->ui_u3.ui_sun.ui_shadow);
	ufsi->i_oeftflag = fs32_to_cpu(sb, ufs_inode->ui_u3.ui_sun.ui_oeftflag);
	*/

	if (S_ISCHR(mode) || S_ISBLK(mode) || inode->i_blocks) {
		memcpy(ufsi->i_u1.u2_i_data, &ufs2_inode->ui_u2.ui_addr,
		       sizeof(ufs2_inode->ui_u2.ui_addr));
	} else {
		memcpy(ufsi->i_u1.i_symlink, ufs2_inode->ui_u2.ui_symlink,
		       sizeof(ufs2_inode->ui_u2.ui_symlink) - 1);
		ufsi->i_u1.i_symlink[sizeof(ufs2_inode->ui_u2.ui_symlink) - 1] = 0;
	}
	return 0;
}

struct inode *ufs_iget(struct super_block *sb, unsigned long ino)
{
	struct ufs_inode_info *ufsi;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	struct buffer_head * bh;
	struct inode *inode;
	int err;

	UFSD("ENTER, ino %lu\n", ino);

	if (ino < UFS_ROOTINO || ino > (uspi->s_ncg * uspi->s_ipg)) {
		ufs_warning(sb, "ufs_read_inode", "bad inode number (%lu)\n",
			    ino);
		return ERR_PTR(-EIO);
	}

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	ufsi = UFS_I(inode);

	bh = sb_bread(sb, uspi->s_sbbase + ufs_inotofsba(inode->i_ino));
	if (!bh) {
		ufs_warning(sb, "ufs_read_inode", "unable to read inode %lu\n",
			    inode->i_ino);
		goto bad_inode;
	}
	if ((UFS_SB(sb)->s_flags & UFS_TYPE_MASK) == UFS_TYPE_UFS2) {
		struct ufs2_inode *ufs2_inode = (struct ufs2_inode *)bh->b_data;

		err = ufs2_read_inode(inode,
				      ufs2_inode + ufs_inotofsbo(inode->i_ino));
	} else {
		struct ufs_inode *ufs_inode = (struct ufs_inode *)bh->b_data;

		err = ufs1_read_inode(inode,
				      ufs_inode + ufs_inotofsbo(inode->i_ino));
	}

	if (err)
		goto bad_inode;
	inode->i_version++;
	ufsi->i_lastfrag =
		(inode->i_size + uspi->s_fsize - 1) >> uspi->s_fshift;
	ufsi->i_dir_start_lookup = 0;
	ufsi->i_osync = 0;

	ufs_set_inode_ops(inode);

	brelse(bh);

	UFSD("EXIT\n");
	unlock_new_inode(inode);
	return inode;

bad_inode:
	iget_failed(inode);
	return ERR_PTR(-EIO);
}

static void ufs1_update_inode(struct inode *inode, struct ufs_inode *ufs_inode)
{
	struct super_block *sb = inode->i_sb;
 	struct ufs_inode_info *ufsi = UFS_I(inode);

	ufs_inode->ui_mode = cpu_to_fs16(sb, inode->i_mode);
	ufs_inode->ui_nlink = cpu_to_fs16(sb, inode->i_nlink);

	ufs_set_inode_uid(sb, ufs_inode, i_uid_read(inode));
	ufs_set_inode_gid(sb, ufs_inode, i_gid_read(inode));

	ufs_inode->ui_size = cpu_to_fs64(sb, inode->i_size);
	ufs_inode->ui_atime.tv_sec = cpu_to_fs32(sb, inode->i_atime.tv_sec);
	ufs_inode->ui_atime.tv_usec = 0;
	ufs_inode->ui_ctime.tv_sec = cpu_to_fs32(sb, inode->i_ctime.tv_sec);
	ufs_inode->ui_ctime.tv_usec = 0;
	ufs_inode->ui_mtime.tv_sec = cpu_to_fs32(sb, inode->i_mtime.tv_sec);
	ufs_inode->ui_mtime.tv_usec = 0;
	ufs_inode->ui_blocks = cpu_to_fs32(sb, inode->i_blocks);
	ufs_inode->ui_flags = cpu_to_fs32(sb, ufsi->i_flags);
	ufs_inode->ui_gen = cpu_to_fs32(sb, inode->i_generation);

	if ((UFS_SB(sb)->s_flags & UFS_UID_MASK) == UFS_UID_EFT) {
		ufs_inode->ui_u3.ui_sun.ui_shadow = cpu_to_fs32(sb, ufsi->i_shadow);
		ufs_inode->ui_u3.ui_sun.ui_oeftflag = cpu_to_fs32(sb, ufsi->i_oeftflag);
	}

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		/* ufs_inode->ui_u2.ui_addr.ui_db[0] = cpu_to_fs32(sb, inode->i_rdev); */
		ufs_inode->ui_u2.ui_addr.ui_db[0] = ufsi->i_u1.i_data[0];
	} else if (inode->i_blocks) {
		memcpy(&ufs_inode->ui_u2.ui_addr, ufsi->i_u1.i_data,
		       sizeof(ufs_inode->ui_u2.ui_addr));
	}
	else {
		memcpy(&ufs_inode->ui_u2.ui_symlink, ufsi->i_u1.i_symlink,
		       sizeof(ufs_inode->ui_u2.ui_symlink));
	}

	if (!inode->i_nlink)
		memset (ufs_inode, 0, sizeof(struct ufs_inode));
}

static void ufs2_update_inode(struct inode *inode, struct ufs2_inode *ufs_inode)
{
	struct super_block *sb = inode->i_sb;
 	struct ufs_inode_info *ufsi = UFS_I(inode);

	UFSD("ENTER\n");
	ufs_inode->ui_mode = cpu_to_fs16(sb, inode->i_mode);
	ufs_inode->ui_nlink = cpu_to_fs16(sb, inode->i_nlink);

	ufs_inode->ui_uid = cpu_to_fs32(sb, i_uid_read(inode));
	ufs_inode->ui_gid = cpu_to_fs32(sb, i_gid_read(inode));

	ufs_inode->ui_size = cpu_to_fs64(sb, inode->i_size);
	ufs_inode->ui_atime = cpu_to_fs64(sb, inode->i_atime.tv_sec);
	ufs_inode->ui_atimensec = cpu_to_fs32(sb, inode->i_atime.tv_nsec);
	ufs_inode->ui_ctime = cpu_to_fs64(sb, inode->i_ctime.tv_sec);
	ufs_inode->ui_ctimensec = cpu_to_fs32(sb, inode->i_ctime.tv_nsec);
	ufs_inode->ui_mtime = cpu_to_fs64(sb, inode->i_mtime.tv_sec);
	ufs_inode->ui_mtimensec = cpu_to_fs32(sb, inode->i_mtime.tv_nsec);

	ufs_inode->ui_blocks = cpu_to_fs64(sb, inode->i_blocks);
	ufs_inode->ui_flags = cpu_to_fs32(sb, ufsi->i_flags);
	ufs_inode->ui_gen = cpu_to_fs32(sb, inode->i_generation);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
		/* ufs_inode->ui_u2.ui_addr.ui_db[0] = cpu_to_fs32(sb, inode->i_rdev); */
		ufs_inode->ui_u2.ui_addr.ui_db[0] = ufsi->i_u1.u2_i_data[0];
	} else if (inode->i_blocks) {
		memcpy(&ufs_inode->ui_u2.ui_addr, ufsi->i_u1.u2_i_data,
		       sizeof(ufs_inode->ui_u2.ui_addr));
	} else {
		memcpy(&ufs_inode->ui_u2.ui_symlink, ufsi->i_u1.i_symlink,
		       sizeof(ufs_inode->ui_u2.ui_symlink));
 	}

	if (!inode->i_nlink)
		memset (ufs_inode, 0, sizeof(struct ufs2_inode));
	UFSD("EXIT\n");
}

static int ufs_update_inode(struct inode * inode, int do_sync)
{
	struct super_block *sb = inode->i_sb;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	struct buffer_head * bh;

	UFSD("ENTER, ino %lu\n", inode->i_ino);

	if (inode->i_ino < UFS_ROOTINO ||
	    inode->i_ino > (uspi->s_ncg * uspi->s_ipg)) {
		ufs_warning (sb, "ufs_read_inode", "bad inode number (%lu)\n", inode->i_ino);
		return -1;
	}

	bh = sb_bread(sb, ufs_inotofsba(inode->i_ino));
	if (!bh) {
		ufs_warning (sb, "ufs_read_inode", "unable to read inode %lu\n", inode->i_ino);
		return -1;
	}
	if (uspi->fs_magic == UFS2_MAGIC) {
		struct ufs2_inode *ufs2_inode = (struct ufs2_inode *)bh->b_data;

		ufs2_update_inode(inode,
				  ufs2_inode + ufs_inotofsbo(inode->i_ino));
	} else {
		struct ufs_inode *ufs_inode = (struct ufs_inode *) bh->b_data;

		ufs1_update_inode(inode, ufs_inode + ufs_inotofsbo(inode->i_ino));
	}

	mark_buffer_dirty(bh);
	if (do_sync)
		sync_dirty_buffer(bh);
	brelse (bh);

	UFSD("EXIT\n");
	return 0;
}

int ufs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int ret;
	lock_ufs(inode->i_sb);
	ret = ufs_update_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
	unlock_ufs(inode->i_sb);
	return ret;
}

int ufs_sync_inode (struct inode *inode)
{
	return ufs_update_inode (inode, 1);
}

void ufs_evict_inode(struct inode * inode)
{
	int want_delete = 0;

	if (!inode->i_nlink && !is_bad_inode(inode))
		want_delete = 1;

	truncate_inode_pages_final(&inode->i_data);
	if (want_delete) {
		loff_t old_i_size;
		/*UFS_I(inode)->i_dtime = CURRENT_TIME;*/
		lock_ufs(inode->i_sb);
		mark_inode_dirty(inode);
		ufs_update_inode(inode, IS_SYNC(inode));
		old_i_size = inode->i_size;
		inode->i_size = 0;
		if (inode->i_blocks && ufs_truncate(inode, old_i_size))
			ufs_warning(inode->i_sb, __func__, "ufs_truncate failed\n");
		unlock_ufs(inode->i_sb);
	}

	invalidate_inode_buffers(inode);
	clear_inode(inode);

	if (want_delete) {
		lock_ufs(inode->i_sb);
		ufs_free_inode (inode);
		unlock_ufs(inode->i_sb);
	}
}
/************************************************************/
/* ../linux-3.17/fs/ufs/inode.c */
/************************************************************/
/*
 * linux/fs/ufs/namei.c
 *
 * Migration to usage of "page cache" on May 2006 by
 * Evgeniy Dushistov <dushistov@mail.ru> based on ext2 code base.
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 *  from
 *
 *  linux/fs/ext2/namei.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

// #include <linux/time.h>
// #include <linux/fs.h>

// #include "ufs_fs.h"
// #include "ufs.h"
// #include "util.h"

static inline int ufs_add_nondir(struct dentry *dentry, struct inode *inode)
{
	int err = ufs_add_link(dentry, inode);
	if (!err) {
		d_instantiate(dentry, inode);
		return 0;
	}
	inode_dec_link_count(inode);
	iput(inode);
	return err;
}

static struct dentry *ufs_lookup(struct inode * dir, struct dentry *dentry, unsigned int flags)
{
	struct inode * inode = NULL;
	ino_t ino;

	if (dentry->d_name.len > UFS_MAXNAMLEN)
		return ERR_PTR(-ENAMETOOLONG);

	lock_ufs(dir->i_sb);
	ino = ufs_inode_by_name(dir, &dentry->d_name);
	if (ino)
		inode = ufs_iget(dir->i_sb, ino);
	unlock_ufs(dir->i_sb);
	return d_splice_alias(inode, dentry);
}

/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int ufs_create (struct inode * dir, struct dentry * dentry, umode_t mode,
		bool excl)
{
	struct inode *inode;
	int err;

	UFSD("BEGIN\n");

	inode = ufs_new_inode(dir, mode);
	err = PTR_ERR(inode);

	if (!IS_ERR(inode)) {
		inode->i_op = &ufs_file_inode_operations;
		inode->i_fop = &ufs_file_operations;
		inode->i_mapping->a_ops = &ufs_aops;
		mark_inode_dirty(inode);
		lock_ufs(dir->i_sb);
		err = ufs_add_nondir(dentry, inode);
		unlock_ufs(dir->i_sb);
	}
	UFSD("END: err=%d\n", err);
	return err;
}

static int ufs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct inode *inode;
	int err;

	if (!old_valid_dev(rdev))
		return -EINVAL;

	inode = ufs_new_inode(dir, mode);
	err = PTR_ERR(inode);
	if (!IS_ERR(inode)) {
		init_special_inode(inode, mode, rdev);
		ufs_set_inode_dev(inode->i_sb, UFS_I(inode), rdev);
		mark_inode_dirty(inode);
		lock_ufs(dir->i_sb);
		err = ufs_add_nondir(dentry, inode);
		unlock_ufs(dir->i_sb);
	}
	return err;
}

static int ufs_symlink (struct inode * dir, struct dentry * dentry,
	const char * symname)
{
	struct super_block * sb = dir->i_sb;
	int err = -ENAMETOOLONG;
	unsigned l = strlen(symname)+1;
	struct inode * inode;

	if (l > sb->s_blocksize)
		goto out_notlocked;

	lock_ufs(dir->i_sb);
	inode = ufs_new_inode(dir, S_IFLNK | S_IRWXUGO);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out;

	if (l > UFS_SB(sb)->s_uspi->s_maxsymlinklen) {
		/* slow symlink */
		inode->i_op = &ufs_symlink_inode_operations;
		inode->i_mapping->a_ops = &ufs_aops;
		err = page_symlink(inode, symname, l);
		if (err)
			goto out_fail;
	} else {
		/* fast symlink */
		inode->i_op = &ufs_fast_symlink_inode_operations;
		memcpy(UFS_I(inode)->i_u1.i_symlink, symname, l);
		inode->i_size = l-1;
	}
	mark_inode_dirty(inode);

	err = ufs_add_nondir(dentry, inode);
out:
	unlock_ufs(dir->i_sb);
out_notlocked:
	return err;

out_fail:
	inode_dec_link_count(inode);
	iput(inode);
	goto out;
}

static int ufs_link (struct dentry * old_dentry, struct inode * dir,
	struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int error;

	lock_ufs(dir->i_sb);

	inode->i_ctime = CURRENT_TIME_SEC;
	inode_inc_link_count(inode);
	ihold(inode);

	error = ufs_add_nondir(dentry, inode);
	unlock_ufs(dir->i_sb);
	return error;
}

static int ufs_mkdir(struct inode * dir, struct dentry * dentry, umode_t mode)
{
	struct inode * inode;
	int err;

	lock_ufs(dir->i_sb);
	inode_inc_link_count(dir);

	inode = ufs_new_inode(dir, S_IFDIR|mode);
	err = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_dir;

	inode->i_op = &ufs_dir_inode_operations;
	inode->i_fop = &ufs_dir_operations;
	inode->i_mapping->a_ops = &ufs_aops;

	inode_inc_link_count(inode);

	err = ufs_make_empty(inode, dir);
	if (err)
		goto out_fail;

	err = ufs_add_link(dentry, inode);
	if (err)
		goto out_fail;
	unlock_ufs(dir->i_sb);

	d_instantiate(dentry, inode);
out:
	return err;

out_fail:
	inode_dec_link_count(inode);
	inode_dec_link_count(inode);
	iput (inode);
out_dir:
	inode_dec_link_count(dir);
	unlock_ufs(dir->i_sb);
	goto out;
}

static int ufs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode * inode = dentry->d_inode;
	struct ufs_dir_entry *de;
	struct page *page;
	int err = -ENOENT;

	de = ufs_find_entry(dir, &dentry->d_name, &page);
	if (!de)
		goto out;

	err = ufs_delete_entry(dir, de, page);
	if (err)
		goto out;

	inode->i_ctime = dir->i_ctime;
	inode_dec_link_count(inode);
	err = 0;
out:
	return err;
}

static int ufs_rmdir (struct inode * dir, struct dentry *dentry)
{
	struct inode * inode = dentry->d_inode;
	int err= -ENOTEMPTY;

	lock_ufs(dir->i_sb);
	if (ufs_empty_dir (inode)) {
		err = ufs_unlink(dir, dentry);
		if (!err) {
			inode->i_size = 0;
			inode_dec_link_count(inode);
			inode_dec_link_count(dir);
		}
	}
	unlock_ufs(dir->i_sb);
	return err;
}

static int ufs_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct page *dir_page = NULL;
	struct ufs_dir_entry * dir_de = NULL;
	struct page *old_page;
	struct ufs_dir_entry *old_de;
	int err = -ENOENT;

	old_de = ufs_find_entry(old_dir, &old_dentry->d_name, &old_page);
	if (!old_de)
		goto out;

	if (S_ISDIR(old_inode->i_mode)) {
		err = -EIO;
		dir_de = ufs_dotdot(old_inode, &dir_page);
		if (!dir_de)
			goto out_old;
	}

	if (new_inode) {
		struct page *new_page;
		struct ufs_dir_entry *new_de;

		err = -ENOTEMPTY;
		if (dir_de && !ufs_empty_dir(new_inode))
			goto out_dir;

		err = -ENOENT;
		new_de = ufs_find_entry(new_dir, &new_dentry->d_name, &new_page);
		if (!new_de)
			goto out_dir;
		ufs_set_link(new_dir, new_de, new_page, old_inode);
		new_inode->i_ctime = CURRENT_TIME_SEC;
		if (dir_de)
			drop_nlink(new_inode);
		inode_dec_link_count(new_inode);
	} else {
		err = ufs_add_link(new_dentry, old_inode);
		if (err)
			goto out_dir;
		if (dir_de)
			inode_inc_link_count(new_dir);
	}

	/*
	 * Like most other Unix systems, set the ctime for inodes on a
 	 * rename.
	 */
	old_inode->i_ctime = CURRENT_TIME_SEC;

	ufs_delete_entry(old_dir, old_de, old_page);
	mark_inode_dirty(old_inode);

	if (dir_de) {
		ufs_set_link(old_inode, dir_de, dir_page, new_dir);
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

const struct inode_operations ufs_dir_inode_operations = {
	.create		= ufs_create,
	.lookup		= ufs_lookup,
	.link		= ufs_link,
	.unlink		= ufs_unlink,
	.symlink	= ufs_symlink,
	.mkdir		= ufs_mkdir,
	.rmdir		= ufs_rmdir,
	.mknod		= ufs_mknod,
	.rename		= ufs_rename,
};
/************************************************************/
/* ../linux-3.17/fs/ufs/namei.c */
/************************************************************/
/*
 *  linux/fs/ufs/super.c
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 */

/* Derived from
 *
 *  linux/fs/ext2/super.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/inode.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

/*
 * Inspired by
 *
 *  linux/fs/ufs/super.c
 *
 * Copyright (C) 1996
 * Adrian Rodriguez (adrian@franklins-tower.rutgers.edu)
 * Laboratory for Computer Science Research Computing Facility
 * Rutgers, The State University of New Jersey
 *
 * Copyright (C) 1996  Eddie C. Dost  (ecd@skynet.be)
 *
 * Kernel module support added on 96/04/26 by
 * Stefan Reinauer <stepan@home.culture.mipt.ru>
 *
 * Module usage counts added on 96/04/29 by
 * Gertjan van Wingerde <gwingerde@gmail.com>
 *
 * Clean swab support on 19970406 by
 * Francois-Rene Rideau <fare@tunes.org>
 *
 * 4.4BSD (FreeBSD) support added on February 1st 1998 by
 * Niels Kristian Bech Jensen <nkbj@image.dk> partially based
 * on code by Martin von Loewis <martin@mira.isdn.cs.tu-berlin.de>.
 *
 * NeXTstep support added on February 5th 1998 by
 * Niels Kristian Bech Jensen <nkbj@image.dk>.
 *
 * write support Daniel Pirkl <daniel.pirkl@email.cz> 1998
 *
 * HP/UX hfs filesystem support added by
 * Martin K. Petersen <mkp@mkp.net>, August 1999
 *
 * UFS2 (of FreeBSD 5.x) support added by
 * Niraj Kumar <niraj17@iitbombay.org>, Jan 2004
 *
 * UFS2 write support added by
 * Evgeniy Dushistov <dushistov@mail.ru>, 2007
 */

#include <linux/exportfs.h>
#include <linux/module.h>
// #include <linux/bitops.h>

#include <stdarg.h>

// #include <asm/uaccess.h>

// #include <linux/errno.h>
// #include <linux/fs.h>
#include <linux/slab.h>
// #include <linux/time.h>
// #include <linux/stat.h>
// #include <linux/string.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/parser.h>
// #include <linux/buffer_head.h>
#include <linux/vfs.h>
#include <linux/log2.h>
#include <linux/mount.h>
#include <linux/seq_file.h>

// #include "ufs_fs.h"
// #include "ufs.h"
// #include "swab.h"
// #include "util.h"

void lock_ufs(struct super_block *sb)
{
#if defined(CONFIG_SMP) || defined (CONFIG_PREEMPT)
	struct ufs_sb_info *sbi = UFS_SB(sb);

	mutex_lock(&sbi->mutex);
	sbi->mutex_owner = current;
#endif
}

void unlock_ufs(struct super_block *sb)
{
#if defined(CONFIG_SMP) || defined (CONFIG_PREEMPT)
	struct ufs_sb_info *sbi = UFS_SB(sb);

	sbi->mutex_owner = NULL;
	mutex_unlock(&sbi->mutex);
#endif
}

static struct inode *ufs_nfs_get_inode(struct super_block *sb, u64 ino, u32 generation)
{
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	struct inode *inode;

	if (ino < UFS_ROOTINO || ino > uspi->s_ncg * uspi->s_ipg)
		return ERR_PTR(-ESTALE);

	inode = ufs_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return inode;
}

static struct dentry *ufs_fh_to_dentry(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type, ufs_nfs_get_inode);
}

static struct dentry *ufs_fh_to_parent(struct super_block *sb, struct fid *fid,
				       int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type, ufs_nfs_get_inode);
}

static struct dentry *ufs_get_parent(struct dentry *child)
{
	struct qstr dot_dot = QSTR_INIT("..", 2);
	ino_t ino;

	ino = ufs_inode_by_name(child->d_inode, &dot_dot);
	if (!ino)
		return ERR_PTR(-ENOENT);
	return d_obtain_alias(ufs_iget(child->d_inode->i_sb, ino));
}

static const struct export_operations ufs_export_ops = {
	.fh_to_dentry	= ufs_fh_to_dentry,
	.fh_to_parent	= ufs_fh_to_parent,
	.get_parent	= ufs_get_parent,
};

#ifdef CONFIG_UFS_DEBUG
/*
 * Print contents of ufs_super_block, useful for debugging
 */
static void ufs_print_super_stuff(struct super_block *sb,
				  struct ufs_super_block_first *usb1,
				  struct ufs_super_block_second *usb2,
				  struct ufs_super_block_third *usb3)
{
	u32 magic = fs32_to_cpu(sb, usb3->fs_magic);

	pr_debug("ufs_print_super_stuff\n");
	pr_debug("  magic:     0x%x\n", magic);
	if (fs32_to_cpu(sb, usb3->fs_magic) == UFS2_MAGIC) {
		pr_debug("  fs_size:   %llu\n", (unsigned long long)
			 fs64_to_cpu(sb, usb3->fs_un1.fs_u2.fs_size));
		pr_debug("  fs_dsize:  %llu\n", (unsigned long long)
			 fs64_to_cpu(sb, usb3->fs_un1.fs_u2.fs_dsize));
		pr_debug("  bsize:         %u\n",
			 fs32_to_cpu(sb, usb1->fs_bsize));
		pr_debug("  fsize:         %u\n",
			 fs32_to_cpu(sb, usb1->fs_fsize));
		pr_debug("  fs_volname:  %s\n", usb2->fs_un.fs_u2.fs_volname);
		pr_debug("  fs_sblockloc: %llu\n", (unsigned long long)
			 fs64_to_cpu(sb, usb2->fs_un.fs_u2.fs_sblockloc));
		pr_debug("  cs_ndir(No of dirs):  %llu\n", (unsigned long long)
			 fs64_to_cpu(sb, usb2->fs_un.fs_u2.cs_ndir));
		pr_debug("  cs_nbfree(No of free blocks):  %llu\n",
			 (unsigned long long)
			 fs64_to_cpu(sb, usb2->fs_un.fs_u2.cs_nbfree));
		pr_info("  cs_nifree(Num of free inodes): %llu\n",
			(unsigned long long)
			fs64_to_cpu(sb, usb3->fs_un1.fs_u2.cs_nifree));
		pr_info("  cs_nffree(Num of free frags): %llu\n",
			(unsigned long long)
			fs64_to_cpu(sb, usb3->fs_un1.fs_u2.cs_nffree));
		pr_info("  fs_maxsymlinklen: %u\n",
			fs32_to_cpu(sb, usb3->fs_un2.fs_44.fs_maxsymlinklen));
	} else {
		pr_debug(" sblkno:      %u\n", fs32_to_cpu(sb, usb1->fs_sblkno));
		pr_debug(" cblkno:      %u\n", fs32_to_cpu(sb, usb1->fs_cblkno));
		pr_debug(" iblkno:      %u\n", fs32_to_cpu(sb, usb1->fs_iblkno));
		pr_debug(" dblkno:      %u\n", fs32_to_cpu(sb, usb1->fs_dblkno));
		pr_debug(" cgoffset:    %u\n",
			 fs32_to_cpu(sb, usb1->fs_cgoffset));
		pr_debug(" ~cgmask:     0x%x\n",
			 ~fs32_to_cpu(sb, usb1->fs_cgmask));
		pr_debug(" size:        %u\n", fs32_to_cpu(sb, usb1->fs_size));
		pr_debug(" dsize:       %u\n", fs32_to_cpu(sb, usb1->fs_dsize));
		pr_debug(" ncg:         %u\n", fs32_to_cpu(sb, usb1->fs_ncg));
		pr_debug(" bsize:       %u\n", fs32_to_cpu(sb, usb1->fs_bsize));
		pr_debug(" fsize:       %u\n", fs32_to_cpu(sb, usb1->fs_fsize));
		pr_debug(" frag:        %u\n", fs32_to_cpu(sb, usb1->fs_frag));
		pr_debug(" fragshift:   %u\n",
			 fs32_to_cpu(sb, usb1->fs_fragshift));
		pr_debug(" ~fmask:      %u\n", ~fs32_to_cpu(sb, usb1->fs_fmask));
		pr_debug(" fshift:      %u\n", fs32_to_cpu(sb, usb1->fs_fshift));
		pr_debug(" sbsize:      %u\n", fs32_to_cpu(sb, usb1->fs_sbsize));
		pr_debug(" spc:         %u\n", fs32_to_cpu(sb, usb1->fs_spc));
		pr_debug(" cpg:         %u\n", fs32_to_cpu(sb, usb1->fs_cpg));
		pr_debug(" ipg:         %u\n", fs32_to_cpu(sb, usb1->fs_ipg));
		pr_debug(" fpg:         %u\n", fs32_to_cpu(sb, usb1->fs_fpg));
		pr_debug(" csaddr:      %u\n", fs32_to_cpu(sb, usb1->fs_csaddr));
		pr_debug(" cssize:      %u\n", fs32_to_cpu(sb, usb1->fs_cssize));
		pr_debug(" cgsize:      %u\n", fs32_to_cpu(sb, usb1->fs_cgsize));
		pr_debug(" fstodb:      %u\n",
			 fs32_to_cpu(sb, usb1->fs_fsbtodb));
		pr_debug(" nrpos:       %u\n", fs32_to_cpu(sb, usb3->fs_nrpos));
		pr_debug(" ndir         %u\n",
			 fs32_to_cpu(sb, usb1->fs_cstotal.cs_ndir));
		pr_debug(" nifree       %u\n",
			 fs32_to_cpu(sb, usb1->fs_cstotal.cs_nifree));
		pr_debug(" nbfree       %u\n",
			 fs32_to_cpu(sb, usb1->fs_cstotal.cs_nbfree));
		pr_debug(" nffree       %u\n",
			 fs32_to_cpu(sb, usb1->fs_cstotal.cs_nffree));
	}
	pr_debug("\n");
}

/*
 * Print contents of ufs_cylinder_group, useful for debugging
 */
static void ufs_print_cylinder_stuff(struct super_block *sb,
				     struct ufs_cylinder_group *cg)
{
	pr_debug("\nufs_print_cylinder_stuff\n");
	pr_debug("size of ucg: %zu\n", sizeof(struct ufs_cylinder_group));
	pr_debug("  magic:        %x\n", fs32_to_cpu(sb, cg->cg_magic));
	pr_debug("  time:         %u\n", fs32_to_cpu(sb, cg->cg_time));
	pr_debug("  cgx:          %u\n", fs32_to_cpu(sb, cg->cg_cgx));
	pr_debug("  ncyl:         %u\n", fs16_to_cpu(sb, cg->cg_ncyl));
	pr_debug("  niblk:        %u\n", fs16_to_cpu(sb, cg->cg_niblk));
	pr_debug("  ndblk:        %u\n", fs32_to_cpu(sb, cg->cg_ndblk));
	pr_debug("  cs_ndir:      %u\n", fs32_to_cpu(sb, cg->cg_cs.cs_ndir));
	pr_debug("  cs_nbfree:    %u\n", fs32_to_cpu(sb, cg->cg_cs.cs_nbfree));
	pr_debug("  cs_nifree:    %u\n", fs32_to_cpu(sb, cg->cg_cs.cs_nifree));
	pr_debug("  cs_nffree:    %u\n", fs32_to_cpu(sb, cg->cg_cs.cs_nffree));
	pr_debug("  rotor:        %u\n", fs32_to_cpu(sb, cg->cg_rotor));
	pr_debug("  frotor:       %u\n", fs32_to_cpu(sb, cg->cg_frotor));
	pr_debug("  irotor:       %u\n", fs32_to_cpu(sb, cg->cg_irotor));
	pr_debug("  frsum:        %u, %u, %u, %u, %u, %u, %u, %u\n",
	    fs32_to_cpu(sb, cg->cg_frsum[0]), fs32_to_cpu(sb, cg->cg_frsum[1]),
	    fs32_to_cpu(sb, cg->cg_frsum[2]), fs32_to_cpu(sb, cg->cg_frsum[3]),
	    fs32_to_cpu(sb, cg->cg_frsum[4]), fs32_to_cpu(sb, cg->cg_frsum[5]),
	    fs32_to_cpu(sb, cg->cg_frsum[6]), fs32_to_cpu(sb, cg->cg_frsum[7]));
	pr_debug("  btotoff:      %u\n", fs32_to_cpu(sb, cg->cg_btotoff));
	pr_debug("  boff:         %u\n", fs32_to_cpu(sb, cg->cg_boff));
	pr_debug("  iuseoff:      %u\n", fs32_to_cpu(sb, cg->cg_iusedoff));
	pr_debug("  freeoff:      %u\n", fs32_to_cpu(sb, cg->cg_freeoff));
	pr_debug("  nextfreeoff:  %u\n", fs32_to_cpu(sb, cg->cg_nextfreeoff));
	pr_debug("  clustersumoff %u\n",
		 fs32_to_cpu(sb, cg->cg_u.cg_44.cg_clustersumoff));
	pr_debug("  clusteroff    %u\n",
		 fs32_to_cpu(sb, cg->cg_u.cg_44.cg_clusteroff));
	pr_debug("  nclusterblks  %u\n",
		 fs32_to_cpu(sb, cg->cg_u.cg_44.cg_nclusterblks));
	pr_debug("\n");
}
#else
#  define ufs_print_super_stuff(sb, usb1, usb2, usb3) /**/
#  define ufs_print_cylinder_stuff(sb, cg) /**/
#endif /* CONFIG_UFS_DEBUG */

static const struct super_operations ufs_super_ops;

void ufs_error (struct super_block * sb, const char * function,
	const char * fmt, ...)
{
	struct ufs_sb_private_info * uspi;
	struct ufs_super_block_first * usb1;
	struct va_format vaf;
	va_list args;

	uspi = UFS_SB(sb)->s_uspi;
	usb1 = ubh_get_usb_first(uspi);

	if (!(sb->s_flags & MS_RDONLY)) {
		usb1->fs_clean = UFS_FSBAD;
		ubh_mark_buffer_dirty(USPI_UBH(uspi));
		ufs_mark_sb_dirty(sb);
		sb->s_flags |= MS_RDONLY;
	}
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	switch (UFS_SB(sb)->s_mount_opt & UFS_MOUNT_ONERROR) {
	case UFS_MOUNT_ONERROR_PANIC:
		panic("panic (device %s): %s: %pV\n",
		      sb->s_id, function, &vaf);

	case UFS_MOUNT_ONERROR_LOCK:
	case UFS_MOUNT_ONERROR_UMOUNT:
	case UFS_MOUNT_ONERROR_REPAIR:
		pr_crit("error (device %s): %s: %pV\n",
			sb->s_id, function, &vaf);
	}
	va_end(args);
}

void ufs_panic (struct super_block * sb, const char * function,
	const char * fmt, ...)
{
	struct ufs_sb_private_info * uspi;
	struct ufs_super_block_first * usb1;
	struct va_format vaf;
	va_list args;

	uspi = UFS_SB(sb)->s_uspi;
	usb1 = ubh_get_usb_first(uspi);

	if (!(sb->s_flags & MS_RDONLY)) {
		usb1->fs_clean = UFS_FSBAD;
		ubh_mark_buffer_dirty(USPI_UBH(uspi));
		ufs_mark_sb_dirty(sb);
	}
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	sb->s_flags |= MS_RDONLY;
	pr_crit("panic (device %s): %s: %pV\n",
		sb->s_id, function, &vaf);
	va_end(args);
}

void ufs_warning (struct super_block * sb, const char * function,
	const char * fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_warn("(device %s): %s: %pV\n",
		sb->s_id, function, &vaf);
	va_end(args);
}

enum {
       Opt_type_old = UFS_MOUNT_UFSTYPE_OLD,
       Opt_type_sunx86 = UFS_MOUNT_UFSTYPE_SUNx86,
       Opt_type_sun = UFS_MOUNT_UFSTYPE_SUN,
       Opt_type_sunos = UFS_MOUNT_UFSTYPE_SUNOS,
       Opt_type_44bsd = UFS_MOUNT_UFSTYPE_44BSD,
       Opt_type_ufs2 = UFS_MOUNT_UFSTYPE_UFS2,
       Opt_type_hp = UFS_MOUNT_UFSTYPE_HP,
       Opt_type_nextstepcd = UFS_MOUNT_UFSTYPE_NEXTSTEP_CD,
       Opt_type_nextstep = UFS_MOUNT_UFSTYPE_NEXTSTEP,
       Opt_type_openstep = UFS_MOUNT_UFSTYPE_OPENSTEP,
       Opt_onerror_panic = UFS_MOUNT_ONERROR_PANIC,
       Opt_onerror_lock = UFS_MOUNT_ONERROR_LOCK,
       Opt_onerror_umount = UFS_MOUNT_ONERROR_UMOUNT,
       Opt_onerror_repair = UFS_MOUNT_ONERROR_REPAIR,
       Opt_err
};

static const match_table_t tokens = {
	{Opt_type_old, "ufstype=old"},
	{Opt_type_sunx86, "ufstype=sunx86"},
	{Opt_type_sun, "ufstype=sun"},
	{Opt_type_sunos, "ufstype=sunos"},
	{Opt_type_44bsd, "ufstype=44bsd"},
	{Opt_type_ufs2, "ufstype=ufs2"},
	{Opt_type_ufs2, "ufstype=5xbsd"},
	{Opt_type_hp, "ufstype=hp"},
	{Opt_type_nextstepcd, "ufstype=nextstep-cd"},
	{Opt_type_nextstep, "ufstype=nextstep"},
	{Opt_type_openstep, "ufstype=openstep"},
/*end of possible ufs types */
	{Opt_onerror_panic, "onerror=panic"},
	{Opt_onerror_lock, "onerror=lock"},
	{Opt_onerror_umount, "onerror=umount"},
	{Opt_onerror_repair, "onerror=repair"},
	{Opt_err, NULL}
};

static int ufs_parse_options (char * options, unsigned * mount_options)
{
	char * p;

	UFSD("ENTER\n");

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_type_old:
			ufs_clear_opt (*mount_options, UFSTYPE);
			ufs_set_opt (*mount_options, UFSTYPE_OLD);
			break;
		case Opt_type_sunx86:
			ufs_clear_opt (*mount_options, UFSTYPE);
			ufs_set_opt (*mount_options, UFSTYPE_SUNx86);
			break;
		case Opt_type_sun:
			ufs_clear_opt (*mount_options, UFSTYPE);
			ufs_set_opt (*mount_options, UFSTYPE_SUN);
			break;
		case Opt_type_sunos:
			ufs_clear_opt(*mount_options, UFSTYPE);
			ufs_set_opt(*mount_options, UFSTYPE_SUNOS);
			break;
		case Opt_type_44bsd:
			ufs_clear_opt (*mount_options, UFSTYPE);
			ufs_set_opt (*mount_options, UFSTYPE_44BSD);
			break;
		case Opt_type_ufs2:
			ufs_clear_opt(*mount_options, UFSTYPE);
			ufs_set_opt(*mount_options, UFSTYPE_UFS2);
			break;
		case Opt_type_hp:
			ufs_clear_opt (*mount_options, UFSTYPE);
			ufs_set_opt (*mount_options, UFSTYPE_HP);
			break;
		case Opt_type_nextstepcd:
			ufs_clear_opt (*mount_options, UFSTYPE);
			ufs_set_opt (*mount_options, UFSTYPE_NEXTSTEP_CD);
			break;
		case Opt_type_nextstep:
			ufs_clear_opt (*mount_options, UFSTYPE);
			ufs_set_opt (*mount_options, UFSTYPE_NEXTSTEP);
			break;
		case Opt_type_openstep:
			ufs_clear_opt (*mount_options, UFSTYPE);
			ufs_set_opt (*mount_options, UFSTYPE_OPENSTEP);
			break;
		case Opt_onerror_panic:
			ufs_clear_opt (*mount_options, ONERROR);
			ufs_set_opt (*mount_options, ONERROR_PANIC);
			break;
		case Opt_onerror_lock:
			ufs_clear_opt (*mount_options, ONERROR);
			ufs_set_opt (*mount_options, ONERROR_LOCK);
			break;
		case Opt_onerror_umount:
			ufs_clear_opt (*mount_options, ONERROR);
			ufs_set_opt (*mount_options, ONERROR_UMOUNT);
			break;
		case Opt_onerror_repair:
			pr_err("Unable to do repair on error, will lock lock instead\n");
			ufs_clear_opt (*mount_options, ONERROR);
			ufs_set_opt (*mount_options, ONERROR_REPAIR);
			break;
		default:
			pr_err("Invalid option: \"%s\" or missing value\n", p);
			return 0;
		}
	}
	return 1;
}

/*
 * Different types of UFS hold fs_cstotal in different
 * places, and use different data structure for it.
 * To make things simpler we just copy fs_cstotal to ufs_sb_private_info
 */
static void ufs_setup_cstotal(struct super_block *sb)
{
	struct ufs_sb_info *sbi = UFS_SB(sb);
	struct ufs_sb_private_info *uspi = sbi->s_uspi;
	struct ufs_super_block_first *usb1;
	struct ufs_super_block_second *usb2;
	struct ufs_super_block_third *usb3;
	unsigned mtype = sbi->s_mount_opt & UFS_MOUNT_UFSTYPE;

	UFSD("ENTER, mtype=%u\n", mtype);
	usb1 = ubh_get_usb_first(uspi);
	usb2 = ubh_get_usb_second(uspi);
	usb3 = ubh_get_usb_third(uspi);

	if ((mtype == UFS_MOUNT_UFSTYPE_44BSD &&
	     (usb1->fs_flags & UFS_FLAGS_UPDATED)) ||
	    mtype == UFS_MOUNT_UFSTYPE_UFS2) {
		/*we have statistic in different place, then usual*/
		uspi->cs_total.cs_ndir = fs64_to_cpu(sb, usb2->fs_un.fs_u2.cs_ndir);
		uspi->cs_total.cs_nbfree = fs64_to_cpu(sb, usb2->fs_un.fs_u2.cs_nbfree);
		uspi->cs_total.cs_nifree = fs64_to_cpu(sb, usb3->fs_un1.fs_u2.cs_nifree);
		uspi->cs_total.cs_nffree = fs64_to_cpu(sb, usb3->fs_un1.fs_u2.cs_nffree);
	} else {
		uspi->cs_total.cs_ndir = fs32_to_cpu(sb, usb1->fs_cstotal.cs_ndir);
		uspi->cs_total.cs_nbfree = fs32_to_cpu(sb, usb1->fs_cstotal.cs_nbfree);
		uspi->cs_total.cs_nifree = fs32_to_cpu(sb, usb1->fs_cstotal.cs_nifree);
		uspi->cs_total.cs_nffree = fs32_to_cpu(sb, usb1->fs_cstotal.cs_nffree);
	}
	UFSD("EXIT\n");
}

/*
 * Read on-disk structures associated with cylinder groups
 */
static int ufs_read_cylinder_structures(struct super_block *sb)
{
	struct ufs_sb_info *sbi = UFS_SB(sb);
	struct ufs_sb_private_info *uspi = sbi->s_uspi;
	struct ufs_buffer_head * ubh;
	unsigned char * base, * space;
	unsigned size, blks, i;

	UFSD("ENTER\n");

	/*
	 * Read cs structures from (usually) first data block
	 * on the device.
	 */
	size = uspi->s_cssize;
	blks = (size + uspi->s_fsize - 1) >> uspi->s_fshift;
	base = space = kmalloc(size, GFP_NOFS);
	if (!base)
		goto failed;
	sbi->s_csp = (struct ufs_csum *)space;
	for (i = 0; i < blks; i += uspi->s_fpb) {
		size = uspi->s_bsize;
		if (i + uspi->s_fpb > blks)
			size = (blks - i) * uspi->s_fsize;

		ubh = ubh_bread(sb, uspi->s_csaddr + i, size);

		if (!ubh)
			goto failed;

		ubh_ubhcpymem (space, ubh, size);

		space += size;
		ubh_brelse (ubh);
		ubh = NULL;
	}

	/*
	 * Read cylinder group (we read only first fragment from block
	 * at this time) and prepare internal data structures for cg caching.
	 */
	if (!(sbi->s_ucg = kmalloc (sizeof(struct buffer_head *) * uspi->s_ncg, GFP_NOFS)))
		goto failed;
	for (i = 0; i < uspi->s_ncg; i++)
		sbi->s_ucg[i] = NULL;
	for (i = 0; i < UFS_MAX_GROUP_LOADED; i++) {
		sbi->s_ucpi[i] = NULL;
		sbi->s_cgno[i] = UFS_CGNO_EMPTY;
	}
	for (i = 0; i < uspi->s_ncg; i++) {
		UFSD("read cg %u\n", i);
		if (!(sbi->s_ucg[i] = sb_bread(sb, ufs_cgcmin(i))))
			goto failed;
		if (!ufs_cg_chkmagic (sb, (struct ufs_cylinder_group *) sbi->s_ucg[i]->b_data))
			goto failed;

		ufs_print_cylinder_stuff(sb, (struct ufs_cylinder_group *) sbi->s_ucg[i]->b_data);
	}
	for (i = 0; i < UFS_MAX_GROUP_LOADED; i++) {
		if (!(sbi->s_ucpi[i] = kmalloc (sizeof(struct ufs_cg_private_info), GFP_NOFS)))
			goto failed;
		sbi->s_cgno[i] = UFS_CGNO_EMPTY;
	}
	sbi->s_cg_loaded = 0;
	UFSD("EXIT\n");
	return 1;

failed:
	kfree (base);
	if (sbi->s_ucg) {
		for (i = 0; i < uspi->s_ncg; i++)
			if (sbi->s_ucg[i])
				brelse (sbi->s_ucg[i]);
		kfree (sbi->s_ucg);
		for (i = 0; i < UFS_MAX_GROUP_LOADED; i++)
			kfree (sbi->s_ucpi[i]);
	}
	UFSD("EXIT (FAILED)\n");
	return 0;
}

/*
 * Sync our internal copy of fs_cstotal with disk
 */
static void ufs_put_cstotal(struct super_block *sb)
{
	unsigned mtype = UFS_SB(sb)->s_mount_opt & UFS_MOUNT_UFSTYPE;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	struct ufs_super_block_first *usb1;
	struct ufs_super_block_second *usb2;
	struct ufs_super_block_third *usb3;

	UFSD("ENTER\n");
	usb1 = ubh_get_usb_first(uspi);
	usb2 = ubh_get_usb_second(uspi);
	usb3 = ubh_get_usb_third(uspi);

	if ((mtype == UFS_MOUNT_UFSTYPE_44BSD &&
	     (usb1->fs_flags & UFS_FLAGS_UPDATED)) ||
	    mtype == UFS_MOUNT_UFSTYPE_UFS2) {
		/*we have statistic in different place, then usual*/
		usb2->fs_un.fs_u2.cs_ndir =
			cpu_to_fs64(sb, uspi->cs_total.cs_ndir);
		usb2->fs_un.fs_u2.cs_nbfree =
			cpu_to_fs64(sb, uspi->cs_total.cs_nbfree);
		usb3->fs_un1.fs_u2.cs_nifree =
			cpu_to_fs64(sb, uspi->cs_total.cs_nifree);
		usb3->fs_un1.fs_u2.cs_nffree =
			cpu_to_fs64(sb, uspi->cs_total.cs_nffree);
	} else {
		usb1->fs_cstotal.cs_ndir =
			cpu_to_fs32(sb, uspi->cs_total.cs_ndir);
		usb1->fs_cstotal.cs_nbfree =
			cpu_to_fs32(sb, uspi->cs_total.cs_nbfree);
		usb1->fs_cstotal.cs_nifree =
			cpu_to_fs32(sb, uspi->cs_total.cs_nifree);
		usb1->fs_cstotal.cs_nffree =
			cpu_to_fs32(sb, uspi->cs_total.cs_nffree);
	}
	ubh_mark_buffer_dirty(USPI_UBH(uspi));
	ufs_print_super_stuff(sb, usb1, usb2, usb3);
	UFSD("EXIT\n");
}

/**
 * ufs_put_super_internal() - put on-disk intrenal structures
 * @sb: pointer to super_block structure
 * Put on-disk structures associated with cylinder groups
 * and write them back to disk, also update cs_total on disk
 */
static void ufs_put_super_internal(struct super_block *sb)
{
	struct ufs_sb_info *sbi = UFS_SB(sb);
	struct ufs_sb_private_info *uspi = sbi->s_uspi;
	struct ufs_buffer_head * ubh;
	unsigned char * base, * space;
	unsigned blks, size, i;


	UFSD("ENTER\n");

	ufs_put_cstotal(sb);
	size = uspi->s_cssize;
	blks = (size + uspi->s_fsize - 1) >> uspi->s_fshift;
	base = space = (char*) sbi->s_csp;
	for (i = 0; i < blks; i += uspi->s_fpb) {
		size = uspi->s_bsize;
		if (i + uspi->s_fpb > blks)
			size = (blks - i) * uspi->s_fsize;

		ubh = ubh_bread(sb, uspi->s_csaddr + i, size);

		ubh_memcpyubh (ubh, space, size);
		space += size;
		ubh_mark_buffer_uptodate (ubh, 1);
		ubh_mark_buffer_dirty (ubh);
		ubh_brelse (ubh);
	}
	for (i = 0; i < sbi->s_cg_loaded; i++) {
		ufs_put_cylinder (sb, i);
		kfree (sbi->s_ucpi[i]);
	}
	for (; i < UFS_MAX_GROUP_LOADED; i++)
		kfree (sbi->s_ucpi[i]);
	for (i = 0; i < uspi->s_ncg; i++)
		brelse (sbi->s_ucg[i]);
	kfree (sbi->s_ucg);
	kfree (base);

	UFSD("EXIT\n");
}

static int ufs_sync_fs(struct super_block *sb, int wait)
{
	struct ufs_sb_private_info * uspi;
	struct ufs_super_block_first * usb1;
	struct ufs_super_block_third * usb3;
	unsigned flags;

	lock_ufs(sb);

	UFSD("ENTER\n");

	flags = UFS_SB(sb)->s_flags;
	uspi = UFS_SB(sb)->s_uspi;
	usb1 = ubh_get_usb_first(uspi);
	usb3 = ubh_get_usb_third(uspi);

	usb1->fs_time = cpu_to_fs32(sb, get_seconds());
	if ((flags & UFS_ST_MASK) == UFS_ST_SUN  ||
	    (flags & UFS_ST_MASK) == UFS_ST_SUNOS ||
	    (flags & UFS_ST_MASK) == UFS_ST_SUNx86)
		ufs_set_fs_state(sb, usb1, usb3,
				UFS_FSOK - fs32_to_cpu(sb, usb1->fs_time));
	ufs_put_cstotal(sb);

	UFSD("EXIT\n");
	unlock_ufs(sb);

	return 0;
}

static void delayed_sync_fs(struct work_struct *work)
{
	struct ufs_sb_info *sbi;

	sbi = container_of(work, struct ufs_sb_info, sync_work.work);

	spin_lock(&sbi->work_lock);
	sbi->work_queued = 0;
	spin_unlock(&sbi->work_lock);

	ufs_sync_fs(sbi->sb, 1);
}

void ufs_mark_sb_dirty(struct super_block *sb)
{
	struct ufs_sb_info *sbi = UFS_SB(sb);
	unsigned long delay;

	spin_lock(&sbi->work_lock);
	if (!sbi->work_queued) {
		delay = msecs_to_jiffies(dirty_writeback_interval * 10);
		queue_delayed_work(system_long_wq, &sbi->sync_work, delay);
		sbi->work_queued = 1;
	}
	spin_unlock(&sbi->work_lock);
}

static void ufs_put_super(struct super_block *sb)
{
	struct ufs_sb_info * sbi = UFS_SB(sb);

	UFSD("ENTER\n");

	if (!(sb->s_flags & MS_RDONLY))
		ufs_put_super_internal(sb);
	cancel_delayed_work_sync(&sbi->sync_work);

	ubh_brelse_uspi (sbi->s_uspi);
	kfree (sbi->s_uspi);
	mutex_destroy(&sbi->mutex);
	kfree (sbi);
	sb->s_fs_info = NULL;
	UFSD("EXIT\n");
	return;
}

static int ufs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct ufs_sb_info * sbi;
	struct ufs_sb_private_info * uspi;
	struct ufs_super_block_first * usb1;
	struct ufs_super_block_second * usb2;
	struct ufs_super_block_third * usb3;
	struct ufs_buffer_head * ubh;
	struct inode *inode;
	unsigned block_size, super_block_size;
	unsigned flags;
	unsigned super_block_offset;
	unsigned maxsymlen;
	int ret = -EINVAL;

	uspi = NULL;
	ubh = NULL;
	flags = 0;

	UFSD("ENTER\n");

#ifndef CONFIG_UFS_FS_WRITE
	if (!(sb->s_flags & MS_RDONLY)) {
		pr_err("ufs was compiled with read-only support, can't be mounted as read-write\n");
		return -EROFS;
	}
#endif

	sbi = kzalloc(sizeof(struct ufs_sb_info), GFP_KERNEL);
	if (!sbi)
		goto failed_nomem;
	sb->s_fs_info = sbi;
	sbi->sb = sb;

	UFSD("flag %u\n", (int)(sb->s_flags & MS_RDONLY));

	mutex_init(&sbi->mutex);
	spin_lock_init(&sbi->work_lock);
	INIT_DELAYED_WORK(&sbi->sync_work, delayed_sync_fs);
	/*
	 * Set default mount options
	 * Parse mount options
	 */
	sbi->s_mount_opt = 0;
	ufs_set_opt (sbi->s_mount_opt, ONERROR_LOCK);
	if (!ufs_parse_options ((char *) data, &sbi->s_mount_opt)) {
		pr_err("wrong mount options\n");
		goto failed;
	}
	if (!(sbi->s_mount_opt & UFS_MOUNT_UFSTYPE)) {
		if (!silent)
			pr_err("You didn't specify the type of your ufs filesystem\n\n"
			"mount -t ufs -o ufstype="
			"sun|sunx86|44bsd|ufs2|5xbsd|old|hp|nextstep|nextstep-cd|openstep ...\n\n"
			">>>WARNING<<< Wrong ufstype may corrupt your filesystem, "
			"default is ufstype=old\n");
		ufs_set_opt (sbi->s_mount_opt, UFSTYPE_OLD);
	}

	uspi = kzalloc(sizeof(struct ufs_sb_private_info), GFP_KERNEL);
	sbi->s_uspi = uspi;
	if (!uspi)
		goto failed;
	uspi->s_dirblksize = UFS_SECTOR_SIZE;
	super_block_offset=UFS_SBLOCK;

	/* Keep 2Gig file limit. Some UFS variants need to override
	   this but as I don't know which I'll let those in the know loosen
	   the rules */
	switch (sbi->s_mount_opt & UFS_MOUNT_UFSTYPE) {
	case UFS_MOUNT_UFSTYPE_44BSD:
		UFSD("ufstype=44bsd\n");
		uspi->s_fsize = block_size = 512;
		uspi->s_fmask = ~(512 - 1);
		uspi->s_fshift = 9;
		uspi->s_sbsize = super_block_size = 1536;
		uspi->s_sbbase = 0;
		flags |= UFS_DE_44BSD | UFS_UID_44BSD | UFS_ST_44BSD | UFS_CG_44BSD;
		break;
	case UFS_MOUNT_UFSTYPE_UFS2:
		UFSD("ufstype=ufs2\n");
		super_block_offset=SBLOCK_UFS2;
		uspi->s_fsize = block_size = 512;
		uspi->s_fmask = ~(512 - 1);
		uspi->s_fshift = 9;
		uspi->s_sbsize = super_block_size = 1536;
		uspi->s_sbbase =  0;
		flags |= UFS_TYPE_UFS2 | UFS_DE_44BSD | UFS_UID_44BSD | UFS_ST_44BSD | UFS_CG_44BSD;
		break;

	case UFS_MOUNT_UFSTYPE_SUN:
		UFSD("ufstype=sun\n");
		uspi->s_fsize = block_size = 1024;
		uspi->s_fmask = ~(1024 - 1);
		uspi->s_fshift = 10;
		uspi->s_sbsize = super_block_size = 2048;
		uspi->s_sbbase = 0;
		uspi->s_maxsymlinklen = 0; /* Not supported on disk */
		flags |= UFS_DE_OLD | UFS_UID_EFT | UFS_ST_SUN | UFS_CG_SUN;
		break;

	case UFS_MOUNT_UFSTYPE_SUNOS:
		UFSD("ufstype=sunos\n");
		uspi->s_fsize = block_size = 1024;
		uspi->s_fmask = ~(1024 - 1);
		uspi->s_fshift = 10;
		uspi->s_sbsize = 2048;
		super_block_size = 2048;
		uspi->s_sbbase = 0;
		uspi->s_maxsymlinklen = 0; /* Not supported on disk */
		flags |= UFS_DE_OLD | UFS_UID_OLD | UFS_ST_SUNOS | UFS_CG_SUN;
		break;

	case UFS_MOUNT_UFSTYPE_SUNx86:
		UFSD("ufstype=sunx86\n");
		uspi->s_fsize = block_size = 1024;
		uspi->s_fmask = ~(1024 - 1);
		uspi->s_fshift = 10;
		uspi->s_sbsize = super_block_size = 2048;
		uspi->s_sbbase = 0;
		uspi->s_maxsymlinklen = 0; /* Not supported on disk */
		flags |= UFS_DE_OLD | UFS_UID_EFT | UFS_ST_SUNx86 | UFS_CG_SUN;
		break;

	case UFS_MOUNT_UFSTYPE_OLD:
		UFSD("ufstype=old\n");
		uspi->s_fsize = block_size = 1024;
		uspi->s_fmask = ~(1024 - 1);
		uspi->s_fshift = 10;
		uspi->s_sbsize = super_block_size = 2048;
		uspi->s_sbbase = 0;
		flags |= UFS_DE_OLD | UFS_UID_OLD | UFS_ST_OLD | UFS_CG_OLD;
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!silent)
				pr_info("ufstype=old is supported read-only\n");
			sb->s_flags |= MS_RDONLY;
		}
		break;

	case UFS_MOUNT_UFSTYPE_NEXTSTEP:
		UFSD("ufstype=nextstep\n");
		uspi->s_fsize = block_size = 1024;
		uspi->s_fmask = ~(1024 - 1);
		uspi->s_fshift = 10;
		uspi->s_sbsize = super_block_size = 2048;
		uspi->s_sbbase = 0;
		uspi->s_dirblksize = 1024;
		flags |= UFS_DE_OLD | UFS_UID_OLD | UFS_ST_OLD | UFS_CG_OLD;
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!silent)
				pr_info("ufstype=nextstep is supported read-only\n");
			sb->s_flags |= MS_RDONLY;
		}
		break;

	case UFS_MOUNT_UFSTYPE_NEXTSTEP_CD:
		UFSD("ufstype=nextstep-cd\n");
		uspi->s_fsize = block_size = 2048;
		uspi->s_fmask = ~(2048 - 1);
		uspi->s_fshift = 11;
		uspi->s_sbsize = super_block_size = 2048;
		uspi->s_sbbase = 0;
		uspi->s_dirblksize = 1024;
		flags |= UFS_DE_OLD | UFS_UID_OLD | UFS_ST_OLD | UFS_CG_OLD;
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!silent)
				pr_info("ufstype=nextstep-cd is supported read-only\n");
			sb->s_flags |= MS_RDONLY;
		}
		break;

	case UFS_MOUNT_UFSTYPE_OPENSTEP:
		UFSD("ufstype=openstep\n");
		uspi->s_fsize = block_size = 1024;
		uspi->s_fmask = ~(1024 - 1);
		uspi->s_fshift = 10;
		uspi->s_sbsize = super_block_size = 2048;
		uspi->s_sbbase = 0;
		uspi->s_dirblksize = 1024;
		flags |= UFS_DE_44BSD | UFS_UID_44BSD | UFS_ST_44BSD | UFS_CG_44BSD;
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!silent)
				pr_info("ufstype=openstep is supported read-only\n");
			sb->s_flags |= MS_RDONLY;
		}
		break;

	case UFS_MOUNT_UFSTYPE_HP:
		UFSD("ufstype=hp\n");
		uspi->s_fsize = block_size = 1024;
		uspi->s_fmask = ~(1024 - 1);
		uspi->s_fshift = 10;
		uspi->s_sbsize = super_block_size = 2048;
		uspi->s_sbbase = 0;
		flags |= UFS_DE_OLD | UFS_UID_OLD | UFS_ST_OLD | UFS_CG_OLD;
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!silent)
				pr_info("ufstype=hp is supported read-only\n");
			sb->s_flags |= MS_RDONLY;
 		}
 		break;
	default:
		if (!silent)
			pr_err("unknown ufstype\n");
		goto failed;
	}

again:
	if (!sb_set_blocksize(sb, block_size)) {
		pr_err("failed to set blocksize\n");
		goto failed;
	}

	/*
	 * read ufs super block from device
	 */

	ubh = ubh_bread_uspi(uspi, sb, uspi->s_sbbase + super_block_offset/block_size, super_block_size);

	if (!ubh)
            goto failed;

	usb1 = ubh_get_usb_first(uspi);
	usb2 = ubh_get_usb_second(uspi);
	usb3 = ubh_get_usb_third(uspi);

	/* Sort out mod used on SunOS 4.1.3 for fs_state */
	uspi->s_postblformat = fs32_to_cpu(sb, usb3->fs_postblformat);
	if (((flags & UFS_ST_MASK) == UFS_ST_SUNOS) &&
	    (uspi->s_postblformat != UFS_42POSTBLFMT)) {
		flags &= ~UFS_ST_MASK;
		flags |=  UFS_ST_SUN;
	}

	/*
	 * Check ufs magic number
	 */
	sbi->s_bytesex = BYTESEX_LE;
	switch ((uspi->fs_magic = fs32_to_cpu(sb, usb3->fs_magic))) {
		case UFS_MAGIC:
		case UFS_MAGIC_BW:
		case UFS2_MAGIC:
		case UFS_MAGIC_LFN:
	        case UFS_MAGIC_FEA:
	        case UFS_MAGIC_4GB:
			goto magic_found;
	}
	sbi->s_bytesex = BYTESEX_BE;
	switch ((uspi->fs_magic = fs32_to_cpu(sb, usb3->fs_magic))) {
		case UFS_MAGIC:
		case UFS_MAGIC_BW:
		case UFS2_MAGIC:
		case UFS_MAGIC_LFN:
	        case UFS_MAGIC_FEA:
	        case UFS_MAGIC_4GB:
			goto magic_found;
	}

	if ((((sbi->s_mount_opt & UFS_MOUNT_UFSTYPE) == UFS_MOUNT_UFSTYPE_NEXTSTEP)
	  || ((sbi->s_mount_opt & UFS_MOUNT_UFSTYPE) == UFS_MOUNT_UFSTYPE_NEXTSTEP_CD)
	  || ((sbi->s_mount_opt & UFS_MOUNT_UFSTYPE) == UFS_MOUNT_UFSTYPE_OPENSTEP))
	  && uspi->s_sbbase < 256) {
		ubh_brelse_uspi(uspi);
		ubh = NULL;
		uspi->s_sbbase += 8;
		goto again;
	}
	if (!silent)
		pr_err("%s(): bad magic number\n", __func__);
	goto failed;

magic_found:
	/*
	 * Check block and fragment sizes
	 */
	uspi->s_bsize = fs32_to_cpu(sb, usb1->fs_bsize);
	uspi->s_fsize = fs32_to_cpu(sb, usb1->fs_fsize);
	uspi->s_sbsize = fs32_to_cpu(sb, usb1->fs_sbsize);
	uspi->s_fmask = fs32_to_cpu(sb, usb1->fs_fmask);
	uspi->s_fshift = fs32_to_cpu(sb, usb1->fs_fshift);

	if (!is_power_of_2(uspi->s_fsize)) {
		pr_err("%s(): fragment size %u is not a power of 2\n",
		       __func__, uspi->s_fsize);
		goto failed;
	}
	if (uspi->s_fsize < 512) {
		pr_err("%s(): fragment size %u is too small\n",
		       __func__, uspi->s_fsize);
		goto failed;
	}
	if (uspi->s_fsize > 4096) {
		pr_err("%s(): fragment size %u is too large\n",
		       __func__, uspi->s_fsize);
		goto failed;
	}
	if (!is_power_of_2(uspi->s_bsize)) {
		pr_err("%s(): block size %u is not a power of 2\n",
		       __func__, uspi->s_bsize);
		goto failed;
	}
	if (uspi->s_bsize < 4096) {
		pr_err("%s(): block size %u is too small\n",
		       __func__, uspi->s_bsize);
		goto failed;
	}
	if (uspi->s_bsize / uspi->s_fsize > 8) {
		pr_err("%s(): too many fragments per block (%u)\n",
		       __func__, uspi->s_bsize / uspi->s_fsize);
		goto failed;
	}
	if (uspi->s_fsize != block_size || uspi->s_sbsize != super_block_size) {
		ubh_brelse_uspi(uspi);
		ubh = NULL;
		block_size = uspi->s_fsize;
		super_block_size = uspi->s_sbsize;
		UFSD("another value of block_size or super_block_size %u, %u\n", block_size, super_block_size);
		goto again;
	}

	sbi->s_flags = flags;/*after that line some functions use s_flags*/
	ufs_print_super_stuff(sb, usb1, usb2, usb3);

	/*
	 * Check, if file system was correctly unmounted.
	 * If not, make it read only.
	 */
	if (((flags & UFS_ST_MASK) == UFS_ST_44BSD) ||
	  ((flags & UFS_ST_MASK) == UFS_ST_OLD) ||
	  (((flags & UFS_ST_MASK) == UFS_ST_SUN ||
	    (flags & UFS_ST_MASK) == UFS_ST_SUNOS ||
	  (flags & UFS_ST_MASK) == UFS_ST_SUNx86) &&
	  (ufs_get_fs_state(sb, usb1, usb3) == (UFS_FSOK - fs32_to_cpu(sb, usb1->fs_time))))) {
		switch(usb1->fs_clean) {
		case UFS_FSCLEAN:
			UFSD("fs is clean\n");
			break;
		case UFS_FSSTABLE:
			UFSD("fs is stable\n");
			break;
		case UFS_FSLOG:
			UFSD("fs is logging fs\n");
			break;
		case UFS_FSOSF1:
			UFSD("fs is DEC OSF/1\n");
			break;
		case UFS_FSACTIVE:
			pr_err("%s(): fs is active\n", __func__);
			sb->s_flags |= MS_RDONLY;
			break;
		case UFS_FSBAD:
			pr_err("%s(): fs is bad\n", __func__);
			sb->s_flags |= MS_RDONLY;
			break;
		default:
			pr_err("%s(): can't grok fs_clean 0x%x\n",
			       __func__, usb1->fs_clean);
			sb->s_flags |= MS_RDONLY;
			break;
		}
	} else {
		pr_err("%s(): fs needs fsck\n", __func__);
		sb->s_flags |= MS_RDONLY;
	}

	/*
	 * Read ufs_super_block into internal data structures
	 */
	sb->s_op = &ufs_super_ops;
	sb->s_export_op = &ufs_export_ops;

	sb->s_magic = fs32_to_cpu(sb, usb3->fs_magic);

	uspi->s_sblkno = fs32_to_cpu(sb, usb1->fs_sblkno);
	uspi->s_cblkno = fs32_to_cpu(sb, usb1->fs_cblkno);
	uspi->s_iblkno = fs32_to_cpu(sb, usb1->fs_iblkno);
	uspi->s_dblkno = fs32_to_cpu(sb, usb1->fs_dblkno);
	uspi->s_cgoffset = fs32_to_cpu(sb, usb1->fs_cgoffset);
	uspi->s_cgmask = fs32_to_cpu(sb, usb1->fs_cgmask);

	if ((flags & UFS_TYPE_MASK) == UFS_TYPE_UFS2) {
		uspi->s_u2_size  = fs64_to_cpu(sb, usb3->fs_un1.fs_u2.fs_size);
		uspi->s_u2_dsize = fs64_to_cpu(sb, usb3->fs_un1.fs_u2.fs_dsize);
	} else {
		uspi->s_size  =  fs32_to_cpu(sb, usb1->fs_size);
		uspi->s_dsize =  fs32_to_cpu(sb, usb1->fs_dsize);
	}

	uspi->s_ncg = fs32_to_cpu(sb, usb1->fs_ncg);
	/* s_bsize already set */
	/* s_fsize already set */
	uspi->s_fpb = fs32_to_cpu(sb, usb1->fs_frag);
	uspi->s_minfree = fs32_to_cpu(sb, usb1->fs_minfree);
	uspi->s_bmask = fs32_to_cpu(sb, usb1->fs_bmask);
	uspi->s_fmask = fs32_to_cpu(sb, usb1->fs_fmask);
	uspi->s_bshift = fs32_to_cpu(sb, usb1->fs_bshift);
	uspi->s_fshift = fs32_to_cpu(sb, usb1->fs_fshift);
	UFSD("uspi->s_bshift = %d,uspi->s_fshift = %d", uspi->s_bshift,
		uspi->s_fshift);
	uspi->s_fpbshift = fs32_to_cpu(sb, usb1->fs_fragshift);
	uspi->s_fsbtodb = fs32_to_cpu(sb, usb1->fs_fsbtodb);
	/* s_sbsize already set */
	uspi->s_csmask = fs32_to_cpu(sb, usb1->fs_csmask);
	uspi->s_csshift = fs32_to_cpu(sb, usb1->fs_csshift);
	uspi->s_nindir = fs32_to_cpu(sb, usb1->fs_nindir);
	uspi->s_inopb = fs32_to_cpu(sb, usb1->fs_inopb);
	uspi->s_nspf = fs32_to_cpu(sb, usb1->fs_nspf);
	uspi->s_npsect = ufs_get_fs_npsect(sb, usb1, usb3);
	uspi->s_interleave = fs32_to_cpu(sb, usb1->fs_interleave);
	uspi->s_trackskew = fs32_to_cpu(sb, usb1->fs_trackskew);

	if (uspi->fs_magic == UFS2_MAGIC)
		uspi->s_csaddr = fs64_to_cpu(sb, usb3->fs_un1.fs_u2.fs_csaddr);
	else
		uspi->s_csaddr = fs32_to_cpu(sb, usb1->fs_csaddr);

	uspi->s_cssize = fs32_to_cpu(sb, usb1->fs_cssize);
	uspi->s_cgsize = fs32_to_cpu(sb, usb1->fs_cgsize);
	uspi->s_ntrak = fs32_to_cpu(sb, usb1->fs_ntrak);
	uspi->s_nsect = fs32_to_cpu(sb, usb1->fs_nsect);
	uspi->s_spc = fs32_to_cpu(sb, usb1->fs_spc);
	uspi->s_ipg = fs32_to_cpu(sb, usb1->fs_ipg);
	uspi->s_fpg = fs32_to_cpu(sb, usb1->fs_fpg);
	uspi->s_cpc = fs32_to_cpu(sb, usb2->fs_un.fs_u1.fs_cpc);
	uspi->s_contigsumsize = fs32_to_cpu(sb, usb3->fs_un2.fs_44.fs_contigsumsize);
	uspi->s_qbmask = ufs_get_fs_qbmask(sb, usb3);
	uspi->s_qfmask = ufs_get_fs_qfmask(sb, usb3);
	uspi->s_nrpos = fs32_to_cpu(sb, usb3->fs_nrpos);
	uspi->s_postbloff = fs32_to_cpu(sb, usb3->fs_postbloff);
	uspi->s_rotbloff = fs32_to_cpu(sb, usb3->fs_rotbloff);

	/*
	 * Compute another frequently used values
	 */
	uspi->s_fpbmask = uspi->s_fpb - 1;
	if ((flags & UFS_TYPE_MASK) == UFS_TYPE_UFS2)
		uspi->s_apbshift = uspi->s_bshift - 3;
	else
		uspi->s_apbshift = uspi->s_bshift - 2;

	uspi->s_2apbshift = uspi->s_apbshift * 2;
	uspi->s_3apbshift = uspi->s_apbshift * 3;
	uspi->s_apb = 1 << uspi->s_apbshift;
	uspi->s_2apb = 1 << uspi->s_2apbshift;
	uspi->s_3apb = 1 << uspi->s_3apbshift;
	uspi->s_apbmask = uspi->s_apb - 1;
	uspi->s_nspfshift = uspi->s_fshift - UFS_SECTOR_BITS;
	uspi->s_nspb = uspi->s_nspf << uspi->s_fpbshift;
	uspi->s_inopf = uspi->s_inopb >> uspi->s_fpbshift;
	uspi->s_bpf = uspi->s_fsize << 3;
	uspi->s_bpfshift = uspi->s_fshift + 3;
	uspi->s_bpfmask = uspi->s_bpf - 1;
	if ((sbi->s_mount_opt & UFS_MOUNT_UFSTYPE) == UFS_MOUNT_UFSTYPE_44BSD ||
	    (sbi->s_mount_opt & UFS_MOUNT_UFSTYPE) == UFS_MOUNT_UFSTYPE_UFS2)
		uspi->s_maxsymlinklen =
		    fs32_to_cpu(sb, usb3->fs_un2.fs_44.fs_maxsymlinklen);

	if (uspi->fs_magic == UFS2_MAGIC)
		maxsymlen = 2 * 4 * (UFS_NDADDR + UFS_NINDIR);
	else
		maxsymlen = 4 * (UFS_NDADDR + UFS_NINDIR);
	if (uspi->s_maxsymlinklen > maxsymlen) {
		ufs_warning(sb, __func__, "ufs_read_super: excessive maximum "
			    "fast symlink size (%u)\n", uspi->s_maxsymlinklen);
		uspi->s_maxsymlinklen = maxsymlen;
	}
	sb->s_max_links = UFS_LINK_MAX;

	inode = ufs_iget(sb, UFS_ROOTINO);
	if (IS_ERR(inode)) {
		ret = PTR_ERR(inode);
		goto failed;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		ret = -ENOMEM;
		goto failed;
	}

	ufs_setup_cstotal(sb);
	/*
	 * Read cylinder group structures
	 */
	if (!(sb->s_flags & MS_RDONLY))
		if (!ufs_read_cylinder_structures(sb))
			goto failed;

	UFSD("EXIT\n");
	return 0;

failed:
	mutex_destroy(&sbi->mutex);
	if (ubh)
		ubh_brelse_uspi (uspi);
	kfree (uspi);
	kfree(sbi);
	sb->s_fs_info = NULL;
	UFSD("EXIT (FAILED)\n");
	return ret;

failed_nomem:
	UFSD("EXIT (NOMEM)\n");
	return -ENOMEM;
}

static int ufs_remount (struct super_block *sb, int *mount_flags, char *data)
{
	struct ufs_sb_private_info * uspi;
	struct ufs_super_block_first * usb1;
	struct ufs_super_block_third * usb3;
	unsigned new_mount_opt, ufstype;
	unsigned flags;

	sync_filesystem(sb);
	lock_ufs(sb);
	uspi = UFS_SB(sb)->s_uspi;
	flags = UFS_SB(sb)->s_flags;
	usb1 = ubh_get_usb_first(uspi);
	usb3 = ubh_get_usb_third(uspi);

	/*
	 * Allow the "check" option to be passed as a remount option.
	 * It is not possible to change ufstype option during remount
	 */
	ufstype = UFS_SB(sb)->s_mount_opt & UFS_MOUNT_UFSTYPE;
	new_mount_opt = 0;
	ufs_set_opt (new_mount_opt, ONERROR_LOCK);
	if (!ufs_parse_options (data, &new_mount_opt)) {
		unlock_ufs(sb);
		return -EINVAL;
	}
	if (!(new_mount_opt & UFS_MOUNT_UFSTYPE)) {
		new_mount_opt |= ufstype;
	} else if ((new_mount_opt & UFS_MOUNT_UFSTYPE) != ufstype) {
		pr_err("ufstype can't be changed during remount\n");
		unlock_ufs(sb);
		return -EINVAL;
	}

	if ((*mount_flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY)) {
		UFS_SB(sb)->s_mount_opt = new_mount_opt;
		unlock_ufs(sb);
		return 0;
	}

	/*
	 * fs was mouted as rw, remounting ro
	 */
	if (*mount_flags & MS_RDONLY) {
		ufs_put_super_internal(sb);
		usb1->fs_time = cpu_to_fs32(sb, get_seconds());
		if ((flags & UFS_ST_MASK) == UFS_ST_SUN
		  || (flags & UFS_ST_MASK) == UFS_ST_SUNOS
		  || (flags & UFS_ST_MASK) == UFS_ST_SUNx86)
			ufs_set_fs_state(sb, usb1, usb3,
				UFS_FSOK - fs32_to_cpu(sb, usb1->fs_time));
		ubh_mark_buffer_dirty (USPI_UBH(uspi));
		sb->s_flags |= MS_RDONLY;
	} else {
	/*
	 * fs was mounted as ro, remounting rw
	 */
#ifndef CONFIG_UFS_FS_WRITE
		pr_err("ufs was compiled with read-only support, can't be mounted as read-write\n");
		unlock_ufs(sb);
		return -EINVAL;
#else
		if (ufstype != UFS_MOUNT_UFSTYPE_SUN &&
		    ufstype != UFS_MOUNT_UFSTYPE_SUNOS &&
		    ufstype != UFS_MOUNT_UFSTYPE_44BSD &&
		    ufstype != UFS_MOUNT_UFSTYPE_SUNx86 &&
		    ufstype != UFS_MOUNT_UFSTYPE_UFS2) {
			pr_err("this ufstype is read-only supported\n");
			unlock_ufs(sb);
			return -EINVAL;
		}
		if (!ufs_read_cylinder_structures(sb)) {
			pr_err("failed during remounting\n");
			unlock_ufs(sb);
			return -EPERM;
		}
		sb->s_flags &= ~MS_RDONLY;
#endif
	}
	UFS_SB(sb)->s_mount_opt = new_mount_opt;
	unlock_ufs(sb);
	return 0;
}

static int ufs_show_options(struct seq_file *seq, struct dentry *root)
{
	struct ufs_sb_info *sbi = UFS_SB(root->d_sb);
	unsigned mval = sbi->s_mount_opt & UFS_MOUNT_UFSTYPE;
	const struct match_token *tp = tokens;

	while (tp->token != Opt_onerror_panic && tp->token != mval)
		++tp;
	BUG_ON(tp->token == Opt_onerror_panic);
	seq_printf(seq, ",%s", tp->pattern);

	mval = sbi->s_mount_opt & UFS_MOUNT_ONERROR;
	while (tp->token != Opt_err && tp->token != mval)
		++tp;
	BUG_ON(tp->token == Opt_err);
	seq_printf(seq, ",%s", tp->pattern);

	return 0;
}

static int ufs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct ufs_sb_private_info *uspi= UFS_SB(sb)->s_uspi;
	unsigned  flags = UFS_SB(sb)->s_flags;
	struct ufs_super_block_third *usb3;
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	lock_ufs(sb);

	usb3 = ubh_get_usb_third(uspi);

	if ((flags & UFS_TYPE_MASK) == UFS_TYPE_UFS2) {
		buf->f_type = UFS2_MAGIC;
		buf->f_blocks = fs64_to_cpu(sb, usb3->fs_un1.fs_u2.fs_dsize);
	} else {
		buf->f_type = UFS_MAGIC;
		buf->f_blocks = uspi->s_dsize;
	}
	buf->f_bfree = ufs_blkstofrags(uspi->cs_total.cs_nbfree) +
		uspi->cs_total.cs_nffree;
	buf->f_ffree = uspi->cs_total.cs_nifree;
	buf->f_bsize = sb->s_blocksize;
	buf->f_bavail = (buf->f_bfree > (((long)buf->f_blocks / 100) * uspi->s_minfree))
		? (buf->f_bfree - (((long)buf->f_blocks / 100) * uspi->s_minfree)) : 0;
	buf->f_files = uspi->s_ncg * uspi->s_ipg;
	buf->f_namelen = UFS_MAXNAMLEN;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);

	unlock_ufs(sb);

	return 0;
}

static struct kmem_cache * ufs_inode_cachep;

static struct inode *ufs_alloc_inode(struct super_block *sb)
{
	struct ufs_inode_info *ei;
	ei = (struct ufs_inode_info *)kmem_cache_alloc(ufs_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;
	ei->vfs_inode.i_version = 1;
	return &ei->vfs_inode;
}

static void ufs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(ufs_inode_cachep, UFS_I(inode));
}

static void ufs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, ufs_i_callback);
}

static void init_once(void *foo)
{
	struct ufs_inode_info *ei = (struct ufs_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	ufs_inode_cachep = kmem_cache_create("ufs_inode_cache",
					     sizeof(struct ufs_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (ufs_inode_cachep == NULL)
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
	kmem_cache_destroy(ufs_inode_cachep);
}

static const struct super_operations ufs_super_ops = {
	.alloc_inode	= ufs_alloc_inode,
	.destroy_inode	= ufs_destroy_inode,
	.write_inode	= ufs_write_inode,
	.evict_inode	= ufs_evict_inode,
	.put_super	= ufs_put_super,
	.sync_fs	= ufs_sync_fs,
	.statfs		= ufs_statfs,
	.remount_fs	= ufs_remount,
	.show_options   = ufs_show_options,
};

static struct dentry *ufs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, ufs_fill_super);
}

static struct file_system_type ufs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ufs",
	.mount		= ufs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("ufs");

static int __init init_ufs_fs(void)
{
	int err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&ufs_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_ufs_fs(void)
{
	unregister_filesystem(&ufs_fs_type);
	destroy_inodecache();
}

module_init(init_ufs_fs)
module_exit(exit_ufs_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../linux-3.17/fs/ufs/super.c */
/************************************************************/
/*
 *  linux/fs/ufs/symlink.c
 *
 * Only fast symlinks left here - the rest is done by generic code. AV, 1999
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@emai.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 *  from
 *
 *  linux/fs/ext2/symlink.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/symlink.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 symlink handling code
 */

// #include <linux/fs.h>
#include <linux/namei.h>

// #include "ufs_fs.h"
// #include "ufs.h"


static void *ufs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ufs_inode_info *p = UFS_I(dentry->d_inode);
	nd_set_link(nd, (char*)p->i_u1.i_symlink);
	return NULL;
}

const struct inode_operations ufs_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= ufs_follow_link,
	.setattr	= ufs_setattr,
};

const struct inode_operations ufs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= ufs_setattr,
};
/************************************************************/
/* ../linux-3.17/fs/ufs/symlink.c */
/************************************************************/
/*
 *  linux/fs/ufs/truncate.c
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 *
 *  from
 *
 *  linux/fs/ext2/truncate.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/truncate.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

/*
 * Real random numbers for secure rm added 94/02/18
 * Idea from Pierre del Perugia <delperug@gla.ecoledoc.ibp.fr>
 */

/*
 * Adoptation to use page cache and UFS2 write support by
 * Evgeniy Dushistov <dushistov@mail.ru>, 2006-2007
 */

// #include <linux/errno.h>
// #include <linux/fs.h>
#include <linux/fcntl.h>
// #include <linux/time.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <linux/buffer_head.h>
// #include <linux/blkdev.h>
// #include <linux/sched.h>

// #include "ufs_fs.h"
// #include "ufs.h"
// #include "swab.h"
// #include "util.h"

/*
 * Secure deletion currently doesn't work. It interacts very badly
 * with buffers shared with memory mappings, and for that reason
 * can't be done in the truncate() routines. It should instead be
 * done separately in "release()" before calling the truncate routines
 * that will release the actual file blocks.
 *
 *		Linus
 */

#define DIRECT_BLOCK ((inode->i_size + uspi->s_bsize - 1) >> uspi->s_bshift)
#define DIRECT_FRAGMENT ((inode->i_size + uspi->s_fsize - 1) >> uspi->s_fshift)


static int ufs_trunc_direct(struct inode *inode)
{
	struct ufs_inode_info *ufsi = UFS_I(inode);
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	void *p;
	u64 frag1, frag2, frag3, frag4, block1, block2;
	unsigned frag_to_free, free_count;
	unsigned i, tmp;
	int retry;

	UFSD("ENTER: ino %lu\n", inode->i_ino);

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;

	frag_to_free = 0;
	free_count = 0;
	retry = 0;

	frag1 = DIRECT_FRAGMENT;
	frag4 = min_t(u64, UFS_NDIR_FRAGMENT, ufsi->i_lastfrag);
	frag2 = ((frag1 & uspi->s_fpbmask) ? ((frag1 | uspi->s_fpbmask) + 1) : frag1);
	frag3 = frag4 & ~uspi->s_fpbmask;
	block1 = block2 = 0;
	if (frag2 > frag3) {
		frag2 = frag4;
		frag3 = frag4 = 0;
	} else if (frag2 < frag3) {
		block1 = ufs_fragstoblks (frag2);
		block2 = ufs_fragstoblks (frag3);
	}

	UFSD("ino %lu, frag1 %llu, frag2 %llu, block1 %llu, block2 %llu,"
	     " frag3 %llu, frag4 %llu\n", inode->i_ino,
	     (unsigned long long)frag1, (unsigned long long)frag2,
	     (unsigned long long)block1, (unsigned long long)block2,
	     (unsigned long long)frag3, (unsigned long long)frag4);

	if (frag1 >= frag2)
		goto next1;

	/*
	 * Free first free fragments
	 */
	p = ufs_get_direct_data_ptr(uspi, ufsi, ufs_fragstoblks(frag1));
	tmp = ufs_data_ptr_to_cpu(sb, p);
	if (!tmp )
		ufs_panic (sb, "ufs_trunc_direct", "internal error");
	frag2 -= frag1;
	frag1 = ufs_fragnum (frag1);

	ufs_free_fragments(inode, tmp + frag1, frag2);
	mark_inode_dirty(inode);
	frag_to_free = tmp + frag1;

next1:
	/*
	 * Free whole blocks
	 */
	for (i = block1 ; i < block2; i++) {
		p = ufs_get_direct_data_ptr(uspi, ufsi, i);
		tmp = ufs_data_ptr_to_cpu(sb, p);
		if (!tmp)
			continue;
		ufs_data_ptr_clear(uspi, p);

		if (free_count == 0) {
			frag_to_free = tmp;
			free_count = uspi->s_fpb;
		} else if (free_count > 0 && frag_to_free == tmp - free_count)
			free_count += uspi->s_fpb;
		else {
			ufs_free_blocks (inode, frag_to_free, free_count);
			frag_to_free = tmp;
			free_count = uspi->s_fpb;
		}
		mark_inode_dirty(inode);
	}

	if (free_count > 0)
		ufs_free_blocks (inode, frag_to_free, free_count);

	if (frag3 >= frag4)
		goto next3;

	/*
	 * Free last free fragments
	 */
	p = ufs_get_direct_data_ptr(uspi, ufsi, ufs_fragstoblks(frag3));
	tmp = ufs_data_ptr_to_cpu(sb, p);
	if (!tmp )
		ufs_panic(sb, "ufs_truncate_direct", "internal error");
	frag4 = ufs_fragnum (frag4);
	ufs_data_ptr_clear(uspi, p);

	ufs_free_fragments (inode, tmp, frag4);
	mark_inode_dirty(inode);
 next3:

	UFSD("EXIT: ino %lu\n", inode->i_ino);
	return retry;
}


static int ufs_trunc_indirect(struct inode *inode, u64 offset, void *p)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_buffer_head * ind_ubh;
	void *ind;
	u64 tmp, indirect_block, i, frag_to_free;
	unsigned free_count;
	int retry;

	UFSD("ENTER: ino %lu, offset %llu, p: %p\n",
	     inode->i_ino, (unsigned long long)offset, p);

	BUG_ON(!p);

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;

	frag_to_free = 0;
	free_count = 0;
	retry = 0;

	tmp = ufs_data_ptr_to_cpu(sb, p);
	if (!tmp)
		return 0;
	ind_ubh = ubh_bread(sb, tmp, uspi->s_bsize);
	if (tmp != ufs_data_ptr_to_cpu(sb, p)) {
		ubh_brelse (ind_ubh);
		return 1;
	}
	if (!ind_ubh) {
		ufs_data_ptr_clear(uspi, p);
		return 0;
	}

	indirect_block = (DIRECT_BLOCK > offset) ? (DIRECT_BLOCK - offset) : 0;
	for (i = indirect_block; i < uspi->s_apb; i++) {
		ind = ubh_get_data_ptr(uspi, ind_ubh, i);
		tmp = ufs_data_ptr_to_cpu(sb, ind);
		if (!tmp)
			continue;

		ufs_data_ptr_clear(uspi, ind);
		ubh_mark_buffer_dirty(ind_ubh);
		if (free_count == 0) {
			frag_to_free = tmp;
			free_count = uspi->s_fpb;
		} else if (free_count > 0 && frag_to_free == tmp - free_count)
			free_count += uspi->s_fpb;
		else {
			ufs_free_blocks (inode, frag_to_free, free_count);
			frag_to_free = tmp;
			free_count = uspi->s_fpb;
		}

		mark_inode_dirty(inode);
	}

	if (free_count > 0) {
		ufs_free_blocks (inode, frag_to_free, free_count);
	}
	for (i = 0; i < uspi->s_apb; i++)
		if (!ufs_is_data_ptr_zero(uspi,
					  ubh_get_data_ptr(uspi, ind_ubh, i)))
			break;
	if (i >= uspi->s_apb) {
		tmp = ufs_data_ptr_to_cpu(sb, p);
		ufs_data_ptr_clear(uspi, p);

		ufs_free_blocks (inode, tmp, uspi->s_fpb);
		mark_inode_dirty(inode);
		ubh_bforget(ind_ubh);
		ind_ubh = NULL;
	}
	if (IS_SYNC(inode) && ind_ubh && ubh_buffer_dirty(ind_ubh))
		ubh_sync_block(ind_ubh);
	ubh_brelse (ind_ubh);

	UFSD("EXIT: ino %lu\n", inode->i_ino);

	return retry;
}

static int ufs_trunc_dindirect(struct inode *inode, u64 offset, void *p)
{
	struct super_block * sb;
	struct ufs_sb_private_info * uspi;
	struct ufs_buffer_head *dind_bh;
	u64 i, tmp, dindirect_block;
	void *dind;
	int retry = 0;

	UFSD("ENTER: ino %lu\n", inode->i_ino);

	sb = inode->i_sb;
	uspi = UFS_SB(sb)->s_uspi;

	dindirect_block = (DIRECT_BLOCK > offset)
		? ((DIRECT_BLOCK - offset) >> uspi->s_apbshift) : 0;
	retry = 0;

	tmp = ufs_data_ptr_to_cpu(sb, p);
	if (!tmp)
		return 0;
	dind_bh = ubh_bread(sb, tmp, uspi->s_bsize);
	if (tmp != ufs_data_ptr_to_cpu(sb, p)) {
		ubh_brelse (dind_bh);
		return 1;
	}
	if (!dind_bh) {
		ufs_data_ptr_clear(uspi, p);
		return 0;
	}

	for (i = dindirect_block ; i < uspi->s_apb ; i++) {
		dind = ubh_get_data_ptr(uspi, dind_bh, i);
		tmp = ufs_data_ptr_to_cpu(sb, dind);
		if (!tmp)
			continue;
		retry |= ufs_trunc_indirect (inode, offset + (i << uspi->s_apbshift), dind);
		ubh_mark_buffer_dirty(dind_bh);
	}

	for (i = 0; i < uspi->s_apb; i++)
		if (!ufs_is_data_ptr_zero(uspi,
					  ubh_get_data_ptr(uspi, dind_bh, i)))
			break;
	if (i >= uspi->s_apb) {
		tmp = ufs_data_ptr_to_cpu(sb, p);
		ufs_data_ptr_clear(uspi, p);

		ufs_free_blocks(inode, tmp, uspi->s_fpb);
		mark_inode_dirty(inode);
		ubh_bforget(dind_bh);
		dind_bh = NULL;
	}
	if (IS_SYNC(inode) && dind_bh && ubh_buffer_dirty(dind_bh))
		ubh_sync_block(dind_bh);
	ubh_brelse (dind_bh);

	UFSD("EXIT: ino %lu\n", inode->i_ino);

	return retry;
}

static int ufs_trunc_tindirect(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	struct ufs_inode_info *ufsi = UFS_I(inode);
	struct ufs_buffer_head * tind_bh;
	u64 tindirect_block, tmp, i;
	void *tind, *p;
	int retry;

	UFSD("ENTER: ino %lu\n", inode->i_ino);

	retry = 0;

	tindirect_block = (DIRECT_BLOCK > (UFS_NDADDR + uspi->s_apb + uspi->s_2apb))
		? ((DIRECT_BLOCK - UFS_NDADDR - uspi->s_apb - uspi->s_2apb) >> uspi->s_2apbshift) : 0;

	p = ufs_get_direct_data_ptr(uspi, ufsi, UFS_TIND_BLOCK);
	if (!(tmp = ufs_data_ptr_to_cpu(sb, p)))
		return 0;
	tind_bh = ubh_bread (sb, tmp, uspi->s_bsize);
	if (tmp != ufs_data_ptr_to_cpu(sb, p)) {
		ubh_brelse (tind_bh);
		return 1;
	}
	if (!tind_bh) {
		ufs_data_ptr_clear(uspi, p);
		return 0;
	}

	for (i = tindirect_block ; i < uspi->s_apb ; i++) {
		tind = ubh_get_data_ptr(uspi, tind_bh, i);
		retry |= ufs_trunc_dindirect(inode, UFS_NDADDR +
			uspi->s_apb + ((i + 1) << uspi->s_2apbshift), tind);
		ubh_mark_buffer_dirty(tind_bh);
	}
	for (i = 0; i < uspi->s_apb; i++)
		if (!ufs_is_data_ptr_zero(uspi,
					  ubh_get_data_ptr(uspi, tind_bh, i)))
			break;
	if (i >= uspi->s_apb) {
		tmp = ufs_data_ptr_to_cpu(sb, p);
		ufs_data_ptr_clear(uspi, p);

		ufs_free_blocks(inode, tmp, uspi->s_fpb);
		mark_inode_dirty(inode);
		ubh_bforget(tind_bh);
		tind_bh = NULL;
	}
	if (IS_SYNC(inode) && tind_bh && ubh_buffer_dirty(tind_bh))
		ubh_sync_block(tind_bh);
	ubh_brelse (tind_bh);

	UFSD("EXIT: ino %lu\n", inode->i_ino);
	return retry;
}

static int ufs_alloc_lastblock(struct inode *inode)
{
	int err = 0;
	struct super_block *sb = inode->i_sb;
	struct address_space *mapping = inode->i_mapping;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	unsigned i, end;
	sector_t lastfrag;
	struct page *lastpage;
	struct buffer_head *bh;
	u64 phys64;

	lastfrag = (i_size_read(inode) + uspi->s_fsize - 1) >> uspi->s_fshift;

	if (!lastfrag)
		goto out;

	lastfrag--;

	lastpage = ufs_get_locked_page(mapping, lastfrag >>
				       (PAGE_CACHE_SHIFT - inode->i_blkbits));
       if (IS_ERR(lastpage)) {
               err = -EIO;
               goto out;
       }

       end = lastfrag & ((1 << (PAGE_CACHE_SHIFT - inode->i_blkbits)) - 1);
       bh = page_buffers(lastpage);
       for (i = 0; i < end; ++i)
               bh = bh->b_this_page;


       err = ufs_getfrag_block(inode, lastfrag, bh, 1);

       if (unlikely(err))
	       goto out_unlock;

       if (buffer_new(bh)) {
	       clear_buffer_new(bh);
	       unmap_underlying_metadata(bh->b_bdev,
					 bh->b_blocknr);
	       /*
		* we do not zeroize fragment, because of
		* if it maped to hole, it already contains zeroes
		*/
	       set_buffer_uptodate(bh);
	       mark_buffer_dirty(bh);
	       set_page_dirty(lastpage);
       }

       if (lastfrag >= UFS_IND_FRAGMENT) {
	       end = uspi->s_fpb - ufs_fragnum(lastfrag) - 1;
	       phys64 = bh->b_blocknr + 1;
	       for (i = 0; i < end; ++i) {
		       bh = sb_getblk(sb, i + phys64);
		       lock_buffer(bh);
		       memset(bh->b_data, 0, sb->s_blocksize);
		       set_buffer_uptodate(bh);
		       mark_buffer_dirty(bh);
		       unlock_buffer(bh);
		       sync_dirty_buffer(bh);
		       brelse(bh);
	       }
       }
out_unlock:
       ufs_put_locked_page(lastpage);
out:
       return err;
}

int ufs_truncate(struct inode *inode, loff_t old_i_size)
{
	struct ufs_inode_info *ufsi = UFS_I(inode);
	struct super_block *sb = inode->i_sb;
	struct ufs_sb_private_info *uspi = UFS_SB(sb)->s_uspi;
	int retry, err = 0;

	UFSD("ENTER: ino %lu, i_size: %llu, old_i_size: %llu\n",
	     inode->i_ino, (unsigned long long)i_size_read(inode),
	     (unsigned long long)old_i_size);

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
	      S_ISLNK(inode->i_mode)))
		return -EINVAL;
	if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
		return -EPERM;

	err = ufs_alloc_lastblock(inode);

	if (err) {
		i_size_write(inode, old_i_size);
		goto out;
	}

	block_truncate_page(inode->i_mapping, inode->i_size, ufs_getfrag_block);

	while (1) {
		retry = ufs_trunc_direct(inode);
		retry |= ufs_trunc_indirect(inode, UFS_IND_BLOCK,
					    ufs_get_direct_data_ptr(uspi, ufsi,
								    UFS_IND_BLOCK));
		retry |= ufs_trunc_dindirect(inode, UFS_IND_BLOCK + uspi->s_apb,
					     ufs_get_direct_data_ptr(uspi, ufsi,
								     UFS_DIND_BLOCK));
		retry |= ufs_trunc_tindirect (inode);
		if (!retry)
			break;
		if (IS_SYNC(inode) && (inode->i_state & I_DIRTY))
			ufs_sync_inode (inode);
		yield();
	}

	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
	ufsi->i_lastfrag = DIRECT_FRAGMENT;
	mark_inode_dirty(inode);
out:
	UFSD("EXIT: err %d\n", err);
	return err;
}

int ufs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	unsigned int ia_valid = attr->ia_valid;
	int error;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if (ia_valid & ATTR_SIZE && attr->ia_size != inode->i_size) {
		loff_t old_i_size = inode->i_size;

		/* XXX(truncate): truncate_setsize should be called last */
		truncate_setsize(inode, attr->ia_size);

		lock_ufs(inode->i_sb);
		error = ufs_truncate(inode, old_i_size);
		unlock_ufs(inode->i_sb);
		if (error)
			return error;
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
	return 0;
}

const struct inode_operations ufs_file_inode_operations = {
	.setattr = ufs_setattr,
};
/************************************************************/
/* ../linux-3.17/fs/ufs/truncate.c */
/************************************************************/
/*
 *  linux/fs/ufs/util.c
 *
 * Copyright (C) 1998
 * Daniel Pirkl <daniel.pirkl@email.cz>
 * Charles University, Faculty of Mathematics and Physics
 */

// #include <linux/string.h>
// #include <linux/slab.h>
// #include <linux/buffer_head.h>

// #include "ufs_fs.h"
// #include "ufs.h"
// #include "swab.h"
// #include "util.h"

struct ufs_buffer_head * _ubh_bread_ (struct ufs_sb_private_info * uspi,
	struct super_block *sb, u64 fragment, u64 size)
{
	struct ufs_buffer_head * ubh;
	unsigned i, j ;
	u64  count = 0;
	if (size & ~uspi->s_fmask)
		return NULL;
	count = size >> uspi->s_fshift;
	if (count > UFS_MAXFRAG)
		return NULL;
	ubh = kmalloc (sizeof (struct ufs_buffer_head), GFP_NOFS);
	if (!ubh)
		return NULL;
	ubh->fragment = fragment;
	ubh->count = count;
	for (i = 0; i < count; i++)
		if (!(ubh->bh[i] = sb_bread(sb, fragment + i)))
			goto failed;
	for (; i < UFS_MAXFRAG; i++)
		ubh->bh[i] = NULL;
	return ubh;
failed:
	for (j = 0; j < i; j++)
		brelse (ubh->bh[j]);
	kfree(ubh);
	return NULL;
}

struct ufs_buffer_head * ubh_bread_uspi (struct ufs_sb_private_info * uspi,
	struct super_block *sb, u64 fragment, u64 size)
{
	unsigned i, j;
	u64 count = 0;
	if (size & ~uspi->s_fmask)
		return NULL;
	count = size >> uspi->s_fshift;
	if (count <= 0 || count > UFS_MAXFRAG)
		return NULL;
	USPI_UBH(uspi)->fragment = fragment;
	USPI_UBH(uspi)->count = count;
	for (i = 0; i < count; i++)
		if (!(USPI_UBH(uspi)->bh[i] = sb_bread(sb, fragment + i)))
			goto failed;
	for (; i < UFS_MAXFRAG; i++)
		USPI_UBH(uspi)->bh[i] = NULL;
	return USPI_UBH(uspi);
failed:
	for (j = 0; j < i; j++)
		brelse (USPI_UBH(uspi)->bh[j]);
	return NULL;
}

void ubh_brelse (struct ufs_buffer_head * ubh)
{
	unsigned i;
	if (!ubh)
		return;
	for (i = 0; i < ubh->count; i++)
		brelse (ubh->bh[i]);
	kfree (ubh);
}

void ubh_brelse_uspi (struct ufs_sb_private_info * uspi)
{
	unsigned i;
	if (!USPI_UBH(uspi))
		return;
	for ( i = 0; i < USPI_UBH(uspi)->count; i++ ) {
		brelse (USPI_UBH(uspi)->bh[i]);
		USPI_UBH(uspi)->bh[i] = NULL;
	}
}

void ubh_mark_buffer_dirty (struct ufs_buffer_head * ubh)
{
	unsigned i;
	if (!ubh)
		return;
	for ( i = 0; i < ubh->count; i++ )
		mark_buffer_dirty (ubh->bh[i]);
}

void ubh_mark_buffer_uptodate (struct ufs_buffer_head * ubh, int flag)
{
	unsigned i;
	if (!ubh)
		return;
	if (flag) {
		for ( i = 0; i < ubh->count; i++ )
			set_buffer_uptodate (ubh->bh[i]);
	} else {
		for ( i = 0; i < ubh->count; i++ )
			clear_buffer_uptodate (ubh->bh[i]);
	}
}

void ubh_sync_block(struct ufs_buffer_head *ubh)
{
	if (ubh) {
		unsigned i;

		for (i = 0; i < ubh->count; i++)
			write_dirty_buffer(ubh->bh[i], WRITE);

		for (i = 0; i < ubh->count; i++)
			wait_on_buffer(ubh->bh[i]);
	}
}

void ubh_bforget (struct ufs_buffer_head * ubh)
{
	unsigned i;
	if (!ubh)
		return;
	for ( i = 0; i < ubh->count; i++ ) if ( ubh->bh[i] )
		bforget (ubh->bh[i]);
}

int ubh_buffer_dirty (struct ufs_buffer_head * ubh)
{
	unsigned i;
	unsigned result = 0;
	if (!ubh)
		return 0;
	for ( i = 0; i < ubh->count; i++ )
		result |= buffer_dirty(ubh->bh[i]);
	return result;
}

void _ubh_ubhcpymem_(struct ufs_sb_private_info * uspi,
	unsigned char * mem, struct ufs_buffer_head * ubh, unsigned size)
{
	unsigned len, bhno;
	if (size > (ubh->count << uspi->s_fshift))
		size = ubh->count << uspi->s_fshift;
	bhno = 0;
	while (size) {
		len = min_t(unsigned int, size, uspi->s_fsize);
		memcpy (mem, ubh->bh[bhno]->b_data, len);
		mem += uspi->s_fsize;
		size -= len;
		bhno++;
	}
}

void _ubh_memcpyubh_(struct ufs_sb_private_info * uspi,
	struct ufs_buffer_head * ubh, unsigned char * mem, unsigned size)
{
	unsigned len, bhno;
	if (size > (ubh->count << uspi->s_fshift))
		size = ubh->count << uspi->s_fshift;
	bhno = 0;
	while (size) {
		len = min_t(unsigned int, size, uspi->s_fsize);
		memcpy (ubh->bh[bhno]->b_data, mem, len);
		mem += uspi->s_fsize;
		size -= len;
		bhno++;
	}
}

dev_t
ufs_get_inode_dev(struct super_block *sb, struct ufs_inode_info *ufsi)
{
	__u32 fs32;
	dev_t dev;

	if ((UFS_SB(sb)->s_flags & UFS_ST_MASK) == UFS_ST_SUNx86)
		fs32 = fs32_to_cpu(sb, ufsi->i_u1.i_data[1]);
	else
		fs32 = fs32_to_cpu(sb, ufsi->i_u1.i_data[0]);
	switch (UFS_SB(sb)->s_flags & UFS_ST_MASK) {
	case UFS_ST_SUNx86:
	case UFS_ST_SUN:
		if ((fs32 & 0xffff0000) == 0 ||
		    (fs32 & 0xffff0000) == 0xffff0000)
			dev = old_decode_dev(fs32 & 0x7fff);
		else
			dev = MKDEV(sysv_major(fs32), sysv_minor(fs32));
		break;

	default:
		dev = old_decode_dev(fs32);
		break;
	}
	return dev;
}

void
ufs_set_inode_dev(struct super_block *sb, struct ufs_inode_info *ufsi, dev_t dev)
{
	__u32 fs32;

	switch (UFS_SB(sb)->s_flags & UFS_ST_MASK) {
	case UFS_ST_SUNx86:
	case UFS_ST_SUN:
		fs32 = sysv_encode_dev(dev);
		if ((fs32 & 0xffff8000) == 0) {
			fs32 = old_encode_dev(dev);
		}
		break;

	default:
		fs32 = old_encode_dev(dev);
		break;
	}
	if ((UFS_SB(sb)->s_flags & UFS_ST_MASK) == UFS_ST_SUNx86)
		ufsi->i_u1.i_data[1] = cpu_to_fs32(sb, fs32);
	else
		ufsi->i_u1.i_data[0] = cpu_to_fs32(sb, fs32);
}

/**
 * ufs_get_locked_page() - locate, pin and lock a pagecache page, if not exist
 * read it from disk.
 * @mapping: the address_space to search
 * @index: the page index
 *
 * Locates the desired pagecache page, if not exist we'll read it,
 * locks it, increments its reference
 * count and returns its address.
 *
 */

struct page *ufs_get_locked_page(struct address_space *mapping,
				 pgoff_t index)
{
	struct page *page;

	page = find_lock_page(mapping, index);
	if (!page) {
		page = read_mapping_page(mapping, index, NULL);

		if (IS_ERR(page)) {
			printk(KERN_ERR "ufs_change_blocknr: "
			       "read_mapping_page error: ino %lu, index: %lu\n",
			       mapping->host->i_ino, index);
			goto out;
		}

		lock_page(page);

		if (unlikely(page->mapping == NULL)) {
			/* Truncate got there first */
			unlock_page(page);
			page_cache_release(page);
			page = NULL;
			goto out;
		}

		if (!PageUptodate(page) || PageError(page)) {
			unlock_page(page);
			page_cache_release(page);

			printk(KERN_ERR "ufs_change_blocknr: "
			       "can not read page: ino %lu, index: %lu\n",
			       mapping->host->i_ino, index);

			page = ERR_PTR(-EIO);
		}
	}
out:
	return page;
}
/************************************************************/
/* ../linux-3.17/fs/ufs/util.c */
/************************************************************/
