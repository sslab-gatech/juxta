/**
 * aops.c - NTFS kernel address space operations and page cache handling.
 *
 * Copyright (c) 2001-2014 Anton Altaparmakov and Tuxera Inc.
 * Copyright (c) 2002 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/bit_spinlock.h>
#include "../../inc/__fss.h"

#include "aops.h"
#include "attrib.h"
#include "debug.h"
#include "inode.h"
#include "mft.h"
#include "runlist.h"
#include "types.h"
#include "ntfs.h"
#include "../../inc/__fss.h"

/**
 * ntfs_end_buffer_async_read - async io completion for reading attributes
 * @bh:		buffer head on which io is completed
 * @uptodate:	whether @bh is now uptodate or not
 *
 * Asynchronous I/O completion handler for reading pages belonging to the
 * attribute address space of an inode.  The inodes can either be files or
 * directories or they can be fake inodes describing some attribute.
 *
 * If NInoMstProtected(), perform the post read mst fixups when all IO on the
 * page has been completed and mark the page uptodate or set the error bit on
 * the page.  To determine the size of the records that need fixing up, we
 * cheat a little bit by setting the index_block_size in ntfs_inode to the ntfs
 * record size, and index_block_size_bits, to the log(base 2) of the ntfs
 * record size.
 */
static void ntfs_end_buffer_async_read(struct buffer_head *bh, int uptodate)
{
	unsigned long flags;
	struct buffer_head *first, *tmp;
	struct page *page;
	struct inode *vi;
	ntfs_inode *ni;
	int page_uptodate = 1;

	page = bh->b_page;
	vi = page->mapping->host;
	ni = NTFS_I(vi);

	if (likely(uptodate)) {
		loff_t i_size;
		s64 file_ofs, init_size;

		set_buffer_uptodate(bh);

		file_ofs = ((s64)page->index << PAGE_CACHE_SHIFT) +
				bh_offset(bh);
		read_lock_irqsave(&ni->size_lock, flags);
		init_size = ni->initialized_size;
		i_size = i_size_read(vi);
		read_unlock_irqrestore(&ni->size_lock, flags);
		if (unlikely(init_size > i_size)) {
			/* Race with shrinking truncate. */
			init_size = i_size;
		}
		/* Check for the current buffer head overflowing. */
		if (unlikely(file_ofs + bh->b_size > init_size)) {
			int ofs;
			void *kaddr;

			ofs = 0;
			if (file_ofs < init_size)
				ofs = init_size - file_ofs;
			local_irq_save(flags);
			kaddr = kmap_atomic(page);
			memset(kaddr + bh_offset(bh) + ofs, 0,
					bh->b_size - ofs);
			flush_dcache_page(page);
			kunmap_atomic(kaddr);
			local_irq_restore(flags);
		}
	} else {
		clear_buffer_uptodate(bh);
		SetPageError(page);
		ntfs_error(ni->vol->sb, "Buffer I/O error, logical block "
				"0x%llx.", (unsigned long long)bh->b_blocknr);
	}
	first = page_buffers(page);
	local_irq_save(flags);
	bit_spin_lock(BH_Uptodate_Lock, &first->b_state);
	clear_buffer_async_read(bh);
	unlock_buffer(bh);
	tmp = bh;
	do {
		if (!buffer_uptodate(tmp))
			page_uptodate = 0;
		if (buffer_async_read(tmp)) {
			if (likely(buffer_locked(tmp)))
				goto still_busy;
			/* Async buffers must be locked. */
			BUG();
		}
		tmp = tmp->b_this_page;
	} while (tmp != bh);
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);
	/*
	 * If none of the buffers had errors then we can set the page uptodate,
	 * but we first have to perform the post read mst fixups, if the
	 * attribute is mst protected, i.e. if NInoMstProteced(ni) is true.
	 * Note we ignore fixup errors as those are detected when
	 * map_mft_record() is called which gives us per record granularity
	 * rather than per page granularity.
	 */
	if (!NInoMstProtected(ni)) {
		if (likely(page_uptodate && !PageError(page)))
			SetPageUptodate(page);
	} else {
		u8 *kaddr;
		unsigned int i, recs;
		u32 rec_size;

		rec_size = ni->itype.index.block_size;
		recs = PAGE_CACHE_SIZE / rec_size;
		/* Should have been verified before we got here... */
		BUG_ON(!recs);
		local_irq_save(flags);
		kaddr = kmap_atomic(page);
		for (i = 0; i < recs; i++)
			post_read_mst_fixup((NTFS_RECORD*)(kaddr +
					i * rec_size), rec_size);
		kunmap_atomic(kaddr);
		local_irq_restore(flags);
		flush_dcache_page(page);
		if (likely(page_uptodate && !PageError(page)))
			SetPageUptodate(page);
	}
	unlock_page(page);
	return;
still_busy:
	bit_spin_unlock(BH_Uptodate_Lock, &first->b_state);
	local_irq_restore(flags);
	return;
}

/**
 * ntfs_read_block - fill a @page of an address space with data
 * @page:	page cache page to fill with data
 *
 * Fill the page @page of the address space belonging to the @page->host inode.
 * We read each buffer asynchronously and when all buffers are read in, our io
 * completion handler ntfs_end_buffer_read_async(), if required, automatically
 * applies the mst fixups to the page before finally marking it uptodate and
 * unlocking it.
 *
 * We only enforce allocated_size limit because i_size is checked for in
 * generic_file_read().
 *
 * Return 0 on success and -errno on error.
 *
 * Contains an adapted version of fs/buffer.c::block_read_full_page().
 */
static int ntfs_read_block(struct page *page)
{
	loff_t i_size;
	VCN vcn;
	LCN lcn;
	s64 init_size;
	struct inode *vi;
	ntfs_inode *ni;
	ntfs_volume *vol;
	runlist_element *rl;
	struct buffer_head *bh, *head, *arr[MAX_BUF_PER_PAGE];
	sector_t iblock, lblock, zblock;
	unsigned long flags;
	unsigned int blocksize, vcn_ofs;
	int i, nr;
	unsigned char blocksize_bits;

	vi = page->mapping->host;
	ni = NTFS_I(vi);
	vol = ni->vol;

	/* $MFT/$DATA must have its complete runlist in memory at all times. */
	BUG_ON(!ni->runlist.rl && !ni->mft_no && !NInoAttr(ni));

	blocksize = vol->sb->s_blocksize;
	blocksize_bits = vol->sb->s_blocksize_bits;

	if (!page_has_buffers(page)) {
		create_empty_buffers(page, blocksize, 0);
		if (unlikely(!page_has_buffers(page))) {
			unlock_page(page);
			return -ENOMEM;
		}
	}
	bh = head = page_buffers(page);
	BUG_ON(!bh);

	/*
	 * We may be racing with truncate.  To avoid some of the problems we
	 * now take a snapshot of the various sizes and use those for the whole
	 * of the function.  In case of an extending truncate it just means we
	 * may leave some buffers unmapped which are now allocated.  This is
	 * not a problem since these buffers will just get mapped when a write
	 * occurs.  In case of a shrinking truncate, we will detect this later
	 * on due to the runlist being incomplete and if the page is being
	 * fully truncated, truncate will throw it away as soon as we unlock
	 * it so no need to worry what we do with it.
	 */
	iblock = (s64)page->index << (PAGE_CACHE_SHIFT - blocksize_bits);
	read_lock_irqsave(&ni->size_lock, flags);
	lblock = (ni->allocated_size + blocksize - 1) >> blocksize_bits;
	init_size = ni->initialized_size;
	i_size = i_size_read(vi);
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (unlikely(init_size > i_size)) {
		/* Race with shrinking truncate. */
		init_size = i_size;
	}
	zblock = (init_size + blocksize - 1) >> blocksize_bits;

	/* Loop through all the buffers in the page. */
	rl = NULL;
	nr = i = 0;
	do {
		int err = 0;

		if (unlikely(buffer_uptodate(bh)))
			continue;
		if (unlikely(buffer_mapped(bh))) {
			arr[nr++] = bh;
			continue;
		}
		bh->b_bdev = vol->sb->s_bdev;
		/* Is the block within the allowed limits? */
		if (iblock < lblock) {
			bool is_retry = false;

			/* Convert iblock into corresponding vcn and offset. */
			vcn = (VCN)iblock << blocksize_bits >>
					vol->cluster_size_bits;
			vcn_ofs = ((VCN)iblock << blocksize_bits) &
					vol->cluster_size_mask;
			if (!rl) {
lock_retry_remap:
				down_read(&ni->runlist.lock);
				rl = ni->runlist.rl;
			}
			if (likely(rl != NULL)) {
				/* Seek to element containing target vcn. */
				while (rl->length && rl[1].vcn <= vcn)
					rl++;
				lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
			} else
				lcn = LCN_RL_NOT_MAPPED;
			/* Successful remap. */
			if (lcn >= 0) {
				/* Setup buffer head to correct block. */
				bh->b_blocknr = ((lcn << vol->cluster_size_bits)
						+ vcn_ofs) >> blocksize_bits;
				set_buffer_mapped(bh);
				/* Only read initialized data blocks. */
				if (iblock < zblock) {
					arr[nr++] = bh;
					continue;
				}
				/* Fully non-initialized data block, zero it. */
				goto handle_zblock;
			}
			/* It is a hole, need to zero it. */
			if (lcn == LCN_HOLE)
				goto handle_hole;
			/* If first try and runlist unmapped, map and retry. */
			if (!is_retry && lcn == LCN_RL_NOT_MAPPED) {
				is_retry = true;
				/*
				 * Attempt to map runlist, dropping lock for
				 * the duration.
				 */
				up_read(&ni->runlist.lock);
				err = ntfs_map_runlist(ni, vcn);
				if (likely(!err))
					goto lock_retry_remap;
				rl = NULL;
			} else if (!rl)
				up_read(&ni->runlist.lock);
			/*
			 * If buffer is outside the runlist, treat it as a
			 * hole.  This can happen due to concurrent truncate
			 * for example.
			 */
			if (err == -ENOENT || lcn == LCN_ENOENT) {
				err = 0;
				goto handle_hole;
			}
			/* Hard error, zero out region. */
			if (!err)
				err = -EIO;
			bh->b_blocknr = -1;
			SetPageError(page);
			ntfs_error(vol->sb, "Failed to read from inode 0x%lx, "
					"attribute type 0x%x, vcn 0x%llx, "
					"offset 0x%x because its location on "
					"disk could not be determined%s "
					"(error code %i).", ni->mft_no,
					ni->type, (unsigned long long)vcn,
					vcn_ofs, is_retry ? " even after "
					"retrying" : "", err);
		}
		/*
		 * Either iblock was outside lblock limits or
		 * ntfs_rl_vcn_to_lcn() returned error.  Just zero that portion
		 * of the page and set the buffer uptodate.
		 */
handle_hole:
		bh->b_blocknr = -1UL;
		clear_buffer_mapped(bh);
handle_zblock:
		zero_user(page, i * blocksize, blocksize);
		if (likely(!err))
			set_buffer_uptodate(bh);
	} while (i++, iblock++, (bh = bh->b_this_page) != head);

	/* Release the lock if we took it. */
	if (rl)
		up_read(&ni->runlist.lock);

	/* Check we have at least one buffer ready for i/o. */
	if (nr) {
		struct buffer_head *tbh;

		/* Lock the buffers. */
		for (i = 0; i < nr; i++) {
			tbh = arr[i];
			lock_buffer(tbh);
			tbh->b_end_io = ntfs_end_buffer_async_read;
			set_buffer_async_read(tbh);
		}
		/* Finally, start i/o on the buffers. */
		for (i = 0; i < nr; i++) {
			tbh = arr[i];
			if (likely(!buffer_uptodate(tbh)))
				submit_bh(READ, tbh);
			else
				ntfs_end_buffer_async_read(tbh, 1);
		}
		return 0;
	}
	/* No i/o was scheduled on any of the buffers. */
	if (likely(!PageError(page)))
		SetPageUptodate(page);
	else /* Signal synchronous i/o error. */
		nr = -EIO;
	unlock_page(page);
	return nr;
}

/**
 * ntfs_readpage - fill a @page of a @file with data from the device
 * @file:	open file to which the page @page belongs or NULL
 * @page:	page cache page to fill with data
 *
 * For non-resident attributes, ntfs_readpage() fills the @page of the open
 * file @file by calling the ntfs version of the generic block_read_full_page()
 * function, ntfs_read_block(), which in turn creates and reads in the buffers
 * associated with the page asynchronously.
 *
 * For resident attributes, OTOH, ntfs_readpage() fills @page by copying the
 * data from the mft record (which at this stage is most likely in memory) and
 * fills the remainder with zeroes. Thus, in this case, I/O is synchronous, as
 * even if the mft record is not cached at this point in time, we need to wait
 * for it to be read in before we can do the copy.
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_readpage(struct file *file, struct page *page)
{
	loff_t i_size;
	struct inode *vi;
	ntfs_inode *ni, *base_ni;
	u8 *addr;
	ntfs_attr_search_ctx *ctx;
	MFT_RECORD *mrec;
	unsigned long flags;
	u32 attr_len;
	int err = 0;

retry_readpage:
	BUG_ON(!PageLocked(page));
	vi = page->mapping->host;
	i_size = i_size_read(vi);
	/* Is the page fully outside i_size? (truncate in progress) */
	if (unlikely(page->index >= (i_size + PAGE_CACHE_SIZE - 1) >>
			PAGE_CACHE_SHIFT)) {
		zero_user(page, 0, PAGE_CACHE_SIZE);
		ntfs_debug("Read outside i_size - truncated?");
		goto done;
	}
	/*
	 * This can potentially happen because we clear PageUptodate() during
	 * ntfs_writepage() of MstProtected() attributes.
	 */
	if (PageUptodate(page)) {
		unlock_page(page);
		return 0;
	}
	ni = NTFS_I(vi);
	/*
	 * Only $DATA attributes can be encrypted and only unnamed $DATA
	 * attributes can be compressed.  Index root can have the flags set but
	 * this means to create compressed/encrypted files, not that the
	 * attribute is compressed/encrypted.  Note we need to check for
	 * AT_INDEX_ALLOCATION since this is the type of both directory and
	 * index inodes.
	 */
	if (ni->type != AT_INDEX_ALLOCATION) {
		/* If attribute is encrypted, deny access, just like NT4. */
		if (NInoEncrypted(ni)) {
			BUG_ON(ni->type != AT_DATA);
			err = -EACCES;
			goto err_out;
		}
		/* Compressed data streams are handled in compress.c. */
		if (NInoNonResident(ni) && NInoCompressed(ni)) {
			BUG_ON(ni->type != AT_DATA);
			BUG_ON(ni->name_len);
			return ntfs_read_compressed_block(page);
		}
	}
	/* NInoNonResident() == NInoIndexAllocPresent() */
	if (NInoNonResident(ni)) {
		/* Normal, non-resident data stream. */
		return ntfs_read_block(page);
	}
	/*
	 * Attribute is resident, implying it is not compressed or encrypted.
	 * This also means the attribute is smaller than an mft record and
	 * hence smaller than a page, so can simply zero out any pages with
	 * index above 0.  Note the attribute can actually be marked compressed
	 * but if it is resident the actual data is not compressed so we are
	 * ok to ignore the compressed flag here.
	 */
	if (unlikely(page->index > 0)) {
		zero_user(page, 0, PAGE_CACHE_SIZE);
		goto done;
	}
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	/* Map, pin, and lock the mft record. */
	mrec = map_mft_record(base_ni);
	if (IS_ERR(mrec)) {
		err = PTR_ERR(mrec);
		goto err_out;
	}
	/*
	 * If a parallel write made the attribute non-resident, drop the mft
	 * record and retry the readpage.
	 */
	if (unlikely(NInoNonResident(ni))) {
		unmap_mft_record(base_ni);
		goto retry_readpage;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, mrec);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto unm_err_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err))
		goto put_unm_err_out;
	attr_len = le32_to_cpu(ctx->attr->data.resident.value_length);
	read_lock_irqsave(&ni->size_lock, flags);
	if (unlikely(attr_len > ni->initialized_size))
		attr_len = ni->initialized_size;
	i_size = i_size_read(vi);
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (unlikely(attr_len > i_size)) {
		/* Race with shrinking truncate. */
		attr_len = i_size;
	}
	addr = kmap_atomic(page);
	/* Copy the data to the page. */
	memcpy(addr, (u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset),
			attr_len);
	/* Zero the remainder of the page. */
	memset(addr + attr_len, 0, PAGE_CACHE_SIZE - attr_len);
	flush_dcache_page(page);
	kunmap_atomic(addr);
put_unm_err_out:
	ntfs_attr_put_search_ctx(ctx);
unm_err_out:
	unmap_mft_record(base_ni);
done:
	SetPageUptodate(page);
err_out:
	unlock_page(page);
	return err;
}

#ifdef NTFS_RW

/**
 * ntfs_write_block - write a @page to the backing store
 * @page:	page cache page to write out
 * @wbc:	writeback control structure
 *
 * This function is for writing pages belonging to non-resident, non-mst
 * protected attributes to their backing store.
 *
 * For a page with buffers, map and write the dirty buffers asynchronously
 * under page writeback. For a page without buffers, create buffers for the
 * page, then proceed as above.
 *
 * If a page doesn't have buffers the page dirty state is definitive. If a page
 * does have buffers, the page dirty state is just a hint, and the buffer dirty
 * state is definitive. (A hint which has rules: dirty buffers against a clean
 * page is illegal. Other combinations are legal and need to be handled. In
 * particular a dirty page containing clean buffers for example.)
 *
 * Return 0 on success and -errno on error.
 *
 * Based on ntfs_read_block() and __block_write_full_page().
 */
static int ntfs_write_block(struct page *page, struct writeback_control *wbc)
{
	VCN vcn;
	LCN lcn;
	s64 initialized_size;
	loff_t i_size;
	sector_t block, dblock, iblock;
	struct inode *vi;
	ntfs_inode *ni;
	ntfs_volume *vol;
	runlist_element *rl;
	struct buffer_head *bh, *head;
	unsigned long flags;
	unsigned int blocksize, vcn_ofs;
	int err;
	bool need_end_writeback;
	unsigned char blocksize_bits;

	vi = page->mapping->host;
	ni = NTFS_I(vi);
	vol = ni->vol;

	ntfs_debug("Entering for inode 0x%lx, attribute type 0x%x, page index "
			"0x%lx.", ni->mft_no, ni->type, page->index);

	BUG_ON(!NInoNonResident(ni));
	BUG_ON(NInoMstProtected(ni));
	blocksize = vol->sb->s_blocksize;
	blocksize_bits = vol->sb->s_blocksize_bits;
	if (!page_has_buffers(page)) {
		BUG_ON(!PageUptodate(page));
		create_empty_buffers(page, blocksize,
				(1 << BH_Uptodate) | (1 << BH_Dirty));
		if (unlikely(!page_has_buffers(page))) {
			ntfs_warning(vol->sb, "Error allocating page "
					"buffers.  Redirtying page so we try "
					"again later.");
			/*
			 * Put the page back on mapping->dirty_pages, but leave
			 * its buffers' dirty state as-is.
			 */
			redirty_page_for_writepage(wbc, page);
			unlock_page(page);
			return 0;
		}
	}
	bh = head = page_buffers(page);
	BUG_ON(!bh);

	/* NOTE: Different naming scheme to ntfs_read_block()! */

	/* The first block in the page. */
	block = (s64)page->index << (PAGE_CACHE_SHIFT - blocksize_bits);

	read_lock_irqsave(&ni->size_lock, flags);
	i_size = i_size_read(vi);
	initialized_size = ni->initialized_size;
	read_unlock_irqrestore(&ni->size_lock, flags);

	/* The first out of bounds block for the data size. */
	dblock = (i_size + blocksize - 1) >> blocksize_bits;

	/* The last (fully or partially) initialized block. */
	iblock = initialized_size >> blocksize_bits;

	/*
	 * Be very careful.  We have no exclusion from __set_page_dirty_buffers
	 * here, and the (potentially unmapped) buffers may become dirty at
	 * any time.  If a buffer becomes dirty here after we've inspected it
	 * then we just miss that fact, and the page stays dirty.
	 *
	 * Buffers outside i_size may be dirtied by __set_page_dirty_buffers;
	 * handle that here by just cleaning them.
	 */

	/*
	 * Loop through all the buffers in the page, mapping all the dirty
	 * buffers to disk addresses and handling any aliases from the
	 * underlying block device's mapping.
	 */
	rl = NULL;
	err = 0;
	do {
		bool is_retry = false;

		if (unlikely(block >= dblock)) {
			/*
			 * Mapped buffers outside i_size will occur, because
			 * this page can be outside i_size when there is a
			 * truncate in progress. The contents of such buffers
			 * were zeroed by ntfs_writepage().
			 *
			 * FIXME: What about the small race window where
			 * ntfs_writepage() has not done any clearing because
			 * the page was within i_size but before we get here,
			 * vmtruncate() modifies i_size?
			 */
			clear_buffer_dirty(bh);
			set_buffer_uptodate(bh);
			continue;
		}

		/* Clean buffers are not written out, so no need to map them. */
		if (!buffer_dirty(bh))
			continue;

		/* Make sure we have enough initialized size. */
		if (unlikely((block >= iblock) &&
				(initialized_size < i_size))) {
			/*
			 * If this page is fully outside initialized size, zero
			 * out all pages between the current initialized size
			 * and the current page. Just use ntfs_readpage() to do
			 * the zeroing transparently.
			 */
			if (block > iblock) {
				// TODO:
				// For each page do:
				// - read_cache_page()
				// Again for each page do:
				// - wait_on_page_locked()
				// - Check (PageUptodate(page) &&
				//			!PageError(page))
				// Update initialized size in the attribute and
				// in the inode.
				// Again, for each page do:
				//	__set_page_dirty_buffers();
				// page_cache_release()
				// We don't need to wait on the writes.
				// Update iblock.
			}
			/*
			 * The current page straddles initialized size. Zero
			 * all non-uptodate buffers and set them uptodate (and
			 * dirty?). Note, there aren't any non-uptodate buffers
			 * if the page is uptodate.
			 * FIXME: For an uptodate page, the buffers may need to
			 * be written out because they were not initialized on
			 * disk before.
			 */
			if (!PageUptodate(page)) {
				// TODO:
				// Zero any non-uptodate buffers up to i_size.
				// Set them uptodate and dirty.
			}
			// TODO:
			// Update initialized size in the attribute and in the
			// inode (up to i_size).
			// Update iblock.
			// FIXME: This is inefficient. Try to batch the two
			// size changes to happen in one go.
			ntfs_error(vol->sb, "Writing beyond initialized size "
					"is not supported yet. Sorry.");
			err = -EOPNOTSUPP;
			break;
			// Do NOT set_buffer_new() BUT DO clear buffer range
			// outside write request range.
			// set_buffer_uptodate() on complete buffers as well as
			// set_buffer_dirty().
		}

		/* No need to map buffers that are already mapped. */
		if (buffer_mapped(bh))
			continue;

		/* Unmapped, dirty buffer. Need to map it. */
		bh->b_bdev = vol->sb->s_bdev;

		/* Convert block into corresponding vcn and offset. */
		vcn = (VCN)block << blocksize_bits;
		vcn_ofs = vcn & vol->cluster_size_mask;
		vcn >>= vol->cluster_size_bits;
		if (!rl) {
lock_retry_remap:
			down_read(&ni->runlist.lock);
			rl = ni->runlist.rl;
		}
		if (likely(rl != NULL)) {
			/* Seek to element containing target vcn. */
			while (rl->length && rl[1].vcn <= vcn)
				rl++;
			lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
		} else
			lcn = LCN_RL_NOT_MAPPED;
		/* Successful remap. */
		if (lcn >= 0) {
			/* Setup buffer head to point to correct block. */
			bh->b_blocknr = ((lcn << vol->cluster_size_bits) +
					vcn_ofs) >> blocksize_bits;
			set_buffer_mapped(bh);
			continue;
		}
		/* It is a hole, need to instantiate it. */
		if (lcn == LCN_HOLE) {
			u8 *kaddr;
			unsigned long *bpos, *bend;

			/* Check if the buffer is zero. */
			kaddr = kmap_atomic(page);
			bpos = (unsigned long *)(kaddr + bh_offset(bh));
			bend = (unsigned long *)((u8*)bpos + blocksize);
			do {
				if (unlikely(*bpos))
					break;
			} while (likely(++bpos < bend));
			kunmap_atomic(kaddr);
			if (bpos == bend) {
				/*
				 * Buffer is zero and sparse, no need to write
				 * it.
				 */
				bh->b_blocknr = -1;
				clear_buffer_dirty(bh);
				continue;
			}
			// TODO: Instantiate the hole.
			// clear_buffer_new(bh);
			// unmap_underlying_metadata(bh->b_bdev, bh->b_blocknr);
			ntfs_error(vol->sb, "Writing into sparse regions is "
					"not supported yet. Sorry.");
			err = -EOPNOTSUPP;
			break;
		}
		/* If first try and runlist unmapped, map and retry. */
		if (!is_retry && lcn == LCN_RL_NOT_MAPPED) {
			is_retry = true;
			/*
			 * Attempt to map runlist, dropping lock for
			 * the duration.
			 */
			up_read(&ni->runlist.lock);
			err = ntfs_map_runlist(ni, vcn);
			if (likely(!err))
				goto lock_retry_remap;
			rl = NULL;
		} else if (!rl)
			up_read(&ni->runlist.lock);
		/*
		 * If buffer is outside the runlist, truncate has cut it out
		 * of the runlist.  Just clean and clear the buffer and set it
		 * uptodate so it can get discarded by the VM.
		 */
		if (err == -ENOENT || lcn == LCN_ENOENT) {
			bh->b_blocknr = -1;
			clear_buffer_dirty(bh);
			zero_user(page, bh_offset(bh), blocksize);
			set_buffer_uptodate(bh);
			err = 0;
			continue;
		}
		/* Failed to map the buffer, even after retrying. */
		if (!err)
			err = -EIO;
		bh->b_blocknr = -1;
		ntfs_error(vol->sb, "Failed to write to inode 0x%lx, "
				"attribute type 0x%x, vcn 0x%llx, offset 0x%x "
				"because its location on disk could not be "
				"determined%s (error code %i).", ni->mft_no,
				ni->type, (unsigned long long)vcn,
				vcn_ofs, is_retry ? " even after "
				"retrying" : "", err);
		break;
	} while (block++, (bh = bh->b_this_page) != head);

	/* Release the lock if we took it. */
	if (rl)
		up_read(&ni->runlist.lock);

	/* For the error case, need to reset bh to the beginning. */
	bh = head;

	/* Just an optimization, so ->readpage() is not called later. */
	if (unlikely(!PageUptodate(page))) {
		int uptodate = 1;
		do {
			if (!buffer_uptodate(bh)) {
				uptodate = 0;
				bh = head;
				break;
			}
		} while ((bh = bh->b_this_page) != head);
		if (uptodate)
			SetPageUptodate(page);
	}

	/* Setup all mapped, dirty buffers for async write i/o. */
	do {
		if (buffer_mapped(bh) && buffer_dirty(bh)) {
			lock_buffer(bh);
			if (test_clear_buffer_dirty(bh)) {
				BUG_ON(!buffer_uptodate(bh));
				mark_buffer_async_write(bh);
			} else
				unlock_buffer(bh);
		} else if (unlikely(err)) {
			/*
			 * For the error case. The buffer may have been set
			 * dirty during attachment to a dirty page.
			 */
			if (err != -ENOMEM)
				clear_buffer_dirty(bh);
		}
	} while ((bh = bh->b_this_page) != head);

	if (unlikely(err)) {
		// TODO: Remove the -EOPNOTSUPP check later on...
		if (unlikely(err == -EOPNOTSUPP))
			err = 0;
		else if (err == -ENOMEM) {
			ntfs_warning(vol->sb, "Error allocating memory. "
					"Redirtying page so we try again "
					"later.");
			/*
			 * Put the page back on mapping->dirty_pages, but
			 * leave its buffer's dirty state as-is.
			 */
			redirty_page_for_writepage(wbc, page);
			err = 0;
		} else
			SetPageError(page);
	}

	BUG_ON(PageWriteback(page));
	set_page_writeback(page);	/* Keeps try_to_free_buffers() away. */

	/* Submit the prepared buffers for i/o. */
	need_end_writeback = true;
	do {
		struct buffer_head *next = bh->b_this_page;
		if (buffer_async_write(bh)) {
			submit_bh(WRITE, bh);
			need_end_writeback = false;
		}
		bh = next;
	} while (bh != head);
	unlock_page(page);

	/* If no i/o was started, need to end_page_writeback(). */
	if (unlikely(need_end_writeback))
		end_page_writeback(page);

	ntfs_debug("Done.");
	return err;
}

/**
 * ntfs_write_mst_block - write a @page to the backing store
 * @page:	page cache page to write out
 * @wbc:	writeback control structure
 *
 * This function is for writing pages belonging to non-resident, mst protected
 * attributes to their backing store.  The only supported attributes are index
 * allocation and $MFT/$DATA.  Both directory inodes and index inodes are
 * supported for the index allocation case.
 *
 * The page must remain locked for the duration of the write because we apply
 * the mst fixups, write, and then undo the fixups, so if we were to unlock the
 * page before undoing the fixups, any other user of the page will see the
 * page contents as corrupt.
 *
 * We clear the page uptodate flag for the duration of the function to ensure
 * exclusion for the $MFT/$DATA case against someone mapping an mft record we
 * are about to apply the mst fixups to.
 *
 * Return 0 on success and -errno on error.
 *
 * Based on ntfs_write_block(), ntfs_mft_writepage(), and
 * write_mft_record_nolock().
 */
static int ntfs_write_mst_block(struct page *page,
		struct writeback_control *wbc)
{
	sector_t block, dblock, rec_block;
	struct inode *vi = page->mapping->host;
	ntfs_inode *ni = NTFS_I(vi);
	ntfs_volume *vol = ni->vol;
	u8 *kaddr;
	unsigned int rec_size = ni->itype.index.block_size;
	ntfs_inode *locked_nis[PAGE_CACHE_SIZE / rec_size];
	struct buffer_head *bh, *head, *tbh, *rec_start_bh;
	struct buffer_head *bhs[MAX_BUF_PER_PAGE];
	runlist_element *rl;
	int i, nr_locked_nis, nr_recs, nr_bhs, max_bhs, bhs_per_rec, err, err2;
	unsigned bh_size, rec_size_bits;
	bool sync, is_mft, page_is_dirty, rec_is_dirty;
	unsigned char bh_size_bits;

	ntfs_debug("Entering for inode 0x%lx, attribute type 0x%x, page index "
			"0x%lx.", vi->i_ino, ni->type, page->index);
	BUG_ON(!NInoNonResident(ni));
	BUG_ON(!NInoMstProtected(ni));
	is_mft = (S_ISREG(vi->i_mode) && !vi->i_ino);
	/*
	 * NOTE: ntfs_write_mst_block() would be called for $MFTMirr if a page
	 * in its page cache were to be marked dirty.  However this should
	 * never happen with the current driver and considering we do not
	 * handle this case here we do want to BUG(), at least for now.
	 */
	BUG_ON(!(is_mft || S_ISDIR(vi->i_mode) ||
			(NInoAttr(ni) && ni->type == AT_INDEX_ALLOCATION)));
	bh_size = vol->sb->s_blocksize;
	bh_size_bits = vol->sb->s_blocksize_bits;
	max_bhs = PAGE_CACHE_SIZE / bh_size;
	BUG_ON(!max_bhs);
	BUG_ON(max_bhs > MAX_BUF_PER_PAGE);

	/* Were we called for sync purposes? */
	sync = (wbc->sync_mode == WB_SYNC_ALL);

	/* Make sure we have mapped buffers. */
	bh = head = page_buffers(page);
	BUG_ON(!bh);

	rec_size_bits = ni->itype.index.block_size_bits;
	BUG_ON(!(PAGE_CACHE_SIZE >> rec_size_bits));
	bhs_per_rec = rec_size >> bh_size_bits;
	BUG_ON(!bhs_per_rec);

	/* The first block in the page. */
	rec_block = block = (sector_t)page->index <<
			(PAGE_CACHE_SHIFT - bh_size_bits);

	/* The first out of bounds block for the data size. */
	dblock = (i_size_read(vi) + bh_size - 1) >> bh_size_bits;

	rl = NULL;
	err = err2 = nr_bhs = nr_recs = nr_locked_nis = 0;
	page_is_dirty = rec_is_dirty = false;
	rec_start_bh = NULL;
	do {
		bool is_retry = false;

		if (likely(block < rec_block)) {
			if (unlikely(block >= dblock)) {
				clear_buffer_dirty(bh);
				set_buffer_uptodate(bh);
				continue;
			}
			/*
			 * This block is not the first one in the record.  We
			 * ignore the buffer's dirty state because we could
			 * have raced with a parallel mark_ntfs_record_dirty().
			 */
			if (!rec_is_dirty)
				continue;
			if (unlikely(err2)) {
				if (err2 != -ENOMEM)
					clear_buffer_dirty(bh);
				continue;
			}
		} else /* if (block == rec_block) */ {
			BUG_ON(block > rec_block);
			/* This block is the first one in the record. */
			rec_block += bhs_per_rec;
			err2 = 0;
			if (unlikely(block >= dblock)) {
				clear_buffer_dirty(bh);
				continue;
			}
			if (!buffer_dirty(bh)) {
				/* Clean records are not written out. */
				rec_is_dirty = false;
				continue;
			}
			rec_is_dirty = true;
			rec_start_bh = bh;
		}
		/* Need to map the buffer if it is not mapped already. */
		if (unlikely(!buffer_mapped(bh))) {
			VCN vcn;
			LCN lcn;
			unsigned int vcn_ofs;

			bh->b_bdev = vol->sb->s_bdev;
			/* Obtain the vcn and offset of the current block. */
			vcn = (VCN)block << bh_size_bits;
			vcn_ofs = vcn & vol->cluster_size_mask;
			vcn >>= vol->cluster_size_bits;
			if (!rl) {
lock_retry_remap:
				down_read(&ni->runlist.lock);
				rl = ni->runlist.rl;
			}
			if (likely(rl != NULL)) {
				/* Seek to element containing target vcn. */
				while (rl->length && rl[1].vcn <= vcn)
					rl++;
				lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
			} else
				lcn = LCN_RL_NOT_MAPPED;
			/* Successful remap. */
			if (likely(lcn >= 0)) {
				/* Setup buffer head to correct block. */
				bh->b_blocknr = ((lcn <<
						vol->cluster_size_bits) +
						vcn_ofs) >> bh_size_bits;
				set_buffer_mapped(bh);
			} else {
				/*
				 * Remap failed.  Retry to map the runlist once
				 * unless we are working on $MFT which always
				 * has the whole of its runlist in memory.
				 */
				if (!is_mft && !is_retry &&
						lcn == LCN_RL_NOT_MAPPED) {
					is_retry = true;
					/*
					 * Attempt to map runlist, dropping
					 * lock for the duration.
					 */
					up_read(&ni->runlist.lock);
					err2 = ntfs_map_runlist(ni, vcn);
					if (likely(!err2))
						goto lock_retry_remap;
					if (err2 == -ENOMEM)
						page_is_dirty = true;
					lcn = err2;
				} else {
					err2 = -EIO;
					if (!rl)
						up_read(&ni->runlist.lock);
				}
				/* Hard error.  Abort writing this record. */
				if (!err || err == -ENOMEM)
					err = err2;
				bh->b_blocknr = -1;
				ntfs_error(vol->sb, "Cannot write ntfs record "
						"0x%llx (inode 0x%lx, "
						"attribute type 0x%x) because "
						"its location on disk could "
						"not be determined (error "
						"code %lli).",
						(long long)block <<
						bh_size_bits >>
						vol->mft_record_size_bits,
						ni->mft_no, ni->type,
						(long long)lcn);
				/*
				 * If this is not the first buffer, remove the
				 * buffers in this record from the list of
				 * buffers to write and clear their dirty bit
				 * if not error -ENOMEM.
				 */
				if (rec_start_bh != bh) {
					while (bhs[--nr_bhs] != rec_start_bh)
						;
					if (err2 != -ENOMEM) {
						do {
							clear_buffer_dirty(
								rec_start_bh);
						} while ((rec_start_bh =
								rec_start_bh->
								b_this_page) !=
								bh);
					}
				}
				continue;
			}
		}
		BUG_ON(!buffer_uptodate(bh));
		BUG_ON(nr_bhs >= max_bhs);
		bhs[nr_bhs++] = bh;
	} while (block++, (bh = bh->b_this_page) != head);
	if (unlikely(rl))
		up_read(&ni->runlist.lock);
	/* If there were no dirty buffers, we are done. */
	if (!nr_bhs)
		goto done;
	/* Map the page so we can access its contents. */
	kaddr = kmap(page);
	/* Clear the page uptodate flag whilst the mst fixups are applied. */
	BUG_ON(!PageUptodate(page));
	ClearPageUptodate(page);
	for (i = 0; i < nr_bhs; i++) {
		unsigned int ofs;

		/* Skip buffers which are not at the beginning of records. */
		if (i % bhs_per_rec)
			continue;
		tbh = bhs[i];
		ofs = bh_offset(tbh);
		if (is_mft) {
			ntfs_inode *tni;
			unsigned long mft_no;

			/* Get the mft record number. */
			mft_no = (((s64)page->index << PAGE_CACHE_SHIFT) + ofs)
					>> rec_size_bits;
			/* Check whether to write this mft record. */
			tni = NULL;
			if (!ntfs_may_write_mft_record(vol, mft_no,
					(MFT_RECORD*)(kaddr + ofs), &tni)) {
				/*
				 * The record should not be written.  This
				 * means we need to redirty the page before
				 * returning.
				 */
				page_is_dirty = true;
				/*
				 * Remove the buffers in this mft record from
				 * the list of buffers to write.
				 */
				do {
					bhs[i] = NULL;
				} while (++i % bhs_per_rec);
				continue;
			}
			/*
			 * The record should be written.  If a locked ntfs
			 * inode was returned, add it to the array of locked
			 * ntfs inodes.
			 */
			if (tni)
				locked_nis[nr_locked_nis++] = tni;
		}
		/* Apply the mst protection fixups. */
		err2 = pre_write_mst_fixup((NTFS_RECORD*)(kaddr + ofs),
				rec_size);
		if (unlikely(err2)) {
			if (!err || err == -ENOMEM)
				err = -EIO;
			ntfs_error(vol->sb, "Failed to apply mst fixups "
					"(inode 0x%lx, attribute type 0x%x, "
					"page index 0x%lx, page offset 0x%x)!"
					"  Unmount and run chkdsk.", vi->i_ino,
					ni->type, page->index, ofs);
			/*
			 * Mark all the buffers in this record clean as we do
			 * not want to write corrupt data to disk.
			 */
			do {
				clear_buffer_dirty(bhs[i]);
				bhs[i] = NULL;
			} while (++i % bhs_per_rec);
			continue;
		}
		nr_recs++;
	}
	/* If no records are to be written out, we are done. */
	if (!nr_recs)
		goto unm_done;
	flush_dcache_page(page);
	/* Lock buffers and start synchronous write i/o on them. */
	for (i = 0; i < nr_bhs; i++) {
		tbh = bhs[i];
		if (!tbh)
			continue;
		if (!trylock_buffer(tbh))
			BUG();
		/* The buffer dirty state is now irrelevant, just clean it. */
		clear_buffer_dirty(tbh);
		BUG_ON(!buffer_uptodate(tbh));
		BUG_ON(!buffer_mapped(tbh));
		get_bh(tbh);
		tbh->b_end_io = end_buffer_write_sync;
		submit_bh(WRITE, tbh);
	}
	/* Synchronize the mft mirror now if not @sync. */
	if (is_mft && !sync)
		goto do_mirror;
do_wait:
	/* Wait on i/o completion of buffers. */
	for (i = 0; i < nr_bhs; i++) {
		tbh = bhs[i];
		if (!tbh)
			continue;
		wait_on_buffer(tbh);
		if (unlikely(!buffer_uptodate(tbh))) {
			ntfs_error(vol->sb, "I/O error while writing ntfs "
					"record buffer (inode 0x%lx, "
					"attribute type 0x%x, page index "
					"0x%lx, page offset 0x%lx)!  Unmount "
					"and run chkdsk.", vi->i_ino, ni->type,
					page->index, bh_offset(tbh));
			if (!err || err == -ENOMEM)
				err = -EIO;
			/*
			 * Set the buffer uptodate so the page and buffer
			 * states do not become out of sync.
			 */
			set_buffer_uptodate(tbh);
		}
	}
	/* If @sync, now synchronize the mft mirror. */
	if (is_mft && sync) {
do_mirror:
		for (i = 0; i < nr_bhs; i++) {
			unsigned long mft_no;
			unsigned int ofs;

			/*
			 * Skip buffers which are not at the beginning of
			 * records.
			 */
			if (i % bhs_per_rec)
				continue;
			tbh = bhs[i];
			/* Skip removed buffers (and hence records). */
			if (!tbh)
				continue;
			ofs = bh_offset(tbh);
			/* Get the mft record number. */
			mft_no = (((s64)page->index << PAGE_CACHE_SHIFT) + ofs)
					>> rec_size_bits;
			if (mft_no < vol->mftmirr_size)
				ntfs_sync_mft_mirror(vol, mft_no,
						(MFT_RECORD*)(kaddr + ofs),
						sync);
		}
		if (!sync)
			goto do_wait;
	}
	/* Remove the mst protection fixups again. */
	for (i = 0; i < nr_bhs; i++) {
		if (!(i % bhs_per_rec)) {
			tbh = bhs[i];
			if (!tbh)
				continue;
			post_write_mst_fixup((NTFS_RECORD*)(kaddr +
					bh_offset(tbh)));
		}
	}
	flush_dcache_page(page);
unm_done:
	/* Unlock any locked inodes. */
	while (nr_locked_nis-- > 0) {
		ntfs_inode *tni, *base_tni;
		
		tni = locked_nis[nr_locked_nis];
		/* Get the base inode. */
		mutex_lock(&tni->extent_lock);
		if (tni->nr_extents >= 0)
			base_tni = tni;
		else {
			base_tni = tni->ext.base_ntfs_ino;
			BUG_ON(!base_tni);
		}
		mutex_unlock(&tni->extent_lock);
		ntfs_debug("Unlocking %s inode 0x%lx.",
				tni == base_tni ? "base" : "extent",
				tni->mft_no);
		mutex_unlock(&tni->mrec_lock);
		atomic_dec(&tni->count);
		iput(VFS_I(base_tni));
	}
	SetPageUptodate(page);
	kunmap(page);
done:
	if (unlikely(err && err != -ENOMEM)) {
		/*
		 * Set page error if there is only one ntfs record in the page.
		 * Otherwise we would loose per-record granularity.
		 */
		if (ni->itype.index.block_size == PAGE_CACHE_SIZE)
			SetPageError(page);
		NVolSetErrors(vol);
	}
	if (page_is_dirty) {
		ntfs_debug("Page still contains one or more dirty ntfs "
				"records.  Redirtying the page starting at "
				"record 0x%lx.", page->index <<
				(PAGE_CACHE_SHIFT - rec_size_bits));
		redirty_page_for_writepage(wbc, page);
		unlock_page(page);
	} else {
		/*
		 * Keep the VM happy.  This must be done otherwise the
		 * radix-tree tag PAGECACHE_TAG_DIRTY remains set even though
		 * the page is clean.
		 */
		BUG_ON(PageWriteback(page));
		set_page_writeback(page);
		unlock_page(page);
		end_page_writeback(page);
	}
	if (likely(!err))
		ntfs_debug("Done.");
	return err;
}

/**
 * ntfs_writepage - write a @page to the backing store
 * @page:	page cache page to write out
 * @wbc:	writeback control structure
 *
 * This is called from the VM when it wants to have a dirty ntfs page cache
 * page cleaned.  The VM has already locked the page and marked it clean.
 *
 * For non-resident attributes, ntfs_writepage() writes the @page by calling
 * the ntfs version of the generic block_write_full_page() function,
 * ntfs_write_block(), which in turn if necessary creates and writes the
 * buffers associated with the page asynchronously.
 *
 * For resident attributes, OTOH, ntfs_writepage() writes the @page by copying
 * the data to the mft record (which at this stage is most likely in memory).
 * The mft record is then marked dirty and written out asynchronously via the
 * vfs inode dirty code path for the inode the mft record belongs to or via the
 * vm page dirty code path for the page the mft record is in.
 *
 * Based on ntfs_readpage() and fs/buffer.c::block_write_full_page().
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_writepage(struct page *page, struct writeback_control *wbc)
{
	loff_t i_size;
	struct inode *vi = page->mapping->host;
	ntfs_inode *base_ni = NULL, *ni = NTFS_I(vi);
	char *addr;
	ntfs_attr_search_ctx *ctx = NULL;
	MFT_RECORD *m = NULL;
	u32 attr_len;
	int err;

retry_writepage:
	BUG_ON(!PageLocked(page));
	i_size = i_size_read(vi);
	/* Is the page fully outside i_size? (truncate in progress) */
	if (unlikely(page->index >= (i_size + PAGE_CACHE_SIZE - 1) >>
			PAGE_CACHE_SHIFT)) {
		/*
		 * The page may have dirty, unmapped buffers.  Make them
		 * freeable here, so the page does not leak.
		 */
		block_invalidatepage(page, 0, PAGE_CACHE_SIZE);
		unlock_page(page);
		ntfs_debug("Write outside i_size - truncated?");
		return 0;
	}
	/*
	 * Only $DATA attributes can be encrypted and only unnamed $DATA
	 * attributes can be compressed.  Index root can have the flags set but
	 * this means to create compressed/encrypted files, not that the
	 * attribute is compressed/encrypted.  Note we need to check for
	 * AT_INDEX_ALLOCATION since this is the type of both directory and
	 * index inodes.
	 */
	if (ni->type != AT_INDEX_ALLOCATION) {
		/* If file is encrypted, deny access, just like NT4. */
		if (NInoEncrypted(ni)) {
			unlock_page(page);
			BUG_ON(ni->type != AT_DATA);
			ntfs_debug("Denying write access to encrypted file.");
			return -EACCES;
		}
		/* Compressed data streams are handled in compress.c. */
		if (NInoNonResident(ni) && NInoCompressed(ni)) {
			BUG_ON(ni->type != AT_DATA);
			BUG_ON(ni->name_len);
			// TODO: Implement and replace this with
			// return ntfs_write_compressed_block(page);
			unlock_page(page);
			ntfs_error(vi->i_sb, "Writing to compressed files is "
					"not supported yet.  Sorry.");
			return -EOPNOTSUPP;
		}
		// TODO: Implement and remove this check.
		if (NInoNonResident(ni) && NInoSparse(ni)) {
			unlock_page(page);
			ntfs_error(vi->i_sb, "Writing to sparse files is not "
					"supported yet.  Sorry.");
			return -EOPNOTSUPP;
		}
	}
	/* NInoNonResident() == NInoIndexAllocPresent() */
	if (NInoNonResident(ni)) {
		/* We have to zero every time due to mmap-at-end-of-file. */
		if (page->index >= (i_size >> PAGE_CACHE_SHIFT)) {
			/* The page straddles i_size. */
			unsigned int ofs = i_size & ~PAGE_CACHE_MASK;
			zero_user_segment(page, ofs, PAGE_CACHE_SIZE);
		}
		/* Handle mst protected attributes. */
		if (NInoMstProtected(ni))
			return ntfs_write_mst_block(page, wbc);
		/* Normal, non-resident data stream. */
		return ntfs_write_block(page, wbc);
	}
	/*
	 * Attribute is resident, implying it is not compressed, encrypted, or
	 * mst protected.  This also means the attribute is smaller than an mft
	 * record and hence smaller than a page, so can simply return error on
	 * any pages with index above 0.  Note the attribute can actually be
	 * marked compressed but if it is resident the actual data is not
	 * compressed so we are ok to ignore the compressed flag here.
	 */
	BUG_ON(page_has_buffers(page));
	BUG_ON(!PageUptodate(page));
	if (unlikely(page->index > 0)) {
		ntfs_error(vi->i_sb, "BUG()! page->index (0x%lx) > 0.  "
				"Aborting write.", page->index);
		BUG_ON(PageWriteback(page));
		set_page_writeback(page);
		unlock_page(page);
		end_page_writeback(page);
		return -EIO;
	}
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	/* Map, pin, and lock the mft record. */
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		ctx = NULL;
		goto err_out;
	}
	/*
	 * If a parallel write made the attribute non-resident, drop the mft
	 * record and retry the writepage.
	 */
	if (unlikely(NInoNonResident(ni))) {
		unmap_mft_record(base_ni);
		goto retry_writepage;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err))
		goto err_out;
	/*
	 * Keep the VM happy.  This must be done otherwise the radix-tree tag
	 * PAGECACHE_TAG_DIRTY remains set even though the page is clean.
	 */
	BUG_ON(PageWriteback(page));
	set_page_writeback(page);
	unlock_page(page);
	attr_len = le32_to_cpu(ctx->attr->data.resident.value_length);
	i_size = i_size_read(vi);
	if (unlikely(attr_len > i_size)) {
		/* Race with shrinking truncate or a failed truncate. */
		attr_len = i_size;
		/*
		 * If the truncate failed, fix it up now.  If a concurrent
		 * truncate, we do its job, so it does not have to do anything.
		 */
		err = ntfs_resident_attr_value_resize(ctx->mrec, ctx->attr,
				attr_len);
		/* Shrinking cannot fail. */
		BUG_ON(err);
	}
	addr = kmap_atomic(page);
	/* Copy the data from the page to the mft record. */
	memcpy((u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset),
			addr, attr_len);
	/* Zero out of bounds area in the page cache page. */
	memset(addr + attr_len, 0, PAGE_CACHE_SIZE - attr_len);
	kunmap_atomic(addr);
	flush_dcache_page(page);
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	/* We are done with the page. */
	end_page_writeback(page);
	/* Finally, mark the mft record dirty, so it gets written back. */
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	return 0;
err_out:
	if (err == -ENOMEM) {
		ntfs_warning(vi->i_sb, "Error allocating memory. Redirtying "
				"page so we try again later.");
		/*
		 * Put the page back on mapping->dirty_pages, but leave its
		 * buffers' dirty state as-is.
		 */
		redirty_page_for_writepage(wbc, page);
		err = 0;
	} else {
		ntfs_error(vi->i_sb, "Resident attribute write failed with "
				"error %i.", err);
		SetPageError(page);
		NVolSetErrors(ni->vol);
	}
	unlock_page(page);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	return err;
}

#endif	/* NTFS_RW */

/**
 * ntfs_bmap - map logical file block to physical device block
 * @mapping:	address space mapping to which the block to be mapped belongs
 * @block:	logical block to map to its physical device block
 *
 * For regular, non-resident files (i.e. not compressed and not encrypted), map
 * the logical @block belonging to the file described by the address space
 * mapping @mapping to its physical device block.
 *
 * The size of the block is equal to the @s_blocksize field of the super block
 * of the mounted file system which is guaranteed to be smaller than or equal
 * to the cluster size thus the block is guaranteed to fit entirely inside the
 * cluster which means we do not need to care how many contiguous bytes are
 * available after the beginning of the block.
 *
 * Return the physical device block if the mapping succeeded or 0 if the block
 * is sparse or there was an error.
 *
 * Note: This is a problem if someone tries to run bmap() on $Boot system file
 * as that really is in block zero but there is nothing we can do.  bmap() is
 * just broken in that respect (just like it cannot distinguish sparse from
 * not available or error).
 */
static sector_t ntfs_bmap(struct address_space *mapping, sector_t block)
{
	s64 ofs, size;
	loff_t i_size;
	LCN lcn;
	unsigned long blocksize, flags;
	ntfs_inode *ni = NTFS_I(mapping->host);
	ntfs_volume *vol = ni->vol;
	unsigned delta;
	unsigned char blocksize_bits, cluster_size_shift;

	ntfs_debug("Entering for mft_no 0x%lx, logical block 0x%llx.",
			ni->mft_no, (unsigned long long)block);
	if (ni->type != AT_DATA || !NInoNonResident(ni) || NInoEncrypted(ni)) {
		ntfs_error(vol->sb, "BMAP does not make sense for %s "
				"attributes, returning 0.",
				(ni->type != AT_DATA) ? "non-data" :
				(!NInoNonResident(ni) ? "resident" :
				"encrypted"));
		return 0;
	}
	/* None of these can happen. */
	BUG_ON(NInoCompressed(ni));
	BUG_ON(NInoMstProtected(ni));
	blocksize = vol->sb->s_blocksize;
	blocksize_bits = vol->sb->s_blocksize_bits;
	ofs = (s64)block << blocksize_bits;
	read_lock_irqsave(&ni->size_lock, flags);
	size = ni->initialized_size;
	i_size = i_size_read(VFS_I(ni));
	read_unlock_irqrestore(&ni->size_lock, flags);
	/*
	 * If the offset is outside the initialized size or the block straddles
	 * the initialized size then pretend it is a hole unless the
	 * initialized size equals the file size.
	 */
	if (unlikely(ofs >= size || (ofs + blocksize > size && size < i_size)))
		goto hole;
	cluster_size_shift = vol->cluster_size_bits;
	down_read(&ni->runlist.lock);
	lcn = ntfs_attr_vcn_to_lcn_nolock(ni, ofs >> cluster_size_shift, false);
	up_read(&ni->runlist.lock);
	if (unlikely(lcn < LCN_HOLE)) {
		/*
		 * Step down to an integer to avoid gcc doing a long long
		 * comparision in the switch when we know @lcn is between
		 * LCN_HOLE and LCN_EIO (i.e. -1 to -5).
		 *
		 * Otherwise older gcc (at least on some architectures) will
		 * try to use __cmpdi2() which is of course not available in
		 * the kernel.
		 */
		switch ((int)lcn) {
		case LCN_ENOENT:
			/*
			 * If the offset is out of bounds then pretend it is a
			 * hole.
			 */
			goto hole;
		case LCN_ENOMEM:
			ntfs_error(vol->sb, "Not enough memory to complete "
					"mapping for inode 0x%lx.  "
					"Returning 0.", ni->mft_no);
			break;
		default:
			ntfs_error(vol->sb, "Failed to complete mapping for "
					"inode 0x%lx.  Run chkdsk.  "
					"Returning 0.", ni->mft_no);
			break;
		}
		return 0;
	}
	if (lcn < 0) {
		/* It is a hole. */
hole:
		ntfs_debug("Done (returning hole).");
		return 0;
	}
	/*
	 * The block is really allocated and fullfils all our criteria.
	 * Convert the cluster to units of block size and return the result.
	 */
	delta = ofs & vol->cluster_size_mask;
	if (unlikely(sizeof(block) < sizeof(lcn))) {
		block = lcn = ((lcn << cluster_size_shift) + delta) >>
				blocksize_bits;
		/* If the block number was truncated return 0. */
		if (unlikely(block != lcn)) {
			ntfs_error(vol->sb, "Physical block 0x%llx is too "
					"large to be returned, returning 0.",
					(long long)lcn);
			return 0;
		}
	} else
		block = ((lcn << cluster_size_shift) + delta) >>
				blocksize_bits;
	ntfs_debug("Done (returning block 0x%llx).", (unsigned long long)lcn);
	return block;
}

/**
 * ntfs_normal_aops - address space operations for normal inodes and attributes
 *
 * Note these are not used for compressed or mst protected inodes and
 * attributes.
 */
const struct address_space_operations ntfs_normal_aops = {
	.readpage	= ntfs_readpage,
#ifdef NTFS_RW
	.writepage	= ntfs_writepage,
	.set_page_dirty	= __set_page_dirty_buffers,
#endif /* NTFS_RW */
	.bmap		= ntfs_bmap,
	.migratepage	= buffer_migrate_page,
	.is_partially_uptodate = block_is_partially_uptodate,
	.error_remove_page = generic_error_remove_page,
};

/**
 * ntfs_compressed_aops - address space operations for compressed inodes
 */
const struct address_space_operations ntfs_compressed_aops = {
	.readpage	= ntfs_readpage,
#ifdef NTFS_RW
	.writepage	= ntfs_writepage,
	.set_page_dirty	= __set_page_dirty_buffers,
#endif /* NTFS_RW */
	.migratepage	= buffer_migrate_page,
	.is_partially_uptodate = block_is_partially_uptodate,
	.error_remove_page = generic_error_remove_page,
};

/**
 * ntfs_mst_aops - general address space operations for mst protecteed inodes
 *		   and attributes
 */
const struct address_space_operations ntfs_mst_aops = {
	.readpage	= ntfs_readpage,	/* Fill page with data. */
#ifdef NTFS_RW
	.writepage	= ntfs_writepage,	/* Write dirty page to disk. */
	.set_page_dirty	= __set_page_dirty_nobuffers,	/* Set the page dirty
						   without touching the buffers
						   belonging to the page. */
#endif /* NTFS_RW */
	.migratepage	= buffer_migrate_page,
	.is_partially_uptodate	= block_is_partially_uptodate,
	.error_remove_page = generic_error_remove_page,
};

#ifdef NTFS_RW

/**
 * mark_ntfs_record_dirty - mark an ntfs record dirty
 * @page:	page containing the ntfs record to mark dirty
 * @ofs:	byte offset within @page at which the ntfs record begins
 *
 * Set the buffers and the page in which the ntfs record is located dirty.
 *
 * The latter also marks the vfs inode the ntfs record belongs to dirty
 * (I_DIRTY_PAGES only).
 *
 * If the page does not have buffers, we create them and set them uptodate.
 * The page may not be locked which is why we need to handle the buffers under
 * the mapping->private_lock.  Once the buffers are marked dirty we no longer
 * need the lock since try_to_free_buffers() does not free dirty buffers.
 */
void mark_ntfs_record_dirty(struct page *page, const unsigned int ofs) {
	struct address_space *mapping = page->mapping;
	ntfs_inode *ni = NTFS_I(mapping->host);
	struct buffer_head *bh, *head, *buffers_to_free = NULL;
	unsigned int end, bh_size, bh_ofs;

	BUG_ON(!PageUptodate(page));
	end = ofs + ni->itype.index.block_size;
	bh_size = VFS_I(ni)->i_sb->s_blocksize;
	spin_lock(&mapping->private_lock);
	if (unlikely(!page_has_buffers(page))) {
		spin_unlock(&mapping->private_lock);
		bh = head = alloc_page_buffers(page, bh_size, 1);
		spin_lock(&mapping->private_lock);
		if (likely(!page_has_buffers(page))) {
			struct buffer_head *tail;

			do {
				set_buffer_uptodate(bh);
				tail = bh;
				bh = bh->b_this_page;
			} while (bh);
			tail->b_this_page = head;
			attach_page_buffers(page, head);
		} else
			buffers_to_free = bh;
	}
	bh = head = page_buffers(page);
	BUG_ON(!bh);
	do {
		bh_ofs = bh_offset(bh);
		if (bh_ofs + bh_size <= ofs)
			continue;
		if (unlikely(bh_ofs >= end))
			break;
		set_buffer_dirty(bh);
	} while ((bh = bh->b_this_page) != head);
	spin_unlock(&mapping->private_lock);
	__set_page_dirty_nobuffers(page);
	if (unlikely(buffers_to_free)) {
		do {
			bh = buffers_to_free->b_this_page;
			free_buffer_head(buffers_to_free);
			buffers_to_free = bh;
		} while (buffers_to_free);
	}
}

#endif /* NTFS_RW */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/aops.c */
/************************************************************/
/**
 * attrib.c - NTFS attribute operations.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2012 Anton Altaparmakov and Tuxera Inc.
 * Copyright (c) 2002 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include <linux/buffer_head.h>
#include <linux/sched.h>
#include <linux/slab.h>
// #include <linux/swap.h>
// #include <linux/writeback.h>
#include "../../inc/__fss.h"

// #include "attrib.h"
// #include "debug.h"
#include "layout.h"
#include "lcnalloc.h"
#include "malloc.h"
// #include "mft.h"
// #include "ntfs.h"
// #include "types.h"
#include "../../inc/__fss.h"

/**
 * ntfs_map_runlist_nolock - map (a part of) a runlist of an ntfs inode
 * @ni:		ntfs inode for which to map (part of) a runlist
 * @vcn:	map runlist part containing this vcn
 * @ctx:	active attribute search context if present or NULL if not
 *
 * Map the part of a runlist containing the @vcn of the ntfs inode @ni.
 *
 * If @ctx is specified, it is an active search context of @ni and its base mft
 * record.  This is needed when ntfs_map_runlist_nolock() encounters unmapped
 * runlist fragments and allows their mapping.  If you do not have the mft
 * record mapped, you can specify @ctx as NULL and ntfs_map_runlist_nolock()
 * will perform the necessary mapping and unmapping.
 *
 * Note, ntfs_map_runlist_nolock() saves the state of @ctx on entry and
 * restores it before returning.  Thus, @ctx will be left pointing to the same
 * attribute on return as on entry.  However, the actual pointers in @ctx may
 * point to different memory locations on return, so you must remember to reset
 * any cached pointers from the @ctx, i.e. after the call to
 * ntfs_map_runlist_nolock(), you will probably want to do:
 *	m = ctx->mrec;
 *	a = ctx->attr;
 * Assuming you cache ctx->attr in a variable @a of type ATTR_RECORD * and that
 * you cache ctx->mrec in a variable @m of type MFT_RECORD *.
 *
 * Return 0 on success and -errno on error.  There is one special error code
 * which is not an error as such.  This is -ENOENT.  It means that @vcn is out
 * of bounds of the runlist.
 *
 * Note the runlist can be NULL after this function returns if @vcn is zero and
 * the attribute has zero allocated size, i.e. there simply is no runlist.
 *
 * WARNING: If @ctx is supplied, regardless of whether success or failure is
 *	    returned, you need to check IS_ERR(@ctx->mrec) and if 'true' the @ctx
 *	    is no longer valid, i.e. you need to either call
 *	    ntfs_attr_reinit_search_ctx() or ntfs_attr_put_search_ctx() on it.
 *	    In that case PTR_ERR(@ctx->mrec) will give you the error code for
 *	    why the mapping of the old inode failed.
 *
 * Locking: - The runlist described by @ni must be locked for writing on entry
 *	      and is locked on return.  Note the runlist will be modified.
 *	    - If @ctx is NULL, the base mft record of @ni must not be mapped on
 *	      entry and it will be left unmapped on return.
 *	    - If @ctx is not NULL, the base mft record must be mapped on entry
 *	      and it will be left mapped on return.
 */
int ntfs_map_runlist_nolock(ntfs_inode *ni, VCN vcn, ntfs_attr_search_ctx *ctx)
{
	VCN end_vcn;
	unsigned long flags;
	ntfs_inode *base_ni;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	runlist_element *rl;
	struct page *put_this_page = NULL;
	int err = 0;
	bool ctx_is_temporary, ctx_needs_reset;
	ntfs_attr_search_ctx old_ctx = { NULL, };

	ntfs_debug("Mapping runlist part containing vcn 0x%llx.",
			(unsigned long long)vcn);
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	if (!ctx) {
		ctx_is_temporary = ctx_needs_reset = true;
		m = map_mft_record(base_ni);
		if (IS_ERR(m))
			return PTR_ERR(m);
		ctx = ntfs_attr_get_search_ctx(base_ni, m);
		if (unlikely(!ctx)) {
			err = -ENOMEM;
			goto err_out;
		}
	} else {
		VCN allocated_size_vcn;

		BUG_ON(IS_ERR(ctx->mrec));
		a = ctx->attr;
		BUG_ON(!a->non_resident);
		ctx_is_temporary = false;
		end_vcn = sle64_to_cpu(a->data.non_resident.highest_vcn);
		read_lock_irqsave(&ni->size_lock, flags);
		allocated_size_vcn = ni->allocated_size >>
				ni->vol->cluster_size_bits;
		read_unlock_irqrestore(&ni->size_lock, flags);
		if (!a->data.non_resident.lowest_vcn && end_vcn <= 0)
			end_vcn = allocated_size_vcn - 1;
		/*
		 * If we already have the attribute extent containing @vcn in
		 * @ctx, no need to look it up again.  We slightly cheat in
		 * that if vcn exceeds the allocated size, we will refuse to
		 * map the runlist below, so there is definitely no need to get
		 * the right attribute extent.
		 */
		if (vcn >= allocated_size_vcn || (a->type == ni->type &&
				a->name_length == ni->name_len &&
				!memcmp((u8*)a + le16_to_cpu(a->name_offset),
				ni->name, ni->name_len) &&
				sle64_to_cpu(a->data.non_resident.lowest_vcn)
				<= vcn && end_vcn >= vcn))
			ctx_needs_reset = false;
		else {
			/* Save the old search context. */
			old_ctx = *ctx;
			/*
			 * If the currently mapped (extent) inode is not the
			 * base inode we will unmap it when we reinitialize the
			 * search context which means we need to get a
			 * reference to the page containing the mapped mft
			 * record so we do not accidentally drop changes to the
			 * mft record when it has not been marked dirty yet.
			 */
			if (old_ctx.base_ntfs_ino && old_ctx.ntfs_ino !=
					old_ctx.base_ntfs_ino) {
				put_this_page = old_ctx.ntfs_ino->page;
				page_cache_get(put_this_page);
			}
			/*
			 * Reinitialize the search context so we can lookup the
			 * needed attribute extent.
			 */
			ntfs_attr_reinit_search_ctx(ctx);
			ctx_needs_reset = true;
		}
	}
	if (ctx_needs_reset) {
		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, vcn, NULL, 0, ctx);
		if (unlikely(err)) {
			if (err == -ENOENT)
				err = -EIO;
			goto err_out;
		}
		BUG_ON(!ctx->attr->non_resident);
	}
	a = ctx->attr;
	/*
	 * Only decompress the mapping pairs if @vcn is inside it.  Otherwise
	 * we get into problems when we try to map an out of bounds vcn because
	 * we then try to map the already mapped runlist fragment and
	 * ntfs_mapping_pairs_decompress() fails.
	 */
	end_vcn = sle64_to_cpu(a->data.non_resident.highest_vcn) + 1;
	if (unlikely(vcn && vcn >= end_vcn)) {
		err = -ENOENT;
		goto err_out;
	}
	rl = ntfs_mapping_pairs_decompress(ni->vol, a, ni->runlist.rl);
	if (IS_ERR(rl))
		err = PTR_ERR(rl);
	else
		ni->runlist.rl = rl;
err_out:
	if (ctx_is_temporary) {
		if (likely(ctx))
			ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(base_ni);
	} else if (ctx_needs_reset) {
		/*
		 * If there is no attribute list, restoring the search context
		 * is accomplished simply by copying the saved context back over
		 * the caller supplied context.  If there is an attribute list,
		 * things are more complicated as we need to deal with mapping
		 * of mft records and resulting potential changes in pointers.
		 */
		if (NInoAttrList(base_ni)) {
			/*
			 * If the currently mapped (extent) inode is not the
			 * one we had before, we need to unmap it and map the
			 * old one.
			 */
			if (ctx->ntfs_ino != old_ctx.ntfs_ino) {
				/*
				 * If the currently mapped inode is not the
				 * base inode, unmap it.
				 */
				if (ctx->base_ntfs_ino && ctx->ntfs_ino !=
						ctx->base_ntfs_ino) {
					unmap_extent_mft_record(ctx->ntfs_ino);
					ctx->mrec = ctx->base_mrec;
					BUG_ON(!ctx->mrec);
				}
				/*
				 * If the old mapped inode is not the base
				 * inode, map it.
				 */
				if (old_ctx.base_ntfs_ino &&
						old_ctx.ntfs_ino !=
						old_ctx.base_ntfs_ino) {
retry_map:
					ctx->mrec = map_mft_record(
							old_ctx.ntfs_ino);
					/*
					 * Something bad has happened.  If out
					 * of memory retry till it succeeds.
					 * Any other errors are fatal and we
					 * return the error code in ctx->mrec.
					 * Let the caller deal with it...  We
					 * just need to fudge things so the
					 * caller can reinit and/or put the
					 * search context safely.
					 */
					if (IS_ERR(ctx->mrec)) {
						if (PTR_ERR(ctx->mrec) ==
								-ENOMEM) {
							schedule();
							goto retry_map;
						} else
							old_ctx.ntfs_ino =
								old_ctx.
								base_ntfs_ino;
					}
				}
			}
			/* Update the changed pointers in the saved context. */
			if (ctx->mrec != old_ctx.mrec) {
				if (!IS_ERR(ctx->mrec))
					old_ctx.attr = (ATTR_RECORD*)(
							(u8*)ctx->mrec +
							((u8*)old_ctx.attr -
							(u8*)old_ctx.mrec));
				old_ctx.mrec = ctx->mrec;
			}
		}
		/* Restore the search context to the saved one. */
		*ctx = old_ctx;
		/*
		 * We drop the reference on the page we took earlier.  In the
		 * case that IS_ERR(ctx->mrec) is true this means we might lose
		 * some changes to the mft record that had been made between
		 * the last time it was marked dirty/written out and now.  This
		 * at this stage is not a problem as the mapping error is fatal
		 * enough that the mft record cannot be written out anyway and
		 * the caller is very likely to shutdown the whole inode
		 * immediately and mark the volume dirty for chkdsk to pick up
		 * the pieces anyway.
		 */
		if (put_this_page)
			page_cache_release(put_this_page);
	}
	return err;
}

/**
 * ntfs_map_runlist - map (a part of) a runlist of an ntfs inode
 * @ni:		ntfs inode for which to map (part of) a runlist
 * @vcn:	map runlist part containing this vcn
 *
 * Map the part of a runlist containing the @vcn of the ntfs inode @ni.
 *
 * Return 0 on success and -errno on error.  There is one special error code
 * which is not an error as such.  This is -ENOENT.  It means that @vcn is out
 * of bounds of the runlist.
 *
 * Locking: - The runlist must be unlocked on entry and is unlocked on return.
 *	    - This function takes the runlist lock for writing and may modify
 *	      the runlist.
 */
int ntfs_map_runlist(ntfs_inode *ni, VCN vcn)
{
	int err = 0;

	down_write(&ni->runlist.lock);
	/* Make sure someone else didn't do the work while we were sleeping. */
	if (likely(ntfs_rl_vcn_to_lcn(ni->runlist.rl, vcn) <=
			LCN_RL_NOT_MAPPED))
		err = ntfs_map_runlist_nolock(ni, vcn, NULL);
	up_write(&ni->runlist.lock);
	return err;
}

/**
 * ntfs_attr_vcn_to_lcn_nolock - convert a vcn into a lcn given an ntfs inode
 * @ni:			ntfs inode of the attribute whose runlist to search
 * @vcn:		vcn to convert
 * @write_locked:	true if the runlist is locked for writing
 *
 * Find the virtual cluster number @vcn in the runlist of the ntfs attribute
 * described by the ntfs inode @ni and return the corresponding logical cluster
 * number (lcn).
 *
 * If the @vcn is not mapped yet, the attempt is made to map the attribute
 * extent containing the @vcn and the vcn to lcn conversion is retried.
 *
 * If @write_locked is true the caller has locked the runlist for writing and
 * if false for reading.
 *
 * Since lcns must be >= 0, we use negative return codes with special meaning:
 *
 * Return code	Meaning / Description
 * ==========================================
 *  LCN_HOLE	Hole / not allocated on disk.
 *  LCN_ENOENT	There is no such vcn in the runlist, i.e. @vcn is out of bounds.
 *  LCN_ENOMEM	Not enough memory to map runlist.
 *  LCN_EIO	Critical error (runlist/file is corrupt, i/o error, etc).
 *
 * Locking: - The runlist must be locked on entry and is left locked on return.
 *	    - If @write_locked is 'false', i.e. the runlist is locked for reading,
 *	      the lock may be dropped inside the function so you cannot rely on
 *	      the runlist still being the same when this function returns.
 */
LCN ntfs_attr_vcn_to_lcn_nolock(ntfs_inode *ni, const VCN vcn,
		const bool write_locked)
{
	LCN lcn;
	unsigned long flags;
	bool is_retry = false;

	BUG_ON(!ni);
	ntfs_debug("Entering for i_ino 0x%lx, vcn 0x%llx, %s_locked.",
			ni->mft_no, (unsigned long long)vcn,
			write_locked ? "write" : "read");
	BUG_ON(!NInoNonResident(ni));
	BUG_ON(vcn < 0);
	if (!ni->runlist.rl) {
		read_lock_irqsave(&ni->size_lock, flags);
		if (!ni->allocated_size) {
			read_unlock_irqrestore(&ni->size_lock, flags);
			return LCN_ENOENT;
		}
		read_unlock_irqrestore(&ni->size_lock, flags);
	}
retry_remap:
	/* Convert vcn to lcn.  If that fails map the runlist and retry once. */
	lcn = ntfs_rl_vcn_to_lcn(ni->runlist.rl, vcn);
	if (likely(lcn >= LCN_HOLE)) {
		ntfs_debug("Done, lcn 0x%llx.", (long long)lcn);
		return lcn;
	}
	if (lcn != LCN_RL_NOT_MAPPED) {
		if (lcn != LCN_ENOENT)
			lcn = LCN_EIO;
	} else if (!is_retry) {
		int err;

		if (!write_locked) {
			up_read(&ni->runlist.lock);
			down_write(&ni->runlist.lock);
			if (unlikely(ntfs_rl_vcn_to_lcn(ni->runlist.rl, vcn) !=
					LCN_RL_NOT_MAPPED)) {
				up_write(&ni->runlist.lock);
				down_read(&ni->runlist.lock);
				goto retry_remap;
			}
		}
		err = ntfs_map_runlist_nolock(ni, vcn, NULL);
		if (!write_locked) {
			up_write(&ni->runlist.lock);
			down_read(&ni->runlist.lock);
		}
		if (likely(!err)) {
			is_retry = true;
			goto retry_remap;
		}
		if (err == -ENOENT)
			lcn = LCN_ENOENT;
		else if (err == -ENOMEM)
			lcn = LCN_ENOMEM;
		else
			lcn = LCN_EIO;
	}
	if (lcn != LCN_ENOENT)
		ntfs_error(ni->vol->sb, "Failed with error code %lli.",
				(long long)lcn);
	return lcn;
}

/**
 * ntfs_attr_find_vcn_nolock - find a vcn in the runlist of an ntfs inode
 * @ni:		ntfs inode describing the runlist to search
 * @vcn:	vcn to find
 * @ctx:	active attribute search context if present or NULL if not
 *
 * Find the virtual cluster number @vcn in the runlist described by the ntfs
 * inode @ni and return the address of the runlist element containing the @vcn.
 *
 * If the @vcn is not mapped yet, the attempt is made to map the attribute
 * extent containing the @vcn and the vcn to lcn conversion is retried.
 *
 * If @ctx is specified, it is an active search context of @ni and its base mft
 * record.  This is needed when ntfs_attr_find_vcn_nolock() encounters unmapped
 * runlist fragments and allows their mapping.  If you do not have the mft
 * record mapped, you can specify @ctx as NULL and ntfs_attr_find_vcn_nolock()
 * will perform the necessary mapping and unmapping.
 *
 * Note, ntfs_attr_find_vcn_nolock() saves the state of @ctx on entry and
 * restores it before returning.  Thus, @ctx will be left pointing to the same
 * attribute on return as on entry.  However, the actual pointers in @ctx may
 * point to different memory locations on return, so you must remember to reset
 * any cached pointers from the @ctx, i.e. after the call to
 * ntfs_attr_find_vcn_nolock(), you will probably want to do:
 *	m = ctx->mrec;
 *	a = ctx->attr;
 * Assuming you cache ctx->attr in a variable @a of type ATTR_RECORD * and that
 * you cache ctx->mrec in a variable @m of type MFT_RECORD *.
 * Note you need to distinguish between the lcn of the returned runlist element
 * being >= 0 and LCN_HOLE.  In the later case you have to return zeroes on
 * read and allocate clusters on write.
 *
 * Return the runlist element containing the @vcn on success and
 * ERR_PTR(-errno) on error.  You need to test the return value with IS_ERR()
 * to decide if the return is success or failure and PTR_ERR() to get to the
 * error code if IS_ERR() is true.
 *
 * The possible error return codes are:
 *	-ENOENT - No such vcn in the runlist, i.e. @vcn is out of bounds.
 *	-ENOMEM - Not enough memory to map runlist.
 *	-EIO	- Critical error (runlist/file is corrupt, i/o error, etc).
 *
 * WARNING: If @ctx is supplied, regardless of whether success or failure is
 *	    returned, you need to check IS_ERR(@ctx->mrec) and if 'true' the @ctx
 *	    is no longer valid, i.e. you need to either call
 *	    ntfs_attr_reinit_search_ctx() or ntfs_attr_put_search_ctx() on it.
 *	    In that case PTR_ERR(@ctx->mrec) will give you the error code for
 *	    why the mapping of the old inode failed.
 *
 * Locking: - The runlist described by @ni must be locked for writing on entry
 *	      and is locked on return.  Note the runlist may be modified when
 *	      needed runlist fragments need to be mapped.
 *	    - If @ctx is NULL, the base mft record of @ni must not be mapped on
 *	      entry and it will be left unmapped on return.
 *	    - If @ctx is not NULL, the base mft record must be mapped on entry
 *	      and it will be left mapped on return.
 */
runlist_element *ntfs_attr_find_vcn_nolock(ntfs_inode *ni, const VCN vcn,
		ntfs_attr_search_ctx *ctx)
{
	unsigned long flags;
	runlist_element *rl;
	int err = 0;
	bool is_retry = false;

	BUG_ON(!ni);
	ntfs_debug("Entering for i_ino 0x%lx, vcn 0x%llx, with%s ctx.",
			ni->mft_no, (unsigned long long)vcn, ctx ? "" : "out");
	BUG_ON(!NInoNonResident(ni));
	BUG_ON(vcn < 0);
	if (!ni->runlist.rl) {
		read_lock_irqsave(&ni->size_lock, flags);
		if (!ni->allocated_size) {
			read_unlock_irqrestore(&ni->size_lock, flags);
			return ERR_PTR(-ENOENT);
		}
		read_unlock_irqrestore(&ni->size_lock, flags);
	}
retry_remap:
	rl = ni->runlist.rl;
	if (likely(rl && vcn >= rl[0].vcn)) {
		while (likely(rl->length)) {
			if (unlikely(vcn < rl[1].vcn)) {
				if (likely(rl->lcn >= LCN_HOLE)) {
					ntfs_debug("Done.");
					return rl;
				}
				break;
			}
			rl++;
		}
		if (likely(rl->lcn != LCN_RL_NOT_MAPPED)) {
			if (likely(rl->lcn == LCN_ENOENT))
				err = -ENOENT;
			else
				err = -EIO;
		}
	}
	if (!err && !is_retry) {
		/*
		 * If the search context is invalid we cannot map the unmapped
		 * region.
		 */
		if (IS_ERR(ctx->mrec))
			err = PTR_ERR(ctx->mrec);
		else {
			/*
			 * The @vcn is in an unmapped region, map the runlist
			 * and retry.
			 */
			err = ntfs_map_runlist_nolock(ni, vcn, ctx);
			if (likely(!err)) {
				is_retry = true;
				goto retry_remap;
			}
		}
		if (err == -EINVAL)
			err = -EIO;
	} else if (!err)
		err = -EIO;
	if (err != -ENOENT)
		ntfs_error(ni->vol->sb, "Failed with error code %i.", err);
	return ERR_PTR(err);
}

/**
 * ntfs_attr_find - find (next) attribute in mft record
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * You should not need to call this function directly.  Use ntfs_attr_lookup()
 * instead.
 *
 * ntfs_attr_find() takes a search context @ctx as parameter and searches the
 * mft record specified by @ctx->mrec, beginning at @ctx->attr, for an
 * attribute of @type, optionally @name and @val.
 *
 * If the attribute is found, ntfs_attr_find() returns 0 and @ctx->attr will
 * point to the found attribute.
 *
 * If the attribute is not found, ntfs_attr_find() returns -ENOENT and
 * @ctx->attr will point to the attribute before which the attribute being
 * searched for would need to be inserted if such an action were to be desired.
 *
 * On actual error, ntfs_attr_find() returns -EIO.  In this case @ctx->attr is
 * undefined and in particular do not rely on it not changing.
 *
 * If @ctx->is_first is 'true', the search begins with @ctx->attr itself.  If it
 * is 'false', the search begins after @ctx->attr.
 *
 * If @ic is IGNORE_CASE, the @name comparisson is not case sensitive and
 * @ctx->ntfs_ino must be set to the ntfs inode to which the mft record
 * @ctx->mrec belongs.  This is so we can get at the ntfs volume and hence at
 * the upcase table.  If @ic is CASE_SENSITIVE, the comparison is case
 * sensitive.  When @name is present, @name_len is the @name length in Unicode
 * characters.
 *
 * If @name is not present (NULL), we assume that the unnamed attribute is
 * being searched for.
 *
 * Finally, the resident attribute value @val is looked for, if present.  If
 * @val is not present (NULL), @val_len is ignored.
 *
 * ntfs_attr_find() only searches the specified mft record and it ignores the
 * presence of an attribute list attribute (unless it is the one being searched
 * for, obviously).  If you need to take attribute lists into consideration,
 * use ntfs_attr_lookup() instead (see below).  This also means that you cannot
 * use ntfs_attr_find() to search for extent records of non-resident
 * attributes, as extents with lowest_vcn != 0 are usually described by the
 * attribute list attribute only. - Note that it is possible that the first
 * extent is only in the attribute list while the last extent is in the base
 * mft record, so do not rely on being able to find the first extent in the
 * base mft record.
 *
 * Warning: Never use @val when looking for attribute types which can be
 *	    non-resident as this most likely will result in a crash!
 */
static int ntfs_attr_find(const ATTR_TYPE type, const ntfschar *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const u8 *val, const u32 val_len, ntfs_attr_search_ctx *ctx)
{
	ATTR_RECORD *a;
	ntfs_volume *vol = ctx->ntfs_ino->vol;
	ntfschar *upcase = vol->upcase;
	u32 upcase_len = vol->upcase_len;

	/*
	 * Iterate over attributes in mft record starting at @ctx->attr, or the
	 * attribute following that, if @ctx->is_first is 'true'.
	 */
	if (ctx->is_first) {
		a = ctx->attr;
		ctx->is_first = false;
	} else
		a = (ATTR_RECORD*)((u8*)ctx->attr +
				le32_to_cpu(ctx->attr->length));
	for (;;	a = (ATTR_RECORD*)((u8*)a + le32_to_cpu(a->length))) {
		if ((u8*)a < (u8*)ctx->mrec || (u8*)a > (u8*)ctx->mrec +
				le32_to_cpu(ctx->mrec->bytes_allocated))
			break;
		ctx->attr = a;
		if (unlikely(le32_to_cpu(a->type) > le32_to_cpu(type) ||
				a->type == AT_END))
			return -ENOENT;
		if (unlikely(!a->length))
			break;
		if (a->type != type)
			continue;
		/*
		 * If @name is present, compare the two names.  If @name is
		 * missing, assume we want an unnamed attribute.
		 */
		if (!name) {
			/* The search failed if the found attribute is named. */
			if (a->name_length)
				return -ENOENT;
		} else if (!ntfs_are_names_equal(name, name_len,
			    (ntfschar*)((u8*)a + le16_to_cpu(a->name_offset)),
			    a->name_length, ic, upcase, upcase_len)) {
			register int rc;

			rc = ntfs_collate_names(name, name_len,
					(ntfschar*)((u8*)a +
					le16_to_cpu(a->name_offset)),
					a->name_length, 1, IGNORE_CASE,
					upcase, upcase_len);
			/*
			 * If @name collates before a->name, there is no
			 * matching attribute.
			 */
			if (rc == -1)
				return -ENOENT;
			/* If the strings are not equal, continue search. */
			if (rc)
				continue;
			rc = ntfs_collate_names(name, name_len,
					(ntfschar*)((u8*)a +
					le16_to_cpu(a->name_offset)),
					a->name_length, 1, CASE_SENSITIVE,
					upcase, upcase_len);
			if (rc == -1)
				return -ENOENT;
			if (rc)
				continue;
		}
		/*
		 * The names match or @name not present and attribute is
		 * unnamed.  If no @val specified, we have found the attribute
		 * and are done.
		 */
		if (!val)
			return 0;
		/* @val is present; compare values. */
		else {
			register int rc;

			rc = memcmp(val, (u8*)a + le16_to_cpu(
					a->data.resident.value_offset),
					min_t(u32, val_len, le32_to_cpu(
					a->data.resident.value_length)));
			/*
			 * If @val collates before the current attribute's
			 * value, there is no matching attribute.
			 */
			if (!rc) {
				register u32 avl;

				avl = le32_to_cpu(
						a->data.resident.value_length);
				if (val_len == avl)
					return 0;
				if (val_len < avl)
					return -ENOENT;
			} else if (rc < 0)
				return -ENOENT;
		}
	}
	ntfs_error(vol->sb, "Inode is corrupt.  Run chkdsk.");
	NVolSetErrors(vol);
	return -EIO;
}

/**
 * load_attribute_list - load an attribute list into memory
 * @vol:		ntfs volume from which to read
 * @runlist:		runlist of the attribute list
 * @al_start:		destination buffer
 * @size:		size of the destination buffer in bytes
 * @initialized_size:	initialized size of the attribute list
 *
 * Walk the runlist @runlist and load all clusters from it copying them into
 * the linear buffer @al. The maximum number of bytes copied to @al is @size
 * bytes. Note, @size does not need to be a multiple of the cluster size. If
 * @initialized_size is less than @size, the region in @al between
 * @initialized_size and @size will be zeroed and not read from disk.
 *
 * Return 0 on success or -errno on error.
 */
int load_attribute_list(ntfs_volume *vol, runlist *runlist, u8 *al_start,
		const s64 size, const s64 initialized_size)
{
	LCN lcn;
	u8 *al = al_start;
	u8 *al_end = al + initialized_size;
	runlist_element *rl;
	struct buffer_head *bh;
	struct super_block *sb;
	unsigned long block_size;
	unsigned long block, max_block;
	int err = 0;
	unsigned char block_size_bits;

	ntfs_debug("Entering.");
	if (!vol || !runlist || !al || size <= 0 || initialized_size < 0 ||
			initialized_size > size)
		return -EINVAL;
	if (!initialized_size) {
		memset(al, 0, size);
		return 0;
	}
	sb = vol->sb;
	block_size = sb->s_blocksize;
	block_size_bits = sb->s_blocksize_bits;
	down_read(&runlist->lock);
	rl = runlist->rl;
	if (!rl) {
		ntfs_error(sb, "Cannot read attribute list since runlist is "
				"missing.");
		goto err_out;	
	}
	/* Read all clusters specified by the runlist one run at a time. */
	while (rl->length) {
		lcn = ntfs_rl_vcn_to_lcn(rl, rl->vcn);
		ntfs_debug("Reading vcn = 0x%llx, lcn = 0x%llx.",
				(unsigned long long)rl->vcn,
				(unsigned long long)lcn);
		/* The attribute list cannot be sparse. */
		if (lcn < 0) {
			ntfs_error(sb, "ntfs_rl_vcn_to_lcn() failed.  Cannot "
					"read attribute list.");
			goto err_out;
		}
		block = lcn << vol->cluster_size_bits >> block_size_bits;
		/* Read the run from device in chunks of block_size bytes. */
		max_block = block + (rl->length << vol->cluster_size_bits >>
				block_size_bits);
		ntfs_debug("max_block = 0x%lx.", max_block);
		do {
			ntfs_debug("Reading block = 0x%lx.", block);
			bh = sb_bread(sb, block);
			if (!bh) {
				ntfs_error(sb, "sb_bread() failed. Cannot "
						"read attribute list.");
				goto err_out;
			}
			if (al + block_size >= al_end)
				goto do_final;
			memcpy(al, bh->b_data, block_size);
			brelse(bh);
			al += block_size;
		} while (++block < max_block);
		rl++;
	}
	if (initialized_size < size) {
initialize:
		memset(al_start + initialized_size, 0, size - initialized_size);
	}
done:
	up_read(&runlist->lock);
	return err;
do_final:
	if (al < al_end) {
		/*
		 * Partial block.
		 *
		 * Note: The attribute list can be smaller than its allocation
		 * by multiple clusters.  This has been encountered by at least
		 * two people running Windows XP, thus we cannot do any
		 * truncation sanity checking here. (AIA)
		 */
		memcpy(al, bh->b_data, al_end - al);
		brelse(bh);
		if (initialized_size < size)
			goto initialize;
		goto done;
	}
	brelse(bh);
	/* Real overflow! */
	ntfs_error(sb, "Attribute list buffer overflow. Read attribute list "
			"is truncated.");
err_out:
	err = -EIO;
	goto done;
}

/**
 * ntfs_external_attr_find - find an attribute in the attribute list of an inode
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @lowest_vcn:	lowest vcn to find (optional, non-resident attributes only)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * You should not need to call this function directly.  Use ntfs_attr_lookup()
 * instead.
 *
 * Find an attribute by searching the attribute list for the corresponding
 * attribute list entry.  Having found the entry, map the mft record if the
 * attribute is in a different mft record/inode, ntfs_attr_find() the attribute
 * in there and return it.
 *
 * On first search @ctx->ntfs_ino must be the base mft record and @ctx must
 * have been obtained from a call to ntfs_attr_get_search_ctx().  On subsequent
 * calls @ctx->ntfs_ino can be any extent inode, too (@ctx->base_ntfs_ino is
 * then the base inode).
 *
 * After finishing with the attribute/mft record you need to call
 * ntfs_attr_put_search_ctx() to cleanup the search context (unmapping any
 * mapped inodes, etc).
 *
 * If the attribute is found, ntfs_external_attr_find() returns 0 and
 * @ctx->attr will point to the found attribute.  @ctx->mrec will point to the
 * mft record in which @ctx->attr is located and @ctx->al_entry will point to
 * the attribute list entry for the attribute.
 *
 * If the attribute is not found, ntfs_external_attr_find() returns -ENOENT and
 * @ctx->attr will point to the attribute in the base mft record before which
 * the attribute being searched for would need to be inserted if such an action
 * were to be desired.  @ctx->mrec will point to the mft record in which
 * @ctx->attr is located and @ctx->al_entry will point to the attribute list
 * entry of the attribute before which the attribute being searched for would
 * need to be inserted if such an action were to be desired.
 *
 * Thus to insert the not found attribute, one wants to add the attribute to
 * @ctx->mrec (the base mft record) and if there is not enough space, the
 * attribute should be placed in a newly allocated extent mft record.  The
 * attribute list entry for the inserted attribute should be inserted in the
 * attribute list attribute at @ctx->al_entry.
 *
 * On actual error, ntfs_external_attr_find() returns -EIO.  In this case
 * @ctx->attr is undefined and in particular do not rely on it not changing.
 */
static int ntfs_external_attr_find(const ATTR_TYPE type,
		const ntfschar *name, const u32 name_len,
		const IGNORE_CASE_BOOL ic, const VCN lowest_vcn,
		const u8 *val, const u32 val_len, ntfs_attr_search_ctx *ctx)
{
	ntfs_inode *base_ni, *ni;
	ntfs_volume *vol;
	ATTR_LIST_ENTRY *al_entry, *next_al_entry;
	u8 *al_start, *al_end;
	ATTR_RECORD *a;
	ntfschar *al_name;
	u32 al_name_len;
	int err = 0;
	static const char *es = " Unmount and run chkdsk.";

	ni = ctx->ntfs_ino;
	base_ni = ctx->base_ntfs_ino;
	ntfs_debug("Entering for inode 0x%lx, type 0x%x.", ni->mft_no, type);
	if (!base_ni) {
		/* First call happens with the base mft record. */
		base_ni = ctx->base_ntfs_ino = ctx->ntfs_ino;
		ctx->base_mrec = ctx->mrec;
	}
	if (ni == base_ni)
		ctx->base_attr = ctx->attr;
	if (type == AT_END)
		goto not_found;
	vol = base_ni->vol;
	al_start = base_ni->attr_list;
	al_end = al_start + base_ni->attr_list_size;
	if (!ctx->al_entry)
		ctx->al_entry = (ATTR_LIST_ENTRY*)al_start;
	/*
	 * Iterate over entries in attribute list starting at @ctx->al_entry,
	 * or the entry following that, if @ctx->is_first is 'true'.
	 */
	if (ctx->is_first) {
		al_entry = ctx->al_entry;
		ctx->is_first = false;
	} else
		al_entry = (ATTR_LIST_ENTRY*)((u8*)ctx->al_entry +
				le16_to_cpu(ctx->al_entry->length));
	for (;; al_entry = next_al_entry) {
		/* Out of bounds check. */
		if ((u8*)al_entry < base_ni->attr_list ||
				(u8*)al_entry > al_end)
			break;	/* Inode is corrupt. */
		ctx->al_entry = al_entry;
		/* Catch the end of the attribute list. */
		if ((u8*)al_entry == al_end)
			goto not_found;
		if (!al_entry->length)
			break;
		if ((u8*)al_entry + 6 > al_end || (u8*)al_entry +
				le16_to_cpu(al_entry->length) > al_end)
			break;
		next_al_entry = (ATTR_LIST_ENTRY*)((u8*)al_entry +
				le16_to_cpu(al_entry->length));
		if (le32_to_cpu(al_entry->type) > le32_to_cpu(type))
			goto not_found;
		if (type != al_entry->type)
			continue;
		/*
		 * If @name is present, compare the two names.  If @name is
		 * missing, assume we want an unnamed attribute.
		 */
		al_name_len = al_entry->name_length;
		al_name = (ntfschar*)((u8*)al_entry + al_entry->name_offset);
		if (!name) {
			if (al_name_len)
				goto not_found;
		} else if (!ntfs_are_names_equal(al_name, al_name_len, name,
				name_len, ic, vol->upcase, vol->upcase_len)) {
			register int rc;

			rc = ntfs_collate_names(name, name_len, al_name,
					al_name_len, 1, IGNORE_CASE,
					vol->upcase, vol->upcase_len);
			/*
			 * If @name collates before al_name, there is no
			 * matching attribute.
			 */
			if (rc == -1)
				goto not_found;
			/* If the strings are not equal, continue search. */
			if (rc)
				continue;
			/*
			 * FIXME: Reverse engineering showed 0, IGNORE_CASE but
			 * that is inconsistent with ntfs_attr_find().  The
			 * subsequent rc checks were also different.  Perhaps I
			 * made a mistake in one of the two.  Need to recheck
			 * which is correct or at least see what is going on...
			 * (AIA)
			 */
			rc = ntfs_collate_names(name, name_len, al_name,
					al_name_len, 1, CASE_SENSITIVE,
					vol->upcase, vol->upcase_len);
			if (rc == -1)
				goto not_found;
			if (rc)
				continue;
		}
		/*
		 * The names match or @name not present and attribute is
		 * unnamed.  Now check @lowest_vcn.  Continue search if the
		 * next attribute list entry still fits @lowest_vcn.  Otherwise
		 * we have reached the right one or the search has failed.
		 */
		if (lowest_vcn && (u8*)next_al_entry >= al_start	    &&
				(u8*)next_al_entry + 6 < al_end		    &&
				(u8*)next_al_entry + le16_to_cpu(
					next_al_entry->length) <= al_end    &&
				sle64_to_cpu(next_al_entry->lowest_vcn) <=
					lowest_vcn			    &&
				next_al_entry->type == al_entry->type	    &&
				next_al_entry->name_length == al_name_len   &&
				ntfs_are_names_equal((ntfschar*)((u8*)
					next_al_entry +
					next_al_entry->name_offset),
					next_al_entry->name_length,
					al_name, al_name_len, CASE_SENSITIVE,
					vol->upcase, vol->upcase_len))
			continue;
		if (MREF_LE(al_entry->mft_reference) == ni->mft_no) {
			if (MSEQNO_LE(al_entry->mft_reference) != ni->seq_no) {
				ntfs_error(vol->sb, "Found stale mft "
						"reference in attribute list "
						"of base inode 0x%lx.%s",
						base_ni->mft_no, es);
				err = -EIO;
				break;
			}
		} else { /* Mft references do not match. */
			/* If there is a mapped record unmap it first. */
			if (ni != base_ni)
				unmap_extent_mft_record(ni);
			/* Do we want the base record back? */
			if (MREF_LE(al_entry->mft_reference) ==
					base_ni->mft_no) {
				ni = ctx->ntfs_ino = base_ni;
				ctx->mrec = ctx->base_mrec;
			} else {
				/* We want an extent record. */
				ctx->mrec = map_extent_mft_record(base_ni,
						le64_to_cpu(
						al_entry->mft_reference), &ni);
				if (IS_ERR(ctx->mrec)) {
					ntfs_error(vol->sb, "Failed to map "
							"extent mft record "
							"0x%lx of base inode "
							"0x%lx.%s",
							MREF_LE(al_entry->
							mft_reference),
							base_ni->mft_no, es);
					err = PTR_ERR(ctx->mrec);
					if (err == -ENOENT)
						err = -EIO;
					/* Cause @ctx to be sanitized below. */
					ni = NULL;
					break;
				}
				ctx->ntfs_ino = ni;
			}
			ctx->attr = (ATTR_RECORD*)((u8*)ctx->mrec +
					le16_to_cpu(ctx->mrec->attrs_offset));
		}
		/*
		 * ctx->vfs_ino, ctx->mrec, and ctx->attr now point to the
		 * mft record containing the attribute represented by the
		 * current al_entry.
		 */
		/*
		 * We could call into ntfs_attr_find() to find the right
		 * attribute in this mft record but this would be less
		 * efficient and not quite accurate as ntfs_attr_find() ignores
		 * the attribute instance numbers for example which become
		 * important when one plays with attribute lists.  Also,
		 * because a proper match has been found in the attribute list
		 * entry above, the comparison can now be optimized.  So it is
		 * worth re-implementing a simplified ntfs_attr_find() here.
		 */
		a = ctx->attr;
		/*
		 * Use a manual loop so we can still use break and continue
		 * with the same meanings as above.
		 */
do_next_attr_loop:
		if ((u8*)a < (u8*)ctx->mrec || (u8*)a > (u8*)ctx->mrec +
				le32_to_cpu(ctx->mrec->bytes_allocated))
			break;
		if (a->type == AT_END)
			break;
		if (!a->length)
			break;
		if (al_entry->instance != a->instance)
			goto do_next_attr;
		/*
		 * If the type and/or the name are mismatched between the
		 * attribute list entry and the attribute record, there is
		 * corruption so we break and return error EIO.
		 */
		if (al_entry->type != a->type)
			break;
		if (!ntfs_are_names_equal((ntfschar*)((u8*)a +
				le16_to_cpu(a->name_offset)), a->name_length,
				al_name, al_name_len, CASE_SENSITIVE,
				vol->upcase, vol->upcase_len))
			break;
		ctx->attr = a;
		/*
		 * If no @val specified or @val specified and it matches, we
		 * have found it!
		 */
		if (!val || (!a->non_resident && le32_to_cpu(
				a->data.resident.value_length) == val_len &&
				!memcmp((u8*)a +
				le16_to_cpu(a->data.resident.value_offset),
				val, val_len))) {
			ntfs_debug("Done, found.");
			return 0;
		}
do_next_attr:
		/* Proceed to the next attribute in the current mft record. */
		a = (ATTR_RECORD*)((u8*)a + le32_to_cpu(a->length));
		goto do_next_attr_loop;
	}
	if (!err) {
		ntfs_error(vol->sb, "Base inode 0x%lx contains corrupt "
				"attribute list attribute.%s", base_ni->mft_no,
				es);
		err = -EIO;
	}
	if (ni != base_ni) {
		if (ni)
			unmap_extent_mft_record(ni);
		ctx->ntfs_ino = base_ni;
		ctx->mrec = ctx->base_mrec;
		ctx->attr = ctx->base_attr;
	}
	if (err != -ENOMEM)
		NVolSetErrors(vol);
	return err;
not_found:
	/*
	 * If we were looking for AT_END, we reset the search context @ctx and
	 * use ntfs_attr_find() to seek to the end of the base mft record.
	 */
	if (type == AT_END) {
		ntfs_attr_reinit_search_ctx(ctx);
		return ntfs_attr_find(AT_END, name, name_len, ic, val, val_len,
				ctx);
	}
	/*
	 * The attribute was not found.  Before we return, we want to ensure
	 * @ctx->mrec and @ctx->attr indicate the position at which the
	 * attribute should be inserted in the base mft record.  Since we also
	 * want to preserve @ctx->al_entry we cannot reinitialize the search
	 * context using ntfs_attr_reinit_search_ctx() as this would set
	 * @ctx->al_entry to NULL.  Thus we do the necessary bits manually (see
	 * ntfs_attr_init_search_ctx() below).  Note, we _only_ preserve
	 * @ctx->al_entry as the remaining fields (base_*) are identical to
	 * their non base_ counterparts and we cannot set @ctx->base_attr
	 * correctly yet as we do not know what @ctx->attr will be set to by
	 * the call to ntfs_attr_find() below.
	 */
	if (ni != base_ni)
		unmap_extent_mft_record(ni);
	ctx->mrec = ctx->base_mrec;
	ctx->attr = (ATTR_RECORD*)((u8*)ctx->mrec +
			le16_to_cpu(ctx->mrec->attrs_offset));
	ctx->is_first = true;
	ctx->ntfs_ino = base_ni;
	ctx->base_ntfs_ino = NULL;
	ctx->base_mrec = NULL;
	ctx->base_attr = NULL;
	/*
	 * In case there are multiple matches in the base mft record, need to
	 * keep enumerating until we get an attribute not found response (or
	 * another error), otherwise we would keep returning the same attribute
	 * over and over again and all programs using us for enumeration would
	 * lock up in a tight loop.
	 */
	do {
		err = ntfs_attr_find(type, name, name_len, ic, val, val_len,
				ctx);
	} while (!err);
	ntfs_debug("Done, not found.");
	return err;
}

/**
 * ntfs_attr_lookup - find an attribute in an ntfs inode
 * @type:	attribute type to find
 * @name:	attribute name to find (optional, i.e. NULL means don't care)
 * @name_len:	attribute name length (only needed if @name present)
 * @ic:		IGNORE_CASE or CASE_SENSITIVE (ignored if @name not present)
 * @lowest_vcn:	lowest vcn to find (optional, non-resident attributes only)
 * @val:	attribute value to find (optional, resident attributes only)
 * @val_len:	attribute value length
 * @ctx:	search context with mft record and attribute to search from
 *
 * Find an attribute in an ntfs inode.  On first search @ctx->ntfs_ino must
 * be the base mft record and @ctx must have been obtained from a call to
 * ntfs_attr_get_search_ctx().
 *
 * This function transparently handles attribute lists and @ctx is used to
 * continue searches where they were left off at.
 *
 * After finishing with the attribute/mft record you need to call
 * ntfs_attr_put_search_ctx() to cleanup the search context (unmapping any
 * mapped inodes, etc).
 *
 * Return 0 if the search was successful and -errno if not.
 *
 * When 0, @ctx->attr is the found attribute and it is in mft record
 * @ctx->mrec.  If an attribute list attribute is present, @ctx->al_entry is
 * the attribute list entry of the found attribute.
 *
 * When -ENOENT, @ctx->attr is the attribute which collates just after the
 * attribute being searched for, i.e. if one wants to add the attribute to the
 * mft record this is the correct place to insert it into.  If an attribute
 * list attribute is present, @ctx->al_entry is the attribute list entry which
 * collates just after the attribute list entry of the attribute being searched
 * for, i.e. if one wants to add the attribute to the mft record this is the
 * correct place to insert its attribute list entry into.
 *
 * When -errno != -ENOENT, an error occurred during the lookup.  @ctx->attr is
 * then undefined and in particular you should not rely on it not changing.
 */
int ntfs_attr_lookup(const ATTR_TYPE type, const ntfschar *name,
		const u32 name_len, const IGNORE_CASE_BOOL ic,
		const VCN lowest_vcn, const u8 *val, const u32 val_len,
		ntfs_attr_search_ctx *ctx)
{
	ntfs_inode *base_ni;

	ntfs_debug("Entering.");
	BUG_ON(IS_ERR(ctx->mrec));
	if (ctx->base_ntfs_ino)
		base_ni = ctx->base_ntfs_ino;
	else
		base_ni = ctx->ntfs_ino;
	/* Sanity check, just for debugging really. */
	BUG_ON(!base_ni);
	if (!NInoAttrList(base_ni) || type == AT_ATTRIBUTE_LIST)
		return ntfs_attr_find(type, name, name_len, ic, val, val_len,
				ctx);
	return ntfs_external_attr_find(type, name, name_len, ic, lowest_vcn,
			val, val_len, ctx);
}

/**
 * ntfs_attr_init_search_ctx - initialize an attribute search context
 * @ctx:	attribute search context to initialize
 * @ni:		ntfs inode with which to initialize the search context
 * @mrec:	mft record with which to initialize the search context
 *
 * Initialize the attribute search context @ctx with @ni and @mrec.
 */
static inline void ntfs_attr_init_search_ctx(ntfs_attr_search_ctx *ctx,
		ntfs_inode *ni, MFT_RECORD *mrec)
{
	*ctx = (ntfs_attr_search_ctx) {
		.mrec = mrec,
		/* Sanity checks are performed elsewhere. */
		.attr = (ATTR_RECORD*)((u8*)mrec +
				le16_to_cpu(mrec->attrs_offset)),
		.is_first = true,
		.ntfs_ino = ni,
	};
}

/**
 * ntfs_attr_reinit_search_ctx - reinitialize an attribute search context
 * @ctx:	attribute search context to reinitialize
 *
 * Reinitialize the attribute search context @ctx, unmapping an associated
 * extent mft record if present, and initialize the search context again.
 *
 * This is used when a search for a new attribute is being started to reset
 * the search context to the beginning.
 */
void ntfs_attr_reinit_search_ctx(ntfs_attr_search_ctx *ctx)
{
	if (likely(!ctx->base_ntfs_ino)) {
		/* No attribute list. */
		ctx->is_first = true;
		/* Sanity checks are performed elsewhere. */
		ctx->attr = (ATTR_RECORD*)((u8*)ctx->mrec +
				le16_to_cpu(ctx->mrec->attrs_offset));
		/*
		 * This needs resetting due to ntfs_external_attr_find() which
		 * can leave it set despite having zeroed ctx->base_ntfs_ino.
		 */
		ctx->al_entry = NULL;
		return;
	} /* Attribute list. */
	if (ctx->ntfs_ino != ctx->base_ntfs_ino)
		unmap_extent_mft_record(ctx->ntfs_ino);
	ntfs_attr_init_search_ctx(ctx, ctx->base_ntfs_ino, ctx->base_mrec);
	return;
}

/**
 * ntfs_attr_get_search_ctx - allocate/initialize a new attribute search context
 * @ni:		ntfs inode with which to initialize the search context
 * @mrec:	mft record with which to initialize the search context
 *
 * Allocate a new attribute search context, initialize it with @ni and @mrec,
 * and return it. Return NULL if allocation failed.
 */
ntfs_attr_search_ctx *ntfs_attr_get_search_ctx(ntfs_inode *ni, MFT_RECORD *mrec)
{
	ntfs_attr_search_ctx *ctx;

	ctx = kmem_cache_alloc(ntfs_attr_ctx_cache, GFP_NOFS);
	if (ctx)
		ntfs_attr_init_search_ctx(ctx, ni, mrec);
	return ctx;
}

/**
 * ntfs_attr_put_search_ctx - release an attribute search context
 * @ctx:	attribute search context to free
 *
 * Release the attribute search context @ctx, unmapping an associated extent
 * mft record if present.
 */
void ntfs_attr_put_search_ctx(ntfs_attr_search_ctx *ctx)
{
	if (ctx->base_ntfs_ino && ctx->ntfs_ino != ctx->base_ntfs_ino)
		unmap_extent_mft_record(ctx->ntfs_ino);
	kmem_cache_free(ntfs_attr_ctx_cache, ctx);
	return;
}

#ifdef NTFS_RW

/**
 * ntfs_attr_find_in_attrdef - find an attribute in the $AttrDef system file
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to find
 *
 * Search for the attribute definition record corresponding to the attribute
 * @type in the $AttrDef system file.
 *
 * Return the attribute type definition record if found and NULL if not found.
 */
static ATTR_DEF *ntfs_attr_find_in_attrdef(const ntfs_volume *vol,
		const ATTR_TYPE type)
{
	ATTR_DEF *ad;

	BUG_ON(!vol->attrdef);
	BUG_ON(!type);
	for (ad = vol->attrdef; (u8*)ad - (u8*)vol->attrdef <
			vol->attrdef_size && ad->type; ++ad) {
		/* We have not found it yet, carry on searching. */
		if (likely(le32_to_cpu(ad->type) < le32_to_cpu(type)))
			continue;
		/* We found the attribute; return it. */
		if (likely(ad->type == type))
			return ad;
		/* We have gone too far already.  No point in continuing. */
		break;
	}
	/* Attribute not found. */
	ntfs_debug("Attribute type 0x%x not found in $AttrDef.",
			le32_to_cpu(type));
	return NULL;
}

/**
 * ntfs_attr_size_bounds_check - check a size of an attribute type for validity
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 * @size:	size which to check
 *
 * Check whether the @size in bytes is valid for an attribute of @type on the
 * ntfs volume @vol.  This information is obtained from $AttrDef system file.
 *
 * Return 0 if valid, -ERANGE if not valid, or -ENOENT if the attribute is not
 * listed in $AttrDef.
 */
int ntfs_attr_size_bounds_check(const ntfs_volume *vol, const ATTR_TYPE type,
		const s64 size)
{
	ATTR_DEF *ad;

	BUG_ON(size < 0);
	/*
	 * $ATTRIBUTE_LIST has a maximum size of 256kiB, but this is not
	 * listed in $AttrDef.
	 */
	if (unlikely(type == AT_ATTRIBUTE_LIST && size > 256 * 1024))
		return -ERANGE;
	/* Get the $AttrDef entry for the attribute @type. */
	ad = ntfs_attr_find_in_attrdef(vol, type);
	if (unlikely(!ad))
		return -ENOENT;
	/* Do the bounds check. */
	if (((sle64_to_cpu(ad->min_size) > 0) &&
			size < sle64_to_cpu(ad->min_size)) ||
			((sle64_to_cpu(ad->max_size) > 0) && size >
			sle64_to_cpu(ad->max_size)))
		return -ERANGE;
	return 0;
}

/**
 * ntfs_attr_can_be_non_resident - check if an attribute can be non-resident
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 *
 * Check whether the attribute of @type on the ntfs volume @vol is allowed to
 * be non-resident.  This information is obtained from $AttrDef system file.
 *
 * Return 0 if the attribute is allowed to be non-resident, -EPERM if not, and
 * -ENOENT if the attribute is not listed in $AttrDef.
 */
int ntfs_attr_can_be_non_resident(const ntfs_volume *vol, const ATTR_TYPE type)
{
	ATTR_DEF *ad;

	/* Find the attribute definition record in $AttrDef. */
	ad = ntfs_attr_find_in_attrdef(vol, type);
	if (unlikely(!ad))
		return -ENOENT;
	/* Check the flags and return the result. */
	if (ad->flags & ATTR_DEF_RESIDENT)
		return -EPERM;
	return 0;
}

/**
 * ntfs_attr_can_be_resident - check if an attribute can be resident
 * @vol:	ntfs volume to which the attribute belongs
 * @type:	attribute type which to check
 *
 * Check whether the attribute of @type on the ntfs volume @vol is allowed to
 * be resident.  This information is derived from our ntfs knowledge and may
 * not be completely accurate, especially when user defined attributes are
 * present.  Basically we allow everything to be resident except for index
 * allocation and $EA attributes.
 *
 * Return 0 if the attribute is allowed to be non-resident and -EPERM if not.
 *
 * Warning: In the system file $MFT the attribute $Bitmap must be non-resident
 *	    otherwise windows will not boot (blue screen of death)!  We cannot
 *	    check for this here as we do not know which inode's $Bitmap is
 *	    being asked about so the caller needs to special case this.
 */
int ntfs_attr_can_be_resident(const ntfs_volume *vol, const ATTR_TYPE type)
{
	if (type == AT_INDEX_ALLOCATION)
		return -EPERM;
	return 0;
}

/**
 * ntfs_attr_record_resize - resize an attribute record
 * @m:		mft record containing attribute record
 * @a:		attribute record to resize
 * @new_size:	new size in bytes to which to resize the attribute record @a
 *
 * Resize the attribute record @a, i.e. the resident part of the attribute, in
 * the mft record @m to @new_size bytes.
 *
 * Return 0 on success and -errno on error.  The following error codes are
 * defined:
 *	-ENOSPC	- Not enough space in the mft record @m to perform the resize.
 *
 * Note: On error, no modifications have been performed whatsoever.
 *
 * Warning: If you make a record smaller without having copied all the data you
 *	    are interested in the data may be overwritten.
 */
int ntfs_attr_record_resize(MFT_RECORD *m, ATTR_RECORD *a, u32 new_size)
{
	ntfs_debug("Entering for new_size %u.", new_size);
	/* Align to 8 bytes if it is not already done. */
	if (new_size & 7)
		new_size = (new_size + 7) & ~7;
	/* If the actual attribute length has changed, move things around. */
	if (new_size != le32_to_cpu(a->length)) {
		u32 new_muse = le32_to_cpu(m->bytes_in_use) -
				le32_to_cpu(a->length) + new_size;
		/* Not enough space in this mft record. */
		if (new_muse > le32_to_cpu(m->bytes_allocated))
			return -ENOSPC;
		/* Move attributes following @a to their new location. */
		memmove((u8*)a + new_size, (u8*)a + le32_to_cpu(a->length),
				le32_to_cpu(m->bytes_in_use) - ((u8*)a -
				(u8*)m) - le32_to_cpu(a->length));
		/* Adjust @m to reflect the change in used space. */
		m->bytes_in_use = cpu_to_le32(new_muse);
		/* Adjust @a to reflect the new size. */
		if (new_size >= offsetof(ATTR_REC, length) + sizeof(a->length))
			a->length = cpu_to_le32(new_size);
	}
	return 0;
}

/**
 * ntfs_resident_attr_value_resize - resize the value of a resident attribute
 * @m:		mft record containing attribute record
 * @a:		attribute record whose value to resize
 * @new_size:	new size in bytes to which to resize the attribute value of @a
 *
 * Resize the value of the attribute @a in the mft record @m to @new_size bytes.
 * If the value is made bigger, the newly allocated space is cleared.
 *
 * Return 0 on success and -errno on error.  The following error codes are
 * defined:
 *	-ENOSPC	- Not enough space in the mft record @m to perform the resize.
 *
 * Note: On error, no modifications have been performed whatsoever.
 *
 * Warning: If you make a record smaller without having copied all the data you
 *	    are interested in the data may be overwritten.
 */
int ntfs_resident_attr_value_resize(MFT_RECORD *m, ATTR_RECORD *a,
		const u32 new_size)
{
	u32 old_size;

	/* Resize the resident part of the attribute record. */
	if (ntfs_attr_record_resize(m, a,
			le16_to_cpu(a->data.resident.value_offset) + new_size))
		return -ENOSPC;
	/*
	 * The resize succeeded!  If we made the attribute value bigger, clear
	 * the area between the old size and @new_size.
	 */
	old_size = le32_to_cpu(a->data.resident.value_length);
	if (new_size > old_size)
		memset((u8*)a + le16_to_cpu(a->data.resident.value_offset) +
				old_size, 0, new_size - old_size);
	/* Finally update the length of the attribute value. */
	a->data.resident.value_length = cpu_to_le32(new_size);
	return 0;
}

/**
 * ntfs_attr_make_non_resident - convert a resident to a non-resident attribute
 * @ni:		ntfs inode describing the attribute to convert
 * @data_size:	size of the resident data to copy to the non-resident attribute
 *
 * Convert the resident ntfs attribute described by the ntfs inode @ni to a
 * non-resident one.
 *
 * @data_size must be equal to the attribute value size.  This is needed since
 * we need to know the size before we can map the mft record and our callers
 * always know it.  The reason we cannot simply read the size from the vfs
 * inode i_size is that this is not necessarily uptodate.  This happens when
 * ntfs_attr_make_non_resident() is called in the ->truncate call path(s).
 *
 * Return 0 on success and -errno on error.  The following error return codes
 * are defined:
 *	-EPERM	- The attribute is not allowed to be non-resident.
 *	-ENOMEM	- Not enough memory.
 *	-ENOSPC	- Not enough disk space.
 *	-EINVAL	- Attribute not defined on the volume.
 *	-EIO	- I/o error or other error.
 * Note that -ENOSPC is also returned in the case that there is not enough
 * space in the mft record to do the conversion.  This can happen when the mft
 * record is already very full.  The caller is responsible for trying to make
 * space in the mft record and trying again.  FIXME: Do we need a separate
 * error return code for this kind of -ENOSPC or is it always worth trying
 * again in case the attribute may then fit in a resident state so no need to
 * make it non-resident at all?  Ho-hum...  (AIA)
 *
 * NOTE to self: No changes in the attribute list are required to move from
 *		 a resident to a non-resident attribute.
 *
 * Locking: - The caller must hold i_mutex on the inode.
 */
int ntfs_attr_make_non_resident(ntfs_inode *ni, const u32 data_size)
{
	s64 new_size;
	struct inode *vi = VFS_I(ni);
	ntfs_volume *vol = ni->vol;
	ntfs_inode *base_ni;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	ntfs_attr_search_ctx *ctx;
	struct page *page;
	runlist_element *rl;
	u8 *kaddr;
	unsigned long flags;
	int mp_size, mp_ofs, name_ofs, arec_size, err, err2;
	u32 attr_size;
	u8 old_res_attr_flags;

	/* Check that the attribute is allowed to be non-resident. */
	err = ntfs_attr_can_be_non_resident(vol, ni->type);
	if (unlikely(err)) {
		if (err == -EPERM)
			ntfs_debug("Attribute is not allowed to be "
					"non-resident.");
		else
			ntfs_debug("Attribute not defined on the NTFS "
					"volume!");
		return err;
	}
	/*
	 * FIXME: Compressed and encrypted attributes are not supported when
	 * writing and we should never have gotten here for them.
	 */
	BUG_ON(NInoCompressed(ni));
	BUG_ON(NInoEncrypted(ni));
	/*
	 * The size needs to be aligned to a cluster boundary for allocation
	 * purposes.
	 */
	new_size = (data_size + vol->cluster_size - 1) &
			~(vol->cluster_size - 1);
	if (new_size > 0) {
		/*
		 * Will need the page later and since the page lock nests
		 * outside all ntfs locks, we need to get the page now.
		 */
		page = find_or_create_page(vi->i_mapping, 0,
				mapping_gfp_mask(vi->i_mapping));
		if (unlikely(!page))
			return -ENOMEM;
		/* Start by allocating clusters to hold the attribute value. */
		rl = ntfs_cluster_alloc(vol, 0, new_size >>
				vol->cluster_size_bits, -1, DATA_ZONE, true);
		if (IS_ERR(rl)) {
			err = PTR_ERR(rl);
			ntfs_debug("Failed to allocate cluster%s, error code "
					"%i.", (new_size >>
					vol->cluster_size_bits) > 1 ? "s" : "",
					err);
			goto page_err_out;
		}
	} else {
		rl = NULL;
		page = NULL;
	}
	/* Determine the size of the mapping pairs array. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl, 0, -1);
	if (unlikely(mp_size < 0)) {
		err = mp_size;
		ntfs_debug("Failed to get size for mapping pairs array, error "
				"code %i.", err);
		goto rl_err_out;
	}
	down_write(&ni->runlist.lock);
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		ctx = NULL;
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			err = -EIO;
		goto err_out;
	}
	m = ctx->mrec;
	a = ctx->attr;
	BUG_ON(NInoNonResident(ni));
	BUG_ON(a->non_resident);
	/*
	 * Calculate new offsets for the name and the mapping pairs array.
	 */
	if (NInoSparse(ni) || NInoCompressed(ni))
		name_ofs = (offsetof(ATTR_REC,
				data.non_resident.compressed_size) +
				sizeof(a->data.non_resident.compressed_size) +
				7) & ~7;
	else
		name_ofs = (offsetof(ATTR_REC,
				data.non_resident.compressed_size) + 7) & ~7;
	mp_ofs = (name_ofs + a->name_length * sizeof(ntfschar) + 7) & ~7;
	/*
	 * Determine the size of the resident part of the now non-resident
	 * attribute record.
	 */
	arec_size = (mp_ofs + mp_size + 7) & ~7;
	/*
	 * If the page is not uptodate bring it uptodate by copying from the
	 * attribute value.
	 */
	attr_size = le32_to_cpu(a->data.resident.value_length);
	BUG_ON(attr_size != data_size);
	if (page && !PageUptodate(page)) {
		kaddr = kmap_atomic(page);
		memcpy(kaddr, (u8*)a +
				le16_to_cpu(a->data.resident.value_offset),
				attr_size);
		memset(kaddr + attr_size, 0, PAGE_CACHE_SIZE - attr_size);
		kunmap_atomic(kaddr);
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	/* Backup the attribute flag. */
	old_res_attr_flags = a->data.resident.flags;
	/* Resize the resident part of the attribute record. */
	err = ntfs_attr_record_resize(m, a, arec_size);
	if (unlikely(err))
		goto err_out;
	/*
	 * Convert the resident part of the attribute record to describe a
	 * non-resident attribute.
	 */
	a->non_resident = 1;
	/* Move the attribute name if it exists and update the offset. */
	if (a->name_length)
		memmove((u8*)a + name_ofs, (u8*)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(ntfschar));
	a->name_offset = cpu_to_le16(name_ofs);
	/* Setup the fields specific to non-resident attributes. */
	a->data.non_resident.lowest_vcn = 0;
	a->data.non_resident.highest_vcn = cpu_to_sle64((new_size - 1) >>
			vol->cluster_size_bits);
	a->data.non_resident.mapping_pairs_offset = cpu_to_le16(mp_ofs);
	memset(&a->data.non_resident.reserved, 0,
			sizeof(a->data.non_resident.reserved));
	a->data.non_resident.allocated_size = cpu_to_sle64(new_size);
	a->data.non_resident.data_size =
			a->data.non_resident.initialized_size =
			cpu_to_sle64(attr_size);
	if (NInoSparse(ni) || NInoCompressed(ni)) {
		a->data.non_resident.compression_unit = 0;
		if (NInoCompressed(ni) || vol->major_ver < 3)
			a->data.non_resident.compression_unit = 4;
		a->data.non_resident.compressed_size =
				a->data.non_resident.allocated_size;
	} else
		a->data.non_resident.compression_unit = 0;
	/* Generate the mapping pairs array into the attribute record. */
	err = ntfs_mapping_pairs_build(vol, (u8*)a + mp_ofs,
			arec_size - mp_ofs, rl, 0, -1, NULL);
	if (unlikely(err)) {
		ntfs_debug("Failed to build mapping pairs, error code %i.",
				err);
		goto undo_err_out;
	}
	/* Setup the in-memory attribute structure to be non-resident. */
	ni->runlist.rl = rl;
	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = new_size;
	if (NInoSparse(ni) || NInoCompressed(ni)) {
		ni->itype.compressed.size = ni->allocated_size;
		if (a->data.non_resident.compression_unit) {
			ni->itype.compressed.block_size = 1U << (a->data.
					non_resident.compression_unit +
					vol->cluster_size_bits);
			ni->itype.compressed.block_size_bits =
					ffs(ni->itype.compressed.block_size) -
					1;
			ni->itype.compressed.block_clusters = 1U <<
					a->data.non_resident.compression_unit;
		} else {
			ni->itype.compressed.block_size = 0;
			ni->itype.compressed.block_size_bits = 0;
			ni->itype.compressed.block_clusters = 0;
		}
		vi->i_blocks = ni->itype.compressed.size >> 9;
	} else
		vi->i_blocks = ni->allocated_size >> 9;
	write_unlock_irqrestore(&ni->size_lock, flags);
	/*
	 * This needs to be last since the address space operations ->readpage
	 * and ->writepage can run concurrently with us as they are not
	 * serialized on i_mutex.  Note, we are not allowed to fail once we flip
	 * this switch, which is another reason to do this last.
	 */
	NInoSetNonResident(ni);
	/* Mark the mft record dirty, so it gets written back. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	up_write(&ni->runlist.lock);
	if (page) {
		set_page_dirty(page);
		unlock_page(page);
		page_cache_release(page);
	}
	ntfs_debug("Done.");
	return 0;
undo_err_out:
	/* Convert the attribute back into a resident attribute. */
	a->non_resident = 0;
	/* Move the attribute name if it exists and update the offset. */
	name_ofs = (offsetof(ATTR_RECORD, data.resident.reserved) +
			sizeof(a->data.resident.reserved) + 7) & ~7;
	if (a->name_length)
		memmove((u8*)a + name_ofs, (u8*)a + le16_to_cpu(a->name_offset),
				a->name_length * sizeof(ntfschar));
	mp_ofs = (name_ofs + a->name_length * sizeof(ntfschar) + 7) & ~7;
	a->name_offset = cpu_to_le16(name_ofs);
	arec_size = (mp_ofs + attr_size + 7) & ~7;
	/* Resize the resident part of the attribute record. */
	err2 = ntfs_attr_record_resize(m, a, arec_size);
	if (unlikely(err2)) {
		/*
		 * This cannot happen (well if memory corruption is at work it
		 * could happen in theory), but deal with it as well as we can.
		 * If the old size is too small, truncate the attribute,
		 * otherwise simply give it a larger allocated size.
		 * FIXME: Should check whether chkdsk complains when the
		 * allocated size is much bigger than the resident value size.
		 */
		arec_size = le32_to_cpu(a->length);
		if ((mp_ofs + attr_size) > arec_size) {
			err2 = attr_size;
			attr_size = arec_size - mp_ofs;
			ntfs_error(vol->sb, "Failed to undo partial resident "
					"to non-resident attribute "
					"conversion.  Truncating inode 0x%lx, "
					"attribute type 0x%x from %i bytes to "
					"%i bytes to maintain metadata "
					"consistency.  THIS MEANS YOU ARE "
					"LOSING %i BYTES DATA FROM THIS %s.",
					vi->i_ino,
					(unsigned)le32_to_cpu(ni->type),
					err2, attr_size, err2 - attr_size,
					((ni->type == AT_DATA) &&
					!ni->name_len) ? "FILE": "ATTRIBUTE");
			write_lock_irqsave(&ni->size_lock, flags);
			ni->initialized_size = attr_size;
			i_size_write(vi, attr_size);
			write_unlock_irqrestore(&ni->size_lock, flags);
		}
	}
	/* Setup the fields specific to resident attributes. */
	a->data.resident.value_length = cpu_to_le32(attr_size);
	a->data.resident.value_offset = cpu_to_le16(mp_ofs);
	a->data.resident.flags = old_res_attr_flags;
	memset(&a->data.resident.reserved, 0,
			sizeof(a->data.resident.reserved));
	/* Copy the data from the page back to the attribute value. */
	if (page) {
		kaddr = kmap_atomic(page);
		memcpy((u8*)a + mp_ofs, kaddr, attr_size);
		kunmap_atomic(kaddr);
	}
	/* Setup the allocated size in the ntfs inode in case it changed. */
	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = arec_size - mp_ofs;
	write_unlock_irqrestore(&ni->size_lock, flags);
	/* Mark the mft record dirty, so it gets written back. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	ni->runlist.rl = NULL;
	up_write(&ni->runlist.lock);
rl_err_out:
	if (rl) {
		if (ntfs_cluster_free_from_rl(vol, rl) < 0) {
			ntfs_error(vol->sb, "Failed to release allocated "
					"cluster(s) in error code path.  Run "
					"chkdsk to recover the lost "
					"cluster(s).");
			NVolSetErrors(vol);
		}
		ntfs_free(rl);
page_err_out:
		unlock_page(page);
		page_cache_release(page);
	}
	if (err == -EINVAL)
		err = -EIO;
	return err;
}

/**
 * ntfs_attr_extend_allocation - extend the allocated space of an attribute
 * @ni:			ntfs inode of the attribute whose allocation to extend
 * @new_alloc_size:	new size in bytes to which to extend the allocation to
 * @new_data_size:	new size in bytes to which to extend the data to
 * @data_start:		beginning of region which is required to be non-sparse
 *
 * Extend the allocated space of an attribute described by the ntfs inode @ni
 * to @new_alloc_size bytes.  If @data_start is -1, the whole extension may be
 * implemented as a hole in the file (as long as both the volume and the ntfs
 * inode @ni have sparse support enabled).  If @data_start is >= 0, then the
 * region between the old allocated size and @data_start - 1 may be made sparse
 * but the regions between @data_start and @new_alloc_size must be backed by
 * actual clusters.
 *
 * If @new_data_size is -1, it is ignored.  If it is >= 0, then the data size
 * of the attribute is extended to @new_data_size.  Note that the i_size of the
 * vfs inode is not updated.  Only the data size in the base attribute record
 * is updated.  The caller has to update i_size separately if this is required.
 * WARNING: It is a BUG() for @new_data_size to be smaller than the old data
 * size as well as for @new_data_size to be greater than @new_alloc_size.
 *
 * For resident attributes this involves resizing the attribute record and if
 * necessary moving it and/or other attributes into extent mft records and/or
 * converting the attribute to a non-resident attribute which in turn involves
 * extending the allocation of a non-resident attribute as described below.
 *
 * For non-resident attributes this involves allocating clusters in the data
 * zone on the volume (except for regions that are being made sparse) and
 * extending the run list to describe the allocated clusters as well as
 * updating the mapping pairs array of the attribute.  This in turn involves
 * resizing the attribute record and if necessary moving it and/or other
 * attributes into extent mft records and/or splitting the attribute record
 * into multiple extent attribute records.
 *
 * Also, the attribute list attribute is updated if present and in some of the
 * above cases (the ones where extent mft records/attributes come into play),
 * an attribute list attribute is created if not already present.
 *
 * Return the new allocated size on success and -errno on error.  In the case
 * that an error is encountered but a partial extension at least up to
 * @data_start (if present) is possible, the allocation is partially extended
 * and this is returned.  This means the caller must check the returned size to
 * determine if the extension was partial.  If @data_start is -1 then partial
 * allocations are not performed.
 *
 * WARNING: Do not call ntfs_attr_extend_allocation() for $MFT/$DATA.
 *
 * Locking: This function takes the runlist lock of @ni for writing as well as
 * locking the mft record of the base ntfs inode.  These locks are maintained
 * throughout execution of the function.  These locks are required so that the
 * attribute can be resized safely and so that it can for example be converted
 * from resident to non-resident safely.
 *
 * TODO: At present attribute list attribute handling is not implemented.
 *
 * TODO: At present it is not safe to call this function for anything other
 * than the $DATA attribute(s) of an uncompressed and unencrypted file.
 */
s64 ntfs_attr_extend_allocation(ntfs_inode *ni, s64 new_alloc_size,
		const s64 new_data_size, const s64 data_start)
{
	VCN vcn;
	s64 ll, allocated_size, start = data_start;
	struct inode *vi = VFS_I(ni);
	ntfs_volume *vol = ni->vol;
	ntfs_inode *base_ni;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	ntfs_attr_search_ctx *ctx;
	runlist_element *rl, *rl2;
	unsigned long flags;
	int err, mp_size;
	u32 attr_len = 0; /* Silence stupid gcc warning. */
	bool mp_rebuilt;

#ifdef DEBUG
	read_lock_irqsave(&ni->size_lock, flags);
	allocated_size = ni->allocated_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	ntfs_debug("Entering for i_ino 0x%lx, attribute type 0x%x, "
			"old_allocated_size 0x%llx, "
			"new_allocated_size 0x%llx, new_data_size 0x%llx, "
			"data_start 0x%llx.", vi->i_ino,
			(unsigned)le32_to_cpu(ni->type),
			(unsigned long long)allocated_size,
			(unsigned long long)new_alloc_size,
			(unsigned long long)new_data_size,
			(unsigned long long)start);
#endif
retry_extend:
	/*
	 * For non-resident attributes, @start and @new_size need to be aligned
	 * to cluster boundaries for allocation purposes.
	 */
	if (NInoNonResident(ni)) {
		if (start > 0)
			start &= ~(s64)vol->cluster_size_mask;
		new_alloc_size = (new_alloc_size + vol->cluster_size - 1) &
				~(s64)vol->cluster_size_mask;
	}
	BUG_ON(new_data_size >= 0 && new_data_size > new_alloc_size);
	/* Check if new size is allowed in $AttrDef. */
	err = ntfs_attr_size_bounds_check(vol, ni->type, new_alloc_size);
	if (unlikely(err)) {
		/* Only emit errors when the write will fail completely. */
		read_lock_irqsave(&ni->size_lock, flags);
		allocated_size = ni->allocated_size;
		read_unlock_irqrestore(&ni->size_lock, flags);
		if (start < 0 || start >= allocated_size) {
			if (err == -ERANGE) {
				ntfs_error(vol->sb, "Cannot extend allocation "
						"of inode 0x%lx, attribute "
						"type 0x%x, because the new "
						"allocation would exceed the "
						"maximum allowed size for "
						"this attribute type.",
						vi->i_ino, (unsigned)
						le32_to_cpu(ni->type));
			} else {
				ntfs_error(vol->sb, "Cannot extend allocation "
						"of inode 0x%lx, attribute "
						"type 0x%x, because this "
						"attribute type is not "
						"defined on the NTFS volume.  "
						"Possible corruption!  You "
						"should run chkdsk!",
						vi->i_ino, (unsigned)
						le32_to_cpu(ni->type));
			}
		}
		/* Translate error code to be POSIX conformant for write(2). */
		if (err == -ERANGE)
			err = -EFBIG;
		else
			err = -EIO;
		return err;
	}
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	/*
	 * We will be modifying both the runlist (if non-resident) and the mft
	 * record so lock them both down.
	 */
	down_write(&ni->runlist.lock);
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		ctx = NULL;
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	read_lock_irqsave(&ni->size_lock, flags);
	allocated_size = ni->allocated_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	/*
	 * If non-resident, seek to the last extent.  If resident, there is
	 * only one extent, so seek to that.
	 */
	vcn = NInoNonResident(ni) ? allocated_size >> vol->cluster_size_bits :
			0;
	/*
	 * Abort if someone did the work whilst we waited for the locks.  If we
	 * just converted the attribute from resident to non-resident it is
	 * likely that exactly this has happened already.  We cannot quite
	 * abort if we need to update the data size.
	 */
	if (unlikely(new_alloc_size <= allocated_size)) {
		ntfs_debug("Allocated size already exceeds requested size.");
		new_alloc_size = allocated_size;
		if (new_data_size < 0)
			goto done;
		/*
		 * We want the first attribute extent so that we can update the
		 * data size.
		 */
		vcn = 0;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, vcn, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			err = -EIO;
		goto err_out;
	}
	m = ctx->mrec;
	a = ctx->attr;
	/* Use goto to reduce indentation. */
	if (a->non_resident)
		goto do_non_resident_extend;
	BUG_ON(NInoNonResident(ni));
	/* The total length of the attribute value. */
	attr_len = le32_to_cpu(a->data.resident.value_length);
	/*
	 * Extend the attribute record to be able to store the new attribute
	 * size.  ntfs_attr_record_resize() will not do anything if the size is
	 * not changing.
	 */
	if (new_alloc_size < vol->mft_record_size &&
			!ntfs_attr_record_resize(m, a,
			le16_to_cpu(a->data.resident.value_offset) +
			new_alloc_size)) {
		/* The resize succeeded! */
		write_lock_irqsave(&ni->size_lock, flags);
		ni->allocated_size = le32_to_cpu(a->length) -
				le16_to_cpu(a->data.resident.value_offset);
		write_unlock_irqrestore(&ni->size_lock, flags);
		if (new_data_size >= 0) {
			BUG_ON(new_data_size < attr_len);
			a->data.resident.value_length =
					cpu_to_le32((u32)new_data_size);
		}
		goto flush_done;
	}
	/*
	 * We have to drop all the locks so we can call
	 * ntfs_attr_make_non_resident().  This could be optimised by try-
	 * locking the first page cache page and only if that fails dropping
	 * the locks, locking the page, and redoing all the locking and
	 * lookups.  While this would be a huge optimisation, it is not worth
	 * it as this is definitely a slow code path.
	 */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	up_write(&ni->runlist.lock);
	/*
	 * Not enough space in the mft record, try to make the attribute
	 * non-resident and if successful restart the extension process.
	 */
	err = ntfs_attr_make_non_resident(ni, attr_len);
	if (likely(!err))
		goto retry_extend;
	/*
	 * Could not make non-resident.  If this is due to this not being
	 * permitted for this attribute type or there not being enough space,
	 * try to make other attributes non-resident.  Otherwise fail.
	 */
	if (unlikely(err != -EPERM && err != -ENOSPC)) {
		/* Only emit errors when the write will fail completely. */
		read_lock_irqsave(&ni->size_lock, flags);
		allocated_size = ni->allocated_size;
		read_unlock_irqrestore(&ni->size_lock, flags);
		if (start < 0 || start >= allocated_size)
			ntfs_error(vol->sb, "Cannot extend allocation of "
					"inode 0x%lx, attribute type 0x%x, "
					"because the conversion from resident "
					"to non-resident attribute failed "
					"with error code %i.", vi->i_ino,
					(unsigned)le32_to_cpu(ni->type), err);
		if (err != -ENOMEM)
			err = -EIO;
		goto conv_err_out;
	}
	/* TODO: Not implemented from here, abort. */
	read_lock_irqsave(&ni->size_lock, flags);
	allocated_size = ni->allocated_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (start < 0 || start >= allocated_size) {
		if (err == -ENOSPC)
			ntfs_error(vol->sb, "Not enough space in the mft "
					"record/on disk for the non-resident "
					"attribute value.  This case is not "
					"implemented yet.");
		else /* if (err == -EPERM) */
			ntfs_error(vol->sb, "This attribute type may not be "
					"non-resident.  This case is not "
					"implemented yet.");
	}
	err = -EOPNOTSUPP;
	goto conv_err_out;
#if 0
	// TODO: Attempt to make other attributes non-resident.
	if (!err)
		goto do_resident_extend;
	/*
	 * Both the attribute list attribute and the standard information
	 * attribute must remain in the base inode.  Thus, if this is one of
	 * these attributes, we have to try to move other attributes out into
	 * extent mft records instead.
	 */
	if (ni->type == AT_ATTRIBUTE_LIST ||
			ni->type == AT_STANDARD_INFORMATION) {
		// TODO: Attempt to move other attributes into extent mft
		// records.
		err = -EOPNOTSUPP;
		if (!err)
			goto do_resident_extend;
		goto err_out;
	}
	// TODO: Attempt to move this attribute to an extent mft record, but
	// only if it is not already the only attribute in an mft record in
	// which case there would be nothing to gain.
	err = -EOPNOTSUPP;
	if (!err)
		goto do_resident_extend;
	/* There is nothing we can do to make enough space. )-: */
	goto err_out;
#endif
do_non_resident_extend:
	BUG_ON(!NInoNonResident(ni));
	if (new_alloc_size == allocated_size) {
		BUG_ON(vcn);
		goto alloc_done;
	}
	/*
	 * If the data starts after the end of the old allocation, this is a
	 * $DATA attribute and sparse attributes are enabled on the volume and
	 * for this inode, then create a sparse region between the old
	 * allocated size and the start of the data.  Otherwise simply proceed
	 * with filling the whole space between the old allocated size and the
	 * new allocated size with clusters.
	 */
	if ((start >= 0 && start <= allocated_size) || ni->type != AT_DATA ||
			!NVolSparseEnabled(vol) || NInoSparseDisabled(ni))
		goto skip_sparse;
	// TODO: This is not implemented yet.  We just fill in with real
	// clusters for now...
	ntfs_debug("Inserting holes is not-implemented yet.  Falling back to "
			"allocating real clusters instead.");
skip_sparse:
	rl = ni->runlist.rl;
	if (likely(rl)) {
		/* Seek to the end of the runlist. */
		while (rl->length)
			rl++;
	}
	/* If this attribute extent is not mapped, map it now. */
	if (unlikely(!rl || rl->lcn == LCN_RL_NOT_MAPPED ||
			(rl->lcn == LCN_ENOENT && rl > ni->runlist.rl &&
			(rl-1)->lcn == LCN_RL_NOT_MAPPED))) {
		if (!rl && !allocated_size)
			goto first_alloc;
		rl = ntfs_mapping_pairs_decompress(vol, a, ni->runlist.rl);
		if (IS_ERR(rl)) {
			err = PTR_ERR(rl);
			if (start < 0 || start >= allocated_size)
				ntfs_error(vol->sb, "Cannot extend allocation "
						"of inode 0x%lx, attribute "
						"type 0x%x, because the "
						"mapping of a runlist "
						"fragment failed with error "
						"code %i.", vi->i_ino,
						(unsigned)le32_to_cpu(ni->type),
						err);
			if (err != -ENOMEM)
				err = -EIO;
			goto err_out;
		}
		ni->runlist.rl = rl;
		/* Seek to the end of the runlist. */
		while (rl->length)
			rl++;
	}
	/*
	 * We now know the runlist of the last extent is mapped and @rl is at
	 * the end of the runlist.  We want to begin allocating clusters
	 * starting at the last allocated cluster to reduce fragmentation.  If
	 * there are no valid LCNs in the attribute we let the cluster
	 * allocator choose the starting cluster.
	 */
	/* If the last LCN is a hole or simillar seek back to last real LCN. */
	while (rl->lcn < 0 && rl > ni->runlist.rl)
		rl--;
first_alloc:
	// FIXME: Need to implement partial allocations so at least part of the
	// write can be performed when start >= 0.  (Needed for POSIX write(2)
	// conformance.)
	rl2 = ntfs_cluster_alloc(vol, allocated_size >> vol->cluster_size_bits,
			(new_alloc_size - allocated_size) >>
			vol->cluster_size_bits, (rl && (rl->lcn >= 0)) ?
			rl->lcn + rl->length : -1, DATA_ZONE, true);
	if (IS_ERR(rl2)) {
		err = PTR_ERR(rl2);
		if (start < 0 || start >= allocated_size)
			ntfs_error(vol->sb, "Cannot extend allocation of "
					"inode 0x%lx, attribute type 0x%x, "
					"because the allocation of clusters "
					"failed with error code %i.", vi->i_ino,
					(unsigned)le32_to_cpu(ni->type), err);
		if (err != -ENOMEM && err != -ENOSPC)
			err = -EIO;
		goto err_out;
	}
	rl = ntfs_runlists_merge(ni->runlist.rl, rl2);
	if (IS_ERR(rl)) {
		err = PTR_ERR(rl);
		if (start < 0 || start >= allocated_size)
			ntfs_error(vol->sb, "Cannot extend allocation of "
					"inode 0x%lx, attribute type 0x%x, "
					"because the runlist merge failed "
					"with error code %i.", vi->i_ino,
					(unsigned)le32_to_cpu(ni->type), err);
		if (err != -ENOMEM)
			err = -EIO;
		if (ntfs_cluster_free_from_rl(vol, rl2)) {
			ntfs_error(vol->sb, "Failed to release allocated "
					"cluster(s) in error code path.  Run "
					"chkdsk to recover the lost "
					"cluster(s).");
			NVolSetErrors(vol);
		}
		ntfs_free(rl2);
		goto err_out;
	}
	ni->runlist.rl = rl;
	ntfs_debug("Allocated 0x%llx clusters.", (long long)(new_alloc_size -
			allocated_size) >> vol->cluster_size_bits);
	/* Find the runlist element with which the attribute extent starts. */
	ll = sle64_to_cpu(a->data.non_resident.lowest_vcn);
	rl2 = ntfs_rl_find_vcn_nolock(rl, ll);
	BUG_ON(!rl2);
	BUG_ON(!rl2->length);
	BUG_ON(rl2->lcn < LCN_HOLE);
	mp_rebuilt = false;
	/* Get the size for the new mapping pairs array for this extent. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl2, ll, -1);
	if (unlikely(mp_size <= 0)) {
		err = mp_size;
		if (start < 0 || start >= allocated_size)
			ntfs_error(vol->sb, "Cannot extend allocation of "
					"inode 0x%lx, attribute type 0x%x, "
					"because determining the size for the "
					"mapping pairs failed with error code "
					"%i.", vi->i_ino,
					(unsigned)le32_to_cpu(ni->type), err);
		err = -EIO;
		goto undo_alloc;
	}
	/* Extend the attribute record to fit the bigger mapping pairs array. */
	attr_len = le32_to_cpu(a->length);
	err = ntfs_attr_record_resize(m, a, mp_size +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset));
	if (unlikely(err)) {
		BUG_ON(err != -ENOSPC);
		// TODO: Deal with this by moving this extent to a new mft
		// record or by starting a new extent in a new mft record,
		// possibly by extending this extent partially and filling it
		// and creating a new extent for the remainder, or by making
		// other attributes non-resident and/or by moving other
		// attributes out of this mft record.
		if (start < 0 || start >= allocated_size)
			ntfs_error(vol->sb, "Not enough space in the mft "
					"record for the extended attribute "
					"record.  This case is not "
					"implemented yet.");
		err = -EOPNOTSUPP;
		goto undo_alloc;
	}
	mp_rebuilt = true;
	/* Generate the mapping pairs array directly into the attr record. */
	err = ntfs_mapping_pairs_build(vol, (u8*)a +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset),
			mp_size, rl2, ll, -1, NULL);
	if (unlikely(err)) {
		if (start < 0 || start >= allocated_size)
			ntfs_error(vol->sb, "Cannot extend allocation of "
					"inode 0x%lx, attribute type 0x%x, "
					"because building the mapping pairs "
					"failed with error code %i.", vi->i_ino,
					(unsigned)le32_to_cpu(ni->type), err);
		err = -EIO;
		goto undo_alloc;
	}
	/* Update the highest_vcn. */
	a->data.non_resident.highest_vcn = cpu_to_sle64((new_alloc_size >>
			vol->cluster_size_bits) - 1);
	/*
	 * We now have extended the allocated size of the attribute.  Reflect
	 * this in the ntfs_inode structure and the attribute record.
	 */
	if (a->data.non_resident.lowest_vcn) {
		/*
		 * We are not in the first attribute extent, switch to it, but
		 * first ensure the changes will make it to disk later.
		 */
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
		ntfs_attr_reinit_search_ctx(ctx);
		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, 0, NULL, 0, ctx);
		if (unlikely(err))
			goto restore_undo_alloc;
		/* @m is not used any more so no need to set it. */
		a = ctx->attr;
	}
	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = new_alloc_size;
	a->data.non_resident.allocated_size = cpu_to_sle64(new_alloc_size);
	/*
	 * FIXME: This would fail if @ni is a directory, $MFT, or an index,
	 * since those can have sparse/compressed set.  For example can be
	 * set compressed even though it is not compressed itself and in that
	 * case the bit means that files are to be created compressed in the
	 * directory...  At present this is ok as this code is only called for
	 * regular files, and only for their $DATA attribute(s).
	 * FIXME: The calculation is wrong if we created a hole above.  For now
	 * it does not matter as we never create holes.
	 */
	if (NInoSparse(ni) || NInoCompressed(ni)) {
		ni->itype.compressed.size += new_alloc_size - allocated_size;
		a->data.non_resident.compressed_size =
				cpu_to_sle64(ni->itype.compressed.size);
		vi->i_blocks = ni->itype.compressed.size >> 9;
	} else
		vi->i_blocks = new_alloc_size >> 9;
	write_unlock_irqrestore(&ni->size_lock, flags);
alloc_done:
	if (new_data_size >= 0) {
		BUG_ON(new_data_size <
				sle64_to_cpu(a->data.non_resident.data_size));
		a->data.non_resident.data_size = cpu_to_sle64(new_data_size);
	}
flush_done:
	/* Ensure the changes make it to disk. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
done:
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	up_write(&ni->runlist.lock);
	ntfs_debug("Done, new_allocated_size 0x%llx.",
			(unsigned long long)new_alloc_size);
	return new_alloc_size;
restore_undo_alloc:
	if (start < 0 || start >= allocated_size)
		ntfs_error(vol->sb, "Cannot complete extension of allocation "
				"of inode 0x%lx, attribute type 0x%x, because "
				"lookup of first attribute extent failed with "
				"error code %i.", vi->i_ino,
				(unsigned)le32_to_cpu(ni->type), err);
	if (err == -ENOENT)
		err = -EIO;
	ntfs_attr_reinit_search_ctx(ctx);
	if (ntfs_attr_lookup(ni->type, ni->name, ni->name_len, CASE_SENSITIVE,
			allocated_size >> vol->cluster_size_bits, NULL, 0,
			ctx)) {
		ntfs_error(vol->sb, "Failed to find last attribute extent of "
				"attribute in error code path.  Run chkdsk to "
				"recover.");
		write_lock_irqsave(&ni->size_lock, flags);
		ni->allocated_size = new_alloc_size;
		/*
		 * FIXME: This would fail if @ni is a directory...  See above.
		 * FIXME: The calculation is wrong if we created a hole above.
		 * For now it does not matter as we never create holes.
		 */
		if (NInoSparse(ni) || NInoCompressed(ni)) {
			ni->itype.compressed.size += new_alloc_size -
					allocated_size;
			vi->i_blocks = ni->itype.compressed.size >> 9;
		} else
			vi->i_blocks = new_alloc_size >> 9;
		write_unlock_irqrestore(&ni->size_lock, flags);
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(base_ni);
		up_write(&ni->runlist.lock);
		/*
		 * The only thing that is now wrong is the allocated size of the
		 * base attribute extent which chkdsk should be able to fix.
		 */
		NVolSetErrors(vol);
		return err;
	}
	ctx->attr->data.non_resident.highest_vcn = cpu_to_sle64(
			(allocated_size >> vol->cluster_size_bits) - 1);
undo_alloc:
	ll = allocated_size >> vol->cluster_size_bits;
	if (ntfs_cluster_free(ni, ll, -1, ctx) < 0) {
		ntfs_error(vol->sb, "Failed to release allocated cluster(s) "
				"in error code path.  Run chkdsk to recover "
				"the lost cluster(s).");
		NVolSetErrors(vol);
	}
	m = ctx->mrec;
	a = ctx->attr;
	/*
	 * If the runlist truncation fails and/or the search context is no
	 * longer valid, we cannot resize the attribute record or build the
	 * mapping pairs array thus we mark the inode bad so that no access to
	 * the freed clusters can happen.
	 */
	if (ntfs_rl_truncate_nolock(vol, &ni->runlist, ll) || IS_ERR(m)) {
		ntfs_error(vol->sb, "Failed to %s in error code path.  Run "
				"chkdsk to recover.", IS_ERR(m) ?
				"restore attribute search context" :
				"truncate attribute runlist");
		NVolSetErrors(vol);
	} else if (mp_rebuilt) {
		if (ntfs_attr_record_resize(m, a, attr_len)) {
			ntfs_error(vol->sb, "Failed to restore attribute "
					"record in error code path.  Run "
					"chkdsk to recover.");
			NVolSetErrors(vol);
		} else /* if (success) */ {
			if (ntfs_mapping_pairs_build(vol, (u8*)a + le16_to_cpu(
					a->data.non_resident.
					mapping_pairs_offset), attr_len -
					le16_to_cpu(a->data.non_resident.
					mapping_pairs_offset), rl2, ll, -1,
					NULL)) {
				ntfs_error(vol->sb, "Failed to restore "
						"mapping pairs array in error "
						"code path.  Run chkdsk to "
						"recover.");
				NVolSetErrors(vol);
			}
			flush_dcache_mft_record_page(ctx->ntfs_ino);
			mark_mft_record_dirty(ctx->ntfs_ino);
		}
	}
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	up_write(&ni->runlist.lock);
conv_err_out:
	ntfs_debug("Failed.  Returning error code %i.", err);
	return err;
}

/**
 * ntfs_attr_set - fill (a part of) an attribute with a byte
 * @ni:		ntfs inode describing the attribute to fill
 * @ofs:	offset inside the attribute at which to start to fill
 * @cnt:	number of bytes to fill
 * @val:	the unsigned 8-bit value with which to fill the attribute
 *
 * Fill @cnt bytes of the attribute described by the ntfs inode @ni starting at
 * byte offset @ofs inside the attribute with the constant byte @val.
 *
 * This function is effectively like memset() applied to an ntfs attribute.
 * Note thie function actually only operates on the page cache pages belonging
 * to the ntfs attribute and it marks them dirty after doing the memset().
 * Thus it relies on the vm dirty page write code paths to cause the modified
 * pages to be written to the mft record/disk.
 *
 * Return 0 on success and -errno on error.  An error code of -ESPIPE means
 * that @ofs + @cnt were outside the end of the attribute and no write was
 * performed.
 */
int ntfs_attr_set(ntfs_inode *ni, const s64 ofs, const s64 cnt, const u8 val)
{
	ntfs_volume *vol = ni->vol;
	struct address_space *mapping;
	struct page *page;
	u8 *kaddr;
	pgoff_t idx, end;
	unsigned start_ofs, end_ofs, size;

	ntfs_debug("Entering for ofs 0x%llx, cnt 0x%llx, val 0x%hx.",
			(long long)ofs, (long long)cnt, val);
	BUG_ON(ofs < 0);
	BUG_ON(cnt < 0);
	if (!cnt)
		goto done;
	/*
	 * FIXME: Compressed and encrypted attributes are not supported when
	 * writing and we should never have gotten here for them.
	 */
	BUG_ON(NInoCompressed(ni));
	BUG_ON(NInoEncrypted(ni));
	mapping = VFS_I(ni)->i_mapping;
	/* Work out the starting index and page offset. */
	idx = ofs >> PAGE_CACHE_SHIFT;
	start_ofs = ofs & ~PAGE_CACHE_MASK;
	/* Work out the ending index and page offset. */
	end = ofs + cnt;
	end_ofs = end & ~PAGE_CACHE_MASK;
	/* If the end is outside the inode size return -ESPIPE. */
	if (unlikely(end > i_size_read(VFS_I(ni)))) {
		ntfs_error(vol->sb, "Request exceeds end of attribute.");
		return -ESPIPE;
	}
	end >>= PAGE_CACHE_SHIFT;
	/* If there is a first partial page, need to do it the slow way. */
	if (start_ofs) {
		page = read_mapping_page(mapping, idx, NULL);
		if (IS_ERR(page)) {
			ntfs_error(vol->sb, "Failed to read first partial "
					"page (error, index 0x%lx).", idx);
			return PTR_ERR(page);
		}
		/*
		 * If the last page is the same as the first page, need to
		 * limit the write to the end offset.
		 */
		size = PAGE_CACHE_SIZE;
		if (idx == end)
			size = end_ofs;
		kaddr = kmap_atomic(page);
		memset(kaddr + start_ofs, val, size - start_ofs);
		flush_dcache_page(page);
		kunmap_atomic(kaddr);
		set_page_dirty(page);
		page_cache_release(page);
		balance_dirty_pages_ratelimited(mapping);
		cond_resched();
		if (idx == end)
			goto done;
		idx++;
	}
	/* Do the whole pages the fast way. */
	for (; idx < end; idx++) {
		/* Find or create the current page.  (The page is locked.) */
		page = grab_cache_page(mapping, idx);
		if (unlikely(!page)) {
			ntfs_error(vol->sb, "Insufficient memory to grab "
					"page (index 0x%lx).", idx);
			return -ENOMEM;
		}
		kaddr = kmap_atomic(page);
		memset(kaddr, val, PAGE_CACHE_SIZE);
		flush_dcache_page(page);
		kunmap_atomic(kaddr);
		/*
		 * If the page has buffers, mark them uptodate since buffer
		 * state and not page state is definitive in 2.6 kernels.
		 */
		if (page_has_buffers(page)) {
			struct buffer_head *bh, *head;

			bh = head = page_buffers(page);
			do {
				set_buffer_uptodate(bh);
			} while ((bh = bh->b_this_page) != head);
		}
		/* Now that buffers are uptodate, set the page uptodate, too. */
		SetPageUptodate(page);
		/*
		 * Set the page and all its buffers dirty and mark the inode
		 * dirty, too.  The VM will write the page later on.
		 */
		set_page_dirty(page);
		/* Finally unlock and release the page. */
		unlock_page(page);
		page_cache_release(page);
		balance_dirty_pages_ratelimited(mapping);
		cond_resched();
	}
	/* If there is a last partial page, need to do it the slow way. */
	if (end_ofs) {
		page = read_mapping_page(mapping, idx, NULL);
		if (IS_ERR(page)) {
			ntfs_error(vol->sb, "Failed to read last partial page "
					"(error, index 0x%lx).", idx);
			return PTR_ERR(page);
		}
		kaddr = kmap_atomic(page);
		memset(kaddr, val, end_ofs);
		flush_dcache_page(page);
		kunmap_atomic(kaddr);
		set_page_dirty(page);
		page_cache_release(page);
		balance_dirty_pages_ratelimited(mapping);
		cond_resched();
	}
done:
	ntfs_debug("Done.");
	return 0;
}

#endif /* NTFS_RW */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/attrib.c */
/************************************************************/
/*
 * collate.c - NTFS kernel collation handling.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "collate.h"
// #include "debug.h"
// #include "ntfs.h"
#include "../../inc/__fss.h"

static int ntfs_collate_binary(ntfs_volume *vol,
		const void *data1, const int data1_len,
		const void *data2, const int data2_len)
{
	int rc;

	ntfs_debug("Entering.");
	rc = memcmp(data1, data2, min(data1_len, data2_len));
	if (!rc && (data1_len != data2_len)) {
		if (data1_len < data2_len)
			rc = -1;
		else
			rc = 1;
	}
	ntfs_debug("Done, returning %i", rc);
	return rc;
}

static int ntfs_collate_ntofs_ulong(ntfs_volume *vol,
		const void *data1, const int data1_len,
		const void *data2, const int data2_len)
{
	int rc;
	u32 d1, d2;

	ntfs_debug("Entering.");
	// FIXME:  We don't really want to bug here.
	BUG_ON(data1_len != data2_len);
	BUG_ON(data1_len != 4);
	d1 = le32_to_cpup(data1);
	d2 = le32_to_cpup(data2);
	if (d1 < d2)
		rc = -1;
	else {
		if (d1 == d2)
			rc = 0;
		else
			rc = 1;
	}
	ntfs_debug("Done, returning %i", rc);
	return rc;
}

typedef int (*ntfs_collate_func_t)(ntfs_volume *, const void *, const int,
		const void *, const int);

static ntfs_collate_func_t ntfs_do_collate0x0[3] = {
	ntfs_collate_binary,
	NULL/*ntfs_collate_file_name*/,
	NULL/*ntfs_collate_unicode_string*/,
};

static ntfs_collate_func_t ntfs_do_collate0x1[4] = {
	ntfs_collate_ntofs_ulong,
	NULL/*ntfs_collate_ntofs_sid*/,
	NULL/*ntfs_collate_ntofs_security_hash*/,
	NULL/*ntfs_collate_ntofs_ulongs*/,
};

/**
 * ntfs_collate - collate two data items using a specified collation rule
 * @vol:	ntfs volume to which the data items belong
 * @cr:		collation rule to use when comparing the items
 * @data1:	first data item to collate
 * @data1_len:	length in bytes of @data1
 * @data2:	second data item to collate
 * @data2_len:	length in bytes of @data2
 *
 * Collate the two data items @data1 and @data2 using the collation rule @cr
 * and return -1, 0, ir 1 if @data1 is found, respectively, to collate before,
 * to match, or to collate after @data2.
 *
 * For speed we use the collation rule @cr as an index into two tables of
 * function pointers to call the appropriate collation function.
 */
int ntfs_collate(ntfs_volume *vol, COLLATION_RULE cr,
		const void *data1, const int data1_len,
		const void *data2, const int data2_len) {
	int i;

	ntfs_debug("Entering.");
	/*
	 * FIXME:  At the moment we only support COLLATION_BINARY and
	 * COLLATION_NTOFS_ULONG, so we BUG() for everything else for now.
	 */
	BUG_ON(cr != COLLATION_BINARY && cr != COLLATION_NTOFS_ULONG);
	i = le32_to_cpu(cr);
	BUG_ON(i < 0);
	if (i <= 0x02)
		return ntfs_do_collate0x0[i](vol, data1, data1_len,
				data2, data2_len);
	BUG_ON(i < 0x10);
	i -= 0x10;
	if (likely(i <= 3))
		return ntfs_do_collate0x1[i](vol, data1, data1_len,
				data2, data2_len);
	BUG();
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/collate.c */
/************************************************************/
/**
 * compress.c - NTFS kernel compressed attributes handling.
 *		Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2004 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include <linux/fs.h>
// #include <linux/buffer_head.h>
#include <linux/blkdev.h>
#include <linux/vmalloc.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

// #include "attrib.h"
// #include "inode.h"
// #include "debug.h"
// #include "ntfs.h"

/**
 * ntfs_compression_constants - enum of constants used in the compression code
 */
typedef enum {
	/* Token types and access mask. */
	NTFS_SYMBOL_TOKEN	=	0,
	NTFS_PHRASE_TOKEN	=	1,
	NTFS_TOKEN_MASK		=	1,

	/* Compression sub-block constants. */
	NTFS_SB_SIZE_MASK	=	0x0fff,
	NTFS_SB_SIZE		=	0x1000,
	NTFS_SB_IS_COMPRESSED	=	0x8000,

	/*
	 * The maximum compression block size is by definition 16 * the cluster
	 * size, with the maximum supported cluster size being 4kiB. Thus the
	 * maximum compression buffer size is 64kiB, so we use this when
	 * initializing the compression buffer.
	 */
	NTFS_MAX_CB_SIZE	= 64 * 1024,
} ntfs_compression_constants;

/**
 * ntfs_compression_buffer - one buffer for the decompression engine
 */
static u8 *ntfs_compression_buffer;

/**
 * ntfs_cb_lock - spinlock which protects ntfs_compression_buffer
 */
static DEFINE_SPINLOCK(ntfs_cb_lock);

/**
 * allocate_compression_buffers - allocate the decompression buffers
 *
 * Caller has to hold the ntfs_lock mutex.
 *
 * Return 0 on success or -ENOMEM if the allocations failed.
 */
int allocate_compression_buffers(void)
{
	BUG_ON(ntfs_compression_buffer);

	ntfs_compression_buffer = vmalloc(NTFS_MAX_CB_SIZE);
	if (!ntfs_compression_buffer)
		return -ENOMEM;
	return 0;
}

/**
 * free_compression_buffers - free the decompression buffers
 *
 * Caller has to hold the ntfs_lock mutex.
 */
void free_compression_buffers(void)
{
	BUG_ON(!ntfs_compression_buffer);
	vfree(ntfs_compression_buffer);
	ntfs_compression_buffer = NULL;
}

/**
 * zero_partial_compressed_page - zero out of bounds compressed page region
 */
static void zero_partial_compressed_page(struct page *page,
		const s64 initialized_size)
{
	u8 *kp = page_address(page);
	unsigned int kp_ofs;

	ntfs_debug("Zeroing page region outside initialized size.");
	if (((s64)page->index << PAGE_CACHE_SHIFT) >= initialized_size) {
		/*
		 * FIXME: Using clear_page() will become wrong when we get
		 * PAGE_CACHE_SIZE != PAGE_SIZE but for now there is no problem.
		 */
		clear_page(kp);
		return;
	}
	kp_ofs = initialized_size & ~PAGE_CACHE_MASK;
	memset(kp + kp_ofs, 0, PAGE_CACHE_SIZE - kp_ofs);
	return;
}

/**
 * handle_bounds_compressed_page - test for&handle out of bounds compressed page
 */
static inline void handle_bounds_compressed_page(struct page *page,
		const loff_t i_size, const s64 initialized_size)
{
	if ((page->index >= (initialized_size >> PAGE_CACHE_SHIFT)) &&
			(initialized_size < i_size))
		zero_partial_compressed_page(page, initialized_size);
	return;
}

/**
 * ntfs_decompress - decompress a compression block into an array of pages
 * @dest_pages:		destination array of pages
 * @dest_index:		current index into @dest_pages (IN/OUT)
 * @dest_ofs:		current offset within @dest_pages[@dest_index] (IN/OUT)
 * @dest_max_index:	maximum index into @dest_pages (IN)
 * @dest_max_ofs:	maximum offset within @dest_pages[@dest_max_index] (IN)
 * @xpage:		the target page (-1 if none) (IN)
 * @xpage_done:		set to 1 if xpage was completed successfully (IN/OUT)
 * @cb_start:		compression block to decompress (IN)
 * @cb_size:		size of compression block @cb_start in bytes (IN)
 * @i_size:		file size when we started the read (IN)
 * @initialized_size:	initialized file size when we started the read (IN)
 *
 * The caller must have disabled preemption. ntfs_decompress() reenables it when
 * the critical section is finished.
 *
 * This decompresses the compression block @cb_start into the array of
 * destination pages @dest_pages starting at index @dest_index into @dest_pages
 * and at offset @dest_pos into the page @dest_pages[@dest_index].
 *
 * When the page @dest_pages[@xpage] is completed, @xpage_done is set to 1.
 * If xpage is -1 or @xpage has not been completed, @xpage_done is not modified.
 *
 * @cb_start is a pointer to the compression block which needs decompressing
 * and @cb_size is the size of @cb_start in bytes (8-64kiB).
 *
 * Return 0 if success or -EOVERFLOW on error in the compressed stream.
 * @xpage_done indicates whether the target page (@dest_pages[@xpage]) was
 * completed during the decompression of the compression block (@cb_start).
 *
 * Warning: This function *REQUIRES* PAGE_CACHE_SIZE >= 4096 or it will blow up
 * unpredicatbly! You have been warned!
 *
 * Note to hackers: This function may not sleep until it has finished accessing
 * the compression block @cb_start as it is a per-CPU buffer.
 */
static int ntfs_decompress(struct page *dest_pages[], int *dest_index,
		int *dest_ofs, const int dest_max_index, const int dest_max_ofs,
		const int xpage, char *xpage_done, u8 *const cb_start,
		const u32 cb_size, const loff_t i_size,
		const s64 initialized_size)
{
	/*
	 * Pointers into the compressed data, i.e. the compression block (cb),
	 * and the therein contained sub-blocks (sb).
	 */
	u8 *cb_end = cb_start + cb_size; /* End of cb. */
	u8 *cb = cb_start;	/* Current position in cb. */
	u8 *cb_sb_start = cb;	/* Beginning of the current sb in the cb. */
	u8 *cb_sb_end;		/* End of current sb / beginning of next sb. */

	/* Variables for uncompressed data / destination. */
	struct page *dp;	/* Current destination page being worked on. */
	u8 *dp_addr;		/* Current pointer into dp. */
	u8 *dp_sb_start;	/* Start of current sub-block in dp. */
	u8 *dp_sb_end;		/* End of current sb in dp (dp_sb_start +
				   NTFS_SB_SIZE). */
	u16 do_sb_start;	/* @dest_ofs when starting this sub-block. */
	u16 do_sb_end;		/* @dest_ofs of end of this sb (do_sb_start +
				   NTFS_SB_SIZE). */

	/* Variables for tag and token parsing. */
	u8 tag;			/* Current tag. */
	int token;		/* Loop counter for the eight tokens in tag. */

	/* Need this because we can't sleep, so need two stages. */
	int completed_pages[dest_max_index - *dest_index + 1];
	int nr_completed_pages = 0;

	/* Default error code. */
	int err = -EOVERFLOW;

	ntfs_debug("Entering, cb_size = 0x%x.", cb_size);
do_next_sb:
	ntfs_debug("Beginning sub-block at offset = 0x%zx in the cb.",
			cb - cb_start);
	/*
	 * Have we reached the end of the compression block or the end of the
	 * decompressed data?  The latter can happen for example if the current
	 * position in the compression block is one byte before its end so the
	 * first two checks do not detect it.
	 */
	if (cb == cb_end || !le16_to_cpup((le16*)cb) ||
			(*dest_index == dest_max_index &&
			*dest_ofs == dest_max_ofs)) {
		int i;

		ntfs_debug("Completed. Returning success (0).");
		err = 0;
return_error:
		/* We can sleep from now on, so we drop lock. */
		spin_unlock(&ntfs_cb_lock);
		/* Second stage: finalize completed pages. */
		if (nr_completed_pages > 0) {
			for (i = 0; i < nr_completed_pages; i++) {
				int di = completed_pages[i];

				dp = dest_pages[di];
				/*
				 * If we are outside the initialized size, zero
				 * the out of bounds page range.
				 */
				handle_bounds_compressed_page(dp, i_size,
						initialized_size);
				flush_dcache_page(dp);
				kunmap(dp);
				SetPageUptodate(dp);
				unlock_page(dp);
				if (di == xpage)
					*xpage_done = 1;
				else
					page_cache_release(dp);
				dest_pages[di] = NULL;
			}
		}
		return err;
	}

	/* Setup offsets for the current sub-block destination. */
	do_sb_start = *dest_ofs;
	do_sb_end = do_sb_start + NTFS_SB_SIZE;

	/* Check that we are still within allowed boundaries. */
	if (*dest_index == dest_max_index && do_sb_end > dest_max_ofs)
		goto return_overflow;

	/* Does the minimum size of a compressed sb overflow valid range? */
	if (cb + 6 > cb_end)
		goto return_overflow;

	/* Setup the current sub-block source pointers and validate range. */
	cb_sb_start = cb;
	cb_sb_end = cb_sb_start + (le16_to_cpup((le16*)cb) & NTFS_SB_SIZE_MASK)
			+ 3;
	if (cb_sb_end > cb_end)
		goto return_overflow;

	/* Get the current destination page. */
	dp = dest_pages[*dest_index];
	if (!dp) {
		/* No page present. Skip decompression of this sub-block. */
		cb = cb_sb_end;

		/* Advance destination position to next sub-block. */
		*dest_ofs = (*dest_ofs + NTFS_SB_SIZE) & ~PAGE_CACHE_MASK;
		if (!*dest_ofs && (++*dest_index > dest_max_index))
			goto return_overflow;
		goto do_next_sb;
	}

	/* We have a valid destination page. Setup the destination pointers. */
	dp_addr = (u8*)page_address(dp) + do_sb_start;

	/* Now, we are ready to process the current sub-block (sb). */
	if (!(le16_to_cpup((le16*)cb) & NTFS_SB_IS_COMPRESSED)) {
		ntfs_debug("Found uncompressed sub-block.");
		/* This sb is not compressed, just copy it into destination. */

		/* Advance source position to first data byte. */
		cb += 2;

		/* An uncompressed sb must be full size. */
		if (cb_sb_end - cb != NTFS_SB_SIZE)
			goto return_overflow;

		/* Copy the block and advance the source position. */
		memcpy(dp_addr, cb, NTFS_SB_SIZE);
		cb += NTFS_SB_SIZE;

		/* Advance destination position to next sub-block. */
		*dest_ofs += NTFS_SB_SIZE;
		if (!(*dest_ofs &= ~PAGE_CACHE_MASK)) {
finalize_page:
			/*
			 * First stage: add current page index to array of
			 * completed pages.
			 */
			completed_pages[nr_completed_pages++] = *dest_index;
			if (++*dest_index > dest_max_index)
				goto return_overflow;
		}
		goto do_next_sb;
	}
	ntfs_debug("Found compressed sub-block.");
	/* This sb is compressed, decompress it into destination. */

	/* Setup destination pointers. */
	dp_sb_start = dp_addr;
	dp_sb_end = dp_sb_start + NTFS_SB_SIZE;

	/* Forward to the first tag in the sub-block. */
	cb += 2;
do_next_tag:
	if (cb == cb_sb_end) {
		/* Check if the decompressed sub-block was not full-length. */
		if (dp_addr < dp_sb_end) {
			int nr_bytes = do_sb_end - *dest_ofs;

			ntfs_debug("Filling incomplete sub-block with "
					"zeroes.");
			/* Zero remainder and update destination position. */
			memset(dp_addr, 0, nr_bytes);
			*dest_ofs += nr_bytes;
		}
		/* We have finished the current sub-block. */
		if (!(*dest_ofs &= ~PAGE_CACHE_MASK))
			goto finalize_page;
		goto do_next_sb;
	}

	/* Check we are still in range. */
	if (cb > cb_sb_end || dp_addr > dp_sb_end)
		goto return_overflow;

	/* Get the next tag and advance to first token. */
	tag = *cb++;

	/* Parse the eight tokens described by the tag. */
	for (token = 0; token < 8; token++, tag >>= 1) {
		u16 lg, pt, length, max_non_overlap;
		register u16 i;
		u8 *dp_back_addr;

		/* Check if we are done / still in range. */
		if (cb >= cb_sb_end || dp_addr > dp_sb_end)
			break;

		/* Determine token type and parse appropriately.*/
		if ((tag & NTFS_TOKEN_MASK) == NTFS_SYMBOL_TOKEN) {
			/*
			 * We have a symbol token, copy the symbol across, and
			 * advance the source and destination positions.
			 */
			*dp_addr++ = *cb++;
			++*dest_ofs;

			/* Continue with the next token. */
			continue;
		}

		/*
		 * We have a phrase token. Make sure it is not the first tag in
		 * the sb as this is illegal and would confuse the code below.
		 */
		if (dp_addr == dp_sb_start)
			goto return_overflow;

		/*
		 * Determine the number of bytes to go back (p) and the number
		 * of bytes to copy (l). We use an optimized algorithm in which
		 * we first calculate log2(current destination position in sb),
		 * which allows determination of l and p in O(1) rather than
		 * O(n). We just need an arch-optimized log2() function now.
		 */
		lg = 0;
		for (i = *dest_ofs - do_sb_start - 1; i >= 0x10; i >>= 1)
			lg++;

		/* Get the phrase token into i. */
		pt = le16_to_cpup((le16*)cb);

		/*
		 * Calculate starting position of the byte sequence in
		 * the destination using the fact that p = (pt >> (12 - lg)) + 1
		 * and make sure we don't go too far back.
		 */
		dp_back_addr = dp_addr - (pt >> (12 - lg)) - 1;
		if (dp_back_addr < dp_sb_start)
			goto return_overflow;

		/* Now calculate the length of the byte sequence. */
		length = (pt & (0xfff >> lg)) + 3;

		/* Advance destination position and verify it is in range. */
		*dest_ofs += length;
		if (*dest_ofs > do_sb_end)
			goto return_overflow;

		/* The number of non-overlapping bytes. */
		max_non_overlap = dp_addr - dp_back_addr;

		if (length <= max_non_overlap) {
			/* The byte sequence doesn't overlap, just copy it. */
			memcpy(dp_addr, dp_back_addr, length);

			/* Advance destination pointer. */
			dp_addr += length;
		} else {
			/*
			 * The byte sequence does overlap, copy non-overlapping
			 * part and then do a slow byte by byte copy for the
			 * overlapping part. Also, advance the destination
			 * pointer.
			 */
			memcpy(dp_addr, dp_back_addr, max_non_overlap);
			dp_addr += max_non_overlap;
			dp_back_addr += max_non_overlap;
			length -= max_non_overlap;
			while (length--)
				*dp_addr++ = *dp_back_addr++;
		}

		/* Advance source position and continue with the next token. */
		cb += 2;
	}

	/* No tokens left in the current tag. Continue with the next tag. */
	goto do_next_tag;

return_overflow:
	ntfs_error(NULL, "Failed. Returning -EOVERFLOW.");
	goto return_error;
}

/**
 * ntfs_read_compressed_block - read a compressed block into the page cache
 * @page:	locked page in the compression block(s) we need to read
 *
 * When we are called the page has already been verified to be locked and the
 * attribute is known to be non-resident, not encrypted, but compressed.
 *
 * 1. Determine which compression block(s) @page is in.
 * 2. Get hold of all pages corresponding to this/these compression block(s).
 * 3. Read the (first) compression block.
 * 4. Decompress it into the corresponding pages.
 * 5. Throw the compressed data away and proceed to 3. for the next compression
 *    block or return success if no more compression blocks left.
 *
 * Warning: We have to be careful what we do about existing pages. They might
 * have been written to so that we would lose data if we were to just overwrite
 * them with the out-of-date uncompressed data.
 *
 * FIXME: For PAGE_CACHE_SIZE > cb_size we are not doing the Right Thing(TM) at
 * the end of the file I think. We need to detect this case and zero the out
 * of bounds remainder of the page in question and mark it as handled. At the
 * moment we would just return -EIO on such a page. This bug will only become
 * apparent if pages are above 8kiB and the NTFS volume only uses 512 byte
 * clusters so is probably not going to be seen by anyone. Still this should
 * be fixed. (AIA)
 *
 * FIXME: Again for PAGE_CACHE_SIZE > cb_size we are screwing up both in
 * handling sparse and compressed cbs. (AIA)
 *
 * FIXME: At the moment we don't do any zeroing out in the case that
 * initialized_size is less than data_size. This should be safe because of the
 * nature of the compression algorithm used. Just in case we check and output
 * an error message in read inode if the two sizes are not equal for a
 * compressed file. (AIA)
 */
int ntfs_read_compressed_block(struct page *page)
{
	loff_t i_size;
	s64 initialized_size;
	struct address_space *mapping = page->mapping;
	ntfs_inode *ni = NTFS_I(mapping->host);
	ntfs_volume *vol = ni->vol;
	struct super_block *sb = vol->sb;
	runlist_element *rl;
	unsigned long flags, block_size = sb->s_blocksize;
	unsigned char block_size_bits = sb->s_blocksize_bits;
	u8 *cb, *cb_pos, *cb_end;
	struct buffer_head **bhs;
	unsigned long offset, index = page->index;
	u32 cb_size = ni->itype.compressed.block_size;
	u64 cb_size_mask = cb_size - 1UL;
	VCN vcn;
	LCN lcn;
	/* The first wanted vcn (minimum alignment is PAGE_CACHE_SIZE). */
	VCN start_vcn = (((s64)index << PAGE_CACHE_SHIFT) & ~cb_size_mask) >>
			vol->cluster_size_bits;
	/*
	 * The first vcn after the last wanted vcn (minimum alignment is again
	 * PAGE_CACHE_SIZE.
	 */
	VCN end_vcn = ((((s64)(index + 1UL) << PAGE_CACHE_SHIFT) + cb_size - 1)
			& ~cb_size_mask) >> vol->cluster_size_bits;
	/* Number of compression blocks (cbs) in the wanted vcn range. */
	unsigned int nr_cbs = (end_vcn - start_vcn) << vol->cluster_size_bits
			>> ni->itype.compressed.block_size_bits;
	/*
	 * Number of pages required to store the uncompressed data from all
	 * compression blocks (cbs) overlapping @page. Due to alignment
	 * guarantees of start_vcn and end_vcn, no need to round up here.
	 */
	unsigned int nr_pages = (end_vcn - start_vcn) <<
			vol->cluster_size_bits >> PAGE_CACHE_SHIFT;
	unsigned int xpage, max_page, cur_page, cur_ofs, i;
	unsigned int cb_clusters, cb_max_ofs;
	int block, max_block, cb_max_page, bhs_size, nr_bhs, err = 0;
	struct page **pages;
	unsigned char xpage_done = 0;

	ntfs_debug("Entering, page->index = 0x%lx, cb_size = 0x%x, nr_pages = "
			"%i.", index, cb_size, nr_pages);
	/*
	 * Bad things happen if we get here for anything that is not an
	 * unnamed $DATA attribute.
	 */
	BUG_ON(ni->type != AT_DATA);
	BUG_ON(ni->name_len);

	pages = kmalloc(nr_pages * sizeof(struct page *), GFP_NOFS);

	/* Allocate memory to store the buffer heads we need. */
	bhs_size = cb_size / block_size * sizeof(struct buffer_head *);
	bhs = kmalloc(bhs_size, GFP_NOFS);

	if (unlikely(!pages || !bhs)) {
		kfree(bhs);
		kfree(pages);
		unlock_page(page);
		ntfs_error(vol->sb, "Failed to allocate internal buffers.");
		return -ENOMEM;
	}

	/*
	 * We have already been given one page, this is the one we must do.
	 * Once again, the alignment guarantees keep it simple.
	 */
	offset = start_vcn << vol->cluster_size_bits >> PAGE_CACHE_SHIFT;
	xpage = index - offset;
	pages[xpage] = page;
	/*
	 * The remaining pages need to be allocated and inserted into the page
	 * cache, alignment guarantees keep all the below much simpler. (-8
	 */
	read_lock_irqsave(&ni->size_lock, flags);
	i_size = i_size_read(VFS_I(ni));
	initialized_size = ni->initialized_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	max_page = ((i_size + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT) -
			offset;
	/* Is the page fully outside i_size? (truncate in progress) */
	if (xpage >= max_page) {
		kfree(bhs);
		kfree(pages);
		zero_user(page, 0, PAGE_CACHE_SIZE);
		ntfs_debug("Compressed read outside i_size - truncated?");
		SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}
	if (nr_pages < max_page)
		max_page = nr_pages;
	for (i = 0; i < max_page; i++, offset++) {
		if (i != xpage)
			pages[i] = grab_cache_page_nowait(mapping, offset);
		page = pages[i];
		if (page) {
			/*
			 * We only (re)read the page if it isn't already read
			 * in and/or dirty or we would be losing data or at
			 * least wasting our time.
			 */
			if (!PageDirty(page) && (!PageUptodate(page) ||
					PageError(page))) {
				ClearPageError(page);
				kmap(page);
				continue;
			}
			unlock_page(page);
			page_cache_release(page);
			pages[i] = NULL;
		}
	}

	/*
	 * We have the runlist, and all the destination pages we need to fill.
	 * Now read the first compression block.
	 */
	cur_page = 0;
	cur_ofs = 0;
	cb_clusters = ni->itype.compressed.block_clusters;
do_next_cb:
	nr_cbs--;
	nr_bhs = 0;

	/* Read all cb buffer heads one cluster at a time. */
	rl = NULL;
	for (vcn = start_vcn, start_vcn += cb_clusters; vcn < start_vcn;
			vcn++) {
		bool is_retry = false;

		if (!rl) {
lock_retry_remap:
			down_read(&ni->runlist.lock);
			rl = ni->runlist.rl;
		}
		if (likely(rl != NULL)) {
			/* Seek to element containing target vcn. */
			while (rl->length && rl[1].vcn <= vcn)
				rl++;
			lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
		} else
			lcn = LCN_RL_NOT_MAPPED;
		ntfs_debug("Reading vcn = 0x%llx, lcn = 0x%llx.",
				(unsigned long long)vcn,
				(unsigned long long)lcn);
		if (lcn < 0) {
			/*
			 * When we reach the first sparse cluster we have
			 * finished with the cb.
			 */
			if (lcn == LCN_HOLE)
				break;
			if (is_retry || lcn != LCN_RL_NOT_MAPPED)
				goto rl_err;
			is_retry = true;
			/*
			 * Attempt to map runlist, dropping lock for the
			 * duration.
			 */
			up_read(&ni->runlist.lock);
			if (!ntfs_map_runlist(ni, vcn))
				goto lock_retry_remap;
			goto map_rl_err;
		}
		block = lcn << vol->cluster_size_bits >> block_size_bits;
		/* Read the lcn from device in chunks of block_size bytes. */
		max_block = block + (vol->cluster_size >> block_size_bits);
		do {
			ntfs_debug("block = 0x%x.", block);
			if (unlikely(!(bhs[nr_bhs] = sb_getblk(sb, block))))
				goto getblk_err;
			nr_bhs++;
		} while (++block < max_block);
	}

	/* Release the lock if we took it. */
	if (rl)
		up_read(&ni->runlist.lock);

	/* Setup and initiate io on all buffer heads. */
	for (i = 0; i < nr_bhs; i++) {
		struct buffer_head *tbh = bhs[i];

		if (!trylock_buffer(tbh))
			continue;
		if (unlikely(buffer_uptodate(tbh))) {
			unlock_buffer(tbh);
			continue;
		}
		get_bh(tbh);
		tbh->b_end_io = end_buffer_read_sync;
		submit_bh(READ, tbh);
	}

	/* Wait for io completion on all buffer heads. */
	for (i = 0; i < nr_bhs; i++) {
		struct buffer_head *tbh = bhs[i];

		if (buffer_uptodate(tbh))
			continue;
		wait_on_buffer(tbh);
		/*
		 * We need an optimization barrier here, otherwise we start
		 * hitting the below fixup code when accessing a loopback
		 * mounted ntfs partition. This indicates either there is a
		 * race condition in the loop driver or, more likely, gcc
		 * overoptimises the code without the barrier and it doesn't
		 * do the Right Thing(TM).
		 */
		barrier();
		if (unlikely(!buffer_uptodate(tbh))) {
			ntfs_warning(vol->sb, "Buffer is unlocked but not "
					"uptodate! Unplugging the disk queue "
					"and rescheduling.");
			get_bh(tbh);
			io_schedule();
			put_bh(tbh);
			if (unlikely(!buffer_uptodate(tbh)))
				goto read_err;
			ntfs_warning(vol->sb, "Buffer is now uptodate. Good.");
		}
	}

	/*
	 * Get the compression buffer. We must not sleep any more
	 * until we are finished with it.
	 */
	spin_lock(&ntfs_cb_lock);
	cb = ntfs_compression_buffer;

	BUG_ON(!cb);

	cb_pos = cb;
	cb_end = cb + cb_size;

	/* Copy the buffer heads into the contiguous buffer. */
	for (i = 0; i < nr_bhs; i++) {
		memcpy(cb_pos, bhs[i]->b_data, block_size);
		cb_pos += block_size;
	}

	/* Just a precaution. */
	if (cb_pos + 2 <= cb + cb_size)
		*(u16*)cb_pos = 0;

	/* Reset cb_pos back to the beginning. */
	cb_pos = cb;

	/* We now have both source (if present) and destination. */
	ntfs_debug("Successfully read the compression block.");

	/* The last page and maximum offset within it for the current cb. */
	cb_max_page = (cur_page << PAGE_CACHE_SHIFT) + cur_ofs + cb_size;
	cb_max_ofs = cb_max_page & ~PAGE_CACHE_MASK;
	cb_max_page >>= PAGE_CACHE_SHIFT;

	/* Catch end of file inside a compression block. */
	if (cb_max_page > max_page)
		cb_max_page = max_page;

	if (vcn == start_vcn - cb_clusters) {
		/* Sparse cb, zero out page range overlapping the cb. */
		ntfs_debug("Found sparse compression block.");
		/* We can sleep from now on, so we drop lock. */
		spin_unlock(&ntfs_cb_lock);
		if (cb_max_ofs)
			cb_max_page--;
		for (; cur_page < cb_max_page; cur_page++) {
			page = pages[cur_page];
			if (page) {
				/*
				 * FIXME: Using clear_page() will become wrong
				 * when we get PAGE_CACHE_SIZE != PAGE_SIZE but
				 * for now there is no problem.
				 */
				if (likely(!cur_ofs))
					clear_page(page_address(page));
				else
					memset(page_address(page) + cur_ofs, 0,
							PAGE_CACHE_SIZE -
							cur_ofs);
				flush_dcache_page(page);
				kunmap(page);
				SetPageUptodate(page);
				unlock_page(page);
				if (cur_page == xpage)
					xpage_done = 1;
				else
					page_cache_release(page);
				pages[cur_page] = NULL;
			}
			cb_pos += PAGE_CACHE_SIZE - cur_ofs;
			cur_ofs = 0;
			if (cb_pos >= cb_end)
				break;
		}
		/* If we have a partial final page, deal with it now. */
		if (cb_max_ofs && cb_pos < cb_end) {
			page = pages[cur_page];
			if (page)
				memset(page_address(page) + cur_ofs, 0,
						cb_max_ofs - cur_ofs);
			/*
			 * No need to update cb_pos at this stage:
			 *	cb_pos += cb_max_ofs - cur_ofs;
			 */
			cur_ofs = cb_max_ofs;
		}
	} else if (vcn == start_vcn) {
		/* We can't sleep so we need two stages. */
		unsigned int cur2_page = cur_page;
		unsigned int cur_ofs2 = cur_ofs;
		u8 *cb_pos2 = cb_pos;

		ntfs_debug("Found uncompressed compression block.");
		/* Uncompressed cb, copy it to the destination pages. */
		/*
		 * TODO: As a big optimization, we could detect this case
		 * before we read all the pages and use block_read_full_page()
		 * on all full pages instead (we still have to treat partial
		 * pages especially but at least we are getting rid of the
		 * synchronous io for the majority of pages.
		 * Or if we choose not to do the read-ahead/-behind stuff, we
		 * could just return block_read_full_page(pages[xpage]) as long
		 * as PAGE_CACHE_SIZE <= cb_size.
		 */
		if (cb_max_ofs)
			cb_max_page--;
		/* First stage: copy data into destination pages. */
		for (; cur_page < cb_max_page; cur_page++) {
			page = pages[cur_page];
			if (page)
				memcpy(page_address(page) + cur_ofs, cb_pos,
						PAGE_CACHE_SIZE - cur_ofs);
			cb_pos += PAGE_CACHE_SIZE - cur_ofs;
			cur_ofs = 0;
			if (cb_pos >= cb_end)
				break;
		}
		/* If we have a partial final page, deal with it now. */
		if (cb_max_ofs && cb_pos < cb_end) {
			page = pages[cur_page];
			if (page)
				memcpy(page_address(page) + cur_ofs, cb_pos,
						cb_max_ofs - cur_ofs);
			cb_pos += cb_max_ofs - cur_ofs;
			cur_ofs = cb_max_ofs;
		}
		/* We can sleep from now on, so drop lock. */
		spin_unlock(&ntfs_cb_lock);
		/* Second stage: finalize pages. */
		for (; cur2_page < cb_max_page; cur2_page++) {
			page = pages[cur2_page];
			if (page) {
				/*
				 * If we are outside the initialized size, zero
				 * the out of bounds page range.
				 */
				handle_bounds_compressed_page(page, i_size,
						initialized_size);
				flush_dcache_page(page);
				kunmap(page);
				SetPageUptodate(page);
				unlock_page(page);
				if (cur2_page == xpage)
					xpage_done = 1;
				else
					page_cache_release(page);
				pages[cur2_page] = NULL;
			}
			cb_pos2 += PAGE_CACHE_SIZE - cur_ofs2;
			cur_ofs2 = 0;
			if (cb_pos2 >= cb_end)
				break;
		}
	} else {
		/* Compressed cb, decompress it into the destination page(s). */
		unsigned int prev_cur_page = cur_page;

		ntfs_debug("Found compressed compression block.");
		err = ntfs_decompress(pages, &cur_page, &cur_ofs,
				cb_max_page, cb_max_ofs, xpage, &xpage_done,
				cb_pos,	cb_size - (cb_pos - cb), i_size,
				initialized_size);
		/*
		 * We can sleep from now on, lock already dropped by
		 * ntfs_decompress().
		 */
		if (err) {
			ntfs_error(vol->sb, "ntfs_decompress() failed in inode "
					"0x%lx with error code %i. Skipping "
					"this compression block.",
					ni->mft_no, -err);
			/* Release the unfinished pages. */
			for (; prev_cur_page < cur_page; prev_cur_page++) {
				page = pages[prev_cur_page];
				if (page) {
					flush_dcache_page(page);
					kunmap(page);
					unlock_page(page);
					if (prev_cur_page != xpage)
						page_cache_release(page);
					pages[prev_cur_page] = NULL;
				}
			}
		}
	}

	/* Release the buffer heads. */
	for (i = 0; i < nr_bhs; i++)
		brelse(bhs[i]);

	/* Do we have more work to do? */
	if (nr_cbs)
		goto do_next_cb;

	/* We no longer need the list of buffer heads. */
	kfree(bhs);

	/* Clean up if we have any pages left. Should never happen. */
	for (cur_page = 0; cur_page < max_page; cur_page++) {
		page = pages[cur_page];
		if (page) {
			ntfs_error(vol->sb, "Still have pages left! "
					"Terminating them with extreme "
					"prejudice.  Inode 0x%lx, page index "
					"0x%lx.", ni->mft_no, page->index);
			flush_dcache_page(page);
			kunmap(page);
			unlock_page(page);
			if (cur_page != xpage)
				page_cache_release(page);
			pages[cur_page] = NULL;
		}
	}

	/* We no longer need the list of pages. */
	kfree(pages);

	/* If we have completed the requested page, we return success. */
	if (likely(xpage_done))
		return 0;

	ntfs_debug("Failed. Returning error code %s.", err == -EOVERFLOW ?
			"EOVERFLOW" : (!err ? "EIO" : "unknown error"));
	return err < 0 ? err : -EIO;

read_err:
	ntfs_error(vol->sb, "IO error while reading compressed data.");
	/* Release the buffer heads. */
	for (i = 0; i < nr_bhs; i++)
		brelse(bhs[i]);
	goto err_out;

map_rl_err:
	ntfs_error(vol->sb, "ntfs_map_runlist() failed. Cannot read "
			"compression block.");
	goto err_out;

rl_err:
	up_read(&ni->runlist.lock);
	ntfs_error(vol->sb, "ntfs_rl_vcn_to_lcn() failed. Cannot read "
			"compression block.");
	goto err_out;

getblk_err:
	up_read(&ni->runlist.lock);
	ntfs_error(vol->sb, "getblk() failed. Cannot read compression block.");

err_out:
	kfree(bhs);
	for (i = cur_page; i < max_page; i++) {
		page = pages[i];
		if (page) {
			flush_dcache_page(page);
			kunmap(page);
			unlock_page(page);
			if (i != xpage)
				page_cache_release(page);
		}
	}
	kfree(pages);
	return -EIO;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/compress.c */
/************************************************************/
/*
 * debug.c - NTFS kernel debug support. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2004 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
// #include "debug.h"

/**
 * __ntfs_warning - output a warning to the syslog
 * @function:	name of function outputting the warning
 * @sb:		super block of mounted ntfs filesystem
 * @fmt:	warning string containing format specifications
 * @...:	a variable number of arguments specified in @fmt
 *
 * Outputs a warning to the syslog for the mounted ntfs filesystem described
 * by @sb.
 *
 * @fmt and the corresponding @... is printf style format string containing
 * the warning string and the corresponding format arguments, respectively.
 *
 * @function is the name of the function from which __ntfs_warning is being
 * called.
 *
 * Note, you should be using debug.h::ntfs_warning(@sb, @fmt, @...) instead
 * as this provides the @function parameter automatically.
 */
void __ntfs_warning(const char *function, const struct super_block *sb,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int flen = 0;

#ifndef DEBUG
	if (!printk_ratelimit())
		return;
#endif
	if (function)
		flen = strlen(function);
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	if (sb)
		pr_warn("(device %s): %s(): %pV\n",
			sb->s_id, flen ? function : "", &vaf);
	else
		pr_warn("%s(): %pV\n", flen ? function : "", &vaf);
	va_end(args);
}

/**
 * __ntfs_error - output an error to the syslog
 * @function:	name of function outputting the error
 * @sb:		super block of mounted ntfs filesystem
 * @fmt:	error string containing format specifications
 * @...:	a variable number of arguments specified in @fmt
 *
 * Outputs an error to the syslog for the mounted ntfs filesystem described
 * by @sb.
 *
 * @fmt and the corresponding @... is printf style format string containing
 * the error string and the corresponding format arguments, respectively.
 *
 * @function is the name of the function from which __ntfs_error is being
 * called.
 *
 * Note, you should be using debug.h::ntfs_error(@sb, @fmt, @...) instead
 * as this provides the @function parameter automatically.
 */
void __ntfs_error(const char *function, const struct super_block *sb,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int flen = 0;

#ifndef DEBUG
	if (!printk_ratelimit())
		return;
#endif
	if (function)
		flen = strlen(function);
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	if (sb)
		pr_err("(device %s): %s(): %pV\n",
		       sb->s_id, flen ? function : "", &vaf);
	else
		pr_err("%s(): %pV\n", flen ? function : "", &vaf);
	va_end(args);
}

#ifdef DEBUG

/* If 1, output debug messages, and if 0, don't. */
int debug_msgs = 0;

void __ntfs_debug(const char *file, int line, const char *function,
		const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int flen = 0;

	if (!debug_msgs)
		return;
	if (function)
		flen = strlen(function);
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_debug("(%s, %d): %s(): %pV", file, line, flen ? function : "", &vaf);
	va_end(args);
}

/* Dump a runlist. Caller has to provide synchronisation for @rl. */
void ntfs_debug_dump_runlist(const runlist_element *rl)
{
	int i;
	const char *lcn_str[5] = { "LCN_HOLE         ", "LCN_RL_NOT_MAPPED",
				   "LCN_ENOENT       ", "LCN_unknown      " };

	if (!debug_msgs)
		return;
	pr_debug("Dumping runlist (values in hex):\n");
	if (!rl) {
		pr_debug("Run list not present.\n");
		return;
	}
	pr_debug("VCN              LCN               Run length\n");
	for (i = 0; ; i++) {
		LCN lcn = (rl + i)->lcn;

		if (lcn < (LCN)0) {
			int index = -lcn - 1;

			if (index > -LCN_ENOENT - 1)
				index = 3;
			pr_debug("%-16Lx %s %-16Lx%s\n",
					(long long)(rl + i)->vcn, lcn_str[index],
					(long long)(rl + i)->length,
					(rl + i)->length ? "" :
						" (runlist end)");
		} else
			pr_debug("%-16Lx %-16Lx  %-16Lx%s\n",
					(long long)(rl + i)->vcn,
					(long long)(rl + i)->lcn,
					(long long)(rl + i)->length,
					(rl + i)->length ? "" :
						" (runlist end)");
		if (!(rl + i)->length)
			break;
	}
}

#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/debug.c */
/************************************************************/
/**
 * dir.c - NTFS kernel directory operations. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2007 Anton Altaparmakov
 * Copyright (c) 2002 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include <linux/buffer_head.h>
// #include <linux/slab.h>

#include "dir.h"
// #include "aops.h"
// #include "attrib.h"
// #include "mft.h"
// #include "debug.h"
// #include "ntfs.h"
#include "../../inc/__fss.h"

/**
 * The little endian Unicode string $I30 as a global constant.
 */
ntfschar I30[5] = { cpu_to_le16('$'), cpu_to_le16('I'),
		cpu_to_le16('3'),	cpu_to_le16('0'), 0 };

/**
 * ntfs_lookup_inode_by_name - find an inode in a directory given its name
 * @dir_ni:	ntfs inode of the directory in which to search for the name
 * @uname:	Unicode name for which to search in the directory
 * @uname_len:	length of the name @uname in Unicode characters
 * @res:	return the found file name if necessary (see below)
 *
 * Look for an inode with name @uname in the directory with inode @dir_ni.
 * ntfs_lookup_inode_by_name() walks the contents of the directory looking for
 * the Unicode name. If the name is found in the directory, the corresponding
 * inode number (>= 0) is returned as a mft reference in cpu format, i.e. it
 * is a 64-bit number containing the sequence number.
 *
 * On error, a negative value is returned corresponding to the error code. In
 * particular if the inode is not found -ENOENT is returned. Note that you
 * can't just check the return value for being negative, you have to check the
 * inode number for being negative which you can extract using MREC(return
 * value).
 *
 * Note, @uname_len does not include the (optional) terminating NULL character.
 *
 * Note, we look for a case sensitive match first but we also look for a case
 * insensitive match at the same time. If we find a case insensitive match, we
 * save that for the case that we don't find an exact match, where we return
 * the case insensitive match and setup @res (which we allocate!) with the mft
 * reference, the file name type, length and with a copy of the little endian
 * Unicode file name itself. If we match a file name which is in the DOS name
 * space, we only return the mft reference and file name type in @res.
 * ntfs_lookup() then uses this to find the long file name in the inode itself.
 * This is to avoid polluting the dcache with short file names. We want them to
 * work but we don't care for how quickly one can access them. This also fixes
 * the dcache aliasing issues.
 *
 * Locking:  - Caller must hold i_mutex on the directory.
 *	     - Each page cache page in the index allocation mapping must be
 *	       locked whilst being accessed otherwise we may find a corrupt
 *	       page due to it being under ->writepage at the moment which
 *	       applies the mst protection fixups before writing out and then
 *	       removes them again after the write is complete after which it 
 *	       unlocks the page.
 */
MFT_REF ntfs_lookup_inode_by_name(ntfs_inode *dir_ni, const ntfschar *uname,
		const int uname_len, ntfs_name **res)
{
	ntfs_volume *vol = dir_ni->vol;
	struct super_block *sb = vol->sb;
	MFT_RECORD *m;
	INDEX_ROOT *ir;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *index_end;
	u64 mref;
	ntfs_attr_search_ctx *ctx;
	int err, rc;
	VCN vcn, old_vcn;
	struct address_space *ia_mapping;
	struct page *page;
	u8 *kaddr;
	ntfs_name *name = NULL;

	BUG_ON(!S_ISDIR(VFS_I(dir_ni)->i_mode));
	BUG_ON(NInoAttr(dir_ni));
	/* Get hold of the mft record for the directory. */
	m = map_mft_record(dir_ni);
	if (IS_ERR(m)) {
		ntfs_error(sb, "map_mft_record() failed with error code %ld.",
				-PTR_ERR(m));
		return ERR_MREF(PTR_ERR(m));
	}
	ctx = ntfs_attr_get_search_ctx(dir_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, I30, 4, CASE_SENSITIVE, 0, NULL,
			0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
			err = -EIO;
		}
		goto err_out;
	}
	/* Get to the index root value (it's been verified in read_inode). */
	ir = (INDEX_ROOT*)((u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset));
	index_end = (u8*)&ir->index + le32_to_cpu(ir->index.index_length);
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ir->index +
			le32_to_cpu(ir->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)ctx->mrec || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end)
			goto dir_err_out;
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/*
		 * We perform a case sensitive comparison and if that matches
		 * we are done and return the mft reference of the inode (i.e.
		 * the inode number together with the sequence number for
		 * consistency checking). We convert it to cpu format before
		 * returning.
		 */
		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len)) {
found_it:
			/*
			 * We have a perfect match, so we don't need to care
			 * about having matched imperfectly before, so we can
			 * free name and set *res to NULL.
			 * However, if the perfect match is a short file name,
			 * we need to signal this through *res, so that
			 * ntfs_lookup() can fix dcache aliasing issues.
			 * As an optimization we just reuse an existing
			 * allocation of *res.
			 */
			if (ie->key.file_name.file_name_type == FILE_NAME_DOS) {
				if (!name) {
					name = kmalloc(sizeof(ntfs_name),
							GFP_NOFS);
					if (!name) {
						err = -ENOMEM;
						goto err_out;
					}
				}
				name->mref = le64_to_cpu(
						ie->data.dir.indexed_file);
				name->type = FILE_NAME_DOS;
				name->len = 0;
				*res = name;
			} else {
				kfree(name);
				*res = NULL;
			}
			mref = le64_to_cpu(ie->data.dir.indexed_file);
			ntfs_attr_put_search_ctx(ctx);
			unmap_mft_record(dir_ni);
			return mref;
		}
		/*
		 * For a case insensitive mount, we also perform a case
		 * insensitive comparison (provided the file name is not in the
		 * POSIX namespace). If the comparison matches, and the name is
		 * in the WIN32 namespace, we cache the filename in *res so
		 * that the caller, ntfs_lookup(), can work on it. If the
		 * comparison matches, and the name is in the DOS namespace, we
		 * only cache the mft reference and the file name type (we set
		 * the name length to zero for simplicity).
		 */
		if (!NVolCaseSensitive(vol) &&
				ie->key.file_name.file_name_type &&
				ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length,
				IGNORE_CASE, vol->upcase, vol->upcase_len)) {
			int name_size = sizeof(ntfs_name);
			u8 type = ie->key.file_name.file_name_type;
			u8 len = ie->key.file_name.file_name_length;

			/* Only one case insensitive matching name allowed. */
			if (name) {
				ntfs_error(sb, "Found already allocated name "
						"in phase 1. Please run chkdsk "
						"and if that doesn't find any "
						"errors please report you saw "
						"this message to "
						"linux-ntfs-dev@lists."
						"sourceforge.net.");
				goto dir_err_out;
			}

			if (type != FILE_NAME_DOS)
				name_size += len * sizeof(ntfschar);
			name = kmalloc(name_size, GFP_NOFS);
			if (!name) {
				err = -ENOMEM;
				goto err_out;
			}
			name->mref = le64_to_cpu(ie->data.dir.indexed_file);
			name->type = type;
			if (type != FILE_NAME_DOS) {
				name->len = len;
				memcpy(name->name, ie->key.file_name.file_name,
						len * sizeof(ntfschar));
			} else
				name->len = 0;
			*res = name;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If uname collates before the name of the current entry, there
		 * is definitely no such name in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/* The names are not equal, continue the search. */
		if (rc)
			continue;
		/*
		 * Names match with case insensitive comparison, now try the
		 * case sensitive comparison, which is required for proper
		 * collation.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (rc == -1)
			break;
		if (rc)
			continue;
		/*
		 * Perfect match, this will never happen as the
		 * ntfs_are_names_equal() call will have gotten a match but we
		 * still treat it correctly.
		 */
		goto found_it;
	}
	/*
	 * We have finished with this index without success. Check for the
	 * presence of a child node and if not present return -ENOENT, unless
	 * we have got a matching name cached in name in which case return the
	 * mft reference associated with it.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		if (name) {
			ntfs_attr_put_search_ctx(ctx);
			unmap_mft_record(dir_ni);
			return name->mref;
		}
		ntfs_debug("Entry not found.");
		err = -ENOENT;
		goto err_out;
	} /* Child node present, descend into it. */
	/* Consistency check: Verify that an index allocation exists. */
	if (!NInoIndexAllocPresent(dir_ni)) {
		ntfs_error(sb, "No index allocation attribute but index entry "
				"requires one. Directory inode 0x%lx is "
				"corrupt or driver bug.", dir_ni->mft_no);
		goto err_out;
	}
	/* Get the starting vcn of the index_block holding the child node. */
	vcn = sle64_to_cpup((sle64*)((u8*)ie + le16_to_cpu(ie->length) - 8));
	ia_mapping = VFS_I(dir_ni)->i_mapping;
	/*
	 * We are done with the index root and the mft record. Release them,
	 * otherwise we deadlock with ntfs_map_page().
	 */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(dir_ni);
	m = NULL;
	ctx = NULL;
descend_into_child_node:
	/*
	 * Convert vcn to index into the index allocation attribute in units
	 * of PAGE_CACHE_SIZE and map the page cache page, reading it from
	 * disk if necessary.
	 */
	page = ntfs_map_page(ia_mapping, vcn <<
			dir_ni->itype.index.vcn_size_bits >> PAGE_CACHE_SHIFT);
	if (IS_ERR(page)) {
		ntfs_error(sb, "Failed to map directory index page, error %ld.",
				-PTR_ERR(page));
		err = PTR_ERR(page);
		goto err_out;
	}
	lock_page(page);
	kaddr = (u8*)page_address(page);
fast_descend_into_child_node:
	/* Get to the index allocation block. */
	ia = (INDEX_ALLOCATION*)(kaddr + ((vcn <<
			dir_ni->itype.index.vcn_size_bits) & ~PAGE_CACHE_MASK));
	/* Bounds checks. */
	if ((u8*)ia < kaddr || (u8*)ia > kaddr + PAGE_CACHE_SIZE) {
		ntfs_error(sb, "Out of bounds check failed. Corrupt directory "
				"inode 0x%lx or driver bug.", dir_ni->mft_no);
		goto unm_err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic))) {
		ntfs_error(sb, "Directory index record with vcn 0x%llx is "
				"corrupt.  Corrupt inode 0x%lx.  Run chkdsk.",
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx). "
				"Directory inode 0x%lx is corrupt or driver "
				"bug.", (unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 !=
			dir_ni->itype.index.block_size) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx has a size (%u) differing from the "
				"directory specified size (%u). Directory "
				"inode is corrupt or driver bug.",
				(unsigned long long)vcn, dir_ni->mft_no,
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				dir_ni->itype.index.block_size);
		goto unm_err_out;
	}
	index_end = (u8*)ia + dir_ni->itype.index.block_size;
	if (index_end > kaddr + PAGE_CACHE_SIZE) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx crosses page boundary. Impossible! "
				"Cannot access! This is probably a bug in the "
				"driver.", (unsigned long long)vcn,
				dir_ni->mft_no);
		goto unm_err_out;
	}
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (index_end > (u8*)ia + dir_ni->itype.index.block_size) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of directory "
				"inode 0x%lx exceeds maximum size.",
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ia->index +
			le32_to_cpu(ia->index.entries_offset));
	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds check. */
		if ((u8*)ie < (u8*)ia || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end) {
			ntfs_error(sb, "Index entry out of bounds in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
			goto unm_err_out;
		}
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/*
		 * We perform a case sensitive comparison and if that matches
		 * we are done and return the mft reference of the inode (i.e.
		 * the inode number together with the sequence number for
		 * consistency checking). We convert it to cpu format before
		 * returning.
		 */
		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len)) {
found_it2:
			/*
			 * We have a perfect match, so we don't need to care
			 * about having matched imperfectly before, so we can
			 * free name and set *res to NULL.
			 * However, if the perfect match is a short file name,
			 * we need to signal this through *res, so that
			 * ntfs_lookup() can fix dcache aliasing issues.
			 * As an optimization we just reuse an existing
			 * allocation of *res.
			 */
			if (ie->key.file_name.file_name_type == FILE_NAME_DOS) {
				if (!name) {
					name = kmalloc(sizeof(ntfs_name),
							GFP_NOFS);
					if (!name) {
						err = -ENOMEM;
						goto unm_err_out;
					}
				}
				name->mref = le64_to_cpu(
						ie->data.dir.indexed_file);
				name->type = FILE_NAME_DOS;
				name->len = 0;
				*res = name;
			} else {
				kfree(name);
				*res = NULL;
			}
			mref = le64_to_cpu(ie->data.dir.indexed_file);
			unlock_page(page);
			ntfs_unmap_page(page);
			return mref;
		}
		/*
		 * For a case insensitive mount, we also perform a case
		 * insensitive comparison (provided the file name is not in the
		 * POSIX namespace). If the comparison matches, and the name is
		 * in the WIN32 namespace, we cache the filename in *res so
		 * that the caller, ntfs_lookup(), can work on it. If the
		 * comparison matches, and the name is in the DOS namespace, we
		 * only cache the mft reference and the file name type (we set
		 * the name length to zero for simplicity).
		 */
		if (!NVolCaseSensitive(vol) &&
				ie->key.file_name.file_name_type &&
				ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length,
				IGNORE_CASE, vol->upcase, vol->upcase_len)) {
			int name_size = sizeof(ntfs_name);
			u8 type = ie->key.file_name.file_name_type;
			u8 len = ie->key.file_name.file_name_length;

			/* Only one case insensitive matching name allowed. */
			if (name) {
				ntfs_error(sb, "Found already allocated name "
						"in phase 2. Please run chkdsk "
						"and if that doesn't find any "
						"errors please report you saw "
						"this message to "
						"linux-ntfs-dev@lists."
						"sourceforge.net.");
				unlock_page(page);
				ntfs_unmap_page(page);
				goto dir_err_out;
			}

			if (type != FILE_NAME_DOS)
				name_size += len * sizeof(ntfschar);
			name = kmalloc(name_size, GFP_NOFS);
			if (!name) {
				err = -ENOMEM;
				goto unm_err_out;
			}
			name->mref = le64_to_cpu(ie->data.dir.indexed_file);
			name->type = type;
			if (type != FILE_NAME_DOS) {
				name->len = len;
				memcpy(name->name, ie->key.file_name.file_name,
						len * sizeof(ntfschar));
			} else
				name->len = 0;
			*res = name;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If uname collates before the name of the current entry, there
		 * is definitely no such name in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/* The names are not equal, continue the search. */
		if (rc)
			continue;
		/*
		 * Names match with case insensitive comparison, now try the
		 * case sensitive comparison, which is required for proper
		 * collation.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (rc == -1)
			break;
		if (rc)
			continue;
		/*
		 * Perfect match, this will never happen as the
		 * ntfs_are_names_equal() call will have gotten a match but we
		 * still treat it correctly.
		 */
		goto found_it2;
	}
	/*
	 * We have finished with this index buffer without success. Check for
	 * the presence of a child node.
	 */
	if (ie->flags & INDEX_ENTRY_NODE) {
		if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
			ntfs_error(sb, "Index entry with child node found in "
					"a leaf node in directory inode 0x%lx.",
					dir_ni->mft_no);
			goto unm_err_out;
		}
		/* Child node present, descend into it. */
		old_vcn = vcn;
		vcn = sle64_to_cpup((sle64*)((u8*)ie +
				le16_to_cpu(ie->length) - 8));
		if (vcn >= 0) {
			/* If vcn is in the same page cache page as old_vcn we
			 * recycle the mapped page. */
			if (old_vcn << vol->cluster_size_bits >>
					PAGE_CACHE_SHIFT == vcn <<
					vol->cluster_size_bits >>
					PAGE_CACHE_SHIFT)
				goto fast_descend_into_child_node;
			unlock_page(page);
			ntfs_unmap_page(page);
			goto descend_into_child_node;
		}
		ntfs_error(sb, "Negative child node vcn in directory inode "
				"0x%lx.", dir_ni->mft_no);
		goto unm_err_out;
	}
	/*
	 * No child node present, return -ENOENT, unless we have got a matching
	 * name cached in name in which case return the mft reference
	 * associated with it.
	 */
	if (name) {
		unlock_page(page);
		ntfs_unmap_page(page);
		return name->mref;
	}
	ntfs_debug("Entry not found.");
	err = -ENOENT;
unm_err_out:
	unlock_page(page);
	ntfs_unmap_page(page);
err_out:
	if (!err)
		err = -EIO;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(dir_ni);
	if (name) {
		kfree(name);
		*res = NULL;
	}
	return ERR_MREF(err);
dir_err_out:
	ntfs_error(sb, "Corrupt directory.  Aborting lookup.");
	goto err_out;
}

#if 0

// TODO: (AIA)
// The algorithm embedded in this code will be required for the time when we
// want to support adding of entries to directories, where we require correct
// collation of file names in order not to cause corruption of the filesystem.

/**
 * ntfs_lookup_inode_by_name - find an inode in a directory given its name
 * @dir_ni:	ntfs inode of the directory in which to search for the name
 * @uname:	Unicode name for which to search in the directory
 * @uname_len:	length of the name @uname in Unicode characters
 *
 * Look for an inode with name @uname in the directory with inode @dir_ni.
 * ntfs_lookup_inode_by_name() walks the contents of the directory looking for
 * the Unicode name. If the name is found in the directory, the corresponding
 * inode number (>= 0) is returned as a mft reference in cpu format, i.e. it
 * is a 64-bit number containing the sequence number.
 *
 * On error, a negative value is returned corresponding to the error code. In
 * particular if the inode is not found -ENOENT is returned. Note that you
 * can't just check the return value for being negative, you have to check the
 * inode number for being negative which you can extract using MREC(return
 * value).
 *
 * Note, @uname_len does not include the (optional) terminating NULL character.
 */
u64 ntfs_lookup_inode_by_name(ntfs_inode *dir_ni, const ntfschar *uname,
		const int uname_len)
{
	ntfs_volume *vol = dir_ni->vol;
	struct super_block *sb = vol->sb;
	MFT_RECORD *m;
	INDEX_ROOT *ir;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *index_end;
	u64 mref;
	ntfs_attr_search_ctx *ctx;
	int err, rc;
	IGNORE_CASE_BOOL ic;
	VCN vcn, old_vcn;
	struct address_space *ia_mapping;
	struct page *page;
	u8 *kaddr;

	/* Get hold of the mft record for the directory. */
	m = map_mft_record(dir_ni);
	if (IS_ERR(m)) {
		ntfs_error(sb, "map_mft_record() failed with error code %ld.",
				-PTR_ERR(m));
		return ERR_MREF(PTR_ERR(m));
	}
	ctx = ntfs_attr_get_search_ctx(dir_ni, m);
	if (!ctx) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, I30, 4, CASE_SENSITIVE, 0, NULL,
			0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
			err = -EIO;
		}
		goto err_out;
	}
	/* Get to the index root value (it's been verified in read_inode). */
	ir = (INDEX_ROOT*)((u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset));
	index_end = (u8*)&ir->index + le32_to_cpu(ir->index.index_length);
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ir->index +
			le32_to_cpu(ir->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)ctx->mrec || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end)
			goto dir_err_out;
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/*
		 * If the current entry has a name type of POSIX, the name is
		 * case sensitive and not otherwise. This has the effect of us
		 * not being able to access any POSIX file names which collate
		 * after the non-POSIX one when they only differ in case, but
		 * anyone doing screwy stuff like that deserves to burn in
		 * hell... Doing that kind of stuff on NT4 actually causes
		 * corruption on the partition even when using SP6a and Linux
		 * is not involved at all.
		 */
		ic = ie->key.file_name.file_name_type ? IGNORE_CASE :
				CASE_SENSITIVE;
		/*
		 * If the names match perfectly, we are done and return the
		 * mft reference of the inode (i.e. the inode number together
		 * with the sequence number for consistency checking. We
		 * convert it to cpu format before returning.
		 */
		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, ic,
				vol->upcase, vol->upcase_len)) {
found_it:
			mref = le64_to_cpu(ie->data.dir.indexed_file);
			ntfs_attr_put_search_ctx(ctx);
			unmap_mft_record(dir_ni);
			return mref;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If uname collates before the name of the current entry, there
		 * is definitely no such name in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/* The names are not equal, continue the search. */
		if (rc)
			continue;
		/*
		 * Names match with case insensitive comparison, now try the
		 * case sensitive comparison, which is required for proper
		 * collation.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (rc == -1)
			break;
		if (rc)
			continue;
		/*
		 * Perfect match, this will never happen as the
		 * ntfs_are_names_equal() call will have gotten a match but we
		 * still treat it correctly.
		 */
		goto found_it;
	}
	/*
	 * We have finished with this index without success. Check for the
	 * presence of a child node.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		/* No child node, return -ENOENT. */
		err = -ENOENT;
		goto err_out;
	} /* Child node present, descend into it. */
	/* Consistency check: Verify that an index allocation exists. */
	if (!NInoIndexAllocPresent(dir_ni)) {
		ntfs_error(sb, "No index allocation attribute but index entry "
				"requires one. Directory inode 0x%lx is "
				"corrupt or driver bug.", dir_ni->mft_no);
		goto err_out;
	}
	/* Get the starting vcn of the index_block holding the child node. */
	vcn = sle64_to_cpup((u8*)ie + le16_to_cpu(ie->length) - 8);
	ia_mapping = VFS_I(dir_ni)->i_mapping;
	/*
	 * We are done with the index root and the mft record. Release them,
	 * otherwise we deadlock with ntfs_map_page().
	 */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(dir_ni);
	m = NULL;
	ctx = NULL;
descend_into_child_node:
	/*
	 * Convert vcn to index into the index allocation attribute in units
	 * of PAGE_CACHE_SIZE and map the page cache page, reading it from
	 * disk if necessary.
	 */
	page = ntfs_map_page(ia_mapping, vcn <<
			dir_ni->itype.index.vcn_size_bits >> PAGE_CACHE_SHIFT);
	if (IS_ERR(page)) {
		ntfs_error(sb, "Failed to map directory index page, error %ld.",
				-PTR_ERR(page));
		err = PTR_ERR(page);
		goto err_out;
	}
	lock_page(page);
	kaddr = (u8*)page_address(page);
fast_descend_into_child_node:
	/* Get to the index allocation block. */
	ia = (INDEX_ALLOCATION*)(kaddr + ((vcn <<
			dir_ni->itype.index.vcn_size_bits) & ~PAGE_CACHE_MASK));
	/* Bounds checks. */
	if ((u8*)ia < kaddr || (u8*)ia > kaddr + PAGE_CACHE_SIZE) {
		ntfs_error(sb, "Out of bounds check failed. Corrupt directory "
				"inode 0x%lx or driver bug.", dir_ni->mft_no);
		goto unm_err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic))) {
		ntfs_error(sb, "Directory index record with vcn 0x%llx is "
				"corrupt.  Corrupt inode 0x%lx.  Run chkdsk.",
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx). "
				"Directory inode 0x%lx is corrupt or driver "
				"bug.", (unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 !=
			dir_ni->itype.index.block_size) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx has a size (%u) differing from the "
				"directory specified size (%u). Directory "
				"inode is corrupt or driver bug.",
				(unsigned long long)vcn, dir_ni->mft_no,
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				dir_ni->itype.index.block_size);
		goto unm_err_out;
	}
	index_end = (u8*)ia + dir_ni->itype.index.block_size;
	if (index_end > kaddr + PAGE_CACHE_SIZE) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx crosses page boundary. Impossible! "
				"Cannot access! This is probably a bug in the "
				"driver.", (unsigned long long)vcn,
				dir_ni->mft_no);
		goto unm_err_out;
	}
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (index_end > (u8*)ia + dir_ni->itype.index.block_size) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of directory "
				"inode 0x%lx exceeds maximum size.",
				(unsigned long long)vcn, dir_ni->mft_no);
		goto unm_err_out;
	}
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ia->index +
			le32_to_cpu(ia->index.entries_offset));
	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds check. */
		if ((u8*)ie < (u8*)ia || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end) {
			ntfs_error(sb, "Index entry out of bounds in "
					"directory inode 0x%lx.",
					dir_ni->mft_no);
			goto unm_err_out;
		}
		/*
		 * The last entry cannot contain a name. It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/*
		 * If the current entry has a name type of POSIX, the name is
		 * case sensitive and not otherwise. This has the effect of us
		 * not being able to access any POSIX file names which collate
		 * after the non-POSIX one when they only differ in case, but
		 * anyone doing screwy stuff like that deserves to burn in
		 * hell... Doing that kind of stuff on NT4 actually causes
		 * corruption on the partition even when using SP6a and Linux
		 * is not involved at all.
		 */
		ic = ie->key.file_name.file_name_type ? IGNORE_CASE :
				CASE_SENSITIVE;
		/*
		 * If the names match perfectly, we are done and return the
		 * mft reference of the inode (i.e. the inode number together
		 * with the sequence number for consistency checking. We
		 * convert it to cpu format before returning.
		 */
		if (ntfs_are_names_equal(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, ic,
				vol->upcase, vol->upcase_len)) {
found_it2:
			mref = le64_to_cpu(ie->data.dir.indexed_file);
			unlock_page(page);
			ntfs_unmap_page(page);
			return mref;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				IGNORE_CASE, vol->upcase, vol->upcase_len);
		/*
		 * If uname collates before the name of the current entry, there
		 * is definitely no such name in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/* The names are not equal, continue the search. */
		if (rc)
			continue;
		/*
		 * Names match with case insensitive comparison, now try the
		 * case sensitive comparison, which is required for proper
		 * collation.
		 */
		rc = ntfs_collate_names(uname, uname_len,
				(ntfschar*)&ie->key.file_name.file_name,
				ie->key.file_name.file_name_length, 1,
				CASE_SENSITIVE, vol->upcase, vol->upcase_len);
		if (rc == -1)
			break;
		if (rc)
			continue;
		/*
		 * Perfect match, this will never happen as the
		 * ntfs_are_names_equal() call will have gotten a match but we
		 * still treat it correctly.
		 */
		goto found_it2;
	}
	/*
	 * We have finished with this index buffer without success. Check for
	 * the presence of a child node.
	 */
	if (ie->flags & INDEX_ENTRY_NODE) {
		if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
			ntfs_error(sb, "Index entry with child node found in "
					"a leaf node in directory inode 0x%lx.",
					dir_ni->mft_no);
			goto unm_err_out;
		}
		/* Child node present, descend into it. */
		old_vcn = vcn;
		vcn = sle64_to_cpup((u8*)ie + le16_to_cpu(ie->length) - 8);
		if (vcn >= 0) {
			/* If vcn is in the same page cache page as old_vcn we
			 * recycle the mapped page. */
			if (old_vcn << vol->cluster_size_bits >>
					PAGE_CACHE_SHIFT == vcn <<
					vol->cluster_size_bits >>
					PAGE_CACHE_SHIFT)
				goto fast_descend_into_child_node;
			unlock_page(page);
			ntfs_unmap_page(page);
			goto descend_into_child_node;
		}
		ntfs_error(sb, "Negative child node vcn in directory inode "
				"0x%lx.", dir_ni->mft_no);
		goto unm_err_out;
	}
	/* No child node, return -ENOENT. */
	ntfs_debug("Entry not found.");
	err = -ENOENT;
unm_err_out:
	unlock_page(page);
	ntfs_unmap_page(page);
err_out:
	if (!err)
		err = -EIO;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(dir_ni);
	return ERR_MREF(err);
dir_err_out:
	ntfs_error(sb, "Corrupt directory. Aborting lookup.");
	goto err_out;
}

#endif

/**
 * ntfs_filldir - ntfs specific filldir method
 * @vol:	current ntfs volume
 * @ndir:	ntfs inode of current directory
 * @ia_page:	page in which the index allocation buffer @ie is in resides
 * @ie:		current index entry
 * @name:	buffer to use for the converted name
 * @actor:	what to feed the entries to
 *
 * Convert the Unicode @name to the loaded NLS and pass it to the @filldir
 * callback.
 *
 * If @ia_page is not NULL it is the locked page containing the index
 * allocation block containing the index entry @ie.
 *
 * Note, we drop (and then reacquire) the page lock on @ia_page across the
 * @filldir() call otherwise we would deadlock with NFSd when it calls ->lookup
 * since ntfs_lookup() will lock the same page.  As an optimization, we do not
 * retake the lock if we are returning a non-zero value as ntfs_readdir()
 * would need to drop the lock immediately anyway.
 */
static inline int ntfs_filldir(ntfs_volume *vol,
		ntfs_inode *ndir, struct page *ia_page, INDEX_ENTRY *ie,
		u8 *name, struct dir_context *actor)
{
	unsigned long mref;
	int name_len;
	unsigned dt_type;
	FILE_NAME_TYPE_FLAGS name_type;

	name_type = ie->key.file_name.file_name_type;
	if (name_type == FILE_NAME_DOS) {
		ntfs_debug("Skipping DOS name space entry.");
		return 0;
	}
	if (MREF_LE(ie->data.dir.indexed_file) == FILE_root) {
		ntfs_debug("Skipping root directory self reference entry.");
		return 0;
	}
	if (MREF_LE(ie->data.dir.indexed_file) < FILE_first_user &&
			!NVolShowSystemFiles(vol)) {
		ntfs_debug("Skipping system file.");
		return 0;
	}
	name_len = ntfs_ucstonls(vol, (ntfschar*)&ie->key.file_name.file_name,
			ie->key.file_name.file_name_length, &name,
			NTFS_MAX_NAME_LEN * NLS_MAX_CHARSET_SIZE + 1);
	if (name_len <= 0) {
		ntfs_warning(vol->sb, "Skipping unrepresentable inode 0x%llx.",
				(long long)MREF_LE(ie->data.dir.indexed_file));
		return 0;
	}
	if (ie->key.file_name.file_attributes &
			FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT)
		dt_type = DT_DIR;
	else
		dt_type = DT_REG;
	mref = MREF_LE(ie->data.dir.indexed_file);
	/*
	 * Drop the page lock otherwise we deadlock with NFS when it calls
	 * ->lookup since ntfs_lookup() will lock the same page.
	 */
	if (ia_page)
		unlock_page(ia_page);
	ntfs_debug("Calling filldir for %s with len %i, fpos 0x%llx, inode "
			"0x%lx, DT_%s.", name, name_len, actor->pos, mref,
			dt_type == DT_DIR ? "DIR" : "REG");
	if (!dir_emit(actor, name, name_len, mref, dt_type))
		return 1;
	/* Relock the page but not if we are aborting ->readdir. */
	if (ia_page)
		lock_page(ia_page);
	return 0;
}

/*
 * We use the same basic approach as the old NTFS driver, i.e. we parse the
 * index root entries and then the index allocation entries that are marked
 * as in use in the index bitmap.
 *
 * While this will return the names in random order this doesn't matter for
 * ->readdir but OTOH results in a faster ->readdir.
 *
 * VFS calls ->readdir without BKL but with i_mutex held. This protects the VFS
 * parts (e.g. ->f_pos and ->i_size, and it also protects against directory
 * modifications).
 *
 * Locking:  - Caller must hold i_mutex on the directory.
 *	     - Each page cache page in the index allocation mapping must be
 *	       locked whilst being accessed otherwise we may find a corrupt
 *	       page due to it being under ->writepage at the moment which
 *	       applies the mst protection fixups before writing out and then
 *	       removes them again after the write is complete after which it 
 *	       unlocks the page.
 */
static int ntfs_readdir(struct file *file, struct dir_context *actor)
{
	s64 ia_pos, ia_start, prev_ia_pos, bmp_pos;
	loff_t i_size;
	struct inode *bmp_vi, *vdir = file_inode(file);
	struct super_block *sb = vdir->i_sb;
	ntfs_inode *ndir = NTFS_I(vdir);
	ntfs_volume *vol = NTFS_SB(sb);
	MFT_RECORD *m;
	INDEX_ROOT *ir = NULL;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *name = NULL;
	int rc, err, ir_pos, cur_bmp_pos;
	struct address_space *ia_mapping, *bmp_mapping;
	struct page *bmp_page = NULL, *ia_page = NULL;
	u8 *kaddr, *bmp, *index_end;
	ntfs_attr_search_ctx *ctx;

	ntfs_debug("Entering for inode 0x%lx, fpos 0x%llx.",
			vdir->i_ino, actor->pos);
	rc = err = 0;
	/* Are we at end of dir yet? */
	i_size = i_size_read(vdir);
	if (actor->pos >= i_size + vol->mft_record_size)
		return 0;
	/* Emulate . and .. for all directories. */
	if (!dir_emit_dots(file, actor))
		return 0;
	m = NULL;
	ctx = NULL;
	/*
	 * Allocate a buffer to store the current name being processed
	 * converted to format determined by current NLS.
	 */
	name = kmalloc(NTFS_MAX_NAME_LEN * NLS_MAX_CHARSET_SIZE + 1, GFP_NOFS);
	if (unlikely(!name)) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Are we jumping straight into the index allocation attribute? */
	if (actor->pos >= vol->mft_record_size)
		goto skip_index_root;
	/* Get hold of the mft record for the directory. */
	m = map_mft_record(ndir);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(ndir, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Get the offset into the index root attribute. */
	ir_pos = (s64)actor->pos;
	/* Find the index root attribute in the mft record. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, I30, 4, CASE_SENSITIVE, 0, NULL,
			0, ctx);
	if (unlikely(err)) {
		ntfs_error(sb, "Index root attribute missing in directory "
				"inode 0x%lx.", vdir->i_ino);
		goto err_out;
	}
	/*
	 * Copy the index root attribute value to a buffer so that we can put
	 * the search context and unmap the mft record before calling the
	 * filldir() callback.  We need to do this because of NFSd which calls
	 * ->lookup() from its filldir callback() and this causes NTFS to
	 * deadlock as ntfs_lookup() maps the mft record of the directory and
	 * we have got it mapped here already.  The only solution is for us to
	 * unmap the mft record here so that a call to ntfs_lookup() is able to
	 * map the mft record without deadlocking.
	 */
	rc = le32_to_cpu(ctx->attr->data.resident.value_length);
	ir = kmalloc(rc, GFP_NOFS);
	if (unlikely(!ir)) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Copy the index root value (it has been verified in read_inode). */
	memcpy(ir, (u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset), rc);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(ndir);
	ctx = NULL;
	m = NULL;
	index_end = (u8*)&ir->index + le32_to_cpu(ir->index.index_length);
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ir->index +
			le32_to_cpu(ir->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry or until filldir tells us it has had enough
	 * or signals an error (both covered by the rc test).
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		ntfs_debug("In index root, offset 0x%zx.", (u8*)ie - (u8*)ir);
		/* Bounds checks. */
		if (unlikely((u8*)ie < (u8*)ir || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end))
			goto err_out;
		/* The last entry cannot contain a name. */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* Skip index root entry if continuing previous readdir. */
		if (ir_pos > (u8*)ie - (u8*)ir)
			continue;
		/* Advance the position even if going to skip the entry. */
		actor->pos = (u8*)ie - (u8*)ir;
		/* Submit the name to the filldir callback. */
		rc = ntfs_filldir(vol, ndir, NULL, ie, name, actor);
		if (rc) {
			kfree(ir);
			goto abort;
		}
	}
	/* We are done with the index root and can free the buffer. */
	kfree(ir);
	ir = NULL;
	/* If there is no index allocation attribute we are finished. */
	if (!NInoIndexAllocPresent(ndir))
		goto EOD;
	/* Advance fpos to the beginning of the index allocation. */
	actor->pos = vol->mft_record_size;
skip_index_root:
	kaddr = NULL;
	prev_ia_pos = -1LL;
	/* Get the offset into the index allocation attribute. */
	ia_pos = (s64)actor->pos - vol->mft_record_size;
	ia_mapping = vdir->i_mapping;
	ntfs_debug("Inode 0x%lx, getting index bitmap.", vdir->i_ino);
	bmp_vi = ntfs_attr_iget(vdir, AT_BITMAP, I30, 4);
	if (IS_ERR(bmp_vi)) {
		ntfs_error(sb, "Failed to get bitmap attribute.");
		err = PTR_ERR(bmp_vi);
		goto err_out;
	}
	bmp_mapping = bmp_vi->i_mapping;
	/* Get the starting bitmap bit position and sanity check it. */
	bmp_pos = ia_pos >> ndir->itype.index.block_size_bits;
	if (unlikely(bmp_pos >> 3 >= i_size_read(bmp_vi))) {
		ntfs_error(sb, "Current index allocation position exceeds "
				"index bitmap size.");
		goto iput_err_out;
	}
	/* Get the starting bit position in the current bitmap page. */
	cur_bmp_pos = bmp_pos & ((PAGE_CACHE_SIZE * 8) - 1);
	bmp_pos &= ~(u64)((PAGE_CACHE_SIZE * 8) - 1);
get_next_bmp_page:
	ntfs_debug("Reading bitmap with page index 0x%llx, bit ofs 0x%llx",
			(unsigned long long)bmp_pos >> (3 + PAGE_CACHE_SHIFT),
			(unsigned long long)bmp_pos &
			(unsigned long long)((PAGE_CACHE_SIZE * 8) - 1));
	bmp_page = ntfs_map_page(bmp_mapping,
			bmp_pos >> (3 + PAGE_CACHE_SHIFT));
	if (IS_ERR(bmp_page)) {
		ntfs_error(sb, "Reading index bitmap failed.");
		err = PTR_ERR(bmp_page);
		bmp_page = NULL;
		goto iput_err_out;
	}
	bmp = (u8*)page_address(bmp_page);
	/* Find next index block in use. */
	while (!(bmp[cur_bmp_pos >> 3] & (1 << (cur_bmp_pos & 7)))) {
find_next_index_buffer:
		cur_bmp_pos++;
		/*
		 * If we have reached the end of the bitmap page, get the next
		 * page, and put away the old one.
		 */
		if (unlikely((cur_bmp_pos >> 3) >= PAGE_CACHE_SIZE)) {
			ntfs_unmap_page(bmp_page);
			bmp_pos += PAGE_CACHE_SIZE * 8;
			cur_bmp_pos = 0;
			goto get_next_bmp_page;
		}
		/* If we have reached the end of the bitmap, we are done. */
		if (unlikely(((bmp_pos + cur_bmp_pos) >> 3) >= i_size))
			goto unm_EOD;
		ia_pos = (bmp_pos + cur_bmp_pos) <<
				ndir->itype.index.block_size_bits;
	}
	ntfs_debug("Handling index buffer 0x%llx.",
			(unsigned long long)bmp_pos + cur_bmp_pos);
	/* If the current index buffer is in the same page we reuse the page. */
	if ((prev_ia_pos & (s64)PAGE_CACHE_MASK) !=
			(ia_pos & (s64)PAGE_CACHE_MASK)) {
		prev_ia_pos = ia_pos;
		if (likely(ia_page != NULL)) {
			unlock_page(ia_page);
			ntfs_unmap_page(ia_page);
		}
		/*
		 * Map the page cache page containing the current ia_pos,
		 * reading it from disk if necessary.
		 */
		ia_page = ntfs_map_page(ia_mapping, ia_pos >> PAGE_CACHE_SHIFT);
		if (IS_ERR(ia_page)) {
			ntfs_error(sb, "Reading index allocation data failed.");
			err = PTR_ERR(ia_page);
			ia_page = NULL;
			goto err_out;
		}
		lock_page(ia_page);
		kaddr = (u8*)page_address(ia_page);
	}
	/* Get the current index buffer. */
	ia = (INDEX_ALLOCATION*)(kaddr + (ia_pos & ~PAGE_CACHE_MASK &
			~(s64)(ndir->itype.index.block_size - 1)));
	/* Bounds checks. */
	if (unlikely((u8*)ia < kaddr || (u8*)ia > kaddr + PAGE_CACHE_SIZE)) {
		ntfs_error(sb, "Out of bounds check failed. Corrupt directory "
				"inode 0x%lx or driver bug.", vdir->i_ino);
		goto err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic))) {
		ntfs_error(sb, "Directory index record with vcn 0x%llx is "
				"corrupt.  Corrupt inode 0x%lx.  Run chkdsk.",
				(unsigned long long)ia_pos >>
				ndir->itype.index.vcn_size_bits, vdir->i_ino);
		goto err_out;
	}
	if (unlikely(sle64_to_cpu(ia->index_block_vcn) != (ia_pos &
			~(s64)(ndir->itype.index.block_size - 1)) >>
			ndir->itype.index.vcn_size_bits)) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx). "
				"Directory inode 0x%lx is corrupt or driver "
				"bug. ", (unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)ia_pos >>
				ndir->itype.index.vcn_size_bits, vdir->i_ino);
		goto err_out;
	}
	if (unlikely(le32_to_cpu(ia->index.allocated_size) + 0x18 !=
			ndir->itype.index.block_size)) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx has a size (%u) differing from the "
				"directory specified size (%u). Directory "
				"inode is corrupt or driver bug.",
				(unsigned long long)ia_pos >>
				ndir->itype.index.vcn_size_bits, vdir->i_ino,
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				ndir->itype.index.block_size);
		goto err_out;
	}
	index_end = (u8*)ia + ndir->itype.index.block_size;
	if (unlikely(index_end > kaddr + PAGE_CACHE_SIZE)) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of directory inode "
				"0x%lx crosses page boundary. Impossible! "
				"Cannot access! This is probably a bug in the "
				"driver.", (unsigned long long)ia_pos >>
				ndir->itype.index.vcn_size_bits, vdir->i_ino);
		goto err_out;
	}
	ia_start = ia_pos & ~(s64)(ndir->itype.index.block_size - 1);
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (unlikely(index_end > (u8*)ia + ndir->itype.index.block_size)) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of directory "
				"inode 0x%lx exceeds maximum size.",
				(unsigned long long)ia_pos >>
				ndir->itype.index.vcn_size_bits, vdir->i_ino);
		goto err_out;
	}
	/* The first index entry in this index buffer. */
	ie = (INDEX_ENTRY*)((u8*)&ia->index +
			le32_to_cpu(ia->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry or until filldir tells us it has had enough
	 * or signals an error (both covered by the rc test).
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		ntfs_debug("In index allocation, offset 0x%llx.",
				(unsigned long long)ia_start +
				(unsigned long long)((u8*)ie - (u8*)ia));
		/* Bounds checks. */
		if (unlikely((u8*)ie < (u8*)ia || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->key_length) >
				index_end))
			goto err_out;
		/* The last entry cannot contain a name. */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* Skip index block entry if continuing previous readdir. */
		if (ia_pos - ia_start > (u8*)ie - (u8*)ia)
			continue;
		/* Advance the position even if going to skip the entry. */
		actor->pos = (u8*)ie - (u8*)ia +
				(sle64_to_cpu(ia->index_block_vcn) <<
				ndir->itype.index.vcn_size_bits) +
				vol->mft_record_size;
		/*
		 * Submit the name to the @filldir callback.  Note,
		 * ntfs_filldir() drops the lock on @ia_page but it retakes it
		 * before returning, unless a non-zero value is returned in
		 * which case the page is left unlocked.
		 */
		rc = ntfs_filldir(vol, ndir, ia_page, ie, name, actor);
		if (rc) {
			/* @ia_page is already unlocked in this case. */
			ntfs_unmap_page(ia_page);
			ntfs_unmap_page(bmp_page);
			iput(bmp_vi);
			goto abort;
		}
	}
	goto find_next_index_buffer;
unm_EOD:
	if (ia_page) {
		unlock_page(ia_page);
		ntfs_unmap_page(ia_page);
	}
	ntfs_unmap_page(bmp_page);
	iput(bmp_vi);
EOD:
	/* We are finished, set fpos to EOD. */
	actor->pos = i_size + vol->mft_record_size;
abort:
	kfree(name);
	return 0;
err_out:
	if (bmp_page) {
		ntfs_unmap_page(bmp_page);
iput_err_out:
		iput(bmp_vi);
	}
	if (ia_page) {
		unlock_page(ia_page);
		ntfs_unmap_page(ia_page);
	}
	kfree(ir);
	kfree(name);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(ndir);
	if (!err)
		err = -EIO;
	ntfs_debug("Failed. Returning error code %i.", -err);
	return err;
}

/**
 * ntfs_dir_open - called when an inode is about to be opened
 * @vi:		inode to be opened
 * @filp:	file structure describing the inode
 *
 * Limit directory size to the page cache limit on architectures where unsigned
 * long is 32-bits. This is the most we can do for now without overflowing the
 * page cache page index. Doing it this way means we don't run into problems
 * because of existing too large directories. It would be better to allow the
 * user to read the accessible part of the directory but I doubt very much
 * anyone is going to hit this check on a 32-bit architecture, so there is no
 * point in adding the extra complexity required to support this.
 *
 * On 64-bit architectures, the check is hopefully optimized away by the
 * compiler.
 */
static int ntfs_dir_open(struct inode *vi, struct file *filp)
{
	if (sizeof(unsigned long) < 8) {
		if (i_size_read(vi) > MAX_LFS_FILESIZE)
			return -EFBIG;
	}
	return 0;
}

#ifdef NTFS_RW

/**
 * ntfs_dir_fsync - sync a directory to disk
 * @filp:	directory to be synced
 * @dentry:	dentry describing the directory to sync
 * @datasync:	if non-zero only flush user data and not metadata
 *
 * Data integrity sync of a directory to disk.  Used for fsync, fdatasync, and
 * msync system calls.  This function is based on file.c::ntfs_file_fsync().
 *
 * Write the mft record and all associated extent mft records as well as the
 * $INDEX_ALLOCATION and $BITMAP attributes and then sync the block device.
 *
 * If @datasync is true, we do not wait on the inode(s) to be written out
 * but we always wait on the page cache pages to be written out.
 *
 * Note: In the past @filp could be NULL so we ignore it as we don't need it
 * anyway.
 *
 * Locking: Caller must hold i_mutex on the inode.
 *
 * TODO: We should probably also write all attribute/index inodes associated
 * with this inode but since we have no simple way of getting to them we ignore
 * this problem for now.  We do write the $BITMAP attribute if it is present
 * which is the important one for a directory so things are not too bad.
 */
static int ntfs_dir_fsync(struct file *filp, loff_t start, loff_t end,
			  int datasync)
{
	struct inode *bmp_vi, *vi = filp->f_mapping->host;
	int err, ret;
	ntfs_attr na;

	ntfs_debug("Entering for inode 0x%lx.", vi->i_ino);

	err = filemap_write_and_wait_range(vi->i_mapping, start, end);
	if (err)
		return err;
	mutex_lock(&vi->i_mutex);

	BUG_ON(!S_ISDIR(vi->i_mode));
	/* If the bitmap attribute inode is in memory sync it, too. */
	na.mft_no = vi->i_ino;
	na.type = AT_BITMAP;
	na.name = I30;
	na.name_len = 4;
	bmp_vi = ilookup5(vi->i_sb, vi->i_ino, (test_t)ntfs_test_inode, &na);
	if (bmp_vi) {
 		write_inode_now(bmp_vi, !datasync);
		iput(bmp_vi);
	}
	ret = __ntfs_write_inode(vi, 1);
	write_inode_now(vi, !datasync);
	err = sync_blockdev(vi->i_sb->s_bdev);
	if (unlikely(err && !ret))
		ret = err;
	if (likely(!ret))
		ntfs_debug("Done.");
	else
		ntfs_warning(vi->i_sb, "Failed to f%ssync inode 0x%lx.  Error "
				"%u.", datasync ? "data" : "", vi->i_ino, -ret);
	mutex_unlock(&vi->i_mutex);
	return ret;
}

#endif /* NTFS_RW */

const struct file_operations ntfs_dir_ops = {
	.llseek		= generic_file_llseek,	/* Seek inside directory. */
	.read		= generic_read_dir,	/* Return -EISDIR. */
	.iterate	= ntfs_readdir,		/* Read directory contents. */
#ifdef NTFS_RW
	.fsync		= ntfs_dir_fsync,	/* Sync a directory to disk. */
	/*.aio_fsync	= ,*/			/* Sync all outstanding async
						   i/o operations on a kiocb. */
#endif /* NTFS_RW */
	/*.ioctl	= ,*/			/* Perform function on the
						   mounted filesystem. */
	.open		= ntfs_dir_open,	/* Open directory. */
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/dir.c */
/************************************************************/
/*
 * file.c - NTFS kernel file operations.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2014 Anton Altaparmakov and Tuxera Inc.
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/backing-dev.h>
// #include <linux/buffer_head.h>
// #include <linux/gfp.h>
// #include <linux/pagemap.h>
#include <linux/pagevec.h>
// #include <linux/sched.h>
// #include <linux/swap.h>
#include <linux/uio.h>
// #include <linux/writeback.h>
#include <linux/aio.h>
#include "../../inc/__fss.h"

#include <asm/page.h>
#include <asm/uaccess.h>
#include "../../inc/__fss.h"

// #include "attrib.h"
#include "bitmap.h"
// #include "inode.h"
// #include "debug.h"
// #include "lcnalloc.h"
// #include "malloc.h"
// #include "mft.h"
// #include "ntfs.h"
#include "../../inc/__fss.h"

/**
 * ntfs_file_open - called when an inode is about to be opened
 * @vi:		inode to be opened
 * @filp:	file structure describing the inode
 *
 * Limit file size to the page cache limit on architectures where unsigned long
 * is 32-bits. This is the most we can do for now without overflowing the page
 * cache page index. Doing it this way means we don't run into problems because
 * of existing too large files. It would be better to allow the user to read
 * the beginning of the file but I doubt very much anyone is going to hit this
 * check on a 32-bit architecture, so there is no point in adding the extra
 * complexity required to support this.
 *
 * On 64-bit architectures, the check is hopefully optimized away by the
 * compiler.
 *
 * After the check passes, just call generic_file_open() to do its work.
 */
static int ntfs_file_open(struct inode *vi, struct file *filp)
{
	if (sizeof(unsigned long) < 8) {
		if (i_size_read(vi) > MAX_LFS_FILESIZE)
			return -EOVERFLOW;
	}
	return generic_file_open(vi, filp);
}

#ifdef NTFS_RW

/**
 * ntfs_attr_extend_initialized - extend the initialized size of an attribute
 * @ni:			ntfs inode of the attribute to extend
 * @new_init_size:	requested new initialized size in bytes
 *
 * Extend the initialized size of an attribute described by the ntfs inode @ni
 * to @new_init_size bytes.  This involves zeroing any non-sparse space between
 * the old initialized size and @new_init_size both in the page cache and on
 * disk (if relevant complete pages are already uptodate in the page cache then
 * these are simply marked dirty).
 *
 * As a side-effect, the file size (vfs inode->i_size) may be incremented as,
 * in the resident attribute case, it is tied to the initialized size and, in
 * the non-resident attribute case, it may not fall below the initialized size.
 *
 * Note that if the attribute is resident, we do not need to touch the page
 * cache at all.  This is because if the page cache page is not uptodate we
 * bring it uptodate later, when doing the write to the mft record since we
 * then already have the page mapped.  And if the page is uptodate, the
 * non-initialized region will already have been zeroed when the page was
 * brought uptodate and the region may in fact already have been overwritten
 * with new data via mmap() based writes, so we cannot just zero it.  And since
 * POSIX specifies that the behaviour of resizing a file whilst it is mmap()ped
 * is unspecified, we choose not to do zeroing and thus we do not need to touch
 * the page at all.  For a more detailed explanation see ntfs_truncate() in
 * fs/ntfs/inode.c.
 *
 * Return 0 on success and -errno on error.  In the case that an error is
 * encountered it is possible that the initialized size will already have been
 * incremented some way towards @new_init_size but it is guaranteed that if
 * this is the case, the necessary zeroing will also have happened and that all
 * metadata is self-consistent.
 *
 * Locking: i_mutex on the vfs inode corrseponsind to the ntfs inode @ni must be
 *	    held by the caller.
 */
static int ntfs_attr_extend_initialized(ntfs_inode *ni, const s64 new_init_size)
{
	s64 old_init_size;
	loff_t old_i_size;
	pgoff_t index, end_index;
	unsigned long flags;
	struct inode *vi = VFS_I(ni);
	ntfs_inode *base_ni;
	MFT_RECORD *m = NULL;
	ATTR_RECORD *a;
	ntfs_attr_search_ctx *ctx = NULL;
	struct address_space *mapping;
	struct page *page = NULL;
	u8 *kattr;
	int err;
	u32 attr_len;

	read_lock_irqsave(&ni->size_lock, flags);
	old_init_size = ni->initialized_size;
	old_i_size = i_size_read(vi);
	BUG_ON(new_init_size > ni->allocated_size);
	read_unlock_irqrestore(&ni->size_lock, flags);
	ntfs_debug("Entering for i_ino 0x%lx, attribute type 0x%x, "
			"old_initialized_size 0x%llx, "
			"new_initialized_size 0x%llx, i_size 0x%llx.",
			vi->i_ino, (unsigned)le32_to_cpu(ni->type),
			(unsigned long long)old_init_size,
			(unsigned long long)new_init_size, old_i_size);
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	/* Use goto to reduce indentation and we need the label below anyway. */
	if (NInoNonResident(ni))
		goto do_non_resident_extend;
	BUG_ON(old_init_size != old_i_size);
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			err = -EIO;
		goto err_out;
	}
	m = ctx->mrec;
	a = ctx->attr;
	BUG_ON(a->non_resident);
	/* The total length of the attribute value. */
	attr_len = le32_to_cpu(a->data.resident.value_length);
	BUG_ON(old_i_size != (loff_t)attr_len);
	/*
	 * Do the zeroing in the mft record and update the attribute size in
	 * the mft record.
	 */
	kattr = (u8*)a + le16_to_cpu(a->data.resident.value_offset);
	memset(kattr + attr_len, 0, new_init_size - attr_len);
	a->data.resident.value_length = cpu_to_le32((u32)new_init_size);
	/* Finally, update the sizes in the vfs and ntfs inodes. */
	write_lock_irqsave(&ni->size_lock, flags);
	i_size_write(vi, new_init_size);
	ni->initialized_size = new_init_size;
	write_unlock_irqrestore(&ni->size_lock, flags);
	goto done;
do_non_resident_extend:
	/*
	 * If the new initialized size @new_init_size exceeds the current file
	 * size (vfs inode->i_size), we need to extend the file size to the
	 * new initialized size.
	 */
	if (new_init_size > old_i_size) {
		m = map_mft_record(base_ni);
		if (IS_ERR(m)) {
			err = PTR_ERR(m);
			m = NULL;
			goto err_out;
		}
		ctx = ntfs_attr_get_search_ctx(base_ni, m);
		if (unlikely(!ctx)) {
			err = -ENOMEM;
			goto err_out;
		}
		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, 0, NULL, 0, ctx);
		if (unlikely(err)) {
			if (err == -ENOENT)
				err = -EIO;
			goto err_out;
		}
		m = ctx->mrec;
		a = ctx->attr;
		BUG_ON(!a->non_resident);
		BUG_ON(old_i_size != (loff_t)
				sle64_to_cpu(a->data.non_resident.data_size));
		a->data.non_resident.data_size = cpu_to_sle64(new_init_size);
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
		/* Update the file size in the vfs inode. */
		i_size_write(vi, new_init_size);
		ntfs_attr_put_search_ctx(ctx);
		ctx = NULL;
		unmap_mft_record(base_ni);
		m = NULL;
	}
	mapping = vi->i_mapping;
	index = old_init_size >> PAGE_CACHE_SHIFT;
	end_index = (new_init_size + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	do {
		/*
		 * Read the page.  If the page is not present, this will zero
		 * the uninitialized regions for us.
		 */
		page = read_mapping_page(mapping, index, NULL);
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			goto init_err_out;
		}
		if (unlikely(PageError(page))) {
			page_cache_release(page);
			err = -EIO;
			goto init_err_out;
		}
		/*
		 * Update the initialized size in the ntfs inode.  This is
		 * enough to make ntfs_writepage() work.
		 */
		write_lock_irqsave(&ni->size_lock, flags);
		ni->initialized_size = (s64)(index + 1) << PAGE_CACHE_SHIFT;
		if (ni->initialized_size > new_init_size)
			ni->initialized_size = new_init_size;
		write_unlock_irqrestore(&ni->size_lock, flags);
		/* Set the page dirty so it gets written out. */
		set_page_dirty(page);
		page_cache_release(page);
		/*
		 * Play nice with the vm and the rest of the system.  This is
		 * very much needed as we can potentially be modifying the
		 * initialised size from a very small value to a really huge
		 * value, e.g.
		 *	f = open(somefile, O_TRUNC);
		 *	truncate(f, 10GiB);
		 *	seek(f, 10GiB);
		 *	write(f, 1);
		 * And this would mean we would be marking dirty hundreds of
		 * thousands of pages or as in the above example more than
		 * two and a half million pages!
		 *
		 * TODO: For sparse pages could optimize this workload by using
		 * the FsMisc / MiscFs page bit as a "PageIsSparse" bit.  This
		 * would be set in readpage for sparse pages and here we would
		 * not need to mark dirty any pages which have this bit set.
		 * The only caveat is that we have to clear the bit everywhere
		 * where we allocate any clusters that lie in the page or that
		 * contain the page.
		 *
		 * TODO: An even greater optimization would be for us to only
		 * call readpage() on pages which are not in sparse regions as
		 * determined from the runlist.  This would greatly reduce the
		 * number of pages we read and make dirty in the case of sparse
		 * files.
		 */
		balance_dirty_pages_ratelimited(mapping);
		cond_resched();
	} while (++index < end_index);
	read_lock_irqsave(&ni->size_lock, flags);
	BUG_ON(ni->initialized_size != new_init_size);
	read_unlock_irqrestore(&ni->size_lock, flags);
	/* Now bring in sync the initialized_size in the mft record. */
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		goto init_err_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto init_err_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			err = -EIO;
		goto init_err_out;
	}
	m = ctx->mrec;
	a = ctx->attr;
	BUG_ON(!a->non_resident);
	a->data.non_resident.initialized_size = cpu_to_sle64(new_init_size);
done:
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	ntfs_debug("Done, initialized_size 0x%llx, i_size 0x%llx.",
			(unsigned long long)new_init_size, i_size_read(vi));
	return 0;
init_err_out:
	write_lock_irqsave(&ni->size_lock, flags);
	ni->initialized_size = old_init_size;
	write_unlock_irqrestore(&ni->size_lock, flags);
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	ntfs_debug("Failed.  Returning error code %i.", err);
	return err;
}

/**
 * ntfs_fault_in_pages_readable -
 *
 * Fault a number of userspace pages into pagetables.
 *
 * Unlike include/linux/pagemap.h::fault_in_pages_readable(), this one copes
 * with more than two userspace pages as well as handling the single page case
 * elegantly.
 *
 * If you find this difficult to understand, then think of the while loop being
 * the following code, except that we do without the integer variable ret:
 *
 *	do {
 *		ret = __get_user(c, uaddr);
 *		uaddr += PAGE_SIZE;
 *	} while (!ret && uaddr < end);
 *
 * Note, the final __get_user() may well run out-of-bounds of the user buffer,
 * but _not_ out-of-bounds of the page the user buffer belongs to, and since
 * this is only a read and not a write, and since it is still in the same page,
 * it should not matter and this makes the code much simpler.
 */
static inline void ntfs_fault_in_pages_readable(const char __user *uaddr,
		int bytes)
{
	const char __user *end;
	volatile char c;

	/* Set @end to the first byte outside the last page we care about. */
	end = (const char __user*)PAGE_ALIGN((unsigned long)uaddr + bytes);

	while (!__get_user(c, uaddr) && (uaddr += PAGE_SIZE, uaddr < end))
		;
}

/**
 * ntfs_fault_in_pages_readable_iovec -
 *
 * Same as ntfs_fault_in_pages_readable() but operates on an array of iovecs.
 */
static inline void ntfs_fault_in_pages_readable_iovec(const struct iovec *iov,
		size_t iov_ofs, int bytes)
{
	do {
		const char __user *buf;
		unsigned len;

		buf = iov->iov_base + iov_ofs;
		len = iov->iov_len - iov_ofs;
		if (len > bytes)
			len = bytes;
		ntfs_fault_in_pages_readable(buf, len);
		bytes -= len;
		iov++;
		iov_ofs = 0;
	} while (bytes);
}

/**
 * __ntfs_grab_cache_pages - obtain a number of locked pages
 * @mapping:	address space mapping from which to obtain page cache pages
 * @index:	starting index in @mapping at which to begin obtaining pages
 * @nr_pages:	number of page cache pages to obtain
 * @pages:	array of pages in which to return the obtained page cache pages
 * @cached_page: allocated but as yet unused page
 *
 * Obtain @nr_pages locked page cache pages from the mapping @mapping and
 * starting at index @index.
 *
 * If a page is newly created, add it to lru list
 *
 * Note, the page locks are obtained in ascending page index order.
 */
static inline int __ntfs_grab_cache_pages(struct address_space *mapping,
		pgoff_t index, const unsigned nr_pages, struct page **pages,
		struct page **cached_page)
{
	int err, nr;

	BUG_ON(!nr_pages);
	err = nr = 0;
	do {
		pages[nr] = find_get_page_flags(mapping, index, FGP_LOCK |
				FGP_ACCESSED);
		if (!pages[nr]) {
			if (!*cached_page) {
				*cached_page = page_cache_alloc(mapping);
				if (unlikely(!*cached_page)) {
					err = -ENOMEM;
					goto err_out;
				}
			}
			err = add_to_page_cache_lru(*cached_page, mapping, index,
					GFP_KERNEL);
			if (unlikely(err)) {
				if (err == -EEXIST)
					continue;
				goto err_out;
			}
			pages[nr] = *cached_page;
			*cached_page = NULL;
		}
		index++;
		nr++;
	} while (nr < nr_pages);
out:
	return err;
err_out:
	while (nr > 0) {
		unlock_page(pages[--nr]);
		page_cache_release(pages[nr]);
	}
	goto out;
}

static inline int ntfs_submit_bh_for_read(struct buffer_head *bh)
{
	lock_buffer(bh);
	get_bh(bh);
	bh->b_end_io = end_buffer_read_sync;
	return submit_bh(READ, bh);
}

/**
 * ntfs_prepare_pages_for_non_resident_write - prepare pages for receiving data
 * @pages:	array of destination pages
 * @nr_pages:	number of pages in @pages
 * @pos:	byte position in file at which the write begins
 * @bytes:	number of bytes to be written
 *
 * This is called for non-resident attributes from ntfs_file_buffered_write()
 * with i_mutex held on the inode (@pages[0]->mapping->host).  There are
 * @nr_pages pages in @pages which are locked but not kmap()ped.  The source
 * data has not yet been copied into the @pages.
 * 
 * Need to fill any holes with actual clusters, allocate buffers if necessary,
 * ensure all the buffers are mapped, and bring uptodate any buffers that are
 * only partially being written to.
 *
 * If @nr_pages is greater than one, we are guaranteed that the cluster size is
 * greater than PAGE_CACHE_SIZE, that all pages in @pages are entirely inside
 * the same cluster and that they are the entirety of that cluster, and that
 * the cluster is sparse, i.e. we need to allocate a cluster to fill the hole.
 *
 * i_size is not to be modified yet.
 *
 * Return 0 on success or -errno on error.
 */
static int ntfs_prepare_pages_for_non_resident_write(struct page **pages,
		unsigned nr_pages, s64 pos, size_t bytes)
{
	VCN vcn, highest_vcn = 0, cpos, cend, bh_cpos, bh_cend;
	LCN lcn;
	s64 bh_pos, vcn_len, end, initialized_size;
	sector_t lcn_block;
	struct page *page;
	struct inode *vi;
	ntfs_inode *ni, *base_ni = NULL;
	ntfs_volume *vol;
	runlist_element *rl, *rl2;
	struct buffer_head *bh, *head, *wait[2], **wait_bh = wait;
	ntfs_attr_search_ctx *ctx = NULL;
	MFT_RECORD *m = NULL;
	ATTR_RECORD *a = NULL;
	unsigned long flags;
	u32 attr_rec_len = 0;
	unsigned blocksize, u;
	int err, mp_size;
	bool rl_write_locked, was_hole, is_retry;
	unsigned char blocksize_bits;
	struct {
		u8 runlist_merged:1;
		u8 mft_attr_mapped:1;
		u8 mp_rebuilt:1;
		u8 attr_switched:1;
	} status = { 0, 0, 0, 0 };

	BUG_ON(!nr_pages);
	BUG_ON(!pages);
	BUG_ON(!*pages);
	vi = pages[0]->mapping->host;
	ni = NTFS_I(vi);
	vol = ni->vol;
	ntfs_debug("Entering for inode 0x%lx, attribute type 0x%x, start page "
			"index 0x%lx, nr_pages 0x%x, pos 0x%llx, bytes 0x%zx.",
			vi->i_ino, ni->type, pages[0]->index, nr_pages,
			(long long)pos, bytes);
	blocksize = vol->sb->s_blocksize;
	blocksize_bits = vol->sb->s_blocksize_bits;
	u = 0;
	do {
		page = pages[u];
		BUG_ON(!page);
		/*
		 * create_empty_buffers() will create uptodate/dirty buffers if
		 * the page is uptodate/dirty.
		 */
		if (!page_has_buffers(page)) {
			create_empty_buffers(page, blocksize, 0);
			if (unlikely(!page_has_buffers(page)))
				return -ENOMEM;
		}
	} while (++u < nr_pages);
	rl_write_locked = false;
	rl = NULL;
	err = 0;
	vcn = lcn = -1;
	vcn_len = 0;
	lcn_block = -1;
	was_hole = false;
	cpos = pos >> vol->cluster_size_bits;
	end = pos + bytes;
	cend = (end + vol->cluster_size - 1) >> vol->cluster_size_bits;
	/*
	 * Loop over each page and for each page over each buffer.  Use goto to
	 * reduce indentation.
	 */
	u = 0;
do_next_page:
	page = pages[u];
	bh_pos = (s64)page->index << PAGE_CACHE_SHIFT;
	bh = head = page_buffers(page);
	do {
		VCN cdelta;
		s64 bh_end;
		unsigned bh_cofs;

		/* Clear buffer_new on all buffers to reinitialise state. */
		if (buffer_new(bh))
			clear_buffer_new(bh);
		bh_end = bh_pos + blocksize;
		bh_cpos = bh_pos >> vol->cluster_size_bits;
		bh_cofs = bh_pos & vol->cluster_size_mask;
		if (buffer_mapped(bh)) {
			/*
			 * The buffer is already mapped.  If it is uptodate,
			 * ignore it.
			 */
			if (buffer_uptodate(bh))
				continue;
			/*
			 * The buffer is not uptodate.  If the page is uptodate
			 * set the buffer uptodate and otherwise ignore it.
			 */
			if (PageUptodate(page)) {
				set_buffer_uptodate(bh);
				continue;
			}
			/*
			 * Neither the page nor the buffer are uptodate.  If
			 * the buffer is only partially being written to, we
			 * need to read it in before the write, i.e. now.
			 */
			if ((bh_pos < pos && bh_end > pos) ||
					(bh_pos < end && bh_end > end)) {
				/*
				 * If the buffer is fully or partially within
				 * the initialized size, do an actual read.
				 * Otherwise, simply zero the buffer.
				 */
				read_lock_irqsave(&ni->size_lock, flags);
				initialized_size = ni->initialized_size;
				read_unlock_irqrestore(&ni->size_lock, flags);
				if (bh_pos < initialized_size) {
					ntfs_submit_bh_for_read(bh);
					*wait_bh++ = bh;
				} else {
					zero_user(page, bh_offset(bh),
							blocksize);
					set_buffer_uptodate(bh);
				}
			}
			continue;
		}
		/* Unmapped buffer.  Need to map it. */
		bh->b_bdev = vol->sb->s_bdev;
		/*
		 * If the current buffer is in the same clusters as the map
		 * cache, there is no need to check the runlist again.  The
		 * map cache is made up of @vcn, which is the first cached file
		 * cluster, @vcn_len which is the number of cached file
		 * clusters, @lcn is the device cluster corresponding to @vcn,
		 * and @lcn_block is the block number corresponding to @lcn.
		 */
		cdelta = bh_cpos - vcn;
		if (likely(!cdelta || (cdelta > 0 && cdelta < vcn_len))) {
map_buffer_cached:
			BUG_ON(lcn < 0);
			bh->b_blocknr = lcn_block +
					(cdelta << (vol->cluster_size_bits -
					blocksize_bits)) +
					(bh_cofs >> blocksize_bits);
			set_buffer_mapped(bh);
			/*
			 * If the page is uptodate so is the buffer.  If the
			 * buffer is fully outside the write, we ignore it if
			 * it was already allocated and we mark it dirty so it
			 * gets written out if we allocated it.  On the other
			 * hand, if we allocated the buffer but we are not
			 * marking it dirty we set buffer_new so we can do
			 * error recovery.
			 */
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
				if (unlikely(was_hole)) {
					/* We allocated the buffer. */
					unmap_underlying_metadata(bh->b_bdev,
							bh->b_blocknr);
					if (bh_end <= pos || bh_pos >= end)
						mark_buffer_dirty(bh);
					else
						set_buffer_new(bh);
				}
				continue;
			}
			/* Page is _not_ uptodate. */
			if (likely(!was_hole)) {
				/*
				 * Buffer was already allocated.  If it is not
				 * uptodate and is only partially being written
				 * to, we need to read it in before the write,
				 * i.e. now.
				 */
				if (!buffer_uptodate(bh) && bh_pos < end &&
						bh_end > pos &&
						(bh_pos < pos ||
						bh_end > end)) {
					/*
					 * If the buffer is fully or partially
					 * within the initialized size, do an
					 * actual read.  Otherwise, simply zero
					 * the buffer.
					 */
					read_lock_irqsave(&ni->size_lock,
							flags);
					initialized_size = ni->initialized_size;
					read_unlock_irqrestore(&ni->size_lock,
							flags);
					if (bh_pos < initialized_size) {
						ntfs_submit_bh_for_read(bh);
						*wait_bh++ = bh;
					} else {
						zero_user(page, bh_offset(bh),
								blocksize);
						set_buffer_uptodate(bh);
					}
				}
				continue;
			}
			/* We allocated the buffer. */
			unmap_underlying_metadata(bh->b_bdev, bh->b_blocknr);
			/*
			 * If the buffer is fully outside the write, zero it,
			 * set it uptodate, and mark it dirty so it gets
			 * written out.  If it is partially being written to,
			 * zero region surrounding the write but leave it to
			 * commit write to do anything else.  Finally, if the
			 * buffer is fully being overwritten, do nothing.
			 */
			if (bh_end <= pos || bh_pos >= end) {
				if (!buffer_uptodate(bh)) {
					zero_user(page, bh_offset(bh),
							blocksize);
					set_buffer_uptodate(bh);
				}
				mark_buffer_dirty(bh);
				continue;
			}
			set_buffer_new(bh);
			if (!buffer_uptodate(bh) &&
					(bh_pos < pos || bh_end > end)) {
				u8 *kaddr;
				unsigned pofs;
					
				kaddr = kmap_atomic(page);
				if (bh_pos < pos) {
					pofs = bh_pos & ~PAGE_CACHE_MASK;
					memset(kaddr + pofs, 0, pos - bh_pos);
				}
				if (bh_end > end) {
					pofs = end & ~PAGE_CACHE_MASK;
					memset(kaddr + pofs, 0, bh_end - end);
				}
				kunmap_atomic(kaddr);
				flush_dcache_page(page);
			}
			continue;
		}
		/*
		 * Slow path: this is the first buffer in the cluster.  If it
		 * is outside allocated size and is not uptodate, zero it and
		 * set it uptodate.
		 */
		read_lock_irqsave(&ni->size_lock, flags);
		initialized_size = ni->allocated_size;
		read_unlock_irqrestore(&ni->size_lock, flags);
		if (bh_pos > initialized_size) {
			if (PageUptodate(page)) {
				if (!buffer_uptodate(bh))
					set_buffer_uptodate(bh);
			} else if (!buffer_uptodate(bh)) {
				zero_user(page, bh_offset(bh), blocksize);
				set_buffer_uptodate(bh);
			}
			continue;
		}
		is_retry = false;
		if (!rl) {
			down_read(&ni->runlist.lock);
retry_remap:
			rl = ni->runlist.rl;
		}
		if (likely(rl != NULL)) {
			/* Seek to element containing target cluster. */
			while (rl->length && rl[1].vcn <= bh_cpos)
				rl++;
			lcn = ntfs_rl_vcn_to_lcn(rl, bh_cpos);
			if (likely(lcn >= 0)) {
				/*
				 * Successful remap, setup the map cache and
				 * use that to deal with the buffer.
				 */
				was_hole = false;
				vcn = bh_cpos;
				vcn_len = rl[1].vcn - vcn;
				lcn_block = lcn << (vol->cluster_size_bits -
						blocksize_bits);
				cdelta = 0;
				/*
				 * If the number of remaining clusters touched
				 * by the write is smaller or equal to the
				 * number of cached clusters, unlock the
				 * runlist as the map cache will be used from
				 * now on.
				 */
				if (likely(vcn + vcn_len >= cend)) {
					if (rl_write_locked) {
						up_write(&ni->runlist.lock);
						rl_write_locked = false;
					} else
						up_read(&ni->runlist.lock);
					rl = NULL;
				}
				goto map_buffer_cached;
			}
		} else
			lcn = LCN_RL_NOT_MAPPED;
		/*
		 * If it is not a hole and not out of bounds, the runlist is
		 * probably unmapped so try to map it now.
		 */
		if (unlikely(lcn != LCN_HOLE && lcn != LCN_ENOENT)) {
			if (likely(!is_retry && lcn == LCN_RL_NOT_MAPPED)) {
				/* Attempt to map runlist. */
				if (!rl_write_locked) {
					/*
					 * We need the runlist locked for
					 * writing, so if it is locked for
					 * reading relock it now and retry in
					 * case it changed whilst we dropped
					 * the lock.
					 */
					up_read(&ni->runlist.lock);
					down_write(&ni->runlist.lock);
					rl_write_locked = true;
					goto retry_remap;
				}
				err = ntfs_map_runlist_nolock(ni, bh_cpos,
						NULL);
				if (likely(!err)) {
					is_retry = true;
					goto retry_remap;
				}
				/*
				 * If @vcn is out of bounds, pretend @lcn is
				 * LCN_ENOENT.  As long as the buffer is out
				 * of bounds this will work fine.
				 */
				if (err == -ENOENT) {
					lcn = LCN_ENOENT;
					err = 0;
					goto rl_not_mapped_enoent;
				}
			} else
				err = -EIO;
			/* Failed to map the buffer, even after retrying. */
			bh->b_blocknr = -1;
			ntfs_error(vol->sb, "Failed to write to inode 0x%lx, "
					"attribute type 0x%x, vcn 0x%llx, "
					"vcn offset 0x%x, because its "
					"location on disk could not be "
					"determined%s (error code %i).",
					ni->mft_no, ni->type,
					(unsigned long long)bh_cpos,
					(unsigned)bh_pos &
					vol->cluster_size_mask,
					is_retry ? " even after retrying" : "",
					err);
			break;
		}
rl_not_mapped_enoent:
		/*
		 * The buffer is in a hole or out of bounds.  We need to fill
		 * the hole, unless the buffer is in a cluster which is not
		 * touched by the write, in which case we just leave the buffer
		 * unmapped.  This can only happen when the cluster size is
		 * less than the page cache size.
		 */
		if (unlikely(vol->cluster_size < PAGE_CACHE_SIZE)) {
			bh_cend = (bh_end + vol->cluster_size - 1) >>
					vol->cluster_size_bits;
			if ((bh_cend <= cpos || bh_cpos >= cend)) {
				bh->b_blocknr = -1;
				/*
				 * If the buffer is uptodate we skip it.  If it
				 * is not but the page is uptodate, we can set
				 * the buffer uptodate.  If the page is not
				 * uptodate, we can clear the buffer and set it
				 * uptodate.  Whether this is worthwhile is
				 * debatable and this could be removed.
				 */
				if (PageUptodate(page)) {
					if (!buffer_uptodate(bh))
						set_buffer_uptodate(bh);
				} else if (!buffer_uptodate(bh)) {
					zero_user(page, bh_offset(bh),
						blocksize);
					set_buffer_uptodate(bh);
				}
				continue;
			}
		}
		/*
		 * Out of bounds buffer is invalid if it was not really out of
		 * bounds.
		 */
		BUG_ON(lcn != LCN_HOLE);
		/*
		 * We need the runlist locked for writing, so if it is locked
		 * for reading relock it now and retry in case it changed
		 * whilst we dropped the lock.
		 */
		BUG_ON(!rl);
		if (!rl_write_locked) {
			up_read(&ni->runlist.lock);
			down_write(&ni->runlist.lock);
			rl_write_locked = true;
			goto retry_remap;
		}
		/* Find the previous last allocated cluster. */
		BUG_ON(rl->lcn != LCN_HOLE);
		lcn = -1;
		rl2 = rl;
		while (--rl2 >= ni->runlist.rl) {
			if (rl2->lcn >= 0) {
				lcn = rl2->lcn + rl2->length;
				break;
			}
		}
		rl2 = ntfs_cluster_alloc(vol, bh_cpos, 1, lcn, DATA_ZONE,
				false);
		if (IS_ERR(rl2)) {
			err = PTR_ERR(rl2);
			ntfs_debug("Failed to allocate cluster, error code %i.",
					err);
			break;
		}
		lcn = rl2->lcn;
		rl = ntfs_runlists_merge(ni->runlist.rl, rl2);
		if (IS_ERR(rl)) {
			err = PTR_ERR(rl);
			if (err != -ENOMEM)
				err = -EIO;
			if (ntfs_cluster_free_from_rl(vol, rl2)) {
				ntfs_error(vol->sb, "Failed to release "
						"allocated cluster in error "
						"code path.  Run chkdsk to "
						"recover the lost cluster.");
				NVolSetErrors(vol);
			}
			ntfs_free(rl2);
			break;
		}
		ni->runlist.rl = rl;
		status.runlist_merged = 1;
		ntfs_debug("Allocated cluster, lcn 0x%llx.",
				(unsigned long long)lcn);
		/* Map and lock the mft record and get the attribute record. */
		if (!NInoAttr(ni))
			base_ni = ni;
		else
			base_ni = ni->ext.base_ntfs_ino;
		m = map_mft_record(base_ni);
		if (IS_ERR(m)) {
			err = PTR_ERR(m);
			break;
		}
		ctx = ntfs_attr_get_search_ctx(base_ni, m);
		if (unlikely(!ctx)) {
			err = -ENOMEM;
			unmap_mft_record(base_ni);
			break;
		}
		status.mft_attr_mapped = 1;
		err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, bh_cpos, NULL, 0, ctx);
		if (unlikely(err)) {
			if (err == -ENOENT)
				err = -EIO;
			break;
		}
		m = ctx->mrec;
		a = ctx->attr;
		/*
		 * Find the runlist element with which the attribute extent
		 * starts.  Note, we cannot use the _attr_ version because we
		 * have mapped the mft record.  That is ok because we know the
		 * runlist fragment must be mapped already to have ever gotten
		 * here, so we can just use the _rl_ version.
		 */
		vcn = sle64_to_cpu(a->data.non_resident.lowest_vcn);
		rl2 = ntfs_rl_find_vcn_nolock(rl, vcn);
		BUG_ON(!rl2);
		BUG_ON(!rl2->length);
		BUG_ON(rl2->lcn < LCN_HOLE);
		highest_vcn = sle64_to_cpu(a->data.non_resident.highest_vcn);
		/*
		 * If @highest_vcn is zero, calculate the real highest_vcn
		 * (which can really be zero).
		 */
		if (!highest_vcn)
			highest_vcn = (sle64_to_cpu(
					a->data.non_resident.allocated_size) >>
					vol->cluster_size_bits) - 1;
		/*
		 * Determine the size of the mapping pairs array for the new
		 * extent, i.e. the old extent with the hole filled.
		 */
		mp_size = ntfs_get_size_for_mapping_pairs(vol, rl2, vcn,
				highest_vcn);
		if (unlikely(mp_size <= 0)) {
			if (!(err = mp_size))
				err = -EIO;
			ntfs_debug("Failed to get size for mapping pairs "
					"array, error code %i.", err);
			break;
		}
		/*
		 * Resize the attribute record to fit the new mapping pairs
		 * array.
		 */
		attr_rec_len = le32_to_cpu(a->length);
		err = ntfs_attr_record_resize(m, a, mp_size + le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset));
		if (unlikely(err)) {
			BUG_ON(err != -ENOSPC);
			// TODO: Deal with this by using the current attribute
			// and fill it with as much of the mapping pairs
			// array as possible.  Then loop over each attribute
			// extent rewriting the mapping pairs arrays as we go
			// along and if when we reach the end we have not
			// enough space, try to resize the last attribute
			// extent and if even that fails, add a new attribute
			// extent.
			// We could also try to resize at each step in the hope
			// that we will not need to rewrite every single extent.
			// Note, we may need to decompress some extents to fill
			// the runlist as we are walking the extents...
			ntfs_error(vol->sb, "Not enough space in the mft "
					"record for the extended attribute "
					"record.  This case is not "
					"implemented yet.");
			err = -EOPNOTSUPP;
			break ;
		}
		status.mp_rebuilt = 1;
		/*
		 * Generate the mapping pairs array directly into the attribute
		 * record.
		 */
		err = ntfs_mapping_pairs_build(vol, (u8*)a + le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset),
				mp_size, rl2, vcn, highest_vcn, NULL);
		if (unlikely(err)) {
			ntfs_error(vol->sb, "Cannot fill hole in inode 0x%lx, "
					"attribute type 0x%x, because building "
					"the mapping pairs failed with error "
					"code %i.", vi->i_ino,
					(unsigned)le32_to_cpu(ni->type), err);
			err = -EIO;
			break;
		}
		/* Update the highest_vcn but only if it was not set. */
		if (unlikely(!a->data.non_resident.highest_vcn))
			a->data.non_resident.highest_vcn =
					cpu_to_sle64(highest_vcn);
		/*
		 * If the attribute is sparse/compressed, update the compressed
		 * size in the ntfs_inode structure and the attribute record.
		 */
		if (likely(NInoSparse(ni) || NInoCompressed(ni))) {
			/*
			 * If we are not in the first attribute extent, switch
			 * to it, but first ensure the changes will make it to
			 * disk later.
			 */
			if (a->data.non_resident.lowest_vcn) {
				flush_dcache_mft_record_page(ctx->ntfs_ino);
				mark_mft_record_dirty(ctx->ntfs_ino);
				ntfs_attr_reinit_search_ctx(ctx);
				err = ntfs_attr_lookup(ni->type, ni->name,
						ni->name_len, CASE_SENSITIVE,
						0, NULL, 0, ctx);
				if (unlikely(err)) {
					status.attr_switched = 1;
					break;
				}
				/* @m is not used any more so do not set it. */
				a = ctx->attr;
			}
			write_lock_irqsave(&ni->size_lock, flags);
			ni->itype.compressed.size += vol->cluster_size;
			a->data.non_resident.compressed_size =
					cpu_to_sle64(ni->itype.compressed.size);
			write_unlock_irqrestore(&ni->size_lock, flags);
		}
		/* Ensure the changes make it to disk. */
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(base_ni);
		/* Successfully filled the hole. */
		status.runlist_merged = 0;
		status.mft_attr_mapped = 0;
		status.mp_rebuilt = 0;
		/* Setup the map cache and use that to deal with the buffer. */
		was_hole = true;
		vcn = bh_cpos;
		vcn_len = 1;
		lcn_block = lcn << (vol->cluster_size_bits - blocksize_bits);
		cdelta = 0;
		/*
		 * If the number of remaining clusters in the @pages is smaller
		 * or equal to the number of cached clusters, unlock the
		 * runlist as the map cache will be used from now on.
		 */
		if (likely(vcn + vcn_len >= cend)) {
			up_write(&ni->runlist.lock);
			rl_write_locked = false;
			rl = NULL;
		}
		goto map_buffer_cached;
	} while (bh_pos += blocksize, (bh = bh->b_this_page) != head);
	/* If there are no errors, do the next page. */
	if (likely(!err && ++u < nr_pages))
		goto do_next_page;
	/* If there are no errors, release the runlist lock if we took it. */
	if (likely(!err)) {
		if (unlikely(rl_write_locked)) {
			up_write(&ni->runlist.lock);
			rl_write_locked = false;
		} else if (unlikely(rl))
			up_read(&ni->runlist.lock);
		rl = NULL;
	}
	/* If we issued read requests, let them complete. */
	read_lock_irqsave(&ni->size_lock, flags);
	initialized_size = ni->initialized_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	while (wait_bh > wait) {
		bh = *--wait_bh;
		wait_on_buffer(bh);
		if (likely(buffer_uptodate(bh))) {
			page = bh->b_page;
			bh_pos = ((s64)page->index << PAGE_CACHE_SHIFT) +
					bh_offset(bh);
			/*
			 * If the buffer overflows the initialized size, need
			 * to zero the overflowing region.
			 */
			if (unlikely(bh_pos + blocksize > initialized_size)) {
				int ofs = 0;

				if (likely(bh_pos < initialized_size))
					ofs = initialized_size - bh_pos;
				zero_user_segment(page, bh_offset(bh) + ofs,
						blocksize);
			}
		} else /* if (unlikely(!buffer_uptodate(bh))) */
			err = -EIO;
	}
	if (likely(!err)) {
		/* Clear buffer_new on all buffers. */
		u = 0;
		do {
			bh = head = page_buffers(pages[u]);
			do {
				if (buffer_new(bh))
					clear_buffer_new(bh);
			} while ((bh = bh->b_this_page) != head);
		} while (++u < nr_pages);
		ntfs_debug("Done.");
		return err;
	}
	if (status.attr_switched) {
		/* Get back to the attribute extent we modified. */
		ntfs_attr_reinit_search_ctx(ctx);
		if (ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
				CASE_SENSITIVE, bh_cpos, NULL, 0, ctx)) {
			ntfs_error(vol->sb, "Failed to find required "
					"attribute extent of attribute in "
					"error code path.  Run chkdsk to "
					"recover.");
			write_lock_irqsave(&ni->size_lock, flags);
			ni->itype.compressed.size += vol->cluster_size;
			write_unlock_irqrestore(&ni->size_lock, flags);
			flush_dcache_mft_record_page(ctx->ntfs_ino);
			mark_mft_record_dirty(ctx->ntfs_ino);
			/*
			 * The only thing that is now wrong is the compressed
			 * size of the base attribute extent which chkdsk
			 * should be able to fix.
			 */
			NVolSetErrors(vol);
		} else {
			m = ctx->mrec;
			a = ctx->attr;
			status.attr_switched = 0;
		}
	}
	/*
	 * If the runlist has been modified, need to restore it by punching a
	 * hole into it and we then need to deallocate the on-disk cluster as
	 * well.  Note, we only modify the runlist if we are able to generate a
	 * new mapping pairs array, i.e. only when the mapped attribute extent
	 * is not switched.
	 */
	if (status.runlist_merged && !status.attr_switched) {
		BUG_ON(!rl_write_locked);
		/* Make the file cluster we allocated sparse in the runlist. */
		if (ntfs_rl_punch_nolock(vol, &ni->runlist, bh_cpos, 1)) {
			ntfs_error(vol->sb, "Failed to punch hole into "
					"attribute runlist in error code "
					"path.  Run chkdsk to recover the "
					"lost cluster.");
			NVolSetErrors(vol);
		} else /* if (success) */ {
			status.runlist_merged = 0;
			/*
			 * Deallocate the on-disk cluster we allocated but only
			 * if we succeeded in punching its vcn out of the
			 * runlist.
			 */
			down_write(&vol->lcnbmp_lock);
			if (ntfs_bitmap_clear_bit(vol->lcnbmp_ino, lcn)) {
				ntfs_error(vol->sb, "Failed to release "
						"allocated cluster in error "
						"code path.  Run chkdsk to "
						"recover the lost cluster.");
				NVolSetErrors(vol);
			}
			up_write(&vol->lcnbmp_lock);
		}
	}
	/*
	 * Resize the attribute record to its old size and rebuild the mapping
	 * pairs array.  Note, we only can do this if the runlist has been
	 * restored to its old state which also implies that the mapped
	 * attribute extent is not switched.
	 */
	if (status.mp_rebuilt && !status.runlist_merged) {
		if (ntfs_attr_record_resize(m, a, attr_rec_len)) {
			ntfs_error(vol->sb, "Failed to restore attribute "
					"record in error code path.  Run "
					"chkdsk to recover.");
			NVolSetErrors(vol);
		} else /* if (success) */ {
			if (ntfs_mapping_pairs_build(vol, (u8*)a +
					le16_to_cpu(a->data.non_resident.
					mapping_pairs_offset), attr_rec_len -
					le16_to_cpu(a->data.non_resident.
					mapping_pairs_offset), ni->runlist.rl,
					vcn, highest_vcn, NULL)) {
				ntfs_error(vol->sb, "Failed to restore "
						"mapping pairs array in error "
						"code path.  Run chkdsk to "
						"recover.");
				NVolSetErrors(vol);
			}
			flush_dcache_mft_record_page(ctx->ntfs_ino);
			mark_mft_record_dirty(ctx->ntfs_ino);
		}
	}
	/* Release the mft record and the attribute. */
	if (status.mft_attr_mapped) {
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(base_ni);
	}
	/* Release the runlist lock. */
	if (rl_write_locked)
		up_write(&ni->runlist.lock);
	else if (rl)
		up_read(&ni->runlist.lock);
	/*
	 * Zero out any newly allocated blocks to avoid exposing stale data.
	 * If BH_New is set, we know that the block was newly allocated above
	 * and that it has not been fully zeroed and marked dirty yet.
	 */
	nr_pages = u;
	u = 0;
	end = bh_cpos << vol->cluster_size_bits;
	do {
		page = pages[u];
		bh = head = page_buffers(page);
		do {
			if (u == nr_pages &&
					((s64)page->index << PAGE_CACHE_SHIFT) +
					bh_offset(bh) >= end)
				break;
			if (!buffer_new(bh))
				continue;
			clear_buffer_new(bh);
			if (!buffer_uptodate(bh)) {
				if (PageUptodate(page))
					set_buffer_uptodate(bh);
				else {
					zero_user(page, bh_offset(bh),
							blocksize);
					set_buffer_uptodate(bh);
				}
			}
			mark_buffer_dirty(bh);
		} while ((bh = bh->b_this_page) != head);
	} while (++u <= nr_pages);
	ntfs_error(vol->sb, "Failed.  Returning error code %i.", err);
	return err;
}

/*
 * Copy as much as we can into the pages and return the number of bytes which
 * were successfully copied.  If a fault is encountered then clear the pages
 * out to (ofs + bytes) and return the number of bytes which were copied.
 */
static inline size_t ntfs_copy_from_user(struct page **pages,
		unsigned nr_pages, unsigned ofs, const char __user *buf,
		size_t bytes)
{
	struct page **last_page = pages + nr_pages;
	char *addr;
	size_t total = 0;
	unsigned len;
	int left;

	do {
		len = PAGE_CACHE_SIZE - ofs;
		if (len > bytes)
			len = bytes;
		addr = kmap_atomic(*pages);
		left = __copy_from_user_inatomic(addr + ofs, buf, len);
		kunmap_atomic(addr);
		if (unlikely(left)) {
			/* Do it the slow way. */
			addr = kmap(*pages);
			left = __copy_from_user(addr + ofs, buf, len);
			kunmap(*pages);
			if (unlikely(left))
				goto err_out;
		}
		total += len;
		bytes -= len;
		if (!bytes)
			break;
		buf += len;
		ofs = 0;
	} while (++pages < last_page);
out:
	return total;
err_out:
	total += len - left;
	/* Zero the rest of the target like __copy_from_user(). */
	while (++pages < last_page) {
		bytes -= len;
		if (!bytes)
			break;
		len = PAGE_CACHE_SIZE;
		if (len > bytes)
			len = bytes;
		zero_user(*pages, 0, len);
	}
	goto out;
}

static size_t __ntfs_copy_from_user_iovec_inatomic(char *vaddr,
		const struct iovec *iov, size_t iov_ofs, size_t bytes)
{
	size_t total = 0;

	while (1) {
		const char __user *buf = iov->iov_base + iov_ofs;
		unsigned len;
		size_t left;

		len = iov->iov_len - iov_ofs;
		if (len > bytes)
			len = bytes;
		left = __copy_from_user_inatomic(vaddr, buf, len);
		total += len;
		bytes -= len;
		vaddr += len;
		if (unlikely(left)) {
			total -= left;
			break;
		}
		if (!bytes)
			break;
		iov++;
		iov_ofs = 0;
	}
	return total;
}

static inline void ntfs_set_next_iovec(const struct iovec **iovp,
		size_t *iov_ofsp, size_t bytes)
{
	const struct iovec *iov = *iovp;
	size_t iov_ofs = *iov_ofsp;

	while (bytes) {
		unsigned len;

		len = iov->iov_len - iov_ofs;
		if (len > bytes)
			len = bytes;
		bytes -= len;
		iov_ofs += len;
		if (iov->iov_len == iov_ofs) {
			iov++;
			iov_ofs = 0;
		}
	}
	*iovp = iov;
	*iov_ofsp = iov_ofs;
}

/*
 * This has the same side-effects and return value as ntfs_copy_from_user().
 * The difference is that on a fault we need to memset the remainder of the
 * pages (out to offset + bytes), to emulate ntfs_copy_from_user()'s
 * single-segment behaviour.
 *
 * We call the same helper (__ntfs_copy_from_user_iovec_inatomic()) both when
 * atomic and when not atomic.  This is ok because it calls
 * __copy_from_user_inatomic() and it is ok to call this when non-atomic.  In
 * fact, the only difference between __copy_from_user_inatomic() and
 * __copy_from_user() is that the latter calls might_sleep() and the former
 * should not zero the tail of the buffer on error.  And on many architectures
 * __copy_from_user_inatomic() is just defined to __copy_from_user() so it
 * makes no difference at all on those architectures.
 */
static inline size_t ntfs_copy_from_user_iovec(struct page **pages,
		unsigned nr_pages, unsigned ofs, const struct iovec **iov,
		size_t *iov_ofs, size_t bytes)
{
	struct page **last_page = pages + nr_pages;
	char *addr;
	size_t copied, len, total = 0;

	do {
		len = PAGE_CACHE_SIZE - ofs;
		if (len > bytes)
			len = bytes;
		addr = kmap_atomic(*pages);
		copied = __ntfs_copy_from_user_iovec_inatomic(addr + ofs,
				*iov, *iov_ofs, len);
		kunmap_atomic(addr);
		if (unlikely(copied != len)) {
			/* Do it the slow way. */
			addr = kmap(*pages);
			copied = __ntfs_copy_from_user_iovec_inatomic(addr +
					ofs, *iov, *iov_ofs, len);
			if (unlikely(copied != len))
				goto err_out;
			kunmap(*pages);
		}
		total += len;
		ntfs_set_next_iovec(iov, iov_ofs, len);
		bytes -= len;
		if (!bytes)
			break;
		ofs = 0;
	} while (++pages < last_page);
out:
	return total;
err_out:
	BUG_ON(copied > len);
	/* Zero the rest of the target like __copy_from_user(). */
	memset(addr + ofs + copied, 0, len - copied);
	kunmap(*pages);
	total += copied;
	ntfs_set_next_iovec(iov, iov_ofs, copied);
	while (++pages < last_page) {
		bytes -= len;
		if (!bytes)
			break;
		len = PAGE_CACHE_SIZE;
		if (len > bytes)
			len = bytes;
		zero_user(*pages, 0, len);
	}
	goto out;
}

static inline void ntfs_flush_dcache_pages(struct page **pages,
		unsigned nr_pages)
{
	BUG_ON(!nr_pages);
	/*
	 * Warning: Do not do the decrement at the same time as the call to
	 * flush_dcache_page() because it is a NULL macro on i386 and hence the
	 * decrement never happens so the loop never terminates.
	 */
	do {
		--nr_pages;
		flush_dcache_page(pages[nr_pages]);
	} while (nr_pages > 0);
}

/**
 * ntfs_commit_pages_after_non_resident_write - commit the received data
 * @pages:	array of destination pages
 * @nr_pages:	number of pages in @pages
 * @pos:	byte position in file at which the write begins
 * @bytes:	number of bytes to be written
 *
 * See description of ntfs_commit_pages_after_write(), below.
 */
static inline int ntfs_commit_pages_after_non_resident_write(
		struct page **pages, const unsigned nr_pages,
		s64 pos, size_t bytes)
{
	s64 end, initialized_size;
	struct inode *vi;
	ntfs_inode *ni, *base_ni;
	struct buffer_head *bh, *head;
	ntfs_attr_search_ctx *ctx;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	unsigned long flags;
	unsigned blocksize, u;
	int err;

	vi = pages[0]->mapping->host;
	ni = NTFS_I(vi);
	blocksize = vi->i_sb->s_blocksize;
	end = pos + bytes;
	u = 0;
	do {
		s64 bh_pos;
		struct page *page;
		bool partial;

		page = pages[u];
		bh_pos = (s64)page->index << PAGE_CACHE_SHIFT;
		bh = head = page_buffers(page);
		partial = false;
		do {
			s64 bh_end;

			bh_end = bh_pos + blocksize;
			if (bh_end <= pos || bh_pos >= end) {
				if (!buffer_uptodate(bh))
					partial = true;
			} else {
				set_buffer_uptodate(bh);
				mark_buffer_dirty(bh);
			}
		} while (bh_pos += blocksize, (bh = bh->b_this_page) != head);
		/*
		 * If all buffers are now uptodate but the page is not, set the
		 * page uptodate.
		 */
		if (!partial && !PageUptodate(page))
			SetPageUptodate(page);
	} while (++u < nr_pages);
	/*
	 * Finally, if we do not need to update initialized_size or i_size we
	 * are finished.
	 */
	read_lock_irqsave(&ni->size_lock, flags);
	initialized_size = ni->initialized_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (end <= initialized_size) {
		ntfs_debug("Done.");
		return 0;
	}
	/*
	 * Update initialized_size/i_size as appropriate, both in the inode and
	 * the mft record.
	 */
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	/* Map, pin, and lock the mft record. */
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		ctx = NULL;
		goto err_out;
	}
	BUG_ON(!NInoNonResident(ni));
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			err = -EIO;
		goto err_out;
	}
	a = ctx->attr;
	BUG_ON(!a->non_resident);
	write_lock_irqsave(&ni->size_lock, flags);
	BUG_ON(end > ni->allocated_size);
	ni->initialized_size = end;
	a->data.non_resident.initialized_size = cpu_to_sle64(end);
	if (end > i_size_read(vi)) {
		i_size_write(vi, end);
		a->data.non_resident.data_size =
				a->data.non_resident.initialized_size;
	}
	write_unlock_irqrestore(&ni->size_lock, flags);
	/* Mark the mft record dirty, so it gets written back. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	ntfs_debug("Done.");
	return 0;
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	ntfs_error(vi->i_sb, "Failed to update initialized_size/i_size (error "
			"code %i).", err);
	if (err != -ENOMEM)
		NVolSetErrors(ni->vol);
	return err;
}

/**
 * ntfs_commit_pages_after_write - commit the received data
 * @pages:	array of destination pages
 * @nr_pages:	number of pages in @pages
 * @pos:	byte position in file at which the write begins
 * @bytes:	number of bytes to be written
 *
 * This is called from ntfs_file_buffered_write() with i_mutex held on the inode
 * (@pages[0]->mapping->host).  There are @nr_pages pages in @pages which are
 * locked but not kmap()ped.  The source data has already been copied into the
 * @page.  ntfs_prepare_pages_for_non_resident_write() has been called before
 * the data was copied (for non-resident attributes only) and it returned
 * success.
 *
 * Need to set uptodate and mark dirty all buffers within the boundary of the
 * write.  If all buffers in a page are uptodate we set the page uptodate, too.
 *
 * Setting the buffers dirty ensures that they get written out later when
 * ntfs_writepage() is invoked by the VM.
 *
 * Finally, we need to update i_size and initialized_size as appropriate both
 * in the inode and the mft record.
 *
 * This is modelled after fs/buffer.c::generic_commit_write(), which marks
 * buffers uptodate and dirty, sets the page uptodate if all buffers in the
 * page are uptodate, and updates i_size if the end of io is beyond i_size.  In
 * that case, it also marks the inode dirty.
 *
 * If things have gone as outlined in
 * ntfs_prepare_pages_for_non_resident_write(), we do not need to do any page
 * content modifications here for non-resident attributes.  For resident
 * attributes we need to do the uptodate bringing here which we combine with
 * the copying into the mft record which means we save one atomic kmap.
 *
 * Return 0 on success or -errno on error.
 */
static int ntfs_commit_pages_after_write(struct page **pages,
		const unsigned nr_pages, s64 pos, size_t bytes)
{
	s64 end, initialized_size;
	loff_t i_size;
	struct inode *vi;
	ntfs_inode *ni, *base_ni;
	struct page *page;
	ntfs_attr_search_ctx *ctx;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	char *kattr, *kaddr;
	unsigned long flags;
	u32 attr_len;
	int err;

	BUG_ON(!nr_pages);
	BUG_ON(!pages);
	page = pages[0];
	BUG_ON(!page);
	vi = page->mapping->host;
	ni = NTFS_I(vi);
	ntfs_debug("Entering for inode 0x%lx, attribute type 0x%x, start page "
			"index 0x%lx, nr_pages 0x%x, pos 0x%llx, bytes 0x%zx.",
			vi->i_ino, ni->type, page->index, nr_pages,
			(long long)pos, bytes);
	if (NInoNonResident(ni))
		return ntfs_commit_pages_after_non_resident_write(pages,
				nr_pages, pos, bytes);
	BUG_ON(nr_pages > 1);
	/*
	 * Attribute is resident, implying it is not compressed, encrypted, or
	 * sparse.
	 */
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	BUG_ON(NInoNonResident(ni));
	/* Map, pin, and lock the mft record. */
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		m = NULL;
		ctx = NULL;
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto err_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			err = -EIO;
		goto err_out;
	}
	a = ctx->attr;
	BUG_ON(a->non_resident);
	/* The total length of the attribute value. */
	attr_len = le32_to_cpu(a->data.resident.value_length);
	i_size = i_size_read(vi);
	BUG_ON(attr_len != i_size);
	BUG_ON(pos > attr_len);
	end = pos + bytes;
	BUG_ON(end > le32_to_cpu(a->length) -
			le16_to_cpu(a->data.resident.value_offset));
	kattr = (u8*)a + le16_to_cpu(a->data.resident.value_offset);
	kaddr = kmap_atomic(page);
	/* Copy the received data from the page to the mft record. */
	memcpy(kattr + pos, kaddr + pos, bytes);
	/* Update the attribute length if necessary. */
	if (end > attr_len) {
		attr_len = end;
		a->data.resident.value_length = cpu_to_le32(attr_len);
	}
	/*
	 * If the page is not uptodate, bring the out of bounds area(s)
	 * uptodate by copying data from the mft record to the page.
	 */
	if (!PageUptodate(page)) {
		if (pos > 0)
			memcpy(kaddr, kattr, pos);
		if (end < attr_len)
			memcpy(kaddr + end, kattr + end, attr_len - end);
		/* Zero the region outside the end of the attribute value. */
		memset(kaddr + attr_len, 0, PAGE_CACHE_SIZE - attr_len);
		flush_dcache_page(page);
		SetPageUptodate(page);
	}
	kunmap_atomic(kaddr);
	/* Update initialized_size/i_size if necessary. */
	read_lock_irqsave(&ni->size_lock, flags);
	initialized_size = ni->initialized_size;
	BUG_ON(end > ni->allocated_size);
	read_unlock_irqrestore(&ni->size_lock, flags);
	BUG_ON(initialized_size != i_size);
	if (end > initialized_size) {
		write_lock_irqsave(&ni->size_lock, flags);
		ni->initialized_size = end;
		i_size_write(vi, end);
		write_unlock_irqrestore(&ni->size_lock, flags);
	}
	/* Mark the mft record dirty, so it gets written back. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	ntfs_debug("Done.");
	return 0;
err_out:
	if (err == -ENOMEM) {
		ntfs_warning(vi->i_sb, "Error allocating memory required to "
				"commit the write.");
		if (PageUptodate(page)) {
			ntfs_warning(vi->i_sb, "Page is uptodate, setting "
					"dirty so the write will be retried "
					"later on by the VM.");
			/*
			 * Put the page on mapping->dirty_pages, but leave its
			 * buffers' dirty state as-is.
			 */
			__set_page_dirty_nobuffers(page);
			err = 0;
		} else
			ntfs_error(vi->i_sb, "Page is not uptodate.  Written "
					"data has been lost.");
	} else {
		ntfs_error(vi->i_sb, "Resident attribute commit write failed "
				"with error %i.", err);
		NVolSetErrors(ni->vol);
	}
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	return err;
}

static void ntfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		ntfs_truncate_vfs(inode);
	}
}

/**
 * ntfs_file_buffered_write -
 *
 * Locking: The vfs is holding ->i_mutex on the inode.
 */
static ssize_t ntfs_file_buffered_write(struct kiocb *iocb,
		const struct iovec *iov, unsigned long nr_segs,
		loff_t pos, loff_t *ppos, size_t count)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *vi = mapping->host;
	ntfs_inode *ni = NTFS_I(vi);
	ntfs_volume *vol = ni->vol;
	struct page *pages[NTFS_MAX_PAGES_PER_CLUSTER];
	struct page *cached_page = NULL;
	char __user *buf = NULL;
	s64 end, ll;
	VCN last_vcn;
	LCN lcn;
	unsigned long flags;
	size_t bytes, iov_ofs = 0;	/* Offset in the current iovec. */
	ssize_t status, written;
	unsigned nr_pages;
	int err;

	ntfs_debug("Entering for i_ino 0x%lx, attribute type 0x%x, "
			"pos 0x%llx, count 0x%lx.",
			vi->i_ino, (unsigned)le32_to_cpu(ni->type),
			(unsigned long long)pos, (unsigned long)count);
	if (unlikely(!count))
		return 0;
	BUG_ON(NInoMstProtected(ni));
	/*
	 * If the attribute is not an index root and it is encrypted or
	 * compressed, we cannot write to it yet.  Note we need to check for
	 * AT_INDEX_ALLOCATION since this is the type of both directory and
	 * index inodes.
	 */
	if (ni->type != AT_INDEX_ALLOCATION) {
		/* If file is encrypted, deny access, just like NT4. */
		if (NInoEncrypted(ni)) {
			/*
			 * Reminder for later: Encrypted files are _always_
			 * non-resident so that the content can always be
			 * encrypted.
			 */
			ntfs_debug("Denying write access to encrypted file.");
			return -EACCES;
		}
		if (NInoCompressed(ni)) {
			/* Only unnamed $DATA attribute can be compressed. */
			BUG_ON(ni->type != AT_DATA);
			BUG_ON(ni->name_len);
			/*
			 * Reminder for later: If resident, the data is not
			 * actually compressed.  Only on the switch to non-
			 * resident does compression kick in.  This is in
			 * contrast to encrypted files (see above).
			 */
			ntfs_error(vi->i_sb, "Writing to compressed files is "
					"not implemented yet.  Sorry.");
			return -EOPNOTSUPP;
		}
	}
	/*
	 * If a previous ntfs_truncate() failed, repeat it and abort if it
	 * fails again.
	 */
	if (unlikely(NInoTruncateFailed(ni))) {
		inode_dio_wait(vi);
		err = ntfs_truncate(vi);
		if (err || NInoTruncateFailed(ni)) {
			if (!err)
				err = -EIO;
			ntfs_error(vol->sb, "Cannot perform write to inode "
					"0x%lx, attribute type 0x%x, because "
					"ntfs_truncate() failed (error code "
					"%i).", vi->i_ino,
					(unsigned)le32_to_cpu(ni->type), err);
			return err;
		}
	}
	/* The first byte after the write. */
	end = pos + count;
	/*
	 * If the write goes beyond the allocated size, extend the allocation
	 * to cover the whole of the write, rounded up to the nearest cluster.
	 */
	read_lock_irqsave(&ni->size_lock, flags);
	ll = ni->allocated_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (end > ll) {
		/* Extend the allocation without changing the data size. */
		ll = ntfs_attr_extend_allocation(ni, end, -1, pos);
		if (likely(ll >= 0)) {
			BUG_ON(pos >= ll);
			/* If the extension was partial truncate the write. */
			if (end > ll) {
				ntfs_debug("Truncating write to inode 0x%lx, "
						"attribute type 0x%x, because "
						"the allocation was only "
						"partially extended.",
						vi->i_ino, (unsigned)
						le32_to_cpu(ni->type));
				end = ll;
				count = ll - pos;
			}
		} else {
			err = ll;
			read_lock_irqsave(&ni->size_lock, flags);
			ll = ni->allocated_size;
			read_unlock_irqrestore(&ni->size_lock, flags);
			/* Perform a partial write if possible or fail. */
			if (pos < ll) {
				ntfs_debug("Truncating write to inode 0x%lx, "
						"attribute type 0x%x, because "
						"extending the allocation "
						"failed (error code %i).",
						vi->i_ino, (unsigned)
						le32_to_cpu(ni->type), err);
				end = ll;
				count = ll - pos;
			} else {
				ntfs_error(vol->sb, "Cannot perform write to "
						"inode 0x%lx, attribute type "
						"0x%x, because extending the "
						"allocation failed (error "
						"code %i).", vi->i_ino,
						(unsigned)
						le32_to_cpu(ni->type), err);
				return err;
			}
		}
	}
	written = 0;
	/*
	 * If the write starts beyond the initialized size, extend it up to the
	 * beginning of the write and initialize all non-sparse space between
	 * the old initialized size and the new one.  This automatically also
	 * increments the vfs inode->i_size to keep it above or equal to the
	 * initialized_size.
	 */
	read_lock_irqsave(&ni->size_lock, flags);
	ll = ni->initialized_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	if (pos > ll) {
		err = ntfs_attr_extend_initialized(ni, pos);
		if (err < 0) {
			ntfs_error(vol->sb, "Cannot perform write to inode "
					"0x%lx, attribute type 0x%x, because "
					"extending the initialized size "
					"failed (error code %i).", vi->i_ino,
					(unsigned)le32_to_cpu(ni->type), err);
			status = err;
			goto err_out;
		}
	}
	/*
	 * Determine the number of pages per cluster for non-resident
	 * attributes.
	 */
	nr_pages = 1;
	if (vol->cluster_size > PAGE_CACHE_SIZE && NInoNonResident(ni))
		nr_pages = vol->cluster_size >> PAGE_CACHE_SHIFT;
	/* Finally, perform the actual write. */
	last_vcn = -1;
	if (likely(nr_segs == 1))
		buf = iov->iov_base;
	do {
		VCN vcn;
		pgoff_t idx, start_idx;
		unsigned ofs, do_pages, u;
		size_t copied;

		start_idx = idx = pos >> PAGE_CACHE_SHIFT;
		ofs = pos & ~PAGE_CACHE_MASK;
		bytes = PAGE_CACHE_SIZE - ofs;
		do_pages = 1;
		if (nr_pages > 1) {
			vcn = pos >> vol->cluster_size_bits;
			if (vcn != last_vcn) {
				last_vcn = vcn;
				/*
				 * Get the lcn of the vcn the write is in.  If
				 * it is a hole, need to lock down all pages in
				 * the cluster.
				 */
				down_read(&ni->runlist.lock);
				lcn = ntfs_attr_vcn_to_lcn_nolock(ni, pos >>
						vol->cluster_size_bits, false);
				up_read(&ni->runlist.lock);
				if (unlikely(lcn < LCN_HOLE)) {
					status = -EIO;
					if (lcn == LCN_ENOMEM)
						status = -ENOMEM;
					else
						ntfs_error(vol->sb, "Cannot "
							"perform write to "
							"inode 0x%lx, "
							"attribute type 0x%x, "
							"because the attribute "
							"is corrupt.",
							vi->i_ino, (unsigned)
							le32_to_cpu(ni->type));
					break;
				}
				if (lcn == LCN_HOLE) {
					start_idx = (pos & ~(s64)
							vol->cluster_size_mask)
							>> PAGE_CACHE_SHIFT;
					bytes = vol->cluster_size - (pos &
							vol->cluster_size_mask);
					do_pages = nr_pages;
				}
			}
		}
		if (bytes > count)
			bytes = count;
		/*
		 * Bring in the user page(s) that we will copy from _first_.
		 * Otherwise there is a nasty deadlock on copying from the same
		 * page(s) as we are writing to, without it/them being marked
		 * up-to-date.  Note, at present there is nothing to stop the
		 * pages being swapped out between us bringing them into memory
		 * and doing the actual copying.
		 */
		if (likely(nr_segs == 1))
			ntfs_fault_in_pages_readable(buf, bytes);
		else
			ntfs_fault_in_pages_readable_iovec(iov, iov_ofs, bytes);
		/* Get and lock @do_pages starting at index @start_idx. */
		status = __ntfs_grab_cache_pages(mapping, start_idx, do_pages,
				pages, &cached_page);
		if (unlikely(status))
			break;
		/*
		 * For non-resident attributes, we need to fill any holes with
		 * actual clusters and ensure all bufferes are mapped.  We also
		 * need to bring uptodate any buffers that are only partially
		 * being written to.
		 */
		if (NInoNonResident(ni)) {
			status = ntfs_prepare_pages_for_non_resident_write(
					pages, do_pages, pos, bytes);
			if (unlikely(status)) {
				loff_t i_size;

				do {
					unlock_page(pages[--do_pages]);
					page_cache_release(pages[do_pages]);
				} while (do_pages);
				/*
				 * The write preparation may have instantiated
				 * allocated space outside i_size.  Trim this
				 * off again.  We can ignore any errors in this
				 * case as we will just be waisting a bit of
				 * allocated space, which is not a disaster.
				 */
				i_size = i_size_read(vi);
				if (pos + bytes > i_size) {
					ntfs_write_failed(mapping, pos + bytes);
				}
				break;
			}
		}
		u = (pos >> PAGE_CACHE_SHIFT) - pages[0]->index;
		if (likely(nr_segs == 1)) {
			copied = ntfs_copy_from_user(pages + u, do_pages - u,
					ofs, buf, bytes);
			buf += copied;
		} else
			copied = ntfs_copy_from_user_iovec(pages + u,
					do_pages - u, ofs, &iov, &iov_ofs,
					bytes);
		ntfs_flush_dcache_pages(pages + u, do_pages - u);
		status = ntfs_commit_pages_after_write(pages, do_pages, pos,
				bytes);
		if (likely(!status)) {
			written += copied;
			count -= copied;
			pos += copied;
			if (unlikely(copied != bytes))
				status = -EFAULT;
		}
		do {
			unlock_page(pages[--do_pages]);
			page_cache_release(pages[do_pages]);
		} while (do_pages);
		if (unlikely(status))
			break;
		balance_dirty_pages_ratelimited(mapping);
		cond_resched();
	} while (count);
err_out:
	*ppos = pos;
	if (cached_page)
		page_cache_release(cached_page);
	ntfs_debug("Done.  Returning %s (written 0x%lx, status %li).",
			written ? "written" : "status", (unsigned long)written,
			(long)status);
	return written ? written : status;
}

/**
 * ntfs_file_aio_write_nolock -
 */
static ssize_t ntfs_file_aio_write_nolock(struct kiocb *iocb,
		const struct iovec *iov, unsigned long nr_segs, loff_t *ppos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	loff_t pos;
	size_t count;		/* after file limit checks */
	ssize_t written, err;

	count = iov_length(iov, nr_segs);
	pos = *ppos;
	/* We can write back this queue in page reclaim. */
	current->backing_dev_info = inode_to_bdi(inode);
	written = 0;
	err = generic_write_checks(file, &pos, &count, S_ISBLK(inode->i_mode));
	if (err)
		goto out;
	if (!count)
		goto out;
	err = file_remove_suid(file);
	if (err)
		goto out;
	err = file_update_time(file);
	if (err)
		goto out;
	written = ntfs_file_buffered_write(iocb, iov, nr_segs, pos, ppos,
			count);
out:
	current->backing_dev_info = NULL;
	return written ? written : err;
}

/**
 * ntfs_file_aio_write -
 */
static ssize_t ntfs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
		unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	ssize_t ret;

	BUG_ON(iocb->ki_pos != pos);

	mutex_lock(&inode->i_mutex);
	ret = ntfs_file_aio_write_nolock(iocb, iov, nr_segs, &iocb->ki_pos);
	mutex_unlock(&inode->i_mutex);
	if (ret > 0) {
		int err = generic_write_sync(file, iocb->ki_pos - ret, ret);
		if (err < 0)
			ret = err;
	}
	return ret;
}

/**
 * ntfs_file_fsync - sync a file to disk
 * @filp:	file to be synced
 * @datasync:	if non-zero only flush user data and not metadata
 *
 * Data integrity sync of a file to disk.  Used for fsync, fdatasync, and msync
 * system calls.  This function is inspired by fs/buffer.c::file_fsync().
 *
 * If @datasync is false, write the mft record and all associated extent mft
 * records as well as the $DATA attribute and then sync the block device.
 *
 * If @datasync is true and the attribute is non-resident, we skip the writing
 * of the mft record and all associated extent mft records (this might still
 * happen due to the write_inode_now() call).
 *
 * Also, if @datasync is true, we do not wait on the inode to be written out
 * but we always wait on the page cache pages to be written out.
 *
 * Locking: Caller must hold i_mutex on the inode.
 *
 * TODO: We should probably also write all attribute/index inodes associated
 * with this inode but since we have no simple way of getting to them we ignore
 * this problem for now.
 */
static int ntfs_file_fsync(struct file *filp, loff_t start, loff_t end,
			   int datasync)
{
	struct inode *vi = filp->f_mapping->host;
	int err, ret = 0;

	ntfs_debug("Entering for inode 0x%lx.", vi->i_ino);

	err = filemap_write_and_wait_range(vi->i_mapping, start, end);
	if (err)
		return err;
	mutex_lock(&vi->i_mutex);

	BUG_ON(S_ISDIR(vi->i_mode));
	if (!datasync || !NInoNonResident(NTFS_I(vi)))
		ret = __ntfs_write_inode(vi, 1);
	write_inode_now(vi, !datasync);
	/*
	 * NOTE: If we were to use mapping->private_list (see ext2 and
	 * fs/buffer.c) for dirty blocks then we could optimize the below to be
	 * sync_mapping_buffers(vi->i_mapping).
	 */
	err = sync_blockdev(vi->i_sb->s_bdev);
	if (unlikely(err && !ret))
		ret = err;
	if (likely(!ret))
		ntfs_debug("Done.");
	else
		ntfs_warning(vi->i_sb, "Failed to f%ssync inode 0x%lx.  Error "
				"%u.", datasync ? "data" : "", vi->i_ino, -ret);
	mutex_unlock(&vi->i_mutex);
	return ret;
}

#endif /* NTFS_RW */

const struct file_operations ntfs_file_ops = {
	.llseek		= generic_file_llseek,	 /* Seek inside file. */
	.read		= new_sync_read,	 /* Read from file. */
	.read_iter	= generic_file_read_iter, /* Async read from file. */
#ifdef NTFS_RW
	.write		= do_sync_write,	 /* Write to file. */
	.aio_write	= ntfs_file_aio_write,	 /* Async write to file. */
	/*.release	= ,*/			 /* Last file is closed.  See
						    fs/ext2/file.c::
						    ext2_release_file() for
						    how to use this to discard
						    preallocated space for
						    write opened files. */
	.fsync		= ntfs_file_fsync,	 /* Sync a file to disk. */
	/*.aio_fsync	= ,*/			 /* Sync all outstanding async
						    i/o operations on a
						    kiocb. */
#endif /* NTFS_RW */
	/*.ioctl	= ,*/			 /* Perform function on the
						    mounted filesystem. */
	.mmap		= generic_file_mmap,	 /* Mmap file. */
	.open		= ntfs_file_open,	 /* Open file. */
	.splice_read	= generic_file_splice_read /* Zero-copy data send with
						    the data source being on
						    the ntfs partition.  We do
						    not need to care about the
						    data destination. */
	/*.sendpage	= ,*/			 /* Zero-copy data send with
						    the data destination being
						    on the ntfs partition.  We
						    do not need to care about
						    the data source. */
};

const struct inode_operations ntfs_file_inode_ops = {
#ifdef NTFS_RW
	.setattr	= ntfs_setattr,
#endif /* NTFS_RW */
};

const struct file_operations ntfs_empty_file_ops = {};

const struct inode_operations ntfs_empty_inode_ops = {};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/file.c */
/************************************************************/
/*
 * index.c - NTFS kernel index handling.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2004-2005 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include <linux/slab.h>

// #include "aops.h"
// #include "collate.h"
// #include "debug.h"
#include "index.h"
// #include "ntfs.h"
#include "../../inc/__fss.h"

/**
 * ntfs_index_ctx_get - allocate and initialize a new index context
 * @idx_ni:	ntfs index inode with which to initialize the context
 *
 * Allocate a new index context, initialize it with @idx_ni and return it.
 * Return NULL if allocation failed.
 *
 * Locking:  Caller must hold i_mutex on the index inode.
 */
ntfs_index_context *ntfs_index_ctx_get(ntfs_inode *idx_ni)
{
	ntfs_index_context *ictx;

	ictx = kmem_cache_alloc(ntfs_index_ctx_cache, GFP_NOFS);
	if (ictx)
		*ictx = (ntfs_index_context){ .idx_ni = idx_ni };
	return ictx;
}

/**
 * ntfs_index_ctx_put - release an index context
 * @ictx:	index context to free
 *
 * Release the index context @ictx, releasing all associated resources.
 *
 * Locking:  Caller must hold i_mutex on the index inode.
 */
void ntfs_index_ctx_put(ntfs_index_context *ictx)
{
	if (ictx->entry) {
		if (ictx->is_in_root) {
			if (ictx->actx)
				ntfs_attr_put_search_ctx(ictx->actx);
			if (ictx->base_ni)
				unmap_mft_record(ictx->base_ni);
		} else {
			struct page *page = ictx->page;
			if (page) {
				BUG_ON(!PageLocked(page));
				unlock_page(page);
				ntfs_unmap_page(page);
			}
		}
	}
	kmem_cache_free(ntfs_index_ctx_cache, ictx);
	return;
}

/**
 * ntfs_index_lookup - find a key in an index and return its index entry
 * @key:	[IN] key for which to search in the index
 * @key_len:	[IN] length of @key in bytes
 * @ictx:	[IN/OUT] context describing the index and the returned entry
 *
 * Before calling ntfs_index_lookup(), @ictx must have been obtained from a
 * call to ntfs_index_ctx_get().
 *
 * Look for the @key in the index specified by the index lookup context @ictx.
 * ntfs_index_lookup() walks the contents of the index looking for the @key.
 *
 * If the @key is found in the index, 0 is returned and @ictx is setup to
 * describe the index entry containing the matching @key.  @ictx->entry is the
 * index entry and @ictx->data and @ictx->data_len are the index entry data and
 * its length in bytes, respectively.
 *
 * If the @key is not found in the index, -ENOENT is returned and @ictx is
 * setup to describe the index entry whose key collates immediately after the
 * search @key, i.e. this is the position in the index at which an index entry
 * with a key of @key would need to be inserted.
 *
 * If an error occurs return the negative error code and @ictx is left
 * untouched.
 *
 * When finished with the entry and its data, call ntfs_index_ctx_put() to free
 * the context and other associated resources.
 *
 * If the index entry was modified, call flush_dcache_index_entry_page()
 * immediately after the modification and either ntfs_index_entry_mark_dirty()
 * or ntfs_index_entry_write() before the call to ntfs_index_ctx_put() to
 * ensure that the changes are written to disk.
 *
 * Locking:  - Caller must hold i_mutex on the index inode.
 *	     - Each page cache page in the index allocation mapping must be
 *	       locked whilst being accessed otherwise we may find a corrupt
 *	       page due to it being under ->writepage at the moment which
 *	       applies the mst protection fixups before writing out and then
 *	       removes them again after the write is complete after which it 
 *	       unlocks the page.
 */
int ntfs_index_lookup(const void *key, const int key_len,
		ntfs_index_context *ictx)
{
	VCN vcn, old_vcn;
	ntfs_inode *idx_ni = ictx->idx_ni;
	ntfs_volume *vol = idx_ni->vol;
	struct super_block *sb = vol->sb;
	ntfs_inode *base_ni = idx_ni->ext.base_ntfs_ino;
	MFT_RECORD *m;
	INDEX_ROOT *ir;
	INDEX_ENTRY *ie;
	INDEX_ALLOCATION *ia;
	u8 *index_end, *kaddr;
	ntfs_attr_search_ctx *actx;
	struct address_space *ia_mapping;
	struct page *page;
	int rc, err = 0;

	ntfs_debug("Entering.");
	BUG_ON(!NInoAttr(idx_ni));
	BUG_ON(idx_ni->type != AT_INDEX_ALLOCATION);
	BUG_ON(idx_ni->nr_extents != -1);
	BUG_ON(!base_ni);
	BUG_ON(!key);
	BUG_ON(key_len <= 0);
	if (!ntfs_is_collation_rule_supported(
			idx_ni->itype.index.collation_rule)) {
		ntfs_error(sb, "Index uses unsupported collation rule 0x%x.  "
				"Aborting lookup.", le32_to_cpu(
				idx_ni->itype.index.collation_rule));
		return -EOPNOTSUPP;
	}
	/* Get hold of the mft record for the index inode. */
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		ntfs_error(sb, "map_mft_record() failed with error code %ld.",
				-PTR_ERR(m));
		return PTR_ERR(m);
	}
	actx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!actx)) {
		err = -ENOMEM;
		goto err_out;
	}
	/* Find the index root attribute in the mft record. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, idx_ni->name, idx_ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, actx);
	if (unlikely(err)) {
		if (err == -ENOENT) {
			ntfs_error(sb, "Index root attribute missing in inode "
					"0x%lx.", idx_ni->mft_no);
			err = -EIO;
		}
		goto err_out;
	}
	/* Get to the index root value (it has been verified in read_inode). */
	ir = (INDEX_ROOT*)((u8*)actx->attr +
			le16_to_cpu(actx->attr->data.resident.value_offset));
	index_end = (u8*)&ir->index + le32_to_cpu(ir->index.index_length);
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ir->index +
			le32_to_cpu(ir->index.entries_offset));
	/*
	 * Loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)actx->mrec || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->length) > index_end)
			goto idx_err_out;
		/*
		 * The last entry cannot contain a key.  It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* Further bounds checks. */
		if ((u32)sizeof(INDEX_ENTRY_HEADER) +
				le16_to_cpu(ie->key_length) >
				le16_to_cpu(ie->data.vi.data_offset) ||
				(u32)le16_to_cpu(ie->data.vi.data_offset) +
				le16_to_cpu(ie->data.vi.data_length) >
				le16_to_cpu(ie->length))
			goto idx_err_out;
		/* If the keys match perfectly, we setup @ictx and return 0. */
		if ((key_len == le16_to_cpu(ie->key_length)) && !memcmp(key,
				&ie->key, key_len)) {
ir_done:
			ictx->is_in_root = true;
			ictx->ir = ir;
			ictx->actx = actx;
			ictx->base_ni = base_ni;
			ictx->ia = NULL;
			ictx->page = NULL;
done:
			ictx->entry = ie;
			ictx->data = (u8*)ie +
					le16_to_cpu(ie->data.vi.data_offset);
			ictx->data_len = le16_to_cpu(ie->data.vi.data_length);
			ntfs_debug("Done.");
			return err;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate(vol, idx_ni->itype.index.collation_rule, key,
				key_len, &ie->key, le16_to_cpu(ie->key_length));
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/*
		 * A match should never happen as the memcmp() call should have
		 * cought it, but we still treat it correctly.
		 */
		if (!rc)
			goto ir_done;
		/* The keys are not equal, continue the search. */
	}
	/*
	 * We have finished with this index without success.  Check for the
	 * presence of a child node and if not present setup @ictx and return
	 * -ENOENT.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ntfs_debug("Entry not found.");
		err = -ENOENT;
		goto ir_done;
	} /* Child node present, descend into it. */
	/* Consistency check: Verify that an index allocation exists. */
	if (!NInoIndexAllocPresent(idx_ni)) {
		ntfs_error(sb, "No index allocation attribute but index entry "
				"requires one.  Inode 0x%lx is corrupt or "
				"driver bug.", idx_ni->mft_no);
		goto err_out;
	}
	/* Get the starting vcn of the index_block holding the child node. */
	vcn = sle64_to_cpup((sle64*)((u8*)ie + le16_to_cpu(ie->length) - 8));
	ia_mapping = VFS_I(idx_ni)->i_mapping;
	/*
	 * We are done with the index root and the mft record.  Release them,
	 * otherwise we deadlock with ntfs_map_page().
	 */
	ntfs_attr_put_search_ctx(actx);
	unmap_mft_record(base_ni);
	m = NULL;
	actx = NULL;
descend_into_child_node:
	/*
	 * Convert vcn to index into the index allocation attribute in units
	 * of PAGE_CACHE_SIZE and map the page cache page, reading it from
	 * disk if necessary.
	 */
	page = ntfs_map_page(ia_mapping, vcn <<
			idx_ni->itype.index.vcn_size_bits >> PAGE_CACHE_SHIFT);
	if (IS_ERR(page)) {
		ntfs_error(sb, "Failed to map index page, error %ld.",
				-PTR_ERR(page));
		err = PTR_ERR(page);
		goto err_out;
	}
	lock_page(page);
	kaddr = (u8*)page_address(page);
fast_descend_into_child_node:
	/* Get to the index allocation block. */
	ia = (INDEX_ALLOCATION*)(kaddr + ((vcn <<
			idx_ni->itype.index.vcn_size_bits) & ~PAGE_CACHE_MASK));
	/* Bounds checks. */
	if ((u8*)ia < kaddr || (u8*)ia > kaddr + PAGE_CACHE_SIZE) {
		ntfs_error(sb, "Out of bounds check failed.  Corrupt inode "
				"0x%lx or driver bug.", idx_ni->mft_no);
		goto unm_err_out;
	}
	/* Catch multi sector transfer fixup errors. */
	if (unlikely(!ntfs_is_indx_record(ia->magic))) {
		ntfs_error(sb, "Index record with vcn 0x%llx is corrupt.  "
				"Corrupt inode 0x%lx.  Run chkdsk.",
				(long long)vcn, idx_ni->mft_no);
		goto unm_err_out;
	}
	if (sle64_to_cpu(ia->index_block_vcn) != vcn) {
		ntfs_error(sb, "Actual VCN (0x%llx) of index buffer is "
				"different from expected VCN (0x%llx).  Inode "
				"0x%lx is corrupt or driver bug.",
				(unsigned long long)
				sle64_to_cpu(ia->index_block_vcn),
				(unsigned long long)vcn, idx_ni->mft_no);
		goto unm_err_out;
	}
	if (le32_to_cpu(ia->index.allocated_size) + 0x18 !=
			idx_ni->itype.index.block_size) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of inode 0x%lx has "
				"a size (%u) differing from the index "
				"specified size (%u).  Inode is corrupt or "
				"driver bug.", (unsigned long long)vcn,
				idx_ni->mft_no,
				le32_to_cpu(ia->index.allocated_size) + 0x18,
				idx_ni->itype.index.block_size);
		goto unm_err_out;
	}
	index_end = (u8*)ia + idx_ni->itype.index.block_size;
	if (index_end > kaddr + PAGE_CACHE_SIZE) {
		ntfs_error(sb, "Index buffer (VCN 0x%llx) of inode 0x%lx "
				"crosses page boundary.  Impossible!  Cannot "
				"access!  This is probably a bug in the "
				"driver.", (unsigned long long)vcn,
				idx_ni->mft_no);
		goto unm_err_out;
	}
	index_end = (u8*)&ia->index + le32_to_cpu(ia->index.index_length);
	if (index_end > (u8*)ia + idx_ni->itype.index.block_size) {
		ntfs_error(sb, "Size of index buffer (VCN 0x%llx) of inode "
				"0x%lx exceeds maximum size.",
				(unsigned long long)vcn, idx_ni->mft_no);
		goto unm_err_out;
	}
	/* The first index entry. */
	ie = (INDEX_ENTRY*)((u8*)&ia->index +
			le32_to_cpu(ia->index.entries_offset));
	/*
	 * Iterate similar to above big loop but applied to index buffer, thus
	 * loop until we exceed valid memory (corruption case) or until we
	 * reach the last entry.
	 */
	for (;; ie = (INDEX_ENTRY*)((u8*)ie + le16_to_cpu(ie->length))) {
		/* Bounds checks. */
		if ((u8*)ie < (u8*)ia || (u8*)ie +
				sizeof(INDEX_ENTRY_HEADER) > index_end ||
				(u8*)ie + le16_to_cpu(ie->length) > index_end) {
			ntfs_error(sb, "Index entry out of bounds in inode "
					"0x%lx.", idx_ni->mft_no);
			goto unm_err_out;
		}
		/*
		 * The last entry cannot contain a key.  It can however contain
		 * a pointer to a child node in the B+tree so we just break out.
		 */
		if (ie->flags & INDEX_ENTRY_END)
			break;
		/* Further bounds checks. */
		if ((u32)sizeof(INDEX_ENTRY_HEADER) +
				le16_to_cpu(ie->key_length) >
				le16_to_cpu(ie->data.vi.data_offset) ||
				(u32)le16_to_cpu(ie->data.vi.data_offset) +
				le16_to_cpu(ie->data.vi.data_length) >
				le16_to_cpu(ie->length)) {
			ntfs_error(sb, "Index entry out of bounds in inode "
					"0x%lx.", idx_ni->mft_no);
			goto unm_err_out;
		}
		/* If the keys match perfectly, we setup @ictx and return 0. */
		if ((key_len == le16_to_cpu(ie->key_length)) && !memcmp(key,
				&ie->key, key_len)) {
ia_done:
			ictx->is_in_root = false;
			ictx->actx = NULL;
			ictx->base_ni = NULL;
			ictx->ia = ia;
			ictx->page = page;
			goto done;
		}
		/*
		 * Not a perfect match, need to do full blown collation so we
		 * know which way in the B+tree we have to go.
		 */
		rc = ntfs_collate(vol, idx_ni->itype.index.collation_rule, key,
				key_len, &ie->key, le16_to_cpu(ie->key_length));
		/*
		 * If @key collates before the key of the current entry, there
		 * is definitely no such key in this index but we might need to
		 * descend into the B+tree so we just break out of the loop.
		 */
		if (rc == -1)
			break;
		/*
		 * A match should never happen as the memcmp() call should have
		 * cought it, but we still treat it correctly.
		 */
		if (!rc)
			goto ia_done;
		/* The keys are not equal, continue the search. */
	}
	/*
	 * We have finished with this index buffer without success.  Check for
	 * the presence of a child node and if not present return -ENOENT.
	 */
	if (!(ie->flags & INDEX_ENTRY_NODE)) {
		ntfs_debug("Entry not found.");
		err = -ENOENT;
		goto ia_done;
	}
	if ((ia->index.flags & NODE_MASK) == LEAF_NODE) {
		ntfs_error(sb, "Index entry with child node found in a leaf "
				"node in inode 0x%lx.", idx_ni->mft_no);
		goto unm_err_out;
	}
	/* Child node present, descend into it. */
	old_vcn = vcn;
	vcn = sle64_to_cpup((sle64*)((u8*)ie + le16_to_cpu(ie->length) - 8));
	if (vcn >= 0) {
		/*
		 * If vcn is in the same page cache page as old_vcn we recycle
		 * the mapped page.
		 */
		if (old_vcn << vol->cluster_size_bits >>
				PAGE_CACHE_SHIFT == vcn <<
				vol->cluster_size_bits >>
				PAGE_CACHE_SHIFT)
			goto fast_descend_into_child_node;
		unlock_page(page);
		ntfs_unmap_page(page);
		goto descend_into_child_node;
	}
	ntfs_error(sb, "Negative child node vcn in inode 0x%lx.",
			idx_ni->mft_no);
unm_err_out:
	unlock_page(page);
	ntfs_unmap_page(page);
err_out:
	if (!err)
		err = -EIO;
	if (actx)
		ntfs_attr_put_search_ctx(actx);
	if (m)
		unmap_mft_record(base_ni);
	return err;
idx_err_out:
	ntfs_error(sb, "Corrupt index.  Aborting lookup.");
	goto err_out;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/index.c */
/************************************************************/
/**
 * inode.c - NTFS kernel inode handling.
 *
 * Copyright (c) 2001-2014 Anton Altaparmakov and Tuxera Inc.
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include <linux/buffer_head.h>
// #include <linux/fs.h>
// #include <linux/mm.h>
#include <linux/mount.h>
#include <linux/mutex.h>
// #include <linux/pagemap.h>
#include <linux/quotaops.h>
// #include <linux/slab.h>
#include <linux/log2.h>
// #include <linux/aio.h>
#include "../../inc/__fss.h"

// #include "aops.h"
// #include "attrib.h"
// #include "bitmap.h"
// #include "dir.h"
// #include "debug.h"
// #include "inode.h"
// #include "lcnalloc.h"
// #include "malloc.h"
// #include "mft.h"
#include "time.h"
// #include "ntfs.h"
#include "../../inc/__fss.h"

/**
 * ntfs_test_inode - compare two (possibly fake) inodes for equality
 * @vi:		vfs inode which to test
 * @na:		ntfs attribute which is being tested with
 *
 * Compare the ntfs attribute embedded in the ntfs specific part of the vfs
 * inode @vi for equality with the ntfs attribute @na.
 *
 * If searching for the normal file/directory inode, set @na->type to AT_UNUSED.
 * @na->name and @na->name_len are then ignored.
 *
 * Return 1 if the attributes match and 0 if not.
 *
 * NOTE: This function runs with the inode_hash_lock spin lock held so it is not
 * allowed to sleep.
 */
int ntfs_test_inode(struct inode *vi, ntfs_attr *na)
{
	ntfs_inode *ni;

	if (vi->i_ino != na->mft_no)
		return 0;
	ni = NTFS_I(vi);
	/* If !NInoAttr(ni), @vi is a normal file or directory inode. */
	if (likely(!NInoAttr(ni))) {
		/* If not looking for a normal inode this is a mismatch. */
		if (unlikely(na->type != AT_UNUSED))
			return 0;
	} else {
		/* A fake inode describing an attribute. */
		if (ni->type != na->type)
			return 0;
		if (ni->name_len != na->name_len)
			return 0;
		if (na->name_len && memcmp(ni->name, na->name,
				na->name_len * sizeof(ntfschar)))
			return 0;
	}
	/* Match! */
	return 1;
}

/**
 * ntfs_init_locked_inode - initialize an inode
 * @vi:		vfs inode to initialize
 * @na:		ntfs attribute which to initialize @vi to
 *
 * Initialize the vfs inode @vi with the values from the ntfs attribute @na in
 * order to enable ntfs_test_inode() to do its work.
 *
 * If initializing the normal file/directory inode, set @na->type to AT_UNUSED.
 * In that case, @na->name and @na->name_len should be set to NULL and 0,
 * respectively. Although that is not strictly necessary as
 * ntfs_read_locked_inode() will fill them in later.
 *
 * Return 0 on success and -errno on error.
 *
 * NOTE: This function runs with the inode->i_lock spin lock held so it is not
 * allowed to sleep. (Hence the GFP_ATOMIC allocation.)
 */
static int ntfs_init_locked_inode(struct inode *vi, ntfs_attr *na)
{
	ntfs_inode *ni = NTFS_I(vi);

	vi->i_ino = na->mft_no;

	ni->type = na->type;
	if (na->type == AT_INDEX_ALLOCATION)
		NInoSetMstProtected(ni);

	ni->name = na->name;
	ni->name_len = na->name_len;

	/* If initializing a normal inode, we are done. */
	if (likely(na->type == AT_UNUSED)) {
		BUG_ON(na->name);
		BUG_ON(na->name_len);
		return 0;
	}

	/* It is a fake inode. */
	NInoSetAttr(ni);

	/*
	 * We have I30 global constant as an optimization as it is the name
	 * in >99.9% of named attributes! The other <0.1% incur a GFP_ATOMIC
	 * allocation but that is ok. And most attributes are unnamed anyway,
	 * thus the fraction of named attributes with name != I30 is actually
	 * absolutely tiny.
	 */
	if (na->name_len && na->name != I30) {
		unsigned int i;

		BUG_ON(!na->name);
		i = na->name_len * sizeof(ntfschar);
		ni->name = kmalloc(i + sizeof(ntfschar), GFP_ATOMIC);
		if (!ni->name)
			return -ENOMEM;
		memcpy(ni->name, na->name, i);
		ni->name[na->name_len] = 0;
	}
	return 0;
}

typedef int (*set_t)(struct inode *, void *);
static int ntfs_read_locked_inode(struct inode *vi);
static int ntfs_read_locked_attr_inode(struct inode *base_vi, struct inode *vi);
static int ntfs_read_locked_index_inode(struct inode *base_vi,
		struct inode *vi);

/**
 * ntfs_iget - obtain a struct inode corresponding to a specific normal inode
 * @sb:		super block of mounted volume
 * @mft_no:	mft record number / inode number to obtain
 *
 * Obtain the struct inode corresponding to a specific normal inode (i.e. a
 * file or directory).
 *
 * If the inode is in the cache, it is just returned with an increased
 * reference count. Otherwise, a new struct inode is allocated and initialized,
 * and finally ntfs_read_locked_inode() is called to read in the inode and
 * fill in the remainder of the inode structure.
 *
 * Return the struct inode on success. Check the return value with IS_ERR() and
 * if true, the function failed and the error code is obtained from PTR_ERR().
 */
struct inode *ntfs_iget(struct super_block *sb, unsigned long mft_no)
{
	struct inode *vi;
	int err;
	ntfs_attr na;

	na.mft_no = mft_no;
	na.type = AT_UNUSED;
	na.name = NULL;
	na.name_len = 0;

	vi = iget5_locked(sb, mft_no, (test_t)ntfs_test_inode,
			(set_t)ntfs_init_locked_inode, &na);
	if (unlikely(!vi))
		return ERR_PTR(-ENOMEM);

	err = 0;

	/* If this is a freshly allocated inode, need to read it now. */
	if (vi->i_state & I_NEW) {
		err = ntfs_read_locked_inode(vi);
		unlock_new_inode(vi);
	}
	/*
	 * There is no point in keeping bad inodes around if the failure was
	 * due to ENOMEM. We want to be able to retry again later.
	 */
	if (unlikely(err == -ENOMEM)) {
		iput(vi);
		vi = ERR_PTR(err);
	}
	return vi;
}

/**
 * ntfs_attr_iget - obtain a struct inode corresponding to an attribute
 * @base_vi:	vfs base inode containing the attribute
 * @type:	attribute type
 * @name:	Unicode name of the attribute (NULL if unnamed)
 * @name_len:	length of @name in Unicode characters (0 if unnamed)
 *
 * Obtain the (fake) struct inode corresponding to the attribute specified by
 * @type, @name, and @name_len, which is present in the base mft record
 * specified by the vfs inode @base_vi.
 *
 * If the attribute inode is in the cache, it is just returned with an
 * increased reference count. Otherwise, a new struct inode is allocated and
 * initialized, and finally ntfs_read_locked_attr_inode() is called to read the
 * attribute and fill in the inode structure.
 *
 * Note, for index allocation attributes, you need to use ntfs_index_iget()
 * instead of ntfs_attr_iget() as working with indices is a lot more complex.
 *
 * Return the struct inode of the attribute inode on success. Check the return
 * value with IS_ERR() and if true, the function failed and the error code is
 * obtained from PTR_ERR().
 */
struct inode *ntfs_attr_iget(struct inode *base_vi, ATTR_TYPE type,
		ntfschar *name, u32 name_len)
{
	struct inode *vi;
	int err;
	ntfs_attr na;

	/* Make sure no one calls ntfs_attr_iget() for indices. */
	BUG_ON(type == AT_INDEX_ALLOCATION);

	na.mft_no = base_vi->i_ino;
	na.type = type;
	na.name = name;
	na.name_len = name_len;

	vi = iget5_locked(base_vi->i_sb, na.mft_no, (test_t)ntfs_test_inode,
			(set_t)ntfs_init_locked_inode, &na);
	if (unlikely(!vi))
		return ERR_PTR(-ENOMEM);

	err = 0;

	/* If this is a freshly allocated inode, need to read it now. */
	if (vi->i_state & I_NEW) {
		err = ntfs_read_locked_attr_inode(base_vi, vi);
		unlock_new_inode(vi);
	}
	/*
	 * There is no point in keeping bad attribute inodes around. This also
	 * simplifies things in that we never need to check for bad attribute
	 * inodes elsewhere.
	 */
	if (unlikely(err)) {
		iput(vi);
		vi = ERR_PTR(err);
	}
	return vi;
}

/**
 * ntfs_index_iget - obtain a struct inode corresponding to an index
 * @base_vi:	vfs base inode containing the index related attributes
 * @name:	Unicode name of the index
 * @name_len:	length of @name in Unicode characters
 *
 * Obtain the (fake) struct inode corresponding to the index specified by @name
 * and @name_len, which is present in the base mft record specified by the vfs
 * inode @base_vi.
 *
 * If the index inode is in the cache, it is just returned with an increased
 * reference count.  Otherwise, a new struct inode is allocated and
 * initialized, and finally ntfs_read_locked_index_inode() is called to read
 * the index related attributes and fill in the inode structure.
 *
 * Return the struct inode of the index inode on success. Check the return
 * value with IS_ERR() and if true, the function failed and the error code is
 * obtained from PTR_ERR().
 */
struct inode *ntfs_index_iget(struct inode *base_vi, ntfschar *name,
		u32 name_len)
{
	struct inode *vi;
	int err;
	ntfs_attr na;

	na.mft_no = base_vi->i_ino;
	na.type = AT_INDEX_ALLOCATION;
	na.name = name;
	na.name_len = name_len;

	vi = iget5_locked(base_vi->i_sb, na.mft_no, (test_t)ntfs_test_inode,
			(set_t)ntfs_init_locked_inode, &na);
	if (unlikely(!vi))
		return ERR_PTR(-ENOMEM);

	err = 0;

	/* If this is a freshly allocated inode, need to read it now. */
	if (vi->i_state & I_NEW) {
		err = ntfs_read_locked_index_inode(base_vi, vi);
		unlock_new_inode(vi);
	}
	/*
	 * There is no point in keeping bad index inodes around.  This also
	 * simplifies things in that we never need to check for bad index
	 * inodes elsewhere.
	 */
	if (unlikely(err)) {
		iput(vi);
		vi = ERR_PTR(err);
	}
	return vi;
}

struct inode *ntfs_alloc_big_inode(struct super_block *sb)
{
	ntfs_inode *ni;

	ntfs_debug("Entering.");
	ni = kmem_cache_alloc(ntfs_big_inode_cache, GFP_NOFS);
	if (likely(ni != NULL)) {
		ni->state = 0;
		return VFS_I(ni);
	}
	ntfs_error(sb, "Allocation of NTFS big inode structure failed.");
	return NULL;
}

static void ntfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(ntfs_big_inode_cache, NTFS_I(inode));
}

void ntfs_destroy_big_inode(struct inode *inode)
{
	ntfs_inode *ni = NTFS_I(inode);

	ntfs_debug("Entering.");
	BUG_ON(ni->page);
	if (!atomic_dec_and_test(&ni->count))
		BUG();
	call_rcu(&inode->i_rcu, ntfs_i_callback);
}

static inline ntfs_inode *ntfs_alloc_extent_inode(void)
{
	ntfs_inode *ni;

	ntfs_debug("Entering.");
	ni = kmem_cache_alloc(ntfs_inode_cache, GFP_NOFS);
	if (likely(ni != NULL)) {
		ni->state = 0;
		return ni;
	}
	ntfs_error(NULL, "Allocation of NTFS inode structure failed.");
	return NULL;
}

static void ntfs_destroy_extent_inode(ntfs_inode *ni)
{
	ntfs_debug("Entering.");
	BUG_ON(ni->page);
	if (!atomic_dec_and_test(&ni->count))
		BUG();
	kmem_cache_free(ntfs_inode_cache, ni);
}

/*
 * The attribute runlist lock has separate locking rules from the
 * normal runlist lock, so split the two lock-classes:
 */
static struct lock_class_key attr_list_rl_lock_class;

/**
 * __ntfs_init_inode - initialize ntfs specific part of an inode
 * @sb:		super block of mounted volume
 * @ni:		freshly allocated ntfs inode which to initialize
 *
 * Initialize an ntfs inode to defaults.
 *
 * NOTE: ni->mft_no, ni->state, ni->type, ni->name, and ni->name_len are left
 * untouched. Make sure to initialize them elsewhere.
 *
 * Return zero on success and -ENOMEM on error.
 */
void __ntfs_init_inode(struct super_block *sb, ntfs_inode *ni)
{
	ntfs_debug("Entering.");
	rwlock_init(&ni->size_lock);
	ni->initialized_size = ni->allocated_size = 0;
	ni->seq_no = 0;
	atomic_set(&ni->count, 1);
	ni->vol = NTFS_SB(sb);
	ntfs_init_runlist(&ni->runlist);
	mutex_init(&ni->mrec_lock);
	ni->page = NULL;
	ni->page_ofs = 0;
	ni->attr_list_size = 0;
	ni->attr_list = NULL;
	ntfs_init_runlist(&ni->attr_list_rl);
	lockdep_set_class(&ni->attr_list_rl.lock,
				&attr_list_rl_lock_class);
	ni->itype.index.block_size = 0;
	ni->itype.index.vcn_size = 0;
	ni->itype.index.collation_rule = 0;
	ni->itype.index.block_size_bits = 0;
	ni->itype.index.vcn_size_bits = 0;
	mutex_init(&ni->extent_lock);
	ni->nr_extents = 0;
	ni->ext.base_ntfs_ino = NULL;
}

/*
 * Extent inodes get MFT-mapped in a nested way, while the base inode
 * is still mapped. Teach this nesting to the lock validator by creating
 * a separate class for nested inode's mrec_lock's:
 */
static struct lock_class_key extent_inode_mrec_lock_key;

inline ntfs_inode *ntfs_new_extent_inode(struct super_block *sb,
		unsigned long mft_no)
{
	ntfs_inode *ni = ntfs_alloc_extent_inode();

	ntfs_debug("Entering.");
	if (likely(ni != NULL)) {
		__ntfs_init_inode(sb, ni);
		lockdep_set_class(&ni->mrec_lock, &extent_inode_mrec_lock_key);
		ni->mft_no = mft_no;
		ni->type = AT_UNUSED;
		ni->name = NULL;
		ni->name_len = 0;
	}
	return ni;
}

/**
 * ntfs_is_extended_system_file - check if a file is in the $Extend directory
 * @ctx:	initialized attribute search context
 *
 * Search all file name attributes in the inode described by the attribute
 * search context @ctx and check if any of the names are in the $Extend system
 * directory.
 *
 * Return values:
 *	   1: file is in $Extend directory
 *	   0: file is not in $Extend directory
 *    -errno: failed to determine if the file is in the $Extend directory
 */
static int ntfs_is_extended_system_file(ntfs_attr_search_ctx *ctx)
{
	int nr_links, err;

	/* Restart search. */
	ntfs_attr_reinit_search_ctx(ctx);

	/* Get number of hard links. */
	nr_links = le16_to_cpu(ctx->mrec->link_count);

	/* Loop through all hard links. */
	while (!(err = ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, 0, 0, NULL, 0,
			ctx))) {
		FILE_NAME_ATTR *file_name_attr;
		ATTR_RECORD *attr = ctx->attr;
		u8 *p, *p2;

		nr_links--;
		/*
		 * Maximum sanity checking as we are called on an inode that
		 * we suspect might be corrupt.
		 */
		p = (u8*)attr + le32_to_cpu(attr->length);
		if (p < (u8*)ctx->mrec || (u8*)p > (u8*)ctx->mrec +
				le32_to_cpu(ctx->mrec->bytes_in_use)) {
err_corrupt_attr:
			ntfs_error(ctx->ntfs_ino->vol->sb, "Corrupt file name "
					"attribute. You should run chkdsk.");
			return -EIO;
		}
		if (attr->non_resident) {
			ntfs_error(ctx->ntfs_ino->vol->sb, "Non-resident file "
					"name. You should run chkdsk.");
			return -EIO;
		}
		if (attr->flags) {
			ntfs_error(ctx->ntfs_ino->vol->sb, "File name with "
					"invalid flags. You should run "
					"chkdsk.");
			return -EIO;
		}
		if (!(attr->data.resident.flags & RESIDENT_ATTR_IS_INDEXED)) {
			ntfs_error(ctx->ntfs_ino->vol->sb, "Unindexed file "
					"name. You should run chkdsk.");
			return -EIO;
		}
		file_name_attr = (FILE_NAME_ATTR*)((u8*)attr +
				le16_to_cpu(attr->data.resident.value_offset));
		p2 = (u8*)attr + le32_to_cpu(attr->data.resident.value_length);
		if (p2 < (u8*)attr || p2 > p)
			goto err_corrupt_attr;
		/* This attribute is ok, but is it in the $Extend directory? */
		if (MREF_LE(file_name_attr->parent_directory) == FILE_Extend)
			return 1;	/* YES, it's an extended system file. */
	}
	if (unlikely(err != -ENOENT))
		return err;
	if (unlikely(nr_links)) {
		ntfs_error(ctx->ntfs_ino->vol->sb, "Inode hard link count "
				"doesn't match number of name attributes. You "
				"should run chkdsk.");
		return -EIO;
	}
	return 0;	/* NO, it is not an extended system file. */
}

/**
 * ntfs_read_locked_inode - read an inode from its device
 * @vi:		inode to read
 *
 * ntfs_read_locked_inode() is called from ntfs_iget() to read the inode
 * described by @vi into memory from the device.
 *
 * The only fields in @vi that we need to/can look at when the function is
 * called are i_sb, pointing to the mounted device's super block, and i_ino,
 * the number of the inode to load.
 *
 * ntfs_read_locked_inode() maps, pins and locks the mft record number i_ino
 * for reading and sets up the necessary @vi fields as well as initializing
 * the ntfs inode.
 *
 * Q: What locks are held when the function is called?
 * A: i_state has I_NEW set, hence the inode is locked, also
 *    i_count is set to 1, so it is not going to go away
 *    i_flags is set to 0 and we have no business touching it.  Only an ioctl()
 *    is allowed to write to them. We should of course be honouring them but
 *    we need to do that using the IS_* macros defined in include/linux/fs.h.
 *    In any case ntfs_read_locked_inode() has nothing to do with i_flags.
 *
 * Return 0 on success and -errno on error.  In the error case, the inode will
 * have had make_bad_inode() executed on it.
 */
static int ntfs_read_locked_inode(struct inode *vi)
{
	ntfs_volume *vol = NTFS_SB(vi->i_sb);
	ntfs_inode *ni;
	struct inode *bvi;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	STANDARD_INFORMATION *si;
	ntfs_attr_search_ctx *ctx;
	int err = 0;

	ntfs_debug("Entering for i_ino 0x%lx.", vi->i_ino);

	/* Setup the generic vfs inode parts now. */

	/*
	 * This is for checking whether an inode has changed w.r.t. a file so
	 * that the file can be updated if necessary (compare with f_version).
	 */
	vi->i_version = 1;

	vi->i_uid = vol->uid;
	vi->i_gid = vol->gid;
	vi->i_mode = 0;

	/*
	 * Initialize the ntfs specific part of @vi special casing
	 * FILE_MFT which we need to do at mount time.
	 */
	if (vi->i_ino != FILE_MFT)
		ntfs_init_big_inode(vi);
	ni = NTFS_I(vi);

	m = map_mft_record(ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(ni, m);
	if (!ctx) {
		err = -ENOMEM;
		goto unm_err_out;
	}

	if (!(m->flags & MFT_RECORD_IN_USE)) {
		ntfs_error(vi->i_sb, "Inode is not in use!");
		goto unm_err_out;
	}
	if (m->base_mft_record) {
		ntfs_error(vi->i_sb, "Inode is an extent inode!");
		goto unm_err_out;
	}

	/* Transfer information from mft record into vfs and ntfs inodes. */
	vi->i_generation = ni->seq_no = le16_to_cpu(m->sequence_number);

	/*
	 * FIXME: Keep in mind that link_count is two for files which have both
	 * a long file name and a short file name as separate entries, so if
	 * we are hiding short file names this will be too high. Either we need
	 * to account for the short file names by subtracting them or we need
	 * to make sure we delete files even though i_nlink is not zero which
	 * might be tricky due to vfs interactions. Need to think about this
	 * some more when implementing the unlink command.
	 */
	set_nlink(vi, le16_to_cpu(m->link_count));
	/*
	 * FIXME: Reparse points can have the directory bit set even though
	 * they would be S_IFLNK. Need to deal with this further below when we
	 * implement reparse points / symbolic links but it will do for now.
	 * Also if not a directory, it could be something else, rather than
	 * a regular file. But again, will do for now.
	 */
	/* Everyone gets all permissions. */
	vi->i_mode |= S_IRWXUGO;
	/* If read-only, no one gets write permissions. */
	if (IS_RDONLY(vi))
		vi->i_mode &= ~S_IWUGO;
	if (m->flags & MFT_RECORD_IS_DIRECTORY) {
		vi->i_mode |= S_IFDIR;
		/*
		 * Apply the directory permissions mask set in the mount
		 * options.
		 */
		vi->i_mode &= ~vol->dmask;
		/* Things break without this kludge! */
		if (vi->i_nlink > 1)
			set_nlink(vi, 1);
	} else {
		vi->i_mode |= S_IFREG;
		/* Apply the file permissions mask set in the mount options. */
		vi->i_mode &= ~vol->fmask;
	}
	/*
	 * Find the standard information attribute in the mft record. At this
	 * stage we haven't setup the attribute list stuff yet, so this could
	 * in fact fail if the standard information is in an extent record, but
	 * I don't think this actually ever happens.
	 */
	err = ntfs_attr_lookup(AT_STANDARD_INFORMATION, NULL, 0, 0, 0, NULL, 0,
			ctx);
	if (unlikely(err)) {
		if (err == -ENOENT) {
			/*
			 * TODO: We should be performing a hot fix here (if the
			 * recover mount option is set) by creating a new
			 * attribute.
			 */
			ntfs_error(vi->i_sb, "$STANDARD_INFORMATION attribute "
					"is missing.");
		}
		goto unm_err_out;
	}
	a = ctx->attr;
	/* Get the standard information attribute value. */
	si = (STANDARD_INFORMATION*)((u8*)a +
			le16_to_cpu(a->data.resident.value_offset));

	/* Transfer information from the standard information into vi. */
	/*
	 * Note: The i_?times do not quite map perfectly onto the NTFS times,
	 * but they are close enough, and in the end it doesn't really matter
	 * that much...
	 */
	/*
	 * mtime is the last change of the data within the file. Not changed
	 * when only metadata is changed, e.g. a rename doesn't affect mtime.
	 */
	vi->i_mtime = ntfs2utc(si->last_data_change_time);
	/*
	 * ctime is the last change of the metadata of the file. This obviously
	 * always changes, when mtime is changed. ctime can be changed on its
	 * own, mtime is then not changed, e.g. when a file is renamed.
	 */
	vi->i_ctime = ntfs2utc(si->last_mft_change_time);
	/*
	 * Last access to the data within the file. Not changed during a rename
	 * for example but changed whenever the file is written to.
	 */
	vi->i_atime = ntfs2utc(si->last_access_time);

	/* Find the attribute list attribute if present. */
	ntfs_attr_reinit_search_ctx(ctx);
	err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, 0, 0, NULL, 0, ctx);
	if (err) {
		if (unlikely(err != -ENOENT)) {
			ntfs_error(vi->i_sb, "Failed to lookup attribute list "
					"attribute.");
			goto unm_err_out;
		}
	} else /* if (!err) */ {
		if (vi->i_ino == FILE_MFT)
			goto skip_attr_list_load;
		ntfs_debug("Attribute list found in inode 0x%lx.", vi->i_ino);
		NInoSetAttrList(ni);
		a = ctx->attr;
		if (a->flags & ATTR_COMPRESSION_MASK) {
			ntfs_error(vi->i_sb, "Attribute list attribute is "
					"compressed.");
			goto unm_err_out;
		}
		if (a->flags & ATTR_IS_ENCRYPTED ||
				a->flags & ATTR_IS_SPARSE) {
			if (a->non_resident) {
				ntfs_error(vi->i_sb, "Non-resident attribute "
						"list attribute is encrypted/"
						"sparse.");
				goto unm_err_out;
			}
			ntfs_warning(vi->i_sb, "Resident attribute list "
					"attribute in inode 0x%lx is marked "
					"encrypted/sparse which is not true.  "
					"However, Windows allows this and "
					"chkdsk does not detect or correct it "
					"so we will just ignore the invalid "
					"flags and pretend they are not set.",
					vi->i_ino);
		}
		/* Now allocate memory for the attribute list. */
		ni->attr_list_size = (u32)ntfs_attr_size(a);
		ni->attr_list = ntfs_malloc_nofs(ni->attr_list_size);
		if (!ni->attr_list) {
			ntfs_error(vi->i_sb, "Not enough memory to allocate "
					"buffer for attribute list.");
			err = -ENOMEM;
			goto unm_err_out;
		}
		if (a->non_resident) {
			NInoSetAttrListNonResident(ni);
			if (a->data.non_resident.lowest_vcn) {
				ntfs_error(vi->i_sb, "Attribute list has non "
						"zero lowest_vcn.");
				goto unm_err_out;
			}
			/*
			 * Setup the runlist. No need for locking as we have
			 * exclusive access to the inode at this time.
			 */
			ni->attr_list_rl.rl = ntfs_mapping_pairs_decompress(vol,
					a, NULL);
			if (IS_ERR(ni->attr_list_rl.rl)) {
				err = PTR_ERR(ni->attr_list_rl.rl);
				ni->attr_list_rl.rl = NULL;
				ntfs_error(vi->i_sb, "Mapping pairs "
						"decompression failed.");
				goto unm_err_out;
			}
			/* Now load the attribute list. */
			if ((err = load_attribute_list(vol, &ni->attr_list_rl,
					ni->attr_list, ni->attr_list_size,
					sle64_to_cpu(a->data.non_resident.
					initialized_size)))) {
				ntfs_error(vi->i_sb, "Failed to load "
						"attribute list attribute.");
				goto unm_err_out;
			}
		} else /* if (!a->non_resident) */ {
			if ((u8*)a + le16_to_cpu(a->data.resident.value_offset)
					+ le32_to_cpu(
					a->data.resident.value_length) >
					(u8*)ctx->mrec + vol->mft_record_size) {
				ntfs_error(vi->i_sb, "Corrupt attribute list "
						"in inode.");
				goto unm_err_out;
			}
			/* Now copy the attribute list. */
			memcpy(ni->attr_list, (u8*)a + le16_to_cpu(
					a->data.resident.value_offset),
					le32_to_cpu(
					a->data.resident.value_length));
		}
	}
skip_attr_list_load:
	/*
	 * If an attribute list is present we now have the attribute list value
	 * in ntfs_ino->attr_list and it is ntfs_ino->attr_list_size bytes.
	 */
	if (S_ISDIR(vi->i_mode)) {
		loff_t bvi_size;
		ntfs_inode *bni;
		INDEX_ROOT *ir;
		u8 *ir_end, *index_end;

		/* It is a directory, find index root attribute. */
		ntfs_attr_reinit_search_ctx(ctx);
		err = ntfs_attr_lookup(AT_INDEX_ROOT, I30, 4, CASE_SENSITIVE,
				0, NULL, 0, ctx);
		if (unlikely(err)) {
			if (err == -ENOENT) {
				// FIXME: File is corrupt! Hot-fix with empty
				// index root attribute if recovery option is
				// set.
				ntfs_error(vi->i_sb, "$INDEX_ROOT attribute "
						"is missing.");
			}
			goto unm_err_out;
		}
		a = ctx->attr;
		/* Set up the state. */
		if (unlikely(a->non_resident)) {
			ntfs_error(vol->sb, "$INDEX_ROOT attribute is not "
					"resident.");
			goto unm_err_out;
		}
		/* Ensure the attribute name is placed before the value. */
		if (unlikely(a->name_length && (le16_to_cpu(a->name_offset) >=
				le16_to_cpu(a->data.resident.value_offset)))) {
			ntfs_error(vol->sb, "$INDEX_ROOT attribute name is "
					"placed after the attribute value.");
			goto unm_err_out;
		}
		/*
		 * Compressed/encrypted index root just means that the newly
		 * created files in that directory should be created compressed/
		 * encrypted. However index root cannot be both compressed and
		 * encrypted.
		 */
		if (a->flags & ATTR_COMPRESSION_MASK)
			NInoSetCompressed(ni);
		if (a->flags & ATTR_IS_ENCRYPTED) {
			if (a->flags & ATTR_COMPRESSION_MASK) {
				ntfs_error(vi->i_sb, "Found encrypted and "
						"compressed attribute.");
				goto unm_err_out;
			}
			NInoSetEncrypted(ni);
		}
		if (a->flags & ATTR_IS_SPARSE)
			NInoSetSparse(ni);
		ir = (INDEX_ROOT*)((u8*)a +
				le16_to_cpu(a->data.resident.value_offset));
		ir_end = (u8*)ir + le32_to_cpu(a->data.resident.value_length);
		if (ir_end > (u8*)ctx->mrec + vol->mft_record_size) {
			ntfs_error(vi->i_sb, "$INDEX_ROOT attribute is "
					"corrupt.");
			goto unm_err_out;
		}
		index_end = (u8*)&ir->index +
				le32_to_cpu(ir->index.index_length);
		if (index_end > ir_end) {
			ntfs_error(vi->i_sb, "Directory index is corrupt.");
			goto unm_err_out;
		}
		if (ir->type != AT_FILE_NAME) {
			ntfs_error(vi->i_sb, "Indexed attribute is not "
					"$FILE_NAME.");
			goto unm_err_out;
		}
		if (ir->collation_rule != COLLATION_FILE_NAME) {
			ntfs_error(vi->i_sb, "Index collation rule is not "
					"COLLATION_FILE_NAME.");
			goto unm_err_out;
		}
		ni->itype.index.collation_rule = ir->collation_rule;
		ni->itype.index.block_size = le32_to_cpu(ir->index_block_size);
		if (ni->itype.index.block_size &
				(ni->itype.index.block_size - 1)) {
			ntfs_error(vi->i_sb, "Index block size (%u) is not a "
					"power of two.",
					ni->itype.index.block_size);
			goto unm_err_out;
		}
		if (ni->itype.index.block_size > PAGE_CACHE_SIZE) {
			ntfs_error(vi->i_sb, "Index block size (%u) > "
					"PAGE_CACHE_SIZE (%ld) is not "
					"supported.  Sorry.",
					ni->itype.index.block_size,
					PAGE_CACHE_SIZE);
			err = -EOPNOTSUPP;
			goto unm_err_out;
		}
		if (ni->itype.index.block_size < NTFS_BLOCK_SIZE) {
			ntfs_error(vi->i_sb, "Index block size (%u) < "
					"NTFS_BLOCK_SIZE (%i) is not "
					"supported.  Sorry.",
					ni->itype.index.block_size,
					NTFS_BLOCK_SIZE);
			err = -EOPNOTSUPP;
			goto unm_err_out;
		}
		ni->itype.index.block_size_bits =
				ffs(ni->itype.index.block_size) - 1;
		/* Determine the size of a vcn in the directory index. */
		if (vol->cluster_size <= ni->itype.index.block_size) {
			ni->itype.index.vcn_size = vol->cluster_size;
			ni->itype.index.vcn_size_bits = vol->cluster_size_bits;
		} else {
			ni->itype.index.vcn_size = vol->sector_size;
			ni->itype.index.vcn_size_bits = vol->sector_size_bits;
		}

		/* Setup the index allocation attribute, even if not present. */
		NInoSetMstProtected(ni);
		ni->type = AT_INDEX_ALLOCATION;
		ni->name = I30;
		ni->name_len = 4;

		if (!(ir->index.flags & LARGE_INDEX)) {
			/* No index allocation. */
			vi->i_size = ni->initialized_size =
					ni->allocated_size = 0;
			/* We are done with the mft record, so we release it. */
			ntfs_attr_put_search_ctx(ctx);
			unmap_mft_record(ni);
			m = NULL;
			ctx = NULL;
			goto skip_large_dir_stuff;
		} /* LARGE_INDEX: Index allocation present. Setup state. */
		NInoSetIndexAllocPresent(ni);
		/* Find index allocation attribute. */
		ntfs_attr_reinit_search_ctx(ctx);
		err = ntfs_attr_lookup(AT_INDEX_ALLOCATION, I30, 4,
				CASE_SENSITIVE, 0, NULL, 0, ctx);
		if (unlikely(err)) {
			if (err == -ENOENT)
				ntfs_error(vi->i_sb, "$INDEX_ALLOCATION "
						"attribute is not present but "
						"$INDEX_ROOT indicated it is.");
			else
				ntfs_error(vi->i_sb, "Failed to lookup "
						"$INDEX_ALLOCATION "
						"attribute.");
			goto unm_err_out;
		}
		a = ctx->attr;
		if (!a->non_resident) {
			ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute "
					"is resident.");
			goto unm_err_out;
		}
		/*
		 * Ensure the attribute name is placed before the mapping pairs
		 * array.
		 */
		if (unlikely(a->name_length && (le16_to_cpu(a->name_offset) >=
				le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset)))) {
			ntfs_error(vol->sb, "$INDEX_ALLOCATION attribute name "
					"is placed after the mapping pairs "
					"array.");
			goto unm_err_out;
		}
		if (a->flags & ATTR_IS_ENCRYPTED) {
			ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute "
					"is encrypted.");
			goto unm_err_out;
		}
		if (a->flags & ATTR_IS_SPARSE) {
			ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute "
					"is sparse.");
			goto unm_err_out;
		}
		if (a->flags & ATTR_COMPRESSION_MASK) {
			ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute "
					"is compressed.");
			goto unm_err_out;
		}
		if (a->data.non_resident.lowest_vcn) {
			ntfs_error(vi->i_sb, "First extent of "
					"$INDEX_ALLOCATION attribute has non "
					"zero lowest_vcn.");
			goto unm_err_out;
		}
		vi->i_size = sle64_to_cpu(a->data.non_resident.data_size);
		ni->initialized_size = sle64_to_cpu(
				a->data.non_resident.initialized_size);
		ni->allocated_size = sle64_to_cpu(
				a->data.non_resident.allocated_size);
		/*
		 * We are done with the mft record, so we release it. Otherwise
		 * we would deadlock in ntfs_attr_iget().
		 */
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(ni);
		m = NULL;
		ctx = NULL;
		/* Get the index bitmap attribute inode. */
		bvi = ntfs_attr_iget(vi, AT_BITMAP, I30, 4);
		if (IS_ERR(bvi)) {
			ntfs_error(vi->i_sb, "Failed to get bitmap attribute.");
			err = PTR_ERR(bvi);
			goto unm_err_out;
		}
		bni = NTFS_I(bvi);
		if (NInoCompressed(bni) || NInoEncrypted(bni) ||
				NInoSparse(bni)) {
			ntfs_error(vi->i_sb, "$BITMAP attribute is compressed "
					"and/or encrypted and/or sparse.");
			goto iput_unm_err_out;
		}
		/* Consistency check bitmap size vs. index allocation size. */
		bvi_size = i_size_read(bvi);
		if ((bvi_size << 3) < (vi->i_size >>
				ni->itype.index.block_size_bits)) {
			ntfs_error(vi->i_sb, "Index bitmap too small (0x%llx) "
					"for index allocation (0x%llx).",
					bvi_size << 3, vi->i_size);
			goto iput_unm_err_out;
		}
		/* No longer need the bitmap attribute inode. */
		iput(bvi);
skip_large_dir_stuff:
		/* Setup the operations for this inode. */
		vi->i_op = &ntfs_dir_inode_ops;
		vi->i_fop = &ntfs_dir_ops;
		vi->i_mapping->a_ops = &ntfs_mst_aops;
	} else {
		/* It is a file. */
		ntfs_attr_reinit_search_ctx(ctx);

		/* Setup the data attribute, even if not present. */
		ni->type = AT_DATA;
		ni->name = NULL;
		ni->name_len = 0;

		/* Find first extent of the unnamed data attribute. */
		err = ntfs_attr_lookup(AT_DATA, NULL, 0, 0, 0, NULL, 0, ctx);
		if (unlikely(err)) {
			vi->i_size = ni->initialized_size =
					ni->allocated_size = 0;
			if (err != -ENOENT) {
				ntfs_error(vi->i_sb, "Failed to lookup $DATA "
						"attribute.");
				goto unm_err_out;
			}
			/*
			 * FILE_Secure does not have an unnamed $DATA
			 * attribute, so we special case it here.
			 */
			if (vi->i_ino == FILE_Secure)
				goto no_data_attr_special_case;
			/*
			 * Most if not all the system files in the $Extend
			 * system directory do not have unnamed data
			 * attributes so we need to check if the parent
			 * directory of the file is FILE_Extend and if it is
			 * ignore this error. To do this we need to get the
			 * name of this inode from the mft record as the name
			 * contains the back reference to the parent directory.
			 */
			if (ntfs_is_extended_system_file(ctx) > 0)
				goto no_data_attr_special_case;
			// FIXME: File is corrupt! Hot-fix with empty data
			// attribute if recovery option is set.
			ntfs_error(vi->i_sb, "$DATA attribute is missing.");
			goto unm_err_out;
		}
		a = ctx->attr;
		/* Setup the state. */
		if (a->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_SPARSE)) {
			if (a->flags & ATTR_COMPRESSION_MASK) {
				NInoSetCompressed(ni);
				if (vol->cluster_size > 4096) {
					ntfs_error(vi->i_sb, "Found "
							"compressed data but "
							"compression is "
							"disabled due to "
							"cluster size (%i) > "
							"4kiB.",
							vol->cluster_size);
					goto unm_err_out;
				}
				if ((a->flags & ATTR_COMPRESSION_MASK)
						!= ATTR_IS_COMPRESSED) {
					ntfs_error(vi->i_sb, "Found unknown "
							"compression method "
							"or corrupt file.");
					goto unm_err_out;
				}
			}
			if (a->flags & ATTR_IS_SPARSE)
				NInoSetSparse(ni);
		}
		if (a->flags & ATTR_IS_ENCRYPTED) {
			if (NInoCompressed(ni)) {
				ntfs_error(vi->i_sb, "Found encrypted and "
						"compressed data.");
				goto unm_err_out;
			}
			NInoSetEncrypted(ni);
		}
		if (a->non_resident) {
			NInoSetNonResident(ni);
			if (NInoCompressed(ni) || NInoSparse(ni)) {
				if (NInoCompressed(ni) && a->data.non_resident.
						compression_unit != 4) {
					ntfs_error(vi->i_sb, "Found "
							"non-standard "
							"compression unit (%u "
							"instead of 4).  "
							"Cannot handle this.",
							a->data.non_resident.
							compression_unit);
					err = -EOPNOTSUPP;
					goto unm_err_out;
				}
				if (a->data.non_resident.compression_unit) {
					ni->itype.compressed.block_size = 1U <<
							(a->data.non_resident.
							compression_unit +
							vol->cluster_size_bits);
					ni->itype.compressed.block_size_bits =
							ffs(ni->itype.
							compressed.
							block_size) - 1;
					ni->itype.compressed.block_clusters =
							1U << a->data.
							non_resident.
							compression_unit;
				} else {
					ni->itype.compressed.block_size = 0;
					ni->itype.compressed.block_size_bits =
							0;
					ni->itype.compressed.block_clusters =
							0;
				}
				ni->itype.compressed.size = sle64_to_cpu(
						a->data.non_resident.
						compressed_size);
			}
			if (a->data.non_resident.lowest_vcn) {
				ntfs_error(vi->i_sb, "First extent of $DATA "
						"attribute has non zero "
						"lowest_vcn.");
				goto unm_err_out;
			}
			vi->i_size = sle64_to_cpu(
					a->data.non_resident.data_size);
			ni->initialized_size = sle64_to_cpu(
					a->data.non_resident.initialized_size);
			ni->allocated_size = sle64_to_cpu(
					a->data.non_resident.allocated_size);
		} else { /* Resident attribute. */
			vi->i_size = ni->initialized_size = le32_to_cpu(
					a->data.resident.value_length);
			ni->allocated_size = le32_to_cpu(a->length) -
					le16_to_cpu(
					a->data.resident.value_offset);
			if (vi->i_size > ni->allocated_size) {
				ntfs_error(vi->i_sb, "Resident data attribute "
						"is corrupt (size exceeds "
						"allocation).");
				goto unm_err_out;
			}
		}
no_data_attr_special_case:
		/* We are done with the mft record, so we release it. */
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(ni);
		m = NULL;
		ctx = NULL;
		/* Setup the operations for this inode. */
		vi->i_op = &ntfs_file_inode_ops;
		vi->i_fop = &ntfs_file_ops;
		vi->i_mapping->a_ops = &ntfs_normal_aops;
		if (NInoMstProtected(ni))
			vi->i_mapping->a_ops = &ntfs_mst_aops;
		else if (NInoCompressed(ni))
			vi->i_mapping->a_ops = &ntfs_compressed_aops;
	}
	/*
	 * The number of 512-byte blocks used on disk (for stat). This is in so
	 * far inaccurate as it doesn't account for any named streams or other
	 * special non-resident attributes, but that is how Windows works, too,
	 * so we are at least consistent with Windows, if not entirely
	 * consistent with the Linux Way. Doing it the Linux Way would cause a
	 * significant slowdown as it would involve iterating over all
	 * attributes in the mft record and adding the allocated/compressed
	 * sizes of all non-resident attributes present to give us the Linux
	 * correct size that should go into i_blocks (after division by 512).
	 */
	if (S_ISREG(vi->i_mode) && (NInoCompressed(ni) || NInoSparse(ni)))
		vi->i_blocks = ni->itype.compressed.size >> 9;
	else
		vi->i_blocks = ni->allocated_size >> 9;
	ntfs_debug("Done.");
	return 0;
iput_unm_err_out:
	iput(bvi);
unm_err_out:
	if (!err)
		err = -EIO;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(ni);
err_out:
	ntfs_error(vol->sb, "Failed with error code %i.  Marking corrupt "
			"inode 0x%lx as bad.  Run chkdsk.", err, vi->i_ino);
	make_bad_inode(vi);
	if (err != -EOPNOTSUPP && err != -ENOMEM)
		NVolSetErrors(vol);
	return err;
}

/**
 * ntfs_read_locked_attr_inode - read an attribute inode from its base inode
 * @base_vi:	base inode
 * @vi:		attribute inode to read
 *
 * ntfs_read_locked_attr_inode() is called from ntfs_attr_iget() to read the
 * attribute inode described by @vi into memory from the base mft record
 * described by @base_ni.
 *
 * ntfs_read_locked_attr_inode() maps, pins and locks the base inode for
 * reading and looks up the attribute described by @vi before setting up the
 * necessary fields in @vi as well as initializing the ntfs inode.
 *
 * Q: What locks are held when the function is called?
 * A: i_state has I_NEW set, hence the inode is locked, also
 *    i_count is set to 1, so it is not going to go away
 *
 * Return 0 on success and -errno on error.  In the error case, the inode will
 * have had make_bad_inode() executed on it.
 *
 * Note this cannot be called for AT_INDEX_ALLOCATION.
 */
static int ntfs_read_locked_attr_inode(struct inode *base_vi, struct inode *vi)
{
	ntfs_volume *vol = NTFS_SB(vi->i_sb);
	ntfs_inode *ni, *base_ni;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	ntfs_attr_search_ctx *ctx;
	int err = 0;

	ntfs_debug("Entering for i_ino 0x%lx.", vi->i_ino);

	ntfs_init_big_inode(vi);

	ni	= NTFS_I(vi);
	base_ni = NTFS_I(base_vi);

	/* Just mirror the values from the base inode. */
	vi->i_version	= base_vi->i_version;
	vi->i_uid	= base_vi->i_uid;
	vi->i_gid	= base_vi->i_gid;
	set_nlink(vi, base_vi->i_nlink);
	vi->i_mtime	= base_vi->i_mtime;
	vi->i_ctime	= base_vi->i_ctime;
	vi->i_atime	= base_vi->i_atime;
	vi->i_generation = ni->seq_no = base_ni->seq_no;

	/* Set inode type to zero but preserve permissions. */
	vi->i_mode	= base_vi->i_mode & ~S_IFMT;

	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (!ctx) {
		err = -ENOMEM;
		goto unm_err_out;
	}
	/* Find the attribute. */
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err))
		goto unm_err_out;
	a = ctx->attr;
	if (a->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_SPARSE)) {
		if (a->flags & ATTR_COMPRESSION_MASK) {
			NInoSetCompressed(ni);
			if ((ni->type != AT_DATA) || (ni->type == AT_DATA &&
					ni->name_len)) {
				ntfs_error(vi->i_sb, "Found compressed "
						"non-data or named data "
						"attribute.  Please report "
						"you saw this message to "
						"linux-ntfs-dev@lists."
						"sourceforge.net");
				goto unm_err_out;
			}
			if (vol->cluster_size > 4096) {
				ntfs_error(vi->i_sb, "Found compressed "
						"attribute but compression is "
						"disabled due to cluster size "
						"(%i) > 4kiB.",
						vol->cluster_size);
				goto unm_err_out;
			}
			if ((a->flags & ATTR_COMPRESSION_MASK) !=
					ATTR_IS_COMPRESSED) {
				ntfs_error(vi->i_sb, "Found unknown "
						"compression method.");
				goto unm_err_out;
			}
		}
		/*
		 * The compressed/sparse flag set in an index root just means
		 * to compress all files.
		 */
		if (NInoMstProtected(ni) && ni->type != AT_INDEX_ROOT) {
			ntfs_error(vi->i_sb, "Found mst protected attribute "
					"but the attribute is %s.  Please "
					"report you saw this message to "
					"linux-ntfs-dev@lists.sourceforge.net",
					NInoCompressed(ni) ? "compressed" :
					"sparse");
			goto unm_err_out;
		}
		if (a->flags & ATTR_IS_SPARSE)
			NInoSetSparse(ni);
	}
	if (a->flags & ATTR_IS_ENCRYPTED) {
		if (NInoCompressed(ni)) {
			ntfs_error(vi->i_sb, "Found encrypted and compressed "
					"data.");
			goto unm_err_out;
		}
		/*
		 * The encryption flag set in an index root just means to
		 * encrypt all files.
		 */
		if (NInoMstProtected(ni) && ni->type != AT_INDEX_ROOT) {
			ntfs_error(vi->i_sb, "Found mst protected attribute "
					"but the attribute is encrypted.  "
					"Please report you saw this message "
					"to linux-ntfs-dev@lists.sourceforge."
					"net");
			goto unm_err_out;
		}
		if (ni->type != AT_DATA) {
			ntfs_error(vi->i_sb, "Found encrypted non-data "
					"attribute.");
			goto unm_err_out;
		}
		NInoSetEncrypted(ni);
	}
	if (!a->non_resident) {
		/* Ensure the attribute name is placed before the value. */
		if (unlikely(a->name_length && (le16_to_cpu(a->name_offset) >=
				le16_to_cpu(a->data.resident.value_offset)))) {
			ntfs_error(vol->sb, "Attribute name is placed after "
					"the attribute value.");
			goto unm_err_out;
		}
		if (NInoMstProtected(ni)) {
			ntfs_error(vi->i_sb, "Found mst protected attribute "
					"but the attribute is resident.  "
					"Please report you saw this message to "
					"linux-ntfs-dev@lists.sourceforge.net");
			goto unm_err_out;
		}
		vi->i_size = ni->initialized_size = le32_to_cpu(
				a->data.resident.value_length);
		ni->allocated_size = le32_to_cpu(a->length) -
				le16_to_cpu(a->data.resident.value_offset);
		if (vi->i_size > ni->allocated_size) {
			ntfs_error(vi->i_sb, "Resident attribute is corrupt "
					"(size exceeds allocation).");
			goto unm_err_out;
		}
	} else {
		NInoSetNonResident(ni);
		/*
		 * Ensure the attribute name is placed before the mapping pairs
		 * array.
		 */
		if (unlikely(a->name_length && (le16_to_cpu(a->name_offset) >=
				le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset)))) {
			ntfs_error(vol->sb, "Attribute name is placed after "
					"the mapping pairs array.");
			goto unm_err_out;
		}
		if (NInoCompressed(ni) || NInoSparse(ni)) {
			if (NInoCompressed(ni) && a->data.non_resident.
					compression_unit != 4) {
				ntfs_error(vi->i_sb, "Found non-standard "
						"compression unit (%u instead "
						"of 4).  Cannot handle this.",
						a->data.non_resident.
						compression_unit);
				err = -EOPNOTSUPP;
				goto unm_err_out;
			}
			if (a->data.non_resident.compression_unit) {
				ni->itype.compressed.block_size = 1U <<
						(a->data.non_resident.
						compression_unit +
						vol->cluster_size_bits);
				ni->itype.compressed.block_size_bits =
						ffs(ni->itype.compressed.
						block_size) - 1;
				ni->itype.compressed.block_clusters = 1U <<
						a->data.non_resident.
						compression_unit;
			} else {
				ni->itype.compressed.block_size = 0;
				ni->itype.compressed.block_size_bits = 0;
				ni->itype.compressed.block_clusters = 0;
			}
			ni->itype.compressed.size = sle64_to_cpu(
					a->data.non_resident.compressed_size);
		}
		if (a->data.non_resident.lowest_vcn) {
			ntfs_error(vi->i_sb, "First extent of attribute has "
					"non-zero lowest_vcn.");
			goto unm_err_out;
		}
		vi->i_size = sle64_to_cpu(a->data.non_resident.data_size);
		ni->initialized_size = sle64_to_cpu(
				a->data.non_resident.initialized_size);
		ni->allocated_size = sle64_to_cpu(
				a->data.non_resident.allocated_size);
	}
	vi->i_mapping->a_ops = &ntfs_normal_aops;
	if (NInoMstProtected(ni))
		vi->i_mapping->a_ops = &ntfs_mst_aops;
	else if (NInoCompressed(ni))
		vi->i_mapping->a_ops = &ntfs_compressed_aops;
	if ((NInoCompressed(ni) || NInoSparse(ni)) && ni->type != AT_INDEX_ROOT)
		vi->i_blocks = ni->itype.compressed.size >> 9;
	else
		vi->i_blocks = ni->allocated_size >> 9;
	/*
	 * Make sure the base inode does not go away and attach it to the
	 * attribute inode.
	 */
	igrab(base_vi);
	ni->ext.base_ntfs_ino = base_ni;
	ni->nr_extents = -1;

	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);

	ntfs_debug("Done.");
	return 0;

unm_err_out:
	if (!err)
		err = -EIO;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
err_out:
	ntfs_error(vol->sb, "Failed with error code %i while reading attribute "
			"inode (mft_no 0x%lx, type 0x%x, name_len %i).  "
			"Marking corrupt inode and base inode 0x%lx as bad.  "
			"Run chkdsk.", err, vi->i_ino, ni->type, ni->name_len,
			base_vi->i_ino);
	make_bad_inode(vi);
	if (err != -ENOMEM)
		NVolSetErrors(vol);
	return err;
}

/**
 * ntfs_read_locked_index_inode - read an index inode from its base inode
 * @base_vi:	base inode
 * @vi:		index inode to read
 *
 * ntfs_read_locked_index_inode() is called from ntfs_index_iget() to read the
 * index inode described by @vi into memory from the base mft record described
 * by @base_ni.
 *
 * ntfs_read_locked_index_inode() maps, pins and locks the base inode for
 * reading and looks up the attributes relating to the index described by @vi
 * before setting up the necessary fields in @vi as well as initializing the
 * ntfs inode.
 *
 * Note, index inodes are essentially attribute inodes (NInoAttr() is true)
 * with the attribute type set to AT_INDEX_ALLOCATION.  Apart from that, they
 * are setup like directory inodes since directories are a special case of
 * indices ao they need to be treated in much the same way.  Most importantly,
 * for small indices the index allocation attribute might not actually exist.
 * However, the index root attribute always exists but this does not need to
 * have an inode associated with it and this is why we define a new inode type
 * index.  Also, like for directories, we need to have an attribute inode for
 * the bitmap attribute corresponding to the index allocation attribute and we
 * can store this in the appropriate field of the inode, just like we do for
 * normal directory inodes.
 *
 * Q: What locks are held when the function is called?
 * A: i_state has I_NEW set, hence the inode is locked, also
 *    i_count is set to 1, so it is not going to go away
 *
 * Return 0 on success and -errno on error.  In the error case, the inode will
 * have had make_bad_inode() executed on it.
 */
static int ntfs_read_locked_index_inode(struct inode *base_vi, struct inode *vi)
{
	loff_t bvi_size;
	ntfs_volume *vol = NTFS_SB(vi->i_sb);
	ntfs_inode *ni, *base_ni, *bni;
	struct inode *bvi;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	ntfs_attr_search_ctx *ctx;
	INDEX_ROOT *ir;
	u8 *ir_end, *index_end;
	int err = 0;

	ntfs_debug("Entering for i_ino 0x%lx.", vi->i_ino);
	ntfs_init_big_inode(vi);
	ni	= NTFS_I(vi);
	base_ni = NTFS_I(base_vi);
	/* Just mirror the values from the base inode. */
	vi->i_version	= base_vi->i_version;
	vi->i_uid	= base_vi->i_uid;
	vi->i_gid	= base_vi->i_gid;
	set_nlink(vi, base_vi->i_nlink);
	vi->i_mtime	= base_vi->i_mtime;
	vi->i_ctime	= base_vi->i_ctime;
	vi->i_atime	= base_vi->i_atime;
	vi->i_generation = ni->seq_no = base_ni->seq_no;
	/* Set inode type to zero but preserve permissions. */
	vi->i_mode	= base_vi->i_mode & ~S_IFMT;
	/* Map the mft record for the base inode. */
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (!ctx) {
		err = -ENOMEM;
		goto unm_err_out;
	}
	/* Find the index root attribute. */
	err = ntfs_attr_lookup(AT_INDEX_ROOT, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			ntfs_error(vi->i_sb, "$INDEX_ROOT attribute is "
					"missing.");
		goto unm_err_out;
	}
	a = ctx->attr;
	/* Set up the state. */
	if (unlikely(a->non_resident)) {
		ntfs_error(vol->sb, "$INDEX_ROOT attribute is not resident.");
		goto unm_err_out;
	}
	/* Ensure the attribute name is placed before the value. */
	if (unlikely(a->name_length && (le16_to_cpu(a->name_offset) >=
			le16_to_cpu(a->data.resident.value_offset)))) {
		ntfs_error(vol->sb, "$INDEX_ROOT attribute name is placed "
				"after the attribute value.");
		goto unm_err_out;
	}
	/*
	 * Compressed/encrypted/sparse index root is not allowed, except for
	 * directories of course but those are not dealt with here.
	 */
	if (a->flags & (ATTR_COMPRESSION_MASK | ATTR_IS_ENCRYPTED |
			ATTR_IS_SPARSE)) {
		ntfs_error(vi->i_sb, "Found compressed/encrypted/sparse index "
				"root attribute.");
		goto unm_err_out;
	}
	ir = (INDEX_ROOT*)((u8*)a + le16_to_cpu(a->data.resident.value_offset));
	ir_end = (u8*)ir + le32_to_cpu(a->data.resident.value_length);
	if (ir_end > (u8*)ctx->mrec + vol->mft_record_size) {
		ntfs_error(vi->i_sb, "$INDEX_ROOT attribute is corrupt.");
		goto unm_err_out;
	}
	index_end = (u8*)&ir->index + le32_to_cpu(ir->index.index_length);
	if (index_end > ir_end) {
		ntfs_error(vi->i_sb, "Index is corrupt.");
		goto unm_err_out;
	}
	if (ir->type) {
		ntfs_error(vi->i_sb, "Index type is not 0 (type is 0x%x).",
				le32_to_cpu(ir->type));
		goto unm_err_out;
	}
	ni->itype.index.collation_rule = ir->collation_rule;
	ntfs_debug("Index collation rule is 0x%x.",
			le32_to_cpu(ir->collation_rule));
	ni->itype.index.block_size = le32_to_cpu(ir->index_block_size);
	if (!is_power_of_2(ni->itype.index.block_size)) {
		ntfs_error(vi->i_sb, "Index block size (%u) is not a power of "
				"two.", ni->itype.index.block_size);
		goto unm_err_out;
	}
	if (ni->itype.index.block_size > PAGE_CACHE_SIZE) {
		ntfs_error(vi->i_sb, "Index block size (%u) > PAGE_CACHE_SIZE "
				"(%ld) is not supported.  Sorry.",
				ni->itype.index.block_size, PAGE_CACHE_SIZE);
		err = -EOPNOTSUPP;
		goto unm_err_out;
	}
	if (ni->itype.index.block_size < NTFS_BLOCK_SIZE) {
		ntfs_error(vi->i_sb, "Index block size (%u) < NTFS_BLOCK_SIZE "
				"(%i) is not supported.  Sorry.",
				ni->itype.index.block_size, NTFS_BLOCK_SIZE);
		err = -EOPNOTSUPP;
		goto unm_err_out;
	}
	ni->itype.index.block_size_bits = ffs(ni->itype.index.block_size) - 1;
	/* Determine the size of a vcn in the index. */
	if (vol->cluster_size <= ni->itype.index.block_size) {
		ni->itype.index.vcn_size = vol->cluster_size;
		ni->itype.index.vcn_size_bits = vol->cluster_size_bits;
	} else {
		ni->itype.index.vcn_size = vol->sector_size;
		ni->itype.index.vcn_size_bits = vol->sector_size_bits;
	}
	/* Check for presence of index allocation attribute. */
	if (!(ir->index.flags & LARGE_INDEX)) {
		/* No index allocation. */
		vi->i_size = ni->initialized_size = ni->allocated_size = 0;
		/* We are done with the mft record, so we release it. */
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(base_ni);
		m = NULL;
		ctx = NULL;
		goto skip_large_index_stuff;
	} /* LARGE_INDEX:  Index allocation present.  Setup state. */
	NInoSetIndexAllocPresent(ni);
	/* Find index allocation attribute. */
	ntfs_attr_reinit_search_ctx(ctx);
	err = ntfs_attr_lookup(AT_INDEX_ALLOCATION, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT)
			ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute is "
					"not present but $INDEX_ROOT "
					"indicated it is.");
		else
			ntfs_error(vi->i_sb, "Failed to lookup "
					"$INDEX_ALLOCATION attribute.");
		goto unm_err_out;
	}
	a = ctx->attr;
	if (!a->non_resident) {
		ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute is "
				"resident.");
		goto unm_err_out;
	}
	/*
	 * Ensure the attribute name is placed before the mapping pairs array.
	 */
	if (unlikely(a->name_length && (le16_to_cpu(a->name_offset) >=
			le16_to_cpu(
			a->data.non_resident.mapping_pairs_offset)))) {
		ntfs_error(vol->sb, "$INDEX_ALLOCATION attribute name is "
				"placed after the mapping pairs array.");
		goto unm_err_out;
	}
	if (a->flags & ATTR_IS_ENCRYPTED) {
		ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute is "
				"encrypted.");
		goto unm_err_out;
	}
	if (a->flags & ATTR_IS_SPARSE) {
		ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute is sparse.");
		goto unm_err_out;
	}
	if (a->flags & ATTR_COMPRESSION_MASK) {
		ntfs_error(vi->i_sb, "$INDEX_ALLOCATION attribute is "
				"compressed.");
		goto unm_err_out;
	}
	if (a->data.non_resident.lowest_vcn) {
		ntfs_error(vi->i_sb, "First extent of $INDEX_ALLOCATION "
				"attribute has non zero lowest_vcn.");
		goto unm_err_out;
	}
	vi->i_size = sle64_to_cpu(a->data.non_resident.data_size);
	ni->initialized_size = sle64_to_cpu(
			a->data.non_resident.initialized_size);
	ni->allocated_size = sle64_to_cpu(a->data.non_resident.allocated_size);
	/*
	 * We are done with the mft record, so we release it.  Otherwise
	 * we would deadlock in ntfs_attr_iget().
	 */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	m = NULL;
	ctx = NULL;
	/* Get the index bitmap attribute inode. */
	bvi = ntfs_attr_iget(base_vi, AT_BITMAP, ni->name, ni->name_len);
	if (IS_ERR(bvi)) {
		ntfs_error(vi->i_sb, "Failed to get bitmap attribute.");
		err = PTR_ERR(bvi);
		goto unm_err_out;
	}
	bni = NTFS_I(bvi);
	if (NInoCompressed(bni) || NInoEncrypted(bni) ||
			NInoSparse(bni)) {
		ntfs_error(vi->i_sb, "$BITMAP attribute is compressed and/or "
				"encrypted and/or sparse.");
		goto iput_unm_err_out;
	}
	/* Consistency check bitmap size vs. index allocation size. */
	bvi_size = i_size_read(bvi);
	if ((bvi_size << 3) < (vi->i_size >> ni->itype.index.block_size_bits)) {
		ntfs_error(vi->i_sb, "Index bitmap too small (0x%llx) for "
				"index allocation (0x%llx).", bvi_size << 3,
				vi->i_size);
		goto iput_unm_err_out;
	}
	iput(bvi);
skip_large_index_stuff:
	/* Setup the operations for this index inode. */
	vi->i_mapping->a_ops = &ntfs_mst_aops;
	vi->i_blocks = ni->allocated_size >> 9;
	/*
	 * Make sure the base inode doesn't go away and attach it to the
	 * index inode.
	 */
	igrab(base_vi);
	ni->ext.base_ntfs_ino = base_ni;
	ni->nr_extents = -1;

	ntfs_debug("Done.");
	return 0;
iput_unm_err_out:
	iput(bvi);
unm_err_out:
	if (!err)
		err = -EIO;
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
err_out:
	ntfs_error(vi->i_sb, "Failed with error code %i while reading index "
			"inode (mft_no 0x%lx, name_len %i.", err, vi->i_ino,
			ni->name_len);
	make_bad_inode(vi);
	if (err != -EOPNOTSUPP && err != -ENOMEM)
		NVolSetErrors(vol);
	return err;
}

/*
 * The MFT inode has special locking, so teach the lock validator
 * about this by splitting off the locking rules of the MFT from
 * the locking rules of other inodes. The MFT inode can never be
 * accessed from the VFS side (or even internally), only by the
 * map_mft functions.
 */
static struct lock_class_key mft_ni_runlist_lock_key, mft_ni_mrec_lock_key;

/**
 * ntfs_read_inode_mount - special read_inode for mount time use only
 * @vi:		inode to read
 *
 * Read inode FILE_MFT at mount time, only called with super_block lock
 * held from within the read_super() code path.
 *
 * This function exists because when it is called the page cache for $MFT/$DATA
 * is not initialized and hence we cannot get at the contents of mft records
 * by calling map_mft_record*().
 *
 * Further it needs to cope with the circular references problem, i.e. cannot
 * load any attributes other than $ATTRIBUTE_LIST until $DATA is loaded, because
 * we do not know where the other extent mft records are yet and again, because
 * we cannot call map_mft_record*() yet.  Obviously this applies only when an
 * attribute list is actually present in $MFT inode.
 *
 * We solve these problems by starting with the $DATA attribute before anything
 * else and iterating using ntfs_attr_lookup($DATA) over all extents.  As each
 * extent is found, we ntfs_mapping_pairs_decompress() including the implied
 * ntfs_runlists_merge().  Each step of the iteration necessarily provides
 * sufficient information for the next step to complete.
 *
 * This should work but there are two possible pit falls (see inline comments
 * below), but only time will tell if they are real pits or just smoke...
 */
int ntfs_read_inode_mount(struct inode *vi)
{
	VCN next_vcn, last_vcn, highest_vcn;
	s64 block;
	struct super_block *sb = vi->i_sb;
	ntfs_volume *vol = NTFS_SB(sb);
	struct buffer_head *bh;
	ntfs_inode *ni;
	MFT_RECORD *m = NULL;
	ATTR_RECORD *a;
	ntfs_attr_search_ctx *ctx;
	unsigned int i, nr_blocks;
	int err;

	ntfs_debug("Entering.");

	/* Initialize the ntfs specific part of @vi. */
	ntfs_init_big_inode(vi);

	ni = NTFS_I(vi);

	/* Setup the data attribute. It is special as it is mst protected. */
	NInoSetNonResident(ni);
	NInoSetMstProtected(ni);
	NInoSetSparseDisabled(ni);
	ni->type = AT_DATA;
	ni->name = NULL;
	ni->name_len = 0;
	/*
	 * This sets up our little cheat allowing us to reuse the async read io
	 * completion handler for directories.
	 */
	ni->itype.index.block_size = vol->mft_record_size;
	ni->itype.index.block_size_bits = vol->mft_record_size_bits;

	/* Very important! Needed to be able to call map_mft_record*(). */
	vol->mft_ino = vi;

	/* Allocate enough memory to read the first mft record. */
	if (vol->mft_record_size > 64 * 1024) {
		ntfs_error(sb, "Unsupported mft record size %i (max 64kiB).",
				vol->mft_record_size);
		goto err_out;
	}
	i = vol->mft_record_size;
	if (i < sb->s_blocksize)
		i = sb->s_blocksize;
	m = (MFT_RECORD*)ntfs_malloc_nofs(i);
	if (!m) {
		ntfs_error(sb, "Failed to allocate buffer for $MFT record 0.");
		goto err_out;
	}

	/* Determine the first block of the $MFT/$DATA attribute. */
	block = vol->mft_lcn << vol->cluster_size_bits >>
			sb->s_blocksize_bits;
	nr_blocks = vol->mft_record_size >> sb->s_blocksize_bits;
	if (!nr_blocks)
		nr_blocks = 1;

	/* Load $MFT/$DATA's first mft record. */
	for (i = 0; i < nr_blocks; i++) {
		bh = sb_bread(sb, block++);
		if (!bh) {
			ntfs_error(sb, "Device read failed.");
			goto err_out;
		}
		memcpy((char*)m + (i << sb->s_blocksize_bits), bh->b_data,
				sb->s_blocksize);
		brelse(bh);
	}

	/* Apply the mst fixups. */
	if (post_read_mst_fixup((NTFS_RECORD*)m, vol->mft_record_size)) {
		/* FIXME: Try to use the $MFTMirr now. */
		ntfs_error(sb, "MST fixup failed. $MFT is corrupt.");
		goto err_out;
	}

	/* Need this to sanity check attribute list references to $MFT. */
	vi->i_generation = ni->seq_no = le16_to_cpu(m->sequence_number);

	/* Provides readpage() and sync_page() for map_mft_record(). */
	vi->i_mapping->a_ops = &ntfs_mst_aops;

	ctx = ntfs_attr_get_search_ctx(ni, m);
	if (!ctx) {
		err = -ENOMEM;
		goto err_out;
	}

	/* Find the attribute list attribute if present. */
	err = ntfs_attr_lookup(AT_ATTRIBUTE_LIST, NULL, 0, 0, 0, NULL, 0, ctx);
	if (err) {
		if (unlikely(err != -ENOENT)) {
			ntfs_error(sb, "Failed to lookup attribute list "
					"attribute. You should run chkdsk.");
			goto put_err_out;
		}
	} else /* if (!err) */ {
		ATTR_LIST_ENTRY *al_entry, *next_al_entry;
		u8 *al_end;
		static const char *es = "  Not allowed.  $MFT is corrupt.  "
				"You should run chkdsk.";

		ntfs_debug("Attribute list attribute found in $MFT.");
		NInoSetAttrList(ni);
		a = ctx->attr;
		if (a->flags & ATTR_COMPRESSION_MASK) {
			ntfs_error(sb, "Attribute list attribute is "
					"compressed.%s", es);
			goto put_err_out;
		}
		if (a->flags & ATTR_IS_ENCRYPTED ||
				a->flags & ATTR_IS_SPARSE) {
			if (a->non_resident) {
				ntfs_error(sb, "Non-resident attribute list "
						"attribute is encrypted/"
						"sparse.%s", es);
				goto put_err_out;
			}
			ntfs_warning(sb, "Resident attribute list attribute "
					"in $MFT system file is marked "
					"encrypted/sparse which is not true.  "
					"However, Windows allows this and "
					"chkdsk does not detect or correct it "
					"so we will just ignore the invalid "
					"flags and pretend they are not set.");
		}
		/* Now allocate memory for the attribute list. */
		ni->attr_list_size = (u32)ntfs_attr_size(a);
		ni->attr_list = ntfs_malloc_nofs(ni->attr_list_size);
		if (!ni->attr_list) {
			ntfs_error(sb, "Not enough memory to allocate buffer "
					"for attribute list.");
			goto put_err_out;
		}
		if (a->non_resident) {
			NInoSetAttrListNonResident(ni);
			if (a->data.non_resident.lowest_vcn) {
				ntfs_error(sb, "Attribute list has non zero "
						"lowest_vcn. $MFT is corrupt. "
						"You should run chkdsk.");
				goto put_err_out;
			}
			/* Setup the runlist. */
			ni->attr_list_rl.rl = ntfs_mapping_pairs_decompress(vol,
					a, NULL);
			if (IS_ERR(ni->attr_list_rl.rl)) {
				err = PTR_ERR(ni->attr_list_rl.rl);
				ni->attr_list_rl.rl = NULL;
				ntfs_error(sb, "Mapping pairs decompression "
						"failed with error code %i.",
						-err);
				goto put_err_out;
			}
			/* Now load the attribute list. */
			if ((err = load_attribute_list(vol, &ni->attr_list_rl,
					ni->attr_list, ni->attr_list_size,
					sle64_to_cpu(a->data.
					non_resident.initialized_size)))) {
				ntfs_error(sb, "Failed to load attribute list "
						"attribute with error code %i.",
						-err);
				goto put_err_out;
			}
		} else /* if (!ctx.attr->non_resident) */ {
			if ((u8*)a + le16_to_cpu(
					a->data.resident.value_offset) +
					le32_to_cpu(
					a->data.resident.value_length) >
					(u8*)ctx->mrec + vol->mft_record_size) {
				ntfs_error(sb, "Corrupt attribute list "
						"attribute.");
				goto put_err_out;
			}
			/* Now copy the attribute list. */
			memcpy(ni->attr_list, (u8*)a + le16_to_cpu(
					a->data.resident.value_offset),
					le32_to_cpu(
					a->data.resident.value_length));
		}
		/* The attribute list is now setup in memory. */
		/*
		 * FIXME: I don't know if this case is actually possible.
		 * According to logic it is not possible but I have seen too
		 * many weird things in MS software to rely on logic... Thus we
		 * perform a manual search and make sure the first $MFT/$DATA
		 * extent is in the base inode. If it is not we abort with an
		 * error and if we ever see a report of this error we will need
		 * to do some magic in order to have the necessary mft record
		 * loaded and in the right place in the page cache. But
		 * hopefully logic will prevail and this never happens...
		 */
		al_entry = (ATTR_LIST_ENTRY*)ni->attr_list;
		al_end = (u8*)al_entry + ni->attr_list_size;
		for (;; al_entry = next_al_entry) {
			/* Out of bounds check. */
			if ((u8*)al_entry < ni->attr_list ||
					(u8*)al_entry > al_end)
				goto em_put_err_out;
			/* Catch the end of the attribute list. */
			if ((u8*)al_entry == al_end)
				goto em_put_err_out;
			if (!al_entry->length)
				goto em_put_err_out;
			if ((u8*)al_entry + 6 > al_end || (u8*)al_entry +
					le16_to_cpu(al_entry->length) > al_end)
				goto em_put_err_out;
			next_al_entry = (ATTR_LIST_ENTRY*)((u8*)al_entry +
					le16_to_cpu(al_entry->length));
			if (le32_to_cpu(al_entry->type) > le32_to_cpu(AT_DATA))
				goto em_put_err_out;
			if (AT_DATA != al_entry->type)
				continue;
			/* We want an unnamed attribute. */
			if (al_entry->name_length)
				goto em_put_err_out;
			/* Want the first entry, i.e. lowest_vcn == 0. */
			if (al_entry->lowest_vcn)
				goto em_put_err_out;
			/* First entry has to be in the base mft record. */
			if (MREF_LE(al_entry->mft_reference) != vi->i_ino) {
				/* MFT references do not match, logic fails. */
				ntfs_error(sb, "BUG: The first $DATA extent "
						"of $MFT is not in the base "
						"mft record. Please report "
						"you saw this message to "
						"linux-ntfs-dev@lists."
						"sourceforge.net");
				goto put_err_out;
			} else {
				/* Sequence numbers must match. */
				if (MSEQNO_LE(al_entry->mft_reference) !=
						ni->seq_no)
					goto em_put_err_out;
				/* Got it. All is ok. We can stop now. */
				break;
			}
		}
	}

	ntfs_attr_reinit_search_ctx(ctx);

	/* Now load all attribute extents. */
	a = NULL;
	next_vcn = last_vcn = highest_vcn = 0;
	while (!(err = ntfs_attr_lookup(AT_DATA, NULL, 0, 0, next_vcn, NULL, 0,
			ctx))) {
		runlist_element *nrl;

		/* Cache the current attribute. */
		a = ctx->attr;
		/* $MFT must be non-resident. */
		if (!a->non_resident) {
			ntfs_error(sb, "$MFT must be non-resident but a "
					"resident extent was found. $MFT is "
					"corrupt. Run chkdsk.");
			goto put_err_out;
		}
		/* $MFT must be uncompressed and unencrypted. */
		if (a->flags & ATTR_COMPRESSION_MASK ||
				a->flags & ATTR_IS_ENCRYPTED ||
				a->flags & ATTR_IS_SPARSE) {
			ntfs_error(sb, "$MFT must be uncompressed, "
					"non-sparse, and unencrypted but a "
					"compressed/sparse/encrypted extent "
					"was found. $MFT is corrupt. Run "
					"chkdsk.");
			goto put_err_out;
		}
		/*
		 * Decompress the mapping pairs array of this extent and merge
		 * the result into the existing runlist. No need for locking
		 * as we have exclusive access to the inode at this time and we
		 * are a mount in progress task, too.
		 */
		nrl = ntfs_mapping_pairs_decompress(vol, a, ni->runlist.rl);
		if (IS_ERR(nrl)) {
			ntfs_error(sb, "ntfs_mapping_pairs_decompress() "
					"failed with error code %ld.  $MFT is "
					"corrupt.", PTR_ERR(nrl));
			goto put_err_out;
		}
		ni->runlist.rl = nrl;

		/* Are we in the first extent? */
		if (!next_vcn) {
			if (a->data.non_resident.lowest_vcn) {
				ntfs_error(sb, "First extent of $DATA "
						"attribute has non zero "
						"lowest_vcn. $MFT is corrupt. "
						"You should run chkdsk.");
				goto put_err_out;
			}
			/* Get the last vcn in the $DATA attribute. */
			last_vcn = sle64_to_cpu(
					a->data.non_resident.allocated_size)
					>> vol->cluster_size_bits;
			/* Fill in the inode size. */
			vi->i_size = sle64_to_cpu(
					a->data.non_resident.data_size);
			ni->initialized_size = sle64_to_cpu(
					a->data.non_resident.initialized_size);
			ni->allocated_size = sle64_to_cpu(
					a->data.non_resident.allocated_size);
			/*
			 * Verify the number of mft records does not exceed
			 * 2^32 - 1.
			 */
			if ((vi->i_size >> vol->mft_record_size_bits) >=
					(1ULL << 32)) {
				ntfs_error(sb, "$MFT is too big! Aborting.");
				goto put_err_out;
			}
			/*
			 * We have got the first extent of the runlist for
			 * $MFT which means it is now relatively safe to call
			 * the normal ntfs_read_inode() function.
			 * Complete reading the inode, this will actually
			 * re-read the mft record for $MFT, this time entering
			 * it into the page cache with which we complete the
			 * kick start of the volume. It should be safe to do
			 * this now as the first extent of $MFT/$DATA is
			 * already known and we would hope that we don't need
			 * further extents in order to find the other
			 * attributes belonging to $MFT. Only time will tell if
			 * this is really the case. If not we will have to play
			 * magic at this point, possibly duplicating a lot of
			 * ntfs_read_inode() at this point. We will need to
			 * ensure we do enough of its work to be able to call
			 * ntfs_read_inode() on extents of $MFT/$DATA. But lets
			 * hope this never happens...
			 */
			ntfs_read_locked_inode(vi);
			if (is_bad_inode(vi)) {
				ntfs_error(sb, "ntfs_read_inode() of $MFT "
						"failed. BUG or corrupt $MFT. "
						"Run chkdsk and if no errors "
						"are found, please report you "
						"saw this message to "
						"linux-ntfs-dev@lists."
						"sourceforge.net");
				ntfs_attr_put_search_ctx(ctx);
				/* Revert to the safe super operations. */
				ntfs_free(m);
				return -1;
			}
			/*
			 * Re-initialize some specifics about $MFT's inode as
			 * ntfs_read_inode() will have set up the default ones.
			 */
			/* Set uid and gid to root. */
			vi->i_uid = GLOBAL_ROOT_UID;
			vi->i_gid = GLOBAL_ROOT_GID;
			/* Regular file. No access for anyone. */
			vi->i_mode = S_IFREG;
			/* No VFS initiated operations allowed for $MFT. */
			vi->i_op = &ntfs_empty_inode_ops;
			vi->i_fop = &ntfs_empty_file_ops;
		}

		/* Get the lowest vcn for the next extent. */
		highest_vcn = sle64_to_cpu(a->data.non_resident.highest_vcn);
		next_vcn = highest_vcn + 1;

		/* Only one extent or error, which we catch below. */
		if (next_vcn <= 0)
			break;

		/* Avoid endless loops due to corruption. */
		if (next_vcn < sle64_to_cpu(
				a->data.non_resident.lowest_vcn)) {
			ntfs_error(sb, "$MFT has corrupt attribute list "
					"attribute. Run chkdsk.");
			goto put_err_out;
		}
	}
	if (err != -ENOENT) {
		ntfs_error(sb, "Failed to lookup $MFT/$DATA attribute extent. "
				"$MFT is corrupt. Run chkdsk.");
		goto put_err_out;
	}
	if (!a) {
		ntfs_error(sb, "$MFT/$DATA attribute not found. $MFT is "
				"corrupt. Run chkdsk.");
		goto put_err_out;
	}
	if (highest_vcn && highest_vcn != last_vcn - 1) {
		ntfs_error(sb, "Failed to load the complete runlist for "
				"$MFT/$DATA. Driver bug or corrupt $MFT. "
				"Run chkdsk.");
		ntfs_debug("highest_vcn = 0x%llx, last_vcn - 1 = 0x%llx",
				(unsigned long long)highest_vcn,
				(unsigned long long)last_vcn - 1);
		goto put_err_out;
	}
	ntfs_attr_put_search_ctx(ctx);
	ntfs_debug("Done.");
	ntfs_free(m);

	/*
	 * Split the locking rules of the MFT inode from the
	 * locking rules of other inodes:
	 */
	lockdep_set_class(&ni->runlist.lock, &mft_ni_runlist_lock_key);
	lockdep_set_class(&ni->mrec_lock, &mft_ni_mrec_lock_key);

	return 0;

em_put_err_out:
	ntfs_error(sb, "Couldn't find first extent of $DATA attribute in "
			"attribute list. $MFT is corrupt. Run chkdsk.");
put_err_out:
	ntfs_attr_put_search_ctx(ctx);
err_out:
	ntfs_error(sb, "Failed. Marking inode as bad.");
	make_bad_inode(vi);
	ntfs_free(m);
	return -1;
}

static void __ntfs_clear_inode(ntfs_inode *ni)
{
	/* Free all alocated memory. */
	down_write(&ni->runlist.lock);
	if (ni->runlist.rl) {
		ntfs_free(ni->runlist.rl);
		ni->runlist.rl = NULL;
	}
	up_write(&ni->runlist.lock);

	if (ni->attr_list) {
		ntfs_free(ni->attr_list);
		ni->attr_list = NULL;
	}

	down_write(&ni->attr_list_rl.lock);
	if (ni->attr_list_rl.rl) {
		ntfs_free(ni->attr_list_rl.rl);
		ni->attr_list_rl.rl = NULL;
	}
	up_write(&ni->attr_list_rl.lock);

	if (ni->name_len && ni->name != I30) {
		/* Catch bugs... */
		BUG_ON(!ni->name);
		kfree(ni->name);
	}
}

void ntfs_clear_extent_inode(ntfs_inode *ni)
{
	ntfs_debug("Entering for inode 0x%lx.", ni->mft_no);

	BUG_ON(NInoAttr(ni));
	BUG_ON(ni->nr_extents != -1);

#ifdef NTFS_RW
	if (NInoDirty(ni)) {
		if (!is_bad_inode(VFS_I(ni->ext.base_ntfs_ino)))
			ntfs_error(ni->vol->sb, "Clearing dirty extent inode!  "
					"Losing data!  This is a BUG!!!");
		// FIXME:  Do something!!!
	}
#endif /* NTFS_RW */

	__ntfs_clear_inode(ni);

	/* Bye, bye... */
	ntfs_destroy_extent_inode(ni);
}

/**
 * ntfs_evict_big_inode - clean up the ntfs specific part of an inode
 * @vi:		vfs inode pending annihilation
 *
 * When the VFS is going to remove an inode from memory, ntfs_clear_big_inode()
 * is called, which deallocates all memory belonging to the NTFS specific part
 * of the inode and returns.
 *
 * If the MFT record is dirty, we commit it before doing anything else.
 */
void ntfs_evict_big_inode(struct inode *vi)
{
	ntfs_inode *ni = NTFS_I(vi);

	truncate_inode_pages_final(&vi->i_data);
	clear_inode(vi);

#ifdef NTFS_RW
	if (NInoDirty(ni)) {
		bool was_bad = (is_bad_inode(vi));

		/* Committing the inode also commits all extent inodes. */
		ntfs_commit_inode(vi);

		if (!was_bad && (is_bad_inode(vi) || NInoDirty(ni))) {
			ntfs_error(vi->i_sb, "Failed to commit dirty inode "
					"0x%lx.  Losing data!", vi->i_ino);
			// FIXME:  Do something!!!
		}
	}
#endif /* NTFS_RW */

	/* No need to lock at this stage as no one else has a reference. */
	if (ni->nr_extents > 0) {
		int i;

		for (i = 0; i < ni->nr_extents; i++)
			ntfs_clear_extent_inode(ni->ext.extent_ntfs_inos[i]);
		kfree(ni->ext.extent_ntfs_inos);
	}

	__ntfs_clear_inode(ni);

	if (NInoAttr(ni)) {
		/* Release the base inode if we are holding it. */
		if (ni->nr_extents == -1) {
			iput(VFS_I(ni->ext.base_ntfs_ino));
			ni->nr_extents = 0;
			ni->ext.base_ntfs_ino = NULL;
		}
	}
	return;
}

/**
 * ntfs_show_options - show mount options in /proc/mounts
 * @sf:		seq_file in which to write our mount options
 * @root:	root of the mounted tree whose mount options to display
 *
 * Called by the VFS once for each mounted ntfs volume when someone reads
 * /proc/mounts in order to display the NTFS specific mount options of each
 * mount. The mount options of fs specified by @root are written to the seq file
 * @sf and success is returned.
 */
int ntfs_show_options(struct seq_file *sf, struct dentry *root)
{
	ntfs_volume *vol = NTFS_SB(root->d_sb);
	int i;

	seq_printf(sf, ",uid=%i", from_kuid_munged(&init_user_ns, vol->uid));
	seq_printf(sf, ",gid=%i", from_kgid_munged(&init_user_ns, vol->gid));
	if (vol->fmask == vol->dmask)
		seq_printf(sf, ",umask=0%o", vol->fmask);
	else {
		seq_printf(sf, ",fmask=0%o", vol->fmask);
		seq_printf(sf, ",dmask=0%o", vol->dmask);
	}
	seq_printf(sf, ",nls=%s", vol->nls_map->charset);
	if (NVolCaseSensitive(vol))
		seq_printf(sf, ",case_sensitive");
	if (NVolShowSystemFiles(vol))
		seq_printf(sf, ",show_sys_files");
	if (!NVolSparseEnabled(vol))
		seq_printf(sf, ",disable_sparse");
	for (i = 0; on_errors_arr[i].val; i++) {
		if (on_errors_arr[i].val & vol->on_errors)
			seq_printf(sf, ",errors=%s", on_errors_arr[i].str);
	}
	seq_printf(sf, ",mft_zone_multiplier=%i", vol->mft_zone_multiplier);
	return 0;
}

#ifdef NTFS_RW

static const char *es = "  Leaving inconsistent metadata.  Unmount and run "
		"chkdsk.";

/**
 * ntfs_truncate - called when the i_size of an ntfs inode is changed
 * @vi:		inode for which the i_size was changed
 *
 * We only support i_size changes for normal files at present, i.e. not
 * compressed and not encrypted.  This is enforced in ntfs_setattr(), see
 * below.
 *
 * The kernel guarantees that @vi is a regular file (S_ISREG() is true) and
 * that the change is allowed.
 *
 * This implies for us that @vi is a file inode rather than a directory, index,
 * or attribute inode as well as that @vi is a base inode.
 *
 * Returns 0 on success or -errno on error.
 *
 * Called with ->i_mutex held.
 */
int ntfs_truncate(struct inode *vi)
{
	s64 new_size, old_size, nr_freed, new_alloc_size, old_alloc_size;
	VCN highest_vcn;
	unsigned long flags;
	ntfs_inode *base_ni, *ni = NTFS_I(vi);
	ntfs_volume *vol = ni->vol;
	ntfs_attr_search_ctx *ctx;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	const char *te = "  Leaving file length out of sync with i_size.";
	int err, mp_size, size_change, alloc_change;
	u32 attr_len;

	ntfs_debug("Entering for inode 0x%lx.", vi->i_ino);
	BUG_ON(NInoAttr(ni));
	BUG_ON(S_ISDIR(vi->i_mode));
	BUG_ON(NInoMstProtected(ni));
	BUG_ON(ni->nr_extents < 0);
retry_truncate:
	/*
	 * Lock the runlist for writing and map the mft record to ensure it is
	 * safe to mess with the attribute runlist and sizes.
	 */
	down_write(&ni->runlist.lock);
	if (!NInoAttr(ni))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	m = map_mft_record(base_ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		ntfs_error(vi->i_sb, "Failed to map mft record for inode 0x%lx "
				"(error code %d).%s", vi->i_ino, err, te);
		ctx = NULL;
		m = NULL;
		goto old_bad_out;
	}
	ctx = ntfs_attr_get_search_ctx(base_ni, m);
	if (unlikely(!ctx)) {
		ntfs_error(vi->i_sb, "Failed to allocate a search context for "
				"inode 0x%lx (not enough memory).%s",
				vi->i_ino, te);
		err = -ENOMEM;
		goto old_bad_out;
	}
	err = ntfs_attr_lookup(ni->type, ni->name, ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		if (err == -ENOENT) {
			ntfs_error(vi->i_sb, "Open attribute is missing from "
					"mft record.  Inode 0x%lx is corrupt.  "
					"Run chkdsk.%s", vi->i_ino, te);
			err = -EIO;
		} else
			ntfs_error(vi->i_sb, "Failed to lookup attribute in "
					"inode 0x%lx (error code %d).%s",
					vi->i_ino, err, te);
		goto old_bad_out;
	}
	m = ctx->mrec;
	a = ctx->attr;
	/*
	 * The i_size of the vfs inode is the new size for the attribute value.
	 */
	new_size = i_size_read(vi);
	/* The current size of the attribute value is the old size. */
	old_size = ntfs_attr_size(a);
	/* Calculate the new allocated size. */
	if (NInoNonResident(ni))
		new_alloc_size = (new_size + vol->cluster_size - 1) &
				~(s64)vol->cluster_size_mask;
	else
		new_alloc_size = (new_size + 7) & ~7;
	/* The current allocated size is the old allocated size. */
	read_lock_irqsave(&ni->size_lock, flags);
	old_alloc_size = ni->allocated_size;
	read_unlock_irqrestore(&ni->size_lock, flags);
	/*
	 * The change in the file size.  This will be 0 if no change, >0 if the
	 * size is growing, and <0 if the size is shrinking.
	 */
	size_change = -1;
	if (new_size - old_size >= 0) {
		size_change = 1;
		if (new_size == old_size)
			size_change = 0;
	}
	/* As above for the allocated size. */
	alloc_change = -1;
	if (new_alloc_size - old_alloc_size >= 0) {
		alloc_change = 1;
		if (new_alloc_size == old_alloc_size)
			alloc_change = 0;
	}
	/*
	 * If neither the size nor the allocation are being changed there is
	 * nothing to do.
	 */
	if (!size_change && !alloc_change)
		goto unm_done;
	/* If the size is changing, check if new size is allowed in $AttrDef. */
	if (size_change) {
		err = ntfs_attr_size_bounds_check(vol, ni->type, new_size);
		if (unlikely(err)) {
			if (err == -ERANGE) {
				ntfs_error(vol->sb, "Truncate would cause the "
						"inode 0x%lx to %simum size "
						"for its attribute type "
						"(0x%x).  Aborting truncate.",
						vi->i_ino,
						new_size > old_size ? "exceed "
						"the max" : "go under the min",
						le32_to_cpu(ni->type));
				err = -EFBIG;
			} else {
				ntfs_error(vol->sb, "Inode 0x%lx has unknown "
						"attribute type 0x%x.  "
						"Aborting truncate.",
						vi->i_ino,
						le32_to_cpu(ni->type));
				err = -EIO;
			}
			/* Reset the vfs inode size to the old size. */
			i_size_write(vi, old_size);
			goto err_out;
		}
	}
	if (NInoCompressed(ni) || NInoEncrypted(ni)) {
		ntfs_warning(vi->i_sb, "Changes in inode size are not "
				"supported yet for %s files, ignoring.",
				NInoCompressed(ni) ? "compressed" :
				"encrypted");
		err = -EOPNOTSUPP;
		goto bad_out;
	}
	if (a->non_resident)
		goto do_non_resident_truncate;
	BUG_ON(NInoNonResident(ni));
	/* Resize the attribute record to best fit the new attribute size. */
	if (new_size < vol->mft_record_size &&
			!ntfs_resident_attr_value_resize(m, a, new_size)) {
		/* The resize succeeded! */
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
		write_lock_irqsave(&ni->size_lock, flags);
		/* Update the sizes in the ntfs inode and all is done. */
		ni->allocated_size = le32_to_cpu(a->length) -
				le16_to_cpu(a->data.resident.value_offset);
		/*
		 * Note ntfs_resident_attr_value_resize() has already done any
		 * necessary data clearing in the attribute record.  When the
		 * file is being shrunk vmtruncate() will already have cleared
		 * the top part of the last partial page, i.e. since this is
		 * the resident case this is the page with index 0.  However,
		 * when the file is being expanded, the page cache page data
		 * between the old data_size, i.e. old_size, and the new_size
		 * has not been zeroed.  Fortunately, we do not need to zero it
		 * either since on one hand it will either already be zero due
		 * to both readpage and writepage clearing partial page data
		 * beyond i_size in which case there is nothing to do or in the
		 * case of the file being mmap()ped at the same time, POSIX
		 * specifies that the behaviour is unspecified thus we do not
		 * have to do anything.  This means that in our implementation
		 * in the rare case that the file is mmap()ped and a write
		 * occurred into the mmap()ped region just beyond the file size
		 * and writepage has not yet been called to write out the page
		 * (which would clear the area beyond the file size) and we now
		 * extend the file size to incorporate this dirty region
		 * outside the file size, a write of the page would result in
		 * this data being written to disk instead of being cleared.
		 * Given both POSIX and the Linux mmap(2) man page specify that
		 * this corner case is undefined, we choose to leave it like
		 * that as this is much simpler for us as we cannot lock the
		 * relevant page now since we are holding too many ntfs locks
		 * which would result in a lock reversal deadlock.
		 */
		ni->initialized_size = new_size;
		write_unlock_irqrestore(&ni->size_lock, flags);
		goto unm_done;
	}
	/* If the above resize failed, this must be an attribute extension. */
	BUG_ON(size_change < 0);
	/*
	 * We have to drop all the locks so we can call
	 * ntfs_attr_make_non_resident().  This could be optimised by try-
	 * locking the first page cache page and only if that fails dropping
	 * the locks, locking the page, and redoing all the locking and
	 * lookups.  While this would be a huge optimisation, it is not worth
	 * it as this is definitely a slow code path as it only ever can happen
	 * once for any given file.
	 */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	up_write(&ni->runlist.lock);
	/*
	 * Not enough space in the mft record, try to make the attribute
	 * non-resident and if successful restart the truncation process.
	 */
	err = ntfs_attr_make_non_resident(ni, old_size);
	if (likely(!err))
		goto retry_truncate;
	/*
	 * Could not make non-resident.  If this is due to this not being
	 * permitted for this attribute type or there not being enough space,
	 * try to make other attributes non-resident.  Otherwise fail.
	 */
	if (unlikely(err != -EPERM && err != -ENOSPC)) {
		ntfs_error(vol->sb, "Cannot truncate inode 0x%lx, attribute "
				"type 0x%x, because the conversion from "
				"resident to non-resident attribute failed "
				"with error code %i.", vi->i_ino,
				(unsigned)le32_to_cpu(ni->type), err);
		if (err != -ENOMEM)
			err = -EIO;
		goto conv_err_out;
	}
	/* TODO: Not implemented from here, abort. */
	if (err == -ENOSPC)
		ntfs_error(vol->sb, "Not enough space in the mft record/on "
				"disk for the non-resident attribute value.  "
				"This case is not implemented yet.");
	else /* if (err == -EPERM) */
		ntfs_error(vol->sb, "This attribute type may not be "
				"non-resident.  This case is not implemented "
				"yet.");
	err = -EOPNOTSUPP;
	goto conv_err_out;
#if 0
	// TODO: Attempt to make other attributes non-resident.
	if (!err)
		goto do_resident_extend;
	/*
	 * Both the attribute list attribute and the standard information
	 * attribute must remain in the base inode.  Thus, if this is one of
	 * these attributes, we have to try to move other attributes out into
	 * extent mft records instead.
	 */
	if (ni->type == AT_ATTRIBUTE_LIST ||
			ni->type == AT_STANDARD_INFORMATION) {
		// TODO: Attempt to move other attributes into extent mft
		// records.
		err = -EOPNOTSUPP;
		if (!err)
			goto do_resident_extend;
		goto err_out;
	}
	// TODO: Attempt to move this attribute to an extent mft record, but
	// only if it is not already the only attribute in an mft record in
	// which case there would be nothing to gain.
	err = -EOPNOTSUPP;
	if (!err)
		goto do_resident_extend;
	/* There is nothing we can do to make enough space. )-: */
	goto err_out;
#endif
do_non_resident_truncate:
	BUG_ON(!NInoNonResident(ni));
	if (alloc_change < 0) {
		highest_vcn = sle64_to_cpu(a->data.non_resident.highest_vcn);
		if (highest_vcn > 0 &&
				old_alloc_size >> vol->cluster_size_bits >
				highest_vcn + 1) {
			/*
			 * This attribute has multiple extents.  Not yet
			 * supported.
			 */
			ntfs_error(vol->sb, "Cannot truncate inode 0x%lx, "
					"attribute type 0x%x, because the "
					"attribute is highly fragmented (it "
					"consists of multiple extents) and "
					"this case is not implemented yet.",
					vi->i_ino,
					(unsigned)le32_to_cpu(ni->type));
			err = -EOPNOTSUPP;
			goto bad_out;
		}
	}
	/*
	 * If the size is shrinking, need to reduce the initialized_size and
	 * the data_size before reducing the allocation.
	 */
	if (size_change < 0) {
		/*
		 * Make the valid size smaller (i_size is already up-to-date).
		 */
		write_lock_irqsave(&ni->size_lock, flags);
		if (new_size < ni->initialized_size) {
			ni->initialized_size = new_size;
			a->data.non_resident.initialized_size =
					cpu_to_sle64(new_size);
		}
		a->data.non_resident.data_size = cpu_to_sle64(new_size);
		write_unlock_irqrestore(&ni->size_lock, flags);
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
		/* If the allocated size is not changing, we are done. */
		if (!alloc_change)
			goto unm_done;
		/*
		 * If the size is shrinking it makes no sense for the
		 * allocation to be growing.
		 */
		BUG_ON(alloc_change > 0);
	} else /* if (size_change >= 0) */ {
		/*
		 * The file size is growing or staying the same but the
		 * allocation can be shrinking, growing or staying the same.
		 */
		if (alloc_change > 0) {
			/*
			 * We need to extend the allocation and possibly update
			 * the data size.  If we are updating the data size,
			 * since we are not touching the initialized_size we do
			 * not need to worry about the actual data on disk.
			 * And as far as the page cache is concerned, there
			 * will be no pages beyond the old data size and any
			 * partial region in the last page between the old and
			 * new data size (or the end of the page if the new
			 * data size is outside the page) does not need to be
			 * modified as explained above for the resident
			 * attribute truncate case.  To do this, we simply drop
			 * the locks we hold and leave all the work to our
			 * friendly helper ntfs_attr_extend_allocation().
			 */
			ntfs_attr_put_search_ctx(ctx);
			unmap_mft_record(base_ni);
			up_write(&ni->runlist.lock);
			err = ntfs_attr_extend_allocation(ni, new_size,
					size_change > 0 ? new_size : -1, -1);
			/*
			 * ntfs_attr_extend_allocation() will have done error
			 * output already.
			 */
			goto done;
		}
		if (!alloc_change)
			goto alloc_done;
	}
	/* alloc_change < 0 */
	/* Free the clusters. */
	nr_freed = ntfs_cluster_free(ni, new_alloc_size >>
			vol->cluster_size_bits, -1, ctx);
	m = ctx->mrec;
	a = ctx->attr;
	if (unlikely(nr_freed < 0)) {
		ntfs_error(vol->sb, "Failed to release cluster(s) (error code "
				"%lli).  Unmount and run chkdsk to recover "
				"the lost cluster(s).", (long long)nr_freed);
		NVolSetErrors(vol);
		nr_freed = 0;
	}
	/* Truncate the runlist. */
	err = ntfs_rl_truncate_nolock(vol, &ni->runlist,
			new_alloc_size >> vol->cluster_size_bits);
	/*
	 * If the runlist truncation failed and/or the search context is no
	 * longer valid, we cannot resize the attribute record or build the
	 * mapping pairs array thus we mark the inode bad so that no access to
	 * the freed clusters can happen.
	 */
	if (unlikely(err || IS_ERR(m))) {
		ntfs_error(vol->sb, "Failed to %s (error code %li).%s",
				IS_ERR(m) ?
				"restore attribute search context" :
				"truncate attribute runlist",
				IS_ERR(m) ? PTR_ERR(m) : err, es);
		err = -EIO;
		goto bad_out;
	}
	/* Get the size for the shrunk mapping pairs array for the runlist. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, ni->runlist.rl, 0, -1);
	if (unlikely(mp_size <= 0)) {
		ntfs_error(vol->sb, "Cannot shrink allocation of inode 0x%lx, "
				"attribute type 0x%x, because determining the "
				"size for the mapping pairs failed with error "
				"code %i.%s", vi->i_ino,
				(unsigned)le32_to_cpu(ni->type), mp_size, es);
		err = -EIO;
		goto bad_out;
	}
	/*
	 * Shrink the attribute record for the new mapping pairs array.  Note,
	 * this cannot fail since we are making the attribute smaller thus by
	 * definition there is enough space to do so.
	 */
	attr_len = le32_to_cpu(a->length);
	err = ntfs_attr_record_resize(m, a, mp_size +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset));
	BUG_ON(err);
	/*
	 * Generate the mapping pairs array directly into the attribute record.
	 */
	err = ntfs_mapping_pairs_build(vol, (u8*)a +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset),
			mp_size, ni->runlist.rl, 0, -1, NULL);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Cannot shrink allocation of inode 0x%lx, "
				"attribute type 0x%x, because building the "
				"mapping pairs failed with error code %i.%s",
				vi->i_ino, (unsigned)le32_to_cpu(ni->type),
				err, es);
		err = -EIO;
		goto bad_out;
	}
	/* Update the allocated/compressed size as well as the highest vcn. */
	a->data.non_resident.highest_vcn = cpu_to_sle64((new_alloc_size >>
			vol->cluster_size_bits) - 1);
	write_lock_irqsave(&ni->size_lock, flags);
	ni->allocated_size = new_alloc_size;
	a->data.non_resident.allocated_size = cpu_to_sle64(new_alloc_size);
	if (NInoSparse(ni) || NInoCompressed(ni)) {
		if (nr_freed) {
			ni->itype.compressed.size -= nr_freed <<
					vol->cluster_size_bits;
			BUG_ON(ni->itype.compressed.size < 0);
			a->data.non_resident.compressed_size = cpu_to_sle64(
					ni->itype.compressed.size);
			vi->i_blocks = ni->itype.compressed.size >> 9;
		}
	} else
		vi->i_blocks = new_alloc_size >> 9;
	write_unlock_irqrestore(&ni->size_lock, flags);
	/*
	 * We have shrunk the allocation.  If this is a shrinking truncate we
	 * have already dealt with the initialized_size and the data_size above
	 * and we are done.  If the truncate is only changing the allocation
	 * and not the data_size, we are also done.  If this is an extending
	 * truncate, need to extend the data_size now which is ensured by the
	 * fact that @size_change is positive.
	 */
alloc_done:
	/*
	 * If the size is growing, need to update it now.  If it is shrinking,
	 * we have already updated it above (before the allocation change).
	 */
	if (size_change > 0)
		a->data.non_resident.data_size = cpu_to_sle64(new_size);
	/* Ensure the modified mft record is written out. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
unm_done:
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(base_ni);
	up_write(&ni->runlist.lock);
done:
	/* Update the mtime and ctime on the base inode. */
	/* normally ->truncate shouldn't update ctime or mtime,
	 * but ntfs did before so it got a copy & paste version
	 * of file_update_time.  one day someone should fix this
	 * for real.
	 */
	if (!IS_NOCMTIME(VFS_I(base_ni)) && !IS_RDONLY(VFS_I(base_ni))) {
		struct timespec now = current_fs_time(VFS_I(base_ni)->i_sb);
		int sync_it = 0;

		if (!timespec_equal(&VFS_I(base_ni)->i_mtime, &now) ||
		    !timespec_equal(&VFS_I(base_ni)->i_ctime, &now))
			sync_it = 1;
		VFS_I(base_ni)->i_mtime = now;
		VFS_I(base_ni)->i_ctime = now;

		if (sync_it)
			mark_inode_dirty_sync(VFS_I(base_ni));
	}

	if (likely(!err)) {
		NInoClearTruncateFailed(ni);
		ntfs_debug("Done.");
	}
	return err;
old_bad_out:
	old_size = -1;
bad_out:
	if (err != -ENOMEM && err != -EOPNOTSUPP)
		NVolSetErrors(vol);
	if (err != -EOPNOTSUPP)
		NInoSetTruncateFailed(ni);
	else if (old_size >= 0)
		i_size_write(vi, old_size);
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(base_ni);
	up_write(&ni->runlist.lock);
out:
	ntfs_debug("Failed.  Returning error code %i.", err);
	return err;
conv_err_out:
	if (err != -ENOMEM && err != -EOPNOTSUPP)
		NVolSetErrors(vol);
	if (err != -EOPNOTSUPP)
		NInoSetTruncateFailed(ni);
	else
		i_size_write(vi, old_size);
	goto out;
}

/**
 * ntfs_truncate_vfs - wrapper for ntfs_truncate() that has no return value
 * @vi:		inode for which the i_size was changed
 *
 * Wrapper for ntfs_truncate() that has no return value.
 *
 * See ntfs_truncate() description above for details.
 */
#ifdef NTFS_RW
void ntfs_truncate_vfs(struct inode *vi) {
	ntfs_truncate(vi);
}
#endif

/**
 * ntfs_setattr - called from notify_change() when an attribute is being changed
 * @dentry:	dentry whose attributes to change
 * @attr:	structure describing the attributes and the changes
 *
 * We have to trap VFS attempts to truncate the file described by @dentry as
 * soon as possible, because we do not implement changes in i_size yet.  So we
 * abort all i_size changes here.
 *
 * We also abort all changes of user, group, and mode as we do not implement
 * the NTFS ACLs yet.
 *
 * Called with ->i_mutex held.
 */
int ntfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *vi = dentry->d_inode;
	int err;
	unsigned int ia_valid = attr->ia_valid;

	err = inode_change_ok(vi, attr);
	if (err)
		goto out;
	/* We do not support NTFS ACLs yet. */
	if (ia_valid & (ATTR_UID | ATTR_GID | ATTR_MODE)) {
		ntfs_warning(vi->i_sb, "Changes in user/group/mode are not "
				"supported yet, ignoring.");
		err = -EOPNOTSUPP;
		goto out;
	}
	if (ia_valid & ATTR_SIZE) {
		if (attr->ia_size != i_size_read(vi)) {
			ntfs_inode *ni = NTFS_I(vi);
			/*
			 * FIXME: For now we do not support resizing of
			 * compressed or encrypted files yet.
			 */
			if (NInoCompressed(ni) || NInoEncrypted(ni)) {
				ntfs_warning(vi->i_sb, "Changes in inode size "
						"are not supported yet for "
						"%s files, ignoring.",
						NInoCompressed(ni) ?
						"compressed" : "encrypted");
				err = -EOPNOTSUPP;
			} else {
				truncate_setsize(vi, attr->ia_size);
				ntfs_truncate_vfs(vi);
			}
			if (err || ia_valid == ATTR_SIZE)
				goto out;
		} else {
			/*
			 * We skipped the truncate but must still update
			 * timestamps.
			 */
			ia_valid |= ATTR_MTIME | ATTR_CTIME;
		}
	}
	if (ia_valid & ATTR_ATIME)
		vi->i_atime = timespec_trunc(attr->ia_atime,
				vi->i_sb->s_time_gran);
	if (ia_valid & ATTR_MTIME)
		vi->i_mtime = timespec_trunc(attr->ia_mtime,
				vi->i_sb->s_time_gran);
	if (ia_valid & ATTR_CTIME)
		vi->i_ctime = timespec_trunc(attr->ia_ctime,
				vi->i_sb->s_time_gran);
	mark_inode_dirty(vi);
out:
	return err;
}

/**
 * ntfs_write_inode - write out a dirty inode
 * @vi:		inode to write out
 * @sync:	if true, write out synchronously
 *
 * Write out a dirty inode to disk including any extent inodes if present.
 *
 * If @sync is true, commit the inode to disk and wait for io completion.  This
 * is done using write_mft_record().
 *
 * If @sync is false, just schedule the write to happen but do not wait for i/o
 * completion.  In 2.6 kernels, scheduling usually happens just by virtue of
 * marking the page (and in this case mft record) dirty but we do not implement
 * this yet as write_mft_record() largely ignores the @sync parameter and
 * always performs synchronous writes.
 *
 * Return 0 on success and -errno on error.
 */
int __ntfs_write_inode(struct inode *vi, int sync)
{
	sle64 nt;
	ntfs_inode *ni = NTFS_I(vi);
	ntfs_attr_search_ctx *ctx;
	MFT_RECORD *m;
	STANDARD_INFORMATION *si;
	int err = 0;
	bool modified = false;

	ntfs_debug("Entering for %sinode 0x%lx.", NInoAttr(ni) ? "attr " : "",
			vi->i_ino);
	/*
	 * Dirty attribute inodes are written via their real inodes so just
	 * clean them here.  Access time updates are taken care off when the
	 * real inode is written.
	 */
	if (NInoAttr(ni)) {
		NInoClearDirty(ni);
		ntfs_debug("Done.");
		return 0;
	}
	/* Map, pin, and lock the mft record belonging to the inode. */
	m = map_mft_record(ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		goto err_out;
	}
	/* Update the access times in the standard information attribute. */
	ctx = ntfs_attr_get_search_ctx(ni, m);
	if (unlikely(!ctx)) {
		err = -ENOMEM;
		goto unm_err_out;
	}
	err = ntfs_attr_lookup(AT_STANDARD_INFORMATION, NULL, 0,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		ntfs_attr_put_search_ctx(ctx);
		goto unm_err_out;
	}
	si = (STANDARD_INFORMATION*)((u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset));
	/* Update the access times if they have changed. */
	nt = utc2ntfs(vi->i_mtime);
	if (si->last_data_change_time != nt) {
		ntfs_debug("Updating mtime for inode 0x%lx: old = 0x%llx, "
				"new = 0x%llx", vi->i_ino, (long long)
				sle64_to_cpu(si->last_data_change_time),
				(long long)sle64_to_cpu(nt));
		si->last_data_change_time = nt;
		modified = true;
	}
	nt = utc2ntfs(vi->i_ctime);
	if (si->last_mft_change_time != nt) {
		ntfs_debug("Updating ctime for inode 0x%lx: old = 0x%llx, "
				"new = 0x%llx", vi->i_ino, (long long)
				sle64_to_cpu(si->last_mft_change_time),
				(long long)sle64_to_cpu(nt));
		si->last_mft_change_time = nt;
		modified = true;
	}
	nt = utc2ntfs(vi->i_atime);
	if (si->last_access_time != nt) {
		ntfs_debug("Updating atime for inode 0x%lx: old = 0x%llx, "
				"new = 0x%llx", vi->i_ino,
				(long long)sle64_to_cpu(si->last_access_time),
				(long long)sle64_to_cpu(nt));
		si->last_access_time = nt;
		modified = true;
	}
	/*
	 * If we just modified the standard information attribute we need to
	 * mark the mft record it is in dirty.  We do this manually so that
	 * mark_inode_dirty() is not called which would redirty the inode and
	 * hence result in an infinite loop of trying to write the inode.
	 * There is no need to mark the base inode nor the base mft record
	 * dirty, since we are going to write this mft record below in any case
	 * and the base mft record may actually not have been modified so it
	 * might not need to be written out.
	 * NOTE: It is not a problem when the inode for $MFT itself is being
	 * written out as mark_ntfs_record_dirty() will only set I_DIRTY_PAGES
	 * on the $MFT inode and hence ntfs_write_inode() will not be
	 * re-invoked because of it which in turn is ok since the dirtied mft
	 * record will be cleaned and written out to disk below, i.e. before
	 * this function returns.
	 */
	if (modified) {
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		if (!NInoTestSetDirty(ctx->ntfs_ino))
			mark_ntfs_record_dirty(ctx->ntfs_ino->page,
					ctx->ntfs_ino->page_ofs);
	}
	ntfs_attr_put_search_ctx(ctx);
	/* Now the access times are updated, write the base mft record. */
	if (NInoDirty(ni))
		err = write_mft_record(ni, m, sync);
	/* Write all attached extent mft records. */
	mutex_lock(&ni->extent_lock);
	if (ni->nr_extents > 0) {
		ntfs_inode **extent_nis = ni->ext.extent_ntfs_inos;
		int i;

		ntfs_debug("Writing %i extent inodes.", ni->nr_extents);
		for (i = 0; i < ni->nr_extents; i++) {
			ntfs_inode *tni = extent_nis[i];

			if (NInoDirty(tni)) {
				MFT_RECORD *tm = map_mft_record(tni);
				int ret;

				if (IS_ERR(tm)) {
					if (!err || err == -ENOMEM)
						err = PTR_ERR(tm);
					continue;
				}
				ret = write_mft_record(tni, tm, sync);
				unmap_mft_record(tni);
				if (unlikely(ret)) {
					if (!err || err == -ENOMEM)
						err = ret;
				}
			}
		}
	}
	mutex_unlock(&ni->extent_lock);
	unmap_mft_record(ni);
	if (unlikely(err))
		goto err_out;
	ntfs_debug("Done.");
	return 0;
unm_err_out:
	unmap_mft_record(ni);
err_out:
	if (err == -ENOMEM) {
		ntfs_warning(vi->i_sb, "Not enough memory to write inode.  "
				"Marking the inode dirty again, so the VFS "
				"retries later.");
		mark_inode_dirty(vi);
	} else {
		ntfs_error(vi->i_sb, "Failed (error %i):  Run chkdsk.", -err);
		NVolSetErrors(ni->vol);
	}
	return err;
}

#endif /* NTFS_RW */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/inode.c */
/************************************************************/
/**
 * mft.c - NTFS kernel mft record operations. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2012 Anton Altaparmakov and Tuxera Inc.
 * Copyright (c) 2002 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include <linux/buffer_head.h>
// #include <linux/slab.h>
// #include <linux/swap.h>

// #include "attrib.h"
// #include "aops.h"
// #include "bitmap.h"
// #include "debug.h"
// #include "dir.h"
// #include "lcnalloc.h"
// #include "malloc.h"
// #include "mft.h"
// #include "ntfs.h"

/**
 * map_mft_record_page - map the page in which a specific mft record resides
 * @ni:		ntfs inode whose mft record page to map
 *
 * This maps the page in which the mft record of the ntfs inode @ni is situated
 * and returns a pointer to the mft record within the mapped page.
 *
 * Return value needs to be checked with IS_ERR() and if that is true PTR_ERR()
 * contains the negative error code returned.
 */
static inline MFT_RECORD *map_mft_record_page(ntfs_inode *ni)
{
	loff_t i_size;
	ntfs_volume *vol = ni->vol;
	struct inode *mft_vi = vol->mft_ino;
	struct page *page;
	unsigned long index, end_index;
	unsigned ofs;

	BUG_ON(ni->page);
	/*
	 * The index into the page cache and the offset within the page cache
	 * page of the wanted mft record. FIXME: We need to check for
	 * overflowing the unsigned long, but I don't think we would ever get
	 * here if the volume was that big...
	 */
	index = (u64)ni->mft_no << vol->mft_record_size_bits >>
			PAGE_CACHE_SHIFT;
	ofs = (ni->mft_no << vol->mft_record_size_bits) & ~PAGE_CACHE_MASK;

	i_size = i_size_read(mft_vi);
	/* The maximum valid index into the page cache for $MFT's data. */
	end_index = i_size >> PAGE_CACHE_SHIFT;

	/* If the wanted index is out of bounds the mft record doesn't exist. */
	if (unlikely(index >= end_index)) {
		if (index > end_index || (i_size & ~PAGE_CACHE_MASK) < ofs +
				vol->mft_record_size) {
			page = ERR_PTR(-ENOENT);
			ntfs_error(vol->sb, "Attempt to read mft record 0x%lx, "
					"which is beyond the end of the mft.  "
					"This is probably a bug in the ntfs "
					"driver.", ni->mft_no);
			goto err_out;
		}
	}
	/* Read, map, and pin the page. */
	page = ntfs_map_page(mft_vi->i_mapping, index);
	if (likely(!IS_ERR(page))) {
		/* Catch multi sector transfer fixup errors. */
		if (likely(ntfs_is_mft_recordp((le32*)(page_address(page) +
				ofs)))) {
			ni->page = page;
			ni->page_ofs = ofs;
			return page_address(page) + ofs;
		}
		ntfs_error(vol->sb, "Mft record 0x%lx is corrupt.  "
				"Run chkdsk.", ni->mft_no);
		ntfs_unmap_page(page);
		page = ERR_PTR(-EIO);
		NVolSetErrors(vol);
	}
err_out:
	ni->page = NULL;
	ni->page_ofs = 0;
	return (void*)page;
}

/**
 * map_mft_record - map, pin and lock an mft record
 * @ni:		ntfs inode whose MFT record to map
 *
 * First, take the mrec_lock mutex.  We might now be sleeping, while waiting
 * for the mutex if it was already locked by someone else.
 *
 * The page of the record is mapped using map_mft_record_page() before being
 * returned to the caller.
 *
 * This in turn uses ntfs_map_page() to get the page containing the wanted mft
 * record (it in turn calls read_cache_page() which reads it in from disk if
 * necessary, increments the use count on the page so that it cannot disappear
 * under us and returns a reference to the page cache page).
 *
 * If read_cache_page() invokes ntfs_readpage() to load the page from disk, it
 * sets PG_locked and clears PG_uptodate on the page. Once I/O has completed
 * and the post-read mst fixups on each mft record in the page have been
 * performed, the page gets PG_uptodate set and PG_locked cleared (this is done
 * in our asynchronous I/O completion handler end_buffer_read_mft_async()).
 * ntfs_map_page() waits for PG_locked to become clear and checks if
 * PG_uptodate is set and returns an error code if not. This provides
 * sufficient protection against races when reading/using the page.
 *
 * However there is the write mapping to think about. Doing the above described
 * checking here will be fine, because when initiating the write we will set
 * PG_locked and clear PG_uptodate making sure nobody is touching the page
 * contents. Doing the locking this way means that the commit to disk code in
 * the page cache code paths is automatically sufficiently locked with us as
 * we will not touch a page that has been locked or is not uptodate. The only
 * locking problem then is them locking the page while we are accessing it.
 *
 * So that code will end up having to own the mrec_lock of all mft
 * records/inodes present in the page before I/O can proceed. In that case we
 * wouldn't need to bother with PG_locked and PG_uptodate as nobody will be
 * accessing anything without owning the mrec_lock mutex.  But we do need to
 * use them because of the read_cache_page() invocation and the code becomes so
 * much simpler this way that it is well worth it.
 *
 * The mft record is now ours and we return a pointer to it. You need to check
 * the returned pointer with IS_ERR() and if that is true, PTR_ERR() will return
 * the error code.
 *
 * NOTE: Caller is responsible for setting the mft record dirty before calling
 * unmap_mft_record(). This is obviously only necessary if the caller really
 * modified the mft record...
 * Q: Do we want to recycle one of the VFS inode state bits instead?
 * A: No, the inode ones mean we want to change the mft record, not we want to
 * write it out.
 */
MFT_RECORD *map_mft_record(ntfs_inode *ni)
{
	MFT_RECORD *m;

	ntfs_debug("Entering for mft_no 0x%lx.", ni->mft_no);

	/* Make sure the ntfs inode doesn't go away. */
	atomic_inc(&ni->count);

	/* Serialize access to this mft record. */
	mutex_lock(&ni->mrec_lock);

	m = map_mft_record_page(ni);
	if (likely(!IS_ERR(m)))
		return m;

	mutex_unlock(&ni->mrec_lock);
	atomic_dec(&ni->count);
	ntfs_error(ni->vol->sb, "Failed with error code %lu.", -PTR_ERR(m));
	return m;
}

/**
 * unmap_mft_record_page - unmap the page in which a specific mft record resides
 * @ni:		ntfs inode whose mft record page to unmap
 *
 * This unmaps the page in which the mft record of the ntfs inode @ni is
 * situated and returns. This is a NOOP if highmem is not configured.
 *
 * The unmap happens via ntfs_unmap_page() which in turn decrements the use
 * count on the page thus releasing it from the pinned state.
 *
 * We do not actually unmap the page from memory of course, as that will be
 * done by the page cache code itself when memory pressure increases or
 * whatever.
 */
static inline void unmap_mft_record_page(ntfs_inode *ni)
{
	BUG_ON(!ni->page);

	// TODO: If dirty, blah...
	ntfs_unmap_page(ni->page);
	ni->page = NULL;
	ni->page_ofs = 0;
	return;
}

/**
 * unmap_mft_record - release a mapped mft record
 * @ni:		ntfs inode whose MFT record to unmap
 *
 * We release the page mapping and the mrec_lock mutex which unmaps the mft
 * record and releases it for others to get hold of. We also release the ntfs
 * inode by decrementing the ntfs inode reference count.
 *
 * NOTE: If caller has modified the mft record, it is imperative to set the mft
 * record dirty BEFORE calling unmap_mft_record().
 */
void unmap_mft_record(ntfs_inode *ni)
{
	struct page *page = ni->page;

	BUG_ON(!page);

	ntfs_debug("Entering for mft_no 0x%lx.", ni->mft_no);

	unmap_mft_record_page(ni);
	mutex_unlock(&ni->mrec_lock);
	atomic_dec(&ni->count);
	/*
	 * If pure ntfs_inode, i.e. no vfs inode attached, we leave it to
	 * ntfs_clear_extent_inode() in the extent inode case, and to the
	 * caller in the non-extent, yet pure ntfs inode case, to do the actual
	 * tear down of all structures and freeing of all allocated memory.
	 */
	return;
}

/**
 * map_extent_mft_record - load an extent inode and attach it to its base
 * @base_ni:	base ntfs inode
 * @mref:	mft reference of the extent inode to load
 * @ntfs_ino:	on successful return, pointer to the ntfs_inode structure
 *
 * Load the extent mft record @mref and attach it to its base inode @base_ni.
 * Return the mapped extent mft record if IS_ERR(result) is false.  Otherwise
 * PTR_ERR(result) gives the negative error code.
 *
 * On successful return, @ntfs_ino contains a pointer to the ntfs_inode
 * structure of the mapped extent inode.
 */
MFT_RECORD *map_extent_mft_record(ntfs_inode *base_ni, MFT_REF mref,
		ntfs_inode **ntfs_ino)
{
	MFT_RECORD *m;
	ntfs_inode *ni = NULL;
	ntfs_inode **extent_nis = NULL;
	int i;
	unsigned long mft_no = MREF(mref);
	u16 seq_no = MSEQNO(mref);
	bool destroy_ni = false;

	ntfs_debug("Mapping extent mft record 0x%lx (base mft record 0x%lx).",
			mft_no, base_ni->mft_no);
	/* Make sure the base ntfs inode doesn't go away. */
	atomic_inc(&base_ni->count);
	/*
	 * Check if this extent inode has already been added to the base inode,
	 * in which case just return it. If not found, add it to the base
	 * inode before returning it.
	 */
	mutex_lock(&base_ni->extent_lock);
	if (base_ni->nr_extents > 0) {
		extent_nis = base_ni->ext.extent_ntfs_inos;
		for (i = 0; i < base_ni->nr_extents; i++) {
			if (mft_no != extent_nis[i]->mft_no)
				continue;
			ni = extent_nis[i];
			/* Make sure the ntfs inode doesn't go away. */
			atomic_inc(&ni->count);
			break;
		}
	}
	if (likely(ni != NULL)) {
		mutex_unlock(&base_ni->extent_lock);
		atomic_dec(&base_ni->count);
		/* We found the record; just have to map and return it. */
		m = map_mft_record(ni);
		/* map_mft_record() has incremented this on success. */
		atomic_dec(&ni->count);
		if (likely(!IS_ERR(m))) {
			/* Verify the sequence number. */
			if (likely(le16_to_cpu(m->sequence_number) == seq_no)) {
				ntfs_debug("Done 1.");
				*ntfs_ino = ni;
				return m;
			}
			unmap_mft_record(ni);
			ntfs_error(base_ni->vol->sb, "Found stale extent mft "
					"reference! Corrupt filesystem. "
					"Run chkdsk.");
			return ERR_PTR(-EIO);
		}
map_err_out:
		ntfs_error(base_ni->vol->sb, "Failed to map extent "
				"mft record, error code %ld.", -PTR_ERR(m));
		return m;
	}
	/* Record wasn't there. Get a new ntfs inode and initialize it. */
	ni = ntfs_new_extent_inode(base_ni->vol->sb, mft_no);
	if (unlikely(!ni)) {
		mutex_unlock(&base_ni->extent_lock);
		atomic_dec(&base_ni->count);
		return ERR_PTR(-ENOMEM);
	}
	ni->vol = base_ni->vol;
	ni->seq_no = seq_no;
	ni->nr_extents = -1;
	ni->ext.base_ntfs_ino = base_ni;
	/* Now map the record. */
	m = map_mft_record(ni);
	if (IS_ERR(m)) {
		mutex_unlock(&base_ni->extent_lock);
		atomic_dec(&base_ni->count);
		ntfs_clear_extent_inode(ni);
		goto map_err_out;
	}
	/* Verify the sequence number if it is present. */
	if (seq_no && (le16_to_cpu(m->sequence_number) != seq_no)) {
		ntfs_error(base_ni->vol->sb, "Found stale extent mft "
				"reference! Corrupt filesystem. Run chkdsk.");
		destroy_ni = true;
		m = ERR_PTR(-EIO);
		goto unm_err_out;
	}
	/* Attach extent inode to base inode, reallocating memory if needed. */
	if (!(base_ni->nr_extents & 3)) {
		ntfs_inode **tmp;
		int new_size = (base_ni->nr_extents + 4) * sizeof(ntfs_inode *);

		tmp = kmalloc(new_size, GFP_NOFS);
		if (unlikely(!tmp)) {
			ntfs_error(base_ni->vol->sb, "Failed to allocate "
					"internal buffer.");
			destroy_ni = true;
			m = ERR_PTR(-ENOMEM);
			goto unm_err_out;
		}
		if (base_ni->nr_extents) {
			BUG_ON(!base_ni->ext.extent_ntfs_inos);
			memcpy(tmp, base_ni->ext.extent_ntfs_inos, new_size -
					4 * sizeof(ntfs_inode *));
			kfree(base_ni->ext.extent_ntfs_inos);
		}
		base_ni->ext.extent_ntfs_inos = tmp;
	}
	base_ni->ext.extent_ntfs_inos[base_ni->nr_extents++] = ni;
	mutex_unlock(&base_ni->extent_lock);
	atomic_dec(&base_ni->count);
	ntfs_debug("Done 2.");
	*ntfs_ino = ni;
	return m;
unm_err_out:
	unmap_mft_record(ni);
	mutex_unlock(&base_ni->extent_lock);
	atomic_dec(&base_ni->count);
	/*
	 * If the extent inode was not attached to the base inode we need to
	 * release it or we will leak memory.
	 */
	if (destroy_ni)
		ntfs_clear_extent_inode(ni);
	return m;
}

#ifdef NTFS_RW

/**
 * __mark_mft_record_dirty - set the mft record and the page containing it dirty
 * @ni:		ntfs inode describing the mapped mft record
 *
 * Internal function.  Users should call mark_mft_record_dirty() instead.
 *
 * Set the mapped (extent) mft record of the (base or extent) ntfs inode @ni,
 * as well as the page containing the mft record, dirty.  Also, mark the base
 * vfs inode dirty.  This ensures that any changes to the mft record are
 * written out to disk.
 *
 * NOTE:  We only set I_DIRTY_SYNC and I_DIRTY_DATASYNC (and not I_DIRTY_PAGES)
 * on the base vfs inode, because even though file data may have been modified,
 * it is dirty in the inode meta data rather than the data page cache of the
 * inode, and thus there are no data pages that need writing out.  Therefore, a
 * full mark_inode_dirty() is overkill.  A mark_inode_dirty_sync(), on the
 * other hand, is not sufficient, because ->write_inode needs to be called even
 * in case of fdatasync. This needs to happen or the file data would not
 * necessarily hit the device synchronously, even though the vfs inode has the
 * O_SYNC flag set.  Also, I_DIRTY_DATASYNC simply "feels" better than just
 * I_DIRTY_SYNC, since the file data has not actually hit the block device yet,
 * which is not what I_DIRTY_SYNC on its own would suggest.
 */
void __mark_mft_record_dirty(ntfs_inode *ni)
{
	ntfs_inode *base_ni;

	ntfs_debug("Entering for inode 0x%lx.", ni->mft_no);
	BUG_ON(NInoAttr(ni));
	mark_ntfs_record_dirty(ni->page, ni->page_ofs);
	/* Determine the base vfs inode and mark it dirty, too. */
	mutex_lock(&ni->extent_lock);
	if (likely(ni->nr_extents >= 0))
		base_ni = ni;
	else
		base_ni = ni->ext.base_ntfs_ino;
	mutex_unlock(&ni->extent_lock);
	__mark_inode_dirty(VFS_I(base_ni), I_DIRTY_SYNC | I_DIRTY_DATASYNC);
}

static const char *ntfs_please_email = "Please email "
		"linux-ntfs-dev@lists.sourceforge.net and say that you saw "
		"this message.  Thank you.";

/**
 * ntfs_sync_mft_mirror_umount - synchronise an mft record to the mft mirror
 * @vol:	ntfs volume on which the mft record to synchronize resides
 * @mft_no:	mft record number of mft record to synchronize
 * @m:		mapped, mst protected (extent) mft record to synchronize
 *
 * Write the mapped, mst protected (extent) mft record @m with mft record
 * number @mft_no to the mft mirror ($MFTMirr) of the ntfs volume @vol,
 * bypassing the page cache and the $MFTMirr inode itself.
 *
 * This function is only for use at umount time when the mft mirror inode has
 * already been disposed off.  We BUG() if we are called while the mft mirror
 * inode is still attached to the volume.
 *
 * On success return 0.  On error return -errno.
 *
 * NOTE:  This function is not implemented yet as I am not convinced it can
 * actually be triggered considering the sequence of commits we do in super.c::
 * ntfs_put_super().  But just in case we provide this place holder as the
 * alternative would be either to BUG() or to get a NULL pointer dereference
 * and Oops.
 */
static int ntfs_sync_mft_mirror_umount(ntfs_volume *vol,
		const unsigned long mft_no, MFT_RECORD *m)
{
	BUG_ON(vol->mftmirr_ino);
	ntfs_error(vol->sb, "Umount time mft mirror syncing is not "
			"implemented yet.  %s", ntfs_please_email);
	return -EOPNOTSUPP;
}

/**
 * ntfs_sync_mft_mirror - synchronize an mft record to the mft mirror
 * @vol:	ntfs volume on which the mft record to synchronize resides
 * @mft_no:	mft record number of mft record to synchronize
 * @m:		mapped, mst protected (extent) mft record to synchronize
 * @sync:	if true, wait for i/o completion
 *
 * Write the mapped, mst protected (extent) mft record @m with mft record
 * number @mft_no to the mft mirror ($MFTMirr) of the ntfs volume @vol.
 *
 * On success return 0.  On error return -errno and set the volume errors flag
 * in the ntfs volume @vol.
 *
 * NOTE:  We always perform synchronous i/o and ignore the @sync parameter.
 *
 * TODO:  If @sync is false, want to do truly asynchronous i/o, i.e. just
 * schedule i/o via ->writepage or do it via kntfsd or whatever.
 */
int ntfs_sync_mft_mirror(ntfs_volume *vol, const unsigned long mft_no,
		MFT_RECORD *m, int sync)
{
	struct page *page;
	unsigned int blocksize = vol->sb->s_blocksize;
	int max_bhs = vol->mft_record_size / blocksize;
	struct buffer_head *bhs[max_bhs];
	struct buffer_head *bh, *head;
	u8 *kmirr;
	runlist_element *rl;
	unsigned int block_start, block_end, m_start, m_end, page_ofs;
	int i_bhs, nr_bhs, err = 0;
	unsigned char blocksize_bits = vol->sb->s_blocksize_bits;

	ntfs_debug("Entering for inode 0x%lx.", mft_no);
	BUG_ON(!max_bhs);
	if (unlikely(!vol->mftmirr_ino)) {
		/* This could happen during umount... */
		err = ntfs_sync_mft_mirror_umount(vol, mft_no, m);
		if (likely(!err))
			return err;
		goto err_out;
	}
	/* Get the page containing the mirror copy of the mft record @m. */
	page = ntfs_map_page(vol->mftmirr_ino->i_mapping, mft_no >>
			(PAGE_CACHE_SHIFT - vol->mft_record_size_bits));
	if (IS_ERR(page)) {
		ntfs_error(vol->sb, "Failed to map mft mirror page.");
		err = PTR_ERR(page);
		goto err_out;
	}
	lock_page(page);
	BUG_ON(!PageUptodate(page));
	ClearPageUptodate(page);
	/* Offset of the mft mirror record inside the page. */
	page_ofs = (mft_no << vol->mft_record_size_bits) & ~PAGE_CACHE_MASK;
	/* The address in the page of the mirror copy of the mft record @m. */
	kmirr = page_address(page) + page_ofs;
	/* Copy the mst protected mft record to the mirror. */
	memcpy(kmirr, m, vol->mft_record_size);
	/* Create uptodate buffers if not present. */
	if (unlikely(!page_has_buffers(page))) {
		struct buffer_head *tail;

		bh = head = alloc_page_buffers(page, blocksize, 1);
		do {
			set_buffer_uptodate(bh);
			tail = bh;
			bh = bh->b_this_page;
		} while (bh);
		tail->b_this_page = head;
		attach_page_buffers(page, head);
	}
	bh = head = page_buffers(page);
	BUG_ON(!bh);
	rl = NULL;
	nr_bhs = 0;
	block_start = 0;
	m_start = kmirr - (u8*)page_address(page);
	m_end = m_start + vol->mft_record_size;
	do {
		block_end = block_start + blocksize;
		/* If the buffer is outside the mft record, skip it. */
		if (block_end <= m_start)
			continue;
		if (unlikely(block_start >= m_end))
			break;
		/* Need to map the buffer if it is not mapped already. */
		if (unlikely(!buffer_mapped(bh))) {
			VCN vcn;
			LCN lcn;
			unsigned int vcn_ofs;

			bh->b_bdev = vol->sb->s_bdev;
			/* Obtain the vcn and offset of the current block. */
			vcn = ((VCN)mft_no << vol->mft_record_size_bits) +
					(block_start - m_start);
			vcn_ofs = vcn & vol->cluster_size_mask;
			vcn >>= vol->cluster_size_bits;
			if (!rl) {
				down_read(&NTFS_I(vol->mftmirr_ino)->
						runlist.lock);
				rl = NTFS_I(vol->mftmirr_ino)->runlist.rl;
				/*
				 * $MFTMirr always has the whole of its runlist
				 * in memory.
				 */
				BUG_ON(!rl);
			}
			/* Seek to element containing target vcn. */
			while (rl->length && rl[1].vcn <= vcn)
				rl++;
			lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
			/* For $MFTMirr, only lcn >= 0 is a successful remap. */
			if (likely(lcn >= 0)) {
				/* Setup buffer head to correct block. */
				bh->b_blocknr = ((lcn <<
						vol->cluster_size_bits) +
						vcn_ofs) >> blocksize_bits;
				set_buffer_mapped(bh);
			} else {
				bh->b_blocknr = -1;
				ntfs_error(vol->sb, "Cannot write mft mirror "
						"record 0x%lx because its "
						"location on disk could not "
						"be determined (error code "
						"%lli).", mft_no,
						(long long)lcn);
				err = -EIO;
			}
		}
		BUG_ON(!buffer_uptodate(bh));
		BUG_ON(!nr_bhs && (m_start != block_start));
		BUG_ON(nr_bhs >= max_bhs);
		bhs[nr_bhs++] = bh;
		BUG_ON((nr_bhs >= max_bhs) && (m_end != block_end));
	} while (block_start = block_end, (bh = bh->b_this_page) != head);
	if (unlikely(rl))
		up_read(&NTFS_I(vol->mftmirr_ino)->runlist.lock);
	if (likely(!err)) {
		/* Lock buffers and start synchronous write i/o on them. */
		for (i_bhs = 0; i_bhs < nr_bhs; i_bhs++) {
			struct buffer_head *tbh = bhs[i_bhs];

			if (!trylock_buffer(tbh))
				BUG();
			BUG_ON(!buffer_uptodate(tbh));
			clear_buffer_dirty(tbh);
			get_bh(tbh);
			tbh->b_end_io = end_buffer_write_sync;
			submit_bh(WRITE, tbh);
		}
		/* Wait on i/o completion of buffers. */
		for (i_bhs = 0; i_bhs < nr_bhs; i_bhs++) {
			struct buffer_head *tbh = bhs[i_bhs];

			wait_on_buffer(tbh);
			if (unlikely(!buffer_uptodate(tbh))) {
				err = -EIO;
				/*
				 * Set the buffer uptodate so the page and
				 * buffer states do not become out of sync.
				 */
				set_buffer_uptodate(tbh);
			}
		}
	} else /* if (unlikely(err)) */ {
		/* Clean the buffers. */
		for (i_bhs = 0; i_bhs < nr_bhs; i_bhs++)
			clear_buffer_dirty(bhs[i_bhs]);
	}
	/* Current state: all buffers are clean, unlocked, and uptodate. */
	/* Remove the mst protection fixups again. */
	post_write_mst_fixup((NTFS_RECORD*)kmirr);
	flush_dcache_page(page);
	SetPageUptodate(page);
	unlock_page(page);
	ntfs_unmap_page(page);
	if (likely(!err)) {
		ntfs_debug("Done.");
	} else {
		ntfs_error(vol->sb, "I/O error while writing mft mirror "
				"record 0x%lx!", mft_no);
err_out:
		ntfs_error(vol->sb, "Failed to synchronize $MFTMirr (error "
				"code %i).  Volume will be left marked dirty "
				"on umount.  Run ntfsfix on the partition "
				"after umounting to correct this.", -err);
		NVolSetErrors(vol);
	}
	return err;
}

/**
 * write_mft_record_nolock - write out a mapped (extent) mft record
 * @ni:		ntfs inode describing the mapped (extent) mft record
 * @m:		mapped (extent) mft record to write
 * @sync:	if true, wait for i/o completion
 *
 * Write the mapped (extent) mft record @m described by the (regular or extent)
 * ntfs inode @ni to backing store.  If the mft record @m has a counterpart in
 * the mft mirror, that is also updated.
 *
 * We only write the mft record if the ntfs inode @ni is dirty and the first
 * buffer belonging to its mft record is dirty, too.  We ignore the dirty state
 * of subsequent buffers because we could have raced with
 * fs/ntfs/aops.c::mark_ntfs_record_dirty().
 *
 * On success, clean the mft record and return 0.  On error, leave the mft
 * record dirty and return -errno.
 *
 * NOTE:  We always perform synchronous i/o and ignore the @sync parameter.
 * However, if the mft record has a counterpart in the mft mirror and @sync is
 * true, we write the mft record, wait for i/o completion, and only then write
 * the mft mirror copy.  This ensures that if the system crashes either the mft
 * or the mft mirror will contain a self-consistent mft record @m.  If @sync is
 * false on the other hand, we start i/o on both and then wait for completion
 * on them.  This provides a speedup but no longer guarantees that you will end
 * up with a self-consistent mft record in the case of a crash but if you asked
 * for asynchronous writing you probably do not care about that anyway.
 *
 * TODO:  If @sync is false, want to do truly asynchronous i/o, i.e. just
 * schedule i/o via ->writepage or do it via kntfsd or whatever.
 */
int write_mft_record_nolock(ntfs_inode *ni, MFT_RECORD *m, int sync)
{
	ntfs_volume *vol = ni->vol;
	struct page *page = ni->page;
	unsigned int blocksize = vol->sb->s_blocksize;
	unsigned char blocksize_bits = vol->sb->s_blocksize_bits;
	int max_bhs = vol->mft_record_size / blocksize;
	struct buffer_head *bhs[max_bhs];
	struct buffer_head *bh, *head;
	runlist_element *rl;
	unsigned int block_start, block_end, m_start, m_end;
	int i_bhs, nr_bhs, err = 0;

	ntfs_debug("Entering for inode 0x%lx.", ni->mft_no);
	BUG_ON(NInoAttr(ni));
	BUG_ON(!max_bhs);
	BUG_ON(!PageLocked(page));
	/*
	 * If the ntfs_inode is clean no need to do anything.  If it is dirty,
	 * mark it as clean now so that it can be redirtied later on if needed.
	 * There is no danger of races since the caller is holding the locks
	 * for the mft record @m and the page it is in.
	 */
	if (!NInoTestClearDirty(ni))
		goto done;
	bh = head = page_buffers(page);
	BUG_ON(!bh);
	rl = NULL;
	nr_bhs = 0;
	block_start = 0;
	m_start = ni->page_ofs;
	m_end = m_start + vol->mft_record_size;
	do {
		block_end = block_start + blocksize;
		/* If the buffer is outside the mft record, skip it. */
		if (block_end <= m_start)
			continue;
		if (unlikely(block_start >= m_end))
			break;
		/*
		 * If this block is not the first one in the record, we ignore
		 * the buffer's dirty state because we could have raced with a
		 * parallel mark_ntfs_record_dirty().
		 */
		if (block_start == m_start) {
			/* This block is the first one in the record. */
			if (!buffer_dirty(bh)) {
				BUG_ON(nr_bhs);
				/* Clean records are not written out. */
				break;
			}
		}
		/* Need to map the buffer if it is not mapped already. */
		if (unlikely(!buffer_mapped(bh))) {
			VCN vcn;
			LCN lcn;
			unsigned int vcn_ofs;

			bh->b_bdev = vol->sb->s_bdev;
			/* Obtain the vcn and offset of the current block. */
			vcn = ((VCN)ni->mft_no << vol->mft_record_size_bits) +
					(block_start - m_start);
			vcn_ofs = vcn & vol->cluster_size_mask;
			vcn >>= vol->cluster_size_bits;
			if (!rl) {
				down_read(&NTFS_I(vol->mft_ino)->runlist.lock);
				rl = NTFS_I(vol->mft_ino)->runlist.rl;
				BUG_ON(!rl);
			}
			/* Seek to element containing target vcn. */
			while (rl->length && rl[1].vcn <= vcn)
				rl++;
			lcn = ntfs_rl_vcn_to_lcn(rl, vcn);
			/* For $MFT, only lcn >= 0 is a successful remap. */
			if (likely(lcn >= 0)) {
				/* Setup buffer head to correct block. */
				bh->b_blocknr = ((lcn <<
						vol->cluster_size_bits) +
						vcn_ofs) >> blocksize_bits;
				set_buffer_mapped(bh);
			} else {
				bh->b_blocknr = -1;
				ntfs_error(vol->sb, "Cannot write mft record "
						"0x%lx because its location "
						"on disk could not be "
						"determined (error code %lli).",
						ni->mft_no, (long long)lcn);
				err = -EIO;
			}
		}
		BUG_ON(!buffer_uptodate(bh));
		BUG_ON(!nr_bhs && (m_start != block_start));
		BUG_ON(nr_bhs >= max_bhs);
		bhs[nr_bhs++] = bh;
		BUG_ON((nr_bhs >= max_bhs) && (m_end != block_end));
	} while (block_start = block_end, (bh = bh->b_this_page) != head);
	if (unlikely(rl))
		up_read(&NTFS_I(vol->mft_ino)->runlist.lock);
	if (!nr_bhs)
		goto done;
	if (unlikely(err))
		goto cleanup_out;
	/* Apply the mst protection fixups. */
	err = pre_write_mst_fixup((NTFS_RECORD*)m, vol->mft_record_size);
	if (err) {
		ntfs_error(vol->sb, "Failed to apply mst fixups!");
		goto cleanup_out;
	}
	flush_dcache_mft_record_page(ni);
	/* Lock buffers and start synchronous write i/o on them. */
	for (i_bhs = 0; i_bhs < nr_bhs; i_bhs++) {
		struct buffer_head *tbh = bhs[i_bhs];

		if (!trylock_buffer(tbh))
			BUG();
		BUG_ON(!buffer_uptodate(tbh));
		clear_buffer_dirty(tbh);
		get_bh(tbh);
		tbh->b_end_io = end_buffer_write_sync;
		submit_bh(WRITE, tbh);
	}
	/* Synchronize the mft mirror now if not @sync. */
	if (!sync && ni->mft_no < vol->mftmirr_size)
		ntfs_sync_mft_mirror(vol, ni->mft_no, m, sync);
	/* Wait on i/o completion of buffers. */
	for (i_bhs = 0; i_bhs < nr_bhs; i_bhs++) {
		struct buffer_head *tbh = bhs[i_bhs];

		wait_on_buffer(tbh);
		if (unlikely(!buffer_uptodate(tbh))) {
			err = -EIO;
			/*
			 * Set the buffer uptodate so the page and buffer
			 * states do not become out of sync.
			 */
			if (PageUptodate(page))
				set_buffer_uptodate(tbh);
		}
	}
	/* If @sync, now synchronize the mft mirror. */
	if (sync && ni->mft_no < vol->mftmirr_size)
		ntfs_sync_mft_mirror(vol, ni->mft_no, m, sync);
	/* Remove the mst protection fixups again. */
	post_write_mst_fixup((NTFS_RECORD*)m);
	flush_dcache_mft_record_page(ni);
	if (unlikely(err)) {
		/* I/O error during writing.  This is really bad! */
		ntfs_error(vol->sb, "I/O error while writing mft record "
				"0x%lx!  Marking base inode as bad.  You "
				"should unmount the volume and run chkdsk.",
				ni->mft_no);
		goto err_out;
	}
done:
	ntfs_debug("Done.");
	return 0;
cleanup_out:
	/* Clean the buffers. */
	for (i_bhs = 0; i_bhs < nr_bhs; i_bhs++)
		clear_buffer_dirty(bhs[i_bhs]);
err_out:
	/*
	 * Current state: all buffers are clean, unlocked, and uptodate.
	 * The caller should mark the base inode as bad so that no more i/o
	 * happens.  ->clear_inode() will still be invoked so all extent inodes
	 * and other allocated memory will be freed.
	 */
	if (err == -ENOMEM) {
		ntfs_error(vol->sb, "Not enough memory to write mft record.  "
				"Redirtying so the write is retried later.");
		mark_mft_record_dirty(ni);
		err = 0;
	} else
		NVolSetErrors(vol);
	return err;
}

/**
 * ntfs_may_write_mft_record - check if an mft record may be written out
 * @vol:	[IN]  ntfs volume on which the mft record to check resides
 * @mft_no:	[IN]  mft record number of the mft record to check
 * @m:		[IN]  mapped mft record to check
 * @locked_ni:	[OUT] caller has to unlock this ntfs inode if one is returned
 *
 * Check if the mapped (base or extent) mft record @m with mft record number
 * @mft_no belonging to the ntfs volume @vol may be written out.  If necessary
 * and possible the ntfs inode of the mft record is locked and the base vfs
 * inode is pinned.  The locked ntfs inode is then returned in @locked_ni.  The
 * caller is responsible for unlocking the ntfs inode and unpinning the base
 * vfs inode.
 *
 * Return 'true' if the mft record may be written out and 'false' if not.
 *
 * The caller has locked the page and cleared the uptodate flag on it which
 * means that we can safely write out any dirty mft records that do not have
 * their inodes in icache as determined by ilookup5() as anyone
 * opening/creating such an inode would block when attempting to map the mft
 * record in read_cache_page() until we are finished with the write out.
 *
 * Here is a description of the tests we perform:
 *
 * If the inode is found in icache we know the mft record must be a base mft
 * record.  If it is dirty, we do not write it and return 'false' as the vfs
 * inode write paths will result in the access times being updated which would
 * cause the base mft record to be redirtied and written out again.  (We know
 * the access time update will modify the base mft record because Windows
 * chkdsk complains if the standard information attribute is not in the base
 * mft record.)
 *
 * If the inode is in icache and not dirty, we attempt to lock the mft record
 * and if we find the lock was already taken, it is not safe to write the mft
 * record and we return 'false'.
 *
 * If we manage to obtain the lock we have exclusive access to the mft record,
 * which also allows us safe writeout of the mft record.  We then set
 * @locked_ni to the locked ntfs inode and return 'true'.
 *
 * Note we cannot just lock the mft record and sleep while waiting for the lock
 * because this would deadlock due to lock reversal (normally the mft record is
 * locked before the page is locked but we already have the page locked here
 * when we try to lock the mft record).
 *
 * If the inode is not in icache we need to perform further checks.
 *
 * If the mft record is not a FILE record or it is a base mft record, we can
 * safely write it and return 'true'.
 *
 * We now know the mft record is an extent mft record.  We check if the inode
 * corresponding to its base mft record is in icache and obtain a reference to
 * it if it is.  If it is not, we can safely write it and return 'true'.
 *
 * We now have the base inode for the extent mft record.  We check if it has an
 * ntfs inode for the extent mft record attached and if not it is safe to write
 * the extent mft record and we return 'true'.
 *
 * The ntfs inode for the extent mft record is attached to the base inode so we
 * attempt to lock the extent mft record and if we find the lock was already
 * taken, it is not safe to write the extent mft record and we return 'false'.
 *
 * If we manage to obtain the lock we have exclusive access to the extent mft
 * record, which also allows us safe writeout of the extent mft record.  We
 * set the ntfs inode of the extent mft record clean and then set @locked_ni to
 * the now locked ntfs inode and return 'true'.
 *
 * Note, the reason for actually writing dirty mft records here and not just
 * relying on the vfs inode dirty code paths is that we can have mft records
 * modified without them ever having actual inodes in memory.  Also we can have
 * dirty mft records with clean ntfs inodes in memory.  None of the described
 * cases would result in the dirty mft records being written out if we only
 * relied on the vfs inode dirty code paths.  And these cases can really occur
 * during allocation of new mft records and in particular when the
 * initialized_size of the $MFT/$DATA attribute is extended and the new space
 * is initialized using ntfs_mft_record_format().  The clean inode can then
 * appear if the mft record is reused for a new inode before it got written
 * out.
 */
bool ntfs_may_write_mft_record(ntfs_volume *vol, const unsigned long mft_no,
		const MFT_RECORD *m, ntfs_inode **locked_ni)
{
	struct super_block *sb = vol->sb;
	struct inode *mft_vi = vol->mft_ino;
	struct inode *vi;
	ntfs_inode *ni, *eni, **extent_nis;
	int i;
	ntfs_attr na;

	ntfs_debug("Entering for inode 0x%lx.", mft_no);
	/*
	 * Normally we do not return a locked inode so set @locked_ni to NULL.
	 */
	BUG_ON(!locked_ni);
	*locked_ni = NULL;
	/*
	 * Check if the inode corresponding to this mft record is in the VFS
	 * inode cache and obtain a reference to it if it is.
	 */
	ntfs_debug("Looking for inode 0x%lx in icache.", mft_no);
	na.mft_no = mft_no;
	na.name = NULL;
	na.name_len = 0;
	na.type = AT_UNUSED;
	/*
	 * Optimize inode 0, i.e. $MFT itself, since we have it in memory and
	 * we get here for it rather often.
	 */
	if (!mft_no) {
		/* Balance the below iput(). */
		vi = igrab(mft_vi);
		BUG_ON(vi != mft_vi);
	} else {
		/*
		 * Have to use ilookup5_nowait() since ilookup5() waits for the
		 * inode lock which causes ntfs to deadlock when a concurrent
		 * inode write via the inode dirty code paths and the page
		 * dirty code path of the inode dirty code path when writing
		 * $MFT occurs.
		 */
		vi = ilookup5_nowait(sb, mft_no, (test_t)ntfs_test_inode, &na);
	}
	if (vi) {
		ntfs_debug("Base inode 0x%lx is in icache.", mft_no);
		/* The inode is in icache. */
		ni = NTFS_I(vi);
		/* Take a reference to the ntfs inode. */
		atomic_inc(&ni->count);
		/* If the inode is dirty, do not write this record. */
		if (NInoDirty(ni)) {
			ntfs_debug("Inode 0x%lx is dirty, do not write it.",
					mft_no);
			atomic_dec(&ni->count);
			iput(vi);
			return false;
		}
		ntfs_debug("Inode 0x%lx is not dirty.", mft_no);
		/* The inode is not dirty, try to take the mft record lock. */
		if (unlikely(!mutex_trylock(&ni->mrec_lock))) {
			ntfs_debug("Mft record 0x%lx is already locked, do "
					"not write it.", mft_no);
			atomic_dec(&ni->count);
			iput(vi);
			return false;
		}
		ntfs_debug("Managed to lock mft record 0x%lx, write it.",
				mft_no);
		/*
		 * The write has to occur while we hold the mft record lock so
		 * return the locked ntfs inode.
		 */
		*locked_ni = ni;
		return true;
	}
	ntfs_debug("Inode 0x%lx is not in icache.", mft_no);
	/* The inode is not in icache. */
	/* Write the record if it is not a mft record (type "FILE"). */
	if (!ntfs_is_mft_record(m->magic)) {
		ntfs_debug("Mft record 0x%lx is not a FILE record, write it.",
				mft_no);
		return true;
	}
	/* Write the mft record if it is a base inode. */
	if (!m->base_mft_record) {
		ntfs_debug("Mft record 0x%lx is a base record, write it.",
				mft_no);
		return true;
	}
	/*
	 * This is an extent mft record.  Check if the inode corresponding to
	 * its base mft record is in icache and obtain a reference to it if it
	 * is.
	 */
	na.mft_no = MREF_LE(m->base_mft_record);
	ntfs_debug("Mft record 0x%lx is an extent record.  Looking for base "
			"inode 0x%lx in icache.", mft_no, na.mft_no);
	if (!na.mft_no) {
		/* Balance the below iput(). */
		vi = igrab(mft_vi);
		BUG_ON(vi != mft_vi);
	} else
		vi = ilookup5_nowait(sb, na.mft_no, (test_t)ntfs_test_inode,
				&na);
	if (!vi) {
		/*
		 * The base inode is not in icache, write this extent mft
		 * record.
		 */
		ntfs_debug("Base inode 0x%lx is not in icache, write the "
				"extent record.", na.mft_no);
		return true;
	}
	ntfs_debug("Base inode 0x%lx is in icache.", na.mft_no);
	/*
	 * The base inode is in icache.  Check if it has the extent inode
	 * corresponding to this extent mft record attached.
	 */
	ni = NTFS_I(vi);
	mutex_lock(&ni->extent_lock);
	if (ni->nr_extents <= 0) {
		/*
		 * The base inode has no attached extent inodes, write this
		 * extent mft record.
		 */
		mutex_unlock(&ni->extent_lock);
		iput(vi);
		ntfs_debug("Base inode 0x%lx has no attached extent inodes, "
				"write the extent record.", na.mft_no);
		return true;
	}
	/* Iterate over the attached extent inodes. */
	extent_nis = ni->ext.extent_ntfs_inos;
	for (eni = NULL, i = 0; i < ni->nr_extents; ++i) {
		if (mft_no == extent_nis[i]->mft_no) {
			/*
			 * Found the extent inode corresponding to this extent
			 * mft record.
			 */
			eni = extent_nis[i];
			break;
		}
	}
	/*
	 * If the extent inode was not attached to the base inode, write this
	 * extent mft record.
	 */
	if (!eni) {
		mutex_unlock(&ni->extent_lock);
		iput(vi);
		ntfs_debug("Extent inode 0x%lx is not attached to its base "
				"inode 0x%lx, write the extent record.",
				mft_no, na.mft_no);
		return true;
	}
	ntfs_debug("Extent inode 0x%lx is attached to its base inode 0x%lx.",
			mft_no, na.mft_no);
	/* Take a reference to the extent ntfs inode. */
	atomic_inc(&eni->count);
	mutex_unlock(&ni->extent_lock);
	/*
	 * Found the extent inode coresponding to this extent mft record.
	 * Try to take the mft record lock.
	 */
	if (unlikely(!mutex_trylock(&eni->mrec_lock))) {
		atomic_dec(&eni->count);
		iput(vi);
		ntfs_debug("Extent mft record 0x%lx is already locked, do "
				"not write it.", mft_no);
		return false;
	}
	ntfs_debug("Managed to lock extent mft record 0x%lx, write it.",
			mft_no);
	if (NInoTestClearDirty(eni))
		ntfs_debug("Extent inode 0x%lx is dirty, marking it clean.",
				mft_no);
	/*
	 * The write has to occur while we hold the mft record lock so return
	 * the locked extent ntfs inode.
	 */
	*locked_ni = eni;
	return true;
}

static const char *es = "  Leaving inconsistent metadata.  Unmount and run "
		"chkdsk.";

/**
 * ntfs_mft_bitmap_find_and_alloc_free_rec_nolock - see name
 * @vol:	volume on which to search for a free mft record
 * @base_ni:	open base inode if allocating an extent mft record or NULL
 *
 * Search for a free mft record in the mft bitmap attribute on the ntfs volume
 * @vol.
 *
 * If @base_ni is NULL start the search at the default allocator position.
 *
 * If @base_ni is not NULL start the search at the mft record after the base
 * mft record @base_ni.
 *
 * Return the free mft record on success and -errno on error.  An error code of
 * -ENOSPC means that there are no free mft records in the currently
 * initialized mft bitmap.
 *
 * Locking: Caller must hold vol->mftbmp_lock for writing.
 */
static int ntfs_mft_bitmap_find_and_alloc_free_rec_nolock(ntfs_volume *vol,
		ntfs_inode *base_ni)
{
	s64 pass_end, ll, data_pos, pass_start, ofs, bit;
	unsigned long flags;
	struct address_space *mftbmp_mapping;
	u8 *buf, *byte;
	struct page *page;
	unsigned int page_ofs, size;
	u8 pass, b;

	ntfs_debug("Searching for free mft record in the currently "
			"initialized mft bitmap.");
	mftbmp_mapping = vol->mftbmp_ino->i_mapping;
	/*
	 * Set the end of the pass making sure we do not overflow the mft
	 * bitmap.
	 */
	read_lock_irqsave(&NTFS_I(vol->mft_ino)->size_lock, flags);
	pass_end = NTFS_I(vol->mft_ino)->allocated_size >>
			vol->mft_record_size_bits;
	read_unlock_irqrestore(&NTFS_I(vol->mft_ino)->size_lock, flags);
	read_lock_irqsave(&NTFS_I(vol->mftbmp_ino)->size_lock, flags);
	ll = NTFS_I(vol->mftbmp_ino)->initialized_size << 3;
	read_unlock_irqrestore(&NTFS_I(vol->mftbmp_ino)->size_lock, flags);
	if (pass_end > ll)
		pass_end = ll;
	pass = 1;
	if (!base_ni)
		data_pos = vol->mft_data_pos;
	else
		data_pos = base_ni->mft_no + 1;
	if (data_pos < 24)
		data_pos = 24;
	if (data_pos >= pass_end) {
		data_pos = 24;
		pass = 2;
		/* This happens on a freshly formatted volume. */
		if (data_pos >= pass_end)
			return -ENOSPC;
	}
	pass_start = data_pos;
	ntfs_debug("Starting bitmap search: pass %u, pass_start 0x%llx, "
			"pass_end 0x%llx, data_pos 0x%llx.", pass,
			(long long)pass_start, (long long)pass_end,
			(long long)data_pos);
	/* Loop until a free mft record is found. */
	for (; pass <= 2;) {
		/* Cap size to pass_end. */
		ofs = data_pos >> 3;
		page_ofs = ofs & ~PAGE_CACHE_MASK;
		size = PAGE_CACHE_SIZE - page_ofs;
		ll = ((pass_end + 7) >> 3) - ofs;
		if (size > ll)
			size = ll;
		size <<= 3;
		/*
		 * If we are still within the active pass, search the next page
		 * for a zero bit.
		 */
		if (size) {
			page = ntfs_map_page(mftbmp_mapping,
					ofs >> PAGE_CACHE_SHIFT);
			if (IS_ERR(page)) {
				ntfs_error(vol->sb, "Failed to read mft "
						"bitmap, aborting.");
				return PTR_ERR(page);
			}
			buf = (u8*)page_address(page) + page_ofs;
			bit = data_pos & 7;
			data_pos &= ~7ull;
			ntfs_debug("Before inner for loop: size 0x%x, "
					"data_pos 0x%llx, bit 0x%llx", size,
					(long long)data_pos, (long long)bit);
			for (; bit < size && data_pos + bit < pass_end;
					bit &= ~7ull, bit += 8) {
				byte = buf + (bit >> 3);
				if (*byte == 0xff)
					continue;
				b = ffz((unsigned long)*byte);
				if (b < 8 && b >= (bit & 7)) {
					ll = data_pos + (bit & ~7ull) + b;
					if (unlikely(ll > (1ll << 32))) {
						ntfs_unmap_page(page);
						return -ENOSPC;
					}
					*byte |= 1 << b;
					flush_dcache_page(page);
					set_page_dirty(page);
					ntfs_unmap_page(page);
					ntfs_debug("Done.  (Found and "
							"allocated mft record "
							"0x%llx.)",
							(long long)ll);
					return ll;
				}
			}
			ntfs_debug("After inner for loop: size 0x%x, "
					"data_pos 0x%llx, bit 0x%llx", size,
					(long long)data_pos, (long long)bit);
			data_pos += size;
			ntfs_unmap_page(page);
			/*
			 * If the end of the pass has not been reached yet,
			 * continue searching the mft bitmap for a zero bit.
			 */
			if (data_pos < pass_end)
				continue;
		}
		/* Do the next pass. */
		if (++pass == 2) {
			/*
			 * Starting the second pass, in which we scan the first
			 * part of the zone which we omitted earlier.
			 */
			pass_end = pass_start;
			data_pos = pass_start = 24;
			ntfs_debug("pass %i, pass_start 0x%llx, pass_end "
					"0x%llx.", pass, (long long)pass_start,
					(long long)pass_end);
			if (data_pos >= pass_end)
				break;
		}
	}
	/* No free mft records in currently initialized mft bitmap. */
	ntfs_debug("Done.  (No free mft records left in currently initialized "
			"mft bitmap.)");
	return -ENOSPC;
}

/**
 * ntfs_mft_bitmap_extend_allocation_nolock - extend mft bitmap by a cluster
 * @vol:	volume on which to extend the mft bitmap attribute
 *
 * Extend the mft bitmap attribute on the ntfs volume @vol by one cluster.
 *
 * Note: Only changes allocated_size, i.e. does not touch initialized_size or
 * data_size.
 *
 * Return 0 on success and -errno on error.
 *
 * Locking: - Caller must hold vol->mftbmp_lock for writing.
 *	    - This function takes NTFS_I(vol->mftbmp_ino)->runlist.lock for
 *	      writing and releases it before returning.
 *	    - This function takes vol->lcnbmp_lock for writing and releases it
 *	      before returning.
 */
static int ntfs_mft_bitmap_extend_allocation_nolock(ntfs_volume *vol)
{
	LCN lcn;
	s64 ll;
	unsigned long flags;
	struct page *page;
	ntfs_inode *mft_ni, *mftbmp_ni;
	runlist_element *rl, *rl2 = NULL;
	ntfs_attr_search_ctx *ctx = NULL;
	MFT_RECORD *mrec;
	ATTR_RECORD *a = NULL;
	int ret, mp_size;
	u32 old_alen = 0;
	u8 *b, tb;
	struct {
		u8 added_cluster:1;
		u8 added_run:1;
		u8 mp_rebuilt:1;
	} status = { 0, 0, 0 };

	ntfs_debug("Extending mft bitmap allocation.");
	mft_ni = NTFS_I(vol->mft_ino);
	mftbmp_ni = NTFS_I(vol->mftbmp_ino);
	/*
	 * Determine the last lcn of the mft bitmap.  The allocated size of the
	 * mft bitmap cannot be zero so we are ok to do this.
	 */
	down_write(&mftbmp_ni->runlist.lock);
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	ll = mftbmp_ni->allocated_size;
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	rl = ntfs_attr_find_vcn_nolock(mftbmp_ni,
			(ll - 1) >> vol->cluster_size_bits, NULL);
	if (unlikely(IS_ERR(rl) || !rl->length || rl->lcn < 0)) {
		up_write(&mftbmp_ni->runlist.lock);
		ntfs_error(vol->sb, "Failed to determine last allocated "
				"cluster of mft bitmap attribute.");
		if (!IS_ERR(rl))
			ret = -EIO;
		else
			ret = PTR_ERR(rl);
		return ret;
	}
	lcn = rl->lcn + rl->length;
	ntfs_debug("Last lcn of mft bitmap attribute is 0x%llx.",
			(long long)lcn);
	/*
	 * Attempt to get the cluster following the last allocated cluster by
	 * hand as it may be in the MFT zone so the allocator would not give it
	 * to us.
	 */
	ll = lcn >> 3;
	page = ntfs_map_page(vol->lcnbmp_ino->i_mapping,
			ll >> PAGE_CACHE_SHIFT);
	if (IS_ERR(page)) {
		up_write(&mftbmp_ni->runlist.lock);
		ntfs_error(vol->sb, "Failed to read from lcn bitmap.");
		return PTR_ERR(page);
	}
	b = (u8*)page_address(page) + (ll & ~PAGE_CACHE_MASK);
	tb = 1 << (lcn & 7ull);
	down_write(&vol->lcnbmp_lock);
	if (*b != 0xff && !(*b & tb)) {
		/* Next cluster is free, allocate it. */
		*b |= tb;
		flush_dcache_page(page);
		set_page_dirty(page);
		up_write(&vol->lcnbmp_lock);
		ntfs_unmap_page(page);
		/* Update the mft bitmap runlist. */
		rl->length++;
		rl[1].vcn++;
		status.added_cluster = 1;
		ntfs_debug("Appending one cluster to mft bitmap.");
	} else {
		up_write(&vol->lcnbmp_lock);
		ntfs_unmap_page(page);
		/* Allocate a cluster from the DATA_ZONE. */
		rl2 = ntfs_cluster_alloc(vol, rl[1].vcn, 1, lcn, DATA_ZONE,
				true);
		if (IS_ERR(rl2)) {
			up_write(&mftbmp_ni->runlist.lock);
			ntfs_error(vol->sb, "Failed to allocate a cluster for "
					"the mft bitmap.");
			return PTR_ERR(rl2);
		}
		rl = ntfs_runlists_merge(mftbmp_ni->runlist.rl, rl2);
		if (IS_ERR(rl)) {
			up_write(&mftbmp_ni->runlist.lock);
			ntfs_error(vol->sb, "Failed to merge runlists for mft "
					"bitmap.");
			if (ntfs_cluster_free_from_rl(vol, rl2)) {
				ntfs_error(vol->sb, "Failed to deallocate "
						"allocated cluster.%s", es);
				NVolSetErrors(vol);
			}
			ntfs_free(rl2);
			return PTR_ERR(rl);
		}
		mftbmp_ni->runlist.rl = rl;
		status.added_run = 1;
		ntfs_debug("Adding one run to mft bitmap.");
		/* Find the last run in the new runlist. */
		for (; rl[1].length; rl++)
			;
	}
	/*
	 * Update the attribute record as well.  Note: @rl is the last
	 * (non-terminator) runlist element of mft bitmap.
	 */
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		ntfs_error(vol->sb, "Failed to map mft record.");
		ret = PTR_ERR(mrec);
		goto undo_alloc;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.");
		ret = -ENOMEM;
		goto undo_alloc;
	}
	ret = ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, rl[1].vcn, NULL,
			0, ctx);
	if (unlikely(ret)) {
		ntfs_error(vol->sb, "Failed to find last attribute extent of "
				"mft bitmap attribute.");
		if (ret == -ENOENT)
			ret = -EIO;
		goto undo_alloc;
	}
	a = ctx->attr;
	ll = sle64_to_cpu(a->data.non_resident.lowest_vcn);
	/* Search back for the previous last allocated cluster of mft bitmap. */
	for (rl2 = rl; rl2 > mftbmp_ni->runlist.rl; rl2--) {
		if (ll >= rl2->vcn)
			break;
	}
	BUG_ON(ll < rl2->vcn);
	BUG_ON(ll >= rl2->vcn + rl2->length);
	/* Get the size for the new mapping pairs array for this extent. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl2, ll, -1);
	if (unlikely(mp_size <= 0)) {
		ntfs_error(vol->sb, "Get size for mapping pairs failed for "
				"mft bitmap attribute extent.");
		ret = mp_size;
		if (!ret)
			ret = -EIO;
		goto undo_alloc;
	}
	/* Expand the attribute record if necessary. */
	old_alen = le32_to_cpu(a->length);
	ret = ntfs_attr_record_resize(ctx->mrec, a, mp_size +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset));
	if (unlikely(ret)) {
		if (ret != -ENOSPC) {
			ntfs_error(vol->sb, "Failed to resize attribute "
					"record for mft bitmap attribute.");
			goto undo_alloc;
		}
		// TODO: Deal with this by moving this extent to a new mft
		// record or by starting a new extent in a new mft record or by
		// moving other attributes out of this mft record.
		// Note: It will need to be a special mft record and if none of
		// those are available it gets rather complicated...
		ntfs_error(vol->sb, "Not enough space in this mft record to "
				"accommodate extended mft bitmap attribute "
				"extent.  Cannot handle this yet.");
		ret = -EOPNOTSUPP;
		goto undo_alloc;
	}
	status.mp_rebuilt = 1;
	/* Generate the mapping pairs array directly into the attr record. */
	ret = ntfs_mapping_pairs_build(vol, (u8*)a +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset),
			mp_size, rl2, ll, -1, NULL);
	if (unlikely(ret)) {
		ntfs_error(vol->sb, "Failed to build mapping pairs array for "
				"mft bitmap attribute.");
		goto undo_alloc;
	}
	/* Update the highest_vcn. */
	a->data.non_resident.highest_vcn = cpu_to_sle64(rl[1].vcn - 1);
	/*
	 * We now have extended the mft bitmap allocated_size by one cluster.
	 * Reflect this in the ntfs_inode structure and the attribute record.
	 */
	if (a->data.non_resident.lowest_vcn) {
		/*
		 * We are not in the first attribute extent, switch to it, but
		 * first ensure the changes will make it to disk later.
		 */
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
		ntfs_attr_reinit_search_ctx(ctx);
		ret = ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
				mftbmp_ni->name_len, CASE_SENSITIVE, 0, NULL,
				0, ctx);
		if (unlikely(ret)) {
			ntfs_error(vol->sb, "Failed to find first attribute "
					"extent of mft bitmap attribute.");
			goto restore_undo_alloc;
		}
		a = ctx->attr;
	}
	write_lock_irqsave(&mftbmp_ni->size_lock, flags);
	mftbmp_ni->allocated_size += vol->cluster_size;
	a->data.non_resident.allocated_size =
			cpu_to_sle64(mftbmp_ni->allocated_size);
	write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	/* Ensure the changes make it to disk. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
	up_write(&mftbmp_ni->runlist.lock);
	ntfs_debug("Done.");
	return 0;
restore_undo_alloc:
	ntfs_attr_reinit_search_ctx(ctx);
	if (ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, rl[1].vcn, NULL,
			0, ctx)) {
		ntfs_error(vol->sb, "Failed to find last attribute extent of "
				"mft bitmap attribute.%s", es);
		write_lock_irqsave(&mftbmp_ni->size_lock, flags);
		mftbmp_ni->allocated_size += vol->cluster_size;
		write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(mft_ni);
		up_write(&mftbmp_ni->runlist.lock);
		/*
		 * The only thing that is now wrong is ->allocated_size of the
		 * base attribute extent which chkdsk should be able to fix.
		 */
		NVolSetErrors(vol);
		return ret;
	}
	a = ctx->attr;
	a->data.non_resident.highest_vcn = cpu_to_sle64(rl[1].vcn - 2);
undo_alloc:
	if (status.added_cluster) {
		/* Truncate the last run in the runlist by one cluster. */
		rl->length--;
		rl[1].vcn--;
	} else if (status.added_run) {
		lcn = rl->lcn;
		/* Remove the last run from the runlist. */
		rl->lcn = rl[1].lcn;
		rl->length = 0;
	}
	/* Deallocate the cluster. */
	down_write(&vol->lcnbmp_lock);
	if (ntfs_bitmap_clear_bit(vol->lcnbmp_ino, lcn)) {
		ntfs_error(vol->sb, "Failed to free allocated cluster.%s", es);
		NVolSetErrors(vol);
	}
	up_write(&vol->lcnbmp_lock);
	if (status.mp_rebuilt) {
		if (ntfs_mapping_pairs_build(vol, (u8*)a + le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset),
				old_alen - le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset),
				rl2, ll, -1, NULL)) {
			ntfs_error(vol->sb, "Failed to restore mapping pairs "
					"array.%s", es);
			NVolSetErrors(vol);
		}
		if (ntfs_attr_record_resize(ctx->mrec, a, old_alen)) {
			ntfs_error(vol->sb, "Failed to restore attribute "
					"record.%s", es);
			NVolSetErrors(vol);
		}
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
	}
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (!IS_ERR(mrec))
		unmap_mft_record(mft_ni);
	up_write(&mftbmp_ni->runlist.lock);
	return ret;
}

/**
 * ntfs_mft_bitmap_extend_initialized_nolock - extend mftbmp initialized data
 * @vol:	volume on which to extend the mft bitmap attribute
 *
 * Extend the initialized portion of the mft bitmap attribute on the ntfs
 * volume @vol by 8 bytes.
 *
 * Note:  Only changes initialized_size and data_size, i.e. requires that
 * allocated_size is big enough to fit the new initialized_size.
 *
 * Return 0 on success and -error on error.
 *
 * Locking: Caller must hold vol->mftbmp_lock for writing.
 */
static int ntfs_mft_bitmap_extend_initialized_nolock(ntfs_volume *vol)
{
	s64 old_data_size, old_initialized_size;
	unsigned long flags;
	struct inode *mftbmp_vi;
	ntfs_inode *mft_ni, *mftbmp_ni;
	ntfs_attr_search_ctx *ctx;
	MFT_RECORD *mrec;
	ATTR_RECORD *a;
	int ret;

	ntfs_debug("Extending mft bitmap initiailized (and data) size.");
	mft_ni = NTFS_I(vol->mft_ino);
	mftbmp_vi = vol->mftbmp_ino;
	mftbmp_ni = NTFS_I(mftbmp_vi);
	/* Get the attribute record. */
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		ntfs_error(vol->sb, "Failed to map mft record.");
		return PTR_ERR(mrec);
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.");
		ret = -ENOMEM;
		goto unm_err_out;
	}
	ret = ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(ret)) {
		ntfs_error(vol->sb, "Failed to find first attribute extent of "
				"mft bitmap attribute.");
		if (ret == -ENOENT)
			ret = -EIO;
		goto put_err_out;
	}
	a = ctx->attr;
	write_lock_irqsave(&mftbmp_ni->size_lock, flags);
	old_data_size = i_size_read(mftbmp_vi);
	old_initialized_size = mftbmp_ni->initialized_size;
	/*
	 * We can simply update the initialized_size before filling the space
	 * with zeroes because the caller is holding the mft bitmap lock for
	 * writing which ensures that no one else is trying to access the data.
	 */
	mftbmp_ni->initialized_size += 8;
	a->data.non_resident.initialized_size =
			cpu_to_sle64(mftbmp_ni->initialized_size);
	if (mftbmp_ni->initialized_size > old_data_size) {
		i_size_write(mftbmp_vi, mftbmp_ni->initialized_size);
		a->data.non_resident.data_size =
				cpu_to_sle64(mftbmp_ni->initialized_size);
	}
	write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	/* Ensure the changes make it to disk. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
	/* Initialize the mft bitmap attribute value with zeroes. */
	ret = ntfs_attr_set(mftbmp_ni, old_initialized_size, 8, 0);
	if (likely(!ret)) {
		ntfs_debug("Done.  (Wrote eight initialized bytes to mft "
				"bitmap.");
		return 0;
	}
	ntfs_error(vol->sb, "Failed to write to mft bitmap.");
	/* Try to recover from the error. */
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		ntfs_error(vol->sb, "Failed to map mft record.%s", es);
		NVolSetErrors(vol);
		return ret;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.%s", es);
		NVolSetErrors(vol);
		goto unm_err_out;
	}
	if (ntfs_attr_lookup(mftbmp_ni->type, mftbmp_ni->name,
			mftbmp_ni->name_len, CASE_SENSITIVE, 0, NULL, 0, ctx)) {
		ntfs_error(vol->sb, "Failed to find first attribute extent of "
				"mft bitmap attribute.%s", es);
		NVolSetErrors(vol);
put_err_out:
		ntfs_attr_put_search_ctx(ctx);
unm_err_out:
		unmap_mft_record(mft_ni);
		goto err_out;
	}
	a = ctx->attr;
	write_lock_irqsave(&mftbmp_ni->size_lock, flags);
	mftbmp_ni->initialized_size = old_initialized_size;
	a->data.non_resident.initialized_size =
			cpu_to_sle64(old_initialized_size);
	if (i_size_read(mftbmp_vi) != old_data_size) {
		i_size_write(mftbmp_vi, old_data_size);
		a->data.non_resident.data_size = cpu_to_sle64(old_data_size);
	}
	write_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
#ifdef DEBUG
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	ntfs_debug("Restored status of mftbmp: allocated_size 0x%llx, "
			"data_size 0x%llx, initialized_size 0x%llx.",
			(long long)mftbmp_ni->allocated_size,
			(long long)i_size_read(mftbmp_vi),
			(long long)mftbmp_ni->initialized_size);
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
#endif /* DEBUG */
err_out:
	return ret;
}

/**
 * ntfs_mft_data_extend_allocation_nolock - extend mft data attribute
 * @vol:	volume on which to extend the mft data attribute
 *
 * Extend the mft data attribute on the ntfs volume @vol by 16 mft records
 * worth of clusters or if not enough space for this by one mft record worth
 * of clusters.
 *
 * Note:  Only changes allocated_size, i.e. does not touch initialized_size or
 * data_size.
 *
 * Return 0 on success and -errno on error.
 *
 * Locking: - Caller must hold vol->mftbmp_lock for writing.
 *	    - This function takes NTFS_I(vol->mft_ino)->runlist.lock for
 *	      writing and releases it before returning.
 *	    - This function calls functions which take vol->lcnbmp_lock for
 *	      writing and release it before returning.
 */
static int ntfs_mft_data_extend_allocation_nolock(ntfs_volume *vol)
{
	LCN lcn;
	VCN old_last_vcn;
	s64 min_nr, nr, ll;
	unsigned long flags;
	ntfs_inode *mft_ni;
	runlist_element *rl, *rl2;
	ntfs_attr_search_ctx *ctx = NULL;
	MFT_RECORD *mrec;
	ATTR_RECORD *a = NULL;
	int ret, mp_size;
	u32 old_alen = 0;
	bool mp_rebuilt = false;

	ntfs_debug("Extending mft data allocation.");
	mft_ni = NTFS_I(vol->mft_ino);
	/*
	 * Determine the preferred allocation location, i.e. the last lcn of
	 * the mft data attribute.  The allocated size of the mft data
	 * attribute cannot be zero so we are ok to do this.
	 */
	down_write(&mft_ni->runlist.lock);
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ll = mft_ni->allocated_size;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	rl = ntfs_attr_find_vcn_nolock(mft_ni,
			(ll - 1) >> vol->cluster_size_bits, NULL);
	if (unlikely(IS_ERR(rl) || !rl->length || rl->lcn < 0)) {
		up_write(&mft_ni->runlist.lock);
		ntfs_error(vol->sb, "Failed to determine last allocated "
				"cluster of mft data attribute.");
		if (!IS_ERR(rl))
			ret = -EIO;
		else
			ret = PTR_ERR(rl);
		return ret;
	}
	lcn = rl->lcn + rl->length;
	ntfs_debug("Last lcn of mft data attribute is 0x%llx.", (long long)lcn);
	/* Minimum allocation is one mft record worth of clusters. */
	min_nr = vol->mft_record_size >> vol->cluster_size_bits;
	if (!min_nr)
		min_nr = 1;
	/* Want to allocate 16 mft records worth of clusters. */
	nr = vol->mft_record_size << 4 >> vol->cluster_size_bits;
	if (!nr)
		nr = min_nr;
	/* Ensure we do not go above 2^32-1 mft records. */
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ll = mft_ni->allocated_size;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	if (unlikely((ll + (nr << vol->cluster_size_bits)) >>
			vol->mft_record_size_bits >= (1ll << 32))) {
		nr = min_nr;
		if (unlikely((ll + (nr << vol->cluster_size_bits)) >>
				vol->mft_record_size_bits >= (1ll << 32))) {
			ntfs_warning(vol->sb, "Cannot allocate mft record "
					"because the maximum number of inodes "
					"(2^32) has already been reached.");
			up_write(&mft_ni->runlist.lock);
			return -ENOSPC;
		}
	}
	ntfs_debug("Trying mft data allocation with %s cluster count %lli.",
			nr > min_nr ? "default" : "minimal", (long long)nr);
	old_last_vcn = rl[1].vcn;
	do {
		rl2 = ntfs_cluster_alloc(vol, old_last_vcn, nr, lcn, MFT_ZONE,
				true);
		if (likely(!IS_ERR(rl2)))
			break;
		if (PTR_ERR(rl2) != -ENOSPC || nr == min_nr) {
			ntfs_error(vol->sb, "Failed to allocate the minimal "
					"number of clusters (%lli) for the "
					"mft data attribute.", (long long)nr);
			up_write(&mft_ni->runlist.lock);
			return PTR_ERR(rl2);
		}
		/*
		 * There is not enough space to do the allocation, but there
		 * might be enough space to do a minimal allocation so try that
		 * before failing.
		 */
		nr = min_nr;
		ntfs_debug("Retrying mft data allocation with minimal cluster "
				"count %lli.", (long long)nr);
	} while (1);
	rl = ntfs_runlists_merge(mft_ni->runlist.rl, rl2);
	if (IS_ERR(rl)) {
		up_write(&mft_ni->runlist.lock);
		ntfs_error(vol->sb, "Failed to merge runlists for mft data "
				"attribute.");
		if (ntfs_cluster_free_from_rl(vol, rl2)) {
			ntfs_error(vol->sb, "Failed to deallocate clusters "
					"from the mft data attribute.%s", es);
			NVolSetErrors(vol);
		}
		ntfs_free(rl2);
		return PTR_ERR(rl);
	}
	mft_ni->runlist.rl = rl;
	ntfs_debug("Allocated %lli clusters.", (long long)nr);
	/* Find the last run in the new runlist. */
	for (; rl[1].length; rl++)
		;
	/* Update the attribute record as well. */
	mrec = map_mft_record(mft_ni);
	if (IS_ERR(mrec)) {
		ntfs_error(vol->sb, "Failed to map mft record.");
		ret = PTR_ERR(mrec);
		goto undo_alloc;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, mrec);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.");
		ret = -ENOMEM;
		goto undo_alloc;
	}
	ret = ntfs_attr_lookup(mft_ni->type, mft_ni->name, mft_ni->name_len,
			CASE_SENSITIVE, rl[1].vcn, NULL, 0, ctx);
	if (unlikely(ret)) {
		ntfs_error(vol->sb, "Failed to find last attribute extent of "
				"mft data attribute.");
		if (ret == -ENOENT)
			ret = -EIO;
		goto undo_alloc;
	}
	a = ctx->attr;
	ll = sle64_to_cpu(a->data.non_resident.lowest_vcn);
	/* Search back for the previous last allocated cluster of mft bitmap. */
	for (rl2 = rl; rl2 > mft_ni->runlist.rl; rl2--) {
		if (ll >= rl2->vcn)
			break;
	}
	BUG_ON(ll < rl2->vcn);
	BUG_ON(ll >= rl2->vcn + rl2->length);
	/* Get the size for the new mapping pairs array for this extent. */
	mp_size = ntfs_get_size_for_mapping_pairs(vol, rl2, ll, -1);
	if (unlikely(mp_size <= 0)) {
		ntfs_error(vol->sb, "Get size for mapping pairs failed for "
				"mft data attribute extent.");
		ret = mp_size;
		if (!ret)
			ret = -EIO;
		goto undo_alloc;
	}
	/* Expand the attribute record if necessary. */
	old_alen = le32_to_cpu(a->length);
	ret = ntfs_attr_record_resize(ctx->mrec, a, mp_size +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset));
	if (unlikely(ret)) {
		if (ret != -ENOSPC) {
			ntfs_error(vol->sb, "Failed to resize attribute "
					"record for mft data attribute.");
			goto undo_alloc;
		}
		// TODO: Deal with this by moving this extent to a new mft
		// record or by starting a new extent in a new mft record or by
		// moving other attributes out of this mft record.
		// Note: Use the special reserved mft records and ensure that
		// this extent is not required to find the mft record in
		// question.  If no free special records left we would need to
		// move an existing record away, insert ours in its place, and
		// then place the moved record into the newly allocated space
		// and we would then need to update all references to this mft
		// record appropriately.  This is rather complicated...
		ntfs_error(vol->sb, "Not enough space in this mft record to "
				"accommodate extended mft data attribute "
				"extent.  Cannot handle this yet.");
		ret = -EOPNOTSUPP;
		goto undo_alloc;
	}
	mp_rebuilt = true;
	/* Generate the mapping pairs array directly into the attr record. */
	ret = ntfs_mapping_pairs_build(vol, (u8*)a +
			le16_to_cpu(a->data.non_resident.mapping_pairs_offset),
			mp_size, rl2, ll, -1, NULL);
	if (unlikely(ret)) {
		ntfs_error(vol->sb, "Failed to build mapping pairs array of "
				"mft data attribute.");
		goto undo_alloc;
	}
	/* Update the highest_vcn. */
	a->data.non_resident.highest_vcn = cpu_to_sle64(rl[1].vcn - 1);
	/*
	 * We now have extended the mft data allocated_size by nr clusters.
	 * Reflect this in the ntfs_inode structure and the attribute record.
	 * @rl is the last (non-terminator) runlist element of mft data
	 * attribute.
	 */
	if (a->data.non_resident.lowest_vcn) {
		/*
		 * We are not in the first attribute extent, switch to it, but
		 * first ensure the changes will make it to disk later.
		 */
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
		ntfs_attr_reinit_search_ctx(ctx);
		ret = ntfs_attr_lookup(mft_ni->type, mft_ni->name,
				mft_ni->name_len, CASE_SENSITIVE, 0, NULL, 0,
				ctx);
		if (unlikely(ret)) {
			ntfs_error(vol->sb, "Failed to find first attribute "
					"extent of mft data attribute.");
			goto restore_undo_alloc;
		}
		a = ctx->attr;
	}
	write_lock_irqsave(&mft_ni->size_lock, flags);
	mft_ni->allocated_size += nr << vol->cluster_size_bits;
	a->data.non_resident.allocated_size =
			cpu_to_sle64(mft_ni->allocated_size);
	write_unlock_irqrestore(&mft_ni->size_lock, flags);
	/* Ensure the changes make it to disk. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
	up_write(&mft_ni->runlist.lock);
	ntfs_debug("Done.");
	return 0;
restore_undo_alloc:
	ntfs_attr_reinit_search_ctx(ctx);
	if (ntfs_attr_lookup(mft_ni->type, mft_ni->name, mft_ni->name_len,
			CASE_SENSITIVE, rl[1].vcn, NULL, 0, ctx)) {
		ntfs_error(vol->sb, "Failed to find last attribute extent of "
				"mft data attribute.%s", es);
		write_lock_irqsave(&mft_ni->size_lock, flags);
		mft_ni->allocated_size += nr << vol->cluster_size_bits;
		write_unlock_irqrestore(&mft_ni->size_lock, flags);
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(mft_ni);
		up_write(&mft_ni->runlist.lock);
		/*
		 * The only thing that is now wrong is ->allocated_size of the
		 * base attribute extent which chkdsk should be able to fix.
		 */
		NVolSetErrors(vol);
		return ret;
	}
	ctx->attr->data.non_resident.highest_vcn =
			cpu_to_sle64(old_last_vcn - 1);
undo_alloc:
	if (ntfs_cluster_free(mft_ni, old_last_vcn, -1, ctx) < 0) {
		ntfs_error(vol->sb, "Failed to free clusters from mft data "
				"attribute.%s", es);
		NVolSetErrors(vol);
	}
	a = ctx->attr;
	if (ntfs_rl_truncate_nolock(vol, &mft_ni->runlist, old_last_vcn)) {
		ntfs_error(vol->sb, "Failed to truncate mft data attribute "
				"runlist.%s", es);
		NVolSetErrors(vol);
	}
	if (mp_rebuilt && !IS_ERR(ctx->mrec)) {
		if (ntfs_mapping_pairs_build(vol, (u8*)a + le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset),
				old_alen - le16_to_cpu(
				a->data.non_resident.mapping_pairs_offset),
				rl2, ll, -1, NULL)) {
			ntfs_error(vol->sb, "Failed to restore mapping pairs "
					"array.%s", es);
			NVolSetErrors(vol);
		}
		if (ntfs_attr_record_resize(ctx->mrec, a, old_alen)) {
			ntfs_error(vol->sb, "Failed to restore attribute "
					"record.%s", es);
			NVolSetErrors(vol);
		}
		flush_dcache_mft_record_page(ctx->ntfs_ino);
		mark_mft_record_dirty(ctx->ntfs_ino);
	} else if (IS_ERR(ctx->mrec)) {
		ntfs_error(vol->sb, "Failed to restore attribute search "
				"context.%s", es);
		NVolSetErrors(vol);
	}
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (!IS_ERR(mrec))
		unmap_mft_record(mft_ni);
	up_write(&mft_ni->runlist.lock);
	return ret;
}

/**
 * ntfs_mft_record_layout - layout an mft record into a memory buffer
 * @vol:	volume to which the mft record will belong
 * @mft_no:	mft reference specifying the mft record number
 * @m:		destination buffer of size >= @vol->mft_record_size bytes
 *
 * Layout an empty, unused mft record with the mft record number @mft_no into
 * the buffer @m.  The volume @vol is needed because the mft record structure
 * was modified in NTFS 3.1 so we need to know which volume version this mft
 * record will be used on.
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_mft_record_layout(const ntfs_volume *vol, const s64 mft_no,
		MFT_RECORD *m)
{
	ATTR_RECORD *a;

	ntfs_debug("Entering for mft record 0x%llx.", (long long)mft_no);
	if (mft_no >= (1ll << 32)) {
		ntfs_error(vol->sb, "Mft record number 0x%llx exceeds "
				"maximum of 2^32.", (long long)mft_no);
		return -ERANGE;
	}
	/* Start by clearing the whole mft record to gives us a clean slate. */
	memset(m, 0, vol->mft_record_size);
	/* Aligned to 2-byte boundary. */
	if (vol->major_ver < 3 || (vol->major_ver == 3 && !vol->minor_ver))
		m->usa_ofs = cpu_to_le16((sizeof(MFT_RECORD_OLD) + 1) & ~1);
	else {
		m->usa_ofs = cpu_to_le16((sizeof(MFT_RECORD) + 1) & ~1);
		/*
		 * Set the NTFS 3.1+ specific fields while we know that the
		 * volume version is 3.1+.
		 */
		m->reserved = 0;
		m->mft_record_number = cpu_to_le32((u32)mft_no);
	}
	m->magic = magic_FILE;
	if (vol->mft_record_size >= NTFS_BLOCK_SIZE)
		m->usa_count = cpu_to_le16(vol->mft_record_size /
				NTFS_BLOCK_SIZE + 1);
	else {
		m->usa_count = cpu_to_le16(1);
		ntfs_warning(vol->sb, "Sector size is bigger than mft record "
				"size.  Setting usa_count to 1.  If chkdsk "
				"reports this as corruption, please email "
				"linux-ntfs-dev@lists.sourceforge.net stating "
				"that you saw this message and that the "
				"modified filesystem created was corrupt.  "
				"Thank you.");
	}
	/* Set the update sequence number to 1. */
	*(le16*)((u8*)m + le16_to_cpu(m->usa_ofs)) = cpu_to_le16(1);
	m->lsn = 0;
	m->sequence_number = cpu_to_le16(1);
	m->link_count = 0;
	/*
	 * Place the attributes straight after the update sequence array,
	 * aligned to 8-byte boundary.
	 */
	m->attrs_offset = cpu_to_le16((le16_to_cpu(m->usa_ofs) +
			(le16_to_cpu(m->usa_count) << 1) + 7) & ~7);
	m->flags = 0;
	/*
	 * Using attrs_offset plus eight bytes (for the termination attribute).
	 * attrs_offset is already aligned to 8-byte boundary, so no need to
	 * align again.
	 */
	m->bytes_in_use = cpu_to_le32(le16_to_cpu(m->attrs_offset) + 8);
	m->bytes_allocated = cpu_to_le32(vol->mft_record_size);
	m->base_mft_record = 0;
	m->next_attr_instance = 0;
	/* Add the termination attribute. */
	a = (ATTR_RECORD*)((u8*)m + le16_to_cpu(m->attrs_offset));
	a->type = AT_END;
	a->length = 0;
	ntfs_debug("Done.");
	return 0;
}

/**
 * ntfs_mft_record_format - format an mft record on an ntfs volume
 * @vol:	volume on which to format the mft record
 * @mft_no:	mft record number to format
 *
 * Format the mft record @mft_no in $MFT/$DATA, i.e. lay out an empty, unused
 * mft record into the appropriate place of the mft data attribute.  This is
 * used when extending the mft data attribute.
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_mft_record_format(const ntfs_volume *vol, const s64 mft_no)
{
	loff_t i_size;
	struct inode *mft_vi = vol->mft_ino;
	struct page *page;
	MFT_RECORD *m;
	pgoff_t index, end_index;
	unsigned int ofs;
	int err;

	ntfs_debug("Entering for mft record 0x%llx.", (long long)mft_no);
	/*
	 * The index into the page cache and the offset within the page cache
	 * page of the wanted mft record.
	 */
	index = mft_no << vol->mft_record_size_bits >> PAGE_CACHE_SHIFT;
	ofs = (mft_no << vol->mft_record_size_bits) & ~PAGE_CACHE_MASK;
	/* The maximum valid index into the page cache for $MFT's data. */
	i_size = i_size_read(mft_vi);
	end_index = i_size >> PAGE_CACHE_SHIFT;
	if (unlikely(index >= end_index)) {
		if (unlikely(index > end_index || ofs + vol->mft_record_size >=
				(i_size & ~PAGE_CACHE_MASK))) {
			ntfs_error(vol->sb, "Tried to format non-existing mft "
					"record 0x%llx.", (long long)mft_no);
			return -ENOENT;
		}
	}
	/* Read, map, and pin the page containing the mft record. */
	page = ntfs_map_page(mft_vi->i_mapping, index);
	if (IS_ERR(page)) {
		ntfs_error(vol->sb, "Failed to map page containing mft record "
				"to format 0x%llx.", (long long)mft_no);
		return PTR_ERR(page);
	}
	lock_page(page);
	BUG_ON(!PageUptodate(page));
	ClearPageUptodate(page);
	m = (MFT_RECORD*)((u8*)page_address(page) + ofs);
	err = ntfs_mft_record_layout(vol, mft_no, m);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Failed to layout mft record 0x%llx.",
				(long long)mft_no);
		SetPageUptodate(page);
		unlock_page(page);
		ntfs_unmap_page(page);
		return err;
	}
	flush_dcache_page(page);
	SetPageUptodate(page);
	unlock_page(page);
	/*
	 * Make sure the mft record is written out to disk.  We could use
	 * ilookup5() to check if an inode is in icache and so on but this is
	 * unnecessary as ntfs_writepage() will write the dirty record anyway.
	 */
	mark_ntfs_record_dirty(page, ofs);
	ntfs_unmap_page(page);
	ntfs_debug("Done.");
	return 0;
}

/**
 * ntfs_mft_record_alloc - allocate an mft record on an ntfs volume
 * @vol:	[IN]  volume on which to allocate the mft record
 * @mode:	[IN]  mode if want a file or directory, i.e. base inode or 0
 * @base_ni:	[IN]  open base inode if allocating an extent mft record or NULL
 * @mrec:	[OUT] on successful return this is the mapped mft record
 *
 * Allocate an mft record in $MFT/$DATA of an open ntfs volume @vol.
 *
 * If @base_ni is NULL make the mft record a base mft record, i.e. a file or
 * direvctory inode, and allocate it at the default allocator position.  In
 * this case @mode is the file mode as given to us by the caller.  We in
 * particular use @mode to distinguish whether a file or a directory is being
 * created (S_IFDIR(mode) and S_IFREG(mode), respectively).
 *
 * If @base_ni is not NULL make the allocated mft record an extent record,
 * allocate it starting at the mft record after the base mft record and attach
 * the allocated and opened ntfs inode to the base inode @base_ni.  In this
 * case @mode must be 0 as it is meaningless for extent inodes.
 *
 * You need to check the return value with IS_ERR().  If false, the function
 * was successful and the return value is the now opened ntfs inode of the
 * allocated mft record.  *@mrec is then set to the allocated, mapped, pinned,
 * and locked mft record.  If IS_ERR() is true, the function failed and the
 * error code is obtained from PTR_ERR(return value).  *@mrec is undefined in
 * this case.
 *
 * Allocation strategy:
 *
 * To find a free mft record, we scan the mft bitmap for a zero bit.  To
 * optimize this we start scanning at the place specified by @base_ni or if
 * @base_ni is NULL we start where we last stopped and we perform wrap around
 * when we reach the end.  Note, we do not try to allocate mft records below
 * number 24 because numbers 0 to 15 are the defined system files anyway and 16
 * to 24 are special in that they are used for storing extension mft records
 * for the $DATA attribute of $MFT.  This is required to avoid the possibility
 * of creating a runlist with a circular dependency which once written to disk
 * can never be read in again.  Windows will only use records 16 to 24 for
 * normal files if the volume is completely out of space.  We never use them
 * which means that when the volume is really out of space we cannot create any
 * more files while Windows can still create up to 8 small files.  We can start
 * doing this at some later time, it does not matter much for now.
 *
 * When scanning the mft bitmap, we only search up to the last allocated mft
 * record.  If there are no free records left in the range 24 to number of
 * allocated mft records, then we extend the $MFT/$DATA attribute in order to
 * create free mft records.  We extend the allocated size of $MFT/$DATA by 16
 * records at a time or one cluster, if cluster size is above 16kiB.  If there
 * is not sufficient space to do this, we try to extend by a single mft record
 * or one cluster, if cluster size is above the mft record size.
 *
 * No matter how many mft records we allocate, we initialize only the first
 * allocated mft record, incrementing mft data size and initialized size
 * accordingly, open an ntfs_inode for it and return it to the caller, unless
 * there are less than 24 mft records, in which case we allocate and initialize
 * mft records until we reach record 24 which we consider as the first free mft
 * record for use by normal files.
 *
 * If during any stage we overflow the initialized data in the mft bitmap, we
 * extend the initialized size (and data size) by 8 bytes, allocating another
 * cluster if required.  The bitmap data size has to be at least equal to the
 * number of mft records in the mft, but it can be bigger, in which case the
 * superflous bits are padded with zeroes.
 *
 * Thus, when we return successfully (IS_ERR() is false), we will have:
 *	- initialized / extended the mft bitmap if necessary,
 *	- initialized / extended the mft data if necessary,
 *	- set the bit corresponding to the mft record being allocated in the
 *	  mft bitmap,
 *	- opened an ntfs_inode for the allocated mft record, and we will have
 *	- returned the ntfs_inode as well as the allocated mapped, pinned, and
 *	  locked mft record.
 *
 * On error, the volume will be left in a consistent state and no record will
 * be allocated.  If rolling back a partial operation fails, we may leave some
 * inconsistent metadata in which case we set NVolErrors() so the volume is
 * left dirty when unmounted.
 *
 * Note, this function cannot make use of most of the normal functions, like
 * for example for attribute resizing, etc, because when the run list overflows
 * the base mft record and an attribute list is used, it is very important that
 * the extension mft records used to store the $DATA attribute of $MFT can be
 * reached without having to read the information contained inside them, as
 * this would make it impossible to find them in the first place after the
 * volume is unmounted.  $MFT/$BITMAP probably does not need to follow this
 * rule because the bitmap is not essential for finding the mft records, but on
 * the other hand, handling the bitmap in this special way would make life
 * easier because otherwise there might be circular invocations of functions
 * when reading the bitmap.
 */
ntfs_inode *ntfs_mft_record_alloc(ntfs_volume *vol, const int mode,
		ntfs_inode *base_ni, MFT_RECORD **mrec)
{
	s64 ll, bit, old_data_initialized, old_data_size;
	unsigned long flags;
	struct inode *vi;
	struct page *page;
	ntfs_inode *mft_ni, *mftbmp_ni, *ni;
	ntfs_attr_search_ctx *ctx;
	MFT_RECORD *m;
	ATTR_RECORD *a;
	pgoff_t index;
	unsigned int ofs;
	int err;
	le16 seq_no, usn;
	bool record_formatted = false;

	if (base_ni) {
		ntfs_debug("Entering (allocating an extent mft record for "
				"base mft record 0x%llx).",
				(long long)base_ni->mft_no);
		/* @mode and @base_ni are mutually exclusive. */
		BUG_ON(mode);
	} else
		ntfs_debug("Entering (allocating a base mft record).");
	if (mode) {
		/* @mode and @base_ni are mutually exclusive. */
		BUG_ON(base_ni);
		/* We only support creation of normal files and directories. */
		if (!S_ISREG(mode) && !S_ISDIR(mode))
			return ERR_PTR(-EOPNOTSUPP);
	}
	BUG_ON(!mrec);
	mft_ni = NTFS_I(vol->mft_ino);
	mftbmp_ni = NTFS_I(vol->mftbmp_ino);
	down_write(&vol->mftbmp_lock);
	bit = ntfs_mft_bitmap_find_and_alloc_free_rec_nolock(vol, base_ni);
	if (bit >= 0) {
		ntfs_debug("Found and allocated free record (#1), bit 0x%llx.",
				(long long)bit);
		goto have_alloc_rec;
	}
	if (bit != -ENOSPC) {
		up_write(&vol->mftbmp_lock);
		return ERR_PTR(bit);
	}
	/*
	 * No free mft records left.  If the mft bitmap already covers more
	 * than the currently used mft records, the next records are all free,
	 * so we can simply allocate the first unused mft record.
	 * Note: We also have to make sure that the mft bitmap at least covers
	 * the first 24 mft records as they are special and whilst they may not
	 * be in use, we do not allocate from them.
	 */
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ll = mft_ni->initialized_size >> vol->mft_record_size_bits;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	old_data_initialized = mftbmp_ni->initialized_size;
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	if (old_data_initialized << 3 > ll && old_data_initialized > 3) {
		bit = ll;
		if (bit < 24)
			bit = 24;
		if (unlikely(bit >= (1ll << 32)))
			goto max_err_out;
		ntfs_debug("Found free record (#2), bit 0x%llx.",
				(long long)bit);
		goto found_free_rec;
	}
	/*
	 * The mft bitmap needs to be expanded until it covers the first unused
	 * mft record that we can allocate.
	 * Note: The smallest mft record we allocate is mft record 24.
	 */
	bit = old_data_initialized << 3;
	if (unlikely(bit >= (1ll << 32)))
		goto max_err_out;
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	old_data_size = mftbmp_ni->allocated_size;
	ntfs_debug("Status of mftbmp before extension: allocated_size 0x%llx, "
			"data_size 0x%llx, initialized_size 0x%llx.",
			(long long)old_data_size,
			(long long)i_size_read(vol->mftbmp_ino),
			(long long)old_data_initialized);
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
	if (old_data_initialized + 8 > old_data_size) {
		/* Need to extend bitmap by one more cluster. */
		ntfs_debug("mftbmp: initialized_size + 8 > allocated_size.");
		err = ntfs_mft_bitmap_extend_allocation_nolock(vol);
		if (unlikely(err)) {
			up_write(&vol->mftbmp_lock);
			goto err_out;
		}
#ifdef DEBUG
		read_lock_irqsave(&mftbmp_ni->size_lock, flags);
		ntfs_debug("Status of mftbmp after allocation extension: "
				"allocated_size 0x%llx, data_size 0x%llx, "
				"initialized_size 0x%llx.",
				(long long)mftbmp_ni->allocated_size,
				(long long)i_size_read(vol->mftbmp_ino),
				(long long)mftbmp_ni->initialized_size);
		read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
#endif /* DEBUG */
	}
	/*
	 * We now have sufficient allocated space, extend the initialized_size
	 * as well as the data_size if necessary and fill the new space with
	 * zeroes.
	 */
	err = ntfs_mft_bitmap_extend_initialized_nolock(vol);
	if (unlikely(err)) {
		up_write(&vol->mftbmp_lock);
		goto err_out;
	}
#ifdef DEBUG
	read_lock_irqsave(&mftbmp_ni->size_lock, flags);
	ntfs_debug("Status of mftbmp after initialized extension: "
			"allocated_size 0x%llx, data_size 0x%llx, "
			"initialized_size 0x%llx.",
			(long long)mftbmp_ni->allocated_size,
			(long long)i_size_read(vol->mftbmp_ino),
			(long long)mftbmp_ni->initialized_size);
	read_unlock_irqrestore(&mftbmp_ni->size_lock, flags);
#endif /* DEBUG */
	ntfs_debug("Found free record (#3), bit 0x%llx.", (long long)bit);
found_free_rec:
	/* @bit is the found free mft record, allocate it in the mft bitmap. */
	ntfs_debug("At found_free_rec.");
	err = ntfs_bitmap_set_bit(vol->mftbmp_ino, bit);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Failed to allocate bit in mft bitmap.");
		up_write(&vol->mftbmp_lock);
		goto err_out;
	}
	ntfs_debug("Set bit 0x%llx in mft bitmap.", (long long)bit);
have_alloc_rec:
	/*
	 * The mft bitmap is now uptodate.  Deal with mft data attribute now.
	 * Note, we keep hold of the mft bitmap lock for writing until all
	 * modifications to the mft data attribute are complete, too, as they
	 * will impact decisions for mft bitmap and mft record allocation done
	 * by a parallel allocation and if the lock is not maintained a
	 * parallel allocation could allocate the same mft record as this one.
	 */
	ll = (bit + 1) << vol->mft_record_size_bits;
	read_lock_irqsave(&mft_ni->size_lock, flags);
	old_data_initialized = mft_ni->initialized_size;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	if (ll <= old_data_initialized) {
		ntfs_debug("Allocated mft record already initialized.");
		goto mft_rec_already_initialized;
	}
	ntfs_debug("Initializing allocated mft record.");
	/*
	 * The mft record is outside the initialized data.  Extend the mft data
	 * attribute until it covers the allocated record.  The loop is only
	 * actually traversed more than once when a freshly formatted volume is
	 * first written to so it optimizes away nicely in the common case.
	 */
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ntfs_debug("Status of mft data before extension: "
			"allocated_size 0x%llx, data_size 0x%llx, "
			"initialized_size 0x%llx.",
			(long long)mft_ni->allocated_size,
			(long long)i_size_read(vol->mft_ino),
			(long long)mft_ni->initialized_size);
	while (ll > mft_ni->allocated_size) {
		read_unlock_irqrestore(&mft_ni->size_lock, flags);
		err = ntfs_mft_data_extend_allocation_nolock(vol);
		if (unlikely(err)) {
			ntfs_error(vol->sb, "Failed to extend mft data "
					"allocation.");
			goto undo_mftbmp_alloc_nolock;
		}
		read_lock_irqsave(&mft_ni->size_lock, flags);
		ntfs_debug("Status of mft data after allocation extension: "
				"allocated_size 0x%llx, data_size 0x%llx, "
				"initialized_size 0x%llx.",
				(long long)mft_ni->allocated_size,
				(long long)i_size_read(vol->mft_ino),
				(long long)mft_ni->initialized_size);
	}
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	/*
	 * Extend mft data initialized size (and data size of course) to reach
	 * the allocated mft record, formatting the mft records allong the way.
	 * Note: We only modify the ntfs_inode structure as that is all that is
	 * needed by ntfs_mft_record_format().  We will update the attribute
	 * record itself in one fell swoop later on.
	 */
	write_lock_irqsave(&mft_ni->size_lock, flags);
	old_data_initialized = mft_ni->initialized_size;
	old_data_size = vol->mft_ino->i_size;
	while (ll > mft_ni->initialized_size) {
		s64 new_initialized_size, mft_no;
		
		new_initialized_size = mft_ni->initialized_size +
				vol->mft_record_size;
		mft_no = mft_ni->initialized_size >> vol->mft_record_size_bits;
		if (new_initialized_size > i_size_read(vol->mft_ino))
			i_size_write(vol->mft_ino, new_initialized_size);
		write_unlock_irqrestore(&mft_ni->size_lock, flags);
		ntfs_debug("Initializing mft record 0x%llx.",
				(long long)mft_no);
		err = ntfs_mft_record_format(vol, mft_no);
		if (unlikely(err)) {
			ntfs_error(vol->sb, "Failed to format mft record.");
			goto undo_data_init;
		}
		write_lock_irqsave(&mft_ni->size_lock, flags);
		mft_ni->initialized_size = new_initialized_size;
	}
	write_unlock_irqrestore(&mft_ni->size_lock, flags);
	record_formatted = true;
	/* Update the mft data attribute record to reflect the new sizes. */
	m = map_mft_record(mft_ni);
	if (IS_ERR(m)) {
		ntfs_error(vol->sb, "Failed to map mft record.");
		err = PTR_ERR(m);
		goto undo_data_init;
	}
	ctx = ntfs_attr_get_search_ctx(mft_ni, m);
	if (unlikely(!ctx)) {
		ntfs_error(vol->sb, "Failed to get search context.");
		err = -ENOMEM;
		unmap_mft_record(mft_ni);
		goto undo_data_init;
	}
	err = ntfs_attr_lookup(mft_ni->type, mft_ni->name, mft_ni->name_len,
			CASE_SENSITIVE, 0, NULL, 0, ctx);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Failed to find first attribute extent of "
				"mft data attribute.");
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(mft_ni);
		goto undo_data_init;
	}
	a = ctx->attr;
	read_lock_irqsave(&mft_ni->size_lock, flags);
	a->data.non_resident.initialized_size =
			cpu_to_sle64(mft_ni->initialized_size);
	a->data.non_resident.data_size =
			cpu_to_sle64(i_size_read(vol->mft_ino));
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	/* Ensure the changes make it to disk. */
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(mft_ni);
	read_lock_irqsave(&mft_ni->size_lock, flags);
	ntfs_debug("Status of mft data after mft record initialization: "
			"allocated_size 0x%llx, data_size 0x%llx, "
			"initialized_size 0x%llx.",
			(long long)mft_ni->allocated_size,
			(long long)i_size_read(vol->mft_ino),
			(long long)mft_ni->initialized_size);
	BUG_ON(i_size_read(vol->mft_ino) > mft_ni->allocated_size);
	BUG_ON(mft_ni->initialized_size > i_size_read(vol->mft_ino));
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
mft_rec_already_initialized:
	/*
	 * We can finally drop the mft bitmap lock as the mft data attribute
	 * has been fully updated.  The only disparity left is that the
	 * allocated mft record still needs to be marked as in use to match the
	 * set bit in the mft bitmap but this is actually not a problem since
	 * this mft record is not referenced from anywhere yet and the fact
	 * that it is allocated in the mft bitmap means that no-one will try to
	 * allocate it either.
	 */
	up_write(&vol->mftbmp_lock);
	/*
	 * We now have allocated and initialized the mft record.  Calculate the
	 * index of and the offset within the page cache page the record is in.
	 */
	index = bit << vol->mft_record_size_bits >> PAGE_CACHE_SHIFT;
	ofs = (bit << vol->mft_record_size_bits) & ~PAGE_CACHE_MASK;
	/* Read, map, and pin the page containing the mft record. */
	page = ntfs_map_page(vol->mft_ino->i_mapping, index);
	if (IS_ERR(page)) {
		ntfs_error(vol->sb, "Failed to map page containing allocated "
				"mft record 0x%llx.", (long long)bit);
		err = PTR_ERR(page);
		goto undo_mftbmp_alloc;
	}
	lock_page(page);
	BUG_ON(!PageUptodate(page));
	ClearPageUptodate(page);
	m = (MFT_RECORD*)((u8*)page_address(page) + ofs);
	/* If we just formatted the mft record no need to do it again. */
	if (!record_formatted) {
		/* Sanity check that the mft record is really not in use. */
		if (ntfs_is_file_record(m->magic) &&
				(m->flags & MFT_RECORD_IN_USE)) {
			ntfs_error(vol->sb, "Mft record 0x%llx was marked "
					"free in mft bitmap but is marked "
					"used itself.  Corrupt filesystem.  "
					"Unmount and run chkdsk.",
					(long long)bit);
			err = -EIO;
			SetPageUptodate(page);
			unlock_page(page);
			ntfs_unmap_page(page);
			NVolSetErrors(vol);
			goto undo_mftbmp_alloc;
		}
		/*
		 * We need to (re-)format the mft record, preserving the
		 * sequence number if it is not zero as well as the update
		 * sequence number if it is not zero or -1 (0xffff).  This
		 * means we do not need to care whether or not something went
		 * wrong with the previous mft record.
		 */
		seq_no = m->sequence_number;
		usn = *(le16*)((u8*)m + le16_to_cpu(m->usa_ofs));
		err = ntfs_mft_record_layout(vol, bit, m);
		if (unlikely(err)) {
			ntfs_error(vol->sb, "Failed to layout allocated mft "
					"record 0x%llx.", (long long)bit);
			SetPageUptodate(page);
			unlock_page(page);
			ntfs_unmap_page(page);
			goto undo_mftbmp_alloc;
		}
		if (seq_no)
			m->sequence_number = seq_no;
		if (usn && le16_to_cpu(usn) != 0xffff)
			*(le16*)((u8*)m + le16_to_cpu(m->usa_ofs)) = usn;
	}
	/* Set the mft record itself in use. */
	m->flags |= MFT_RECORD_IN_USE;
	if (S_ISDIR(mode))
		m->flags |= MFT_RECORD_IS_DIRECTORY;
	flush_dcache_page(page);
	SetPageUptodate(page);
	if (base_ni) {
		MFT_RECORD *m_tmp;

		/*
		 * Setup the base mft record in the extent mft record.  This
		 * completes initialization of the allocated extent mft record
		 * and we can simply use it with map_extent_mft_record().
		 */
		m->base_mft_record = MK_LE_MREF(base_ni->mft_no,
				base_ni->seq_no);
		/*
		 * Allocate an extent inode structure for the new mft record,
		 * attach it to the base inode @base_ni and map, pin, and lock
		 * its, i.e. the allocated, mft record.
		 */
		m_tmp = map_extent_mft_record(base_ni, bit, &ni);
		if (IS_ERR(m_tmp)) {
			ntfs_error(vol->sb, "Failed to map allocated extent "
					"mft record 0x%llx.", (long long)bit);
			err = PTR_ERR(m_tmp);
			/* Set the mft record itself not in use. */
			m->flags &= cpu_to_le16(
					~le16_to_cpu(MFT_RECORD_IN_USE));
			flush_dcache_page(page);
			/* Make sure the mft record is written out to disk. */
			mark_ntfs_record_dirty(page, ofs);
			unlock_page(page);
			ntfs_unmap_page(page);
			goto undo_mftbmp_alloc;
		}
		BUG_ON(m != m_tmp);
		/*
		 * Make sure the allocated mft record is written out to disk.
		 * No need to set the inode dirty because the caller is going
		 * to do that anyway after finishing with the new extent mft
		 * record (e.g. at a minimum a new attribute will be added to
		 * the mft record.
		 */
		mark_ntfs_record_dirty(page, ofs);
		unlock_page(page);
		/*
		 * Need to unmap the page since map_extent_mft_record() mapped
		 * it as well so we have it mapped twice at the moment.
		 */
		ntfs_unmap_page(page);
	} else {
		/*
		 * Allocate a new VFS inode and set it up.  NOTE: @vi->i_nlink
		 * is set to 1 but the mft record->link_count is 0.  The caller
		 * needs to bear this in mind.
		 */
		vi = new_inode(vol->sb);
		if (unlikely(!vi)) {
			err = -ENOMEM;
			/* Set the mft record itself not in use. */
			m->flags &= cpu_to_le16(
					~le16_to_cpu(MFT_RECORD_IN_USE));
			flush_dcache_page(page);
			/* Make sure the mft record is written out to disk. */
			mark_ntfs_record_dirty(page, ofs);
			unlock_page(page);
			ntfs_unmap_page(page);
			goto undo_mftbmp_alloc;
		}
		vi->i_ino = bit;
		/*
		 * This is for checking whether an inode has changed w.r.t. a
		 * file so that the file can be updated if necessary (compare
		 * with f_version).
		 */
		vi->i_version = 1;

		/* The owner and group come from the ntfs volume. */
		vi->i_uid = vol->uid;
		vi->i_gid = vol->gid;

		/* Initialize the ntfs specific part of @vi. */
		ntfs_init_big_inode(vi);
		ni = NTFS_I(vi);
		/*
		 * Set the appropriate mode, attribute type, and name.  For
		 * directories, also setup the index values to the defaults.
		 */
		if (S_ISDIR(mode)) {
			vi->i_mode = S_IFDIR | S_IRWXUGO;
			vi->i_mode &= ~vol->dmask;

			NInoSetMstProtected(ni);
			ni->type = AT_INDEX_ALLOCATION;
			ni->name = I30;
			ni->name_len = 4;

			ni->itype.index.block_size = 4096;
			ni->itype.index.block_size_bits = ntfs_ffs(4096) - 1;
			ni->itype.index.collation_rule = COLLATION_FILE_NAME;
			if (vol->cluster_size <= ni->itype.index.block_size) {
				ni->itype.index.vcn_size = vol->cluster_size;
				ni->itype.index.vcn_size_bits =
						vol->cluster_size_bits;
			} else {
				ni->itype.index.vcn_size = vol->sector_size;
				ni->itype.index.vcn_size_bits =
						vol->sector_size_bits;
			}
		} else {
			vi->i_mode = S_IFREG | S_IRWXUGO;
			vi->i_mode &= ~vol->fmask;

			ni->type = AT_DATA;
			ni->name = NULL;
			ni->name_len = 0;
		}
		if (IS_RDONLY(vi))
			vi->i_mode &= ~S_IWUGO;

		/* Set the inode times to the current time. */
		vi->i_atime = vi->i_mtime = vi->i_ctime =
			current_fs_time(vi->i_sb);
		/*
		 * Set the file size to 0, the ntfs inode sizes are set to 0 by
		 * the call to ntfs_init_big_inode() below.
		 */
		vi->i_size = 0;
		vi->i_blocks = 0;

		/* Set the sequence number. */
		vi->i_generation = ni->seq_no = le16_to_cpu(m->sequence_number);
		/*
		 * Manually map, pin, and lock the mft record as we already
		 * have its page mapped and it is very easy to do.
		 */
		atomic_inc(&ni->count);
		mutex_lock(&ni->mrec_lock);
		ni->page = page;
		ni->page_ofs = ofs;
		/*
		 * Make sure the allocated mft record is written out to disk.
		 * NOTE: We do not set the ntfs inode dirty because this would
		 * fail in ntfs_write_inode() because the inode does not have a
		 * standard information attribute yet.  Also, there is no need
		 * to set the inode dirty because the caller is going to do
		 * that anyway after finishing with the new mft record (e.g. at
		 * a minimum some new attributes will be added to the mft
		 * record.
		 */
		mark_ntfs_record_dirty(page, ofs);
		unlock_page(page);

		/* Add the inode to the inode hash for the superblock. */
		insert_inode_hash(vi);

		/* Update the default mft allocation position. */
		vol->mft_data_pos = bit + 1;
	}
	/*
	 * Return the opened, allocated inode of the allocated mft record as
	 * well as the mapped, pinned, and locked mft record.
	 */
	ntfs_debug("Returning opened, allocated %sinode 0x%llx.",
			base_ni ? "extent " : "", (long long)bit);
	*mrec = m;
	return ni;
undo_data_init:
	write_lock_irqsave(&mft_ni->size_lock, flags);
	mft_ni->initialized_size = old_data_initialized;
	i_size_write(vol->mft_ino, old_data_size);
	write_unlock_irqrestore(&mft_ni->size_lock, flags);
	goto undo_mftbmp_alloc_nolock;
undo_mftbmp_alloc:
	down_write(&vol->mftbmp_lock);
undo_mftbmp_alloc_nolock:
	if (ntfs_bitmap_clear_bit(vol->mftbmp_ino, bit)) {
		ntfs_error(vol->sb, "Failed to clear bit in mft bitmap.%s", es);
		NVolSetErrors(vol);
	}
	up_write(&vol->mftbmp_lock);
err_out:
	return ERR_PTR(err);
max_err_out:
	ntfs_warning(vol->sb, "Cannot allocate mft record because the maximum "
			"number of inodes (2^32) has already been reached.");
	up_write(&vol->mftbmp_lock);
	return ERR_PTR(-ENOSPC);
}

/**
 * ntfs_extent_mft_record_free - free an extent mft record on an ntfs volume
 * @ni:		ntfs inode of the mapped extent mft record to free
 * @m:		mapped extent mft record of the ntfs inode @ni
 *
 * Free the mapped extent mft record @m of the extent ntfs inode @ni.
 *
 * Note that this function unmaps the mft record and closes and destroys @ni
 * internally and hence you cannot use either @ni nor @m any more after this
 * function returns success.
 *
 * On success return 0 and on error return -errno.  @ni and @m are still valid
 * in this case and have not been freed.
 *
 * For some errors an error message is displayed and the success code 0 is
 * returned and the volume is then left dirty on umount.  This makes sense in
 * case we could not rollback the changes that were already done since the
 * caller no longer wants to reference this mft record so it does not matter to
 * the caller if something is wrong with it as long as it is properly detached
 * from the base inode.
 */
int ntfs_extent_mft_record_free(ntfs_inode *ni, MFT_RECORD *m)
{
	unsigned long mft_no = ni->mft_no;
	ntfs_volume *vol = ni->vol;
	ntfs_inode *base_ni;
	ntfs_inode **extent_nis;
	int i, err;
	le16 old_seq_no;
	u16 seq_no;
	
	BUG_ON(NInoAttr(ni));
	BUG_ON(ni->nr_extents != -1);

	mutex_lock(&ni->extent_lock);
	base_ni = ni->ext.base_ntfs_ino;
	mutex_unlock(&ni->extent_lock);

	BUG_ON(base_ni->nr_extents <= 0);

	ntfs_debug("Entering for extent inode 0x%lx, base inode 0x%lx.\n",
			mft_no, base_ni->mft_no);

	mutex_lock(&base_ni->extent_lock);

	/* Make sure we are holding the only reference to the extent inode. */
	if (atomic_read(&ni->count) > 2) {
		ntfs_error(vol->sb, "Tried to free busy extent inode 0x%lx, "
				"not freeing.", base_ni->mft_no);
		mutex_unlock(&base_ni->extent_lock);
		return -EBUSY;
	}

	/* Dissociate the ntfs inode from the base inode. */
	extent_nis = base_ni->ext.extent_ntfs_inos;
	err = -ENOENT;
	for (i = 0; i < base_ni->nr_extents; i++) {
		if (ni != extent_nis[i])
			continue;
		extent_nis += i;
		base_ni->nr_extents--;
		memmove(extent_nis, extent_nis + 1, (base_ni->nr_extents - i) *
				sizeof(ntfs_inode*));
		err = 0;
		break;
	}

	mutex_unlock(&base_ni->extent_lock);

	if (unlikely(err)) {
		ntfs_error(vol->sb, "Extent inode 0x%lx is not attached to "
				"its base inode 0x%lx.", mft_no,
				base_ni->mft_no);
		BUG();
	}

	/*
	 * The extent inode is no longer attached to the base inode so no one
	 * can get a reference to it any more.
	 */

	/* Mark the mft record as not in use. */
	m->flags &= ~MFT_RECORD_IN_USE;

	/* Increment the sequence number, skipping zero, if it is not zero. */
	old_seq_no = m->sequence_number;
	seq_no = le16_to_cpu(old_seq_no);
	if (seq_no == 0xffff)
		seq_no = 1;
	else if (seq_no)
		seq_no++;
	m->sequence_number = cpu_to_le16(seq_no);

	/*
	 * Set the ntfs inode dirty and write it out.  We do not need to worry
	 * about the base inode here since whatever caused the extent mft
	 * record to be freed is guaranteed to do it already.
	 */
	NInoSetDirty(ni);
	err = write_mft_record(ni, m, 0);
	if (unlikely(err)) {
		ntfs_error(vol->sb, "Failed to write mft record 0x%lx, not "
				"freeing.", mft_no);
		goto rollback;
	}
rollback_error:
	/* Unmap and throw away the now freed extent inode. */
	unmap_extent_mft_record(ni);
	ntfs_clear_extent_inode(ni);

	/* Clear the bit in the $MFT/$BITMAP corresponding to this record. */
	down_write(&vol->mftbmp_lock);
	err = ntfs_bitmap_clear_bit(vol->mftbmp_ino, mft_no);
	up_write(&vol->mftbmp_lock);
	if (unlikely(err)) {
		/*
		 * The extent inode is gone but we failed to deallocate it in
		 * the mft bitmap.  Just emit a warning and leave the volume
		 * dirty on umount.
		 */
		ntfs_error(vol->sb, "Failed to clear bit in mft bitmap.%s", es);
		NVolSetErrors(vol);
	}
	return 0;
rollback:
	/* Rollback what we did... */
	mutex_lock(&base_ni->extent_lock);
	extent_nis = base_ni->ext.extent_ntfs_inos;
	if (!(base_ni->nr_extents & 3)) {
		int new_size = (base_ni->nr_extents + 4) * sizeof(ntfs_inode*);

		extent_nis = kmalloc(new_size, GFP_NOFS);
		if (unlikely(!extent_nis)) {
			ntfs_error(vol->sb, "Failed to allocate internal "
					"buffer during rollback.%s", es);
			mutex_unlock(&base_ni->extent_lock);
			NVolSetErrors(vol);
			goto rollback_error;
		}
		if (base_ni->nr_extents) {
			BUG_ON(!base_ni->ext.extent_ntfs_inos);
			memcpy(extent_nis, base_ni->ext.extent_ntfs_inos,
					new_size - 4 * sizeof(ntfs_inode*));
			kfree(base_ni->ext.extent_ntfs_inos);
		}
		base_ni->ext.extent_ntfs_inos = extent_nis;
	}
	m->flags |= MFT_RECORD_IN_USE;
	m->sequence_number = old_seq_no;
	extent_nis[base_ni->nr_extents++] = ni;
	mutex_unlock(&base_ni->extent_lock);
	mark_mft_record_dirty(ni);
	return err;
}
#endif /* NTFS_RW */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/mft.c */
/************************************************************/
/*
 * mst.c - NTFS multi sector transfer protection handling code. Part of the
 *	   Linux-NTFS project.
 *
 * Copyright (c) 2001-2004 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include "ntfs.h"

/**
 * post_read_mst_fixup - deprotect multi sector transfer protected data
 * @b:		pointer to the data to deprotect
 * @size:	size in bytes of @b
 *
 * Perform the necessary post read multi sector transfer fixup and detect the
 * presence of incomplete multi sector transfers. - In that case, overwrite the
 * magic of the ntfs record header being processed with "BAAD" (in memory only!)
 * and abort processing.
 *
 * Return 0 on success and -EINVAL on error ("BAAD" magic will be present).
 *
 * NOTE: We consider the absence / invalidity of an update sequence array to
 * mean that the structure is not protected at all and hence doesn't need to
 * be fixed up. Thus, we return success and not failure in this case. This is
 * in contrast to pre_write_mst_fixup(), see below.
 */
int post_read_mst_fixup(NTFS_RECORD *b, const u32 size)
{
	u16 usa_ofs, usa_count, usn;
	u16 *usa_pos, *data_pos;

	/* Setup the variables. */
	usa_ofs = le16_to_cpu(b->usa_ofs);
	/* Decrement usa_count to get number of fixups. */
	usa_count = le16_to_cpu(b->usa_count) - 1;
	/* Size and alignment checks. */
	if ( size & (NTFS_BLOCK_SIZE - 1)	||
	     usa_ofs & 1			||
	     usa_ofs + (usa_count * 2) > size	||
	     (size >> NTFS_BLOCK_SIZE_BITS) != usa_count)
		return 0;
	/* Position of usn in update sequence array. */
	usa_pos = (u16*)b + usa_ofs/sizeof(u16);
	/*
	 * The update sequence number which has to be equal to each of the
	 * u16 values before they are fixed up. Note no need to care for
	 * endianness since we are comparing and moving data for on disk
	 * structures which means the data is consistent. - If it is
	 * consistenty the wrong endianness it doesn't make any difference.
	 */
	usn = *usa_pos;
	/*
	 * Position in protected data of first u16 that needs fixing up.
	 */
	data_pos = (u16*)b + NTFS_BLOCK_SIZE/sizeof(u16) - 1;
	/*
	 * Check for incomplete multi sector transfer(s).
	 */
	while (usa_count--) {
		if (*data_pos != usn) {
			/*
			 * Incomplete multi sector transfer detected! )-:
			 * Set the magic to "BAAD" and return failure.
			 * Note that magic_BAAD is already converted to le32.
			 */
			b->magic = magic_BAAD;
			return -EINVAL;
		}
		data_pos += NTFS_BLOCK_SIZE/sizeof(u16);
	}
	/* Re-setup the variables. */
	usa_count = le16_to_cpu(b->usa_count) - 1;
	data_pos = (u16*)b + NTFS_BLOCK_SIZE/sizeof(u16) - 1;
	/* Fixup all sectors. */
	while (usa_count--) {
		/*
		 * Increment position in usa and restore original data from
		 * the usa into the data buffer.
		 */
		*data_pos = *(++usa_pos);
		/* Increment position in data as well. */
		data_pos += NTFS_BLOCK_SIZE/sizeof(u16);
	}
	return 0;
}

/**
 * pre_write_mst_fixup - apply multi sector transfer protection
 * @b:		pointer to the data to protect
 * @size:	size in bytes of @b
 *
 * Perform the necessary pre write multi sector transfer fixup on the data
 * pointer to by @b of @size.
 *
 * Return 0 if fixup applied (success) or -EINVAL if no fixup was performed
 * (assumed not needed). This is in contrast to post_read_mst_fixup() above.
 *
 * NOTE: We consider the absence / invalidity of an update sequence array to
 * mean that the structure is not subject to protection and hence doesn't need
 * to be fixed up. This means that you have to create a valid update sequence
 * array header in the ntfs record before calling this function, otherwise it
 * will fail (the header needs to contain the position of the update sequence
 * array together with the number of elements in the array). You also need to
 * initialise the update sequence number before calling this function
 * otherwise a random word will be used (whatever was in the record at that
 * position at that time).
 */
int pre_write_mst_fixup(NTFS_RECORD *b, const u32 size)
{
	le16 *usa_pos, *data_pos;
	u16 usa_ofs, usa_count, usn;
	le16 le_usn;

	/* Sanity check + only fixup if it makes sense. */
	if (!b || ntfs_is_baad_record(b->magic) ||
			ntfs_is_hole_record(b->magic))
		return -EINVAL;
	/* Setup the variables. */
	usa_ofs = le16_to_cpu(b->usa_ofs);
	/* Decrement usa_count to get number of fixups. */
	usa_count = le16_to_cpu(b->usa_count) - 1;
	/* Size and alignment checks. */
	if ( size & (NTFS_BLOCK_SIZE - 1)	||
	     usa_ofs & 1			||
	     usa_ofs + (usa_count * 2) > size	||
	     (size >> NTFS_BLOCK_SIZE_BITS) != usa_count)
		return -EINVAL;
	/* Position of usn in update sequence array. */
	usa_pos = (le16*)((u8*)b + usa_ofs);
	/*
	 * Cyclically increment the update sequence number
	 * (skipping 0 and -1, i.e. 0xffff).
	 */
	usn = le16_to_cpup(usa_pos) + 1;
	if (usn == 0xffff || !usn)
		usn = 1;
	le_usn = cpu_to_le16(usn);
	*usa_pos = le_usn;
	/* Position in data of first u16 that needs fixing up. */
	data_pos = (le16*)b + NTFS_BLOCK_SIZE/sizeof(le16) - 1;
	/* Fixup all sectors. */
	while (usa_count--) {
		/*
		 * Increment the position in the usa and save the
		 * original data from the data buffer into the usa.
		 */
		*(++usa_pos) = *data_pos;
		/* Apply fixup to data. */
		*data_pos = le_usn;
		/* Increment position in data as well. */
		data_pos += NTFS_BLOCK_SIZE/sizeof(le16);
	}
	return 0;
}

/**
 * post_write_mst_fixup - fast deprotect multi sector transfer protected data
 * @b:		pointer to the data to deprotect
 *
 * Perform the necessary post write multi sector transfer fixup, not checking
 * for any errors, because we assume we have just used pre_write_mst_fixup(),
 * thus the data will be fine or we would never have gotten here.
 */
void post_write_mst_fixup(NTFS_RECORD *b)
{
	le16 *usa_pos, *data_pos;

	u16 usa_ofs = le16_to_cpu(b->usa_ofs);
	u16 usa_count = le16_to_cpu(b->usa_count) - 1;

	/* Position of usn in update sequence array. */
	usa_pos = (le16*)b + usa_ofs/sizeof(le16);

	/* Position in protected data of first u16 that needs fixing up. */
	data_pos = (le16*)b + NTFS_BLOCK_SIZE/sizeof(le16) - 1;

	/* Fixup all sectors. */
	while (usa_count--) {
		/*
		 * Increment position in usa and restore original data from
		 * the usa into the data buffer.
		 */
		*data_pos = *(++usa_pos);

		/* Increment position in data as well. */
		data_pos += NTFS_BLOCK_SIZE/sizeof(le16);
	}
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/mst.c */
/************************************************************/
/*
 * namei.c - NTFS kernel directory inode operations. Part of the Linux-NTFS
 *	     project.
 *
 * Copyright (c) 2001-2006 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/dcache.h>
#include <linux/exportfs.h>
#include <linux/security.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

// #include "attrib.h"
// #include "debug.h"
// #include "dir.h"
// #include "mft.h"
// #include "ntfs.h"

/**
 * ntfs_lookup - find the inode represented by a dentry in a directory inode
 * @dir_ino:	directory inode in which to look for the inode
 * @dent:	dentry representing the inode to look for
 * @nd:		lookup nameidata
 *
 * In short, ntfs_lookup() looks for the inode represented by the dentry @dent
 * in the directory inode @dir_ino and if found attaches the inode to the
 * dentry @dent.
 *
 * In more detail, the dentry @dent specifies which inode to look for by
 * supplying the name of the inode in @dent->d_name.name. ntfs_lookup()
 * converts the name to Unicode and walks the contents of the directory inode
 * @dir_ino looking for the converted Unicode name. If the name is found in the
 * directory, the corresponding inode is loaded by calling ntfs_iget() on its
 * inode number and the inode is associated with the dentry @dent via a call to
 * d_splice_alias().
 *
 * If the name is not found in the directory, a NULL inode is inserted into the
 * dentry @dent via a call to d_add(). The dentry is then termed a negative
 * dentry.
 *
 * Only if an actual error occurs, do we return an error via ERR_PTR().
 *
 * In order to handle the case insensitivity issues of NTFS with regards to the
 * dcache and the dcache requiring only one dentry per directory, we deal with
 * dentry aliases that only differ in case in ->ntfs_lookup() while maintaining
 * a case sensitive dcache. This means that we get the full benefit of dcache
 * speed when the file/directory is looked up with the same case as returned by
 * ->ntfs_readdir() but that a lookup for any other case (or for the short file
 * name) will not find anything in dcache and will enter ->ntfs_lookup()
 * instead, where we search the directory for a fully matching file name
 * (including case) and if that is not found, we search for a file name that
 * matches with different case and if that has non-POSIX semantics we return
 * that. We actually do only one search (case sensitive) and keep tabs on
 * whether we have found a case insensitive match in the process.
 *
 * To simplify matters for us, we do not treat the short vs long filenames as
 * two hard links but instead if the lookup matches a short filename, we
 * return the dentry for the corresponding long filename instead.
 *
 * There are three cases we need to distinguish here:
 *
 * 1) @dent perfectly matches (i.e. including case) a directory entry with a
 *    file name in the WIN32 or POSIX namespaces. In this case
 *    ntfs_lookup_inode_by_name() will return with name set to NULL and we
 *    just d_splice_alias() @dent.
 * 2) @dent matches (not including case) a directory entry with a file name in
 *    the WIN32 namespace. In this case ntfs_lookup_inode_by_name() will return
 *    with name set to point to a kmalloc()ed ntfs_name structure containing
 *    the properly cased little endian Unicode name. We convert the name to the
 *    current NLS code page, search if a dentry with this name already exists
 *    and if so return that instead of @dent.  At this point things are
 *    complicated by the possibility of 'disconnected' dentries due to NFS
 *    which we deal with appropriately (see the code comments).  The VFS will
 *    then destroy the old @dent and use the one we returned.  If a dentry is
 *    not found, we allocate a new one, d_splice_alias() it, and return it as
 *    above.
 * 3) @dent matches either perfectly or not (i.e. we don't care about case) a
 *    directory entry with a file name in the DOS namespace. In this case
 *    ntfs_lookup_inode_by_name() will return with name set to point to a
 *    kmalloc()ed ntfs_name structure containing the mft reference (cpu endian)
 *    of the inode. We use the mft reference to read the inode and to find the
 *    file name in the WIN32 namespace corresponding to the matched short file
 *    name. We then convert the name to the current NLS code page, and proceed
 *    searching for a dentry with this name, etc, as in case 2), above.
 *
 * Locking: Caller must hold i_mutex on the directory.
 */
static struct dentry *ntfs_lookup(struct inode *dir_ino, struct dentry *dent,
		unsigned int flags)
{
	ntfs_volume *vol = NTFS_SB(dir_ino->i_sb);
	struct inode *dent_inode;
	ntfschar *uname;
	ntfs_name *name = NULL;
	MFT_REF mref;
	unsigned long dent_ino;
	int uname_len;

	ntfs_debug("Looking up %pd in directory inode 0x%lx.",
			dent, dir_ino->i_ino);
	/* Convert the name of the dentry to Unicode. */
	uname_len = ntfs_nlstoucs(vol, dent->d_name.name, dent->d_name.len,
			&uname);
	if (uname_len < 0) {
		if (uname_len != -ENAMETOOLONG)
			ntfs_error(vol->sb, "Failed to convert name to "
					"Unicode.");
		return ERR_PTR(uname_len);
	}
	mref = ntfs_lookup_inode_by_name(NTFS_I(dir_ino), uname, uname_len,
			&name);
	kmem_cache_free(ntfs_name_cache, uname);
	if (!IS_ERR_MREF(mref)) {
		dent_ino = MREF(mref);
		ntfs_debug("Found inode 0x%lx. Calling ntfs_iget.", dent_ino);
		dent_inode = ntfs_iget(vol->sb, dent_ino);
		if (likely(!IS_ERR(dent_inode))) {
			/* Consistency check. */
			if (is_bad_inode(dent_inode) || MSEQNO(mref) ==
					NTFS_I(dent_inode)->seq_no ||
					dent_ino == FILE_MFT) {
				/* Perfect WIN32/POSIX match. -- Case 1. */
				if (!name) {
					ntfs_debug("Done.  (Case 1.)");
					return d_splice_alias(dent_inode, dent);
				}
				/*
				 * We are too indented.  Handle imperfect
				 * matches and short file names further below.
				 */
				goto handle_name;
			}
			ntfs_error(vol->sb, "Found stale reference to inode "
					"0x%lx (reference sequence number = "
					"0x%x, inode sequence number = 0x%x), "
					"returning -EIO. Run chkdsk.",
					dent_ino, MSEQNO(mref),
					NTFS_I(dent_inode)->seq_no);
			iput(dent_inode);
			dent_inode = ERR_PTR(-EIO);
		} else
			ntfs_error(vol->sb, "ntfs_iget(0x%lx) failed with "
					"error code %li.", dent_ino,
					PTR_ERR(dent_inode));
		kfree(name);
		/* Return the error code. */
		return (struct dentry *)dent_inode;
	}
	/* It is guaranteed that @name is no longer allocated at this point. */
	if (MREF_ERR(mref) == -ENOENT) {
		ntfs_debug("Entry was not found, adding negative dentry.");
		/* The dcache will handle negative entries. */
		d_add(dent, NULL);
		ntfs_debug("Done.");
		return NULL;
	}
	ntfs_error(vol->sb, "ntfs_lookup_ino_by_name() failed with error "
			"code %i.", -MREF_ERR(mref));
	return ERR_PTR(MREF_ERR(mref));
	// TODO: Consider moving this lot to a separate function! (AIA)
handle_name:
   {
	MFT_RECORD *m;
	ntfs_attr_search_ctx *ctx;
	ntfs_inode *ni = NTFS_I(dent_inode);
	int err;
	struct qstr nls_name;

	nls_name.name = NULL;
	if (name->type != FILE_NAME_DOS) {			/* Case 2. */
		ntfs_debug("Case 2.");
		nls_name.len = (unsigned)ntfs_ucstonls(vol,
				(ntfschar*)&name->name, name->len,
				(unsigned char**)&nls_name.name, 0);
		kfree(name);
	} else /* if (name->type == FILE_NAME_DOS) */ {		/* Case 3. */
		FILE_NAME_ATTR *fn;

		ntfs_debug("Case 3.");
		kfree(name);

		/* Find the WIN32 name corresponding to the matched DOS name. */
		ni = NTFS_I(dent_inode);
		m = map_mft_record(ni);
		if (IS_ERR(m)) {
			err = PTR_ERR(m);
			m = NULL;
			ctx = NULL;
			goto err_out;
		}
		ctx = ntfs_attr_get_search_ctx(ni, m);
		if (unlikely(!ctx)) {
			err = -ENOMEM;
			goto err_out;
		}
		do {
			ATTR_RECORD *a;
			u32 val_len;

			err = ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, 0, 0,
					NULL, 0, ctx);
			if (unlikely(err)) {
				ntfs_error(vol->sb, "Inode corrupt: No WIN32 "
						"namespace counterpart to DOS "
						"file name. Run chkdsk.");
				if (err == -ENOENT)
					err = -EIO;
				goto err_out;
			}
			/* Consistency checks. */
			a = ctx->attr;
			if (a->non_resident || a->flags)
				goto eio_err_out;
			val_len = le32_to_cpu(a->data.resident.value_length);
			if (le16_to_cpu(a->data.resident.value_offset) +
					val_len > le32_to_cpu(a->length))
				goto eio_err_out;
			fn = (FILE_NAME_ATTR*)((u8*)ctx->attr + le16_to_cpu(
					ctx->attr->data.resident.value_offset));
			if ((u32)(fn->file_name_length * sizeof(ntfschar) +
					sizeof(FILE_NAME_ATTR)) > val_len)
				goto eio_err_out;
		} while (fn->file_name_type != FILE_NAME_WIN32);

		/* Convert the found WIN32 name to current NLS code page. */
		nls_name.len = (unsigned)ntfs_ucstonls(vol,
				(ntfschar*)&fn->file_name, fn->file_name_length,
				(unsigned char**)&nls_name.name, 0);

		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(ni);
	}
	m = NULL;
	ctx = NULL;

	/* Check if a conversion error occurred. */
	if ((signed)nls_name.len < 0) {
		err = (signed)nls_name.len;
		goto err_out;
	}
	nls_name.hash = full_name_hash(nls_name.name, nls_name.len);

	dent = d_add_ci(dent, dent_inode, &nls_name);
	kfree(nls_name.name);
	return dent;

eio_err_out:
	ntfs_error(vol->sb, "Illegal file name attribute. Run chkdsk.");
	err = -EIO;
err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	if (m)
		unmap_mft_record(ni);
	iput(dent_inode);
	ntfs_error(vol->sb, "Failed, returning error code %i.", err);
	return ERR_PTR(err);
   }
}

/**
 * Inode operations for directories.
 */
const struct inode_operations ntfs_dir_inode_ops = {
	.lookup	= ntfs_lookup,	/* VFS: Lookup directory. */
};

/**
 * ntfs_get_parent - find the dentry of the parent of a given directory dentry
 * @child_dent:		dentry of the directory whose parent directory to find
 *
 * Find the dentry for the parent directory of the directory specified by the
 * dentry @child_dent.  This function is called from
 * fs/exportfs/expfs.c::find_exported_dentry() which in turn is called from the
 * default ->decode_fh() which is export_decode_fh() in the same file.
 *
 * The code is based on the ext3 ->get_parent() implementation found in
 * fs/ext3/namei.c::ext3_get_parent().
 *
 * Note: ntfs_get_parent() is called with @child_dent->d_inode->i_mutex down.
 *
 * Return the dentry of the parent directory on success or the error code on
 * error (IS_ERR() is true).
 */
static struct dentry *ntfs_get_parent(struct dentry *child_dent)
{
	struct inode *vi = child_dent->d_inode;
	ntfs_inode *ni = NTFS_I(vi);
	MFT_RECORD *mrec;
	ntfs_attr_search_ctx *ctx;
	ATTR_RECORD *attr;
	FILE_NAME_ATTR *fn;
	unsigned long parent_ino;
	int err;

	ntfs_debug("Entering for inode 0x%lx.", vi->i_ino);
	/* Get the mft record of the inode belonging to the child dentry. */
	mrec = map_mft_record(ni);
	if (IS_ERR(mrec))
		return (struct dentry *)mrec;
	/* Find the first file name attribute in the mft record. */
	ctx = ntfs_attr_get_search_ctx(ni, mrec);
	if (unlikely(!ctx)) {
		unmap_mft_record(ni);
		return ERR_PTR(-ENOMEM);
	}
try_next:
	err = ntfs_attr_lookup(AT_FILE_NAME, NULL, 0, CASE_SENSITIVE, 0, NULL,
			0, ctx);
	if (unlikely(err)) {
		ntfs_attr_put_search_ctx(ctx);
		unmap_mft_record(ni);
		if (err == -ENOENT)
			ntfs_error(vi->i_sb, "Inode 0x%lx does not have a "
					"file name attribute.  Run chkdsk.",
					vi->i_ino);
		return ERR_PTR(err);
	}
	attr = ctx->attr;
	if (unlikely(attr->non_resident))
		goto try_next;
	fn = (FILE_NAME_ATTR *)((u8 *)attr +
			le16_to_cpu(attr->data.resident.value_offset));
	if (unlikely((u8 *)fn + le32_to_cpu(attr->data.resident.value_length) >
			(u8*)attr + le32_to_cpu(attr->length)))
		goto try_next;
	/* Get the inode number of the parent directory. */
	parent_ino = MREF_LE(fn->parent_directory);
	/* Release the search context and the mft record of the child. */
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(ni);

	return d_obtain_alias(ntfs_iget(vi->i_sb, parent_ino));
}

static struct inode *ntfs_nfs_get_inode(struct super_block *sb,
		u64 ino, u32 generation)
{
	struct inode *inode;

	inode = ntfs_iget(sb, ino);
	if (!IS_ERR(inode)) {
		if (is_bad_inode(inode) || inode->i_generation != generation) {
			iput(inode);
			inode = ERR_PTR(-ESTALE);
		}
	}

	return inode;
}

static struct dentry *ntfs_fh_to_dentry(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    ntfs_nfs_get_inode);
}

static struct dentry *ntfs_fh_to_parent(struct super_block *sb, struct fid *fid,
		int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    ntfs_nfs_get_inode);
}

/**
 * Export operations allowing NFS exporting of mounted NTFS partitions.
 *
 * We use the default ->encode_fh() for now.  Note that they
 * use 32 bits to store the inode number which is an unsigned long so on 64-bit
 * architectures is usually 64 bits so it would all fail horribly on huge
 * volumes.  I guess we need to define our own encode and decode fh functions
 * that store 64-bit inode numbers at some point but for now we will ignore the
 * problem...
 *
 * We also use the default ->get_name() helper (used by ->decode_fh() via
 * fs/exportfs/expfs.c::find_exported_dentry()) as that is completely fs
 * independent.
 *
 * The default ->get_parent() just returns -EACCES so we have to provide our
 * own and the default ->get_dentry() is incompatible with NTFS due to not
 * allowing the inode number 0 which is used in NTFS for the system file $MFT
 * and due to using iget() whereas NTFS needs ntfs_iget().
 */
const struct export_operations ntfs_export_ops = {
	.get_parent	= ntfs_get_parent,	/* Find the parent of a given
						   directory. */
	.fh_to_dentry	= ntfs_fh_to_dentry,
	.fh_to_parent	= ntfs_fh_to_parent,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/namei.c */
/************************************************************/
/**
 * runlist.c - NTFS runlist handling code.  Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2007 Anton Altaparmakov
 * Copyright (c) 2002-2005 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include "debug.h"
// #include "dir.h"
#include "endian.h"
// #include "malloc.h"
// #include "ntfs.h"
#include "../../inc/__fss.h"

/**
 * ntfs_rl_mm - runlist memmove
 *
 * It is up to the caller to serialize access to the runlist @base.
 */
static inline void ntfs_rl_mm(runlist_element *base, int dst, int src,
		int size)
{
	if (likely((dst != src) && (size > 0)))
		memmove(base + dst, base + src, size * sizeof(*base));
}

/**
 * ntfs_rl_mc - runlist memory copy
 *
 * It is up to the caller to serialize access to the runlists @dstbase and
 * @srcbase.
 */
static inline void ntfs_rl_mc(runlist_element *dstbase, int dst,
		runlist_element *srcbase, int src, int size)
{
	if (likely(size > 0))
		memcpy(dstbase + dst, srcbase + src, size * sizeof(*dstbase));
}

/**
 * ntfs_rl_realloc - Reallocate memory for runlists
 * @rl:		original runlist
 * @old_size:	number of runlist elements in the original runlist @rl
 * @new_size:	number of runlist elements we need space for
 *
 * As the runlists grow, more memory will be required.  To prevent the
 * kernel having to allocate and reallocate large numbers of small bits of
 * memory, this function returns an entire page of memory.
 *
 * It is up to the caller to serialize access to the runlist @rl.
 *
 * N.B.  If the new allocation doesn't require a different number of pages in
 *       memory, the function will return the original pointer.
 *
 * On success, return a pointer to the newly allocated, or recycled, memory.
 * On error, return -errno. The following error codes are defined:
 *	-ENOMEM	- Not enough memory to allocate runlist array.
 *	-EINVAL	- Invalid parameters were passed in.
 */
static inline runlist_element *ntfs_rl_realloc(runlist_element *rl,
		int old_size, int new_size)
{
	runlist_element *new_rl;

	old_size = PAGE_ALIGN(old_size * sizeof(*rl));
	new_size = PAGE_ALIGN(new_size * sizeof(*rl));
	if (old_size == new_size)
		return rl;

	new_rl = ntfs_malloc_nofs(new_size);
	if (unlikely(!new_rl))
		return ERR_PTR(-ENOMEM);

	if (likely(rl != NULL)) {
		if (unlikely(old_size > new_size))
			old_size = new_size;
		memcpy(new_rl, rl, old_size);
		ntfs_free(rl);
	}
	return new_rl;
}

/**
 * ntfs_rl_realloc_nofail - Reallocate memory for runlists
 * @rl:		original runlist
 * @old_size:	number of runlist elements in the original runlist @rl
 * @new_size:	number of runlist elements we need space for
 *
 * As the runlists grow, more memory will be required.  To prevent the
 * kernel having to allocate and reallocate large numbers of small bits of
 * memory, this function returns an entire page of memory.
 *
 * This function guarantees that the allocation will succeed.  It will sleep
 * for as long as it takes to complete the allocation.
 *
 * It is up to the caller to serialize access to the runlist @rl.
 *
 * N.B.  If the new allocation doesn't require a different number of pages in
 *       memory, the function will return the original pointer.
 *
 * On success, return a pointer to the newly allocated, or recycled, memory.
 * On error, return -errno. The following error codes are defined:
 *	-ENOMEM	- Not enough memory to allocate runlist array.
 *	-EINVAL	- Invalid parameters were passed in.
 */
static inline runlist_element *ntfs_rl_realloc_nofail(runlist_element *rl,
		int old_size, int new_size)
{
	runlist_element *new_rl;

	old_size = PAGE_ALIGN(old_size * sizeof(*rl));
	new_size = PAGE_ALIGN(new_size * sizeof(*rl));
	if (old_size == new_size)
		return rl;

	new_rl = ntfs_malloc_nofs_nofail(new_size);
	BUG_ON(!new_rl);

	if (likely(rl != NULL)) {
		if (unlikely(old_size > new_size))
			old_size = new_size;
		memcpy(new_rl, rl, old_size);
		ntfs_free(rl);
	}
	return new_rl;
}

/**
 * ntfs_are_rl_mergeable - test if two runlists can be joined together
 * @dst:	original runlist
 * @src:	new runlist to test for mergeability with @dst
 *
 * Test if two runlists can be joined together. For this, their VCNs and LCNs
 * must be adjacent.
 *
 * It is up to the caller to serialize access to the runlists @dst and @src.
 *
 * Return: true   Success, the runlists can be merged.
 *	   false  Failure, the runlists cannot be merged.
 */
static inline bool ntfs_are_rl_mergeable(runlist_element *dst,
		runlist_element *src)
{
	BUG_ON(!dst);
	BUG_ON(!src);

	/* We can merge unmapped regions even if they are misaligned. */
	if ((dst->lcn == LCN_RL_NOT_MAPPED) && (src->lcn == LCN_RL_NOT_MAPPED))
		return true;
	/* If the runs are misaligned, we cannot merge them. */
	if ((dst->vcn + dst->length) != src->vcn)
		return false;
	/* If both runs are non-sparse and contiguous, we can merge them. */
	if ((dst->lcn >= 0) && (src->lcn >= 0) &&
			((dst->lcn + dst->length) == src->lcn))
		return true;
	/* If we are merging two holes, we can merge them. */
	if ((dst->lcn == LCN_HOLE) && (src->lcn == LCN_HOLE))
		return true;
	/* Cannot merge. */
	return false;
}

/**
 * __ntfs_rl_merge - merge two runlists without testing if they can be merged
 * @dst:	original, destination runlist
 * @src:	new runlist to merge with @dst
 *
 * Merge the two runlists, writing into the destination runlist @dst. The
 * caller must make sure the runlists can be merged or this will corrupt the
 * destination runlist.
 *
 * It is up to the caller to serialize access to the runlists @dst and @src.
 */
static inline void __ntfs_rl_merge(runlist_element *dst, runlist_element *src)
{
	dst->length += src->length;
}

/**
 * ntfs_rl_append - append a runlist after a given element
 * @dst:	original runlist to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	runlist to be inserted into @dst
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	append the new runlist @src after this element in @dst
 *
 * Append the runlist @src after element @loc in @dst.  Merge the right end of
 * the new runlist, if necessary. Adjust the size of the hole before the
 * appended runlist.
 *
 * It is up to the caller to serialize access to the runlists @dst and @src.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return -errno. Both runlists are left unmodified. The following
 * error codes are defined:
 *	-ENOMEM	- Not enough memory to allocate runlist array.
 *	-EINVAL	- Invalid parameters were passed in.
 */
static inline runlist_element *ntfs_rl_append(runlist_element *dst,
		int dsize, runlist_element *src, int ssize, int loc)
{
	bool right = false;	/* Right end of @src needs merging. */
	int marker;		/* End of the inserted runs. */

	BUG_ON(!dst);
	BUG_ON(!src);

	/* First, check if the right hand end needs merging. */
	if ((loc + 1) < dsize)
		right = ntfs_are_rl_mergeable(src + ssize - 1, dst + loc + 1);

	/* Space required: @dst size + @src size, less one if we merged. */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize - right);
	if (IS_ERR(dst))
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original runlists.
	 */

	/* First, merge the right hand end, if necessary. */
	if (right)
		__ntfs_rl_merge(src + ssize - 1, dst + loc + 1);

	/* First run after the @src runs that have been inserted. */
	marker = loc + ssize + 1;

	/* Move the tail of @dst out of the way, then copy in @src. */
	ntfs_rl_mm(dst, marker, loc + 1 + right, dsize - (loc + 1 + right));
	ntfs_rl_mc(dst, loc + 1, src, 0, ssize);

	/* Adjust the size of the preceding hole. */
	dst[loc].length = dst[loc + 1].vcn - dst[loc].vcn;

	/* We may have changed the length of the file, so fix the end marker */
	if (dst[marker].lcn == LCN_ENOENT)
		dst[marker].vcn = dst[marker - 1].vcn + dst[marker - 1].length;

	return dst;
}

/**
 * ntfs_rl_insert - insert a runlist into another
 * @dst:	original runlist to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new runlist to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	insert the new runlist @src before this element in @dst
 *
 * Insert the runlist @src before element @loc in the runlist @dst. Merge the
 * left end of the new runlist, if necessary. Adjust the size of the hole
 * after the inserted runlist.
 *
 * It is up to the caller to serialize access to the runlists @dst and @src.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return -errno. Both runlists are left unmodified. The following
 * error codes are defined:
 *	-ENOMEM	- Not enough memory to allocate runlist array.
 *	-EINVAL	- Invalid parameters were passed in.
 */
static inline runlist_element *ntfs_rl_insert(runlist_element *dst,
		int dsize, runlist_element *src, int ssize, int loc)
{
	bool left = false;	/* Left end of @src needs merging. */
	bool disc = false;	/* Discontinuity between @dst and @src. */
	int marker;		/* End of the inserted runs. */

	BUG_ON(!dst);
	BUG_ON(!src);

	/*
	 * disc => Discontinuity between the end of @dst and the start of @src.
	 *	   This means we might need to insert a "not mapped" run.
	 */
	if (loc == 0)
		disc = (src[0].vcn > 0);
	else {
		s64 merged_length;

		left = ntfs_are_rl_mergeable(dst + loc - 1, src);

		merged_length = dst[loc - 1].length;
		if (left)
			merged_length += src->length;

		disc = (src[0].vcn > dst[loc - 1].vcn + merged_length);
	}
	/*
	 * Space required: @dst size + @src size, less one if we merged, plus
	 * one if there was a discontinuity.
	 */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize - left + disc);
	if (IS_ERR(dst))
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original runlist.
	 */
	if (left)
		__ntfs_rl_merge(dst + loc - 1, src);
	/*
	 * First run after the @src runs that have been inserted.
	 * Nominally,  @marker equals @loc + @ssize, i.e. location + number of
	 * runs in @src.  However, if @left, then the first run in @src has
	 * been merged with one in @dst.  And if @disc, then @dst and @src do
	 * not meet and we need an extra run to fill the gap.
	 */
	marker = loc + ssize - left + disc;

	/* Move the tail of @dst out of the way, then copy in @src. */
	ntfs_rl_mm(dst, marker, loc, dsize - loc);
	ntfs_rl_mc(dst, loc + disc, src, left, ssize - left);

	/* Adjust the VCN of the first run after the insertion... */
	dst[marker].vcn = dst[marker - 1].vcn + dst[marker - 1].length;
	/* ... and the length. */
	if (dst[marker].lcn == LCN_HOLE || dst[marker].lcn == LCN_RL_NOT_MAPPED)
		dst[marker].length = dst[marker + 1].vcn - dst[marker].vcn;

	/* Writing beyond the end of the file and there is a discontinuity. */
	if (disc) {
		if (loc > 0) {
			dst[loc].vcn = dst[loc - 1].vcn + dst[loc - 1].length;
			dst[loc].length = dst[loc + 1].vcn - dst[loc].vcn;
		} else {
			dst[loc].vcn = 0;
			dst[loc].length = dst[loc + 1].vcn;
		}
		dst[loc].lcn = LCN_RL_NOT_MAPPED;
	}
	return dst;
}

/**
 * ntfs_rl_replace - overwrite a runlist element with another runlist
 * @dst:	original runlist to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new runlist to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	index in runlist @dst to overwrite with @src
 *
 * Replace the runlist element @dst at @loc with @src. Merge the left and
 * right ends of the inserted runlist, if necessary.
 *
 * It is up to the caller to serialize access to the runlists @dst and @src.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return -errno. Both runlists are left unmodified. The following
 * error codes are defined:
 *	-ENOMEM	- Not enough memory to allocate runlist array.
 *	-EINVAL	- Invalid parameters were passed in.
 */
static inline runlist_element *ntfs_rl_replace(runlist_element *dst,
		int dsize, runlist_element *src, int ssize, int loc)
{
	signed delta;
	bool left = false;	/* Left end of @src needs merging. */
	bool right = false;	/* Right end of @src needs merging. */
	int tail;		/* Start of tail of @dst. */
	int marker;		/* End of the inserted runs. */

	BUG_ON(!dst);
	BUG_ON(!src);

	/* First, see if the left and right ends need merging. */
	if ((loc + 1) < dsize)
		right = ntfs_are_rl_mergeable(src + ssize - 1, dst + loc + 1);
	if (loc > 0)
		left = ntfs_are_rl_mergeable(dst + loc - 1, src);
	/*
	 * Allocate some space.  We will need less if the left, right, or both
	 * ends get merged.  The -1 accounts for the run being replaced.
	 */
	delta = ssize - 1 - left - right;
	if (delta > 0) {
		dst = ntfs_rl_realloc(dst, dsize, dsize + delta);
		if (IS_ERR(dst))
			return dst;
	}
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original runlists.
	 */

	/* First, merge the left and right ends, if necessary. */
	if (right)
		__ntfs_rl_merge(src + ssize - 1, dst + loc + 1);
	if (left)
		__ntfs_rl_merge(dst + loc - 1, src);
	/*
	 * Offset of the tail of @dst.  This needs to be moved out of the way
	 * to make space for the runs to be copied from @src, i.e. the first
	 * run of the tail of @dst.
	 * Nominally, @tail equals @loc + 1, i.e. location, skipping the
	 * replaced run.  However, if @right, then one of @dst's runs is
	 * already merged into @src.
	 */
	tail = loc + right + 1;
	/*
	 * First run after the @src runs that have been inserted, i.e. where
	 * the tail of @dst needs to be moved to.
	 * Nominally, @marker equals @loc + @ssize, i.e. location + number of
	 * runs in @src.  However, if @left, then the first run in @src has
	 * been merged with one in @dst.
	 */
	marker = loc + ssize - left;

	/* Move the tail of @dst out of the way, then copy in @src. */
	ntfs_rl_mm(dst, marker, tail, dsize - tail);
	ntfs_rl_mc(dst, loc, src, left, ssize - left);

	/* We may have changed the length of the file, so fix the end marker. */
	if (dsize - tail > 0 && dst[marker].lcn == LCN_ENOENT)
		dst[marker].vcn = dst[marker - 1].vcn + dst[marker - 1].length;
	return dst;
}

/**
 * ntfs_rl_split - insert a runlist into the centre of a hole
 * @dst:	original runlist to be worked on
 * @dsize:	number of elements in @dst (including end marker)
 * @src:	new runlist to be inserted
 * @ssize:	number of elements in @src (excluding end marker)
 * @loc:	index in runlist @dst at which to split and insert @src
 *
 * Split the runlist @dst at @loc into two and insert @new in between the two
 * fragments. No merging of runlists is necessary. Adjust the size of the
 * holes either side.
 *
 * It is up to the caller to serialize access to the runlists @dst and @src.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @dst and @src are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return -errno. Both runlists are left unmodified. The following
 * error codes are defined:
 *	-ENOMEM	- Not enough memory to allocate runlist array.
 *	-EINVAL	- Invalid parameters were passed in.
 */
static inline runlist_element *ntfs_rl_split(runlist_element *dst, int dsize,
		runlist_element *src, int ssize, int loc)
{
	BUG_ON(!dst);
	BUG_ON(!src);

	/* Space required: @dst size + @src size + one new hole. */
	dst = ntfs_rl_realloc(dst, dsize, dsize + ssize + 1);
	if (IS_ERR(dst))
		return dst;
	/*
	 * We are guaranteed to succeed from here so can start modifying the
	 * original runlists.
	 */

	/* Move the tail of @dst out of the way, then copy in @src. */
	ntfs_rl_mm(dst, loc + 1 + ssize, loc, dsize - loc);
	ntfs_rl_mc(dst, loc + 1, src, 0, ssize);

	/* Adjust the size of the holes either size of @src. */
	dst[loc].length		= dst[loc+1].vcn       - dst[loc].vcn;
	dst[loc+ssize+1].vcn    = dst[loc+ssize].vcn   + dst[loc+ssize].length;
	dst[loc+ssize+1].length = dst[loc+ssize+2].vcn - dst[loc+ssize+1].vcn;

	return dst;
}

/**
 * ntfs_runlists_merge - merge two runlists into one
 * @drl:	original runlist to be worked on
 * @srl:	new runlist to be merged into @drl
 *
 * First we sanity check the two runlists @srl and @drl to make sure that they
 * are sensible and can be merged. The runlist @srl must be either after the
 * runlist @drl or completely within a hole (or unmapped region) in @drl.
 *
 * It is up to the caller to serialize access to the runlists @drl and @srl.
 *
 * Merging of runlists is necessary in two cases:
 *   1. When attribute lists are used and a further extent is being mapped.
 *   2. When new clusters are allocated to fill a hole or extend a file.
 *
 * There are four possible ways @srl can be merged. It can:
 *	- be inserted at the beginning of a hole,
 *	- split the hole in two and be inserted between the two fragments,
 *	- be appended at the end of a hole, or it can
 *	- replace the whole hole.
 * It can also be appended to the end of the runlist, which is just a variant
 * of the insert case.
 *
 * On success, return a pointer to the new, combined, runlist. Note, both
 * runlists @drl and @srl are deallocated before returning so you cannot use
 * the pointers for anything any more. (Strictly speaking the returned runlist
 * may be the same as @dst but this is irrelevant.)
 *
 * On error, return -errno. Both runlists are left unmodified. The following
 * error codes are defined:
 *	-ENOMEM	- Not enough memory to allocate runlist array.
 *	-EINVAL	- Invalid parameters were passed in.
 *	-ERANGE	- The runlists overlap and cannot be merged.
 */
runlist_element *ntfs_runlists_merge(runlist_element *drl,
		runlist_element *srl)
{
	int di, si;		/* Current index into @[ds]rl. */
	int sstart;		/* First index with lcn > LCN_RL_NOT_MAPPED. */
	int dins;		/* Index into @drl at which to insert @srl. */
	int dend, send;		/* Last index into @[ds]rl. */
	int dfinal, sfinal;	/* The last index into @[ds]rl with
				   lcn >= LCN_HOLE. */
	int marker = 0;
	VCN marker_vcn = 0;

#ifdef DEBUG
	ntfs_debug("dst:");
	ntfs_debug_dump_runlist(drl);
	ntfs_debug("src:");
	ntfs_debug_dump_runlist(srl);
#endif

	/* Check for silly calling... */
	if (unlikely(!srl))
		return drl;
	if (IS_ERR(srl) || IS_ERR(drl))
		return ERR_PTR(-EINVAL);

	/* Check for the case where the first mapping is being done now. */
	if (unlikely(!drl)) {
		drl = srl;
		/* Complete the source runlist if necessary. */
		if (unlikely(drl[0].vcn)) {
			/* Scan to the end of the source runlist. */
			for (dend = 0; likely(drl[dend].length); dend++)
				;
			dend++;
			drl = ntfs_rl_realloc(drl, dend, dend + 1);
			if (IS_ERR(drl))
				return drl;
			/* Insert start element at the front of the runlist. */
			ntfs_rl_mm(drl, 1, 0, dend);
			drl[0].vcn = 0;
			drl[0].lcn = LCN_RL_NOT_MAPPED;
			drl[0].length = drl[1].vcn;
		}
		goto finished;
	}

	si = di = 0;

	/* Skip any unmapped start element(s) in the source runlist. */
	while (srl[si].length && srl[si].lcn < LCN_HOLE)
		si++;

	/* Can't have an entirely unmapped source runlist. */
	BUG_ON(!srl[si].length);

	/* Record the starting points. */
	sstart = si;

	/*
	 * Skip forward in @drl until we reach the position where @srl needs to
	 * be inserted. If we reach the end of @drl, @srl just needs to be
	 * appended to @drl.
	 */
	for (; drl[di].length; di++) {
		if (drl[di].vcn + drl[di].length > srl[sstart].vcn)
			break;
	}
	dins = di;

	/* Sanity check for illegal overlaps. */
	if ((drl[di].vcn == srl[si].vcn) && (drl[di].lcn >= 0) &&
			(srl[si].lcn >= 0)) {
		ntfs_error(NULL, "Run lists overlap. Cannot merge!");
		return ERR_PTR(-ERANGE);
	}

	/* Scan to the end of both runlists in order to know their sizes. */
	for (send = si; srl[send].length; send++)
		;
	for (dend = di; drl[dend].length; dend++)
		;

	if (srl[send].lcn == LCN_ENOENT)
		marker_vcn = srl[marker = send].vcn;

	/* Scan to the last element with lcn >= LCN_HOLE. */
	for (sfinal = send; sfinal >= 0 && srl[sfinal].lcn < LCN_HOLE; sfinal--)
		;
	for (dfinal = dend; dfinal >= 0 && drl[dfinal].lcn < LCN_HOLE; dfinal--)
		;

	{
	bool start;
	bool finish;
	int ds = dend + 1;		/* Number of elements in drl & srl */
	int ss = sfinal - sstart + 1;

	start  = ((drl[dins].lcn <  LCN_RL_NOT_MAPPED) ||    /* End of file   */
		  (drl[dins].vcn == srl[sstart].vcn));	     /* Start of hole */
	finish = ((drl[dins].lcn >= LCN_RL_NOT_MAPPED) &&    /* End of file   */
		 ((drl[dins].vcn + drl[dins].length) <=      /* End of hole   */
		  (srl[send - 1].vcn + srl[send - 1].length)));

	/* Or we will lose an end marker. */
	if (finish && !drl[dins].length)
		ss++;
	if (marker && (drl[dins].vcn + drl[dins].length > srl[send - 1].vcn))
		finish = false;
#if 0
	ntfs_debug("dfinal = %i, dend = %i", dfinal, dend);
	ntfs_debug("sstart = %i, sfinal = %i, send = %i", sstart, sfinal, send);
	ntfs_debug("start = %i, finish = %i", start, finish);
	ntfs_debug("ds = %i, ss = %i, dins = %i", ds, ss, dins);
#endif
	if (start) {
		if (finish)
			drl = ntfs_rl_replace(drl, ds, srl + sstart, ss, dins);
		else
			drl = ntfs_rl_insert(drl, ds, srl + sstart, ss, dins);
	} else {
		if (finish)
			drl = ntfs_rl_append(drl, ds, srl + sstart, ss, dins);
		else
			drl = ntfs_rl_split(drl, ds, srl + sstart, ss, dins);
	}
	if (IS_ERR(drl)) {
		ntfs_error(NULL, "Merge failed.");
		return drl;
	}
	ntfs_free(srl);
	if (marker) {
		ntfs_debug("Triggering marker code.");
		for (ds = dend; drl[ds].length; ds++)
			;
		/* We only need to care if @srl ended after @drl. */
		if (drl[ds].vcn <= marker_vcn) {
			int slots = 0;

			if (drl[ds].vcn == marker_vcn) {
				ntfs_debug("Old marker = 0x%llx, replacing "
						"with LCN_ENOENT.",
						(unsigned long long)
						drl[ds].lcn);
				drl[ds].lcn = LCN_ENOENT;
				goto finished;
			}
			/*
			 * We need to create an unmapped runlist element in
			 * @drl or extend an existing one before adding the
			 * ENOENT terminator.
			 */
			if (drl[ds].lcn == LCN_ENOENT) {
				ds--;
				slots = 1;
			}
			if (drl[ds].lcn != LCN_RL_NOT_MAPPED) {
				/* Add an unmapped runlist element. */
				if (!slots) {
					drl = ntfs_rl_realloc_nofail(drl, ds,
							ds + 2);
					slots = 2;
				}
				ds++;
				/* Need to set vcn if it isn't set already. */
				if (slots != 1)
					drl[ds].vcn = drl[ds - 1].vcn +
							drl[ds - 1].length;
				drl[ds].lcn = LCN_RL_NOT_MAPPED;
				/* We now used up a slot. */
				slots--;
			}
			drl[ds].length = marker_vcn - drl[ds].vcn;
			/* Finally add the ENOENT terminator. */
			ds++;
			if (!slots)
				drl = ntfs_rl_realloc_nofail(drl, ds, ds + 1);
			drl[ds].vcn = marker_vcn;
			drl[ds].lcn = LCN_ENOENT;
			drl[ds].length = (s64)0;
		}
	}
	}

finished:
	/* The merge was completed successfully. */
	ntfs_debug("Merged runlist:");
	ntfs_debug_dump_runlist(drl);
	return drl;
}

/**
 * ntfs_mapping_pairs_decompress - convert mapping pairs array to runlist
 * @vol:	ntfs volume on which the attribute resides
 * @attr:	attribute record whose mapping pairs array to decompress
 * @old_rl:	optional runlist in which to insert @attr's runlist
 *
 * It is up to the caller to serialize access to the runlist @old_rl.
 *
 * Decompress the attribute @attr's mapping pairs array into a runlist. On
 * success, return the decompressed runlist.
 *
 * If @old_rl is not NULL, decompressed runlist is inserted into the
 * appropriate place in @old_rl and the resultant, combined runlist is
 * returned. The original @old_rl is deallocated.
 *
 * On error, return -errno. @old_rl is left unmodified in that case.
 *
 * The following error codes are defined:
 *	-ENOMEM	- Not enough memory to allocate runlist array.
 *	-EIO	- Corrupt runlist.
 *	-EINVAL	- Invalid parameters were passed in.
 *	-ERANGE	- The two runlists overlap.
 *
 * FIXME: For now we take the conceptionally simplest approach of creating the
 * new runlist disregarding the already existing one and then splicing the
 * two into one, if that is possible (we check for overlap and discard the new
 * runlist if overlap present before returning ERR_PTR(-ERANGE)).
 */
runlist_element *ntfs_mapping_pairs_decompress(const ntfs_volume *vol,
		const ATTR_RECORD *attr, runlist_element *old_rl)
{
	VCN vcn;		/* Current vcn. */
	LCN lcn;		/* Current lcn. */
	s64 deltaxcn;		/* Change in [vl]cn. */
	runlist_element *rl;	/* The output runlist. */
	u8 *buf;		/* Current position in mapping pairs array. */
	u8 *attr_end;		/* End of attribute. */
	int rlsize;		/* Size of runlist buffer. */
	u16 rlpos;		/* Current runlist position in units of
				   runlist_elements. */
	u8 b;			/* Current byte offset in buf. */

#ifdef DEBUG
	/* Make sure attr exists and is non-resident. */
	if (!attr || !attr->non_resident || sle64_to_cpu(
			attr->data.non_resident.lowest_vcn) < (VCN)0) {
		ntfs_error(vol->sb, "Invalid arguments.");
		return ERR_PTR(-EINVAL);
	}
#endif
	/* Start at vcn = lowest_vcn and lcn 0. */
	vcn = sle64_to_cpu(attr->data.non_resident.lowest_vcn);
	lcn = 0;
	/* Get start of the mapping pairs array. */
	buf = (u8*)attr + le16_to_cpu(
			attr->data.non_resident.mapping_pairs_offset);
	attr_end = (u8*)attr + le32_to_cpu(attr->length);
	if (unlikely(buf < (u8*)attr || buf > attr_end)) {
		ntfs_error(vol->sb, "Corrupt attribute.");
		return ERR_PTR(-EIO);
	}
	/* If the mapping pairs array is valid but empty, nothing to do. */
	if (!vcn && !*buf)
		return old_rl;
	/* Current position in runlist array. */
	rlpos = 0;
	/* Allocate first page and set current runlist size to one page. */
	rl = ntfs_malloc_nofs(rlsize = PAGE_SIZE);
	if (unlikely(!rl))
		return ERR_PTR(-ENOMEM);
	/* Insert unmapped starting element if necessary. */
	if (vcn) {
		rl->vcn = 0;
		rl->lcn = LCN_RL_NOT_MAPPED;
		rl->length = vcn;
		rlpos++;
	}
	while (buf < attr_end && *buf) {
		/*
		 * Allocate more memory if needed, including space for the
		 * not-mapped and terminator elements. ntfs_malloc_nofs()
		 * operates on whole pages only.
		 */
		if (((rlpos + 3) * sizeof(*old_rl)) > rlsize) {
			runlist_element *rl2;

			rl2 = ntfs_malloc_nofs(rlsize + (int)PAGE_SIZE);
			if (unlikely(!rl2)) {
				ntfs_free(rl);
				return ERR_PTR(-ENOMEM);
			}
			memcpy(rl2, rl, rlsize);
			ntfs_free(rl);
			rl = rl2;
			rlsize += PAGE_SIZE;
		}
		/* Enter the current vcn into the current runlist element. */
		rl[rlpos].vcn = vcn;
		/*
		 * Get the change in vcn, i.e. the run length in clusters.
		 * Doing it this way ensures that we signextend negative values.
		 * A negative run length doesn't make any sense, but hey, I
		 * didn't make up the NTFS specs and Windows NT4 treats the run
		 * length as a signed value so that's how it is...
		 */
		b = *buf & 0xf;
		if (b) {
			if (unlikely(buf + b > attr_end))
				goto io_error;
			for (deltaxcn = (s8)buf[b--]; b; b--)
				deltaxcn = (deltaxcn << 8) + buf[b];
		} else { /* The length entry is compulsory. */
			ntfs_error(vol->sb, "Missing length entry in mapping "
					"pairs array.");
			deltaxcn = (s64)-1;
		}
		/*
		 * Assume a negative length to indicate data corruption and
		 * hence clean-up and return NULL.
		 */
		if (unlikely(deltaxcn < 0)) {
			ntfs_error(vol->sb, "Invalid length in mapping pairs "
					"array.");
			goto err_out;
		}
		/*
		 * Enter the current run length into the current runlist
		 * element.
		 */
		rl[rlpos].length = deltaxcn;
		/* Increment the current vcn by the current run length. */
		vcn += deltaxcn;
		/*
		 * There might be no lcn change at all, as is the case for
		 * sparse clusters on NTFS 3.0+, in which case we set the lcn
		 * to LCN_HOLE.
		 */
		if (!(*buf & 0xf0))
			rl[rlpos].lcn = LCN_HOLE;
		else {
			/* Get the lcn change which really can be negative. */
			u8 b2 = *buf & 0xf;
			b = b2 + ((*buf >> 4) & 0xf);
			if (buf + b > attr_end)
				goto io_error;
			for (deltaxcn = (s8)buf[b--]; b > b2; b--)
				deltaxcn = (deltaxcn << 8) + buf[b];
			/* Change the current lcn to its new value. */
			lcn += deltaxcn;
#ifdef DEBUG
			/*
			 * On NTFS 1.2-, apparently can have lcn == -1 to
			 * indicate a hole. But we haven't verified ourselves
			 * whether it is really the lcn or the deltaxcn that is
			 * -1. So if either is found give us a message so we
			 * can investigate it further!
			 */
			if (vol->major_ver < 3) {
				if (unlikely(deltaxcn == (LCN)-1))
					ntfs_error(vol->sb, "lcn delta == -1");
				if (unlikely(lcn == (LCN)-1))
					ntfs_error(vol->sb, "lcn == -1");
			}
#endif
			/* Check lcn is not below -1. */
			if (unlikely(lcn < (LCN)-1)) {
				ntfs_error(vol->sb, "Invalid LCN < -1 in "
						"mapping pairs array.");
				goto err_out;
			}
			/* Enter the current lcn into the runlist element. */
			rl[rlpos].lcn = lcn;
		}
		/* Get to the next runlist element. */
		rlpos++;
		/* Increment the buffer position to the next mapping pair. */
		buf += (*buf & 0xf) + ((*buf >> 4) & 0xf) + 1;
	}
	if (unlikely(buf >= attr_end))
		goto io_error;
	/*
	 * If there is a highest_vcn specified, it must be equal to the final
	 * vcn in the runlist - 1, or something has gone badly wrong.
	 */
	deltaxcn = sle64_to_cpu(attr->data.non_resident.highest_vcn);
	if (unlikely(deltaxcn && vcn - 1 != deltaxcn)) {
mpa_err:
		ntfs_error(vol->sb, "Corrupt mapping pairs array in "
				"non-resident attribute.");
		goto err_out;
	}
	/* Setup not mapped runlist element if this is the base extent. */
	if (!attr->data.non_resident.lowest_vcn) {
		VCN max_cluster;

		max_cluster = ((sle64_to_cpu(
				attr->data.non_resident.allocated_size) +
				vol->cluster_size - 1) >>
				vol->cluster_size_bits) - 1;
		/*
		 * A highest_vcn of zero means this is a single extent
		 * attribute so simply terminate the runlist with LCN_ENOENT).
		 */
		if (deltaxcn) {
			/*
			 * If there is a difference between the highest_vcn and
			 * the highest cluster, the runlist is either corrupt
			 * or, more likely, there are more extents following
			 * this one.
			 */
			if (deltaxcn < max_cluster) {
				ntfs_debug("More extents to follow; deltaxcn "
						"= 0x%llx, max_cluster = "
						"0x%llx",
						(unsigned long long)deltaxcn,
						(unsigned long long)
						max_cluster);
				rl[rlpos].vcn = vcn;
				vcn += rl[rlpos].length = max_cluster -
						deltaxcn;
				rl[rlpos].lcn = LCN_RL_NOT_MAPPED;
				rlpos++;
			} else if (unlikely(deltaxcn > max_cluster)) {
				ntfs_error(vol->sb, "Corrupt attribute.  "
						"deltaxcn = 0x%llx, "
						"max_cluster = 0x%llx",
						(unsigned long long)deltaxcn,
						(unsigned long long)
						max_cluster);
				goto mpa_err;
			}
		}
		rl[rlpos].lcn = LCN_ENOENT;
	} else /* Not the base extent. There may be more extents to follow. */
		rl[rlpos].lcn = LCN_RL_NOT_MAPPED;

	/* Setup terminating runlist element. */
	rl[rlpos].vcn = vcn;
	rl[rlpos].length = (s64)0;
	/* If no existing runlist was specified, we are done. */
	if (!old_rl) {
		ntfs_debug("Mapping pairs array successfully decompressed:");
		ntfs_debug_dump_runlist(rl);
		return rl;
	}
	/* Now combine the new and old runlists checking for overlaps. */
	old_rl = ntfs_runlists_merge(old_rl, rl);
	if (likely(!IS_ERR(old_rl)))
		return old_rl;
	ntfs_free(rl);
	ntfs_error(vol->sb, "Failed to merge runlists.");
	return old_rl;
io_error:
	ntfs_error(vol->sb, "Corrupt attribute.");
err_out:
	ntfs_free(rl);
	return ERR_PTR(-EIO);
}

/**
 * ntfs_rl_vcn_to_lcn - convert a vcn into a lcn given a runlist
 * @rl:		runlist to use for conversion
 * @vcn:	vcn to convert
 *
 * Convert the virtual cluster number @vcn of an attribute into a logical
 * cluster number (lcn) of a device using the runlist @rl to map vcns to their
 * corresponding lcns.
 *
 * It is up to the caller to serialize access to the runlist @rl.
 *
 * Since lcns must be >= 0, we use negative return codes with special meaning:
 *
 * Return code		Meaning / Description
 * ==================================================
 *  LCN_HOLE		Hole / not allocated on disk.
 *  LCN_RL_NOT_MAPPED	This is part of the runlist which has not been
 *			inserted into the runlist yet.
 *  LCN_ENOENT		There is no such vcn in the attribute.
 *
 * Locking: - The caller must have locked the runlist (for reading or writing).
 *	    - This function does not touch the lock, nor does it modify the
 *	      runlist.
 */
LCN ntfs_rl_vcn_to_lcn(const runlist_element *rl, const VCN vcn)
{
	int i;

	BUG_ON(vcn < 0);
	/*
	 * If rl is NULL, assume that we have found an unmapped runlist. The
	 * caller can then attempt to map it and fail appropriately if
	 * necessary.
	 */
	if (unlikely(!rl))
		return LCN_RL_NOT_MAPPED;

	/* Catch out of lower bounds vcn. */
	if (unlikely(vcn < rl[0].vcn))
		return LCN_ENOENT;

	for (i = 0; likely(rl[i].length); i++) {
		if (unlikely(vcn < rl[i+1].vcn)) {
			if (likely(rl[i].lcn >= (LCN)0))
				return rl[i].lcn + (vcn - rl[i].vcn);
			return rl[i].lcn;
		}
	}
	/*
	 * The terminator element is setup to the correct value, i.e. one of
	 * LCN_HOLE, LCN_RL_NOT_MAPPED, or LCN_ENOENT.
	 */
	if (likely(rl[i].lcn < (LCN)0))
		return rl[i].lcn;
	/* Just in case... We could replace this with BUG() some day. */
	return LCN_ENOENT;
}

#ifdef NTFS_RW

/**
 * ntfs_rl_find_vcn_nolock - find a vcn in a runlist
 * @rl:		runlist to search
 * @vcn:	vcn to find
 *
 * Find the virtual cluster number @vcn in the runlist @rl and return the
 * address of the runlist element containing the @vcn on success.
 *
 * Return NULL if @rl is NULL or @vcn is in an unmapped part/out of bounds of
 * the runlist.
 *
 * Locking: The runlist must be locked on entry.
 */
runlist_element *ntfs_rl_find_vcn_nolock(runlist_element *rl, const VCN vcn)
{
	BUG_ON(vcn < 0);
	if (unlikely(!rl || vcn < rl[0].vcn))
		return NULL;
	while (likely(rl->length)) {
		if (unlikely(vcn < rl[1].vcn)) {
			if (likely(rl->lcn >= LCN_HOLE))
				return rl;
			return NULL;
		}
		rl++;
	}
	if (likely(rl->lcn == LCN_ENOENT))
		return rl;
	return NULL;
}

/**
 * ntfs_get_nr_significant_bytes - get number of bytes needed to store a number
 * @n:		number for which to get the number of bytes for
 *
 * Return the number of bytes required to store @n unambiguously as
 * a signed number.
 *
 * This is used in the context of the mapping pairs array to determine how
 * many bytes will be needed in the array to store a given logical cluster
 * number (lcn) or a specific run length.
 *
 * Return the number of bytes written.  This function cannot fail.
 */
static inline int ntfs_get_nr_significant_bytes(const s64 n)
{
	s64 l = n;
	int i;
	s8 j;

	i = 0;
	do {
		l >>= 8;
		i++;
	} while (l != 0 && l != -1);
	j = (n >> 8 * (i - 1)) & 0xff;
	/* If the sign bit is wrong, we need an extra byte. */
	if ((n < 0 && j >= 0) || (n > 0 && j < 0))
		i++;
	return i;
}

/**
 * ntfs_get_size_for_mapping_pairs - get bytes needed for mapping pairs array
 * @vol:	ntfs volume (needed for the ntfs version)
 * @rl:		locked runlist to determine the size of the mapping pairs of
 * @first_vcn:	first vcn which to include in the mapping pairs array
 * @last_vcn:	last vcn which to include in the mapping pairs array
 *
 * Walk the locked runlist @rl and calculate the size in bytes of the mapping
 * pairs array corresponding to the runlist @rl, starting at vcn @first_vcn and
 * finishing with vcn @last_vcn.
 *
 * A @last_vcn of -1 means end of runlist and in that case the size of the
 * mapping pairs array corresponding to the runlist starting at vcn @first_vcn
 * and finishing at the end of the runlist is determined.
 *
 * This for example allows us to allocate a buffer of the right size when
 * building the mapping pairs array.
 *
 * If @rl is NULL, just return 1 (for the single terminator byte).
 *
 * Return the calculated size in bytes on success.  On error, return -errno.
 * The following error codes are defined:
 *	-EINVAL	- Run list contains unmapped elements.  Make sure to only pass
 *		  fully mapped runlists to this function.
 *	-EIO	- The runlist is corrupt.
 *
 * Locking: @rl must be locked on entry (either for reading or writing), it
 *	    remains locked throughout, and is left locked upon return.
 */
int ntfs_get_size_for_mapping_pairs(const ntfs_volume *vol,
		const runlist_element *rl, const VCN first_vcn,
		const VCN last_vcn)
{
	LCN prev_lcn;
	int rls;
	bool the_end = false;

	BUG_ON(first_vcn < 0);
	BUG_ON(last_vcn < -1);
	BUG_ON(last_vcn >= 0 && first_vcn > last_vcn);
	if (!rl) {
		BUG_ON(first_vcn);
		BUG_ON(last_vcn > 0);
		return 1;
	}
	/* Skip to runlist element containing @first_vcn. */
	while (rl->length && first_vcn >= rl[1].vcn)
		rl++;
	if (unlikely((!rl->length && first_vcn > rl->vcn) ||
			first_vcn < rl->vcn))
		return -EINVAL;
	prev_lcn = 0;
	/* Always need the termining zero byte. */
	rls = 1;
	/* Do the first partial run if present. */
	if (first_vcn > rl->vcn) {
		s64 delta, length = rl->length;

		/* We know rl->length != 0 already. */
		if (unlikely(length < 0 || rl->lcn < LCN_HOLE))
			goto err_out;
		/*
		 * If @stop_vcn is given and finishes inside this run, cap the
		 * run length.
		 */
		if (unlikely(last_vcn >= 0 && rl[1].vcn > last_vcn)) {
			s64 s1 = last_vcn + 1;
			if (unlikely(rl[1].vcn > s1))
				length = s1 - rl->vcn;
			the_end = true;
		}
		delta = first_vcn - rl->vcn;
		/* Header byte + length. */
		rls += 1 + ntfs_get_nr_significant_bytes(length - delta);
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space.  On earlier NTFS versions we just store the lcn.
		 * Note: this assumes that on NTFS 1.2-, holes are stored with
		 * an lcn of -1 and not a delta_lcn of -1 (unless both are -1).
		 */
		if (likely(rl->lcn >= 0 || vol->major_ver < 3)) {
			prev_lcn = rl->lcn;
			if (likely(rl->lcn >= 0))
				prev_lcn += delta;
			/* Change in lcn. */
			rls += ntfs_get_nr_significant_bytes(prev_lcn);
		}
		/* Go to next runlist element. */
		rl++;
	}
	/* Do the full runs. */
	for (; rl->length && !the_end; rl++) {
		s64 length = rl->length;

		if (unlikely(length < 0 || rl->lcn < LCN_HOLE))
			goto err_out;
		/*
		 * If @stop_vcn is given and finishes inside this run, cap the
		 * run length.
		 */
		if (unlikely(last_vcn >= 0 && rl[1].vcn > last_vcn)) {
			s64 s1 = last_vcn + 1;
			if (unlikely(rl[1].vcn > s1))
				length = s1 - rl->vcn;
			the_end = true;
		}
		/* Header byte + length. */
		rls += 1 + ntfs_get_nr_significant_bytes(length);
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space.  On earlier NTFS versions we just store the lcn.
		 * Note: this assumes that on NTFS 1.2-, holes are stored with
		 * an lcn of -1 and not a delta_lcn of -1 (unless both are -1).
		 */
		if (likely(rl->lcn >= 0 || vol->major_ver < 3)) {
			/* Change in lcn. */
			rls += ntfs_get_nr_significant_bytes(rl->lcn -
					prev_lcn);
			prev_lcn = rl->lcn;
		}
	}
	return rls;
err_out:
	if (rl->lcn == LCN_RL_NOT_MAPPED)
		rls = -EINVAL;
	else
		rls = -EIO;
	return rls;
}

/**
 * ntfs_write_significant_bytes - write the significant bytes of a number
 * @dst:	destination buffer to write to
 * @dst_max:	pointer to last byte of destination buffer for bounds checking
 * @n:		number whose significant bytes to write
 *
 * Store in @dst, the minimum bytes of the number @n which are required to
 * identify @n unambiguously as a signed number, taking care not to exceed
 * @dest_max, the maximum position within @dst to which we are allowed to
 * write.
 *
 * This is used when building the mapping pairs array of a runlist to compress
 * a given logical cluster number (lcn) or a specific run length to the minimum
 * size possible.
 *
 * Return the number of bytes written on success.  On error, i.e. the
 * destination buffer @dst is too small, return -ENOSPC.
 */
static inline int ntfs_write_significant_bytes(s8 *dst, const s8 *dst_max,
		const s64 n)
{
	s64 l = n;
	int i;
	s8 j;

	i = 0;
	do {
		if (unlikely(dst > dst_max))
			goto err_out;
		*dst++ = l & 0xffll;
		l >>= 8;
		i++;
	} while (l != 0 && l != -1);
	j = (n >> 8 * (i - 1)) & 0xff;
	/* If the sign bit is wrong, we need an extra byte. */
	if (n < 0 && j >= 0) {
		if (unlikely(dst > dst_max))
			goto err_out;
		i++;
		*dst = (s8)-1;
	} else if (n > 0 && j < 0) {
		if (unlikely(dst > dst_max))
			goto err_out;
		i++;
		*dst = (s8)0;
	}
	return i;
err_out:
	return -ENOSPC;
}

/**
 * ntfs_mapping_pairs_build - build the mapping pairs array from a runlist
 * @vol:	ntfs volume (needed for the ntfs version)
 * @dst:	destination buffer to which to write the mapping pairs array
 * @dst_len:	size of destination buffer @dst in bytes
 * @rl:		locked runlist for which to build the mapping pairs array
 * @first_vcn:	first vcn which to include in the mapping pairs array
 * @last_vcn:	last vcn which to include in the mapping pairs array
 * @stop_vcn:	first vcn outside destination buffer on success or -ENOSPC
 *
 * Create the mapping pairs array from the locked runlist @rl, starting at vcn
 * @first_vcn and finishing with vcn @last_vcn and save the array in @dst.
 * @dst_len is the size of @dst in bytes and it should be at least equal to the
 * value obtained by calling ntfs_get_size_for_mapping_pairs().
 *
 * A @last_vcn of -1 means end of runlist and in that case the mapping pairs
 * array corresponding to the runlist starting at vcn @first_vcn and finishing
 * at the end of the runlist is created.
 *
 * If @rl is NULL, just write a single terminator byte to @dst.
 *
 * On success or -ENOSPC error, if @stop_vcn is not NULL, *@stop_vcn is set to
 * the first vcn outside the destination buffer.  Note that on error, @dst has
 * been filled with all the mapping pairs that will fit, thus it can be treated
 * as partial success, in that a new attribute extent needs to be created or
 * the next extent has to be used and the mapping pairs build has to be
 * continued with @first_vcn set to *@stop_vcn.
 *
 * Return 0 on success and -errno on error.  The following error codes are
 * defined:
 *	-EINVAL	- Run list contains unmapped elements.  Make sure to only pass
 *		  fully mapped runlists to this function.
 *	-EIO	- The runlist is corrupt.
 *	-ENOSPC	- The destination buffer is too small.
 *
 * Locking: @rl must be locked on entry (either for reading or writing), it
 *	    remains locked throughout, and is left locked upon return.
 */
int ntfs_mapping_pairs_build(const ntfs_volume *vol, s8 *dst,
		const int dst_len, const runlist_element *rl,
		const VCN first_vcn, const VCN last_vcn, VCN *const stop_vcn)
{
	LCN prev_lcn;
	s8 *dst_max, *dst_next;
	int err = -ENOSPC;
	bool the_end = false;
	s8 len_len, lcn_len;

	BUG_ON(first_vcn < 0);
	BUG_ON(last_vcn < -1);
	BUG_ON(last_vcn >= 0 && first_vcn > last_vcn);
	BUG_ON(dst_len < 1);
	if (!rl) {
		BUG_ON(first_vcn);
		BUG_ON(last_vcn > 0);
		if (stop_vcn)
			*stop_vcn = 0;
		/* Terminator byte. */
		*dst = 0;
		return 0;
	}
	/* Skip to runlist element containing @first_vcn. */
	while (rl->length && first_vcn >= rl[1].vcn)
		rl++;
	if (unlikely((!rl->length && first_vcn > rl->vcn) ||
			first_vcn < rl->vcn))
		return -EINVAL;
	/*
	 * @dst_max is used for bounds checking in
	 * ntfs_write_significant_bytes().
	 */
	dst_max = dst + dst_len - 1;
	prev_lcn = 0;
	/* Do the first partial run if present. */
	if (first_vcn > rl->vcn) {
		s64 delta, length = rl->length;

		/* We know rl->length != 0 already. */
		if (unlikely(length < 0 || rl->lcn < LCN_HOLE))
			goto err_out;
		/*
		 * If @stop_vcn is given and finishes inside this run, cap the
		 * run length.
		 */
		if (unlikely(last_vcn >= 0 && rl[1].vcn > last_vcn)) {
			s64 s1 = last_vcn + 1;
			if (unlikely(rl[1].vcn > s1))
				length = s1 - rl->vcn;
			the_end = true;
		}
		delta = first_vcn - rl->vcn;
		/* Write length. */
		len_len = ntfs_write_significant_bytes(dst + 1, dst_max,
				length - delta);
		if (unlikely(len_len < 0))
			goto size_err;
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space.  On earlier NTFS versions we just write the lcn
		 * change.  FIXME: Do we need to write the lcn change or just
		 * the lcn in that case?  Not sure as I have never seen this
		 * case on NT4. - We assume that we just need to write the lcn
		 * change until someone tells us otherwise... (AIA)
		 */
		if (likely(rl->lcn >= 0 || vol->major_ver < 3)) {
			prev_lcn = rl->lcn;
			if (likely(rl->lcn >= 0))
				prev_lcn += delta;
			/* Write change in lcn. */
			lcn_len = ntfs_write_significant_bytes(dst + 1 +
					len_len, dst_max, prev_lcn);
			if (unlikely(lcn_len < 0))
				goto size_err;
		} else
			lcn_len = 0;
		dst_next = dst + len_len + lcn_len + 1;
		if (unlikely(dst_next > dst_max))
			goto size_err;
		/* Update header byte. */
		*dst = lcn_len << 4 | len_len;
		/* Position at next mapping pairs array element. */
		dst = dst_next;
		/* Go to next runlist element. */
		rl++;
	}
	/* Do the full runs. */
	for (; rl->length && !the_end; rl++) {
		s64 length = rl->length;

		if (unlikely(length < 0 || rl->lcn < LCN_HOLE))
			goto err_out;
		/*
		 * If @stop_vcn is given and finishes inside this run, cap the
		 * run length.
		 */
		if (unlikely(last_vcn >= 0 && rl[1].vcn > last_vcn)) {
			s64 s1 = last_vcn + 1;
			if (unlikely(rl[1].vcn > s1))
				length = s1 - rl->vcn;
			the_end = true;
		}
		/* Write length. */
		len_len = ntfs_write_significant_bytes(dst + 1, dst_max,
				length);
		if (unlikely(len_len < 0))
			goto size_err;
		/*
		 * If the logical cluster number (lcn) denotes a hole and we
		 * are on NTFS 3.0+, we don't store it at all, i.e. we need
		 * zero space.  On earlier NTFS versions we just write the lcn
		 * change.  FIXME: Do we need to write the lcn change or just
		 * the lcn in that case?  Not sure as I have never seen this
		 * case on NT4. - We assume that we just need to write the lcn
		 * change until someone tells us otherwise... (AIA)
		 */
		if (likely(rl->lcn >= 0 || vol->major_ver < 3)) {
			/* Write change in lcn. */
			lcn_len = ntfs_write_significant_bytes(dst + 1 +
					len_len, dst_max, rl->lcn - prev_lcn);
			if (unlikely(lcn_len < 0))
				goto size_err;
			prev_lcn = rl->lcn;
		} else
			lcn_len = 0;
		dst_next = dst + len_len + lcn_len + 1;
		if (unlikely(dst_next > dst_max))
			goto size_err;
		/* Update header byte. */
		*dst = lcn_len << 4 | len_len;
		/* Position at next mapping pairs array element. */
		dst = dst_next;
	}
	/* Success. */
	err = 0;
size_err:
	/* Set stop vcn. */
	if (stop_vcn)
		*stop_vcn = rl->vcn;
	/* Add terminator byte. */
	*dst = 0;
	return err;
err_out:
	if (rl->lcn == LCN_RL_NOT_MAPPED)
		err = -EINVAL;
	else
		err = -EIO;
	return err;
}

/**
 * ntfs_rl_truncate_nolock - truncate a runlist starting at a specified vcn
 * @vol:	ntfs volume (needed for error output)
 * @runlist:	runlist to truncate
 * @new_length:	the new length of the runlist in VCNs
 *
 * Truncate the runlist described by @runlist as well as the memory buffer
 * holding the runlist elements to a length of @new_length VCNs.
 *
 * If @new_length lies within the runlist, the runlist elements with VCNs of
 * @new_length and above are discarded.  As a special case if @new_length is
 * zero, the runlist is discarded and set to NULL.
 *
 * If @new_length lies beyond the runlist, a sparse runlist element is added to
 * the end of the runlist @runlist or if the last runlist element is a sparse
 * one already, this is extended.
 *
 * Note, no checking is done for unmapped runlist elements.  It is assumed that
 * the caller has mapped any elements that need to be mapped already.
 *
 * Return 0 on success and -errno on error.
 *
 * Locking: The caller must hold @runlist->lock for writing.
 */
int ntfs_rl_truncate_nolock(const ntfs_volume *vol, runlist *const runlist,
		const s64 new_length)
{
	runlist_element *rl;
	int old_size;

	ntfs_debug("Entering for new_length 0x%llx.", (long long)new_length);
	BUG_ON(!runlist);
	BUG_ON(new_length < 0);
	rl = runlist->rl;
	if (!new_length) {
		ntfs_debug("Freeing runlist.");
		runlist->rl = NULL;
		if (rl)
			ntfs_free(rl);
		return 0;
	}
	if (unlikely(!rl)) {
		/*
		 * Create a runlist consisting of a sparse runlist element of
		 * length @new_length followed by a terminator runlist element.
		 */
		rl = ntfs_malloc_nofs(PAGE_SIZE);
		if (unlikely(!rl)) {
			ntfs_error(vol->sb, "Not enough memory to allocate "
					"runlist element buffer.");
			return -ENOMEM;
		}
		runlist->rl = rl;
		rl[1].length = rl->vcn = 0;
		rl->lcn = LCN_HOLE;
		rl[1].vcn = rl->length = new_length;
		rl[1].lcn = LCN_ENOENT;
		return 0;
	}
	BUG_ON(new_length < rl->vcn);
	/* Find @new_length in the runlist. */
	while (likely(rl->length && new_length >= rl[1].vcn))
		rl++;
	/*
	 * If not at the end of the runlist we need to shrink it.
	 * If at the end of the runlist we need to expand it.
	 */
	if (rl->length) {
		runlist_element *trl;
		bool is_end;

		ntfs_debug("Shrinking runlist.");
		/* Determine the runlist size. */
		trl = rl + 1;
		while (likely(trl->length))
			trl++;
		old_size = trl - runlist->rl + 1;
		/* Truncate the run. */
		rl->length = new_length - rl->vcn;
		/*
		 * If a run was partially truncated, make the following runlist
		 * element a terminator.
		 */
		is_end = false;
		if (rl->length) {
			rl++;
			if (!rl->length)
				is_end = true;
			rl->vcn = new_length;
			rl->length = 0;
		}
		rl->lcn = LCN_ENOENT;
		/* Reallocate memory if necessary. */
		if (!is_end) {
			int new_size = rl - runlist->rl + 1;
			rl = ntfs_rl_realloc(runlist->rl, old_size, new_size);
			if (IS_ERR(rl))
				ntfs_warning(vol->sb, "Failed to shrink "
						"runlist buffer.  This just "
						"wastes a bit of memory "
						"temporarily so we ignore it "
						"and return success.");
			else
				runlist->rl = rl;
		}
	} else if (likely(/* !rl->length && */ new_length > rl->vcn)) {
		ntfs_debug("Expanding runlist.");
		/*
		 * If there is a previous runlist element and it is a sparse
		 * one, extend it.  Otherwise need to add a new, sparse runlist
		 * element.
		 */
		if ((rl > runlist->rl) && ((rl - 1)->lcn == LCN_HOLE))
			(rl - 1)->length = new_length - (rl - 1)->vcn;
		else {
			/* Determine the runlist size. */
			old_size = rl - runlist->rl + 1;
			/* Reallocate memory if necessary. */
			rl = ntfs_rl_realloc(runlist->rl, old_size,
					old_size + 1);
			if (IS_ERR(rl)) {
				ntfs_error(vol->sb, "Failed to expand runlist "
						"buffer, aborting.");
				return PTR_ERR(rl);
			}
			runlist->rl = rl;
			/*
			 * Set @rl to the same runlist element in the new
			 * runlist as before in the old runlist.
			 */
			rl += old_size - 1;
			/* Add a new, sparse runlist element. */
			rl->lcn = LCN_HOLE;
			rl->length = new_length - rl->vcn;
			/* Add a new terminator runlist element. */
			rl++;
			rl->length = 0;
		}
		rl->vcn = new_length;
		rl->lcn = LCN_ENOENT;
	} else /* if (unlikely(!rl->length && new_length == rl->vcn)) */ {
		/* Runlist already has same size as requested. */
		rl->lcn = LCN_ENOENT;
	}
	ntfs_debug("Done.");
	return 0;
}

/**
 * ntfs_rl_punch_nolock - punch a hole into a runlist
 * @vol:	ntfs volume (needed for error output)
 * @runlist:	runlist to punch a hole into
 * @start:	starting VCN of the hole to be created
 * @length:	size of the hole to be created in units of clusters
 *
 * Punch a hole into the runlist @runlist starting at VCN @start and of size
 * @length clusters.
 *
 * Return 0 on success and -errno on error, in which case @runlist has not been
 * modified.
 *
 * If @start and/or @start + @length are outside the runlist return error code
 * -ENOENT.
 *
 * If the runlist contains unmapped or error elements between @start and @start
 * + @length return error code -EINVAL.
 *
 * Locking: The caller must hold @runlist->lock for writing.
 */
int ntfs_rl_punch_nolock(const ntfs_volume *vol, runlist *const runlist,
		const VCN start, const s64 length)
{
	const VCN end = start + length;
	s64 delta;
	runlist_element *rl, *rl_end, *rl_real_end, *trl;
	int old_size;
	bool lcn_fixup = false;

	ntfs_debug("Entering for start 0x%llx, length 0x%llx.",
			(long long)start, (long long)length);
	BUG_ON(!runlist);
	BUG_ON(start < 0);
	BUG_ON(length < 0);
	BUG_ON(end < 0);
	rl = runlist->rl;
	if (unlikely(!rl)) {
		if (likely(!start && !length))
			return 0;
		return -ENOENT;
	}
	/* Find @start in the runlist. */
	while (likely(rl->length && start >= rl[1].vcn))
		rl++;
	rl_end = rl;
	/* Find @end in the runlist. */
	while (likely(rl_end->length && end >= rl_end[1].vcn)) {
		/* Verify there are no unmapped or error elements. */
		if (unlikely(rl_end->lcn < LCN_HOLE))
			return -EINVAL;
		rl_end++;
	}
	/* Check the last element. */
	if (unlikely(rl_end->length && rl_end->lcn < LCN_HOLE))
		return -EINVAL;
	/* This covers @start being out of bounds, too. */
	if (!rl_end->length && end > rl_end->vcn)
		return -ENOENT;
	if (!length)
		return 0;
	if (!rl->length)
		return -ENOENT;
	rl_real_end = rl_end;
	/* Determine the runlist size. */
	while (likely(rl_real_end->length))
		rl_real_end++;
	old_size = rl_real_end - runlist->rl + 1;
	/* If @start is in a hole simply extend the hole. */
	if (rl->lcn == LCN_HOLE) {
		/*
		 * If both @start and @end are in the same sparse run, we are
		 * done.
		 */
		if (end <= rl[1].vcn) {
			ntfs_debug("Done (requested hole is already sparse).");
			return 0;
		}
extend_hole:
		/* Extend the hole. */
		rl->length = end - rl->vcn;
		/* If @end is in a hole, merge it with the current one. */
		if (rl_end->lcn == LCN_HOLE) {
			rl_end++;
			rl->length = rl_end->vcn - rl->vcn;
		}
		/* We have done the hole.  Now deal with the remaining tail. */
		rl++;
		/* Cut out all runlist elements up to @end. */
		if (rl < rl_end)
			memmove(rl, rl_end, (rl_real_end - rl_end + 1) *
					sizeof(*rl));
		/* Adjust the beginning of the tail if necessary. */
		if (end > rl->vcn) {
			delta = end - rl->vcn;
			rl->vcn = end;
			rl->length -= delta;
			/* Only adjust the lcn if it is real. */
			if (rl->lcn >= 0)
				rl->lcn += delta;
		}
shrink_allocation:
		/* Reallocate memory if the allocation changed. */
		if (rl < rl_end) {
			rl = ntfs_rl_realloc(runlist->rl, old_size,
					old_size - (rl_end - rl));
			if (IS_ERR(rl))
				ntfs_warning(vol->sb, "Failed to shrink "
						"runlist buffer.  This just "
						"wastes a bit of memory "
						"temporarily so we ignore it "
						"and return success.");
			else
				runlist->rl = rl;
		}
		ntfs_debug("Done (extend hole).");
		return 0;
	}
	/*
	 * If @start is at the beginning of a run things are easier as there is
	 * no need to split the first run.
	 */
	if (start == rl->vcn) {
		/*
		 * @start is at the beginning of a run.
		 *
		 * If the previous run is sparse, extend its hole.
		 *
		 * If @end is not in the same run, switch the run to be sparse
		 * and extend the newly created hole.
		 *
		 * Thus both of these cases reduce the problem to the above
		 * case of "@start is in a hole".
		 */
		if (rl > runlist->rl && (rl - 1)->lcn == LCN_HOLE) {
			rl--;
			goto extend_hole;
		}
		if (end >= rl[1].vcn) {
			rl->lcn = LCN_HOLE;
			goto extend_hole;
		}
		/*
		 * The final case is when @end is in the same run as @start.
		 * For this need to split the run into two.  One run for the
		 * sparse region between the beginning of the old run, i.e.
		 * @start, and @end and one for the remaining non-sparse
		 * region, i.e. between @end and the end of the old run.
		 */
		trl = ntfs_rl_realloc(runlist->rl, old_size, old_size + 1);
		if (IS_ERR(trl))
			goto enomem_out;
		old_size++;
		if (runlist->rl != trl) {
			rl = trl + (rl - runlist->rl);
			rl_end = trl + (rl_end - runlist->rl);
			rl_real_end = trl + (rl_real_end - runlist->rl);
			runlist->rl = trl;
		}
split_end:
		/* Shift all the runs up by one. */
		memmove(rl + 1, rl, (rl_real_end - rl + 1) * sizeof(*rl));
		/* Finally, setup the two split runs. */
		rl->lcn = LCN_HOLE;
		rl->length = length;
		rl++;
		rl->vcn += length;
		/* Only adjust the lcn if it is real. */
		if (rl->lcn >= 0 || lcn_fixup)
			rl->lcn += length;
		rl->length -= length;
		ntfs_debug("Done (split one).");
		return 0;
	}
	/*
	 * @start is neither in a hole nor at the beginning of a run.
	 *
	 * If @end is in a hole, things are easier as simply truncating the run
	 * @start is in to end at @start - 1, deleting all runs after that up
	 * to @end, and finally extending the beginning of the run @end is in
	 * to be @start is all that is needed.
	 */
	if (rl_end->lcn == LCN_HOLE) {
		/* Truncate the run containing @start. */
		rl->length = start - rl->vcn;
		rl++;
		/* Cut out all runlist elements up to @end. */
		if (rl < rl_end)
			memmove(rl, rl_end, (rl_real_end - rl_end + 1) *
					sizeof(*rl));
		/* Extend the beginning of the run @end is in to be @start. */
		rl->vcn = start;
		rl->length = rl[1].vcn - start;
		goto shrink_allocation;
	}
	/* 
	 * If @end is not in a hole there are still two cases to distinguish.
	 * Either @end is or is not in the same run as @start.
	 *
	 * The second case is easier as it can be reduced to an already solved
	 * problem by truncating the run @start is in to end at @start - 1.
	 * Then, if @end is in the next run need to split the run into a sparse
	 * run followed by a non-sparse run (already covered above) and if @end
	 * is not in the next run switching it to be sparse, again reduces the
	 * problem to the already covered case of "@start is in a hole".
	 */
	if (end >= rl[1].vcn) {
		/*
		 * If @end is not in the next run, reduce the problem to the
		 * case of "@start is in a hole".
		 */
		if (rl[1].length && end >= rl[2].vcn) {
			/* Truncate the run containing @start. */
			rl->length = start - rl->vcn;
			rl++;
			rl->vcn = start;
			rl->lcn = LCN_HOLE;
			goto extend_hole;
		}
		trl = ntfs_rl_realloc(runlist->rl, old_size, old_size + 1);
		if (IS_ERR(trl))
			goto enomem_out;
		old_size++;
		if (runlist->rl != trl) {
			rl = trl + (rl - runlist->rl);
			rl_end = trl + (rl_end - runlist->rl);
			rl_real_end = trl + (rl_real_end - runlist->rl);
			runlist->rl = trl;
		}
		/* Truncate the run containing @start. */
		rl->length = start - rl->vcn;
		rl++;
		/*
		 * @end is in the next run, reduce the problem to the case
		 * where "@start is at the beginning of a run and @end is in
		 * the same run as @start".
		 */
		delta = rl->vcn - start;
		rl->vcn = start;
		if (rl->lcn >= 0) {
			rl->lcn -= delta;
			/* Need this in case the lcn just became negative. */
			lcn_fixup = true;
		}
		rl->length += delta;
		goto split_end;
	}
	/*
	 * The first case from above, i.e. @end is in the same run as @start.
	 * We need to split the run into three.  One run for the non-sparse
	 * region between the beginning of the old run and @start, one for the
	 * sparse region between @start and @end, and one for the remaining
	 * non-sparse region, i.e. between @end and the end of the old run.
	 */
	trl = ntfs_rl_realloc(runlist->rl, old_size, old_size + 2);
	if (IS_ERR(trl))
		goto enomem_out;
	old_size += 2;
	if (runlist->rl != trl) {
		rl = trl + (rl - runlist->rl);
		rl_end = trl + (rl_end - runlist->rl);
		rl_real_end = trl + (rl_real_end - runlist->rl);
		runlist->rl = trl;
	}
	/* Shift all the runs up by two. */
	memmove(rl + 2, rl, (rl_real_end - rl + 1) * sizeof(*rl));
	/* Finally, setup the three split runs. */
	rl->length = start - rl->vcn;
	rl++;
	rl->vcn = start;
	rl->lcn = LCN_HOLE;
	rl->length = length;
	rl++;
	delta = end - rl->vcn;
	rl->vcn = end;
	rl->lcn += delta;
	rl->length -= delta;
	ntfs_debug("Done (split both).");
	return 0;
enomem_out:
	ntfs_error(vol->sb, "Not enough memory to extend runlist buffer.");
	return -ENOMEM;
}

#endif /* NTFS_RW */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/runlist.c */
/************************************************************/
/*
 * super.c - NTFS kernel super block handling. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2012 Anton Altaparmakov and Tuxera Inc.
 * Copyright (c) 2001,2002 Richard Russon
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/stddef.h>
#include <linux/init.h>
// #include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
// #include <linux/blkdev.h>	/* For bdev_logical_block_size(). */
// #include <linux/backing-dev.h>
// #include <linux/buffer_head.h>
#include <linux/vfs.h>
#include <linux/moduleparam.h>
#include <linux/bitmap.h>
#include "../../inc/__fss.h"

#include "sysctl.h"
#include "logfile.h"
#include "quota.h"
#include "usnjrnl.h"
// #include "dir.h"
// #include "debug.h"
// #include "index.h"
// #include "inode.h"
// #include "aops.h"
// #include "layout.h"
// #include "malloc.h"
// #include "ntfs.h"
#include "../../inc/__fss.h"

/* Number of mounted filesystems which have compression enabled. */
static unsigned long ntfs_nr_compression_users;

/* A global default upcase table and a corresponding reference count. */
static ntfschar *default_upcase;
static unsigned long ntfs_nr_upcase_users;

/* Error constants/strings used in inode.c::ntfs_show_options(). */
typedef enum {
	/* One of these must be present, default is ON_ERRORS_CONTINUE. */
	ON_ERRORS_PANIC			= 0x01,
	ON_ERRORS_REMOUNT_RO		= 0x02,
	ON_ERRORS_CONTINUE		= 0x04,
	/* Optional, can be combined with any of the above. */
	ON_ERRORS_RECOVER		= 0x10,
} ON_ERRORS_ACTIONS;

const option_t on_errors_arr[] = {
	{ ON_ERRORS_PANIC,	"panic" },
	{ ON_ERRORS_REMOUNT_RO,	"remount-ro", },
	{ ON_ERRORS_CONTINUE,	"continue", },
	{ ON_ERRORS_RECOVER,	"recover" },
	{ 0,			NULL }
};

/**
 * simple_getbool -
 *
 * Copied from old ntfs driver (which copied from vfat driver).
 */
static int simple_getbool(char *s, bool *setval)
{
	if (s) {
		if (!strcmp(s, "1") || !strcmp(s, "yes") || !strcmp(s, "true"))
			*setval = true;
		else if (!strcmp(s, "0") || !strcmp(s, "no") ||
							!strcmp(s, "false"))
			*setval = false;
		else
			return 0;
	} else
		*setval = true;
	return 1;
}

/**
 * parse_options - parse the (re)mount options
 * @vol:	ntfs volume
 * @opt:	string containing the (re)mount options
 *
 * Parse the recognized options in @opt for the ntfs volume described by @vol.
 */
static bool parse_options(ntfs_volume *vol, char *opt)
{
	char *p, *v, *ov;
	static char *utf8 = "utf8";
	int errors = 0, sloppy = 0;
	kuid_t uid = INVALID_UID;
	kgid_t gid = INVALID_GID;
	umode_t fmask = (umode_t)-1, dmask = (umode_t)-1;
	int mft_zone_multiplier = -1, on_errors = -1;
	int show_sys_files = -1, case_sensitive = -1, disable_sparse = -1;
	struct nls_table *nls_map = NULL, *old_nls;

	/* I am lazy... (-8 */
#define NTFS_GETOPT_WITH_DEFAULT(option, variable, default_value)	\
	if (!strcmp(p, option)) {					\
		if (!v || !*v)						\
			variable = default_value;			\
		else {							\
			variable = simple_strtoul(ov = v, &v, 0);	\
			if (*v)						\
				goto needs_val;				\
		}							\
	}
#define NTFS_GETOPT(option, variable)					\
	if (!strcmp(p, option)) {					\
		if (!v || !*v)						\
			goto needs_arg;					\
		variable = simple_strtoul(ov = v, &v, 0);		\
		if (*v)							\
			goto needs_val;					\
	}
#define NTFS_GETOPT_UID(option, variable)				\
	if (!strcmp(p, option)) {					\
		uid_t uid_value;					\
		if (!v || !*v)						\
			goto needs_arg;					\
		uid_value = simple_strtoul(ov = v, &v, 0);		\
		if (*v)							\
			goto needs_val;					\
		variable = make_kuid(current_user_ns(), uid_value);	\
		if (!uid_valid(variable))				\
			goto needs_val;					\
	}
#define NTFS_GETOPT_GID(option, variable)				\
	if (!strcmp(p, option)) {					\
		gid_t gid_value;					\
		if (!v || !*v)						\
			goto needs_arg;					\
		gid_value = simple_strtoul(ov = v, &v, 0);		\
		if (*v)							\
			goto needs_val;					\
		variable = make_kgid(current_user_ns(), gid_value);	\
		if (!gid_valid(variable))				\
			goto needs_val;					\
	}
#define NTFS_GETOPT_OCTAL(option, variable)				\
	if (!strcmp(p, option)) {					\
		if (!v || !*v)						\
			goto needs_arg;					\
		variable = simple_strtoul(ov = v, &v, 8);		\
		if (*v)							\
			goto needs_val;					\
	}
#define NTFS_GETOPT_BOOL(option, variable)				\
	if (!strcmp(p, option)) {					\
		bool val;						\
		if (!simple_getbool(v, &val))				\
			goto needs_bool;				\
		variable = val;						\
	}
#define NTFS_GETOPT_OPTIONS_ARRAY(option, variable, opt_array)		\
	if (!strcmp(p, option)) {					\
		int _i;							\
		if (!v || !*v)						\
			goto needs_arg;					\
		ov = v;							\
		if (variable == -1)					\
			variable = 0;					\
		for (_i = 0; opt_array[_i].str && *opt_array[_i].str; _i++) \
			if (!strcmp(opt_array[_i].str, v)) {		\
				variable |= opt_array[_i].val;		\
				break;					\
			}						\
		if (!opt_array[_i].str || !*opt_array[_i].str)		\
			goto needs_val;					\
	}
	if (!opt || !*opt)
		goto no_mount_options;
	ntfs_debug("Entering with mount options string: %s", opt);
	while ((p = strsep(&opt, ","))) {
		if ((v = strchr(p, '=')))
			*v++ = 0;
		NTFS_GETOPT_UID("uid", uid)
		else NTFS_GETOPT_GID("gid", gid)
		else NTFS_GETOPT_OCTAL("umask", fmask = dmask)
		else NTFS_GETOPT_OCTAL("fmask", fmask)
		else NTFS_GETOPT_OCTAL("dmask", dmask)
		else NTFS_GETOPT("mft_zone_multiplier", mft_zone_multiplier)
		else NTFS_GETOPT_WITH_DEFAULT("sloppy", sloppy, true)
		else NTFS_GETOPT_BOOL("show_sys_files", show_sys_files)
		else NTFS_GETOPT_BOOL("case_sensitive", case_sensitive)
		else NTFS_GETOPT_BOOL("disable_sparse", disable_sparse)
		else NTFS_GETOPT_OPTIONS_ARRAY("errors", on_errors,
				on_errors_arr)
		else if (!strcmp(p, "posix") || !strcmp(p, "show_inodes"))
			ntfs_warning(vol->sb, "Ignoring obsolete option %s.",
					p);
		else if (!strcmp(p, "nls") || !strcmp(p, "iocharset")) {
			if (!strcmp(p, "iocharset"))
				ntfs_warning(vol->sb, "Option iocharset is "
						"deprecated. Please use "
						"option nls=<charsetname> in "
						"the future.");
			if (!v || !*v)
				goto needs_arg;
use_utf8:
			old_nls = nls_map;
			nls_map = load_nls(v);
			if (!nls_map) {
				if (!old_nls) {
					ntfs_error(vol->sb, "NLS character set "
							"%s not found.", v);
					return false;
				}
				ntfs_error(vol->sb, "NLS character set %s not "
						"found. Using previous one %s.",
						v, old_nls->charset);
				nls_map = old_nls;
			} else /* nls_map */ {
				unload_nls(old_nls);
			}
		} else if (!strcmp(p, "utf8")) {
			bool val = false;
			ntfs_warning(vol->sb, "Option utf8 is no longer "
				   "supported, using option nls=utf8. Please "
				   "use option nls=utf8 in the future and "
				   "make sure utf8 is compiled either as a "
				   "module or into the kernel.");
			if (!v || !*v)
				val = true;
			else if (!simple_getbool(v, &val))
				goto needs_bool;
			if (val) {
				v = utf8;
				goto use_utf8;
			}
		} else {
			ntfs_error(vol->sb, "Unrecognized mount option %s.", p);
			if (errors < INT_MAX)
				errors++;
		}
#undef NTFS_GETOPT_OPTIONS_ARRAY
#undef NTFS_GETOPT_BOOL
#undef NTFS_GETOPT
#undef NTFS_GETOPT_WITH_DEFAULT
	}
no_mount_options:
	if (errors && !sloppy)
		return false;
	if (sloppy)
		ntfs_warning(vol->sb, "Sloppy option given. Ignoring "
				"unrecognized mount option(s) and continuing.");
	/* Keep this first! */
	if (on_errors != -1) {
		if (!on_errors) {
			ntfs_error(vol->sb, "Invalid errors option argument "
					"or bug in options parser.");
			return false;
		}
	}
	if (nls_map) {
		if (vol->nls_map && vol->nls_map != nls_map) {
			ntfs_error(vol->sb, "Cannot change NLS character set "
					"on remount.");
			return false;
		} /* else (!vol->nls_map) */
		ntfs_debug("Using NLS character set %s.", nls_map->charset);
		vol->nls_map = nls_map;
	} else /* (!nls_map) */ {
		if (!vol->nls_map) {
			vol->nls_map = load_nls_default();
			if (!vol->nls_map) {
				ntfs_error(vol->sb, "Failed to load default "
						"NLS character set.");
				return false;
			}
			ntfs_debug("Using default NLS character set (%s).",
					vol->nls_map->charset);
		}
	}
	if (mft_zone_multiplier != -1) {
		if (vol->mft_zone_multiplier && vol->mft_zone_multiplier !=
				mft_zone_multiplier) {
			ntfs_error(vol->sb, "Cannot change mft_zone_multiplier "
					"on remount.");
			return false;
		}
		if (mft_zone_multiplier < 1 || mft_zone_multiplier > 4) {
			ntfs_error(vol->sb, "Invalid mft_zone_multiplier. "
					"Using default value, i.e. 1.");
			mft_zone_multiplier = 1;
		}
		vol->mft_zone_multiplier = mft_zone_multiplier;
	}
	if (!vol->mft_zone_multiplier)
		vol->mft_zone_multiplier = 1;
	if (on_errors != -1)
		vol->on_errors = on_errors;
	if (!vol->on_errors || vol->on_errors == ON_ERRORS_RECOVER)
		vol->on_errors |= ON_ERRORS_CONTINUE;
	if (uid_valid(uid))
		vol->uid = uid;
	if (gid_valid(gid))
		vol->gid = gid;
	if (fmask != (umode_t)-1)
		vol->fmask = fmask;
	if (dmask != (umode_t)-1)
		vol->dmask = dmask;
	if (show_sys_files != -1) {
		if (show_sys_files)
			NVolSetShowSystemFiles(vol);
		else
			NVolClearShowSystemFiles(vol);
	}
	if (case_sensitive != -1) {
		if (case_sensitive)
			NVolSetCaseSensitive(vol);
		else
			NVolClearCaseSensitive(vol);
	}
	if (disable_sparse != -1) {
		if (disable_sparse)
			NVolClearSparseEnabled(vol);
		else {
			if (!NVolSparseEnabled(vol) &&
					vol->major_ver && vol->major_ver < 3)
				ntfs_warning(vol->sb, "Not enabling sparse "
						"support due to NTFS volume "
						"version %i.%i (need at least "
						"version 3.0).", vol->major_ver,
						vol->minor_ver);
			else
				NVolSetSparseEnabled(vol);
		}
	}
	return true;
needs_arg:
	ntfs_error(vol->sb, "The %s option requires an argument.", p);
	return false;
needs_bool:
	ntfs_error(vol->sb, "The %s option requires a boolean argument.", p);
	return false;
needs_val:
	ntfs_error(vol->sb, "Invalid %s option argument: %s", p, ov);
	return false;
}

#ifdef NTFS_RW

/**
 * ntfs_write_volume_flags - write new flags to the volume information flags
 * @vol:	ntfs volume on which to modify the flags
 * @flags:	new flags value for the volume information flags
 *
 * Internal function.  You probably want to use ntfs_{set,clear}_volume_flags()
 * instead (see below).
 *
 * Replace the volume information flags on the volume @vol with the value
 * supplied in @flags.  Note, this overwrites the volume information flags, so
 * make sure to combine the flags you want to modify with the old flags and use
 * the result when calling ntfs_write_volume_flags().
 *
 * Return 0 on success and -errno on error.
 */
static int ntfs_write_volume_flags(ntfs_volume *vol, const VOLUME_FLAGS flags)
{
	ntfs_inode *ni = NTFS_I(vol->vol_ino);
	MFT_RECORD *m;
	VOLUME_INFORMATION *vi;
	ntfs_attr_search_ctx *ctx;
	int err;

	ntfs_debug("Entering, old flags = 0x%x, new flags = 0x%x.",
			le16_to_cpu(vol->vol_flags), le16_to_cpu(flags));
	if (vol->vol_flags == flags)
		goto done;
	BUG_ON(!ni);
	m = map_mft_record(ni);
	if (IS_ERR(m)) {
		err = PTR_ERR(m);
		goto err_out;
	}
	ctx = ntfs_attr_get_search_ctx(ni, m);
	if (!ctx) {
		err = -ENOMEM;
		goto put_unm_err_out;
	}
	err = ntfs_attr_lookup(AT_VOLUME_INFORMATION, NULL, 0, 0, 0, NULL, 0,
			ctx);
	if (err)
		goto put_unm_err_out;
	vi = (VOLUME_INFORMATION*)((u8*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset));
	vol->vol_flags = vi->flags = flags;
	flush_dcache_mft_record_page(ctx->ntfs_ino);
	mark_mft_record_dirty(ctx->ntfs_ino);
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(ni);
done:
	ntfs_debug("Done.");
	return 0;
put_unm_err_out:
	if (ctx)
		ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(ni);
err_out:
	ntfs_error(vol->sb, "Failed with error code %i.", -err);
	return err;
}

/**
 * ntfs_set_volume_flags - set bits in the volume information flags
 * @vol:	ntfs volume on which to modify the flags
 * @flags:	flags to set on the volume
 *
 * Set the bits in @flags in the volume information flags on the volume @vol.
 *
 * Return 0 on success and -errno on error.
 */
static inline int ntfs_set_volume_flags(ntfs_volume *vol, VOLUME_FLAGS flags)
{
	flags &= VOLUME_FLAGS_MASK;
	return ntfs_write_volume_flags(vol, vol->vol_flags | flags);
}

/**
 * ntfs_clear_volume_flags - clear bits in the volume information flags
 * @vol:	ntfs volume on which to modify the flags
 * @flags:	flags to clear on the volume
 *
 * Clear the bits in @flags in the volume information flags on the volume @vol.
 *
 * Return 0 on success and -errno on error.
 */
static inline int ntfs_clear_volume_flags(ntfs_volume *vol, VOLUME_FLAGS flags)
{
	flags &= VOLUME_FLAGS_MASK;
	flags = vol->vol_flags & cpu_to_le16(~le16_to_cpu(flags));
	return ntfs_write_volume_flags(vol, flags);
}

#endif /* NTFS_RW */

/**
 * ntfs_remount - change the mount options of a mounted ntfs filesystem
 * @sb:		superblock of mounted ntfs filesystem
 * @flags:	remount flags
 * @opt:	remount options string
 *
 * Change the mount options of an already mounted ntfs filesystem.
 *
 * NOTE:  The VFS sets the @sb->s_flags remount flags to @flags after
 * ntfs_remount() returns successfully (i.e. returns 0).  Otherwise,
 * @sb->s_flags are not changed.
 */
static int ntfs_remount(struct super_block *sb, int *flags, char *opt)
{
	ntfs_volume *vol = NTFS_SB(sb);

	ntfs_debug("Entering with remount options string: %s", opt);

	sync_filesystem(sb);

#ifndef NTFS_RW
	/* For read-only compiled driver, enforce read-only flag. */
	*flags |= MS_RDONLY;
#else /* NTFS_RW */
	/*
	 * For the read-write compiled driver, if we are remounting read-write,
	 * make sure there are no volume errors and that no unsupported volume
	 * flags are set.  Also, empty the logfile journal as it would become
	 * stale as soon as something is written to the volume and mark the
	 * volume dirty so that chkdsk is run if the volume is not umounted
	 * cleanly.  Finally, mark the quotas out of date so Windows rescans
	 * the volume on boot and updates them.
	 *
	 * When remounting read-only, mark the volume clean if no volume errors
	 * have occurred.
	 */
	if ((sb->s_flags & MS_RDONLY) && !(*flags & MS_RDONLY)) {
		static const char *es = ".  Cannot remount read-write.";

		/* Remounting read-write. */
		if (NVolErrors(vol)) {
			ntfs_error(sb, "Volume has errors and is read-only%s",
					es);
			return -EROFS;
		}
		if (vol->vol_flags & VOLUME_IS_DIRTY) {
			ntfs_error(sb, "Volume is dirty and read-only%s", es);
			return -EROFS;
		}
		if (vol->vol_flags & VOLUME_MODIFIED_BY_CHKDSK) {
			ntfs_error(sb, "Volume has been modified by chkdsk "
					"and is read-only%s", es);
			return -EROFS;
		}
		if (vol->vol_flags & VOLUME_MUST_MOUNT_RO_MASK) {
			ntfs_error(sb, "Volume has unsupported flags set "
					"(0x%x) and is read-only%s",
					(unsigned)le16_to_cpu(vol->vol_flags),
					es);
			return -EROFS;
		}
		if (ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY)) {
			ntfs_error(sb, "Failed to set dirty bit in volume "
					"information flags%s", es);
			return -EROFS;
		}
#if 0
		// TODO: Enable this code once we start modifying anything that
		//	 is different between NTFS 1.2 and 3.x...
		/* Set NT4 compatibility flag on newer NTFS version volumes. */
		if ((vol->major_ver > 1)) {
			if (ntfs_set_volume_flags(vol, VOLUME_MOUNTED_ON_NT4)) {
				ntfs_error(sb, "Failed to set NT4 "
						"compatibility flag%s", es);
				NVolSetErrors(vol);
				return -EROFS;
			}
		}
#endif
		if (!ntfs_empty_logfile(vol->logfile_ino)) {
			ntfs_error(sb, "Failed to empty journal $LogFile%s",
					es);
			NVolSetErrors(vol);
			return -EROFS;
		}
		if (!ntfs_mark_quotas_out_of_date(vol)) {
			ntfs_error(sb, "Failed to mark quotas out of date%s",
					es);
			NVolSetErrors(vol);
			return -EROFS;
		}
		if (!ntfs_stamp_usnjrnl(vol)) {
			ntfs_error(sb, "Failed to stamp transation log "
					"($UsnJrnl)%s", es);
			NVolSetErrors(vol);
			return -EROFS;
		}
	} else if (!(sb->s_flags & MS_RDONLY) && (*flags & MS_RDONLY)) {
		/* Remounting read-only. */
		if (!NVolErrors(vol)) {
			if (ntfs_clear_volume_flags(vol, VOLUME_IS_DIRTY))
				ntfs_warning(sb, "Failed to clear dirty bit "
						"in volume information "
						"flags.  Run chkdsk.");
		}
	}
#endif /* NTFS_RW */

	// TODO: Deal with *flags.

	if (!parse_options(vol, opt))
		return -EINVAL;

	ntfs_debug("Done.");
	return 0;
}

/**
 * is_boot_sector_ntfs - check whether a boot sector is a valid NTFS boot sector
 * @sb:		Super block of the device to which @b belongs.
 * @b:		Boot sector of device @sb to check.
 * @silent:	If 'true', all output will be silenced.
 *
 * is_boot_sector_ntfs() checks whether the boot sector @b is a valid NTFS boot
 * sector. Returns 'true' if it is valid and 'false' if not.
 *
 * @sb is only needed for warning/error output, i.e. it can be NULL when silent
 * is 'true'.
 */
static bool is_boot_sector_ntfs(const struct super_block *sb,
		const NTFS_BOOT_SECTOR *b, const bool silent)
{
	/*
	 * Check that checksum == sum of u32 values from b to the checksum
	 * field.  If checksum is zero, no checking is done.  We will work when
	 * the checksum test fails, since some utilities update the boot sector
	 * ignoring the checksum which leaves the checksum out-of-date.  We
	 * report a warning if this is the case.
	 */
	if ((void*)b < (void*)&b->checksum && b->checksum && !silent) {
		le32 *u;
		u32 i;

		for (i = 0, u = (le32*)b; u < (le32*)(&b->checksum); ++u)
			i += le32_to_cpup(u);
		if (le32_to_cpu(b->checksum) != i)
			ntfs_warning(sb, "Invalid boot sector checksum.");
	}
	/* Check OEMidentifier is "NTFS    " */
	if (b->oem_id != magicNTFS)
		goto not_ntfs;
	/* Check bytes per sector value is between 256 and 4096. */
	if (le16_to_cpu(b->bpb.bytes_per_sector) < 0x100 ||
			le16_to_cpu(b->bpb.bytes_per_sector) > 0x1000)
		goto not_ntfs;
	/* Check sectors per cluster value is valid. */
	switch (b->bpb.sectors_per_cluster) {
	case 1: case 2: case 4: case 8: case 16: case 32: case 64: case 128:
		break;
	default:
		goto not_ntfs;
	}
	/* Check the cluster size is not above the maximum (64kiB). */
	if ((u32)le16_to_cpu(b->bpb.bytes_per_sector) *
			b->bpb.sectors_per_cluster > NTFS_MAX_CLUSTER_SIZE)
		goto not_ntfs;
	/* Check reserved/unused fields are really zero. */
	if (le16_to_cpu(b->bpb.reserved_sectors) ||
			le16_to_cpu(b->bpb.root_entries) ||
			le16_to_cpu(b->bpb.sectors) ||
			le16_to_cpu(b->bpb.sectors_per_fat) ||
			le32_to_cpu(b->bpb.large_sectors) || b->bpb.fats)
		goto not_ntfs;
	/* Check clusters per file mft record value is valid. */
	if ((u8)b->clusters_per_mft_record < 0xe1 ||
			(u8)b->clusters_per_mft_record > 0xf7)
		switch (b->clusters_per_mft_record) {
		case 1: case 2: case 4: case 8: case 16: case 32: case 64:
			break;
		default:
			goto not_ntfs;
		}
	/* Check clusters per index block value is valid. */
	if ((u8)b->clusters_per_index_record < 0xe1 ||
			(u8)b->clusters_per_index_record > 0xf7)
		switch (b->clusters_per_index_record) {
		case 1: case 2: case 4: case 8: case 16: case 32: case 64:
			break;
		default:
			goto not_ntfs;
		}
	/*
	 * Check for valid end of sector marker. We will work without it, but
	 * many BIOSes will refuse to boot from a bootsector if the magic is
	 * incorrect, so we emit a warning.
	 */
	if (!silent && b->end_of_sector_marker != cpu_to_le16(0xaa55))
		ntfs_warning(sb, "Invalid end of sector marker.");
	return true;
not_ntfs:
	return false;
}

/**
 * read_ntfs_boot_sector - read the NTFS boot sector of a device
 * @sb:		super block of device to read the boot sector from
 * @silent:	if true, suppress all output
 *
 * Reads the boot sector from the device and validates it. If that fails, tries
 * to read the backup boot sector, first from the end of the device a-la NT4 and
 * later and then from the middle of the device a-la NT3.51 and before.
 *
 * If a valid boot sector is found but it is not the primary boot sector, we
 * repair the primary boot sector silently (unless the device is read-only or
 * the primary boot sector is not accessible).
 *
 * NOTE: To call this function, @sb must have the fields s_dev, the ntfs super
 * block (u.ntfs_sb), nr_blocks and the device flags (s_flags) initialized
 * to their respective values.
 *
 * Return the unlocked buffer head containing the boot sector or NULL on error.
 */
static struct buffer_head *read_ntfs_boot_sector(struct super_block *sb,
		const int silent)
{
	const char *read_err_str = "Unable to read %s boot sector.";
	struct buffer_head *bh_primary, *bh_backup;
	sector_t nr_blocks = NTFS_SB(sb)->nr_blocks;

	/* Try to read primary boot sector. */
	if ((bh_primary = sb_bread(sb, 0))) {
		if (is_boot_sector_ntfs(sb, (NTFS_BOOT_SECTOR*)
				bh_primary->b_data, silent))
			return bh_primary;
		if (!silent)
			ntfs_error(sb, "Primary boot sector is invalid.");
	} else if (!silent)
		ntfs_error(sb, read_err_str, "primary");
	if (!(NTFS_SB(sb)->on_errors & ON_ERRORS_RECOVER)) {
		if (bh_primary)
			brelse(bh_primary);
		if (!silent)
			ntfs_error(sb, "Mount option errors=recover not used. "
					"Aborting without trying to recover.");
		return NULL;
	}
	/* Try to read NT4+ backup boot sector. */
	if ((bh_backup = sb_bread(sb, nr_blocks - 1))) {
		if (is_boot_sector_ntfs(sb, (NTFS_BOOT_SECTOR*)
				bh_backup->b_data, silent))
			goto hotfix_primary_boot_sector;
		brelse(bh_backup);
	} else if (!silent)
		ntfs_error(sb, read_err_str, "backup");
	/* Try to read NT3.51- backup boot sector. */
	if ((bh_backup = sb_bread(sb, nr_blocks >> 1))) {
		if (is_boot_sector_ntfs(sb, (NTFS_BOOT_SECTOR*)
				bh_backup->b_data, silent))
			goto hotfix_primary_boot_sector;
		if (!silent)
			ntfs_error(sb, "Could not find a valid backup boot "
					"sector.");
		brelse(bh_backup);
	} else if (!silent)
		ntfs_error(sb, read_err_str, "backup");
	/* We failed. Cleanup and return. */
	if (bh_primary)
		brelse(bh_primary);
	return NULL;
hotfix_primary_boot_sector:
	if (bh_primary) {
		/*
		 * If we managed to read sector zero and the volume is not
		 * read-only, copy the found, valid backup boot sector to the
		 * primary boot sector.  Note we only copy the actual boot
		 * sector structure, not the actual whole device sector as that
		 * may be bigger and would potentially damage the $Boot system
		 * file (FIXME: Would be nice to know if the backup boot sector
		 * on a large sector device contains the whole boot loader or
		 * just the first 512 bytes).
		 */
		if (!(sb->s_flags & MS_RDONLY)) {
			ntfs_warning(sb, "Hot-fix: Recovering invalid primary "
					"boot sector from backup copy.");
			memcpy(bh_primary->b_data, bh_backup->b_data,
					NTFS_BLOCK_SIZE);
			mark_buffer_dirty(bh_primary);
			sync_dirty_buffer(bh_primary);
			if (buffer_uptodate(bh_primary)) {
				brelse(bh_backup);
				return bh_primary;
			}
			ntfs_error(sb, "Hot-fix: Device write error while "
					"recovering primary boot sector.");
		} else {
			ntfs_warning(sb, "Hot-fix: Recovery of primary boot "
					"sector failed: Read-only mount.");
		}
		brelse(bh_primary);
	}
	ntfs_warning(sb, "Using backup boot sector.");
	return bh_backup;
}

/**
 * parse_ntfs_boot_sector - parse the boot sector and store the data in @vol
 * @vol:	volume structure to initialise with data from boot sector
 * @b:		boot sector to parse
 *
 * Parse the ntfs boot sector @b and store all imporant information therein in
 * the ntfs super block @vol.  Return 'true' on success and 'false' on error.
 */
static bool parse_ntfs_boot_sector(ntfs_volume *vol, const NTFS_BOOT_SECTOR *b)
{
	unsigned int sectors_per_cluster_bits, nr_hidden_sects;
	int clusters_per_mft_record, clusters_per_index_record;
	s64 ll;

	vol->sector_size = le16_to_cpu(b->bpb.bytes_per_sector);
	vol->sector_size_bits = ffs(vol->sector_size) - 1;
	ntfs_debug("vol->sector_size = %i (0x%x)", vol->sector_size,
			vol->sector_size);
	ntfs_debug("vol->sector_size_bits = %i (0x%x)", vol->sector_size_bits,
			vol->sector_size_bits);
	if (vol->sector_size < vol->sb->s_blocksize) {
		ntfs_error(vol->sb, "Sector size (%i) is smaller than the "
				"device block size (%lu).  This is not "
				"supported.  Sorry.", vol->sector_size,
				vol->sb->s_blocksize);
		return false;
	}
	ntfs_debug("sectors_per_cluster = 0x%x", b->bpb.sectors_per_cluster);
	sectors_per_cluster_bits = ffs(b->bpb.sectors_per_cluster) - 1;
	ntfs_debug("sectors_per_cluster_bits = 0x%x",
			sectors_per_cluster_bits);
	nr_hidden_sects = le32_to_cpu(b->bpb.hidden_sectors);
	ntfs_debug("number of hidden sectors = 0x%x", nr_hidden_sects);
	vol->cluster_size = vol->sector_size << sectors_per_cluster_bits;
	vol->cluster_size_mask = vol->cluster_size - 1;
	vol->cluster_size_bits = ffs(vol->cluster_size) - 1;
	ntfs_debug("vol->cluster_size = %i (0x%x)", vol->cluster_size,
			vol->cluster_size);
	ntfs_debug("vol->cluster_size_mask = 0x%x", vol->cluster_size_mask);
	ntfs_debug("vol->cluster_size_bits = %i", vol->cluster_size_bits);
	if (vol->cluster_size < vol->sector_size) {
		ntfs_error(vol->sb, "Cluster size (%i) is smaller than the "
				"sector size (%i).  This is not supported.  "
				"Sorry.", vol->cluster_size, vol->sector_size);
		return false;
	}
	clusters_per_mft_record = b->clusters_per_mft_record;
	ntfs_debug("clusters_per_mft_record = %i (0x%x)",
			clusters_per_mft_record, clusters_per_mft_record);
	if (clusters_per_mft_record > 0)
		vol->mft_record_size = vol->cluster_size <<
				(ffs(clusters_per_mft_record) - 1);
	else
		/*
		 * When mft_record_size < cluster_size, clusters_per_mft_record
		 * = -log2(mft_record_size) bytes. mft_record_size normaly is
		 * 1024 bytes, which is encoded as 0xF6 (-10 in decimal).
		 */
		vol->mft_record_size = 1 << -clusters_per_mft_record;
	vol->mft_record_size_mask = vol->mft_record_size - 1;
	vol->mft_record_size_bits = ffs(vol->mft_record_size) - 1;
	ntfs_debug("vol->mft_record_size = %i (0x%x)", vol->mft_record_size,
			vol->mft_record_size);
	ntfs_debug("vol->mft_record_size_mask = 0x%x",
			vol->mft_record_size_mask);
	ntfs_debug("vol->mft_record_size_bits = %i (0x%x)",
			vol->mft_record_size_bits, vol->mft_record_size_bits);
	/*
	 * We cannot support mft record sizes above the PAGE_CACHE_SIZE since
	 * we store $MFT/$DATA, the table of mft records in the page cache.
	 */
	if (vol->mft_record_size > PAGE_CACHE_SIZE) {
		ntfs_error(vol->sb, "Mft record size (%i) exceeds the "
				"PAGE_CACHE_SIZE on your system (%lu).  "
				"This is not supported.  Sorry.",
				vol->mft_record_size, PAGE_CACHE_SIZE);
		return false;
	}
	/* We cannot support mft record sizes below the sector size. */
	if (vol->mft_record_size < vol->sector_size) {
		ntfs_error(vol->sb, "Mft record size (%i) is smaller than the "
				"sector size (%i).  This is not supported.  "
				"Sorry.", vol->mft_record_size,
				vol->sector_size);
		return false;
	}
	clusters_per_index_record = b->clusters_per_index_record;
	ntfs_debug("clusters_per_index_record = %i (0x%x)",
			clusters_per_index_record, clusters_per_index_record);
	if (clusters_per_index_record > 0)
		vol->index_record_size = vol->cluster_size <<
				(ffs(clusters_per_index_record) - 1);
	else
		/*
		 * When index_record_size < cluster_size,
		 * clusters_per_index_record = -log2(index_record_size) bytes.
		 * index_record_size normaly equals 4096 bytes, which is
		 * encoded as 0xF4 (-12 in decimal).
		 */
		vol->index_record_size = 1 << -clusters_per_index_record;
	vol->index_record_size_mask = vol->index_record_size - 1;
	vol->index_record_size_bits = ffs(vol->index_record_size) - 1;
	ntfs_debug("vol->index_record_size = %i (0x%x)",
			vol->index_record_size, vol->index_record_size);
	ntfs_debug("vol->index_record_size_mask = 0x%x",
			vol->index_record_size_mask);
	ntfs_debug("vol->index_record_size_bits = %i (0x%x)",
			vol->index_record_size_bits,
			vol->index_record_size_bits);
	/* We cannot support index record sizes below the sector size. */
	if (vol->index_record_size < vol->sector_size) {
		ntfs_error(vol->sb, "Index record size (%i) is smaller than "
				"the sector size (%i).  This is not "
				"supported.  Sorry.", vol->index_record_size,
				vol->sector_size);
		return false;
	}
	/*
	 * Get the size of the volume in clusters and check for 64-bit-ness.
	 * Windows currently only uses 32 bits to save the clusters so we do
	 * the same as it is much faster on 32-bit CPUs.
	 */
	ll = sle64_to_cpu(b->number_of_sectors) >> sectors_per_cluster_bits;
	if ((u64)ll >= 1ULL << 32) {
		ntfs_error(vol->sb, "Cannot handle 64-bit clusters.  Sorry.");
		return false;
	}
	vol->nr_clusters = ll;
	ntfs_debug("vol->nr_clusters = 0x%llx", (long long)vol->nr_clusters);
	/*
	 * On an architecture where unsigned long is 32-bits, we restrict the
	 * volume size to 2TiB (2^41). On a 64-bit architecture, the compiler
	 * will hopefully optimize the whole check away.
	 */
	if (sizeof(unsigned long) < 8) {
		if ((ll << vol->cluster_size_bits) >= (1ULL << 41)) {
			ntfs_error(vol->sb, "Volume size (%lluTiB) is too "
					"large for this architecture.  "
					"Maximum supported is 2TiB.  Sorry.",
					(unsigned long long)ll >> (40 -
					vol->cluster_size_bits));
			return false;
		}
	}
	ll = sle64_to_cpu(b->mft_lcn);
	if (ll >= vol->nr_clusters) {
		ntfs_error(vol->sb, "MFT LCN (%lli, 0x%llx) is beyond end of "
				"volume.  Weird.", (unsigned long long)ll,
				(unsigned long long)ll);
		return false;
	}
	vol->mft_lcn = ll;
	ntfs_debug("vol->mft_lcn = 0x%llx", (long long)vol->mft_lcn);
	ll = sle64_to_cpu(b->mftmirr_lcn);
	if (ll >= vol->nr_clusters) {
		ntfs_error(vol->sb, "MFTMirr LCN (%lli, 0x%llx) is beyond end "
				"of volume.  Weird.", (unsigned long long)ll,
				(unsigned long long)ll);
		return false;
	}
	vol->mftmirr_lcn = ll;
	ntfs_debug("vol->mftmirr_lcn = 0x%llx", (long long)vol->mftmirr_lcn);
#ifdef NTFS_RW
	/*
	 * Work out the size of the mft mirror in number of mft records. If the
	 * cluster size is less than or equal to the size taken by four mft
	 * records, the mft mirror stores the first four mft records. If the
	 * cluster size is bigger than the size taken by four mft records, the
	 * mft mirror contains as many mft records as will fit into one
	 * cluster.
	 */
	if (vol->cluster_size <= (4 << vol->mft_record_size_bits))
		vol->mftmirr_size = 4;
	else
		vol->mftmirr_size = vol->cluster_size >>
				vol->mft_record_size_bits;
	ntfs_debug("vol->mftmirr_size = %i", vol->mftmirr_size);
#endif /* NTFS_RW */
	vol->serial_no = le64_to_cpu(b->volume_serial_number);
	ntfs_debug("vol->serial_no = 0x%llx",
			(unsigned long long)vol->serial_no);
	return true;
}

/**
 * ntfs_setup_allocators - initialize the cluster and mft allocators
 * @vol:	volume structure for which to setup the allocators
 *
 * Setup the cluster (lcn) and mft allocators to the starting values.
 */
static void ntfs_setup_allocators(ntfs_volume *vol)
{
#ifdef NTFS_RW
	LCN mft_zone_size, mft_lcn;
#endif /* NTFS_RW */

	ntfs_debug("vol->mft_zone_multiplier = 0x%x",
			vol->mft_zone_multiplier);
#ifdef NTFS_RW
	/* Determine the size of the MFT zone. */
	mft_zone_size = vol->nr_clusters;
	switch (vol->mft_zone_multiplier) {  /* % of volume size in clusters */
	case 4:
		mft_zone_size >>= 1;			/* 50%   */
		break;
	case 3:
		mft_zone_size = (mft_zone_size +
				(mft_zone_size >> 1)) >> 2;	/* 37.5% */
		break;
	case 2:
		mft_zone_size >>= 2;			/* 25%   */
		break;
	/* case 1: */
	default:
		mft_zone_size >>= 3;			/* 12.5% */
		break;
	}
	/* Setup the mft zone. */
	vol->mft_zone_start = vol->mft_zone_pos = vol->mft_lcn;
	ntfs_debug("vol->mft_zone_pos = 0x%llx",
			(unsigned long long)vol->mft_zone_pos);
	/*
	 * Calculate the mft_lcn for an unmodified NTFS volume (see mkntfs
	 * source) and if the actual mft_lcn is in the expected place or even
	 * further to the front of the volume, extend the mft_zone to cover the
	 * beginning of the volume as well.  This is in order to protect the
	 * area reserved for the mft bitmap as well within the mft_zone itself.
	 * On non-standard volumes we do not protect it as the overhead would
	 * be higher than the speed increase we would get by doing it.
	 */
	mft_lcn = (8192 + 2 * vol->cluster_size - 1) / vol->cluster_size;
	if (mft_lcn * vol->cluster_size < 16 * 1024)
		mft_lcn = (16 * 1024 + vol->cluster_size - 1) /
				vol->cluster_size;
	if (vol->mft_zone_start <= mft_lcn)
		vol->mft_zone_start = 0;
	ntfs_debug("vol->mft_zone_start = 0x%llx",
			(unsigned long long)vol->mft_zone_start);
	/*
	 * Need to cap the mft zone on non-standard volumes so that it does
	 * not point outside the boundaries of the volume.  We do this by
	 * halving the zone size until we are inside the volume.
	 */
	vol->mft_zone_end = vol->mft_lcn + mft_zone_size;
	while (vol->mft_zone_end >= vol->nr_clusters) {
		mft_zone_size >>= 1;
		vol->mft_zone_end = vol->mft_lcn + mft_zone_size;
	}
	ntfs_debug("vol->mft_zone_end = 0x%llx",
			(unsigned long long)vol->mft_zone_end);
	/*
	 * Set the current position within each data zone to the start of the
	 * respective zone.
	 */
	vol->data1_zone_pos = vol->mft_zone_end;
	ntfs_debug("vol->data1_zone_pos = 0x%llx",
			(unsigned long long)vol->data1_zone_pos);
	vol->data2_zone_pos = 0;
	ntfs_debug("vol->data2_zone_pos = 0x%llx",
			(unsigned long long)vol->data2_zone_pos);

	/* Set the mft data allocation position to mft record 24. */
	vol->mft_data_pos = 24;
	ntfs_debug("vol->mft_data_pos = 0x%llx",
			(unsigned long long)vol->mft_data_pos);
#endif /* NTFS_RW */
}

#ifdef NTFS_RW

/**
 * load_and_init_mft_mirror - load and setup the mft mirror inode for a volume
 * @vol:	ntfs super block describing device whose mft mirror to load
 *
 * Return 'true' on success or 'false' on error.
 */
static bool load_and_init_mft_mirror(ntfs_volume *vol)
{
	struct inode *tmp_ino;
	ntfs_inode *tmp_ni;

	ntfs_debug("Entering.");
	/* Get mft mirror inode. */
	tmp_ino = ntfs_iget(vol->sb, FILE_MFTMirr);
	if (IS_ERR(tmp_ino) || is_bad_inode(tmp_ino)) {
		if (!IS_ERR(tmp_ino))
			iput(tmp_ino);
		/* Caller will display error message. */
		return false;
	}
	/*
	 * Re-initialize some specifics about $MFTMirr's inode as
	 * ntfs_read_inode() will have set up the default ones.
	 */
	/* Set uid and gid to root. */
	tmp_ino->i_uid = GLOBAL_ROOT_UID;
	tmp_ino->i_gid = GLOBAL_ROOT_GID;
	/* Regular file.  No access for anyone. */
	tmp_ino->i_mode = S_IFREG;
	/* No VFS initiated operations allowed for $MFTMirr. */
	tmp_ino->i_op = &ntfs_empty_inode_ops;
	tmp_ino->i_fop = &ntfs_empty_file_ops;
	/* Put in our special address space operations. */
	tmp_ino->i_mapping->a_ops = &ntfs_mst_aops;
	tmp_ni = NTFS_I(tmp_ino);
	/* The $MFTMirr, like the $MFT is multi sector transfer protected. */
	NInoSetMstProtected(tmp_ni);
	NInoSetSparseDisabled(tmp_ni);
	/*
	 * Set up our little cheat allowing us to reuse the async read io
	 * completion handler for directories.
	 */
	tmp_ni->itype.index.block_size = vol->mft_record_size;
	tmp_ni->itype.index.block_size_bits = vol->mft_record_size_bits;
	vol->mftmirr_ino = tmp_ino;
	ntfs_debug("Done.");
	return true;
}

/**
 * check_mft_mirror - compare contents of the mft mirror with the mft
 * @vol:	ntfs super block describing device whose mft mirror to check
 *
 * Return 'true' on success or 'false' on error.
 *
 * Note, this function also results in the mft mirror runlist being completely
 * mapped into memory.  The mft mirror write code requires this and will BUG()
 * should it find an unmapped runlist element.
 */
static bool check_mft_mirror(ntfs_volume *vol)
{
	struct super_block *sb = vol->sb;
	ntfs_inode *mirr_ni;
	struct page *mft_page, *mirr_page;
	u8 *kmft, *kmirr;
	runlist_element *rl, rl2[2];
	pgoff_t index;
	int mrecs_per_page, i;

	ntfs_debug("Entering.");
	/* Compare contents of $MFT and $MFTMirr. */
	mrecs_per_page = PAGE_CACHE_SIZE / vol->mft_record_size;
	BUG_ON(!mrecs_per_page);
	BUG_ON(!vol->mftmirr_size);
	mft_page = mirr_page = NULL;
	kmft = kmirr = NULL;
	index = i = 0;
	do {
		u32 bytes;

		/* Switch pages if necessary. */
		if (!(i % mrecs_per_page)) {
			if (index) {
				ntfs_unmap_page(mft_page);
				ntfs_unmap_page(mirr_page);
			}
			/* Get the $MFT page. */
			mft_page = ntfs_map_page(vol->mft_ino->i_mapping,
					index);
			if (IS_ERR(mft_page)) {
				ntfs_error(sb, "Failed to read $MFT.");
				return false;
			}
			kmft = page_address(mft_page);
			/* Get the $MFTMirr page. */
			mirr_page = ntfs_map_page(vol->mftmirr_ino->i_mapping,
					index);
			if (IS_ERR(mirr_page)) {
				ntfs_error(sb, "Failed to read $MFTMirr.");
				goto mft_unmap_out;
			}
			kmirr = page_address(mirr_page);
			++index;
		}
		/* Do not check the record if it is not in use. */
		if (((MFT_RECORD*)kmft)->flags & MFT_RECORD_IN_USE) {
			/* Make sure the record is ok. */
			if (ntfs_is_baad_recordp((le32*)kmft)) {
				ntfs_error(sb, "Incomplete multi sector "
						"transfer detected in mft "
						"record %i.", i);
mm_unmap_out:
				ntfs_unmap_page(mirr_page);
mft_unmap_out:
				ntfs_unmap_page(mft_page);
				return false;
			}
		}
		/* Do not check the mirror record if it is not in use. */
		if (((MFT_RECORD*)kmirr)->flags & MFT_RECORD_IN_USE) {
			if (ntfs_is_baad_recordp((le32*)kmirr)) {
				ntfs_error(sb, "Incomplete multi sector "
						"transfer detected in mft "
						"mirror record %i.", i);
				goto mm_unmap_out;
			}
		}
		/* Get the amount of data in the current record. */
		bytes = le32_to_cpu(((MFT_RECORD*)kmft)->bytes_in_use);
		if (bytes < sizeof(MFT_RECORD_OLD) ||
				bytes > vol->mft_record_size ||
				ntfs_is_baad_recordp((le32*)kmft)) {
			bytes = le32_to_cpu(((MFT_RECORD*)kmirr)->bytes_in_use);
			if (bytes < sizeof(MFT_RECORD_OLD) ||
					bytes > vol->mft_record_size ||
					ntfs_is_baad_recordp((le32*)kmirr))
				bytes = vol->mft_record_size;
		}
		/* Compare the two records. */
		if (memcmp(kmft, kmirr, bytes)) {
			ntfs_error(sb, "$MFT and $MFTMirr (record %i) do not "
					"match.  Run ntfsfix or chkdsk.", i);
			goto mm_unmap_out;
		}
		kmft += vol->mft_record_size;
		kmirr += vol->mft_record_size;
	} while (++i < vol->mftmirr_size);
	/* Release the last pages. */
	ntfs_unmap_page(mft_page);
	ntfs_unmap_page(mirr_page);

	/* Construct the mft mirror runlist by hand. */
	rl2[0].vcn = 0;
	rl2[0].lcn = vol->mftmirr_lcn;
	rl2[0].length = (vol->mftmirr_size * vol->mft_record_size +
			vol->cluster_size - 1) / vol->cluster_size;
	rl2[1].vcn = rl2[0].length;
	rl2[1].lcn = LCN_ENOENT;
	rl2[1].length = 0;
	/*
	 * Because we have just read all of the mft mirror, we know we have
	 * mapped the full runlist for it.
	 */
	mirr_ni = NTFS_I(vol->mftmirr_ino);
	down_read(&mirr_ni->runlist.lock);
	rl = mirr_ni->runlist.rl;
	/* Compare the two runlists.  They must be identical. */
	i = 0;
	do {
		if (rl2[i].vcn != rl[i].vcn || rl2[i].lcn != rl[i].lcn ||
				rl2[i].length != rl[i].length) {
			ntfs_error(sb, "$MFTMirr location mismatch.  "
					"Run chkdsk.");
			up_read(&mirr_ni->runlist.lock);
			return false;
		}
	} while (rl2[i++].length);
	up_read(&mirr_ni->runlist.lock);
	ntfs_debug("Done.");
	return true;
}

/**
 * load_and_check_logfile - load and check the logfile inode for a volume
 * @vol:	ntfs super block describing device whose logfile to load
 *
 * Return 'true' on success or 'false' on error.
 */
static bool load_and_check_logfile(ntfs_volume *vol,
		RESTART_PAGE_HEADER **rp)
{
	struct inode *tmp_ino;

	ntfs_debug("Entering.");
	tmp_ino = ntfs_iget(vol->sb, FILE_LogFile);
	if (IS_ERR(tmp_ino) || is_bad_inode(tmp_ino)) {
		if (!IS_ERR(tmp_ino))
			iput(tmp_ino);
		/* Caller will display error message. */
		return false;
	}
	if (!ntfs_check_logfile(tmp_ino, rp)) {
		iput(tmp_ino);
		/* ntfs_check_logfile() will have displayed error output. */
		return false;
	}
	NInoSetSparseDisabled(NTFS_I(tmp_ino));
	vol->logfile_ino = tmp_ino;
	ntfs_debug("Done.");
	return true;
}

#define NTFS_HIBERFIL_HEADER_SIZE	4096

/**
 * check_windows_hibernation_status - check if Windows is suspended on a volume
 * @vol:	ntfs super block of device to check
 *
 * Check if Windows is hibernated on the ntfs volume @vol.  This is done by
 * looking for the file hiberfil.sys in the root directory of the volume.  If
 * the file is not present Windows is definitely not suspended.
 *
 * If hiberfil.sys exists and is less than 4kiB in size it means Windows is
 * definitely suspended (this volume is not the system volume).  Caveat:  on a
 * system with many volumes it is possible that the < 4kiB check is bogus but
 * for now this should do fine.
 *
 * If hiberfil.sys exists and is larger than 4kiB in size, we need to read the
 * hiberfil header (which is the first 4kiB).  If this begins with "hibr",
 * Windows is definitely suspended.  If it is completely full of zeroes,
 * Windows is definitely not hibernated.  Any other case is treated as if
 * Windows is suspended.  This caters for the above mentioned caveat of a
 * system with many volumes where no "hibr" magic would be present and there is
 * no zero header.
 *
 * Return 0 if Windows is not hibernated on the volume, >0 if Windows is
 * hibernated on the volume, and -errno on error.
 */
static int check_windows_hibernation_status(ntfs_volume *vol)
{
	MFT_REF mref;
	struct inode *vi;
	struct page *page;
	u32 *kaddr, *kend;
	ntfs_name *name = NULL;
	int ret = 1;
	static const ntfschar hiberfil[13] = { cpu_to_le16('h'),
			cpu_to_le16('i'), cpu_to_le16('b'),
			cpu_to_le16('e'), cpu_to_le16('r'),
			cpu_to_le16('f'), cpu_to_le16('i'),
			cpu_to_le16('l'), cpu_to_le16('.'),
			cpu_to_le16('s'), cpu_to_le16('y'),
			cpu_to_le16('s'), 0 };

	ntfs_debug("Entering.");
	/*
	 * Find the inode number for the hibernation file by looking up the
	 * filename hiberfil.sys in the root directory.
	 */
	mutex_lock(&vol->root_ino->i_mutex);
	mref = ntfs_lookup_inode_by_name(NTFS_I(vol->root_ino), hiberfil, 12,
			&name);
	mutex_unlock(&vol->root_ino->i_mutex);
	if (IS_ERR_MREF(mref)) {
		ret = MREF_ERR(mref);
		/* If the file does not exist, Windows is not hibernated. */
		if (ret == -ENOENT) {
			ntfs_debug("hiberfil.sys not present.  Windows is not "
					"hibernated on the volume.");
			return 0;
		}
		/* A real error occurred. */
		ntfs_error(vol->sb, "Failed to find inode number for "
				"hiberfil.sys.");
		return ret;
	}
	/* We do not care for the type of match that was found. */
	kfree(name);
	/* Get the inode. */
	vi = ntfs_iget(vol->sb, MREF(mref));
	if (IS_ERR(vi) || is_bad_inode(vi)) {
		if (!IS_ERR(vi))
			iput(vi);
		ntfs_error(vol->sb, "Failed to load hiberfil.sys.");
		return IS_ERR(vi) ? PTR_ERR(vi) : -EIO;
	}
	if (unlikely(i_size_read(vi) < NTFS_HIBERFIL_HEADER_SIZE)) {
		ntfs_debug("hiberfil.sys is smaller than 4kiB (0x%llx).  "
				"Windows is hibernated on the volume.  This "
				"is not the system volume.", i_size_read(vi));
		goto iput_out;
	}
	page = ntfs_map_page(vi->i_mapping, 0);
	if (IS_ERR(page)) {
		ntfs_error(vol->sb, "Failed to read from hiberfil.sys.");
		ret = PTR_ERR(page);
		goto iput_out;
	}
	kaddr = (u32*)page_address(page);
	if (*(le32*)kaddr == cpu_to_le32(0x72626968)/*'hibr'*/) {
		ntfs_debug("Magic \"hibr\" found in hiberfil.sys.  Windows is "
				"hibernated on the volume.  This is the "
				"system volume.");
		goto unm_iput_out;
	}
	kend = kaddr + NTFS_HIBERFIL_HEADER_SIZE/sizeof(*kaddr);
	do {
		if (unlikely(*kaddr)) {
			ntfs_debug("hiberfil.sys is larger than 4kiB "
					"(0x%llx), does not contain the "
					"\"hibr\" magic, and does not have a "
					"zero header.  Windows is hibernated "
					"on the volume.  This is not the "
					"system volume.", i_size_read(vi));
			goto unm_iput_out;
		}
	} while (++kaddr < kend);
	ntfs_debug("hiberfil.sys contains a zero header.  Windows is not "
			"hibernated on the volume.  This is the system "
			"volume.");
	ret = 0;
unm_iput_out:
	ntfs_unmap_page(page);
iput_out:
	iput(vi);
	return ret;
}

/**
 * load_and_init_quota - load and setup the quota file for a volume if present
 * @vol:	ntfs super block describing device whose quota file to load
 *
 * Return 'true' on success or 'false' on error.  If $Quota is not present, we
 * leave vol->quota_ino as NULL and return success.
 */
static bool load_and_init_quota(ntfs_volume *vol)
{
	MFT_REF mref;
	struct inode *tmp_ino;
	ntfs_name *name = NULL;
	static const ntfschar Quota[7] = { cpu_to_le16('$'),
			cpu_to_le16('Q'), cpu_to_le16('u'),
			cpu_to_le16('o'), cpu_to_le16('t'),
			cpu_to_le16('a'), 0 };
	static ntfschar Q[3] = { cpu_to_le16('$'),
			cpu_to_le16('Q'), 0 };

	ntfs_debug("Entering.");
	/*
	 * Find the inode number for the quota file by looking up the filename
	 * $Quota in the extended system files directory $Extend.
	 */
	mutex_lock(&vol->extend_ino->i_mutex);
	mref = ntfs_lookup_inode_by_name(NTFS_I(vol->extend_ino), Quota, 6,
			&name);
	mutex_unlock(&vol->extend_ino->i_mutex);
	if (IS_ERR_MREF(mref)) {
		/*
		 * If the file does not exist, quotas are disabled and have
		 * never been enabled on this volume, just return success.
		 */
		if (MREF_ERR(mref) == -ENOENT) {
			ntfs_debug("$Quota not present.  Volume does not have "
					"quotas enabled.");
			/*
			 * No need to try to set quotas out of date if they are
			 * not enabled.
			 */
			NVolSetQuotaOutOfDate(vol);
			return true;
		}
		/* A real error occurred. */
		ntfs_error(vol->sb, "Failed to find inode number for $Quota.");
		return false;
	}
	/* We do not care for the type of match that was found. */
	kfree(name);
	/* Get the inode. */
	tmp_ino = ntfs_iget(vol->sb, MREF(mref));
	if (IS_ERR(tmp_ino) || is_bad_inode(tmp_ino)) {
		if (!IS_ERR(tmp_ino))
			iput(tmp_ino);
		ntfs_error(vol->sb, "Failed to load $Quota.");
		return false;
	}
	vol->quota_ino = tmp_ino;
	/* Get the $Q index allocation attribute. */
	tmp_ino = ntfs_index_iget(vol->quota_ino, Q, 2);
	if (IS_ERR(tmp_ino)) {
		ntfs_error(vol->sb, "Failed to load $Quota/$Q index.");
		return false;
	}
	vol->quota_q_ino = tmp_ino;
	ntfs_debug("Done.");
	return true;
}

/**
 * load_and_init_usnjrnl - load and setup the transaction log if present
 * @vol:	ntfs super block describing device whose usnjrnl file to load
 *
 * Return 'true' on success or 'false' on error.
 *
 * If $UsnJrnl is not present or in the process of being disabled, we set
 * NVolUsnJrnlStamped() and return success.
 *
 * If the $UsnJrnl $DATA/$J attribute has a size equal to the lowest valid usn,
 * i.e. transaction logging has only just been enabled or the journal has been
 * stamped and nothing has been logged since, we also set NVolUsnJrnlStamped()
 * and return success.
 */
static bool load_and_init_usnjrnl(ntfs_volume *vol)
{
	MFT_REF mref;
	struct inode *tmp_ino;
	ntfs_inode *tmp_ni;
	struct page *page;
	ntfs_name *name = NULL;
	USN_HEADER *uh;
	static const ntfschar UsnJrnl[9] = { cpu_to_le16('$'),
			cpu_to_le16('U'), cpu_to_le16('s'),
			cpu_to_le16('n'), cpu_to_le16('J'),
			cpu_to_le16('r'), cpu_to_le16('n'),
			cpu_to_le16('l'), 0 };
	static ntfschar Max[5] = { cpu_to_le16('$'),
			cpu_to_le16('M'), cpu_to_le16('a'),
			cpu_to_le16('x'), 0 };
	static ntfschar J[3] = { cpu_to_le16('$'),
			cpu_to_le16('J'), 0 };

	ntfs_debug("Entering.");
	/*
	 * Find the inode number for the transaction log file by looking up the
	 * filename $UsnJrnl in the extended system files directory $Extend.
	 */
	mutex_lock(&vol->extend_ino->i_mutex);
	mref = ntfs_lookup_inode_by_name(NTFS_I(vol->extend_ino), UsnJrnl, 8,
			&name);
	mutex_unlock(&vol->extend_ino->i_mutex);
	if (IS_ERR_MREF(mref)) {
		/*
		 * If the file does not exist, transaction logging is disabled,
		 * just return success.
		 */
		if (MREF_ERR(mref) == -ENOENT) {
			ntfs_debug("$UsnJrnl not present.  Volume does not "
					"have transaction logging enabled.");
not_enabled:
			/*
			 * No need to try to stamp the transaction log if
			 * transaction logging is not enabled.
			 */
			NVolSetUsnJrnlStamped(vol);
			return true;
		}
		/* A real error occurred. */
		ntfs_error(vol->sb, "Failed to find inode number for "
				"$UsnJrnl.");
		return false;
	}
	/* We do not care for the type of match that was found. */
	kfree(name);
	/* Get the inode. */
	tmp_ino = ntfs_iget(vol->sb, MREF(mref));
	if (unlikely(IS_ERR(tmp_ino) || is_bad_inode(tmp_ino))) {
		if (!IS_ERR(tmp_ino))
			iput(tmp_ino);
		ntfs_error(vol->sb, "Failed to load $UsnJrnl.");
		return false;
	}
	vol->usnjrnl_ino = tmp_ino;
	/*
	 * If the transaction log is in the process of being deleted, we can
	 * ignore it.
	 */
	if (unlikely(vol->vol_flags & VOLUME_DELETE_USN_UNDERWAY)) {
		ntfs_debug("$UsnJrnl in the process of being disabled.  "
				"Volume does not have transaction logging "
				"enabled.");
		goto not_enabled;
	}
	/* Get the $DATA/$Max attribute. */
	tmp_ino = ntfs_attr_iget(vol->usnjrnl_ino, AT_DATA, Max, 4);
	if (IS_ERR(tmp_ino)) {
		ntfs_error(vol->sb, "Failed to load $UsnJrnl/$DATA/$Max "
				"attribute.");
		return false;
	}
	vol->usnjrnl_max_ino = tmp_ino;
	if (unlikely(i_size_read(tmp_ino) < sizeof(USN_HEADER))) {
		ntfs_error(vol->sb, "Found corrupt $UsnJrnl/$DATA/$Max "
				"attribute (size is 0x%llx but should be at "
				"least 0x%zx bytes).", i_size_read(tmp_ino),
				sizeof(USN_HEADER));
		return false;
	}
	/* Get the $DATA/$J attribute. */
	tmp_ino = ntfs_attr_iget(vol->usnjrnl_ino, AT_DATA, J, 2);
	if (IS_ERR(tmp_ino)) {
		ntfs_error(vol->sb, "Failed to load $UsnJrnl/$DATA/$J "
				"attribute.");
		return false;
	}
	vol->usnjrnl_j_ino = tmp_ino;
	/* Verify $J is non-resident and sparse. */
	tmp_ni = NTFS_I(vol->usnjrnl_j_ino);
	if (unlikely(!NInoNonResident(tmp_ni) || !NInoSparse(tmp_ni))) {
		ntfs_error(vol->sb, "$UsnJrnl/$DATA/$J attribute is resident "
				"and/or not sparse.");
		return false;
	}
	/* Read the USN_HEADER from $DATA/$Max. */
	page = ntfs_map_page(vol->usnjrnl_max_ino->i_mapping, 0);
	if (IS_ERR(page)) {
		ntfs_error(vol->sb, "Failed to read from $UsnJrnl/$DATA/$Max "
				"attribute.");
		return false;
	}
	uh = (USN_HEADER*)page_address(page);
	/* Sanity check the $Max. */
	if (unlikely(sle64_to_cpu(uh->allocation_delta) >
			sle64_to_cpu(uh->maximum_size))) {
		ntfs_error(vol->sb, "Allocation delta (0x%llx) exceeds "
				"maximum size (0x%llx).  $UsnJrnl is corrupt.",
				(long long)sle64_to_cpu(uh->allocation_delta),
				(long long)sle64_to_cpu(uh->maximum_size));
		ntfs_unmap_page(page);
		return false;
	}
	/*
	 * If the transaction log has been stamped and nothing has been written
	 * to it since, we do not need to stamp it.
	 */
	if (unlikely(sle64_to_cpu(uh->lowest_valid_usn) >=
			i_size_read(vol->usnjrnl_j_ino))) {
		if (likely(sle64_to_cpu(uh->lowest_valid_usn) ==
				i_size_read(vol->usnjrnl_j_ino))) {
			ntfs_unmap_page(page);
			ntfs_debug("$UsnJrnl is enabled but nothing has been "
					"logged since it was last stamped.  "
					"Treating this as if the volume does "
					"not have transaction logging "
					"enabled.");
			goto not_enabled;
		}
		ntfs_error(vol->sb, "$UsnJrnl has lowest valid usn (0x%llx) "
				"which is out of bounds (0x%llx).  $UsnJrnl "
				"is corrupt.",
				(long long)sle64_to_cpu(uh->lowest_valid_usn),
				i_size_read(vol->usnjrnl_j_ino));
		ntfs_unmap_page(page);
		return false;
	}
	ntfs_unmap_page(page);
	ntfs_debug("Done.");
	return true;
}

/**
 * load_and_init_attrdef - load the attribute definitions table for a volume
 * @vol:	ntfs super block describing device whose attrdef to load
 *
 * Return 'true' on success or 'false' on error.
 */
static bool load_and_init_attrdef(ntfs_volume *vol)
{
	loff_t i_size;
	struct super_block *sb = vol->sb;
	struct inode *ino;
	struct page *page;
	pgoff_t index, max_index;
	unsigned int size;

	ntfs_debug("Entering.");
	/* Read attrdef table and setup vol->attrdef and vol->attrdef_size. */
	ino = ntfs_iget(sb, FILE_AttrDef);
	if (IS_ERR(ino) || is_bad_inode(ino)) {
		if (!IS_ERR(ino))
			iput(ino);
		goto failed;
	}
	NInoSetSparseDisabled(NTFS_I(ino));
	/* The size of FILE_AttrDef must be above 0 and fit inside 31 bits. */
	i_size = i_size_read(ino);
	if (i_size <= 0 || i_size > 0x7fffffff)
		goto iput_failed;
	vol->attrdef = (ATTR_DEF*)ntfs_malloc_nofs(i_size);
	if (!vol->attrdef)
		goto iput_failed;
	index = 0;
	max_index = i_size >> PAGE_CACHE_SHIFT;
	size = PAGE_CACHE_SIZE;
	while (index < max_index) {
		/* Read the attrdef table and copy it into the linear buffer. */
read_partial_attrdef_page:
		page = ntfs_map_page(ino->i_mapping, index);
		if (IS_ERR(page))
			goto free_iput_failed;
		memcpy((u8*)vol->attrdef + (index++ << PAGE_CACHE_SHIFT),
				page_address(page), size);
		ntfs_unmap_page(page);
	};
	if (size == PAGE_CACHE_SIZE) {
		size = i_size & ~PAGE_CACHE_MASK;
		if (size)
			goto read_partial_attrdef_page;
	}
	vol->attrdef_size = i_size;
	ntfs_debug("Read %llu bytes from $AttrDef.", i_size);
	iput(ino);
	return true;
free_iput_failed:
	ntfs_free(vol->attrdef);
	vol->attrdef = NULL;
iput_failed:
	iput(ino);
failed:
	ntfs_error(sb, "Failed to initialize attribute definition table.");
	return false;
}

#endif /* NTFS_RW */

/**
 * load_and_init_upcase - load the upcase table for an ntfs volume
 * @vol:	ntfs super block describing device whose upcase to load
 *
 * Return 'true' on success or 'false' on error.
 */
static bool load_and_init_upcase(ntfs_volume *vol)
{
	loff_t i_size;
	struct super_block *sb = vol->sb;
	struct inode *ino;
	struct page *page;
	pgoff_t index, max_index;
	unsigned int size;
	int i, max;

	ntfs_debug("Entering.");
	/* Read upcase table and setup vol->upcase and vol->upcase_len. */
	ino = ntfs_iget(sb, FILE_UpCase);
	if (IS_ERR(ino) || is_bad_inode(ino)) {
		if (!IS_ERR(ino))
			iput(ino);
		goto upcase_failed;
	}
	/*
	 * The upcase size must not be above 64k Unicode characters, must not
	 * be zero and must be a multiple of sizeof(ntfschar).
	 */
	i_size = i_size_read(ino);
	if (!i_size || i_size & (sizeof(ntfschar) - 1) ||
			i_size > 64ULL * 1024 * sizeof(ntfschar))
		goto iput_upcase_failed;
	vol->upcase = (ntfschar*)ntfs_malloc_nofs(i_size);
	if (!vol->upcase)
		goto iput_upcase_failed;
	index = 0;
	max_index = i_size >> PAGE_CACHE_SHIFT;
	size = PAGE_CACHE_SIZE;
	while (index < max_index) {
		/* Read the upcase table and copy it into the linear buffer. */
read_partial_upcase_page:
		page = ntfs_map_page(ino->i_mapping, index);
		if (IS_ERR(page))
			goto iput_upcase_failed;
		memcpy((char*)vol->upcase + (index++ << PAGE_CACHE_SHIFT),
				page_address(page), size);
		ntfs_unmap_page(page);
	};
	if (size == PAGE_CACHE_SIZE) {
		size = i_size & ~PAGE_CACHE_MASK;
		if (size)
			goto read_partial_upcase_page;
	}
	vol->upcase_len = i_size >> UCHAR_T_SIZE_BITS;
	ntfs_debug("Read %llu bytes from $UpCase (expected %zu bytes).",
			i_size, 64 * 1024 * sizeof(ntfschar));
	iput(ino);
	mutex_lock(&ntfs_lock);
	if (!default_upcase) {
		ntfs_debug("Using volume specified $UpCase since default is "
				"not present.");
		mutex_unlock(&ntfs_lock);
		return true;
	}
	max = default_upcase_len;
	if (max > vol->upcase_len)
		max = vol->upcase_len;
	for (i = 0; i < max; i++)
		if (vol->upcase[i] != default_upcase[i])
			break;
	if (i == max) {
		ntfs_free(vol->upcase);
		vol->upcase = default_upcase;
		vol->upcase_len = max;
		ntfs_nr_upcase_users++;
		mutex_unlock(&ntfs_lock);
		ntfs_debug("Volume specified $UpCase matches default. Using "
				"default.");
		return true;
	}
	mutex_unlock(&ntfs_lock);
	ntfs_debug("Using volume specified $UpCase since it does not match "
			"the default.");
	return true;
iput_upcase_failed:
	iput(ino);
	ntfs_free(vol->upcase);
	vol->upcase = NULL;
upcase_failed:
	mutex_lock(&ntfs_lock);
	if (default_upcase) {
		vol->upcase = default_upcase;
		vol->upcase_len = default_upcase_len;
		ntfs_nr_upcase_users++;
		mutex_unlock(&ntfs_lock);
		ntfs_error(sb, "Failed to load $UpCase from the volume. Using "
				"default.");
		return true;
	}
	mutex_unlock(&ntfs_lock);
	ntfs_error(sb, "Failed to initialize upcase table.");
	return false;
}

/*
 * The lcn and mft bitmap inodes are NTFS-internal inodes with
 * their own special locking rules:
 */
static struct lock_class_key
	lcnbmp_runlist_lock_key, lcnbmp_mrec_lock_key,
	mftbmp_runlist_lock_key, mftbmp_mrec_lock_key;

/**
 * load_system_files - open the system files using normal functions
 * @vol:	ntfs super block describing device whose system files to load
 *
 * Open the system files with normal access functions and complete setting up
 * the ntfs super block @vol.
 *
 * Return 'true' on success or 'false' on error.
 */
static bool load_system_files(ntfs_volume *vol)
{
	struct super_block *sb = vol->sb;
	MFT_RECORD *m;
	VOLUME_INFORMATION *vi;
	ntfs_attr_search_ctx *ctx;
#ifdef NTFS_RW
	RESTART_PAGE_HEADER *rp;
	int err;
#endif /* NTFS_RW */

	ntfs_debug("Entering.");
#ifdef NTFS_RW
	/* Get mft mirror inode compare the contents of $MFT and $MFTMirr. */
	if (!load_and_init_mft_mirror(vol) || !check_mft_mirror(vol)) {
		static const char *es1 = "Failed to load $MFTMirr";
		static const char *es2 = "$MFTMirr does not match $MFT";
		static const char *es3 = ".  Run ntfsfix and/or chkdsk.";

		/* If a read-write mount, convert it to a read-only mount. */
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
					ON_ERRORS_CONTINUE))) {
				ntfs_error(sb, "%s and neither on_errors="
						"continue nor on_errors="
						"remount-ro was specified%s",
						!vol->mftmirr_ino ? es1 : es2,
						es3);
				goto iput_mirr_err_out;
			}
			sb->s_flags |= MS_RDONLY;
			ntfs_error(sb, "%s.  Mounting read-only%s",
					!vol->mftmirr_ino ? es1 : es2, es3);
		} else
			ntfs_warning(sb, "%s.  Will not be able to remount "
					"read-write%s",
					!vol->mftmirr_ino ? es1 : es2, es3);
		/* This will prevent a read-write remount. */
		NVolSetErrors(vol);
	}
#endif /* NTFS_RW */
	/* Get mft bitmap attribute inode. */
	vol->mftbmp_ino = ntfs_attr_iget(vol->mft_ino, AT_BITMAP, NULL, 0);
	if (IS_ERR(vol->mftbmp_ino)) {
		ntfs_error(sb, "Failed to load $MFT/$BITMAP attribute.");
		goto iput_mirr_err_out;
	}
	lockdep_set_class(&NTFS_I(vol->mftbmp_ino)->runlist.lock,
			   &mftbmp_runlist_lock_key);
	lockdep_set_class(&NTFS_I(vol->mftbmp_ino)->mrec_lock,
			   &mftbmp_mrec_lock_key);
	/* Read upcase table and setup @vol->upcase and @vol->upcase_len. */
	if (!load_and_init_upcase(vol))
		goto iput_mftbmp_err_out;
#ifdef NTFS_RW
	/*
	 * Read attribute definitions table and setup @vol->attrdef and
	 * @vol->attrdef_size.
	 */
	if (!load_and_init_attrdef(vol))
		goto iput_upcase_err_out;
#endif /* NTFS_RW */
	/*
	 * Get the cluster allocation bitmap inode and verify the size, no
	 * need for any locking at this stage as we are already running
	 * exclusively as we are mount in progress task.
	 */
	vol->lcnbmp_ino = ntfs_iget(sb, FILE_Bitmap);
	if (IS_ERR(vol->lcnbmp_ino) || is_bad_inode(vol->lcnbmp_ino)) {
		if (!IS_ERR(vol->lcnbmp_ino))
			iput(vol->lcnbmp_ino);
		goto bitmap_failed;
	}
	lockdep_set_class(&NTFS_I(vol->lcnbmp_ino)->runlist.lock,
			   &lcnbmp_runlist_lock_key);
	lockdep_set_class(&NTFS_I(vol->lcnbmp_ino)->mrec_lock,
			   &lcnbmp_mrec_lock_key);

	NInoSetSparseDisabled(NTFS_I(vol->lcnbmp_ino));
	if ((vol->nr_clusters + 7) >> 3 > i_size_read(vol->lcnbmp_ino)) {
		iput(vol->lcnbmp_ino);
bitmap_failed:
		ntfs_error(sb, "Failed to load $Bitmap.");
		goto iput_attrdef_err_out;
	}
	/*
	 * Get the volume inode and setup our cache of the volume flags and
	 * version.
	 */
	vol->vol_ino = ntfs_iget(sb, FILE_Volume);
	if (IS_ERR(vol->vol_ino) || is_bad_inode(vol->vol_ino)) {
		if (!IS_ERR(vol->vol_ino))
			iput(vol->vol_ino);
volume_failed:
		ntfs_error(sb, "Failed to load $Volume.");
		goto iput_lcnbmp_err_out;
	}
	m = map_mft_record(NTFS_I(vol->vol_ino));
	if (IS_ERR(m)) {
iput_volume_failed:
		iput(vol->vol_ino);
		goto volume_failed;
	}
	if (!(ctx = ntfs_attr_get_search_ctx(NTFS_I(vol->vol_ino), m))) {
		ntfs_error(sb, "Failed to get attribute search context.");
		goto get_ctx_vol_failed;
	}
	if (ntfs_attr_lookup(AT_VOLUME_INFORMATION, NULL, 0, 0, 0, NULL, 0,
			ctx) || ctx->attr->non_resident || ctx->attr->flags) {
err_put_vol:
		ntfs_attr_put_search_ctx(ctx);
get_ctx_vol_failed:
		unmap_mft_record(NTFS_I(vol->vol_ino));
		goto iput_volume_failed;
	}
	vi = (VOLUME_INFORMATION*)((char*)ctx->attr +
			le16_to_cpu(ctx->attr->data.resident.value_offset));
	/* Some bounds checks. */
	if ((u8*)vi < (u8*)ctx->attr || (u8*)vi +
			le32_to_cpu(ctx->attr->data.resident.value_length) >
			(u8*)ctx->attr + le32_to_cpu(ctx->attr->length))
		goto err_put_vol;
	/* Copy the volume flags and version to the ntfs_volume structure. */
	vol->vol_flags = vi->flags;
	vol->major_ver = vi->major_ver;
	vol->minor_ver = vi->minor_ver;
	ntfs_attr_put_search_ctx(ctx);
	unmap_mft_record(NTFS_I(vol->vol_ino));
	pr_info("volume version %i.%i.\n", vol->major_ver,
			vol->minor_ver);
	if (vol->major_ver < 3 && NVolSparseEnabled(vol)) {
		ntfs_warning(vol->sb, "Disabling sparse support due to NTFS "
				"volume version %i.%i (need at least version "
				"3.0).", vol->major_ver, vol->minor_ver);
		NVolClearSparseEnabled(vol);
	}
#ifdef NTFS_RW
	/* Make sure that no unsupported volume flags are set. */
	if (vol->vol_flags & VOLUME_MUST_MOUNT_RO_MASK) {
		static const char *es1a = "Volume is dirty";
		static const char *es1b = "Volume has been modified by chkdsk";
		static const char *es1c = "Volume has unsupported flags set";
		static const char *es2a = ".  Run chkdsk and mount in Windows.";
		static const char *es2b = ".  Mount in Windows.";
		const char *es1, *es2;

		es2 = es2a;
		if (vol->vol_flags & VOLUME_IS_DIRTY)
			es1 = es1a;
		else if (vol->vol_flags & VOLUME_MODIFIED_BY_CHKDSK) {
			es1 = es1b;
			es2 = es2b;
		} else {
			es1 = es1c;
			ntfs_warning(sb, "Unsupported volume flags 0x%x "
					"encountered.",
					(unsigned)le16_to_cpu(vol->vol_flags));
		}
		/* If a read-write mount, convert it to a read-only mount. */
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
					ON_ERRORS_CONTINUE))) {
				ntfs_error(sb, "%s and neither on_errors="
						"continue nor on_errors="
						"remount-ro was specified%s",
						es1, es2);
				goto iput_vol_err_out;
			}
			sb->s_flags |= MS_RDONLY;
			ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		} else
			ntfs_warning(sb, "%s.  Will not be able to remount "
					"read-write%s", es1, es2);
		/*
		 * Do not set NVolErrors() because ntfs_remount() re-checks the
		 * flags which we need to do in case any flags have changed.
		 */
	}
	/*
	 * Get the inode for the logfile, check it and determine if the volume
	 * was shutdown cleanly.
	 */
	rp = NULL;
	if (!load_and_check_logfile(vol, &rp) ||
			!ntfs_is_logfile_clean(vol->logfile_ino, rp)) {
		static const char *es1a = "Failed to load $LogFile";
		static const char *es1b = "$LogFile is not clean";
		static const char *es2 = ".  Mount in Windows.";
		const char *es1;

		es1 = !vol->logfile_ino ? es1a : es1b;
		/* If a read-write mount, convert it to a read-only mount. */
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
					ON_ERRORS_CONTINUE))) {
				ntfs_error(sb, "%s and neither on_errors="
						"continue nor on_errors="
						"remount-ro was specified%s",
						es1, es2);
				if (vol->logfile_ino) {
					BUG_ON(!rp);
					ntfs_free(rp);
				}
				goto iput_logfile_err_out;
			}
			sb->s_flags |= MS_RDONLY;
			ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		} else
			ntfs_warning(sb, "%s.  Will not be able to remount "
					"read-write%s", es1, es2);
		/* This will prevent a read-write remount. */
		NVolSetErrors(vol);
	}
	ntfs_free(rp);
#endif /* NTFS_RW */
	/* Get the root directory inode so we can do path lookups. */
	vol->root_ino = ntfs_iget(sb, FILE_root);
	if (IS_ERR(vol->root_ino) || is_bad_inode(vol->root_ino)) {
		if (!IS_ERR(vol->root_ino))
			iput(vol->root_ino);
		ntfs_error(sb, "Failed to load root directory.");
		goto iput_logfile_err_out;
	}
#ifdef NTFS_RW
	/*
	 * Check if Windows is suspended to disk on the target volume.  If it
	 * is hibernated, we must not write *anything* to the disk so set
	 * NVolErrors() without setting the dirty volume flag and mount
	 * read-only.  This will prevent read-write remounting and it will also
	 * prevent all writes.
	 */
	err = check_windows_hibernation_status(vol);
	if (unlikely(err)) {
		static const char *es1a = "Failed to determine if Windows is "
				"hibernated";
		static const char *es1b = "Windows is hibernated";
		static const char *es2 = ".  Run chkdsk.";
		const char *es1;

		es1 = err < 0 ? es1a : es1b;
		/* If a read-write mount, convert it to a read-only mount. */
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
					ON_ERRORS_CONTINUE))) {
				ntfs_error(sb, "%s and neither on_errors="
						"continue nor on_errors="
						"remount-ro was specified%s",
						es1, es2);
				goto iput_root_err_out;
			}
			sb->s_flags |= MS_RDONLY;
			ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		} else
			ntfs_warning(sb, "%s.  Will not be able to remount "
					"read-write%s", es1, es2);
		/* This will prevent a read-write remount. */
		NVolSetErrors(vol);
	}
	/* If (still) a read-write mount, mark the volume dirty. */
	if (!(sb->s_flags & MS_RDONLY) &&
			ntfs_set_volume_flags(vol, VOLUME_IS_DIRTY)) {
		static const char *es1 = "Failed to set dirty bit in volume "
				"information flags";
		static const char *es2 = ".  Run chkdsk.";

		/* Convert to a read-only mount. */
		if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
				ON_ERRORS_CONTINUE))) {
			ntfs_error(sb, "%s and neither on_errors=continue nor "
					"on_errors=remount-ro was specified%s",
					es1, es2);
			goto iput_root_err_out;
		}
		ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		sb->s_flags |= MS_RDONLY;
		/*
		 * Do not set NVolErrors() because ntfs_remount() might manage
		 * to set the dirty flag in which case all would be well.
		 */
	}
#if 0
	// TODO: Enable this code once we start modifying anything that is
	//	 different between NTFS 1.2 and 3.x...
	/*
	 * If (still) a read-write mount, set the NT4 compatibility flag on
	 * newer NTFS version volumes.
	 */
	if (!(sb->s_flags & MS_RDONLY) && (vol->major_ver > 1) &&
			ntfs_set_volume_flags(vol, VOLUME_MOUNTED_ON_NT4)) {
		static const char *es1 = "Failed to set NT4 compatibility flag";
		static const char *es2 = ".  Run chkdsk.";

		/* Convert to a read-only mount. */
		if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
				ON_ERRORS_CONTINUE))) {
			ntfs_error(sb, "%s and neither on_errors=continue nor "
					"on_errors=remount-ro was specified%s",
					es1, es2);
			goto iput_root_err_out;
		}
		ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		sb->s_flags |= MS_RDONLY;
		NVolSetErrors(vol);
	}
#endif
	/* If (still) a read-write mount, empty the logfile. */
	if (!(sb->s_flags & MS_RDONLY) &&
			!ntfs_empty_logfile(vol->logfile_ino)) {
		static const char *es1 = "Failed to empty $LogFile";
		static const char *es2 = ".  Mount in Windows.";

		/* Convert to a read-only mount. */
		if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
				ON_ERRORS_CONTINUE))) {
			ntfs_error(sb, "%s and neither on_errors=continue nor "
					"on_errors=remount-ro was specified%s",
					es1, es2);
			goto iput_root_err_out;
		}
		ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		sb->s_flags |= MS_RDONLY;
		NVolSetErrors(vol);
	}
#endif /* NTFS_RW */
	/* If on NTFS versions before 3.0, we are done. */
	if (unlikely(vol->major_ver < 3))
		return true;
	/* NTFS 3.0+ specific initialization. */
	/* Get the security descriptors inode. */
	vol->secure_ino = ntfs_iget(sb, FILE_Secure);
	if (IS_ERR(vol->secure_ino) || is_bad_inode(vol->secure_ino)) {
		if (!IS_ERR(vol->secure_ino))
			iput(vol->secure_ino);
		ntfs_error(sb, "Failed to load $Secure.");
		goto iput_root_err_out;
	}
	// TODO: Initialize security.
	/* Get the extended system files' directory inode. */
	vol->extend_ino = ntfs_iget(sb, FILE_Extend);
	if (IS_ERR(vol->extend_ino) || is_bad_inode(vol->extend_ino)) {
		if (!IS_ERR(vol->extend_ino))
			iput(vol->extend_ino);
		ntfs_error(sb, "Failed to load $Extend.");
		goto iput_sec_err_out;
	}
#ifdef NTFS_RW
	/* Find the quota file, load it if present, and set it up. */
	if (!load_and_init_quota(vol)) {
		static const char *es1 = "Failed to load $Quota";
		static const char *es2 = ".  Run chkdsk.";

		/* If a read-write mount, convert it to a read-only mount. */
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
					ON_ERRORS_CONTINUE))) {
				ntfs_error(sb, "%s and neither on_errors="
						"continue nor on_errors="
						"remount-ro was specified%s",
						es1, es2);
				goto iput_quota_err_out;
			}
			sb->s_flags |= MS_RDONLY;
			ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		} else
			ntfs_warning(sb, "%s.  Will not be able to remount "
					"read-write%s", es1, es2);
		/* This will prevent a read-write remount. */
		NVolSetErrors(vol);
	}
	/* If (still) a read-write mount, mark the quotas out of date. */
	if (!(sb->s_flags & MS_RDONLY) &&
			!ntfs_mark_quotas_out_of_date(vol)) {
		static const char *es1 = "Failed to mark quotas out of date";
		static const char *es2 = ".  Run chkdsk.";

		/* Convert to a read-only mount. */
		if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
				ON_ERRORS_CONTINUE))) {
			ntfs_error(sb, "%s and neither on_errors=continue nor "
					"on_errors=remount-ro was specified%s",
					es1, es2);
			goto iput_quota_err_out;
		}
		ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		sb->s_flags |= MS_RDONLY;
		NVolSetErrors(vol);
	}
	/*
	 * Find the transaction log file ($UsnJrnl), load it if present, check
	 * it, and set it up.
	 */
	if (!load_and_init_usnjrnl(vol)) {
		static const char *es1 = "Failed to load $UsnJrnl";
		static const char *es2 = ".  Run chkdsk.";

		/* If a read-write mount, convert it to a read-only mount. */
		if (!(sb->s_flags & MS_RDONLY)) {
			if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
					ON_ERRORS_CONTINUE))) {
				ntfs_error(sb, "%s and neither on_errors="
						"continue nor on_errors="
						"remount-ro was specified%s",
						es1, es2);
				goto iput_usnjrnl_err_out;
			}
			sb->s_flags |= MS_RDONLY;
			ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		} else
			ntfs_warning(sb, "%s.  Will not be able to remount "
					"read-write%s", es1, es2);
		/* This will prevent a read-write remount. */
		NVolSetErrors(vol);
	}
	/* If (still) a read-write mount, stamp the transaction log. */
	if (!(sb->s_flags & MS_RDONLY) && !ntfs_stamp_usnjrnl(vol)) {
		static const char *es1 = "Failed to stamp transaction log "
				"($UsnJrnl)";
		static const char *es2 = ".  Run chkdsk.";

		/* Convert to a read-only mount. */
		if (!(vol->on_errors & (ON_ERRORS_REMOUNT_RO |
				ON_ERRORS_CONTINUE))) {
			ntfs_error(sb, "%s and neither on_errors=continue nor "
					"on_errors=remount-ro was specified%s",
					es1, es2);
			goto iput_usnjrnl_err_out;
		}
		ntfs_error(sb, "%s.  Mounting read-only%s", es1, es2);
		sb->s_flags |= MS_RDONLY;
		NVolSetErrors(vol);
	}
#endif /* NTFS_RW */
	return true;
#ifdef NTFS_RW
iput_usnjrnl_err_out:
	if (vol->usnjrnl_j_ino)
		iput(vol->usnjrnl_j_ino);
	if (vol->usnjrnl_max_ino)
		iput(vol->usnjrnl_max_ino);
	if (vol->usnjrnl_ino)
		iput(vol->usnjrnl_ino);
iput_quota_err_out:
	if (vol->quota_q_ino)
		iput(vol->quota_q_ino);
	if (vol->quota_ino)
		iput(vol->quota_ino);
	iput(vol->extend_ino);
#endif /* NTFS_RW */
iput_sec_err_out:
	iput(vol->secure_ino);
iput_root_err_out:
	iput(vol->root_ino);
iput_logfile_err_out:
#ifdef NTFS_RW
	if (vol->logfile_ino)
		iput(vol->logfile_ino);
iput_vol_err_out:
#endif /* NTFS_RW */
	iput(vol->vol_ino);
iput_lcnbmp_err_out:
	iput(vol->lcnbmp_ino);
iput_attrdef_err_out:
	vol->attrdef_size = 0;
	if (vol->attrdef) {
		ntfs_free(vol->attrdef);
		vol->attrdef = NULL;
	}
#ifdef NTFS_RW
iput_upcase_err_out:
#endif /* NTFS_RW */
	vol->upcase_len = 0;
	mutex_lock(&ntfs_lock);
	if (vol->upcase == default_upcase) {
		ntfs_nr_upcase_users--;
		vol->upcase = NULL;
	}
	mutex_unlock(&ntfs_lock);
	if (vol->upcase) {
		ntfs_free(vol->upcase);
		vol->upcase = NULL;
	}
iput_mftbmp_err_out:
	iput(vol->mftbmp_ino);
iput_mirr_err_out:
#ifdef NTFS_RW
	if (vol->mftmirr_ino)
		iput(vol->mftmirr_ino);
#endif /* NTFS_RW */
	return false;
}

/**
 * ntfs_put_super - called by the vfs to unmount a volume
 * @sb:		vfs superblock of volume to unmount
 *
 * ntfs_put_super() is called by the VFS (from fs/super.c::do_umount()) when
 * the volume is being unmounted (umount system call has been invoked) and it
 * releases all inodes and memory belonging to the NTFS specific part of the
 * super block.
 */
static void ntfs_put_super(struct super_block *sb)
{
	ntfs_volume *vol = NTFS_SB(sb);

	ntfs_debug("Entering.");

#ifdef NTFS_RW
	/*
	 * Commit all inodes while they are still open in case some of them
	 * cause others to be dirtied.
	 */
	ntfs_commit_inode(vol->vol_ino);

	/* NTFS 3.0+ specific. */
	if (vol->major_ver >= 3) {
		if (vol->usnjrnl_j_ino)
			ntfs_commit_inode(vol->usnjrnl_j_ino);
		if (vol->usnjrnl_max_ino)
			ntfs_commit_inode(vol->usnjrnl_max_ino);
		if (vol->usnjrnl_ino)
			ntfs_commit_inode(vol->usnjrnl_ino);
		if (vol->quota_q_ino)
			ntfs_commit_inode(vol->quota_q_ino);
		if (vol->quota_ino)
			ntfs_commit_inode(vol->quota_ino);
		if (vol->extend_ino)
			ntfs_commit_inode(vol->extend_ino);
		if (vol->secure_ino)
			ntfs_commit_inode(vol->secure_ino);
	}

	ntfs_commit_inode(vol->root_ino);

	down_write(&vol->lcnbmp_lock);
	ntfs_commit_inode(vol->lcnbmp_ino);
	up_write(&vol->lcnbmp_lock);

	down_write(&vol->mftbmp_lock);
	ntfs_commit_inode(vol->mftbmp_ino);
	up_write(&vol->mftbmp_lock);

	if (vol->logfile_ino)
		ntfs_commit_inode(vol->logfile_ino);

	if (vol->mftmirr_ino)
		ntfs_commit_inode(vol->mftmirr_ino);
	ntfs_commit_inode(vol->mft_ino);

	/*
	 * If a read-write mount and no volume errors have occurred, mark the
	 * volume clean.  Also, re-commit all affected inodes.
	 */
	if (!(sb->s_flags & MS_RDONLY)) {
		if (!NVolErrors(vol)) {
			if (ntfs_clear_volume_flags(vol, VOLUME_IS_DIRTY))
				ntfs_warning(sb, "Failed to clear dirty bit "
						"in volume information "
						"flags.  Run chkdsk.");
			ntfs_commit_inode(vol->vol_ino);
			ntfs_commit_inode(vol->root_ino);
			if (vol->mftmirr_ino)
				ntfs_commit_inode(vol->mftmirr_ino);
			ntfs_commit_inode(vol->mft_ino);
		} else {
			ntfs_warning(sb, "Volume has errors.  Leaving volume "
					"marked dirty.  Run chkdsk.");
		}
	}
#endif /* NTFS_RW */

	iput(vol->vol_ino);
	vol->vol_ino = NULL;

	/* NTFS 3.0+ specific clean up. */
	if (vol->major_ver >= 3) {
#ifdef NTFS_RW
		if (vol->usnjrnl_j_ino) {
			iput(vol->usnjrnl_j_ino);
			vol->usnjrnl_j_ino = NULL;
		}
		if (vol->usnjrnl_max_ino) {
			iput(vol->usnjrnl_max_ino);
			vol->usnjrnl_max_ino = NULL;
		}
		if (vol->usnjrnl_ino) {
			iput(vol->usnjrnl_ino);
			vol->usnjrnl_ino = NULL;
		}
		if (vol->quota_q_ino) {
			iput(vol->quota_q_ino);
			vol->quota_q_ino = NULL;
		}
		if (vol->quota_ino) {
			iput(vol->quota_ino);
			vol->quota_ino = NULL;
		}
#endif /* NTFS_RW */
		if (vol->extend_ino) {
			iput(vol->extend_ino);
			vol->extend_ino = NULL;
		}
		if (vol->secure_ino) {
			iput(vol->secure_ino);
			vol->secure_ino = NULL;
		}
	}

	iput(vol->root_ino);
	vol->root_ino = NULL;

	down_write(&vol->lcnbmp_lock);
	iput(vol->lcnbmp_ino);
	vol->lcnbmp_ino = NULL;
	up_write(&vol->lcnbmp_lock);

	down_write(&vol->mftbmp_lock);
	iput(vol->mftbmp_ino);
	vol->mftbmp_ino = NULL;
	up_write(&vol->mftbmp_lock);

#ifdef NTFS_RW
	if (vol->logfile_ino) {
		iput(vol->logfile_ino);
		vol->logfile_ino = NULL;
	}
	if (vol->mftmirr_ino) {
		/* Re-commit the mft mirror and mft just in case. */
		ntfs_commit_inode(vol->mftmirr_ino);
		ntfs_commit_inode(vol->mft_ino);
		iput(vol->mftmirr_ino);
		vol->mftmirr_ino = NULL;
	}
	/*
	 * We should have no dirty inodes left, due to
	 * mft.c::ntfs_mft_writepage() cleaning all the dirty pages as
	 * the underlying mft records are written out and cleaned.
	 */
	ntfs_commit_inode(vol->mft_ino);
	write_inode_now(vol->mft_ino, 1);
#endif /* NTFS_RW */

	iput(vol->mft_ino);
	vol->mft_ino = NULL;

	/* Throw away the table of attribute definitions. */
	vol->attrdef_size = 0;
	if (vol->attrdef) {
		ntfs_free(vol->attrdef);
		vol->attrdef = NULL;
	}
	vol->upcase_len = 0;
	/*
	 * Destroy the global default upcase table if necessary.  Also decrease
	 * the number of upcase users if we are a user.
	 */
	mutex_lock(&ntfs_lock);
	if (vol->upcase == default_upcase) {
		ntfs_nr_upcase_users--;
		vol->upcase = NULL;
	}
	if (!ntfs_nr_upcase_users && default_upcase) {
		ntfs_free(default_upcase);
		default_upcase = NULL;
	}
	if (vol->cluster_size <= 4096 && !--ntfs_nr_compression_users)
		free_compression_buffers();
	mutex_unlock(&ntfs_lock);
	if (vol->upcase) {
		ntfs_free(vol->upcase);
		vol->upcase = NULL;
	}

	unload_nls(vol->nls_map);

	sb->s_fs_info = NULL;
	kfree(vol);
}

/**
 * get_nr_free_clusters - return the number of free clusters on a volume
 * @vol:	ntfs volume for which to obtain free cluster count
 *
 * Calculate the number of free clusters on the mounted NTFS volume @vol. We
 * actually calculate the number of clusters in use instead because this
 * allows us to not care about partial pages as these will be just zero filled
 * and hence not be counted as allocated clusters.
 *
 * The only particularity is that clusters beyond the end of the logical ntfs
 * volume will be marked as allocated to prevent errors which means we have to
 * discount those at the end. This is important as the cluster bitmap always
 * has a size in multiples of 8 bytes, i.e. up to 63 clusters could be outside
 * the logical volume and marked in use when they are not as they do not exist.
 *
 * If any pages cannot be read we assume all clusters in the erroring pages are
 * in use. This means we return an underestimate on errors which is better than
 * an overestimate.
 */
static s64 get_nr_free_clusters(ntfs_volume *vol)
{
	s64 nr_free = vol->nr_clusters;
	struct address_space *mapping = vol->lcnbmp_ino->i_mapping;
	struct page *page;
	pgoff_t index, max_index;

	ntfs_debug("Entering.");
	/* Serialize accesses to the cluster bitmap. */
	down_read(&vol->lcnbmp_lock);
	/*
	 * Convert the number of bits into bytes rounded up, then convert into
	 * multiples of PAGE_CACHE_SIZE, rounding up so that if we have one
	 * full and one partial page max_index = 2.
	 */
	max_index = (((vol->nr_clusters + 7) >> 3) + PAGE_CACHE_SIZE - 1) >>
			PAGE_CACHE_SHIFT;
	/* Use multiples of 4 bytes, thus max_size is PAGE_CACHE_SIZE / 4. */
	ntfs_debug("Reading $Bitmap, max_index = 0x%lx, max_size = 0x%lx.",
			max_index, PAGE_CACHE_SIZE / 4);
	for (index = 0; index < max_index; index++) {
		unsigned long *kaddr;

		/*
		 * Read the page from page cache, getting it from backing store
		 * if necessary, and increment the use count.
		 */
		page = read_mapping_page(mapping, index, NULL);
		/* Ignore pages which errored synchronously. */
		if (IS_ERR(page)) {
			ntfs_debug("read_mapping_page() error. Skipping "
					"page (index 0x%lx).", index);
			nr_free -= PAGE_CACHE_SIZE * 8;
			continue;
		}
		kaddr = kmap_atomic(page);
		/*
		 * Subtract the number of set bits. If this
		 * is the last page and it is partial we don't really care as
		 * it just means we do a little extra work but it won't affect
		 * the result as all out of range bytes are set to zero by
		 * ntfs_readpage().
		 */
		nr_free -= bitmap_weight(kaddr,
					PAGE_CACHE_SIZE * BITS_PER_BYTE);
		kunmap_atomic(kaddr);
		page_cache_release(page);
	}
	ntfs_debug("Finished reading $Bitmap, last index = 0x%lx.", index - 1);
	/*
	 * Fixup for eventual bits outside logical ntfs volume (see function
	 * description above).
	 */
	if (vol->nr_clusters & 63)
		nr_free += 64 - (vol->nr_clusters & 63);
	up_read(&vol->lcnbmp_lock);
	/* If errors occurred we may well have gone below zero, fix this. */
	if (nr_free < 0)
		nr_free = 0;
	ntfs_debug("Exiting.");
	return nr_free;
}

/**
 * __get_nr_free_mft_records - return the number of free inodes on a volume
 * @vol:	ntfs volume for which to obtain free inode count
 * @nr_free:	number of mft records in filesystem
 * @max_index:	maximum number of pages containing set bits
 *
 * Calculate the number of free mft records (inodes) on the mounted NTFS
 * volume @vol. We actually calculate the number of mft records in use instead
 * because this allows us to not care about partial pages as these will be just
 * zero filled and hence not be counted as allocated mft record.
 *
 * If any pages cannot be read we assume all mft records in the erroring pages
 * are in use. This means we return an underestimate on errors which is better
 * than an overestimate.
 *
 * NOTE: Caller must hold mftbmp_lock rw_semaphore for reading or writing.
 */
static unsigned long __get_nr_free_mft_records(ntfs_volume *vol,
		s64 nr_free, const pgoff_t max_index)
{
	struct address_space *mapping = vol->mftbmp_ino->i_mapping;
	struct page *page;
	pgoff_t index;

	ntfs_debug("Entering.");
	/* Use multiples of 4 bytes, thus max_size is PAGE_CACHE_SIZE / 4. */
	ntfs_debug("Reading $MFT/$BITMAP, max_index = 0x%lx, max_size = "
			"0x%lx.", max_index, PAGE_CACHE_SIZE / 4);
	for (index = 0; index < max_index; index++) {
		unsigned long *kaddr;

		/*
		 * Read the page from page cache, getting it from backing store
		 * if necessary, and increment the use count.
		 */
		page = read_mapping_page(mapping, index, NULL);
		/* Ignore pages which errored synchronously. */
		if (IS_ERR(page)) {
			ntfs_debug("read_mapping_page() error. Skipping "
					"page (index 0x%lx).", index);
			nr_free -= PAGE_CACHE_SIZE * 8;
			continue;
		}
		kaddr = kmap_atomic(page);
		/*
		 * Subtract the number of set bits. If this
		 * is the last page and it is partial we don't really care as
		 * it just means we do a little extra work but it won't affect
		 * the result as all out of range bytes are set to zero by
		 * ntfs_readpage().
		 */
		nr_free -= bitmap_weight(kaddr,
					PAGE_CACHE_SIZE * BITS_PER_BYTE);
		kunmap_atomic(kaddr);
		page_cache_release(page);
	}
	ntfs_debug("Finished reading $MFT/$BITMAP, last index = 0x%lx.",
			index - 1);
	/* If errors occurred we may well have gone below zero, fix this. */
	if (nr_free < 0)
		nr_free = 0;
	ntfs_debug("Exiting.");
	return nr_free;
}

/**
 * ntfs_statfs - return information about mounted NTFS volume
 * @dentry:	dentry from mounted volume
 * @sfs:	statfs structure in which to return the information
 *
 * Return information about the mounted NTFS volume @dentry in the statfs structure
 * pointed to by @sfs (this is initialized with zeros before ntfs_statfs is
 * called). We interpret the values to be correct of the moment in time at
 * which we are called. Most values are variable otherwise and this isn't just
 * the free values but the totals as well. For example we can increase the
 * total number of file nodes if we run out and we can keep doing this until
 * there is no more space on the volume left at all.
 *
 * Called from vfs_statfs which is used to handle the statfs, fstatfs, and
 * ustat system calls.
 *
 * Return 0 on success or -errno on error.
 */
static int ntfs_statfs(struct dentry *dentry, struct kstatfs *sfs)
{
	struct super_block *sb = dentry->d_sb;
	s64 size;
	ntfs_volume *vol = NTFS_SB(sb);
	ntfs_inode *mft_ni = NTFS_I(vol->mft_ino);
	pgoff_t max_index;
	unsigned long flags;

	ntfs_debug("Entering.");
	/* Type of filesystem. */
	sfs->f_type   = NTFS_SB_MAGIC;
	/* Optimal transfer block size. */
	sfs->f_bsize  = PAGE_CACHE_SIZE;
	/*
	 * Total data blocks in filesystem in units of f_bsize and since
	 * inodes are also stored in data blocs ($MFT is a file) this is just
	 * the total clusters.
	 */
	sfs->f_blocks = vol->nr_clusters << vol->cluster_size_bits >>
				PAGE_CACHE_SHIFT;
	/* Free data blocks in filesystem in units of f_bsize. */
	size	      = get_nr_free_clusters(vol) << vol->cluster_size_bits >>
				PAGE_CACHE_SHIFT;
	if (size < 0LL)
		size = 0LL;
	/* Free blocks avail to non-superuser, same as above on NTFS. */
	sfs->f_bavail = sfs->f_bfree = size;
	/* Serialize accesses to the inode bitmap. */
	down_read(&vol->mftbmp_lock);
	read_lock_irqsave(&mft_ni->size_lock, flags);
	size = i_size_read(vol->mft_ino) >> vol->mft_record_size_bits;
	/*
	 * Convert the maximum number of set bits into bytes rounded up, then
	 * convert into multiples of PAGE_CACHE_SIZE, rounding up so that if we
	 * have one full and one partial page max_index = 2.
	 */
	max_index = ((((mft_ni->initialized_size >> vol->mft_record_size_bits)
			+ 7) >> 3) + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	read_unlock_irqrestore(&mft_ni->size_lock, flags);
	/* Number of inodes in filesystem (at this point in time). */
	sfs->f_files = size;
	/* Free inodes in fs (based on current total count). */
	sfs->f_ffree = __get_nr_free_mft_records(vol, size, max_index);
	up_read(&vol->mftbmp_lock);
	/*
	 * File system id. This is extremely *nix flavour dependent and even
	 * within Linux itself all fs do their own thing. I interpret this to
	 * mean a unique id associated with the mounted fs and not the id
	 * associated with the filesystem driver, the latter is already given
	 * by the filesystem type in sfs->f_type. Thus we use the 64-bit
	 * volume serial number splitting it into two 32-bit parts. We enter
	 * the least significant 32-bits in f_fsid[0] and the most significant
	 * 32-bits in f_fsid[1].
	 */
	sfs->f_fsid.val[0] = vol->serial_no & 0xffffffff;
	sfs->f_fsid.val[1] = (vol->serial_no >> 32) & 0xffffffff;
	/* Maximum length of filenames. */
	sfs->f_namelen	   = NTFS_MAX_NAME_LEN;
	return 0;
}

#ifdef NTFS_RW
static int ntfs_write_inode(struct inode *vi, struct writeback_control *wbc)
{
	return __ntfs_write_inode(vi, wbc->sync_mode == WB_SYNC_ALL);
}
#endif

/**
 * The complete super operations.
 */
static const struct super_operations ntfs_sops = {
	.alloc_inode	= ntfs_alloc_big_inode,	  /* VFS: Allocate new inode. */
	.destroy_inode	= ntfs_destroy_big_inode, /* VFS: Deallocate inode. */
#ifdef NTFS_RW
	.write_inode	= ntfs_write_inode,	/* VFS: Write dirty inode to
						   disk. */
#endif /* NTFS_RW */
	.put_super	= ntfs_put_super,	/* Syscall: umount. */
	.statfs		= ntfs_statfs,		/* Syscall: statfs */
	.remount_fs	= ntfs_remount,		/* Syscall: mount -o remount. */
	.evict_inode	= ntfs_evict_big_inode,	/* VFS: Called when an inode is
						   removed from memory. */
	.show_options	= ntfs_show_options,	/* Show mount options in
						   proc. */
};

/**
 * ntfs_fill_super - mount an ntfs filesystem
 * @sb:		super block of ntfs filesystem to mount
 * @opt:	string containing the mount options
 * @silent:	silence error output
 *
 * ntfs_fill_super() is called by the VFS to mount the device described by @sb
 * with the mount otions in @data with the NTFS filesystem.
 *
 * If @silent is true, remain silent even if errors are detected. This is used
 * during bootup, when the kernel tries to mount the root filesystem with all
 * registered filesystems one after the other until one succeeds. This implies
 * that all filesystems except the correct one will quite correctly and
 * expectedly return an error, but nobody wants to see error messages when in
 * fact this is what is supposed to happen.
 *
 * NOTE: @sb->s_flags contains the mount options flags.
 */
static int ntfs_fill_super(struct super_block *sb, void *opt, const int silent)
{
	ntfs_volume *vol;
	struct buffer_head *bh;
	struct inode *tmp_ino;
	int blocksize, result;

	/*
	 * We do a pretty difficult piece of bootstrap by reading the
	 * MFT (and other metadata) from disk into memory. We'll only
	 * release this metadata during umount, so the locking patterns
	 * observed during bootstrap do not count. So turn off the
	 * observation of locking patterns (strictly for this context
	 * only) while mounting NTFS. [The validator is still active
	 * otherwise, even for this context: it will for example record
	 * lock class registrations.]
	 */
	lockdep_off();
	ntfs_debug("Entering.");
#ifndef NTFS_RW
	sb->s_flags |= MS_RDONLY;
#endif /* ! NTFS_RW */
	/* Allocate a new ntfs_volume and place it in sb->s_fs_info. */
	sb->s_fs_info = kmalloc(sizeof(ntfs_volume), GFP_NOFS);
	vol = NTFS_SB(sb);
	if (!vol) {
		if (!silent)
			ntfs_error(sb, "Allocation of NTFS volume structure "
					"failed. Aborting mount...");
		lockdep_on();
		return -ENOMEM;
	}
	/* Initialize ntfs_volume structure. */
	*vol = (ntfs_volume) {
		.sb = sb,
		/*
		 * Default is group and other don't have any access to files or
		 * directories while owner has full access. Further, files by
		 * default are not executable but directories are of course
		 * browseable.
		 */
		.fmask = 0177,
		.dmask = 0077,
	};
	init_rwsem(&vol->mftbmp_lock);
	init_rwsem(&vol->lcnbmp_lock);

	/* By default, enable sparse support. */
	NVolSetSparseEnabled(vol);

	/* Important to get the mount options dealt with now. */
	if (!parse_options(vol, (char*)opt))
		goto err_out_now;

	/* We support sector sizes up to the PAGE_CACHE_SIZE. */
	if (bdev_logical_block_size(sb->s_bdev) > PAGE_CACHE_SIZE) {
		if (!silent)
			ntfs_error(sb, "Device has unsupported sector size "
					"(%i).  The maximum supported sector "
					"size on this architecture is %lu "
					"bytes.",
					bdev_logical_block_size(sb->s_bdev),
					PAGE_CACHE_SIZE);
		goto err_out_now;
	}
	/*
	 * Setup the device access block size to NTFS_BLOCK_SIZE or the hard
	 * sector size, whichever is bigger.
	 */
	blocksize = sb_min_blocksize(sb, NTFS_BLOCK_SIZE);
	if (blocksize < NTFS_BLOCK_SIZE) {
		if (!silent)
			ntfs_error(sb, "Unable to set device block size.");
		goto err_out_now;
	}
	BUG_ON(blocksize != sb->s_blocksize);
	ntfs_debug("Set device block size to %i bytes (block size bits %i).",
			blocksize, sb->s_blocksize_bits);
	/* Determine the size of the device in units of block_size bytes. */
	if (!i_size_read(sb->s_bdev->bd_inode)) {
		if (!silent)
			ntfs_error(sb, "Unable to determine device size.");
		goto err_out_now;
	}
	vol->nr_blocks = i_size_read(sb->s_bdev->bd_inode) >>
			sb->s_blocksize_bits;
	/* Read the boot sector and return unlocked buffer head to it. */
	if (!(bh = read_ntfs_boot_sector(sb, silent))) {
		if (!silent)
			ntfs_error(sb, "Not an NTFS volume.");
		goto err_out_now;
	}
	/*
	 * Extract the data from the boot sector and setup the ntfs volume
	 * using it.
	 */
	result = parse_ntfs_boot_sector(vol, (NTFS_BOOT_SECTOR*)bh->b_data);
	brelse(bh);
	if (!result) {
		if (!silent)
			ntfs_error(sb, "Unsupported NTFS filesystem.");
		goto err_out_now;
	}
	/*
	 * If the boot sector indicates a sector size bigger than the current
	 * device block size, switch the device block size to the sector size.
	 * TODO: It may be possible to support this case even when the set
	 * below fails, we would just be breaking up the i/o for each sector
	 * into multiple blocks for i/o purposes but otherwise it should just
	 * work.  However it is safer to leave disabled until someone hits this
	 * error message and then we can get them to try it without the setting
	 * so we know for sure that it works.
	 */
	if (vol->sector_size > blocksize) {
		blocksize = sb_set_blocksize(sb, vol->sector_size);
		if (blocksize != vol->sector_size) {
			if (!silent)
				ntfs_error(sb, "Unable to set device block "
						"size to sector size (%i).",
						vol->sector_size);
			goto err_out_now;
		}
		BUG_ON(blocksize != sb->s_blocksize);
		vol->nr_blocks = i_size_read(sb->s_bdev->bd_inode) >>
				sb->s_blocksize_bits;
		ntfs_debug("Changed device block size to %i bytes (block size "
				"bits %i) to match volume sector size.",
				blocksize, sb->s_blocksize_bits);
	}
	/* Initialize the cluster and mft allocators. */
	ntfs_setup_allocators(vol);
	/* Setup remaining fields in the super block. */
	sb->s_magic = NTFS_SB_MAGIC;
	/*
	 * Ntfs allows 63 bits for the file size, i.e. correct would be:
	 *	sb->s_maxbytes = ~0ULL >> 1;
	 * But the kernel uses a long as the page cache page index which on
	 * 32-bit architectures is only 32-bits. MAX_LFS_FILESIZE is kernel
	 * defined to the maximum the page cache page index can cope with
	 * without overflowing the index or to 2^63 - 1, whichever is smaller.
	 */
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	/* Ntfs measures time in 100ns intervals. */
	sb->s_time_gran = 100;
	/*
	 * Now load the metadata required for the page cache and our address
	 * space operations to function. We do this by setting up a specialised
	 * read_inode method and then just calling the normal iget() to obtain
	 * the inode for $MFT which is sufficient to allow our normal inode
	 * operations and associated address space operations to function.
	 */
	sb->s_op = &ntfs_sops;
	tmp_ino = new_inode(sb);
	if (!tmp_ino) {
		if (!silent)
			ntfs_error(sb, "Failed to load essential metadata.");
		goto err_out_now;
	}
	tmp_ino->i_ino = FILE_MFT;
	insert_inode_hash(tmp_ino);
	if (ntfs_read_inode_mount(tmp_ino) < 0) {
		if (!silent)
			ntfs_error(sb, "Failed to load essential metadata.");
		goto iput_tmp_ino_err_out_now;
	}
	mutex_lock(&ntfs_lock);
	/*
	 * The current mount is a compression user if the cluster size is
	 * less than or equal 4kiB.
	 */
	if (vol->cluster_size <= 4096 && !ntfs_nr_compression_users++) {
		result = allocate_compression_buffers();
		if (result) {
			ntfs_error(NULL, "Failed to allocate buffers "
					"for compression engine.");
			ntfs_nr_compression_users--;
			mutex_unlock(&ntfs_lock);
			goto iput_tmp_ino_err_out_now;
		}
	}
	/*
	 * Generate the global default upcase table if necessary.  Also
	 * temporarily increment the number of upcase users to avoid race
	 * conditions with concurrent (u)mounts.
	 */
	if (!default_upcase)
		default_upcase = generate_default_upcase();
	ntfs_nr_upcase_users++;
	mutex_unlock(&ntfs_lock);
	/*
	 * From now on, ignore @silent parameter. If we fail below this line,
	 * it will be due to a corrupt fs or a system error, so we report it.
	 */
	/*
	 * Open the system files with normal access functions and complete
	 * setting up the ntfs super block.
	 */
	if (!load_system_files(vol)) {
		ntfs_error(sb, "Failed to load system files.");
		goto unl_upcase_iput_tmp_ino_err_out_now;
	}

	/* We grab a reference, simulating an ntfs_iget(). */
	ihold(vol->root_ino);
	if ((sb->s_root = d_make_root(vol->root_ino))) {
		ntfs_debug("Exiting, status successful.");
		/* Release the default upcase if it has no users. */
		mutex_lock(&ntfs_lock);
		if (!--ntfs_nr_upcase_users && default_upcase) {
			ntfs_free(default_upcase);
			default_upcase = NULL;
		}
		mutex_unlock(&ntfs_lock);
		sb->s_export_op = &ntfs_export_ops;
		lockdep_on();
		return 0;
	}
	ntfs_error(sb, "Failed to allocate root directory.");
	/* Clean up after the successful load_system_files() call from above. */
	// TODO: Use ntfs_put_super() instead of repeating all this code...
	// FIXME: Should mark the volume clean as the error is most likely
	// 	  -ENOMEM.
	iput(vol->vol_ino);
	vol->vol_ino = NULL;
	/* NTFS 3.0+ specific clean up. */
	if (vol->major_ver >= 3) {
#ifdef NTFS_RW
		if (vol->usnjrnl_j_ino) {
			iput(vol->usnjrnl_j_ino);
			vol->usnjrnl_j_ino = NULL;
		}
		if (vol->usnjrnl_max_ino) {
			iput(vol->usnjrnl_max_ino);
			vol->usnjrnl_max_ino = NULL;
		}
		if (vol->usnjrnl_ino) {
			iput(vol->usnjrnl_ino);
			vol->usnjrnl_ino = NULL;
		}
		if (vol->quota_q_ino) {
			iput(vol->quota_q_ino);
			vol->quota_q_ino = NULL;
		}
		if (vol->quota_ino) {
			iput(vol->quota_ino);
			vol->quota_ino = NULL;
		}
#endif /* NTFS_RW */
		if (vol->extend_ino) {
			iput(vol->extend_ino);
			vol->extend_ino = NULL;
		}
		if (vol->secure_ino) {
			iput(vol->secure_ino);
			vol->secure_ino = NULL;
		}
	}
	iput(vol->root_ino);
	vol->root_ino = NULL;
	iput(vol->lcnbmp_ino);
	vol->lcnbmp_ino = NULL;
	iput(vol->mftbmp_ino);
	vol->mftbmp_ino = NULL;
#ifdef NTFS_RW
	if (vol->logfile_ino) {
		iput(vol->logfile_ino);
		vol->logfile_ino = NULL;
	}
	if (vol->mftmirr_ino) {
		iput(vol->mftmirr_ino);
		vol->mftmirr_ino = NULL;
	}
#endif /* NTFS_RW */
	/* Throw away the table of attribute definitions. */
	vol->attrdef_size = 0;
	if (vol->attrdef) {
		ntfs_free(vol->attrdef);
		vol->attrdef = NULL;
	}
	vol->upcase_len = 0;
	mutex_lock(&ntfs_lock);
	if (vol->upcase == default_upcase) {
		ntfs_nr_upcase_users--;
		vol->upcase = NULL;
	}
	mutex_unlock(&ntfs_lock);
	if (vol->upcase) {
		ntfs_free(vol->upcase);
		vol->upcase = NULL;
	}
	if (vol->nls_map) {
		unload_nls(vol->nls_map);
		vol->nls_map = NULL;
	}
	/* Error exit code path. */
unl_upcase_iput_tmp_ino_err_out_now:
	/*
	 * Decrease the number of upcase users and destroy the global default
	 * upcase table if necessary.
	 */
	mutex_lock(&ntfs_lock);
	if (!--ntfs_nr_upcase_users && default_upcase) {
		ntfs_free(default_upcase);
		default_upcase = NULL;
	}
	if (vol->cluster_size <= 4096 && !--ntfs_nr_compression_users)
		free_compression_buffers();
	mutex_unlock(&ntfs_lock);
iput_tmp_ino_err_out_now:
	iput(tmp_ino);
	if (vol->mft_ino && vol->mft_ino != tmp_ino)
		iput(vol->mft_ino);
	vol->mft_ino = NULL;
	/* Errors at this stage are irrelevant. */
err_out_now:
	sb->s_fs_info = NULL;
	kfree(vol);
	ntfs_debug("Failed, returning -EINVAL.");
	lockdep_on();
	return -EINVAL;
}

/*
 * This is a slab cache to optimize allocations and deallocations of Unicode
 * strings of the maximum length allowed by NTFS, which is NTFS_MAX_NAME_LEN
 * (255) Unicode characters + a terminating NULL Unicode character.
 */
struct kmem_cache *ntfs_name_cache;

/* Slab caches for efficient allocation/deallocation of inodes. */
struct kmem_cache *ntfs_inode_cache;
struct kmem_cache *ntfs_big_inode_cache;

/* Init once constructor for the inode slab cache. */
static void ntfs_big_inode_init_once(void *foo)
{
	ntfs_inode *ni = (ntfs_inode *)foo;

	inode_init_once(VFS_I(ni));
}

/*
 * Slab caches to optimize allocations and deallocations of attribute search
 * contexts and index contexts, respectively.
 */
struct kmem_cache *ntfs_attr_ctx_cache;
struct kmem_cache *ntfs_index_ctx_cache;

/* Driver wide mutex. */
DEFINE_MUTEX(ntfs_lock);

static struct dentry *ntfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, ntfs_fill_super);
}

static struct file_system_type ntfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ntfs",
	.mount		= ntfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("ntfs");

/* Stable names for the slab caches. */
static const char ntfs_index_ctx_cache_name[] = "ntfs_index_ctx_cache";
static const char ntfs_attr_ctx_cache_name[] = "ntfs_attr_ctx_cache";
static const char ntfs_name_cache_name[] = "ntfs_name_cache";
static const char ntfs_inode_cache_name[] = "ntfs_inode_cache";
static const char ntfs_big_inode_cache_name[] = "ntfs_big_inode_cache";

static int __init init_ntfs_fs(void)
{
	int err = 0;

	/* This may be ugly but it results in pretty output so who cares. (-8 */
	pr_info("driver " NTFS_VERSION " [Flags: R/"
#ifdef NTFS_RW
			"W"
#else
			"O"
#endif
#ifdef DEBUG
			" DEBUG"
#endif
#ifdef MODULE
			" MODULE"
#endif
			"].\n");

	ntfs_debug("Debug messages are enabled.");

	ntfs_index_ctx_cache = kmem_cache_create(ntfs_index_ctx_cache_name,
			sizeof(ntfs_index_context), 0 /* offset */,
			SLAB_HWCACHE_ALIGN, NULL /* ctor */);
	if (!ntfs_index_ctx_cache) {
		pr_crit("Failed to create %s!\n", ntfs_index_ctx_cache_name);
		goto ictx_err_out;
	}
	ntfs_attr_ctx_cache = kmem_cache_create(ntfs_attr_ctx_cache_name,
			sizeof(ntfs_attr_search_ctx), 0 /* offset */,
			SLAB_HWCACHE_ALIGN, NULL /* ctor */);
	if (!ntfs_attr_ctx_cache) {
		pr_crit("NTFS: Failed to create %s!\n",
			ntfs_attr_ctx_cache_name);
		goto actx_err_out;
	}

	ntfs_name_cache = kmem_cache_create(ntfs_name_cache_name,
			(NTFS_MAX_NAME_LEN+1) * sizeof(ntfschar), 0,
			SLAB_HWCACHE_ALIGN, NULL);
	if (!ntfs_name_cache) {
		pr_crit("Failed to create %s!\n", ntfs_name_cache_name);
		goto name_err_out;
	}

	ntfs_inode_cache = kmem_cache_create(ntfs_inode_cache_name,
			sizeof(ntfs_inode), 0,
			SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD, NULL);
	if (!ntfs_inode_cache) {
		pr_crit("Failed to create %s!\n", ntfs_inode_cache_name);
		goto inode_err_out;
	}

	ntfs_big_inode_cache = kmem_cache_create(ntfs_big_inode_cache_name,
			sizeof(big_ntfs_inode), 0,
			SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD,
			ntfs_big_inode_init_once);
	if (!ntfs_big_inode_cache) {
		pr_crit("Failed to create %s!\n", ntfs_big_inode_cache_name);
		goto big_inode_err_out;
	}

	/* Register the ntfs sysctls. */
	err = ntfs_sysctl(1);
	if (err) {
		pr_crit("Failed to register NTFS sysctls!\n");
		goto sysctl_err_out;
	}

	err = register_filesystem(&ntfs_fs_type);
	if (!err) {
		ntfs_debug("NTFS driver registered successfully.");
		return 0; /* Success! */
	}
	pr_crit("Failed to register NTFS filesystem driver!\n");

	/* Unregister the ntfs sysctls. */
	ntfs_sysctl(0);
sysctl_err_out:
	kmem_cache_destroy(ntfs_big_inode_cache);
big_inode_err_out:
	kmem_cache_destroy(ntfs_inode_cache);
inode_err_out:
	kmem_cache_destroy(ntfs_name_cache);
name_err_out:
	kmem_cache_destroy(ntfs_attr_ctx_cache);
actx_err_out:
	kmem_cache_destroy(ntfs_index_ctx_cache);
ictx_err_out:
	if (!err) {
		pr_crit("Aborting NTFS filesystem driver registration...\n");
		err = -ENOMEM;
	}
	return err;
}

static void __exit exit_ntfs_fs(void)
{
	ntfs_debug("Unregistering NTFS driver.");

	unregister_filesystem(&ntfs_fs_type);

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(ntfs_big_inode_cache);
	kmem_cache_destroy(ntfs_inode_cache);
	kmem_cache_destroy(ntfs_name_cache);
	kmem_cache_destroy(ntfs_attr_ctx_cache);
	kmem_cache_destroy(ntfs_index_ctx_cache);
	/* Unregister the ntfs sysctls. */
	ntfs_sysctl(0);
}

MODULE_AUTHOR("Anton Altaparmakov <anton@tuxera.com>");
MODULE_DESCRIPTION("NTFS 1.2/3.x driver - Copyright (c) 2001-2014 Anton Altaparmakov and Tuxera Inc.");
MODULE_VERSION(NTFS_VERSION);
MODULE_LICENSE("GPL");
#ifdef DEBUG
module_param(debug_msgs, bint, 0);
MODULE_PARM_DESC(debug_msgs, "Enable debug messages.");
#endif

module_init(init_ntfs_fs)
module_exit(exit_ntfs_fs)
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/super.c */
/************************************************************/
/*
 * sysctl.c - Code for sysctl handling in NTFS Linux kernel driver. Part of
 *	      the Linux-NTFS project. Adapted from the old NTFS driver,
 *	      Copyright (C) 1997 Martin von Löwis, Régis Duchesne
 *
 * Copyright (c) 2002-2005 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef DEBUG

#include <linux/module.h>
#include "../../inc/__fss.h"

#ifdef CONFIG_SYSCTL

#include <linux/proc_fs.h>
#include <linux/sysctl.h>
#include "../../inc/__fss.h"

// #include "sysctl.h"
// #include "debug.h"

/* Definition of the ntfs sysctl. */
static struct ctl_table ntfs_sysctls[] = {
	{
		.procname	= "ntfs-debug",
		.data		= &debug_msgs,		/* Data pointer and size. */
		.maxlen		= sizeof(debug_msgs),
		.mode		= 0644,			/* Mode, proc handler. */
		.proc_handler	= proc_dointvec
	},
	{}
};

/* Define the parent directory /proc/sys/fs. */
static struct ctl_table sysctls_root[] = {
	{
		.procname	= "fs",
		.mode		= 0555,
		.child		= ntfs_sysctls
	},
	{}
};

/* Storage for the sysctls header. */
static struct ctl_table_header *sysctls_root_table;

/**
 * ntfs_sysctl - add or remove the debug sysctl
 * @add:	add (1) or remove (0) the sysctl
 *
 * Add or remove the debug sysctl. Return 0 on success or -errno on error.
 */
int ntfs_sysctl(int add)
{
	if (add) {
		BUG_ON(sysctls_root_table);
		sysctls_root_table = register_sysctl_table(sysctls_root);
		if (!sysctls_root_table)
			return -ENOMEM;
	} else {
		BUG_ON(!sysctls_root_table);
		unregister_sysctl_table(sysctls_root_table);
		sysctls_root_table = NULL;
	}
	return 0;
}

#endif /* CONFIG_SYSCTL */
#endif /* DEBUG */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/sysctl.c */
/************************************************************/
/*
 * unistr.c - NTFS Unicode string handling. Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001-2006 Anton Altaparmakov
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include <linux/slab.h>

// #include "types.h"
// #include "debug.h"
// #include "ntfs.h"

/*
 * IMPORTANT
 * =========
 *
 * All these routines assume that the Unicode characters are in little endian
 * encoding inside the strings!!!
 */

/*
 * This is used by the name collation functions to quickly determine what
 * characters are (in)valid.
 */
static const u8 legal_ansi_char_array[0x40] = {
	0x00, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,

	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,

	0x17, 0x07, 0x18, 0x17, 0x17, 0x17, 0x17, 0x17,
	0x17, 0x17, 0x18, 0x16, 0x16, 0x17, 0x07, 0x00,

	0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17, 0x17,
	0x17, 0x17, 0x04, 0x16, 0x18, 0x16, 0x18, 0x18,
};

/**
 * ntfs_are_names_equal - compare two Unicode names for equality
 * @s1:			name to compare to @s2
 * @s1_len:		length in Unicode characters of @s1
 * @s2:			name to compare to @s1
 * @s2_len:		length in Unicode characters of @s2
 * @ic:			ignore case bool
 * @upcase:		upcase table (only if @ic == IGNORE_CASE)
 * @upcase_size:	length in Unicode characters of @upcase (if present)
 *
 * Compare the names @s1 and @s2 and return 'true' (1) if the names are
 * identical, or 'false' (0) if they are not identical. If @ic is IGNORE_CASE,
 * the @upcase table is used to performa a case insensitive comparison.
 */
bool ntfs_are_names_equal(const ntfschar *s1, size_t s1_len,
		const ntfschar *s2, size_t s2_len, const IGNORE_CASE_BOOL ic,
		const ntfschar *upcase, const u32 upcase_size)
{
	if (s1_len != s2_len)
		return false;
	if (ic == CASE_SENSITIVE)
		return !ntfs_ucsncmp(s1, s2, s1_len);
	return !ntfs_ucsncasecmp(s1, s2, s1_len, upcase, upcase_size);
}

/**
 * ntfs_collate_names - collate two Unicode names
 * @name1:	first Unicode name to compare
 * @name2:	second Unicode name to compare
 * @err_val:	if @name1 contains an invalid character return this value
 * @ic:		either CASE_SENSITIVE or IGNORE_CASE
 * @upcase:	upcase table (ignored if @ic is CASE_SENSITIVE)
 * @upcase_len:	upcase table size (ignored if @ic is CASE_SENSITIVE)
 *
 * ntfs_collate_names collates two Unicode names and returns:
 *
 *  -1 if the first name collates before the second one,
 *   0 if the names match,
 *   1 if the second name collates before the first one, or
 * @err_val if an invalid character is found in @name1 during the comparison.
 *
 * The following characters are considered invalid: '"', '*', '<', '>' and '?'.
 */
int ntfs_collate_names(const ntfschar *name1, const u32 name1_len,
		const ntfschar *name2, const u32 name2_len,
		const int err_val, const IGNORE_CASE_BOOL ic,
		const ntfschar *upcase, const u32 upcase_len)
{
	u32 cnt, min_len;
	u16 c1, c2;

	min_len = name1_len;
	if (name1_len > name2_len)
		min_len = name2_len;
	for (cnt = 0; cnt < min_len; ++cnt) {
		c1 = le16_to_cpu(*name1++);
		c2 = le16_to_cpu(*name2++);
		if (ic) {
			if (c1 < upcase_len)
				c1 = le16_to_cpu(upcase[c1]);
			if (c2 < upcase_len)
				c2 = le16_to_cpu(upcase[c2]);
		}
		if (c1 < 64 && legal_ansi_char_array[c1] & 8)
			return err_val;
		if (c1 < c2)
			return -1;
		if (c1 > c2)
			return 1;
	}
	if (name1_len < name2_len)
		return -1;
	if (name1_len == name2_len)
		return 0;
	/* name1_len > name2_len */
	c1 = le16_to_cpu(*name1);
	if (c1 < 64 && legal_ansi_char_array[c1] & 8)
		return err_val;
	return 1;
}

/**
 * ntfs_ucsncmp - compare two little endian Unicode strings
 * @s1:		first string
 * @s2:		second string
 * @n:		maximum unicode characters to compare
 *
 * Compare the first @n characters of the Unicode strings @s1 and @s2,
 * The strings in little endian format and appropriate le16_to_cpu()
 * conversion is performed on non-little endian machines.
 *
 * The function returns an integer less than, equal to, or greater than zero
 * if @s1 (or the first @n Unicode characters thereof) is found, respectively,
 * to be less than, to match, or be greater than @s2.
 */
int ntfs_ucsncmp(const ntfschar *s1, const ntfschar *s2, size_t n)
{
	u16 c1, c2;
	size_t i;

	for (i = 0; i < n; ++i) {
		c1 = le16_to_cpu(s1[i]);
		c2 = le16_to_cpu(s2[i]);
		if (c1 < c2)
			return -1;
		if (c1 > c2)
			return 1;
		if (!c1)
			break;
	}
	return 0;
}

/**
 * ntfs_ucsncasecmp - compare two little endian Unicode strings, ignoring case
 * @s1:			first string
 * @s2:			second string
 * @n:			maximum unicode characters to compare
 * @upcase:		upcase table
 * @upcase_size:	upcase table size in Unicode characters
 *
 * Compare the first @n characters of the Unicode strings @s1 and @s2,
 * ignoring case. The strings in little endian format and appropriate
 * le16_to_cpu() conversion is performed on non-little endian machines.
 *
 * Each character is uppercased using the @upcase table before the comparison.
 *
 * The function returns an integer less than, equal to, or greater than zero
 * if @s1 (or the first @n Unicode characters thereof) is found, respectively,
 * to be less than, to match, or be greater than @s2.
 */
int ntfs_ucsncasecmp(const ntfschar *s1, const ntfschar *s2, size_t n,
		const ntfschar *upcase, const u32 upcase_size)
{
	size_t i;
	u16 c1, c2;

	for (i = 0; i < n; ++i) {
		if ((c1 = le16_to_cpu(s1[i])) < upcase_size)
			c1 = le16_to_cpu(upcase[c1]);
		if ((c2 = le16_to_cpu(s2[i])) < upcase_size)
			c2 = le16_to_cpu(upcase[c2]);
		if (c1 < c2)
			return -1;
		if (c1 > c2)
			return 1;
		if (!c1)
			break;
	}
	return 0;
}

void ntfs_upcase_name(ntfschar *name, u32 name_len, const ntfschar *upcase,
		const u32 upcase_len)
{
	u32 i;
	u16 u;

	for (i = 0; i < name_len; i++)
		if ((u = le16_to_cpu(name[i])) < upcase_len)
			name[i] = upcase[u];
}

void ntfs_file_upcase_value(FILE_NAME_ATTR *file_name_attr,
		const ntfschar *upcase, const u32 upcase_len)
{
	ntfs_upcase_name((ntfschar*)&file_name_attr->file_name,
			file_name_attr->file_name_length, upcase, upcase_len);
}

int ntfs_file_compare_values(FILE_NAME_ATTR *file_name_attr1,
		FILE_NAME_ATTR *file_name_attr2,
		const int err_val, const IGNORE_CASE_BOOL ic,
		const ntfschar *upcase, const u32 upcase_len)
{
	return ntfs_collate_names((ntfschar*)&file_name_attr1->file_name,
			file_name_attr1->file_name_length,
			(ntfschar*)&file_name_attr2->file_name,
			file_name_attr2->file_name_length,
			err_val, ic, upcase, upcase_len);
}

/**
 * ntfs_nlstoucs - convert NLS string to little endian Unicode string
 * @vol:	ntfs volume which we are working with
 * @ins:	input NLS string buffer
 * @ins_len:	length of input string in bytes
 * @outs:	on return contains the allocated output Unicode string buffer
 *
 * Convert the input string @ins, which is in whatever format the loaded NLS
 * map dictates, into a little endian, 2-byte Unicode string.
 *
 * This function allocates the string and the caller is responsible for
 * calling kmem_cache_free(ntfs_name_cache, *@outs); when finished with it.
 *
 * On success the function returns the number of Unicode characters written to
 * the output string *@outs (>= 0), not counting the terminating Unicode NULL
 * character. *@outs is set to the allocated output string buffer.
 *
 * On error, a negative number corresponding to the error code is returned. In
 * that case the output string is not allocated. Both *@outs and *@outs_len
 * are then undefined.
 *
 * This might look a bit odd due to fast path optimization...
 */
int ntfs_nlstoucs(const ntfs_volume *vol, const char *ins,
		const int ins_len, ntfschar **outs)
{
	struct nls_table *nls = vol->nls_map;
	ntfschar *ucs;
	wchar_t wc;
	int i, o, wc_len;

	/* We do not trust outside sources. */
	if (likely(ins)) {
		ucs = kmem_cache_alloc(ntfs_name_cache, GFP_NOFS);
		if (likely(ucs)) {
			for (i = o = 0; i < ins_len; i += wc_len) {
				wc_len = nls->char2uni(ins + i, ins_len - i,
						&wc);
				if (likely(wc_len >= 0 &&
						o < NTFS_MAX_NAME_LEN)) {
					if (likely(wc)) {
						ucs[o++] = cpu_to_le16(wc);
						continue;
					} /* else if (!wc) */
					break;
				} /* else if (wc_len < 0 ||
						o >= NTFS_MAX_NAME_LEN) */
				goto name_err;
			}
			ucs[o] = 0;
			*outs = ucs;
			return o;
		} /* else if (!ucs) */
		ntfs_error(vol->sb, "Failed to allocate buffer for converted "
				"name from ntfs_name_cache.");
		return -ENOMEM;
	} /* else if (!ins) */
	ntfs_error(vol->sb, "Received NULL pointer.");
	return -EINVAL;
name_err:
	kmem_cache_free(ntfs_name_cache, ucs);
	if (wc_len < 0) {
		ntfs_error(vol->sb, "Name using character set %s contains "
				"characters that cannot be converted to "
				"Unicode.", nls->charset);
		i = -EILSEQ;
	} else /* if (o >= NTFS_MAX_NAME_LEN) */ {
		ntfs_error(vol->sb, "Name is too long (maximum length for a "
				"name on NTFS is %d Unicode characters.",
				NTFS_MAX_NAME_LEN);
		i = -ENAMETOOLONG;
	}
	return i;
}

/**
 * ntfs_ucstonls - convert little endian Unicode string to NLS string
 * @vol:	ntfs volume which we are working with
 * @ins:	input Unicode string buffer
 * @ins_len:	length of input string in Unicode characters
 * @outs:	on return contains the (allocated) output NLS string buffer
 * @outs_len:	length of output string buffer in bytes
 *
 * Convert the input little endian, 2-byte Unicode string @ins, of length
 * @ins_len into the string format dictated by the loaded NLS.
 *
 * If *@outs is NULL, this function allocates the string and the caller is
 * responsible for calling kfree(*@outs); when finished with it. In this case
 * @outs_len is ignored and can be 0.
 *
 * On success the function returns the number of bytes written to the output
 * string *@outs (>= 0), not counting the terminating NULL byte. If the output
 * string buffer was allocated, *@outs is set to it.
 *
 * On error, a negative number corresponding to the error code is returned. In
 * that case the output string is not allocated. The contents of *@outs are
 * then undefined.
 *
 * This might look a bit odd due to fast path optimization...
 */
int ntfs_ucstonls(const ntfs_volume *vol, const ntfschar *ins,
		const int ins_len, unsigned char **outs, int outs_len)
{
	struct nls_table *nls = vol->nls_map;
	unsigned char *ns;
	int i, o, ns_len, wc;

	/* We don't trust outside sources. */
	if (ins) {
		ns = *outs;
		ns_len = outs_len;
		if (ns && !ns_len) {
			wc = -ENAMETOOLONG;
			goto conversion_err;
		}
		if (!ns) {
			ns_len = ins_len * NLS_MAX_CHARSET_SIZE;
			ns = kmalloc(ns_len + 1, GFP_NOFS);
			if (!ns)
				goto mem_err_out;
		}
		for (i = o = 0; i < ins_len; i++) {
retry:			wc = nls->uni2char(le16_to_cpu(ins[i]), ns + o,
					ns_len - o);
			if (wc > 0) {
				o += wc;
				continue;
			} else if (!wc)
				break;
			else if (wc == -ENAMETOOLONG && ns != *outs) {
				unsigned char *tc;
				/* Grow in multiples of 64 bytes. */
				tc = kmalloc((ns_len + 64) &
						~63, GFP_NOFS);
				if (tc) {
					memcpy(tc, ns, ns_len);
					ns_len = ((ns_len + 64) & ~63) - 1;
					kfree(ns);
					ns = tc;
					goto retry;
				} /* No memory so goto conversion_error; */
			} /* wc < 0, real error. */
			goto conversion_err;
		}
		ns[o] = 0;
		*outs = ns;
		return o;
	} /* else (!ins) */
	ntfs_error(vol->sb, "Received NULL pointer.");
	return -EINVAL;
conversion_err:
	ntfs_error(vol->sb, "Unicode name contains characters that cannot be "
			"converted to character set %s.  You might want to "
			"try to use the mount option nls=utf8.", nls->charset);
	if (ns != *outs)
		kfree(ns);
	if (wc != -ENAMETOOLONG)
		wc = -EILSEQ;
	return wc;
mem_err_out:
	ntfs_error(vol->sb, "Failed to allocate name!");
	return -ENOMEM;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/unistr.c */
/************************************************************/
/*
 * upcase.c - Generate the full NTFS Unicode upcase table in little endian.
 *	      Part of the Linux-NTFS project.
 *
 * Copyright (c) 2001 Richard Russon <ntfs@flatcap.org>
 * Copyright (c) 2001-2006 Anton Altaparmakov
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the Linux-NTFS source
 * in the file COPYING); if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

// #include "malloc.h"
// #include "ntfs.h"

ntfschar *generate_default_upcase(void)
{
	static const int uc_run_table[][3] = { /* Start, End, Add */
	{0x0061, 0x007B,  -32}, {0x0451, 0x045D, -80}, {0x1F70, 0x1F72,  74},
	{0x00E0, 0x00F7,  -32}, {0x045E, 0x0460, -80}, {0x1F72, 0x1F76,  86},
	{0x00F8, 0x00FF,  -32}, {0x0561, 0x0587, -48}, {0x1F76, 0x1F78, 100},
	{0x0256, 0x0258, -205}, {0x1F00, 0x1F08,   8}, {0x1F78, 0x1F7A, 128},
	{0x028A, 0x028C, -217}, {0x1F10, 0x1F16,   8}, {0x1F7A, 0x1F7C, 112},
	{0x03AC, 0x03AD,  -38}, {0x1F20, 0x1F28,   8}, {0x1F7C, 0x1F7E, 126},
	{0x03AD, 0x03B0,  -37}, {0x1F30, 0x1F38,   8}, {0x1FB0, 0x1FB2,   8},
	{0x03B1, 0x03C2,  -32}, {0x1F40, 0x1F46,   8}, {0x1FD0, 0x1FD2,   8},
	{0x03C2, 0x03C3,  -31}, {0x1F51, 0x1F52,   8}, {0x1FE0, 0x1FE2,   8},
	{0x03C3, 0x03CC,  -32}, {0x1F53, 0x1F54,   8}, {0x1FE5, 0x1FE6,   7},
	{0x03CC, 0x03CD,  -64}, {0x1F55, 0x1F56,   8}, {0x2170, 0x2180, -16},
	{0x03CD, 0x03CF,  -63}, {0x1F57, 0x1F58,   8}, {0x24D0, 0x24EA, -26},
	{0x0430, 0x0450,  -32}, {0x1F60, 0x1F68,   8}, {0xFF41, 0xFF5B, -32},
	{0}
	};

	static const int uc_dup_table[][2] = { /* Start, End */
	{0x0100, 0x012F}, {0x01A0, 0x01A6}, {0x03E2, 0x03EF}, {0x04CB, 0x04CC},
	{0x0132, 0x0137}, {0x01B3, 0x01B7}, {0x0460, 0x0481}, {0x04D0, 0x04EB},
	{0x0139, 0x0149}, {0x01CD, 0x01DD}, {0x0490, 0x04BF}, {0x04EE, 0x04F5},
	{0x014A, 0x0178}, {0x01DE, 0x01EF}, {0x04BF, 0x04BF}, {0x04F8, 0x04F9},
	{0x0179, 0x017E}, {0x01F4, 0x01F5}, {0x04C1, 0x04C4}, {0x1E00, 0x1E95},
	{0x018B, 0x018B}, {0x01FA, 0x0218}, {0x04C7, 0x04C8}, {0x1EA0, 0x1EF9},
	{0}
	};

	static const int uc_word_table[][2] = { /* Offset, Value */
	{0x00FF, 0x0178}, {0x01AD, 0x01AC}, {0x01F3, 0x01F1}, {0x0269, 0x0196},
	{0x0183, 0x0182}, {0x01B0, 0x01AF}, {0x0253, 0x0181}, {0x026F, 0x019C},
	{0x0185, 0x0184}, {0x01B9, 0x01B8}, {0x0254, 0x0186}, {0x0272, 0x019D},
	{0x0188, 0x0187}, {0x01BD, 0x01BC}, {0x0259, 0x018F}, {0x0275, 0x019F},
	{0x018C, 0x018B}, {0x01C6, 0x01C4}, {0x025B, 0x0190}, {0x0283, 0x01A9},
	{0x0192, 0x0191}, {0x01C9, 0x01C7}, {0x0260, 0x0193}, {0x0288, 0x01AE},
	{0x0199, 0x0198}, {0x01CC, 0x01CA}, {0x0263, 0x0194}, {0x0292, 0x01B7},
	{0x01A8, 0x01A7}, {0x01DD, 0x018E}, {0x0268, 0x0197},
	{0}
	};

	int i, r;
	ntfschar *uc;

	uc = ntfs_malloc_nofs(default_upcase_len * sizeof(ntfschar));
	if (!uc)
		return uc;
	memset(uc, 0, default_upcase_len * sizeof(ntfschar));
	/* Generate the little endian Unicode upcase table used by ntfs. */
	for (i = 0; i < default_upcase_len; i++)
		uc[i] = cpu_to_le16(i);
	for (r = 0; uc_run_table[r][0]; r++)
		for (i = uc_run_table[r][0]; i < uc_run_table[r][1]; i++)
			le16_add_cpu(&uc[i], uc_run_table[r][2]);
	for (r = 0; uc_dup_table[r][0]; r++)
		for (i = uc_dup_table[r][0]; i < uc_dup_table[r][1]; i += 2)
			le16_add_cpu(&uc[i + 1], -1);
	for (r = 0; uc_word_table[r][0]; r++)
		uc[uc_word_table[r][0]] = cpu_to_le16(uc_word_table[r][1]);
	return uc;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ntfs/upcase.c */
/************************************************************/
