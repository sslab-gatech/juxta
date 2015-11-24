/***
 *  fs/ext4/resize.c
 *  patch id: 7f1468d1d50d368097ab13596dc08eaba7eace7f
 *  Bug: double unlock, the second unlock may happen in 
 *  	 bh_submit_read(), bh_uptodate_or_lock() is used 
 *  	 to avoid races.
 *
 ***/

/**
 * bh_uptodate_or_lock - Test whether the buffer is uptodate
 * @bh: struct buffer_head
 *
 * Return true if the buffer is up-to-date and false,
 * with the buffer locked, if not.
 */
int bh_uptodate_or_lock(struct buffer_head *bh)
{
	if (!buffer_uptodate(bh)) {
		lock_buffer(bh);
		if (!buffer_uptodate(bh))
			return 0;
		unlock_buffer(bh);
	}
	return 1;
}

/**
 * bh_submit_read - Submit a locked buffer for reading
 * @bh: struct buffer_head
 *
 * Returns zero on success and -EIO on error.
 */
int bh_submit_read(struct buffer_head *bh)
{
	BUG_ON(!buffer_locked(bh));

	if (buffer_uptodate(bh)) {
		unlock_buffer(bh);
		return 0;
	}

	get_bh(bh);
	bh->b_end_io = end_buffer_read_sync;
	submit_bh(READ, bh);
	wait_on_buffer(bh);
	if (buffer_uptodate(bh))
		return 0;
	return -EIO;
}


static struct buffer_head *ext4_get_bitmap(struct super_block *sb, __u64 block)
{
	struct buffer_head *bh = sb_getblk(sb, block);
	if (!bh)
		return NULL;

#ifndef __PATCH__
	if (bitmap_uptodate(bh))
		return bh;
        
	lock_buffer(bh);
	if (bh_submit_read(bh) < 0) {
		unlock_buffer(bh);
		brelse(bh);
		return NULL;
	}
	unlock_buffer(bh);
#else
	if (!bh_uptodate_or_lock(bh)) {
		if (bh_submit_read(bh) < 0) {
			brelse(bh);
			return NULL;
		}
	}
#endif
	return bh;
}
