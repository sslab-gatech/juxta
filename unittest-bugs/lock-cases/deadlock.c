/***
 * file: fs/ext4/extends_status.c
 * patch id: 3f1f9b851311a76226140b55b1ea22111234a7c2
 * Description:
 * 	a potential deadlock in _ext4_es_shrink()
 ***/


# define __cond_lock(x,c)       ((c) ? ({ __acquire(x); 1; }) : 0)

#define write_trylock(lock)     __cond_lock(lock, _raw_write_trylock(lock))


static int __ext4_es_shrink(struct ext4_sb_info *sbi, int nr_to_scan,
			    struct ext4_inode_info *locked_ei)
{
	struct ext4_inode_info *ei;
	struct list_head *cur, *tmp;
	LIST_HEAD(skipped);
	int nr_shrunk = 0;
	int retried = 0, skip_precached = 1, nr_skipped = 0;

	spin_lock(&sbi->s_es_lru_lock);

retry:
	list_for_each_safe(cur, tmp, &sbi->s_es_lru) {
		int shrunk;

		/*
 * 		 * If we have already reclaimed all extents from extent
 * 		 		 * status tree, just stop the loop immediately.
 * 		 		 		 */
		if (percpu_counter_read_positive(&sbi->s_extent_cache_cnt) == 0)
			break;

		ei = list_entry(cur, struct ext4_inode_info, i_es_lru);

		/*
 * 		 * Skip the inode that is newer than the last_sorted
 * 		 		 * time.  Normally we try hard to avoid shrinking
 * 		 		 		 * precached inodes, but we will as a last resort.
 * 		 		 		 		 */
		if ((sbi->s_es_last_sorted < ei->i_touch_when) ||
		    (skip_precached && ext4_test_inode_state(&ei->vfs_inode,
						EXT4_STATE_EXT_PRECACHED))) {
			nr_skipped++;
			list_move_tail(cur, &skipped);
			continue;
		}

#ifndef __PATCH__
		if (ei->i_es_lru_nr == 0 || ei == locked_ei )
			continue;
		write_lock(&ei->i_es_lock);
		
#else
		if (ei->i_es_lru_nr == 0 || ei == locked_ei ||
		    !write_trylock(&ei->i_es_lock))
			continue;
#endif

		shrunk = __es_try_to_reclaim_extents(ei, nr_to_scan);
		if (ei->i_es_lru_nr == 0)
			list_del_init(&ei->i_es_lru);
		write_unlock(&ei->i_es_lock);

		nr_shrunk += shrunk;
		nr_to_scan -= shrunk;
		if (nr_to_scan == 0)
			break;
	}

	/* Move the newer inodes into the tail of the LRU list. */
	list_splice_tail(&skipped, &sbi->s_es_lru);
	INIT_LIST_HEAD(&skipped);

	/*
 * 	 * If we skipped any inodes, and we weren't able to make any
 * 	 	 * forward progress, sort the list and try again.
 * 	 	 	 */
	if ((nr_shrunk == 0) && nr_skipped && !retried) {
		retried++;
		list_sort(NULL, &sbi->s_es_lru, ext4_inode_touch_time_cmp);
		sbi->s_es_last_sorted = jiffies;
		ei = list_first_entry(&sbi->s_es_lru, struct ext4_inode_info,
				      i_es_lru);
		/*
 * 		 * If there are no non-precached inodes left on the
 * 		 		 * list, start releasing precached extents.
 * 		 		 		 */
		if (ext4_test_inode_state(&ei->vfs_inode,
					  EXT4_STATE_EXT_PRECACHED))
			skip_precached = 0;
		goto retry;
	}

	spin_unlock(&sbi->s_es_lru_lock);

	if (locked_ei && nr_shrunk == 0)
		nr_shrunk = __es_try_to_reclaim_extents(locked_ei, nr_to_scan);

	return nr_shrunk;
}
