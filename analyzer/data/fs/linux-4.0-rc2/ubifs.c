/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file implements UBIFS shrinker which evicts clean znodes from the TNC
 * tree when Linux VM needs more RAM.
 *
 * We do not implement any LRU lists to find oldest znodes to free because it
 * would add additional overhead to the file system fast paths. So the shrinker
 * just walks the TNC tree when searching for znodes to free.
 *
 * If the root of a TNC sub-tree is clean and old enough, then the children are
 * also clean and old enough. So the shrinker walks the TNC in level order and
 * dumps entire sub-trees.
 *
 * The age of znodes is just the time-stamp when they were last looked at.
 * The current shrinker first tries to evict old znodes, then young ones.
 *
 * Since the shrinker is global, it has to protect against races with FS
 * un-mounts, which is done by the 'ubifs_infos_lock' and 'c->umount_mutex'.
 */

#include "ubifs.h"
#include "../../inc/__fss.h"

/* List of all UBIFS file-system instances */
LIST_HEAD(ubifs_infos);

/*
 * We number each shrinker run and record the number on the ubifs_info structure
 * so that we can easily work out which ubifs_info structures have already been
 * done by the current run.
 */
static unsigned int shrinker_run_no;

/* Protects 'ubifs_infos' list */
DEFINE_SPINLOCK(ubifs_infos_lock);

/* Global clean znode counter (for all mounted UBIFS instances) */
atomic_long_t ubifs_clean_zn_cnt;

/**
 * shrink_tnc - shrink TNC tree.
 * @c: UBIFS file-system description object
 * @nr: number of znodes to free
 * @age: the age of znodes to free
 * @contention: if any contention, this is set to %1
 *
 * This function traverses TNC tree and frees clean znodes. It does not free
 * clean znodes which younger then @age. Returns number of freed znodes.
 */
static int shrink_tnc(struct ubifs_info *c, int nr, int age, int *contention)
{
	int total_freed = 0;
	struct ubifs_znode *znode, *zprev;
	int time = get_seconds();

	ubifs_assert(mutex_is_locked(&c->umount_mutex));
	ubifs_assert(mutex_is_locked(&c->tnc_mutex));

	if (!c->zroot.znode || atomic_long_read(&c->clean_zn_cnt) == 0)
		return 0;

	/*
	 * Traverse the TNC tree in levelorder manner, so that it is possible
	 * to destroy large sub-trees. Indeed, if a znode is old, then all its
	 * children are older or of the same age.
	 *
	 * Note, we are holding 'c->tnc_mutex', so we do not have to lock the
	 * 'c->space_lock' when _reading_ 'c->clean_zn_cnt', because it is
	 * changed only when the 'c->tnc_mutex' is held.
	 */
	zprev = NULL;
	znode = ubifs_tnc_levelorder_next(c->zroot.znode, NULL);
	while (znode && total_freed < nr &&
	       atomic_long_read(&c->clean_zn_cnt) > 0) {
		int freed;

		/*
		 * If the znode is clean, but it is in the 'c->cnext' list, this
		 * means that this znode has just been written to flash as a
		 * part of commit and was marked clean. They will be removed
		 * from the list at end commit. We cannot change the list,
		 * because it is not protected by any mutex (design decision to
		 * make commit really independent and parallel to main I/O). So
		 * we just skip these znodes.
		 *
		 * Note, the 'clean_zn_cnt' counters are not updated until
		 * after the commit, so the UBIFS shrinker does not report
		 * the znodes which are in the 'c->cnext' list as freeable.
		 *
		 * Also note, if the root of a sub-tree is not in 'c->cnext',
		 * then the whole sub-tree is not in 'c->cnext' as well, so it
		 * is safe to dump whole sub-tree.
		 */

		if (znode->cnext) {
			/*
			 * Very soon these znodes will be removed from the list
			 * and become freeable.
			 */
			*contention = 1;
		} else if (!ubifs_zn_dirty(znode) &&
			   abs(time - znode->time) >= age) {
			if (znode->parent)
				znode->parent->zbranch[znode->iip].znode = NULL;
			else
				c->zroot.znode = NULL;

			freed = ubifs_destroy_tnc_subtree(znode);
			atomic_long_sub(freed, &ubifs_clean_zn_cnt);
			atomic_long_sub(freed, &c->clean_zn_cnt);
			total_freed += freed;
			znode = zprev;
		}

		if (unlikely(!c->zroot.znode))
			break;

		zprev = znode;
		znode = ubifs_tnc_levelorder_next(c->zroot.znode, znode);
		cond_resched();
	}

	return total_freed;
}

/**
 * shrink_tnc_trees - shrink UBIFS TNC trees.
 * @nr: number of znodes to free
 * @age: the age of znodes to free
 * @contention: if any contention, this is set to %1
 *
 * This function walks the list of mounted UBIFS file-systems and frees clean
 * znodes which are older than @age, until at least @nr znodes are freed.
 * Returns the number of freed znodes.
 */
static int shrink_tnc_trees(int nr, int age, int *contention)
{
	struct ubifs_info *c;
	struct list_head *p;
	unsigned int run_no;
	int freed = 0;

	spin_lock(&ubifs_infos_lock);
	do {
		run_no = ++shrinker_run_no;
	} while (run_no == 0);
	/* Iterate over all mounted UBIFS file-systems and try to shrink them */
	p = ubifs_infos.next;
	while (p != &ubifs_infos) {
		c = list_entry(p, struct ubifs_info, infos_list);
		/*
		 * We move the ones we do to the end of the list, so we stop
		 * when we see one we have already done.
		 */
		if (c->shrinker_run_no == run_no)
			break;
		if (!mutex_trylock(&c->umount_mutex)) {
			/* Some un-mount is in progress, try next FS */
			*contention = 1;
			p = p->next;
			continue;
		}
		/*
		 * We're holding 'c->umount_mutex', so the file-system won't go
		 * away.
		 */
		if (!mutex_trylock(&c->tnc_mutex)) {
			mutex_unlock(&c->umount_mutex);
			*contention = 1;
			p = p->next;
			continue;
		}
		spin_unlock(&ubifs_infos_lock);
		/*
		 * OK, now we have TNC locked, the file-system cannot go away -
		 * it is safe to reap the cache.
		 */
		c->shrinker_run_no = run_no;
		freed += shrink_tnc(c, nr, age, contention);
		mutex_unlock(&c->tnc_mutex);
		spin_lock(&ubifs_infos_lock);
		/* Get the next list element before we move this one */
		p = p->next;
		/*
		 * Move this one to the end of the list to provide some
		 * fairness.
		 */
		list_move_tail(&c->infos_list, &ubifs_infos);
		mutex_unlock(&c->umount_mutex);
		if (freed >= nr)
			break;
	}
	spin_unlock(&ubifs_infos_lock);
	return freed;
}

/**
 * kick_a_thread - kick a background thread to start commit.
 *
 * This function kicks a background thread to start background commit. Returns
 * %-1 if a thread was kicked or there is another reason to assume the memory
 * will soon be freed or become freeable. If there are no dirty znodes, returns
 * %0.
 */
static int kick_a_thread(void)
{
	int i;
	struct ubifs_info *c;

	/*
	 * Iterate over all mounted UBIFS file-systems and find out if there is
	 * already an ongoing commit operation there. If no, then iterate for
	 * the second time and initiate background commit.
	 */
	spin_lock(&ubifs_infos_lock);
	for (i = 0; i < 2; i++) {
		list_for_each_entry(c, &ubifs_infos, infos_list) {
			long dirty_zn_cnt;

			if (!mutex_trylock(&c->umount_mutex)) {
				/*
				 * Some un-mount is in progress, it will
				 * certainly free memory, so just return.
				 */
				spin_unlock(&ubifs_infos_lock);
				return -1;
			}

			dirty_zn_cnt = atomic_long_read(&c->dirty_zn_cnt);

			if (!dirty_zn_cnt || c->cmt_state == COMMIT_BROKEN ||
			    c->ro_mount || c->ro_error) {
				mutex_unlock(&c->umount_mutex);
				continue;
			}

			if (c->cmt_state != COMMIT_RESTING) {
				spin_unlock(&ubifs_infos_lock);
				mutex_unlock(&c->umount_mutex);
				return -1;
			}

			if (i == 1) {
				list_move_tail(&c->infos_list, &ubifs_infos);
				spin_unlock(&ubifs_infos_lock);

				ubifs_request_bg_commit(c);
				mutex_unlock(&c->umount_mutex);
				return -1;
			}
			mutex_unlock(&c->umount_mutex);
		}
	}
	spin_unlock(&ubifs_infos_lock);

	return 0;
}

unsigned long ubifs_shrink_count(struct shrinker *shrink,
				 struct shrink_control *sc)
{
	long clean_zn_cnt = atomic_long_read(&ubifs_clean_zn_cnt);

	/*
	 * Due to the way UBIFS updates the clean znode counter it may
	 * temporarily be negative.
	 */
	return clean_zn_cnt >= 0 ? clean_zn_cnt : 1;
}

unsigned long ubifs_shrink_scan(struct shrinker *shrink,
				struct shrink_control *sc)
{
	unsigned long nr = sc->nr_to_scan;
	int contention = 0;
	unsigned long freed;
	long clean_zn_cnt = atomic_long_read(&ubifs_clean_zn_cnt);

	if (!clean_zn_cnt) {
		/*
		 * No clean znodes, nothing to reap. All we can do in this case
		 * is to kick background threads to start commit, which will
		 * probably make clean znodes which, in turn, will be freeable.
		 * And we return -1 which means will make VM call us again
		 * later.
		 */
		dbg_tnc("no clean znodes, kick a thread");
		return kick_a_thread();
	}

	freed = shrink_tnc_trees(nr, OLD_ZNODE_AGE, &contention);
	if (freed >= nr)
		goto out;

	dbg_tnc("not enough old znodes, try to free young ones");
	freed += shrink_tnc_trees(nr - freed, YOUNG_ZNODE_AGE, &contention);
	if (freed >= nr)
		goto out;

	dbg_tnc("not enough young znodes, free all");
	freed += shrink_tnc_trees(nr - freed, 0, &contention);

	if (!freed && contention) {
		dbg_tnc("freed nothing, but contention");
		return SHRINK_STOP;
	}

out:
	dbg_tnc("%lu znodes were freed, requested %lu", freed, nr);
	return freed;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/shrinker.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file implements UBIFS journal.
 *
 * The journal consists of 2 parts - the log and bud LEBs. The log has fixed
 * length and position, while a bud logical eraseblock is any LEB in the main
 * area. Buds contain file system data - data nodes, inode nodes, etc. The log
 * contains only references to buds and some other stuff like commit
 * start node. The idea is that when we commit the journal, we do
 * not copy the data, the buds just become indexed. Since after the commit the
 * nodes in bud eraseblocks become leaf nodes of the file system index tree, we
 * use term "bud". Analogy is obvious, bud eraseblocks contain nodes which will
 * become leafs in the future.
 *
 * The journal is multi-headed because we want to write data to the journal as
 * optimally as possible. It is nice to have nodes belonging to the same inode
 * in one LEB, so we may write data owned by different inodes to different
 * journal heads, although at present only one data head is used.
 *
 * For recovery reasons, the base head contains all inode nodes, all directory
 * entry nodes and all truncate nodes. This means that the other heads contain
 * only data nodes.
 *
 * Bud LEBs may be half-indexed. For example, if the bud was not full at the
 * time of commit, the bud is retained to continue to be used in the journal,
 * even though the "front" of the LEB is now indexed. In that case, the log
 * reference contains the offset where the bud starts for the purposes of the
 * journal.
 *
 * The journal size has to be limited, because the larger is the journal, the
 * longer it takes to mount UBIFS (scanning the journal) and the more memory it
 * takes (indexing in the TNC).
 *
 * All the journal write operations like 'ubifs_jnl_update()' here, which write
 * multiple UBIFS nodes to the journal at one go, are atomic with respect to
 * unclean reboots. Should the unclean reboot happen, the recovery code drops
 * all the nodes.
 */

// #include "ubifs.h"

/**
 * zero_ino_node_unused - zero out unused fields of an on-flash inode node.
 * @ino: the inode to zero out
 */
static inline void zero_ino_node_unused(struct ubifs_ino_node *ino)
{
	memset(ino->padding1, 0, 4);
	memset(ino->padding2, 0, 26);
}

/**
 * zero_dent_node_unused - zero out unused fields of an on-flash directory
 *                         entry node.
 * @dent: the directory entry to zero out
 */
static inline void zero_dent_node_unused(struct ubifs_dent_node *dent)
{
	dent->padding1 = 0;
	memset(dent->padding2, 0, 4);
}

/**
 * zero_data_node_unused - zero out unused fields of an on-flash data node.
 * @data: the data node to zero out
 */
static inline void zero_data_node_unused(struct ubifs_data_node *data)
{
	memset(data->padding, 0, 2);
}

/**
 * zero_trun_node_unused - zero out unused fields of an on-flash truncation
 *                         node.
 * @trun: the truncation node to zero out
 */
static inline void zero_trun_node_unused(struct ubifs_trun_node *trun)
{
	memset(trun->padding, 0, 12);
}

/**
 * reserve_space - reserve space in the journal.
 * @c: UBIFS file-system description object
 * @jhead: journal head number
 * @len: node length
 *
 * This function reserves space in journal head @head. If the reservation
 * succeeded, the journal head stays locked and later has to be unlocked using
 * 'release_head()'. 'write_node()' and 'write_head()' functions also unlock
 * it. Returns zero in case of success, %-EAGAIN if commit has to be done, and
 * other negative error codes in case of other failures.
 */
static int reserve_space(struct ubifs_info *c, int jhead, int len)
{
	int err = 0, err1, retries = 0, avail, lnum, offs, squeeze;
	struct ubifs_wbuf *wbuf = &c->jheads[jhead].wbuf;

	/*
	 * Typically, the base head has smaller nodes written to it, so it is
	 * better to try to allocate space at the ends of eraseblocks. This is
	 * what the squeeze parameter does.
	 */
	ubifs_assert(!c->ro_media && !c->ro_mount);
	squeeze = (jhead == BASEHD);
again:
	mutex_lock_nested(&wbuf->io_mutex, wbuf->jhead);

	if (c->ro_error) {
		err = -EROFS;
		goto out_unlock;
	}

	avail = c->leb_size - wbuf->offs - wbuf->used;
	if (wbuf->lnum != -1 && avail >= len)
		return 0;

	/*
	 * Write buffer wasn't seek'ed or there is no enough space - look for an
	 * LEB with some empty space.
	 */
	lnum = ubifs_find_free_space(c, len, &offs, squeeze);
	if (lnum >= 0)
		goto out;

	err = lnum;
	if (err != -ENOSPC)
		goto out_unlock;

	/*
	 * No free space, we have to run garbage collector to make
	 * some. But the write-buffer mutex has to be unlocked because
	 * GC also takes it.
	 */
	dbg_jnl("no free space in jhead %s, run GC", dbg_jhead(jhead));
	mutex_unlock(&wbuf->io_mutex);

	lnum = ubifs_garbage_collect(c, 0);
	if (lnum < 0) {
		err = lnum;
		if (err != -ENOSPC)
			return err;

		/*
		 * GC could not make a free LEB. But someone else may
		 * have allocated new bud for this journal head,
		 * because we dropped @wbuf->io_mutex, so try once
		 * again.
		 */
		dbg_jnl("GC couldn't make a free LEB for jhead %s",
			dbg_jhead(jhead));
		if (retries++ < 2) {
			dbg_jnl("retry (%d)", retries);
			goto again;
		}

		dbg_jnl("return -ENOSPC");
		return err;
	}

	mutex_lock_nested(&wbuf->io_mutex, wbuf->jhead);
	dbg_jnl("got LEB %d for jhead %s", lnum, dbg_jhead(jhead));
	avail = c->leb_size - wbuf->offs - wbuf->used;

	if (wbuf->lnum != -1 && avail >= len) {
		/*
		 * Someone else has switched the journal head and we have
		 * enough space now. This happens when more than one process is
		 * trying to write to the same journal head at the same time.
		 */
		dbg_jnl("return LEB %d back, already have LEB %d:%d",
			lnum, wbuf->lnum, wbuf->offs + wbuf->used);
		err = ubifs_return_leb(c, lnum);
		if (err)
			goto out_unlock;
		return 0;
	}

	offs = 0;

out:
	/*
	 * Make sure we synchronize the write-buffer before we add the new bud
	 * to the log. Otherwise we may have a power cut after the log
	 * reference node for the last bud (@lnum) is written but before the
	 * write-buffer data are written to the next-to-last bud
	 * (@wbuf->lnum). And the effect would be that the recovery would see
	 * that there is corruption in the next-to-last bud.
	 */
	err = ubifs_wbuf_sync_nolock(wbuf);
	if (err)
		goto out_return;
	err = ubifs_add_bud_to_log(c, jhead, lnum, offs);
	if (err)
		goto out_return;
	err = ubifs_wbuf_seek_nolock(wbuf, lnum, offs);
	if (err)
		goto out_unlock;

	return 0;

out_unlock:
	mutex_unlock(&wbuf->io_mutex);
	return err;

out_return:
	/* An error occurred and the LEB has to be returned to lprops */
	ubifs_assert(err < 0);
	err1 = ubifs_return_leb(c, lnum);
	if (err1 && err == -EAGAIN)
		/*
		 * Return original error code only if it is not %-EAGAIN,
		 * which is not really an error. Otherwise, return the error
		 * code of 'ubifs_return_leb()'.
		 */
		err = err1;
	mutex_unlock(&wbuf->io_mutex);
	return err;
}

/**
 * write_node - write node to a journal head.
 * @c: UBIFS file-system description object
 * @jhead: journal head
 * @node: node to write
 * @len: node length
 * @lnum: LEB number written is returned here
 * @offs: offset written is returned here
 *
 * This function writes a node to reserved space of journal head @jhead.
 * Returns zero in case of success and a negative error code in case of
 * failure.
 */
static int write_node(struct ubifs_info *c, int jhead, void *node, int len,
		      int *lnum, int *offs)
{
	struct ubifs_wbuf *wbuf = &c->jheads[jhead].wbuf;

	ubifs_assert(jhead != GCHD);

	*lnum = c->jheads[jhead].wbuf.lnum;
	*offs = c->jheads[jhead].wbuf.offs + c->jheads[jhead].wbuf.used;

	dbg_jnl("jhead %s, LEB %d:%d, len %d",
		dbg_jhead(jhead), *lnum, *offs, len);
	ubifs_prepare_node(c, node, len, 0);

	return ubifs_wbuf_write_nolock(wbuf, node, len);
}

/**
 * write_head - write data to a journal head.
 * @c: UBIFS file-system description object
 * @jhead: journal head
 * @buf: buffer to write
 * @len: length to write
 * @lnum: LEB number written is returned here
 * @offs: offset written is returned here
 * @sync: non-zero if the write-buffer has to by synchronized
 *
 * This function is the same as 'write_node()' but it does not assume the
 * buffer it is writing is a node, so it does not prepare it (which means
 * initializing common header and calculating CRC).
 */
static int write_head(struct ubifs_info *c, int jhead, void *buf, int len,
		      int *lnum, int *offs, int sync)
{
	int err;
	struct ubifs_wbuf *wbuf = &c->jheads[jhead].wbuf;

	ubifs_assert(jhead != GCHD);

	*lnum = c->jheads[jhead].wbuf.lnum;
	*offs = c->jheads[jhead].wbuf.offs + c->jheads[jhead].wbuf.used;
	dbg_jnl("jhead %s, LEB %d:%d, len %d",
		dbg_jhead(jhead), *lnum, *offs, len);

	err = ubifs_wbuf_write_nolock(wbuf, buf, len);
	if (err)
		return err;
	if (sync)
		err = ubifs_wbuf_sync_nolock(wbuf);
	return err;
}

/**
 * make_reservation - reserve journal space.
 * @c: UBIFS file-system description object
 * @jhead: journal head
 * @len: how many bytes to reserve
 *
 * This function makes space reservation in journal head @jhead. The function
 * takes the commit lock and locks the journal head, and the caller has to
 * unlock the head and finish the reservation with 'finish_reservation()'.
 * Returns zero in case of success and a negative error code in case of
 * failure.
 *
 * Note, the journal head may be unlocked as soon as the data is written, while
 * the commit lock has to be released after the data has been added to the
 * TNC.
 */
static int make_reservation(struct ubifs_info *c, int jhead, int len)
{
	int err, cmt_retries = 0, nospc_retries = 0;

again:
	down_read(&c->commit_sem);
	err = reserve_space(c, jhead, len);
	if (!err)
		return 0;
	up_read(&c->commit_sem);

	if (err == -ENOSPC) {
		/*
		 * GC could not make any progress. We should try to commit
		 * once because it could make some dirty space and GC would
		 * make progress, so make the error -EAGAIN so that the below
		 * will commit and re-try.
		 */
		if (nospc_retries++ < 2) {
			dbg_jnl("no space, retry");
			err = -EAGAIN;
		}

		/*
		 * This means that the budgeting is incorrect. We always have
		 * to be able to write to the media, because all operations are
		 * budgeted. Deletions are not budgeted, though, but we reserve
		 * an extra LEB for them.
		 */
	}

	if (err != -EAGAIN)
		goto out;

	/*
	 * -EAGAIN means that the journal is full or too large, or the above
	 * code wants to do one commit. Do this and re-try.
	 */
	if (cmt_retries > 128) {
		/*
		 * This should not happen unless the journal size limitations
		 * are too tough.
		 */
		ubifs_err("stuck in space allocation");
		err = -ENOSPC;
		goto out;
	} else if (cmt_retries > 32)
		ubifs_warn("too many space allocation re-tries (%d)",
			   cmt_retries);

	dbg_jnl("-EAGAIN, commit and retry (retried %d times)",
		cmt_retries);
	cmt_retries += 1;

	err = ubifs_run_commit(c);
	if (err)
		return err;
	goto again;

out:
	ubifs_err("cannot reserve %d bytes in jhead %d, error %d",
		  len, jhead, err);
	if (err == -ENOSPC) {
		/* This are some budgeting problems, print useful information */
		down_write(&c->commit_sem);
		dump_stack();
		ubifs_dump_budg(c, &c->bi);
		ubifs_dump_lprops(c);
		cmt_retries = dbg_check_lprops(c);
		up_write(&c->commit_sem);
	}
	return err;
}

/**
 * release_head - release a journal head.
 * @c: UBIFS file-system description object
 * @jhead: journal head
 *
 * This function releases journal head @jhead which was locked by
 * the 'make_reservation()' function. It has to be called after each successful
 * 'make_reservation()' invocation.
 */
static inline void release_head(struct ubifs_info *c, int jhead)
{
	mutex_unlock(&c->jheads[jhead].wbuf.io_mutex);
}

/**
 * finish_reservation - finish a reservation.
 * @c: UBIFS file-system description object
 *
 * This function finishes journal space reservation. It must be called after
 * 'make_reservation()'.
 */
static void finish_reservation(struct ubifs_info *c)
{
	up_read(&c->commit_sem);
}

/**
 * get_dent_type - translate VFS inode mode to UBIFS directory entry type.
 * @mode: inode mode
 */
static int get_dent_type_journal_c(int mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
		return UBIFS_ITYPE_REG;
	case S_IFDIR:
		return UBIFS_ITYPE_DIR;
	case S_IFLNK:
		return UBIFS_ITYPE_LNK;
	case S_IFBLK:
		return UBIFS_ITYPE_BLK;
	case S_IFCHR:
		return UBIFS_ITYPE_CHR;
	case S_IFIFO:
		return UBIFS_ITYPE_FIFO;
	case S_IFSOCK:
		return UBIFS_ITYPE_SOCK;
	default:
		BUG();
	}
	return 0;
}

/**
 * pack_inode - pack an inode node.
 * @c: UBIFS file-system description object
 * @ino: buffer in which to pack inode node
 * @inode: inode to pack
 * @last: indicates the last node of the group
 */
static void pack_inode(struct ubifs_info *c, struct ubifs_ino_node *ino,
		       const struct inode *inode, int last)
{
	int data_len = 0, last_reference = !inode->i_nlink;
	struct ubifs_inode *ui = ubifs_inode(inode);

	ino->ch.node_type = UBIFS_INO_NODE;
	ino_key_init_flash(c, &ino->key, inode->i_ino);
	ino->creat_sqnum = cpu_to_le64(ui->creat_sqnum);
	ino->atime_sec  = cpu_to_le64(inode->i_atime.tv_sec);
	ino->atime_nsec = cpu_to_le32(inode->i_atime.tv_nsec);
	ino->ctime_sec  = cpu_to_le64(inode->i_ctime.tv_sec);
	ino->ctime_nsec = cpu_to_le32(inode->i_ctime.tv_nsec);
	ino->mtime_sec  = cpu_to_le64(inode->i_mtime.tv_sec);
	ino->mtime_nsec = cpu_to_le32(inode->i_mtime.tv_nsec);
	ino->uid   = cpu_to_le32(i_uid_read(inode));
	ino->gid   = cpu_to_le32(i_gid_read(inode));
	ino->mode  = cpu_to_le32(inode->i_mode);
	ino->flags = cpu_to_le32(ui->flags);
	ino->size  = cpu_to_le64(ui->ui_size);
	ino->nlink = cpu_to_le32(inode->i_nlink);
	ino->compr_type  = cpu_to_le16(ui->compr_type);
	ino->data_len    = cpu_to_le32(ui->data_len);
	ino->xattr_cnt   = cpu_to_le32(ui->xattr_cnt);
	ino->xattr_size  = cpu_to_le32(ui->xattr_size);
	ino->xattr_names = cpu_to_le32(ui->xattr_names);
	zero_ino_node_unused(ino);

	/*
	 * Drop the attached data if this is a deletion inode, the data is not
	 * needed anymore.
	 */
	if (!last_reference) {
		memcpy(ino->data, ui->data, ui->data_len);
		data_len = ui->data_len;
	}

	ubifs_prep_grp_node(c, ino, UBIFS_INO_NODE_SZ + data_len, last);
}

/**
 * mark_inode_clean - mark UBIFS inode as clean.
 * @c: UBIFS file-system description object
 * @ui: UBIFS inode to mark as clean
 *
 * This helper function marks UBIFS inode @ui as clean by cleaning the
 * @ui->dirty flag and releasing its budget. Note, VFS may still treat the
 * inode as dirty and try to write it back, but 'ubifs_write_inode()' would
 * just do nothing.
 */
static void mark_inode_clean(struct ubifs_info *c, struct ubifs_inode *ui)
{
	if (ui->dirty)
		ubifs_release_dirty_inode_budget(c, ui);
	ui->dirty = 0;
}

/**
 * ubifs_jnl_update - update inode.
 * @c: UBIFS file-system description object
 * @dir: parent inode or host inode in case of extended attributes
 * @nm: directory entry name
 * @inode: inode to update
 * @deletion: indicates a directory entry deletion i.e unlink or rmdir
 * @xent: non-zero if the directory entry is an extended attribute entry
 *
 * This function updates an inode by writing a directory entry (or extended
 * attribute entry), the inode itself, and the parent directory inode (or the
 * host inode) to the journal.
 *
 * The function writes the host inode @dir last, which is important in case of
 * extended attributes. Indeed, then we guarantee that if the host inode gets
 * synchronized (with 'fsync()'), and the write-buffer it sits in gets flushed,
 * the extended attribute inode gets flushed too. And this is exactly what the
 * user expects - synchronizing the host inode synchronizes its extended
 * attributes. Similarly, this guarantees that if @dir is synchronized, its
 * directory entry corresponding to @nm gets synchronized too.
 *
 * If the inode (@inode) or the parent directory (@dir) are synchronous, this
 * function synchronizes the write-buffer.
 *
 * This function marks the @dir and @inode inodes as clean and returns zero on
 * success. In case of failure, a negative error code is returned.
 */
int ubifs_jnl_update(struct ubifs_info *c, const struct inode *dir,
		     const struct qstr *nm, const struct inode *inode,
		     int deletion, int xent)
{
	int err, dlen, ilen, len, lnum, ino_offs, dent_offs;
	int aligned_dlen, aligned_ilen, sync = IS_DIRSYNC(dir);
	int last_reference = !!(deletion && inode->i_nlink == 0);
	struct ubifs_inode *ui = ubifs_inode(inode);
	struct ubifs_inode *host_ui = ubifs_inode(dir);
	struct ubifs_dent_node *dent;
	struct ubifs_ino_node *ino;
	union ubifs_key dent_key, ino_key;

	dbg_jnl("ino %lu, dent '%.*s', data len %d in dir ino %lu",
		inode->i_ino, nm->len, nm->name, ui->data_len, dir->i_ino);
	ubifs_assert(mutex_is_locked(&host_ui->ui_mutex));

	dlen = UBIFS_DENT_NODE_SZ + nm->len + 1;
	ilen = UBIFS_INO_NODE_SZ;

	/*
	 * If the last reference to the inode is being deleted, then there is
	 * no need to attach and write inode data, it is being deleted anyway.
	 * And if the inode is being deleted, no need to synchronize
	 * write-buffer even if the inode is synchronous.
	 */
	if (!last_reference) {
		ilen += ui->data_len;
		sync |= IS_SYNC(inode);
	}

	aligned_dlen = ALIGN(dlen, 8);
	aligned_ilen = ALIGN(ilen, 8);

	len = aligned_dlen + aligned_ilen + UBIFS_INO_NODE_SZ;
	/* Make sure to also account for extended attributes */
	len += host_ui->data_len;

	dent = kmalloc(len, GFP_NOFS);
	if (!dent)
		return -ENOMEM;

	/* Make reservation before allocating sequence numbers */
	err = make_reservation(c, BASEHD, len);
	if (err)
		goto out_free;

	if (!xent) {
		dent->ch.node_type = UBIFS_DENT_NODE;
		dent_key_init(c, &dent_key, dir->i_ino, nm);
	} else {
		dent->ch.node_type = UBIFS_XENT_NODE;
		xent_key_init(c, &dent_key, dir->i_ino, nm);
	}

	key_write(c, &dent_key, dent->key);
	dent->inum = deletion ? 0 : cpu_to_le64(inode->i_ino);
	dent->type = get_dent_type_journal_c(inode->i_mode);
	dent->nlen = cpu_to_le16(nm->len);
	memcpy(dent->name, nm->name, nm->len);
	dent->name[nm->len] = '\0';
	zero_dent_node_unused(dent);
	ubifs_prep_grp_node(c, dent, dlen, 0);

	ino = (void *)dent + aligned_dlen;
	pack_inode(c, ino, inode, 0);
	ino = (void *)ino + aligned_ilen;
	pack_inode(c, ino, dir, 1);

	if (last_reference) {
		err = ubifs_add_orphan(c, inode->i_ino);
		if (err) {
			release_head(c, BASEHD);
			goto out_finish;
		}
		ui->del_cmtno = c->cmt_no;
	}

	err = write_head(c, BASEHD, dent, len, &lnum, &dent_offs, sync);
	if (err)
		goto out_release;
	if (!sync) {
		struct ubifs_wbuf *wbuf = &c->jheads[BASEHD].wbuf;

		ubifs_wbuf_add_ino_nolock(wbuf, inode->i_ino);
		ubifs_wbuf_add_ino_nolock(wbuf, dir->i_ino);
	}
	release_head(c, BASEHD);
	kfree(dent);

	if (deletion) {
		err = ubifs_tnc_remove_nm(c, &dent_key, nm);
		if (err)
			goto out_ro;
		err = ubifs_add_dirt(c, lnum, dlen);
	} else
		err = ubifs_tnc_add_nm(c, &dent_key, lnum, dent_offs, dlen, nm);
	if (err)
		goto out_ro;

	/*
	 * Note, we do not remove the inode from TNC even if the last reference
	 * to it has just been deleted, because the inode may still be opened.
	 * Instead, the inode has been added to orphan lists and the orphan
	 * subsystem will take further care about it.
	 */
	ino_key_init(c, &ino_key, inode->i_ino);
	ino_offs = dent_offs + aligned_dlen;
	err = ubifs_tnc_add(c, &ino_key, lnum, ino_offs, ilen);
	if (err)
		goto out_ro;

	ino_key_init(c, &ino_key, dir->i_ino);
	ino_offs += aligned_ilen;
	err = ubifs_tnc_add(c, &ino_key, lnum, ino_offs,
			    UBIFS_INO_NODE_SZ + host_ui->data_len);
	if (err)
		goto out_ro;

	finish_reservation(c);
	spin_lock(&ui->ui_lock);
	ui->synced_i_size = ui->ui_size;
	spin_unlock(&ui->ui_lock);
	mark_inode_clean(c, ui);
	mark_inode_clean(c, host_ui);
	return 0;

out_finish:
	finish_reservation(c);
out_free:
	kfree(dent);
	return err;

out_release:
	release_head(c, BASEHD);
	kfree(dent);
out_ro:
	ubifs_ro_mode(c, err);
	if (last_reference)
		ubifs_delete_orphan(c, inode->i_ino);
	finish_reservation(c);
	return err;
}

/**
 * ubifs_jnl_write_data - write a data node to the journal.
 * @c: UBIFS file-system description object
 * @inode: inode the data node belongs to
 * @key: node key
 * @buf: buffer to write
 * @len: data length (must not exceed %UBIFS_BLOCK_SIZE)
 *
 * This function writes a data node to the journal. Returns %0 if the data node
 * was successfully written, and a negative error code in case of failure.
 */
int ubifs_jnl_write_data(struct ubifs_info *c, const struct inode *inode,
			 const union ubifs_key *key, const void *buf, int len)
{
	struct ubifs_data_node *data;
	int err, lnum, offs, compr_type, out_len;
	int dlen = COMPRESSED_DATA_NODE_BUF_SZ, allocated = 1;
	struct ubifs_inode *ui = ubifs_inode(inode);

	dbg_jnlk(key, "ino %lu, blk %u, len %d, key ",
		(unsigned long)key_inum(c, key), key_block(c, key), len);
	ubifs_assert(len <= UBIFS_BLOCK_SIZE);

	data = kmalloc(dlen, GFP_NOFS | __GFP_NOWARN);
	if (!data) {
		/*
		 * Fall-back to the write reserve buffer. Note, we might be
		 * currently on the memory reclaim path, when the kernel is
		 * trying to free some memory by writing out dirty pages. The
		 * write reserve buffer helps us to guarantee that we are
		 * always able to write the data.
		 */
		allocated = 0;
		mutex_lock(&c->write_reserve_mutex);
		data = c->write_reserve_buf;
	}

	data->ch.node_type = UBIFS_DATA_NODE;
	key_write(c, key, &data->key);
	data->size = cpu_to_le32(len);
	zero_data_node_unused(data);

	if (!(ui->flags & UBIFS_COMPR_FL))
		/* Compression is disabled for this inode */
		compr_type = UBIFS_COMPR_NONE;
	else
		compr_type = ui->compr_type;

	out_len = dlen - UBIFS_DATA_NODE_SZ;
	ubifs_compress(buf, len, &data->data, &out_len, &compr_type);
	ubifs_assert(out_len <= UBIFS_BLOCK_SIZE);

	dlen = UBIFS_DATA_NODE_SZ + out_len;
	data->compr_type = cpu_to_le16(compr_type);

	/* Make reservation before allocating sequence numbers */
	err = make_reservation(c, DATAHD, dlen);
	if (err)
		goto out_free;

	err = write_node(c, DATAHD, data, dlen, &lnum, &offs);
	if (err)
		goto out_release;
	ubifs_wbuf_add_ino_nolock(&c->jheads[DATAHD].wbuf, key_inum(c, key));
	release_head(c, DATAHD);

	err = ubifs_tnc_add(c, key, lnum, offs, dlen);
	if (err)
		goto out_ro;

	finish_reservation(c);
	if (!allocated)
		mutex_unlock(&c->write_reserve_mutex);
	else
		kfree(data);
	return 0;

out_release:
	release_head(c, DATAHD);
out_ro:
	ubifs_ro_mode(c, err);
	finish_reservation(c);
out_free:
	if (!allocated)
		mutex_unlock(&c->write_reserve_mutex);
	else
		kfree(data);
	return err;
}

/**
 * ubifs_jnl_write_inode - flush inode to the journal.
 * @c: UBIFS file-system description object
 * @inode: inode to flush
 *
 * This function writes inode @inode to the journal. If the inode is
 * synchronous, it also synchronizes the write-buffer. Returns zero in case of
 * success and a negative error code in case of failure.
 */
int ubifs_jnl_write_inode(struct ubifs_info *c, const struct inode *inode)
{
	int err, lnum, offs;
	struct ubifs_ino_node *ino;
	struct ubifs_inode *ui = ubifs_inode(inode);
	int sync = 0, len = UBIFS_INO_NODE_SZ, last_reference = !inode->i_nlink;

	dbg_jnl("ino %lu, nlink %u", inode->i_ino, inode->i_nlink);

	/*
	 * If the inode is being deleted, do not write the attached data. No
	 * need to synchronize the write-buffer either.
	 */
	if (!last_reference) {
		len += ui->data_len;
		sync = IS_SYNC(inode);
	}
	ino = kmalloc(len, GFP_NOFS);
	if (!ino)
		return -ENOMEM;

	/* Make reservation before allocating sequence numbers */
	err = make_reservation(c, BASEHD, len);
	if (err)
		goto out_free;

	pack_inode(c, ino, inode, 1);
	err = write_head(c, BASEHD, ino, len, &lnum, &offs, sync);
	if (err)
		goto out_release;
	if (!sync)
		ubifs_wbuf_add_ino_nolock(&c->jheads[BASEHD].wbuf,
					  inode->i_ino);
	release_head(c, BASEHD);

	if (last_reference) {
		err = ubifs_tnc_remove_ino(c, inode->i_ino);
		if (err)
			goto out_ro;
		ubifs_delete_orphan(c, inode->i_ino);
		err = ubifs_add_dirt(c, lnum, len);
	} else {
		union ubifs_key key;

		ino_key_init(c, &key, inode->i_ino);
		err = ubifs_tnc_add(c, &key, lnum, offs, len);
	}
	if (err)
		goto out_ro;

	finish_reservation(c);
	spin_lock(&ui->ui_lock);
	ui->synced_i_size = ui->ui_size;
	spin_unlock(&ui->ui_lock);
	kfree(ino);
	return 0;

out_release:
	release_head(c, BASEHD);
out_ro:
	ubifs_ro_mode(c, err);
	finish_reservation(c);
out_free:
	kfree(ino);
	return err;
}

/**
 * ubifs_jnl_delete_inode - delete an inode.
 * @c: UBIFS file-system description object
 * @inode: inode to delete
 *
 * This function deletes inode @inode which includes removing it from orphans,
 * deleting it from TNC and, in some cases, writing a deletion inode to the
 * journal.
 *
 * When regular file inodes are unlinked or a directory inode is removed, the
 * 'ubifs_jnl_update()' function writes a corresponding deletion inode and
 * direntry to the media, and adds the inode to orphans. After this, when the
 * last reference to this inode has been dropped, this function is called. In
 * general, it has to write one more deletion inode to the media, because if
 * a commit happened between 'ubifs_jnl_update()' and
 * 'ubifs_jnl_delete_inode()', the deletion inode is not in the journal
 * anymore, and in fact it might not be on the flash anymore, because it might
 * have been garbage-collected already. And for optimization reasons UBIFS does
 * not read the orphan area if it has been unmounted cleanly, so it would have
 * no indication in the journal that there is a deleted inode which has to be
 * removed from TNC.
 *
 * However, if there was no commit between 'ubifs_jnl_update()' and
 * 'ubifs_jnl_delete_inode()', then there is no need to write the deletion
 * inode to the media for the second time. And this is quite a typical case.
 *
 * This function returns zero in case of success and a negative error code in
 * case of failure.
 */
int ubifs_jnl_delete_inode(struct ubifs_info *c, const struct inode *inode)
{
	int err;
	struct ubifs_inode *ui = ubifs_inode(inode);

	ubifs_assert(inode->i_nlink == 0);

	if (ui->del_cmtno != c->cmt_no)
		/* A commit happened for sure */
		return ubifs_jnl_write_inode(c, inode);

	down_read(&c->commit_sem);
	/*
	 * Check commit number again, because the first test has been done
	 * without @c->commit_sem, so a commit might have happened.
	 */
	if (ui->del_cmtno != c->cmt_no) {
		up_read(&c->commit_sem);
		return ubifs_jnl_write_inode(c, inode);
	}

	err = ubifs_tnc_remove_ino(c, inode->i_ino);
	if (err)
		ubifs_ro_mode(c, err);
	else
		ubifs_delete_orphan(c, inode->i_ino);
	up_read(&c->commit_sem);
	return err;
}

/**
 * ubifs_jnl_rename - rename a directory entry.
 * @c: UBIFS file-system description object
 * @old_dir: parent inode of directory entry to rename
 * @old_dentry: directory entry to rename
 * @new_dir: parent inode of directory entry to rename
 * @new_dentry: new directory entry (or directory entry to replace)
 * @sync: non-zero if the write-buffer has to be synchronized
 *
 * This function implements the re-name operation which may involve writing up
 * to 3 inodes and 2 directory entries. It marks the written inodes as clean
 * and returns zero on success. In case of failure, a negative error code is
 * returned.
 */
int ubifs_jnl_rename(struct ubifs_info *c, const struct inode *old_dir,
		     const struct dentry *old_dentry,
		     const struct inode *new_dir,
		     const struct dentry *new_dentry, int sync)
{
	void *p;
	union ubifs_key key;
	struct ubifs_dent_node *dent, *dent2;
	int err, dlen1, dlen2, ilen, lnum, offs, len;
	const struct inode *old_inode = old_dentry->d_inode;
	const struct inode *new_inode = new_dentry->d_inode;
	int aligned_dlen1, aligned_dlen2, plen = UBIFS_INO_NODE_SZ;
	int last_reference = !!(new_inode && new_inode->i_nlink == 0);
	int move = (old_dir != new_dir);
	struct ubifs_inode *uninitialized_var(new_ui);

	dbg_jnl("dent '%pd' in dir ino %lu to dent '%pd' in dir ino %lu",
		old_dentry, old_dir->i_ino, new_dentry, new_dir->i_ino);
	ubifs_assert(ubifs_inode(old_dir)->data_len == 0);
	ubifs_assert(ubifs_inode(new_dir)->data_len == 0);
	ubifs_assert(mutex_is_locked(&ubifs_inode(old_dir)->ui_mutex));
	ubifs_assert(mutex_is_locked(&ubifs_inode(new_dir)->ui_mutex));

	dlen1 = UBIFS_DENT_NODE_SZ + new_dentry->d_name.len + 1;
	dlen2 = UBIFS_DENT_NODE_SZ + old_dentry->d_name.len + 1;
	if (new_inode) {
		new_ui = ubifs_inode(new_inode);
		ubifs_assert(mutex_is_locked(&new_ui->ui_mutex));
		ilen = UBIFS_INO_NODE_SZ;
		if (!last_reference)
			ilen += new_ui->data_len;
	} else
		ilen = 0;

	aligned_dlen1 = ALIGN(dlen1, 8);
	aligned_dlen2 = ALIGN(dlen2, 8);
	len = aligned_dlen1 + aligned_dlen2 + ALIGN(ilen, 8) + ALIGN(plen, 8);
	if (old_dir != new_dir)
		len += plen;
	dent = kmalloc(len, GFP_NOFS);
	if (!dent)
		return -ENOMEM;

	/* Make reservation before allocating sequence numbers */
	err = make_reservation(c, BASEHD, len);
	if (err)
		goto out_free;

	/* Make new dent */
	dent->ch.node_type = UBIFS_DENT_NODE;
	dent_key_init_flash(c, &dent->key, new_dir->i_ino, &new_dentry->d_name);
	dent->inum = cpu_to_le64(old_inode->i_ino);
	dent->type = get_dent_type_journal_c(old_inode->i_mode);
	dent->nlen = cpu_to_le16(new_dentry->d_name.len);
	memcpy(dent->name, new_dentry->d_name.name, new_dentry->d_name.len);
	dent->name[new_dentry->d_name.len] = '\0';
	zero_dent_node_unused(dent);
	ubifs_prep_grp_node(c, dent, dlen1, 0);

	/* Make deletion dent */
	dent2 = (void *)dent + aligned_dlen1;
	dent2->ch.node_type = UBIFS_DENT_NODE;
	dent_key_init_flash(c, &dent2->key, old_dir->i_ino,
			    &old_dentry->d_name);
	dent2->inum = 0;
	dent2->type = DT_UNKNOWN;
	dent2->nlen = cpu_to_le16(old_dentry->d_name.len);
	memcpy(dent2->name, old_dentry->d_name.name, old_dentry->d_name.len);
	dent2->name[old_dentry->d_name.len] = '\0';
	zero_dent_node_unused(dent2);
	ubifs_prep_grp_node(c, dent2, dlen2, 0);

	p = (void *)dent2 + aligned_dlen2;
	if (new_inode) {
		pack_inode(c, p, new_inode, 0);
		p += ALIGN(ilen, 8);
	}

	if (!move)
		pack_inode(c, p, old_dir, 1);
	else {
		pack_inode(c, p, old_dir, 0);
		p += ALIGN(plen, 8);
		pack_inode(c, p, new_dir, 1);
	}

	if (last_reference) {
		err = ubifs_add_orphan(c, new_inode->i_ino);
		if (err) {
			release_head(c, BASEHD);
			goto out_finish;
		}
		new_ui->del_cmtno = c->cmt_no;
	}

	err = write_head(c, BASEHD, dent, len, &lnum, &offs, sync);
	if (err)
		goto out_release;
	if (!sync) {
		struct ubifs_wbuf *wbuf = &c->jheads[BASEHD].wbuf;

		ubifs_wbuf_add_ino_nolock(wbuf, new_dir->i_ino);
		ubifs_wbuf_add_ino_nolock(wbuf, old_dir->i_ino);
		if (new_inode)
			ubifs_wbuf_add_ino_nolock(&c->jheads[BASEHD].wbuf,
						  new_inode->i_ino);
	}
	release_head(c, BASEHD);

	dent_key_init(c, &key, new_dir->i_ino, &new_dentry->d_name);
	err = ubifs_tnc_add_nm(c, &key, lnum, offs, dlen1, &new_dentry->d_name);
	if (err)
		goto out_ro;

	err = ubifs_add_dirt(c, lnum, dlen2);
	if (err)
		goto out_ro;

	dent_key_init(c, &key, old_dir->i_ino, &old_dentry->d_name);
	err = ubifs_tnc_remove_nm(c, &key, &old_dentry->d_name);
	if (err)
		goto out_ro;

	offs += aligned_dlen1 + aligned_dlen2;
	if (new_inode) {
		ino_key_init(c, &key, new_inode->i_ino);
		err = ubifs_tnc_add(c, &key, lnum, offs, ilen);
		if (err)
			goto out_ro;
		offs += ALIGN(ilen, 8);
	}

	ino_key_init(c, &key, old_dir->i_ino);
	err = ubifs_tnc_add(c, &key, lnum, offs, plen);
	if (err)
		goto out_ro;

	if (old_dir != new_dir) {
		offs += ALIGN(plen, 8);
		ino_key_init(c, &key, new_dir->i_ino);
		err = ubifs_tnc_add(c, &key, lnum, offs, plen);
		if (err)
			goto out_ro;
	}

	finish_reservation(c);
	if (new_inode) {
		mark_inode_clean(c, new_ui);
		spin_lock(&new_ui->ui_lock);
		new_ui->synced_i_size = new_ui->ui_size;
		spin_unlock(&new_ui->ui_lock);
	}
	mark_inode_clean(c, ubifs_inode(old_dir));
	if (move)
		mark_inode_clean(c, ubifs_inode(new_dir));
	kfree(dent);
	return 0;

out_release:
	release_head(c, BASEHD);
out_ro:
	ubifs_ro_mode(c, err);
	if (last_reference)
		ubifs_delete_orphan(c, new_inode->i_ino);
out_finish:
	finish_reservation(c);
out_free:
	kfree(dent);
	return err;
}

/**
 * recomp_data_node - re-compress a truncated data node.
 * @dn: data node to re-compress
 * @new_len: new length
 *
 * This function is used when an inode is truncated and the last data node of
 * the inode has to be re-compressed and re-written.
 */
static int recomp_data_node(struct ubifs_data_node *dn, int *new_len)
{
	void *buf;
	int err, len, compr_type, out_len;

	out_len = le32_to_cpu(dn->size);
	buf = kmalloc(out_len * WORST_COMPR_FACTOR, GFP_NOFS);
	if (!buf)
		return -ENOMEM;

	len = le32_to_cpu(dn->ch.len) - UBIFS_DATA_NODE_SZ;
	compr_type = le16_to_cpu(dn->compr_type);
	err = ubifs_decompress(&dn->data, len, buf, &out_len, compr_type);
	if (err)
		goto out;

	ubifs_compress(buf, *new_len, &dn->data, &out_len, &compr_type);
	ubifs_assert(out_len <= UBIFS_BLOCK_SIZE);
	dn->compr_type = cpu_to_le16(compr_type);
	dn->size = cpu_to_le32(*new_len);
	*new_len = UBIFS_DATA_NODE_SZ + out_len;
out:
	kfree(buf);
	return err;
}

/**
 * ubifs_jnl_truncate - update the journal for a truncation.
 * @c: UBIFS file-system description object
 * @inode: inode to truncate
 * @old_size: old size
 * @new_size: new size
 *
 * When the size of a file decreases due to truncation, a truncation node is
 * written, the journal tree is updated, and the last data block is re-written
 * if it has been affected. The inode is also updated in order to synchronize
 * the new inode size.
 *
 * This function marks the inode as clean and returns zero on success. In case
 * of failure, a negative error code is returned.
 */
int ubifs_jnl_truncate(struct ubifs_info *c, const struct inode *inode,
		       loff_t old_size, loff_t new_size)
{
	union ubifs_key key, to_key;
	struct ubifs_ino_node *ino;
	struct ubifs_trun_node *trun;
	struct ubifs_data_node *uninitialized_var(dn);
	int err, dlen, len, lnum, offs, bit, sz, sync = IS_SYNC(inode);
	struct ubifs_inode *ui = ubifs_inode(inode);
	ino_t inum = inode->i_ino;
	unsigned int blk;

	dbg_jnl("ino %lu, size %lld -> %lld",
		(unsigned long)inum, old_size, new_size);
	ubifs_assert(!ui->data_len);
	ubifs_assert(S_ISREG(inode->i_mode));
	ubifs_assert(mutex_is_locked(&ui->ui_mutex));

	sz = UBIFS_TRUN_NODE_SZ + UBIFS_INO_NODE_SZ +
	     UBIFS_MAX_DATA_NODE_SZ * WORST_COMPR_FACTOR;
	ino = kmalloc(sz, GFP_NOFS);
	if (!ino)
		return -ENOMEM;

	trun = (void *)ino + UBIFS_INO_NODE_SZ;
	trun->ch.node_type = UBIFS_TRUN_NODE;
	trun->inum = cpu_to_le32(inum);
	trun->old_size = cpu_to_le64(old_size);
	trun->new_size = cpu_to_le64(new_size);
	zero_trun_node_unused(trun);

	dlen = new_size & (UBIFS_BLOCK_SIZE - 1);
	if (dlen) {
		/* Get last data block so it can be truncated */
		dn = (void *)trun + UBIFS_TRUN_NODE_SZ;
		blk = new_size >> UBIFS_BLOCK_SHIFT;
		data_key_init(c, &key, inum, blk);
		dbg_jnlk(&key, "last block key ");
		err = ubifs_tnc_lookup(c, &key, dn);
		if (err == -ENOENT)
			dlen = 0; /* Not found (so it is a hole) */
		else if (err)
			goto out_free;
		else {
			if (le32_to_cpu(dn->size) <= dlen)
				dlen = 0; /* Nothing to do */
			else {
				int compr_type = le16_to_cpu(dn->compr_type);

				if (compr_type != UBIFS_COMPR_NONE) {
					err = recomp_data_node(dn, &dlen);
					if (err)
						goto out_free;
				} else {
					dn->size = cpu_to_le32(dlen);
					dlen += UBIFS_DATA_NODE_SZ;
				}
				zero_data_node_unused(dn);
			}
		}
	}

	/* Must make reservation before allocating sequence numbers */
	len = UBIFS_TRUN_NODE_SZ + UBIFS_INO_NODE_SZ;
	if (dlen)
		len += dlen;
	err = make_reservation(c, BASEHD, len);
	if (err)
		goto out_free;

	pack_inode(c, ino, inode, 0);
	ubifs_prep_grp_node(c, trun, UBIFS_TRUN_NODE_SZ, dlen ? 0 : 1);
	if (dlen)
		ubifs_prep_grp_node(c, dn, dlen, 1);

	err = write_head(c, BASEHD, ino, len, &lnum, &offs, sync);
	if (err)
		goto out_release;
	if (!sync)
		ubifs_wbuf_add_ino_nolock(&c->jheads[BASEHD].wbuf, inum);
	release_head(c, BASEHD);

	if (dlen) {
		sz = offs + UBIFS_INO_NODE_SZ + UBIFS_TRUN_NODE_SZ;
		err = ubifs_tnc_add(c, &key, lnum, sz, dlen);
		if (err)
			goto out_ro;
	}

	ino_key_init(c, &key, inum);
	err = ubifs_tnc_add(c, &key, lnum, offs, UBIFS_INO_NODE_SZ);
	if (err)
		goto out_ro;

	err = ubifs_add_dirt(c, lnum, UBIFS_TRUN_NODE_SZ);
	if (err)
		goto out_ro;

	bit = new_size & (UBIFS_BLOCK_SIZE - 1);
	blk = (new_size >> UBIFS_BLOCK_SHIFT) + (bit ? 1 : 0);
	data_key_init(c, &key, inum, blk);

	bit = old_size & (UBIFS_BLOCK_SIZE - 1);
	blk = (old_size >> UBIFS_BLOCK_SHIFT) - (bit ? 0 : 1);
	data_key_init(c, &to_key, inum, blk);

	err = ubifs_tnc_remove_range(c, &key, &to_key);
	if (err)
		goto out_ro;

	finish_reservation(c);
	spin_lock(&ui->ui_lock);
	ui->synced_i_size = ui->ui_size;
	spin_unlock(&ui->ui_lock);
	mark_inode_clean(c, ui);
	kfree(ino);
	return 0;

out_release:
	release_head(c, BASEHD);
out_ro:
	ubifs_ro_mode(c, err);
	finish_reservation(c);
out_free:
	kfree(ino);
	return err;
}


/**
 * ubifs_jnl_delete_xattr - delete an extended attribute.
 * @c: UBIFS file-system description object
 * @host: host inode
 * @inode: extended attribute inode
 * @nm: extended attribute entry name
 *
 * This function delete an extended attribute which is very similar to
 * un-linking regular files - it writes a deletion xentry, a deletion inode and
 * updates the target inode. Returns zero in case of success and a negative
 * error code in case of failure.
 */
int ubifs_jnl_delete_xattr(struct ubifs_info *c, const struct inode *host,
			   const struct inode *inode, const struct qstr *nm)
{
	int err, xlen, hlen, len, lnum, xent_offs, aligned_xlen;
	struct ubifs_dent_node *xent;
	struct ubifs_ino_node *ino;
	union ubifs_key xent_key, key1, key2;
	int sync = IS_DIRSYNC(host);
	struct ubifs_inode *host_ui = ubifs_inode(host);

	dbg_jnl("host %lu, xattr ino %lu, name '%s', data len %d",
		host->i_ino, inode->i_ino, nm->name,
		ubifs_inode(inode)->data_len);
	ubifs_assert(inode->i_nlink == 0);
	ubifs_assert(mutex_is_locked(&host_ui->ui_mutex));

	/*
	 * Since we are deleting the inode, we do not bother to attach any data
	 * to it and assume its length is %UBIFS_INO_NODE_SZ.
	 */
	xlen = UBIFS_DENT_NODE_SZ + nm->len + 1;
	aligned_xlen = ALIGN(xlen, 8);
	hlen = host_ui->data_len + UBIFS_INO_NODE_SZ;
	len = aligned_xlen + UBIFS_INO_NODE_SZ + ALIGN(hlen, 8);

	xent = kmalloc(len, GFP_NOFS);
	if (!xent)
		return -ENOMEM;

	/* Make reservation before allocating sequence numbers */
	err = make_reservation(c, BASEHD, len);
	if (err) {
		kfree(xent);
		return err;
	}

	xent->ch.node_type = UBIFS_XENT_NODE;
	xent_key_init(c, &xent_key, host->i_ino, nm);
	key_write(c, &xent_key, xent->key);
	xent->inum = 0;
	xent->type = get_dent_type_journal_c(inode->i_mode);
	xent->nlen = cpu_to_le16(nm->len);
	memcpy(xent->name, nm->name, nm->len);
	xent->name[nm->len] = '\0';
	zero_dent_node_unused(xent);
	ubifs_prep_grp_node(c, xent, xlen, 0);

	ino = (void *)xent + aligned_xlen;
	pack_inode(c, ino, inode, 0);
	ino = (void *)ino + UBIFS_INO_NODE_SZ;
	pack_inode(c, ino, host, 1);

	err = write_head(c, BASEHD, xent, len, &lnum, &xent_offs, sync);
	if (!sync && !err)
		ubifs_wbuf_add_ino_nolock(&c->jheads[BASEHD].wbuf, host->i_ino);
	release_head(c, BASEHD);
	kfree(xent);
	if (err)
		goto out_ro;

	/* Remove the extended attribute entry from TNC */
	err = ubifs_tnc_remove_nm(c, &xent_key, nm);
	if (err)
		goto out_ro;
	err = ubifs_add_dirt(c, lnum, xlen);
	if (err)
		goto out_ro;

	/*
	 * Remove all nodes belonging to the extended attribute inode from TNC.
	 * Well, there actually must be only one node - the inode itself.
	 */
	lowest_ino_key(c, &key1, inode->i_ino);
	highest_ino_key(c, &key2, inode->i_ino);
	err = ubifs_tnc_remove_range(c, &key1, &key2);
	if (err)
		goto out_ro;
	err = ubifs_add_dirt(c, lnum, UBIFS_INO_NODE_SZ);
	if (err)
		goto out_ro;

	/* And update TNC with the new host inode position */
	ino_key_init(c, &key1, host->i_ino);
	err = ubifs_tnc_add(c, &key1, lnum, xent_offs + len - hlen, hlen);
	if (err)
		goto out_ro;

	finish_reservation(c);
	spin_lock(&host_ui->ui_lock);
	host_ui->synced_i_size = host_ui->ui_size;
	spin_unlock(&host_ui->ui_lock);
	mark_inode_clean(c, host_ui);
	return 0;

out_ro:
	ubifs_ro_mode(c, err);
	finish_reservation(c);
	return err;
}

/**
 * ubifs_jnl_change_xattr - change an extended attribute.
 * @c: UBIFS file-system description object
 * @inode: extended attribute inode
 * @host: host inode
 *
 * This function writes the updated version of an extended attribute inode and
 * the host inode to the journal (to the base head). The host inode is written
 * after the extended attribute inode in order to guarantee that the extended
 * attribute will be flushed when the inode is synchronized by 'fsync()' and
 * consequently, the write-buffer is synchronized. This function returns zero
 * in case of success and a negative error code in case of failure.
 */
int ubifs_jnl_change_xattr(struct ubifs_info *c, const struct inode *inode,
			   const struct inode *host)
{
	int err, len1, len2, aligned_len, aligned_len1, lnum, offs;
	struct ubifs_inode *host_ui = ubifs_inode(host);
	struct ubifs_ino_node *ino;
	union ubifs_key key;
	int sync = IS_DIRSYNC(host);

	dbg_jnl("ino %lu, ino %lu", host->i_ino, inode->i_ino);
	ubifs_assert(host->i_nlink > 0);
	ubifs_assert(inode->i_nlink > 0);
	ubifs_assert(mutex_is_locked(&host_ui->ui_mutex));

	len1 = UBIFS_INO_NODE_SZ + host_ui->data_len;
	len2 = UBIFS_INO_NODE_SZ + ubifs_inode(inode)->data_len;
	aligned_len1 = ALIGN(len1, 8);
	aligned_len = aligned_len1 + ALIGN(len2, 8);

	ino = kmalloc(aligned_len, GFP_NOFS);
	if (!ino)
		return -ENOMEM;

	/* Make reservation before allocating sequence numbers */
	err = make_reservation(c, BASEHD, aligned_len);
	if (err)
		goto out_free;

	pack_inode(c, ino, host, 0);
	pack_inode(c, (void *)ino + aligned_len1, inode, 1);

	err = write_head(c, BASEHD, ino, aligned_len, &lnum, &offs, 0);
	if (!sync && !err) {
		struct ubifs_wbuf *wbuf = &c->jheads[BASEHD].wbuf;

		ubifs_wbuf_add_ino_nolock(wbuf, host->i_ino);
		ubifs_wbuf_add_ino_nolock(wbuf, inode->i_ino);
	}
	release_head(c, BASEHD);
	if (err)
		goto out_ro;

	ino_key_init(c, &key, host->i_ino);
	err = ubifs_tnc_add(c, &key, lnum, offs, len1);
	if (err)
		goto out_ro;

	ino_key_init(c, &key, inode->i_ino);
	err = ubifs_tnc_add(c, &key, lnum, offs + aligned_len1, len2);
	if (err)
		goto out_ro;

	finish_reservation(c);
	spin_lock(&host_ui->ui_lock);
	host_ui->synced_i_size = host_ui->ui_size;
	spin_unlock(&host_ui->ui_lock);
	mark_inode_clean(c, host_ui);
	kfree(ino);
	return 0;

out_ro:
	ubifs_ro_mode(c, err);
	finish_reservation(c);
out_free:
	kfree(ino);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/journal.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file implements VFS file and inode operations for regular files, device
 * nodes and symlinks as well as address space operations.
 *
 * UBIFS uses 2 page flags: @PG_private and @PG_checked. @PG_private is set if
 * the page is dirty and is used for optimization purposes - dirty pages are
 * not budgeted so the flag shows that 'ubifs_write_end()' should not release
 * the budget for this page. The @PG_checked flag is set if full budgeting is
 * required for the page e.g., when it corresponds to a file hole or it is
 * beyond the file size. The budgeting is done in 'ubifs_write_begin()', because
 * it is OK to fail in this function, and the budget is released in
 * 'ubifs_write_end()'. So the @PG_private and @PG_checked flags carry
 * information about how the page was budgeted, to make it possible to release
 * the budget properly.
 *
 * A thing to keep in mind: inode @i_mutex is locked in most VFS operations we
 * implement. However, this is not true for 'ubifs_writepage()', which may be
 * called with @i_mutex unlocked. For example, when flusher thread is doing
 * background write-back, it calls 'ubifs_writepage()' with unlocked @i_mutex.
 * At "normal" work-paths the @i_mutex is locked in 'ubifs_writepage()', e.g.
 * in the "sys_write -> alloc_pages -> direct reclaim path". So, in
 * 'ubifs_writepage()' we are only guaranteed that the page is locked.
 *
 * Similarly, @i_mutex is not always locked in 'ubifs_readpage()', e.g., the
 * read-ahead path does not lock it ("sys_read -> generic_file_aio_read ->
 * ondemand_readahead -> readpage"). In case of readahead, @I_SYNC flag is not
 * set as well. However, UBIFS disables readahead.
 */

// #include "ubifs.h"
#include <linux/aio.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include "../../inc/__fss.h"

static int read_block(struct inode *inode, void *addr, unsigned int block,
		      struct ubifs_data_node *dn)
{
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	int err, len, out_len;
	union ubifs_key key;
	unsigned int dlen;

	data_key_init(c, &key, inode->i_ino, block);
	err = ubifs_tnc_lookup(c, &key, dn);
	if (err) {
		if (err == -ENOENT)
			/* Not found, so it must be a hole */
			memset(addr, 0, UBIFS_BLOCK_SIZE);
		return err;
	}

	ubifs_assert(le64_to_cpu(dn->ch.sqnum) >
		     ubifs_inode(inode)->creat_sqnum);
	len = le32_to_cpu(dn->size);
	if (len <= 0 || len > UBIFS_BLOCK_SIZE)
		goto dump;

	dlen = le32_to_cpu(dn->ch.len) - UBIFS_DATA_NODE_SZ;
	out_len = UBIFS_BLOCK_SIZE;
	err = ubifs_decompress(&dn->data, dlen, addr, &out_len,
			       le16_to_cpu(dn->compr_type));
	if (err || len != out_len)
		goto dump;

	/*
	 * Data length can be less than a full block, even for blocks that are
	 * not the last in the file (e.g., as a result of making a hole and
	 * appending data). Ensure that the remainder is zeroed out.
	 */
	if (len < UBIFS_BLOCK_SIZE)
		memset(addr + len, 0, UBIFS_BLOCK_SIZE - len);

	return 0;

dump:
	ubifs_err("bad data node (block %u, inode %lu)",
		  block, inode->i_ino);
	ubifs_dump_node(c, dn);
	return -EINVAL;
}

static int do_readpage(struct page *page)
{
	void *addr;
	int err = 0, i;
	unsigned int block, beyond;
	struct ubifs_data_node *dn;
	struct inode *inode = page->mapping->host;
	loff_t i_size = i_size_read(inode);

	dbg_gen("ino %lu, pg %lu, i_size %lld, flags %#lx",
		inode->i_ino, page->index, i_size, page->flags);
	ubifs_assert(!PageChecked(page));
	ubifs_assert(!PagePrivate(page));

	addr = kmap(page);

	block = page->index << UBIFS_BLOCKS_PER_PAGE_SHIFT;
	beyond = (i_size + UBIFS_BLOCK_SIZE - 1) >> UBIFS_BLOCK_SHIFT;
	if (block >= beyond) {
		/* Reading beyond inode */
		SetPageChecked(page);
		memset(addr, 0, PAGE_CACHE_SIZE);
		goto out;
	}

	dn = kmalloc(UBIFS_MAX_DATA_NODE_SZ, GFP_NOFS);
	if (!dn) {
		err = -ENOMEM;
		goto error;
	}

	i = 0;
	while (1) {
		int ret;

		if (block >= beyond) {
			/* Reading beyond inode */
			err = -ENOENT;
			memset(addr, 0, UBIFS_BLOCK_SIZE);
		} else {
			ret = read_block(inode, addr, block, dn);
			if (ret) {
				err = ret;
				if (err != -ENOENT)
					break;
			} else if (block + 1 == beyond) {
				int dlen = le32_to_cpu(dn->size);
				int ilen = i_size & (UBIFS_BLOCK_SIZE - 1);

				if (ilen && ilen < dlen)
					memset(addr + ilen, 0, dlen - ilen);
			}
		}
		if (++i >= UBIFS_BLOCKS_PER_PAGE)
			break;
		block += 1;
		addr += UBIFS_BLOCK_SIZE;
	}
	if (err) {
		if (err == -ENOENT) {
			/* Not found, so it must be a hole */
			SetPageChecked(page);
			dbg_gen("hole");
			goto out_free;
		}
		ubifs_err("cannot read page %lu of inode %lu, error %d",
			  page->index, inode->i_ino, err);
		goto error;
	}

out_free:
	kfree(dn);
out:
	SetPageUptodate(page);
	ClearPageError(page);
	flush_dcache_page(page);
	kunmap(page);
	return 0;

error:
	kfree(dn);
	ClearPageUptodate(page);
	SetPageError(page);
	flush_dcache_page(page);
	kunmap(page);
	return err;
}

/**
 * release_new_page_budget - release budget of a new page.
 * @c: UBIFS file-system description object
 *
 * This is a helper function which releases budget corresponding to the budget
 * of one new page of data.
 */
static void release_new_page_budget(struct ubifs_info *c)
{
	struct ubifs_budget_req req = { .recalculate = 1, .new_page = 1 };

	ubifs_release_budget(c, &req);
}

/**
 * release_existing_page_budget - release budget of an existing page.
 * @c: UBIFS file-system description object
 *
 * This is a helper function which releases budget corresponding to the budget
 * of changing one one page of data which already exists on the flash media.
 */
static void release_existing_page_budget(struct ubifs_info *c)
{
	struct ubifs_budget_req req = { .dd_growth = c->bi.page_budget};

	ubifs_release_budget(c, &req);
}

static int write_begin_slow(struct address_space *mapping,
			    loff_t pos, unsigned len, struct page **pagep,
			    unsigned flags)
{
	struct inode *inode = mapping->host;
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct ubifs_budget_req req = { .new_page = 1 };
	int uninitialized_var(err), appending = !!(pos + len > inode->i_size);
	struct page *page;

	dbg_gen("ino %lu, pos %llu, len %u, i_size %lld",
		inode->i_ino, pos, len, inode->i_size);

	/*
	 * At the slow path we have to budget before locking the page, because
	 * budgeting may force write-back, which would wait on locked pages and
	 * deadlock if we had the page locked. At this point we do not know
	 * anything about the page, so assume that this is a new page which is
	 * written to a hole. This corresponds to largest budget. Later the
	 * budget will be amended if this is not true.
	 */
	if (appending)
		/* We are appending data, budget for inode change */
		req.dirtied_ino = 1;

	err = ubifs_budget_space(c, &req);
	if (unlikely(err))
		return err;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (unlikely(!page)) {
		ubifs_release_budget(c, &req);
		return -ENOMEM;
	}

	if (!PageUptodate(page)) {
		if (!(pos & ~PAGE_CACHE_MASK) && len == PAGE_CACHE_SIZE)
			SetPageChecked(page);
		else {
			err = do_readpage(page);
			if (err) {
				unlock_page(page);
				page_cache_release(page);
				ubifs_release_budget(c, &req);
				return err;
			}
		}

		SetPageUptodate(page);
		ClearPageError(page);
	}

	if (PagePrivate(page))
		/*
		 * The page is dirty, which means it was budgeted twice:
		 *   o first time the budget was allocated by the task which
		 *     made the page dirty and set the PG_private flag;
		 *   o and then we budgeted for it for the second time at the
		 *     very beginning of this function.
		 *
		 * So what we have to do is to release the page budget we
		 * allocated.
		 */
		release_new_page_budget(c);
	else if (!PageChecked(page))
		/*
		 * We are changing a page which already exists on the media.
		 * This means that changing the page does not make the amount
		 * of indexing information larger, and this part of the budget
		 * which we have already acquired may be released.
		 */
		ubifs_convert_page_budget(c);

	if (appending) {
		struct ubifs_inode *ui = ubifs_inode(inode);

		/*
		 * 'ubifs_write_end()' is optimized from the fast-path part of
		 * 'ubifs_write_begin()' and expects the @ui_mutex to be locked
		 * if data is appended.
		 */
		mutex_lock(&ui->ui_mutex);
		if (ui->dirty)
			/*
			 * The inode is dirty already, so we may free the
			 * budget we allocated.
			 */
			ubifs_release_dirty_inode_budget(c, ui);
	}

	*pagep = page;
	return 0;
}

/**
 * allocate_budget - allocate budget for 'ubifs_write_begin()'.
 * @c: UBIFS file-system description object
 * @page: page to allocate budget for
 * @ui: UBIFS inode object the page belongs to
 * @appending: non-zero if the page is appended
 *
 * This is a helper function for 'ubifs_write_begin()' which allocates budget
 * for the operation. The budget is allocated differently depending on whether
 * this is appending, whether the page is dirty or not, and so on. This
 * function leaves the @ui->ui_mutex locked in case of appending. Returns zero
 * in case of success and %-ENOSPC in case of failure.
 */
static int allocate_budget(struct ubifs_info *c, struct page *page,
			   struct ubifs_inode *ui, int appending)
{
	struct ubifs_budget_req req = { .fast = 1 };

	if (PagePrivate(page)) {
		if (!appending)
			/*
			 * The page is dirty and we are not appending, which
			 * means no budget is needed at all.
			 */
			return 0;

		mutex_lock(&ui->ui_mutex);
		if (ui->dirty)
			/*
			 * The page is dirty and we are appending, so the inode
			 * has to be marked as dirty. However, it is already
			 * dirty, so we do not need any budget. We may return,
			 * but @ui->ui_mutex hast to be left locked because we
			 * should prevent write-back from flushing the inode
			 * and freeing the budget. The lock will be released in
			 * 'ubifs_write_end()'.
			 */
			return 0;

		/*
		 * The page is dirty, we are appending, the inode is clean, so
		 * we need to budget the inode change.
		 */
		req.dirtied_ino = 1;
	} else {
		if (PageChecked(page))
			/*
			 * The page corresponds to a hole and does not
			 * exist on the media. So changing it makes
			 * make the amount of indexing information
			 * larger, and we have to budget for a new
			 * page.
			 */
			req.new_page = 1;
		else
			/*
			 * Not a hole, the change will not add any new
			 * indexing information, budget for page
			 * change.
			 */
			req.dirtied_page = 1;

		if (appending) {
			mutex_lock(&ui->ui_mutex);
			if (!ui->dirty)
				/*
				 * The inode is clean but we will have to mark
				 * it as dirty because we are appending. This
				 * needs a budget.
				 */
				req.dirtied_ino = 1;
		}
	}

	return ubifs_budget_space(c, &req);
}

/*
 * This function is called when a page of data is going to be written. Since
 * the page of data will not necessarily go to the flash straight away, UBIFS
 * has to reserve space on the media for it, which is done by means of
 * budgeting.
 *
 * This is the hot-path of the file-system and we are trying to optimize it as
 * much as possible. For this reasons it is split on 2 parts - slow and fast.
 *
 * There many budgeting cases:
 *     o a new page is appended - we have to budget for a new page and for
 *       changing the inode; however, if the inode is already dirty, there is
 *       no need to budget for it;
 *     o an existing clean page is changed - we have budget for it; if the page
 *       does not exist on the media (a hole), we have to budget for a new
 *       page; otherwise, we may budget for changing an existing page; the
 *       difference between these cases is that changing an existing page does
 *       not introduce anything new to the FS indexing information, so it does
 *       not grow, and smaller budget is acquired in this case;
 *     o an existing dirty page is changed - no need to budget at all, because
 *       the page budget has been acquired by earlier, when the page has been
 *       marked dirty.
 *
 * UBIFS budgeting sub-system may force write-back if it thinks there is no
 * space to reserve. This imposes some locking restrictions and makes it
 * impossible to take into account the above cases, and makes it impossible to
 * optimize budgeting.
 *
 * The solution for this is that the fast path of 'ubifs_write_begin()' assumes
 * there is a plenty of flash space and the budget will be acquired quickly,
 * without forcing write-back. The slow path does not make this assumption.
 */
static int ubifs_write_begin(struct file *file, struct address_space *mapping,
			     loff_t pos, unsigned len, unsigned flags,
			     struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	struct ubifs_inode *ui = ubifs_inode(inode);
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	int uninitialized_var(err), appending = !!(pos + len > inode->i_size);
	int skipped_read = 0;
	struct page *page;

	ubifs_assert(ubifs_inode(inode)->ui_size == inode->i_size);
	ubifs_assert(!c->ro_media && !c->ro_mount);

	if (unlikely(c->ro_error))
		return -EROFS;

	/* Try out the fast-path part first */
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (unlikely(!page))
		return -ENOMEM;

	if (!PageUptodate(page)) {
		/* The page is not loaded from the flash */
		if (!(pos & ~PAGE_CACHE_MASK) && len == PAGE_CACHE_SIZE) {
			/*
			 * We change whole page so no need to load it. But we
			 * do not know whether this page exists on the media or
			 * not, so we assume the latter because it requires
			 * larger budget. The assumption is that it is better
			 * to budget a bit more than to read the page from the
			 * media. Thus, we are setting the @PG_checked flag
			 * here.
			 */
			SetPageChecked(page);
			skipped_read = 1;
		} else {
			err = do_readpage(page);
			if (err) {
				unlock_page(page);
				page_cache_release(page);
				return err;
			}
		}

		SetPageUptodate(page);
		ClearPageError(page);
	}

	err = allocate_budget(c, page, ui, appending);
	if (unlikely(err)) {
		ubifs_assert(err == -ENOSPC);
		/*
		 * If we skipped reading the page because we were going to
		 * write all of it, then it is not up to date.
		 */
		if (skipped_read) {
			ClearPageChecked(page);
			ClearPageUptodate(page);
		}
		/*
		 * Budgeting failed which means it would have to force
		 * write-back but didn't, because we set the @fast flag in the
		 * request. Write-back cannot be done now, while we have the
		 * page locked, because it would deadlock. Unlock and free
		 * everything and fall-back to slow-path.
		 */
		if (appending) {
			ubifs_assert(mutex_is_locked(&ui->ui_mutex));
			mutex_unlock(&ui->ui_mutex);
		}
		unlock_page(page);
		page_cache_release(page);

		return write_begin_slow(mapping, pos, len, pagep, flags);
	}

	/*
	 * Whee, we acquired budgeting quickly - without involving
	 * garbage-collection, committing or forcing write-back. We return
	 * with @ui->ui_mutex locked if we are appending pages, and unlocked
	 * otherwise. This is an optimization (slightly hacky though).
	 */
	*pagep = page;
	return 0;

}

/**
 * cancel_budget - cancel budget.
 * @c: UBIFS file-system description object
 * @page: page to cancel budget for
 * @ui: UBIFS inode object the page belongs to
 * @appending: non-zero if the page is appended
 *
 * This is a helper function for a page write operation. It unlocks the
 * @ui->ui_mutex in case of appending.
 */
static void cancel_budget(struct ubifs_info *c, struct page *page,
			  struct ubifs_inode *ui, int appending)
{
	if (appending) {
		if (!ui->dirty)
			ubifs_release_dirty_inode_budget(c, ui);
		mutex_unlock(&ui->ui_mutex);
	}
	if (!PagePrivate(page)) {
		if (PageChecked(page))
			release_new_page_budget(c);
		else
			release_existing_page_budget(c);
	}
}

static int ubifs_write_end(struct file *file, struct address_space *mapping,
			   loff_t pos, unsigned len, unsigned copied,
			   struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct ubifs_inode *ui = ubifs_inode(inode);
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	loff_t end_pos = pos + len;
	int appending = !!(end_pos > inode->i_size);

	dbg_gen("ino %lu, pos %llu, pg %lu, len %u, copied %d, i_size %lld",
		inode->i_ino, pos, page->index, len, copied, inode->i_size);

	if (unlikely(copied < len && len == PAGE_CACHE_SIZE)) {
		/*
		 * VFS copied less data to the page that it intended and
		 * declared in its '->write_begin()' call via the @len
		 * argument. If the page was not up-to-date, and @len was
		 * @PAGE_CACHE_SIZE, the 'ubifs_write_begin()' function did
		 * not load it from the media (for optimization reasons). This
		 * means that part of the page contains garbage. So read the
		 * page now.
		 */
		dbg_gen("copied %d instead of %d, read page and repeat",
			copied, len);
		cancel_budget(c, page, ui, appending);
		ClearPageChecked(page);

		/*
		 * Return 0 to force VFS to repeat the whole operation, or the
		 * error code if 'do_readpage()' fails.
		 */
		copied = do_readpage(page);
		goto out;
	}

	if (!PagePrivate(page)) {
		SetPagePrivate(page);
		atomic_long_inc(&c->dirty_pg_cnt);
		__set_page_dirty_nobuffers(page);
	}

	if (appending) {
		i_size_write(inode, end_pos);
		ui->ui_size = end_pos;
		/*
		 * Note, we do not set @I_DIRTY_PAGES (which means that the
		 * inode has dirty pages), this has been done in
		 * '__set_page_dirty_nobuffers()'.
		 */
		__mark_inode_dirty(inode, I_DIRTY_DATASYNC);
		ubifs_assert(mutex_is_locked(&ui->ui_mutex));
		mutex_unlock(&ui->ui_mutex);
	}

out:
	unlock_page(page);
	page_cache_release(page);
	return copied;
}

/**
 * populate_page - copy data nodes into a page for bulk-read.
 * @c: UBIFS file-system description object
 * @page: page
 * @bu: bulk-read information
 * @n: next zbranch slot
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int populate_page(struct ubifs_info *c, struct page *page,
			 struct bu_info *bu, int *n)
{
	int i = 0, nn = *n, offs = bu->zbranch[0].offs, hole = 0, read = 0;
	struct inode *inode = page->mapping->host;
	loff_t i_size = i_size_read(inode);
	unsigned int page_block;
	void *addr, *zaddr;
	pgoff_t end_index;

	dbg_gen("ino %lu, pg %lu, i_size %lld, flags %#lx",
		inode->i_ino, page->index, i_size, page->flags);

	addr = zaddr = kmap(page);

	end_index = (i_size - 1) >> PAGE_CACHE_SHIFT;
	if (!i_size || page->index > end_index) {
		hole = 1;
		memset(addr, 0, PAGE_CACHE_SIZE);
		goto out_hole;
	}

	page_block = page->index << UBIFS_BLOCKS_PER_PAGE_SHIFT;
	while (1) {
		int err, len, out_len, dlen;

		if (nn >= bu->cnt) {
			hole = 1;
			memset(addr, 0, UBIFS_BLOCK_SIZE);
		} else if (key_block(c, &bu->zbranch[nn].key) == page_block) {
			struct ubifs_data_node *dn;

			dn = bu->buf + (bu->zbranch[nn].offs - offs);

			ubifs_assert(le64_to_cpu(dn->ch.sqnum) >
				     ubifs_inode(inode)->creat_sqnum);

			len = le32_to_cpu(dn->size);
			if (len <= 0 || len > UBIFS_BLOCK_SIZE)
				goto out_err;

			dlen = le32_to_cpu(dn->ch.len) - UBIFS_DATA_NODE_SZ;
			out_len = UBIFS_BLOCK_SIZE;
			err = ubifs_decompress(&dn->data, dlen, addr, &out_len,
					       le16_to_cpu(dn->compr_type));
			if (err || len != out_len)
				goto out_err;

			if (len < UBIFS_BLOCK_SIZE)
				memset(addr + len, 0, UBIFS_BLOCK_SIZE - len);

			nn += 1;
			read = (i << UBIFS_BLOCK_SHIFT) + len;
		} else if (key_block(c, &bu->zbranch[nn].key) < page_block) {
			nn += 1;
			continue;
		} else {
			hole = 1;
			memset(addr, 0, UBIFS_BLOCK_SIZE);
		}
		if (++i >= UBIFS_BLOCKS_PER_PAGE)
			break;
		addr += UBIFS_BLOCK_SIZE;
		page_block += 1;
	}

	if (end_index == page->index) {
		int len = i_size & (PAGE_CACHE_SIZE - 1);

		if (len && len < read)
			memset(zaddr + len, 0, read - len);
	}

out_hole:
	if (hole) {
		SetPageChecked(page);
		dbg_gen("hole");
	}

	SetPageUptodate(page);
	ClearPageError(page);
	flush_dcache_page(page);
	kunmap(page);
	*n = nn;
	return 0;

out_err:
	ClearPageUptodate(page);
	SetPageError(page);
	flush_dcache_page(page);
	kunmap(page);
	ubifs_err("bad data node (block %u, inode %lu)",
		  page_block, inode->i_ino);
	return -EINVAL;
}

/**
 * ubifs_do_bulk_read - do bulk-read.
 * @c: UBIFS file-system description object
 * @bu: bulk-read information
 * @page1: first page to read
 *
 * This function returns %1 if the bulk-read is done, otherwise %0 is returned.
 */
static int ubifs_do_bulk_read(struct ubifs_info *c, struct bu_info *bu,
			      struct page *page1)
{
	pgoff_t offset = page1->index, end_index;
	struct address_space *mapping = page1->mapping;
	struct inode *inode = mapping->host;
	struct ubifs_inode *ui = ubifs_inode(inode);
	int err, page_idx, page_cnt, ret = 0, n = 0;
	int allocate = bu->buf ? 0 : 1;
	loff_t isize;

	err = ubifs_tnc_get_bu_keys(c, bu);
	if (err)
		goto out_warn;

	if (bu->eof) {
		/* Turn off bulk-read at the end of the file */
		ui->read_in_a_row = 1;
		ui->bulk_read = 0;
	}

	page_cnt = bu->blk_cnt >> UBIFS_BLOCKS_PER_PAGE_SHIFT;
	if (!page_cnt) {
		/*
		 * This happens when there are multiple blocks per page and the
		 * blocks for the first page we are looking for, are not
		 * together. If all the pages were like this, bulk-read would
		 * reduce performance, so we turn it off for a while.
		 */
		goto out_bu_off;
	}

	if (bu->cnt) {
		if (allocate) {
			/*
			 * Allocate bulk-read buffer depending on how many data
			 * nodes we are going to read.
			 */
			bu->buf_len = bu->zbranch[bu->cnt - 1].offs +
				      bu->zbranch[bu->cnt - 1].len -
				      bu->zbranch[0].offs;
			ubifs_assert(bu->buf_len > 0);
			ubifs_assert(bu->buf_len <= c->leb_size);
			bu->buf = kmalloc(bu->buf_len, GFP_NOFS | __GFP_NOWARN);
			if (!bu->buf)
				goto out_bu_off;
		}

		err = ubifs_tnc_bulk_read(c, bu);
		if (err)
			goto out_warn;
	}

	err = populate_page(c, page1, bu, &n);
	if (err)
		goto out_warn;

	unlock_page(page1);
	ret = 1;

	isize = i_size_read(inode);
	if (isize == 0)
		goto out_free;
	end_index = ((isize - 1) >> PAGE_CACHE_SHIFT);

	for (page_idx = 1; page_idx < page_cnt; page_idx++) {
		pgoff_t page_offset = offset + page_idx;
		struct page *page;

		if (page_offset > end_index)
			break;
		page = find_or_create_page(mapping, page_offset,
					   GFP_NOFS | __GFP_COLD);
		if (!page)
			break;
		if (!PageUptodate(page))
			err = populate_page(c, page, bu, &n);
		unlock_page(page);
		page_cache_release(page);
		if (err)
			break;
	}

	ui->last_page_read = offset + page_idx - 1;

out_free:
	if (allocate)
		kfree(bu->buf);
	return ret;

out_warn:
	ubifs_warn("ignoring error %d and skipping bulk-read", err);
	goto out_free;

out_bu_off:
	ui->read_in_a_row = ui->bulk_read = 0;
	goto out_free;
}

/**
 * ubifs_bulk_read - determine whether to bulk-read and, if so, do it.
 * @page: page from which to start bulk-read.
 *
 * Some flash media are capable of reading sequentially at faster rates. UBIFS
 * bulk-read facility is designed to take advantage of that, by reading in one
 * go consecutive data nodes that are also located consecutively in the same
 * LEB. This function returns %1 if a bulk-read is done and %0 otherwise.
 */
static int ubifs_bulk_read(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	struct ubifs_inode *ui = ubifs_inode(inode);
	pgoff_t index = page->index, last_page_read = ui->last_page_read;
	struct bu_info *bu;
	int err = 0, allocated = 0;

	ui->last_page_read = index;
	if (!c->bulk_read)
		return 0;

	/*
	 * Bulk-read is protected by @ui->ui_mutex, but it is an optimization,
	 * so don't bother if we cannot lock the mutex.
	 */
	if (!mutex_trylock(&ui->ui_mutex))
		return 0;

	if (index != last_page_read + 1) {
		/* Turn off bulk-read if we stop reading sequentially */
		ui->read_in_a_row = 1;
		if (ui->bulk_read)
			ui->bulk_read = 0;
		goto out_unlock;
	}

	if (!ui->bulk_read) {
		ui->read_in_a_row += 1;
		if (ui->read_in_a_row < 3)
			goto out_unlock;
		/* Three reads in a row, so switch on bulk-read */
		ui->bulk_read = 1;
	}

	/*
	 * If possible, try to use pre-allocated bulk-read information, which
	 * is protected by @c->bu_mutex.
	 */
	if (mutex_trylock(&c->bu_mutex))
		bu = &c->bu;
	else {
		bu = kmalloc(sizeof(struct bu_info), GFP_NOFS | __GFP_NOWARN);
		if (!bu)
			goto out_unlock;

		bu->buf = NULL;
		allocated = 1;
	}

	bu->buf_len = c->max_bu_buf_len;
	data_key_init(c, &bu->key, inode->i_ino,
		      page->index << UBIFS_BLOCKS_PER_PAGE_SHIFT);
	err = ubifs_do_bulk_read(c, bu, page);

	if (!allocated)
		mutex_unlock(&c->bu_mutex);
	else
		kfree(bu);

out_unlock:
	mutex_unlock(&ui->ui_mutex);
	return err;
}

static int ubifs_readpage(struct file *file, struct page *page)
{
	if (ubifs_bulk_read(page))
		return 0;
	do_readpage(page);
	unlock_page(page);
	return 0;
}

static int do_writepage(struct page *page, int len)
{
	int err = 0, i, blen;
	unsigned int block;
	void *addr;
	union ubifs_key key;
	struct inode *inode = page->mapping->host;
	struct ubifs_info *c = inode->i_sb->s_fs_info;

#ifdef UBIFS_DEBUG
	struct ubifs_inode *ui = ubifs_inode(inode);
	spin_lock(&ui->ui_lock);
	ubifs_assert(page->index <= ui->synced_i_size >> PAGE_CACHE_SHIFT);
	spin_unlock(&ui->ui_lock);
#endif

	/* Update radix tree tags */
	set_page_writeback(page);

	addr = kmap(page);
	block = page->index << UBIFS_BLOCKS_PER_PAGE_SHIFT;
	i = 0;
	while (len) {
		blen = min_t(int, len, UBIFS_BLOCK_SIZE);
		data_key_init(c, &key, inode->i_ino, block);
		err = ubifs_jnl_write_data(c, inode, &key, addr, blen);
		if (err)
			break;
		if (++i >= UBIFS_BLOCKS_PER_PAGE)
			break;
		block += 1;
		addr += blen;
		len -= blen;
	}
	if (err) {
		SetPageError(page);
		ubifs_err("cannot write page %lu of inode %lu, error %d",
			  page->index, inode->i_ino, err);
		ubifs_ro_mode(c, err);
	}

	ubifs_assert(PagePrivate(page));
	if (PageChecked(page))
		release_new_page_budget(c);
	else
		release_existing_page_budget(c);

	atomic_long_dec(&c->dirty_pg_cnt);
	ClearPagePrivate(page);
	ClearPageChecked(page);

	kunmap(page);
	unlock_page(page);
	end_page_writeback(page);
	return err;
}

/*
 * When writing-back dirty inodes, VFS first writes-back pages belonging to the
 * inode, then the inode itself. For UBIFS this may cause a problem. Consider a
 * situation when a we have an inode with size 0, then a megabyte of data is
 * appended to the inode, then write-back starts and flushes some amount of the
 * dirty pages, the journal becomes full, commit happens and finishes, and then
 * an unclean reboot happens. When the file system is mounted next time, the
 * inode size would still be 0, but there would be many pages which are beyond
 * the inode size, they would be indexed and consume flash space. Because the
 * journal has been committed, the replay would not be able to detect this
 * situation and correct the inode size. This means UBIFS would have to scan
 * whole index and correct all inode sizes, which is long an unacceptable.
 *
 * To prevent situations like this, UBIFS writes pages back only if they are
 * within the last synchronized inode size, i.e. the size which has been
 * written to the flash media last time. Otherwise, UBIFS forces inode
 * write-back, thus making sure the on-flash inode contains current inode size,
 * and then keeps writing pages back.
 *
 * Some locking issues explanation. 'ubifs_writepage()' first is called with
 * the page locked, and it locks @ui_mutex. However, write-back does take inode
 * @i_mutex, which means other VFS operations may be run on this inode at the
 * same time. And the problematic one is truncation to smaller size, from where
 * we have to call 'truncate_setsize()', which first changes @inode->i_size,
 * then drops the truncated pages. And while dropping the pages, it takes the
 * page lock. This means that 'do_truncation()' cannot call 'truncate_setsize()'
 * with @ui_mutex locked, because it would deadlock with 'ubifs_writepage()'.
 * This means that @inode->i_size is changed while @ui_mutex is unlocked.
 *
 * XXX(truncate): with the new truncate sequence this is not true anymore,
 * and the calls to truncate_setsize can be move around freely.  They should
 * be moved to the very end of the truncate sequence.
 *
 * But in 'ubifs_writepage()' we have to guarantee that we do not write beyond
 * inode size. How do we do this if @inode->i_size may became smaller while we
 * are in the middle of 'ubifs_writepage()'? The UBIFS solution is the
 * @ui->ui_isize "shadow" field which UBIFS uses instead of @inode->i_size
 * internally and updates it under @ui_mutex.
 *
 * Q: why we do not worry that if we race with truncation, we may end up with a
 * situation when the inode is truncated while we are in the middle of
 * 'do_writepage()', so we do write beyond inode size?
 * A: If we are in the middle of 'do_writepage()', truncation would be locked
 * on the page lock and it would not write the truncated inode node to the
 * journal before we have finished.
 */
static int ubifs_writepage(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode = page->mapping->host;
	struct ubifs_inode *ui = ubifs_inode(inode);
	loff_t i_size =  i_size_read(inode), synced_i_size;
	pgoff_t end_index = i_size >> PAGE_CACHE_SHIFT;
	int err, len = i_size & (PAGE_CACHE_SIZE - 1);
	void *kaddr;

	dbg_gen("ino %lu, pg %lu, pg flags %#lx",
		inode->i_ino, page->index, page->flags);
	ubifs_assert(PagePrivate(page));

	/* Is the page fully outside @i_size? (truncate in progress) */
	if (page->index > end_index || (page->index == end_index && !len)) {
		err = 0;
		goto out_unlock;
	}

	spin_lock(&ui->ui_lock);
	synced_i_size = ui->synced_i_size;
	spin_unlock(&ui->ui_lock);

	/* Is the page fully inside @i_size? */
	if (page->index < end_index) {
		if (page->index >= synced_i_size >> PAGE_CACHE_SHIFT) {
			err = inode->i_sb->s_op->write_inode(inode, NULL);
			if (err)
				goto out_unlock;
			/*
			 * The inode has been written, but the write-buffer has
			 * not been synchronized, so in case of an unclean
			 * reboot we may end up with some pages beyond inode
			 * size, but they would be in the journal (because
			 * commit flushes write buffers) and recovery would deal
			 * with this.
			 */
		}
		return do_writepage(page, PAGE_CACHE_SIZE);
	}

	/*
	 * The page straddles @i_size. It must be zeroed out on each and every
	 * writepage invocation because it may be mmapped. "A file is mapped
	 * in multiples of the page size. For a file that is not a multiple of
	 * the page size, the remaining memory is zeroed when mapped, and
	 * writes to that region are not written out to the file."
	 */
	kaddr = kmap_atomic(page);
	memset(kaddr + len, 0, PAGE_CACHE_SIZE - len);
	flush_dcache_page(page);
	kunmap_atomic(kaddr);

	if (i_size > synced_i_size) {
		err = inode->i_sb->s_op->write_inode(inode, NULL);
		if (err)
			goto out_unlock;
	}

	return do_writepage(page, len);

out_unlock:
	unlock_page(page);
	return err;
}

/**
 * do_attr_changes - change inode attributes.
 * @inode: inode to change attributes for
 * @attr: describes attributes to change
 */
static void do_attr_changes(struct inode *inode, const struct iattr *attr)
{
	if (attr->ia_valid & ATTR_UID)
		inode->i_uid = attr->ia_uid;
	if (attr->ia_valid & ATTR_GID)
		inode->i_gid = attr->ia_gid;
	if (attr->ia_valid & ATTR_ATIME)
		inode->i_atime = timespec_trunc(attr->ia_atime,
						inode->i_sb->s_time_gran);
	if (attr->ia_valid & ATTR_MTIME)
		inode->i_mtime = timespec_trunc(attr->ia_mtime,
						inode->i_sb->s_time_gran);
	if (attr->ia_valid & ATTR_CTIME)
		inode->i_ctime = timespec_trunc(attr->ia_ctime,
						inode->i_sb->s_time_gran);
	if (attr->ia_valid & ATTR_MODE) {
		umode_t mode = attr->ia_mode;

		if (!in_group_p(inode->i_gid) && !capable(CAP_FSETID))
			mode &= ~S_ISGID;
		inode->i_mode = mode;
	}
}

/**
 * do_truncation - truncate an inode.
 * @c: UBIFS file-system description object
 * @inode: inode to truncate
 * @attr: inode attribute changes description
 *
 * This function implements VFS '->setattr()' call when the inode is truncated
 * to a smaller size. Returns zero in case of success and a negative error code
 * in case of failure.
 */
static int do_truncation(struct ubifs_info *c, struct inode *inode,
			 const struct iattr *attr)
{
	int err;
	struct ubifs_budget_req req;
	loff_t old_size = inode->i_size, new_size = attr->ia_size;
	int offset = new_size & (UBIFS_BLOCK_SIZE - 1), budgeted = 1;
	struct ubifs_inode *ui = ubifs_inode(inode);

	dbg_gen("ino %lu, size %lld -> %lld", inode->i_ino, old_size, new_size);
	memset(&req, 0, sizeof(struct ubifs_budget_req));

	/*
	 * If this is truncation to a smaller size, and we do not truncate on a
	 * block boundary, budget for changing one data block, because the last
	 * block will be re-written.
	 */
	if (new_size & (UBIFS_BLOCK_SIZE - 1))
		req.dirtied_page = 1;

	req.dirtied_ino = 1;
	/* A funny way to budget for truncation node */
	req.dirtied_ino_d = UBIFS_TRUN_NODE_SZ;
	err = ubifs_budget_space(c, &req);
	if (err) {
		/*
		 * Treat truncations to zero as deletion and always allow them,
		 * just like we do for '->unlink()'.
		 */
		if (new_size || err != -ENOSPC)
			return err;
		budgeted = 0;
	}

	truncate_setsize(inode, new_size);

	if (offset) {
		pgoff_t index = new_size >> PAGE_CACHE_SHIFT;
		struct page *page;

		page = find_lock_page(inode->i_mapping, index);
		if (page) {
			if (PageDirty(page)) {
				/*
				 * 'ubifs_jnl_truncate()' will try to truncate
				 * the last data node, but it contains
				 * out-of-date data because the page is dirty.
				 * Write the page now, so that
				 * 'ubifs_jnl_truncate()' will see an already
				 * truncated (and up to date) data node.
				 */
				ubifs_assert(PagePrivate(page));

				clear_page_dirty_for_io(page);
				if (UBIFS_BLOCKS_PER_PAGE_SHIFT)
					offset = new_size &
						 (PAGE_CACHE_SIZE - 1);
				err = do_writepage(page, offset);
				page_cache_release(page);
				if (err)
					goto out_budg;
				/*
				 * We could now tell 'ubifs_jnl_truncate()' not
				 * to read the last block.
				 */
			} else {
				/*
				 * We could 'kmap()' the page and pass the data
				 * to 'ubifs_jnl_truncate()' to save it from
				 * having to read it.
				 */
				unlock_page(page);
				page_cache_release(page);
			}
		}
	}

	mutex_lock(&ui->ui_mutex);
	ui->ui_size = inode->i_size;
	/* Truncation changes inode [mc]time */
	inode->i_mtime = inode->i_ctime = ubifs_current_time(inode);
	/* Other attributes may be changed at the same time as well */
	do_attr_changes(inode, attr);
	err = ubifs_jnl_truncate(c, inode, old_size, new_size);
	mutex_unlock(&ui->ui_mutex);

out_budg:
	if (budgeted)
		ubifs_release_budget(c, &req);
	else {
		c->bi.nospace = c->bi.nospace_rp = 0;
		smp_wmb();
	}
	return err;
}

/**
 * do_setattr - change inode attributes.
 * @c: UBIFS file-system description object
 * @inode: inode to change attributes for
 * @attr: inode attribute changes description
 *
 * This function implements VFS '->setattr()' call for all cases except
 * truncations to smaller size. Returns zero in case of success and a negative
 * error code in case of failure.
 */
static int do_setattr(struct ubifs_info *c, struct inode *inode,
		      const struct iattr *attr)
{
	int err, release;
	loff_t new_size = attr->ia_size;
	struct ubifs_inode *ui = ubifs_inode(inode);
	struct ubifs_budget_req req = { .dirtied_ino = 1,
				.dirtied_ino_d = ALIGN(ui->data_len, 8) };

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	if (attr->ia_valid & ATTR_SIZE) {
		dbg_gen("size %lld -> %lld", inode->i_size, new_size);
		truncate_setsize(inode, new_size);
	}

	mutex_lock(&ui->ui_mutex);
	if (attr->ia_valid & ATTR_SIZE) {
		/* Truncation changes inode [mc]time */
		inode->i_mtime = inode->i_ctime = ubifs_current_time(inode);
		/* 'truncate_setsize()' changed @i_size, update @ui_size */
		ui->ui_size = inode->i_size;
	}

	do_attr_changes(inode, attr);

	release = ui->dirty;
	if (attr->ia_valid & ATTR_SIZE)
		/*
		 * Inode length changed, so we have to make sure
		 * @I_DIRTY_DATASYNC is set.
		 */
		 __mark_inode_dirty(inode, I_DIRTY_SYNC | I_DIRTY_DATASYNC);
	else
		mark_inode_dirty_sync(inode);
	mutex_unlock(&ui->ui_mutex);

	if (release)
		ubifs_release_budget(c, &req);
	if (IS_SYNC(inode))
		err = inode->i_sb->s_op->write_inode(inode, NULL);
	return err;
}

int ubifs_setattr(struct dentry *dentry, struct iattr *attr)
{
	int err;
	struct inode *inode = dentry->d_inode;
	struct ubifs_info *c = inode->i_sb->s_fs_info;

	dbg_gen("ino %lu, mode %#x, ia_valid %#x",
		inode->i_ino, inode->i_mode, attr->ia_valid);
	err = inode_change_ok(inode, attr);
	if (err)
		return err;

	err = dbg_check_synced_i_size(c, inode);
	if (err)
		return err;

	if ((attr->ia_valid & ATTR_SIZE) && attr->ia_size < inode->i_size)
		/* Truncation to a smaller size */
		err = do_truncation(c, inode, attr);
	else
		err = do_setattr(c, inode, attr);

	return err;
}

static void ubifs_invalidatepage(struct page *page, unsigned int offset,
				 unsigned int length)
{
	struct inode *inode = page->mapping->host;
	struct ubifs_info *c = inode->i_sb->s_fs_info;

	ubifs_assert(PagePrivate(page));
	if (offset || length < PAGE_CACHE_SIZE)
		/* Partial page remains dirty */
		return;

	if (PageChecked(page))
		release_new_page_budget(c);
	else
		release_existing_page_budget(c);

	atomic_long_dec(&c->dirty_pg_cnt);
	ClearPagePrivate(page);
	ClearPageChecked(page);
}

static void *ubifs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ubifs_inode *ui = ubifs_inode(dentry->d_inode);

	nd_set_link(nd, ui->data);
	return NULL;
}

int ubifs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	int err;

	dbg_gen("syncing inode %lu", inode->i_ino);

	if (c->ro_mount)
		/*
		 * For some really strange reasons VFS does not filter out
		 * 'fsync()' for R/O mounted file-systems as per 2.6.39.
		 */
		return 0;

	err = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (err)
		return err;
	mutex_lock(&inode->i_mutex);

	/* Synchronize the inode unless this is a 'datasync()' call. */
	if (!datasync || (inode->i_state & I_DIRTY_DATASYNC)) {
		err = inode->i_sb->s_op->write_inode(inode, NULL);
		if (err)
			goto out;
	}

	/*
	 * Nodes related to this inode may still sit in a write-buffer. Flush
	 * them.
	 */
	err = ubifs_sync_wbufs_by_inode(c, inode);
out:
	mutex_unlock(&inode->i_mutex);
	return err;
}

/**
 * mctime_update_needed - check if mtime or ctime update is needed.
 * @inode: the inode to do the check for
 * @now: current time
 *
 * This helper function checks if the inode mtime/ctime should be updated or
 * not. If current values of the time-stamps are within the UBIFS inode time
 * granularity, they are not updated. This is an optimization.
 */
static inline int mctime_update_needed(const struct inode *inode,
				       const struct timespec *now)
{
	if (!timespec_equal(&inode->i_mtime, now) ||
	    !timespec_equal(&inode->i_ctime, now))
		return 1;
	return 0;
}

/**
 * update_ctime - update mtime and ctime of an inode.
 * @inode: inode to update
 *
 * This function updates mtime and ctime of the inode if it is not equivalent to
 * current time. Returns zero in case of success and a negative error code in
 * case of failure.
 */
static int update_mctime(struct inode *inode)
{
	struct timespec now = ubifs_current_time(inode);
	struct ubifs_inode *ui = ubifs_inode(inode);
	struct ubifs_info *c = inode->i_sb->s_fs_info;

	if (mctime_update_needed(inode, &now)) {
		int err, release;
		struct ubifs_budget_req req = { .dirtied_ino = 1,
				.dirtied_ino_d = ALIGN(ui->data_len, 8) };

		err = ubifs_budget_space(c, &req);
		if (err)
			return err;

		mutex_lock(&ui->ui_mutex);
		inode->i_mtime = inode->i_ctime = ubifs_current_time(inode);
		release = ui->dirty;
		mark_inode_dirty_sync(inode);
		mutex_unlock(&ui->ui_mutex);
		if (release)
			ubifs_release_budget(c, &req);
	}

	return 0;
}

static ssize_t ubifs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	int err = update_mctime(file_inode(iocb->ki_filp));
	if (err)
		return err;

	return generic_file_write_iter(iocb, from);
}

static int ubifs_set_page_dirty(struct page *page)
{
	int ret;

	ret = __set_page_dirty_nobuffers(page);
	/*
	 * An attempt to dirty a page without budgeting for it - should not
	 * happen.
	 */
	ubifs_assert(ret == 0);
	return ret;
}

static int ubifs_releasepage(struct page *page, gfp_t unused_gfp_flags)
{
	/*
	 * An attempt to release a dirty page without budgeting for it - should
	 * not happen.
	 */
	if (PageWriteback(page))
		return 0;
	ubifs_assert(PagePrivate(page));
	ubifs_assert(0);
	ClearPagePrivate(page);
	ClearPageChecked(page);
	return 1;
}

/*
 * mmap()d file has taken write protection fault and is being made writable.
 * UBIFS must ensure page is budgeted for.
 */
static int ubifs_vm_page_mkwrite(struct vm_area_struct *vma,
				 struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vma->vm_file);
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	struct timespec now = ubifs_current_time(inode);
	struct ubifs_budget_req req = { .new_page = 1 };
	int err, update_time;

	dbg_gen("ino %lu, pg %lu, i_size %lld",	inode->i_ino, page->index,
		i_size_read(inode));
	ubifs_assert(!c->ro_media && !c->ro_mount);

	if (unlikely(c->ro_error))
		return VM_FAULT_SIGBUS; /* -EROFS */

	/*
	 * We have not locked @page so far so we may budget for changing the
	 * page. Note, we cannot do this after we locked the page, because
	 * budgeting may cause write-back which would cause deadlock.
	 *
	 * At the moment we do not know whether the page is dirty or not, so we
	 * assume that it is not and budget for a new page. We could look at
	 * the @PG_private flag and figure this out, but we may race with write
	 * back and the page state may change by the time we lock it, so this
	 * would need additional care. We do not bother with this at the
	 * moment, although it might be good idea to do. Instead, we allocate
	 * budget for a new page and amend it later on if the page was in fact
	 * dirty.
	 *
	 * The budgeting-related logic of this function is similar to what we
	 * do in 'ubifs_write_begin()' and 'ubifs_write_end()'. Glance there
	 * for more comments.
	 */
	update_time = mctime_update_needed(inode, &now);
	if (update_time)
		/*
		 * We have to change inode time stamp which requires extra
		 * budgeting.
		 */
		req.dirtied_ino = 1;

	err = ubifs_budget_space(c, &req);
	if (unlikely(err)) {
		if (err == -ENOSPC)
			ubifs_warn("out of space for mmapped file (inode number %lu)",
				   inode->i_ino);
		return VM_FAULT_SIGBUS;
	}

	lock_page(page);
	if (unlikely(page->mapping != inode->i_mapping ||
		     page_offset(page) > i_size_read(inode))) {
		/* Page got truncated out from underneath us */
		err = -EINVAL;
		goto out_unlock;
	}

	if (PagePrivate(page))
		release_new_page_budget(c);
	else {
		if (!PageChecked(page))
			ubifs_convert_page_budget(c);
		SetPagePrivate(page);
		atomic_long_inc(&c->dirty_pg_cnt);
		__set_page_dirty_nobuffers(page);
	}

	if (update_time) {
		int release;
		struct ubifs_inode *ui = ubifs_inode(inode);

		mutex_lock(&ui->ui_mutex);
		inode->i_mtime = inode->i_ctime = ubifs_current_time(inode);
		release = ui->dirty;
		mark_inode_dirty_sync(inode);
		mutex_unlock(&ui->ui_mutex);
		if (release)
			ubifs_release_dirty_inode_budget(c, ui);
	}

	wait_for_stable_page(page);
	return VM_FAULT_LOCKED;

out_unlock:
	unlock_page(page);
	ubifs_release_budget(c, &req);
	if (err)
		err = VM_FAULT_SIGBUS;
	return err;
}

static const struct vm_operations_struct ubifs_file_vm_ops = {
	.fault        = filemap_fault,
	.map_pages = filemap_map_pages,
	.page_mkwrite = ubifs_vm_page_mkwrite,
};

static int ubifs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err;

	err = generic_file_mmap(file, vma);
	if (err)
		return err;
	vma->vm_ops = &ubifs_file_vm_ops;
	return 0;
}

const struct address_space_operations ubifs_file_address_operations = {
	.readpage       = ubifs_readpage,
	.writepage      = ubifs_writepage,
	.write_begin    = ubifs_write_begin,
	.write_end      = ubifs_write_end,
	.invalidatepage = ubifs_invalidatepage,
	.set_page_dirty = ubifs_set_page_dirty,
	.releasepage    = ubifs_releasepage,
};

const struct inode_operations ubifs_file_inode_operations = {
	.setattr     = ubifs_setattr,
	.getattr     = ubifs_getattr,
	.setxattr    = ubifs_setxattr,
	.getxattr    = ubifs_getxattr,
	.listxattr   = ubifs_listxattr,
	.removexattr = ubifs_removexattr,
};

const struct inode_operations ubifs_symlink_inode_operations = {
	.readlink    = generic_readlink,
	.follow_link = ubifs_follow_link,
	.setattr     = ubifs_setattr,
	.getattr     = ubifs_getattr,
	.setxattr    = ubifs_setxattr,
	.getxattr    = ubifs_getxattr,
	.listxattr   = ubifs_listxattr,
	.removexattr = ubifs_removexattr,
};

const struct file_operations ubifs_file_operations = {
	.llseek         = generic_file_llseek,
	.read           = new_sync_read,
	.write          = new_sync_write,
	.read_iter      = generic_file_read_iter,
	.write_iter     = ubifs_write_iter,
	.mmap           = ubifs_file_mmap,
	.fsync          = ubifs_fsync,
	.unlocked_ioctl = ubifs_ioctl,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = ubifs_compat_ioctl,
#endif
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/file.c */
/************************************************************/
/* * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 * Copyright (C) 2006, 2007 University of Szeged, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 *          Zoltan Sogor
 */

/*
 * This file implements directory operations.
 *
 * All FS operations in this file allocate budget before writing anything to the
 * media. If they fail to allocate it, the error is returned. The only
 * exceptions are 'ubifs_unlink()' and 'ubifs_rmdir()' which keep working even
 * if they unable to allocate the budget, because deletion %-ENOSPC failure is
 * not what users are usually ready to get. UBIFS budgeting subsystem has some
 * space reserved for these purposes.
 *
 * All operations in this file write all inodes which they change straight
 * away, instead of marking them dirty. For example, 'ubifs_link()' changes
 * @i_size of the parent inode and writes the parent inode together with the
 * target inode. This was done to simplify file-system recovery which would
 * otherwise be very difficult to do. The only exception is rename which marks
 * the re-named inode dirty (because its @i_ctime is updated) but does not
 * write it, but just marks it as dirty.
 */

// #include "ubifs.h"

/**
 * inherit_flags - inherit flags of the parent inode.
 * @dir: parent inode
 * @mode: new inode mode flags
 *
 * This is a helper function for 'ubifs_new_inode()' which inherits flag of the
 * parent directory inode @dir. UBIFS inodes inherit the following flags:
 * o %UBIFS_COMPR_FL, which is useful to switch compression on/of on
 *   sub-directory basis;
 * o %UBIFS_SYNC_FL - useful for the same reasons;
 * o %UBIFS_DIRSYNC_FL - similar, but relevant only to directories.
 *
 * This function returns the inherited flags.
 */
static int inherit_flags(const struct inode *dir, umode_t mode)
{
	int flags;
	const struct ubifs_inode *ui = ubifs_inode(dir);

	if (!S_ISDIR(dir->i_mode))
		/*
		 * The parent is not a directory, which means that an extended
		 * attribute inode is being created. No flags.
		 */
		return 0;

	flags = ui->flags & (UBIFS_COMPR_FL | UBIFS_SYNC_FL | UBIFS_DIRSYNC_FL);
	if (!S_ISDIR(mode))
		/* The "DIRSYNC" flag only applies to directories */
		flags &= ~UBIFS_DIRSYNC_FL;
	return flags;
}

/**
 * ubifs_new_inode - allocate new UBIFS inode object.
 * @c: UBIFS file-system description object
 * @dir: parent directory inode
 * @mode: inode mode flags
 *
 * This function finds an unused inode number, allocates new inode and
 * initializes it. Returns new inode in case of success and an error code in
 * case of failure.
 */
struct inode *ubifs_new_inode(struct ubifs_info *c, const struct inode *dir,
			      umode_t mode)
{
	struct inode *inode;
	struct ubifs_inode *ui;

	inode = new_inode(c->vfs_sb);
	ui = ubifs_inode(inode);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	/*
	 * Set 'S_NOCMTIME' to prevent VFS form updating [mc]time of inodes and
	 * marking them dirty in file write path (see 'file_update_time()').
	 * UBIFS has to fully control "clean <-> dirty" transitions of inodes
	 * to make budgeting work.
	 */
	inode->i_flags |= S_NOCMTIME;

	inode_init_owner(inode, dir, mode);
	inode->i_mtime = inode->i_atime = inode->i_ctime =
			 ubifs_current_time(inode);
	inode->i_mapping->nrpages = 0;

	switch (mode & S_IFMT) {
	case S_IFREG:
		inode->i_mapping->a_ops = &ubifs_file_address_operations;
		inode->i_op = &ubifs_file_inode_operations;
		inode->i_fop = &ubifs_file_operations;
		break;
	case S_IFDIR:
		inode->i_op  = &ubifs_dir_inode_operations;
		inode->i_fop = &ubifs_dir_operations;
		inode->i_size = ui->ui_size = UBIFS_INO_NODE_SZ;
		break;
	case S_IFLNK:
		inode->i_op = &ubifs_symlink_inode_operations;
		break;
	case S_IFSOCK:
	case S_IFIFO:
	case S_IFBLK:
	case S_IFCHR:
		inode->i_op  = &ubifs_file_inode_operations;
		break;
	default:
		BUG();
	}

	ui->flags = inherit_flags(dir, mode);
	ubifs_set_inode_flags(inode);
	if (S_ISREG(mode))
		ui->compr_type = c->default_compr;
	else
		ui->compr_type = UBIFS_COMPR_NONE;
	ui->synced_i_size = 0;

	spin_lock(&c->cnt_lock);
	/* Inode number overflow is currently not supported */
	if (c->highest_inum >= INUM_WARN_WATERMARK) {
		if (c->highest_inum >= INUM_WATERMARK) {
			spin_unlock(&c->cnt_lock);
			ubifs_err("out of inode numbers");
			make_bad_inode(inode);
			iput(inode);
			return ERR_PTR(-EINVAL);
		}
		ubifs_warn("running out of inode numbers (current %lu, max %d)",
			   (unsigned long)c->highest_inum, INUM_WATERMARK);
	}

	inode->i_ino = ++c->highest_inum;
	/*
	 * The creation sequence number remains with this inode for its
	 * lifetime. All nodes for this inode have a greater sequence number,
	 * and so it is possible to distinguish obsolete nodes belonging to a
	 * previous incarnation of the same inode number - for example, for the
	 * purpose of rebuilding the index.
	 */
	ui->creat_sqnum = ++c->max_sqnum;
	spin_unlock(&c->cnt_lock);
	return inode;
}

static int dbg_check_name(const struct ubifs_info *c,
			  const struct ubifs_dent_node *dent,
			  const struct qstr *nm)
{
	if (!dbg_is_chk_gen(c))
		return 0;
	if (le16_to_cpu(dent->nlen) != nm->len)
		return -EINVAL;
	if (memcmp(dent->name, nm->name, nm->len))
		return -EINVAL;
	return 0;
}

static struct dentry *ubifs_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	int err;
	union ubifs_key key;
	struct inode *inode = NULL;
	struct ubifs_dent_node *dent;
	struct ubifs_info *c = dir->i_sb->s_fs_info;

	dbg_gen("'%pd' in dir ino %lu", dentry, dir->i_ino);

	if (dentry->d_name.len > UBIFS_MAX_NLEN)
		return ERR_PTR(-ENAMETOOLONG);

	dent = kmalloc(UBIFS_MAX_DENT_NODE_SZ, GFP_NOFS);
	if (!dent)
		return ERR_PTR(-ENOMEM);

	dent_key_init(c, &key, dir->i_ino, &dentry->d_name);

	err = ubifs_tnc_lookup_nm(c, &key, dent, &dentry->d_name);
	if (err) {
		if (err == -ENOENT) {
			dbg_gen("not found");
			goto done;
		}
		goto out;
	}

	if (dbg_check_name(c, dent, &dentry->d_name)) {
		err = -EINVAL;
		goto out;
	}

	inode = ubifs_iget(dir->i_sb, le64_to_cpu(dent->inum));
	if (IS_ERR(inode)) {
		/*
		 * This should not happen. Probably the file-system needs
		 * checking.
		 */
		err = PTR_ERR(inode);
		ubifs_err("dead directory entry '%pd', error %d",
			  dentry, err);
		ubifs_ro_mode(c, err);
		goto out;
	}

done:
	kfree(dent);
	/*
	 * Note, d_splice_alias() would be required instead if we supported
	 * NFS.
	 */
	d_add(dentry, inode);
	return NULL;

out:
	kfree(dent);
	return ERR_PTR(err);
}

static int ubifs_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool excl)
{
	struct inode *inode;
	struct ubifs_info *c = dir->i_sb->s_fs_info;
	int err, sz_change = CALC_DENT_SIZE(dentry->d_name.len);
	struct ubifs_budget_req req = { .new_ino = 1, .new_dent = 1,
					.dirtied_ino = 1 };
	struct ubifs_inode *dir_ui = ubifs_inode(dir);

	/*
	 * Budget request settings: new inode, new direntry, changing the
	 * parent directory inode.
	 */

	dbg_gen("dent '%pd', mode %#hx in dir ino %lu",
		dentry, mode, dir->i_ino);

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	inode = ubifs_new_inode(c, dir, mode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_budg;
	}

	err = ubifs_init_security(dir, inode, &dentry->d_name);
	if (err)
		goto out_cancel;

	mutex_lock(&dir_ui->ui_mutex);
	dir->i_size += sz_change;
	dir_ui->ui_size = dir->i_size;
	dir->i_mtime = dir->i_ctime = inode->i_ctime;
	err = ubifs_jnl_update(c, dir, &dentry->d_name, inode, 0, 0);
	if (err)
		goto out_cancel;
	mutex_unlock(&dir_ui->ui_mutex);

	ubifs_release_budget(c, &req);
	insert_inode_hash(inode);
	d_instantiate(dentry, inode);
	return 0;

out_cancel:
	dir->i_size -= sz_change;
	dir_ui->ui_size = dir->i_size;
	mutex_unlock(&dir_ui->ui_mutex);
	make_bad_inode(inode);
	iput(inode);
out_budg:
	ubifs_release_budget(c, &req);
	ubifs_err("cannot create regular file, error %d", err);
	return err;
}

/**
 * vfs_dent_type - get VFS directory entry type.
 * @type: UBIFS directory entry type
 *
 * This function converts UBIFS directory entry type into VFS directory entry
 * type.
 */
static unsigned int vfs_dent_type(uint8_t type)
{
	switch (type) {
	case UBIFS_ITYPE_REG:
		return DT_REG;
	case UBIFS_ITYPE_DIR:
		return DT_DIR;
	case UBIFS_ITYPE_LNK:
		return DT_LNK;
	case UBIFS_ITYPE_BLK:
		return DT_BLK;
	case UBIFS_ITYPE_CHR:
		return DT_CHR;
	case UBIFS_ITYPE_FIFO:
		return DT_FIFO;
	case UBIFS_ITYPE_SOCK:
		return DT_SOCK;
	default:
		BUG();
	}
	return 0;
}

/*
 * The classical Unix view for directory is that it is a linear array of
 * (name, inode number) entries. Linux/VFS assumes this model as well.
 * Particularly, 'readdir()' call wants us to return a directory entry offset
 * which later may be used to continue 'readdir()'ing the directory or to
 * 'seek()' to that specific direntry. Obviously UBIFS does not really fit this
 * model because directory entries are identified by keys, which may collide.
 *
 * UBIFS uses directory entry hash value for directory offsets, so
 * 'seekdir()'/'telldir()' may not always work because of possible key
 * collisions. But UBIFS guarantees that consecutive 'readdir()' calls work
 * properly by means of saving full directory entry name in the private field
 * of the file description object.
 *
 * This means that UBIFS cannot support NFS which requires full
 * 'seekdir()'/'telldir()' support.
 */
static int ubifs_readdir(struct file *file, struct dir_context *ctx)
{
	int err;
	struct qstr nm;
	union ubifs_key key;
	struct ubifs_dent_node *dent;
	struct inode *dir = file_inode(file);
	struct ubifs_info *c = dir->i_sb->s_fs_info;

	dbg_gen("dir ino %lu, f_pos %#llx", dir->i_ino, ctx->pos);

	if (ctx->pos > UBIFS_S_KEY_HASH_MASK || ctx->pos == 2)
		/*
		 * The directory was seek'ed to a senseless position or there
		 * are no more entries.
		 */
		return 0;

	if (file->f_version == 0) {
		/*
		 * The file was seek'ed, which means that @file->private_data
		 * is now invalid. This may also be just the first
		 * 'ubifs_readdir()' invocation, in which case
		 * @file->private_data is NULL, and the below code is
		 * basically a no-op.
		 */
		kfree(file->private_data);
		file->private_data = NULL;
	}

	/*
	 * 'generic_file_llseek()' unconditionally sets @file->f_version to
	 * zero, and we use this for detecting whether the file was seek'ed.
	 */
	file->f_version = 1;

	/* File positions 0 and 1 correspond to "." and ".." */
	if (ctx->pos < 2) {
		ubifs_assert(!file->private_data);
		if (!dir_emit_dots(file, ctx))
			return 0;

		/* Find the first entry in TNC and save it */
		lowest_dent_key(c, &key, dir->i_ino);
		nm.name = NULL;
		dent = ubifs_tnc_next_ent(c, &key, &nm);
		if (IS_ERR(dent)) {
			err = PTR_ERR(dent);
			goto out;
		}

		ctx->pos = key_hash_flash(c, &dent->key);
		file->private_data = dent;
	}

	dent = file->private_data;
	if (!dent) {
		/*
		 * The directory was seek'ed to and is now readdir'ed.
		 * Find the entry corresponding to @ctx->pos or the closest one.
		 */
		dent_key_init_hash(c, &key, dir->i_ino, ctx->pos);
		nm.name = NULL;
		dent = ubifs_tnc_next_ent(c, &key, &nm);
		if (IS_ERR(dent)) {
			err = PTR_ERR(dent);
			goto out;
		}
		ctx->pos = key_hash_flash(c, &dent->key);
		file->private_data = dent;
	}

	while (1) {
		dbg_gen("feed '%s', ino %llu, new f_pos %#x",
			dent->name, (unsigned long long)le64_to_cpu(dent->inum),
			key_hash_flash(c, &dent->key));
		ubifs_assert(le64_to_cpu(dent->ch.sqnum) >
			     ubifs_inode(dir)->creat_sqnum);

		nm.len = le16_to_cpu(dent->nlen);
		if (!dir_emit(ctx, dent->name, nm.len,
			       le64_to_cpu(dent->inum),
			       vfs_dent_type(dent->type)))
			return 0;

		/* Switch to the next entry */
		key_read(c, &dent->key, &key);
		nm.name = dent->name;
		dent = ubifs_tnc_next_ent(c, &key, &nm);
		if (IS_ERR(dent)) {
			err = PTR_ERR(dent);
			goto out;
		}

		kfree(file->private_data);
		ctx->pos = key_hash_flash(c, &dent->key);
		file->private_data = dent;
		cond_resched();
	}

out:
	if (err != -ENOENT) {
		ubifs_err("cannot find next direntry, error %d", err);
		return err;
	}

	kfree(file->private_data);
	file->private_data = NULL;
	/* 2 is a special value indicating that there are no more direntries */
	ctx->pos = 2;
	return 0;
}

/* Free saved readdir() state when the directory is closed */
static int ubifs_dir_release(struct inode *dir, struct file *file)
{
	kfree(file->private_data);
	file->private_data = NULL;
	return 0;
}

/**
 * lock_2_inodes - a wrapper for locking two UBIFS inodes.
 * @inode1: first inode
 * @inode2: second inode
 *
 * We do not implement any tricks to guarantee strict lock ordering, because
 * VFS has already done it for us on the @i_mutex. So this is just a simple
 * wrapper function.
 */
static void lock_2_inodes(struct inode *inode1, struct inode *inode2)
{
	mutex_lock_nested(&ubifs_inode(inode1)->ui_mutex, WB_MUTEX_1);
	mutex_lock_nested(&ubifs_inode(inode2)->ui_mutex, WB_MUTEX_2);
}

/**
 * unlock_2_inodes - a wrapper for unlocking two UBIFS inodes.
 * @inode1: first inode
 * @inode2: second inode
 */
static void unlock_2_inodes(struct inode *inode1, struct inode *inode2)
{
	mutex_unlock(&ubifs_inode(inode2)->ui_mutex);
	mutex_unlock(&ubifs_inode(inode1)->ui_mutex);
}

static int ubifs_link(struct dentry *old_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct ubifs_info *c = dir->i_sb->s_fs_info;
	struct inode *inode = old_dentry->d_inode;
	struct ubifs_inode *ui = ubifs_inode(inode);
	struct ubifs_inode *dir_ui = ubifs_inode(dir);
	int err, sz_change = CALC_DENT_SIZE(dentry->d_name.len);
	struct ubifs_budget_req req = { .new_dent = 1, .dirtied_ino = 2,
				.dirtied_ino_d = ALIGN(ui->data_len, 8) };

	/*
	 * Budget request settings: new direntry, changing the target inode,
	 * changing the parent inode.
	 */

	dbg_gen("dent '%pd' to ino %lu (nlink %d) in dir ino %lu",
		dentry, inode->i_ino,
		inode->i_nlink, dir->i_ino);
	ubifs_assert(mutex_is_locked(&dir->i_mutex));
	ubifs_assert(mutex_is_locked(&inode->i_mutex));

	err = dbg_check_synced_i_size(c, inode);
	if (err)
		return err;

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	lock_2_inodes(dir, inode);
	inc_nlink(inode);
	ihold(inode);
	inode->i_ctime = ubifs_current_time(inode);
	dir->i_size += sz_change;
	dir_ui->ui_size = dir->i_size;
	dir->i_mtime = dir->i_ctime = inode->i_ctime;
	err = ubifs_jnl_update(c, dir, &dentry->d_name, inode, 0, 0);
	if (err)
		goto out_cancel;
	unlock_2_inodes(dir, inode);

	ubifs_release_budget(c, &req);
	d_instantiate(dentry, inode);
	return 0;

out_cancel:
	dir->i_size -= sz_change;
	dir_ui->ui_size = dir->i_size;
	drop_nlink(inode);
	unlock_2_inodes(dir, inode);
	ubifs_release_budget(c, &req);
	iput(inode);
	return err;
}

static int ubifs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct ubifs_info *c = dir->i_sb->s_fs_info;
	struct inode *inode = dentry->d_inode;
	struct ubifs_inode *dir_ui = ubifs_inode(dir);
	int sz_change = CALC_DENT_SIZE(dentry->d_name.len);
	int err, budgeted = 1;
	struct ubifs_budget_req req = { .mod_dent = 1, .dirtied_ino = 2 };
	unsigned int saved_nlink = inode->i_nlink;

	/*
	 * Budget request settings: deletion direntry, deletion inode (+1 for
	 * @dirtied_ino), changing the parent directory inode. If budgeting
	 * fails, go ahead anyway because we have extra space reserved for
	 * deletions.
	 */

	dbg_gen("dent '%pd' from ino %lu (nlink %d) in dir ino %lu",
		dentry, inode->i_ino,
		inode->i_nlink, dir->i_ino);
	ubifs_assert(mutex_is_locked(&dir->i_mutex));
	ubifs_assert(mutex_is_locked(&inode->i_mutex));
	err = dbg_check_synced_i_size(c, inode);
	if (err)
		return err;

	err = ubifs_budget_space(c, &req);
	if (err) {
		if (err != -ENOSPC)
			return err;
		budgeted = 0;
	}

	lock_2_inodes(dir, inode);
	inode->i_ctime = ubifs_current_time(dir);
	drop_nlink(inode);
	dir->i_size -= sz_change;
	dir_ui->ui_size = dir->i_size;
	dir->i_mtime = dir->i_ctime = inode->i_ctime;
	err = ubifs_jnl_update(c, dir, &dentry->d_name, inode, 1, 0);
	if (err)
		goto out_cancel;
	unlock_2_inodes(dir, inode);

	if (budgeted)
		ubifs_release_budget(c, &req);
	else {
		/* We've deleted something - clean the "no space" flags */
		c->bi.nospace = c->bi.nospace_rp = 0;
		smp_wmb();
	}
	return 0;

out_cancel:
	dir->i_size += sz_change;
	dir_ui->ui_size = dir->i_size;
	set_nlink(inode, saved_nlink);
	unlock_2_inodes(dir, inode);
	if (budgeted)
		ubifs_release_budget(c, &req);
	return err;
}

/**
 * check_dir_empty - check if a directory is empty or not.
 * @c: UBIFS file-system description object
 * @dir: VFS inode object of the directory to check
 *
 * This function checks if directory @dir is empty. Returns zero if the
 * directory is empty, %-ENOTEMPTY if it is not, and other negative error codes
 * in case of of errors.
 */
static int check_dir_empty(struct ubifs_info *c, struct inode *dir)
{
	struct qstr nm = { .name = NULL };
	struct ubifs_dent_node *dent;
	union ubifs_key key;
	int err;

	lowest_dent_key(c, &key, dir->i_ino);
	dent = ubifs_tnc_next_ent(c, &key, &nm);
	if (IS_ERR(dent)) {
		err = PTR_ERR(dent);
		if (err == -ENOENT)
			err = 0;
	} else {
		kfree(dent);
		err = -ENOTEMPTY;
	}
	return err;
}

static int ubifs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct ubifs_info *c = dir->i_sb->s_fs_info;
	struct inode *inode = dentry->d_inode;
	int sz_change = CALC_DENT_SIZE(dentry->d_name.len);
	int err, budgeted = 1;
	struct ubifs_inode *dir_ui = ubifs_inode(dir);
	struct ubifs_budget_req req = { .mod_dent = 1, .dirtied_ino = 2 };

	/*
	 * Budget request settings: deletion direntry, deletion inode and
	 * changing the parent inode. If budgeting fails, go ahead anyway
	 * because we have extra space reserved for deletions.
	 */

	dbg_gen("directory '%pd', ino %lu in dir ino %lu", dentry,
		inode->i_ino, dir->i_ino);
	ubifs_assert(mutex_is_locked(&dir->i_mutex));
	ubifs_assert(mutex_is_locked(&inode->i_mutex));
	err = check_dir_empty(c, dentry->d_inode);
	if (err)
		return err;

	err = ubifs_budget_space(c, &req);
	if (err) {
		if (err != -ENOSPC)
			return err;
		budgeted = 0;
	}

	lock_2_inodes(dir, inode);
	inode->i_ctime = ubifs_current_time(dir);
	clear_nlink(inode);
	drop_nlink(dir);
	dir->i_size -= sz_change;
	dir_ui->ui_size = dir->i_size;
	dir->i_mtime = dir->i_ctime = inode->i_ctime;
	err = ubifs_jnl_update(c, dir, &dentry->d_name, inode, 1, 0);
	if (err)
		goto out_cancel;
	unlock_2_inodes(dir, inode);

	if (budgeted)
		ubifs_release_budget(c, &req);
	else {
		/* We've deleted something - clean the "no space" flags */
		c->bi.nospace = c->bi.nospace_rp = 0;
		smp_wmb();
	}
	return 0;

out_cancel:
	dir->i_size += sz_change;
	dir_ui->ui_size = dir->i_size;
	inc_nlink(dir);
	set_nlink(inode, 2);
	unlock_2_inodes(dir, inode);
	if (budgeted)
		ubifs_release_budget(c, &req);
	return err;
}

static int ubifs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode *inode;
	struct ubifs_inode *dir_ui = ubifs_inode(dir);
	struct ubifs_info *c = dir->i_sb->s_fs_info;
	int err, sz_change = CALC_DENT_SIZE(dentry->d_name.len);
	struct ubifs_budget_req req = { .new_ino = 1, .new_dent = 1 };

	/*
	 * Budget request settings: new inode, new direntry and changing parent
	 * directory inode.
	 */

	dbg_gen("dent '%pd', mode %#hx in dir ino %lu",
		dentry, mode, dir->i_ino);

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	inode = ubifs_new_inode(c, dir, S_IFDIR | mode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_budg;
	}

	err = ubifs_init_security(dir, inode, &dentry->d_name);
	if (err)
		goto out_cancel;

	mutex_lock(&dir_ui->ui_mutex);
	insert_inode_hash(inode);
	inc_nlink(inode);
	inc_nlink(dir);
	dir->i_size += sz_change;
	dir_ui->ui_size = dir->i_size;
	dir->i_mtime = dir->i_ctime = inode->i_ctime;
	err = ubifs_jnl_update(c, dir, &dentry->d_name, inode, 0, 0);
	if (err) {
		ubifs_err("cannot create directory, error %d", err);
		goto out_cancel;
	}
	mutex_unlock(&dir_ui->ui_mutex);

	ubifs_release_budget(c, &req);
	d_instantiate(dentry, inode);
	return 0;

out_cancel:
	dir->i_size -= sz_change;
	dir_ui->ui_size = dir->i_size;
	drop_nlink(dir);
	mutex_unlock(&dir_ui->ui_mutex);
	make_bad_inode(inode);
	iput(inode);
out_budg:
	ubifs_release_budget(c, &req);
	return err;
}

static int ubifs_mknod(struct inode *dir, struct dentry *dentry,
		       umode_t mode, dev_t rdev)
{
	struct inode *inode;
	struct ubifs_inode *ui;
	struct ubifs_inode *dir_ui = ubifs_inode(dir);
	struct ubifs_info *c = dir->i_sb->s_fs_info;
	union ubifs_dev_desc *dev = NULL;
	int sz_change = CALC_DENT_SIZE(dentry->d_name.len);
	int err, devlen = 0;
	struct ubifs_budget_req req = { .new_ino = 1, .new_dent = 1,
					.new_ino_d = ALIGN(devlen, 8),
					.dirtied_ino = 1 };

	/*
	 * Budget request settings: new inode, new direntry and changing parent
	 * directory inode.
	 */

	dbg_gen("dent '%pd' in dir ino %lu", dentry, dir->i_ino);

	if (!new_valid_dev(rdev))
		return -EINVAL;

	if (S_ISBLK(mode) || S_ISCHR(mode)) {
		dev = kmalloc(sizeof(union ubifs_dev_desc), GFP_NOFS);
		if (!dev)
			return -ENOMEM;
		devlen = ubifs_encode_dev(dev, rdev);
	}

	err = ubifs_budget_space(c, &req);
	if (err) {
		kfree(dev);
		return err;
	}

	inode = ubifs_new_inode(c, dir, mode);
	if (IS_ERR(inode)) {
		kfree(dev);
		err = PTR_ERR(inode);
		goto out_budg;
	}

	init_special_inode(inode, inode->i_mode, rdev);
	inode->i_size = ubifs_inode(inode)->ui_size = devlen;
	ui = ubifs_inode(inode);
	ui->data = dev;
	ui->data_len = devlen;

	err = ubifs_init_security(dir, inode, &dentry->d_name);
	if (err)
		goto out_cancel;

	mutex_lock(&dir_ui->ui_mutex);
	dir->i_size += sz_change;
	dir_ui->ui_size = dir->i_size;
	dir->i_mtime = dir->i_ctime = inode->i_ctime;
	err = ubifs_jnl_update(c, dir, &dentry->d_name, inode, 0, 0);
	if (err)
		goto out_cancel;
	mutex_unlock(&dir_ui->ui_mutex);

	ubifs_release_budget(c, &req);
	insert_inode_hash(inode);
	d_instantiate(dentry, inode);
	return 0;

out_cancel:
	dir->i_size -= sz_change;
	dir_ui->ui_size = dir->i_size;
	mutex_unlock(&dir_ui->ui_mutex);
	make_bad_inode(inode);
	iput(inode);
out_budg:
	ubifs_release_budget(c, &req);
	return err;
}

static int ubifs_symlink(struct inode *dir, struct dentry *dentry,
			 const char *symname)
{
	struct inode *inode;
	struct ubifs_inode *ui;
	struct ubifs_inode *dir_ui = ubifs_inode(dir);
	struct ubifs_info *c = dir->i_sb->s_fs_info;
	int err, len = strlen(symname);
	int sz_change = CALC_DENT_SIZE(dentry->d_name.len);
	struct ubifs_budget_req req = { .new_ino = 1, .new_dent = 1,
					.new_ino_d = ALIGN(len, 8),
					.dirtied_ino = 1 };

	/*
	 * Budget request settings: new inode, new direntry and changing parent
	 * directory inode.
	 */

	dbg_gen("dent '%pd', target '%s' in dir ino %lu", dentry,
		symname, dir->i_ino);

	if (len > UBIFS_MAX_INO_DATA)
		return -ENAMETOOLONG;

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	inode = ubifs_new_inode(c, dir, S_IFLNK | S_IRWXUGO);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_budg;
	}

	ui = ubifs_inode(inode);
	ui->data = kmalloc(len + 1, GFP_NOFS);
	if (!ui->data) {
		err = -ENOMEM;
		goto out_inode;
	}

	memcpy(ui->data, symname, len);
	((char *)ui->data)[len] = '\0';
	/*
	 * The terminating zero byte is not written to the flash media and it
	 * is put just to make later in-memory string processing simpler. Thus,
	 * data length is @len, not @len + %1.
	 */
	ui->data_len = len;
	inode->i_size = ubifs_inode(inode)->ui_size = len;

	err = ubifs_init_security(dir, inode, &dentry->d_name);
	if (err)
		goto out_cancel;

	mutex_lock(&dir_ui->ui_mutex);
	dir->i_size += sz_change;
	dir_ui->ui_size = dir->i_size;
	dir->i_mtime = dir->i_ctime = inode->i_ctime;
	err = ubifs_jnl_update(c, dir, &dentry->d_name, inode, 0, 0);
	if (err)
		goto out_cancel;
	mutex_unlock(&dir_ui->ui_mutex);

	ubifs_release_budget(c, &req);
	insert_inode_hash(inode);
	d_instantiate(dentry, inode);
	return 0;

out_cancel:
	dir->i_size -= sz_change;
	dir_ui->ui_size = dir->i_size;
	mutex_unlock(&dir_ui->ui_mutex);
out_inode:
	make_bad_inode(inode);
	iput(inode);
out_budg:
	ubifs_release_budget(c, &req);
	return err;
}

/**
 * lock_3_inodes - a wrapper for locking three UBIFS inodes.
 * @inode1: first inode
 * @inode2: second inode
 * @inode3: third inode
 *
 * This function is used for 'ubifs_rename()' and @inode1 may be the same as
 * @inode2 whereas @inode3 may be %NULL.
 *
 * We do not implement any tricks to guarantee strict lock ordering, because
 * VFS has already done it for us on the @i_mutex. So this is just a simple
 * wrapper function.
 */
static void lock_3_inodes(struct inode *inode1, struct inode *inode2,
			  struct inode *inode3)
{
	mutex_lock_nested(&ubifs_inode(inode1)->ui_mutex, WB_MUTEX_1);
	if (inode2 != inode1)
		mutex_lock_nested(&ubifs_inode(inode2)->ui_mutex, WB_MUTEX_2);
	if (inode3)
		mutex_lock_nested(&ubifs_inode(inode3)->ui_mutex, WB_MUTEX_3);
}

/**
 * unlock_3_inodes - a wrapper for unlocking three UBIFS inodes for rename.
 * @inode1: first inode
 * @inode2: second inode
 * @inode3: third inode
 */
static void unlock_3_inodes(struct inode *inode1, struct inode *inode2,
			    struct inode *inode3)
{
	if (inode3)
		mutex_unlock(&ubifs_inode(inode3)->ui_mutex);
	if (inode1 != inode2)
		mutex_unlock(&ubifs_inode(inode2)->ui_mutex);
	mutex_unlock(&ubifs_inode(inode1)->ui_mutex);
}

static int ubifs_rename(struct inode *old_dir, struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry)
{
	struct ubifs_info *c = old_dir->i_sb->s_fs_info;
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct ubifs_inode *old_inode_ui = ubifs_inode(old_inode);
	int err, release, sync = 0, move = (new_dir != old_dir);
	int is_dir = S_ISDIR(old_inode->i_mode);
	int unlink = !!new_inode;
	int new_sz = CALC_DENT_SIZE(new_dentry->d_name.len);
	int old_sz = CALC_DENT_SIZE(old_dentry->d_name.len);
	struct ubifs_budget_req req = { .new_dent = 1, .mod_dent = 1,
					.dirtied_ino = 3 };
	struct ubifs_budget_req ino_req = { .dirtied_ino = 1,
			.dirtied_ino_d = ALIGN(old_inode_ui->data_len, 8) };
	struct timespec time;
	unsigned int uninitialized_var(saved_nlink);

	/*
	 * Budget request settings: deletion direntry, new direntry, removing
	 * the old inode, and changing old and new parent directory inodes.
	 *
	 * However, this operation also marks the target inode as dirty and
	 * does not write it, so we allocate budget for the target inode
	 * separately.
	 */

	dbg_gen("dent '%pd' ino %lu in dir ino %lu to dent '%pd' in dir ino %lu",
		old_dentry, old_inode->i_ino, old_dir->i_ino,
		new_dentry, new_dir->i_ino);
	ubifs_assert(mutex_is_locked(&old_dir->i_mutex));
	ubifs_assert(mutex_is_locked(&new_dir->i_mutex));
	if (unlink)
		ubifs_assert(mutex_is_locked(&new_inode->i_mutex));


	if (unlink && is_dir) {
		err = check_dir_empty(c, new_inode);
		if (err)
			return err;
	}

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;
	err = ubifs_budget_space(c, &ino_req);
	if (err) {
		ubifs_release_budget(c, &req);
		return err;
	}

	lock_3_inodes(old_dir, new_dir, new_inode);

	/*
	 * Like most other Unix systems, set the @i_ctime for inodes on a
	 * rename.
	 */
	time = ubifs_current_time(old_dir);
	old_inode->i_ctime = time;

	/* We must adjust parent link count when renaming directories */
	if (is_dir) {
		if (move) {
			/*
			 * @old_dir loses a link because we are moving
			 * @old_inode to a different directory.
			 */
			drop_nlink(old_dir);
			/*
			 * @new_dir only gains a link if we are not also
			 * overwriting an existing directory.
			 */
			if (!unlink)
				inc_nlink(new_dir);
		} else {
			/*
			 * @old_inode is not moving to a different directory,
			 * but @old_dir still loses a link if we are
			 * overwriting an existing directory.
			 */
			if (unlink)
				drop_nlink(old_dir);
		}
	}

	old_dir->i_size -= old_sz;
	ubifs_inode(old_dir)->ui_size = old_dir->i_size;
	old_dir->i_mtime = old_dir->i_ctime = time;
	new_dir->i_mtime = new_dir->i_ctime = time;

	/*
	 * And finally, if we unlinked a direntry which happened to have the
	 * same name as the moved direntry, we have to decrement @i_nlink of
	 * the unlinked inode and change its ctime.
	 */
	if (unlink) {
		/*
		 * Directories cannot have hard-links, so if this is a
		 * directory, just clear @i_nlink.
		 */
		saved_nlink = new_inode->i_nlink;
		if (is_dir)
			clear_nlink(new_inode);
		else
			drop_nlink(new_inode);
		new_inode->i_ctime = time;
	} else {
		new_dir->i_size += new_sz;
		ubifs_inode(new_dir)->ui_size = new_dir->i_size;
	}

	/*
	 * Do not ask 'ubifs_jnl_rename()' to flush write-buffer if @old_inode
	 * is dirty, because this will be done later on at the end of
	 * 'ubifs_rename()'.
	 */
	if (IS_SYNC(old_inode)) {
		sync = IS_DIRSYNC(old_dir) || IS_DIRSYNC(new_dir);
		if (unlink && IS_SYNC(new_inode))
			sync = 1;
	}
	err = ubifs_jnl_rename(c, old_dir, old_dentry, new_dir, new_dentry,
			       sync);
	if (err)
		goto out_cancel;

	unlock_3_inodes(old_dir, new_dir, new_inode);
	ubifs_release_budget(c, &req);

	mutex_lock(&old_inode_ui->ui_mutex);
	release = old_inode_ui->dirty;
	mark_inode_dirty_sync(old_inode);
	mutex_unlock(&old_inode_ui->ui_mutex);

	if (release)
		ubifs_release_budget(c, &ino_req);
	if (IS_SYNC(old_inode))
		err = old_inode->i_sb->s_op->write_inode(old_inode, NULL);
	return err;

out_cancel:
	if (unlink) {
		set_nlink(new_inode, saved_nlink);
	} else {
		new_dir->i_size -= new_sz;
		ubifs_inode(new_dir)->ui_size = new_dir->i_size;
	}
	old_dir->i_size += old_sz;
	ubifs_inode(old_dir)->ui_size = old_dir->i_size;
	if (is_dir) {
		if (move) {
			inc_nlink(old_dir);
			if (!unlink)
				drop_nlink(new_dir);
		} else {
			if (unlink)
				inc_nlink(old_dir);
		}
	}
	unlock_3_inodes(old_dir, new_dir, new_inode);
	ubifs_release_budget(c, &ino_req);
	ubifs_release_budget(c, &req);
	return err;
}

int ubifs_getattr(struct vfsmount *mnt, struct dentry *dentry,
		  struct kstat *stat)
{
	loff_t size;
	struct inode *inode = dentry->d_inode;
	struct ubifs_inode *ui = ubifs_inode(inode);

	mutex_lock(&ui->ui_mutex);
	generic_fillattr(inode, stat);
	stat->blksize = UBIFS_BLOCK_SIZE;
	stat->size = ui->ui_size;

	/*
	 * Unfortunately, the 'stat()' system call was designed for block
	 * device based file systems, and it is not appropriate for UBIFS,
	 * because UBIFS does not have notion of "block". For example, it is
	 * difficult to tell how many block a directory takes - it actually
	 * takes less than 300 bytes, but we have to round it to block size,
	 * which introduces large mistake. This makes utilities like 'du' to
	 * report completely senseless numbers. This is the reason why UBIFS
	 * goes the same way as JFFS2 - it reports zero blocks for everything
	 * but regular files, which makes more sense than reporting completely
	 * wrong sizes.
	 */
	if (S_ISREG(inode->i_mode)) {
		size = ui->xattr_size;
		size += stat->size;
		size = ALIGN(size, UBIFS_BLOCK_SIZE);
		/*
		 * Note, user-space expects 512-byte blocks count irrespectively
		 * of what was reported in @stat->size.
		 */
		stat->blocks = size >> 9;
	} else
		stat->blocks = 0;
	mutex_unlock(&ui->ui_mutex);
	return 0;
}

const struct inode_operations ubifs_dir_inode_operations = {
	.lookup      = ubifs_lookup,
	.create      = ubifs_create,
	.link        = ubifs_link,
	.symlink     = ubifs_symlink,
	.unlink      = ubifs_unlink,
	.mkdir       = ubifs_mkdir,
	.rmdir       = ubifs_rmdir,
	.mknod       = ubifs_mknod,
	.rename      = ubifs_rename,
	.setattr     = ubifs_setattr,
	.getattr     = ubifs_getattr,
	.setxattr    = ubifs_setxattr,
	.getxattr    = ubifs_getxattr,
	.listxattr   = ubifs_listxattr,
	.removexattr = ubifs_removexattr,
};

const struct file_operations ubifs_dir_operations = {
	.llseek         = generic_file_llseek,
	.release        = ubifs_dir_release,
	.read           = generic_read_dir,
	.iterate        = ubifs_readdir,
	.fsync          = ubifs_fsync,
	.unlocked_ioctl = ubifs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = ubifs_compat_ioctl,
#endif
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/dir.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file implements UBIFS initialization and VFS superblock operations. Some
 * initialization stuff which is rather large and complex is placed at
 * corresponding subsystems, but most of it is here.
 */

#include <linux/init.h>
// #include <linux/slab.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/parser.h>
#include <linux/seq_file.h>
// #include <linux/mount.h>
#include <linux/math64.h>
#include <linux/writeback.h>
// #include "ubifs.h"
#include "../../inc/__fss.h"

/*
 * Maximum amount of memory we may 'kmalloc()' without worrying that we are
 * allocating too much.
 */
#define UBIFS_KMALLOC_OK (128*1024)

/* Slab cache for UBIFS inodes */
struct kmem_cache *ubifs_inode_slab;

/* UBIFS TNC shrinker description */
static struct shrinker ubifs_shrinker_info = {
	.scan_objects = ubifs_shrink_scan,
	.count_objects = ubifs_shrink_count,
	.seeks = DEFAULT_SEEKS,
};

/**
 * validate_inode - validate inode.
 * @c: UBIFS file-system description object
 * @inode: the inode to validate
 *
 * This is a helper function for 'ubifs_iget()' which validates various fields
 * of a newly built inode to make sure they contain sane values and prevent
 * possible vulnerabilities. Returns zero if the inode is all right and
 * a non-zero error code if not.
 */
static int validate_inode(struct ubifs_info *c, const struct inode *inode)
{
	int err;
	const struct ubifs_inode *ui = ubifs_inode(inode);

	if (inode->i_size > c->max_inode_sz) {
		ubifs_err("inode is too large (%lld)",
			  (long long)inode->i_size);
		return 1;
	}

	if (ui->compr_type >= UBIFS_COMPR_TYPES_CNT) {
		ubifs_err("unknown compression type %d", ui->compr_type);
		return 2;
	}

	if (ui->xattr_names + ui->xattr_cnt > XATTR_LIST_MAX)
		return 3;

	if (ui->data_len < 0 || ui->data_len > UBIFS_MAX_INO_DATA)
		return 4;

	if (ui->xattr && !S_ISREG(inode->i_mode))
		return 5;

	if (!ubifs_compr_present(ui->compr_type)) {
		ubifs_warn("inode %lu uses '%s' compression, but it was not compiled in",
			   inode->i_ino, ubifs_compr_name(ui->compr_type));
	}

	err = dbg_check_dir(c, inode);
	return err;
}

struct inode *ubifs_iget(struct super_block *sb, unsigned long inum)
{
	int err;
	union ubifs_key key;
	struct ubifs_ino_node *ino;
	struct ubifs_info *c = sb->s_fs_info;
	struct inode *inode;
	struct ubifs_inode *ui;

	dbg_gen("inode %lu", inum);

	inode = iget_locked(sb, inum);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;
	ui = ubifs_inode(inode);

	ino = kmalloc(UBIFS_MAX_INO_NODE_SZ, GFP_NOFS);
	if (!ino) {
		err = -ENOMEM;
		goto out;
	}

	ino_key_init(c, &key, inode->i_ino);

	err = ubifs_tnc_lookup(c, &key, ino);
	if (err)
		goto out_ino;

	inode->i_flags |= (S_NOCMTIME | S_NOATIME);
	set_nlink(inode, le32_to_cpu(ino->nlink));
	i_uid_write(inode, le32_to_cpu(ino->uid));
	i_gid_write(inode, le32_to_cpu(ino->gid));
	inode->i_atime.tv_sec  = (int64_t)le64_to_cpu(ino->atime_sec);
	inode->i_atime.tv_nsec = le32_to_cpu(ino->atime_nsec);
	inode->i_mtime.tv_sec  = (int64_t)le64_to_cpu(ino->mtime_sec);
	inode->i_mtime.tv_nsec = le32_to_cpu(ino->mtime_nsec);
	inode->i_ctime.tv_sec  = (int64_t)le64_to_cpu(ino->ctime_sec);
	inode->i_ctime.tv_nsec = le32_to_cpu(ino->ctime_nsec);
	inode->i_mode = le32_to_cpu(ino->mode);
	inode->i_size = le64_to_cpu(ino->size);

	ui->data_len    = le32_to_cpu(ino->data_len);
	ui->flags       = le32_to_cpu(ino->flags);
	ui->compr_type  = le16_to_cpu(ino->compr_type);
	ui->creat_sqnum = le64_to_cpu(ino->creat_sqnum);
	ui->xattr_cnt   = le32_to_cpu(ino->xattr_cnt);
	ui->xattr_size  = le32_to_cpu(ino->xattr_size);
	ui->xattr_names = le32_to_cpu(ino->xattr_names);
	ui->synced_i_size = ui->ui_size = inode->i_size;

	ui->xattr = (ui->flags & UBIFS_XATTR_FL) ? 1 : 0;

	err = validate_inode(c, inode);
	if (err)
		goto out_invalid;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_mapping->a_ops = &ubifs_file_address_operations;
		inode->i_op = &ubifs_file_inode_operations;
		inode->i_fop = &ubifs_file_operations;
		if (ui->xattr) {
			ui->data = kmalloc(ui->data_len + 1, GFP_NOFS);
			if (!ui->data) {
				err = -ENOMEM;
				goto out_ino;
			}
			memcpy(ui->data, ino->data, ui->data_len);
			((char *)ui->data)[ui->data_len] = '\0';
		} else if (ui->data_len != 0) {
			err = 10;
			goto out_invalid;
		}
		break;
	case S_IFDIR:
		inode->i_op  = &ubifs_dir_inode_operations;
		inode->i_fop = &ubifs_dir_operations;
		if (ui->data_len != 0) {
			err = 11;
			goto out_invalid;
		}
		break;
	case S_IFLNK:
		inode->i_op = &ubifs_symlink_inode_operations;
		if (ui->data_len <= 0 || ui->data_len > UBIFS_MAX_INO_DATA) {
			err = 12;
			goto out_invalid;
		}
		ui->data = kmalloc(ui->data_len + 1, GFP_NOFS);
		if (!ui->data) {
			err = -ENOMEM;
			goto out_ino;
		}
		memcpy(ui->data, ino->data, ui->data_len);
		((char *)ui->data)[ui->data_len] = '\0';
		break;
	case S_IFBLK:
	case S_IFCHR:
	{
		dev_t rdev;
		union ubifs_dev_desc *dev;

		ui->data = kmalloc(sizeof(union ubifs_dev_desc), GFP_NOFS);
		if (!ui->data) {
			err = -ENOMEM;
			goto out_ino;
		}

		dev = (union ubifs_dev_desc *)ino->data;
		if (ui->data_len == sizeof(dev->new))
			rdev = new_decode_dev(le32_to_cpu(dev->new));
		else if (ui->data_len == sizeof(dev->huge))
			rdev = huge_decode_dev(le64_to_cpu(dev->huge));
		else {
			err = 13;
			goto out_invalid;
		}
		memcpy(ui->data, ino->data, ui->data_len);
		inode->i_op = &ubifs_file_inode_operations;
		init_special_inode(inode, inode->i_mode, rdev);
		break;
	}
	case S_IFSOCK:
	case S_IFIFO:
		inode->i_op = &ubifs_file_inode_operations;
		init_special_inode(inode, inode->i_mode, 0);
		if (ui->data_len != 0) {
			err = 14;
			goto out_invalid;
		}
		break;
	default:
		err = 15;
		goto out_invalid;
	}

	kfree(ino);
	ubifs_set_inode_flags(inode);
	unlock_new_inode(inode);
	return inode;

out_invalid:
	ubifs_err("inode %lu validation failed, error %d", inode->i_ino, err);
	ubifs_dump_node(c, ino);
	ubifs_dump_inode(c, inode);
	err = -EINVAL;
out_ino:
	kfree(ino);
out:
	ubifs_err("failed to read inode %lu, error %d", inode->i_ino, err);
	iget_failed(inode);
	return ERR_PTR(err);
}

static struct inode *ubifs_alloc_inode(struct super_block *sb)
{
	struct ubifs_inode *ui;

	ui = kmem_cache_alloc(ubifs_inode_slab, GFP_NOFS);
	if (!ui)
		return NULL;

	memset((void *)ui + sizeof(struct inode), 0,
	       sizeof(struct ubifs_inode) - sizeof(struct inode));
	mutex_init(&ui->ui_mutex);
	spin_lock_init(&ui->ui_lock);
	return &ui->vfs_inode;
};

static void ubifs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct ubifs_inode *ui = ubifs_inode(inode);
	kmem_cache_free(ubifs_inode_slab, ui);
}

static void ubifs_destroy_inode(struct inode *inode)
{
	struct ubifs_inode *ui = ubifs_inode(inode);

	kfree(ui->data);
	call_rcu(&inode->i_rcu, ubifs_i_callback);
}

/*
 * Note, Linux write-back code calls this without 'i_mutex'.
 */
static int ubifs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int err = 0;
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	struct ubifs_inode *ui = ubifs_inode(inode);

	ubifs_assert(!ui->xattr);
	if (is_bad_inode(inode))
		return 0;

	mutex_lock(&ui->ui_mutex);
	/*
	 * Due to races between write-back forced by budgeting
	 * (see 'sync_some_inodes()') and background write-back, the inode may
	 * have already been synchronized, do not do this again. This might
	 * also happen if it was synchronized in an VFS operation, e.g.
	 * 'ubifs_link()'.
	 */
	if (!ui->dirty) {
		mutex_unlock(&ui->ui_mutex);
		return 0;
	}

	/*
	 * As an optimization, do not write orphan inodes to the media just
	 * because this is not needed.
	 */
	dbg_gen("inode %lu, mode %#x, nlink %u",
		inode->i_ino, (int)inode->i_mode, inode->i_nlink);
	if (inode->i_nlink) {
		err = ubifs_jnl_write_inode(c, inode);
		if (err)
			ubifs_err("can't write inode %lu, error %d",
				  inode->i_ino, err);
		else
			err = dbg_check_inode_size(c, inode, ui->ui_size);
	}

	ui->dirty = 0;
	mutex_unlock(&ui->ui_mutex);
	ubifs_release_dirty_inode_budget(c, ui);
	return err;
}

static void ubifs_evict_inode(struct inode *inode)
{
	int err;
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	struct ubifs_inode *ui = ubifs_inode(inode);

	if (ui->xattr)
		/*
		 * Extended attribute inode deletions are fully handled in
		 * 'ubifs_removexattr()'. These inodes are special and have
		 * limited usage, so there is nothing to do here.
		 */
		goto out;

	dbg_gen("inode %lu, mode %#x", inode->i_ino, (int)inode->i_mode);
	ubifs_assert(!atomic_read(&inode->i_count));

	truncate_inode_pages_final(&inode->i_data);

	if (inode->i_nlink)
		goto done;

	if (is_bad_inode(inode))
		goto out;

	ui->ui_size = inode->i_size = 0;
	err = ubifs_jnl_delete_inode(c, inode);
	if (err)
		/*
		 * Worst case we have a lost orphan inode wasting space, so a
		 * simple error message is OK here.
		 */
		ubifs_err("can't delete inode %lu, error %d",
			  inode->i_ino, err);

out:
	if (ui->dirty)
		ubifs_release_dirty_inode_budget(c, ui);
	else {
		/* We've deleted something - clean the "no space" flags */
		c->bi.nospace = c->bi.nospace_rp = 0;
		smp_wmb();
	}
done:
	clear_inode(inode);
}

static void ubifs_dirty_inode(struct inode *inode, int flags)
{
	struct ubifs_inode *ui = ubifs_inode(inode);

	ubifs_assert(mutex_is_locked(&ui->ui_mutex));
	if (!ui->dirty) {
		ui->dirty = 1;
		dbg_gen("inode %lu",  inode->i_ino);
	}
}

static int ubifs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct ubifs_info *c = dentry->d_sb->s_fs_info;
	unsigned long long free;
	__le32 *uuid = (__le32 *)c->uuid;

	free = ubifs_get_free_space(c);
	dbg_gen("free space %lld bytes (%lld blocks)",
		free, free >> UBIFS_BLOCK_SHIFT);

	buf->f_type = UBIFS_SUPER_MAGIC;
	buf->f_bsize = UBIFS_BLOCK_SIZE;
	buf->f_blocks = c->block_cnt;
	buf->f_bfree = free >> UBIFS_BLOCK_SHIFT;
	if (free > c->report_rp_size)
		buf->f_bavail = (free - c->report_rp_size) >> UBIFS_BLOCK_SHIFT;
	else
		buf->f_bavail = 0;
	buf->f_files = 0;
	buf->f_ffree = 0;
	buf->f_namelen = UBIFS_MAX_NLEN;
	buf->f_fsid.val[0] = le32_to_cpu(uuid[0]) ^ le32_to_cpu(uuid[2]);
	buf->f_fsid.val[1] = le32_to_cpu(uuid[1]) ^ le32_to_cpu(uuid[3]);
	ubifs_assert(buf->f_bfree <= c->block_cnt);
	return 0;
}

static int ubifs_show_options(struct seq_file *s, struct dentry *root)
{
	struct ubifs_info *c = root->d_sb->s_fs_info;

	if (c->mount_opts.unmount_mode == 2)
		seq_puts(s, ",fast_unmount");
	else if (c->mount_opts.unmount_mode == 1)
		seq_puts(s, ",norm_unmount");

	if (c->mount_opts.bulk_read == 2)
		seq_puts(s, ",bulk_read");
	else if (c->mount_opts.bulk_read == 1)
		seq_puts(s, ",no_bulk_read");

	if (c->mount_opts.chk_data_crc == 2)
		seq_puts(s, ",chk_data_crc");
	else if (c->mount_opts.chk_data_crc == 1)
		seq_puts(s, ",no_chk_data_crc");

	if (c->mount_opts.override_compr) {
		seq_printf(s, ",compr=%s",
			   ubifs_compr_name(c->mount_opts.compr_type));
	}

	return 0;
}

static int ubifs_sync_fs(struct super_block *sb, int wait)
{
	int i, err;
	struct ubifs_info *c = sb->s_fs_info;

	/*
	 * Zero @wait is just an advisory thing to help the file system shove
	 * lots of data into the queues, and there will be the second
	 * '->sync_fs()' call, with non-zero @wait.
	 */
	if (!wait)
		return 0;

	/*
	 * Synchronize write buffers, because 'ubifs_run_commit()' does not
	 * do this if it waits for an already running commit.
	 */
	for (i = 0; i < c->jhead_cnt; i++) {
		err = ubifs_wbuf_sync(&c->jheads[i].wbuf);
		if (err)
			return err;
	}

	/*
	 * Strictly speaking, it is not necessary to commit the journal here,
	 * synchronizing write-buffers would be enough. But committing makes
	 * UBIFS free space predictions much more accurate, so we want to let
	 * the user be able to get more accurate results of 'statfs()' after
	 * they synchronize the file system.
	 */
	err = ubifs_run_commit(c);
	if (err)
		return err;

	return ubi_sync(c->vi.ubi_num);
}

/**
 * init_constants_early - initialize UBIFS constants.
 * @c: UBIFS file-system description object
 *
 * This function initialize UBIFS constants which do not need the superblock to
 * be read. It also checks that the UBI volume satisfies basic UBIFS
 * requirements. Returns zero in case of success and a negative error code in
 * case of failure.
 */
static int init_constants_early(struct ubifs_info *c)
{
	if (c->vi.corrupted) {
		ubifs_warn("UBI volume is corrupted - read-only mode");
		c->ro_media = 1;
	}

	if (c->di.ro_mode) {
		ubifs_msg("read-only UBI device");
		c->ro_media = 1;
	}

	if (c->vi.vol_type == UBI_STATIC_VOLUME) {
		ubifs_msg("static UBI volume - read-only mode");
		c->ro_media = 1;
	}

	c->leb_cnt = c->vi.size;
	c->leb_size = c->vi.usable_leb_size;
	c->leb_start = c->di.leb_start;
	c->half_leb_size = c->leb_size / 2;
	c->min_io_size = c->di.min_io_size;
	c->min_io_shift = fls(c->min_io_size) - 1;
	c->max_write_size = c->di.max_write_size;
	c->max_write_shift = fls(c->max_write_size) - 1;

	if (c->leb_size < UBIFS_MIN_LEB_SZ) {
		ubifs_err("too small LEBs (%d bytes), min. is %d bytes",
			  c->leb_size, UBIFS_MIN_LEB_SZ);
		return -EINVAL;
	}

	if (c->leb_cnt < UBIFS_MIN_LEB_CNT) {
		ubifs_err("too few LEBs (%d), min. is %d",
			  c->leb_cnt, UBIFS_MIN_LEB_CNT);
		return -EINVAL;
	}

	if (!is_power_of_2(c->min_io_size)) {
		ubifs_err("bad min. I/O size %d", c->min_io_size);
		return -EINVAL;
	}

	/*
	 * Maximum write size has to be greater or equivalent to min. I/O
	 * size, and be multiple of min. I/O size.
	 */
	if (c->max_write_size < c->min_io_size ||
	    c->max_write_size % c->min_io_size ||
	    !is_power_of_2(c->max_write_size)) {
		ubifs_err("bad write buffer size %d for %d min. I/O unit",
			  c->max_write_size, c->min_io_size);
		return -EINVAL;
	}

	/*
	 * UBIFS aligns all node to 8-byte boundary, so to make function in
	 * io.c simpler, assume minimum I/O unit size to be 8 bytes if it is
	 * less than 8.
	 */
	if (c->min_io_size < 8) {
		c->min_io_size = 8;
		c->min_io_shift = 3;
		if (c->max_write_size < c->min_io_size) {
			c->max_write_size = c->min_io_size;
			c->max_write_shift = c->min_io_shift;
		}
	}

	c->ref_node_alsz = ALIGN(UBIFS_REF_NODE_SZ, c->min_io_size);
	c->mst_node_alsz = ALIGN(UBIFS_MST_NODE_SZ, c->min_io_size);

	/*
	 * Initialize node length ranges which are mostly needed for node
	 * length validation.
	 */
	c->ranges[UBIFS_PAD_NODE].len  = UBIFS_PAD_NODE_SZ;
	c->ranges[UBIFS_SB_NODE].len   = UBIFS_SB_NODE_SZ;
	c->ranges[UBIFS_MST_NODE].len  = UBIFS_MST_NODE_SZ;
	c->ranges[UBIFS_REF_NODE].len  = UBIFS_REF_NODE_SZ;
	c->ranges[UBIFS_TRUN_NODE].len = UBIFS_TRUN_NODE_SZ;
	c->ranges[UBIFS_CS_NODE].len   = UBIFS_CS_NODE_SZ;

	c->ranges[UBIFS_INO_NODE].min_len  = UBIFS_INO_NODE_SZ;
	c->ranges[UBIFS_INO_NODE].max_len  = UBIFS_MAX_INO_NODE_SZ;
	c->ranges[UBIFS_ORPH_NODE].min_len =
				UBIFS_ORPH_NODE_SZ + sizeof(__le64);
	c->ranges[UBIFS_ORPH_NODE].max_len = c->leb_size;
	c->ranges[UBIFS_DENT_NODE].min_len = UBIFS_DENT_NODE_SZ;
	c->ranges[UBIFS_DENT_NODE].max_len = UBIFS_MAX_DENT_NODE_SZ;
	c->ranges[UBIFS_XENT_NODE].min_len = UBIFS_XENT_NODE_SZ;
	c->ranges[UBIFS_XENT_NODE].max_len = UBIFS_MAX_XENT_NODE_SZ;
	c->ranges[UBIFS_DATA_NODE].min_len = UBIFS_DATA_NODE_SZ;
	c->ranges[UBIFS_DATA_NODE].max_len = UBIFS_MAX_DATA_NODE_SZ;
	/*
	 * Minimum indexing node size is amended later when superblock is
	 * read and the key length is known.
	 */
	c->ranges[UBIFS_IDX_NODE].min_len = UBIFS_IDX_NODE_SZ + UBIFS_BRANCH_SZ;
	/*
	 * Maximum indexing node size is amended later when superblock is
	 * read and the fanout is known.
	 */
	c->ranges[UBIFS_IDX_NODE].max_len = INT_MAX;

	/*
	 * Initialize dead and dark LEB space watermarks. See gc.c for comments
	 * about these values.
	 */
	c->dead_wm = ALIGN(MIN_WRITE_SZ, c->min_io_size);
	c->dark_wm = ALIGN(UBIFS_MAX_NODE_SZ, c->min_io_size);

	/*
	 * Calculate how many bytes would be wasted at the end of LEB if it was
	 * fully filled with data nodes of maximum size. This is used in
	 * calculations when reporting free space.
	 */
	c->leb_overhead = c->leb_size % UBIFS_MAX_DATA_NODE_SZ;

	/* Buffer size for bulk-reads */
	c->max_bu_buf_len = UBIFS_MAX_BULK_READ * UBIFS_MAX_DATA_NODE_SZ;
	if (c->max_bu_buf_len > c->leb_size)
		c->max_bu_buf_len = c->leb_size;
	return 0;
}

/**
 * bud_wbuf_callback - bud LEB write-buffer synchronization call-back.
 * @c: UBIFS file-system description object
 * @lnum: LEB the write-buffer was synchronized to
 * @free: how many free bytes left in this LEB
 * @pad: how many bytes were padded
 *
 * This is a callback function which is called by the I/O unit when the
 * write-buffer is synchronized. We need this to correctly maintain space
 * accounting in bud logical eraseblocks. This function returns zero in case of
 * success and a negative error code in case of failure.
 *
 * This function actually belongs to the journal, but we keep it here because
 * we want to keep it static.
 */
static int bud_wbuf_callback(struct ubifs_info *c, int lnum, int free, int pad)
{
	return ubifs_update_one_lp(c, lnum, free, pad, 0, 0);
}

/*
 * init_constants_sb - initialize UBIFS constants.
 * @c: UBIFS file-system description object
 *
 * This is a helper function which initializes various UBIFS constants after
 * the superblock has been read. It also checks various UBIFS parameters and
 * makes sure they are all right. Returns zero in case of success and a
 * negative error code in case of failure.
 */
static int init_constants_sb(struct ubifs_info *c)
{
	int tmp, err;
	long long tmp64;

	c->main_bytes = (long long)c->main_lebs * c->leb_size;
	c->max_znode_sz = sizeof(struct ubifs_znode) +
				c->fanout * sizeof(struct ubifs_zbranch);

	tmp = ubifs_idx_node_sz(c, 1);
	c->ranges[UBIFS_IDX_NODE].min_len = tmp;
	c->min_idx_node_sz = ALIGN(tmp, 8);

	tmp = ubifs_idx_node_sz(c, c->fanout);
	c->ranges[UBIFS_IDX_NODE].max_len = tmp;
	c->max_idx_node_sz = ALIGN(tmp, 8);

	/* Make sure LEB size is large enough to fit full commit */
	tmp = UBIFS_CS_NODE_SZ + UBIFS_REF_NODE_SZ * c->jhead_cnt;
	tmp = ALIGN(tmp, c->min_io_size);
	if (tmp > c->leb_size) {
		ubifs_err("too small LEB size %d, at least %d needed",
			  c->leb_size, tmp);
		return -EINVAL;
	}

	/*
	 * Make sure that the log is large enough to fit reference nodes for
	 * all buds plus one reserved LEB.
	 */
	tmp64 = c->max_bud_bytes + c->leb_size - 1;
	c->max_bud_cnt = div_u64(tmp64, c->leb_size);
	tmp = (c->ref_node_alsz * c->max_bud_cnt + c->leb_size - 1);
	tmp /= c->leb_size;
	tmp += 1;
	if (c->log_lebs < tmp) {
		ubifs_err("too small log %d LEBs, required min. %d LEBs",
			  c->log_lebs, tmp);
		return -EINVAL;
	}

	/*
	 * When budgeting we assume worst-case scenarios when the pages are not
	 * be compressed and direntries are of the maximum size.
	 *
	 * Note, data, which may be stored in inodes is budgeted separately, so
	 * it is not included into 'c->bi.inode_budget'.
	 */
	c->bi.page_budget = UBIFS_MAX_DATA_NODE_SZ * UBIFS_BLOCKS_PER_PAGE;
	c->bi.inode_budget = UBIFS_INO_NODE_SZ;
	c->bi.dent_budget = UBIFS_MAX_DENT_NODE_SZ;

	/*
	 * When the amount of flash space used by buds becomes
	 * 'c->max_bud_bytes', UBIFS just blocks all writers and starts commit.
	 * The writers are unblocked when the commit is finished. To avoid
	 * writers to be blocked UBIFS initiates background commit in advance,
	 * when number of bud bytes becomes above the limit defined below.
	 */
	c->bg_bud_bytes = (c->max_bud_bytes * 13) >> 4;

	/*
	 * Ensure minimum journal size. All the bytes in the journal heads are
	 * considered to be used, when calculating the current journal usage.
	 * Consequently, if the journal is too small, UBIFS will treat it as
	 * always full.
	 */
	tmp64 = (long long)(c->jhead_cnt + 1) * c->leb_size + 1;
	if (c->bg_bud_bytes < tmp64)
		c->bg_bud_bytes = tmp64;
	if (c->max_bud_bytes < tmp64 + c->leb_size)
		c->max_bud_bytes = tmp64 + c->leb_size;

	err = ubifs_calc_lpt_geom(c);
	if (err)
		return err;

	/* Initialize effective LEB size used in budgeting calculations */
	c->idx_leb_size = c->leb_size - c->max_idx_node_sz;
	return 0;
}

/*
 * init_constants_master - initialize UBIFS constants.
 * @c: UBIFS file-system description object
 *
 * This is a helper function which initializes various UBIFS constants after
 * the master node has been read. It also checks various UBIFS parameters and
 * makes sure they are all right.
 */
static void init_constants_master(struct ubifs_info *c)
{
	long long tmp64;

	c->bi.min_idx_lebs = ubifs_calc_min_idx_lebs(c);
	c->report_rp_size = ubifs_reported_space(c, c->rp_size);

	/*
	 * Calculate total amount of FS blocks. This number is not used
	 * internally because it does not make much sense for UBIFS, but it is
	 * necessary to report something for the 'statfs()' call.
	 *
	 * Subtract the LEB reserved for GC, the LEB which is reserved for
	 * deletions, minimum LEBs for the index, and assume only one journal
	 * head is available.
	 */
	tmp64 = c->main_lebs - 1 - 1 - MIN_INDEX_LEBS - c->jhead_cnt + 1;
	tmp64 *= (long long)c->leb_size - c->leb_overhead;
	tmp64 = ubifs_reported_space(c, tmp64);
	c->block_cnt = tmp64 >> UBIFS_BLOCK_SHIFT;
}

/**
 * take_gc_lnum - reserve GC LEB.
 * @c: UBIFS file-system description object
 *
 * This function ensures that the LEB reserved for garbage collection is marked
 * as "taken" in lprops. We also have to set free space to LEB size and dirty
 * space to zero, because lprops may contain out-of-date information if the
 * file-system was un-mounted before it has been committed. This function
 * returns zero in case of success and a negative error code in case of
 * failure.
 */
static int take_gc_lnum(struct ubifs_info *c)
{
	int err;

	if (c->gc_lnum == -1) {
		ubifs_err("no LEB for GC");
		return -EINVAL;
	}

	/* And we have to tell lprops that this LEB is taken */
	err = ubifs_change_one_lp(c, c->gc_lnum, c->leb_size, 0,
				  LPROPS_TAKEN, 0, 0);
	return err;
}

/**
 * alloc_wbufs - allocate write-buffers.
 * @c: UBIFS file-system description object
 *
 * This helper function allocates and initializes UBIFS write-buffers. Returns
 * zero in case of success and %-ENOMEM in case of failure.
 */
static int alloc_wbufs(struct ubifs_info *c)
{
	int i, err;

	c->jheads = kcalloc(c->jhead_cnt, sizeof(struct ubifs_jhead),
			    GFP_KERNEL);
	if (!c->jheads)
		return -ENOMEM;

	/* Initialize journal heads */
	for (i = 0; i < c->jhead_cnt; i++) {
		INIT_LIST_HEAD(&c->jheads[i].buds_list);
		err = ubifs_wbuf_init(c, &c->jheads[i].wbuf);
		if (err)
			return err;

		c->jheads[i].wbuf.sync_callback = &bud_wbuf_callback;
		c->jheads[i].wbuf.jhead = i;
		c->jheads[i].grouped = 1;
	}

	/*
	 * Garbage Collector head does not need to be synchronized by timer.
	 * Also GC head nodes are not grouped.
	 */
	c->jheads[GCHD].wbuf.no_timer = 1;
	c->jheads[GCHD].grouped = 0;

	return 0;
}

/**
 * free_wbufs - free write-buffers.
 * @c: UBIFS file-system description object
 */
static void free_wbufs(struct ubifs_info *c)
{
	int i;

	if (c->jheads) {
		for (i = 0; i < c->jhead_cnt; i++) {
			kfree(c->jheads[i].wbuf.buf);
			kfree(c->jheads[i].wbuf.inodes);
		}
		kfree(c->jheads);
		c->jheads = NULL;
	}
}

/**
 * free_orphans - free orphans.
 * @c: UBIFS file-system description object
 */
static void free_orphans(struct ubifs_info *c)
{
	struct ubifs_orphan *orph;

	while (c->orph_dnext) {
		orph = c->orph_dnext;
		c->orph_dnext = orph->dnext;
		list_del(&orph->list);
		kfree(orph);
	}

	while (!list_empty(&c->orph_list)) {
		orph = list_entry(c->orph_list.next, struct ubifs_orphan, list);
		list_del(&orph->list);
		kfree(orph);
		ubifs_err("orphan list not empty at unmount");
	}

	vfree(c->orph_buf);
	c->orph_buf = NULL;
}

/**
 * free_buds - free per-bud objects.
 * @c: UBIFS file-system description object
 */
static void free_buds(struct ubifs_info *c)
{
	struct ubifs_bud *bud, *n;

	rbtree_postorder_for_each_entry_safe(bud, n, &c->buds, rb)
		kfree(bud);
}

/**
 * check_volume_empty - check if the UBI volume is empty.
 * @c: UBIFS file-system description object
 *
 * This function checks if the UBIFS volume is empty by looking if its LEBs are
 * mapped or not. The result of checking is stored in the @c->empty variable.
 * Returns zero in case of success and a negative error code in case of
 * failure.
 */
static int check_volume_empty(struct ubifs_info *c)
{
	int lnum, err;

	c->empty = 1;
	for (lnum = 0; lnum < c->leb_cnt; lnum++) {
		err = ubifs_is_mapped(c, lnum);
		if (unlikely(err < 0))
			return err;
		if (err == 1) {
			c->empty = 0;
			break;
		}

		cond_resched();
	}

	return 0;
}

/*
 * UBIFS mount options.
 *
 * Opt_fast_unmount: do not run a journal commit before un-mounting
 * Opt_norm_unmount: run a journal commit before un-mounting
 * Opt_bulk_read: enable bulk-reads
 * Opt_no_bulk_read: disable bulk-reads
 * Opt_chk_data_crc: check CRCs when reading data nodes
 * Opt_no_chk_data_crc: do not check CRCs when reading data nodes
 * Opt_override_compr: override default compressor
 * Opt_err: just end of array marker
 */
enum {
	Opt_fast_unmount,
	Opt_norm_unmount,
	Opt_bulk_read,
	Opt_no_bulk_read,
	Opt_chk_data_crc,
	Opt_no_chk_data_crc,
	Opt_override_compr,
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_fast_unmount, "fast_unmount"},
	{Opt_norm_unmount, "norm_unmount"},
	{Opt_bulk_read, "bulk_read"},
	{Opt_no_bulk_read, "no_bulk_read"},
	{Opt_chk_data_crc, "chk_data_crc"},
	{Opt_no_chk_data_crc, "no_chk_data_crc"},
	{Opt_override_compr, "compr=%s"},
	{Opt_err, NULL},
};

/**
 * parse_standard_option - parse a standard mount option.
 * @option: the option to parse
 *
 * Normally, standard mount options like "sync" are passed to file-systems as
 * flags. However, when a "rootflags=" kernel boot parameter is used, they may
 * be present in the options string. This function tries to deal with this
 * situation and parse standard options. Returns 0 if the option was not
 * recognized, and the corresponding integer flag if it was.
 *
 * UBIFS is only interested in the "sync" option, so do not check for anything
 * else.
 */
static int parse_standard_option(const char *option)
{
	ubifs_msg("parse %s", option);
	if (!strcmp(option, "sync"))
		return MS_SYNCHRONOUS;
	return 0;
}

/**
 * ubifs_parse_options - parse mount parameters.
 * @c: UBIFS file-system description object
 * @options: parameters to parse
 * @is_remount: non-zero if this is FS re-mount
 *
 * This function parses UBIFS mount options and returns zero in case success
 * and a negative error code in case of failure.
 */
static int ubifs_parse_options(struct ubifs_info *c, char *options,
			       int is_remount)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];

	if (!options)
		return 0;

	while ((p = strsep(&options, ","))) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		/*
		 * %Opt_fast_unmount and %Opt_norm_unmount options are ignored.
		 * We accept them in order to be backward-compatible. But this
		 * should be removed at some point.
		 */
		case Opt_fast_unmount:
			c->mount_opts.unmount_mode = 2;
			break;
		case Opt_norm_unmount:
			c->mount_opts.unmount_mode = 1;
			break;
		case Opt_bulk_read:
			c->mount_opts.bulk_read = 2;
			c->bulk_read = 1;
			break;
		case Opt_no_bulk_read:
			c->mount_opts.bulk_read = 1;
			c->bulk_read = 0;
			break;
		case Opt_chk_data_crc:
			c->mount_opts.chk_data_crc = 2;
			c->no_chk_data_crc = 0;
			break;
		case Opt_no_chk_data_crc:
			c->mount_opts.chk_data_crc = 1;
			c->no_chk_data_crc = 1;
			break;
		case Opt_override_compr:
		{
			char *name = match_strdup(&args[0]);

			if (!name)
				return -ENOMEM;
			if (!strcmp(name, "none"))
				c->mount_opts.compr_type = UBIFS_COMPR_NONE;
			else if (!strcmp(name, "lzo"))
				c->mount_opts.compr_type = UBIFS_COMPR_LZO;
			else if (!strcmp(name, "zlib"))
				c->mount_opts.compr_type = UBIFS_COMPR_ZLIB;
			else {
				ubifs_err("unknown compressor \"%s\"", name);
				kfree(name);
				return -EINVAL;
			}
			kfree(name);
			c->mount_opts.override_compr = 1;
			c->default_compr = c->mount_opts.compr_type;
			break;
		}
		default:
		{
			unsigned long flag;
			struct super_block *sb = c->vfs_sb;

			flag = parse_standard_option(p);
			if (!flag) {
				ubifs_err("unrecognized mount option \"%s\" or missing value",
					  p);
				return -EINVAL;
			}
			sb->s_flags |= flag;
			break;
		}
		}
	}

	return 0;
}

/**
 * destroy_journal - destroy journal data structures.
 * @c: UBIFS file-system description object
 *
 * This function destroys journal data structures including those that may have
 * been created by recovery functions.
 */
static void destroy_journal(struct ubifs_info *c)
{
	while (!list_empty(&c->unclean_leb_list)) {
		struct ubifs_unclean_leb *ucleb;

		ucleb = list_entry(c->unclean_leb_list.next,
				   struct ubifs_unclean_leb, list);
		list_del(&ucleb->list);
		kfree(ucleb);
	}
	while (!list_empty(&c->old_buds)) {
		struct ubifs_bud *bud;

		bud = list_entry(c->old_buds.next, struct ubifs_bud, list);
		list_del(&bud->list);
		kfree(bud);
	}
	ubifs_destroy_idx_gc(c);
	ubifs_destroy_size_tree(c);
	ubifs_tnc_close(c);
	free_buds(c);
}

/**
 * bu_init - initialize bulk-read information.
 * @c: UBIFS file-system description object
 */
static void bu_init(struct ubifs_info *c)
{
	ubifs_assert(c->bulk_read == 1);

	if (c->bu.buf)
		return; /* Already initialized */

again:
	c->bu.buf = kmalloc(c->max_bu_buf_len, GFP_KERNEL | __GFP_NOWARN);
	if (!c->bu.buf) {
		if (c->max_bu_buf_len > UBIFS_KMALLOC_OK) {
			c->max_bu_buf_len = UBIFS_KMALLOC_OK;
			goto again;
		}

		/* Just disable bulk-read */
		ubifs_warn("cannot allocate %d bytes of memory for bulk-read, disabling it",
			   c->max_bu_buf_len);
		c->mount_opts.bulk_read = 1;
		c->bulk_read = 0;
		return;
	}
}

/**
 * check_free_space - check if there is enough free space to mount.
 * @c: UBIFS file-system description object
 *
 * This function makes sure UBIFS has enough free space to be mounted in
 * read/write mode. UBIFS must always have some free space to allow deletions.
 */
static int check_free_space(struct ubifs_info *c)
{
	ubifs_assert(c->dark_wm > 0);
	if (c->lst.total_free + c->lst.total_dirty < c->dark_wm) {
		ubifs_err("insufficient free space to mount in R/W mode");
		ubifs_dump_budg(c, &c->bi);
		ubifs_dump_lprops(c);
		return -ENOSPC;
	}
	return 0;
}

/**
 * mount_ubifs - mount UBIFS file-system.
 * @c: UBIFS file-system description object
 *
 * This function mounts UBIFS file system. Returns zero in case of success and
 * a negative error code in case of failure.
 */
static int mount_ubifs(struct ubifs_info *c)
{
	int err;
	long long x, y;
	size_t sz;

	c->ro_mount = !!(c->vfs_sb->s_flags & MS_RDONLY);
	/* Suppress error messages while probing if MS_SILENT is set */
	c->probing = !!(c->vfs_sb->s_flags & MS_SILENT);

	err = init_constants_early(c);
	if (err)
		return err;

	err = ubifs_debugging_init(c);
	if (err)
		return err;

	err = check_volume_empty(c);
	if (err)
		goto out_free;

	if (c->empty && (c->ro_mount || c->ro_media)) {
		/*
		 * This UBI volume is empty, and read-only, or the file system
		 * is mounted read-only - we cannot format it.
		 */
		ubifs_err("can't format empty UBI volume: read-only %s",
			  c->ro_media ? "UBI volume" : "mount");
		err = -EROFS;
		goto out_free;
	}

	if (c->ro_media && !c->ro_mount) {
		ubifs_err("cannot mount read-write - read-only media");
		err = -EROFS;
		goto out_free;
	}

	/*
	 * The requirement for the buffer is that it should fit indexing B-tree
	 * height amount of integers. We assume the height if the TNC tree will
	 * never exceed 64.
	 */
	err = -ENOMEM;
	c->bottom_up_buf = kmalloc(BOTTOM_UP_HEIGHT * sizeof(int), GFP_KERNEL);
	if (!c->bottom_up_buf)
		goto out_free;

	c->sbuf = vmalloc(c->leb_size);
	if (!c->sbuf)
		goto out_free;

	if (!c->ro_mount) {
		c->ileb_buf = vmalloc(c->leb_size);
		if (!c->ileb_buf)
			goto out_free;
	}

	if (c->bulk_read == 1)
		bu_init(c);

	if (!c->ro_mount) {
		c->write_reserve_buf = kmalloc(COMPRESSED_DATA_NODE_BUF_SZ,
					       GFP_KERNEL);
		if (!c->write_reserve_buf)
			goto out_free;
	}

	c->mounting = 1;

	err = ubifs_read_superblock(c);
	if (err)
		goto out_free;

	c->probing = 0;

	/*
	 * Make sure the compressor which is set as default in the superblock
	 * or overridden by mount options is actually compiled in.
	 */
	if (!ubifs_compr_present(c->default_compr)) {
		ubifs_err("'compressor \"%s\" is not compiled in",
			  ubifs_compr_name(c->default_compr));
		err = -ENOTSUPP;
		goto out_free;
	}

	err = init_constants_sb(c);
	if (err)
		goto out_free;

	sz = ALIGN(c->max_idx_node_sz, c->min_io_size);
	sz = ALIGN(sz + c->max_idx_node_sz, c->min_io_size);
	c->cbuf = kmalloc(sz, GFP_NOFS);
	if (!c->cbuf) {
		err = -ENOMEM;
		goto out_free;
	}

	err = alloc_wbufs(c);
	if (err)
		goto out_cbuf;

	sprintf(c->bgt_name, BGT_NAME_PATTERN, c->vi.ubi_num, c->vi.vol_id);
	if (!c->ro_mount) {
		/* Create background thread */
		c->bgt = kthread_create(ubifs_bg_thread, c, "%s", c->bgt_name);
		if (IS_ERR(c->bgt)) {
			err = PTR_ERR(c->bgt);
			c->bgt = NULL;
			ubifs_err("cannot spawn \"%s\", error %d",
				  c->bgt_name, err);
			goto out_wbufs;
		}
		wake_up_process(c->bgt);
	}

	err = ubifs_read_master(c);
	if (err)
		goto out_master;

	init_constants_master(c);

	if ((c->mst_node->flags & cpu_to_le32(UBIFS_MST_DIRTY)) != 0) {
		ubifs_msg("recovery needed");
		c->need_recovery = 1;
	}

	if (c->need_recovery && !c->ro_mount) {
		err = ubifs_recover_inl_heads(c, c->sbuf);
		if (err)
			goto out_master;
	}

	err = ubifs_lpt_init(c, 1, !c->ro_mount);
	if (err)
		goto out_master;

	if (!c->ro_mount && c->space_fixup) {
		err = ubifs_fixup_free_space(c);
		if (err)
			goto out_lpt;
	}

	if (!c->ro_mount) {
		/*
		 * Set the "dirty" flag so that if we reboot uncleanly we
		 * will notice this immediately on the next mount.
		 */
		c->mst_node->flags |= cpu_to_le32(UBIFS_MST_DIRTY);
		err = ubifs_write_master(c);
		if (err)
			goto out_lpt;
	}

	err = dbg_check_idx_size(c, c->bi.old_idx_sz);
	if (err)
		goto out_lpt;

	err = ubifs_replay_journal(c);
	if (err)
		goto out_journal;

	/* Calculate 'min_idx_lebs' after journal replay */
	c->bi.min_idx_lebs = ubifs_calc_min_idx_lebs(c);

	err = ubifs_mount_orphans(c, c->need_recovery, c->ro_mount);
	if (err)
		goto out_orphans;

	if (!c->ro_mount) {
		int lnum;

		err = check_free_space(c);
		if (err)
			goto out_orphans;

		/* Check for enough log space */
		lnum = c->lhead_lnum + 1;
		if (lnum >= UBIFS_LOG_LNUM + c->log_lebs)
			lnum = UBIFS_LOG_LNUM;
		if (lnum == c->ltail_lnum) {
			err = ubifs_consolidate_log(c);
			if (err)
				goto out_orphans;
		}

		if (c->need_recovery) {
			err = ubifs_recover_size(c);
			if (err)
				goto out_orphans;
			err = ubifs_rcvry_gc_commit(c);
			if (err)
				goto out_orphans;
		} else {
			err = take_gc_lnum(c);
			if (err)
				goto out_orphans;

			/*
			 * GC LEB may contain garbage if there was an unclean
			 * reboot, and it should be un-mapped.
			 */
			err = ubifs_leb_unmap(c, c->gc_lnum);
			if (err)
				goto out_orphans;
		}

		err = dbg_check_lprops(c);
		if (err)
			goto out_orphans;
	} else if (c->need_recovery) {
		err = ubifs_recover_size(c);
		if (err)
			goto out_orphans;
	} else {
		/*
		 * Even if we mount read-only, we have to set space in GC LEB
		 * to proper value because this affects UBIFS free space
		 * reporting. We do not want to have a situation when
		 * re-mounting from R/O to R/W changes amount of free space.
		 */
		err = take_gc_lnum(c);
		if (err)
			goto out_orphans;
	}

	spin_lock(&ubifs_infos_lock);
	list_add_tail(&c->infos_list, &ubifs_infos);
	spin_unlock(&ubifs_infos_lock);

	if (c->need_recovery) {
		if (c->ro_mount)
			ubifs_msg("recovery deferred");
		else {
			c->need_recovery = 0;
			ubifs_msg("recovery completed");
			/*
			 * GC LEB has to be empty and taken at this point. But
			 * the journal head LEBs may also be accounted as
			 * "empty taken" if they are empty.
			 */
			ubifs_assert(c->lst.taken_empty_lebs > 0);
		}
	} else
		ubifs_assert(c->lst.taken_empty_lebs > 0);

	err = dbg_check_filesystem(c);
	if (err)
		goto out_infos;

	err = dbg_debugfs_init_fs(c);
	if (err)
		goto out_infos;

	c->mounting = 0;

	ubifs_msg("mounted UBI device %d, volume %d, name \"%s\"%s",
		  c->vi.ubi_num, c->vi.vol_id, c->vi.name,
		  c->ro_mount ? ", R/O mode" : "");
	x = (long long)c->main_lebs * c->leb_size;
	y = (long long)c->log_lebs * c->leb_size + c->max_bud_bytes;
	ubifs_msg("LEB size: %d bytes (%d KiB), min./max. I/O unit sizes: %d bytes/%d bytes",
		  c->leb_size, c->leb_size >> 10, c->min_io_size,
		  c->max_write_size);
	ubifs_msg("FS size: %lld bytes (%lld MiB, %d LEBs), journal size %lld bytes (%lld MiB, %d LEBs)",
		  x, x >> 20, c->main_lebs,
		  y, y >> 20, c->log_lebs + c->max_bud_cnt);
	ubifs_msg("reserved for root: %llu bytes (%llu KiB)",
		  c->report_rp_size, c->report_rp_size >> 10);
	ubifs_msg("media format: w%d/r%d (latest is w%d/r%d), UUID %pUB%s",
		  c->fmt_version, c->ro_compat_version,
		  UBIFS_FORMAT_VERSION, UBIFS_RO_COMPAT_VERSION, c->uuid,
		  c->big_lpt ? ", big LPT model" : ", small LPT model");

	dbg_gen("default compressor:  %s", ubifs_compr_name(c->default_compr));
	dbg_gen("data journal heads:  %d",
		c->jhead_cnt - NONDATA_JHEADS_CNT);
	dbg_gen("log LEBs:            %d (%d - %d)",
		c->log_lebs, UBIFS_LOG_LNUM, c->log_last);
	dbg_gen("LPT area LEBs:       %d (%d - %d)",
		c->lpt_lebs, c->lpt_first, c->lpt_last);
	dbg_gen("orphan area LEBs:    %d (%d - %d)",
		c->orph_lebs, c->orph_first, c->orph_last);
	dbg_gen("main area LEBs:      %d (%d - %d)",
		c->main_lebs, c->main_first, c->leb_cnt - 1);
	dbg_gen("index LEBs:          %d", c->lst.idx_lebs);
	dbg_gen("total index bytes:   %lld (%lld KiB, %lld MiB)",
		c->bi.old_idx_sz, c->bi.old_idx_sz >> 10,
		c->bi.old_idx_sz >> 20);
	dbg_gen("key hash type:       %d", c->key_hash_type);
	dbg_gen("tree fanout:         %d", c->fanout);
	dbg_gen("reserved GC LEB:     %d", c->gc_lnum);
	dbg_gen("max. znode size      %d", c->max_znode_sz);
	dbg_gen("max. index node size %d", c->max_idx_node_sz);
	dbg_gen("node sizes:          data %zu, inode %zu, dentry %zu",
		UBIFS_DATA_NODE_SZ, UBIFS_INO_NODE_SZ, UBIFS_DENT_NODE_SZ);
	dbg_gen("node sizes:          trun %zu, sb %zu, master %zu",
		UBIFS_TRUN_NODE_SZ, UBIFS_SB_NODE_SZ, UBIFS_MST_NODE_SZ);
	dbg_gen("node sizes:          ref %zu, cmt. start %zu, orph %zu",
		UBIFS_REF_NODE_SZ, UBIFS_CS_NODE_SZ, UBIFS_ORPH_NODE_SZ);
	dbg_gen("max. node sizes:     data %zu, inode %zu dentry %zu, idx %d",
		UBIFS_MAX_DATA_NODE_SZ, UBIFS_MAX_INO_NODE_SZ,
		UBIFS_MAX_DENT_NODE_SZ, ubifs_idx_node_sz(c, c->fanout));
	dbg_gen("dead watermark:      %d", c->dead_wm);
	dbg_gen("dark watermark:      %d", c->dark_wm);
	dbg_gen("LEB overhead:        %d", c->leb_overhead);
	x = (long long)c->main_lebs * c->dark_wm;
	dbg_gen("max. dark space:     %lld (%lld KiB, %lld MiB)",
		x, x >> 10, x >> 20);
	dbg_gen("maximum bud bytes:   %lld (%lld KiB, %lld MiB)",
		c->max_bud_bytes, c->max_bud_bytes >> 10,
		c->max_bud_bytes >> 20);
	dbg_gen("BG commit bud bytes: %lld (%lld KiB, %lld MiB)",
		c->bg_bud_bytes, c->bg_bud_bytes >> 10,
		c->bg_bud_bytes >> 20);
	dbg_gen("current bud bytes    %lld (%lld KiB, %lld MiB)",
		c->bud_bytes, c->bud_bytes >> 10, c->bud_bytes >> 20);
	dbg_gen("max. seq. number:    %llu", c->max_sqnum);
	dbg_gen("commit number:       %llu", c->cmt_no);

	return 0;

out_infos:
	spin_lock(&ubifs_infos_lock);
	list_del(&c->infos_list);
	spin_unlock(&ubifs_infos_lock);
out_orphans:
	free_orphans(c);
out_journal:
	destroy_journal(c);
out_lpt:
	ubifs_lpt_free(c, 0);
out_master:
	kfree(c->mst_node);
	kfree(c->rcvrd_mst_node);
	if (c->bgt)
		kthread_stop(c->bgt);
out_wbufs:
	free_wbufs(c);
out_cbuf:
	kfree(c->cbuf);
out_free:
	kfree(c->write_reserve_buf);
	kfree(c->bu.buf);
	vfree(c->ileb_buf);
	vfree(c->sbuf);
	kfree(c->bottom_up_buf);
	ubifs_debugging_exit(c);
	return err;
}

/**
 * ubifs_umount - un-mount UBIFS file-system.
 * @c: UBIFS file-system description object
 *
 * Note, this function is called to free allocated resourced when un-mounting,
 * as well as free resources when an error occurred while we were half way
 * through mounting (error path cleanup function). So it has to make sure the
 * resource was actually allocated before freeing it.
 */
static void ubifs_umount(struct ubifs_info *c)
{
	dbg_gen("un-mounting UBI device %d, volume %d", c->vi.ubi_num,
		c->vi.vol_id);

	dbg_debugfs_exit_fs(c);
	spin_lock(&ubifs_infos_lock);
	list_del(&c->infos_list);
	spin_unlock(&ubifs_infos_lock);

	if (c->bgt)
		kthread_stop(c->bgt);

	destroy_journal(c);
	free_wbufs(c);
	free_orphans(c);
	ubifs_lpt_free(c, 0);

	kfree(c->cbuf);
	kfree(c->rcvrd_mst_node);
	kfree(c->mst_node);
	kfree(c->write_reserve_buf);
	kfree(c->bu.buf);
	vfree(c->ileb_buf);
	vfree(c->sbuf);
	kfree(c->bottom_up_buf);
	ubifs_debugging_exit(c);
}

/**
 * ubifs_remount_rw - re-mount in read-write mode.
 * @c: UBIFS file-system description object
 *
 * UBIFS avoids allocating many unnecessary resources when mounted in read-only
 * mode. This function allocates the needed resources and re-mounts UBIFS in
 * read-write mode.
 */
static int ubifs_remount_rw(struct ubifs_info *c)
{
	int err, lnum;

	if (c->rw_incompat) {
		ubifs_err("the file-system is not R/W-compatible");
		ubifs_msg("on-flash format version is w%d/r%d, but software only supports up to version w%d/r%d",
			  c->fmt_version, c->ro_compat_version,
			  UBIFS_FORMAT_VERSION, UBIFS_RO_COMPAT_VERSION);
		return -EROFS;
	}

	mutex_lock(&c->umount_mutex);
	dbg_save_space_info(c);
	c->remounting_rw = 1;
	c->ro_mount = 0;

	if (c->space_fixup) {
		err = ubifs_fixup_free_space(c);
		if (err)
			goto out;
	}

	err = check_free_space(c);
	if (err)
		goto out;

	if (c->old_leb_cnt != c->leb_cnt) {
		struct ubifs_sb_node *sup;

		sup = ubifs_read_sb_node(c);
		if (IS_ERR(sup)) {
			err = PTR_ERR(sup);
			goto out;
		}
		sup->leb_cnt = cpu_to_le32(c->leb_cnt);
		err = ubifs_write_sb_node(c, sup);
		kfree(sup);
		if (err)
			goto out;
	}

	if (c->need_recovery) {
		ubifs_msg("completing deferred recovery");
		err = ubifs_write_rcvrd_mst_node(c);
		if (err)
			goto out;
		err = ubifs_recover_size(c);
		if (err)
			goto out;
		err = ubifs_clean_lebs(c, c->sbuf);
		if (err)
			goto out;
		err = ubifs_recover_inl_heads(c, c->sbuf);
		if (err)
			goto out;
	} else {
		/* A readonly mount is not allowed to have orphans */
		ubifs_assert(c->tot_orphans == 0);
		err = ubifs_clear_orphans(c);
		if (err)
			goto out;
	}

	if (!(c->mst_node->flags & cpu_to_le32(UBIFS_MST_DIRTY))) {
		c->mst_node->flags |= cpu_to_le32(UBIFS_MST_DIRTY);
		err = ubifs_write_master(c);
		if (err)
			goto out;
	}

	c->ileb_buf = vmalloc(c->leb_size);
	if (!c->ileb_buf) {
		err = -ENOMEM;
		goto out;
	}

	c->write_reserve_buf = kmalloc(COMPRESSED_DATA_NODE_BUF_SZ, GFP_KERNEL);
	if (!c->write_reserve_buf) {
		err = -ENOMEM;
		goto out;
	}

	err = ubifs_lpt_init(c, 0, 1);
	if (err)
		goto out;

	/* Create background thread */
	c->bgt = kthread_create(ubifs_bg_thread, c, "%s", c->bgt_name);
	if (IS_ERR(c->bgt)) {
		err = PTR_ERR(c->bgt);
		c->bgt = NULL;
		ubifs_err("cannot spawn \"%s\", error %d",
			  c->bgt_name, err);
		goto out;
	}
	wake_up_process(c->bgt);

	c->orph_buf = vmalloc(c->leb_size);
	if (!c->orph_buf) {
		err = -ENOMEM;
		goto out;
	}

	/* Check for enough log space */
	lnum = c->lhead_lnum + 1;
	if (lnum >= UBIFS_LOG_LNUM + c->log_lebs)
		lnum = UBIFS_LOG_LNUM;
	if (lnum == c->ltail_lnum) {
		err = ubifs_consolidate_log(c);
		if (err)
			goto out;
	}

	if (c->need_recovery)
		err = ubifs_rcvry_gc_commit(c);
	else
		err = ubifs_leb_unmap(c, c->gc_lnum);
	if (err)
		goto out;

	dbg_gen("re-mounted read-write");
	c->remounting_rw = 0;

	if (c->need_recovery) {
		c->need_recovery = 0;
		ubifs_msg("deferred recovery completed");
	} else {
		/*
		 * Do not run the debugging space check if the were doing
		 * recovery, because when we saved the information we had the
		 * file-system in a state where the TNC and lprops has been
		 * modified in memory, but all the I/O operations (including a
		 * commit) were deferred. So the file-system was in
		 * "non-committed" state. Now the file-system is in committed
		 * state, and of course the amount of free space will change
		 * because, for example, the old index size was imprecise.
		 */
		err = dbg_check_space_info(c);
	}

	mutex_unlock(&c->umount_mutex);
	return err;

out:
	c->ro_mount = 1;
	vfree(c->orph_buf);
	c->orph_buf = NULL;
	if (c->bgt) {
		kthread_stop(c->bgt);
		c->bgt = NULL;
	}
	free_wbufs(c);
	kfree(c->write_reserve_buf);
	c->write_reserve_buf = NULL;
	vfree(c->ileb_buf);
	c->ileb_buf = NULL;
	ubifs_lpt_free(c, 1);
	c->remounting_rw = 0;
	mutex_unlock(&c->umount_mutex);
	return err;
}

/**
 * ubifs_remount_ro - re-mount in read-only mode.
 * @c: UBIFS file-system description object
 *
 * We assume VFS has stopped writing. Possibly the background thread could be
 * running a commit, however kthread_stop will wait in that case.
 */
static void ubifs_remount_ro(struct ubifs_info *c)
{
	int i, err;

	ubifs_assert(!c->need_recovery);
	ubifs_assert(!c->ro_mount);

	mutex_lock(&c->umount_mutex);
	if (c->bgt) {
		kthread_stop(c->bgt);
		c->bgt = NULL;
	}

	dbg_save_space_info(c);

	for (i = 0; i < c->jhead_cnt; i++)
		ubifs_wbuf_sync(&c->jheads[i].wbuf);

	c->mst_node->flags &= ~cpu_to_le32(UBIFS_MST_DIRTY);
	c->mst_node->flags |= cpu_to_le32(UBIFS_MST_NO_ORPHS);
	c->mst_node->gc_lnum = cpu_to_le32(c->gc_lnum);
	err = ubifs_write_master(c);
	if (err)
		ubifs_ro_mode(c, err);

	vfree(c->orph_buf);
	c->orph_buf = NULL;
	kfree(c->write_reserve_buf);
	c->write_reserve_buf = NULL;
	vfree(c->ileb_buf);
	c->ileb_buf = NULL;
	ubifs_lpt_free(c, 1);
	c->ro_mount = 1;
	err = dbg_check_space_info(c);
	if (err)
		ubifs_ro_mode(c, err);
	mutex_unlock(&c->umount_mutex);
}

static void ubifs_put_super(struct super_block *sb)
{
	int i;
	struct ubifs_info *c = sb->s_fs_info;

	ubifs_msg("un-mount UBI device %d, volume %d", c->vi.ubi_num,
		  c->vi.vol_id);

	/*
	 * The following asserts are only valid if there has not been a failure
	 * of the media. For example, there will be dirty inodes if we failed
	 * to write them back because of I/O errors.
	 */
	if (!c->ro_error) {
		ubifs_assert(c->bi.idx_growth == 0);
		ubifs_assert(c->bi.dd_growth == 0);
		ubifs_assert(c->bi.data_growth == 0);
	}

	/*
	 * The 'c->umount_lock' prevents races between UBIFS memory shrinker
	 * and file system un-mount. Namely, it prevents the shrinker from
	 * picking this superblock for shrinking - it will be just skipped if
	 * the mutex is locked.
	 */
	mutex_lock(&c->umount_mutex);
	if (!c->ro_mount) {
		/*
		 * First of all kill the background thread to make sure it does
		 * not interfere with un-mounting and freeing resources.
		 */
		if (c->bgt) {
			kthread_stop(c->bgt);
			c->bgt = NULL;
		}

		/*
		 * On fatal errors c->ro_error is set to 1, in which case we do
		 * not write the master node.
		 */
		if (!c->ro_error) {
			int err;

			/* Synchronize write-buffers */
			for (i = 0; i < c->jhead_cnt; i++)
				ubifs_wbuf_sync(&c->jheads[i].wbuf);

			/*
			 * We are being cleanly unmounted which means the
			 * orphans were killed - indicate this in the master
			 * node. Also save the reserved GC LEB number.
			 */
			c->mst_node->flags &= ~cpu_to_le32(UBIFS_MST_DIRTY);
			c->mst_node->flags |= cpu_to_le32(UBIFS_MST_NO_ORPHS);
			c->mst_node->gc_lnum = cpu_to_le32(c->gc_lnum);
			err = ubifs_write_master(c);
			if (err)
				/*
				 * Recovery will attempt to fix the master area
				 * next mount, so we just print a message and
				 * continue to unmount normally.
				 */
				ubifs_err("failed to write master node, error %d",
					  err);
		} else {
			for (i = 0; i < c->jhead_cnt; i++)
				/* Make sure write-buffer timers are canceled */
				hrtimer_cancel(&c->jheads[i].wbuf.timer);
		}
	}

	ubifs_umount(c);
	bdi_destroy(&c->bdi);
	ubi_close_volume(c->ubi);
	mutex_unlock(&c->umount_mutex);
}

static int ubifs_remount_fs(struct super_block *sb, int *flags, char *data)
{
	int err;
	struct ubifs_info *c = sb->s_fs_info;

	sync_filesystem(sb);
	dbg_gen("old flags %#lx, new flags %#x", sb->s_flags, *flags);

	err = ubifs_parse_options(c, data, 1);
	if (err) {
		ubifs_err("invalid or unknown remount parameter");
		return err;
	}

	if (c->ro_mount && !(*flags & MS_RDONLY)) {
		if (c->ro_error) {
			ubifs_msg("cannot re-mount R/W due to prior errors");
			return -EROFS;
		}
		if (c->ro_media) {
			ubifs_msg("cannot re-mount R/W - UBI volume is R/O");
			return -EROFS;
		}
		err = ubifs_remount_rw(c);
		if (err)
			return err;
	} else if (!c->ro_mount && (*flags & MS_RDONLY)) {
		if (c->ro_error) {
			ubifs_msg("cannot re-mount R/O due to prior errors");
			return -EROFS;
		}
		ubifs_remount_ro(c);
	}

	if (c->bulk_read == 1)
		bu_init(c);
	else {
		dbg_gen("disable bulk-read");
		kfree(c->bu.buf);
		c->bu.buf = NULL;
	}

	ubifs_assert(c->lst.taken_empty_lebs > 0);
	return 0;
}

const struct super_operations ubifs_super_operations = {
	.alloc_inode   = ubifs_alloc_inode,
	.destroy_inode = ubifs_destroy_inode,
	.put_super     = ubifs_put_super,
	.write_inode   = ubifs_write_inode,
	.evict_inode   = ubifs_evict_inode,
	.statfs        = ubifs_statfs,
	.dirty_inode   = ubifs_dirty_inode,
	.remount_fs    = ubifs_remount_fs,
	.show_options  = ubifs_show_options,
	.sync_fs       = ubifs_sync_fs,
};

/**
 * open_ubi - parse UBI device name string and open the UBI device.
 * @name: UBI volume name
 * @mode: UBI volume open mode
 *
 * The primary method of mounting UBIFS is by specifying the UBI volume
 * character device node path. However, UBIFS may also be mounted withoug any
 * character device node using one of the following methods:
 *
 * o ubiX_Y    - mount UBI device number X, volume Y;
 * o ubiY      - mount UBI device number 0, volume Y;
 * o ubiX:NAME - mount UBI device X, volume with name NAME;
 * o ubi:NAME  - mount UBI device 0, volume with name NAME.
 *
 * Alternative '!' separator may be used instead of ':' (because some shells
 * like busybox may interpret ':' as an NFS host name separator). This function
 * returns UBI volume description object in case of success and a negative
 * error code in case of failure.
 */
static struct ubi_volume_desc *open_ubi(const char *name, int mode)
{
	struct ubi_volume_desc *ubi;
	int dev, vol;
	char *endptr;

	/* First, try to open using the device node path method */
	ubi = ubi_open_volume_path(name, mode);
	if (!IS_ERR(ubi))
		return ubi;

	/* Try the "nodev" method */
	if (name[0] != 'u' || name[1] != 'b' || name[2] != 'i')
		return ERR_PTR(-EINVAL);

	/* ubi:NAME method */
	if ((name[3] == ':' || name[3] == '!') && name[4] != '\0')
		return ubi_open_volume_nm(0, name + 4, mode);

	if (!isdigit(name[3]))
		return ERR_PTR(-EINVAL);

	dev = simple_strtoul(name + 3, &endptr, 0);

	/* ubiY method */
	if (*endptr == '\0')
		return ubi_open_volume(0, dev, mode);

	/* ubiX_Y method */
	if (*endptr == '_' && isdigit(endptr[1])) {
		vol = simple_strtoul(endptr + 1, &endptr, 0);
		if (*endptr != '\0')
			return ERR_PTR(-EINVAL);
		return ubi_open_volume(dev, vol, mode);
	}

	/* ubiX:NAME method */
	if ((*endptr == ':' || *endptr == '!') && endptr[1] != '\0')
		return ubi_open_volume_nm(dev, ++endptr, mode);

	return ERR_PTR(-EINVAL);
}

static struct ubifs_info *alloc_ubifs_info(struct ubi_volume_desc *ubi)
{
	struct ubifs_info *c;

	c = kzalloc(sizeof(struct ubifs_info), GFP_KERNEL);
	if (c) {
		spin_lock_init(&c->cnt_lock);
		spin_lock_init(&c->cs_lock);
		spin_lock_init(&c->buds_lock);
		spin_lock_init(&c->space_lock);
		spin_lock_init(&c->orphan_lock);
		init_rwsem(&c->commit_sem);
		mutex_init(&c->lp_mutex);
		mutex_init(&c->tnc_mutex);
		mutex_init(&c->log_mutex);
		mutex_init(&c->umount_mutex);
		mutex_init(&c->bu_mutex);
		mutex_init(&c->write_reserve_mutex);
		init_waitqueue_head(&c->cmt_wq);
		c->buds = RB_ROOT;
		c->old_idx = RB_ROOT;
		c->size_tree = RB_ROOT;
		c->orph_tree = RB_ROOT;
		INIT_LIST_HEAD(&c->infos_list);
		INIT_LIST_HEAD(&c->idx_gc);
		INIT_LIST_HEAD(&c->replay_list);
		INIT_LIST_HEAD(&c->replay_buds);
		INIT_LIST_HEAD(&c->uncat_list);
		INIT_LIST_HEAD(&c->empty_list);
		INIT_LIST_HEAD(&c->freeable_list);
		INIT_LIST_HEAD(&c->frdi_idx_list);
		INIT_LIST_HEAD(&c->unclean_leb_list);
		INIT_LIST_HEAD(&c->old_buds);
		INIT_LIST_HEAD(&c->orph_list);
		INIT_LIST_HEAD(&c->orph_new);
		c->no_chk_data_crc = 1;

		c->highest_inum = UBIFS_FIRST_INO;
		c->lhead_lnum = c->ltail_lnum = UBIFS_LOG_LNUM;

		ubi_get_volume_info(ubi, &c->vi);
		ubi_get_device_info(c->vi.ubi_num, &c->di);
	}
	return c;
}

static int ubifs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct ubifs_info *c = sb->s_fs_info;
	struct inode *root;
	int err;

	c->vfs_sb = sb;
	/* Re-open the UBI device in read-write mode */
	c->ubi = ubi_open_volume(c->vi.ubi_num, c->vi.vol_id, UBI_READWRITE);
	if (IS_ERR(c->ubi)) {
		err = PTR_ERR(c->ubi);
		goto out;
	}

	/*
	 * UBIFS provides 'backing_dev_info' in order to disable read-ahead. For
	 * UBIFS, I/O is not deferred, it is done immediately in readpage,
	 * which means the user would have to wait not just for their own I/O
	 * but the read-ahead I/O as well i.e. completely pointless.
	 *
	 * Read-ahead will be disabled because @c->bdi.ra_pages is 0.
	 */
	c->bdi.name = "ubifs",
	c->bdi.capabilities = 0;
	err  = bdi_init(&c->bdi);
	if (err)
		goto out_close;
	err = bdi_register(&c->bdi, NULL, "ubifs_%d_%d",
			   c->vi.ubi_num, c->vi.vol_id);
	if (err)
		goto out_bdi;

	err = ubifs_parse_options(c, data, 0);
	if (err)
		goto out_bdi;

	sb->s_bdi = &c->bdi;
	sb->s_fs_info = c;
	sb->s_magic = UBIFS_SUPER_MAGIC;
	sb->s_blocksize = UBIFS_BLOCK_SIZE;
	sb->s_blocksize_bits = UBIFS_BLOCK_SHIFT;
	sb->s_maxbytes = c->max_inode_sz = key_max_inode_size(c);
	if (c->max_inode_sz > MAX_LFS_FILESIZE)
		sb->s_maxbytes = c->max_inode_sz = MAX_LFS_FILESIZE;
	sb->s_op = &ubifs_super_operations;
	sb->s_xattr = ubifs_xattr_handlers;

	mutex_lock(&c->umount_mutex);
	err = mount_ubifs(c);
	if (err) {
		ubifs_assert(err < 0);
		goto out_unlock;
	}

	/* Read the root inode */
	root = ubifs_iget(sb, UBIFS_ROOT_INO);
	if (IS_ERR(root)) {
		err = PTR_ERR(root);
		goto out_umount;
	}

	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_umount;
	}

	mutex_unlock(&c->umount_mutex);
	return 0;

out_umount:
	ubifs_umount(c);
out_unlock:
	mutex_unlock(&c->umount_mutex);
out_bdi:
	bdi_destroy(&c->bdi);
out_close:
	ubi_close_volume(c->ubi);
out:
	return err;
}

static int sb_test(struct super_block *sb, void *data)
{
	struct ubifs_info *c1 = data;
	struct ubifs_info *c = sb->s_fs_info;

	return c->vi.cdev == c1->vi.cdev;
}

static int sb_set(struct super_block *sb, void *data)
{
	sb->s_fs_info = data;
	return set_anon_super(sb, NULL);
}

static struct dentry *ubifs_mount(struct file_system_type *fs_type, int flags,
			const char *name, void *data)
{
	struct ubi_volume_desc *ubi;
	struct ubifs_info *c;
	struct super_block *sb;
	int err;

	dbg_gen("name %s, flags %#x", name, flags);

	/*
	 * Get UBI device number and volume ID. Mount it read-only so far
	 * because this might be a new mount point, and UBI allows only one
	 * read-write user at a time.
	 */
	ubi = open_ubi(name, UBI_READONLY);
	if (IS_ERR(ubi)) {
		ubifs_err("cannot open \"%s\", error %d",
			  name, (int)PTR_ERR(ubi));
		return ERR_CAST(ubi);
	}

	c = alloc_ubifs_info(ubi);
	if (!c) {
		err = -ENOMEM;
		goto out_close;
	}

	dbg_gen("opened ubi%d_%d", c->vi.ubi_num, c->vi.vol_id);

	sb = sget(fs_type, sb_test, sb_set, flags, c);
	if (IS_ERR(sb)) {
		err = PTR_ERR(sb);
		kfree(c);
		goto out_close;
	}

	if (sb->s_root) {
		struct ubifs_info *c1 = sb->s_fs_info;
		kfree(c);
		/* A new mount point for already mounted UBIFS */
		dbg_gen("this ubi volume is already mounted");
		if (!!(flags & MS_RDONLY) != c1->ro_mount) {
			err = -EBUSY;
			goto out_deact;
		}
	} else {
		err = ubifs_fill_super(sb, data, flags & MS_SILENT ? 1 : 0);
		if (err)
			goto out_deact;
		/* We do not support atime */
		sb->s_flags |= MS_ACTIVE | MS_NOATIME;
	}

	/* 'fill_super()' opens ubi again so we must close it here */
	ubi_close_volume(ubi);

	return dget(sb->s_root);

out_deact:
	deactivate_locked_super(sb);
out_close:
	ubi_close_volume(ubi);
	return ERR_PTR(err);
}

static void kill_ubifs_super(struct super_block *s)
{
	struct ubifs_info *c = s->s_fs_info;
	kill_anon_super(s);
	kfree(c);
}

static struct file_system_type ubifs_fs_type = {
	.name    = "ubifs",
	.owner   = THIS_MODULE,
	.mount   = ubifs_mount,
	.kill_sb = kill_ubifs_super,
};
MODULE_ALIAS_FS("ubifs");

/*
 * Inode slab cache constructor.
 */
static void inode_slab_ctor(void *obj)
{
	struct ubifs_inode *ui = obj;
	inode_init_once(&ui->vfs_inode);
}

static int __init ubifs_init(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct ubifs_ch) != 24);

	/* Make sure node sizes are 8-byte aligned */
	BUILD_BUG_ON(UBIFS_CH_SZ        & 7);
	BUILD_BUG_ON(UBIFS_INO_NODE_SZ  & 7);
	BUILD_BUG_ON(UBIFS_DENT_NODE_SZ & 7);
	BUILD_BUG_ON(UBIFS_XENT_NODE_SZ & 7);
	BUILD_BUG_ON(UBIFS_DATA_NODE_SZ & 7);
	BUILD_BUG_ON(UBIFS_TRUN_NODE_SZ & 7);
	BUILD_BUG_ON(UBIFS_SB_NODE_SZ   & 7);
	BUILD_BUG_ON(UBIFS_MST_NODE_SZ  & 7);
	BUILD_BUG_ON(UBIFS_REF_NODE_SZ  & 7);
	BUILD_BUG_ON(UBIFS_CS_NODE_SZ   & 7);
	BUILD_BUG_ON(UBIFS_ORPH_NODE_SZ & 7);

	BUILD_BUG_ON(UBIFS_MAX_DENT_NODE_SZ & 7);
	BUILD_BUG_ON(UBIFS_MAX_XENT_NODE_SZ & 7);
	BUILD_BUG_ON(UBIFS_MAX_DATA_NODE_SZ & 7);
	BUILD_BUG_ON(UBIFS_MAX_INO_NODE_SZ  & 7);
	BUILD_BUG_ON(UBIFS_MAX_NODE_SZ      & 7);
	BUILD_BUG_ON(MIN_WRITE_SZ           & 7);

	/* Check min. node size */
	BUILD_BUG_ON(UBIFS_INO_NODE_SZ  < MIN_WRITE_SZ);
	BUILD_BUG_ON(UBIFS_DENT_NODE_SZ < MIN_WRITE_SZ);
	BUILD_BUG_ON(UBIFS_XENT_NODE_SZ < MIN_WRITE_SZ);
	BUILD_BUG_ON(UBIFS_TRUN_NODE_SZ < MIN_WRITE_SZ);

	BUILD_BUG_ON(UBIFS_MAX_DENT_NODE_SZ > UBIFS_MAX_NODE_SZ);
	BUILD_BUG_ON(UBIFS_MAX_XENT_NODE_SZ > UBIFS_MAX_NODE_SZ);
	BUILD_BUG_ON(UBIFS_MAX_DATA_NODE_SZ > UBIFS_MAX_NODE_SZ);
	BUILD_BUG_ON(UBIFS_MAX_INO_NODE_SZ  > UBIFS_MAX_NODE_SZ);

	/* Defined node sizes */
	BUILD_BUG_ON(UBIFS_SB_NODE_SZ  != 4096);
	BUILD_BUG_ON(UBIFS_MST_NODE_SZ != 512);
	BUILD_BUG_ON(UBIFS_INO_NODE_SZ != 160);
	BUILD_BUG_ON(UBIFS_REF_NODE_SZ != 64);

	/*
	 * We use 2 bit wide bit-fields to store compression type, which should
	 * be amended if more compressors are added. The bit-fields are:
	 * @compr_type in 'struct ubifs_inode', @default_compr in
	 * 'struct ubifs_info' and @compr_type in 'struct ubifs_mount_opts'.
	 */
	BUILD_BUG_ON(UBIFS_COMPR_TYPES_CNT > 4);

	/*
	 * We require that PAGE_CACHE_SIZE is greater-than-or-equal-to
	 * UBIFS_BLOCK_SIZE. It is assumed that both are powers of 2.
	 */
	if (PAGE_CACHE_SIZE < UBIFS_BLOCK_SIZE) {
		ubifs_err("VFS page cache size is %u bytes, but UBIFS requires at least 4096 bytes",
			  (unsigned int)PAGE_CACHE_SIZE);
		return -EINVAL;
	}

	ubifs_inode_slab = kmem_cache_create("ubifs_inode_slab",
				sizeof(struct ubifs_inode), 0,
				SLAB_MEM_SPREAD | SLAB_RECLAIM_ACCOUNT,
				&inode_slab_ctor);
	if (!ubifs_inode_slab)
		return -ENOMEM;

	register_shrinker(&ubifs_shrinker_info);

	err = ubifs_compressors_init();
	if (err)
		goto out_shrinker;

	err = dbg_debugfs_init();
	if (err)
		goto out_compr;

	err = register_filesystem(&ubifs_fs_type);
	if (err) {
		ubifs_err("cannot register file system, error %d", err);
		goto out_dbg;
	}
	return 0;

out_dbg:
	dbg_debugfs_exit();
out_compr:
	ubifs_compressors_exit();
out_shrinker:
	unregister_shrinker(&ubifs_shrinker_info);
	kmem_cache_destroy(ubifs_inode_slab);
	return err;
}
/* late_initcall to let compressors initialize first */
late_initcall(ubifs_init);

static void __exit ubifs_exit(void)
{
	ubifs_assert(list_empty(&ubifs_infos));
	ubifs_assert(atomic_long_read(&ubifs_clean_zn_cnt) == 0);

	dbg_debugfs_exit();
	ubifs_compressors_exit();
	unregister_shrinker(&ubifs_shrinker_info);

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(ubifs_inode_slab);
	unregister_filesystem(&ubifs_fs_type);
}
module_exit(ubifs_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(__stringify(UBIFS_VERSION));
MODULE_AUTHOR("Artem Bityutskiy, Adrian Hunter");
MODULE_DESCRIPTION("UBIFS - UBI File System");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/super.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file implements UBIFS superblock. The superblock is stored at the first
 * LEB of the volume and is never changed by UBIFS. Only user-space tools may
 * change it. The superblock node mostly contains geometry information.
 */

// #include "ubifs.h"
// #include <linux/slab.h>
#include <linux/random.h>
// #include <linux/math64.h>
#include "../../inc/__fss.h"

/*
 * Default journal size in logical eraseblocks as a percent of total
 * flash size.
 */
#define DEFAULT_JNL_PERCENT 5

/* Default maximum journal size in bytes */
#define DEFAULT_MAX_JNL (32*1024*1024)

/* Default indexing tree fanout */
#define DEFAULT_FANOUT 8

/* Default number of data journal heads */
#define DEFAULT_JHEADS_CNT 1

/* Default positions of different LEBs in the main area */
#define DEFAULT_IDX_LEB  0
#define DEFAULT_DATA_LEB 1
#define DEFAULT_GC_LEB   2

/* Default number of LEB numbers in LPT's save table */
#define DEFAULT_LSAVE_CNT 256

/* Default reserved pool size as a percent of maximum free space */
#define DEFAULT_RP_PERCENT 5

/* The default maximum size of reserved pool in bytes */
#define DEFAULT_MAX_RP_SIZE (5*1024*1024)

/* Default time granularity in nanoseconds */
#define DEFAULT_TIME_GRAN 1000000000

/**
 * create_default_filesystem - format empty UBI volume.
 * @c: UBIFS file-system description object
 *
 * This function creates default empty file-system. Returns zero in case of
 * success and a negative error code in case of failure.
 */
static int create_default_filesystem(struct ubifs_info *c)
{
	struct ubifs_sb_node *sup;
	struct ubifs_mst_node *mst;
	struct ubifs_idx_node *idx;
	struct ubifs_branch *br;
	struct ubifs_ino_node *ino;
	struct ubifs_cs_node *cs;
	union ubifs_key key;
	int err, tmp, jnl_lebs, log_lebs, max_buds, main_lebs, main_first;
	int lpt_lebs, lpt_first, orph_lebs, big_lpt, ino_waste, sup_flags = 0;
	int min_leb_cnt = UBIFS_MIN_LEB_CNT;
	long long tmp64, main_bytes;
	__le64 tmp_le64;

	/* Some functions called from here depend on the @c->key_len filed */
	c->key_len = UBIFS_SK_LEN;

	/*
	 * First of all, we have to calculate default file-system geometry -
	 * log size, journal size, etc.
	 */
	if (c->leb_cnt < 0x7FFFFFFF / DEFAULT_JNL_PERCENT)
		/* We can first multiply then divide and have no overflow */
		jnl_lebs = c->leb_cnt * DEFAULT_JNL_PERCENT / 100;
	else
		jnl_lebs = (c->leb_cnt / 100) * DEFAULT_JNL_PERCENT;

	if (jnl_lebs < UBIFS_MIN_JNL_LEBS)
		jnl_lebs = UBIFS_MIN_JNL_LEBS;
	if (jnl_lebs * c->leb_size > DEFAULT_MAX_JNL)
		jnl_lebs = DEFAULT_MAX_JNL / c->leb_size;

	/*
	 * The log should be large enough to fit reference nodes for all bud
	 * LEBs. Because buds do not have to start from the beginning of LEBs
	 * (half of the LEB may contain committed data), the log should
	 * generally be larger, make it twice as large.
	 */
	tmp = 2 * (c->ref_node_alsz * jnl_lebs) + c->leb_size - 1;
	log_lebs = tmp / c->leb_size;
	/* Plus one LEB reserved for commit */
	log_lebs += 1;
	if (c->leb_cnt - min_leb_cnt > 8) {
		/* And some extra space to allow writes while committing */
		log_lebs += 1;
		min_leb_cnt += 1;
	}

	max_buds = jnl_lebs - log_lebs;
	if (max_buds < UBIFS_MIN_BUD_LEBS)
		max_buds = UBIFS_MIN_BUD_LEBS;

	/*
	 * Orphan nodes are stored in a separate area. One node can store a lot
	 * of orphan inode numbers, but when new orphan comes we just add a new
	 * orphan node. At some point the nodes are consolidated into one
	 * orphan node.
	 */
	orph_lebs = UBIFS_MIN_ORPH_LEBS;
	if (c->leb_cnt - min_leb_cnt > 1)
		/*
		 * For debugging purposes it is better to have at least 2
		 * orphan LEBs, because the orphan subsystem would need to do
		 * consolidations and would be stressed more.
		 */
		orph_lebs += 1;

	main_lebs = c->leb_cnt - UBIFS_SB_LEBS - UBIFS_MST_LEBS - log_lebs;
	main_lebs -= orph_lebs;

	lpt_first = UBIFS_LOG_LNUM + log_lebs;
	c->lsave_cnt = DEFAULT_LSAVE_CNT;
	c->max_leb_cnt = c->leb_cnt;
	err = ubifs_create_dflt_lpt(c, &main_lebs, lpt_first, &lpt_lebs,
				    &big_lpt);
	if (err)
		return err;

	dbg_gen("LEB Properties Tree created (LEBs %d-%d)", lpt_first,
		lpt_first + lpt_lebs - 1);

	main_first = c->leb_cnt - main_lebs;

	/* Create default superblock */
	tmp = ALIGN(UBIFS_SB_NODE_SZ, c->min_io_size);
	sup = kzalloc(tmp, GFP_KERNEL);
	if (!sup)
		return -ENOMEM;

	tmp64 = (long long)max_buds * c->leb_size;
	if (big_lpt)
		sup_flags |= UBIFS_FLG_BIGLPT;

	sup->ch.node_type  = UBIFS_SB_NODE;
	sup->key_hash      = UBIFS_KEY_HASH_R5;
	sup->flags         = cpu_to_le32(sup_flags);
	sup->min_io_size   = cpu_to_le32(c->min_io_size);
	sup->leb_size      = cpu_to_le32(c->leb_size);
	sup->leb_cnt       = cpu_to_le32(c->leb_cnt);
	sup->max_leb_cnt   = cpu_to_le32(c->max_leb_cnt);
	sup->max_bud_bytes = cpu_to_le64(tmp64);
	sup->log_lebs      = cpu_to_le32(log_lebs);
	sup->lpt_lebs      = cpu_to_le32(lpt_lebs);
	sup->orph_lebs     = cpu_to_le32(orph_lebs);
	sup->jhead_cnt     = cpu_to_le32(DEFAULT_JHEADS_CNT);
	sup->fanout        = cpu_to_le32(DEFAULT_FANOUT);
	sup->lsave_cnt     = cpu_to_le32(c->lsave_cnt);
	sup->fmt_version   = cpu_to_le32(UBIFS_FORMAT_VERSION);
	sup->time_gran     = cpu_to_le32(DEFAULT_TIME_GRAN);
	if (c->mount_opts.override_compr)
		sup->default_compr = cpu_to_le16(c->mount_opts.compr_type);
	else
		sup->default_compr = cpu_to_le16(UBIFS_COMPR_LZO);

	generate_random_uuid(sup->uuid);

	main_bytes = (long long)main_lebs * c->leb_size;
	tmp64 = div_u64(main_bytes * DEFAULT_RP_PERCENT, 100);
	if (tmp64 > DEFAULT_MAX_RP_SIZE)
		tmp64 = DEFAULT_MAX_RP_SIZE;
	sup->rp_size = cpu_to_le64(tmp64);
	sup->ro_compat_version = cpu_to_le32(UBIFS_RO_COMPAT_VERSION);

	err = ubifs_write_node(c, sup, UBIFS_SB_NODE_SZ, 0, 0);
	kfree(sup);
	if (err)
		return err;

	dbg_gen("default superblock created at LEB 0:0");

	/* Create default master node */
	mst = kzalloc(c->mst_node_alsz, GFP_KERNEL);
	if (!mst)
		return -ENOMEM;

	mst->ch.node_type = UBIFS_MST_NODE;
	mst->log_lnum     = cpu_to_le32(UBIFS_LOG_LNUM);
	mst->highest_inum = cpu_to_le64(UBIFS_FIRST_INO);
	mst->cmt_no       = 0;
	mst->root_lnum    = cpu_to_le32(main_first + DEFAULT_IDX_LEB);
	mst->root_offs    = 0;
	tmp = ubifs_idx_node_sz(c, 1);
	mst->root_len     = cpu_to_le32(tmp);
	mst->gc_lnum      = cpu_to_le32(main_first + DEFAULT_GC_LEB);
	mst->ihead_lnum   = cpu_to_le32(main_first + DEFAULT_IDX_LEB);
	mst->ihead_offs   = cpu_to_le32(ALIGN(tmp, c->min_io_size));
	mst->index_size   = cpu_to_le64(ALIGN(tmp, 8));
	mst->lpt_lnum     = cpu_to_le32(c->lpt_lnum);
	mst->lpt_offs     = cpu_to_le32(c->lpt_offs);
	mst->nhead_lnum   = cpu_to_le32(c->nhead_lnum);
	mst->nhead_offs   = cpu_to_le32(c->nhead_offs);
	mst->ltab_lnum    = cpu_to_le32(c->ltab_lnum);
	mst->ltab_offs    = cpu_to_le32(c->ltab_offs);
	mst->lsave_lnum   = cpu_to_le32(c->lsave_lnum);
	mst->lsave_offs   = cpu_to_le32(c->lsave_offs);
	mst->lscan_lnum   = cpu_to_le32(main_first);
	mst->empty_lebs   = cpu_to_le32(main_lebs - 2);
	mst->idx_lebs     = cpu_to_le32(1);
	mst->leb_cnt      = cpu_to_le32(c->leb_cnt);

	/* Calculate lprops statistics */
	tmp64 = main_bytes;
	tmp64 -= ALIGN(ubifs_idx_node_sz(c, 1), c->min_io_size);
	tmp64 -= ALIGN(UBIFS_INO_NODE_SZ, c->min_io_size);
	mst->total_free = cpu_to_le64(tmp64);

	tmp64 = ALIGN(ubifs_idx_node_sz(c, 1), c->min_io_size);
	ino_waste = ALIGN(UBIFS_INO_NODE_SZ, c->min_io_size) -
			  UBIFS_INO_NODE_SZ;
	tmp64 += ino_waste;
	tmp64 -= ALIGN(ubifs_idx_node_sz(c, 1), 8);
	mst->total_dirty = cpu_to_le64(tmp64);

	/*  The indexing LEB does not contribute to dark space */
	tmp64 = ((long long)(c->main_lebs - 1) * c->dark_wm);
	mst->total_dark = cpu_to_le64(tmp64);

	mst->total_used = cpu_to_le64(UBIFS_INO_NODE_SZ);

	err = ubifs_write_node(c, mst, UBIFS_MST_NODE_SZ, UBIFS_MST_LNUM, 0);
	if (err) {
		kfree(mst);
		return err;
	}
	err = ubifs_write_node(c, mst, UBIFS_MST_NODE_SZ, UBIFS_MST_LNUM + 1,
			       0);
	kfree(mst);
	if (err)
		return err;

	dbg_gen("default master node created at LEB %d:0", UBIFS_MST_LNUM);

	/* Create the root indexing node */
	tmp = ubifs_idx_node_sz(c, 1);
	idx = kzalloc(ALIGN(tmp, c->min_io_size), GFP_KERNEL);
	if (!idx)
		return -ENOMEM;

	c->key_fmt = UBIFS_SIMPLE_KEY_FMT;
	c->key_hash = key_r5_hash;

	idx->ch.node_type = UBIFS_IDX_NODE;
	idx->child_cnt = cpu_to_le16(1);
	ino_key_init(c, &key, UBIFS_ROOT_INO);
	br = ubifs_idx_branch(c, idx, 0);
	key_write_idx(c, &key, &br->key);
	br->lnum = cpu_to_le32(main_first + DEFAULT_DATA_LEB);
	br->len  = cpu_to_le32(UBIFS_INO_NODE_SZ);
	err = ubifs_write_node(c, idx, tmp, main_first + DEFAULT_IDX_LEB, 0);
	kfree(idx);
	if (err)
		return err;

	dbg_gen("default root indexing node created LEB %d:0",
		main_first + DEFAULT_IDX_LEB);

	/* Create default root inode */
	tmp = ALIGN(UBIFS_INO_NODE_SZ, c->min_io_size);
	ino = kzalloc(tmp, GFP_KERNEL);
	if (!ino)
		return -ENOMEM;

	ino_key_init_flash(c, &ino->key, UBIFS_ROOT_INO);
	ino->ch.node_type = UBIFS_INO_NODE;
	ino->creat_sqnum = cpu_to_le64(++c->max_sqnum);
	ino->nlink = cpu_to_le32(2);
	tmp_le64 = cpu_to_le64(CURRENT_TIME_SEC.tv_sec);
	ino->atime_sec   = tmp_le64;
	ino->ctime_sec   = tmp_le64;
	ino->mtime_sec   = tmp_le64;
	ino->atime_nsec  = 0;
	ino->ctime_nsec  = 0;
	ino->mtime_nsec  = 0;
	ino->mode = cpu_to_le32(S_IFDIR | S_IRUGO | S_IWUSR | S_IXUGO);
	ino->size = cpu_to_le64(UBIFS_INO_NODE_SZ);

	/* Set compression enabled by default */
	ino->flags = cpu_to_le32(UBIFS_COMPR_FL);

	err = ubifs_write_node(c, ino, UBIFS_INO_NODE_SZ,
			       main_first + DEFAULT_DATA_LEB, 0);
	kfree(ino);
	if (err)
		return err;

	dbg_gen("root inode created at LEB %d:0",
		main_first + DEFAULT_DATA_LEB);

	/*
	 * The first node in the log has to be the commit start node. This is
	 * always the case during normal file-system operation. Write a fake
	 * commit start node to the log.
	 */
	tmp = ALIGN(UBIFS_CS_NODE_SZ, c->min_io_size);
	cs = kzalloc(tmp, GFP_KERNEL);
	if (!cs)
		return -ENOMEM;

	cs->ch.node_type = UBIFS_CS_NODE;
	err = ubifs_write_node(c, cs, UBIFS_CS_NODE_SZ, UBIFS_LOG_LNUM, 0);
	kfree(cs);
	if (err)
		return err;

	ubifs_msg("default file-system created");
	return 0;
}

/**
 * validate_sb - validate superblock node.
 * @c: UBIFS file-system description object
 * @sup: superblock node
 *
 * This function validates superblock node @sup. Since most of data was read
 * from the superblock and stored in @c, the function validates fields in @c
 * instead. Returns zero in case of success and %-EINVAL in case of validation
 * failure.
 */
static int validate_sb(struct ubifs_info *c, struct ubifs_sb_node *sup)
{
	long long max_bytes;
	int err = 1, min_leb_cnt;

	if (!c->key_hash) {
		err = 2;
		goto failed;
	}

	if (sup->key_fmt != UBIFS_SIMPLE_KEY_FMT) {
		err = 3;
		goto failed;
	}

	if (le32_to_cpu(sup->min_io_size) != c->min_io_size) {
		ubifs_err("min. I/O unit mismatch: %d in superblock, %d real",
			  le32_to_cpu(sup->min_io_size), c->min_io_size);
		goto failed;
	}

	if (le32_to_cpu(sup->leb_size) != c->leb_size) {
		ubifs_err("LEB size mismatch: %d in superblock, %d real",
			  le32_to_cpu(sup->leb_size), c->leb_size);
		goto failed;
	}

	if (c->log_lebs < UBIFS_MIN_LOG_LEBS ||
	    c->lpt_lebs < UBIFS_MIN_LPT_LEBS ||
	    c->orph_lebs < UBIFS_MIN_ORPH_LEBS ||
	    c->main_lebs < UBIFS_MIN_MAIN_LEBS) {
		err = 4;
		goto failed;
	}

	/*
	 * Calculate minimum allowed amount of main area LEBs. This is very
	 * similar to %UBIFS_MIN_LEB_CNT, but we take into account real what we
	 * have just read from the superblock.
	 */
	min_leb_cnt = UBIFS_SB_LEBS + UBIFS_MST_LEBS + c->log_lebs;
	min_leb_cnt += c->lpt_lebs + c->orph_lebs + c->jhead_cnt + 6;

	if (c->leb_cnt < min_leb_cnt || c->leb_cnt > c->vi.size) {
		ubifs_err("bad LEB count: %d in superblock, %d on UBI volume, %d minimum required",
			  c->leb_cnt, c->vi.size, min_leb_cnt);
		goto failed;
	}

	if (c->max_leb_cnt < c->leb_cnt) {
		ubifs_err("max. LEB count %d less than LEB count %d",
			  c->max_leb_cnt, c->leb_cnt);
		goto failed;
	}

	if (c->main_lebs < UBIFS_MIN_MAIN_LEBS) {
		ubifs_err("too few main LEBs count %d, must be at least %d",
			  c->main_lebs, UBIFS_MIN_MAIN_LEBS);
		goto failed;
	}

	max_bytes = (long long)c->leb_size * UBIFS_MIN_BUD_LEBS;
	if (c->max_bud_bytes < max_bytes) {
		ubifs_err("too small journal (%lld bytes), must be at least %lld bytes",
			  c->max_bud_bytes, max_bytes);
		goto failed;
	}

	max_bytes = (long long)c->leb_size * c->main_lebs;
	if (c->max_bud_bytes > max_bytes) {
		ubifs_err("too large journal size (%lld bytes), only %lld bytes available in the main area",
			  c->max_bud_bytes, max_bytes);
		goto failed;
	}

	if (c->jhead_cnt < NONDATA_JHEADS_CNT + 1 ||
	    c->jhead_cnt > NONDATA_JHEADS_CNT + UBIFS_MAX_JHEADS) {
		err = 9;
		goto failed;
	}

	if (c->fanout < UBIFS_MIN_FANOUT ||
	    ubifs_idx_node_sz(c, c->fanout) > c->leb_size) {
		err = 10;
		goto failed;
	}

	if (c->lsave_cnt < 0 || (c->lsave_cnt > DEFAULT_LSAVE_CNT &&
	    c->lsave_cnt > c->max_leb_cnt - UBIFS_SB_LEBS - UBIFS_MST_LEBS -
	    c->log_lebs - c->lpt_lebs - c->orph_lebs)) {
		err = 11;
		goto failed;
	}

	if (UBIFS_SB_LEBS + UBIFS_MST_LEBS + c->log_lebs + c->lpt_lebs +
	    c->orph_lebs + c->main_lebs != c->leb_cnt) {
		err = 12;
		goto failed;
	}

	if (c->default_compr >= UBIFS_COMPR_TYPES_CNT) {
		err = 13;
		goto failed;
	}

	if (c->rp_size < 0 || max_bytes < c->rp_size) {
		err = 14;
		goto failed;
	}

	if (le32_to_cpu(sup->time_gran) > 1000000000 ||
	    le32_to_cpu(sup->time_gran) < 1) {
		err = 15;
		goto failed;
	}

	return 0;

failed:
	ubifs_err("bad superblock, error %d", err);
	ubifs_dump_node(c, sup);
	return -EINVAL;
}

/**
 * ubifs_read_sb_node - read superblock node.
 * @c: UBIFS file-system description object
 *
 * This function returns a pointer to the superblock node or a negative error
 * code. Note, the user of this function is responsible of kfree()'ing the
 * returned superblock buffer.
 */
struct ubifs_sb_node *ubifs_read_sb_node(struct ubifs_info *c)
{
	struct ubifs_sb_node *sup;
	int err;

	sup = kmalloc(ALIGN(UBIFS_SB_NODE_SZ, c->min_io_size), GFP_NOFS);
	if (!sup)
		return ERR_PTR(-ENOMEM);

	err = ubifs_read_node(c, sup, UBIFS_SB_NODE, UBIFS_SB_NODE_SZ,
			      UBIFS_SB_LNUM, 0);
	if (err) {
		kfree(sup);
		return ERR_PTR(err);
	}

	return sup;
}

/**
 * ubifs_write_sb_node - write superblock node.
 * @c: UBIFS file-system description object
 * @sup: superblock node read with 'ubifs_read_sb_node()'
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_write_sb_node(struct ubifs_info *c, struct ubifs_sb_node *sup)
{
	int len = ALIGN(UBIFS_SB_NODE_SZ, c->min_io_size);

	ubifs_prepare_node(c, sup, UBIFS_SB_NODE_SZ, 1);
	return ubifs_leb_change(c, UBIFS_SB_LNUM, sup, len);
}

/**
 * ubifs_read_superblock - read superblock.
 * @c: UBIFS file-system description object
 *
 * This function finds, reads and checks the superblock. If an empty UBI volume
 * is being mounted, this function creates default superblock. Returns zero in
 * case of success, and a negative error code in case of failure.
 */
int ubifs_read_superblock(struct ubifs_info *c)
{
	int err, sup_flags;
	struct ubifs_sb_node *sup;

	if (c->empty) {
		err = create_default_filesystem(c);
		if (err)
			return err;
	}

	sup = ubifs_read_sb_node(c);
	if (IS_ERR(sup))
		return PTR_ERR(sup);

	c->fmt_version = le32_to_cpu(sup->fmt_version);
	c->ro_compat_version = le32_to_cpu(sup->ro_compat_version);

	/*
	 * The software supports all previous versions but not future versions,
	 * due to the unavailability of time-travelling equipment.
	 */
	if (c->fmt_version > UBIFS_FORMAT_VERSION) {
		ubifs_assert(!c->ro_media || c->ro_mount);
		if (!c->ro_mount ||
		    c->ro_compat_version > UBIFS_RO_COMPAT_VERSION) {
			ubifs_err("on-flash format version is w%d/r%d, but software only supports up to version w%d/r%d",
				  c->fmt_version, c->ro_compat_version,
				  UBIFS_FORMAT_VERSION,
				  UBIFS_RO_COMPAT_VERSION);
			if (c->ro_compat_version <= UBIFS_RO_COMPAT_VERSION) {
				ubifs_msg("only R/O mounting is possible");
				err = -EROFS;
			} else
				err = -EINVAL;
			goto out;
		}

		/*
		 * The FS is mounted R/O, and the media format is
		 * R/O-compatible with the UBIFS implementation, so we can
		 * mount.
		 */
		c->rw_incompat = 1;
	}

	if (c->fmt_version < 3) {
		ubifs_err("on-flash format version %d is not supported",
			  c->fmt_version);
		err = -EINVAL;
		goto out;
	}

	switch (sup->key_hash) {
	case UBIFS_KEY_HASH_R5:
		c->key_hash = key_r5_hash;
		c->key_hash_type = UBIFS_KEY_HASH_R5;
		break;

	case UBIFS_KEY_HASH_TEST:
		c->key_hash = key_test_hash;
		c->key_hash_type = UBIFS_KEY_HASH_TEST;
		break;
	};

	c->key_fmt = sup->key_fmt;

	switch (c->key_fmt) {
	case UBIFS_SIMPLE_KEY_FMT:
		c->key_len = UBIFS_SK_LEN;
		break;
	default:
		ubifs_err("unsupported key format");
		err = -EINVAL;
		goto out;
	}

	c->leb_cnt       = le32_to_cpu(sup->leb_cnt);
	c->max_leb_cnt   = le32_to_cpu(sup->max_leb_cnt);
	c->max_bud_bytes = le64_to_cpu(sup->max_bud_bytes);
	c->log_lebs      = le32_to_cpu(sup->log_lebs);
	c->lpt_lebs      = le32_to_cpu(sup->lpt_lebs);
	c->orph_lebs     = le32_to_cpu(sup->orph_lebs);
	c->jhead_cnt     = le32_to_cpu(sup->jhead_cnt) + NONDATA_JHEADS_CNT;
	c->fanout        = le32_to_cpu(sup->fanout);
	c->lsave_cnt     = le32_to_cpu(sup->lsave_cnt);
	c->rp_size       = le64_to_cpu(sup->rp_size);
	c->rp_uid        = make_kuid(&init_user_ns, le32_to_cpu(sup->rp_uid));
	c->rp_gid        = make_kgid(&init_user_ns, le32_to_cpu(sup->rp_gid));
	sup_flags        = le32_to_cpu(sup->flags);
	if (!c->mount_opts.override_compr)
		c->default_compr = le16_to_cpu(sup->default_compr);

	c->vfs_sb->s_time_gran = le32_to_cpu(sup->time_gran);
	memcpy(&c->uuid, &sup->uuid, 16);
	c->big_lpt = !!(sup_flags & UBIFS_FLG_BIGLPT);
	c->space_fixup = !!(sup_flags & UBIFS_FLG_SPACE_FIXUP);

	/* Automatically increase file system size to the maximum size */
	c->old_leb_cnt = c->leb_cnt;
	if (c->leb_cnt < c->vi.size && c->leb_cnt < c->max_leb_cnt) {
		c->leb_cnt = min_t(int, c->max_leb_cnt, c->vi.size);
		if (c->ro_mount)
			dbg_mnt("Auto resizing (ro) from %d LEBs to %d LEBs",
				c->old_leb_cnt,	c->leb_cnt);
		else {
			dbg_mnt("Auto resizing (sb) from %d LEBs to %d LEBs",
				c->old_leb_cnt, c->leb_cnt);
			sup->leb_cnt = cpu_to_le32(c->leb_cnt);
			err = ubifs_write_sb_node(c, sup);
			if (err)
				goto out;
			c->old_leb_cnt = c->leb_cnt;
		}
	}

	c->log_bytes = (long long)c->log_lebs * c->leb_size;
	c->log_last = UBIFS_LOG_LNUM + c->log_lebs - 1;
	c->lpt_first = UBIFS_LOG_LNUM + c->log_lebs;
	c->lpt_last = c->lpt_first + c->lpt_lebs - 1;
	c->orph_first = c->lpt_last + 1;
	c->orph_last = c->orph_first + c->orph_lebs - 1;
	c->main_lebs = c->leb_cnt - UBIFS_SB_LEBS - UBIFS_MST_LEBS;
	c->main_lebs -= c->log_lebs + c->lpt_lebs + c->orph_lebs;
	c->main_first = c->leb_cnt - c->main_lebs;

	err = validate_sb(c, sup);
out:
	kfree(sup);
	return err;
}

/**
 * fixup_leb - fixup/unmap an LEB containing free space.
 * @c: UBIFS file-system description object
 * @lnum: the LEB number to fix up
 * @len: number of used bytes in LEB (starting at offset 0)
 *
 * This function reads the contents of the given LEB number @lnum, then fixes
 * it up, so that empty min. I/O units in the end of LEB are actually erased on
 * flash (rather than being just all-0xff real data). If the LEB is completely
 * empty, it is simply unmapped.
 */
static int fixup_leb(struct ubifs_info *c, int lnum, int len)
{
	int err;

	ubifs_assert(len >= 0);
	ubifs_assert(len % c->min_io_size == 0);
	ubifs_assert(len < c->leb_size);

	if (len == 0) {
		dbg_mnt("unmap empty LEB %d", lnum);
		return ubifs_leb_unmap(c, lnum);
	}

	dbg_mnt("fixup LEB %d, data len %d", lnum, len);
	err = ubifs_leb_read(c, lnum, c->sbuf, 0, len, 1);
	if (err)
		return err;

	return ubifs_leb_change(c, lnum, c->sbuf, len);
}

/**
 * fixup_free_space - find & remap all LEBs containing free space.
 * @c: UBIFS file-system description object
 *
 * This function walks through all LEBs in the filesystem and fiexes up those
 * containing free/empty space.
 */
static int fixup_free_space(struct ubifs_info *c)
{
	int lnum, err = 0;
	struct ubifs_lprops *lprops;

	ubifs_get_lprops(c);

	/* Fixup LEBs in the master area */
	for (lnum = UBIFS_MST_LNUM; lnum < UBIFS_LOG_LNUM; lnum++) {
		err = fixup_leb(c, lnum, c->mst_offs + c->mst_node_alsz);
		if (err)
			goto out;
	}

	/* Unmap unused log LEBs */
	lnum = ubifs_next_log_lnum(c, c->lhead_lnum);
	while (lnum != c->ltail_lnum) {
		err = fixup_leb(c, lnum, 0);
		if (err)
			goto out;
		lnum = ubifs_next_log_lnum(c, lnum);
	}

	/*
	 * Fixup the log head which contains the only a CS node at the
	 * beginning.
	 */
	err = fixup_leb(c, c->lhead_lnum,
			ALIGN(UBIFS_CS_NODE_SZ, c->min_io_size));
	if (err)
		goto out;

	/* Fixup LEBs in the LPT area */
	for (lnum = c->lpt_first; lnum <= c->lpt_last; lnum++) {
		int free = c->ltab[lnum - c->lpt_first].free;

		if (free > 0) {
			err = fixup_leb(c, lnum, c->leb_size - free);
			if (err)
				goto out;
		}
	}

	/* Unmap LEBs in the orphans area */
	for (lnum = c->orph_first; lnum <= c->orph_last; lnum++) {
		err = fixup_leb(c, lnum, 0);
		if (err)
			goto out;
	}

	/* Fixup LEBs in the main area */
	for (lnum = c->main_first; lnum < c->leb_cnt; lnum++) {
		lprops = ubifs_lpt_lookup(c, lnum);
		if (IS_ERR(lprops)) {
			err = PTR_ERR(lprops);
			goto out;
		}

		if (lprops->free > 0) {
			err = fixup_leb(c, lnum, c->leb_size - lprops->free);
			if (err)
				goto out;
		}
	}

out:
	ubifs_release_lprops(c);
	return err;
}

/**
 * ubifs_fixup_free_space - find & fix all LEBs with free space.
 * @c: UBIFS file-system description object
 *
 * This function fixes up LEBs containing free space on first mount, if the
 * appropriate flag was set when the FS was created. Each LEB with one or more
 * empty min. I/O unit (i.e. free-space-count > 0) is re-written, to make sure
 * the free space is actually erased. E.g., this is necessary for some NAND
 * chips, since the free space may have been programmed like real "0xff" data
 * (generating a non-0xff ECC), causing future writes to the not-really-erased
 * NAND pages to behave badly. After the space is fixed up, the superblock flag
 * is cleared, so that this is skipped for all future mounts.
 */
int ubifs_fixup_free_space(struct ubifs_info *c)
{
	int err;
	struct ubifs_sb_node *sup;

	ubifs_assert(c->space_fixup);
	ubifs_assert(!c->ro_mount);

	ubifs_msg("start fixing up free space");

	err = fixup_free_space(c);
	if (err)
		return err;

	sup = ubifs_read_sb_node(c);
	if (IS_ERR(sup))
		return PTR_ERR(sup);

	/* Free-space fixup is no longer required */
	c->space_fixup = 0;
	sup->flags &= cpu_to_le32(~UBIFS_FLG_SPACE_FIXUP);

	err = ubifs_write_sb_node(c, sup);
	kfree(sup);
	if (err)
		return err;

	ubifs_msg("free space fixup complete");
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/sb.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 * Copyright (C) 2006, 2007 University of Szeged, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 *          Zoltan Sogor
 */

/*
 * This file implements UBIFS I/O subsystem which provides various I/O-related
 * helper functions (reading/writing/checking/validating nodes) and implements
 * write-buffering support. Write buffers help to save space which otherwise
 * would have been wasted for padding to the nearest minimal I/O unit boundary.
 * Instead, data first goes to the write-buffer and is flushed when the
 * buffer is full or when it is not used for some time (by timer). This is
 * similar to the mechanism is used by JFFS2.
 *
 * UBIFS distinguishes between minimum write size (@c->min_io_size) and maximum
 * write size (@c->max_write_size). The latter is the maximum amount of bytes
 * the underlying flash is able to program at a time, and writing in
 * @c->max_write_size units should presumably be faster. Obviously,
 * @c->min_io_size <= @c->max_write_size. Write-buffers are of
 * @c->max_write_size bytes in size for maximum performance. However, when a
 * write-buffer is flushed, only the portion of it (aligned to @c->min_io_size
 * boundary) which contains data is written, not the whole write-buffer,
 * because this is more space-efficient.
 *
 * This optimization adds few complications to the code. Indeed, on the one
 * hand, we want to write in optimal @c->max_write_size bytes chunks, which
 * also means aligning writes at the @c->max_write_size bytes offsets. On the
 * other hand, we do not want to waste space when synchronizing the write
 * buffer, so during synchronization we writes in smaller chunks. And this makes
 * the next write offset to be not aligned to @c->max_write_size bytes. So the
 * have to make sure that the write-buffer offset (@wbuf->offs) becomes aligned
 * to @c->max_write_size bytes again. We do this by temporarily shrinking
 * write-buffer size (@wbuf->size).
 *
 * Write-buffers are defined by 'struct ubifs_wbuf' objects and protected by
 * mutexes defined inside these objects. Since sometimes upper-level code
 * has to lock the write-buffer (e.g. journal space reservation code), many
 * functions related to write-buffers have "nolock" suffix which means that the
 * caller has to lock the write-buffer before calling this function.
 *
 * UBIFS stores nodes at 64 bit-aligned addresses. If the node length is not
 * aligned, UBIFS starts the next node from the aligned address, and the padded
 * bytes may contain any rubbish. In other words, UBIFS does not put padding
 * bytes in those small gaps. Common headers of nodes store real node lengths,
 * not aligned lengths. Indexing nodes also store real lengths in branches.
 *
 * UBIFS uses padding when it pads to the next min. I/O unit. In this case it
 * uses padding nodes or padding bytes, if the padding node does not fit.
 *
 * All UBIFS nodes are protected by CRC checksums and UBIFS checks CRC when
 * they are read from the flash media.
 */

#include <linux/crc32.h>
// #include <linux/slab.h>
// #include "ubifs.h"
#include "../../inc/__fss.h"

/**
 * ubifs_ro_mode - switch UBIFS to read read-only mode.
 * @c: UBIFS file-system description object
 * @err: error code which is the reason of switching to R/O mode
 */
void ubifs_ro_mode(struct ubifs_info *c, int err)
{
	if (!c->ro_error) {
		c->ro_error = 1;
		c->no_chk_data_crc = 0;
		c->vfs_sb->s_flags |= MS_RDONLY;
		ubifs_warn("switched to read-only mode, error %d", err);
		dump_stack();
	}
}

/*
 * Below are simple wrappers over UBI I/O functions which include some
 * additional checks and UBIFS debugging stuff. See corresponding UBI function
 * for more information.
 */

int ubifs_leb_read(const struct ubifs_info *c, int lnum, void *buf, int offs,
		   int len, int even_ebadmsg)
{
	int err;

	err = ubi_read(c->ubi, lnum, buf, offs, len);
	/*
	 * In case of %-EBADMSG print the error message only if the
	 * @even_ebadmsg is true.
	 */
	if (err && (err != -EBADMSG || even_ebadmsg)) {
		ubifs_err("reading %d bytes from LEB %d:%d failed, error %d",
			  len, lnum, offs, err);
		dump_stack();
	}
	return err;
}

int ubifs_leb_write(struct ubifs_info *c, int lnum, const void *buf, int offs,
		    int len)
{
	int err;

	ubifs_assert(!c->ro_media && !c->ro_mount);
	if (c->ro_error)
		return -EROFS;
	if (!dbg_is_tst_rcvry(c))
		err = ubi_leb_write(c->ubi, lnum, buf, offs, len);
	else
		err = dbg_leb_write(c, lnum, buf, offs, len);
	if (err) {
		ubifs_err("writing %d bytes to LEB %d:%d failed, error %d",
			  len, lnum, offs, err);
		ubifs_ro_mode(c, err);
		dump_stack();
	}
	return err;
}

int ubifs_leb_change(struct ubifs_info *c, int lnum, const void *buf, int len)
{
	int err;

	ubifs_assert(!c->ro_media && !c->ro_mount);
	if (c->ro_error)
		return -EROFS;
	if (!dbg_is_tst_rcvry(c))
		err = ubi_leb_change(c->ubi, lnum, buf, len);
	else
		err = dbg_leb_change(c, lnum, buf, len);
	if (err) {
		ubifs_err("changing %d bytes in LEB %d failed, error %d",
			  len, lnum, err);
		ubifs_ro_mode(c, err);
		dump_stack();
	}
	return err;
}

int ubifs_leb_unmap(struct ubifs_info *c, int lnum)
{
	int err;

	ubifs_assert(!c->ro_media && !c->ro_mount);
	if (c->ro_error)
		return -EROFS;
	if (!dbg_is_tst_rcvry(c))
		err = ubi_leb_unmap(c->ubi, lnum);
	else
		err = dbg_leb_unmap(c, lnum);
	if (err) {
		ubifs_err("unmap LEB %d failed, error %d", lnum, err);
		ubifs_ro_mode(c, err);
		dump_stack();
	}
	return err;
}

int ubifs_leb_map(struct ubifs_info *c, int lnum)
{
	int err;

	ubifs_assert(!c->ro_media && !c->ro_mount);
	if (c->ro_error)
		return -EROFS;
	if (!dbg_is_tst_rcvry(c))
		err = ubi_leb_map(c->ubi, lnum);
	else
		err = dbg_leb_map(c, lnum);
	if (err) {
		ubifs_err("mapping LEB %d failed, error %d", lnum, err);
		ubifs_ro_mode(c, err);
		dump_stack();
	}
	return err;
}

int ubifs_is_mapped(const struct ubifs_info *c, int lnum)
{
	int err;

	err = ubi_is_mapped(c->ubi, lnum);
	if (err < 0) {
		ubifs_err("ubi_is_mapped failed for LEB %d, error %d",
			  lnum, err);
		dump_stack();
	}
	return err;
}

/**
 * ubifs_check_node - check node.
 * @c: UBIFS file-system description object
 * @buf: node to check
 * @lnum: logical eraseblock number
 * @offs: offset within the logical eraseblock
 * @quiet: print no messages
 * @must_chk_crc: indicates whether to always check the CRC
 *
 * This function checks node magic number and CRC checksum. This function also
 * validates node length to prevent UBIFS from becoming crazy when an attacker
 * feeds it a file-system image with incorrect nodes. For example, too large
 * node length in the common header could cause UBIFS to read memory outside of
 * allocated buffer when checking the CRC checksum.
 *
 * This function may skip data nodes CRC checking if @c->no_chk_data_crc is
 * true, which is controlled by corresponding UBIFS mount option. However, if
 * @must_chk_crc is true, then @c->no_chk_data_crc is ignored and CRC is
 * checked. Similarly, if @c->mounting or @c->remounting_rw is true (we are
 * mounting or re-mounting to R/W mode), @c->no_chk_data_crc is ignored and CRC
 * is checked. This is because during mounting or re-mounting from R/O mode to
 * R/W mode we may read journal nodes (when replying the journal or doing the
 * recovery) and the journal nodes may potentially be corrupted, so checking is
 * required.
 *
 * This function returns zero in case of success and %-EUCLEAN in case of bad
 * CRC or magic.
 */
int ubifs_check_node(const struct ubifs_info *c, const void *buf, int lnum,
		     int offs, int quiet, int must_chk_crc)
{
	int err = -EINVAL, type, node_len;
	uint32_t crc, node_crc, magic;
	const struct ubifs_ch *ch = buf;

	ubifs_assert(lnum >= 0 && lnum < c->leb_cnt && offs >= 0);
	ubifs_assert(!(offs & 7) && offs < c->leb_size);

	magic = le32_to_cpu(ch->magic);
	if (magic != UBIFS_NODE_MAGIC) {
		if (!quiet)
			ubifs_err("bad magic %#08x, expected %#08x",
				  magic, UBIFS_NODE_MAGIC);
		err = -EUCLEAN;
		goto out;
	}

	type = ch->node_type;
	if (type < 0 || type >= UBIFS_NODE_TYPES_CNT) {
		if (!quiet)
			ubifs_err("bad node type %d", type);
		goto out;
	}

	node_len = le32_to_cpu(ch->len);
	if (node_len + offs > c->leb_size)
		goto out_len;

	if (c->ranges[type].max_len == 0) {
		if (node_len != c->ranges[type].len)
			goto out_len;
	} else if (node_len < c->ranges[type].min_len ||
		   node_len > c->ranges[type].max_len)
		goto out_len;

	if (!must_chk_crc && type == UBIFS_DATA_NODE && !c->mounting &&
	    !c->remounting_rw && c->no_chk_data_crc)
		return 0;

	crc = crc32(UBIFS_CRC32_INIT, buf + 8, node_len - 8);
	node_crc = le32_to_cpu(ch->crc);
	if (crc != node_crc) {
		if (!quiet)
			ubifs_err("bad CRC: calculated %#08x, read %#08x",
				  crc, node_crc);
		err = -EUCLEAN;
		goto out;
	}

	return 0;

out_len:
	if (!quiet)
		ubifs_err("bad node length %d", node_len);
out:
	if (!quiet) {
		ubifs_err("bad node at LEB %d:%d", lnum, offs);
		ubifs_dump_node(c, buf);
		dump_stack();
	}
	return err;
}

/**
 * ubifs_pad - pad flash space.
 * @c: UBIFS file-system description object
 * @buf: buffer to put padding to
 * @pad: how many bytes to pad
 *
 * The flash media obliges us to write only in chunks of %c->min_io_size and
 * when we have to write less data we add padding node to the write-buffer and
 * pad it to the next minimal I/O unit's boundary. Padding nodes help when the
 * media is being scanned. If the amount of wasted space is not enough to fit a
 * padding node which takes %UBIFS_PAD_NODE_SZ bytes, we write padding bytes
 * pattern (%UBIFS_PADDING_BYTE).
 *
 * Padding nodes are also used to fill gaps when the "commit-in-gaps" method is
 * used.
 */
void ubifs_pad(const struct ubifs_info *c, void *buf, int pad)
{
	uint32_t crc;

	ubifs_assert(pad >= 0 && !(pad & 7));

	if (pad >= UBIFS_PAD_NODE_SZ) {
		struct ubifs_ch *ch = buf;
		struct ubifs_pad_node *pad_node = buf;

		ch->magic = cpu_to_le32(UBIFS_NODE_MAGIC);
		ch->node_type = UBIFS_PAD_NODE;
		ch->group_type = UBIFS_NO_NODE_GROUP;
		ch->padding[0] = ch->padding[1] = 0;
		ch->sqnum = 0;
		ch->len = cpu_to_le32(UBIFS_PAD_NODE_SZ);
		pad -= UBIFS_PAD_NODE_SZ;
		pad_node->pad_len = cpu_to_le32(pad);
		crc = crc32(UBIFS_CRC32_INIT, buf + 8, UBIFS_PAD_NODE_SZ - 8);
		ch->crc = cpu_to_le32(crc);
		memset(buf + UBIFS_PAD_NODE_SZ, 0, pad);
	} else if (pad > 0)
		/* Too little space, padding node won't fit */
		memset(buf, UBIFS_PADDING_BYTE, pad);
}

/**
 * next_sqnum - get next sequence number.
 * @c: UBIFS file-system description object
 */
static unsigned long long next_sqnum(struct ubifs_info *c)
{
	unsigned long long sqnum;

	spin_lock(&c->cnt_lock);
	sqnum = ++c->max_sqnum;
	spin_unlock(&c->cnt_lock);

	if (unlikely(sqnum >= SQNUM_WARN_WATERMARK)) {
		if (sqnum >= SQNUM_WATERMARK) {
			ubifs_err("sequence number overflow %llu, end of life",
				  sqnum);
			ubifs_ro_mode(c, -EINVAL);
		}
		ubifs_warn("running out of sequence numbers, end of life soon");
	}

	return sqnum;
}

/**
 * ubifs_prepare_node - prepare node to be written to flash.
 * @c: UBIFS file-system description object
 * @node: the node to pad
 * @len: node length
 * @pad: if the buffer has to be padded
 *
 * This function prepares node at @node to be written to the media - it
 * calculates node CRC, fills the common header, and adds proper padding up to
 * the next minimum I/O unit if @pad is not zero.
 */
void ubifs_prepare_node(struct ubifs_info *c, void *node, int len, int pad)
{
	uint32_t crc;
	struct ubifs_ch *ch = node;
	unsigned long long sqnum = next_sqnum(c);

	ubifs_assert(len >= UBIFS_CH_SZ);

	ch->magic = cpu_to_le32(UBIFS_NODE_MAGIC);
	ch->len = cpu_to_le32(len);
	ch->group_type = UBIFS_NO_NODE_GROUP;
	ch->sqnum = cpu_to_le64(sqnum);
	ch->padding[0] = ch->padding[1] = 0;
	crc = crc32(UBIFS_CRC32_INIT, node + 8, len - 8);
	ch->crc = cpu_to_le32(crc);

	if (pad) {
		len = ALIGN(len, 8);
		pad = ALIGN(len, c->min_io_size) - len;
		ubifs_pad(c, node + len, pad);
	}
}

/**
 * ubifs_prep_grp_node - prepare node of a group to be written to flash.
 * @c: UBIFS file-system description object
 * @node: the node to pad
 * @len: node length
 * @last: indicates the last node of the group
 *
 * This function prepares node at @node to be written to the media - it
 * calculates node CRC and fills the common header.
 */
void ubifs_prep_grp_node(struct ubifs_info *c, void *node, int len, int last)
{
	uint32_t crc;
	struct ubifs_ch *ch = node;
	unsigned long long sqnum = next_sqnum(c);

	ubifs_assert(len >= UBIFS_CH_SZ);

	ch->magic = cpu_to_le32(UBIFS_NODE_MAGIC);
	ch->len = cpu_to_le32(len);
	if (last)
		ch->group_type = UBIFS_LAST_OF_NODE_GROUP;
	else
		ch->group_type = UBIFS_IN_NODE_GROUP;
	ch->sqnum = cpu_to_le64(sqnum);
	ch->padding[0] = ch->padding[1] = 0;
	crc = crc32(UBIFS_CRC32_INIT, node + 8, len - 8);
	ch->crc = cpu_to_le32(crc);
}

/**
 * wbuf_timer_callback - write-buffer timer callback function.
 * @timer: timer data (write-buffer descriptor)
 *
 * This function is called when the write-buffer timer expires.
 */
static enum hrtimer_restart wbuf_timer_callback_nolock(struct hrtimer *timer)
{
	struct ubifs_wbuf *wbuf = container_of(timer, struct ubifs_wbuf, timer);

	dbg_io("jhead %s", dbg_jhead(wbuf->jhead));
	wbuf->need_sync = 1;
	wbuf->c->need_wbuf_sync = 1;
	ubifs_wake_up_bgt(wbuf->c);
	return HRTIMER_NORESTART;
}

/**
 * new_wbuf_timer - start new write-buffer timer.
 * @wbuf: write-buffer descriptor
 */
static void new_wbuf_timer_nolock(struct ubifs_wbuf *wbuf)
{
	ubifs_assert(!hrtimer_active(&wbuf->timer));

	if (wbuf->no_timer)
		return;
	dbg_io("set timer for jhead %s, %llu-%llu millisecs",
	       dbg_jhead(wbuf->jhead),
	       div_u64(ktime_to_ns(wbuf->softlimit), USEC_PER_SEC),
	       div_u64(ktime_to_ns(wbuf->softlimit) + wbuf->delta,
		       USEC_PER_SEC));
	hrtimer_start_range_ns(&wbuf->timer, wbuf->softlimit, wbuf->delta,
			       HRTIMER_MODE_REL);
}

/**
 * cancel_wbuf_timer - cancel write-buffer timer.
 * @wbuf: write-buffer descriptor
 */
static void cancel_wbuf_timer_nolock(struct ubifs_wbuf *wbuf)
{
	if (wbuf->no_timer)
		return;
	wbuf->need_sync = 0;
	hrtimer_cancel(&wbuf->timer);
}

/**
 * ubifs_wbuf_sync_nolock - synchronize write-buffer.
 * @wbuf: write-buffer to synchronize
 *
 * This function synchronizes write-buffer @buf and returns zero in case of
 * success or a negative error code in case of failure.
 *
 * Note, although write-buffers are of @c->max_write_size, this function does
 * not necessarily writes all @c->max_write_size bytes to the flash. Instead,
 * if the write-buffer is only partially filled with data, only the used part
 * of the write-buffer (aligned on @c->min_io_size boundary) is synchronized.
 * This way we waste less space.
 */
int ubifs_wbuf_sync_nolock(struct ubifs_wbuf *wbuf)
{
	struct ubifs_info *c = wbuf->c;
	int err, dirt, sync_len;

	cancel_wbuf_timer_nolock(wbuf);
	if (!wbuf->used || wbuf->lnum == -1)
		/* Write-buffer is empty or not seeked */
		return 0;

	dbg_io("LEB %d:%d, %d bytes, jhead %s",
	       wbuf->lnum, wbuf->offs, wbuf->used, dbg_jhead(wbuf->jhead));
	ubifs_assert(!(wbuf->avail & 7));
	ubifs_assert(wbuf->offs + wbuf->size <= c->leb_size);
	ubifs_assert(wbuf->size >= c->min_io_size);
	ubifs_assert(wbuf->size <= c->max_write_size);
	ubifs_assert(wbuf->size % c->min_io_size == 0);
	ubifs_assert(!c->ro_media && !c->ro_mount);
	if (c->leb_size - wbuf->offs >= c->max_write_size)
		ubifs_assert(!((wbuf->offs + wbuf->size) % c->max_write_size));

	if (c->ro_error)
		return -EROFS;

	/*
	 * Do not write whole write buffer but write only the minimum necessary
	 * amount of min. I/O units.
	 */
	sync_len = ALIGN(wbuf->used, c->min_io_size);
	dirt = sync_len - wbuf->used;
	if (dirt)
		ubifs_pad(c, wbuf->buf + wbuf->used, dirt);
	err = ubifs_leb_write(c, wbuf->lnum, wbuf->buf, wbuf->offs, sync_len);
	if (err)
		return err;

	spin_lock(&wbuf->lock);
	wbuf->offs += sync_len;
	/*
	 * Now @wbuf->offs is not necessarily aligned to @c->max_write_size.
	 * But our goal is to optimize writes and make sure we write in
	 * @c->max_write_size chunks and to @c->max_write_size-aligned offset.
	 * Thus, if @wbuf->offs is not aligned to @c->max_write_size now, make
	 * sure that @wbuf->offs + @wbuf->size is aligned to
	 * @c->max_write_size. This way we make sure that after next
	 * write-buffer flush we are again at the optimal offset (aligned to
	 * @c->max_write_size).
	 */
	if (c->leb_size - wbuf->offs < c->max_write_size)
		wbuf->size = c->leb_size - wbuf->offs;
	else if (wbuf->offs & (c->max_write_size - 1))
		wbuf->size = ALIGN(wbuf->offs, c->max_write_size) - wbuf->offs;
	else
		wbuf->size = c->max_write_size;
	wbuf->avail = wbuf->size;
	wbuf->used = 0;
	wbuf->next_ino = 0;
	spin_unlock(&wbuf->lock);

	if (wbuf->sync_callback)
		err = wbuf->sync_callback(c, wbuf->lnum,
					  c->leb_size - wbuf->offs, dirt);
	return err;
}

/**
 * ubifs_wbuf_seek_nolock - seek write-buffer.
 * @wbuf: write-buffer
 * @lnum: logical eraseblock number to seek to
 * @offs: logical eraseblock offset to seek to
 *
 * This function targets the write-buffer to logical eraseblock @lnum:@offs.
 * The write-buffer has to be empty. Returns zero in case of success and a
 * negative error code in case of failure.
 */
int ubifs_wbuf_seek_nolock(struct ubifs_wbuf *wbuf, int lnum, int offs)
{
	const struct ubifs_info *c = wbuf->c;

	dbg_io("LEB %d:%d, jhead %s", lnum, offs, dbg_jhead(wbuf->jhead));
	ubifs_assert(lnum >= 0 && lnum < c->leb_cnt);
	ubifs_assert(offs >= 0 && offs <= c->leb_size);
	ubifs_assert(offs % c->min_io_size == 0 && !(offs & 7));
	ubifs_assert(lnum != wbuf->lnum);
	ubifs_assert(wbuf->used == 0);

	spin_lock(&wbuf->lock);
	wbuf->lnum = lnum;
	wbuf->offs = offs;
	if (c->leb_size - wbuf->offs < c->max_write_size)
		wbuf->size = c->leb_size - wbuf->offs;
	else if (wbuf->offs & (c->max_write_size - 1))
		wbuf->size = ALIGN(wbuf->offs, c->max_write_size) - wbuf->offs;
	else
		wbuf->size = c->max_write_size;
	wbuf->avail = wbuf->size;
	wbuf->used = 0;
	spin_unlock(&wbuf->lock);

	return 0;
}

/**
 * ubifs_bg_wbufs_sync - synchronize write-buffers.
 * @c: UBIFS file-system description object
 *
 * This function is called by background thread to synchronize write-buffers.
 * Returns zero in case of success and a negative error code in case of
 * failure.
 */
int ubifs_bg_wbufs_sync(struct ubifs_info *c)
{
	int err, i;

	ubifs_assert(!c->ro_media && !c->ro_mount);
	if (!c->need_wbuf_sync)
		return 0;
	c->need_wbuf_sync = 0;

	if (c->ro_error) {
		err = -EROFS;
		goto out_timers;
	}

	dbg_io("synchronize");
	for (i = 0; i < c->jhead_cnt; i++) {
		struct ubifs_wbuf *wbuf = &c->jheads[i].wbuf;

		cond_resched();

		/*
		 * If the mutex is locked then wbuf is being changed, so
		 * synchronization is not necessary.
		 */
		if (mutex_is_locked(&wbuf->io_mutex))
			continue;

		mutex_lock_nested(&wbuf->io_mutex, wbuf->jhead);
		if (!wbuf->need_sync) {
			mutex_unlock(&wbuf->io_mutex);
			continue;
		}

		err = ubifs_wbuf_sync_nolock(wbuf);
		mutex_unlock(&wbuf->io_mutex);
		if (err) {
			ubifs_err("cannot sync write-buffer, error %d", err);
			ubifs_ro_mode(c, err);
			goto out_timers;
		}
	}

	return 0;

out_timers:
	/* Cancel all timers to prevent repeated errors */
	for (i = 0; i < c->jhead_cnt; i++) {
		struct ubifs_wbuf *wbuf = &c->jheads[i].wbuf;

		mutex_lock_nested(&wbuf->io_mutex, wbuf->jhead);
		cancel_wbuf_timer_nolock(wbuf);
		mutex_unlock(&wbuf->io_mutex);
	}
	return err;
}

/**
 * ubifs_wbuf_write_nolock - write data to flash via write-buffer.
 * @wbuf: write-buffer
 * @buf: node to write
 * @len: node length
 *
 * This function writes data to flash via write-buffer @wbuf. This means that
 * the last piece of the node won't reach the flash media immediately if it
 * does not take whole max. write unit (@c->max_write_size). Instead, the node
 * will sit in RAM until the write-buffer is synchronized (e.g., by timer, or
 * because more data are appended to the write-buffer).
 *
 * This function returns zero in case of success and a negative error code in
 * case of failure. If the node cannot be written because there is no more
 * space in this logical eraseblock, %-ENOSPC is returned.
 */
int ubifs_wbuf_write_nolock(struct ubifs_wbuf *wbuf, void *buf, int len)
{
	struct ubifs_info *c = wbuf->c;
	int err, written, n, aligned_len = ALIGN(len, 8);

	dbg_io("%d bytes (%s) to jhead %s wbuf at LEB %d:%d", len,
	       dbg_ntype(((struct ubifs_ch *)buf)->node_type),
	       dbg_jhead(wbuf->jhead), wbuf->lnum, wbuf->offs + wbuf->used);
	ubifs_assert(len > 0 && wbuf->lnum >= 0 && wbuf->lnum < c->leb_cnt);
	ubifs_assert(wbuf->offs >= 0 && wbuf->offs % c->min_io_size == 0);
	ubifs_assert(!(wbuf->offs & 7) && wbuf->offs <= c->leb_size);
	ubifs_assert(wbuf->avail > 0 && wbuf->avail <= wbuf->size);
	ubifs_assert(wbuf->size >= c->min_io_size);
	ubifs_assert(wbuf->size <= c->max_write_size);
	ubifs_assert(wbuf->size % c->min_io_size == 0);
	ubifs_assert(mutex_is_locked(&wbuf->io_mutex));
	ubifs_assert(!c->ro_media && !c->ro_mount);
	ubifs_assert(!c->space_fixup);
	if (c->leb_size - wbuf->offs >= c->max_write_size)
		ubifs_assert(!((wbuf->offs + wbuf->size) % c->max_write_size));

	if (c->leb_size - wbuf->offs - wbuf->used < aligned_len) {
		err = -ENOSPC;
		goto out;
	}

	cancel_wbuf_timer_nolock(wbuf);

	if (c->ro_error)
		return -EROFS;

	if (aligned_len <= wbuf->avail) {
		/*
		 * The node is not very large and fits entirely within
		 * write-buffer.
		 */
		memcpy(wbuf->buf + wbuf->used, buf, len);

		if (aligned_len == wbuf->avail) {
			dbg_io("flush jhead %s wbuf to LEB %d:%d",
			       dbg_jhead(wbuf->jhead), wbuf->lnum, wbuf->offs);
			err = ubifs_leb_write(c, wbuf->lnum, wbuf->buf,
					      wbuf->offs, wbuf->size);
			if (err)
				goto out;

			spin_lock(&wbuf->lock);
			wbuf->offs += wbuf->size;
			if (c->leb_size - wbuf->offs >= c->max_write_size)
				wbuf->size = c->max_write_size;
			else
				wbuf->size = c->leb_size - wbuf->offs;
			wbuf->avail = wbuf->size;
			wbuf->used = 0;
			wbuf->next_ino = 0;
			spin_unlock(&wbuf->lock);
		} else {
			spin_lock(&wbuf->lock);
			wbuf->avail -= aligned_len;
			wbuf->used += aligned_len;
			spin_unlock(&wbuf->lock);
		}

		goto exit;
	}

	written = 0;

	if (wbuf->used) {
		/*
		 * The node is large enough and does not fit entirely within
		 * current available space. We have to fill and flush
		 * write-buffer and switch to the next max. write unit.
		 */
		dbg_io("flush jhead %s wbuf to LEB %d:%d",
		       dbg_jhead(wbuf->jhead), wbuf->lnum, wbuf->offs);
		memcpy(wbuf->buf + wbuf->used, buf, wbuf->avail);
		err = ubifs_leb_write(c, wbuf->lnum, wbuf->buf, wbuf->offs,
				      wbuf->size);
		if (err)
			goto out;

		wbuf->offs += wbuf->size;
		len -= wbuf->avail;
		aligned_len -= wbuf->avail;
		written += wbuf->avail;
	} else if (wbuf->offs & (c->max_write_size - 1)) {
		/*
		 * The write-buffer offset is not aligned to
		 * @c->max_write_size and @wbuf->size is less than
		 * @c->max_write_size. Write @wbuf->size bytes to make sure the
		 * following writes are done in optimal @c->max_write_size
		 * chunks.
		 */
		dbg_io("write %d bytes to LEB %d:%d",
		       wbuf->size, wbuf->lnum, wbuf->offs);
		err = ubifs_leb_write(c, wbuf->lnum, buf, wbuf->offs,
				      wbuf->size);
		if (err)
			goto out;

		wbuf->offs += wbuf->size;
		len -= wbuf->size;
		aligned_len -= wbuf->size;
		written += wbuf->size;
	}

	/*
	 * The remaining data may take more whole max. write units, so write the
	 * remains multiple to max. write unit size directly to the flash media.
	 * We align node length to 8-byte boundary because we anyway flash wbuf
	 * if the remaining space is less than 8 bytes.
	 */
	n = aligned_len >> c->max_write_shift;
	if (n) {
		n <<= c->max_write_shift;
		dbg_io("write %d bytes to LEB %d:%d", n, wbuf->lnum,
		       wbuf->offs);
		err = ubifs_leb_write(c, wbuf->lnum, buf + written,
				      wbuf->offs, n);
		if (err)
			goto out;
		wbuf->offs += n;
		aligned_len -= n;
		len -= n;
		written += n;
	}

	spin_lock(&wbuf->lock);
	if (aligned_len)
		/*
		 * And now we have what's left and what does not take whole
		 * max. write unit, so write it to the write-buffer and we are
		 * done.
		 */
		memcpy(wbuf->buf, buf + written, len);

	if (c->leb_size - wbuf->offs >= c->max_write_size)
		wbuf->size = c->max_write_size;
	else
		wbuf->size = c->leb_size - wbuf->offs;
	wbuf->avail = wbuf->size - aligned_len;
	wbuf->used = aligned_len;
	wbuf->next_ino = 0;
	spin_unlock(&wbuf->lock);

exit:
	if (wbuf->sync_callback) {
		int free = c->leb_size - wbuf->offs - wbuf->used;

		err = wbuf->sync_callback(c, wbuf->lnum, free, 0);
		if (err)
			goto out;
	}

	if (wbuf->used)
		new_wbuf_timer_nolock(wbuf);

	return 0;

out:
	ubifs_err("cannot write %d bytes to LEB %d:%d, error %d",
		  len, wbuf->lnum, wbuf->offs, err);
	ubifs_dump_node(c, buf);
	dump_stack();
	ubifs_dump_leb(c, wbuf->lnum);
	return err;
}

/**
 * ubifs_write_node - write node to the media.
 * @c: UBIFS file-system description object
 * @buf: the node to write
 * @len: node length
 * @lnum: logical eraseblock number
 * @offs: offset within the logical eraseblock
 *
 * This function automatically fills node magic number, assigns sequence
 * number, and calculates node CRC checksum. The length of the @buf buffer has
 * to be aligned to the minimal I/O unit size. This function automatically
 * appends padding node and padding bytes if needed. Returns zero in case of
 * success and a negative error code in case of failure.
 */
int ubifs_write_node(struct ubifs_info *c, void *buf, int len, int lnum,
		     int offs)
{
	int err, buf_len = ALIGN(len, c->min_io_size);

	dbg_io("LEB %d:%d, %s, length %d (aligned %d)",
	       lnum, offs, dbg_ntype(((struct ubifs_ch *)buf)->node_type), len,
	       buf_len);
	ubifs_assert(lnum >= 0 && lnum < c->leb_cnt && offs >= 0);
	ubifs_assert(offs % c->min_io_size == 0 && offs < c->leb_size);
	ubifs_assert(!c->ro_media && !c->ro_mount);
	ubifs_assert(!c->space_fixup);

	if (c->ro_error)
		return -EROFS;

	ubifs_prepare_node(c, buf, len, 1);
	err = ubifs_leb_write(c, lnum, buf, offs, buf_len);
	if (err)
		ubifs_dump_node(c, buf);

	return err;
}

/**
 * ubifs_read_node_wbuf - read node from the media or write-buffer.
 * @wbuf: wbuf to check for un-written data
 * @buf: buffer to read to
 * @type: node type
 * @len: node length
 * @lnum: logical eraseblock number
 * @offs: offset within the logical eraseblock
 *
 * This function reads a node of known type and length, checks it and stores
 * in @buf. If the node partially or fully sits in the write-buffer, this
 * function takes data from the buffer, otherwise it reads the flash media.
 * Returns zero in case of success, %-EUCLEAN if CRC mismatched and a negative
 * error code in case of failure.
 */
int ubifs_read_node_wbuf(struct ubifs_wbuf *wbuf, void *buf, int type, int len,
			 int lnum, int offs)
{
	const struct ubifs_info *c = wbuf->c;
	int err, rlen, overlap;
	struct ubifs_ch *ch = buf;

	dbg_io("LEB %d:%d, %s, length %d, jhead %s", lnum, offs,
	       dbg_ntype(type), len, dbg_jhead(wbuf->jhead));
	ubifs_assert(wbuf && lnum >= 0 && lnum < c->leb_cnt && offs >= 0);
	ubifs_assert(!(offs & 7) && offs < c->leb_size);
	ubifs_assert(type >= 0 && type < UBIFS_NODE_TYPES_CNT);

	spin_lock(&wbuf->lock);
	overlap = (lnum == wbuf->lnum && offs + len > wbuf->offs);
	if (!overlap) {
		/* We may safely unlock the write-buffer and read the data */
		spin_unlock(&wbuf->lock);
		return ubifs_read_node(c, buf, type, len, lnum, offs);
	}

	/* Don't read under wbuf */
	rlen = wbuf->offs - offs;
	if (rlen < 0)
		rlen = 0;

	/* Copy the rest from the write-buffer */
	memcpy(buf + rlen, wbuf->buf + offs + rlen - wbuf->offs, len - rlen);
	spin_unlock(&wbuf->lock);

	if (rlen > 0) {
		/* Read everything that goes before write-buffer */
		err = ubifs_leb_read(c, lnum, buf, offs, rlen, 0);
		if (err && err != -EBADMSG)
			return err;
	}

	if (type != ch->node_type) {
		ubifs_err("bad node type (%d but expected %d)",
			  ch->node_type, type);
		goto out;
	}

	err = ubifs_check_node(c, buf, lnum, offs, 0, 0);
	if (err) {
		ubifs_err("expected node type %d", type);
		return err;
	}

	rlen = le32_to_cpu(ch->len);
	if (rlen != len) {
		ubifs_err("bad node length %d, expected %d", rlen, len);
		goto out;
	}

	return 0;

out:
	ubifs_err("bad node at LEB %d:%d", lnum, offs);
	ubifs_dump_node(c, buf);
	dump_stack();
	return -EINVAL;
}

/**
 * ubifs_read_node - read node.
 * @c: UBIFS file-system description object
 * @buf: buffer to read to
 * @type: node type
 * @len: node length (not aligned)
 * @lnum: logical eraseblock number
 * @offs: offset within the logical eraseblock
 *
 * This function reads a node of known type and and length, checks it and
 * stores in @buf. Returns zero in case of success, %-EUCLEAN if CRC mismatched
 * and a negative error code in case of failure.
 */
int ubifs_read_node(const struct ubifs_info *c, void *buf, int type, int len,
		    int lnum, int offs)
{
	int err, l;
	struct ubifs_ch *ch = buf;

	dbg_io("LEB %d:%d, %s, length %d", lnum, offs, dbg_ntype(type), len);
	ubifs_assert(lnum >= 0 && lnum < c->leb_cnt && offs >= 0);
	ubifs_assert(len >= UBIFS_CH_SZ && offs + len <= c->leb_size);
	ubifs_assert(!(offs & 7) && offs < c->leb_size);
	ubifs_assert(type >= 0 && type < UBIFS_NODE_TYPES_CNT);

	err = ubifs_leb_read(c, lnum, buf, offs, len, 0);
	if (err && err != -EBADMSG)
		return err;

	if (type != ch->node_type) {
		ubifs_errc(c, "bad node type (%d but expected %d)",
			   ch->node_type, type);
		goto out;
	}

	err = ubifs_check_node(c, buf, lnum, offs, 0, 0);
	if (err) {
		ubifs_errc(c, "expected node type %d", type);
		return err;
	}

	l = le32_to_cpu(ch->len);
	if (l != len) {
		ubifs_errc(c, "bad node length %d, expected %d", l, len);
		goto out;
	}

	return 0;

out:
	ubifs_errc(c, "bad node at LEB %d:%d, LEB mapping status %d", lnum,
		   offs, ubi_is_mapped(c->ubi, lnum));
	if (!c->probing) {
		ubifs_dump_node(c, buf);
		dump_stack();
	}
	return -EINVAL;
}

/**
 * ubifs_wbuf_init - initialize write-buffer.
 * @c: UBIFS file-system description object
 * @wbuf: write-buffer to initialize
 *
 * This function initializes write-buffer. Returns zero in case of success
 * %-ENOMEM in case of failure.
 */
int ubifs_wbuf_init(struct ubifs_info *c, struct ubifs_wbuf *wbuf)
{
	size_t size;

	wbuf->buf = kmalloc(c->max_write_size, GFP_KERNEL);
	if (!wbuf->buf)
		return -ENOMEM;

	size = (c->max_write_size / UBIFS_CH_SZ + 1) * sizeof(ino_t);
	wbuf->inodes = kmalloc(size, GFP_KERNEL);
	if (!wbuf->inodes) {
		kfree(wbuf->buf);
		wbuf->buf = NULL;
		return -ENOMEM;
	}

	wbuf->used = 0;
	wbuf->lnum = wbuf->offs = -1;
	/*
	 * If the LEB starts at the max. write size aligned address, then
	 * write-buffer size has to be set to @c->max_write_size. Otherwise,
	 * set it to something smaller so that it ends at the closest max.
	 * write size boundary.
	 */
	size = c->max_write_size - (c->leb_start % c->max_write_size);
	wbuf->avail = wbuf->size = size;
	wbuf->sync_callback = NULL;
	mutex_init(&wbuf->io_mutex);
	spin_lock_init(&wbuf->lock);
	wbuf->c = c;
	wbuf->next_ino = 0;

	hrtimer_init(&wbuf->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	wbuf->timer.function = wbuf_timer_callback_nolock;
	wbuf->softlimit = ktime_set(WBUF_TIMEOUT_SOFTLIMIT, 0);
	wbuf->delta = WBUF_TIMEOUT_HARDLIMIT - WBUF_TIMEOUT_SOFTLIMIT;
	wbuf->delta *= 1000000000ULL;
	ubifs_assert(wbuf->delta <= ULONG_MAX);
	return 0;
}

/**
 * ubifs_wbuf_add_ino_nolock - add an inode number into the wbuf inode array.
 * @wbuf: the write-buffer where to add
 * @inum: the inode number
 *
 * This function adds an inode number to the inode array of the write-buffer.
 */
void ubifs_wbuf_add_ino_nolock(struct ubifs_wbuf *wbuf, ino_t inum)
{
	if (!wbuf->buf)
		/* NOR flash or something similar */
		return;

	spin_lock(&wbuf->lock);
	if (wbuf->used)
		wbuf->inodes[wbuf->next_ino++] = inum;
	spin_unlock(&wbuf->lock);
}

/**
 * wbuf_has_ino - returns if the wbuf contains data from the inode.
 * @wbuf: the write-buffer
 * @inum: the inode number
 *
 * This function returns with %1 if the write-buffer contains some data from the
 * given inode otherwise it returns with %0.
 */
static int wbuf_has_ino(struct ubifs_wbuf *wbuf, ino_t inum)
{
	int i, ret = 0;

	spin_lock(&wbuf->lock);
	for (i = 0; i < wbuf->next_ino; i++)
		if (inum == wbuf->inodes[i]) {
			ret = 1;
			break;
		}
	spin_unlock(&wbuf->lock);

	return ret;
}

/**
 * ubifs_sync_wbufs_by_inode - synchronize write-buffers for an inode.
 * @c: UBIFS file-system description object
 * @inode: inode to synchronize
 *
 * This function synchronizes write-buffers which contain nodes belonging to
 * @inode. Returns zero in case of success and a negative error code in case of
 * failure.
 */
int ubifs_sync_wbufs_by_inode(struct ubifs_info *c, struct inode *inode)
{
	int i, err = 0;

	for (i = 0; i < c->jhead_cnt; i++) {
		struct ubifs_wbuf *wbuf = &c->jheads[i].wbuf;

		if (i == GCHD)
			/*
			 * GC head is special, do not look at it. Even if the
			 * head contains something related to this inode, it is
			 * a _copy_ of corresponding on-flash node which sits
			 * somewhere else.
			 */
			continue;

		if (!wbuf_has_ino(wbuf, inode->i_ino))
			continue;

		mutex_lock_nested(&wbuf->io_mutex, wbuf->jhead);
		if (wbuf_has_ino(wbuf, inode->i_ino))
			err = ubifs_wbuf_sync_nolock(wbuf);
		mutex_unlock(&wbuf->io_mutex);

		if (err) {
			ubifs_ro_mode(c, err);
			return err;
		}
	}
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/io.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements TNC (Tree Node Cache) which caches indexing nodes of
 * the UBIFS B-tree.
 *
 * At the moment the locking rules of the TNC tree are quite simple and
 * straightforward. We just have a mutex and lock it when we traverse the
 * tree. If a znode is not in memory, we read it from flash while still having
 * the mutex locked.
 */

// #include <linux/crc32.h>
// #include <linux/slab.h>
// #include "ubifs.h"

/*
 * Returned codes of 'matches_name()' and 'fallible_matches_name()' functions.
 * @NAME_LESS: name corresponding to the first argument is less than second
 * @NAME_MATCHES: names match
 * @NAME_GREATER: name corresponding to the second argument is greater than
 *                first
 * @NOT_ON_MEDIA: node referred by zbranch does not exist on the media
 *
 * These constants were introduce to improve readability.
 */
enum {
	NAME_LESS    = 0,
	NAME_MATCHES = 1,
	NAME_GREATER = 2,
	NOT_ON_MEDIA = 3,
};

/**
 * insert_old_idx - record an index node obsoleted since the last commit start.
 * @c: UBIFS file-system description object
 * @lnum: LEB number of obsoleted index node
 * @offs: offset of obsoleted index node
 *
 * Returns %0 on success, and a negative error code on failure.
 *
 * For recovery, there must always be a complete intact version of the index on
 * flash at all times. That is called the "old index". It is the index as at the
 * time of the last successful commit. Many of the index nodes in the old index
 * may be dirty, but they must not be erased until the next successful commit
 * (at which point that index becomes the old index).
 *
 * That means that the garbage collection and the in-the-gaps method of
 * committing must be able to determine if an index node is in the old index.
 * Most of the old index nodes can be found by looking up the TNC using the
 * 'lookup_znode()' function. However, some of the old index nodes may have
 * been deleted from the current index or may have been changed so much that
 * they cannot be easily found. In those cases, an entry is added to an RB-tree.
 * That is what this function does. The RB-tree is ordered by LEB number and
 * offset because they uniquely identify the old index node.
 */
static int insert_old_idx(struct ubifs_info *c, int lnum, int offs)
{
	struct ubifs_old_idx *old_idx, *o;
	struct rb_node **p, *parent = NULL;

	old_idx = kmalloc(sizeof(struct ubifs_old_idx), GFP_NOFS);
	if (unlikely(!old_idx))
		return -ENOMEM;
	old_idx->lnum = lnum;
	old_idx->offs = offs;

	p = &c->old_idx.rb_node;
	while (*p) {
		parent = *p;
		o = rb_entry(parent, struct ubifs_old_idx, rb);
		if (lnum < o->lnum)
			p = &(*p)->rb_left;
		else if (lnum > o->lnum)
			p = &(*p)->rb_right;
		else if (offs < o->offs)
			p = &(*p)->rb_left;
		else if (offs > o->offs)
			p = &(*p)->rb_right;
		else {
			ubifs_err("old idx added twice!");
			kfree(old_idx);
			return 0;
		}
	}
	rb_link_node(&old_idx->rb, parent, p);
	rb_insert_color(&old_idx->rb, &c->old_idx);
	return 0;
}

/**
 * insert_old_idx_znode - record a znode obsoleted since last commit start.
 * @c: UBIFS file-system description object
 * @znode: znode of obsoleted index node
 *
 * Returns %0 on success, and a negative error code on failure.
 */
int insert_old_idx_znode(struct ubifs_info *c, struct ubifs_znode *znode)
{
	if (znode->parent) {
		struct ubifs_zbranch *zbr;

		zbr = &znode->parent->zbranch[znode->iip];
		if (zbr->len)
			return insert_old_idx(c, zbr->lnum, zbr->offs);
	} else
		if (c->zroot.len)
			return insert_old_idx(c, c->zroot.lnum,
					      c->zroot.offs);
	return 0;
}

/**
 * ins_clr_old_idx_znode - record a znode obsoleted since last commit start.
 * @c: UBIFS file-system description object
 * @znode: znode of obsoleted index node
 *
 * Returns %0 on success, and a negative error code on failure.
 */
static int ins_clr_old_idx_znode(struct ubifs_info *c,
				 struct ubifs_znode *znode)
{
	int err;

	if (znode->parent) {
		struct ubifs_zbranch *zbr;

		zbr = &znode->parent->zbranch[znode->iip];
		if (zbr->len) {
			err = insert_old_idx(c, zbr->lnum, zbr->offs);
			if (err)
				return err;
			zbr->lnum = 0;
			zbr->offs = 0;
			zbr->len = 0;
		}
	} else
		if (c->zroot.len) {
			err = insert_old_idx(c, c->zroot.lnum, c->zroot.offs);
			if (err)
				return err;
			c->zroot.lnum = 0;
			c->zroot.offs = 0;
			c->zroot.len = 0;
		}
	return 0;
}

/**
 * destroy_old_idx - destroy the old_idx RB-tree.
 * @c: UBIFS file-system description object
 *
 * During start commit, the old_idx RB-tree is used to avoid overwriting index
 * nodes that were in the index last commit but have since been deleted.  This
 * is necessary for recovery i.e. the old index must be kept intact until the
 * new index is successfully written.  The old-idx RB-tree is used for the
 * in-the-gaps method of writing index nodes and is destroyed every commit.
 */
void destroy_old_idx(struct ubifs_info *c)
{
	struct ubifs_old_idx *old_idx, *n;

	rbtree_postorder_for_each_entry_safe(old_idx, n, &c->old_idx, rb)
		kfree(old_idx);

	c->old_idx = RB_ROOT;
}

/**
 * copy_znode - copy a dirty znode.
 * @c: UBIFS file-system description object
 * @znode: znode to copy
 *
 * A dirty znode being committed may not be changed, so it is copied.
 */
static struct ubifs_znode *copy_znode(struct ubifs_info *c,
				      struct ubifs_znode *znode)
{
	struct ubifs_znode *zn;

	zn = kmalloc(c->max_znode_sz, GFP_NOFS);
	if (unlikely(!zn))
		return ERR_PTR(-ENOMEM);

	memcpy(zn, znode, c->max_znode_sz);
	zn->cnext = NULL;
	__set_bit(DIRTY_ZNODE, &zn->flags);
	__clear_bit(COW_ZNODE, &zn->flags);

	ubifs_assert(!ubifs_zn_obsolete(znode));
	__set_bit(OBSOLETE_ZNODE, &znode->flags);

	if (znode->level != 0) {
		int i;
		const int n = zn->child_cnt;

		/* The children now have new parent */
		for (i = 0; i < n; i++) {
			struct ubifs_zbranch *zbr = &zn->zbranch[i];

			if (zbr->znode)
				zbr->znode->parent = zn;
		}
	}

	atomic_long_inc(&c->dirty_zn_cnt);
	return zn;
}

/**
 * add_idx_dirt - add dirt due to a dirty znode.
 * @c: UBIFS file-system description object
 * @lnum: LEB number of index node
 * @dirt: size of index node
 *
 * This function updates lprops dirty space and the new size of the index.
 */
static int add_idx_dirt(struct ubifs_info *c, int lnum, int dirt)
{
	c->calc_idx_sz -= ALIGN(dirt, 8);
	return ubifs_add_dirt(c, lnum, dirt);
}

/**
 * dirty_cow_znode - ensure a znode is not being committed.
 * @c: UBIFS file-system description object
 * @zbr: branch of znode to check
 *
 * Returns dirtied znode on success or negative error code on failure.
 */
static struct ubifs_znode *dirty_cow_znode(struct ubifs_info *c,
					   struct ubifs_zbranch *zbr)
{
	struct ubifs_znode *znode = zbr->znode;
	struct ubifs_znode *zn;
	int err;

	if (!ubifs_zn_cow(znode)) {
		/* znode is not being committed */
		if (!test_and_set_bit(DIRTY_ZNODE, &znode->flags)) {
			atomic_long_inc(&c->dirty_zn_cnt);
			atomic_long_dec(&c->clean_zn_cnt);
			atomic_long_dec(&ubifs_clean_zn_cnt);
			err = add_idx_dirt(c, zbr->lnum, zbr->len);
			if (unlikely(err))
				return ERR_PTR(err);
		}
		return znode;
	}

	zn = copy_znode(c, znode);
	if (IS_ERR(zn))
		return zn;

	if (zbr->len) {
		err = insert_old_idx(c, zbr->lnum, zbr->offs);
		if (unlikely(err))
			return ERR_PTR(err);
		err = add_idx_dirt(c, zbr->lnum, zbr->len);
	} else
		err = 0;

	zbr->znode = zn;
	zbr->lnum = 0;
	zbr->offs = 0;
	zbr->len = 0;

	if (unlikely(err))
		return ERR_PTR(err);
	return zn;
}

/**
 * lnc_add - add a leaf node to the leaf node cache.
 * @c: UBIFS file-system description object
 * @zbr: zbranch of leaf node
 * @node: leaf node
 *
 * Leaf nodes are non-index nodes directory entry nodes or data nodes. The
 * purpose of the leaf node cache is to save re-reading the same leaf node over
 * and over again. Most things are cached by VFS, however the file system must
 * cache directory entries for readdir and for resolving hash collisions. The
 * present implementation of the leaf node cache is extremely simple, and
 * allows for error returns that are not used but that may be needed if a more
 * complex implementation is created.
 *
 * Note, this function does not add the @node object to LNC directly, but
 * allocates a copy of the object and adds the copy to LNC. The reason for this
 * is that @node has been allocated outside of the TNC subsystem and will be
 * used with @c->tnc_mutex unlock upon return from the TNC subsystem. But LNC
 * may be changed at any time, e.g. freed by the shrinker.
 */
static int lnc_add(struct ubifs_info *c, struct ubifs_zbranch *zbr,
		   const void *node)
{
	int err;
	void *lnc_node;
	const struct ubifs_dent_node *dent = node;

	ubifs_assert(!zbr->leaf);
	ubifs_assert(zbr->len != 0);
	ubifs_assert(is_hash_key(c, &zbr->key));

	err = ubifs_validate_entry(c, dent);
	if (err) {
		dump_stack();
		ubifs_dump_node(c, dent);
		return err;
	}

	lnc_node = kmemdup(node, zbr->len, GFP_NOFS);
	if (!lnc_node)
		/* We don't have to have the cache, so no error */
		return 0;

	zbr->leaf = lnc_node;
	return 0;
}

 /**
 * lnc_add_directly - add a leaf node to the leaf-node-cache.
 * @c: UBIFS file-system description object
 * @zbr: zbranch of leaf node
 * @node: leaf node
 *
 * This function is similar to 'lnc_add()', but it does not create a copy of
 * @node but inserts @node to TNC directly.
 */
static int lnc_add_directly(struct ubifs_info *c, struct ubifs_zbranch *zbr,
			    void *node)
{
	int err;

	ubifs_assert(!zbr->leaf);
	ubifs_assert(zbr->len != 0);

	err = ubifs_validate_entry(c, node);
	if (err) {
		dump_stack();
		ubifs_dump_node(c, node);
		return err;
	}

	zbr->leaf = node;
	return 0;
}

/**
 * lnc_free - remove a leaf node from the leaf node cache.
 * @zbr: zbranch of leaf node
 * @node: leaf node
 */
static void lnc_free(struct ubifs_zbranch *zbr)
{
	if (!zbr->leaf)
		return;
	kfree(zbr->leaf);
	zbr->leaf = NULL;
}

/**
 * tnc_read_node_nm - read a "hashed" leaf node.
 * @c: UBIFS file-system description object
 * @zbr: key and position of the node
 * @node: node is returned here
 *
 * This function reads a "hashed" node defined by @zbr from the leaf node cache
 * (in it is there) or from the hash media, in which case the node is also
 * added to LNC. Returns zero in case of success or a negative negative error
 * code in case of failure.
 */
static int tnc_read_node_nm(struct ubifs_info *c, struct ubifs_zbranch *zbr,
			    void *node)
{
	int err;

	ubifs_assert(is_hash_key(c, &zbr->key));

	if (zbr->leaf) {
		/* Read from the leaf node cache */
		ubifs_assert(zbr->len != 0);
		memcpy(node, zbr->leaf, zbr->len);
		return 0;
	}

	err = ubifs_tnc_read_node(c, zbr, node);
	if (err)
		return err;

	/* Add the node to the leaf node cache */
	err = lnc_add(c, zbr, node);
	return err;
}

/**
 * try_read_node - read a node if it is a node.
 * @c: UBIFS file-system description object
 * @buf: buffer to read to
 * @type: node type
 * @len: node length (not aligned)
 * @lnum: LEB number of node to read
 * @offs: offset of node to read
 *
 * This function tries to read a node of known type and length, checks it and
 * stores it in @buf. This function returns %1 if a node is present and %0 if
 * a node is not present. A negative error code is returned for I/O errors.
 * This function performs that same function as ubifs_read_node except that
 * it does not require that there is actually a node present and instead
 * the return code indicates if a node was read.
 *
 * Note, this function does not check CRC of data nodes if @c->no_chk_data_crc
 * is true (it is controlled by corresponding mount option). However, if
 * @c->mounting or @c->remounting_rw is true (we are mounting or re-mounting to
 * R/W mode), @c->no_chk_data_crc is ignored and CRC is checked. This is
 * because during mounting or re-mounting from R/O mode to R/W mode we may read
 * journal nodes (when replying the journal or doing the recovery) and the
 * journal nodes may potentially be corrupted, so checking is required.
 */
static int try_read_node(const struct ubifs_info *c, void *buf, int type,
			 int len, int lnum, int offs)
{
	int err, node_len;
	struct ubifs_ch *ch = buf;
	uint32_t crc, node_crc;

	dbg_io("LEB %d:%d, %s, length %d", lnum, offs, dbg_ntype(type), len);

	err = ubifs_leb_read(c, lnum, buf, offs, len, 1);
	if (err) {
		ubifs_err("cannot read node type %d from LEB %d:%d, error %d",
			  type, lnum, offs, err);
		return err;
	}

	if (le32_to_cpu(ch->magic) != UBIFS_NODE_MAGIC)
		return 0;

	if (ch->node_type != type)
		return 0;

	node_len = le32_to_cpu(ch->len);
	if (node_len != len)
		return 0;

	if (type == UBIFS_DATA_NODE && c->no_chk_data_crc && !c->mounting &&
	    !c->remounting_rw)
		return 1;

	crc = crc32(UBIFS_CRC32_INIT, buf + 8, node_len - 8);
	node_crc = le32_to_cpu(ch->crc);
	if (crc != node_crc)
		return 0;

	return 1;
}

/**
 * fallible_read_node - try to read a leaf node.
 * @c: UBIFS file-system description object
 * @key:  key of node to read
 * @zbr:  position of node
 * @node: node returned
 *
 * This function tries to read a node and returns %1 if the node is read, %0
 * if the node is not present, and a negative error code in the case of error.
 */
static int fallible_read_node(struct ubifs_info *c, const union ubifs_key *key,
			      struct ubifs_zbranch *zbr, void *node)
{
	int ret;

	dbg_tnck(key, "LEB %d:%d, key ", zbr->lnum, zbr->offs);

	ret = try_read_node(c, node, key_type(c, key), zbr->len, zbr->lnum,
			    zbr->offs);
	if (ret == 1) {
		union ubifs_key node_key;
		struct ubifs_dent_node *dent = node;

		/* All nodes have key in the same place */
		key_read(c, &dent->key, &node_key);
		if (keys_cmp(c, key, &node_key) != 0)
			ret = 0;
	}
	if (ret == 0 && c->replaying)
		dbg_mntk(key, "dangling branch LEB %d:%d len %d, key ",
			zbr->lnum, zbr->offs, zbr->len);
	return ret;
}

/**
 * matches_name - determine if a direntry or xattr entry matches a given name.
 * @c: UBIFS file-system description object
 * @zbr: zbranch of dent
 * @nm: name to match
 *
 * This function checks if xentry/direntry referred by zbranch @zbr matches name
 * @nm. Returns %NAME_MATCHES if it does, %NAME_LESS if the name referred by
 * @zbr is less than @nm, and %NAME_GREATER if it is greater than @nm. In case
 * of failure, a negative error code is returned.
 */
static int matches_name(struct ubifs_info *c, struct ubifs_zbranch *zbr,
			const struct qstr *nm)
{
	struct ubifs_dent_node *dent;
	int nlen, err;

	/* If possible, match against the dent in the leaf node cache */
	if (!zbr->leaf) {
		dent = kmalloc(zbr->len, GFP_NOFS);
		if (!dent)
			return -ENOMEM;

		err = ubifs_tnc_read_node(c, zbr, dent);
		if (err)
			goto out_free;

		/* Add the node to the leaf node cache */
		err = lnc_add_directly(c, zbr, dent);
		if (err)
			goto out_free;
	} else
		dent = zbr->leaf;

	nlen = le16_to_cpu(dent->nlen);
	err = memcmp(dent->name, nm->name, min_t(int, nlen, nm->len));
	if (err == 0) {
		if (nlen == nm->len)
			return NAME_MATCHES;
		else if (nlen < nm->len)
			return NAME_LESS;
		else
			return NAME_GREATER;
	} else if (err < 0)
		return NAME_LESS;
	else
		return NAME_GREATER;

out_free:
	kfree(dent);
	return err;
}

/**
 * get_znode - get a TNC znode that may not be loaded yet.
 * @c: UBIFS file-system description object
 * @znode: parent znode
 * @n: znode branch slot number
 *
 * This function returns the znode or a negative error code.
 */
static struct ubifs_znode *get_znode(struct ubifs_info *c,
				     struct ubifs_znode *znode, int n)
{
	struct ubifs_zbranch *zbr;

	zbr = &znode->zbranch[n];
	if (zbr->znode)
		znode = zbr->znode;
	else
		znode = ubifs_load_znode(c, zbr, znode, n);
	return znode;
}

/**
 * tnc_next - find next TNC entry.
 * @c: UBIFS file-system description object
 * @zn: znode is passed and returned here
 * @n: znode branch slot number is passed and returned here
 *
 * This function returns %0 if the next TNC entry is found, %-ENOENT if there is
 * no next entry, or a negative error code otherwise.
 */
static int tnc_next(struct ubifs_info *c, struct ubifs_znode **zn, int *n)
{
	struct ubifs_znode *znode = *zn;
	int nn = *n;

	nn += 1;
	if (nn < znode->child_cnt) {
		*n = nn;
		return 0;
	}
	while (1) {
		struct ubifs_znode *zp;

		zp = znode->parent;
		if (!zp)
			return -ENOENT;
		nn = znode->iip + 1;
		znode = zp;
		if (nn < znode->child_cnt) {
			znode = get_znode(c, znode, nn);
			if (IS_ERR(znode))
				return PTR_ERR(znode);
			while (znode->level != 0) {
				znode = get_znode(c, znode, 0);
				if (IS_ERR(znode))
					return PTR_ERR(znode);
			}
			nn = 0;
			break;
		}
	}
	*zn = znode;
	*n = nn;
	return 0;
}

/**
 * tnc_prev - find previous TNC entry.
 * @c: UBIFS file-system description object
 * @zn: znode is returned here
 * @n: znode branch slot number is passed and returned here
 *
 * This function returns %0 if the previous TNC entry is found, %-ENOENT if
 * there is no next entry, or a negative error code otherwise.
 */
static int tnc_prev(struct ubifs_info *c, struct ubifs_znode **zn, int *n)
{
	struct ubifs_znode *znode = *zn;
	int nn = *n;

	if (nn > 0) {
		*n = nn - 1;
		return 0;
	}
	while (1) {
		struct ubifs_znode *zp;

		zp = znode->parent;
		if (!zp)
			return -ENOENT;
		nn = znode->iip - 1;
		znode = zp;
		if (nn >= 0) {
			znode = get_znode(c, znode, nn);
			if (IS_ERR(znode))
				return PTR_ERR(znode);
			while (znode->level != 0) {
				nn = znode->child_cnt - 1;
				znode = get_znode(c, znode, nn);
				if (IS_ERR(znode))
					return PTR_ERR(znode);
			}
			nn = znode->child_cnt - 1;
			break;
		}
	}
	*zn = znode;
	*n = nn;
	return 0;
}

/**
 * resolve_collision - resolve a collision.
 * @c: UBIFS file-system description object
 * @key: key of a directory or extended attribute entry
 * @zn: znode is returned here
 * @n: zbranch number is passed and returned here
 * @nm: name of the entry
 *
 * This function is called for "hashed" keys to make sure that the found key
 * really corresponds to the looked up node (directory or extended attribute
 * entry). It returns %1 and sets @zn and @n if the collision is resolved.
 * %0 is returned if @nm is not found and @zn and @n are set to the previous
 * entry, i.e. to the entry after which @nm could follow if it were in TNC.
 * This means that @n may be set to %-1 if the leftmost key in @zn is the
 * previous one. A negative error code is returned on failures.
 */
static int resolve_collision(struct ubifs_info *c, const union ubifs_key *key,
			     struct ubifs_znode **zn, int *n,
			     const struct qstr *nm)
{
	int err;

	err = matches_name(c, &(*zn)->zbranch[*n], nm);
	if (unlikely(err < 0))
		return err;
	if (err == NAME_MATCHES)
		return 1;

	if (err == NAME_GREATER) {
		/* Look left */
		while (1) {
			err = tnc_prev(c, zn, n);
			if (err == -ENOENT) {
				ubifs_assert(*n == 0);
				*n = -1;
				return 0;
			}
			if (err < 0)
				return err;
			if (keys_cmp(c, &(*zn)->zbranch[*n].key, key)) {
				/*
				 * We have found the branch after which we would
				 * like to insert, but inserting in this znode
				 * may still be wrong. Consider the following 3
				 * znodes, in the case where we are resolving a
				 * collision with Key2.
				 *
				 *                  znode zp
				 *            ----------------------
				 * level 1     |  Key0  |  Key1  |
				 *            -----------------------
				 *                 |            |
				 *       znode za  |            |  znode zb
				 *          ------------      ------------
				 * level 0  |  Key0  |        |  Key2  |
				 *          ------------      ------------
				 *
				 * The lookup finds Key2 in znode zb. Lets say
				 * there is no match and the name is greater so
				 * we look left. When we find Key0, we end up
				 * here. If we return now, we will insert into
				 * znode za at slot n = 1.  But that is invalid
				 * according to the parent's keys.  Key2 must
				 * be inserted into znode zb.
				 *
				 * Note, this problem is not relevant for the
				 * case when we go right, because
				 * 'tnc_insert()' would correct the parent key.
				 */
				if (*n == (*zn)->child_cnt - 1) {
					err = tnc_next(c, zn, n);
					if (err) {
						/* Should be impossible */
						ubifs_assert(0);
						if (err == -ENOENT)
							err = -EINVAL;
						return err;
					}
					ubifs_assert(*n == 0);
					*n = -1;
				}
				return 0;
			}
			err = matches_name(c, &(*zn)->zbranch[*n], nm);
			if (err < 0)
				return err;
			if (err == NAME_LESS)
				return 0;
			if (err == NAME_MATCHES)
				return 1;
			ubifs_assert(err == NAME_GREATER);
		}
	} else {
		int nn = *n;
		struct ubifs_znode *znode = *zn;

		/* Look right */
		while (1) {
			err = tnc_next(c, &znode, &nn);
			if (err == -ENOENT)
				return 0;
			if (err < 0)
				return err;
			if (keys_cmp(c, &znode->zbranch[nn].key, key))
				return 0;
			err = matches_name(c, &znode->zbranch[nn], nm);
			if (err < 0)
				return err;
			if (err == NAME_GREATER)
				return 0;
			*zn = znode;
			*n = nn;
			if (err == NAME_MATCHES)
				return 1;
			ubifs_assert(err == NAME_LESS);
		}
	}
}

/**
 * fallible_matches_name - determine if a dent matches a given name.
 * @c: UBIFS file-system description object
 * @zbr: zbranch of dent
 * @nm: name to match
 *
 * This is a "fallible" version of 'matches_name()' function which does not
 * panic if the direntry/xentry referred by @zbr does not exist on the media.
 *
 * This function checks if xentry/direntry referred by zbranch @zbr matches name
 * @nm. Returns %NAME_MATCHES it does, %NAME_LESS if the name referred by @zbr
 * is less than @nm, %NAME_GREATER if it is greater than @nm, and @NOT_ON_MEDIA
 * if xentry/direntry referred by @zbr does not exist on the media. A negative
 * error code is returned in case of failure.
 */
static int fallible_matches_name(struct ubifs_info *c,
				 struct ubifs_zbranch *zbr,
				 const struct qstr *nm)
{
	struct ubifs_dent_node *dent;
	int nlen, err;

	/* If possible, match against the dent in the leaf node cache */
	if (!zbr->leaf) {
		dent = kmalloc(zbr->len, GFP_NOFS);
		if (!dent)
			return -ENOMEM;

		err = fallible_read_node(c, &zbr->key, zbr, dent);
		if (err < 0)
			goto out_free;
		if (err == 0) {
			/* The node was not present */
			err = NOT_ON_MEDIA;
			goto out_free;
		}
		ubifs_assert(err == 1);

		err = lnc_add_directly(c, zbr, dent);
		if (err)
			goto out_free;
	} else
		dent = zbr->leaf;

	nlen = le16_to_cpu(dent->nlen);
	err = memcmp(dent->name, nm->name, min_t(int, nlen, nm->len));
	if (err == 0) {
		if (nlen == nm->len)
			return NAME_MATCHES;
		else if (nlen < nm->len)
			return NAME_LESS;
		else
			return NAME_GREATER;
	} else if (err < 0)
		return NAME_LESS;
	else
		return NAME_GREATER;

out_free:
	kfree(dent);
	return err;
}

/**
 * fallible_resolve_collision - resolve a collision even if nodes are missing.
 * @c: UBIFS file-system description object
 * @key: key
 * @zn: znode is returned here
 * @n: branch number is passed and returned here
 * @nm: name of directory entry
 * @adding: indicates caller is adding a key to the TNC
 *
 * This is a "fallible" version of the 'resolve_collision()' function which
 * does not panic if one of the nodes referred to by TNC does not exist on the
 * media. This may happen when replaying the journal if a deleted node was
 * Garbage-collected and the commit was not done. A branch that refers to a node
 * that is not present is called a dangling branch. The following are the return
 * codes for this function:
 *  o if @nm was found, %1 is returned and @zn and @n are set to the found
 *    branch;
 *  o if we are @adding and @nm was not found, %0 is returned;
 *  o if we are not @adding and @nm was not found, but a dangling branch was
 *    found, then %1 is returned and @zn and @n are set to the dangling branch;
 *  o a negative error code is returned in case of failure.
 */
static int fallible_resolve_collision(struct ubifs_info *c,
				      const union ubifs_key *key,
				      struct ubifs_znode **zn, int *n,
				      const struct qstr *nm, int adding)
{
	struct ubifs_znode *o_znode = NULL, *znode = *zn;
	int uninitialized_var(o_n), err, cmp, unsure = 0, nn = *n;

	cmp = fallible_matches_name(c, &znode->zbranch[nn], nm);
	if (unlikely(cmp < 0))
		return cmp;
	if (cmp == NAME_MATCHES)
		return 1;
	if (cmp == NOT_ON_MEDIA) {
		o_znode = znode;
		o_n = nn;
		/*
		 * We are unlucky and hit a dangling branch straight away.
		 * Now we do not really know where to go to find the needed
		 * branch - to the left or to the right. Well, let's try left.
		 */
		unsure = 1;
	} else if (!adding)
		unsure = 1; /* Remove a dangling branch wherever it is */

	if (cmp == NAME_GREATER || unsure) {
		/* Look left */
		while (1) {
			err = tnc_prev(c, zn, n);
			if (err == -ENOENT) {
				ubifs_assert(*n == 0);
				*n = -1;
				break;
			}
			if (err < 0)
				return err;
			if (keys_cmp(c, &(*zn)->zbranch[*n].key, key)) {
				/* See comments in 'resolve_collision()' */
				if (*n == (*zn)->child_cnt - 1) {
					err = tnc_next(c, zn, n);
					if (err) {
						/* Should be impossible */
						ubifs_assert(0);
						if (err == -ENOENT)
							err = -EINVAL;
						return err;
					}
					ubifs_assert(*n == 0);
					*n = -1;
				}
				break;
			}
			err = fallible_matches_name(c, &(*zn)->zbranch[*n], nm);
			if (err < 0)
				return err;
			if (err == NAME_MATCHES)
				return 1;
			if (err == NOT_ON_MEDIA) {
				o_znode = *zn;
				o_n = *n;
				continue;
			}
			if (!adding)
				continue;
			if (err == NAME_LESS)
				break;
			else
				unsure = 0;
		}
	}

	if (cmp == NAME_LESS || unsure) {
		/* Look right */
		*zn = znode;
		*n = nn;
		while (1) {
			err = tnc_next(c, &znode, &nn);
			if (err == -ENOENT)
				break;
			if (err < 0)
				return err;
			if (keys_cmp(c, &znode->zbranch[nn].key, key))
				break;
			err = fallible_matches_name(c, &znode->zbranch[nn], nm);
			if (err < 0)
				return err;
			if (err == NAME_GREATER)
				break;
			*zn = znode;
			*n = nn;
			if (err == NAME_MATCHES)
				return 1;
			if (err == NOT_ON_MEDIA) {
				o_znode = znode;
				o_n = nn;
			}
		}
	}

	/* Never match a dangling branch when adding */
	if (adding || !o_znode)
		return 0;

	dbg_mntk(key, "dangling match LEB %d:%d len %d key ",
		o_znode->zbranch[o_n].lnum, o_znode->zbranch[o_n].offs,
		o_znode->zbranch[o_n].len);
	*zn = o_znode;
	*n = o_n;
	return 1;
}

/**
 * matches_position - determine if a zbranch matches a given position.
 * @zbr: zbranch of dent
 * @lnum: LEB number of dent to match
 * @offs: offset of dent to match
 *
 * This function returns %1 if @lnum:@offs matches, and %0 otherwise.
 */
static int matches_position(struct ubifs_zbranch *zbr, int lnum, int offs)
{
	if (zbr->lnum == lnum && zbr->offs == offs)
		return 1;
	else
		return 0;
}

/**
 * resolve_collision_directly - resolve a collision directly.
 * @c: UBIFS file-system description object
 * @key: key of directory entry
 * @zn: znode is passed and returned here
 * @n: zbranch number is passed and returned here
 * @lnum: LEB number of dent node to match
 * @offs: offset of dent node to match
 *
 * This function is used for "hashed" keys to make sure the found directory or
 * extended attribute entry node is what was looked for. It is used when the
 * flash address of the right node is known (@lnum:@offs) which makes it much
 * easier to resolve collisions (no need to read entries and match full
 * names). This function returns %1 and sets @zn and @n if the collision is
 * resolved, %0 if @lnum:@offs is not found and @zn and @n are set to the
 * previous directory entry. Otherwise a negative error code is returned.
 */
static int resolve_collision_directly(struct ubifs_info *c,
				      const union ubifs_key *key,
				      struct ubifs_znode **zn, int *n,
				      int lnum, int offs)
{
	struct ubifs_znode *znode;
	int nn, err;

	znode = *zn;
	nn = *n;
	if (matches_position(&znode->zbranch[nn], lnum, offs))
		return 1;

	/* Look left */
	while (1) {
		err = tnc_prev(c, &znode, &nn);
		if (err == -ENOENT)
			break;
		if (err < 0)
			return err;
		if (keys_cmp(c, &znode->zbranch[nn].key, key))
			break;
		if (matches_position(&znode->zbranch[nn], lnum, offs)) {
			*zn = znode;
			*n = nn;
			return 1;
		}
	}

	/* Look right */
	znode = *zn;
	nn = *n;
	while (1) {
		err = tnc_next(c, &znode, &nn);
		if (err == -ENOENT)
			return 0;
		if (err < 0)
			return err;
		if (keys_cmp(c, &znode->zbranch[nn].key, key))
			return 0;
		*zn = znode;
		*n = nn;
		if (matches_position(&znode->zbranch[nn], lnum, offs))
			return 1;
	}
}

/**
 * dirty_cow_bottom_up - dirty a znode and its ancestors.
 * @c: UBIFS file-system description object
 * @znode: znode to dirty
 *
 * If we do not have a unique key that resides in a znode, then we cannot
 * dirty that znode from the top down (i.e. by using lookup_level0_dirty)
 * This function records the path back to the last dirty ancestor, and then
 * dirties the znodes on that path.
 */
static struct ubifs_znode *dirty_cow_bottom_up(struct ubifs_info *c,
					       struct ubifs_znode *znode)
{
	struct ubifs_znode *zp;
	int *path = c->bottom_up_buf, p = 0;

	ubifs_assert(c->zroot.znode);
	ubifs_assert(znode);
	if (c->zroot.znode->level > BOTTOM_UP_HEIGHT) {
		kfree(c->bottom_up_buf);
		c->bottom_up_buf = kmalloc(c->zroot.znode->level * sizeof(int),
					   GFP_NOFS);
		if (!c->bottom_up_buf)
			return ERR_PTR(-ENOMEM);
		path = c->bottom_up_buf;
	}
	if (c->zroot.znode->level) {
		/* Go up until parent is dirty */
		while (1) {
			int n;

			zp = znode->parent;
			if (!zp)
				break;
			n = znode->iip;
			ubifs_assert(p < c->zroot.znode->level);
			path[p++] = n;
			if (!zp->cnext && ubifs_zn_dirty(znode))
				break;
			znode = zp;
		}
	}

	/* Come back down, dirtying as we go */
	while (1) {
		struct ubifs_zbranch *zbr;

		zp = znode->parent;
		if (zp) {
			ubifs_assert(path[p - 1] >= 0);
			ubifs_assert(path[p - 1] < zp->child_cnt);
			zbr = &zp->zbranch[path[--p]];
			znode = dirty_cow_znode(c, zbr);
		} else {
			ubifs_assert(znode == c->zroot.znode);
			znode = dirty_cow_znode(c, &c->zroot);
		}
		if (IS_ERR(znode) || !p)
			break;
		ubifs_assert(path[p - 1] >= 0);
		ubifs_assert(path[p - 1] < znode->child_cnt);
		znode = znode->zbranch[path[p - 1]].znode;
	}

	return znode;
}

/**
 * ubifs_lookup_level0 - search for zero-level znode.
 * @c: UBIFS file-system description object
 * @key:  key to lookup
 * @zn: znode is returned here
 * @n: znode branch slot number is returned here
 *
 * This function looks up the TNC tree and search for zero-level znode which
 * refers key @key. The found zero-level znode is returned in @zn. There are 3
 * cases:
 *   o exact match, i.e. the found zero-level znode contains key @key, then %1
 *     is returned and slot number of the matched branch is stored in @n;
 *   o not exact match, which means that zero-level znode does not contain
 *     @key, then %0 is returned and slot number of the closest branch is stored
 *     in @n;
 *   o @key is so small that it is even less than the lowest key of the
 *     leftmost zero-level node, then %0 is returned and %0 is stored in @n.
 *
 * Note, when the TNC tree is traversed, some znodes may be absent, then this
 * function reads corresponding indexing nodes and inserts them to TNC. In
 * case of failure, a negative error code is returned.
 */
int ubifs_lookup_level0(struct ubifs_info *c, const union ubifs_key *key,
			struct ubifs_znode **zn, int *n)
{
	int err, exact;
	struct ubifs_znode *znode;
	unsigned long time = get_seconds();

	dbg_tnck(key, "search key ");
	ubifs_assert(key_type(c, key) < UBIFS_INVALID_KEY);

	znode = c->zroot.znode;
	if (unlikely(!znode)) {
		znode = ubifs_load_znode(c, &c->zroot, NULL, 0);
		if (IS_ERR(znode))
			return PTR_ERR(znode);
	}

	znode->time = time;

	while (1) {
		struct ubifs_zbranch *zbr;

		exact = ubifs_search_zbranch(c, znode, key, n);

		if (znode->level == 0)
			break;

		if (*n < 0)
			*n = 0;
		zbr = &znode->zbranch[*n];

		if (zbr->znode) {
			znode->time = time;
			znode = zbr->znode;
			continue;
		}

		/* znode is not in TNC cache, load it from the media */
		znode = ubifs_load_znode(c, zbr, znode, *n);
		if (IS_ERR(znode))
			return PTR_ERR(znode);
	}

	*zn = znode;
	if (exact || !is_hash_key(c, key) || *n != -1) {
		dbg_tnc("found %d, lvl %d, n %d", exact, znode->level, *n);
		return exact;
	}

	/*
	 * Here is a tricky place. We have not found the key and this is a
	 * "hashed" key, which may collide. The rest of the code deals with
	 * situations like this:
	 *
	 *                  | 3 | 5 |
	 *                  /       \
	 *          | 3 | 5 |      | 6 | 7 | (x)
	 *
	 * Or more a complex example:
	 *
	 *                | 1 | 5 |
	 *                /       \
	 *       | 1 | 3 |         | 5 | 8 |
	 *              \           /
	 *          | 5 | 5 |   | 6 | 7 | (x)
	 *
	 * In the examples, if we are looking for key "5", we may reach nodes
	 * marked with "(x)". In this case what we have do is to look at the
	 * left and see if there is "5" key there. If there is, we have to
	 * return it.
	 *
	 * Note, this whole situation is possible because we allow to have
	 * elements which are equivalent to the next key in the parent in the
	 * children of current znode. For example, this happens if we split a
	 * znode like this: | 3 | 5 | 5 | 6 | 7 |, which results in something
	 * like this:
	 *                      | 3 | 5 |
	 *                       /     \
	 *                | 3 | 5 |   | 5 | 6 | 7 |
	 *                              ^
	 * And this becomes what is at the first "picture" after key "5" marked
	 * with "^" is removed. What could be done is we could prohibit
	 * splitting in the middle of the colliding sequence. Also, when
	 * removing the leftmost key, we would have to correct the key of the
	 * parent node, which would introduce additional complications. Namely,
	 * if we changed the leftmost key of the parent znode, the garbage
	 * collector would be unable to find it (GC is doing this when GC'ing
	 * indexing LEBs). Although we already have an additional RB-tree where
	 * we save such changed znodes (see 'ins_clr_old_idx_znode()') until
	 * after the commit. But anyway, this does not look easy to implement
	 * so we did not try this.
	 */
	err = tnc_prev(c, &znode, n);
	if (err == -ENOENT) {
		dbg_tnc("found 0, lvl %d, n -1", znode->level);
		*n = -1;
		return 0;
	}
	if (unlikely(err < 0))
		return err;
	if (keys_cmp(c, key, &znode->zbranch[*n].key)) {
		dbg_tnc("found 0, lvl %d, n -1", znode->level);
		*n = -1;
		return 0;
	}

	dbg_tnc("found 1, lvl %d, n %d", znode->level, *n);
	*zn = znode;
	return 1;
}

/**
 * lookup_level0_dirty - search for zero-level znode dirtying.
 * @c: UBIFS file-system description object
 * @key:  key to lookup
 * @zn: znode is returned here
 * @n: znode branch slot number is returned here
 *
 * This function looks up the TNC tree and search for zero-level znode which
 * refers key @key. The found zero-level znode is returned in @zn. There are 3
 * cases:
 *   o exact match, i.e. the found zero-level znode contains key @key, then %1
 *     is returned and slot number of the matched branch is stored in @n;
 *   o not exact match, which means that zero-level znode does not contain @key
 *     then %0 is returned and slot number of the closed branch is stored in
 *     @n;
 *   o @key is so small that it is even less than the lowest key of the
 *     leftmost zero-level node, then %0 is returned and %-1 is stored in @n.
 *
 * Additionally all znodes in the path from the root to the located zero-level
 * znode are marked as dirty.
 *
 * Note, when the TNC tree is traversed, some znodes may be absent, then this
 * function reads corresponding indexing nodes and inserts them to TNC. In
 * case of failure, a negative error code is returned.
 */
static int lookup_level0_dirty(struct ubifs_info *c, const union ubifs_key *key,
			       struct ubifs_znode **zn, int *n)
{
	int err, exact;
	struct ubifs_znode *znode;
	unsigned long time = get_seconds();

	dbg_tnck(key, "search and dirty key ");

	znode = c->zroot.znode;
	if (unlikely(!znode)) {
		znode = ubifs_load_znode(c, &c->zroot, NULL, 0);
		if (IS_ERR(znode))
			return PTR_ERR(znode);
	}

	znode = dirty_cow_znode(c, &c->zroot);
	if (IS_ERR(znode))
		return PTR_ERR(znode);

	znode->time = time;

	while (1) {
		struct ubifs_zbranch *zbr;

		exact = ubifs_search_zbranch(c, znode, key, n);

		if (znode->level == 0)
			break;

		if (*n < 0)
			*n = 0;
		zbr = &znode->zbranch[*n];

		if (zbr->znode) {
			znode->time = time;
			znode = dirty_cow_znode(c, zbr);
			if (IS_ERR(znode))
				return PTR_ERR(znode);
			continue;
		}

		/* znode is not in TNC cache, load it from the media */
		znode = ubifs_load_znode(c, zbr, znode, *n);
		if (IS_ERR(znode))
			return PTR_ERR(znode);
		znode = dirty_cow_znode(c, zbr);
		if (IS_ERR(znode))
			return PTR_ERR(znode);
	}

	*zn = znode;
	if (exact || !is_hash_key(c, key) || *n != -1) {
		dbg_tnc("found %d, lvl %d, n %d", exact, znode->level, *n);
		return exact;
	}

	/*
	 * See huge comment at 'lookup_level0_dirty()' what is the rest of the
	 * code.
	 */
	err = tnc_prev(c, &znode, n);
	if (err == -ENOENT) {
		*n = -1;
		dbg_tnc("found 0, lvl %d, n -1", znode->level);
		return 0;
	}
	if (unlikely(err < 0))
		return err;
	if (keys_cmp(c, key, &znode->zbranch[*n].key)) {
		*n = -1;
		dbg_tnc("found 0, lvl %d, n -1", znode->level);
		return 0;
	}

	if (znode->cnext || !ubifs_zn_dirty(znode)) {
		znode = dirty_cow_bottom_up(c, znode);
		if (IS_ERR(znode))
			return PTR_ERR(znode);
	}

	dbg_tnc("found 1, lvl %d, n %d", znode->level, *n);
	*zn = znode;
	return 1;
}

/**
 * maybe_leb_gced - determine if a LEB may have been garbage collected.
 * @c: UBIFS file-system description object
 * @lnum: LEB number
 * @gc_seq1: garbage collection sequence number
 *
 * This function determines if @lnum may have been garbage collected since
 * sequence number @gc_seq1. If it may have been then %1 is returned, otherwise
 * %0 is returned.
 */
static int maybe_leb_gced(struct ubifs_info *c, int lnum, int gc_seq1)
{
	int gc_seq2, gced_lnum;

	gced_lnum = c->gced_lnum;
	smp_rmb();
	gc_seq2 = c->gc_seq;
	/* Same seq means no GC */
	if (gc_seq1 == gc_seq2)
		return 0;
	/* Different by more than 1 means we don't know */
	if (gc_seq1 + 1 != gc_seq2)
		return 1;
	/*
	 * We have seen the sequence number has increased by 1. Now we need to
	 * be sure we read the right LEB number, so read it again.
	 */
	smp_rmb();
	if (gced_lnum != c->gced_lnum)
		return 1;
	/* Finally we can check lnum */
	if (gced_lnum == lnum)
		return 1;
	return 0;
}

/**
 * ubifs_tnc_locate - look up a file-system node and return it and its location.
 * @c: UBIFS file-system description object
 * @key: node key to lookup
 * @node: the node is returned here
 * @lnum: LEB number is returned here
 * @offs: offset is returned here
 *
 * This function looks up and reads node with key @key. The caller has to make
 * sure the @node buffer is large enough to fit the node. Returns zero in case
 * of success, %-ENOENT if the node was not found, and a negative error code in
 * case of failure. The node location can be returned in @lnum and @offs.
 */
int ubifs_tnc_locate(struct ubifs_info *c, const union ubifs_key *key,
		     void *node, int *lnum, int *offs)
{
	int found, n, err, safely = 0, gc_seq1;
	struct ubifs_znode *znode;
	struct ubifs_zbranch zbr, *zt;

again:
	mutex_lock(&c->tnc_mutex);
	found = ubifs_lookup_level0(c, key, &znode, &n);
	if (!found) {
		err = -ENOENT;
		goto out;
	} else if (found < 0) {
		err = found;
		goto out;
	}
	zt = &znode->zbranch[n];
	if (lnum) {
		*lnum = zt->lnum;
		*offs = zt->offs;
	}
	if (is_hash_key(c, key)) {
		/*
		 * In this case the leaf node cache gets used, so we pass the
		 * address of the zbranch and keep the mutex locked
		 */
		err = tnc_read_node_nm(c, zt, node);
		goto out;
	}
	if (safely) {
		err = ubifs_tnc_read_node(c, zt, node);
		goto out;
	}
	/* Drop the TNC mutex prematurely and race with garbage collection */
	zbr = znode->zbranch[n];
	gc_seq1 = c->gc_seq;
	mutex_unlock(&c->tnc_mutex);

	if (ubifs_get_wbuf(c, zbr.lnum)) {
		/* We do not GC journal heads */
		err = ubifs_tnc_read_node(c, &zbr, node);
		return err;
	}

	err = fallible_read_node(c, key, &zbr, node);
	if (err <= 0 || maybe_leb_gced(c, zbr.lnum, gc_seq1)) {
		/*
		 * The node may have been GC'ed out from under us so try again
		 * while keeping the TNC mutex locked.
		 */
		safely = 1;
		goto again;
	}
	return 0;

out:
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * ubifs_tnc_get_bu_keys - lookup keys for bulk-read.
 * @c: UBIFS file-system description object
 * @bu: bulk-read parameters and results
 *
 * Lookup consecutive data node keys for the same inode that reside
 * consecutively in the same LEB. This function returns zero in case of success
 * and a negative error code in case of failure.
 *
 * Note, if the bulk-read buffer length (@bu->buf_len) is known, this function
 * makes sure bulk-read nodes fit the buffer. Otherwise, this function prepares
 * maximum possible amount of nodes for bulk-read.
 */
int ubifs_tnc_get_bu_keys(struct ubifs_info *c, struct bu_info *bu)
{
	int n, err = 0, lnum = -1, uninitialized_var(offs);
	int uninitialized_var(len);
	unsigned int block = key_block(c, &bu->key);
	struct ubifs_znode *znode;

	bu->cnt = 0;
	bu->blk_cnt = 0;
	bu->eof = 0;

	mutex_lock(&c->tnc_mutex);
	/* Find first key */
	err = ubifs_lookup_level0(c, &bu->key, &znode, &n);
	if (err < 0)
		goto out;
	if (err) {
		/* Key found */
		len = znode->zbranch[n].len;
		/* The buffer must be big enough for at least 1 node */
		if (len > bu->buf_len) {
			err = -EINVAL;
			goto out;
		}
		/* Add this key */
		bu->zbranch[bu->cnt++] = znode->zbranch[n];
		bu->blk_cnt += 1;
		lnum = znode->zbranch[n].lnum;
		offs = ALIGN(znode->zbranch[n].offs + len, 8);
	}
	while (1) {
		struct ubifs_zbranch *zbr;
		union ubifs_key *key;
		unsigned int next_block;

		/* Find next key */
		err = tnc_next(c, &znode, &n);
		if (err)
			goto out;
		zbr = &znode->zbranch[n];
		key = &zbr->key;
		/* See if there is another data key for this file */
		if (key_inum(c, key) != key_inum(c, &bu->key) ||
		    key_type(c, key) != UBIFS_DATA_KEY) {
			err = -ENOENT;
			goto out;
		}
		if (lnum < 0) {
			/* First key found */
			lnum = zbr->lnum;
			offs = ALIGN(zbr->offs + zbr->len, 8);
			len = zbr->len;
			if (len > bu->buf_len) {
				err = -EINVAL;
				goto out;
			}
		} else {
			/*
			 * The data nodes must be in consecutive positions in
			 * the same LEB.
			 */
			if (zbr->lnum != lnum || zbr->offs != offs)
				goto out;
			offs += ALIGN(zbr->len, 8);
			len = ALIGN(len, 8) + zbr->len;
			/* Must not exceed buffer length */
			if (len > bu->buf_len)
				goto out;
		}
		/* Allow for holes */
		next_block = key_block(c, key);
		bu->blk_cnt += (next_block - block - 1);
		if (bu->blk_cnt >= UBIFS_MAX_BULK_READ)
			goto out;
		block = next_block;
		/* Add this key */
		bu->zbranch[bu->cnt++] = *zbr;
		bu->blk_cnt += 1;
		/* See if we have room for more */
		if (bu->cnt >= UBIFS_MAX_BULK_READ)
			goto out;
		if (bu->blk_cnt >= UBIFS_MAX_BULK_READ)
			goto out;
	}
out:
	if (err == -ENOENT) {
		bu->eof = 1;
		err = 0;
	}
	bu->gc_seq = c->gc_seq;
	mutex_unlock(&c->tnc_mutex);
	if (err)
		return err;
	/*
	 * An enormous hole could cause bulk-read to encompass too many
	 * page cache pages, so limit the number here.
	 */
	if (bu->blk_cnt > UBIFS_MAX_BULK_READ)
		bu->blk_cnt = UBIFS_MAX_BULK_READ;
	/*
	 * Ensure that bulk-read covers a whole number of page cache
	 * pages.
	 */
	if (UBIFS_BLOCKS_PER_PAGE == 1 ||
	    !(bu->blk_cnt & (UBIFS_BLOCKS_PER_PAGE - 1)))
		return 0;
	if (bu->eof) {
		/* At the end of file we can round up */
		bu->blk_cnt += UBIFS_BLOCKS_PER_PAGE - 1;
		return 0;
	}
	/* Exclude data nodes that do not make up a whole page cache page */
	block = key_block(c, &bu->key) + bu->blk_cnt;
	block &= ~(UBIFS_BLOCKS_PER_PAGE - 1);
	while (bu->cnt) {
		if (key_block(c, &bu->zbranch[bu->cnt - 1].key) < block)
			break;
		bu->cnt -= 1;
	}
	return 0;
}

/**
 * read_wbuf - bulk-read from a LEB with a wbuf.
 * @wbuf: wbuf that may overlap the read
 * @buf: buffer into which to read
 * @len: read length
 * @lnum: LEB number from which to read
 * @offs: offset from which to read
 *
 * This functions returns %0 on success or a negative error code on failure.
 */
static int read_wbuf(struct ubifs_wbuf *wbuf, void *buf, int len, int lnum,
		     int offs)
{
	const struct ubifs_info *c = wbuf->c;
	int rlen, overlap;

	dbg_io("LEB %d:%d, length %d", lnum, offs, len);
	ubifs_assert(wbuf && lnum >= 0 && lnum < c->leb_cnt && offs >= 0);
	ubifs_assert(!(offs & 7) && offs < c->leb_size);
	ubifs_assert(offs + len <= c->leb_size);

	spin_lock(&wbuf->lock);
	overlap = (lnum == wbuf->lnum && offs + len > wbuf->offs);
	if (!overlap) {
		/* We may safely unlock the write-buffer and read the data */
		spin_unlock(&wbuf->lock);
		return ubifs_leb_read(c, lnum, buf, offs, len, 0);
	}

	/* Don't read under wbuf */
	rlen = wbuf->offs - offs;
	if (rlen < 0)
		rlen = 0;

	/* Copy the rest from the write-buffer */
	memcpy(buf + rlen, wbuf->buf + offs + rlen - wbuf->offs, len - rlen);
	spin_unlock(&wbuf->lock);

	if (rlen > 0)
		/* Read everything that goes before write-buffer */
		return ubifs_leb_read(c, lnum, buf, offs, rlen, 0);

	return 0;
}

/**
 * validate_data_node - validate data nodes for bulk-read.
 * @c: UBIFS file-system description object
 * @buf: buffer containing data node to validate
 * @zbr: zbranch of data node to validate
 *
 * This functions returns %0 on success or a negative error code on failure.
 */
static int validate_data_node(struct ubifs_info *c, void *buf,
			      struct ubifs_zbranch *zbr)
{
	union ubifs_key key1;
	struct ubifs_ch *ch = buf;
	int err, len;

	if (ch->node_type != UBIFS_DATA_NODE) {
		ubifs_err("bad node type (%d but expected %d)",
			  ch->node_type, UBIFS_DATA_NODE);
		goto out_err;
	}

	err = ubifs_check_node(c, buf, zbr->lnum, zbr->offs, 0, 0);
	if (err) {
		ubifs_err("expected node type %d", UBIFS_DATA_NODE);
		goto out;
	}

	len = le32_to_cpu(ch->len);
	if (len != zbr->len) {
		ubifs_err("bad node length %d, expected %d", len, zbr->len);
		goto out_err;
	}

	/* Make sure the key of the read node is correct */
	key_read(c, buf + UBIFS_KEY_OFFSET, &key1);
	if (!keys_eq(c, &zbr->key, &key1)) {
		ubifs_err("bad key in node at LEB %d:%d",
			  zbr->lnum, zbr->offs);
		dbg_tnck(&zbr->key, "looked for key ");
		dbg_tnck(&key1, "found node's key ");
		goto out_err;
	}

	return 0;

out_err:
	err = -EINVAL;
out:
	ubifs_err("bad node at LEB %d:%d", zbr->lnum, zbr->offs);
	ubifs_dump_node(c, buf);
	dump_stack();
	return err;
}

/**
 * ubifs_tnc_bulk_read - read a number of data nodes in one go.
 * @c: UBIFS file-system description object
 * @bu: bulk-read parameters and results
 *
 * This functions reads and validates the data nodes that were identified by the
 * 'ubifs_tnc_get_bu_keys()' function. This functions returns %0 on success,
 * -EAGAIN to indicate a race with GC, or another negative error code on
 * failure.
 */
int ubifs_tnc_bulk_read(struct ubifs_info *c, struct bu_info *bu)
{
	int lnum = bu->zbranch[0].lnum, offs = bu->zbranch[0].offs, len, err, i;
	struct ubifs_wbuf *wbuf;
	void *buf;

	len = bu->zbranch[bu->cnt - 1].offs;
	len += bu->zbranch[bu->cnt - 1].len - offs;
	if (len > bu->buf_len) {
		ubifs_err("buffer too small %d vs %d", bu->buf_len, len);
		return -EINVAL;
	}

	/* Do the read */
	wbuf = ubifs_get_wbuf(c, lnum);
	if (wbuf)
		err = read_wbuf(wbuf, bu->buf, len, lnum, offs);
	else
		err = ubifs_leb_read(c, lnum, bu->buf, offs, len, 0);

	/* Check for a race with GC */
	if (maybe_leb_gced(c, lnum, bu->gc_seq))
		return -EAGAIN;

	if (err && err != -EBADMSG) {
		ubifs_err("failed to read from LEB %d:%d, error %d",
			  lnum, offs, err);
		dump_stack();
		dbg_tnck(&bu->key, "key ");
		return err;
	}

	/* Validate the nodes read */
	buf = bu->buf;
	for (i = 0; i < bu->cnt; i++) {
		err = validate_data_node(c, buf, &bu->zbranch[i]);
		if (err)
			return err;
		buf = buf + ALIGN(bu->zbranch[i].len, 8);
	}

	return 0;
}

/**
 * do_lookup_nm- look up a "hashed" node.
 * @c: UBIFS file-system description object
 * @key: node key to lookup
 * @node: the node is returned here
 * @nm: node name
 *
 * This function look up and reads a node which contains name hash in the key.
 * Since the hash may have collisions, there may be many nodes with the same
 * key, so we have to sequentially look to all of them until the needed one is
 * found. This function returns zero in case of success, %-ENOENT if the node
 * was not found, and a negative error code in case of failure.
 */
static int do_lookup_nm(struct ubifs_info *c, const union ubifs_key *key,
			void *node, const struct qstr *nm)
{
	int found, n, err;
	struct ubifs_znode *znode;

	dbg_tnck(key, "name '%.*s' key ", nm->len, nm->name);
	mutex_lock(&c->tnc_mutex);
	found = ubifs_lookup_level0(c, key, &znode, &n);
	if (!found) {
		err = -ENOENT;
		goto out_unlock;
	} else if (found < 0) {
		err = found;
		goto out_unlock;
	}

	ubifs_assert(n >= 0);

	err = resolve_collision(c, key, &znode, &n, nm);
	dbg_tnc("rc returned %d, znode %p, n %d", err, znode, n);
	if (unlikely(err < 0))
		goto out_unlock;
	if (err == 0) {
		err = -ENOENT;
		goto out_unlock;
	}

	err = tnc_read_node_nm(c, &znode->zbranch[n], node);

out_unlock:
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * ubifs_tnc_lookup_nm - look up a "hashed" node.
 * @c: UBIFS file-system description object
 * @key: node key to lookup
 * @node: the node is returned here
 * @nm: node name
 *
 * This function look up and reads a node which contains name hash in the key.
 * Since the hash may have collisions, there may be many nodes with the same
 * key, so we have to sequentially look to all of them until the needed one is
 * found. This function returns zero in case of success, %-ENOENT if the node
 * was not found, and a negative error code in case of failure.
 */
int ubifs_tnc_lookup_nm(struct ubifs_info *c, const union ubifs_key *key,
			void *node, const struct qstr *nm)
{
	int err, len;
	const struct ubifs_dent_node *dent = node;

	/*
	 * We assume that in most of the cases there are no name collisions and
	 * 'ubifs_tnc_lookup()' returns us the right direntry.
	 */
	err = ubifs_tnc_lookup(c, key, node);
	if (err)
		return err;

	len = le16_to_cpu(dent->nlen);
	if (nm->len == len && !memcmp(dent->name, nm->name, len))
		return 0;

	/*
	 * Unluckily, there are hash collisions and we have to iterate over
	 * them look at each direntry with colliding name hash sequentially.
	 */
	return do_lookup_nm(c, key, node, nm);
}

/**
 * correct_parent_keys - correct parent znodes' keys.
 * @c: UBIFS file-system description object
 * @znode: znode to correct parent znodes for
 *
 * This is a helper function for 'tnc_insert()'. When the key of the leftmost
 * zbranch changes, keys of parent znodes have to be corrected. This helper
 * function is called in such situations and corrects the keys if needed.
 */
static void correct_parent_keys(const struct ubifs_info *c,
				struct ubifs_znode *znode)
{
	union ubifs_key *key, *key1;

	ubifs_assert(znode->parent);
	ubifs_assert(znode->iip == 0);

	key = &znode->zbranch[0].key;
	key1 = &znode->parent->zbranch[0].key;

	while (keys_cmp(c, key, key1) < 0) {
		key_copy(c, key, key1);
		znode = znode->parent;
		znode->alt = 1;
		if (!znode->parent || znode->iip)
			break;
		key1 = &znode->parent->zbranch[0].key;
	}
}

/**
 * insert_zbranch - insert a zbranch into a znode.
 * @znode: znode into which to insert
 * @zbr: zbranch to insert
 * @n: slot number to insert to
 *
 * This is a helper function for 'tnc_insert()'. UBIFS does not allow "gaps" in
 * znode's array of zbranches and keeps zbranches consolidated, so when a new
 * zbranch has to be inserted to the @znode->zbranches[]' array at the @n-th
 * slot, zbranches starting from @n have to be moved right.
 */
static void insert_zbranch(struct ubifs_znode *znode,
			   const struct ubifs_zbranch *zbr, int n)
{
	int i;

	ubifs_assert(ubifs_zn_dirty(znode));

	if (znode->level) {
		for (i = znode->child_cnt; i > n; i--) {
			znode->zbranch[i] = znode->zbranch[i - 1];
			if (znode->zbranch[i].znode)
				znode->zbranch[i].znode->iip = i;
		}
		if (zbr->znode)
			zbr->znode->iip = n;
	} else
		for (i = znode->child_cnt; i > n; i--)
			znode->zbranch[i] = znode->zbranch[i - 1];

	znode->zbranch[n] = *zbr;
	znode->child_cnt += 1;

	/*
	 * After inserting at slot zero, the lower bound of the key range of
	 * this znode may have changed. If this znode is subsequently split
	 * then the upper bound of the key range may change, and furthermore
	 * it could change to be lower than the original lower bound. If that
	 * happens, then it will no longer be possible to find this znode in the
	 * TNC using the key from the index node on flash. That is bad because
	 * if it is not found, we will assume it is obsolete and may overwrite
	 * it. Then if there is an unclean unmount, we will start using the
	 * old index which will be broken.
	 *
	 * So we first mark znodes that have insertions at slot zero, and then
	 * if they are split we add their lnum/offs to the old_idx tree.
	 */
	if (n == 0)
		znode->alt = 1;
}

/**
 * tnc_insert - insert a node into TNC.
 * @c: UBIFS file-system description object
 * @znode: znode to insert into
 * @zbr: branch to insert
 * @n: slot number to insert new zbranch to
 *
 * This function inserts a new node described by @zbr into znode @znode. If
 * znode does not have a free slot for new zbranch, it is split. Parent znodes
 * are splat as well if needed. Returns zero in case of success or a negative
 * error code in case of failure.
 */
static int tnc_insert(struct ubifs_info *c, struct ubifs_znode *znode,
		      struct ubifs_zbranch *zbr, int n)
{
	struct ubifs_znode *zn, *zi, *zp;
	int i, keep, move, appending = 0;
	union ubifs_key *key = &zbr->key, *key1;

	ubifs_assert(n >= 0 && n <= c->fanout);

	/* Implement naive insert for now */
again:
	zp = znode->parent;
	if (znode->child_cnt < c->fanout) {
		ubifs_assert(n != c->fanout);
		dbg_tnck(key, "inserted at %d level %d, key ", n, znode->level);

		insert_zbranch(znode, zbr, n);

		/* Ensure parent's key is correct */
		if (n == 0 && zp && znode->iip == 0)
			correct_parent_keys(c, znode);

		return 0;
	}

	/*
	 * Unfortunately, @znode does not have more empty slots and we have to
	 * split it.
	 */
	dbg_tnck(key, "splitting level %d, key ", znode->level);

	if (znode->alt)
		/*
		 * We can no longer be sure of finding this znode by key, so we
		 * record it in the old_idx tree.
		 */
		ins_clr_old_idx_znode(c, znode);

	zn = kzalloc(c->max_znode_sz, GFP_NOFS);
	if (!zn)
		return -ENOMEM;
	zn->parent = zp;
	zn->level = znode->level;

	/* Decide where to split */
	if (znode->level == 0 && key_type(c, key) == UBIFS_DATA_KEY) {
		/* Try not to split consecutive data keys */
		if (n == c->fanout) {
			key1 = &znode->zbranch[n - 1].key;
			if (key_inum(c, key1) == key_inum(c, key) &&
			    key_type(c, key1) == UBIFS_DATA_KEY)
				appending = 1;
		} else
			goto check_split;
	} else if (appending && n != c->fanout) {
		/* Try not to split consecutive data keys */
		appending = 0;
check_split:
		if (n >= (c->fanout + 1) / 2) {
			key1 = &znode->zbranch[0].key;
			if (key_inum(c, key1) == key_inum(c, key) &&
			    key_type(c, key1) == UBIFS_DATA_KEY) {
				key1 = &znode->zbranch[n].key;
				if (key_inum(c, key1) != key_inum(c, key) ||
				    key_type(c, key1) != UBIFS_DATA_KEY) {
					keep = n;
					move = c->fanout - keep;
					zi = znode;
					goto do_split;
				}
			}
		}
	}

	if (appending) {
		keep = c->fanout;
		move = 0;
	} else {
		keep = (c->fanout + 1) / 2;
		move = c->fanout - keep;
	}

	/*
	 * Although we don't at present, we could look at the neighbors and see
	 * if we can move some zbranches there.
	 */

	if (n < keep) {
		/* Insert into existing znode */
		zi = znode;
		move += 1;
		keep -= 1;
	} else {
		/* Insert into new znode */
		zi = zn;
		n -= keep;
		/* Re-parent */
		if (zn->level != 0)
			zbr->znode->parent = zn;
	}

do_split:

	__set_bit(DIRTY_ZNODE, &zn->flags);
	atomic_long_inc(&c->dirty_zn_cnt);

	zn->child_cnt = move;
	znode->child_cnt = keep;

	dbg_tnc("moving %d, keeping %d", move, keep);

	/* Move zbranch */
	for (i = 0; i < move; i++) {
		zn->zbranch[i] = znode->zbranch[keep + i];
		/* Re-parent */
		if (zn->level != 0)
			if (zn->zbranch[i].znode) {
				zn->zbranch[i].znode->parent = zn;
				zn->zbranch[i].znode->iip = i;
			}
	}

	/* Insert new key and branch */
	dbg_tnck(key, "inserting at %d level %d, key ", n, zn->level);

	insert_zbranch(zi, zbr, n);

	/* Insert new znode (produced by spitting) into the parent */
	if (zp) {
		if (n == 0 && zi == znode && znode->iip == 0)
			correct_parent_keys(c, znode);

		/* Locate insertion point */
		n = znode->iip + 1;

		/* Tail recursion */
		zbr->key = zn->zbranch[0].key;
		zbr->znode = zn;
		zbr->lnum = 0;
		zbr->offs = 0;
		zbr->len = 0;
		znode = zp;

		goto again;
	}

	/* We have to split root znode */
	dbg_tnc("creating new zroot at level %d", znode->level + 1);

	zi = kzalloc(c->max_znode_sz, GFP_NOFS);
	if (!zi)
		return -ENOMEM;

	zi->child_cnt = 2;
	zi->level = znode->level + 1;

	__set_bit(DIRTY_ZNODE, &zi->flags);
	atomic_long_inc(&c->dirty_zn_cnt);

	zi->zbranch[0].key = znode->zbranch[0].key;
	zi->zbranch[0].znode = znode;
	zi->zbranch[0].lnum = c->zroot.lnum;
	zi->zbranch[0].offs = c->zroot.offs;
	zi->zbranch[0].len = c->zroot.len;
	zi->zbranch[1].key = zn->zbranch[0].key;
	zi->zbranch[1].znode = zn;

	c->zroot.lnum = 0;
	c->zroot.offs = 0;
	c->zroot.len = 0;
	c->zroot.znode = zi;

	zn->parent = zi;
	zn->iip = 1;
	znode->parent = zi;
	znode->iip = 0;

	return 0;
}

/**
 * ubifs_tnc_add - add a node to TNC.
 * @c: UBIFS file-system description object
 * @key: key to add
 * @lnum: LEB number of node
 * @offs: node offset
 * @len: node length
 *
 * This function adds a node with key @key to TNC. The node may be new or it may
 * obsolete some existing one. Returns %0 on success or negative error code on
 * failure.
 */
int ubifs_tnc_add(struct ubifs_info *c, const union ubifs_key *key, int lnum,
		  int offs, int len)
{
	int found, n, err = 0;
	struct ubifs_znode *znode;

	mutex_lock(&c->tnc_mutex);
	dbg_tnck(key, "%d:%d, len %d, key ", lnum, offs, len);
	found = lookup_level0_dirty(c, key, &znode, &n);
	if (!found) {
		struct ubifs_zbranch zbr;

		zbr.znode = NULL;
		zbr.lnum = lnum;
		zbr.offs = offs;
		zbr.len = len;
		key_copy(c, key, &zbr.key);
		err = tnc_insert(c, znode, &zbr, n + 1);
	} else if (found == 1) {
		struct ubifs_zbranch *zbr = &znode->zbranch[n];

		lnc_free(zbr);
		err = ubifs_add_dirt(c, zbr->lnum, zbr->len);
		zbr->lnum = lnum;
		zbr->offs = offs;
		zbr->len = len;
	} else
		err = found;
	if (!err)
		err = dbg_check_tnc(c, 0);
	mutex_unlock(&c->tnc_mutex);

	return err;
}

/**
 * ubifs_tnc_replace - replace a node in the TNC only if the old node is found.
 * @c: UBIFS file-system description object
 * @key: key to add
 * @old_lnum: LEB number of old node
 * @old_offs: old node offset
 * @lnum: LEB number of node
 * @offs: node offset
 * @len: node length
 *
 * This function replaces a node with key @key in the TNC only if the old node
 * is found.  This function is called by garbage collection when node are moved.
 * Returns %0 on success or negative error code on failure.
 */
int ubifs_tnc_replace(struct ubifs_info *c, const union ubifs_key *key,
		      int old_lnum, int old_offs, int lnum, int offs, int len)
{
	int found, n, err = 0;
	struct ubifs_znode *znode;

	mutex_lock(&c->tnc_mutex);
	dbg_tnck(key, "old LEB %d:%d, new LEB %d:%d, len %d, key ", old_lnum,
		 old_offs, lnum, offs, len);
	found = lookup_level0_dirty(c, key, &znode, &n);
	if (found < 0) {
		err = found;
		goto out_unlock;
	}

	if (found == 1) {
		struct ubifs_zbranch *zbr = &znode->zbranch[n];

		found = 0;
		if (zbr->lnum == old_lnum && zbr->offs == old_offs) {
			lnc_free(zbr);
			err = ubifs_add_dirt(c, zbr->lnum, zbr->len);
			if (err)
				goto out_unlock;
			zbr->lnum = lnum;
			zbr->offs = offs;
			zbr->len = len;
			found = 1;
		} else if (is_hash_key(c, key)) {
			found = resolve_collision_directly(c, key, &znode, &n,
							   old_lnum, old_offs);
			dbg_tnc("rc returned %d, znode %p, n %d, LEB %d:%d",
				found, znode, n, old_lnum, old_offs);
			if (found < 0) {
				err = found;
				goto out_unlock;
			}

			if (found) {
				/* Ensure the znode is dirtied */
				if (znode->cnext || !ubifs_zn_dirty(znode)) {
					znode = dirty_cow_bottom_up(c, znode);
					if (IS_ERR(znode)) {
						err = PTR_ERR(znode);
						goto out_unlock;
					}
				}
				zbr = &znode->zbranch[n];
				lnc_free(zbr);
				err = ubifs_add_dirt(c, zbr->lnum,
						     zbr->len);
				if (err)
					goto out_unlock;
				zbr->lnum = lnum;
				zbr->offs = offs;
				zbr->len = len;
			}
		}
	}

	if (!found)
		err = ubifs_add_dirt(c, lnum, len);

	if (!err)
		err = dbg_check_tnc(c, 0);

out_unlock:
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * ubifs_tnc_add_nm - add a "hashed" node to TNC.
 * @c: UBIFS file-system description object
 * @key: key to add
 * @lnum: LEB number of node
 * @offs: node offset
 * @len: node length
 * @nm: node name
 *
 * This is the same as 'ubifs_tnc_add()' but it should be used with keys which
 * may have collisions, like directory entry keys.
 */
int ubifs_tnc_add_nm(struct ubifs_info *c, const union ubifs_key *key,
		     int lnum, int offs, int len, const struct qstr *nm)
{
	int found, n, err = 0;
	struct ubifs_znode *znode;

	mutex_lock(&c->tnc_mutex);
	dbg_tnck(key, "LEB %d:%d, name '%.*s', key ",
		 lnum, offs, nm->len, nm->name);
	found = lookup_level0_dirty(c, key, &znode, &n);
	if (found < 0) {
		err = found;
		goto out_unlock;
	}

	if (found == 1) {
		if (c->replaying)
			found = fallible_resolve_collision(c, key, &znode, &n,
							   nm, 1);
		else
			found = resolve_collision(c, key, &znode, &n, nm);
		dbg_tnc("rc returned %d, znode %p, n %d", found, znode, n);
		if (found < 0) {
			err = found;
			goto out_unlock;
		}

		/* Ensure the znode is dirtied */
		if (znode->cnext || !ubifs_zn_dirty(znode)) {
			znode = dirty_cow_bottom_up(c, znode);
			if (IS_ERR(znode)) {
				err = PTR_ERR(znode);
				goto out_unlock;
			}
		}

		if (found == 1) {
			struct ubifs_zbranch *zbr = &znode->zbranch[n];

			lnc_free(zbr);
			err = ubifs_add_dirt(c, zbr->lnum, zbr->len);
			zbr->lnum = lnum;
			zbr->offs = offs;
			zbr->len = len;
			goto out_unlock;
		}
	}

	if (!found) {
		struct ubifs_zbranch zbr;

		zbr.znode = NULL;
		zbr.lnum = lnum;
		zbr.offs = offs;
		zbr.len = len;
		key_copy(c, key, &zbr.key);
		err = tnc_insert(c, znode, &zbr, n + 1);
		if (err)
			goto out_unlock;
		if (c->replaying) {
			/*
			 * We did not find it in the index so there may be a
			 * dangling branch still in the index. So we remove it
			 * by passing 'ubifs_tnc_remove_nm()' the same key but
			 * an unmatchable name.
			 */
			struct qstr noname = { .name = "" };

			err = dbg_check_tnc(c, 0);
			mutex_unlock(&c->tnc_mutex);
			if (err)
				return err;
			return ubifs_tnc_remove_nm(c, key, &noname);
		}
	}

out_unlock:
	if (!err)
		err = dbg_check_tnc(c, 0);
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * tnc_delete - delete a znode form TNC.
 * @c: UBIFS file-system description object
 * @znode: znode to delete from
 * @n: zbranch slot number to delete
 *
 * This function deletes a leaf node from @n-th slot of @znode. Returns zero in
 * case of success and a negative error code in case of failure.
 */
static int tnc_delete(struct ubifs_info *c, struct ubifs_znode *znode, int n)
{
	struct ubifs_zbranch *zbr;
	struct ubifs_znode *zp;
	int i, err;

	/* Delete without merge for now */
	ubifs_assert(znode->level == 0);
	ubifs_assert(n >= 0 && n < c->fanout);
	dbg_tnck(&znode->zbranch[n].key, "deleting key ");

	zbr = &znode->zbranch[n];
	lnc_free(zbr);

	err = ubifs_add_dirt(c, zbr->lnum, zbr->len);
	if (err) {
		ubifs_dump_znode(c, znode);
		return err;
	}

	/* We do not "gap" zbranch slots */
	for (i = n; i < znode->child_cnt - 1; i++)
		znode->zbranch[i] = znode->zbranch[i + 1];
	znode->child_cnt -= 1;

	if (znode->child_cnt > 0)
		return 0;

	/*
	 * This was the last zbranch, we have to delete this znode from the
	 * parent.
	 */

	do {
		ubifs_assert(!ubifs_zn_obsolete(znode));
		ubifs_assert(ubifs_zn_dirty(znode));

		zp = znode->parent;
		n = znode->iip;

		atomic_long_dec(&c->dirty_zn_cnt);

		err = insert_old_idx_znode(c, znode);
		if (err)
			return err;

		if (znode->cnext) {
			__set_bit(OBSOLETE_ZNODE, &znode->flags);
			atomic_long_inc(&c->clean_zn_cnt);
			atomic_long_inc(&ubifs_clean_zn_cnt);
		} else
			kfree(znode);
		znode = zp;
	} while (znode->child_cnt == 1); /* while removing last child */

	/* Remove from znode, entry n - 1 */
	znode->child_cnt -= 1;
	ubifs_assert(znode->level != 0);
	for (i = n; i < znode->child_cnt; i++) {
		znode->zbranch[i] = znode->zbranch[i + 1];
		if (znode->zbranch[i].znode)
			znode->zbranch[i].znode->iip = i;
	}

	/*
	 * If this is the root and it has only 1 child then
	 * collapse the tree.
	 */
	if (!znode->parent) {
		while (znode->child_cnt == 1 && znode->level != 0) {
			zp = znode;
			zbr = &znode->zbranch[0];
			znode = get_znode(c, znode, 0);
			if (IS_ERR(znode))
				return PTR_ERR(znode);
			znode = dirty_cow_znode(c, zbr);
			if (IS_ERR(znode))
				return PTR_ERR(znode);
			znode->parent = NULL;
			znode->iip = 0;
			if (c->zroot.len) {
				err = insert_old_idx(c, c->zroot.lnum,
						     c->zroot.offs);
				if (err)
					return err;
			}
			c->zroot.lnum = zbr->lnum;
			c->zroot.offs = zbr->offs;
			c->zroot.len = zbr->len;
			c->zroot.znode = znode;
			ubifs_assert(!ubifs_zn_obsolete(zp));
			ubifs_assert(ubifs_zn_dirty(zp));
			atomic_long_dec(&c->dirty_zn_cnt);

			if (zp->cnext) {
				__set_bit(OBSOLETE_ZNODE, &zp->flags);
				atomic_long_inc(&c->clean_zn_cnt);
				atomic_long_inc(&ubifs_clean_zn_cnt);
			} else
				kfree(zp);
		}
	}

	return 0;
}

/**
 * ubifs_tnc_remove - remove an index entry of a node.
 * @c: UBIFS file-system description object
 * @key: key of node
 *
 * Returns %0 on success or negative error code on failure.
 */
int ubifs_tnc_remove(struct ubifs_info *c, const union ubifs_key *key)
{
	int found, n, err = 0;
	struct ubifs_znode *znode;

	mutex_lock(&c->tnc_mutex);
	dbg_tnck(key, "key ");
	found = lookup_level0_dirty(c, key, &znode, &n);
	if (found < 0) {
		err = found;
		goto out_unlock;
	}
	if (found == 1)
		err = tnc_delete(c, znode, n);
	if (!err)
		err = dbg_check_tnc(c, 0);

out_unlock:
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * ubifs_tnc_remove_nm - remove an index entry for a "hashed" node.
 * @c: UBIFS file-system description object
 * @key: key of node
 * @nm: directory entry name
 *
 * Returns %0 on success or negative error code on failure.
 */
int ubifs_tnc_remove_nm(struct ubifs_info *c, const union ubifs_key *key,
			const struct qstr *nm)
{
	int n, err;
	struct ubifs_znode *znode;

	mutex_lock(&c->tnc_mutex);
	dbg_tnck(key, "%.*s, key ", nm->len, nm->name);
	err = lookup_level0_dirty(c, key, &znode, &n);
	if (err < 0)
		goto out_unlock;

	if (err) {
		if (c->replaying)
			err = fallible_resolve_collision(c, key, &znode, &n,
							 nm, 0);
		else
			err = resolve_collision(c, key, &znode, &n, nm);
		dbg_tnc("rc returned %d, znode %p, n %d", err, znode, n);
		if (err < 0)
			goto out_unlock;
		if (err) {
			/* Ensure the znode is dirtied */
			if (znode->cnext || !ubifs_zn_dirty(znode)) {
				znode = dirty_cow_bottom_up(c, znode);
				if (IS_ERR(znode)) {
					err = PTR_ERR(znode);
					goto out_unlock;
				}
			}
			err = tnc_delete(c, znode, n);
		}
	}

out_unlock:
	if (!err)
		err = dbg_check_tnc(c, 0);
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * key_in_range - determine if a key falls within a range of keys.
 * @c: UBIFS file-system description object
 * @key: key to check
 * @from_key: lowest key in range
 * @to_key: highest key in range
 *
 * This function returns %1 if the key is in range and %0 otherwise.
 */
static int key_in_range(struct ubifs_info *c, union ubifs_key *key,
			union ubifs_key *from_key, union ubifs_key *to_key)
{
	if (keys_cmp(c, key, from_key) < 0)
		return 0;
	if (keys_cmp(c, key, to_key) > 0)
		return 0;
	return 1;
}

/**
 * ubifs_tnc_remove_range - remove index entries in range.
 * @c: UBIFS file-system description object
 * @from_key: lowest key to remove
 * @to_key: highest key to remove
 *
 * This function removes index entries starting at @from_key and ending at
 * @to_key.  This function returns zero in case of success and a negative error
 * code in case of failure.
 */
int ubifs_tnc_remove_range(struct ubifs_info *c, union ubifs_key *from_key,
			   union ubifs_key *to_key)
{
	int i, n, k, err = 0;
	struct ubifs_znode *znode;
	union ubifs_key *key;

	mutex_lock(&c->tnc_mutex);
	while (1) {
		/* Find first level 0 znode that contains keys to remove */
		err = ubifs_lookup_level0(c, from_key, &znode, &n);
		if (err < 0)
			goto out_unlock;

		if (err)
			key = from_key;
		else {
			err = tnc_next(c, &znode, &n);
			if (err == -ENOENT) {
				err = 0;
				goto out_unlock;
			}
			if (err < 0)
				goto out_unlock;
			key = &znode->zbranch[n].key;
			if (!key_in_range(c, key, from_key, to_key)) {
				err = 0;
				goto out_unlock;
			}
		}

		/* Ensure the znode is dirtied */
		if (znode->cnext || !ubifs_zn_dirty(znode)) {
			znode = dirty_cow_bottom_up(c, znode);
			if (IS_ERR(znode)) {
				err = PTR_ERR(znode);
				goto out_unlock;
			}
		}

		/* Remove all keys in range except the first */
		for (i = n + 1, k = 0; i < znode->child_cnt; i++, k++) {
			key = &znode->zbranch[i].key;
			if (!key_in_range(c, key, from_key, to_key))
				break;
			lnc_free(&znode->zbranch[i]);
			err = ubifs_add_dirt(c, znode->zbranch[i].lnum,
					     znode->zbranch[i].len);
			if (err) {
				ubifs_dump_znode(c, znode);
				goto out_unlock;
			}
			dbg_tnck(key, "removing key ");
		}
		if (k) {
			for (i = n + 1 + k; i < znode->child_cnt; i++)
				znode->zbranch[i - k] = znode->zbranch[i];
			znode->child_cnt -= k;
		}

		/* Now delete the first */
		err = tnc_delete(c, znode, n);
		if (err)
			goto out_unlock;
	}

out_unlock:
	if (!err)
		err = dbg_check_tnc(c, 0);
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * ubifs_tnc_remove_ino - remove an inode from TNC.
 * @c: UBIFS file-system description object
 * @inum: inode number to remove
 *
 * This function remove inode @inum and all the extended attributes associated
 * with the anode from TNC and returns zero in case of success or a negative
 * error code in case of failure.
 */
int ubifs_tnc_remove_ino(struct ubifs_info *c, ino_t inum)
{
	union ubifs_key key1, key2;
	struct ubifs_dent_node *xent, *pxent = NULL;
	struct qstr nm = { .name = NULL };

	dbg_tnc("ino %lu", (unsigned long)inum);

	/*
	 * Walk all extended attribute entries and remove them together with
	 * corresponding extended attribute inodes.
	 */
	lowest_xent_key(c, &key1, inum);
	while (1) {
		ino_t xattr_inum;
		int err;

		xent = ubifs_tnc_next_ent(c, &key1, &nm);
		if (IS_ERR(xent)) {
			err = PTR_ERR(xent);
			if (err == -ENOENT)
				break;
			return err;
		}

		xattr_inum = le64_to_cpu(xent->inum);
		dbg_tnc("xent '%s', ino %lu", xent->name,
			(unsigned long)xattr_inum);

		nm.name = xent->name;
		nm.len = le16_to_cpu(xent->nlen);
		err = ubifs_tnc_remove_nm(c, &key1, &nm);
		if (err) {
			kfree(xent);
			return err;
		}

		lowest_ino_key(c, &key1, xattr_inum);
		highest_ino_key(c, &key2, xattr_inum);
		err = ubifs_tnc_remove_range(c, &key1, &key2);
		if (err) {
			kfree(xent);
			return err;
		}

		kfree(pxent);
		pxent = xent;
		key_read(c, &xent->key, &key1);
	}

	kfree(pxent);
	lowest_ino_key(c, &key1, inum);
	highest_ino_key(c, &key2, inum);

	return ubifs_tnc_remove_range(c, &key1, &key2);
}

/**
 * ubifs_tnc_next_ent - walk directory or extended attribute entries.
 * @c: UBIFS file-system description object
 * @key: key of last entry
 * @nm: name of last entry found or %NULL
 *
 * This function finds and reads the next directory or extended attribute entry
 * after the given key (@key) if there is one. @nm is used to resolve
 * collisions.
 *
 * If the name of the current entry is not known and only the key is known,
 * @nm->name has to be %NULL. In this case the semantics of this function is a
 * little bit different and it returns the entry corresponding to this key, not
 * the next one. If the key was not found, the closest "right" entry is
 * returned.
 *
 * If the fist entry has to be found, @key has to contain the lowest possible
 * key value for this inode and @name has to be %NULL.
 *
 * This function returns the found directory or extended attribute entry node
 * in case of success, %-ENOENT is returned if no entry was found, and a
 * negative error code is returned in case of failure.
 */
struct ubifs_dent_node *ubifs_tnc_next_ent(struct ubifs_info *c,
					   union ubifs_key *key,
					   const struct qstr *nm)
{
	int n, err, type = key_type(c, key);
	struct ubifs_znode *znode;
	struct ubifs_dent_node *dent;
	struct ubifs_zbranch *zbr;
	union ubifs_key *dkey;

	dbg_tnck(key, "%s ", nm->name ? (char *)nm->name : "(lowest)");
	ubifs_assert(is_hash_key(c, key));

	mutex_lock(&c->tnc_mutex);
	err = ubifs_lookup_level0(c, key, &znode, &n);
	if (unlikely(err < 0))
		goto out_unlock;

	if (nm->name) {
		if (err) {
			/* Handle collisions */
			err = resolve_collision(c, key, &znode, &n, nm);
			dbg_tnc("rc returned %d, znode %p, n %d",
				err, znode, n);
			if (unlikely(err < 0))
				goto out_unlock;
		}

		/* Now find next entry */
		err = tnc_next(c, &znode, &n);
		if (unlikely(err))
			goto out_unlock;
	} else {
		/*
		 * The full name of the entry was not given, in which case the
		 * behavior of this function is a little different and it
		 * returns current entry, not the next one.
		 */
		if (!err) {
			/*
			 * However, the given key does not exist in the TNC
			 * tree and @znode/@n variables contain the closest
			 * "preceding" element. Switch to the next one.
			 */
			err = tnc_next(c, &znode, &n);
			if (err)
				goto out_unlock;
		}
	}

	zbr = &znode->zbranch[n];
	dent = kmalloc(zbr->len, GFP_NOFS);
	if (unlikely(!dent)) {
		err = -ENOMEM;
		goto out_unlock;
	}

	/*
	 * The above 'tnc_next()' call could lead us to the next inode, check
	 * this.
	 */
	dkey = &zbr->key;
	if (key_inum(c, dkey) != key_inum(c, key) ||
	    key_type(c, dkey) != type) {
		err = -ENOENT;
		goto out_free;
	}

	err = tnc_read_node_nm(c, zbr, dent);
	if (unlikely(err))
		goto out_free;

	mutex_unlock(&c->tnc_mutex);
	return dent;

out_free:
	kfree(dent);
out_unlock:
	mutex_unlock(&c->tnc_mutex);
	return ERR_PTR(err);
}

/**
 * tnc_destroy_cnext - destroy left-over obsolete znodes from a failed commit.
 * @c: UBIFS file-system description object
 *
 * Destroy left-over obsolete znodes from a failed commit.
 */
static void tnc_destroy_cnext(struct ubifs_info *c)
{
	struct ubifs_znode *cnext;

	if (!c->cnext)
		return;
	ubifs_assert(c->cmt_state == COMMIT_BROKEN);
	cnext = c->cnext;
	do {
		struct ubifs_znode *znode = cnext;

		cnext = cnext->cnext;
		if (ubifs_zn_obsolete(znode))
			kfree(znode);
	} while (cnext && cnext != c->cnext);
}

/**
 * ubifs_tnc_close - close TNC subsystem and free all related resources.
 * @c: UBIFS file-system description object
 */
void ubifs_tnc_close(struct ubifs_info *c)
{
	tnc_destroy_cnext(c);
	if (c->zroot.znode) {
		long n, freed;

		n = atomic_long_read(&c->clean_zn_cnt);
		freed = ubifs_destroy_tnc_subtree(c->zroot.znode);
		ubifs_assert(freed == n);
		atomic_long_sub(n, &ubifs_clean_zn_cnt);
	}
	kfree(c->gap_lebs);
	kfree(c->ilebs);
	destroy_old_idx(c);
}

/**
 * left_znode - get the znode to the left.
 * @c: UBIFS file-system description object
 * @znode: znode
 *
 * This function returns a pointer to the znode to the left of @znode or NULL if
 * there is not one. A negative error code is returned on failure.
 */
static struct ubifs_znode *left_znode(struct ubifs_info *c,
				      struct ubifs_znode *znode)
{
	int level = znode->level;

	while (1) {
		int n = znode->iip - 1;

		/* Go up until we can go left */
		znode = znode->parent;
		if (!znode)
			return NULL;
		if (n >= 0) {
			/* Now go down the rightmost branch to 'level' */
			znode = get_znode(c, znode, n);
			if (IS_ERR(znode))
				return znode;
			while (znode->level != level) {
				n = znode->child_cnt - 1;
				znode = get_znode(c, znode, n);
				if (IS_ERR(znode))
					return znode;
			}
			break;
		}
	}
	return znode;
}

/**
 * right_znode - get the znode to the right.
 * @c: UBIFS file-system description object
 * @znode: znode
 *
 * This function returns a pointer to the znode to the right of @znode or NULL
 * if there is not one. A negative error code is returned on failure.
 */
static struct ubifs_znode *right_znode(struct ubifs_info *c,
				       struct ubifs_znode *znode)
{
	int level = znode->level;

	while (1) {
		int n = znode->iip + 1;

		/* Go up until we can go right */
		znode = znode->parent;
		if (!znode)
			return NULL;
		if (n < znode->child_cnt) {
			/* Now go down the leftmost branch to 'level' */
			znode = get_znode(c, znode, n);
			if (IS_ERR(znode))
				return znode;
			while (znode->level != level) {
				znode = get_znode(c, znode, 0);
				if (IS_ERR(znode))
					return znode;
			}
			break;
		}
	}
	return znode;
}

/**
 * lookup_znode - find a particular indexing node from TNC.
 * @c: UBIFS file-system description object
 * @key: index node key to lookup
 * @level: index node level
 * @lnum: index node LEB number
 * @offs: index node offset
 *
 * This function searches an indexing node by its first key @key and its
 * address @lnum:@offs. It looks up the indexing tree by pulling all indexing
 * nodes it traverses to TNC. This function is called for indexing nodes which
 * were found on the media by scanning, for example when garbage-collecting or
 * when doing in-the-gaps commit. This means that the indexing node which is
 * looked for does not have to have exactly the same leftmost key @key, because
 * the leftmost key may have been changed, in which case TNC will contain a
 * dirty znode which still refers the same @lnum:@offs. This function is clever
 * enough to recognize such indexing nodes.
 *
 * Note, if a znode was deleted or changed too much, then this function will
 * not find it. For situations like this UBIFS has the old index RB-tree
 * (indexed by @lnum:@offs).
 *
 * This function returns a pointer to the znode found or %NULL if it is not
 * found. A negative error code is returned on failure.
 */
static struct ubifs_znode *lookup_znode(struct ubifs_info *c,
					union ubifs_key *key, int level,
					int lnum, int offs)
{
	struct ubifs_znode *znode, *zn;
	int n, nn;

	ubifs_assert(key_type(c, key) < UBIFS_INVALID_KEY);

	/*
	 * The arguments have probably been read off flash, so don't assume
	 * they are valid.
	 */
	if (level < 0)
		return ERR_PTR(-EINVAL);

	/* Get the root znode */
	znode = c->zroot.znode;
	if (!znode) {
		znode = ubifs_load_znode(c, &c->zroot, NULL, 0);
		if (IS_ERR(znode))
			return znode;
	}
	/* Check if it is the one we are looking for */
	if (c->zroot.lnum == lnum && c->zroot.offs == offs)
		return znode;
	/* Descend to the parent level i.e. (level + 1) */
	if (level >= znode->level)
		return NULL;
	while (1) {
		ubifs_search_zbranch(c, znode, key, &n);
		if (n < 0) {
			/*
			 * We reached a znode where the leftmost key is greater
			 * than the key we are searching for. This is the same
			 * situation as the one described in a huge comment at
			 * the end of the 'ubifs_lookup_level0()' function. And
			 * for exactly the same reasons we have to try to look
			 * left before giving up.
			 */
			znode = left_znode(c, znode);
			if (!znode)
				return NULL;
			if (IS_ERR(znode))
				return znode;
			ubifs_search_zbranch(c, znode, key, &n);
			ubifs_assert(n >= 0);
		}
		if (znode->level == level + 1)
			break;
		znode = get_znode(c, znode, n);
		if (IS_ERR(znode))
			return znode;
	}
	/* Check if the child is the one we are looking for */
	if (znode->zbranch[n].lnum == lnum && znode->zbranch[n].offs == offs)
		return get_znode(c, znode, n);
	/* If the key is unique, there is nowhere else to look */
	if (!is_hash_key(c, key))
		return NULL;
	/*
	 * The key is not unique and so may be also in the znodes to either
	 * side.
	 */
	zn = znode;
	nn = n;
	/* Look left */
	while (1) {
		/* Move one branch to the left */
		if (n)
			n -= 1;
		else {
			znode = left_znode(c, znode);
			if (!znode)
				break;
			if (IS_ERR(znode))
				return znode;
			n = znode->child_cnt - 1;
		}
		/* Check it */
		if (znode->zbranch[n].lnum == lnum &&
		    znode->zbranch[n].offs == offs)
			return get_znode(c, znode, n);
		/* Stop if the key is less than the one we are looking for */
		if (keys_cmp(c, &znode->zbranch[n].key, key) < 0)
			break;
	}
	/* Back to the middle */
	znode = zn;
	n = nn;
	/* Look right */
	while (1) {
		/* Move one branch to the right */
		if (++n >= znode->child_cnt) {
			znode = right_znode(c, znode);
			if (!znode)
				break;
			if (IS_ERR(znode))
				return znode;
			n = 0;
		}
		/* Check it */
		if (znode->zbranch[n].lnum == lnum &&
		    znode->zbranch[n].offs == offs)
			return get_znode(c, znode, n);
		/* Stop if the key is greater than the one we are looking for */
		if (keys_cmp(c, &znode->zbranch[n].key, key) > 0)
			break;
	}
	return NULL;
}

/**
 * is_idx_node_in_tnc - determine if an index node is in the TNC.
 * @c: UBIFS file-system description object
 * @key: key of index node
 * @level: index node level
 * @lnum: LEB number of index node
 * @offs: offset of index node
 *
 * This function returns %0 if the index node is not referred to in the TNC, %1
 * if the index node is referred to in the TNC and the corresponding znode is
 * dirty, %2 if an index node is referred to in the TNC and the corresponding
 * znode is clean, and a negative error code in case of failure.
 *
 * Note, the @key argument has to be the key of the first child. Also note,
 * this function relies on the fact that 0:0 is never a valid LEB number and
 * offset for a main-area node.
 */
int is_idx_node_in_tnc(struct ubifs_info *c, union ubifs_key *key, int level,
		       int lnum, int offs)
{
	struct ubifs_znode *znode;

	znode = lookup_znode(c, key, level, lnum, offs);
	if (!znode)
		return 0;
	if (IS_ERR(znode))
		return PTR_ERR(znode);

	return ubifs_zn_dirty(znode) ? 1 : 2;
}

/**
 * is_leaf_node_in_tnc - determine if a non-indexing not is in the TNC.
 * @c: UBIFS file-system description object
 * @key: node key
 * @lnum: node LEB number
 * @offs: node offset
 *
 * This function returns %1 if the node is referred to in the TNC, %0 if it is
 * not, and a negative error code in case of failure.
 *
 * Note, this function relies on the fact that 0:0 is never a valid LEB number
 * and offset for a main-area node.
 */
static int is_leaf_node_in_tnc(struct ubifs_info *c, union ubifs_key *key,
			       int lnum, int offs)
{
	struct ubifs_zbranch *zbr;
	struct ubifs_znode *znode, *zn;
	int n, found, err, nn;
	const int unique = !is_hash_key(c, key);

	found = ubifs_lookup_level0(c, key, &znode, &n);
	if (found < 0)
		return found; /* Error code */
	if (!found)
		return 0;
	zbr = &znode->zbranch[n];
	if (lnum == zbr->lnum && offs == zbr->offs)
		return 1; /* Found it */
	if (unique)
		return 0;
	/*
	 * Because the key is not unique, we have to look left
	 * and right as well
	 */
	zn = znode;
	nn = n;
	/* Look left */
	while (1) {
		err = tnc_prev(c, &znode, &n);
		if (err == -ENOENT)
			break;
		if (err)
			return err;
		if (keys_cmp(c, key, &znode->zbranch[n].key))
			break;
		zbr = &znode->zbranch[n];
		if (lnum == zbr->lnum && offs == zbr->offs)
			return 1; /* Found it */
	}
	/* Look right */
	znode = zn;
	n = nn;
	while (1) {
		err = tnc_next(c, &znode, &n);
		if (err) {
			if (err == -ENOENT)
				return 0;
			return err;
		}
		if (keys_cmp(c, key, &znode->zbranch[n].key))
			break;
		zbr = &znode->zbranch[n];
		if (lnum == zbr->lnum && offs == zbr->offs)
			return 1; /* Found it */
	}
	return 0;
}

/**
 * ubifs_tnc_has_node - determine whether a node is in the TNC.
 * @c: UBIFS file-system description object
 * @key: node key
 * @level: index node level (if it is an index node)
 * @lnum: node LEB number
 * @offs: node offset
 * @is_idx: non-zero if the node is an index node
 *
 * This function returns %1 if the node is in the TNC, %0 if it is not, and a
 * negative error code in case of failure. For index nodes, @key has to be the
 * key of the first child. An index node is considered to be in the TNC only if
 * the corresponding znode is clean or has not been loaded.
 */
int ubifs_tnc_has_node(struct ubifs_info *c, union ubifs_key *key, int level,
		       int lnum, int offs, int is_idx)
{
	int err;

	mutex_lock(&c->tnc_mutex);
	if (is_idx) {
		err = is_idx_node_in_tnc(c, key, level, lnum, offs);
		if (err < 0)
			goto out_unlock;
		if (err == 1)
			/* The index node was found but it was dirty */
			err = 0;
		else if (err == 2)
			/* The index node was found and it was clean */
			err = 1;
		else
			BUG_ON(err != 0);
	} else
		err = is_leaf_node_in_tnc(c, key, lnum, offs);

out_unlock:
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * ubifs_dirty_idx_node - dirty an index node.
 * @c: UBIFS file-system description object
 * @key: index node key
 * @level: index node level
 * @lnum: index node LEB number
 * @offs: index node offset
 *
 * This function loads and dirties an index node so that it can be garbage
 * collected. The @key argument has to be the key of the first child. This
 * function relies on the fact that 0:0 is never a valid LEB number and offset
 * for a main-area node. Returns %0 on success and a negative error code on
 * failure.
 */
int ubifs_dirty_idx_node(struct ubifs_info *c, union ubifs_key *key, int level,
			 int lnum, int offs)
{
	struct ubifs_znode *znode;
	int err = 0;

	mutex_lock(&c->tnc_mutex);
	znode = lookup_znode(c, key, level, lnum, offs);
	if (!znode)
		goto out_unlock;
	if (IS_ERR(znode)) {
		err = PTR_ERR(znode);
		goto out_unlock;
	}
	znode = dirty_cow_bottom_up(c, znode);
	if (IS_ERR(znode)) {
		err = PTR_ERR(znode);
		goto out_unlock;
	}

out_unlock:
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * dbg_check_inode_size - check if inode size is correct.
 * @c: UBIFS file-system description object
 * @inum: inode number
 * @size: inode size
 *
 * This function makes sure that the inode size (@size) is correct and it does
 * not have any pages beyond @size. Returns zero if the inode is OK, %-EINVAL
 * if it has a data page beyond @size, and other negative error code in case of
 * other errors.
 */
int dbg_check_inode_size(struct ubifs_info *c, const struct inode *inode,
			 loff_t size)
{
	int err, n;
	union ubifs_key from_key, to_key, *key;
	struct ubifs_znode *znode;
	unsigned int block;

	if (!S_ISREG(inode->i_mode))
		return 0;
	if (!dbg_is_chk_gen(c))
		return 0;

	block = (size + UBIFS_BLOCK_SIZE - 1) >> UBIFS_BLOCK_SHIFT;
	data_key_init(c, &from_key, inode->i_ino, block);
	highest_data_key(c, &to_key, inode->i_ino);

	mutex_lock(&c->tnc_mutex);
	err = ubifs_lookup_level0(c, &from_key, &znode, &n);
	if (err < 0)
		goto out_unlock;

	if (err) {
		key = &from_key;
		goto out_dump;
	}

	err = tnc_next(c, &znode, &n);
	if (err == -ENOENT) {
		err = 0;
		goto out_unlock;
	}
	if (err < 0)
		goto out_unlock;

	ubifs_assert(err == 0);
	key = &znode->zbranch[n].key;
	if (!key_in_range(c, key, &from_key, &to_key))
		goto out_unlock;

out_dump:
	block = key_block(c, key);
	ubifs_err("inode %lu has size %lld, but there are data at offset %lld",
		  (unsigned long)inode->i_ino, size,
		  ((loff_t)block) << UBIFS_BLOCK_SHIFT);
	mutex_unlock(&c->tnc_mutex);
	ubifs_dump_inode(c, inode);
	dump_stack();
	return -EINVAL;

out_unlock:
	mutex_unlock(&c->tnc_mutex);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/tnc.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/* This file implements reading and writing the master node */

// #include "ubifs.h"

/**
 * scan_for_master - search the valid master node.
 * @c: UBIFS file-system description object
 *
 * This function scans the master node LEBs and search for the latest master
 * node. Returns zero in case of success, %-EUCLEAN if there master area is
 * corrupted and requires recovery, and a negative error code in case of
 * failure.
 */
static int scan_for_master(struct ubifs_info *c)
{
	struct ubifs_scan_leb *sleb;
	struct ubifs_scan_node *snod;
	int lnum, offs = 0, nodes_cnt;

	lnum = UBIFS_MST_LNUM;

	sleb = ubifs_scan(c, lnum, 0, c->sbuf, 1);
	if (IS_ERR(sleb))
		return PTR_ERR(sleb);
	nodes_cnt = sleb->nodes_cnt;
	if (nodes_cnt > 0) {
		snod = list_entry(sleb->nodes.prev, struct ubifs_scan_node,
				  list);
		if (snod->type != UBIFS_MST_NODE)
			goto out_dump;
		memcpy(c->mst_node, snod->node, snod->len);
		offs = snod->offs;
	}
	ubifs_scan_destroy(sleb);

	lnum += 1;

	sleb = ubifs_scan(c, lnum, 0, c->sbuf, 1);
	if (IS_ERR(sleb))
		return PTR_ERR(sleb);
	if (sleb->nodes_cnt != nodes_cnt)
		goto out;
	if (!sleb->nodes_cnt)
		goto out;
	snod = list_entry(sleb->nodes.prev, struct ubifs_scan_node, list);
	if (snod->type != UBIFS_MST_NODE)
		goto out_dump;
	if (snod->offs != offs)
		goto out;
	if (memcmp((void *)c->mst_node + UBIFS_CH_SZ,
		   (void *)snod->node + UBIFS_CH_SZ,
		   UBIFS_MST_NODE_SZ - UBIFS_CH_SZ))
		goto out;
	c->mst_offs = offs;
	ubifs_scan_destroy(sleb);
	return 0;

out:
	ubifs_scan_destroy(sleb);
	return -EUCLEAN;

out_dump:
	ubifs_err("unexpected node type %d master LEB %d:%d",
		  snod->type, lnum, snod->offs);
	ubifs_scan_destroy(sleb);
	return -EINVAL;
}

/**
 * validate_master - validate master node.
 * @c: UBIFS file-system description object
 *
 * This function validates data which was read from master node. Returns zero
 * if the data is all right and %-EINVAL if not.
 */
static int validate_master(const struct ubifs_info *c)
{
	long long main_sz;
	int err;

	if (c->max_sqnum >= SQNUM_WATERMARK) {
		err = 1;
		goto out;
	}

	if (c->cmt_no >= c->max_sqnum) {
		err = 2;
		goto out;
	}

	if (c->highest_inum >= INUM_WATERMARK) {
		err = 3;
		goto out;
	}

	if (c->lhead_lnum < UBIFS_LOG_LNUM ||
	    c->lhead_lnum >= UBIFS_LOG_LNUM + c->log_lebs ||
	    c->lhead_offs < 0 || c->lhead_offs >= c->leb_size ||
	    c->lhead_offs & (c->min_io_size - 1)) {
		err = 4;
		goto out;
	}

	if (c->zroot.lnum >= c->leb_cnt || c->zroot.lnum < c->main_first ||
	    c->zroot.offs >= c->leb_size || c->zroot.offs & 7) {
		err = 5;
		goto out;
	}

	if (c->zroot.len < c->ranges[UBIFS_IDX_NODE].min_len ||
	    c->zroot.len > c->ranges[UBIFS_IDX_NODE].max_len) {
		err = 6;
		goto out;
	}

	if (c->gc_lnum >= c->leb_cnt || c->gc_lnum < c->main_first) {
		err = 7;
		goto out;
	}

	if (c->ihead_lnum >= c->leb_cnt || c->ihead_lnum < c->main_first ||
	    c->ihead_offs % c->min_io_size || c->ihead_offs < 0 ||
	    c->ihead_offs > c->leb_size || c->ihead_offs & 7) {
		err = 8;
		goto out;
	}

	main_sz = (long long)c->main_lebs * c->leb_size;
	if (c->bi.old_idx_sz & 7 || c->bi.old_idx_sz >= main_sz) {
		err = 9;
		goto out;
	}

	if (c->lpt_lnum < c->lpt_first || c->lpt_lnum > c->lpt_last ||
	    c->lpt_offs < 0 || c->lpt_offs + c->nnode_sz > c->leb_size) {
		err = 10;
		goto out;
	}

	if (c->nhead_lnum < c->lpt_first || c->nhead_lnum > c->lpt_last ||
	    c->nhead_offs < 0 || c->nhead_offs % c->min_io_size ||
	    c->nhead_offs > c->leb_size) {
		err = 11;
		goto out;
	}

	if (c->ltab_lnum < c->lpt_first || c->ltab_lnum > c->lpt_last ||
	    c->ltab_offs < 0 ||
	    c->ltab_offs + c->ltab_sz > c->leb_size) {
		err = 12;
		goto out;
	}

	if (c->big_lpt && (c->lsave_lnum < c->lpt_first ||
	    c->lsave_lnum > c->lpt_last || c->lsave_offs < 0 ||
	    c->lsave_offs + c->lsave_sz > c->leb_size)) {
		err = 13;
		goto out;
	}

	if (c->lscan_lnum < c->main_first || c->lscan_lnum >= c->leb_cnt) {
		err = 14;
		goto out;
	}

	if (c->lst.empty_lebs < 0 || c->lst.empty_lebs > c->main_lebs - 2) {
		err = 15;
		goto out;
	}

	if (c->lst.idx_lebs < 0 || c->lst.idx_lebs > c->main_lebs - 1) {
		err = 16;
		goto out;
	}

	if (c->lst.total_free < 0 || c->lst.total_free > main_sz ||
	    c->lst.total_free & 7) {
		err = 17;
		goto out;
	}

	if (c->lst.total_dirty < 0 || (c->lst.total_dirty & 7)) {
		err = 18;
		goto out;
	}

	if (c->lst.total_used < 0 || (c->lst.total_used & 7)) {
		err = 19;
		goto out;
	}

	if (c->lst.total_free + c->lst.total_dirty +
	    c->lst.total_used > main_sz) {
		err = 20;
		goto out;
	}

	if (c->lst.total_dead + c->lst.total_dark +
	    c->lst.total_used + c->bi.old_idx_sz > main_sz) {
		err = 21;
		goto out;
	}

	if (c->lst.total_dead < 0 ||
	    c->lst.total_dead > c->lst.total_free + c->lst.total_dirty ||
	    c->lst.total_dead & 7) {
		err = 22;
		goto out;
	}

	if (c->lst.total_dark < 0 ||
	    c->lst.total_dark > c->lst.total_free + c->lst.total_dirty ||
	    c->lst.total_dark & 7) {
		err = 23;
		goto out;
	}

	return 0;

out:
	ubifs_err("bad master node at offset %d error %d", c->mst_offs, err);
	ubifs_dump_node(c, c->mst_node);
	return -EINVAL;
}

/**
 * ubifs_read_master - read master node.
 * @c: UBIFS file-system description object
 *
 * This function finds and reads the master node during file-system mount. If
 * the flash is empty, it creates default master node as well. Returns zero in
 * case of success and a negative error code in case of failure.
 */
int ubifs_read_master(struct ubifs_info *c)
{
	int err, old_leb_cnt;

	c->mst_node = kzalloc(c->mst_node_alsz, GFP_KERNEL);
	if (!c->mst_node)
		return -ENOMEM;

	err = scan_for_master(c);
	if (err) {
		if (err == -EUCLEAN)
			err = ubifs_recover_master_node(c);
		if (err)
			/*
			 * Note, we do not free 'c->mst_node' here because the
			 * unmount routine will take care of this.
			 */
			return err;
	}

	/* Make sure that the recovery flag is clear */
	c->mst_node->flags &= cpu_to_le32(~UBIFS_MST_RCVRY);

	c->max_sqnum       = le64_to_cpu(c->mst_node->ch.sqnum);
	c->highest_inum    = le64_to_cpu(c->mst_node->highest_inum);
	c->cmt_no          = le64_to_cpu(c->mst_node->cmt_no);
	c->zroot.lnum      = le32_to_cpu(c->mst_node->root_lnum);
	c->zroot.offs      = le32_to_cpu(c->mst_node->root_offs);
	c->zroot.len       = le32_to_cpu(c->mst_node->root_len);
	c->lhead_lnum      = le32_to_cpu(c->mst_node->log_lnum);
	c->gc_lnum         = le32_to_cpu(c->mst_node->gc_lnum);
	c->ihead_lnum      = le32_to_cpu(c->mst_node->ihead_lnum);
	c->ihead_offs      = le32_to_cpu(c->mst_node->ihead_offs);
	c->bi.old_idx_sz   = le64_to_cpu(c->mst_node->index_size);
	c->lpt_lnum        = le32_to_cpu(c->mst_node->lpt_lnum);
	c->lpt_offs        = le32_to_cpu(c->mst_node->lpt_offs);
	c->nhead_lnum      = le32_to_cpu(c->mst_node->nhead_lnum);
	c->nhead_offs      = le32_to_cpu(c->mst_node->nhead_offs);
	c->ltab_lnum       = le32_to_cpu(c->mst_node->ltab_lnum);
	c->ltab_offs       = le32_to_cpu(c->mst_node->ltab_offs);
	c->lsave_lnum      = le32_to_cpu(c->mst_node->lsave_lnum);
	c->lsave_offs      = le32_to_cpu(c->mst_node->lsave_offs);
	c->lscan_lnum      = le32_to_cpu(c->mst_node->lscan_lnum);
	c->lst.empty_lebs  = le32_to_cpu(c->mst_node->empty_lebs);
	c->lst.idx_lebs    = le32_to_cpu(c->mst_node->idx_lebs);
	old_leb_cnt        = le32_to_cpu(c->mst_node->leb_cnt);
	c->lst.total_free  = le64_to_cpu(c->mst_node->total_free);
	c->lst.total_dirty = le64_to_cpu(c->mst_node->total_dirty);
	c->lst.total_used  = le64_to_cpu(c->mst_node->total_used);
	c->lst.total_dead  = le64_to_cpu(c->mst_node->total_dead);
	c->lst.total_dark  = le64_to_cpu(c->mst_node->total_dark);

	c->calc_idx_sz = c->bi.old_idx_sz;

	if (c->mst_node->flags & cpu_to_le32(UBIFS_MST_NO_ORPHS))
		c->no_orphs = 1;

	if (old_leb_cnt != c->leb_cnt) {
		/* The file system has been resized */
		int growth = c->leb_cnt - old_leb_cnt;

		if (c->leb_cnt < old_leb_cnt ||
		    c->leb_cnt < UBIFS_MIN_LEB_CNT) {
			ubifs_err("bad leb_cnt on master node");
			ubifs_dump_node(c, c->mst_node);
			return -EINVAL;
		}

		dbg_mnt("Auto resizing (master) from %d LEBs to %d LEBs",
			old_leb_cnt, c->leb_cnt);
		c->lst.empty_lebs += growth;
		c->lst.total_free += growth * (long long)c->leb_size;
		c->lst.total_dark += growth * (long long)c->dark_wm;

		/*
		 * Reflect changes back onto the master node. N.B. the master
		 * node gets written immediately whenever mounting (or
		 * remounting) in read-write mode, so we do not need to write it
		 * here.
		 */
		c->mst_node->leb_cnt = cpu_to_le32(c->leb_cnt);
		c->mst_node->empty_lebs = cpu_to_le32(c->lst.empty_lebs);
		c->mst_node->total_free = cpu_to_le64(c->lst.total_free);
		c->mst_node->total_dark = cpu_to_le64(c->lst.total_dark);
	}

	err = validate_master(c);
	if (err)
		return err;

	err = dbg_old_index_check_init(c, &c->zroot);

	return err;
}

/**
 * ubifs_write_master - write master node.
 * @c: UBIFS file-system description object
 *
 * This function writes the master node. Returns zero in case of success and a
 * negative error code in case of failure. The master node is written twice to
 * enable recovery.
 */
int ubifs_write_master(struct ubifs_info *c)
{
	int err, lnum, offs, len;

	ubifs_assert(!c->ro_media && !c->ro_mount);
	if (c->ro_error)
		return -EROFS;

	lnum = UBIFS_MST_LNUM;
	offs = c->mst_offs + c->mst_node_alsz;
	len = UBIFS_MST_NODE_SZ;

	if (offs + UBIFS_MST_NODE_SZ > c->leb_size) {
		err = ubifs_leb_unmap(c, lnum);
		if (err)
			return err;
		offs = 0;
	}

	c->mst_offs = offs;
	c->mst_node->highest_inum = cpu_to_le64(c->highest_inum);

	err = ubifs_write_node(c, c->mst_node, len, lnum, offs);
	if (err)
		return err;

	lnum += 1;

	if (offs == 0) {
		err = ubifs_leb_unmap(c, lnum);
		if (err)
			return err;
	}
	err = ubifs_write_node(c, c->mst_node, len, lnum, offs);

	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/master.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements the scan which is a general-purpose function for
 * determining what nodes are in an eraseblock. The scan is used to replay the
 * journal, to do garbage collection. for the TNC in-the-gaps method, and by
 * debugging functions.
 */

// #include "ubifs.h"

/**
 * scan_padding_bytes - scan for padding bytes.
 * @buf: buffer to scan
 * @len: length of buffer
 *
 * This function returns the number of padding bytes on success and
 * %SCANNED_GARBAGE on failure.
 */
static int scan_padding_bytes(void *buf, int len)
{
	int pad_len = 0, max_pad_len = min_t(int, UBIFS_PAD_NODE_SZ, len);
	uint8_t *p = buf;

	dbg_scan("not a node");

	while (pad_len < max_pad_len && *p++ == UBIFS_PADDING_BYTE)
		pad_len += 1;

	if (!pad_len || (pad_len & 7))
		return SCANNED_GARBAGE;

	dbg_scan("%d padding bytes", pad_len);

	return pad_len;
}

/**
 * ubifs_scan_a_node - scan for a node or padding.
 * @c: UBIFS file-system description object
 * @buf: buffer to scan
 * @len: length of buffer
 * @lnum: logical eraseblock number
 * @offs: offset within the logical eraseblock
 * @quiet: print no messages
 *
 * This function returns a scanning code to indicate what was scanned.
 */
int ubifs_scan_a_node(const struct ubifs_info *c, void *buf, int len, int lnum,
		      int offs, int quiet)
{
	struct ubifs_ch *ch = buf;
	uint32_t magic;

	magic = le32_to_cpu(ch->magic);

	if (magic == 0xFFFFFFFF) {
		dbg_scan("hit empty space at LEB %d:%d", lnum, offs);
		return SCANNED_EMPTY_SPACE;
	}

	if (magic != UBIFS_NODE_MAGIC)
		return scan_padding_bytes(buf, len);

	if (len < UBIFS_CH_SZ)
		return SCANNED_GARBAGE;

	dbg_scan("scanning %s at LEB %d:%d",
		 dbg_ntype(ch->node_type), lnum, offs);

	if (ubifs_check_node(c, buf, lnum, offs, quiet, 1))
		return SCANNED_A_CORRUPT_NODE;

	if (ch->node_type == UBIFS_PAD_NODE) {
		struct ubifs_pad_node *pad = buf;
		int pad_len = le32_to_cpu(pad->pad_len);
		int node_len = le32_to_cpu(ch->len);

		/* Validate the padding node */
		if (pad_len < 0 ||
		    offs + node_len + pad_len > c->leb_size) {
			if (!quiet) {
				ubifs_err("bad pad node at LEB %d:%d",
					  lnum, offs);
				ubifs_dump_node(c, pad);
			}
			return SCANNED_A_BAD_PAD_NODE;
		}

		/* Make the node pads to 8-byte boundary */
		if ((node_len + pad_len) & 7) {
			if (!quiet)
				ubifs_err("bad padding length %d - %d",
					  offs, offs + node_len + pad_len);
			return SCANNED_A_BAD_PAD_NODE;
		}

		dbg_scan("%d bytes padded at LEB %d:%d, offset now %d", pad_len,
			 lnum, offs, ALIGN(offs + node_len + pad_len, 8));

		return node_len + pad_len;
	}

	return SCANNED_A_NODE;
}

/**
 * ubifs_start_scan - create LEB scanning information at start of scan.
 * @c: UBIFS file-system description object
 * @lnum: logical eraseblock number
 * @offs: offset to start at (usually zero)
 * @sbuf: scan buffer (must be c->leb_size)
 *
 * This function returns the scanned information on success and a negative error
 * code on failure.
 */
struct ubifs_scan_leb *ubifs_start_scan(const struct ubifs_info *c, int lnum,
					int offs, void *sbuf)
{
	struct ubifs_scan_leb *sleb;
	int err;

	dbg_scan("scan LEB %d:%d", lnum, offs);

	sleb = kzalloc(sizeof(struct ubifs_scan_leb), GFP_NOFS);
	if (!sleb)
		return ERR_PTR(-ENOMEM);

	sleb->lnum = lnum;
	INIT_LIST_HEAD(&sleb->nodes);
	sleb->buf = sbuf;

	err = ubifs_leb_read(c, lnum, sbuf + offs, offs, c->leb_size - offs, 0);
	if (err && err != -EBADMSG) {
		ubifs_err("cannot read %d bytes from LEB %d:%d, error %d",
			  c->leb_size - offs, lnum, offs, err);
		kfree(sleb);
		return ERR_PTR(err);
	}

	/*
	 * Note, we ignore integrity errors (EBASMSG) because all the nodes are
	 * protected by CRC checksums.
	 */
	return sleb;
}

/**
 * ubifs_end_scan - update LEB scanning information at end of scan.
 * @c: UBIFS file-system description object
 * @sleb: scanning information
 * @lnum: logical eraseblock number
 * @offs: offset to start at (usually zero)
 */
void ubifs_end_scan(const struct ubifs_info *c, struct ubifs_scan_leb *sleb,
		    int lnum, int offs)
{
	lnum = lnum;
	dbg_scan("stop scanning LEB %d at offset %d", lnum, offs);
	ubifs_assert(offs % c->min_io_size == 0);

	sleb->endpt = ALIGN(offs, c->min_io_size);
}

/**
 * ubifs_add_snod - add a scanned node to LEB scanning information.
 * @c: UBIFS file-system description object
 * @sleb: scanning information
 * @buf: buffer containing node
 * @offs: offset of node on flash
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_add_snod(const struct ubifs_info *c, struct ubifs_scan_leb *sleb,
		   void *buf, int offs)
{
	struct ubifs_ch *ch = buf;
	struct ubifs_ino_node *ino = buf;
	struct ubifs_scan_node *snod;

	snod = kmalloc(sizeof(struct ubifs_scan_node), GFP_NOFS);
	if (!snod)
		return -ENOMEM;

	snod->sqnum = le64_to_cpu(ch->sqnum);
	snod->type = ch->node_type;
	snod->offs = offs;
	snod->len = le32_to_cpu(ch->len);
	snod->node = buf;

	switch (ch->node_type) {
	case UBIFS_INO_NODE:
	case UBIFS_DENT_NODE:
	case UBIFS_XENT_NODE:
	case UBIFS_DATA_NODE:
		/*
		 * The key is in the same place in all keyed
		 * nodes.
		 */
		key_read(c, &ino->key, &snod->key);
		break;
	default:
		invalid_key_init(c, &snod->key);
		break;
	}
	list_add_tail(&snod->list, &sleb->nodes);
	sleb->nodes_cnt += 1;
	return 0;
}

/**
 * ubifs_scanned_corruption - print information after UBIFS scanned corruption.
 * @c: UBIFS file-system description object
 * @lnum: LEB number of corruption
 * @offs: offset of corruption
 * @buf: buffer containing corruption
 */
void ubifs_scanned_corruption(const struct ubifs_info *c, int lnum, int offs,
			      void *buf)
{
	int len;

	ubifs_err("corruption at LEB %d:%d", lnum, offs);
	len = c->leb_size - offs;
	if (len > 8192)
		len = 8192;
	ubifs_err("first %d bytes from LEB %d:%d", len, lnum, offs);
	print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 32, 4, buf, len, 1);
}

/**
 * ubifs_scan - scan a logical eraseblock.
 * @c: UBIFS file-system description object
 * @lnum: logical eraseblock number
 * @offs: offset to start at (usually zero)
 * @sbuf: scan buffer (must be of @c->leb_size bytes in size)
 * @quiet: print no messages
 *
 * This function scans LEB number @lnum and returns complete information about
 * its contents. Returns the scanned information in case of success and,
 * %-EUCLEAN if the LEB neads recovery, and other negative error codes in case
 * of failure.
 *
 * If @quiet is non-zero, this function does not print large and scary
 * error messages and flash dumps in case of errors.
 */
struct ubifs_scan_leb *ubifs_scan(const struct ubifs_info *c, int lnum,
				  int offs, void *sbuf, int quiet)
{
	void *buf = sbuf + offs;
	int err, len = c->leb_size - offs;
	struct ubifs_scan_leb *sleb;

	sleb = ubifs_start_scan(c, lnum, offs, sbuf);
	if (IS_ERR(sleb))
		return sleb;

	while (len >= 8) {
		struct ubifs_ch *ch = buf;
		int node_len, ret;

		dbg_scan("look at LEB %d:%d (%d bytes left)",
			 lnum, offs, len);

		cond_resched();

		ret = ubifs_scan_a_node(c, buf, len, lnum, offs, quiet);
		if (ret > 0) {
			/* Padding bytes or a valid padding node */
			offs += ret;
			buf += ret;
			len -= ret;
			continue;
		}

		if (ret == SCANNED_EMPTY_SPACE)
			/* Empty space is checked later */
			break;

		switch (ret) {
		case SCANNED_GARBAGE:
			ubifs_err("garbage");
			goto corrupted;
		case SCANNED_A_NODE:
			break;
		case SCANNED_A_CORRUPT_NODE:
		case SCANNED_A_BAD_PAD_NODE:
			ubifs_err("bad node");
			goto corrupted;
		default:
			ubifs_err("unknown");
			err = -EINVAL;
			goto error;
		}

		err = ubifs_add_snod(c, sleb, buf, offs);
		if (err)
			goto error;

		node_len = ALIGN(le32_to_cpu(ch->len), 8);
		offs += node_len;
		buf += node_len;
		len -= node_len;
	}

	if (offs % c->min_io_size) {
		if (!quiet)
			ubifs_err("empty space starts at non-aligned offset %d",
				  offs);
		goto corrupted;
	}

	ubifs_end_scan(c, sleb, lnum, offs);

	for (; len > 4; offs += 4, buf = buf + 4, len -= 4)
		if (*(uint32_t *)buf != 0xffffffff)
			break;
	for (; len; offs++, buf++, len--)
		if (*(uint8_t *)buf != 0xff) {
			if (!quiet)
				ubifs_err("corrupt empty space at LEB %d:%d",
					  lnum, offs);
			goto corrupted;
		}

	return sleb;

corrupted:
	if (!quiet) {
		ubifs_scanned_corruption(c, lnum, offs, buf);
		ubifs_err("LEB %d scanning failed", lnum);
	}
	err = -EUCLEAN;
	ubifs_scan_destroy(sleb);
	return ERR_PTR(err);

error:
	ubifs_err("LEB %d scanning failed, error %d", lnum, err);
	ubifs_scan_destroy(sleb);
	return ERR_PTR(err);
}

/**
 * ubifs_scan_destroy - destroy LEB scanning information.
 * @sleb: scanning information to free
 */
void ubifs_scan_destroy(struct ubifs_scan_leb *sleb)
{
	struct ubifs_scan_node *node;
	struct list_head *head;

	head = &sleb->nodes;
	while (!list_empty(head)) {
		node = list_entry(head->next, struct ubifs_scan_node, list);
		list_del(&node->list);
		kfree(node);
	}
	kfree(sleb);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/scan.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file contains journal replay code. It runs when the file-system is being
 * mounted and requires no locking.
 *
 * The larger is the journal, the longer it takes to scan it, so the longer it
 * takes to mount UBIFS. This is why the journal has limited size which may be
 * changed depending on the system requirements. But a larger journal gives
 * faster I/O speed because it writes the index less frequently. So this is a
 * trade-off. Also, the journal is indexed by the in-memory index (TNC), so the
 * larger is the journal, the more memory its index may consume.
 */

// #include "ubifs.h"
#include <linux/list_sort.h>
#include "../../inc/__fss.h"

/**
 * struct replay_entry - replay list entry.
 * @lnum: logical eraseblock number of the node
 * @offs: node offset
 * @len: node length
 * @deletion: non-zero if this entry corresponds to a node deletion
 * @sqnum: node sequence number
 * @list: links the replay list
 * @key: node key
 * @nm: directory entry name
 * @old_size: truncation old size
 * @new_size: truncation new size
 *
 * The replay process first scans all buds and builds the replay list, then
 * sorts the replay list in nodes sequence number order, and then inserts all
 * the replay entries to the TNC.
 */
struct replay_entry {
	int lnum;
	int offs;
	int len;
	unsigned int deletion:1;
	unsigned long long sqnum;
	struct list_head list;
	union ubifs_key key;
	union {
		struct qstr nm;
		struct {
			loff_t old_size;
			loff_t new_size;
		};
	};
};

/**
 * struct bud_entry - entry in the list of buds to replay.
 * @list: next bud in the list
 * @bud: bud description object
 * @sqnum: reference node sequence number
 * @free: free bytes in the bud
 * @dirty: dirty bytes in the bud
 */
struct bud_entry {
	struct list_head list;
	struct ubifs_bud *bud;
	unsigned long long sqnum;
	int free;
	int dirty;
};

/**
 * set_bud_lprops - set free and dirty space used by a bud.
 * @c: UBIFS file-system description object
 * @b: bud entry which describes the bud
 *
 * This function makes sure the LEB properties of bud @b are set correctly
 * after the replay. Returns zero in case of success and a negative error code
 * in case of failure.
 */
static int set_bud_lprops(struct ubifs_info *c, struct bud_entry *b)
{
	const struct ubifs_lprops *lp;
	int err = 0, dirty;

	ubifs_get_lprops(c);

	lp = ubifs_lpt_lookup_dirty(c, b->bud->lnum);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		goto out;
	}

	dirty = lp->dirty;
	if (b->bud->start == 0 && (lp->free != c->leb_size || lp->dirty != 0)) {
		/*
		 * The LEB was added to the journal with a starting offset of
		 * zero which means the LEB must have been empty. The LEB
		 * property values should be @lp->free == @c->leb_size and
		 * @lp->dirty == 0, but that is not the case. The reason is that
		 * the LEB had been garbage collected before it became the bud,
		 * and there was not commit inbetween. The garbage collector
		 * resets the free and dirty space without recording it
		 * anywhere except lprops, so if there was no commit then
		 * lprops does not have that information.
		 *
		 * We do not need to adjust free space because the scan has told
		 * us the exact value which is recorded in the replay entry as
		 * @b->free.
		 *
		 * However we do need to subtract from the dirty space the
		 * amount of space that the garbage collector reclaimed, which
		 * is the whole LEB minus the amount of space that was free.
		 */
		dbg_mnt("bud LEB %d was GC'd (%d free, %d dirty)", b->bud->lnum,
			lp->free, lp->dirty);
		dbg_gc("bud LEB %d was GC'd (%d free, %d dirty)", b->bud->lnum,
			lp->free, lp->dirty);
		dirty -= c->leb_size - lp->free;
		/*
		 * If the replay order was perfect the dirty space would now be
		 * zero. The order is not perfect because the journal heads
		 * race with each other. This is not a problem but is does mean
		 * that the dirty space may temporarily exceed c->leb_size
		 * during the replay.
		 */
		if (dirty != 0)
			dbg_mnt("LEB %d lp: %d free %d dirty replay: %d free %d dirty",
				b->bud->lnum, lp->free, lp->dirty, b->free,
				b->dirty);
	}
	lp = ubifs_change_lp(c, lp, b->free, dirty + b->dirty,
			     lp->flags | LPROPS_TAKEN, 0);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		goto out;
	}

	/* Make sure the journal head points to the latest bud */
	err = ubifs_wbuf_seek_nolock(&c->jheads[b->bud->jhead].wbuf,
				     b->bud->lnum, c->leb_size - b->free);

out:
	ubifs_release_lprops(c);
	return err;
}

/**
 * set_buds_lprops - set free and dirty space for all replayed buds.
 * @c: UBIFS file-system description object
 *
 * This function sets LEB properties for all replayed buds. Returns zero in
 * case of success and a negative error code in case of failure.
 */
static int set_buds_lprops(struct ubifs_info *c)
{
	struct bud_entry *b;
	int err;

	list_for_each_entry(b, &c->replay_buds, list) {
		err = set_bud_lprops(c, b);
		if (err)
			return err;
	}

	return 0;
}

/**
 * trun_remove_range - apply a replay entry for a truncation to the TNC.
 * @c: UBIFS file-system description object
 * @r: replay entry of truncation
 */
static int trun_remove_range(struct ubifs_info *c, struct replay_entry *r)
{
	unsigned min_blk, max_blk;
	union ubifs_key min_key, max_key;
	ino_t ino;

	min_blk = r->new_size / UBIFS_BLOCK_SIZE;
	if (r->new_size & (UBIFS_BLOCK_SIZE - 1))
		min_blk += 1;

	max_blk = r->old_size / UBIFS_BLOCK_SIZE;
	if ((r->old_size & (UBIFS_BLOCK_SIZE - 1)) == 0)
		max_blk -= 1;

	ino = key_inum(c, &r->key);

	data_key_init(c, &min_key, ino, min_blk);
	data_key_init(c, &max_key, ino, max_blk);

	return ubifs_tnc_remove_range(c, &min_key, &max_key);
}

/**
 * apply_replay_entry - apply a replay entry to the TNC.
 * @c: UBIFS file-system description object
 * @r: replay entry to apply
 *
 * Apply a replay entry to the TNC.
 */
static int apply_replay_entry(struct ubifs_info *c, struct replay_entry *r)
{
	int err;

	dbg_mntk(&r->key, "LEB %d:%d len %d deletion %d sqnum %llu key ",
		 r->lnum, r->offs, r->len, r->deletion, r->sqnum);

	/* Set c->replay_sqnum to help deal with dangling branches. */
	c->replay_sqnum = r->sqnum;

	if (is_hash_key(c, &r->key)) {
		if (r->deletion)
			err = ubifs_tnc_remove_nm(c, &r->key, &r->nm);
		else
			err = ubifs_tnc_add_nm(c, &r->key, r->lnum, r->offs,
					       r->len, &r->nm);
	} else {
		if (r->deletion)
			switch (key_type(c, &r->key)) {
			case UBIFS_INO_KEY:
			{
				ino_t inum = key_inum(c, &r->key);

				err = ubifs_tnc_remove_ino(c, inum);
				break;
			}
			case UBIFS_TRUN_KEY:
				err = trun_remove_range(c, r);
				break;
			default:
				err = ubifs_tnc_remove(c, &r->key);
				break;
			}
		else
			err = ubifs_tnc_add(c, &r->key, r->lnum, r->offs,
					    r->len);
		if (err)
			return err;

		if (c->need_recovery)
			err = ubifs_recover_size_accum(c, &r->key, r->deletion,
						       r->new_size);
	}

	return err;
}

/**
 * replay_entries_cmp - compare 2 replay entries.
 * @priv: UBIFS file-system description object
 * @a: first replay entry
 * @a: second replay entry
 *
 * This is a comparios function for 'list_sort()' which compares 2 replay
 * entries @a and @b by comparing their sequence numer.  Returns %1 if @a has
 * greater sequence number and %-1 otherwise.
 */
static int replay_entries_cmp(void *priv, struct list_head *a,
			      struct list_head *b)
{
	struct replay_entry *ra, *rb;

	cond_resched();
	if (a == b)
		return 0;

	ra = list_entry(a, struct replay_entry, list);
	rb = list_entry(b, struct replay_entry, list);
	ubifs_assert(ra->sqnum != rb->sqnum);
	if (ra->sqnum > rb->sqnum)
		return 1;
	return -1;
}

/**
 * apply_replay_list - apply the replay list to the TNC.
 * @c: UBIFS file-system description object
 *
 * Apply all entries in the replay list to the TNC. Returns zero in case of
 * success and a negative error code in case of failure.
 */
static int apply_replay_list(struct ubifs_info *c)
{
	struct replay_entry *r;
	int err;

	list_sort(c, &c->replay_list, &replay_entries_cmp);

	list_for_each_entry(r, &c->replay_list, list) {
		cond_resched();

		err = apply_replay_entry(c, r);
		if (err)
			return err;
	}

	return 0;
}

/**
 * destroy_replay_list - destroy the replay.
 * @c: UBIFS file-system description object
 *
 * Destroy the replay list.
 */
static void destroy_replay_list(struct ubifs_info *c)
{
	struct replay_entry *r, *tmp;

	list_for_each_entry_safe(r, tmp, &c->replay_list, list) {
		if (is_hash_key(c, &r->key))
			kfree(r->nm.name);
		list_del(&r->list);
		kfree(r);
	}
}

/**
 * insert_node - insert a node to the replay list
 * @c: UBIFS file-system description object
 * @lnum: node logical eraseblock number
 * @offs: node offset
 * @len: node length
 * @key: node key
 * @sqnum: sequence number
 * @deletion: non-zero if this is a deletion
 * @used: number of bytes in use in a LEB
 * @old_size: truncation old size
 * @new_size: truncation new size
 *
 * This function inserts a scanned non-direntry node to the replay list. The
 * replay list contains @struct replay_entry elements, and we sort this list in
 * sequence number order before applying it. The replay list is applied at the
 * very end of the replay process. Since the list is sorted in sequence number
 * order, the older modifications are applied first. This function returns zero
 * in case of success and a negative error code in case of failure.
 */
static int insert_node(struct ubifs_info *c, int lnum, int offs, int len,
		       union ubifs_key *key, unsigned long long sqnum,
		       int deletion, int *used, loff_t old_size,
		       loff_t new_size)
{
	struct replay_entry *r;

	dbg_mntk(key, "add LEB %d:%d, key ", lnum, offs);

	if (key_inum(c, key) >= c->highest_inum)
		c->highest_inum = key_inum(c, key);

	r = kzalloc(sizeof(struct replay_entry), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	if (!deletion)
		*used += ALIGN(len, 8);
	r->lnum = lnum;
	r->offs = offs;
	r->len = len;
	r->deletion = !!deletion;
	r->sqnum = sqnum;
	key_copy(c, key, &r->key);
	r->old_size = old_size;
	r->new_size = new_size;

	list_add_tail(&r->list, &c->replay_list);
	return 0;
}

/**
 * insert_dent - insert a directory entry node into the replay list.
 * @c: UBIFS file-system description object
 * @lnum: node logical eraseblock number
 * @offs: node offset
 * @len: node length
 * @key: node key
 * @name: directory entry name
 * @nlen: directory entry name length
 * @sqnum: sequence number
 * @deletion: non-zero if this is a deletion
 * @used: number of bytes in use in a LEB
 *
 * This function inserts a scanned directory entry node or an extended
 * attribute entry to the replay list. Returns zero in case of success and a
 * negative error code in case of failure.
 */
static int insert_dent(struct ubifs_info *c, int lnum, int offs, int len,
		       union ubifs_key *key, const char *name, int nlen,
		       unsigned long long sqnum, int deletion, int *used)
{
	struct replay_entry *r;
	char *nbuf;

	dbg_mntk(key, "add LEB %d:%d, key ", lnum, offs);
	if (key_inum(c, key) >= c->highest_inum)
		c->highest_inum = key_inum(c, key);

	r = kzalloc(sizeof(struct replay_entry), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	nbuf = kmalloc(nlen + 1, GFP_KERNEL);
	if (!nbuf) {
		kfree(r);
		return -ENOMEM;
	}

	if (!deletion)
		*used += ALIGN(len, 8);
	r->lnum = lnum;
	r->offs = offs;
	r->len = len;
	r->deletion = !!deletion;
	r->sqnum = sqnum;
	key_copy(c, key, &r->key);
	r->nm.len = nlen;
	memcpy(nbuf, name, nlen);
	nbuf[nlen] = '\0';
	r->nm.name = nbuf;

	list_add_tail(&r->list, &c->replay_list);
	return 0;
}

/**
 * ubifs_validate_entry - validate directory or extended attribute entry node.
 * @c: UBIFS file-system description object
 * @dent: the node to validate
 *
 * This function validates directory or extended attribute entry node @dent.
 * Returns zero if the node is all right and a %-EINVAL if not.
 */
int ubifs_validate_entry(struct ubifs_info *c,
			 const struct ubifs_dent_node *dent)
{
	int key_type = key_type_flash(c, dent->key);
	int nlen = le16_to_cpu(dent->nlen);

	if (le32_to_cpu(dent->ch.len) != nlen + UBIFS_DENT_NODE_SZ + 1 ||
	    dent->type >= UBIFS_ITYPES_CNT ||
	    nlen > UBIFS_MAX_NLEN || dent->name[nlen] != 0 ||
	    strnlen(dent->name, nlen) != nlen ||
	    le64_to_cpu(dent->inum) > MAX_INUM) {
		ubifs_err("bad %s node", key_type == UBIFS_DENT_KEY ?
			  "directory entry" : "extended attribute entry");
		return -EINVAL;
	}

	if (key_type != UBIFS_DENT_KEY && key_type != UBIFS_XENT_KEY) {
		ubifs_err("bad key type %d", key_type);
		return -EINVAL;
	}

	return 0;
}

/**
 * is_last_bud - check if the bud is the last in the journal head.
 * @c: UBIFS file-system description object
 * @bud: bud description object
 *
 * This function checks if bud @bud is the last bud in its journal head. This
 * information is then used by 'replay_bud()' to decide whether the bud can
 * have corruptions or not. Indeed, only last buds can be corrupted by power
 * cuts. Returns %1 if this is the last bud, and %0 if not.
 */
static int is_last_bud(struct ubifs_info *c, struct ubifs_bud *bud)
{
	struct ubifs_jhead *jh = &c->jheads[bud->jhead];
	struct ubifs_bud *next;
	uint32_t data;
	int err;

	if (list_is_last(&bud->list, &jh->buds_list))
		return 1;

	/*
	 * The following is a quirk to make sure we work correctly with UBIFS
	 * images used with older UBIFS.
	 *
	 * Normally, the last bud will be the last in the journal head's list
	 * of bud. However, there is one exception if the UBIFS image belongs
	 * to older UBIFS. This is fairly unlikely: one would need to use old
	 * UBIFS, then have a power cut exactly at the right point, and then
	 * try to mount this image with new UBIFS.
	 *
	 * The exception is: it is possible to have 2 buds A and B, A goes
	 * before B, and B is the last, bud B is contains no data, and bud A is
	 * corrupted at the end. The reason is that in older versions when the
	 * journal code switched the next bud (from A to B), it first added a
	 * log reference node for the new bud (B), and only after this it
	 * synchronized the write-buffer of current bud (A). But later this was
	 * changed and UBIFS started to always synchronize the write-buffer of
	 * the bud (A) before writing the log reference for the new bud (B).
	 *
	 * But because older UBIFS always synchronized A's write-buffer before
	 * writing to B, we can recognize this exceptional situation but
	 * checking the contents of bud B - if it is empty, then A can be
	 * treated as the last and we can recover it.
	 *
	 * TODO: remove this piece of code in a couple of years (today it is
	 * 16.05.2011).
	 */
	next = list_entry(bud->list.next, struct ubifs_bud, list);
	if (!list_is_last(&next->list, &jh->buds_list))
		return 0;

	err = ubifs_leb_read(c, next->lnum, (char *)&data, next->start, 4, 1);
	if (err)
		return 0;

	return data == 0xFFFFFFFF;
}

/**
 * replay_bud - replay a bud logical eraseblock.
 * @c: UBIFS file-system description object
 * @b: bud entry which describes the bud
 *
 * This function replays bud @bud, recovers it if needed, and adds all nodes
 * from this bud to the replay list. Returns zero in case of success and a
 * negative error code in case of failure.
 */
static int replay_bud(struct ubifs_info *c, struct bud_entry *b)
{
	int is_last = is_last_bud(c, b->bud);
	int err = 0, used = 0, lnum = b->bud->lnum, offs = b->bud->start;
	struct ubifs_scan_leb *sleb;
	struct ubifs_scan_node *snod;

	dbg_mnt("replay bud LEB %d, head %d, offs %d, is_last %d",
		lnum, b->bud->jhead, offs, is_last);

	if (c->need_recovery && is_last)
		/*
		 * Recover only last LEBs in the journal heads, because power
		 * cuts may cause corruptions only in these LEBs, because only
		 * these LEBs could possibly be written to at the power cut
		 * time.
		 */
		sleb = ubifs_recover_leb(c, lnum, offs, c->sbuf, b->bud->jhead);
	else
		sleb = ubifs_scan(c, lnum, offs, c->sbuf, 0);
	if (IS_ERR(sleb))
		return PTR_ERR(sleb);

	/*
	 * The bud does not have to start from offset zero - the beginning of
	 * the 'lnum' LEB may contain previously committed data. One of the
	 * things we have to do in replay is to correctly update lprops with
	 * newer information about this LEB.
	 *
	 * At this point lprops thinks that this LEB has 'c->leb_size - offs'
	 * bytes of free space because it only contain information about
	 * committed data.
	 *
	 * But we know that real amount of free space is 'c->leb_size -
	 * sleb->endpt', and the space in the 'lnum' LEB between 'offs' and
	 * 'sleb->endpt' is used by bud data. We have to correctly calculate
	 * how much of these data are dirty and update lprops with this
	 * information.
	 *
	 * The dirt in that LEB region is comprised of padding nodes, deletion
	 * nodes, truncation nodes and nodes which are obsoleted by subsequent
	 * nodes in this LEB. So instead of calculating clean space, we
	 * calculate used space ('used' variable).
	 */

	list_for_each_entry(snod, &sleb->nodes, list) {
		int deletion = 0;

		cond_resched();

		if (snod->sqnum >= SQNUM_WATERMARK) {
			ubifs_err("file system's life ended");
			goto out_dump;
		}

		if (snod->sqnum > c->max_sqnum)
			c->max_sqnum = snod->sqnum;

		switch (snod->type) {
		case UBIFS_INO_NODE:
		{
			struct ubifs_ino_node *ino = snod->node;
			loff_t new_size = le64_to_cpu(ino->size);

			if (le32_to_cpu(ino->nlink) == 0)
				deletion = 1;
			err = insert_node(c, lnum, snod->offs, snod->len,
					  &snod->key, snod->sqnum, deletion,
					  &used, 0, new_size);
			break;
		}
		case UBIFS_DATA_NODE:
		{
			struct ubifs_data_node *dn = snod->node;
			loff_t new_size = le32_to_cpu(dn->size) +
					  key_block(c, &snod->key) *
					  UBIFS_BLOCK_SIZE;

			err = insert_node(c, lnum, snod->offs, snod->len,
					  &snod->key, snod->sqnum, deletion,
					  &used, 0, new_size);
			break;
		}
		case UBIFS_DENT_NODE:
		case UBIFS_XENT_NODE:
		{
			struct ubifs_dent_node *dent = snod->node;

			err = ubifs_validate_entry(c, dent);
			if (err)
				goto out_dump;

			err = insert_dent(c, lnum, snod->offs, snod->len,
					  &snod->key, dent->name,
					  le16_to_cpu(dent->nlen), snod->sqnum,
					  !le64_to_cpu(dent->inum), &used);
			break;
		}
		case UBIFS_TRUN_NODE:
		{
			struct ubifs_trun_node *trun = snod->node;
			loff_t old_size = le64_to_cpu(trun->old_size);
			loff_t new_size = le64_to_cpu(trun->new_size);
			union ubifs_key key;

			/* Validate truncation node */
			if (old_size < 0 || old_size > c->max_inode_sz ||
			    new_size < 0 || new_size > c->max_inode_sz ||
			    old_size <= new_size) {
				ubifs_err("bad truncation node");
				goto out_dump;
			}

			/*
			 * Create a fake truncation key just to use the same
			 * functions which expect nodes to have keys.
			 */
			trun_key_init(c, &key, le32_to_cpu(trun->inum));
			err = insert_node(c, lnum, snod->offs, snod->len,
					  &key, snod->sqnum, 1, &used,
					  old_size, new_size);
			break;
		}
		default:
			ubifs_err("unexpected node type %d in bud LEB %d:%d",
				  snod->type, lnum, snod->offs);
			err = -EINVAL;
			goto out_dump;
		}
		if (err)
			goto out;
	}

	ubifs_assert(ubifs_search_bud(c, lnum));
	ubifs_assert(sleb->endpt - offs >= used);
	ubifs_assert(sleb->endpt % c->min_io_size == 0);

	b->dirty = sleb->endpt - offs - used;
	b->free = c->leb_size - sleb->endpt;
	dbg_mnt("bud LEB %d replied: dirty %d, free %d",
		lnum, b->dirty, b->free);

out:
	ubifs_scan_destroy(sleb);
	return err;

out_dump:
	ubifs_err("bad node is at LEB %d:%d", lnum, snod->offs);
	ubifs_dump_node(c, snod->node);
	ubifs_scan_destroy(sleb);
	return -EINVAL;
}

/**
 * replay_buds - replay all buds.
 * @c: UBIFS file-system description object
 *
 * This function returns zero in case of success and a negative error code in
 * case of failure.
 */
static int replay_buds(struct ubifs_info *c)
{
	struct bud_entry *b;
	int err;
	unsigned long long prev_sqnum = 0;

	list_for_each_entry(b, &c->replay_buds, list) {
		err = replay_bud(c, b);
		if (err)
			return err;

		ubifs_assert(b->sqnum > prev_sqnum);
		prev_sqnum = b->sqnum;
	}

	return 0;
}

/**
 * destroy_bud_list - destroy the list of buds to replay.
 * @c: UBIFS file-system description object
 */
static void destroy_bud_list(struct ubifs_info *c)
{
	struct bud_entry *b;

	while (!list_empty(&c->replay_buds)) {
		b = list_entry(c->replay_buds.next, struct bud_entry, list);
		list_del(&b->list);
		kfree(b);
	}
}

/**
 * add_replay_bud - add a bud to the list of buds to replay.
 * @c: UBIFS file-system description object
 * @lnum: bud logical eraseblock number to replay
 * @offs: bud start offset
 * @jhead: journal head to which this bud belongs
 * @sqnum: reference node sequence number
 *
 * This function returns zero in case of success and a negative error code in
 * case of failure.
 */
static int add_replay_bud(struct ubifs_info *c, int lnum, int offs, int jhead,
			  unsigned long long sqnum)
{
	struct ubifs_bud *bud;
	struct bud_entry *b;

	dbg_mnt("add replay bud LEB %d:%d, head %d", lnum, offs, jhead);

	bud = kmalloc(sizeof(struct ubifs_bud), GFP_KERNEL);
	if (!bud)
		return -ENOMEM;

	b = kmalloc(sizeof(struct bud_entry), GFP_KERNEL);
	if (!b) {
		kfree(bud);
		return -ENOMEM;
	}

	bud->lnum = lnum;
	bud->start = offs;
	bud->jhead = jhead;
	ubifs_add_bud(c, bud);

	b->bud = bud;
	b->sqnum = sqnum;
	list_add_tail(&b->list, &c->replay_buds);

	return 0;
}

/**
 * validate_ref - validate a reference node.
 * @c: UBIFS file-system description object
 * @ref: the reference node to validate
 * @ref_lnum: LEB number of the reference node
 * @ref_offs: reference node offset
 *
 * This function returns %1 if a bud reference already exists for the LEB. %0 is
 * returned if the reference node is new, otherwise %-EINVAL is returned if
 * validation failed.
 */
static int validate_ref(struct ubifs_info *c, const struct ubifs_ref_node *ref)
{
	struct ubifs_bud *bud;
	int lnum = le32_to_cpu(ref->lnum);
	unsigned int offs = le32_to_cpu(ref->offs);
	unsigned int jhead = le32_to_cpu(ref->jhead);

	/*
	 * ref->offs may point to the end of LEB when the journal head points
	 * to the end of LEB and we write reference node for it during commit.
	 * So this is why we require 'offs > c->leb_size'.
	 */
	if (jhead >= c->jhead_cnt || lnum >= c->leb_cnt ||
	    lnum < c->main_first || offs > c->leb_size ||
	    offs & (c->min_io_size - 1))
		return -EINVAL;

	/* Make sure we have not already looked at this bud */
	bud = ubifs_search_bud(c, lnum);
	if (bud) {
		if (bud->jhead == jhead && bud->start <= offs)
			return 1;
		ubifs_err("bud at LEB %d:%d was already referred", lnum, offs);
		return -EINVAL;
	}

	return 0;
}

/**
 * replay_log_leb - replay a log logical eraseblock.
 * @c: UBIFS file-system description object
 * @lnum: log logical eraseblock to replay
 * @offs: offset to start replaying from
 * @sbuf: scan buffer
 *
 * This function replays a log LEB and returns zero in case of success, %1 if
 * this is the last LEB in the log, and a negative error code in case of
 * failure.
 */
static int replay_log_leb(struct ubifs_info *c, int lnum, int offs, void *sbuf)
{
	int err;
	struct ubifs_scan_leb *sleb;
	struct ubifs_scan_node *snod;
	const struct ubifs_cs_node *node;

	dbg_mnt("replay log LEB %d:%d", lnum, offs);
	sleb = ubifs_scan(c, lnum, offs, sbuf, c->need_recovery);
	if (IS_ERR(sleb)) {
		if (PTR_ERR(sleb) != -EUCLEAN || !c->need_recovery)
			return PTR_ERR(sleb);
		/*
		 * Note, the below function will recover this log LEB only if
		 * it is the last, because unclean reboots can possibly corrupt
		 * only the tail of the log.
		 */
		sleb = ubifs_recover_log_leb(c, lnum, offs, sbuf);
		if (IS_ERR(sleb))
			return PTR_ERR(sleb);
	}

	if (sleb->nodes_cnt == 0) {
		err = 1;
		goto out;
	}

	node = sleb->buf;
	snod = list_entry(sleb->nodes.next, struct ubifs_scan_node, list);
	if (c->cs_sqnum == 0) {
		/*
		 * This is the first log LEB we are looking at, make sure that
		 * the first node is a commit start node. Also record its
		 * sequence number so that UBIFS can determine where the log
		 * ends, because all nodes which were have higher sequence
		 * numbers.
		 */
		if (snod->type != UBIFS_CS_NODE) {
			ubifs_err("first log node at LEB %d:%d is not CS node",
				  lnum, offs);
			goto out_dump;
		}
		if (le64_to_cpu(node->cmt_no) != c->cmt_no) {
			ubifs_err("first CS node at LEB %d:%d has wrong commit number %llu expected %llu",
				  lnum, offs,
				  (unsigned long long)le64_to_cpu(node->cmt_no),
				  c->cmt_no);
			goto out_dump;
		}

		c->cs_sqnum = le64_to_cpu(node->ch.sqnum);
		dbg_mnt("commit start sqnum %llu", c->cs_sqnum);
	}

	if (snod->sqnum < c->cs_sqnum) {
		/*
		 * This means that we reached end of log and now
		 * look to the older log data, which was already
		 * committed but the eraseblock was not erased (UBIFS
		 * only un-maps it). So this basically means we have to
		 * exit with "end of log" code.
		 */
		err = 1;
		goto out;
	}

	/* Make sure the first node sits at offset zero of the LEB */
	if (snod->offs != 0) {
		ubifs_err("first node is not at zero offset");
		goto out_dump;
	}

	list_for_each_entry(snod, &sleb->nodes, list) {
		cond_resched();

		if (snod->sqnum >= SQNUM_WATERMARK) {
			ubifs_err("file system's life ended");
			goto out_dump;
		}

		if (snod->sqnum < c->cs_sqnum) {
			ubifs_err("bad sqnum %llu, commit sqnum %llu",
				  snod->sqnum, c->cs_sqnum);
			goto out_dump;
		}

		if (snod->sqnum > c->max_sqnum)
			c->max_sqnum = snod->sqnum;

		switch (snod->type) {
		case UBIFS_REF_NODE: {
			const struct ubifs_ref_node *ref = snod->node;

			err = validate_ref(c, ref);
			if (err == 1)
				break; /* Already have this bud */
			if (err)
				goto out_dump;

			err = add_replay_bud(c, le32_to_cpu(ref->lnum),
					     le32_to_cpu(ref->offs),
					     le32_to_cpu(ref->jhead),
					     snod->sqnum);
			if (err)
				goto out;

			break;
		}
		case UBIFS_CS_NODE:
			/* Make sure it sits at the beginning of LEB */
			if (snod->offs != 0) {
				ubifs_err("unexpected node in log");
				goto out_dump;
			}
			break;
		default:
			ubifs_err("unexpected node in log");
			goto out_dump;
		}
	}

	if (sleb->endpt || c->lhead_offs >= c->leb_size) {
		c->lhead_lnum = lnum;
		c->lhead_offs = sleb->endpt;
	}

	err = !sleb->endpt;
out:
	ubifs_scan_destroy(sleb);
	return err;

out_dump:
	ubifs_err("log error detected while replaying the log at LEB %d:%d",
		  lnum, offs + snod->offs);
	ubifs_dump_node(c, snod->node);
	ubifs_scan_destroy(sleb);
	return -EINVAL;
}

/**
 * take_ihead - update the status of the index head in lprops to 'taken'.
 * @c: UBIFS file-system description object
 *
 * This function returns the amount of free space in the index head LEB or a
 * negative error code.
 */
static int take_ihead(struct ubifs_info *c)
{
	const struct ubifs_lprops *lp;
	int err, free;

	ubifs_get_lprops(c);

	lp = ubifs_lpt_lookup_dirty(c, c->ihead_lnum);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		goto out;
	}

	free = lp->free;

	lp = ubifs_change_lp(c, lp, LPROPS_NC, LPROPS_NC,
			     lp->flags | LPROPS_TAKEN, 0);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		goto out;
	}

	err = free;
out:
	ubifs_release_lprops(c);
	return err;
}

/**
 * ubifs_replay_journal - replay journal.
 * @c: UBIFS file-system description object
 *
 * This function scans the journal, replays and cleans it up. It makes sure all
 * memory data structures related to uncommitted journal are built (dirty TNC
 * tree, tree of buds, modified lprops, etc).
 */
int ubifs_replay_journal(struct ubifs_info *c)
{
	int err, lnum, free;

	BUILD_BUG_ON(UBIFS_TRUN_KEY > 5);

	/* Update the status of the index head in lprops to 'taken' */
	free = take_ihead(c);
	if (free < 0)
		return free; /* Error code */

	if (c->ihead_offs != c->leb_size - free) {
		ubifs_err("bad index head LEB %d:%d", c->ihead_lnum,
			  c->ihead_offs);
		return -EINVAL;
	}

	dbg_mnt("start replaying the journal");
	c->replaying = 1;
	lnum = c->ltail_lnum = c->lhead_lnum;

	do {
		err = replay_log_leb(c, lnum, 0, c->sbuf);
		if (err == 1) {
			if (lnum != c->lhead_lnum)
				/* We hit the end of the log */
				break;

			/*
			 * The head of the log must always start with the
			 * "commit start" node on a properly formatted UBIFS.
			 * But we found no nodes at all, which means that
			 * someting went wrong and we cannot proceed mounting
			 * the file-system.
			 */
			ubifs_err("no UBIFS nodes found at the log head LEB %d:%d, possibly corrupted",
				  lnum, 0);
			err = -EINVAL;
		}
		if (err)
			goto out;
		lnum = ubifs_next_log_lnum(c, lnum);
	} while (lnum != c->ltail_lnum);

	err = replay_buds(c);
	if (err)
		goto out;

	err = apply_replay_list(c);
	if (err)
		goto out;

	err = set_buds_lprops(c);
	if (err)
		goto out;

	/*
	 * UBIFS budgeting calculations use @c->bi.uncommitted_idx variable
	 * to roughly estimate index growth. Things like @c->bi.min_idx_lebs
	 * depend on it. This means we have to initialize it to make sure
	 * budgeting works properly.
	 */
	c->bi.uncommitted_idx = atomic_long_read(&c->dirty_zn_cnt);
	c->bi.uncommitted_idx *= c->max_idx_node_sz;

	ubifs_assert(c->bud_bytes <= c->max_bud_bytes || c->need_recovery);
	dbg_mnt("finished, log head LEB %d:%d, max_sqnum %llu, highest_inum %lu",
		c->lhead_lnum, c->lhead_offs, c->max_sqnum,
		(unsigned long)c->highest_inum);
out:
	destroy_replay_list(c);
	destroy_bud_list(c);
	c->replaying = 0;
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/replay.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file is a part of UBIFS journal implementation and contains various
 * functions which manipulate the log. The log is a fixed area on the flash
 * which does not contain any data but refers to buds. The log is a part of the
 * journal.
 */

// #include "ubifs.h"

static int dbg_check_bud_bytes(struct ubifs_info *c);

/**
 * ubifs_search_bud - search bud LEB.
 * @c: UBIFS file-system description object
 * @lnum: logical eraseblock number to search
 *
 * This function searches bud LEB @lnum. Returns bud description object in case
 * of success and %NULL if there is no bud with this LEB number.
 */
struct ubifs_bud *ubifs_search_bud(struct ubifs_info *c, int lnum)
{
	struct rb_node *p;
	struct ubifs_bud *bud;

	spin_lock(&c->buds_lock);
	p = c->buds.rb_node;
	while (p) {
		bud = rb_entry(p, struct ubifs_bud, rb);
		if (lnum < bud->lnum)
			p = p->rb_left;
		else if (lnum > bud->lnum)
			p = p->rb_right;
		else {
			spin_unlock(&c->buds_lock);
			return bud;
		}
	}
	spin_unlock(&c->buds_lock);
	return NULL;
}

/**
 * ubifs_get_wbuf - get the wbuf associated with a LEB, if there is one.
 * @c: UBIFS file-system description object
 * @lnum: logical eraseblock number to search
 *
 * This functions returns the wbuf for @lnum or %NULL if there is not one.
 */
struct ubifs_wbuf *ubifs_get_wbuf(struct ubifs_info *c, int lnum)
{
	struct rb_node *p;
	struct ubifs_bud *bud;
	int jhead;

	if (!c->jheads)
		return NULL;

	spin_lock(&c->buds_lock);
	p = c->buds.rb_node;
	while (p) {
		bud = rb_entry(p, struct ubifs_bud, rb);
		if (lnum < bud->lnum)
			p = p->rb_left;
		else if (lnum > bud->lnum)
			p = p->rb_right;
		else {
			jhead = bud->jhead;
			spin_unlock(&c->buds_lock);
			return &c->jheads[jhead].wbuf;
		}
	}
	spin_unlock(&c->buds_lock);
	return NULL;
}

/**
 * empty_log_bytes - calculate amount of empty space in the log.
 * @c: UBIFS file-system description object
 */
static inline long long empty_log_bytes(const struct ubifs_info *c)
{
	long long h, t;

	h = (long long)c->lhead_lnum * c->leb_size + c->lhead_offs;
	t = (long long)c->ltail_lnum * c->leb_size;

	if (h > t)
		return c->log_bytes - h + t;
	else if (h != t)
		return t - h;
	else if (c->lhead_lnum != c->ltail_lnum)
		return 0;
	else
		return c->log_bytes;
}

/**
 * ubifs_add_bud - add bud LEB to the tree of buds and its journal head list.
 * @c: UBIFS file-system description object
 * @bud: the bud to add
 */
void ubifs_add_bud(struct ubifs_info *c, struct ubifs_bud *bud)
{
	struct rb_node **p, *parent = NULL;
	struct ubifs_bud *b;
	struct ubifs_jhead *jhead;

	spin_lock(&c->buds_lock);
	p = &c->buds.rb_node;
	while (*p) {
		parent = *p;
		b = rb_entry(parent, struct ubifs_bud, rb);
		ubifs_assert(bud->lnum != b->lnum);
		if (bud->lnum < b->lnum)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	rb_link_node(&bud->rb, parent, p);
	rb_insert_color(&bud->rb, &c->buds);
	if (c->jheads) {
		jhead = &c->jheads[bud->jhead];
		list_add_tail(&bud->list, &jhead->buds_list);
	} else
		ubifs_assert(c->replaying && c->ro_mount);

	/*
	 * Note, although this is a new bud, we anyway account this space now,
	 * before any data has been written to it, because this is about to
	 * guarantee fixed mount time, and this bud will anyway be read and
	 * scanned.
	 */
	c->bud_bytes += c->leb_size - bud->start;

	dbg_log("LEB %d:%d, jhead %s, bud_bytes %lld", bud->lnum,
		bud->start, dbg_jhead(bud->jhead), c->bud_bytes);
	spin_unlock(&c->buds_lock);
}

/**
 * ubifs_add_bud_to_log - add a new bud to the log.
 * @c: UBIFS file-system description object
 * @jhead: journal head the bud belongs to
 * @lnum: LEB number of the bud
 * @offs: starting offset of the bud
 *
 * This function writes reference node for the new bud LEB @lnum it to the log,
 * and adds it to the buds tress. It also makes sure that log size does not
 * exceed the 'c->max_bud_bytes' limit. Returns zero in case of success,
 * %-EAGAIN if commit is required, and a negative error codes in case of
 * failure.
 */
int ubifs_add_bud_to_log(struct ubifs_info *c, int jhead, int lnum, int offs)
{
	int err;
	struct ubifs_bud *bud;
	struct ubifs_ref_node *ref;

	bud = kmalloc(sizeof(struct ubifs_bud), GFP_NOFS);
	if (!bud)
		return -ENOMEM;
	ref = kzalloc(c->ref_node_alsz, GFP_NOFS);
	if (!ref) {
		kfree(bud);
		return -ENOMEM;
	}

	mutex_lock(&c->log_mutex);
	ubifs_assert(!c->ro_media && !c->ro_mount);
	if (c->ro_error) {
		err = -EROFS;
		goto out_unlock;
	}

	/* Make sure we have enough space in the log */
	if (empty_log_bytes(c) - c->ref_node_alsz < c->min_log_bytes) {
		dbg_log("not enough log space - %lld, required %d",
			empty_log_bytes(c), c->min_log_bytes);
		ubifs_commit_required(c);
		err = -EAGAIN;
		goto out_unlock;
	}

	/*
	 * Make sure the amount of space in buds will not exceed the
	 * 'c->max_bud_bytes' limit, because we want to guarantee mount time
	 * limits.
	 *
	 * It is not necessary to hold @c->buds_lock when reading @c->bud_bytes
	 * because we are holding @c->log_mutex. All @c->bud_bytes take place
	 * when both @c->log_mutex and @c->bud_bytes are locked.
	 */
	if (c->bud_bytes + c->leb_size - offs > c->max_bud_bytes) {
		dbg_log("bud bytes %lld (%lld max), require commit",
			c->bud_bytes, c->max_bud_bytes);
		ubifs_commit_required(c);
		err = -EAGAIN;
		goto out_unlock;
	}

	/*
	 * If the journal is full enough - start background commit. Note, it is
	 * OK to read 'c->cmt_state' without spinlock because integer reads
	 * are atomic in the kernel.
	 */
	if (c->bud_bytes >= c->bg_bud_bytes &&
	    c->cmt_state == COMMIT_RESTING) {
		dbg_log("bud bytes %lld (%lld max), initiate BG commit",
			c->bud_bytes, c->max_bud_bytes);
		ubifs_request_bg_commit(c);
	}

	bud->lnum = lnum;
	bud->start = offs;
	bud->jhead = jhead;

	ref->ch.node_type = UBIFS_REF_NODE;
	ref->lnum = cpu_to_le32(bud->lnum);
	ref->offs = cpu_to_le32(bud->start);
	ref->jhead = cpu_to_le32(jhead);

	if (c->lhead_offs > c->leb_size - c->ref_node_alsz) {
		c->lhead_lnum = ubifs_next_log_lnum(c, c->lhead_lnum);
		ubifs_assert(c->lhead_lnum != c->ltail_lnum);
		c->lhead_offs = 0;
	}

	if (c->lhead_offs == 0) {
		/* Must ensure next log LEB has been unmapped */
		err = ubifs_leb_unmap(c, c->lhead_lnum);
		if (err)
			goto out_unlock;
	}

	if (bud->start == 0) {
		/*
		 * Before writing the LEB reference which refers an empty LEB
		 * to the log, we have to make sure it is mapped, because
		 * otherwise we'd risk to refer an LEB with garbage in case of
		 * an unclean reboot, because the target LEB might have been
		 * unmapped, but not yet physically erased.
		 */
		err = ubifs_leb_map(c, bud->lnum);
		if (err)
			goto out_unlock;
	}

	dbg_log("write ref LEB %d:%d",
		c->lhead_lnum, c->lhead_offs);
	err = ubifs_write_node(c, ref, UBIFS_REF_NODE_SZ, c->lhead_lnum,
			       c->lhead_offs);
	if (err)
		goto out_unlock;

	c->lhead_offs += c->ref_node_alsz;

	ubifs_add_bud(c, bud);

	mutex_unlock(&c->log_mutex);
	kfree(ref);
	return 0;

out_unlock:
	mutex_unlock(&c->log_mutex);
	kfree(ref);
	kfree(bud);
	return err;
}

/**
 * remove_buds - remove used buds.
 * @c: UBIFS file-system description object
 *
 * This function removes use buds from the buds tree. It does not remove the
 * buds which are pointed to by journal heads.
 */
static void remove_buds(struct ubifs_info *c)
{
	struct rb_node *p;

	ubifs_assert(list_empty(&c->old_buds));
	c->cmt_bud_bytes = 0;
	spin_lock(&c->buds_lock);
	p = rb_first(&c->buds);
	while (p) {
		struct rb_node *p1 = p;
		struct ubifs_bud *bud;
		struct ubifs_wbuf *wbuf;

		p = rb_next(p);
		bud = rb_entry(p1, struct ubifs_bud, rb);
		wbuf = &c->jheads[bud->jhead].wbuf;

		if (wbuf->lnum == bud->lnum) {
			/*
			 * Do not remove buds which are pointed to by journal
			 * heads (non-closed buds).
			 */
			c->cmt_bud_bytes += wbuf->offs - bud->start;
			dbg_log("preserve %d:%d, jhead %s, bud bytes %d, cmt_bud_bytes %lld",
				bud->lnum, bud->start, dbg_jhead(bud->jhead),
				wbuf->offs - bud->start, c->cmt_bud_bytes);
			bud->start = wbuf->offs;
		} else {
			c->cmt_bud_bytes += c->leb_size - bud->start;
			dbg_log("remove %d:%d, jhead %s, bud bytes %d, cmt_bud_bytes %lld",
				bud->lnum, bud->start, dbg_jhead(bud->jhead),
				c->leb_size - bud->start, c->cmt_bud_bytes);
			rb_erase(p1, &c->buds);
			/*
			 * If the commit does not finish, the recovery will need
			 * to replay the journal, in which case the old buds
			 * must be unchanged. Do not release them until post
			 * commit i.e. do not allow them to be garbage
			 * collected.
			 */
			list_move(&bud->list, &c->old_buds);
		}
	}
	spin_unlock(&c->buds_lock);
}

/**
 * ubifs_log_start_commit - start commit.
 * @c: UBIFS file-system description object
 * @ltail_lnum: return new log tail LEB number
 *
 * The commit operation starts with writing "commit start" node to the log and
 * reference nodes for all journal heads which will define new journal after
 * the commit has been finished. The commit start and reference nodes are
 * written in one go to the nearest empty log LEB (hence, when commit is
 * finished UBIFS may safely unmap all the previous log LEBs). This function
 * returns zero in case of success and a negative error code in case of
 * failure.
 */
int ubifs_log_start_commit(struct ubifs_info *c, int *ltail_lnum)
{
	void *buf;
	struct ubifs_cs_node *cs;
	struct ubifs_ref_node *ref;
	int err, i, max_len, len;

	err = dbg_check_bud_bytes(c);
	if (err)
		return err;

	max_len = UBIFS_CS_NODE_SZ + c->jhead_cnt * UBIFS_REF_NODE_SZ;
	max_len = ALIGN(max_len, c->min_io_size);
	buf = cs = kmalloc(max_len, GFP_NOFS);
	if (!buf)
		return -ENOMEM;

	cs->ch.node_type = UBIFS_CS_NODE;
	cs->cmt_no = cpu_to_le64(c->cmt_no);
	ubifs_prepare_node(c, cs, UBIFS_CS_NODE_SZ, 0);

	/*
	 * Note, we do not lock 'c->log_mutex' because this is the commit start
	 * phase and we are exclusively using the log. And we do not lock
	 * write-buffer because nobody can write to the file-system at this
	 * phase.
	 */

	len = UBIFS_CS_NODE_SZ;
	for (i = 0; i < c->jhead_cnt; i++) {
		int lnum = c->jheads[i].wbuf.lnum;
		int offs = c->jheads[i].wbuf.offs;

		if (lnum == -1 || offs == c->leb_size)
			continue;

		dbg_log("add ref to LEB %d:%d for jhead %s",
			lnum, offs, dbg_jhead(i));
		ref = buf + len;
		ref->ch.node_type = UBIFS_REF_NODE;
		ref->lnum = cpu_to_le32(lnum);
		ref->offs = cpu_to_le32(offs);
		ref->jhead = cpu_to_le32(i);

		ubifs_prepare_node(c, ref, UBIFS_REF_NODE_SZ, 0);
		len += UBIFS_REF_NODE_SZ;
	}

	ubifs_pad(c, buf + len, ALIGN(len, c->min_io_size) - len);

	/* Switch to the next log LEB */
	if (c->lhead_offs) {
		c->lhead_lnum = ubifs_next_log_lnum(c, c->lhead_lnum);
		ubifs_assert(c->lhead_lnum != c->ltail_lnum);
		c->lhead_offs = 0;
	}

	/* Must ensure next LEB has been unmapped */
	err = ubifs_leb_unmap(c, c->lhead_lnum);
	if (err)
		goto out;

	len = ALIGN(len, c->min_io_size);
	dbg_log("writing commit start at LEB %d:0, len %d", c->lhead_lnum, len);
	err = ubifs_leb_write(c, c->lhead_lnum, cs, 0, len);
	if (err)
		goto out;

	*ltail_lnum = c->lhead_lnum;

	c->lhead_offs += len;
	if (c->lhead_offs == c->leb_size) {
		c->lhead_lnum = ubifs_next_log_lnum(c, c->lhead_lnum);
		c->lhead_offs = 0;
	}

	remove_buds(c);

	/*
	 * We have started the commit and now users may use the rest of the log
	 * for new writes.
	 */
	c->min_log_bytes = 0;

out:
	kfree(buf);
	return err;
}

/**
 * ubifs_log_end_commit - end commit.
 * @c: UBIFS file-system description object
 * @ltail_lnum: new log tail LEB number
 *
 * This function is called on when the commit operation was finished. It
 * moves log tail to new position and updates the master node so that it stores
 * the new log tail LEB number. Returns zero in case of success and a negative
 * error code in case of failure.
 */
int ubifs_log_end_commit(struct ubifs_info *c, int ltail_lnum)
{
	int err;

	/*
	 * At this phase we have to lock 'c->log_mutex' because UBIFS allows FS
	 * writes during commit. Its only short "commit" start phase when
	 * writers are blocked.
	 */
	mutex_lock(&c->log_mutex);

	dbg_log("old tail was LEB %d:0, new tail is LEB %d:0",
		c->ltail_lnum, ltail_lnum);

	c->ltail_lnum = ltail_lnum;
	/*
	 * The commit is finished and from now on it must be guaranteed that
	 * there is always enough space for the next commit.
	 */
	c->min_log_bytes = c->leb_size;

	spin_lock(&c->buds_lock);
	c->bud_bytes -= c->cmt_bud_bytes;
	spin_unlock(&c->buds_lock);

	err = dbg_check_bud_bytes(c);
	if (err)
		goto out;

	err = ubifs_write_master(c);

out:
	mutex_unlock(&c->log_mutex);
	return err;
}

/**
 * ubifs_log_post_commit - things to do after commit is completed.
 * @c: UBIFS file-system description object
 * @old_ltail_lnum: old log tail LEB number
 *
 * Release buds only after commit is completed, because they must be unchanged
 * if recovery is needed.
 *
 * Unmap log LEBs only after commit is completed, because they may be needed for
 * recovery.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_log_post_commit(struct ubifs_info *c, int old_ltail_lnum)
{
	int lnum, err = 0;

	while (!list_empty(&c->old_buds)) {
		struct ubifs_bud *bud;

		bud = list_entry(c->old_buds.next, struct ubifs_bud, list);
		err = ubifs_return_leb(c, bud->lnum);
		if (err)
			return err;
		list_del(&bud->list);
		kfree(bud);
	}
	mutex_lock(&c->log_mutex);
	for (lnum = old_ltail_lnum; lnum != c->ltail_lnum;
	     lnum = ubifs_next_log_lnum(c, lnum)) {
		dbg_log("unmap log LEB %d", lnum);
		err = ubifs_leb_unmap(c, lnum);
		if (err)
			goto out;
	}
out:
	mutex_unlock(&c->log_mutex);
	return err;
}

/**
 * struct done_ref - references that have been done.
 * @rb: rb-tree node
 * @lnum: LEB number
 */
struct done_ref {
	struct rb_node rb;
	int lnum;
};

/**
 * done_already - determine if a reference has been done already.
 * @done_tree: rb-tree to store references that have been done
 * @lnum: LEB number of reference
 *
 * This function returns %1 if the reference has been done, %0 if not, otherwise
 * a negative error code is returned.
 */
static int done_already(struct rb_root *done_tree, int lnum)
{
	struct rb_node **p = &done_tree->rb_node, *parent = NULL;
	struct done_ref *dr;

	while (*p) {
		parent = *p;
		dr = rb_entry(parent, struct done_ref, rb);
		if (lnum < dr->lnum)
			p = &(*p)->rb_left;
		else if (lnum > dr->lnum)
			p = &(*p)->rb_right;
		else
			return 1;
	}

	dr = kzalloc(sizeof(struct done_ref), GFP_NOFS);
	if (!dr)
		return -ENOMEM;

	dr->lnum = lnum;

	rb_link_node(&dr->rb, parent, p);
	rb_insert_color(&dr->rb, done_tree);

	return 0;
}

/**
 * destroy_done_tree - destroy the done tree.
 * @done_tree: done tree to destroy
 */
static void destroy_done_tree(struct rb_root *done_tree)
{
	struct done_ref *dr, *n;

	rbtree_postorder_for_each_entry_safe(dr, n, done_tree, rb)
		kfree(dr);
}

/**
 * add_node - add a node to the consolidated log.
 * @c: UBIFS file-system description object
 * @buf: buffer to which to add
 * @lnum: LEB number to which to write is passed and returned here
 * @offs: offset to where to write is passed and returned here
 * @node: node to add
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int add_node(struct ubifs_info *c, void *buf, int *lnum, int *offs,
		    void *node)
{
	struct ubifs_ch *ch = node;
	int len = le32_to_cpu(ch->len), remains = c->leb_size - *offs;

	if (len > remains) {
		int sz = ALIGN(*offs, c->min_io_size), err;

		ubifs_pad(c, buf + *offs, sz - *offs);
		err = ubifs_leb_change(c, *lnum, buf, sz);
		if (err)
			return err;
		*lnum = ubifs_next_log_lnum(c, *lnum);
		*offs = 0;
	}
	memcpy(buf + *offs, node, len);
	*offs += ALIGN(len, 8);
	return 0;
}

/**
 * ubifs_consolidate_log - consolidate the log.
 * @c: UBIFS file-system description object
 *
 * Repeated failed commits could cause the log to be full, but at least 1 LEB is
 * needed for commit. This function rewrites the reference nodes in the log
 * omitting duplicates, and failed CS nodes, and leaving no gaps.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_consolidate_log(struct ubifs_info *c)
{
	struct ubifs_scan_leb *sleb;
	struct ubifs_scan_node *snod;
	struct rb_root done_tree = RB_ROOT;
	int lnum, err, first = 1, write_lnum, offs = 0;
	void *buf;

	dbg_rcvry("log tail LEB %d, log head LEB %d", c->ltail_lnum,
		  c->lhead_lnum);
	buf = vmalloc(c->leb_size);
	if (!buf)
		return -ENOMEM;
	lnum = c->ltail_lnum;
	write_lnum = lnum;
	while (1) {
		sleb = ubifs_scan(c, lnum, 0, c->sbuf, 0);
		if (IS_ERR(sleb)) {
			err = PTR_ERR(sleb);
			goto out_free;
		}
		list_for_each_entry(snod, &sleb->nodes, list) {
			switch (snod->type) {
			case UBIFS_REF_NODE: {
				struct ubifs_ref_node *ref = snod->node;
				int ref_lnum = le32_to_cpu(ref->lnum);

				err = done_already(&done_tree, ref_lnum);
				if (err < 0)
					goto out_scan;
				if (err != 1) {
					err = add_node(c, buf, &write_lnum,
						       &offs, snod->node);
					if (err)
						goto out_scan;
				}
				break;
			}
			case UBIFS_CS_NODE:
				if (!first)
					break;
				err = add_node(c, buf, &write_lnum, &offs,
					       snod->node);
				if (err)
					goto out_scan;
				first = 0;
				break;
			}
		}
		ubifs_scan_destroy(sleb);
		if (lnum == c->lhead_lnum)
			break;
		lnum = ubifs_next_log_lnum(c, lnum);
	}
	if (offs) {
		int sz = ALIGN(offs, c->min_io_size);

		ubifs_pad(c, buf + offs, sz - offs);
		err = ubifs_leb_change(c, write_lnum, buf, sz);
		if (err)
			goto out_free;
		offs = ALIGN(offs, c->min_io_size);
	}
	destroy_done_tree(&done_tree);
	vfree(buf);
	if (write_lnum == c->lhead_lnum) {
		ubifs_err("log is too full");
		return -EINVAL;
	}
	/* Unmap remaining LEBs */
	lnum = write_lnum;
	do {
		lnum = ubifs_next_log_lnum(c, lnum);
		err = ubifs_leb_unmap(c, lnum);
		if (err)
			return err;
	} while (lnum != c->lhead_lnum);
	c->lhead_lnum = write_lnum;
	c->lhead_offs = offs;
	dbg_rcvry("new log head at %d:%d", c->lhead_lnum, c->lhead_offs);
	return 0;

out_scan:
	ubifs_scan_destroy(sleb);
out_free:
	destroy_done_tree(&done_tree);
	vfree(buf);
	return err;
}

/**
 * dbg_check_bud_bytes - make sure bud bytes calculation are all right.
 * @c: UBIFS file-system description object
 *
 * This function makes sure the amount of flash space used by closed buds
 * ('c->bud_bytes' is correct). Returns zero in case of success and %-EINVAL in
 * case of failure.
 */
static int dbg_check_bud_bytes(struct ubifs_info *c)
{
	int i, err = 0;
	struct ubifs_bud *bud;
	long long bud_bytes = 0;

	if (!dbg_is_chk_gen(c))
		return 0;

	spin_lock(&c->buds_lock);
	for (i = 0; i < c->jhead_cnt; i++)
		list_for_each_entry(bud, &c->jheads[i].buds_list, list)
			bud_bytes += c->leb_size - bud->start;

	if (c->bud_bytes != bud_bytes) {
		ubifs_err("bad bud_bytes %lld, calculated %lld",
			  c->bud_bytes, bud_bytes);
		err = -EINVAL;
	}
	spin_unlock(&c->buds_lock);

	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/log.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements functions that manage the running of the commit process.
 * Each affected module has its own functions to accomplish their part in the
 * commit and those functions are called here.
 *
 * The commit is the process whereby all updates to the index and LEB properties
 * are written out together and the journal becomes empty. This keeps the
 * file system consistent - at all times the state can be recreated by reading
 * the index and LEB properties and then replaying the journal.
 *
 * The commit is split into two parts named "commit start" and "commit end".
 * During commit start, the commit process has exclusive access to the journal
 * by holding the commit semaphore down for writing. As few I/O operations as
 * possible are performed during commit start, instead the nodes that are to be
 * written are merely identified. During commit end, the commit semaphore is no
 * longer held and the journal is again in operation, allowing users to continue
 * to use the file system while the bulk of the commit I/O is performed. The
 * purpose of this two-step approach is to prevent the commit from causing any
 * latency blips. Note that in any case, the commit does not prevent lookups
 * (as permitted by the TNC mutex), or access to VFS data structures e.g. page
 * cache.
 */

#include <linux/freezer.h>
// #include <linux/kthread.h>
// #include <linux/slab.h>
// #include "ubifs.h"
#include "../../inc/__fss.h"

/*
 * nothing_to_commit - check if there is nothing to commit.
 * @c: UBIFS file-system description object
 *
 * This is a helper function which checks if there is anything to commit. It is
 * used as an optimization to avoid starting the commit if it is not really
 * necessary. Indeed, the commit operation always assumes flash I/O (e.g.,
 * writing the commit start node to the log), and it is better to avoid doing
 * this unnecessarily. E.g., 'ubifs_sync_fs()' runs the commit, but if there is
 * nothing to commit, it is more optimal to avoid any flash I/O.
 *
 * This function has to be called with @c->commit_sem locked for writing -
 * this function does not take LPT/TNC locks because the @c->commit_sem
 * guarantees that we have exclusive access to the TNC and LPT data structures.
 *
 * This function returns %1 if there is nothing to commit and %0 otherwise.
 */
static int nothing_to_commit(struct ubifs_info *c)
{
	/*
	 * During mounting or remounting from R/O mode to R/W mode we may
	 * commit for various recovery-related reasons.
	 */
	if (c->mounting || c->remounting_rw)
		return 0;

	/*
	 * If the root TNC node is dirty, we definitely have something to
	 * commit.
	 */
	if (c->zroot.znode && ubifs_zn_dirty(c->zroot.znode))
		return 0;

	/*
	 * Even though the TNC is clean, the LPT tree may have dirty nodes. For
	 * example, this may happen if the budgeting subsystem invoked GC to
	 * make some free space, and the GC found an LEB with only dirty and
	 * free space. In this case GC would just change the lprops of this
	 * LEB (by turning all space into free space) and unmap it.
	 */
	if (c->nroot && test_bit(DIRTY_CNODE, &c->nroot->flags))
		return 0;

	ubifs_assert(atomic_long_read(&c->dirty_zn_cnt) == 0);
	ubifs_assert(c->dirty_pn_cnt == 0);
	ubifs_assert(c->dirty_nn_cnt == 0);

	return 1;
}

/**
 * do_commit - commit the journal.
 * @c: UBIFS file-system description object
 *
 * This function implements UBIFS commit. It has to be called with commit lock
 * locked. Returns zero in case of success and a negative error code in case of
 * failure.
 */
static int do_commit(struct ubifs_info *c)
{
	int err, new_ltail_lnum, old_ltail_lnum, i;
	struct ubifs_zbranch zroot;
	struct ubifs_lp_stats lst;

	dbg_cmt("start");
	ubifs_assert(!c->ro_media && !c->ro_mount);

	if (c->ro_error) {
		err = -EROFS;
		goto out_up;
	}

	if (nothing_to_commit(c)) {
		up_write(&c->commit_sem);
		err = 0;
		goto out_cancel;
	}

	/* Sync all write buffers (necessary for recovery) */
	for (i = 0; i < c->jhead_cnt; i++) {
		err = ubifs_wbuf_sync(&c->jheads[i].wbuf);
		if (err)
			goto out_up;
	}

	c->cmt_no += 1;
	err = ubifs_gc_start_commit(c);
	if (err)
		goto out_up;
	err = dbg_check_lprops(c);
	if (err)
		goto out_up;
	err = ubifs_log_start_commit(c, &new_ltail_lnum);
	if (err)
		goto out_up;
	err = ubifs_tnc_start_commit(c, &zroot);
	if (err)
		goto out_up;
	err = ubifs_lpt_start_commit(c);
	if (err)
		goto out_up;
	err = ubifs_orphan_start_commit(c);
	if (err)
		goto out_up;

	ubifs_get_lp_stats(c, &lst);

	up_write(&c->commit_sem);

	err = ubifs_tnc_end_commit(c);
	if (err)
		goto out;
	err = ubifs_lpt_end_commit(c);
	if (err)
		goto out;
	err = ubifs_orphan_end_commit(c);
	if (err)
		goto out;
	err = dbg_check_old_index(c, &zroot);
	if (err)
		goto out;

	c->mst_node->cmt_no      = cpu_to_le64(c->cmt_no);
	c->mst_node->log_lnum    = cpu_to_le32(new_ltail_lnum);
	c->mst_node->root_lnum   = cpu_to_le32(zroot.lnum);
	c->mst_node->root_offs   = cpu_to_le32(zroot.offs);
	c->mst_node->root_len    = cpu_to_le32(zroot.len);
	c->mst_node->ihead_lnum  = cpu_to_le32(c->ihead_lnum);
	c->mst_node->ihead_offs  = cpu_to_le32(c->ihead_offs);
	c->mst_node->index_size  = cpu_to_le64(c->bi.old_idx_sz);
	c->mst_node->lpt_lnum    = cpu_to_le32(c->lpt_lnum);
	c->mst_node->lpt_offs    = cpu_to_le32(c->lpt_offs);
	c->mst_node->nhead_lnum  = cpu_to_le32(c->nhead_lnum);
	c->mst_node->nhead_offs  = cpu_to_le32(c->nhead_offs);
	c->mst_node->ltab_lnum   = cpu_to_le32(c->ltab_lnum);
	c->mst_node->ltab_offs   = cpu_to_le32(c->ltab_offs);
	c->mst_node->lsave_lnum  = cpu_to_le32(c->lsave_lnum);
	c->mst_node->lsave_offs  = cpu_to_le32(c->lsave_offs);
	c->mst_node->lscan_lnum  = cpu_to_le32(c->lscan_lnum);
	c->mst_node->empty_lebs  = cpu_to_le32(lst.empty_lebs);
	c->mst_node->idx_lebs    = cpu_to_le32(lst.idx_lebs);
	c->mst_node->total_free  = cpu_to_le64(lst.total_free);
	c->mst_node->total_dirty = cpu_to_le64(lst.total_dirty);
	c->mst_node->total_used  = cpu_to_le64(lst.total_used);
	c->mst_node->total_dead  = cpu_to_le64(lst.total_dead);
	c->mst_node->total_dark  = cpu_to_le64(lst.total_dark);
	if (c->no_orphs)
		c->mst_node->flags |= cpu_to_le32(UBIFS_MST_NO_ORPHS);
	else
		c->mst_node->flags &= ~cpu_to_le32(UBIFS_MST_NO_ORPHS);

	old_ltail_lnum = c->ltail_lnum;
	err = ubifs_log_end_commit(c, new_ltail_lnum);
	if (err)
		goto out;

	err = ubifs_log_post_commit(c, old_ltail_lnum);
	if (err)
		goto out;
	err = ubifs_gc_end_commit(c);
	if (err)
		goto out;
	err = ubifs_lpt_post_commit(c);
	if (err)
		goto out;

out_cancel:
	spin_lock(&c->cs_lock);
	c->cmt_state = COMMIT_RESTING;
	wake_up(&c->cmt_wq);
	dbg_cmt("commit end");
	spin_unlock(&c->cs_lock);
	return 0;

out_up:
	up_write(&c->commit_sem);
out:
	ubifs_err("commit failed, error %d", err);
	spin_lock(&c->cs_lock);
	c->cmt_state = COMMIT_BROKEN;
	wake_up(&c->cmt_wq);
	spin_unlock(&c->cs_lock);
	ubifs_ro_mode(c, err);
	return err;
}

/**
 * run_bg_commit - run background commit if it is needed.
 * @c: UBIFS file-system description object
 *
 * This function runs background commit if it is needed. Returns zero in case
 * of success and a negative error code in case of failure.
 */
static int run_bg_commit(struct ubifs_info *c)
{
	spin_lock(&c->cs_lock);
	/*
	 * Run background commit only if background commit was requested or if
	 * commit is required.
	 */
	if (c->cmt_state != COMMIT_BACKGROUND &&
	    c->cmt_state != COMMIT_REQUIRED)
		goto out;
	spin_unlock(&c->cs_lock);

	down_write(&c->commit_sem);
	spin_lock(&c->cs_lock);
	if (c->cmt_state == COMMIT_REQUIRED)
		c->cmt_state = COMMIT_RUNNING_REQUIRED;
	else if (c->cmt_state == COMMIT_BACKGROUND)
		c->cmt_state = COMMIT_RUNNING_BACKGROUND;
	else
		goto out_cmt_unlock;
	spin_unlock(&c->cs_lock);

	return do_commit(c);

out_cmt_unlock:
	up_write(&c->commit_sem);
out:
	spin_unlock(&c->cs_lock);
	return 0;
}

/**
 * ubifs_bg_thread - UBIFS background thread function.
 * @info: points to the file-system description object
 *
 * This function implements various file-system background activities:
 * o when a write-buffer timer expires it synchronizes the appropriate
 *   write-buffer;
 * o when the journal is about to be full, it starts in-advance commit.
 *
 * Note, other stuff like background garbage collection may be added here in
 * future.
 */
int ubifs_bg_thread(void *info)
{
	int err;
	struct ubifs_info *c = info;

	ubifs_msg("background thread \"%s\" started, PID %d",
		  c->bgt_name, current->pid);
	set_freezable();

	while (1) {
		if (kthread_should_stop())
			break;

		if (try_to_freeze())
			continue;

		set_current_state(TASK_INTERRUPTIBLE);
		/* Check if there is something to do */
		if (!c->need_bgt) {
			/*
			 * Nothing prevents us from going sleep now and
			 * be never woken up and block the task which
			 * could wait in 'kthread_stop()' forever.
			 */
			if (kthread_should_stop())
				break;
			schedule();
			continue;
		} else
			__set_current_state(TASK_RUNNING);

		c->need_bgt = 0;
		err = ubifs_bg_wbufs_sync(c);
		if (err)
			ubifs_ro_mode(c, err);

		run_bg_commit(c);
		cond_resched();
	}

	ubifs_msg("background thread \"%s\" stops", c->bgt_name);
	return 0;
}

/**
 * ubifs_commit_required - set commit state to "required".
 * @c: UBIFS file-system description object
 *
 * This function is called if a commit is required but cannot be done from the
 * calling function, so it is just flagged instead.
 */
void ubifs_commit_required(struct ubifs_info *c)
{
	spin_lock(&c->cs_lock);
	switch (c->cmt_state) {
	case COMMIT_RESTING:
	case COMMIT_BACKGROUND:
		dbg_cmt("old: %s, new: %s", dbg_cstate(c->cmt_state),
			dbg_cstate(COMMIT_REQUIRED));
		c->cmt_state = COMMIT_REQUIRED;
		break;
	case COMMIT_RUNNING_BACKGROUND:
		dbg_cmt("old: %s, new: %s", dbg_cstate(c->cmt_state),
			dbg_cstate(COMMIT_RUNNING_REQUIRED));
		c->cmt_state = COMMIT_RUNNING_REQUIRED;
		break;
	case COMMIT_REQUIRED:
	case COMMIT_RUNNING_REQUIRED:
	case COMMIT_BROKEN:
		break;
	}
	spin_unlock(&c->cs_lock);
}

/**
 * ubifs_request_bg_commit - notify the background thread to do a commit.
 * @c: UBIFS file-system description object
 *
 * This function is called if the journal is full enough to make a commit
 * worthwhile, so background thread is kicked to start it.
 */
void ubifs_request_bg_commit(struct ubifs_info *c)
{
	spin_lock(&c->cs_lock);
	if (c->cmt_state == COMMIT_RESTING) {
		dbg_cmt("old: %s, new: %s", dbg_cstate(c->cmt_state),
			dbg_cstate(COMMIT_BACKGROUND));
		c->cmt_state = COMMIT_BACKGROUND;
		spin_unlock(&c->cs_lock);
		ubifs_wake_up_bgt(c);
	} else
		spin_unlock(&c->cs_lock);
}

/**
 * wait_for_commit - wait for commit.
 * @c: UBIFS file-system description object
 *
 * This function sleeps until the commit operation is no longer running.
 */
static int wait_for_commit(struct ubifs_info *c)
{
	dbg_cmt("pid %d goes sleep", current->pid);

	/*
	 * The following sleeps if the condition is false, and will be woken
	 * when the commit ends. It is possible, although very unlikely, that we
	 * will wake up and see the subsequent commit running, rather than the
	 * one we were waiting for, and go back to sleep.  However, we will be
	 * woken again, so there is no danger of sleeping forever.
	 */
	wait_event(c->cmt_wq, c->cmt_state != COMMIT_RUNNING_BACKGROUND &&
			      c->cmt_state != COMMIT_RUNNING_REQUIRED);
	dbg_cmt("commit finished, pid %d woke up", current->pid);
	return 0;
}

/**
 * ubifs_run_commit - run or wait for commit.
 * @c: UBIFS file-system description object
 *
 * This function runs commit and returns zero in case of success and a negative
 * error code in case of failure.
 */
int ubifs_run_commit(struct ubifs_info *c)
{
	int err = 0;

	spin_lock(&c->cs_lock);
	if (c->cmt_state == COMMIT_BROKEN) {
		err = -EROFS;
		goto out;
	}

	if (c->cmt_state == COMMIT_RUNNING_BACKGROUND)
		/*
		 * We set the commit state to 'running required' to indicate
		 * that we want it to complete as quickly as possible.
		 */
		c->cmt_state = COMMIT_RUNNING_REQUIRED;

	if (c->cmt_state == COMMIT_RUNNING_REQUIRED) {
		spin_unlock(&c->cs_lock);
		return wait_for_commit(c);
	}
	spin_unlock(&c->cs_lock);

	/* Ok, the commit is indeed needed */

	down_write(&c->commit_sem);
	spin_lock(&c->cs_lock);
	/*
	 * Since we unlocked 'c->cs_lock', the state may have changed, so
	 * re-check it.
	 */
	if (c->cmt_state == COMMIT_BROKEN) {
		err = -EROFS;
		goto out_cmt_unlock;
	}

	if (c->cmt_state == COMMIT_RUNNING_BACKGROUND)
		c->cmt_state = COMMIT_RUNNING_REQUIRED;

	if (c->cmt_state == COMMIT_RUNNING_REQUIRED) {
		up_write(&c->commit_sem);
		spin_unlock(&c->cs_lock);
		return wait_for_commit(c);
	}
	c->cmt_state = COMMIT_RUNNING_REQUIRED;
	spin_unlock(&c->cs_lock);

	err = do_commit(c);
	return err;

out_cmt_unlock:
	up_write(&c->commit_sem);
out:
	spin_unlock(&c->cs_lock);
	return err;
}

/**
 * ubifs_gc_should_commit - determine if it is time for GC to run commit.
 * @c: UBIFS file-system description object
 *
 * This function is called by garbage collection to determine if commit should
 * be run. If commit state is @COMMIT_BACKGROUND, which means that the journal
 * is full enough to start commit, this function returns true. It is not
 * absolutely necessary to commit yet, but it feels like this should be better
 * then to keep doing GC. This function returns %1 if GC has to initiate commit
 * and %0 if not.
 */
int ubifs_gc_should_commit(struct ubifs_info *c)
{
	int ret = 0;

	spin_lock(&c->cs_lock);
	if (c->cmt_state == COMMIT_BACKGROUND) {
		dbg_cmt("commit required now");
		c->cmt_state = COMMIT_REQUIRED;
	} else
		dbg_cmt("commit not requested");
	if (c->cmt_state == COMMIT_REQUIRED)
		ret = 1;
	spin_unlock(&c->cs_lock);
	return ret;
}

/*
 * Everything below is related to debugging.
 */

/**
 * struct idx_node - hold index nodes during index tree traversal.
 * @list: list
 * @iip: index in parent (slot number of this indexing node in the parent
 *       indexing node)
 * @upper_key: all keys in this indexing node have to be less or equivalent to
 *             this key
 * @idx: index node (8-byte aligned because all node structures must be 8-byte
 *       aligned)
 */
struct idx_node {
	struct list_head list;
	int iip;
	union ubifs_key upper_key;
	struct ubifs_idx_node idx __aligned(8);
};

/**
 * dbg_old_index_check_init - get information for the next old index check.
 * @c: UBIFS file-system description object
 * @zroot: root of the index
 *
 * This function records information about the index that will be needed for the
 * next old index check i.e. 'dbg_check_old_index()'.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int dbg_old_index_check_init(struct ubifs_info *c, struct ubifs_zbranch *zroot)
{
	struct ubifs_idx_node *idx;
	int lnum, offs, len, err = 0;
	struct ubifs_debug_info *d = c->dbg;

	d->old_zroot = *zroot;
	lnum = d->old_zroot.lnum;
	offs = d->old_zroot.offs;
	len = d->old_zroot.len;

	idx = kmalloc(c->max_idx_node_sz, GFP_NOFS);
	if (!idx)
		return -ENOMEM;

	err = ubifs_read_node(c, idx, UBIFS_IDX_NODE, len, lnum, offs);
	if (err)
		goto out;

	d->old_zroot_level = le16_to_cpu(idx->level);
	d->old_zroot_sqnum = le64_to_cpu(idx->ch.sqnum);
out:
	kfree(idx);
	return err;
}

/**
 * dbg_check_old_index - check the old copy of the index.
 * @c: UBIFS file-system description object
 * @zroot: root of the new index
 *
 * In order to be able to recover from an unclean unmount, a complete copy of
 * the index must exist on flash. This is the "old" index. The commit process
 * must write the "new" index to flash without overwriting or destroying any
 * part of the old index. This function is run at commit end in order to check
 * that the old index does indeed exist completely intact.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int dbg_check_old_index(struct ubifs_info *c, struct ubifs_zbranch *zroot)
{
	int lnum, offs, len, err = 0, uninitialized_var(last_level), child_cnt;
	int first = 1, iip;
	struct ubifs_debug_info *d = c->dbg;
	union ubifs_key uninitialized_var(lower_key), upper_key, l_key, u_key;
	unsigned long long uninitialized_var(last_sqnum);
	struct ubifs_idx_node *idx;
	struct list_head list;
	struct idx_node *i;
	size_t sz;

	if (!dbg_is_chk_index(c))
		return 0;

	INIT_LIST_HEAD(&list);

	sz = sizeof(struct idx_node) + ubifs_idx_node_sz(c, c->fanout) -
	     UBIFS_IDX_NODE_SZ;

	/* Start at the old zroot */
	lnum = d->old_zroot.lnum;
	offs = d->old_zroot.offs;
	len = d->old_zroot.len;
	iip = 0;

	/*
	 * Traverse the index tree preorder depth-first i.e. do a node and then
	 * its subtrees from left to right.
	 */
	while (1) {
		struct ubifs_branch *br;

		/* Get the next index node */
		i = kmalloc(sz, GFP_NOFS);
		if (!i) {
			err = -ENOMEM;
			goto out_free;
		}
		i->iip = iip;
		/* Keep the index nodes on our path in a linked list */
		list_add_tail(&i->list, &list);
		/* Read the index node */
		idx = &i->idx;
		err = ubifs_read_node(c, idx, UBIFS_IDX_NODE, len, lnum, offs);
		if (err)
			goto out_free;
		/* Validate index node */
		child_cnt = le16_to_cpu(idx->child_cnt);
		if (child_cnt < 1 || child_cnt > c->fanout) {
			err = 1;
			goto out_dump;
		}
		if (first) {
			first = 0;
			/* Check root level and sqnum */
			if (le16_to_cpu(idx->level) != d->old_zroot_level) {
				err = 2;
				goto out_dump;
			}
			if (le64_to_cpu(idx->ch.sqnum) != d->old_zroot_sqnum) {
				err = 3;
				goto out_dump;
			}
			/* Set last values as though root had a parent */
			last_level = le16_to_cpu(idx->level) + 1;
			last_sqnum = le64_to_cpu(idx->ch.sqnum) + 1;
			key_read(c, ubifs_idx_key(c, idx), &lower_key);
			highest_ino_key(c, &upper_key, INUM_WATERMARK);
		}
		key_copy(c, &upper_key, &i->upper_key);
		if (le16_to_cpu(idx->level) != last_level - 1) {
			err = 3;
			goto out_dump;
		}
		/*
		 * The index is always written bottom up hence a child's sqnum
		 * is always less than the parents.
		 */
		if (le64_to_cpu(idx->ch.sqnum) >= last_sqnum) {
			err = 4;
			goto out_dump;
		}
		/* Check key range */
		key_read(c, ubifs_idx_key(c, idx), &l_key);
		br = ubifs_idx_branch(c, idx, child_cnt - 1);
		key_read(c, &br->key, &u_key);
		if (keys_cmp(c, &lower_key, &l_key) > 0) {
			err = 5;
			goto out_dump;
		}
		if (keys_cmp(c, &upper_key, &u_key) < 0) {
			err = 6;
			goto out_dump;
		}
		if (keys_cmp(c, &upper_key, &u_key) == 0)
			if (!is_hash_key(c, &u_key)) {
				err = 7;
				goto out_dump;
			}
		/* Go to next index node */
		if (le16_to_cpu(idx->level) == 0) {
			/* At the bottom, so go up until can go right */
			while (1) {
				/* Drop the bottom of the list */
				list_del(&i->list);
				kfree(i);
				/* No more list means we are done */
				if (list_empty(&list))
					goto out;
				/* Look at the new bottom */
				i = list_entry(list.prev, struct idx_node,
					       list);
				idx = &i->idx;
				/* Can we go right */
				if (iip + 1 < le16_to_cpu(idx->child_cnt)) {
					iip = iip + 1;
					break;
				} else
					/* Nope, so go up again */
					iip = i->iip;
			}
		} else
			/* Go down left */
			iip = 0;
		/*
		 * We have the parent in 'idx' and now we set up for reading the
		 * child pointed to by slot 'iip'.
		 */
		last_level = le16_to_cpu(idx->level);
		last_sqnum = le64_to_cpu(idx->ch.sqnum);
		br = ubifs_idx_branch(c, idx, iip);
		lnum = le32_to_cpu(br->lnum);
		offs = le32_to_cpu(br->offs);
		len = le32_to_cpu(br->len);
		key_read(c, &br->key, &lower_key);
		if (iip + 1 < le16_to_cpu(idx->child_cnt)) {
			br = ubifs_idx_branch(c, idx, iip + 1);
			key_read(c, &br->key, &upper_key);
		} else
			key_copy(c, &i->upper_key, &upper_key);
	}
out:
	err = dbg_old_index_check_init(c, zroot);
	if (err)
		goto out_free;

	return 0;

out_dump:
	ubifs_err("dumping index node (iip=%d)", i->iip);
	ubifs_dump_node(c, idx);
	list_del(&i->list);
	kfree(i);
	if (!list_empty(&list)) {
		i = list_entry(list.prev, struct idx_node, list);
		ubifs_err("dumping parent index node");
		ubifs_dump_node(c, &i->idx);
	}
out_free:
	while (!list_empty(&list)) {
		i = list_entry(list.next, struct idx_node, list);
		list_del(&i->list);
		kfree(i);
	}
	ubifs_err("failed, error %d", err);
	if (err > 0)
		err = -EINVAL;
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/commit.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements garbage collection. The procedure for garbage collection
 * is different depending on whether a LEB as an index LEB (contains index
 * nodes) or not. For non-index LEBs, garbage collection finds a LEB which
 * contains a lot of dirty space (obsolete nodes), and copies the non-obsolete
 * nodes to the journal, at which point the garbage-collected LEB is free to be
 * reused. For index LEBs, garbage collection marks the non-obsolete index nodes
 * dirty in the TNC, and after the next commit, the garbage-collected LEB is
 * to be reused. Garbage collection will cause the number of dirty index nodes
 * to grow, however sufficient space is reserved for the index to ensure the
 * commit will never run out of space.
 *
 * Notes about dead watermark. At current UBIFS implementation we assume that
 * LEBs which have less than @c->dead_wm bytes of free + dirty space are full
 * and not worth garbage-collecting. The dead watermark is one min. I/O unit
 * size, or min. UBIFS node size, depending on what is greater. Indeed, UBIFS
 * Garbage Collector has to synchronize the GC head's write buffer before
 * returning, so this is about wasting one min. I/O unit. However, UBIFS GC can
 * actually reclaim even very small pieces of dirty space by garbage collecting
 * enough dirty LEBs, but we do not bother doing this at this implementation.
 *
 * Notes about dark watermark. The results of GC work depends on how big are
 * the UBIFS nodes GC deals with. Large nodes make GC waste more space. Indeed,
 * if GC move data from LEB A to LEB B and nodes in LEB A are large, GC would
 * have to waste large pieces of free space at the end of LEB B, because nodes
 * from LEB A would not fit. And the worst situation is when all nodes are of
 * maximum size. So dark watermark is the amount of free + dirty space in LEB
 * which are guaranteed to be reclaimable. If LEB has less space, the GC might
 * be unable to reclaim it. So, LEBs with free + dirty greater than dark
 * watermark are "good" LEBs from GC's point of few. The other LEBs are not so
 * good, and GC takes extra care when moving them.
 */

// #include <linux/slab.h>
#include <linux/pagemap.h>
// #include <linux/list_sort.h>
// #include "ubifs.h"
#include "../../inc/__fss.h"

/*
 * GC may need to move more than one LEB to make progress. The below constants
 * define "soft" and "hard" limits on the number of LEBs the garbage collector
 * may move.
 */
#define SOFT_LEBS_LIMIT 4
#define HARD_LEBS_LIMIT 32

/**
 * switch_gc_head - switch the garbage collection journal head.
 * @c: UBIFS file-system description object
 * @buf: buffer to write
 * @len: length of the buffer to write
 * @lnum: LEB number written is returned here
 * @offs: offset written is returned here
 *
 * This function switch the GC head to the next LEB which is reserved in
 * @c->gc_lnum. Returns %0 in case of success, %-EAGAIN if commit is required,
 * and other negative error code in case of failures.
 */
static int switch_gc_head(struct ubifs_info *c)
{
	int err, gc_lnum = c->gc_lnum;
	struct ubifs_wbuf *wbuf = &c->jheads[GCHD].wbuf;

	ubifs_assert(gc_lnum != -1);
	dbg_gc("switch GC head from LEB %d:%d to LEB %d (waste %d bytes)",
	       wbuf->lnum, wbuf->offs + wbuf->used, gc_lnum,
	       c->leb_size - wbuf->offs - wbuf->used);

	err = ubifs_wbuf_sync_nolock(wbuf);
	if (err)
		return err;

	/*
	 * The GC write-buffer was synchronized, we may safely unmap
	 * 'c->gc_lnum'.
	 */
	err = ubifs_leb_unmap(c, gc_lnum);
	if (err)
		return err;

	err = ubifs_wbuf_sync_nolock(wbuf);
	if (err)
		return err;

	err = ubifs_add_bud_to_log(c, GCHD, gc_lnum, 0);
	if (err)
		return err;

	c->gc_lnum = -1;
	err = ubifs_wbuf_seek_nolock(wbuf, gc_lnum, 0);
	return err;
}

/**
 * data_nodes_cmp - compare 2 data nodes.
 * @priv: UBIFS file-system description object
 * @a: first data node
 * @a: second data node
 *
 * This function compares data nodes @a and @b. Returns %1 if @a has greater
 * inode or block number, and %-1 otherwise.
 */
static int data_nodes_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	ino_t inuma, inumb;
	struct ubifs_info *c = priv;
	struct ubifs_scan_node *sa, *sb;

	cond_resched();
	if (a == b)
		return 0;

	sa = list_entry(a, struct ubifs_scan_node, list);
	sb = list_entry(b, struct ubifs_scan_node, list);

	ubifs_assert(key_type(c, &sa->key) == UBIFS_DATA_KEY);
	ubifs_assert(key_type(c, &sb->key) == UBIFS_DATA_KEY);
	ubifs_assert(sa->type == UBIFS_DATA_NODE);
	ubifs_assert(sb->type == UBIFS_DATA_NODE);

	inuma = key_inum(c, &sa->key);
	inumb = key_inum(c, &sb->key);

	if (inuma == inumb) {
		unsigned int blka = key_block(c, &sa->key);
		unsigned int blkb = key_block(c, &sb->key);

		if (blka <= blkb)
			return -1;
	} else if (inuma <= inumb)
		return -1;

	return 1;
}

/*
 * nondata_nodes_cmp - compare 2 non-data nodes.
 * @priv: UBIFS file-system description object
 * @a: first node
 * @a: second node
 *
 * This function compares nodes @a and @b. It makes sure that inode nodes go
 * first and sorted by length in descending order. Directory entry nodes go
 * after inode nodes and are sorted in ascending hash valuer order.
 */
static int nondata_nodes_cmp(void *priv, struct list_head *a,
			     struct list_head *b)
{
	ino_t inuma, inumb;
	struct ubifs_info *c = priv;
	struct ubifs_scan_node *sa, *sb;

	cond_resched();
	if (a == b)
		return 0;

	sa = list_entry(a, struct ubifs_scan_node, list);
	sb = list_entry(b, struct ubifs_scan_node, list);

	ubifs_assert(key_type(c, &sa->key) != UBIFS_DATA_KEY &&
		     key_type(c, &sb->key) != UBIFS_DATA_KEY);
	ubifs_assert(sa->type != UBIFS_DATA_NODE &&
		     sb->type != UBIFS_DATA_NODE);

	/* Inodes go before directory entries */
	if (sa->type == UBIFS_INO_NODE) {
		if (sb->type == UBIFS_INO_NODE)
			return sb->len - sa->len;
		return -1;
	}
	if (sb->type == UBIFS_INO_NODE)
		return 1;

	ubifs_assert(key_type(c, &sa->key) == UBIFS_DENT_KEY ||
		     key_type(c, &sa->key) == UBIFS_XENT_KEY);
	ubifs_assert(key_type(c, &sb->key) == UBIFS_DENT_KEY ||
		     key_type(c, &sb->key) == UBIFS_XENT_KEY);
	ubifs_assert(sa->type == UBIFS_DENT_NODE ||
		     sa->type == UBIFS_XENT_NODE);
	ubifs_assert(sb->type == UBIFS_DENT_NODE ||
		     sb->type == UBIFS_XENT_NODE);

	inuma = key_inum(c, &sa->key);
	inumb = key_inum(c, &sb->key);

	if (inuma == inumb) {
		uint32_t hasha = key_hash(c, &sa->key);
		uint32_t hashb = key_hash(c, &sb->key);

		if (hasha <= hashb)
			return -1;
	} else if (inuma <= inumb)
		return -1;

	return 1;
}

/**
 * sort_nodes - sort nodes for GC.
 * @c: UBIFS file-system description object
 * @sleb: describes nodes to sort and contains the result on exit
 * @nondata: contains non-data nodes on exit
 * @min: minimum node size is returned here
 *
 * This function sorts the list of inodes to garbage collect. First of all, it
 * kills obsolete nodes and separates data and non-data nodes to the
 * @sleb->nodes and @nondata lists correspondingly.
 *
 * Data nodes are then sorted in block number order - this is important for
 * bulk-read; data nodes with lower inode number go before data nodes with
 * higher inode number, and data nodes with lower block number go before data
 * nodes with higher block number;
 *
 * Non-data nodes are sorted as follows.
 *   o First go inode nodes - they are sorted in descending length order.
 *   o Then go directory entry nodes - they are sorted in hash order, which
 *     should supposedly optimize 'readdir()'. Direntry nodes with lower parent
 *     inode number go before direntry nodes with higher parent inode number,
 *     and direntry nodes with lower name hash values go before direntry nodes
 *     with higher name hash values.
 *
 * This function returns zero in case of success and a negative error code in
 * case of failure.
 */
static int sort_nodes(struct ubifs_info *c, struct ubifs_scan_leb *sleb,
		      struct list_head *nondata, int *min)
{
	int err;
	struct ubifs_scan_node *snod, *tmp;

	*min = INT_MAX;

	/* Separate data nodes and non-data nodes */
	list_for_each_entry_safe(snod, tmp, &sleb->nodes, list) {
		ubifs_assert(snod->type == UBIFS_INO_NODE  ||
			     snod->type == UBIFS_DATA_NODE ||
			     snod->type == UBIFS_DENT_NODE ||
			     snod->type == UBIFS_XENT_NODE ||
			     snod->type == UBIFS_TRUN_NODE);

		if (snod->type != UBIFS_INO_NODE  &&
		    snod->type != UBIFS_DATA_NODE &&
		    snod->type != UBIFS_DENT_NODE &&
		    snod->type != UBIFS_XENT_NODE) {
			/* Probably truncation node, zap it */
			list_del(&snod->list);
			kfree(snod);
			continue;
		}

		ubifs_assert(key_type(c, &snod->key) == UBIFS_DATA_KEY ||
			     key_type(c, &snod->key) == UBIFS_INO_KEY  ||
			     key_type(c, &snod->key) == UBIFS_DENT_KEY ||
			     key_type(c, &snod->key) == UBIFS_XENT_KEY);

		err = ubifs_tnc_has_node(c, &snod->key, 0, sleb->lnum,
					 snod->offs, 0);
		if (err < 0)
			return err;

		if (!err) {
			/* The node is obsolete, remove it from the list */
			list_del(&snod->list);
			kfree(snod);
			continue;
		}

		if (snod->len < *min)
			*min = snod->len;

		if (key_type(c, &snod->key) != UBIFS_DATA_KEY)
			list_move_tail(&snod->list, nondata);
	}

	/* Sort data and non-data nodes */
	list_sort(c, &sleb->nodes, &data_nodes_cmp);
	list_sort(c, nondata, &nondata_nodes_cmp);

	err = dbg_check_data_nodes_order(c, &sleb->nodes);
	if (err)
		return err;
	err = dbg_check_nondata_nodes_order(c, nondata);
	if (err)
		return err;
	return 0;
}

/**
 * move_node - move a node.
 * @c: UBIFS file-system description object
 * @sleb: describes the LEB to move nodes from
 * @snod: the mode to move
 * @wbuf: write-buffer to move node to
 *
 * This function moves node @snod to @wbuf, changes TNC correspondingly, and
 * destroys @snod. Returns zero in case of success and a negative error code in
 * case of failure.
 */
static int move_node(struct ubifs_info *c, struct ubifs_scan_leb *sleb,
		     struct ubifs_scan_node *snod, struct ubifs_wbuf *wbuf)
{
	int err, new_lnum = wbuf->lnum, new_offs = wbuf->offs + wbuf->used;

	cond_resched();
	err = ubifs_wbuf_write_nolock(wbuf, snod->node, snod->len);
	if (err)
		return err;

	err = ubifs_tnc_replace(c, &snod->key, sleb->lnum,
				snod->offs, new_lnum, new_offs,
				snod->len);
	list_del(&snod->list);
	kfree(snod);
	return err;
}

/**
 * move_nodes - move nodes.
 * @c: UBIFS file-system description object
 * @sleb: describes the LEB to move nodes from
 *
 * This function moves valid nodes from data LEB described by @sleb to the GC
 * journal head. This function returns zero in case of success, %-EAGAIN if
 * commit is required, and other negative error codes in case of other
 * failures.
 */
static int move_nodes(struct ubifs_info *c, struct ubifs_scan_leb *sleb)
{
	int err, min;
	LIST_HEAD(nondata);
	struct ubifs_wbuf *wbuf = &c->jheads[GCHD].wbuf;

	if (wbuf->lnum == -1) {
		/*
		 * The GC journal head is not set, because it is the first GC
		 * invocation since mount.
		 */
		err = switch_gc_head(c);
		if (err)
			return err;
	}

	err = sort_nodes(c, sleb, &nondata, &min);
	if (err)
		goto out;

	/* Write nodes to their new location. Use the first-fit strategy */
	while (1) {
		int avail;
		struct ubifs_scan_node *snod, *tmp;

		/* Move data nodes */
		list_for_each_entry_safe(snod, tmp, &sleb->nodes, list) {
			avail = c->leb_size - wbuf->offs - wbuf->used;
			if  (snod->len > avail)
				/*
				 * Do not skip data nodes in order to optimize
				 * bulk-read.
				 */
				break;

			err = move_node(c, sleb, snod, wbuf);
			if (err)
				goto out;
		}

		/* Move non-data nodes */
		list_for_each_entry_safe(snod, tmp, &nondata, list) {
			avail = c->leb_size - wbuf->offs - wbuf->used;
			if (avail < min)
				break;

			if  (snod->len > avail) {
				/*
				 * Keep going only if this is an inode with
				 * some data. Otherwise stop and switch the GC
				 * head. IOW, we assume that data-less inode
				 * nodes and direntry nodes are roughly of the
				 * same size.
				 */
				if (key_type(c, &snod->key) == UBIFS_DENT_KEY ||
				    snod->len == UBIFS_INO_NODE_SZ)
					break;
				continue;
			}

			err = move_node(c, sleb, snod, wbuf);
			if (err)
				goto out;
		}

		if (list_empty(&sleb->nodes) && list_empty(&nondata))
			break;

		/*
		 * Waste the rest of the space in the LEB and switch to the
		 * next LEB.
		 */
		err = switch_gc_head(c);
		if (err)
			goto out;
	}

	return 0;

out:
	list_splice_tail(&nondata, &sleb->nodes);
	return err;
}

/**
 * gc_sync_wbufs - sync write-buffers for GC.
 * @c: UBIFS file-system description object
 *
 * We must guarantee that obsoleting nodes are on flash. Unfortunately they may
 * be in a write-buffer instead. That is, a node could be written to a
 * write-buffer, obsoleting another node in a LEB that is GC'd. If that LEB is
 * erased before the write-buffer is sync'd and then there is an unclean
 * unmount, then an existing node is lost. To avoid this, we sync all
 * write-buffers.
 *
 * This function returns %0 on success or a negative error code on failure.
 */
static int gc_sync_wbufs(struct ubifs_info *c)
{
	int err, i;

	for (i = 0; i < c->jhead_cnt; i++) {
		if (i == GCHD)
			continue;
		err = ubifs_wbuf_sync(&c->jheads[i].wbuf);
		if (err)
			return err;
	}
	return 0;
}

/**
 * ubifs_garbage_collect_leb - garbage-collect a logical eraseblock.
 * @c: UBIFS file-system description object
 * @lp: describes the LEB to garbage collect
 *
 * This function garbage-collects an LEB and returns one of the @LEB_FREED,
 * @LEB_RETAINED, etc positive codes in case of success, %-EAGAIN if commit is
 * required, and other negative error codes in case of failures.
 */
int ubifs_garbage_collect_leb(struct ubifs_info *c, struct ubifs_lprops *lp)
{
	struct ubifs_scan_leb *sleb;
	struct ubifs_scan_node *snod;
	struct ubifs_wbuf *wbuf = &c->jheads[GCHD].wbuf;
	int err = 0, lnum = lp->lnum;

	ubifs_assert(c->gc_lnum != -1 || wbuf->offs + wbuf->used == 0 ||
		     c->need_recovery);
	ubifs_assert(c->gc_lnum != lnum);
	ubifs_assert(wbuf->lnum != lnum);

	if (lp->free + lp->dirty == c->leb_size) {
		/* Special case - a free LEB  */
		dbg_gc("LEB %d is free, return it", lp->lnum);
		ubifs_assert(!(lp->flags & LPROPS_INDEX));

		if (lp->free != c->leb_size) {
			/*
			 * Write buffers must be sync'd before unmapping
			 * freeable LEBs, because one of them may contain data
			 * which obsoletes something in 'lp->pnum'.
			 */
			err = gc_sync_wbufs(c);
			if (err)
				return err;
			err = ubifs_change_one_lp(c, lp->lnum, c->leb_size,
						  0, 0, 0, 0);
			if (err)
				return err;
		}
		err = ubifs_leb_unmap(c, lp->lnum);
		if (err)
			return err;

		if (c->gc_lnum == -1) {
			c->gc_lnum = lnum;
			return LEB_RETAINED;
		}

		return LEB_FREED;
	}

	/*
	 * We scan the entire LEB even though we only really need to scan up to
	 * (c->leb_size - lp->free).
	 */
	sleb = ubifs_scan(c, lnum, 0, c->sbuf, 0);
	if (IS_ERR(sleb))
		return PTR_ERR(sleb);

	ubifs_assert(!list_empty(&sleb->nodes));
	snod = list_entry(sleb->nodes.next, struct ubifs_scan_node, list);

	if (snod->type == UBIFS_IDX_NODE) {
		struct ubifs_gced_idx_leb *idx_gc;

		dbg_gc("indexing LEB %d (free %d, dirty %d)",
		       lnum, lp->free, lp->dirty);
		list_for_each_entry(snod, &sleb->nodes, list) {
			struct ubifs_idx_node *idx = snod->node;
			int level = le16_to_cpu(idx->level);

			ubifs_assert(snod->type == UBIFS_IDX_NODE);
			key_read(c, ubifs_idx_key(c, idx), &snod->key);
			err = ubifs_dirty_idx_node(c, &snod->key, level, lnum,
						   snod->offs);
			if (err)
				goto out;
		}

		idx_gc = kmalloc(sizeof(struct ubifs_gced_idx_leb), GFP_NOFS);
		if (!idx_gc) {
			err = -ENOMEM;
			goto out;
		}

		idx_gc->lnum = lnum;
		idx_gc->unmap = 0;
		list_add(&idx_gc->list, &c->idx_gc);

		/*
		 * Don't release the LEB until after the next commit, because
		 * it may contain data which is needed for recovery. So
		 * although we freed this LEB, it will become usable only after
		 * the commit.
		 */
		err = ubifs_change_one_lp(c, lnum, c->leb_size, 0, 0,
					  LPROPS_INDEX, 1);
		if (err)
			goto out;
		err = LEB_FREED_IDX;
	} else {
		dbg_gc("data LEB %d (free %d, dirty %d)",
		       lnum, lp->free, lp->dirty);

		err = move_nodes(c, sleb);
		if (err)
			goto out_inc_seq;

		err = gc_sync_wbufs(c);
		if (err)
			goto out_inc_seq;

		err = ubifs_change_one_lp(c, lnum, c->leb_size, 0, 0, 0, 0);
		if (err)
			goto out_inc_seq;

		/* Allow for races with TNC */
		c->gced_lnum = lnum;
		smp_wmb();
		c->gc_seq += 1;
		smp_wmb();

		if (c->gc_lnum == -1) {
			c->gc_lnum = lnum;
			err = LEB_RETAINED;
		} else {
			err = ubifs_wbuf_sync_nolock(wbuf);
			if (err)
				goto out;

			err = ubifs_leb_unmap(c, lnum);
			if (err)
				goto out;

			err = LEB_FREED;
		}
	}

out:
	ubifs_scan_destroy(sleb);
	return err;

out_inc_seq:
	/* We may have moved at least some nodes so allow for races with TNC */
	c->gced_lnum = lnum;
	smp_wmb();
	c->gc_seq += 1;
	smp_wmb();
	goto out;
}

/**
 * ubifs_garbage_collect - UBIFS garbage collector.
 * @c: UBIFS file-system description object
 * @anyway: do GC even if there are free LEBs
 *
 * This function does out-of-place garbage collection. The return codes are:
 *   o positive LEB number if the LEB has been freed and may be used;
 *   o %-EAGAIN if the caller has to run commit;
 *   o %-ENOSPC if GC failed to make any progress;
 *   o other negative error codes in case of other errors.
 *
 * Garbage collector writes data to the journal when GC'ing data LEBs, and just
 * marking indexing nodes dirty when GC'ing indexing LEBs. Thus, at some point
 * commit may be required. But commit cannot be run from inside GC, because the
 * caller might be holding the commit lock, so %-EAGAIN is returned instead;
 * And this error code means that the caller has to run commit, and re-run GC
 * if there is still no free space.
 *
 * There are many reasons why this function may return %-EAGAIN:
 * o the log is full and there is no space to write an LEB reference for
 *   @c->gc_lnum;
 * o the journal is too large and exceeds size limitations;
 * o GC moved indexing LEBs, but they can be used only after the commit;
 * o the shrinker fails to find clean znodes to free and requests the commit;
 * o etc.
 *
 * Note, if the file-system is close to be full, this function may return
 * %-EAGAIN infinitely, so the caller has to limit amount of re-invocations of
 * the function. E.g., this happens if the limits on the journal size are too
 * tough and GC writes too much to the journal before an LEB is freed. This
 * might also mean that the journal is too large, and the TNC becomes to big,
 * so that the shrinker is constantly called, finds not clean znodes to free,
 * and requests commit. Well, this may also happen if the journal is all right,
 * but another kernel process consumes too much memory. Anyway, infinite
 * %-EAGAIN may happen, but in some extreme/misconfiguration cases.
 */
int ubifs_garbage_collect(struct ubifs_info *c, int anyway)
{
	int i, err, ret, min_space = c->dead_wm;
	struct ubifs_lprops lp;
	struct ubifs_wbuf *wbuf = &c->jheads[GCHD].wbuf;

	ubifs_assert_cmt_locked(c);
	ubifs_assert(!c->ro_media && !c->ro_mount);

	if (ubifs_gc_should_commit(c))
		return -EAGAIN;

	mutex_lock_nested(&wbuf->io_mutex, wbuf->jhead);

	if (c->ro_error) {
		ret = -EROFS;
		goto out_unlock;
	}

	/* We expect the write-buffer to be empty on entry */
	ubifs_assert(!wbuf->used);

	for (i = 0; ; i++) {
		int space_before, space_after;

		cond_resched();

		/* Give the commit an opportunity to run */
		if (ubifs_gc_should_commit(c)) {
			ret = -EAGAIN;
			break;
		}

		if (i > SOFT_LEBS_LIMIT && !list_empty(&c->idx_gc)) {
			/*
			 * We've done enough iterations. Indexing LEBs were
			 * moved and will be available after the commit.
			 */
			dbg_gc("soft limit, some index LEBs GC'ed, -EAGAIN");
			ubifs_commit_required(c);
			ret = -EAGAIN;
			break;
		}

		if (i > HARD_LEBS_LIMIT) {
			/*
			 * We've moved too many LEBs and have not made
			 * progress, give up.
			 */
			dbg_gc("hard limit, -ENOSPC");
			ret = -ENOSPC;
			break;
		}

		/*
		 * Empty and freeable LEBs can turn up while we waited for
		 * the wbuf lock, or while we have been running GC. In that
		 * case, we should just return one of those instead of
		 * continuing to GC dirty LEBs. Hence we request
		 * 'ubifs_find_dirty_leb()' to return an empty LEB if it can.
		 */
		ret = ubifs_find_dirty_leb(c, &lp, min_space, anyway ? 0 : 1);
		if (ret) {
			if (ret == -ENOSPC)
				dbg_gc("no more dirty LEBs");
			break;
		}

		dbg_gc("found LEB %d: free %d, dirty %d, sum %d (min. space %d)",
		       lp.lnum, lp.free, lp.dirty, lp.free + lp.dirty,
		       min_space);

		space_before = c->leb_size - wbuf->offs - wbuf->used;
		if (wbuf->lnum == -1)
			space_before = 0;

		ret = ubifs_garbage_collect_leb(c, &lp);
		if (ret < 0) {
			if (ret == -EAGAIN) {
				/*
				 * This is not error, so we have to return the
				 * LEB to lprops. But if 'ubifs_return_leb()'
				 * fails, its failure code is propagated to the
				 * caller instead of the original '-EAGAIN'.
				 */
				err = ubifs_return_leb(c, lp.lnum);
				if (err)
					ret = err;
				break;
			}
			goto out;
		}

		if (ret == LEB_FREED) {
			/* An LEB has been freed and is ready for use */
			dbg_gc("LEB %d freed, return", lp.lnum);
			ret = lp.lnum;
			break;
		}

		if (ret == LEB_FREED_IDX) {
			/*
			 * This was an indexing LEB and it cannot be
			 * immediately used. And instead of requesting the
			 * commit straight away, we try to garbage collect some
			 * more.
			 */
			dbg_gc("indexing LEB %d freed, continue", lp.lnum);
			continue;
		}

		ubifs_assert(ret == LEB_RETAINED);
		space_after = c->leb_size - wbuf->offs - wbuf->used;
		dbg_gc("LEB %d retained, freed %d bytes", lp.lnum,
		       space_after - space_before);

		if (space_after > space_before) {
			/* GC makes progress, keep working */
			min_space >>= 1;
			if (min_space < c->dead_wm)
				min_space = c->dead_wm;
			continue;
		}

		dbg_gc("did not make progress");

		/*
		 * GC moved an LEB bud have not done any progress. This means
		 * that the previous GC head LEB contained too few free space
		 * and the LEB which was GC'ed contained only large nodes which
		 * did not fit that space.
		 *
		 * We can do 2 things:
		 * 1. pick another LEB in a hope it'll contain a small node
		 *    which will fit the space we have at the end of current GC
		 *    head LEB, but there is no guarantee, so we try this out
		 *    unless we have already been working for too long;
		 * 2. request an LEB with more dirty space, which will force
		 *    'ubifs_find_dirty_leb()' to start scanning the lprops
		 *    table, instead of just picking one from the heap
		 *    (previously it already picked the dirtiest LEB).
		 */
		if (i < SOFT_LEBS_LIMIT) {
			dbg_gc("try again");
			continue;
		}

		min_space <<= 1;
		if (min_space > c->dark_wm)
			min_space = c->dark_wm;
		dbg_gc("set min. space to %d", min_space);
	}

	if (ret == -ENOSPC && !list_empty(&c->idx_gc)) {
		dbg_gc("no space, some index LEBs GC'ed, -EAGAIN");
		ubifs_commit_required(c);
		ret = -EAGAIN;
	}

	err = ubifs_wbuf_sync_nolock(wbuf);
	if (!err)
		err = ubifs_leb_unmap(c, c->gc_lnum);
	if (err) {
		ret = err;
		goto out;
	}
out_unlock:
	mutex_unlock(&wbuf->io_mutex);
	return ret;

out:
	ubifs_assert(ret < 0);
	ubifs_assert(ret != -ENOSPC && ret != -EAGAIN);
	ubifs_wbuf_sync_nolock(wbuf);
	ubifs_ro_mode(c, ret);
	mutex_unlock(&wbuf->io_mutex);
	ubifs_return_leb(c, lp.lnum);
	return ret;
}

/**
 * ubifs_gc_start_commit - garbage collection at start of commit.
 * @c: UBIFS file-system description object
 *
 * If a LEB has only dirty and free space, then we may safely unmap it and make
 * it free.  Note, we cannot do this with indexing LEBs because dirty space may
 * correspond index nodes that are required for recovery.  In that case, the
 * LEB cannot be unmapped until after the next commit.
 *
 * This function returns %0 upon success and a negative error code upon failure.
 */
int ubifs_gc_start_commit(struct ubifs_info *c)
{
	struct ubifs_gced_idx_leb *idx_gc;
	const struct ubifs_lprops *lp;
	int err = 0, flags;

	ubifs_get_lprops(c);

	/*
	 * Unmap (non-index) freeable LEBs. Note that recovery requires that all
	 * wbufs are sync'd before this, which is done in 'do_commit()'.
	 */
	while (1) {
		lp = ubifs_fast_find_freeable(c);
		if (IS_ERR(lp)) {
			err = PTR_ERR(lp);
			goto out;
		}
		if (!lp)
			break;
		ubifs_assert(!(lp->flags & LPROPS_TAKEN));
		ubifs_assert(!(lp->flags & LPROPS_INDEX));
		err = ubifs_leb_unmap(c, lp->lnum);
		if (err)
			goto out;
		lp = ubifs_change_lp(c, lp, c->leb_size, 0, lp->flags, 0);
		if (IS_ERR(lp)) {
			err = PTR_ERR(lp);
			goto out;
		}
		ubifs_assert(!(lp->flags & LPROPS_TAKEN));
		ubifs_assert(!(lp->flags & LPROPS_INDEX));
	}

	/* Mark GC'd index LEBs OK to unmap after this commit finishes */
	list_for_each_entry(idx_gc, &c->idx_gc, list)
		idx_gc->unmap = 1;

	/* Record index freeable LEBs for unmapping after commit */
	while (1) {
		lp = ubifs_fast_find_frdi_idx(c);
		if (IS_ERR(lp)) {
			err = PTR_ERR(lp);
			goto out;
		}
		if (!lp)
			break;
		idx_gc = kmalloc(sizeof(struct ubifs_gced_idx_leb), GFP_NOFS);
		if (!idx_gc) {
			err = -ENOMEM;
			goto out;
		}
		ubifs_assert(!(lp->flags & LPROPS_TAKEN));
		ubifs_assert(lp->flags & LPROPS_INDEX);
		/* Don't release the LEB until after the next commit */
		flags = (lp->flags | LPROPS_TAKEN) ^ LPROPS_INDEX;
		lp = ubifs_change_lp(c, lp, c->leb_size, 0, flags, 1);
		if (IS_ERR(lp)) {
			err = PTR_ERR(lp);
			kfree(idx_gc);
			goto out;
		}
		ubifs_assert(lp->flags & LPROPS_TAKEN);
		ubifs_assert(!(lp->flags & LPROPS_INDEX));
		idx_gc->lnum = lp->lnum;
		idx_gc->unmap = 1;
		list_add(&idx_gc->list, &c->idx_gc);
	}
out:
	ubifs_release_lprops(c);
	return err;
}

/**
 * ubifs_gc_end_commit - garbage collection at end of commit.
 * @c: UBIFS file-system description object
 *
 * This function completes out-of-place garbage collection of index LEBs.
 */
int ubifs_gc_end_commit(struct ubifs_info *c)
{
	struct ubifs_gced_idx_leb *idx_gc, *tmp;
	struct ubifs_wbuf *wbuf;
	int err = 0;

	wbuf = &c->jheads[GCHD].wbuf;
	mutex_lock_nested(&wbuf->io_mutex, wbuf->jhead);
	list_for_each_entry_safe(idx_gc, tmp, &c->idx_gc, list)
		if (idx_gc->unmap) {
			dbg_gc("LEB %d", idx_gc->lnum);
			err = ubifs_leb_unmap(c, idx_gc->lnum);
			if (err)
				goto out;
			err = ubifs_change_one_lp(c, idx_gc->lnum, LPROPS_NC,
					  LPROPS_NC, 0, LPROPS_TAKEN, -1);
			if (err)
				goto out;
			list_del(&idx_gc->list);
			kfree(idx_gc);
		}
out:
	mutex_unlock(&wbuf->io_mutex);
	return err;
}

/**
 * ubifs_destroy_idx_gc - destroy idx_gc list.
 * @c: UBIFS file-system description object
 *
 * This function destroys the @c->idx_gc list. It is called when unmounting
 * so locks are not needed. Returns zero in case of success and a negative
 * error code in case of failure.
 */
void ubifs_destroy_idx_gc(struct ubifs_info *c)
{
	while (!list_empty(&c->idx_gc)) {
		struct ubifs_gced_idx_leb *idx_gc;

		idx_gc = list_entry(c->idx_gc.next, struct ubifs_gced_idx_leb,
				    list);
		c->idx_gc_cnt -= 1;
		list_del(&idx_gc->list);
		kfree(idx_gc);
	}
}

/**
 * ubifs_get_idx_gc_leb - get a LEB from GC'd index LEB list.
 * @c: UBIFS file-system description object
 *
 * Called during start commit so locks are not needed.
 */
int ubifs_get_idx_gc_leb(struct ubifs_info *c)
{
	struct ubifs_gced_idx_leb *idx_gc;
	int lnum;

	if (list_empty(&c->idx_gc))
		return -ENOSPC;
	idx_gc = list_entry(c->idx_gc.next, struct ubifs_gced_idx_leb, list);
	lnum = idx_gc->lnum;
	/* c->idx_gc_cnt is updated by the caller when lprops are updated */
	list_del(&idx_gc->list);
	kfree(idx_gc);
	return lnum;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/gc.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Author: Adrian Hunter
 */

// #include "ubifs.h"

/*
 * An orphan is an inode number whose inode node has been committed to the index
 * with a link count of zero. That happens when an open file is deleted
 * (unlinked) and then a commit is run. In the normal course of events the inode
 * would be deleted when the file is closed. However in the case of an unclean
 * unmount, orphans need to be accounted for. After an unclean unmount, the
 * orphans' inodes must be deleted which means either scanning the entire index
 * looking for them, or keeping a list on flash somewhere. This unit implements
 * the latter approach.
 *
 * The orphan area is a fixed number of LEBs situated between the LPT area and
 * the main area. The number of orphan area LEBs is specified when the file
 * system is created. The minimum number is 1. The size of the orphan area
 * should be so that it can hold the maximum number of orphans that are expected
 * to ever exist at one time.
 *
 * The number of orphans that can fit in a LEB is:
 *
 *         (c->leb_size - UBIFS_ORPH_NODE_SZ) / sizeof(__le64)
 *
 * For example: a 15872 byte LEB can fit 1980 orphans so 1 LEB may be enough.
 *
 * Orphans are accumulated in a rb-tree. When an inode's link count drops to
 * zero, the inode number is added to the rb-tree. It is removed from the tree
 * when the inode is deleted.  Any new orphans that are in the orphan tree when
 * the commit is run, are written to the orphan area in 1 or more orphan nodes.
 * If the orphan area is full, it is consolidated to make space.  There is
 * always enough space because validation prevents the user from creating more
 * than the maximum number of orphans allowed.
 */

static int dbg_check_orphans(struct ubifs_info *c);

/**
 * ubifs_add_orphan - add an orphan.
 * @c: UBIFS file-system description object
 * @inum: orphan inode number
 *
 * Add an orphan. This function is called when an inodes link count drops to
 * zero.
 */
int ubifs_add_orphan(struct ubifs_info *c, ino_t inum)
{
	struct ubifs_orphan *orphan, *o;
	struct rb_node **p, *parent = NULL;

	orphan = kzalloc(sizeof(struct ubifs_orphan), GFP_NOFS);
	if (!orphan)
		return -ENOMEM;
	orphan->inum = inum;
	orphan->new = 1;

	spin_lock(&c->orphan_lock);
	if (c->tot_orphans >= c->max_orphans) {
		spin_unlock(&c->orphan_lock);
		kfree(orphan);
		return -ENFILE;
	}
	p = &c->orph_tree.rb_node;
	while (*p) {
		parent = *p;
		o = rb_entry(parent, struct ubifs_orphan, rb);
		if (inum < o->inum)
			p = &(*p)->rb_left;
		else if (inum > o->inum)
			p = &(*p)->rb_right;
		else {
			ubifs_err("orphaned twice");
			spin_unlock(&c->orphan_lock);
			kfree(orphan);
			return 0;
		}
	}
	c->tot_orphans += 1;
	c->new_orphans += 1;
	rb_link_node(&orphan->rb, parent, p);
	rb_insert_color(&orphan->rb, &c->orph_tree);
	list_add_tail(&orphan->list, &c->orph_list);
	list_add_tail(&orphan->new_list, &c->orph_new);
	spin_unlock(&c->orphan_lock);
	dbg_gen("ino %lu", (unsigned long)inum);
	return 0;
}

/**
 * ubifs_delete_orphan - delete an orphan.
 * @c: UBIFS file-system description object
 * @inum: orphan inode number
 *
 * Delete an orphan. This function is called when an inode is deleted.
 */
void ubifs_delete_orphan(struct ubifs_info *c, ino_t inum)
{
	struct ubifs_orphan *o;
	struct rb_node *p;

	spin_lock(&c->orphan_lock);
	p = c->orph_tree.rb_node;
	while (p) {
		o = rb_entry(p, struct ubifs_orphan, rb);
		if (inum < o->inum)
			p = p->rb_left;
		else if (inum > o->inum)
			p = p->rb_right;
		else {
			if (o->del) {
				spin_unlock(&c->orphan_lock);
				dbg_gen("deleted twice ino %lu",
					(unsigned long)inum);
				return;
			}
			if (o->cmt) {
				o->del = 1;
				o->dnext = c->orph_dnext;
				c->orph_dnext = o;
				spin_unlock(&c->orphan_lock);
				dbg_gen("delete later ino %lu",
					(unsigned long)inum);
				return;
			}
			rb_erase(p, &c->orph_tree);
			list_del(&o->list);
			c->tot_orphans -= 1;
			if (o->new) {
				list_del(&o->new_list);
				c->new_orphans -= 1;
			}
			spin_unlock(&c->orphan_lock);
			kfree(o);
			dbg_gen("inum %lu", (unsigned long)inum);
			return;
		}
	}
	spin_unlock(&c->orphan_lock);
	ubifs_err("missing orphan ino %lu", (unsigned long)inum);
	dump_stack();
}

/**
 * ubifs_orphan_start_commit - start commit of orphans.
 * @c: UBIFS file-system description object
 *
 * Start commit of orphans.
 */
int ubifs_orphan_start_commit(struct ubifs_info *c)
{
	struct ubifs_orphan *orphan, **last;

	spin_lock(&c->orphan_lock);
	last = &c->orph_cnext;
	list_for_each_entry(orphan, &c->orph_new, new_list) {
		ubifs_assert(orphan->new);
		ubifs_assert(!orphan->cmt);
		orphan->new = 0;
		orphan->cmt = 1;
		*last = orphan;
		last = &orphan->cnext;
	}
	*last = NULL;
	c->cmt_orphans = c->new_orphans;
	c->new_orphans = 0;
	dbg_cmt("%d orphans to commit", c->cmt_orphans);
	INIT_LIST_HEAD(&c->orph_new);
	if (c->tot_orphans == 0)
		c->no_orphs = 1;
	else
		c->no_orphs = 0;
	spin_unlock(&c->orphan_lock);
	return 0;
}

/**
 * avail_orphs - calculate available space.
 * @c: UBIFS file-system description object
 *
 * This function returns the number of orphans that can be written in the
 * available space.
 */
static int avail_orphs(struct ubifs_info *c)
{
	int avail_lebs, avail, gap;

	avail_lebs = c->orph_lebs - (c->ohead_lnum - c->orph_first) - 1;
	avail = avail_lebs *
	       ((c->leb_size - UBIFS_ORPH_NODE_SZ) / sizeof(__le64));
	gap = c->leb_size - c->ohead_offs;
	if (gap >= UBIFS_ORPH_NODE_SZ + sizeof(__le64))
		avail += (gap - UBIFS_ORPH_NODE_SZ) / sizeof(__le64);
	return avail;
}

/**
 * tot_avail_orphs - calculate total space.
 * @c: UBIFS file-system description object
 *
 * This function returns the number of orphans that can be written in half
 * the total space. That leaves half the space for adding new orphans.
 */
static int tot_avail_orphs(struct ubifs_info *c)
{
	int avail_lebs, avail;

	avail_lebs = c->orph_lebs;
	avail = avail_lebs *
	       ((c->leb_size - UBIFS_ORPH_NODE_SZ) / sizeof(__le64));
	return avail / 2;
}

/**
 * do_write_orph_node - write a node to the orphan head.
 * @c: UBIFS file-system description object
 * @len: length of node
 * @atomic: write atomically
 *
 * This function writes a node to the orphan head from the orphan buffer. If
 * %atomic is not zero, then the write is done atomically. On success, %0 is
 * returned, otherwise a negative error code is returned.
 */
static int do_write_orph_node(struct ubifs_info *c, int len, int atomic)
{
	int err = 0;

	if (atomic) {
		ubifs_assert(c->ohead_offs == 0);
		ubifs_prepare_node(c, c->orph_buf, len, 1);
		len = ALIGN(len, c->min_io_size);
		err = ubifs_leb_change(c, c->ohead_lnum, c->orph_buf, len);
	} else {
		if (c->ohead_offs == 0) {
			/* Ensure LEB has been unmapped */
			err = ubifs_leb_unmap(c, c->ohead_lnum);
			if (err)
				return err;
		}
		err = ubifs_write_node(c, c->orph_buf, len, c->ohead_lnum,
				       c->ohead_offs);
	}
	return err;
}

/**
 * write_orph_node - write an orphan node.
 * @c: UBIFS file-system description object
 * @atomic: write atomically
 *
 * This function builds an orphan node from the cnext list and writes it to the
 * orphan head. On success, %0 is returned, otherwise a negative error code
 * is returned.
 */
static int write_orph_node(struct ubifs_info *c, int atomic)
{
	struct ubifs_orphan *orphan, *cnext;
	struct ubifs_orph_node *orph;
	int gap, err, len, cnt, i;

	ubifs_assert(c->cmt_orphans > 0);
	gap = c->leb_size - c->ohead_offs;
	if (gap < UBIFS_ORPH_NODE_SZ + sizeof(__le64)) {
		c->ohead_lnum += 1;
		c->ohead_offs = 0;
		gap = c->leb_size;
		if (c->ohead_lnum > c->orph_last) {
			/*
			 * We limit the number of orphans so that this should
			 * never happen.
			 */
			ubifs_err("out of space in orphan area");
			return -EINVAL;
		}
	}
	cnt = (gap - UBIFS_ORPH_NODE_SZ) / sizeof(__le64);
	if (cnt > c->cmt_orphans)
		cnt = c->cmt_orphans;
	len = UBIFS_ORPH_NODE_SZ + cnt * sizeof(__le64);
	ubifs_assert(c->orph_buf);
	orph = c->orph_buf;
	orph->ch.node_type = UBIFS_ORPH_NODE;
	spin_lock(&c->orphan_lock);
	cnext = c->orph_cnext;
	for (i = 0; i < cnt; i++) {
		orphan = cnext;
		ubifs_assert(orphan->cmt);
		orph->inos[i] = cpu_to_le64(orphan->inum);
		orphan->cmt = 0;
		cnext = orphan->cnext;
		orphan->cnext = NULL;
	}
	c->orph_cnext = cnext;
	c->cmt_orphans -= cnt;
	spin_unlock(&c->orphan_lock);
	if (c->cmt_orphans)
		orph->cmt_no = cpu_to_le64(c->cmt_no);
	else
		/* Mark the last node of the commit */
		orph->cmt_no = cpu_to_le64((c->cmt_no) | (1ULL << 63));
	ubifs_assert(c->ohead_offs + len <= c->leb_size);
	ubifs_assert(c->ohead_lnum >= c->orph_first);
	ubifs_assert(c->ohead_lnum <= c->orph_last);
	err = do_write_orph_node(c, len, atomic);
	c->ohead_offs += ALIGN(len, c->min_io_size);
	c->ohead_offs = ALIGN(c->ohead_offs, 8);
	return err;
}

/**
 * write_orph_nodes - write orphan nodes until there are no more to commit.
 * @c: UBIFS file-system description object
 * @atomic: write atomically
 *
 * This function writes orphan nodes for all the orphans to commit. On success,
 * %0 is returned, otherwise a negative error code is returned.
 */
static int write_orph_nodes(struct ubifs_info *c, int atomic)
{
	int err;

	while (c->cmt_orphans > 0) {
		err = write_orph_node(c, atomic);
		if (err)
			return err;
	}
	if (atomic) {
		int lnum;

		/* Unmap any unused LEBs after consolidation */
		for (lnum = c->ohead_lnum + 1; lnum <= c->orph_last; lnum++) {
			err = ubifs_leb_unmap(c, lnum);
			if (err)
				return err;
		}
	}
	return 0;
}

/**
 * consolidate - consolidate the orphan area.
 * @c: UBIFS file-system description object
 *
 * This function enables consolidation by putting all the orphans into the list
 * to commit. The list is in the order that the orphans were added, and the
 * LEBs are written atomically in order, so at no time can orphans be lost by
 * an unclean unmount.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int consolidate(struct ubifs_info *c)
{
	int tot_avail = tot_avail_orphs(c), err = 0;

	spin_lock(&c->orphan_lock);
	dbg_cmt("there is space for %d orphans and there are %d",
		tot_avail, c->tot_orphans);
	if (c->tot_orphans - c->new_orphans <= tot_avail) {
		struct ubifs_orphan *orphan, **last;
		int cnt = 0;

		/* Change the cnext list to include all non-new orphans */
		last = &c->orph_cnext;
		list_for_each_entry(orphan, &c->orph_list, list) {
			if (orphan->new)
				continue;
			orphan->cmt = 1;
			*last = orphan;
			last = &orphan->cnext;
			cnt += 1;
		}
		*last = NULL;
		ubifs_assert(cnt == c->tot_orphans - c->new_orphans);
		c->cmt_orphans = cnt;
		c->ohead_lnum = c->orph_first;
		c->ohead_offs = 0;
	} else {
		/*
		 * We limit the number of orphans so that this should
		 * never happen.
		 */
		ubifs_err("out of space in orphan area");
		err = -EINVAL;
	}
	spin_unlock(&c->orphan_lock);
	return err;
}

/**
 * commit_orphans - commit orphans.
 * @c: UBIFS file-system description object
 *
 * This function commits orphans to flash. On success, %0 is returned,
 * otherwise a negative error code is returned.
 */
static int commit_orphans(struct ubifs_info *c)
{
	int avail, atomic = 0, err;

	ubifs_assert(c->cmt_orphans > 0);
	avail = avail_orphs(c);
	if (avail < c->cmt_orphans) {
		/* Not enough space to write new orphans, so consolidate */
		err = consolidate(c);
		if (err)
			return err;
		atomic = 1;
	}
	err = write_orph_nodes(c, atomic);
	return err;
}

/**
 * erase_deleted - erase the orphans marked for deletion.
 * @c: UBIFS file-system description object
 *
 * During commit, the orphans being committed cannot be deleted, so they are
 * marked for deletion and deleted by this function. Also, the recovery
 * adds killed orphans to the deletion list, and therefore they are deleted
 * here too.
 */
static void erase_deleted(struct ubifs_info *c)
{
	struct ubifs_orphan *orphan, *dnext;

	spin_lock(&c->orphan_lock);
	dnext = c->orph_dnext;
	while (dnext) {
		orphan = dnext;
		dnext = orphan->dnext;
		ubifs_assert(!orphan->new);
		ubifs_assert(orphan->del);
		rb_erase(&orphan->rb, &c->orph_tree);
		list_del(&orphan->list);
		c->tot_orphans -= 1;
		dbg_gen("deleting orphan ino %lu", (unsigned long)orphan->inum);
		kfree(orphan);
	}
	c->orph_dnext = NULL;
	spin_unlock(&c->orphan_lock);
}

/**
 * ubifs_orphan_end_commit - end commit of orphans.
 * @c: UBIFS file-system description object
 *
 * End commit of orphans.
 */
int ubifs_orphan_end_commit(struct ubifs_info *c)
{
	int err;

	if (c->cmt_orphans != 0) {
		err = commit_orphans(c);
		if (err)
			return err;
	}
	erase_deleted(c);
	err = dbg_check_orphans(c);
	return err;
}

/**
 * ubifs_clear_orphans - erase all LEBs used for orphans.
 * @c: UBIFS file-system description object
 *
 * If recovery is not required, then the orphans from the previous session
 * are not needed. This function locates the LEBs used to record
 * orphans, and un-maps them.
 */
int ubifs_clear_orphans(struct ubifs_info *c)
{
	int lnum, err;

	for (lnum = c->orph_first; lnum <= c->orph_last; lnum++) {
		err = ubifs_leb_unmap(c, lnum);
		if (err)
			return err;
	}
	c->ohead_lnum = c->orph_first;
	c->ohead_offs = 0;
	return 0;
}

/**
 * insert_dead_orphan - insert an orphan.
 * @c: UBIFS file-system description object
 * @inum: orphan inode number
 *
 * This function is a helper to the 'do_kill_orphans()' function. The orphan
 * must be kept until the next commit, so it is added to the rb-tree and the
 * deletion list.
 */
static int insert_dead_orphan(struct ubifs_info *c, ino_t inum)
{
	struct ubifs_orphan *orphan, *o;
	struct rb_node **p, *parent = NULL;

	orphan = kzalloc(sizeof(struct ubifs_orphan), GFP_KERNEL);
	if (!orphan)
		return -ENOMEM;
	orphan->inum = inum;

	p = &c->orph_tree.rb_node;
	while (*p) {
		parent = *p;
		o = rb_entry(parent, struct ubifs_orphan, rb);
		if (inum < o->inum)
			p = &(*p)->rb_left;
		else if (inum > o->inum)
			p = &(*p)->rb_right;
		else {
			/* Already added - no problem */
			kfree(orphan);
			return 0;
		}
	}
	c->tot_orphans += 1;
	rb_link_node(&orphan->rb, parent, p);
	rb_insert_color(&orphan->rb, &c->orph_tree);
	list_add_tail(&orphan->list, &c->orph_list);
	orphan->del = 1;
	orphan->dnext = c->orph_dnext;
	c->orph_dnext = orphan;
	dbg_mnt("ino %lu, new %d, tot %d", (unsigned long)inum,
		c->new_orphans, c->tot_orphans);
	return 0;
}

/**
 * do_kill_orphans - remove orphan inodes from the index.
 * @c: UBIFS file-system description object
 * @sleb: scanned LEB
 * @last_cmt_no: cmt_no of last orphan node read is passed and returned here
 * @outofdate: whether the LEB is out of date is returned here
 * @last_flagged: whether the end orphan node is encountered
 *
 * This function is a helper to the 'kill_orphans()' function. It goes through
 * every orphan node in a LEB and for every inode number recorded, removes
 * all keys for that inode from the TNC.
 */
static int do_kill_orphans(struct ubifs_info *c, struct ubifs_scan_leb *sleb,
			   unsigned long long *last_cmt_no, int *outofdate,
			   int *last_flagged)
{
	struct ubifs_scan_node *snod;
	struct ubifs_orph_node *orph;
	unsigned long long cmt_no;
	ino_t inum;
	int i, n, err, first = 1;

	list_for_each_entry(snod, &sleb->nodes, list) {
		if (snod->type != UBIFS_ORPH_NODE) {
			ubifs_err("invalid node type %d in orphan area at %d:%d",
				  snod->type, sleb->lnum, snod->offs);
			ubifs_dump_node(c, snod->node);
			return -EINVAL;
		}

		orph = snod->node;

		/* Check commit number */
		cmt_no = le64_to_cpu(orph->cmt_no) & LLONG_MAX;
		/*
		 * The commit number on the master node may be less, because
		 * of a failed commit. If there are several failed commits in a
		 * row, the commit number written on orphan nodes will continue
		 * to increase (because the commit number is adjusted here) even
		 * though the commit number on the master node stays the same
		 * because the master node has not been re-written.
		 */
		if (cmt_no > c->cmt_no)
			c->cmt_no = cmt_no;
		if (cmt_no < *last_cmt_no && *last_flagged) {
			/*
			 * The last orphan node had a higher commit number and
			 * was flagged as the last written for that commit
			 * number. That makes this orphan node, out of date.
			 */
			if (!first) {
				ubifs_err("out of order commit number %llu in orphan node at %d:%d",
					  cmt_no, sleb->lnum, snod->offs);
				ubifs_dump_node(c, snod->node);
				return -EINVAL;
			}
			dbg_rcvry("out of date LEB %d", sleb->lnum);
			*outofdate = 1;
			return 0;
		}

		if (first)
			first = 0;

		n = (le32_to_cpu(orph->ch.len) - UBIFS_ORPH_NODE_SZ) >> 3;
		for (i = 0; i < n; i++) {
			inum = le64_to_cpu(orph->inos[i]);
			dbg_rcvry("deleting orphaned inode %lu",
				  (unsigned long)inum);
			err = ubifs_tnc_remove_ino(c, inum);
			if (err)
				return err;
			err = insert_dead_orphan(c, inum);
			if (err)
				return err;
		}

		*last_cmt_no = cmt_no;
		if (le64_to_cpu(orph->cmt_no) & (1ULL << 63)) {
			dbg_rcvry("last orph node for commit %llu at %d:%d",
				  cmt_no, sleb->lnum, snod->offs);
			*last_flagged = 1;
		} else
			*last_flagged = 0;
	}

	return 0;
}

/**
 * kill_orphans - remove all orphan inodes from the index.
 * @c: UBIFS file-system description object
 *
 * If recovery is required, then orphan inodes recorded during the previous
 * session (which ended with an unclean unmount) must be deleted from the index.
 * This is done by updating the TNC, but since the index is not updated until
 * the next commit, the LEBs where the orphan information is recorded are not
 * erased until the next commit.
 */
static int kill_orphans(struct ubifs_info *c)
{
	unsigned long long last_cmt_no = 0;
	int lnum, err = 0, outofdate = 0, last_flagged = 0;

	c->ohead_lnum = c->orph_first;
	c->ohead_offs = 0;
	/* Check no-orphans flag and skip this if no orphans */
	if (c->no_orphs) {
		dbg_rcvry("no orphans");
		return 0;
	}
	/*
	 * Orph nodes always start at c->orph_first and are written to each
	 * successive LEB in turn. Generally unused LEBs will have been unmapped
	 * but may contain out of date orphan nodes if the unmap didn't go
	 * through. In addition, the last orphan node written for each commit is
	 * marked (top bit of orph->cmt_no is set to 1). It is possible that
	 * there are orphan nodes from the next commit (i.e. the commit did not
	 * complete successfully). In that case, no orphans will have been lost
	 * due to the way that orphans are written, and any orphans added will
	 * be valid orphans anyway and so can be deleted.
	 */
	for (lnum = c->orph_first; lnum <= c->orph_last; lnum++) {
		struct ubifs_scan_leb *sleb;

		dbg_rcvry("LEB %d", lnum);
		sleb = ubifs_scan(c, lnum, 0, c->sbuf, 1);
		if (IS_ERR(sleb)) {
			if (PTR_ERR(sleb) == -EUCLEAN)
				sleb = ubifs_recover_leb(c, lnum, 0,
							 c->sbuf, -1);
			if (IS_ERR(sleb)) {
				err = PTR_ERR(sleb);
				break;
			}
		}
		err = do_kill_orphans(c, sleb, &last_cmt_no, &outofdate,
				      &last_flagged);
		if (err || outofdate) {
			ubifs_scan_destroy(sleb);
			break;
		}
		if (sleb->endpt) {
			c->ohead_lnum = lnum;
			c->ohead_offs = sleb->endpt;
		}
		ubifs_scan_destroy(sleb);
	}
	return err;
}

/**
 * ubifs_mount_orphans - delete orphan inodes and erase LEBs that recorded them.
 * @c: UBIFS file-system description object
 * @unclean: indicates recovery from unclean unmount
 * @read_only: indicates read only mount
 *
 * This function is called when mounting to erase orphans from the previous
 * session. If UBIFS was not unmounted cleanly, then the inodes recorded as
 * orphans are deleted.
 */
int ubifs_mount_orphans(struct ubifs_info *c, int unclean, int read_only)
{
	int err = 0;

	c->max_orphans = tot_avail_orphs(c);

	if (!read_only) {
		c->orph_buf = vmalloc(c->leb_size);
		if (!c->orph_buf)
			return -ENOMEM;
	}

	if (unclean)
		err = kill_orphans(c);
	else if (!read_only)
		err = ubifs_clear_orphans(c);

	return err;
}

/*
 * Everything below is related to debugging.
 */

struct check_orphan {
	struct rb_node rb;
	ino_t inum;
};

struct check_info {
	unsigned long last_ino;
	unsigned long tot_inos;
	unsigned long missing;
	unsigned long long leaf_cnt;
	struct ubifs_ino_node *node;
	struct rb_root root;
};

static int dbg_find_orphan(struct ubifs_info *c, ino_t inum)
{
	struct ubifs_orphan *o;
	struct rb_node *p;

	spin_lock(&c->orphan_lock);
	p = c->orph_tree.rb_node;
	while (p) {
		o = rb_entry(p, struct ubifs_orphan, rb);
		if (inum < o->inum)
			p = p->rb_left;
		else if (inum > o->inum)
			p = p->rb_right;
		else {
			spin_unlock(&c->orphan_lock);
			return 1;
		}
	}
	spin_unlock(&c->orphan_lock);
	return 0;
}

static int dbg_ins_check_orphan(struct rb_root *root, ino_t inum)
{
	struct check_orphan *orphan, *o;
	struct rb_node **p, *parent = NULL;

	orphan = kzalloc(sizeof(struct check_orphan), GFP_NOFS);
	if (!orphan)
		return -ENOMEM;
	orphan->inum = inum;

	p = &root->rb_node;
	while (*p) {
		parent = *p;
		o = rb_entry(parent, struct check_orphan, rb);
		if (inum < o->inum)
			p = &(*p)->rb_left;
		else if (inum > o->inum)
			p = &(*p)->rb_right;
		else {
			kfree(orphan);
			return 0;
		}
	}
	rb_link_node(&orphan->rb, parent, p);
	rb_insert_color(&orphan->rb, root);
	return 0;
}

static int dbg_find_check_orphan(struct rb_root *root, ino_t inum)
{
	struct check_orphan *o;
	struct rb_node *p;

	p = root->rb_node;
	while (p) {
		o = rb_entry(p, struct check_orphan, rb);
		if (inum < o->inum)
			p = p->rb_left;
		else if (inum > o->inum)
			p = p->rb_right;
		else
			return 1;
	}
	return 0;
}

static void dbg_free_check_tree(struct rb_root *root)
{
	struct check_orphan *o, *n;

	rbtree_postorder_for_each_entry_safe(o, n, root, rb)
		kfree(o);
}

static int dbg_orphan_check(struct ubifs_info *c, struct ubifs_zbranch *zbr,
			    void *priv)
{
	struct check_info *ci = priv;
	ino_t inum;
	int err;

	inum = key_inum(c, &zbr->key);
	if (inum != ci->last_ino) {
		/* Lowest node type is the inode node, so it comes first */
		if (key_type(c, &zbr->key) != UBIFS_INO_KEY)
			ubifs_err("found orphan node ino %lu, type %d",
				  (unsigned long)inum, key_type(c, &zbr->key));
		ci->last_ino = inum;
		ci->tot_inos += 1;
		err = ubifs_tnc_read_node(c, zbr, ci->node);
		if (err) {
			ubifs_err("node read failed, error %d", err);
			return err;
		}
		if (ci->node->nlink == 0)
			/* Must be recorded as an orphan */
			if (!dbg_find_check_orphan(&ci->root, inum) &&
			    !dbg_find_orphan(c, inum)) {
				ubifs_err("missing orphan, ino %lu",
					  (unsigned long)inum);
				ci->missing += 1;
			}
	}
	ci->leaf_cnt += 1;
	return 0;
}

static int dbg_read_orphans(struct check_info *ci, struct ubifs_scan_leb *sleb)
{
	struct ubifs_scan_node *snod;
	struct ubifs_orph_node *orph;
	ino_t inum;
	int i, n, err;

	list_for_each_entry(snod, &sleb->nodes, list) {
		cond_resched();
		if (snod->type != UBIFS_ORPH_NODE)
			continue;
		orph = snod->node;
		n = (le32_to_cpu(orph->ch.len) - UBIFS_ORPH_NODE_SZ) >> 3;
		for (i = 0; i < n; i++) {
			inum = le64_to_cpu(orph->inos[i]);
			err = dbg_ins_check_orphan(&ci->root, inum);
			if (err)
				return err;
		}
	}
	return 0;
}

static int dbg_scan_orphans(struct ubifs_info *c, struct check_info *ci)
{
	int lnum, err = 0;
	void *buf;

	/* Check no-orphans flag and skip this if no orphans */
	if (c->no_orphs)
		return 0;

	buf = __vmalloc(c->leb_size, GFP_NOFS, PAGE_KERNEL);
	if (!buf) {
		ubifs_err("cannot allocate memory to check orphans");
		return 0;
	}

	for (lnum = c->orph_first; lnum <= c->orph_last; lnum++) {
		struct ubifs_scan_leb *sleb;

		sleb = ubifs_scan(c, lnum, 0, buf, 0);
		if (IS_ERR(sleb)) {
			err = PTR_ERR(sleb);
			break;
		}

		err = dbg_read_orphans(ci, sleb);
		ubifs_scan_destroy(sleb);
		if (err)
			break;
	}

	vfree(buf);
	return err;
}

static int dbg_check_orphans(struct ubifs_info *c)
{
	struct check_info ci;
	int err;

	if (!dbg_is_chk_orph(c))
		return 0;

	ci.last_ino = 0;
	ci.tot_inos = 0;
	ci.missing  = 0;
	ci.leaf_cnt = 0;
	ci.root = RB_ROOT;
	ci.node = kmalloc(UBIFS_MAX_INO_NODE_SZ, GFP_NOFS);
	if (!ci.node) {
		ubifs_err("out of memory");
		return -ENOMEM;
	}

	err = dbg_scan_orphans(c, &ci);
	if (err)
		goto out;

	err = dbg_walk_index(c, &dbg_orphan_check, NULL, &ci);
	if (err) {
		ubifs_err("cannot scan TNC, error %d", err);
		goto out;
	}

	if (ci.missing) {
		ubifs_err("%lu missing orphan(s)", ci.missing);
		err = -EINVAL;
		goto out;
	}

	dbg_cmt("last inode number is %lu", ci.last_ino);
	dbg_cmt("total number of inodes is %lu", ci.tot_inos);
	dbg_cmt("total number of leaf nodes is %llu", ci.leaf_cnt);

out:
	dbg_free_check_tree(&ci.root);
	kfree(ci.node);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/orphan.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements the budgeting sub-system which is responsible for UBIFS
 * space management.
 *
 * Factors such as compression, wasted space at the ends of LEBs, space in other
 * journal heads, the effect of updates on the index, and so on, make it
 * impossible to accurately predict the amount of space needed. Consequently
 * approximations are used.
 */

// #include "ubifs.h"
// #include <linux/writeback.h>
// #include <linux/math64.h>

/*
 * When pessimistic budget calculations say that there is no enough space,
 * UBIFS starts writing back dirty inodes and pages, doing garbage collection,
 * or committing. The below constant defines maximum number of times UBIFS
 * repeats the operations.
 */
#define MAX_MKSPC_RETRIES 3

/*
 * The below constant defines amount of dirty pages which should be written
 * back at when trying to shrink the liability.
 */
#define NR_TO_WRITE 16

/**
 * shrink_liability - write-back some dirty pages/inodes.
 * @c: UBIFS file-system description object
 * @nr_to_write: how many dirty pages to write-back
 *
 * This function shrinks UBIFS liability by means of writing back some amount
 * of dirty inodes and their pages.
 *
 * Note, this function synchronizes even VFS inodes which are locked
 * (@i_mutex) by the caller of the budgeting function, because write-back does
 * not touch @i_mutex.
 */
static void shrink_liability(struct ubifs_info *c, int nr_to_write)
{
	down_read(&c->vfs_sb->s_umount);
	writeback_inodes_sb(c->vfs_sb, WB_REASON_FS_FREE_SPACE);
	up_read(&c->vfs_sb->s_umount);
}

/**
 * run_gc - run garbage collector.
 * @c: UBIFS file-system description object
 *
 * This function runs garbage collector to make some more free space. Returns
 * zero if a free LEB has been produced, %-EAGAIN if commit is required, and a
 * negative error code in case of failure.
 */
static int run_gc(struct ubifs_info *c)
{
	int err, lnum;

	/* Make some free space by garbage-collecting dirty space */
	down_read(&c->commit_sem);
	lnum = ubifs_garbage_collect(c, 1);
	up_read(&c->commit_sem);
	if (lnum < 0)
		return lnum;

	/* GC freed one LEB, return it to lprops */
	dbg_budg("GC freed LEB %d", lnum);
	err = ubifs_return_leb(c, lnum);
	if (err)
		return err;
	return 0;
}

/**
 * get_liability - calculate current liability.
 * @c: UBIFS file-system description object
 *
 * This function calculates and returns current UBIFS liability, i.e. the
 * amount of bytes UBIFS has "promised" to write to the media.
 */
static long long get_liability(struct ubifs_info *c)
{
	long long liab;

	spin_lock(&c->space_lock);
	liab = c->bi.idx_growth + c->bi.data_growth + c->bi.dd_growth;
	spin_unlock(&c->space_lock);
	return liab;
}

/**
 * make_free_space - make more free space on the file-system.
 * @c: UBIFS file-system description object
 *
 * This function is called when an operation cannot be budgeted because there
 * is supposedly no free space. But in most cases there is some free space:
 *   o budgeting is pessimistic, so it always budgets more than it is actually
 *     needed, so shrinking the liability is one way to make free space - the
 *     cached data will take less space then it was budgeted for;
 *   o GC may turn some dark space into free space (budgeting treats dark space
 *     as not available);
 *   o commit may free some LEB, i.e., turn freeable LEBs into free LEBs.
 *
 * So this function tries to do the above. Returns %-EAGAIN if some free space
 * was presumably made and the caller has to re-try budgeting the operation.
 * Returns %-ENOSPC if it couldn't do more free space, and other negative error
 * codes on failures.
 */
static int make_free_space(struct ubifs_info *c)
{
	int err, retries = 0;
	long long liab1, liab2;

	do {
		liab1 = get_liability(c);
		/*
		 * We probably have some dirty pages or inodes (liability), try
		 * to write them back.
		 */
		dbg_budg("liability %lld, run write-back", liab1);
		shrink_liability(c, NR_TO_WRITE);

		liab2 = get_liability(c);
		if (liab2 < liab1)
			return -EAGAIN;

		dbg_budg("new liability %lld (not shrunk)", liab2);

		/* Liability did not shrink again, try GC */
		dbg_budg("Run GC");
		err = run_gc(c);
		if (!err)
			return -EAGAIN;

		if (err != -EAGAIN && err != -ENOSPC)
			/* Some real error happened */
			return err;

		dbg_budg("Run commit (retries %d)", retries);
		err = ubifs_run_commit(c);
		if (err)
			return err;
	} while (retries++ < MAX_MKSPC_RETRIES);

	return -ENOSPC;
}

/**
 * ubifs_calc_min_idx_lebs - calculate amount of LEBs for the index.
 * @c: UBIFS file-system description object
 *
 * This function calculates and returns the number of LEBs which should be kept
 * for index usage.
 */
int ubifs_calc_min_idx_lebs(struct ubifs_info *c)
{
	int idx_lebs;
	long long idx_size;

	idx_size = c->bi.old_idx_sz + c->bi.idx_growth + c->bi.uncommitted_idx;
	/* And make sure we have thrice the index size of space reserved */
	idx_size += idx_size << 1;
	/*
	 * We do not maintain 'old_idx_size' as 'old_idx_lebs'/'old_idx_bytes'
	 * pair, nor similarly the two variables for the new index size, so we
	 * have to do this costly 64-bit division on fast-path.
	 */
	idx_lebs = div_u64(idx_size + c->idx_leb_size - 1, c->idx_leb_size);
	/*
	 * The index head is not available for the in-the-gaps method, so add an
	 * extra LEB to compensate.
	 */
	idx_lebs += 1;
	if (idx_lebs < MIN_INDEX_LEBS)
		idx_lebs = MIN_INDEX_LEBS;
	return idx_lebs;
}

/**
 * ubifs_calc_available - calculate available FS space.
 * @c: UBIFS file-system description object
 * @min_idx_lebs: minimum number of LEBs reserved for the index
 *
 * This function calculates and returns amount of FS space available for use.
 */
long long ubifs_calc_available(const struct ubifs_info *c, int min_idx_lebs)
{
	int subtract_lebs;
	long long available;

	available = c->main_bytes - c->lst.total_used;

	/*
	 * Now 'available' contains theoretically available flash space
	 * assuming there is no index, so we have to subtract the space which
	 * is reserved for the index.
	 */
	subtract_lebs = min_idx_lebs;

	/* Take into account that GC reserves one LEB for its own needs */
	subtract_lebs += 1;

	/*
	 * The GC journal head LEB is not really accessible. And since
	 * different write types go to different heads, we may count only on
	 * one head's space.
	 */
	subtract_lebs += c->jhead_cnt - 1;

	/* We also reserve one LEB for deletions, which bypass budgeting */
	subtract_lebs += 1;

	available -= (long long)subtract_lebs * c->leb_size;

	/* Subtract the dead space which is not available for use */
	available -= c->lst.total_dead;

	/*
	 * Subtract dark space, which might or might not be usable - it depends
	 * on the data which we have on the media and which will be written. If
	 * this is a lot of uncompressed or not-compressible data, the dark
	 * space cannot be used.
	 */
	available -= c->lst.total_dark;

	/*
	 * However, there is more dark space. The index may be bigger than
	 * @min_idx_lebs. Those extra LEBs are assumed to be available, but
	 * their dark space is not included in total_dark, so it is subtracted
	 * here.
	 */
	if (c->lst.idx_lebs > min_idx_lebs) {
		subtract_lebs = c->lst.idx_lebs - min_idx_lebs;
		available -= subtract_lebs * c->dark_wm;
	}

	/* The calculations are rough and may end up with a negative number */
	return available > 0 ? available : 0;
}

/**
 * can_use_rp - check whether the user is allowed to use reserved pool.
 * @c: UBIFS file-system description object
 *
 * UBIFS has so-called "reserved pool" which is flash space reserved
 * for the superuser and for uses whose UID/GID is recorded in UBIFS superblock.
 * This function checks whether current user is allowed to use reserved pool.
 * Returns %1  current user is allowed to use reserved pool and %0 otherwise.
 */
static int can_use_rp(struct ubifs_info *c)
{
	if (uid_eq(current_fsuid(), c->rp_uid) || capable(CAP_SYS_RESOURCE) ||
	    (!gid_eq(c->rp_gid, GLOBAL_ROOT_GID) && in_group_p(c->rp_gid)))
		return 1;
	return 0;
}

/**
 * do_budget_space - reserve flash space for index and data growth.
 * @c: UBIFS file-system description object
 *
 * This function makes sure UBIFS has enough free LEBs for index growth and
 * data.
 *
 * When budgeting index space, UBIFS reserves thrice as many LEBs as the index
 * would take if it was consolidated and written to the flash. This guarantees
 * that the "in-the-gaps" commit method always succeeds and UBIFS will always
 * be able to commit dirty index. So this function basically adds amount of
 * budgeted index space to the size of the current index, multiplies this by 3,
 * and makes sure this does not exceed the amount of free LEBs.
 *
 * Notes about @c->bi.min_idx_lebs and @c->lst.idx_lebs variables:
 * o @c->lst.idx_lebs is the number of LEBs the index currently uses. It might
 *    be large, because UBIFS does not do any index consolidation as long as
 *    there is free space. IOW, the index may take a lot of LEBs, but the LEBs
 *    will contain a lot of dirt.
 * o @c->bi.min_idx_lebs is the number of LEBS the index presumably takes. IOW,
 *    the index may be consolidated to take up to @c->bi.min_idx_lebs LEBs.
 *
 * This function returns zero in case of success, and %-ENOSPC in case of
 * failure.
 */
static int do_budget_space(struct ubifs_info *c)
{
	long long outstanding, available;
	int lebs, rsvd_idx_lebs, min_idx_lebs;

	/* First budget index space */
	min_idx_lebs = ubifs_calc_min_idx_lebs(c);

	/* Now 'min_idx_lebs' contains number of LEBs to reserve */
	if (min_idx_lebs > c->lst.idx_lebs)
		rsvd_idx_lebs = min_idx_lebs - c->lst.idx_lebs;
	else
		rsvd_idx_lebs = 0;

	/*
	 * The number of LEBs that are available to be used by the index is:
	 *
	 *    @c->lst.empty_lebs + @c->freeable_cnt + @c->idx_gc_cnt -
	 *    @c->lst.taken_empty_lebs
	 *
	 * @c->lst.empty_lebs are available because they are empty.
	 * @c->freeable_cnt are available because they contain only free and
	 * dirty space, @c->idx_gc_cnt are available because they are index
	 * LEBs that have been garbage collected and are awaiting the commit
	 * before they can be used. And the in-the-gaps method will grab these
	 * if it needs them. @c->lst.taken_empty_lebs are empty LEBs that have
	 * already been allocated for some purpose.
	 *
	 * Note, @c->idx_gc_cnt is included to both @c->lst.empty_lebs (because
	 * these LEBs are empty) and to @c->lst.taken_empty_lebs (because they
	 * are taken until after the commit).
	 *
	 * Note, @c->lst.taken_empty_lebs may temporarily be higher by one
	 * because of the way we serialize LEB allocations and budgeting. See a
	 * comment in 'ubifs_find_free_space()'.
	 */
	lebs = c->lst.empty_lebs + c->freeable_cnt + c->idx_gc_cnt -
	       c->lst.taken_empty_lebs;
	if (unlikely(rsvd_idx_lebs > lebs)) {
		dbg_budg("out of indexing space: min_idx_lebs %d (old %d), rsvd_idx_lebs %d",
			 min_idx_lebs, c->bi.min_idx_lebs, rsvd_idx_lebs);
		return -ENOSPC;
	}

	available = ubifs_calc_available(c, min_idx_lebs);
	outstanding = c->bi.data_growth + c->bi.dd_growth;

	if (unlikely(available < outstanding)) {
		dbg_budg("out of data space: available %lld, outstanding %lld",
			 available, outstanding);
		return -ENOSPC;
	}

	if (available - outstanding <= c->rp_size && !can_use_rp(c))
		return -ENOSPC;

	c->bi.min_idx_lebs = min_idx_lebs;
	return 0;
}

/**
 * calc_idx_growth - calculate approximate index growth from budgeting request.
 * @c: UBIFS file-system description object
 * @req: budgeting request
 *
 * For now we assume each new node adds one znode. But this is rather poor
 * approximation, though.
 */
static int calc_idx_growth(const struct ubifs_info *c,
			   const struct ubifs_budget_req *req)
{
	int znodes;

	znodes = req->new_ino + (req->new_page << UBIFS_BLOCKS_PER_PAGE_SHIFT) +
		 req->new_dent;
	return znodes * c->max_idx_node_sz;
}

/**
 * calc_data_growth - calculate approximate amount of new data from budgeting
 * request.
 * @c: UBIFS file-system description object
 * @req: budgeting request
 */
static int calc_data_growth(const struct ubifs_info *c,
			    const struct ubifs_budget_req *req)
{
	int data_growth;

	data_growth = req->new_ino  ? c->bi.inode_budget : 0;
	if (req->new_page)
		data_growth += c->bi.page_budget;
	if (req->new_dent)
		data_growth += c->bi.dent_budget;
	data_growth += req->new_ino_d;
	return data_growth;
}

/**
 * calc_dd_growth - calculate approximate amount of data which makes other data
 * dirty from budgeting request.
 * @c: UBIFS file-system description object
 * @req: budgeting request
 */
static int calc_dd_growth(const struct ubifs_info *c,
			  const struct ubifs_budget_req *req)
{
	int dd_growth;

	dd_growth = req->dirtied_page ? c->bi.page_budget : 0;

	if (req->dirtied_ino)
		dd_growth += c->bi.inode_budget << (req->dirtied_ino - 1);
	if (req->mod_dent)
		dd_growth += c->bi.dent_budget;
	dd_growth += req->dirtied_ino_d;
	return dd_growth;
}

/**
 * ubifs_budget_space - ensure there is enough space to complete an operation.
 * @c: UBIFS file-system description object
 * @req: budget request
 *
 * This function allocates budget for an operation. It uses pessimistic
 * approximation of how much flash space the operation needs. The goal of this
 * function is to make sure UBIFS always has flash space to flush all dirty
 * pages, dirty inodes, and dirty znodes (liability). This function may force
 * commit, garbage-collection or write-back. Returns zero in case of success,
 * %-ENOSPC if there is no free space and other negative error codes in case of
 * failures.
 */
int ubifs_budget_space(struct ubifs_info *c, struct ubifs_budget_req *req)
{
	int err, idx_growth, data_growth, dd_growth, retried = 0;

	ubifs_assert(req->new_page <= 1);
	ubifs_assert(req->dirtied_page <= 1);
	ubifs_assert(req->new_dent <= 1);
	ubifs_assert(req->mod_dent <= 1);
	ubifs_assert(req->new_ino <= 1);
	ubifs_assert(req->new_ino_d <= UBIFS_MAX_INO_DATA);
	ubifs_assert(req->dirtied_ino <= 4);
	ubifs_assert(req->dirtied_ino_d <= UBIFS_MAX_INO_DATA * 4);
	ubifs_assert(!(req->new_ino_d & 7));
	ubifs_assert(!(req->dirtied_ino_d & 7));

	data_growth = calc_data_growth(c, req);
	dd_growth = calc_dd_growth(c, req);
	if (!data_growth && !dd_growth)
		return 0;
	idx_growth = calc_idx_growth(c, req);

again:
	spin_lock(&c->space_lock);
	ubifs_assert(c->bi.idx_growth >= 0);
	ubifs_assert(c->bi.data_growth >= 0);
	ubifs_assert(c->bi.dd_growth >= 0);

	if (unlikely(c->bi.nospace) && (c->bi.nospace_rp || !can_use_rp(c))) {
		dbg_budg("no space");
		spin_unlock(&c->space_lock);
		return -ENOSPC;
	}

	c->bi.idx_growth += idx_growth;
	c->bi.data_growth += data_growth;
	c->bi.dd_growth += dd_growth;

	err = do_budget_space(c);
	if (likely(!err)) {
		req->idx_growth = idx_growth;
		req->data_growth = data_growth;
		req->dd_growth = dd_growth;
		spin_unlock(&c->space_lock);
		return 0;
	}

	/* Restore the old values */
	c->bi.idx_growth -= idx_growth;
	c->bi.data_growth -= data_growth;
	c->bi.dd_growth -= dd_growth;
	spin_unlock(&c->space_lock);

	if (req->fast) {
		dbg_budg("no space for fast budgeting");
		return err;
	}

	err = make_free_space(c);
	cond_resched();
	if (err == -EAGAIN) {
		dbg_budg("try again");
		goto again;
	} else if (err == -ENOSPC) {
		if (!retried) {
			retried = 1;
			dbg_budg("-ENOSPC, but anyway try once again");
			goto again;
		}
		dbg_budg("FS is full, -ENOSPC");
		c->bi.nospace = 1;
		if (can_use_rp(c) || c->rp_size == 0)
			c->bi.nospace_rp = 1;
		smp_wmb();
	} else
		ubifs_err("cannot budget space, error %d", err);
	return err;
}

/**
 * ubifs_release_budget - release budgeted free space.
 * @c: UBIFS file-system description object
 * @req: budget request
 *
 * This function releases the space budgeted by 'ubifs_budget_space()'. Note,
 * since the index changes (which were budgeted for in @req->idx_growth) will
 * only be written to the media on commit, this function moves the index budget
 * from @c->bi.idx_growth to @c->bi.uncommitted_idx. The latter will be zeroed
 * by the commit operation.
 */
void ubifs_release_budget(struct ubifs_info *c, struct ubifs_budget_req *req)
{
	ubifs_assert(req->new_page <= 1);
	ubifs_assert(req->dirtied_page <= 1);
	ubifs_assert(req->new_dent <= 1);
	ubifs_assert(req->mod_dent <= 1);
	ubifs_assert(req->new_ino <= 1);
	ubifs_assert(req->new_ino_d <= UBIFS_MAX_INO_DATA);
	ubifs_assert(req->dirtied_ino <= 4);
	ubifs_assert(req->dirtied_ino_d <= UBIFS_MAX_INO_DATA * 4);
	ubifs_assert(!(req->new_ino_d & 7));
	ubifs_assert(!(req->dirtied_ino_d & 7));
	if (!req->recalculate) {
		ubifs_assert(req->idx_growth >= 0);
		ubifs_assert(req->data_growth >= 0);
		ubifs_assert(req->dd_growth >= 0);
	}

	if (req->recalculate) {
		req->data_growth = calc_data_growth(c, req);
		req->dd_growth = calc_dd_growth(c, req);
		req->idx_growth = calc_idx_growth(c, req);
	}

	if (!req->data_growth && !req->dd_growth)
		return;

	c->bi.nospace = c->bi.nospace_rp = 0;
	smp_wmb();

	spin_lock(&c->space_lock);
	c->bi.idx_growth -= req->idx_growth;
	c->bi.uncommitted_idx += req->idx_growth;
	c->bi.data_growth -= req->data_growth;
	c->bi.dd_growth -= req->dd_growth;
	c->bi.min_idx_lebs = ubifs_calc_min_idx_lebs(c);

	ubifs_assert(c->bi.idx_growth >= 0);
	ubifs_assert(c->bi.data_growth >= 0);
	ubifs_assert(c->bi.dd_growth >= 0);
	ubifs_assert(c->bi.min_idx_lebs < c->main_lebs);
	ubifs_assert(!(c->bi.idx_growth & 7));
	ubifs_assert(!(c->bi.data_growth & 7));
	ubifs_assert(!(c->bi.dd_growth & 7));
	spin_unlock(&c->space_lock);
}

/**
 * ubifs_convert_page_budget - convert budget of a new page.
 * @c: UBIFS file-system description object
 *
 * This function converts budget which was allocated for a new page of data to
 * the budget of changing an existing page of data. The latter is smaller than
 * the former, so this function only does simple re-calculation and does not
 * involve any write-back.
 */
void ubifs_convert_page_budget(struct ubifs_info *c)
{
	spin_lock(&c->space_lock);
	/* Release the index growth reservation */
	c->bi.idx_growth -= c->max_idx_node_sz << UBIFS_BLOCKS_PER_PAGE_SHIFT;
	/* Release the data growth reservation */
	c->bi.data_growth -= c->bi.page_budget;
	/* Increase the dirty data growth reservation instead */
	c->bi.dd_growth += c->bi.page_budget;
	/* And re-calculate the indexing space reservation */
	c->bi.min_idx_lebs = ubifs_calc_min_idx_lebs(c);
	spin_unlock(&c->space_lock);
}

/**
 * ubifs_release_dirty_inode_budget - release dirty inode budget.
 * @c: UBIFS file-system description object
 * @ui: UBIFS inode to release the budget for
 *
 * This function releases budget corresponding to a dirty inode. It is usually
 * called when after the inode has been written to the media and marked as
 * clean. It also causes the "no space" flags to be cleared.
 */
void ubifs_release_dirty_inode_budget(struct ubifs_info *c,
				      struct ubifs_inode *ui)
{
	struct ubifs_budget_req req;

	memset(&req, 0, sizeof(struct ubifs_budget_req));
	/* The "no space" flags will be cleared because dd_growth is > 0 */
	req.dd_growth = c->bi.inode_budget + ALIGN(ui->data_len, 8);
	ubifs_release_budget(c, &req);
}

/**
 * ubifs_reported_space - calculate reported free space.
 * @c: the UBIFS file-system description object
 * @free: amount of free space
 *
 * This function calculates amount of free space which will be reported to
 * user-space. User-space application tend to expect that if the file-system
 * (e.g., via the 'statfs()' call) reports that it has N bytes available, they
 * are able to write a file of size N. UBIFS attaches node headers to each data
 * node and it has to write indexing nodes as well. This introduces additional
 * overhead, and UBIFS has to report slightly less free space to meet the above
 * expectations.
 *
 * This function assumes free space is made up of uncompressed data nodes and
 * full index nodes (one per data node, tripled because we always allow enough
 * space to write the index thrice).
 *
 * Note, the calculation is pessimistic, which means that most of the time
 * UBIFS reports less space than it actually has.
 */
long long ubifs_reported_space(const struct ubifs_info *c, long long free)
{
	int divisor, factor, f;

	/*
	 * Reported space size is @free * X, where X is UBIFS block size
	 * divided by UBIFS block size + all overhead one data block
	 * introduces. The overhead is the node header + indexing overhead.
	 *
	 * Indexing overhead calculations are based on the following formula:
	 * I = N/(f - 1) + 1, where I - number of indexing nodes, N - number
	 * of data nodes, f - fanout. Because effective UBIFS fanout is twice
	 * as less than maximum fanout, we assume that each data node
	 * introduces 3 * @c->max_idx_node_sz / (@c->fanout/2 - 1) bytes.
	 * Note, the multiplier 3 is because UBIFS reserves thrice as more space
	 * for the index.
	 */
	f = c->fanout > 3 ? c->fanout >> 1 : 2;
	factor = UBIFS_BLOCK_SIZE;
	divisor = UBIFS_MAX_DATA_NODE_SZ;
	divisor += (c->max_idx_node_sz * 3) / (f - 1);
	free *= factor;
	return div_u64(free, divisor);
}

/**
 * ubifs_get_free_space_nolock - return amount of free space.
 * @c: UBIFS file-system description object
 *
 * This function calculates amount of free space to report to user-space.
 *
 * Because UBIFS may introduce substantial overhead (the index, node headers,
 * alignment, wastage at the end of LEBs, etc), it cannot report real amount of
 * free flash space it has (well, because not all dirty space is reclaimable,
 * UBIFS does not actually know the real amount). If UBIFS did so, it would
 * bread user expectations about what free space is. Users seem to accustomed
 * to assume that if the file-system reports N bytes of free space, they would
 * be able to fit a file of N bytes to the FS. This almost works for
 * traditional file-systems, because they have way less overhead than UBIFS.
 * So, to keep users happy, UBIFS tries to take the overhead into account.
 */
long long ubifs_get_free_space_nolock(struct ubifs_info *c)
{
	int rsvd_idx_lebs, lebs;
	long long available, outstanding, free;

	ubifs_assert(c->bi.min_idx_lebs == ubifs_calc_min_idx_lebs(c));
	outstanding = c->bi.data_growth + c->bi.dd_growth;
	available = ubifs_calc_available(c, c->bi.min_idx_lebs);

	/*
	 * When reporting free space to user-space, UBIFS guarantees that it is
	 * possible to write a file of free space size. This means that for
	 * empty LEBs we may use more precise calculations than
	 * 'ubifs_calc_available()' is using. Namely, we know that in empty
	 * LEBs we would waste only @c->leb_overhead bytes, not @c->dark_wm.
	 * Thus, amend the available space.
	 *
	 * Note, the calculations below are similar to what we have in
	 * 'do_budget_space()', so refer there for comments.
	 */
	if (c->bi.min_idx_lebs > c->lst.idx_lebs)
		rsvd_idx_lebs = c->bi.min_idx_lebs - c->lst.idx_lebs;
	else
		rsvd_idx_lebs = 0;
	lebs = c->lst.empty_lebs + c->freeable_cnt + c->idx_gc_cnt -
	       c->lst.taken_empty_lebs;
	lebs -= rsvd_idx_lebs;
	available += lebs * (c->dark_wm - c->leb_overhead);

	if (available > outstanding)
		free = ubifs_reported_space(c, available - outstanding);
	else
		free = 0;
	return free;
}

/**
 * ubifs_get_free_space - return amount of free space.
 * @c: UBIFS file-system description object
 *
 * This function calculates and returns amount of free space to report to
 * user-space.
 */
long long ubifs_get_free_space(struct ubifs_info *c)
{
	long long free;

	spin_lock(&c->space_lock);
	free = ubifs_get_free_space_nolock(c);
	spin_unlock(&c->space_lock);

	return free;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/budget.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file contains functions for finding LEBs for various purposes e.g.
 * garbage collection. In general, lprops category heaps and lists are used
 * for fast access, falling back on scanning the LPT as a last resort.
 */

#include <linux/sort.h>
// #include "ubifs.h"
#include "../../inc/__fss.h"

/**
 * struct scan_data - data provided to scan callback functions
 * @min_space: minimum number of bytes for which to scan
 * @pick_free: whether it is OK to scan for empty LEBs
 * @lnum: LEB number found is returned here
 * @exclude_index: whether to exclude index LEBs
 */
struct scan_data {
	int min_space;
	int pick_free;
	int lnum;
	int exclude_index;
};

/**
 * valuable - determine whether LEB properties are valuable.
 * @c: the UBIFS file-system description object
 * @lprops: LEB properties
 *
 * This function return %1 if the LEB properties should be added to the LEB
 * properties tree in memory. Otherwise %0 is returned.
 */
static int valuable(struct ubifs_info *c, const struct ubifs_lprops *lprops)
{
	int n, cat = lprops->flags & LPROPS_CAT_MASK;
	struct ubifs_lpt_heap *heap;

	switch (cat) {
	case LPROPS_DIRTY:
	case LPROPS_DIRTY_IDX:
	case LPROPS_FREE:
		heap = &c->lpt_heap[cat - 1];
		if (heap->cnt < heap->max_cnt)
			return 1;
		if (lprops->free + lprops->dirty >= c->dark_wm)
			return 1;
		return 0;
	case LPROPS_EMPTY:
		n = c->lst.empty_lebs + c->freeable_cnt -
		    c->lst.taken_empty_lebs;
		if (n < c->lsave_cnt)
			return 1;
		return 0;
	case LPROPS_FREEABLE:
		return 1;
	case LPROPS_FRDI_IDX:
		return 1;
	}
	return 0;
}

/**
 * scan_for_dirty_cb - dirty space scan callback.
 * @c: the UBIFS file-system description object
 * @lprops: LEB properties to scan
 * @in_tree: whether the LEB properties are in main memory
 * @data: information passed to and from the caller of the scan
 *
 * This function returns a code that indicates whether the scan should continue
 * (%LPT_SCAN_CONTINUE), whether the LEB properties should be added to the tree
 * in main memory (%LPT_SCAN_ADD), or whether the scan should stop
 * (%LPT_SCAN_STOP).
 */
static int scan_for_dirty_cb(struct ubifs_info *c,
			     const struct ubifs_lprops *lprops, int in_tree,
			     struct scan_data *data)
{
	int ret = LPT_SCAN_CONTINUE;

	/* Exclude LEBs that are currently in use */
	if (lprops->flags & LPROPS_TAKEN)
		return LPT_SCAN_CONTINUE;
	/* Determine whether to add these LEB properties to the tree */
	if (!in_tree && valuable(c, lprops))
		ret |= LPT_SCAN_ADD;
	/* Exclude LEBs with too little space */
	if (lprops->free + lprops->dirty < data->min_space)
		return ret;
	/* If specified, exclude index LEBs */
	if (data->exclude_index && lprops->flags & LPROPS_INDEX)
		return ret;
	/* If specified, exclude empty or freeable LEBs */
	if (lprops->free + lprops->dirty == c->leb_size) {
		if (!data->pick_free)
			return ret;
	/* Exclude LEBs with too little dirty space (unless it is empty) */
	} else if (lprops->dirty < c->dead_wm)
		return ret;
	/* Finally we found space */
	data->lnum = lprops->lnum;
	return LPT_SCAN_ADD | LPT_SCAN_STOP;
}

/**
 * scan_for_dirty - find a data LEB with free space.
 * @c: the UBIFS file-system description object
 * @min_space: minimum amount free plus dirty space the returned LEB has to
 *             have
 * @pick_free: if it is OK to return a free or freeable LEB
 * @exclude_index: whether to exclude index LEBs
 *
 * This function returns a pointer to the LEB properties found or a negative
 * error code.
 */
static const struct ubifs_lprops *scan_for_dirty(struct ubifs_info *c,
						 int min_space, int pick_free,
						 int exclude_index)
{
	const struct ubifs_lprops *lprops;
	struct ubifs_lpt_heap *heap;
	struct scan_data data;
	int err, i;

	/* There may be an LEB with enough dirty space on the free heap */
	heap = &c->lpt_heap[LPROPS_FREE - 1];
	for (i = 0; i < heap->cnt; i++) {
		lprops = heap->arr[i];
		if (lprops->free + lprops->dirty < min_space)
			continue;
		if (lprops->dirty < c->dead_wm)
			continue;
		return lprops;
	}
	/*
	 * A LEB may have fallen off of the bottom of the dirty heap, and ended
	 * up as uncategorized even though it has enough dirty space for us now,
	 * so check the uncategorized list. N.B. neither empty nor freeable LEBs
	 * can end up as uncategorized because they are kept on lists not
	 * finite-sized heaps.
	 */
	list_for_each_entry(lprops, &c->uncat_list, list) {
		if (lprops->flags & LPROPS_TAKEN)
			continue;
		if (lprops->free + lprops->dirty < min_space)
			continue;
		if (exclude_index && (lprops->flags & LPROPS_INDEX))
			continue;
		if (lprops->dirty < c->dead_wm)
			continue;
		return lprops;
	}
	/* We have looked everywhere in main memory, now scan the flash */
	if (c->pnodes_have >= c->pnode_cnt)
		/* All pnodes are in memory, so skip scan */
		return ERR_PTR(-ENOSPC);
	data.min_space = min_space;
	data.pick_free = pick_free;
	data.lnum = -1;
	data.exclude_index = exclude_index;
	err = ubifs_lpt_scan_nolock(c, -1, c->lscan_lnum,
				    (ubifs_lpt_scan_callback)scan_for_dirty_cb,
				    &data);
	if (err)
		return ERR_PTR(err);
	ubifs_assert(data.lnum >= c->main_first && data.lnum < c->leb_cnt);
	c->lscan_lnum = data.lnum;
	lprops = ubifs_lpt_lookup_dirty(c, data.lnum);
	if (IS_ERR(lprops))
		return lprops;
	ubifs_assert(lprops->lnum == data.lnum);
	ubifs_assert(lprops->free + lprops->dirty >= min_space);
	ubifs_assert(lprops->dirty >= c->dead_wm ||
		     (pick_free &&
		      lprops->free + lprops->dirty == c->leb_size));
	ubifs_assert(!(lprops->flags & LPROPS_TAKEN));
	ubifs_assert(!exclude_index || !(lprops->flags & LPROPS_INDEX));
	return lprops;
}

/**
 * ubifs_find_dirty_leb - find a dirty LEB for the Garbage Collector.
 * @c: the UBIFS file-system description object
 * @ret_lp: LEB properties are returned here on exit
 * @min_space: minimum amount free plus dirty space the returned LEB has to
 *             have
 * @pick_free: controls whether it is OK to pick empty or index LEBs
 *
 * This function tries to find a dirty logical eraseblock which has at least
 * @min_space free and dirty space. It prefers to take an LEB from the dirty or
 * dirty index heap, and it falls-back to LPT scanning if the heaps are empty
 * or do not have an LEB which satisfies the @min_space criteria.
 *
 * Note, LEBs which have less than dead watermark of free + dirty space are
 * never picked by this function.
 *
 * The additional @pick_free argument controls if this function has to return a
 * free or freeable LEB if one is present. For example, GC must to set it to %1,
 * when called from the journal space reservation function, because the
 * appearance of free space may coincide with the loss of enough dirty space
 * for GC to succeed anyway.
 *
 * In contrast, if the Garbage Collector is called from budgeting, it should
 * just make free space, not return LEBs which are already free or freeable.
 *
 * In addition @pick_free is set to %2 by the recovery process in order to
 * recover gc_lnum in which case an index LEB must not be returned.
 *
 * This function returns zero and the LEB properties of found dirty LEB in case
 * of success, %-ENOSPC if no dirty LEB was found and a negative error code in
 * case of other failures. The returned LEB is marked as "taken".
 */
int ubifs_find_dirty_leb(struct ubifs_info *c, struct ubifs_lprops *ret_lp,
			 int min_space, int pick_free)
{
	int err = 0, sum, exclude_index = pick_free == 2 ? 1 : 0;
	const struct ubifs_lprops *lp = NULL, *idx_lp = NULL;
	struct ubifs_lpt_heap *heap, *idx_heap;

	ubifs_get_lprops(c);

	if (pick_free) {
		int lebs, rsvd_idx_lebs = 0;

		spin_lock(&c->space_lock);
		lebs = c->lst.empty_lebs + c->idx_gc_cnt;
		lebs += c->freeable_cnt - c->lst.taken_empty_lebs;

		/*
		 * Note, the index may consume more LEBs than have been reserved
		 * for it. It is OK because it might be consolidated by GC.
		 * But if the index takes fewer LEBs than it is reserved for it,
		 * this function must avoid picking those reserved LEBs.
		 */
		if (c->bi.min_idx_lebs >= c->lst.idx_lebs) {
			rsvd_idx_lebs = c->bi.min_idx_lebs -  c->lst.idx_lebs;
			exclude_index = 1;
		}
		spin_unlock(&c->space_lock);

		/* Check if there are enough free LEBs for the index */
		if (rsvd_idx_lebs < lebs) {
			/* OK, try to find an empty LEB */
			lp = ubifs_fast_find_empty(c);
			if (lp)
				goto found;

			/* Or a freeable LEB */
			lp = ubifs_fast_find_freeable(c);
			if (lp)
				goto found;
		} else
			/*
			 * We cannot pick free/freeable LEBs in the below code.
			 */
			pick_free = 0;
	} else {
		spin_lock(&c->space_lock);
		exclude_index = (c->bi.min_idx_lebs >= c->lst.idx_lebs);
		spin_unlock(&c->space_lock);
	}

	/* Look on the dirty and dirty index heaps */
	heap = &c->lpt_heap[LPROPS_DIRTY - 1];
	idx_heap = &c->lpt_heap[LPROPS_DIRTY_IDX - 1];

	if (idx_heap->cnt && !exclude_index) {
		idx_lp = idx_heap->arr[0];
		sum = idx_lp->free + idx_lp->dirty;
		/*
		 * Since we reserve thrice as much space for the index than it
		 * actually takes, it does not make sense to pick indexing LEBs
		 * with less than, say, half LEB of dirty space. May be half is
		 * not the optimal boundary - this should be tested and
		 * checked. This boundary should determine how much we use
		 * in-the-gaps to consolidate the index comparing to how much
		 * we use garbage collector to consolidate it. The "half"
		 * criteria just feels to be fine.
		 */
		if (sum < min_space || sum < c->half_leb_size)
			idx_lp = NULL;
	}

	if (heap->cnt) {
		lp = heap->arr[0];
		if (lp->dirty + lp->free < min_space)
			lp = NULL;
	}

	/* Pick the LEB with most space */
	if (idx_lp && lp) {
		if (idx_lp->free + idx_lp->dirty >= lp->free + lp->dirty)
			lp = idx_lp;
	} else if (idx_lp && !lp)
		lp = idx_lp;

	if (lp) {
		ubifs_assert(lp->free + lp->dirty >= c->dead_wm);
		goto found;
	}

	/* Did not find a dirty LEB on the dirty heaps, have to scan */
	dbg_find("scanning LPT for a dirty LEB");
	lp = scan_for_dirty(c, min_space, pick_free, exclude_index);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		goto out;
	}
	ubifs_assert(lp->dirty >= c->dead_wm ||
		     (pick_free && lp->free + lp->dirty == c->leb_size));

found:
	dbg_find("found LEB %d, free %d, dirty %d, flags %#x",
		 lp->lnum, lp->free, lp->dirty, lp->flags);

	lp = ubifs_change_lp(c, lp, LPROPS_NC, LPROPS_NC,
			     lp->flags | LPROPS_TAKEN, 0);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		goto out;
	}

	memcpy(ret_lp, lp, sizeof(struct ubifs_lprops));

out:
	ubifs_release_lprops(c);
	return err;
}

/**
 * scan_for_free_cb - free space scan callback.
 * @c: the UBIFS file-system description object
 * @lprops: LEB properties to scan
 * @in_tree: whether the LEB properties are in main memory
 * @data: information passed to and from the caller of the scan
 *
 * This function returns a code that indicates whether the scan should continue
 * (%LPT_SCAN_CONTINUE), whether the LEB properties should be added to the tree
 * in main memory (%LPT_SCAN_ADD), or whether the scan should stop
 * (%LPT_SCAN_STOP).
 */
static int scan_for_free_cb(struct ubifs_info *c,
			    const struct ubifs_lprops *lprops, int in_tree,
			    struct scan_data *data)
{
	int ret = LPT_SCAN_CONTINUE;

	/* Exclude LEBs that are currently in use */
	if (lprops->flags & LPROPS_TAKEN)
		return LPT_SCAN_CONTINUE;
	/* Determine whether to add these LEB properties to the tree */
	if (!in_tree && valuable(c, lprops))
		ret |= LPT_SCAN_ADD;
	/* Exclude index LEBs */
	if (lprops->flags & LPROPS_INDEX)
		return ret;
	/* Exclude LEBs with too little space */
	if (lprops->free < data->min_space)
		return ret;
	/* If specified, exclude empty LEBs */
	if (!data->pick_free && lprops->free == c->leb_size)
		return ret;
	/*
	 * LEBs that have only free and dirty space must not be allocated
	 * because they may have been unmapped already or they may have data
	 * that is obsolete only because of nodes that are still sitting in a
	 * wbuf.
	 */
	if (lprops->free + lprops->dirty == c->leb_size && lprops->dirty > 0)
		return ret;
	/* Finally we found space */
	data->lnum = lprops->lnum;
	return LPT_SCAN_ADD | LPT_SCAN_STOP;
}

/**
 * do_find_free_space - find a data LEB with free space.
 * @c: the UBIFS file-system description object
 * @min_space: minimum amount of free space required
 * @pick_free: whether it is OK to scan for empty LEBs
 * @squeeze: whether to try to find space in a non-empty LEB first
 *
 * This function returns a pointer to the LEB properties found or a negative
 * error code.
 */
static
const struct ubifs_lprops *do_find_free_space(struct ubifs_info *c,
					      int min_space, int pick_free,
					      int squeeze)
{
	const struct ubifs_lprops *lprops;
	struct ubifs_lpt_heap *heap;
	struct scan_data data;
	int err, i;

	if (squeeze) {
		lprops = ubifs_fast_find_free(c);
		if (lprops && lprops->free >= min_space)
			return lprops;
	}
	if (pick_free) {
		lprops = ubifs_fast_find_empty(c);
		if (lprops)
			return lprops;
	}
	if (!squeeze) {
		lprops = ubifs_fast_find_free(c);
		if (lprops && lprops->free >= min_space)
			return lprops;
	}
	/* There may be an LEB with enough free space on the dirty heap */
	heap = &c->lpt_heap[LPROPS_DIRTY - 1];
	for (i = 0; i < heap->cnt; i++) {
		lprops = heap->arr[i];
		if (lprops->free >= min_space)
			return lprops;
	}
	/*
	 * A LEB may have fallen off of the bottom of the free heap, and ended
	 * up as uncategorized even though it has enough free space for us now,
	 * so check the uncategorized list. N.B. neither empty nor freeable LEBs
	 * can end up as uncategorized because they are kept on lists not
	 * finite-sized heaps.
	 */
	list_for_each_entry(lprops, &c->uncat_list, list) {
		if (lprops->flags & LPROPS_TAKEN)
			continue;
		if (lprops->flags & LPROPS_INDEX)
			continue;
		if (lprops->free >= min_space)
			return lprops;
	}
	/* We have looked everywhere in main memory, now scan the flash */
	if (c->pnodes_have >= c->pnode_cnt)
		/* All pnodes are in memory, so skip scan */
		return ERR_PTR(-ENOSPC);
	data.min_space = min_space;
	data.pick_free = pick_free;
	data.lnum = -1;
	err = ubifs_lpt_scan_nolock(c, -1, c->lscan_lnum,
				    (ubifs_lpt_scan_callback)scan_for_free_cb,
				    &data);
	if (err)
		return ERR_PTR(err);
	ubifs_assert(data.lnum >= c->main_first && data.lnum < c->leb_cnt);
	c->lscan_lnum = data.lnum;
	lprops = ubifs_lpt_lookup_dirty(c, data.lnum);
	if (IS_ERR(lprops))
		return lprops;
	ubifs_assert(lprops->lnum == data.lnum);
	ubifs_assert(lprops->free >= min_space);
	ubifs_assert(!(lprops->flags & LPROPS_TAKEN));
	ubifs_assert(!(lprops->flags & LPROPS_INDEX));
	return lprops;
}

/**
 * ubifs_find_free_space - find a data LEB with free space.
 * @c: the UBIFS file-system description object
 * @min_space: minimum amount of required free space
 * @offs: contains offset of where free space starts on exit
 * @squeeze: whether to try to find space in a non-empty LEB first
 *
 * This function looks for an LEB with at least @min_space bytes of free space.
 * It tries to find an empty LEB if possible. If no empty LEBs are available,
 * this function searches for a non-empty data LEB. The returned LEB is marked
 * as "taken".
 *
 * This function returns found LEB number in case of success, %-ENOSPC if it
 * failed to find a LEB with @min_space bytes of free space and other a negative
 * error codes in case of failure.
 */
int ubifs_find_free_space(struct ubifs_info *c, int min_space, int *offs,
			  int squeeze)
{
	const struct ubifs_lprops *lprops;
	int lebs, rsvd_idx_lebs, pick_free = 0, err, lnum, flags;

	dbg_find("min_space %d", min_space);
	ubifs_get_lprops(c);

	/* Check if there are enough empty LEBs for commit */
	spin_lock(&c->space_lock);
	if (c->bi.min_idx_lebs > c->lst.idx_lebs)
		rsvd_idx_lebs = c->bi.min_idx_lebs -  c->lst.idx_lebs;
	else
		rsvd_idx_lebs = 0;
	lebs = c->lst.empty_lebs + c->freeable_cnt + c->idx_gc_cnt -
	       c->lst.taken_empty_lebs;
	if (rsvd_idx_lebs < lebs)
		/*
		 * OK to allocate an empty LEB, but we still don't want to go
		 * looking for one if there aren't any.
		 */
		if (c->lst.empty_lebs - c->lst.taken_empty_lebs > 0) {
			pick_free = 1;
			/*
			 * Because we release the space lock, we must account
			 * for this allocation here. After the LEB properties
			 * flags have been updated, we subtract one. Note, the
			 * result of this is that lprops also decreases
			 * @taken_empty_lebs in 'ubifs_change_lp()', so it is
			 * off by one for a short period of time which may
			 * introduce a small disturbance to budgeting
			 * calculations, but this is harmless because at the
			 * worst case this would make the budgeting subsystem
			 * be more pessimistic than needed.
			 *
			 * Fundamentally, this is about serialization of the
			 * budgeting and lprops subsystems. We could make the
			 * @space_lock a mutex and avoid dropping it before
			 * calling 'ubifs_change_lp()', but mutex is more
			 * heavy-weight, and we want budgeting to be as fast as
			 * possible.
			 */
			c->lst.taken_empty_lebs += 1;
		}
	spin_unlock(&c->space_lock);

	lprops = do_find_free_space(c, min_space, pick_free, squeeze);
	if (IS_ERR(lprops)) {
		err = PTR_ERR(lprops);
		goto out;
	}

	lnum = lprops->lnum;
	flags = lprops->flags | LPROPS_TAKEN;

	lprops = ubifs_change_lp(c, lprops, LPROPS_NC, LPROPS_NC, flags, 0);
	if (IS_ERR(lprops)) {
		err = PTR_ERR(lprops);
		goto out;
	}

	if (pick_free) {
		spin_lock(&c->space_lock);
		c->lst.taken_empty_lebs -= 1;
		spin_unlock(&c->space_lock);
	}

	*offs = c->leb_size - lprops->free;
	ubifs_release_lprops(c);

	if (*offs == 0) {
		/*
		 * Ensure that empty LEBs have been unmapped. They may not have
		 * been, for example, because of an unclean unmount.  Also
		 * LEBs that were freeable LEBs (free + dirty == leb_size) will
		 * not have been unmapped.
		 */
		err = ubifs_leb_unmap(c, lnum);
		if (err)
			return err;
	}

	dbg_find("found LEB %d, free %d", lnum, c->leb_size - *offs);
	ubifs_assert(*offs <= c->leb_size - min_space);
	return lnum;

out:
	if (pick_free) {
		spin_lock(&c->space_lock);
		c->lst.taken_empty_lebs -= 1;
		spin_unlock(&c->space_lock);
	}
	ubifs_release_lprops(c);
	return err;
}

/**
 * scan_for_idx_cb - callback used by the scan for a free LEB for the index.
 * @c: the UBIFS file-system description object
 * @lprops: LEB properties to scan
 * @in_tree: whether the LEB properties are in main memory
 * @data: information passed to and from the caller of the scan
 *
 * This function returns a code that indicates whether the scan should continue
 * (%LPT_SCAN_CONTINUE), whether the LEB properties should be added to the tree
 * in main memory (%LPT_SCAN_ADD), or whether the scan should stop
 * (%LPT_SCAN_STOP).
 */
static int scan_for_idx_cb(struct ubifs_info *c,
			   const struct ubifs_lprops *lprops, int in_tree,
			   struct scan_data *data)
{
	int ret = LPT_SCAN_CONTINUE;

	/* Exclude LEBs that are currently in use */
	if (lprops->flags & LPROPS_TAKEN)
		return LPT_SCAN_CONTINUE;
	/* Determine whether to add these LEB properties to the tree */
	if (!in_tree && valuable(c, lprops))
		ret |= LPT_SCAN_ADD;
	/* Exclude index LEBS */
	if (lprops->flags & LPROPS_INDEX)
		return ret;
	/* Exclude LEBs that cannot be made empty */
	if (lprops->free + lprops->dirty != c->leb_size)
		return ret;
	/*
	 * We are allocating for the index so it is safe to allocate LEBs with
	 * only free and dirty space, because write buffers are sync'd at commit
	 * start.
	 */
	data->lnum = lprops->lnum;
	return LPT_SCAN_ADD | LPT_SCAN_STOP;
}

/**
 * scan_for_leb_for_idx - scan for a free LEB for the index.
 * @c: the UBIFS file-system description object
 */
static const struct ubifs_lprops *scan_for_leb_for_idx(struct ubifs_info *c)
{
	struct ubifs_lprops *lprops;
	struct scan_data data;
	int err;

	data.lnum = -1;
	err = ubifs_lpt_scan_nolock(c, -1, c->lscan_lnum,
				    (ubifs_lpt_scan_callback)scan_for_idx_cb,
				    &data);
	if (err)
		return ERR_PTR(err);
	ubifs_assert(data.lnum >= c->main_first && data.lnum < c->leb_cnt);
	c->lscan_lnum = data.lnum;
	lprops = ubifs_lpt_lookup_dirty(c, data.lnum);
	if (IS_ERR(lprops))
		return lprops;
	ubifs_assert(lprops->lnum == data.lnum);
	ubifs_assert(lprops->free + lprops->dirty == c->leb_size);
	ubifs_assert(!(lprops->flags & LPROPS_TAKEN));
	ubifs_assert(!(lprops->flags & LPROPS_INDEX));
	return lprops;
}

/**
 * ubifs_find_free_leb_for_idx - find a free LEB for the index.
 * @c: the UBIFS file-system description object
 *
 * This function looks for a free LEB and returns that LEB number. The returned
 * LEB is marked as "taken", "index".
 *
 * Only empty LEBs are allocated. This is for two reasons. First, the commit
 * calculates the number of LEBs to allocate based on the assumption that they
 * will be empty. Secondly, free space at the end of an index LEB is not
 * guaranteed to be empty because it may have been used by the in-the-gaps
 * method prior to an unclean unmount.
 *
 * If no LEB is found %-ENOSPC is returned. For other failures another negative
 * error code is returned.
 */
int ubifs_find_free_leb_for_idx(struct ubifs_info *c)
{
	const struct ubifs_lprops *lprops;
	int lnum = -1, err, flags;

	ubifs_get_lprops(c);

	lprops = ubifs_fast_find_empty(c);
	if (!lprops) {
		lprops = ubifs_fast_find_freeable(c);
		if (!lprops) {
			/*
			 * The first condition means the following: go scan the
			 * LPT if there are uncategorized lprops, which means
			 * there may be freeable LEBs there (UBIFS does not
			 * store the information about freeable LEBs in the
			 * master node).
			 */
			if (c->in_a_category_cnt != c->main_lebs ||
			    c->lst.empty_lebs - c->lst.taken_empty_lebs > 0) {
				ubifs_assert(c->freeable_cnt == 0);
				lprops = scan_for_leb_for_idx(c);
				if (IS_ERR(lprops)) {
					err = PTR_ERR(lprops);
					goto out;
				}
			}
		}
	}

	if (!lprops) {
		err = -ENOSPC;
		goto out;
	}

	lnum = lprops->lnum;

	dbg_find("found LEB %d, free %d, dirty %d, flags %#x",
		 lnum, lprops->free, lprops->dirty, lprops->flags);

	flags = lprops->flags | LPROPS_TAKEN | LPROPS_INDEX;
	lprops = ubifs_change_lp(c, lprops, c->leb_size, 0, flags, 0);
	if (IS_ERR(lprops)) {
		err = PTR_ERR(lprops);
		goto out;
	}

	ubifs_release_lprops(c);

	/*
	 * Ensure that empty LEBs have been unmapped. They may not have been,
	 * for example, because of an unclean unmount. Also LEBs that were
	 * freeable LEBs (free + dirty == leb_size) will not have been unmapped.
	 */
	err = ubifs_leb_unmap(c, lnum);
	if (err) {
		ubifs_change_one_lp(c, lnum, LPROPS_NC, LPROPS_NC, 0,
				    LPROPS_TAKEN | LPROPS_INDEX, 0);
		return err;
	}

	return lnum;

out:
	ubifs_release_lprops(c);
	return err;
}

static int cmp_dirty_idx(const struct ubifs_lprops **a,
			 const struct ubifs_lprops **b)
{
	const struct ubifs_lprops *lpa = *a;
	const struct ubifs_lprops *lpb = *b;

	return lpa->dirty + lpa->free - lpb->dirty - lpb->free;
}

static void swap_dirty_idx(struct ubifs_lprops **a, struct ubifs_lprops **b,
			   int size)
{
	struct ubifs_lprops *t = *a;

	*a = *b;
	*b = t;
}

/**
 * ubifs_save_dirty_idx_lnums - save an array of the most dirty index LEB nos.
 * @c: the UBIFS file-system description object
 *
 * This function is called each commit to create an array of LEB numbers of
 * dirty index LEBs sorted in order of dirty and free space.  This is used by
 * the in-the-gaps method of TNC commit.
 */
int ubifs_save_dirty_idx_lnums(struct ubifs_info *c)
{
	int i;

	ubifs_get_lprops(c);
	/* Copy the LPROPS_DIRTY_IDX heap */
	c->dirty_idx.cnt = c->lpt_heap[LPROPS_DIRTY_IDX - 1].cnt;
	memcpy(c->dirty_idx.arr, c->lpt_heap[LPROPS_DIRTY_IDX - 1].arr,
	       sizeof(void *) * c->dirty_idx.cnt);
	/* Sort it so that the dirtiest is now at the end */
	sort(c->dirty_idx.arr, c->dirty_idx.cnt, sizeof(void *),
	     (int (*)(const void *, const void *))cmp_dirty_idx,
	     (void (*)(void *, void *, int))swap_dirty_idx);
	dbg_find("found %d dirty index LEBs", c->dirty_idx.cnt);
	if (c->dirty_idx.cnt)
		dbg_find("dirtiest index LEB is %d with dirty %d and free %d",
			 c->dirty_idx.arr[c->dirty_idx.cnt - 1]->lnum,
			 c->dirty_idx.arr[c->dirty_idx.cnt - 1]->dirty,
			 c->dirty_idx.arr[c->dirty_idx.cnt - 1]->free);
	/* Replace the lprops pointers with LEB numbers */
	for (i = 0; i < c->dirty_idx.cnt; i++)
		c->dirty_idx.arr[i] = (void *)(size_t)c->dirty_idx.arr[i]->lnum;
	ubifs_release_lprops(c);
	return 0;
}

/**
 * scan_dirty_idx_cb - callback used by the scan for a dirty index LEB.
 * @c: the UBIFS file-system description object
 * @lprops: LEB properties to scan
 * @in_tree: whether the LEB properties are in main memory
 * @data: information passed to and from the caller of the scan
 *
 * This function returns a code that indicates whether the scan should continue
 * (%LPT_SCAN_CONTINUE), whether the LEB properties should be added to the tree
 * in main memory (%LPT_SCAN_ADD), or whether the scan should stop
 * (%LPT_SCAN_STOP).
 */
static int scan_dirty_idx_cb(struct ubifs_info *c,
			   const struct ubifs_lprops *lprops, int in_tree,
			   struct scan_data *data)
{
	int ret = LPT_SCAN_CONTINUE;

	/* Exclude LEBs that are currently in use */
	if (lprops->flags & LPROPS_TAKEN)
		return LPT_SCAN_CONTINUE;
	/* Determine whether to add these LEB properties to the tree */
	if (!in_tree && valuable(c, lprops))
		ret |= LPT_SCAN_ADD;
	/* Exclude non-index LEBs */
	if (!(lprops->flags & LPROPS_INDEX))
		return ret;
	/* Exclude LEBs with too little space */
	if (lprops->free + lprops->dirty < c->min_idx_node_sz)
		return ret;
	/* Finally we found space */
	data->lnum = lprops->lnum;
	return LPT_SCAN_ADD | LPT_SCAN_STOP;
}

/**
 * find_dirty_idx_leb - find a dirty index LEB.
 * @c: the UBIFS file-system description object
 *
 * This function returns LEB number upon success and a negative error code upon
 * failure.  In particular, -ENOSPC is returned if a dirty index LEB is not
 * found.
 *
 * Note that this function scans the entire LPT but it is called very rarely.
 */
static int find_dirty_idx_leb(struct ubifs_info *c)
{
	const struct ubifs_lprops *lprops;
	struct ubifs_lpt_heap *heap;
	struct scan_data data;
	int err, i, ret;

	/* Check all structures in memory first */
	data.lnum = -1;
	heap = &c->lpt_heap[LPROPS_DIRTY_IDX - 1];
	for (i = 0; i < heap->cnt; i++) {
		lprops = heap->arr[i];
		ret = scan_dirty_idx_cb(c, lprops, 1, &data);
		if (ret & LPT_SCAN_STOP)
			goto found;
	}
	list_for_each_entry(lprops, &c->frdi_idx_list, list) {
		ret = scan_dirty_idx_cb(c, lprops, 1, &data);
		if (ret & LPT_SCAN_STOP)
			goto found;
	}
	list_for_each_entry(lprops, &c->uncat_list, list) {
		ret = scan_dirty_idx_cb(c, lprops, 1, &data);
		if (ret & LPT_SCAN_STOP)
			goto found;
	}
	if (c->pnodes_have >= c->pnode_cnt)
		/* All pnodes are in memory, so skip scan */
		return -ENOSPC;
	err = ubifs_lpt_scan_nolock(c, -1, c->lscan_lnum,
				    (ubifs_lpt_scan_callback)scan_dirty_idx_cb,
				    &data);
	if (err)
		return err;
found:
	ubifs_assert(data.lnum >= c->main_first && data.lnum < c->leb_cnt);
	c->lscan_lnum = data.lnum;
	lprops = ubifs_lpt_lookup_dirty(c, data.lnum);
	if (IS_ERR(lprops))
		return PTR_ERR(lprops);
	ubifs_assert(lprops->lnum == data.lnum);
	ubifs_assert(lprops->free + lprops->dirty >= c->min_idx_node_sz);
	ubifs_assert(!(lprops->flags & LPROPS_TAKEN));
	ubifs_assert((lprops->flags & LPROPS_INDEX));

	dbg_find("found dirty LEB %d, free %d, dirty %d, flags %#x",
		 lprops->lnum, lprops->free, lprops->dirty, lprops->flags);

	lprops = ubifs_change_lp(c, lprops, LPROPS_NC, LPROPS_NC,
				 lprops->flags | LPROPS_TAKEN, 0);
	if (IS_ERR(lprops))
		return PTR_ERR(lprops);

	return lprops->lnum;
}

/**
 * get_idx_gc_leb - try to get a LEB number from trivial GC.
 * @c: the UBIFS file-system description object
 */
static int get_idx_gc_leb(struct ubifs_info *c)
{
	const struct ubifs_lprops *lp;
	int err, lnum;

	err = ubifs_get_idx_gc_leb(c);
	if (err < 0)
		return err;
	lnum = err;
	/*
	 * The LEB was due to be unmapped after the commit but
	 * it is needed now for this commit.
	 */
	lp = ubifs_lpt_lookup_dirty(c, lnum);
	if (IS_ERR(lp))
		return PTR_ERR(lp);
	lp = ubifs_change_lp(c, lp, LPROPS_NC, LPROPS_NC,
			     lp->flags | LPROPS_INDEX, -1);
	if (IS_ERR(lp))
		return PTR_ERR(lp);
	dbg_find("LEB %d, dirty %d and free %d flags %#x",
		 lp->lnum, lp->dirty, lp->free, lp->flags);
	return lnum;
}

/**
 * find_dirtiest_idx_leb - find dirtiest index LEB from dirtiest array.
 * @c: the UBIFS file-system description object
 */
static int find_dirtiest_idx_leb(struct ubifs_info *c)
{
	const struct ubifs_lprops *lp;
	int lnum;

	while (1) {
		if (!c->dirty_idx.cnt)
			return -ENOSPC;
		/* The lprops pointers were replaced by LEB numbers */
		lnum = (size_t)c->dirty_idx.arr[--c->dirty_idx.cnt];
		lp = ubifs_lpt_lookup(c, lnum);
		if (IS_ERR(lp))
			return PTR_ERR(lp);
		if ((lp->flags & LPROPS_TAKEN) || !(lp->flags & LPROPS_INDEX))
			continue;
		lp = ubifs_change_lp(c, lp, LPROPS_NC, LPROPS_NC,
				     lp->flags | LPROPS_TAKEN, 0);
		if (IS_ERR(lp))
			return PTR_ERR(lp);
		break;
	}
	dbg_find("LEB %d, dirty %d and free %d flags %#x", lp->lnum, lp->dirty,
		 lp->free, lp->flags);
	ubifs_assert(lp->flags & LPROPS_TAKEN);
	ubifs_assert(lp->flags & LPROPS_INDEX);
	return lnum;
}

/**
 * ubifs_find_dirty_idx_leb - try to find dirtiest index LEB as at last commit.
 * @c: the UBIFS file-system description object
 *
 * This function attempts to find an untaken index LEB with the most free and
 * dirty space that can be used without overwriting index nodes that were in the
 * last index committed.
 */
int ubifs_find_dirty_idx_leb(struct ubifs_info *c)
{
	int err;

	ubifs_get_lprops(c);

	/*
	 * We made an array of the dirtiest index LEB numbers as at the start of
	 * last commit.  Try that array first.
	 */
	err = find_dirtiest_idx_leb(c);

	/* Next try scanning the entire LPT */
	if (err == -ENOSPC)
		err = find_dirty_idx_leb(c);

	/* Finally take any index LEBs awaiting trivial GC */
	if (err == -ENOSPC)
		err = get_idx_gc_leb(c);

	ubifs_release_lprops(c);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/find.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/* This file implements TNC functions for committing */

// #include <linux/random.h>
// #include "ubifs.h"

/**
 * make_idx_node - make an index node for fill-the-gaps method of TNC commit.
 * @c: UBIFS file-system description object
 * @idx: buffer in which to place new index node
 * @znode: znode from which to make new index node
 * @lnum: LEB number where new index node will be written
 * @offs: offset where new index node will be written
 * @len: length of new index node
 */
static int make_idx_node(struct ubifs_info *c, struct ubifs_idx_node *idx,
			 struct ubifs_znode *znode, int lnum, int offs, int len)
{
	struct ubifs_znode *zp;
	int i, err;

	/* Make index node */
	idx->ch.node_type = UBIFS_IDX_NODE;
	idx->child_cnt = cpu_to_le16(znode->child_cnt);
	idx->level = cpu_to_le16(znode->level);
	for (i = 0; i < znode->child_cnt; i++) {
		struct ubifs_branch *br = ubifs_idx_branch(c, idx, i);
		struct ubifs_zbranch *zbr = &znode->zbranch[i];

		key_write_idx(c, &zbr->key, &br->key);
		br->lnum = cpu_to_le32(zbr->lnum);
		br->offs = cpu_to_le32(zbr->offs);
		br->len = cpu_to_le32(zbr->len);
		if (!zbr->lnum || !zbr->len) {
			ubifs_err("bad ref in znode");
			ubifs_dump_znode(c, znode);
			if (zbr->znode)
				ubifs_dump_znode(c, zbr->znode);
		}
	}
	ubifs_prepare_node(c, idx, len, 0);

	znode->lnum = lnum;
	znode->offs = offs;
	znode->len = len;

	err = insert_old_idx_znode(c, znode);

	/* Update the parent */
	zp = znode->parent;
	if (zp) {
		struct ubifs_zbranch *zbr;

		zbr = &zp->zbranch[znode->iip];
		zbr->lnum = lnum;
		zbr->offs = offs;
		zbr->len = len;
	} else {
		c->zroot.lnum = lnum;
		c->zroot.offs = offs;
		c->zroot.len = len;
	}
	c->calc_idx_sz += ALIGN(len, 8);

	atomic_long_dec(&c->dirty_zn_cnt);

	ubifs_assert(ubifs_zn_dirty(znode));
	ubifs_assert(ubifs_zn_cow(znode));

	/*
	 * Note, unlike 'write_index()' we do not add memory barriers here
	 * because this function is called with @c->tnc_mutex locked.
	 */
	__clear_bit(DIRTY_ZNODE, &znode->flags);
	__clear_bit(COW_ZNODE, &znode->flags);

	return err;
}

/**
 * fill_gap - make index nodes in gaps in dirty index LEBs.
 * @c: UBIFS file-system description object
 * @lnum: LEB number that gap appears in
 * @gap_start: offset of start of gap
 * @gap_end: offset of end of gap
 * @dirt: adds dirty space to this
 *
 * This function returns the number of index nodes written into the gap.
 */
static int fill_gap(struct ubifs_info *c, int lnum, int gap_start, int gap_end,
		    int *dirt)
{
	int len, gap_remains, gap_pos, written, pad_len;

	ubifs_assert((gap_start & 7) == 0);
	ubifs_assert((gap_end & 7) == 0);
	ubifs_assert(gap_end >= gap_start);

	gap_remains = gap_end - gap_start;
	if (!gap_remains)
		return 0;
	gap_pos = gap_start;
	written = 0;
	while (c->enext) {
		len = ubifs_idx_node_sz(c, c->enext->child_cnt);
		if (len < gap_remains) {
			struct ubifs_znode *znode = c->enext;
			const int alen = ALIGN(len, 8);
			int err;

			ubifs_assert(alen <= gap_remains);
			err = make_idx_node(c, c->ileb_buf + gap_pos, znode,
					    lnum, gap_pos, len);
			if (err)
				return err;
			gap_remains -= alen;
			gap_pos += alen;
			c->enext = znode->cnext;
			if (c->enext == c->cnext)
				c->enext = NULL;
			written += 1;
		} else
			break;
	}
	if (gap_end == c->leb_size) {
		c->ileb_len = ALIGN(gap_pos, c->min_io_size);
		/* Pad to end of min_io_size */
		pad_len = c->ileb_len - gap_pos;
	} else
		/* Pad to end of gap */
		pad_len = gap_remains;
	dbg_gc("LEB %d:%d to %d len %d nodes written %d wasted bytes %d",
	       lnum, gap_start, gap_end, gap_end - gap_start, written, pad_len);
	ubifs_pad(c, c->ileb_buf + gap_pos, pad_len);
	*dirt += pad_len;
	return written;
}

/**
 * find_old_idx - find an index node obsoleted since the last commit start.
 * @c: UBIFS file-system description object
 * @lnum: LEB number of obsoleted index node
 * @offs: offset of obsoleted index node
 *
 * Returns %1 if found and %0 otherwise.
 */
static int find_old_idx(struct ubifs_info *c, int lnum, int offs)
{
	struct ubifs_old_idx *o;
	struct rb_node *p;

	p = c->old_idx.rb_node;
	while (p) {
		o = rb_entry(p, struct ubifs_old_idx, rb);
		if (lnum < o->lnum)
			p = p->rb_left;
		else if (lnum > o->lnum)
			p = p->rb_right;
		else if (offs < o->offs)
			p = p->rb_left;
		else if (offs > o->offs)
			p = p->rb_right;
		else
			return 1;
	}
	return 0;
}

/**
 * is_idx_node_in_use - determine if an index node can be overwritten.
 * @c: UBIFS file-system description object
 * @key: key of index node
 * @level: index node level
 * @lnum: LEB number of index node
 * @offs: offset of index node
 *
 * If @key / @lnum / @offs identify an index node that was not part of the old
 * index, then this function returns %0 (obsolete).  Else if the index node was
 * part of the old index but is now dirty %1 is returned, else if it is clean %2
 * is returned. A negative error code is returned on failure.
 */
static int is_idx_node_in_use(struct ubifs_info *c, union ubifs_key *key,
			      int level, int lnum, int offs)
{
	int ret;

	ret = is_idx_node_in_tnc(c, key, level, lnum, offs);
	if (ret < 0)
		return ret; /* Error code */
	if (ret == 0)
		if (find_old_idx(c, lnum, offs))
			return 1;
	return ret;
}

/**
 * layout_leb_in_gaps - layout index nodes using in-the-gaps method.
 * @c: UBIFS file-system description object
 * @p: return LEB number here
 *
 * This function lays out new index nodes for dirty znodes using in-the-gaps
 * method of TNC commit.
 * This function merely puts the next znode into the next gap, making no attempt
 * to try to maximise the number of znodes that fit.
 * This function returns the number of index nodes written into the gaps, or a
 * negative error code on failure.
 */
static int layout_leb_in_gaps(struct ubifs_info *c, int *p)
{
	struct ubifs_scan_leb *sleb;
	struct ubifs_scan_node *snod;
	int lnum, dirt = 0, gap_start, gap_end, err, written, tot_written;

	tot_written = 0;
	/* Get an index LEB with lots of obsolete index nodes */
	lnum = ubifs_find_dirty_idx_leb(c);
	if (lnum < 0)
		/*
		 * There also may be dirt in the index head that could be
		 * filled, however we do not check there at present.
		 */
		return lnum; /* Error code */
	*p = lnum;
	dbg_gc("LEB %d", lnum);
	/*
	 * Scan the index LEB.  We use the generic scan for this even though
	 * it is more comprehensive and less efficient than is needed for this
	 * purpose.
	 */
	sleb = ubifs_scan(c, lnum, 0, c->ileb_buf, 0);
	c->ileb_len = 0;
	if (IS_ERR(sleb))
		return PTR_ERR(sleb);
	gap_start = 0;
	list_for_each_entry(snod, &sleb->nodes, list) {
		struct ubifs_idx_node *idx;
		int in_use, level;

		ubifs_assert(snod->type == UBIFS_IDX_NODE);
		idx = snod->node;
		key_read(c, ubifs_idx_key(c, idx), &snod->key);
		level = le16_to_cpu(idx->level);
		/* Determine if the index node is in use (not obsolete) */
		in_use = is_idx_node_in_use(c, &snod->key, level, lnum,
					    snod->offs);
		if (in_use < 0) {
			ubifs_scan_destroy(sleb);
			return in_use; /* Error code */
		}
		if (in_use) {
			if (in_use == 1)
				dirt += ALIGN(snod->len, 8);
			/*
			 * The obsolete index nodes form gaps that can be
			 * overwritten.  This gap has ended because we have
			 * found an index node that is still in use
			 * i.e. not obsolete
			 */
			gap_end = snod->offs;
			/* Try to fill gap */
			written = fill_gap(c, lnum, gap_start, gap_end, &dirt);
			if (written < 0) {
				ubifs_scan_destroy(sleb);
				return written; /* Error code */
			}
			tot_written += written;
			gap_start = ALIGN(snod->offs + snod->len, 8);
		}
	}
	ubifs_scan_destroy(sleb);
	c->ileb_len = c->leb_size;
	gap_end = c->leb_size;
	/* Try to fill gap */
	written = fill_gap(c, lnum, gap_start, gap_end, &dirt);
	if (written < 0)
		return written; /* Error code */
	tot_written += written;
	if (tot_written == 0) {
		struct ubifs_lprops lp;

		dbg_gc("LEB %d wrote %d index nodes", lnum, tot_written);
		err = ubifs_read_one_lp(c, lnum, &lp);
		if (err)
			return err;
		if (lp.free == c->leb_size) {
			/*
			 * We must have snatched this LEB from the idx_gc list
			 * so we need to correct the free and dirty space.
			 */
			err = ubifs_change_one_lp(c, lnum,
						  c->leb_size - c->ileb_len,
						  dirt, 0, 0, 0);
			if (err)
				return err;
		}
		return 0;
	}
	err = ubifs_change_one_lp(c, lnum, c->leb_size - c->ileb_len, dirt,
				  0, 0, 0);
	if (err)
		return err;
	err = ubifs_leb_change(c, lnum, c->ileb_buf, c->ileb_len);
	if (err)
		return err;
	dbg_gc("LEB %d wrote %d index nodes", lnum, tot_written);
	return tot_written;
}

/**
 * get_leb_cnt - calculate the number of empty LEBs needed to commit.
 * @c: UBIFS file-system description object
 * @cnt: number of znodes to commit
 *
 * This function returns the number of empty LEBs needed to commit @cnt znodes
 * to the current index head.  The number is not exact and may be more than
 * needed.
 */
static int get_leb_cnt(struct ubifs_info *c, int cnt)
{
	int d;

	/* Assume maximum index node size (i.e. overestimate space needed) */
	cnt -= (c->leb_size - c->ihead_offs) / c->max_idx_node_sz;
	if (cnt < 0)
		cnt = 0;
	d = c->leb_size / c->max_idx_node_sz;
	return DIV_ROUND_UP(cnt, d);
}

/**
 * layout_in_gaps - in-the-gaps method of committing TNC.
 * @c: UBIFS file-system description object
 * @cnt: number of dirty znodes to commit.
 *
 * This function lays out new index nodes for dirty znodes using in-the-gaps
 * method of TNC commit.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int layout_in_gaps(struct ubifs_info *c, int cnt)
{
	int err, leb_needed_cnt, written, *p;

	dbg_gc("%d znodes to write", cnt);

	c->gap_lebs = kmalloc(sizeof(int) * (c->lst.idx_lebs + 1), GFP_NOFS);
	if (!c->gap_lebs)
		return -ENOMEM;

	p = c->gap_lebs;
	do {
		ubifs_assert(p < c->gap_lebs + sizeof(int) * c->lst.idx_lebs);
		written = layout_leb_in_gaps(c, p);
		if (written < 0) {
			err = written;
			if (err != -ENOSPC) {
				kfree(c->gap_lebs);
				c->gap_lebs = NULL;
				return err;
			}
			if (!dbg_is_chk_index(c)) {
				/*
				 * Do not print scary warnings if the debugging
				 * option which forces in-the-gaps is enabled.
				 */
				ubifs_warn("out of space");
				ubifs_dump_budg(c, &c->bi);
				ubifs_dump_lprops(c);
			}
			/* Try to commit anyway */
			break;
		}
		p++;
		cnt -= written;
		leb_needed_cnt = get_leb_cnt(c, cnt);
		dbg_gc("%d znodes remaining, need %d LEBs, have %d", cnt,
		       leb_needed_cnt, c->ileb_cnt);
	} while (leb_needed_cnt > c->ileb_cnt);

	*p = -1;
	return 0;
}

/**
 * layout_in_empty_space - layout index nodes in empty space.
 * @c: UBIFS file-system description object
 *
 * This function lays out new index nodes for dirty znodes using empty LEBs.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int layout_in_empty_space(struct ubifs_info *c)
{
	struct ubifs_znode *znode, *cnext, *zp;
	int lnum, offs, len, next_len, buf_len, buf_offs, used, avail;
	int wlen, blen, err;

	cnext = c->enext;
	if (!cnext)
		return 0;

	lnum = c->ihead_lnum;
	buf_offs = c->ihead_offs;

	buf_len = ubifs_idx_node_sz(c, c->fanout);
	buf_len = ALIGN(buf_len, c->min_io_size);
	used = 0;
	avail = buf_len;

	/* Ensure there is enough room for first write */
	next_len = ubifs_idx_node_sz(c, cnext->child_cnt);
	if (buf_offs + next_len > c->leb_size)
		lnum = -1;

	while (1) {
		znode = cnext;

		len = ubifs_idx_node_sz(c, znode->child_cnt);

		/* Determine the index node position */
		if (lnum == -1) {
			if (c->ileb_nxt >= c->ileb_cnt) {
				ubifs_err("out of space");
				return -ENOSPC;
			}
			lnum = c->ilebs[c->ileb_nxt++];
			buf_offs = 0;
			used = 0;
			avail = buf_len;
		}

		offs = buf_offs + used;

		znode->lnum = lnum;
		znode->offs = offs;
		znode->len = len;

		/* Update the parent */
		zp = znode->parent;
		if (zp) {
			struct ubifs_zbranch *zbr;
			int i;

			i = znode->iip;
			zbr = &zp->zbranch[i];
			zbr->lnum = lnum;
			zbr->offs = offs;
			zbr->len = len;
		} else {
			c->zroot.lnum = lnum;
			c->zroot.offs = offs;
			c->zroot.len = len;
		}
		c->calc_idx_sz += ALIGN(len, 8);

		/*
		 * Once lprops is updated, we can decrease the dirty znode count
		 * but it is easier to just do it here.
		 */
		atomic_long_dec(&c->dirty_zn_cnt);

		/*
		 * Calculate the next index node length to see if there is
		 * enough room for it
		 */
		cnext = znode->cnext;
		if (cnext == c->cnext)
			next_len = 0;
		else
			next_len = ubifs_idx_node_sz(c, cnext->child_cnt);

		/* Update buffer positions */
		wlen = used + len;
		used += ALIGN(len, 8);
		avail -= ALIGN(len, 8);

		if (next_len != 0 &&
		    buf_offs + used + next_len <= c->leb_size &&
		    avail > 0)
			continue;

		if (avail <= 0 && next_len &&
		    buf_offs + used + next_len <= c->leb_size)
			blen = buf_len;
		else
			blen = ALIGN(wlen, c->min_io_size);

		/* The buffer is full or there are no more znodes to do */
		buf_offs += blen;
		if (next_len) {
			if (buf_offs + next_len > c->leb_size) {
				err = ubifs_update_one_lp(c, lnum,
					c->leb_size - buf_offs, blen - used,
					0, 0);
				if (err)
					return err;
				lnum = -1;
			}
			used -= blen;
			if (used < 0)
				used = 0;
			avail = buf_len - used;
			continue;
		}
		err = ubifs_update_one_lp(c, lnum, c->leb_size - buf_offs,
					  blen - used, 0, 0);
		if (err)
			return err;
		break;
	}

	c->dbg->new_ihead_lnum = lnum;
	c->dbg->new_ihead_offs = buf_offs;

	return 0;
}

/**
 * layout_commit - determine positions of index nodes to commit.
 * @c: UBIFS file-system description object
 * @no_space: indicates that insufficient empty LEBs were allocated
 * @cnt: number of znodes to commit
 *
 * Calculate and update the positions of index nodes to commit.  If there were
 * an insufficient number of empty LEBs allocated, then index nodes are placed
 * into the gaps created by obsolete index nodes in non-empty index LEBs.  For
 * this purpose, an obsolete index node is one that was not in the index as at
 * the end of the last commit.  To write "in-the-gaps" requires that those index
 * LEBs are updated atomically in-place.
 */
static int layout_commit(struct ubifs_info *c, int no_space, int cnt)
{
	int err;

	if (no_space) {
		err = layout_in_gaps(c, cnt);
		if (err)
			return err;
	}
	err = layout_in_empty_space(c);
	return err;
}

/**
 * find_first_dirty - find first dirty znode.
 * @znode: znode to begin searching from
 */
static struct ubifs_znode *find_first_dirty(struct ubifs_znode *znode)
{
	int i, cont;

	if (!znode)
		return NULL;

	while (1) {
		if (znode->level == 0) {
			if (ubifs_zn_dirty(znode))
				return znode;
			return NULL;
		}
		cont = 0;
		for (i = 0; i < znode->child_cnt; i++) {
			struct ubifs_zbranch *zbr = &znode->zbranch[i];

			if (zbr->znode && ubifs_zn_dirty(zbr->znode)) {
				znode = zbr->znode;
				cont = 1;
				break;
			}
		}
		if (!cont) {
			if (ubifs_zn_dirty(znode))
				return znode;
			return NULL;
		}
	}
}

/**
 * find_next_dirty - find next dirty znode.
 * @znode: znode to begin searching from
 */
static struct ubifs_znode *find_next_dirty(struct ubifs_znode *znode)
{
	int n = znode->iip + 1;

	znode = znode->parent;
	if (!znode)
		return NULL;
	for (; n < znode->child_cnt; n++) {
		struct ubifs_zbranch *zbr = &znode->zbranch[n];

		if (zbr->znode && ubifs_zn_dirty(zbr->znode))
			return find_first_dirty(zbr->znode);
	}
	return znode;
}

/**
 * get_znodes_to_commit - create list of dirty znodes to commit.
 * @c: UBIFS file-system description object
 *
 * This function returns the number of znodes to commit.
 */
static int get_znodes_to_commit(struct ubifs_info *c)
{
	struct ubifs_znode *znode, *cnext;
	int cnt = 0;

	c->cnext = find_first_dirty(c->zroot.znode);
	znode = c->enext = c->cnext;
	if (!znode) {
		dbg_cmt("no znodes to commit");
		return 0;
	}
	cnt += 1;
	while (1) {
		ubifs_assert(!ubifs_zn_cow(znode));
		__set_bit(COW_ZNODE, &znode->flags);
		znode->alt = 0;
		cnext = find_next_dirty(znode);
		if (!cnext) {
			znode->cnext = c->cnext;
			break;
		}
		znode->cnext = cnext;
		znode = cnext;
		cnt += 1;
	}
	dbg_cmt("committing %d znodes", cnt);
	ubifs_assert(cnt == atomic_long_read(&c->dirty_zn_cnt));
	return cnt;
}

/**
 * alloc_idx_lebs - allocate empty LEBs to be used to commit.
 * @c: UBIFS file-system description object
 * @cnt: number of znodes to commit
 *
 * This function returns %-ENOSPC if it cannot allocate a sufficient number of
 * empty LEBs.  %0 is returned on success, otherwise a negative error code
 * is returned.
 */
static int alloc_idx_lebs(struct ubifs_info *c, int cnt)
{
	int i, leb_cnt, lnum;

	c->ileb_cnt = 0;
	c->ileb_nxt = 0;
	leb_cnt = get_leb_cnt(c, cnt);
	dbg_cmt("need about %d empty LEBS for TNC commit", leb_cnt);
	if (!leb_cnt)
		return 0;
	c->ilebs = kmalloc(leb_cnt * sizeof(int), GFP_NOFS);
	if (!c->ilebs)
		return -ENOMEM;
	for (i = 0; i < leb_cnt; i++) {
		lnum = ubifs_find_free_leb_for_idx(c);
		if (lnum < 0)
			return lnum;
		c->ilebs[c->ileb_cnt++] = lnum;
		dbg_cmt("LEB %d", lnum);
	}
	if (dbg_is_chk_index(c) && !(prandom_u32() & 7))
		return -ENOSPC;
	return 0;
}

/**
 * free_unused_idx_lebs - free unused LEBs that were allocated for the commit.
 * @c: UBIFS file-system description object
 *
 * It is possible that we allocate more empty LEBs for the commit than we need.
 * This functions frees the surplus.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int free_unused_idx_lebs(struct ubifs_info *c)
{
	int i, err = 0, lnum, er;

	for (i = c->ileb_nxt; i < c->ileb_cnt; i++) {
		lnum = c->ilebs[i];
		dbg_cmt("LEB %d", lnum);
		er = ubifs_change_one_lp(c, lnum, LPROPS_NC, LPROPS_NC, 0,
					 LPROPS_INDEX | LPROPS_TAKEN, 0);
		if (!err)
			err = er;
	}
	return err;
}

/**
 * free_idx_lebs - free unused LEBs after commit end.
 * @c: UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int free_idx_lebs(struct ubifs_info *c)
{
	int err;

	err = free_unused_idx_lebs(c);
	kfree(c->ilebs);
	c->ilebs = NULL;
	return err;
}

/**
 * ubifs_tnc_start_commit - start TNC commit.
 * @c: UBIFS file-system description object
 * @zroot: new index root position is returned here
 *
 * This function prepares the list of indexing nodes to commit and lays out
 * their positions on flash. If there is not enough free space it uses the
 * in-gap commit method. Returns zero in case of success and a negative error
 * code in case of failure.
 */
int ubifs_tnc_start_commit(struct ubifs_info *c, struct ubifs_zbranch *zroot)
{
	int err = 0, cnt;

	mutex_lock(&c->tnc_mutex);
	err = dbg_check_tnc(c, 1);
	if (err)
		goto out;
	cnt = get_znodes_to_commit(c);
	if (cnt != 0) {
		int no_space = 0;

		err = alloc_idx_lebs(c, cnt);
		if (err == -ENOSPC)
			no_space = 1;
		else if (err)
			goto out_free;
		err = layout_commit(c, no_space, cnt);
		if (err)
			goto out_free;
		ubifs_assert(atomic_long_read(&c->dirty_zn_cnt) == 0);
		err = free_unused_idx_lebs(c);
		if (err)
			goto out;
	}
	destroy_old_idx(c);
	memcpy(zroot, &c->zroot, sizeof(struct ubifs_zbranch));

	err = ubifs_save_dirty_idx_lnums(c);
	if (err)
		goto out;

	spin_lock(&c->space_lock);
	/*
	 * Although we have not finished committing yet, update size of the
	 * committed index ('c->bi.old_idx_sz') and zero out the index growth
	 * budget. It is OK to do this now, because we've reserved all the
	 * space which is needed to commit the index, and it is save for the
	 * budgeting subsystem to assume the index is already committed,
	 * even though it is not.
	 */
	ubifs_assert(c->bi.min_idx_lebs == ubifs_calc_min_idx_lebs(c));
	c->bi.old_idx_sz = c->calc_idx_sz;
	c->bi.uncommitted_idx = 0;
	c->bi.min_idx_lebs = ubifs_calc_min_idx_lebs(c);
	spin_unlock(&c->space_lock);
	mutex_unlock(&c->tnc_mutex);

	dbg_cmt("number of index LEBs %d", c->lst.idx_lebs);
	dbg_cmt("size of index %llu", c->calc_idx_sz);
	return err;

out_free:
	free_idx_lebs(c);
out:
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * write_index - write index nodes.
 * @c: UBIFS file-system description object
 *
 * This function writes the index nodes whose positions were laid out in the
 * layout_in_empty_space function.
 */
static int write_index(struct ubifs_info *c)
{
	struct ubifs_idx_node *idx;
	struct ubifs_znode *znode, *cnext;
	int i, lnum, offs, len, next_len, buf_len, buf_offs, used;
	int avail, wlen, err, lnum_pos = 0, blen, nxt_offs;

	cnext = c->enext;
	if (!cnext)
		return 0;

	/*
	 * Always write index nodes to the index head so that index nodes and
	 * other types of nodes are never mixed in the same erase block.
	 */
	lnum = c->ihead_lnum;
	buf_offs = c->ihead_offs;

	/* Allocate commit buffer */
	buf_len = ALIGN(c->max_idx_node_sz, c->min_io_size);
	used = 0;
	avail = buf_len;

	/* Ensure there is enough room for first write */
	next_len = ubifs_idx_node_sz(c, cnext->child_cnt);
	if (buf_offs + next_len > c->leb_size) {
		err = ubifs_update_one_lp(c, lnum, LPROPS_NC, 0, 0,
					  LPROPS_TAKEN);
		if (err)
			return err;
		lnum = -1;
	}

	while (1) {
		cond_resched();

		znode = cnext;
		idx = c->cbuf + used;

		/* Make index node */
		idx->ch.node_type = UBIFS_IDX_NODE;
		idx->child_cnt = cpu_to_le16(znode->child_cnt);
		idx->level = cpu_to_le16(znode->level);
		for (i = 0; i < znode->child_cnt; i++) {
			struct ubifs_branch *br = ubifs_idx_branch(c, idx, i);
			struct ubifs_zbranch *zbr = &znode->zbranch[i];

			key_write_idx(c, &zbr->key, &br->key);
			br->lnum = cpu_to_le32(zbr->lnum);
			br->offs = cpu_to_le32(zbr->offs);
			br->len = cpu_to_le32(zbr->len);
			if (!zbr->lnum || !zbr->len) {
				ubifs_err("bad ref in znode");
				ubifs_dump_znode(c, znode);
				if (zbr->znode)
					ubifs_dump_znode(c, zbr->znode);
			}
		}
		len = ubifs_idx_node_sz(c, znode->child_cnt);
		ubifs_prepare_node(c, idx, len, 0);

		/* Determine the index node position */
		if (lnum == -1) {
			lnum = c->ilebs[lnum_pos++];
			buf_offs = 0;
			used = 0;
			avail = buf_len;
		}
		offs = buf_offs + used;

		if (lnum != znode->lnum || offs != znode->offs ||
		    len != znode->len) {
			ubifs_err("inconsistent znode posn");
			return -EINVAL;
		}

		/* Grab some stuff from znode while we still can */
		cnext = znode->cnext;

		ubifs_assert(ubifs_zn_dirty(znode));
		ubifs_assert(ubifs_zn_cow(znode));

		/*
		 * It is important that other threads should see %DIRTY_ZNODE
		 * flag cleared before %COW_ZNODE. Specifically, it matters in
		 * the 'dirty_cow_znode()' function. This is the reason for the
		 * first barrier. Also, we want the bit changes to be seen to
		 * other threads ASAP, to avoid unnecesarry copying, which is
		 * the reason for the second barrier.
		 */
		clear_bit(DIRTY_ZNODE, &znode->flags);
		smp_mb__before_atomic();
		clear_bit(COW_ZNODE, &znode->flags);
		smp_mb__after_atomic();

		/*
		 * We have marked the znode as clean but have not updated the
		 * @c->clean_zn_cnt counter. If this znode becomes dirty again
		 * before 'free_obsolete_znodes()' is called, then
		 * @c->clean_zn_cnt will be decremented before it gets
		 * incremented (resulting in 2 decrements for the same znode).
		 * This means that @c->clean_zn_cnt may become negative for a
		 * while.
		 *
		 * Q: why we cannot increment @c->clean_zn_cnt?
		 * A: because we do not have the @c->tnc_mutex locked, and the
		 *    following code would be racy and buggy:
		 *
		 *    if (!ubifs_zn_obsolete(znode)) {
		 *            atomic_long_inc(&c->clean_zn_cnt);
		 *            atomic_long_inc(&ubifs_clean_zn_cnt);
		 *    }
		 *
		 *    Thus, we just delay the @c->clean_zn_cnt update until we
		 *    have the mutex locked.
		 */

		/* Do not access znode from this point on */

		/* Update buffer positions */
		wlen = used + len;
		used += ALIGN(len, 8);
		avail -= ALIGN(len, 8);

		/*
		 * Calculate the next index node length to see if there is
		 * enough room for it
		 */
		if (cnext == c->cnext)
			next_len = 0;
		else
			next_len = ubifs_idx_node_sz(c, cnext->child_cnt);

		nxt_offs = buf_offs + used + next_len;
		if (next_len && nxt_offs <= c->leb_size) {
			if (avail > 0)
				continue;
			else
				blen = buf_len;
		} else {
			wlen = ALIGN(wlen, 8);
			blen = ALIGN(wlen, c->min_io_size);
			ubifs_pad(c, c->cbuf + wlen, blen - wlen);
		}

		/* The buffer is full or there are no more znodes to do */
		err = ubifs_leb_write(c, lnum, c->cbuf, buf_offs, blen);
		if (err)
			return err;
		buf_offs += blen;
		if (next_len) {
			if (nxt_offs > c->leb_size) {
				err = ubifs_update_one_lp(c, lnum, LPROPS_NC, 0,
							  0, LPROPS_TAKEN);
				if (err)
					return err;
				lnum = -1;
			}
			used -= blen;
			if (used < 0)
				used = 0;
			avail = buf_len - used;
			memmove(c->cbuf, c->cbuf + blen, used);
			continue;
		}
		break;
	}

	if (lnum != c->dbg->new_ihead_lnum ||
	    buf_offs != c->dbg->new_ihead_offs) {
		ubifs_err("inconsistent ihead");
		return -EINVAL;
	}

	c->ihead_lnum = lnum;
	c->ihead_offs = buf_offs;

	return 0;
}

/**
 * free_obsolete_znodes - free obsolete znodes.
 * @c: UBIFS file-system description object
 *
 * At the end of commit end, obsolete znodes are freed.
 */
static void free_obsolete_znodes(struct ubifs_info *c)
{
	struct ubifs_znode *znode, *cnext;

	cnext = c->cnext;
	do {
		znode = cnext;
		cnext = znode->cnext;
		if (ubifs_zn_obsolete(znode))
			kfree(znode);
		else {
			znode->cnext = NULL;
			atomic_long_inc(&c->clean_zn_cnt);
			atomic_long_inc(&ubifs_clean_zn_cnt);
		}
	} while (cnext != c->cnext);
}

/**
 * return_gap_lebs - return LEBs used by the in-gap commit method.
 * @c: UBIFS file-system description object
 *
 * This function clears the "taken" flag for the LEBs which were used by the
 * "commit in-the-gaps" method.
 */
static int return_gap_lebs(struct ubifs_info *c)
{
	int *p, err;

	if (!c->gap_lebs)
		return 0;

	dbg_cmt("");
	for (p = c->gap_lebs; *p != -1; p++) {
		err = ubifs_change_one_lp(c, *p, LPROPS_NC, LPROPS_NC, 0,
					  LPROPS_TAKEN, 0);
		if (err)
			return err;
	}

	kfree(c->gap_lebs);
	c->gap_lebs = NULL;
	return 0;
}

/**
 * ubifs_tnc_end_commit - update the TNC for commit end.
 * @c: UBIFS file-system description object
 *
 * Write the dirty znodes.
 */
int ubifs_tnc_end_commit(struct ubifs_info *c)
{
	int err;

	if (!c->cnext)
		return 0;

	err = return_gap_lebs(c);
	if (err)
		return err;

	err = write_index(c);
	if (err)
		return err;

	mutex_lock(&c->tnc_mutex);

	dbg_cmt("TNC height is %d", c->zroot.znode->level + 1);

	free_obsolete_znodes(c);

	c->cnext = NULL;
	kfree(c->ilebs);
	c->ilebs = NULL;

	mutex_unlock(&c->tnc_mutex);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/tnc_commit.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 * Copyright (C) 2006, 2007 University of Szeged, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 *          Zoltan Sogor
 */

/*
 * This file provides a single place to access to compression and
 * decompression.
 */

#include <linux/crypto.h>
// #include "ubifs.h"
#include "../../inc/__fss.h"

/* Fake description object for the "none" compressor */
static struct ubifs_compressor none_compr = {
	.compr_type = UBIFS_COMPR_NONE,
	.name = "none",
	.capi_name = "",
};

#ifdef CONFIG_UBIFS_FS_LZO
static DEFINE_MUTEX(lzo_mutex);

static struct ubifs_compressor lzo_compr = {
	.compr_type = UBIFS_COMPR_LZO,
	.comp_mutex = &lzo_mutex,
	.name = "lzo",
	.capi_name = "lzo",
};
#else
static struct ubifs_compressor lzo_compr = {
	.compr_type = UBIFS_COMPR_LZO,
	.name = "lzo",
};
#endif

#ifdef CONFIG_UBIFS_FS_ZLIB
static DEFINE_MUTEX(deflate_mutex);
static DEFINE_MUTEX(inflate_mutex);

static struct ubifs_compressor zlib_compr = {
	.compr_type = UBIFS_COMPR_ZLIB,
	.comp_mutex = &deflate_mutex,
	.decomp_mutex = &inflate_mutex,
	.name = "zlib",
	.capi_name = "deflate",
};
#else
static struct ubifs_compressor zlib_compr = {
	.compr_type = UBIFS_COMPR_ZLIB,
	.name = "zlib",
};
#endif

/* All UBIFS compressors */
struct ubifs_compressor *ubifs_compressors[UBIFS_COMPR_TYPES_CNT];

/**
 * ubifs_compress - compress data.
 * @in_buf: data to compress
 * @in_len: length of the data to compress
 * @out_buf: output buffer where compressed data should be stored
 * @out_len: output buffer length is returned here
 * @compr_type: type of compression to use on enter, actually used compression
 *              type on exit
 *
 * This function compresses input buffer @in_buf of length @in_len and stores
 * the result in the output buffer @out_buf and the resulting length in
 * @out_len. If the input buffer does not compress, it is just copied to the
 * @out_buf. The same happens if @compr_type is %UBIFS_COMPR_NONE or if
 * compression error occurred.
 *
 * Note, if the input buffer was not compressed, it is copied to the output
 * buffer and %UBIFS_COMPR_NONE is returned in @compr_type.
 */
void ubifs_compress(const void *in_buf, int in_len, void *out_buf, int *out_len,
		    int *compr_type)
{
	int err;
	struct ubifs_compressor *compr = ubifs_compressors[*compr_type];

	if (*compr_type == UBIFS_COMPR_NONE)
		goto no_compr;

	/* If the input data is small, do not even try to compress it */
	if (in_len < UBIFS_MIN_COMPR_LEN)
		goto no_compr;

	if (compr->comp_mutex)
		mutex_lock(compr->comp_mutex);
	err = crypto_comp_compress(compr->cc, in_buf, in_len, out_buf,
				   (unsigned int *)out_len);
	if (compr->comp_mutex)
		mutex_unlock(compr->comp_mutex);
	if (unlikely(err)) {
		ubifs_warn("cannot compress %d bytes, compressor %s, error %d, leave data uncompressed",
			   in_len, compr->name, err);
		 goto no_compr;
	}

	/*
	 * If the data compressed only slightly, it is better to leave it
	 * uncompressed to improve read speed.
	 */
	if (in_len - *out_len < UBIFS_MIN_COMPRESS_DIFF)
		goto no_compr;

	return;

no_compr:
	memcpy(out_buf, in_buf, in_len);
	*out_len = in_len;
	*compr_type = UBIFS_COMPR_NONE;
}

/**
 * ubifs_decompress - decompress data.
 * @in_buf: data to decompress
 * @in_len: length of the data to decompress
 * @out_buf: output buffer where decompressed data should
 * @out_len: output length is returned here
 * @compr_type: type of compression
 *
 * This function decompresses data from buffer @in_buf into buffer @out_buf.
 * The length of the uncompressed data is returned in @out_len. This functions
 * returns %0 on success or a negative error code on failure.
 */
int ubifs_decompress(const void *in_buf, int in_len, void *out_buf,
		     int *out_len, int compr_type)
{
	int err;
	struct ubifs_compressor *compr;

	if (unlikely(compr_type < 0 || compr_type >= UBIFS_COMPR_TYPES_CNT)) {
		ubifs_err("invalid compression type %d", compr_type);
		return -EINVAL;
	}

	compr = ubifs_compressors[compr_type];

	if (unlikely(!compr->capi_name)) {
		ubifs_err("%s compression is not compiled in", compr->name);
		return -EINVAL;
	}

	if (compr_type == UBIFS_COMPR_NONE) {
		memcpy(out_buf, in_buf, in_len);
		*out_len = in_len;
		return 0;
	}

	if (compr->decomp_mutex)
		mutex_lock(compr->decomp_mutex);
	err = crypto_comp_decompress(compr->cc, in_buf, in_len, out_buf,
				     (unsigned int *)out_len);
	if (compr->decomp_mutex)
		mutex_unlock(compr->decomp_mutex);
	if (err)
		ubifs_err("cannot decompress %d bytes, compressor %s, error %d",
			  in_len, compr->name, err);

	return err;
}

/**
 * compr_init - initialize a compressor.
 * @compr: compressor description object
 *
 * This function initializes the requested compressor and returns zero in case
 * of success or a negative error code in case of failure.
 */
static int __init compr_init(struct ubifs_compressor *compr)
{
	if (compr->capi_name) {
		compr->cc = crypto_alloc_comp(compr->capi_name, 0, 0);
		if (IS_ERR(compr->cc)) {
			ubifs_err("cannot initialize compressor %s, error %ld",
				  compr->name, PTR_ERR(compr->cc));
			return PTR_ERR(compr->cc);
		}
	}

	ubifs_compressors[compr->compr_type] = compr;
	return 0;
}

/**
 * compr_exit - de-initialize a compressor.
 * @compr: compressor description object
 */
static void compr_exit(struct ubifs_compressor *compr)
{
	if (compr->capi_name)
		crypto_free_comp(compr->cc);
	return;
}

/**
 * ubifs_compressors_init - initialize UBIFS compressors.
 *
 * This function initializes the compressor which were compiled in. Returns
 * zero in case of success and a negative error code in case of failure.
 */
int __init ubifs_compressors_init(void)
{
	int err;

	err = compr_init(&lzo_compr);
	if (err)
		return err;

	err = compr_init(&zlib_compr);
	if (err)
		goto out_lzo;

	ubifs_compressors[UBIFS_COMPR_NONE] = &none_compr;
	return 0;

out_lzo:
	compr_exit(&lzo_compr);
	return err;
}

/**
 * ubifs_compressors_exit - de-initialize UBIFS compressors.
 */
void ubifs_compressors_exit(void)
{
	compr_exit(&lzo_compr);
	compr_exit(&zlib_compr);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/compress.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements the LEB properties tree (LPT) area. The LPT area
 * contains the LEB properties tree, a table of LPT area eraseblocks (ltab), and
 * (for the "big" model) a table of saved LEB numbers (lsave). The LPT area sits
 * between the log and the orphan area.
 *
 * The LPT area is like a miniature self-contained file system. It is required
 * that it never runs out of space, is fast to access and update, and scales
 * logarithmically. The LEB properties tree is implemented as a wandering tree
 * much like the TNC, and the LPT area has its own garbage collection.
 *
 * The LPT has two slightly different forms called the "small model" and the
 * "big model". The small model is used when the entire LEB properties table
 * can be written into a single eraseblock. In that case, garbage collection
 * consists of just writing the whole table, which therefore makes all other
 * eraseblocks reusable. In the case of the big model, dirty eraseblocks are
 * selected for garbage collection, which consists of marking the clean nodes in
 * that LEB as dirty, and then only the dirty nodes are written out. Also, in
 * the case of the big model, a table of LEB numbers is saved so that the entire
 * LPT does not to be scanned looking for empty eraseblocks when UBIFS is first
 * mounted.
 */

// #include "ubifs.h"
#include <linux/crc16.h>
// #include <linux/math64.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

/**
 * do_calc_lpt_geom - calculate sizes for the LPT area.
 * @c: the UBIFS file-system description object
 *
 * Calculate the sizes of LPT bit fields, nodes, and tree, based on the
 * properties of the flash and whether LPT is "big" (c->big_lpt).
 */
static void do_calc_lpt_geom(struct ubifs_info *c)
{
	int i, n, bits, per_leb_wastage, max_pnode_cnt;
	long long sz, tot_wastage;

	n = c->main_lebs + c->max_leb_cnt - c->leb_cnt;
	max_pnode_cnt = DIV_ROUND_UP(n, UBIFS_LPT_FANOUT);

	c->lpt_hght = 1;
	n = UBIFS_LPT_FANOUT;
	while (n < max_pnode_cnt) {
		c->lpt_hght += 1;
		n <<= UBIFS_LPT_FANOUT_SHIFT;
	}

	c->pnode_cnt = DIV_ROUND_UP(c->main_lebs, UBIFS_LPT_FANOUT);

	n = DIV_ROUND_UP(c->pnode_cnt, UBIFS_LPT_FANOUT);
	c->nnode_cnt = n;
	for (i = 1; i < c->lpt_hght; i++) {
		n = DIV_ROUND_UP(n, UBIFS_LPT_FANOUT);
		c->nnode_cnt += n;
	}

	c->space_bits = fls(c->leb_size) - 3;
	c->lpt_lnum_bits = fls(c->lpt_lebs);
	c->lpt_offs_bits = fls(c->leb_size - 1);
	c->lpt_spc_bits = fls(c->leb_size);

	n = DIV_ROUND_UP(c->max_leb_cnt, UBIFS_LPT_FANOUT);
	c->pcnt_bits = fls(n - 1);

	c->lnum_bits = fls(c->max_leb_cnt - 1);

	bits = UBIFS_LPT_CRC_BITS + UBIFS_LPT_TYPE_BITS +
	       (c->big_lpt ? c->pcnt_bits : 0) +
	       (c->space_bits * 2 + 1) * UBIFS_LPT_FANOUT;
	c->pnode_sz = (bits + 7) / 8;

	bits = UBIFS_LPT_CRC_BITS + UBIFS_LPT_TYPE_BITS +
	       (c->big_lpt ? c->pcnt_bits : 0) +
	       (c->lpt_lnum_bits + c->lpt_offs_bits) * UBIFS_LPT_FANOUT;
	c->nnode_sz = (bits + 7) / 8;

	bits = UBIFS_LPT_CRC_BITS + UBIFS_LPT_TYPE_BITS +
	       c->lpt_lebs * c->lpt_spc_bits * 2;
	c->ltab_sz = (bits + 7) / 8;

	bits = UBIFS_LPT_CRC_BITS + UBIFS_LPT_TYPE_BITS +
	       c->lnum_bits * c->lsave_cnt;
	c->lsave_sz = (bits + 7) / 8;

	/* Calculate the minimum LPT size */
	c->lpt_sz = (long long)c->pnode_cnt * c->pnode_sz;
	c->lpt_sz += (long long)c->nnode_cnt * c->nnode_sz;
	c->lpt_sz += c->ltab_sz;
	if (c->big_lpt)
		c->lpt_sz += c->lsave_sz;

	/* Add wastage */
	sz = c->lpt_sz;
	per_leb_wastage = max_t(int, c->pnode_sz, c->nnode_sz);
	sz += per_leb_wastage;
	tot_wastage = per_leb_wastage;
	while (sz > c->leb_size) {
		sz += per_leb_wastage;
		sz -= c->leb_size;
		tot_wastage += per_leb_wastage;
	}
	tot_wastage += ALIGN(sz, c->min_io_size) - sz;
	c->lpt_sz += tot_wastage;
}

/**
 * ubifs_calc_lpt_geom - calculate and check sizes for the LPT area.
 * @c: the UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_calc_lpt_geom(struct ubifs_info *c)
{
	int lebs_needed;
	long long sz;

	do_calc_lpt_geom(c);

	/* Verify that lpt_lebs is big enough */
	sz = c->lpt_sz * 2; /* Must have at least 2 times the size */
	lebs_needed = div_u64(sz + c->leb_size - 1, c->leb_size);
	if (lebs_needed > c->lpt_lebs) {
		ubifs_err("too few LPT LEBs");
		return -EINVAL;
	}

	/* Verify that ltab fits in a single LEB (since ltab is a single node */
	if (c->ltab_sz > c->leb_size) {
		ubifs_err("LPT ltab too big");
		return -EINVAL;
	}

	c->check_lpt_free = c->big_lpt;
	return 0;
}

/**
 * calc_dflt_lpt_geom - calculate default LPT geometry.
 * @c: the UBIFS file-system description object
 * @main_lebs: number of main area LEBs is passed and returned here
 * @big_lpt: whether the LPT area is "big" is returned here
 *
 * The size of the LPT area depends on parameters that themselves are dependent
 * on the size of the LPT area. This function, successively recalculates the LPT
 * area geometry until the parameters and resultant geometry are consistent.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int calc_dflt_lpt_geom(struct ubifs_info *c, int *main_lebs,
			      int *big_lpt)
{
	int i, lebs_needed;
	long long sz;

	/* Start by assuming the minimum number of LPT LEBs */
	c->lpt_lebs = UBIFS_MIN_LPT_LEBS;
	c->main_lebs = *main_lebs - c->lpt_lebs;
	if (c->main_lebs <= 0)
		return -EINVAL;

	/* And assume we will use the small LPT model */
	c->big_lpt = 0;

	/*
	 * Calculate the geometry based on assumptions above and then see if it
	 * makes sense
	 */
	do_calc_lpt_geom(c);

	/* Small LPT model must have lpt_sz < leb_size */
	if (c->lpt_sz > c->leb_size) {
		/* Nope, so try again using big LPT model */
		c->big_lpt = 1;
		do_calc_lpt_geom(c);
	}

	/* Now check there are enough LPT LEBs */
	for (i = 0; i < 64 ; i++) {
		sz = c->lpt_sz * 4; /* Allow 4 times the size */
		lebs_needed = div_u64(sz + c->leb_size - 1, c->leb_size);
		if (lebs_needed > c->lpt_lebs) {
			/* Not enough LPT LEBs so try again with more */
			c->lpt_lebs = lebs_needed;
			c->main_lebs = *main_lebs - c->lpt_lebs;
			if (c->main_lebs <= 0)
				return -EINVAL;
			do_calc_lpt_geom(c);
			continue;
		}
		if (c->ltab_sz > c->leb_size) {
			ubifs_err("LPT ltab too big");
			return -EINVAL;
		}
		*main_lebs = c->main_lebs;
		*big_lpt = c->big_lpt;
		return 0;
	}
	return -EINVAL;
}

/**
 * pack_bits - pack bit fields end-to-end.
 * @addr: address at which to pack (passed and next address returned)
 * @pos: bit position at which to pack (passed and next position returned)
 * @val: value to pack
 * @nrbits: number of bits of value to pack (1-32)
 */
static void pack_bits(uint8_t **addr, int *pos, uint32_t val, int nrbits)
{
	uint8_t *p = *addr;
	int b = *pos;

	ubifs_assert(nrbits > 0);
	ubifs_assert(nrbits <= 32);
	ubifs_assert(*pos >= 0);
	ubifs_assert(*pos < 8);
	ubifs_assert((val >> nrbits) == 0 || nrbits == 32);
	if (b) {
		*p |= ((uint8_t)val) << b;
		nrbits += b;
		if (nrbits > 8) {
			*++p = (uint8_t)(val >>= (8 - b));
			if (nrbits > 16) {
				*++p = (uint8_t)(val >>= 8);
				if (nrbits > 24) {
					*++p = (uint8_t)(val >>= 8);
					if (nrbits > 32)
						*++p = (uint8_t)(val >>= 8);
				}
			}
		}
	} else {
		*p = (uint8_t)val;
		if (nrbits > 8) {
			*++p = (uint8_t)(val >>= 8);
			if (nrbits > 16) {
				*++p = (uint8_t)(val >>= 8);
				if (nrbits > 24)
					*++p = (uint8_t)(val >>= 8);
			}
		}
	}
	b = nrbits & 7;
	if (b == 0)
		p++;
	*addr = p;
	*pos = b;
}

/**
 * ubifs_unpack_bits - unpack bit fields.
 * @addr: address at which to unpack (passed and next address returned)
 * @pos: bit position at which to unpack (passed and next position returned)
 * @nrbits: number of bits of value to unpack (1-32)
 *
 * This functions returns the value unpacked.
 */
uint32_t ubifs_unpack_bits(uint8_t **addr, int *pos, int nrbits)
{
	const int k = 32 - nrbits;
	uint8_t *p = *addr;
	int b = *pos;
	uint32_t uninitialized_var(val);
	const int bytes = (nrbits + b + 7) >> 3;

	ubifs_assert(nrbits > 0);
	ubifs_assert(nrbits <= 32);
	ubifs_assert(*pos >= 0);
	ubifs_assert(*pos < 8);
	if (b) {
		switch (bytes) {
		case 2:
			val = p[1];
			break;
		case 3:
			val = p[1] | ((uint32_t)p[2] << 8);
			break;
		case 4:
			val = p[1] | ((uint32_t)p[2] << 8) |
				     ((uint32_t)p[3] << 16);
			break;
		case 5:
			val = p[1] | ((uint32_t)p[2] << 8) |
				     ((uint32_t)p[3] << 16) |
				     ((uint32_t)p[4] << 24);
		}
		val <<= (8 - b);
		val |= *p >> b;
		nrbits += b;
	} else {
		switch (bytes) {
		case 1:
			val = p[0];
			break;
		case 2:
			val = p[0] | ((uint32_t)p[1] << 8);
			break;
		case 3:
			val = p[0] | ((uint32_t)p[1] << 8) |
				     ((uint32_t)p[2] << 16);
			break;
		case 4:
			val = p[0] | ((uint32_t)p[1] << 8) |
				     ((uint32_t)p[2] << 16) |
				     ((uint32_t)p[3] << 24);
			break;
		}
	}
	val <<= k;
	val >>= k;
	b = nrbits & 7;
	p += nrbits >> 3;
	*addr = p;
	*pos = b;
	ubifs_assert((val >> nrbits) == 0 || nrbits - b == 32);
	return val;
}

/**
 * ubifs_pack_pnode - pack all the bit fields of a pnode.
 * @c: UBIFS file-system description object
 * @buf: buffer into which to pack
 * @pnode: pnode to pack
 */
void ubifs_pack_pnode(struct ubifs_info *c, void *buf,
		      struct ubifs_pnode *pnode)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int i, pos = 0;
	uint16_t crc;

	pack_bits(&addr, &pos, UBIFS_LPT_PNODE, UBIFS_LPT_TYPE_BITS);
	if (c->big_lpt)
		pack_bits(&addr, &pos, pnode->num, c->pcnt_bits);
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		pack_bits(&addr, &pos, pnode->lprops[i].free >> 3,
			  c->space_bits);
		pack_bits(&addr, &pos, pnode->lprops[i].dirty >> 3,
			  c->space_bits);
		if (pnode->lprops[i].flags & LPROPS_INDEX)
			pack_bits(&addr, &pos, 1, 1);
		else
			pack_bits(&addr, &pos, 0, 1);
	}
	crc = crc16(-1, buf + UBIFS_LPT_CRC_BYTES,
		    c->pnode_sz - UBIFS_LPT_CRC_BYTES);
	addr = buf;
	pos = 0;
	pack_bits(&addr, &pos, crc, UBIFS_LPT_CRC_BITS);
}

/**
 * ubifs_pack_nnode - pack all the bit fields of a nnode.
 * @c: UBIFS file-system description object
 * @buf: buffer into which to pack
 * @nnode: nnode to pack
 */
void ubifs_pack_nnode(struct ubifs_info *c, void *buf,
		      struct ubifs_nnode *nnode)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int i, pos = 0;
	uint16_t crc;

	pack_bits(&addr, &pos, UBIFS_LPT_NNODE, UBIFS_LPT_TYPE_BITS);
	if (c->big_lpt)
		pack_bits(&addr, &pos, nnode->num, c->pcnt_bits);
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		int lnum = nnode->nbranch[i].lnum;

		if (lnum == 0)
			lnum = c->lpt_last + 1;
		pack_bits(&addr, &pos, lnum - c->lpt_first, c->lpt_lnum_bits);
		pack_bits(&addr, &pos, nnode->nbranch[i].offs,
			  c->lpt_offs_bits);
	}
	crc = crc16(-1, buf + UBIFS_LPT_CRC_BYTES,
		    c->nnode_sz - UBIFS_LPT_CRC_BYTES);
	addr = buf;
	pos = 0;
	pack_bits(&addr, &pos, crc, UBIFS_LPT_CRC_BITS);
}

/**
 * ubifs_pack_ltab - pack the LPT's own lprops table.
 * @c: UBIFS file-system description object
 * @buf: buffer into which to pack
 * @ltab: LPT's own lprops table to pack
 */
void ubifs_pack_ltab(struct ubifs_info *c, void *buf,
		     struct ubifs_lpt_lprops *ltab)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int i, pos = 0;
	uint16_t crc;

	pack_bits(&addr, &pos, UBIFS_LPT_LTAB, UBIFS_LPT_TYPE_BITS);
	for (i = 0; i < c->lpt_lebs; i++) {
		pack_bits(&addr, &pos, ltab[i].free, c->lpt_spc_bits);
		pack_bits(&addr, &pos, ltab[i].dirty, c->lpt_spc_bits);
	}
	crc = crc16(-1, buf + UBIFS_LPT_CRC_BYTES,
		    c->ltab_sz - UBIFS_LPT_CRC_BYTES);
	addr = buf;
	pos = 0;
	pack_bits(&addr, &pos, crc, UBIFS_LPT_CRC_BITS);
}

/**
 * ubifs_pack_lsave - pack the LPT's save table.
 * @c: UBIFS file-system description object
 * @buf: buffer into which to pack
 * @lsave: LPT's save table to pack
 */
void ubifs_pack_lsave(struct ubifs_info *c, void *buf, int *lsave)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int i, pos = 0;
	uint16_t crc;

	pack_bits(&addr, &pos, UBIFS_LPT_LSAVE, UBIFS_LPT_TYPE_BITS);
	for (i = 0; i < c->lsave_cnt; i++)
		pack_bits(&addr, &pos, lsave[i], c->lnum_bits);
	crc = crc16(-1, buf + UBIFS_LPT_CRC_BYTES,
		    c->lsave_sz - UBIFS_LPT_CRC_BYTES);
	addr = buf;
	pos = 0;
	pack_bits(&addr, &pos, crc, UBIFS_LPT_CRC_BITS);
}

/**
 * ubifs_add_lpt_dirt - add dirty space to LPT LEB properties.
 * @c: UBIFS file-system description object
 * @lnum: LEB number to which to add dirty space
 * @dirty: amount of dirty space to add
 */
void ubifs_add_lpt_dirt(struct ubifs_info *c, int lnum, int dirty)
{
	if (!dirty || !lnum)
		return;
	dbg_lp("LEB %d add %d to %d",
	       lnum, dirty, c->ltab[lnum - c->lpt_first].dirty);
	ubifs_assert(lnum >= c->lpt_first && lnum <= c->lpt_last);
	c->ltab[lnum - c->lpt_first].dirty += dirty;
}

/**
 * set_ltab - set LPT LEB properties.
 * @c: UBIFS file-system description object
 * @lnum: LEB number
 * @free: amount of free space
 * @dirty: amount of dirty space
 */
static void set_ltab(struct ubifs_info *c, int lnum, int free, int dirty)
{
	dbg_lp("LEB %d free %d dirty %d to %d %d",
	       lnum, c->ltab[lnum - c->lpt_first].free,
	       c->ltab[lnum - c->lpt_first].dirty, free, dirty);
	ubifs_assert(lnum >= c->lpt_first && lnum <= c->lpt_last);
	c->ltab[lnum - c->lpt_first].free = free;
	c->ltab[lnum - c->lpt_first].dirty = dirty;
}

/**
 * ubifs_add_nnode_dirt - add dirty space to LPT LEB properties.
 * @c: UBIFS file-system description object
 * @nnode: nnode for which to add dirt
 */
void ubifs_add_nnode_dirt(struct ubifs_info *c, struct ubifs_nnode *nnode)
{
	struct ubifs_nnode *np = nnode->parent;

	if (np)
		ubifs_add_lpt_dirt(c, np->nbranch[nnode->iip].lnum,
				   c->nnode_sz);
	else {
		ubifs_add_lpt_dirt(c, c->lpt_lnum, c->nnode_sz);
		if (!(c->lpt_drty_flgs & LTAB_DIRTY)) {
			c->lpt_drty_flgs |= LTAB_DIRTY;
			ubifs_add_lpt_dirt(c, c->ltab_lnum, c->ltab_sz);
		}
	}
}

/**
 * add_pnode_dirt - add dirty space to LPT LEB properties.
 * @c: UBIFS file-system description object
 * @pnode: pnode for which to add dirt
 */
static void add_pnode_dirt_lpt_c(struct ubifs_info *c, struct ubifs_pnode *pnode)
{
	ubifs_add_lpt_dirt(c, pnode->parent->nbranch[pnode->iip].lnum,
			   c->pnode_sz);
}

/**
 * calc_nnode_num - calculate nnode number.
 * @row: the row in the tree (root is zero)
 * @col: the column in the row (leftmost is zero)
 *
 * The nnode number is a number that uniquely identifies a nnode and can be used
 * easily to traverse the tree from the root to that nnode.
 *
 * This function calculates and returns the nnode number for the nnode at @row
 * and @col.
 */
static int calc_nnode_num(int row, int col)
{
	int num, bits;

	num = 1;
	while (row--) {
		bits = (col & (UBIFS_LPT_FANOUT - 1));
		col >>= UBIFS_LPT_FANOUT_SHIFT;
		num <<= UBIFS_LPT_FANOUT_SHIFT;
		num |= bits;
	}
	return num;
}

/**
 * calc_nnode_num_from_parent - calculate nnode number.
 * @c: UBIFS file-system description object
 * @parent: parent nnode
 * @iip: index in parent
 *
 * The nnode number is a number that uniquely identifies a nnode and can be used
 * easily to traverse the tree from the root to that nnode.
 *
 * This function calculates and returns the nnode number based on the parent's
 * nnode number and the index in parent.
 */
static int calc_nnode_num_from_parent(const struct ubifs_info *c,
				      struct ubifs_nnode *parent, int iip)
{
	int num, shft;

	if (!parent)
		return 1;
	shft = (c->lpt_hght - parent->level) * UBIFS_LPT_FANOUT_SHIFT;
	num = parent->num ^ (1 << shft);
	num |= (UBIFS_LPT_FANOUT + iip) << shft;
	return num;
}

/**
 * calc_pnode_num_from_parent - calculate pnode number.
 * @c: UBIFS file-system description object
 * @parent: parent nnode
 * @iip: index in parent
 *
 * The pnode number is a number that uniquely identifies a pnode and can be used
 * easily to traverse the tree from the root to that pnode.
 *
 * This function calculates and returns the pnode number based on the parent's
 * nnode number and the index in parent.
 */
static int calc_pnode_num_from_parent(const struct ubifs_info *c,
				      struct ubifs_nnode *parent, int iip)
{
	int i, n = c->lpt_hght - 1, pnum = parent->num, num = 0;

	for (i = 0; i < n; i++) {
		num <<= UBIFS_LPT_FANOUT_SHIFT;
		num |= pnum & (UBIFS_LPT_FANOUT - 1);
		pnum >>= UBIFS_LPT_FANOUT_SHIFT;
	}
	num <<= UBIFS_LPT_FANOUT_SHIFT;
	num |= iip;
	return num;
}

/**
 * ubifs_create_dflt_lpt - create default LPT.
 * @c: UBIFS file-system description object
 * @main_lebs: number of main area LEBs is passed and returned here
 * @lpt_first: LEB number of first LPT LEB
 * @lpt_lebs: number of LEBs for LPT is passed and returned here
 * @big_lpt: use big LPT model is passed and returned here
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_create_dflt_lpt(struct ubifs_info *c, int *main_lebs, int lpt_first,
			  int *lpt_lebs, int *big_lpt)
{
	int lnum, err = 0, node_sz, iopos, i, j, cnt, len, alen, row;
	int blnum, boffs, bsz, bcnt;
	struct ubifs_pnode *pnode = NULL;
	struct ubifs_nnode *nnode = NULL;
	void *buf = NULL, *p;
	struct ubifs_lpt_lprops *ltab = NULL;
	int *lsave = NULL;

	err = calc_dflt_lpt_geom(c, main_lebs, big_lpt);
	if (err)
		return err;
	*lpt_lebs = c->lpt_lebs;

	/* Needed by 'ubifs_pack_nnode()' and 'set_ltab()' */
	c->lpt_first = lpt_first;
	/* Needed by 'set_ltab()' */
	c->lpt_last = lpt_first + c->lpt_lebs - 1;
	/* Needed by 'ubifs_pack_lsave()' */
	c->main_first = c->leb_cnt - *main_lebs;

	lsave = kmalloc(sizeof(int) * c->lsave_cnt, GFP_KERNEL);
	pnode = kzalloc(sizeof(struct ubifs_pnode), GFP_KERNEL);
	nnode = kzalloc(sizeof(struct ubifs_nnode), GFP_KERNEL);
	buf = vmalloc(c->leb_size);
	ltab = vmalloc(sizeof(struct ubifs_lpt_lprops) * c->lpt_lebs);
	if (!pnode || !nnode || !buf || !ltab || !lsave) {
		err = -ENOMEM;
		goto out;
	}

	ubifs_assert(!c->ltab);
	c->ltab = ltab; /* Needed by set_ltab */

	/* Initialize LPT's own lprops */
	for (i = 0; i < c->lpt_lebs; i++) {
		ltab[i].free = c->leb_size;
		ltab[i].dirty = 0;
		ltab[i].tgc = 0;
		ltab[i].cmt = 0;
	}

	lnum = lpt_first;
	p = buf;
	/* Number of leaf nodes (pnodes) */
	cnt = c->pnode_cnt;

	/*
	 * The first pnode contains the LEB properties for the LEBs that contain
	 * the root inode node and the root index node of the index tree.
	 */
	node_sz = ALIGN(ubifs_idx_node_sz(c, 1), 8);
	iopos = ALIGN(node_sz, c->min_io_size);
	pnode->lprops[0].free = c->leb_size - iopos;
	pnode->lprops[0].dirty = iopos - node_sz;
	pnode->lprops[0].flags = LPROPS_INDEX;

	node_sz = UBIFS_INO_NODE_SZ;
	iopos = ALIGN(node_sz, c->min_io_size);
	pnode->lprops[1].free = c->leb_size - iopos;
	pnode->lprops[1].dirty = iopos - node_sz;

	for (i = 2; i < UBIFS_LPT_FANOUT; i++)
		pnode->lprops[i].free = c->leb_size;

	/* Add first pnode */
	ubifs_pack_pnode(c, p, pnode);
	p += c->pnode_sz;
	len = c->pnode_sz;
	pnode->num += 1;

	/* Reset pnode values for remaining pnodes */
	pnode->lprops[0].free = c->leb_size;
	pnode->lprops[0].dirty = 0;
	pnode->lprops[0].flags = 0;

	pnode->lprops[1].free = c->leb_size;
	pnode->lprops[1].dirty = 0;

	/*
	 * To calculate the internal node branches, we keep information about
	 * the level below.
	 */
	blnum = lnum; /* LEB number of level below */
	boffs = 0; /* Offset of level below */
	bcnt = cnt; /* Number of nodes in level below */
	bsz = c->pnode_sz; /* Size of nodes in level below */

	/* Add all remaining pnodes */
	for (i = 1; i < cnt; i++) {
		if (len + c->pnode_sz > c->leb_size) {
			alen = ALIGN(len, c->min_io_size);
			set_ltab(c, lnum, c->leb_size - alen, alen - len);
			memset(p, 0xff, alen - len);
			err = ubifs_leb_change(c, lnum++, buf, alen);
			if (err)
				goto out;
			p = buf;
			len = 0;
		}
		ubifs_pack_pnode(c, p, pnode);
		p += c->pnode_sz;
		len += c->pnode_sz;
		/*
		 * pnodes are simply numbered left to right starting at zero,
		 * which means the pnode number can be used easily to traverse
		 * down the tree to the corresponding pnode.
		 */
		pnode->num += 1;
	}

	row = 0;
	for (i = UBIFS_LPT_FANOUT; cnt > i; i <<= UBIFS_LPT_FANOUT_SHIFT)
		row += 1;
	/* Add all nnodes, one level at a time */
	while (1) {
		/* Number of internal nodes (nnodes) at next level */
		cnt = DIV_ROUND_UP(cnt, UBIFS_LPT_FANOUT);
		for (i = 0; i < cnt; i++) {
			if (len + c->nnode_sz > c->leb_size) {
				alen = ALIGN(len, c->min_io_size);
				set_ltab(c, lnum, c->leb_size - alen,
					    alen - len);
				memset(p, 0xff, alen - len);
				err = ubifs_leb_change(c, lnum++, buf, alen);
				if (err)
					goto out;
				p = buf;
				len = 0;
			}
			/* Only 1 nnode at this level, so it is the root */
			if (cnt == 1) {
				c->lpt_lnum = lnum;
				c->lpt_offs = len;
			}
			/* Set branches to the level below */
			for (j = 0; j < UBIFS_LPT_FANOUT; j++) {
				if (bcnt) {
					if (boffs + bsz > c->leb_size) {
						blnum += 1;
						boffs = 0;
					}
					nnode->nbranch[j].lnum = blnum;
					nnode->nbranch[j].offs = boffs;
					boffs += bsz;
					bcnt--;
				} else {
					nnode->nbranch[j].lnum = 0;
					nnode->nbranch[j].offs = 0;
				}
			}
			nnode->num = calc_nnode_num(row, i);
			ubifs_pack_nnode(c, p, nnode);
			p += c->nnode_sz;
			len += c->nnode_sz;
		}
		/* Only 1 nnode at this level, so it is the root */
		if (cnt == 1)
			break;
		/* Update the information about the level below */
		bcnt = cnt;
		bsz = c->nnode_sz;
		row -= 1;
	}

	if (*big_lpt) {
		/* Need to add LPT's save table */
		if (len + c->lsave_sz > c->leb_size) {
			alen = ALIGN(len, c->min_io_size);
			set_ltab(c, lnum, c->leb_size - alen, alen - len);
			memset(p, 0xff, alen - len);
			err = ubifs_leb_change(c, lnum++, buf, alen);
			if (err)
				goto out;
			p = buf;
			len = 0;
		}

		c->lsave_lnum = lnum;
		c->lsave_offs = len;

		for (i = 0; i < c->lsave_cnt && i < *main_lebs; i++)
			lsave[i] = c->main_first + i;
		for (; i < c->lsave_cnt; i++)
			lsave[i] = c->main_first;

		ubifs_pack_lsave(c, p, lsave);
		p += c->lsave_sz;
		len += c->lsave_sz;
	}

	/* Need to add LPT's own LEB properties table */
	if (len + c->ltab_sz > c->leb_size) {
		alen = ALIGN(len, c->min_io_size);
		set_ltab(c, lnum, c->leb_size - alen, alen - len);
		memset(p, 0xff, alen - len);
		err = ubifs_leb_change(c, lnum++, buf, alen);
		if (err)
			goto out;
		p = buf;
		len = 0;
	}

	c->ltab_lnum = lnum;
	c->ltab_offs = len;

	/* Update ltab before packing it */
	len += c->ltab_sz;
	alen = ALIGN(len, c->min_io_size);
	set_ltab(c, lnum, c->leb_size - alen, alen - len);

	ubifs_pack_ltab(c, p, ltab);
	p += c->ltab_sz;

	/* Write remaining buffer */
	memset(p, 0xff, alen - len);
	err = ubifs_leb_change(c, lnum, buf, alen);
	if (err)
		goto out;

	c->nhead_lnum = lnum;
	c->nhead_offs = ALIGN(len, c->min_io_size);

	dbg_lp("space_bits %d", c->space_bits);
	dbg_lp("lpt_lnum_bits %d", c->lpt_lnum_bits);
	dbg_lp("lpt_offs_bits %d", c->lpt_offs_bits);
	dbg_lp("lpt_spc_bits %d", c->lpt_spc_bits);
	dbg_lp("pcnt_bits %d", c->pcnt_bits);
	dbg_lp("lnum_bits %d", c->lnum_bits);
	dbg_lp("pnode_sz %d", c->pnode_sz);
	dbg_lp("nnode_sz %d", c->nnode_sz);
	dbg_lp("ltab_sz %d", c->ltab_sz);
	dbg_lp("lsave_sz %d", c->lsave_sz);
	dbg_lp("lsave_cnt %d", c->lsave_cnt);
	dbg_lp("lpt_hght %d", c->lpt_hght);
	dbg_lp("big_lpt %d", c->big_lpt);
	dbg_lp("LPT root is at %d:%d", c->lpt_lnum, c->lpt_offs);
	dbg_lp("LPT head is at %d:%d", c->nhead_lnum, c->nhead_offs);
	dbg_lp("LPT ltab is at %d:%d", c->ltab_lnum, c->ltab_offs);
	if (c->big_lpt)
		dbg_lp("LPT lsave is at %d:%d", c->lsave_lnum, c->lsave_offs);
out:
	c->ltab = NULL;
	kfree(lsave);
	vfree(ltab);
	vfree(buf);
	kfree(nnode);
	kfree(pnode);
	return err;
}

/**
 * update_cats - add LEB properties of a pnode to LEB category lists and heaps.
 * @c: UBIFS file-system description object
 * @pnode: pnode
 *
 * When a pnode is loaded into memory, the LEB properties it contains are added,
 * by this function, to the LEB category lists and heaps.
 */
static void update_cats(struct ubifs_info *c, struct ubifs_pnode *pnode)
{
	int i;

	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		int cat = pnode->lprops[i].flags & LPROPS_CAT_MASK;
		int lnum = pnode->lprops[i].lnum;

		if (!lnum)
			return;
		ubifs_add_to_cat(c, &pnode->lprops[i], cat);
	}
}

/**
 * replace_cats - add LEB properties of a pnode to LEB category lists and heaps.
 * @c: UBIFS file-system description object
 * @old_pnode: pnode copied
 * @new_pnode: pnode copy
 *
 * During commit it is sometimes necessary to copy a pnode
 * (see dirty_cow_pnode).  When that happens, references in
 * category lists and heaps must be replaced.  This function does that.
 */
static void replace_cats(struct ubifs_info *c, struct ubifs_pnode *old_pnode,
			 struct ubifs_pnode *new_pnode)
{
	int i;

	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		if (!new_pnode->lprops[i].lnum)
			return;
		ubifs_replace_cat(c, &old_pnode->lprops[i],
				  &new_pnode->lprops[i]);
	}
}

/**
 * check_lpt_crc - check LPT node crc is correct.
 * @c: UBIFS file-system description object
 * @buf: buffer containing node
 * @len: length of node
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int check_lpt_crc(void *buf, int len)
{
	int pos = 0;
	uint8_t *addr = buf;
	uint16_t crc, calc_crc;

	crc = ubifs_unpack_bits(&addr, &pos, UBIFS_LPT_CRC_BITS);
	calc_crc = crc16(-1, buf + UBIFS_LPT_CRC_BYTES,
			 len - UBIFS_LPT_CRC_BYTES);
	if (crc != calc_crc) {
		ubifs_err("invalid crc in LPT node: crc %hx calc %hx", crc,
			  calc_crc);
		dump_stack();
		return -EINVAL;
	}
	return 0;
}

/**
 * check_lpt_type - check LPT node type is correct.
 * @c: UBIFS file-system description object
 * @addr: address of type bit field is passed and returned updated here
 * @pos: position of type bit field is passed and returned updated here
 * @type: expected type
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int check_lpt_type(uint8_t **addr, int *pos, int type)
{
	int node_type;

	node_type = ubifs_unpack_bits(addr, pos, UBIFS_LPT_TYPE_BITS);
	if (node_type != type) {
		ubifs_err("invalid type (%d) in LPT node type %d", node_type,
			  type);
		dump_stack();
		return -EINVAL;
	}
	return 0;
}

/**
 * unpack_pnode - unpack a pnode.
 * @c: UBIFS file-system description object
 * @buf: buffer containing packed pnode to unpack
 * @pnode: pnode structure to fill
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int unpack_pnode(const struct ubifs_info *c, void *buf,
			struct ubifs_pnode *pnode)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int i, pos = 0, err;

	err = check_lpt_type(&addr, &pos, UBIFS_LPT_PNODE);
	if (err)
		return err;
	if (c->big_lpt)
		pnode->num = ubifs_unpack_bits(&addr, &pos, c->pcnt_bits);
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		struct ubifs_lprops * const lprops = &pnode->lprops[i];

		lprops->free = ubifs_unpack_bits(&addr, &pos, c->space_bits);
		lprops->free <<= 3;
		lprops->dirty = ubifs_unpack_bits(&addr, &pos, c->space_bits);
		lprops->dirty <<= 3;

		if (ubifs_unpack_bits(&addr, &pos, 1))
			lprops->flags = LPROPS_INDEX;
		else
			lprops->flags = 0;
		lprops->flags |= ubifs_categorize_lprops(c, lprops);
	}
	err = check_lpt_crc(buf, c->pnode_sz);
	return err;
}

/**
 * ubifs_unpack_nnode - unpack a nnode.
 * @c: UBIFS file-system description object
 * @buf: buffer containing packed nnode to unpack
 * @nnode: nnode structure to fill
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_unpack_nnode(const struct ubifs_info *c, void *buf,
		       struct ubifs_nnode *nnode)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int i, pos = 0, err;

	err = check_lpt_type(&addr, &pos, UBIFS_LPT_NNODE);
	if (err)
		return err;
	if (c->big_lpt)
		nnode->num = ubifs_unpack_bits(&addr, &pos, c->pcnt_bits);
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		int lnum;

		lnum = ubifs_unpack_bits(&addr, &pos, c->lpt_lnum_bits) +
		       c->lpt_first;
		if (lnum == c->lpt_last + 1)
			lnum = 0;
		nnode->nbranch[i].lnum = lnum;
		nnode->nbranch[i].offs = ubifs_unpack_bits(&addr, &pos,
						     c->lpt_offs_bits);
	}
	err = check_lpt_crc(buf, c->nnode_sz);
	return err;
}

/**
 * unpack_ltab - unpack the LPT's own lprops table.
 * @c: UBIFS file-system description object
 * @buf: buffer from which to unpack
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int unpack_ltab(const struct ubifs_info *c, void *buf)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int i, pos = 0, err;

	err = check_lpt_type(&addr, &pos, UBIFS_LPT_LTAB);
	if (err)
		return err;
	for (i = 0; i < c->lpt_lebs; i++) {
		int free = ubifs_unpack_bits(&addr, &pos, c->lpt_spc_bits);
		int dirty = ubifs_unpack_bits(&addr, &pos, c->lpt_spc_bits);

		if (free < 0 || free > c->leb_size || dirty < 0 ||
		    dirty > c->leb_size || free + dirty > c->leb_size)
			return -EINVAL;

		c->ltab[i].free = free;
		c->ltab[i].dirty = dirty;
		c->ltab[i].tgc = 0;
		c->ltab[i].cmt = 0;
	}
	err = check_lpt_crc(buf, c->ltab_sz);
	return err;
}

/**
 * unpack_lsave - unpack the LPT's save table.
 * @c: UBIFS file-system description object
 * @buf: buffer from which to unpack
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int unpack_lsave(const struct ubifs_info *c, void *buf)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int i, pos = 0, err;

	err = check_lpt_type(&addr, &pos, UBIFS_LPT_LSAVE);
	if (err)
		return err;
	for (i = 0; i < c->lsave_cnt; i++) {
		int lnum = ubifs_unpack_bits(&addr, &pos, c->lnum_bits);

		if (lnum < c->main_first || lnum >= c->leb_cnt)
			return -EINVAL;
		c->lsave[i] = lnum;
	}
	err = check_lpt_crc(buf, c->lsave_sz);
	return err;
}

/**
 * validate_nnode - validate a nnode.
 * @c: UBIFS file-system description object
 * @nnode: nnode to validate
 * @parent: parent nnode (or NULL for the root nnode)
 * @iip: index in parent
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int validate_nnode(const struct ubifs_info *c, struct ubifs_nnode *nnode,
			  struct ubifs_nnode *parent, int iip)
{
	int i, lvl, max_offs;

	if (c->big_lpt) {
		int num = calc_nnode_num_from_parent(c, parent, iip);

		if (nnode->num != num)
			return -EINVAL;
	}
	lvl = parent ? parent->level - 1 : c->lpt_hght;
	if (lvl < 1)
		return -EINVAL;
	if (lvl == 1)
		max_offs = c->leb_size - c->pnode_sz;
	else
		max_offs = c->leb_size - c->nnode_sz;
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		int lnum = nnode->nbranch[i].lnum;
		int offs = nnode->nbranch[i].offs;

		if (lnum == 0) {
			if (offs != 0)
				return -EINVAL;
			continue;
		}
		if (lnum < c->lpt_first || lnum > c->lpt_last)
			return -EINVAL;
		if (offs < 0 || offs > max_offs)
			return -EINVAL;
	}
	return 0;
}

/**
 * validate_pnode - validate a pnode.
 * @c: UBIFS file-system description object
 * @pnode: pnode to validate
 * @parent: parent nnode
 * @iip: index in parent
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int validate_pnode(const struct ubifs_info *c, struct ubifs_pnode *pnode,
			  struct ubifs_nnode *parent, int iip)
{
	int i;

	if (c->big_lpt) {
		int num = calc_pnode_num_from_parent(c, parent, iip);

		if (pnode->num != num)
			return -EINVAL;
	}
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		int free = pnode->lprops[i].free;
		int dirty = pnode->lprops[i].dirty;

		if (free < 0 || free > c->leb_size || free % c->min_io_size ||
		    (free & 7))
			return -EINVAL;
		if (dirty < 0 || dirty > c->leb_size || (dirty & 7))
			return -EINVAL;
		if (dirty + free > c->leb_size)
			return -EINVAL;
	}
	return 0;
}

/**
 * set_pnode_lnum - set LEB numbers on a pnode.
 * @c: UBIFS file-system description object
 * @pnode: pnode to update
 *
 * This function calculates the LEB numbers for the LEB properties it contains
 * based on the pnode number.
 */
static void set_pnode_lnum(const struct ubifs_info *c,
			   struct ubifs_pnode *pnode)
{
	int i, lnum;

	lnum = (pnode->num << UBIFS_LPT_FANOUT_SHIFT) + c->main_first;
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		if (lnum >= c->leb_cnt)
			return;
		pnode->lprops[i].lnum = lnum++;
	}
}

/**
 * ubifs_read_nnode - read a nnode from flash and link it to the tree in memory.
 * @c: UBIFS file-system description object
 * @parent: parent nnode (or NULL for the root)
 * @iip: index in parent
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_read_nnode(struct ubifs_info *c, struct ubifs_nnode *parent, int iip)
{
	struct ubifs_nbranch *branch = NULL;
	struct ubifs_nnode *nnode = NULL;
	void *buf = c->lpt_nod_buf;
	int err, lnum, offs;

	if (parent) {
		branch = &parent->nbranch[iip];
		lnum = branch->lnum;
		offs = branch->offs;
	} else {
		lnum = c->lpt_lnum;
		offs = c->lpt_offs;
	}
	nnode = kzalloc(sizeof(struct ubifs_nnode), GFP_NOFS);
	if (!nnode) {
		err = -ENOMEM;
		goto out;
	}
	if (lnum == 0) {
		/*
		 * This nnode was not written which just means that the LEB
		 * properties in the subtree below it describe empty LEBs. We
		 * make the nnode as though we had read it, which in fact means
		 * doing almost nothing.
		 */
		if (c->big_lpt)
			nnode->num = calc_nnode_num_from_parent(c, parent, iip);
	} else {
		err = ubifs_leb_read(c, lnum, buf, offs, c->nnode_sz, 1);
		if (err)
			goto out;
		err = ubifs_unpack_nnode(c, buf, nnode);
		if (err)
			goto out;
	}
	err = validate_nnode(c, nnode, parent, iip);
	if (err)
		goto out;
	if (!c->big_lpt)
		nnode->num = calc_nnode_num_from_parent(c, parent, iip);
	if (parent) {
		branch->nnode = nnode;
		nnode->level = parent->level - 1;
	} else {
		c->nroot = nnode;
		nnode->level = c->lpt_hght;
	}
	nnode->parent = parent;
	nnode->iip = iip;
	return 0;

out:
	ubifs_err("error %d reading nnode at %d:%d", err, lnum, offs);
	dump_stack();
	kfree(nnode);
	return err;
}

/**
 * read_pnode - read a pnode from flash and link it to the tree in memory.
 * @c: UBIFS file-system description object
 * @parent: parent nnode
 * @iip: index in parent
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int read_pnode(struct ubifs_info *c, struct ubifs_nnode *parent, int iip)
{
	struct ubifs_nbranch *branch;
	struct ubifs_pnode *pnode = NULL;
	void *buf = c->lpt_nod_buf;
	int err, lnum, offs;

	branch = &parent->nbranch[iip];
	lnum = branch->lnum;
	offs = branch->offs;
	pnode = kzalloc(sizeof(struct ubifs_pnode), GFP_NOFS);
	if (!pnode)
		return -ENOMEM;

	if (lnum == 0) {
		/*
		 * This pnode was not written which just means that the LEB
		 * properties in it describe empty LEBs. We make the pnode as
		 * though we had read it.
		 */
		int i;

		if (c->big_lpt)
			pnode->num = calc_pnode_num_from_parent(c, parent, iip);
		for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
			struct ubifs_lprops * const lprops = &pnode->lprops[i];

			lprops->free = c->leb_size;
			lprops->flags = ubifs_categorize_lprops(c, lprops);
		}
	} else {
		err = ubifs_leb_read(c, lnum, buf, offs, c->pnode_sz, 1);
		if (err)
			goto out;
		err = unpack_pnode(c, buf, pnode);
		if (err)
			goto out;
	}
	err = validate_pnode(c, pnode, parent, iip);
	if (err)
		goto out;
	if (!c->big_lpt)
		pnode->num = calc_pnode_num_from_parent(c, parent, iip);
	branch->pnode = pnode;
	pnode->parent = parent;
	pnode->iip = iip;
	set_pnode_lnum(c, pnode);
	c->pnodes_have += 1;
	return 0;

out:
	ubifs_err("error %d reading pnode at %d:%d", err, lnum, offs);
	ubifs_dump_pnode(c, pnode, parent, iip);
	dump_stack();
	ubifs_err("calc num: %d", calc_pnode_num_from_parent(c, parent, iip));
	kfree(pnode);
	return err;
}

/**
 * read_ltab - read LPT's own lprops table.
 * @c: UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int read_ltab(struct ubifs_info *c)
{
	int err;
	void *buf;

	buf = vmalloc(c->ltab_sz);
	if (!buf)
		return -ENOMEM;
	err = ubifs_leb_read(c, c->ltab_lnum, buf, c->ltab_offs, c->ltab_sz, 1);
	if (err)
		goto out;
	err = unpack_ltab(c, buf);
out:
	vfree(buf);
	return err;
}

/**
 * read_lsave - read LPT's save table.
 * @c: UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int read_lsave(struct ubifs_info *c)
{
	int err, i;
	void *buf;

	buf = vmalloc(c->lsave_sz);
	if (!buf)
		return -ENOMEM;
	err = ubifs_leb_read(c, c->lsave_lnum, buf, c->lsave_offs,
			     c->lsave_sz, 1);
	if (err)
		goto out;
	err = unpack_lsave(c, buf);
	if (err)
		goto out;
	for (i = 0; i < c->lsave_cnt; i++) {
		int lnum = c->lsave[i];
		struct ubifs_lprops *lprops;

		/*
		 * Due to automatic resizing, the values in the lsave table
		 * could be beyond the volume size - just ignore them.
		 */
		if (lnum >= c->leb_cnt)
			continue;
		lprops = ubifs_lpt_lookup(c, lnum);
		if (IS_ERR(lprops)) {
			err = PTR_ERR(lprops);
			goto out;
		}
	}
out:
	vfree(buf);
	return err;
}

/**
 * ubifs_get_nnode - get a nnode.
 * @c: UBIFS file-system description object
 * @parent: parent nnode (or NULL for the root)
 * @iip: index in parent
 *
 * This function returns a pointer to the nnode on success or a negative error
 * code on failure.
 */
struct ubifs_nnode *ubifs_get_nnode(struct ubifs_info *c,
				    struct ubifs_nnode *parent, int iip)
{
	struct ubifs_nbranch *branch;
	struct ubifs_nnode *nnode;
	int err;

	branch = &parent->nbranch[iip];
	nnode = branch->nnode;
	if (nnode)
		return nnode;
	err = ubifs_read_nnode(c, parent, iip);
	if (err)
		return ERR_PTR(err);
	return branch->nnode;
}

/**
 * ubifs_get_pnode - get a pnode.
 * @c: UBIFS file-system description object
 * @parent: parent nnode
 * @iip: index in parent
 *
 * This function returns a pointer to the pnode on success or a negative error
 * code on failure.
 */
struct ubifs_pnode *ubifs_get_pnode(struct ubifs_info *c,
				    struct ubifs_nnode *parent, int iip)
{
	struct ubifs_nbranch *branch;
	struct ubifs_pnode *pnode;
	int err;

	branch = &parent->nbranch[iip];
	pnode = branch->pnode;
	if (pnode)
		return pnode;
	err = read_pnode(c, parent, iip);
	if (err)
		return ERR_PTR(err);
	update_cats(c, branch->pnode);
	return branch->pnode;
}

/**
 * ubifs_lpt_lookup - lookup LEB properties in the LPT.
 * @c: UBIFS file-system description object
 * @lnum: LEB number to lookup
 *
 * This function returns a pointer to the LEB properties on success or a
 * negative error code on failure.
 */
struct ubifs_lprops *ubifs_lpt_lookup(struct ubifs_info *c, int lnum)
{
	int err, i, h, iip, shft;
	struct ubifs_nnode *nnode;
	struct ubifs_pnode *pnode;

	if (!c->nroot) {
		err = ubifs_read_nnode(c, NULL, 0);
		if (err)
			return ERR_PTR(err);
	}
	nnode = c->nroot;
	i = lnum - c->main_first;
	shft = c->lpt_hght * UBIFS_LPT_FANOUT_SHIFT;
	for (h = 1; h < c->lpt_hght; h++) {
		iip = ((i >> shft) & (UBIFS_LPT_FANOUT - 1));
		shft -= UBIFS_LPT_FANOUT_SHIFT;
		nnode = ubifs_get_nnode(c, nnode, iip);
		if (IS_ERR(nnode))
			return ERR_CAST(nnode);
	}
	iip = ((i >> shft) & (UBIFS_LPT_FANOUT - 1));
	pnode = ubifs_get_pnode(c, nnode, iip);
	if (IS_ERR(pnode))
		return ERR_CAST(pnode);
	iip = (i & (UBIFS_LPT_FANOUT - 1));
	dbg_lp("LEB %d, free %d, dirty %d, flags %d", lnum,
	       pnode->lprops[iip].free, pnode->lprops[iip].dirty,
	       pnode->lprops[iip].flags);
	return &pnode->lprops[iip];
}

/**
 * dirty_cow_nnode - ensure a nnode is not being committed.
 * @c: UBIFS file-system description object
 * @nnode: nnode to check
 *
 * Returns dirtied nnode on success or negative error code on failure.
 */
static struct ubifs_nnode *dirty_cow_nnode(struct ubifs_info *c,
					   struct ubifs_nnode *nnode)
{
	struct ubifs_nnode *n;
	int i;

	if (!test_bit(COW_CNODE, &nnode->flags)) {
		/* nnode is not being committed */
		if (!test_and_set_bit(DIRTY_CNODE, &nnode->flags)) {
			c->dirty_nn_cnt += 1;
			ubifs_add_nnode_dirt(c, nnode);
		}
		return nnode;
	}

	/* nnode is being committed, so copy it */
	n = kmalloc(sizeof(struct ubifs_nnode), GFP_NOFS);
	if (unlikely(!n))
		return ERR_PTR(-ENOMEM);

	memcpy(n, nnode, sizeof(struct ubifs_nnode));
	n->cnext = NULL;
	__set_bit(DIRTY_CNODE, &n->flags);
	__clear_bit(COW_CNODE, &n->flags);

	/* The children now have new parent */
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		struct ubifs_nbranch *branch = &n->nbranch[i];

		if (branch->cnode)
			branch->cnode->parent = n;
	}

	ubifs_assert(!test_bit(OBSOLETE_CNODE, &nnode->flags));
	__set_bit(OBSOLETE_CNODE, &nnode->flags);

	c->dirty_nn_cnt += 1;
	ubifs_add_nnode_dirt(c, nnode);
	if (nnode->parent)
		nnode->parent->nbranch[n->iip].nnode = n;
	else
		c->nroot = n;
	return n;
}

/**
 * dirty_cow_pnode - ensure a pnode is not being committed.
 * @c: UBIFS file-system description object
 * @pnode: pnode to check
 *
 * Returns dirtied pnode on success or negative error code on failure.
 */
static struct ubifs_pnode *dirty_cow_pnode(struct ubifs_info *c,
					   struct ubifs_pnode *pnode)
{
	struct ubifs_pnode *p;

	if (!test_bit(COW_CNODE, &pnode->flags)) {
		/* pnode is not being committed */
		if (!test_and_set_bit(DIRTY_CNODE, &pnode->flags)) {
			c->dirty_pn_cnt += 1;
			add_pnode_dirt_lpt_c(c, pnode);
		}
		return pnode;
	}

	/* pnode is being committed, so copy it */
	p = kmalloc(sizeof(struct ubifs_pnode), GFP_NOFS);
	if (unlikely(!p))
		return ERR_PTR(-ENOMEM);

	memcpy(p, pnode, sizeof(struct ubifs_pnode));
	p->cnext = NULL;
	__set_bit(DIRTY_CNODE, &p->flags);
	__clear_bit(COW_CNODE, &p->flags);
	replace_cats(c, pnode, p);

	ubifs_assert(!test_bit(OBSOLETE_CNODE, &pnode->flags));
	__set_bit(OBSOLETE_CNODE, &pnode->flags);

	c->dirty_pn_cnt += 1;
	add_pnode_dirt_lpt_c(c, pnode);
	pnode->parent->nbranch[p->iip].pnode = p;
	return p;
}

/**
 * ubifs_lpt_lookup_dirty - lookup LEB properties in the LPT.
 * @c: UBIFS file-system description object
 * @lnum: LEB number to lookup
 *
 * This function returns a pointer to the LEB properties on success or a
 * negative error code on failure.
 */
struct ubifs_lprops *ubifs_lpt_lookup_dirty(struct ubifs_info *c, int lnum)
{
	int err, i, h, iip, shft;
	struct ubifs_nnode *nnode;
	struct ubifs_pnode *pnode;

	if (!c->nroot) {
		err = ubifs_read_nnode(c, NULL, 0);
		if (err)
			return ERR_PTR(err);
	}
	nnode = c->nroot;
	nnode = dirty_cow_nnode(c, nnode);
	if (IS_ERR(nnode))
		return ERR_CAST(nnode);
	i = lnum - c->main_first;
	shft = c->lpt_hght * UBIFS_LPT_FANOUT_SHIFT;
	for (h = 1; h < c->lpt_hght; h++) {
		iip = ((i >> shft) & (UBIFS_LPT_FANOUT - 1));
		shft -= UBIFS_LPT_FANOUT_SHIFT;
		nnode = ubifs_get_nnode(c, nnode, iip);
		if (IS_ERR(nnode))
			return ERR_CAST(nnode);
		nnode = dirty_cow_nnode(c, nnode);
		if (IS_ERR(nnode))
			return ERR_CAST(nnode);
	}
	iip = ((i >> shft) & (UBIFS_LPT_FANOUT - 1));
	pnode = ubifs_get_pnode(c, nnode, iip);
	if (IS_ERR(pnode))
		return ERR_CAST(pnode);
	pnode = dirty_cow_pnode(c, pnode);
	if (IS_ERR(pnode))
		return ERR_CAST(pnode);
	iip = (i & (UBIFS_LPT_FANOUT - 1));
	dbg_lp("LEB %d, free %d, dirty %d, flags %d", lnum,
	       pnode->lprops[iip].free, pnode->lprops[iip].dirty,
	       pnode->lprops[iip].flags);
	ubifs_assert(test_bit(DIRTY_CNODE, &pnode->flags));
	return &pnode->lprops[iip];
}

/**
 * lpt_init_rd - initialize the LPT for reading.
 * @c: UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int lpt_init_rd(struct ubifs_info *c)
{
	int err, i;

	c->ltab = vmalloc(sizeof(struct ubifs_lpt_lprops) * c->lpt_lebs);
	if (!c->ltab)
		return -ENOMEM;

	i = max_t(int, c->nnode_sz, c->pnode_sz);
	c->lpt_nod_buf = kmalloc(i, GFP_KERNEL);
	if (!c->lpt_nod_buf)
		return -ENOMEM;

	for (i = 0; i < LPROPS_HEAP_CNT; i++) {
		c->lpt_heap[i].arr = kmalloc(sizeof(void *) * LPT_HEAP_SZ,
					     GFP_KERNEL);
		if (!c->lpt_heap[i].arr)
			return -ENOMEM;
		c->lpt_heap[i].cnt = 0;
		c->lpt_heap[i].max_cnt = LPT_HEAP_SZ;
	}

	c->dirty_idx.arr = kmalloc(sizeof(void *) * LPT_HEAP_SZ, GFP_KERNEL);
	if (!c->dirty_idx.arr)
		return -ENOMEM;
	c->dirty_idx.cnt = 0;
	c->dirty_idx.max_cnt = LPT_HEAP_SZ;

	err = read_ltab(c);
	if (err)
		return err;

	dbg_lp("space_bits %d", c->space_bits);
	dbg_lp("lpt_lnum_bits %d", c->lpt_lnum_bits);
	dbg_lp("lpt_offs_bits %d", c->lpt_offs_bits);
	dbg_lp("lpt_spc_bits %d", c->lpt_spc_bits);
	dbg_lp("pcnt_bits %d", c->pcnt_bits);
	dbg_lp("lnum_bits %d", c->lnum_bits);
	dbg_lp("pnode_sz %d", c->pnode_sz);
	dbg_lp("nnode_sz %d", c->nnode_sz);
	dbg_lp("ltab_sz %d", c->ltab_sz);
	dbg_lp("lsave_sz %d", c->lsave_sz);
	dbg_lp("lsave_cnt %d", c->lsave_cnt);
	dbg_lp("lpt_hght %d", c->lpt_hght);
	dbg_lp("big_lpt %d", c->big_lpt);
	dbg_lp("LPT root is at %d:%d", c->lpt_lnum, c->lpt_offs);
	dbg_lp("LPT head is at %d:%d", c->nhead_lnum, c->nhead_offs);
	dbg_lp("LPT ltab is at %d:%d", c->ltab_lnum, c->ltab_offs);
	if (c->big_lpt)
		dbg_lp("LPT lsave is at %d:%d", c->lsave_lnum, c->lsave_offs);

	return 0;
}

/**
 * lpt_init_wr - initialize the LPT for writing.
 * @c: UBIFS file-system description object
 *
 * 'lpt_init_rd()' must have been called already.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int lpt_init_wr(struct ubifs_info *c)
{
	int err, i;

	c->ltab_cmt = vmalloc(sizeof(struct ubifs_lpt_lprops) * c->lpt_lebs);
	if (!c->ltab_cmt)
		return -ENOMEM;

	c->lpt_buf = vmalloc(c->leb_size);
	if (!c->lpt_buf)
		return -ENOMEM;

	if (c->big_lpt) {
		c->lsave = kmalloc(sizeof(int) * c->lsave_cnt, GFP_NOFS);
		if (!c->lsave)
			return -ENOMEM;
		err = read_lsave(c);
		if (err)
			return err;
	}

	for (i = 0; i < c->lpt_lebs; i++)
		if (c->ltab[i].free == c->leb_size) {
			err = ubifs_leb_unmap(c, i + c->lpt_first);
			if (err)
				return err;
		}

	return 0;
}

/**
 * ubifs_lpt_init - initialize the LPT.
 * @c: UBIFS file-system description object
 * @rd: whether to initialize lpt for reading
 * @wr: whether to initialize lpt for writing
 *
 * For mounting 'rw', @rd and @wr are both true. For mounting 'ro', @rd is true
 * and @wr is false. For mounting from 'ro' to 'rw', @rd is false and @wr is
 * true.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_lpt_init(struct ubifs_info *c, int rd, int wr)
{
	int err;

	if (rd) {
		err = lpt_init_rd(c);
		if (err)
			goto out_err;
	}

	if (wr) {
		err = lpt_init_wr(c);
		if (err)
			goto out_err;
	}

	return 0;

out_err:
	if (wr)
		ubifs_lpt_free(c, 1);
	if (rd)
		ubifs_lpt_free(c, 0);
	return err;
}

/**
 * struct lpt_scan_node - somewhere to put nodes while we scan LPT.
 * @nnode: where to keep a nnode
 * @pnode: where to keep a pnode
 * @cnode: where to keep a cnode
 * @in_tree: is the node in the tree in memory
 * @ptr.nnode: pointer to the nnode (if it is an nnode) which may be here or in
 * the tree
 * @ptr.pnode: ditto for pnode
 * @ptr.cnode: ditto for cnode
 */
struct lpt_scan_node {
	union {
		struct ubifs_nnode nnode;
		struct ubifs_pnode pnode;
		struct ubifs_cnode cnode;
	};
	int in_tree;
	union {
		struct ubifs_nnode *nnode;
		struct ubifs_pnode *pnode;
		struct ubifs_cnode *cnode;
	} ptr;
};

/**
 * scan_get_nnode - for the scan, get a nnode from either the tree or flash.
 * @c: the UBIFS file-system description object
 * @path: where to put the nnode
 * @parent: parent of the nnode
 * @iip: index in parent of the nnode
 *
 * This function returns a pointer to the nnode on success or a negative error
 * code on failure.
 */
static struct ubifs_nnode *scan_get_nnode(struct ubifs_info *c,
					  struct lpt_scan_node *path,
					  struct ubifs_nnode *parent, int iip)
{
	struct ubifs_nbranch *branch;
	struct ubifs_nnode *nnode;
	void *buf = c->lpt_nod_buf;
	int err;

	branch = &parent->nbranch[iip];
	nnode = branch->nnode;
	if (nnode) {
		path->in_tree = 1;
		path->ptr.nnode = nnode;
		return nnode;
	}
	nnode = &path->nnode;
	path->in_tree = 0;
	path->ptr.nnode = nnode;
	memset(nnode, 0, sizeof(struct ubifs_nnode));
	if (branch->lnum == 0) {
		/*
		 * This nnode was not written which just means that the LEB
		 * properties in the subtree below it describe empty LEBs. We
		 * make the nnode as though we had read it, which in fact means
		 * doing almost nothing.
		 */
		if (c->big_lpt)
			nnode->num = calc_nnode_num_from_parent(c, parent, iip);
	} else {
		err = ubifs_leb_read(c, branch->lnum, buf, branch->offs,
				     c->nnode_sz, 1);
		if (err)
			return ERR_PTR(err);
		err = ubifs_unpack_nnode(c, buf, nnode);
		if (err)
			return ERR_PTR(err);
	}
	err = validate_nnode(c, nnode, parent, iip);
	if (err)
		return ERR_PTR(err);
	if (!c->big_lpt)
		nnode->num = calc_nnode_num_from_parent(c, parent, iip);
	nnode->level = parent->level - 1;
	nnode->parent = parent;
	nnode->iip = iip;
	return nnode;
}

/**
 * scan_get_pnode - for the scan, get a pnode from either the tree or flash.
 * @c: the UBIFS file-system description object
 * @path: where to put the pnode
 * @parent: parent of the pnode
 * @iip: index in parent of the pnode
 *
 * This function returns a pointer to the pnode on success or a negative error
 * code on failure.
 */
static struct ubifs_pnode *scan_get_pnode(struct ubifs_info *c,
					  struct lpt_scan_node *path,
					  struct ubifs_nnode *parent, int iip)
{
	struct ubifs_nbranch *branch;
	struct ubifs_pnode *pnode;
	void *buf = c->lpt_nod_buf;
	int err;

	branch = &parent->nbranch[iip];
	pnode = branch->pnode;
	if (pnode) {
		path->in_tree = 1;
		path->ptr.pnode = pnode;
		return pnode;
	}
	pnode = &path->pnode;
	path->in_tree = 0;
	path->ptr.pnode = pnode;
	memset(pnode, 0, sizeof(struct ubifs_pnode));
	if (branch->lnum == 0) {
		/*
		 * This pnode was not written which just means that the LEB
		 * properties in it describe empty LEBs. We make the pnode as
		 * though we had read it.
		 */
		int i;

		if (c->big_lpt)
			pnode->num = calc_pnode_num_from_parent(c, parent, iip);
		for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
			struct ubifs_lprops * const lprops = &pnode->lprops[i];

			lprops->free = c->leb_size;
			lprops->flags = ubifs_categorize_lprops(c, lprops);
		}
	} else {
		ubifs_assert(branch->lnum >= c->lpt_first &&
			     branch->lnum <= c->lpt_last);
		ubifs_assert(branch->offs >= 0 && branch->offs < c->leb_size);
		err = ubifs_leb_read(c, branch->lnum, buf, branch->offs,
				     c->pnode_sz, 1);
		if (err)
			return ERR_PTR(err);
		err = unpack_pnode(c, buf, pnode);
		if (err)
			return ERR_PTR(err);
	}
	err = validate_pnode(c, pnode, parent, iip);
	if (err)
		return ERR_PTR(err);
	if (!c->big_lpt)
		pnode->num = calc_pnode_num_from_parent(c, parent, iip);
	pnode->parent = parent;
	pnode->iip = iip;
	set_pnode_lnum(c, pnode);
	return pnode;
}

/**
 * ubifs_lpt_scan_nolock - scan the LPT.
 * @c: the UBIFS file-system description object
 * @start_lnum: LEB number from which to start scanning
 * @end_lnum: LEB number at which to stop scanning
 * @scan_cb: callback function called for each lprops
 * @data: data to be passed to the callback function
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_lpt_scan_nolock(struct ubifs_info *c, int start_lnum, int end_lnum,
			  ubifs_lpt_scan_callback scan_cb, void *data)
{
	int err = 0, i, h, iip, shft;
	struct ubifs_nnode *nnode;
	struct ubifs_pnode *pnode;
	struct lpt_scan_node *path;

	if (start_lnum == -1) {
		start_lnum = end_lnum + 1;
		if (start_lnum >= c->leb_cnt)
			start_lnum = c->main_first;
	}

	ubifs_assert(start_lnum >= c->main_first && start_lnum < c->leb_cnt);
	ubifs_assert(end_lnum >= c->main_first && end_lnum < c->leb_cnt);

	if (!c->nroot) {
		err = ubifs_read_nnode(c, NULL, 0);
		if (err)
			return err;
	}

	path = kmalloc(sizeof(struct lpt_scan_node) * (c->lpt_hght + 1),
		       GFP_NOFS);
	if (!path)
		return -ENOMEM;

	path[0].ptr.nnode = c->nroot;
	path[0].in_tree = 1;
again:
	/* Descend to the pnode containing start_lnum */
	nnode = c->nroot;
	i = start_lnum - c->main_first;
	shft = c->lpt_hght * UBIFS_LPT_FANOUT_SHIFT;
	for (h = 1; h < c->lpt_hght; h++) {
		iip = ((i >> shft) & (UBIFS_LPT_FANOUT - 1));
		shft -= UBIFS_LPT_FANOUT_SHIFT;
		nnode = scan_get_nnode(c, path + h, nnode, iip);
		if (IS_ERR(nnode)) {
			err = PTR_ERR(nnode);
			goto out;
		}
	}
	iip = ((i >> shft) & (UBIFS_LPT_FANOUT - 1));
	pnode = scan_get_pnode(c, path + h, nnode, iip);
	if (IS_ERR(pnode)) {
		err = PTR_ERR(pnode);
		goto out;
	}
	iip = (i & (UBIFS_LPT_FANOUT - 1));

	/* Loop for each lprops */
	while (1) {
		struct ubifs_lprops *lprops = &pnode->lprops[iip];
		int ret, lnum = lprops->lnum;

		ret = scan_cb(c, lprops, path[h].in_tree, data);
		if (ret < 0) {
			err = ret;
			goto out;
		}
		if (ret & LPT_SCAN_ADD) {
			/* Add all the nodes in path to the tree in memory */
			for (h = 1; h < c->lpt_hght; h++) {
				const size_t sz = sizeof(struct ubifs_nnode);
				struct ubifs_nnode *parent;

				if (path[h].in_tree)
					continue;
				nnode = kmemdup(&path[h].nnode, sz, GFP_NOFS);
				if (!nnode) {
					err = -ENOMEM;
					goto out;
				}
				parent = nnode->parent;
				parent->nbranch[nnode->iip].nnode = nnode;
				path[h].ptr.nnode = nnode;
				path[h].in_tree = 1;
				path[h + 1].cnode.parent = nnode;
			}
			if (path[h].in_tree)
				ubifs_ensure_cat(c, lprops);
			else {
				const size_t sz = sizeof(struct ubifs_pnode);
				struct ubifs_nnode *parent;

				pnode = kmemdup(&path[h].pnode, sz, GFP_NOFS);
				if (!pnode) {
					err = -ENOMEM;
					goto out;
				}
				parent = pnode->parent;
				parent->nbranch[pnode->iip].pnode = pnode;
				path[h].ptr.pnode = pnode;
				path[h].in_tree = 1;
				update_cats(c, pnode);
				c->pnodes_have += 1;
			}
			err = dbg_check_lpt_nodes(c, (struct ubifs_cnode *)
						  c->nroot, 0, 0);
			if (err)
				goto out;
			err = dbg_check_cats(c);
			if (err)
				goto out;
		}
		if (ret & LPT_SCAN_STOP) {
			err = 0;
			break;
		}
		/* Get the next lprops */
		if (lnum == end_lnum) {
			/*
			 * We got to the end without finding what we were
			 * looking for
			 */
			err = -ENOSPC;
			goto out;
		}
		if (lnum + 1 >= c->leb_cnt) {
			/* Wrap-around to the beginning */
			start_lnum = c->main_first;
			goto again;
		}
		if (iip + 1 < UBIFS_LPT_FANOUT) {
			/* Next lprops is in the same pnode */
			iip += 1;
			continue;
		}
		/* We need to get the next pnode. Go up until we can go right */
		iip = pnode->iip;
		while (1) {
			h -= 1;
			ubifs_assert(h >= 0);
			nnode = path[h].ptr.nnode;
			if (iip + 1 < UBIFS_LPT_FANOUT)
				break;
			iip = nnode->iip;
		}
		/* Go right */
		iip += 1;
		/* Descend to the pnode */
		h += 1;
		for (; h < c->lpt_hght; h++) {
			nnode = scan_get_nnode(c, path + h, nnode, iip);
			if (IS_ERR(nnode)) {
				err = PTR_ERR(nnode);
				goto out;
			}
			iip = 0;
		}
		pnode = scan_get_pnode(c, path + h, nnode, iip);
		if (IS_ERR(pnode)) {
			err = PTR_ERR(pnode);
			goto out;
		}
		iip = 0;
	}
out:
	kfree(path);
	return err;
}

/**
 * dbg_chk_pnode - check a pnode.
 * @c: the UBIFS file-system description object
 * @pnode: pnode to check
 * @col: pnode column
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int dbg_chk_pnode(struct ubifs_info *c, struct ubifs_pnode *pnode,
			 int col)
{
	int i;

	if (pnode->num != col) {
		ubifs_err("pnode num %d expected %d parent num %d iip %d",
			  pnode->num, col, pnode->parent->num, pnode->iip);
		return -EINVAL;
	}
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		struct ubifs_lprops *lp, *lprops = &pnode->lprops[i];
		int lnum = (pnode->num << UBIFS_LPT_FANOUT_SHIFT) + i +
			   c->main_first;
		int found, cat = lprops->flags & LPROPS_CAT_MASK;
		struct ubifs_lpt_heap *heap;
		struct list_head *list = NULL;

		if (lnum >= c->leb_cnt)
			continue;
		if (lprops->lnum != lnum) {
			ubifs_err("bad LEB number %d expected %d",
				  lprops->lnum, lnum);
			return -EINVAL;
		}
		if (lprops->flags & LPROPS_TAKEN) {
			if (cat != LPROPS_UNCAT) {
				ubifs_err("LEB %d taken but not uncat %d",
					  lprops->lnum, cat);
				return -EINVAL;
			}
			continue;
		}
		if (lprops->flags & LPROPS_INDEX) {
			switch (cat) {
			case LPROPS_UNCAT:
			case LPROPS_DIRTY_IDX:
			case LPROPS_FRDI_IDX:
				break;
			default:
				ubifs_err("LEB %d index but cat %d",
					  lprops->lnum, cat);
				return -EINVAL;
			}
		} else {
			switch (cat) {
			case LPROPS_UNCAT:
			case LPROPS_DIRTY:
			case LPROPS_FREE:
			case LPROPS_EMPTY:
			case LPROPS_FREEABLE:
				break;
			default:
				ubifs_err("LEB %d not index but cat %d",
					  lprops->lnum, cat);
				return -EINVAL;
			}
		}
		switch (cat) {
		case LPROPS_UNCAT:
			list = &c->uncat_list;
			break;
		case LPROPS_EMPTY:
			list = &c->empty_list;
			break;
		case LPROPS_FREEABLE:
			list = &c->freeable_list;
			break;
		case LPROPS_FRDI_IDX:
			list = &c->frdi_idx_list;
			break;
		}
		found = 0;
		switch (cat) {
		case LPROPS_DIRTY:
		case LPROPS_DIRTY_IDX:
		case LPROPS_FREE:
			heap = &c->lpt_heap[cat - 1];
			if (lprops->hpos < heap->cnt &&
			    heap->arr[lprops->hpos] == lprops)
				found = 1;
			break;
		case LPROPS_UNCAT:
		case LPROPS_EMPTY:
		case LPROPS_FREEABLE:
		case LPROPS_FRDI_IDX:
			list_for_each_entry(lp, list, list)
				if (lprops == lp) {
					found = 1;
					break;
				}
			break;
		}
		if (!found) {
			ubifs_err("LEB %d cat %d not found in cat heap/list",
				  lprops->lnum, cat);
			return -EINVAL;
		}
		switch (cat) {
		case LPROPS_EMPTY:
			if (lprops->free != c->leb_size) {
				ubifs_err("LEB %d cat %d free %d dirty %d",
					  lprops->lnum, cat, lprops->free,
					  lprops->dirty);
				return -EINVAL;
			}
			break;
		case LPROPS_FREEABLE:
		case LPROPS_FRDI_IDX:
			if (lprops->free + lprops->dirty != c->leb_size) {
				ubifs_err("LEB %d cat %d free %d dirty %d",
					  lprops->lnum, cat, lprops->free,
					  lprops->dirty);
				return -EINVAL;
			}
			break;
		}
	}
	return 0;
}

/**
 * dbg_check_lpt_nodes - check nnodes and pnodes.
 * @c: the UBIFS file-system description object
 * @cnode: next cnode (nnode or pnode) to check
 * @row: row of cnode (root is zero)
 * @col: column of cnode (leftmost is zero)
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int dbg_check_lpt_nodes(struct ubifs_info *c, struct ubifs_cnode *cnode,
			int row, int col)
{
	struct ubifs_nnode *nnode, *nn;
	struct ubifs_cnode *cn;
	int num, iip = 0, err;

	if (!dbg_is_chk_lprops(c))
		return 0;

	while (cnode) {
		ubifs_assert(row >= 0);
		nnode = cnode->parent;
		if (cnode->level) {
			/* cnode is a nnode */
			num = calc_nnode_num(row, col);
			if (cnode->num != num) {
				ubifs_err("nnode num %d expected %d parent num %d iip %d",
					  cnode->num, num,
					  (nnode ? nnode->num : 0), cnode->iip);
				return -EINVAL;
			}
			nn = (struct ubifs_nnode *)cnode;
			while (iip < UBIFS_LPT_FANOUT) {
				cn = nn->nbranch[iip].cnode;
				if (cn) {
					/* Go down */
					row += 1;
					col <<= UBIFS_LPT_FANOUT_SHIFT;
					col += iip;
					iip = 0;
					cnode = cn;
					break;
				}
				/* Go right */
				iip += 1;
			}
			if (iip < UBIFS_LPT_FANOUT)
				continue;
		} else {
			struct ubifs_pnode *pnode;

			/* cnode is a pnode */
			pnode = (struct ubifs_pnode *)cnode;
			err = dbg_chk_pnode(c, pnode, col);
			if (err)
				return err;
		}
		/* Go up and to the right */
		row -= 1;
		col >>= UBIFS_LPT_FANOUT_SHIFT;
		iip = cnode->iip + 1;
		cnode = (struct ubifs_cnode *)nnode;
	}
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/lpt.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements the functions that access LEB properties and their
 * categories. LEBs are categorized based on the needs of UBIFS, and the
 * categories are stored as either heaps or lists to provide a fast way of
 * finding a LEB in a particular category. For example, UBIFS may need to find
 * an empty LEB for the journal, or a very dirty LEB for garbage collection.
 */

// #include "ubifs.h"

/**
 * get_heap_comp_val - get the LEB properties value for heap comparisons.
 * @lprops: LEB properties
 * @cat: LEB category
 */
static int get_heap_comp_val(struct ubifs_lprops *lprops, int cat)
{
	switch (cat) {
	case LPROPS_FREE:
		return lprops->free;
	case LPROPS_DIRTY_IDX:
		return lprops->free + lprops->dirty;
	default:
		return lprops->dirty;
	}
}

/**
 * move_up_lpt_heap - move a new heap entry up as far as possible.
 * @c: UBIFS file-system description object
 * @heap: LEB category heap
 * @lprops: LEB properties to move
 * @cat: LEB category
 *
 * New entries to a heap are added at the bottom and then moved up until the
 * parent's value is greater.  In the case of LPT's category heaps, the value
 * is either the amount of free space or the amount of dirty space, depending
 * on the category.
 */
static void move_up_lpt_heap(struct ubifs_info *c, struct ubifs_lpt_heap *heap,
			     struct ubifs_lprops *lprops, int cat)
{
	int val1, val2, hpos;

	hpos = lprops->hpos;
	if (!hpos)
		return; /* Already top of the heap */
	val1 = get_heap_comp_val(lprops, cat);
	/* Compare to parent and, if greater, move up the heap */
	do {
		int ppos = (hpos - 1) / 2;

		val2 = get_heap_comp_val(heap->arr[ppos], cat);
		if (val2 >= val1)
			return;
		/* Greater than parent so move up */
		heap->arr[ppos]->hpos = hpos;
		heap->arr[hpos] = heap->arr[ppos];
		heap->arr[ppos] = lprops;
		lprops->hpos = ppos;
		hpos = ppos;
	} while (hpos);
}

/**
 * adjust_lpt_heap - move a changed heap entry up or down the heap.
 * @c: UBIFS file-system description object
 * @heap: LEB category heap
 * @lprops: LEB properties to move
 * @hpos: heap position of @lprops
 * @cat: LEB category
 *
 * Changed entries in a heap are moved up or down until the parent's value is
 * greater.  In the case of LPT's category heaps, the value is either the amount
 * of free space or the amount of dirty space, depending on the category.
 */
static void adjust_lpt_heap(struct ubifs_info *c, struct ubifs_lpt_heap *heap,
			    struct ubifs_lprops *lprops, int hpos, int cat)
{
	int val1, val2, val3, cpos;

	val1 = get_heap_comp_val(lprops, cat);
	/* Compare to parent and, if greater than parent, move up the heap */
	if (hpos) {
		int ppos = (hpos - 1) / 2;

		val2 = get_heap_comp_val(heap->arr[ppos], cat);
		if (val1 > val2) {
			/* Greater than parent so move up */
			while (1) {
				heap->arr[ppos]->hpos = hpos;
				heap->arr[hpos] = heap->arr[ppos];
				heap->arr[ppos] = lprops;
				lprops->hpos = ppos;
				hpos = ppos;
				if (!hpos)
					return;
				ppos = (hpos - 1) / 2;
				val2 = get_heap_comp_val(heap->arr[ppos], cat);
				if (val1 <= val2)
					return;
				/* Still greater than parent so keep going */
			}
		}
	}

	/* Not greater than parent, so compare to children */
	while (1) {
		/* Compare to left child */
		cpos = hpos * 2 + 1;
		if (cpos >= heap->cnt)
			return;
		val2 = get_heap_comp_val(heap->arr[cpos], cat);
		if (val1 < val2) {
			/* Less than left child, so promote biggest child */
			if (cpos + 1 < heap->cnt) {
				val3 = get_heap_comp_val(heap->arr[cpos + 1],
							 cat);
				if (val3 > val2)
					cpos += 1; /* Right child is bigger */
			}
			heap->arr[cpos]->hpos = hpos;
			heap->arr[hpos] = heap->arr[cpos];
			heap->arr[cpos] = lprops;
			lprops->hpos = cpos;
			hpos = cpos;
			continue;
		}
		/* Compare to right child */
		cpos += 1;
		if (cpos >= heap->cnt)
			return;
		val3 = get_heap_comp_val(heap->arr[cpos], cat);
		if (val1 < val3) {
			/* Less than right child, so promote right child */
			heap->arr[cpos]->hpos = hpos;
			heap->arr[hpos] = heap->arr[cpos];
			heap->arr[cpos] = lprops;
			lprops->hpos = cpos;
			hpos = cpos;
			continue;
		}
		return;
	}
}

/**
 * add_to_lpt_heap - add LEB properties to a LEB category heap.
 * @c: UBIFS file-system description object
 * @lprops: LEB properties to add
 * @cat: LEB category
 *
 * This function returns %1 if @lprops is added to the heap for LEB category
 * @cat, otherwise %0 is returned because the heap is full.
 */
static int add_to_lpt_heap(struct ubifs_info *c, struct ubifs_lprops *lprops,
			   int cat)
{
	struct ubifs_lpt_heap *heap = &c->lpt_heap[cat - 1];

	if (heap->cnt >= heap->max_cnt) {
		const int b = LPT_HEAP_SZ / 2 - 1;
		int cpos, val1, val2;

		/* Compare to some other LEB on the bottom of heap */
		/* Pick a position kind of randomly */
		cpos = (((size_t)lprops >> 4) & b) + b;
		ubifs_assert(cpos >= b);
		ubifs_assert(cpos < LPT_HEAP_SZ);
		ubifs_assert(cpos < heap->cnt);

		val1 = get_heap_comp_val(lprops, cat);
		val2 = get_heap_comp_val(heap->arr[cpos], cat);
		if (val1 > val2) {
			struct ubifs_lprops *lp;

			lp = heap->arr[cpos];
			lp->flags &= ~LPROPS_CAT_MASK;
			lp->flags |= LPROPS_UNCAT;
			list_add(&lp->list, &c->uncat_list);
			lprops->hpos = cpos;
			heap->arr[cpos] = lprops;
			move_up_lpt_heap(c, heap, lprops, cat);
			dbg_check_heap(c, heap, cat, lprops->hpos);
			return 1; /* Added to heap */
		}
		dbg_check_heap(c, heap, cat, -1);
		return 0; /* Not added to heap */
	} else {
		lprops->hpos = heap->cnt++;
		heap->arr[lprops->hpos] = lprops;
		move_up_lpt_heap(c, heap, lprops, cat);
		dbg_check_heap(c, heap, cat, lprops->hpos);
		return 1; /* Added to heap */
	}
}

/**
 * remove_from_lpt_heap - remove LEB properties from a LEB category heap.
 * @c: UBIFS file-system description object
 * @lprops: LEB properties to remove
 * @cat: LEB category
 */
static void remove_from_lpt_heap(struct ubifs_info *c,
				 struct ubifs_lprops *lprops, int cat)
{
	struct ubifs_lpt_heap *heap;
	int hpos = lprops->hpos;

	heap = &c->lpt_heap[cat - 1];
	ubifs_assert(hpos >= 0 && hpos < heap->cnt);
	ubifs_assert(heap->arr[hpos] == lprops);
	heap->cnt -= 1;
	if (hpos < heap->cnt) {
		heap->arr[hpos] = heap->arr[heap->cnt];
		heap->arr[hpos]->hpos = hpos;
		adjust_lpt_heap(c, heap, heap->arr[hpos], hpos, cat);
	}
	dbg_check_heap(c, heap, cat, -1);
}

/**
 * lpt_heap_replace - replace lprops in a category heap.
 * @c: UBIFS file-system description object
 * @old_lprops: LEB properties to replace
 * @new_lprops: LEB properties with which to replace
 * @cat: LEB category
 *
 * During commit it is sometimes necessary to copy a pnode (see dirty_cow_pnode)
 * and the lprops that the pnode contains.  When that happens, references in
 * the category heaps to those lprops must be updated to point to the new
 * lprops.  This function does that.
 */
static void lpt_heap_replace(struct ubifs_info *c,
			     struct ubifs_lprops *old_lprops,
			     struct ubifs_lprops *new_lprops, int cat)
{
	struct ubifs_lpt_heap *heap;
	int hpos = new_lprops->hpos;

	heap = &c->lpt_heap[cat - 1];
	heap->arr[hpos] = new_lprops;
}

/**
 * ubifs_add_to_cat - add LEB properties to a category list or heap.
 * @c: UBIFS file-system description object
 * @lprops: LEB properties to add
 * @cat: LEB category to which to add
 *
 * LEB properties are categorized to enable fast find operations.
 */
void ubifs_add_to_cat(struct ubifs_info *c, struct ubifs_lprops *lprops,
		      int cat)
{
	switch (cat) {
	case LPROPS_DIRTY:
	case LPROPS_DIRTY_IDX:
	case LPROPS_FREE:
		if (add_to_lpt_heap(c, lprops, cat))
			break;
		/* No more room on heap so make it un-categorized */
		cat = LPROPS_UNCAT;
		/* Fall through */
	case LPROPS_UNCAT:
		list_add(&lprops->list, &c->uncat_list);
		break;
	case LPROPS_EMPTY:
		list_add(&lprops->list, &c->empty_list);
		break;
	case LPROPS_FREEABLE:
		list_add(&lprops->list, &c->freeable_list);
		c->freeable_cnt += 1;
		break;
	case LPROPS_FRDI_IDX:
		list_add(&lprops->list, &c->frdi_idx_list);
		break;
	default:
		ubifs_assert(0);
	}

	lprops->flags &= ~LPROPS_CAT_MASK;
	lprops->flags |= cat;
	c->in_a_category_cnt += 1;
	ubifs_assert(c->in_a_category_cnt <= c->main_lebs);
}

/**
 * ubifs_remove_from_cat - remove LEB properties from a category list or heap.
 * @c: UBIFS file-system description object
 * @lprops: LEB properties to remove
 * @cat: LEB category from which to remove
 *
 * LEB properties are categorized to enable fast find operations.
 */
static void ubifs_remove_from_cat(struct ubifs_info *c,
				  struct ubifs_lprops *lprops, int cat)
{
	switch (cat) {
	case LPROPS_DIRTY:
	case LPROPS_DIRTY_IDX:
	case LPROPS_FREE:
		remove_from_lpt_heap(c, lprops, cat);
		break;
	case LPROPS_FREEABLE:
		c->freeable_cnt -= 1;
		ubifs_assert(c->freeable_cnt >= 0);
		/* Fall through */
	case LPROPS_UNCAT:
	case LPROPS_EMPTY:
	case LPROPS_FRDI_IDX:
		ubifs_assert(!list_empty(&lprops->list));
		list_del(&lprops->list);
		break;
	default:
		ubifs_assert(0);
	}

	c->in_a_category_cnt -= 1;
	ubifs_assert(c->in_a_category_cnt >= 0);
}

/**
 * ubifs_replace_cat - replace lprops in a category list or heap.
 * @c: UBIFS file-system description object
 * @old_lprops: LEB properties to replace
 * @new_lprops: LEB properties with which to replace
 *
 * During commit it is sometimes necessary to copy a pnode (see dirty_cow_pnode)
 * and the lprops that the pnode contains. When that happens, references in
 * category lists and heaps must be replaced. This function does that.
 */
void ubifs_replace_cat(struct ubifs_info *c, struct ubifs_lprops *old_lprops,
		       struct ubifs_lprops *new_lprops)
{
	int cat;

	cat = new_lprops->flags & LPROPS_CAT_MASK;
	switch (cat) {
	case LPROPS_DIRTY:
	case LPROPS_DIRTY_IDX:
	case LPROPS_FREE:
		lpt_heap_replace(c, old_lprops, new_lprops, cat);
		break;
	case LPROPS_UNCAT:
	case LPROPS_EMPTY:
	case LPROPS_FREEABLE:
	case LPROPS_FRDI_IDX:
		list_replace(&old_lprops->list, &new_lprops->list);
		break;
	default:
		ubifs_assert(0);
	}
}

/**
 * ubifs_ensure_cat - ensure LEB properties are categorized.
 * @c: UBIFS file-system description object
 * @lprops: LEB properties
 *
 * A LEB may have fallen off of the bottom of a heap, and ended up as
 * un-categorized even though it has enough space for us now. If that is the
 * case this function will put the LEB back onto a heap.
 */
void ubifs_ensure_cat(struct ubifs_info *c, struct ubifs_lprops *lprops)
{
	int cat = lprops->flags & LPROPS_CAT_MASK;

	if (cat != LPROPS_UNCAT)
		return;
	cat = ubifs_categorize_lprops(c, lprops);
	if (cat == LPROPS_UNCAT)
		return;
	ubifs_remove_from_cat(c, lprops, LPROPS_UNCAT);
	ubifs_add_to_cat(c, lprops, cat);
}

/**
 * ubifs_categorize_lprops - categorize LEB properties.
 * @c: UBIFS file-system description object
 * @lprops: LEB properties to categorize
 *
 * LEB properties are categorized to enable fast find operations. This function
 * returns the LEB category to which the LEB properties belong. Note however
 * that if the LEB category is stored as a heap and the heap is full, the
 * LEB properties may have their category changed to %LPROPS_UNCAT.
 */
int ubifs_categorize_lprops(const struct ubifs_info *c,
			    const struct ubifs_lprops *lprops)
{
	if (lprops->flags & LPROPS_TAKEN)
		return LPROPS_UNCAT;

	if (lprops->free == c->leb_size) {
		ubifs_assert(!(lprops->flags & LPROPS_INDEX));
		return LPROPS_EMPTY;
	}

	if (lprops->free + lprops->dirty == c->leb_size) {
		if (lprops->flags & LPROPS_INDEX)
			return LPROPS_FRDI_IDX;
		else
			return LPROPS_FREEABLE;
	}

	if (lprops->flags & LPROPS_INDEX) {
		if (lprops->dirty + lprops->free >= c->min_idx_node_sz)
			return LPROPS_DIRTY_IDX;
	} else {
		if (lprops->dirty >= c->dead_wm &&
		    lprops->dirty > lprops->free)
			return LPROPS_DIRTY;
		if (lprops->free > 0)
			return LPROPS_FREE;
	}

	return LPROPS_UNCAT;
}

/**
 * change_category - change LEB properties category.
 * @c: UBIFS file-system description object
 * @lprops: LEB properties to re-categorize
 *
 * LEB properties are categorized to enable fast find operations. When the LEB
 * properties change they must be re-categorized.
 */
static void change_category(struct ubifs_info *c, struct ubifs_lprops *lprops)
{
	int old_cat = lprops->flags & LPROPS_CAT_MASK;
	int new_cat = ubifs_categorize_lprops(c, lprops);

	if (old_cat == new_cat) {
		struct ubifs_lpt_heap *heap;

		/* lprops on a heap now must be moved up or down */
		if (new_cat < 1 || new_cat > LPROPS_HEAP_CNT)
			return; /* Not on a heap */
		heap = &c->lpt_heap[new_cat - 1];
		adjust_lpt_heap(c, heap, lprops, lprops->hpos, new_cat);
	} else {
		ubifs_remove_from_cat(c, lprops, old_cat);
		ubifs_add_to_cat(c, lprops, new_cat);
	}
}

/**
 * ubifs_calc_dark - calculate LEB dark space size.
 * @c: the UBIFS file-system description object
 * @spc: amount of free and dirty space in the LEB
 *
 * This function calculates and returns amount of dark space in an LEB which
 * has @spc bytes of free and dirty space.
 *
 * UBIFS is trying to account the space which might not be usable, and this
 * space is called "dark space". For example, if an LEB has only %512 free
 * bytes, it is dark space, because it cannot fit a large data node.
 */
int ubifs_calc_dark(const struct ubifs_info *c, int spc)
{
	ubifs_assert(!(spc & 7));

	if (spc < c->dark_wm)
		return spc;

	/*
	 * If we have slightly more space then the dark space watermark, we can
	 * anyway safely assume it we'll be able to write a node of the
	 * smallest size there.
	 */
	if (spc - c->dark_wm < MIN_WRITE_SZ)
		return spc - MIN_WRITE_SZ;

	return c->dark_wm;
}

/**
 * is_lprops_dirty - determine if LEB properties are dirty.
 * @c: the UBIFS file-system description object
 * @lprops: LEB properties to test
 */
static int is_lprops_dirty(struct ubifs_info *c, struct ubifs_lprops *lprops)
{
	struct ubifs_pnode *pnode;
	int pos;

	pos = (lprops->lnum - c->main_first) & (UBIFS_LPT_FANOUT - 1);
	pnode = (struct ubifs_pnode *)container_of(lprops - pos,
						   struct ubifs_pnode,
						   lprops[0]);
	return !test_bit(COW_CNODE, &pnode->flags) &&
	       test_bit(DIRTY_CNODE, &pnode->flags);
}

/**
 * ubifs_change_lp - change LEB properties.
 * @c: the UBIFS file-system description object
 * @lp: LEB properties to change
 * @free: new free space amount
 * @dirty: new dirty space amount
 * @flags: new flags
 * @idx_gc_cnt: change to the count of @idx_gc list
 *
 * This function changes LEB properties (@free, @dirty or @flag). However, the
 * property which has the %LPROPS_NC value is not changed. Returns a pointer to
 * the updated LEB properties on success and a negative error code on failure.
 *
 * Note, the LEB properties may have had to be copied (due to COW) and
 * consequently the pointer returned may not be the same as the pointer
 * passed.
 */
const struct ubifs_lprops *ubifs_change_lp(struct ubifs_info *c,
					   const struct ubifs_lprops *lp,
					   int free, int dirty, int flags,
					   int idx_gc_cnt)
{
	/*
	 * This is the only function that is allowed to change lprops, so we
	 * discard the "const" qualifier.
	 */
	struct ubifs_lprops *lprops = (struct ubifs_lprops *)lp;

	dbg_lp("LEB %d, free %d, dirty %d, flags %d",
	       lprops->lnum, free, dirty, flags);

	ubifs_assert(mutex_is_locked(&c->lp_mutex));
	ubifs_assert(c->lst.empty_lebs >= 0 &&
		     c->lst.empty_lebs <= c->main_lebs);
	ubifs_assert(c->freeable_cnt >= 0);
	ubifs_assert(c->freeable_cnt <= c->main_lebs);
	ubifs_assert(c->lst.taken_empty_lebs >= 0);
	ubifs_assert(c->lst.taken_empty_lebs <= c->lst.empty_lebs);
	ubifs_assert(!(c->lst.total_free & 7) && !(c->lst.total_dirty & 7));
	ubifs_assert(!(c->lst.total_dead & 7) && !(c->lst.total_dark & 7));
	ubifs_assert(!(c->lst.total_used & 7));
	ubifs_assert(free == LPROPS_NC || free >= 0);
	ubifs_assert(dirty == LPROPS_NC || dirty >= 0);

	if (!is_lprops_dirty(c, lprops)) {
		lprops = ubifs_lpt_lookup_dirty(c, lprops->lnum);
		if (IS_ERR(lprops))
			return lprops;
	} else
		ubifs_assert(lprops == ubifs_lpt_lookup_dirty(c, lprops->lnum));

	ubifs_assert(!(lprops->free & 7) && !(lprops->dirty & 7));

	spin_lock(&c->space_lock);
	if ((lprops->flags & LPROPS_TAKEN) && lprops->free == c->leb_size)
		c->lst.taken_empty_lebs -= 1;

	if (!(lprops->flags & LPROPS_INDEX)) {
		int old_spc;

		old_spc = lprops->free + lprops->dirty;
		if (old_spc < c->dead_wm)
			c->lst.total_dead -= old_spc;
		else
			c->lst.total_dark -= ubifs_calc_dark(c, old_spc);

		c->lst.total_used -= c->leb_size - old_spc;
	}

	if (free != LPROPS_NC) {
		free = ALIGN(free, 8);
		c->lst.total_free += free - lprops->free;

		/* Increase or decrease empty LEBs counter if needed */
		if (free == c->leb_size) {
			if (lprops->free != c->leb_size)
				c->lst.empty_lebs += 1;
		} else if (lprops->free == c->leb_size)
			c->lst.empty_lebs -= 1;
		lprops->free = free;
	}

	if (dirty != LPROPS_NC) {
		dirty = ALIGN(dirty, 8);
		c->lst.total_dirty += dirty - lprops->dirty;
		lprops->dirty = dirty;
	}

	if (flags != LPROPS_NC) {
		/* Take care about indexing LEBs counter if needed */
		if ((lprops->flags & LPROPS_INDEX)) {
			if (!(flags & LPROPS_INDEX))
				c->lst.idx_lebs -= 1;
		} else if (flags & LPROPS_INDEX)
			c->lst.idx_lebs += 1;
		lprops->flags = flags;
	}

	if (!(lprops->flags & LPROPS_INDEX)) {
		int new_spc;

		new_spc = lprops->free + lprops->dirty;
		if (new_spc < c->dead_wm)
			c->lst.total_dead += new_spc;
		else
			c->lst.total_dark += ubifs_calc_dark(c, new_spc);

		c->lst.total_used += c->leb_size - new_spc;
	}

	if ((lprops->flags & LPROPS_TAKEN) && lprops->free == c->leb_size)
		c->lst.taken_empty_lebs += 1;

	change_category(c, lprops);
	c->idx_gc_cnt += idx_gc_cnt;
	spin_unlock(&c->space_lock);
	return lprops;
}

/**
 * ubifs_get_lp_stats - get lprops statistics.
 * @c: UBIFS file-system description object
 * @st: return statistics
 */
void ubifs_get_lp_stats(struct ubifs_info *c, struct ubifs_lp_stats *lst)
{
	spin_lock(&c->space_lock);
	memcpy(lst, &c->lst, sizeof(struct ubifs_lp_stats));
	spin_unlock(&c->space_lock);
}

/**
 * ubifs_change_one_lp - change LEB properties.
 * @c: the UBIFS file-system description object
 * @lnum: LEB to change properties for
 * @free: amount of free space
 * @dirty: amount of dirty space
 * @flags_set: flags to set
 * @flags_clean: flags to clean
 * @idx_gc_cnt: change to the count of idx_gc list
 *
 * This function changes properties of LEB @lnum. It is a helper wrapper over
 * 'ubifs_change_lp()' which hides lprops get/release. The arguments are the
 * same as in case of 'ubifs_change_lp()'. Returns zero in case of success and
 * a negative error code in case of failure.
 */
int ubifs_change_one_lp(struct ubifs_info *c, int lnum, int free, int dirty,
			int flags_set, int flags_clean, int idx_gc_cnt)
{
	int err = 0, flags;
	const struct ubifs_lprops *lp;

	ubifs_get_lprops(c);

	lp = ubifs_lpt_lookup_dirty(c, lnum);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		goto out;
	}

	flags = (lp->flags | flags_set) & ~flags_clean;
	lp = ubifs_change_lp(c, lp, free, dirty, flags, idx_gc_cnt);
	if (IS_ERR(lp))
		err = PTR_ERR(lp);

out:
	ubifs_release_lprops(c);
	if (err)
		ubifs_err("cannot change properties of LEB %d, error %d",
			  lnum, err);
	return err;
}

/**
 * ubifs_update_one_lp - update LEB properties.
 * @c: the UBIFS file-system description object
 * @lnum: LEB to change properties for
 * @free: amount of free space
 * @dirty: amount of dirty space to add
 * @flags_set: flags to set
 * @flags_clean: flags to clean
 *
 * This function is the same as 'ubifs_change_one_lp()' but @dirty is added to
 * current dirty space, not substitutes it.
 */
int ubifs_update_one_lp(struct ubifs_info *c, int lnum, int free, int dirty,
			int flags_set, int flags_clean)
{
	int err = 0, flags;
	const struct ubifs_lprops *lp;

	ubifs_get_lprops(c);

	lp = ubifs_lpt_lookup_dirty(c, lnum);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		goto out;
	}

	flags = (lp->flags | flags_set) & ~flags_clean;
	lp = ubifs_change_lp(c, lp, free, lp->dirty + dirty, flags, 0);
	if (IS_ERR(lp))
		err = PTR_ERR(lp);

out:
	ubifs_release_lprops(c);
	if (err)
		ubifs_err("cannot update properties of LEB %d, error %d",
			  lnum, err);
	return err;
}

/**
 * ubifs_read_one_lp - read LEB properties.
 * @c: the UBIFS file-system description object
 * @lnum: LEB to read properties for
 * @lp: where to store read properties
 *
 * This helper function reads properties of a LEB @lnum and stores them in @lp.
 * Returns zero in case of success and a negative error code in case of
 * failure.
 */
int ubifs_read_one_lp(struct ubifs_info *c, int lnum, struct ubifs_lprops *lp)
{
	int err = 0;
	const struct ubifs_lprops *lpp;

	ubifs_get_lprops(c);

	lpp = ubifs_lpt_lookup(c, lnum);
	if (IS_ERR(lpp)) {
		err = PTR_ERR(lpp);
		ubifs_err("cannot read properties of LEB %d, error %d",
			  lnum, err);
		goto out;
	}

	memcpy(lp, lpp, sizeof(struct ubifs_lprops));

out:
	ubifs_release_lprops(c);
	return err;
}

/**
 * ubifs_fast_find_free - try to find a LEB with free space quickly.
 * @c: the UBIFS file-system description object
 *
 * This function returns LEB properties for a LEB with free space or %NULL if
 * the function is unable to find a LEB quickly.
 */
const struct ubifs_lprops *ubifs_fast_find_free(struct ubifs_info *c)
{
	struct ubifs_lprops *lprops;
	struct ubifs_lpt_heap *heap;

	ubifs_assert(mutex_is_locked(&c->lp_mutex));

	heap = &c->lpt_heap[LPROPS_FREE - 1];
	if (heap->cnt == 0)
		return NULL;

	lprops = heap->arr[0];
	ubifs_assert(!(lprops->flags & LPROPS_TAKEN));
	ubifs_assert(!(lprops->flags & LPROPS_INDEX));
	return lprops;
}

/**
 * ubifs_fast_find_empty - try to find an empty LEB quickly.
 * @c: the UBIFS file-system description object
 *
 * This function returns LEB properties for an empty LEB or %NULL if the
 * function is unable to find an empty LEB quickly.
 */
const struct ubifs_lprops *ubifs_fast_find_empty(struct ubifs_info *c)
{
	struct ubifs_lprops *lprops;

	ubifs_assert(mutex_is_locked(&c->lp_mutex));

	if (list_empty(&c->empty_list))
		return NULL;

	lprops = list_entry(c->empty_list.next, struct ubifs_lprops, list);
	ubifs_assert(!(lprops->flags & LPROPS_TAKEN));
	ubifs_assert(!(lprops->flags & LPROPS_INDEX));
	ubifs_assert(lprops->free == c->leb_size);
	return lprops;
}

/**
 * ubifs_fast_find_freeable - try to find a freeable LEB quickly.
 * @c: the UBIFS file-system description object
 *
 * This function returns LEB properties for a freeable LEB or %NULL if the
 * function is unable to find a freeable LEB quickly.
 */
const struct ubifs_lprops *ubifs_fast_find_freeable(struct ubifs_info *c)
{
	struct ubifs_lprops *lprops;

	ubifs_assert(mutex_is_locked(&c->lp_mutex));

	if (list_empty(&c->freeable_list))
		return NULL;

	lprops = list_entry(c->freeable_list.next, struct ubifs_lprops, list);
	ubifs_assert(!(lprops->flags & LPROPS_TAKEN));
	ubifs_assert(!(lprops->flags & LPROPS_INDEX));
	ubifs_assert(lprops->free + lprops->dirty == c->leb_size);
	ubifs_assert(c->freeable_cnt > 0);
	return lprops;
}

/**
 * ubifs_fast_find_frdi_idx - try to find a freeable index LEB quickly.
 * @c: the UBIFS file-system description object
 *
 * This function returns LEB properties for a freeable index LEB or %NULL if the
 * function is unable to find a freeable index LEB quickly.
 */
const struct ubifs_lprops *ubifs_fast_find_frdi_idx(struct ubifs_info *c)
{
	struct ubifs_lprops *lprops;

	ubifs_assert(mutex_is_locked(&c->lp_mutex));

	if (list_empty(&c->frdi_idx_list))
		return NULL;

	lprops = list_entry(c->frdi_idx_list.next, struct ubifs_lprops, list);
	ubifs_assert(!(lprops->flags & LPROPS_TAKEN));
	ubifs_assert((lprops->flags & LPROPS_INDEX));
	ubifs_assert(lprops->free + lprops->dirty == c->leb_size);
	return lprops;
}

/*
 * Everything below is related to debugging.
 */

/**
 * dbg_check_cats - check category heaps and lists.
 * @c: UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int dbg_check_cats(struct ubifs_info *c)
{
	struct ubifs_lprops *lprops;
	struct list_head *pos;
	int i, cat;

	if (!dbg_is_chk_gen(c) && !dbg_is_chk_lprops(c))
		return 0;

	list_for_each_entry(lprops, &c->empty_list, list) {
		if (lprops->free != c->leb_size) {
			ubifs_err("non-empty LEB %d on empty list (free %d dirty %d flags %d)",
				  lprops->lnum, lprops->free, lprops->dirty,
				  lprops->flags);
			return -EINVAL;
		}
		if (lprops->flags & LPROPS_TAKEN) {
			ubifs_err("taken LEB %d on empty list (free %d dirty %d flags %d)",
				  lprops->lnum, lprops->free, lprops->dirty,
				  lprops->flags);
			return -EINVAL;
		}
	}

	i = 0;
	list_for_each_entry(lprops, &c->freeable_list, list) {
		if (lprops->free + lprops->dirty != c->leb_size) {
			ubifs_err("non-freeable LEB %d on freeable list (free %d dirty %d flags %d)",
				  lprops->lnum, lprops->free, lprops->dirty,
				  lprops->flags);
			return -EINVAL;
		}
		if (lprops->flags & LPROPS_TAKEN) {
			ubifs_err("taken LEB %d on freeable list (free %d dirty %d flags %d)",
				  lprops->lnum, lprops->free, lprops->dirty,
				  lprops->flags);
			return -EINVAL;
		}
		i += 1;
	}
	if (i != c->freeable_cnt) {
		ubifs_err("freeable list count %d expected %d", i,
			  c->freeable_cnt);
		return -EINVAL;
	}

	i = 0;
	list_for_each(pos, &c->idx_gc)
		i += 1;
	if (i != c->idx_gc_cnt) {
		ubifs_err("idx_gc list count %d expected %d", i,
			  c->idx_gc_cnt);
		return -EINVAL;
	}

	list_for_each_entry(lprops, &c->frdi_idx_list, list) {
		if (lprops->free + lprops->dirty != c->leb_size) {
			ubifs_err("non-freeable LEB %d on frdi_idx list (free %d dirty %d flags %d)",
				  lprops->lnum, lprops->free, lprops->dirty,
				  lprops->flags);
			return -EINVAL;
		}
		if (lprops->flags & LPROPS_TAKEN) {
			ubifs_err("taken LEB %d on frdi_idx list (free %d dirty %d flags %d)",
				  lprops->lnum, lprops->free, lprops->dirty,
				  lprops->flags);
			return -EINVAL;
		}
		if (!(lprops->flags & LPROPS_INDEX)) {
			ubifs_err("non-index LEB %d on frdi_idx list (free %d dirty %d flags %d)",
				  lprops->lnum, lprops->free, lprops->dirty,
				  lprops->flags);
			return -EINVAL;
		}
	}

	for (cat = 1; cat <= LPROPS_HEAP_CNT; cat++) {
		struct ubifs_lpt_heap *heap = &c->lpt_heap[cat - 1];

		for (i = 0; i < heap->cnt; i++) {
			lprops = heap->arr[i];
			if (!lprops) {
				ubifs_err("null ptr in LPT heap cat %d", cat);
				return -EINVAL;
			}
			if (lprops->hpos != i) {
				ubifs_err("bad ptr in LPT heap cat %d", cat);
				return -EINVAL;
			}
			if (lprops->flags & LPROPS_TAKEN) {
				ubifs_err("taken LEB in LPT heap cat %d", cat);
				return -EINVAL;
			}
		}
	}

	return 0;
}

void dbg_check_heap(struct ubifs_info *c, struct ubifs_lpt_heap *heap, int cat,
		    int add_pos)
{
	int i = 0, j, err = 0;

	if (!dbg_is_chk_gen(c) && !dbg_is_chk_lprops(c))
		return;

	for (i = 0; i < heap->cnt; i++) {
		struct ubifs_lprops *lprops = heap->arr[i];
		struct ubifs_lprops *lp;

		if (i != add_pos)
			if ((lprops->flags & LPROPS_CAT_MASK) != cat) {
				err = 1;
				goto out;
			}
		if (lprops->hpos != i) {
			err = 2;
			goto out;
		}
		lp = ubifs_lpt_lookup(c, lprops->lnum);
		if (IS_ERR(lp)) {
			err = 3;
			goto out;
		}
		if (lprops != lp) {
			ubifs_err("lprops %zx lp %zx lprops->lnum %d lp->lnum %d",
				  (size_t)lprops, (size_t)lp, lprops->lnum,
				  lp->lnum);
			err = 4;
			goto out;
		}
		for (j = 0; j < i; j++) {
			lp = heap->arr[j];
			if (lp == lprops) {
				err = 5;
				goto out;
			}
			if (lp->lnum == lprops->lnum) {
				err = 6;
				goto out;
			}
		}
	}
out:
	if (err) {
		ubifs_err("failed cat %d hpos %d err %d", cat, i, err);
		dump_stack();
		ubifs_dump_heap(c, heap, cat);
	}
}

/**
 * scan_check_cb - scan callback.
 * @c: the UBIFS file-system description object
 * @lp: LEB properties to scan
 * @in_tree: whether the LEB properties are in main memory
 * @lst: lprops statistics to update
 *
 * This function returns a code that indicates whether the scan should continue
 * (%LPT_SCAN_CONTINUE), whether the LEB properties should be added to the tree
 * in main memory (%LPT_SCAN_ADD), or whether the scan should stop
 * (%LPT_SCAN_STOP).
 */
static int scan_check_cb(struct ubifs_info *c,
			 const struct ubifs_lprops *lp, int in_tree,
			 struct ubifs_lp_stats *lst)
{
	struct ubifs_scan_leb *sleb;
	struct ubifs_scan_node *snod;
	int cat, lnum = lp->lnum, is_idx = 0, used = 0, free, dirty, ret;
	void *buf = NULL;

	cat = lp->flags & LPROPS_CAT_MASK;
	if (cat != LPROPS_UNCAT) {
		cat = ubifs_categorize_lprops(c, lp);
		if (cat != (lp->flags & LPROPS_CAT_MASK)) {
			ubifs_err("bad LEB category %d expected %d",
				  (lp->flags & LPROPS_CAT_MASK), cat);
			return -EINVAL;
		}
	}

	/* Check lp is on its category list (if it has one) */
	if (in_tree) {
		struct list_head *list = NULL;

		switch (cat) {
		case LPROPS_EMPTY:
			list = &c->empty_list;
			break;
		case LPROPS_FREEABLE:
			list = &c->freeable_list;
			break;
		case LPROPS_FRDI_IDX:
			list = &c->frdi_idx_list;
			break;
		case LPROPS_UNCAT:
			list = &c->uncat_list;
			break;
		}
		if (list) {
			struct ubifs_lprops *lprops;
			int found = 0;

			list_for_each_entry(lprops, list, list) {
				if (lprops == lp) {
					found = 1;
					break;
				}
			}
			if (!found) {
				ubifs_err("bad LPT list (category %d)", cat);
				return -EINVAL;
			}
		}
	}

	/* Check lp is on its category heap (if it has one) */
	if (in_tree && cat > 0 && cat <= LPROPS_HEAP_CNT) {
		struct ubifs_lpt_heap *heap = &c->lpt_heap[cat - 1];

		if ((lp->hpos != -1 && heap->arr[lp->hpos]->lnum != lnum) ||
		    lp != heap->arr[lp->hpos]) {
			ubifs_err("bad LPT heap (category %d)", cat);
			return -EINVAL;
		}
	}

	buf = __vmalloc(c->leb_size, GFP_NOFS, PAGE_KERNEL);
	if (!buf)
		return -ENOMEM;

	/*
	 * After an unclean unmount, empty and freeable LEBs
	 * may contain garbage - do not scan them.
	 */
	if (lp->free == c->leb_size) {
		lst->empty_lebs += 1;
		lst->total_free += c->leb_size;
		lst->total_dark += ubifs_calc_dark(c, c->leb_size);
		return LPT_SCAN_CONTINUE;
	}
	if (lp->free + lp->dirty == c->leb_size &&
	    !(lp->flags & LPROPS_INDEX)) {
		lst->total_free  += lp->free;
		lst->total_dirty += lp->dirty;
		lst->total_dark  +=  ubifs_calc_dark(c, c->leb_size);
		return LPT_SCAN_CONTINUE;
	}

	sleb = ubifs_scan(c, lnum, 0, buf, 0);
	if (IS_ERR(sleb)) {
		ret = PTR_ERR(sleb);
		if (ret == -EUCLEAN) {
			ubifs_dump_lprops(c);
			ubifs_dump_budg(c, &c->bi);
		}
		goto out;
	}

	is_idx = -1;
	list_for_each_entry(snod, &sleb->nodes, list) {
		int found, level = 0;

		cond_resched();

		if (is_idx == -1)
			is_idx = (snod->type == UBIFS_IDX_NODE) ? 1 : 0;

		if (is_idx && snod->type != UBIFS_IDX_NODE) {
			ubifs_err("indexing node in data LEB %d:%d",
				  lnum, snod->offs);
			goto out_destroy;
		}

		if (snod->type == UBIFS_IDX_NODE) {
			struct ubifs_idx_node *idx = snod->node;

			key_read(c, ubifs_idx_key(c, idx), &snod->key);
			level = le16_to_cpu(idx->level);
		}

		found = ubifs_tnc_has_node(c, &snod->key, level, lnum,
					   snod->offs, is_idx);
		if (found) {
			if (found < 0)
				goto out_destroy;
			used += ALIGN(snod->len, 8);
		}
	}

	free = c->leb_size - sleb->endpt;
	dirty = sleb->endpt - used;

	if (free > c->leb_size || free < 0 || dirty > c->leb_size ||
	    dirty < 0) {
		ubifs_err("bad calculated accounting for LEB %d: free %d, dirty %d",
			  lnum, free, dirty);
		goto out_destroy;
	}

	if (lp->free + lp->dirty == c->leb_size &&
	    free + dirty == c->leb_size)
		if ((is_idx && !(lp->flags & LPROPS_INDEX)) ||
		    (!is_idx && free == c->leb_size) ||
		    lp->free == c->leb_size) {
			/*
			 * Empty or freeable LEBs could contain index
			 * nodes from an uncompleted commit due to an
			 * unclean unmount. Or they could be empty for
			 * the same reason. Or it may simply not have been
			 * unmapped.
			 */
			free = lp->free;
			dirty = lp->dirty;
			is_idx = 0;
		    }

	if (is_idx && lp->free + lp->dirty == free + dirty &&
	    lnum != c->ihead_lnum) {
		/*
		 * After an unclean unmount, an index LEB could have a different
		 * amount of free space than the value recorded by lprops. That
		 * is because the in-the-gaps method may use free space or
		 * create free space (as a side-effect of using ubi_leb_change
		 * and not writing the whole LEB). The incorrect free space
		 * value is not a problem because the index is only ever
		 * allocated empty LEBs, so there will never be an attempt to
		 * write to the free space at the end of an index LEB - except
		 * by the in-the-gaps method for which it is not a problem.
		 */
		free = lp->free;
		dirty = lp->dirty;
	}

	if (lp->free != free || lp->dirty != dirty)
		goto out_print;

	if (is_idx && !(lp->flags & LPROPS_INDEX)) {
		if (free == c->leb_size)
			/* Free but not unmapped LEB, it's fine */
			is_idx = 0;
		else {
			ubifs_err("indexing node without indexing flag");
			goto out_print;
		}
	}

	if (!is_idx && (lp->flags & LPROPS_INDEX)) {
		ubifs_err("data node with indexing flag");
		goto out_print;
	}

	if (free == c->leb_size)
		lst->empty_lebs += 1;

	if (is_idx)
		lst->idx_lebs += 1;

	if (!(lp->flags & LPROPS_INDEX))
		lst->total_used += c->leb_size - free - dirty;
	lst->total_free += free;
	lst->total_dirty += dirty;

	if (!(lp->flags & LPROPS_INDEX)) {
		int spc = free + dirty;

		if (spc < c->dead_wm)
			lst->total_dead += spc;
		else
			lst->total_dark += ubifs_calc_dark(c, spc);
	}

	ubifs_scan_destroy(sleb);
	vfree(buf);
	return LPT_SCAN_CONTINUE;

out_print:
	ubifs_err("bad accounting of LEB %d: free %d, dirty %d flags %#x, should be free %d, dirty %d",
		  lnum, lp->free, lp->dirty, lp->flags, free, dirty);
	ubifs_dump_leb(c, lnum);
out_destroy:
	ubifs_scan_destroy(sleb);
	ret = -EINVAL;
out:
	vfree(buf);
	return ret;
}

/**
 * dbg_check_lprops - check all LEB properties.
 * @c: UBIFS file-system description object
 *
 * This function checks all LEB properties and makes sure they are all correct.
 * It returns zero if everything is fine, %-EINVAL if there is an inconsistency
 * and other negative error codes in case of other errors. This function is
 * called while the file system is locked (because of commit start), so no
 * additional locking is required. Note that locking the LPT mutex would cause
 * a circular lock dependency with the TNC mutex.
 */
int dbg_check_lprops(struct ubifs_info *c)
{
	int i, err;
	struct ubifs_lp_stats lst;

	if (!dbg_is_chk_lprops(c))
		return 0;

	/*
	 * As we are going to scan the media, the write buffers have to be
	 * synchronized.
	 */
	for (i = 0; i < c->jhead_cnt; i++) {
		err = ubifs_wbuf_sync(&c->jheads[i].wbuf);
		if (err)
			return err;
	}

	memset(&lst, 0, sizeof(struct ubifs_lp_stats));
	err = ubifs_lpt_scan_nolock(c, c->main_first, c->leb_cnt - 1,
				    (ubifs_lpt_scan_callback)scan_check_cb,
				    &lst);
	if (err && err != -ENOSPC)
		goto out;

	if (lst.empty_lebs != c->lst.empty_lebs ||
	    lst.idx_lebs != c->lst.idx_lebs ||
	    lst.total_free != c->lst.total_free ||
	    lst.total_dirty != c->lst.total_dirty ||
	    lst.total_used != c->lst.total_used) {
		ubifs_err("bad overall accounting");
		ubifs_err("calculated: empty_lebs %d, idx_lebs %d, total_free %lld, total_dirty %lld, total_used %lld",
			  lst.empty_lebs, lst.idx_lebs, lst.total_free,
			  lst.total_dirty, lst.total_used);
		ubifs_err("read from lprops: empty_lebs %d, idx_lebs %d, total_free %lld, total_dirty %lld, total_used %lld",
			  c->lst.empty_lebs, c->lst.idx_lebs, c->lst.total_free,
			  c->lst.total_dirty, c->lst.total_used);
		err = -EINVAL;
		goto out;
	}

	if (lst.total_dead != c->lst.total_dead ||
	    lst.total_dark != c->lst.total_dark) {
		ubifs_err("bad dead/dark space accounting");
		ubifs_err("calculated: total_dead %lld, total_dark %lld",
			  lst.total_dead, lst.total_dark);
		ubifs_err("read from lprops: total_dead %lld, total_dark %lld",
			  c->lst.total_dead, c->lst.total_dark);
		err = -EINVAL;
		goto out;
	}

	err = dbg_check_cats(c);
out:
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/lprops.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements functions needed to recover from unclean un-mounts.
 * When UBIFS is mounted, it checks a flag on the master node to determine if
 * an un-mount was completed successfully. If not, the process of mounting
 * incorporates additional checking and fixing of on-flash data structures.
 * UBIFS always cleans away all remnants of an unclean un-mount, so that
 * errors do not accumulate. However UBIFS defers recovery if it is mounted
 * read-only, and the flash is not modified in that case.
 *
 * The general UBIFS approach to the recovery is that it recovers from
 * corruptions which could be caused by power cuts, but it refuses to recover
 * from corruption caused by other reasons. And UBIFS tries to distinguish
 * between these 2 reasons of corruptions and silently recover in the former
 * case and loudly complain in the latter case.
 *
 * UBIFS writes only to erased LEBs, so it writes only to the flash space
 * containing only 0xFFs. UBIFS also always writes strictly from the beginning
 * of the LEB to the end. And UBIFS assumes that the underlying flash media
 * writes in @c->max_write_size bytes at a time.
 *
 * Hence, if UBIFS finds a corrupted node at offset X, it expects only the min.
 * I/O unit corresponding to offset X to contain corrupted data, all the
 * following min. I/O units have to contain empty space (all 0xFFs). If this is
 * not true, the corruption cannot be the result of a power cut, and UBIFS
 * refuses to mount.
 */

// #include <linux/crc32.h>
// #include <linux/slab.h>
// #include "ubifs.h"

/**
 * is_empty - determine whether a buffer is empty (contains all 0xff).
 * @buf: buffer to clean
 * @len: length of buffer
 *
 * This function returns %1 if the buffer is empty (contains all 0xff) otherwise
 * %0 is returned.
 */
static int is_empty(void *buf, int len)
{
	uint8_t *p = buf;
	int i;

	for (i = 0; i < len; i++)
		if (*p++ != 0xff)
			return 0;
	return 1;
}

/**
 * first_non_ff - find offset of the first non-0xff byte.
 * @buf: buffer to search in
 * @len: length of buffer
 *
 * This function returns offset of the first non-0xff byte in @buf or %-1 if
 * the buffer contains only 0xff bytes.
 */
static int first_non_ff(void *buf, int len)
{
	uint8_t *p = buf;
	int i;

	for (i = 0; i < len; i++)
		if (*p++ != 0xff)
			return i;
	return -1;
}

/**
 * get_master_node - get the last valid master node allowing for corruption.
 * @c: UBIFS file-system description object
 * @lnum: LEB number
 * @pbuf: buffer containing the LEB read, is returned here
 * @mst: master node, if found, is returned here
 * @cor: corruption, if found, is returned here
 *
 * This function allocates a buffer, reads the LEB into it, and finds and
 * returns the last valid master node allowing for one area of corruption.
 * The corrupt area, if there is one, must be consistent with the assumption
 * that it is the result of an unclean unmount while the master node was being
 * written. Under those circumstances, it is valid to use the previously written
 * master node.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int get_master_node(const struct ubifs_info *c, int lnum, void **pbuf,
			   struct ubifs_mst_node **mst, void **cor)
{
	const int sz = c->mst_node_alsz;
	int err, offs, len;
	void *sbuf, *buf;

	sbuf = vmalloc(c->leb_size);
	if (!sbuf)
		return -ENOMEM;

	err = ubifs_leb_read(c, lnum, sbuf, 0, c->leb_size, 0);
	if (err && err != -EBADMSG)
		goto out_free;

	/* Find the first position that is definitely not a node */
	offs = 0;
	buf = sbuf;
	len = c->leb_size;
	while (offs + UBIFS_MST_NODE_SZ <= c->leb_size) {
		struct ubifs_ch *ch = buf;

		if (le32_to_cpu(ch->magic) != UBIFS_NODE_MAGIC)
			break;
		offs += sz;
		buf  += sz;
		len  -= sz;
	}
	/* See if there was a valid master node before that */
	if (offs) {
		int ret;

		offs -= sz;
		buf  -= sz;
		len  += sz;
		ret = ubifs_scan_a_node(c, buf, len, lnum, offs, 1);
		if (ret != SCANNED_A_NODE && offs) {
			/* Could have been corruption so check one place back */
			offs -= sz;
			buf  -= sz;
			len  += sz;
			ret = ubifs_scan_a_node(c, buf, len, lnum, offs, 1);
			if (ret != SCANNED_A_NODE)
				/*
				 * We accept only one area of corruption because
				 * we are assuming that it was caused while
				 * trying to write a master node.
				 */
				goto out_err;
		}
		if (ret == SCANNED_A_NODE) {
			struct ubifs_ch *ch = buf;

			if (ch->node_type != UBIFS_MST_NODE)
				goto out_err;
			dbg_rcvry("found a master node at %d:%d", lnum, offs);
			*mst = buf;
			offs += sz;
			buf  += sz;
			len  -= sz;
		}
	}
	/* Check for corruption */
	if (offs < c->leb_size) {
		if (!is_empty(buf, min_t(int, len, sz))) {
			*cor = buf;
			dbg_rcvry("found corruption at %d:%d", lnum, offs);
		}
		offs += sz;
		buf  += sz;
		len  -= sz;
	}
	/* Check remaining empty space */
	if (offs < c->leb_size)
		if (!is_empty(buf, len))
			goto out_err;
	*pbuf = sbuf;
	return 0;

out_err:
	err = -EINVAL;
out_free:
	vfree(sbuf);
	*mst = NULL;
	*cor = NULL;
	return err;
}

/**
 * write_rcvrd_mst_node - write recovered master node.
 * @c: UBIFS file-system description object
 * @mst: master node
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int write_rcvrd_mst_node(struct ubifs_info *c,
				struct ubifs_mst_node *mst)
{
	int err = 0, lnum = UBIFS_MST_LNUM, sz = c->mst_node_alsz;
	__le32 save_flags;

	dbg_rcvry("recovery");

	save_flags = mst->flags;
	mst->flags |= cpu_to_le32(UBIFS_MST_RCVRY);

	ubifs_prepare_node(c, mst, UBIFS_MST_NODE_SZ, 1);
	err = ubifs_leb_change(c, lnum, mst, sz);
	if (err)
		goto out;
	err = ubifs_leb_change(c, lnum + 1, mst, sz);
	if (err)
		goto out;
out:
	mst->flags = save_flags;
	return err;
}

/**
 * ubifs_recover_master_node - recover the master node.
 * @c: UBIFS file-system description object
 *
 * This function recovers the master node from corruption that may occur due to
 * an unclean unmount.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_recover_master_node(struct ubifs_info *c)
{
	void *buf1 = NULL, *buf2 = NULL, *cor1 = NULL, *cor2 = NULL;
	struct ubifs_mst_node *mst1 = NULL, *mst2 = NULL, *mst;
	const int sz = c->mst_node_alsz;
	int err, offs1, offs2;

	dbg_rcvry("recovery");

	err = get_master_node(c, UBIFS_MST_LNUM, &buf1, &mst1, &cor1);
	if (err)
		goto out_free;

	err = get_master_node(c, UBIFS_MST_LNUM + 1, &buf2, &mst2, &cor2);
	if (err)
		goto out_free;

	if (mst1) {
		offs1 = (void *)mst1 - buf1;
		if ((le32_to_cpu(mst1->flags) & UBIFS_MST_RCVRY) &&
		    (offs1 == 0 && !cor1)) {
			/*
			 * mst1 was written by recovery at offset 0 with no
			 * corruption.
			 */
			dbg_rcvry("recovery recovery");
			mst = mst1;
		} else if (mst2) {
			offs2 = (void *)mst2 - buf2;
			if (offs1 == offs2) {
				/* Same offset, so must be the same */
				if (memcmp((void *)mst1 + UBIFS_CH_SZ,
					   (void *)mst2 + UBIFS_CH_SZ,
					   UBIFS_MST_NODE_SZ - UBIFS_CH_SZ))
					goto out_err;
				mst = mst1;
			} else if (offs2 + sz == offs1) {
				/* 1st LEB was written, 2nd was not */
				if (cor1)
					goto out_err;
				mst = mst1;
			} else if (offs1 == 0 &&
				   c->leb_size - offs2 - sz < sz) {
				/* 1st LEB was unmapped and written, 2nd not */
				if (cor1)
					goto out_err;
				mst = mst1;
			} else
				goto out_err;
		} else {
			/*
			 * 2nd LEB was unmapped and about to be written, so
			 * there must be only one master node in the first LEB
			 * and no corruption.
			 */
			if (offs1 != 0 || cor1)
				goto out_err;
			mst = mst1;
		}
	} else {
		if (!mst2)
			goto out_err;
		/*
		 * 1st LEB was unmapped and about to be written, so there must
		 * be no room left in 2nd LEB.
		 */
		offs2 = (void *)mst2 - buf2;
		if (offs2 + sz + sz <= c->leb_size)
			goto out_err;
		mst = mst2;
	}

	ubifs_msg("recovered master node from LEB %d",
		  (mst == mst1 ? UBIFS_MST_LNUM : UBIFS_MST_LNUM + 1));

	memcpy(c->mst_node, mst, UBIFS_MST_NODE_SZ);

	if (c->ro_mount) {
		/* Read-only mode. Keep a copy for switching to rw mode */
		c->rcvrd_mst_node = kmalloc(sz, GFP_KERNEL);
		if (!c->rcvrd_mst_node) {
			err = -ENOMEM;
			goto out_free;
		}
		memcpy(c->rcvrd_mst_node, c->mst_node, UBIFS_MST_NODE_SZ);

		/*
		 * We had to recover the master node, which means there was an
		 * unclean reboot. However, it is possible that the master node
		 * is clean at this point, i.e., %UBIFS_MST_DIRTY is not set.
		 * E.g., consider the following chain of events:
		 *
		 * 1. UBIFS was cleanly unmounted, so the master node is clean
		 * 2. UBIFS is being mounted R/W and starts changing the master
		 *    node in the first (%UBIFS_MST_LNUM). A power cut happens,
		 *    so this LEB ends up with some amount of garbage at the
		 *    end.
		 * 3. UBIFS is being mounted R/O. We reach this place and
		 *    recover the master node from the second LEB
		 *    (%UBIFS_MST_LNUM + 1). But we cannot update the media
		 *    because we are being mounted R/O. We have to defer the
		 *    operation.
		 * 4. However, this master node (@c->mst_node) is marked as
		 *    clean (since the step 1). And if we just return, the
		 *    mount code will be confused and won't recover the master
		 *    node when it is re-mounter R/W later.
		 *
		 *    Thus, to force the recovery by marking the master node as
		 *    dirty.
		 */
		c->mst_node->flags |= cpu_to_le32(UBIFS_MST_DIRTY);
	} else {
		/* Write the recovered master node */
		c->max_sqnum = le64_to_cpu(mst->ch.sqnum) - 1;
		err = write_rcvrd_mst_node(c, c->mst_node);
		if (err)
			goto out_free;
	}

	vfree(buf2);
	vfree(buf1);

	return 0;

out_err:
	err = -EINVAL;
out_free:
	ubifs_err("failed to recover master node");
	if (mst1) {
		ubifs_err("dumping first master node");
		ubifs_dump_node(c, mst1);
	}
	if (mst2) {
		ubifs_err("dumping second master node");
		ubifs_dump_node(c, mst2);
	}
	vfree(buf2);
	vfree(buf1);
	return err;
}

/**
 * ubifs_write_rcvrd_mst_node - write the recovered master node.
 * @c: UBIFS file-system description object
 *
 * This function writes the master node that was recovered during mounting in
 * read-only mode and must now be written because we are remounting rw.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_write_rcvrd_mst_node(struct ubifs_info *c)
{
	int err;

	if (!c->rcvrd_mst_node)
		return 0;
	c->rcvrd_mst_node->flags |= cpu_to_le32(UBIFS_MST_DIRTY);
	c->mst_node->flags |= cpu_to_le32(UBIFS_MST_DIRTY);
	err = write_rcvrd_mst_node(c, c->rcvrd_mst_node);
	if (err)
		return err;
	kfree(c->rcvrd_mst_node);
	c->rcvrd_mst_node = NULL;
	return 0;
}

/**
 * is_last_write - determine if an offset was in the last write to a LEB.
 * @c: UBIFS file-system description object
 * @buf: buffer to check
 * @offs: offset to check
 *
 * This function returns %1 if @offs was in the last write to the LEB whose data
 * is in @buf, otherwise %0 is returned. The determination is made by checking
 * for subsequent empty space starting from the next @c->max_write_size
 * boundary.
 */
static int is_last_write(const struct ubifs_info *c, void *buf, int offs)
{
	int empty_offs, check_len;
	uint8_t *p;

	/*
	 * Round up to the next @c->max_write_size boundary i.e. @offs is in
	 * the last wbuf written. After that should be empty space.
	 */
	empty_offs = ALIGN(offs + 1, c->max_write_size);
	check_len = c->leb_size - empty_offs;
	p = buf + empty_offs - offs;
	return is_empty(p, check_len);
}

/**
 * clean_buf - clean the data from an LEB sitting in a buffer.
 * @c: UBIFS file-system description object
 * @buf: buffer to clean
 * @lnum: LEB number to clean
 * @offs: offset from which to clean
 * @len: length of buffer
 *
 * This function pads up to the next min_io_size boundary (if there is one) and
 * sets empty space to all 0xff. @buf, @offs and @len are updated to the next
 * @c->min_io_size boundary.
 */
static void clean_buf(const struct ubifs_info *c, void **buf, int lnum,
		      int *offs, int *len)
{
	int empty_offs, pad_len;

	lnum = lnum;
	dbg_rcvry("cleaning corruption at %d:%d", lnum, *offs);

	ubifs_assert(!(*offs & 7));
	empty_offs = ALIGN(*offs, c->min_io_size);
	pad_len = empty_offs - *offs;
	ubifs_pad(c, *buf, pad_len);
	*offs += pad_len;
	*buf += pad_len;
	*len -= pad_len;
	memset(*buf, 0xff, c->leb_size - empty_offs);
}

/**
 * no_more_nodes - determine if there are no more nodes in a buffer.
 * @c: UBIFS file-system description object
 * @buf: buffer to check
 * @len: length of buffer
 * @lnum: LEB number of the LEB from which @buf was read
 * @offs: offset from which @buf was read
 *
 * This function ensures that the corrupted node at @offs is the last thing
 * written to a LEB. This function returns %1 if more data is not found and
 * %0 if more data is found.
 */
static int no_more_nodes(const struct ubifs_info *c, void *buf, int len,
			int lnum, int offs)
{
	struct ubifs_ch *ch = buf;
	int skip, dlen = le32_to_cpu(ch->len);

	/* Check for empty space after the corrupt node's common header */
	skip = ALIGN(offs + UBIFS_CH_SZ, c->max_write_size) - offs;
	if (is_empty(buf + skip, len - skip))
		return 1;
	/*
	 * The area after the common header size is not empty, so the common
	 * header must be intact. Check it.
	 */
	if (ubifs_check_node(c, buf, lnum, offs, 1, 0) != -EUCLEAN) {
		dbg_rcvry("unexpected bad common header at %d:%d", lnum, offs);
		return 0;
	}
	/* Now we know the corrupt node's length we can skip over it */
	skip = ALIGN(offs + dlen, c->max_write_size) - offs;
	/* After which there should be empty space */
	if (is_empty(buf + skip, len - skip))
		return 1;
	dbg_rcvry("unexpected data at %d:%d", lnum, offs + skip);
	return 0;
}

/**
 * fix_unclean_leb - fix an unclean LEB.
 * @c: UBIFS file-system description object
 * @sleb: scanned LEB information
 * @start: offset where scan started
 */
static int fix_unclean_leb(struct ubifs_info *c, struct ubifs_scan_leb *sleb,
			   int start)
{
	int lnum = sleb->lnum, endpt = start;

	/* Get the end offset of the last node we are keeping */
	if (!list_empty(&sleb->nodes)) {
		struct ubifs_scan_node *snod;

		snod = list_entry(sleb->nodes.prev,
				  struct ubifs_scan_node, list);
		endpt = snod->offs + snod->len;
	}

	if (c->ro_mount && !c->remounting_rw) {
		/* Add to recovery list */
		struct ubifs_unclean_leb *ucleb;

		dbg_rcvry("need to fix LEB %d start %d endpt %d",
			  lnum, start, sleb->endpt);
		ucleb = kzalloc(sizeof(struct ubifs_unclean_leb), GFP_NOFS);
		if (!ucleb)
			return -ENOMEM;
		ucleb->lnum = lnum;
		ucleb->endpt = endpt;
		list_add_tail(&ucleb->list, &c->unclean_leb_list);
	} else {
		/* Write the fixed LEB back to flash */
		int err;

		dbg_rcvry("fixing LEB %d start %d endpt %d",
			  lnum, start, sleb->endpt);
		if (endpt == 0) {
			err = ubifs_leb_unmap(c, lnum);
			if (err)
				return err;
		} else {
			int len = ALIGN(endpt, c->min_io_size);

			if (start) {
				err = ubifs_leb_read(c, lnum, sleb->buf, 0,
						     start, 1);
				if (err)
					return err;
			}
			/* Pad to min_io_size */
			if (len > endpt) {
				int pad_len = len - ALIGN(endpt, 8);

				if (pad_len > 0) {
					void *buf = sleb->buf + len - pad_len;

					ubifs_pad(c, buf, pad_len);
				}
			}
			err = ubifs_leb_change(c, lnum, sleb->buf, len);
			if (err)
				return err;
		}
	}
	return 0;
}

/**
 * drop_last_group - drop the last group of nodes.
 * @sleb: scanned LEB information
 * @offs: offset of dropped nodes is returned here
 *
 * This is a helper function for 'ubifs_recover_leb()' which drops the last
 * group of nodes of the scanned LEB.
 */
static void drop_last_group(struct ubifs_scan_leb *sleb, int *offs)
{
	while (!list_empty(&sleb->nodes)) {
		struct ubifs_scan_node *snod;
		struct ubifs_ch *ch;

		snod = list_entry(sleb->nodes.prev, struct ubifs_scan_node,
				  list);
		ch = snod->node;
		if (ch->group_type != UBIFS_IN_NODE_GROUP)
			break;

		dbg_rcvry("dropping grouped node at %d:%d",
			  sleb->lnum, snod->offs);
		*offs = snod->offs;
		list_del(&snod->list);
		kfree(snod);
		sleb->nodes_cnt -= 1;
	}
}

/**
 * drop_last_node - drop the last node.
 * @sleb: scanned LEB information
 * @offs: offset of dropped nodes is returned here
 *
 * This is a helper function for 'ubifs_recover_leb()' which drops the last
 * node of the scanned LEB.
 */
static void drop_last_node(struct ubifs_scan_leb *sleb, int *offs)
{
	struct ubifs_scan_node *snod;

	if (!list_empty(&sleb->nodes)) {
		snod = list_entry(sleb->nodes.prev, struct ubifs_scan_node,
				  list);

		dbg_rcvry("dropping last node at %d:%d",
			  sleb->lnum, snod->offs);
		*offs = snod->offs;
		list_del(&snod->list);
		kfree(snod);
		sleb->nodes_cnt -= 1;
	}
}

/**
 * ubifs_recover_leb - scan and recover a LEB.
 * @c: UBIFS file-system description object
 * @lnum: LEB number
 * @offs: offset
 * @sbuf: LEB-sized buffer to use
 * @jhead: journal head number this LEB belongs to (%-1 if the LEB does not
 *         belong to any journal head)
 *
 * This function does a scan of a LEB, but caters for errors that might have
 * been caused by the unclean unmount from which we are attempting to recover.
 * Returns the scanned information on success and a negative error code on
 * failure.
 */
struct ubifs_scan_leb *ubifs_recover_leb(struct ubifs_info *c, int lnum,
					 int offs, void *sbuf, int jhead)
{
	int ret = 0, err, len = c->leb_size - offs, start = offs, min_io_unit;
	int grouped = jhead == -1 ? 0 : c->jheads[jhead].grouped;
	struct ubifs_scan_leb *sleb;
	void *buf = sbuf + offs;

	dbg_rcvry("%d:%d, jhead %d, grouped %d", lnum, offs, jhead, grouped);

	sleb = ubifs_start_scan(c, lnum, offs, sbuf);
	if (IS_ERR(sleb))
		return sleb;

	ubifs_assert(len >= 8);
	while (len >= 8) {
		dbg_scan("look at LEB %d:%d (%d bytes left)",
			 lnum, offs, len);

		cond_resched();

		/*
		 * Scan quietly until there is an error from which we cannot
		 * recover
		 */
		ret = ubifs_scan_a_node(c, buf, len, lnum, offs, 1);
		if (ret == SCANNED_A_NODE) {
			/* A valid node, and not a padding node */
			struct ubifs_ch *ch = buf;
			int node_len;

			err = ubifs_add_snod(c, sleb, buf, offs);
			if (err)
				goto error;
			node_len = ALIGN(le32_to_cpu(ch->len), 8);
			offs += node_len;
			buf += node_len;
			len -= node_len;
		} else if (ret > 0) {
			/* Padding bytes or a valid padding node */
			offs += ret;
			buf += ret;
			len -= ret;
		} else if (ret == SCANNED_EMPTY_SPACE ||
			   ret == SCANNED_GARBAGE     ||
			   ret == SCANNED_A_BAD_PAD_NODE ||
			   ret == SCANNED_A_CORRUPT_NODE) {
			dbg_rcvry("found corruption (%d) at %d:%d",
				  ret, lnum, offs);
			break;
		} else {
			ubifs_err("unexpected return value %d", ret);
			err = -EINVAL;
			goto error;
		}
	}

	if (ret == SCANNED_GARBAGE || ret == SCANNED_A_BAD_PAD_NODE) {
		if (!is_last_write(c, buf, offs))
			goto corrupted_rescan;
	} else if (ret == SCANNED_A_CORRUPT_NODE) {
		if (!no_more_nodes(c, buf, len, lnum, offs))
			goto corrupted_rescan;
	} else if (!is_empty(buf, len)) {
		if (!is_last_write(c, buf, offs)) {
			int corruption = first_non_ff(buf, len);

			/*
			 * See header comment for this file for more
			 * explanations about the reasons we have this check.
			 */
			ubifs_err("corrupt empty space LEB %d:%d, corruption starts at %d",
				  lnum, offs, corruption);
			/* Make sure we dump interesting non-0xFF data */
			offs += corruption;
			buf += corruption;
			goto corrupted;
		}
	}

	min_io_unit = round_down(offs, c->min_io_size);
	if (grouped)
		/*
		 * If nodes are grouped, always drop the incomplete group at
		 * the end.
		 */
		drop_last_group(sleb, &offs);

	if (jhead == GCHD) {
		/*
		 * If this LEB belongs to the GC head then while we are in the
		 * middle of the same min. I/O unit keep dropping nodes. So
		 * basically, what we want is to make sure that the last min.
		 * I/O unit where we saw the corruption is dropped completely
		 * with all the uncorrupted nodes which may possibly sit there.
		 *
		 * In other words, let's name the min. I/O unit where the
		 * corruption starts B, and the previous min. I/O unit A. The
		 * below code tries to deal with a situation when half of B
		 * contains valid nodes or the end of a valid node, and the
		 * second half of B contains corrupted data or garbage. This
		 * means that UBIFS had been writing to B just before the power
		 * cut happened. I do not know how realistic is this scenario
		 * that half of the min. I/O unit had been written successfully
		 * and the other half not, but this is possible in our 'failure
		 * mode emulation' infrastructure at least.
		 *
		 * So what is the problem, why we need to drop those nodes? Why
		 * can't we just clean-up the second half of B by putting a
		 * padding node there? We can, and this works fine with one
		 * exception which was reproduced with power cut emulation
		 * testing and happens extremely rarely.
		 *
		 * Imagine the file-system is full, we run GC which starts
		 * moving valid nodes from LEB X to LEB Y (obviously, LEB Y is
		 * the current GC head LEB). The @c->gc_lnum is -1, which means
		 * that GC will retain LEB X and will try to continue. Imagine
		 * that LEB X is currently the dirtiest LEB, and the amount of
		 * used space in LEB Y is exactly the same as amount of free
		 * space in LEB X.
		 *
		 * And a power cut happens when nodes are moved from LEB X to
		 * LEB Y. We are here trying to recover LEB Y which is the GC
		 * head LEB. We find the min. I/O unit B as described above.
		 * Then we clean-up LEB Y by padding min. I/O unit. And later
		 * 'ubifs_rcvry_gc_commit()' function fails, because it cannot
		 * find a dirty LEB which could be GC'd into LEB Y! Even LEB X
		 * does not match because the amount of valid nodes there does
		 * not fit the free space in LEB Y any more! And this is
		 * because of the padding node which we added to LEB Y. The
		 * user-visible effect of this which I once observed and
		 * analysed is that we cannot mount the file-system with
		 * -ENOSPC error.
		 *
		 * So obviously, to make sure that situation does not happen we
		 * should free min. I/O unit B in LEB Y completely and the last
		 * used min. I/O unit in LEB Y should be A. This is basically
		 * what the below code tries to do.
		 */
		while (offs > min_io_unit)
			drop_last_node(sleb, &offs);
	}

	buf = sbuf + offs;
	len = c->leb_size - offs;

	clean_buf(c, &buf, lnum, &offs, &len);
	ubifs_end_scan(c, sleb, lnum, offs);

	err = fix_unclean_leb(c, sleb, start);
	if (err)
		goto error;

	return sleb;

corrupted_rescan:
	/* Re-scan the corrupted data with verbose messages */
	ubifs_err("corruption %d", ret);
	ubifs_scan_a_node(c, buf, len, lnum, offs, 1);
corrupted:
	ubifs_scanned_corruption(c, lnum, offs, buf);
	err = -EUCLEAN;
error:
	ubifs_err("LEB %d scanning failed", lnum);
	ubifs_scan_destroy(sleb);
	return ERR_PTR(err);
}

/**
 * get_cs_sqnum - get commit start sequence number.
 * @c: UBIFS file-system description object
 * @lnum: LEB number of commit start node
 * @offs: offset of commit start node
 * @cs_sqnum: commit start sequence number is returned here
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int get_cs_sqnum(struct ubifs_info *c, int lnum, int offs,
			unsigned long long *cs_sqnum)
{
	struct ubifs_cs_node *cs_node = NULL;
	int err, ret;

	dbg_rcvry("at %d:%d", lnum, offs);
	cs_node = kmalloc(UBIFS_CS_NODE_SZ, GFP_KERNEL);
	if (!cs_node)
		return -ENOMEM;
	if (c->leb_size - offs < UBIFS_CS_NODE_SZ)
		goto out_err;
	err = ubifs_leb_read(c, lnum, (void *)cs_node, offs,
			     UBIFS_CS_NODE_SZ, 0);
	if (err && err != -EBADMSG)
		goto out_free;
	ret = ubifs_scan_a_node(c, cs_node, UBIFS_CS_NODE_SZ, lnum, offs, 0);
	if (ret != SCANNED_A_NODE) {
		ubifs_err("Not a valid node");
		goto out_err;
	}
	if (cs_node->ch.node_type != UBIFS_CS_NODE) {
		ubifs_err("Node a CS node, type is %d", cs_node->ch.node_type);
		goto out_err;
	}
	if (le64_to_cpu(cs_node->cmt_no) != c->cmt_no) {
		ubifs_err("CS node cmt_no %llu != current cmt_no %llu",
			  (unsigned long long)le64_to_cpu(cs_node->cmt_no),
			  c->cmt_no);
		goto out_err;
	}
	*cs_sqnum = le64_to_cpu(cs_node->ch.sqnum);
	dbg_rcvry("commit start sqnum %llu", *cs_sqnum);
	kfree(cs_node);
	return 0;

out_err:
	err = -EINVAL;
out_free:
	ubifs_err("failed to get CS sqnum");
	kfree(cs_node);
	return err;
}

/**
 * ubifs_recover_log_leb - scan and recover a log LEB.
 * @c: UBIFS file-system description object
 * @lnum: LEB number
 * @offs: offset
 * @sbuf: LEB-sized buffer to use
 *
 * This function does a scan of a LEB, but caters for errors that might have
 * been caused by unclean reboots from which we are attempting to recover
 * (assume that only the last log LEB can be corrupted by an unclean reboot).
 *
 * This function returns %0 on success and a negative error code on failure.
 */
struct ubifs_scan_leb *ubifs_recover_log_leb(struct ubifs_info *c, int lnum,
					     int offs, void *sbuf)
{
	struct ubifs_scan_leb *sleb;
	int next_lnum;

	dbg_rcvry("LEB %d", lnum);
	next_lnum = lnum + 1;
	if (next_lnum >= UBIFS_LOG_LNUM + c->log_lebs)
		next_lnum = UBIFS_LOG_LNUM;
	if (next_lnum != c->ltail_lnum) {
		/*
		 * We can only recover at the end of the log, so check that the
		 * next log LEB is empty or out of date.
		 */
		sleb = ubifs_scan(c, next_lnum, 0, sbuf, 0);
		if (IS_ERR(sleb))
			return sleb;
		if (sleb->nodes_cnt) {
			struct ubifs_scan_node *snod;
			unsigned long long cs_sqnum = c->cs_sqnum;

			snod = list_entry(sleb->nodes.next,
					  struct ubifs_scan_node, list);
			if (cs_sqnum == 0) {
				int err;

				err = get_cs_sqnum(c, lnum, offs, &cs_sqnum);
				if (err) {
					ubifs_scan_destroy(sleb);
					return ERR_PTR(err);
				}
			}
			if (snod->sqnum > cs_sqnum) {
				ubifs_err("unrecoverable log corruption in LEB %d",
					  lnum);
				ubifs_scan_destroy(sleb);
				return ERR_PTR(-EUCLEAN);
			}
		}
		ubifs_scan_destroy(sleb);
	}
	return ubifs_recover_leb(c, lnum, offs, sbuf, -1);
}

/**
 * recover_head - recover a head.
 * @c: UBIFS file-system description object
 * @lnum: LEB number of head to recover
 * @offs: offset of head to recover
 * @sbuf: LEB-sized buffer to use
 *
 * This function ensures that there is no data on the flash at a head location.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int recover_head(struct ubifs_info *c, int lnum, int offs, void *sbuf)
{
	int len = c->max_write_size, err;

	if (offs + len > c->leb_size)
		len = c->leb_size - offs;

	if (!len)
		return 0;

	/* Read at the head location and check it is empty flash */
	err = ubifs_leb_read(c, lnum, sbuf, offs, len, 1);
	if (err || !is_empty(sbuf, len)) {
		dbg_rcvry("cleaning head at %d:%d", lnum, offs);
		if (offs == 0)
			return ubifs_leb_unmap(c, lnum);
		err = ubifs_leb_read(c, lnum, sbuf, 0, offs, 1);
		if (err)
			return err;
		return ubifs_leb_change(c, lnum, sbuf, offs);
	}

	return 0;
}

/**
 * ubifs_recover_inl_heads - recover index and LPT heads.
 * @c: UBIFS file-system description object
 * @sbuf: LEB-sized buffer to use
 *
 * This function ensures that there is no data on the flash at the index and
 * LPT head locations.
 *
 * This deals with the recovery of a half-completed journal commit. UBIFS is
 * careful never to overwrite the last version of the index or the LPT. Because
 * the index and LPT are wandering trees, data from a half-completed commit will
 * not be referenced anywhere in UBIFS. The data will be either in LEBs that are
 * assumed to be empty and will be unmapped anyway before use, or in the index
 * and LPT heads.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_recover_inl_heads(struct ubifs_info *c, void *sbuf)
{
	int err;

	ubifs_assert(!c->ro_mount || c->remounting_rw);

	dbg_rcvry("checking index head at %d:%d", c->ihead_lnum, c->ihead_offs);
	err = recover_head(c, c->ihead_lnum, c->ihead_offs, sbuf);
	if (err)
		return err;

	dbg_rcvry("checking LPT head at %d:%d", c->nhead_lnum, c->nhead_offs);
	err = recover_head(c, c->nhead_lnum, c->nhead_offs, sbuf);
	if (err)
		return err;

	return 0;
}

/**
 * clean_an_unclean_leb - read and write a LEB to remove corruption.
 * @c: UBIFS file-system description object
 * @ucleb: unclean LEB information
 * @sbuf: LEB-sized buffer to use
 *
 * This function reads a LEB up to a point pre-determined by the mount recovery,
 * checks the nodes, and writes the result back to the flash, thereby cleaning
 * off any following corruption, or non-fatal ECC errors.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int clean_an_unclean_leb(struct ubifs_info *c,
				struct ubifs_unclean_leb *ucleb, void *sbuf)
{
	int err, lnum = ucleb->lnum, offs = 0, len = ucleb->endpt, quiet = 1;
	void *buf = sbuf;

	dbg_rcvry("LEB %d len %d", lnum, len);

	if (len == 0) {
		/* Nothing to read, just unmap it */
		err = ubifs_leb_unmap(c, lnum);
		if (err)
			return err;
		return 0;
	}

	err = ubifs_leb_read(c, lnum, buf, offs, len, 0);
	if (err && err != -EBADMSG)
		return err;

	while (len >= 8) {
		int ret;

		cond_resched();

		/* Scan quietly until there is an error */
		ret = ubifs_scan_a_node(c, buf, len, lnum, offs, quiet);

		if (ret == SCANNED_A_NODE) {
			/* A valid node, and not a padding node */
			struct ubifs_ch *ch = buf;
			int node_len;

			node_len = ALIGN(le32_to_cpu(ch->len), 8);
			offs += node_len;
			buf += node_len;
			len -= node_len;
			continue;
		}

		if (ret > 0) {
			/* Padding bytes or a valid padding node */
			offs += ret;
			buf += ret;
			len -= ret;
			continue;
		}

		if (ret == SCANNED_EMPTY_SPACE) {
			ubifs_err("unexpected empty space at %d:%d",
				  lnum, offs);
			return -EUCLEAN;
		}

		if (quiet) {
			/* Redo the last scan but noisily */
			quiet = 0;
			continue;
		}

		ubifs_scanned_corruption(c, lnum, offs, buf);
		return -EUCLEAN;
	}

	/* Pad to min_io_size */
	len = ALIGN(ucleb->endpt, c->min_io_size);
	if (len > ucleb->endpt) {
		int pad_len = len - ALIGN(ucleb->endpt, 8);

		if (pad_len > 0) {
			buf = c->sbuf + len - pad_len;
			ubifs_pad(c, buf, pad_len);
		}
	}

	/* Write back the LEB atomically */
	err = ubifs_leb_change(c, lnum, sbuf, len);
	if (err)
		return err;

	dbg_rcvry("cleaned LEB %d", lnum);

	return 0;
}

/**
 * ubifs_clean_lebs - clean LEBs recovered during read-only mount.
 * @c: UBIFS file-system description object
 * @sbuf: LEB-sized buffer to use
 *
 * This function cleans a LEB identified during recovery that needs to be
 * written but was not because UBIFS was mounted read-only. This happens when
 * remounting to read-write mode.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_clean_lebs(struct ubifs_info *c, void *sbuf)
{
	dbg_rcvry("recovery");
	while (!list_empty(&c->unclean_leb_list)) {
		struct ubifs_unclean_leb *ucleb;
		int err;

		ucleb = list_entry(c->unclean_leb_list.next,
				   struct ubifs_unclean_leb, list);
		err = clean_an_unclean_leb(c, ucleb, sbuf);
		if (err)
			return err;
		list_del(&ucleb->list);
		kfree(ucleb);
	}
	return 0;
}

/**
 * grab_empty_leb - grab an empty LEB to use as GC LEB and run commit.
 * @c: UBIFS file-system description object
 *
 * This is a helper function for 'ubifs_rcvry_gc_commit()' which grabs an empty
 * LEB to be used as GC LEB (@c->gc_lnum), and then runs the commit. Returns
 * zero in case of success and a negative error code in case of failure.
 */
static int grab_empty_leb(struct ubifs_info *c)
{
	int lnum, err;

	/*
	 * Note, it is very important to first search for an empty LEB and then
	 * run the commit, not vice-versa. The reason is that there might be
	 * only one empty LEB at the moment, the one which has been the
	 * @c->gc_lnum just before the power cut happened. During the regular
	 * UBIFS operation (not now) @c->gc_lnum is marked as "taken", so no
	 * one but GC can grab it. But at this moment this single empty LEB is
	 * not marked as taken, so if we run commit - what happens? Right, the
	 * commit will grab it and write the index there. Remember that the
	 * index always expands as long as there is free space, and it only
	 * starts consolidating when we run out of space.
	 *
	 * IOW, if we run commit now, we might not be able to find a free LEB
	 * after this.
	 */
	lnum = ubifs_find_free_leb_for_idx(c);
	if (lnum < 0) {
		ubifs_err("could not find an empty LEB");
		ubifs_dump_lprops(c);
		ubifs_dump_budg(c, &c->bi);
		return lnum;
	}

	/* Reset the index flag */
	err = ubifs_change_one_lp(c, lnum, LPROPS_NC, LPROPS_NC, 0,
				  LPROPS_INDEX, 0);
	if (err)
		return err;

	c->gc_lnum = lnum;
	dbg_rcvry("found empty LEB %d, run commit", lnum);

	return ubifs_run_commit(c);
}

/**
 * ubifs_rcvry_gc_commit - recover the GC LEB number and run the commit.
 * @c: UBIFS file-system description object
 *
 * Out-of-place garbage collection requires always one empty LEB with which to
 * start garbage collection. The LEB number is recorded in c->gc_lnum and is
 * written to the master node on unmounting. In the case of an unclean unmount
 * the value of gc_lnum recorded in the master node is out of date and cannot
 * be used. Instead, recovery must allocate an empty LEB for this purpose.
 * However, there may not be enough empty space, in which case it must be
 * possible to GC the dirtiest LEB into the GC head LEB.
 *
 * This function also runs the commit which causes the TNC updates from
 * size-recovery and orphans to be written to the flash. That is important to
 * ensure correct replay order for subsequent mounts.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int ubifs_rcvry_gc_commit(struct ubifs_info *c)
{
	struct ubifs_wbuf *wbuf = &c->jheads[GCHD].wbuf;
	struct ubifs_lprops lp;
	int err;

	dbg_rcvry("GC head LEB %d, offs %d", wbuf->lnum, wbuf->offs);

	c->gc_lnum = -1;
	if (wbuf->lnum == -1 || wbuf->offs == c->leb_size)
		return grab_empty_leb(c);

	err = ubifs_find_dirty_leb(c, &lp, wbuf->offs, 2);
	if (err) {
		if (err != -ENOSPC)
			return err;

		dbg_rcvry("could not find a dirty LEB");
		return grab_empty_leb(c);
	}

	ubifs_assert(!(lp.flags & LPROPS_INDEX));
	ubifs_assert(lp.free + lp.dirty >= wbuf->offs);

	/*
	 * We run the commit before garbage collection otherwise subsequent
	 * mounts will see the GC and orphan deletion in a different order.
	 */
	dbg_rcvry("committing");
	err = ubifs_run_commit(c);
	if (err)
		return err;

	dbg_rcvry("GC'ing LEB %d", lp.lnum);
	mutex_lock_nested(&wbuf->io_mutex, wbuf->jhead);
	err = ubifs_garbage_collect_leb(c, &lp);
	if (err >= 0) {
		int err2 = ubifs_wbuf_sync_nolock(wbuf);

		if (err2)
			err = err2;
	}
	mutex_unlock(&wbuf->io_mutex);
	if (err < 0) {
		ubifs_err("GC failed, error %d", err);
		if (err == -EAGAIN)
			err = -EINVAL;
		return err;
	}

	ubifs_assert(err == LEB_RETAINED);
	if (err != LEB_RETAINED)
		return -EINVAL;

	err = ubifs_leb_unmap(c, c->gc_lnum);
	if (err)
		return err;

	dbg_rcvry("allocated LEB %d for GC", lp.lnum);
	return 0;
}

/**
 * struct size_entry - inode size information for recovery.
 * @rb: link in the RB-tree of sizes
 * @inum: inode number
 * @i_size: size on inode
 * @d_size: maximum size based on data nodes
 * @exists: indicates whether the inode exists
 * @inode: inode if pinned in memory awaiting rw mode to fix it
 */
struct size_entry {
	struct rb_node rb;
	ino_t inum;
	loff_t i_size;
	loff_t d_size;
	int exists;
	struct inode *inode;
};

/**
 * add_ino - add an entry to the size tree.
 * @c: UBIFS file-system description object
 * @inum: inode number
 * @i_size: size on inode
 * @d_size: maximum size based on data nodes
 * @exists: indicates whether the inode exists
 */
static int add_ino(struct ubifs_info *c, ino_t inum, loff_t i_size,
		   loff_t d_size, int exists)
{
	struct rb_node **p = &c->size_tree.rb_node, *parent = NULL;
	struct size_entry *e;

	while (*p) {
		parent = *p;
		e = rb_entry(parent, struct size_entry, rb);
		if (inum < e->inum)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	e = kzalloc(sizeof(struct size_entry), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->inum = inum;
	e->i_size = i_size;
	e->d_size = d_size;
	e->exists = exists;

	rb_link_node(&e->rb, parent, p);
	rb_insert_color(&e->rb, &c->size_tree);

	return 0;
}

/**
 * find_ino - find an entry on the size tree.
 * @c: UBIFS file-system description object
 * @inum: inode number
 */
static struct size_entry *find_ino(struct ubifs_info *c, ino_t inum)
{
	struct rb_node *p = c->size_tree.rb_node;
	struct size_entry *e;

	while (p) {
		e = rb_entry(p, struct size_entry, rb);
		if (inum < e->inum)
			p = p->rb_left;
		else if (inum > e->inum)
			p = p->rb_right;
		else
			return e;
	}
	return NULL;
}

/**
 * remove_ino - remove an entry from the size tree.
 * @c: UBIFS file-system description object
 * @inum: inode number
 */
static void remove_ino(struct ubifs_info *c, ino_t inum)
{
	struct size_entry *e = find_ino(c, inum);

	if (!e)
		return;
	rb_erase(&e->rb, &c->size_tree);
	kfree(e);
}

/**
 * ubifs_destroy_size_tree - free resources related to the size tree.
 * @c: UBIFS file-system description object
 */
void ubifs_destroy_size_tree(struct ubifs_info *c)
{
	struct size_entry *e, *n;

	rbtree_postorder_for_each_entry_safe(e, n, &c->size_tree, rb) {
		if (e->inode)
			iput(e->inode);
		kfree(e);
	}

	c->size_tree = RB_ROOT;
}

/**
 * ubifs_recover_size_accum - accumulate inode sizes for recovery.
 * @c: UBIFS file-system description object
 * @key: node key
 * @deletion: node is for a deletion
 * @new_size: inode size
 *
 * This function has two purposes:
 *     1) to ensure there are no data nodes that fall outside the inode size
 *     2) to ensure there are no data nodes for inodes that do not exist
 * To accomplish those purposes, a rb-tree is constructed containing an entry
 * for each inode number in the journal that has not been deleted, and recording
 * the size from the inode node, the maximum size of any data node (also altered
 * by truncations) and a flag indicating a inode number for which no inode node
 * was present in the journal.
 *
 * Note that there is still the possibility that there are data nodes that have
 * been committed that are beyond the inode size, however the only way to find
 * them would be to scan the entire index. Alternatively, some provision could
 * be made to record the size of inodes at the start of commit, which would seem
 * very cumbersome for a scenario that is quite unlikely and the only negative
 * consequence of which is wasted space.
 *
 * This functions returns %0 on success and a negative error code on failure.
 */
int ubifs_recover_size_accum(struct ubifs_info *c, union ubifs_key *key,
			     int deletion, loff_t new_size)
{
	ino_t inum = key_inum(c, key);
	struct size_entry *e;
	int err;

	switch (key_type(c, key)) {
	case UBIFS_INO_KEY:
		if (deletion)
			remove_ino(c, inum);
		else {
			e = find_ino(c, inum);
			if (e) {
				e->i_size = new_size;
				e->exists = 1;
			} else {
				err = add_ino(c, inum, new_size, 0, 1);
				if (err)
					return err;
			}
		}
		break;
	case UBIFS_DATA_KEY:
		e = find_ino(c, inum);
		if (e) {
			if (new_size > e->d_size)
				e->d_size = new_size;
		} else {
			err = add_ino(c, inum, 0, new_size, 0);
			if (err)
				return err;
		}
		break;
	case UBIFS_TRUN_KEY:
		e = find_ino(c, inum);
		if (e)
			e->d_size = new_size;
		break;
	}
	return 0;
}

/**
 * fix_size_in_place - fix inode size in place on flash.
 * @c: UBIFS file-system description object
 * @e: inode size information for recovery
 */
static int fix_size_in_place(struct ubifs_info *c, struct size_entry *e)
{
	struct ubifs_ino_node *ino = c->sbuf;
	unsigned char *p;
	union ubifs_key key;
	int err, lnum, offs, len;
	loff_t i_size;
	uint32_t crc;

	/* Locate the inode node LEB number and offset */
	ino_key_init(c, &key, e->inum);
	err = ubifs_tnc_locate(c, &key, ino, &lnum, &offs);
	if (err)
		goto out;
	/*
	 * If the size recorded on the inode node is greater than the size that
	 * was calculated from nodes in the journal then don't change the inode.
	 */
	i_size = le64_to_cpu(ino->size);
	if (i_size >= e->d_size)
		return 0;
	/* Read the LEB */
	err = ubifs_leb_read(c, lnum, c->sbuf, 0, c->leb_size, 1);
	if (err)
		goto out;
	/* Change the size field and recalculate the CRC */
	ino = c->sbuf + offs;
	ino->size = cpu_to_le64(e->d_size);
	len = le32_to_cpu(ino->ch.len);
	crc = crc32(UBIFS_CRC32_INIT, (void *)ino + 8, len - 8);
	ino->ch.crc = cpu_to_le32(crc);
	/* Work out where data in the LEB ends and free space begins */
	p = c->sbuf;
	len = c->leb_size - 1;
	while (p[len] == 0xff)
		len -= 1;
	len = ALIGN(len + 1, c->min_io_size);
	/* Atomically write the fixed LEB back again */
	err = ubifs_leb_change(c, lnum, c->sbuf, len);
	if (err)
		goto out;
	dbg_rcvry("inode %lu at %d:%d size %lld -> %lld",
		  (unsigned long)e->inum, lnum, offs, i_size, e->d_size);
	return 0;

out:
	ubifs_warn("inode %lu failed to fix size %lld -> %lld error %d",
		   (unsigned long)e->inum, e->i_size, e->d_size, err);
	return err;
}

/**
 * ubifs_recover_size - recover inode size.
 * @c: UBIFS file-system description object
 *
 * This function attempts to fix inode size discrepancies identified by the
 * 'ubifs_recover_size_accum()' function.
 *
 * This functions returns %0 on success and a negative error code on failure.
 */
int ubifs_recover_size(struct ubifs_info *c)
{
	struct rb_node *this = rb_first(&c->size_tree);

	while (this) {
		struct size_entry *e;
		int err;

		e = rb_entry(this, struct size_entry, rb);
		if (!e->exists) {
			union ubifs_key key;

			ino_key_init(c, &key, e->inum);
			err = ubifs_tnc_lookup(c, &key, c->sbuf);
			if (err && err != -ENOENT)
				return err;
			if (err == -ENOENT) {
				/* Remove data nodes that have no inode */
				dbg_rcvry("removing ino %lu",
					  (unsigned long)e->inum);
				err = ubifs_tnc_remove_ino(c, e->inum);
				if (err)
					return err;
			} else {
				struct ubifs_ino_node *ino = c->sbuf;

				e->exists = 1;
				e->i_size = le64_to_cpu(ino->size);
			}
		}

		if (e->exists && e->i_size < e->d_size) {
			if (c->ro_mount) {
				/* Fix the inode size and pin it in memory */
				struct inode *inode;
				struct ubifs_inode *ui;

				ubifs_assert(!e->inode);

				inode = ubifs_iget(c->vfs_sb, e->inum);
				if (IS_ERR(inode))
					return PTR_ERR(inode);

				ui = ubifs_inode(inode);
				if (inode->i_size < e->d_size) {
					dbg_rcvry("ino %lu size %lld -> %lld",
						  (unsigned long)e->inum,
						  inode->i_size, e->d_size);
					inode->i_size = e->d_size;
					ui->ui_size = e->d_size;
					ui->synced_i_size = e->d_size;
					e->inode = inode;
					this = rb_next(this);
					continue;
				}
				iput(inode);
			} else {
				/* Fix the size in place */
				err = fix_size_in_place(c, e);
				if (err)
					return err;
				if (e->inode)
					iput(e->inode);
			}
		}

		this = rb_next(this);
		rb_erase(&e->rb, &c->size_tree);
		kfree(e);
	}

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/recovery.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 * Copyright (C) 2006, 2007 University of Szeged, Hungary
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Zoltan Sogor
 *          Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/* This file implements EXT2-compatible extended attribute ioctl() calls */

#include <linux/compat.h>
// #include <linux/mount.h>
// #include "ubifs.h"
#include "../../inc/__fss.h"

/**
 * ubifs_set_inode_flags - set VFS inode flags.
 * @inode: VFS inode to set flags for
 *
 * This function propagates flags from UBIFS inode object to VFS inode object.
 */
void ubifs_set_inode_flags(struct inode *inode)
{
	unsigned int flags = ubifs_inode(inode)->flags;

	inode->i_flags &= ~(S_SYNC | S_APPEND | S_IMMUTABLE | S_DIRSYNC);
	if (flags & UBIFS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & UBIFS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & UBIFS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & UBIFS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
}

/*
 * ioctl2ubifs - convert ioctl inode flags to UBIFS inode flags.
 * @ioctl_flags: flags to convert
 *
 * This function convert ioctl flags (@FS_COMPR_FL, etc) to UBIFS inode flags
 * (@UBIFS_COMPR_FL, etc).
 */
static int ioctl2ubifs(int ioctl_flags)
{
	int ubifs_flags = 0;

	if (ioctl_flags & FS_COMPR_FL)
		ubifs_flags |= UBIFS_COMPR_FL;
	if (ioctl_flags & FS_SYNC_FL)
		ubifs_flags |= UBIFS_SYNC_FL;
	if (ioctl_flags & FS_APPEND_FL)
		ubifs_flags |= UBIFS_APPEND_FL;
	if (ioctl_flags & FS_IMMUTABLE_FL)
		ubifs_flags |= UBIFS_IMMUTABLE_FL;
	if (ioctl_flags & FS_DIRSYNC_FL)
		ubifs_flags |= UBIFS_DIRSYNC_FL;

	return ubifs_flags;
}

/*
 * ubifs2ioctl - convert UBIFS inode flags to ioctl inode flags.
 * @ubifs_flags: flags to convert
 *
 * This function convert UBIFS (@UBIFS_COMPR_FL, etc) to ioctl flags
 * (@FS_COMPR_FL, etc).
 */
static int ubifs2ioctl(int ubifs_flags)
{
	int ioctl_flags = 0;

	if (ubifs_flags & UBIFS_COMPR_FL)
		ioctl_flags |= FS_COMPR_FL;
	if (ubifs_flags & UBIFS_SYNC_FL)
		ioctl_flags |= FS_SYNC_FL;
	if (ubifs_flags & UBIFS_APPEND_FL)
		ioctl_flags |= FS_APPEND_FL;
	if (ubifs_flags & UBIFS_IMMUTABLE_FL)
		ioctl_flags |= FS_IMMUTABLE_FL;
	if (ubifs_flags & UBIFS_DIRSYNC_FL)
		ioctl_flags |= FS_DIRSYNC_FL;

	return ioctl_flags;
}

static int setflags(struct inode *inode, int flags)
{
	int oldflags, err, release;
	struct ubifs_inode *ui = ubifs_inode(inode);
	struct ubifs_info *c = inode->i_sb->s_fs_info;
	struct ubifs_budget_req req = { .dirtied_ino = 1,
					.dirtied_ino_d = ui->data_len };

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	/*
	 * The IMMUTABLE and APPEND_ONLY flags can only be changed by
	 * the relevant capability.
	 */
	mutex_lock(&ui->ui_mutex);
	oldflags = ubifs2ioctl(ui->flags);
	if ((flags ^ oldflags) & (FS_APPEND_FL | FS_IMMUTABLE_FL)) {
		if (!capable(CAP_LINUX_IMMUTABLE)) {
			err = -EPERM;
			goto out_unlock;
		}
	}

	ui->flags = ioctl2ubifs(flags);
	ubifs_set_inode_flags(inode);
	inode->i_ctime = ubifs_current_time(inode);
	release = ui->dirty;
	mark_inode_dirty_sync(inode);
	mutex_unlock(&ui->ui_mutex);

	if (release)
		ubifs_release_budget(c, &req);
	if (IS_SYNC(inode))
		err = write_inode_now(inode, 1);
	return err;

out_unlock:
	ubifs_err("can't modify inode %lu attributes", inode->i_ino);
	mutex_unlock(&ui->ui_mutex);
	ubifs_release_budget(c, &req);
	return err;
}

long ubifs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int flags, err;
	struct inode *inode = file_inode(file);

	switch (cmd) {
	case FS_IOC_GETFLAGS:
		flags = ubifs2ioctl(ubifs_inode(inode)->flags);

		dbg_gen("get flags: %#x, i_flags %#x", flags, inode->i_flags);
		return put_user(flags, (int __user *) arg);

	case FS_IOC_SETFLAGS: {
		if (IS_RDONLY(inode))
			return -EROFS;

		if (!inode_owner_or_capable(inode))
			return -EACCES;

		if (get_user(flags, (int __user *) arg))
			return -EFAULT;

		if (!S_ISDIR(inode->i_mode))
			flags &= ~FS_DIRSYNC_FL;

		/*
		 * Make sure the file-system is read-write and make sure it
		 * will not become read-only while we are changing the flags.
		 */
		err = mnt_want_write_file(file);
		if (err)
			return err;
		dbg_gen("set flags: %#x, i_flags %#x", flags, inode->i_flags);
		err = setflags(inode, flags);
		mnt_drop_write_file(file);
		return err;
	}

	default:
		return -ENOTTY;
	}
}

#ifdef CONFIG_COMPAT
long ubifs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return ubifs_ioctl(file, cmd, (unsigned long)compat_ptr(arg));
}
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/ioctl.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file implements commit-related functionality of the LEB properties
 * subsystem.
 */

// #include <linux/crc16.h>
// #include <linux/slab.h>
// #include <linux/random.h>
// #include "ubifs.h"

static int dbg_populate_lsave(struct ubifs_info *c);

/**
 * first_dirty_cnode - find first dirty cnode.
 * @c: UBIFS file-system description object
 * @nnode: nnode at which to start
 *
 * This function returns the first dirty cnode or %NULL if there is not one.
 */
static struct ubifs_cnode *first_dirty_cnode(struct ubifs_nnode *nnode)
{
	ubifs_assert(nnode);
	while (1) {
		int i, cont = 0;

		for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
			struct ubifs_cnode *cnode;

			cnode = nnode->nbranch[i].cnode;
			if (cnode &&
			    test_bit(DIRTY_CNODE, &cnode->flags)) {
				if (cnode->level == 0)
					return cnode;
				nnode = (struct ubifs_nnode *)cnode;
				cont = 1;
				break;
			}
		}
		if (!cont)
			return (struct ubifs_cnode *)nnode;
	}
}

/**
 * next_dirty_cnode - find next dirty cnode.
 * @cnode: cnode from which to begin searching
 *
 * This function returns the next dirty cnode or %NULL if there is not one.
 */
static struct ubifs_cnode *next_dirty_cnode(struct ubifs_cnode *cnode)
{
	struct ubifs_nnode *nnode;
	int i;

	ubifs_assert(cnode);
	nnode = cnode->parent;
	if (!nnode)
		return NULL;
	for (i = cnode->iip + 1; i < UBIFS_LPT_FANOUT; i++) {
		cnode = nnode->nbranch[i].cnode;
		if (cnode && test_bit(DIRTY_CNODE, &cnode->flags)) {
			if (cnode->level == 0)
				return cnode; /* cnode is a pnode */
			/* cnode is a nnode */
			return first_dirty_cnode((struct ubifs_nnode *)cnode);
		}
	}
	return (struct ubifs_cnode *)nnode;
}

/**
 * get_cnodes_to_commit - create list of dirty cnodes to commit.
 * @c: UBIFS file-system description object
 *
 * This function returns the number of cnodes to commit.
 */
static int get_cnodes_to_commit(struct ubifs_info *c)
{
	struct ubifs_cnode *cnode, *cnext;
	int cnt = 0;

	if (!c->nroot)
		return 0;

	if (!test_bit(DIRTY_CNODE, &c->nroot->flags))
		return 0;

	c->lpt_cnext = first_dirty_cnode(c->nroot);
	cnode = c->lpt_cnext;
	if (!cnode)
		return 0;
	cnt += 1;
	while (1) {
		ubifs_assert(!test_bit(COW_CNODE, &cnode->flags));
		__set_bit(COW_CNODE, &cnode->flags);
		cnext = next_dirty_cnode(cnode);
		if (!cnext) {
			cnode->cnext = c->lpt_cnext;
			break;
		}
		cnode->cnext = cnext;
		cnode = cnext;
		cnt += 1;
	}
	dbg_cmt("committing %d cnodes", cnt);
	dbg_lp("committing %d cnodes", cnt);
	ubifs_assert(cnt == c->dirty_nn_cnt + c->dirty_pn_cnt);
	return cnt;
}

/**
 * upd_ltab - update LPT LEB properties.
 * @c: UBIFS file-system description object
 * @lnum: LEB number
 * @free: amount of free space
 * @dirty: amount of dirty space to add
 */
static void upd_ltab(struct ubifs_info *c, int lnum, int free, int dirty)
{
	dbg_lp("LEB %d free %d dirty %d to %d +%d",
	       lnum, c->ltab[lnum - c->lpt_first].free,
	       c->ltab[lnum - c->lpt_first].dirty, free, dirty);
	ubifs_assert(lnum >= c->lpt_first && lnum <= c->lpt_last);
	c->ltab[lnum - c->lpt_first].free = free;
	c->ltab[lnum - c->lpt_first].dirty += dirty;
}

/**
 * alloc_lpt_leb - allocate an LPT LEB that is empty.
 * @c: UBIFS file-system description object
 * @lnum: LEB number is passed and returned here
 *
 * This function finds the next empty LEB in the ltab starting from @lnum. If a
 * an empty LEB is found it is returned in @lnum and the function returns %0.
 * Otherwise the function returns -ENOSPC.  Note however, that LPT is designed
 * never to run out of space.
 */
static int alloc_lpt_leb(struct ubifs_info *c, int *lnum)
{
	int i, n;

	n = *lnum - c->lpt_first + 1;
	for (i = n; i < c->lpt_lebs; i++) {
		if (c->ltab[i].tgc || c->ltab[i].cmt)
			continue;
		if (c->ltab[i].free == c->leb_size) {
			c->ltab[i].cmt = 1;
			*lnum = i + c->lpt_first;
			return 0;
		}
	}

	for (i = 0; i < n; i++) {
		if (c->ltab[i].tgc || c->ltab[i].cmt)
			continue;
		if (c->ltab[i].free == c->leb_size) {
			c->ltab[i].cmt = 1;
			*lnum = i + c->lpt_first;
			return 0;
		}
	}
	return -ENOSPC;
}

/**
 * layout_cnodes - layout cnodes for commit.
 * @c: UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int layout_cnodes(struct ubifs_info *c)
{
	int lnum, offs, len, alen, done_lsave, done_ltab, err;
	struct ubifs_cnode *cnode;

	err = dbg_chk_lpt_sz(c, 0, 0);
	if (err)
		return err;
	cnode = c->lpt_cnext;
	if (!cnode)
		return 0;
	lnum = c->nhead_lnum;
	offs = c->nhead_offs;
	/* Try to place lsave and ltab nicely */
	done_lsave = !c->big_lpt;
	done_ltab = 0;
	if (!done_lsave && offs + c->lsave_sz <= c->leb_size) {
		done_lsave = 1;
		c->lsave_lnum = lnum;
		c->lsave_offs = offs;
		offs += c->lsave_sz;
		dbg_chk_lpt_sz(c, 1, c->lsave_sz);
	}

	if (offs + c->ltab_sz <= c->leb_size) {
		done_ltab = 1;
		c->ltab_lnum = lnum;
		c->ltab_offs = offs;
		offs += c->ltab_sz;
		dbg_chk_lpt_sz(c, 1, c->ltab_sz);
	}

	do {
		if (cnode->level) {
			len = c->nnode_sz;
			c->dirty_nn_cnt -= 1;
		} else {
			len = c->pnode_sz;
			c->dirty_pn_cnt -= 1;
		}
		while (offs + len > c->leb_size) {
			alen = ALIGN(offs, c->min_io_size);
			upd_ltab(c, lnum, c->leb_size - alen, alen - offs);
			dbg_chk_lpt_sz(c, 2, c->leb_size - offs);
			err = alloc_lpt_leb(c, &lnum);
			if (err)
				goto no_space;
			offs = 0;
			ubifs_assert(lnum >= c->lpt_first &&
				     lnum <= c->lpt_last);
			/* Try to place lsave and ltab nicely */
			if (!done_lsave) {
				done_lsave = 1;
				c->lsave_lnum = lnum;
				c->lsave_offs = offs;
				offs += c->lsave_sz;
				dbg_chk_lpt_sz(c, 1, c->lsave_sz);
				continue;
			}
			if (!done_ltab) {
				done_ltab = 1;
				c->ltab_lnum = lnum;
				c->ltab_offs = offs;
				offs += c->ltab_sz;
				dbg_chk_lpt_sz(c, 1, c->ltab_sz);
				continue;
			}
			break;
		}
		if (cnode->parent) {
			cnode->parent->nbranch[cnode->iip].lnum = lnum;
			cnode->parent->nbranch[cnode->iip].offs = offs;
		} else {
			c->lpt_lnum = lnum;
			c->lpt_offs = offs;
		}
		offs += len;
		dbg_chk_lpt_sz(c, 1, len);
		cnode = cnode->cnext;
	} while (cnode && cnode != c->lpt_cnext);

	/* Make sure to place LPT's save table */
	if (!done_lsave) {
		if (offs + c->lsave_sz > c->leb_size) {
			alen = ALIGN(offs, c->min_io_size);
			upd_ltab(c, lnum, c->leb_size - alen, alen - offs);
			dbg_chk_lpt_sz(c, 2, c->leb_size - offs);
			err = alloc_lpt_leb(c, &lnum);
			if (err)
				goto no_space;
			offs = 0;
			ubifs_assert(lnum >= c->lpt_first &&
				     lnum <= c->lpt_last);
		}
		done_lsave = 1;
		c->lsave_lnum = lnum;
		c->lsave_offs = offs;
		offs += c->lsave_sz;
		dbg_chk_lpt_sz(c, 1, c->lsave_sz);
	}

	/* Make sure to place LPT's own lprops table */
	if (!done_ltab) {
		if (offs + c->ltab_sz > c->leb_size) {
			alen = ALIGN(offs, c->min_io_size);
			upd_ltab(c, lnum, c->leb_size - alen, alen - offs);
			dbg_chk_lpt_sz(c, 2, c->leb_size - offs);
			err = alloc_lpt_leb(c, &lnum);
			if (err)
				goto no_space;
			offs = 0;
			ubifs_assert(lnum >= c->lpt_first &&
				     lnum <= c->lpt_last);
		}
		c->ltab_lnum = lnum;
		c->ltab_offs = offs;
		offs += c->ltab_sz;
		dbg_chk_lpt_sz(c, 1, c->ltab_sz);
	}

	alen = ALIGN(offs, c->min_io_size);
	upd_ltab(c, lnum, c->leb_size - alen, alen - offs);
	dbg_chk_lpt_sz(c, 4, alen - offs);
	err = dbg_chk_lpt_sz(c, 3, alen);
	if (err)
		return err;
	return 0;

no_space:
	ubifs_err("LPT out of space at LEB %d:%d needing %d, done_ltab %d, done_lsave %d",
		  lnum, offs, len, done_ltab, done_lsave);
	ubifs_dump_lpt_info(c);
	ubifs_dump_lpt_lebs(c);
	dump_stack();
	return err;
}

/**
 * realloc_lpt_leb - allocate an LPT LEB that is empty.
 * @c: UBIFS file-system description object
 * @lnum: LEB number is passed and returned here
 *
 * This function duplicates exactly the results of the function alloc_lpt_leb.
 * It is used during end commit to reallocate the same LEB numbers that were
 * allocated by alloc_lpt_leb during start commit.
 *
 * This function finds the next LEB that was allocated by the alloc_lpt_leb
 * function starting from @lnum. If a LEB is found it is returned in @lnum and
 * the function returns %0. Otherwise the function returns -ENOSPC.
 * Note however, that LPT is designed never to run out of space.
 */
static int realloc_lpt_leb(struct ubifs_info *c, int *lnum)
{
	int i, n;

	n = *lnum - c->lpt_first + 1;
	for (i = n; i < c->lpt_lebs; i++)
		if (c->ltab[i].cmt) {
			c->ltab[i].cmt = 0;
			*lnum = i + c->lpt_first;
			return 0;
		}

	for (i = 0; i < n; i++)
		if (c->ltab[i].cmt) {
			c->ltab[i].cmt = 0;
			*lnum = i + c->lpt_first;
			return 0;
		}
	return -ENOSPC;
}

/**
 * write_cnodes - write cnodes for commit.
 * @c: UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int write_cnodes(struct ubifs_info *c)
{
	int lnum, offs, len, from, err, wlen, alen, done_ltab, done_lsave;
	struct ubifs_cnode *cnode;
	void *buf = c->lpt_buf;

	cnode = c->lpt_cnext;
	if (!cnode)
		return 0;
	lnum = c->nhead_lnum;
	offs = c->nhead_offs;
	from = offs;
	/* Ensure empty LEB is unmapped */
	if (offs == 0) {
		err = ubifs_leb_unmap(c, lnum);
		if (err)
			return err;
	}
	/* Try to place lsave and ltab nicely */
	done_lsave = !c->big_lpt;
	done_ltab = 0;
	if (!done_lsave && offs + c->lsave_sz <= c->leb_size) {
		done_lsave = 1;
		ubifs_pack_lsave(c, buf + offs, c->lsave);
		offs += c->lsave_sz;
		dbg_chk_lpt_sz(c, 1, c->lsave_sz);
	}

	if (offs + c->ltab_sz <= c->leb_size) {
		done_ltab = 1;
		ubifs_pack_ltab(c, buf + offs, c->ltab_cmt);
		offs += c->ltab_sz;
		dbg_chk_lpt_sz(c, 1, c->ltab_sz);
	}

	/* Loop for each cnode */
	do {
		if (cnode->level)
			len = c->nnode_sz;
		else
			len = c->pnode_sz;
		while (offs + len > c->leb_size) {
			wlen = offs - from;
			if (wlen) {
				alen = ALIGN(wlen, c->min_io_size);
				memset(buf + offs, 0xff, alen - wlen);
				err = ubifs_leb_write(c, lnum, buf + from, from,
						       alen);
				if (err)
					return err;
			}
			dbg_chk_lpt_sz(c, 2, c->leb_size - offs);
			err = realloc_lpt_leb(c, &lnum);
			if (err)
				goto no_space;
			offs = from = 0;
			ubifs_assert(lnum >= c->lpt_first &&
				     lnum <= c->lpt_last);
			err = ubifs_leb_unmap(c, lnum);
			if (err)
				return err;
			/* Try to place lsave and ltab nicely */
			if (!done_lsave) {
				done_lsave = 1;
				ubifs_pack_lsave(c, buf + offs, c->lsave);
				offs += c->lsave_sz;
				dbg_chk_lpt_sz(c, 1, c->lsave_sz);
				continue;
			}
			if (!done_ltab) {
				done_ltab = 1;
				ubifs_pack_ltab(c, buf + offs, c->ltab_cmt);
				offs += c->ltab_sz;
				dbg_chk_lpt_sz(c, 1, c->ltab_sz);
				continue;
			}
			break;
		}
		if (cnode->level)
			ubifs_pack_nnode(c, buf + offs,
					 (struct ubifs_nnode *)cnode);
		else
			ubifs_pack_pnode(c, buf + offs,
					 (struct ubifs_pnode *)cnode);
		/*
		 * The reason for the barriers is the same as in case of TNC.
		 * See comment in 'write_index()'. 'dirty_cow_nnode()' and
		 * 'dirty_cow_pnode()' are the functions for which this is
		 * important.
		 */
		clear_bit(DIRTY_CNODE, &cnode->flags);
		smp_mb__before_atomic();
		clear_bit(COW_CNODE, &cnode->flags);
		smp_mb__after_atomic();
		offs += len;
		dbg_chk_lpt_sz(c, 1, len);
		cnode = cnode->cnext;
	} while (cnode && cnode != c->lpt_cnext);

	/* Make sure to place LPT's save table */
	if (!done_lsave) {
		if (offs + c->lsave_sz > c->leb_size) {
			wlen = offs - from;
			alen = ALIGN(wlen, c->min_io_size);
			memset(buf + offs, 0xff, alen - wlen);
			err = ubifs_leb_write(c, lnum, buf + from, from, alen);
			if (err)
				return err;
			dbg_chk_lpt_sz(c, 2, c->leb_size - offs);
			err = realloc_lpt_leb(c, &lnum);
			if (err)
				goto no_space;
			offs = from = 0;
			ubifs_assert(lnum >= c->lpt_first &&
				     lnum <= c->lpt_last);
			err = ubifs_leb_unmap(c, lnum);
			if (err)
				return err;
		}
		done_lsave = 1;
		ubifs_pack_lsave(c, buf + offs, c->lsave);
		offs += c->lsave_sz;
		dbg_chk_lpt_sz(c, 1, c->lsave_sz);
	}

	/* Make sure to place LPT's own lprops table */
	if (!done_ltab) {
		if (offs + c->ltab_sz > c->leb_size) {
			wlen = offs - from;
			alen = ALIGN(wlen, c->min_io_size);
			memset(buf + offs, 0xff, alen - wlen);
			err = ubifs_leb_write(c, lnum, buf + from, from, alen);
			if (err)
				return err;
			dbg_chk_lpt_sz(c, 2, c->leb_size - offs);
			err = realloc_lpt_leb(c, &lnum);
			if (err)
				goto no_space;
			offs = from = 0;
			ubifs_assert(lnum >= c->lpt_first &&
				     lnum <= c->lpt_last);
			err = ubifs_leb_unmap(c, lnum);
			if (err)
				return err;
		}
		ubifs_pack_ltab(c, buf + offs, c->ltab_cmt);
		offs += c->ltab_sz;
		dbg_chk_lpt_sz(c, 1, c->ltab_sz);
	}

	/* Write remaining data in buffer */
	wlen = offs - from;
	alen = ALIGN(wlen, c->min_io_size);
	memset(buf + offs, 0xff, alen - wlen);
	err = ubifs_leb_write(c, lnum, buf + from, from, alen);
	if (err)
		return err;

	dbg_chk_lpt_sz(c, 4, alen - wlen);
	err = dbg_chk_lpt_sz(c, 3, ALIGN(offs, c->min_io_size));
	if (err)
		return err;

	c->nhead_lnum = lnum;
	c->nhead_offs = ALIGN(offs, c->min_io_size);

	dbg_lp("LPT root is at %d:%d", c->lpt_lnum, c->lpt_offs);
	dbg_lp("LPT head is at %d:%d", c->nhead_lnum, c->nhead_offs);
	dbg_lp("LPT ltab is at %d:%d", c->ltab_lnum, c->ltab_offs);
	if (c->big_lpt)
		dbg_lp("LPT lsave is at %d:%d", c->lsave_lnum, c->lsave_offs);

	return 0;

no_space:
	ubifs_err("LPT out of space mismatch at LEB %d:%d needing %d, done_ltab %d, done_lsave %d",
		  lnum, offs, len, done_ltab, done_lsave);
	ubifs_dump_lpt_info(c);
	ubifs_dump_lpt_lebs(c);
	dump_stack();
	return err;
}

/**
 * next_pnode_to_dirty - find next pnode to dirty.
 * @c: UBIFS file-system description object
 * @pnode: pnode
 *
 * This function returns the next pnode to dirty or %NULL if there are no more
 * pnodes.  Note that pnodes that have never been written (lnum == 0) are
 * skipped.
 */
static struct ubifs_pnode *next_pnode_to_dirty(struct ubifs_info *c,
					       struct ubifs_pnode *pnode)
{
	struct ubifs_nnode *nnode;
	int iip;

	/* Try to go right */
	nnode = pnode->parent;
	for (iip = pnode->iip + 1; iip < UBIFS_LPT_FANOUT; iip++) {
		if (nnode->nbranch[iip].lnum)
			return ubifs_get_pnode(c, nnode, iip);
	}

	/* Go up while can't go right */
	do {
		iip = nnode->iip + 1;
		nnode = nnode->parent;
		if (!nnode)
			return NULL;
		for (; iip < UBIFS_LPT_FANOUT; iip++) {
			if (nnode->nbranch[iip].lnum)
				break;
		}
	} while (iip >= UBIFS_LPT_FANOUT);

	/* Go right */
	nnode = ubifs_get_nnode(c, nnode, iip);
	if (IS_ERR(nnode))
		return (void *)nnode;

	/* Go down to level 1 */
	while (nnode->level > 1) {
		for (iip = 0; iip < UBIFS_LPT_FANOUT; iip++) {
			if (nnode->nbranch[iip].lnum)
				break;
		}
		if (iip >= UBIFS_LPT_FANOUT) {
			/*
			 * Should not happen, but we need to keep going
			 * if it does.
			 */
			iip = 0;
		}
		nnode = ubifs_get_nnode(c, nnode, iip);
		if (IS_ERR(nnode))
			return (void *)nnode;
	}

	for (iip = 0; iip < UBIFS_LPT_FANOUT; iip++)
		if (nnode->nbranch[iip].lnum)
			break;
	if (iip >= UBIFS_LPT_FANOUT)
		/* Should not happen, but we need to keep going if it does */
		iip = 0;
	return ubifs_get_pnode(c, nnode, iip);
}

/**
 * pnode_lookup - lookup a pnode in the LPT.
 * @c: UBIFS file-system description object
 * @i: pnode number (0 to main_lebs - 1)
 *
 * This function returns a pointer to the pnode on success or a negative
 * error code on failure.
 */
static struct ubifs_pnode *pnode_lookup(struct ubifs_info *c, int i)
{
	int err, h, iip, shft;
	struct ubifs_nnode *nnode;

	if (!c->nroot) {
		err = ubifs_read_nnode(c, NULL, 0);
		if (err)
			return ERR_PTR(err);
	}
	i <<= UBIFS_LPT_FANOUT_SHIFT;
	nnode = c->nroot;
	shft = c->lpt_hght * UBIFS_LPT_FANOUT_SHIFT;
	for (h = 1; h < c->lpt_hght; h++) {
		iip = ((i >> shft) & (UBIFS_LPT_FANOUT - 1));
		shft -= UBIFS_LPT_FANOUT_SHIFT;
		nnode = ubifs_get_nnode(c, nnode, iip);
		if (IS_ERR(nnode))
			return ERR_CAST(nnode);
	}
	iip = ((i >> shft) & (UBIFS_LPT_FANOUT - 1));
	return ubifs_get_pnode(c, nnode, iip);
}

/**
 * add_pnode_dirt - add dirty space to LPT LEB properties.
 * @c: UBIFS file-system description object
 * @pnode: pnode for which to add dirt
 */
static void add_pnode_dirt(struct ubifs_info *c, struct ubifs_pnode *pnode)
{
	ubifs_add_lpt_dirt(c, pnode->parent->nbranch[pnode->iip].lnum,
			   c->pnode_sz);
}

/**
 * do_make_pnode_dirty - mark a pnode dirty.
 * @c: UBIFS file-system description object
 * @pnode: pnode to mark dirty
 */
static void do_make_pnode_dirty(struct ubifs_info *c, struct ubifs_pnode *pnode)
{
	/* Assumes cnext list is empty i.e. not called during commit */
	if (!test_and_set_bit(DIRTY_CNODE, &pnode->flags)) {
		struct ubifs_nnode *nnode;

		c->dirty_pn_cnt += 1;
		add_pnode_dirt(c, pnode);
		/* Mark parent and ancestors dirty too */
		nnode = pnode->parent;
		while (nnode) {
			if (!test_and_set_bit(DIRTY_CNODE, &nnode->flags)) {
				c->dirty_nn_cnt += 1;
				ubifs_add_nnode_dirt(c, nnode);
				nnode = nnode->parent;
			} else
				break;
		}
	}
}

/**
 * make_tree_dirty - mark the entire LEB properties tree dirty.
 * @c: UBIFS file-system description object
 *
 * This function is used by the "small" LPT model to cause the entire LEB
 * properties tree to be written.  The "small" LPT model does not use LPT
 * garbage collection because it is more efficient to write the entire tree
 * (because it is small).
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int make_tree_dirty(struct ubifs_info *c)
{
	struct ubifs_pnode *pnode;

	pnode = pnode_lookup(c, 0);
	if (IS_ERR(pnode))
		return PTR_ERR(pnode);

	while (pnode) {
		do_make_pnode_dirty(c, pnode);
		pnode = next_pnode_to_dirty(c, pnode);
		if (IS_ERR(pnode))
			return PTR_ERR(pnode);
	}
	return 0;
}

/**
 * need_write_all - determine if the LPT area is running out of free space.
 * @c: UBIFS file-system description object
 *
 * This function returns %1 if the LPT area is running out of free space and %0
 * if it is not.
 */
static int need_write_all(struct ubifs_info *c)
{
	long long free = 0;
	int i;

	for (i = 0; i < c->lpt_lebs; i++) {
		if (i + c->lpt_first == c->nhead_lnum)
			free += c->leb_size - c->nhead_offs;
		else if (c->ltab[i].free == c->leb_size)
			free += c->leb_size;
		else if (c->ltab[i].free + c->ltab[i].dirty == c->leb_size)
			free += c->leb_size;
	}
	/* Less than twice the size left */
	if (free <= c->lpt_sz * 2)
		return 1;
	return 0;
}

/**
 * lpt_tgc_start - start trivial garbage collection of LPT LEBs.
 * @c: UBIFS file-system description object
 *
 * LPT trivial garbage collection is where a LPT LEB contains only dirty and
 * free space and so may be reused as soon as the next commit is completed.
 * This function is called during start commit to mark LPT LEBs for trivial GC.
 */
static void lpt_tgc_start(struct ubifs_info *c)
{
	int i;

	for (i = 0; i < c->lpt_lebs; i++) {
		if (i + c->lpt_first == c->nhead_lnum)
			continue;
		if (c->ltab[i].dirty > 0 &&
		    c->ltab[i].free + c->ltab[i].dirty == c->leb_size) {
			c->ltab[i].tgc = 1;
			c->ltab[i].free = c->leb_size;
			c->ltab[i].dirty = 0;
			dbg_lp("LEB %d", i + c->lpt_first);
		}
	}
}

/**
 * lpt_tgc_end - end trivial garbage collection of LPT LEBs.
 * @c: UBIFS file-system description object
 *
 * LPT trivial garbage collection is where a LPT LEB contains only dirty and
 * free space and so may be reused as soon as the next commit is completed.
 * This function is called after the commit is completed (master node has been
 * written) and un-maps LPT LEBs that were marked for trivial GC.
 */
static int lpt_tgc_end(struct ubifs_info *c)
{
	int i, err;

	for (i = 0; i < c->lpt_lebs; i++)
		if (c->ltab[i].tgc) {
			err = ubifs_leb_unmap(c, i + c->lpt_first);
			if (err)
				return err;
			c->ltab[i].tgc = 0;
			dbg_lp("LEB %d", i + c->lpt_first);
		}
	return 0;
}

/**
 * populate_lsave - fill the lsave array with important LEB numbers.
 * @c: the UBIFS file-system description object
 *
 * This function is only called for the "big" model. It records a small number
 * of LEB numbers of important LEBs.  Important LEBs are ones that are (from
 * most important to least important): empty, freeable, freeable index, dirty
 * index, dirty or free. Upon mount, we read this list of LEB numbers and bring
 * their pnodes into memory.  That will stop us from having to scan the LPT
 * straight away. For the "small" model we assume that scanning the LPT is no
 * big deal.
 */
static void populate_lsave(struct ubifs_info *c)
{
	struct ubifs_lprops *lprops;
	struct ubifs_lpt_heap *heap;
	int i, cnt = 0;

	ubifs_assert(c->big_lpt);
	if (!(c->lpt_drty_flgs & LSAVE_DIRTY)) {
		c->lpt_drty_flgs |= LSAVE_DIRTY;
		ubifs_add_lpt_dirt(c, c->lsave_lnum, c->lsave_sz);
	}

	if (dbg_populate_lsave(c))
		return;

	list_for_each_entry(lprops, &c->empty_list, list) {
		c->lsave[cnt++] = lprops->lnum;
		if (cnt >= c->lsave_cnt)
			return;
	}
	list_for_each_entry(lprops, &c->freeable_list, list) {
		c->lsave[cnt++] = lprops->lnum;
		if (cnt >= c->lsave_cnt)
			return;
	}
	list_for_each_entry(lprops, &c->frdi_idx_list, list) {
		c->lsave[cnt++] = lprops->lnum;
		if (cnt >= c->lsave_cnt)
			return;
	}
	heap = &c->lpt_heap[LPROPS_DIRTY_IDX - 1];
	for (i = 0; i < heap->cnt; i++) {
		c->lsave[cnt++] = heap->arr[i]->lnum;
		if (cnt >= c->lsave_cnt)
			return;
	}
	heap = &c->lpt_heap[LPROPS_DIRTY - 1];
	for (i = 0; i < heap->cnt; i++) {
		c->lsave[cnt++] = heap->arr[i]->lnum;
		if (cnt >= c->lsave_cnt)
			return;
	}
	heap = &c->lpt_heap[LPROPS_FREE - 1];
	for (i = 0; i < heap->cnt; i++) {
		c->lsave[cnt++] = heap->arr[i]->lnum;
		if (cnt >= c->lsave_cnt)
			return;
	}
	/* Fill it up completely */
	while (cnt < c->lsave_cnt)
		c->lsave[cnt++] = c->main_first;
}

/**
 * nnode_lookup - lookup a nnode in the LPT.
 * @c: UBIFS file-system description object
 * @i: nnode number
 *
 * This function returns a pointer to the nnode on success or a negative
 * error code on failure.
 */
static struct ubifs_nnode *nnode_lookup(struct ubifs_info *c, int i)
{
	int err, iip;
	struct ubifs_nnode *nnode;

	if (!c->nroot) {
		err = ubifs_read_nnode(c, NULL, 0);
		if (err)
			return ERR_PTR(err);
	}
	nnode = c->nroot;
	while (1) {
		iip = i & (UBIFS_LPT_FANOUT - 1);
		i >>= UBIFS_LPT_FANOUT_SHIFT;
		if (!i)
			break;
		nnode = ubifs_get_nnode(c, nnode, iip);
		if (IS_ERR(nnode))
			return nnode;
	}
	return nnode;
}

/**
 * make_nnode_dirty - find a nnode and, if found, make it dirty.
 * @c: UBIFS file-system description object
 * @node_num: nnode number of nnode to make dirty
 * @lnum: LEB number where nnode was written
 * @offs: offset where nnode was written
 *
 * This function is used by LPT garbage collection.  LPT garbage collection is
 * used only for the "big" LPT model (c->big_lpt == 1).  Garbage collection
 * simply involves marking all the nodes in the LEB being garbage-collected as
 * dirty.  The dirty nodes are written next commit, after which the LEB is free
 * to be reused.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int make_nnode_dirty(struct ubifs_info *c, int node_num, int lnum,
			    int offs)
{
	struct ubifs_nnode *nnode;

	nnode = nnode_lookup(c, node_num);
	if (IS_ERR(nnode))
		return PTR_ERR(nnode);
	if (nnode->parent) {
		struct ubifs_nbranch *branch;

		branch = &nnode->parent->nbranch[nnode->iip];
		if (branch->lnum != lnum || branch->offs != offs)
			return 0; /* nnode is obsolete */
	} else if (c->lpt_lnum != lnum || c->lpt_offs != offs)
			return 0; /* nnode is obsolete */
	/* Assumes cnext list is empty i.e. not called during commit */
	if (!test_and_set_bit(DIRTY_CNODE, &nnode->flags)) {
		c->dirty_nn_cnt += 1;
		ubifs_add_nnode_dirt(c, nnode);
		/* Mark parent and ancestors dirty too */
		nnode = nnode->parent;
		while (nnode) {
			if (!test_and_set_bit(DIRTY_CNODE, &nnode->flags)) {
				c->dirty_nn_cnt += 1;
				ubifs_add_nnode_dirt(c, nnode);
				nnode = nnode->parent;
			} else
				break;
		}
	}
	return 0;
}

/**
 * make_pnode_dirty - find a pnode and, if found, make it dirty.
 * @c: UBIFS file-system description object
 * @node_num: pnode number of pnode to make dirty
 * @lnum: LEB number where pnode was written
 * @offs: offset where pnode was written
 *
 * This function is used by LPT garbage collection.  LPT garbage collection is
 * used only for the "big" LPT model (c->big_lpt == 1).  Garbage collection
 * simply involves marking all the nodes in the LEB being garbage-collected as
 * dirty.  The dirty nodes are written next commit, after which the LEB is free
 * to be reused.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int make_pnode_dirty(struct ubifs_info *c, int node_num, int lnum,
			    int offs)
{
	struct ubifs_pnode *pnode;
	struct ubifs_nbranch *branch;

	pnode = pnode_lookup(c, node_num);
	if (IS_ERR(pnode))
		return PTR_ERR(pnode);
	branch = &pnode->parent->nbranch[pnode->iip];
	if (branch->lnum != lnum || branch->offs != offs)
		return 0;
	do_make_pnode_dirty(c, pnode);
	return 0;
}

/**
 * make_ltab_dirty - make ltab node dirty.
 * @c: UBIFS file-system description object
 * @lnum: LEB number where ltab was written
 * @offs: offset where ltab was written
 *
 * This function is used by LPT garbage collection.  LPT garbage collection is
 * used only for the "big" LPT model (c->big_lpt == 1).  Garbage collection
 * simply involves marking all the nodes in the LEB being garbage-collected as
 * dirty.  The dirty nodes are written next commit, after which the LEB is free
 * to be reused.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int make_ltab_dirty(struct ubifs_info *c, int lnum, int offs)
{
	if (lnum != c->ltab_lnum || offs != c->ltab_offs)
		return 0; /* This ltab node is obsolete */
	if (!(c->lpt_drty_flgs & LTAB_DIRTY)) {
		c->lpt_drty_flgs |= LTAB_DIRTY;
		ubifs_add_lpt_dirt(c, c->ltab_lnum, c->ltab_sz);
	}
	return 0;
}

/**
 * make_lsave_dirty - make lsave node dirty.
 * @c: UBIFS file-system description object
 * @lnum: LEB number where lsave was written
 * @offs: offset where lsave was written
 *
 * This function is used by LPT garbage collection.  LPT garbage collection is
 * used only for the "big" LPT model (c->big_lpt == 1).  Garbage collection
 * simply involves marking all the nodes in the LEB being garbage-collected as
 * dirty.  The dirty nodes are written next commit, after which the LEB is free
 * to be reused.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int make_lsave_dirty(struct ubifs_info *c, int lnum, int offs)
{
	if (lnum != c->lsave_lnum || offs != c->lsave_offs)
		return 0; /* This lsave node is obsolete */
	if (!(c->lpt_drty_flgs & LSAVE_DIRTY)) {
		c->lpt_drty_flgs |= LSAVE_DIRTY;
		ubifs_add_lpt_dirt(c, c->lsave_lnum, c->lsave_sz);
	}
	return 0;
}

/**
 * make_node_dirty - make node dirty.
 * @c: UBIFS file-system description object
 * @node_type: LPT node type
 * @node_num: node number
 * @lnum: LEB number where node was written
 * @offs: offset where node was written
 *
 * This function is used by LPT garbage collection.  LPT garbage collection is
 * used only for the "big" LPT model (c->big_lpt == 1).  Garbage collection
 * simply involves marking all the nodes in the LEB being garbage-collected as
 * dirty.  The dirty nodes are written next commit, after which the LEB is free
 * to be reused.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int make_node_dirty(struct ubifs_info *c, int node_type, int node_num,
			   int lnum, int offs)
{
	switch (node_type) {
	case UBIFS_LPT_NNODE:
		return make_nnode_dirty(c, node_num, lnum, offs);
	case UBIFS_LPT_PNODE:
		return make_pnode_dirty(c, node_num, lnum, offs);
	case UBIFS_LPT_LTAB:
		return make_ltab_dirty(c, lnum, offs);
	case UBIFS_LPT_LSAVE:
		return make_lsave_dirty(c, lnum, offs);
	}
	return -EINVAL;
}

/**
 * get_lpt_node_len - return the length of a node based on its type.
 * @c: UBIFS file-system description object
 * @node_type: LPT node type
 */
static int get_lpt_node_len(const struct ubifs_info *c, int node_type)
{
	switch (node_type) {
	case UBIFS_LPT_NNODE:
		return c->nnode_sz;
	case UBIFS_LPT_PNODE:
		return c->pnode_sz;
	case UBIFS_LPT_LTAB:
		return c->ltab_sz;
	case UBIFS_LPT_LSAVE:
		return c->lsave_sz;
	}
	return 0;
}

/**
 * get_pad_len - return the length of padding in a buffer.
 * @c: UBIFS file-system description object
 * @buf: buffer
 * @len: length of buffer
 */
static int get_pad_len(const struct ubifs_info *c, uint8_t *buf, int len)
{
	int offs, pad_len;

	if (c->min_io_size == 1)
		return 0;
	offs = c->leb_size - len;
	pad_len = ALIGN(offs, c->min_io_size) - offs;
	return pad_len;
}

/**
 * get_lpt_node_type - return type (and node number) of a node in a buffer.
 * @c: UBIFS file-system description object
 * @buf: buffer
 * @node_num: node number is returned here
 */
static int get_lpt_node_type(const struct ubifs_info *c, uint8_t *buf,
			     int *node_num)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int pos = 0, node_type;

	node_type = ubifs_unpack_bits(&addr, &pos, UBIFS_LPT_TYPE_BITS);
	*node_num = ubifs_unpack_bits(&addr, &pos, c->pcnt_bits);
	return node_type;
}

/**
 * is_a_node - determine if a buffer contains a node.
 * @c: UBIFS file-system description object
 * @buf: buffer
 * @len: length of buffer
 *
 * This function returns %1 if the buffer contains a node or %0 if it does not.
 */
static int is_a_node(const struct ubifs_info *c, uint8_t *buf, int len)
{
	uint8_t *addr = buf + UBIFS_LPT_CRC_BYTES;
	int pos = 0, node_type, node_len;
	uint16_t crc, calc_crc;

	if (len < UBIFS_LPT_CRC_BYTES + (UBIFS_LPT_TYPE_BITS + 7) / 8)
		return 0;
	node_type = ubifs_unpack_bits(&addr, &pos, UBIFS_LPT_TYPE_BITS);
	if (node_type == UBIFS_LPT_NOT_A_NODE)
		return 0;
	node_len = get_lpt_node_len(c, node_type);
	if (!node_len || node_len > len)
		return 0;
	pos = 0;
	addr = buf;
	crc = ubifs_unpack_bits(&addr, &pos, UBIFS_LPT_CRC_BITS);
	calc_crc = crc16(-1, buf + UBIFS_LPT_CRC_BYTES,
			 node_len - UBIFS_LPT_CRC_BYTES);
	if (crc != calc_crc)
		return 0;
	return 1;
}

/**
 * lpt_gc_lnum - garbage collect a LPT LEB.
 * @c: UBIFS file-system description object
 * @lnum: LEB number to garbage collect
 *
 * LPT garbage collection is used only for the "big" LPT model
 * (c->big_lpt == 1).  Garbage collection simply involves marking all the nodes
 * in the LEB being garbage-collected as dirty.  The dirty nodes are written
 * next commit, after which the LEB is free to be reused.
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int lpt_gc_lnum(struct ubifs_info *c, int lnum)
{
	int err, len = c->leb_size, node_type, node_num, node_len, offs;
	void *buf = c->lpt_buf;

	dbg_lp("LEB %d", lnum);

	err = ubifs_leb_read(c, lnum, buf, 0, c->leb_size, 1);
	if (err)
		return err;

	while (1) {
		if (!is_a_node(c, buf, len)) {
			int pad_len;

			pad_len = get_pad_len(c, buf, len);
			if (pad_len) {
				buf += pad_len;
				len -= pad_len;
				continue;
			}
			return 0;
		}
		node_type = get_lpt_node_type(c, buf, &node_num);
		node_len = get_lpt_node_len(c, node_type);
		offs = c->leb_size - len;
		ubifs_assert(node_len != 0);
		mutex_lock(&c->lp_mutex);
		err = make_node_dirty(c, node_type, node_num, lnum, offs);
		mutex_unlock(&c->lp_mutex);
		if (err)
			return err;
		buf += node_len;
		len -= node_len;
	}
	return 0;
}

/**
 * lpt_gc - LPT garbage collection.
 * @c: UBIFS file-system description object
 *
 * Select a LPT LEB for LPT garbage collection and call 'lpt_gc_lnum()'.
 * Returns %0 on success and a negative error code on failure.
 */
static int lpt_gc(struct ubifs_info *c)
{
	int i, lnum = -1, dirty = 0;

	mutex_lock(&c->lp_mutex);
	for (i = 0; i < c->lpt_lebs; i++) {
		ubifs_assert(!c->ltab[i].tgc);
		if (i + c->lpt_first == c->nhead_lnum ||
		    c->ltab[i].free + c->ltab[i].dirty == c->leb_size)
			continue;
		if (c->ltab[i].dirty > dirty) {
			dirty = c->ltab[i].dirty;
			lnum = i + c->lpt_first;
		}
	}
	mutex_unlock(&c->lp_mutex);
	if (lnum == -1)
		return -ENOSPC;
	return lpt_gc_lnum(c, lnum);
}

/**
 * ubifs_lpt_start_commit - UBIFS commit starts.
 * @c: the UBIFS file-system description object
 *
 * This function has to be called when UBIFS starts the commit operation.
 * This function "freezes" all currently dirty LEB properties and does not
 * change them anymore. Further changes are saved and tracked separately
 * because they are not part of this commit. This function returns zero in case
 * of success and a negative error code in case of failure.
 */
int ubifs_lpt_start_commit(struct ubifs_info *c)
{
	int err, cnt;

	dbg_lp("");

	mutex_lock(&c->lp_mutex);
	err = dbg_chk_lpt_free_spc(c);
	if (err)
		goto out;
	err = dbg_check_ltab(c);
	if (err)
		goto out;

	if (c->check_lpt_free) {
		/*
		 * We ensure there is enough free space in
		 * ubifs_lpt_post_commit() by marking nodes dirty. That
		 * information is lost when we unmount, so we also need
		 * to check free space once after mounting also.
		 */
		c->check_lpt_free = 0;
		while (need_write_all(c)) {
			mutex_unlock(&c->lp_mutex);
			err = lpt_gc(c);
			if (err)
				return err;
			mutex_lock(&c->lp_mutex);
		}
	}

	lpt_tgc_start(c);

	if (!c->dirty_pn_cnt) {
		dbg_cmt("no cnodes to commit");
		err = 0;
		goto out;
	}

	if (!c->big_lpt && need_write_all(c)) {
		/* If needed, write everything */
		err = make_tree_dirty(c);
		if (err)
			goto out;
		lpt_tgc_start(c);
	}

	if (c->big_lpt)
		populate_lsave(c);

	cnt = get_cnodes_to_commit(c);
	ubifs_assert(cnt != 0);

	err = layout_cnodes(c);
	if (err)
		goto out;

	/* Copy the LPT's own lprops for end commit to write */
	memcpy(c->ltab_cmt, c->ltab,
	       sizeof(struct ubifs_lpt_lprops) * c->lpt_lebs);
	c->lpt_drty_flgs &= ~(LTAB_DIRTY | LSAVE_DIRTY);

out:
	mutex_unlock(&c->lp_mutex);
	return err;
}

/**
 * free_obsolete_cnodes - free obsolete cnodes for commit end.
 * @c: UBIFS file-system description object
 */
static void free_obsolete_cnodes(struct ubifs_info *c)
{
	struct ubifs_cnode *cnode, *cnext;

	cnext = c->lpt_cnext;
	if (!cnext)
		return;
	do {
		cnode = cnext;
		cnext = cnode->cnext;
		if (test_bit(OBSOLETE_CNODE, &cnode->flags))
			kfree(cnode);
		else
			cnode->cnext = NULL;
	} while (cnext != c->lpt_cnext);
	c->lpt_cnext = NULL;
}

/**
 * ubifs_lpt_end_commit - finish the commit operation.
 * @c: the UBIFS file-system description object
 *
 * This function has to be called when the commit operation finishes. It
 * flushes the changes which were "frozen" by 'ubifs_lprops_start_commit()' to
 * the media. Returns zero in case of success and a negative error code in case
 * of failure.
 */
int ubifs_lpt_end_commit(struct ubifs_info *c)
{
	int err;

	dbg_lp("");

	if (!c->lpt_cnext)
		return 0;

	err = write_cnodes(c);
	if (err)
		return err;

	mutex_lock(&c->lp_mutex);
	free_obsolete_cnodes(c);
	mutex_unlock(&c->lp_mutex);

	return 0;
}

/**
 * ubifs_lpt_post_commit - post commit LPT trivial GC and LPT GC.
 * @c: UBIFS file-system description object
 *
 * LPT trivial GC is completed after a commit. Also LPT GC is done after a
 * commit for the "big" LPT model.
 */
int ubifs_lpt_post_commit(struct ubifs_info *c)
{
	int err;

	mutex_lock(&c->lp_mutex);
	err = lpt_tgc_end(c);
	if (err)
		goto out;
	if (c->big_lpt)
		while (need_write_all(c)) {
			mutex_unlock(&c->lp_mutex);
			err = lpt_gc(c);
			if (err)
				return err;
			mutex_lock(&c->lp_mutex);
		}
out:
	mutex_unlock(&c->lp_mutex);
	return err;
}

/**
 * first_nnode - find the first nnode in memory.
 * @c: UBIFS file-system description object
 * @hght: height of tree where nnode found is returned here
 *
 * This function returns a pointer to the nnode found or %NULL if no nnode is
 * found. This function is a helper to 'ubifs_lpt_free()'.
 */
static struct ubifs_nnode *first_nnode(struct ubifs_info *c, int *hght)
{
	struct ubifs_nnode *nnode;
	int h, i, found;

	nnode = c->nroot;
	*hght = 0;
	if (!nnode)
		return NULL;
	for (h = 1; h < c->lpt_hght; h++) {
		found = 0;
		for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
			if (nnode->nbranch[i].nnode) {
				found = 1;
				nnode = nnode->nbranch[i].nnode;
				*hght = h;
				break;
			}
		}
		if (!found)
			break;
	}
	return nnode;
}

/**
 * next_nnode - find the next nnode in memory.
 * @c: UBIFS file-system description object
 * @nnode: nnode from which to start.
 * @hght: height of tree where nnode is, is passed and returned here
 *
 * This function returns a pointer to the nnode found or %NULL if no nnode is
 * found. This function is a helper to 'ubifs_lpt_free()'.
 */
static struct ubifs_nnode *next_nnode(struct ubifs_info *c,
				      struct ubifs_nnode *nnode, int *hght)
{
	struct ubifs_nnode *parent;
	int iip, h, i, found;

	parent = nnode->parent;
	if (!parent)
		return NULL;
	if (nnode->iip == UBIFS_LPT_FANOUT - 1) {
		*hght -= 1;
		return parent;
	}
	for (iip = nnode->iip + 1; iip < UBIFS_LPT_FANOUT; iip++) {
		nnode = parent->nbranch[iip].nnode;
		if (nnode)
			break;
	}
	if (!nnode) {
		*hght -= 1;
		return parent;
	}
	for (h = *hght + 1; h < c->lpt_hght; h++) {
		found = 0;
		for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
			if (nnode->nbranch[i].nnode) {
				found = 1;
				nnode = nnode->nbranch[i].nnode;
				*hght = h;
				break;
			}
		}
		if (!found)
			break;
	}
	return nnode;
}

/**
 * ubifs_lpt_free - free resources owned by the LPT.
 * @c: UBIFS file-system description object
 * @wr_only: free only resources used for writing
 */
void ubifs_lpt_free(struct ubifs_info *c, int wr_only)
{
	struct ubifs_nnode *nnode;
	int i, hght;

	/* Free write-only things first */

	free_obsolete_cnodes(c); /* Leftover from a failed commit */

	vfree(c->ltab_cmt);
	c->ltab_cmt = NULL;
	vfree(c->lpt_buf);
	c->lpt_buf = NULL;
	kfree(c->lsave);
	c->lsave = NULL;

	if (wr_only)
		return;

	/* Now free the rest */

	nnode = first_nnode(c, &hght);
	while (nnode) {
		for (i = 0; i < UBIFS_LPT_FANOUT; i++)
			kfree(nnode->nbranch[i].nnode);
		nnode = next_nnode(c, nnode, &hght);
	}
	for (i = 0; i < LPROPS_HEAP_CNT; i++)
		kfree(c->lpt_heap[i].arr);
	kfree(c->dirty_idx.arr);
	kfree(c->nroot);
	vfree(c->ltab);
	kfree(c->lpt_nod_buf);
}

/*
 * Everything below is related to debugging.
 */

/**
 * dbg_is_all_ff - determine if a buffer contains only 0xFF bytes.
 * @buf: buffer
 * @len: buffer length
 */
static int dbg_is_all_ff(uint8_t *buf, int len)
{
	int i;

	for (i = 0; i < len; i++)
		if (buf[i] != 0xff)
			return 0;
	return 1;
}

/**
 * dbg_is_nnode_dirty - determine if a nnode is dirty.
 * @c: the UBIFS file-system description object
 * @lnum: LEB number where nnode was written
 * @offs: offset where nnode was written
 */
static int dbg_is_nnode_dirty(struct ubifs_info *c, int lnum, int offs)
{
	struct ubifs_nnode *nnode;
	int hght;

	/* Entire tree is in memory so first_nnode / next_nnode are OK */
	nnode = first_nnode(c, &hght);
	for (; nnode; nnode = next_nnode(c, nnode, &hght)) {
		struct ubifs_nbranch *branch;

		cond_resched();
		if (nnode->parent) {
			branch = &nnode->parent->nbranch[nnode->iip];
			if (branch->lnum != lnum || branch->offs != offs)
				continue;
			if (test_bit(DIRTY_CNODE, &nnode->flags))
				return 1;
			return 0;
		} else {
			if (c->lpt_lnum != lnum || c->lpt_offs != offs)
				continue;
			if (test_bit(DIRTY_CNODE, &nnode->flags))
				return 1;
			return 0;
		}
	}
	return 1;
}

/**
 * dbg_is_pnode_dirty - determine if a pnode is dirty.
 * @c: the UBIFS file-system description object
 * @lnum: LEB number where pnode was written
 * @offs: offset where pnode was written
 */
static int dbg_is_pnode_dirty(struct ubifs_info *c, int lnum, int offs)
{
	int i, cnt;

	cnt = DIV_ROUND_UP(c->main_lebs, UBIFS_LPT_FANOUT);
	for (i = 0; i < cnt; i++) {
		struct ubifs_pnode *pnode;
		struct ubifs_nbranch *branch;

		cond_resched();
		pnode = pnode_lookup(c, i);
		if (IS_ERR(pnode))
			return PTR_ERR(pnode);
		branch = &pnode->parent->nbranch[pnode->iip];
		if (branch->lnum != lnum || branch->offs != offs)
			continue;
		if (test_bit(DIRTY_CNODE, &pnode->flags))
			return 1;
		return 0;
	}
	return 1;
}

/**
 * dbg_is_ltab_dirty - determine if a ltab node is dirty.
 * @c: the UBIFS file-system description object
 * @lnum: LEB number where ltab node was written
 * @offs: offset where ltab node was written
 */
static int dbg_is_ltab_dirty(struct ubifs_info *c, int lnum, int offs)
{
	if (lnum != c->ltab_lnum || offs != c->ltab_offs)
		return 1;
	return (c->lpt_drty_flgs & LTAB_DIRTY) != 0;
}

/**
 * dbg_is_lsave_dirty - determine if a lsave node is dirty.
 * @c: the UBIFS file-system description object
 * @lnum: LEB number where lsave node was written
 * @offs: offset where lsave node was written
 */
static int dbg_is_lsave_dirty(struct ubifs_info *c, int lnum, int offs)
{
	if (lnum != c->lsave_lnum || offs != c->lsave_offs)
		return 1;
	return (c->lpt_drty_flgs & LSAVE_DIRTY) != 0;
}

/**
 * dbg_is_node_dirty - determine if a node is dirty.
 * @c: the UBIFS file-system description object
 * @node_type: node type
 * @lnum: LEB number where node was written
 * @offs: offset where node was written
 */
static int dbg_is_node_dirty(struct ubifs_info *c, int node_type, int lnum,
			     int offs)
{
	switch (node_type) {
	case UBIFS_LPT_NNODE:
		return dbg_is_nnode_dirty(c, lnum, offs);
	case UBIFS_LPT_PNODE:
		return dbg_is_pnode_dirty(c, lnum, offs);
	case UBIFS_LPT_LTAB:
		return dbg_is_ltab_dirty(c, lnum, offs);
	case UBIFS_LPT_LSAVE:
		return dbg_is_lsave_dirty(c, lnum, offs);
	}
	return 1;
}

/**
 * dbg_check_ltab_lnum - check the ltab for a LPT LEB number.
 * @c: the UBIFS file-system description object
 * @lnum: LEB number where node was written
 * @offs: offset where node was written
 *
 * This function returns %0 on success and a negative error code on failure.
 */
static int dbg_check_ltab_lnum(struct ubifs_info *c, int lnum)
{
	int err, len = c->leb_size, dirty = 0, node_type, node_num, node_len;
	int ret;
	void *buf, *p;

	if (!dbg_is_chk_lprops(c))
		return 0;

	buf = p = __vmalloc(c->leb_size, GFP_NOFS, PAGE_KERNEL);
	if (!buf) {
		ubifs_err("cannot allocate memory for ltab checking");
		return 0;
	}

	dbg_lp("LEB %d", lnum);

	err = ubifs_leb_read(c, lnum, buf, 0, c->leb_size, 1);
	if (err)
		goto out;

	while (1) {
		if (!is_a_node(c, p, len)) {
			int i, pad_len;

			pad_len = get_pad_len(c, p, len);
			if (pad_len) {
				p += pad_len;
				len -= pad_len;
				dirty += pad_len;
				continue;
			}
			if (!dbg_is_all_ff(p, len)) {
				ubifs_err("invalid empty space in LEB %d at %d",
					  lnum, c->leb_size - len);
				err = -EINVAL;
			}
			i = lnum - c->lpt_first;
			if (len != c->ltab[i].free) {
				ubifs_err("invalid free space in LEB %d (free %d, expected %d)",
					  lnum, len, c->ltab[i].free);
				err = -EINVAL;
			}
			if (dirty != c->ltab[i].dirty) {
				ubifs_err("invalid dirty space in LEB %d (dirty %d, expected %d)",
					  lnum, dirty, c->ltab[i].dirty);
				err = -EINVAL;
			}
			goto out;
		}
		node_type = get_lpt_node_type(c, p, &node_num);
		node_len = get_lpt_node_len(c, node_type);
		ret = dbg_is_node_dirty(c, node_type, lnum, c->leb_size - len);
		if (ret == 1)
			dirty += node_len;
		p += node_len;
		len -= node_len;
	}

	err = 0;
out:
	vfree(buf);
	return err;
}

/**
 * dbg_check_ltab - check the free and dirty space in the ltab.
 * @c: the UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int dbg_check_ltab(struct ubifs_info *c)
{
	int lnum, err, i, cnt;

	if (!dbg_is_chk_lprops(c))
		return 0;

	/* Bring the entire tree into memory */
	cnt = DIV_ROUND_UP(c->main_lebs, UBIFS_LPT_FANOUT);
	for (i = 0; i < cnt; i++) {
		struct ubifs_pnode *pnode;

		pnode = pnode_lookup(c, i);
		if (IS_ERR(pnode))
			return PTR_ERR(pnode);
		cond_resched();
	}

	/* Check nodes */
	err = dbg_check_lpt_nodes(c, (struct ubifs_cnode *)c->nroot, 0, 0);
	if (err)
		return err;

	/* Check each LEB */
	for (lnum = c->lpt_first; lnum <= c->lpt_last; lnum++) {
		err = dbg_check_ltab_lnum(c, lnum);
		if (err) {
			ubifs_err("failed at LEB %d", lnum);
			return err;
		}
	}

	dbg_lp("succeeded");
	return 0;
}

/**
 * dbg_chk_lpt_free_spc - check LPT free space is enough to write entire LPT.
 * @c: the UBIFS file-system description object
 *
 * This function returns %0 on success and a negative error code on failure.
 */
int dbg_chk_lpt_free_spc(struct ubifs_info *c)
{
	long long free = 0;
	int i;

	if (!dbg_is_chk_lprops(c))
		return 0;

	for (i = 0; i < c->lpt_lebs; i++) {
		if (c->ltab[i].tgc || c->ltab[i].cmt)
			continue;
		if (i + c->lpt_first == c->nhead_lnum)
			free += c->leb_size - c->nhead_offs;
		else if (c->ltab[i].free == c->leb_size)
			free += c->leb_size;
	}
	if (free < c->lpt_sz) {
		ubifs_err("LPT space error: free %lld lpt_sz %lld",
			  free, c->lpt_sz);
		ubifs_dump_lpt_info(c);
		ubifs_dump_lpt_lebs(c);
		dump_stack();
		return -EINVAL;
	}
	return 0;
}

/**
 * dbg_chk_lpt_sz - check LPT does not write more than LPT size.
 * @c: the UBIFS file-system description object
 * @action: what to do
 * @len: length written
 *
 * This function returns %0 on success and a negative error code on failure.
 * The @action argument may be one of:
 *   o %0 - LPT debugging checking starts, initialize debugging variables;
 *   o %1 - wrote an LPT node, increase LPT size by @len bytes;
 *   o %2 - switched to a different LEB and wasted @len bytes;
 *   o %3 - check that we've written the right number of bytes.
 *   o %4 - wasted @len bytes;
 */
int dbg_chk_lpt_sz(struct ubifs_info *c, int action, int len)
{
	struct ubifs_debug_info *d = c->dbg;
	long long chk_lpt_sz, lpt_sz;
	int err = 0;

	if (!dbg_is_chk_lprops(c))
		return 0;

	switch (action) {
	case 0:
		d->chk_lpt_sz = 0;
		d->chk_lpt_sz2 = 0;
		d->chk_lpt_lebs = 0;
		d->chk_lpt_wastage = 0;
		if (c->dirty_pn_cnt > c->pnode_cnt) {
			ubifs_err("dirty pnodes %d exceed max %d",
				  c->dirty_pn_cnt, c->pnode_cnt);
			err = -EINVAL;
		}
		if (c->dirty_nn_cnt > c->nnode_cnt) {
			ubifs_err("dirty nnodes %d exceed max %d",
				  c->dirty_nn_cnt, c->nnode_cnt);
			err = -EINVAL;
		}
		return err;
	case 1:
		d->chk_lpt_sz += len;
		return 0;
	case 2:
		d->chk_lpt_sz += len;
		d->chk_lpt_wastage += len;
		d->chk_lpt_lebs += 1;
		return 0;
	case 3:
		chk_lpt_sz = c->leb_size;
		chk_lpt_sz *= d->chk_lpt_lebs;
		chk_lpt_sz += len - c->nhead_offs;
		if (d->chk_lpt_sz != chk_lpt_sz) {
			ubifs_err("LPT wrote %lld but space used was %lld",
				  d->chk_lpt_sz, chk_lpt_sz);
			err = -EINVAL;
		}
		if (d->chk_lpt_sz > c->lpt_sz) {
			ubifs_err("LPT wrote %lld but lpt_sz is %lld",
				  d->chk_lpt_sz, c->lpt_sz);
			err = -EINVAL;
		}
		if (d->chk_lpt_sz2 && d->chk_lpt_sz != d->chk_lpt_sz2) {
			ubifs_err("LPT layout size %lld but wrote %lld",
				  d->chk_lpt_sz, d->chk_lpt_sz2);
			err = -EINVAL;
		}
		if (d->chk_lpt_sz2 && d->new_nhead_offs != len) {
			ubifs_err("LPT new nhead offs: expected %d was %d",
				  d->new_nhead_offs, len);
			err = -EINVAL;
		}
		lpt_sz = (long long)c->pnode_cnt * c->pnode_sz;
		lpt_sz += (long long)c->nnode_cnt * c->nnode_sz;
		lpt_sz += c->ltab_sz;
		if (c->big_lpt)
			lpt_sz += c->lsave_sz;
		if (d->chk_lpt_sz - d->chk_lpt_wastage > lpt_sz) {
			ubifs_err("LPT chk_lpt_sz %lld + waste %lld exceeds %lld",
				  d->chk_lpt_sz, d->chk_lpt_wastage, lpt_sz);
			err = -EINVAL;
		}
		if (err) {
			ubifs_dump_lpt_info(c);
			ubifs_dump_lpt_lebs(c);
			dump_stack();
		}
		d->chk_lpt_sz2 = d->chk_lpt_sz;
		d->chk_lpt_sz = 0;
		d->chk_lpt_wastage = 0;
		d->chk_lpt_lebs = 0;
		d->new_nhead_offs = len;
		return err;
	case 4:
		d->chk_lpt_sz += len;
		d->chk_lpt_wastage += len;
		return 0;
	default:
		return -EINVAL;
	}
}

/**
 * ubifs_dump_lpt_leb - dump an LPT LEB.
 * @c: UBIFS file-system description object
 * @lnum: LEB number to dump
 *
 * This function dumps an LEB from LPT area. Nodes in this area are very
 * different to nodes in the main area (e.g., they do not have common headers,
 * they do not have 8-byte alignments, etc), so we have a separate function to
 * dump LPT area LEBs. Note, LPT has to be locked by the caller.
 */
static void dump_lpt_leb(const struct ubifs_info *c, int lnum)
{
	int err, len = c->leb_size, node_type, node_num, node_len, offs;
	void *buf, *p;

	pr_err("(pid %d) start dumping LEB %d\n", current->pid, lnum);
	buf = p = __vmalloc(c->leb_size, GFP_NOFS, PAGE_KERNEL);
	if (!buf) {
		ubifs_err("cannot allocate memory to dump LPT");
		return;
	}

	err = ubifs_leb_read(c, lnum, buf, 0, c->leb_size, 1);
	if (err)
		goto out;

	while (1) {
		offs = c->leb_size - len;
		if (!is_a_node(c, p, len)) {
			int pad_len;

			pad_len = get_pad_len(c, p, len);
			if (pad_len) {
				pr_err("LEB %d:%d, pad %d bytes\n",
				       lnum, offs, pad_len);
				p += pad_len;
				len -= pad_len;
				continue;
			}
			if (len)
				pr_err("LEB %d:%d, free %d bytes\n",
				       lnum, offs, len);
			break;
		}

		node_type = get_lpt_node_type(c, p, &node_num);
		switch (node_type) {
		case UBIFS_LPT_PNODE:
		{
			node_len = c->pnode_sz;
			if (c->big_lpt)
				pr_err("LEB %d:%d, pnode num %d\n",
				       lnum, offs, node_num);
			else
				pr_err("LEB %d:%d, pnode\n", lnum, offs);
			break;
		}
		case UBIFS_LPT_NNODE:
		{
			int i;
			struct ubifs_nnode nnode;

			node_len = c->nnode_sz;
			if (c->big_lpt)
				pr_err("LEB %d:%d, nnode num %d, ",
				       lnum, offs, node_num);
			else
				pr_err("LEB %d:%d, nnode, ",
				       lnum, offs);
			err = ubifs_unpack_nnode(c, p, &nnode);
			if (err) {
				pr_err("failed to unpack_node, error %d\n",
				       err);
				break;
			}
			for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
				pr_cont("%d:%d", nnode.nbranch[i].lnum,
				       nnode.nbranch[i].offs);
				if (i != UBIFS_LPT_FANOUT - 1)
					pr_cont(", ");
			}
			pr_cont("\n");
			break;
		}
		case UBIFS_LPT_LTAB:
			node_len = c->ltab_sz;
			pr_err("LEB %d:%d, ltab\n", lnum, offs);
			break;
		case UBIFS_LPT_LSAVE:
			node_len = c->lsave_sz;
			pr_err("LEB %d:%d, lsave len\n", lnum, offs);
			break;
		default:
			ubifs_err("LPT node type %d not recognized", node_type);
			goto out;
		}

		p += node_len;
		len -= node_len;
	}

	pr_err("(pid %d) finish dumping LEB %d\n", current->pid, lnum);
out:
	vfree(buf);
	return;
}

/**
 * ubifs_dump_lpt_lebs - dump LPT lebs.
 * @c: UBIFS file-system description object
 *
 * This function dumps all LPT LEBs. The caller has to make sure the LPT is
 * locked.
 */
void ubifs_dump_lpt_lebs(const struct ubifs_info *c)
{
	int i;

	pr_err("(pid %d) start dumping all LPT LEBs\n", current->pid);
	for (i = 0; i < c->lpt_lebs; i++)
		dump_lpt_leb(c, i + c->lpt_first);
	pr_err("(pid %d) finish dumping all LPT LEBs\n", current->pid);
}

/**
 * dbg_populate_lsave - debugging version of 'populate_lsave()'
 * @c: UBIFS file-system description object
 *
 * This is a debugging version for 'populate_lsave()' which populates lsave
 * with random LEBs instead of useful LEBs, which is good for test coverage.
 * Returns zero if lsave has not been populated (this debugging feature is
 * disabled) an non-zero if lsave has been populated.
 */
static int dbg_populate_lsave(struct ubifs_info *c)
{
	struct ubifs_lprops *lprops;
	struct ubifs_lpt_heap *heap;
	int i;

	if (!dbg_is_chk_gen(c))
		return 0;
	if (prandom_u32() & 3)
		return 0;

	for (i = 0; i < c->lsave_cnt; i++)
		c->lsave[i] = c->main_first;

	list_for_each_entry(lprops, &c->empty_list, list)
		c->lsave[prandom_u32() % c->lsave_cnt] = lprops->lnum;
	list_for_each_entry(lprops, &c->freeable_list, list)
		c->lsave[prandom_u32() % c->lsave_cnt] = lprops->lnum;
	list_for_each_entry(lprops, &c->frdi_idx_list, list)
		c->lsave[prandom_u32() % c->lsave_cnt] = lprops->lnum;

	heap = &c->lpt_heap[LPROPS_DIRTY_IDX - 1];
	for (i = 0; i < heap->cnt; i++)
		c->lsave[prandom_u32() % c->lsave_cnt] = heap->arr[i]->lnum;
	heap = &c->lpt_heap[LPROPS_DIRTY - 1];
	for (i = 0; i < heap->cnt; i++)
		c->lsave[prandom_u32() % c->lsave_cnt] = heap->arr[i]->lnum;
	heap = &c->lpt_heap[LPROPS_FREE - 1];
	for (i = 0; i < heap->cnt; i++)
		c->lsave[prandom_u32() % c->lsave_cnt] = heap->arr[i]->lnum;

	return 1;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/lpt_commit.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Adrian Hunter
 *          Artem Bityutskiy (Битюцкий Артём)
 */

/*
 * This file contains miscelanious TNC-related functions shared betweend
 * different files. This file does not form any logically separate TNC
 * sub-system. The file was created because there is a lot of TNC code and
 * putting it all in one file would make that file too big and unreadable.
 */

// #include "ubifs.h"

/**
 * ubifs_tnc_levelorder_next - next TNC tree element in levelorder traversal.
 * @zr: root of the subtree to traverse
 * @znode: previous znode
 *
 * This function implements levelorder TNC traversal. The LNC is ignored.
 * Returns the next element or %NULL if @znode is already the last one.
 */
struct ubifs_znode *ubifs_tnc_levelorder_next(struct ubifs_znode *zr,
					      struct ubifs_znode *znode)
{
	int level, iip, level_search = 0;
	struct ubifs_znode *zn;

	ubifs_assert(zr);

	if (unlikely(!znode))
		return zr;

	if (unlikely(znode == zr)) {
		if (znode->level == 0)
			return NULL;
		return ubifs_tnc_find_child(zr, 0);
	}

	level = znode->level;

	iip = znode->iip;
	while (1) {
		ubifs_assert(znode->level <= zr->level);

		/*
		 * First walk up until there is a znode with next branch to
		 * look at.
		 */
		while (znode->parent != zr && iip >= znode->parent->child_cnt) {
			znode = znode->parent;
			iip = znode->iip;
		}

		if (unlikely(znode->parent == zr &&
			     iip >= znode->parent->child_cnt)) {
			/* This level is done, switch to the lower one */
			level -= 1;
			if (level_search || level < 0)
				/*
				 * We were already looking for znode at lower
				 * level ('level_search'). As we are here
				 * again, it just does not exist. Or all levels
				 * were finished ('level < 0').
				 */
				return NULL;

			level_search = 1;
			iip = -1;
			znode = ubifs_tnc_find_child(zr, 0);
			ubifs_assert(znode);
		}

		/* Switch to the next index */
		zn = ubifs_tnc_find_child(znode->parent, iip + 1);
		if (!zn) {
			/* No more children to look at, we have walk up */
			iip = znode->parent->child_cnt;
			continue;
		}

		/* Walk back down to the level we came from ('level') */
		while (zn->level != level) {
			znode = zn;
			zn = ubifs_tnc_find_child(zn, 0);
			if (!zn) {
				/*
				 * This path is not too deep so it does not
				 * reach 'level'. Try next path.
				 */
				iip = znode->iip;
				break;
			}
		}

		if (zn) {
			ubifs_assert(zn->level >= 0);
			return zn;
		}
	}
}

/**
 * ubifs_search_zbranch - search znode branch.
 * @c: UBIFS file-system description object
 * @znode: znode to search in
 * @key: key to search for
 * @n: znode branch slot number is returned here
 *
 * This is a helper function which search branch with key @key in @znode using
 * binary search. The result of the search may be:
 *   o exact match, then %1 is returned, and the slot number of the branch is
 *     stored in @n;
 *   o no exact match, then %0 is returned and the slot number of the left
 *     closest branch is returned in @n; the slot if all keys in this znode are
 *     greater than @key, then %-1 is returned in @n.
 */
int ubifs_search_zbranch(const struct ubifs_info *c,
			 const struct ubifs_znode *znode,
			 const union ubifs_key *key, int *n)
{
	int beg = 0, end = znode->child_cnt, uninitialized_var(mid);
	int uninitialized_var(cmp);
	const struct ubifs_zbranch *zbr = &znode->zbranch[0];

	ubifs_assert(end > beg);

	while (end > beg) {
		mid = (beg + end) >> 1;
		cmp = keys_cmp(c, key, &zbr[mid].key);
		if (cmp > 0)
			beg = mid + 1;
		else if (cmp < 0)
			end = mid;
		else {
			*n = mid;
			return 1;
		}
	}

	*n = end - 1;

	/* The insert point is after *n */
	ubifs_assert(*n >= -1 && *n < znode->child_cnt);
	if (*n == -1)
		ubifs_assert(keys_cmp(c, key, &zbr[0].key) < 0);
	else
		ubifs_assert(keys_cmp(c, key, &zbr[*n].key) > 0);
	if (*n + 1 < znode->child_cnt)
		ubifs_assert(keys_cmp(c, key, &zbr[*n + 1].key) < 0);

	return 0;
}

/**
 * ubifs_tnc_postorder_first - find first znode to do postorder tree traversal.
 * @znode: znode to start at (root of the sub-tree to traverse)
 *
 * Find the lowest leftmost znode in a subtree of the TNC tree. The LNC is
 * ignored.
 */
struct ubifs_znode *ubifs_tnc_postorder_first(struct ubifs_znode *znode)
{
	if (unlikely(!znode))
		return NULL;

	while (znode->level > 0) {
		struct ubifs_znode *child;

		child = ubifs_tnc_find_child(znode, 0);
		if (!child)
			return znode;
		znode = child;
	}

	return znode;
}

/**
 * ubifs_tnc_postorder_next - next TNC tree element in postorder traversal.
 * @znode: previous znode
 *
 * This function implements postorder TNC traversal. The LNC is ignored.
 * Returns the next element or %NULL if @znode is already the last one.
 */
struct ubifs_znode *ubifs_tnc_postorder_next(struct ubifs_znode *znode)
{
	struct ubifs_znode *zn;

	ubifs_assert(znode);
	if (unlikely(!znode->parent))
		return NULL;

	/* Switch to the next index in the parent */
	zn = ubifs_tnc_find_child(znode->parent, znode->iip + 1);
	if (!zn)
		/* This is in fact the last child, return parent */
		return znode->parent;

	/* Go to the first znode in this new subtree */
	return ubifs_tnc_postorder_first(zn);
}

/**
 * ubifs_destroy_tnc_subtree - destroy all znodes connected to a subtree.
 * @znode: znode defining subtree to destroy
 *
 * This function destroys subtree of the TNC tree. Returns number of clean
 * znodes in the subtree.
 */
long ubifs_destroy_tnc_subtree(struct ubifs_znode *znode)
{
	struct ubifs_znode *zn = ubifs_tnc_postorder_first(znode);
	long clean_freed = 0;
	int n;

	ubifs_assert(zn);
	while (1) {
		for (n = 0; n < zn->child_cnt; n++) {
			if (!zn->zbranch[n].znode)
				continue;

			if (zn->level > 0 &&
			    !ubifs_zn_dirty(zn->zbranch[n].znode))
				clean_freed += 1;

			cond_resched();
			kfree(zn->zbranch[n].znode);
		}

		if (zn == znode) {
			if (!ubifs_zn_dirty(zn))
				clean_freed += 1;
			kfree(zn);
			return clean_freed;
		}

		zn = ubifs_tnc_postorder_next(zn);
	}
}

/**
 * read_znode - read an indexing node from flash and fill znode.
 * @c: UBIFS file-system description object
 * @lnum: LEB of the indexing node to read
 * @offs: node offset
 * @len: node length
 * @znode: znode to read to
 *
 * This function reads an indexing node from the flash media and fills znode
 * with the read data. Returns zero in case of success and a negative error
 * code in case of failure. The read indexing node is validated and if anything
 * is wrong with it, this function prints complaint messages and returns
 * %-EINVAL.
 */
static int read_znode(struct ubifs_info *c, int lnum, int offs, int len,
		      struct ubifs_znode *znode)
{
	int i, err, type, cmp;
	struct ubifs_idx_node *idx;

	idx = kmalloc(c->max_idx_node_sz, GFP_NOFS);
	if (!idx)
		return -ENOMEM;

	err = ubifs_read_node(c, idx, UBIFS_IDX_NODE, len, lnum, offs);
	if (err < 0) {
		kfree(idx);
		return err;
	}

	znode->child_cnt = le16_to_cpu(idx->child_cnt);
	znode->level = le16_to_cpu(idx->level);

	dbg_tnc("LEB %d:%d, level %d, %d branch",
		lnum, offs, znode->level, znode->child_cnt);

	if (znode->child_cnt > c->fanout || znode->level > UBIFS_MAX_LEVELS) {
		ubifs_err("current fanout %d, branch count %d",
			  c->fanout, znode->child_cnt);
		ubifs_err("max levels %d, znode level %d",
			  UBIFS_MAX_LEVELS, znode->level);
		err = 1;
		goto out_dump;
	}

	for (i = 0; i < znode->child_cnt; i++) {
		const struct ubifs_branch *br = ubifs_idx_branch(c, idx, i);
		struct ubifs_zbranch *zbr = &znode->zbranch[i];

		key_read(c, &br->key, &zbr->key);
		zbr->lnum = le32_to_cpu(br->lnum);
		zbr->offs = le32_to_cpu(br->offs);
		zbr->len  = le32_to_cpu(br->len);
		zbr->znode = NULL;

		/* Validate branch */

		if (zbr->lnum < c->main_first ||
		    zbr->lnum >= c->leb_cnt || zbr->offs < 0 ||
		    zbr->offs + zbr->len > c->leb_size || zbr->offs & 7) {
			ubifs_err("bad branch %d", i);
			err = 2;
			goto out_dump;
		}

		switch (key_type(c, &zbr->key)) {
		case UBIFS_INO_KEY:
		case UBIFS_DATA_KEY:
		case UBIFS_DENT_KEY:
		case UBIFS_XENT_KEY:
			break;
		default:
			ubifs_err("bad key type at slot %d: %d",
				  i, key_type(c, &zbr->key));
			err = 3;
			goto out_dump;
		}

		if (znode->level)
			continue;

		type = key_type(c, &zbr->key);
		if (c->ranges[type].max_len == 0) {
			if (zbr->len != c->ranges[type].len) {
				ubifs_err("bad target node (type %d) length (%d)",
					  type, zbr->len);
				ubifs_err("have to be %d", c->ranges[type].len);
				err = 4;
				goto out_dump;
			}
		} else if (zbr->len < c->ranges[type].min_len ||
			   zbr->len > c->ranges[type].max_len) {
			ubifs_err("bad target node (type %d) length (%d)",
				  type, zbr->len);
			ubifs_err("have to be in range of %d-%d",
				  c->ranges[type].min_len,
				  c->ranges[type].max_len);
			err = 5;
			goto out_dump;
		}
	}

	/*
	 * Ensure that the next key is greater or equivalent to the
	 * previous one.
	 */
	for (i = 0; i < znode->child_cnt - 1; i++) {
		const union ubifs_key *key1, *key2;

		key1 = &znode->zbranch[i].key;
		key2 = &znode->zbranch[i + 1].key;

		cmp = keys_cmp(c, key1, key2);
		if (cmp > 0) {
			ubifs_err("bad key order (keys %d and %d)", i, i + 1);
			err = 6;
			goto out_dump;
		} else if (cmp == 0 && !is_hash_key(c, key1)) {
			/* These can only be keys with colliding hash */
			ubifs_err("keys %d and %d are not hashed but equivalent",
				  i, i + 1);
			err = 7;
			goto out_dump;
		}
	}

	kfree(idx);
	return 0;

out_dump:
	ubifs_err("bad indexing node at LEB %d:%d, error %d", lnum, offs, err);
	ubifs_dump_node(c, idx);
	kfree(idx);
	return -EINVAL;
}

/**
 * ubifs_load_znode - load znode to TNC cache.
 * @c: UBIFS file-system description object
 * @zbr: znode branch
 * @parent: znode's parent
 * @iip: index in parent
 *
 * This function loads znode pointed to by @zbr into the TNC cache and
 * returns pointer to it in case of success and a negative error code in case
 * of failure.
 */
struct ubifs_znode *ubifs_load_znode(struct ubifs_info *c,
				     struct ubifs_zbranch *zbr,
				     struct ubifs_znode *parent, int iip)
{
	int err;
	struct ubifs_znode *znode;

	ubifs_assert(!zbr->znode);
	/*
	 * A slab cache is not presently used for znodes because the znode size
	 * depends on the fanout which is stored in the superblock.
	 */
	znode = kzalloc(c->max_znode_sz, GFP_NOFS);
	if (!znode)
		return ERR_PTR(-ENOMEM);

	err = read_znode(c, zbr->lnum, zbr->offs, zbr->len, znode);
	if (err)
		goto out;

	atomic_long_inc(&c->clean_zn_cnt);

	/*
	 * Increment the global clean znode counter as well. It is OK that
	 * global and per-FS clean znode counters may be inconsistent for some
	 * short time (because we might be preempted at this point), the global
	 * one is only used in shrinker.
	 */
	atomic_long_inc(&ubifs_clean_zn_cnt);

	zbr->znode = znode;
	znode->parent = parent;
	znode->time = get_seconds();
	znode->iip = iip;

	return znode;

out:
	kfree(znode);
	return ERR_PTR(err);
}

/**
 * ubifs_tnc_read_node - read a leaf node from the flash media.
 * @c: UBIFS file-system description object
 * @zbr: key and position of the node
 * @node: node is returned here
 *
 * This function reads a node defined by @zbr from the flash media. Returns
 * zero in case of success or a negative negative error code in case of
 * failure.
 */
int ubifs_tnc_read_node(struct ubifs_info *c, struct ubifs_zbranch *zbr,
			void *node)
{
	union ubifs_key key1, *key = &zbr->key;
	int err, type = key_type(c, key);
	struct ubifs_wbuf *wbuf;

	/*
	 * 'zbr' has to point to on-flash node. The node may sit in a bud and
	 * may even be in a write buffer, so we have to take care about this.
	 */
	wbuf = ubifs_get_wbuf(c, zbr->lnum);
	if (wbuf)
		err = ubifs_read_node_wbuf(wbuf, node, type, zbr->len,
					   zbr->lnum, zbr->offs);
	else
		err = ubifs_read_node(c, node, type, zbr->len, zbr->lnum,
				      zbr->offs);

	if (err) {
		dbg_tnck(key, "key ");
		return err;
	}

	/* Make sure the key of the read node is correct */
	key_read(c, node + UBIFS_KEY_OFFSET, &key1);
	if (!keys_eq(c, key, &key1)) {
		ubifs_err("bad key in node at LEB %d:%d",
			  zbr->lnum, zbr->offs);
		dbg_tnck(key, "looked for key ");
		dbg_tnck(&key1, "but found node's key ");
		ubifs_dump_node(c, node);
		return -EINVAL;
	}

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/tnc_misc.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file implements UBIFS extended attributes support.
 *
 * Extended attributes are implemented as regular inodes with attached data,
 * which limits extended attribute size to UBIFS block size (4KiB). Names of
 * extended attributes are described by extended attribute entries (xentries),
 * which are almost identical to directory entries, but have different key type.
 *
 * In other words, the situation with extended attributes is very similar to
 * directories. Indeed, any inode (but of course not xattr inodes) may have a
 * number of associated xentries, just like directory inodes have associated
 * directory entries. Extended attribute entries store the name of the extended
 * attribute, the host inode number, and the extended attribute inode number.
 * Similarly, direntries store the name, the parent and the target inode
 * numbers. Thus, most of the common UBIFS mechanisms may be re-used for
 * extended attributes.
 *
 * The number of extended attributes is not limited, but there is Linux
 * limitation on the maximum possible size of the list of all extended
 * attributes associated with an inode (%XATTR_LIST_MAX), so UBIFS makes sure
 * the sum of all extended attribute names of the inode does not exceed that
 * limit.
 *
 * Extended attributes are synchronous, which means they are written to the
 * flash media synchronously and there is no write-back for extended attribute
 * inodes. The extended attribute values are not stored in compressed form on
 * the media.
 *
 * Since extended attributes are represented by regular inodes, they are cached
 * in the VFS inode cache. The xentries are cached in the LNC cache (see
 * tnc.c).
 *
 * ACL support is not implemented.
 */

// #include "ubifs.h"
#include <linux/fs.h>
// #include <linux/slab.h>
#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>
#include "../../inc/__fss.h"

/*
 * Limit the number of extended attributes per inode so that the total size
 * (@xattr_size) is guaranteeded to fit in an 'unsigned int'.
 */
#define MAX_XATTRS_PER_INODE 65535

/*
 * Extended attribute type constants.
 *
 * USER_XATTR: user extended attribute ("user.*")
 * TRUSTED_XATTR: trusted extended attribute ("trusted.*)
 * SECURITY_XATTR: security extended attribute ("security.*")
 */
enum {
	USER_XATTR,
	TRUSTED_XATTR,
	SECURITY_XATTR,
};

static const struct inode_operations empty_iops;
static const struct file_operations empty_fops;

/**
 * create_xattr - create an extended attribute.
 * @c: UBIFS file-system description object
 * @host: host inode
 * @nm: extended attribute name
 * @value: extended attribute value
 * @size: size of extended attribute value
 *
 * This is a helper function which creates an extended attribute of name @nm
 * and value @value for inode @host. The host inode is also updated on flash
 * because the ctime and extended attribute accounting data changes. This
 * function returns zero in case of success and a negative error code in case
 * of failure.
 */
static int create_xattr(struct ubifs_info *c, struct inode *host,
			const struct qstr *nm, const void *value, int size)
{
	int err, names_len;
	struct inode *inode;
	struct ubifs_inode *ui, *host_ui = ubifs_inode(host);
	struct ubifs_budget_req req = { .new_ino = 1, .new_dent = 1,
				.new_ino_d = ALIGN(size, 8), .dirtied_ino = 1,
				.dirtied_ino_d = ALIGN(host_ui->data_len, 8) };

	if (host_ui->xattr_cnt >= MAX_XATTRS_PER_INODE) {
		ubifs_err("inode %lu already has too many xattrs (%d), cannot create more",
			  host->i_ino, host_ui->xattr_cnt);
		return -ENOSPC;
	}
	/*
	 * Linux limits the maximum size of the extended attribute names list
	 * to %XATTR_LIST_MAX. This means we should not allow creating more
	 * extended attributes if the name list becomes larger. This limitation
	 * is artificial for UBIFS, though.
	 */
	names_len = host_ui->xattr_names + host_ui->xattr_cnt + nm->len + 1;
	if (names_len > XATTR_LIST_MAX) {
		ubifs_err("cannot add one more xattr name to inode %lu, total names length would become %d, max. is %d",
			  host->i_ino, names_len, XATTR_LIST_MAX);
		return -ENOSPC;
	}

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	inode = ubifs_new_inode(c, host, S_IFREG | S_IRWXUGO);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_budg;
	}

	/* Re-define all operations to be "nothing" */
	inode->i_mapping->a_ops = &empty_aops;
	inode->i_op = &empty_iops;
	inode->i_fop = &empty_fops;

	inode->i_flags |= S_SYNC | S_NOATIME | S_NOCMTIME | S_NOQUOTA;
	ui = ubifs_inode(inode);
	ui->xattr = 1;
	ui->flags |= UBIFS_XATTR_FL;
	ui->data = kmemdup(value, size, GFP_NOFS);
	if (!ui->data) {
		err = -ENOMEM;
		goto out_free;
	}
	inode->i_size = ui->ui_size = size;
	ui->data_len = size;

	mutex_lock(&host_ui->ui_mutex);
	host->i_ctime = ubifs_current_time(host);
	host_ui->xattr_cnt += 1;
	host_ui->xattr_size += CALC_DENT_SIZE(nm->len);
	host_ui->xattr_size += CALC_XATTR_BYTES(size);
	host_ui->xattr_names += nm->len;

	err = ubifs_jnl_update(c, host, nm, inode, 0, 1);
	if (err)
		goto out_cancel;
	mutex_unlock(&host_ui->ui_mutex);

	ubifs_release_budget(c, &req);
	insert_inode_hash(inode);
	iput(inode);
	return 0;

out_cancel:
	host_ui->xattr_cnt -= 1;
	host_ui->xattr_size -= CALC_DENT_SIZE(nm->len);
	host_ui->xattr_size -= CALC_XATTR_BYTES(size);
	mutex_unlock(&host_ui->ui_mutex);
out_free:
	make_bad_inode(inode);
	iput(inode);
out_budg:
	ubifs_release_budget(c, &req);
	return err;
}

/**
 * change_xattr - change an extended attribute.
 * @c: UBIFS file-system description object
 * @host: host inode
 * @inode: extended attribute inode
 * @value: extended attribute value
 * @size: size of extended attribute value
 *
 * This helper function changes the value of extended attribute @inode with new
 * data from @value. Returns zero in case of success and a negative error code
 * in case of failure.
 */
static int change_xattr(struct ubifs_info *c, struct inode *host,
			struct inode *inode, const void *value, int size)
{
	int err;
	struct ubifs_inode *host_ui = ubifs_inode(host);
	struct ubifs_inode *ui = ubifs_inode(inode);
	struct ubifs_budget_req req = { .dirtied_ino = 2,
		.dirtied_ino_d = ALIGN(size, 8) + ALIGN(host_ui->data_len, 8) };

	ubifs_assert(ui->data_len == inode->i_size);
	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	kfree(ui->data);
	ui->data = kmemdup(value, size, GFP_NOFS);
	if (!ui->data) {
		err = -ENOMEM;
		goto out_free;
	}
	inode->i_size = ui->ui_size = size;
	ui->data_len = size;

	mutex_lock(&host_ui->ui_mutex);
	host->i_ctime = ubifs_current_time(host);
	host_ui->xattr_size -= CALC_XATTR_BYTES(ui->data_len);
	host_ui->xattr_size += CALC_XATTR_BYTES(size);

	/*
	 * It is important to write the host inode after the xattr inode
	 * because if the host inode gets synchronized (via 'fsync()'), then
	 * the extended attribute inode gets synchronized, because it goes
	 * before the host inode in the write-buffer.
	 */
	err = ubifs_jnl_change_xattr(c, inode, host);
	if (err)
		goto out_cancel;
	mutex_unlock(&host_ui->ui_mutex);

	ubifs_release_budget(c, &req);
	return 0;

out_cancel:
	host_ui->xattr_size -= CALC_XATTR_BYTES(size);
	host_ui->xattr_size += CALC_XATTR_BYTES(ui->data_len);
	mutex_unlock(&host_ui->ui_mutex);
	make_bad_inode(inode);
out_free:
	ubifs_release_budget(c, &req);
	return err;
}

/**
 * check_namespace - check extended attribute name-space.
 * @nm: extended attribute name
 *
 * This function makes sure the extended attribute name belongs to one of the
 * supported extended attribute name-spaces. Returns name-space index in case
 * of success and a negative error code in case of failure.
 */
static int check_namespace(const struct qstr *nm)
{
	int type;

	if (nm->len > UBIFS_MAX_NLEN)
		return -ENAMETOOLONG;

	if (!strncmp(nm->name, XATTR_TRUSTED_PREFIX,
		     XATTR_TRUSTED_PREFIX_LEN)) {
		if (nm->name[sizeof(XATTR_TRUSTED_PREFIX) - 1] == '\0')
			return -EINVAL;
		type = TRUSTED_XATTR;
	} else if (!strncmp(nm->name, XATTR_USER_PREFIX,
				      XATTR_USER_PREFIX_LEN)) {
		if (nm->name[XATTR_USER_PREFIX_LEN] == '\0')
			return -EINVAL;
		type = USER_XATTR;
	} else if (!strncmp(nm->name, XATTR_SECURITY_PREFIX,
				     XATTR_SECURITY_PREFIX_LEN)) {
		if (nm->name[sizeof(XATTR_SECURITY_PREFIX) - 1] == '\0')
			return -EINVAL;
		type = SECURITY_XATTR;
	} else
		return -EOPNOTSUPP;

	return type;
}

static struct inode *iget_xattr(struct ubifs_info *c, ino_t inum)
{
	struct inode *inode;

	inode = ubifs_iget(c->vfs_sb, inum);
	if (IS_ERR(inode)) {
		ubifs_err("dead extended attribute entry, error %d",
			  (int)PTR_ERR(inode));
		return inode;
	}
	if (ubifs_inode(inode)->xattr)
		return inode;
	ubifs_err("corrupt extended attribute entry");
	iput(inode);
	return ERR_PTR(-EINVAL);
}

static int setxattr(struct inode *host, const char *name, const void *value,
		    size_t size, int flags)
{
	struct inode *inode;
	struct ubifs_info *c = host->i_sb->s_fs_info;
	struct qstr nm = QSTR_INIT(name, strlen(name));
	struct ubifs_dent_node *xent;
	union ubifs_key key;
	int err, type;

	ubifs_assert(mutex_is_locked(&host->i_mutex));

	if (size > UBIFS_MAX_INO_DATA)
		return -ERANGE;

	type = check_namespace(&nm);
	if (type < 0)
		return type;

	xent = kmalloc(UBIFS_MAX_XENT_NODE_SZ, GFP_NOFS);
	if (!xent)
		return -ENOMEM;

	/*
	 * The extended attribute entries are stored in LNC, so multiple
	 * look-ups do not involve reading the flash.
	 */
	xent_key_init(c, &key, host->i_ino, &nm);
	err = ubifs_tnc_lookup_nm(c, &key, xent, &nm);
	if (err) {
		if (err != -ENOENT)
			goto out_free;

		if (flags & XATTR_REPLACE)
			/* We are asked not to create the xattr */
			err = -ENODATA;
		else
			err = create_xattr(c, host, &nm, value, size);
		goto out_free;
	}

	if (flags & XATTR_CREATE) {
		/* We are asked not to replace the xattr */
		err = -EEXIST;
		goto out_free;
	}

	inode = iget_xattr(c, le64_to_cpu(xent->inum));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_free;
	}

	err = change_xattr(c, host, inode, value, size);
	iput(inode);

out_free:
	kfree(xent);
	return err;
}

int ubifs_setxattr(struct dentry *dentry, const char *name,
		   const void *value, size_t size, int flags)
{
	dbg_gen("xattr '%s', host ino %lu ('%pd'), size %zd",
		name, dentry->d_inode->i_ino, dentry, size);

	return setxattr(dentry->d_inode, name, value, size, flags);
}

ssize_t ubifs_getxattr(struct dentry *dentry, const char *name, void *buf,
		       size_t size)
{
	struct inode *inode, *host = dentry->d_inode;
	struct ubifs_info *c = host->i_sb->s_fs_info;
	struct qstr nm = QSTR_INIT(name, strlen(name));
	struct ubifs_inode *ui;
	struct ubifs_dent_node *xent;
	union ubifs_key key;
	int err;

	dbg_gen("xattr '%s', ino %lu ('%pd'), buf size %zd", name,
		host->i_ino, dentry, size);

	err = check_namespace(&nm);
	if (err < 0)
		return err;

	xent = kmalloc(UBIFS_MAX_XENT_NODE_SZ, GFP_NOFS);
	if (!xent)
		return -ENOMEM;

	xent_key_init(c, &key, host->i_ino, &nm);
	err = ubifs_tnc_lookup_nm(c, &key, xent, &nm);
	if (err) {
		if (err == -ENOENT)
			err = -ENODATA;
		goto out_unlock;
	}

	inode = iget_xattr(c, le64_to_cpu(xent->inum));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_unlock;
	}

	ui = ubifs_inode(inode);
	ubifs_assert(inode->i_size == ui->data_len);
	ubifs_assert(ubifs_inode(host)->xattr_size > ui->data_len);

	if (buf) {
		/* If @buf is %NULL we are supposed to return the length */
		if (ui->data_len > size) {
			ubifs_err("buffer size %zd, xattr len %d",
				  size, ui->data_len);
			err = -ERANGE;
			goto out_iput;
		}

		memcpy(buf, ui->data, ui->data_len);
	}
	err = ui->data_len;

out_iput:
	iput(inode);
out_unlock:
	kfree(xent);
	return err;
}

ssize_t ubifs_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	union ubifs_key key;
	struct inode *host = dentry->d_inode;
	struct ubifs_info *c = host->i_sb->s_fs_info;
	struct ubifs_inode *host_ui = ubifs_inode(host);
	struct ubifs_dent_node *xent, *pxent = NULL;
	int err, len, written = 0;
	struct qstr nm = { .name = NULL };

	dbg_gen("ino %lu ('%pd'), buffer size %zd", host->i_ino,
		dentry, size);

	len = host_ui->xattr_names + host_ui->xattr_cnt;
	if (!buffer)
		/*
		 * We should return the minimum buffer size which will fit a
		 * null-terminated list of all the extended attribute names.
		 */
		return len;

	if (len > size)
		return -ERANGE;

	lowest_xent_key(c, &key, host->i_ino);
	while (1) {
		int type;

		xent = ubifs_tnc_next_ent(c, &key, &nm);
		if (IS_ERR(xent)) {
			err = PTR_ERR(xent);
			break;
		}

		nm.name = xent->name;
		nm.len = le16_to_cpu(xent->nlen);

		type = check_namespace(&nm);
		if (unlikely(type < 0)) {
			err = type;
			break;
		}

		/* Show trusted namespace only for "power" users */
		if (type != TRUSTED_XATTR || capable(CAP_SYS_ADMIN)) {
			memcpy(buffer + written, nm.name, nm.len + 1);
			written += nm.len + 1;
		}

		kfree(pxent);
		pxent = xent;
		key_read(c, &xent->key, &key);
	}

	kfree(pxent);
	if (err != -ENOENT) {
		ubifs_err("cannot find next direntry, error %d", err);
		return err;
	}

	ubifs_assert(written <= size);
	return written;
}

static int remove_xattr(struct ubifs_info *c, struct inode *host,
			struct inode *inode, const struct qstr *nm)
{
	int err;
	struct ubifs_inode *host_ui = ubifs_inode(host);
	struct ubifs_inode *ui = ubifs_inode(inode);
	struct ubifs_budget_req req = { .dirtied_ino = 2, .mod_dent = 1,
				.dirtied_ino_d = ALIGN(host_ui->data_len, 8) };

	ubifs_assert(ui->data_len == inode->i_size);

	err = ubifs_budget_space(c, &req);
	if (err)
		return err;

	mutex_lock(&host_ui->ui_mutex);
	host->i_ctime = ubifs_current_time(host);
	host_ui->xattr_cnt -= 1;
	host_ui->xattr_size -= CALC_DENT_SIZE(nm->len);
	host_ui->xattr_size -= CALC_XATTR_BYTES(ui->data_len);
	host_ui->xattr_names -= nm->len;

	err = ubifs_jnl_delete_xattr(c, host, inode, nm);
	if (err)
		goto out_cancel;
	mutex_unlock(&host_ui->ui_mutex);

	ubifs_release_budget(c, &req);
	return 0;

out_cancel:
	host_ui->xattr_cnt += 1;
	host_ui->xattr_size += CALC_DENT_SIZE(nm->len);
	host_ui->xattr_size += CALC_XATTR_BYTES(ui->data_len);
	mutex_unlock(&host_ui->ui_mutex);
	ubifs_release_budget(c, &req);
	make_bad_inode(inode);
	return err;
}

int ubifs_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode, *host = dentry->d_inode;
	struct ubifs_info *c = host->i_sb->s_fs_info;
	struct qstr nm = QSTR_INIT(name, strlen(name));
	struct ubifs_dent_node *xent;
	union ubifs_key key;
	int err;

	dbg_gen("xattr '%s', ino %lu ('%pd')", name,
		host->i_ino, dentry);
	ubifs_assert(mutex_is_locked(&host->i_mutex));

	err = check_namespace(&nm);
	if (err < 0)
		return err;

	xent = kmalloc(UBIFS_MAX_XENT_NODE_SZ, GFP_NOFS);
	if (!xent)
		return -ENOMEM;

	xent_key_init(c, &key, host->i_ino, &nm);
	err = ubifs_tnc_lookup_nm(c, &key, xent, &nm);
	if (err) {
		if (err == -ENOENT)
			err = -ENODATA;
		goto out_free;
	}

	inode = iget_xattr(c, le64_to_cpu(xent->inum));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_free;
	}

	ubifs_assert(inode->i_nlink == 1);
	clear_nlink(inode);
	err = remove_xattr(c, host, inode, &nm);
	if (err)
		set_nlink(inode, 1);

	/* If @i_nlink is 0, 'iput()' will delete the inode */
	iput(inode);

out_free:
	kfree(xent);
	return err;
}

static size_t security_listxattr(struct dentry *d, char *list, size_t list_size,
				 const char *name, size_t name_len, int flags)
{
	const int prefix_len = XATTR_SECURITY_PREFIX_LEN;
	const size_t total_len = prefix_len + name_len + 1;

	if (list && total_len <= list_size) {
		memcpy(list, XATTR_SECURITY_PREFIX, prefix_len);
		memcpy(list + prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}

	return total_len;
}

static int security_getxattr(struct dentry *d, const char *name, void *buffer,
		      size_t size, int flags)
{
	return ubifs_getxattr(d, name, buffer, size);
}

static int security_setxattr(struct dentry *d, const char *name,
			     const void *value, size_t size, int flags,
			     int handler_flags)
{
	return ubifs_setxattr(d, name, value, size, flags);
}

static const struct xattr_handler ubifs_xattr_security_handler = {
	.prefix = XATTR_SECURITY_PREFIX,
	.list   = security_listxattr,
	.get    = security_getxattr,
	.set    = security_setxattr,
};

const struct xattr_handler *ubifs_xattr_handlers[] = {
	&ubifs_xattr_security_handler,
	NULL,
};

static int init_xattrs(struct inode *inode, const struct xattr *xattr_array,
		      void *fs_info)
{
	const struct xattr *xattr;
	char *name;
	int err = 0;

	for (xattr = xattr_array; xattr->name != NULL; xattr++) {
		name = kmalloc(XATTR_SECURITY_PREFIX_LEN +
			       strlen(xattr->name) + 1, GFP_NOFS);
		if (!name) {
			err = -ENOMEM;
			break;
		}
		strcpy(name, XATTR_SECURITY_PREFIX);
		strcpy(name + XATTR_SECURITY_PREFIX_LEN, xattr->name);
		err = setxattr(inode, name, xattr->value, xattr->value_len, 0);
		kfree(name);
		if (err < 0)
			break;
	}

	return err;
}

int ubifs_init_security(struct inode *dentry, struct inode *inode,
			const struct qstr *qstr)
{
	int err;

	mutex_lock(&inode->i_mutex);
	err = security_inode_init_security(inode, dentry, qstr,
					   &init_xattrs, 0);
	mutex_unlock(&inode->i_mutex);

	if (err)
		ubifs_err("cannot initialize security for inode %lu, error %d",
			  inode->i_ino, err);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/xattr.c */
/************************************************************/
/*
 * This file is part of UBIFS.
 *
 * Copyright (C) 2006-2008 Nokia Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Authors: Artem Bityutskiy (Битюцкий Артём)
 *          Adrian Hunter
 */

/*
 * This file implements most of the debugging stuff which is compiled in only
 * when it is enabled. But some debugging check functions are implemented in
 * corresponding subsystem, just because they are closely related and utilize
 * various local functions of those subsystems.
 */

// #include <linux/module.h>
#include <linux/debugfs.h>
// #include <linux/math64.h>
#include <linux/uaccess.h>
// #include <linux/random.h>
// #include "ubifs.h"
#include "../../inc/__fss.h"

static DEFINE_SPINLOCK(dbg_lock);

static const char *get_key_fmt(int fmt)
{
	switch (fmt) {
	case UBIFS_SIMPLE_KEY_FMT:
		return "simple";
	default:
		return "unknown/invalid format";
	}
}

static const char *get_key_hash(int hash)
{
	switch (hash) {
	case UBIFS_KEY_HASH_R5:
		return "R5";
	case UBIFS_KEY_HASH_TEST:
		return "test";
	default:
		return "unknown/invalid name hash";
	}
}

static const char *get_key_type(int type)
{
	switch (type) {
	case UBIFS_INO_KEY:
		return "inode";
	case UBIFS_DENT_KEY:
		return "direntry";
	case UBIFS_XENT_KEY:
		return "xentry";
	case UBIFS_DATA_KEY:
		return "data";
	case UBIFS_TRUN_KEY:
		return "truncate";
	default:
		return "unknown/invalid key";
	}
}

static const char *get_dent_type(int type)
{
	switch (type) {
	case UBIFS_ITYPE_REG:
		return "file";
	case UBIFS_ITYPE_DIR:
		return "dir";
	case UBIFS_ITYPE_LNK:
		return "symlink";
	case UBIFS_ITYPE_BLK:
		return "blkdev";
	case UBIFS_ITYPE_CHR:
		return "char dev";
	case UBIFS_ITYPE_FIFO:
		return "fifo";
	case UBIFS_ITYPE_SOCK:
		return "socket";
	default:
		return "unknown/invalid type";
	}
}

const char *dbg_snprintf_key(const struct ubifs_info *c,
			     const union ubifs_key *key, char *buffer, int len)
{
	char *p = buffer;
	int type = key_type(c, key);

	if (c->key_fmt == UBIFS_SIMPLE_KEY_FMT) {
		switch (type) {
		case UBIFS_INO_KEY:
			len -= snprintf(p, len, "(%lu, %s)",
					(unsigned long)key_inum(c, key),
					get_key_type(type));
			break;
		case UBIFS_DENT_KEY:
		case UBIFS_XENT_KEY:
			len -= snprintf(p, len, "(%lu, %s, %#08x)",
					(unsigned long)key_inum(c, key),
					get_key_type(type), key_hash(c, key));
			break;
		case UBIFS_DATA_KEY:
			len -= snprintf(p, len, "(%lu, %s, %u)",
					(unsigned long)key_inum(c, key),
					get_key_type(type), key_block(c, key));
			break;
		case UBIFS_TRUN_KEY:
			len -= snprintf(p, len, "(%lu, %s)",
					(unsigned long)key_inum(c, key),
					get_key_type(type));
			break;
		default:
			len -= snprintf(p, len, "(bad key type: %#08x, %#08x)",
					key->u32[0], key->u32[1]);
		}
	} else
		len -= snprintf(p, len, "bad key format %d", c->key_fmt);
	ubifs_assert(len > 0);
	return p;
}

const char *dbg_ntype(int type)
{
	switch (type) {
	case UBIFS_PAD_NODE:
		return "padding node";
	case UBIFS_SB_NODE:
		return "superblock node";
	case UBIFS_MST_NODE:
		return "master node";
	case UBIFS_REF_NODE:
		return "reference node";
	case UBIFS_INO_NODE:
		return "inode node";
	case UBIFS_DENT_NODE:
		return "direntry node";
	case UBIFS_XENT_NODE:
		return "xentry node";
	case UBIFS_DATA_NODE:
		return "data node";
	case UBIFS_TRUN_NODE:
		return "truncate node";
	case UBIFS_IDX_NODE:
		return "indexing node";
	case UBIFS_CS_NODE:
		return "commit start node";
	case UBIFS_ORPH_NODE:
		return "orphan node";
	default:
		return "unknown node";
	}
}

static const char *dbg_gtype(int type)
{
	switch (type) {
	case UBIFS_NO_NODE_GROUP:
		return "no node group";
	case UBIFS_IN_NODE_GROUP:
		return "in node group";
	case UBIFS_LAST_OF_NODE_GROUP:
		return "last of node group";
	default:
		return "unknown";
	}
}

const char *dbg_cstate(int cmt_state)
{
	switch (cmt_state) {
	case COMMIT_RESTING:
		return "commit resting";
	case COMMIT_BACKGROUND:
		return "background commit requested";
	case COMMIT_REQUIRED:
		return "commit required";
	case COMMIT_RUNNING_BACKGROUND:
		return "BACKGROUND commit running";
	case COMMIT_RUNNING_REQUIRED:
		return "commit running and required";
	case COMMIT_BROKEN:
		return "broken commit";
	default:
		return "unknown commit state";
	}
}

const char *dbg_jhead(int jhead)
{
	switch (jhead) {
	case GCHD:
		return "0 (GC)";
	case BASEHD:
		return "1 (base)";
	case DATAHD:
		return "2 (data)";
	default:
		return "unknown journal head";
	}
}

static void dump_ch(const struct ubifs_ch *ch)
{
	pr_err("\tmagic          %#x\n", le32_to_cpu(ch->magic));
	pr_err("\tcrc            %#x\n", le32_to_cpu(ch->crc));
	pr_err("\tnode_type      %d (%s)\n", ch->node_type,
	       dbg_ntype(ch->node_type));
	pr_err("\tgroup_type     %d (%s)\n", ch->group_type,
	       dbg_gtype(ch->group_type));
	pr_err("\tsqnum          %llu\n",
	       (unsigned long long)le64_to_cpu(ch->sqnum));
	pr_err("\tlen            %u\n", le32_to_cpu(ch->len));
}

void ubifs_dump_inode(struct ubifs_info *c, const struct inode *inode)
{
	const struct ubifs_inode *ui = ubifs_inode(inode);
	struct qstr nm = { .name = NULL };
	union ubifs_key key;
	struct ubifs_dent_node *dent, *pdent = NULL;
	int count = 2;

	pr_err("Dump in-memory inode:");
	pr_err("\tinode          %lu\n", inode->i_ino);
	pr_err("\tsize           %llu\n",
	       (unsigned long long)i_size_read(inode));
	pr_err("\tnlink          %u\n", inode->i_nlink);
	pr_err("\tuid            %u\n", (unsigned int)i_uid_read(inode));
	pr_err("\tgid            %u\n", (unsigned int)i_gid_read(inode));
	pr_err("\tatime          %u.%u\n",
	       (unsigned int)inode->i_atime.tv_sec,
	       (unsigned int)inode->i_atime.tv_nsec);
	pr_err("\tmtime          %u.%u\n",
	       (unsigned int)inode->i_mtime.tv_sec,
	       (unsigned int)inode->i_mtime.tv_nsec);
	pr_err("\tctime          %u.%u\n",
	       (unsigned int)inode->i_ctime.tv_sec,
	       (unsigned int)inode->i_ctime.tv_nsec);
	pr_err("\tcreat_sqnum    %llu\n", ui->creat_sqnum);
	pr_err("\txattr_size     %u\n", ui->xattr_size);
	pr_err("\txattr_cnt      %u\n", ui->xattr_cnt);
	pr_err("\txattr_names    %u\n", ui->xattr_names);
	pr_err("\tdirty          %u\n", ui->dirty);
	pr_err("\txattr          %u\n", ui->xattr);
	pr_err("\tbulk_read      %u\n", ui->xattr);
	pr_err("\tsynced_i_size  %llu\n",
	       (unsigned long long)ui->synced_i_size);
	pr_err("\tui_size        %llu\n",
	       (unsigned long long)ui->ui_size);
	pr_err("\tflags          %d\n", ui->flags);
	pr_err("\tcompr_type     %d\n", ui->compr_type);
	pr_err("\tlast_page_read %lu\n", ui->last_page_read);
	pr_err("\tread_in_a_row  %lu\n", ui->read_in_a_row);
	pr_err("\tdata_len       %d\n", ui->data_len);

	if (!S_ISDIR(inode->i_mode))
		return;

	pr_err("List of directory entries:\n");
	ubifs_assert(!mutex_is_locked(&c->tnc_mutex));

	lowest_dent_key(c, &key, inode->i_ino);
	while (1) {
		dent = ubifs_tnc_next_ent(c, &key, &nm);
		if (IS_ERR(dent)) {
			if (PTR_ERR(dent) != -ENOENT)
				pr_err("error %ld\n", PTR_ERR(dent));
			break;
		}

		pr_err("\t%d: %s (%s)\n",
		       count++, dent->name, get_dent_type(dent->type));

		nm.name = dent->name;
		nm.len = le16_to_cpu(dent->nlen);
		kfree(pdent);
		pdent = dent;
		key_read(c, &dent->key, &key);
	}
	kfree(pdent);
}

void ubifs_dump_node(const struct ubifs_info *c, const void *node)
{
	int i, n;
	union ubifs_key key;
	const struct ubifs_ch *ch = node;
	char key_buf[DBG_KEY_BUF_LEN];

	/* If the magic is incorrect, just hexdump the first bytes */
	if (le32_to_cpu(ch->magic) != UBIFS_NODE_MAGIC) {
		pr_err("Not a node, first %zu bytes:", UBIFS_CH_SZ);
		print_hex_dump(KERN_ERR, "", DUMP_PREFIX_OFFSET, 32, 1,
			       (void *)node, UBIFS_CH_SZ, 1);
		return;
	}

	spin_lock(&dbg_lock);
	dump_ch(node);

	switch (ch->node_type) {
	case UBIFS_PAD_NODE:
	{
		const struct ubifs_pad_node *pad = node;

		pr_err("\tpad_len        %u\n", le32_to_cpu(pad->pad_len));
		break;
	}
	case UBIFS_SB_NODE:
	{
		const struct ubifs_sb_node *sup = node;
		unsigned int sup_flags = le32_to_cpu(sup->flags);

		pr_err("\tkey_hash       %d (%s)\n",
		       (int)sup->key_hash, get_key_hash(sup->key_hash));
		pr_err("\tkey_fmt        %d (%s)\n",
		       (int)sup->key_fmt, get_key_fmt(sup->key_fmt));
		pr_err("\tflags          %#x\n", sup_flags);
		pr_err("\tbig_lpt        %u\n",
		       !!(sup_flags & UBIFS_FLG_BIGLPT));
		pr_err("\tspace_fixup    %u\n",
		       !!(sup_flags & UBIFS_FLG_SPACE_FIXUP));
		pr_err("\tmin_io_size    %u\n", le32_to_cpu(sup->min_io_size));
		pr_err("\tleb_size       %u\n", le32_to_cpu(sup->leb_size));
		pr_err("\tleb_cnt        %u\n", le32_to_cpu(sup->leb_cnt));
		pr_err("\tmax_leb_cnt    %u\n", le32_to_cpu(sup->max_leb_cnt));
		pr_err("\tmax_bud_bytes  %llu\n",
		       (unsigned long long)le64_to_cpu(sup->max_bud_bytes));
		pr_err("\tlog_lebs       %u\n", le32_to_cpu(sup->log_lebs));
		pr_err("\tlpt_lebs       %u\n", le32_to_cpu(sup->lpt_lebs));
		pr_err("\torph_lebs      %u\n", le32_to_cpu(sup->orph_lebs));
		pr_err("\tjhead_cnt      %u\n", le32_to_cpu(sup->jhead_cnt));
		pr_err("\tfanout         %u\n", le32_to_cpu(sup->fanout));
		pr_err("\tlsave_cnt      %u\n", le32_to_cpu(sup->lsave_cnt));
		pr_err("\tdefault_compr  %u\n",
		       (int)le16_to_cpu(sup->default_compr));
		pr_err("\trp_size        %llu\n",
		       (unsigned long long)le64_to_cpu(sup->rp_size));
		pr_err("\trp_uid         %u\n", le32_to_cpu(sup->rp_uid));
		pr_err("\trp_gid         %u\n", le32_to_cpu(sup->rp_gid));
		pr_err("\tfmt_version    %u\n", le32_to_cpu(sup->fmt_version));
		pr_err("\ttime_gran      %u\n", le32_to_cpu(sup->time_gran));
		pr_err("\tUUID           %pUB\n", sup->uuid);
		break;
	}
	case UBIFS_MST_NODE:
	{
		const struct ubifs_mst_node *mst = node;

		pr_err("\thighest_inum   %llu\n",
		       (unsigned long long)le64_to_cpu(mst->highest_inum));
		pr_err("\tcommit number  %llu\n",
		       (unsigned long long)le64_to_cpu(mst->cmt_no));
		pr_err("\tflags          %#x\n", le32_to_cpu(mst->flags));
		pr_err("\tlog_lnum       %u\n", le32_to_cpu(mst->log_lnum));
		pr_err("\troot_lnum      %u\n", le32_to_cpu(mst->root_lnum));
		pr_err("\troot_offs      %u\n", le32_to_cpu(mst->root_offs));
		pr_err("\troot_len       %u\n", le32_to_cpu(mst->root_len));
		pr_err("\tgc_lnum        %u\n", le32_to_cpu(mst->gc_lnum));
		pr_err("\tihead_lnum     %u\n", le32_to_cpu(mst->ihead_lnum));
		pr_err("\tihead_offs     %u\n", le32_to_cpu(mst->ihead_offs));
		pr_err("\tindex_size     %llu\n",
		       (unsigned long long)le64_to_cpu(mst->index_size));
		pr_err("\tlpt_lnum       %u\n", le32_to_cpu(mst->lpt_lnum));
		pr_err("\tlpt_offs       %u\n", le32_to_cpu(mst->lpt_offs));
		pr_err("\tnhead_lnum     %u\n", le32_to_cpu(mst->nhead_lnum));
		pr_err("\tnhead_offs     %u\n", le32_to_cpu(mst->nhead_offs));
		pr_err("\tltab_lnum      %u\n", le32_to_cpu(mst->ltab_lnum));
		pr_err("\tltab_offs      %u\n", le32_to_cpu(mst->ltab_offs));
		pr_err("\tlsave_lnum     %u\n", le32_to_cpu(mst->lsave_lnum));
		pr_err("\tlsave_offs     %u\n", le32_to_cpu(mst->lsave_offs));
		pr_err("\tlscan_lnum     %u\n", le32_to_cpu(mst->lscan_lnum));
		pr_err("\tleb_cnt        %u\n", le32_to_cpu(mst->leb_cnt));
		pr_err("\tempty_lebs     %u\n", le32_to_cpu(mst->empty_lebs));
		pr_err("\tidx_lebs       %u\n", le32_to_cpu(mst->idx_lebs));
		pr_err("\ttotal_free     %llu\n",
		       (unsigned long long)le64_to_cpu(mst->total_free));
		pr_err("\ttotal_dirty    %llu\n",
		       (unsigned long long)le64_to_cpu(mst->total_dirty));
		pr_err("\ttotal_used     %llu\n",
		       (unsigned long long)le64_to_cpu(mst->total_used));
		pr_err("\ttotal_dead     %llu\n",
		       (unsigned long long)le64_to_cpu(mst->total_dead));
		pr_err("\ttotal_dark     %llu\n",
		       (unsigned long long)le64_to_cpu(mst->total_dark));
		break;
	}
	case UBIFS_REF_NODE:
	{
		const struct ubifs_ref_node *ref = node;

		pr_err("\tlnum           %u\n", le32_to_cpu(ref->lnum));
		pr_err("\toffs           %u\n", le32_to_cpu(ref->offs));
		pr_err("\tjhead          %u\n", le32_to_cpu(ref->jhead));
		break;
	}
	case UBIFS_INO_NODE:
	{
		const struct ubifs_ino_node *ino = node;

		key_read(c, &ino->key, &key);
		pr_err("\tkey            %s\n",
		       dbg_snprintf_key(c, &key, key_buf, DBG_KEY_BUF_LEN));
		pr_err("\tcreat_sqnum    %llu\n",
		       (unsigned long long)le64_to_cpu(ino->creat_sqnum));
		pr_err("\tsize           %llu\n",
		       (unsigned long long)le64_to_cpu(ino->size));
		pr_err("\tnlink          %u\n", le32_to_cpu(ino->nlink));
		pr_err("\tatime          %lld.%u\n",
		       (long long)le64_to_cpu(ino->atime_sec),
		       le32_to_cpu(ino->atime_nsec));
		pr_err("\tmtime          %lld.%u\n",
		       (long long)le64_to_cpu(ino->mtime_sec),
		       le32_to_cpu(ino->mtime_nsec));
		pr_err("\tctime          %lld.%u\n",
		       (long long)le64_to_cpu(ino->ctime_sec),
		       le32_to_cpu(ino->ctime_nsec));
		pr_err("\tuid            %u\n", le32_to_cpu(ino->uid));
		pr_err("\tgid            %u\n", le32_to_cpu(ino->gid));
		pr_err("\tmode           %u\n", le32_to_cpu(ino->mode));
		pr_err("\tflags          %#x\n", le32_to_cpu(ino->flags));
		pr_err("\txattr_cnt      %u\n", le32_to_cpu(ino->xattr_cnt));
		pr_err("\txattr_size     %u\n", le32_to_cpu(ino->xattr_size));
		pr_err("\txattr_names    %u\n", le32_to_cpu(ino->xattr_names));
		pr_err("\tcompr_type     %#x\n",
		       (int)le16_to_cpu(ino->compr_type));
		pr_err("\tdata len       %u\n", le32_to_cpu(ino->data_len));
		break;
	}
	case UBIFS_DENT_NODE:
	case UBIFS_XENT_NODE:
	{
		const struct ubifs_dent_node *dent = node;
		int nlen = le16_to_cpu(dent->nlen);

		key_read(c, &dent->key, &key);
		pr_err("\tkey            %s\n",
		       dbg_snprintf_key(c, &key, key_buf, DBG_KEY_BUF_LEN));
		pr_err("\tinum           %llu\n",
		       (unsigned long long)le64_to_cpu(dent->inum));
		pr_err("\ttype           %d\n", (int)dent->type);
		pr_err("\tnlen           %d\n", nlen);
		pr_err("\tname           ");

		if (nlen > UBIFS_MAX_NLEN)
			pr_err("(bad name length, not printing, bad or corrupted node)");
		else {
			for (i = 0; i < nlen && dent->name[i]; i++)
				pr_cont("%c", dent->name[i]);
		}
		pr_cont("\n");

		break;
	}
	case UBIFS_DATA_NODE:
	{
		const struct ubifs_data_node *dn = node;
		int dlen = le32_to_cpu(ch->len) - UBIFS_DATA_NODE_SZ;

		key_read(c, &dn->key, &key);
		pr_err("\tkey            %s\n",
		       dbg_snprintf_key(c, &key, key_buf, DBG_KEY_BUF_LEN));
		pr_err("\tsize           %u\n", le32_to_cpu(dn->size));
		pr_err("\tcompr_typ      %d\n",
		       (int)le16_to_cpu(dn->compr_type));
		pr_err("\tdata size      %d\n", dlen);
		pr_err("\tdata:\n");
		print_hex_dump(KERN_ERR, "\t", DUMP_PREFIX_OFFSET, 32, 1,
			       (void *)&dn->data, dlen, 0);
		break;
	}
	case UBIFS_TRUN_NODE:
	{
		const struct ubifs_trun_node *trun = node;

		pr_err("\tinum           %u\n", le32_to_cpu(trun->inum));
		pr_err("\told_size       %llu\n",
		       (unsigned long long)le64_to_cpu(trun->old_size));
		pr_err("\tnew_size       %llu\n",
		       (unsigned long long)le64_to_cpu(trun->new_size));
		break;
	}
	case UBIFS_IDX_NODE:
	{
		const struct ubifs_idx_node *idx = node;

		n = le16_to_cpu(idx->child_cnt);
		pr_err("\tchild_cnt      %d\n", n);
		pr_err("\tlevel          %d\n", (int)le16_to_cpu(idx->level));
		pr_err("\tBranches:\n");

		for (i = 0; i < n && i < c->fanout - 1; i++) {
			const struct ubifs_branch *br;

			br = ubifs_idx_branch(c, idx, i);
			key_read(c, &br->key, &key);
			pr_err("\t%d: LEB %d:%d len %d key %s\n",
			       i, le32_to_cpu(br->lnum), le32_to_cpu(br->offs),
			       le32_to_cpu(br->len),
			       dbg_snprintf_key(c, &key, key_buf,
						DBG_KEY_BUF_LEN));
		}
		break;
	}
	case UBIFS_CS_NODE:
		break;
	case UBIFS_ORPH_NODE:
	{
		const struct ubifs_orph_node *orph = node;

		pr_err("\tcommit number  %llu\n",
		       (unsigned long long)
				le64_to_cpu(orph->cmt_no) & LLONG_MAX);
		pr_err("\tlast node flag %llu\n",
		       (unsigned long long)(le64_to_cpu(orph->cmt_no)) >> 63);
		n = (le32_to_cpu(ch->len) - UBIFS_ORPH_NODE_SZ) >> 3;
		pr_err("\t%d orphan inode numbers:\n", n);
		for (i = 0; i < n; i++)
			pr_err("\t  ino %llu\n",
			       (unsigned long long)le64_to_cpu(orph->inos[i]));
		break;
	}
	default:
		pr_err("node type %d was not recognized\n",
		       (int)ch->node_type);
	}
	spin_unlock(&dbg_lock);
}

void ubifs_dump_budget_req(const struct ubifs_budget_req *req)
{
	spin_lock(&dbg_lock);
	pr_err("Budgeting request: new_ino %d, dirtied_ino %d\n",
	       req->new_ino, req->dirtied_ino);
	pr_err("\tnew_ino_d   %d, dirtied_ino_d %d\n",
	       req->new_ino_d, req->dirtied_ino_d);
	pr_err("\tnew_page    %d, dirtied_page %d\n",
	       req->new_page, req->dirtied_page);
	pr_err("\tnew_dent    %d, mod_dent     %d\n",
	       req->new_dent, req->mod_dent);
	pr_err("\tidx_growth  %d\n", req->idx_growth);
	pr_err("\tdata_growth %d dd_growth     %d\n",
	       req->data_growth, req->dd_growth);
	spin_unlock(&dbg_lock);
}

void ubifs_dump_lstats(const struct ubifs_lp_stats *lst)
{
	spin_lock(&dbg_lock);
	pr_err("(pid %d) Lprops statistics: empty_lebs %d, idx_lebs  %d\n",
	       current->pid, lst->empty_lebs, lst->idx_lebs);
	pr_err("\ttaken_empty_lebs %d, total_free %lld, total_dirty %lld\n",
	       lst->taken_empty_lebs, lst->total_free, lst->total_dirty);
	pr_err("\ttotal_used %lld, total_dark %lld, total_dead %lld\n",
	       lst->total_used, lst->total_dark, lst->total_dead);
	spin_unlock(&dbg_lock);
}

void ubifs_dump_budg(struct ubifs_info *c, const struct ubifs_budg_info *bi)
{
	int i;
	struct rb_node *rb;
	struct ubifs_bud *bud;
	struct ubifs_gced_idx_leb *idx_gc;
	long long available, outstanding, free;

	spin_lock(&c->space_lock);
	spin_lock(&dbg_lock);
	pr_err("(pid %d) Budgeting info: data budget sum %lld, total budget sum %lld\n",
	       current->pid, bi->data_growth + bi->dd_growth,
	       bi->data_growth + bi->dd_growth + bi->idx_growth);
	pr_err("\tbudg_data_growth %lld, budg_dd_growth %lld, budg_idx_growth %lld\n",
	       bi->data_growth, bi->dd_growth, bi->idx_growth);
	pr_err("\tmin_idx_lebs %d, old_idx_sz %llu, uncommitted_idx %lld\n",
	       bi->min_idx_lebs, bi->old_idx_sz, bi->uncommitted_idx);
	pr_err("\tpage_budget %d, inode_budget %d, dent_budget %d\n",
	       bi->page_budget, bi->inode_budget, bi->dent_budget);
	pr_err("\tnospace %u, nospace_rp %u\n", bi->nospace, bi->nospace_rp);
	pr_err("\tdark_wm %d, dead_wm %d, max_idx_node_sz %d\n",
	       c->dark_wm, c->dead_wm, c->max_idx_node_sz);

	if (bi != &c->bi)
		/*
		 * If we are dumping saved budgeting data, do not print
		 * additional information which is about the current state, not
		 * the old one which corresponded to the saved budgeting data.
		 */
		goto out_unlock;

	pr_err("\tfreeable_cnt %d, calc_idx_sz %lld, idx_gc_cnt %d\n",
	       c->freeable_cnt, c->calc_idx_sz, c->idx_gc_cnt);
	pr_err("\tdirty_pg_cnt %ld, dirty_zn_cnt %ld, clean_zn_cnt %ld\n",
	       atomic_long_read(&c->dirty_pg_cnt),
	       atomic_long_read(&c->dirty_zn_cnt),
	       atomic_long_read(&c->clean_zn_cnt));
	pr_err("\tgc_lnum %d, ihead_lnum %d\n", c->gc_lnum, c->ihead_lnum);

	/* If we are in R/O mode, journal heads do not exist */
	if (c->jheads)
		for (i = 0; i < c->jhead_cnt; i++)
			pr_err("\tjhead %s\t LEB %d\n",
			       dbg_jhead(c->jheads[i].wbuf.jhead),
			       c->jheads[i].wbuf.lnum);
	for (rb = rb_first(&c->buds); rb; rb = rb_next(rb)) {
		bud = rb_entry(rb, struct ubifs_bud, rb);
		pr_err("\tbud LEB %d\n", bud->lnum);
	}
	list_for_each_entry(bud, &c->old_buds, list)
		pr_err("\told bud LEB %d\n", bud->lnum);
	list_for_each_entry(idx_gc, &c->idx_gc, list)
		pr_err("\tGC'ed idx LEB %d unmap %d\n",
		       idx_gc->lnum, idx_gc->unmap);
	pr_err("\tcommit state %d\n", c->cmt_state);

	/* Print budgeting predictions */
	available = ubifs_calc_available(c, c->bi.min_idx_lebs);
	outstanding = c->bi.data_growth + c->bi.dd_growth;
	free = ubifs_get_free_space_nolock(c);
	pr_err("Budgeting predictions:\n");
	pr_err("\tavailable: %lld, outstanding %lld, free %lld\n",
	       available, outstanding, free);
out_unlock:
	spin_unlock(&dbg_lock);
	spin_unlock(&c->space_lock);
}

void ubifs_dump_lprop(const struct ubifs_info *c, const struct ubifs_lprops *lp)
{
	int i, spc, dark = 0, dead = 0;
	struct rb_node *rb;
	struct ubifs_bud *bud;

	spc = lp->free + lp->dirty;
	if (spc < c->dead_wm)
		dead = spc;
	else
		dark = ubifs_calc_dark(c, spc);

	if (lp->flags & LPROPS_INDEX)
		pr_err("LEB %-7d free %-8d dirty %-8d used %-8d free + dirty %-8d flags %#x (",
		       lp->lnum, lp->free, lp->dirty, c->leb_size - spc, spc,
		       lp->flags);
	else
		pr_err("LEB %-7d free %-8d dirty %-8d used %-8d free + dirty %-8d dark %-4d dead %-4d nodes fit %-3d flags %#-4x (",
		       lp->lnum, lp->free, lp->dirty, c->leb_size - spc, spc,
		       dark, dead, (int)(spc / UBIFS_MAX_NODE_SZ), lp->flags);

	if (lp->flags & LPROPS_TAKEN) {
		if (lp->flags & LPROPS_INDEX)
			pr_cont("index, taken");
		else
			pr_cont("taken");
	} else {
		const char *s;

		if (lp->flags & LPROPS_INDEX) {
			switch (lp->flags & LPROPS_CAT_MASK) {
			case LPROPS_DIRTY_IDX:
				s = "dirty index";
				break;
			case LPROPS_FRDI_IDX:
				s = "freeable index";
				break;
			default:
				s = "index";
			}
		} else {
			switch (lp->flags & LPROPS_CAT_MASK) {
			case LPROPS_UNCAT:
				s = "not categorized";
				break;
			case LPROPS_DIRTY:
				s = "dirty";
				break;
			case LPROPS_FREE:
				s = "free";
				break;
			case LPROPS_EMPTY:
				s = "empty";
				break;
			case LPROPS_FREEABLE:
				s = "freeable";
				break;
			default:
				s = NULL;
				break;
			}
		}
		pr_cont("%s", s);
	}

	for (rb = rb_first((struct rb_root *)&c->buds); rb; rb = rb_next(rb)) {
		bud = rb_entry(rb, struct ubifs_bud, rb);
		if (bud->lnum == lp->lnum) {
			int head = 0;
			for (i = 0; i < c->jhead_cnt; i++) {
				/*
				 * Note, if we are in R/O mode or in the middle
				 * of mounting/re-mounting, the write-buffers do
				 * not exist.
				 */
				if (c->jheads &&
				    lp->lnum == c->jheads[i].wbuf.lnum) {
					pr_cont(", jhead %s", dbg_jhead(i));
					head = 1;
				}
			}
			if (!head)
				pr_cont(", bud of jhead %s",
				       dbg_jhead(bud->jhead));
		}
	}
	if (lp->lnum == c->gc_lnum)
		pr_cont(", GC LEB");
	pr_cont(")\n");
}

void ubifs_dump_lprops(struct ubifs_info *c)
{
	int lnum, err;
	struct ubifs_lprops lp;
	struct ubifs_lp_stats lst;

	pr_err("(pid %d) start dumping LEB properties\n", current->pid);
	ubifs_get_lp_stats(c, &lst);
	ubifs_dump_lstats(&lst);

	for (lnum = c->main_first; lnum < c->leb_cnt; lnum++) {
		err = ubifs_read_one_lp(c, lnum, &lp);
		if (err) {
			ubifs_err("cannot read lprops for LEB %d", lnum);
			continue;
		}

		ubifs_dump_lprop(c, &lp);
	}
	pr_err("(pid %d) finish dumping LEB properties\n", current->pid);
}

void ubifs_dump_lpt_info(struct ubifs_info *c)
{
	int i;

	spin_lock(&dbg_lock);
	pr_err("(pid %d) dumping LPT information\n", current->pid);
	pr_err("\tlpt_sz:        %lld\n", c->lpt_sz);
	pr_err("\tpnode_sz:      %d\n", c->pnode_sz);
	pr_err("\tnnode_sz:      %d\n", c->nnode_sz);
	pr_err("\tltab_sz:       %d\n", c->ltab_sz);
	pr_err("\tlsave_sz:      %d\n", c->lsave_sz);
	pr_err("\tbig_lpt:       %d\n", c->big_lpt);
	pr_err("\tlpt_hght:      %d\n", c->lpt_hght);
	pr_err("\tpnode_cnt:     %d\n", c->pnode_cnt);
	pr_err("\tnnode_cnt:     %d\n", c->nnode_cnt);
	pr_err("\tdirty_pn_cnt:  %d\n", c->dirty_pn_cnt);
	pr_err("\tdirty_nn_cnt:  %d\n", c->dirty_nn_cnt);
	pr_err("\tlsave_cnt:     %d\n", c->lsave_cnt);
	pr_err("\tspace_bits:    %d\n", c->space_bits);
	pr_err("\tlpt_lnum_bits: %d\n", c->lpt_lnum_bits);
	pr_err("\tlpt_offs_bits: %d\n", c->lpt_offs_bits);
	pr_err("\tlpt_spc_bits:  %d\n", c->lpt_spc_bits);
	pr_err("\tpcnt_bits:     %d\n", c->pcnt_bits);
	pr_err("\tlnum_bits:     %d\n", c->lnum_bits);
	pr_err("\tLPT root is at %d:%d\n", c->lpt_lnum, c->lpt_offs);
	pr_err("\tLPT head is at %d:%d\n",
	       c->nhead_lnum, c->nhead_offs);
	pr_err("\tLPT ltab is at %d:%d\n", c->ltab_lnum, c->ltab_offs);
	if (c->big_lpt)
		pr_err("\tLPT lsave is at %d:%d\n",
		       c->lsave_lnum, c->lsave_offs);
	for (i = 0; i < c->lpt_lebs; i++)
		pr_err("\tLPT LEB %d free %d dirty %d tgc %d cmt %d\n",
		       i + c->lpt_first, c->ltab[i].free, c->ltab[i].dirty,
		       c->ltab[i].tgc, c->ltab[i].cmt);
	spin_unlock(&dbg_lock);
}

void ubifs_dump_sleb(const struct ubifs_info *c,
		     const struct ubifs_scan_leb *sleb, int offs)
{
	struct ubifs_scan_node *snod;

	pr_err("(pid %d) start dumping scanned data from LEB %d:%d\n",
	       current->pid, sleb->lnum, offs);

	list_for_each_entry(snod, &sleb->nodes, list) {
		cond_resched();
		pr_err("Dumping node at LEB %d:%d len %d\n",
		       sleb->lnum, snod->offs, snod->len);
		ubifs_dump_node(c, snod->node);
	}
}

void ubifs_dump_leb(const struct ubifs_info *c, int lnum)
{
	struct ubifs_scan_leb *sleb;
	struct ubifs_scan_node *snod;
	void *buf;

	pr_err("(pid %d) start dumping LEB %d\n", current->pid, lnum);

	buf = __vmalloc(c->leb_size, GFP_NOFS, PAGE_KERNEL);
	if (!buf) {
		ubifs_err("cannot allocate memory for dumping LEB %d", lnum);
		return;
	}

	sleb = ubifs_scan(c, lnum, 0, buf, 0);
	if (IS_ERR(sleb)) {
		ubifs_err("scan error %d", (int)PTR_ERR(sleb));
		goto out;
	}

	pr_err("LEB %d has %d nodes ending at %d\n", lnum,
	       sleb->nodes_cnt, sleb->endpt);

	list_for_each_entry(snod, &sleb->nodes, list) {
		cond_resched();
		pr_err("Dumping node at LEB %d:%d len %d\n", lnum,
		       snod->offs, snod->len);
		ubifs_dump_node(c, snod->node);
	}

	pr_err("(pid %d) finish dumping LEB %d\n", current->pid, lnum);
	ubifs_scan_destroy(sleb);

out:
	vfree(buf);
	return;
}

void ubifs_dump_znode(const struct ubifs_info *c,
		      const struct ubifs_znode *znode)
{
	int n;
	const struct ubifs_zbranch *zbr;
	char key_buf[DBG_KEY_BUF_LEN];

	spin_lock(&dbg_lock);
	if (znode->parent)
		zbr = &znode->parent->zbranch[znode->iip];
	else
		zbr = &c->zroot;

	pr_err("znode %p, LEB %d:%d len %d parent %p iip %d level %d child_cnt %d flags %lx\n",
	       znode, zbr->lnum, zbr->offs, zbr->len, znode->parent, znode->iip,
	       znode->level, znode->child_cnt, znode->flags);

	if (znode->child_cnt <= 0 || znode->child_cnt > c->fanout) {
		spin_unlock(&dbg_lock);
		return;
	}

	pr_err("zbranches:\n");
	for (n = 0; n < znode->child_cnt; n++) {
		zbr = &znode->zbranch[n];
		if (znode->level > 0)
			pr_err("\t%d: znode %p LEB %d:%d len %d key %s\n",
			       n, zbr->znode, zbr->lnum, zbr->offs, zbr->len,
			       dbg_snprintf_key(c, &zbr->key, key_buf,
						DBG_KEY_BUF_LEN));
		else
			pr_err("\t%d: LNC %p LEB %d:%d len %d key %s\n",
			       n, zbr->znode, zbr->lnum, zbr->offs, zbr->len,
			       dbg_snprintf_key(c, &zbr->key, key_buf,
						DBG_KEY_BUF_LEN));
	}
	spin_unlock(&dbg_lock);
}

void ubifs_dump_heap(struct ubifs_info *c, struct ubifs_lpt_heap *heap, int cat)
{
	int i;

	pr_err("(pid %d) start dumping heap cat %d (%d elements)\n",
	       current->pid, cat, heap->cnt);
	for (i = 0; i < heap->cnt; i++) {
		struct ubifs_lprops *lprops = heap->arr[i];

		pr_err("\t%d. LEB %d hpos %d free %d dirty %d flags %d\n",
		       i, lprops->lnum, lprops->hpos, lprops->free,
		       lprops->dirty, lprops->flags);
	}
	pr_err("(pid %d) finish dumping heap\n", current->pid);
}

void ubifs_dump_pnode(struct ubifs_info *c, struct ubifs_pnode *pnode,
		      struct ubifs_nnode *parent, int iip)
{
	int i;

	pr_err("(pid %d) dumping pnode:\n", current->pid);
	pr_err("\taddress %zx parent %zx cnext %zx\n",
	       (size_t)pnode, (size_t)parent, (size_t)pnode->cnext);
	pr_err("\tflags %lu iip %d level %d num %d\n",
	       pnode->flags, iip, pnode->level, pnode->num);
	for (i = 0; i < UBIFS_LPT_FANOUT; i++) {
		struct ubifs_lprops *lp = &pnode->lprops[i];

		pr_err("\t%d: free %d dirty %d flags %d lnum %d\n",
		       i, lp->free, lp->dirty, lp->flags, lp->lnum);
	}
}

void ubifs_dump_tnc(struct ubifs_info *c)
{
	struct ubifs_znode *znode;
	int level;

	pr_err("\n");
	pr_err("(pid %d) start dumping TNC tree\n", current->pid);
	znode = ubifs_tnc_levelorder_next(c->zroot.znode, NULL);
	level = znode->level;
	pr_err("== Level %d ==\n", level);
	while (znode) {
		if (level != znode->level) {
			level = znode->level;
			pr_err("== Level %d ==\n", level);
		}
		ubifs_dump_znode(c, znode);
		znode = ubifs_tnc_levelorder_next(c->zroot.znode, znode);
	}
	pr_err("(pid %d) finish dumping TNC tree\n", current->pid);
}

static int dump_znode(struct ubifs_info *c, struct ubifs_znode *znode,
		      void *priv)
{
	ubifs_dump_znode(c, znode);
	return 0;
}

/**
 * ubifs_dump_index - dump the on-flash index.
 * @c: UBIFS file-system description object
 *
 * This function dumps whole UBIFS indexing B-tree, unlike 'ubifs_dump_tnc()'
 * which dumps only in-memory znodes and does not read znodes which from flash.
 */
void ubifs_dump_index(struct ubifs_info *c)
{
	dbg_walk_index(c, NULL, dump_znode, NULL);
}

/**
 * dbg_save_space_info - save information about flash space.
 * @c: UBIFS file-system description object
 *
 * This function saves information about UBIFS free space, dirty space, etc, in
 * order to check it later.
 */
void dbg_save_space_info(struct ubifs_info *c)
{
	struct ubifs_debug_info *d = c->dbg;
	int freeable_cnt;

	spin_lock(&c->space_lock);
	memcpy(&d->saved_lst, &c->lst, sizeof(struct ubifs_lp_stats));
	memcpy(&d->saved_bi, &c->bi, sizeof(struct ubifs_budg_info));
	d->saved_idx_gc_cnt = c->idx_gc_cnt;

	/*
	 * We use a dirty hack here and zero out @c->freeable_cnt, because it
	 * affects the free space calculations, and UBIFS might not know about
	 * all freeable eraseblocks. Indeed, we know about freeable eraseblocks
	 * only when we read their lprops, and we do this only lazily, upon the
	 * need. So at any given point of time @c->freeable_cnt might be not
	 * exactly accurate.
	 *
	 * Just one example about the issue we hit when we did not zero
	 * @c->freeable_cnt.
	 * 1. The file-system is mounted R/O, c->freeable_cnt is %0. We save the
	 *    amount of free space in @d->saved_free
	 * 2. We re-mount R/W, which makes UBIFS to read the "lsave"
	 *    information from flash, where we cache LEBs from various
	 *    categories ('ubifs_remount_fs()' -> 'ubifs_lpt_init()'
	 *    -> 'lpt_init_wr()' -> 'read_lsave()' -> 'ubifs_lpt_lookup()'
	 *    -> 'ubifs_get_pnode()' -> 'update_cats()'
	 *    -> 'ubifs_add_to_cat()').
	 * 3. Lsave contains a freeable eraseblock, and @c->freeable_cnt
	 *    becomes %1.
	 * 4. We calculate the amount of free space when the re-mount is
	 *    finished in 'dbg_check_space_info()' and it does not match
	 *    @d->saved_free.
	 */
	freeable_cnt = c->freeable_cnt;
	c->freeable_cnt = 0;
	d->saved_free = ubifs_get_free_space_nolock(c);
	c->freeable_cnt = freeable_cnt;
	spin_unlock(&c->space_lock);
}

/**
 * dbg_check_space_info - check flash space information.
 * @c: UBIFS file-system description object
 *
 * This function compares current flash space information with the information
 * which was saved when the 'dbg_save_space_info()' function was called.
 * Returns zero if the information has not changed, and %-EINVAL it it has
 * changed.
 */
int dbg_check_space_info(struct ubifs_info *c)
{
	struct ubifs_debug_info *d = c->dbg;
	struct ubifs_lp_stats lst;
	long long free;
	int freeable_cnt;

	spin_lock(&c->space_lock);
	freeable_cnt = c->freeable_cnt;
	c->freeable_cnt = 0;
	free = ubifs_get_free_space_nolock(c);
	c->freeable_cnt = freeable_cnt;
	spin_unlock(&c->space_lock);

	if (free != d->saved_free) {
		ubifs_err("free space changed from %lld to %lld",
			  d->saved_free, free);
		goto out;
	}

	return 0;

out:
	ubifs_msg("saved lprops statistics dump");
	ubifs_dump_lstats(&d->saved_lst);
	ubifs_msg("saved budgeting info dump");
	ubifs_dump_budg(c, &d->saved_bi);
	ubifs_msg("saved idx_gc_cnt %d", d->saved_idx_gc_cnt);
	ubifs_msg("current lprops statistics dump");
	ubifs_get_lp_stats(c, &lst);
	ubifs_dump_lstats(&lst);
	ubifs_msg("current budgeting info dump");
	ubifs_dump_budg(c, &c->bi);
	dump_stack();
	return -EINVAL;
}

/**
 * dbg_check_synced_i_size - check synchronized inode size.
 * @c: UBIFS file-system description object
 * @inode: inode to check
 *
 * If inode is clean, synchronized inode size has to be equivalent to current
 * inode size. This function has to be called only for locked inodes (@i_mutex
 * has to be locked). Returns %0 if synchronized inode size if correct, and
 * %-EINVAL if not.
 */
int dbg_check_synced_i_size(const struct ubifs_info *c, struct inode *inode)
{
	int err = 0;
	struct ubifs_inode *ui = ubifs_inode(inode);

	if (!dbg_is_chk_gen(c))
		return 0;
	if (!S_ISREG(inode->i_mode))
		return 0;

	mutex_lock(&ui->ui_mutex);
	spin_lock(&ui->ui_lock);
	if (ui->ui_size != ui->synced_i_size && !ui->dirty) {
		ubifs_err("ui_size is %lld, synced_i_size is %lld, but inode is clean",
			  ui->ui_size, ui->synced_i_size);
		ubifs_err("i_ino %lu, i_mode %#x, i_size %lld", inode->i_ino,
			  inode->i_mode, i_size_read(inode));
		dump_stack();
		err = -EINVAL;
	}
	spin_unlock(&ui->ui_lock);
	mutex_unlock(&ui->ui_mutex);
	return err;
}

/*
 * dbg_check_dir - check directory inode size and link count.
 * @c: UBIFS file-system description object
 * @dir: the directory to calculate size for
 * @size: the result is returned here
 *
 * This function makes sure that directory size and link count are correct.
 * Returns zero in case of success and a negative error code in case of
 * failure.
 *
 * Note, it is good idea to make sure the @dir->i_mutex is locked before
 * calling this function.
 */
int dbg_check_dir(struct ubifs_info *c, const struct inode *dir)
{
	unsigned int nlink = 2;
	union ubifs_key key;
	struct ubifs_dent_node *dent, *pdent = NULL;
	struct qstr nm = { .name = NULL };
	loff_t size = UBIFS_INO_NODE_SZ;

	if (!dbg_is_chk_gen(c))
		return 0;

	if (!S_ISDIR(dir->i_mode))
		return 0;

	lowest_dent_key(c, &key, dir->i_ino);
	while (1) {
		int err;

		dent = ubifs_tnc_next_ent(c, &key, &nm);
		if (IS_ERR(dent)) {
			err = PTR_ERR(dent);
			if (err == -ENOENT)
				break;
			return err;
		}

		nm.name = dent->name;
		nm.len = le16_to_cpu(dent->nlen);
		size += CALC_DENT_SIZE(nm.len);
		if (dent->type == UBIFS_ITYPE_DIR)
			nlink += 1;
		kfree(pdent);
		pdent = dent;
		key_read(c, &dent->key, &key);
	}
	kfree(pdent);

	if (i_size_read(dir) != size) {
		ubifs_err("directory inode %lu has size %llu, but calculated size is %llu",
			  dir->i_ino, (unsigned long long)i_size_read(dir),
			  (unsigned long long)size);
		ubifs_dump_inode(c, dir);
		dump_stack();
		return -EINVAL;
	}
	if (dir->i_nlink != nlink) {
		ubifs_err("directory inode %lu has nlink %u, but calculated nlink is %u",
			  dir->i_ino, dir->i_nlink, nlink);
		ubifs_dump_inode(c, dir);
		dump_stack();
		return -EINVAL;
	}

	return 0;
}

/**
 * dbg_check_key_order - make sure that colliding keys are properly ordered.
 * @c: UBIFS file-system description object
 * @zbr1: first zbranch
 * @zbr2: following zbranch
 *
 * In UBIFS indexing B-tree colliding keys has to be sorted in binary order of
 * names of the direntries/xentries which are referred by the keys. This
 * function reads direntries/xentries referred by @zbr1 and @zbr2 and makes
 * sure the name of direntry/xentry referred by @zbr1 is less than
 * direntry/xentry referred by @zbr2. Returns zero if this is true, %1 if not,
 * and a negative error code in case of failure.
 */
static int dbg_check_key_order(struct ubifs_info *c, struct ubifs_zbranch *zbr1,
			       struct ubifs_zbranch *zbr2)
{
	int err, nlen1, nlen2, cmp;
	struct ubifs_dent_node *dent1, *dent2;
	union ubifs_key key;
	char key_buf[DBG_KEY_BUF_LEN];

	ubifs_assert(!keys_cmp(c, &zbr1->key, &zbr2->key));
	dent1 = kmalloc(UBIFS_MAX_DENT_NODE_SZ, GFP_NOFS);
	if (!dent1)
		return -ENOMEM;
	dent2 = kmalloc(UBIFS_MAX_DENT_NODE_SZ, GFP_NOFS);
	if (!dent2) {
		err = -ENOMEM;
		goto out_free;
	}

	err = ubifs_tnc_read_node(c, zbr1, dent1);
	if (err)
		goto out_free;
	err = ubifs_validate_entry(c, dent1);
	if (err)
		goto out_free;

	err = ubifs_tnc_read_node(c, zbr2, dent2);
	if (err)
		goto out_free;
	err = ubifs_validate_entry(c, dent2);
	if (err)
		goto out_free;

	/* Make sure node keys are the same as in zbranch */
	err = 1;
	key_read(c, &dent1->key, &key);
	if (keys_cmp(c, &zbr1->key, &key)) {
		ubifs_err("1st entry at %d:%d has key %s", zbr1->lnum,
			  zbr1->offs, dbg_snprintf_key(c, &key, key_buf,
						       DBG_KEY_BUF_LEN));
		ubifs_err("but it should have key %s according to tnc",
			  dbg_snprintf_key(c, &zbr1->key, key_buf,
					   DBG_KEY_BUF_LEN));
		ubifs_dump_node(c, dent1);
		goto out_free;
	}

	key_read(c, &dent2->key, &key);
	if (keys_cmp(c, &zbr2->key, &key)) {
		ubifs_err("2nd entry at %d:%d has key %s", zbr1->lnum,
			  zbr1->offs, dbg_snprintf_key(c, &key, key_buf,
						       DBG_KEY_BUF_LEN));
		ubifs_err("but it should have key %s according to tnc",
			  dbg_snprintf_key(c, &zbr2->key, key_buf,
					   DBG_KEY_BUF_LEN));
		ubifs_dump_node(c, dent2);
		goto out_free;
	}

	nlen1 = le16_to_cpu(dent1->nlen);
	nlen2 = le16_to_cpu(dent2->nlen);

	cmp = memcmp(dent1->name, dent2->name, min_t(int, nlen1, nlen2));
	if (cmp < 0 || (cmp == 0 && nlen1 < nlen2)) {
		err = 0;
		goto out_free;
	}
	if (cmp == 0 && nlen1 == nlen2)
		ubifs_err("2 xent/dent nodes with the same name");
	else
		ubifs_err("bad order of colliding key %s",
			  dbg_snprintf_key(c, &key, key_buf, DBG_KEY_BUF_LEN));

	ubifs_msg("first node at %d:%d\n", zbr1->lnum, zbr1->offs);
	ubifs_dump_node(c, dent1);
	ubifs_msg("second node at %d:%d\n", zbr2->lnum, zbr2->offs);
	ubifs_dump_node(c, dent2);

out_free:
	kfree(dent2);
	kfree(dent1);
	return err;
}

/**
 * dbg_check_znode - check if znode is all right.
 * @c: UBIFS file-system description object
 * @zbr: zbranch which points to this znode
 *
 * This function makes sure that znode referred to by @zbr is all right.
 * Returns zero if it is, and %-EINVAL if it is not.
 */
static int dbg_check_znode(struct ubifs_info *c, struct ubifs_zbranch *zbr)
{
	struct ubifs_znode *znode = zbr->znode;
	struct ubifs_znode *zp = znode->parent;
	int n, err, cmp;

	if (znode->child_cnt <= 0 || znode->child_cnt > c->fanout) {
		err = 1;
		goto out;
	}
	if (znode->level < 0) {
		err = 2;
		goto out;
	}
	if (znode->iip < 0 || znode->iip >= c->fanout) {
		err = 3;
		goto out;
	}

	if (zbr->len == 0)
		/* Only dirty zbranch may have no on-flash nodes */
		if (!ubifs_zn_dirty(znode)) {
			err = 4;
			goto out;
		}

	if (ubifs_zn_dirty(znode)) {
		/*
		 * If znode is dirty, its parent has to be dirty as well. The
		 * order of the operation is important, so we have to have
		 * memory barriers.
		 */
		smp_mb();
		if (zp && !ubifs_zn_dirty(zp)) {
			/*
			 * The dirty flag is atomic and is cleared outside the
			 * TNC mutex, so znode's dirty flag may now have
			 * been cleared. The child is always cleared before the
			 * parent, so we just need to check again.
			 */
			smp_mb();
			if (ubifs_zn_dirty(znode)) {
				err = 5;
				goto out;
			}
		}
	}

	if (zp) {
		const union ubifs_key *min, *max;

		if (znode->level != zp->level - 1) {
			err = 6;
			goto out;
		}

		/* Make sure the 'parent' pointer in our znode is correct */
		err = ubifs_search_zbranch(c, zp, &zbr->key, &n);
		if (!err) {
			/* This zbranch does not exist in the parent */
			err = 7;
			goto out;
		}

		if (znode->iip >= zp->child_cnt) {
			err = 8;
			goto out;
		}

		if (znode->iip != n) {
			/* This may happen only in case of collisions */
			if (keys_cmp(c, &zp->zbranch[n].key,
				     &zp->zbranch[znode->iip].key)) {
				err = 9;
				goto out;
			}
			n = znode->iip;
		}

		/*
		 * Make sure that the first key in our znode is greater than or
		 * equal to the key in the pointing zbranch.
		 */
		min = &zbr->key;
		cmp = keys_cmp(c, min, &znode->zbranch[0].key);
		if (cmp == 1) {
			err = 10;
			goto out;
		}

		if (n + 1 < zp->child_cnt) {
			max = &zp->zbranch[n + 1].key;

			/*
			 * Make sure the last key in our znode is less or
			 * equivalent than the key in the zbranch which goes
			 * after our pointing zbranch.
			 */
			cmp = keys_cmp(c, max,
				&znode->zbranch[znode->child_cnt - 1].key);
			if (cmp == -1) {
				err = 11;
				goto out;
			}
		}
	} else {
		/* This may only be root znode */
		if (zbr != &c->zroot) {
			err = 12;
			goto out;
		}
	}

	/*
	 * Make sure that next key is greater or equivalent then the previous
	 * one.
	 */
	for (n = 1; n < znode->child_cnt; n++) {
		cmp = keys_cmp(c, &znode->zbranch[n - 1].key,
			       &znode->zbranch[n].key);
		if (cmp > 0) {
			err = 13;
			goto out;
		}
		if (cmp == 0) {
			/* This can only be keys with colliding hash */
			if (!is_hash_key(c, &znode->zbranch[n].key)) {
				err = 14;
				goto out;
			}

			if (znode->level != 0 || c->replaying)
				continue;

			/*
			 * Colliding keys should follow binary order of
			 * corresponding xentry/dentry names.
			 */
			err = dbg_check_key_order(c, &znode->zbranch[n - 1],
						  &znode->zbranch[n]);
			if (err < 0)
				return err;
			if (err) {
				err = 15;
				goto out;
			}
		}
	}

	for (n = 0; n < znode->child_cnt; n++) {
		if (!znode->zbranch[n].znode &&
		    (znode->zbranch[n].lnum == 0 ||
		     znode->zbranch[n].len == 0)) {
			err = 16;
			goto out;
		}

		if (znode->zbranch[n].lnum != 0 &&
		    znode->zbranch[n].len == 0) {
			err = 17;
			goto out;
		}

		if (znode->zbranch[n].lnum == 0 &&
		    znode->zbranch[n].len != 0) {
			err = 18;
			goto out;
		}

		if (znode->zbranch[n].lnum == 0 &&
		    znode->zbranch[n].offs != 0) {
			err = 19;
			goto out;
		}

		if (znode->level != 0 && znode->zbranch[n].znode)
			if (znode->zbranch[n].znode->parent != znode) {
				err = 20;
				goto out;
			}
	}

	return 0;

out:
	ubifs_err("failed, error %d", err);
	ubifs_msg("dump of the znode");
	ubifs_dump_znode(c, znode);
	if (zp) {
		ubifs_msg("dump of the parent znode");
		ubifs_dump_znode(c, zp);
	}
	dump_stack();
	return -EINVAL;
}

/**
 * dbg_check_tnc - check TNC tree.
 * @c: UBIFS file-system description object
 * @extra: do extra checks that are possible at start commit
 *
 * This function traverses whole TNC tree and checks every znode. Returns zero
 * if everything is all right and %-EINVAL if something is wrong with TNC.
 */
int dbg_check_tnc(struct ubifs_info *c, int extra)
{
	struct ubifs_znode *znode;
	long clean_cnt = 0, dirty_cnt = 0;
	int err, last;

	if (!dbg_is_chk_index(c))
		return 0;

	ubifs_assert(mutex_is_locked(&c->tnc_mutex));
	if (!c->zroot.znode)
		return 0;

	znode = ubifs_tnc_postorder_first(c->zroot.znode);
	while (1) {
		struct ubifs_znode *prev;
		struct ubifs_zbranch *zbr;

		if (!znode->parent)
			zbr = &c->zroot;
		else
			zbr = &znode->parent->zbranch[znode->iip];

		err = dbg_check_znode(c, zbr);
		if (err)
			return err;

		if (extra) {
			if (ubifs_zn_dirty(znode))
				dirty_cnt += 1;
			else
				clean_cnt += 1;
		}

		prev = znode;
		znode = ubifs_tnc_postorder_next(znode);
		if (!znode)
			break;

		/*
		 * If the last key of this znode is equivalent to the first key
		 * of the next znode (collision), then check order of the keys.
		 */
		last = prev->child_cnt - 1;
		if (prev->level == 0 && znode->level == 0 && !c->replaying &&
		    !keys_cmp(c, &prev->zbranch[last].key,
			      &znode->zbranch[0].key)) {
			err = dbg_check_key_order(c, &prev->zbranch[last],
						  &znode->zbranch[0]);
			if (err < 0)
				return err;
			if (err) {
				ubifs_msg("first znode");
				ubifs_dump_znode(c, prev);
				ubifs_msg("second znode");
				ubifs_dump_znode(c, znode);
				return -EINVAL;
			}
		}
	}

	if (extra) {
		if (clean_cnt != atomic_long_read(&c->clean_zn_cnt)) {
			ubifs_err("incorrect clean_zn_cnt %ld, calculated %ld",
				  atomic_long_read(&c->clean_zn_cnt),
				  clean_cnt);
			return -EINVAL;
		}
		if (dirty_cnt != atomic_long_read(&c->dirty_zn_cnt)) {
			ubifs_err("incorrect dirty_zn_cnt %ld, calculated %ld",
				  atomic_long_read(&c->dirty_zn_cnt),
				  dirty_cnt);
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * dbg_walk_index - walk the on-flash index.
 * @c: UBIFS file-system description object
 * @leaf_cb: called for each leaf node
 * @znode_cb: called for each indexing node
 * @priv: private data which is passed to callbacks
 *
 * This function walks the UBIFS index and calls the @leaf_cb for each leaf
 * node and @znode_cb for each indexing node. Returns zero in case of success
 * and a negative error code in case of failure.
 *
 * It would be better if this function removed every znode it pulled to into
 * the TNC, so that the behavior more closely matched the non-debugging
 * behavior.
 */
int dbg_walk_index(struct ubifs_info *c, dbg_leaf_callback leaf_cb,
		   dbg_znode_callback znode_cb, void *priv)
{
	int err;
	struct ubifs_zbranch *zbr;
	struct ubifs_znode *znode, *child;

	mutex_lock(&c->tnc_mutex);
	/* If the root indexing node is not in TNC - pull it */
	if (!c->zroot.znode) {
		c->zroot.znode = ubifs_load_znode(c, &c->zroot, NULL, 0);
		if (IS_ERR(c->zroot.znode)) {
			err = PTR_ERR(c->zroot.znode);
			c->zroot.znode = NULL;
			goto out_unlock;
		}
	}

	/*
	 * We are going to traverse the indexing tree in the postorder manner.
	 * Go down and find the leftmost indexing node where we are going to
	 * start from.
	 */
	znode = c->zroot.znode;
	while (znode->level > 0) {
		zbr = &znode->zbranch[0];
		child = zbr->znode;
		if (!child) {
			child = ubifs_load_znode(c, zbr, znode, 0);
			if (IS_ERR(child)) {
				err = PTR_ERR(child);
				goto out_unlock;
			}
			zbr->znode = child;
		}

		znode = child;
	}

	/* Iterate over all indexing nodes */
	while (1) {
		int idx;

		cond_resched();

		if (znode_cb) {
			err = znode_cb(c, znode, priv);
			if (err) {
				ubifs_err("znode checking function returned error %d",
					  err);
				ubifs_dump_znode(c, znode);
				goto out_dump;
			}
		}
		if (leaf_cb && znode->level == 0) {
			for (idx = 0; idx < znode->child_cnt; idx++) {
				zbr = &znode->zbranch[idx];
				err = leaf_cb(c, zbr, priv);
				if (err) {
					ubifs_err("leaf checking function returned error %d, for leaf at LEB %d:%d",
						  err, zbr->lnum, zbr->offs);
					goto out_dump;
				}
			}
		}

		if (!znode->parent)
			break;

		idx = znode->iip + 1;
		znode = znode->parent;
		if (idx < znode->child_cnt) {
			/* Switch to the next index in the parent */
			zbr = &znode->zbranch[idx];
			child = zbr->znode;
			if (!child) {
				child = ubifs_load_znode(c, zbr, znode, idx);
				if (IS_ERR(child)) {
					err = PTR_ERR(child);
					goto out_unlock;
				}
				zbr->znode = child;
			}
			znode = child;
		} else
			/*
			 * This is the last child, switch to the parent and
			 * continue.
			 */
			continue;

		/* Go to the lowest leftmost znode in the new sub-tree */
		while (znode->level > 0) {
			zbr = &znode->zbranch[0];
			child = zbr->znode;
			if (!child) {
				child = ubifs_load_znode(c, zbr, znode, 0);
				if (IS_ERR(child)) {
					err = PTR_ERR(child);
					goto out_unlock;
				}
				zbr->znode = child;
			}
			znode = child;
		}
	}

	mutex_unlock(&c->tnc_mutex);
	return 0;

out_dump:
	if (znode->parent)
		zbr = &znode->parent->zbranch[znode->iip];
	else
		zbr = &c->zroot;
	ubifs_msg("dump of znode at LEB %d:%d", zbr->lnum, zbr->offs);
	ubifs_dump_znode(c, znode);
out_unlock:
	mutex_unlock(&c->tnc_mutex);
	return err;
}

/**
 * add_size - add znode size to partially calculated index size.
 * @c: UBIFS file-system description object
 * @znode: znode to add size for
 * @priv: partially calculated index size
 *
 * This is a helper function for 'dbg_check_idx_size()' which is called for
 * every indexing node and adds its size to the 'long long' variable pointed to
 * by @priv.
 */
static int add_size(struct ubifs_info *c, struct ubifs_znode *znode, void *priv)
{
	long long *idx_size = priv;
	int add;

	add = ubifs_idx_node_sz(c, znode->child_cnt);
	add = ALIGN(add, 8);
	*idx_size += add;
	return 0;
}

/**
 * dbg_check_idx_size - check index size.
 * @c: UBIFS file-system description object
 * @idx_size: size to check
 *
 * This function walks the UBIFS index, calculates its size and checks that the
 * size is equivalent to @idx_size. Returns zero in case of success and a
 * negative error code in case of failure.
 */
int dbg_check_idx_size(struct ubifs_info *c, long long idx_size)
{
	int err;
	long long calc = 0;

	if (!dbg_is_chk_index(c))
		return 0;

	err = dbg_walk_index(c, NULL, add_size, &calc);
	if (err) {
		ubifs_err("error %d while walking the index", err);
		return err;
	}

	if (calc != idx_size) {
		ubifs_err("index size check failed: calculated size is %lld, should be %lld",
			  calc, idx_size);
		dump_stack();
		return -EINVAL;
	}

	return 0;
}

/**
 * struct fsck_inode - information about an inode used when checking the file-system.
 * @rb: link in the RB-tree of inodes
 * @inum: inode number
 * @mode: inode type, permissions, etc
 * @nlink: inode link count
 * @xattr_cnt: count of extended attributes
 * @references: how many directory/xattr entries refer this inode (calculated
 *              while walking the index)
 * @calc_cnt: for directory inode count of child directories
 * @size: inode size (read from on-flash inode)
 * @xattr_sz: summary size of all extended attributes (read from on-flash
 *            inode)
 * @calc_sz: for directories calculated directory size
 * @calc_xcnt: count of extended attributes
 * @calc_xsz: calculated summary size of all extended attributes
 * @xattr_nms: sum of lengths of all extended attribute names belonging to this
 *             inode (read from on-flash inode)
 * @calc_xnms: calculated sum of lengths of all extended attribute names
 */
struct fsck_inode {
	struct rb_node rb;
	ino_t inum;
	umode_t mode;
	unsigned int nlink;
	unsigned int xattr_cnt;
	int references;
	int calc_cnt;
	long long size;
	unsigned int xattr_sz;
	long long calc_sz;
	long long calc_xcnt;
	long long calc_xsz;
	unsigned int xattr_nms;
	long long calc_xnms;
};

/**
 * struct fsck_data - private FS checking information.
 * @inodes: RB-tree of all inodes (contains @struct fsck_inode objects)
 */
struct fsck_data {
	struct rb_root inodes;
};

/**
 * add_inode - add inode information to RB-tree of inodes.
 * @c: UBIFS file-system description object
 * @fsckd: FS checking information
 * @ino: raw UBIFS inode to add
 *
 * This is a helper function for 'check_leaf()' which adds information about
 * inode @ino to the RB-tree of inodes. Returns inode information pointer in
 * case of success and a negative error code in case of failure.
 */
static struct fsck_inode *add_inode(struct ubifs_info *c,
				    struct fsck_data *fsckd,
				    struct ubifs_ino_node *ino)
{
	struct rb_node **p, *parent = NULL;
	struct fsck_inode *fscki;
	ino_t inum = key_inum_flash(c, &ino->key);
	struct inode *inode;
	struct ubifs_inode *ui;

	p = &fsckd->inodes.rb_node;
	while (*p) {
		parent = *p;
		fscki = rb_entry(parent, struct fsck_inode, rb);
		if (inum < fscki->inum)
			p = &(*p)->rb_left;
		else if (inum > fscki->inum)
			p = &(*p)->rb_right;
		else
			return fscki;
	}

	if (inum > c->highest_inum) {
		ubifs_err("too high inode number, max. is %lu",
			  (unsigned long)c->highest_inum);
		return ERR_PTR(-EINVAL);
	}

	fscki = kzalloc(sizeof(struct fsck_inode), GFP_NOFS);
	if (!fscki)
		return ERR_PTR(-ENOMEM);

	inode = ilookup(c->vfs_sb, inum);

	fscki->inum = inum;
	/*
	 * If the inode is present in the VFS inode cache, use it instead of
	 * the on-flash inode which might be out-of-date. E.g., the size might
	 * be out-of-date. If we do not do this, the following may happen, for
	 * example:
	 *   1. A power cut happens
	 *   2. We mount the file-system R/O, the replay process fixes up the
	 *      inode size in the VFS cache, but on on-flash.
	 *   3. 'check_leaf()' fails because it hits a data node beyond inode
	 *      size.
	 */
	if (!inode) {
		fscki->nlink = le32_to_cpu(ino->nlink);
		fscki->size = le64_to_cpu(ino->size);
		fscki->xattr_cnt = le32_to_cpu(ino->xattr_cnt);
		fscki->xattr_sz = le32_to_cpu(ino->xattr_size);
		fscki->xattr_nms = le32_to_cpu(ino->xattr_names);
		fscki->mode = le32_to_cpu(ino->mode);
	} else {
		ui = ubifs_inode(inode);
		fscki->nlink = inode->i_nlink;
		fscki->size = inode->i_size;
		fscki->xattr_cnt = ui->xattr_cnt;
		fscki->xattr_sz = ui->xattr_size;
		fscki->xattr_nms = ui->xattr_names;
		fscki->mode = inode->i_mode;
		iput(inode);
	}

	if (S_ISDIR(fscki->mode)) {
		fscki->calc_sz = UBIFS_INO_NODE_SZ;
		fscki->calc_cnt = 2;
	}

	rb_link_node(&fscki->rb, parent, p);
	rb_insert_color(&fscki->rb, &fsckd->inodes);

	return fscki;
}

/**
 * search_inode - search inode in the RB-tree of inodes.
 * @fsckd: FS checking information
 * @inum: inode number to search
 *
 * This is a helper function for 'check_leaf()' which searches inode @inum in
 * the RB-tree of inodes and returns an inode information pointer or %NULL if
 * the inode was not found.
 */
static struct fsck_inode *search_inode(struct fsck_data *fsckd, ino_t inum)
{
	struct rb_node *p;
	struct fsck_inode *fscki;

	p = fsckd->inodes.rb_node;
	while (p) {
		fscki = rb_entry(p, struct fsck_inode, rb);
		if (inum < fscki->inum)
			p = p->rb_left;
		else if (inum > fscki->inum)
			p = p->rb_right;
		else
			return fscki;
	}
	return NULL;
}

/**
 * read_add_inode - read inode node and add it to RB-tree of inodes.
 * @c: UBIFS file-system description object
 * @fsckd: FS checking information
 * @inum: inode number to read
 *
 * This is a helper function for 'check_leaf()' which finds inode node @inum in
 * the index, reads it, and adds it to the RB-tree of inodes. Returns inode
 * information pointer in case of success and a negative error code in case of
 * failure.
 */
static struct fsck_inode *read_add_inode(struct ubifs_info *c,
					 struct fsck_data *fsckd, ino_t inum)
{
	int n, err;
	union ubifs_key key;
	struct ubifs_znode *znode;
	struct ubifs_zbranch *zbr;
	struct ubifs_ino_node *ino;
	struct fsck_inode *fscki;

	fscki = search_inode(fsckd, inum);
	if (fscki)
		return fscki;

	ino_key_init(c, &key, inum);
	err = ubifs_lookup_level0(c, &key, &znode, &n);
	if (!err) {
		ubifs_err("inode %lu not found in index", (unsigned long)inum);
		return ERR_PTR(-ENOENT);
	} else if (err < 0) {
		ubifs_err("error %d while looking up inode %lu",
			  err, (unsigned long)inum);
		return ERR_PTR(err);
	}

	zbr = &znode->zbranch[n];
	if (zbr->len < UBIFS_INO_NODE_SZ) {
		ubifs_err("bad node %lu node length %d",
			  (unsigned long)inum, zbr->len);
		return ERR_PTR(-EINVAL);
	}

	ino = kmalloc(zbr->len, GFP_NOFS);
	if (!ino)
		return ERR_PTR(-ENOMEM);

	err = ubifs_tnc_read_node(c, zbr, ino);
	if (err) {
		ubifs_err("cannot read inode node at LEB %d:%d, error %d",
			  zbr->lnum, zbr->offs, err);
		kfree(ino);
		return ERR_PTR(err);
	}

	fscki = add_inode(c, fsckd, ino);
	kfree(ino);
	if (IS_ERR(fscki)) {
		ubifs_err("error %ld while adding inode %lu node",
			  PTR_ERR(fscki), (unsigned long)inum);
		return fscki;
	}

	return fscki;
}

/**
 * check_leaf - check leaf node.
 * @c: UBIFS file-system description object
 * @zbr: zbranch of the leaf node to check
 * @priv: FS checking information
 *
 * This is a helper function for 'dbg_check_filesystem()' which is called for
 * every single leaf node while walking the indexing tree. It checks that the
 * leaf node referred from the indexing tree exists, has correct CRC, and does
 * some other basic validation. This function is also responsible for building
 * an RB-tree of inodes - it adds all inodes into the RB-tree. It also
 * calculates reference count, size, etc for each inode in order to later
 * compare them to the information stored inside the inodes and detect possible
 * inconsistencies. Returns zero in case of success and a negative error code
 * in case of failure.
 */
static int check_leaf(struct ubifs_info *c, struct ubifs_zbranch *zbr,
		      void *priv)
{
	ino_t inum;
	void *node;
	struct ubifs_ch *ch;
	int err, type = key_type(c, &zbr->key);
	struct fsck_inode *fscki;

	if (zbr->len < UBIFS_CH_SZ) {
		ubifs_err("bad leaf length %d (LEB %d:%d)",
			  zbr->len, zbr->lnum, zbr->offs);
		return -EINVAL;
	}

	node = kmalloc(zbr->len, GFP_NOFS);
	if (!node)
		return -ENOMEM;

	err = ubifs_tnc_read_node(c, zbr, node);
	if (err) {
		ubifs_err("cannot read leaf node at LEB %d:%d, error %d",
			  zbr->lnum, zbr->offs, err);
		goto out_free;
	}

	/* If this is an inode node, add it to RB-tree of inodes */
	if (type == UBIFS_INO_KEY) {
		fscki = add_inode(c, priv, node);
		if (IS_ERR(fscki)) {
			err = PTR_ERR(fscki);
			ubifs_err("error %d while adding inode node", err);
			goto out_dump;
		}
		goto out;
	}

	if (type != UBIFS_DENT_KEY && type != UBIFS_XENT_KEY &&
	    type != UBIFS_DATA_KEY) {
		ubifs_err("unexpected node type %d at LEB %d:%d",
			  type, zbr->lnum, zbr->offs);
		err = -EINVAL;
		goto out_free;
	}

	ch = node;
	if (le64_to_cpu(ch->sqnum) > c->max_sqnum) {
		ubifs_err("too high sequence number, max. is %llu",
			  c->max_sqnum);
		err = -EINVAL;
		goto out_dump;
	}

	if (type == UBIFS_DATA_KEY) {
		long long blk_offs;
		struct ubifs_data_node *dn = node;

		ubifs_assert(zbr->len >= UBIFS_DATA_NODE_SZ);

		/*
		 * Search the inode node this data node belongs to and insert
		 * it to the RB-tree of inodes.
		 */
		inum = key_inum_flash(c, &dn->key);
		fscki = read_add_inode(c, priv, inum);
		if (IS_ERR(fscki)) {
			err = PTR_ERR(fscki);
			ubifs_err("error %d while processing data node and trying to find inode node %lu",
				  err, (unsigned long)inum);
			goto out_dump;
		}

		/* Make sure the data node is within inode size */
		blk_offs = key_block_flash(c, &dn->key);
		blk_offs <<= UBIFS_BLOCK_SHIFT;
		blk_offs += le32_to_cpu(dn->size);
		if (blk_offs > fscki->size) {
			ubifs_err("data node at LEB %d:%d is not within inode size %lld",
				  zbr->lnum, zbr->offs, fscki->size);
			err = -EINVAL;
			goto out_dump;
		}
	} else {
		int nlen;
		struct ubifs_dent_node *dent = node;
		struct fsck_inode *fscki1;

		ubifs_assert(zbr->len >= UBIFS_DENT_NODE_SZ);

		err = ubifs_validate_entry(c, dent);
		if (err)
			goto out_dump;

		/*
		 * Search the inode node this entry refers to and the parent
		 * inode node and insert them to the RB-tree of inodes.
		 */
		inum = le64_to_cpu(dent->inum);
		fscki = read_add_inode(c, priv, inum);
		if (IS_ERR(fscki)) {
			err = PTR_ERR(fscki);
			ubifs_err("error %d while processing entry node and trying to find inode node %lu",
				  err, (unsigned long)inum);
			goto out_dump;
		}

		/* Count how many direntries or xentries refers this inode */
		fscki->references += 1;

		inum = key_inum_flash(c, &dent->key);
		fscki1 = read_add_inode(c, priv, inum);
		if (IS_ERR(fscki1)) {
			err = PTR_ERR(fscki1);
			ubifs_err("error %d while processing entry node and trying to find parent inode node %lu",
				  err, (unsigned long)inum);
			goto out_dump;
		}

		nlen = le16_to_cpu(dent->nlen);
		if (type == UBIFS_XENT_KEY) {
			fscki1->calc_xcnt += 1;
			fscki1->calc_xsz += CALC_DENT_SIZE(nlen);
			fscki1->calc_xsz += CALC_XATTR_BYTES(fscki->size);
			fscki1->calc_xnms += nlen;
		} else {
			fscki1->calc_sz += CALC_DENT_SIZE(nlen);
			if (dent->type == UBIFS_ITYPE_DIR)
				fscki1->calc_cnt += 1;
		}
	}

out:
	kfree(node);
	return 0;

out_dump:
	ubifs_msg("dump of node at LEB %d:%d", zbr->lnum, zbr->offs);
	ubifs_dump_node(c, node);
out_free:
	kfree(node);
	return err;
}

/**
 * free_inodes - free RB-tree of inodes.
 * @fsckd: FS checking information
 */
static void free_inodes(struct fsck_data *fsckd)
{
	struct fsck_inode *fscki, *n;

	rbtree_postorder_for_each_entry_safe(fscki, n, &fsckd->inodes, rb)
		kfree(fscki);
}

/**
 * check_inodes - checks all inodes.
 * @c: UBIFS file-system description object
 * @fsckd: FS checking information
 *
 * This is a helper function for 'dbg_check_filesystem()' which walks the
 * RB-tree of inodes after the index scan has been finished, and checks that
 * inode nlink, size, etc are correct. Returns zero if inodes are fine,
 * %-EINVAL if not, and a negative error code in case of failure.
 */
static int check_inodes(struct ubifs_info *c, struct fsck_data *fsckd)
{
	int n, err;
	union ubifs_key key;
	struct ubifs_znode *znode;
	struct ubifs_zbranch *zbr;
	struct ubifs_ino_node *ino;
	struct fsck_inode *fscki;
	struct rb_node *this = rb_first(&fsckd->inodes);

	while (this) {
		fscki = rb_entry(this, struct fsck_inode, rb);
		this = rb_next(this);

		if (S_ISDIR(fscki->mode)) {
			/*
			 * Directories have to have exactly one reference (they
			 * cannot have hardlinks), although root inode is an
			 * exception.
			 */
			if (fscki->inum != UBIFS_ROOT_INO &&
			    fscki->references != 1) {
				ubifs_err("directory inode %lu has %d direntries which refer it, but should be 1",
					  (unsigned long)fscki->inum,
					  fscki->references);
				goto out_dump;
			}
			if (fscki->inum == UBIFS_ROOT_INO &&
			    fscki->references != 0) {
				ubifs_err("root inode %lu has non-zero (%d) direntries which refer it",
					  (unsigned long)fscki->inum,
					  fscki->references);
				goto out_dump;
			}
			if (fscki->calc_sz != fscki->size) {
				ubifs_err("directory inode %lu size is %lld, but calculated size is %lld",
					  (unsigned long)fscki->inum,
					  fscki->size, fscki->calc_sz);
				goto out_dump;
			}
			if (fscki->calc_cnt != fscki->nlink) {
				ubifs_err("directory inode %lu nlink is %d, but calculated nlink is %d",
					  (unsigned long)fscki->inum,
					  fscki->nlink, fscki->calc_cnt);
				goto out_dump;
			}
		} else {
			if (fscki->references != fscki->nlink) {
				ubifs_err("inode %lu nlink is %d, but calculated nlink is %d",
					  (unsigned long)fscki->inum,
					  fscki->nlink, fscki->references);
				goto out_dump;
			}
		}
		if (fscki->xattr_sz != fscki->calc_xsz) {
			ubifs_err("inode %lu has xattr size %u, but calculated size is %lld",
				  (unsigned long)fscki->inum, fscki->xattr_sz,
				  fscki->calc_xsz);
			goto out_dump;
		}
		if (fscki->xattr_cnt != fscki->calc_xcnt) {
			ubifs_err("inode %lu has %u xattrs, but calculated count is %lld",
				  (unsigned long)fscki->inum,
				  fscki->xattr_cnt, fscki->calc_xcnt);
			goto out_dump;
		}
		if (fscki->xattr_nms != fscki->calc_xnms) {
			ubifs_err("inode %lu has xattr names' size %u, but calculated names' size is %lld",
				  (unsigned long)fscki->inum, fscki->xattr_nms,
				  fscki->calc_xnms);
			goto out_dump;
		}
	}

	return 0;

out_dump:
	/* Read the bad inode and dump it */
	ino_key_init(c, &key, fscki->inum);
	err = ubifs_lookup_level0(c, &key, &znode, &n);
	if (!err) {
		ubifs_err("inode %lu not found in index",
			  (unsigned long)fscki->inum);
		return -ENOENT;
	} else if (err < 0) {
		ubifs_err("error %d while looking up inode %lu",
			  err, (unsigned long)fscki->inum);
		return err;
	}

	zbr = &znode->zbranch[n];
	ino = kmalloc(zbr->len, GFP_NOFS);
	if (!ino)
		return -ENOMEM;

	err = ubifs_tnc_read_node(c, zbr, ino);
	if (err) {
		ubifs_err("cannot read inode node at LEB %d:%d, error %d",
			  zbr->lnum, zbr->offs, err);
		kfree(ino);
		return err;
	}

	ubifs_msg("dump of the inode %lu sitting in LEB %d:%d",
		  (unsigned long)fscki->inum, zbr->lnum, zbr->offs);
	ubifs_dump_node(c, ino);
	kfree(ino);
	return -EINVAL;
}

/**
 * dbg_check_filesystem - check the file-system.
 * @c: UBIFS file-system description object
 *
 * This function checks the file system, namely:
 * o makes sure that all leaf nodes exist and their CRCs are correct;
 * o makes sure inode nlink, size, xattr size/count are correct (for all
 *   inodes).
 *
 * The function reads whole indexing tree and all nodes, so it is pretty
 * heavy-weight. Returns zero if the file-system is consistent, %-EINVAL if
 * not, and a negative error code in case of failure.
 */
int dbg_check_filesystem(struct ubifs_info *c)
{
	int err;
	struct fsck_data fsckd;

	if (!dbg_is_chk_fs(c))
		return 0;

	fsckd.inodes = RB_ROOT;
	err = dbg_walk_index(c, check_leaf, NULL, &fsckd);
	if (err)
		goto out_free;

	err = check_inodes(c, &fsckd);
	if (err)
		goto out_free;

	free_inodes(&fsckd);
	return 0;

out_free:
	ubifs_err("file-system check failed with error %d", err);
	dump_stack();
	free_inodes(&fsckd);
	return err;
}

/**
 * dbg_check_data_nodes_order - check that list of data nodes is sorted.
 * @c: UBIFS file-system description object
 * @head: the list of nodes ('struct ubifs_scan_node' objects)
 *
 * This function returns zero if the list of data nodes is sorted correctly,
 * and %-EINVAL if not.
 */
int dbg_check_data_nodes_order(struct ubifs_info *c, struct list_head *head)
{
	struct list_head *cur;
	struct ubifs_scan_node *sa, *sb;

	if (!dbg_is_chk_gen(c))
		return 0;

	for (cur = head->next; cur->next != head; cur = cur->next) {
		ino_t inuma, inumb;
		uint32_t blka, blkb;

		cond_resched();
		sa = container_of(cur, struct ubifs_scan_node, list);
		sb = container_of(cur->next, struct ubifs_scan_node, list);

		if (sa->type != UBIFS_DATA_NODE) {
			ubifs_err("bad node type %d", sa->type);
			ubifs_dump_node(c, sa->node);
			return -EINVAL;
		}
		if (sb->type != UBIFS_DATA_NODE) {
			ubifs_err("bad node type %d", sb->type);
			ubifs_dump_node(c, sb->node);
			return -EINVAL;
		}

		inuma = key_inum(c, &sa->key);
		inumb = key_inum(c, &sb->key);

		if (inuma < inumb)
			continue;
		if (inuma > inumb) {
			ubifs_err("larger inum %lu goes before inum %lu",
				  (unsigned long)inuma, (unsigned long)inumb);
			goto error_dump;
		}

		blka = key_block(c, &sa->key);
		blkb = key_block(c, &sb->key);

		if (blka > blkb) {
			ubifs_err("larger block %u goes before %u", blka, blkb);
			goto error_dump;
		}
		if (blka == blkb) {
			ubifs_err("two data nodes for the same block");
			goto error_dump;
		}
	}

	return 0;

error_dump:
	ubifs_dump_node(c, sa->node);
	ubifs_dump_node(c, sb->node);
	return -EINVAL;
}

/**
 * dbg_check_nondata_nodes_order - check that list of data nodes is sorted.
 * @c: UBIFS file-system description object
 * @head: the list of nodes ('struct ubifs_scan_node' objects)
 *
 * This function returns zero if the list of non-data nodes is sorted correctly,
 * and %-EINVAL if not.
 */
int dbg_check_nondata_nodes_order(struct ubifs_info *c, struct list_head *head)
{
	struct list_head *cur;
	struct ubifs_scan_node *sa, *sb;

	if (!dbg_is_chk_gen(c))
		return 0;

	for (cur = head->next; cur->next != head; cur = cur->next) {
		ino_t inuma, inumb;
		uint32_t hasha, hashb;

		cond_resched();
		sa = container_of(cur, struct ubifs_scan_node, list);
		sb = container_of(cur->next, struct ubifs_scan_node, list);

		if (sa->type != UBIFS_INO_NODE && sa->type != UBIFS_DENT_NODE &&
		    sa->type != UBIFS_XENT_NODE) {
			ubifs_err("bad node type %d", sa->type);
			ubifs_dump_node(c, sa->node);
			return -EINVAL;
		}
		if (sa->type != UBIFS_INO_NODE && sa->type != UBIFS_DENT_NODE &&
		    sa->type != UBIFS_XENT_NODE) {
			ubifs_err("bad node type %d", sb->type);
			ubifs_dump_node(c, sb->node);
			return -EINVAL;
		}

		if (sa->type != UBIFS_INO_NODE && sb->type == UBIFS_INO_NODE) {
			ubifs_err("non-inode node goes before inode node");
			goto error_dump;
		}

		if (sa->type == UBIFS_INO_NODE && sb->type != UBIFS_INO_NODE)
			continue;

		if (sa->type == UBIFS_INO_NODE && sb->type == UBIFS_INO_NODE) {
			/* Inode nodes are sorted in descending size order */
			if (sa->len < sb->len) {
				ubifs_err("smaller inode node goes first");
				goto error_dump;
			}
			continue;
		}

		/*
		 * This is either a dentry or xentry, which should be sorted in
		 * ascending (parent ino, hash) order.
		 */
		inuma = key_inum(c, &sa->key);
		inumb = key_inum(c, &sb->key);

		if (inuma < inumb)
			continue;
		if (inuma > inumb) {
			ubifs_err("larger inum %lu goes before inum %lu",
				  (unsigned long)inuma, (unsigned long)inumb);
			goto error_dump;
		}

		hasha = key_block(c, &sa->key);
		hashb = key_block(c, &sb->key);

		if (hasha > hashb) {
			ubifs_err("larger hash %u goes before %u",
				  hasha, hashb);
			goto error_dump;
		}
	}

	return 0;

error_dump:
	ubifs_msg("dumping first node");
	ubifs_dump_node(c, sa->node);
	ubifs_msg("dumping second node");
	ubifs_dump_node(c, sb->node);
	return -EINVAL;
	return 0;
}

static inline int chance(unsigned int n, unsigned int out_of)
{
	return !!((prandom_u32() % out_of) + 1 <= n);

}

static int power_cut_emulated(struct ubifs_info *c, int lnum, int write)
{
	struct ubifs_debug_info *d = c->dbg;

	ubifs_assert(dbg_is_tst_rcvry(c));

	if (!d->pc_cnt) {
		/* First call - decide delay to the power cut */
		if (chance(1, 2)) {
			unsigned long delay;

			if (chance(1, 2)) {
				d->pc_delay = 1;
				/* Fail within 1 minute */
				delay = prandom_u32() % 60000;
				d->pc_timeout = jiffies;
				d->pc_timeout += msecs_to_jiffies(delay);
				ubifs_warn("failing after %lums", delay);
			} else {
				d->pc_delay = 2;
				delay = prandom_u32() % 10000;
				/* Fail within 10000 operations */
				d->pc_cnt_max = delay;
				ubifs_warn("failing after %lu calls", delay);
			}
		}

		d->pc_cnt += 1;
	}

	/* Determine if failure delay has expired */
	if (d->pc_delay == 1 && time_before(jiffies, d->pc_timeout))
			return 0;
	if (d->pc_delay == 2 && d->pc_cnt++ < d->pc_cnt_max)
			return 0;

	if (lnum == UBIFS_SB_LNUM) {
		if (write && chance(1, 2))
			return 0;
		if (chance(19, 20))
			return 0;
		ubifs_warn("failing in super block LEB %d", lnum);
	} else if (lnum == UBIFS_MST_LNUM || lnum == UBIFS_MST_LNUM + 1) {
		if (chance(19, 20))
			return 0;
		ubifs_warn("failing in master LEB %d", lnum);
	} else if (lnum >= UBIFS_LOG_LNUM && lnum <= c->log_last) {
		if (write && chance(99, 100))
			return 0;
		if (chance(399, 400))
			return 0;
		ubifs_warn("failing in log LEB %d", lnum);
	} else if (lnum >= c->lpt_first && lnum <= c->lpt_last) {
		if (write && chance(7, 8))
			return 0;
		if (chance(19, 20))
			return 0;
		ubifs_warn("failing in LPT LEB %d", lnum);
	} else if (lnum >= c->orph_first && lnum <= c->orph_last) {
		if (write && chance(1, 2))
			return 0;
		if (chance(9, 10))
			return 0;
		ubifs_warn("failing in orphan LEB %d", lnum);
	} else if (lnum == c->ihead_lnum) {
		if (chance(99, 100))
			return 0;
		ubifs_warn("failing in index head LEB %d", lnum);
	} else if (c->jheads && lnum == c->jheads[GCHD].wbuf.lnum) {
		if (chance(9, 10))
			return 0;
		ubifs_warn("failing in GC head LEB %d", lnum);
	} else if (write && !RB_EMPTY_ROOT(&c->buds) &&
		   !ubifs_search_bud(c, lnum)) {
		if (chance(19, 20))
			return 0;
		ubifs_warn("failing in non-bud LEB %d", lnum);
	} else if (c->cmt_state == COMMIT_RUNNING_BACKGROUND ||
		   c->cmt_state == COMMIT_RUNNING_REQUIRED) {
		if (chance(999, 1000))
			return 0;
		ubifs_warn("failing in bud LEB %d commit running", lnum);
	} else {
		if (chance(9999, 10000))
			return 0;
		ubifs_warn("failing in bud LEB %d commit not running", lnum);
	}

	d->pc_happened = 1;
	ubifs_warn("========== Power cut emulated ==========");
	dump_stack();
	return 1;
}

static int corrupt_data(const struct ubifs_info *c, const void *buf,
			unsigned int len)
{
	unsigned int from, to, ffs = chance(1, 2);
	unsigned char *p = (void *)buf;

	from = prandom_u32() % len;
	/* Corruption span max to end of write unit */
	to = min(len, ALIGN(from + 1, c->max_write_size));

	ubifs_warn("filled bytes %u-%u with %s", from, to - 1,
		   ffs ? "0xFFs" : "random data");

	if (ffs)
		memset(p + from, 0xFF, to - from);
	else
		prandom_bytes(p + from, to - from);

	return to;
}

int dbg_leb_write(struct ubifs_info *c, int lnum, const void *buf,
		  int offs, int len)
{
	int err, failing;

	if (c->dbg->pc_happened)
		return -EROFS;

	failing = power_cut_emulated(c, lnum, 1);
	if (failing) {
		len = corrupt_data(c, buf, len);
		ubifs_warn("actually write %d bytes to LEB %d:%d (the buffer was corrupted)",
			   len, lnum, offs);
	}
	err = ubi_leb_write(c->ubi, lnum, buf, offs, len);
	if (err)
		return err;
	if (failing)
		return -EROFS;
	return 0;
}

int dbg_leb_change(struct ubifs_info *c, int lnum, const void *buf,
		   int len)
{
	int err;

	if (c->dbg->pc_happened)
		return -EROFS;
	if (power_cut_emulated(c, lnum, 1))
		return -EROFS;
	err = ubi_leb_change(c->ubi, lnum, buf, len);
	if (err)
		return err;
	if (power_cut_emulated(c, lnum, 1))
		return -EROFS;
	return 0;
}

int dbg_leb_unmap(struct ubifs_info *c, int lnum)
{
	int err;

	if (c->dbg->pc_happened)
		return -EROFS;
	if (power_cut_emulated(c, lnum, 0))
		return -EROFS;
	err = ubi_leb_unmap(c->ubi, lnum);
	if (err)
		return err;
	if (power_cut_emulated(c, lnum, 0))
		return -EROFS;
	return 0;
}

int dbg_leb_map(struct ubifs_info *c, int lnum)
{
	int err;

	if (c->dbg->pc_happened)
		return -EROFS;
	if (power_cut_emulated(c, lnum, 0))
		return -EROFS;
	err = ubi_leb_map(c->ubi, lnum);
	if (err)
		return err;
	if (power_cut_emulated(c, lnum, 0))
		return -EROFS;
	return 0;
}

/*
 * Root directory for UBIFS stuff in debugfs. Contains sub-directories which
 * contain the stuff specific to particular file-system mounts.
 */
static struct dentry *dfs_rootdir;

static int dfs_file_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return nonseekable_open(inode, file);
}

/**
 * provide_user_output - provide output to the user reading a debugfs file.
 * @val: boolean value for the answer
 * @u: the buffer to store the answer at
 * @count: size of the buffer
 * @ppos: position in the @u output buffer
 *
 * This is a simple helper function which stores @val boolean value in the user
 * buffer when the user reads one of UBIFS debugfs files. Returns amount of
 * bytes written to @u in case of success and a negative error code in case of
 * failure.
 */
static int provide_user_output(int val, char __user *u, size_t count,
			       loff_t *ppos)
{
	char buf[3];

	if (val)
		buf[0] = '1';
	else
		buf[0] = '0';
	buf[1] = '\n';
	buf[2] = 0x00;

	return simple_read_from_buffer(u, count, ppos, buf, 2);
}

static ssize_t dfs_file_read(struct file *file, char __user *u, size_t count,
			     loff_t *ppos)
{
	struct dentry *dent = file->f_path.dentry;
	struct ubifs_info *c = file->private_data;
	struct ubifs_debug_info *d = c->dbg;
	int val;

	if (dent == d->dfs_chk_gen)
		val = d->chk_gen;
	else if (dent == d->dfs_chk_index)
		val = d->chk_index;
	else if (dent == d->dfs_chk_orph)
		val = d->chk_orph;
	else if (dent == d->dfs_chk_lprops)
		val = d->chk_lprops;
	else if (dent == d->dfs_chk_fs)
		val = d->chk_fs;
	else if (dent == d->dfs_tst_rcvry)
		val = d->tst_rcvry;
	else if (dent == d->dfs_ro_error)
		val = c->ro_error;
	else
		return -EINVAL;

	return provide_user_output(val, u, count, ppos);
}

/**
 * interpret_user_input - interpret user debugfs file input.
 * @u: user-provided buffer with the input
 * @count: buffer size
 *
 * This is a helper function which interpret user input to a boolean UBIFS
 * debugfs file. Returns %0 or %1 in case of success and a negative error code
 * in case of failure.
 */
static int interpret_user_input(const char __user *u, size_t count)
{
	size_t buf_size;
	char buf[8];

	buf_size = min_t(size_t, count, (sizeof(buf) - 1));
	if (copy_from_user(buf, u, buf_size))
		return -EFAULT;

	if (buf[0] == '1')
		return 1;
	else if (buf[0] == '0')
		return 0;

	return -EINVAL;
}

static ssize_t dfs_file_write(struct file *file, const char __user *u,
			      size_t count, loff_t *ppos)
{
	struct ubifs_info *c = file->private_data;
	struct ubifs_debug_info *d = c->dbg;
	struct dentry *dent = file->f_path.dentry;
	int val;

	/*
	 * TODO: this is racy - the file-system might have already been
	 * unmounted and we'd oops in this case. The plan is to fix it with
	 * help of 'iterate_supers_type()' which we should have in v3.0: when
	 * a debugfs opened, we rember FS's UUID in file->private_data. Then
	 * whenever we access the FS via a debugfs file, we iterate all UBIFS
	 * superblocks and fine the one with the same UUID, and take the
	 * locking right.
	 *
	 * The other way to go suggested by Al Viro is to create a separate
	 * 'ubifs-debug' file-system instead.
	 */
	if (file->f_path.dentry == d->dfs_dump_lprops) {
		ubifs_dump_lprops(c);
		return count;
	}
	if (file->f_path.dentry == d->dfs_dump_budg) {
		ubifs_dump_budg(c, &c->bi);
		return count;
	}
	if (file->f_path.dentry == d->dfs_dump_tnc) {
		mutex_lock(&c->tnc_mutex);
		ubifs_dump_tnc(c);
		mutex_unlock(&c->tnc_mutex);
		return count;
	}

	val = interpret_user_input(u, count);
	if (val < 0)
		return val;

	if (dent == d->dfs_chk_gen)
		d->chk_gen = val;
	else if (dent == d->dfs_chk_index)
		d->chk_index = val;
	else if (dent == d->dfs_chk_orph)
		d->chk_orph = val;
	else if (dent == d->dfs_chk_lprops)
		d->chk_lprops = val;
	else if (dent == d->dfs_chk_fs)
		d->chk_fs = val;
	else if (dent == d->dfs_tst_rcvry)
		d->tst_rcvry = val;
	else if (dent == d->dfs_ro_error)
		c->ro_error = !!val;
	else
		return -EINVAL;

	return count;
}

static const struct file_operations dfs_fops = {
	.open = dfs_file_open,
	.read = dfs_file_read,
	.write = dfs_file_write,
	.owner = THIS_MODULE,
	.llseek = no_llseek,
};

/**
 * dbg_debugfs_init_fs - initialize debugfs for UBIFS instance.
 * @c: UBIFS file-system description object
 *
 * This function creates all debugfs files for this instance of UBIFS. Returns
 * zero in case of success and a negative error code in case of failure.
 *
 * Note, the only reason we have not merged this function with the
 * 'ubifs_debugging_init()' function is because it is better to initialize
 * debugfs interfaces at the very end of the mount process, and remove them at
 * the very beginning of the mount process.
 */
int dbg_debugfs_init_fs(struct ubifs_info *c)
{
	int err, n;
	const char *fname;
	struct dentry *dent;
	struct ubifs_debug_info *d = c->dbg;

	if (!IS_ENABLED(CONFIG_DEBUG_FS))
		return 0;

	n = snprintf(d->dfs_dir_name, UBIFS_DFS_DIR_LEN + 1, UBIFS_DFS_DIR_NAME,
		     c->vi.ubi_num, c->vi.vol_id);
	if (n == UBIFS_DFS_DIR_LEN) {
		/* The array size is too small */
		fname = UBIFS_DFS_DIR_NAME;
		dent = ERR_PTR(-EINVAL);
		goto out;
	}

	fname = d->dfs_dir_name;
	dent = debugfs_create_dir(fname, dfs_rootdir);
	if (IS_ERR_OR_NULL(dent))
		goto out;
	d->dfs_dir = dent;

	fname = "dump_lprops";
	dent = debugfs_create_file(fname, S_IWUSR, d->dfs_dir, c, &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_dump_lprops = dent;

	fname = "dump_budg";
	dent = debugfs_create_file(fname, S_IWUSR, d->dfs_dir, c, &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_dump_budg = dent;

	fname = "dump_tnc";
	dent = debugfs_create_file(fname, S_IWUSR, d->dfs_dir, c, &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_dump_tnc = dent;

	fname = "chk_general";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, d->dfs_dir, c,
				   &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_chk_gen = dent;

	fname = "chk_index";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, d->dfs_dir, c,
				   &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_chk_index = dent;

	fname = "chk_orphans";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, d->dfs_dir, c,
				   &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_chk_orph = dent;

	fname = "chk_lprops";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, d->dfs_dir, c,
				   &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_chk_lprops = dent;

	fname = "chk_fs";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, d->dfs_dir, c,
				   &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_chk_fs = dent;

	fname = "tst_recovery";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, d->dfs_dir, c,
				   &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_tst_rcvry = dent;

	fname = "ro_error";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, d->dfs_dir, c,
				   &dfs_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	d->dfs_ro_error = dent;

	return 0;

out_remove:
	debugfs_remove_recursive(d->dfs_dir);
out:
	err = dent ? PTR_ERR(dent) : -ENODEV;
	ubifs_err("cannot create \"%s\" debugfs file or directory, error %d\n",
		  fname, err);
	return err;
}

/**
 * dbg_debugfs_exit_fs - remove all debugfs files.
 * @c: UBIFS file-system description object
 */
void dbg_debugfs_exit_fs(struct ubifs_info *c)
{
	if (IS_ENABLED(CONFIG_DEBUG_FS))
		debugfs_remove_recursive(c->dbg->dfs_dir);
}

struct ubifs_global_debug_info ubifs_dbg;

static struct dentry *dfs_chk_gen;
static struct dentry *dfs_chk_index;
static struct dentry *dfs_chk_orph;
static struct dentry *dfs_chk_lprops;
static struct dentry *dfs_chk_fs;
static struct dentry *dfs_tst_rcvry;

static ssize_t dfs_global_file_read(struct file *file, char __user *u,
				    size_t count, loff_t *ppos)
{
	struct dentry *dent = file->f_path.dentry;
	int val;

	if (dent == dfs_chk_gen)
		val = ubifs_dbg.chk_gen;
	else if (dent == dfs_chk_index)
		val = ubifs_dbg.chk_index;
	else if (dent == dfs_chk_orph)
		val = ubifs_dbg.chk_orph;
	else if (dent == dfs_chk_lprops)
		val = ubifs_dbg.chk_lprops;
	else if (dent == dfs_chk_fs)
		val = ubifs_dbg.chk_fs;
	else if (dent == dfs_tst_rcvry)
		val = ubifs_dbg.tst_rcvry;
	else
		return -EINVAL;

	return provide_user_output(val, u, count, ppos);
}

static ssize_t dfs_global_file_write(struct file *file, const char __user *u,
				     size_t count, loff_t *ppos)
{
	struct dentry *dent = file->f_path.dentry;
	int val;

	val = interpret_user_input(u, count);
	if (val < 0)
		return val;

	if (dent == dfs_chk_gen)
		ubifs_dbg.chk_gen = val;
	else if (dent == dfs_chk_index)
		ubifs_dbg.chk_index = val;
	else if (dent == dfs_chk_orph)
		ubifs_dbg.chk_orph = val;
	else if (dent == dfs_chk_lprops)
		ubifs_dbg.chk_lprops = val;
	else if (dent == dfs_chk_fs)
		ubifs_dbg.chk_fs = val;
	else if (dent == dfs_tst_rcvry)
		ubifs_dbg.tst_rcvry = val;
	else
		return -EINVAL;

	return count;
}

static const struct file_operations dfs_global_fops = {
	.read = dfs_global_file_read,
	.write = dfs_global_file_write,
	.owner = THIS_MODULE,
	.llseek = no_llseek,
};

/**
 * dbg_debugfs_init - initialize debugfs file-system.
 *
 * UBIFS uses debugfs file-system to expose various debugging knobs to
 * user-space. This function creates "ubifs" directory in the debugfs
 * file-system. Returns zero in case of success and a negative error code in
 * case of failure.
 */
int dbg_debugfs_init(void)
{
	int err;
	const char *fname;
	struct dentry *dent;

	if (!IS_ENABLED(CONFIG_DEBUG_FS))
		return 0;

	fname = "ubifs";
	dent = debugfs_create_dir(fname, NULL);
	if (IS_ERR_OR_NULL(dent))
		goto out;
	dfs_rootdir = dent;

	fname = "chk_general";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, dfs_rootdir, NULL,
				   &dfs_global_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	dfs_chk_gen = dent;

	fname = "chk_index";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, dfs_rootdir, NULL,
				   &dfs_global_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	dfs_chk_index = dent;

	fname = "chk_orphans";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, dfs_rootdir, NULL,
				   &dfs_global_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	dfs_chk_orph = dent;

	fname = "chk_lprops";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, dfs_rootdir, NULL,
				   &dfs_global_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	dfs_chk_lprops = dent;

	fname = "chk_fs";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, dfs_rootdir, NULL,
				   &dfs_global_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	dfs_chk_fs = dent;

	fname = "tst_recovery";
	dent = debugfs_create_file(fname, S_IRUSR | S_IWUSR, dfs_rootdir, NULL,
				   &dfs_global_fops);
	if (IS_ERR_OR_NULL(dent))
		goto out_remove;
	dfs_tst_rcvry = dent;

	return 0;

out_remove:
	debugfs_remove_recursive(dfs_rootdir);
out:
	err = dent ? PTR_ERR(dent) : -ENODEV;
	ubifs_err("cannot create \"%s\" debugfs file or directory, error %d\n",
		  fname, err);
	return err;
}

/**
 * dbg_debugfs_exit - remove the "ubifs" directory from debugfs file-system.
 */
void dbg_debugfs_exit(void)
{
	if (IS_ENABLED(CONFIG_DEBUG_FS))
		debugfs_remove_recursive(dfs_rootdir);
}

/**
 * ubifs_debugging_init - initialize UBIFS debugging.
 * @c: UBIFS file-system description object
 *
 * This function initializes debugging-related data for the file system.
 * Returns zero in case of success and a negative error code in case of
 * failure.
 */
int ubifs_debugging_init(struct ubifs_info *c)
{
	c->dbg = kzalloc(sizeof(struct ubifs_debug_info), GFP_KERNEL);
	if (!c->dbg)
		return -ENOMEM;

	return 0;
}

/**
 * ubifs_debugging_exit - free debugging data.
 * @c: UBIFS file-system description object
 */
void ubifs_debugging_exit(struct ubifs_info *c)
{
	kfree(c->dbg);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ubifs/debug.c */
/************************************************************/
