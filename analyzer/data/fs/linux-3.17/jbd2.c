/*
 * linux/fs/jbd2/transaction.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Generic filesystem transaction handling code; part of the ext2fs
 * journaling system.
 *
 * This file manages transactions (compound commits managed by the
 * journaling code) and handles (individual atomic operations by the
 * filesystem).
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/jbd2.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/backing-dev.h>
#include <linux/bug.h>
#include <linux/module.h>

#include <trace/events/jbd2.h>

static void __jbd2_journal_temp_unlink_buffer(struct journal_head *jh);
static void __jbd2_journal_unfile_buffer(struct journal_head *jh);

static struct kmem_cache *transaction_cache;
int __init jbd2_journal_init_transaction_cache(void)
{
	J_ASSERT(!transaction_cache);
	transaction_cache = kmem_cache_create("jbd2_transaction_s",
					sizeof(transaction_t),
					0,
					SLAB_HWCACHE_ALIGN|SLAB_TEMPORARY,
					NULL);
	if (transaction_cache)
		return 0;
	return -ENOMEM;
}

void jbd2_journal_destroy_transaction_cache(void)
{
	if (transaction_cache) {
		kmem_cache_destroy(transaction_cache);
		transaction_cache = NULL;
	}
}

void jbd2_journal_free_transaction(transaction_t *transaction)
{
	if (unlikely(ZERO_OR_NULL_PTR(transaction)))
		return;
	kmem_cache_free(transaction_cache, transaction);
}

/*
 * jbd2_get_transaction: obtain a new transaction_t object.
 *
 * Simply allocate and initialise a new transaction.  Create it in
 * RUNNING state and add it to the current journal (which should not
 * have an existing running transaction: we only make a new transaction
 * once we have started to commit the old one).
 *
 * Preconditions:
 *	The journal MUST be locked.  We don't perform atomic mallocs on the
 *	new transaction	and we can't block without protecting against other
 *	processes trying to touch the journal while it is in transition.
 *
 */

static transaction_t *
jbd2_get_transaction(journal_t *journal, transaction_t *transaction)
{
	transaction->t_journal = journal;
	transaction->t_state = T_RUNNING;
	transaction->t_start_time = ktime_get();
	transaction->t_tid = journal->j_transaction_sequence++;
	transaction->t_expires = jiffies + journal->j_commit_interval;
	spin_lock_init(&transaction->t_handle_lock);
	atomic_set(&transaction->t_updates, 0);
	atomic_set(&transaction->t_outstanding_credits,
		   atomic_read(&journal->j_reserved_credits));
	atomic_set(&transaction->t_handle_count, 0);
	INIT_LIST_HEAD(&transaction->t_inode_list);
	INIT_LIST_HEAD(&transaction->t_private_list);

	/* Set up the commit timer for the new transaction. */
	journal->j_commit_timer.expires = round_jiffies_up(transaction->t_expires);
	add_timer(&journal->j_commit_timer);

	J_ASSERT(journal->j_running_transaction == NULL);
	journal->j_running_transaction = transaction;
	transaction->t_max_wait = 0;
	transaction->t_start = jiffies;
	transaction->t_requested = 0;

	return transaction;
}

/*
 * Handle management.
 *
 * A handle_t is an object which represents a single atomic update to a
 * filesystem, and which tracks all of the modifications which form part
 * of that one update.
 */

/*
 * Update transaction's maximum wait time, if debugging is enabled.
 *
 * In order for t_max_wait to be reliable, it must be protected by a
 * lock.  But doing so will mean that start_this_handle() can not be
 * run in parallel on SMP systems, which limits our scalability.  So
 * unless debugging is enabled, we no longer update t_max_wait, which
 * means that maximum wait time reported by the jbd2_run_stats
 * tracepoint will always be zero.
 */
static inline void update_t_max_wait(transaction_t *transaction,
				     unsigned long ts)
{
#ifdef CONFIG_JBD2_DEBUG
	if (jbd2_journal_enable_debug &&
	    time_after(transaction->t_start, ts)) {
		ts = jbd2_time_diff(ts, transaction->t_start);
		spin_lock(&transaction->t_handle_lock);
		if (ts > transaction->t_max_wait)
			transaction->t_max_wait = ts;
		spin_unlock(&transaction->t_handle_lock);
	}
#endif
}

/*
 * Wait until running transaction passes T_LOCKED state. Also starts the commit
 * if needed. The function expects running transaction to exist and releases
 * j_state_lock.
 */
static void wait_transaction_locked(journal_t *journal)
	__releases(journal->j_state_lock)
{
	DEFINE_WAIT(wait);
	int need_to_start;
	tid_t tid = journal->j_running_transaction->t_tid;

	prepare_to_wait(&journal->j_wait_transaction_locked, &wait,
			TASK_UNINTERRUPTIBLE);
	need_to_start = !tid_geq(journal->j_commit_request, tid);
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		jbd2_log_start_commit(journal, tid);
	schedule();
	finish_wait(&journal->j_wait_transaction_locked, &wait);
}

static void sub_reserved_credits(journal_t *journal, int blocks)
{
	atomic_sub(blocks, &journal->j_reserved_credits);
	wake_up(&journal->j_wait_reserved);
}

/*
 * Wait until we can add credits for handle to the running transaction.  Called
 * with j_state_lock held for reading. Returns 0 if handle joined the running
 * transaction. Returns 1 if we had to wait, j_state_lock is dropped, and
 * caller must retry.
 */
static int add_transaction_credits(journal_t *journal, int blocks,
				   int rsv_blocks)
{
	transaction_t *t = journal->j_running_transaction;
	int needed;
	int total = blocks + rsv_blocks;

	/*
	 * If the current transaction is locked down for commit, wait
	 * for the lock to be released.
	 */
	if (t->t_state == T_LOCKED) {
		wait_transaction_locked(journal);
		return 1;
	}

	/*
	 * If there is not enough space left in the log to write all
	 * potential buffers requested by this operation, we need to
	 * stall pending a log checkpoint to free some more log space.
	 */
	needed = atomic_add_return(total, &t->t_outstanding_credits);
	if (needed > journal->j_max_transaction_buffers) {
		/*
		 * If the current transaction is already too large,
		 * then start to commit it: we can then go back and
		 * attach this handle to a new transaction.
		 */
		atomic_sub(total, &t->t_outstanding_credits);
		wait_transaction_locked(journal);
		return 1;
	}

	/*
	 * The commit code assumes that it can get enough log space
	 * without forcing a checkpoint.  This is *critical* for
	 * correctness: a checkpoint of a buffer which is also
	 * associated with a committing transaction creates a deadlock,
	 * so commit simply cannot force through checkpoints.
	 *
	 * We must therefore ensure the necessary space in the journal
	 * *before* starting to dirty potentially checkpointed buffers
	 * in the new transaction.
	 */
	if (jbd2_log_space_left(journal) < jbd2_space_needed(journal)) {
		atomic_sub(total, &t->t_outstanding_credits);
		read_unlock(&journal->j_state_lock);
		write_lock(&journal->j_state_lock);
		if (jbd2_log_space_left(journal) < jbd2_space_needed(journal))
			__jbd2_log_wait_for_space(journal);
		write_unlock(&journal->j_state_lock);
		return 1;
	}

	/* No reservation? We are done... */
	if (!rsv_blocks)
		return 0;

	needed = atomic_add_return(rsv_blocks, &journal->j_reserved_credits);
	/* We allow at most half of a transaction to be reserved */
	if (needed > journal->j_max_transaction_buffers / 2) {
		sub_reserved_credits(journal, rsv_blocks);
		atomic_sub(total, &t->t_outstanding_credits);
		read_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_reserved,
			 atomic_read(&journal->j_reserved_credits) + rsv_blocks
			 <= journal->j_max_transaction_buffers / 2);
		return 1;
	}
	return 0;
}

/*
 * start_this_handle: Given a handle, deal with any locking or stalling
 * needed to make sure that there is enough journal space for the handle
 * to begin.  Attach the handle to a transaction and set up the
 * transaction's buffer credits.
 */

static int start_this_handle(journal_t *journal, handle_t *handle,
			     gfp_t gfp_mask)
{
	transaction_t	*transaction, *new_transaction = NULL;
	int		blocks = handle->h_buffer_credits;
	int		rsv_blocks = 0;
	unsigned long ts = jiffies;

	/*
	 * 1/2 of transaction can be reserved so we can practically handle
	 * only 1/2 of maximum transaction size per operation
	 */
	if (WARN_ON(blocks > journal->j_max_transaction_buffers / 2)) {
		printk(KERN_ERR "JBD2: %s wants too many credits (%d > %d)\n",
		       current->comm, blocks,
		       journal->j_max_transaction_buffers / 2);
		return -ENOSPC;
	}

	if (handle->h_rsv_handle)
		rsv_blocks = handle->h_rsv_handle->h_buffer_credits;

alloc_transaction:
	if (!journal->j_running_transaction) {
		new_transaction = kmem_cache_zalloc(transaction_cache,
						    gfp_mask);
		if (!new_transaction) {
			/*
			 * If __GFP_FS is not present, then we may be
			 * being called from inside the fs writeback
			 * layer, so we MUST NOT fail.  Since
			 * __GFP_NOFAIL is going away, we will arrange
			 * to retry the allocation ourselves.
			 */
			if ((gfp_mask & __GFP_FS) == 0) {
				congestion_wait(BLK_RW_ASYNC, HZ/50);
				goto alloc_transaction;
			}
			return -ENOMEM;
		}
	}

	jbd_debug(3, "New handle %p going live.\n", handle);

	/*
	 * We need to hold j_state_lock until t_updates has been incremented,
	 * for proper journal barrier handling
	 */
repeat:
	read_lock(&journal->j_state_lock);
	BUG_ON(journal->j_flags & JBD2_UNMOUNT);
	if (is_journal_aborted(journal) ||
	    (journal->j_errno != 0 && !(journal->j_flags & JBD2_ACK_ERR))) {
		read_unlock(&journal->j_state_lock);
		jbd2_journal_free_transaction(new_transaction);
		return -EROFS;
	}

	/*
	 * Wait on the journal's transaction barrier if necessary. Specifically
	 * we allow reserved handles to proceed because otherwise commit could
	 * deadlock on page writeback not being able to complete.
	 */
	if (!handle->h_reserved && journal->j_barrier_count) {
		read_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_transaction_locked,
				journal->j_barrier_count == 0);
		goto repeat;
	}

	if (!journal->j_running_transaction) {
		read_unlock(&journal->j_state_lock);
		if (!new_transaction)
			goto alloc_transaction;
		write_lock(&journal->j_state_lock);
		if (!journal->j_running_transaction &&
		    (handle->h_reserved || !journal->j_barrier_count)) {
			jbd2_get_transaction(journal, new_transaction);
			new_transaction = NULL;
		}
		write_unlock(&journal->j_state_lock);
		goto repeat;
	}

	transaction = journal->j_running_transaction;

	if (!handle->h_reserved) {
		/* We may have dropped j_state_lock - restart in that case */
		if (add_transaction_credits(journal, blocks, rsv_blocks))
			goto repeat;
	} else {
		/*
		 * We have handle reserved so we are allowed to join T_LOCKED
		 * transaction and we don't have to check for transaction size
		 * and journal space.
		 */
		sub_reserved_credits(journal, blocks);
		handle->h_reserved = 0;
	}

	/* OK, account for the buffers that this operation expects to
	 * use and add the handle to the running transaction.
	 */
	update_t_max_wait(transaction, ts);
	handle->h_transaction = transaction;
	handle->h_requested_credits = blocks;
	handle->h_start_jiffies = jiffies;
	atomic_inc(&transaction->t_updates);
	atomic_inc(&transaction->t_handle_count);
	jbd_debug(4, "Handle %p given %d credits (total %d, free %lu)\n",
		  handle, blocks,
		  atomic_read(&transaction->t_outstanding_credits),
		  jbd2_log_space_left(journal));
	read_unlock(&journal->j_state_lock);
	current->journal_info = handle;

	lock_map_acquire(&handle->h_lockdep_map);
	jbd2_journal_free_transaction(new_transaction);
	return 0;
}

static struct lock_class_key jbd2_handle_key;

/* Allocate a new handle.  This should probably be in a slab... */
static handle_t *new_handle(int nblocks)
{
	handle_t *handle = jbd2_alloc_handle(GFP_NOFS);
	if (!handle)
		return NULL;
	handle->h_buffer_credits = nblocks;
	handle->h_ref = 1;

	lockdep_init_map(&handle->h_lockdep_map, "jbd2_handle",
						&jbd2_handle_key, 0);

	return handle;
}

/**
 * handle_t *jbd2_journal_start() - Obtain a new handle.
 * @journal: Journal to start transaction on.
 * @nblocks: number of block buffer we might modify
 *
 * We make sure that the transaction can guarantee at least nblocks of
 * modified buffers in the log.  We block until the log can guarantee
 * that much space. Additionally, if rsv_blocks > 0, we also create another
 * handle with rsv_blocks reserved blocks in the journal. This handle is
 * is stored in h_rsv_handle. It is not attached to any particular transaction
 * and thus doesn't block transaction commit. If the caller uses this reserved
 * handle, it has to set h_rsv_handle to NULL as otherwise jbd2_journal_stop()
 * on the parent handle will dispose the reserved one. Reserved handle has to
 * be converted to a normal handle using jbd2_journal_start_reserved() before
 * it can be used.
 *
 * Return a pointer to a newly allocated handle, or an ERR_PTR() value
 * on failure.
 */
handle_t *jbd2__journal_start(journal_t *journal, int nblocks, int rsv_blocks,
			      gfp_t gfp_mask, unsigned int type,
			      unsigned int line_no)
{
	handle_t *handle = journal_current_handle();
	int err;

	if (!journal)
		return ERR_PTR(-EROFS);

	if (handle) {
		J_ASSERT(handle->h_transaction->t_journal == journal);
		handle->h_ref++;
		return handle;
	}

	handle = new_handle(nblocks);
	if (!handle)
		return ERR_PTR(-ENOMEM);
	if (rsv_blocks) {
		handle_t *rsv_handle;

		rsv_handle = new_handle(rsv_blocks);
		if (!rsv_handle) {
			jbd2_free_handle(handle);
			return ERR_PTR(-ENOMEM);
		}
		rsv_handle->h_reserved = 1;
		rsv_handle->h_journal = journal;
		handle->h_rsv_handle = rsv_handle;
	}

	err = start_this_handle(journal, handle, gfp_mask);
	if (err < 0) {
		if (handle->h_rsv_handle)
			jbd2_free_handle(handle->h_rsv_handle);
		jbd2_free_handle(handle);
		return ERR_PTR(err);
	}
	handle->h_type = type;
	handle->h_line_no = line_no;
	trace_jbd2_handle_start(journal->j_fs_dev->bd_dev,
				handle->h_transaction->t_tid, type,
				line_no, nblocks);
	return handle;
}
EXPORT_SYMBOL(jbd2__journal_start);


handle_t *jbd2_journal_start(journal_t *journal, int nblocks)
{
	return jbd2__journal_start(journal, nblocks, 0, GFP_NOFS, 0, 0);
}
EXPORT_SYMBOL(jbd2_journal_start);

void jbd2_journal_free_reserved(handle_t *handle)
{
	journal_t *journal = handle->h_journal;

	WARN_ON(!handle->h_reserved);
	sub_reserved_credits(journal, handle->h_buffer_credits);
	jbd2_free_handle(handle);
}
EXPORT_SYMBOL(jbd2_journal_free_reserved);

/**
 * int jbd2_journal_start_reserved(handle_t *handle) - start reserved handle
 * @handle: handle to start
 *
 * Start handle that has been previously reserved with jbd2_journal_reserve().
 * This attaches @handle to the running transaction (or creates one if there's
 * not transaction running). Unlike jbd2_journal_start() this function cannot
 * block on journal commit, checkpointing, or similar stuff. It can block on
 * memory allocation or frozen journal though.
 *
 * Return 0 on success, non-zero on error - handle is freed in that case.
 */
int jbd2_journal_start_reserved(handle_t *handle, unsigned int type,
				unsigned int line_no)
{
	journal_t *journal = handle->h_journal;
	int ret = -EIO;

	if (WARN_ON(!handle->h_reserved)) {
		/* Someone passed in normal handle? Just stop it. */
		jbd2_journal_stop(handle);
		return ret;
	}
	/*
	 * Usefulness of mixing of reserved and unreserved handles is
	 * questionable. So far nobody seems to need it so just error out.
	 */
	if (WARN_ON(current->journal_info)) {
		jbd2_journal_free_reserved(handle);
		return ret;
	}

	handle->h_journal = NULL;
	/*
	 * GFP_NOFS is here because callers are likely from writeback or
	 * similarly constrained call sites
	 */
	ret = start_this_handle(journal, handle, GFP_NOFS);
	if (ret < 0) {
		jbd2_journal_free_reserved(handle);
		return ret;
	}
	handle->h_type = type;
	handle->h_line_no = line_no;
	return 0;
}
EXPORT_SYMBOL(jbd2_journal_start_reserved);

/**
 * int jbd2_journal_extend() - extend buffer credits.
 * @handle:  handle to 'extend'
 * @nblocks: nr blocks to try to extend by.
 *
 * Some transactions, such as large extends and truncates, can be done
 * atomically all at once or in several stages.  The operation requests
 * a credit for a number of buffer modications in advance, but can
 * extend its credit if it needs more.
 *
 * jbd2_journal_extend tries to give the running handle more buffer credits.
 * It does not guarantee that allocation - this is a best-effort only.
 * The calling process MUST be able to deal cleanly with a failure to
 * extend here.
 *
 * Return 0 on success, non-zero on failure.
 *
 * return code < 0 implies an error
 * return code > 0 implies normal transaction-full status.
 */
int jbd2_journal_extend(handle_t *handle, int nblocks)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int result;
	int wanted;

	WARN_ON(!transaction);
	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	result = 1;

	read_lock(&journal->j_state_lock);

	/* Don't extend a locked-down transaction! */
	if (transaction->t_state != T_RUNNING) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "transaction not running\n", handle, nblocks);
		goto error_out;
	}

	spin_lock(&transaction->t_handle_lock);
	wanted = atomic_add_return(nblocks,
				   &transaction->t_outstanding_credits);

	if (wanted > journal->j_max_transaction_buffers) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "transaction too large\n", handle, nblocks);
		atomic_sub(nblocks, &transaction->t_outstanding_credits);
		goto unlock;
	}

	if (wanted + (wanted >> JBD2_CONTROL_BLOCKS_SHIFT) >
	    jbd2_log_space_left(journal)) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "insufficient log space\n", handle, nblocks);
		atomic_sub(nblocks, &transaction->t_outstanding_credits);
		goto unlock;
	}

	trace_jbd2_handle_extend(journal->j_fs_dev->bd_dev,
				 transaction->t_tid,
				 handle->h_type, handle->h_line_no,
				 handle->h_buffer_credits,
				 nblocks);

	handle->h_buffer_credits += nblocks;
	handle->h_requested_credits += nblocks;
	result = 0;

	jbd_debug(3, "extended handle %p by %d\n", handle, nblocks);
unlock:
	spin_unlock(&transaction->t_handle_lock);
error_out:
	read_unlock(&journal->j_state_lock);
	return result;
}


/**
 * int jbd2_journal_restart() - restart a handle .
 * @handle:  handle to restart
 * @nblocks: nr credits requested
 *
 * Restart a handle for a multi-transaction filesystem
 * operation.
 *
 * If the jbd2_journal_extend() call above fails to grant new buffer credits
 * to a running handle, a call to jbd2_journal_restart will commit the
 * handle's transaction so far and reattach the handle to a new
 * transaction capabable of guaranteeing the requested number of
 * credits. We preserve reserved handle if there's any attached to the
 * passed in handle.
 */
int jbd2__journal_restart(handle_t *handle, int nblocks, gfp_t gfp_mask)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	tid_t		tid;
	int		need_to_start, ret;

	WARN_ON(!transaction);
	/* If we've had an abort of any type, don't even think about
	 * actually doing the restart! */
	if (is_handle_aborted(handle))
		return 0;
	journal = transaction->t_journal;

	/*
	 * First unlink the handle from its current transaction, and start the
	 * commit on that.
	 */
	J_ASSERT(atomic_read(&transaction->t_updates) > 0);
	J_ASSERT(journal_current_handle() == handle);

	read_lock(&journal->j_state_lock);
	spin_lock(&transaction->t_handle_lock);
	atomic_sub(handle->h_buffer_credits,
		   &transaction->t_outstanding_credits);
	if (handle->h_rsv_handle) {
		sub_reserved_credits(journal,
				     handle->h_rsv_handle->h_buffer_credits);
	}
	if (atomic_dec_and_test(&transaction->t_updates))
		wake_up(&journal->j_wait_updates);
	tid = transaction->t_tid;
	spin_unlock(&transaction->t_handle_lock);
	handle->h_transaction = NULL;
	current->journal_info = NULL;

	jbd_debug(2, "restarting handle %p\n", handle);
	need_to_start = !tid_geq(journal->j_commit_request, tid);
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		jbd2_log_start_commit(journal, tid);

	lock_map_release(&handle->h_lockdep_map);
	handle->h_buffer_credits = nblocks;
	ret = start_this_handle(journal, handle, gfp_mask);
	return ret;
}
EXPORT_SYMBOL(jbd2__journal_restart);


int jbd2_journal_restart(handle_t *handle, int nblocks)
{
	return jbd2__journal_restart(handle, nblocks, GFP_NOFS);
}
EXPORT_SYMBOL(jbd2_journal_restart);

/**
 * void jbd2_journal_lock_updates () - establish a transaction barrier.
 * @journal:  Journal to establish a barrier on.
 *
 * This locks out any further updates from being started, and blocks
 * until all existing updates have completed, returning only once the
 * journal is in a quiescent state with no updates running.
 *
 * The journal lock should not be held on entry.
 */
void jbd2_journal_lock_updates(journal_t *journal)
{
	DEFINE_WAIT(wait);

	write_lock(&journal->j_state_lock);
	++journal->j_barrier_count;

	/* Wait until there are no reserved handles */
	if (atomic_read(&journal->j_reserved_credits)) {
		write_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_reserved,
			   atomic_read(&journal->j_reserved_credits) == 0);
		write_lock(&journal->j_state_lock);
	}

	/* Wait until there are no running updates */
	while (1) {
		transaction_t *transaction = journal->j_running_transaction;

		if (!transaction)
			break;

		spin_lock(&transaction->t_handle_lock);
		prepare_to_wait(&journal->j_wait_updates, &wait,
				TASK_UNINTERRUPTIBLE);
		if (!atomic_read(&transaction->t_updates)) {
			spin_unlock(&transaction->t_handle_lock);
			finish_wait(&journal->j_wait_updates, &wait);
			break;
		}
		spin_unlock(&transaction->t_handle_lock);
		write_unlock(&journal->j_state_lock);
		schedule();
		finish_wait(&journal->j_wait_updates, &wait);
		write_lock(&journal->j_state_lock);
	}
	write_unlock(&journal->j_state_lock);

	/*
	 * We have now established a barrier against other normal updates, but
	 * we also need to barrier against other jbd2_journal_lock_updates() calls
	 * to make sure that we serialise special journal-locked operations
	 * too.
	 */
	mutex_lock(&journal->j_barrier);
}

/**
 * void jbd2_journal_unlock_updates (journal_t* journal) - release barrier
 * @journal:  Journal to release the barrier on.
 *
 * Release a transaction barrier obtained with jbd2_journal_lock_updates().
 *
 * Should be called without the journal lock held.
 */
void jbd2_journal_unlock_updates (journal_t *journal)
{
	J_ASSERT(journal->j_barrier_count != 0);

	mutex_unlock(&journal->j_barrier);
	write_lock(&journal->j_state_lock);
	--journal->j_barrier_count;
	write_unlock(&journal->j_state_lock);
	wake_up(&journal->j_wait_transaction_locked);
}

static void warn_dirty_buffer(struct buffer_head *bh)
{
	char b[BDEVNAME_SIZE];

	printk(KERN_WARNING
	       "JBD2: Spotted dirty metadata buffer (dev = %s, blocknr = %llu). "
	       "There's a risk of filesystem corruption in case of system "
	       "crash.\n",
	       bdevname(bh->b_bdev, b), (unsigned long long)bh->b_blocknr);
}

/*
 * If the buffer is already part of the current transaction, then there
 * is nothing we need to do.  If it is already part of a prior
 * transaction which we are still committing to disk, then we need to
 * make sure that we do not overwrite the old copy: we do copy-out to
 * preserve the copy going to disk.  We also account the buffer against
 * the handle's metadata buffer credits (unless the buffer is already
 * part of the transaction, that is).
 *
 */
static int
do_get_write_access(handle_t *handle, struct journal_head *jh,
			int force_copy)
{
	struct buffer_head *bh;
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int error;
	char *frozen_buffer = NULL;
	int need_copy = 0;
	unsigned long start_lock, time_lock;

	WARN_ON(!transaction);
	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	jbd_debug(5, "journal_head %p, force_copy %d\n", jh, force_copy);

	JBUFFER_TRACE(jh, "entry");
repeat:
	bh = jh2bh(jh);

	/* @@@ Need to check for errors here at some point. */

 	start_lock = jiffies;
	lock_buffer(bh);
	jbd_lock_bh_state(bh);

	/* If it takes too long to lock the buffer, trace it */
	time_lock = jbd2_time_diff(start_lock, jiffies);
	if (time_lock > HZ/10)
		trace_jbd2_lock_buffer_stall(bh->b_bdev->bd_dev,
			jiffies_to_msecs(time_lock));

	/* We now hold the buffer lock so it is safe to query the buffer
	 * state.  Is the buffer dirty?
	 *
	 * If so, there are two possibilities.  The buffer may be
	 * non-journaled, and undergoing a quite legitimate writeback.
	 * Otherwise, it is journaled, and we don't expect dirty buffers
	 * in that state (the buffers should be marked JBD_Dirty
	 * instead.)  So either the IO is being done under our own
	 * control and this is a bug, or it's a third party IO such as
	 * dump(8) (which may leave the buffer scheduled for read ---
	 * ie. locked but not dirty) or tune2fs (which may actually have
	 * the buffer dirtied, ugh.)  */

	if (buffer_dirty(bh)) {
		/*
		 * First question: is this buffer already part of the current
		 * transaction or the existing committing transaction?
		 */
		if (jh->b_transaction) {
			J_ASSERT_JH(jh,
				jh->b_transaction == transaction ||
				jh->b_transaction ==
					journal->j_committing_transaction);
			if (jh->b_next_transaction)
				J_ASSERT_JH(jh, jh->b_next_transaction ==
							transaction);
			warn_dirty_buffer(bh);
		}
		/*
		 * In any case we need to clean the dirty flag and we must
		 * do it under the buffer lock to be sure we don't race
		 * with running write-out.
		 */
		JBUFFER_TRACE(jh, "Journalling dirty buffer");
		clear_buffer_dirty(bh);
		set_buffer_jbddirty(bh);
	}

	unlock_buffer(bh);

	error = -EROFS;
	if (is_handle_aborted(handle)) {
		jbd_unlock_bh_state(bh);
		goto out;
	}
	error = 0;

	/*
	 * The buffer is already part of this transaction if b_transaction or
	 * b_next_transaction points to it
	 */
	if (jh->b_transaction == transaction ||
	    jh->b_next_transaction == transaction)
		goto done;

	/*
	 * this is the first time this transaction is touching this buffer,
	 * reset the modified flag
	 */
       jh->b_modified = 0;

	/*
	 * If there is already a copy-out version of this buffer, then we don't
	 * need to make another one
	 */
	if (jh->b_frozen_data) {
		JBUFFER_TRACE(jh, "has frozen data");
		J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
		jh->b_next_transaction = transaction;
		goto done;
	}

	/* Is there data here we need to preserve? */

	if (jh->b_transaction && jh->b_transaction != transaction) {
		JBUFFER_TRACE(jh, "owned by older transaction");
		J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
		J_ASSERT_JH(jh, jh->b_transaction ==
					journal->j_committing_transaction);

		/* There is one case we have to be very careful about.
		 * If the committing transaction is currently writing
		 * this buffer out to disk and has NOT made a copy-out,
		 * then we cannot modify the buffer contents at all
		 * right now.  The essence of copy-out is that it is the
		 * extra copy, not the primary copy, which gets
		 * journaled.  If the primary copy is already going to
		 * disk then we cannot do copy-out here. */

		if (buffer_shadow(bh)) {
			JBUFFER_TRACE(jh, "on shadow: sleep");
			jbd_unlock_bh_state(bh);
			wait_on_bit_io(&bh->b_state, BH_Shadow,
				       TASK_UNINTERRUPTIBLE);
			goto repeat;
		}

		/*
		 * Only do the copy if the currently-owning transaction still
		 * needs it. If buffer isn't on BJ_Metadata list, the
		 * committing transaction is past that stage (here we use the
		 * fact that BH_Shadow is set under bh_state lock together with
		 * refiling to BJ_Shadow list and at this point we know the
		 * buffer doesn't have BH_Shadow set).
		 *
		 * Subtle point, though: if this is a get_undo_access,
		 * then we will be relying on the frozen_data to contain
		 * the new value of the committed_data record after the
		 * transaction, so we HAVE to force the frozen_data copy
		 * in that case.
		 */
		if (jh->b_jlist == BJ_Metadata || force_copy) {
			JBUFFER_TRACE(jh, "generate frozen data");
			if (!frozen_buffer) {
				JBUFFER_TRACE(jh, "allocate memory for buffer");
				jbd_unlock_bh_state(bh);
				frozen_buffer =
					jbd2_alloc(jh2bh(jh)->b_size,
							 GFP_NOFS);
				if (!frozen_buffer) {
					printk(KERN_ERR
					       "%s: OOM for frozen_buffer\n",
					       __func__);
					JBUFFER_TRACE(jh, "oom!");
					error = -ENOMEM;
					jbd_lock_bh_state(bh);
					goto done;
				}
				goto repeat;
			}
			jh->b_frozen_data = frozen_buffer;
			frozen_buffer = NULL;
			need_copy = 1;
		}
		jh->b_next_transaction = transaction;
	}


	/*
	 * Finally, if the buffer is not journaled right now, we need to make
	 * sure it doesn't get written to disk before the caller actually
	 * commits the new data
	 */
	if (!jh->b_transaction) {
		JBUFFER_TRACE(jh, "no transaction");
		J_ASSERT_JH(jh, !jh->b_next_transaction);
		JBUFFER_TRACE(jh, "file as BJ_Reserved");
		spin_lock(&journal->j_list_lock);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Reserved);
		spin_unlock(&journal->j_list_lock);
	}

done:
	if (need_copy) {
		struct page *page;
		int offset;
		char *source;

		J_EXPECT_JH(jh, buffer_uptodate(jh2bh(jh)),
			    "Possible IO failure.\n");
		page = jh2bh(jh)->b_page;
		offset = offset_in_page(jh2bh(jh)->b_data);
		source = kmap_atomic(page);
		/* Fire data frozen trigger just before we copy the data */
		jbd2_buffer_frozen_trigger(jh, source + offset,
					   jh->b_triggers);
		memcpy(jh->b_frozen_data, source+offset, jh2bh(jh)->b_size);
		kunmap_atomic(source);

		/*
		 * Now that the frozen data is saved off, we need to store
		 * any matching triggers.
		 */
		jh->b_frozen_triggers = jh->b_triggers;
	}
	jbd_unlock_bh_state(bh);

	/*
	 * If we are about to journal a buffer, then any revoke pending on it is
	 * no longer valid
	 */
	jbd2_journal_cancel_revoke(handle, jh);

out:
	if (unlikely(frozen_buffer))	/* It's usually NULL */
		jbd2_free(frozen_buffer, bh->b_size);

	JBUFFER_TRACE(jh, "exit");
	return error;
}

/**
 * int jbd2_journal_get_write_access() - notify intent to modify a buffer for metadata (not data) update.
 * @handle: transaction to add buffer modifications to
 * @bh:     bh to be used for metadata writes
 *
 * Returns an error code or 0 on success.
 *
 * In full data journalling mode the buffer may be of type BJ_AsyncData,
 * because we're write()ing a buffer which is also part of a shared mapping.
 */

int jbd2_journal_get_write_access(handle_t *handle, struct buffer_head *bh)
{
	struct journal_head *jh = jbd2_journal_add_journal_head(bh);
	int rc;

	/* We do not want to get caught playing with fields which the
	 * log thread also manipulates.  Make sure that the buffer
	 * completes any outstanding IO before proceeding. */
	rc = do_get_write_access(handle, jh, 0);
	jbd2_journal_put_journal_head(jh);
	return rc;
}


/*
 * When the user wants to journal a newly created buffer_head
 * (ie. getblk() returned a new buffer and we are going to populate it
 * manually rather than reading off disk), then we need to keep the
 * buffer_head locked until it has been completely filled with new
 * data.  In this case, we should be able to make the assertion that
 * the bh is not already part of an existing transaction.
 *
 * The buffer should already be locked by the caller by this point.
 * There is no lock ranking violation: it was a newly created,
 * unlocked buffer beforehand. */

/**
 * int jbd2_journal_get_create_access () - notify intent to use newly created bh
 * @handle: transaction to new buffer to
 * @bh: new buffer.
 *
 * Call this if you create a new bh.
 */
int jbd2_journal_get_create_access(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh = jbd2_journal_add_journal_head(bh);
	int err;

	jbd_debug(5, "journal_head %p\n", jh);
	WARN_ON(!transaction);
	err = -EROFS;
	if (is_handle_aborted(handle))
		goto out;
	journal = transaction->t_journal;
	err = 0;

	JBUFFER_TRACE(jh, "entry");
	/*
	 * The buffer may already belong to this transaction due to pre-zeroing
	 * in the filesystem's new_block code.  It may also be on the previous,
	 * committing transaction's lists, but it HAS to be in Forget state in
	 * that case: the transaction must have deleted the buffer for it to be
	 * reused here.
	 */
	jbd_lock_bh_state(bh);
	J_ASSERT_JH(jh, (jh->b_transaction == transaction ||
		jh->b_transaction == NULL ||
		(jh->b_transaction == journal->j_committing_transaction &&
			  jh->b_jlist == BJ_Forget)));

	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, buffer_locked(jh2bh(jh)));

	if (jh->b_transaction == NULL) {
		/*
		 * Previous jbd2_journal_forget() could have left the buffer
		 * with jbddirty bit set because it was being committed. When
		 * the commit finished, we've filed the buffer for
		 * checkpointing and marked it dirty. Now we are reallocating
		 * the buffer so the transaction freeing it must have
		 * committed and so it's safe to clear the dirty bit.
		 */
		clear_buffer_dirty(jh2bh(jh));
		/* first access by this transaction */
		jh->b_modified = 0;

		JBUFFER_TRACE(jh, "file as BJ_Reserved");
		spin_lock(&journal->j_list_lock);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Reserved);
	} else if (jh->b_transaction == journal->j_committing_transaction) {
		/* first access by this transaction */
		jh->b_modified = 0;

		JBUFFER_TRACE(jh, "set next transaction");
		spin_lock(&journal->j_list_lock);
		jh->b_next_transaction = transaction;
	}
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh);

	/*
	 * akpm: I added this.  ext3_alloc_branch can pick up new indirect
	 * blocks which contain freed but then revoked metadata.  We need
	 * to cancel the revoke in case we end up freeing it yet again
	 * and the reallocating as data - this would cause a second revoke,
	 * which hits an assertion error.
	 */
	JBUFFER_TRACE(jh, "cancelling revoke");
	jbd2_journal_cancel_revoke(handle, jh);
out:
	jbd2_journal_put_journal_head(jh);
	return err;
}

/**
 * int jbd2_journal_get_undo_access() -  Notify intent to modify metadata with
 *     non-rewindable consequences
 * @handle: transaction
 * @bh: buffer to undo
 *
 * Sometimes there is a need to distinguish between metadata which has
 * been committed to disk and that which has not.  The ext3fs code uses
 * this for freeing and allocating space, we have to make sure that we
 * do not reuse freed space until the deallocation has been committed,
 * since if we overwrote that space we would make the delete
 * un-rewindable in case of a crash.
 *
 * To deal with that, jbd2_journal_get_undo_access requests write access to a
 * buffer for parts of non-rewindable operations such as delete
 * operations on the bitmaps.  The journaling code must keep a copy of
 * the buffer's contents prior to the undo_access call until such time
 * as we know that the buffer has definitely been committed to disk.
 *
 * We never need to know which transaction the committed data is part
 * of, buffers touched here are guaranteed to be dirtied later and so
 * will be committed to a new transaction in due course, at which point
 * we can discard the old committed data pointer.
 *
 * Returns error number or 0 on success.
 */
int jbd2_journal_get_undo_access(handle_t *handle, struct buffer_head *bh)
{
	int err;
	struct journal_head *jh = jbd2_journal_add_journal_head(bh);
	char *committed_data = NULL;

	JBUFFER_TRACE(jh, "entry");

	/*
	 * Do this first --- it can drop the journal lock, so we want to
	 * make sure that obtaining the committed_data is done
	 * atomically wrt. completion of any outstanding commits.
	 */
	err = do_get_write_access(handle, jh, 1);
	if (err)
		goto out;

repeat:
	if (!jh->b_committed_data) {
		committed_data = jbd2_alloc(jh2bh(jh)->b_size, GFP_NOFS);
		if (!committed_data) {
			printk(KERN_ERR "%s: No memory for committed data\n",
				__func__);
			err = -ENOMEM;
			goto out;
		}
	}

	jbd_lock_bh_state(bh);
	if (!jh->b_committed_data) {
		/* Copy out the current buffer contents into the
		 * preserved, committed copy. */
		JBUFFER_TRACE(jh, "generate b_committed data");
		if (!committed_data) {
			jbd_unlock_bh_state(bh);
			goto repeat;
		}

		jh->b_committed_data = committed_data;
		committed_data = NULL;
		memcpy(jh->b_committed_data, bh->b_data, bh->b_size);
	}
	jbd_unlock_bh_state(bh);
out:
	jbd2_journal_put_journal_head(jh);
	if (unlikely(committed_data))
		jbd2_free(committed_data, bh->b_size);
	return err;
}

/**
 * void jbd2_journal_set_triggers() - Add triggers for commit writeout
 * @bh: buffer to trigger on
 * @type: struct jbd2_buffer_trigger_type containing the trigger(s).
 *
 * Set any triggers on this journal_head.  This is always safe, because
 * triggers for a committing buffer will be saved off, and triggers for
 * a running transaction will match the buffer in that transaction.
 *
 * Call with NULL to clear the triggers.
 */
void jbd2_journal_set_triggers(struct buffer_head *bh,
			       struct jbd2_buffer_trigger_type *type)
{
	struct journal_head *jh = jbd2_journal_grab_journal_head(bh);

	if (WARN_ON(!jh))
		return;
	jh->b_triggers = type;
	jbd2_journal_put_journal_head(jh);
}

void jbd2_buffer_frozen_trigger(struct journal_head *jh, void *mapped_data,
				struct jbd2_buffer_trigger_type *triggers)
{
	struct buffer_head *bh = jh2bh(jh);

	if (!triggers || !triggers->t_frozen)
		return;

	triggers->t_frozen(triggers, bh, mapped_data, bh->b_size);
}

void jbd2_buffer_abort_trigger(struct journal_head *jh,
			       struct jbd2_buffer_trigger_type *triggers)
{
	if (!triggers || !triggers->t_abort)
		return;

	triggers->t_abort(triggers, jh2bh(jh));
}



/**
 * int jbd2_journal_dirty_metadata() -  mark a buffer as containing dirty metadata
 * @handle: transaction to add buffer to.
 * @bh: buffer to mark
 *
 * mark dirty metadata which needs to be journaled as part of the current
 * transaction.
 *
 * The buffer must have previously had jbd2_journal_get_write_access()
 * called so that it has a valid journal_head attached to the buffer
 * head.
 *
 * The buffer is placed on the transaction's metadata list and is marked
 * as belonging to the transaction.
 *
 * Returns error number or 0 on success.
 *
 * Special care needs to be taken if the buffer already belongs to the
 * current committing transaction (in which case we should have frozen
 * data present for that commit).  In that case, we don't relink the
 * buffer: that only gets done when the old transaction finally
 * completes its commit.
 */
int jbd2_journal_dirty_metadata(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh;
	int ret = 0;

	WARN_ON(!transaction);
	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;
	jh = jbd2_journal_grab_journal_head(bh);
	if (!jh) {
		ret = -EUCLEAN;
		goto out;
	}
	jbd_debug(5, "journal_head %p\n", jh);
	JBUFFER_TRACE(jh, "entry");

	jbd_lock_bh_state(bh);

	if (jh->b_modified == 0) {
		/*
		 * This buffer's got modified and becoming part
		 * of the transaction. This needs to be done
		 * once a transaction -bzzz
		 */
		jh->b_modified = 1;
		if (handle->h_buffer_credits <= 0) {
			ret = -ENOSPC;
			goto out_unlock_bh;
		}
		handle->h_buffer_credits--;
	}

	/*
	 * fastpath, to avoid expensive locking.  If this buffer is already
	 * on the running transaction's metadata list there is nothing to do.
	 * Nobody can take it off again because there is a handle open.
	 * I _think_ we're OK here with SMP barriers - a mistaken decision will
	 * result in this test being false, so we go in and take the locks.
	 */
	if (jh->b_transaction == transaction && jh->b_jlist == BJ_Metadata) {
		JBUFFER_TRACE(jh, "fastpath");
		if (unlikely(jh->b_transaction !=
			     journal->j_running_transaction)) {
			printk(KERN_ERR "JBD2: %s: "
			       "jh->b_transaction (%llu, %p, %u) != "
			       "journal->j_running_transaction (%p, %u)\n",
			       journal->j_devname,
			       (unsigned long long) bh->b_blocknr,
			       jh->b_transaction,
			       jh->b_transaction ? jh->b_transaction->t_tid : 0,
			       journal->j_running_transaction,
			       journal->j_running_transaction ?
			       journal->j_running_transaction->t_tid : 0);
			ret = -EINVAL;
		}
		goto out_unlock_bh;
	}

	set_buffer_jbddirty(bh);

	/*
	 * Metadata already on the current transaction list doesn't
	 * need to be filed.  Metadata on another transaction's list must
	 * be committing, and will be refiled once the commit completes:
	 * leave it alone for now.
	 */
	if (jh->b_transaction != transaction) {
		JBUFFER_TRACE(jh, "already on other transaction");
		if (unlikely(((jh->b_transaction !=
			       journal->j_committing_transaction)) ||
			     (jh->b_next_transaction != transaction))) {
			printk(KERN_ERR "jbd2_journal_dirty_metadata: %s: "
			       "bad jh for block %llu: "
			       "transaction (%p, %u), "
			       "jh->b_transaction (%p, %u), "
			       "jh->b_next_transaction (%p, %u), jlist %u\n",
			       journal->j_devname,
			       (unsigned long long) bh->b_blocknr,
			       transaction, transaction->t_tid,
			       jh->b_transaction,
			       jh->b_transaction ?
			       jh->b_transaction->t_tid : 0,
			       jh->b_next_transaction,
			       jh->b_next_transaction ?
			       jh->b_next_transaction->t_tid : 0,
			       jh->b_jlist);
			WARN_ON(1);
			ret = -EINVAL;
		}
		/* And this case is illegal: we can't reuse another
		 * transaction's data buffer, ever. */
		goto out_unlock_bh;
	}

	/* That test should have eliminated the following case: */
	J_ASSERT_JH(jh, jh->b_frozen_data == NULL);

	JBUFFER_TRACE(jh, "file as BJ_Metadata");
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_file_buffer(jh, transaction, BJ_Metadata);
	spin_unlock(&journal->j_list_lock);
out_unlock_bh:
	jbd_unlock_bh_state(bh);
	jbd2_journal_put_journal_head(jh);
out:
	JBUFFER_TRACE(jh, "exit");
	return ret;
}

/**
 * void jbd2_journal_forget() - bforget() for potentially-journaled buffers.
 * @handle: transaction handle
 * @bh:     bh to 'forget'
 *
 * We can only do the bforget if there are no commits pending against the
 * buffer.  If the buffer is dirty in the current running transaction we
 * can safely unlink it.
 *
 * bh may not be a journalled buffer at all - it may be a non-JBD
 * buffer which came off the hashtable.  Check for this.
 *
 * Decrements bh->b_count by one.
 *
 * Allow this call even if the handle has aborted --- it may be part of
 * the caller's cleanup after an abort.
 */
int jbd2_journal_forget (handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	struct journal_head *jh;
	int drop_reserve = 0;
	int err = 0;
	int was_modified = 0;

	WARN_ON(!transaction);
	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	BUFFER_TRACE(bh, "entry");

	jbd_lock_bh_state(bh);

	if (!buffer_jbd(bh))
		goto not_jbd;
	jh = bh2jh(bh);

	/* Critical error: attempting to delete a bitmap buffer, maybe?
	 * Don't do any jbd operations, and return an error. */
	if (!J_EXPECT_JH(jh, !jh->b_committed_data,
			 "inconsistent data on disk")) {
		err = -EIO;
		goto not_jbd;
	}

	/* keep track of whether or not this transaction modified us */
	was_modified = jh->b_modified;

	/*
	 * The buffer's going from the transaction, we must drop
	 * all references -bzzz
	 */
	jh->b_modified = 0;

	if (jh->b_transaction == transaction) {
		J_ASSERT_JH(jh, !jh->b_frozen_data);

		/* If we are forgetting a buffer which is already part
		 * of this transaction, then we can just drop it from
		 * the transaction immediately. */
		clear_buffer_dirty(bh);
		clear_buffer_jbddirty(bh);

		JBUFFER_TRACE(jh, "belongs to current transaction: unfile");

		/*
		 * we only want to drop a reference if this transaction
		 * modified the buffer
		 */
		if (was_modified)
			drop_reserve = 1;

		/*
		 * We are no longer going to journal this buffer.
		 * However, the commit of this transaction is still
		 * important to the buffer: the delete that we are now
		 * processing might obsolete an old log entry, so by
		 * committing, we can satisfy the buffer's checkpoint.
		 *
		 * So, if we have a checkpoint on the buffer, we should
		 * now refile the buffer on our BJ_Forget list so that
		 * we know to remove the checkpoint after we commit.
		 */

		spin_lock(&journal->j_list_lock);
		if (jh->b_cp_transaction) {
			__jbd2_journal_temp_unlink_buffer(jh);
			__jbd2_journal_file_buffer(jh, transaction, BJ_Forget);
		} else {
			__jbd2_journal_unfile_buffer(jh);
			if (!buffer_jbd(bh)) {
				spin_unlock(&journal->j_list_lock);
				jbd_unlock_bh_state(bh);
				__bforget(bh);
				goto drop;
			}
		}
		spin_unlock(&journal->j_list_lock);
	} else if (jh->b_transaction) {
		J_ASSERT_JH(jh, (jh->b_transaction ==
				 journal->j_committing_transaction));
		/* However, if the buffer is still owned by a prior
		 * (committing) transaction, we can't drop it yet... */
		JBUFFER_TRACE(jh, "belongs to older transaction");
		/* ... but we CAN drop it from the new transaction if we
		 * have also modified it since the original commit. */

		if (jh->b_next_transaction) {
			J_ASSERT(jh->b_next_transaction == transaction);
			spin_lock(&journal->j_list_lock);
			jh->b_next_transaction = NULL;
			spin_unlock(&journal->j_list_lock);

			/*
			 * only drop a reference if this transaction modified
			 * the buffer
			 */
			if (was_modified)
				drop_reserve = 1;
		}
	}

not_jbd:
	jbd_unlock_bh_state(bh);
	__brelse(bh);
drop:
	if (drop_reserve) {
		/* no need to reserve log space for this block -bzzz */
		handle->h_buffer_credits++;
	}
	return err;
}

/**
 * int jbd2_journal_stop() - complete a transaction
 * @handle: tranaction to complete.
 *
 * All done for a particular handle.
 *
 * There is not much action needed here.  We just return any remaining
 * buffer credits to the transaction and remove the handle.  The only
 * complication is that we need to start a commit operation if the
 * filesystem is marked for synchronous update.
 *
 * jbd2_journal_stop itself will not usually return an error, but it may
 * do so in unusual circumstances.  In particular, expect it to
 * return -EIO if a jbd2_journal_abort has been executed since the
 * transaction began.
 */
int jbd2_journal_stop(handle_t *handle)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;
	int err = 0, wait_for_commit = 0;
	tid_t tid;
	pid_t pid;

	if (!transaction)
		goto free_and_exit;
	journal = transaction->t_journal;

	J_ASSERT(journal_current_handle() == handle);

	if (is_handle_aborted(handle))
		err = -EIO;
	else
		J_ASSERT(atomic_read(&transaction->t_updates) > 0);

	if (--handle->h_ref > 0) {
		jbd_debug(4, "h_ref %d -> %d\n", handle->h_ref + 1,
			  handle->h_ref);
		return err;
	}

	jbd_debug(4, "Handle %p going down\n", handle);
	trace_jbd2_handle_stats(journal->j_fs_dev->bd_dev,
				transaction->t_tid,
				handle->h_type, handle->h_line_no,
				jiffies - handle->h_start_jiffies,
				handle->h_sync, handle->h_requested_credits,
				(handle->h_requested_credits -
				 handle->h_buffer_credits));

	/*
	 * Implement synchronous transaction batching.  If the handle
	 * was synchronous, don't force a commit immediately.  Let's
	 * yield and let another thread piggyback onto this
	 * transaction.  Keep doing that while new threads continue to
	 * arrive.  It doesn't cost much - we're about to run a commit
	 * and sleep on IO anyway.  Speeds up many-threaded, many-dir
	 * operations by 30x or more...
	 *
	 * We try and optimize the sleep time against what the
	 * underlying disk can do, instead of having a static sleep
	 * time.  This is useful for the case where our storage is so
	 * fast that it is more optimal to go ahead and force a flush
	 * and wait for the transaction to be committed than it is to
	 * wait for an arbitrary amount of time for new writers to
	 * join the transaction.  We achieve this by measuring how
	 * long it takes to commit a transaction, and compare it with
	 * how long this transaction has been running, and if run time
	 * < commit time then we sleep for the delta and commit.  This
	 * greatly helps super fast disks that would see slowdowns as
	 * more threads started doing fsyncs.
	 *
	 * But don't do this if this process was the most recent one
	 * to perform a synchronous write.  We do this to detect the
	 * case where a single process is doing a stream of sync
	 * writes.  No point in waiting for joiners in that case.
	 *
	 * Setting max_batch_time to 0 disables this completely.
	 */
	pid = current->pid;
	if (handle->h_sync && journal->j_last_sync_writer != pid &&
	    journal->j_max_batch_time) {
		u64 commit_time, trans_time;

		journal->j_last_sync_writer = pid;

		read_lock(&journal->j_state_lock);
		commit_time = journal->j_average_commit_time;
		read_unlock(&journal->j_state_lock);

		trans_time = ktime_to_ns(ktime_sub(ktime_get(),
						   transaction->t_start_time));

		commit_time = max_t(u64, commit_time,
				    1000*journal->j_min_batch_time);
		commit_time = min_t(u64, commit_time,
				    1000*journal->j_max_batch_time);

		if (trans_time < commit_time) {
			ktime_t expires = ktime_add_ns(ktime_get(),
						       commit_time);
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_hrtimeout(&expires, HRTIMER_MODE_ABS);
		}
	}

	if (handle->h_sync)
		transaction->t_synchronous_commit = 1;
	current->journal_info = NULL;
	atomic_sub(handle->h_buffer_credits,
		   &transaction->t_outstanding_credits);

	/*
	 * If the handle is marked SYNC, we need to set another commit
	 * going!  We also want to force a commit if the current
	 * transaction is occupying too much of the log, or if the
	 * transaction is too old now.
	 */
	if (handle->h_sync ||
	    (atomic_read(&transaction->t_outstanding_credits) >
	     journal->j_max_transaction_buffers) ||
	    time_after_eq(jiffies, transaction->t_expires)) {
		/* Do this even for aborted journals: an abort still
		 * completes the commit thread, it just doesn't write
		 * anything to disk. */

		jbd_debug(2, "transaction too old, requesting commit for "
					"handle %p\n", handle);
		/* This is non-blocking */
		jbd2_log_start_commit(journal, transaction->t_tid);

		/*
		 * Special case: JBD2_SYNC synchronous updates require us
		 * to wait for the commit to complete.
		 */
		if (handle->h_sync && !(current->flags & PF_MEMALLOC))
			wait_for_commit = 1;
	}

	/*
	 * Once we drop t_updates, if it goes to zero the transaction
	 * could start committing on us and eventually disappear.  So
	 * once we do this, we must not dereference transaction
	 * pointer again.
	 */
	tid = transaction->t_tid;
	if (atomic_dec_and_test(&transaction->t_updates)) {
		wake_up(&journal->j_wait_updates);
		if (journal->j_barrier_count)
			wake_up(&journal->j_wait_transaction_locked);
	}

	if (wait_for_commit)
		err = jbd2_log_wait_commit(journal, tid);

	lock_map_release(&handle->h_lockdep_map);

	if (handle->h_rsv_handle)
		jbd2_journal_free_reserved(handle->h_rsv_handle);
free_and_exit:
	jbd2_free_handle(handle);
	return err;
}

/*
 *
 * List management code snippets: various functions for manipulating the
 * transaction buffer lists.
 *
 */

/*
 * Append a buffer to a transaction list, given the transaction's list head
 * pointer.
 *
 * j_list_lock is held.
 *
 * jbd_lock_bh_state(jh2bh(jh)) is held.
 */

static inline void
__blist_add_buffer(struct journal_head **list, struct journal_head *jh)
{
	if (!*list) {
		jh->b_tnext = jh->b_tprev = jh;
		*list = jh;
	} else {
		/* Insert at the tail of the list to preserve order */
		struct journal_head *first = *list, *last = first->b_tprev;
		jh->b_tprev = last;
		jh->b_tnext = first;
		last->b_tnext = first->b_tprev = jh;
	}
}

/*
 * Remove a buffer from a transaction list, given the transaction's list
 * head pointer.
 *
 * Called with j_list_lock held, and the journal may not be locked.
 *
 * jbd_lock_bh_state(jh2bh(jh)) is held.
 */

static inline void
__blist_del_buffer(struct journal_head **list, struct journal_head *jh)
{
	if (*list == jh) {
		*list = jh->b_tnext;
		if (*list == jh)
			*list = NULL;
	}
	jh->b_tprev->b_tnext = jh->b_tnext;
	jh->b_tnext->b_tprev = jh->b_tprev;
}

/*
 * Remove a buffer from the appropriate transaction list.
 *
 * Note that this function can *change* the value of
 * bh->b_transaction->t_buffers, t_forget, t_shadow_list, t_log_list or
 * t_reserved_list.  If the caller is holding onto a copy of one of these
 * pointers, it could go bad.  Generally the caller needs to re-read the
 * pointer from the transaction_t.
 *
 * Called under j_list_lock.
 */
static void __jbd2_journal_temp_unlink_buffer(struct journal_head *jh)
{
	struct journal_head **list = NULL;
	transaction_t *transaction;
	struct buffer_head *bh = jh2bh(jh);

	J_ASSERT_JH(jh, jbd_is_locked_bh_state(bh));
	transaction = jh->b_transaction;
	if (transaction)
		assert_spin_locked(&transaction->t_journal->j_list_lock);

	J_ASSERT_JH(jh, jh->b_jlist < BJ_Types);
	if (jh->b_jlist != BJ_None)
		J_ASSERT_JH(jh, transaction != NULL);

	switch (jh->b_jlist) {
	case BJ_None:
		return;
	case BJ_Metadata:
		transaction->t_nr_buffers--;
		J_ASSERT_JH(jh, transaction->t_nr_buffers >= 0);
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	}

	__blist_del_buffer(list, jh);
	jh->b_jlist = BJ_None;
	if (test_clear_buffer_jbddirty(bh))
		mark_buffer_dirty(bh);	/* Expose it to the VM */
}

/*
 * Remove buffer from all transactions.
 *
 * Called with bh_state lock and j_list_lock
 *
 * jh and bh may be already freed when this function returns.
 */
static void __jbd2_journal_unfile_buffer(struct journal_head *jh)
{
	__jbd2_journal_temp_unlink_buffer(jh);
	jh->b_transaction = NULL;
	jbd2_journal_put_journal_head(jh);
}

void jbd2_journal_unfile_buffer(journal_t *journal, struct journal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	/* Get reference so that buffer cannot be freed before we unlock it */
	get_bh(bh);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_unfile_buffer(jh);
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh);
	__brelse(bh);
}

/*
 * Called from jbd2_journal_try_to_free_buffers().
 *
 * Called under jbd_lock_bh_state(bh)
 */
static void
__journal_try_to_free_buffer(journal_t *journal, struct buffer_head *bh)
{
	struct journal_head *jh;

	jh = bh2jh(bh);

	if (buffer_locked(bh) || buffer_dirty(bh))
		goto out;

	if (jh->b_next_transaction != NULL || jh->b_transaction != NULL)
		goto out;

	spin_lock(&journal->j_list_lock);
	if (jh->b_cp_transaction != NULL) {
		/* written-back checkpointed metadata buffer */
		JBUFFER_TRACE(jh, "remove from checkpoint list");
		__jbd2_journal_remove_checkpoint(jh);
	}
	spin_unlock(&journal->j_list_lock);
out:
	return;
}

/**
 * int jbd2_journal_try_to_free_buffers() - try to free page buffers.
 * @journal: journal for operation
 * @page: to try and free
 * @gfp_mask: we use the mask to detect how hard should we try to release
 * buffers. If __GFP_WAIT and __GFP_FS is set, we wait for commit code to
 * release the buffers.
 *
 *
 * For all the buffers on this page,
 * if they are fully written out ordered data, move them onto BUF_CLEAN
 * so try_to_free_buffers() can reap them.
 *
 * This function returns non-zero if we wish try_to_free_buffers()
 * to be called. We do this if the page is releasable by try_to_free_buffers().
 * We also do it if the page has locked or dirty buffers and the caller wants
 * us to perform sync or async writeout.
 *
 * This complicates JBD locking somewhat.  We aren't protected by the
 * BKL here.  We wish to remove the buffer from its committing or
 * running transaction's ->t_datalist via __jbd2_journal_unfile_buffer.
 *
 * This may *change* the value of transaction_t->t_datalist, so anyone
 * who looks at t_datalist needs to lock against this function.
 *
 * Even worse, someone may be doing a jbd2_journal_dirty_data on this
 * buffer.  So we need to lock against that.  jbd2_journal_dirty_data()
 * will come out of the lock with the buffer dirty, which makes it
 * ineligible for release here.
 *
 * Who else is affected by this?  hmm...  Really the only contender
 * is do_get_write_access() - it could be looking at the buffer while
 * journal_try_to_free_buffer() is changing its state.  But that
 * cannot happen because we never reallocate freed data as metadata
 * while the data is part of a transaction.  Yes?
 *
 * Return 0 on failure, 1 on success
 */
int jbd2_journal_try_to_free_buffers(journal_t *journal,
				struct page *page, gfp_t gfp_mask)
{
	struct buffer_head *head;
	struct buffer_head *bh;
	int ret = 0;

	J_ASSERT(PageLocked(page));

	head = page_buffers(page);
	bh = head;
	do {
		struct journal_head *jh;

		/*
		 * We take our own ref against the journal_head here to avoid
		 * having to add tons of locking around each instance of
		 * jbd2_journal_put_journal_head().
		 */
		jh = jbd2_journal_grab_journal_head(bh);
		if (!jh)
			continue;

		jbd_lock_bh_state(bh);
		__journal_try_to_free_buffer(journal, bh);
		jbd2_journal_put_journal_head(jh);
		jbd_unlock_bh_state(bh);
		if (buffer_jbd(bh))
			goto busy;
	} while ((bh = bh->b_this_page) != head);

	ret = try_to_free_buffers(page);

busy:
	return ret;
}

/*
 * This buffer is no longer needed.  If it is on an older transaction's
 * checkpoint list we need to record it on this transaction's forget list
 * to pin this buffer (and hence its checkpointing transaction) down until
 * this transaction commits.  If the buffer isn't on a checkpoint list, we
 * release it.
 * Returns non-zero if JBD no longer has an interest in the buffer.
 *
 * Called under j_list_lock.
 *
 * Called under jbd_lock_bh_state(bh).
 */
static int __dispose_buffer(struct journal_head *jh, transaction_t *transaction)
{
	int may_free = 1;
	struct buffer_head *bh = jh2bh(jh);

	if (jh->b_cp_transaction) {
		JBUFFER_TRACE(jh, "on running+cp transaction");
		__jbd2_journal_temp_unlink_buffer(jh);
		/*
		 * We don't want to write the buffer anymore, clear the
		 * bit so that we don't confuse checks in
		 * __journal_file_buffer
		 */
		clear_buffer_dirty(bh);
		__jbd2_journal_file_buffer(jh, transaction, BJ_Forget);
		may_free = 0;
	} else {
		JBUFFER_TRACE(jh, "on running transaction");
		__jbd2_journal_unfile_buffer(jh);
	}
	return may_free;
}

/*
 * jbd2_journal_invalidatepage
 *
 * This code is tricky.  It has a number of cases to deal with.
 *
 * There are two invariants which this code relies on:
 *
 * i_size must be updated on disk before we start calling invalidatepage on the
 * data.
 *
 *  This is done in ext3 by defining an ext3_setattr method which
 *  updates i_size before truncate gets going.  By maintaining this
 *  invariant, we can be sure that it is safe to throw away any buffers
 *  attached to the current transaction: once the transaction commits,
 *  we know that the data will not be needed.
 *
 *  Note however that we can *not* throw away data belonging to the
 *  previous, committing transaction!
 *
 * Any disk blocks which *are* part of the previous, committing
 * transaction (and which therefore cannot be discarded immediately) are
 * not going to be reused in the new running transaction
 *
 *  The bitmap committed_data images guarantee this: any block which is
 *  allocated in one transaction and removed in the next will be marked
 *  as in-use in the committed_data bitmap, so cannot be reused until
 *  the next transaction to delete the block commits.  This means that
 *  leaving committing buffers dirty is quite safe: the disk blocks
 *  cannot be reallocated to a different file and so buffer aliasing is
 *  not possible.
 *
 *
 * The above applies mainly to ordered data mode.  In writeback mode we
 * don't make guarantees about the order in which data hits disk --- in
 * particular we don't guarantee that new dirty data is flushed before
 * transaction commit --- so it is always safe just to discard data
 * immediately in that mode.  --sct
 */

/*
 * The journal_unmap_buffer helper function returns zero if the buffer
 * concerned remains pinned as an anonymous buffer belonging to an older
 * transaction.
 *
 * We're outside-transaction here.  Either or both of j_running_transaction
 * and j_committing_transaction may be NULL.
 */
static int journal_unmap_buffer(journal_t *journal, struct buffer_head *bh,
				int partial_page)
{
	transaction_t *transaction;
	struct journal_head *jh;
	int may_free = 1;

	BUFFER_TRACE(bh, "entry");

	/*
	 * It is safe to proceed here without the j_list_lock because the
	 * buffers cannot be stolen by try_to_free_buffers as long as we are
	 * holding the page lock. --sct
	 */

	if (!buffer_jbd(bh))
		goto zap_buffer_unlocked;

	/* OK, we have data buffer in journaled mode */
	write_lock(&journal->j_state_lock);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);

	jh = jbd2_journal_grab_journal_head(bh);
	if (!jh)
		goto zap_buffer_no_jh;

	/*
	 * We cannot remove the buffer from checkpoint lists until the
	 * transaction adding inode to orphan list (let's call it T)
	 * is committed.  Otherwise if the transaction changing the
	 * buffer would be cleaned from the journal before T is
	 * committed, a crash will cause that the correct contents of
	 * the buffer will be lost.  On the other hand we have to
	 * clear the buffer dirty bit at latest at the moment when the
	 * transaction marking the buffer as freed in the filesystem
	 * structures is committed because from that moment on the
	 * block can be reallocated and used by a different page.
	 * Since the block hasn't been freed yet but the inode has
	 * already been added to orphan list, it is safe for us to add
	 * the buffer to BJ_Forget list of the newest transaction.
	 *
	 * Also we have to clear buffer_mapped flag of a truncated buffer
	 * because the buffer_head may be attached to the page straddling
	 * i_size (can happen only when blocksize < pagesize) and thus the
	 * buffer_head can be reused when the file is extended again. So we end
	 * up keeping around invalidated buffers attached to transactions'
	 * BJ_Forget list just to stop checkpointing code from cleaning up
	 * the transaction this buffer was modified in.
	 */
	transaction = jh->b_transaction;
	if (transaction == NULL) {
		/* First case: not on any transaction.  If it
		 * has no checkpoint link, then we can zap it:
		 * it's a writeback-mode buffer so we don't care
		 * if it hits disk safely. */
		if (!jh->b_cp_transaction) {
			JBUFFER_TRACE(jh, "not on any transaction: zap");
			goto zap_buffer;
		}

		if (!buffer_dirty(bh)) {
			/* bdflush has written it.  We can drop it now */
			goto zap_buffer;
		}

		/* OK, it must be in the journal but still not
		 * written fully to disk: it's metadata or
		 * journaled data... */

		if (journal->j_running_transaction) {
			/* ... and once the current transaction has
			 * committed, the buffer won't be needed any
			 * longer. */
			JBUFFER_TRACE(jh, "checkpointed: add to BJ_Forget");
			may_free = __dispose_buffer(jh,
					journal->j_running_transaction);
			goto zap_buffer;
		} else {
			/* There is no currently-running transaction. So the
			 * orphan record which we wrote for this file must have
			 * passed into commit.  We must attach this buffer to
			 * the committing transaction, if it exists. */
			if (journal->j_committing_transaction) {
				JBUFFER_TRACE(jh, "give to committing trans");
				may_free = __dispose_buffer(jh,
					journal->j_committing_transaction);
				goto zap_buffer;
			} else {
				/* The orphan record's transaction has
				 * committed.  We can cleanse this buffer */
				clear_buffer_jbddirty(bh);
				goto zap_buffer;
			}
		}
	} else if (transaction == journal->j_committing_transaction) {
		JBUFFER_TRACE(jh, "on committing transaction");
		/*
		 * The buffer is committing, we simply cannot touch
		 * it. If the page is straddling i_size we have to wait
		 * for commit and try again.
		 */
		if (partial_page) {
			jbd2_journal_put_journal_head(jh);
			spin_unlock(&journal->j_list_lock);
			jbd_unlock_bh_state(bh);
			write_unlock(&journal->j_state_lock);
			return -EBUSY;
		}
		/*
		 * OK, buffer won't be reachable after truncate. We just set
		 * j_next_transaction to the running transaction (if there is
		 * one) and mark buffer as freed so that commit code knows it
		 * should clear dirty bits when it is done with the buffer.
		 */
		set_buffer_freed(bh);
		if (journal->j_running_transaction && buffer_jbddirty(bh))
			jh->b_next_transaction = journal->j_running_transaction;
		jbd2_journal_put_journal_head(jh);
		spin_unlock(&journal->j_list_lock);
		jbd_unlock_bh_state(bh);
		write_unlock(&journal->j_state_lock);
		return 0;
	} else {
		/* Good, the buffer belongs to the running transaction.
		 * We are writing our own transaction's data, not any
		 * previous one's, so it is safe to throw it away
		 * (remember that we expect the filesystem to have set
		 * i_size already for this truncate so recovery will not
		 * expose the disk blocks we are discarding here.) */
		J_ASSERT_JH(jh, transaction == journal->j_running_transaction);
		JBUFFER_TRACE(jh, "on running transaction");
		may_free = __dispose_buffer(jh, transaction);
	}

zap_buffer:
	/*
	 * This is tricky. Although the buffer is truncated, it may be reused
	 * if blocksize < pagesize and it is attached to the page straddling
	 * EOF. Since the buffer might have been added to BJ_Forget list of the
	 * running transaction, journal_get_write_access() won't clear
	 * b_modified and credit accounting gets confused. So clear b_modified
	 * here.
	 */
	jh->b_modified = 0;
	jbd2_journal_put_journal_head(jh);
zap_buffer_no_jh:
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh);
	write_unlock(&journal->j_state_lock);
zap_buffer_unlocked:
	clear_buffer_dirty(bh);
	J_ASSERT_BH(bh, !buffer_jbddirty(bh));
	clear_buffer_mapped(bh);
	clear_buffer_req(bh);
	clear_buffer_new(bh);
	clear_buffer_delay(bh);
	clear_buffer_unwritten(bh);
	bh->b_bdev = NULL;
	return may_free;
}

/**
 * void jbd2_journal_invalidatepage()
 * @journal: journal to use for flush...
 * @page:    page to flush
 * @offset:  start of the range to invalidate
 * @length:  length of the range to invalidate
 *
 * Reap page buffers containing data after in the specified range in page.
 * Can return -EBUSY if buffers are part of the committing transaction and
 * the page is straddling i_size. Caller then has to wait for current commit
 * and try again.
 */
int jbd2_journal_invalidatepage(journal_t *journal,
				struct page *page,
				unsigned int offset,
				unsigned int length)
{
	struct buffer_head *head, *bh, *next;
	unsigned int stop = offset + length;
	unsigned int curr_off = 0;
	int partial_page = (offset || length < PAGE_CACHE_SIZE);
	int may_free = 1;
	int ret = 0;

	if (!PageLocked(page))
		BUG();
	if (!page_has_buffers(page))
		return 0;

	BUG_ON(stop > PAGE_CACHE_SIZE || stop < length);

	/* We will potentially be playing with lists other than just the
	 * data lists (especially for journaled data mode), so be
	 * cautious in our locking. */

	head = bh = page_buffers(page);
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		if (next_off > stop)
			return 0;

		if (offset <= curr_off) {
			/* This block is wholly outside the truncation point */
			lock_buffer(bh);
			ret = journal_unmap_buffer(journal, bh, partial_page);
			unlock_buffer(bh);
			if (ret < 0)
				return ret;
			may_free &= ret;
		}
		curr_off = next_off;
		bh = next;

	} while (bh != head);

	if (!partial_page) {
		if (may_free && try_to_free_buffers(page))
			J_ASSERT(!page_has_buffers(page));
	}
	return 0;
}

/*
 * File a buffer on the given transaction list.
 */
void __jbd2_journal_file_buffer(struct journal_head *jh,
			transaction_t *transaction, int jlist)
{
	struct journal_head **list = NULL;
	int was_dirty = 0;
	struct buffer_head *bh = jh2bh(jh);

	J_ASSERT_JH(jh, jbd_is_locked_bh_state(bh));
	assert_spin_locked(&transaction->t_journal->j_list_lock);

	J_ASSERT_JH(jh, jh->b_jlist < BJ_Types);
	J_ASSERT_JH(jh, jh->b_transaction == transaction ||
				jh->b_transaction == NULL);

	if (jh->b_transaction && jh->b_jlist == jlist)
		return;

	if (jlist == BJ_Metadata || jlist == BJ_Reserved ||
	    jlist == BJ_Shadow || jlist == BJ_Forget) {
		/*
		 * For metadata buffers, we track dirty bit in buffer_jbddirty
		 * instead of buffer_dirty. We should not see a dirty bit set
		 * here because we clear it in do_get_write_access but e.g.
		 * tune2fs can modify the sb and set the dirty bit at any time
		 * so we try to gracefully handle that.
		 */
		if (buffer_dirty(bh))
			warn_dirty_buffer(bh);
		if (test_clear_buffer_dirty(bh) ||
		    test_clear_buffer_jbddirty(bh))
			was_dirty = 1;
	}

	if (jh->b_transaction)
		__jbd2_journal_temp_unlink_buffer(jh);
	else
		jbd2_journal_grab_journal_head(bh);
	jh->b_transaction = transaction;

	switch (jlist) {
	case BJ_None:
		J_ASSERT_JH(jh, !jh->b_committed_data);
		J_ASSERT_JH(jh, !jh->b_frozen_data);
		return;
	case BJ_Metadata:
		transaction->t_nr_buffers++;
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	}

	__blist_add_buffer(list, jh);
	jh->b_jlist = jlist;

	if (was_dirty)
		set_buffer_jbddirty(bh);
}

void jbd2_journal_file_buffer(struct journal_head *jh,
				transaction_t *transaction, int jlist)
{
	jbd_lock_bh_state(jh2bh(jh));
	spin_lock(&transaction->t_journal->j_list_lock);
	__jbd2_journal_file_buffer(jh, transaction, jlist);
	spin_unlock(&transaction->t_journal->j_list_lock);
	jbd_unlock_bh_state(jh2bh(jh));
}

/*
 * Remove a buffer from its current buffer list in preparation for
 * dropping it from its current transaction entirely.  If the buffer has
 * already started to be used by a subsequent transaction, refile the
 * buffer on that transaction's metadata list.
 *
 * Called under j_list_lock
 * Called under jbd_lock_bh_state(jh2bh(jh))
 *
 * jh and bh may be already free when this function returns
 */
void __jbd2_journal_refile_buffer(struct journal_head *jh)
{
	int was_dirty, jlist;
	struct buffer_head *bh = jh2bh(jh);

	J_ASSERT_JH(jh, jbd_is_locked_bh_state(bh));
	if (jh->b_transaction)
		assert_spin_locked(&jh->b_transaction->t_journal->j_list_lock);

	/* If the buffer is now unused, just drop it. */
	if (jh->b_next_transaction == NULL) {
		__jbd2_journal_unfile_buffer(jh);
		return;
	}

	/*
	 * It has been modified by a later transaction: add it to the new
	 * transaction's metadata list.
	 */

	was_dirty = test_clear_buffer_jbddirty(bh);
	__jbd2_journal_temp_unlink_buffer(jh);
	/*
	 * We set b_transaction here because b_next_transaction will inherit
	 * our jh reference and thus __jbd2_journal_file_buffer() must not
	 * take a new one.
	 */
	jh->b_transaction = jh->b_next_transaction;
	jh->b_next_transaction = NULL;
	if (buffer_freed(bh))
		jlist = BJ_Forget;
	else if (jh->b_modified)
		jlist = BJ_Metadata;
	else
		jlist = BJ_Reserved;
	__jbd2_journal_file_buffer(jh, jh->b_transaction, jlist);
	J_ASSERT_JH(jh, jh->b_transaction->t_state == T_RUNNING);

	if (was_dirty)
		set_buffer_jbddirty(bh);
}

/*
 * __jbd2_journal_refile_buffer() with necessary locking added. We take our
 * bh reference so that we can safely unlock bh.
 *
 * The jh and bh may be freed by this call.
 */
void jbd2_journal_refile_buffer(journal_t *journal, struct journal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	/* Get reference so that buffer cannot be freed before we unlock it */
	get_bh(bh);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_refile_buffer(jh);
	jbd_unlock_bh_state(bh);
	spin_unlock(&journal->j_list_lock);
	__brelse(bh);
}

/*
 * File inode in the inode list of the handle's transaction
 */
int jbd2_journal_file_inode(handle_t *handle, struct jbd2_inode *jinode)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal;

	WARN_ON(!transaction);
	if (is_handle_aborted(handle))
		return -EROFS;
	journal = transaction->t_journal;

	jbd_debug(4, "Adding inode %lu, tid:%d\n", jinode->i_vfs_inode->i_ino,
			transaction->t_tid);

	/*
	 * First check whether inode isn't already on the transaction's
	 * lists without taking the lock. Note that this check is safe
	 * without the lock as we cannot race with somebody removing inode
	 * from the transaction. The reason is that we remove inode from the
	 * transaction only in journal_release_jbd_inode() and when we commit
	 * the transaction. We are guarded from the first case by holding
	 * a reference to the inode. We are safe against the second case
	 * because if jinode->i_transaction == transaction, commit code
	 * cannot touch the transaction because we hold reference to it,
	 * and if jinode->i_next_transaction == transaction, commit code
	 * will only file the inode where we want it.
	 */
	if (jinode->i_transaction == transaction ||
	    jinode->i_next_transaction == transaction)
		return 0;

	spin_lock(&journal->j_list_lock);

	if (jinode->i_transaction == transaction ||
	    jinode->i_next_transaction == transaction)
		goto done;

	/*
	 * We only ever set this variable to 1 so the test is safe. Since
	 * t_need_data_flush is likely to be set, we do the test to save some
	 * cacheline bouncing
	 */
	if (!transaction->t_need_data_flush)
		transaction->t_need_data_flush = 1;
	/* On some different transaction's list - should be
	 * the committing one */
	if (jinode->i_transaction) {
		J_ASSERT(jinode->i_next_transaction == NULL);
		J_ASSERT(jinode->i_transaction ==
					journal->j_committing_transaction);
		jinode->i_next_transaction = transaction;
		goto done;
	}
	/* Not on any transaction list... */
	J_ASSERT(!jinode->i_next_transaction);
	jinode->i_transaction = transaction;
	list_add(&jinode->i_list, &transaction->t_inode_list);
done:
	spin_unlock(&journal->j_list_lock);

	return 0;
}

/*
 * File truncate and transaction commit interact with each other in a
 * non-trivial way.  If a transaction writing data block A is
 * committing, we cannot discard the data by truncate until we have
 * written them.  Otherwise if we crashed after the transaction with
 * write has committed but before the transaction with truncate has
 * committed, we could see stale data in block A.  This function is a
 * helper to solve this problem.  It starts writeout of the truncated
 * part in case it is in the committing transaction.
 *
 * Filesystem code must call this function when inode is journaled in
 * ordered mode before truncation happens and after the inode has been
 * placed on orphan list with the new inode size. The second condition
 * avoids the race that someone writes new data and we start
 * committing the transaction after this function has been called but
 * before a transaction for truncate is started (and furthermore it
 * allows us to optimize the case where the addition to orphan list
 * happens in the same transaction as write --- we don't have to write
 * any data in such case).
 */
int jbd2_journal_begin_ordered_truncate(journal_t *journal,
					struct jbd2_inode *jinode,
					loff_t new_size)
{
	transaction_t *inode_trans, *commit_trans;
	int ret = 0;

	/* This is a quick check to avoid locking if not necessary */
	if (!jinode->i_transaction)
		goto out;
	/* Locks are here just to force reading of recent values, it is
	 * enough that the transaction was not committing before we started
	 * a transaction adding the inode to orphan list */
	read_lock(&journal->j_state_lock);
	commit_trans = journal->j_committing_transaction;
	read_unlock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	inode_trans = jinode->i_transaction;
	spin_unlock(&journal->j_list_lock);
	if (inode_trans == commit_trans) {
		ret = filemap_fdatawrite_range(jinode->i_vfs_inode->i_mapping,
			new_size, LLONG_MAX);
		if (ret)
			jbd2_journal_abort(journal, ret);
	}
out:
	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/jbd2/transaction.c */
/************************************************************/
/*
 * linux/fs/jbd2/commit.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal commit routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.
 */

// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/jbd2.h>
// #include <linux/errno.h>
// #include <linux/slab.h>
// #include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/jiffies.h>
#include <linux/crc32.h>
#include <linux/writeback.h>
// #include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/bitops.h>
// #include <trace/events/jbd2.h>

/*
 * IO end handler for temporary buffer_heads handling writes to the journal.
 */
static void journal_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	struct buffer_head *orig_bh = bh->b_private;

	BUFFER_TRACE(bh, "");
	if (uptodate)
		set_buffer_uptodate(bh);
	else
		clear_buffer_uptodate(bh);
	if (orig_bh) {
		clear_bit_unlock(BH_Shadow, &orig_bh->b_state);
		smp_mb__after_atomic();
		wake_up_bit(&orig_bh->b_state, BH_Shadow);
	}
	unlock_buffer(bh);
}

/*
 * When an ext4 file is truncated, it is possible that some pages are not
 * successfully freed, because they are attached to a committing transaction.
 * After the transaction commits, these pages are left on the LRU, with no
 * ->mapping, and with attached buffers.  These pages are trivially reclaimable
 * by the VM, but their apparent absence upsets the VM accounting, and it makes
 * the numbers in /proc/meminfo look odd.
 *
 * So here, we have a buffer which has just come off the forget list.  Look to
 * see if we can strip all buffers from the backing page.
 *
 * Called under lock_journal(), and possibly under journal_datalist_lock.  The
 * caller provided us with a ref against the buffer, and we drop that here.
 */
static void release_buffer_page(struct buffer_head *bh)
{
	struct page *page;

	if (buffer_dirty(bh))
		goto nope;
	if (atomic_read(&bh->b_count) != 1)
		goto nope;
	page = bh->b_page;
	if (!page)
		goto nope;
	if (page->mapping)
		goto nope;

	/* OK, it's a truncated page */
	if (!trylock_page(page))
		goto nope;

	page_cache_get(page);
	__brelse(bh);
	try_to_free_buffers(page);
	unlock_page(page);
	page_cache_release(page);
	return;

nope:
	__brelse(bh);
}

static void jbd2_commit_block_csum_set(journal_t *j, struct buffer_head *bh)
{
	struct commit_header *h;
	__u32 csum;

	if (!jbd2_journal_has_csum_v2or3(j))
		return;

	h = (struct commit_header *)(bh->b_data);
	h->h_chksum_type = 0;
	h->h_chksum_size = 0;
	h->h_chksum[0] = 0;
	csum = jbd2_chksum(j, j->j_csum_seed, bh->b_data, j->j_blocksize);
	h->h_chksum[0] = cpu_to_be32(csum);
}

/*
 * Done it all: now submit the commit record.  We should have
 * cleaned up our previous buffers by now, so if we are in abort
 * mode we can now just skip the rest of the journal write
 * entirely.
 *
 * Returns 1 if the journal needs to be aborted or 0 on success
 */
static int journal_submit_commit_record(journal_t *journal,
					transaction_t *commit_transaction,
					struct buffer_head **cbh,
					__u32 crc32_sum)
{
	struct commit_header *tmp;
	struct buffer_head *bh;
	int ret;
	struct timespec now = current_kernel_time();

	*cbh = NULL;

	if (is_journal_aborted(journal))
		return 0;

	bh = jbd2_journal_get_descriptor_buffer(journal);
	if (!bh)
		return 1;

	tmp = (struct commit_header *)bh->b_data;
	tmp->h_magic = cpu_to_be32(JBD2_MAGIC_NUMBER);
	tmp->h_blocktype = cpu_to_be32(JBD2_COMMIT_BLOCK);
	tmp->h_sequence = cpu_to_be32(commit_transaction->t_tid);
	tmp->h_commit_sec = cpu_to_be64(now.tv_sec);
	tmp->h_commit_nsec = cpu_to_be32(now.tv_nsec);

	if (JBD2_HAS_COMPAT_FEATURE(journal,
				    JBD2_FEATURE_COMPAT_CHECKSUM)) {
		tmp->h_chksum_type 	= JBD2_CRC32_CHKSUM;
		tmp->h_chksum_size 	= JBD2_CRC32_CHKSUM_SIZE;
		tmp->h_chksum[0] 	= cpu_to_be32(crc32_sum);
	}
	jbd2_commit_block_csum_set(journal, bh);

	BUFFER_TRACE(bh, "submit commit block");
	lock_buffer(bh);
	clear_buffer_dirty(bh);
	set_buffer_uptodate(bh);
	bh->b_end_io = journal_end_buffer_io_sync;

	if (journal->j_flags & JBD2_BARRIER &&
	    !JBD2_HAS_INCOMPAT_FEATURE(journal,
				       JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT))
		ret = submit_bh(WRITE_SYNC | WRITE_FLUSH_FUA, bh);
	else
		ret = submit_bh(WRITE_SYNC, bh);

	*cbh = bh;
	return ret;
}

/*
 * This function along with journal_submit_commit_record
 * allows to write the commit record asynchronously.
 */
static int journal_wait_on_commit_record(journal_t *journal,
					 struct buffer_head *bh)
{
	int ret = 0;

	clear_buffer_dirty(bh);
	wait_on_buffer(bh);

	if (unlikely(!buffer_uptodate(bh)))
		ret = -EIO;
	put_bh(bh);            /* One for getblk() */

	return ret;
}

/*
 * write the filemap data using writepage() address_space_operations.
 * We don't do block allocation here even for delalloc. We don't
 * use writepages() because with dealyed allocation we may be doing
 * block allocation in writepages().
 */
static int journal_submit_inode_data_buffers(struct address_space *mapping)
{
	int ret;
	struct writeback_control wbc = {
		.sync_mode =  WB_SYNC_ALL,
		.nr_to_write = mapping->nrpages * 2,
		.range_start = 0,
		.range_end = i_size_read(mapping->host),
	};

	ret = generic_writepages(mapping, &wbc);
	return ret;
}

/*
 * Submit all the data buffers of inode associated with the transaction to
 * disk.
 *
 * We are in a committing transaction. Therefore no new inode can be added to
 * our inode list. We use JI_COMMIT_RUNNING flag to protect inode we currently
 * operate on from being released while we write out pages.
 */
static int journal_submit_data_buffers(journal_t *journal,
		transaction_t *commit_transaction)
{
	struct jbd2_inode *jinode;
	int err, ret = 0;
	struct address_space *mapping;

	spin_lock(&journal->j_list_lock);
	list_for_each_entry(jinode, &commit_transaction->t_inode_list, i_list) {
		mapping = jinode->i_vfs_inode->i_mapping;
		set_bit(__JI_COMMIT_RUNNING, &jinode->i_flags);
		spin_unlock(&journal->j_list_lock);
		/*
		 * submit the inode data buffers. We use writepage
		 * instead of writepages. Because writepages can do
		 * block allocation  with delalloc. We need to write
		 * only allocated blocks here.
		 */
		trace_jbd2_submit_inode_data(jinode->i_vfs_inode);
		err = journal_submit_inode_data_buffers(mapping);
		if (!ret)
			ret = err;
		spin_lock(&journal->j_list_lock);
		J_ASSERT(jinode->i_transaction == commit_transaction);
		clear_bit(__JI_COMMIT_RUNNING, &jinode->i_flags);
		smp_mb__after_atomic();
		wake_up_bit(&jinode->i_flags, __JI_COMMIT_RUNNING);
	}
	spin_unlock(&journal->j_list_lock);
	return ret;
}

/*
 * Wait for data submitted for writeout, refile inodes to proper
 * transaction if needed.
 *
 */
static int journal_finish_inode_data_buffers(journal_t *journal,
		transaction_t *commit_transaction)
{
	struct jbd2_inode *jinode, *next_i;
	int err, ret = 0;

	/* For locking, see the comment in journal_submit_data_buffers() */
	spin_lock(&journal->j_list_lock);
	list_for_each_entry(jinode, &commit_transaction->t_inode_list, i_list) {
		set_bit(__JI_COMMIT_RUNNING, &jinode->i_flags);
		spin_unlock(&journal->j_list_lock);
		err = filemap_fdatawait(jinode->i_vfs_inode->i_mapping);
		if (err) {
			/*
			 * Because AS_EIO is cleared by
			 * filemap_fdatawait_range(), set it again so
			 * that user process can get -EIO from fsync().
			 */
			set_bit(AS_EIO,
				&jinode->i_vfs_inode->i_mapping->flags);

			if (!ret)
				ret = err;
		}
		spin_lock(&journal->j_list_lock);
		clear_bit(__JI_COMMIT_RUNNING, &jinode->i_flags);
		smp_mb__after_atomic();
		wake_up_bit(&jinode->i_flags, __JI_COMMIT_RUNNING);
	}

	/* Now refile inode to proper lists */
	list_for_each_entry_safe(jinode, next_i,
				 &commit_transaction->t_inode_list, i_list) {
		list_del(&jinode->i_list);
		if (jinode->i_next_transaction) {
			jinode->i_transaction = jinode->i_next_transaction;
			jinode->i_next_transaction = NULL;
			list_add(&jinode->i_list,
				&jinode->i_transaction->t_inode_list);
		} else {
			jinode->i_transaction = NULL;
		}
	}
	spin_unlock(&journal->j_list_lock);

	return ret;
}

static __u32 jbd2_checksum_data(__u32 crc32_sum, struct buffer_head *bh)
{
	struct page *page = bh->b_page;
	char *addr;
	__u32 checksum;

	addr = kmap_atomic(page);
	checksum = crc32_be(crc32_sum,
		(void *)(addr + offset_in_page(bh->b_data)), bh->b_size);
	kunmap_atomic(addr);

	return checksum;
}

static void write_tag_block(journal_t *j, journal_block_tag_t *tag,
				   unsigned long long block)
{
	tag->t_blocknr = cpu_to_be32(block & (u32)~0);
	if (JBD2_HAS_INCOMPAT_FEATURE(j, JBD2_FEATURE_INCOMPAT_64BIT))
		tag->t_blocknr_high = cpu_to_be32((block >> 31) >> 1);
}

static void jbd2_descr_block_csum_set(journal_t *j,
				      struct buffer_head *bh)
{
	struct jbd2_journal_block_tail *tail;
	__u32 csum;

	if (!jbd2_journal_has_csum_v2or3(j))
		return;

	tail = (struct jbd2_journal_block_tail *)(bh->b_data + j->j_blocksize -
			sizeof(struct jbd2_journal_block_tail));
	tail->t_checksum = 0;
	csum = jbd2_chksum(j, j->j_csum_seed, bh->b_data, j->j_blocksize);
	tail->t_checksum = cpu_to_be32(csum);
}

static void jbd2_block_tag_csum_set(journal_t *j, journal_block_tag_t *tag,
				    struct buffer_head *bh, __u32 sequence)
{
	journal_block_tag3_t *tag3 = (journal_block_tag3_t *)tag;
	struct page *page = bh->b_page;
	__u8 *addr;
	__u32 csum32;
	__be32 seq;

	if (!jbd2_journal_has_csum_v2or3(j))
		return;

	seq = cpu_to_be32(sequence);
	addr = kmap_atomic(page);
	csum32 = jbd2_chksum(j, j->j_csum_seed, (__u8 *)&seq, sizeof(seq));
	csum32 = jbd2_chksum(j, csum32, addr + offset_in_page(bh->b_data),
			     bh->b_size);
	kunmap_atomic(addr);

	if (JBD2_HAS_INCOMPAT_FEATURE(j, JBD2_FEATURE_INCOMPAT_CSUM_V3))
		tag3->t_checksum = cpu_to_be32(csum32);
	else
		tag->t_checksum = cpu_to_be16(csum32);
}
/*
 * jbd2_journal_commit_transaction
 *
 * The primary function for committing a transaction to the log.  This
 * function is called by the journal thread to begin a complete commit.
 */
void jbd2_journal_commit_transaction(journal_t *journal)
{
	struct transaction_stats_s stats;
	transaction_t *commit_transaction;
	struct journal_head *jh;
	struct buffer_head *descriptor;
	struct buffer_head **wbuf = journal->j_wbuf;
	int bufs;
	int flags;
	int err;
	unsigned long long blocknr;
	ktime_t start_time;
	u64 commit_time;
	char *tagp = NULL;
	journal_header_t *header;
	journal_block_tag_t *tag = NULL;
	int space_left = 0;
	int first_tag = 0;
	int tag_flag;
	int i;
	int tag_bytes = journal_tag_bytes(journal);
	struct buffer_head *cbh = NULL; /* For transactional checksums */
	__u32 crc32_sum = ~0;
	struct blk_plug plug;
	/* Tail of the journal */
	unsigned long first_block;
	tid_t first_tid;
	int update_tail;
	int csum_size = 0;
	LIST_HEAD(io_bufs);
	LIST_HEAD(log_bufs);

	if (jbd2_journal_has_csum_v2or3(journal))
		csum_size = sizeof(struct jbd2_journal_block_tail);

	/*
	 * First job: lock down the current transaction and wait for
	 * all outstanding updates to complete.
	 */

	/* Do we need to erase the effects of a prior jbd2_journal_flush? */
	if (journal->j_flags & JBD2_FLUSHED) {
		jbd_debug(3, "super block updated\n");
		mutex_lock(&journal->j_checkpoint_mutex);
		/*
		 * We hold j_checkpoint_mutex so tail cannot change under us.
		 * We don't need any special data guarantees for writing sb
		 * since journal is empty and it is ok for write to be
		 * flushed only with transaction commit.
		 */
		jbd2_journal_update_sb_log_tail(journal,
						journal->j_tail_sequence,
						journal->j_tail,
						WRITE_SYNC);
		mutex_unlock(&journal->j_checkpoint_mutex);
	} else {
		jbd_debug(3, "superblock not updated\n");
	}

	J_ASSERT(journal->j_running_transaction != NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);

	commit_transaction = journal->j_running_transaction;

	trace_jbd2_start_commit(journal, commit_transaction);
	jbd_debug(1, "JBD2: starting commit of transaction %d\n",
			commit_transaction->t_tid);

	write_lock(&journal->j_state_lock);
	J_ASSERT(commit_transaction->t_state == T_RUNNING);
	commit_transaction->t_state = T_LOCKED;

	trace_jbd2_commit_locking(journal, commit_transaction);
	stats.run.rs_wait = commit_transaction->t_max_wait;
	stats.run.rs_request_delay = 0;
	stats.run.rs_locked = jiffies;
	if (commit_transaction->t_requested)
		stats.run.rs_request_delay =
			jbd2_time_diff(commit_transaction->t_requested,
				       stats.run.rs_locked);
	stats.run.rs_running = jbd2_time_diff(commit_transaction->t_start,
					      stats.run.rs_locked);

	spin_lock(&commit_transaction->t_handle_lock);
	while (atomic_read(&commit_transaction->t_updates)) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_updates, &wait,
					TASK_UNINTERRUPTIBLE);
		if (atomic_read(&commit_transaction->t_updates)) {
			spin_unlock(&commit_transaction->t_handle_lock);
			write_unlock(&journal->j_state_lock);
			schedule();
			write_lock(&journal->j_state_lock);
			spin_lock(&commit_transaction->t_handle_lock);
		}
		finish_wait(&journal->j_wait_updates, &wait);
	}
	spin_unlock(&commit_transaction->t_handle_lock);

	J_ASSERT (atomic_read(&commit_transaction->t_outstanding_credits) <=
			journal->j_max_transaction_buffers);

	/*
	 * First thing we are allowed to do is to discard any remaining
	 * BJ_Reserved buffers.  Note, it is _not_ permissible to assume
	 * that there are no such buffers: if a large filesystem
	 * operation like a truncate needs to split itself over multiple
	 * transactions, then it may try to do a jbd2_journal_restart() while
	 * there are still BJ_Reserved buffers outstanding.  These must
	 * be released cleanly from the current transaction.
	 *
	 * In this case, the filesystem must still reserve write access
	 * again before modifying the buffer in the new transaction, but
	 * we do not require it to remember exactly which old buffers it
	 * has reserved.  This is consistent with the existing behaviour
	 * that multiple jbd2_journal_get_write_access() calls to the same
	 * buffer are perfectly permissible.
	 */
	while (commit_transaction->t_reserved_list) {
		jh = commit_transaction->t_reserved_list;
		JBUFFER_TRACE(jh, "reserved, unused: refile");
		/*
		 * A jbd2_journal_get_undo_access()+jbd2_journal_release_buffer() may
		 * leave undo-committed data.
		 */
		if (jh->b_committed_data) {
			struct buffer_head *bh = jh2bh(jh);

			jbd_lock_bh_state(bh);
			jbd2_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			jbd_unlock_bh_state(bh);
		}
		jbd2_journal_refile_buffer(journal, jh);
	}

	/*
	 * Now try to drop any written-back buffers from the journal's
	 * checkpoint lists.  We do this *before* commit because it potentially
	 * frees some memory
	 */
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_clean_checkpoint_list(journal);
	spin_unlock(&journal->j_list_lock);

	jbd_debug(3, "JBD2: commit phase 1\n");

	/*
	 * Clear revoked flag to reflect there is no revoked buffers
	 * in the next transaction which is going to be started.
	 */
	jbd2_clear_buffer_revoked_flags(journal);

	/*
	 * Switch to a new revoke table.
	 */
	jbd2_journal_switch_revoke_table(journal);

	/*
	 * Reserved credits cannot be claimed anymore, free them
	 */
	atomic_sub(atomic_read(&journal->j_reserved_credits),
		   &commit_transaction->t_outstanding_credits);

	trace_jbd2_commit_flushing(journal, commit_transaction);
	stats.run.rs_flushing = jiffies;
	stats.run.rs_locked = jbd2_time_diff(stats.run.rs_locked,
					     stats.run.rs_flushing);

	commit_transaction->t_state = T_FLUSH;
	journal->j_committing_transaction = commit_transaction;
	journal->j_running_transaction = NULL;
	start_time = ktime_get();
	commit_transaction->t_log_start = journal->j_head;
	wake_up(&journal->j_wait_transaction_locked);
	write_unlock(&journal->j_state_lock);

	jbd_debug(3, "JBD2: commit phase 2a\n");

	/*
	 * Now start flushing things to disk, in the order they appear
	 * on the transaction lists.  Data blocks go first.
	 */
	err = journal_submit_data_buffers(journal, commit_transaction);
	if (err)
		jbd2_journal_abort(journal, err);

	blk_start_plug(&plug);
	jbd2_journal_write_revoke_records(journal, commit_transaction,
					  &log_bufs, WRITE_SYNC);

	jbd_debug(3, "JBD2: commit phase 2b\n");

	/*
	 * Way to go: we have now written out all of the data for a
	 * transaction!  Now comes the tricky part: we need to write out
	 * metadata.  Loop over the transaction's entire buffer list:
	 */
	write_lock(&journal->j_state_lock);
	commit_transaction->t_state = T_COMMIT;
	write_unlock(&journal->j_state_lock);

	trace_jbd2_commit_logging(journal, commit_transaction);
	stats.run.rs_logging = jiffies;
	stats.run.rs_flushing = jbd2_time_diff(stats.run.rs_flushing,
					       stats.run.rs_logging);
	stats.run.rs_blocks =
		atomic_read(&commit_transaction->t_outstanding_credits);
	stats.run.rs_blocks_logged = 0;

	J_ASSERT(commit_transaction->t_nr_buffers <=
		 atomic_read(&commit_transaction->t_outstanding_credits));

	err = 0;
	bufs = 0;
	descriptor = NULL;
	while (commit_transaction->t_buffers) {

		/* Find the next buffer to be journaled... */

		jh = commit_transaction->t_buffers;

		/* If we're in abort mode, we just un-journal the buffer and
		   release it. */

		if (is_journal_aborted(journal)) {
			clear_buffer_jbddirty(jh2bh(jh));
			JBUFFER_TRACE(jh, "journal is aborting: refile");
			jbd2_buffer_abort_trigger(jh,
						  jh->b_frozen_data ?
						  jh->b_frozen_triggers :
						  jh->b_triggers);
			jbd2_journal_refile_buffer(journal, jh);
			/* If that was the last one, we need to clean up
			 * any descriptor buffers which may have been
			 * already allocated, even if we are now
			 * aborting. */
			if (!commit_transaction->t_buffers)
				goto start_journal_io;
			continue;
		}

		/* Make sure we have a descriptor block in which to
		   record the metadata buffer. */

		if (!descriptor) {
			J_ASSERT (bufs == 0);

			jbd_debug(4, "JBD2: get descriptor\n");

			descriptor = jbd2_journal_get_descriptor_buffer(journal);
			if (!descriptor) {
				jbd2_journal_abort(journal, -EIO);
				continue;
			}

			jbd_debug(4, "JBD2: got buffer %llu (%p)\n",
				(unsigned long long)descriptor->b_blocknr,
				descriptor->b_data);
			header = (journal_header_t *)descriptor->b_data;
			header->h_magic     = cpu_to_be32(JBD2_MAGIC_NUMBER);
			header->h_blocktype = cpu_to_be32(JBD2_DESCRIPTOR_BLOCK);
			header->h_sequence  = cpu_to_be32(commit_transaction->t_tid);

			tagp = &descriptor->b_data[sizeof(journal_header_t)];
			space_left = descriptor->b_size -
						sizeof(journal_header_t);
			first_tag = 1;
			set_buffer_jwrite(descriptor);
			set_buffer_dirty(descriptor);
			wbuf[bufs++] = descriptor;

			/* Record it so that we can wait for IO
                           completion later */
			BUFFER_TRACE(descriptor, "ph3: file as descriptor");
			jbd2_file_log_bh(&log_bufs, descriptor);
		}

		/* Where is the buffer to be written? */

		err = jbd2_journal_next_log_block(journal, &blocknr);
		/* If the block mapping failed, just abandon the buffer
		   and repeat this loop: we'll fall into the
		   refile-on-abort condition above. */
		if (err) {
			jbd2_journal_abort(journal, err);
			continue;
		}

		/*
		 * start_this_handle() uses t_outstanding_credits to determine
		 * the free space in the log, but this counter is changed
		 * by jbd2_journal_next_log_block() also.
		 */
		atomic_dec(&commit_transaction->t_outstanding_credits);

		/* Bump b_count to prevent truncate from stumbling over
                   the shadowed buffer!  @@@ This can go if we ever get
                   rid of the shadow pairing of buffers. */
		atomic_inc(&jh2bh(jh)->b_count);

		/*
		 * Make a temporary IO buffer with which to write it out
		 * (this will requeue the metadata buffer to BJ_Shadow).
		 */
		set_bit(BH_JWrite, &jh2bh(jh)->b_state);
		JBUFFER_TRACE(jh, "ph3: write metadata");
		flags = jbd2_journal_write_metadata_buffer(commit_transaction,
						jh, &wbuf[bufs], blocknr);
		if (flags < 0) {
			jbd2_journal_abort(journal, flags);
			continue;
		}
		jbd2_file_log_bh(&io_bufs, wbuf[bufs]);

		/* Record the new block's tag in the current descriptor
                   buffer */

		tag_flag = 0;
		if (flags & 1)
			tag_flag |= JBD2_FLAG_ESCAPE;
		if (!first_tag)
			tag_flag |= JBD2_FLAG_SAME_UUID;

		tag = (journal_block_tag_t *) tagp;
		write_tag_block(journal, tag, jh2bh(jh)->b_blocknr);
		tag->t_flags = cpu_to_be16(tag_flag);
		jbd2_block_tag_csum_set(journal, tag, wbuf[bufs],
					commit_transaction->t_tid);
		tagp += tag_bytes;
		space_left -= tag_bytes;
		bufs++;

		if (first_tag) {
			memcpy (tagp, journal->j_uuid, 16);
			tagp += 16;
			space_left -= 16;
			first_tag = 0;
		}

		/* If there's no more to do, or if the descriptor is full,
		   let the IO rip! */

		if (bufs == journal->j_wbufsize ||
		    commit_transaction->t_buffers == NULL ||
		    space_left < tag_bytes + 16 + csum_size) {

			jbd_debug(4, "JBD2: Submit %d IOs\n", bufs);

			/* Write an end-of-descriptor marker before
                           submitting the IOs.  "tag" still points to
                           the last tag we set up. */

			tag->t_flags |= cpu_to_be16(JBD2_FLAG_LAST_TAG);

			jbd2_descr_block_csum_set(journal, descriptor);
start_journal_io:
			for (i = 0; i < bufs; i++) {
				struct buffer_head *bh = wbuf[i];
				/*
				 * Compute checksum.
				 */
				if (JBD2_HAS_COMPAT_FEATURE(journal,
					JBD2_FEATURE_COMPAT_CHECKSUM)) {
					crc32_sum =
					    jbd2_checksum_data(crc32_sum, bh);
				}

				lock_buffer(bh);
				clear_buffer_dirty(bh);
				set_buffer_uptodate(bh);
				bh->b_end_io = journal_end_buffer_io_sync;
				submit_bh(WRITE_SYNC, bh);
			}
			cond_resched();
			stats.run.rs_blocks_logged += bufs;

			/* Force a new descriptor to be generated next
                           time round the loop. */
			descriptor = NULL;
			bufs = 0;
		}
	}

	err = journal_finish_inode_data_buffers(journal, commit_transaction);
	if (err) {
		printk(KERN_WARNING
			"JBD2: Detected IO errors while flushing file data "
		       "on %s\n", journal->j_devname);
		if (journal->j_flags & JBD2_ABORT_ON_SYNCDATA_ERR)
			jbd2_journal_abort(journal, err);
		err = 0;
	}

	/*
	 * Get current oldest transaction in the log before we issue flush
	 * to the filesystem device. After the flush we can be sure that
	 * blocks of all older transactions are checkpointed to persistent
	 * storage and we will be safe to update journal start in the
	 * superblock with the numbers we get here.
	 */
	update_tail =
		jbd2_journal_get_log_tail(journal, &first_tid, &first_block);

	write_lock(&journal->j_state_lock);
	if (update_tail) {
		long freed = first_block - journal->j_tail;

		if (first_block < journal->j_tail)
			freed += journal->j_last - journal->j_first;
		/* Update tail only if we free significant amount of space */
		if (freed < journal->j_maxlen / 4)
			update_tail = 0;
	}
	J_ASSERT(commit_transaction->t_state == T_COMMIT);
	commit_transaction->t_state = T_COMMIT_DFLUSH;
	write_unlock(&journal->j_state_lock);

	/*
	 * If the journal is not located on the file system device,
	 * then we must flush the file system device before we issue
	 * the commit record
	 */
	if (commit_transaction->t_need_data_flush &&
	    (journal->j_fs_dev != journal->j_dev) &&
	    (journal->j_flags & JBD2_BARRIER))
		blkdev_issue_flush(journal->j_fs_dev, GFP_NOFS, NULL);

	/* Done it all: now write the commit record asynchronously. */
	if (JBD2_HAS_INCOMPAT_FEATURE(journal,
				      JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)) {
		err = journal_submit_commit_record(journal, commit_transaction,
						 &cbh, crc32_sum);
		if (err)
			__jbd2_journal_abort_hard(journal);
	}

	blk_finish_plug(&plug);

	/* Lo and behold: we have just managed to send a transaction to
           the log.  Before we can commit it, wait for the IO so far to
           complete.  Control buffers being written are on the
           transaction's t_log_list queue, and metadata buffers are on
           the io_bufs list.

	   Wait for the buffers in reverse order.  That way we are
	   less likely to be woken up until all IOs have completed, and
	   so we incur less scheduling load.
	*/

	jbd_debug(3, "JBD2: commit phase 3\n");

	while (!list_empty(&io_bufs)) {
		struct buffer_head *bh = list_entry(io_bufs.prev,
						    struct buffer_head,
						    b_assoc_buffers);

		wait_on_buffer(bh);
		cond_resched();

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;
		jbd2_unfile_log_bh(bh);

		/*
		 * The list contains temporary buffer heads created by
		 * jbd2_journal_write_metadata_buffer().
		 */
		BUFFER_TRACE(bh, "dumping temporary bh");
		__brelse(bh);
		J_ASSERT_BH(bh, atomic_read(&bh->b_count) == 0);
		free_buffer_head(bh);

		/* We also have to refile the corresponding shadowed buffer */
		jh = commit_transaction->t_shadow_list->b_tprev;
		bh = jh2bh(jh);
		clear_buffer_jwrite(bh);
		J_ASSERT_BH(bh, buffer_jbddirty(bh));
		J_ASSERT_BH(bh, !buffer_shadow(bh));

		/* The metadata is now released for reuse, but we need
                   to remember it against this transaction so that when
                   we finally commit, we can do any checkpointing
                   required. */
		JBUFFER_TRACE(jh, "file as BJ_Forget");
		jbd2_journal_file_buffer(jh, commit_transaction, BJ_Forget);
		JBUFFER_TRACE(jh, "brelse shadowed buffer");
		__brelse(bh);
	}

	J_ASSERT (commit_transaction->t_shadow_list == NULL);

	jbd_debug(3, "JBD2: commit phase 4\n");

	/* Here we wait for the revoke record and descriptor record buffers */
	while (!list_empty(&log_bufs)) {
		struct buffer_head *bh;

		bh = list_entry(log_bufs.prev, struct buffer_head, b_assoc_buffers);
		wait_on_buffer(bh);
		cond_resched();

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		BUFFER_TRACE(bh, "ph5: control buffer writeout done: unfile");
		clear_buffer_jwrite(bh);
		jbd2_unfile_log_bh(bh);
		__brelse(bh);		/* One for getblk */
		/* AKPM: bforget here */
	}

	if (err)
		jbd2_journal_abort(journal, err);

	jbd_debug(3, "JBD2: commit phase 5\n");
	write_lock(&journal->j_state_lock);
	J_ASSERT(commit_transaction->t_state == T_COMMIT_DFLUSH);
	commit_transaction->t_state = T_COMMIT_JFLUSH;
	write_unlock(&journal->j_state_lock);

	if (!JBD2_HAS_INCOMPAT_FEATURE(journal,
				       JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)) {
		err = journal_submit_commit_record(journal, commit_transaction,
						&cbh, crc32_sum);
		if (err)
			__jbd2_journal_abort_hard(journal);
	}
	if (cbh)
		err = journal_wait_on_commit_record(journal, cbh);
	if (JBD2_HAS_INCOMPAT_FEATURE(journal,
				      JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT) &&
	    journal->j_flags & JBD2_BARRIER) {
		blkdev_issue_flush(journal->j_dev, GFP_NOFS, NULL);
	}

	if (err)
		jbd2_journal_abort(journal, err);

	/*
	 * Now disk caches for filesystem device are flushed so we are safe to
	 * erase checkpointed transactions from the log by updating journal
	 * superblock.
	 */
	if (update_tail)
		jbd2_update_log_tail(journal, first_tid, first_block);

	/* End of a transaction!  Finally, we can do checkpoint
           processing: any buffers committed as a result of this
           transaction can be removed from any checkpoint list it was on
           before. */

	jbd_debug(3, "JBD2: commit phase 6\n");

	J_ASSERT(list_empty(&commit_transaction->t_inode_list));
	J_ASSERT(commit_transaction->t_buffers == NULL);
	J_ASSERT(commit_transaction->t_checkpoint_list == NULL);
	J_ASSERT(commit_transaction->t_shadow_list == NULL);

restart_loop:
	/*
	 * As there are other places (journal_unmap_buffer()) adding buffers
	 * to this list we have to be careful and hold the j_list_lock.
	 */
	spin_lock(&journal->j_list_lock);
	while (commit_transaction->t_forget) {
		transaction_t *cp_transaction;
		struct buffer_head *bh;
		int try_to_free = 0;

		jh = commit_transaction->t_forget;
		spin_unlock(&journal->j_list_lock);
		bh = jh2bh(jh);
		/*
		 * Get a reference so that bh cannot be freed before we are
		 * done with it.
		 */
		get_bh(bh);
		jbd_lock_bh_state(bh);
		J_ASSERT_JH(jh,	jh->b_transaction == commit_transaction);

		/*
		 * If there is undo-protected committed data against
		 * this buffer, then we can remove it now.  If it is a
		 * buffer needing such protection, the old frozen_data
		 * field now points to a committed version of the
		 * buffer, so rotate that field to the new committed
		 * data.
		 *
		 * Otherwise, we can just throw away the frozen data now.
		 *
		 * We also know that the frozen data has already fired
		 * its triggers if they exist, so we can clear that too.
		 */
		if (jh->b_committed_data) {
			jbd2_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			if (jh->b_frozen_data) {
				jh->b_committed_data = jh->b_frozen_data;
				jh->b_frozen_data = NULL;
				jh->b_frozen_triggers = NULL;
			}
		} else if (jh->b_frozen_data) {
			jbd2_free(jh->b_frozen_data, bh->b_size);
			jh->b_frozen_data = NULL;
			jh->b_frozen_triggers = NULL;
		}

		spin_lock(&journal->j_list_lock);
		cp_transaction = jh->b_cp_transaction;
		if (cp_transaction) {
			JBUFFER_TRACE(jh, "remove from old cp transaction");
			cp_transaction->t_chp_stats.cs_dropped++;
			__jbd2_journal_remove_checkpoint(jh);
		}

		/* Only re-checkpoint the buffer_head if it is marked
		 * dirty.  If the buffer was added to the BJ_Forget list
		 * by jbd2_journal_forget, it may no longer be dirty and
		 * there's no point in keeping a checkpoint record for
		 * it. */

		/*
		* A buffer which has been freed while still being journaled by
		* a previous transaction.
		*/
		if (buffer_freed(bh)) {
			/*
			 * If the running transaction is the one containing
			 * "add to orphan" operation (b_next_transaction !=
			 * NULL), we have to wait for that transaction to
			 * commit before we can really get rid of the buffer.
			 * So just clear b_modified to not confuse transaction
			 * credit accounting and refile the buffer to
			 * BJ_Forget of the running transaction. If the just
			 * committed transaction contains "add to orphan"
			 * operation, we can completely invalidate the buffer
			 * now. We are rather through in that since the
			 * buffer may be still accessible when blocksize <
			 * pagesize and it is attached to the last partial
			 * page.
			 */
			jh->b_modified = 0;
			if (!jh->b_next_transaction) {
				clear_buffer_freed(bh);
				clear_buffer_jbddirty(bh);
				clear_buffer_mapped(bh);
				clear_buffer_new(bh);
				clear_buffer_req(bh);
				bh->b_bdev = NULL;
			}
		}

		if (buffer_jbddirty(bh)) {
			JBUFFER_TRACE(jh, "add to new checkpointing trans");
			__jbd2_journal_insert_checkpoint(jh, commit_transaction);
			if (is_journal_aborted(journal))
				clear_buffer_jbddirty(bh);
		} else {
			J_ASSERT_BH(bh, !buffer_dirty(bh));
			/*
			 * The buffer on BJ_Forget list and not jbddirty means
			 * it has been freed by this transaction and hence it
			 * could not have been reallocated until this
			 * transaction has committed. *BUT* it could be
			 * reallocated once we have written all the data to
			 * disk and before we process the buffer on BJ_Forget
			 * list.
			 */
			if (!jh->b_next_transaction)
				try_to_free = 1;
		}
		JBUFFER_TRACE(jh, "refile or unfile buffer");
		__jbd2_journal_refile_buffer(jh);
		jbd_unlock_bh_state(bh);
		if (try_to_free)
			release_buffer_page(bh);	/* Drops bh reference */
		else
			__brelse(bh);
		cond_resched_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);
	/*
	 * This is a bit sleazy.  We use j_list_lock to protect transition
	 * of a transaction into T_FINISHED state and calling
	 * __jbd2_journal_drop_transaction(). Otherwise we could race with
	 * other checkpointing code processing the transaction...
	 */
	write_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	/*
	 * Now recheck if some buffers did not get attached to the transaction
	 * while the lock was dropped...
	 */
	if (commit_transaction->t_forget) {
		spin_unlock(&journal->j_list_lock);
		write_unlock(&journal->j_state_lock);
		goto restart_loop;
	}

	/* Add the transaction to the checkpoint list
	 * __journal_remove_checkpoint() can not destroy transaction
	 * under us because it is not marked as T_FINISHED yet */
	if (journal->j_checkpoint_transactions == NULL) {
		journal->j_checkpoint_transactions = commit_transaction;
		commit_transaction->t_cpnext = commit_transaction;
		commit_transaction->t_cpprev = commit_transaction;
	} else {
		commit_transaction->t_cpnext =
			journal->j_checkpoint_transactions;
		commit_transaction->t_cpprev =
			commit_transaction->t_cpnext->t_cpprev;
		commit_transaction->t_cpnext->t_cpprev =
			commit_transaction;
		commit_transaction->t_cpprev->t_cpnext =
				commit_transaction;
	}
	spin_unlock(&journal->j_list_lock);

	/* Done with this transaction! */

	jbd_debug(3, "JBD2: commit phase 7\n");

	J_ASSERT(commit_transaction->t_state == T_COMMIT_JFLUSH);

	commit_transaction->t_start = jiffies;
	stats.run.rs_logging = jbd2_time_diff(stats.run.rs_logging,
					      commit_transaction->t_start);

	/*
	 * File the transaction statistics
	 */
	stats.ts_tid = commit_transaction->t_tid;
	stats.run.rs_handle_count =
		atomic_read(&commit_transaction->t_handle_count);
	trace_jbd2_run_stats(journal->j_fs_dev->bd_dev,
			     commit_transaction->t_tid, &stats.run);
	stats.ts_requested = (commit_transaction->t_requested) ? 1 : 0;

	commit_transaction->t_state = T_COMMIT_CALLBACK;
	J_ASSERT(commit_transaction == journal->j_committing_transaction);
	journal->j_commit_sequence = commit_transaction->t_tid;
	journal->j_committing_transaction = NULL;
	commit_time = ktime_to_ns(ktime_sub(ktime_get(), start_time));

	/*
	 * weight the commit time higher than the average time so we don't
	 * react too strongly to vast changes in the commit time
	 */
	if (likely(journal->j_average_commit_time))
		journal->j_average_commit_time = (commit_time +
				journal->j_average_commit_time*3) / 4;
	else
		journal->j_average_commit_time = commit_time;

	write_unlock(&journal->j_state_lock);

	if (journal->j_commit_callback)
		journal->j_commit_callback(journal, commit_transaction);

	trace_jbd2_end_commit(journal, commit_transaction);
	jbd_debug(1, "JBD2: commit %d complete, head %d\n",
		  journal->j_commit_sequence, journal->j_tail_sequence);

	write_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	commit_transaction->t_state = T_FINISHED;
	/* Check if the transaction can be dropped now that we are finished */
	if (commit_transaction->t_checkpoint_list == NULL &&
	    commit_transaction->t_checkpoint_io_list == NULL) {
		__jbd2_journal_drop_transaction(journal, commit_transaction);
		jbd2_journal_free_transaction(commit_transaction);
	}
	spin_unlock(&journal->j_list_lock);
	write_unlock(&journal->j_state_lock);
	wake_up(&journal->j_wait_done_commit);

	/*
	 * Calculate overall stats
	 */
	spin_lock(&journal->j_history_lock);
	journal->j_stats.ts_tid++;
	journal->j_stats.ts_requested += stats.ts_requested;
	journal->j_stats.run.rs_wait += stats.run.rs_wait;
	journal->j_stats.run.rs_request_delay += stats.run.rs_request_delay;
	journal->j_stats.run.rs_running += stats.run.rs_running;
	journal->j_stats.run.rs_locked += stats.run.rs_locked;
	journal->j_stats.run.rs_flushing += stats.run.rs_flushing;
	journal->j_stats.run.rs_logging += stats.run.rs_logging;
	journal->j_stats.run.rs_handle_count += stats.run.rs_handle_count;
	journal->j_stats.run.rs_blocks += stats.run.rs_blocks;
	journal->j_stats.run.rs_blocks_logged += stats.run.rs_blocks_logged;
	spin_unlock(&journal->j_history_lock);
}
/************************************************************/
/* ../linux-3.17/fs/jbd2/commit.c */
/************************************************************/
/*
 * linux/fs/jbd2/recovery.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1999-2000 Red Hat Software --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal recovery routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.
 */

#ifndef __KERNEL__
#include "jfs_user.h"
#else
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/jbd2.h>
// #include <linux/errno.h>
// #include <linux/crc32.h>
// #include <linux/blkdev.h>
#endif

/*
 * Maintain information about the progress of the recovery job, so that
 * the different passes can carry information between them.
 */
struct recovery_info
{
	tid_t		start_transaction;
	tid_t		end_transaction;

	int		nr_replays;
	int		nr_revokes;
	int		nr_revoke_hits;
};

enum passtype {PASS_SCAN, PASS_REVOKE, PASS_REPLAY};
static int do_one_pass(journal_t *journal,
				struct recovery_info *info, enum passtype pass);
static int scan_revoke_records(journal_t *, struct buffer_head *,
				tid_t, struct recovery_info *);

#ifdef __KERNEL__

/* Release readahead buffers after use */
static void journal_brelse_array(struct buffer_head *b[], int n)
{
	while (--n >= 0)
		brelse (b[n]);
}


/*
 * When reading from the journal, we are going through the block device
 * layer directly and so there is no readahead being done for us.  We
 * need to implement any readahead ourselves if we want it to happen at
 * all.  Recovery is basically one long sequential read, so make sure we
 * do the IO in reasonably large chunks.
 *
 * This is not so critical that we need to be enormously clever about
 * the readahead size, though.  128K is a purely arbitrary, good-enough
 * fixed value.
 */

#define MAXBUF 8
static int do_readahead(journal_t *journal, unsigned int start)
{
	int err;
	unsigned int max, nbufs, next;
	unsigned long long blocknr;
	struct buffer_head *bh;

	struct buffer_head * bufs[MAXBUF];

	/* Do up to 128K of readahead */
	max = start + (128 * 1024 / journal->j_blocksize);
	if (max > journal->j_maxlen)
		max = journal->j_maxlen;

	/* Do the readahead itself.  We'll submit MAXBUF buffer_heads at
	 * a time to the block device IO layer. */

	nbufs = 0;

	for (next = start; next < max; next++) {
		err = jbd2_journal_bmap(journal, next, &blocknr);

		if (err) {
			printk(KERN_ERR "JBD2: bad block at offset %u\n",
				next);
			goto failed;
		}

		bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
		if (!bh) {
			err = -ENOMEM;
			goto failed;
		}

		if (!buffer_uptodate(bh) && !buffer_locked(bh)) {
			bufs[nbufs++] = bh;
			if (nbufs == MAXBUF) {
				ll_rw_block(READ, nbufs, bufs);
				journal_brelse_array(bufs, nbufs);
				nbufs = 0;
			}
		} else
			brelse(bh);
	}

	if (nbufs)
		ll_rw_block(READ, nbufs, bufs);
	err = 0;

failed:
	if (nbufs)
		journal_brelse_array(bufs, nbufs);
	return err;
}

#endif /* __KERNEL__ */


/*
 * Read a block from the journal
 */

static int jread(struct buffer_head **bhp, journal_t *journal,
		 unsigned int offset)
{
	int err;
	unsigned long long blocknr;
	struct buffer_head *bh;

	*bhp = NULL;

	if (offset >= journal->j_maxlen) {
		printk(KERN_ERR "JBD2: corrupted journal superblock\n");
		return -EIO;
	}

	err = jbd2_journal_bmap(journal, offset, &blocknr);

	if (err) {
		printk(KERN_ERR "JBD2: bad block at offset %u\n",
			offset);
		return err;
	}

	bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
	if (!bh)
		return -ENOMEM;

	if (!buffer_uptodate(bh)) {
		/* If this is a brand new buffer, start readahead.
                   Otherwise, we assume we are already reading it.  */
		if (!buffer_req(bh))
			do_readahead(journal, offset);
		wait_on_buffer(bh);
	}

	if (!buffer_uptodate(bh)) {
		printk(KERN_ERR "JBD2: Failed to read block at offset %u\n",
			offset);
		brelse(bh);
		return -EIO;
	}

	*bhp = bh;
	return 0;
}

static int jbd2_descr_block_csum_verify(journal_t *j,
					void *buf)
{
	struct jbd2_journal_block_tail *tail;
	__be32 provided;
	__u32 calculated;

	if (!jbd2_journal_has_csum_v2or3(j))
		return 1;

	tail = (struct jbd2_journal_block_tail *)(buf + j->j_blocksize -
			sizeof(struct jbd2_journal_block_tail));
	provided = tail->t_checksum;
	tail->t_checksum = 0;
	calculated = jbd2_chksum(j, j->j_csum_seed, buf, j->j_blocksize);
	tail->t_checksum = provided;

	return provided == cpu_to_be32(calculated);
}

/*
 * Count the number of in-use tags in a journal descriptor block.
 */

static int count_tags(journal_t *journal, struct buffer_head *bh)
{
	char *			tagp;
	journal_block_tag_t *	tag;
	int			nr = 0, size = journal->j_blocksize;
	int			tag_bytes = journal_tag_bytes(journal);

	if (jbd2_journal_has_csum_v2or3(journal))
		size -= sizeof(struct jbd2_journal_block_tail);

	tagp = &bh->b_data[sizeof(journal_header_t)];

	while ((tagp - bh->b_data + tag_bytes) <= size) {
		tag = (journal_block_tag_t *) tagp;

		nr++;
		tagp += tag_bytes;
		if (!(tag->t_flags & cpu_to_be16(JBD2_FLAG_SAME_UUID)))
			tagp += 16;

		if (tag->t_flags & cpu_to_be16(JBD2_FLAG_LAST_TAG))
			break;
	}

	return nr;
}


/* Make sure we wrap around the log correctly! */
#define wrap(journal, var)						\
do {									\
	if (var >= (journal)->j_last)					\
		var -= ((journal)->j_last - (journal)->j_first);	\
} while (0)

/**
 * jbd2_journal_recover - recovers a on-disk journal
 * @journal: the journal to recover
 *
 * The primary function for recovering the log contents when mounting a
 * journaled device.
 *
 * Recovery is done in three passes.  In the first pass, we look for the
 * end of the log.  In the second, we assemble the list of revoke
 * blocks.  In the third and final pass, we replay any un-revoked blocks
 * in the log.
 */
int jbd2_journal_recover(journal_t *journal)
{
	int			err, err2;
	journal_superblock_t *	sb;

	struct recovery_info	info;

	memset(&info, 0, sizeof(info));
	sb = journal->j_superblock;

	/*
	 * The journal superblock's s_start field (the current log head)
	 * is always zero if, and only if, the journal was cleanly
	 * unmounted.
	 */

	if (!sb->s_start) {
		jbd_debug(1, "No recovery required, last transaction %d\n",
			  be32_to_cpu(sb->s_sequence));
		journal->j_transaction_sequence = be32_to_cpu(sb->s_sequence) + 1;
		return 0;
	}

	err = do_one_pass(journal, &info, PASS_SCAN);
	if (!err)
		err = do_one_pass(journal, &info, PASS_REVOKE);
	if (!err)
		err = do_one_pass(journal, &info, PASS_REPLAY);

	jbd_debug(1, "JBD2: recovery, exit status %d, "
		  "recovered transactions %u to %u\n",
		  err, info.start_transaction, info.end_transaction);
	jbd_debug(1, "JBD2: Replayed %d and revoked %d/%d blocks\n",
		  info.nr_replays, info.nr_revoke_hits, info.nr_revokes);

	/* Restart the log at the next transaction ID, thus invalidating
	 * any existing commit records in the log. */
	journal->j_transaction_sequence = ++info.end_transaction;

	jbd2_journal_clear_revoke(journal);
	err2 = sync_blockdev(journal->j_fs_dev);
	if (!err)
		err = err2;
	/* Make sure all replayed data is on permanent storage */
	if (journal->j_flags & JBD2_BARRIER) {
		err2 = blkdev_issue_flush(journal->j_fs_dev, GFP_KERNEL, NULL);
		if (!err)
			err = err2;
	}
	return err;
}

/**
 * jbd2_journal_skip_recovery - Start journal and wipe exiting records
 * @journal: journal to startup
 *
 * Locate any valid recovery information from the journal and set up the
 * journal structures in memory to ignore it (presumably because the
 * caller has evidence that it is out of date).
 * This function does'nt appear to be exorted..
 *
 * We perform one pass over the journal to allow us to tell the user how
 * much recovery information is being erased, and to let us initialise
 * the journal transaction sequence numbers to the next unused ID.
 */
int jbd2_journal_skip_recovery(journal_t *journal)
{
	int			err;

	struct recovery_info	info;

	memset (&info, 0, sizeof(info));

	err = do_one_pass(journal, &info, PASS_SCAN);

	if (err) {
		printk(KERN_ERR "JBD2: error %d scanning journal\n", err);
		++journal->j_transaction_sequence;
	} else {
#ifdef CONFIG_JBD2_DEBUG
		int dropped = info.end_transaction -
			be32_to_cpu(journal->j_superblock->s_sequence);
		jbd_debug(1,
			  "JBD2: ignoring %d transaction%s from the journal.\n",
			  dropped, (dropped == 1) ? "" : "s");
#endif
		journal->j_transaction_sequence = ++info.end_transaction;
	}

	journal->j_tail = 0;
	return err;
}

static inline unsigned long long read_tag_block(journal_t *journal,
						journal_block_tag_t *tag)
{
	unsigned long long block = be32_to_cpu(tag->t_blocknr);
	if (JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_64BIT))
		block |= (u64)be32_to_cpu(tag->t_blocknr_high) << 32;
	return block;
}

/*
 * calc_chksums calculates the checksums for the blocks described in the
 * descriptor block.
 */
static int calc_chksums(journal_t *journal, struct buffer_head *bh,
			unsigned long *next_log_block, __u32 *crc32_sum)
{
	int i, num_blks, err;
	unsigned long io_block;
	struct buffer_head *obh;

	num_blks = count_tags(journal, bh);
	/* Calculate checksum of the descriptor block. */
	*crc32_sum = crc32_be(*crc32_sum, (void *)bh->b_data, bh->b_size);

	for (i = 0; i < num_blks; i++) {
		io_block = (*next_log_block)++;
		wrap(journal, *next_log_block);
		err = jread(&obh, journal, io_block);
		if (err) {
			printk(KERN_ERR "JBD2: IO error %d recovering block "
				"%lu in log\n", err, io_block);
			return 1;
		} else {
			*crc32_sum = crc32_be(*crc32_sum, (void *)obh->b_data,
				     obh->b_size);
		}
		put_bh(obh);
	}
	return 0;
}

static int jbd2_commit_block_csum_verify(journal_t *j, void *buf)
{
	struct commit_header *h;
	__be32 provided;
	__u32 calculated;

	if (!jbd2_journal_has_csum_v2or3(j))
		return 1;

	h = buf;
	provided = h->h_chksum[0];
	h->h_chksum[0] = 0;
	calculated = jbd2_chksum(j, j->j_csum_seed, buf, j->j_blocksize);
	h->h_chksum[0] = provided;

	return provided == cpu_to_be32(calculated);
}

static int jbd2_block_tag_csum_verify(journal_t *j, journal_block_tag_t *tag,
				      void *buf, __u32 sequence)
{
	journal_block_tag3_t *tag3 = (journal_block_tag3_t *)tag;
	__u32 csum32;
	__be32 seq;

	if (!jbd2_journal_has_csum_v2or3(j))
		return 1;

	seq = cpu_to_be32(sequence);
	csum32 = jbd2_chksum(j, j->j_csum_seed, (__u8 *)&seq, sizeof(seq));
	csum32 = jbd2_chksum(j, csum32, buf, j->j_blocksize);

	if (JBD2_HAS_INCOMPAT_FEATURE(j, JBD2_FEATURE_INCOMPAT_CSUM_V3))
		return tag3->t_checksum == cpu_to_be32(csum32);
	else
		return tag->t_checksum == cpu_to_be16(csum32);
}

static int do_one_pass(journal_t *journal,
			struct recovery_info *info, enum passtype pass)
{
	unsigned int		first_commit_ID, next_commit_ID;
	unsigned long		next_log_block;
	int			err, success = 0;
	journal_superblock_t *	sb;
	journal_header_t *	tmp;
	struct buffer_head *	bh;
	unsigned int		sequence;
	int			blocktype;
	int			tag_bytes = journal_tag_bytes(journal);
	__u32			crc32_sum = ~0; /* Transactional Checksums */
	int			descr_csum_size = 0;
	int			block_error = 0;

	/*
	 * First thing is to establish what we expect to find in the log
	 * (in terms of transaction IDs), and where (in terms of log
	 * block offsets): query the superblock.
	 */

	sb = journal->j_superblock;
	next_commit_ID = be32_to_cpu(sb->s_sequence);
	next_log_block = be32_to_cpu(sb->s_start);

	first_commit_ID = next_commit_ID;
	if (pass == PASS_SCAN)
		info->start_transaction = first_commit_ID;

	jbd_debug(1, "Starting recovery pass %d\n", pass);

	/*
	 * Now we walk through the log, transaction by transaction,
	 * making sure that each transaction has a commit block in the
	 * expected place.  Each complete transaction gets replayed back
	 * into the main filesystem.
	 */

	while (1) {
		int			flags;
		char *			tagp;
		journal_block_tag_t *	tag;
		struct buffer_head *	obh;
		struct buffer_head *	nbh;

		cond_resched();

		/* If we already know where to stop the log traversal,
		 * check right now that we haven't gone past the end of
		 * the log. */

		if (pass != PASS_SCAN)
			if (tid_geq(next_commit_ID, info->end_transaction))
				break;

		jbd_debug(2, "Scanning for sequence ID %u at %lu/%lu\n",
			  next_commit_ID, next_log_block, journal->j_last);

		/* Skip over each chunk of the transaction looking
		 * either the next descriptor block or the final commit
		 * record. */

		jbd_debug(3, "JBD2: checking block %ld\n", next_log_block);
		err = jread(&bh, journal, next_log_block);
		if (err)
			goto failed;

		next_log_block++;
		wrap(journal, next_log_block);

		/* What kind of buffer is it?
		 *
		 * If it is a descriptor block, check that it has the
		 * expected sequence number.  Otherwise, we're all done
		 * here. */

		tmp = (journal_header_t *)bh->b_data;

		if (tmp->h_magic != cpu_to_be32(JBD2_MAGIC_NUMBER)) {
			brelse(bh);
			break;
		}

		blocktype = be32_to_cpu(tmp->h_blocktype);
		sequence = be32_to_cpu(tmp->h_sequence);
		jbd_debug(3, "Found magic %d, sequence %d\n",
			  blocktype, sequence);

		if (sequence != next_commit_ID) {
			brelse(bh);
			break;
		}

		/* OK, we have a valid descriptor block which matches
		 * all of the sequence number checks.  What are we going
		 * to do with it?  That depends on the pass... */

		switch(blocktype) {
		case JBD2_DESCRIPTOR_BLOCK:
			/* Verify checksum first */
			if (jbd2_journal_has_csum_v2or3(journal))
				descr_csum_size =
					sizeof(struct jbd2_journal_block_tail);
			if (descr_csum_size > 0 &&
			    !jbd2_descr_block_csum_verify(journal,
							  bh->b_data)) {
				err = -EIO;
				goto failed;
			}

			/* If it is a valid descriptor block, replay it
			 * in pass REPLAY; if journal_checksums enabled, then
			 * calculate checksums in PASS_SCAN, otherwise,
			 * just skip over the blocks it describes. */
			if (pass != PASS_REPLAY) {
				if (pass == PASS_SCAN &&
				    JBD2_HAS_COMPAT_FEATURE(journal,
					    JBD2_FEATURE_COMPAT_CHECKSUM) &&
				    !info->end_transaction) {
					if (calc_chksums(journal, bh,
							&next_log_block,
							&crc32_sum)) {
						put_bh(bh);
						break;
					}
					put_bh(bh);
					continue;
				}
				next_log_block += count_tags(journal, bh);
				wrap(journal, next_log_block);
				put_bh(bh);
				continue;
			}

			/* A descriptor block: we can now write all of
			 * the data blocks.  Yay, useful work is finally
			 * getting done here! */

			tagp = &bh->b_data[sizeof(journal_header_t)];
			while ((tagp - bh->b_data + tag_bytes)
			       <= journal->j_blocksize - descr_csum_size) {
				unsigned long io_block;

				tag = (journal_block_tag_t *) tagp;
				flags = be16_to_cpu(tag->t_flags);

				io_block = next_log_block++;
				wrap(journal, next_log_block);
				err = jread(&obh, journal, io_block);
				if (err) {
					/* Recover what we can, but
					 * report failure at the end. */
					success = err;
					printk(KERN_ERR
						"JBD2: IO error %d recovering "
						"block %ld in log\n",
						err, io_block);
				} else {
					unsigned long long blocknr;

					J_ASSERT(obh != NULL);
					blocknr = read_tag_block(journal,
								 tag);

					/* If the block has been
					 * revoked, then we're all done
					 * here. */
					if (jbd2_journal_test_revoke
					    (journal, blocknr,
					     next_commit_ID)) {
						brelse(obh);
						++info->nr_revoke_hits;
						goto skip_write;
					}

					/* Look for block corruption */
					if (!jbd2_block_tag_csum_verify(
						journal, tag, obh->b_data,
						be32_to_cpu(tmp->h_sequence))) {
						brelse(obh);
						success = -EIO;
						printk(KERN_ERR "JBD2: Invalid "
						       "checksum recovering "
						       "block %llu in log\n",
						       blocknr);
						block_error = 1;
						goto skip_write;
					}

					/* Find a buffer for the new
					 * data being restored */
					nbh = __getblk(journal->j_fs_dev,
							blocknr,
							journal->j_blocksize);
					if (nbh == NULL) {
						printk(KERN_ERR
						       "JBD2: Out of memory "
						       "during recovery.\n");
						err = -ENOMEM;
						brelse(bh);
						brelse(obh);
						goto failed;
					}

					lock_buffer(nbh);
					memcpy(nbh->b_data, obh->b_data,
							journal->j_blocksize);
					if (flags & JBD2_FLAG_ESCAPE) {
						*((__be32 *)nbh->b_data) =
						cpu_to_be32(JBD2_MAGIC_NUMBER);
					}

					BUFFER_TRACE(nbh, "marking dirty");
					set_buffer_uptodate(nbh);
					mark_buffer_dirty(nbh);
					BUFFER_TRACE(nbh, "marking uptodate");
					++info->nr_replays;
					/* ll_rw_block(WRITE, 1, &nbh); */
					unlock_buffer(nbh);
					brelse(obh);
					brelse(nbh);
				}

			skip_write:
				tagp += tag_bytes;
				if (!(flags & JBD2_FLAG_SAME_UUID))
					tagp += 16;

				if (flags & JBD2_FLAG_LAST_TAG)
					break;
			}

			brelse(bh);
			continue;

		case JBD2_COMMIT_BLOCK:
			/*     How to differentiate between interrupted commit
			 *               and journal corruption ?
			 *
			 * {nth transaction}
			 *        Checksum Verification Failed
			 *			 |
			 *		 ____________________
			 *		|		     |
			 * 	async_commit             sync_commit
			 *     		|                    |
			 *		| GO TO NEXT    "Journal Corruption"
			 *		| TRANSACTION
			 *		|
			 * {(n+1)th transanction}
			 *		|
			 * 	 _______|______________
			 * 	|	 	      |
			 * Commit block found	Commit block not found
			 *      |		      |
			 * "Journal Corruption"       |
			 *		 _____________|_________
			 *     		|	           	|
			 *	nth trans corrupt	OR   nth trans
			 *	and (n+1)th interrupted     interrupted
			 *	before commit block
			 *      could reach the disk.
			 *	(Cannot find the difference in above
			 *	 mentioned conditions. Hence assume
			 *	 "Interrupted Commit".)
			 */

			/* Found an expected commit block: if checksums
			 * are present verify them in PASS_SCAN; else not
			 * much to do other than move on to the next sequence
			 * number. */
			if (pass == PASS_SCAN &&
			    JBD2_HAS_COMPAT_FEATURE(journal,
				    JBD2_FEATURE_COMPAT_CHECKSUM)) {
				int chksum_err, chksum_seen;
				struct commit_header *cbh =
					(struct commit_header *)bh->b_data;
				unsigned found_chksum =
					be32_to_cpu(cbh->h_chksum[0]);

				chksum_err = chksum_seen = 0;

				if (info->end_transaction) {
					journal->j_failed_commit =
						info->end_transaction;
					brelse(bh);
					break;
				}

				if (crc32_sum == found_chksum &&
				    cbh->h_chksum_type == JBD2_CRC32_CHKSUM &&
				    cbh->h_chksum_size ==
						JBD2_CRC32_CHKSUM_SIZE)
				       chksum_seen = 1;
				else if (!(cbh->h_chksum_type == 0 &&
					     cbh->h_chksum_size == 0 &&
					     found_chksum == 0 &&
					     !chksum_seen))
				/*
				 * If fs is mounted using an old kernel and then
				 * kernel with journal_chksum is used then we
				 * get a situation where the journal flag has
				 * checksum flag set but checksums are not
				 * present i.e chksum = 0, in the individual
				 * commit blocks.
				 * Hence to avoid checksum failures, in this
				 * situation, this extra check is added.
				 */
						chksum_err = 1;

				if (chksum_err) {
					info->end_transaction = next_commit_ID;

					if (!JBD2_HAS_INCOMPAT_FEATURE(journal,
					   JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)){
						journal->j_failed_commit =
							next_commit_ID;
						brelse(bh);
						break;
					}
				}
				crc32_sum = ~0;
			}
			if (pass == PASS_SCAN &&
			    !jbd2_commit_block_csum_verify(journal,
							   bh->b_data)) {
				info->end_transaction = next_commit_ID;

				if (!JBD2_HAS_INCOMPAT_FEATURE(journal,
				     JBD2_FEATURE_INCOMPAT_ASYNC_COMMIT)) {
					journal->j_failed_commit =
						next_commit_ID;
					brelse(bh);
					break;
				}
			}
			brelse(bh);
			next_commit_ID++;
			continue;

		case JBD2_REVOKE_BLOCK:
			/* If we aren't in the REVOKE pass, then we can
			 * just skip over this block. */
			if (pass != PASS_REVOKE) {
				brelse(bh);
				continue;
			}

			err = scan_revoke_records(journal, bh,
						  next_commit_ID, info);
			brelse(bh);
			if (err)
				goto failed;
			continue;

		default:
			jbd_debug(3, "Unrecognised magic %d, end of scan.\n",
				  blocktype);
			brelse(bh);
			goto done;
		}
	}

 done:
	/*
	 * We broke out of the log scan loop: either we came to the
	 * known end of the log or we found an unexpected block in the
	 * log.  If the latter happened, then we know that the "current"
	 * transaction marks the end of the valid log.
	 */

	if (pass == PASS_SCAN) {
		if (!info->end_transaction)
			info->end_transaction = next_commit_ID;
	} else {
		/* It's really bad news if different passes end up at
		 * different places (but possible due to IO errors). */
		if (info->end_transaction != next_commit_ID) {
			printk(KERN_ERR "JBD2: recovery pass %d ended at "
				"transaction %u, expected %u\n",
				pass, next_commit_ID, info->end_transaction);
			if (!success)
				success = -EIO;
		}
	}
	if (block_error && success == 0)
		success = -EIO;
	return success;

 failed:
	return err;
}

static int jbd2_revoke_block_csum_verify(journal_t *j,
					 void *buf)
{
	struct jbd2_journal_revoke_tail *tail;
	__be32 provided;
	__u32 calculated;

	if (!jbd2_journal_has_csum_v2or3(j))
		return 1;

	tail = (struct jbd2_journal_revoke_tail *)(buf + j->j_blocksize -
			sizeof(struct jbd2_journal_revoke_tail));
	provided = tail->r_checksum;
	tail->r_checksum = 0;
	calculated = jbd2_chksum(j, j->j_csum_seed, buf, j->j_blocksize);
	tail->r_checksum = provided;

	return provided == cpu_to_be32(calculated);
}

/* Scan a revoke record, marking all blocks mentioned as revoked. */

static int scan_revoke_records(journal_t *journal, struct buffer_head *bh,
			       tid_t sequence, struct recovery_info *info)
{
	jbd2_journal_revoke_header_t *header;
	int offset, max;
	int record_len = 4;

	header = (jbd2_journal_revoke_header_t *) bh->b_data;
	offset = sizeof(jbd2_journal_revoke_header_t);
	max = be32_to_cpu(header->r_count);

	if (!jbd2_revoke_block_csum_verify(journal, header))
		return -EINVAL;

	if (JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_64BIT))
		record_len = 8;

	while (offset + record_len <= max) {
		unsigned long long blocknr;
		int err;

		if (record_len == 4)
			blocknr = be32_to_cpu(* ((__be32 *) (bh->b_data+offset)));
		else
			blocknr = be64_to_cpu(* ((__be64 *) (bh->b_data+offset)));
		offset += record_len;
		err = jbd2_journal_set_revoke(journal, blocknr, sequence);
		if (err)
			return err;
		++info->nr_revokes;
	}
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/jbd2/recovery.c */
/************************************************************/
/*
 * linux/fs/jbd2/checkpoint.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1999
 *
 * Copyright 1999 Red Hat Software --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Checkpoint routines for the generic filesystem journaling code.
 * Part of the ext2fs journaling system.
 *
 * Checkpointing is the process of ensuring that a section of the log is
 * committed fully to disk, so that that portion of the log can be
 * reused.
 */

// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/jbd2.h>
// #include <linux/errno.h>
// #include <linux/slab.h>
// #include <linux/blkdev.h>
// #include <trace/events/jbd2.h>

/*
 * Unlink a buffer from a transaction checkpoint list.
 *
 * Called with j_list_lock held.
 */
static inline void __buffer_unlink_first(struct journal_head *jh)
{
	transaction_t *transaction = jh->b_cp_transaction;

	jh->b_cpnext->b_cpprev = jh->b_cpprev;
	jh->b_cpprev->b_cpnext = jh->b_cpnext;
	if (transaction->t_checkpoint_list == jh) {
		transaction->t_checkpoint_list = jh->b_cpnext;
		if (transaction->t_checkpoint_list == jh)
			transaction->t_checkpoint_list = NULL;
	}
}

/*
 * Unlink a buffer from a transaction checkpoint(io) list.
 *
 * Called with j_list_lock held.
 */
static inline void __buffer_unlink(struct journal_head *jh)
{
	transaction_t *transaction = jh->b_cp_transaction;

	__buffer_unlink_first(jh);
	if (transaction->t_checkpoint_io_list == jh) {
		transaction->t_checkpoint_io_list = jh->b_cpnext;
		if (transaction->t_checkpoint_io_list == jh)
			transaction->t_checkpoint_io_list = NULL;
	}
}

/*
 * Move a buffer from the checkpoint list to the checkpoint io list
 *
 * Called with j_list_lock held
 */
static inline void __buffer_relink_io(struct journal_head *jh)
{
	transaction_t *transaction = jh->b_cp_transaction;

	__buffer_unlink_first(jh);

	if (!transaction->t_checkpoint_io_list) {
		jh->b_cpnext = jh->b_cpprev = jh;
	} else {
		jh->b_cpnext = transaction->t_checkpoint_io_list;
		jh->b_cpprev = transaction->t_checkpoint_io_list->b_cpprev;
		jh->b_cpprev->b_cpnext = jh;
		jh->b_cpnext->b_cpprev = jh;
	}
	transaction->t_checkpoint_io_list = jh;
}

/*
 * Try to release a checkpointed buffer from its transaction.
 * Returns 1 if we released it and 2 if we also released the
 * whole transaction.
 *
 * Requires j_list_lock
 */
static int __try_to_free_cp_buf(struct journal_head *jh)
{
	int ret = 0;
	struct buffer_head *bh = jh2bh(jh);

	if (jh->b_transaction == NULL && !buffer_locked(bh) &&
	    !buffer_dirty(bh) && !buffer_write_io_error(bh)) {
		/*
		 * Get our reference so that bh cannot be freed before
		 * we unlock it
		 */
		get_bh(bh);
		JBUFFER_TRACE(jh, "remove from checkpoint list");
		ret = __jbd2_journal_remove_checkpoint(jh) + 1;
		BUFFER_TRACE(bh, "release");
		__brelse(bh);
	}
	return ret;
}

/*
 * __jbd2_log_wait_for_space: wait until there is space in the journal.
 *
 * Called under j-state_lock *only*.  It will be unlocked if we have to wait
 * for a checkpoint to free up some space in the log.
 */
void __jbd2_log_wait_for_space(journal_t *journal)
{
	int nblocks, space_left;
	/* assert_spin_locked(&journal->j_state_lock); */

	nblocks = jbd2_space_needed(journal);
	while (jbd2_log_space_left(journal) < nblocks) {
		if (journal->j_flags & JBD2_ABORT)
			return;
		write_unlock(&journal->j_state_lock);
		mutex_lock(&journal->j_checkpoint_mutex);

		/*
		 * Test again, another process may have checkpointed while we
		 * were waiting for the checkpoint lock. If there are no
		 * transactions ready to be checkpointed, try to recover
		 * journal space by calling cleanup_journal_tail(), and if
		 * that doesn't work, by waiting for the currently committing
		 * transaction to complete.  If there is absolutely no way
		 * to make progress, this is either a BUG or corrupted
		 * filesystem, so abort the journal and leave a stack
		 * trace for forensic evidence.
		 */
		write_lock(&journal->j_state_lock);
		spin_lock(&journal->j_list_lock);
		nblocks = jbd2_space_needed(journal);
		space_left = jbd2_log_space_left(journal);
		if (space_left < nblocks) {
			int chkpt = journal->j_checkpoint_transactions != NULL;
			tid_t tid = 0;

			if (journal->j_committing_transaction)
				tid = journal->j_committing_transaction->t_tid;
			spin_unlock(&journal->j_list_lock);
			write_unlock(&journal->j_state_lock);
			if (chkpt) {
				jbd2_log_do_checkpoint(journal);
			} else if (jbd2_cleanup_journal_tail(journal) == 0) {
				/* We were able to recover space; yay! */
				;
			} else if (tid) {
				/*
				 * jbd2_journal_commit_transaction() may want
				 * to take the checkpoint_mutex if JBD2_FLUSHED
				 * is set.  So we need to temporarily drop it.
				 */
				mutex_unlock(&journal->j_checkpoint_mutex);
				jbd2_log_wait_commit(journal, tid);
				write_lock(&journal->j_state_lock);
				continue;
			} else {
				printk(KERN_ERR "%s: needed %d blocks and "
				       "only had %d space available\n",
				       __func__, nblocks, space_left);
				printk(KERN_ERR "%s: no way to get more "
				       "journal space in %s\n", __func__,
				       journal->j_devname);
				WARN_ON(1);
				jbd2_journal_abort(journal, 0);
			}
			write_lock(&journal->j_state_lock);
		} else {
			spin_unlock(&journal->j_list_lock);
		}
		mutex_unlock(&journal->j_checkpoint_mutex);
	}
}

/*
 * Clean up transaction's list of buffers submitted for io.
 * We wait for any pending IO to complete and remove any clean
 * buffers. Note that we take the buffers in the opposite ordering
 * from the one in which they were submitted for IO.
 *
 * Return 0 on success, and return <0 if some buffers have failed
 * to be written out.
 *
 * Called with j_list_lock held.
 */
static int __wait_cp_io(journal_t *journal, transaction_t *transaction)
{
	struct journal_head *jh;
	struct buffer_head *bh;
	tid_t this_tid;
	int released = 0;
	int ret = 0;

	this_tid = transaction->t_tid;
restart:
	/* Did somebody clean up the transaction in the meanwhile? */
	if (journal->j_checkpoint_transactions != transaction ||
			transaction->t_tid != this_tid)
		return ret;
	while (!released && transaction->t_checkpoint_io_list) {
		jh = transaction->t_checkpoint_io_list;
		bh = jh2bh(jh);
		get_bh(bh);
		if (buffer_locked(bh)) {
			spin_unlock(&journal->j_list_lock);
			wait_on_buffer(bh);
			/* the journal_head may have gone by now */
			BUFFER_TRACE(bh, "brelse");
			__brelse(bh);
			spin_lock(&journal->j_list_lock);
			goto restart;
		}
		if (unlikely(buffer_write_io_error(bh)))
			ret = -EIO;

		/*
		 * Now in whatever state the buffer currently is, we know that
		 * it has been written out and so we can drop it from the list
		 */
		released = __jbd2_journal_remove_checkpoint(jh);
		__brelse(bh);
	}

	return ret;
}

static void
__flush_batch(journal_t *journal, int *batch_count)
{
	int i;
	struct blk_plug plug;

	blk_start_plug(&plug);
	for (i = 0; i < *batch_count; i++)
		write_dirty_buffer(journal->j_chkpt_bhs[i], WRITE_SYNC);
	blk_finish_plug(&plug);

	for (i = 0; i < *batch_count; i++) {
		struct buffer_head *bh = journal->j_chkpt_bhs[i];
		BUFFER_TRACE(bh, "brelse");
		__brelse(bh);
	}
	*batch_count = 0;
}

/*
 * Try to flush one buffer from the checkpoint list to disk.
 *
 * Return 1 if something happened which requires us to abort the current
 * scan of the checkpoint list.  Return <0 if the buffer has failed to
 * be written out.
 *
 * Called with j_list_lock held and drops it if 1 is returned
 */
static int __process_buffer(journal_t *journal, struct journal_head *jh,
			    int *batch_count, transaction_t *transaction)
{
	struct buffer_head *bh = jh2bh(jh);
	int ret = 0;

	if (buffer_locked(bh)) {
		get_bh(bh);
		spin_unlock(&journal->j_list_lock);
		wait_on_buffer(bh);
		/* the journal_head may have gone by now */
		BUFFER_TRACE(bh, "brelse");
		__brelse(bh);
		ret = 1;
	} else if (jh->b_transaction != NULL) {
		transaction_t *t = jh->b_transaction;
		tid_t tid = t->t_tid;

		transaction->t_chp_stats.cs_forced_to_close++;
		spin_unlock(&journal->j_list_lock);
		if (unlikely(journal->j_flags & JBD2_UNMOUNT))
			/*
			 * The journal thread is dead; so starting and
			 * waiting for a commit to finish will cause
			 * us to wait for a _very_ long time.
			 */
			printk(KERN_ERR "JBD2: %s: "
			       "Waiting for Godot: block %llu\n",
			       journal->j_devname,
			       (unsigned long long) bh->b_blocknr);
		jbd2_log_start_commit(journal, tid);
		jbd2_log_wait_commit(journal, tid);
		ret = 1;
	} else if (!buffer_dirty(bh)) {
		ret = 1;
		if (unlikely(buffer_write_io_error(bh)))
			ret = -EIO;
		get_bh(bh);
		BUFFER_TRACE(bh, "remove from checkpoint");
		__jbd2_journal_remove_checkpoint(jh);
		spin_unlock(&journal->j_list_lock);
		__brelse(bh);
	} else {
		/*
		 * Important: we are about to write the buffer, and
		 * possibly block, while still holding the journal lock.
		 * We cannot afford to let the transaction logic start
		 * messing around with this buffer before we write it to
		 * disk, as that would break recoverability.
		 */
		BUFFER_TRACE(bh, "queue");
		get_bh(bh);
		J_ASSERT_BH(bh, !buffer_jwrite(bh));
		journal->j_chkpt_bhs[*batch_count] = bh;
		__buffer_relink_io(jh);
		transaction->t_chp_stats.cs_written++;
		(*batch_count)++;
		if (*batch_count == JBD2_NR_BATCH) {
			spin_unlock(&journal->j_list_lock);
			__flush_batch(journal, batch_count);
			ret = 1;
		}
	}
	return ret;
}

/*
 * Perform an actual checkpoint. We take the first transaction on the
 * list of transactions to be checkpointed and send all its buffers
 * to disk. We submit larger chunks of data at once.
 *
 * The journal should be locked before calling this function.
 * Called with j_checkpoint_mutex held.
 */
int jbd2_log_do_checkpoint(journal_t *journal)
{
	transaction_t *transaction;
	tid_t this_tid;
	int result;

	jbd_debug(1, "Start checkpoint\n");

	/*
	 * First thing: if there are any transactions in the log which
	 * don't need checkpointing, just eliminate them from the
	 * journal straight away.
	 */
	result = jbd2_cleanup_journal_tail(journal);
	trace_jbd2_checkpoint(journal, result);
	jbd_debug(1, "cleanup_journal_tail returned %d\n", result);
	if (result <= 0)
		return result;

	/*
	 * OK, we need to start writing disk blocks.  Take one transaction
	 * and write it.
	 */
	result = 0;
	spin_lock(&journal->j_list_lock);
	if (!journal->j_checkpoint_transactions)
		goto out;
	transaction = journal->j_checkpoint_transactions;
	if (transaction->t_chp_stats.cs_chp_time == 0)
		transaction->t_chp_stats.cs_chp_time = jiffies;
	this_tid = transaction->t_tid;
restart:
	/*
	 * If someone cleaned up this transaction while we slept, we're
	 * done (maybe it's a new transaction, but it fell at the same
	 * address).
	 */
	if (journal->j_checkpoint_transactions == transaction &&
			transaction->t_tid == this_tid) {
		int batch_count = 0;
		struct journal_head *jh;
		int retry = 0, err;

		while (!retry && transaction->t_checkpoint_list) {
			jh = transaction->t_checkpoint_list;
			retry = __process_buffer(journal, jh, &batch_count,
						 transaction);
			if (retry < 0 && !result)
				result = retry;
			if (!retry && (need_resched() ||
				spin_needbreak(&journal->j_list_lock))) {
				spin_unlock(&journal->j_list_lock);
				retry = 1;
				break;
			}
		}

		if (batch_count) {
			if (!retry) {
				spin_unlock(&journal->j_list_lock);
				retry = 1;
			}
			__flush_batch(journal, &batch_count);
		}

		if (retry) {
			spin_lock(&journal->j_list_lock);
			goto restart;
		}
		/*
		 * Now we have cleaned up the first transaction's checkpoint
		 * list. Let's clean up the second one
		 */
		err = __wait_cp_io(journal, transaction);
		if (!result)
			result = err;
	}
out:
	spin_unlock(&journal->j_list_lock);
	if (result < 0)
		jbd2_journal_abort(journal, result);
	else
		result = jbd2_cleanup_journal_tail(journal);

	return (result < 0) ? result : 0;
}

/*
 * Check the list of checkpoint transactions for the journal to see if
 * we have already got rid of any since the last update of the log tail
 * in the journal superblock.  If so, we can instantly roll the
 * superblock forward to remove those transactions from the log.
 *
 * Return <0 on error, 0 on success, 1 if there was nothing to clean up.
 *
 * Called with the journal lock held.
 *
 * This is the only part of the journaling code which really needs to be
 * aware of transaction aborts.  Checkpointing involves writing to the
 * main filesystem area rather than to the journal, so it can proceed
 * even in abort state, but we must not update the super block if
 * checkpointing may have failed.  Otherwise, we would lose some metadata
 * buffers which should be written-back to the filesystem.
 */

int jbd2_cleanup_journal_tail(journal_t *journal)
{
	tid_t		first_tid;
	unsigned long	blocknr;

	if (is_journal_aborted(journal))
		return 1;

	if (!jbd2_journal_get_log_tail(journal, &first_tid, &blocknr))
		return 1;
	J_ASSERT(blocknr != 0);

	/*
	 * We need to make sure that any blocks that were recently written out
	 * --- perhaps by jbd2_log_do_checkpoint() --- are flushed out before
	 * we drop the transactions from the journal. It's unlikely this will
	 * be necessary, especially with an appropriately sized journal, but we
	 * need this to guarantee correctness.  Fortunately
	 * jbd2_cleanup_journal_tail() doesn't get called all that often.
	 */
	if (journal->j_flags & JBD2_BARRIER)
		blkdev_issue_flush(journal->j_fs_dev, GFP_KERNEL, NULL);

	__jbd2_update_log_tail(journal, first_tid, blocknr);
	return 0;
}


/* Checkpoint list management */

/*
 * journal_clean_one_cp_list
 *
 * Find all the written-back checkpoint buffers in the given list and
 * release them.
 *
 * Called with the journal locked.
 * Called with j_list_lock held.
 * Returns number of buffers reaped (for debug)
 */

static int journal_clean_one_cp_list(struct journal_head *jh, int *released)
{
	struct journal_head *last_jh;
	struct journal_head *next_jh = jh;
	int ret, freed = 0;

	*released = 0;
	if (!jh)
		return 0;

	last_jh = jh->b_cpprev;
	do {
		jh = next_jh;
		next_jh = jh->b_cpnext;
		ret = __try_to_free_cp_buf(jh);
		if (ret) {
			freed++;
			if (ret == 2) {
				*released = 1;
				return freed;
			}
		}
		/*
		 * This function only frees up some memory
		 * if possible so we dont have an obligation
		 * to finish processing. Bail out if preemption
		 * requested:
		 */
		if (need_resched())
			return freed;
	} while (jh != last_jh);

	return freed;
}

/*
 * journal_clean_checkpoint_list
 *
 * Find all the written-back checkpoint buffers in the journal and release them.
 *
 * Called with the journal locked.
 * Called with j_list_lock held.
 * Returns number of buffers reaped (for debug)
 */

int __jbd2_journal_clean_checkpoint_list(journal_t *journal)
{
	transaction_t *transaction, *last_transaction, *next_transaction;
	int ret = 0;
	int released;

	transaction = journal->j_checkpoint_transactions;
	if (!transaction)
		goto out;

	last_transaction = transaction->t_cpprev;
	next_transaction = transaction;
	do {
		transaction = next_transaction;
		next_transaction = transaction->t_cpnext;
		ret += journal_clean_one_cp_list(transaction->
				t_checkpoint_list, &released);
		/*
		 * This function only frees up some memory if possible so we
		 * dont have an obligation to finish processing. Bail out if
		 * preemption requested:
		 */
		if (need_resched())
			goto out;
		if (released)
			continue;
		/*
		 * It is essential that we are as careful as in the case of
		 * t_checkpoint_list with removing the buffer from the list as
		 * we can possibly see not yet submitted buffers on io_list
		 */
		ret += journal_clean_one_cp_list(transaction->
				t_checkpoint_io_list, &released);
		if (need_resched())
			goto out;
	} while (transaction != last_transaction);
out:
	return ret;
}

/*
 * journal_remove_checkpoint: called after a buffer has been committed
 * to disk (either by being write-back flushed to disk, or being
 * committed to the log).
 *
 * We cannot safely clean a transaction out of the log until all of the
 * buffer updates committed in that transaction have safely been stored
 * elsewhere on disk.  To achieve this, all of the buffers in a
 * transaction need to be maintained on the transaction's checkpoint
 * lists until they have been rewritten, at which point this function is
 * called to remove the buffer from the existing transaction's
 * checkpoint lists.
 *
 * The function returns 1 if it frees the transaction, 0 otherwise.
 * The function can free jh and bh.
 *
 * This function is called with j_list_lock held.
 */
int __jbd2_journal_remove_checkpoint(struct journal_head *jh)
{
	struct transaction_chp_stats_s *stats;
	transaction_t *transaction;
	journal_t *journal;
	int ret = 0;

	JBUFFER_TRACE(jh, "entry");

	if ((transaction = jh->b_cp_transaction) == NULL) {
		JBUFFER_TRACE(jh, "not on transaction");
		goto out;
	}
	journal = transaction->t_journal;

	JBUFFER_TRACE(jh, "removing from transaction");
	__buffer_unlink(jh);
	jh->b_cp_transaction = NULL;
	jbd2_journal_put_journal_head(jh);

	if (transaction->t_checkpoint_list != NULL ||
	    transaction->t_checkpoint_io_list != NULL)
		goto out;

	/*
	 * There is one special case to worry about: if we have just pulled the
	 * buffer off a running or committing transaction's checkpoing list,
	 * then even if the checkpoint list is empty, the transaction obviously
	 * cannot be dropped!
	 *
	 * The locking here around t_state is a bit sleazy.
	 * See the comment at the end of jbd2_journal_commit_transaction().
	 */
	if (transaction->t_state != T_FINISHED)
		goto out;

	/* OK, that was the last buffer for the transaction: we can now
	   safely remove this transaction from the log */
	stats = &transaction->t_chp_stats;
	if (stats->cs_chp_time)
		stats->cs_chp_time = jbd2_time_diff(stats->cs_chp_time,
						    jiffies);
	trace_jbd2_checkpoint_stats(journal->j_fs_dev->bd_dev,
				    transaction->t_tid, stats);

	__jbd2_journal_drop_transaction(journal, transaction);
	jbd2_journal_free_transaction(transaction);
	ret = 1;
out:
	return ret;
}

/*
 * journal_insert_checkpoint: put a committed buffer onto a checkpoint
 * list so that we know when it is safe to clean the transaction out of
 * the log.
 *
 * Called with the journal locked.
 * Called with j_list_lock held.
 */
void __jbd2_journal_insert_checkpoint(struct journal_head *jh,
			       transaction_t *transaction)
{
	JBUFFER_TRACE(jh, "entry");
	J_ASSERT_JH(jh, buffer_dirty(jh2bh(jh)) || buffer_jbddirty(jh2bh(jh)));
	J_ASSERT_JH(jh, jh->b_cp_transaction == NULL);

	/* Get reference for checkpointing transaction */
	jbd2_journal_grab_journal_head(jh2bh(jh));
	jh->b_cp_transaction = transaction;

	if (!transaction->t_checkpoint_list) {
		jh->b_cpnext = jh->b_cpprev = jh;
	} else {
		jh->b_cpnext = transaction->t_checkpoint_list;
		jh->b_cpprev = transaction->t_checkpoint_list->b_cpprev;
		jh->b_cpprev->b_cpnext = jh;
		jh->b_cpnext->b_cpprev = jh;
	}
	transaction->t_checkpoint_list = jh;
}

/*
 * We've finished with this transaction structure: adios...
 *
 * The transaction must have no links except for the checkpoint by this
 * point.
 *
 * Called with the journal locked.
 * Called with j_list_lock held.
 */

void __jbd2_journal_drop_transaction(journal_t *journal, transaction_t *transaction)
{
	assert_spin_locked(&journal->j_list_lock);
	if (transaction->t_cpnext) {
		transaction->t_cpnext->t_cpprev = transaction->t_cpprev;
		transaction->t_cpprev->t_cpnext = transaction->t_cpnext;
		if (journal->j_checkpoint_transactions == transaction)
			journal->j_checkpoint_transactions =
				transaction->t_cpnext;
		if (journal->j_checkpoint_transactions == transaction)
			journal->j_checkpoint_transactions = NULL;
	}

	J_ASSERT(transaction->t_state == T_FINISHED);
	J_ASSERT(transaction->t_buffers == NULL);
	J_ASSERT(transaction->t_forget == NULL);
	J_ASSERT(transaction->t_shadow_list == NULL);
	J_ASSERT(transaction->t_checkpoint_list == NULL);
	J_ASSERT(transaction->t_checkpoint_io_list == NULL);
	J_ASSERT(atomic_read(&transaction->t_updates) == 0);
	J_ASSERT(journal->j_committing_transaction != transaction);
	J_ASSERT(journal->j_running_transaction != transaction);

	trace_jbd2_drop_transaction(journal, transaction);

	jbd_debug(1, "Dropping transaction %d, all done\n", transaction->t_tid);
}
/************************************************************/
/* ../linux-3.17/fs/jbd2/checkpoint.c */
/************************************************************/
/*
 * linux/fs/jbd2/revoke.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 2000
 *
 * Copyright 2000 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Journal revoke routines for the generic filesystem journaling code;
 * part of the ext2fs journaling system.
 *
 * Revoke is the mechanism used to prevent old log records for deleted
 * metadata from being replayed on top of newer data using the same
 * blocks.  The revoke mechanism is used in two separate places:
 *
 * + Commit: during commit we write the entire list of the current
 *   transaction's revoked blocks to the journal
 *
 * + Recovery: during recovery we record the transaction ID of all
 *   revoked blocks.  If there are multiple revoke records in the log
 *   for a single block, only the last one counts, and if there is a log
 *   entry for a block beyond the last revoke, then that log entry still
 *   gets replayed.
 *
 * We can get interactions between revokes and new log data within a
 * single transaction:
 *
 * Block is revoked and then journaled:
 *   The desired end result is the journaling of the new block, so we
 *   cancel the revoke before the transaction commits.
 *
 * Block is journaled and then revoked:
 *   The revoke must take precedence over the write of the block, so we
 *   need either to cancel the journal entry or to write the revoke
 *   later in the log than the log block.  In this case, we choose the
 *   latter: journaling a block cancels any revoke record for that block
 *   in the current transaction, so any revoke for that block in the
 *   transaction must have happened after the block was journaled and so
 *   the revoke must take precedence.
 *
 * Block is revoked and then written as data:
 *   The data write is allowed to succeed, but the revoke is _not_
 *   cancelled.  We still need to prevent old log records from
 *   overwriting the new data.  We don't even need to clear the revoke
 *   bit here.
 *
 * We cache revoke status of a buffer in the current transaction in b_states
 * bits.  As the name says, revokevalid flag indicates that the cached revoke
 * status of a buffer is valid and we can rely on the cached status.
 *
 * Revoke information on buffers is a tri-state value:
 *
 * RevokeValid clear:	no cached revoke status, need to look it up
 * RevokeValid set, Revoked clear:
 *			buffer has not been revoked, and cancel_revoke
 *			need do nothing.
 * RevokeValid set, Revoked set:
 *			buffer has been revoked.
 *
 * Locking rules:
 * We keep two hash tables of revoke records. One hashtable belongs to the
 * running transaction (is pointed to by journal->j_revoke), the other one
 * belongs to the committing transaction. Accesses to the second hash table
 * happen only from the kjournald and no other thread touches this table.  Also
 * journal_switch_revoke_table() which switches which hashtable belongs to the
 * running and which to the committing transaction is called only from
 * kjournald. Therefore we need no locks when accessing the hashtable belonging
 * to the committing transaction.
 *
 * All users operating on the hash table belonging to the running transaction
 * have a handle to the transaction. Therefore they are safe from kjournald
 * switching hash tables under them. For operations on the lists of entries in
 * the hash table j_revoke_lock is used.
 *
 * Finally, also replay code uses the hash tables but at this moment no one else
 * can touch them (filesystem isn't mounted yet) and hence no locking is
 * needed.
 */

#ifndef __KERNEL__
// #include "jfs_user.h"
#else
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/jbd2.h>
// #include <linux/errno.h>
// #include <linux/slab.h>
#include <linux/list.h>
#include <linux/init.h>
// #include <linux/bio.h>
#include <linux/log2.h>
#endif

static struct kmem_cache *jbd2_revoke_record_cache;
static struct kmem_cache *jbd2_revoke_table_cache;

/* Each revoke record represents one single revoked block.  During
   journal replay, this involves recording the transaction ID of the
   last transaction to revoke this block. */

struct jbd2_revoke_record_s
{
	struct list_head  hash;
	tid_t		  sequence;	/* Used for recovery only */
	unsigned long long	  blocknr;
};


/* The revoke table is just a simple hash table of revoke records. */
struct jbd2_revoke_table_s
{
	/* It is conceivable that we might want a larger hash table
	 * for recovery.  Must be a power of two. */
	int		  hash_size;
	int		  hash_shift;
	struct list_head *hash_table;
};


#ifdef __KERNEL__
static void write_one_revoke_record(journal_t *, transaction_t *,
				    struct list_head *,
				    struct buffer_head **, int *,
				    struct jbd2_revoke_record_s *, int);
static void flush_descriptor(journal_t *, struct buffer_head *, int, int);
#endif

/* Utility functions to maintain the revoke table */

/* Borrowed from buffer.c: this is a tried and tested block hash function */
static inline int hash(journal_t *journal, unsigned long long block)
{
	struct jbd2_revoke_table_s *table = journal->j_revoke;
	int hash_shift = table->hash_shift;
	int hash = (int)block ^ (int)((block >> 31) >> 1);

	return ((hash << (hash_shift - 6)) ^
		(hash >> 13) ^
		(hash << (hash_shift - 12))) & (table->hash_size - 1);
}

static int insert_revoke_hash(journal_t *journal, unsigned long long blocknr,
			      tid_t seq)
{
	struct list_head *hash_list;
	struct jbd2_revoke_record_s *record;

repeat:
	record = kmem_cache_alloc(jbd2_revoke_record_cache, GFP_NOFS);
	if (!record)
		goto oom;

	record->sequence = seq;
	record->blocknr = blocknr;
	hash_list = &journal->j_revoke->hash_table[hash(journal, blocknr)];
	spin_lock(&journal->j_revoke_lock);
	list_add(&record->hash, hash_list);
	spin_unlock(&journal->j_revoke_lock);
	return 0;

oom:
	if (!journal_oom_retry)
		return -ENOMEM;
	jbd_debug(1, "ENOMEM in %s, retrying\n", __func__);
	yield();
	goto repeat;
}

/* Find a revoke record in the journal's hash table. */

static struct jbd2_revoke_record_s *find_revoke_record(journal_t *journal,
						      unsigned long long blocknr)
{
	struct list_head *hash_list;
	struct jbd2_revoke_record_s *record;

	hash_list = &journal->j_revoke->hash_table[hash(journal, blocknr)];

	spin_lock(&journal->j_revoke_lock);
	record = (struct jbd2_revoke_record_s *) hash_list->next;
	while (&(record->hash) != hash_list) {
		if (record->blocknr == blocknr) {
			spin_unlock(&journal->j_revoke_lock);
			return record;
		}
		record = (struct jbd2_revoke_record_s *) record->hash.next;
	}
	spin_unlock(&journal->j_revoke_lock);
	return NULL;
}

void jbd2_journal_destroy_revoke_caches(void)
{
	if (jbd2_revoke_record_cache) {
		kmem_cache_destroy(jbd2_revoke_record_cache);
		jbd2_revoke_record_cache = NULL;
	}
	if (jbd2_revoke_table_cache) {
		kmem_cache_destroy(jbd2_revoke_table_cache);
		jbd2_revoke_table_cache = NULL;
	}
}

int __init jbd2_journal_init_revoke_caches(void)
{
	J_ASSERT(!jbd2_revoke_record_cache);
	J_ASSERT(!jbd2_revoke_table_cache);

	jbd2_revoke_record_cache = KMEM_CACHE(jbd2_revoke_record_s,
					SLAB_HWCACHE_ALIGN|SLAB_TEMPORARY);
	if (!jbd2_revoke_record_cache)
		goto record_cache_failure;

	jbd2_revoke_table_cache = KMEM_CACHE(jbd2_revoke_table_s,
					     SLAB_TEMPORARY);
	if (!jbd2_revoke_table_cache)
		goto table_cache_failure;
	return 0;
table_cache_failure:
	jbd2_journal_destroy_revoke_caches();
record_cache_failure:
		return -ENOMEM;
}

static struct jbd2_revoke_table_s *jbd2_journal_init_revoke_table(int hash_size)
{
	int shift = 0;
	int tmp = hash_size;
	struct jbd2_revoke_table_s *table;

	table = kmem_cache_alloc(jbd2_revoke_table_cache, GFP_KERNEL);
	if (!table)
		goto out;

	while((tmp >>= 1UL) != 0UL)
		shift++;

	table->hash_size = hash_size;
	table->hash_shift = shift;
	table->hash_table =
		kmalloc(hash_size * sizeof(struct list_head), GFP_KERNEL);
	if (!table->hash_table) {
		kmem_cache_free(jbd2_revoke_table_cache, table);
		table = NULL;
		goto out;
	}

	for (tmp = 0; tmp < hash_size; tmp++)
		INIT_LIST_HEAD(&table->hash_table[tmp]);

out:
	return table;
}

static void jbd2_journal_destroy_revoke_table(struct jbd2_revoke_table_s *table)
{
	int i;
	struct list_head *hash_list;

	for (i = 0; i < table->hash_size; i++) {
		hash_list = &table->hash_table[i];
		J_ASSERT(list_empty(hash_list));
	}

	kfree(table->hash_table);
	kmem_cache_free(jbd2_revoke_table_cache, table);
}

/* Initialise the revoke table for a given journal to a given size. */
int jbd2_journal_init_revoke(journal_t *journal, int hash_size)
{
	J_ASSERT(journal->j_revoke_table[0] == NULL);
	J_ASSERT(is_power_of_2(hash_size));

	journal->j_revoke_table[0] = jbd2_journal_init_revoke_table(hash_size);
	if (!journal->j_revoke_table[0])
		goto fail0;

	journal->j_revoke_table[1] = jbd2_journal_init_revoke_table(hash_size);
	if (!journal->j_revoke_table[1])
		goto fail1;

	journal->j_revoke = journal->j_revoke_table[1];

	spin_lock_init(&journal->j_revoke_lock);

	return 0;

fail1:
	jbd2_journal_destroy_revoke_table(journal->j_revoke_table[0]);
fail0:
	return -ENOMEM;
}

/* Destroy a journal's revoke table.  The table must already be empty! */
void jbd2_journal_destroy_revoke(journal_t *journal)
{
	journal->j_revoke = NULL;
	if (journal->j_revoke_table[0])
		jbd2_journal_destroy_revoke_table(journal->j_revoke_table[0]);
	if (journal->j_revoke_table[1])
		jbd2_journal_destroy_revoke_table(journal->j_revoke_table[1]);
}


#ifdef __KERNEL__

/*
 * jbd2_journal_revoke: revoke a given buffer_head from the journal.  This
 * prevents the block from being replayed during recovery if we take a
 * crash after this current transaction commits.  Any subsequent
 * metadata writes of the buffer in this transaction cancel the
 * revoke.
 *
 * Note that this call may block --- it is up to the caller to make
 * sure that there are no further calls to journal_write_metadata
 * before the revoke is complete.  In ext3, this implies calling the
 * revoke before clearing the block bitmap when we are deleting
 * metadata.
 *
 * Revoke performs a jbd2_journal_forget on any buffer_head passed in as a
 * parameter, but does _not_ forget the buffer_head if the bh was only
 * found implicitly.
 *
 * bh_in may not be a journalled buffer - it may have come off
 * the hash tables without an attached journal_head.
 *
 * If bh_in is non-zero, jbd2_journal_revoke() will decrement its b_count
 * by one.
 */

int jbd2_journal_revoke(handle_t *handle, unsigned long long blocknr,
		   struct buffer_head *bh_in)
{
	struct buffer_head *bh = NULL;
	journal_t *journal;
	struct block_device *bdev;
	int err;

	might_sleep();
	if (bh_in)
		BUFFER_TRACE(bh_in, "enter");

	journal = handle->h_transaction->t_journal;
	if (!jbd2_journal_set_features(journal, 0, 0, JBD2_FEATURE_INCOMPAT_REVOKE)){
		J_ASSERT (!"Cannot set revoke feature!");
		return -EINVAL;
	}

	bdev = journal->j_fs_dev;
	bh = bh_in;

	if (!bh) {
		bh = __find_get_block(bdev, blocknr, journal->j_blocksize);
		if (bh)
			BUFFER_TRACE(bh, "found on hash");
	}
#ifdef JBD2_EXPENSIVE_CHECKING
	else {
		struct buffer_head *bh2;

		/* If there is a different buffer_head lying around in
		 * memory anywhere... */
		bh2 = __find_get_block(bdev, blocknr, journal->j_blocksize);
		if (bh2) {
			/* ... and it has RevokeValid status... */
			if (bh2 != bh && buffer_revokevalid(bh2))
				/* ...then it better be revoked too,
				 * since it's illegal to create a revoke
				 * record against a buffer_head which is
				 * not marked revoked --- that would
				 * risk missing a subsequent revoke
				 * cancel. */
				J_ASSERT_BH(bh2, buffer_revoked(bh2));
			put_bh(bh2);
		}
	}
#endif

	/* We really ought not ever to revoke twice in a row without
           first having the revoke cancelled: it's illegal to free a
           block twice without allocating it in between! */
	if (bh) {
		if (!J_EXPECT_BH(bh, !buffer_revoked(bh),
				 "inconsistent data on disk")) {
			if (!bh_in)
				brelse(bh);
			return -EIO;
		}
		set_buffer_revoked(bh);
		set_buffer_revokevalid(bh);
		if (bh_in) {
			BUFFER_TRACE(bh_in, "call jbd2_journal_forget");
			jbd2_journal_forget(handle, bh_in);
		} else {
			BUFFER_TRACE(bh, "call brelse");
			__brelse(bh);
		}
	}

	jbd_debug(2, "insert revoke for block %llu, bh_in=%p\n",blocknr, bh_in);
	err = insert_revoke_hash(journal, blocknr,
				handle->h_transaction->t_tid);
	BUFFER_TRACE(bh_in, "exit");
	return err;
}

/*
 * Cancel an outstanding revoke.  For use only internally by the
 * journaling code (called from jbd2_journal_get_write_access).
 *
 * We trust buffer_revoked() on the buffer if the buffer is already
 * being journaled: if there is no revoke pending on the buffer, then we
 * don't do anything here.
 *
 * This would break if it were possible for a buffer to be revoked and
 * discarded, and then reallocated within the same transaction.  In such
 * a case we would have lost the revoked bit, but when we arrived here
 * the second time we would still have a pending revoke to cancel.  So,
 * do not trust the Revoked bit on buffers unless RevokeValid is also
 * set.
 */
int jbd2_journal_cancel_revoke(handle_t *handle, struct journal_head *jh)
{
	struct jbd2_revoke_record_s *record;
	journal_t *journal = handle->h_transaction->t_journal;
	int need_cancel;
	int did_revoke = 0;	/* akpm: debug */
	struct buffer_head *bh = jh2bh(jh);

	jbd_debug(4, "journal_head %p, cancelling revoke\n", jh);

	/* Is the existing Revoke bit valid?  If so, we trust it, and
	 * only perform the full cancel if the revoke bit is set.  If
	 * not, we can't trust the revoke bit, and we need to do the
	 * full search for a revoke record. */
	if (test_set_buffer_revokevalid(bh)) {
		need_cancel = test_clear_buffer_revoked(bh);
	} else {
		need_cancel = 1;
		clear_buffer_revoked(bh);
	}

	if (need_cancel) {
		record = find_revoke_record(journal, bh->b_blocknr);
		if (record) {
			jbd_debug(4, "cancelled existing revoke on "
				  "blocknr %llu\n", (unsigned long long)bh->b_blocknr);
			spin_lock(&journal->j_revoke_lock);
			list_del(&record->hash);
			spin_unlock(&journal->j_revoke_lock);
			kmem_cache_free(jbd2_revoke_record_cache, record);
			did_revoke = 1;
		}
	}

#ifdef JBD2_EXPENSIVE_CHECKING
	/* There better not be one left behind by now! */
	record = find_revoke_record(journal, bh->b_blocknr);
	J_ASSERT_JH(jh, record == NULL);
#endif

	/* Finally, have we just cleared revoke on an unhashed
	 * buffer_head?  If so, we'd better make sure we clear the
	 * revoked status on any hashed alias too, otherwise the revoke
	 * state machine will get very upset later on. */
	if (need_cancel) {
		struct buffer_head *bh2;
		bh2 = __find_get_block(bh->b_bdev, bh->b_blocknr, bh->b_size);
		if (bh2) {
			if (bh2 != bh)
				clear_buffer_revoked(bh2);
			__brelse(bh2);
		}
	}
	return did_revoke;
}

/*
 * journal_clear_revoked_flag clears revoked flag of buffers in
 * revoke table to reflect there is no revoked buffers in the next
 * transaction which is going to be started.
 */
void jbd2_clear_buffer_revoked_flags(journal_t *journal)
{
	struct jbd2_revoke_table_s *revoke = journal->j_revoke;
	int i = 0;

	for (i = 0; i < revoke->hash_size; i++) {
		struct list_head *hash_list;
		struct list_head *list_entry;
		hash_list = &revoke->hash_table[i];

		list_for_each(list_entry, hash_list) {
			struct jbd2_revoke_record_s *record;
			struct buffer_head *bh;
			record = (struct jbd2_revoke_record_s *)list_entry;
			bh = __find_get_block(journal->j_fs_dev,
					      record->blocknr,
					      journal->j_blocksize);
			if (bh) {
				clear_buffer_revoked(bh);
				__brelse(bh);
			}
		}
	}
}

/* journal_switch_revoke table select j_revoke for next transaction
 * we do not want to suspend any processing until all revokes are
 * written -bzzz
 */
void jbd2_journal_switch_revoke_table(journal_t *journal)
{
	int i;

	if (journal->j_revoke == journal->j_revoke_table[0])
		journal->j_revoke = journal->j_revoke_table[1];
	else
		journal->j_revoke = journal->j_revoke_table[0];

	for (i = 0; i < journal->j_revoke->hash_size; i++)
		INIT_LIST_HEAD(&journal->j_revoke->hash_table[i]);
}

/*
 * Write revoke records to the journal for all entries in the current
 * revoke hash, deleting the entries as we go.
 */
void jbd2_journal_write_revoke_records(journal_t *journal,
				       transaction_t *transaction,
				       struct list_head *log_bufs,
				       int write_op)
{
	struct buffer_head *descriptor;
	struct jbd2_revoke_record_s *record;
	struct jbd2_revoke_table_s *revoke;
	struct list_head *hash_list;
	int i, offset, count;

	descriptor = NULL;
	offset = 0;
	count = 0;

	/* select revoke table for committing transaction */
	revoke = journal->j_revoke == journal->j_revoke_table[0] ?
		journal->j_revoke_table[1] : journal->j_revoke_table[0];

	for (i = 0; i < revoke->hash_size; i++) {
		hash_list = &revoke->hash_table[i];

		while (!list_empty(hash_list)) {
			record = (struct jbd2_revoke_record_s *)
				hash_list->next;
			write_one_revoke_record(journal, transaction, log_bufs,
						&descriptor, &offset,
						record, write_op);
			count++;
			list_del(&record->hash);
			kmem_cache_free(jbd2_revoke_record_cache, record);
		}
	}
	if (descriptor)
		flush_descriptor(journal, descriptor, offset, write_op);
	jbd_debug(1, "Wrote %d revoke records\n", count);
}

/*
 * Write out one revoke record.  We need to create a new descriptor
 * block if the old one is full or if we have not already created one.
 */

static void write_one_revoke_record(journal_t *journal,
				    transaction_t *transaction,
				    struct list_head *log_bufs,
				    struct buffer_head **descriptorp,
				    int *offsetp,
				    struct jbd2_revoke_record_s *record,
				    int write_op)
{
	int csum_size = 0;
	struct buffer_head *descriptor;
	int offset;
	journal_header_t *header;

	/* If we are already aborting, this all becomes a noop.  We
           still need to go round the loop in
           jbd2_journal_write_revoke_records in order to free all of the
           revoke records: only the IO to the journal is omitted. */
	if (is_journal_aborted(journal))
		return;

	descriptor = *descriptorp;
	offset = *offsetp;

	/* Do we need to leave space at the end for a checksum? */
	if (jbd2_journal_has_csum_v2or3(journal))
		csum_size = sizeof(struct jbd2_journal_revoke_tail);

	/* Make sure we have a descriptor with space left for the record */
	if (descriptor) {
		if (offset >= journal->j_blocksize - csum_size) {
			flush_descriptor(journal, descriptor, offset, write_op);
			descriptor = NULL;
		}
	}

	if (!descriptor) {
		descriptor = jbd2_journal_get_descriptor_buffer(journal);
		if (!descriptor)
			return;
		header = (journal_header_t *)descriptor->b_data;
		header->h_magic     = cpu_to_be32(JBD2_MAGIC_NUMBER);
		header->h_blocktype = cpu_to_be32(JBD2_REVOKE_BLOCK);
		header->h_sequence  = cpu_to_be32(transaction->t_tid);

		/* Record it so that we can wait for IO completion later */
		BUFFER_TRACE(descriptor, "file in log_bufs");
		jbd2_file_log_bh(log_bufs, descriptor);

		offset = sizeof(jbd2_journal_revoke_header_t);
		*descriptorp = descriptor;
	}

	if (JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_64BIT)) {
		* ((__be64 *)(&descriptor->b_data[offset])) =
			cpu_to_be64(record->blocknr);
		offset += 8;

	} else {
		* ((__be32 *)(&descriptor->b_data[offset])) =
			cpu_to_be32(record->blocknr);
		offset += 4;
	}

	*offsetp = offset;
}

static void jbd2_revoke_csum_set(journal_t *j, struct buffer_head *bh)
{
	struct jbd2_journal_revoke_tail *tail;
	__u32 csum;

	if (!jbd2_journal_has_csum_v2or3(j))
		return;

	tail = (struct jbd2_journal_revoke_tail *)(bh->b_data + j->j_blocksize -
			sizeof(struct jbd2_journal_revoke_tail));
	tail->r_checksum = 0;
	csum = jbd2_chksum(j, j->j_csum_seed, bh->b_data, j->j_blocksize);
	tail->r_checksum = cpu_to_be32(csum);
}

/*
 * Flush a revoke descriptor out to the journal.  If we are aborting,
 * this is a noop; otherwise we are generating a buffer which needs to
 * be waited for during commit, so it has to go onto the appropriate
 * journal buffer list.
 */

static void flush_descriptor(journal_t *journal,
			     struct buffer_head *descriptor,
			     int offset, int write_op)
{
	jbd2_journal_revoke_header_t *header;

	if (is_journal_aborted(journal)) {
		put_bh(descriptor);
		return;
	}

	header = (jbd2_journal_revoke_header_t *)descriptor->b_data;
	header->r_count = cpu_to_be32(offset);
	jbd2_revoke_csum_set(journal, descriptor);

	set_buffer_jwrite(descriptor);
	BUFFER_TRACE(descriptor, "write");
	set_buffer_dirty(descriptor);
	write_dirty_buffer(descriptor, write_op);
}
#endif

/*
 * Revoke support for recovery.
 *
 * Recovery needs to be able to:
 *
 *  record all revoke records, including the tid of the latest instance
 *  of each revoke in the journal
 *
 *  check whether a given block in a given transaction should be replayed
 *  (ie. has not been revoked by a revoke record in that or a subsequent
 *  transaction)
 *
 *  empty the revoke table after recovery.
 */

/*
 * First, setting revoke records.  We create a new revoke record for
 * every block ever revoked in the log as we scan it for recovery, and
 * we update the existing records if we find multiple revokes for a
 * single block.
 */

int jbd2_journal_set_revoke(journal_t *journal,
		       unsigned long long blocknr,
		       tid_t sequence)
{
	struct jbd2_revoke_record_s *record;

	record = find_revoke_record(journal, blocknr);
	if (record) {
		/* If we have multiple occurrences, only record the
		 * latest sequence number in the hashed record */
		if (tid_gt(sequence, record->sequence))
			record->sequence = sequence;
		return 0;
	}
	return insert_revoke_hash(journal, blocknr, sequence);
}

/*
 * Test revoke records.  For a given block referenced in the log, has
 * that block been revoked?  A revoke record with a given transaction
 * sequence number revokes all blocks in that transaction and earlier
 * ones, but later transactions still need replayed.
 */

int jbd2_journal_test_revoke(journal_t *journal,
			unsigned long long blocknr,
			tid_t sequence)
{
	struct jbd2_revoke_record_s *record;

	record = find_revoke_record(journal, blocknr);
	if (!record)
		return 0;
	if (tid_gt(sequence, record->sequence))
		return 0;
	return 1;
}

/*
 * Finally, once recovery is over, we need to clear the revoke table so
 * that it can be reused by the running filesystem.
 */

void jbd2_journal_clear_revoke(journal_t *journal)
{
	int i;
	struct list_head *hash_list;
	struct jbd2_revoke_record_s *record;
	struct jbd2_revoke_table_s *revoke;

	revoke = journal->j_revoke;

	for (i = 0; i < revoke->hash_size; i++) {
		hash_list = &revoke->hash_table[i];
		while (!list_empty(hash_list)) {
			record = (struct jbd2_revoke_record_s*) hash_list->next;
			list_del(&record->hash);
			kmem_cache_free(jbd2_revoke_record_cache, record);
		}
	}
}
/************************************************************/
/* ../linux-3.17/fs/jbd2/revoke.c */
/************************************************************/
/*
 * linux/fs/jbd2/journal.c
 *
 * Written by Stephen C. Tweedie <sct@redhat.com>, 1998
 *
 * Copyright 1998 Red Hat corp --- All Rights Reserved
 *
 * This file is part of the Linux kernel and is made available under
 * the terms of the GNU General Public License, version 2, or at your
 * option, any later version, incorporated herein by reference.
 *
 * Generic filesystem journal-writing code; part of the ext2fs
 * journaling system.
 *
 * This file manages journals: areas of disk reserved for logging
 * transactional updates.  This includes the kernel journaling thread
 * which is responsible for scheduling updates to the log.
 *
 * We do not actually manage the physical storage of the journal in this
 * file: that is left to a per-journal policy function, which allows us
 * to store the journal within a filesystem-specified area for ext2
 * journaling (ext2 can use a reserved inode for storing the log).
 */

// #include <linux/module.h>
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/jbd2.h>
// #include <linux/errno.h>
// #include <linux/slab.h>
// #include <linux/init.h>
// #include <linux/mm.h>
#include <linux/freezer.h>
// #include <linux/pagemap.h>
#include <linux/kthread.h>
#include <linux/poison.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/math64.h>
#include <linux/hash.h>
// #include <linux/log2.h>
#include <linux/vmalloc.h>
// #include <linux/backing-dev.h>
// #include <linux/bitops.h>
#include <linux/ratelimit.h>

#define CREATE_TRACE_POINTS
// #include <trace/events/jbd2.h>

#include <asm/uaccess.h>
#include <asm/page.h>

#ifdef CONFIG_JBD2_DEBUG
ushort jbd2_journal_enable_debug __read_mostly;
EXPORT_SYMBOL(jbd2_journal_enable_debug);

module_param_named(jbd2_debug, jbd2_journal_enable_debug, ushort, 0644);
MODULE_PARM_DESC(jbd2_debug, "Debugging level for jbd2");
#endif

EXPORT_SYMBOL(jbd2_journal_extend);
EXPORT_SYMBOL(jbd2_journal_stop);
EXPORT_SYMBOL(jbd2_journal_lock_updates);
EXPORT_SYMBOL(jbd2_journal_unlock_updates);
EXPORT_SYMBOL(jbd2_journal_get_write_access);
EXPORT_SYMBOL(jbd2_journal_get_create_access);
EXPORT_SYMBOL(jbd2_journal_get_undo_access);
EXPORT_SYMBOL(jbd2_journal_set_triggers);
EXPORT_SYMBOL(jbd2_journal_dirty_metadata);
EXPORT_SYMBOL(jbd2_journal_forget);
#if 0
EXPORT_SYMBOL(journal_sync_buffer);
#endif
EXPORT_SYMBOL(jbd2_journal_flush);
EXPORT_SYMBOL(jbd2_journal_revoke);

EXPORT_SYMBOL(jbd2_journal_init_dev);
EXPORT_SYMBOL(jbd2_journal_init_inode);
EXPORT_SYMBOL(jbd2_journal_check_used_features);
EXPORT_SYMBOL(jbd2_journal_check_available_features);
EXPORT_SYMBOL(jbd2_journal_set_features);
EXPORT_SYMBOL(jbd2_journal_load);
EXPORT_SYMBOL(jbd2_journal_destroy);
EXPORT_SYMBOL(jbd2_journal_abort);
EXPORT_SYMBOL(jbd2_journal_errno);
EXPORT_SYMBOL(jbd2_journal_ack_err);
EXPORT_SYMBOL(jbd2_journal_clear_err);
EXPORT_SYMBOL(jbd2_log_wait_commit);
EXPORT_SYMBOL(jbd2_log_start_commit);
EXPORT_SYMBOL(jbd2_journal_start_commit);
EXPORT_SYMBOL(jbd2_journal_force_commit_nested);
EXPORT_SYMBOL(jbd2_journal_wipe);
EXPORT_SYMBOL(jbd2_journal_blocks_per_page);
EXPORT_SYMBOL(jbd2_journal_invalidatepage);
EXPORT_SYMBOL(jbd2_journal_try_to_free_buffers);
EXPORT_SYMBOL(jbd2_journal_force_commit);
EXPORT_SYMBOL(jbd2_journal_file_inode);
EXPORT_SYMBOL(jbd2_journal_init_jbd_inode);
EXPORT_SYMBOL(jbd2_journal_release_jbd_inode);
EXPORT_SYMBOL(jbd2_journal_begin_ordered_truncate);
EXPORT_SYMBOL(jbd2_inode_cache);

static void __journal_abort_soft (journal_t *journal, int errno);
static int jbd2_journal_create_slab(size_t slab_size);

#ifdef CONFIG_JBD2_DEBUG
void __jbd2_debug(int level, const char *file, const char *func,
		  unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (level > jbd2_journal_enable_debug)
		return;
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_DEBUG "%s: (%s, %u): %pV\n", file, func, line, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(__jbd2_debug);
#endif

/* Checksumming functions */
static int jbd2_verify_csum_type(journal_t *j, journal_superblock_t *sb)
{
	if (!jbd2_journal_has_csum_v2or3(j))
		return 1;

	return sb->s_checksum_type == JBD2_CRC32C_CHKSUM;
}

static __be32 jbd2_superblock_csum(journal_t *j, journal_superblock_t *sb)
{
	__u32 csum;
	__be32 old_csum;

	old_csum = sb->s_checksum;
	sb->s_checksum = 0;
	csum = jbd2_chksum(j, ~0, (char *)sb, sizeof(journal_superblock_t));
	sb->s_checksum = old_csum;

	return cpu_to_be32(csum);
}

static int jbd2_superblock_csum_verify(journal_t *j, journal_superblock_t *sb)
{
	if (!jbd2_journal_has_csum_v2or3(j))
		return 1;

	return sb->s_checksum == jbd2_superblock_csum(j, sb);
}

static void jbd2_superblock_csum_set(journal_t *j, journal_superblock_t *sb)
{
	if (!jbd2_journal_has_csum_v2or3(j))
		return;

	sb->s_checksum = jbd2_superblock_csum(j, sb);
}

/*
 * Helper function used to manage commit timeouts
 */

static void commit_timeout(unsigned long __data)
{
	struct task_struct * p = (struct task_struct *) __data;

	wake_up_process(p);
}

/*
 * kjournald2: The main thread function used to manage a logging device
 * journal.
 *
 * This kernel thread is responsible for two things:
 *
 * 1) COMMIT:  Every so often we need to commit the current state of the
 *    filesystem to disk.  The journal thread is responsible for writing
 *    all of the metadata buffers to disk.
 *
 * 2) CHECKPOINT: We cannot reuse a used section of the log file until all
 *    of the data in that part of the log has been rewritten elsewhere on
 *    the disk.  Flushing these old buffers to reclaim space in the log is
 *    known as checkpointing, and this thread is responsible for that job.
 */

static int kjournald2(void *arg)
{
	journal_t *journal = arg;
	transaction_t *transaction;

	/*
	 * Set up an interval timer which can be used to trigger a commit wakeup
	 * after the commit interval expires
	 */
	setup_timer(&journal->j_commit_timer, commit_timeout,
			(unsigned long)current);

	set_freezable();

	/* Record that the journal thread is running */
	journal->j_task = current;
	wake_up(&journal->j_wait_done_commit);

	/*
	 * And now, wait forever for commit wakeup events.
	 */
	write_lock(&journal->j_state_lock);

loop:
	if (journal->j_flags & JBD2_UNMOUNT)
		goto end_loop;

	jbd_debug(1, "commit_sequence=%d, commit_request=%d\n",
		journal->j_commit_sequence, journal->j_commit_request);

	if (journal->j_commit_sequence != journal->j_commit_request) {
		jbd_debug(1, "OK, requests differ\n");
		write_unlock(&journal->j_state_lock);
		del_timer_sync(&journal->j_commit_timer);
		jbd2_journal_commit_transaction(journal);
		write_lock(&journal->j_state_lock);
		goto loop;
	}

	wake_up(&journal->j_wait_done_commit);
	if (freezing(current)) {
		/*
		 * The simpler the better. Flushing journal isn't a
		 * good idea, because that depends on threads that may
		 * be already stopped.
		 */
		jbd_debug(1, "Now suspending kjournald2\n");
		write_unlock(&journal->j_state_lock);
		try_to_freeze();
		write_lock(&journal->j_state_lock);
	} else {
		/*
		 * We assume on resume that commits are already there,
		 * so we don't sleep
		 */
		DEFINE_WAIT(wait);
		int should_sleep = 1;

		prepare_to_wait(&journal->j_wait_commit, &wait,
				TASK_INTERRUPTIBLE);
		if (journal->j_commit_sequence != journal->j_commit_request)
			should_sleep = 0;
		transaction = journal->j_running_transaction;
		if (transaction && time_after_eq(jiffies,
						transaction->t_expires))
			should_sleep = 0;
		if (journal->j_flags & JBD2_UNMOUNT)
			should_sleep = 0;
		if (should_sleep) {
			write_unlock(&journal->j_state_lock);
			schedule();
			write_lock(&journal->j_state_lock);
		}
		finish_wait(&journal->j_wait_commit, &wait);
	}

	jbd_debug(1, "kjournald2 wakes\n");

	/*
	 * Were we woken up by a commit wakeup event?
	 */
	transaction = journal->j_running_transaction;
	if (transaction && time_after_eq(jiffies, transaction->t_expires)) {
		journal->j_commit_request = transaction->t_tid;
		jbd_debug(1, "woke because of timeout\n");
	}
	goto loop;

end_loop:
	write_unlock(&journal->j_state_lock);
	del_timer_sync(&journal->j_commit_timer);
	journal->j_task = NULL;
	wake_up(&journal->j_wait_done_commit);
	jbd_debug(1, "Journal thread exiting.\n");
	return 0;
}

static int jbd2_journal_start_thread(journal_t *journal)
{
	struct task_struct *t;

	t = kthread_run(kjournald2, journal, "jbd2/%s",
			journal->j_devname);
	if (IS_ERR(t))
		return PTR_ERR(t);

	wait_event(journal->j_wait_done_commit, journal->j_task != NULL);
	return 0;
}

static void journal_kill_thread(journal_t *journal)
{
	write_lock(&journal->j_state_lock);
	journal->j_flags |= JBD2_UNMOUNT;

	while (journal->j_task) {
		write_unlock(&journal->j_state_lock);
		wake_up(&journal->j_wait_commit);
		wait_event(journal->j_wait_done_commit, journal->j_task == NULL);
		write_lock(&journal->j_state_lock);
	}
	write_unlock(&journal->j_state_lock);
}

/*
 * jbd2_journal_write_metadata_buffer: write a metadata buffer to the journal.
 *
 * Writes a metadata buffer to a given disk block.  The actual IO is not
 * performed but a new buffer_head is constructed which labels the data
 * to be written with the correct destination disk block.
 *
 * Any magic-number escaping which needs to be done will cause a
 * copy-out here.  If the buffer happens to start with the
 * JBD2_MAGIC_NUMBER, then we can't write it to the log directly: the
 * magic number is only written to the log for descripter blocks.  In
 * this case, we copy the data and replace the first word with 0, and we
 * return a result code which indicates that this buffer needs to be
 * marked as an escaped buffer in the corresponding log descriptor
 * block.  The missing word can then be restored when the block is read
 * during recovery.
 *
 * If the source buffer has already been modified by a new transaction
 * since we took the last commit snapshot, we use the frozen copy of
 * that data for IO. If we end up using the existing buffer_head's data
 * for the write, then we have to make sure nobody modifies it while the
 * IO is in progress. do_get_write_access() handles this.
 *
 * The function returns a pointer to the buffer_head to be used for IO.
 *
 *
 * Return value:
 *  <0: Error
 * >=0: Finished OK
 *
 * On success:
 * Bit 0 set == escape performed on the data
 * Bit 1 set == buffer copy-out performed (kfree the data after IO)
 */

int jbd2_journal_write_metadata_buffer(transaction_t *transaction,
				  struct journal_head  *jh_in,
				  struct buffer_head **bh_out,
				  sector_t blocknr)
{
	int need_copy_out = 0;
	int done_copy_out = 0;
	int do_escape = 0;
	char *mapped_data;
	struct buffer_head *new_bh;
	struct page *new_page;
	unsigned int new_offset;
	struct buffer_head *bh_in = jh2bh(jh_in);
	journal_t *journal = transaction->t_journal;

	/*
	 * The buffer really shouldn't be locked: only the current committing
	 * transaction is allowed to write it, so nobody else is allowed
	 * to do any IO.
	 *
	 * akpm: except if we're journalling data, and write() output is
	 * also part of a shared mapping, and another thread has
	 * decided to launch a writepage() against this buffer.
	 */
	J_ASSERT_BH(bh_in, buffer_jbddirty(bh_in));

retry_alloc:
	new_bh = alloc_buffer_head(GFP_NOFS);
	if (!new_bh) {
		/*
		 * Failure is not an option, but __GFP_NOFAIL is going
		 * away; so we retry ourselves here.
		 */
		congestion_wait(BLK_RW_ASYNC, HZ/50);
		goto retry_alloc;
	}

	/* keep subsequent assertions sane */
	atomic_set(&new_bh->b_count, 1);

	jbd_lock_bh_state(bh_in);
repeat:
	/*
	 * If a new transaction has already done a buffer copy-out, then
	 * we use that version of the data for the commit.
	 */
	if (jh_in->b_frozen_data) {
		done_copy_out = 1;
		new_page = virt_to_page(jh_in->b_frozen_data);
		new_offset = offset_in_page(jh_in->b_frozen_data);
	} else {
		new_page = jh2bh(jh_in)->b_page;
		new_offset = offset_in_page(jh2bh(jh_in)->b_data);
	}

	mapped_data = kmap_atomic(new_page);
	/*
	 * Fire data frozen trigger if data already wasn't frozen.  Do this
	 * before checking for escaping, as the trigger may modify the magic
	 * offset.  If a copy-out happens afterwards, it will have the correct
	 * data in the buffer.
	 */
	if (!done_copy_out)
		jbd2_buffer_frozen_trigger(jh_in, mapped_data + new_offset,
					   jh_in->b_triggers);

	/*
	 * Check for escaping
	 */
	if (*((__be32 *)(mapped_data + new_offset)) ==
				cpu_to_be32(JBD2_MAGIC_NUMBER)) {
		need_copy_out = 1;
		do_escape = 1;
	}
	kunmap_atomic(mapped_data);

	/*
	 * Do we need to do a data copy?
	 */
	if (need_copy_out && !done_copy_out) {
		char *tmp;

		jbd_unlock_bh_state(bh_in);
		tmp = jbd2_alloc(bh_in->b_size, GFP_NOFS);
		if (!tmp) {
			brelse(new_bh);
			return -ENOMEM;
		}
		jbd_lock_bh_state(bh_in);
		if (jh_in->b_frozen_data) {
			jbd2_free(tmp, bh_in->b_size);
			goto repeat;
		}

		jh_in->b_frozen_data = tmp;
		mapped_data = kmap_atomic(new_page);
		memcpy(tmp, mapped_data + new_offset, bh_in->b_size);
		kunmap_atomic(mapped_data);

		new_page = virt_to_page(tmp);
		new_offset = offset_in_page(tmp);
		done_copy_out = 1;

		/*
		 * This isn't strictly necessary, as we're using frozen
		 * data for the escaping, but it keeps consistency with
		 * b_frozen_data usage.
		 */
		jh_in->b_frozen_triggers = jh_in->b_triggers;
	}

	/*
	 * Did we need to do an escaping?  Now we've done all the
	 * copying, we can finally do so.
	 */
	if (do_escape) {
		mapped_data = kmap_atomic(new_page);
		*((unsigned int *)(mapped_data + new_offset)) = 0;
		kunmap_atomic(mapped_data);
	}

	set_bh_page(new_bh, new_page, new_offset);
	new_bh->b_size = bh_in->b_size;
	new_bh->b_bdev = journal->j_dev;
	new_bh->b_blocknr = blocknr;
	new_bh->b_private = bh_in;
	set_buffer_mapped(new_bh);
	set_buffer_dirty(new_bh);

	*bh_out = new_bh;

	/*
	 * The to-be-written buffer needs to get moved to the io queue,
	 * and the original buffer whose contents we are shadowing or
	 * copying is moved to the transaction's shadow queue.
	 */
	JBUFFER_TRACE(jh_in, "file as BJ_Shadow");
	spin_lock(&journal->j_list_lock);
	__jbd2_journal_file_buffer(jh_in, transaction, BJ_Shadow);
	spin_unlock(&journal->j_list_lock);
	set_buffer_shadow(bh_in);
	jbd_unlock_bh_state(bh_in);

	return do_escape | (done_copy_out << 1);
}

/*
 * Allocation code for the journal file.  Manage the space left in the
 * journal, so that we can begin checkpointing when appropriate.
 */

/*
 * Called with j_state_lock locked for writing.
 * Returns true if a transaction commit was started.
 */
int __jbd2_log_start_commit(journal_t *journal, tid_t target)
{
	/* Return if the txn has already requested to be committed */
	if (journal->j_commit_request == target)
		return 0;

	/*
	 * The only transaction we can possibly wait upon is the
	 * currently running transaction (if it exists).  Otherwise,
	 * the target tid must be an old one.
	 */
	if (journal->j_running_transaction &&
	    journal->j_running_transaction->t_tid == target) {
		/*
		 * We want a new commit: OK, mark the request and wakeup the
		 * commit thread.  We do _not_ do the commit ourselves.
		 */

		journal->j_commit_request = target;
		jbd_debug(1, "JBD2: requesting commit %d/%d\n",
			  journal->j_commit_request,
			  journal->j_commit_sequence);
		journal->j_running_transaction->t_requested = jiffies;
		wake_up(&journal->j_wait_commit);
		return 1;
	} else if (!tid_geq(journal->j_commit_request, target))
		/* This should never happen, but if it does, preserve
		   the evidence before kjournald goes into a loop and
		   increments j_commit_sequence beyond all recognition. */
		WARN_ONCE(1, "JBD2: bad log_start_commit: %u %u %u %u\n",
			  journal->j_commit_request,
			  journal->j_commit_sequence,
			  target, journal->j_running_transaction ?
			  journal->j_running_transaction->t_tid : 0);
	return 0;
}

int jbd2_log_start_commit(journal_t *journal, tid_t tid)
{
	int ret;

	write_lock(&journal->j_state_lock);
	ret = __jbd2_log_start_commit(journal, tid);
	write_unlock(&journal->j_state_lock);
	return ret;
}

/*
 * Force and wait any uncommitted transactions.  We can only force the running
 * transaction if we don't have an active handle, otherwise, we will deadlock.
 * Returns: <0 in case of error,
 *           0 if nothing to commit,
 *           1 if transaction was successfully committed.
 */
static int __jbd2_journal_force_commit(journal_t *journal)
{
	transaction_t *transaction = NULL;
	tid_t tid;
	int need_to_start = 0, ret = 0;

	read_lock(&journal->j_state_lock);
	if (journal->j_running_transaction && !current->journal_info) {
		transaction = journal->j_running_transaction;
		if (!tid_geq(journal->j_commit_request, transaction->t_tid))
			need_to_start = 1;
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	if (!transaction) {
		/* Nothing to commit */
		read_unlock(&journal->j_state_lock);
		return 0;
	}
	tid = transaction->t_tid;
	read_unlock(&journal->j_state_lock);
	if (need_to_start)
		jbd2_log_start_commit(journal, tid);
	ret = jbd2_log_wait_commit(journal, tid);
	if (!ret)
		ret = 1;

	return ret;
}

/**
 * Force and wait upon a commit if the calling process is not within
 * transaction.  This is used for forcing out undo-protected data which contains
 * bitmaps, when the fs is running out of space.
 *
 * @journal: journal to force
 * Returns true if progress was made.
 */
int jbd2_journal_force_commit_nested(journal_t *journal)
{
	int ret;

	ret = __jbd2_journal_force_commit(journal);
	return ret > 0;
}

/**
 * int journal_force_commit() - force any uncommitted transactions
 * @journal: journal to force
 *
 * Caller want unconditional commit. We can only force the running transaction
 * if we don't have an active handle, otherwise, we will deadlock.
 */
int jbd2_journal_force_commit(journal_t *journal)
{
	int ret;

	J_ASSERT(!current->journal_info);
	ret = __jbd2_journal_force_commit(journal);
	if (ret > 0)
		ret = 0;
	return ret;
}

/*
 * Start a commit of the current running transaction (if any).  Returns true
 * if a transaction is going to be committed (or is currently already
 * committing), and fills its tid in at *ptid
 */
int jbd2_journal_start_commit(journal_t *journal, tid_t *ptid)
{
	int ret = 0;

	write_lock(&journal->j_state_lock);
	if (journal->j_running_transaction) {
		tid_t tid = journal->j_running_transaction->t_tid;

		__jbd2_log_start_commit(journal, tid);
		/* There's a running transaction and we've just made sure
		 * it's commit has been scheduled. */
		if (ptid)
			*ptid = tid;
		ret = 1;
	} else if (journal->j_committing_transaction) {
		/*
		 * If commit has been started, then we have to wait for
		 * completion of that transaction.
		 */
		if (ptid)
			*ptid = journal->j_committing_transaction->t_tid;
		ret = 1;
	}
	write_unlock(&journal->j_state_lock);
	return ret;
}

/*
 * Return 1 if a given transaction has not yet sent barrier request
 * connected with a transaction commit. If 0 is returned, transaction
 * may or may not have sent the barrier. Used to avoid sending barrier
 * twice in common cases.
 */
int jbd2_trans_will_send_data_barrier(journal_t *journal, tid_t tid)
{
	int ret = 0;
	transaction_t *commit_trans;

	if (!(journal->j_flags & JBD2_BARRIER))
		return 0;
	read_lock(&journal->j_state_lock);
	/* Transaction already committed? */
	if (tid_geq(journal->j_commit_sequence, tid))
		goto out;
	commit_trans = journal->j_committing_transaction;
	if (!commit_trans || commit_trans->t_tid != tid) {
		ret = 1;
		goto out;
	}
	/*
	 * Transaction is being committed and we already proceeded to
	 * submitting a flush to fs partition?
	 */
	if (journal->j_fs_dev != journal->j_dev) {
		if (!commit_trans->t_need_data_flush ||
		    commit_trans->t_state >= T_COMMIT_DFLUSH)
			goto out;
	} else {
		if (commit_trans->t_state >= T_COMMIT_JFLUSH)
			goto out;
	}
	ret = 1;
out:
	read_unlock(&journal->j_state_lock);
	return ret;
}
EXPORT_SYMBOL(jbd2_trans_will_send_data_barrier);

/*
 * Wait for a specified commit to complete.
 * The caller may not hold the journal lock.
 */
int jbd2_log_wait_commit(journal_t *journal, tid_t tid)
{
	int err = 0;

	read_lock(&journal->j_state_lock);
#ifdef CONFIG_JBD2_DEBUG
	if (!tid_geq(journal->j_commit_request, tid)) {
		printk(KERN_ERR
		       "%s: error: j_commit_request=%d, tid=%d\n",
		       __func__, journal->j_commit_request, tid);
	}
#endif
	while (tid_gt(tid, journal->j_commit_sequence)) {
		jbd_debug(1, "JBD2: want %d, j_commit_sequence=%d\n",
				  tid, journal->j_commit_sequence);
		read_unlock(&journal->j_state_lock);
		wake_up(&journal->j_wait_commit);
		wait_event(journal->j_wait_done_commit,
				!tid_gt(tid, journal->j_commit_sequence));
		read_lock(&journal->j_state_lock);
	}
	read_unlock(&journal->j_state_lock);

	if (unlikely(is_journal_aborted(journal)))
		err = -EIO;
	return err;
}

/*
 * When this function returns the transaction corresponding to tid
 * will be completed.  If the transaction has currently running, start
 * committing that transaction before waiting for it to complete.  If
 * the transaction id is stale, it is by definition already completed,
 * so just return SUCCESS.
 */
int jbd2_complete_transaction(journal_t *journal, tid_t tid)
{
	int	need_to_wait = 1;

	read_lock(&journal->j_state_lock);
	if (journal->j_running_transaction &&
	    journal->j_running_transaction->t_tid == tid) {
		if (journal->j_commit_request != tid) {
			/* transaction not yet started, so request it */
			read_unlock(&journal->j_state_lock);
			jbd2_log_start_commit(journal, tid);
			goto wait_commit;
		}
	} else if (!(journal->j_committing_transaction &&
		     journal->j_committing_transaction->t_tid == tid))
		need_to_wait = 0;
	read_unlock(&journal->j_state_lock);
	if (!need_to_wait)
		return 0;
wait_commit:
	return jbd2_log_wait_commit(journal, tid);
}
EXPORT_SYMBOL(jbd2_complete_transaction);

/*
 * Log buffer allocation routines:
 */

int jbd2_journal_next_log_block(journal_t *journal, unsigned long long *retp)
{
	unsigned long blocknr;

	write_lock(&journal->j_state_lock);
	J_ASSERT(journal->j_free > 1);

	blocknr = journal->j_head;
	journal->j_head++;
	journal->j_free--;
	if (journal->j_head == journal->j_last)
		journal->j_head = journal->j_first;
	write_unlock(&journal->j_state_lock);
	return jbd2_journal_bmap(journal, blocknr, retp);
}

/*
 * Conversion of logical to physical block numbers for the journal
 *
 * On external journals the journal blocks are identity-mapped, so
 * this is a no-op.  If needed, we can use j_blk_offset - everything is
 * ready.
 */
int jbd2_journal_bmap(journal_t *journal, unsigned long blocknr,
		 unsigned long long *retp)
{
	int err = 0;
	unsigned long long ret;

	if (journal->j_inode) {
		ret = bmap(journal->j_inode, blocknr);
		if (ret)
			*retp = ret;
		else {
			printk(KERN_ALERT "%s: journal block not found "
					"at offset %lu on %s\n",
			       __func__, blocknr, journal->j_devname);
			err = -EIO;
			__journal_abort_soft(journal, err);
		}
	} else {
		*retp = blocknr; /* +journal->j_blk_offset */
	}
	return err;
}

/*
 * We play buffer_head aliasing tricks to write data/metadata blocks to
 * the journal without copying their contents, but for journal
 * descriptor blocks we do need to generate bona fide buffers.
 *
 * After the caller of jbd2_journal_get_descriptor_buffer() has finished modifying
 * the buffer's contents they really should run flush_dcache_page(bh->b_page).
 * But we don't bother doing that, so there will be coherency problems with
 * mmaps of blockdevs which hold live JBD-controlled filesystems.
 */
struct buffer_head *jbd2_journal_get_descriptor_buffer(journal_t *journal)
{
	struct buffer_head *bh;
	unsigned long long blocknr;
	int err;

	err = jbd2_journal_next_log_block(journal, &blocknr);

	if (err)
		return NULL;

	bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
	if (!bh)
		return NULL;
	lock_buffer(bh);
	memset(bh->b_data, 0, journal->j_blocksize);
	set_buffer_uptodate(bh);
	unlock_buffer(bh);
	BUFFER_TRACE(bh, "return this buffer");
	return bh;
}

/*
 * Return tid of the oldest transaction in the journal and block in the journal
 * where the transaction starts.
 *
 * If the journal is now empty, return which will be the next transaction ID
 * we will write and where will that transaction start.
 *
 * The return value is 0 if journal tail cannot be pushed any further, 1 if
 * it can.
 */
int jbd2_journal_get_log_tail(journal_t *journal, tid_t *tid,
			      unsigned long *block)
{
	transaction_t *transaction;
	int ret;

	read_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	transaction = journal->j_checkpoint_transactions;
	if (transaction) {
		*tid = transaction->t_tid;
		*block = transaction->t_log_start;
	} else if ((transaction = journal->j_committing_transaction) != NULL) {
		*tid = transaction->t_tid;
		*block = transaction->t_log_start;
	} else if ((transaction = journal->j_running_transaction) != NULL) {
		*tid = transaction->t_tid;
		*block = journal->j_head;
	} else {
		*tid = journal->j_transaction_sequence;
		*block = journal->j_head;
	}
	ret = tid_gt(*tid, journal->j_tail_sequence);
	spin_unlock(&journal->j_list_lock);
	read_unlock(&journal->j_state_lock);

	return ret;
}

/*
 * Update information in journal structure and in on disk journal superblock
 * about log tail. This function does not check whether information passed in
 * really pushes log tail further. It's responsibility of the caller to make
 * sure provided log tail information is valid (e.g. by holding
 * j_checkpoint_mutex all the time between computing log tail and calling this
 * function as is the case with jbd2_cleanup_journal_tail()).
 *
 * Requires j_checkpoint_mutex
 */
void __jbd2_update_log_tail(journal_t *journal, tid_t tid, unsigned long block)
{
	unsigned long freed;

	BUG_ON(!mutex_is_locked(&journal->j_checkpoint_mutex));

	/*
	 * We cannot afford for write to remain in drive's caches since as
	 * soon as we update j_tail, next transaction can start reusing journal
	 * space and if we lose sb update during power failure we'd replay
	 * old transaction with possibly newly overwritten data.
	 */
	jbd2_journal_update_sb_log_tail(journal, tid, block, WRITE_FUA);
	write_lock(&journal->j_state_lock);
	freed = block - journal->j_tail;
	if (block < journal->j_tail)
		freed += journal->j_last - journal->j_first;

	trace_jbd2_update_log_tail(journal, tid, block, freed);
	jbd_debug(1,
		  "Cleaning journal tail from %d to %d (offset %lu), "
		  "freeing %lu\n",
		  journal->j_tail_sequence, tid, block, freed);

	journal->j_free += freed;
	journal->j_tail_sequence = tid;
	journal->j_tail = block;
	write_unlock(&journal->j_state_lock);
}

/*
 * This is a variaon of __jbd2_update_log_tail which checks for validity of
 * provided log tail and locks j_checkpoint_mutex. So it is safe against races
 * with other threads updating log tail.
 */
void jbd2_update_log_tail(journal_t *journal, tid_t tid, unsigned long block)
{
	mutex_lock(&journal->j_checkpoint_mutex);
	if (tid_gt(tid, journal->j_tail_sequence))
		__jbd2_update_log_tail(journal, tid, block);
	mutex_unlock(&journal->j_checkpoint_mutex);
}

struct jbd2_stats_proc_session {
	journal_t *journal;
	struct transaction_stats_s *stats;
	int start;
	int max;
};

static void *jbd2_seq_info_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? NULL : SEQ_START_TOKEN;
}

static void *jbd2_seq_info_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return NULL;
}

static int jbd2_seq_info_show(struct seq_file *seq, void *v)
{
	struct jbd2_stats_proc_session *s = seq->private;

	if (v != SEQ_START_TOKEN)
		return 0;
	seq_printf(seq, "%lu transactions (%lu requested), "
		   "each up to %u blocks\n",
		   s->stats->ts_tid, s->stats->ts_requested,
		   s->journal->j_max_transaction_buffers);
	if (s->stats->ts_tid == 0)
		return 0;
	seq_printf(seq, "average: \n  %ums waiting for transaction\n",
	    jiffies_to_msecs(s->stats->run.rs_wait / s->stats->ts_tid));
	seq_printf(seq, "  %ums request delay\n",
	    (s->stats->ts_requested == 0) ? 0 :
	    jiffies_to_msecs(s->stats->run.rs_request_delay /
			     s->stats->ts_requested));
	seq_printf(seq, "  %ums running transaction\n",
	    jiffies_to_msecs(s->stats->run.rs_running / s->stats->ts_tid));
	seq_printf(seq, "  %ums transaction was being locked\n",
	    jiffies_to_msecs(s->stats->run.rs_locked / s->stats->ts_tid));
	seq_printf(seq, "  %ums flushing data (in ordered mode)\n",
	    jiffies_to_msecs(s->stats->run.rs_flushing / s->stats->ts_tid));
	seq_printf(seq, "  %ums logging transaction\n",
	    jiffies_to_msecs(s->stats->run.rs_logging / s->stats->ts_tid));
	seq_printf(seq, "  %lluus average transaction commit time\n",
		   div_u64(s->journal->j_average_commit_time, 1000));
	seq_printf(seq, "  %lu handles per transaction\n",
	    s->stats->run.rs_handle_count / s->stats->ts_tid);
	seq_printf(seq, "  %lu blocks per transaction\n",
	    s->stats->run.rs_blocks / s->stats->ts_tid);
	seq_printf(seq, "  %lu logged blocks per transaction\n",
	    s->stats->run.rs_blocks_logged / s->stats->ts_tid);
	return 0;
}

static void jbd2_seq_info_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations jbd2_seq_info_ops = {
	.start  = jbd2_seq_info_start,
	.next   = jbd2_seq_info_next,
	.stop   = jbd2_seq_info_stop,
	.show   = jbd2_seq_info_show,
};

static int jbd2_seq_info_open(struct inode *inode, struct file *file)
{
	journal_t *journal = PDE_DATA(inode);
	struct jbd2_stats_proc_session *s;
	int rc, size;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (s == NULL)
		return -ENOMEM;
	size = sizeof(struct transaction_stats_s);
	s->stats = kmalloc(size, GFP_KERNEL);
	if (s->stats == NULL) {
		kfree(s);
		return -ENOMEM;
	}
	spin_lock(&journal->j_history_lock);
	memcpy(s->stats, &journal->j_stats, size);
	s->journal = journal;
	spin_unlock(&journal->j_history_lock);

	rc = seq_open(file, &jbd2_seq_info_ops);
	if (rc == 0) {
		struct seq_file *m = file->private_data;
		m->private = s;
	} else {
		kfree(s->stats);
		kfree(s);
	}
	return rc;

}

static int jbd2_seq_info_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct jbd2_stats_proc_session *s = seq->private;
	kfree(s->stats);
	kfree(s);
	return seq_release(inode, file);
}

static const struct file_operations jbd2_seq_info_fops = {
	.owner		= THIS_MODULE,
	.open           = jbd2_seq_info_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = jbd2_seq_info_release,
};

static struct proc_dir_entry *proc_jbd2_stats;

static void jbd2_stats_proc_init(journal_t *journal)
{
	journal->j_proc_entry = proc_mkdir(journal->j_devname, proc_jbd2_stats);
	if (journal->j_proc_entry) {
		proc_create_data("info", S_IRUGO, journal->j_proc_entry,
				 &jbd2_seq_info_fops, journal);
	}
}

static void jbd2_stats_proc_exit(journal_t *journal)
{
	remove_proc_entry("info", journal->j_proc_entry);
	remove_proc_entry(journal->j_devname, proc_jbd2_stats);
}

/*
 * Management for journal control blocks: functions to create and
 * destroy journal_t structures, and to initialise and read existing
 * journal blocks from disk.  */

/* First: create and setup a journal_t object in memory.  We initialise
 * very few fields yet: that has to wait until we have created the
 * journal structures from from scratch, or loaded them from disk. */

static journal_t * journal_init_common (void)
{
	journal_t *journal;
	int err;

	journal = kzalloc(sizeof(*journal), GFP_KERNEL);
	if (!journal)
		return NULL;

	init_waitqueue_head(&journal->j_wait_transaction_locked);
	init_waitqueue_head(&journal->j_wait_done_commit);
	init_waitqueue_head(&journal->j_wait_commit);
	init_waitqueue_head(&journal->j_wait_updates);
	init_waitqueue_head(&journal->j_wait_reserved);
	mutex_init(&journal->j_barrier);
	mutex_init(&journal->j_checkpoint_mutex);
	spin_lock_init(&journal->j_revoke_lock);
	spin_lock_init(&journal->j_list_lock);
	rwlock_init(&journal->j_state_lock);

	journal->j_commit_interval = (HZ * JBD2_DEFAULT_MAX_COMMIT_AGE);
	journal->j_min_batch_time = 0;
	journal->j_max_batch_time = 15000; /* 15ms */
	atomic_set(&journal->j_reserved_credits, 0);

	/* The journal is marked for error until we succeed with recovery! */
	journal->j_flags = JBD2_ABORT;

	/* Set up a default-sized revoke table for the new mount. */
	err = jbd2_journal_init_revoke(journal, JOURNAL_REVOKE_DEFAULT_HASH);
	if (err) {
		kfree(journal);
		return NULL;
	}

	spin_lock_init(&journal->j_history_lock);

	return journal;
}

/* jbd2_journal_init_dev and jbd2_journal_init_inode:
 *
 * Create a journal structure assigned some fixed set of disk blocks to
 * the journal.  We don't actually touch those disk blocks yet, but we
 * need to set up all of the mapping information to tell the journaling
 * system where the journal blocks are.
 *
 */

/**
 *  journal_t * jbd2_journal_init_dev() - creates and initialises a journal structure
 *  @bdev: Block device on which to create the journal
 *  @fs_dev: Device which hold journalled filesystem for this journal.
 *  @start: Block nr Start of journal.
 *  @len:  Length of the journal in blocks.
 *  @blocksize: blocksize of journalling device
 *
 *  Returns: a newly created journal_t *
 *
 *  jbd2_journal_init_dev creates a journal which maps a fixed contiguous
 *  range of blocks on an arbitrary block device.
 *
 */
journal_t * jbd2_journal_init_dev(struct block_device *bdev,
			struct block_device *fs_dev,
			unsigned long long start, int len, int blocksize)
{
	journal_t *journal = journal_init_common();
	struct buffer_head *bh;
	char *p;
	int n;

	if (!journal)
		return NULL;

	/* journal descriptor can store up to n blocks -bzzz */
	journal->j_blocksize = blocksize;
	journal->j_dev = bdev;
	journal->j_fs_dev = fs_dev;
	journal->j_blk_offset = start;
	journal->j_maxlen = len;
	bdevname(journal->j_dev, journal->j_devname);
	p = journal->j_devname;
	while ((p = strchr(p, '/')))
		*p = '!';
	jbd2_stats_proc_init(journal);
	n = journal->j_blocksize / sizeof(journal_block_tag_t);
	journal->j_wbufsize = n;
	journal->j_wbuf = kmalloc(n * sizeof(struct buffer_head*), GFP_KERNEL);
	if (!journal->j_wbuf) {
		printk(KERN_ERR "%s: Can't allocate bhs for commit thread\n",
			__func__);
		goto out_err;
	}

	bh = __getblk(journal->j_dev, start, journal->j_blocksize);
	if (!bh) {
		printk(KERN_ERR
		       "%s: Cannot get buffer for journal superblock\n",
		       __func__);
		goto out_err;
	}
	journal->j_sb_buffer = bh;
	journal->j_superblock = (journal_superblock_t *)bh->b_data;

	return journal;
out_err:
	kfree(journal->j_wbuf);
	jbd2_stats_proc_exit(journal);
	kfree(journal);
	return NULL;
}

/**
 *  journal_t * jbd2_journal_init_inode () - creates a journal which maps to a inode.
 *  @inode: An inode to create the journal in
 *
 * jbd2_journal_init_inode creates a journal which maps an on-disk inode as
 * the journal.  The inode must exist already, must support bmap() and
 * must have all data blocks preallocated.
 */
journal_t * jbd2_journal_init_inode (struct inode *inode)
{
	struct buffer_head *bh;
	journal_t *journal = journal_init_common();
	char *p;
	int err;
	int n;
	unsigned long long blocknr;

	if (!journal)
		return NULL;

	journal->j_dev = journal->j_fs_dev = inode->i_sb->s_bdev;
	journal->j_inode = inode;
	bdevname(journal->j_dev, journal->j_devname);
	p = journal->j_devname;
	while ((p = strchr(p, '/')))
		*p = '!';
	p = journal->j_devname + strlen(journal->j_devname);
	sprintf(p, "-%lu", journal->j_inode->i_ino);
	jbd_debug(1,
		  "journal %p: inode %s/%ld, size %Ld, bits %d, blksize %ld\n",
		  journal, inode->i_sb->s_id, inode->i_ino,
		  (long long) inode->i_size,
		  inode->i_sb->s_blocksize_bits, inode->i_sb->s_blocksize);

	journal->j_maxlen = inode->i_size >> inode->i_sb->s_blocksize_bits;
	journal->j_blocksize = inode->i_sb->s_blocksize;
	jbd2_stats_proc_init(journal);

	/* journal descriptor can store up to n blocks -bzzz */
	n = journal->j_blocksize / sizeof(journal_block_tag_t);
	journal->j_wbufsize = n;
	journal->j_wbuf = kmalloc(n * sizeof(struct buffer_head*), GFP_KERNEL);
	if (!journal->j_wbuf) {
		printk(KERN_ERR "%s: Can't allocate bhs for commit thread\n",
			__func__);
		goto out_err;
	}

	err = jbd2_journal_bmap(journal, 0, &blocknr);
	/* If that failed, give up */
	if (err) {
		printk(KERN_ERR "%s: Cannot locate journal superblock\n",
		       __func__);
		goto out_err;
	}

	bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
	if (!bh) {
		printk(KERN_ERR
		       "%s: Cannot get buffer for journal superblock\n",
		       __func__);
		goto out_err;
	}
	journal->j_sb_buffer = bh;
	journal->j_superblock = (journal_superblock_t *)bh->b_data;

	return journal;
out_err:
	kfree(journal->j_wbuf);
	jbd2_stats_proc_exit(journal);
	kfree(journal);
	return NULL;
}

/*
 * If the journal init or create aborts, we need to mark the journal
 * superblock as being NULL to prevent the journal destroy from writing
 * back a bogus superblock.
 */
static void journal_fail_superblock (journal_t *journal)
{
	struct buffer_head *bh = journal->j_sb_buffer;
	brelse(bh);
	journal->j_sb_buffer = NULL;
}

/*
 * Given a journal_t structure, initialise the various fields for
 * startup of a new journaling session.  We use this both when creating
 * a journal, and after recovering an old journal to reset it for
 * subsequent use.
 */

static int journal_reset(journal_t *journal)
{
	journal_superblock_t *sb = journal->j_superblock;
	unsigned long long first, last;

	first = be32_to_cpu(sb->s_first);
	last = be32_to_cpu(sb->s_maxlen);
	if (first + JBD2_MIN_JOURNAL_BLOCKS > last + 1) {
		printk(KERN_ERR "JBD2: Journal too short (blocks %llu-%llu).\n",
		       first, last);
		journal_fail_superblock(journal);
		return -EINVAL;
	}

	journal->j_first = first;
	journal->j_last = last;

	journal->j_head = first;
	journal->j_tail = first;
	journal->j_free = last - first;

	journal->j_tail_sequence = journal->j_transaction_sequence;
	journal->j_commit_sequence = journal->j_transaction_sequence - 1;
	journal->j_commit_request = journal->j_commit_sequence;

	journal->j_max_transaction_buffers = journal->j_maxlen / 4;

	/*
	 * As a special case, if the on-disk copy is already marked as needing
	 * no recovery (s_start == 0), then we can safely defer the superblock
	 * update until the next commit by setting JBD2_FLUSHED.  This avoids
	 * attempting a write to a potential-readonly device.
	 */
	if (sb->s_start == 0) {
		jbd_debug(1, "JBD2: Skipping superblock update on recovered sb "
			"(start %ld, seq %d, errno %d)\n",
			journal->j_tail, journal->j_tail_sequence,
			journal->j_errno);
		journal->j_flags |= JBD2_FLUSHED;
	} else {
		/* Lock here to make assertions happy... */
		mutex_lock(&journal->j_checkpoint_mutex);
		/*
		 * Update log tail information. We use WRITE_FUA since new
		 * transaction will start reusing journal space and so we
		 * must make sure information about current log tail is on
		 * disk before that.
		 */
		jbd2_journal_update_sb_log_tail(journal,
						journal->j_tail_sequence,
						journal->j_tail,
						WRITE_FUA);
		mutex_unlock(&journal->j_checkpoint_mutex);
	}
	return jbd2_journal_start_thread(journal);
}

static void jbd2_write_superblock(journal_t *journal, int write_op)
{
	struct buffer_head *bh = journal->j_sb_buffer;
	journal_superblock_t *sb = journal->j_superblock;
	int ret;

	trace_jbd2_write_superblock(journal, write_op);
	if (!(journal->j_flags & JBD2_BARRIER))
		write_op &= ~(REQ_FUA | REQ_FLUSH);
	lock_buffer(bh);
	if (buffer_write_io_error(bh)) {
		/*
		 * Oh, dear.  A previous attempt to write the journal
		 * superblock failed.  This could happen because the
		 * USB device was yanked out.  Or it could happen to
		 * be a transient write error and maybe the block will
		 * be remapped.  Nothing we can do but to retry the
		 * write and hope for the best.
		 */
		printk(KERN_ERR "JBD2: previous I/O error detected "
		       "for journal superblock update for %s.\n",
		       journal->j_devname);
		clear_buffer_write_io_error(bh);
		set_buffer_uptodate(bh);
	}
	jbd2_superblock_csum_set(journal, sb);
	get_bh(bh);
	bh->b_end_io = end_buffer_write_sync;
	ret = submit_bh(write_op, bh);
	wait_on_buffer(bh);
	if (buffer_write_io_error(bh)) {
		clear_buffer_write_io_error(bh);
		set_buffer_uptodate(bh);
		ret = -EIO;
	}
	if (ret) {
		printk(KERN_ERR "JBD2: Error %d detected when updating "
		       "journal superblock for %s.\n", ret,
		       journal->j_devname);
	}
}

/**
 * jbd2_journal_update_sb_log_tail() - Update log tail in journal sb on disk.
 * @journal: The journal to update.
 * @tail_tid: TID of the new transaction at the tail of the log
 * @tail_block: The first block of the transaction at the tail of the log
 * @write_op: With which operation should we write the journal sb
 *
 * Update a journal's superblock information about log tail and write it to
 * disk, waiting for the IO to complete.
 */
void jbd2_journal_update_sb_log_tail(journal_t *journal, tid_t tail_tid,
				     unsigned long tail_block, int write_op)
{
	journal_superblock_t *sb = journal->j_superblock;

	BUG_ON(!mutex_is_locked(&journal->j_checkpoint_mutex));
	jbd_debug(1, "JBD2: updating superblock (start %lu, seq %u)\n",
		  tail_block, tail_tid);

	sb->s_sequence = cpu_to_be32(tail_tid);
	sb->s_start    = cpu_to_be32(tail_block);

	jbd2_write_superblock(journal, write_op);

	/* Log is no longer empty */
	write_lock(&journal->j_state_lock);
	WARN_ON(!sb->s_sequence);
	journal->j_flags &= ~JBD2_FLUSHED;
	write_unlock(&journal->j_state_lock);
}

/**
 * jbd2_mark_journal_empty() - Mark on disk journal as empty.
 * @journal: The journal to update.
 *
 * Update a journal's dynamic superblock fields to show that journal is empty.
 * Write updated superblock to disk waiting for IO to complete.
 */
static void jbd2_mark_journal_empty(journal_t *journal)
{
	journal_superblock_t *sb = journal->j_superblock;

	BUG_ON(!mutex_is_locked(&journal->j_checkpoint_mutex));
	read_lock(&journal->j_state_lock);
	/* Is it already empty? */
	if (sb->s_start == 0) {
		read_unlock(&journal->j_state_lock);
		return;
	}
	jbd_debug(1, "JBD2: Marking journal as empty (seq %d)\n",
		  journal->j_tail_sequence);

	sb->s_sequence = cpu_to_be32(journal->j_tail_sequence);
	sb->s_start    = cpu_to_be32(0);
	read_unlock(&journal->j_state_lock);

	jbd2_write_superblock(journal, WRITE_FUA);

	/* Log is no longer empty */
	write_lock(&journal->j_state_lock);
	journal->j_flags |= JBD2_FLUSHED;
	write_unlock(&journal->j_state_lock);
}


/**
 * jbd2_journal_update_sb_errno() - Update error in the journal.
 * @journal: The journal to update.
 *
 * Update a journal's errno.  Write updated superblock to disk waiting for IO
 * to complete.
 */
void jbd2_journal_update_sb_errno(journal_t *journal)
{
	journal_superblock_t *sb = journal->j_superblock;

	read_lock(&journal->j_state_lock);
	jbd_debug(1, "JBD2: updating superblock error (errno %d)\n",
		  journal->j_errno);
	sb->s_errno    = cpu_to_be32(journal->j_errno);
	read_unlock(&journal->j_state_lock);

	jbd2_write_superblock(journal, WRITE_SYNC);
}
EXPORT_SYMBOL(jbd2_journal_update_sb_errno);

/*
 * Read the superblock for a given journal, performing initial
 * validation of the format.
 */
static int journal_get_superblock(journal_t *journal)
{
	struct buffer_head *bh;
	journal_superblock_t *sb;
	int err = -EIO;

	bh = journal->j_sb_buffer;

	J_ASSERT(bh != NULL);
	if (!buffer_uptodate(bh)) {
		ll_rw_block(READ, 1, &bh);
		wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
			printk(KERN_ERR
				"JBD2: IO error reading journal superblock\n");
			goto out;
		}
	}

	if (buffer_verified(bh))
		return 0;

	sb = journal->j_superblock;

	err = -EINVAL;

	if (sb->s_header.h_magic != cpu_to_be32(JBD2_MAGIC_NUMBER) ||
	    sb->s_blocksize != cpu_to_be32(journal->j_blocksize)) {
		printk(KERN_WARNING "JBD2: no valid journal superblock found\n");
		goto out;
	}

	switch(be32_to_cpu(sb->s_header.h_blocktype)) {
	case JBD2_SUPERBLOCK_V1:
		journal->j_format_version = 1;
		break;
	case JBD2_SUPERBLOCK_V2:
		journal->j_format_version = 2;
		break;
	default:
		printk(KERN_WARNING "JBD2: unrecognised superblock format ID\n");
		goto out;
	}

	if (be32_to_cpu(sb->s_maxlen) < journal->j_maxlen)
		journal->j_maxlen = be32_to_cpu(sb->s_maxlen);
	else if (be32_to_cpu(sb->s_maxlen) > journal->j_maxlen) {
		printk(KERN_WARNING "JBD2: journal file too short\n");
		goto out;
	}

	if (be32_to_cpu(sb->s_first) == 0 ||
	    be32_to_cpu(sb->s_first) >= journal->j_maxlen) {
		printk(KERN_WARNING
			"JBD2: Invalid start block of journal: %u\n",
			be32_to_cpu(sb->s_first));
		goto out;
	}

	if (jbd2_journal_has_csum_v2or3(journal) &&
	    JBD2_HAS_COMPAT_FEATURE(journal, JBD2_FEATURE_COMPAT_CHECKSUM)) {
		/* Can't have checksum v1 and v2 on at the same time! */
		printk(KERN_ERR "JBD2: Can't enable checksumming v1 and v2 "
		       "at the same time!\n");
		goto out;
	}

	if (JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_CSUM_V2) &&
	    JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_CSUM_V3)) {
		/* Can't have checksum v2 and v3 at the same time! */
		printk(KERN_ERR "JBD2: Can't enable checksumming v2 and v3 "
		       "at the same time!\n");
		goto out;
	}

	if (!jbd2_verify_csum_type(journal, sb)) {
		printk(KERN_ERR "JBD2: Unknown checksum type\n");
		goto out;
	}

	/* Load the checksum driver */
	if (jbd2_journal_has_csum_v2or3(journal)) {
		journal->j_chksum_driver = crypto_alloc_shash("crc32c", 0, 0);
		if (IS_ERR(journal->j_chksum_driver)) {
			printk(KERN_ERR "JBD2: Cannot load crc32c driver.\n");
			err = PTR_ERR(journal->j_chksum_driver);
			journal->j_chksum_driver = NULL;
			goto out;
		}
	}

	/* Check superblock checksum */
	if (!jbd2_superblock_csum_verify(journal, sb)) {
		printk(KERN_ERR "JBD2: journal checksum error\n");
		goto out;
	}

	/* Precompute checksum seed for all metadata */
	if (jbd2_journal_has_csum_v2or3(journal))
		journal->j_csum_seed = jbd2_chksum(journal, ~0, sb->s_uuid,
						   sizeof(sb->s_uuid));

	set_buffer_verified(bh);

	return 0;

out:
	journal_fail_superblock(journal);
	return err;
}

/*
 * Load the on-disk journal superblock and read the key fields into the
 * journal_t.
 */

static int load_superblock(journal_t *journal)
{
	int err;
	journal_superblock_t *sb;

	err = journal_get_superblock(journal);
	if (err)
		return err;

	sb = journal->j_superblock;

	journal->j_tail_sequence = be32_to_cpu(sb->s_sequence);
	journal->j_tail = be32_to_cpu(sb->s_start);
	journal->j_first = be32_to_cpu(sb->s_first);
	journal->j_last = be32_to_cpu(sb->s_maxlen);
	journal->j_errno = be32_to_cpu(sb->s_errno);

	return 0;
}


/**
 * int jbd2_journal_load() - Read journal from disk.
 * @journal: Journal to act on.
 *
 * Given a journal_t structure which tells us which disk blocks contain
 * a journal, read the journal from disk to initialise the in-memory
 * structures.
 */
int jbd2_journal_load(journal_t *journal)
{
	int err;
	journal_superblock_t *sb;

	err = load_superblock(journal);
	if (err)
		return err;

	sb = journal->j_superblock;
	/* If this is a V2 superblock, then we have to check the
	 * features flags on it. */

	if (journal->j_format_version >= 2) {
		if ((sb->s_feature_ro_compat &
		     ~cpu_to_be32(JBD2_KNOWN_ROCOMPAT_FEATURES)) ||
		    (sb->s_feature_incompat &
		     ~cpu_to_be32(JBD2_KNOWN_INCOMPAT_FEATURES))) {
			printk(KERN_WARNING
				"JBD2: Unrecognised features on journal\n");
			return -EINVAL;
		}
	}

	/*
	 * Create a slab for this blocksize
	 */
	err = jbd2_journal_create_slab(be32_to_cpu(sb->s_blocksize));
	if (err)
		return err;

	/* Let the recovery code check whether it needs to recover any
	 * data from the journal. */
	if (jbd2_journal_recover(journal))
		goto recovery_error;

	if (journal->j_failed_commit) {
		printk(KERN_ERR "JBD2: journal transaction %u on %s "
		       "is corrupt.\n", journal->j_failed_commit,
		       journal->j_devname);
		return -EIO;
	}

	/* OK, we've finished with the dynamic journal bits:
	 * reinitialise the dynamic contents of the superblock in memory
	 * and reset them on disk. */
	if (journal_reset(journal))
		goto recovery_error;

	journal->j_flags &= ~JBD2_ABORT;
	journal->j_flags |= JBD2_LOADED;
	return 0;

recovery_error:
	printk(KERN_WARNING "JBD2: recovery failed\n");
	return -EIO;
}

/**
 * void jbd2_journal_destroy() - Release a journal_t structure.
 * @journal: Journal to act on.
 *
 * Release a journal_t structure once it is no longer in use by the
 * journaled object.
 * Return <0 if we couldn't clean up the journal.
 */
int jbd2_journal_destroy(journal_t *journal)
{
	int err = 0;

	/* Wait for the commit thread to wake up and die. */
	journal_kill_thread(journal);

	/* Force a final log commit */
	if (journal->j_running_transaction)
		jbd2_journal_commit_transaction(journal);

	/* Force any old transactions to disk */

	/* Totally anal locking here... */
	spin_lock(&journal->j_list_lock);
	while (journal->j_checkpoint_transactions != NULL) {
		spin_unlock(&journal->j_list_lock);
		mutex_lock(&journal->j_checkpoint_mutex);
		jbd2_log_do_checkpoint(journal);
		mutex_unlock(&journal->j_checkpoint_mutex);
		spin_lock(&journal->j_list_lock);
	}

	J_ASSERT(journal->j_running_transaction == NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);
	J_ASSERT(journal->j_checkpoint_transactions == NULL);
	spin_unlock(&journal->j_list_lock);

	if (journal->j_sb_buffer) {
		if (!is_journal_aborted(journal)) {
			mutex_lock(&journal->j_checkpoint_mutex);
			jbd2_mark_journal_empty(journal);
			mutex_unlock(&journal->j_checkpoint_mutex);
		} else
			err = -EIO;
		brelse(journal->j_sb_buffer);
	}

	if (journal->j_proc_entry)
		jbd2_stats_proc_exit(journal);
	if (journal->j_inode)
		iput(journal->j_inode);
	if (journal->j_revoke)
		jbd2_journal_destroy_revoke(journal);
	if (journal->j_chksum_driver)
		crypto_free_shash(journal->j_chksum_driver);
	kfree(journal->j_wbuf);
	kfree(journal);

	return err;
}


/**
 *int jbd2_journal_check_used_features () - Check if features specified are used.
 * @journal: Journal to check.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Check whether the journal uses all of a given set of
 * features.  Return true (non-zero) if it does.
 **/

int jbd2_journal_check_used_features (journal_t *journal, unsigned long compat,
				 unsigned long ro, unsigned long incompat)
{
	journal_superblock_t *sb;

	if (!compat && !ro && !incompat)
		return 1;
	/* Load journal superblock if it is not loaded yet. */
	if (journal->j_format_version == 0 &&
	    journal_get_superblock(journal) != 0)
		return 0;
	if (journal->j_format_version == 1)
		return 0;

	sb = journal->j_superblock;

	if (((be32_to_cpu(sb->s_feature_compat) & compat) == compat) &&
	    ((be32_to_cpu(sb->s_feature_ro_compat) & ro) == ro) &&
	    ((be32_to_cpu(sb->s_feature_incompat) & incompat) == incompat))
		return 1;

	return 0;
}

/**
 * int jbd2_journal_check_available_features() - Check feature set in journalling layer
 * @journal: Journal to check.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Check whether the journaling code supports the use of
 * all of a given set of features on this journal.  Return true
 * (non-zero) if it can. */

int jbd2_journal_check_available_features (journal_t *journal, unsigned long compat,
				      unsigned long ro, unsigned long incompat)
{
	if (!compat && !ro && !incompat)
		return 1;

	/* We can support any known requested features iff the
	 * superblock is in version 2.  Otherwise we fail to support any
	 * extended sb features. */

	if (journal->j_format_version != 2)
		return 0;

	if ((compat   & JBD2_KNOWN_COMPAT_FEATURES) == compat &&
	    (ro       & JBD2_KNOWN_ROCOMPAT_FEATURES) == ro &&
	    (incompat & JBD2_KNOWN_INCOMPAT_FEATURES) == incompat)
		return 1;

	return 0;
}

/**
 * int jbd2_journal_set_features () - Mark a given journal feature in the superblock
 * @journal: Journal to act on.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Mark a given journal feature as present on the
 * superblock.  Returns true if the requested features could be set.
 *
 */

int jbd2_journal_set_features (journal_t *journal, unsigned long compat,
			  unsigned long ro, unsigned long incompat)
{
#define INCOMPAT_FEATURE_ON(f) \
		((incompat & (f)) && !(sb->s_feature_incompat & cpu_to_be32(f)))
#define COMPAT_FEATURE_ON(f) \
		((compat & (f)) && !(sb->s_feature_compat & cpu_to_be32(f)))
	journal_superblock_t *sb;

	if (jbd2_journal_check_used_features(journal, compat, ro, incompat))
		return 1;

	if (!jbd2_journal_check_available_features(journal, compat, ro, incompat))
		return 0;

	/* If enabling v2 checksums, turn on v3 instead */
	if (incompat & JBD2_FEATURE_INCOMPAT_CSUM_V2) {
		incompat &= ~JBD2_FEATURE_INCOMPAT_CSUM_V2;
		incompat |= JBD2_FEATURE_INCOMPAT_CSUM_V3;
	}

	/* Asking for checksumming v3 and v1?  Only give them v3. */
	if (incompat & JBD2_FEATURE_INCOMPAT_CSUM_V3 &&
	    compat & JBD2_FEATURE_COMPAT_CHECKSUM)
		compat &= ~JBD2_FEATURE_COMPAT_CHECKSUM;

	jbd_debug(1, "Setting new features 0x%lx/0x%lx/0x%lx\n",
		  compat, ro, incompat);

	sb = journal->j_superblock;

	/* If enabling v3 checksums, update superblock */
	if (INCOMPAT_FEATURE_ON(JBD2_FEATURE_INCOMPAT_CSUM_V3)) {
		sb->s_checksum_type = JBD2_CRC32C_CHKSUM;
		sb->s_feature_compat &=
			~cpu_to_be32(JBD2_FEATURE_COMPAT_CHECKSUM);

		/* Load the checksum driver */
		if (journal->j_chksum_driver == NULL) {
			journal->j_chksum_driver = crypto_alloc_shash("crc32c",
								      0, 0);
			if (IS_ERR(journal->j_chksum_driver)) {
				printk(KERN_ERR "JBD2: Cannot load crc32c "
				       "driver.\n");
				journal->j_chksum_driver = NULL;
				return 0;
			}
		}

		/* Precompute checksum seed for all metadata */
		if (jbd2_journal_has_csum_v2or3(journal))
			journal->j_csum_seed = jbd2_chksum(journal, ~0,
							   sb->s_uuid,
							   sizeof(sb->s_uuid));
	}

	/* If enabling v1 checksums, downgrade superblock */
	if (COMPAT_FEATURE_ON(JBD2_FEATURE_COMPAT_CHECKSUM))
		sb->s_feature_incompat &=
			~cpu_to_be32(JBD2_FEATURE_INCOMPAT_CSUM_V2 |
				     JBD2_FEATURE_INCOMPAT_CSUM_V3);

	sb->s_feature_compat    |= cpu_to_be32(compat);
	sb->s_feature_ro_compat |= cpu_to_be32(ro);
	sb->s_feature_incompat  |= cpu_to_be32(incompat);

	return 1;
#undef COMPAT_FEATURE_ON
#undef INCOMPAT_FEATURE_ON
}

/*
 * jbd2_journal_clear_features () - Clear a given journal feature in the
 * 				    superblock
 * @journal: Journal to act on.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Clear a given journal feature as present on the
 * superblock.
 */
void jbd2_journal_clear_features(journal_t *journal, unsigned long compat,
				unsigned long ro, unsigned long incompat)
{
	journal_superblock_t *sb;

	jbd_debug(1, "Clear features 0x%lx/0x%lx/0x%lx\n",
		  compat, ro, incompat);

	sb = journal->j_superblock;

	sb->s_feature_compat    &= ~cpu_to_be32(compat);
	sb->s_feature_ro_compat &= ~cpu_to_be32(ro);
	sb->s_feature_incompat  &= ~cpu_to_be32(incompat);
}
EXPORT_SYMBOL(jbd2_journal_clear_features);

/**
 * int jbd2_journal_flush () - Flush journal
 * @journal: Journal to act on.
 *
 * Flush all data for a given journal to disk and empty the journal.
 * Filesystems can use this when remounting readonly to ensure that
 * recovery does not need to happen on remount.
 */

int jbd2_journal_flush(journal_t *journal)
{
	int err = 0;
	transaction_t *transaction = NULL;

	write_lock(&journal->j_state_lock);

	/* Force everything buffered to the log... */
	if (journal->j_running_transaction) {
		transaction = journal->j_running_transaction;
		__jbd2_log_start_commit(journal, transaction->t_tid);
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	/* Wait for the log commit to complete... */
	if (transaction) {
		tid_t tid = transaction->t_tid;

		write_unlock(&journal->j_state_lock);
		jbd2_log_wait_commit(journal, tid);
	} else {
		write_unlock(&journal->j_state_lock);
	}

	/* ...and flush everything in the log out to disk. */
	spin_lock(&journal->j_list_lock);
	while (!err && journal->j_checkpoint_transactions != NULL) {
		spin_unlock(&journal->j_list_lock);
		mutex_lock(&journal->j_checkpoint_mutex);
		err = jbd2_log_do_checkpoint(journal);
		mutex_unlock(&journal->j_checkpoint_mutex);
		spin_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);

	if (is_journal_aborted(journal))
		return -EIO;

	mutex_lock(&journal->j_checkpoint_mutex);
	jbd2_cleanup_journal_tail(journal);

	/* Finally, mark the journal as really needing no recovery.
	 * This sets s_start==0 in the underlying superblock, which is
	 * the magic code for a fully-recovered superblock.  Any future
	 * commits of data to the journal will restore the current
	 * s_start value. */
	jbd2_mark_journal_empty(journal);
	mutex_unlock(&journal->j_checkpoint_mutex);
	write_lock(&journal->j_state_lock);
	J_ASSERT(!journal->j_running_transaction);
	J_ASSERT(!journal->j_committing_transaction);
	J_ASSERT(!journal->j_checkpoint_transactions);
	J_ASSERT(journal->j_head == journal->j_tail);
	J_ASSERT(journal->j_tail_sequence == journal->j_transaction_sequence);
	write_unlock(&journal->j_state_lock);
	return 0;
}

/**
 * int jbd2_journal_wipe() - Wipe journal contents
 * @journal: Journal to act on.
 * @write: flag (see below)
 *
 * Wipe out all of the contents of a journal, safely.  This will produce
 * a warning if the journal contains any valid recovery information.
 * Must be called between journal_init_*() and jbd2_journal_load().
 *
 * If 'write' is non-zero, then we wipe out the journal on disk; otherwise
 * we merely suppress recovery.
 */

int jbd2_journal_wipe(journal_t *journal, int write)
{
	int err = 0;

	J_ASSERT (!(journal->j_flags & JBD2_LOADED));

	err = load_superblock(journal);
	if (err)
		return err;

	if (!journal->j_tail)
		goto no_recovery;

	printk(KERN_WARNING "JBD2: %s recovery information on journal\n",
		write ? "Clearing" : "Ignoring");

	err = jbd2_journal_skip_recovery(journal);
	if (write) {
		/* Lock to make assertions happy... */
		mutex_lock(&journal->j_checkpoint_mutex);
		jbd2_mark_journal_empty(journal);
		mutex_unlock(&journal->j_checkpoint_mutex);
	}

 no_recovery:
	return err;
}

/*
 * Journal abort has very specific semantics, which we describe
 * for journal abort.
 *
 * Two internal functions, which provide abort to the jbd layer
 * itself are here.
 */

/*
 * Quick version for internal journal use (doesn't lock the journal).
 * Aborts hard --- we mark the abort as occurred, but do _nothing_ else,
 * and don't attempt to make any other journal updates.
 */
void __jbd2_journal_abort_hard(journal_t *journal)
{
	transaction_t *transaction;

	if (journal->j_flags & JBD2_ABORT)
		return;

	printk(KERN_ERR "Aborting journal on device %s.\n",
	       journal->j_devname);

	write_lock(&journal->j_state_lock);
	journal->j_flags |= JBD2_ABORT;
	transaction = journal->j_running_transaction;
	if (transaction)
		__jbd2_log_start_commit(journal, transaction->t_tid);
	write_unlock(&journal->j_state_lock);
}

/* Soft abort: record the abort error status in the journal superblock,
 * but don't do any other IO. */
static void __journal_abort_soft (journal_t *journal, int errno)
{
	if (journal->j_flags & JBD2_ABORT)
		return;

	if (!journal->j_errno)
		journal->j_errno = errno;

	__jbd2_journal_abort_hard(journal);

	if (errno)
		jbd2_journal_update_sb_errno(journal);
}

/**
 * void jbd2_journal_abort () - Shutdown the journal immediately.
 * @journal: the journal to shutdown.
 * @errno:   an error number to record in the journal indicating
 *           the reason for the shutdown.
 *
 * Perform a complete, immediate shutdown of the ENTIRE
 * journal (not of a single transaction).  This operation cannot be
 * undone without closing and reopening the journal.
 *
 * The jbd2_journal_abort function is intended to support higher level error
 * recovery mechanisms such as the ext2/ext3 remount-readonly error
 * mode.
 *
 * Journal abort has very specific semantics.  Any existing dirty,
 * unjournaled buffers in the main filesystem will still be written to
 * disk by bdflush, but the journaling mechanism will be suspended
 * immediately and no further transaction commits will be honoured.
 *
 * Any dirty, journaled buffers will be written back to disk without
 * hitting the journal.  Atomicity cannot be guaranteed on an aborted
 * filesystem, but we _do_ attempt to leave as much data as possible
 * behind for fsck to use for cleanup.
 *
 * Any attempt to get a new transaction handle on a journal which is in
 * ABORT state will just result in an -EROFS error return.  A
 * jbd2_journal_stop on an existing handle will return -EIO if we have
 * entered abort state during the update.
 *
 * Recursive transactions are not disturbed by journal abort until the
 * final jbd2_journal_stop, which will receive the -EIO error.
 *
 * Finally, the jbd2_journal_abort call allows the caller to supply an errno
 * which will be recorded (if possible) in the journal superblock.  This
 * allows a client to record failure conditions in the middle of a
 * transaction without having to complete the transaction to record the
 * failure to disk.  ext3_error, for example, now uses this
 * functionality.
 *
 * Errors which originate from within the journaling layer will NOT
 * supply an errno; a null errno implies that absolutely no further
 * writes are done to the journal (unless there are any already in
 * progress).
 *
 */

void jbd2_journal_abort(journal_t *journal, int errno)
{
	__journal_abort_soft(journal, errno);
}

/**
 * int jbd2_journal_errno () - returns the journal's error state.
 * @journal: journal to examine.
 *
 * This is the errno number set with jbd2_journal_abort(), the last
 * time the journal was mounted - if the journal was stopped
 * without calling abort this will be 0.
 *
 * If the journal has been aborted on this mount time -EROFS will
 * be returned.
 */
int jbd2_journal_errno(journal_t *journal)
{
	int err;

	read_lock(&journal->j_state_lock);
	if (journal->j_flags & JBD2_ABORT)
		err = -EROFS;
	else
		err = journal->j_errno;
	read_unlock(&journal->j_state_lock);
	return err;
}

/**
 * int jbd2_journal_clear_err () - clears the journal's error state
 * @journal: journal to act on.
 *
 * An error must be cleared or acked to take a FS out of readonly
 * mode.
 */
int jbd2_journal_clear_err(journal_t *journal)
{
	int err = 0;

	write_lock(&journal->j_state_lock);
	if (journal->j_flags & JBD2_ABORT)
		err = -EROFS;
	else
		journal->j_errno = 0;
	write_unlock(&journal->j_state_lock);
	return err;
}

/**
 * void jbd2_journal_ack_err() - Ack journal err.
 * @journal: journal to act on.
 *
 * An error must be cleared or acked to take a FS out of readonly
 * mode.
 */
void jbd2_journal_ack_err(journal_t *journal)
{
	write_lock(&journal->j_state_lock);
	if (journal->j_errno)
		journal->j_flags |= JBD2_ACK_ERR;
	write_unlock(&journal->j_state_lock);
}

int jbd2_journal_blocks_per_page(struct inode *inode)
{
	return 1 << (PAGE_CACHE_SHIFT - inode->i_sb->s_blocksize_bits);
}

/*
 * helper functions to deal with 32 or 64bit block numbers.
 */
size_t journal_tag_bytes(journal_t *journal)
{
	size_t sz;

	if (JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_CSUM_V3))
		return sizeof(journal_block_tag3_t);

	sz = sizeof(journal_block_tag_t);

	if (JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_CSUM_V2))
		sz += sizeof(__u16);

	if (JBD2_HAS_INCOMPAT_FEATURE(journal, JBD2_FEATURE_INCOMPAT_64BIT))
		return sz;
	else
		return sz - sizeof(__u32);
}

/*
 * JBD memory management
 *
 * These functions are used to allocate block-sized chunks of memory
 * used for making copies of buffer_head data.  Very often it will be
 * page-sized chunks of data, but sometimes it will be in
 * sub-page-size chunks.  (For example, 16k pages on Power systems
 * with a 4k block file system.)  For blocks smaller than a page, we
 * use a SLAB allocator.  There are slab caches for each block size,
 * which are allocated at mount time, if necessary, and we only free
 * (all of) the slab caches when/if the jbd2 module is unloaded.  For
 * this reason we don't need to a mutex to protect access to
 * jbd2_slab[] allocating or releasing memory; only in
 * jbd2_journal_create_slab().
 */
#define JBD2_MAX_SLABS 8
static struct kmem_cache *jbd2_slab[JBD2_MAX_SLABS];

static const char *jbd2_slab_names[JBD2_MAX_SLABS] = {
	"jbd2_1k", "jbd2_2k", "jbd2_4k", "jbd2_8k",
	"jbd2_16k", "jbd2_32k", "jbd2_64k", "jbd2_128k"
};


static void jbd2_journal_destroy_slabs(void)
{
	int i;

	for (i = 0; i < JBD2_MAX_SLABS; i++) {
		if (jbd2_slab[i])
			kmem_cache_destroy(jbd2_slab[i]);
		jbd2_slab[i] = NULL;
	}
}

static int jbd2_journal_create_slab(size_t size)
{
	static DEFINE_MUTEX(jbd2_slab_create_mutex);
	int i = order_base_2(size) - 10;
	size_t slab_size;

	if (size == PAGE_SIZE)
		return 0;

	if (i >= JBD2_MAX_SLABS)
		return -EINVAL;

	if (unlikely(i < 0))
		i = 0;
	mutex_lock(&jbd2_slab_create_mutex);
	if (jbd2_slab[i]) {
		mutex_unlock(&jbd2_slab_create_mutex);
		return 0;	/* Already created */
	}

	slab_size = 1 << (i+10);
	jbd2_slab[i] = kmem_cache_create(jbd2_slab_names[i], slab_size,
					 slab_size, 0, NULL);
	mutex_unlock(&jbd2_slab_create_mutex);
	if (!jbd2_slab[i]) {
		printk(KERN_EMERG "JBD2: no memory for jbd2_slab cache\n");
		return -ENOMEM;
	}
	return 0;
}

static struct kmem_cache *get_slab(size_t size)
{
	int i = order_base_2(size) - 10;

	BUG_ON(i >= JBD2_MAX_SLABS);
	if (unlikely(i < 0))
		i = 0;
	BUG_ON(jbd2_slab[i] == NULL);
	return jbd2_slab[i];
}

void *jbd2_alloc(size_t size, gfp_t flags)
{
	void *ptr;

	BUG_ON(size & (size-1)); /* Must be a power of 2 */

	flags |= __GFP_REPEAT;
	if (size == PAGE_SIZE)
		ptr = (void *)__get_free_pages(flags, 0);
	else if (size > PAGE_SIZE) {
		int order = get_order(size);

		if (order < 3)
			ptr = (void *)__get_free_pages(flags, order);
		else
			ptr = vmalloc(size);
	} else
		ptr = kmem_cache_alloc(get_slab(size), flags);

	/* Check alignment; SLUB has gotten this wrong in the past,
	 * and this can lead to user data corruption! */
	BUG_ON(((unsigned long) ptr) & (size-1));

	return ptr;
}

void jbd2_free(void *ptr, size_t size)
{
	if (size == PAGE_SIZE) {
		free_pages((unsigned long)ptr, 0);
		return;
	}
	if (size > PAGE_SIZE) {
		int order = get_order(size);

		if (order < 3)
			free_pages((unsigned long)ptr, order);
		else
			vfree(ptr);
		return;
	}
	kmem_cache_free(get_slab(size), ptr);
};

/*
 * Journal_head storage management
 */
static struct kmem_cache *jbd2_journal_head_cache;
#ifdef CONFIG_JBD2_DEBUG
static atomic_t nr_journal_heads = ATOMIC_INIT(0);
#endif

static int jbd2_journal_init_journal_head_cache(void)
{
	int retval;

	J_ASSERT(jbd2_journal_head_cache == NULL);
	jbd2_journal_head_cache = kmem_cache_create("jbd2_journal_head",
				sizeof(struct journal_head),
				0,		/* offset */
				SLAB_TEMPORARY,	/* flags */
				NULL);		/* ctor */
	retval = 0;
	if (!jbd2_journal_head_cache) {
		retval = -ENOMEM;
		printk(KERN_EMERG "JBD2: no memory for journal_head cache\n");
	}
	return retval;
}

static void jbd2_journal_destroy_journal_head_cache(void)
{
	if (jbd2_journal_head_cache) {
		kmem_cache_destroy(jbd2_journal_head_cache);
		jbd2_journal_head_cache = NULL;
	}
}

/*
 * journal_head splicing and dicing
 */
static struct journal_head *journal_alloc_journal_head(void)
{
	struct journal_head *ret;

#ifdef CONFIG_JBD2_DEBUG
	atomic_inc(&nr_journal_heads);
#endif
	ret = kmem_cache_zalloc(jbd2_journal_head_cache, GFP_NOFS);
	if (!ret) {
		jbd_debug(1, "out of memory for journal_head\n");
		pr_notice_ratelimited("ENOMEM in %s, retrying.\n", __func__);
		while (!ret) {
			yield();
			ret = kmem_cache_zalloc(jbd2_journal_head_cache, GFP_NOFS);
		}
	}
	return ret;
}

static void journal_free_journal_head(struct journal_head *jh)
{
#ifdef CONFIG_JBD2_DEBUG
	atomic_dec(&nr_journal_heads);
	memset(jh, JBD2_POISON_FREE, sizeof(*jh));
#endif
	kmem_cache_free(jbd2_journal_head_cache, jh);
}

/*
 * A journal_head is attached to a buffer_head whenever JBD has an
 * interest in the buffer.
 *
 * Whenever a buffer has an attached journal_head, its ->b_state:BH_JBD bit
 * is set.  This bit is tested in core kernel code where we need to take
 * JBD-specific actions.  Testing the zeroness of ->b_private is not reliable
 * there.
 *
 * When a buffer has its BH_JBD bit set, its ->b_count is elevated by one.
 *
 * When a buffer has its BH_JBD bit set it is immune from being released by
 * core kernel code, mainly via ->b_count.
 *
 * A journal_head is detached from its buffer_head when the journal_head's
 * b_jcount reaches zero. Running transaction (b_transaction) and checkpoint
 * transaction (b_cp_transaction) hold their references to b_jcount.
 *
 * Various places in the kernel want to attach a journal_head to a buffer_head
 * _before_ attaching the journal_head to a transaction.  To protect the
 * journal_head in this situation, jbd2_journal_add_journal_head elevates the
 * journal_head's b_jcount refcount by one.  The caller must call
 * jbd2_journal_put_journal_head() to undo this.
 *
 * So the typical usage would be:
 *
 *	(Attach a journal_head if needed.  Increments b_jcount)
 *	struct journal_head *jh = jbd2_journal_add_journal_head(bh);
 *	...
 *      (Get another reference for transaction)
 *	jbd2_journal_grab_journal_head(bh);
 *	jh->b_transaction = xxx;
 *	(Put original reference)
 *	jbd2_journal_put_journal_head(jh);
 */

/*
 * Give a buffer_head a journal_head.
 *
 * May sleep.
 */
struct journal_head *jbd2_journal_add_journal_head(struct buffer_head *bh)
{
	struct journal_head *jh;
	struct journal_head *new_jh = NULL;

repeat:
	if (!buffer_jbd(bh))
		new_jh = journal_alloc_journal_head();

	jbd_lock_bh_journal_head(bh);
	if (buffer_jbd(bh)) {
		jh = bh2jh(bh);
	} else {
		J_ASSERT_BH(bh,
			(atomic_read(&bh->b_count) > 0) ||
			(bh->b_page && bh->b_page->mapping));

		if (!new_jh) {
			jbd_unlock_bh_journal_head(bh);
			goto repeat;
		}

		jh = new_jh;
		new_jh = NULL;		/* We consumed it */
		set_buffer_jbd(bh);
		bh->b_private = jh;
		jh->b_bh = bh;
		get_bh(bh);
		BUFFER_TRACE(bh, "added journal_head");
	}
	jh->b_jcount++;
	jbd_unlock_bh_journal_head(bh);
	if (new_jh)
		journal_free_journal_head(new_jh);
	return bh->b_private;
}

/*
 * Grab a ref against this buffer_head's journal_head.  If it ended up not
 * having a journal_head, return NULL
 */
struct journal_head *jbd2_journal_grab_journal_head(struct buffer_head *bh)
{
	struct journal_head *jh = NULL;

	jbd_lock_bh_journal_head(bh);
	if (buffer_jbd(bh)) {
		jh = bh2jh(bh);
		jh->b_jcount++;
	}
	jbd_unlock_bh_journal_head(bh);
	return jh;
}

static void __journal_remove_journal_head(struct buffer_head *bh)
{
	struct journal_head *jh = bh2jh(bh);

	J_ASSERT_JH(jh, jh->b_jcount >= 0);
	J_ASSERT_JH(jh, jh->b_transaction == NULL);
	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, jh->b_cp_transaction == NULL);
	J_ASSERT_JH(jh, jh->b_jlist == BJ_None);
	J_ASSERT_BH(bh, buffer_jbd(bh));
	J_ASSERT_BH(bh, jh2bh(jh) == bh);
	BUFFER_TRACE(bh, "remove journal_head");
	if (jh->b_frozen_data) {
		printk(KERN_WARNING "%s: freeing b_frozen_data\n", __func__);
		jbd2_free(jh->b_frozen_data, bh->b_size);
	}
	if (jh->b_committed_data) {
		printk(KERN_WARNING "%s: freeing b_committed_data\n", __func__);
		jbd2_free(jh->b_committed_data, bh->b_size);
	}
	bh->b_private = NULL;
	jh->b_bh = NULL;	/* debug, really */
	clear_buffer_jbd(bh);
	journal_free_journal_head(jh);
}

/*
 * Drop a reference on the passed journal_head.  If it fell to zero then
 * release the journal_head from the buffer_head.
 */
void jbd2_journal_put_journal_head(struct journal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	jbd_lock_bh_journal_head(bh);
	J_ASSERT_JH(jh, jh->b_jcount > 0);
	--jh->b_jcount;
	if (!jh->b_jcount) {
		__journal_remove_journal_head(bh);
		jbd_unlock_bh_journal_head(bh);
		__brelse(bh);
	} else
		jbd_unlock_bh_journal_head(bh);
}

/*
 * Initialize jbd inode head
 */
void jbd2_journal_init_jbd_inode(struct jbd2_inode *jinode, struct inode *inode)
{
	jinode->i_transaction = NULL;
	jinode->i_next_transaction = NULL;
	jinode->i_vfs_inode = inode;
	jinode->i_flags = 0;
	INIT_LIST_HEAD(&jinode->i_list);
}

/*
 * Function to be called before we start removing inode from memory (i.e.,
 * clear_inode() is a fine place to be called from). It removes inode from
 * transaction's lists.
 */
void jbd2_journal_release_jbd_inode(journal_t *journal,
				    struct jbd2_inode *jinode)
{
	if (!journal)
		return;
restart:
	spin_lock(&journal->j_list_lock);
	/* Is commit writing out inode - we have to wait */
	if (test_bit(__JI_COMMIT_RUNNING, &jinode->i_flags)) {
		wait_queue_head_t *wq;
		DEFINE_WAIT_BIT(wait, &jinode->i_flags, __JI_COMMIT_RUNNING);
		wq = bit_waitqueue(&jinode->i_flags, __JI_COMMIT_RUNNING);
		prepare_to_wait(wq, &wait.wait, TASK_UNINTERRUPTIBLE);
		spin_unlock(&journal->j_list_lock);
		schedule();
		finish_wait(wq, &wait.wait);
		goto restart;
	}

	if (jinode->i_transaction) {
		list_del(&jinode->i_list);
		jinode->i_transaction = NULL;
	}
	spin_unlock(&journal->j_list_lock);
}


#ifdef CONFIG_PROC_FS

#define JBD2_STATS_PROC_NAME "fs/jbd2"

static void __init jbd2_create_jbd_stats_proc_entry(void)
{
	proc_jbd2_stats = proc_mkdir(JBD2_STATS_PROC_NAME, NULL);
}

static void __exit jbd2_remove_jbd_stats_proc_entry(void)
{
	if (proc_jbd2_stats)
		remove_proc_entry(JBD2_STATS_PROC_NAME, NULL);
}

#else

#define jbd2_create_jbd_stats_proc_entry() do {} while (0)
#define jbd2_remove_jbd_stats_proc_entry() do {} while (0)

#endif

struct kmem_cache *jbd2_handle_cache, *jbd2_inode_cache;

static int __init jbd2_journal_init_handle_cache(void)
{
	jbd2_handle_cache = KMEM_CACHE(jbd2_journal_handle, SLAB_TEMPORARY);
	if (jbd2_handle_cache == NULL) {
		printk(KERN_EMERG "JBD2: failed to create handle cache\n");
		return -ENOMEM;
	}
	jbd2_inode_cache = KMEM_CACHE(jbd2_inode, 0);
	if (jbd2_inode_cache == NULL) {
		printk(KERN_EMERG "JBD2: failed to create inode cache\n");
		kmem_cache_destroy(jbd2_handle_cache);
		return -ENOMEM;
	}
	return 0;
}

static void jbd2_journal_destroy_handle_cache(void)
{
	if (jbd2_handle_cache)
		kmem_cache_destroy(jbd2_handle_cache);
	if (jbd2_inode_cache)
		kmem_cache_destroy(jbd2_inode_cache);

}

/*
 * Module startup and shutdown
 */

static int __init journal_init_caches(void)
{
	int ret;

	ret = jbd2_journal_init_revoke_caches();
	if (ret == 0)
		ret = jbd2_journal_init_journal_head_cache();
	if (ret == 0)
		ret = jbd2_journal_init_handle_cache();
	if (ret == 0)
		ret = jbd2_journal_init_transaction_cache();
	return ret;
}

static void jbd2_journal_destroy_caches(void)
{
	jbd2_journal_destroy_revoke_caches();
	jbd2_journal_destroy_journal_head_cache();
	jbd2_journal_destroy_handle_cache();
	jbd2_journal_destroy_transaction_cache();
	jbd2_journal_destroy_slabs();
}

static int __init journal_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct journal_superblock_s) != 1024);

	ret = journal_init_caches();
	if (ret == 0) {
		jbd2_create_jbd_stats_proc_entry();
	} else {
		jbd2_journal_destroy_caches();
	}
	return ret;
}

static void __exit journal_exit(void)
{
#ifdef CONFIG_JBD2_DEBUG
	int n = atomic_read(&nr_journal_heads);
	if (n)
		printk(KERN_ERR "JBD2: leaked %d journal_heads!\n", n);
#endif
	jbd2_remove_jbd_stats_proc_entry();
	jbd2_journal_destroy_caches();
}

MODULE_LICENSE("GPL");
module_init(journal_init);
module_exit(journal_exit);
/************************************************************/
/* ../linux-3.17/fs/jbd2/journal.c */
/************************************************************/
