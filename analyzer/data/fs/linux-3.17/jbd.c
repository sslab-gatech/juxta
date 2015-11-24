/*
 * linux/fs/jbd/transaction.c
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
#include <linux/jbd.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>

static void __journal_temp_unlink_buffer(struct journal_head *jh);

/*
 * get_transaction: obtain a new transaction_t object.
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
 * Called under j_state_lock
 */

static transaction_t *
get_transaction(journal_t *journal, transaction_t *transaction)
{
	transaction->t_journal = journal;
	transaction->t_state = T_RUNNING;
	transaction->t_start_time = ktime_get();
	transaction->t_tid = journal->j_transaction_sequence++;
	transaction->t_expires = jiffies + journal->j_commit_interval;
	spin_lock_init(&transaction->t_handle_lock);

	/* Set up the commit timer for the new transaction. */
	journal->j_commit_timer.expires =
				round_jiffies_up(transaction->t_expires);
	add_timer(&journal->j_commit_timer);

	J_ASSERT(journal->j_running_transaction == NULL);
	journal->j_running_transaction = transaction;

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
 * start_this_handle: Given a handle, deal with any locking or stalling
 * needed to make sure that there is enough journal space for the handle
 * to begin.  Attach the handle to a transaction and set up the
 * transaction's buffer credits.
 */

static int start_this_handle(journal_t *journal, handle_t *handle)
{
	transaction_t *transaction;
	int needed;
	int nblocks = handle->h_buffer_credits;
	transaction_t *new_transaction = NULL;
	int ret = 0;

	if (nblocks > journal->j_max_transaction_buffers) {
		printk(KERN_ERR "JBD: %s wants too many credits (%d > %d)\n",
		       current->comm, nblocks,
		       journal->j_max_transaction_buffers);
		ret = -ENOSPC;
		goto out;
	}

alloc_transaction:
	if (!journal->j_running_transaction) {
		new_transaction = kzalloc(sizeof(*new_transaction),
						GFP_NOFS|__GFP_NOFAIL);
		if (!new_transaction) {
			ret = -ENOMEM;
			goto out;
		}
	}

	jbd_debug(3, "New handle %p going live.\n", handle);

repeat:

	/*
	 * We need to hold j_state_lock until t_updates has been incremented,
	 * for proper journal barrier handling
	 */
	spin_lock(&journal->j_state_lock);
repeat_locked:
	if (is_journal_aborted(journal) ||
	    (journal->j_errno != 0 && !(journal->j_flags & JFS_ACK_ERR))) {
		spin_unlock(&journal->j_state_lock);
		ret = -EROFS;
		goto out;
	}

	/* Wait on the journal's transaction barrier if necessary */
	if (journal->j_barrier_count) {
		spin_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_transaction_locked,
				journal->j_barrier_count == 0);
		goto repeat;
	}

	if (!journal->j_running_transaction) {
		if (!new_transaction) {
			spin_unlock(&journal->j_state_lock);
			goto alloc_transaction;
		}
		get_transaction(journal, new_transaction);
		new_transaction = NULL;
	}

	transaction = journal->j_running_transaction;

	/*
	 * If the current transaction is locked down for commit, wait for the
	 * lock to be released.
	 */
	if (transaction->t_state == T_LOCKED) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_transaction_locked,
					&wait, TASK_UNINTERRUPTIBLE);
		spin_unlock(&journal->j_state_lock);
		schedule();
		finish_wait(&journal->j_wait_transaction_locked, &wait);
		goto repeat;
	}

	/*
	 * If there is not enough space left in the log to write all potential
	 * buffers requested by this operation, we need to stall pending a log
	 * checkpoint to free some more log space.
	 */
	spin_lock(&transaction->t_handle_lock);
	needed = transaction->t_outstanding_credits + nblocks;

	if (needed > journal->j_max_transaction_buffers) {
		/*
		 * If the current transaction is already too large, then start
		 * to commit it: we can then go back and attach this handle to
		 * a new transaction.
		 */
		DEFINE_WAIT(wait);

		jbd_debug(2, "Handle %p starting new commit...\n", handle);
		spin_unlock(&transaction->t_handle_lock);
		prepare_to_wait(&journal->j_wait_transaction_locked, &wait,
				TASK_UNINTERRUPTIBLE);
		__log_start_commit(journal, transaction->t_tid);
		spin_unlock(&journal->j_state_lock);
		schedule();
		finish_wait(&journal->j_wait_transaction_locked, &wait);
		goto repeat;
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
	 *
	 * The worst part is, any transaction currently committing can
	 * reduce the free space arbitrarily.  Be careful to account for
	 * those buffers when checkpointing.
	 */

	/*
	 * @@@ AKPM: This seems rather over-defensive.  We're giving commit
	 * a _lot_ of headroom: 1/4 of the journal plus the size of
	 * the committing transaction.  Really, we only need to give it
	 * committing_transaction->t_outstanding_credits plus "enough" for
	 * the log control blocks.
	 * Also, this test is inconsistent with the matching one in
	 * journal_extend().
	 */
	if (__log_space_left(journal) < jbd_space_needed(journal)) {
		jbd_debug(2, "Handle %p waiting for checkpoint...\n", handle);
		spin_unlock(&transaction->t_handle_lock);
		__log_wait_for_space(journal);
		goto repeat_locked;
	}

	/* OK, account for the buffers that this operation expects to
	 * use and add the handle to the running transaction. */

	handle->h_transaction = transaction;
	transaction->t_outstanding_credits += nblocks;
	transaction->t_updates++;
	transaction->t_handle_count++;
	jbd_debug(4, "Handle %p given %d credits (total %d, free %d)\n",
		  handle, nblocks, transaction->t_outstanding_credits,
		  __log_space_left(journal));
	spin_unlock(&transaction->t_handle_lock);
	spin_unlock(&journal->j_state_lock);

	lock_map_acquire(&handle->h_lockdep_map);
out:
	if (unlikely(new_transaction))		/* It's usually NULL */
		kfree(new_transaction);
	return ret;
}

static struct lock_class_key jbd_handle_key;

/* Allocate a new handle.  This should probably be in a slab... */
static handle_t *new_handle(int nblocks)
{
	handle_t *handle = jbd_alloc_handle(GFP_NOFS);
	if (!handle)
		return NULL;
	handle->h_buffer_credits = nblocks;
	handle->h_ref = 1;

	lockdep_init_map(&handle->h_lockdep_map, "jbd_handle", &jbd_handle_key, 0);

	return handle;
}

/**
 * handle_t *journal_start() - Obtain a new handle.
 * @journal: Journal to start transaction on.
 * @nblocks: number of block buffer we might modify
 *
 * We make sure that the transaction can guarantee at least nblocks of
 * modified buffers in the log.  We block until the log can guarantee
 * that much space.
 *
 * This function is visible to journal users (like ext3fs), so is not
 * called with the journal already locked.
 *
 * Return a pointer to a newly allocated handle, or an ERR_PTR() value
 * on failure.
 */
handle_t *journal_start(journal_t *journal, int nblocks)
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

	current->journal_info = handle;

	err = start_this_handle(journal, handle);
	if (err < 0) {
		jbd_free_handle(handle);
		current->journal_info = NULL;
		handle = ERR_PTR(err);
	}
	return handle;
}

/**
 * int journal_extend() - extend buffer credits.
 * @handle:  handle to 'extend'
 * @nblocks: nr blocks to try to extend by.
 *
 * Some transactions, such as large extends and truncates, can be done
 * atomically all at once or in several stages.  The operation requests
 * a credit for a number of buffer modications in advance, but can
 * extend its credit if it needs more.
 *
 * journal_extend tries to give the running handle more buffer credits.
 * It does not guarantee that allocation - this is a best-effort only.
 * The calling process MUST be able to deal cleanly with a failure to
 * extend here.
 *
 * Return 0 on success, non-zero on failure.
 *
 * return code < 0 implies an error
 * return code > 0 implies normal transaction-full status.
 */
int journal_extend(handle_t *handle, int nblocks)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal = transaction->t_journal;
	int result;
	int wanted;

	result = -EIO;
	if (is_handle_aborted(handle))
		goto out;

	result = 1;

	spin_lock(&journal->j_state_lock);

	/* Don't extend a locked-down transaction! */
	if (handle->h_transaction->t_state != T_RUNNING) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "transaction not running\n", handle, nblocks);
		goto error_out;
	}

	spin_lock(&transaction->t_handle_lock);
	wanted = transaction->t_outstanding_credits + nblocks;

	if (wanted > journal->j_max_transaction_buffers) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "transaction too large\n", handle, nblocks);
		goto unlock;
	}

	if (wanted > __log_space_left(journal)) {
		jbd_debug(3, "denied handle %p %d blocks: "
			  "insufficient log space\n", handle, nblocks);
		goto unlock;
	}

	handle->h_buffer_credits += nblocks;
	transaction->t_outstanding_credits += nblocks;
	result = 0;

	jbd_debug(3, "extended handle %p by %d\n", handle, nblocks);
unlock:
	spin_unlock(&transaction->t_handle_lock);
error_out:
	spin_unlock(&journal->j_state_lock);
out:
	return result;
}


/**
 * int journal_restart() - restart a handle.
 * @handle:  handle to restart
 * @nblocks: nr credits requested
 *
 * Restart a handle for a multi-transaction filesystem
 * operation.
 *
 * If the journal_extend() call above fails to grant new buffer credits
 * to a running handle, a call to journal_restart will commit the
 * handle's transaction so far and reattach the handle to a new
 * transaction capabable of guaranteeing the requested number of
 * credits.
 */

int journal_restart(handle_t *handle, int nblocks)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal = transaction->t_journal;
	int ret;

	/* If we've had an abort of any type, don't even think about
	 * actually doing the restart! */
	if (is_handle_aborted(handle))
		return 0;

	/*
	 * First unlink the handle from its current transaction, and start the
	 * commit on that.
	 */
	J_ASSERT(transaction->t_updates > 0);
	J_ASSERT(journal_current_handle() == handle);

	spin_lock(&journal->j_state_lock);
	spin_lock(&transaction->t_handle_lock);
	transaction->t_outstanding_credits -= handle->h_buffer_credits;
	transaction->t_updates--;

	if (!transaction->t_updates)
		wake_up(&journal->j_wait_updates);
	spin_unlock(&transaction->t_handle_lock);

	jbd_debug(2, "restarting handle %p\n", handle);
	__log_start_commit(journal, transaction->t_tid);
	spin_unlock(&journal->j_state_lock);

	lock_map_release(&handle->h_lockdep_map);
	handle->h_buffer_credits = nblocks;
	ret = start_this_handle(journal, handle);
	return ret;
}


/**
 * void journal_lock_updates () - establish a transaction barrier.
 * @journal:  Journal to establish a barrier on.
 *
 * This locks out any further updates from being started, and blocks until all
 * existing updates have completed, returning only once the journal is in a
 * quiescent state with no updates running.
 *
 * We do not use simple mutex for synchronization as there are syscalls which
 * want to return with filesystem locked and that trips up lockdep. Also
 * hibernate needs to lock filesystem but locked mutex then blocks hibernation.
 * Since locking filesystem is rare operation, we use simple counter and
 * waitqueue for locking.
 */
void journal_lock_updates(journal_t *journal)
{
	DEFINE_WAIT(wait);

wait:
	/* Wait for previous locked operation to finish */
	wait_event(journal->j_wait_transaction_locked,
		   journal->j_barrier_count == 0);

	spin_lock(&journal->j_state_lock);
	/*
	 * Check reliably under the lock whether we are the ones winning the race
	 * and locking the journal
	 */
	if (journal->j_barrier_count > 0) {
		spin_unlock(&journal->j_state_lock);
		goto wait;
	}
	++journal->j_barrier_count;

	/* Wait until there are no running updates */
	while (1) {
		transaction_t *transaction = journal->j_running_transaction;

		if (!transaction)
			break;

		spin_lock(&transaction->t_handle_lock);
		if (!transaction->t_updates) {
			spin_unlock(&transaction->t_handle_lock);
			break;
		}
		prepare_to_wait(&journal->j_wait_updates, &wait,
				TASK_UNINTERRUPTIBLE);
		spin_unlock(&transaction->t_handle_lock);
		spin_unlock(&journal->j_state_lock);
		schedule();
		finish_wait(&journal->j_wait_updates, &wait);
		spin_lock(&journal->j_state_lock);
	}
	spin_unlock(&journal->j_state_lock);
}

/**
 * void journal_unlock_updates (journal_t* journal) - release barrier
 * @journal:  Journal to release the barrier on.
 *
 * Release a transaction barrier obtained with journal_lock_updates().
 */
void journal_unlock_updates (journal_t *journal)
{
	J_ASSERT(journal->j_barrier_count != 0);

	spin_lock(&journal->j_state_lock);
	--journal->j_barrier_count;
	spin_unlock(&journal->j_state_lock);
	wake_up(&journal->j_wait_transaction_locked);
}

static void warn_dirty_buffer(struct buffer_head *bh)
{
	char b[BDEVNAME_SIZE];

	printk(KERN_WARNING
	       "JBD: Spotted dirty metadata buffer (dev = %s, blocknr = %llu). "
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
	transaction_t *transaction;
	journal_t *journal;
	int error;
	char *frozen_buffer = NULL;
	int need_copy = 0;

	if (is_handle_aborted(handle))
		return -EROFS;

	transaction = handle->h_transaction;
	journal = transaction->t_journal;

	jbd_debug(5, "journal_head %p, force_copy %d\n", jh, force_copy);

	JBUFFER_TRACE(jh, "entry");
repeat:
	bh = jh2bh(jh);

	/* @@@ Need to check for errors here at some point. */

	lock_buffer(bh);
	jbd_lock_bh_state(bh);

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

		if (jh->b_jlist == BJ_Shadow) {
			DEFINE_WAIT_BIT(wait, &bh->b_state, BH_Unshadow);
			wait_queue_head_t *wqh;

			wqh = bit_waitqueue(&bh->b_state, BH_Unshadow);

			JBUFFER_TRACE(jh, "on shadow: sleep");
			jbd_unlock_bh_state(bh);
			/* commit wakes up all shadow buffers after IO */
			for ( ; ; ) {
				prepare_to_wait(wqh, &wait.wait,
						TASK_UNINTERRUPTIBLE);
				if (jh->b_jlist != BJ_Shadow)
					break;
				schedule();
			}
			finish_wait(wqh, &wait.wait);
			goto repeat;
		}

		/* Only do the copy if the currently-owning transaction
		 * still needs it.  If it is on the Forget list, the
		 * committing transaction is past that stage.  The
		 * buffer had better remain locked during the kmalloc,
		 * but that should be true --- we hold the journal lock
		 * still and the buffer is already on the BUF_JOURNAL
		 * list so won't be flushed.
		 *
		 * Subtle point, though: if this is a get_undo_access,
		 * then we will be relying on the frozen_data to contain
		 * the new value of the committed_data record after the
		 * transaction, so we HAVE to force the frozen_data copy
		 * in that case. */

		if (jh->b_jlist != BJ_Forget || force_copy) {
			JBUFFER_TRACE(jh, "generate frozen data");
			if (!frozen_buffer) {
				JBUFFER_TRACE(jh, "allocate memory for buffer");
				jbd_unlock_bh_state(bh);
				frozen_buffer =
					jbd_alloc(jh2bh(jh)->b_size,
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
		__journal_file_buffer(jh, transaction, BJ_Reserved);
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
		memcpy(jh->b_frozen_data, source+offset, jh2bh(jh)->b_size);
		kunmap_atomic(source);
	}
	jbd_unlock_bh_state(bh);

	/*
	 * If we are about to journal a buffer, then any revoke pending on it is
	 * no longer valid
	 */
	journal_cancel_revoke(handle, jh);

out:
	if (unlikely(frozen_buffer))	/* It's usually NULL */
		jbd_free(frozen_buffer, bh->b_size);

	JBUFFER_TRACE(jh, "exit");
	return error;
}

/**
 * int journal_get_write_access() - notify intent to modify a buffer for metadata (not data) update.
 * @handle: transaction to add buffer modifications to
 * @bh:     bh to be used for metadata writes
 *
 * Returns an error code or 0 on success.
 *
 * In full data journalling mode the buffer may be of type BJ_AsyncData,
 * because we're write()ing a buffer which is also part of a shared mapping.
 */

int journal_get_write_access(handle_t *handle, struct buffer_head *bh)
{
	struct journal_head *jh = journal_add_journal_head(bh);
	int rc;

	/* We do not want to get caught playing with fields which the
	 * log thread also manipulates.  Make sure that the buffer
	 * completes any outstanding IO before proceeding. */
	rc = do_get_write_access(handle, jh, 0);
	journal_put_journal_head(jh);
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
 * int journal_get_create_access () - notify intent to use newly created bh
 * @handle: transaction to new buffer to
 * @bh: new buffer.
 *
 * Call this if you create a new bh.
 */
int journal_get_create_access(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal = transaction->t_journal;
	struct journal_head *jh = journal_add_journal_head(bh);
	int err;

	jbd_debug(5, "journal_head %p\n", jh);
	err = -EROFS;
	if (is_handle_aborted(handle))
		goto out;
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
	spin_lock(&journal->j_list_lock);
	J_ASSERT_JH(jh, (jh->b_transaction == transaction ||
		jh->b_transaction == NULL ||
		(jh->b_transaction == journal->j_committing_transaction &&
			  jh->b_jlist == BJ_Forget)));

	J_ASSERT_JH(jh, jh->b_next_transaction == NULL);
	J_ASSERT_JH(jh, buffer_locked(jh2bh(jh)));

	if (jh->b_transaction == NULL) {
		/*
		 * Previous journal_forget() could have left the buffer
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
		__journal_file_buffer(jh, transaction, BJ_Reserved);
	} else if (jh->b_transaction == journal->j_committing_transaction) {
		/* first access by this transaction */
		jh->b_modified = 0;

		JBUFFER_TRACE(jh, "set next transaction");
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
	journal_cancel_revoke(handle, jh);
out:
	journal_put_journal_head(jh);
	return err;
}

/**
 * int journal_get_undo_access() - Notify intent to modify metadata with non-rewindable consequences
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
 * To deal with that, journal_get_undo_access requests write access to a
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
int journal_get_undo_access(handle_t *handle, struct buffer_head *bh)
{
	int err;
	struct journal_head *jh = journal_add_journal_head(bh);
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
		committed_data = jbd_alloc(jh2bh(jh)->b_size, GFP_NOFS);
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
	journal_put_journal_head(jh);
	if (unlikely(committed_data))
		jbd_free(committed_data, bh->b_size);
	return err;
}

/**
 * int journal_dirty_data() - mark a buffer as containing dirty data to be flushed
 * @handle: transaction
 * @bh: bufferhead to mark
 *
 * Description:
 * Mark a buffer as containing dirty data which needs to be flushed before
 * we can commit the current transaction.
 *
 * The buffer is placed on the transaction's data list and is marked as
 * belonging to the transaction.
 *
 * Returns error number or 0 on success.
 *
 * journal_dirty_data() can be called via page_launder->ext3_writepage
 * by kswapd.
 */
int journal_dirty_data(handle_t *handle, struct buffer_head *bh)
{
	journal_t *journal = handle->h_transaction->t_journal;
	int need_brelse = 0;
	struct journal_head *jh;
	int ret = 0;

	if (is_handle_aborted(handle))
		return ret;

	jh = journal_add_journal_head(bh);
	JBUFFER_TRACE(jh, "entry");

	/*
	 * The buffer could *already* be dirty.  Writeout can start
	 * at any time.
	 */
	jbd_debug(4, "jh: %p, tid:%d\n", jh, handle->h_transaction->t_tid);

	/*
	 * What if the buffer is already part of a running transaction?
	 *
	 * There are two cases:
	 * 1) It is part of the current running transaction.  Refile it,
	 *    just in case we have allocated it as metadata, deallocated
	 *    it, then reallocated it as data.
	 * 2) It is part of the previous, still-committing transaction.
	 *    If all we want to do is to guarantee that the buffer will be
	 *    written to disk before this new transaction commits, then
	 *    being sure that the *previous* transaction has this same
	 *    property is sufficient for us!  Just leave it on its old
	 *    transaction.
	 *
	 * In case (2), the buffer must not already exist as metadata
	 * --- that would violate write ordering (a transaction is free
	 * to write its data at any point, even before the previous
	 * committing transaction has committed).  The caller must
	 * never, ever allow this to happen: there's nothing we can do
	 * about it in this layer.
	 */
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);

	/* Now that we have bh_state locked, are we really still mapped? */
	if (!buffer_mapped(bh)) {
		JBUFFER_TRACE(jh, "unmapped buffer, bailing out");
		goto no_journal;
	}

	if (jh->b_transaction) {
		JBUFFER_TRACE(jh, "has transaction");
		if (jh->b_transaction != handle->h_transaction) {
			JBUFFER_TRACE(jh, "belongs to older transaction");
			J_ASSERT_JH(jh, jh->b_transaction ==
					journal->j_committing_transaction);

			/* @@@ IS THIS TRUE  ? */
			/*
			 * Not any more.  Scenario: someone does a write()
			 * in data=journal mode.  The buffer's transaction has
			 * moved into commit.  Then someone does another
			 * write() to the file.  We do the frozen data copyout
			 * and set b_next_transaction to point to j_running_t.
			 * And while we're in that state, someone does a
			 * writepage() in an attempt to pageout the same area
			 * of the file via a shared mapping.  At present that
			 * calls journal_dirty_data(), and we get right here.
			 * It may be too late to journal the data.  Simply
			 * falling through to the next test will suffice: the
			 * data will be dirty and wil be checkpointed.  The
			 * ordering comments in the next comment block still
			 * apply.
			 */
			//J_ASSERT_JH(jh, jh->b_next_transaction == NULL);

			/*
			 * If we're journalling data, and this buffer was
			 * subject to a write(), it could be metadata, forget
			 * or shadow against the committing transaction.  Now,
			 * someone has dirtied the same darn page via a mapping
			 * and it is being writepage()'d.
			 * We *could* just steal the page from commit, with some
			 * fancy locking there.  Instead, we just skip it -
			 * don't tie the page's buffers to the new transaction
			 * at all.
			 * Implication: if we crash before the writepage() data
			 * is written into the filesystem, recovery will replay
			 * the write() data.
			 */
			if (jh->b_jlist != BJ_None &&
					jh->b_jlist != BJ_SyncData &&
					jh->b_jlist != BJ_Locked) {
				JBUFFER_TRACE(jh, "Not stealing");
				goto no_journal;
			}

			/*
			 * This buffer may be undergoing writeout in commit.  We
			 * can't return from here and let the caller dirty it
			 * again because that can cause the write-out loop in
			 * commit to never terminate.
			 */
			if (buffer_dirty(bh)) {
				get_bh(bh);
				spin_unlock(&journal->j_list_lock);
				jbd_unlock_bh_state(bh);
				need_brelse = 1;
				sync_dirty_buffer(bh);
				jbd_lock_bh_state(bh);
				spin_lock(&journal->j_list_lock);
				/* Since we dropped the lock... */
				if (!buffer_mapped(bh)) {
					JBUFFER_TRACE(jh, "buffer got unmapped");
					goto no_journal;
				}
				/* The buffer may become locked again at any
				   time if it is redirtied */
			}

			/*
			 * We cannot remove the buffer with io error from the
			 * committing transaction, because otherwise it would
			 * miss the error and the commit would not abort.
			 */
			if (unlikely(!buffer_uptodate(bh))) {
				ret = -EIO;
				goto no_journal;
			}
			/* We might have slept so buffer could be refiled now */
			if (jh->b_transaction != NULL &&
			    jh->b_transaction != handle->h_transaction) {
				JBUFFER_TRACE(jh, "unfile from commit");
				__journal_temp_unlink_buffer(jh);
				/* It still points to the committing
				 * transaction; move it to this one so
				 * that the refile assert checks are
				 * happy. */
				jh->b_transaction = handle->h_transaction;
			}
			/* The buffer will be refiled below */

		}
		/*
		 * Special case --- the buffer might actually have been
		 * allocated and then immediately deallocated in the previous,
		 * committing transaction, so might still be left on that
		 * transaction's metadata lists.
		 */
		if (jh->b_jlist != BJ_SyncData && jh->b_jlist != BJ_Locked) {
			JBUFFER_TRACE(jh, "not on correct data list: unfile");
			J_ASSERT_JH(jh, jh->b_jlist != BJ_Shadow);
			JBUFFER_TRACE(jh, "file as data");
			__journal_file_buffer(jh, handle->h_transaction,
						BJ_SyncData);
		}
	} else {
		JBUFFER_TRACE(jh, "not on a transaction");
		__journal_file_buffer(jh, handle->h_transaction, BJ_SyncData);
	}
no_journal:
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh);
	if (need_brelse) {
		BUFFER_TRACE(bh, "brelse");
		__brelse(bh);
	}
	JBUFFER_TRACE(jh, "exit");
	journal_put_journal_head(jh);
	return ret;
}

/**
 * int journal_dirty_metadata() - mark a buffer as containing dirty metadata
 * @handle: transaction to add buffer to.
 * @bh: buffer to mark
 *
 * Mark dirty metadata which needs to be journaled as part of the current
 * transaction.
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
int journal_dirty_metadata(handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal = transaction->t_journal;
	struct journal_head *jh = bh2jh(bh);

	jbd_debug(5, "journal_head %p\n", jh);
	JBUFFER_TRACE(jh, "entry");
	if (is_handle_aborted(handle))
		goto out;

	jbd_lock_bh_state(bh);

	if (jh->b_modified == 0) {
		/*
		 * This buffer's got modified and becoming part
		 * of the transaction. This needs to be done
		 * once a transaction -bzzz
		 */
		jh->b_modified = 1;
		J_ASSERT_JH(jh, handle->h_buffer_credits > 0);
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
		J_ASSERT_JH(jh, jh->b_transaction ==
					journal->j_running_transaction);
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
		J_ASSERT_JH(jh, jh->b_transaction ==
					journal->j_committing_transaction);
		J_ASSERT_JH(jh, jh->b_next_transaction == transaction);
		/* And this case is illegal: we can't reuse another
		 * transaction's data buffer, ever. */
		goto out_unlock_bh;
	}

	/* That test should have eliminated the following case: */
	J_ASSERT_JH(jh, jh->b_frozen_data == NULL);

	JBUFFER_TRACE(jh, "file as BJ_Metadata");
	spin_lock(&journal->j_list_lock);
	__journal_file_buffer(jh, handle->h_transaction, BJ_Metadata);
	spin_unlock(&journal->j_list_lock);
out_unlock_bh:
	jbd_unlock_bh_state(bh);
out:
	JBUFFER_TRACE(jh, "exit");
	return 0;
}

/*
 * journal_release_buffer: undo a get_write_access without any buffer
 * updates, if the update decided in the end that it didn't need access.
 *
 */
void
journal_release_buffer(handle_t *handle, struct buffer_head *bh)
{
	BUFFER_TRACE(bh, "entry");
}

/**
 * void journal_forget() - bforget() for potentially-journaled buffers.
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
int journal_forget (handle_t *handle, struct buffer_head *bh)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal = transaction->t_journal;
	struct journal_head *jh;
	int drop_reserve = 0;
	int err = 0;
	int was_modified = 0;

	BUFFER_TRACE(bh, "entry");

	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);

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

	if (jh->b_transaction == handle->h_transaction) {
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

		if (jh->b_cp_transaction) {
			__journal_temp_unlink_buffer(jh);
			__journal_file_buffer(jh, transaction, BJ_Forget);
		} else {
			__journal_unfile_buffer(jh);
			if (!buffer_jbd(bh)) {
				spin_unlock(&journal->j_list_lock);
				jbd_unlock_bh_state(bh);
				__bforget(bh);
				goto drop;
			}
		}
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
			jh->b_next_transaction = NULL;

			/*
			 * only drop a reference if this transaction modified
			 * the buffer
			 */
			if (was_modified)
				drop_reserve = 1;
		}
	}

not_jbd:
	spin_unlock(&journal->j_list_lock);
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
 * int journal_stop() - complete a transaction
 * @handle: tranaction to complete.
 *
 * All done for a particular handle.
 *
 * There is not much action needed here.  We just return any remaining
 * buffer credits to the transaction and remove the handle.  The only
 * complication is that we need to start a commit operation if the
 * filesystem is marked for synchronous update.
 *
 * journal_stop itself will not usually return an error, but it may
 * do so in unusual circumstances.  In particular, expect it to
 * return -EIO if a journal_abort has been executed since the
 * transaction began.
 */
int journal_stop(handle_t *handle)
{
	transaction_t *transaction = handle->h_transaction;
	journal_t *journal = transaction->t_journal;
	int err;
	pid_t pid;

	J_ASSERT(journal_current_handle() == handle);

	if (is_handle_aborted(handle))
		err = -EIO;
	else {
		J_ASSERT(transaction->t_updates > 0);
		err = 0;
	}

	if (--handle->h_ref > 0) {
		jbd_debug(4, "h_ref %d -> %d\n", handle->h_ref + 1,
			  handle->h_ref);
		return err;
	}

	jbd_debug(4, "Handle %p going down\n", handle);

	/*
	 * Implement synchronous transaction batching.  If the handle
	 * was synchronous, don't force a commit immediately.  Let's
	 * yield and let another thread piggyback onto this transaction.
	 * Keep doing that while new threads continue to arrive.
	 * It doesn't cost much - we're about to run a commit and sleep
	 * on IO anyway.  Speeds up many-threaded, many-dir operations
	 * by 30x or more...
	 *
	 * We try and optimize the sleep time against what the underlying disk
	 * can do, instead of having a static sleep time.  This is useful for
	 * the case where our storage is so fast that it is more optimal to go
	 * ahead and force a flush and wait for the transaction to be committed
	 * than it is to wait for an arbitrary amount of time for new writers to
	 * join the transaction.  We achieve this by measuring how long it takes
	 * to commit a transaction, and compare it with how long this
	 * transaction has been running, and if run time < commit time then we
	 * sleep for the delta and commit.  This greatly helps super fast disks
	 * that would see slowdowns as more threads started doing fsyncs.
	 *
	 * But don't do this if this process was the most recent one to
	 * perform a synchronous write.  We do this to detect the case where a
	 * single process is doing a stream of sync writes.  No point in waiting
	 * for joiners in that case.
	 */
	pid = current->pid;
	if (handle->h_sync && journal->j_last_sync_writer != pid) {
		u64 commit_time, trans_time;

		journal->j_last_sync_writer = pid;

		spin_lock(&journal->j_state_lock);
		commit_time = journal->j_average_commit_time;
		spin_unlock(&journal->j_state_lock);

		trans_time = ktime_to_ns(ktime_sub(ktime_get(),
						   transaction->t_start_time));

		commit_time = min_t(u64, commit_time,
				    1000*jiffies_to_usecs(1));

		if (trans_time < commit_time) {
			ktime_t expires = ktime_add_ns(ktime_get(),
						       commit_time);
			set_current_state(TASK_UNINTERRUPTIBLE);
			schedule_hrtimeout(&expires, HRTIMER_MODE_ABS);
		}
	}

	current->journal_info = NULL;
	spin_lock(&journal->j_state_lock);
	spin_lock(&transaction->t_handle_lock);
	transaction->t_outstanding_credits -= handle->h_buffer_credits;
	transaction->t_updates--;
	if (!transaction->t_updates) {
		wake_up(&journal->j_wait_updates);
		if (journal->j_barrier_count)
			wake_up(&journal->j_wait_transaction_locked);
	}

	/*
	 * If the handle is marked SYNC, we need to set another commit
	 * going!  We also want to force a commit if the current
	 * transaction is occupying too much of the log, or if the
	 * transaction is too old now.
	 */
	if (handle->h_sync ||
			transaction->t_outstanding_credits >
				journal->j_max_transaction_buffers ||
			time_after_eq(jiffies, transaction->t_expires)) {
		/* Do this even for aborted journals: an abort still
		 * completes the commit thread, it just doesn't write
		 * anything to disk. */
		tid_t tid = transaction->t_tid;

		spin_unlock(&transaction->t_handle_lock);
		jbd_debug(2, "transaction too old, requesting commit for "
					"handle %p\n", handle);
		/* This is non-blocking */
		__log_start_commit(journal, transaction->t_tid);
		spin_unlock(&journal->j_state_lock);

		/*
		 * Special case: JFS_SYNC synchronous updates require us
		 * to wait for the commit to complete.
		 */
		if (handle->h_sync && !(current->flags & PF_MEMALLOC))
			err = log_wait_commit(journal, tid);
	} else {
		spin_unlock(&transaction->t_handle_lock);
		spin_unlock(&journal->j_state_lock);
	}

	lock_map_release(&handle->h_lockdep_map);

	jbd_free_handle(handle);
	return err;
}

/**
 * int journal_force_commit() - force any uncommitted transactions
 * @journal: journal to force
 *
 * For synchronous operations: force any uncommitted transactions
 * to disk.  May seem kludgy, but it reuses all the handle batching
 * code in a very simple manner.
 */
int journal_force_commit(journal_t *journal)
{
	handle_t *handle;
	int ret;

	handle = journal_start(journal, 1);
	if (IS_ERR(handle)) {
		ret = PTR_ERR(handle);
	} else {
		handle->h_sync = 1;
		ret = journal_stop(handle);
	}
	return ret;
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
 * bh->b_transaction->t_sync_datalist, t_buffers, t_forget,
 * t_iobuf_list, t_shadow_list, t_log_list or t_reserved_list.  If the caller
 * is holding onto a copy of one of thee pointers, it could go bad.
 * Generally the caller needs to re-read the pointer from the transaction_t.
 *
 * Called under j_list_lock.  The journal may not be locked.
 */
static void __journal_temp_unlink_buffer(struct journal_head *jh)
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
	case BJ_SyncData:
		list = &transaction->t_sync_datalist;
		break;
	case BJ_Metadata:
		transaction->t_nr_buffers--;
		J_ASSERT_JH(jh, transaction->t_nr_buffers >= 0);
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_IO:
		list = &transaction->t_iobuf_list;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_LogCtl:
		list = &transaction->t_log_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	case BJ_Locked:
		list = &transaction->t_locked_list;
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
void __journal_unfile_buffer(struct journal_head *jh)
{
	__journal_temp_unlink_buffer(jh);
	jh->b_transaction = NULL;
	journal_put_journal_head(jh);
}

void journal_unfile_buffer(journal_t *journal, struct journal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	/* Get reference so that buffer cannot be freed before we unlock it */
	get_bh(bh);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);
	__journal_unfile_buffer(jh);
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh);
	__brelse(bh);
}

/*
 * Called from journal_try_to_free_buffers().
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

	if (jh->b_next_transaction != NULL)
		goto out;

	spin_lock(&journal->j_list_lock);
	if (jh->b_transaction != NULL && jh->b_cp_transaction == NULL) {
		if (jh->b_jlist == BJ_SyncData || jh->b_jlist == BJ_Locked) {
			/* A written-back ordered data buffer */
			JBUFFER_TRACE(jh, "release data");
			__journal_unfile_buffer(jh);
		}
	} else if (jh->b_cp_transaction != NULL && jh->b_transaction == NULL) {
		/* written-back checkpointed metadata buffer */
		if (jh->b_jlist == BJ_None) {
			JBUFFER_TRACE(jh, "remove from checkpoint list");
			__journal_remove_checkpoint(jh);
		}
	}
	spin_unlock(&journal->j_list_lock);
out:
	return;
}

/**
 * int journal_try_to_free_buffers() - try to free page buffers.
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
 * running transaction's ->t_datalist via __journal_unfile_buffer.
 *
 * This may *change* the value of transaction_t->t_datalist, so anyone
 * who looks at t_datalist needs to lock against this function.
 *
 * Even worse, someone may be doing a journal_dirty_data on this
 * buffer.  So we need to lock against that.  journal_dirty_data()
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
int journal_try_to_free_buffers(journal_t *journal,
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
		 * journal_put_journal_head().
		 */
		jh = journal_grab_journal_head(bh);
		if (!jh)
			continue;

		jbd_lock_bh_state(bh);
		__journal_try_to_free_buffer(journal, bh);
		journal_put_journal_head(jh);
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
		__journal_temp_unlink_buffer(jh);
		/*
		 * We don't want to write the buffer anymore, clear the
		 * bit so that we don't confuse checks in
		 * __journal_file_buffer
		 */
		clear_buffer_dirty(bh);
		__journal_file_buffer(jh, transaction, BJ_Forget);
		may_free = 0;
	} else {
		JBUFFER_TRACE(jh, "on running transaction");
		__journal_unfile_buffer(jh);
	}
	return may_free;
}

/*
 * journal_invalidatepage
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

retry:
	/*
	 * It is safe to proceed here without the j_list_lock because the
	 * buffers cannot be stolen by try_to_free_buffers as long as we are
	 * holding the page lock. --sct
	 */

	if (!buffer_jbd(bh))
		goto zap_buffer_unlocked;

	spin_lock(&journal->j_state_lock);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);

	jh = journal_grab_journal_head(bh);
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
		if (jh->b_jlist == BJ_Locked) {
			/*
			 * The buffer is on the committing transaction's locked
			 * list.  We have the buffer locked, so I/O has
			 * completed.  So we can nail the buffer now.
			 */
			may_free = __dispose_buffer(jh, transaction);
			goto zap_buffer;
		}
		/*
		 * The buffer is committing, we simply cannot touch
		 * it. If the page is straddling i_size we have to wait
		 * for commit and try again.
		 */
		if (partial_page) {
			tid_t tid = journal->j_committing_transaction->t_tid;

			journal_put_journal_head(jh);
			spin_unlock(&journal->j_list_lock);
			jbd_unlock_bh_state(bh);
			spin_unlock(&journal->j_state_lock);
			unlock_buffer(bh);
			log_wait_commit(journal, tid);
			lock_buffer(bh);
			goto retry;
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
		journal_put_journal_head(jh);
		spin_unlock(&journal->j_list_lock);
		jbd_unlock_bh_state(bh);
		spin_unlock(&journal->j_state_lock);
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
	 * here. */
	jh->b_modified = 0;
	journal_put_journal_head(jh);
zap_buffer_no_jh:
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh);
	spin_unlock(&journal->j_state_lock);
zap_buffer_unlocked:
	clear_buffer_dirty(bh);
	J_ASSERT_BH(bh, !buffer_jbddirty(bh));
	clear_buffer_mapped(bh);
	clear_buffer_req(bh);
	clear_buffer_new(bh);
	bh->b_bdev = NULL;
	return may_free;
}

/**
 * void journal_invalidatepage() - invalidate a journal page
 * @journal: journal to use for flush
 * @page:    page to flush
 * @offset:  offset of the range to invalidate
 * @length:  length of the range to invalidate
 *
 * Reap page buffers containing data in specified range in page.
 */
void journal_invalidatepage(journal_t *journal,
		      struct page *page,
		      unsigned int offset,
		      unsigned int length)
{
	struct buffer_head *head, *bh, *next;
	unsigned int stop = offset + length;
	unsigned int curr_off = 0;
	int partial_page = (offset || length < PAGE_CACHE_SIZE);
	int may_free = 1;

	if (!PageLocked(page))
		BUG();
	if (!page_has_buffers(page))
		return;

	BUG_ON(stop > PAGE_CACHE_SIZE || stop < length);

	/* We will potentially be playing with lists other than just the
	 * data lists (especially for journaled data mode), so be
	 * cautious in our locking. */

	head = bh = page_buffers(page);
	do {
		unsigned int next_off = curr_off + bh->b_size;
		next = bh->b_this_page;

		if (next_off > stop)
			return;

		if (offset <= curr_off) {
			/* This block is wholly outside the truncation point */
			lock_buffer(bh);
			may_free &= journal_unmap_buffer(journal, bh,
							 partial_page);
			unlock_buffer(bh);
		}
		curr_off = next_off;
		bh = next;

	} while (bh != head);

	if (!partial_page) {
		if (may_free && try_to_free_buffers(page))
			J_ASSERT(!page_has_buffers(page));
	}
}

/*
 * File a buffer on the given transaction list.
 */
void __journal_file_buffer(struct journal_head *jh,
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
		__journal_temp_unlink_buffer(jh);
	else
		journal_grab_journal_head(bh);
	jh->b_transaction = transaction;

	switch (jlist) {
	case BJ_None:
		J_ASSERT_JH(jh, !jh->b_committed_data);
		J_ASSERT_JH(jh, !jh->b_frozen_data);
		return;
	case BJ_SyncData:
		list = &transaction->t_sync_datalist;
		break;
	case BJ_Metadata:
		transaction->t_nr_buffers++;
		list = &transaction->t_buffers;
		break;
	case BJ_Forget:
		list = &transaction->t_forget;
		break;
	case BJ_IO:
		list = &transaction->t_iobuf_list;
		break;
	case BJ_Shadow:
		list = &transaction->t_shadow_list;
		break;
	case BJ_LogCtl:
		list = &transaction->t_log_list;
		break;
	case BJ_Reserved:
		list = &transaction->t_reserved_list;
		break;
	case BJ_Locked:
		list =  &transaction->t_locked_list;
		break;
	}

	__blist_add_buffer(list, jh);
	jh->b_jlist = jlist;

	if (was_dirty)
		set_buffer_jbddirty(bh);
}

void journal_file_buffer(struct journal_head *jh,
				transaction_t *transaction, int jlist)
{
	jbd_lock_bh_state(jh2bh(jh));
	spin_lock(&transaction->t_journal->j_list_lock);
	__journal_file_buffer(jh, transaction, jlist);
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
void __journal_refile_buffer(struct journal_head *jh)
{
	int was_dirty, jlist;
	struct buffer_head *bh = jh2bh(jh);

	J_ASSERT_JH(jh, jbd_is_locked_bh_state(bh));
	if (jh->b_transaction)
		assert_spin_locked(&jh->b_transaction->t_journal->j_list_lock);

	/* If the buffer is now unused, just drop it. */
	if (jh->b_next_transaction == NULL) {
		__journal_unfile_buffer(jh);
		return;
	}

	/*
	 * It has been modified by a later transaction: add it to the new
	 * transaction's metadata list.
	 */

	was_dirty = test_clear_buffer_jbddirty(bh);
	__journal_temp_unlink_buffer(jh);
	/*
	 * We set b_transaction here because b_next_transaction will inherit
	 * our jh reference and thus __journal_file_buffer() must not take a
	 * new one.
	 */
	jh->b_transaction = jh->b_next_transaction;
	jh->b_next_transaction = NULL;
	if (buffer_freed(bh))
		jlist = BJ_Forget;
	else if (jh->b_modified)
		jlist = BJ_Metadata;
	else
		jlist = BJ_Reserved;
	__journal_file_buffer(jh, jh->b_transaction, jlist);
	J_ASSERT_JH(jh, jh->b_transaction->t_state == T_RUNNING);

	if (was_dirty)
		set_buffer_jbddirty(bh);
}

/*
 * __journal_refile_buffer() with necessary locking added. We take our bh
 * reference so that we can safely unlock bh.
 *
 * The jh and bh may be freed by this call.
 */
void journal_refile_buffer(journal_t *journal, struct journal_head *jh)
{
	struct buffer_head *bh = jh2bh(jh);

	/* Get reference so that buffer cannot be freed before we unlock it */
	get_bh(bh);
	jbd_lock_bh_state(bh);
	spin_lock(&journal->j_list_lock);
	__journal_refile_buffer(jh);
	jbd_unlock_bh_state(bh);
	spin_unlock(&journal->j_list_lock);
	__brelse(bh);
}
/************************************************************/
/* ../linux-3.17/fs/jbd/transaction.c */
/************************************************************/
/*
 * linux/fs/jbd/commit.c
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
// #include <linux/jbd.h>
// #include <linux/errno.h>
// #include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <trace/events/jbd.h>

/*
 * Default IO end handler for temporary BJ_IO buffer_heads.
 */
static void journal_end_buffer_io_sync(struct buffer_head *bh, int uptodate)
{
	BUFFER_TRACE(bh, "");
	if (uptodate)
		set_buffer_uptodate(bh);
	else
		clear_buffer_uptodate(bh);
	unlock_buffer(bh);
}

/*
 * When an ext3-ordered file is truncated, it is possible that many pages are
 * not successfully freed, because they are attached to a committing transaction.
 * After the transaction commits, these pages are left on the LRU, with no
 * ->mapping, and with attached buffers.  These pages are trivially reclaimable
 * by the VM, but their apparent absence upsets the VM accounting, and it makes
 * the numbers in /proc/meminfo look odd.
 *
 * So here, we have a buffer which has just come off the forget list.  Look to
 * see if we can strip all buffers from the backing page.
 *
 * Called under journal->j_list_lock.  The caller provided us with a ref
 * against the buffer, and we drop that here.
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

/*
 * Decrement reference counter for data buffer. If it has been marked
 * 'BH_Freed', release it and the page to which it belongs if possible.
 */
static void release_data_buffer(struct buffer_head *bh)
{
	if (buffer_freed(bh)) {
		WARN_ON_ONCE(buffer_dirty(bh));
		clear_buffer_freed(bh);
		clear_buffer_mapped(bh);
		clear_buffer_new(bh);
		clear_buffer_req(bh);
		bh->b_bdev = NULL;
		release_buffer_page(bh);
	} else
		put_bh(bh);
}

/*
 * Try to acquire jbd_lock_bh_state() against the buffer, when j_list_lock is
 * held.  For ranking reasons we must trylock.  If we lose, schedule away and
 * return 0.  j_list_lock is dropped in this case.
 */
static int inverted_lock(journal_t *journal, struct buffer_head *bh)
{
	if (!jbd_trylock_bh_state(bh)) {
		spin_unlock(&journal->j_list_lock);
		schedule();
		return 0;
	}
	return 1;
}

/* Done it all: now write the commit record.  We should have
 * cleaned up our previous buffers by now, so if we are in abort
 * mode we can now just skip the rest of the journal write
 * entirely.
 *
 * Returns 1 if the journal needs to be aborted or 0 on success
 */
static int journal_write_commit_record(journal_t *journal,
					transaction_t *commit_transaction)
{
	struct journal_head *descriptor;
	struct buffer_head *bh;
	journal_header_t *header;
	int ret;

	if (is_journal_aborted(journal))
		return 0;

	descriptor = journal_get_descriptor_buffer(journal);
	if (!descriptor)
		return 1;

	bh = jh2bh(descriptor);

	header = (journal_header_t *)(bh->b_data);
	header->h_magic = cpu_to_be32(JFS_MAGIC_NUMBER);
	header->h_blocktype = cpu_to_be32(JFS_COMMIT_BLOCK);
	header->h_sequence = cpu_to_be32(commit_transaction->t_tid);

	JBUFFER_TRACE(descriptor, "write commit block");
	set_buffer_dirty(bh);

	if (journal->j_flags & JFS_BARRIER)
		ret = __sync_dirty_buffer(bh, WRITE_SYNC | WRITE_FLUSH_FUA);
	else
		ret = sync_dirty_buffer(bh);

	put_bh(bh);		/* One for getblk() */
	journal_put_journal_head(descriptor);

	return (ret == -EIO);
}

static void journal_do_submit_data(struct buffer_head **wbuf, int bufs,
				   int write_op)
{
	int i;

	for (i = 0; i < bufs; i++) {
		wbuf[i]->b_end_io = end_buffer_write_sync;
		/*
		 * Here we write back pagecache data that may be mmaped. Since
		 * we cannot afford to clean the page and set PageWriteback
		 * here due to lock ordering (page lock ranks above transaction
		 * start), the data can change while IO is in flight. Tell the
		 * block layer it should bounce the bio pages if stable data
		 * during write is required.
		 *
		 * We use up our safety reference in submit_bh().
		 */
		_submit_bh(write_op, wbuf[i], 1 << BIO_SNAP_STABLE);
	}
}

/*
 *  Submit all the data buffers to disk
 */
static int journal_submit_data_buffers(journal_t *journal,
				       transaction_t *commit_transaction,
				       int write_op)
{
	struct journal_head *jh;
	struct buffer_head *bh;
	int locked;
	int bufs = 0;
	struct buffer_head **wbuf = journal->j_wbuf;
	int err = 0;

	/*
	 * Whenever we unlock the journal and sleep, things can get added
	 * onto ->t_sync_datalist, so we have to keep looping back to
	 * write_out_data until we *know* that the list is empty.
	 *
	 * Cleanup any flushed data buffers from the data list.  Even in
	 * abort mode, we want to flush this out as soon as possible.
	 */
write_out_data:
	cond_resched();
	spin_lock(&journal->j_list_lock);

	while (commit_transaction->t_sync_datalist) {
		jh = commit_transaction->t_sync_datalist;
		bh = jh2bh(jh);
		locked = 0;

		/* Get reference just to make sure buffer does not disappear
		 * when we are forced to drop various locks */
		get_bh(bh);
		/* If the buffer is dirty, we need to submit IO and hence
		 * we need the buffer lock. We try to lock the buffer without
		 * blocking. If we fail, we need to drop j_list_lock and do
		 * blocking lock_buffer().
		 */
		if (buffer_dirty(bh)) {
			if (!trylock_buffer(bh)) {
				BUFFER_TRACE(bh, "needs blocking lock");
				spin_unlock(&journal->j_list_lock);
				trace_jbd_do_submit_data(journal,
						     commit_transaction);
				/* Write out all data to prevent deadlocks */
				journal_do_submit_data(wbuf, bufs, write_op);
				bufs = 0;
				lock_buffer(bh);
				spin_lock(&journal->j_list_lock);
			}
			locked = 1;
		}
		/* We have to get bh_state lock. Again out of order, sigh. */
		if (!inverted_lock(journal, bh)) {
			jbd_lock_bh_state(bh);
			spin_lock(&journal->j_list_lock);
		}
		/* Someone already cleaned up the buffer? */
		if (!buffer_jbd(bh) || bh2jh(bh) != jh
			|| jh->b_transaction != commit_transaction
			|| jh->b_jlist != BJ_SyncData) {
			jbd_unlock_bh_state(bh);
			if (locked)
				unlock_buffer(bh);
			BUFFER_TRACE(bh, "already cleaned up");
			release_data_buffer(bh);
			continue;
		}
		if (locked && test_clear_buffer_dirty(bh)) {
			BUFFER_TRACE(bh, "needs writeout, adding to array");
			wbuf[bufs++] = bh;
			__journal_file_buffer(jh, commit_transaction,
						BJ_Locked);
			jbd_unlock_bh_state(bh);
			if (bufs == journal->j_wbufsize) {
				spin_unlock(&journal->j_list_lock);
				trace_jbd_do_submit_data(journal,
						     commit_transaction);
				journal_do_submit_data(wbuf, bufs, write_op);
				bufs = 0;
				goto write_out_data;
			}
		} else if (!locked && buffer_locked(bh)) {
			__journal_file_buffer(jh, commit_transaction,
						BJ_Locked);
			jbd_unlock_bh_state(bh);
			put_bh(bh);
		} else {
			BUFFER_TRACE(bh, "writeout complete: unfile");
			if (unlikely(!buffer_uptodate(bh)))
				err = -EIO;
			__journal_unfile_buffer(jh);
			jbd_unlock_bh_state(bh);
			if (locked)
				unlock_buffer(bh);
			release_data_buffer(bh);
		}

		if (need_resched() || spin_needbreak(&journal->j_list_lock)) {
			spin_unlock(&journal->j_list_lock);
			goto write_out_data;
		}
	}
	spin_unlock(&journal->j_list_lock);
	trace_jbd_do_submit_data(journal, commit_transaction);
	journal_do_submit_data(wbuf, bufs, write_op);

	return err;
}

/*
 * journal_commit_transaction
 *
 * The primary function for committing a transaction to the log.  This
 * function is called by the journal thread to begin a complete commit.
 */
void journal_commit_transaction(journal_t *journal)
{
	transaction_t *commit_transaction;
	struct journal_head *jh, *new_jh, *descriptor;
	struct buffer_head **wbuf = journal->j_wbuf;
	int bufs;
	int flags;
	int err;
	unsigned int blocknr;
	ktime_t start_time;
	u64 commit_time;
	char *tagp = NULL;
	journal_header_t *header;
	journal_block_tag_t *tag = NULL;
	int space_left = 0;
	int first_tag = 0;
	int tag_flag;
	int i;
	struct blk_plug plug;
	int write_op = WRITE;

	/*
	 * First job: lock down the current transaction and wait for
	 * all outstanding updates to complete.
	 */

	/* Do we need to erase the effects of a prior journal_flush? */
	if (journal->j_flags & JFS_FLUSHED) {
		jbd_debug(3, "super block updated\n");
		mutex_lock(&journal->j_checkpoint_mutex);
		/*
		 * We hold j_checkpoint_mutex so tail cannot change under us.
		 * We don't need any special data guarantees for writing sb
		 * since journal is empty and it is ok for write to be
		 * flushed only with transaction commit.
		 */
		journal_update_sb_log_tail(journal, journal->j_tail_sequence,
					   journal->j_tail, WRITE_SYNC);
		mutex_unlock(&journal->j_checkpoint_mutex);
	} else {
		jbd_debug(3, "superblock not updated\n");
	}

	J_ASSERT(journal->j_running_transaction != NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);

	commit_transaction = journal->j_running_transaction;

	trace_jbd_start_commit(journal, commit_transaction);
	jbd_debug(1, "JBD: starting commit of transaction %d\n",
			commit_transaction->t_tid);

	spin_lock(&journal->j_state_lock);
	J_ASSERT(commit_transaction->t_state == T_RUNNING);
	commit_transaction->t_state = T_LOCKED;

	trace_jbd_commit_locking(journal, commit_transaction);
	spin_lock(&commit_transaction->t_handle_lock);
	while (commit_transaction->t_updates) {
		DEFINE_WAIT(wait);

		prepare_to_wait(&journal->j_wait_updates, &wait,
					TASK_UNINTERRUPTIBLE);
		if (commit_transaction->t_updates) {
			spin_unlock(&commit_transaction->t_handle_lock);
			spin_unlock(&journal->j_state_lock);
			schedule();
			spin_lock(&journal->j_state_lock);
			spin_lock(&commit_transaction->t_handle_lock);
		}
		finish_wait(&journal->j_wait_updates, &wait);
	}
	spin_unlock(&commit_transaction->t_handle_lock);

	J_ASSERT (commit_transaction->t_outstanding_credits <=
			journal->j_max_transaction_buffers);

	/*
	 * First thing we are allowed to do is to discard any remaining
	 * BJ_Reserved buffers.  Note, it is _not_ permissible to assume
	 * that there are no such buffers: if a large filesystem
	 * operation like a truncate needs to split itself over multiple
	 * transactions, then it may try to do a journal_restart() while
	 * there are still BJ_Reserved buffers outstanding.  These must
	 * be released cleanly from the current transaction.
	 *
	 * In this case, the filesystem must still reserve write access
	 * again before modifying the buffer in the new transaction, but
	 * we do not require it to remember exactly which old buffers it
	 * has reserved.  This is consistent with the existing behaviour
	 * that multiple journal_get_write_access() calls to the same
	 * buffer are perfectly permissible.
	 */
	while (commit_transaction->t_reserved_list) {
		jh = commit_transaction->t_reserved_list;
		JBUFFER_TRACE(jh, "reserved, unused: refile");
		/*
		 * A journal_get_undo_access()+journal_release_buffer() may
		 * leave undo-committed data.
		 */
		if (jh->b_committed_data) {
			struct buffer_head *bh = jh2bh(jh);

			jbd_lock_bh_state(bh);
			jbd_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			jbd_unlock_bh_state(bh);
		}
		journal_refile_buffer(journal, jh);
	}

	/*
	 * Now try to drop any written-back buffers from the journal's
	 * checkpoint lists.  We do this *before* commit because it potentially
	 * frees some memory
	 */
	spin_lock(&journal->j_list_lock);
	__journal_clean_checkpoint_list(journal);
	spin_unlock(&journal->j_list_lock);

	jbd_debug (3, "JBD: commit phase 1\n");

	/*
	 * Clear revoked flag to reflect there is no revoked buffers
	 * in the next transaction which is going to be started.
	 */
	journal_clear_buffer_revoked_flags(journal);

	/*
	 * Switch to a new revoke table.
	 */
	journal_switch_revoke_table(journal);

	trace_jbd_commit_flushing(journal, commit_transaction);
	commit_transaction->t_state = T_FLUSH;
	journal->j_committing_transaction = commit_transaction;
	journal->j_running_transaction = NULL;
	start_time = ktime_get();
	commit_transaction->t_log_start = journal->j_head;
	wake_up(&journal->j_wait_transaction_locked);
	spin_unlock(&journal->j_state_lock);

	jbd_debug (3, "JBD: commit phase 2\n");

	if (tid_geq(journal->j_commit_waited, commit_transaction->t_tid))
		write_op = WRITE_SYNC;

	/*
	 * Now start flushing things to disk, in the order they appear
	 * on the transaction lists.  Data blocks go first.
	 */
	blk_start_plug(&plug);
	err = journal_submit_data_buffers(journal, commit_transaction,
					  write_op);
	blk_finish_plug(&plug);

	/*
	 * Wait for all previously submitted IO to complete.
	 */
	spin_lock(&journal->j_list_lock);
	while (commit_transaction->t_locked_list) {
		struct buffer_head *bh;

		jh = commit_transaction->t_locked_list->b_tprev;
		bh = jh2bh(jh);
		get_bh(bh);
		if (buffer_locked(bh)) {
			spin_unlock(&journal->j_list_lock);
			wait_on_buffer(bh);
			spin_lock(&journal->j_list_lock);
		}
		if (unlikely(!buffer_uptodate(bh))) {
			if (!trylock_page(bh->b_page)) {
				spin_unlock(&journal->j_list_lock);
				lock_page(bh->b_page);
				spin_lock(&journal->j_list_lock);
			}
			if (bh->b_page->mapping)
				set_bit(AS_EIO, &bh->b_page->mapping->flags);

			unlock_page(bh->b_page);
			SetPageError(bh->b_page);
			err = -EIO;
		}
		if (!inverted_lock(journal, bh)) {
			put_bh(bh);
			spin_lock(&journal->j_list_lock);
			continue;
		}
		if (buffer_jbd(bh) && bh2jh(bh) == jh &&
		    jh->b_transaction == commit_transaction &&
		    jh->b_jlist == BJ_Locked)
			__journal_unfile_buffer(jh);
		jbd_unlock_bh_state(bh);
		release_data_buffer(bh);
		cond_resched_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);

	if (err) {
		char b[BDEVNAME_SIZE];

		printk(KERN_WARNING
			"JBD: Detected IO errors while flushing file data "
			"on %s\n", bdevname(journal->j_fs_dev, b));
		if (journal->j_flags & JFS_ABORT_ON_SYNCDATA_ERR)
			journal_abort(journal, err);
		err = 0;
	}

	blk_start_plug(&plug);

	journal_write_revoke_records(journal, commit_transaction, write_op);

	/*
	 * If we found any dirty or locked buffers, then we should have
	 * looped back up to the write_out_data label.  If there weren't
	 * any then journal_clean_data_list should have wiped the list
	 * clean by now, so check that it is in fact empty.
	 */
	J_ASSERT (commit_transaction->t_sync_datalist == NULL);

	jbd_debug (3, "JBD: commit phase 3\n");

	/*
	 * Way to go: we have now written out all of the data for a
	 * transaction!  Now comes the tricky part: we need to write out
	 * metadata.  Loop over the transaction's entire buffer list:
	 */
	spin_lock(&journal->j_state_lock);
	commit_transaction->t_state = T_COMMIT;
	spin_unlock(&journal->j_state_lock);

	trace_jbd_commit_logging(journal, commit_transaction);
	J_ASSERT(commit_transaction->t_nr_buffers <=
		 commit_transaction->t_outstanding_credits);

	descriptor = NULL;
	bufs = 0;
	while (commit_transaction->t_buffers) {

		/* Find the next buffer to be journaled... */

		jh = commit_transaction->t_buffers;

		/* If we're in abort mode, we just un-journal the buffer and
		   release it. */

		if (is_journal_aborted(journal)) {
			clear_buffer_jbddirty(jh2bh(jh));
			JBUFFER_TRACE(jh, "journal is aborting: refile");
			journal_refile_buffer(journal, jh);
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
			struct buffer_head *bh;

			J_ASSERT (bufs == 0);

			jbd_debug(4, "JBD: get descriptor\n");

			descriptor = journal_get_descriptor_buffer(journal);
			if (!descriptor) {
				journal_abort(journal, -EIO);
				continue;
			}

			bh = jh2bh(descriptor);
			jbd_debug(4, "JBD: got buffer %llu (%p)\n",
				(unsigned long long)bh->b_blocknr, bh->b_data);
			header = (journal_header_t *)&bh->b_data[0];
			header->h_magic     = cpu_to_be32(JFS_MAGIC_NUMBER);
			header->h_blocktype = cpu_to_be32(JFS_DESCRIPTOR_BLOCK);
			header->h_sequence  = cpu_to_be32(commit_transaction->t_tid);

			tagp = &bh->b_data[sizeof(journal_header_t)];
			space_left = bh->b_size - sizeof(journal_header_t);
			first_tag = 1;
			set_buffer_jwrite(bh);
			set_buffer_dirty(bh);
			wbuf[bufs++] = bh;

			/* Record it so that we can wait for IO
                           completion later */
			BUFFER_TRACE(bh, "ph3: file as descriptor");
			journal_file_buffer(descriptor, commit_transaction,
					BJ_LogCtl);
		}

		/* Where is the buffer to be written? */

		err = journal_next_log_block(journal, &blocknr);
		/* If the block mapping failed, just abandon the buffer
		   and repeat this loop: we'll fall into the
		   refile-on-abort condition above. */
		if (err) {
			journal_abort(journal, err);
			continue;
		}

		/*
		 * start_this_handle() uses t_outstanding_credits to determine
		 * the free space in the log, but this counter is changed
		 * by journal_next_log_block() also.
		 */
		commit_transaction->t_outstanding_credits--;

		/* Bump b_count to prevent truncate from stumbling over
                   the shadowed buffer!  @@@ This can go if we ever get
                   rid of the BJ_IO/BJ_Shadow pairing of buffers. */
		get_bh(jh2bh(jh));

		/* Make a temporary IO buffer with which to write it out
                   (this will requeue both the metadata buffer and the
                   temporary IO buffer). new_bh goes on BJ_IO*/

		set_buffer_jwrite(jh2bh(jh));
		/*
		 * akpm: journal_write_metadata_buffer() sets
		 * new_bh->b_transaction to commit_transaction.
		 * We need to clean this up before we release new_bh
		 * (which is of type BJ_IO)
		 */
		JBUFFER_TRACE(jh, "ph3: write metadata");
		flags = journal_write_metadata_buffer(commit_transaction,
						      jh, &new_jh, blocknr);
		set_buffer_jwrite(jh2bh(new_jh));
		wbuf[bufs++] = jh2bh(new_jh);

		/* Record the new block's tag in the current descriptor
                   buffer */

		tag_flag = 0;
		if (flags & 1)
			tag_flag |= JFS_FLAG_ESCAPE;
		if (!first_tag)
			tag_flag |= JFS_FLAG_SAME_UUID;

		tag = (journal_block_tag_t *) tagp;
		tag->t_blocknr = cpu_to_be32(jh2bh(jh)->b_blocknr);
		tag->t_flags = cpu_to_be32(tag_flag);
		tagp += sizeof(journal_block_tag_t);
		space_left -= sizeof(journal_block_tag_t);

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
		    space_left < sizeof(journal_block_tag_t) + 16) {

			jbd_debug(4, "JBD: Submit %d IOs\n", bufs);

			/* Write an end-of-descriptor marker before
                           submitting the IOs.  "tag" still points to
                           the last tag we set up. */

			tag->t_flags |= cpu_to_be32(JFS_FLAG_LAST_TAG);

start_journal_io:
			for (i = 0; i < bufs; i++) {
				struct buffer_head *bh = wbuf[i];
				lock_buffer(bh);
				clear_buffer_dirty(bh);
				set_buffer_uptodate(bh);
				bh->b_end_io = journal_end_buffer_io_sync;
				/*
				 * In data=journal mode, here we can end up
				 * writing pagecache data that might be
				 * mmapped. Since we can't afford to clean the
				 * page and set PageWriteback (see the comment
				 * near the other use of _submit_bh()), the
				 * data can change while the write is in
				 * flight.  Tell the block layer to bounce the
				 * bio pages if stable pages are required.
				 */
				_submit_bh(write_op, bh, 1 << BIO_SNAP_STABLE);
			}
			cond_resched();

			/* Force a new descriptor to be generated next
                           time round the loop. */
			descriptor = NULL;
			bufs = 0;
		}
	}

	blk_finish_plug(&plug);

	/* Lo and behold: we have just managed to send a transaction to
           the log.  Before we can commit it, wait for the IO so far to
           complete.  Control buffers being written are on the
           transaction's t_log_list queue, and metadata buffers are on
           the t_iobuf_list queue.

	   Wait for the buffers in reverse order.  That way we are
	   less likely to be woken up until all IOs have completed, and
	   so we incur less scheduling load.
	*/

	jbd_debug(3, "JBD: commit phase 4\n");

	/*
	 * akpm: these are BJ_IO, and j_list_lock is not needed.
	 * See __journal_try_to_free_buffer.
	 */
wait_for_iobuf:
	while (commit_transaction->t_iobuf_list != NULL) {
		struct buffer_head *bh;

		jh = commit_transaction->t_iobuf_list->b_tprev;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) {
			wait_on_buffer(bh);
			goto wait_for_iobuf;
		}
		if (cond_resched())
			goto wait_for_iobuf;

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		clear_buffer_jwrite(bh);

		JBUFFER_TRACE(jh, "ph4: unfile after journal write");
		journal_unfile_buffer(journal, jh);

		/*
		 * ->t_iobuf_list should contain only dummy buffer_heads
		 * which were created by journal_write_metadata_buffer().
		 */
		BUFFER_TRACE(bh, "dumping temporary bh");
		journal_put_journal_head(jh);
		__brelse(bh);
		J_ASSERT_BH(bh, atomic_read(&bh->b_count) == 0);
		free_buffer_head(bh);

		/* We also have to unlock and free the corresponding
                   shadowed buffer */
		jh = commit_transaction->t_shadow_list->b_tprev;
		bh = jh2bh(jh);
		clear_buffer_jwrite(bh);
		J_ASSERT_BH(bh, buffer_jbddirty(bh));

		/* The metadata is now released for reuse, but we need
                   to remember it against this transaction so that when
                   we finally commit, we can do any checkpointing
                   required. */
		JBUFFER_TRACE(jh, "file as BJ_Forget");
		journal_file_buffer(jh, commit_transaction, BJ_Forget);
		/*
		 * Wake up any transactions which were waiting for this
		 * IO to complete. The barrier must be here so that changes
		 * by journal_file_buffer() take effect before wake_up_bit()
		 * does the waitqueue check.
		 */
		smp_mb();
		wake_up_bit(&bh->b_state, BH_Unshadow);
		JBUFFER_TRACE(jh, "brelse shadowed buffer");
		__brelse(bh);
	}

	J_ASSERT (commit_transaction->t_shadow_list == NULL);

	jbd_debug(3, "JBD: commit phase 5\n");

	/* Here we wait for the revoke record and descriptor record buffers */
 wait_for_ctlbuf:
	while (commit_transaction->t_log_list != NULL) {
		struct buffer_head *bh;

		jh = commit_transaction->t_log_list->b_tprev;
		bh = jh2bh(jh);
		if (buffer_locked(bh)) {
			wait_on_buffer(bh);
			goto wait_for_ctlbuf;
		}
		if (cond_resched())
			goto wait_for_ctlbuf;

		if (unlikely(!buffer_uptodate(bh)))
			err = -EIO;

		BUFFER_TRACE(bh, "ph5: control buffer writeout done: unfile");
		clear_buffer_jwrite(bh);
		journal_unfile_buffer(journal, jh);
		journal_put_journal_head(jh);
		__brelse(bh);		/* One for getblk */
		/* AKPM: bforget here */
	}

	if (err)
		journal_abort(journal, err);

	jbd_debug(3, "JBD: commit phase 6\n");

	/* All metadata is written, now write commit record and do cleanup */
	spin_lock(&journal->j_state_lock);
	J_ASSERT(commit_transaction->t_state == T_COMMIT);
	commit_transaction->t_state = T_COMMIT_RECORD;
	spin_unlock(&journal->j_state_lock);

	if (journal_write_commit_record(journal, commit_transaction))
		err = -EIO;

	if (err)
		journal_abort(journal, err);

	/* End of a transaction!  Finally, we can do checkpoint
           processing: any buffers committed as a result of this
           transaction can be removed from any checkpoint list it was on
           before. */

	jbd_debug(3, "JBD: commit phase 7\n");

	J_ASSERT(commit_transaction->t_sync_datalist == NULL);
	J_ASSERT(commit_transaction->t_buffers == NULL);
	J_ASSERT(commit_transaction->t_checkpoint_list == NULL);
	J_ASSERT(commit_transaction->t_iobuf_list == NULL);
	J_ASSERT(commit_transaction->t_shadow_list == NULL);
	J_ASSERT(commit_transaction->t_log_list == NULL);

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
		J_ASSERT_JH(jh,	jh->b_transaction == commit_transaction ||
			jh->b_transaction == journal->j_running_transaction);

		/*
		 * If there is undo-protected committed data against
		 * this buffer, then we can remove it now.  If it is a
		 * buffer needing such protection, the old frozen_data
		 * field now points to a committed version of the
		 * buffer, so rotate that field to the new committed
		 * data.
		 *
		 * Otherwise, we can just throw away the frozen data now.
		 */
		if (jh->b_committed_data) {
			jbd_free(jh->b_committed_data, bh->b_size);
			jh->b_committed_data = NULL;
			if (jh->b_frozen_data) {
				jh->b_committed_data = jh->b_frozen_data;
				jh->b_frozen_data = NULL;
			}
		} else if (jh->b_frozen_data) {
			jbd_free(jh->b_frozen_data, bh->b_size);
			jh->b_frozen_data = NULL;
		}

		spin_lock(&journal->j_list_lock);
		cp_transaction = jh->b_cp_transaction;
		if (cp_transaction) {
			JBUFFER_TRACE(jh, "remove from old cp transaction");
			__journal_remove_checkpoint(jh);
		}

		/* Only re-checkpoint the buffer_head if it is marked
		 * dirty.  If the buffer was added to the BJ_Forget list
		 * by journal_forget, it may no longer be dirty and
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
			 * now. We are rather throughout in that since the
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
			__journal_insert_checkpoint(jh, commit_transaction);
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
		JBUFFER_TRACE(jh, "refile or unfile freed buffer");
		__journal_refile_buffer(jh);
		jbd_unlock_bh_state(bh);
		if (try_to_free)
			release_buffer_page(bh);
		else
			__brelse(bh);
		cond_resched_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);
	/*
	 * This is a bit sleazy.  We use j_list_lock to protect transition
	 * of a transaction into T_FINISHED state and calling
	 * __journal_drop_transaction(). Otherwise we could race with
	 * other checkpointing code processing the transaction...
	 */
	spin_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	/*
	 * Now recheck if some buffers did not get attached to the transaction
	 * while the lock was dropped...
	 */
	if (commit_transaction->t_forget) {
		spin_unlock(&journal->j_list_lock);
		spin_unlock(&journal->j_state_lock);
		goto restart_loop;
	}

	/* Done with this transaction! */

	jbd_debug(3, "JBD: commit phase 8\n");

	J_ASSERT(commit_transaction->t_state == T_COMMIT_RECORD);

	commit_transaction->t_state = T_FINISHED;
	J_ASSERT(commit_transaction == journal->j_committing_transaction);
	journal->j_commit_sequence = commit_transaction->t_tid;
	journal->j_committing_transaction = NULL;
	commit_time = ktime_to_ns(ktime_sub(ktime_get(), start_time));

	/*
	 * weight the commit time higher than the average time so we don't
	 * react too strongly to vast changes in commit time
	 */
	if (likely(journal->j_average_commit_time))
		journal->j_average_commit_time = (commit_time*3 +
				journal->j_average_commit_time) / 4;
	else
		journal->j_average_commit_time = commit_time;

	spin_unlock(&journal->j_state_lock);

	if (commit_transaction->t_checkpoint_list == NULL &&
	    commit_transaction->t_checkpoint_io_list == NULL) {
		__journal_drop_transaction(journal, commit_transaction);
	} else {
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
	}
	spin_unlock(&journal->j_list_lock);

	trace_jbd_end_commit(journal, commit_transaction);
	jbd_debug(1, "JBD: commit %d complete, head %d\n",
		  journal->j_commit_sequence, journal->j_tail_sequence);

	wake_up(&journal->j_wait_done_commit);
}
/************************************************************/
/* ../linux-3.17/fs/jbd/commit.c */
/************************************************************/
/*
 * linux/fs/jbd/recovery.c
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
// #include <linux/jbd.h>
// #include <linux/errno.h>
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
	unsigned int blocknr;
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
		err = journal_bmap(journal, next, &blocknr);

		if (err) {
			printk (KERN_ERR "JBD: bad block at offset %u\n",
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
	unsigned int blocknr;
	struct buffer_head *bh;

	*bhp = NULL;

	if (offset >= journal->j_maxlen) {
		printk(KERN_ERR "JBD: corrupted journal superblock\n");
		return -EIO;
	}

	err = journal_bmap(journal, offset, &blocknr);

	if (err) {
		printk (KERN_ERR "JBD: bad block at offset %u\n",
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
		printk (KERN_ERR "JBD: Failed to read block at offset %u\n",
			offset);
		brelse(bh);
		return -EIO;
	}

	*bhp = bh;
	return 0;
}


/*
 * Count the number of in-use tags in a journal descriptor block.
 */

static int count_tags(struct buffer_head *bh, int size)
{
	char *			tagp;
	journal_block_tag_t *	tag;
	int			nr = 0;

	tagp = &bh->b_data[sizeof(journal_header_t)];

	while ((tagp - bh->b_data + sizeof(journal_block_tag_t)) <= size) {
		tag = (journal_block_tag_t *) tagp;

		nr++;
		tagp += sizeof(journal_block_tag_t);
		if (!(tag->t_flags & cpu_to_be32(JFS_FLAG_SAME_UUID)))
			tagp += 16;

		if (tag->t_flags & cpu_to_be32(JFS_FLAG_LAST_TAG))
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
 * journal_recover - recovers a on-disk journal
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
int journal_recover(journal_t *journal)
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

	jbd_debug(1, "JBD: recovery, exit status %d, "
		  "recovered transactions %u to %u\n",
		  err, info.start_transaction, info.end_transaction);
	jbd_debug(1, "JBD: Replayed %d and revoked %d/%d blocks\n",
		  info.nr_replays, info.nr_revoke_hits, info.nr_revokes);

	/* Restart the log at the next transaction ID, thus invalidating
	 * any existing commit records in the log. */
	journal->j_transaction_sequence = ++info.end_transaction;

	journal_clear_revoke(journal);
	err2 = sync_blockdev(journal->j_fs_dev);
	if (!err)
		err = err2;
	/* Flush disk caches to get replayed data on the permanent storage */
	if (journal->j_flags & JFS_BARRIER) {
		err2 = blkdev_issue_flush(journal->j_fs_dev, GFP_KERNEL, NULL);
		if (!err)
			err = err2;
	}

	return err;
}

/**
 * journal_skip_recovery - Start journal and wipe exiting records
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
int journal_skip_recovery(journal_t *journal)
{
	int			err;
	struct recovery_info	info;

	memset (&info, 0, sizeof(info));

	err = do_one_pass(journal, &info, PASS_SCAN);

	if (err) {
		printk(KERN_ERR "JBD: error %d scanning journal\n", err);
		++journal->j_transaction_sequence;
	} else {
#ifdef CONFIG_JBD_DEBUG
		int dropped = info.end_transaction -
			      be32_to_cpu(journal->j_superblock->s_sequence);
		jbd_debug(1,
			  "JBD: ignoring %d transaction%s from the journal.\n",
			  dropped, (dropped == 1) ? "" : "s");
#endif
		journal->j_transaction_sequence = ++info.end_transaction;
	}

	journal->j_tail = 0;
	return err;
}

static int do_one_pass(journal_t *journal,
			struct recovery_info *info, enum passtype pass)
{
	unsigned int		first_commit_ID, next_commit_ID;
	unsigned int		next_log_block;
	int			err, success = 0;
	journal_superblock_t *	sb;
	journal_header_t *	tmp;
	struct buffer_head *	bh;
	unsigned int		sequence;
	int			blocktype;

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

		jbd_debug(2, "Scanning for sequence ID %u at %u/%u\n",
			  next_commit_ID, next_log_block, journal->j_last);

		/* Skip over each chunk of the transaction looking
		 * either the next descriptor block or the final commit
		 * record. */

		jbd_debug(3, "JBD: checking block %u\n", next_log_block);
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

		if (tmp->h_magic != cpu_to_be32(JFS_MAGIC_NUMBER)) {
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
		case JFS_DESCRIPTOR_BLOCK:
			/* If it is a valid descriptor block, replay it
			 * in pass REPLAY; otherwise, just skip over the
			 * blocks it describes. */
			if (pass != PASS_REPLAY) {
				next_log_block +=
					count_tags(bh, journal->j_blocksize);
				wrap(journal, next_log_block);
				brelse(bh);
				continue;
			}

			/* A descriptor block: we can now write all of
			 * the data blocks.  Yay, useful work is finally
			 * getting done here! */

			tagp = &bh->b_data[sizeof(journal_header_t)];
			while ((tagp - bh->b_data +sizeof(journal_block_tag_t))
			       <= journal->j_blocksize) {
				unsigned int io_block;

				tag = (journal_block_tag_t *) tagp;
				flags = be32_to_cpu(tag->t_flags);

				io_block = next_log_block++;
				wrap(journal, next_log_block);
				err = jread(&obh, journal, io_block);
				if (err) {
					/* Recover what we can, but
					 * report failure at the end. */
					success = err;
					printk (KERN_ERR
						"JBD: IO error %d recovering "
						"block %u in log\n",
						err, io_block);
				} else {
					unsigned int blocknr;

					J_ASSERT(obh != NULL);
					blocknr = be32_to_cpu(tag->t_blocknr);

					/* If the block has been
					 * revoked, then we're all done
					 * here. */
					if (journal_test_revoke
					    (journal, blocknr,
					     next_commit_ID)) {
						brelse(obh);
						++info->nr_revoke_hits;
						goto skip_write;
					}

					/* Find a buffer for the new
					 * data being restored */
					nbh = __getblk(journal->j_fs_dev,
							blocknr,
							journal->j_blocksize);
					if (nbh == NULL) {
						printk(KERN_ERR
						       "JBD: Out of memory "
						       "during recovery.\n");
						err = -ENOMEM;
						brelse(bh);
						brelse(obh);
						goto failed;
					}

					lock_buffer(nbh);
					memcpy(nbh->b_data, obh->b_data,
							journal->j_blocksize);
					if (flags & JFS_FLAG_ESCAPE) {
						*((__be32 *)nbh->b_data) =
						cpu_to_be32(JFS_MAGIC_NUMBER);
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
				tagp += sizeof(journal_block_tag_t);
				if (!(flags & JFS_FLAG_SAME_UUID))
					tagp += 16;

				if (flags & JFS_FLAG_LAST_TAG)
					break;
			}

			brelse(bh);
			continue;

		case JFS_COMMIT_BLOCK:
			/* Found an expected commit block: not much to
			 * do other than move on to the next sequence
			 * number. */
			brelse(bh);
			next_commit_ID++;
			continue;

		case JFS_REVOKE_BLOCK:
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

	if (pass == PASS_SCAN)
		info->end_transaction = next_commit_ID;
	else {
		/* It's really bad news if different passes end up at
		 * different places (but possible due to IO errors). */
		if (info->end_transaction != next_commit_ID) {
			printk (KERN_ERR "JBD: recovery pass %d ended at "
				"transaction %u, expected %u\n",
				pass, next_commit_ID, info->end_transaction);
			if (!success)
				success = -EIO;
		}
	}

	return success;

 failed:
	return err;
}


/* Scan a revoke record, marking all blocks mentioned as revoked. */

static int scan_revoke_records(journal_t *journal, struct buffer_head *bh,
			       tid_t sequence, struct recovery_info *info)
{
	journal_revoke_header_t *header;
	int offset, max;

	header = (journal_revoke_header_t *) bh->b_data;
	offset = sizeof(journal_revoke_header_t);
	max = be32_to_cpu(header->r_count);

	while (offset < max) {
		unsigned int blocknr;
		int err;

		blocknr = be32_to_cpu(* ((__be32 *) (bh->b_data+offset)));
		offset += 4;
		err = journal_set_revoke(journal, blocknr, sequence);
		if (err)
			return err;
		++info->nr_revokes;
	}
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/jbd/recovery.c */
/************************************************************/
/*
 * linux/fs/jbd/checkpoint.c
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
// #include <linux/jbd.h>
// #include <linux/errno.h>
// #include <linux/slab.h>
// #include <linux/blkdev.h>
// #include <trace/events/jbd.h>

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
 * Called under jbd_lock_bh_state(jh2bh(jh)), and drops it
 */
static int __try_to_free_cp_buf(struct journal_head *jh)
{
	int ret = 0;
	struct buffer_head *bh = jh2bh(jh);

	if (jh->b_jlist == BJ_None && !buffer_locked(bh) &&
	    !buffer_dirty(bh) && !buffer_write_io_error(bh)) {
		/*
		 * Get our reference so that bh cannot be freed before
		 * we unlock it
		 */
		get_bh(bh);
		JBUFFER_TRACE(jh, "remove from checkpoint list");
		ret = __journal_remove_checkpoint(jh) + 1;
		jbd_unlock_bh_state(bh);
		BUFFER_TRACE(bh, "release");
		__brelse(bh);
	} else {
		jbd_unlock_bh_state(bh);
	}
	return ret;
}

/*
 * __log_wait_for_space: wait until there is space in the journal.
 *
 * Called under j-state_lock *only*.  It will be unlocked if we have to wait
 * for a checkpoint to free up some space in the log.
 */
void __log_wait_for_space(journal_t *journal)
{
	int nblocks, space_left;
	assert_spin_locked(&journal->j_state_lock);

	nblocks = jbd_space_needed(journal);
	while (__log_space_left(journal) < nblocks) {
		if (journal->j_flags & JFS_ABORT)
			return;
		spin_unlock(&journal->j_state_lock);
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
		spin_lock(&journal->j_state_lock);
		spin_lock(&journal->j_list_lock);
		nblocks = jbd_space_needed(journal);
		space_left = __log_space_left(journal);
		if (space_left < nblocks) {
			int chkpt = journal->j_checkpoint_transactions != NULL;
			tid_t tid = 0;

			if (journal->j_committing_transaction)
				tid = journal->j_committing_transaction->t_tid;
			spin_unlock(&journal->j_list_lock);
			spin_unlock(&journal->j_state_lock);
			if (chkpt) {
				log_do_checkpoint(journal);
			} else if (cleanup_journal_tail(journal) == 0) {
				/* We were able to recover space; yay! */
				;
			} else if (tid) {
				log_wait_commit(journal, tid);
			} else {
				printk(KERN_ERR "%s: needed %d blocks and "
				       "only had %d space available\n",
				       __func__, nblocks, space_left);
				printk(KERN_ERR "%s: no way to get more "
				       "journal space\n", __func__);
				WARN_ON(1);
				journal_abort(journal, 0);
			}
			spin_lock(&journal->j_state_lock);
		} else {
			spin_unlock(&journal->j_list_lock);
		}
		mutex_unlock(&journal->j_checkpoint_mutex);
	}
}

/*
 * We were unable to perform jbd_trylock_bh_state() inside j_list_lock.
 * The caller must restart a list walk.  Wait for someone else to run
 * jbd_unlock_bh_state().
 */
static void jbd_sync_bh(journal_t *journal, struct buffer_head *bh)
	__releases(journal->j_list_lock)
{
	get_bh(bh);
	spin_unlock(&journal->j_list_lock);
	jbd_lock_bh_state(bh);
	jbd_unlock_bh_state(bh);
	put_bh(bh);
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
		if (!jbd_trylock_bh_state(bh)) {
			jbd_sync_bh(journal, bh);
			spin_lock(&journal->j_list_lock);
			goto restart;
		}
		get_bh(bh);
		if (buffer_locked(bh)) {
			spin_unlock(&journal->j_list_lock);
			jbd_unlock_bh_state(bh);
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
		released = __journal_remove_checkpoint(jh);
		jbd_unlock_bh_state(bh);
		__brelse(bh);
	}

	return ret;
}

#define NR_BATCH	64

static void
__flush_batch(journal_t *journal, struct buffer_head **bhs, int *batch_count)
{
	int i;
	struct blk_plug plug;

	blk_start_plug(&plug);
	for (i = 0; i < *batch_count; i++)
		write_dirty_buffer(bhs[i], WRITE_SYNC);
	blk_finish_plug(&plug);

	for (i = 0; i < *batch_count; i++) {
		struct buffer_head *bh = bhs[i];
		clear_buffer_jwrite(bh);
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
 * Called under jbd_lock_bh_state(jh2bh(jh)), and drops it
 */
static int __process_buffer(journal_t *journal, struct journal_head *jh,
			struct buffer_head **bhs, int *batch_count)
{
	struct buffer_head *bh = jh2bh(jh);
	int ret = 0;

	if (buffer_locked(bh)) {
		get_bh(bh);
		spin_unlock(&journal->j_list_lock);
		jbd_unlock_bh_state(bh);
		wait_on_buffer(bh);
		/* the journal_head may have gone by now */
		BUFFER_TRACE(bh, "brelse");
		__brelse(bh);
		ret = 1;
	} else if (jh->b_transaction != NULL) {
		transaction_t *t = jh->b_transaction;
		tid_t tid = t->t_tid;

		spin_unlock(&journal->j_list_lock);
		jbd_unlock_bh_state(bh);
		log_start_commit(journal, tid);
		log_wait_commit(journal, tid);
		ret = 1;
	} else if (!buffer_dirty(bh)) {
		ret = 1;
		if (unlikely(buffer_write_io_error(bh)))
			ret = -EIO;
		get_bh(bh);
		J_ASSERT_JH(jh, !buffer_jbddirty(bh));
		BUFFER_TRACE(bh, "remove from checkpoint");
		__journal_remove_checkpoint(jh);
		spin_unlock(&journal->j_list_lock);
		jbd_unlock_bh_state(bh);
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
		set_buffer_jwrite(bh);
		bhs[*batch_count] = bh;
		__buffer_relink_io(jh);
		jbd_unlock_bh_state(bh);
		(*batch_count)++;
		if (*batch_count == NR_BATCH) {
			spin_unlock(&journal->j_list_lock);
			__flush_batch(journal, bhs, batch_count);
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
int log_do_checkpoint(journal_t *journal)
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
	result = cleanup_journal_tail(journal);
	trace_jbd_checkpoint(journal, result);
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
		struct buffer_head *bhs[NR_BATCH];
		struct journal_head *jh;
		int retry = 0, err;

		while (!retry && transaction->t_checkpoint_list) {
			struct buffer_head *bh;

			jh = transaction->t_checkpoint_list;
			bh = jh2bh(jh);
			if (!jbd_trylock_bh_state(bh)) {
				jbd_sync_bh(journal, bh);
				retry = 1;
				break;
			}
			retry = __process_buffer(journal, jh, bhs,&batch_count);
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
			__flush_batch(journal, bhs, &batch_count);
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
		journal_abort(journal, result);
	else
		result = cleanup_journal_tail(journal);

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
 * This is the only part of the journaling code which really needs to be
 * aware of transaction aborts.  Checkpointing involves writing to the
 * main filesystem area rather than to the journal, so it can proceed
 * even in abort state, but we must not update the super block if
 * checkpointing may have failed.  Otherwise, we would lose some metadata
 * buffers which should be written-back to the filesystem.
 */

int cleanup_journal_tail(journal_t *journal)
{
	transaction_t * transaction;
	tid_t		first_tid;
	unsigned int	blocknr, freed;

	if (is_journal_aborted(journal))
		return 1;

	/*
	 * OK, work out the oldest transaction remaining in the log, and
	 * the log block it starts at.
	 *
	 * If the log is now empty, we need to work out which is the
	 * next transaction ID we will write, and where it will
	 * start.
	 */
	spin_lock(&journal->j_state_lock);
	spin_lock(&journal->j_list_lock);
	transaction = journal->j_checkpoint_transactions;
	if (transaction) {
		first_tid = transaction->t_tid;
		blocknr = transaction->t_log_start;
	} else if ((transaction = journal->j_committing_transaction) != NULL) {
		first_tid = transaction->t_tid;
		blocknr = transaction->t_log_start;
	} else if ((transaction = journal->j_running_transaction) != NULL) {
		first_tid = transaction->t_tid;
		blocknr = journal->j_head;
	} else {
		first_tid = journal->j_transaction_sequence;
		blocknr = journal->j_head;
	}
	spin_unlock(&journal->j_list_lock);
	J_ASSERT(blocknr != 0);

	/* If the oldest pinned transaction is at the tail of the log
           already then there's not much we can do right now. */
	if (journal->j_tail_sequence == first_tid) {
		spin_unlock(&journal->j_state_lock);
		return 1;
	}
	spin_unlock(&journal->j_state_lock);

	/*
	 * We need to make sure that any blocks that were recently written out
	 * --- perhaps by log_do_checkpoint() --- are flushed out before we
	 * drop the transactions from the journal. Similarly we need to be sure
	 * superblock makes it to disk before next transaction starts reusing
	 * freed space (otherwise we could replay some blocks of the new
	 * transaction thinking they belong to the old one). So we use
	 * WRITE_FLUSH_FUA. It's unlikely this will be necessary, especially
	 * with an appropriately sized journal, but we need this to guarantee
	 * correctness.  Fortunately cleanup_journal_tail() doesn't get called
	 * all that often.
	 */
	journal_update_sb_log_tail(journal, first_tid, blocknr,
				   WRITE_FLUSH_FUA);

	spin_lock(&journal->j_state_lock);
	/* OK, update the superblock to recover the freed space.
	 * Physical blocks come first: have we wrapped beyond the end of
	 * the log?  */
	freed = blocknr - journal->j_tail;
	if (blocknr < journal->j_tail)
		freed = freed + journal->j_last - journal->j_first;

	trace_jbd_cleanup_journal_tail(journal, first_tid, blocknr, freed);
	jbd_debug(1,
		  "Cleaning journal tail from %d to %d (offset %u), "
		  "freeing %u\n",
		  journal->j_tail_sequence, first_tid, blocknr, freed);

	journal->j_free += freed;
	journal->j_tail_sequence = first_tid;
	journal->j_tail = blocknr;
	spin_unlock(&journal->j_state_lock);
	return 0;
}


/* Checkpoint list management */

/*
 * journal_clean_one_cp_list
 *
 * Find all the written-back checkpoint buffers in the given list and release
 * them.
 *
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
		/* Use trylock because of the ranking */
		if (jbd_trylock_bh_state(jh2bh(jh))) {
			ret = __try_to_free_cp_buf(jh);
			if (ret) {
				freed++;
				if (ret == 2) {
					*released = 1;
					return freed;
				}
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

int __journal_clean_checkpoint_list(journal_t *journal)
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
 * This function is called with jbd_lock_bh_state(jh2bh(jh))
 */

int __journal_remove_checkpoint(struct journal_head *jh)
{
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
	journal_put_journal_head(jh);

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
	 * See the comment at the end of journal_commit_transaction().
	 */
	if (transaction->t_state != T_FINISHED)
		goto out;

	/* OK, that was the last buffer for the transaction: we can now
	   safely remove this transaction from the log */

	__journal_drop_transaction(journal, transaction);

	/* Just in case anybody was waiting for more transactions to be
           checkpointed... */
	wake_up(&journal->j_wait_logspace);
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
void __journal_insert_checkpoint(struct journal_head *jh,
			       transaction_t *transaction)
{
	JBUFFER_TRACE(jh, "entry");
	J_ASSERT_JH(jh, buffer_dirty(jh2bh(jh)) || buffer_jbddirty(jh2bh(jh)));
	J_ASSERT_JH(jh, jh->b_cp_transaction == NULL);

	/* Get reference for checkpointing transaction */
	journal_grab_journal_head(jh2bh(jh));
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

void __journal_drop_transaction(journal_t *journal, transaction_t *transaction)
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
	J_ASSERT(transaction->t_sync_datalist == NULL);
	J_ASSERT(transaction->t_forget == NULL);
	J_ASSERT(transaction->t_iobuf_list == NULL);
	J_ASSERT(transaction->t_shadow_list == NULL);
	J_ASSERT(transaction->t_log_list == NULL);
	J_ASSERT(transaction->t_checkpoint_list == NULL);
	J_ASSERT(transaction->t_checkpoint_io_list == NULL);
	J_ASSERT(transaction->t_updates == 0);
	J_ASSERT(journal->j_committing_transaction != transaction);
	J_ASSERT(journal->j_running_transaction != transaction);

	trace_jbd_drop_transaction(journal, transaction);
	jbd_debug(1, "Dropping transaction %d, all done\n", transaction->t_tid);
	kfree(transaction);
}
/************************************************************/
/* ../linux-3.17/fs/jbd/checkpoint.c */
/************************************************************/
/*
 * linux/fs/jbd/revoke.c
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
// #include <linux/jbd.h>
// #include <linux/errno.h>
// #include <linux/slab.h>
#include <linux/list.h>
#include <linux/init.h>
// #include <linux/bio.h>
#endif
#include <linux/log2.h>

static struct kmem_cache *revoke_record_cache;
static struct kmem_cache *revoke_table_cache;

/* Each revoke record represents one single revoked block.  During
   journal replay, this involves recording the transaction ID of the
   last transaction to revoke this block. */

struct jbd_revoke_record_s
{
	struct list_head  hash;
	tid_t		  sequence;	/* Used for recovery only */
	unsigned int	  blocknr;
};


/* The revoke table is just a simple hash table of revoke records. */
struct jbd_revoke_table_s
{
	/* It is conceivable that we might want a larger hash table
	 * for recovery.  Must be a power of two. */
	int		  hash_size;
	int		  hash_shift;
	struct list_head *hash_table;
};


#ifdef __KERNEL__
static void write_one_revoke_record(journal_t *, transaction_t *,
				    struct journal_head **, int *,
				    struct jbd_revoke_record_s *, int);
static void flush_descriptor(journal_t *, struct journal_head *, int, int);
#endif

/* Utility functions to maintain the revoke table */

/* Borrowed from buffer.c: this is a tried and tested block hash function */
static inline int hash(journal_t *journal, unsigned int block)
{
	struct jbd_revoke_table_s *table = journal->j_revoke;
	int hash_shift = table->hash_shift;

	return ((block << (hash_shift - 6)) ^
		(block >> 13) ^
		(block << (hash_shift - 12))) & (table->hash_size - 1);
}

static int insert_revoke_hash(journal_t *journal, unsigned int blocknr,
			      tid_t seq)
{
	struct list_head *hash_list;
	struct jbd_revoke_record_s *record;

repeat:
	record = kmem_cache_alloc(revoke_record_cache, GFP_NOFS);
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

static struct jbd_revoke_record_s *find_revoke_record(journal_t *journal,
						      unsigned int blocknr)
{
	struct list_head *hash_list;
	struct jbd_revoke_record_s *record;

	hash_list = &journal->j_revoke->hash_table[hash(journal, blocknr)];

	spin_lock(&journal->j_revoke_lock);
	record = (struct jbd_revoke_record_s *) hash_list->next;
	while (&(record->hash) != hash_list) {
		if (record->blocknr == blocknr) {
			spin_unlock(&journal->j_revoke_lock);
			return record;
		}
		record = (struct jbd_revoke_record_s *) record->hash.next;
	}
	spin_unlock(&journal->j_revoke_lock);
	return NULL;
}

void journal_destroy_revoke_caches(void)
{
	if (revoke_record_cache) {
		kmem_cache_destroy(revoke_record_cache);
		revoke_record_cache = NULL;
	}
	if (revoke_table_cache) {
		kmem_cache_destroy(revoke_table_cache);
		revoke_table_cache = NULL;
	}
}

int __init journal_init_revoke_caches(void)
{
	J_ASSERT(!revoke_record_cache);
	J_ASSERT(!revoke_table_cache);

	revoke_record_cache = kmem_cache_create("revoke_record",
					   sizeof(struct jbd_revoke_record_s),
					   0,
					   SLAB_HWCACHE_ALIGN|SLAB_TEMPORARY,
					   NULL);
	if (!revoke_record_cache)
		goto record_cache_failure;

	revoke_table_cache = kmem_cache_create("revoke_table",
					   sizeof(struct jbd_revoke_table_s),
					   0, SLAB_TEMPORARY, NULL);
	if (!revoke_table_cache)
		goto table_cache_failure;

	return 0;

table_cache_failure:
	journal_destroy_revoke_caches();
record_cache_failure:
	return -ENOMEM;
}

static struct jbd_revoke_table_s *journal_init_revoke_table(int hash_size)
{
	int i;
	struct jbd_revoke_table_s *table;

	table = kmem_cache_alloc(revoke_table_cache, GFP_KERNEL);
	if (!table)
		goto out;

	table->hash_size = hash_size;
	table->hash_shift = ilog2(hash_size);
	table->hash_table =
		kmalloc(hash_size * sizeof(struct list_head), GFP_KERNEL);
	if (!table->hash_table) {
		kmem_cache_free(revoke_table_cache, table);
		table = NULL;
		goto out;
	}

	for (i = 0; i < hash_size; i++)
		INIT_LIST_HEAD(&table->hash_table[i]);

out:
	return table;
}

static void journal_destroy_revoke_table(struct jbd_revoke_table_s *table)
{
	int i;
	struct list_head *hash_list;

	for (i = 0; i < table->hash_size; i++) {
		hash_list = &table->hash_table[i];
		J_ASSERT(list_empty(hash_list));
	}

	kfree(table->hash_table);
	kmem_cache_free(revoke_table_cache, table);
}

/* Initialise the revoke table for a given journal to a given size. */
int journal_init_revoke(journal_t *journal, int hash_size)
{
	J_ASSERT(journal->j_revoke_table[0] == NULL);
	J_ASSERT(is_power_of_2(hash_size));

	journal->j_revoke_table[0] = journal_init_revoke_table(hash_size);
	if (!journal->j_revoke_table[0])
		goto fail0;

	journal->j_revoke_table[1] = journal_init_revoke_table(hash_size);
	if (!journal->j_revoke_table[1])
		goto fail1;

	journal->j_revoke = journal->j_revoke_table[1];

	spin_lock_init(&journal->j_revoke_lock);

	return 0;

fail1:
	journal_destroy_revoke_table(journal->j_revoke_table[0]);
fail0:
	return -ENOMEM;
}

/* Destroy a journal's revoke table.  The table must already be empty! */
void journal_destroy_revoke(journal_t *journal)
{
	journal->j_revoke = NULL;
	if (journal->j_revoke_table[0])
		journal_destroy_revoke_table(journal->j_revoke_table[0]);
	if (journal->j_revoke_table[1])
		journal_destroy_revoke_table(journal->j_revoke_table[1]);
}


#ifdef __KERNEL__

/*
 * journal_revoke: revoke a given buffer_head from the journal.  This
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
 * Revoke performs a journal_forget on any buffer_head passed in as a
 * parameter, but does _not_ forget the buffer_head if the bh was only
 * found implicitly.
 *
 * bh_in may not be a journalled buffer - it may have come off
 * the hash tables without an attached journal_head.
 *
 * If bh_in is non-zero, journal_revoke() will decrement its b_count
 * by one.
 */

int journal_revoke(handle_t *handle, unsigned int blocknr,
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
	if (!journal_set_features(journal, 0, 0, JFS_FEATURE_INCOMPAT_REVOKE)){
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
#ifdef JBD_EXPENSIVE_CHECKING
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
			BUFFER_TRACE(bh_in, "call journal_forget");
			journal_forget(handle, bh_in);
		} else {
			BUFFER_TRACE(bh, "call brelse");
			__brelse(bh);
		}
	}

	jbd_debug(2, "insert revoke for block %u, bh_in=%p\n", blocknr, bh_in);
	err = insert_revoke_hash(journal, blocknr,
				handle->h_transaction->t_tid);
	BUFFER_TRACE(bh_in, "exit");
	return err;
}

/*
 * Cancel an outstanding revoke.  For use only internally by the
 * journaling code (called from journal_get_write_access).
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
int journal_cancel_revoke(handle_t *handle, struct journal_head *jh)
{
	struct jbd_revoke_record_s *record;
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
			kmem_cache_free(revoke_record_cache, record);
			did_revoke = 1;
		}
	}

#ifdef JBD_EXPENSIVE_CHECKING
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
 * journal_clear_revoked_flags clears revoked flag of buffers in
 * revoke table to reflect there is no revoked buffer in the next
 * transaction which is going to be started.
 */
void journal_clear_buffer_revoked_flags(journal_t *journal)
{
	struct jbd_revoke_table_s *revoke = journal->j_revoke;
	int i = 0;

	for (i = 0; i < revoke->hash_size; i++) {
		struct list_head *hash_list;
		struct list_head *list_entry;
		hash_list = &revoke->hash_table[i];

		list_for_each(list_entry, hash_list) {
			struct jbd_revoke_record_s *record;
			struct buffer_head *bh;
			record = (struct jbd_revoke_record_s *)list_entry;
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
void journal_switch_revoke_table(journal_t *journal)
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
void journal_write_revoke_records(journal_t *journal,
				  transaction_t *transaction, int write_op)
{
	struct journal_head *descriptor;
	struct jbd_revoke_record_s *record;
	struct jbd_revoke_table_s *revoke;
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
			record = (struct jbd_revoke_record_s *)
				hash_list->next;
			write_one_revoke_record(journal, transaction,
						&descriptor, &offset,
						record, write_op);
			count++;
			list_del(&record->hash);
			kmem_cache_free(revoke_record_cache, record);
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
				    struct journal_head **descriptorp,
				    int *offsetp,
				    struct jbd_revoke_record_s *record,
				    int write_op)
{
	struct journal_head *descriptor;
	int offset;
	journal_header_t *header;

	/* If we are already aborting, this all becomes a noop.  We
           still need to go round the loop in
           journal_write_revoke_records in order to free all of the
           revoke records: only the IO to the journal is omitted. */
	if (is_journal_aborted(journal))
		return;

	descriptor = *descriptorp;
	offset = *offsetp;

	/* Make sure we have a descriptor with space left for the record */
	if (descriptor) {
		if (offset == journal->j_blocksize) {
			flush_descriptor(journal, descriptor, offset, write_op);
			descriptor = NULL;
		}
	}

	if (!descriptor) {
		descriptor = journal_get_descriptor_buffer(journal);
		if (!descriptor)
			return;
		header = (journal_header_t *) &jh2bh(descriptor)->b_data[0];
		header->h_magic     = cpu_to_be32(JFS_MAGIC_NUMBER);
		header->h_blocktype = cpu_to_be32(JFS_REVOKE_BLOCK);
		header->h_sequence  = cpu_to_be32(transaction->t_tid);

		/* Record it so that we can wait for IO completion later */
		JBUFFER_TRACE(descriptor, "file as BJ_LogCtl");
		journal_file_buffer(descriptor, transaction, BJ_LogCtl);

		offset = sizeof(journal_revoke_header_t);
		*descriptorp = descriptor;
	}

	* ((__be32 *)(&jh2bh(descriptor)->b_data[offset])) =
		cpu_to_be32(record->blocknr);
	offset += 4;
	*offsetp = offset;
}

/*
 * Flush a revoke descriptor out to the journal.  If we are aborting,
 * this is a noop; otherwise we are generating a buffer which needs to
 * be waited for during commit, so it has to go onto the appropriate
 * journal buffer list.
 */

static void flush_descriptor(journal_t *journal,
			     struct journal_head *descriptor,
			     int offset, int write_op)
{
	journal_revoke_header_t *header;
	struct buffer_head *bh = jh2bh(descriptor);

	if (is_journal_aborted(journal)) {
		put_bh(bh);
		return;
	}

	header = (journal_revoke_header_t *) jh2bh(descriptor)->b_data;
	header->r_count = cpu_to_be32(offset);
	set_buffer_jwrite(bh);
	BUFFER_TRACE(bh, "write");
	set_buffer_dirty(bh);
	write_dirty_buffer(bh, write_op);
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

int journal_set_revoke(journal_t *journal,
		       unsigned int blocknr,
		       tid_t sequence)
{
	struct jbd_revoke_record_s *record;

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

int journal_test_revoke(journal_t *journal,
			unsigned int blocknr,
			tid_t sequence)
{
	struct jbd_revoke_record_s *record;

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

void journal_clear_revoke(journal_t *journal)
{
	int i;
	struct list_head *hash_list;
	struct jbd_revoke_record_s *record;
	struct jbd_revoke_table_s *revoke;

	revoke = journal->j_revoke;

	for (i = 0; i < revoke->hash_size; i++) {
		hash_list = &revoke->hash_table[i];
		while (!list_empty(hash_list)) {
			record = (struct jbd_revoke_record_s*) hash_list->next;
			list_del(&record->hash);
			kmem_cache_free(revoke_record_cache, record);
		}
	}
}
/************************************************************/
/* ../linux-3.17/fs/jbd/revoke.c */
/************************************************************/
/*
 * linux/fs/jbd/journal.c
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

#include <linux/module.h>
// #include <linux/time.h>
// #include <linux/fs.h>
// #include <linux/jbd.h>
// #include <linux/errno.h>
// #include <linux/slab.h>
// #include <linux/init.h>
// #include <linux/mm.h>
#include <linux/freezer.h>
// #include <linux/pagemap.h>
#include <linux/kthread.h>
#include <linux/poison.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/ratelimit.h>

#define CREATE_TRACE_POINTS
// #include <trace/events/jbd.h>

#include <asm/uaccess.h>
#include <asm/page.h>

EXPORT_SYMBOL(journal_start);
EXPORT_SYMBOL(journal_restart);
EXPORT_SYMBOL(journal_extend);
EXPORT_SYMBOL(journal_stop);
EXPORT_SYMBOL(journal_lock_updates);
EXPORT_SYMBOL(journal_unlock_updates);
EXPORT_SYMBOL(journal_get_write_access);
EXPORT_SYMBOL(journal_get_create_access);
EXPORT_SYMBOL(journal_get_undo_access);
EXPORT_SYMBOL(journal_dirty_data);
EXPORT_SYMBOL(journal_dirty_metadata);
EXPORT_SYMBOL(journal_release_buffer);
EXPORT_SYMBOL(journal_forget);
#if 0
EXPORT_SYMBOL(journal_sync_buffer);
#endif
EXPORT_SYMBOL(journal_flush);
EXPORT_SYMBOL(journal_revoke);

EXPORT_SYMBOL(journal_init_dev);
EXPORT_SYMBOL(journal_init_inode);
EXPORT_SYMBOL(journal_update_format);
EXPORT_SYMBOL(journal_check_used_features);
EXPORT_SYMBOL(journal_check_available_features);
EXPORT_SYMBOL(journal_set_features);
EXPORT_SYMBOL(journal_create);
EXPORT_SYMBOL(journal_load);
EXPORT_SYMBOL(journal_destroy);
EXPORT_SYMBOL(journal_abort);
EXPORT_SYMBOL(journal_errno);
EXPORT_SYMBOL(journal_ack_err);
EXPORT_SYMBOL(journal_clear_err);
EXPORT_SYMBOL(log_wait_commit);
EXPORT_SYMBOL(log_start_commit);
EXPORT_SYMBOL(journal_start_commit);
EXPORT_SYMBOL(journal_force_commit_nested);
EXPORT_SYMBOL(journal_wipe);
EXPORT_SYMBOL(journal_blocks_per_page);
EXPORT_SYMBOL(journal_invalidatepage);
EXPORT_SYMBOL(journal_try_to_free_buffers);
EXPORT_SYMBOL(journal_force_commit);

static int journal_convert_superblock_v1(journal_t *, journal_superblock_t *);
static void __journal_abort_soft (journal_t *journal, int errno);
static const char *journal_dev_name(journal_t *journal, char *buffer);

#ifdef CONFIG_JBD_DEBUG
void __jbd_debug(int level, const char *file, const char *func,
		 unsigned int line, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	if (level > journal_enable_debug)
		return;
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk(KERN_DEBUG "%s: (%s, %u): %pV\n", file, func, line, &vaf);
	va_end(args);
}
EXPORT_SYMBOL(__jbd_debug);
#endif

/*
 * Helper function used to manage commit timeouts
 */

static void commit_timeout(unsigned long __data)
{
	struct task_struct * p = (struct task_struct *) __data;

	wake_up_process(p);
}

/*
 * kjournald: The main thread function used to manage a logging device
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

static int kjournald(void *arg)
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

	printk(KERN_INFO "kjournald starting.  Commit interval %ld seconds\n",
			journal->j_commit_interval / HZ);

	/*
	 * And now, wait forever for commit wakeup events.
	 */
	spin_lock(&journal->j_state_lock);

loop:
	if (journal->j_flags & JFS_UNMOUNT)
		goto end_loop;

	jbd_debug(1, "commit_sequence=%d, commit_request=%d\n",
		journal->j_commit_sequence, journal->j_commit_request);

	if (journal->j_commit_sequence != journal->j_commit_request) {
		jbd_debug(1, "OK, requests differ\n");
		spin_unlock(&journal->j_state_lock);
		del_timer_sync(&journal->j_commit_timer);
		journal_commit_transaction(journal);
		spin_lock(&journal->j_state_lock);
		goto loop;
	}

	wake_up(&journal->j_wait_done_commit);
	if (freezing(current)) {
		/*
		 * The simpler the better. Flushing journal isn't a
		 * good idea, because that depends on threads that may
		 * be already stopped.
		 */
		jbd_debug(1, "Now suspending kjournald\n");
		spin_unlock(&journal->j_state_lock);
		try_to_freeze();
		spin_lock(&journal->j_state_lock);
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
		if (journal->j_flags & JFS_UNMOUNT)
			should_sleep = 0;
		if (should_sleep) {
			spin_unlock(&journal->j_state_lock);
			schedule();
			spin_lock(&journal->j_state_lock);
		}
		finish_wait(&journal->j_wait_commit, &wait);
	}

	jbd_debug(1, "kjournald wakes\n");

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
	spin_unlock(&journal->j_state_lock);
	del_timer_sync(&journal->j_commit_timer);
	journal->j_task = NULL;
	wake_up(&journal->j_wait_done_commit);
	jbd_debug(1, "Journal thread exiting.\n");
	return 0;
}

static int journal_start_thread(journal_t *journal)
{
	struct task_struct *t;

	t = kthread_run(kjournald, journal, "kjournald");
	if (IS_ERR(t))
		return PTR_ERR(t);

	wait_event(journal->j_wait_done_commit, journal->j_task != NULL);
	return 0;
}

static void journal_kill_thread(journal_t *journal)
{
	spin_lock(&journal->j_state_lock);
	journal->j_flags |= JFS_UNMOUNT;

	while (journal->j_task) {
		wake_up(&journal->j_wait_commit);
		spin_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_done_commit,
				journal->j_task == NULL);
		spin_lock(&journal->j_state_lock);
	}
	spin_unlock(&journal->j_state_lock);
}

/*
 * journal_write_metadata_buffer: write a metadata buffer to the journal.
 *
 * Writes a metadata buffer to a given disk block.  The actual IO is not
 * performed but a new buffer_head is constructed which labels the data
 * to be written with the correct destination disk block.
 *
 * Any magic-number escaping which needs to be done will cause a
 * copy-out here.  If the buffer happens to start with the
 * JFS_MAGIC_NUMBER, then we can't write it to the log directly: the
 * magic number is only written to the log for descripter blocks.  In
 * this case, we copy the data and replace the first word with 0, and we
 * return a result code which indicates that this buffer needs to be
 * marked as an escaped buffer in the corresponding log descriptor
 * block.  The missing word can then be restored when the block is read
 * during recovery.
 *
 * If the source buffer has already been modified by a new transaction
 * since we took the last commit snapshot, we use the frozen copy of
 * that data for IO.  If we end up using the existing buffer_head's data
 * for the write, then we *have* to lock the buffer to prevent anyone
 * else from using and possibly modifying it while the IO is in
 * progress.
 *
 * The function returns a pointer to the buffer_heads to be used for IO.
 *
 * We assume that the journal has already been locked in this function.
 *
 * Return value:
 *  <0: Error
 * >=0: Finished OK
 *
 * On success:
 * Bit 0 set == escape performed on the data
 * Bit 1 set == buffer copy-out performed (kfree the data after IO)
 */

int journal_write_metadata_buffer(transaction_t *transaction,
				  struct journal_head  *jh_in,
				  struct journal_head **jh_out,
				  unsigned int blocknr)
{
	int need_copy_out = 0;
	int done_copy_out = 0;
	int do_escape = 0;
	char *mapped_data;
	struct buffer_head *new_bh;
	struct journal_head *new_jh;
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

	new_bh = alloc_buffer_head(GFP_NOFS|__GFP_NOFAIL);
	/* keep subsequent assertions sane */
	atomic_set(&new_bh->b_count, 1);
	new_jh = journal_add_journal_head(new_bh);	/* This sleeps */

	/*
	 * If a new transaction has already done a buffer copy-out, then
	 * we use that version of the data for the commit.
	 */
	jbd_lock_bh_state(bh_in);
repeat:
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
	 * Check for escaping
	 */
	if (*((__be32 *)(mapped_data + new_offset)) ==
				cpu_to_be32(JFS_MAGIC_NUMBER)) {
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
		tmp = jbd_alloc(bh_in->b_size, GFP_NOFS);
		jbd_lock_bh_state(bh_in);
		if (jh_in->b_frozen_data) {
			jbd_free(tmp, bh_in->b_size);
			goto repeat;
		}

		jh_in->b_frozen_data = tmp;
		mapped_data = kmap_atomic(new_page);
		memcpy(tmp, mapped_data + new_offset, jh2bh(jh_in)->b_size);
		kunmap_atomic(mapped_data);

		new_page = virt_to_page(tmp);
		new_offset = offset_in_page(tmp);
		done_copy_out = 1;
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
	new_jh->b_transaction = NULL;
	new_bh->b_size = jh2bh(jh_in)->b_size;
	new_bh->b_bdev = transaction->t_journal->j_dev;
	new_bh->b_blocknr = blocknr;
	set_buffer_mapped(new_bh);
	set_buffer_dirty(new_bh);

	*jh_out = new_jh;

	/*
	 * The to-be-written buffer needs to get moved to the io queue,
	 * and the original buffer whose contents we are shadowing or
	 * copying is moved to the transaction's shadow queue.
	 */
	JBUFFER_TRACE(jh_in, "file as BJ_Shadow");
	spin_lock(&journal->j_list_lock);
	__journal_file_buffer(jh_in, transaction, BJ_Shadow);
	spin_unlock(&journal->j_list_lock);
	jbd_unlock_bh_state(bh_in);

	JBUFFER_TRACE(new_jh, "file as BJ_IO");
	journal_file_buffer(new_jh, transaction, BJ_IO);

	return do_escape | (done_copy_out << 1);
}

/*
 * Allocation code for the journal file.  Manage the space left in the
 * journal, so that we can begin checkpointing when appropriate.
 */

/*
 * __log_space_left: Return the number of free blocks left in the journal.
 *
 * Called with the journal already locked.
 *
 * Called under j_state_lock
 */

int __log_space_left(journal_t *journal)
{
	int left = journal->j_free;

	assert_spin_locked(&journal->j_state_lock);

	/*
	 * Be pessimistic here about the number of those free blocks which
	 * might be required for log descriptor control blocks.
	 */

#define MIN_LOG_RESERVED_BLOCKS 32 /* Allow for rounding errors */

	left -= MIN_LOG_RESERVED_BLOCKS;

	if (left <= 0)
		return 0;
	left -= (left >> 3);
	return left;
}

/*
 * Called under j_state_lock.  Returns true if a transaction commit was started.
 */
int __log_start_commit(journal_t *journal, tid_t target)
{
	/*
	 * The only transaction we can possibly wait upon is the
	 * currently running transaction (if it exists).  Otherwise,
	 * the target tid must be an old one.
	 */
	if (journal->j_commit_request != target &&
	    journal->j_running_transaction &&
	    journal->j_running_transaction->t_tid == target) {
		/*
		 * We want a new commit: OK, mark the request and wakeup the
		 * commit thread.  We do _not_ do the commit ourselves.
		 */

		journal->j_commit_request = target;
		jbd_debug(1, "JBD: requesting commit %d/%d\n",
			  journal->j_commit_request,
			  journal->j_commit_sequence);
		wake_up(&journal->j_wait_commit);
		return 1;
	} else if (!tid_geq(journal->j_commit_request, target))
		/* This should never happen, but if it does, preserve
		   the evidence before kjournald goes into a loop and
		   increments j_commit_sequence beyond all recognition. */
		WARN_ONCE(1, "jbd: bad log_start_commit: %u %u %u %u\n",
		    journal->j_commit_request, journal->j_commit_sequence,
		    target, journal->j_running_transaction ?
		    journal->j_running_transaction->t_tid : 0);
	return 0;
}

int log_start_commit(journal_t *journal, tid_t tid)
{
	int ret;

	spin_lock(&journal->j_state_lock);
	ret = __log_start_commit(journal, tid);
	spin_unlock(&journal->j_state_lock);
	return ret;
}

/*
 * Force and wait upon a commit if the calling process is not within
 * transaction.  This is used for forcing out undo-protected data which contains
 * bitmaps, when the fs is running out of space.
 *
 * We can only force the running transaction if we don't have an active handle;
 * otherwise, we will deadlock.
 *
 * Returns true if a transaction was started.
 */
int journal_force_commit_nested(journal_t *journal)
{
	transaction_t *transaction = NULL;
	tid_t tid;

	spin_lock(&journal->j_state_lock);
	if (journal->j_running_transaction && !current->journal_info) {
		transaction = journal->j_running_transaction;
		__log_start_commit(journal, transaction->t_tid);
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	if (!transaction) {
		spin_unlock(&journal->j_state_lock);
		return 0;	/* Nothing to retry */
	}

	tid = transaction->t_tid;
	spin_unlock(&journal->j_state_lock);
	log_wait_commit(journal, tid);
	return 1;
}

/*
 * Start a commit of the current running transaction (if any).  Returns true
 * if a transaction is going to be committed (or is currently already
 * committing), and fills its tid in at *ptid
 */
int journal_start_commit(journal_t *journal, tid_t *ptid)
{
	int ret = 0;

	spin_lock(&journal->j_state_lock);
	if (journal->j_running_transaction) {
		tid_t tid = journal->j_running_transaction->t_tid;

		__log_start_commit(journal, tid);
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
	spin_unlock(&journal->j_state_lock);
	return ret;
}

/*
 * Wait for a specified commit to complete.
 * The caller may not hold the journal lock.
 */
int log_wait_commit(journal_t *journal, tid_t tid)
{
	int err = 0;

#ifdef CONFIG_JBD_DEBUG
	spin_lock(&journal->j_state_lock);
	if (!tid_geq(journal->j_commit_request, tid)) {
		printk(KERN_ERR
		       "%s: error: j_commit_request=%d, tid=%d\n",
		       __func__, journal->j_commit_request, tid);
	}
	spin_unlock(&journal->j_state_lock);
#endif
	spin_lock(&journal->j_state_lock);
	/*
	 * Not running or committing trans? Must be already committed. This
	 * saves us from waiting for a *long* time when tid overflows.
	 */
	if (!((journal->j_running_transaction &&
	       journal->j_running_transaction->t_tid == tid) ||
	      (journal->j_committing_transaction &&
	       journal->j_committing_transaction->t_tid == tid)))
		goto out_unlock;

	if (!tid_geq(journal->j_commit_waited, tid))
		journal->j_commit_waited = tid;
	while (tid_gt(tid, journal->j_commit_sequence)) {
		jbd_debug(1, "JBD: want %d, j_commit_sequence=%d\n",
				  tid, journal->j_commit_sequence);
		wake_up(&journal->j_wait_commit);
		spin_unlock(&journal->j_state_lock);
		wait_event(journal->j_wait_done_commit,
				!tid_gt(tid, journal->j_commit_sequence));
		spin_lock(&journal->j_state_lock);
	}
out_unlock:
	spin_unlock(&journal->j_state_lock);

	if (unlikely(is_journal_aborted(journal)))
		err = -EIO;
	return err;
}

/*
 * Return 1 if a given transaction has not yet sent barrier request
 * connected with a transaction commit. If 0 is returned, transaction
 * may or may not have sent the barrier. Used to avoid sending barrier
 * twice in common cases.
 */
int journal_trans_will_send_data_barrier(journal_t *journal, tid_t tid)
{
	int ret = 0;
	transaction_t *commit_trans;

	if (!(journal->j_flags & JFS_BARRIER))
		return 0;
	spin_lock(&journal->j_state_lock);
	/* Transaction already committed? */
	if (tid_geq(journal->j_commit_sequence, tid))
		goto out;
	/*
	 * Transaction is being committed and we already proceeded to
	 * writing commit record?
	 */
	commit_trans = journal->j_committing_transaction;
	if (commit_trans && commit_trans->t_tid == tid &&
	    commit_trans->t_state >= T_COMMIT_RECORD)
		goto out;
	ret = 1;
out:
	spin_unlock(&journal->j_state_lock);
	return ret;
}
EXPORT_SYMBOL(journal_trans_will_send_data_barrier);

/*
 * Log buffer allocation routines:
 */

int journal_next_log_block(journal_t *journal, unsigned int *retp)
{
	unsigned int blocknr;

	spin_lock(&journal->j_state_lock);
	J_ASSERT(journal->j_free > 1);

	blocknr = journal->j_head;
	journal->j_head++;
	journal->j_free--;
	if (journal->j_head == journal->j_last)
		journal->j_head = journal->j_first;
	spin_unlock(&journal->j_state_lock);
	return journal_bmap(journal, blocknr, retp);
}

/*
 * Conversion of logical to physical block numbers for the journal
 *
 * On external journals the journal blocks are identity-mapped, so
 * this is a no-op.  If needed, we can use j_blk_offset - everything is
 * ready.
 */
int journal_bmap(journal_t *journal, unsigned int blocknr,
		 unsigned int *retp)
{
	int err = 0;
	unsigned int ret;

	if (journal->j_inode) {
		ret = bmap(journal->j_inode, blocknr);
		if (ret)
			*retp = ret;
		else {
			char b[BDEVNAME_SIZE];

			printk(KERN_ALERT "%s: journal block not found "
					"at offset %u on %s\n",
				__func__,
				blocknr,
				bdevname(journal->j_dev, b));
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
 * After the caller of journal_get_descriptor_buffer() has finished modifying
 * the buffer's contents they really should run flush_dcache_page(bh->b_page).
 * But we don't bother doing that, so there will be coherency problems with
 * mmaps of blockdevs which hold live JBD-controlled filesystems.
 */
struct journal_head *journal_get_descriptor_buffer(journal_t *journal)
{
	struct buffer_head *bh;
	unsigned int blocknr;
	int err;

	err = journal_next_log_block(journal, &blocknr);

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
	return journal_add_journal_head(bh);
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
		goto fail;

	init_waitqueue_head(&journal->j_wait_transaction_locked);
	init_waitqueue_head(&journal->j_wait_logspace);
	init_waitqueue_head(&journal->j_wait_done_commit);
	init_waitqueue_head(&journal->j_wait_checkpoint);
	init_waitqueue_head(&journal->j_wait_commit);
	init_waitqueue_head(&journal->j_wait_updates);
	mutex_init(&journal->j_checkpoint_mutex);
	spin_lock_init(&journal->j_revoke_lock);
	spin_lock_init(&journal->j_list_lock);
	spin_lock_init(&journal->j_state_lock);

	journal->j_commit_interval = (HZ * JBD_DEFAULT_MAX_COMMIT_AGE);

	/* The journal is marked for error until we succeed with recovery! */
	journal->j_flags = JFS_ABORT;

	/* Set up a default-sized revoke table for the new mount. */
	err = journal_init_revoke(journal, JOURNAL_REVOKE_DEFAULT_HASH);
	if (err) {
		kfree(journal);
		goto fail;
	}
	return journal;
fail:
	return NULL;
}

/* journal_init_dev and journal_init_inode:
 *
 * Create a journal structure assigned some fixed set of disk blocks to
 * the journal.  We don't actually touch those disk blocks yet, but we
 * need to set up all of the mapping information to tell the journaling
 * system where the journal blocks are.
 *
 */

/**
 *  journal_t * journal_init_dev() - creates and initialises a journal structure
 *  @bdev: Block device on which to create the journal
 *  @fs_dev: Device which hold journalled filesystem for this journal.
 *  @start: Block nr Start of journal.
 *  @len:  Length of the journal in blocks.
 *  @blocksize: blocksize of journalling device
 *
 *  Returns: a newly created journal_t *
 *
 *  journal_init_dev creates a journal which maps a fixed contiguous
 *  range of blocks on an arbitrary block device.
 *
 */
journal_t * journal_init_dev(struct block_device *bdev,
			struct block_device *fs_dev,
			int start, int len, int blocksize)
{
	journal_t *journal = journal_init_common();
	struct buffer_head *bh;
	int n;

	if (!journal)
		return NULL;

	/* journal descriptor can store up to n blocks -bzzz */
	journal->j_blocksize = blocksize;
	n = journal->j_blocksize / sizeof(journal_block_tag_t);
	journal->j_wbufsize = n;
	journal->j_wbuf = kmalloc(n * sizeof(struct buffer_head*), GFP_KERNEL);
	if (!journal->j_wbuf) {
		printk(KERN_ERR "%s: Can't allocate bhs for commit thread\n",
			__func__);
		goto out_err;
	}
	journal->j_dev = bdev;
	journal->j_fs_dev = fs_dev;
	journal->j_blk_offset = start;
	journal->j_maxlen = len;

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
	kfree(journal);
	return NULL;
}

/**
 *  journal_t * journal_init_inode () - creates a journal which maps to a inode.
 *  @inode: An inode to create the journal in
 *
 * journal_init_inode creates a journal which maps an on-disk inode as
 * the journal.  The inode must exist already, must support bmap() and
 * must have all data blocks preallocated.
 */
journal_t * journal_init_inode (struct inode *inode)
{
	struct buffer_head *bh;
	journal_t *journal = journal_init_common();
	int err;
	int n;
	unsigned int blocknr;

	if (!journal)
		return NULL;

	journal->j_dev = journal->j_fs_dev = inode->i_sb->s_bdev;
	journal->j_inode = inode;
	jbd_debug(1,
		  "journal %p: inode %s/%ld, size %Ld, bits %d, blksize %ld\n",
		  journal, inode->i_sb->s_id, inode->i_ino,
		  (long long) inode->i_size,
		  inode->i_sb->s_blocksize_bits, inode->i_sb->s_blocksize);

	journal->j_maxlen = inode->i_size >> inode->i_sb->s_blocksize_bits;
	journal->j_blocksize = inode->i_sb->s_blocksize;

	/* journal descriptor can store up to n blocks -bzzz */
	n = journal->j_blocksize / sizeof(journal_block_tag_t);
	journal->j_wbufsize = n;
	journal->j_wbuf = kmalloc(n * sizeof(struct buffer_head*), GFP_KERNEL);
	if (!journal->j_wbuf) {
		printk(KERN_ERR "%s: Can't allocate bhs for commit thread\n",
			__func__);
		goto out_err;
	}

	err = journal_bmap(journal, 0, &blocknr);
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
	unsigned int first, last;

	first = be32_to_cpu(sb->s_first);
	last = be32_to_cpu(sb->s_maxlen);
	if (first + JFS_MIN_JOURNAL_BLOCKS > last + 1) {
		printk(KERN_ERR "JBD: Journal too short (blocks %u-%u).\n",
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
	 * update until the next commit by setting JFS_FLUSHED.  This avoids
	 * attempting a write to a potential-readonly device.
	 */
	if (sb->s_start == 0) {
		jbd_debug(1,"JBD: Skipping superblock update on recovered sb "
			"(start %u, seq %d, errno %d)\n",
			journal->j_tail, journal->j_tail_sequence,
			journal->j_errno);
		journal->j_flags |= JFS_FLUSHED;
	} else {
		/* Lock here to make assertions happy... */
		mutex_lock(&journal->j_checkpoint_mutex);
		/*
		 * Update log tail information. We use WRITE_FUA since new
		 * transaction will start reusing journal space and so we
		 * must make sure information about current log tail is on
		 * disk before that.
		 */
		journal_update_sb_log_tail(journal,
					   journal->j_tail_sequence,
					   journal->j_tail,
					   WRITE_FUA);
		mutex_unlock(&journal->j_checkpoint_mutex);
	}
	return journal_start_thread(journal);
}

/**
 * int journal_create() - Initialise the new journal file
 * @journal: Journal to create. This structure must have been initialised
 *
 * Given a journal_t structure which tells us which disk blocks we can
 * use, create a new journal superblock and initialise all of the
 * journal fields from scratch.
 **/
int journal_create(journal_t *journal)
{
	unsigned int blocknr;
	struct buffer_head *bh;
	journal_superblock_t *sb;
	int i, err;

	if (journal->j_maxlen < JFS_MIN_JOURNAL_BLOCKS) {
		printk (KERN_ERR "Journal length (%d blocks) too short.\n",
			journal->j_maxlen);
		journal_fail_superblock(journal);
		return -EINVAL;
	}

	if (journal->j_inode == NULL) {
		/*
		 * We don't know what block to start at!
		 */
		printk(KERN_EMERG
		       "%s: creation of journal on external device!\n",
		       __func__);
		BUG();
	}

	/* Zero out the entire journal on disk.  We cannot afford to
	   have any blocks on disk beginning with JFS_MAGIC_NUMBER. */
	jbd_debug(1, "JBD: Zeroing out journal blocks...\n");
	for (i = 0; i < journal->j_maxlen; i++) {
		err = journal_bmap(journal, i, &blocknr);
		if (err)
			return err;
		bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
		if (unlikely(!bh))
			return -ENOMEM;
		lock_buffer(bh);
		memset (bh->b_data, 0, journal->j_blocksize);
		BUFFER_TRACE(bh, "marking dirty");
		mark_buffer_dirty(bh);
		BUFFER_TRACE(bh, "marking uptodate");
		set_buffer_uptodate(bh);
		unlock_buffer(bh);
		__brelse(bh);
	}

	sync_blockdev(journal->j_dev);
	jbd_debug(1, "JBD: journal cleared.\n");

	/* OK, fill in the initial static fields in the new superblock */
	sb = journal->j_superblock;

	sb->s_header.h_magic	 = cpu_to_be32(JFS_MAGIC_NUMBER);
	sb->s_header.h_blocktype = cpu_to_be32(JFS_SUPERBLOCK_V2);

	sb->s_blocksize	= cpu_to_be32(journal->j_blocksize);
	sb->s_maxlen	= cpu_to_be32(journal->j_maxlen);
	sb->s_first	= cpu_to_be32(1);

	journal->j_transaction_sequence = 1;

	journal->j_flags &= ~JFS_ABORT;
	journal->j_format_version = 2;

	return journal_reset(journal);
}

static void journal_write_superblock(journal_t *journal, int write_op)
{
	struct buffer_head *bh = journal->j_sb_buffer;
	int ret;

	trace_journal_write_superblock(journal, write_op);
	if (!(journal->j_flags & JFS_BARRIER))
		write_op &= ~(REQ_FUA | REQ_FLUSH);
	lock_buffer(bh);
	if (buffer_write_io_error(bh)) {
		char b[BDEVNAME_SIZE];
		/*
		 * Oh, dear.  A previous attempt to write the journal
		 * superblock failed.  This could happen because the
		 * USB device was yanked out.  Or it could happen to
		 * be a transient write error and maybe the block will
		 * be remapped.  Nothing we can do but to retry the
		 * write and hope for the best.
		 */
		printk(KERN_ERR "JBD: previous I/O error detected "
		       "for journal superblock update for %s.\n",
		       journal_dev_name(journal, b));
		clear_buffer_write_io_error(bh);
		set_buffer_uptodate(bh);
	}

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
		char b[BDEVNAME_SIZE];
		printk(KERN_ERR "JBD: Error %d detected "
		       "when updating journal superblock for %s.\n",
		       ret, journal_dev_name(journal, b));
	}
}

/**
 * journal_update_sb_log_tail() - Update log tail in journal sb on disk.
 * @journal: The journal to update.
 * @tail_tid: TID of the new transaction at the tail of the log
 * @tail_block: The first block of the transaction at the tail of the log
 * @write_op: With which operation should we write the journal sb
 *
 * Update a journal's superblock information about log tail and write it to
 * disk, waiting for the IO to complete.
 */
void journal_update_sb_log_tail(journal_t *journal, tid_t tail_tid,
				unsigned int tail_block, int write_op)
{
	journal_superblock_t *sb = journal->j_superblock;

	BUG_ON(!mutex_is_locked(&journal->j_checkpoint_mutex));
	jbd_debug(1,"JBD: updating superblock (start %u, seq %u)\n",
		  tail_block, tail_tid);

	sb->s_sequence = cpu_to_be32(tail_tid);
	sb->s_start    = cpu_to_be32(tail_block);

	journal_write_superblock(journal, write_op);

	/* Log is no longer empty */
	spin_lock(&journal->j_state_lock);
	WARN_ON(!sb->s_sequence);
	journal->j_flags &= ~JFS_FLUSHED;
	spin_unlock(&journal->j_state_lock);
}

/**
 * mark_journal_empty() - Mark on disk journal as empty.
 * @journal: The journal to update.
 *
 * Update a journal's dynamic superblock fields to show that journal is empty.
 * Write updated superblock to disk waiting for IO to complete.
 */
static void mark_journal_empty(journal_t *journal)
{
	journal_superblock_t *sb = journal->j_superblock;

	BUG_ON(!mutex_is_locked(&journal->j_checkpoint_mutex));
	spin_lock(&journal->j_state_lock);
	/* Is it already empty? */
	if (sb->s_start == 0) {
		spin_unlock(&journal->j_state_lock);
		return;
	}
	jbd_debug(1, "JBD: Marking journal as empty (seq %d)\n",
        	  journal->j_tail_sequence);

	sb->s_sequence = cpu_to_be32(journal->j_tail_sequence);
	sb->s_start    = cpu_to_be32(0);
	spin_unlock(&journal->j_state_lock);

	journal_write_superblock(journal, WRITE_FUA);

	spin_lock(&journal->j_state_lock);
	/* Log is empty */
	journal->j_flags |= JFS_FLUSHED;
	spin_unlock(&journal->j_state_lock);
}

/**
 * journal_update_sb_errno() - Update error in the journal.
 * @journal: The journal to update.
 *
 * Update a journal's errno.  Write updated superblock to disk waiting for IO
 * to complete.
 */
static void journal_update_sb_errno(journal_t *journal)
{
	journal_superblock_t *sb = journal->j_superblock;

	spin_lock(&journal->j_state_lock);
	jbd_debug(1, "JBD: updating superblock error (errno %d)\n",
        	  journal->j_errno);
	sb->s_errno = cpu_to_be32(journal->j_errno);
	spin_unlock(&journal->j_state_lock);

	journal_write_superblock(journal, WRITE_SYNC);
}

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
			printk (KERN_ERR
				"JBD: IO error reading journal superblock\n");
			goto out;
		}
	}

	sb = journal->j_superblock;

	err = -EINVAL;

	if (sb->s_header.h_magic != cpu_to_be32(JFS_MAGIC_NUMBER) ||
	    sb->s_blocksize != cpu_to_be32(journal->j_blocksize)) {
		printk(KERN_WARNING "JBD: no valid journal superblock found\n");
		goto out;
	}

	switch(be32_to_cpu(sb->s_header.h_blocktype)) {
	case JFS_SUPERBLOCK_V1:
		journal->j_format_version = 1;
		break;
	case JFS_SUPERBLOCK_V2:
		journal->j_format_version = 2;
		break;
	default:
		printk(KERN_WARNING "JBD: unrecognised superblock format ID\n");
		goto out;
	}

	if (be32_to_cpu(sb->s_maxlen) < journal->j_maxlen)
		journal->j_maxlen = be32_to_cpu(sb->s_maxlen);
	else if (be32_to_cpu(sb->s_maxlen) > journal->j_maxlen) {
		printk (KERN_WARNING "JBD: journal file too short\n");
		goto out;
	}

	if (be32_to_cpu(sb->s_first) == 0 ||
	    be32_to_cpu(sb->s_first) >= journal->j_maxlen) {
		printk(KERN_WARNING
			"JBD: Invalid start block of journal: %u\n",
			be32_to_cpu(sb->s_first));
		goto out;
	}

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
 * int journal_load() - Read journal from disk.
 * @journal: Journal to act on.
 *
 * Given a journal_t structure which tells us which disk blocks contain
 * a journal, read the journal from disk to initialise the in-memory
 * structures.
 */
int journal_load(journal_t *journal)
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
		     ~cpu_to_be32(JFS_KNOWN_ROCOMPAT_FEATURES)) ||
		    (sb->s_feature_incompat &
		     ~cpu_to_be32(JFS_KNOWN_INCOMPAT_FEATURES))) {
			printk (KERN_WARNING
				"JBD: Unrecognised features on journal\n");
			return -EINVAL;
		}
	}

	/* Let the recovery code check whether it needs to recover any
	 * data from the journal. */
	if (journal_recover(journal))
		goto recovery_error;

	/* OK, we've finished with the dynamic journal bits:
	 * reinitialise the dynamic contents of the superblock in memory
	 * and reset them on disk. */
	if (journal_reset(journal))
		goto recovery_error;

	journal->j_flags &= ~JFS_ABORT;
	journal->j_flags |= JFS_LOADED;
	return 0;

recovery_error:
	printk (KERN_WARNING "JBD: recovery failed\n");
	return -EIO;
}

/**
 * void journal_destroy() - Release a journal_t structure.
 * @journal: Journal to act on.
 *
 * Release a journal_t structure once it is no longer in use by the
 * journaled object.
 * Return <0 if we couldn't clean up the journal.
 */
int journal_destroy(journal_t *journal)
{
	int err = 0;


	/* Wait for the commit thread to wake up and die. */
	journal_kill_thread(journal);

	/* Force a final log commit */
	if (journal->j_running_transaction)
		journal_commit_transaction(journal);

	/* Force any old transactions to disk */

	/* We cannot race with anybody but must keep assertions happy */
	mutex_lock(&journal->j_checkpoint_mutex);
	/* Totally anal locking here... */
	spin_lock(&journal->j_list_lock);
	while (journal->j_checkpoint_transactions != NULL) {
		spin_unlock(&journal->j_list_lock);
		log_do_checkpoint(journal);
		spin_lock(&journal->j_list_lock);
	}

	J_ASSERT(journal->j_running_transaction == NULL);
	J_ASSERT(journal->j_committing_transaction == NULL);
	J_ASSERT(journal->j_checkpoint_transactions == NULL);
	spin_unlock(&journal->j_list_lock);

	if (journal->j_sb_buffer) {
		if (!is_journal_aborted(journal)) {
			journal->j_tail_sequence =
				++journal->j_transaction_sequence;
			mark_journal_empty(journal);
		} else
			err = -EIO;
		brelse(journal->j_sb_buffer);
	}
	mutex_unlock(&journal->j_checkpoint_mutex);

	if (journal->j_inode)
		iput(journal->j_inode);
	if (journal->j_revoke)
		journal_destroy_revoke(journal);
	kfree(journal->j_wbuf);
	kfree(journal);

	return err;
}


/**
 *int journal_check_used_features () - Check if features specified are used.
 * @journal: Journal to check.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Check whether the journal uses all of a given set of
 * features.  Return true (non-zero) if it does.
 **/

int journal_check_used_features (journal_t *journal, unsigned long compat,
				 unsigned long ro, unsigned long incompat)
{
	journal_superblock_t *sb;

	if (!compat && !ro && !incompat)
		return 1;
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
 * int journal_check_available_features() - Check feature set in journalling layer
 * @journal: Journal to check.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Check whether the journaling code supports the use of
 * all of a given set of features on this journal.  Return true
 * (non-zero) if it can. */

int journal_check_available_features (journal_t *journal, unsigned long compat,
				      unsigned long ro, unsigned long incompat)
{
	if (!compat && !ro && !incompat)
		return 1;

	/* We can support any known requested features iff the
	 * superblock is in version 2.  Otherwise we fail to support any
	 * extended sb features. */

	if (journal->j_format_version != 2)
		return 0;

	if ((compat   & JFS_KNOWN_COMPAT_FEATURES) == compat &&
	    (ro       & JFS_KNOWN_ROCOMPAT_FEATURES) == ro &&
	    (incompat & JFS_KNOWN_INCOMPAT_FEATURES) == incompat)
		return 1;

	return 0;
}

/**
 * int journal_set_features () - Mark a given journal feature in the superblock
 * @journal: Journal to act on.
 * @compat: bitmask of compatible features
 * @ro: bitmask of features that force read-only mount
 * @incompat: bitmask of incompatible features
 *
 * Mark a given journal feature as present on the
 * superblock.  Returns true if the requested features could be set.
 *
 */

int journal_set_features (journal_t *journal, unsigned long compat,
			  unsigned long ro, unsigned long incompat)
{
	journal_superblock_t *sb;

	if (journal_check_used_features(journal, compat, ro, incompat))
		return 1;

	if (!journal_check_available_features(journal, compat, ro, incompat))
		return 0;

	jbd_debug(1, "Setting new features 0x%lx/0x%lx/0x%lx\n",
		  compat, ro, incompat);

	sb = journal->j_superblock;

	sb->s_feature_compat    |= cpu_to_be32(compat);
	sb->s_feature_ro_compat |= cpu_to_be32(ro);
	sb->s_feature_incompat  |= cpu_to_be32(incompat);

	return 1;
}


/**
 * int journal_update_format () - Update on-disk journal structure.
 * @journal: Journal to act on.
 *
 * Given an initialised but unloaded journal struct, poke about in the
 * on-disk structure to update it to the most recent supported version.
 */
int journal_update_format (journal_t *journal)
{
	journal_superblock_t *sb;
	int err;

	err = journal_get_superblock(journal);
	if (err)
		return err;

	sb = journal->j_superblock;

	switch (be32_to_cpu(sb->s_header.h_blocktype)) {
	case JFS_SUPERBLOCK_V2:
		return 0;
	case JFS_SUPERBLOCK_V1:
		return journal_convert_superblock_v1(journal, sb);
	default:
		break;
	}
	return -EINVAL;
}

static int journal_convert_superblock_v1(journal_t *journal,
					 journal_superblock_t *sb)
{
	int offset, blocksize;
	struct buffer_head *bh;

	printk(KERN_WARNING
		"JBD: Converting superblock from version 1 to 2.\n");

	/* Pre-initialise new fields to zero */
	offset = ((char *) &(sb->s_feature_compat)) - ((char *) sb);
	blocksize = be32_to_cpu(sb->s_blocksize);
	memset(&sb->s_feature_compat, 0, blocksize-offset);

	sb->s_nr_users = cpu_to_be32(1);
	sb->s_header.h_blocktype = cpu_to_be32(JFS_SUPERBLOCK_V2);
	journal->j_format_version = 2;

	bh = journal->j_sb_buffer;
	BUFFER_TRACE(bh, "marking dirty");
	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	return 0;
}


/**
 * int journal_flush () - Flush journal
 * @journal: Journal to act on.
 *
 * Flush all data for a given journal to disk and empty the journal.
 * Filesystems can use this when remounting readonly to ensure that
 * recovery does not need to happen on remount.
 */

int journal_flush(journal_t *journal)
{
	int err = 0;
	transaction_t *transaction = NULL;

	spin_lock(&journal->j_state_lock);

	/* Force everything buffered to the log... */
	if (journal->j_running_transaction) {
		transaction = journal->j_running_transaction;
		__log_start_commit(journal, transaction->t_tid);
	} else if (journal->j_committing_transaction)
		transaction = journal->j_committing_transaction;

	/* Wait for the log commit to complete... */
	if (transaction) {
		tid_t tid = transaction->t_tid;

		spin_unlock(&journal->j_state_lock);
		log_wait_commit(journal, tid);
	} else {
		spin_unlock(&journal->j_state_lock);
	}

	/* ...and flush everything in the log out to disk. */
	spin_lock(&journal->j_list_lock);
	while (!err && journal->j_checkpoint_transactions != NULL) {
		spin_unlock(&journal->j_list_lock);
		mutex_lock(&journal->j_checkpoint_mutex);
		err = log_do_checkpoint(journal);
		mutex_unlock(&journal->j_checkpoint_mutex);
		spin_lock(&journal->j_list_lock);
	}
	spin_unlock(&journal->j_list_lock);

	if (is_journal_aborted(journal))
		return -EIO;

	mutex_lock(&journal->j_checkpoint_mutex);
	cleanup_journal_tail(journal);

	/* Finally, mark the journal as really needing no recovery.
	 * This sets s_start==0 in the underlying superblock, which is
	 * the magic code for a fully-recovered superblock.  Any future
	 * commits of data to the journal will restore the current
	 * s_start value. */
	mark_journal_empty(journal);
	mutex_unlock(&journal->j_checkpoint_mutex);
	spin_lock(&journal->j_state_lock);
	J_ASSERT(!journal->j_running_transaction);
	J_ASSERT(!journal->j_committing_transaction);
	J_ASSERT(!journal->j_checkpoint_transactions);
	J_ASSERT(journal->j_head == journal->j_tail);
	J_ASSERT(journal->j_tail_sequence == journal->j_transaction_sequence);
	spin_unlock(&journal->j_state_lock);
	return 0;
}

/**
 * int journal_wipe() - Wipe journal contents
 * @journal: Journal to act on.
 * @write: flag (see below)
 *
 * Wipe out all of the contents of a journal, safely.  This will produce
 * a warning if the journal contains any valid recovery information.
 * Must be called between journal_init_*() and journal_load().
 *
 * If 'write' is non-zero, then we wipe out the journal on disk; otherwise
 * we merely suppress recovery.
 */

int journal_wipe(journal_t *journal, int write)
{
	int err = 0;

	J_ASSERT (!(journal->j_flags & JFS_LOADED));

	err = load_superblock(journal);
	if (err)
		return err;

	if (!journal->j_tail)
		goto no_recovery;

	printk (KERN_WARNING "JBD: %s recovery information on journal\n",
		write ? "Clearing" : "Ignoring");

	err = journal_skip_recovery(journal);
	if (write) {
		/* Lock to make assertions happy... */
		mutex_lock(&journal->j_checkpoint_mutex);
		mark_journal_empty(journal);
		mutex_unlock(&journal->j_checkpoint_mutex);
	}

 no_recovery:
	return err;
}

/*
 * journal_dev_name: format a character string to describe on what
 * device this journal is present.
 */

static const char *journal_dev_name(journal_t *journal, char *buffer)
{
	struct block_device *bdev;

	if (journal->j_inode)
		bdev = journal->j_inode->i_sb->s_bdev;
	else
		bdev = journal->j_dev;

	return bdevname(bdev, buffer);
}

/*
 * Journal abort has very specific semantics, which we describe
 * for journal abort.
 *
 * Two internal function, which provide abort to te jbd layer
 * itself are here.
 */

/*
 * Quick version for internal journal use (doesn't lock the journal).
 * Aborts hard --- we mark the abort as occurred, but do _nothing_ else,
 * and don't attempt to make any other journal updates.
 */
static void __journal_abort_hard(journal_t *journal)
{
	transaction_t *transaction;
	char b[BDEVNAME_SIZE];

	if (journal->j_flags & JFS_ABORT)
		return;

	printk(KERN_ERR "Aborting journal on device %s.\n",
		journal_dev_name(journal, b));

	spin_lock(&journal->j_state_lock);
	journal->j_flags |= JFS_ABORT;
	transaction = journal->j_running_transaction;
	if (transaction)
		__log_start_commit(journal, transaction->t_tid);
	spin_unlock(&journal->j_state_lock);
}

/* Soft abort: record the abort error status in the journal superblock,
 * but don't do any other IO. */
static void __journal_abort_soft (journal_t *journal, int errno)
{
	if (journal->j_flags & JFS_ABORT)
		return;

	if (!journal->j_errno)
		journal->j_errno = errno;

	__journal_abort_hard(journal);

	if (errno)
		journal_update_sb_errno(journal);
}

/**
 * void journal_abort () - Shutdown the journal immediately.
 * @journal: the journal to shutdown.
 * @errno:   an error number to record in the journal indicating
 *           the reason for the shutdown.
 *
 * Perform a complete, immediate shutdown of the ENTIRE
 * journal (not of a single transaction).  This operation cannot be
 * undone without closing and reopening the journal.
 *
 * The journal_abort function is intended to support higher level error
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
 * journal_stop on an existing handle will return -EIO if we have
 * entered abort state during the update.
 *
 * Recursive transactions are not disturbed by journal abort until the
 * final journal_stop, which will receive the -EIO error.
 *
 * Finally, the journal_abort call allows the caller to supply an errno
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

void journal_abort(journal_t *journal, int errno)
{
	__journal_abort_soft(journal, errno);
}

/**
 * int journal_errno () - returns the journal's error state.
 * @journal: journal to examine.
 *
 * This is the errno numbet set with journal_abort(), the last
 * time the journal was mounted - if the journal was stopped
 * without calling abort this will be 0.
 *
 * If the journal has been aborted on this mount time -EROFS will
 * be returned.
 */
int journal_errno(journal_t *journal)
{
	int err;

	spin_lock(&journal->j_state_lock);
	if (journal->j_flags & JFS_ABORT)
		err = -EROFS;
	else
		err = journal->j_errno;
	spin_unlock(&journal->j_state_lock);
	return err;
}

/**
 * int journal_clear_err () - clears the journal's error state
 * @journal: journal to act on.
 *
 * An error must be cleared or Acked to take a FS out of readonly
 * mode.
 */
int journal_clear_err(journal_t *journal)
{
	int err = 0;

	spin_lock(&journal->j_state_lock);
	if (journal->j_flags & JFS_ABORT)
		err = -EROFS;
	else
		journal->j_errno = 0;
	spin_unlock(&journal->j_state_lock);
	return err;
}

/**
 * void journal_ack_err() - Ack journal err.
 * @journal: journal to act on.
 *
 * An error must be cleared or Acked to take a FS out of readonly
 * mode.
 */
void journal_ack_err(journal_t *journal)
{
	spin_lock(&journal->j_state_lock);
	if (journal->j_errno)
		journal->j_flags |= JFS_ACK_ERR;
	spin_unlock(&journal->j_state_lock);
}

int journal_blocks_per_page(struct inode *inode)
{
	return 1 << (PAGE_CACHE_SHIFT - inode->i_sb->s_blocksize_bits);
}

/*
 * Journal_head storage management
 */
static struct kmem_cache *journal_head_cache;
#ifdef CONFIG_JBD_DEBUG
static atomic_t nr_journal_heads = ATOMIC_INIT(0);
#endif

static int journal_init_journal_head_cache(void)
{
	int retval;

	J_ASSERT(journal_head_cache == NULL);
	journal_head_cache = kmem_cache_create("journal_head",
				sizeof(struct journal_head),
				0,		/* offset */
				SLAB_TEMPORARY,	/* flags */
				NULL);		/* ctor */
	retval = 0;
	if (!journal_head_cache) {
		retval = -ENOMEM;
		printk(KERN_EMERG "JBD: no memory for journal_head cache\n");
	}
	return retval;
}

static void journal_destroy_journal_head_cache(void)
{
	if (journal_head_cache) {
		kmem_cache_destroy(journal_head_cache);
		journal_head_cache = NULL;
	}
}

/*
 * journal_head splicing and dicing
 */
static struct journal_head *journal_alloc_journal_head(void)
{
	struct journal_head *ret;

#ifdef CONFIG_JBD_DEBUG
	atomic_inc(&nr_journal_heads);
#endif
	ret = kmem_cache_zalloc(journal_head_cache, GFP_NOFS);
	if (ret == NULL) {
		jbd_debug(1, "out of memory for journal_head\n");
		printk_ratelimited(KERN_NOTICE "ENOMEM in %s, retrying.\n",
				   __func__);

		while (ret == NULL) {
			yield();
			ret = kmem_cache_zalloc(journal_head_cache, GFP_NOFS);
		}
	}
	return ret;
}

static void journal_free_journal_head(struct journal_head *jh)
{
#ifdef CONFIG_JBD_DEBUG
	atomic_dec(&nr_journal_heads);
	memset(jh, JBD_POISON_FREE, sizeof(*jh));
#endif
	kmem_cache_free(journal_head_cache, jh);
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
 * journal_head in this situation, journal_add_journal_head elevates the
 * journal_head's b_jcount refcount by one.  The caller must call
 * journal_put_journal_head() to undo this.
 *
 * So the typical usage would be:
 *
 *	(Attach a journal_head if needed.  Increments b_jcount)
 *	struct journal_head *jh = journal_add_journal_head(bh);
 *	...
 *      (Get another reference for transaction)
 *      journal_grab_journal_head(bh);
 *      jh->b_transaction = xxx;
 *      (Put original reference)
 *      journal_put_journal_head(jh);
 */

/*
 * Give a buffer_head a journal_head.
 *
 * May sleep.
 */
struct journal_head *journal_add_journal_head(struct buffer_head *bh)
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
struct journal_head *journal_grab_journal_head(struct buffer_head *bh)
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
		jbd_free(jh->b_frozen_data, bh->b_size);
	}
	if (jh->b_committed_data) {
		printk(KERN_WARNING "%s: freeing b_committed_data\n", __func__);
		jbd_free(jh->b_committed_data, bh->b_size);
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
void journal_put_journal_head(struct journal_head *jh)
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
 * debugfs tunables
 */
#ifdef CONFIG_JBD_DEBUG

u8 journal_enable_debug __read_mostly;
EXPORT_SYMBOL(journal_enable_debug);

static struct dentry *jbd_debugfs_dir;
static struct dentry *jbd_debug;

static void __init jbd_create_debugfs_entry(void)
{
	jbd_debugfs_dir = debugfs_create_dir("jbd", NULL);
	if (jbd_debugfs_dir)
		jbd_debug = debugfs_create_u8("jbd-debug", S_IRUGO | S_IWUSR,
					       jbd_debugfs_dir,
					       &journal_enable_debug);
}

static void __exit jbd_remove_debugfs_entry(void)
{
	debugfs_remove(jbd_debug);
	debugfs_remove(jbd_debugfs_dir);
}

#else

static inline void jbd_create_debugfs_entry(void)
{
}

static inline void jbd_remove_debugfs_entry(void)
{
}

#endif

struct kmem_cache *jbd_handle_cache;

static int __init journal_init_handle_cache(void)
{
	jbd_handle_cache = kmem_cache_create("journal_handle",
				sizeof(handle_t),
				0,		/* offset */
				SLAB_TEMPORARY,	/* flags */
				NULL);		/* ctor */
	if (jbd_handle_cache == NULL) {
		printk(KERN_EMERG "JBD: failed to create handle cache\n");
		return -ENOMEM;
	}
	return 0;
}

static void journal_destroy_handle_cache(void)
{
	if (jbd_handle_cache)
		kmem_cache_destroy(jbd_handle_cache);
}

/*
 * Module startup and shutdown
 */

static int __init journal_init_caches(void)
{
	int ret;

	ret = journal_init_revoke_caches();
	if (ret == 0)
		ret = journal_init_journal_head_cache();
	if (ret == 0)
		ret = journal_init_handle_cache();
	return ret;
}

static void journal_destroy_caches(void)
{
	journal_destroy_revoke_caches();
	journal_destroy_journal_head_cache();
	journal_destroy_handle_cache();
}

static int __init journal_init(void)
{
	int ret;

	BUILD_BUG_ON(sizeof(struct journal_superblock_s) != 1024);

	ret = journal_init_caches();
	if (ret != 0)
		journal_destroy_caches();
	jbd_create_debugfs_entry();
	return ret;
}

static void __exit journal_exit(void)
{
#ifdef CONFIG_JBD_DEBUG
	int n = atomic_read(&nr_journal_heads);
	if (n)
		printk(KERN_ERR "JBD: leaked %d journal_heads!\n", n);
#endif
	jbd_remove_debugfs_entry();
	journal_destroy_caches();
}

MODULE_LICENSE("GPL");
module_init(journal_init);
module_exit(journal_exit);
/************************************************************/
/* ../linux-3.17/fs/jbd/journal.c */
/************************************************************/
