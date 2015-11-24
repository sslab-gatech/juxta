/*
 * linux/fs/befs/datastream.c
 *
 * Copyright (C) 2001 Will Dyson <will_dyson@pobox.com>
 *
 * Based on portions of file.c by Makoto Kato <m_kato@ga2.so-net.ne.jp>
 *
 * Many thanks to Dominic Giampaolo, author of "Practical File System
 * Design with the Be File System", for such a helpful book.
 *
 */

#include <linux/kernel.h>
#include <linux/buffer_head.h>
#include <linux/string.h>

#include "befs.h"
#include "datastream.h"
#include "io.h"

const befs_inode_addr BAD_IADDR = { 0, 0, 0 };

static int befs_find_brun_direct(struct super_block *sb,
				 befs_data_stream * data,
				 befs_blocknr_t blockno, befs_block_run * run);

static int befs_find_brun_indirect(struct super_block *sb,
				   befs_data_stream * data,
				   befs_blocknr_t blockno,
				   befs_block_run * run);

static int befs_find_brun_dblindirect(struct super_block *sb,
				      befs_data_stream * data,
				      befs_blocknr_t blockno,
				      befs_block_run * run);

/**
 * befs_read_datastream - get buffer_head containing data, starting from pos.
 * @sb: Filesystem superblock
 * @ds: datastrem to find data with
 * @pos: start of data
 * @off: offset of data in buffer_head->b_data
 *
 * Returns pointer to buffer_head containing data starting with offset @off,
 * if you don't need to know offset just set @off = NULL.
 */
struct buffer_head *
befs_read_datastream(struct super_block *sb, befs_data_stream * ds,
		     befs_off_t pos, uint * off)
{
	struct buffer_head *bh = NULL;
	befs_block_run run;
	befs_blocknr_t block;	/* block coresponding to pos */

	befs_debug(sb, "---> %s %llu", __func__, pos);
	block = pos >> BEFS_SB(sb)->block_shift;
	if (off)
		*off = pos - (block << BEFS_SB(sb)->block_shift);

	if (befs_fblock2brun(sb, ds, block, &run) != BEFS_OK) {
		befs_error(sb, "BeFS: Error finding disk addr of block %lu",
			   (unsigned long)block);
		befs_debug(sb, "<--- %s ERROR", __func__);
		return NULL;
	}
	bh = befs_bread_iaddr(sb, run);
	if (!bh) {
		befs_error(sb, "BeFS: Error reading block %lu from datastream",
			   (unsigned long)block);
		return NULL;
	}

	befs_debug(sb, "<--- %s read data, starting at %llu", __func__, pos);

	return bh;
}

/*
 * Takes a file position and gives back a brun who's starting block
 * is block number fblock of the file.
 *
 * Returns BEFS_OK or BEFS_ERR.
 *
 * Calls specialized functions for each of the three possible
 * datastream regions.
 *
 * 2001-11-15 Will Dyson
 */
int
befs_fblock2brun(struct super_block *sb, befs_data_stream * data,
		 befs_blocknr_t fblock, befs_block_run * run)
{
	int err;
	befs_off_t pos = fblock << BEFS_SB(sb)->block_shift;

	if (pos < data->max_direct_range) {
		err = befs_find_brun_direct(sb, data, fblock, run);

	} else if (pos < data->max_indirect_range) {
		err = befs_find_brun_indirect(sb, data, fblock, run);

	} else if (pos < data->max_double_indirect_range) {
		err = befs_find_brun_dblindirect(sb, data, fblock, run);

	} else {
		befs_error(sb,
			   "befs_fblock2brun() was asked to find block %lu, "
			   "which is not mapped by the datastream\n",
			   (unsigned long)fblock);
		err = BEFS_ERR;
	}
	return err;
}

/**
 * befs_read_lsmylink - read long symlink from datastream.
 * @sb: Filesystem superblock
 * @ds: Datastrem to read from
 * @buff: Buffer in which to place long symlink data
 * @len: Length of the long symlink in bytes
 *
 * Returns the number of bytes read
 */
size_t
befs_read_lsymlink(struct super_block * sb, befs_data_stream * ds, void *buff,
		   befs_off_t len)
{
	befs_off_t bytes_read = 0;	/* bytes readed */
	u16 plen;
	struct buffer_head *bh = NULL;
	befs_debug(sb, "---> %s length: %llu", __func__, len);

	while (bytes_read < len) {
		bh = befs_read_datastream(sb, ds, bytes_read, NULL);
		if (!bh) {
			befs_error(sb, "BeFS: Error reading datastream block "
				   "starting from %llu", bytes_read);
			befs_debug(sb, "<--- %s ERROR", __func__);
			return bytes_read;

		}
		plen = ((bytes_read + BEFS_SB(sb)->block_size) < len) ?
		    BEFS_SB(sb)->block_size : len - bytes_read;
		memcpy(buff + bytes_read, bh->b_data, plen);
		brelse(bh);
		bytes_read += plen;
	}

	befs_debug(sb, "<--- %s read %u bytes", __func__, (unsigned int)
		   bytes_read);
	return bytes_read;
}

/**
 * befs_count_blocks - blocks used by a file
 * @sb: Filesystem superblock
 * @ds: Datastream of the file
 *
 * Counts the number of fs blocks that the file represented by
 * inode occupies on the filesystem, counting both regular file
 * data and filesystem metadata (and eventually attribute data
 * when we support attributes)
*/

befs_blocknr_t
befs_count_blocks(struct super_block * sb, befs_data_stream * ds)
{
	befs_blocknr_t blocks;
	befs_blocknr_t datablocks;	/* File data blocks */
	befs_blocknr_t metablocks;	/* FS metadata blocks */
	befs_sb_info *befs_sb = BEFS_SB(sb);

	befs_debug(sb, "---> %s", __func__);

	datablocks = ds->size >> befs_sb->block_shift;
	if (ds->size & (befs_sb->block_size - 1))
		datablocks += 1;

	metablocks = 1;		/* Start with 1 block for inode */

	/* Size of indirect block */
	if (ds->size > ds->max_direct_range)
		metablocks += ds->indirect.len;

	/*
	   Double indir block, plus all the indirect blocks it mapps
	   In the double-indirect range, all block runs of data are
	   BEFS_DBLINDIR_BRUN_LEN blocks long. Therefore, we know
	   how many data block runs are in the double-indirect region,
	   and from that we know how many indirect blocks it takes to
	   map them. We assume that the indirect blocks are also
	   BEFS_DBLINDIR_BRUN_LEN blocks long.
	 */
	if (ds->size > ds->max_indirect_range && ds->max_indirect_range != 0) {
		uint dbl_bytes;
		uint dbl_bruns;
		uint indirblocks;

		dbl_bytes =
		    ds->max_double_indirect_range - ds->max_indirect_range;
		dbl_bruns =
		    dbl_bytes / (befs_sb->block_size * BEFS_DBLINDIR_BRUN_LEN);
		indirblocks = dbl_bruns / befs_iaddrs_per_block(sb);

		metablocks += ds->double_indirect.len;
		metablocks += indirblocks;
	}

	blocks = datablocks + metablocks;
	befs_debug(sb, "<--- %s %u blocks", __func__, (unsigned int)blocks);

	return blocks;
}

/*
	Finds the block run that starts at file block number blockno
	in the file represented by the datastream data, if that
	blockno is in the direct region of the datastream.

	sb: the superblock
	data: the datastream
	blockno: the blocknumber to find
	run: The found run is passed back through this pointer

	Return value is BEFS_OK if the blockrun is found, BEFS_ERR
	otherwise.

	Algorithm:
	Linear search. Checks each element of array[] to see if it
	contains the blockno-th filesystem block. This is necessary
	because the block runs map variable amounts of data. Simply
	keeps a count of the number of blocks searched so far (sum),
	incrementing this by the length of each block run as we come
	across it. Adds sum to *count before returning (this is so
	you can search multiple arrays that are logicaly one array,
	as in the indirect region code).

	When/if blockno is found, if blockno is inside of a block
	run as stored on disk, we offset the start and length members
	of the block run, so that blockno is the start and len is
	still valid (the run ends in the same place).

	2001-11-15 Will Dyson
*/
static int
befs_find_brun_direct(struct super_block *sb, befs_data_stream * data,
		      befs_blocknr_t blockno, befs_block_run * run)
{
	int i;
	befs_block_run *array = data->direct;
	befs_blocknr_t sum;
	befs_blocknr_t max_block =
	    data->max_direct_range >> BEFS_SB(sb)->block_shift;

	befs_debug(sb, "---> %s, find %lu", __func__, (unsigned long)blockno);

	if (blockno > max_block) {
		befs_error(sb, "%s passed block outside of direct region",
			   __func__);
		return BEFS_ERR;
	}

	for (i = 0, sum = 0; i < BEFS_NUM_DIRECT_BLOCKS;
	     sum += array[i].len, i++) {
		if (blockno >= sum && blockno < sum + (array[i].len)) {
			int offset = blockno - sum;
			run->allocation_group = array[i].allocation_group;
			run->start = array[i].start + offset;
			run->len = array[i].len - offset;

			befs_debug(sb, "---> %s, "
				   "found %lu at direct[%d]", __func__,
				   (unsigned long)blockno, i);
			return BEFS_OK;
		}
	}

	befs_debug(sb, "---> %s ERROR", __func__);
	return BEFS_ERR;
}

/*
	Finds the block run that starts at file block number blockno
	in the file represented by the datastream data, if that
	blockno is in the indirect region of the datastream.

	sb: the superblock
	data: the datastream
	blockno: the blocknumber to find
	run: The found run is passed back through this pointer

	Return value is BEFS_OK if the blockrun is found, BEFS_ERR
	otherwise.

	Algorithm:
	For each block in the indirect run of the datastream, read
	it in and search through it for	search_blk.

	XXX:
	Really should check to make sure blockno is inside indirect
	region.

	2001-11-15 Will Dyson
*/
static int
befs_find_brun_indirect(struct super_block *sb,
			befs_data_stream * data, befs_blocknr_t blockno,
			befs_block_run * run)
{
	int i, j;
	befs_blocknr_t sum = 0;
	befs_blocknr_t indir_start_blk;
	befs_blocknr_t search_blk;
	struct buffer_head *indirblock;
	befs_disk_block_run *array;

	befs_block_run indirect = data->indirect;
	befs_blocknr_t indirblockno = iaddr2blockno(sb, &indirect);
	int arraylen = befs_iaddrs_per_block(sb);

	befs_debug(sb, "---> %s, find %lu", __func__, (unsigned long)blockno);

	indir_start_blk = data->max_direct_range >> BEFS_SB(sb)->block_shift;
	search_blk = blockno - indir_start_blk;

	/* Examine blocks of the indirect run one at a time */
	for (i = 0; i < indirect.len; i++) {
		indirblock = befs_bread(sb, indirblockno + i);
		if (indirblock == NULL) {
			befs_debug(sb, "---> %s failed to read "
				   "disk block %lu from the indirect brun",
				   __func__, (unsigned long)indirblockno + i);
			return BEFS_ERR;
		}

		array = (befs_disk_block_run *) indirblock->b_data;

		for (j = 0; j < arraylen; ++j) {
			int len = fs16_to_cpu(sb, array[j].len);

			if (search_blk >= sum && search_blk < sum + len) {
				int offset = search_blk - sum;
				run->allocation_group =
				    fs32_to_cpu(sb, array[j].allocation_group);
				run->start =
				    fs16_to_cpu(sb, array[j].start) + offset;
				run->len =
				    fs16_to_cpu(sb, array[j].len) - offset;

				brelse(indirblock);
				befs_debug(sb,
					   "<--- %s found file block "
					   "%lu at indirect[%d]", __func__,
					   (unsigned long)blockno,
					   j + (i * arraylen));
				return BEFS_OK;
			}
			sum += len;
		}

		brelse(indirblock);
	}

	/* Only fallthrough is an error */
	befs_error(sb, "BeFS: %s failed to find "
		   "file block %lu", __func__, (unsigned long)blockno);

	befs_debug(sb, "<--- %s ERROR", __func__);
	return BEFS_ERR;
}

/*
	Finds the block run that starts at file block number blockno
	in the file represented by the datastream data, if that
	blockno is in the double-indirect region of the datastream.

	sb: the superblock
	data: the datastream
	blockno: the blocknumber to find
	run: The found run is passed back through this pointer

	Return value is BEFS_OK if the blockrun is found, BEFS_ERR
	otherwise.

	Algorithm:
	The block runs in the double-indirect region are different.
	They are always allocated 4 fs blocks at a time, so each
	block run maps a constant amount of file data. This means
	that we can directly calculate how many block runs into the
	double-indirect region we need to go to get to the one that
	maps a particular filesystem block.

	We do this in two stages. First we calculate which of the
	inode addresses in the double-indirect block will point us
	to the indirect block that contains the mapping for the data,
	then we calculate which of the inode addresses in that
	indirect block maps the data block we are after.

	Oh, and once we've done that, we actually read in the blocks
	that contain the inode addresses we calculated above. Even
	though the double-indirect run may be several blocks long,
	we can calculate which of those blocks will contain the index
	we are after and only read that one. We then follow it to
	the indirect block and perform a  similar process to find
	the actual block run that maps the data block we are interested
	in.

	Then we offset the run as in befs_find_brun_array() and we are
	done.

	2001-11-15 Will Dyson
*/
static int
befs_find_brun_dblindirect(struct super_block *sb,
			   befs_data_stream * data, befs_blocknr_t blockno,
			   befs_block_run * run)
{
	int dblindir_indx;
	int indir_indx;
	int offset;
	int dbl_which_block;
	int which_block;
	int dbl_block_indx;
	int block_indx;
	off_t dblindir_leftover;
	befs_blocknr_t blockno_at_run_start;
	struct buffer_head *dbl_indir_block;
	struct buffer_head *indir_block;
	befs_block_run indir_run;
	befs_disk_inode_addr *iaddr_array = NULL;
	befs_sb_info *befs_sb = BEFS_SB(sb);

	befs_blocknr_t indir_start_blk =
	    data->max_indirect_range >> befs_sb->block_shift;

	off_t dbl_indir_off = blockno - indir_start_blk;

	/* number of data blocks mapped by each of the iaddrs in
	 * the indirect block pointed to by the double indirect block
	 */
	size_t iblklen = BEFS_DBLINDIR_BRUN_LEN;

	/* number of data blocks mapped by each of the iaddrs in
	 * the double indirect block
	 */
	size_t diblklen = iblklen * befs_iaddrs_per_block(sb)
	    * BEFS_DBLINDIR_BRUN_LEN;

	befs_debug(sb, "---> %s find %lu", __func__, (unsigned long)blockno);

	/* First, discover which of the double_indir->indir blocks
	 * contains pos. Then figure out how much of pos that
	 * accounted for. Then discover which of the iaddrs in
	 * the indirect block contains pos.
	 */

	dblindir_indx = dbl_indir_off / diblklen;
	dblindir_leftover = dbl_indir_off % diblklen;
	indir_indx = dblindir_leftover / diblklen;

	/* Read double indirect block */
	dbl_which_block = dblindir_indx / befs_iaddrs_per_block(sb);
	if (dbl_which_block > data->double_indirect.len) {
		befs_error(sb, "The double-indirect index calculated by "
			   "%s, %d, is outside the range "
			   "of the double-indirect block", __func__,
			   dblindir_indx);
		return BEFS_ERR;
	}

	dbl_indir_block =
	    befs_bread(sb, iaddr2blockno(sb, &data->double_indirect) +
					dbl_which_block);
	if (dbl_indir_block == NULL) {
		befs_error(sb, "%s couldn't read the "
			   "double-indirect block at blockno %lu", __func__,
			   (unsigned long)
			   iaddr2blockno(sb, &data->double_indirect) +
			   dbl_which_block);
		brelse(dbl_indir_block);
		return BEFS_ERR;
	}

	dbl_block_indx =
	    dblindir_indx - (dbl_which_block * befs_iaddrs_per_block(sb));
	iaddr_array = (befs_disk_inode_addr *) dbl_indir_block->b_data;
	indir_run = fsrun_to_cpu(sb, iaddr_array[dbl_block_indx]);
	brelse(dbl_indir_block);
	iaddr_array = NULL;

	/* Read indirect block */
	which_block = indir_indx / befs_iaddrs_per_block(sb);
	if (which_block > indir_run.len) {
		befs_error(sb, "The indirect index calculated by "
			   "%s, %d, is outside the range "
			   "of the indirect block", __func__, indir_indx);
		return BEFS_ERR;
	}

	indir_block =
	    befs_bread(sb, iaddr2blockno(sb, &indir_run) + which_block);
	if (indir_block == NULL) {
		befs_error(sb, "%s couldn't read the indirect block "
			   "at blockno %lu", __func__, (unsigned long)
			   iaddr2blockno(sb, &indir_run) + which_block);
		brelse(indir_block);
		return BEFS_ERR;
	}

	block_indx = indir_indx - (which_block * befs_iaddrs_per_block(sb));
	iaddr_array = (befs_disk_inode_addr *) indir_block->b_data;
	*run = fsrun_to_cpu(sb, iaddr_array[block_indx]);
	brelse(indir_block);
	iaddr_array = NULL;

	blockno_at_run_start = indir_start_blk;
	blockno_at_run_start += diblklen * dblindir_indx;
	blockno_at_run_start += iblklen * indir_indx;
	offset = blockno - blockno_at_run_start;

	run->start += offset;
	run->len -= offset;

	befs_debug(sb, "Found file block %lu in double_indirect[%d][%d],"
		   " double_indirect_leftover = %lu", (unsigned long)
		   blockno, dblindir_indx, indir_indx, dblindir_leftover);

	return BEFS_OK;
}
/************************************************************/
/* ../linux-3.17/fs/befs/datastream.c */
/************************************************************/
/*
 * linux/fs/befs/btree.c
 *
 * Copyright (C) 2001-2002 Will Dyson <will_dyson@pobox.com>
 *
 * Licensed under the GNU GPL. See the file COPYING for details.
 *
 * 2002-02-05: Sergey S. Kostyliov added binary search within
 * 		btree nodes.
 *
 * Many thanks to:
 *
 * Dominic Giampaolo, author of "Practical File System
 * Design with the Be File System", for such a helpful book.
 *
 * Marcus J. Ranum, author of the b+tree package in
 * comp.sources.misc volume 10. This code is not copied from that
 * work, but it is partially based on it.
 *
 * Makoto Kato, author of the original BeFS for linux filesystem
 * driver.
 */

// #include <linux/kernel.h>
// #include <linux/string.h>
#include <linux/slab.h>
#include <linux/mm.h>
// #include <linux/buffer_head.h>

// #include "befs.h"
#include "btree.h"
// #include "datastream.h"

/*
 * The btree functions in this file are built on top of the
 * datastream.c interface, which is in turn built on top of the
 * io.c interface.
 */

/* Befs B+tree structure:
 *
 * The first thing in the tree is the tree superblock. It tells you
 * all kinds of useful things about the tree, like where the rootnode
 * is located, and the size of the nodes (always 1024 with current version
 * of BeOS).
 *
 * The rest of the tree consists of a series of nodes. Nodes contain a header
 * (struct befs_btree_nodehead), the packed key data, an array of shorts
 * containing the ending offsets for each of the keys, and an array of
 * befs_off_t values. In interior nodes, the keys are the ending keys for
 * the childnode they point to, and the values are offsets into the
 * datastream containing the tree.
 */

/* Note:
 *
 * The book states 2 confusing things about befs b+trees. First,
 * it states that the overflow field of node headers is used by internal nodes
 * to point to another node that "effectively continues this one". Here is what
 * I believe that means. Each key in internal nodes points to another node that
 * contains key values less than itself. Inspection reveals that the last key
 * in the internal node is not the last key in the index. Keys that are
 * greater than the last key in the internal node go into the overflow node.
 * I imagine there is a performance reason for this.
 *
 * Second, it states that the header of a btree node is sufficient to
 * distinguish internal nodes from leaf nodes. Without saying exactly how.
 * After figuring out the first, it becomes obvious that internal nodes have
 * overflow nodes and leafnodes do not.
 */

/*
 * Currently, this code is only good for directory B+trees.
 * In order to be used for other BFS indexes, it needs to be extended to handle
 * duplicate keys and non-string keytypes (int32, int64, float, double).
 */

/*
 * In memory structure of each btree node
 */
typedef struct {
	befs_host_btree_nodehead head;	/* head of node converted to cpu byteorder */
	struct buffer_head *bh;
	befs_btree_nodehead *od_node;	/* on disk node */
} befs_btree_node;

/* local constants */
static const befs_off_t befs_bt_inval = 0xffffffffffffffffULL;

/* local functions */
static int befs_btree_seekleaf(struct super_block *sb, befs_data_stream * ds,
			       befs_btree_super * bt_super,
			       befs_btree_node * this_node,
			       befs_off_t * node_off);

static int befs_bt_read_super(struct super_block *sb, befs_data_stream * ds,
			      befs_btree_super * sup);

static int befs_bt_read_node(struct super_block *sb, befs_data_stream * ds,
			     befs_btree_node * node, befs_off_t node_off);

static int befs_leafnode(befs_btree_node * node);

static fs16 *befs_bt_keylen_index(befs_btree_node * node);

static fs64 *befs_bt_valarray(befs_btree_node * node);

static char *befs_bt_keydata(befs_btree_node * node);

static int befs_find_key(struct super_block *sb, befs_btree_node * node,
			 const char *findkey, befs_off_t * value);

static char *befs_bt_get_key(struct super_block *sb, befs_btree_node * node,
			     int index, u16 * keylen);

static int befs_compare_strings(const void *key1, int keylen1,
				const void *key2, int keylen2);

/**
 * befs_bt_read_super - read in btree superblock convert to cpu byteorder
 * @sb: Filesystem superblock
 * @ds: Datastream to read from
 * @sup: Buffer in which to place the btree superblock
 *
 * Calls befs_read_datastream to read in the btree superblock and
 * makes sure it is in cpu byteorder, byteswapping if necessary.
 *
 * On success, returns BEFS_OK and *@sup contains the btree superblock,
 * in cpu byte order.
 *
 * On failure, BEFS_ERR is returned.
 */
static int
befs_bt_read_super(struct super_block *sb, befs_data_stream * ds,
		   befs_btree_super * sup)
{
	struct buffer_head *bh = NULL;
	befs_disk_btree_super *od_sup = NULL;

	befs_debug(sb, "---> %s", __func__);

	bh = befs_read_datastream(sb, ds, 0, NULL);

	if (!bh) {
		befs_error(sb, "Couldn't read index header.");
		goto error;
	}
	od_sup = (befs_disk_btree_super *) bh->b_data;
	befs_dump_index_entry(sb, od_sup);

	sup->magic = fs32_to_cpu(sb, od_sup->magic);
	sup->node_size = fs32_to_cpu(sb, od_sup->node_size);
	sup->max_depth = fs32_to_cpu(sb, od_sup->max_depth);
	sup->data_type = fs32_to_cpu(sb, od_sup->data_type);
	sup->root_node_ptr = fs64_to_cpu(sb, od_sup->root_node_ptr);
	sup->free_node_ptr = fs64_to_cpu(sb, od_sup->free_node_ptr);
	sup->max_size = fs64_to_cpu(sb, od_sup->max_size);

	brelse(bh);
	if (sup->magic != BEFS_BTREE_MAGIC) {
		befs_error(sb, "Index header has bad magic.");
		goto error;
	}

	befs_debug(sb, "<--- %s", __func__);
	return BEFS_OK;

      error:
	befs_debug(sb, "<--- %s ERROR", __func__);
	return BEFS_ERR;
}

/**
 * befs_bt_read_node - read in btree node and convert to cpu byteorder
 * @sb: Filesystem superblock
 * @ds: Datastream to read from
 * @node: Buffer in which to place the btree node
 * @node_off: Starting offset (in bytes) of the node in @ds
 *
 * Calls befs_read_datastream to read in the indicated btree node and
 * makes sure its header fields are in cpu byteorder, byteswapping if
 * necessary.
 * Note: node->bh must be NULL when this function called first
 * time. Don't forget brelse(node->bh) after last call.
 *
 * On success, returns BEFS_OK and *@node contains the btree node that
 * starts at @node_off, with the node->head fields in cpu byte order.
 *
 * On failure, BEFS_ERR is returned.
 */

static int
befs_bt_read_node(struct super_block *sb, befs_data_stream * ds,
		  befs_btree_node * node, befs_off_t node_off)
{
	uint off = 0;

	befs_debug(sb, "---> %s", __func__);

	if (node->bh)
		brelse(node->bh);

	node->bh = befs_read_datastream(sb, ds, node_off, &off);
	if (!node->bh) {
		befs_error(sb, "%s failed to read "
			   "node at %llu", __func__, node_off);
		befs_debug(sb, "<--- %s ERROR", __func__);

		return BEFS_ERR;
	}
	node->od_node =
	    (befs_btree_nodehead *) ((void *) node->bh->b_data + off);

	befs_dump_index_node(sb, node->od_node);

	node->head.left = fs64_to_cpu(sb, node->od_node->left);
	node->head.right = fs64_to_cpu(sb, node->od_node->right);
	node->head.overflow = fs64_to_cpu(sb, node->od_node->overflow);
	node->head.all_key_count =
	    fs16_to_cpu(sb, node->od_node->all_key_count);
	node->head.all_key_length =
	    fs16_to_cpu(sb, node->od_node->all_key_length);

	befs_debug(sb, "<--- %s", __func__);
	return BEFS_OK;
}

/**
 * befs_btree_find - Find a key in a befs B+tree
 * @sb: Filesystem superblock
 * @ds: Datastream containing btree
 * @key: Key string to lookup in btree
 * @value: Value stored with @key
 *
 * On success, returns BEFS_OK and sets *@value to the value stored
 * with @key (usually the disk block number of an inode).
 *
 * On failure, returns BEFS_ERR or BEFS_BT_NOT_FOUND.
 *
 * Algorithm:
 *   Read the superblock and rootnode of the b+tree.
 *   Drill down through the interior nodes using befs_find_key().
 *   Once at the correct leaf node, use befs_find_key() again to get the
 *   actuall value stored with the key.
 */
int
befs_btree_find(struct super_block *sb, befs_data_stream * ds,
		const char *key, befs_off_t * value)
{
	befs_btree_node *this_node = NULL;
	befs_btree_super bt_super;
	befs_off_t node_off;
	int res;

	befs_debug(sb, "---> %s Key: %s", __func__, key);

	if (befs_bt_read_super(sb, ds, &bt_super) != BEFS_OK) {
		befs_error(sb,
			   "befs_btree_find() failed to read index superblock");
		goto error;
	}

	this_node = kmalloc(sizeof (befs_btree_node),
						GFP_NOFS);
	if (!this_node) {
		befs_error(sb, "befs_btree_find() failed to allocate %zu "
			   "bytes of memory", sizeof (befs_btree_node));
		goto error;
	}

	this_node->bh = NULL;

	/* read in root node */
	node_off = bt_super.root_node_ptr;
	if (befs_bt_read_node(sb, ds, this_node, node_off) != BEFS_OK) {
		befs_error(sb, "befs_btree_find() failed to read "
			   "node at %llu", node_off);
		goto error_alloc;
	}

	while (!befs_leafnode(this_node)) {
		res = befs_find_key(sb, this_node, key, &node_off);
		if (res == BEFS_BT_NOT_FOUND)
			node_off = this_node->head.overflow;
		/* if no match, go to overflow node */
		if (befs_bt_read_node(sb, ds, this_node, node_off) != BEFS_OK) {
			befs_error(sb, "befs_btree_find() failed to read "
				   "node at %llu", node_off);
			goto error_alloc;
		}
	}

	/* at the correct leaf node now */

	res = befs_find_key(sb, this_node, key, value);

	brelse(this_node->bh);
	kfree(this_node);

	if (res != BEFS_BT_MATCH) {
		befs_debug(sb, "<--- %s Key %s not found", __func__, key);
		*value = 0;
		return BEFS_BT_NOT_FOUND;
	}
	befs_debug(sb, "<--- %s Found key %s, value %llu", __func__,
		   key, *value);
	return BEFS_OK;

      error_alloc:
	kfree(this_node);
      error:
	*value = 0;
	befs_debug(sb, "<--- %s ERROR", __func__);
	return BEFS_ERR;
}

/**
 * befs_find_key - Search for a key within a node
 * @sb: Filesystem superblock
 * @node: Node to find the key within
 * @findkey: Keystring to search for
 * @value: If key is found, the value stored with the key is put here
 *
 * finds exact match if one exists, and returns BEFS_BT_MATCH
 * If no exact match, finds first key in node that is greater
 * (alphabetically) than the search key and returns BEFS_BT_PARMATCH
 * (for partial match, I guess). Can you think of something better to
 * call it?
 *
 * If no key was a match or greater than the search key, return
 * BEFS_BT_NOT_FOUND.
 *
 * Use binary search instead of a linear.
 */
static int
befs_find_key(struct super_block *sb, befs_btree_node * node,
	      const char *findkey, befs_off_t * value)
{
	int first, last, mid;
	int eq;
	u16 keylen;
	int findkey_len;
	char *thiskey;
	fs64 *valarray;

	befs_debug(sb, "---> %s %s", __func__, findkey);

	*value = 0;

	findkey_len = strlen(findkey);

	/* if node can not contain key, just skeep this node */
	last = node->head.all_key_count - 1;
	thiskey = befs_bt_get_key(sb, node, last, &keylen);

	eq = befs_compare_strings(thiskey, keylen, findkey, findkey_len);
	if (eq < 0) {
		befs_debug(sb, "<--- %s %s not found", __func__, findkey);
		return BEFS_BT_NOT_FOUND;
	}

	valarray = befs_bt_valarray(node);

	/* simple binary search */
	first = 0;
	mid = 0;
	while (last >= first) {
		mid = (last + first) / 2;
		befs_debug(sb, "first: %d, last: %d, mid: %d", first, last,
			   mid);
		thiskey = befs_bt_get_key(sb, node, mid, &keylen);
		eq = befs_compare_strings(thiskey, keylen, findkey,
					  findkey_len);

		if (eq == 0) {
			befs_debug(sb, "<--- %s found %s at %d",
				   __func__, thiskey, mid);

			*value = fs64_to_cpu(sb, valarray[mid]);
			return BEFS_BT_MATCH;
		}
		if (eq > 0)
			last = mid - 1;
		else
			first = mid + 1;
	}
	if (eq < 0)
		*value = fs64_to_cpu(sb, valarray[mid + 1]);
	else
		*value = fs64_to_cpu(sb, valarray[mid]);
	befs_debug(sb, "<--- %s found %s at %d", __func__, thiskey, mid);
	return BEFS_BT_PARMATCH;
}

/**
 * befs_btree_read - Traverse leafnodes of a btree
 * @sb: Filesystem superblock
 * @ds: Datastream containing btree
 * @key_no: Key number (alphabetical order) of key to read
 * @bufsize: Size of the buffer to return key in
 * @keybuf: Pointer to a buffer to put the key in
 * @keysize: Length of the returned key
 * @value: Value stored with the returned key
 *
 * Heres how it works: Key_no is the index of the key/value pair to
 * return in keybuf/value.
 * Bufsize is the size of keybuf (BEFS_NAME_LEN+1 is a good size). Keysize is
 * the number of characters in the key (just a convenience).
 *
 * Algorithm:
 *   Get the first leafnode of the tree. See if the requested key is in that
 *   node. If not, follow the node->right link to the next leafnode. Repeat
 *   until the (key_no)th key is found or the tree is out of keys.
 */
int
befs_btree_read(struct super_block *sb, befs_data_stream * ds,
		loff_t key_no, size_t bufsize, char *keybuf, size_t * keysize,
		befs_off_t * value)
{
	befs_btree_node *this_node;
	befs_btree_super bt_super;
	befs_off_t node_off = 0;
	int cur_key;
	fs64 *valarray;
	char *keystart;
	u16 keylen;
	int res;

	uint key_sum = 0;

	befs_debug(sb, "---> %s", __func__);

	if (befs_bt_read_super(sb, ds, &bt_super) != BEFS_OK) {
		befs_error(sb,
			   "befs_btree_read() failed to read index superblock");
		goto error;
	}

	if ((this_node = kmalloc(sizeof (befs_btree_node), GFP_NOFS)) == NULL) {
		befs_error(sb, "befs_btree_read() failed to allocate %zu "
			   "bytes of memory", sizeof (befs_btree_node));
		goto error;
	}

	node_off = bt_super.root_node_ptr;
	this_node->bh = NULL;

	/* seeks down to first leafnode, reads it into this_node */
	res = befs_btree_seekleaf(sb, ds, &bt_super, this_node, &node_off);
	if (res == BEFS_BT_EMPTY) {
		brelse(this_node->bh);
		kfree(this_node);
		*value = 0;
		*keysize = 0;
		befs_debug(sb, "<--- %s Tree is EMPTY", __func__);
		return BEFS_BT_EMPTY;
	} else if (res == BEFS_ERR) {
		goto error_alloc;
	}

	/* find the leaf node containing the key_no key */

	while (key_sum + this_node->head.all_key_count <= key_no) {

		/* no more nodes to look in: key_no is too large */
		if (this_node->head.right == befs_bt_inval) {
			*keysize = 0;
			*value = 0;
			befs_debug(sb,
				   "<--- %s END of keys at %llu", __func__,
				   (unsigned long long)
				   key_sum + this_node->head.all_key_count);
			brelse(this_node->bh);
			kfree(this_node);
			return BEFS_BT_END;
		}

		key_sum += this_node->head.all_key_count;
		node_off = this_node->head.right;

		if (befs_bt_read_node(sb, ds, this_node, node_off) != BEFS_OK) {
			befs_error(sb, "%s failed to read node at %llu",
				  __func__, (unsigned long long)node_off);
			goto error_alloc;
		}
	}

	/* how many keys into this_node is key_no */
	cur_key = key_no - key_sum;

	/* get pointers to datastructures within the node body */
	valarray = befs_bt_valarray(this_node);

	keystart = befs_bt_get_key(sb, this_node, cur_key, &keylen);

	befs_debug(sb, "Read [%llu,%d]: keysize %d",
		   (long long unsigned int)node_off, (int)cur_key,
		   (int)keylen);

	if (bufsize < keylen + 1) {
		befs_error(sb, "%s keybuf too small (%zu) "
			   "for key of size %d", __func__, bufsize, keylen);
		brelse(this_node->bh);
		goto error_alloc;
	}

	strlcpy(keybuf, keystart, keylen + 1);
	*value = fs64_to_cpu(sb, valarray[cur_key]);
	*keysize = keylen;

	befs_debug(sb, "Read [%llu,%d]: Key \"%.*s\", Value %llu", node_off,
		   cur_key, keylen, keybuf, *value);

	brelse(this_node->bh);
	kfree(this_node);

	befs_debug(sb, "<--- %s", __func__);

	return BEFS_OK;

      error_alloc:
	kfree(this_node);

      error:
	*keysize = 0;
	*value = 0;
	befs_debug(sb, "<--- %s ERROR", __func__);
	return BEFS_ERR;
}

/**
 * befs_btree_seekleaf - Find the first leafnode in the btree
 * @sb: Filesystem superblock
 * @ds: Datastream containing btree
 * @bt_super: Pointer to the superblock of the btree
 * @this_node: Buffer to return the leafnode in
 * @node_off: Pointer to offset of current node within datastream. Modified
 * 		by the function.
 *
 *
 * Helper function for btree traverse. Moves the current position to the
 * start of the first leaf node.
 *
 * Also checks for an empty tree. If there are no keys, returns BEFS_BT_EMPTY.
 */
static int
befs_btree_seekleaf(struct super_block *sb, befs_data_stream * ds,
		    befs_btree_super * bt_super, befs_btree_node * this_node,
		    befs_off_t * node_off)
{

	befs_debug(sb, "---> %s", __func__);

	if (befs_bt_read_node(sb, ds, this_node, *node_off) != BEFS_OK) {
		befs_error(sb, "%s failed to read "
			   "node at %llu", __func__, *node_off);
		goto error;
	}
	befs_debug(sb, "Seekleaf to root node %llu", *node_off);

	if (this_node->head.all_key_count == 0 && befs_leafnode(this_node)) {
		befs_debug(sb, "<--- %s Tree is EMPTY", __func__);
		return BEFS_BT_EMPTY;
	}

	while (!befs_leafnode(this_node)) {

		if (this_node->head.all_key_count == 0) {
			befs_debug(sb, "%s encountered "
				   "an empty interior node: %llu. Using Overflow "
				   "node: %llu", __func__, *node_off,
				   this_node->head.overflow);
			*node_off = this_node->head.overflow;
		} else {
			fs64 *valarray = befs_bt_valarray(this_node);
			*node_off = fs64_to_cpu(sb, valarray[0]);
		}
		if (befs_bt_read_node(sb, ds, this_node, *node_off) != BEFS_OK) {
			befs_error(sb, "%s failed to read "
				   "node at %llu", __func__, *node_off);
			goto error;
		}

		befs_debug(sb, "Seekleaf to child node %llu", *node_off);
	}
	befs_debug(sb, "Node %llu is a leaf node", *node_off);

	return BEFS_OK;

      error:
	befs_debug(sb, "<--- %s ERROR", __func__);
	return BEFS_ERR;
}

/**
 * befs_leafnode - Determine if the btree node is a leaf node or an
 * interior node
 * @node: Pointer to node structure to test
 *
 * Return 1 if leaf, 0 if interior
 */
static int
befs_leafnode(befs_btree_node * node)
{
	/* all interior nodes (and only interior nodes) have an overflow node */
	if (node->head.overflow == befs_bt_inval)
		return 1;
	else
		return 0;
}

/**
 * befs_bt_keylen_index - Finds start of keylen index in a node
 * @node: Pointer to the node structure to find the keylen index within
 *
 * Returns a pointer to the start of the key length index array
 * of the B+tree node *@node
 *
 * "The length of all the keys in the node is added to the size of the
 * header and then rounded up to a multiple of four to get the beginning
 * of the key length index" (p.88, practical filesystem design).
 *
 * Except that rounding up to 8 works, and rounding up to 4 doesn't.
 */
static fs16 *
befs_bt_keylen_index(befs_btree_node * node)
{
	const int keylen_align = 8;
	unsigned long int off =
	    (sizeof (befs_btree_nodehead) + node->head.all_key_length);
	ulong tmp = off % keylen_align;

	if (tmp)
		off += keylen_align - tmp;

	return (fs16 *) ((void *) node->od_node + off);
}

/**
 * befs_bt_valarray - Finds the start of value array in a node
 * @node: Pointer to the node structure to find the value array within
 *
 * Returns a pointer to the start of the value array
 * of the node pointed to by the node header
 */
static fs64 *
befs_bt_valarray(befs_btree_node * node)
{
	void *keylen_index_start = (void *) befs_bt_keylen_index(node);
	size_t keylen_index_size = node->head.all_key_count * sizeof (fs16);

	return (fs64 *) (keylen_index_start + keylen_index_size);
}

/**
 * befs_bt_keydata - Finds start of keydata array in a node
 * @node: Pointer to the node structure to find the keydata array within
 *
 * Returns a pointer to the start of the keydata array
 * of the node pointed to by the node header
 */
static char *
befs_bt_keydata(befs_btree_node * node)
{
	return (char *) ((void *) node->od_node + sizeof (befs_btree_nodehead));
}

/**
 * befs_bt_get_key - returns a pointer to the start of a key
 * @sb: filesystem superblock
 * @node: node in which to look for the key
 * @index: the index of the key to get
 * @keylen: modified to be the length of the key at @index
 *
 * Returns a valid pointer into @node on success.
 * Returns NULL on failure (bad input) and sets *@keylen = 0
 */
static char *
befs_bt_get_key(struct super_block *sb, befs_btree_node * node,
		int index, u16 * keylen)
{
	int prev_key_end;
	char *keystart;
	fs16 *keylen_index;

	if (index < 0 || index > node->head.all_key_count) {
		*keylen = 0;
		return NULL;
	}

	keystart = befs_bt_keydata(node);
	keylen_index = befs_bt_keylen_index(node);

	if (index == 0)
		prev_key_end = 0;
	else
		prev_key_end = fs16_to_cpu(sb, keylen_index[index - 1]);

	*keylen = fs16_to_cpu(sb, keylen_index[index]) - prev_key_end;

	return keystart + prev_key_end;
}

/**
 * befs_compare_strings - compare two strings
 * @key1: pointer to the first key to be compared
 * @keylen1: length in bytes of key1
 * @key2: pointer to the second key to be compared
 * @keylen2: length in bytes of key2
 *
 * Returns 0 if @key1 and @key2 are equal.
 * Returns >0 if @key1 is greater.
 * Returns <0 if @key2 is greater..
 */
static int
befs_compare_strings(const void *key1, int keylen1,
		     const void *key2, int keylen2)
{
	int len = min_t(int, keylen1, keylen2);
	int result = strncmp(key1, key2, len);
	if (result == 0)
		result = keylen1 - keylen2;
	return result;
}

/* These will be used for non-string keyed btrees */
#if 0
static int
btree_compare_int32(cont void *key1, int keylen1, const void *key2, int keylen2)
{
	return *(int32_t *) key1 - *(int32_t *) key2;
}

static int
btree_compare_uint32(cont void *key1, int keylen1,
		     const void *key2, int keylen2)
{
	if (*(u_int32_t *) key1 == *(u_int32_t *) key2)
		return 0;
	else if (*(u_int32_t *) key1 > *(u_int32_t *) key2)
		return 1;

	return -1;
}
static int
btree_compare_int64(cont void *key1, int keylen1, const void *key2, int keylen2)
{
	if (*(int64_t *) key1 == *(int64_t *) key2)
		return 0;
	else if (*(int64_t *) key1 > *(int64_t *) key2)
		return 1;

	return -1;
}

static int
btree_compare_uint64(cont void *key1, int keylen1,
		     const void *key2, int keylen2)
{
	if (*(u_int64_t *) key1 == *(u_int64_t *) key2)
		return 0;
	else if (*(u_int64_t *) key1 > *(u_int64_t *) key2)
		return 1;

	return -1;
}

static int
btree_compare_float(cont void *key1, int keylen1, const void *key2, int keylen2)
{
	float result = *(float *) key1 - *(float *) key2;
	if (result == 0.0f)
		return 0;

	return (result < 0.0f) ? -1 : 1;
}

static int
btree_compare_double(cont void *key1, int keylen1,
		     const void *key2, int keylen2)
{
	double result = *(double *) key1 - *(double *) key2;
	if (result == 0.0)
		return 0;

	return (result < 0.0) ? -1 : 1;
}
#endif				//0
/************************************************************/
/* ../linux-3.17/fs/befs/btree.c */
/************************************************************/
/*
 * super.c
 *
 * Copyright (C) 2001-2002 Will Dyson <will_dyson@pobox.com>
 *
 * Licensed under the GNU GPL. See the file COPYING for details.
 *
 */

#include <linux/fs.h>
#include <asm/page.h> /* for PAGE_SIZE */

// #include "befs.h"
#include "super.h"

/**
 * load_befs_sb -- Read from disk and properly byteswap all the fields
 * of the befs superblock
 *
 *
 *
 *
 */
int
befs_load_sb(struct super_block *sb, befs_super_block * disk_sb)
{
	befs_sb_info *befs_sb = BEFS_SB(sb);

	/* Check the byte order of the filesystem */
	if (disk_sb->fs_byte_order == BEFS_BYTEORDER_NATIVE_LE)
	    befs_sb->byte_order = BEFS_BYTESEX_LE;
	else if (disk_sb->fs_byte_order == BEFS_BYTEORDER_NATIVE_BE)
	    befs_sb->byte_order = BEFS_BYTESEX_BE;

	befs_sb->magic1 = fs32_to_cpu(sb, disk_sb->magic1);
	befs_sb->magic2 = fs32_to_cpu(sb, disk_sb->magic2);
	befs_sb->magic3 = fs32_to_cpu(sb, disk_sb->magic3);
	befs_sb->block_size = fs32_to_cpu(sb, disk_sb->block_size);
	befs_sb->block_shift = fs32_to_cpu(sb, disk_sb->block_shift);
	befs_sb->num_blocks = fs64_to_cpu(sb, disk_sb->num_blocks);
	befs_sb->used_blocks = fs64_to_cpu(sb, disk_sb->used_blocks);
	befs_sb->inode_size = fs32_to_cpu(sb, disk_sb->inode_size);

	befs_sb->blocks_per_ag = fs32_to_cpu(sb, disk_sb->blocks_per_ag);
	befs_sb->ag_shift = fs32_to_cpu(sb, disk_sb->ag_shift);
	befs_sb->num_ags = fs32_to_cpu(sb, disk_sb->num_ags);

	befs_sb->log_blocks = fsrun_to_cpu(sb, disk_sb->log_blocks);
	befs_sb->log_start = fs64_to_cpu(sb, disk_sb->log_start);
	befs_sb->log_end = fs64_to_cpu(sb, disk_sb->log_end);

	befs_sb->root_dir = fsrun_to_cpu(sb, disk_sb->root_dir);
	befs_sb->indices = fsrun_to_cpu(sb, disk_sb->indices);
	befs_sb->nls = NULL;

	return BEFS_OK;
}

int
befs_check_sb(struct super_block *sb)
{
	befs_sb_info *befs_sb = BEFS_SB(sb);

	/* Check magic headers of super block */
	if ((befs_sb->magic1 != BEFS_SUPER_MAGIC1)
	    || (befs_sb->magic2 != BEFS_SUPER_MAGIC2)
	    || (befs_sb->magic3 != BEFS_SUPER_MAGIC3)) {
		befs_error(sb, "invalid magic header");
		return BEFS_ERR;
	}

	/*
	 * Check blocksize of BEFS.
	 *
	 * Blocksize of BEFS is 1024, 2048, 4096 or 8192.
	 */

	if ((befs_sb->block_size != 1024)
	    && (befs_sb->block_size != 2048)
	    && (befs_sb->block_size != 4096)
	    && (befs_sb->block_size != 8192)) {
		befs_error(sb, "invalid blocksize: %u", befs_sb->block_size);
		return BEFS_ERR;
	}

	if (befs_sb->block_size > PAGE_SIZE) {
		befs_error(sb, "blocksize(%u) cannot be larger"
			   "than system pagesize(%lu)", befs_sb->block_size,
			   PAGE_SIZE);
		return BEFS_ERR;
	}

	/*
	   * block_shift and block_size encode the same information
	   * in different ways as a consistency check.
	 */

	if ((1 << befs_sb->block_shift) != befs_sb->block_size) {
		befs_error(sb, "block_shift disagrees with block_size. "
			   "Corruption likely.");
		return BEFS_ERR;
	}

	if (befs_sb->log_start != befs_sb->log_end) {
		befs_error(sb, "Filesystem not clean! There are blocks in the "
			   "journal. You must boot into BeOS and mount this volume "
			   "to make it clean.");
		return BEFS_ERR;
	}

	return BEFS_OK;
}
/************************************************************/
/* ../linux-3.17/fs/befs/super.c */
/************************************************************/
/*
 * inode.c
 *
 * Copyright (C) 2001 Will Dyson <will_dyson@pobox.com>
 */

// #include <linux/fs.h>

// #include "befs.h"
#include "inode.h"

/*
	Validates the correctness of the befs inode
	Returns BEFS_OK if the inode should be used, otherwise
	returns BEFS_BAD_INODE
*/
int
befs_check_inode(struct super_block *sb, befs_inode * raw_inode,
		 befs_blocknr_t inode)
{
	u32 magic1 = fs32_to_cpu(sb, raw_inode->magic1);
	befs_inode_addr ino_num = fsrun_to_cpu(sb, raw_inode->inode_num);
	u32 flags = fs32_to_cpu(sb, raw_inode->flags);

	/* check magic header. */
	if (magic1 != BEFS_INODE_MAGIC1) {
		befs_error(sb,
			   "Inode has a bad magic header - inode = %lu",
			   (unsigned long)inode);
		return BEFS_BAD_INODE;
	}

	/*
	 * Sanity check2: inodes store their own block address. Check it.
	 */
	if (inode != iaddr2blockno(sb, &ino_num)) {
		befs_error(sb, "inode blocknr field disagrees with vfs "
			   "VFS: %lu, Inode %lu", (unsigned long)
			   inode, (unsigned long)iaddr2blockno(sb, &ino_num));
		return BEFS_BAD_INODE;
	}

	/*
	 * check flag
	 */

	if (!(flags & BEFS_INODE_IN_USE)) {
		befs_error(sb, "inode is not used - inode = %lu",
			   (unsigned long)inode);
		return BEFS_BAD_INODE;
	}

	return BEFS_OK;
}
/************************************************************/
/* ../linux-3.17/fs/befs/inode.c */
/************************************************************/
/*
 *  linux/fs/befs/debug.c
 *
 * Copyright (C) 2001 Will Dyson (will_dyson at pobox.com)
 *
 * With help from the ntfs-tng driver by Anton Altparmakov
 *
 * Copyright (C) 1999  Makoto Kato (m_kato@ga2.so-net.ne.jp)
 *
 * debug functions
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#ifdef __KERNEL__

#include <stdarg.h>
// #include <linux/string.h>
#include <linux/spinlock.h>
// #include <linux/kernel.h>
// #include <linux/fs.h>
// #include <linux/slab.h>

#endif				/* __KERNEL__ */

// #include "befs.h"

void
befs_error(const struct super_block *sb, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_err("(%s): %pV\n", sb->s_id, &vaf);
	va_end(args);
}

void
befs_warning(const struct super_block *sb, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_warn("(%s): %pV\n", sb->s_id, &vaf);
	va_end(args);
}

void
befs_debug(const struct super_block *sb, const char *fmt, ...)
{
#ifdef CONFIG_BEFS_DEBUG

	struct va_format vaf;
	va_list args;
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_debug("(%s): %pV\n", sb->s_id, &vaf);
	va_end(args);

#endif				//CONFIG_BEFS_DEBUG
}

void
befs_dump_inode(const struct super_block *sb, befs_inode * inode)
{
#ifdef CONFIG_BEFS_DEBUG

	befs_block_run tmp_run;

	befs_debug(sb, "befs_inode information");

	befs_debug(sb, "  magic1 %08x", fs32_to_cpu(sb, inode->magic1));

	tmp_run = fsrun_to_cpu(sb, inode->inode_num);
	befs_debug(sb, "  inode_num %u, %hu, %hu",
		   tmp_run.allocation_group, tmp_run.start, tmp_run.len);

	befs_debug(sb, "  uid %u", fs32_to_cpu(sb, inode->uid));
	befs_debug(sb, "  gid %u", fs32_to_cpu(sb, inode->gid));
	befs_debug(sb, "  mode %08x", fs32_to_cpu(sb, inode->mode));
	befs_debug(sb, "  flags %08x", fs32_to_cpu(sb, inode->flags));
	befs_debug(sb, "  create_time %llu",
		   fs64_to_cpu(sb, inode->create_time));
	befs_debug(sb, "  last_modified_time %llu",
		   fs64_to_cpu(sb, inode->last_modified_time));

	tmp_run = fsrun_to_cpu(sb, inode->parent);
	befs_debug(sb, "  parent [%u, %hu, %hu]",
		   tmp_run.allocation_group, tmp_run.start, tmp_run.len);

	tmp_run = fsrun_to_cpu(sb, inode->attributes);
	befs_debug(sb, "  attributes [%u, %hu, %hu]",
		   tmp_run.allocation_group, tmp_run.start, tmp_run.len);

	befs_debug(sb, "  type %08x", fs32_to_cpu(sb, inode->type));
	befs_debug(sb, "  inode_size %u", fs32_to_cpu(sb, inode->inode_size));

	if (S_ISLNK(fs32_to_cpu(sb, inode->mode))) {
		befs_debug(sb, "  Symbolic link [%s]", inode->data.symlink);
	} else {
		int i;

		for (i = 0; i < BEFS_NUM_DIRECT_BLOCKS; i++) {
			tmp_run =
			    fsrun_to_cpu(sb, inode->data.datastream.direct[i]);
			befs_debug(sb, "  direct %d [%u, %hu, %hu]", i,
				   tmp_run.allocation_group, tmp_run.start,
				   tmp_run.len);
		}
		befs_debug(sb, "  max_direct_range %llu",
			   fs64_to_cpu(sb,
				       inode->data.datastream.
				       max_direct_range));

		tmp_run = fsrun_to_cpu(sb, inode->data.datastream.indirect);
		befs_debug(sb, "  indirect [%u, %hu, %hu]",
			   tmp_run.allocation_group,
			   tmp_run.start, tmp_run.len);

		befs_debug(sb, "  max_indirect_range %llu",
			   fs64_to_cpu(sb,
				       inode->data.datastream.
				       max_indirect_range));

		tmp_run =
		    fsrun_to_cpu(sb, inode->data.datastream.double_indirect);
		befs_debug(sb, "  double indirect [%u, %hu, %hu]",
			   tmp_run.allocation_group, tmp_run.start,
			   tmp_run.len);

		befs_debug(sb, "  max_double_indirect_range %llu",
			   fs64_to_cpu(sb,
				       inode->data.datastream.
				       max_double_indirect_range));

		befs_debug(sb, "  size %llu",
			   fs64_to_cpu(sb, inode->data.datastream.size));
	}

#endif				//CONFIG_BEFS_DEBUG
}

/*
 * Display super block structure for debug.
 */

void
befs_dump_super_block(const struct super_block *sb, befs_super_block * sup)
{
#ifdef CONFIG_BEFS_DEBUG

	befs_block_run tmp_run;

	befs_debug(sb, "befs_super_block information");

	befs_debug(sb, "  name %s", sup->name);
	befs_debug(sb, "  magic1 %08x", fs32_to_cpu(sb, sup->magic1));
	befs_debug(sb, "  fs_byte_order %08x",
		   fs32_to_cpu(sb, sup->fs_byte_order));

	befs_debug(sb, "  block_size %u", fs32_to_cpu(sb, sup->block_size));
	befs_debug(sb, "  block_shift %u", fs32_to_cpu(sb, sup->block_shift));

	befs_debug(sb, "  num_blocks %llu", fs64_to_cpu(sb, sup->num_blocks));
	befs_debug(sb, "  used_blocks %llu", fs64_to_cpu(sb, sup->used_blocks));

	befs_debug(sb, "  magic2 %08x", fs32_to_cpu(sb, sup->magic2));
	befs_debug(sb, "  blocks_per_ag %u",
		   fs32_to_cpu(sb, sup->blocks_per_ag));
	befs_debug(sb, "  ag_shift %u", fs32_to_cpu(sb, sup->ag_shift));
	befs_debug(sb, "  num_ags %u", fs32_to_cpu(sb, sup->num_ags));

	befs_debug(sb, "  flags %08x", fs32_to_cpu(sb, sup->flags));

	tmp_run = fsrun_to_cpu(sb, sup->log_blocks);
	befs_debug(sb, "  log_blocks %u, %hu, %hu",
		   tmp_run.allocation_group, tmp_run.start, tmp_run.len);

	befs_debug(sb, "  log_start %lld", fs64_to_cpu(sb, sup->log_start));
	befs_debug(sb, "  log_end %lld", fs64_to_cpu(sb, sup->log_end));

	befs_debug(sb, "  magic3 %08x", fs32_to_cpu(sb, sup->magic3));

	tmp_run = fsrun_to_cpu(sb, sup->root_dir);
	befs_debug(sb, "  root_dir %u, %hu, %hu",
		   tmp_run.allocation_group, tmp_run.start, tmp_run.len);

	tmp_run = fsrun_to_cpu(sb, sup->indices);
	befs_debug(sb, "  indices %u, %hu, %hu",
		   tmp_run.allocation_group, tmp_run.start, tmp_run.len);

#endif				//CONFIG_BEFS_DEBUG
}

#if 0
/* unused */
void
befs_dump_small_data(const struct super_block *sb, befs_small_data * sd)
{
}

/* unused */
void
befs_dump_run(const struct super_block *sb, befs_disk_block_run run)
{
#ifdef CONFIG_BEFS_DEBUG

	befs_block_run n = fsrun_to_cpu(sb, run);

	befs_debug(sb, "[%u, %hu, %hu]", n.allocation_group, n.start, n.len);

#endif				//CONFIG_BEFS_DEBUG
}
#endif  /*  0  */

void
befs_dump_index_entry(const struct super_block *sb, befs_disk_btree_super * super)
{
#ifdef CONFIG_BEFS_DEBUG

	befs_debug(sb, "Btree super structure");
	befs_debug(sb, "  magic %08x", fs32_to_cpu(sb, super->magic));
	befs_debug(sb, "  node_size %u", fs32_to_cpu(sb, super->node_size));
	befs_debug(sb, "  max_depth %08x", fs32_to_cpu(sb, super->max_depth));

	befs_debug(sb, "  data_type %08x", fs32_to_cpu(sb, super->data_type));
	befs_debug(sb, "  root_node_pointer %016LX",
		   fs64_to_cpu(sb, super->root_node_ptr));
	befs_debug(sb, "  free_node_pointer %016LX",
		   fs64_to_cpu(sb, super->free_node_ptr));
	befs_debug(sb, "  maximum size %016LX",
		   fs64_to_cpu(sb, super->max_size));

#endif				//CONFIG_BEFS_DEBUG
}

void
befs_dump_index_node(const struct super_block *sb, befs_btree_nodehead * node)
{
#ifdef CONFIG_BEFS_DEBUG

	befs_debug(sb, "Btree node structure");
	befs_debug(sb, "  left %016LX", fs64_to_cpu(sb, node->left));
	befs_debug(sb, "  right %016LX", fs64_to_cpu(sb, node->right));
	befs_debug(sb, "  overflow %016LX", fs64_to_cpu(sb, node->overflow));
	befs_debug(sb, "  all_key_count %hu",
		   fs16_to_cpu(sb, node->all_key_count));
	befs_debug(sb, "  all_key_length %hu",
		   fs16_to_cpu(sb, node->all_key_length));

#endif				//CONFIG_BEFS_DEBUG
}
/************************************************************/
/* ../linux-3.17/fs/befs/debug.c */
/************************************************************/
/*
 * linux/fs/befs/io.c
 *
 * Copyright (C) 2001 Will Dyson <will_dyson@pobox.com
 *
 * Based on portions of file.c and inode.c
 * by Makoto Kato (m_kato@ga2.so-net.ne.jp)
 *
 * Many thanks to Dominic Giampaolo, author of Practical File System
 * Design with the Be File System, for such a helpful book.
 *
 */

// #include <linux/buffer_head.h>

// #include "befs.h"
// #include "io.h"

/*
 * Converts befs notion of disk addr to a disk offset and uses
 * linux kernel function sb_bread() to get the buffer containing
 * the offset. -Will Dyson
 *
 */

struct buffer_head *
befs_bread_iaddr(struct super_block *sb, befs_inode_addr iaddr)
{
	struct buffer_head *bh = NULL;
	befs_blocknr_t block = 0;
	befs_sb_info *befs_sb = BEFS_SB(sb);

	befs_debug(sb, "---> Enter %s "
		   "[%u, %hu, %hu]", __func__, iaddr.allocation_group,
		   iaddr.start, iaddr.len);

	if (iaddr.allocation_group > befs_sb->num_ags) {
		befs_error(sb, "BEFS: Invalid allocation group %u, max is %u",
			   iaddr.allocation_group, befs_sb->num_ags);
		goto error;
	}

	block = iaddr2blockno(sb, &iaddr);

	befs_debug(sb, "%s: offset = %lu", __func__, (unsigned long)block);

	bh = sb_bread(sb, block);

	if (bh == NULL) {
		befs_error(sb, "Failed to read block %lu",
			   (unsigned long)block);
		goto error;
	}

	befs_debug(sb, "<--- %s", __func__);
	return bh;

      error:
	befs_debug(sb, "<--- %s ERROR", __func__);
	return NULL;
}

struct buffer_head *
befs_bread(struct super_block *sb, befs_blocknr_t block)
{
	struct buffer_head *bh = NULL;

	befs_debug(sb, "---> Enter %s %lu", __func__, (unsigned long)block);

	bh = sb_bread(sb, block);

	if (bh == NULL) {
		befs_error(sb, "Failed to read block %lu",
			   (unsigned long)block);
		goto error;
	}

	befs_debug(sb, "<--- %s", __func__);

	return bh;

      error:
	befs_debug(sb, "<--- %s ERROR", __func__);
	return NULL;
}
/************************************************************/
/* ../linux-3.17/fs/befs/io.c */
/************************************************************/
/*
 * linux/fs/befs/linuxvfs.c
 *
 * Copyright (C) 2001 Will Dyson <will_dyson@pobox.com
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
// #include <linux/slab.h>
// #include <linux/fs.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/nls.h>
// #include <linux/buffer_head.h>
#include <linux/vfs.h>
#include <linux/parser.h>
#include <linux/namei.h>
#include <linux/sched.h>

// #include "befs.h"
// #include "btree.h"
// #include "inode.h"
// #include "datastream.h"
// #include "super.h"
// #include "io.h"

MODULE_DESCRIPTION("BeOS File System (BeFS) driver");
MODULE_AUTHOR("Will Dyson");
MODULE_LICENSE("GPL");

/* The units the vfs expects inode->i_blocks to be in */
#define VFS_BLOCK_SIZE 512

static int befs_readdir(struct file *, struct dir_context *);
static int befs_get_block(struct inode *, sector_t, struct buffer_head *, int);
static int befs_readpage(struct file *file, struct page *page);
static sector_t befs_bmap(struct address_space *mapping, sector_t block);
static struct dentry *befs_lookup(struct inode *, struct dentry *, unsigned int);
static struct inode *befs_iget(struct super_block *, unsigned long);
static struct inode *befs_alloc_inode(struct super_block *sb);
static void befs_destroy_inode(struct inode *inode);
static void befs_destroy_inodecache(void);
static void *befs_follow_link(struct dentry *, struct nameidata *);
static void *befs_fast_follow_link(struct dentry *, struct nameidata *);
static int befs_utf2nls(struct super_block *sb, const char *in, int in_len,
			char **out, int *out_len);
static int befs_nls2utf(struct super_block *sb, const char *in, int in_len,
			char **out, int *out_len);
static void befs_put_super(struct super_block *);
static int befs_remount(struct super_block *, int *, char *);
static int befs_statfs(struct dentry *, struct kstatfs *);
static int parse_options(char *, befs_mount_options *);

static const struct super_operations befs_sops = {
	.alloc_inode	= befs_alloc_inode,	/* allocate a new inode */
	.destroy_inode	= befs_destroy_inode, /* deallocate an inode */
	.put_super	= befs_put_super,	/* uninit super */
	.statfs		= befs_statfs,	/* statfs */
	.remount_fs	= befs_remount,
	.show_options	= generic_show_options,
};

/* slab cache for befs_inode_info objects */
static struct kmem_cache *befs_inode_cachep;

static const struct file_operations befs_dir_operations = {
	.read		= generic_read_dir,
	.iterate	= befs_readdir,
	.llseek		= generic_file_llseek,
};

static const struct inode_operations befs_dir_inode_operations = {
	.lookup		= befs_lookup,
};

static const struct address_space_operations befs_aops = {
	.readpage	= befs_readpage,
	.bmap		= befs_bmap,
};

static const struct inode_operations befs_fast_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= befs_fast_follow_link,
};

static const struct inode_operations befs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= befs_follow_link,
	.put_link	= kfree_put_link,
};

/*
 * Called by generic_file_read() to read a page of data
 *
 * In turn, simply calls a generic block read function and
 * passes it the address of befs_get_block, for mapping file
 * positions to disk blocks.
 */
static int
befs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, befs_get_block);
}

static sector_t
befs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, befs_get_block);
}

/*
 * Generic function to map a file position (block) to a
 * disk offset (passed back in bh_result).
 *
 * Used by many higher level functions.
 *
 * Calls befs_fblock2brun() in datastream.c to do the real work.
 *
 * -WD 10-26-01
 */

static int
befs_get_block(struct inode *inode, sector_t block,
	       struct buffer_head *bh_result, int create)
{
	struct super_block *sb = inode->i_sb;
	befs_data_stream *ds = &BEFS_I(inode)->i_data.ds;
	befs_block_run run = BAD_IADDR;
	int res = 0;
	ulong disk_off;

	befs_debug(sb, "---> befs_get_block() for inode %lu, block %ld",
		   (unsigned long)inode->i_ino, (long)block);
	if (create) {
		befs_error(sb, "befs_get_block() was asked to write to "
			   "block %ld in inode %lu", (long)block,
			   (unsigned long)inode->i_ino);
		return -EPERM;
	}

	res = befs_fblock2brun(sb, ds, block, &run);
	if (res != BEFS_OK) {
		befs_error(sb,
			   "<--- %s for inode %lu, block %ld ERROR",
			   __func__, (unsigned long)inode->i_ino,
			   (long)block);
		return -EFBIG;
	}

	disk_off = (ulong) iaddr2blockno(sb, &run);

	map_bh(bh_result, inode->i_sb, disk_off);

	befs_debug(sb, "<--- %s for inode %lu, block %ld, disk address %lu",
		  __func__, (unsigned long)inode->i_ino, (long)block,
		  (unsigned long)disk_off);

	return 0;
}

static struct dentry *
befs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct inode *inode = NULL;
	struct super_block *sb = dir->i_sb;
	befs_data_stream *ds = &BEFS_I(dir)->i_data.ds;
	befs_off_t offset;
	int ret;
	int utfnamelen;
	char *utfname;
	const char *name = dentry->d_name.name;

	befs_debug(sb, "---> %s name %s inode %ld", __func__,
		   dentry->d_name.name, dir->i_ino);

	/* Convert to UTF-8 */
	if (BEFS_SB(sb)->nls) {
		ret =
		    befs_nls2utf(sb, name, strlen(name), &utfname, &utfnamelen);
		if (ret < 0) {
			befs_debug(sb, "<--- %s ERROR", __func__);
			return ERR_PTR(ret);
		}
		ret = befs_btree_find(sb, ds, utfname, &offset);
		kfree(utfname);

	} else {
		ret = befs_btree_find(sb, ds, dentry->d_name.name, &offset);
	}

	if (ret == BEFS_BT_NOT_FOUND) {
		befs_debug(sb, "<--- %s %s not found", __func__,
			   dentry->d_name.name);
		return ERR_PTR(-ENOENT);

	} else if (ret != BEFS_OK || offset == 0) {
		befs_warning(sb, "<--- %s Error", __func__);
		return ERR_PTR(-ENODATA);
	}

	inode = befs_iget(dir->i_sb, (ino_t) offset);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	d_add(dentry, inode);

	befs_debug(sb, "<--- %s", __func__);

	return NULL;
}

static int
befs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	befs_data_stream *ds = &BEFS_I(inode)->i_data.ds;
	befs_off_t value;
	int result;
	size_t keysize;
	unsigned char d_type;
	char keybuf[BEFS_NAME_LEN + 1];
	const char *dirname = file->f_path.dentry->d_name.name;

	befs_debug(sb, "---> %s name %s, inode %ld, ctx->pos %lld",
		  __func__, dirname, inode->i_ino, ctx->pos);

more:
	result = befs_btree_read(sb, ds, ctx->pos, BEFS_NAME_LEN + 1,
				 keybuf, &keysize, &value);

	if (result == BEFS_ERR) {
		befs_debug(sb, "<--- %s ERROR", __func__);
		befs_error(sb, "IO error reading %s (inode %lu)",
			   dirname, inode->i_ino);
		return -EIO;

	} else if (result == BEFS_BT_END) {
		befs_debug(sb, "<--- %s END", __func__);
		return 0;

	} else if (result == BEFS_BT_EMPTY) {
		befs_debug(sb, "<--- %s Empty directory", __func__);
		return 0;
	}

	d_type = DT_UNKNOWN;

	/* Convert to NLS */
	if (BEFS_SB(sb)->nls) {
		char *nlsname;
		int nlsnamelen;
		result =
		    befs_utf2nls(sb, keybuf, keysize, &nlsname, &nlsnamelen);
		if (result < 0) {
			befs_debug(sb, "<--- %s ERROR", __func__);
			return result;
		}
		if (!dir_emit(ctx, nlsname, nlsnamelen,
				 (ino_t) value, d_type)) {
			kfree(nlsname);
			return 0;
		}
		kfree(nlsname);
	} else {
		if (!dir_emit(ctx, keybuf, keysize,
				 (ino_t) value, d_type))
			return 0;
	}
	ctx->pos++;
	goto more;

	befs_debug(sb, "<--- %s pos %lld", __func__, ctx->pos);

	return 0;
}

static struct inode *
befs_alloc_inode(struct super_block *sb)
{
        struct befs_inode_info *bi;
        bi = (struct befs_inode_info *)kmem_cache_alloc(befs_inode_cachep,
							GFP_KERNEL);
        if (!bi)
                return NULL;
        return &bi->vfs_inode;
}

static void befs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
        kmem_cache_free(befs_inode_cachep, BEFS_I(inode));
}

static void befs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, befs_i_callback);
}

static void init_once(void *foo)
{
        struct befs_inode_info *bi = (struct befs_inode_info *) foo;

	inode_init_once(&bi->vfs_inode);
}

static struct inode *befs_iget(struct super_block *sb, unsigned long ino)
{
	struct buffer_head *bh = NULL;
	befs_inode *raw_inode = NULL;

	befs_sb_info *befs_sb = BEFS_SB(sb);
	befs_inode_info *befs_ino = NULL;
	struct inode *inode;
	long ret = -EIO;

	befs_debug(sb, "---> %s inode = %lu", __func__, ino);

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	befs_ino = BEFS_I(inode);

	/* convert from vfs's inode number to befs's inode number */
	befs_ino->i_inode_num = blockno2iaddr(sb, inode->i_ino);

	befs_debug(sb, "  real inode number [%u, %hu, %hu]",
		   befs_ino->i_inode_num.allocation_group,
		   befs_ino->i_inode_num.start, befs_ino->i_inode_num.len);

	bh = befs_bread(sb, inode->i_ino);
	if (!bh) {
		befs_error(sb, "unable to read inode block - "
			   "inode = %lu", inode->i_ino);
		goto unacquire_none;
	}

	raw_inode = (befs_inode *) bh->b_data;

	befs_dump_inode(sb, raw_inode);

	if (befs_check_inode(sb, raw_inode, inode->i_ino) != BEFS_OK) {
		befs_error(sb, "Bad inode: %lu", inode->i_ino);
		goto unacquire_bh;
	}

	inode->i_mode = (umode_t) fs32_to_cpu(sb, raw_inode->mode);

	/*
	 * set uid and gid.  But since current BeOS is single user OS, so
	 * you can change by "uid" or "gid" options.
	 */

	inode->i_uid = befs_sb->mount_opts.use_uid ?
		befs_sb->mount_opts.uid :
		make_kuid(&init_user_ns, fs32_to_cpu(sb, raw_inode->uid));
	inode->i_gid = befs_sb->mount_opts.use_gid ?
		befs_sb->mount_opts.gid :
		make_kgid(&init_user_ns, fs32_to_cpu(sb, raw_inode->gid));

	set_nlink(inode, 1);

	/*
	 * BEFS's time is 64 bits, but current VFS is 32 bits...
	 * BEFS don't have access time. Nor inode change time. VFS
	 * doesn't have creation time.
	 * Also, the lower 16 bits of the last_modified_time and
	 * create_time are just a counter to help ensure uniqueness
	 * for indexing purposes. (PFD, page 54)
	 */

	inode->i_mtime.tv_sec =
	    fs64_to_cpu(sb, raw_inode->last_modified_time) >> 16;
	inode->i_mtime.tv_nsec = 0;   /* lower 16 bits are not a time */
	inode->i_ctime = inode->i_mtime;
	inode->i_atime = inode->i_mtime;

	befs_ino->i_inode_num = fsrun_to_cpu(sb, raw_inode->inode_num);
	befs_ino->i_parent = fsrun_to_cpu(sb, raw_inode->parent);
	befs_ino->i_attribute = fsrun_to_cpu(sb, raw_inode->attributes);
	befs_ino->i_flags = fs32_to_cpu(sb, raw_inode->flags);

	if (S_ISLNK(inode->i_mode) && !(befs_ino->i_flags & BEFS_LONG_SYMLINK)){
		inode->i_size = 0;
		inode->i_blocks = befs_sb->block_size / VFS_BLOCK_SIZE;
		strlcpy(befs_ino->i_data.symlink, raw_inode->data.symlink,
			BEFS_SYMLINK_LEN);
	} else {
		int num_blks;

		befs_ino->i_data.ds =
		    fsds_to_cpu(sb, &raw_inode->data.datastream);

		num_blks = befs_count_blocks(sb, &befs_ino->i_data.ds);
		inode->i_blocks =
		    num_blks * (befs_sb->block_size / VFS_BLOCK_SIZE);
		inode->i_size = befs_ino->i_data.ds.size;
	}

	inode->i_mapping->a_ops = &befs_aops;

	if (S_ISREG(inode->i_mode)) {
		inode->i_fop = &generic_ro_fops;
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &befs_dir_inode_operations;
		inode->i_fop = &befs_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		if (befs_ino->i_flags & BEFS_LONG_SYMLINK)
			inode->i_op = &befs_symlink_inode_operations;
		else
			inode->i_op = &befs_fast_symlink_inode_operations;
	} else {
		befs_error(sb, "Inode %lu is not a regular file, "
			   "directory or symlink. THAT IS WRONG! BeFS has no "
			   "on disk special files", inode->i_ino);
		goto unacquire_bh;
	}

	brelse(bh);
	befs_debug(sb, "<--- %s", __func__);
	unlock_new_inode(inode);
	return inode;

      unacquire_bh:
	brelse(bh);

      unacquire_none:
	iget_failed(inode);
	befs_debug(sb, "<--- %s - Bad inode", __func__);
	return ERR_PTR(ret);
}

/* Initialize the inode cache. Called at fs setup.
 *
 * Taken from NFS implementation by Al Viro.
 */
static int __init
befs_init_inodecache(void)
{
	befs_inode_cachep = kmem_cache_create("befs_inode_cache",
					      sizeof (struct befs_inode_info),
					      0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					      init_once);
	if (befs_inode_cachep == NULL) {
		pr_err("%s: Couldn't initialize inode slabcache\n", __func__);
		return -ENOMEM;
	}
	return 0;
}

/* Called at fs teardown.
 *
 * Taken from NFS implementation by Al Viro.
 */
static void
befs_destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(befs_inode_cachep);
}

/*
 * The inode of symbolic link is different to data stream.
 * The data stream become link name. Unless the LONG_SYMLINK
 * flag is set.
 */
static void *
befs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct super_block *sb = dentry->d_sb;
	befs_inode_info *befs_ino = BEFS_I(dentry->d_inode);
	befs_data_stream *data = &befs_ino->i_data.ds;
	befs_off_t len = data->size;
	char *link;

	if (len == 0) {
		befs_error(sb, "Long symlink with illegal length");
		link = ERR_PTR(-EIO);
	} else {
		befs_debug(sb, "Follow long symlink");

		link = kmalloc(len, GFP_NOFS);
		if (!link) {
			link = ERR_PTR(-ENOMEM);
		} else if (befs_read_lsymlink(sb, data, link, len) != len) {
			kfree(link);
			befs_error(sb, "Failed to read entire long symlink");
			link = ERR_PTR(-EIO);
		} else {
			link[len - 1] = '\0';
		}
	}
	nd_set_link(nd, link);
	return NULL;
}


static void *
befs_fast_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	befs_inode_info *befs_ino = BEFS_I(dentry->d_inode);
	nd_set_link(nd, befs_ino->i_data.symlink);
	return NULL;
}

/*
 * UTF-8 to NLS charset  convert routine
 *
 *
 * Changed 8/10/01 by Will Dyson. Now use uni2char() / char2uni() rather than
 * the nls tables directly
 */

static int
befs_utf2nls(struct super_block *sb, const char *in,
	     int in_len, char **out, int *out_len)
{
	struct nls_table *nls = BEFS_SB(sb)->nls;
	int i, o;
	unicode_t uni;
	int unilen, utflen;
	char *result;
	/* The utf8->nls conversion won't make the final nls string bigger
	 * than the utf one, but if the string is pure ascii they'll have the
	 * same width and an extra char is needed to save the additional \0
	 */
	int maxlen = in_len + 1;

	befs_debug(sb, "---> %s", __func__);

	if (!nls) {
		befs_error(sb, "%s called with no NLS table loaded", __func__);
		return -EINVAL;
	}

	*out = result = kmalloc(maxlen, GFP_NOFS);
	if (!*out) {
		befs_error(sb, "%s cannot allocate memory", __func__);
		*out_len = 0;
		return -ENOMEM;
	}

	for (i = o = 0; i < in_len; i += utflen, o += unilen) {

		/* convert from UTF-8 to Unicode */
		utflen = utf8_to_utf32(&in[i], in_len - i, &uni);
		if (utflen < 0)
			goto conv_err;

		/* convert from Unicode to nls */
		if (uni > MAX_WCHAR_T)
			goto conv_err;
		unilen = nls->uni2char(uni, &result[o], in_len - o);
		if (unilen < 0)
			goto conv_err;
	}
	result[o] = '\0';
	*out_len = o;

	befs_debug(sb, "<--- %s", __func__);

	return o;

      conv_err:
	befs_error(sb, "Name using character set %s contains a character that "
		   "cannot be converted to unicode.", nls->charset);
	befs_debug(sb, "<--- %s", __func__);
	kfree(result);
	return -EILSEQ;
}

/**
 * befs_nls2utf - Convert NLS string to utf8 encodeing
 * @sb: Superblock
 * @in: Input string buffer in NLS format
 * @in_len: Length of input string in bytes
 * @out: The output string in UTF-8 format
 * @out_len: Length of the output buffer
 *
 * Converts input string @in, which is in the format of the loaded NLS map,
 * into a utf8 string.
 *
 * The destination string @out is allocated by this function and the caller is
 * responsible for freeing it with kfree()
 *
 * On return, *@out_len is the length of @out in bytes.
 *
 * On success, the return value is the number of utf8 characters written to
 * the output buffer @out.
 *
 * On Failure, a negative number coresponding to the error code is returned.
 */

static int
befs_nls2utf(struct super_block *sb, const char *in,
	     int in_len, char **out, int *out_len)
{
	struct nls_table *nls = BEFS_SB(sb)->nls;
	int i, o;
	wchar_t uni;
	int unilen, utflen;
	char *result;
	/* There're nls characters that will translate to 3-chars-wide UTF-8
	 * characters, a additional byte is needed to save the final \0
	 * in special cases */
	int maxlen = (3 * in_len) + 1;

	befs_debug(sb, "---> %s\n", __func__);

	if (!nls) {
		befs_error(sb, "%s called with no NLS table loaded.",
			   __func__);
		return -EINVAL;
	}

	*out = result = kmalloc(maxlen, GFP_NOFS);
	if (!*out) {
		befs_error(sb, "%s cannot allocate memory", __func__);
		*out_len = 0;
		return -ENOMEM;
	}

	for (i = o = 0; i < in_len; i += unilen, o += utflen) {

		/* convert from nls to unicode */
		unilen = nls->char2uni(&in[i], in_len - i, &uni);
		if (unilen < 0)
			goto conv_err;

		/* convert from unicode to UTF-8 */
		utflen = utf32_to_utf8(uni, &result[o], 3);
		if (utflen <= 0)
			goto conv_err;
	}

	result[o] = '\0';
	*out_len = o;

	befs_debug(sb, "<--- %s", __func__);

	return i;

      conv_err:
	befs_error(sb, "Name using charecter set %s contains a charecter that "
		   "cannot be converted to unicode.", nls->charset);
	befs_debug(sb, "<--- %s", __func__);
	kfree(result);
	return -EILSEQ;
}

/**
 * Use the
 *
 */
enum {
	Opt_uid, Opt_gid, Opt_charset, Opt_debug, Opt_err,
};

static const match_table_t befs_tokens = {
	{Opt_uid, "uid=%d"},
	{Opt_gid, "gid=%d"},
	{Opt_charset, "iocharset=%s"},
	{Opt_debug, "debug"},
	{Opt_err, NULL}
};

static int
parse_options(char *options, befs_mount_options * opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	kuid_t uid;
	kgid_t gid;

	/* Initialize options */
	opts->uid = GLOBAL_ROOT_UID;
	opts->gid = GLOBAL_ROOT_GID;
	opts->use_uid = 0;
	opts->use_gid = 0;
	opts->iocharset = NULL;
	opts->debug = 0;

	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, befs_tokens, args);
		switch (token) {
		case Opt_uid:
			if (match_int(&args[0], &option))
				return 0;
			uid = INVALID_UID;
			if (option >= 0)
				uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(uid)) {
				pr_err("Invalid uid %d, "
				       "using default\n", option);
				break;
			}
			opts->uid = uid;
			opts->use_uid = 1;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return 0;
			gid = INVALID_GID;
			if (option >= 0)
				gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(gid)) {
				pr_err("Invalid gid %d, "
				       "using default\n", option);
				break;
			}
			opts->gid = gid;
			opts->use_gid = 1;
			break;
		case Opt_charset:
			kfree(opts->iocharset);
			opts->iocharset = match_strdup(&args[0]);
			if (!opts->iocharset) {
				pr_err("allocation failure for "
				       "iocharset string\n");
				return 0;
			}
			break;
		case Opt_debug:
			opts->debug = 1;
			break;
		default:
			pr_err("Unrecognized mount option \"%s\" "
			       "or missing value\n", p);
			return 0;
		}
	}
	return 1;
}

/* This function has the responsibiltiy of getting the
 * filesystem ready for unmounting.
 * Basically, we free everything that we allocated in
 * befs_read_inode
 */
static void
befs_put_super(struct super_block *sb)
{
	kfree(BEFS_SB(sb)->mount_opts.iocharset);
	BEFS_SB(sb)->mount_opts.iocharset = NULL;
	unload_nls(BEFS_SB(sb)->nls);
	kfree(sb->s_fs_info);
	sb->s_fs_info = NULL;
}

/* Allocate private field of the superblock, fill it.
 *
 * Finish filling the public superblock fields
 * Make the root directory
 * Load a set of NLS translations if needed.
 */
static int
befs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct buffer_head *bh;
	befs_sb_info *befs_sb;
	befs_super_block *disk_sb;
	struct inode *root;
	long ret = -EINVAL;
	const unsigned long sb_block = 0;
	const off_t x86_sb_off = 512;

	save_mount_options(sb, data);

	sb->s_fs_info = kzalloc(sizeof(*befs_sb), GFP_KERNEL);
	if (sb->s_fs_info == NULL) {
		pr_err("(%s): Unable to allocate memory for private "
		       "portion of superblock. Bailing.\n", sb->s_id);
		goto unacquire_none;
	}
	befs_sb = BEFS_SB(sb);

	if (!parse_options((char *) data, &befs_sb->mount_opts)) {
		befs_error(sb, "cannot parse mount options");
		goto unacquire_priv_sbp;
	}

	befs_debug(sb, "---> %s", __func__);

	if (!(sb->s_flags & MS_RDONLY)) {
		befs_warning(sb,
			     "No write support. Marking filesystem read-only");
		sb->s_flags |= MS_RDONLY;
	}

	/*
	 * Set dummy blocksize to read super block.
	 * Will be set to real fs blocksize later.
	 *
	 * Linux 2.4.10 and later refuse to read blocks smaller than
	 * the hardsect size for the device. But we also need to read at
	 * least 1k to get the second 512 bytes of the volume.
	 * -WD 10-26-01
	 */
	sb_min_blocksize(sb, 1024);

	if (!(bh = sb_bread(sb, sb_block))) {
		befs_error(sb, "unable to read superblock");
		goto unacquire_priv_sbp;
	}

	/* account for offset of super block on x86 */
	disk_sb = (befs_super_block *) bh->b_data;
	if ((disk_sb->magic1 == BEFS_SUPER_MAGIC1_LE) ||
	    (disk_sb->magic1 == BEFS_SUPER_MAGIC1_BE)) {
		befs_debug(sb, "Using PPC superblock location");
	} else {
		befs_debug(sb, "Using x86 superblock location");
		disk_sb =
		    (befs_super_block *) ((void *) bh->b_data + x86_sb_off);
	}

	if ((befs_load_sb(sb, disk_sb) != BEFS_OK) ||
	    (befs_check_sb(sb) != BEFS_OK))
		goto unacquire_bh;

	befs_dump_super_block(sb, disk_sb);

	brelse(bh);

	if( befs_sb->num_blocks > ~((sector_t)0) ) {
		befs_error(sb, "blocks count: %llu "
			"is larger than the host can use",
			befs_sb->num_blocks);
		goto unacquire_priv_sbp;
	}

	/*
	 * set up enough so that it can read an inode
	 * Fill in kernel superblock fields from private sb
	 */
	sb->s_magic = BEFS_SUPER_MAGIC;
	/* Set real blocksize of fs */
	sb_set_blocksize(sb, (ulong) befs_sb->block_size);
	sb->s_op = &befs_sops;
	root = befs_iget(sb, iaddr2blockno(sb, &(befs_sb->root_dir)));
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto unacquire_priv_sbp;
	}
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		befs_error(sb, "get root inode failed");
		goto unacquire_priv_sbp;
	}

	/* load nls library */
	if (befs_sb->mount_opts.iocharset) {
		befs_debug(sb, "Loading nls: %s",
			   befs_sb->mount_opts.iocharset);
		befs_sb->nls = load_nls(befs_sb->mount_opts.iocharset);
		if (!befs_sb->nls) {
			befs_warning(sb, "Cannot load nls %s"
					" loading default nls",
					befs_sb->mount_opts.iocharset);
			befs_sb->nls = load_nls_default();
		}
	/* load default nls if none is specified  in mount options */
	} else {
		befs_debug(sb, "Loading default nls");
		befs_sb->nls = load_nls_default();
	}

	return 0;
/*****************/
      unacquire_bh:
	brelse(bh);

      unacquire_priv_sbp:
	kfree(befs_sb->mount_opts.iocharset);
	kfree(sb->s_fs_info);

      unacquire_none:
	sb->s_fs_info = NULL;
	return ret;
}

static int
befs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	if (!(*flags & MS_RDONLY))
		return -EINVAL;
	return 0;
}

static int
befs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	befs_debug(sb, "---> %s", __func__);

	buf->f_type = BEFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = BEFS_SB(sb)->num_blocks;
	buf->f_bfree = BEFS_SB(sb)->num_blocks - BEFS_SB(sb)->used_blocks;
	buf->f_bavail = buf->f_bfree;
	buf->f_files = 0;	/* UNKNOWN */
	buf->f_ffree = 0;	/* UNKNOWN */
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = BEFS_NAME_LEN;

	befs_debug(sb, "<--- %s", __func__);

	return 0;
}

static struct dentry *
befs_mount(struct file_system_type *fs_type, int flags, const char *dev_name,
	    void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, befs_fill_super);
}

static struct file_system_type befs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "befs",
	.mount		= befs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("befs");

static int __init
init_befs_fs(void)
{
	int err;

	pr_info("version: %s\n", BEFS_VERSION);

	err = befs_init_inodecache();
	if (err)
		goto unacquire_none;

	err = register_filesystem(&befs_fs_type);
	if (err)
		goto unacquire_inodecache;

	return 0;

unacquire_inodecache:
	befs_destroy_inodecache();

unacquire_none:
	return err;
}

static void __exit
exit_befs_fs(void)
{
	befs_destroy_inodecache();

	unregister_filesystem(&befs_fs_type);
}

/*
Macros that typecheck the init and exit functions,
ensures that they are called at init and cleanup,
and eliminates warnings about unused functions.
*/
module_init(init_befs_fs)
module_exit(exit_befs_fs)
/************************************************************/
/* ../linux-3.17/fs/befs/linuxvfs.c */
/************************************************************/
