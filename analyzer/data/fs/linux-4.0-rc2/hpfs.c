/*
 *  linux/fs/hpfs/alloc.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  HPFS bitmap operations
 */

#include "hpfs_fn.h"
#include "../../inc/__fss.h"

static void hpfs_claim_alloc(struct super_block *s, secno sec)
{
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	if (sbi->sb_n_free != (unsigned)-1) {
		if (unlikely(!sbi->sb_n_free)) {
			hpfs_error(s, "free count underflow, allocating sector %08x", sec);
			sbi->sb_n_free = -1;
			return;
		}
		sbi->sb_n_free--;
	}
}

static void hpfs_claim_free(struct super_block *s, secno sec)
{
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	if (sbi->sb_n_free != (unsigned)-1) {
		if (unlikely(sbi->sb_n_free >= sbi->sb_fs_size)) {
			hpfs_error(s, "free count overflow, freeing sector %08x", sec);
			sbi->sb_n_free = -1;
			return;
		}
		sbi->sb_n_free++;
	}
}

static void hpfs_claim_dirband_alloc(struct super_block *s, secno sec)
{
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	if (sbi->sb_n_free_dnodes != (unsigned)-1) {
		if (unlikely(!sbi->sb_n_free_dnodes)) {
			hpfs_error(s, "dirband free count underflow, allocating sector %08x", sec);
			sbi->sb_n_free_dnodes = -1;
			return;
		}
		sbi->sb_n_free_dnodes--;
	}
}

static void hpfs_claim_dirband_free(struct super_block *s, secno sec)
{
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	if (sbi->sb_n_free_dnodes != (unsigned)-1) {
		if (unlikely(sbi->sb_n_free_dnodes >= sbi->sb_dirband_size / 4)) {
			hpfs_error(s, "dirband free count overflow, freeing sector %08x", sec);
			sbi->sb_n_free_dnodes = -1;
			return;
		}
		sbi->sb_n_free_dnodes++;
	}
}

/*
 * Check if a sector is allocated in bitmap
 * This is really slow. Turned on only if chk==2
 */

static int chk_if_allocated(struct super_block *s, secno sec, char *msg)
{
	struct quad_buffer_head qbh;
	__le32 *bmp;
	if (!(bmp = hpfs_map_bitmap(s, sec >> 14, &qbh, "chk"))) goto fail;
	if ((le32_to_cpu(bmp[(sec & 0x3fff) >> 5]) >> (sec & 0x1f)) & 1) {
		hpfs_error(s, "sector '%s' - %08x not allocated in bitmap", msg, sec);
		goto fail1;
	}
	hpfs_brelse4(&qbh);
	if (sec >= hpfs_sb(s)->sb_dirband_start && sec < hpfs_sb(s)->sb_dirband_start + hpfs_sb(s)->sb_dirband_size) {
		unsigned ssec = (sec - hpfs_sb(s)->sb_dirband_start) / 4;
		if (!(bmp = hpfs_map_dnode_bitmap(s, &qbh))) goto fail;
		if ((le32_to_cpu(bmp[ssec >> 5]) >> (ssec & 0x1f)) & 1) {
			hpfs_error(s, "sector '%s' - %08x not allocated in directory bitmap", msg, sec);
			goto fail1;
		}
		hpfs_brelse4(&qbh);
	}
	return 0;
	fail1:
	hpfs_brelse4(&qbh);
	fail:
	return 1;
}

/*
 * Check if sector(s) have proper number and additionally check if they're
 * allocated in bitmap.
 */
	
int hpfs_chk_sectors(struct super_block *s, secno start, int len, char *msg)
{
	if (start + len < start || start < 0x12 ||
	    start + len > hpfs_sb(s)->sb_fs_size) {
	    	hpfs_error(s, "sector(s) '%s' badly placed at %08x", msg, start);
		return 1;
	}
	if (hpfs_sb(s)->sb_chk>=2) {
		int i;
		for (i = 0; i < len; i++)
			if (chk_if_allocated(s, start + i, msg)) return 1;
	}
	return 0;
}

static secno alloc_in_bmp(struct super_block *s, secno near, unsigned n, unsigned forward)
{
	struct quad_buffer_head qbh;
	__le32 *bmp;
	unsigned bs = near & ~0x3fff;
	unsigned nr = (near & 0x3fff) & ~(n - 1);
	/*unsigned mnr;*/
	unsigned i, q;
	int a, b;
	secno ret = 0;
	if (n != 1 && n != 4) {
		hpfs_error(s, "Bad allocation size: %d", n);
		return 0;
	}
	if (bs != ~0x3fff) {
		if (!(bmp = hpfs_map_bitmap(s, near >> 14, &qbh, "aib"))) goto uls;
	} else {
		if (!(bmp = hpfs_map_dnode_bitmap(s, &qbh))) goto uls;
	}
	if (!tstbits(bmp, nr, n + forward)) {
		ret = bs + nr;
		goto rt;
	}
	q = nr + n; b = 0;
	while ((a = tstbits(bmp, q, n + forward)) != 0) {
		q += a;
		if (n != 1) q = ((q-1)&~(n-1))+n;
		if (!b) {
			if (q>>5 != nr>>5) {
				b = 1;
				q = nr & 0x1f;
			}
		} else if (q > nr) break;
	}
	if (!a) {
		ret = bs + q;
		goto rt;
	}
	nr >>= 5;
	/*for (i = nr + 1; i != nr; i++, i &= 0x1ff) */
	i = nr;
	do {
		if (!le32_to_cpu(bmp[i])) goto cont;
		if (n + forward >= 0x3f && le32_to_cpu(bmp[i]) != 0xffffffff) goto cont;
		q = i<<5;
		if (i > 0) {
			unsigned k = le32_to_cpu(bmp[i-1]);
			while (k & 0x80000000) {
				q--; k <<= 1;
			}
		}
		if (n != 1) q = ((q-1)&~(n-1))+n;
		while ((a = tstbits(bmp, q, n + forward)) != 0) {
			q += a;
			if (n != 1) q = ((q-1)&~(n-1))+n;
			if (q>>5 > i) break;
		}
		if (!a) {
			ret = bs + q;
			goto rt;
		}
		cont:
		i++, i &= 0x1ff;
	} while (i != nr);
	rt:
	if (ret) {
		if (hpfs_sb(s)->sb_chk && ((ret >> 14) != (bs >> 14) || (le32_to_cpu(bmp[(ret & 0x3fff) >> 5]) | ~(((1 << n) - 1) << (ret & 0x1f))) != 0xffffffff)) {
			hpfs_error(s, "Allocation doesn't work! Wanted %d, allocated at %08x", n, ret);
			ret = 0;
			goto b;
		}
		bmp[(ret & 0x3fff) >> 5] &= cpu_to_le32(~(((1 << n) - 1) << (ret & 0x1f)));
		hpfs_mark_4buffers_dirty(&qbh);
	}
	b:
	hpfs_brelse4(&qbh);
	uls:
	return ret;
}

/*
 * Allocation strategy:	1) search place near the sector specified
 *			2) search bitmap where free sectors last found
 *			3) search all bitmaps
 *			4) search all bitmaps ignoring number of pre-allocated
 *				sectors
 */

secno hpfs_alloc_sector(struct super_block *s, secno near, unsigned n, int forward)
{
	secno sec;
	int i;
	unsigned n_bmps;
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	int f_p = 0;
	int near_bmp;
	if (forward < 0) {
		forward = -forward;
		f_p = 1;
	}
	n_bmps = (sbi->sb_fs_size + 0x4000 - 1) >> 14;
	if (near && near < sbi->sb_fs_size) {
		if ((sec = alloc_in_bmp(s, near, n, f_p ? forward : forward/4))) goto ret;
		near_bmp = near >> 14;
	} else near_bmp = n_bmps / 2;
	/*
	if (b != -1) {
		if ((sec = alloc_in_bmp(s, b<<14, n, f_p ? forward : forward/2))) {
			b &= 0x0fffffff;
			goto ret;
		}
		if (b > 0x10000000) if ((sec = alloc_in_bmp(s, (b&0xfffffff)<<14, n, f_p ? forward : 0))) goto ret;
	*/
	if (!f_p) if (forward > sbi->sb_max_fwd_alloc) forward = sbi->sb_max_fwd_alloc;
	less_fwd:
	for (i = 0; i < n_bmps; i++) {
		if (near_bmp+i < n_bmps && ((sec = alloc_in_bmp(s, (near_bmp+i) << 14, n, forward)))) {
			sbi->sb_c_bitmap = near_bmp+i;
			goto ret;
		}	
		if (!forward) {
			if (near_bmp-i-1 >= 0 && ((sec = alloc_in_bmp(s, (near_bmp-i-1) << 14, n, forward)))) {
				sbi->sb_c_bitmap = near_bmp-i-1;
				goto ret;
			}
		} else {
			if (near_bmp+i >= n_bmps && ((sec = alloc_in_bmp(s, (near_bmp+i-n_bmps) << 14, n, forward)))) {
				sbi->sb_c_bitmap = near_bmp+i-n_bmps;
				goto ret;
			}
		}
		if (i == 1 && sbi->sb_c_bitmap != -1 && ((sec = alloc_in_bmp(s, (sbi->sb_c_bitmap) << 14, n, forward)))) {
			goto ret;
		}
	}
	if (!f_p) {
		if (forward) {
			sbi->sb_max_fwd_alloc = forward * 3 / 4;
			forward /= 2;
			goto less_fwd;
		}
	}
	sec = 0;
	ret:
	if (sec) {
		i = 0;
		do
			hpfs_claim_alloc(s, sec + i);
		while (unlikely(++i < n));
	}
	if (sec && f_p) {
		for (i = 0; i < forward; i++) {
			if (!hpfs_alloc_if_possible(s, sec + n + i)) {
				hpfs_error(s, "Prealloc doesn't work! Wanted %d, allocated at %08x, can't allocate %d", forward, sec, i);
				sec = 0;
				break;
			}
		}
	}
	return sec;
}

static secno alloc_in_dirband(struct super_block *s, secno near)
{
	unsigned nr = near;
	secno sec;
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	if (nr < sbi->sb_dirband_start)
		nr = sbi->sb_dirband_start;
	if (nr >= sbi->sb_dirband_start + sbi->sb_dirband_size)
		nr = sbi->sb_dirband_start + sbi->sb_dirband_size - 4;
	nr -= sbi->sb_dirband_start;
	nr >>= 2;
	sec = alloc_in_bmp(s, (~0x3fff) | nr, 1, 0);
	if (!sec) return 0;
	hpfs_claim_dirband_alloc(s, sec);
	return ((sec & 0x3fff) << 2) + sbi->sb_dirband_start;
}

/* Alloc sector if it's free */

int hpfs_alloc_if_possible(struct super_block *s, secno sec)
{
	struct quad_buffer_head qbh;
	__le32 *bmp;
	if (!(bmp = hpfs_map_bitmap(s, sec >> 14, &qbh, "aip"))) goto end;
	if (le32_to_cpu(bmp[(sec & 0x3fff) >> 5]) & (1 << (sec & 0x1f))) {
		bmp[(sec & 0x3fff) >> 5] &= cpu_to_le32(~(1 << (sec & 0x1f)));
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
		hpfs_claim_alloc(s, sec);
		return 1;
	}
	hpfs_brelse4(&qbh);
	end:
	return 0;
}

/* Free sectors in bitmaps */

void hpfs_free_sectors(struct super_block *s, secno sec, unsigned n)
{
	struct quad_buffer_head qbh;
	__le32 *bmp;
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	/*pr_info("2 - ");*/
	if (!n) return;
	if (sec < 0x12) {
		hpfs_error(s, "Trying to free reserved sector %08x", sec);
		return;
	}
	sbi->sb_max_fwd_alloc += n > 0xffff ? 0xffff : n;
	if (sbi->sb_max_fwd_alloc > 0xffffff) sbi->sb_max_fwd_alloc = 0xffffff;
	new_map:
	if (!(bmp = hpfs_map_bitmap(s, sec >> 14, &qbh, "free"))) {
		return;
	}	
	new_tst:
	if ((le32_to_cpu(bmp[(sec & 0x3fff) >> 5]) >> (sec & 0x1f) & 1)) {
		hpfs_error(s, "sector %08x not allocated", sec);
		hpfs_brelse4(&qbh);
		return;
	}
	bmp[(sec & 0x3fff) >> 5] |= cpu_to_le32(1 << (sec & 0x1f));
	hpfs_claim_free(s, sec);
	if (!--n) {
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
		return;
	}	
	if (!(++sec & 0x3fff)) {
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
		goto new_map;
	}
	goto new_tst;
}

/*
 * Check if there are at least n free dnodes on the filesystem.
 * Called before adding to dnode. If we run out of space while
 * splitting dnodes, it would corrupt dnode tree.
 */

int hpfs_check_free_dnodes(struct super_block *s, int n)
{
	int n_bmps = (hpfs_sb(s)->sb_fs_size + 0x4000 - 1) >> 14;
	int b = hpfs_sb(s)->sb_c_bitmap & 0x0fffffff;
	int i, j;
	__le32 *bmp;
	struct quad_buffer_head qbh;
	if ((bmp = hpfs_map_dnode_bitmap(s, &qbh))) {
		for (j = 0; j < 512; j++) {
			unsigned k;
			if (!le32_to_cpu(bmp[j])) continue;
			for (k = le32_to_cpu(bmp[j]); k; k >>= 1) if (k & 1) if (!--n) {
				hpfs_brelse4(&qbh);
				return 0;
			}
		}
	}
	hpfs_brelse4(&qbh);
	i = 0;
	if (hpfs_sb(s)->sb_c_bitmap != -1) {
		bmp = hpfs_map_bitmap(s, b, &qbh, "chkdn1");
		goto chk_bmp;
	}
	chk_next:
	if (i == b) i++;
	if (i >= n_bmps) return 1;
	bmp = hpfs_map_bitmap(s, i, &qbh, "chkdn2");
	chk_bmp:
	if (bmp) {
		for (j = 0; j < 512; j++) {
			u32 k;
			if (!le32_to_cpu(bmp[j])) continue;
			for (k = 0xf; k; k <<= 4)
				if ((le32_to_cpu(bmp[j]) & k) == k) {
					if (!--n) {
						hpfs_brelse4(&qbh);
						return 0;
					}
				}
		}
		hpfs_brelse4(&qbh);
	}
	i++;
	goto chk_next;
}

void hpfs_free_dnode(struct super_block *s, dnode_secno dno)
{
	if (hpfs_sb(s)->sb_chk) if (dno & 3) {
		hpfs_error(s, "hpfs_free_dnode: dnode %08x not aligned", dno);
		return;
	}
	if (dno < hpfs_sb(s)->sb_dirband_start ||
	    dno >= hpfs_sb(s)->sb_dirband_start + hpfs_sb(s)->sb_dirband_size) {
		hpfs_free_sectors(s, dno, 4);
	} else {
		struct quad_buffer_head qbh;
		__le32 *bmp;
		unsigned ssec = (dno - hpfs_sb(s)->sb_dirband_start) / 4;
		if (!(bmp = hpfs_map_dnode_bitmap(s, &qbh))) {
			return;
		}
		bmp[ssec >> 5] |= cpu_to_le32(1 << (ssec & 0x1f));
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
		hpfs_claim_dirband_free(s, dno);
	}
}

struct dnode *hpfs_alloc_dnode(struct super_block *s, secno near,
			 dnode_secno *dno, struct quad_buffer_head *qbh)
{
	struct dnode *d;
	if (hpfs_get_free_dnodes(s) > FREE_DNODES_ADD) {
		if (!(*dno = alloc_in_dirband(s, near)))
			if (!(*dno = hpfs_alloc_sector(s, near, 4, 0))) return NULL;
	} else {
		if (!(*dno = hpfs_alloc_sector(s, near, 4, 0)))
			if (!(*dno = alloc_in_dirband(s, near))) return NULL;
	}
	if (!(d = hpfs_get_4sectors(s, *dno, qbh))) {
		hpfs_free_dnode(s, *dno);
		return NULL;
	}
	memset(d, 0, 2048);
	d->magic = cpu_to_le32(DNODE_MAGIC);
	d->first_free = cpu_to_le32(52);
	d->dirent[0] = 32;
	d->dirent[2] = 8;
	d->dirent[30] = 1;
	d->dirent[31] = 255;
	d->self = cpu_to_le32(*dno);
	return d;
}

struct fnode *hpfs_alloc_fnode(struct super_block *s, secno near, fnode_secno *fno,
			  struct buffer_head **bh)
{
	struct fnode *f;
	if (!(*fno = hpfs_alloc_sector(s, near, 1, FNODE_ALLOC_FWD))) return NULL;
	if (!(f = hpfs_get_sector(s, *fno, bh))) {
		hpfs_free_sectors(s, *fno, 1);
		return NULL;
	}	
	memset(f, 0, 512);
	f->magic = cpu_to_le32(FNODE_MAGIC);
	f->ea_offs = cpu_to_le16(0xc4);
	f->btree.n_free_nodes = 8;
	f->btree.first_free = cpu_to_le16(8);
	return f;
}

struct anode *hpfs_alloc_anode(struct super_block *s, secno near, anode_secno *ano,
			  struct buffer_head **bh)
{
	struct anode *a;
	if (!(*ano = hpfs_alloc_sector(s, near, 1, ANODE_ALLOC_FWD))) return NULL;
	if (!(a = hpfs_get_sector(s, *ano, bh))) {
		hpfs_free_sectors(s, *ano, 1);
		return NULL;
	}
	memset(a, 0, 512);
	a->magic = cpu_to_le32(ANODE_MAGIC);
	a->self = cpu_to_le32(*ano);
	a->btree.n_free_nodes = 40;
	a->btree.n_used_nodes = 0;
	a->btree.first_free = cpu_to_le16(8);
	return a;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/alloc.c */
/************************************************************/
/*
 *  linux/fs/hpfs/anode.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  handling HPFS anode tree that contains file allocation info
 */

// #include "hpfs_fn.h"

/* Find a sector in allocation tree */

secno hpfs_bplus_lookup(struct super_block *s, struct inode *inode,
		   struct bplus_header *btree, unsigned sec,
		   struct buffer_head *bh)
{
	anode_secno a = -1;
	struct anode *anode;
	int i;
	int c1, c2 = 0;
	go_down:
	if (hpfs_sb(s)->sb_chk) if (hpfs_stop_cycles(s, a, &c1, &c2, "hpfs_bplus_lookup")) return -1;
	if (bp_internal(btree)) {
		for (i = 0; i < btree->n_used_nodes; i++)
			if (le32_to_cpu(btree->u.internal[i].file_secno) > sec) {
				a = le32_to_cpu(btree->u.internal[i].down);
				brelse(bh);
				if (!(anode = hpfs_map_anode(s, a, &bh))) return -1;
				btree = &anode->btree;
				goto go_down;
			}
		hpfs_error(s, "sector %08x not found in internal anode %08x", sec, a);
		brelse(bh);
		return -1;
	}
	for (i = 0; i < btree->n_used_nodes; i++)
		if (le32_to_cpu(btree->u.external[i].file_secno) <= sec &&
		    le32_to_cpu(btree->u.external[i].file_secno) + le32_to_cpu(btree->u.external[i].length) > sec) {
			a = le32_to_cpu(btree->u.external[i].disk_secno) + sec - le32_to_cpu(btree->u.external[i].file_secno);
			if (hpfs_sb(s)->sb_chk) if (hpfs_chk_sectors(s, a, 1, "data")) {
				brelse(bh);
				return -1;
			}
			if (inode) {
				struct hpfs_inode_info *hpfs_inode = hpfs_i(inode);
				hpfs_inode->i_file_sec = le32_to_cpu(btree->u.external[i].file_secno);
				hpfs_inode->i_disk_sec = le32_to_cpu(btree->u.external[i].disk_secno);
				hpfs_inode->i_n_secs = le32_to_cpu(btree->u.external[i].length);
			}
			brelse(bh);
			return a;
		}
	hpfs_error(s, "sector %08x not found in external anode %08x", sec, a);
	brelse(bh);
	return -1;
}

/* Add a sector to tree */

secno hpfs_add_sector_to_btree(struct super_block *s, secno node, int fnod, unsigned fsecno)
{
	struct bplus_header *btree;
	struct anode *anode = NULL, *ranode = NULL;
	struct fnode *fnode;
	anode_secno a, na = -1, ra, up = -1;
	secno se;
	struct buffer_head *bh, *bh1, *bh2;
	int n;
	unsigned fs;
	int c1, c2 = 0;
	if (fnod) {
		if (!(fnode = hpfs_map_fnode(s, node, &bh))) return -1;
		btree = &fnode->btree;
	} else {
		if (!(anode = hpfs_map_anode(s, node, &bh))) return -1;
		btree = &anode->btree;
	}
	a = node;
	go_down:
	if ((n = btree->n_used_nodes - 1) < -!!fnod) {
		hpfs_error(s, "anode %08x has no entries", a);
		brelse(bh);
		return -1;
	}
	if (bp_internal(btree)) {
		a = le32_to_cpu(btree->u.internal[n].down);
		btree->u.internal[n].file_secno = cpu_to_le32(-1);
		mark_buffer_dirty(bh);
		brelse(bh);
		if (hpfs_sb(s)->sb_chk)
			if (hpfs_stop_cycles(s, a, &c1, &c2, "hpfs_add_sector_to_btree #1")) return -1;
		if (!(anode = hpfs_map_anode(s, a, &bh))) return -1;
		btree = &anode->btree;
		goto go_down;
	}
	if (n >= 0) {
		if (le32_to_cpu(btree->u.external[n].file_secno) + le32_to_cpu(btree->u.external[n].length) != fsecno) {
			hpfs_error(s, "allocated size %08x, trying to add sector %08x, %cnode %08x",
				le32_to_cpu(btree->u.external[n].file_secno) + le32_to_cpu(btree->u.external[n].length), fsecno,
				fnod?'f':'a', node);
			brelse(bh);
			return -1;
		}
		if (hpfs_alloc_if_possible(s, se = le32_to_cpu(btree->u.external[n].disk_secno) + le32_to_cpu(btree->u.external[n].length))) {
			le32_add_cpu(&btree->u.external[n].length, 1);
			mark_buffer_dirty(bh);
			brelse(bh);
			return se;
		}
	} else {
		if (fsecno) {
			hpfs_error(s, "empty file %08x, trying to add sector %08x", node, fsecno);
			brelse(bh);
			return -1;
		}
		se = !fnod ? node : (node + 16384) & ~16383;
	}	
	if (!(se = hpfs_alloc_sector(s, se, 1, fsecno*ALLOC_M>ALLOC_FWD_MAX ? ALLOC_FWD_MAX : fsecno*ALLOC_M<ALLOC_FWD_MIN ? ALLOC_FWD_MIN : fsecno*ALLOC_M))) {
		brelse(bh);
		return -1;
	}
	fs = n < 0 ? 0 : le32_to_cpu(btree->u.external[n].file_secno) + le32_to_cpu(btree->u.external[n].length);
	if (!btree->n_free_nodes) {
		up = a != node ? le32_to_cpu(anode->up) : -1;
		if (!(anode = hpfs_alloc_anode(s, a, &na, &bh1))) {
			brelse(bh);
			hpfs_free_sectors(s, se, 1);
			return -1;
		}
		if (a == node && fnod) {
			anode->up = cpu_to_le32(node);
			anode->btree.flags |= BP_fnode_parent;
			anode->btree.n_used_nodes = btree->n_used_nodes;
			anode->btree.first_free = btree->first_free;
			anode->btree.n_free_nodes = 40 - anode->btree.n_used_nodes;
			memcpy(&anode->u, &btree->u, btree->n_used_nodes * 12);
			btree->flags |= BP_internal;
			btree->n_free_nodes = 11;
			btree->n_used_nodes = 1;
			btree->first_free = cpu_to_le16((char *)&(btree->u.internal[1]) - (char *)btree);
			btree->u.internal[0].file_secno = cpu_to_le32(-1);
			btree->u.internal[0].down = cpu_to_le32(na);
			mark_buffer_dirty(bh);
		} else if (!(ranode = hpfs_alloc_anode(s, /*a*/0, &ra, &bh2))) {
			brelse(bh);
			brelse(bh1);
			hpfs_free_sectors(s, se, 1);
			hpfs_free_sectors(s, na, 1);
			return -1;
		}
		brelse(bh);
		bh = bh1;
		btree = &anode->btree;
	}
	btree->n_free_nodes--; n = btree->n_used_nodes++;
	le16_add_cpu(&btree->first_free, 12);
	btree->u.external[n].disk_secno = cpu_to_le32(se);
	btree->u.external[n].file_secno = cpu_to_le32(fs);
	btree->u.external[n].length = cpu_to_le32(1);
	mark_buffer_dirty(bh);
	brelse(bh);
	if ((a == node && fnod) || na == -1) return se;
	c2 = 0;
	while (up != (anode_secno)-1) {
		struct anode *new_anode;
		if (hpfs_sb(s)->sb_chk)
			if (hpfs_stop_cycles(s, up, &c1, &c2, "hpfs_add_sector_to_btree #2")) return -1;
		if (up != node || !fnod) {
			if (!(anode = hpfs_map_anode(s, up, &bh))) return -1;
			btree = &anode->btree;
		} else {
			if (!(fnode = hpfs_map_fnode(s, up, &bh))) return -1;
			btree = &fnode->btree;
		}
		if (btree->n_free_nodes) {
			btree->n_free_nodes--; n = btree->n_used_nodes++;
			le16_add_cpu(&btree->first_free, 8);
			btree->u.internal[n].file_secno = cpu_to_le32(-1);
			btree->u.internal[n].down = cpu_to_le32(na);
			btree->u.internal[n-1].file_secno = cpu_to_le32(fs);
			mark_buffer_dirty(bh);
			brelse(bh);
			brelse(bh2);
			hpfs_free_sectors(s, ra, 1);
			if ((anode = hpfs_map_anode(s, na, &bh))) {
				anode->up = cpu_to_le32(up);
				if (up == node && fnod)
					anode->btree.flags |= BP_fnode_parent;
				else
					anode->btree.flags &= ~BP_fnode_parent;
				mark_buffer_dirty(bh);
				brelse(bh);
			}
			return se;
		}
		up = up != node ? le32_to_cpu(anode->up) : -1;
		btree->u.internal[btree->n_used_nodes - 1].file_secno = cpu_to_le32(/*fs*/-1);
		mark_buffer_dirty(bh);
		brelse(bh);
		a = na;
		if ((new_anode = hpfs_alloc_anode(s, a, &na, &bh))) {
			anode = new_anode;
			/*anode->up = cpu_to_le32(up != -1 ? up : ra);*/
			anode->btree.flags |= BP_internal;
			anode->btree.n_used_nodes = 1;
			anode->btree.n_free_nodes = 59;
			anode->btree.first_free = cpu_to_le16(16);
			anode->btree.u.internal[0].down = cpu_to_le32(a);
			anode->btree.u.internal[0].file_secno = cpu_to_le32(-1);
			mark_buffer_dirty(bh);
			brelse(bh);
			if ((anode = hpfs_map_anode(s, a, &bh))) {
				anode->up = cpu_to_le32(na);
				mark_buffer_dirty(bh);
				brelse(bh);
			}
		} else na = a;
	}
	if ((anode = hpfs_map_anode(s, na, &bh))) {
		anode->up = cpu_to_le32(node);
		if (fnod)
			anode->btree.flags |= BP_fnode_parent;
		mark_buffer_dirty(bh);
		brelse(bh);
	}
	if (!fnod) {
		if (!(anode = hpfs_map_anode(s, node, &bh))) {
			brelse(bh2);
			return -1;
		}
		btree = &anode->btree;
	} else {
		if (!(fnode = hpfs_map_fnode(s, node, &bh))) {
			brelse(bh2);
			return -1;
		}
		btree = &fnode->btree;
	}
	ranode->up = cpu_to_le32(node);
	memcpy(&ranode->btree, btree, le16_to_cpu(btree->first_free));
	if (fnod)
		ranode->btree.flags |= BP_fnode_parent;
	ranode->btree.n_free_nodes = (bp_internal(&ranode->btree) ? 60 : 40) - ranode->btree.n_used_nodes;
	if (bp_internal(&ranode->btree)) for (n = 0; n < ranode->btree.n_used_nodes; n++) {
		struct anode *unode;
		if ((unode = hpfs_map_anode(s, le32_to_cpu(ranode->u.internal[n].down), &bh1))) {
			unode->up = cpu_to_le32(ra);
			unode->btree.flags &= ~BP_fnode_parent;
			mark_buffer_dirty(bh1);
			brelse(bh1);
		}
	}
	btree->flags |= BP_internal;
	btree->n_free_nodes = fnod ? 10 : 58;
	btree->n_used_nodes = 2;
	btree->first_free = cpu_to_le16((char *)&btree->u.internal[2] - (char *)btree);
	btree->u.internal[0].file_secno = cpu_to_le32(fs);
	btree->u.internal[0].down = cpu_to_le32(ra);
	btree->u.internal[1].file_secno = cpu_to_le32(-1);
	btree->u.internal[1].down = cpu_to_le32(na);
	mark_buffer_dirty(bh);
	brelse(bh);
	mark_buffer_dirty(bh2);
	brelse(bh2);
	return se;
}

/*
 * Remove allocation tree. Recursion would look much nicer but
 * I want to avoid it because it can cause stack overflow.
 */

void hpfs_remove_btree(struct super_block *s, struct bplus_header *btree)
{
	struct bplus_header *btree1 = btree;
	struct anode *anode = NULL;
	anode_secno ano = 0, oano;
	struct buffer_head *bh;
	int level = 0;
	int pos = 0;
	int i;
	int c1, c2 = 0;
	int d1, d2;
	go_down:
	d2 = 0;
	while (bp_internal(btree1)) {
		ano = le32_to_cpu(btree1->u.internal[pos].down);
		if (level) brelse(bh);
		if (hpfs_sb(s)->sb_chk)
			if (hpfs_stop_cycles(s, ano, &d1, &d2, "hpfs_remove_btree #1"))
				return;
		if (!(anode = hpfs_map_anode(s, ano, &bh))) return;
		btree1 = &anode->btree;
		level++;
		pos = 0;
	}
	for (i = 0; i < btree1->n_used_nodes; i++)
		hpfs_free_sectors(s, le32_to_cpu(btree1->u.external[i].disk_secno), le32_to_cpu(btree1->u.external[i].length));
	go_up:
	if (!level) return;
	brelse(bh);
	if (hpfs_sb(s)->sb_chk)
		if (hpfs_stop_cycles(s, ano, &c1, &c2, "hpfs_remove_btree #2")) return;
	hpfs_free_sectors(s, ano, 1);
	oano = ano;
	ano = le32_to_cpu(anode->up);
	if (--level) {
		if (!(anode = hpfs_map_anode(s, ano, &bh))) return;
		btree1 = &anode->btree;
	} else btree1 = btree;
	for (i = 0; i < btree1->n_used_nodes; i++) {
		if (le32_to_cpu(btree1->u.internal[i].down) == oano) {
			if ((pos = i + 1) < btree1->n_used_nodes)
				goto go_down;
			else
				goto go_up;
		}
	}
	hpfs_error(s,
		   "reference to anode %08x not found in anode %08x "
		   "(probably bad up pointer)",
		   oano, level ? ano : -1);
	if (level)
		brelse(bh);
}

/* Just a wrapper around hpfs_bplus_lookup .. used for reading eas */

static secno anode_lookup(struct super_block *s, anode_secno a, unsigned sec)
{
	struct anode *anode;
	struct buffer_head *bh;
	if (!(anode = hpfs_map_anode(s, a, &bh))) return -1;
	return hpfs_bplus_lookup(s, NULL, &anode->btree, sec, bh);
}

int hpfs_ea_read(struct super_block *s, secno a, int ano, unsigned pos,
	    unsigned len, char *buf)
{
	struct buffer_head *bh;
	char *data;
	secno sec;
	unsigned l;
	while (len) {
		if (ano) {
			if ((sec = anode_lookup(s, a, pos >> 9)) == -1)
				return -1;
		} else sec = a + (pos >> 9);
		if (hpfs_sb(s)->sb_chk) if (hpfs_chk_sectors(s, sec, 1, "ea #1")) return -1;
		if (!(data = hpfs_map_sector(s, sec, &bh, (len - 1) >> 9)))
			return -1;
		l = 0x200 - (pos & 0x1ff); if (l > len) l = len;
		memcpy(buf, data + (pos & 0x1ff), l);
		brelse(bh);
		buf += l; pos += l; len -= l;
	}
	return 0;
}

int hpfs_ea_write(struct super_block *s, secno a, int ano, unsigned pos,
	     unsigned len, const char *buf)
{
	struct buffer_head *bh;
	char *data;
	secno sec;
	unsigned l;
	while (len) {
		if (ano) {
			if ((sec = anode_lookup(s, a, pos >> 9)) == -1)
				return -1;
		} else sec = a + (pos >> 9);
		if (hpfs_sb(s)->sb_chk) if (hpfs_chk_sectors(s, sec, 1, "ea #2")) return -1;
		if (!(data = hpfs_map_sector(s, sec, &bh, (len - 1) >> 9)))
			return -1;
		l = 0x200 - (pos & 0x1ff); if (l > len) l = len;
		memcpy(data + (pos & 0x1ff), buf, l);
		mark_buffer_dirty(bh);
		brelse(bh);
		buf += l; pos += l; len -= l;
	}
	return 0;
}

void hpfs_ea_remove(struct super_block *s, secno a, int ano, unsigned len)
{
	struct anode *anode;
	struct buffer_head *bh;
	if (ano) {
		if (!(anode = hpfs_map_anode(s, a, &bh))) return;
		hpfs_remove_btree(s, &anode->btree);
		brelse(bh);
		hpfs_free_sectors(s, a, 1);
	} else hpfs_free_sectors(s, a, (len + 511) >> 9);
}

/* Truncate allocation tree. Doesn't join anodes - I hope it doesn't matter */

void hpfs_truncate_btree(struct super_block *s, secno f, int fno, unsigned secs)
{
	struct fnode *fnode;
	struct anode *anode;
	struct buffer_head *bh;
	struct bplus_header *btree;
	anode_secno node = f;
	int i, j, nodes;
	int c1, c2 = 0;
	if (fno) {
		if (!(fnode = hpfs_map_fnode(s, f, &bh))) return;
		btree = &fnode->btree;
	} else {
		if (!(anode = hpfs_map_anode(s, f, &bh))) return;
		btree = &anode->btree;
	}
	if (!secs) {
		hpfs_remove_btree(s, btree);
		if (fno) {
			btree->n_free_nodes = 8;
			btree->n_used_nodes = 0;
			btree->first_free = cpu_to_le16(8);
			btree->flags &= ~BP_internal;
			mark_buffer_dirty(bh);
		} else hpfs_free_sectors(s, f, 1);
		brelse(bh);
		return;
	}
	while (bp_internal(btree)) {
		nodes = btree->n_used_nodes + btree->n_free_nodes;
		for (i = 0; i < btree->n_used_nodes; i++)
			if (le32_to_cpu(btree->u.internal[i].file_secno) >= secs) goto f;
		brelse(bh);
		hpfs_error(s, "internal btree %08x doesn't end with -1", node);
		return;
		f:
		for (j = i + 1; j < btree->n_used_nodes; j++)
			hpfs_ea_remove(s, le32_to_cpu(btree->u.internal[j].down), 1, 0);
		btree->n_used_nodes = i + 1;
		btree->n_free_nodes = nodes - btree->n_used_nodes;
		btree->first_free = cpu_to_le16(8 + 8 * btree->n_used_nodes);
		mark_buffer_dirty(bh);
		if (btree->u.internal[i].file_secno == cpu_to_le32(secs)) {
			brelse(bh);
			return;
		}
		node = le32_to_cpu(btree->u.internal[i].down);
		brelse(bh);
		if (hpfs_sb(s)->sb_chk)
			if (hpfs_stop_cycles(s, node, &c1, &c2, "hpfs_truncate_btree"))
				return;
		if (!(anode = hpfs_map_anode(s, node, &bh))) return;
		btree = &anode->btree;
	}	
	nodes = btree->n_used_nodes + btree->n_free_nodes;
	for (i = 0; i < btree->n_used_nodes; i++)
		if (le32_to_cpu(btree->u.external[i].file_secno) + le32_to_cpu(btree->u.external[i].length) >= secs) goto ff;
	brelse(bh);
	return;
	ff:
	if (secs <= le32_to_cpu(btree->u.external[i].file_secno)) {
		hpfs_error(s, "there is an allocation error in file %08x, sector %08x", f, secs);
		if (i) i--;
	}
	else if (le32_to_cpu(btree->u.external[i].file_secno) + le32_to_cpu(btree->u.external[i].length) > secs) {
		hpfs_free_sectors(s, le32_to_cpu(btree->u.external[i].disk_secno) + secs -
			le32_to_cpu(btree->u.external[i].file_secno), le32_to_cpu(btree->u.external[i].length)
			- secs + le32_to_cpu(btree->u.external[i].file_secno)); /* I hope gcc optimizes this :-) */
		btree->u.external[i].length = cpu_to_le32(secs - le32_to_cpu(btree->u.external[i].file_secno));
	}
	for (j = i + 1; j < btree->n_used_nodes; j++)
		hpfs_free_sectors(s, le32_to_cpu(btree->u.external[j].disk_secno), le32_to_cpu(btree->u.external[j].length));
	btree->n_used_nodes = i + 1;
	btree->n_free_nodes = nodes - btree->n_used_nodes;
	btree->first_free = cpu_to_le16(8 + 12 * btree->n_used_nodes);
	mark_buffer_dirty(bh);
	brelse(bh);
}

/* Remove file or directory and it's eas - note that directory must
   be empty when this is called. */

void hpfs_remove_fnode(struct super_block *s, fnode_secno fno)
{
	struct buffer_head *bh;
	struct fnode *fnode;
	struct extended_attribute *ea;
	struct extended_attribute *ea_end;
	if (!(fnode = hpfs_map_fnode(s, fno, &bh))) return;
	if (!fnode_is_dir(fnode)) hpfs_remove_btree(s, &fnode->btree);
	else hpfs_remove_dtree(s, le32_to_cpu(fnode->u.external[0].disk_secno));
	ea_end = fnode_end_ea(fnode);
	for (ea = fnode_ea(fnode); ea < ea_end; ea = next_ea(ea))
		if (ea_indirect(ea))
			hpfs_ea_remove(s, ea_sec(ea), ea_in_anode(ea), ea_len(ea));
	hpfs_ea_ext_remove(s, le32_to_cpu(fnode->ea_secno), fnode_in_anode(fnode), le32_to_cpu(fnode->ea_size_l));
	brelse(bh);
	hpfs_free_sectors(s, fno, 1);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/anode.c */
/************************************************************/
/*
 *  linux/fs/hpfs/buffer.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  general buffer i/o
 */
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
// #include "hpfs_fn.h"
#include "../../inc/__fss.h"

void hpfs_prefetch_sectors(struct super_block *s, unsigned secno, int n)
{
	struct buffer_head *bh;
	struct blk_plug plug;

	if (n <= 0 || unlikely(secno >= hpfs_sb(s)->sb_fs_size))
		return;

	bh = sb_find_get_block(s, secno);
	if (bh) {
		if (buffer_uptodate(bh)) {
			brelse(bh);
			return;
		}
		brelse(bh);
	};

	blk_start_plug(&plug);
	while (n > 0) {
		if (unlikely(secno >= hpfs_sb(s)->sb_fs_size))
			break;
		sb_breadahead(s, secno);
		secno++;
		n--;
	}
	blk_finish_plug(&plug);
}

/* Map a sector into a buffer and return pointers to it and to the buffer. */

void *hpfs_map_sector(struct super_block *s, unsigned secno, struct buffer_head **bhp,
		 int ahead)
{
	struct buffer_head *bh;

	hpfs_lock_assert(s);

	hpfs_prefetch_sectors(s, secno, ahead);

	cond_resched();

	*bhp = bh = sb_bread(s, secno);
	if (bh != NULL)
		return bh->b_data;
	else {
		pr_err("%s(): read error\n", __func__);
		return NULL;
	}
}

/* Like hpfs_map_sector but don't read anything */

void *hpfs_get_sector(struct super_block *s, unsigned secno, struct buffer_head **bhp)
{
	struct buffer_head *bh;
	/*return hpfs_map_sector(s, secno, bhp, 0);*/

	hpfs_lock_assert(s);

	cond_resched();

	if ((*bhp = bh = sb_getblk(s, secno)) != NULL) {
		if (!buffer_uptodate(bh)) wait_on_buffer(bh);
		set_buffer_uptodate(bh);
		return bh->b_data;
	} else {
		pr_err("%s(): getblk failed\n", __func__);
		return NULL;
	}
}

/* Map 4 sectors into a 4buffer and return pointers to it and to the buffer. */

void *hpfs_map_4sectors(struct super_block *s, unsigned secno, struct quad_buffer_head *qbh,
		   int ahead)
{
	char *data;

	hpfs_lock_assert(s);

	cond_resched();

	if (secno & 3) {
		pr_err("%s(): unaligned read\n", __func__);
		return NULL;
	}

	hpfs_prefetch_sectors(s, secno, 4 + ahead);

	if (!(qbh->bh[0] = sb_bread(s, secno + 0))) goto bail0;
	if (!(qbh->bh[1] = sb_bread(s, secno + 1))) goto bail1;
	if (!(qbh->bh[2] = sb_bread(s, secno + 2))) goto bail2;
	if (!(qbh->bh[3] = sb_bread(s, secno + 3))) goto bail3;

	if (likely(qbh->bh[1]->b_data == qbh->bh[0]->b_data + 1 * 512) &&
	    likely(qbh->bh[2]->b_data == qbh->bh[0]->b_data + 2 * 512) &&
	    likely(qbh->bh[3]->b_data == qbh->bh[0]->b_data + 3 * 512)) {
		return qbh->data = qbh->bh[0]->b_data;
	}

	qbh->data = data = kmalloc(2048, GFP_NOFS);
	if (!data) {
		pr_err("%s(): out of memory\n", __func__);
		goto bail4;
	}

	memcpy(data + 0 * 512, qbh->bh[0]->b_data, 512);
	memcpy(data + 1 * 512, qbh->bh[1]->b_data, 512);
	memcpy(data + 2 * 512, qbh->bh[2]->b_data, 512);
	memcpy(data + 3 * 512, qbh->bh[3]->b_data, 512);

	return data;

 bail4:
	brelse(qbh->bh[3]);
 bail3:
	brelse(qbh->bh[2]);
 bail2:
	brelse(qbh->bh[1]);
 bail1:
	brelse(qbh->bh[0]);
 bail0:
	return NULL;
}

/* Don't read sectors */

void *hpfs_get_4sectors(struct super_block *s, unsigned secno,
                          struct quad_buffer_head *qbh)
{
	cond_resched();

	hpfs_lock_assert(s);

	if (secno & 3) {
		pr_err("%s(): unaligned read\n", __func__);
		return NULL;
	}

	if (!hpfs_get_sector(s, secno + 0, &qbh->bh[0])) goto bail0;
	if (!hpfs_get_sector(s, secno + 1, &qbh->bh[1])) goto bail1;
	if (!hpfs_get_sector(s, secno + 2, &qbh->bh[2])) goto bail2;
	if (!hpfs_get_sector(s, secno + 3, &qbh->bh[3])) goto bail3;

	if (likely(qbh->bh[1]->b_data == qbh->bh[0]->b_data + 1 * 512) &&
	    likely(qbh->bh[2]->b_data == qbh->bh[0]->b_data + 2 * 512) &&
	    likely(qbh->bh[3]->b_data == qbh->bh[0]->b_data + 3 * 512)) {
		return qbh->data = qbh->bh[0]->b_data;
	}

	if (!(qbh->data = kmalloc(2048, GFP_NOFS))) {
		pr_err("%s(): out of memory\n", __func__);
		goto bail4;
	}
	return qbh->data;

bail4:
	brelse(qbh->bh[3]);
bail3:
	brelse(qbh->bh[2]);
bail2:
	brelse(qbh->bh[1]);
bail1:
	brelse(qbh->bh[0]);
bail0:
	return NULL;
}
	

void hpfs_brelse4(struct quad_buffer_head *qbh)
{
	if (unlikely(qbh->data != qbh->bh[0]->b_data))
		kfree(qbh->data);
	brelse(qbh->bh[0]);
	brelse(qbh->bh[1]);
	brelse(qbh->bh[2]);
	brelse(qbh->bh[3]);
}	

void hpfs_mark_4buffers_dirty(struct quad_buffer_head *qbh)
{
	if (unlikely(qbh->data != qbh->bh[0]->b_data)) {
		memcpy(qbh->bh[0]->b_data, qbh->data + 0 * 512, 512);
		memcpy(qbh->bh[1]->b_data, qbh->data + 1 * 512, 512);
		memcpy(qbh->bh[2]->b_data, qbh->data + 2 * 512, 512);
		memcpy(qbh->bh[3]->b_data, qbh->data + 3 * 512, 512);
	}
	mark_buffer_dirty(qbh->bh[0]);
	mark_buffer_dirty(qbh->bh[1]);
	mark_buffer_dirty(qbh->bh[2]);
	mark_buffer_dirty(qbh->bh[3]);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/buffer.c */
/************************************************************/
/*
 *  linux/fs/hpfs/dentry.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  dcache operations
 */

// #include "hpfs_fn.h"

/*
 * Note: the dentry argument is the parent dentry.
 */

static int hpfs_hash_dentry(const struct dentry *dentry, struct qstr *qstr)
{
	unsigned long	 hash;
	int		 i;
	unsigned l = qstr->len;

	if (l == 1) if (qstr->name[0]=='.') goto x;
	if (l == 2) if (qstr->name[0]=='.' || qstr->name[1]=='.') goto x;
	hpfs_adjust_length(qstr->name, &l);
	/*if (hpfs_chk_name(qstr->name,&l))*/
		/*return -ENAMETOOLONG;*/
		/*return -ENOENT;*/
	x:

	hash = init_name_hash();
	for (i = 0; i < l; i++)
		hash = partial_name_hash(hpfs_upcase(hpfs_sb(dentry->d_sb)->sb_cp_table,qstr->name[i]), hash);
	qstr->hash = end_name_hash(hash);

	return 0;
}

static int hpfs_compare_dentry(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	unsigned al = len;
	unsigned bl = name->len;

	hpfs_adjust_length(str, &al);
	/*hpfs_adjust_length(b->name, &bl);*/

	/*
	 * 'str' is the nane of an already existing dentry, so the name
	 * must be valid. 'name' must be validated first.
	 */

	if (hpfs_chk_name(name->name, &bl))
		return 1;
	if (hpfs_compare_names(parent->d_sb, str, al, name->name, bl, 0))
		return 1;
	return 0;
}

const struct dentry_operations hpfs_dentry_operations = {
	.d_hash		= hpfs_hash_dentry,
	.d_compare	= hpfs_compare_dentry,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/dentry.c */
/************************************************************/
/*
 *  linux/fs/hpfs/dir.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  directory VFS functions
 */

// #include <linux/slab.h>
// #include "hpfs_fn.h"

static int hpfs_dir_release(struct inode *inode, struct file *filp)
{
	hpfs_lock(inode->i_sb);
	hpfs_del_pos(inode, &filp->f_pos);
	/*hpfs_write_if_changed(inode);*/
	hpfs_unlock(inode->i_sb);
	return 0;
}

/* This is slow, but it's not used often */

static loff_t hpfs_dir_lseek(struct file *filp, loff_t off, int whence)
{
	loff_t new_off = off + (whence == 1 ? filp->f_pos : 0);
	loff_t pos;
	struct quad_buffer_head qbh;
	struct inode *i = file_inode(filp);
	struct hpfs_inode_info *hpfs_inode = hpfs_i(i);
	struct super_block *s = i->i_sb;

	/* Somebody else will have to figure out what to do here */
	if (whence == SEEK_DATA || whence == SEEK_HOLE)
		return -EINVAL;

	mutex_lock(&i->i_mutex);
	hpfs_lock(s);

	/*pr_info("dir lseek\n");*/
	if (new_off == 0 || new_off == 1 || new_off == 11 || new_off == 12 || new_off == 13) goto ok;
	pos = ((loff_t) hpfs_de_as_down_as_possible(s, hpfs_inode->i_dno) << 4) + 1;
	while (pos != new_off) {
		if (map_pos_dirent(i, &pos, &qbh)) hpfs_brelse4(&qbh);
		else goto fail;
		if (pos == 12) goto fail;
	}
	hpfs_add_pos(i, &filp->f_pos);
ok:
	filp->f_pos = new_off;
	hpfs_unlock(s);
	mutex_unlock(&i->i_mutex);
	return new_off;
fail:
	/*pr_warn("illegal lseek: %016llx\n", new_off);*/
	hpfs_unlock(s);
	mutex_unlock(&i->i_mutex);
	return -ESPIPE;
}

static int hpfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct hpfs_inode_info *hpfs_inode = hpfs_i(inode);
	struct quad_buffer_head qbh;
	struct hpfs_dirent *de;
	int lc;
	loff_t next_pos;
	unsigned char *tempname;
	int c1, c2 = 0;
	int ret = 0;

	hpfs_lock(inode->i_sb);

	if (hpfs_sb(inode->i_sb)->sb_chk) {
		if (hpfs_chk_sectors(inode->i_sb, inode->i_ino, 1, "dir_fnode")) {
			ret = -EFSERROR;
			goto out;
		}
		if (hpfs_chk_sectors(inode->i_sb, hpfs_inode->i_dno, 4, "dir_dnode")) {
			ret = -EFSERROR;
			goto out;
		}
	}
	if (hpfs_sb(inode->i_sb)->sb_chk >= 2) {
		struct buffer_head *bh;
		struct fnode *fno;
		int e = 0;
		if (!(fno = hpfs_map_fnode(inode->i_sb, inode->i_ino, &bh))) {
			ret = -EIOERROR;
			goto out;
		}
		if (!fnode_is_dir(fno)) {
			e = 1;
			hpfs_error(inode->i_sb, "not a directory, fnode %08lx",
					(unsigned long)inode->i_ino);
		}
		if (hpfs_inode->i_dno != le32_to_cpu(fno->u.external[0].disk_secno)) {
			e = 1;
			hpfs_error(inode->i_sb, "corrupted inode: i_dno == %08x, fnode -> dnode == %08x", hpfs_inode->i_dno, le32_to_cpu(fno->u.external[0].disk_secno));
		}
		brelse(bh);
		if (e) {
			ret = -EFSERROR;
			goto out;
		}
	}
	lc = hpfs_sb(inode->i_sb)->sb_lowercase;
	if (ctx->pos == 12) { /* diff -r requires this (note, that diff -r */
		ctx->pos = 13; /* also fails on msdos filesystem in 2.0) */
		goto out;
	}
	if (ctx->pos == 13) {
		ret = -ENOENT;
		goto out;
	}
	
	while (1) {
		again:
		/* This won't work when cycle is longer than number of dirents
		   accepted by filldir, but what can I do?
		   maybe killall -9 ls helps */
		if (hpfs_sb(inode->i_sb)->sb_chk)
			if (hpfs_stop_cycles(inode->i_sb, ctx->pos, &c1, &c2, "hpfs_readdir")) {
				ret = -EFSERROR;
				goto out;
			}
		if (ctx->pos == 12)
			goto out;
		if (ctx->pos == 3 || ctx->pos == 4 || ctx->pos == 5) {
			pr_err("pos==%d\n", (int)ctx->pos);
			goto out;
		}
		if (ctx->pos == 0) {
			if (!dir_emit_dot(file, ctx))
				goto out;
			ctx->pos = 11;
		}
		if (ctx->pos == 11) {
			if (!dir_emit(ctx, "..", 2, hpfs_inode->i_parent_dir, DT_DIR))
				goto out;
			ctx->pos = 1;
		}
		if (ctx->pos == 1) {
			ctx->pos = ((loff_t) hpfs_de_as_down_as_possible(inode->i_sb, hpfs_inode->i_dno) << 4) + 1;
			hpfs_add_pos(inode, &file->f_pos);
			file->f_version = inode->i_version;
		}
		next_pos = ctx->pos;
		if (!(de = map_pos_dirent(inode, &next_pos, &qbh))) {
			ctx->pos = next_pos;
			ret = -EIOERROR;
			goto out;
		}
		if (de->first || de->last) {
			if (hpfs_sb(inode->i_sb)->sb_chk) {
				if (de->first && !de->last && (de->namelen != 2
				    || de ->name[0] != 1 || de->name[1] != 1))
					hpfs_error(inode->i_sb, "hpfs_readdir: bad ^A^A entry; pos = %08lx", (unsigned long)ctx->pos);
				if (de->last && (de->namelen != 1 || de ->name[0] != 255))
					hpfs_error(inode->i_sb, "hpfs_readdir: bad \\377 entry; pos = %08lx", (unsigned long)ctx->pos);
			}
			hpfs_brelse4(&qbh);
			ctx->pos = next_pos;
			goto again;
		}
		tempname = hpfs_translate_name(inode->i_sb, de->name, de->namelen, lc, de->not_8x3);
		if (!dir_emit(ctx, tempname, de->namelen, le32_to_cpu(de->fnode), DT_UNKNOWN)) {
			if (tempname != de->name) kfree(tempname);
			hpfs_brelse4(&qbh);
			goto out;
		}
		ctx->pos = next_pos;
		if (tempname != de->name) kfree(tempname);
		hpfs_brelse4(&qbh);
	}
out:
	hpfs_unlock(inode->i_sb);
	return ret;
}

/*
 * lookup.  Search the specified directory for the specified name, set
 * *result to the corresponding inode.
 *
 * lookup uses the inode number to tell read_inode whether it is reading
 * the inode of a directory or a file -- file ino's are odd, directory
 * ino's are even.  read_inode avoids i/o for file inodes; everything
 * needed is up here in the directory.  (And file fnodes are out in
 * the boondocks.)
 *
 *    - M.P.: this is over, sometimes we've got to read file's fnode for eas
 *	      inode numbers are just fnode sector numbers; iget lock is used
 *	      to tell read_inode to read fnode or not.
 */

struct dentry *hpfs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	const unsigned char *name = dentry->d_name.name;
	unsigned len = dentry->d_name.len;
	struct quad_buffer_head qbh;
	struct hpfs_dirent *de;
	ino_t ino;
	int err;
	struct inode *result = NULL;
	struct hpfs_inode_info *hpfs_result;

	hpfs_lock(dir->i_sb);
	if ((err = hpfs_chk_name(name, &len))) {
		if (err == -ENAMETOOLONG) {
			hpfs_unlock(dir->i_sb);
			return ERR_PTR(-ENAMETOOLONG);
		}
		goto end_add;
	}

	/*
	 * '.' and '..' will never be passed here.
	 */

	de = map_dirent(dir, hpfs_i(dir)->i_dno, name, len, NULL, &qbh);

	/*
	 * This is not really a bailout, just means file not found.
	 */

	if (!de) goto end;

	/*
	 * Get inode number, what we're after.
	 */

	ino = le32_to_cpu(de->fnode);

	/*
	 * Go find or make an inode.
	 */

	result = iget_locked(dir->i_sb, ino);
	if (!result) {
		hpfs_error(dir->i_sb, "hpfs_lookup: can't get inode");
		goto bail1;
	}
	if (result->i_state & I_NEW) {
		hpfs_init_inode(result);
		if (de->directory)
			hpfs_read_inode(result);
		else if (le32_to_cpu(de->ea_size) && hpfs_sb(dir->i_sb)->sb_eas)
			hpfs_read_inode(result);
		else {
			result->i_mode |= S_IFREG;
			result->i_mode &= ~0111;
			result->i_op = &hpfs_file_iops;
			result->i_fop = &hpfs_file_ops;
			set_nlink(result, 1);
		}
		unlock_new_inode(result);
	}
	hpfs_result = hpfs_i(result);
	if (!de->directory) hpfs_result->i_parent_dir = dir->i_ino;

	if (de->has_acl || de->has_xtd_perm) if (!(dir->i_sb->s_flags & MS_RDONLY)) {
		hpfs_error(result->i_sb, "ACLs or XPERM found. This is probably HPFS386. This driver doesn't support it now. Send me some info on these structures");
		goto bail1;
	}

	/*
	 * Fill in the info from the directory if this is a newly created
	 * inode.
	 */

	if (!result->i_ctime.tv_sec) {
		if (!(result->i_ctime.tv_sec = local_to_gmt(dir->i_sb, le32_to_cpu(de->creation_date))))
			result->i_ctime.tv_sec = 1;
		result->i_ctime.tv_nsec = 0;
		result->i_mtime.tv_sec = local_to_gmt(dir->i_sb, le32_to_cpu(de->write_date));
		result->i_mtime.tv_nsec = 0;
		result->i_atime.tv_sec = local_to_gmt(dir->i_sb, le32_to_cpu(de->read_date));
		result->i_atime.tv_nsec = 0;
		hpfs_result->i_ea_size = le32_to_cpu(de->ea_size);
		if (!hpfs_result->i_ea_mode && de->read_only)
			result->i_mode &= ~0222;
		if (!de->directory) {
			if (result->i_size == -1) {
				result->i_size = le32_to_cpu(de->file_size);
				result->i_data.a_ops = &hpfs_aops;
				hpfs_i(result)->mmu_private = result->i_size;
			/*
			 * i_blocks should count the fnode and any anodes.
			 * We count 1 for the fnode and don't bother about
			 * anodes -- the disk heads are on the directory band
			 * and we want them to stay there.
			 */
				result->i_blocks = 1 + ((result->i_size + 511) >> 9);
			}
		}
	}

	hpfs_brelse4(&qbh);

	/*
	 * Made it.
	 */

	end:
	end_add:
	hpfs_unlock(dir->i_sb);
	d_add(dentry, result);
	return NULL;

	/*
	 * Didn't.
	 */
	bail1:
	
	hpfs_brelse4(&qbh);
	
	/*bail:*/

	hpfs_unlock(dir->i_sb);
	return ERR_PTR(-ENOENT);
}

const struct file_operations hpfs_dir_ops =
{
	.llseek		= hpfs_dir_lseek,
	.read		= generic_read_dir,
	.iterate	= hpfs_readdir,
	.release	= hpfs_dir_release,
	.fsync		= hpfs_file_fsync,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/dir.c */
/************************************************************/
/*
 *  linux/fs/hpfs/dnode.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  handling directory dnode tree - adding, deleteing & searching for dirents
 */

// #include "hpfs_fn.h"

static loff_t get_pos(struct dnode *d, struct hpfs_dirent *fde)
{
	struct hpfs_dirent *de;
	struct hpfs_dirent *de_end = dnode_end_de(d);
	int i = 1;
	for (de = dnode_first_de(d); de < de_end; de = de_next_de(de)) {
		if (de == fde) return ((loff_t) le32_to_cpu(d->self) << 4) | (loff_t)i;
		i++;
	}
	pr_info("%s(): not_found\n", __func__);
	return ((loff_t)le32_to_cpu(d->self) << 4) | (loff_t)1;
}

void hpfs_add_pos(struct inode *inode, loff_t *pos)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(inode);
	int i = 0;
	loff_t **ppos;

	if (hpfs_inode->i_rddir_off)
		for (; hpfs_inode->i_rddir_off[i]; i++)
			if (hpfs_inode->i_rddir_off[i] == pos) return;
	if (!(i&0x0f)) {
		if (!(ppos = kmalloc((i+0x11) * sizeof(loff_t*), GFP_NOFS))) {
			pr_err("out of memory for position list\n");
			return;
		}
		if (hpfs_inode->i_rddir_off) {
			memcpy(ppos, hpfs_inode->i_rddir_off, i * sizeof(loff_t));
			kfree(hpfs_inode->i_rddir_off);
		}
		hpfs_inode->i_rddir_off = ppos;
	}
	hpfs_inode->i_rddir_off[i] = pos;
	hpfs_inode->i_rddir_off[i + 1] = NULL;
}

void hpfs_del_pos(struct inode *inode, loff_t *pos)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(inode);
	loff_t **i, **j;

	if (!hpfs_inode->i_rddir_off) goto not_f;
	for (i = hpfs_inode->i_rddir_off; *i; i++) if (*i == pos) goto fnd;
	goto not_f;
	fnd:
	for (j = i + 1; *j; j++) ;
	*i = *(j - 1);
	*(j - 1) = NULL;
	if (j - 1 == hpfs_inode->i_rddir_off) {
		kfree(hpfs_inode->i_rddir_off);
		hpfs_inode->i_rddir_off = NULL;
	}
	return;
	not_f:
	/*pr_warn("position pointer %p->%08x not found\n",
		  pos, (int)*pos);*/
	return;
}

static void for_all_poss(struct inode *inode, void (*f)(loff_t *, loff_t, loff_t),
			 loff_t p1, loff_t p2)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(inode);
	loff_t **i;

	if (!hpfs_inode->i_rddir_off) return;
	for (i = hpfs_inode->i_rddir_off; *i; i++) (*f)(*i, p1, p2);
	return;
}

static void hpfs_pos_subst(loff_t *p, loff_t f, loff_t t)
{
	if (*p == f) *p = t;
}

/*void hpfs_hpfs_pos_substd(loff_t *p, loff_t f, loff_t t)
{
	if ((*p & ~0x3f) == (f & ~0x3f)) *p = (t & ~0x3f) | (*p & 0x3f);
}*/

static void hpfs_pos_ins(loff_t *p, loff_t d, loff_t c)
{
	if ((*p & ~0x3f) == (d & ~0x3f) && (*p & 0x3f) >= (d & 0x3f)) {
		int n = (*p & 0x3f) + c;
		if (n > 0x3f)
			pr_err("%s(): %08x + %d\n",
				__func__, (int)*p, (int)c >> 8);
		else
			*p = (*p & ~0x3f) | n;
	}
}

static void hpfs_pos_del(loff_t *p, loff_t d, loff_t c)
{
	if ((*p & ~0x3f) == (d & ~0x3f) && (*p & 0x3f) >= (d & 0x3f)) {
		int n = (*p & 0x3f) - c;
		if (n < 1)
			pr_err("%s(): %08x - %d\n",
				__func__, (int)*p, (int)c >> 8);
		else
			*p = (*p & ~0x3f) | n;
	}
}

static struct hpfs_dirent *dnode_pre_last_de(struct dnode *d)
{
	struct hpfs_dirent *de, *de_end, *dee = NULL, *deee = NULL;
	de_end = dnode_end_de(d);
	for (de = dnode_first_de(d); de < de_end; de = de_next_de(de)) {
		deee = dee; dee = de;
	}	
	return deee;
}

static struct hpfs_dirent *dnode_last_de(struct dnode *d)
{
	struct hpfs_dirent *de, *de_end, *dee = NULL;
	de_end = dnode_end_de(d);
	for (de = dnode_first_de(d); de < de_end; de = de_next_de(de)) {
		dee = de;
	}	
	return dee;
}

static void set_last_pointer(struct super_block *s, struct dnode *d, dnode_secno ptr)
{
	struct hpfs_dirent *de;
	if (!(de = dnode_last_de(d))) {
		hpfs_error(s, "set_last_pointer: empty dnode %08x", le32_to_cpu(d->self));
		return;
	}
	if (hpfs_sb(s)->sb_chk) {
		if (de->down) {
			hpfs_error(s, "set_last_pointer: dnode %08x has already last pointer %08x",
				le32_to_cpu(d->self), de_down_pointer(de));
			return;
		}
		if (le16_to_cpu(de->length) != 32) {
			hpfs_error(s, "set_last_pointer: bad last dirent in dnode %08x", le32_to_cpu(d->self));
			return;
		}
	}
	if (ptr) {
		le32_add_cpu(&d->first_free, 4);
		if (le32_to_cpu(d->first_free) > 2048) {
			hpfs_error(s, "set_last_pointer: too long dnode %08x", le32_to_cpu(d->self));
			le32_add_cpu(&d->first_free, -4);
			return;
		}
		de->length = cpu_to_le16(36);
		de->down = 1;
		*(__le32 *)((char *)de + 32) = cpu_to_le32(ptr);
	}
}

/* Add an entry to dnode and don't care if it grows over 2048 bytes */

struct hpfs_dirent *hpfs_add_de(struct super_block *s, struct dnode *d,
				const unsigned char *name,
				unsigned namelen, secno down_ptr)
{
	struct hpfs_dirent *de;
	struct hpfs_dirent *de_end = dnode_end_de(d);
	unsigned d_size = de_size(namelen, down_ptr);
	for (de = dnode_first_de(d); de < de_end; de = de_next_de(de)) {
		int c = hpfs_compare_names(s, name, namelen, de->name, de->namelen, de->last);
		if (!c) {
			hpfs_error(s, "name (%c,%d) already exists in dnode %08x", *name, namelen, le32_to_cpu(d->self));
			return NULL;
		}
		if (c < 0) break;
	}
	memmove((char *)de + d_size, de, (char *)de_end - (char *)de);
	memset(de, 0, d_size);
	if (down_ptr) {
		*(__le32 *)((char *)de + d_size - 4) = cpu_to_le32(down_ptr);
		de->down = 1;
	}
	de->length = cpu_to_le16(d_size);
	de->not_8x3 = hpfs_is_name_long(name, namelen);
	de->namelen = namelen;
	memcpy(de->name, name, namelen);
	le32_add_cpu(&d->first_free, d_size);
	return de;
}

/* Delete dirent and don't care about its subtree */

static void hpfs_delete_de(struct super_block *s, struct dnode *d,
			   struct hpfs_dirent *de)
{
	if (de->last) {
		hpfs_error(s, "attempt to delete last dirent in dnode %08x", le32_to_cpu(d->self));
		return;
	}
	d->first_free = cpu_to_le32(le32_to_cpu(d->first_free) - le16_to_cpu(de->length));
	memmove(de, de_next_de(de), le32_to_cpu(d->first_free) + (char *)d - (char *)de);
}

static void fix_up_ptrs(struct super_block *s, struct dnode *d)
{
	struct hpfs_dirent *de;
	struct hpfs_dirent *de_end = dnode_end_de(d);
	dnode_secno dno = le32_to_cpu(d->self);
	for (de = dnode_first_de(d); de < de_end; de = de_next_de(de))
		if (de->down) {
			struct quad_buffer_head qbh;
			struct dnode *dd;
			if ((dd = hpfs_map_dnode(s, de_down_pointer(de), &qbh))) {
				if (le32_to_cpu(dd->up) != dno || dd->root_dnode) {
					dd->up = cpu_to_le32(dno);
					dd->root_dnode = 0;
					hpfs_mark_4buffers_dirty(&qbh);
				}
				hpfs_brelse4(&qbh);
			}
		}
}

/* Add an entry to dnode and do dnode splitting if required */

static int hpfs_add_to_dnode(struct inode *i, dnode_secno dno,
			     const unsigned char *name, unsigned namelen,
			     struct hpfs_dirent *new_de, dnode_secno down_ptr)
{
	struct quad_buffer_head qbh, qbh1, qbh2;
	struct dnode *d, *ad, *rd, *nd = NULL;
	dnode_secno adno, rdno;
	struct hpfs_dirent *de;
	struct hpfs_dirent nde;
	unsigned char *nname;
	int h;
	int pos;
	struct buffer_head *bh;
	struct fnode *fnode;
	int c1, c2 = 0;
	if (!(nname = kmalloc(256, GFP_NOFS))) {
		pr_err("out of memory, can't add to dnode\n");
		return 1;
	}
	go_up:
	if (namelen >= 256) {
		hpfs_error(i->i_sb, "%s(): namelen == %d", __func__, namelen);
		kfree(nd);
		kfree(nname);
		return 1;
	}
	if (!(d = hpfs_map_dnode(i->i_sb, dno, &qbh))) {
		kfree(nd);
		kfree(nname);
		return 1;
	}
	go_up_a:
	if (hpfs_sb(i->i_sb)->sb_chk)
		if (hpfs_stop_cycles(i->i_sb, dno, &c1, &c2, "hpfs_add_to_dnode")) {
			hpfs_brelse4(&qbh);
			kfree(nd);
			kfree(nname);
			return 1;
		}
	if (le32_to_cpu(d->first_free) + de_size(namelen, down_ptr) <= 2048) {
		loff_t t;
		copy_de(de=hpfs_add_de(i->i_sb, d, name, namelen, down_ptr), new_de);
		t = get_pos(d, de);
		for_all_poss(i, hpfs_pos_ins, t, 1);
		for_all_poss(i, hpfs_pos_subst, 4, t);
		for_all_poss(i, hpfs_pos_subst, 5, t + 1);
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
		kfree(nd);
		kfree(nname);
		return 0;
	}
	if (!nd) if (!(nd = kmalloc(0x924, GFP_NOFS))) {
		/* 0x924 is a max size of dnode after adding a dirent with
		   max name length. We alloc this only once. There must
		   not be any error while splitting dnodes, otherwise the
		   whole directory, not only file we're adding, would
		   be lost. */
		pr_err("out of memory for dnode splitting\n");
		hpfs_brelse4(&qbh);
		kfree(nname);
		return 1;
	}	
	memcpy(nd, d, le32_to_cpu(d->first_free));
	copy_de(de = hpfs_add_de(i->i_sb, nd, name, namelen, down_ptr), new_de);
	for_all_poss(i, hpfs_pos_ins, get_pos(nd, de), 1);
	h = ((char *)dnode_last_de(nd) - (char *)nd) / 2 + 10;
	if (!(ad = hpfs_alloc_dnode(i->i_sb, le32_to_cpu(d->up), &adno, &qbh1))) {
		hpfs_error(i->i_sb, "unable to alloc dnode - dnode tree will be corrupted");
		hpfs_brelse4(&qbh);
		kfree(nd);
		kfree(nname);
		return 1;
	}
	i->i_size += 2048;
	i->i_blocks += 4;
	pos = 1;
	for (de = dnode_first_de(nd); (char *)de_next_de(de) - (char *)nd < h; de = de_next_de(de)) {
		copy_de(hpfs_add_de(i->i_sb, ad, de->name, de->namelen, de->down ? de_down_pointer(de) : 0), de);
		for_all_poss(i, hpfs_pos_subst, ((loff_t)dno << 4) | pos, ((loff_t)adno << 4) | pos);
		pos++;
	}
	copy_de(new_de = &nde, de);
	memcpy(nname, de->name, de->namelen);
	name = nname;
	namelen = de->namelen;
	for_all_poss(i, hpfs_pos_subst, ((loff_t)dno << 4) | pos, 4);
	down_ptr = adno;
	set_last_pointer(i->i_sb, ad, de->down ? de_down_pointer(de) : 0);
	de = de_next_de(de);
	memmove((char *)nd + 20, de, le32_to_cpu(nd->first_free) + (char *)nd - (char *)de);
	le32_add_cpu(&nd->first_free, -((char *)de - (char *)nd - 20));
	memcpy(d, nd, le32_to_cpu(nd->first_free));
	for_all_poss(i, hpfs_pos_del, (loff_t)dno << 4, pos);
	fix_up_ptrs(i->i_sb, ad);
	if (!d->root_dnode) {
		ad->up = d->up;
		dno = le32_to_cpu(ad->up);
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
		hpfs_mark_4buffers_dirty(&qbh1);
		hpfs_brelse4(&qbh1);
		goto go_up;
	}
	if (!(rd = hpfs_alloc_dnode(i->i_sb, le32_to_cpu(d->up), &rdno, &qbh2))) {
		hpfs_error(i->i_sb, "unable to alloc dnode - dnode tree will be corrupted");
		hpfs_brelse4(&qbh);
		hpfs_brelse4(&qbh1);
		kfree(nd);
		kfree(nname);
		return 1;
	}
	i->i_size += 2048;
	i->i_blocks += 4;
	rd->root_dnode = 1;
	rd->up = d->up;
	if (!(fnode = hpfs_map_fnode(i->i_sb, le32_to_cpu(d->up), &bh))) {
		hpfs_free_dnode(i->i_sb, rdno);
		hpfs_brelse4(&qbh);
		hpfs_brelse4(&qbh1);
		hpfs_brelse4(&qbh2);
		kfree(nd);
		kfree(nname);
		return 1;
	}
	fnode->u.external[0].disk_secno = cpu_to_le32(rdno);
	mark_buffer_dirty(bh);
	brelse(bh);
	hpfs_i(i)->i_dno = rdno;
	d->up = ad->up = cpu_to_le32(rdno);
	d->root_dnode = ad->root_dnode = 0;
	hpfs_mark_4buffers_dirty(&qbh);
	hpfs_brelse4(&qbh);
	hpfs_mark_4buffers_dirty(&qbh1);
	hpfs_brelse4(&qbh1);
	qbh = qbh2;
	set_last_pointer(i->i_sb, rd, dno);
	dno = rdno;
	d = rd;
	goto go_up_a;
}

/*
 * Add an entry to directory btree.
 * I hate such crazy directory structure.
 * It's easy to read but terrible to write.
 * I wrote this directory code 4 times.
 * I hope, now it's finally bug-free.
 */

int hpfs_add_dirent(struct inode *i,
		    const unsigned char *name, unsigned namelen,
		    struct hpfs_dirent *new_de)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(i);
	struct dnode *d;
	struct hpfs_dirent *de, *de_end;
	struct quad_buffer_head qbh;
	dnode_secno dno;
	int c;
	int c1, c2 = 0;
	dno = hpfs_inode->i_dno;
	down:
	if (hpfs_sb(i->i_sb)->sb_chk)
		if (hpfs_stop_cycles(i->i_sb, dno, &c1, &c2, "hpfs_add_dirent")) return 1;
	if (!(d = hpfs_map_dnode(i->i_sb, dno, &qbh))) return 1;
	de_end = dnode_end_de(d);
	for (de = dnode_first_de(d); de < de_end; de = de_next_de(de)) {
		if (!(c = hpfs_compare_names(i->i_sb, name, namelen, de->name, de->namelen, de->last))) {
			hpfs_brelse4(&qbh);
			return -1;
		}	
		if (c < 0) {
			if (de->down) {
				dno = de_down_pointer(de);
				hpfs_brelse4(&qbh);
				goto down;
			}
			break;
		}
	}
	hpfs_brelse4(&qbh);
	if (hpfs_check_free_dnodes(i->i_sb, FREE_DNODES_ADD)) {
		c = 1;
		goto ret;
	}	
	i->i_version++;
	c = hpfs_add_to_dnode(i, dno, name, namelen, new_de, 0);
	ret:
	return c;
}

/* 
 * Find dirent with higher name in 'from' subtree and move it to 'to' dnode.
 * Return the dnode we moved from (to be checked later if it's empty)
 */

static secno move_to_top(struct inode *i, dnode_secno from, dnode_secno to)
{
	dnode_secno dno, ddno;
	dnode_secno chk_up = to;
	struct dnode *dnode;
	struct quad_buffer_head qbh;
	struct hpfs_dirent *de, *nde;
	int a;
	loff_t t;
	int c1, c2 = 0;
	dno = from;
	while (1) {
		if (hpfs_sb(i->i_sb)->sb_chk)
			if (hpfs_stop_cycles(i->i_sb, dno, &c1, &c2, "move_to_top"))
				return 0;
		if (!(dnode = hpfs_map_dnode(i->i_sb, dno, &qbh))) return 0;
		if (hpfs_sb(i->i_sb)->sb_chk) {
			if (le32_to_cpu(dnode->up) != chk_up) {
				hpfs_error(i->i_sb, "move_to_top: up pointer from %08x should be %08x, is %08x",
					dno, chk_up, le32_to_cpu(dnode->up));
				hpfs_brelse4(&qbh);
				return 0;
			}
			chk_up = dno;
		}
		if (!(de = dnode_last_de(dnode))) {
			hpfs_error(i->i_sb, "move_to_top: dnode %08x has no last de", dno);
			hpfs_brelse4(&qbh);
			return 0;
		}
		if (!de->down) break;
		dno = de_down_pointer(de);
		hpfs_brelse4(&qbh);
	}
	while (!(de = dnode_pre_last_de(dnode))) {
		dnode_secno up = le32_to_cpu(dnode->up);
		hpfs_brelse4(&qbh);
		hpfs_free_dnode(i->i_sb, dno);
		i->i_size -= 2048;
		i->i_blocks -= 4;
		for_all_poss(i, hpfs_pos_subst, ((loff_t)dno << 4) | 1, 5);
		if (up == to) return to;
		if (!(dnode = hpfs_map_dnode(i->i_sb, up, &qbh))) return 0;
		if (dnode->root_dnode) {
			hpfs_error(i->i_sb, "move_to_top: got to root_dnode while moving from %08x to %08x", from, to);
			hpfs_brelse4(&qbh);
			return 0;
		}
		de = dnode_last_de(dnode);
		if (!de || !de->down) {
			hpfs_error(i->i_sb, "move_to_top: dnode %08x doesn't point down to %08x", up, dno);
			hpfs_brelse4(&qbh);
			return 0;
		}
		le32_add_cpu(&dnode->first_free, -4);
		le16_add_cpu(&de->length, -4);
		de->down = 0;
		hpfs_mark_4buffers_dirty(&qbh);
		dno = up;
	}
	t = get_pos(dnode, de);
	for_all_poss(i, hpfs_pos_subst, t, 4);
	for_all_poss(i, hpfs_pos_subst, t + 1, 5);
	if (!(nde = kmalloc(le16_to_cpu(de->length), GFP_NOFS))) {
		hpfs_error(i->i_sb, "out of memory for dirent - directory will be corrupted");
		hpfs_brelse4(&qbh);
		return 0;
	}
	memcpy(nde, de, le16_to_cpu(de->length));
	ddno = de->down ? de_down_pointer(de) : 0;
	hpfs_delete_de(i->i_sb, dnode, de);
	set_last_pointer(i->i_sb, dnode, ddno);
	hpfs_mark_4buffers_dirty(&qbh);
	hpfs_brelse4(&qbh);
	a = hpfs_add_to_dnode(i, to, nde->name, nde->namelen, nde, from);
	kfree(nde);
	if (a) return 0;
	return dno;
}

/* 
 * Check if a dnode is empty and delete it from the tree
 * (chkdsk doesn't like empty dnodes)
 */

static void delete_empty_dnode(struct inode *i, dnode_secno dno)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(i);
	struct quad_buffer_head qbh;
	struct dnode *dnode;
	dnode_secno down, up, ndown;
	int p;
	struct hpfs_dirent *de;
	int c1, c2 = 0;
	try_it_again:
	if (hpfs_stop_cycles(i->i_sb, dno, &c1, &c2, "delete_empty_dnode")) return;
	if (!(dnode = hpfs_map_dnode(i->i_sb, dno, &qbh))) return;
	if (le32_to_cpu(dnode->first_free) > 56) goto end;
	if (le32_to_cpu(dnode->first_free) == 52 || le32_to_cpu(dnode->first_free) == 56) {
		struct hpfs_dirent *de_end;
		int root = dnode->root_dnode;
		up = le32_to_cpu(dnode->up);
		de = dnode_first_de(dnode);
		down = de->down ? de_down_pointer(de) : 0;
		if (hpfs_sb(i->i_sb)->sb_chk) if (root && !down) {
			hpfs_error(i->i_sb, "delete_empty_dnode: root dnode %08x is empty", dno);
			goto end;
		}
		hpfs_brelse4(&qbh);
		hpfs_free_dnode(i->i_sb, dno);
		i->i_size -= 2048;
		i->i_blocks -= 4;
		if (root) {
			struct fnode *fnode;
			struct buffer_head *bh;
			struct dnode *d1;
			struct quad_buffer_head qbh1;
			if (hpfs_sb(i->i_sb)->sb_chk)
				if (up != i->i_ino) {
					hpfs_error(i->i_sb,
						   "bad pointer to fnode, dnode %08x, pointing to %08x, should be %08lx",
						   dno, up,
						   (unsigned long)i->i_ino);
					return;
				}
			if ((d1 = hpfs_map_dnode(i->i_sb, down, &qbh1))) {
				d1->up = cpu_to_le32(up);
				d1->root_dnode = 1;
				hpfs_mark_4buffers_dirty(&qbh1);
				hpfs_brelse4(&qbh1);
			}
			if ((fnode = hpfs_map_fnode(i->i_sb, up, &bh))) {
				fnode->u.external[0].disk_secno = cpu_to_le32(down);
				mark_buffer_dirty(bh);
				brelse(bh);
			}
			hpfs_inode->i_dno = down;
			for_all_poss(i, hpfs_pos_subst, ((loff_t)dno << 4) | 1, (loff_t) 12);
			return;
		}
		if (!(dnode = hpfs_map_dnode(i->i_sb, up, &qbh))) return;
		p = 1;
		de_end = dnode_end_de(dnode);
		for (de = dnode_first_de(dnode); de < de_end; de = de_next_de(de), p++)
			if (de->down) if (de_down_pointer(de) == dno) goto fnd;
		hpfs_error(i->i_sb, "delete_empty_dnode: pointer to dnode %08x not found in dnode %08x", dno, up);
		goto end;
		fnd:
		for_all_poss(i, hpfs_pos_subst, ((loff_t)dno << 4) | 1, ((loff_t)up << 4) | p);
		if (!down) {
			de->down = 0;
			le16_add_cpu(&de->length, -4);
			le32_add_cpu(&dnode->first_free, -4);
			memmove(de_next_de(de), (char *)de_next_de(de) + 4,
				(char *)dnode + le32_to_cpu(dnode->first_free) - (char *)de_next_de(de));
		} else {
			struct dnode *d1;
			struct quad_buffer_head qbh1;
			*(dnode_secno *) ((void *) de + le16_to_cpu(de->length) - 4) = down;
			if ((d1 = hpfs_map_dnode(i->i_sb, down, &qbh1))) {
				d1->up = cpu_to_le32(up);
				hpfs_mark_4buffers_dirty(&qbh1);
				hpfs_brelse4(&qbh1);
			}
		}
	} else {
		hpfs_error(i->i_sb, "delete_empty_dnode: dnode %08x, first_free == %03x", dno, le32_to_cpu(dnode->first_free));
		goto end;
	}

	if (!de->last) {
		struct hpfs_dirent *de_next = de_next_de(de);
		struct hpfs_dirent *de_cp;
		struct dnode *d1;
		struct quad_buffer_head qbh1;
		if (!de_next->down) goto endm;
		ndown = de_down_pointer(de_next);
		if (!(de_cp = kmalloc(le16_to_cpu(de->length), GFP_NOFS))) {
			pr_err("out of memory for dtree balancing\n");
			goto endm;
		}
		memcpy(de_cp, de, le16_to_cpu(de->length));
		hpfs_delete_de(i->i_sb, dnode, de);
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
		for_all_poss(i, hpfs_pos_subst, ((loff_t)up << 4) | p, 4);
		for_all_poss(i, hpfs_pos_del, ((loff_t)up << 4) | p, 1);
		if (de_cp->down) if ((d1 = hpfs_map_dnode(i->i_sb, de_down_pointer(de_cp), &qbh1))) {
			d1->up = cpu_to_le32(ndown);
			hpfs_mark_4buffers_dirty(&qbh1);
			hpfs_brelse4(&qbh1);
		}
		hpfs_add_to_dnode(i, ndown, de_cp->name, de_cp->namelen, de_cp, de_cp->down ? de_down_pointer(de_cp) : 0);
		/*pr_info("UP-TO-DNODE: %08x (ndown = %08x, down = %08x, dno = %08x)\n",
		  up, ndown, down, dno);*/
		dno = up;
		kfree(de_cp);
		goto try_it_again;
	} else {
		struct hpfs_dirent *de_prev = dnode_pre_last_de(dnode);
		struct hpfs_dirent *de_cp;
		struct dnode *d1;
		struct quad_buffer_head qbh1;
		dnode_secno dlp;
		if (!de_prev) {
			hpfs_error(i->i_sb, "delete_empty_dnode: empty dnode %08x", up);
			hpfs_mark_4buffers_dirty(&qbh);
			hpfs_brelse4(&qbh);
			dno = up;
			goto try_it_again;
		}
		if (!de_prev->down) goto endm;
		ndown = de_down_pointer(de_prev);
		if ((d1 = hpfs_map_dnode(i->i_sb, ndown, &qbh1))) {
			struct hpfs_dirent *del = dnode_last_de(d1);
			dlp = del->down ? de_down_pointer(del) : 0;
			if (!dlp && down) {
				if (le32_to_cpu(d1->first_free) > 2044) {
					if (hpfs_sb(i->i_sb)->sb_chk >= 2) {
						pr_err("unbalanced dnode tree, see hpfs.txt 4 more info\n");
						pr_err("terminating balancing operation\n");
					}
					hpfs_brelse4(&qbh1);
					goto endm;
				}
				if (hpfs_sb(i->i_sb)->sb_chk >= 2) {
					pr_err("unbalanced dnode tree, see hpfs.txt 4 more info\n");
					pr_err("goin'on\n");
				}
				le16_add_cpu(&del->length, 4);
				del->down = 1;
				le32_add_cpu(&d1->first_free, 4);
			}
			if (dlp && !down) {
				le16_add_cpu(&del->length, -4);
				del->down = 0;
				le32_add_cpu(&d1->first_free, -4);
			} else if (down)
				*(__le32 *) ((void *) del + le16_to_cpu(del->length) - 4) = cpu_to_le32(down);
		} else goto endm;
		if (!(de_cp = kmalloc(le16_to_cpu(de_prev->length), GFP_NOFS))) {
			pr_err("out of memory for dtree balancing\n");
			hpfs_brelse4(&qbh1);
			goto endm;
		}
		hpfs_mark_4buffers_dirty(&qbh1);
		hpfs_brelse4(&qbh1);
		memcpy(de_cp, de_prev, le16_to_cpu(de_prev->length));
		hpfs_delete_de(i->i_sb, dnode, de_prev);
		if (!de_prev->down) {
			le16_add_cpu(&de_prev->length, 4);
			de_prev->down = 1;
			le32_add_cpu(&dnode->first_free, 4);
		}
		*(__le32 *) ((void *) de_prev + le16_to_cpu(de_prev->length) - 4) = cpu_to_le32(ndown);
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
		for_all_poss(i, hpfs_pos_subst, ((loff_t)up << 4) | (p - 1), 4);
		for_all_poss(i, hpfs_pos_subst, ((loff_t)up << 4) | p, ((loff_t)up << 4) | (p - 1));
		if (down) if ((d1 = hpfs_map_dnode(i->i_sb, de_down_pointer(de), &qbh1))) {
			d1->up = cpu_to_le32(ndown);
			hpfs_mark_4buffers_dirty(&qbh1);
			hpfs_brelse4(&qbh1);
		}
		hpfs_add_to_dnode(i, ndown, de_cp->name, de_cp->namelen, de_cp, dlp);
		dno = up;
		kfree(de_cp);
		goto try_it_again;
	}
	endm:
	hpfs_mark_4buffers_dirty(&qbh);
	end:
	hpfs_brelse4(&qbh);
}


/* Delete dirent from directory */

int hpfs_remove_dirent(struct inode *i, dnode_secno dno, struct hpfs_dirent *de,
		       struct quad_buffer_head *qbh, int depth)
{
	struct dnode *dnode = qbh->data;
	dnode_secno down = 0;
	loff_t t;
	if (de->first || de->last) {
		hpfs_error(i->i_sb, "hpfs_remove_dirent: attempt to delete first or last dirent in dnode %08x", dno);
		hpfs_brelse4(qbh);
		return 1;
	}
	if (de->down) down = de_down_pointer(de);
	if (depth && (de->down || (de == dnode_first_de(dnode) && de_next_de(de)->last))) {
		if (hpfs_check_free_dnodes(i->i_sb, FREE_DNODES_DEL)) {
			hpfs_brelse4(qbh);
			return 2;
		}
	}
	i->i_version++;
	for_all_poss(i, hpfs_pos_del, (t = get_pos(dnode, de)) + 1, 1);
	hpfs_delete_de(i->i_sb, dnode, de);
	hpfs_mark_4buffers_dirty(qbh);
	hpfs_brelse4(qbh);
	if (down) {
		dnode_secno a = move_to_top(i, down, dno);
		for_all_poss(i, hpfs_pos_subst, 5, t);
		if (a) delete_empty_dnode(i, a);
		return !a;
	}
	delete_empty_dnode(i, dno);
	return 0;
}

void hpfs_count_dnodes(struct super_block *s, dnode_secno dno, int *n_dnodes,
		       int *n_subdirs, int *n_items)
{
	struct dnode *dnode;
	struct quad_buffer_head qbh;
	struct hpfs_dirent *de;
	dnode_secno ptr, odno = 0;
	int c1, c2 = 0;
	int d1, d2 = 0;
	go_down:
	if (n_dnodes) (*n_dnodes)++;
	if (hpfs_sb(s)->sb_chk)
		if (hpfs_stop_cycles(s, dno, &c1, &c2, "hpfs_count_dnodes #1")) return;
	ptr = 0;
	go_up:
	if (!(dnode = hpfs_map_dnode(s, dno, &qbh))) return;
	if (hpfs_sb(s)->sb_chk) if (odno && odno != -1 && le32_to_cpu(dnode->up) != odno)
		hpfs_error(s, "hpfs_count_dnodes: bad up pointer; dnode %08x, down %08x points to %08x", odno, dno, le32_to_cpu(dnode->up));
	de = dnode_first_de(dnode);
	if (ptr) while(1) {
		if (de->down) if (de_down_pointer(de) == ptr) goto process_de;
		if (de->last) {
			hpfs_brelse4(&qbh);
			hpfs_error(s, "hpfs_count_dnodes: pointer to dnode %08x not found in dnode %08x, got here from %08x",
				ptr, dno, odno);
			return;
		}
		de = de_next_de(de);
	}
	next_de:
	if (de->down) {
		odno = dno;
		dno = de_down_pointer(de);
		hpfs_brelse4(&qbh);
		goto go_down;
	}
	process_de:
	if (!de->first && !de->last && de->directory && n_subdirs) (*n_subdirs)++;
	if (!de->first && !de->last && n_items) (*n_items)++;
	if ((de = de_next_de(de)) < dnode_end_de(dnode)) goto next_de;
	ptr = dno;
	dno = le32_to_cpu(dnode->up);
	if (dnode->root_dnode) {
		hpfs_brelse4(&qbh);
		return;
	}
	hpfs_brelse4(&qbh);
	if (hpfs_sb(s)->sb_chk)
		if (hpfs_stop_cycles(s, ptr, &d1, &d2, "hpfs_count_dnodes #2")) return;
	odno = -1;
	goto go_up;
}

static struct hpfs_dirent *map_nth_dirent(struct super_block *s, dnode_secno dno, int n,
					  struct quad_buffer_head *qbh, struct dnode **dn)
{
	int i;
	struct hpfs_dirent *de, *de_end;
	struct dnode *dnode;
	dnode = hpfs_map_dnode(s, dno, qbh);
	if (!dnode) return NULL;
	if (dn) *dn=dnode;
	de = dnode_first_de(dnode);
	de_end = dnode_end_de(dnode);
	for (i = 1; de < de_end; i++, de = de_next_de(de)) {
		if (i == n) {
			return de;
		}	
		if (de->last) break;
	}
	hpfs_brelse4(qbh);
	hpfs_error(s, "map_nth_dirent: n too high; dnode = %08x, requested %08x", dno, n);
	return NULL;
}

dnode_secno hpfs_de_as_down_as_possible(struct super_block *s, dnode_secno dno)
{
	struct quad_buffer_head qbh;
	dnode_secno d = dno;
	dnode_secno up = 0;
	struct hpfs_dirent *de;
	int c1, c2 = 0;

	again:
	if (hpfs_sb(s)->sb_chk)
		if (hpfs_stop_cycles(s, d, &c1, &c2, "hpfs_de_as_down_as_possible"))
			return d;
	if (!(de = map_nth_dirent(s, d, 1, &qbh, NULL))) return dno;
	if (hpfs_sb(s)->sb_chk)
		if (up && le32_to_cpu(((struct dnode *)qbh.data)->up) != up)
			hpfs_error(s, "hpfs_de_as_down_as_possible: bad up pointer; dnode %08x, down %08x points to %08x", up, d, le32_to_cpu(((struct dnode *)qbh.data)->up));
	if (!de->down) {
		hpfs_brelse4(&qbh);
		return d;
	}
	up = d;
	d = de_down_pointer(de);
	hpfs_brelse4(&qbh);
	goto again;
}

struct hpfs_dirent *map_pos_dirent(struct inode *inode, loff_t *posp,
				   struct quad_buffer_head *qbh)
{
	loff_t pos;
	unsigned c;
	dnode_secno dno;
	struct hpfs_dirent *de, *d;
	struct hpfs_dirent *up_de;
	struct hpfs_dirent *end_up_de;
	struct dnode *dnode;
	struct dnode *up_dnode;
	struct quad_buffer_head qbh0;

	pos = *posp;
	dno = pos >> 6 << 2;
	pos &= 077;
	if (!(de = map_nth_dirent(inode->i_sb, dno, pos, qbh, &dnode)))
		goto bail;

	/* Going to the next dirent */
	if ((d = de_next_de(de)) < dnode_end_de(dnode)) {
		if (!(++*posp & 077)) {
			hpfs_error(inode->i_sb,
				"map_pos_dirent: pos crossed dnode boundary; pos = %08llx",
				(unsigned long long)*posp);
			goto bail;
		}
		/* We're going down the tree */
		if (d->down) {
			*posp = ((loff_t) hpfs_de_as_down_as_possible(inode->i_sb, de_down_pointer(d)) << 4) + 1;
		}
	
		return de;
	}

	/* Going up */
	if (dnode->root_dnode) goto bail;

	if (!(up_dnode = hpfs_map_dnode(inode->i_sb, le32_to_cpu(dnode->up), &qbh0)))
		goto bail;

	end_up_de = dnode_end_de(up_dnode);
	c = 0;
	for (up_de = dnode_first_de(up_dnode); up_de < end_up_de;
	     up_de = de_next_de(up_de)) {
		if (!(++c & 077)) hpfs_error(inode->i_sb,
			"map_pos_dirent: pos crossed dnode boundary; dnode = %08x", le32_to_cpu(dnode->up));
		if (up_de->down && de_down_pointer(up_de) == dno) {
			*posp = ((loff_t) le32_to_cpu(dnode->up) << 4) + c;
			hpfs_brelse4(&qbh0);
			return de;
		}
	}
	
	hpfs_error(inode->i_sb, "map_pos_dirent: pointer to dnode %08x not found in parent dnode %08x",
		dno, le32_to_cpu(dnode->up));
	hpfs_brelse4(&qbh0);
	
	bail:
	*posp = 12;
	return de;
}

/* Find a dirent in tree */

struct hpfs_dirent *map_dirent(struct inode *inode, dnode_secno dno,
			       const unsigned char *name, unsigned len,
			       dnode_secno *dd, struct quad_buffer_head *qbh)
{
	struct dnode *dnode;
	struct hpfs_dirent *de;
	struct hpfs_dirent *de_end;
	int c1, c2 = 0;

	if (!S_ISDIR(inode->i_mode)) hpfs_error(inode->i_sb, "map_dirent: not a directory\n");
	again:
	if (hpfs_sb(inode->i_sb)->sb_chk)
		if (hpfs_stop_cycles(inode->i_sb, dno, &c1, &c2, "map_dirent")) return NULL;
	if (!(dnode = hpfs_map_dnode(inode->i_sb, dno, qbh))) return NULL;
	
	de_end = dnode_end_de(dnode);
	for (de = dnode_first_de(dnode); de < de_end; de = de_next_de(de)) {
		int t = hpfs_compare_names(inode->i_sb, name, len, de->name, de->namelen, de->last);
		if (!t) {
			if (dd) *dd = dno;
			return de;
		}
		if (t < 0) {
			if (de->down) {
				dno = de_down_pointer(de);
				hpfs_brelse4(qbh);
				goto again;
			}
		break;
		}
	}
	hpfs_brelse4(qbh);
	return NULL;
}

/*
 * Remove empty directory. In normal cases it is only one dnode with two
 * entries, but we must handle also such obscure cases when it's a tree
 * of empty dnodes.
 */

void hpfs_remove_dtree(struct super_block *s, dnode_secno dno)
{
	struct quad_buffer_head qbh;
	struct dnode *dnode;
	struct hpfs_dirent *de;
	dnode_secno d1, d2, rdno = dno;
	while (1) {
		if (!(dnode = hpfs_map_dnode(s, dno, &qbh))) return;
		de = dnode_first_de(dnode);
		if (de->last) {
			if (de->down) d1 = de_down_pointer(de);
			else goto error;
			hpfs_brelse4(&qbh);
			hpfs_free_dnode(s, dno);
			dno = d1;
		} else break;
	}
	if (!de->first) goto error;
	d1 = de->down ? de_down_pointer(de) : 0;
	de = de_next_de(de);
	if (!de->last) goto error;
	d2 = de->down ? de_down_pointer(de) : 0;
	hpfs_brelse4(&qbh);
	hpfs_free_dnode(s, dno);
	do {
		while (d1) {
			if (!(dnode = hpfs_map_dnode(s, dno = d1, &qbh))) return;
			de = dnode_first_de(dnode);
			if (!de->last) goto error;
			d1 = de->down ? de_down_pointer(de) : 0;
			hpfs_brelse4(&qbh);
			hpfs_free_dnode(s, dno);
		}
		d1 = d2;
		d2 = 0;
	} while (d1);
	return;
	error:
	hpfs_brelse4(&qbh);
	hpfs_free_dnode(s, dno);
	hpfs_error(s, "directory %08x is corrupted or not empty", rdno);
}

/* 
 * Find dirent for specified fnode. Use truncated 15-char name in fnode as
 * a help for searching.
 */

struct hpfs_dirent *map_fnode_dirent(struct super_block *s, fnode_secno fno,
				     struct fnode *f, struct quad_buffer_head *qbh)
{
	unsigned char *name1;
	unsigned char *name2;
	int name1len, name2len;
	struct dnode *d;
	dnode_secno dno, downd;
	struct fnode *upf;
	struct buffer_head *bh;
	struct hpfs_dirent *de, *de_end;
	int c;
	int c1, c2 = 0;
	int d1, d2 = 0;
	name1 = f->name;
	if (!(name2 = kmalloc(256, GFP_NOFS))) {
		pr_err("out of memory, can't map dirent\n");
		return NULL;
	}
	if (f->len <= 15)
		memcpy(name2, name1, name1len = name2len = f->len);
	else {
		memcpy(name2, name1, 15);
		memset(name2 + 15, 0xff, 256 - 15);
		/*name2[15] = 0xff;*/
		name1len = 15; name2len = 256;
	}
	if (!(upf = hpfs_map_fnode(s, le32_to_cpu(f->up), &bh))) {
		kfree(name2);
		return NULL;
	}	
	if (!fnode_is_dir(upf)) {
		brelse(bh);
		hpfs_error(s, "fnode %08x has non-directory parent %08x", fno, le32_to_cpu(f->up));
		kfree(name2);
		return NULL;
	}
	dno = le32_to_cpu(upf->u.external[0].disk_secno);
	brelse(bh);
	go_down:
	downd = 0;
	go_up:
	if (!(d = hpfs_map_dnode(s, dno, qbh))) {
		kfree(name2);
		return NULL;
	}
	de_end = dnode_end_de(d);
	de = dnode_first_de(d);
	if (downd) {
		while (de < de_end) {
			if (de->down) if (de_down_pointer(de) == downd) goto f;
			de = de_next_de(de);
		}
		hpfs_error(s, "pointer to dnode %08x not found in dnode %08x", downd, dno);
		hpfs_brelse4(qbh);
		kfree(name2);
		return NULL;
	}
	next_de:
	if (le32_to_cpu(de->fnode) == fno) {
		kfree(name2);
		return de;
	}
	c = hpfs_compare_names(s, name1, name1len, de->name, de->namelen, de->last);
	if (c < 0 && de->down) {
		dno = de_down_pointer(de);
		hpfs_brelse4(qbh);
		if (hpfs_sb(s)->sb_chk)
			if (hpfs_stop_cycles(s, dno, &c1, &c2, "map_fnode_dirent #1")) {
				kfree(name2);
				return NULL;
		}
		goto go_down;
	}
	f:
	if (le32_to_cpu(de->fnode) == fno) {
		kfree(name2);
		return de;
	}
	c = hpfs_compare_names(s, name2, name2len, de->name, de->namelen, de->last);
	if (c < 0 && !de->last) goto not_found;
	if ((de = de_next_de(de)) < de_end) goto next_de;
	if (d->root_dnode) goto not_found;
	downd = dno;
	dno = le32_to_cpu(d->up);
	hpfs_brelse4(qbh);
	if (hpfs_sb(s)->sb_chk)
		if (hpfs_stop_cycles(s, downd, &d1, &d2, "map_fnode_dirent #2")) {
			kfree(name2);
			return NULL;
		}
	goto go_up;
	not_found:
	hpfs_brelse4(qbh);
	hpfs_error(s, "dirent for fnode %08x not found", fno);
	kfree(name2);
	return NULL;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/dnode.c */
/************************************************************/
/*
 *  linux/fs/hpfs/ea.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  handling extended attributes
 */

// #include "hpfs_fn.h"

/* Remove external extended attributes. ano specifies whether a is a 
   direct sector where eas starts or an anode */

void hpfs_ea_ext_remove(struct super_block *s, secno a, int ano, unsigned len)
{
	unsigned pos = 0;
	while (pos < len) {
		char ex[4 + 255 + 1 + 8];
		struct extended_attribute *ea = (struct extended_attribute *)ex;
		if (pos + 4 > len) {
			hpfs_error(s, "EAs don't end correctly, %s %08x, len %08x",
				ano ? "anode" : "sectors", a, len);
			return;
		}
		if (hpfs_ea_read(s, a, ano, pos, 4, ex)) return;
		if (ea_indirect(ea)) {
			if (ea_valuelen(ea) != 8) {
				hpfs_error(s, "ea_indirect(ea) set while ea->valuelen!=8, %s %08x, pos %08x",
					ano ? "anode" : "sectors", a, pos);
				return;
			}
			if (hpfs_ea_read(s, a, ano, pos + 4, ea->namelen + 9, ex+4))
				return;
			hpfs_ea_remove(s, ea_sec(ea), ea_in_anode(ea), ea_len(ea));
		}
		pos += ea->namelen + ea_valuelen(ea) + 5;
	}
	if (!ano) hpfs_free_sectors(s, a, (len+511) >> 9);
	else {
		struct buffer_head *bh;
		struct anode *anode;
		if ((anode = hpfs_map_anode(s, a, &bh))) {
			hpfs_remove_btree(s, &anode->btree);
			brelse(bh);
			hpfs_free_sectors(s, a, 1);
		}
	}
}

static char *get_indirect_ea(struct super_block *s, int ano, secno a, int size)
{
	char *ret;
	if (!(ret = kmalloc(size + 1, GFP_NOFS))) {
		pr_err("out of memory for EA\n");
		return NULL;
	}
	if (hpfs_ea_read(s, a, ano, 0, size, ret)) {
		kfree(ret);
		return NULL;
	}
	ret[size] = 0;
	return ret;
}

static void set_indirect_ea(struct super_block *s, int ano, secno a,
			    const char *data, int size)
{
	hpfs_ea_write(s, a, ano, 0, size, data);
}

/* Read an extended attribute named 'key' into the provided buffer */

int hpfs_read_ea(struct super_block *s, struct fnode *fnode, char *key,
		char *buf, int size)
{
	unsigned pos;
	int ano, len;
	secno a;
	char ex[4 + 255 + 1 + 8];
	struct extended_attribute *ea;
	struct extended_attribute *ea_end = fnode_end_ea(fnode);
	for (ea = fnode_ea(fnode); ea < ea_end; ea = next_ea(ea))
		if (!strcmp(ea->name, key)) {
			if (ea_indirect(ea))
				goto indirect;
			if (ea_valuelen(ea) >= size)
				return -EINVAL;
			memcpy(buf, ea_data(ea), ea_valuelen(ea));
			buf[ea_valuelen(ea)] = 0;
			return 0;
		}
	a = le32_to_cpu(fnode->ea_secno);
	len = le32_to_cpu(fnode->ea_size_l);
	ano = fnode_in_anode(fnode);
	pos = 0;
	while (pos < len) {
		ea = (struct extended_attribute *)ex;
		if (pos + 4 > len) {
			hpfs_error(s, "EAs don't end correctly, %s %08x, len %08x",
				ano ? "anode" : "sectors", a, len);
			return -EIO;
		}
		if (hpfs_ea_read(s, a, ano, pos, 4, ex)) return -EIO;
		if (hpfs_ea_read(s, a, ano, pos + 4, ea->namelen + 1 + (ea_indirect(ea) ? 8 : 0), ex + 4))
			return -EIO;
		if (!strcmp(ea->name, key)) {
			if (ea_indirect(ea))
				goto indirect;
			if (ea_valuelen(ea) >= size)
				return -EINVAL;
			if (hpfs_ea_read(s, a, ano, pos + 4 + ea->namelen + 1, ea_valuelen(ea), buf))
				return -EIO;
			buf[ea_valuelen(ea)] = 0;
			return 0;
		}
		pos += ea->namelen + ea_valuelen(ea) + 5;
	}
	return -ENOENT;
indirect:
	if (ea_len(ea) >= size)
		return -EINVAL;
	if (hpfs_ea_read(s, ea_sec(ea), ea_in_anode(ea), 0, ea_len(ea), buf))
		return -EIO;
	buf[ea_len(ea)] = 0;
	return 0;
}

/* Read an extended attribute named 'key' */
char *hpfs_get_ea(struct super_block *s, struct fnode *fnode, char *key, int *size)
{
	char *ret;
	unsigned pos;
	int ano, len;
	secno a;
	struct extended_attribute *ea;
	struct extended_attribute *ea_end = fnode_end_ea(fnode);
	for (ea = fnode_ea(fnode); ea < ea_end; ea = next_ea(ea))
		if (!strcmp(ea->name, key)) {
			if (ea_indirect(ea))
				return get_indirect_ea(s, ea_in_anode(ea), ea_sec(ea), *size = ea_len(ea));
			if (!(ret = kmalloc((*size = ea_valuelen(ea)) + 1, GFP_NOFS))) {
				pr_err("out of memory for EA\n");
				return NULL;
			}
			memcpy(ret, ea_data(ea), ea_valuelen(ea));
			ret[ea_valuelen(ea)] = 0;
			return ret;
		}
	a = le32_to_cpu(fnode->ea_secno);
	len = le32_to_cpu(fnode->ea_size_l);
	ano = fnode_in_anode(fnode);
	pos = 0;
	while (pos < len) {
		char ex[4 + 255 + 1 + 8];
		ea = (struct extended_attribute *)ex;
		if (pos + 4 > len) {
			hpfs_error(s, "EAs don't end correctly, %s %08x, len %08x",
				ano ? "anode" : "sectors", a, len);
			return NULL;
		}
		if (hpfs_ea_read(s, a, ano, pos, 4, ex)) return NULL;
		if (hpfs_ea_read(s, a, ano, pos + 4, ea->namelen + 1 + (ea_indirect(ea) ? 8 : 0), ex + 4))
			return NULL;
		if (!strcmp(ea->name, key)) {
			if (ea_indirect(ea))
				return get_indirect_ea(s, ea_in_anode(ea), ea_sec(ea), *size = ea_len(ea));
			if (!(ret = kmalloc((*size = ea_valuelen(ea)) + 1, GFP_NOFS))) {
				pr_err("out of memory for EA\n");
				return NULL;
			}
			if (hpfs_ea_read(s, a, ano, pos + 4 + ea->namelen + 1, ea_valuelen(ea), ret)) {
				kfree(ret);
				return NULL;
			}
			ret[ea_valuelen(ea)] = 0;
			return ret;
		}
		pos += ea->namelen + ea_valuelen(ea) + 5;
	}
	return NULL;
}

/* 
 * Update or create extended attribute 'key' with value 'data'. Note that
 * when this ea exists, it MUST have the same size as size of data.
 * This driver can't change sizes of eas ('cause I just don't need it).
 */

void hpfs_set_ea(struct inode *inode, struct fnode *fnode, const char *key,
		 const char *data, int size)
{
	fnode_secno fno = inode->i_ino;
	struct super_block *s = inode->i_sb;
	unsigned pos;
	int ano, len;
	secno a;
	unsigned char h[4];
	struct extended_attribute *ea;
	struct extended_attribute *ea_end = fnode_end_ea(fnode);
	for (ea = fnode_ea(fnode); ea < ea_end; ea = next_ea(ea))
		if (!strcmp(ea->name, key)) {
			if (ea_indirect(ea)) {
				if (ea_len(ea) == size)
					set_indirect_ea(s, ea_in_anode(ea), ea_sec(ea), data, size);
			} else if (ea_valuelen(ea) == size) {
				memcpy(ea_data(ea), data, size);
			}
			return;
		}
	a = le32_to_cpu(fnode->ea_secno);
	len = le32_to_cpu(fnode->ea_size_l);
	ano = fnode_in_anode(fnode);
	pos = 0;
	while (pos < len) {
		char ex[4 + 255 + 1 + 8];
		ea = (struct extended_attribute *)ex;
		if (pos + 4 > len) {
			hpfs_error(s, "EAs don't end correctly, %s %08x, len %08x",
				ano ? "anode" : "sectors", a, len);
			return;
		}
		if (hpfs_ea_read(s, a, ano, pos, 4, ex)) return;
		if (hpfs_ea_read(s, a, ano, pos + 4, ea->namelen + 1 + (ea_indirect(ea) ? 8 : 0), ex + 4))
			return;
		if (!strcmp(ea->name, key)) {
			if (ea_indirect(ea)) {
				if (ea_len(ea) == size)
					set_indirect_ea(s, ea_in_anode(ea), ea_sec(ea), data, size);
			}
			else {
				if (ea_valuelen(ea) == size)
					hpfs_ea_write(s, a, ano, pos + 4 + ea->namelen + 1, size, data);
			}
			return;
		}
		pos += ea->namelen + ea_valuelen(ea) + 5;
	}
	if (!le16_to_cpu(fnode->ea_offs)) {
		/*if (le16_to_cpu(fnode->ea_size_s)) {
			hpfs_error(s, "fnode %08x: ea_size_s == %03x, ea_offs == 0",
				inode->i_ino, le16_to_cpu(fnode->ea_size_s));
			return;
		}*/
		fnode->ea_offs = cpu_to_le16(0xc4);
	}
	if (le16_to_cpu(fnode->ea_offs) < 0xc4 || le16_to_cpu(fnode->ea_offs) + le16_to_cpu(fnode->acl_size_s) + le16_to_cpu(fnode->ea_size_s) > 0x200) {
		hpfs_error(s, "fnode %08lx: ea_offs == %03x, ea_size_s == %03x",
			(unsigned long)inode->i_ino,
			le16_to_cpu(fnode->ea_offs), le16_to_cpu(fnode->ea_size_s));
		return;
	}
	if ((le16_to_cpu(fnode->ea_size_s) || !le32_to_cpu(fnode->ea_size_l)) &&
	     le16_to_cpu(fnode->ea_offs) + le16_to_cpu(fnode->acl_size_s) + le16_to_cpu(fnode->ea_size_s) + strlen(key) + size + 5 <= 0x200) {
		ea = fnode_end_ea(fnode);
		*(char *)ea = 0;
		ea->namelen = strlen(key);
		ea->valuelen_lo = size;
		ea->valuelen_hi = size >> 8;
		strcpy(ea->name, key);
		memcpy(ea_data(ea), data, size);
		fnode->ea_size_s = cpu_to_le16(le16_to_cpu(fnode->ea_size_s) + strlen(key) + size + 5);
		goto ret;
	}
	/* Most the code here is 99.9993422% unused. I hope there are no bugs.
	   But what .. HPFS.IFS has also bugs in ea management. */
	if (le16_to_cpu(fnode->ea_size_s) && !le32_to_cpu(fnode->ea_size_l)) {
		secno n;
		struct buffer_head *bh;
		char *data;
		if (!(n = hpfs_alloc_sector(s, fno, 1, 0))) return;
		if (!(data = hpfs_get_sector(s, n, &bh))) {
			hpfs_free_sectors(s, n, 1);
			return;
		}
		memcpy(data, fnode_ea(fnode), le16_to_cpu(fnode->ea_size_s));
		fnode->ea_size_l = cpu_to_le32(le16_to_cpu(fnode->ea_size_s));
		fnode->ea_size_s = cpu_to_le16(0);
		fnode->ea_secno = cpu_to_le32(n);
		fnode->flags &= ~FNODE_anode;
		mark_buffer_dirty(bh);
		brelse(bh);
	}
	pos = le32_to_cpu(fnode->ea_size_l) + 5 + strlen(key) + size;
	len = (le32_to_cpu(fnode->ea_size_l) + 511) >> 9;
	if (pos >= 30000) goto bail;
	while (((pos + 511) >> 9) > len) {
		if (!len) {
			secno q = hpfs_alloc_sector(s, fno, 1, 0);
			if (!q) goto bail;
			fnode->ea_secno = cpu_to_le32(q);
			fnode->flags &= ~FNODE_anode;
			len++;
		} else if (!fnode_in_anode(fnode)) {
			if (hpfs_alloc_if_possible(s, le32_to_cpu(fnode->ea_secno) + len)) {
				len++;
			} else {
				/* Aargh... don't know how to create ea anodes :-( */
				/*struct buffer_head *bh;
				struct anode *anode;
				anode_secno a_s;
				if (!(anode = hpfs_alloc_anode(s, fno, &a_s, &bh)))
					goto bail;
				anode->up = cpu_to_le32(fno);
				anode->btree.fnode_parent = 1;
				anode->btree.n_free_nodes--;
				anode->btree.n_used_nodes++;
				anode->btree.first_free = cpu_to_le16(le16_to_cpu(anode->btree.first_free) + 12);
				anode->u.external[0].disk_secno = cpu_to_le32(le32_to_cpu(fnode->ea_secno));
				anode->u.external[0].file_secno = cpu_to_le32(0);
				anode->u.external[0].length = cpu_to_le32(len);
				mark_buffer_dirty(bh);
				brelse(bh);
				fnode->flags |= FNODE_anode;
				fnode->ea_secno = cpu_to_le32(a_s);*/
				secno new_sec;
				int i;
				if (!(new_sec = hpfs_alloc_sector(s, fno, 1, 1 - ((pos + 511) >> 9))))
					goto bail;
				for (i = 0; i < len; i++) {
					struct buffer_head *bh1, *bh2;
					void *b1, *b2;
					if (!(b1 = hpfs_map_sector(s, le32_to_cpu(fnode->ea_secno) + i, &bh1, len - i - 1))) {
						hpfs_free_sectors(s, new_sec, (pos + 511) >> 9);
						goto bail;
					}
					if (!(b2 = hpfs_get_sector(s, new_sec + i, &bh2))) {
						brelse(bh1);
						hpfs_free_sectors(s, new_sec, (pos + 511) >> 9);
						goto bail;
					}
					memcpy(b2, b1, 512);
					brelse(bh1);
					mark_buffer_dirty(bh2);
					brelse(bh2);
				}
				hpfs_free_sectors(s, le32_to_cpu(fnode->ea_secno), len);
				fnode->ea_secno = cpu_to_le32(new_sec);
				len = (pos + 511) >> 9;
			}
		}
		if (fnode_in_anode(fnode)) {
			if (hpfs_add_sector_to_btree(s, le32_to_cpu(fnode->ea_secno),
						     0, len) != -1) {
				len++;
			} else {
				goto bail;
			}
		}
	}
	h[0] = 0;
	h[1] = strlen(key);
	h[2] = size & 0xff;
	h[3] = size >> 8;
	if (hpfs_ea_write(s, le32_to_cpu(fnode->ea_secno), fnode_in_anode(fnode), le32_to_cpu(fnode->ea_size_l), 4, h)) goto bail;
	if (hpfs_ea_write(s, le32_to_cpu(fnode->ea_secno), fnode_in_anode(fnode), le32_to_cpu(fnode->ea_size_l) + 4, h[1] + 1, key)) goto bail;
	if (hpfs_ea_write(s, le32_to_cpu(fnode->ea_secno), fnode_in_anode(fnode), le32_to_cpu(fnode->ea_size_l) + 5 + h[1], size, data)) goto bail;
	fnode->ea_size_l = cpu_to_le32(pos);
	ret:
	hpfs_i(inode)->i_ea_size += 5 + strlen(key) + size;
	return;
	bail:
	if (le32_to_cpu(fnode->ea_secno))
		if (fnode_in_anode(fnode)) hpfs_truncate_btree(s, le32_to_cpu(fnode->ea_secno), 1, (le32_to_cpu(fnode->ea_size_l) + 511) >> 9);
		else hpfs_free_sectors(s, le32_to_cpu(fnode->ea_secno) + ((le32_to_cpu(fnode->ea_size_l) + 511) >> 9), len - ((le32_to_cpu(fnode->ea_size_l) + 511) >> 9));
	else fnode->ea_secno = fnode->ea_size_l = cpu_to_le32(0);
}
	
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/ea.c */
/************************************************************/
/*
 *  linux/fs/hpfs/file.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  file VFS functions
 */

// #include "hpfs_fn.h"
#include <linux/mpage.h>
#include "../../inc/__fss.h"

#define BLOCKS(size) (((size) + 511) >> 9)

static int hpfs_file_release(struct inode *inode, struct file *file)
{
	hpfs_lock(inode->i_sb);
	hpfs_write_if_changed(inode);
	hpfs_unlock(inode->i_sb);
	return 0;
}

int hpfs_file_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	int ret;

	ret = filemap_write_and_wait_range(file->f_mapping, start, end);
	if (ret)
		return ret;
	return sync_blockdev(inode->i_sb->s_bdev);
}

/*
 * generic_file_read often calls bmap with non-existing sector,
 * so we must ignore such errors.
 */

static secno hpfs_bmap(struct inode *inode, unsigned file_secno, unsigned *n_secs)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(inode);
	unsigned n, disk_secno;
	struct fnode *fnode;
	struct buffer_head *bh;
	if (BLOCKS(hpfs_i(inode)->mmu_private) <= file_secno) return 0;
	n = file_secno - hpfs_inode->i_file_sec;
	if (n < hpfs_inode->i_n_secs) {
		*n_secs = hpfs_inode->i_n_secs - n;
		return hpfs_inode->i_disk_sec + n;
	}
	if (!(fnode = hpfs_map_fnode(inode->i_sb, inode->i_ino, &bh))) return 0;
	disk_secno = hpfs_bplus_lookup(inode->i_sb, inode, &fnode->btree, file_secno, bh);
	if (disk_secno == -1) return 0;
	if (hpfs_chk_sectors(inode->i_sb, disk_secno, 1, "bmap")) return 0;
	n = file_secno - hpfs_inode->i_file_sec;
	if (n < hpfs_inode->i_n_secs) {
		*n_secs = hpfs_inode->i_n_secs - n;
		return hpfs_inode->i_disk_sec + n;
	}
	*n_secs = 1;
	return disk_secno;
}

void hpfs_truncate(struct inode *i)
{
	if (IS_IMMUTABLE(i)) return /*-EPERM*/;
	hpfs_lock_assert(i->i_sb);

	hpfs_i(i)->i_n_secs = 0;
	i->i_blocks = 1 + ((i->i_size + 511) >> 9);
	hpfs_i(i)->mmu_private = i->i_size;
	hpfs_truncate_btree(i->i_sb, i->i_ino, 1, ((i->i_size + 511) >> 9));
	hpfs_write_inode(i);
	hpfs_i(i)->i_n_secs = 0;
}

static int hpfs_get_block(struct inode *inode, sector_t iblock, struct buffer_head *bh_result, int create)
{
	int r;
	secno s;
	unsigned n_secs;
	hpfs_lock(inode->i_sb);
	s = hpfs_bmap(inode, iblock, &n_secs);
	if (s) {
		if (bh_result->b_size >> 9 < n_secs)
			n_secs = bh_result->b_size >> 9;
		map_bh(bh_result, inode->i_sb, s);
		bh_result->b_size = n_secs << 9;
		goto ret_0;
	}
	if (!create) goto ret_0;
	if (iblock<<9 != hpfs_i(inode)->mmu_private) {
		BUG();
		r = -EIO;
		goto ret_r;
	}
	if ((s = hpfs_add_sector_to_btree(inode->i_sb, inode->i_ino, 1, inode->i_blocks - 1)) == -1) {
		hpfs_truncate_btree(inode->i_sb, inode->i_ino, 1, inode->i_blocks - 1);
		r = -ENOSPC;
		goto ret_r;
	}
	inode->i_blocks++;
	hpfs_i(inode)->mmu_private += 512;
	set_buffer_new(bh_result);
	map_bh(bh_result, inode->i_sb, s);
	ret_0:
	r = 0;
	ret_r:
	hpfs_unlock(inode->i_sb);
	return r;
}

static int hpfs_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, hpfs_get_block);
}

static int hpfs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, hpfs_get_block, wbc);
}

static int hpfs_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, hpfs_get_block);
}

static int hpfs_writepages(struct address_space *mapping,
			   struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, hpfs_get_block);
}

static void hpfs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	hpfs_lock(inode->i_sb);

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		hpfs_truncate(inode);
	}

	hpfs_unlock(inode->i_sb);
}

static int hpfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	*pagep = NULL;
	ret = cont_write_begin(file, mapping, pos, len, flags, pagep, fsdata,
				hpfs_get_block,
				&hpfs_i(mapping->host)->mmu_private);
	if (unlikely(ret))
		hpfs_write_failed(mapping, pos + len);

	return ret;
}

static int hpfs_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *pagep, void *fsdata)
{
	struct inode *inode = mapping->host;
	int err;
	err = generic_write_end(file, mapping, pos, len, copied, pagep, fsdata);
	if (err < len)
		hpfs_write_failed(mapping, pos + len);
	if (!(err < 0)) {
		/* make sure we write it on close, if not earlier */
		hpfs_lock(inode->i_sb);
		hpfs_i(inode)->i_dirty = 1;
		hpfs_unlock(inode->i_sb);
	}
	return err;
}

static sector_t _hpfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,hpfs_get_block);
}

const struct address_space_operations hpfs_aops = {
	.readpage = hpfs_readpage,
	.writepage = hpfs_writepage,
	.readpages = hpfs_readpages,
	.writepages = hpfs_writepages,
	.write_begin = hpfs_write_begin,
	.write_end = hpfs_write_end,
	.bmap = _hpfs_bmap
};

const struct file_operations hpfs_file_ops =
{
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.release	= hpfs_file_release,
	.fsync		= hpfs_file_fsync,
	.splice_read	= generic_file_splice_read,
};

const struct inode_operations hpfs_file_iops =
{
	.setattr	= hpfs_setattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/file.c */
/************************************************************/
/*
 *  linux/fs/hpfs/inode.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  inode VFS functions
 */

// #include <linux/slab.h>
#include <linux/user_namespace.h>
// #include "hpfs_fn.h"
#include "../../inc/__fss.h"

void hpfs_init_inode(struct inode *i)
{
	struct super_block *sb = i->i_sb;
	struct hpfs_inode_info *hpfs_inode = hpfs_i(i);

	i->i_uid = hpfs_sb(sb)->sb_uid;
	i->i_gid = hpfs_sb(sb)->sb_gid;
	i->i_mode = hpfs_sb(sb)->sb_mode;
	i->i_size = -1;
	i->i_blocks = -1;
	
	hpfs_inode->i_dno = 0;
	hpfs_inode->i_n_secs = 0;
	hpfs_inode->i_file_sec = 0;
	hpfs_inode->i_disk_sec = 0;
	hpfs_inode->i_dpos = 0;
	hpfs_inode->i_dsubdno = 0;
	hpfs_inode->i_ea_mode = 0;
	hpfs_inode->i_ea_uid = 0;
	hpfs_inode->i_ea_gid = 0;
	hpfs_inode->i_ea_size = 0;

	hpfs_inode->i_rddir_off = NULL;
	hpfs_inode->i_dirty = 0;

	i->i_ctime.tv_sec = i->i_ctime.tv_nsec = 0;
	i->i_mtime.tv_sec = i->i_mtime.tv_nsec = 0;
	i->i_atime.tv_sec = i->i_atime.tv_nsec = 0;
}

void hpfs_read_inode(struct inode *i)
{
	struct buffer_head *bh;
	struct fnode *fnode;
	struct super_block *sb = i->i_sb;
	struct hpfs_inode_info *hpfs_inode = hpfs_i(i);
	void *ea;
	int ea_size;

	if (!(fnode = hpfs_map_fnode(sb, i->i_ino, &bh))) {
		/*i->i_mode |= S_IFREG;
		i->i_mode &= ~0111;
		i->i_op = &hpfs_file_iops;
		i->i_fop = &hpfs_file_ops;
		clear_nlink(i);*/
		make_bad_inode(i);
		return;
	}
	if (hpfs_sb(i->i_sb)->sb_eas) {
		if ((ea = hpfs_get_ea(i->i_sb, fnode, "UID", &ea_size))) {
			if (ea_size == 2) {
				i_uid_write(i, le16_to_cpu(*(__le16*)ea));
				hpfs_inode->i_ea_uid = 1;
			}
			kfree(ea);
		}
		if ((ea = hpfs_get_ea(i->i_sb, fnode, "GID", &ea_size))) {
			if (ea_size == 2) {
				i_gid_write(i, le16_to_cpu(*(__le16*)ea));
				hpfs_inode->i_ea_gid = 1;
			}
			kfree(ea);
		}
		if ((ea = hpfs_get_ea(i->i_sb, fnode, "SYMLINK", &ea_size))) {
			kfree(ea);
			i->i_mode = S_IFLNK | 0777;
			i->i_op = &page_symlink_inode_operations;
			i->i_data.a_ops = &hpfs_symlink_aops;
			set_nlink(i, 1);
			i->i_size = ea_size;
			i->i_blocks = 1;
			brelse(bh);
			return;
		}
		if ((ea = hpfs_get_ea(i->i_sb, fnode, "MODE", &ea_size))) {
			int rdev = 0;
			umode_t mode = hpfs_sb(sb)->sb_mode;
			if (ea_size == 2) {
				mode = le16_to_cpu(*(__le16*)ea);
				hpfs_inode->i_ea_mode = 1;
			}
			kfree(ea);
			i->i_mode = mode;
			if (S_ISBLK(mode) || S_ISCHR(mode)) {
				if ((ea = hpfs_get_ea(i->i_sb, fnode, "DEV", &ea_size))) {
					if (ea_size == 4)
						rdev = le32_to_cpu(*(__le32*)ea);
					kfree(ea);
				}
			}
			if (S_ISBLK(mode) || S_ISCHR(mode) || S_ISFIFO(mode) || S_ISSOCK(mode)) {
				brelse(bh);
				set_nlink(i, 1);
				i->i_size = 0;
				i->i_blocks = 1;
				init_special_inode(i, mode,
					new_decode_dev(rdev));
				return;
			}
		}
	}
	if (fnode_is_dir(fnode)) {
		int n_dnodes, n_subdirs;
		i->i_mode |= S_IFDIR;
		i->i_op = &hpfs_dir_iops;
		i->i_fop = &hpfs_dir_ops;
		hpfs_inode->i_parent_dir = le32_to_cpu(fnode->up);
		hpfs_inode->i_dno = le32_to_cpu(fnode->u.external[0].disk_secno);
		if (hpfs_sb(sb)->sb_chk >= 2) {
			struct buffer_head *bh0;
			if (hpfs_map_fnode(sb, hpfs_inode->i_parent_dir, &bh0)) brelse(bh0);
		}
		n_dnodes = 0; n_subdirs = 0;
		hpfs_count_dnodes(i->i_sb, hpfs_inode->i_dno, &n_dnodes, &n_subdirs, NULL);
		i->i_blocks = 4 * n_dnodes;
		i->i_size = 2048 * n_dnodes;
		set_nlink(i, 2 + n_subdirs);
	} else {
		i->i_mode |= S_IFREG;
		if (!hpfs_inode->i_ea_mode) i->i_mode &= ~0111;
		i->i_op = &hpfs_file_iops;
		i->i_fop = &hpfs_file_ops;
		set_nlink(i, 1);
		i->i_size = le32_to_cpu(fnode->file_size);
		i->i_blocks = ((i->i_size + 511) >> 9) + 1;
		i->i_data.a_ops = &hpfs_aops;
		hpfs_i(i)->mmu_private = i->i_size;
	}
	brelse(bh);
}

static void hpfs_write_inode_ea(struct inode *i, struct fnode *fnode)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(i);
	/*if (le32_to_cpu(fnode->acl_size_l) || le16_to_cpu(fnode->acl_size_s)) {
		   Some unknown structures like ACL may be in fnode,
		   we'd better not overwrite them
		hpfs_error(i->i_sb, "fnode %08x has some unknown HPFS386 structures", i->i_ino);
	} else*/ if (hpfs_sb(i->i_sb)->sb_eas >= 2) {
		__le32 ea;
		if (!uid_eq(i->i_uid, hpfs_sb(i->i_sb)->sb_uid) || hpfs_inode->i_ea_uid) {
			ea = cpu_to_le32(i_uid_read(i));
			hpfs_set_ea(i, fnode, "UID", (char*)&ea, 2);
			hpfs_inode->i_ea_uid = 1;
		}
		if (!gid_eq(i->i_gid, hpfs_sb(i->i_sb)->sb_gid) || hpfs_inode->i_ea_gid) {
			ea = cpu_to_le32(i_gid_read(i));
			hpfs_set_ea(i, fnode, "GID", (char *)&ea, 2);
			hpfs_inode->i_ea_gid = 1;
		}
		if (!S_ISLNK(i->i_mode))
			if ((i->i_mode != ((hpfs_sb(i->i_sb)->sb_mode & ~(S_ISDIR(i->i_mode) ? 0 : 0111))
			  | (S_ISDIR(i->i_mode) ? S_IFDIR : S_IFREG))
			  && i->i_mode != ((hpfs_sb(i->i_sb)->sb_mode & ~(S_ISDIR(i->i_mode) ? 0222 : 0333))
			  | (S_ISDIR(i->i_mode) ? S_IFDIR : S_IFREG))) || hpfs_inode->i_ea_mode) {
				ea = cpu_to_le32(i->i_mode);
				/* sick, but legal */
				hpfs_set_ea(i, fnode, "MODE", (char *)&ea, 2);
				hpfs_inode->i_ea_mode = 1;
			}
		if (S_ISBLK(i->i_mode) || S_ISCHR(i->i_mode)) {
			ea = cpu_to_le32(new_encode_dev(i->i_rdev));
			hpfs_set_ea(i, fnode, "DEV", (char *)&ea, 4);
		}
	}
}

void hpfs_write_inode(struct inode *i)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(i);
	struct inode *parent;
	if (i->i_ino == hpfs_sb(i->i_sb)->sb_root) return;
	if (hpfs_inode->i_rddir_off && !atomic_read(&i->i_count)) {
		if (*hpfs_inode->i_rddir_off)
			pr_err("write_inode: some position still there\n");
		kfree(hpfs_inode->i_rddir_off);
		hpfs_inode->i_rddir_off = NULL;
	}
	if (!i->i_nlink) {
		return;
	}
	parent = iget_locked(i->i_sb, hpfs_inode->i_parent_dir);
	if (parent) {
		hpfs_inode->i_dirty = 0;
		if (parent->i_state & I_NEW) {
			hpfs_init_inode(parent);
			hpfs_read_inode(parent);
			unlock_new_inode(parent);
		}
		hpfs_write_inode_nolock(i);
		iput(parent);
	}
}

void hpfs_write_inode_nolock(struct inode *i)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(i);
	struct buffer_head *bh;
	struct fnode *fnode;
	struct quad_buffer_head qbh;
	struct hpfs_dirent *de;
	if (i->i_ino == hpfs_sb(i->i_sb)->sb_root) return;
	if (!(fnode = hpfs_map_fnode(i->i_sb, i->i_ino, &bh))) return;
	if (i->i_ino != hpfs_sb(i->i_sb)->sb_root && i->i_nlink) {
		if (!(de = map_fnode_dirent(i->i_sb, i->i_ino, fnode, &qbh))) {
			brelse(bh);
			return;
		}
	} else de = NULL;
	if (S_ISREG(i->i_mode)) {
		fnode->file_size = cpu_to_le32(i->i_size);
		if (de) de->file_size = cpu_to_le32(i->i_size);
	} else if (S_ISDIR(i->i_mode)) {
		fnode->file_size = cpu_to_le32(0);
		if (de) de->file_size = cpu_to_le32(0);
	}
	hpfs_write_inode_ea(i, fnode);
	if (de) {
		de->write_date = cpu_to_le32(gmt_to_local(i->i_sb, i->i_mtime.tv_sec));
		de->read_date = cpu_to_le32(gmt_to_local(i->i_sb, i->i_atime.tv_sec));
		de->creation_date = cpu_to_le32(gmt_to_local(i->i_sb, i->i_ctime.tv_sec));
		de->read_only = !(i->i_mode & 0222);
		de->ea_size = cpu_to_le32(hpfs_inode->i_ea_size);
		hpfs_mark_4buffers_dirty(&qbh);
		hpfs_brelse4(&qbh);
	}
	if (S_ISDIR(i->i_mode)) {
		if ((de = map_dirent(i, hpfs_inode->i_dno, "\001\001", 2, NULL, &qbh))) {
			de->write_date = cpu_to_le32(gmt_to_local(i->i_sb, i->i_mtime.tv_sec));
			de->read_date = cpu_to_le32(gmt_to_local(i->i_sb, i->i_atime.tv_sec));
			de->creation_date = cpu_to_le32(gmt_to_local(i->i_sb, i->i_ctime.tv_sec));
			de->read_only = !(i->i_mode & 0222);
			de->ea_size = cpu_to_le32(/*hpfs_inode->i_ea_size*/0);
			de->file_size = cpu_to_le32(0);
			hpfs_mark_4buffers_dirty(&qbh);
			hpfs_brelse4(&qbh);
		} else
			hpfs_error(i->i_sb,
				"directory %08lx doesn't have '.' entry",
				(unsigned long)i->i_ino);
	}
	mark_buffer_dirty(bh);
	brelse(bh);
}

int hpfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error = -EINVAL;

	hpfs_lock(inode->i_sb);
	if (inode->i_ino == hpfs_sb(inode->i_sb)->sb_root)
		goto out_unlock;
	if ((attr->ia_valid & ATTR_UID) &&
	    from_kuid(&init_user_ns, attr->ia_uid) >= 0x10000)
		goto out_unlock;
	if ((attr->ia_valid & ATTR_GID) &&
	    from_kgid(&init_user_ns, attr->ia_gid) >= 0x10000)
		goto out_unlock;
	if ((attr->ia_valid & ATTR_SIZE) && attr->ia_size > inode->i_size)
		goto out_unlock;

	error = inode_change_ok(inode, attr);
	if (error)
		goto out_unlock;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			goto out_unlock;

		truncate_setsize(inode, attr->ia_size);
		hpfs_truncate(inode);
	}

	setattr_copy(inode, attr);

	hpfs_write_inode(inode);

 out_unlock:
	hpfs_unlock(inode->i_sb);
	return error;
}

void hpfs_write_if_changed(struct inode *inode)
{
	struct hpfs_inode_info *hpfs_inode = hpfs_i(inode);

	if (hpfs_inode->i_dirty)
		hpfs_write_inode(inode);
}

void hpfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (!inode->i_nlink) {
		hpfs_lock(inode->i_sb);
		hpfs_remove_fnode(inode->i_sb, inode->i_ino);
		hpfs_unlock(inode->i_sb);
	}
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/inode.c */
/************************************************************/
/*
 *  linux/fs/hpfs/map.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  mapping structures to memory with some minimal checks
 */

// #include "hpfs_fn.h"

__le32 *hpfs_map_dnode_bitmap(struct super_block *s, struct quad_buffer_head *qbh)
{
	return hpfs_map_4sectors(s, hpfs_sb(s)->sb_dmap, qbh, 0);
}

__le32 *hpfs_map_bitmap(struct super_block *s, unsigned bmp_block,
			 struct quad_buffer_head *qbh, char *id)
{
	secno sec;
	__le32 *ret;
	unsigned n_bands = (hpfs_sb(s)->sb_fs_size + 0x3fff) >> 14;
	if (hpfs_sb(s)->sb_chk) if (bmp_block >= n_bands) {
		hpfs_error(s, "hpfs_map_bitmap called with bad parameter: %08x at %s", bmp_block, id);
		return NULL;
	}
	sec = le32_to_cpu(hpfs_sb(s)->sb_bmp_dir[bmp_block]);
	if (!sec || sec > hpfs_sb(s)->sb_fs_size-4) {
		hpfs_error(s, "invalid bitmap block pointer %08x -> %08x at %s", bmp_block, sec, id);
		return NULL;
	}
	ret = hpfs_map_4sectors(s, sec, qbh, 4);
	if (ret) hpfs_prefetch_bitmap(s, bmp_block + 1);
	return ret;
}

void hpfs_prefetch_bitmap(struct super_block *s, unsigned bmp_block)
{
	unsigned to_prefetch, next_prefetch;
	unsigned n_bands = (hpfs_sb(s)->sb_fs_size + 0x3fff) >> 14;
	if (unlikely(bmp_block >= n_bands))
		return;
	to_prefetch = le32_to_cpu(hpfs_sb(s)->sb_bmp_dir[bmp_block]);
	if (unlikely(bmp_block + 1 >= n_bands))
		next_prefetch = 0;
	else
		next_prefetch = le32_to_cpu(hpfs_sb(s)->sb_bmp_dir[bmp_block + 1]);
	hpfs_prefetch_sectors(s, to_prefetch, 4 + 4 * (to_prefetch + 4 == next_prefetch));
}

/*
 * Load first code page into kernel memory, return pointer to 256-byte array,
 * first 128 bytes are uppercasing table for chars 128-255, next 128 bytes are
 * lowercasing table
 */

unsigned char *hpfs_load_code_page(struct super_block *s, secno cps)
{
	struct buffer_head *bh;
	secno cpds;
	unsigned cpi;
	unsigned char *ptr;
	unsigned char *cp_table;
	int i;
	struct code_page_data *cpd;
	struct code_page_directory *cp = hpfs_map_sector(s, cps, &bh, 0);
	if (!cp) return NULL;
	if (le32_to_cpu(cp->magic) != CP_DIR_MAGIC) {
		pr_err("Code page directory magic doesn't match (magic = %08x)\n",
			le32_to_cpu(cp->magic));
		brelse(bh);
		return NULL;
	}
	if (!le32_to_cpu(cp->n_code_pages)) {
		pr_err("n_code_pages == 0\n");
		brelse(bh);
		return NULL;
	}
	cpds = le32_to_cpu(cp->array[0].code_page_data);
	cpi = le16_to_cpu(cp->array[0].index);
	brelse(bh);

	if (cpi >= 3) {
		pr_err("Code page index out of array\n");
		return NULL;
	}
	
	if (!(cpd = hpfs_map_sector(s, cpds, &bh, 0))) return NULL;
	if (le16_to_cpu(cpd->offs[cpi]) > 0x178) {
		pr_err("Code page index out of sector\n");
		brelse(bh);
		return NULL;
	}
	ptr = (unsigned char *)cpd + le16_to_cpu(cpd->offs[cpi]) + 6;
	if (!(cp_table = kmalloc(256, GFP_KERNEL))) {
		pr_err("out of memory for code page table\n");
		brelse(bh);
		return NULL;
	}
	memcpy(cp_table, ptr, 128);
	brelse(bh);

	/* Try to build lowercasing table from uppercasing one */

	for (i=128; i<256; i++) cp_table[i]=i;
	for (i=128; i<256; i++) if (cp_table[i-128]!=i && cp_table[i-128]>=128)
		cp_table[cp_table[i-128]] = i;
	
	return cp_table;
}

__le32 *hpfs_load_bitmap_directory(struct super_block *s, secno bmp)
{
	struct buffer_head *bh;
	int n = (hpfs_sb(s)->sb_fs_size + 0x200000 - 1) >> 21;
	int i;
	__le32 *b;
	if (!(b = kmalloc(n * 512, GFP_KERNEL))) {
		pr_err("can't allocate memory for bitmap directory\n");
		return NULL;
	}	
	for (i=0;i<n;i++) {
		__le32 *d = hpfs_map_sector(s, bmp+i, &bh, n - i - 1);
		if (!d) {
			kfree(b);
			return NULL;
		}
		memcpy((char *)b + 512 * i, d, 512);
		brelse(bh);
	}
	return b;
}

/*
 * Load fnode to memory
 */

struct fnode *hpfs_map_fnode(struct super_block *s, ino_t ino, struct buffer_head **bhp)
{
	struct fnode *fnode;
	if (hpfs_sb(s)->sb_chk) if (hpfs_chk_sectors(s, ino, 1, "fnode")) {
		return NULL;
	}
	if ((fnode = hpfs_map_sector(s, ino, bhp, FNODE_RD_AHEAD))) {
		if (hpfs_sb(s)->sb_chk) {
			struct extended_attribute *ea;
			struct extended_attribute *ea_end;
			if (le32_to_cpu(fnode->magic) != FNODE_MAGIC) {
				hpfs_error(s, "bad magic on fnode %08lx",
					(unsigned long)ino);
				goto bail;
			}
			if (!fnode_is_dir(fnode)) {
				if ((unsigned)fnode->btree.n_used_nodes + (unsigned)fnode->btree.n_free_nodes !=
				    (bp_internal(&fnode->btree) ? 12 : 8)) {
					hpfs_error(s,
					   "bad number of nodes in fnode %08lx",
					    (unsigned long)ino);
					goto bail;
				}
				if (le16_to_cpu(fnode->btree.first_free) !=
				    8 + fnode->btree.n_used_nodes * (bp_internal(&fnode->btree) ? 8 : 12)) {
					hpfs_error(s,
					    "bad first_free pointer in fnode %08lx",
					    (unsigned long)ino);
					goto bail;
				}
			}
			if (le16_to_cpu(fnode->ea_size_s) && (le16_to_cpu(fnode->ea_offs) < 0xc4 ||
			   le16_to_cpu(fnode->ea_offs) + le16_to_cpu(fnode->acl_size_s) + le16_to_cpu(fnode->ea_size_s) > 0x200)) {
				hpfs_error(s,
					"bad EA info in fnode %08lx: ea_offs == %04x ea_size_s == %04x",
					(unsigned long)ino,
					le16_to_cpu(fnode->ea_offs), le16_to_cpu(fnode->ea_size_s));
				goto bail;
			}
			ea = fnode_ea(fnode);
			ea_end = fnode_end_ea(fnode);
			while (ea != ea_end) {
				if (ea > ea_end) {
					hpfs_error(s, "bad EA in fnode %08lx",
						(unsigned long)ino);
					goto bail;
				}
				ea = next_ea(ea);
			}
		}
	}
	return fnode;
	bail:
	brelse(*bhp);
	return NULL;
}

struct anode *hpfs_map_anode(struct super_block *s, anode_secno ano, struct buffer_head **bhp)
{
	struct anode *anode;
	if (hpfs_sb(s)->sb_chk) if (hpfs_chk_sectors(s, ano, 1, "anode")) return NULL;
	if ((anode = hpfs_map_sector(s, ano, bhp, ANODE_RD_AHEAD)))
		if (hpfs_sb(s)->sb_chk) {
			if (le32_to_cpu(anode->magic) != ANODE_MAGIC) {
				hpfs_error(s, "bad magic on anode %08x", ano);
				goto bail;
			}
			if (le32_to_cpu(anode->self) != ano) {
				hpfs_error(s, "self pointer invalid on anode %08x", ano);
				goto bail;
			}
			if ((unsigned)anode->btree.n_used_nodes + (unsigned)anode->btree.n_free_nodes !=
			    (bp_internal(&anode->btree) ? 60 : 40)) {
				hpfs_error(s, "bad number of nodes in anode %08x", ano);
				goto bail;
			}
			if (le16_to_cpu(anode->btree.first_free) !=
			    8 + anode->btree.n_used_nodes * (bp_internal(&anode->btree) ? 8 : 12)) {
				hpfs_error(s, "bad first_free pointer in anode %08x", ano);
				goto bail;
			}
		}
	return anode;
	bail:
	brelse(*bhp);
	return NULL;
}

/*
 * Load dnode to memory and do some checks
 */

struct dnode *hpfs_map_dnode(struct super_block *s, unsigned secno,
			     struct quad_buffer_head *qbh)
{
	struct dnode *dnode;
	if (hpfs_sb(s)->sb_chk) {
		if (hpfs_chk_sectors(s, secno, 4, "dnode")) return NULL;
		if (secno & 3) {
			hpfs_error(s, "dnode %08x not byte-aligned", secno);
			return NULL;
		}	
	}
	if ((dnode = hpfs_map_4sectors(s, secno, qbh, DNODE_RD_AHEAD)))
		if (hpfs_sb(s)->sb_chk) {
			unsigned p, pp = 0;
			unsigned char *d = (unsigned char *)dnode;
			int b = 0;
			if (le32_to_cpu(dnode->magic) != DNODE_MAGIC) {
				hpfs_error(s, "bad magic on dnode %08x", secno);
				goto bail;
			}
			if (le32_to_cpu(dnode->self) != secno)
				hpfs_error(s, "bad self pointer on dnode %08x self = %08x", secno, le32_to_cpu(dnode->self));
			/* Check dirents - bad dirents would cause infinite
			   loops or shooting to memory */
			if (le32_to_cpu(dnode->first_free) > 2048) {
				hpfs_error(s, "dnode %08x has first_free == %08x", secno, le32_to_cpu(dnode->first_free));
				goto bail;
			}
			for (p = 20; p < le32_to_cpu(dnode->first_free); p += d[p] + (d[p+1] << 8)) {
				struct hpfs_dirent *de = (struct hpfs_dirent *)((char *)dnode + p);
				if (le16_to_cpu(de->length) > 292 || (le16_to_cpu(de->length) < 32) || (le16_to_cpu(de->length) & 3) || p + le16_to_cpu(de->length) > 2048) {
					hpfs_error(s, "bad dirent size in dnode %08x, dirent %03x, last %03x", secno, p, pp);
					goto bail;
				}
				if (((31 + de->namelen + de->down*4 + 3) & ~3) != le16_to_cpu(de->length)) {
					if (((31 + de->namelen + de->down*4 + 3) & ~3) < le16_to_cpu(de->length) && s->s_flags & MS_RDONLY) goto ok;
					hpfs_error(s, "namelen does not match dirent size in dnode %08x, dirent %03x, last %03x", secno, p, pp);
					goto bail;
				}
				ok:
				if (hpfs_sb(s)->sb_chk >= 2) b |= 1 << de->down;
				if (de->down) if (de_down_pointer(de) < 0x10) {
					hpfs_error(s, "bad down pointer in dnode %08x, dirent %03x, last %03x", secno, p, pp);
					goto bail;
				}
				pp = p;
				
			}
			if (p != le32_to_cpu(dnode->first_free)) {
				hpfs_error(s, "size on last dirent does not match first_free; dnode %08x", secno);
				goto bail;
			}
			if (d[pp + 30] != 1 || d[pp + 31] != 255) {
				hpfs_error(s, "dnode %08x does not end with \\377 entry", secno);
				goto bail;
			}
			if (b == 3)
				pr_err("unbalanced dnode tree, dnode %08x; see hpfs.txt 4 more info\n",
					secno);
		}
	return dnode;
	bail:
	hpfs_brelse4(qbh);
	return NULL;
}

dnode_secno hpfs_fnode_dno(struct super_block *s, ino_t ino)
{
	struct buffer_head *bh;
	struct fnode *fnode;
	dnode_secno dno;

	fnode = hpfs_map_fnode(s, ino, &bh);
	if (!fnode)
		return 0;

	dno = le32_to_cpu(fnode->u.external[0].disk_secno);
	brelse(bh);
	return dno;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/map.c */
/************************************************************/
/*
 *  linux/fs/hpfs/name.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  operations with filenames
 */

// #include "hpfs_fn.h"

static inline int not_allowed_char(unsigned char c)
{
	return c<' ' || c=='"' || c=='*' || c=='/' || c==':' || c=='<' ||
	      c=='>' || c=='?' || c=='\\' || c=='|';
}

static inline int no_dos_char(unsigned char c)
{	/* Characters that are allowed in HPFS but not in DOS */
	return c=='+' || c==',' || c==';' || c=='=' || c=='[' || c==']';
}

static inline unsigned char upcase(unsigned char *dir, unsigned char a)
{
	if (a<128 || a==255) return a>='a' && a<='z' ? a - 0x20 : a;
	if (!dir) return a;
	return dir[a-128];
}

unsigned char hpfs_upcase(unsigned char *dir, unsigned char a)
{
	return upcase(dir, a);
}

static inline unsigned char locase(unsigned char *dir, unsigned char a)
{
	if (a<128 || a==255) return a>='A' && a<='Z' ? a + 0x20 : a;
	if (!dir) return a;
	return dir[a];
}

int hpfs_chk_name(const unsigned char *name, unsigned *len)
{
	int i;
	if (*len > 254) return -ENAMETOOLONG;
	hpfs_adjust_length(name, len);
	if (!*len) return -EINVAL;
	for (i = 0; i < *len; i++) if (not_allowed_char(name[i])) return -EINVAL;
	if (*len == 1) if (name[0] == '.') return -EINVAL;
	if (*len == 2) if (name[0] == '.' && name[1] == '.') return -EINVAL;
	return 0;
}

unsigned char *hpfs_translate_name(struct super_block *s, unsigned char *from,
			  unsigned len, int lc, int lng)
{
	unsigned char *to;
	int i;
	if (hpfs_sb(s)->sb_chk >= 2) if (hpfs_is_name_long(from, len) != lng) {
		pr_err("Long name flag mismatch - name ");
		for (i = 0; i < len; i++)
			pr_cont("%c", from[i]);
		pr_cont(" misidentified as %s.\n", lng ? "short" : "long");
		pr_err("It's nothing serious. It could happen because of bug in OS/2.\nSet checks=normal to disable this message.\n");
	}
	if (!lc) return from;
	if (!(to = kmalloc(len, GFP_KERNEL))) {
		pr_err("can't allocate memory for name conversion buffer\n");
		return from;
	}
	for (i = 0; i < len; i++) to[i] = locase(hpfs_sb(s)->sb_cp_table,from[i]);
	return to;
}

int hpfs_compare_names(struct super_block *s,
		       const unsigned char *n1, unsigned l1,
		       const unsigned char *n2, unsigned l2, int last)
{
	unsigned l = l1 < l2 ? l1 : l2;
	unsigned i;
	if (last) return -1;
	for (i = 0; i < l; i++) {
		unsigned char c1 = upcase(hpfs_sb(s)->sb_cp_table,n1[i]);
		unsigned char c2 = upcase(hpfs_sb(s)->sb_cp_table,n2[i]);
		if (c1 < c2) return -1;
		if (c1 > c2) return 1;
	}
	if (l1 < l2) return -1;
	if (l1 > l2) return 1;
	return 0;
}

int hpfs_is_name_long(const unsigned char *name, unsigned len)
{
	int i,j;
	for (i = 0; i < len && name[i] != '.'; i++)
		if (no_dos_char(name[i])) return 1;
	if (!i || i > 8) return 1;
	if (i == len) return 0;
	for (j = i + 1; j < len; j++)
		if (name[j] == '.' || no_dos_char(name[i])) return 1;
	return j - i > 4;
}

/* OS/2 clears dots and spaces at the end of file name, so we have to */

void hpfs_adjust_length(const unsigned char *name, unsigned *len)
{
	if (!*len) return;
	if (*len == 1 && name[0] == '.') return;
	if (*len == 2 && name[0] == '.' && name[1] == '.') return;
	while (*len && (name[*len - 1] == '.' || name[*len - 1] == ' '))
		(*len)--;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/name.c */
/************************************************************/
/*
 *  linux/fs/hpfs/namei.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  adding & removing files & directories
 */
// #include <linux/sched.h>
// #include "hpfs_fn.h"

static int hpfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	const unsigned char *name = dentry->d_name.name;
	unsigned len = dentry->d_name.len;
	struct quad_buffer_head qbh0;
	struct buffer_head *bh;
	struct hpfs_dirent *de;
	struct fnode *fnode;
	struct dnode *dnode;
	struct inode *result;
	fnode_secno fno;
	dnode_secno dno;
	int r;
	struct hpfs_dirent dee;
	int err;
	if ((err = hpfs_chk_name(name, &len))) return err==-ENOENT ? -EINVAL : err;
	hpfs_lock(dir->i_sb);
	err = -ENOSPC;
	fnode = hpfs_alloc_fnode(dir->i_sb, hpfs_i(dir)->i_dno, &fno, &bh);
	if (!fnode)
		goto bail;
	dnode = hpfs_alloc_dnode(dir->i_sb, fno, &dno, &qbh0);
	if (!dnode)
		goto bail1;
	memset(&dee, 0, sizeof dee);
	dee.directory = 1;
	if (!(mode & 0222)) dee.read_only = 1;
	/*dee.archive = 0;*/
	dee.hidden = name[0] == '.';
	dee.fnode = cpu_to_le32(fno);
	dee.creation_date = dee.write_date = dee.read_date = cpu_to_le32(gmt_to_local(dir->i_sb, get_seconds()));
	result = new_inode(dir->i_sb);
	if (!result)
		goto bail2;
	hpfs_init_inode(result);
	result->i_ino = fno;
	hpfs_i(result)->i_parent_dir = dir->i_ino;
	hpfs_i(result)->i_dno = dno;
	result->i_ctime.tv_sec = result->i_mtime.tv_sec = result->i_atime.tv_sec = local_to_gmt(dir->i_sb, le32_to_cpu(dee.creation_date));
	result->i_ctime.tv_nsec = 0; 
	result->i_mtime.tv_nsec = 0; 
	result->i_atime.tv_nsec = 0; 
	hpfs_i(result)->i_ea_size = 0;
	result->i_mode |= S_IFDIR;
	result->i_op = &hpfs_dir_iops;
	result->i_fop = &hpfs_dir_ops;
	result->i_blocks = 4;
	result->i_size = 2048;
	set_nlink(result, 2);
	if (dee.read_only)
		result->i_mode &= ~0222;

	r = hpfs_add_dirent(dir, name, len, &dee);
	if (r == 1)
		goto bail3;
	if (r == -1) {
		err = -EEXIST;
		goto bail3;
	}
	fnode->len = len;
	memcpy(fnode->name, name, len > 15 ? 15 : len);
	fnode->up = cpu_to_le32(dir->i_ino);
	fnode->flags |= FNODE_dir;
	fnode->btree.n_free_nodes = 7;
	fnode->btree.n_used_nodes = 1;
	fnode->btree.first_free = cpu_to_le16(0x14);
	fnode->u.external[0].disk_secno = cpu_to_le32(dno);
	fnode->u.external[0].file_secno = cpu_to_le32(-1);
	dnode->root_dnode = 1;
	dnode->up = cpu_to_le32(fno);
	de = hpfs_add_de(dir->i_sb, dnode, "\001\001", 2, 0);
	de->creation_date = de->write_date = de->read_date = cpu_to_le32(gmt_to_local(dir->i_sb, get_seconds()));
	if (!(mode & 0222)) de->read_only = 1;
	de->first = de->directory = 1;
	/*de->hidden = de->system = 0;*/
	de->fnode = cpu_to_le32(fno);
	mark_buffer_dirty(bh);
	brelse(bh);
	hpfs_mark_4buffers_dirty(&qbh0);
	hpfs_brelse4(&qbh0);
	inc_nlink(dir);
	insert_inode_hash(result);

	if (!uid_eq(result->i_uid, current_fsuid()) ||
	    !gid_eq(result->i_gid, current_fsgid()) ||
	    result->i_mode != (mode | S_IFDIR)) {
		result->i_uid = current_fsuid();
		result->i_gid = current_fsgid();
		result->i_mode = mode | S_IFDIR;
		hpfs_write_inode_nolock(result);
	}
	d_instantiate(dentry, result);
	hpfs_unlock(dir->i_sb);
	return 0;
bail3:
	iput(result);
bail2:
	hpfs_brelse4(&qbh0);
	hpfs_free_dnode(dir->i_sb, dno);
bail1:
	brelse(bh);
	hpfs_free_sectors(dir->i_sb, fno, 1);
bail:
	hpfs_unlock(dir->i_sb);
	return err;
}

static int hpfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	const unsigned char *name = dentry->d_name.name;
	unsigned len = dentry->d_name.len;
	struct inode *result = NULL;
	struct buffer_head *bh;
	struct fnode *fnode;
	fnode_secno fno;
	int r;
	struct hpfs_dirent dee;
	int err;
	if ((err = hpfs_chk_name(name, &len)))
		return err==-ENOENT ? -EINVAL : err;
	hpfs_lock(dir->i_sb);
	err = -ENOSPC;
	fnode = hpfs_alloc_fnode(dir->i_sb, hpfs_i(dir)->i_dno, &fno, &bh);
	if (!fnode)
		goto bail;
	memset(&dee, 0, sizeof dee);
	if (!(mode & 0222)) dee.read_only = 1;
	dee.archive = 1;
	dee.hidden = name[0] == '.';
	dee.fnode = cpu_to_le32(fno);
	dee.creation_date = dee.write_date = dee.read_date = cpu_to_le32(gmt_to_local(dir->i_sb, get_seconds()));

	result = new_inode(dir->i_sb);
	if (!result)
		goto bail1;
	
	hpfs_init_inode(result);
	result->i_ino = fno;
	result->i_mode |= S_IFREG;
	result->i_mode &= ~0111;
	result->i_op = &hpfs_file_iops;
	result->i_fop = &hpfs_file_ops;
	set_nlink(result, 1);
	hpfs_i(result)->i_parent_dir = dir->i_ino;
	result->i_ctime.tv_sec = result->i_mtime.tv_sec = result->i_atime.tv_sec = local_to_gmt(dir->i_sb, le32_to_cpu(dee.creation_date));
	result->i_ctime.tv_nsec = 0;
	result->i_mtime.tv_nsec = 0;
	result->i_atime.tv_nsec = 0;
	hpfs_i(result)->i_ea_size = 0;
	if (dee.read_only)
		result->i_mode &= ~0222;
	result->i_blocks = 1;
	result->i_size = 0;
	result->i_data.a_ops = &hpfs_aops;
	hpfs_i(result)->mmu_private = 0;

	r = hpfs_add_dirent(dir, name, len, &dee);
	if (r == 1)
		goto bail2;
	if (r == -1) {
		err = -EEXIST;
		goto bail2;
	}
	fnode->len = len;
	memcpy(fnode->name, name, len > 15 ? 15 : len);
	fnode->up = cpu_to_le32(dir->i_ino);
	mark_buffer_dirty(bh);
	brelse(bh);

	insert_inode_hash(result);

	if (!uid_eq(result->i_uid, current_fsuid()) ||
	    !gid_eq(result->i_gid, current_fsgid()) ||
	    result->i_mode != (mode | S_IFREG)) {
		result->i_uid = current_fsuid();
		result->i_gid = current_fsgid();
		result->i_mode = mode | S_IFREG;
		hpfs_write_inode_nolock(result);
	}
	d_instantiate(dentry, result);
	hpfs_unlock(dir->i_sb);
	return 0;

bail2:
	iput(result);
bail1:
	brelse(bh);
	hpfs_free_sectors(dir->i_sb, fno, 1);
bail:
	hpfs_unlock(dir->i_sb);
	return err;
}

static int hpfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	const unsigned char *name = dentry->d_name.name;
	unsigned len = dentry->d_name.len;
	struct buffer_head *bh;
	struct fnode *fnode;
	fnode_secno fno;
	int r;
	struct hpfs_dirent dee;
	struct inode *result = NULL;
	int err;
	if ((err = hpfs_chk_name(name, &len))) return err==-ENOENT ? -EINVAL : err;
	if (hpfs_sb(dir->i_sb)->sb_eas < 2) return -EPERM;
	if (!new_valid_dev(rdev))
		return -EINVAL;
	hpfs_lock(dir->i_sb);
	err = -ENOSPC;
	fnode = hpfs_alloc_fnode(dir->i_sb, hpfs_i(dir)->i_dno, &fno, &bh);
	if (!fnode)
		goto bail;
	memset(&dee, 0, sizeof dee);
	if (!(mode & 0222)) dee.read_only = 1;
	dee.archive = 1;
	dee.hidden = name[0] == '.';
	dee.fnode = cpu_to_le32(fno);
	dee.creation_date = dee.write_date = dee.read_date = cpu_to_le32(gmt_to_local(dir->i_sb, get_seconds()));

	result = new_inode(dir->i_sb);
	if (!result)
		goto bail1;

	hpfs_init_inode(result);
	result->i_ino = fno;
	hpfs_i(result)->i_parent_dir = dir->i_ino;
	result->i_ctime.tv_sec = result->i_mtime.tv_sec = result->i_atime.tv_sec = local_to_gmt(dir->i_sb, le32_to_cpu(dee.creation_date));
	result->i_ctime.tv_nsec = 0;
	result->i_mtime.tv_nsec = 0;
	result->i_atime.tv_nsec = 0;
	hpfs_i(result)->i_ea_size = 0;
	result->i_uid = current_fsuid();
	result->i_gid = current_fsgid();
	set_nlink(result, 1);
	result->i_size = 0;
	result->i_blocks = 1;
	init_special_inode(result, mode, rdev);

	r = hpfs_add_dirent(dir, name, len, &dee);
	if (r == 1)
		goto bail2;
	if (r == -1) {
		err = -EEXIST;
		goto bail2;
	}
	fnode->len = len;
	memcpy(fnode->name, name, len > 15 ? 15 : len);
	fnode->up = cpu_to_le32(dir->i_ino);
	mark_buffer_dirty(bh);

	insert_inode_hash(result);

	hpfs_write_inode_nolock(result);
	d_instantiate(dentry, result);
	brelse(bh);
	hpfs_unlock(dir->i_sb);
	return 0;
bail2:
	iput(result);
bail1:
	brelse(bh);
	hpfs_free_sectors(dir->i_sb, fno, 1);
bail:
	hpfs_unlock(dir->i_sb);
	return err;
}

static int hpfs_symlink(struct inode *dir, struct dentry *dentry, const char *symlink)
{
	const unsigned char *name = dentry->d_name.name;
	unsigned len = dentry->d_name.len;
	struct buffer_head *bh;
	struct fnode *fnode;
	fnode_secno fno;
	int r;
	struct hpfs_dirent dee;
	struct inode *result;
	int err;
	if ((err = hpfs_chk_name(name, &len))) return err==-ENOENT ? -EINVAL : err;
	hpfs_lock(dir->i_sb);
	if (hpfs_sb(dir->i_sb)->sb_eas < 2) {
		hpfs_unlock(dir->i_sb);
		return -EPERM;
	}
	err = -ENOSPC;
	fnode = hpfs_alloc_fnode(dir->i_sb, hpfs_i(dir)->i_dno, &fno, &bh);
	if (!fnode)
		goto bail;
	memset(&dee, 0, sizeof dee);
	dee.archive = 1;
	dee.hidden = name[0] == '.';
	dee.fnode = cpu_to_le32(fno);
	dee.creation_date = dee.write_date = dee.read_date = cpu_to_le32(gmt_to_local(dir->i_sb, get_seconds()));

	result = new_inode(dir->i_sb);
	if (!result)
		goto bail1;
	result->i_ino = fno;
	hpfs_init_inode(result);
	hpfs_i(result)->i_parent_dir = dir->i_ino;
	result->i_ctime.tv_sec = result->i_mtime.tv_sec = result->i_atime.tv_sec = local_to_gmt(dir->i_sb, le32_to_cpu(dee.creation_date));
	result->i_ctime.tv_nsec = 0;
	result->i_mtime.tv_nsec = 0;
	result->i_atime.tv_nsec = 0;
	hpfs_i(result)->i_ea_size = 0;
	result->i_mode = S_IFLNK | 0777;
	result->i_uid = current_fsuid();
	result->i_gid = current_fsgid();
	result->i_blocks = 1;
	set_nlink(result, 1);
	result->i_size = strlen(symlink);
	result->i_op = &page_symlink_inode_operations;
	result->i_data.a_ops = &hpfs_symlink_aops;

	r = hpfs_add_dirent(dir, name, len, &dee);
	if (r == 1)
		goto bail2;
	if (r == -1) {
		err = -EEXIST;
		goto bail2;
	}
	fnode->len = len;
	memcpy(fnode->name, name, len > 15 ? 15 : len);
	fnode->up = cpu_to_le32(dir->i_ino);
	hpfs_set_ea(result, fnode, "SYMLINK", symlink, strlen(symlink));
	mark_buffer_dirty(bh);
	brelse(bh);

	insert_inode_hash(result);

	hpfs_write_inode_nolock(result);
	d_instantiate(dentry, result);
	hpfs_unlock(dir->i_sb);
	return 0;
bail2:
	iput(result);
bail1:
	brelse(bh);
	hpfs_free_sectors(dir->i_sb, fno, 1);
bail:
	hpfs_unlock(dir->i_sb);
	return err;
}

static int hpfs_unlink(struct inode *dir, struct dentry *dentry)
{
	const unsigned char *name = dentry->d_name.name;
	unsigned len = dentry->d_name.len;
	struct quad_buffer_head qbh;
	struct hpfs_dirent *de;
	struct inode *inode = dentry->d_inode;
	dnode_secno dno;
	int r;
	int rep = 0;
	int err;

	hpfs_lock(dir->i_sb);
	hpfs_adjust_length(name, &len);
again:
	err = -ENOENT;
	de = map_dirent(dir, hpfs_i(dir)->i_dno, name, len, &dno, &qbh);
	if (!de)
		goto out;

	err = -EPERM;
	if (de->first)
		goto out1;

	err = -EISDIR;
	if (de->directory)
		goto out1;

	r = hpfs_remove_dirent(dir, dno, de, &qbh, 1);
	switch (r) {
	case 1:
		hpfs_error(dir->i_sb, "there was error when removing dirent");
		err = -EFSERROR;
		break;
	case 2:		/* no space for deleting, try to truncate file */

		err = -ENOSPC;
		if (rep++)
			break;

		dentry_unhash(dentry);
		if (!d_unhashed(dentry)) {
			hpfs_unlock(dir->i_sb);
			return -ENOSPC;
		}
		if (generic_permission(inode, MAY_WRITE) ||
		    !S_ISREG(inode->i_mode) ||
		    get_write_access(inode)) {
			d_rehash(dentry);
		} else {
			struct iattr newattrs;
			/*pr_info("truncating file before delete.\n");*/
			newattrs.ia_size = 0;
			newattrs.ia_valid = ATTR_SIZE | ATTR_CTIME;
			err = notify_change(dentry, &newattrs, NULL);
			put_write_access(inode);
			if (!err)
				goto again;
		}
		hpfs_unlock(dir->i_sb);
		return -ENOSPC;
	default:
		drop_nlink(inode);
		err = 0;
	}
	goto out;

out1:
	hpfs_brelse4(&qbh);
out:
	hpfs_unlock(dir->i_sb);
	return err;
}

static int hpfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	const unsigned char *name = dentry->d_name.name;
	unsigned len = dentry->d_name.len;
	struct quad_buffer_head qbh;
	struct hpfs_dirent *de;
	struct inode *inode = dentry->d_inode;
	dnode_secno dno;
	int n_items = 0;
	int err;
	int r;

	hpfs_adjust_length(name, &len);
	hpfs_lock(dir->i_sb);
	err = -ENOENT;
	de = map_dirent(dir, hpfs_i(dir)->i_dno, name, len, &dno, &qbh);
	if (!de)
		goto out;

	err = -EPERM;
	if (de->first)
		goto out1;

	err = -ENOTDIR;
	if (!de->directory)
		goto out1;

	hpfs_count_dnodes(dir->i_sb, hpfs_i(inode)->i_dno, NULL, NULL, &n_items);
	err = -ENOTEMPTY;
	if (n_items)
		goto out1;

	r = hpfs_remove_dirent(dir, dno, de, &qbh, 1);
	switch (r) {
	case 1:
		hpfs_error(dir->i_sb, "there was error when removing dirent");
		err = -EFSERROR;
		break;
	case 2:
		err = -ENOSPC;
		break;
	default:
		drop_nlink(dir);
		clear_nlink(inode);
		err = 0;
	}
	goto out;
out1:
	hpfs_brelse4(&qbh);
out:
	hpfs_unlock(dir->i_sb);
	return err;
}

static int hpfs_symlink_readpage(struct file *file, struct page *page)
{
	char *link = kmap(page);
	struct inode *i = page->mapping->host;
	struct fnode *fnode;
	struct buffer_head *bh;
	int err;

	err = -EIO;
	hpfs_lock(i->i_sb);
	if (!(fnode = hpfs_map_fnode(i->i_sb, i->i_ino, &bh)))
		goto fail;
	err = hpfs_read_ea(i->i_sb, fnode, "SYMLINK", link, PAGE_SIZE);
	brelse(bh);
	if (err)
		goto fail;
	hpfs_unlock(i->i_sb);
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;

fail:
	hpfs_unlock(i->i_sb);
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	return err;
}

const struct address_space_operations hpfs_symlink_aops = {
	.readpage	= hpfs_symlink_readpage
};
	
static int hpfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		struct inode *new_dir, struct dentry *new_dentry)
{
	const unsigned char *old_name = old_dentry->d_name.name;
	unsigned old_len = old_dentry->d_name.len;
	const unsigned char *new_name = new_dentry->d_name.name;
	unsigned new_len = new_dentry->d_name.len;
	struct inode *i = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct quad_buffer_head qbh, qbh1;
	struct hpfs_dirent *dep, *nde;
	struct hpfs_dirent de;
	dnode_secno dno;
	int r;
	struct buffer_head *bh;
	struct fnode *fnode;
	int err;

	if ((err = hpfs_chk_name(new_name, &new_len))) return err;
	err = 0;
	hpfs_adjust_length(old_name, &old_len);

	hpfs_lock(i->i_sb);
	/* order doesn't matter, due to VFS exclusion */
	
	/* Erm? Moving over the empty non-busy directory is perfectly legal */
	if (new_inode && S_ISDIR(new_inode->i_mode)) {
		err = -EINVAL;
		goto end1;
	}

	if (!(dep = map_dirent(old_dir, hpfs_i(old_dir)->i_dno, old_name, old_len, &dno, &qbh))) {
		hpfs_error(i->i_sb, "lookup succeeded but map dirent failed");
		err = -ENOENT;
		goto end1;
	}
	copy_de(&de, dep);
	de.hidden = new_name[0] == '.';

	if (new_inode) {
		int r;
		if ((r = hpfs_remove_dirent(old_dir, dno, dep, &qbh, 1)) != 2) {
			if ((nde = map_dirent(new_dir, hpfs_i(new_dir)->i_dno, new_name, new_len, NULL, &qbh1))) {
				clear_nlink(new_inode);
				copy_de(nde, &de);
				memcpy(nde->name, new_name, new_len);
				hpfs_mark_4buffers_dirty(&qbh1);
				hpfs_brelse4(&qbh1);
				goto end;
			}
			hpfs_error(new_dir->i_sb, "hpfs_rename: could not find dirent");
			err = -EFSERROR;
			goto end1;
		}
		err = r == 2 ? -ENOSPC : r == 1 ? -EFSERROR : 0;
		goto end1;
	}

	if (new_dir == old_dir) hpfs_brelse4(&qbh);

	if ((r = hpfs_add_dirent(new_dir, new_name, new_len, &de))) {
		if (r == -1) hpfs_error(new_dir->i_sb, "hpfs_rename: dirent already exists!");
		err = r == 1 ? -ENOSPC : -EFSERROR;
		if (new_dir != old_dir) hpfs_brelse4(&qbh);
		goto end1;
	}
	
	if (new_dir == old_dir)
		if (!(dep = map_dirent(old_dir, hpfs_i(old_dir)->i_dno, old_name, old_len, &dno, &qbh))) {
			hpfs_error(i->i_sb, "lookup succeeded but map dirent failed at #2");
			err = -ENOENT;
			goto end1;
		}

	if ((r = hpfs_remove_dirent(old_dir, dno, dep, &qbh, 0))) {
		hpfs_error(i->i_sb, "hpfs_rename: could not remove dirent");
		err = r == 2 ? -ENOSPC : -EFSERROR;
		goto end1;
	}

	end:
	hpfs_i(i)->i_parent_dir = new_dir->i_ino;
	if (S_ISDIR(i->i_mode)) {
		inc_nlink(new_dir);
		drop_nlink(old_dir);
	}
	if ((fnode = hpfs_map_fnode(i->i_sb, i->i_ino, &bh))) {
		fnode->up = cpu_to_le32(new_dir->i_ino);
		fnode->len = new_len;
		memcpy(fnode->name, new_name, new_len>15?15:new_len);
		if (new_len < 15) memset(&fnode->name[new_len], 0, 15 - new_len);
		mark_buffer_dirty(bh);
		brelse(bh);
	}
end1:
	hpfs_unlock(i->i_sb);
	return err;
}

const struct inode_operations hpfs_dir_iops =
{
	.create		= hpfs_create,
	.lookup		= hpfs_lookup,
	.unlink		= hpfs_unlink,
	.symlink	= hpfs_symlink,
	.mkdir		= hpfs_mkdir,
	.rmdir		= hpfs_rmdir,
	.mknod		= hpfs_mknod,
	.rename		= hpfs_rename,
	.setattr	= hpfs_setattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/namei.c */
/************************************************************/
/*
 *  linux/fs/hpfs/super.c
 *
 *  Mikulas Patocka (mikulas@artax.karlin.mff.cuni.cz), 1998-1999
 *
 *  mounting, unmounting, error handling
 */

// #include "hpfs_fn.h"
#include <linux/module.h>
#include <linux/parser.h>
#include <linux/init.h>
#include <linux/statfs.h>
#include <linux/magic.h>
// #include <linux/sched.h>
#include <linux/bitmap.h>
// #include <linux/slab.h>
#include "../../inc/__fss.h"

/* Mark the filesystem dirty, so that chkdsk checks it when os/2 booted */

static void mark_dirty(struct super_block *s, int remount)
{
	if (hpfs_sb(s)->sb_chkdsk && (remount || !(s->s_flags & MS_RDONLY))) {
		struct buffer_head *bh;
		struct hpfs_spare_block *sb;
		if ((sb = hpfs_map_sector(s, 17, &bh, 0))) {
			sb->dirty = 1;
			sb->old_wrote = 0;
			mark_buffer_dirty(bh);
			sync_dirty_buffer(bh);
			brelse(bh);
		}
	}
}

/* Mark the filesystem clean (mark it dirty for chkdsk if chkdsk==2 or if there
   were errors) */

static void unmark_dirty(struct super_block *s)
{
	struct buffer_head *bh;
	struct hpfs_spare_block *sb;
	if (s->s_flags & MS_RDONLY) return;
	sync_blockdev(s->s_bdev);
	if ((sb = hpfs_map_sector(s, 17, &bh, 0))) {
		sb->dirty = hpfs_sb(s)->sb_chkdsk > 1 - hpfs_sb(s)->sb_was_error;
		sb->old_wrote = hpfs_sb(s)->sb_chkdsk >= 2 && !hpfs_sb(s)->sb_was_error;
		mark_buffer_dirty(bh);
		sync_dirty_buffer(bh);
		brelse(bh);
	}
}

/* Filesystem error... */
static char err_buf[1024];

void hpfs_error(struct super_block *s, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsnprintf(err_buf, sizeof(err_buf), fmt, args);
	va_end(args);

	pr_err("filesystem error: %s", err_buf);
	if (!hpfs_sb(s)->sb_was_error) {
		if (hpfs_sb(s)->sb_err == 2) {
			pr_cont("; crashing the system because you wanted it\n");
			mark_dirty(s, 0);
			panic("HPFS panic");
		} else if (hpfs_sb(s)->sb_err == 1) {
			if (s->s_flags & MS_RDONLY)
				pr_cont("; already mounted read-only\n");
			else {
				pr_cont("; remounting read-only\n");
				mark_dirty(s, 0);
				s->s_flags |= MS_RDONLY;
			}
		} else if (s->s_flags & MS_RDONLY)
				pr_cont("; going on - but anything won't be destroyed because it's read-only\n");
		else
			pr_cont("; corrupted filesystem mounted read/write - your computer will explode within 20 seconds ... but you wanted it so!\n");
	} else
		pr_cont("\n");
	hpfs_sb(s)->sb_was_error = 1;
}

/* 
 * A little trick to detect cycles in many hpfs structures and don't let the
 * kernel crash on corrupted filesystem. When first called, set c2 to 0.
 *
 * BTW. chkdsk doesn't detect cycles correctly. When I had 2 lost directories
 * nested each in other, chkdsk locked up happilly.
 */

int hpfs_stop_cycles(struct super_block *s, int key, int *c1, int *c2,
		char *msg)
{
	if (*c2 && *c1 == key) {
		hpfs_error(s, "cycle detected on key %08x in %s", key, msg);
		return 1;
	}
	(*c2)++;
	if (!((*c2 - 1) & *c2)) *c1 = key;
	return 0;
}

static void free_sbi(struct hpfs_sb_info *sbi)
{
	kfree(sbi->sb_cp_table);
	kfree(sbi->sb_bmp_dir);
	kfree(sbi);
}

static void lazy_free_sbi(struct rcu_head *rcu)
{
	free_sbi(container_of(rcu, struct hpfs_sb_info, rcu));
}

static void hpfs_put_super(struct super_block *s)
{
	hpfs_lock(s);
	unmark_dirty(s);
	hpfs_unlock(s);
	call_rcu(&hpfs_sb(s)->rcu, lazy_free_sbi);
}

static unsigned hpfs_count_one_bitmap(struct super_block *s, secno secno)
{
	struct quad_buffer_head qbh;
	unsigned long *bits;
	unsigned count;

	bits = hpfs_map_4sectors(s, secno, &qbh, 0);
	if (!bits)
		return (unsigned)-1;
	count = bitmap_weight(bits, 2048 * BITS_PER_BYTE);
	hpfs_brelse4(&qbh);
	return count;
}

static unsigned count_bitmaps(struct super_block *s)
{
	unsigned n, count, n_bands;
	n_bands = (hpfs_sb(s)->sb_fs_size + 0x3fff) >> 14;
	count = 0;
	for (n = 0; n < COUNT_RD_AHEAD; n++) {
		hpfs_prefetch_bitmap(s, n);
	}
	for (n = 0; n < n_bands; n++) {
		unsigned c;
		hpfs_prefetch_bitmap(s, n + COUNT_RD_AHEAD);
		c = hpfs_count_one_bitmap(s, le32_to_cpu(hpfs_sb(s)->sb_bmp_dir[n]));
		if (c != (unsigned)-1)
			count += c;
	}
	return count;
}

unsigned hpfs_get_free_dnodes(struct super_block *s)
{
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	if (sbi->sb_n_free_dnodes == (unsigned)-1) {
		unsigned c = hpfs_count_one_bitmap(s, sbi->sb_dmap);
		if (c == (unsigned)-1)
			return 0;
		sbi->sb_n_free_dnodes = c;
	}
	return sbi->sb_n_free_dnodes;
}

static int hpfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *s = dentry->d_sb;
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	u64 id = huge_encode_dev(s->s_bdev->bd_dev);

	hpfs_lock(s);

	if (sbi->sb_n_free == (unsigned)-1)
		sbi->sb_n_free = count_bitmaps(s);

	buf->f_type = s->s_magic;
	buf->f_bsize = 512;
	buf->f_blocks = sbi->sb_fs_size;
	buf->f_bfree = sbi->sb_n_free;
	buf->f_bavail = sbi->sb_n_free;
	buf->f_files = sbi->sb_dirband_size / 4;
	buf->f_ffree = hpfs_get_free_dnodes(s);
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = 254;

	hpfs_unlock(s);

	return 0;
}

static struct kmem_cache * hpfs_inode_cachep;

static struct inode *hpfs_alloc_inode(struct super_block *sb)
{
	struct hpfs_inode_info *ei;
	ei = (struct hpfs_inode_info *)kmem_cache_alloc(hpfs_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;
	ei->vfs_inode.i_version = 1;
	return &ei->vfs_inode;
}

static void hpfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(hpfs_inode_cachep, hpfs_i(inode));
}

static void hpfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, hpfs_i_callback);
}

static void init_once(void *foo)
{
	struct hpfs_inode_info *ei = (struct hpfs_inode_info *) foo;

	inode_init_once(&ei->vfs_inode);
}

static int init_inodecache(void)
{
	hpfs_inode_cachep = kmem_cache_create("hpfs_inode_cache",
					     sizeof(struct hpfs_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (hpfs_inode_cachep == NULL)
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
	kmem_cache_destroy(hpfs_inode_cachep);
}

/*
 * A tiny parser for option strings, stolen from dosfs.
 * Stolen again from read-only hpfs.
 * And updated for table-driven option parsing.
 */

enum {
	Opt_help, Opt_uid, Opt_gid, Opt_umask, Opt_case_lower, Opt_case_asis,
	Opt_check_none, Opt_check_normal, Opt_check_strict,
	Opt_err_cont, Opt_err_ro, Opt_err_panic,
	Opt_eas_no, Opt_eas_ro, Opt_eas_rw,
	Opt_chkdsk_no, Opt_chkdsk_errors, Opt_chkdsk_always,
	Opt_timeshift, Opt_err,
};

static const match_table_t tokens = {
	{Opt_help, "help"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_umask, "umask=%o"},
	{Opt_case_lower, "case=lower"},
	{Opt_case_asis, "case=asis"},
	{Opt_check_none, "check=none"},
	{Opt_check_normal, "check=normal"},
	{Opt_check_strict, "check=strict"},
	{Opt_err_cont, "errors=continue"},
	{Opt_err_ro, "errors=remount-ro"},
	{Opt_err_panic, "errors=panic"},
	{Opt_eas_no, "eas=no"},
	{Opt_eas_ro, "eas=ro"},
	{Opt_eas_rw, "eas=rw"},
	{Opt_chkdsk_no, "chkdsk=no"},
	{Opt_chkdsk_errors, "chkdsk=errors"},
	{Opt_chkdsk_always, "chkdsk=always"},
	{Opt_timeshift, "timeshift=%d"},
	{Opt_err, NULL},
};

static int parse_opts(char *opts, kuid_t *uid, kgid_t *gid, umode_t *umask,
		      int *lowercase, int *eas, int *chk, int *errs,
		      int *chkdsk, int *timeshift)
{
	char *p;
	int option;

	if (!opts)
		return 1;

	/*pr_info("Parsing opts: '%s'\n",opts);*/

	while ((p = strsep(&opts, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_help:
			return 2;
		case Opt_uid:
			if (match_int(args, &option))
				return 0;
			*uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(*uid))
				return 0;
			break;
		case Opt_gid:
			if (match_int(args, &option))
				return 0;
			*gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(*gid))
				return 0;
			break;
		case Opt_umask:
			if (match_octal(args, &option))
				return 0;
			*umask = option;
			break;
		case Opt_case_lower:
			*lowercase = 1;
			break;
		case Opt_case_asis:
			*lowercase = 0;
			break;
		case Opt_check_none:
			*chk = 0;
			break;
		case Opt_check_normal:
			*chk = 1;
			break;
		case Opt_check_strict:
			*chk = 2;
			break;
		case Opt_err_cont:
			*errs = 0;
			break;
		case Opt_err_ro:
			*errs = 1;
			break;
		case Opt_err_panic:
			*errs = 2;
			break;
		case Opt_eas_no:
			*eas = 0;
			break;
		case Opt_eas_ro:
			*eas = 1;
			break;
		case Opt_eas_rw:
			*eas = 2;
			break;
		case Opt_chkdsk_no:
			*chkdsk = 0;
			break;
		case Opt_chkdsk_errors:
			*chkdsk = 1;
			break;
		case Opt_chkdsk_always:
			*chkdsk = 2;
			break;
		case Opt_timeshift:
		{
			int m = 1;
			char *rhs = args[0].from;
			if (!rhs || !*rhs)
				return 0;
			if (*rhs == '-') m = -1;
			if (*rhs == '+' || *rhs == '-') rhs++;
			*timeshift = simple_strtoul(rhs, &rhs, 0) * m;
			if (*rhs)
				return 0;
			break;
		}
		default:
			return 0;
		}
	}
	return 1;
}

static inline void hpfs_help(void)
{
	pr_info("\n\
HPFS filesystem options:\n\
      help              do not mount and display this text\n\
      uid=xxx           set uid of files that don't have uid specified in eas\n\
      gid=xxx           set gid of files that don't have gid specified in eas\n\
      umask=xxx         set mode of files that don't have mode specified in eas\n\
      case=lower        lowercase all files\n\
      case=asis         do not lowercase files (default)\n\
      check=none        no fs checks - kernel may crash on corrupted filesystem\n\
      check=normal      do some checks - it should not crash (default)\n\
      check=strict      do extra time-consuming checks, used for debugging\n\
      errors=continue   continue on errors\n\
      errors=remount-ro remount read-only if errors found (default)\n\
      errors=panic      panic on errors\n\
      chkdsk=no         do not mark fs for chkdsking even if there were errors\n\
      chkdsk=errors     mark fs dirty if errors found (default)\n\
      chkdsk=always     always mark fs dirty - used for debugging\n\
      eas=no            ignore extended attributes\n\
      eas=ro            read but do not write extended attributes\n\
      eas=rw            r/w eas => enables chmod, chown, mknod, ln -s (default)\n\
      timeshift=nnn	add nnn seconds to file times\n\
\n");
}

static int hpfs_remount_fs(struct super_block *s, int *flags, char *data)
{
	kuid_t uid;
	kgid_t gid;
	umode_t umask;
	int lowercase, eas, chk, errs, chkdsk, timeshift;
	int o;
	struct hpfs_sb_info *sbi = hpfs_sb(s);
	char *new_opts = kstrdup(data, GFP_KERNEL);
	
	sync_filesystem(s);

	*flags |= MS_NOATIME;
	
	hpfs_lock(s);
	uid = sbi->sb_uid; gid = sbi->sb_gid;
	umask = 0777 & ~sbi->sb_mode;
	lowercase = sbi->sb_lowercase;
	eas = sbi->sb_eas; chk = sbi->sb_chk; chkdsk = sbi->sb_chkdsk;
	errs = sbi->sb_err; timeshift = sbi->sb_timeshift;

	if (!(o = parse_opts(data, &uid, &gid, &umask, &lowercase,
	    &eas, &chk, &errs, &chkdsk, &timeshift))) {
		pr_err("bad mount options.\n");
		goto out_err;
	}
	if (o == 2) {
		hpfs_help();
		goto out_err;
	}
	if (timeshift != sbi->sb_timeshift) {
		pr_err("timeshift can't be changed using remount.\n");
		goto out_err;
	}

	unmark_dirty(s);

	sbi->sb_uid = uid; sbi->sb_gid = gid;
	sbi->sb_mode = 0777 & ~umask;
	sbi->sb_lowercase = lowercase;
	sbi->sb_eas = eas; sbi->sb_chk = chk; sbi->sb_chkdsk = chkdsk;
	sbi->sb_err = errs; sbi->sb_timeshift = timeshift;

	if (!(*flags & MS_RDONLY)) mark_dirty(s, 1);

	replace_mount_options(s, new_opts);

	hpfs_unlock(s);
	return 0;

out_err:
	hpfs_unlock(s);
	kfree(new_opts);
	return -EINVAL;
}

/* Super operations */

static const struct super_operations hpfs_sops =
{
	.alloc_inode	= hpfs_alloc_inode,
	.destroy_inode	= hpfs_destroy_inode,
	.evict_inode	= hpfs_evict_inode,
	.put_super	= hpfs_put_super,
	.statfs		= hpfs_statfs,
	.remount_fs	= hpfs_remount_fs,
	.show_options	= generic_show_options,
};

static int hpfs_fill_super(struct super_block *s, void *options, int silent)
{
	struct buffer_head *bh0, *bh1, *bh2;
	struct hpfs_boot_block *bootblock;
	struct hpfs_super_block *superblock;
	struct hpfs_spare_block *spareblock;
	struct hpfs_sb_info *sbi;
	struct inode *root;

	kuid_t uid;
	kgid_t gid;
	umode_t umask;
	int lowercase, eas, chk, errs, chkdsk, timeshift;

	dnode_secno root_dno;
	struct hpfs_dirent *de = NULL;
	struct quad_buffer_head qbh;

	int o;

	save_mount_options(s, options);

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi) {
		return -ENOMEM;
	}
	s->s_fs_info = sbi;

	mutex_init(&sbi->hpfs_mutex);
	hpfs_lock(s);

	uid = current_uid();
	gid = current_gid();
	umask = current_umask();
	lowercase = 0;
	eas = 2;
	chk = 1;
	errs = 1;
	chkdsk = 1;
	timeshift = 0;

	if (!(o = parse_opts(options, &uid, &gid, &umask, &lowercase,
	    &eas, &chk, &errs, &chkdsk, &timeshift))) {
		pr_err("bad mount options.\n");
		goto bail0;
	}
	if (o==2) {
		hpfs_help();
		goto bail0;
	}

	/*sbi->sb_mounting = 1;*/
	sb_set_blocksize(s, 512);
	sbi->sb_fs_size = -1;
	if (!(bootblock = hpfs_map_sector(s, 0, &bh0, 0))) goto bail1;
	if (!(superblock = hpfs_map_sector(s, 16, &bh1, 1))) goto bail2;
	if (!(spareblock = hpfs_map_sector(s, 17, &bh2, 0))) goto bail3;

	/* Check magics */
	if (/*le16_to_cpu(bootblock->magic) != BB_MAGIC
	    ||*/ le32_to_cpu(superblock->magic) != SB_MAGIC
	    || le32_to_cpu(spareblock->magic) != SP_MAGIC) {
		if (!silent)
			pr_err("Bad magic ... probably not HPFS\n");
		goto bail4;
	}

	/* Check version */
	if (!(s->s_flags & MS_RDONLY) &&
	      superblock->funcversion != 2 && superblock->funcversion != 3) {
		pr_err("Bad version %d,%d. Mount readonly to go around\n",
			(int)superblock->version, (int)superblock->funcversion);
		pr_err("please try recent version of HPFS driver at http://artax.karlin.mff.cuni.cz/~mikulas/vyplody/hpfs/index-e.cgi and if it still can't understand this format, contact author - mikulas@artax.karlin.mff.cuni.cz\n");
		goto bail4;
	}

	s->s_flags |= MS_NOATIME;

	/* Fill superblock stuff */
	s->s_magic = HPFS_SUPER_MAGIC;
	s->s_op = &hpfs_sops;
	s->s_d_op = &hpfs_dentry_operations;

	sbi->sb_root = le32_to_cpu(superblock->root);
	sbi->sb_fs_size = le32_to_cpu(superblock->n_sectors);
	sbi->sb_bitmaps = le32_to_cpu(superblock->bitmaps);
	sbi->sb_dirband_start = le32_to_cpu(superblock->dir_band_start);
	sbi->sb_dirband_size = le32_to_cpu(superblock->n_dir_band);
	sbi->sb_dmap = le32_to_cpu(superblock->dir_band_bitmap);
	sbi->sb_uid = uid;
	sbi->sb_gid = gid;
	sbi->sb_mode = 0777 & ~umask;
	sbi->sb_n_free = -1;
	sbi->sb_n_free_dnodes = -1;
	sbi->sb_lowercase = lowercase;
	sbi->sb_eas = eas;
	sbi->sb_chk = chk;
	sbi->sb_chkdsk = chkdsk;
	sbi->sb_err = errs;
	sbi->sb_timeshift = timeshift;
	sbi->sb_was_error = 0;
	sbi->sb_cp_table = NULL;
	sbi->sb_c_bitmap = -1;
	sbi->sb_max_fwd_alloc = 0xffffff;

	if (sbi->sb_fs_size >= 0x80000000) {
		hpfs_error(s, "invalid size in superblock: %08x",
			(unsigned)sbi->sb_fs_size);
		goto bail4;
	}

	/* Load bitmap directory */
	if (!(sbi->sb_bmp_dir = hpfs_load_bitmap_directory(s, le32_to_cpu(superblock->bitmaps))))
		goto bail4;
	
	/* Check for general fs errors*/
	if (spareblock->dirty && !spareblock->old_wrote) {
		if (errs == 2) {
			pr_err("Improperly stopped, not mounted\n");
			goto bail4;
		}
		hpfs_error(s, "improperly stopped");
	}

	if (!(s->s_flags & MS_RDONLY)) {
		spareblock->dirty = 1;
		spareblock->old_wrote = 0;
		mark_buffer_dirty(bh2);
	}

	if (spareblock->hotfixes_used || spareblock->n_spares_used) {
		if (errs >= 2) {
			pr_err("Hotfixes not supported here, try chkdsk\n");
			mark_dirty(s, 0);
			goto bail4;
		}
		hpfs_error(s, "hotfixes not supported here, try chkdsk");
		if (errs == 0)
			pr_err("Proceeding, but your filesystem will be probably corrupted by this driver...\n");
		else
			pr_err("This driver may read bad files or crash when operating on disk with hotfixes.\n");
	}
	if (le32_to_cpu(spareblock->n_dnode_spares) != le32_to_cpu(spareblock->n_dnode_spares_free)) {
		if (errs >= 2) {
			pr_err("Spare dnodes used, try chkdsk\n");
			mark_dirty(s, 0);
			goto bail4;
		}
		hpfs_error(s, "warning: spare dnodes used, try chkdsk");
		if (errs == 0)
			pr_err("Proceeding, but your filesystem could be corrupted if you delete files or directories\n");
	}
	if (chk) {
		unsigned a;
		if (le32_to_cpu(superblock->dir_band_end) - le32_to_cpu(superblock->dir_band_start) + 1 != le32_to_cpu(superblock->n_dir_band) ||
		    le32_to_cpu(superblock->dir_band_end) < le32_to_cpu(superblock->dir_band_start) || le32_to_cpu(superblock->n_dir_band) > 0x4000) {
			hpfs_error(s, "dir band size mismatch: dir_band_start==%08x, dir_band_end==%08x, n_dir_band==%08x",
				le32_to_cpu(superblock->dir_band_start), le32_to_cpu(superblock->dir_band_end), le32_to_cpu(superblock->n_dir_band));
			goto bail4;
		}
		a = sbi->sb_dirband_size;
		sbi->sb_dirband_size = 0;
		if (hpfs_chk_sectors(s, le32_to_cpu(superblock->dir_band_start), le32_to_cpu(superblock->n_dir_band), "dir_band") ||
		    hpfs_chk_sectors(s, le32_to_cpu(superblock->dir_band_bitmap), 4, "dir_band_bitmap") ||
		    hpfs_chk_sectors(s, le32_to_cpu(superblock->bitmaps), 4, "bitmaps")) {
			mark_dirty(s, 0);
			goto bail4;
		}
		sbi->sb_dirband_size = a;
	} else
		pr_err("You really don't want any checks? You are crazy...\n");

	/* Load code page table */
	if (le32_to_cpu(spareblock->n_code_pages))
		if (!(sbi->sb_cp_table = hpfs_load_code_page(s, le32_to_cpu(spareblock->code_page_dir))))
			pr_err("code page support is disabled\n");

	brelse(bh2);
	brelse(bh1);
	brelse(bh0);

	root = iget_locked(s, sbi->sb_root);
	if (!root)
		goto bail0;
	hpfs_init_inode(root);
	hpfs_read_inode(root);
	unlock_new_inode(root);
	s->s_root = d_make_root(root);
	if (!s->s_root)
		goto bail0;

	/*
	 * find the root directory's . pointer & finish filling in the inode
	 */

	root_dno = hpfs_fnode_dno(s, sbi->sb_root);
	if (root_dno)
		de = map_dirent(root, root_dno, "\001\001", 2, NULL, &qbh);
	if (!de)
		hpfs_error(s, "unable to find root dir");
	else {
		root->i_atime.tv_sec = local_to_gmt(s, le32_to_cpu(de->read_date));
		root->i_atime.tv_nsec = 0;
		root->i_mtime.tv_sec = local_to_gmt(s, le32_to_cpu(de->write_date));
		root->i_mtime.tv_nsec = 0;
		root->i_ctime.tv_sec = local_to_gmt(s, le32_to_cpu(de->creation_date));
		root->i_ctime.tv_nsec = 0;
		hpfs_i(root)->i_ea_size = le32_to_cpu(de->ea_size);
		hpfs_i(root)->i_parent_dir = root->i_ino;
		if (root->i_size == -1)
			root->i_size = 2048;
		if (root->i_blocks == -1)
			root->i_blocks = 5;
		hpfs_brelse4(&qbh);
	}
	hpfs_unlock(s);
	return 0;

bail4:	brelse(bh2);
bail3:	brelse(bh1);
bail2:	brelse(bh0);
bail1:
bail0:
	hpfs_unlock(s);
	free_sbi(sbi);
	return -EINVAL;
}

static struct dentry *hpfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, hpfs_fill_super);
}

static struct file_system_type hpfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "hpfs",
	.mount		= hpfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("hpfs");

static int __init init_hpfs_fs(void)
{
	int err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&hpfs_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_hpfs_fs(void)
{
	unregister_filesystem(&hpfs_fs_type);
	destroy_inodecache();
}

module_init(init_hpfs_fs)
module_exit(exit_hpfs_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hpfs/super.c */
/************************************************************/
