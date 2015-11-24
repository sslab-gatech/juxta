/*
 *  linux/fs/fat/cache.c
 *
 *  Written 1992,1993 by Werner Almesberger
 *
 *  Mar 1999. AV. Changed cache, so that it uses the starting cluster instead
 *	of inode number.
 *  May 1999. AV. Fixed the bogosity with FAT32 (read "FAT28"). Fscking lusers.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/buffer_head.h>
#include "fat.h"

/* this must be > 0. */
#define FAT_MAX_CACHE	8

struct fat_cache {
	struct list_head cache_list;
	int nr_contig;	/* number of contiguous clusters */
	int fcluster;	/* cluster number in the file. */
	int dcluster;	/* cluster number on disk. */
};

struct fat_cache_id {
	unsigned int id;
	int nr_contig;
	int fcluster;
	int dcluster;
};

static inline int fat_max_cache(struct inode *inode)
{
	return FAT_MAX_CACHE;
}

static struct kmem_cache *fat_cache_cachep;

static void init_once(void *foo)
{
	struct fat_cache *cache = (struct fat_cache *)foo;

	INIT_LIST_HEAD(&cache->cache_list);
}

int __init fat_cache_init(void)
{
	fat_cache_cachep = kmem_cache_create("fat_cache",
				sizeof(struct fat_cache),
				0, SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD,
				init_once);
	if (fat_cache_cachep == NULL)
		return -ENOMEM;
	return 0;
}

void fat_cache_destroy(void)
{
	kmem_cache_destroy(fat_cache_cachep);
}

static inline struct fat_cache *fat_cache_alloc(struct inode *inode)
{
	return kmem_cache_alloc(fat_cache_cachep, GFP_NOFS);
}

static inline void fat_cache_free(struct fat_cache *cache)
{
	BUG_ON(!list_empty(&cache->cache_list));
	kmem_cache_free(fat_cache_cachep, cache);
}

static inline void fat_cache_update_lru(struct inode *inode,
					struct fat_cache *cache)
{
	if (MSDOS_I(inode)->cache_lru.next != &cache->cache_list)
		list_move(&cache->cache_list, &MSDOS_I(inode)->cache_lru);
}

static int fat_cache_lookup(struct inode *inode, int fclus,
			    struct fat_cache_id *cid,
			    int *cached_fclus, int *cached_dclus)
{
	static struct fat_cache nohit = { .fcluster = 0, };

	struct fat_cache *hit = &nohit, *p;
	int offset = -1;

	spin_lock(&MSDOS_I(inode)->cache_lru_lock);
	list_for_each_entry(p, &MSDOS_I(inode)->cache_lru, cache_list) {
		/* Find the cache of "fclus" or nearest cache. */
		if (p->fcluster <= fclus && hit->fcluster < p->fcluster) {
			hit = p;
			if ((hit->fcluster + hit->nr_contig) < fclus) {
				offset = hit->nr_contig;
			} else {
				offset = fclus - hit->fcluster;
				break;
			}
		}
	}
	if (hit != &nohit) {
		fat_cache_update_lru(inode, hit);

		cid->id = MSDOS_I(inode)->cache_valid_id;
		cid->nr_contig = hit->nr_contig;
		cid->fcluster = hit->fcluster;
		cid->dcluster = hit->dcluster;
		*cached_fclus = cid->fcluster + offset;
		*cached_dclus = cid->dcluster + offset;
	}
	spin_unlock(&MSDOS_I(inode)->cache_lru_lock);

	return offset;
}

static struct fat_cache *fat_cache_merge(struct inode *inode,
					 struct fat_cache_id *new)
{
	struct fat_cache *p;

	list_for_each_entry(p, &MSDOS_I(inode)->cache_lru, cache_list) {
		/* Find the same part as "new" in cluster-chain. */
		if (p->fcluster == new->fcluster) {
			BUG_ON(p->dcluster != new->dcluster);
			if (new->nr_contig > p->nr_contig)
				p->nr_contig = new->nr_contig;
			return p;
		}
	}
	return NULL;
}

static void fat_cache_add(struct inode *inode, struct fat_cache_id *new)
{
	struct fat_cache *cache, *tmp;

	if (new->fcluster == -1) /* dummy cache */
		return;

	spin_lock(&MSDOS_I(inode)->cache_lru_lock);
	if (new->id != FAT_CACHE_VALID &&
	    new->id != MSDOS_I(inode)->cache_valid_id)
		goto out;	/* this cache was invalidated */

	cache = fat_cache_merge(inode, new);
	if (cache == NULL) {
		if (MSDOS_I(inode)->nr_caches < fat_max_cache(inode)) {
			MSDOS_I(inode)->nr_caches++;
			spin_unlock(&MSDOS_I(inode)->cache_lru_lock);

			tmp = fat_cache_alloc(inode);
			if (!tmp) {
				spin_lock(&MSDOS_I(inode)->cache_lru_lock);
				MSDOS_I(inode)->nr_caches--;
				spin_unlock(&MSDOS_I(inode)->cache_lru_lock);
				return;
			}

			spin_lock(&MSDOS_I(inode)->cache_lru_lock);
			cache = fat_cache_merge(inode, new);
			if (cache != NULL) {
				MSDOS_I(inode)->nr_caches--;
				fat_cache_free(tmp);
				goto out_update_lru;
			}
			cache = tmp;
		} else {
			struct list_head *p = MSDOS_I(inode)->cache_lru.prev;
			cache = list_entry(p, struct fat_cache, cache_list);
		}
		cache->fcluster = new->fcluster;
		cache->dcluster = new->dcluster;
		cache->nr_contig = new->nr_contig;
	}
out_update_lru:
	fat_cache_update_lru(inode, cache);
out:
	spin_unlock(&MSDOS_I(inode)->cache_lru_lock);
}

/*
 * Cache invalidation occurs rarely, thus the LRU chain is not updated. It
 * fixes itself after a while.
 */
static void __fat_cache_inval_inode(struct inode *inode)
{
	struct msdos_inode_info *i = MSDOS_I(inode);
	struct fat_cache *cache;

	while (!list_empty(&i->cache_lru)) {
		cache = list_entry(i->cache_lru.next,
				   struct fat_cache, cache_list);
		list_del_init(&cache->cache_list);
		i->nr_caches--;
		fat_cache_free(cache);
	}
	/* Update. The copy of caches before this id is discarded. */
	i->cache_valid_id++;
	if (i->cache_valid_id == FAT_CACHE_VALID)
		i->cache_valid_id++;
}

void fat_cache_inval_inode(struct inode *inode)
{
	spin_lock(&MSDOS_I(inode)->cache_lru_lock);
	__fat_cache_inval_inode(inode);
	spin_unlock(&MSDOS_I(inode)->cache_lru_lock);
}

static inline int cache_contiguous(struct fat_cache_id *cid, int dclus)
{
	cid->nr_contig++;
	return ((cid->dcluster + cid->nr_contig) == dclus);
}

static inline void cache_init(struct fat_cache_id *cid, int fclus, int dclus)
{
	cid->id = FAT_CACHE_VALID;
	cid->fcluster = fclus;
	cid->dcluster = dclus;
	cid->nr_contig = 0;
}

int fat_get_cluster(struct inode *inode, int cluster, int *fclus, int *dclus)
{
	struct super_block *sb = inode->i_sb;
	const int limit = sb->s_maxbytes >> MSDOS_SB(sb)->cluster_bits;
	struct fat_entry fatent;
	struct fat_cache_id cid;
	int nr;

	BUG_ON(MSDOS_I(inode)->i_start == 0);

	*fclus = 0;
	*dclus = MSDOS_I(inode)->i_start;
	if (cluster == 0)
		return 0;

	if (fat_cache_lookup(inode, cluster, &cid, fclus, dclus) < 0) {
		/*
		 * dummy, always not contiguous
		 * This is reinitialized by cache_init(), later.
		 */
		cache_init(&cid, -1, -1);
	}

	fatent_init(&fatent);
	while (*fclus < cluster) {
		/* prevent the infinite loop of cluster chain */
		if (*fclus > limit) {
			fat_fs_error_ratelimit(sb,
					"%s: detected the cluster chain loop"
					" (i_pos %lld)", __func__,
					MSDOS_I(inode)->i_pos);
			nr = -EIO;
			goto out;
		}

		nr = fat_ent_read(inode, &fatent, *dclus);
		if (nr < 0)
			goto out;
		else if (nr == FAT_ENT_FREE) {
			fat_fs_error_ratelimit(sb,
				       "%s: invalid cluster chain (i_pos %lld)",
				       __func__,
				       MSDOS_I(inode)->i_pos);
			nr = -EIO;
			goto out;
		} else if (nr == FAT_ENT_EOF) {
			fat_cache_add(inode, &cid);
			goto out;
		}
		(*fclus)++;
		*dclus = nr;
		if (!cache_contiguous(&cid, *dclus))
			cache_init(&cid, *fclus, *dclus);
	}
	nr = 0;
	fat_cache_add(inode, &cid);
out:
	fatent_brelse(&fatent);
	return nr;
}

static int fat_bmap_cluster(struct inode *inode, int cluster)
{
	struct super_block *sb = inode->i_sb;
	int ret, fclus, dclus;

	if (MSDOS_I(inode)->i_start == 0)
		return 0;

	ret = fat_get_cluster(inode, cluster, &fclus, &dclus);
	if (ret < 0)
		return ret;
	else if (ret == FAT_ENT_EOF) {
		fat_fs_error(sb, "%s: request beyond EOF (i_pos %lld)",
			     __func__, MSDOS_I(inode)->i_pos);
		return -EIO;
	}
	return dclus;
}

int fat_bmap(struct inode *inode, sector_t sector, sector_t *phys,
	     unsigned long *mapped_blocks, int create)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	const unsigned long blocksize = sb->s_blocksize;
	const unsigned char blocksize_bits = sb->s_blocksize_bits;
	sector_t last_block;
	int cluster, offset;

	*phys = 0;
	*mapped_blocks = 0;
	if ((sbi->fat_bits != 32) && (inode->i_ino == MSDOS_ROOT_INO)) {
		if (sector < (sbi->dir_entries >> sbi->dir_per_block_bits)) {
			*phys = sector + sbi->dir_start;
			*mapped_blocks = 1;
		}
		return 0;
	}

	last_block = (i_size_read(inode) + (blocksize - 1)) >> blocksize_bits;
	if (sector >= last_block) {
		if (!create)
			return 0;

		/*
		 * ->mmu_private can access on only allocation path.
		 * (caller must hold ->i_mutex)
		 */
		last_block = (MSDOS_I(inode)->mmu_private + (blocksize - 1))
			>> blocksize_bits;
		if (sector >= last_block)
			return 0;
	}

	cluster = sector >> (sbi->cluster_bits - sb->s_blocksize_bits);
	offset  = sector & (sbi->sec_per_clus - 1);
	cluster = fat_bmap_cluster(inode, cluster);
	if (cluster < 0)
		return cluster;
	else if (cluster) {
		*phys = fat_clus_to_blknr(sbi, cluster) + offset;
		*mapped_blocks = sbi->sec_per_clus - offset;
		if (*mapped_blocks > last_block - sector)
			*mapped_blocks = last_block - sector;
	}
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/fat/cache.c */
/************************************************************/
/*
 *  linux/fs/fat/dir.c
 *
 *  directory handling functions for fat-based filesystems
 *
 *  Written 1992,1993 by Werner Almesberger
 *
 *  Hidden files 1995 by Albert Cahalan <albert@ccs.neu.edu> <adc@coe.neu.edu>
 *
 *  VFAT extensions by Gordon Chaffee <chaffee@plateau.cs.berkeley.edu>
 *  Merged with msdos fs by Henrik Storner <storner@osiris.ping.dk>
 *  Rewritten for constant inumbers. Plugged buffer overrun in readdir(). AV
 *  Short name translation 1999, 2001 by Wolfram Pienkoss <wp@bszh.de>
 */

#include <linux/module.h>
// #include <linux/slab.h>
#include <linux/time.h>
// #include <linux/buffer_head.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
// #include "fat.h"

/*
 * Maximum buffer size of short name.
 * [(MSDOS_NAME + '.') * max one char + nul]
 * For msdos style, ['.' (hidden) + MSDOS_NAME + '.' + nul]
 */
#define FAT_MAX_SHORT_SIZE	((MSDOS_NAME + 1) * NLS_MAX_CHARSET_SIZE + 1)
/*
 * Maximum buffer size of unicode chars from slots.
 * [(max longname slots * 13 (size in a slot) + nul) * sizeof(wchar_t)]
 */
#define FAT_MAX_UNI_CHARS	((MSDOS_SLOTS - 1) * 13 + 1)
#define FAT_MAX_UNI_SIZE	(FAT_MAX_UNI_CHARS * sizeof(wchar_t))

static inline unsigned char fat_tolower(unsigned char c)
{
	return ((c >= 'A') && (c <= 'Z')) ? c+32 : c;
}

static inline loff_t fat_make_i_pos(struct super_block *sb,
				    struct buffer_head *bh,
				    struct msdos_dir_entry *de)
{
	return ((loff_t)bh->b_blocknr << MSDOS_SB(sb)->dir_per_block_bits)
		| (de - (struct msdos_dir_entry *)bh->b_data);
}

static inline void fat_dir_readahead(struct inode *dir, sector_t iblock,
				     sector_t phys)
{
	struct super_block *sb = dir->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bh;
	int sec;

	/* This is not a first sector of cluster, or sec_per_clus == 1 */
	if ((iblock & (sbi->sec_per_clus - 1)) || sbi->sec_per_clus == 1)
		return;
	/* root dir of FAT12/FAT16 */
	if ((sbi->fat_bits != 32) && (dir->i_ino == MSDOS_ROOT_INO))
		return;

	bh = sb_find_get_block(sb, phys);
	if (bh == NULL || !buffer_uptodate(bh)) {
		for (sec = 0; sec < sbi->sec_per_clus; sec++)
			sb_breadahead(sb, phys + sec);
	}
	brelse(bh);
}

/* Returns the inode number of the directory entry at offset pos. If bh is
   non-NULL, it is brelse'd before. Pos is incremented. The buffer header is
   returned in bh.
   AV. Most often we do it item-by-item. Makes sense to optimize.
   AV. OK, there we go: if both bh and de are non-NULL we assume that we just
   AV. want the next entry (took one explicit de=NULL in vfat/namei.c).
   AV. It's done in fat_get_entry() (inlined), here the slow case lives.
   AV. Additionally, when we return -1 (i.e. reached the end of directory)
   AV. we make bh NULL.
 */
static int fat__get_entry(struct inode *dir, loff_t *pos,
			  struct buffer_head **bh, struct msdos_dir_entry **de)
{
	struct super_block *sb = dir->i_sb;
	sector_t phys, iblock;
	unsigned long mapped_blocks;
	int err, offset;

next:
	if (*bh)
		brelse(*bh);

	*bh = NULL;
	iblock = *pos >> sb->s_blocksize_bits;
	err = fat_bmap(dir, iblock, &phys, &mapped_blocks, 0);
	if (err || !phys)
		return -1;	/* beyond EOF or error */

	fat_dir_readahead(dir, iblock, phys);

	*bh = sb_bread(sb, phys);
	if (*bh == NULL) {
		fat_msg_ratelimit(sb, KERN_ERR,
			"Directory bread(block %llu) failed", (llu)phys);
		/* skip this block */
		*pos = (iblock + 1) << sb->s_blocksize_bits;
		goto next;
	}

	offset = *pos & (sb->s_blocksize - 1);
	*pos += sizeof(struct msdos_dir_entry);
	*de = (struct msdos_dir_entry *)((*bh)->b_data + offset);

	return 0;
}

static inline int fat_get_entry(struct inode *dir, loff_t *pos,
				struct buffer_head **bh,
				struct msdos_dir_entry **de)
{
	/* Fast stuff first */
	if (*bh && *de &&
	   (*de - (struct msdos_dir_entry *)(*bh)->b_data) <
				MSDOS_SB(dir->i_sb)->dir_per_block - 1) {
		*pos += sizeof(struct msdos_dir_entry);
		(*de)++;
		return 0;
	}
	return fat__get_entry(dir, pos, bh, de);
}

/*
 * Convert Unicode 16 to UTF-8, translated Unicode, or ASCII.
 * If uni_xlate is enabled and we can't get a 1:1 conversion, use a
 * colon as an escape character since it is normally invalid on the vfat
 * filesystem. The following four characters are the hexadecimal digits
 * of Unicode value. This lets us do a full dump and restore of Unicode
 * filenames. We could get into some trouble with long Unicode names,
 * but ignore that right now.
 * Ahem... Stack smashing in ring 0 isn't fun. Fixed.
 */
static int uni16_to_x8(struct super_block *sb, unsigned char *ascii,
		       const wchar_t *uni, int len, struct nls_table *nls)
{
	int uni_xlate = MSDOS_SB(sb)->options.unicode_xlate;
	const wchar_t *ip;
	wchar_t ec;
	unsigned char *op;
	int charlen;

	ip = uni;
	op = ascii;

	while (*ip && ((len - NLS_MAX_CHARSET_SIZE) > 0)) {
		ec = *ip++;
		charlen = nls->uni2char(ec, op, NLS_MAX_CHARSET_SIZE);
		if (charlen > 0) {
			op += charlen;
			len -= charlen;
		} else {
			if (uni_xlate == 1) {
				*op++ = ':';
				op = hex_byte_pack(op, ec >> 8);
				op = hex_byte_pack(op, ec);
				len -= 5;
			} else {
				*op++ = '?';
				len--;
			}
		}
	}

	if (unlikely(*ip)) {
		fat_msg(sb, KERN_WARNING,
			"filename was truncated while converting.");
	}

	*op = 0;
	return op - ascii;
}

static inline int fat_uni_to_x8(struct super_block *sb, const wchar_t *uni,
				unsigned char *buf, int size)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	if (sbi->options.utf8)
		return utf16s_to_utf8s(uni, FAT_MAX_UNI_CHARS,
				UTF16_HOST_ENDIAN, buf, size);
	else
		return uni16_to_x8(sb, buf, uni, size, sbi->nls_io);
}

static inline int
fat_short2uni(struct nls_table *t, unsigned char *c, int clen, wchar_t *uni)
{
	int charlen;

	charlen = t->char2uni(c, clen, uni);
	if (charlen < 0) {
		*uni = 0x003f;	/* a question mark */
		charlen = 1;
	}
	return charlen;
}

static inline int
fat_short2lower_uni(struct nls_table *t, unsigned char *c,
		    int clen, wchar_t *uni)
{
	int charlen;
	wchar_t wc;

	charlen = t->char2uni(c, clen, &wc);
	if (charlen < 0) {
		*uni = 0x003f;	/* a question mark */
		charlen = 1;
	} else if (charlen <= 1) {
		unsigned char nc = t->charset2lower[*c];

		if (!nc)
			nc = *c;

		charlen = t->char2uni(&nc, 1, uni);
		if (charlen < 0) {
			*uni = 0x003f;	/* a question mark */
			charlen = 1;
		}
	} else
		*uni = wc;

	return charlen;
}

static inline int
fat_shortname2uni(struct nls_table *nls, unsigned char *buf, int buf_size,
		  wchar_t *uni_buf, unsigned short opt, int lower)
{
	int len = 0;

	if (opt & VFAT_SFN_DISPLAY_LOWER)
		len =  fat_short2lower_uni(nls, buf, buf_size, uni_buf);
	else if (opt & VFAT_SFN_DISPLAY_WIN95)
		len = fat_short2uni(nls, buf, buf_size, uni_buf);
	else if (opt & VFAT_SFN_DISPLAY_WINNT) {
		if (lower)
			len = fat_short2lower_uni(nls, buf, buf_size, uni_buf);
		else
			len = fat_short2uni(nls, buf, buf_size, uni_buf);
	} else
		len = fat_short2uni(nls, buf, buf_size, uni_buf);

	return len;
}

static inline int fat_name_match(struct msdos_sb_info *sbi,
				 const unsigned char *a, int a_len,
				 const unsigned char *b, int b_len)
{
	if (a_len != b_len)
		return 0;

	if (sbi->options.name_check != 's')
		return !nls_strnicmp(sbi->nls_io, a, b, a_len);
	else
		return !memcmp(a, b, a_len);
}

enum { PARSE_INVALID = 1, PARSE_NOT_LONGNAME, PARSE_EOF, };

/**
 * fat_parse_long - Parse extended directory entry.
 *
 * This function returns zero on success, negative value on error, or one of
 * the following:
 *
 * %PARSE_INVALID - Directory entry is invalid.
 * %PARSE_NOT_LONGNAME - Directory entry does not contain longname.
 * %PARSE_EOF - Directory has no more entries.
 */
static int fat_parse_long(struct inode *dir, loff_t *pos,
			  struct buffer_head **bh, struct msdos_dir_entry **de,
			  wchar_t **unicode, unsigned char *nr_slots)
{
	struct msdos_dir_slot *ds;
	unsigned char id, slot, slots, alias_checksum;

	if (!*unicode) {
		*unicode = __getname();
		if (!*unicode) {
			brelse(*bh);
			return -ENOMEM;
		}
	}
parse_long:
	slots = 0;
	ds = (struct msdos_dir_slot *)*de;
	id = ds->id;
	if (!(id & 0x40))
		return PARSE_INVALID;
	slots = id & ~0x40;
	if (slots > 20 || !slots)	/* ceil(256 * 2 / 26) */
		return PARSE_INVALID;
	*nr_slots = slots;
	alias_checksum = ds->alias_checksum;

	slot = slots;
	while (1) {
		int offset;

		slot--;
		offset = slot * 13;
		fat16_towchar(*unicode + offset, ds->name0_4, 5);
		fat16_towchar(*unicode + offset + 5, ds->name5_10, 6);
		fat16_towchar(*unicode + offset + 11, ds->name11_12, 2);

		if (ds->id & 0x40)
			(*unicode)[offset + 13] = 0;
		if (fat_get_entry(dir, pos, bh, de) < 0)
			return PARSE_EOF;
		if (slot == 0)
			break;
		ds = (struct msdos_dir_slot *)*de;
		if (ds->attr != ATTR_EXT)
			return PARSE_NOT_LONGNAME;
		if ((ds->id & ~0x40) != slot)
			goto parse_long;
		if (ds->alias_checksum != alias_checksum)
			goto parse_long;
	}
	if ((*de)->name[0] == DELETED_FLAG)
		return PARSE_INVALID;
	if ((*de)->attr == ATTR_EXT)
		goto parse_long;
	if (IS_FREE((*de)->name) || ((*de)->attr & ATTR_VOLUME))
		return PARSE_INVALID;
	if (fat_checksum((*de)->name) != alias_checksum)
		*nr_slots = 0;

	return 0;
}

/**
 * fat_parse_short - Parse MS-DOS (short) directory entry.
 * @sb:		superblock
 * @de:		directory entry to parse
 * @name:	FAT_MAX_SHORT_SIZE array in which to place extracted name
 * @dot_hidden:	Nonzero == prepend '.' to names with ATTR_HIDDEN
 *
 * Returns the number of characters extracted into 'name'.
 */
static int fat_parse_short(struct super_block *sb,
			   const struct msdos_dir_entry *de,
			   unsigned char *name, int dot_hidden)
{
	const struct msdos_sb_info *sbi = MSDOS_SB(sb);
	int isvfat = sbi->options.isvfat;
	int nocase = sbi->options.nocase;
	unsigned short opt_shortname = sbi->options.shortname;
	struct nls_table *nls_disk = sbi->nls_disk;
	wchar_t uni_name[14];
	unsigned char c, work[MSDOS_NAME];
	unsigned char *ptname = name;
	int chi, chl, i, j, k;
	int dotoffset = 0;
	int name_len = 0, uni_len = 0;

	if (!isvfat && dot_hidden && (de->attr & ATTR_HIDDEN)) {
		*ptname++ = '.';
		dotoffset = 1;
	}

	memcpy(work, de->name, sizeof(work));
	/* see namei.c, msdos_format_name */
	if (work[0] == 0x05)
		work[0] = 0xE5;

	/* Filename */
	for (i = 0, j = 0; i < 8;) {
		c = work[i];
		if (!c)
			break;
		chl = fat_shortname2uni(nls_disk, &work[i], 8 - i,
					&uni_name[j++], opt_shortname,
					de->lcase & CASE_LOWER_BASE);
		if (chl <= 1) {
			if (!isvfat)
				ptname[i] = nocase ? c : fat_tolower(c);
			i++;
			if (c != ' ') {
				name_len = i;
				uni_len  = j;
			}
		} else {
			uni_len = j;
			if (isvfat)
				i += min(chl, 8-i);
			else {
				for (chi = 0; chi < chl && i < 8; chi++, i++)
					ptname[i] = work[i];
			}
			if (chl)
				name_len = i;
		}
	}

	i = name_len;
	j = uni_len;
	fat_short2uni(nls_disk, ".", 1, &uni_name[j++]);
	if (!isvfat)
		ptname[i] = '.';
	i++;

	/* Extension */
	for (k = 8; k < MSDOS_NAME;) {
		c = work[k];
		if (!c)
			break;
		chl = fat_shortname2uni(nls_disk, &work[k], MSDOS_NAME - k,
					&uni_name[j++], opt_shortname,
					de->lcase & CASE_LOWER_EXT);
		if (chl <= 1) {
			k++;
			if (!isvfat)
				ptname[i] = nocase ? c : fat_tolower(c);
			i++;
			if (c != ' ') {
				name_len = i;
				uni_len  = j;
			}
		} else {
			uni_len = j;
			if (isvfat) {
				int offset = min(chl, MSDOS_NAME-k);
				k += offset;
				i += offset;
			} else {
				for (chi = 0; chi < chl && k < MSDOS_NAME;
				     chi++, i++, k++) {
						ptname[i] = work[k];
				}
			}
			if (chl)
				name_len = i;
		}
	}

	if (name_len > 0) {
		name_len += dotoffset;

		if (sbi->options.isvfat) {
			uni_name[uni_len] = 0x0000;
			name_len = fat_uni_to_x8(sb, uni_name, name,
						 FAT_MAX_SHORT_SIZE);
		}
	}

	return name_len;
}

/*
 * Return values: negative -> error/not found, 0 -> found.
 */
int fat_search_long(struct inode *inode, const unsigned char *name,
		    int name_len, struct fat_slot_info *sinfo)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bh = NULL;
	struct msdos_dir_entry *de;
	unsigned char nr_slots;
	wchar_t *unicode = NULL;
	unsigned char bufname[FAT_MAX_SHORT_SIZE];
	loff_t cpos = 0;
	int err, len;

	err = -ENOENT;
	while (1) {
		if (fat_get_entry(inode, &cpos, &bh, &de) == -1)
			goto end_of_dir;
parse_record:
		nr_slots = 0;
		if (de->name[0] == DELETED_FLAG)
			continue;
		if (de->attr != ATTR_EXT && (de->attr & ATTR_VOLUME))
			continue;
		if (de->attr != ATTR_EXT && IS_FREE(de->name))
			continue;
		if (de->attr == ATTR_EXT) {
			int status = fat_parse_long(inode, &cpos, &bh, &de,
						    &unicode, &nr_slots);
			if (status < 0) {
				err = status;
				goto end_of_dir;
			} else if (status == PARSE_INVALID)
				continue;
			else if (status == PARSE_NOT_LONGNAME)
				goto parse_record;
			else if (status == PARSE_EOF)
				goto end_of_dir;
		}

		/* Never prepend '.' to hidden files here.
		 * That is done only for msdos mounts (and only when
		 * 'dotsOK=yes'); if we are executing here, it is in the
		 * context of a vfat mount.
		 */
		len = fat_parse_short(sb, de, bufname, 0);
		if (len == 0)
			continue;

		/* Compare shortname */
		if (fat_name_match(sbi, name, name_len, bufname, len))
			goto found;

		if (nr_slots) {
			void *longname = unicode + FAT_MAX_UNI_CHARS;
			int size = PATH_MAX - FAT_MAX_UNI_SIZE;

			/* Compare longname */
			len = fat_uni_to_x8(sb, unicode, longname, size);
			if (fat_name_match(sbi, name, name_len, longname, len))
				goto found;
		}
	}

found:
	nr_slots++;	/* include the de */
	sinfo->slot_off = cpos - nr_slots * sizeof(*de);
	sinfo->nr_slots = nr_slots;
	sinfo->de = de;
	sinfo->bh = bh;
	sinfo->i_pos = fat_make_i_pos(sb, sinfo->bh, sinfo->de);
	err = 0;
end_of_dir:
	if (unicode)
		__putname(unicode);

	return err;
}
EXPORT_SYMBOL_GPL(fat_search_long);

struct fat_ioctl_filldir_callback {
	struct dir_context ctx;
	void __user *dirent;
	int result;
	/* for dir ioctl */
	const char *longname;
	int long_len;
	const char *shortname;
	int short_len;
};

static int __fat_readdir(struct inode *inode, struct file *file,
			 struct dir_context *ctx, int short_only,
			 struct fat_ioctl_filldir_callback *both)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bh;
	struct msdos_dir_entry *de;
	unsigned char nr_slots;
	wchar_t *unicode = NULL;
	unsigned char bufname[FAT_MAX_SHORT_SIZE];
	int isvfat = sbi->options.isvfat;
	const char *fill_name = NULL;
	int fake_offset = 0;
	loff_t cpos;
	int short_len = 0, fill_len = 0;
	int ret = 0;

	mutex_lock(&sbi->s_lock);

	cpos = ctx->pos;
	/* Fake . and .. for the root directory. */
	if (inode->i_ino == MSDOS_ROOT_INO) {
		if (!dir_emit_dots(file, ctx))
			goto out;
		if (ctx->pos == 2) {
			fake_offset = 1;
			cpos = 0;
		}
	}
	if (cpos & (sizeof(struct msdos_dir_entry) - 1)) {
		ret = -ENOENT;
		goto out;
	}

	bh = NULL;
get_new:
	if (fat_get_entry(inode, &cpos, &bh, &de) == -1)
		goto end_of_dir;
parse_record:
	nr_slots = 0;
	/*
	 * Check for long filename entry, but if short_only, we don't
	 * need to parse long filename.
	 */
	if (isvfat && !short_only) {
		if (de->name[0] == DELETED_FLAG)
			goto record_end;
		if (de->attr != ATTR_EXT && (de->attr & ATTR_VOLUME))
			goto record_end;
		if (de->attr != ATTR_EXT && IS_FREE(de->name))
			goto record_end;
	} else {
		if ((de->attr & ATTR_VOLUME) || IS_FREE(de->name))
			goto record_end;
	}

	if (isvfat && de->attr == ATTR_EXT) {
		int status = fat_parse_long(inode, &cpos, &bh, &de,
					    &unicode, &nr_slots);
		if (status < 0) {
			ctx->pos = cpos;
			ret = status;
			goto out;
		} else if (status == PARSE_INVALID)
			goto record_end;
		else if (status == PARSE_NOT_LONGNAME)
			goto parse_record;
		else if (status == PARSE_EOF)
			goto end_of_dir;

		if (nr_slots) {
			void *longname = unicode + FAT_MAX_UNI_CHARS;
			int size = PATH_MAX - FAT_MAX_UNI_SIZE;
			int len = fat_uni_to_x8(sb, unicode, longname, size);

			fill_name = longname;
			fill_len = len;
			/* !both && !short_only, so we don't need shortname. */
			if (!both)
				goto start_filldir;

			short_len = fat_parse_short(sb, de, bufname,
						    sbi->options.dotsOK);
			if (short_len == 0)
				goto record_end;
			/* hack for fat_ioctl_filldir() */
			both->longname = fill_name;
			both->long_len = fill_len;
			both->shortname = bufname;
			both->short_len = short_len;
			fill_name = NULL;
			fill_len = 0;
			goto start_filldir;
		}
	}

	short_len = fat_parse_short(sb, de, bufname, sbi->options.dotsOK);
	if (short_len == 0)
		goto record_end;

	fill_name = bufname;
	fill_len = short_len;

start_filldir:
	if (!fake_offset)
		ctx->pos = cpos - (nr_slots + 1) * sizeof(struct msdos_dir_entry);

	if (!memcmp(de->name, MSDOS_DOT, MSDOS_NAME)) {
		if (!dir_emit_dot(file, ctx))
			goto fill_failed;
	} else if (!memcmp(de->name, MSDOS_DOTDOT, MSDOS_NAME)) {
		if (!dir_emit_dotdot(file, ctx))
			goto fill_failed;
	} else {
		unsigned long inum;
		loff_t i_pos = fat_make_i_pos(sb, bh, de);
		struct inode *tmp = fat_iget(sb, i_pos);
		if (tmp) {
			inum = tmp->i_ino;
			iput(tmp);
		} else
			inum = iunique(sb, MSDOS_ROOT_INO);
		if (!dir_emit(ctx, fill_name, fill_len, inum,
			    (de->attr & ATTR_DIR) ? DT_DIR : DT_REG))
			goto fill_failed;
	}

record_end:
	fake_offset = 0;
	ctx->pos = cpos;
	goto get_new;
end_of_dir:
	ctx->pos = cpos;
fill_failed:
	brelse(bh);
	if (unicode)
		__putname(unicode);
out:
	mutex_unlock(&sbi->s_lock);
	return ret;
}

static int fat_readdir(struct file *file, struct dir_context *ctx)
{
	return __fat_readdir(file_inode(file), file, ctx, 0, NULL);
}

#define FAT_IOCTL_FILLDIR_FUNC(func, dirent_type)			   \
static int func(void *__buf, const char *name, int name_len,		   \
			     loff_t offset, u64 ino, unsigned int d_type)  \
{									   \
	struct fat_ioctl_filldir_callback *buf = __buf;			   \
	struct dirent_type __user *d1 = buf->dirent;			   \
	struct dirent_type __user *d2 = d1 + 1;				   \
									   \
	if (buf->result)						   \
		return -EINVAL;						   \
	buf->result++;							   \
									   \
	if (name != NULL) {						   \
		/* dirent has only short name */			   \
		if (name_len >= sizeof(d1->d_name))			   \
			name_len = sizeof(d1->d_name) - 1;		   \
									   \
		if (put_user(0, d2->d_name)			||	   \
		    put_user(0, &d2->d_reclen)			||	   \
		    copy_to_user(d1->d_name, name, name_len)	||	   \
		    put_user(0, d1->d_name + name_len)		||	   \
		    put_user(name_len, &d1->d_reclen))			   \
			goto efault;					   \
	} else {							   \
		/* dirent has short and long name */			   \
		const char *longname = buf->longname;			   \
		int long_len = buf->long_len;				   \
		const char *shortname = buf->shortname;			   \
		int short_len = buf->short_len;				   \
									   \
		if (long_len >= sizeof(d1->d_name))			   \
			long_len = sizeof(d1->d_name) - 1;		   \
		if (short_len >= sizeof(d1->d_name))			   \
			short_len = sizeof(d1->d_name) - 1;		   \
									   \
		if (copy_to_user(d2->d_name, longname, long_len)	|| \
		    put_user(0, d2->d_name + long_len)			|| \
		    put_user(long_len, &d2->d_reclen)			|| \
		    put_user(ino, &d2->d_ino)				|| \
		    put_user(offset, &d2->d_off)			|| \
		    copy_to_user(d1->d_name, shortname, short_len)	|| \
		    put_user(0, d1->d_name + short_len)			|| \
		    put_user(short_len, &d1->d_reclen))			   \
			goto efault;					   \
	}								   \
	return 0;							   \
efault:									   \
	buf->result = -EFAULT;						   \
	return -EFAULT;							   \
}

FAT_IOCTL_FILLDIR_FUNC(fat_ioctl_filldir, __fat_dirent)

static int fat_ioctl_readdir(struct inode *inode, struct file *file,
			     void __user *dirent, filldir_t filldir,
			     int short_only, int both)
{
	struct fat_ioctl_filldir_callback buf = {
		.ctx.actor = filldir,
		.dirent = dirent
	};
	int ret;

	buf.dirent = dirent;
	buf.result = 0;
	mutex_lock(&inode->i_mutex);
	buf.ctx.pos = file->f_pos;
	ret = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		ret = __fat_readdir(inode, file, &buf.ctx,
				    short_only, both ? &buf : NULL);
		file->f_pos = buf.ctx.pos;
	}
	mutex_unlock(&inode->i_mutex);
	if (ret >= 0)
		ret = buf.result;
	return ret;
}

static long fat_dir_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct __fat_dirent __user *d1 = (struct __fat_dirent __user *)arg;
	int short_only, both;

	switch (cmd) {
	case VFAT_IOCTL_READDIR_SHORT:
		short_only = 1;
		both = 0;
		break;
	case VFAT_IOCTL_READDIR_BOTH:
		short_only = 0;
		both = 1;
		break;
	default:
		return fat_generic_ioctl(filp, cmd, arg);
	}

	if (!access_ok(VERIFY_WRITE, d1, sizeof(struct __fat_dirent[2])))
		return -EFAULT;
	/*
	 * Yes, we don't need this put_user() absolutely. However old
	 * code didn't return the right value. So, app use this value,
	 * in order to check whether it is EOF.
	 */
	if (put_user(0, &d1->d_reclen))
		return -EFAULT;

	return fat_ioctl_readdir(inode, filp, d1, fat_ioctl_filldir,
				 short_only, both);
}

#ifdef CONFIG_COMPAT
#define	VFAT_IOCTL_READDIR_BOTH32	_IOR('r', 1, struct compat_dirent[2])
#define	VFAT_IOCTL_READDIR_SHORT32	_IOR('r', 2, struct compat_dirent[2])

FAT_IOCTL_FILLDIR_FUNC(fat_compat_ioctl_filldir, compat_dirent)

static long fat_compat_dir_ioctl(struct file *filp, unsigned cmd,
				 unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct compat_dirent __user *d1 = compat_ptr(arg);
	int short_only, both;

	switch (cmd) {
	case VFAT_IOCTL_READDIR_SHORT32:
		short_only = 1;
		both = 0;
		break;
	case VFAT_IOCTL_READDIR_BOTH32:
		short_only = 0;
		both = 1;
		break;
	default:
		return fat_generic_ioctl(filp, cmd, (unsigned long)arg);
	}

	if (!access_ok(VERIFY_WRITE, d1, sizeof(struct compat_dirent[2])))
		return -EFAULT;
	/*
	 * Yes, we don't need this put_user() absolutely. However old
	 * code didn't return the right value. So, app use this value,
	 * in order to check whether it is EOF.
	 */
	if (put_user(0, &d1->d_reclen))
		return -EFAULT;

	return fat_ioctl_readdir(inode, filp, d1, fat_compat_ioctl_filldir,
				 short_only, both);
}
#endif /* CONFIG_COMPAT */

const struct file_operations fat_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= fat_readdir,
	.unlocked_ioctl	= fat_dir_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= fat_compat_dir_ioctl,
#endif
	.fsync		= fat_file_fsync,
};

static int fat_get_short_entry(struct inode *dir, loff_t *pos,
			       struct buffer_head **bh,
			       struct msdos_dir_entry **de)
{
	while (fat_get_entry(dir, pos, bh, de) >= 0) {
		/* free entry or long name entry or volume label */
		if (!IS_FREE((*de)->name) && !((*de)->attr & ATTR_VOLUME))
			return 0;
	}
	return -ENOENT;
}

/*
 * The ".." entry can not provide the "struct fat_slot_info" information
 * for inode, nor a usable i_pos. So, this function provides some information
 * only.
 *
 * Since this function walks through the on-disk inodes within a directory,
 * callers are responsible for taking any locks necessary to prevent the
 * directory from changing.
 */
int fat_get_dotdot_entry(struct inode *dir, struct buffer_head **bh,
			 struct msdos_dir_entry **de)
{
	loff_t offset = 0;

	*de = NULL;
	while (fat_get_short_entry(dir, &offset, bh, de) >= 0) {
		if (!strncmp((*de)->name, MSDOS_DOTDOT, MSDOS_NAME))
			return 0;
	}
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(fat_get_dotdot_entry);

/* See if directory is empty */
int fat_dir_empty(struct inode *dir)
{
	struct buffer_head *bh;
	struct msdos_dir_entry *de;
	loff_t cpos;
	int result = 0;

	bh = NULL;
	cpos = 0;
	while (fat_get_short_entry(dir, &cpos, &bh, &de) >= 0) {
		if (strncmp(de->name, MSDOS_DOT   , MSDOS_NAME) &&
		    strncmp(de->name, MSDOS_DOTDOT, MSDOS_NAME)) {
			result = -ENOTEMPTY;
			break;
		}
	}
	brelse(bh);
	return result;
}
EXPORT_SYMBOL_GPL(fat_dir_empty);

/*
 * fat_subdirs counts the number of sub-directories of dir. It can be run
 * on directories being created.
 */
int fat_subdirs(struct inode *dir)
{
	struct buffer_head *bh;
	struct msdos_dir_entry *de;
	loff_t cpos;
	int count = 0;

	bh = NULL;
	cpos = 0;
	while (fat_get_short_entry(dir, &cpos, &bh, &de) >= 0) {
		if (de->attr & ATTR_DIR)
			count++;
	}
	brelse(bh);
	return count;
}

/*
 * Scans a directory for a given file (name points to its formatted name).
 * Returns an error code or zero.
 */
int fat_scan(struct inode *dir, const unsigned char *name,
	     struct fat_slot_info *sinfo)
{
	struct super_block *sb = dir->i_sb;

	sinfo->slot_off = 0;
	sinfo->bh = NULL;
	while (fat_get_short_entry(dir, &sinfo->slot_off, &sinfo->bh,
				   &sinfo->de) >= 0) {
		if (!strncmp(sinfo->de->name, name, MSDOS_NAME)) {
			sinfo->slot_off -= sizeof(*sinfo->de);
			sinfo->nr_slots = 1;
			sinfo->i_pos = fat_make_i_pos(sb, sinfo->bh, sinfo->de);
			return 0;
		}
	}
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(fat_scan);

/*
 * Scans a directory for a given logstart.
 * Returns an error code or zero.
 */
int fat_scan_logstart(struct inode *dir, int i_logstart,
		      struct fat_slot_info *sinfo)
{
	struct super_block *sb = dir->i_sb;

	sinfo->slot_off = 0;
	sinfo->bh = NULL;
	while (fat_get_short_entry(dir, &sinfo->slot_off, &sinfo->bh,
				   &sinfo->de) >= 0) {
		if (fat_get_start(MSDOS_SB(sb), sinfo->de) == i_logstart) {
			sinfo->slot_off -= sizeof(*sinfo->de);
			sinfo->nr_slots = 1;
			sinfo->i_pos = fat_make_i_pos(sb, sinfo->bh, sinfo->de);
			return 0;
		}
	}
	return -ENOENT;
}

static int __fat_remove_entries(struct inode *dir, loff_t pos, int nr_slots)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *bh;
	struct msdos_dir_entry *de, *endp;
	int err = 0, orig_slots;

	while (nr_slots) {
		bh = NULL;
		if (fat_get_entry(dir, &pos, &bh, &de) < 0) {
			err = -EIO;
			break;
		}

		orig_slots = nr_slots;
		endp = (struct msdos_dir_entry *)(bh->b_data + sb->s_blocksize);
		while (nr_slots && de < endp) {
			de->name[0] = DELETED_FLAG;
			de++;
			nr_slots--;
		}
		mark_buffer_dirty_inode(bh, dir);
		if (IS_DIRSYNC(dir))
			err = sync_dirty_buffer(bh);
		brelse(bh);
		if (err)
			break;

		/* pos is *next* de's position, so this does `- sizeof(de)' */
		pos += ((orig_slots - nr_slots) * sizeof(*de)) - sizeof(*de);
	}

	return err;
}

int fat_remove_entries(struct inode *dir, struct fat_slot_info *sinfo)
{
	struct super_block *sb = dir->i_sb;
	struct msdos_dir_entry *de;
	struct buffer_head *bh;
	int err = 0, nr_slots;

	/*
	 * First stage: Remove the shortname. By this, the directory
	 * entry is removed.
	 */
	nr_slots = sinfo->nr_slots;
	de = sinfo->de;
	sinfo->de = NULL;
	bh = sinfo->bh;
	sinfo->bh = NULL;
	while (nr_slots && de >= (struct msdos_dir_entry *)bh->b_data) {
		de->name[0] = DELETED_FLAG;
		de--;
		nr_slots--;
	}
	mark_buffer_dirty_inode(bh, dir);
	if (IS_DIRSYNC(dir))
		err = sync_dirty_buffer(bh);
	brelse(bh);
	if (err)
		return err;
	dir->i_version++;

	if (nr_slots) {
		/*
		 * Second stage: remove the remaining longname slots.
		 * (This directory entry is already removed, and so return
		 * the success)
		 */
		err = __fat_remove_entries(dir, sinfo->slot_off, nr_slots);
		if (err) {
			fat_msg(sb, KERN_WARNING,
			       "Couldn't remove the long name slots");
		}
	}

	dir->i_mtime = dir->i_atime = CURRENT_TIME_SEC;
	if (IS_DIRSYNC(dir))
		(void)fat_sync_inode(dir);
	else
		mark_inode_dirty(dir);

	return 0;
}
EXPORT_SYMBOL_GPL(fat_remove_entries);

static int fat_zeroed_cluster(struct inode *dir, sector_t blknr, int nr_used,
			      struct buffer_head **bhs, int nr_bhs)
{
	struct super_block *sb = dir->i_sb;
	sector_t last_blknr = blknr + MSDOS_SB(sb)->sec_per_clus;
	int err, i, n;

	/* Zeroing the unused blocks on this cluster */
	blknr += nr_used;
	n = nr_used;
	while (blknr < last_blknr) {
		bhs[n] = sb_getblk(sb, blknr);
		if (!bhs[n]) {
			err = -ENOMEM;
			goto error;
		}
		memset(bhs[n]->b_data, 0, sb->s_blocksize);
		set_buffer_uptodate(bhs[n]);
		mark_buffer_dirty_inode(bhs[n], dir);

		n++;
		blknr++;
		if (n == nr_bhs) {
			if (IS_DIRSYNC(dir)) {
				err = fat_sync_bhs(bhs, n);
				if (err)
					goto error;
			}
			for (i = 0; i < n; i++)
				brelse(bhs[i]);
			n = 0;
		}
	}
	if (IS_DIRSYNC(dir)) {
		err = fat_sync_bhs(bhs, n);
		if (err)
			goto error;
	}
	for (i = 0; i < n; i++)
		brelse(bhs[i]);

	return 0;

error:
	for (i = 0; i < n; i++)
		bforget(bhs[i]);
	return err;
}

int fat_alloc_new_dir(struct inode *dir, struct timespec *ts)
{
	struct super_block *sb = dir->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bhs[MAX_BUF_PER_PAGE];
	struct msdos_dir_entry *de;
	sector_t blknr;
	__le16 date, time;
	u8 time_cs;
	int err, cluster;

	err = fat_alloc_clusters(dir, &cluster, 1);
	if (err)
		goto error;

	blknr = fat_clus_to_blknr(sbi, cluster);
	bhs[0] = sb_getblk(sb, blknr);
	if (!bhs[0]) {
		err = -ENOMEM;
		goto error_free;
	}

	fat_time_unix2fat(sbi, ts, &time, &date, &time_cs);

	de = (struct msdos_dir_entry *)bhs[0]->b_data;
	/* filling the new directory slots ("." and ".." entries) */
	memcpy(de[0].name, MSDOS_DOT, MSDOS_NAME);
	memcpy(de[1].name, MSDOS_DOTDOT, MSDOS_NAME);
	de->attr = de[1].attr = ATTR_DIR;
	de[0].lcase = de[1].lcase = 0;
	de[0].time = de[1].time = time;
	de[0].date = de[1].date = date;
	if (sbi->options.isvfat) {
		/* extra timestamps */
		de[0].ctime = de[1].ctime = time;
		de[0].ctime_cs = de[1].ctime_cs = time_cs;
		de[0].adate = de[0].cdate = de[1].adate = de[1].cdate = date;
	} else {
		de[0].ctime = de[1].ctime = 0;
		de[0].ctime_cs = de[1].ctime_cs = 0;
		de[0].adate = de[0].cdate = de[1].adate = de[1].cdate = 0;
	}
	fat_set_start(&de[0], cluster);
	fat_set_start(&de[1], MSDOS_I(dir)->i_logstart);
	de[0].size = de[1].size = 0;
	memset(de + 2, 0, sb->s_blocksize - 2 * sizeof(*de));
	set_buffer_uptodate(bhs[0]);
	mark_buffer_dirty_inode(bhs[0], dir);

	err = fat_zeroed_cluster(dir, blknr, 1, bhs, MAX_BUF_PER_PAGE);
	if (err)
		goto error_free;

	return cluster;

error_free:
	fat_free_clusters(dir, cluster);
error:
	return err;
}
EXPORT_SYMBOL_GPL(fat_alloc_new_dir);

static int fat_add_new_entries(struct inode *dir, void *slots, int nr_slots,
			       int *nr_cluster, struct msdos_dir_entry **de,
			       struct buffer_head **bh, loff_t *i_pos)
{
	struct super_block *sb = dir->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bhs[MAX_BUF_PER_PAGE];
	sector_t blknr, start_blknr, last_blknr;
	unsigned long size, copy;
	int err, i, n, offset, cluster[2];

	/*
	 * The minimum cluster size is 512bytes, and maximum entry
	 * size is 32*slots (672bytes).  So, iff the cluster size is
	 * 512bytes, we may need two clusters.
	 */
	size = nr_slots * sizeof(struct msdos_dir_entry);
	*nr_cluster = (size + (sbi->cluster_size - 1)) >> sbi->cluster_bits;
	BUG_ON(*nr_cluster > 2);

	err = fat_alloc_clusters(dir, cluster, *nr_cluster);
	if (err)
		goto error;

	/*
	 * First stage: Fill the directory entry.  NOTE: This cluster
	 * is not referenced from any inode yet, so updates order is
	 * not important.
	 */
	i = n = copy = 0;
	do {
		start_blknr = blknr = fat_clus_to_blknr(sbi, cluster[i]);
		last_blknr = start_blknr + sbi->sec_per_clus;
		while (blknr < last_blknr) {
			bhs[n] = sb_getblk(sb, blknr);
			if (!bhs[n]) {
				err = -ENOMEM;
				goto error_nomem;
			}

			/* fill the directory entry */
			copy = min(size, sb->s_blocksize);
			memcpy(bhs[n]->b_data, slots, copy);
			slots += copy;
			size -= copy;
			set_buffer_uptodate(bhs[n]);
			mark_buffer_dirty_inode(bhs[n], dir);
			if (!size)
				break;
			n++;
			blknr++;
		}
	} while (++i < *nr_cluster);

	memset(bhs[n]->b_data + copy, 0, sb->s_blocksize - copy);
	offset = copy - sizeof(struct msdos_dir_entry);
	get_bh(bhs[n]);
	*bh = bhs[n];
	*de = (struct msdos_dir_entry *)((*bh)->b_data + offset);
	*i_pos = fat_make_i_pos(sb, *bh, *de);

	/* Second stage: clear the rest of cluster, and write outs */
	err = fat_zeroed_cluster(dir, start_blknr, ++n, bhs, MAX_BUF_PER_PAGE);
	if (err)
		goto error_free;

	return cluster[0];

error_free:
	brelse(*bh);
	*bh = NULL;
	n = 0;
error_nomem:
	for (i = 0; i < n; i++)
		bforget(bhs[i]);
	fat_free_clusters(dir, cluster[0]);
error:
	return err;
}

int fat_add_entries(struct inode *dir, void *slots, int nr_slots,
		    struct fat_slot_info *sinfo)
{
	struct super_block *sb = dir->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bh, *prev, *bhs[3]; /* 32*slots (672bytes) */
	struct msdos_dir_entry *uninitialized_var(de);
	int err, free_slots, i, nr_bhs;
	loff_t pos, i_pos;

	sinfo->nr_slots = nr_slots;

	/* First stage: search free directory entries */
	free_slots = nr_bhs = 0;
	bh = prev = NULL;
	pos = 0;
	err = -ENOSPC;
	while (fat_get_entry(dir, &pos, &bh, &de) > -1) {
		/* check the maximum size of directory */
		if (pos >= FAT_MAX_DIR_SIZE)
			goto error;

		if (IS_FREE(de->name)) {
			if (prev != bh) {
				get_bh(bh);
				bhs[nr_bhs] = prev = bh;
				nr_bhs++;
			}
			free_slots++;
			if (free_slots == nr_slots)
				goto found;
		} else {
			for (i = 0; i < nr_bhs; i++)
				brelse(bhs[i]);
			prev = NULL;
			free_slots = nr_bhs = 0;
		}
	}
	if (dir->i_ino == MSDOS_ROOT_INO) {
		if (sbi->fat_bits != 32)
			goto error;
	} else if (MSDOS_I(dir)->i_start == 0) {
		fat_msg(sb, KERN_ERR, "Corrupted directory (i_pos %lld)",
		       MSDOS_I(dir)->i_pos);
		err = -EIO;
		goto error;
	}

found:
	err = 0;
	pos -= free_slots * sizeof(*de);
	nr_slots -= free_slots;
	if (free_slots) {
		/*
		 * Second stage: filling the free entries with new entries.
		 * NOTE: If this slots has shortname, first, we write
		 * the long name slots, then write the short name.
		 */
		int size = free_slots * sizeof(*de);
		int offset = pos & (sb->s_blocksize - 1);
		int long_bhs = nr_bhs - (nr_slots == 0);

		/* Fill the long name slots. */
		for (i = 0; i < long_bhs; i++) {
			int copy = min_t(int, sb->s_blocksize - offset, size);
			memcpy(bhs[i]->b_data + offset, slots, copy);
			mark_buffer_dirty_inode(bhs[i], dir);
			offset = 0;
			slots += copy;
			size -= copy;
		}
		if (long_bhs && IS_DIRSYNC(dir))
			err = fat_sync_bhs(bhs, long_bhs);
		if (!err && i < nr_bhs) {
			/* Fill the short name slot. */
			int copy = min_t(int, sb->s_blocksize - offset, size);
			memcpy(bhs[i]->b_data + offset, slots, copy);
			mark_buffer_dirty_inode(bhs[i], dir);
			if (IS_DIRSYNC(dir))
				err = sync_dirty_buffer(bhs[i]);
		}
		for (i = 0; i < nr_bhs; i++)
			brelse(bhs[i]);
		if (err)
			goto error_remove;
	}

	if (nr_slots) {
		int cluster, nr_cluster;

		/*
		 * Third stage: allocate the cluster for new entries.
		 * And initialize the cluster with new entries, then
		 * add the cluster to dir.
		 */
		cluster = fat_add_new_entries(dir, slots, nr_slots, &nr_cluster,
					      &de, &bh, &i_pos);
		if (cluster < 0) {
			err = cluster;
			goto error_remove;
		}
		err = fat_chain_add(dir, cluster, nr_cluster);
		if (err) {
			fat_free_clusters(dir, cluster);
			goto error_remove;
		}
		if (dir->i_size & (sbi->cluster_size - 1)) {
			fat_fs_error(sb, "Odd directory size");
			dir->i_size = (dir->i_size + sbi->cluster_size - 1)
				& ~((loff_t)sbi->cluster_size - 1);
		}
		dir->i_size += nr_cluster << sbi->cluster_bits;
		MSDOS_I(dir)->mmu_private += nr_cluster << sbi->cluster_bits;
	}
	sinfo->slot_off = pos;
	sinfo->de = de;
	sinfo->bh = bh;
	sinfo->i_pos = fat_make_i_pos(sb, sinfo->bh, sinfo->de);

	return 0;

error:
	brelse(bh);
	for (i = 0; i < nr_bhs; i++)
		brelse(bhs[i]);
	return err;

error_remove:
	brelse(bh);
	if (free_slots)
		__fat_remove_entries(dir, pos, free_slots);
	return err;
}
EXPORT_SYMBOL_GPL(fat_add_entries);
/************************************************************/
/* ../linux-3.17/fs/fat/dir.c */
/************************************************************/
/*
 * Copyright (C) 2004, OGAWA Hirofumi
 * Released under GPL v2.
 */

// #include <linux/module.h>
// #include <linux/fs.h>
#include <linux/msdos_fs.h>
#include <linux/blkdev.h>
// #include "fat.h"

struct fatent_operations {
	void (*ent_blocknr)(struct super_block *, int, int *, sector_t *);
	void (*ent_set_ptr)(struct fat_entry *, int);
	int (*ent_bread)(struct super_block *, struct fat_entry *,
			 int, sector_t);
	int (*ent_get)(struct fat_entry *);
	void (*ent_put)(struct fat_entry *, int);
	int (*ent_next)(struct fat_entry *);
};

static DEFINE_SPINLOCK(fat12_entry_lock);

static void fat12_ent_blocknr(struct super_block *sb, int entry,
			      int *offset, sector_t *blocknr)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	int bytes = entry + (entry >> 1);
	WARN_ON(entry < FAT_START_ENT || sbi->max_cluster <= entry);
	*offset = bytes & (sb->s_blocksize - 1);
	*blocknr = sbi->fat_start + (bytes >> sb->s_blocksize_bits);
}

static void fat_ent_blocknr(struct super_block *sb, int entry,
			    int *offset, sector_t *blocknr)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	int bytes = (entry << sbi->fatent_shift);
	WARN_ON(entry < FAT_START_ENT || sbi->max_cluster <= entry);
	*offset = bytes & (sb->s_blocksize - 1);
	*blocknr = sbi->fat_start + (bytes >> sb->s_blocksize_bits);
}

static void fat12_ent_set_ptr(struct fat_entry *fatent, int offset)
{
	struct buffer_head **bhs = fatent->bhs;
	if (fatent->nr_bhs == 1) {
		WARN_ON(offset >= (bhs[0]->b_size - 1));
		fatent->u.ent12_p[0] = bhs[0]->b_data + offset;
		fatent->u.ent12_p[1] = bhs[0]->b_data + (offset + 1);
	} else {
		WARN_ON(offset != (bhs[0]->b_size - 1));
		fatent->u.ent12_p[0] = bhs[0]->b_data + offset;
		fatent->u.ent12_p[1] = bhs[1]->b_data;
	}
}

static void fat16_ent_set_ptr(struct fat_entry *fatent, int offset)
{
	WARN_ON(offset & (2 - 1));
	fatent->u.ent16_p = (__le16 *)(fatent->bhs[0]->b_data + offset);
}

static void fat32_ent_set_ptr(struct fat_entry *fatent, int offset)
{
	WARN_ON(offset & (4 - 1));
	fatent->u.ent32_p = (__le32 *)(fatent->bhs[0]->b_data + offset);
}

static int fat12_ent_bread(struct super_block *sb, struct fat_entry *fatent,
			   int offset, sector_t blocknr)
{
	struct buffer_head **bhs = fatent->bhs;

	WARN_ON(blocknr < MSDOS_SB(sb)->fat_start);
	fatent->fat_inode = MSDOS_SB(sb)->fat_inode;

	bhs[0] = sb_bread(sb, blocknr);
	if (!bhs[0])
		goto err;

	if ((offset + 1) < sb->s_blocksize)
		fatent->nr_bhs = 1;
	else {
		/* This entry is block boundary, it needs the next block */
		blocknr++;
		bhs[1] = sb_bread(sb, blocknr);
		if (!bhs[1])
			goto err_brelse;
		fatent->nr_bhs = 2;
	}
	fat12_ent_set_ptr(fatent, offset);
	return 0;

err_brelse:
	brelse(bhs[0]);
err:
	fat_msg(sb, KERN_ERR, "FAT read failed (blocknr %llu)", (llu)blocknr);
	return -EIO;
}

static int fat_ent_bread(struct super_block *sb, struct fat_entry *fatent,
			 int offset, sector_t blocknr)
{
	struct fatent_operations *ops = MSDOS_SB(sb)->fatent_ops;

	WARN_ON(blocknr < MSDOS_SB(sb)->fat_start);
	fatent->fat_inode = MSDOS_SB(sb)->fat_inode;
	fatent->bhs[0] = sb_bread(sb, blocknr);
	if (!fatent->bhs[0]) {
		fat_msg(sb, KERN_ERR, "FAT read failed (blocknr %llu)",
		       (llu)blocknr);
		return -EIO;
	}
	fatent->nr_bhs = 1;
	ops->ent_set_ptr(fatent, offset);
	return 0;
}

static int fat12_ent_get(struct fat_entry *fatent)
{
	u8 **ent12_p = fatent->u.ent12_p;
	int next;

	spin_lock(&fat12_entry_lock);
	if (fatent->entry & 1)
		next = (*ent12_p[0] >> 4) | (*ent12_p[1] << 4);
	else
		next = (*ent12_p[1] << 8) | *ent12_p[0];
	spin_unlock(&fat12_entry_lock);

	next &= 0x0fff;
	if (next >= BAD_FAT12)
		next = FAT_ENT_EOF;
	return next;
}

static int fat16_ent_get(struct fat_entry *fatent)
{
	int next = le16_to_cpu(*fatent->u.ent16_p);
	WARN_ON((unsigned long)fatent->u.ent16_p & (2 - 1));
	if (next >= BAD_FAT16)
		next = FAT_ENT_EOF;
	return next;
}

static int fat32_ent_get(struct fat_entry *fatent)
{
	int next = le32_to_cpu(*fatent->u.ent32_p) & 0x0fffffff;
	WARN_ON((unsigned long)fatent->u.ent32_p & (4 - 1));
	if (next >= BAD_FAT32)
		next = FAT_ENT_EOF;
	return next;
}

static void fat12_ent_put(struct fat_entry *fatent, int new)
{
	u8 **ent12_p = fatent->u.ent12_p;

	if (new == FAT_ENT_EOF)
		new = EOF_FAT12;

	spin_lock(&fat12_entry_lock);
	if (fatent->entry & 1) {
		*ent12_p[0] = (new << 4) | (*ent12_p[0] & 0x0f);
		*ent12_p[1] = new >> 4;
	} else {
		*ent12_p[0] = new & 0xff;
		*ent12_p[1] = (*ent12_p[1] & 0xf0) | (new >> 8);
	}
	spin_unlock(&fat12_entry_lock);

	mark_buffer_dirty_inode(fatent->bhs[0], fatent->fat_inode);
	if (fatent->nr_bhs == 2)
		mark_buffer_dirty_inode(fatent->bhs[1], fatent->fat_inode);
}

static void fat16_ent_put(struct fat_entry *fatent, int new)
{
	if (new == FAT_ENT_EOF)
		new = EOF_FAT16;

	*fatent->u.ent16_p = cpu_to_le16(new);
	mark_buffer_dirty_inode(fatent->bhs[0], fatent->fat_inode);
}

static void fat32_ent_put(struct fat_entry *fatent, int new)
{
	WARN_ON(new & 0xf0000000);
	new |= le32_to_cpu(*fatent->u.ent32_p) & ~0x0fffffff;
	*fatent->u.ent32_p = cpu_to_le32(new);
	mark_buffer_dirty_inode(fatent->bhs[0], fatent->fat_inode);
}

static int fat12_ent_next(struct fat_entry *fatent)
{
	u8 **ent12_p = fatent->u.ent12_p;
	struct buffer_head **bhs = fatent->bhs;
	u8 *nextp = ent12_p[1] + 1 + (fatent->entry & 1);

	fatent->entry++;
	if (fatent->nr_bhs == 1) {
		WARN_ON(ent12_p[0] > (u8 *)(bhs[0]->b_data +
							(bhs[0]->b_size - 2)));
		WARN_ON(ent12_p[1] > (u8 *)(bhs[0]->b_data +
							(bhs[0]->b_size - 1)));
		if (nextp < (u8 *)(bhs[0]->b_data + (bhs[0]->b_size - 1))) {
			ent12_p[0] = nextp - 1;
			ent12_p[1] = nextp;
			return 1;
		}
	} else {
		WARN_ON(ent12_p[0] != (u8 *)(bhs[0]->b_data +
							(bhs[0]->b_size - 1)));
		WARN_ON(ent12_p[1] != (u8 *)bhs[1]->b_data);
		ent12_p[0] = nextp - 1;
		ent12_p[1] = nextp;
		brelse(bhs[0]);
		bhs[0] = bhs[1];
		fatent->nr_bhs = 1;
		return 1;
	}
	ent12_p[0] = NULL;
	ent12_p[1] = NULL;
	return 0;
}

static int fat16_ent_next(struct fat_entry *fatent)
{
	const struct buffer_head *bh = fatent->bhs[0];
	fatent->entry++;
	if (fatent->u.ent16_p < (__le16 *)(bh->b_data + (bh->b_size - 2))) {
		fatent->u.ent16_p++;
		return 1;
	}
	fatent->u.ent16_p = NULL;
	return 0;
}

static int fat32_ent_next(struct fat_entry *fatent)
{
	const struct buffer_head *bh = fatent->bhs[0];
	fatent->entry++;
	if (fatent->u.ent32_p < (__le32 *)(bh->b_data + (bh->b_size - 4))) {
		fatent->u.ent32_p++;
		return 1;
	}
	fatent->u.ent32_p = NULL;
	return 0;
}

static struct fatent_operations fat12_ops = {
	.ent_blocknr	= fat12_ent_blocknr,
	.ent_set_ptr	= fat12_ent_set_ptr,
	.ent_bread	= fat12_ent_bread,
	.ent_get	= fat12_ent_get,
	.ent_put	= fat12_ent_put,
	.ent_next	= fat12_ent_next,
};

static struct fatent_operations fat16_ops = {
	.ent_blocknr	= fat_ent_blocknr,
	.ent_set_ptr	= fat16_ent_set_ptr,
	.ent_bread	= fat_ent_bread,
	.ent_get	= fat16_ent_get,
	.ent_put	= fat16_ent_put,
	.ent_next	= fat16_ent_next,
};

static struct fatent_operations fat32_ops = {
	.ent_blocknr	= fat_ent_blocknr,
	.ent_set_ptr	= fat32_ent_set_ptr,
	.ent_bread	= fat_ent_bread,
	.ent_get	= fat32_ent_get,
	.ent_put	= fat32_ent_put,
	.ent_next	= fat32_ent_next,
};

static inline void lock_fat(struct msdos_sb_info *sbi)
{
	mutex_lock(&sbi->fat_lock);
}

static inline void unlock_fat(struct msdos_sb_info *sbi)
{
	mutex_unlock(&sbi->fat_lock);
}

void fat_ent_access_init(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);

	mutex_init(&sbi->fat_lock);

	switch (sbi->fat_bits) {
	case 32:
		sbi->fatent_shift = 2;
		sbi->fatent_ops = &fat32_ops;
		break;
	case 16:
		sbi->fatent_shift = 1;
		sbi->fatent_ops = &fat16_ops;
		break;
	case 12:
		sbi->fatent_shift = -1;
		sbi->fatent_ops = &fat12_ops;
		break;
	}
}

static void mark_fsinfo_dirty(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);

	if (sb->s_flags & MS_RDONLY || sbi->fat_bits != 32)
		return;

	__mark_inode_dirty(sbi->fsinfo_inode, I_DIRTY_SYNC);
}

static inline int fat_ent_update_ptr(struct super_block *sb,
				     struct fat_entry *fatent,
				     int offset, sector_t blocknr)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct fatent_operations *ops = sbi->fatent_ops;
	struct buffer_head **bhs = fatent->bhs;

	/* Is this fatent's blocks including this entry? */
	if (!fatent->nr_bhs || bhs[0]->b_blocknr != blocknr)
		return 0;
	if (sbi->fat_bits == 12) {
		if ((offset + 1) < sb->s_blocksize) {
			/* This entry is on bhs[0]. */
			if (fatent->nr_bhs == 2) {
				brelse(bhs[1]);
				fatent->nr_bhs = 1;
			}
		} else {
			/* This entry needs the next block. */
			if (fatent->nr_bhs != 2)
				return 0;
			if (bhs[1]->b_blocknr != (blocknr + 1))
				return 0;
		}
	}
	ops->ent_set_ptr(fatent, offset);
	return 1;
}

int fat_ent_read(struct inode *inode, struct fat_entry *fatent, int entry)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	struct fatent_operations *ops = sbi->fatent_ops;
	int err, offset;
	sector_t blocknr;

	if (entry < FAT_START_ENT || sbi->max_cluster <= entry) {
		fatent_brelse(fatent);
		fat_fs_error(sb, "invalid access to FAT (entry 0x%08x)", entry);
		return -EIO;
	}

	fatent_set_entry(fatent, entry);
	ops->ent_blocknr(sb, entry, &offset, &blocknr);

	if (!fat_ent_update_ptr(sb, fatent, offset, blocknr)) {
		fatent_brelse(fatent);
		err = ops->ent_bread(sb, fatent, offset, blocknr);
		if (err)
			return err;
	}
	return ops->ent_get(fatent);
}

/* FIXME: We can write the blocks as more big chunk. */
static int fat_mirror_bhs(struct super_block *sb, struct buffer_head **bhs,
			  int nr_bhs)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *c_bh;
	int err, n, copy;

	err = 0;
	for (copy = 1; copy < sbi->fats; copy++) {
		sector_t backup_fat = sbi->fat_length * copy;

		for (n = 0; n < nr_bhs; n++) {
			c_bh = sb_getblk(sb, backup_fat + bhs[n]->b_blocknr);
			if (!c_bh) {
				err = -ENOMEM;
				goto error;
			}
			memcpy(c_bh->b_data, bhs[n]->b_data, sb->s_blocksize);
			set_buffer_uptodate(c_bh);
			mark_buffer_dirty_inode(c_bh, sbi->fat_inode);
			if (sb->s_flags & MS_SYNCHRONOUS)
				err = sync_dirty_buffer(c_bh);
			brelse(c_bh);
			if (err)
				goto error;
		}
	}
error:
	return err;
}

int fat_ent_write(struct inode *inode, struct fat_entry *fatent,
		  int new, int wait)
{
	struct super_block *sb = inode->i_sb;
	struct fatent_operations *ops = MSDOS_SB(sb)->fatent_ops;
	int err;

	ops->ent_put(fatent, new);
	if (wait) {
		err = fat_sync_bhs(fatent->bhs, fatent->nr_bhs);
		if (err)
			return err;
	}
	return fat_mirror_bhs(sb, fatent->bhs, fatent->nr_bhs);
}

static inline int fat_ent_next(struct msdos_sb_info *sbi,
			       struct fat_entry *fatent)
{
	if (sbi->fatent_ops->ent_next(fatent)) {
		if (fatent->entry < sbi->max_cluster)
			return 1;
	}
	return 0;
}

static inline int fat_ent_read_block(struct super_block *sb,
				     struct fat_entry *fatent)
{
	struct fatent_operations *ops = MSDOS_SB(sb)->fatent_ops;
	sector_t blocknr;
	int offset;

	fatent_brelse(fatent);
	ops->ent_blocknr(sb, fatent->entry, &offset, &blocknr);
	return ops->ent_bread(sb, fatent, offset, blocknr);
}

static void fat_collect_bhs(struct buffer_head **bhs, int *nr_bhs,
			    struct fat_entry *fatent)
{
	int n, i;

	for (n = 0; n < fatent->nr_bhs; n++) {
		for (i = 0; i < *nr_bhs; i++) {
			if (fatent->bhs[n] == bhs[i])
				break;
		}
		if (i == *nr_bhs) {
			get_bh(fatent->bhs[n]);
			bhs[i] = fatent->bhs[n];
			(*nr_bhs)++;
		}
	}
}

int fat_alloc_clusters(struct inode *inode, int *cluster, int nr_cluster)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct fatent_operations *ops = sbi->fatent_ops;
	struct fat_entry fatent, prev_ent;
	struct buffer_head *bhs[MAX_BUF_PER_PAGE];
	int i, count, err, nr_bhs, idx_clus;

	BUG_ON(nr_cluster > (MAX_BUF_PER_PAGE / 2));	/* fixed limit */

	lock_fat(sbi);
	if (sbi->free_clusters != -1 && sbi->free_clus_valid &&
	    sbi->free_clusters < nr_cluster) {
		unlock_fat(sbi);
		return -ENOSPC;
	}

	err = nr_bhs = idx_clus = 0;
	count = FAT_START_ENT;
	fatent_init(&prev_ent);
	fatent_init(&fatent);
	fatent_set_entry(&fatent, sbi->prev_free + 1);
	while (count < sbi->max_cluster) {
		if (fatent.entry >= sbi->max_cluster)
			fatent.entry = FAT_START_ENT;
		fatent_set_entry(&fatent, fatent.entry);
		err = fat_ent_read_block(sb, &fatent);
		if (err)
			goto out;

		/* Find the free entries in a block */
		do {
			if (ops->ent_get(&fatent) == FAT_ENT_FREE) {
				int entry = fatent.entry;

				/* make the cluster chain */
				ops->ent_put(&fatent, FAT_ENT_EOF);
				if (prev_ent.nr_bhs)
					ops->ent_put(&prev_ent, entry);

				fat_collect_bhs(bhs, &nr_bhs, &fatent);

				sbi->prev_free = entry;
				if (sbi->free_clusters != -1)
					sbi->free_clusters--;

				cluster[idx_clus] = entry;
				idx_clus++;
				if (idx_clus == nr_cluster)
					goto out;

				/*
				 * fat_collect_bhs() gets ref-count of bhs,
				 * so we can still use the prev_ent.
				 */
				prev_ent = fatent;
			}
			count++;
			if (count == sbi->max_cluster)
				break;
		} while (fat_ent_next(sbi, &fatent));
	}

	/* Couldn't allocate the free entries */
	sbi->free_clusters = 0;
	sbi->free_clus_valid = 1;
	err = -ENOSPC;

out:
	unlock_fat(sbi);
	mark_fsinfo_dirty(sb);
	fatent_brelse(&fatent);
	if (!err) {
		if (inode_needs_sync(inode))
			err = fat_sync_bhs(bhs, nr_bhs);
		if (!err)
			err = fat_mirror_bhs(sb, bhs, nr_bhs);
	}
	for (i = 0; i < nr_bhs; i++)
		brelse(bhs[i]);

	if (err && idx_clus)
		fat_free_clusters(inode, cluster[0]);

	return err;
}

int fat_free_clusters(struct inode *inode, int cluster)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct fatent_operations *ops = sbi->fatent_ops;
	struct fat_entry fatent;
	struct buffer_head *bhs[MAX_BUF_PER_PAGE];
	int i, err, nr_bhs;
	int first_cl = cluster, dirty_fsinfo = 0;

	nr_bhs = 0;
	fatent_init(&fatent);
	lock_fat(sbi);
	do {
		cluster = fat_ent_read(inode, &fatent, cluster);
		if (cluster < 0) {
			err = cluster;
			goto error;
		} else if (cluster == FAT_ENT_FREE) {
			fat_fs_error(sb, "%s: deleting FAT entry beyond EOF",
				     __func__);
			err = -EIO;
			goto error;
		}

		if (sbi->options.discard) {
			/*
			 * Issue discard for the sectors we no longer
			 * care about, batching contiguous clusters
			 * into one request
			 */
			if (cluster != fatent.entry + 1) {
				int nr_clus = fatent.entry - first_cl + 1;

				sb_issue_discard(sb,
					fat_clus_to_blknr(sbi, first_cl),
					nr_clus * sbi->sec_per_clus,
					GFP_NOFS, 0);

				first_cl = cluster;
			}
		}

		ops->ent_put(&fatent, FAT_ENT_FREE);
		if (sbi->free_clusters != -1) {
			sbi->free_clusters++;
			dirty_fsinfo = 1;
		}

		if (nr_bhs + fatent.nr_bhs > MAX_BUF_PER_PAGE) {
			if (sb->s_flags & MS_SYNCHRONOUS) {
				err = fat_sync_bhs(bhs, nr_bhs);
				if (err)
					goto error;
			}
			err = fat_mirror_bhs(sb, bhs, nr_bhs);
			if (err)
				goto error;
			for (i = 0; i < nr_bhs; i++)
				brelse(bhs[i]);
			nr_bhs = 0;
		}
		fat_collect_bhs(bhs, &nr_bhs, &fatent);
	} while (cluster != FAT_ENT_EOF);

	if (sb->s_flags & MS_SYNCHRONOUS) {
		err = fat_sync_bhs(bhs, nr_bhs);
		if (err)
			goto error;
	}
	err = fat_mirror_bhs(sb, bhs, nr_bhs);
error:
	fatent_brelse(&fatent);
	for (i = 0; i < nr_bhs; i++)
		brelse(bhs[i]);
	unlock_fat(sbi);
	if (dirty_fsinfo)
		mark_fsinfo_dirty(sb);

	return err;
}
EXPORT_SYMBOL_GPL(fat_free_clusters);

/* 128kb is the whole sectors for FAT12 and FAT16 */
#define FAT_READA_SIZE		(128 * 1024)

static void fat_ent_reada(struct super_block *sb, struct fat_entry *fatent,
			  unsigned long reada_blocks)
{
	struct fatent_operations *ops = MSDOS_SB(sb)->fatent_ops;
	sector_t blocknr;
	int i, offset;

	ops->ent_blocknr(sb, fatent->entry, &offset, &blocknr);

	for (i = 0; i < reada_blocks; i++)
		sb_breadahead(sb, blocknr + i);
}

int fat_count_free_clusters(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct fatent_operations *ops = sbi->fatent_ops;
	struct fat_entry fatent;
	unsigned long reada_blocks, reada_mask, cur_block;
	int err = 0, free;

	lock_fat(sbi);
	if (sbi->free_clusters != -1 && sbi->free_clus_valid)
		goto out;

	reada_blocks = FAT_READA_SIZE >> sb->s_blocksize_bits;
	reada_mask = reada_blocks - 1;
	cur_block = 0;

	free = 0;
	fatent_init(&fatent);
	fatent_set_entry(&fatent, FAT_START_ENT);
	while (fatent.entry < sbi->max_cluster) {
		/* readahead of fat blocks */
		if ((cur_block & reada_mask) == 0) {
			unsigned long rest = sbi->fat_length - cur_block;
			fat_ent_reada(sb, &fatent, min(reada_blocks, rest));
		}
		cur_block++;

		err = fat_ent_read_block(sb, &fatent);
		if (err)
			goto out;

		do {
			if (ops->ent_get(&fatent) == FAT_ENT_FREE)
				free++;
		} while (fat_ent_next(sbi, &fatent));
	}
	sbi->free_clusters = free;
	sbi->free_clus_valid = 1;
	mark_fsinfo_dirty(sb);
	fatent_brelse(&fatent);
out:
	unlock_fat(sbi);
	return err;
}
/************************************************************/
/* ../linux-3.17/fs/fat/fatent.c */
/************************************************************/
/*
 *  linux/fs/fat/file.c
 *
 *  Written 1992,1993 by Werner Almesberger
 *
 *  regular file handling primitives for fat-based filesystems
 */

#include <linux/capability.h>
// #include <linux/module.h>
// #include <linux/compat.h>
#include <linux/mount.h>
// #include <linux/time.h>
// #include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/backing-dev.h>
// #include <linux/blkdev.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
// #include "fat.h"

static int fat_ioctl_get_attributes(struct inode *inode, u32 __user *user_attr)
{
	u32 attr;

	mutex_lock(&inode->i_mutex);
	attr = fat_make_attrs(inode);
	mutex_unlock(&inode->i_mutex);

	return put_user(attr, user_attr);
}

static int fat_ioctl_set_attributes(struct file *file, u32 __user *user_attr)
{
	struct inode *inode = file_inode(file);
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	int is_dir = S_ISDIR(inode->i_mode);
	u32 attr, oldattr;
	struct iattr ia;
	int err;

	err = get_user(attr, user_attr);
	if (err)
		goto out;

	err = mnt_want_write_file(file);
	if (err)
		goto out;
	mutex_lock(&inode->i_mutex);

	/*
	 * ATTR_VOLUME and ATTR_DIR cannot be changed; this also
	 * prevents the user from turning us into a VFAT
	 * longname entry.  Also, we obviously can't set
	 * any of the NTFS attributes in the high 24 bits.
	 */
	attr &= 0xff & ~(ATTR_VOLUME | ATTR_DIR);
	/* Merge in ATTR_VOLUME and ATTR_DIR */
	attr |= (MSDOS_I(inode)->i_attrs & ATTR_VOLUME) |
		(is_dir ? ATTR_DIR : 0);
	oldattr = fat_make_attrs(inode);

	/* Equivalent to a chmod() */
	ia.ia_valid = ATTR_MODE | ATTR_CTIME;
	ia.ia_ctime = current_fs_time(inode->i_sb);
	if (is_dir)
		ia.ia_mode = fat_make_mode(sbi, attr, S_IRWXUGO);
	else {
		ia.ia_mode = fat_make_mode(sbi, attr,
			S_IRUGO | S_IWUGO | (inode->i_mode & S_IXUGO));
	}

	/* The root directory has no attributes */
	if (inode->i_ino == MSDOS_ROOT_INO && attr != ATTR_DIR) {
		err = -EINVAL;
		goto out_unlock_inode;
	}

	if (sbi->options.sys_immutable &&
	    ((attr | oldattr) & ATTR_SYS) &&
	    !capable(CAP_LINUX_IMMUTABLE)) {
		err = -EPERM;
		goto out_unlock_inode;
	}

	/*
	 * The security check is questionable...  We single
	 * out the RO attribute for checking by the security
	 * module, just because it maps to a file mode.
	 */
	err = security_inode_setattr(file->f_path.dentry, &ia);
	if (err)
		goto out_unlock_inode;

	/* This MUST be done before doing anything irreversible... */
	err = fat_setattr(file->f_path.dentry, &ia);
	if (err)
		goto out_unlock_inode;

	fsnotify_change(file->f_path.dentry, ia.ia_valid);
	if (sbi->options.sys_immutable) {
		if (attr & ATTR_SYS)
			inode->i_flags |= S_IMMUTABLE;
		else
			inode->i_flags &= ~S_IMMUTABLE;
	}

	fat_save_attrs(inode, attr);
	mark_inode_dirty(inode);
out_unlock_inode:
	mutex_unlock(&inode->i_mutex);
	mnt_drop_write_file(file);
out:
	return err;
}

static int fat_ioctl_get_volume_id(struct inode *inode, u32 __user *user_attr)
{
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	return put_user(sbi->vol_id, user_attr);
}

long fat_generic_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	u32 __user *user_attr = (u32 __user *)arg;

	switch (cmd) {
	case FAT_IOCTL_GET_ATTRIBUTES:
		return fat_ioctl_get_attributes(inode, user_attr);
	case FAT_IOCTL_SET_ATTRIBUTES:
		return fat_ioctl_set_attributes(filp, user_attr);
	case FAT_IOCTL_GET_VOLUME_ID:
		return fat_ioctl_get_volume_id(inode, user_attr);
	default:
		return -ENOTTY;	/* Inappropriate ioctl for device */
	}
}

#ifdef CONFIG_COMPAT
static long fat_generic_compat_ioctl(struct file *filp, unsigned int cmd,
				      unsigned long arg)

{
	return fat_generic_ioctl(filp, cmd, (unsigned long)compat_ptr(arg));
}
#endif

static int fat_file_release(struct inode *inode, struct file *filp)
{
	if ((filp->f_mode & FMODE_WRITE) &&
	     MSDOS_SB(inode->i_sb)->options.flush) {
		fat_flush_inodes(inode->i_sb, inode, NULL);
		congestion_wait(BLK_RW_ASYNC, HZ/10);
	}
	return 0;
}

int fat_file_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	int res, err;

	res = generic_file_fsync(filp, start, end, datasync);
	err = sync_mapping_buffers(MSDOS_SB(inode->i_sb)->fat_inode->i_mapping);

	return res ? res : err;
}


const struct file_operations fat_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.write		= new_sync_write,
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.release	= fat_file_release,
	.unlocked_ioctl	= fat_generic_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= fat_generic_compat_ioctl,
#endif
	.fsync		= fat_file_fsync,
	.splice_read	= generic_file_splice_read,
};

static int fat_cont_expand(struct inode *inode, loff_t size)
{
	struct address_space *mapping = inode->i_mapping;
	loff_t start = inode->i_size, count = size - inode->i_size;
	int err;

	err = generic_cont_expand_simple(inode, size);
	if (err)
		goto out;

	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);
	if (IS_SYNC(inode)) {
		int err2;

		/*
		 * Opencode syncing since we don't have a file open to use
		 * standard fsync path.
		 */
		err = filemap_fdatawrite_range(mapping, start,
					       start + count - 1);
		err2 = sync_mapping_buffers(mapping);
		if (!err)
			err = err2;
		err2 = write_inode_now(inode, 1);
		if (!err)
			err = err2;
		if (!err) {
			err =  filemap_fdatawait_range(mapping, start,
						       start + count - 1);
		}
	}
out:
	return err;
}

/* Free all clusters after the skip'th cluster. */
static int fat_free(struct inode *inode, int skip)
{
	struct super_block *sb = inode->i_sb;
	int err, wait, free_start, i_start, i_logstart;

	if (MSDOS_I(inode)->i_start == 0)
		return 0;

	fat_cache_inval_inode(inode);

	wait = IS_DIRSYNC(inode);
	i_start = free_start = MSDOS_I(inode)->i_start;
	i_logstart = MSDOS_I(inode)->i_logstart;

	/* First, we write the new file size. */
	if (!skip) {
		MSDOS_I(inode)->i_start = 0;
		MSDOS_I(inode)->i_logstart = 0;
	}
	MSDOS_I(inode)->i_attrs |= ATTR_ARCH;
	inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	if (wait) {
		err = fat_sync_inode(inode);
		if (err) {
			MSDOS_I(inode)->i_start = i_start;
			MSDOS_I(inode)->i_logstart = i_logstart;
			return err;
		}
	} else
		mark_inode_dirty(inode);

	/* Write a new EOF, and get the remaining cluster chain for freeing. */
	if (skip) {
		struct fat_entry fatent;
		int ret, fclus, dclus;

		ret = fat_get_cluster(inode, skip - 1, &fclus, &dclus);
		if (ret < 0)
			return ret;
		else if (ret == FAT_ENT_EOF)
			return 0;

		fatent_init(&fatent);
		ret = fat_ent_read(inode, &fatent, dclus);
		if (ret == FAT_ENT_EOF) {
			fatent_brelse(&fatent);
			return 0;
		} else if (ret == FAT_ENT_FREE) {
			fat_fs_error(sb,
				     "%s: invalid cluster chain (i_pos %lld)",
				     __func__, MSDOS_I(inode)->i_pos);
			ret = -EIO;
		} else if (ret > 0) {
			err = fat_ent_write(inode, &fatent, FAT_ENT_EOF, wait);
			if (err)
				ret = err;
		}
		fatent_brelse(&fatent);
		if (ret < 0)
			return ret;

		free_start = ret;
	}
	inode->i_blocks = skip << (MSDOS_SB(sb)->cluster_bits - 9);

	/* Freeing the remained cluster chain */
	return fat_free_clusters(inode, free_start);
}

void fat_truncate_blocks(struct inode *inode, loff_t offset)
{
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	const unsigned int cluster_size = sbi->cluster_size;
	int nr_clusters;

	/*
	 * This protects against truncating a file bigger than it was then
	 * trying to write into the hole.
	 */
	if (MSDOS_I(inode)->mmu_private > offset)
		MSDOS_I(inode)->mmu_private = offset;

	nr_clusters = (offset + (cluster_size - 1)) >> sbi->cluster_bits;

	fat_free(inode, nr_clusters);
	fat_flush_inodes(inode->i_sb, inode, NULL);
}

int fat_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	generic_fillattr(inode, stat);
	stat->blksize = MSDOS_SB(inode->i_sb)->cluster_size;

	if (MSDOS_SB(inode->i_sb)->options.nfs == FAT_NFS_NOSTALE_RO) {
		/* Use i_pos for ino. This is used as fileid of nfs. */
		stat->ino = fat_i_pos_read(MSDOS_SB(inode->i_sb), inode);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(fat_getattr);

static int fat_sanitize_mode(const struct msdos_sb_info *sbi,
			     struct inode *inode, umode_t *mode_ptr)
{
	umode_t mask, perm;

	/*
	 * Note, the basic check is already done by a caller of
	 * (attr->ia_mode & ~FAT_VALID_MODE)
	 */

	if (S_ISREG(inode->i_mode))
		mask = sbi->options.fs_fmask;
	else
		mask = sbi->options.fs_dmask;

	perm = *mode_ptr & ~(S_IFMT | mask);

	/*
	 * Of the r and x bits, all (subject to umask) must be present. Of the
	 * w bits, either all (subject to umask) or none must be present.
	 *
	 * If fat_mode_can_hold_ro(inode) is false, can't change w bits.
	 */
	if ((perm & (S_IRUGO | S_IXUGO)) != (inode->i_mode & (S_IRUGO|S_IXUGO)))
		return -EPERM;
	if (fat_mode_can_hold_ro(inode)) {
		if ((perm & S_IWUGO) && ((perm & S_IWUGO) != (S_IWUGO & ~mask)))
			return -EPERM;
	} else {
		if ((perm & S_IWUGO) != (S_IWUGO & ~mask))
			return -EPERM;
	}

	*mode_ptr &= S_IFMT | perm;

	return 0;
}

static int fat_allow_set_time(struct msdos_sb_info *sbi, struct inode *inode)
{
	umode_t allow_utime = sbi->options.allow_utime;

	if (!uid_eq(current_fsuid(), inode->i_uid)) {
		if (in_group_p(inode->i_gid))
			allow_utime >>= 3;
		if (allow_utime & MAY_WRITE)
			return 1;
	}

	/* use a default check */
	return 0;
}

#define TIMES_SET_FLAGS	(ATTR_MTIME_SET | ATTR_ATIME_SET | ATTR_TIMES_SET)
/* valid file mode bits */
#define FAT_VALID_MODE	(S_IFREG | S_IFDIR | S_IRWXUGO)

int fat_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct msdos_sb_info *sbi = MSDOS_SB(dentry->d_sb);
	struct inode *inode = dentry->d_inode;
	unsigned int ia_valid;
	int error;

	/* Check for setting the inode time. */
	ia_valid = attr->ia_valid;
	if (ia_valid & TIMES_SET_FLAGS) {
		if (fat_allow_set_time(sbi, inode))
			attr->ia_valid &= ~TIMES_SET_FLAGS;
	}

	error = inode_change_ok(inode, attr);
	attr->ia_valid = ia_valid;
	if (error) {
		if (sbi->options.quiet)
			error = 0;
		goto out;
	}

	/*
	 * Expand the file. Since inode_setattr() updates ->i_size
	 * before calling the ->truncate(), but FAT needs to fill the
	 * hole before it. XXX: this is no longer true with new truncate
	 * sequence.
	 */
	if (attr->ia_valid & ATTR_SIZE) {
		inode_dio_wait(inode);

		if (attr->ia_size > inode->i_size) {
			error = fat_cont_expand(inode, attr->ia_size);
			if (error || attr->ia_valid == ATTR_SIZE)
				goto out;
			attr->ia_valid &= ~ATTR_SIZE;
		}
	}

	if (((attr->ia_valid & ATTR_UID) &&
	     (!uid_eq(attr->ia_uid, sbi->options.fs_uid))) ||
	    ((attr->ia_valid & ATTR_GID) &&
	     (!gid_eq(attr->ia_gid, sbi->options.fs_gid))) ||
	    ((attr->ia_valid & ATTR_MODE) &&
	     (attr->ia_mode & ~FAT_VALID_MODE)))
		error = -EPERM;

	if (error) {
		if (sbi->options.quiet)
			error = 0;
		goto out;
	}

	/*
	 * We don't return -EPERM here. Yes, strange, but this is too
	 * old behavior.
	 */
	if (attr->ia_valid & ATTR_MODE) {
		if (fat_sanitize_mode(sbi, inode, &attr->ia_mode) < 0)
			attr->ia_valid &= ~ATTR_MODE;
	}

	if (attr->ia_valid & ATTR_SIZE) {
		down_write(&MSDOS_I(inode)->truncate_lock);
		truncate_setsize(inode, attr->ia_size);
		fat_truncate_blocks(inode, attr->ia_size);
		up_write(&MSDOS_I(inode)->truncate_lock);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);
out:
	return error;
}
EXPORT_SYMBOL_GPL(fat_setattr);

const struct inode_operations fat_file_inode_operations = {
	.setattr	= fat_setattr,
	.getattr	= fat_getattr,
};
/************************************************************/
/* ../linux-3.17/fs/fat/file.c */
/************************************************************/
/*
 *  linux/fs/fat/inode.c
 *
 *  Written 1992,1993 by Werner Almesberger
 *  VFAT extensions by Gordon Chaffee, merged with msdos fs by Henrik Storner
 *  Rewritten for the constant inumbers support by Al Viro
 *
 *  Fixes:
 *
 *	Max Cohan: Fixed invalid FSINFO offset when info_sector is 0
 */

// #include <linux/module.h>
#include <linux/init.h>
// #include <linux/time.h>
// #include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/pagemap.h>
#include <linux/mpage.h>
// #include <linux/buffer_head.h>
// #include <linux/mount.h>
#include <linux/aio.h>
#include <linux/vfs.h>
#include <linux/parser.h>
#include <linux/uio.h>
// #include <linux/writeback.h>
#include <linux/log2.h>
#include <linux/hash.h>
// #include <linux/blkdev.h>
#include <asm/unaligned.h>
// #include "fat.h"

#ifndef CONFIG_FAT_DEFAULT_IOCHARSET
/* if user don't select VFAT, this is undefined. */
#define CONFIG_FAT_DEFAULT_IOCHARSET	""
#endif

#define KB_IN_SECTORS 2

/*
 * A deserialized copy of the on-disk structure laid out in struct
 * fat_boot_sector.
 */
struct fat_bios_param_block {
	u16	fat_sector_size;
	u8	fat_sec_per_clus;
	u16	fat_reserved;
	u8	fat_fats;
	u16	fat_dir_entries;
	u16	fat_sectors;
	u16	fat_fat_length;
	u32	fat_total_sect;

	u8	fat16_state;
	u32	fat16_vol_id;

	u32	fat32_length;
	u32	fat32_root_cluster;
	u16	fat32_info_sector;
	u8	fat32_state;
	u32	fat32_vol_id;
};

static int fat_default_codepage = CONFIG_FAT_DEFAULT_CODEPAGE;
static char fat_default_iocharset[] = CONFIG_FAT_DEFAULT_IOCHARSET;

static struct fat_floppy_defaults {
	unsigned nr_sectors;
	unsigned sec_per_clus;
	unsigned dir_entries;
	unsigned media;
	unsigned fat_length;
} floppy_defaults[] = {
{
	.nr_sectors = 160 * KB_IN_SECTORS,
	.sec_per_clus = 1,
	.dir_entries = 64,
	.media = 0xFE,
	.fat_length = 1,
},
{
	.nr_sectors = 180 * KB_IN_SECTORS,
	.sec_per_clus = 1,
	.dir_entries = 64,
	.media = 0xFC,
	.fat_length = 2,
},
{
	.nr_sectors = 320 * KB_IN_SECTORS,
	.sec_per_clus = 2,
	.dir_entries = 112,
	.media = 0xFF,
	.fat_length = 1,
},
{
	.nr_sectors = 360 * KB_IN_SECTORS,
	.sec_per_clus = 2,
	.dir_entries = 112,
	.media = 0xFD,
	.fat_length = 2,
},
};

static int fat_add_cluster(struct inode *inode)
{
	int err, cluster;

	err = fat_alloc_clusters(inode, &cluster, 1);
	if (err)
		return err;
	/* FIXME: this cluster should be added after data of this
	 * cluster is writed */
	err = fat_chain_add(inode, cluster, 1);
	if (err)
		fat_free_clusters(inode, cluster);
	return err;
}

static inline int __fat_get_block(struct inode *inode, sector_t iblock,
				  unsigned long *max_blocks,
				  struct buffer_head *bh_result, int create)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	unsigned long mapped_blocks;
	sector_t phys;
	int err, offset;

	err = fat_bmap(inode, iblock, &phys, &mapped_blocks, create);
	if (err)
		return err;
	if (phys) {
		map_bh(bh_result, sb, phys);
		*max_blocks = min(mapped_blocks, *max_blocks);
		return 0;
	}
	if (!create)
		return 0;

	if (iblock != MSDOS_I(inode)->mmu_private >> sb->s_blocksize_bits) {
		fat_fs_error(sb, "corrupted file size (i_pos %lld, %lld)",
			MSDOS_I(inode)->i_pos, MSDOS_I(inode)->mmu_private);
		return -EIO;
	}

	offset = (unsigned long)iblock & (sbi->sec_per_clus - 1);
	if (!offset) {
		/* TODO: multiple cluster allocation would be desirable. */
		err = fat_add_cluster(inode);
		if (err)
			return err;
	}
	/* available blocks on this cluster */
	mapped_blocks = sbi->sec_per_clus - offset;

	*max_blocks = min(mapped_blocks, *max_blocks);
	MSDOS_I(inode)->mmu_private += *max_blocks << sb->s_blocksize_bits;

	err = fat_bmap(inode, iblock, &phys, &mapped_blocks, create);
	if (err)
		return err;

	BUG_ON(!phys);
	BUG_ON(*max_blocks != mapped_blocks);
	set_buffer_new(bh_result);
	map_bh(bh_result, sb, phys);

	return 0;
}

static int fat_get_block(struct inode *inode, sector_t iblock,
			 struct buffer_head *bh_result, int create)
{
	struct super_block *sb = inode->i_sb;
	unsigned long max_blocks = bh_result->b_size >> inode->i_blkbits;
	int err;

	err = __fat_get_block(inode, iblock, &max_blocks, bh_result, create);
	if (err)
		return err;
	bh_result->b_size = max_blocks << sb->s_blocksize_bits;
	return 0;
}

static int fat_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, fat_get_block, wbc);
}

static int fat_writepages(struct address_space *mapping,
			  struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, fat_get_block);
}

static int fat_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, fat_get_block);
}

static int fat_readpages(struct file *file, struct address_space *mapping,
			 struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, fat_get_block);
}

static void fat_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		fat_truncate_blocks(inode, inode->i_size);
	}
}

static int fat_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int err;

	*pagep = NULL;
	err = cont_write_begin(file, mapping, pos, len, flags,
				pagep, fsdata, fat_get_block,
				&MSDOS_I(mapping->host)->mmu_private);
	if (err < 0)
		fat_write_failed(mapping, pos + len);
	return err;
}

static int fat_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *pagep, void *fsdata)
{
	struct inode *inode = mapping->host;
	int err;
	err = generic_write_end(file, mapping, pos, len, copied, pagep, fsdata);
	if (err < len)
		fat_write_failed(mapping, pos + len);
	if (!(err < 0) && !(MSDOS_I(inode)->i_attrs & ATTR_ARCH)) {
		inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
		MSDOS_I(inode)->i_attrs |= ATTR_ARCH;
		mark_inode_dirty(inode);
	}
	return err;
}

static ssize_t fat_direct_IO(int rw, struct kiocb *iocb,
			     struct iov_iter *iter,
			     loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	size_t count = iov_iter_count(iter);
	ssize_t ret;

	if (rw == WRITE) {
		/*
		 * FIXME: blockdev_direct_IO() doesn't use ->write_begin(),
		 * so we need to update the ->mmu_private to block boundary.
		 *
		 * But we must fill the remaining area or hole by nul for
		 * updating ->mmu_private.
		 *
		 * Return 0, and fallback to normal buffered write.
		 */
		loff_t size = offset + count;
		if (MSDOS_I(inode)->mmu_private < size)
			return 0;
	}

	/*
	 * FAT need to use the DIO_LOCKING for avoiding the race
	 * condition of fat_get_block() and ->truncate().
	 */
	ret = blockdev_direct_IO(rw, iocb, inode, iter, offset, fat_get_block);
	if (ret < 0 && (rw & WRITE))
		fat_write_failed(mapping, offset + count);

	return ret;
}

static sector_t _fat_bmap(struct address_space *mapping, sector_t block)
{
	sector_t blocknr;

	/* fat_get_cluster() assumes the requested blocknr isn't truncated. */
	down_read(&MSDOS_I(mapping->host)->truncate_lock);
	blocknr = generic_block_bmap(mapping, block, fat_get_block);
	up_read(&MSDOS_I(mapping->host)->truncate_lock);

	return blocknr;
}

static const struct address_space_operations fat_aops = {
	.readpage	= fat_readpage,
	.readpages	= fat_readpages,
	.writepage	= fat_writepage,
	.writepages	= fat_writepages,
	.write_begin	= fat_write_begin,
	.write_end	= fat_write_end,
	.direct_IO	= fat_direct_IO,
	.bmap		= _fat_bmap
};

/*
 * New FAT inode stuff. We do the following:
 *	a) i_ino is constant and has nothing with on-disk location.
 *	b) FAT manages its own cache of directory entries.
 *	c) *This* cache is indexed by on-disk location.
 *	d) inode has an associated directory entry, all right, but
 *		it may be unhashed.
 *	e) currently entries are stored within struct inode. That should
 *		change.
 *	f) we deal with races in the following way:
 *		1. readdir() and lookup() do FAT-dir-cache lookup.
 *		2. rename() unhashes the F-d-c entry and rehashes it in
 *			a new place.
 *		3. unlink() and rmdir() unhash F-d-c entry.
 *		4. fat_write_inode() checks whether the thing is unhashed.
 *			If it is we silently return. If it isn't we do bread(),
 *			check if the location is still valid and retry if it
 *			isn't. Otherwise we do changes.
 *		5. Spinlock is used to protect hash/unhash/location check/lookup
 *		6. fat_evict_inode() unhashes the F-d-c entry.
 *		7. lookup() and readdir() do igrab() if they find a F-d-c entry
 *			and consider negative result as cache miss.
 */

static void fat_hash_init(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	int i;

	spin_lock_init(&sbi->inode_hash_lock);
	for (i = 0; i < FAT_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&sbi->inode_hashtable[i]);
}

static inline unsigned long fat_hash(loff_t i_pos)
{
	return hash_32(i_pos, FAT_HASH_BITS);
}

static void dir_hash_init(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	int i;

	spin_lock_init(&sbi->dir_hash_lock);
	for (i = 0; i < FAT_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&sbi->dir_hashtable[i]);
}

void fat_attach(struct inode *inode, loff_t i_pos)
{
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);

	if (inode->i_ino != MSDOS_ROOT_INO) {
		struct hlist_head *head =   sbi->inode_hashtable
					  + fat_hash(i_pos);

		spin_lock(&sbi->inode_hash_lock);
		MSDOS_I(inode)->i_pos = i_pos;
		hlist_add_head(&MSDOS_I(inode)->i_fat_hash, head);
		spin_unlock(&sbi->inode_hash_lock);
	}

	/* If NFS support is enabled, cache the mapping of start cluster
	 * to directory inode. This is used during reconnection of
	 * dentries to the filesystem root.
	 */
	if (S_ISDIR(inode->i_mode) && sbi->options.nfs) {
		struct hlist_head *d_head = sbi->dir_hashtable;
		d_head += fat_dir_hash(MSDOS_I(inode)->i_logstart);

		spin_lock(&sbi->dir_hash_lock);
		hlist_add_head(&MSDOS_I(inode)->i_dir_hash, d_head);
		spin_unlock(&sbi->dir_hash_lock);
	}
}
EXPORT_SYMBOL_GPL(fat_attach);

void fat_detach(struct inode *inode)
{
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	spin_lock(&sbi->inode_hash_lock);
	MSDOS_I(inode)->i_pos = 0;
	hlist_del_init(&MSDOS_I(inode)->i_fat_hash);
	spin_unlock(&sbi->inode_hash_lock);

	if (S_ISDIR(inode->i_mode) && sbi->options.nfs) {
		spin_lock(&sbi->dir_hash_lock);
		hlist_del_init(&MSDOS_I(inode)->i_dir_hash);
		spin_unlock(&sbi->dir_hash_lock);
	}
}
EXPORT_SYMBOL_GPL(fat_detach);

struct inode *fat_iget(struct super_block *sb, loff_t i_pos)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct hlist_head *head = sbi->inode_hashtable + fat_hash(i_pos);
	struct msdos_inode_info *i;
	struct inode *inode = NULL;

	spin_lock(&sbi->inode_hash_lock);
	hlist_for_each_entry(i, head, i_fat_hash) {
		BUG_ON(i->vfs_inode.i_sb != sb);
		if (i->i_pos != i_pos)
			continue;
		inode = igrab(&i->vfs_inode);
		if (inode)
			break;
	}
	spin_unlock(&sbi->inode_hash_lock);
	return inode;
}

static int is_exec(unsigned char *extension)
{
	unsigned char exe_extensions[] = "EXECOMBAT", *walk;

	for (walk = exe_extensions; *walk; walk += 3)
		if (!strncmp(extension, walk, 3))
			return 1;
	return 0;
}

static int fat_calc_dir_size(struct inode *inode)
{
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	int ret, fclus, dclus;

	inode->i_size = 0;
	if (MSDOS_I(inode)->i_start == 0)
		return 0;

	ret = fat_get_cluster(inode, FAT_ENT_EOF, &fclus, &dclus);
	if (ret < 0)
		return ret;
	inode->i_size = (fclus + 1) << sbi->cluster_bits;

	return 0;
}

/* doesn't deal with root inode */
int fat_fill_inode(struct inode *inode, struct msdos_dir_entry *de)
{
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	int error;

	MSDOS_I(inode)->i_pos = 0;
	inode->i_uid = sbi->options.fs_uid;
	inode->i_gid = sbi->options.fs_gid;
	inode->i_version++;
	inode->i_generation = get_seconds();

	if ((de->attr & ATTR_DIR) && !IS_FREE(de->name)) {
		inode->i_generation &= ~1;
		inode->i_mode = fat_make_mode(sbi, de->attr, S_IRWXUGO);
		inode->i_op = sbi->dir_ops;
		inode->i_fop = &fat_dir_operations;

		MSDOS_I(inode)->i_start = fat_get_start(sbi, de);
		MSDOS_I(inode)->i_logstart = MSDOS_I(inode)->i_start;
		error = fat_calc_dir_size(inode);
		if (error < 0)
			return error;
		MSDOS_I(inode)->mmu_private = inode->i_size;

		set_nlink(inode, fat_subdirs(inode));
	} else { /* not a directory */
		inode->i_generation |= 1;
		inode->i_mode = fat_make_mode(sbi, de->attr,
			((sbi->options.showexec && !is_exec(de->name + 8))
			 ? S_IRUGO|S_IWUGO : S_IRWXUGO));
		MSDOS_I(inode)->i_start = fat_get_start(sbi, de);

		MSDOS_I(inode)->i_logstart = MSDOS_I(inode)->i_start;
		inode->i_size = le32_to_cpu(de->size);
		inode->i_op = &fat_file_inode_operations;
		inode->i_fop = &fat_file_operations;
		inode->i_mapping->a_ops = &fat_aops;
		MSDOS_I(inode)->mmu_private = inode->i_size;
	}
	if (de->attr & ATTR_SYS) {
		if (sbi->options.sys_immutable)
			inode->i_flags |= S_IMMUTABLE;
	}
	fat_save_attrs(inode, de->attr);

	inode->i_blocks = ((inode->i_size + (sbi->cluster_size - 1))
			   & ~((loff_t)sbi->cluster_size - 1)) >> 9;

	fat_time_fat2unix(sbi, &inode->i_mtime, de->time, de->date, 0);
	if (sbi->options.isvfat) {
		fat_time_fat2unix(sbi, &inode->i_ctime, de->ctime,
				  de->cdate, de->ctime_cs);
		fat_time_fat2unix(sbi, &inode->i_atime, 0, de->adate, 0);
	} else
		inode->i_ctime = inode->i_atime = inode->i_mtime;

	return 0;
}

static inline void fat_lock_build_inode(struct msdos_sb_info *sbi)
{
	if (sbi->options.nfs == FAT_NFS_NOSTALE_RO)
		mutex_lock(&sbi->nfs_build_inode_lock);
}

static inline void fat_unlock_build_inode(struct msdos_sb_info *sbi)
{
	if (sbi->options.nfs == FAT_NFS_NOSTALE_RO)
		mutex_unlock(&sbi->nfs_build_inode_lock);
}

struct inode *fat_build_inode(struct super_block *sb,
			struct msdos_dir_entry *de, loff_t i_pos)
{
	struct inode *inode;
	int err;

	fat_lock_build_inode(MSDOS_SB(sb));
	inode = fat_iget(sb, i_pos);
	if (inode)
		goto out;
	inode = new_inode(sb);
	if (!inode) {
		inode = ERR_PTR(-ENOMEM);
		goto out;
	}
	inode->i_ino = iunique(sb, MSDOS_ROOT_INO);
	inode->i_version = 1;
	err = fat_fill_inode(inode, de);
	if (err) {
		iput(inode);
		inode = ERR_PTR(err);
		goto out;
	}
	fat_attach(inode, i_pos);
	insert_inode_hash(inode);
out:
	fat_unlock_build_inode(MSDOS_SB(sb));
	return inode;
}

EXPORT_SYMBOL_GPL(fat_build_inode);

static void fat_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	if (!inode->i_nlink) {
		inode->i_size = 0;
		fat_truncate_blocks(inode, 0);
	}
	invalidate_inode_buffers(inode);
	clear_inode(inode);
	fat_cache_inval_inode(inode);
	fat_detach(inode);
}

static void fat_set_state(struct super_block *sb,
			unsigned int set, unsigned int force)
{
	struct buffer_head *bh;
	struct fat_boot_sector *b;
	struct msdos_sb_info *sbi = sb->s_fs_info;

	/* do not change any thing if mounted read only */
	if ((sb->s_flags & MS_RDONLY) && !force)
		return;

	/* do not change state if fs was dirty */
	if (sbi->dirty) {
		/* warn only on set (mount). */
		if (set)
			fat_msg(sb, KERN_WARNING, "Volume was not properly "
				"unmounted. Some data may be corrupt. "
				"Please run fsck.");
		return;
	}

	bh = sb_bread(sb, 0);
	if (bh == NULL) {
		fat_msg(sb, KERN_ERR, "unable to read boot sector "
			"to mark fs as dirty");
		return;
	}

	b = (struct fat_boot_sector *) bh->b_data;

	if (sbi->fat_bits == 32) {
		if (set)
			b->fat32.state |= FAT_STATE_DIRTY;
		else
			b->fat32.state &= ~FAT_STATE_DIRTY;
	} else /* fat 16 and 12 */ {
		if (set)
			b->fat16.state |= FAT_STATE_DIRTY;
		else
			b->fat16.state &= ~FAT_STATE_DIRTY;
	}

	mark_buffer_dirty(bh);
	sync_dirty_buffer(bh);
	brelse(bh);
}

static void delayed_free(struct rcu_head *p)
{
	struct msdos_sb_info *sbi = container_of(p, struct msdos_sb_info, rcu);
	unload_nls(sbi->nls_disk);
	unload_nls(sbi->nls_io);
	if (sbi->options.iocharset != fat_default_iocharset)
		kfree(sbi->options.iocharset);
	kfree(sbi);
}

static void fat_put_super(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);

	fat_set_state(sb, 0, 0);

	iput(sbi->fsinfo_inode);
	iput(sbi->fat_inode);

	call_rcu(&sbi->rcu, delayed_free);
}

static struct kmem_cache *fat_inode_cachep;

static struct inode *fat_alloc_inode(struct super_block *sb)
{
	struct msdos_inode_info *ei;
	ei = kmem_cache_alloc(fat_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	init_rwsem(&ei->truncate_lock);
	return &ei->vfs_inode;
}

static void fat_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(fat_inode_cachep, MSDOS_I(inode));
}

static void fat_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, fat_i_callback);
}

static void init_once_inode_c(void *foo)
{
	struct msdos_inode_info *ei = (struct msdos_inode_info *)foo;

	spin_lock_init(&ei->cache_lru_lock);
	ei->nr_caches = 0;
	ei->cache_valid_id = FAT_CACHE_VALID + 1;
	INIT_LIST_HEAD(&ei->cache_lru);
	INIT_HLIST_NODE(&ei->i_fat_hash);
	INIT_HLIST_NODE(&ei->i_dir_hash);
	inode_init_once(&ei->vfs_inode);
}

static int __init fat_init_inodecache(void)
{
	fat_inode_cachep = kmem_cache_create("fat_inode_cache",
					     sizeof(struct msdos_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once_inode_c);
	if (fat_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void __exit fat_destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(fat_inode_cachep);
}

static int fat_remount(struct super_block *sb, int *flags, char *data)
{
	int new_rdonly;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	*flags |= MS_NODIRATIME | (sbi->options.isvfat ? 0 : MS_NOATIME);

	sync_filesystem(sb);

	/* make sure we update state on remount. */
	new_rdonly = *flags & MS_RDONLY;
	if (new_rdonly != (sb->s_flags & MS_RDONLY)) {
		if (new_rdonly)
			fat_set_state(sb, 0, 0);
		else
			fat_set_state(sb, 1, 1);
	}
	return 0;
}

static int fat_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	/* If the count of free cluster is still unknown, counts it here. */
	if (sbi->free_clusters == -1 || !sbi->free_clus_valid) {
		int err = fat_count_free_clusters(dentry->d_sb);
		if (err)
			return err;
	}

	buf->f_type = dentry->d_sb->s_magic;
	buf->f_bsize = sbi->cluster_size;
	buf->f_blocks = sbi->max_cluster - FAT_START_ENT;
	buf->f_bfree = sbi->free_clusters;
	buf->f_bavail = sbi->free_clusters;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen =
		(sbi->options.isvfat ? FAT_LFN_LEN : 12) * NLS_MAX_CHARSET_SIZE;

	return 0;
}

static int __fat_write_inode(struct inode *inode, int wait)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bh;
	struct msdos_dir_entry *raw_entry;
	loff_t i_pos;
	sector_t blocknr;
	int err, offset;

	if (inode->i_ino == MSDOS_ROOT_INO)
		return 0;

retry:
	i_pos = fat_i_pos_read(sbi, inode);
	if (!i_pos)
		return 0;

	fat_get_blknr_offset(sbi, i_pos, &blocknr, &offset);
	bh = sb_bread(sb, blocknr);
	if (!bh) {
		fat_msg(sb, KERN_ERR, "unable to read inode block "
		       "for updating (i_pos %lld)", i_pos);
		return -EIO;
	}
	spin_lock(&sbi->inode_hash_lock);
	if (i_pos != MSDOS_I(inode)->i_pos) {
		spin_unlock(&sbi->inode_hash_lock);
		brelse(bh);
		goto retry;
	}

	raw_entry = &((struct msdos_dir_entry *) (bh->b_data))[offset];
	if (S_ISDIR(inode->i_mode))
		raw_entry->size = 0;
	else
		raw_entry->size = cpu_to_le32(inode->i_size);
	raw_entry->attr = fat_make_attrs(inode);
	fat_set_start(raw_entry, MSDOS_I(inode)->i_logstart);
	fat_time_unix2fat(sbi, &inode->i_mtime, &raw_entry->time,
			  &raw_entry->date, NULL);
	if (sbi->options.isvfat) {
		__le16 atime;
		fat_time_unix2fat(sbi, &inode->i_ctime, &raw_entry->ctime,
				  &raw_entry->cdate, &raw_entry->ctime_cs);
		fat_time_unix2fat(sbi, &inode->i_atime, &atime,
				  &raw_entry->adate, NULL);
	}
	spin_unlock(&sbi->inode_hash_lock);
	mark_buffer_dirty(bh);
	err = 0;
	if (wait)
		err = sync_dirty_buffer(bh);
	brelse(bh);
	return err;
}

static int fat_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	int err;

	if (inode->i_ino == MSDOS_FSINFO_INO) {
		struct super_block *sb = inode->i_sb;

		mutex_lock(&MSDOS_SB(sb)->s_lock);
		err = fat_clusters_flush(sb);
		mutex_unlock(&MSDOS_SB(sb)->s_lock);
	} else
		err = __fat_write_inode(inode, wbc->sync_mode == WB_SYNC_ALL);

	return err;
}

int fat_sync_inode(struct inode *inode)
{
	return __fat_write_inode(inode, 1);
}

EXPORT_SYMBOL_GPL(fat_sync_inode);

static int fat_show_options(struct seq_file *m, struct dentry *root);
static const struct super_operations fat_sops = {
	.alloc_inode	= fat_alloc_inode,
	.destroy_inode	= fat_destroy_inode,
	.write_inode	= fat_write_inode,
	.evict_inode	= fat_evict_inode,
	.put_super	= fat_put_super,
	.statfs		= fat_statfs,
	.remount_fs	= fat_remount,

	.show_options	= fat_show_options,
};

static int fat_show_options(struct seq_file *m, struct dentry *root)
{
	struct msdos_sb_info *sbi = MSDOS_SB(root->d_sb);
	struct fat_mount_options *opts = &sbi->options;
	int isvfat = opts->isvfat;

	if (!uid_eq(opts->fs_uid, GLOBAL_ROOT_UID))
		seq_printf(m, ",uid=%u",
				from_kuid_munged(&init_user_ns, opts->fs_uid));
	if (!gid_eq(opts->fs_gid, GLOBAL_ROOT_GID))
		seq_printf(m, ",gid=%u",
				from_kgid_munged(&init_user_ns, opts->fs_gid));
	seq_printf(m, ",fmask=%04o", opts->fs_fmask);
	seq_printf(m, ",dmask=%04o", opts->fs_dmask);
	if (opts->allow_utime)
		seq_printf(m, ",allow_utime=%04o", opts->allow_utime);
	if (sbi->nls_disk)
		/* strip "cp" prefix from displayed option */
		seq_printf(m, ",codepage=%s", &sbi->nls_disk->charset[2]);
	if (isvfat) {
		if (sbi->nls_io)
			seq_printf(m, ",iocharset=%s", sbi->nls_io->charset);

		switch (opts->shortname) {
		case VFAT_SFN_DISPLAY_WIN95 | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=win95");
			break;
		case VFAT_SFN_DISPLAY_WINNT | VFAT_SFN_CREATE_WINNT:
			seq_puts(m, ",shortname=winnt");
			break;
		case VFAT_SFN_DISPLAY_WINNT | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=mixed");
			break;
		case VFAT_SFN_DISPLAY_LOWER | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=lower");
			break;
		default:
			seq_puts(m, ",shortname=unknown");
			break;
		}
	}
	if (opts->name_check != 'n')
		seq_printf(m, ",check=%c", opts->name_check);
	if (opts->usefree)
		seq_puts(m, ",usefree");
	if (opts->quiet)
		seq_puts(m, ",quiet");
	if (opts->showexec)
		seq_puts(m, ",showexec");
	if (opts->sys_immutable)
		seq_puts(m, ",sys_immutable");
	if (!isvfat) {
		if (opts->dotsOK)
			seq_puts(m, ",dotsOK=yes");
		if (opts->nocase)
			seq_puts(m, ",nocase");
	} else {
		if (opts->utf8)
			seq_puts(m, ",utf8");
		if (opts->unicode_xlate)
			seq_puts(m, ",uni_xlate");
		if (!opts->numtail)
			seq_puts(m, ",nonumtail");
		if (opts->rodir)
			seq_puts(m, ",rodir");
	}
	if (opts->flush)
		seq_puts(m, ",flush");
	if (opts->tz_set) {
		if (opts->time_offset)
			seq_printf(m, ",time_offset=%d", opts->time_offset);
		else
			seq_puts(m, ",tz=UTC");
	}
	if (opts->errors == FAT_ERRORS_CONT)
		seq_puts(m, ",errors=continue");
	else if (opts->errors == FAT_ERRORS_PANIC)
		seq_puts(m, ",errors=panic");
	else
		seq_puts(m, ",errors=remount-ro");
	if (opts->nfs == FAT_NFS_NOSTALE_RO)
		seq_puts(m, ",nfs=nostale_ro");
	else if (opts->nfs)
		seq_puts(m, ",nfs=stale_rw");
	if (opts->discard)
		seq_puts(m, ",discard");
	if (opts->dos1xfloppy)
		seq_puts(m, ",dos1xfloppy");

	return 0;
}

enum {
	Opt_check_n, Opt_check_r, Opt_check_s, Opt_uid, Opt_gid,
	Opt_umask, Opt_dmask, Opt_fmask, Opt_allow_utime, Opt_codepage,
	Opt_usefree, Opt_nocase, Opt_quiet, Opt_showexec, Opt_debug,
	Opt_immutable, Opt_dots, Opt_nodots,
	Opt_charset, Opt_shortname_lower, Opt_shortname_win95,
	Opt_shortname_winnt, Opt_shortname_mixed, Opt_utf8_no, Opt_utf8_yes,
	Opt_uni_xl_no, Opt_uni_xl_yes, Opt_nonumtail_no, Opt_nonumtail_yes,
	Opt_obsolete, Opt_flush, Opt_tz_utc, Opt_rodir, Opt_err_cont,
	Opt_err_panic, Opt_err_ro, Opt_discard, Opt_nfs, Opt_time_offset,
	Opt_nfs_stale_rw, Opt_nfs_nostale_ro, Opt_err, Opt_dos1xfloppy,
};

static const match_table_t fat_tokens = {
	{Opt_check_r, "check=relaxed"},
	{Opt_check_s, "check=strict"},
	{Opt_check_n, "check=normal"},
	{Opt_check_r, "check=r"},
	{Opt_check_s, "check=s"},
	{Opt_check_n, "check=n"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_umask, "umask=%o"},
	{Opt_dmask, "dmask=%o"},
	{Opt_fmask, "fmask=%o"},
	{Opt_allow_utime, "allow_utime=%o"},
	{Opt_codepage, "codepage=%u"},
	{Opt_usefree, "usefree"},
	{Opt_nocase, "nocase"},
	{Opt_quiet, "quiet"},
	{Opt_showexec, "showexec"},
	{Opt_debug, "debug"},
	{Opt_immutable, "sys_immutable"},
	{Opt_flush, "flush"},
	{Opt_tz_utc, "tz=UTC"},
	{Opt_time_offset, "time_offset=%d"},
	{Opt_err_cont, "errors=continue"},
	{Opt_err_panic, "errors=panic"},
	{Opt_err_ro, "errors=remount-ro"},
	{Opt_discard, "discard"},
	{Opt_nfs_stale_rw, "nfs"},
	{Opt_nfs_stale_rw, "nfs=stale_rw"},
	{Opt_nfs_nostale_ro, "nfs=nostale_ro"},
	{Opt_dos1xfloppy, "dos1xfloppy"},
	{Opt_obsolete, "conv=binary"},
	{Opt_obsolete, "conv=text"},
	{Opt_obsolete, "conv=auto"},
	{Opt_obsolete, "conv=b"},
	{Opt_obsolete, "conv=t"},
	{Opt_obsolete, "conv=a"},
	{Opt_obsolete, "fat=%u"},
	{Opt_obsolete, "blocksize=%u"},
	{Opt_obsolete, "cvf_format=%20s"},
	{Opt_obsolete, "cvf_options=%100s"},
	{Opt_obsolete, "posix"},
	{Opt_err, NULL},
};
static const match_table_t msdos_tokens = {
	{Opt_nodots, "nodots"},
	{Opt_nodots, "dotsOK=no"},
	{Opt_dots, "dots"},
	{Opt_dots, "dotsOK=yes"},
	{Opt_err, NULL}
};
static const match_table_t vfat_tokens = {
	{Opt_charset, "iocharset=%s"},
	{Opt_shortname_lower, "shortname=lower"},
	{Opt_shortname_win95, "shortname=win95"},
	{Opt_shortname_winnt, "shortname=winnt"},
	{Opt_shortname_mixed, "shortname=mixed"},
	{Opt_utf8_no, "utf8=0"},		/* 0 or no or false */
	{Opt_utf8_no, "utf8=no"},
	{Opt_utf8_no, "utf8=false"},
	{Opt_utf8_yes, "utf8=1"},		/* empty or 1 or yes or true */
	{Opt_utf8_yes, "utf8=yes"},
	{Opt_utf8_yes, "utf8=true"},
	{Opt_utf8_yes, "utf8"},
	{Opt_uni_xl_no, "uni_xlate=0"},		/* 0 or no or false */
	{Opt_uni_xl_no, "uni_xlate=no"},
	{Opt_uni_xl_no, "uni_xlate=false"},
	{Opt_uni_xl_yes, "uni_xlate=1"},	/* empty or 1 or yes or true */
	{Opt_uni_xl_yes, "uni_xlate=yes"},
	{Opt_uni_xl_yes, "uni_xlate=true"},
	{Opt_uni_xl_yes, "uni_xlate"},
	{Opt_nonumtail_no, "nonumtail=0"},	/* 0 or no or false */
	{Opt_nonumtail_no, "nonumtail=no"},
	{Opt_nonumtail_no, "nonumtail=false"},
	{Opt_nonumtail_yes, "nonumtail=1"},	/* empty or 1 or yes or true */
	{Opt_nonumtail_yes, "nonumtail=yes"},
	{Opt_nonumtail_yes, "nonumtail=true"},
	{Opt_nonumtail_yes, "nonumtail"},
	{Opt_rodir, "rodir"},
	{Opt_err, NULL}
};

static int parse_options(struct super_block *sb, char *options, int is_vfat,
			 int silent, int *debug, struct fat_mount_options *opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	char *iocharset;

	opts->isvfat = is_vfat;

	opts->fs_uid = current_uid();
	opts->fs_gid = current_gid();
	opts->fs_fmask = opts->fs_dmask = current_umask();
	opts->allow_utime = -1;
	opts->codepage = fat_default_codepage;
	opts->iocharset = fat_default_iocharset;
	if (is_vfat) {
		opts->shortname = VFAT_SFN_DISPLAY_WINNT|VFAT_SFN_CREATE_WIN95;
		opts->rodir = 0;
	} else {
		opts->shortname = 0;
		opts->rodir = 1;
	}
	opts->name_check = 'n';
	opts->quiet = opts->showexec = opts->sys_immutable = opts->dotsOK =  0;
	opts->utf8 = opts->unicode_xlate = 0;
	opts->numtail = 1;
	opts->usefree = opts->nocase = 0;
	opts->tz_set = 0;
	opts->nfs = 0;
	opts->errors = FAT_ERRORS_RO;
	*debug = 0;

	if (!options)
		goto out;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		if (!*p)
			continue;

		token = match_token(p, fat_tokens, args);
		if (token == Opt_err) {
			if (is_vfat)
				token = match_token(p, vfat_tokens, args);
			else
				token = match_token(p, msdos_tokens, args);
		}
		switch (token) {
		case Opt_check_s:
			opts->name_check = 's';
			break;
		case Opt_check_r:
			opts->name_check = 'r';
			break;
		case Opt_check_n:
			opts->name_check = 'n';
			break;
		case Opt_usefree:
			opts->usefree = 1;
			break;
		case Opt_nocase:
			if (!is_vfat)
				opts->nocase = 1;
			else {
				/* for backward compatibility */
				opts->shortname = VFAT_SFN_DISPLAY_WIN95
					| VFAT_SFN_CREATE_WIN95;
			}
			break;
		case Opt_quiet:
			opts->quiet = 1;
			break;
		case Opt_showexec:
			opts->showexec = 1;
			break;
		case Opt_debug:
			*debug = 1;
			break;
		case Opt_immutable:
			opts->sys_immutable = 1;
			break;
		case Opt_uid:
			if (match_int(&args[0], &option))
				return -EINVAL;
			opts->fs_uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(opts->fs_uid))
				return -EINVAL;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return -EINVAL;
			opts->fs_gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(opts->fs_gid))
				return -EINVAL;
			break;
		case Opt_umask:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->fs_fmask = opts->fs_dmask = option;
			break;
		case Opt_dmask:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->fs_dmask = option;
			break;
		case Opt_fmask:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->fs_fmask = option;
			break;
		case Opt_allow_utime:
			if (match_octal(&args[0], &option))
				return -EINVAL;
			opts->allow_utime = option & (S_IWGRP | S_IWOTH);
			break;
		case Opt_codepage:
			if (match_int(&args[0], &option))
				return -EINVAL;
			opts->codepage = option;
			break;
		case Opt_flush:
			opts->flush = 1;
			break;
		case Opt_time_offset:
			if (match_int(&args[0], &option))
				return -EINVAL;
			if (option < -12 * 60 || option > 12 * 60)
				return -EINVAL;
			opts->tz_set = 1;
			opts->time_offset = option;
			break;
		case Opt_tz_utc:
			opts->tz_set = 1;
			opts->time_offset = 0;
			break;
		case Opt_err_cont:
			opts->errors = FAT_ERRORS_CONT;
			break;
		case Opt_err_panic:
			opts->errors = FAT_ERRORS_PANIC;
			break;
		case Opt_err_ro:
			opts->errors = FAT_ERRORS_RO;
			break;
		case Opt_nfs_stale_rw:
			opts->nfs = FAT_NFS_STALE_RW;
			break;
		case Opt_nfs_nostale_ro:
			opts->nfs = FAT_NFS_NOSTALE_RO;
			break;
		case Opt_dos1xfloppy:
			opts->dos1xfloppy = 1;
			break;

		/* msdos specific */
		case Opt_dots:
			opts->dotsOK = 1;
			break;
		case Opt_nodots:
			opts->dotsOK = 0;
			break;

		/* vfat specific */
		case Opt_charset:
			if (opts->iocharset != fat_default_iocharset)
				kfree(opts->iocharset);
			iocharset = match_strdup(&args[0]);
			if (!iocharset)
				return -ENOMEM;
			opts->iocharset = iocharset;
			break;
		case Opt_shortname_lower:
			opts->shortname = VFAT_SFN_DISPLAY_LOWER
					| VFAT_SFN_CREATE_WIN95;
			break;
		case Opt_shortname_win95:
			opts->shortname = VFAT_SFN_DISPLAY_WIN95
					| VFAT_SFN_CREATE_WIN95;
			break;
		case Opt_shortname_winnt:
			opts->shortname = VFAT_SFN_DISPLAY_WINNT
					| VFAT_SFN_CREATE_WINNT;
			break;
		case Opt_shortname_mixed:
			opts->shortname = VFAT_SFN_DISPLAY_WINNT
					| VFAT_SFN_CREATE_WIN95;
			break;
		case Opt_utf8_no:		/* 0 or no or false */
			opts->utf8 = 0;
			break;
		case Opt_utf8_yes:		/* empty or 1 or yes or true */
			opts->utf8 = 1;
			break;
		case Opt_uni_xl_no:		/* 0 or no or false */
			opts->unicode_xlate = 0;
			break;
		case Opt_uni_xl_yes:		/* empty or 1 or yes or true */
			opts->unicode_xlate = 1;
			break;
		case Opt_nonumtail_no:		/* 0 or no or false */
			opts->numtail = 1;	/* negated option */
			break;
		case Opt_nonumtail_yes:		/* empty or 1 or yes or true */
			opts->numtail = 0;	/* negated option */
			break;
		case Opt_rodir:
			opts->rodir = 1;
			break;
		case Opt_discard:
			opts->discard = 1;
			break;

		/* obsolete mount options */
		case Opt_obsolete:
			fat_msg(sb, KERN_INFO, "\"%s\" option is obsolete, "
			       "not supported now", p);
			break;
		/* unknown option */
		default:
			if (!silent) {
				fat_msg(sb, KERN_ERR,
				       "Unrecognized mount option \"%s\" "
				       "or missing value", p);
			}
			return -EINVAL;
		}
	}

out:
	/* UTF-8 doesn't provide FAT semantics */
	if (!strcmp(opts->iocharset, "utf8")) {
		fat_msg(sb, KERN_WARNING, "utf8 is not a recommended IO charset"
		       " for FAT filesystems, filesystem will be "
		       "case sensitive!");
	}

	/* If user doesn't specify allow_utime, it's initialized from dmask. */
	if (opts->allow_utime == (unsigned short)-1)
		opts->allow_utime = ~opts->fs_dmask & (S_IWGRP | S_IWOTH);
	if (opts->unicode_xlate)
		opts->utf8 = 0;
	if (opts->nfs == FAT_NFS_NOSTALE_RO) {
		sb->s_flags |= MS_RDONLY;
		sb->s_export_op = &fat_export_ops_nostale;
	}

	return 0;
}

static int fat_read_root(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	int error;

	MSDOS_I(inode)->i_pos = MSDOS_ROOT_INO;
	inode->i_uid = sbi->options.fs_uid;
	inode->i_gid = sbi->options.fs_gid;
	inode->i_version++;
	inode->i_generation = 0;
	inode->i_mode = fat_make_mode(sbi, ATTR_DIR, S_IRWXUGO);
	inode->i_op = sbi->dir_ops;
	inode->i_fop = &fat_dir_operations;
	if (sbi->fat_bits == 32) {
		MSDOS_I(inode)->i_start = sbi->root_cluster;
		error = fat_calc_dir_size(inode);
		if (error < 0)
			return error;
	} else {
		MSDOS_I(inode)->i_start = 0;
		inode->i_size = sbi->dir_entries * sizeof(struct msdos_dir_entry);
	}
	inode->i_blocks = ((inode->i_size + (sbi->cluster_size - 1))
			   & ~((loff_t)sbi->cluster_size - 1)) >> 9;
	MSDOS_I(inode)->i_logstart = 0;
	MSDOS_I(inode)->mmu_private = inode->i_size;

	fat_save_attrs(inode, ATTR_DIR);
	inode->i_mtime.tv_sec = inode->i_atime.tv_sec = inode->i_ctime.tv_sec = 0;
	inode->i_mtime.tv_nsec = inode->i_atime.tv_nsec = inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, fat_subdirs(inode)+2);

	return 0;
}

static unsigned long calc_fat_clusters(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);

	/* Divide first to avoid overflow */
	if (sbi->fat_bits != 12) {
		unsigned long ent_per_sec = sb->s_blocksize * 8 / sbi->fat_bits;
		return ent_per_sec * sbi->fat_length;
	}

	return sbi->fat_length * sb->s_blocksize * 8 / sbi->fat_bits;
}

static bool fat_bpb_is_zero(struct fat_boot_sector *b)
{
	if (get_unaligned_le16(&b->sector_size))
		return false;
	if (b->sec_per_clus)
		return false;
	if (b->reserved)
		return false;
	if (b->fats)
		return false;
	if (get_unaligned_le16(&b->dir_entries))
		return false;
	if (get_unaligned_le16(&b->sectors))
		return false;
	if (b->media)
		return false;
	if (b->fat_length)
		return false;
	if (b->secs_track)
		return false;
	if (b->heads)
		return false;
	return true;
}

static int fat_read_bpb(struct super_block *sb, struct fat_boot_sector *b,
	int silent, struct fat_bios_param_block *bpb)
{
	int error = -EINVAL;

	/* Read in BPB ... */
	memset(bpb, 0, sizeof(*bpb));
	bpb->fat_sector_size = get_unaligned_le16(&b->sector_size);
	bpb->fat_sec_per_clus = b->sec_per_clus;
	bpb->fat_reserved = le16_to_cpu(b->reserved);
	bpb->fat_fats = b->fats;
	bpb->fat_dir_entries = get_unaligned_le16(&b->dir_entries);
	bpb->fat_sectors = get_unaligned_le16(&b->sectors);
	bpb->fat_fat_length = le16_to_cpu(b->fat_length);
	bpb->fat_total_sect = le32_to_cpu(b->total_sect);

	bpb->fat16_state = b->fat16.state;
	bpb->fat16_vol_id = get_unaligned_le32(b->fat16.vol_id);

	bpb->fat32_length = le32_to_cpu(b->fat32.length);
	bpb->fat32_root_cluster = le32_to_cpu(b->fat32.root_cluster);
	bpb->fat32_info_sector = le16_to_cpu(b->fat32.info_sector);
	bpb->fat32_state = b->fat32.state;
	bpb->fat32_vol_id = get_unaligned_le32(b->fat32.vol_id);

	/* Validate this looks like a FAT filesystem BPB */
	if (!bpb->fat_reserved) {
		if (!silent)
			fat_msg(sb, KERN_ERR,
				"bogus number of reserved sectors");
		goto out;
	}
	if (!bpb->fat_fats) {
		if (!silent)
			fat_msg(sb, KERN_ERR, "bogus number of FAT structure");
		goto out;
	}

	/*
	 * Earlier we checked here that b->secs_track and b->head are nonzero,
	 * but it turns out valid FAT filesystems can have zero there.
	 */

	if (!fat_valid_media(b->media)) {
		if (!silent)
			fat_msg(sb, KERN_ERR, "invalid media value (0x%02x)",
				(unsigned)b->media);
		goto out;
	}

	if (!is_power_of_2(bpb->fat_sector_size)
	    || (bpb->fat_sector_size < 512)
	    || (bpb->fat_sector_size > 4096)) {
		if (!silent)
			fat_msg(sb, KERN_ERR, "bogus logical sector size %u",
			       (unsigned)bpb->fat_sector_size);
		goto out;
	}

	if (!is_power_of_2(bpb->fat_sec_per_clus)) {
		if (!silent)
			fat_msg(sb, KERN_ERR, "bogus sectors per cluster %u",
				(unsigned)bpb->fat_sec_per_clus);
		goto out;
	}

	error = 0;

out:
	return error;
}

static int fat_read_static_bpb(struct super_block *sb,
	struct fat_boot_sector *b, int silent,
	struct fat_bios_param_block *bpb)
{
	static const char *notdos1x = "This doesn't look like a DOS 1.x volume";

	struct fat_floppy_defaults *fdefaults = NULL;
	int error = -EINVAL;
	sector_t bd_sects;
	unsigned i;

	bd_sects = i_size_read(sb->s_bdev->bd_inode) / SECTOR_SIZE;

	/* 16-bit DOS 1.x reliably wrote bootstrap short-jmp code */
	if (b->ignored[0] != 0xeb || b->ignored[2] != 0x90) {
		if (!silent)
			fat_msg(sb, KERN_ERR,
				"%s; no bootstrapping code", notdos1x);
		goto out;
	}

	/*
	 * If any value in this region is non-zero, it isn't archaic
	 * DOS.
	 */
	if (!fat_bpb_is_zero(b)) {
		if (!silent)
			fat_msg(sb, KERN_ERR,
				"%s; DOS 2.x BPB is non-zero", notdos1x);
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(floppy_defaults); i++) {
		if (floppy_defaults[i].nr_sectors == bd_sects) {
			fdefaults = &floppy_defaults[i];
			break;
		}
	}

	if (fdefaults == NULL) {
		if (!silent)
			fat_msg(sb, KERN_WARNING,
				"This looks like a DOS 1.x volume, but isn't a recognized floppy size (%llu sectors)",
				(u64)bd_sects);
		goto out;
	}

	if (!silent)
		fat_msg(sb, KERN_INFO,
			"This looks like a DOS 1.x volume; assuming default BPB values");

	memset(bpb, 0, sizeof(*bpb));
	bpb->fat_sector_size = SECTOR_SIZE;
	bpb->fat_sec_per_clus = fdefaults->sec_per_clus;
	bpb->fat_reserved = 1;
	bpb->fat_fats = 2;
	bpb->fat_dir_entries = fdefaults->dir_entries;
	bpb->fat_sectors = fdefaults->nr_sectors;
	bpb->fat_fat_length = fdefaults->fat_length;

	error = 0;

out:
	return error;
}

/*
 * Read the super block of an MS-DOS FS.
 */
int fat_fill_super(struct super_block *sb, void *data, int silent, int isvfat,
		   void (*setup)(struct super_block *))
{
	struct inode *root_inode = NULL, *fat_inode = NULL;
	struct inode *fsinfo_inode = NULL;
	struct buffer_head *bh;
	struct fat_bios_param_block bpb;
	struct msdos_sb_info *sbi;
	u16 logical_sector_size;
	u32 total_sectors, total_clusters, fat_clusters, rootdir_sectors;
	int debug;
	long error;
	char buf[50];

	/*
	 * GFP_KERNEL is ok here, because while we do hold the
	 * supeblock lock, memory pressure can't call back into
	 * the filesystem, since we're only just about to mount
	 * it and have no inodes etc active!
	 */
	sbi = kzalloc(sizeof(struct msdos_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;

	sb->s_flags |= MS_NODIRATIME;
	sb->s_magic = MSDOS_SUPER_MAGIC;
	sb->s_op = &fat_sops;
	sb->s_export_op = &fat_export_ops;
	mutex_init(&sbi->nfs_build_inode_lock);
	ratelimit_state_init(&sbi->ratelimit, DEFAULT_RATELIMIT_INTERVAL,
			     DEFAULT_RATELIMIT_BURST);

	error = parse_options(sb, data, isvfat, silent, &debug, &sbi->options);
	if (error)
		goto out_fail;

	setup(sb); /* flavour-specific stuff that needs options */

	error = -EIO;
	sb_min_blocksize(sb, 512);
	bh = sb_bread(sb, 0);
	if (bh == NULL) {
		fat_msg(sb, KERN_ERR, "unable to read boot sector");
		goto out_fail;
	}

	error = fat_read_bpb(sb, (struct fat_boot_sector *)bh->b_data, silent,
		&bpb);
	if (error == -EINVAL && sbi->options.dos1xfloppy)
		error = fat_read_static_bpb(sb,
			(struct fat_boot_sector *)bh->b_data, silent, &bpb);
	brelse(bh);

	if (error == -EINVAL)
		goto out_invalid;
	else if (error)
		goto out_fail;

	logical_sector_size = bpb.fat_sector_size;
	sbi->sec_per_clus = bpb.fat_sec_per_clus;

	error = -EIO;
	if (logical_sector_size < sb->s_blocksize) {
		fat_msg(sb, KERN_ERR, "logical sector size too small for device"
		       " (logical sector size = %u)", logical_sector_size);
		goto out_fail;
	}

	if (logical_sector_size > sb->s_blocksize) {
		struct buffer_head *bh_resize;

		if (!sb_set_blocksize(sb, logical_sector_size)) {
			fat_msg(sb, KERN_ERR, "unable to set blocksize %u",
			       logical_sector_size);
			goto out_fail;
		}

		/* Verify that the larger boot sector is fully readable */
		bh_resize = sb_bread(sb, 0);
		if (bh_resize == NULL) {
			fat_msg(sb, KERN_ERR, "unable to read boot sector"
			       " (logical sector size = %lu)",
			       sb->s_blocksize);
			goto out_fail;
		}
		brelse(bh_resize);
	}

	mutex_init(&sbi->s_lock);
	sbi->cluster_size = sb->s_blocksize * sbi->sec_per_clus;
	sbi->cluster_bits = ffs(sbi->cluster_size) - 1;
	sbi->fats = bpb.fat_fats;
	sbi->fat_bits = 0;		/* Don't know yet */
	sbi->fat_start = bpb.fat_reserved;
	sbi->fat_length = bpb.fat_fat_length;
	sbi->root_cluster = 0;
	sbi->free_clusters = -1;	/* Don't know yet */
	sbi->free_clus_valid = 0;
	sbi->prev_free = FAT_START_ENT;
	sb->s_maxbytes = 0xffffffff;

	if (!sbi->fat_length && bpb.fat32_length) {
		struct fat_boot_fsinfo *fsinfo;
		struct buffer_head *fsinfo_bh;

		/* Must be FAT32 */
		sbi->fat_bits = 32;
		sbi->fat_length = bpb.fat32_length;
		sbi->root_cluster = bpb.fat32_root_cluster;

		/* MC - if info_sector is 0, don't multiply by 0 */
		sbi->fsinfo_sector = bpb.fat32_info_sector;
		if (sbi->fsinfo_sector == 0)
			sbi->fsinfo_sector = 1;

		fsinfo_bh = sb_bread(sb, sbi->fsinfo_sector);
		if (fsinfo_bh == NULL) {
			fat_msg(sb, KERN_ERR, "bread failed, FSINFO block"
			       " (sector = %lu)", sbi->fsinfo_sector);
			goto out_fail;
		}

		fsinfo = (struct fat_boot_fsinfo *)fsinfo_bh->b_data;
		if (!IS_FSINFO(fsinfo)) {
			fat_msg(sb, KERN_WARNING, "Invalid FSINFO signature: "
			       "0x%08x, 0x%08x (sector = %lu)",
			       le32_to_cpu(fsinfo->signature1),
			       le32_to_cpu(fsinfo->signature2),
			       sbi->fsinfo_sector);
		} else {
			if (sbi->options.usefree)
				sbi->free_clus_valid = 1;
			sbi->free_clusters = le32_to_cpu(fsinfo->free_clusters);
			sbi->prev_free = le32_to_cpu(fsinfo->next_cluster);
		}

		brelse(fsinfo_bh);
	}

	/* interpret volume ID as a little endian 32 bit integer */
	if (sbi->fat_bits == 32)
		sbi->vol_id = bpb.fat32_vol_id;
	else /* fat 16 or 12 */
		sbi->vol_id = bpb.fat16_vol_id;

	sbi->dir_per_block = sb->s_blocksize / sizeof(struct msdos_dir_entry);
	sbi->dir_per_block_bits = ffs(sbi->dir_per_block) - 1;

	sbi->dir_start = sbi->fat_start + sbi->fats * sbi->fat_length;
	sbi->dir_entries = bpb.fat_dir_entries;
	if (sbi->dir_entries & (sbi->dir_per_block - 1)) {
		if (!silent)
			fat_msg(sb, KERN_ERR, "bogus directory-entries per block"
			       " (%u)", sbi->dir_entries);
		goto out_invalid;
	}

	rootdir_sectors = sbi->dir_entries
		* sizeof(struct msdos_dir_entry) / sb->s_blocksize;
	sbi->data_start = sbi->dir_start + rootdir_sectors;
	total_sectors = bpb.fat_sectors;
	if (total_sectors == 0)
		total_sectors = bpb.fat_total_sect;

	total_clusters = (total_sectors - sbi->data_start) / sbi->sec_per_clus;

	if (sbi->fat_bits != 32)
		sbi->fat_bits = (total_clusters > MAX_FAT12) ? 16 : 12;

	/* some OSes set FAT_STATE_DIRTY and clean it on unmount. */
	if (sbi->fat_bits == 32)
		sbi->dirty = bpb.fat32_state & FAT_STATE_DIRTY;
	else /* fat 16 or 12 */
		sbi->dirty = bpb.fat16_state & FAT_STATE_DIRTY;

	/* check that FAT table does not overflow */
	fat_clusters = calc_fat_clusters(sb);
	total_clusters = min(total_clusters, fat_clusters - FAT_START_ENT);
	if (total_clusters > MAX_FAT(sb)) {
		if (!silent)
			fat_msg(sb, KERN_ERR, "count of clusters too big (%u)",
			       total_clusters);
		goto out_invalid;
	}

	sbi->max_cluster = total_clusters + FAT_START_ENT;
	/* check the free_clusters, it's not necessarily correct */
	if (sbi->free_clusters != -1 && sbi->free_clusters > total_clusters)
		sbi->free_clusters = -1;
	/* check the prev_free, it's not necessarily correct */
	sbi->prev_free %= sbi->max_cluster;
	if (sbi->prev_free < FAT_START_ENT)
		sbi->prev_free = FAT_START_ENT;

	/* set up enough so that it can read an inode */
	fat_hash_init(sb);
	dir_hash_init(sb);
	fat_ent_access_init(sb);

	/*
	 * The low byte of FAT's first entry must have same value with
	 * media-field.  But in real world, too many devices is
	 * writing wrong value.  So, removed that validity check.
	 *
	 * if (FAT_FIRST_ENT(sb, media) != first)
	 */

	error = -EINVAL;
	sprintf(buf, "cp%d", sbi->options.codepage);
	sbi->nls_disk = load_nls(buf);
	if (!sbi->nls_disk) {
		fat_msg(sb, KERN_ERR, "codepage %s not found", buf);
		goto out_fail;
	}

	/* FIXME: utf8 is using iocharset for upper/lower conversion */
	if (sbi->options.isvfat) {
		sbi->nls_io = load_nls(sbi->options.iocharset);
		if (!sbi->nls_io) {
			fat_msg(sb, KERN_ERR, "IO charset %s not found",
			       sbi->options.iocharset);
			goto out_fail;
		}
	}

	error = -ENOMEM;
	fat_inode = new_inode(sb);
	if (!fat_inode)
		goto out_fail;
	MSDOS_I(fat_inode)->i_pos = 0;
	sbi->fat_inode = fat_inode;

	fsinfo_inode = new_inode(sb);
	if (!fsinfo_inode)
		goto out_fail;
	fsinfo_inode->i_ino = MSDOS_FSINFO_INO;
	sbi->fsinfo_inode = fsinfo_inode;
	insert_inode_hash(fsinfo_inode);

	root_inode = new_inode(sb);
	if (!root_inode)
		goto out_fail;
	root_inode->i_ino = MSDOS_ROOT_INO;
	root_inode->i_version = 1;
	error = fat_read_root(root_inode);
	if (error < 0) {
		iput(root_inode);
		goto out_fail;
	}
	error = -ENOMEM;
	insert_inode_hash(root_inode);
	fat_attach(root_inode, 0);
	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		fat_msg(sb, KERN_ERR, "get root inode failed");
		goto out_fail;
	}

	if (sbi->options.discard) {
		struct request_queue *q = bdev_get_queue(sb->s_bdev);
		if (!blk_queue_discard(q))
			fat_msg(sb, KERN_WARNING,
					"mounting with \"discard\" option, but "
					"the device does not support discard");
	}

	fat_set_state(sb, 1, 0);
	return 0;

out_invalid:
	error = -EINVAL;
	if (!silent)
		fat_msg(sb, KERN_INFO, "Can't find a valid FAT filesystem");

out_fail:
	if (fsinfo_inode)
		iput(fsinfo_inode);
	if (fat_inode)
		iput(fat_inode);
	unload_nls(sbi->nls_io);
	unload_nls(sbi->nls_disk);
	if (sbi->options.iocharset != fat_default_iocharset)
		kfree(sbi->options.iocharset);
	sb->s_fs_info = NULL;
	kfree(sbi);
	return error;
}

EXPORT_SYMBOL_GPL(fat_fill_super);

/*
 * helper function for fat_flush_inodes.  This writes both the inode
 * and the file data blocks, waiting for in flight data blocks before
 * the start of the call.  It does not wait for any io started
 * during the call
 */
static int writeback_inode(struct inode *inode)
{

	int ret;

	/* if we used wait=1, sync_inode_metadata waits for the io for the
	* inode to finish.  So wait=0 is sent down to sync_inode_metadata
	* and filemap_fdatawrite is used for the data blocks
	*/
	ret = sync_inode_metadata(inode, 0);
	if (!ret)
		ret = filemap_fdatawrite(inode->i_mapping);
	return ret;
}

/*
 * write data and metadata corresponding to i1 and i2.  The io is
 * started but we do not wait for any of it to finish.
 *
 * filemap_flush is used for the block device, so if there is a dirty
 * page for a block already in flight, we will not wait and start the
 * io over again
 */
int fat_flush_inodes(struct super_block *sb, struct inode *i1, struct inode *i2)
{
	int ret = 0;
	if (!MSDOS_SB(sb)->options.flush)
		return 0;
	if (i1)
		ret = writeback_inode(i1);
	if (!ret && i2)
		ret = writeback_inode(i2);
	if (!ret) {
		struct address_space *mapping = sb->s_bdev->bd_inode->i_mapping;
		ret = filemap_flush(mapping);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(fat_flush_inodes);

static int __init init_fat_fs(void)
{
	int err;

	err = fat_cache_init();
	if (err)
		return err;

	err = fat_init_inodecache();
	if (err)
		goto failed;

	return 0;

failed:
	fat_cache_destroy();
	return err;
}

static void __exit exit_fat_fs(void)
{
	fat_cache_destroy();
	fat_destroy_inodecache();
}

module_init(init_fat_fs)
module_exit(exit_fat_fs)

MODULE_LICENSE("GPL");
/************************************************************/
/* ../linux-3.17/fs/fat/inode.c */
/************************************************************/
/*
 *  linux/fs/fat/misc.c
 *
 *  Written 1992,1993 by Werner Almesberger
 *  22/11/2000 - Fixed fat_date_unix2dos for dates earlier than 01/01/1980
 *		 and date_dos2unix for date==0 by Igor Zhbanov(bsg@uniyar.ac.ru)
 */

// #include <linux/module.h>
// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/time.h>
// #include "fat.h"

/*
 * fat_fs_error reports a file system problem that might indicate fa data
 * corruption/inconsistency. Depending on 'errors' mount option the
 * panic() is called, or error message is printed FAT and nothing is done,
 * or filesystem is remounted read-only (default behavior).
 * In case the file system is remounted read-only, it can be made writable
 * again by remounting it.
 */
void __fat_fs_error(struct super_block *sb, int report, const char *fmt, ...)
{
	struct fat_mount_options *opts = &MSDOS_SB(sb)->options;
	va_list args;
	struct va_format vaf;

	if (report) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		fat_msg(sb, KERN_ERR, "error, %pV", &vaf);
		va_end(args);
	}

	if (opts->errors == FAT_ERRORS_PANIC)
		panic("FAT-fs (%s): fs panic from previous error\n", sb->s_id);
	else if (opts->errors == FAT_ERRORS_RO && !(sb->s_flags & MS_RDONLY)) {
		sb->s_flags |= MS_RDONLY;
		fat_msg(sb, KERN_ERR, "Filesystem has been set read-only");
	}
}
EXPORT_SYMBOL_GPL(__fat_fs_error);

/**
 * fat_msg() - print preformated FAT specific messages. Every thing what is
 * not fat_fs_error() should be fat_msg().
 */
void fat_msg(struct super_block *sb, const char *level, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	printk("%sFAT-fs (%s): %pV\n", level, sb->s_id, &vaf);
	va_end(args);
}

/* Flushes the number of free clusters on FAT32 */
/* XXX: Need to write one per FSINFO block.  Currently only writes 1 */
int fat_clusters_flush(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bh;
	struct fat_boot_fsinfo *fsinfo;

	if (sbi->fat_bits != 32)
		return 0;

	bh = sb_bread(sb, sbi->fsinfo_sector);
	if (bh == NULL) {
		fat_msg(sb, KERN_ERR, "bread failed in fat_clusters_flush");
		return -EIO;
	}

	fsinfo = (struct fat_boot_fsinfo *)bh->b_data;
	/* Sanity check */
	if (!IS_FSINFO(fsinfo)) {
		fat_msg(sb, KERN_ERR, "Invalid FSINFO signature: "
		       "0x%08x, 0x%08x (sector = %lu)",
		       le32_to_cpu(fsinfo->signature1),
		       le32_to_cpu(fsinfo->signature2),
		       sbi->fsinfo_sector);
	} else {
		if (sbi->free_clusters != -1)
			fsinfo->free_clusters = cpu_to_le32(sbi->free_clusters);
		if (sbi->prev_free != -1)
			fsinfo->next_cluster = cpu_to_le32(sbi->prev_free);
		mark_buffer_dirty(bh);
	}
	brelse(bh);

	return 0;
}

/*
 * fat_chain_add() adds a new cluster to the chain of clusters represented
 * by inode.
 */
int fat_chain_add(struct inode *inode, int new_dclus, int nr_cluster)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	int ret, new_fclus, last;

	/*
	 * We must locate the last cluster of the file to add this new
	 * one (new_dclus) to the end of the link list (the FAT).
	 */
	last = new_fclus = 0;
	if (MSDOS_I(inode)->i_start) {
		int fclus, dclus;

		ret = fat_get_cluster(inode, FAT_ENT_EOF, &fclus, &dclus);
		if (ret < 0)
			return ret;
		new_fclus = fclus + 1;
		last = dclus;
	}

	/* add new one to the last of the cluster chain */
	if (last) {
		struct fat_entry fatent;

		fatent_init(&fatent);
		ret = fat_ent_read(inode, &fatent, last);
		if (ret >= 0) {
			int wait = inode_needs_sync(inode);
			ret = fat_ent_write(inode, &fatent, new_dclus, wait);
			fatent_brelse(&fatent);
		}
		if (ret < 0)
			return ret;
		/*
		 * FIXME:Although we can add this cache, fat_cache_add() is
		 * assuming to be called after linear search with fat_cache_id.
		 */
//		fat_cache_add(inode, new_fclus, new_dclus);
	} else {
		MSDOS_I(inode)->i_start = new_dclus;
		MSDOS_I(inode)->i_logstart = new_dclus;
		/*
		 * Since generic_write_sync() synchronizes regular files later,
		 * we sync here only directories.
		 */
		if (S_ISDIR(inode->i_mode) && IS_DIRSYNC(inode)) {
			ret = fat_sync_inode(inode);
			if (ret)
				return ret;
		} else
			mark_inode_dirty(inode);
	}
	if (new_fclus != (inode->i_blocks >> (sbi->cluster_bits - 9))) {
		fat_fs_error(sb, "clusters badly computed (%d != %llu)",
			     new_fclus,
			     (llu)(inode->i_blocks >> (sbi->cluster_bits - 9)));
		fat_cache_inval_inode(inode);
	}
	inode->i_blocks += nr_cluster << (sbi->cluster_bits - 9);

	return 0;
}

extern struct timezone sys_tz;

/*
 * The epoch of FAT timestamp is 1980.
 *     :  bits :     value
 * date:  0 -  4: day	(1 -  31)
 * date:  5 -  8: month	(1 -  12)
 * date:  9 - 15: year	(0 - 127) from 1980
 * time:  0 -  4: sec	(0 -  29) 2sec counts
 * time:  5 - 10: min	(0 -  59)
 * time: 11 - 15: hour	(0 -  23)
 */
#define SECS_PER_MIN	60
#define SECS_PER_HOUR	(60 * 60)
#define SECS_PER_DAY	(SECS_PER_HOUR * 24)
/* days between 1.1.70 and 1.1.80 (2 leap days) */
#define DAYS_DELTA	(365 * 10 + 2)
/* 120 (2100 - 1980) isn't leap year */
#define YEAR_2100	120
#define IS_LEAP_YEAR(y)	(!((y) & 3) && (y) != YEAR_2100)

/* Linear day numbers of the respective 1sts in non-leap years. */
static time_t days_in_year[] = {
	/* Jan  Feb  Mar  Apr  May  Jun  Jul  Aug  Sep  Oct  Nov  Dec */
	0,   0,  31,  59,  90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0,
};

/* Convert a FAT time/date pair to a UNIX date (seconds since 1 1 70). */
void fat_time_fat2unix(struct msdos_sb_info *sbi, struct timespec *ts,
		       __le16 __time, __le16 __date, u8 time_cs)
{
	u16 time = le16_to_cpu(__time), date = le16_to_cpu(__date);
	time_t second, day, leap_day, month, year;

	year  = date >> 9;
	month = max(1, (date >> 5) & 0xf);
	day   = max(1, date & 0x1f) - 1;

	leap_day = (year + 3) / 4;
	if (year > YEAR_2100)		/* 2100 isn't leap year */
		leap_day--;
	if (IS_LEAP_YEAR(year) && month > 2)
		leap_day++;

	second =  (time & 0x1f) << 1;
	second += ((time >> 5) & 0x3f) * SECS_PER_MIN;
	second += (time >> 11) * SECS_PER_HOUR;
	second += (year * 365 + leap_day
		   + days_in_year[month] + day
		   + DAYS_DELTA) * SECS_PER_DAY;

	if (!sbi->options.tz_set)
		second += sys_tz.tz_minuteswest * SECS_PER_MIN;
	else
		second -= sbi->options.time_offset * SECS_PER_MIN;

	if (time_cs) {
		ts->tv_sec = second + (time_cs / 100);
		ts->tv_nsec = (time_cs % 100) * 10000000;
	} else {
		ts->tv_sec = second;
		ts->tv_nsec = 0;
	}
}

/* Convert linear UNIX date to a FAT time/date pair. */
void fat_time_unix2fat(struct msdos_sb_info *sbi, struct timespec *ts,
		       __le16 *time, __le16 *date, u8 *time_cs)
{
	struct tm tm;
	time_to_tm(ts->tv_sec,
		   (sbi->options.tz_set ? sbi->options.time_offset :
		   -sys_tz.tz_minuteswest) * SECS_PER_MIN, &tm);

	/*  FAT can only support year between 1980 to 2107 */
	if (tm.tm_year < 1980 - 1900) {
		*time = 0;
		*date = cpu_to_le16((0 << 9) | (1 << 5) | 1);
		if (time_cs)
			*time_cs = 0;
		return;
	}
	if (tm.tm_year > 2107 - 1900) {
		*time = cpu_to_le16((23 << 11) | (59 << 5) | 29);
		*date = cpu_to_le16((127 << 9) | (12 << 5) | 31);
		if (time_cs)
			*time_cs = 199;
		return;
	}

	/* from 1900 -> from 1980 */
	tm.tm_year -= 80;
	/* 0~11 -> 1~12 */
	tm.tm_mon++;
	/* 0~59 -> 0~29(2sec counts) */
	tm.tm_sec >>= 1;

	*time = cpu_to_le16(tm.tm_hour << 11 | tm.tm_min << 5 | tm.tm_sec);
	*date = cpu_to_le16(tm.tm_year << 9 | tm.tm_mon << 5 | tm.tm_mday);
	if (time_cs)
		*time_cs = (ts->tv_sec & 1) * 100 + ts->tv_nsec / 10000000;
}
EXPORT_SYMBOL_GPL(fat_time_unix2fat);

int fat_sync_bhs(struct buffer_head **bhs, int nr_bhs)
{
	int i, err = 0;

	for (i = 0; i < nr_bhs; i++)
		write_dirty_buffer(bhs[i], WRITE);

	for (i = 0; i < nr_bhs; i++) {
		wait_on_buffer(bhs[i]);
		if (!err && !buffer_uptodate(bhs[i]))
			err = -EIO;
	}
	return err;
}
/************************************************************/
/* ../linux-3.17/fs/fat/misc.c */
/************************************************************/
/* fs/fat/nfs.c
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/exportfs.h>
// #include "fat.h"

struct fat_fid {
	u32 i_gen;
	u32 i_pos_low;
	u16 i_pos_hi;
	u16 parent_i_pos_hi;
	u32 parent_i_pos_low;
	u32 parent_i_gen;
};

#define FAT_FID_SIZE_WITHOUT_PARENT 3
#define FAT_FID_SIZE_WITH_PARENT (sizeof(struct fat_fid)/sizeof(u32))

/**
 * Look up a directory inode given its starting cluster.
 */
static struct inode *fat_dget(struct super_block *sb, int i_logstart)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct hlist_head *head;
	struct msdos_inode_info *i;
	struct inode *inode = NULL;

	head = sbi->dir_hashtable + fat_dir_hash(i_logstart);
	spin_lock(&sbi->dir_hash_lock);
	hlist_for_each_entry(i, head, i_dir_hash) {
		BUG_ON(i->vfs_inode.i_sb != sb);
		if (i->i_logstart != i_logstart)
			continue;
		inode = igrab(&i->vfs_inode);
		if (inode)
			break;
	}
	spin_unlock(&sbi->dir_hash_lock);
	return inode;
}

static struct inode *fat_ilookup(struct super_block *sb, u64 ino, loff_t i_pos)
{
	if (MSDOS_SB(sb)->options.nfs == FAT_NFS_NOSTALE_RO)
		return fat_iget(sb, i_pos);

	else {
		if ((ino < MSDOS_ROOT_INO) || (ino == MSDOS_FSINFO_INO))
			return NULL;
		return ilookup(sb, ino);
	}
}

static struct inode *__fat_nfs_get_inode(struct super_block *sb,
				       u64 ino, u32 generation, loff_t i_pos)
{
	struct inode *inode = fat_ilookup(sb, ino, i_pos);

	if (inode && generation && (inode->i_generation != generation)) {
		iput(inode);
		inode = NULL;
	}
	if (inode == NULL && MSDOS_SB(sb)->options.nfs == FAT_NFS_NOSTALE_RO) {
		struct buffer_head *bh = NULL;
		struct msdos_dir_entry *de ;
		sector_t blocknr;
		int offset;
		fat_get_blknr_offset(MSDOS_SB(sb), i_pos, &blocknr, &offset);
		bh = sb_bread(sb, blocknr);
		if (!bh) {
			fat_msg(sb, KERN_ERR,
				"unable to read block(%llu) for building NFS inode",
				(llu)blocknr);
			return inode;
		}
		de = (struct msdos_dir_entry *)bh->b_data;
		/* If a file is deleted on server and client is not updated
		 * yet, we must not build the inode upon a lookup call.
		 */
		if (IS_FREE(de[offset].name))
			inode = NULL;
		else
			inode = fat_build_inode(sb, &de[offset], i_pos);
		brelse(bh);
	}

	return inode;
}

static struct inode *fat_nfs_get_inode(struct super_block *sb,
				       u64 ino, u32 generation)
{

	return __fat_nfs_get_inode(sb, ino, generation, 0);
}

static int
fat_encode_fh_nostale(struct inode *inode, __u32 *fh, int *lenp,
		      struct inode *parent)
{
	int len = *lenp;
	struct msdos_sb_info *sbi = MSDOS_SB(inode->i_sb);
	struct fat_fid *fid = (struct fat_fid *) fh;
	loff_t i_pos;
	int type = FILEID_FAT_WITHOUT_PARENT;

	if (parent) {
		if (len < FAT_FID_SIZE_WITH_PARENT) {
			*lenp = FAT_FID_SIZE_WITH_PARENT;
			return FILEID_INVALID;
		}
	} else {
		if (len < FAT_FID_SIZE_WITHOUT_PARENT) {
			*lenp = FAT_FID_SIZE_WITHOUT_PARENT;
			return FILEID_INVALID;
		}
	}

	i_pos = fat_i_pos_read(sbi, inode);
	*lenp = FAT_FID_SIZE_WITHOUT_PARENT;
	fid->i_gen = inode->i_generation;
	fid->i_pos_low = i_pos & 0xFFFFFFFF;
	fid->i_pos_hi = (i_pos >> 32) & 0xFFFF;
	if (parent) {
		i_pos = fat_i_pos_read(sbi, parent);
		fid->parent_i_pos_hi = (i_pos >> 32) & 0xFFFF;
		fid->parent_i_pos_low = i_pos & 0xFFFFFFFF;
		fid->parent_i_gen = parent->i_generation;
		type = FILEID_FAT_WITH_PARENT;
		*lenp = FAT_FID_SIZE_WITH_PARENT;
	}

	return type;
}

/**
 * Map a NFS file handle to a corresponding dentry.
 * The dentry may or may not be connected to the filesystem root.
 */
static struct dentry *fat_fh_to_dentry(struct super_block *sb, struct fid *fid,
				int fh_len, int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    fat_nfs_get_inode);
}

static struct dentry *fat_fh_to_dentry_nostale(struct super_block *sb,
					       struct fid *fh, int fh_len,
					       int fh_type)
{
	struct inode *inode = NULL;
	struct fat_fid *fid = (struct fat_fid *)fh;
	loff_t i_pos;

	switch (fh_type) {
	case FILEID_FAT_WITHOUT_PARENT:
		if (fh_len < FAT_FID_SIZE_WITHOUT_PARENT)
			return NULL;
		break;
	case FILEID_FAT_WITH_PARENT:
		if (fh_len < FAT_FID_SIZE_WITH_PARENT)
			return NULL;
		break;
	default:
		return NULL;
	}
	i_pos = fid->i_pos_hi;
	i_pos = (i_pos << 32) | (fid->i_pos_low);
	inode = __fat_nfs_get_inode(sb, 0, fid->i_gen, i_pos);

	return d_obtain_alias(inode);
}

/*
 * Find the parent for a file specified by NFS handle.
 * This requires that the handle contain the i_ino of the parent.
 */
static struct dentry *fat_fh_to_parent(struct super_block *sb, struct fid *fid,
				int fh_len, int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    fat_nfs_get_inode);
}

static struct dentry *fat_fh_to_parent_nostale(struct super_block *sb,
					       struct fid *fh, int fh_len,
					       int fh_type)
{
	struct inode *inode = NULL;
	struct fat_fid *fid = (struct fat_fid *)fh;
	loff_t i_pos;

	if (fh_len < FAT_FID_SIZE_WITH_PARENT)
		return NULL;

	switch (fh_type) {
	case FILEID_FAT_WITH_PARENT:
		i_pos = fid->parent_i_pos_hi;
		i_pos = (i_pos << 32) | (fid->parent_i_pos_low);
		inode = __fat_nfs_get_inode(sb, 0, fid->parent_i_gen, i_pos);
		break;
	}

	return d_obtain_alias(inode);
}

/*
 * Rebuild the parent for a directory that is not connected
 *  to the filesystem root
 */
static
struct inode *fat_rebuild_parent(struct super_block *sb, int parent_logstart)
{
	int search_clus, clus_to_match;
	struct msdos_dir_entry *de;
	struct inode *parent = NULL;
	struct inode *dummy_grand_parent = NULL;
	struct fat_slot_info sinfo;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	sector_t blknr = fat_clus_to_blknr(sbi, parent_logstart);
	struct buffer_head *parent_bh = sb_bread(sb, blknr);
	if (!parent_bh) {
		fat_msg(sb, KERN_ERR,
			"unable to read cluster of parent directory");
		return NULL;
	}

	de = (struct msdos_dir_entry *) parent_bh->b_data;
	clus_to_match = fat_get_start(sbi, &de[0]);
	search_clus = fat_get_start(sbi, &de[1]);

	dummy_grand_parent = fat_dget(sb, search_clus);
	if (!dummy_grand_parent) {
		dummy_grand_parent = new_inode(sb);
		if (!dummy_grand_parent) {
			brelse(parent_bh);
			return parent;
		}

		dummy_grand_parent->i_ino = iunique(sb, MSDOS_ROOT_INO);
		fat_fill_inode(dummy_grand_parent, &de[1]);
		MSDOS_I(dummy_grand_parent)->i_pos = -1;
	}

	if (!fat_scan_logstart(dummy_grand_parent, clus_to_match, &sinfo))
		parent = fat_build_inode(sb, sinfo.de, sinfo.i_pos);

	brelse(parent_bh);
	iput(dummy_grand_parent);

	return parent;
}

/*
 * Find the parent for a directory that is not currently connected to
 * the filesystem root.
 *
 * On entry, the caller holds child_dir->d_inode->i_mutex.
 */
static struct dentry *fat_get_parent(struct dentry *child_dir)
{
	struct super_block *sb = child_dir->d_sb;
	struct buffer_head *bh = NULL;
	struct msdos_dir_entry *de;
	struct inode *parent_inode = NULL;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);

	if (!fat_get_dotdot_entry(child_dir->d_inode, &bh, &de)) {
		int parent_logstart = fat_get_start(sbi, de);
		parent_inode = fat_dget(sb, parent_logstart);
		if (!parent_inode && sbi->options.nfs == FAT_NFS_NOSTALE_RO)
			parent_inode = fat_rebuild_parent(sb, parent_logstart);
	}
	brelse(bh);

	return d_obtain_alias(parent_inode);
}

const struct export_operations fat_export_ops = {
	.fh_to_dentry   = fat_fh_to_dentry,
	.fh_to_parent   = fat_fh_to_parent,
	.get_parent     = fat_get_parent,
};

const struct export_operations fat_export_ops_nostale = {
	.encode_fh      = fat_encode_fh_nostale,
	.fh_to_dentry   = fat_fh_to_dentry_nostale,
	.fh_to_parent   = fat_fh_to_parent_nostale,
	.get_parent     = fat_get_parent,
};
/************************************************************/
/* ../linux-3.17/fs/fat/nfs.c */
/************************************************************/
