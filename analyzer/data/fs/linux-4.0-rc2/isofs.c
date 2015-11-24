/*
 *  linux/fs/isofs/namei.c
 *
 *  (C) 1992  Eric Youngdale Modified for ISO 9660 filesystem.
 *
 *  (C) 1991  Linus Torvalds - minix filesystem
 */

#include <linux/gfp.h>
#include "isofs.h"
#include "../../inc/__fss.h"

/*
 * ok, we cannot use strncmp, as the name is not in our data space.
 * Thus we'll have to use isofs_match. No big problem. Match also makes
 * some sanity tests.
 */
static int
isofs_cmp(struct dentry *dentry, const char *compare, int dlen)
{
	struct qstr qstr;
	qstr.name = compare;
	qstr.len = dlen;
	if (likely(!dentry->d_op))
		return dentry->d_name.len != dlen || memcmp(dentry->d_name.name, compare, dlen);
	return dentry->d_op->d_compare(NULL, NULL, dentry->d_name.len, dentry->d_name.name, &qstr);
}

/*
 *	isofs_find_entry()
 *
 * finds an entry in the specified directory with the wanted name. It
 * returns the inode number of the found entry, or 0 on error.
 */
static unsigned long
isofs_find_entry(struct inode *dir, struct dentry *dentry,
	unsigned long *block_rv, unsigned long *offset_rv,
	char *tmpname, struct iso_directory_record *tmpde)
{
	unsigned long bufsize = ISOFS_BUFFER_SIZE(dir);
	unsigned char bufbits = ISOFS_BUFFER_BITS(dir);
	unsigned long block, f_pos, offset, block_saved, offset_saved;
	struct buffer_head *bh = NULL;
	struct isofs_sb_info *sbi = ISOFS_SB(dir->i_sb);

	if (!ISOFS_I(dir)->i_first_extent)
		return 0;

	f_pos = 0;
	offset = 0;
	block = 0;

	while (f_pos < dir->i_size) {
		struct iso_directory_record *de;
		int de_len, match, i, dlen;
		char *dpnt;

		if (!bh) {
			bh = isofs_bread(dir, block);
			if (!bh)
				return 0;
		}

		de = (struct iso_directory_record *) (bh->b_data + offset);

		de_len = *(unsigned char *) de;
		if (!de_len) {
			brelse(bh);
			bh = NULL;
			f_pos = (f_pos + ISOFS_BLOCK_SIZE) & ~(ISOFS_BLOCK_SIZE - 1);
			block = f_pos >> bufbits;
			offset = 0;
			continue;
		}

		block_saved = bh->b_blocknr;
		offset_saved = offset;
		offset += de_len;
		f_pos += de_len;

		/* Make sure we have a full directory entry */
		if (offset >= bufsize) {
			int slop = bufsize - offset + de_len;
			memcpy(tmpde, de, slop);
			offset &= bufsize - 1;
			block++;
			brelse(bh);
			bh = NULL;
			if (offset) {
				bh = isofs_bread(dir, block);
				if (!bh)
					return 0;
				memcpy((void *) tmpde + slop, bh->b_data, offset);
			}
			de = tmpde;
		}

		dlen = de->name_len[0];
		dpnt = de->name;
		/* Basic sanity check, whether name doesn't exceed dir entry */
		if (de_len < dlen + sizeof(struct iso_directory_record)) {
			printk(KERN_NOTICE "iso9660: Corrupted directory entry"
			       " in block %lu of inode %lu\n", block,
			       dir->i_ino);
			return 0;
		}

		if (sbi->s_rock &&
		    ((i = get_rock_ridge_filename(de, tmpname, dir)))) {
			dlen = i;	/* possibly -1 */
			dpnt = tmpname;
#ifdef CONFIG_JOLIET
		} else if (sbi->s_joliet_level) {
			dlen = get_joliet_filename(de, tmpname, dir);
			dpnt = tmpname;
#endif
		} else if (sbi->s_mapping == 'a') {
			dlen = get_acorn_filename(de, tmpname, dir);
			dpnt = tmpname;
		} else if (sbi->s_mapping == 'n') {
			dlen = isofs_name_translate(de, tmpname, dir);
			dpnt = tmpname;
		}

		/*
		 * Skip hidden or associated files unless hide or showassoc,
		 * respectively, is set
		 */
		match = 0;
		if (dlen > 0 &&
			(!sbi->s_hide ||
				(!(de->flags[-sbi->s_high_sierra] & 1))) &&
			(sbi->s_showassoc ||
				(!(de->flags[-sbi->s_high_sierra] & 4)))) {
			if (dpnt && (dlen > 1 || dpnt[0] > 1))
				match = (isofs_cmp(dentry, dpnt, dlen) == 0);
		}
		if (match) {
			isofs_normalize_block_and_offset(de,
							 &block_saved,
							 &offset_saved);
			*block_rv = block_saved;
			*offset_rv = offset_saved;
			brelse(bh);
			return 1;
		}
	}
	brelse(bh);
	return 0;
}

struct dentry *isofs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	int found;
	unsigned long uninitialized_var(block);
	unsigned long uninitialized_var(offset);
	struct inode *inode;
	struct page *page;

	page = alloc_page(GFP_USER);
	if (!page)
		return ERR_PTR(-ENOMEM);

	found = isofs_find_entry(dir, dentry,
				&block, &offset,
				page_address(page),
				1024 + page_address(page));
	__free_page(page);

	inode = found ? isofs_iget(dir->i_sb, block, offset) : NULL;

	return d_splice_alias(inode, dentry);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/isofs/namei.c */
/************************************************************/
/*
 *  linux/fs/isofs/inode.c
 *
 *  (C) 1991  Linus Torvalds - minix filesystem
 *      1992, 1993, 1994  Eric Youngdale Modified for ISO 9660 filesystem.
 *      1994  Eberhard Mönkeberg - multi session handling.
 *      1995  Mark Dobie - allow mounting of some weird VideoCDs and PhotoCDs.
 *	1997  Gordon Chaffee - Joliet CDs
 *	1998  Eric Lammerts - ISO 9660 Level 3
 *	2004  Paul Serice - Inode Support pushed out from 4GB to 128GB
 *	2004  Paul Serice - NFS Export Operations
 */

#include <linux/init.h>
#include <linux/module.h>
#include "../../inc/__fss.h"

#include <linux/slab.h>
#include <linux/nls.h>
#include <linux/ctype.h>
#include <linux/statfs.h>
#include <linux/cdrom.h>
#include <linux/parser.h>
#include <linux/mpage.h>
#include <linux/user_namespace.h>
#include "../../inc/__fss.h"

// #include "isofs.h"
#include "zisofs.h"
#include "../../inc/__fss.h"

#define BEQUIET

static int isofs_hashi(const struct dentry *parent, struct qstr *qstr);
static int isofs_dentry_cmpi(const struct dentry *parent,
		const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name);

#ifdef CONFIG_JOLIET
static int isofs_hashi_ms(const struct dentry *parent, struct qstr *qstr);
static int isofs_hash_ms(const struct dentry *parent, struct qstr *qstr);
static int isofs_dentry_cmpi_ms(const struct dentry *parent,
		const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name);
static int isofs_dentry_cmp_ms(const struct dentry *parent,
		const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name);
#endif

static void isofs_put_super(struct super_block *sb)
{
	struct isofs_sb_info *sbi = ISOFS_SB(sb);

#ifdef CONFIG_JOLIET
	unload_nls(sbi->s_nls_iocharset);
#endif

	kfree(sbi);
	sb->s_fs_info = NULL;
	return;
}

static int isofs_read_inode(struct inode *, int relocated);
static int isofs_statfs (struct dentry *, struct kstatfs *);

static struct kmem_cache *isofs_inode_cachep;

static struct inode *isofs_alloc_inode(struct super_block *sb)
{
	struct iso_inode_info *ei;
	ei = kmem_cache_alloc(isofs_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void isofs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(isofs_inode_cachep, ISOFS_I(inode));
}

static void isofs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, isofs_i_callback);
}

static void init_once(void *foo)
{
	struct iso_inode_info *ei = foo;

	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	isofs_inode_cachep = kmem_cache_create("isofs_inode_cache",
					sizeof(struct iso_inode_info),
					0, (SLAB_RECLAIM_ACCOUNT|
					SLAB_MEM_SPREAD),
					init_once);
	if (isofs_inode_cachep == NULL)
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
	kmem_cache_destroy(isofs_inode_cachep);
}

static int isofs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	if (!(*flags & MS_RDONLY))
		return -EROFS;
	return 0;
}

static const struct super_operations isofs_sops = {
	.alloc_inode	= isofs_alloc_inode,
	.destroy_inode	= isofs_destroy_inode,
	.put_super	= isofs_put_super,
	.statfs		= isofs_statfs,
	.remount_fs	= isofs_remount,
	.show_options	= generic_show_options,
};


static const struct dentry_operations isofs_dentry_ops[] = {
	{
		.d_hash		= isofs_hashi,
		.d_compare	= isofs_dentry_cmpi,
	},
#ifdef CONFIG_JOLIET
	{
		.d_hash		= isofs_hash_ms,
		.d_compare	= isofs_dentry_cmp_ms,
	},
	{
		.d_hash		= isofs_hashi_ms,
		.d_compare	= isofs_dentry_cmpi_ms,
	},
#endif
};

struct iso9660_options{
	unsigned int rock:1;
	unsigned int joliet:1;
	unsigned int cruft:1;
	unsigned int hide:1;
	unsigned int showassoc:1;
	unsigned int nocompress:1;
	unsigned int overriderockperm:1;
	unsigned int uid_set:1;
	unsigned int gid_set:1;
	unsigned int utf8:1;
	unsigned char map;
	unsigned char check;
	unsigned int blocksize;
	umode_t fmode;
	umode_t dmode;
	kgid_t gid;
	kuid_t uid;
	char *iocharset;
	/* LVE */
	s32 session;
	s32 sbsector;
};

/*
 * Compute the hash for the isofs name corresponding to the dentry.
 */
static int
isofs_hashi_common(struct qstr *qstr, int ms)
{
	const char *name;
	int len;
	char c;
	unsigned long hash;

	len = qstr->len;
	name = qstr->name;
	if (ms) {
		while (len && name[len-1] == '.')
			len--;
	}

	hash = init_name_hash();
	while (len--) {
		c = tolower(*name++);
		hash = partial_name_hash(c, hash);
	}
	qstr->hash = end_name_hash(hash);

	return 0;
}

/*
 * Compare of two isofs names.
 */
static int isofs_dentry_cmp_common(
		unsigned int len, const char *str,
		const struct qstr *name, int ms, int ci)
{
	int alen, blen;

	/* A filename cannot end in '.' or we treat it like it has none */
	alen = name->len;
	blen = len;
	if (ms) {
		while (alen && name->name[alen-1] == '.')
			alen--;
		while (blen && str[blen-1] == '.')
			blen--;
	}
	if (alen == blen) {
		if (ci) {
			if (strncasecmp(name->name, str, alen) == 0)
				return 0;
		} else {
			if (strncmp(name->name, str, alen) == 0)
				return 0;
		}
	}
	return 1;
}

static int
isofs_hashi(const struct dentry *dentry, struct qstr *qstr)
{
	return isofs_hashi_common(qstr, 0);
}

static int
isofs_dentry_cmpi(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	return isofs_dentry_cmp_common(len, str, name, 0, 1);
}

#ifdef CONFIG_JOLIET
/*
 * Compute the hash for the isofs name corresponding to the dentry.
 */
static int
isofs_hash_common(struct qstr *qstr, int ms)
{
	const char *name;
	int len;

	len = qstr->len;
	name = qstr->name;
	if (ms) {
		while (len && name[len-1] == '.')
			len--;
	}

	qstr->hash = full_name_hash(name, len);

	return 0;
}

static int
isofs_hash_ms(const struct dentry *dentry, struct qstr *qstr)
{
	return isofs_hash_common(qstr, 1);
}

static int
isofs_hashi_ms(const struct dentry *dentry, struct qstr *qstr)
{
	return isofs_hashi_common(qstr, 1);
}

static int
isofs_dentry_cmp_ms(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	return isofs_dentry_cmp_common(len, str, name, 1, 0);
}

static int
isofs_dentry_cmpi_ms(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	return isofs_dentry_cmp_common(len, str, name, 1, 1);
}
#endif

enum {
	Opt_block, Opt_check_r, Opt_check_s, Opt_cruft, Opt_gid, Opt_ignore,
	Opt_iocharset, Opt_map_a, Opt_map_n, Opt_map_o, Opt_mode, Opt_nojoliet,
	Opt_norock, Opt_sb, Opt_session, Opt_uid, Opt_unhide, Opt_utf8, Opt_err,
	Opt_nocompress, Opt_hide, Opt_showassoc, Opt_dmode, Opt_overriderockperm,
};

static const match_table_t tokens = {
	{Opt_norock, "norock"},
	{Opt_nojoliet, "nojoliet"},
	{Opt_unhide, "unhide"},
	{Opt_hide, "hide"},
	{Opt_showassoc, "showassoc"},
	{Opt_cruft, "cruft"},
	{Opt_utf8, "utf8"},
	{Opt_iocharset, "iocharset=%s"},
	{Opt_map_a, "map=acorn"},
	{Opt_map_a, "map=a"},
	{Opt_map_n, "map=normal"},
	{Opt_map_n, "map=n"},
	{Opt_map_o, "map=off"},
	{Opt_map_o, "map=o"},
	{Opt_session, "session=%u"},
	{Opt_sb, "sbsector=%u"},
	{Opt_check_r, "check=relaxed"},
	{Opt_check_r, "check=r"},
	{Opt_check_s, "check=strict"},
	{Opt_check_s, "check=s"},
	{Opt_uid, "uid=%u"},
	{Opt_gid, "gid=%u"},
	{Opt_mode, "mode=%u"},
	{Opt_dmode, "dmode=%u"},
	{Opt_overriderockperm, "overriderockperm"},
	{Opt_block, "block=%u"},
	{Opt_ignore, "conv=binary"},
	{Opt_ignore, "conv=b"},
	{Opt_ignore, "conv=text"},
	{Opt_ignore, "conv=t"},
	{Opt_ignore, "conv=mtext"},
	{Opt_ignore, "conv=m"},
	{Opt_ignore, "conv=auto"},
	{Opt_ignore, "conv=a"},
	{Opt_nocompress, "nocompress"},
	{Opt_err, NULL}
};

static int parse_options(char *options, struct iso9660_options *popt)
{
	char *p;
	int option;

	popt->map = 'n';
	popt->rock = 1;
	popt->joliet = 1;
	popt->cruft = 0;
	popt->hide = 0;
	popt->showassoc = 0;
	popt->check = 'u';		/* unset */
	popt->nocompress = 0;
	popt->blocksize = 1024;
	popt->fmode = popt->dmode = ISOFS_INVALID_MODE;
	popt->uid_set = 0;
	popt->gid_set = 0;
	popt->gid = GLOBAL_ROOT_GID;
	popt->uid = GLOBAL_ROOT_UID;
	popt->iocharset = NULL;
	popt->utf8 = 0;
	popt->overriderockperm = 0;
	popt->session=-1;
	popt->sbsector=-1;
	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;
		substring_t args[MAX_OPT_ARGS];
		unsigned n;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_norock:
			popt->rock = 0;
			break;
		case Opt_nojoliet:
			popt->joliet = 0;
			break;
		case Opt_hide:
			popt->hide = 1;
			break;
		case Opt_unhide:
		case Opt_showassoc:
			popt->showassoc = 1;
			break;
		case Opt_cruft:
			popt->cruft = 1;
			break;
		case Opt_utf8:
			popt->utf8 = 1;
			break;
#ifdef CONFIG_JOLIET
		case Opt_iocharset:
			popt->iocharset = match_strdup(&args[0]);
			break;
#endif
		case Opt_map_a:
			popt->map = 'a';
			break;
		case Opt_map_o:
			popt->map = 'o';
			break;
		case Opt_map_n:
			popt->map = 'n';
			break;
		case Opt_session:
			if (match_int(&args[0], &option))
				return 0;
			n = option;
			if (n > 99)
				return 0;
			popt->session = n + 1;
			break;
		case Opt_sb:
			if (match_int(&args[0], &option))
				return 0;
			popt->sbsector = option;
			break;
		case Opt_check_r:
			popt->check = 'r';
			break;
		case Opt_check_s:
			popt->check = 's';
			break;
		case Opt_ignore:
			break;
		case Opt_uid:
			if (match_int(&args[0], &option))
				return 0;
			popt->uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(popt->uid))
				return 0;
			popt->uid_set = 1;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				return 0;
			popt->gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(popt->gid))
				return 0;
			popt->gid_set = 1;
			break;
		case Opt_mode:
			if (match_int(&args[0], &option))
				return 0;
			popt->fmode = option;
			break;
		case Opt_dmode:
			if (match_int(&args[0], &option))
				return 0;
			popt->dmode = option;
			break;
		case Opt_overriderockperm:
			popt->overriderockperm = 1;
			break;
		case Opt_block:
			if (match_int(&args[0], &option))
				return 0;
			n = option;
			if (n != 512 && n != 1024 && n != 2048)
				return 0;
			popt->blocksize = n;
			break;
		case Opt_nocompress:
			popt->nocompress = 1;
			break;
		default:
			return 0;
		}
	}
	return 1;
}

/*
 * look if the driver can tell the multi session redirection value
 *
 * don't change this if you don't know what you do, please!
 * Multisession is legal only with XA disks.
 * A non-XA disk with more than one volume descriptor may do it right, but
 * usually is written in a nowhere standardized "multi-partition" manner.
 * Multisession uses absolute addressing (solely the first frame of the whole
 * track is #0), multi-partition uses relative addressing (each first frame of
 * each track is #0), and a track is not a session.
 *
 * A broken CDwriter software or drive firmware does not set new standards,
 * at least not if conflicting with the existing ones.
 *
 * emoenke@gwdg.de
 */
#define WE_OBEY_THE_WRITTEN_STANDARDS 1

static unsigned int isofs_get_last_session(struct super_block *sb, s32 session)
{
	struct cdrom_multisession ms_info;
	unsigned int vol_desc_start;
	struct block_device *bdev = sb->s_bdev;
	int i;

	vol_desc_start=0;
	ms_info.addr_format=CDROM_LBA;
	if(session >= 0 && session <= 99) {
		struct cdrom_tocentry Te;
		Te.cdte_track=session;
		Te.cdte_format=CDROM_LBA;
		i = ioctl_by_bdev(bdev, CDROMREADTOCENTRY, (unsigned long) &Te);
		if (!i) {
			printk(KERN_DEBUG "ISOFS: Session %d start %d type %d\n",
				session, Te.cdte_addr.lba,
				Te.cdte_ctrl&CDROM_DATA_TRACK);
			if ((Te.cdte_ctrl&CDROM_DATA_TRACK) == 4)
				return Te.cdte_addr.lba;
		}

		printk(KERN_ERR "ISOFS: Invalid session number or type of track\n");
	}
	i = ioctl_by_bdev(bdev, CDROMMULTISESSION, (unsigned long) &ms_info);
	if (session > 0)
		printk(KERN_ERR "ISOFS: Invalid session number\n");
#if 0
	printk(KERN_DEBUG "isofs.inode: CDROMMULTISESSION: rc=%d\n",i);
	if (i==0) {
		printk(KERN_DEBUG "isofs.inode: XA disk: %s\n",ms_info.xa_flag?"yes":"no");
		printk(KERN_DEBUG "isofs.inode: vol_desc_start = %d\n", ms_info.addr.lba);
	}
#endif
	if (i==0)
#if WE_OBEY_THE_WRITTEN_STANDARDS
		if (ms_info.xa_flag) /* necessary for a valid ms_info.addr */
#endif
			vol_desc_start=ms_info.addr.lba;
	return vol_desc_start;
}

/*
 * Check if root directory is empty (has less than 3 files).
 *
 * Used to detect broken CDs where ISO root directory is empty but Joliet root
 * directory is OK. If such CD has Rock Ridge extensions, they will be disabled
 * (and Joliet used instead) or else no files would be visible.
 */
static bool rootdir_empty(struct super_block *sb, unsigned long block)
{
	int offset = 0, files = 0, de_len;
	struct iso_directory_record *de;
	struct buffer_head *bh;

	bh = sb_bread(sb, block);
	if (!bh)
		return true;
	while (files < 3) {
		de = (struct iso_directory_record *) (bh->b_data + offset);
		de_len = *(unsigned char *) de;
		if (de_len == 0)
			break;
		files++;
		offset += de_len;
	}
	brelse(bh);
	return files < 3;
}

/*
 * Initialize the superblock and read the root inode.
 *
 * Note: a check_disk_change() has been done immediately prior
 * to this call, so we don't need to check again.
 */
static int isofs_fill_super(struct super_block *s, void *data, int silent)
{
	struct buffer_head *bh = NULL, *pri_bh = NULL;
	struct hs_primary_descriptor *h_pri = NULL;
	struct iso_primary_descriptor *pri = NULL;
	struct iso_supplementary_descriptor *sec = NULL;
	struct iso_directory_record *rootp;
	struct inode *inode;
	struct iso9660_options opt;
	struct isofs_sb_info *sbi;
	unsigned long first_data_zone;
	int joliet_level = 0;
	int iso_blknum, block;
	int orig_zonesize;
	int table, error = -EINVAL;
	unsigned int vol_desc_start;

	save_mount_options(s, data);

	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	s->s_fs_info = sbi;

	if (!parse_options((char *)data, &opt))
		goto out_freesbi;

	/*
	 * First of all, get the hardware blocksize for this device.
	 * If we don't know what it is, or the hardware blocksize is
	 * larger than the blocksize the user specified, then use
	 * that value.
	 */
	/*
	 * What if bugger tells us to go beyond page size?
	 */
	opt.blocksize = sb_min_blocksize(s, opt.blocksize);

	sbi->s_high_sierra = 0; /* default is iso9660 */

	vol_desc_start = (opt.sbsector != -1) ?
		opt.sbsector : isofs_get_last_session(s,opt.session);

	for (iso_blknum = vol_desc_start+16;
		iso_blknum < vol_desc_start+100; iso_blknum++) {
		struct hs_volume_descriptor *hdp;
		struct iso_volume_descriptor  *vdp;

		block = iso_blknum << (ISOFS_BLOCK_BITS - s->s_blocksize_bits);
		if (!(bh = sb_bread(s, block)))
			goto out_no_read;

		vdp = (struct iso_volume_descriptor *)bh->b_data;
		hdp = (struct hs_volume_descriptor *)bh->b_data;

		/*
		 * Due to the overlapping physical location of the descriptors,
		 * ISO CDs can match hdp->id==HS_STANDARD_ID as well. To ensure
		 * proper identification in this case, we first check for ISO.
		 */
		if (strncmp (vdp->id, ISO_STANDARD_ID, sizeof vdp->id) == 0) {
			if (isonum_711(vdp->type) == ISO_VD_END)
				break;
			if (isonum_711(vdp->type) == ISO_VD_PRIMARY) {
				if (pri == NULL) {
					pri = (struct iso_primary_descriptor *)vdp;
					/* Save the buffer in case we need it ... */
					pri_bh = bh;
					bh = NULL;
				}
			}
#ifdef CONFIG_JOLIET
			else if (isonum_711(vdp->type) == ISO_VD_SUPPLEMENTARY) {
				sec = (struct iso_supplementary_descriptor *)vdp;
				if (sec->escape[0] == 0x25 && sec->escape[1] == 0x2f) {
					if (opt.joliet) {
						if (sec->escape[2] == 0x40)
							joliet_level = 1;
						else if (sec->escape[2] == 0x43)
							joliet_level = 2;
						else if (sec->escape[2] == 0x45)
							joliet_level = 3;

						printk(KERN_DEBUG "ISO 9660 Extensions: "
							"Microsoft Joliet Level %d\n",
							joliet_level);
					}
					goto root_found;
				} else {
				/* Unknown supplementary volume descriptor */
				sec = NULL;
				}
			}
#endif
		} else {
			if (strncmp (hdp->id, HS_STANDARD_ID, sizeof hdp->id) == 0) {
				if (isonum_711(hdp->type) != ISO_VD_PRIMARY)
					goto out_freebh;

				sbi->s_high_sierra = 1;
				opt.rock = 0;
				h_pri = (struct hs_primary_descriptor *)vdp;
				goto root_found;
			}
		}

		/* Just skip any volume descriptors we don't recognize */

		brelse(bh);
		bh = NULL;
	}
	/*
	 * If we fall through, either no volume descriptor was found,
	 * or else we passed a primary descriptor looking for others.
	 */
	if (!pri)
		goto out_unknown_format;
	brelse(bh);
	bh = pri_bh;
	pri_bh = NULL;

root_found:

	if (joliet_level && (pri == NULL || !opt.rock)) {
		/* This is the case of Joliet with the norock mount flag.
		 * A disc with both Joliet and Rock Ridge is handled later
		 */
		pri = (struct iso_primary_descriptor *) sec;
	}

	if(sbi->s_high_sierra){
		rootp = (struct iso_directory_record *) h_pri->root_directory_record;
		sbi->s_nzones = isonum_733(h_pri->volume_space_size);
		sbi->s_log_zone_size = isonum_723(h_pri->logical_block_size);
		sbi->s_max_size = isonum_733(h_pri->volume_space_size);
	} else {
		if (!pri)
			goto out_freebh;
		rootp = (struct iso_directory_record *) pri->root_directory_record;
		sbi->s_nzones = isonum_733(pri->volume_space_size);
		sbi->s_log_zone_size = isonum_723(pri->logical_block_size);
		sbi->s_max_size = isonum_733(pri->volume_space_size);
	}

	sbi->s_ninodes = 0; /* No way to figure this out easily */

	orig_zonesize = sbi->s_log_zone_size;
	/*
	 * If the zone size is smaller than the hardware sector size,
	 * this is a fatal error.  This would occur if the disc drive
	 * had sectors that were 2048 bytes, but the filesystem had
	 * blocks that were 512 bytes (which should only very rarely
	 * happen.)
	 */
	if (orig_zonesize < opt.blocksize)
		goto out_bad_size;

	/* RDE: convert log zone size to bit shift */
	switch (sbi->s_log_zone_size) {
	case  512: sbi->s_log_zone_size =  9; break;
	case 1024: sbi->s_log_zone_size = 10; break;
	case 2048: sbi->s_log_zone_size = 11; break;

	default:
		goto out_bad_zone_size;
	}

	s->s_magic = ISOFS_SUPER_MAGIC;

	/*
	 * With multi-extent files, file size is only limited by the maximum
	 * size of a file system, which is 8 TB.
	 */
	s->s_maxbytes = 0x80000000000LL;

	/* Set this for reference. Its not currently used except on write
	   which we don't have .. */

	first_data_zone = isonum_733(rootp->extent) +
			  isonum_711(rootp->ext_attr_length);
	sbi->s_firstdatazone = first_data_zone;
#ifndef BEQUIET
	printk(KERN_DEBUG "ISOFS: Max size:%ld   Log zone size:%ld\n",
		sbi->s_max_size, 1UL << sbi->s_log_zone_size);
	printk(KERN_DEBUG "ISOFS: First datazone:%ld\n", sbi->s_firstdatazone);
	if(sbi->s_high_sierra)
		printk(KERN_DEBUG "ISOFS: Disc in High Sierra format.\n");
#endif

	/*
	 * If the Joliet level is set, we _may_ decide to use the
	 * secondary descriptor, but can't be sure until after we
	 * read the root inode. But before reading the root inode
	 * we may need to change the device blocksize, and would
	 * rather release the old buffer first. So, we cache the
	 * first_data_zone value from the secondary descriptor.
	 */
	if (joliet_level) {
		pri = (struct iso_primary_descriptor *) sec;
		rootp = (struct iso_directory_record *)
			pri->root_directory_record;
		first_data_zone = isonum_733(rootp->extent) +
				isonum_711(rootp->ext_attr_length);
	}

	/*
	 * We're all done using the volume descriptor, and may need
	 * to change the device blocksize, so release the buffer now.
	 */
	brelse(pri_bh);
	brelse(bh);

	/*
	 * Force the blocksize to 512 for 512 byte sectors.  The file
	 * read primitives really get it wrong in a bad way if we don't
	 * do this.
	 *
	 * Note - we should never be setting the blocksize to something
	 * less than the hardware sector size for the device.  If we
	 * do, we would end up having to read larger buffers and split
	 * out portions to satisfy requests.
	 *
	 * Note2- the idea here is that we want to deal with the optimal
	 * zonesize in the filesystem.  If we have it set to something less,
	 * then we have horrible problems with trying to piece together
	 * bits of adjacent blocks in order to properly read directory
	 * entries.  By forcing the blocksize in this way, we ensure
	 * that we will never be required to do this.
	 */
	sb_set_blocksize(s, orig_zonesize);

	sbi->s_nls_iocharset = NULL;

#ifdef CONFIG_JOLIET
	if (joliet_level && opt.utf8 == 0) {
		char *p = opt.iocharset ? opt.iocharset : CONFIG_NLS_DEFAULT;
		sbi->s_nls_iocharset = load_nls(p);
		if (! sbi->s_nls_iocharset) {
			/* Fail only if explicit charset specified */
			if (opt.iocharset)
				goto out_freesbi;
			sbi->s_nls_iocharset = load_nls_default();
		}
	}
#endif
	s->s_op = &isofs_sops;
	s->s_export_op = &isofs_export_ops;
	sbi->s_mapping = opt.map;
	sbi->s_rock = (opt.rock ? 2 : 0);
	sbi->s_rock_offset = -1; /* initial offset, will guess until SP is found*/
	sbi->s_cruft = opt.cruft;
	sbi->s_hide = opt.hide;
	sbi->s_showassoc = opt.showassoc;
	sbi->s_uid = opt.uid;
	sbi->s_gid = opt.gid;
	sbi->s_uid_set = opt.uid_set;
	sbi->s_gid_set = opt.gid_set;
	sbi->s_utf8 = opt.utf8;
	sbi->s_nocompress = opt.nocompress;
	sbi->s_overriderockperm = opt.overriderockperm;
	/*
	 * It would be incredibly stupid to allow people to mark every file
	 * on the disk as suid, so we merely allow them to set the default
	 * permissions.
	 */
	if (opt.fmode != ISOFS_INVALID_MODE)
		sbi->s_fmode = opt.fmode & 0777;
	else
		sbi->s_fmode = ISOFS_INVALID_MODE;
	if (opt.dmode != ISOFS_INVALID_MODE)
		sbi->s_dmode = opt.dmode & 0777;
	else
		sbi->s_dmode = ISOFS_INVALID_MODE;

	/*
	 * Read the root inode, which _may_ result in changing
	 * the s_rock flag. Once we have the final s_rock value,
	 * we then decide whether to use the Joliet descriptor.
	 */
	inode = isofs_iget(s, sbi->s_firstdatazone, 0);
	if (IS_ERR(inode))
		goto out_no_root;

	/*
	 * Fix for broken CDs with Rock Ridge and empty ISO root directory but
	 * correct Joliet root directory.
	 */
	if (sbi->s_rock == 1 && joliet_level &&
				rootdir_empty(s, sbi->s_firstdatazone)) {
		printk(KERN_NOTICE
			"ISOFS: primary root directory is empty. "
			"Disabling Rock Ridge and switching to Joliet.");
		sbi->s_rock = 0;
	}

	/*
	 * If this disk has both Rock Ridge and Joliet on it, then we
	 * want to use Rock Ridge by default.  This can be overridden
	 * by using the norock mount option.  There is still one other
	 * possibility that is not taken into account: a Rock Ridge
	 * CD with Unicode names.  Until someone sees such a beast, it
	 * will not be supported.
	 */
	if (sbi->s_rock == 1) {
		joliet_level = 0;
	} else if (joliet_level) {
		sbi->s_rock = 0;
		if (sbi->s_firstdatazone != first_data_zone) {
			sbi->s_firstdatazone = first_data_zone;
			printk(KERN_DEBUG
				"ISOFS: changing to secondary root\n");
			iput(inode);
			inode = isofs_iget(s, sbi->s_firstdatazone, 0);
			if (IS_ERR(inode))
				goto out_no_root;
		}
	}

	if (opt.check == 'u') {
		/* Only Joliet is case insensitive by default */
		if (joliet_level)
			opt.check = 'r';
		else
			opt.check = 's';
	}
	sbi->s_joliet_level = joliet_level;

	/* Make sure the root inode is a directory */
	if (!S_ISDIR(inode->i_mode)) {
		printk(KERN_WARNING
			"isofs_fill_super: root inode is not a directory. "
			"Corrupted media?\n");
		goto out_iput;
	}

	table = 0;
	if (joliet_level)
		table += 2;
	if (opt.check == 'r')
		table++;

	if (table)
		s->s_d_op = &isofs_dentry_ops[table - 1];

	/* get the root dentry */
	s->s_root = d_make_root(inode);
	if (!(s->s_root)) {
		error = -ENOMEM;
		goto out_no_inode;
	}

	kfree(opt.iocharset);

	return 0;

	/*
	 * Display error messages and free resources.
	 */
out_iput:
	iput(inode);
	goto out_no_inode;
out_no_root:
	error = PTR_ERR(inode);
	if (error != -ENOMEM)
		printk(KERN_WARNING "%s: get root inode failed\n", __func__);
out_no_inode:
#ifdef CONFIG_JOLIET
	unload_nls(sbi->s_nls_iocharset);
#endif
	goto out_freesbi;
out_no_read:
	printk(KERN_WARNING "%s: bread failed, dev=%s, iso_blknum=%d, block=%d\n",
		__func__, s->s_id, iso_blknum, block);
	goto out_freebh;
out_bad_zone_size:
	printk(KERN_WARNING "ISOFS: Bad logical zone size %ld\n",
		sbi->s_log_zone_size);
	goto out_freebh;
out_bad_size:
	printk(KERN_WARNING "ISOFS: Logical zone size(%d) < hardware blocksize(%u)\n",
		orig_zonesize, opt.blocksize);
	goto out_freebh;
out_unknown_format:
	if (!silent)
		printk(KERN_WARNING "ISOFS: Unable to identify CD-ROM format.\n");

out_freebh:
	brelse(bh);
	brelse(pri_bh);
out_freesbi:
	kfree(opt.iocharset);
	kfree(sbi);
	s->s_fs_info = NULL;
	return error;
}

static int isofs_statfs (struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type = ISOFS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = (ISOFS_SB(sb)->s_nzones
		<< (ISOFS_SB(sb)->s_log_zone_size - sb->s_blocksize_bits));
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_files = ISOFS_SB(sb)->s_ninodes;
	buf->f_ffree = 0;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = NAME_MAX;
	return 0;
}

/*
 * Get a set of blocks; filling in buffer_heads if already allocated
 * or getblk() if they are not.  Returns the number of blocks inserted
 * (-ve == error.)
 */
int isofs_get_blocks(struct inode *inode, sector_t iblock,
		     struct buffer_head **bh, unsigned long nblocks)
{
	unsigned long b_off = iblock;
	unsigned offset, sect_size;
	unsigned int firstext;
	unsigned long nextblk, nextoff;
	int section, rv, error;
	struct iso_inode_info *ei = ISOFS_I(inode);

	error = -EIO;
	rv = 0;
	if (iblock != b_off) {
		printk(KERN_DEBUG "%s: block number too large\n", __func__);
		goto abort;
	}


	offset = 0;
	firstext = ei->i_first_extent;
	sect_size = ei->i_section_size >> ISOFS_BUFFER_BITS(inode);
	nextblk = ei->i_next_section_block;
	nextoff = ei->i_next_section_offset;
	section = 0;

	while (nblocks) {
		/* If we are *way* beyond the end of the file, print a message.
		 * Access beyond the end of the file up to the next page boundary
		 * is normal, however because of the way the page cache works.
		 * In this case, we just return 0 so that we can properly fill
		 * the page with useless information without generating any
		 * I/O errors.
		 */
		if (b_off > ((inode->i_size + PAGE_CACHE_SIZE - 1) >> ISOFS_BUFFER_BITS(inode))) {
			printk(KERN_DEBUG "%s: block >= EOF (%lu, %llu)\n",
				__func__, b_off,
				(unsigned long long)inode->i_size);
			goto abort;
		}

		/* On the last section, nextblk == 0, section size is likely to
		 * exceed sect_size by a partial block, and access beyond the
		 * end of the file will reach beyond the section size, too.
		 */
		while (nextblk && (b_off >= (offset + sect_size))) {
			struct inode *ninode;

			offset += sect_size;
			ninode = isofs_iget(inode->i_sb, nextblk, nextoff);
			if (IS_ERR(ninode)) {
				error = PTR_ERR(ninode);
				goto abort;
			}
			firstext  = ISOFS_I(ninode)->i_first_extent;
			sect_size = ISOFS_I(ninode)->i_section_size >> ISOFS_BUFFER_BITS(ninode);
			nextblk   = ISOFS_I(ninode)->i_next_section_block;
			nextoff   = ISOFS_I(ninode)->i_next_section_offset;
			iput(ninode);

			if (++section > 100) {
				printk(KERN_DEBUG "%s: More than 100 file sections ?!?"
					" aborting...\n", __func__);
				printk(KERN_DEBUG "%s: block=%lu firstext=%u sect_size=%u "
					"nextblk=%lu nextoff=%lu\n", __func__,
					b_off, firstext, (unsigned) sect_size,
					nextblk, nextoff);
				goto abort;
			}
		}

		if (*bh) {
			map_bh(*bh, inode->i_sb, firstext + b_off - offset);
		} else {
			*bh = sb_getblk(inode->i_sb, firstext+b_off-offset);
			if (!*bh)
				goto abort;
		}
		bh++;	/* Next buffer head */
		b_off++;	/* Next buffer offset */
		nblocks--;
		rv++;
	}

	error = 0;
abort:
	return rv != 0 ? rv : error;
}

/*
 * Used by the standard interfaces.
 */
static int isofs_get_block(struct inode *inode, sector_t iblock,
		    struct buffer_head *bh_result, int create)
{
	int ret;

	if (create) {
		printk(KERN_DEBUG "%s: Kernel tries to allocate a block\n", __func__);
		return -EROFS;
	}

	ret = isofs_get_blocks(inode, iblock, &bh_result, 1);
	return ret < 0 ? ret : 0;
}

static int isofs_bmap(struct inode *inode, sector_t block)
{
	struct buffer_head dummy;
	int error;

	dummy.b_state = 0;
	dummy.b_blocknr = -1000;
	error = isofs_get_block(inode, block, &dummy, 0);
	if (!error)
		return dummy.b_blocknr;
	return 0;
}

struct buffer_head *isofs_bread(struct inode *inode, sector_t block)
{
	sector_t blknr = isofs_bmap(inode, block);
	if (!blknr)
		return NULL;
	return sb_bread(inode->i_sb, blknr);
}

static int isofs_readpage(struct file *file, struct page *page)
{
	return mpage_readpage(page, isofs_get_block);
}

static int isofs_readpages(struct file *file, struct address_space *mapping,
			struct list_head *pages, unsigned nr_pages)
{
	return mpage_readpages(mapping, pages, nr_pages, isofs_get_block);
}

static sector_t _isofs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,isofs_get_block);
}

static const struct address_space_operations isofs_aops = {
	.readpage = isofs_readpage,
	.readpages = isofs_readpages,
	.bmap = _isofs_bmap
};

static int isofs_read_level3_size(struct inode *inode)
{
	unsigned long bufsize = ISOFS_BUFFER_SIZE(inode);
	int high_sierra = ISOFS_SB(inode->i_sb)->s_high_sierra;
	struct buffer_head *bh = NULL;
	unsigned long block, offset, block_saved, offset_saved;
	int i = 0;
	int more_entries = 0;
	struct iso_directory_record *tmpde = NULL;
	struct iso_inode_info *ei = ISOFS_I(inode);

	inode->i_size = 0;

	/* The first 16 blocks are reserved as the System Area.  Thus,
	 * no inodes can appear in block 0.  We use this to flag that
	 * this is the last section. */
	ei->i_next_section_block = 0;
	ei->i_next_section_offset = 0;

	block = ei->i_iget5_block;
	offset = ei->i_iget5_offset;

	do {
		struct iso_directory_record *de;
		unsigned int de_len;

		if (!bh) {
			bh = sb_bread(inode->i_sb, block);
			if (!bh)
				goto out_noread;
		}
		de = (struct iso_directory_record *) (bh->b_data + offset);
		de_len = *(unsigned char *) de;

		if (de_len == 0) {
			brelse(bh);
			bh = NULL;
			++block;
			offset = 0;
			continue;
		}

		block_saved = block;
		offset_saved = offset;
		offset += de_len;

		/* Make sure we have a full directory entry */
		if (offset >= bufsize) {
			int slop = bufsize - offset + de_len;
			if (!tmpde) {
				tmpde = kmalloc(256, GFP_KERNEL);
				if (!tmpde)
					goto out_nomem;
			}
			memcpy(tmpde, de, slop);
			offset &= bufsize - 1;
			block++;
			brelse(bh);
			bh = NULL;
			if (offset) {
				bh = sb_bread(inode->i_sb, block);
				if (!bh)
					goto out_noread;
				memcpy((void *)tmpde+slop, bh->b_data, offset);
			}
			de = tmpde;
		}

		inode->i_size += isonum_733(de->size);
		if (i == 1) {
			ei->i_next_section_block = block_saved;
			ei->i_next_section_offset = offset_saved;
		}

		more_entries = de->flags[-high_sierra] & 0x80;

		i++;
		if (i > 100)
			goto out_toomany;
	} while (more_entries);
out:
	kfree(tmpde);
	if (bh)
		brelse(bh);
	return 0;

out_nomem:
	if (bh)
		brelse(bh);
	return -ENOMEM;

out_noread:
	printk(KERN_INFO "ISOFS: unable to read i-node block %lu\n", block);
	kfree(tmpde);
	return -EIO;

out_toomany:
	printk(KERN_INFO "%s: More than 100 file sections ?!?, aborting...\n"
		"isofs_read_level3_size: inode=%lu\n",
		__func__, inode->i_ino);
	goto out;
}

static int isofs_read_inode(struct inode *inode, int relocated)
{
	struct super_block *sb = inode->i_sb;
	struct isofs_sb_info *sbi = ISOFS_SB(sb);
	unsigned long bufsize = ISOFS_BUFFER_SIZE(inode);
	unsigned long block;
	int high_sierra = sbi->s_high_sierra;
	struct buffer_head *bh = NULL;
	struct iso_directory_record *de;
	struct iso_directory_record *tmpde = NULL;
	unsigned int de_len;
	unsigned long offset;
	struct iso_inode_info *ei = ISOFS_I(inode);
	int ret = -EIO;

	block = ei->i_iget5_block;
	bh = sb_bread(inode->i_sb, block);
	if (!bh)
		goto out_badread;

	offset = ei->i_iget5_offset;

	de = (struct iso_directory_record *) (bh->b_data + offset);
	de_len = *(unsigned char *) de;

	if (offset + de_len > bufsize) {
		int frag1 = bufsize - offset;

		tmpde = kmalloc(de_len, GFP_KERNEL);
		if (tmpde == NULL) {
			printk(KERN_INFO "%s: out of memory\n", __func__);
			ret = -ENOMEM;
			goto fail;
		}
		memcpy(tmpde, bh->b_data + offset, frag1);
		brelse(bh);
		bh = sb_bread(inode->i_sb, ++block);
		if (!bh)
			goto out_badread;
		memcpy((char *)tmpde+frag1, bh->b_data, de_len - frag1);
		de = tmpde;
	}

	inode->i_ino = isofs_get_ino(ei->i_iget5_block,
					ei->i_iget5_offset,
					ISOFS_BUFFER_BITS(inode));

	/* Assume it is a normal-format file unless told otherwise */
	ei->i_file_format = isofs_file_normal;

	if (de->flags[-high_sierra] & 2) {
		if (sbi->s_dmode != ISOFS_INVALID_MODE)
			inode->i_mode = S_IFDIR | sbi->s_dmode;
		else
			inode->i_mode = S_IFDIR | S_IRUGO | S_IXUGO;
		set_nlink(inode, 1);	/*
					 * Set to 1.  We know there are 2, but
					 * the find utility tries to optimize
					 * if it is 2, and it screws up.  It is
					 * easier to give 1 which tells find to
					 * do it the hard way.
					 */
	} else {
		if (sbi->s_fmode != ISOFS_INVALID_MODE) {
			inode->i_mode = S_IFREG | sbi->s_fmode;
		} else {
			/*
			 * Set default permissions: r-x for all.  The disc
			 * could be shared with DOS machines so virtually
			 * anything could be a valid executable.
			 */
			inode->i_mode = S_IFREG | S_IRUGO | S_IXUGO;
		}
		set_nlink(inode, 1);
	}
	inode->i_uid = sbi->s_uid;
	inode->i_gid = sbi->s_gid;
	inode->i_blocks = 0;

	ei->i_format_parm[0] = 0;
	ei->i_format_parm[1] = 0;
	ei->i_format_parm[2] = 0;

	ei->i_section_size = isonum_733(de->size);
	if (de->flags[-high_sierra] & 0x80) {
		ret = isofs_read_level3_size(inode);
		if (ret < 0)
			goto fail;
		ret = -EIO;
	} else {
		ei->i_next_section_block = 0;
		ei->i_next_section_offset = 0;
		inode->i_size = isonum_733(de->size);
	}

	/*
	 * Some dipshit decided to store some other bit of information
	 * in the high byte of the file length.  Truncate size in case
	 * this CDROM was mounted with the cruft option.
	 */

	if (sbi->s_cruft)
		inode->i_size &= 0x00ffffff;

	if (de->interleave[0]) {
		printk(KERN_DEBUG "ISOFS: Interleaved files not (yet) supported.\n");
		inode->i_size = 0;
	}

	/* I have no idea what file_unit_size is used for, so
	   we will flag it for now */
	if (de->file_unit_size[0] != 0) {
		printk(KERN_DEBUG "ISOFS: File unit size != 0 for ISO file (%ld).\n",
			inode->i_ino);
	}

	/* I have no idea what other flag bits are used for, so
	   we will flag it for now */
#ifdef DEBUG
	if((de->flags[-high_sierra] & ~2)!= 0){
		printk(KERN_DEBUG "ISOFS: Unusual flag settings for ISO file "
				"(%ld %x).\n",
			inode->i_ino, de->flags[-high_sierra]);
	}
#endif

	inode->i_mtime.tv_sec =
	inode->i_atime.tv_sec =
	inode->i_ctime.tv_sec = iso_date(de->date, high_sierra);
	inode->i_mtime.tv_nsec =
	inode->i_atime.tv_nsec =
	inode->i_ctime.tv_nsec = 0;

	ei->i_first_extent = (isonum_733(de->extent) +
			isonum_711(de->ext_attr_length));

	/* Set the number of blocks for stat() - should be done before RR */
	inode->i_blocks = (inode->i_size + 511) >> 9;

	/*
	 * Now test for possible Rock Ridge extensions which will override
	 * some of these numbers in the inode structure.
	 */

	if (!high_sierra) {
		parse_rock_ridge_inode(de, inode, relocated);
		/* if we want uid/gid set, override the rock ridge setting */
		if (sbi->s_uid_set)
			inode->i_uid = sbi->s_uid;
		if (sbi->s_gid_set)
			inode->i_gid = sbi->s_gid;
	}
	/* Now set final access rights if overriding rock ridge setting */
	if (S_ISDIR(inode->i_mode) && sbi->s_overriderockperm &&
	    sbi->s_dmode != ISOFS_INVALID_MODE)
		inode->i_mode = S_IFDIR | sbi->s_dmode;
	if (S_ISREG(inode->i_mode) && sbi->s_overriderockperm &&
	    sbi->s_fmode != ISOFS_INVALID_MODE)
		inode->i_mode = S_IFREG | sbi->s_fmode;

	/* Install the inode operations vector */
	if (S_ISREG(inode->i_mode)) {
		inode->i_fop = &generic_ro_fops;
		switch (ei->i_file_format) {
#ifdef CONFIG_ZISOFS
		case isofs_file_compressed:
			inode->i_data.a_ops = &zisofs_aops;
			break;
#endif
		default:
			inode->i_data.a_ops = &isofs_aops;
			break;
		}
	} else if (S_ISDIR(inode->i_mode)) {
		inode->i_op = &isofs_dir_inode_operations;
		inode->i_fop = &isofs_dir_operations;
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_op = &page_symlink_inode_operations;
		inode->i_data.a_ops = &isofs_symlink_aops;
	} else
		/* XXX - parse_rock_ridge_inode() had already set i_rdev. */
		init_special_inode(inode, inode->i_mode, inode->i_rdev);

	ret = 0;
out:
	kfree(tmpde);
	if (bh)
		brelse(bh);
	return ret;

out_badread:
	printk(KERN_WARNING "ISOFS: unable to read i-node block\n");
fail:
	goto out;
}

struct isofs_iget5_callback_data {
	unsigned long block;
	unsigned long offset;
};

static int isofs_iget5_test(struct inode *ino, void *data)
{
	struct iso_inode_info *i = ISOFS_I(ino);
	struct isofs_iget5_callback_data *d =
		(struct isofs_iget5_callback_data*)data;
	return (i->i_iget5_block == d->block)
		&& (i->i_iget5_offset == d->offset);
}

static int isofs_iget5_set(struct inode *ino, void *data)
{
	struct iso_inode_info *i = ISOFS_I(ino);
	struct isofs_iget5_callback_data *d =
		(struct isofs_iget5_callback_data*)data;
	i->i_iget5_block = d->block;
	i->i_iget5_offset = d->offset;
	return 0;
}

/* Store, in the inode's containing structure, the block and block
 * offset that point to the underlying meta-data for the inode.  The
 * code below is otherwise similar to the iget() code in
 * include/linux/fs.h */
struct inode *__isofs_iget(struct super_block *sb,
			   unsigned long block,
			   unsigned long offset,
			   int relocated)
{
	unsigned long hashval;
	struct inode *inode;
	struct isofs_iget5_callback_data data;
	long ret;

	if (offset >= 1ul << sb->s_blocksize_bits)
		return ERR_PTR(-EINVAL);

	data.block = block;
	data.offset = offset;

	hashval = (block << sb->s_blocksize_bits) | offset;

	inode = iget5_locked(sb, hashval, &isofs_iget5_test,
				&isofs_iget5_set, &data);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	if (inode->i_state & I_NEW) {
		ret = isofs_read_inode(inode, relocated);
		if (ret < 0) {
			iget_failed(inode);
			inode = ERR_PTR(ret);
		} else {
			unlock_new_inode(inode);
		}
	}

	return inode;
}

static struct dentry *isofs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	/* We don't support read-write mounts */
	if (!(flags & MS_RDONLY))
		return ERR_PTR(-EACCES);
	return mount_bdev(fs_type, flags, dev_name, data, isofs_fill_super);
}

static struct file_system_type iso9660_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "iso9660",
	.mount		= isofs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("iso9660");
MODULE_ALIAS("iso9660");

static int __init init_iso9660_fs(void)
{
	int err = init_inodecache();
	if (err)
		goto out;
#ifdef CONFIG_ZISOFS
	err = zisofs_init();
	if (err)
		goto out1;
#endif
	err = register_filesystem(&iso9660_fs_type);
	if (err)
		goto out2;
	return 0;
out2:
#ifdef CONFIG_ZISOFS
	zisofs_cleanup();
out1:
#endif
	destroy_inodecache();
out:
	return err;
}

static void __exit exit_iso9660_fs(void)
{
        unregister_filesystem(&iso9660_fs_type);
#ifdef CONFIG_ZISOFS
	zisofs_cleanup();
#endif
	destroy_inodecache();
}

module_init(init_iso9660_fs)
module_exit(exit_iso9660_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/isofs/inode.c */
/************************************************************/
/*
 *  linux/fs/isofs/dir.c
 *
 *  (C) 1992, 1993, 1994  Eric Youngdale Modified for ISO 9660 filesystem.
 *
 *  (C) 1991  Linus Torvalds - minix filesystem
 *
 *  Steve Beynon		       : Missing last directory entries fixed
 *  (stephen@askone.demon.co.uk)      : 21st June 1996
 *
 *  isofs directory handling functions
 */
// #include <linux/gfp.h>
// #include "isofs.h"

int isofs_name_translate(struct iso_directory_record *de, char *new, struct inode *inode)
{
	char * old = de->name;
	int len = de->name_len[0];
	int i;

	for (i = 0; i < len; i++) {
		unsigned char c = old[i];
		if (!c)
			break;

		if (c >= 'A' && c <= 'Z')
			c |= 0x20;	/* lower case */

		/* Drop trailing '.;1' (ISO 9660:1988 7.5.1 requires period) */
		if (c == '.' && i == len - 3 && old[i + 1] == ';' && old[i + 2] == '1')
			break;

		/* Drop trailing ';1' */
		if (c == ';' && i == len - 2 && old[i + 1] == '1')
			break;

		/* Convert remaining ';' to '.' */
		/* Also '/' to '.' (broken Acorn-generated ISO9660 images) */
		if (c == ';' || c == '/')
			c = '.';

		new[i] = c;
	}
	return i;
}

/* Acorn extensions written by Matthew Wilcox <willy@bofh.ai> 1998 */
int get_acorn_filename(struct iso_directory_record *de,
			    char *retname, struct inode *inode)
{
	int std;
	unsigned char *chr;
	int retnamlen = isofs_name_translate(de, retname, inode);

	if (retnamlen == 0)
		return 0;
	std = sizeof(struct iso_directory_record) + de->name_len[0];
	if (std & 1)
		std++;
	if ((*((unsigned char *) de) - std) != 32)
		return retnamlen;
	chr = ((unsigned char *) de) + std;
	if (strncmp(chr, "ARCHIMEDES", 10))
		return retnamlen;
	if ((*retname == '_') && ((chr[19] & 1) == 1))
		*retname = '!';
	if (((de->flags[0] & 2) == 0) && (chr[13] == 0xff)
		&& ((chr[12] & 0xf0) == 0xf0)) {
		retname[retnamlen] = ',';
		sprintf(retname+retnamlen+1, "%3.3x",
			((chr[12] & 0xf) << 8) | chr[11]);
		retnamlen += 4;
	}
	return retnamlen;
}

/*
 * This should _really_ be cleaned up some day..
 */
static int do_isofs_readdir(struct inode *inode, struct file *file,
		struct dir_context *ctx,
		char *tmpname, struct iso_directory_record *tmpde)
{
	unsigned long bufsize = ISOFS_BUFFER_SIZE(inode);
	unsigned char bufbits = ISOFS_BUFFER_BITS(inode);
	unsigned long block, offset, block_saved, offset_saved;
	unsigned long inode_number = 0;	/* Quiet GCC */
	struct buffer_head *bh = NULL;
	int len;
	int map;
	int first_de = 1;
	char *p = NULL;		/* Quiet GCC */
	struct iso_directory_record *de;
	struct isofs_sb_info *sbi = ISOFS_SB(inode->i_sb);

	offset = ctx->pos & (bufsize - 1);
	block = ctx->pos >> bufbits;

	while (ctx->pos < inode->i_size) {
		int de_len;

		if (!bh) {
			bh = isofs_bread(inode, block);
			if (!bh)
				return 0;
		}

		de = (struct iso_directory_record *) (bh->b_data + offset);

		de_len = *(unsigned char *)de;

		/*
		 * If the length byte is zero, we should move on to the next
		 * CDROM sector.  If we are at the end of the directory, we
		 * kick out of the while loop.
		 */

		if (de_len == 0) {
			brelse(bh);
			bh = NULL;
			ctx->pos = (ctx->pos + ISOFS_BLOCK_SIZE) & ~(ISOFS_BLOCK_SIZE - 1);
			block = ctx->pos >> bufbits;
			offset = 0;
			continue;
		}

		block_saved = block;
		offset_saved = offset;
		offset += de_len;

		/* Make sure we have a full directory entry */
		if (offset >= bufsize) {
			int slop = bufsize - offset + de_len;
			memcpy(tmpde, de, slop);
			offset &= bufsize - 1;
			block++;
			brelse(bh);
			bh = NULL;
			if (offset) {
				bh = isofs_bread(inode, block);
				if (!bh)
					return 0;
				memcpy((void *) tmpde + slop, bh->b_data, offset);
			}
			de = tmpde;
		}
		/* Basic sanity check, whether name doesn't exceed dir entry */
		if (de_len < de->name_len[0] +
					sizeof(struct iso_directory_record)) {
			printk(KERN_NOTICE "iso9660: Corrupted directory entry"
			       " in block %lu of inode %lu\n", block,
			       inode->i_ino);
			return -EIO;
		}

		if (first_de) {
			isofs_normalize_block_and_offset(de,
							&block_saved,
							&offset_saved);
			inode_number = isofs_get_ino(block_saved,
							offset_saved, bufbits);
		}

		if (de->flags[-sbi->s_high_sierra] & 0x80) {
			first_de = 0;
			ctx->pos += de_len;
			continue;
		}
		first_de = 1;

		/* Handle the case of the '.' directory */
		if (de->name_len[0] == 1 && de->name[0] == 0) {
			if (!dir_emit_dot(file, ctx))
				break;
			ctx->pos += de_len;
			continue;
		}

		len = 0;

		/* Handle the case of the '..' directory */
		if (de->name_len[0] == 1 && de->name[0] == 1) {
			if (!dir_emit_dotdot(file, ctx))
				break;
			ctx->pos += de_len;
			continue;
		}

		/* Handle everything else.  Do name translation if there
		   is no Rock Ridge NM field. */

		/*
		 * Do not report hidden files if so instructed, or associated
		 * files unless instructed to do so
		 */
		if ((sbi->s_hide && (de->flags[-sbi->s_high_sierra] & 1)) ||
		    (!sbi->s_showassoc &&
				(de->flags[-sbi->s_high_sierra] & 4))) {
			ctx->pos += de_len;
			continue;
		}

		map = 1;
		if (sbi->s_rock) {
			len = get_rock_ridge_filename(de, tmpname, inode);
			if (len != 0) {		/* may be -1 */
				p = tmpname;
				map = 0;
			}
		}
		if (map) {
#ifdef CONFIG_JOLIET
			if (sbi->s_joliet_level) {
				len = get_joliet_filename(de, tmpname, inode);
				p = tmpname;
			} else
#endif
			if (sbi->s_mapping == 'a') {
				len = get_acorn_filename(de, tmpname, inode);
				p = tmpname;
			} else
			if (sbi->s_mapping == 'n') {
				len = isofs_name_translate(de, tmpname, inode);
				p = tmpname;
			} else {
				p = de->name;
				len = de->name_len[0];
			}
		}
		if (len > 0) {
			if (!dir_emit(ctx, p, len, inode_number, DT_UNKNOWN))
				break;
		}
		ctx->pos += de_len;

		continue;
	}
	if (bh)
		brelse(bh);
	return 0;
}

/*
 * Handle allocation of temporary space for name translation and
 * handling split directory entries.. The real work is done by
 * "do_isofs_readdir()".
 */
static int isofs_readdir(struct file *file, struct dir_context *ctx)
{
	int result;
	char *tmpname;
	struct iso_directory_record *tmpde;
	struct inode *inode = file_inode(file);

	tmpname = (char *)__get_free_page(GFP_KERNEL);
	if (tmpname == NULL)
		return -ENOMEM;

	tmpde = (struct iso_directory_record *) (tmpname+1024);

	result = do_isofs_readdir(inode, file, ctx, tmpname, tmpde);

	free_page((unsigned long) tmpname);
	return result;
}

const struct file_operations isofs_dir_operations =
{
	.llseek = generic_file_llseek,
	.read = generic_read_dir,
	.iterate = isofs_readdir,
};

/*
 * directories can handle most operations...
 */
const struct inode_operations isofs_dir_inode_operations =
{
	.lookup = isofs_lookup,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/isofs/dir.c */
/************************************************************/
/*
 *  linux/fs/isofs/util.c
 */

#include <linux/time.h>
// #include "isofs.h"
#include "../../inc/__fss.h"

/* 
 * We have to convert from a MM/DD/YY format to the Unix ctime format.
 * We have to take into account leap years and all of that good stuff.
 * Unfortunately, the kernel does not have the information on hand to
 * take into account daylight savings time, but it shouldn't matter.
 * The time stored should be localtime (with or without DST in effect),
 * and the timezone offset should hold the offset required to get back
 * to GMT.  Thus  we should always be correct.
 */

int iso_date(char * p, int flag)
{
	int year, month, day, hour, minute, second, tz;
	int crtime;

	year = p[0];
	month = p[1];
	day = p[2];
	hour = p[3];
	minute = p[4];
	second = p[5];
	if (flag == 0) tz = p[6]; /* High sierra has no time zone */
	else tz = 0;
	
	if (year < 0) {
		crtime = 0;
	} else {
		crtime = mktime64(year+1900, month, day, hour, minute, second);

		/* sign extend */
		if (tz & 0x80)
			tz |= (-1 << 8);
		
		/* 
		 * The timezone offset is unreliable on some disks,
		 * so we make a sanity check.  In no case is it ever
		 * more than 13 hours from GMT, which is 52*15min.
		 * The time is always stored in localtime with the
		 * timezone offset being what get added to GMT to
		 * get to localtime.  Thus we need to subtract the offset
		 * to get to true GMT, which is what we store the time
		 * as internally.  On the local system, the user may set
		 * their timezone any way they wish, of course, so GMT
		 * gets converted back to localtime on the receiving
		 * system.
		 *
		 * NOTE: mkisofs in versions prior to mkisofs-1.10 had
		 * the sign wrong on the timezone offset.  This has now
		 * been corrected there too, but if you are getting screwy
		 * results this may be the explanation.  If enough people
		 * complain, a user configuration option could be added
		 * to add the timezone offset in with the wrong sign
		 * for 'compatibility' with older discs, but I cannot see how
		 * it will matter that much.
		 *
		 * Thanks to kuhlmav@elec.canterbury.ac.nz (Volker Kuhlmann)
		 * for pointing out the sign error.
		 */
		if (-52 <= tz && tz <= 52)
			crtime -= tz * 15 * 60;
	}
	return crtime;
}		
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/isofs/util.c */
/************************************************************/
/*
 *  linux/fs/isofs/rock.c
 *
 *  (C) 1992, 1993  Eric Youngdale
 *
 *  Rock Ridge Extensions to iso9660
 */

// #include <linux/slab.h>
#include <linux/pagemap.h>
#include "../../inc/__fss.h"

// #include "isofs.h"
#include "rock.h"
#include "../../inc/__fss.h"

/*
 * These functions are designed to read the system areas of a directory record
 * and extract relevant information.  There are different functions provided
 * depending upon what information we need at the time.  One function fills
 * out an inode structure, a second one extracts a filename, a third one
 * returns a symbolic link name, and a fourth one returns the extent number
 * for the file.
 */

#define SIG(A,B) ((A) | ((B) << 8))	/* isonum_721() */

struct rock_state {
	void *buffer;
	unsigned char *chr;
	int len;
	int cont_size;
	int cont_extent;
	int cont_offset;
	int cont_loops;
	struct inode *inode;
};

/*
 * This is a way of ensuring that we have something in the system
 * use fields that is compatible with Rock Ridge.  Return zero on success.
 */

static int check_sp(struct rock_ridge *rr, struct inode *inode)
{
	if (rr->u.SP.magic[0] != 0xbe)
		return -1;
	if (rr->u.SP.magic[1] != 0xef)
		return -1;
	ISOFS_SB(inode->i_sb)->s_rock_offset = rr->u.SP.skip;
	return 0;
}

static void setup_rock_ridge(struct iso_directory_record *de,
			struct inode *inode, struct rock_state *rs)
{
	rs->len = sizeof(struct iso_directory_record) + de->name_len[0];
	if (rs->len & 1)
		(rs->len)++;
	rs->chr = (unsigned char *)de + rs->len;
	rs->len = *((unsigned char *)de) - rs->len;
	if (rs->len < 0)
		rs->len = 0;

	if (ISOFS_SB(inode->i_sb)->s_rock_offset != -1) {
		rs->len -= ISOFS_SB(inode->i_sb)->s_rock_offset;
		rs->chr += ISOFS_SB(inode->i_sb)->s_rock_offset;
		if (rs->len < 0)
			rs->len = 0;
	}
}

static void init_rock_state(struct rock_state *rs, struct inode *inode)
{
	memset(rs, 0, sizeof(*rs));
	rs->inode = inode;
}

/* Maximum number of Rock Ridge continuation entries */
#define RR_MAX_CE_ENTRIES 32

/*
 * Returns 0 if the caller should continue scanning, 1 if the scan must end
 * and -ve on error.
 */
static int rock_continue(struct rock_state *rs)
{
	int ret = 1;
	int blocksize = 1 << rs->inode->i_blkbits;
	const int min_de_size = offsetof(struct rock_ridge, u);

	kfree(rs->buffer);
	rs->buffer = NULL;

	if ((unsigned)rs->cont_offset > blocksize - min_de_size ||
	    (unsigned)rs->cont_size > blocksize ||
	    (unsigned)(rs->cont_offset + rs->cont_size) > blocksize) {
		printk(KERN_NOTICE "rock: corrupted directory entry. "
			"extent=%d, offset=%d, size=%d\n",
			rs->cont_extent, rs->cont_offset, rs->cont_size);
		ret = -EIO;
		goto out;
	}

	if (rs->cont_extent) {
		struct buffer_head *bh;

		rs->buffer = kmalloc(rs->cont_size, GFP_KERNEL);
		if (!rs->buffer) {
			ret = -ENOMEM;
			goto out;
		}
		ret = -EIO;
		if (++rs->cont_loops >= RR_MAX_CE_ENTRIES)
			goto out;
		bh = sb_bread(rs->inode->i_sb, rs->cont_extent);
		if (bh) {
			memcpy(rs->buffer, bh->b_data + rs->cont_offset,
					rs->cont_size);
			put_bh(bh);
			rs->chr = rs->buffer;
			rs->len = rs->cont_size;
			rs->cont_extent = 0;
			rs->cont_size = 0;
			rs->cont_offset = 0;
			return 0;
		}
		printk("Unable to read rock-ridge attributes\n");
	}
out:
	kfree(rs->buffer);
	rs->buffer = NULL;
	return ret;
}

/*
 * We think there's a record of type `sig' at rs->chr.  Parse the signature
 * and make sure that there's really room for a record of that type.
 */
static int rock_check_overflow(struct rock_state *rs, int sig)
{
	int len;

	switch (sig) {
	case SIG('S', 'P'):
		len = sizeof(struct SU_SP_s);
		break;
	case SIG('C', 'E'):
		len = sizeof(struct SU_CE_s);
		break;
	case SIG('E', 'R'):
		len = sizeof(struct SU_ER_s);
		break;
	case SIG('R', 'R'):
		len = sizeof(struct RR_RR_s);
		break;
	case SIG('P', 'X'):
		len = sizeof(struct RR_PX_s);
		break;
	case SIG('P', 'N'):
		len = sizeof(struct RR_PN_s);
		break;
	case SIG('S', 'L'):
		len = sizeof(struct RR_SL_s);
		break;
	case SIG('N', 'M'):
		len = sizeof(struct RR_NM_s);
		break;
	case SIG('C', 'L'):
		len = sizeof(struct RR_CL_s);
		break;
	case SIG('P', 'L'):
		len = sizeof(struct RR_PL_s);
		break;
	case SIG('T', 'F'):
		len = sizeof(struct RR_TF_s);
		break;
	case SIG('Z', 'F'):
		len = sizeof(struct RR_ZF_s);
		break;
	default:
		len = 0;
		break;
	}
	len += offsetof(struct rock_ridge, u);
	if (len > rs->len) {
		printk(KERN_NOTICE "rock: directory entry would overflow "
				"storage\n");
		printk(KERN_NOTICE "rock: sig=0x%02x, size=%d, remaining=%d\n",
				sig, len, rs->len);
		return -EIO;
	}
	return 0;
}

/*
 * return length of name field; 0: not found, -1: to be ignored
 */
int get_rock_ridge_filename(struct iso_directory_record *de,
			    char *retname, struct inode *inode)
{
	struct rock_state rs;
	struct rock_ridge *rr;
	int sig;
	int retnamlen = 0;
	int truncate = 0;
	int ret = 0;

	if (!ISOFS_SB(inode->i_sb)->s_rock)
		return 0;
	*retname = 0;

	init_rock_state(&rs, inode);
	setup_rock_ridge(de, inode, &rs);
repeat:

	while (rs.len > 2) { /* There may be one byte for padding somewhere */
		rr = (struct rock_ridge *)rs.chr;
		/*
		 * Ignore rock ridge info if rr->len is out of range, but
		 * don't return -EIO because that would make the file
		 * invisible.
		 */
		if (rr->len < 3)
			goto out;	/* Something got screwed up here */
		sig = isonum_721(rs.chr);
		if (rock_check_overflow(&rs, sig))
			goto eio;
		rs.chr += rr->len;
		rs.len -= rr->len;
		/*
		 * As above, just ignore the rock ridge info if rr->len
		 * is bogus.
		 */
		if (rs.len < 0)
			goto out;	/* Something got screwed up here */

		switch (sig) {
		case SIG('R', 'R'):
			if ((rr->u.RR.flags[0] & RR_NM) == 0)
				goto out;
			break;
		case SIG('S', 'P'):
			if (check_sp(rr, inode))
				goto out;
			break;
		case SIG('C', 'E'):
			rs.cont_extent = isonum_733(rr->u.CE.extent);
			rs.cont_offset = isonum_733(rr->u.CE.offset);
			rs.cont_size = isonum_733(rr->u.CE.size);
			break;
		case SIG('N', 'M'):
			if (truncate)
				break;
			if (rr->len < 5)
				break;
			/*
			 * If the flags are 2 or 4, this indicates '.' or '..'.
			 * We don't want to do anything with this, because it
			 * screws up the code that calls us.  We don't really
			 * care anyways, since we can just use the non-RR
			 * name.
			 */
			if (rr->u.NM.flags & 6)
				break;

			if (rr->u.NM.flags & ~1) {
				printk("Unsupported NM flag settings (%d)\n",
					rr->u.NM.flags);
				break;
			}
			if ((strlen(retname) + rr->len - 5) >= 254) {
				truncate = 1;
				break;
			}
			strncat(retname, rr->u.NM.name, rr->len - 5);
			retnamlen += rr->len - 5;
			break;
		case SIG('R', 'E'):
			kfree(rs.buffer);
			return -1;
		default:
			break;
		}
	}
	ret = rock_continue(&rs);
	if (ret == 0)
		goto repeat;
	if (ret == 1)
		return retnamlen; /* If 0, this file did not have a NM field */
out:
	kfree(rs.buffer);
	return ret;
eio:
	ret = -EIO;
	goto out;
}

#define RR_REGARD_XA 1
#define RR_RELOC_DE 2

static int
parse_rock_ridge_inode_internal(struct iso_directory_record *de,
				struct inode *inode, int flags)
{
	int symlink_len = 0;
	int cnt, sig;
	unsigned int reloc_block;
	struct inode *reloc;
	struct rock_ridge *rr;
	int rootflag;
	struct rock_state rs;
	int ret = 0;

	if (!ISOFS_SB(inode->i_sb)->s_rock)
		return 0;

	init_rock_state(&rs, inode);
	setup_rock_ridge(de, inode, &rs);
	if (flags & RR_REGARD_XA) {
		rs.chr += 14;
		rs.len -= 14;
		if (rs.len < 0)
			rs.len = 0;
	}

repeat:
	while (rs.len > 2) { /* There may be one byte for padding somewhere */
		rr = (struct rock_ridge *)rs.chr;
		/*
		 * Ignore rock ridge info if rr->len is out of range, but
		 * don't return -EIO because that would make the file
		 * invisible.
		 */
		if (rr->len < 3)
			goto out;	/* Something got screwed up here */
		sig = isonum_721(rs.chr);
		if (rock_check_overflow(&rs, sig))
			goto eio;
		rs.chr += rr->len;
		rs.len -= rr->len;
		/*
		 * As above, just ignore the rock ridge info if rr->len
		 * is bogus.
		 */
		if (rs.len < 0)
			goto out;	/* Something got screwed up here */

		switch (sig) {
#ifndef CONFIG_ZISOFS		/* No flag for SF or ZF */
		case SIG('R', 'R'):
			if ((rr->u.RR.flags[0] &
			     (RR_PX | RR_TF | RR_SL | RR_CL)) == 0)
				goto out;
			break;
#endif
		case SIG('S', 'P'):
			if (check_sp(rr, inode))
				goto out;
			break;
		case SIG('C', 'E'):
			rs.cont_extent = isonum_733(rr->u.CE.extent);
			rs.cont_offset = isonum_733(rr->u.CE.offset);
			rs.cont_size = isonum_733(rr->u.CE.size);
			break;
		case SIG('E', 'R'):
			/* Invalid length of ER tag id? */
			if (rr->u.ER.len_id + offsetof(struct rock_ridge, u.ER.data) > rr->len)
				goto out;
			ISOFS_SB(inode->i_sb)->s_rock = 1;
			printk(KERN_DEBUG "ISO 9660 Extensions: ");
			{
				int p;
				for (p = 0; p < rr->u.ER.len_id; p++)
					printk("%c", rr->u.ER.data[p]);
			}
			printk("\n");
			break;
		case SIG('P', 'X'):
			inode->i_mode = isonum_733(rr->u.PX.mode);
			set_nlink(inode, isonum_733(rr->u.PX.n_links));
			i_uid_write(inode, isonum_733(rr->u.PX.uid));
			i_gid_write(inode, isonum_733(rr->u.PX.gid));
			break;
		case SIG('P', 'N'):
			{
				int high, low;
				high = isonum_733(rr->u.PN.dev_high);
				low = isonum_733(rr->u.PN.dev_low);
				/*
				 * The Rock Ridge standard specifies that if
				 * sizeof(dev_t) <= 4, then the high field is
				 * unused, and the device number is completely
				 * stored in the low field.  Some writers may
				 * ignore this subtlety,
				 * and as a result we test to see if the entire
				 * device number is
				 * stored in the low field, and use that.
				 */
				if ((low & ~0xff) && high == 0) {
					inode->i_rdev =
					    MKDEV(low >> 8, low & 0xff);
				} else {
					inode->i_rdev =
					    MKDEV(high, low);
				}
			}
			break;
		case SIG('T', 'F'):
			/*
			 * Some RRIP writers incorrectly place ctime in the
			 * TF_CREATE field. Try to handle this correctly for
			 * either case.
			 */
			/* Rock ridge never appears on a High Sierra disk */
			cnt = 0;
			if (rr->u.TF.flags & TF_CREATE) {
				inode->i_ctime.tv_sec =
				    iso_date(rr->u.TF.times[cnt++].time,
					     0);
				inode->i_ctime.tv_nsec = 0;
			}
			if (rr->u.TF.flags & TF_MODIFY) {
				inode->i_mtime.tv_sec =
				    iso_date(rr->u.TF.times[cnt++].time,
					     0);
				inode->i_mtime.tv_nsec = 0;
			}
			if (rr->u.TF.flags & TF_ACCESS) {
				inode->i_atime.tv_sec =
				    iso_date(rr->u.TF.times[cnt++].time,
					     0);
				inode->i_atime.tv_nsec = 0;
			}
			if (rr->u.TF.flags & TF_ATTRIBUTES) {
				inode->i_ctime.tv_sec =
				    iso_date(rr->u.TF.times[cnt++].time,
					     0);
				inode->i_ctime.tv_nsec = 0;
			}
			break;
		case SIG('S', 'L'):
			{
				int slen;
				struct SL_component *slp;
				struct SL_component *oldslp;
				slen = rr->len - 5;
				slp = &rr->u.SL.link;
				inode->i_size = symlink_len;
				while (slen > 1) {
					rootflag = 0;
					switch (slp->flags & ~1) {
					case 0:
						inode->i_size +=
						    slp->len;
						break;
					case 2:
						inode->i_size += 1;
						break;
					case 4:
						inode->i_size += 2;
						break;
					case 8:
						rootflag = 1;
						inode->i_size += 1;
						break;
					default:
						printk("Symlink component flag "
							"not implemented\n");
					}
					slen -= slp->len + 2;
					oldslp = slp;
					slp = (struct SL_component *)
						(((char *)slp) + slp->len + 2);

					if (slen < 2) {
						if (((rr->u.SL.
						      flags & 1) != 0)
						    &&
						    ((oldslp->
						      flags & 1) == 0))
							inode->i_size +=
							    1;
						break;
					}

					/*
					 * If this component record isn't
					 * continued, then append a '/'.
					 */
					if (!rootflag
					    && (oldslp->flags & 1) == 0)
						inode->i_size += 1;
				}
			}
			symlink_len = inode->i_size;
			break;
		case SIG('R', 'E'):
			printk(KERN_WARNING "Attempt to read inode for "
					"relocated directory\n");
			goto out;
		case SIG('C', 'L'):
			if (flags & RR_RELOC_DE) {
				printk(KERN_ERR
				       "ISOFS: Recursive directory relocation "
				       "is not supported\n");
				goto eio;
			}
			reloc_block = isonum_733(rr->u.CL.location);
			if (reloc_block == ISOFS_I(inode)->i_iget5_block &&
			    ISOFS_I(inode)->i_iget5_offset == 0) {
				printk(KERN_ERR
				       "ISOFS: Directory relocation points to "
				       "itself\n");
				goto eio;
			}
			ISOFS_I(inode)->i_first_extent = reloc_block;
			reloc = isofs_iget_reloc(inode->i_sb, reloc_block, 0);
			if (IS_ERR(reloc)) {
				ret = PTR_ERR(reloc);
				goto out;
			}
			inode->i_mode = reloc->i_mode;
			set_nlink(inode, reloc->i_nlink);
			inode->i_uid = reloc->i_uid;
			inode->i_gid = reloc->i_gid;
			inode->i_rdev = reloc->i_rdev;
			inode->i_size = reloc->i_size;
			inode->i_blocks = reloc->i_blocks;
			inode->i_atime = reloc->i_atime;
			inode->i_ctime = reloc->i_ctime;
			inode->i_mtime = reloc->i_mtime;
			iput(reloc);
			break;
#ifdef CONFIG_ZISOFS
		case SIG('Z', 'F'): {
			int algo;

			if (ISOFS_SB(inode->i_sb)->s_nocompress)
				break;
			algo = isonum_721(rr->u.ZF.algorithm);
			if (algo == SIG('p', 'z')) {
				int block_shift =
					isonum_711(&rr->u.ZF.parms[1]);
				if (block_shift > 17) {
					printk(KERN_WARNING "isofs: "
						"Can't handle ZF block "
						"size of 2^%d\n",
						block_shift);
				} else {
					/*
					 * Note: we don't change
					 * i_blocks here
					 */
					ISOFS_I(inode)->i_file_format =
						isofs_file_compressed;
					/*
					 * Parameters to compression
					 * algorithm (header size,
					 * block size)
					 */
					ISOFS_I(inode)->i_format_parm[0] =
						isonum_711(&rr->u.ZF.parms[0]);
					ISOFS_I(inode)->i_format_parm[1] =
						isonum_711(&rr->u.ZF.parms[1]);
					inode->i_size =
					    isonum_733(rr->u.ZF.
						       real_size);
				}
			} else {
				printk(KERN_WARNING
				       "isofs: Unknown ZF compression "
						"algorithm: %c%c\n",
				       rr->u.ZF.algorithm[0],
				       rr->u.ZF.algorithm[1]);
			}
			break;
		}
#endif
		default:
			break;
		}
	}
	ret = rock_continue(&rs);
	if (ret == 0)
		goto repeat;
	if (ret == 1)
		ret = 0;
out:
	kfree(rs.buffer);
	return ret;
eio:
	ret = -EIO;
	goto out;
}

static char *get_symlink_chunk(char *rpnt, struct rock_ridge *rr, char *plimit)
{
	int slen;
	int rootflag;
	struct SL_component *oldslp;
	struct SL_component *slp;
	slen = rr->len - 5;
	slp = &rr->u.SL.link;
	while (slen > 1) {
		rootflag = 0;
		switch (slp->flags & ~1) {
		case 0:
			if (slp->len > plimit - rpnt)
				return NULL;
			memcpy(rpnt, slp->text, slp->len);
			rpnt += slp->len;
			break;
		case 2:
			if (rpnt >= plimit)
				return NULL;
			*rpnt++ = '.';
			break;
		case 4:
			if (2 > plimit - rpnt)
				return NULL;
			*rpnt++ = '.';
			*rpnt++ = '.';
			break;
		case 8:
			if (rpnt >= plimit)
				return NULL;
			rootflag = 1;
			*rpnt++ = '/';
			break;
		default:
			printk("Symlink component flag not implemented (%d)\n",
			       slp->flags);
		}
		slen -= slp->len + 2;
		oldslp = slp;
		slp = (struct SL_component *)((char *)slp + slp->len + 2);

		if (slen < 2) {
			/*
			 * If there is another SL record, and this component
			 * record isn't continued, then add a slash.
			 */
			if ((!rootflag) && (rr->u.SL.flags & 1) &&
			    !(oldslp->flags & 1)) {
				if (rpnt >= plimit)
					return NULL;
				*rpnt++ = '/';
			}
			break;
		}

		/*
		 * If this component record isn't continued, then append a '/'.
		 */
		if (!rootflag && !(oldslp->flags & 1)) {
			if (rpnt >= plimit)
				return NULL;
			*rpnt++ = '/';
		}
	}
	return rpnt;
}

int parse_rock_ridge_inode(struct iso_directory_record *de, struct inode *inode,
			   int relocated)
{
	int flags = relocated ? RR_RELOC_DE : 0;
	int result = parse_rock_ridge_inode_internal(de, inode, flags);

	/*
	 * if rockridge flag was reset and we didn't look for attributes
	 * behind eventual XA attributes, have a look there
	 */
	if ((ISOFS_SB(inode->i_sb)->s_rock_offset == -1)
	    && (ISOFS_SB(inode->i_sb)->s_rock == 2)) {
		result = parse_rock_ridge_inode_internal(de, inode,
							 flags | RR_REGARD_XA);
	}
	return result;
}

/*
 * readpage() for symlinks: reads symlink contents into the page and either
 * makes it uptodate and returns 0 or returns error (-EIO)
 */
static int rock_ridge_symlink_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct iso_inode_info *ei = ISOFS_I(inode);
	struct isofs_sb_info *sbi = ISOFS_SB(inode->i_sb);
	char *link = kmap(page);
	unsigned long bufsize = ISOFS_BUFFER_SIZE(inode);
	struct buffer_head *bh;
	char *rpnt = link;
	unsigned char *pnt;
	struct iso_directory_record *raw_de;
	unsigned long block, offset;
	int sig;
	struct rock_ridge *rr;
	struct rock_state rs;
	int ret;

	if (!sbi->s_rock)
		goto error;

	init_rock_state(&rs, inode);
	block = ei->i_iget5_block;
	bh = sb_bread(inode->i_sb, block);
	if (!bh)
		goto out_noread;

	offset = ei->i_iget5_offset;
	pnt = (unsigned char *)bh->b_data + offset;

	raw_de = (struct iso_directory_record *)pnt;

	/*
	 * If we go past the end of the buffer, there is some sort of error.
	 */
	if (offset + *pnt > bufsize)
		goto out_bad_span;

	/*
	 * Now test for possible Rock Ridge extensions which will override
	 * some of these numbers in the inode structure.
	 */

	setup_rock_ridge(raw_de, inode, &rs);

repeat:
	while (rs.len > 2) { /* There may be one byte for padding somewhere */
		rr = (struct rock_ridge *)rs.chr;
		if (rr->len < 3)
			goto out;	/* Something got screwed up here */
		sig = isonum_721(rs.chr);
		if (rock_check_overflow(&rs, sig))
			goto out;
		rs.chr += rr->len;
		rs.len -= rr->len;
		if (rs.len < 0)
			goto out;	/* corrupted isofs */

		switch (sig) {
		case SIG('R', 'R'):
			if ((rr->u.RR.flags[0] & RR_SL) == 0)
				goto out;
			break;
		case SIG('S', 'P'):
			if (check_sp(rr, inode))
				goto out;
			break;
		case SIG('S', 'L'):
			rpnt = get_symlink_chunk(rpnt, rr,
						 link + (PAGE_SIZE - 1));
			if (rpnt == NULL)
				goto out;
			break;
		case SIG('C', 'E'):
			/* This tells is if there is a continuation record */
			rs.cont_extent = isonum_733(rr->u.CE.extent);
			rs.cont_offset = isonum_733(rr->u.CE.offset);
			rs.cont_size = isonum_733(rr->u.CE.size);
		default:
			break;
		}
	}
	ret = rock_continue(&rs);
	if (ret == 0)
		goto repeat;
	if (ret < 0)
		goto fail;

	if (rpnt == link)
		goto fail;
	brelse(bh);
	*rpnt = '\0';
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;

	/* error exit from macro */
out:
	kfree(rs.buffer);
	goto fail;
out_noread:
	printk("unable to read i-node block");
	goto fail;
out_bad_span:
	printk("symlink spans iso9660 blocks\n");
fail:
	brelse(bh);
error:
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	return -EIO;
}

const struct address_space_operations isofs_symlink_aops = {
	.readpage = rock_ridge_symlink_readpage
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/isofs/rock.c */
/************************************************************/
/*
 * fs/isofs/export.c
 *
 *  (C) 2004  Paul Serice - The new inode scheme requires switching
 *                          from iget() to iget5_locked() which means
 *                          the NFS export operations have to be hand
 *                          coded because the default routines rely on
 *                          iget().
 *
 * The following files are helpful:
 *
 *     Documentation/filesystems/nfs/Exporting
 *     fs/exportfs/expfs.c.
 */

// #include "isofs.h"

static struct dentry *
isofs_export_iget(struct super_block *sb,
		  unsigned long block,
		  unsigned long offset,
		  __u32 generation)
{
	struct inode *inode;

	if (block == 0)
		return ERR_PTR(-ESTALE);
	inode = isofs_iget(sb, block, offset);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (generation && inode->i_generation != generation) {
		iput(inode);
		return ERR_PTR(-ESTALE);
	}
	return d_obtain_alias(inode);
}

/* This function is surprisingly simple.  The trick is understanding
 * that "child" is always a directory. So, to find its parent, you
 * simply need to find its ".." entry, normalize its block and offset,
 * and return the underlying inode.  See the comments for
 * isofs_normalize_block_and_offset(). */
static struct dentry *isofs_export_get_parent(struct dentry *child)
{
	unsigned long parent_block = 0;
	unsigned long parent_offset = 0;
	struct inode *child_inode = child->d_inode;
	struct iso_inode_info *e_child_inode = ISOFS_I(child_inode);
	struct iso_directory_record *de = NULL;
	struct buffer_head * bh = NULL;
	struct dentry *rv = NULL;

	/* "child" must always be a directory. */
	if (!S_ISDIR(child_inode->i_mode)) {
		printk(KERN_ERR "isofs: isofs_export_get_parent(): "
		       "child is not a directory!\n");
		rv = ERR_PTR(-EACCES);
		goto out;
	}

	/* It is an invariant that the directory offset is zero.  If
	 * it is not zero, it means the directory failed to be
	 * normalized for some reason. */
	if (e_child_inode->i_iget5_offset != 0) {
		printk(KERN_ERR "isofs: isofs_export_get_parent(): "
		       "child directory not normalized!\n");
		rv = ERR_PTR(-EACCES);
		goto out;
	}

	/* The child inode has been normalized such that its
	 * i_iget5_block value points to the "." entry.  Fortunately,
	 * the ".." entry is located in the same block. */
	parent_block = e_child_inode->i_iget5_block;

	/* Get the block in question. */
	bh = sb_bread(child_inode->i_sb, parent_block);
	if (bh == NULL) {
		rv = ERR_PTR(-EACCES);
		goto out;
	}

	/* This is the "." entry. */
	de = (struct iso_directory_record*)bh->b_data;

	/* The ".." entry is always the second entry. */
	parent_offset = (unsigned long)isonum_711(de->length);
	de = (struct iso_directory_record*)(bh->b_data + parent_offset);

	/* Verify it is in fact the ".." entry. */
	if ((isonum_711(de->name_len) != 1) || (de->name[0] != 1)) {
		printk(KERN_ERR "isofs: Unable to find the \"..\" "
		       "directory for NFS.\n");
		rv = ERR_PTR(-EACCES);
		goto out;
	}

	/* Normalize */
	isofs_normalize_block_and_offset(de, &parent_block, &parent_offset);

	rv = d_obtain_alias(isofs_iget(child_inode->i_sb, parent_block,
				     parent_offset));
 out:
	if (bh)
		brelse(bh);
	return rv;
}

static int
isofs_export_encode_fh(struct inode *inode,
		       __u32 *fh32,
		       int *max_len,
		       struct inode *parent)
{
	struct iso_inode_info * ei = ISOFS_I(inode);
	int len = *max_len;
	int type = 1;
	__u16 *fh16 = (__u16*)fh32;

	/*
	 * WARNING: max_len is 5 for NFSv2.  Because of this
	 * limitation, we use the lower 16 bits of fh32[1] to hold the
	 * offset of the inode and the upper 16 bits of fh32[1] to
	 * hold the offset of the parent.
	 */
	if (parent && (len < 5)) {
		*max_len = 5;
		return FILEID_INVALID;
	} else if (len < 3) {
		*max_len = 3;
		return FILEID_INVALID;
	}

	len = 3;
	fh32[0] = ei->i_iget5_block;
 	fh16[2] = (__u16)ei->i_iget5_offset;  /* fh16 [sic] */
	fh16[3] = 0;  /* avoid leaking uninitialized data */
	fh32[2] = inode->i_generation;
	if (parent) {
		struct iso_inode_info *eparent;
		eparent = ISOFS_I(parent);
		fh32[3] = eparent->i_iget5_block;
		fh16[3] = (__u16)eparent->i_iget5_offset;  /* fh16 [sic] */
		fh32[4] = parent->i_generation;
		len = 5;
		type = 2;
	}
	*max_len = len;
	return type;
}

struct isofs_fid {
	u32 block;
	u16 offset;
	u16 parent_offset;
	u32 generation;
	u32 parent_block;
	u32 parent_generation;
};

static struct dentry *isofs_fh_to_dentry(struct super_block *sb,
	struct fid *fid, int fh_len, int fh_type)
{
	struct isofs_fid *ifid = (struct isofs_fid *)fid;

	if (fh_len < 3 || fh_type > 2)
		return NULL;

	return isofs_export_iget(sb, ifid->block, ifid->offset,
			ifid->generation);
}

static struct dentry *isofs_fh_to_parent(struct super_block *sb,
		struct fid *fid, int fh_len, int fh_type)
{
	struct isofs_fid *ifid = (struct isofs_fid *)fid;

	if (fh_len < 2 || fh_type != 2)
		return NULL;

	return isofs_export_iget(sb,
			fh_len > 2 ? ifid->parent_block : 0,
			ifid->parent_offset,
			fh_len > 4 ? ifid->parent_generation : 0);
}

const struct export_operations isofs_export_ops = {
	.encode_fh	= isofs_export_encode_fh,
	.fh_to_dentry	= isofs_fh_to_dentry,
	.fh_to_parent	= isofs_fh_to_parent,
	.get_parent     = isofs_export_get_parent,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/isofs/export.c */
/************************************************************/
/*
 *  linux/fs/isofs/joliet.c
 *
 *  (C) 1996 Gordon Chaffee
 *
 *  Joliet: Microsoft's Unicode extensions to iso9660
 */

#include <linux/types.h>
// #include <linux/nls.h>
// #include "isofs.h"
#include "../../inc/__fss.h"

/*
 * Convert Unicode 16 to UTF-8 or ASCII.
 */
static int
uni16_to_x8(unsigned char *ascii, __be16 *uni, int len, struct nls_table *nls)
{
	__be16 *ip, ch;
	unsigned char *op;

	ip = uni;
	op = ascii;

	while ((ch = get_unaligned(ip)) && len) {
		int llen;
		llen = nls->uni2char(be16_to_cpu(ch), op, NLS_MAX_CHARSET_SIZE);
		if (llen > 0)
			op += llen;
		else
			*op++ = '?';
		ip++;

		len--;
	}
	*op = 0;
	return (op - ascii);
}

int
get_joliet_filename(struct iso_directory_record * de, unsigned char *outname, struct inode * inode)
{
	unsigned char utf8;
	struct nls_table *nls;
	unsigned char len = 0;

	utf8 = ISOFS_SB(inode->i_sb)->s_utf8;
	nls = ISOFS_SB(inode->i_sb)->s_nls_iocharset;

	if (utf8) {
		len = utf16s_to_utf8s((const wchar_t *) de->name,
				de->name_len[0] >> 1, UTF16_BIG_ENDIAN,
				outname, PAGE_SIZE);
	} else {
		len = uni16_to_x8(outname, (__be16 *) de->name,
				de->name_len[0] >> 1, nls);
	}
	if ((len > 2) && (outname[len-2] == ';') && (outname[len-1] == '1'))
		len -= 2;

	/*
	 * Windows doesn't like periods at the end of a name,
	 * so neither do we
	 */
	while (len >= 2 && (outname[len-1] == '.'))
		len--;

	return len;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/isofs/joliet.c */
/************************************************************/
/* -*- linux-c -*- ------------------------------------------------------- *
 *   
 *   Copyright 2001 H. Peter Anvin - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

/*
 * linux/fs/isofs/compress.c
 *
 * Transparent decompression of files on an iso9660 filesystem
 */

// #include <linux/module.h>
// #include <linux/init.h>

#include <linux/vmalloc.h>
#include <linux/zlib.h>
#include "../../inc/__fss.h"

// #include "isofs.h"
// #include "zisofs.h"

/* This should probably be global. */
static char zisofs_sink_page[PAGE_CACHE_SIZE];

/*
 * This contains the zlib memory allocation and the mutex for the
 * allocation; this avoids failures at block-decompression time.
 */
static void *zisofs_zlib_workspace;
static DEFINE_MUTEX(zisofs_zlib_lock);

/*
 * Read data of @inode from @block_start to @block_end and uncompress
 * to one zisofs block. Store the data in the @pages array with @pcount
 * entries. Start storing at offset @poffset of the first page.
 */
static loff_t zisofs_uncompress_block(struct inode *inode, loff_t block_start,
				      loff_t block_end, int pcount,
				      struct page **pages, unsigned poffset,
				      int *errp)
{
	unsigned int zisofs_block_shift = ISOFS_I(inode)->i_format_parm[1];
	unsigned int bufsize = ISOFS_BUFFER_SIZE(inode);
	unsigned int bufshift = ISOFS_BUFFER_BITS(inode);
	unsigned int bufmask = bufsize - 1;
	int i, block_size = block_end - block_start;
	z_stream stream = { .total_out = 0,
			    .avail_in = 0,
			    .avail_out = 0, };
	int zerr;
	int needblocks = (block_size + (block_start & bufmask) + bufmask)
				>> bufshift;
	int haveblocks;
	blkcnt_t blocknum;
	struct buffer_head *bhs[needblocks + 1];
	int curbh, curpage;

	if (block_size > deflateBound(1UL << zisofs_block_shift)) {
		*errp = -EIO;
		return 0;
	}
	/* Empty block? */
	if (block_size == 0) {
		for ( i = 0 ; i < pcount ; i++ ) {
			if (!pages[i])
				continue;
			memset(page_address(pages[i]), 0, PAGE_CACHE_SIZE);
			flush_dcache_page(pages[i]);
			SetPageUptodate(pages[i]);
		}
		return ((loff_t)pcount) << PAGE_CACHE_SHIFT;
	}

	/* Because zlib is not thread-safe, do all the I/O at the top. */
	blocknum = block_start >> bufshift;
	memset(bhs, 0, (needblocks + 1) * sizeof(struct buffer_head *));
	haveblocks = isofs_get_blocks(inode, blocknum, bhs, needblocks);
	ll_rw_block(READ, haveblocks, bhs);

	curbh = 0;
	curpage = 0;
	/*
	 * First block is special since it may be fractional.  We also wait for
	 * it before grabbing the zlib mutex; odds are that the subsequent
	 * blocks are going to come in in short order so we don't hold the zlib
	 * mutex longer than necessary.
	 */

	if (!bhs[0])
		goto b_eio;

	wait_on_buffer(bhs[0]);
	if (!buffer_uptodate(bhs[0])) {
		*errp = -EIO;
		goto b_eio;
	}

	stream.workspace = zisofs_zlib_workspace;
	mutex_lock(&zisofs_zlib_lock);
		
	zerr = zlib_inflateInit(&stream);
	if (zerr != Z_OK) {
		if (zerr == Z_MEM_ERROR)
			*errp = -ENOMEM;
		else
			*errp = -EIO;
		printk(KERN_DEBUG "zisofs: zisofs_inflateInit returned %d\n",
			       zerr);
		goto z_eio;
	}

	while (curpage < pcount && curbh < haveblocks &&
	       zerr != Z_STREAM_END) {
		if (!stream.avail_out) {
			if (pages[curpage]) {
				stream.next_out = page_address(pages[curpage])
						+ poffset;
				stream.avail_out = PAGE_CACHE_SIZE - poffset;
				poffset = 0;
			} else {
				stream.next_out = (void *)&zisofs_sink_page;
				stream.avail_out = PAGE_CACHE_SIZE;
			}
		}
		if (!stream.avail_in) {
			wait_on_buffer(bhs[curbh]);
			if (!buffer_uptodate(bhs[curbh])) {
				*errp = -EIO;
				break;
			}
			stream.next_in  = bhs[curbh]->b_data +
						(block_start & bufmask);
			stream.avail_in = min_t(unsigned, bufsize -
						(block_start & bufmask),
						block_size);
			block_size -= stream.avail_in;
			block_start = 0;
		}

		while (stream.avail_out && stream.avail_in) {
			zerr = zlib_inflate(&stream, Z_SYNC_FLUSH);
			if (zerr == Z_BUF_ERROR && stream.avail_in == 0)
				break;
			if (zerr == Z_STREAM_END)
				break;
			if (zerr != Z_OK) {
				/* EOF, error, or trying to read beyond end of input */
				if (zerr == Z_MEM_ERROR)
					*errp = -ENOMEM;
				else {
					printk(KERN_DEBUG
					       "zisofs: zisofs_inflate returned"
					       " %d, inode = %lu,"
					       " page idx = %d, bh idx = %d,"
					       " avail_in = %ld,"
					       " avail_out = %ld\n",
					       zerr, inode->i_ino, curpage,
					       curbh, stream.avail_in,
					       stream.avail_out);
					*errp = -EIO;
				}
				goto inflate_out;
			}
		}

		if (!stream.avail_out) {
			/* This page completed */
			if (pages[curpage]) {
				flush_dcache_page(pages[curpage]);
				SetPageUptodate(pages[curpage]);
			}
			curpage++;
		}
		if (!stream.avail_in)
			curbh++;
	}
inflate_out:
	zlib_inflateEnd(&stream);

z_eio:
	mutex_unlock(&zisofs_zlib_lock);

b_eio:
	for (i = 0; i < haveblocks; i++)
		brelse(bhs[i]);
	return stream.total_out;
}

/*
 * Uncompress data so that pages[full_page] is fully uptodate and possibly
 * fills in other pages if we have data for them.
 */
static int zisofs_fill_pages(struct inode *inode, int full_page, int pcount,
			     struct page **pages)
{
	loff_t start_off, end_off;
	loff_t block_start, block_end;
	unsigned int header_size = ISOFS_I(inode)->i_format_parm[0];
	unsigned int zisofs_block_shift = ISOFS_I(inode)->i_format_parm[1];
	unsigned int blockptr;
	loff_t poffset = 0;
	blkcnt_t cstart_block, cend_block;
	struct buffer_head *bh;
	unsigned int blkbits = ISOFS_BUFFER_BITS(inode);
	unsigned int blksize = 1 << blkbits;
	int err;
	loff_t ret;

	BUG_ON(!pages[full_page]);

	/*
	 * We want to read at least 'full_page' page. Because we have to
	 * uncompress the whole compression block anyway, fill the surrounding
	 * pages with the data we have anyway...
	 */
	start_off = page_offset(pages[full_page]);
	end_off = min_t(loff_t, start_off + PAGE_CACHE_SIZE, inode->i_size);

	cstart_block = start_off >> zisofs_block_shift;
	cend_block = (end_off + (1 << zisofs_block_shift) - 1)
			>> zisofs_block_shift;

	WARN_ON(start_off - (full_page << PAGE_CACHE_SHIFT) !=
		((cstart_block << zisofs_block_shift) & PAGE_CACHE_MASK));

	/* Find the pointer to this specific chunk */
	/* Note: we're not using isonum_731() here because the data is known aligned */
	/* Note: header_size is in 32-bit words (4 bytes) */
	blockptr = (header_size + cstart_block) << 2;
	bh = isofs_bread(inode, blockptr >> blkbits);
	if (!bh)
		return -EIO;
	block_start = le32_to_cpu(*(__le32 *)
				(bh->b_data + (blockptr & (blksize - 1))));

	while (cstart_block < cend_block && pcount > 0) {
		/* Load end of the compressed block in the file */
		blockptr += 4;
		/* Traversed to next block? */
		if (!(blockptr & (blksize - 1))) {
			brelse(bh);

			bh = isofs_bread(inode, blockptr >> blkbits);
			if (!bh)
				return -EIO;
		}
		block_end = le32_to_cpu(*(__le32 *)
				(bh->b_data + (blockptr & (blksize - 1))));
		if (block_start > block_end) {
			brelse(bh);
			return -EIO;
		}
		err = 0;
		ret = zisofs_uncompress_block(inode, block_start, block_end,
					      pcount, pages, poffset, &err);
		poffset += ret;
		pages += poffset >> PAGE_CACHE_SHIFT;
		pcount -= poffset >> PAGE_CACHE_SHIFT;
		full_page -= poffset >> PAGE_CACHE_SHIFT;
		poffset &= ~PAGE_CACHE_MASK;

		if (err) {
			brelse(bh);
			/*
			 * Did we finish reading the page we really wanted
			 * to read?
			 */
			if (full_page < 0)
				return 0;
			return err;
		}

		block_start = block_end;
		cstart_block++;
	}

	if (poffset && *pages) {
		memset(page_address(*pages) + poffset, 0,
		       PAGE_CACHE_SIZE - poffset);
		flush_dcache_page(*pages);
		SetPageUptodate(*pages);
	}
	return 0;
}

/*
 * When decompressing, we typically obtain more than one page
 * per reference.  We inject the additional pages into the page
 * cache as a form of readahead.
 */
static int zisofs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = file_inode(file);
	struct address_space *mapping = inode->i_mapping;
	int err;
	int i, pcount, full_page;
	unsigned int zisofs_block_shift = ISOFS_I(inode)->i_format_parm[1];
	unsigned int zisofs_pages_per_cblock =
		PAGE_CACHE_SHIFT <= zisofs_block_shift ?
		(1 << (zisofs_block_shift - PAGE_CACHE_SHIFT)) : 0;
	struct page *pages[max_t(unsigned, zisofs_pages_per_cblock, 1)];
	pgoff_t index = page->index, end_index;

	end_index = (inode->i_size + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	/*
	 * If this page is wholly outside i_size we just return zero;
	 * do_generic_file_read() will handle this for us
	 */
	if (index >= end_index) {
		SetPageUptodate(page);
		unlock_page(page);
		return 0;
	}

	if (PAGE_CACHE_SHIFT <= zisofs_block_shift) {
		/* We have already been given one page, this is the one
		   we must do. */
		full_page = index & (zisofs_pages_per_cblock - 1);
		pcount = min_t(int, zisofs_pages_per_cblock,
			end_index - (index & ~(zisofs_pages_per_cblock - 1)));
		index -= full_page;
	} else {
		full_page = 0;
		pcount = 1;
	}
	pages[full_page] = page;

	for (i = 0; i < pcount; i++, index++) {
		if (i != full_page)
			pages[i] = grab_cache_page_nowait(mapping, index);
		if (pages[i]) {
			ClearPageError(pages[i]);
			kmap(pages[i]);
		}
	}

	err = zisofs_fill_pages(inode, full_page, pcount, pages);

	/* Release any residual pages, do not SetPageUptodate */
	for (i = 0; i < pcount; i++) {
		if (pages[i]) {
			flush_dcache_page(pages[i]);
			if (i == full_page && err)
				SetPageError(pages[i]);
			kunmap(pages[i]);
			unlock_page(pages[i]);
			if (i != full_page)
				page_cache_release(pages[i]);
		}
	}			

	/* At this point, err contains 0 or -EIO depending on the "critical" page */
	return err;
}

const struct address_space_operations zisofs_aops = {
	.readpage = zisofs_readpage,
	/* No sync_page operation supported? */
	/* No bmap operation supported */
};

int __init zisofs_init(void)
{
	zisofs_zlib_workspace = vmalloc(zlib_inflate_workspacesize());
	if ( !zisofs_zlib_workspace )
		return -ENOMEM;

	return 0;
}

void zisofs_cleanup(void)
{
	vfree(zisofs_zlib_workspace);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/isofs/compress.c */
/************************************************************/
