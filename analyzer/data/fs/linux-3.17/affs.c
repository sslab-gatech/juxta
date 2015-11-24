/*
 *  linux/fs/affs/inode.c
 *
 *  (c) 1996  Hans-Joachim Widmaier - Rewritten
 *
 *  (C) 1993  Ray Burr - Modified for Amiga FFS filesystem.
 *
 *  (C) 1992  Eric Youngdale Modified for ISO 9660 filesystem.
 *
 *  (C) 1991  Linus Torvalds - minix filesystem
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/statfs.h>
#include <linux/parser.h>
#include <linux/magic.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/writeback.h>
#include "affs.h"

extern struct timezone sys_tz;

static int affs_statfs(struct dentry *dentry, struct kstatfs *buf);
static int affs_remount (struct super_block *sb, int *flags, char *data);

static void
affs_commit_super(struct super_block *sb, int wait)
{
	struct affs_sb_info *sbi = AFFS_SB(sb);
	struct buffer_head *bh = sbi->s_root_bh;
	struct affs_root_tail *tail = AFFS_ROOT_TAIL(sb, bh);

	lock_buffer(bh);
	secs_to_datestamp(get_seconds(), &tail->disk_change);
	affs_fix_checksum(sb, bh);
	unlock_buffer(bh);

	mark_buffer_dirty(bh);
	if (wait)
		sync_dirty_buffer(bh);
}

static void
affs_put_super(struct super_block *sb)
{
	struct affs_sb_info *sbi = AFFS_SB(sb);
	pr_debug("%s()\n", __func__);

	cancel_delayed_work_sync(&sbi->sb_work);
}

static int
affs_sync_fs(struct super_block *sb, int wait)
{
	affs_commit_super(sb, wait);
	return 0;
}

static void flush_superblock(struct work_struct *work)
{
	struct affs_sb_info *sbi;
	struct super_block *sb;

	sbi = container_of(work, struct affs_sb_info, sb_work.work);
	sb = sbi->sb;

	spin_lock(&sbi->work_lock);
	sbi->work_queued = 0;
	spin_unlock(&sbi->work_lock);

	affs_commit_super(sb, 1);
}

void affs_mark_sb_dirty(struct super_block *sb)
{
	struct affs_sb_info *sbi = AFFS_SB(sb);
	unsigned long delay;

	if (sb->s_flags & MS_RDONLY)
	       return;

	spin_lock(&sbi->work_lock);
	if (!sbi->work_queued) {
	       delay = msecs_to_jiffies(dirty_writeback_interval * 10);
	       queue_delayed_work(system_long_wq, &sbi->sb_work, delay);
	       sbi->work_queued = 1;
	}
	spin_unlock(&sbi->work_lock);
}

static struct kmem_cache * affs_inode_cachep;

static struct inode *affs_alloc_inode(struct super_block *sb)
{
	struct affs_inode_info *i;

	i = kmem_cache_alloc(affs_inode_cachep, GFP_KERNEL);
	if (!i)
		return NULL;

	i->vfs_inode.i_version = 1;
	i->i_lc = NULL;
	i->i_ext_bh = NULL;
	i->i_pa_cnt = 0;

	return &i->vfs_inode;
}

static void affs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(affs_inode_cachep, AFFS_I(inode));
}

static void affs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, affs_i_callback);
}

static void init_once(void *foo)
{
	struct affs_inode_info *ei = (struct affs_inode_info *) foo;

	sema_init(&ei->i_link_lock, 1);
	sema_init(&ei->i_ext_lock, 1);
	inode_init_once(&ei->vfs_inode);
}

static int __init init_inodecache(void)
{
	affs_inode_cachep = kmem_cache_create("affs_inode_cache",
					     sizeof(struct affs_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (affs_inode_cachep == NULL)
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
	kmem_cache_destroy(affs_inode_cachep);
}

static const struct super_operations affs_sops = {
	.alloc_inode	= affs_alloc_inode,
	.destroy_inode	= affs_destroy_inode,
	.write_inode	= affs_write_inode,
	.evict_inode	= affs_evict_inode,
	.put_super	= affs_put_super,
	.sync_fs	= affs_sync_fs,
	.statfs		= affs_statfs,
	.remount_fs	= affs_remount,
	.show_options	= generic_show_options,
};

enum {
	Opt_bs, Opt_mode, Opt_mufs, Opt_notruncate, Opt_prefix, Opt_protect,
	Opt_reserved, Opt_root, Opt_setgid, Opt_setuid,
	Opt_verbose, Opt_volume, Opt_ignore, Opt_err,
};

static const match_table_t tokens = {
	{Opt_bs, "bs=%u"},
	{Opt_mode, "mode=%o"},
	{Opt_mufs, "mufs"},
	{Opt_notruncate, "nofilenametruncate"},
	{Opt_prefix, "prefix=%s"},
	{Opt_protect, "protect"},
	{Opt_reserved, "reserved=%u"},
	{Opt_root, "root=%u"},
	{Opt_setgid, "setgid=%u"},
	{Opt_setuid, "setuid=%u"},
	{Opt_verbose, "verbose"},
	{Opt_volume, "volume=%s"},
	{Opt_ignore, "grpquota"},
	{Opt_ignore, "noquota"},
	{Opt_ignore, "quota"},
	{Opt_ignore, "usrquota"},
	{Opt_err, NULL},
};

static int
parse_options(char *options, kuid_t *uid, kgid_t *gid, int *mode, int *reserved, s32 *root,
		int *blocksize, char **prefix, char *volume, unsigned long *mount_opts)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];

	/* Fill in defaults */

	*uid        = current_uid();
	*gid        = current_gid();
	*reserved   = 2;
	*root       = -1;
	*blocksize  = -1;
	volume[0]   = ':';
	volume[1]   = 0;
	*mount_opts = 0;
	if (!options)
		return 1;

	while ((p = strsep(&options, ",")) != NULL) {
		int token, n, option;
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_bs:
			if (match_int(&args[0], &n))
				return 0;
			if (n != 512 && n != 1024 && n != 2048
			    && n != 4096) {
				pr_warn("Invalid blocksize (512, 1024, 2048, 4096 allowed)\n");
				return 0;
			}
			*blocksize = n;
			break;
		case Opt_mode:
			if (match_octal(&args[0], &option))
				return 0;
			*mode = option & 0777;
			*mount_opts |= SF_SETMODE;
			break;
		case Opt_mufs:
			*mount_opts |= SF_MUFS;
			break;
		case Opt_notruncate:
			*mount_opts |= SF_NO_TRUNCATE;
			break;
		case Opt_prefix:
			*prefix = match_strdup(&args[0]);
			if (!*prefix)
				return 0;
			*mount_opts |= SF_PREFIX;
			break;
		case Opt_protect:
			*mount_opts |= SF_IMMUTABLE;
			break;
		case Opt_reserved:
			if (match_int(&args[0], reserved))
				return 0;
			break;
		case Opt_root:
			if (match_int(&args[0], root))
				return 0;
			break;
		case Opt_setgid:
			if (match_int(&args[0], &option))
				return 0;
			*gid = make_kgid(current_user_ns(), option);
			if (!gid_valid(*gid))
				return 0;
			*mount_opts |= SF_SETGID;
			break;
		case Opt_setuid:
			if (match_int(&args[0], &option))
				return 0;
			*uid = make_kuid(current_user_ns(), option);
			if (!uid_valid(*uid))
				return 0;
			*mount_opts |= SF_SETUID;
			break;
		case Opt_verbose:
			*mount_opts |= SF_VERBOSE;
			break;
		case Opt_volume: {
			char *vol = match_strdup(&args[0]);
			if (!vol)
				return 0;
			strlcpy(volume, vol, 32);
			kfree(vol);
			break;
		}
		case Opt_ignore:
		 	/* Silently ignore the quota options */
			break;
		default:
			pr_warn("Unrecognized mount option \"%s\" or missing value\n",
				p);
			return 0;
		}
	}
	return 1;
}

/* This function definitely needs to be split up. Some fine day I'll
 * hopefully have the guts to do so. Until then: sorry for the mess.
 */

static int affs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct affs_sb_info	*sbi;
	struct buffer_head	*root_bh = NULL;
	struct buffer_head	*boot_bh;
	struct inode		*root_inode = NULL;
	s32			 root_block;
	int			 size, blocksize;
	u32			 chksum;
	int			 num_bm;
	int			 i, j;
	s32			 key;
	kuid_t			 uid;
	kgid_t			 gid;
	int			 reserved;
	unsigned long		 mount_flags;
	int			 tmp_flags;	/* fix remount prototype... */
	u8			 sig[4];
	int			 ret;

	save_mount_options(sb, data);

	pr_debug("read_super(%s)\n", data ? (const char *)data : "no options");

	sb->s_magic             = AFFS_SUPER_MAGIC;
	sb->s_op                = &affs_sops;
	sb->s_flags |= MS_NODIRATIME;

	sbi = kzalloc(sizeof(struct affs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;

	sb->s_fs_info = sbi;
	sbi->sb = sb;
	mutex_init(&sbi->s_bmlock);
	spin_lock_init(&sbi->symlink_lock);
	spin_lock_init(&sbi->work_lock);
	INIT_DELAYED_WORK(&sbi->sb_work, flush_superblock);

	if (!parse_options(data,&uid,&gid,&i,&reserved,&root_block,
				&blocksize,&sbi->s_prefix,
				sbi->s_volume, &mount_flags)) {
		pr_err("Error parsing options\n");
		return -EINVAL;
	}
	/* N.B. after this point s_prefix must be released */

	sbi->s_flags   = mount_flags;
	sbi->s_mode    = i;
	sbi->s_uid     = uid;
	sbi->s_gid     = gid;
	sbi->s_reserved= reserved;

	/* Get the size of the device in 512-byte blocks.
	 * If we later see that the partition uses bigger
	 * blocks, we will have to change it.
	 */

	size = sb->s_bdev->bd_inode->i_size >> 9;
	pr_debug("initial blocksize=%d, #blocks=%d\n", 512, size);

	affs_set_blocksize(sb, PAGE_SIZE);
	/* Try to find root block. Its location depends on the block size. */

	i = 512;
	j = 4096;
	if (blocksize > 0) {
		i = j = blocksize;
		size = size / (blocksize / 512);
	}
	for (blocksize = i, key = 0; blocksize <= j; blocksize <<= 1, size >>= 1) {
		sbi->s_root_block = root_block;
		if (root_block < 0)
			sbi->s_root_block = (reserved + size - 1) / 2;
		pr_debug("setting blocksize to %d\n", blocksize);
		affs_set_blocksize(sb, blocksize);
		sbi->s_partition_size = size;

		/* The root block location that was calculated above is not
		 * correct if the partition size is an odd number of 512-
		 * byte blocks, which will be rounded down to a number of
		 * 1024-byte blocks, and if there were an even number of
		 * reserved blocks. Ideally, all partition checkers should
		 * report the real number of blocks of the real blocksize,
		 * but since this just cannot be done, we have to try to
		 * find the root block anyways. In the above case, it is one
		 * block behind the calculated one. So we check this one, too.
		 */
		for (num_bm = 0; num_bm < 2; num_bm++) {
			pr_debug("Dev %s, trying root=%u, bs=%d, "
				"size=%d, reserved=%d\n",
				sb->s_id,
				sbi->s_root_block + num_bm,
				blocksize, size, reserved);
			root_bh = affs_bread(sb, sbi->s_root_block + num_bm);
			if (!root_bh)
				continue;
			if (!affs_checksum_block(sb, root_bh) &&
			    be32_to_cpu(AFFS_ROOT_HEAD(root_bh)->ptype) == T_SHORT &&
			    be32_to_cpu(AFFS_ROOT_TAIL(sb, root_bh)->stype) == ST_ROOT) {
				sbi->s_hashsize    = blocksize / 4 - 56;
				sbi->s_root_block += num_bm;
				key                        = 1;
				goto got_root;
			}
			affs_brelse(root_bh);
			root_bh = NULL;
		}
	}
	if (!silent)
		pr_err("No valid root block on device %s\n", sb->s_id);
	return -EINVAL;

	/* N.B. after this point bh must be released */
got_root:
	/* Keep super block in cache */
	sbi->s_root_bh = root_bh;
	root_block = sbi->s_root_block;

	/* Find out which kind of FS we have */
	boot_bh = sb_bread(sb, 0);
	if (!boot_bh) {
		pr_err("Cannot read boot block\n");
		return -EINVAL;
	}
	memcpy(sig, boot_bh->b_data, 4);
	brelse(boot_bh);
	chksum = be32_to_cpu(*(__be32 *)sig);

	/* Dircache filesystems are compatible with non-dircache ones
	 * when reading. As long as they aren't supported, writing is
	 * not recommended.
	 */
	if ((chksum == FS_DCFFS || chksum == MUFS_DCFFS || chksum == FS_DCOFS
	     || chksum == MUFS_DCOFS) && !(sb->s_flags & MS_RDONLY)) {
		pr_notice("Dircache FS - mounting %s read only\n", sb->s_id);
		sb->s_flags |= MS_RDONLY;
	}
	switch (chksum) {
		case MUFS_FS:
		case MUFS_INTLFFS:
		case MUFS_DCFFS:
			sbi->s_flags |= SF_MUFS;
			/* fall thru */
		case FS_INTLFFS:
		case FS_DCFFS:
			sbi->s_flags |= SF_INTL;
			break;
		case MUFS_FFS:
			sbi->s_flags |= SF_MUFS;
			break;
		case FS_FFS:
			break;
		case MUFS_OFS:
			sbi->s_flags |= SF_MUFS;
			/* fall thru */
		case FS_OFS:
			sbi->s_flags |= SF_OFS;
			sb->s_flags |= MS_NOEXEC;
			break;
		case MUFS_DCOFS:
		case MUFS_INTLOFS:
			sbi->s_flags |= SF_MUFS;
		case FS_DCOFS:
		case FS_INTLOFS:
			sbi->s_flags |= SF_INTL | SF_OFS;
			sb->s_flags |= MS_NOEXEC;
			break;
		default:
			pr_err("Unknown filesystem on device %s: %08X\n",
			       sb->s_id, chksum);
			return -EINVAL;
	}

	if (mount_flags & SF_VERBOSE) {
		u8 len = AFFS_ROOT_TAIL(sb, root_bh)->disk_name[0];
		pr_notice("Mounting volume \"%.*s\": Type=%.3s\\%c, Blocksize=%d\n",
			len > 31 ? 31 : len,
			AFFS_ROOT_TAIL(sb, root_bh)->disk_name + 1,
			sig, sig[3] + '0', blocksize);
	}

	sb->s_flags |= MS_NODEV | MS_NOSUID;

	sbi->s_data_blksize = sb->s_blocksize;
	if (sbi->s_flags & SF_OFS)
		sbi->s_data_blksize -= 24;

	tmp_flags = sb->s_flags;
	ret = affs_init_bitmap(sb, &tmp_flags);
	if (ret)
		return ret;
	sb->s_flags = tmp_flags;

	/* set up enough so that it can read an inode */

	root_inode = affs_iget(sb, root_block);
	if (IS_ERR(root_inode))
		return PTR_ERR(root_inode);

	if (AFFS_SB(sb)->s_flags & SF_INTL)
		sb->s_d_op = &affs_intl_dentry_operations;
	else
		sb->s_d_op = &affs_dentry_operations;

	sb->s_root = d_make_root(root_inode);
	if (!sb->s_root) {
		pr_err("AFFS: Get root inode failed\n");
		return -ENOMEM;
	}

	pr_debug("s_flags=%lX\n", sb->s_flags);
	return 0;
}

static int
affs_remount(struct super_block *sb, int *flags, char *data)
{
	struct affs_sb_info	*sbi = AFFS_SB(sb);
	int			 blocksize;
	kuid_t			 uid;
	kgid_t			 gid;
	int			 mode;
	int			 reserved;
	int			 root_block;
	unsigned long		 mount_flags;
	int			 res = 0;
	char			*new_opts = kstrdup(data, GFP_KERNEL);
	char			 volume[32];
	char			*prefix = NULL;

	pr_debug("%s(flags=0x%x,opts=\"%s\")\n", __func__, *flags, data);

	sync_filesystem(sb);
	*flags |= MS_NODIRATIME;

	memcpy(volume, sbi->s_volume, 32);
	if (!parse_options(data, &uid, &gid, &mode, &reserved, &root_block,
			   &blocksize, &prefix, volume,
			   &mount_flags)) {
		kfree(prefix);
		kfree(new_opts);
		return -EINVAL;
	}

	flush_delayed_work(&sbi->sb_work);
	replace_mount_options(sb, new_opts);

	sbi->s_flags = mount_flags;
	sbi->s_mode  = mode;
	sbi->s_uid   = uid;
	sbi->s_gid   = gid;
	/* protect against readers */
	spin_lock(&sbi->symlink_lock);
	if (prefix) {
		kfree(sbi->s_prefix);
		sbi->s_prefix = prefix;
	}
	memcpy(sbi->s_volume, volume, 32);
	spin_unlock(&sbi->symlink_lock);

	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		return 0;

	if (*flags & MS_RDONLY)
		affs_free_bitmap(sb);
	else
		res = affs_init_bitmap(sb, flags);

	return res;
}

static int
affs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	int		 free;
	u64		 id = huge_encode_dev(sb->s_bdev->bd_dev);

	pr_debug("%s() partsize=%d, reserved=%d\n",
		 __func__, AFFS_SB(sb)->s_partition_size,
		 AFFS_SB(sb)->s_reserved);

	free          = affs_count_free_blocks(sb);
	buf->f_type    = AFFS_SUPER_MAGIC;
	buf->f_bsize   = sb->s_blocksize;
	buf->f_blocks  = AFFS_SB(sb)->s_partition_size - AFFS_SB(sb)->s_reserved;
	buf->f_bfree   = free;
	buf->f_bavail  = free;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = 30;
	return 0;
}

static struct dentry *affs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, affs_fill_super);
}

static void affs_kill_sb(struct super_block *sb)
{
	struct affs_sb_info *sbi = AFFS_SB(sb);
	kill_block_super(sb);
	if (sbi) {
		affs_free_bitmap(sb);
		affs_brelse(sbi->s_root_bh);
		kfree(sbi->s_prefix);
		kfree(sbi);
	}
}

static struct file_system_type affs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "affs",
	.mount		= affs_mount,
	.kill_sb	= affs_kill_sb,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("affs");

static int __init init_affs_fs(void)
{
	int err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&affs_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_affs_fs(void)
{
	unregister_filesystem(&affs_fs_type);
	destroy_inodecache();
}

MODULE_DESCRIPTION("Amiga filesystem support for Linux");
MODULE_LICENSE("GPL");

module_init(init_affs_fs)
module_exit(exit_affs_fs)
/************************************************************/
/* ../linux-3.17/fs/affs/super.c */
/************************************************************/
/*
 *  linux/fs/affs/namei.c
 *
 *  (c) 1996  Hans-Joachim Widmaier - Rewritten
 *
 *  (C) 1993  Ray Burr - Modified for Amiga FFS filesystem.
 *
 *  (C) 1991  Linus Torvalds - minix filesystem
 */

// #include "affs.h"

typedef int (*toupper_t)(int);

static int	 affs_toupper(int ch);
static int	 affs_hash_dentry(const struct dentry *, struct qstr *);
static int       affs_compare_dentry(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name);
static int	 affs_intl_toupper(int ch);
static int	 affs_intl_hash_dentry(const struct dentry *, struct qstr *);
static int       affs_intl_compare_dentry(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name);

const struct dentry_operations affs_dentry_operations = {
	.d_hash		= affs_hash_dentry,
	.d_compare	= affs_compare_dentry,
};

const struct dentry_operations affs_intl_dentry_operations = {
	.d_hash		= affs_intl_hash_dentry,
	.d_compare	= affs_intl_compare_dentry,
};


/* Simple toupper() for DOS\1 */

static int
affs_toupper(int ch)
{
	return ch >= 'a' && ch <= 'z' ? ch -= ('a' - 'A') : ch;
}

/* International toupper() for DOS\3 ("international") */

static int
affs_intl_toupper(int ch)
{
	return (ch >= 'a' && ch <= 'z') || (ch >= 0xE0
		&& ch <= 0xFE && ch != 0xF7) ?
		ch - ('a' - 'A') : ch;
}

static inline toupper_t
affs_get_toupper(struct super_block *sb)
{
	return AFFS_SB(sb)->s_flags & SF_INTL ? affs_intl_toupper : affs_toupper;
}

/*
 * Note: the dentry argument is the parent dentry.
 */
static inline int
__affs_hash_dentry(struct qstr *qstr, toupper_t toupper, bool notruncate)
{
	const u8 *name = qstr->name;
	unsigned long hash;
	int i;

	i = affs_check_name(qstr->name, qstr->len, notruncate);
	if (i)
		return i;

	hash = init_name_hash();
	i = min(qstr->len, 30u);
	for (; i > 0; name++, i--)
		hash = partial_name_hash(toupper(*name), hash);
	qstr->hash = end_name_hash(hash);

	return 0;
}

static int
affs_hash_dentry(const struct dentry *dentry, struct qstr *qstr)
{
	return __affs_hash_dentry(qstr, affs_toupper,
				  affs_nofilenametruncate(dentry));

}

static int
affs_intl_hash_dentry(const struct dentry *dentry, struct qstr *qstr)
{
	return __affs_hash_dentry(qstr, affs_intl_toupper,
				  affs_nofilenametruncate(dentry));

}

static inline int __affs_compare_dentry(unsigned int len,
		const char *str, const struct qstr *name, toupper_t toupper,
		bool notruncate)
{
	const u8 *aname = str;
	const u8 *bname = name->name;

	/*
	 * 'str' is the name of an already existing dentry, so the name
	 * must be valid. 'name' must be validated first.
	 */

	if (affs_check_name(name->name, name->len, notruncate))
		return 1;

	/*
	 * If the names are longer than the allowed 30 chars,
	 * the excess is ignored, so their length may differ.
	 */
	if (len >= 30) {
		if (name->len < 30)
			return 1;
		len = 30;
	} else if (len != name->len)
		return 1;

	for (; len > 0; len--)
		if (toupper(*aname++) != toupper(*bname++))
			return 1;

	return 0;
}

static int
affs_compare_dentry(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{

	return __affs_compare_dentry(len, str, name, affs_toupper,
				     affs_nofilenametruncate(parent));
}

static int
affs_intl_compare_dentry(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	return __affs_compare_dentry(len, str, name, affs_intl_toupper,
				     affs_nofilenametruncate(parent));

}

/*
 * NOTE! unlike strncmp, affs_match returns 1 for success, 0 for failure.
 */

static inline int
affs_match(struct dentry *dentry, const u8 *name2, toupper_t toupper)
{
	const u8 *name = dentry->d_name.name;
	int len = dentry->d_name.len;

	if (len >= 30) {
		if (*name2 < 30)
			return 0;
		len = 30;
	} else if (len != *name2)
		return 0;

	for (name2++; len > 0; len--)
		if (toupper(*name++) != toupper(*name2++))
			return 0;
	return 1;
}

int
affs_hash_name(struct super_block *sb, const u8 *name, unsigned int len)
{
	toupper_t toupper = affs_get_toupper(sb);
	int hash;

	hash = len = min(len, 30u);
	for (; len > 0; len--)
		hash = (hash * 13 + toupper(*name++)) & 0x7ff;

	return hash % AFFS_SB(sb)->s_hashsize;
}

static struct buffer_head *
affs_find_entry(struct inode *dir, struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *bh;
	toupper_t toupper = affs_get_toupper(sb);
	u32 key;

	pr_debug("%s(\"%.*s\")\n",
		 __func__, (int)dentry->d_name.len, dentry->d_name.name);

	bh = affs_bread(sb, dir->i_ino);
	if (!bh)
		return ERR_PTR(-EIO);

	key = be32_to_cpu(AFFS_HEAD(bh)->table[affs_hash_name(sb, dentry->d_name.name, dentry->d_name.len)]);

	for (;;) {
		affs_brelse(bh);
		if (key == 0)
			return NULL;
		bh = affs_bread(sb, key);
		if (!bh)
			return ERR_PTR(-EIO);
		if (affs_match(dentry, AFFS_TAIL(sb, bh)->name, toupper))
			return bh;
		key = be32_to_cpu(AFFS_TAIL(sb, bh)->hash_chain);
	}
}

struct dentry *
affs_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *bh;
	struct inode *inode = NULL;

	pr_debug("%s(\"%.*s\")\n",
		 __func__, (int)dentry->d_name.len, dentry->d_name.name);

	affs_lock_dir(dir);
	bh = affs_find_entry(dir, dentry);
	affs_unlock_dir(dir);
	if (IS_ERR(bh))
		return ERR_CAST(bh);
	if (bh) {
		u32 ino = bh->b_blocknr;

		/* store the real header ino in d_fsdata for faster lookups */
		dentry->d_fsdata = (void *)(long)ino;
		switch (be32_to_cpu(AFFS_TAIL(sb, bh)->stype)) {
		//link to dirs disabled
		//case ST_LINKDIR:
		case ST_LINKFILE:
			ino = be32_to_cpu(AFFS_TAIL(sb, bh)->original);
		}
		affs_brelse(bh);
		inode = affs_iget(sb, ino);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}
	d_add(dentry, inode);
	return NULL;
}

int
affs_unlink(struct inode *dir, struct dentry *dentry)
{
	pr_debug("%s(dir=%d, %lu \"%.*s\")\n",
		 __func__, (u32)dir->i_ino, dentry->d_inode->i_ino,
		(int)dentry->d_name.len, dentry->d_name.name);

	return affs_remove_header(dentry);
}

int
affs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
	struct super_block *sb = dir->i_sb;
	struct inode	*inode;
	int		 error;

	pr_debug("%s(%lu,\"%.*s\",0%ho)\n",
		 __func__, dir->i_ino, (int)dentry->d_name.len,
		 dentry->d_name.name,mode);

	inode = affs_new_inode(dir);
	if (!inode)
		return -ENOSPC;

	inode->i_mode = mode;
	mode_to_prot(inode);
	mark_inode_dirty(inode);

	inode->i_op = &affs_file_inode_operations;
	inode->i_fop = &affs_file_operations;
	inode->i_mapping->a_ops = (AFFS_SB(sb)->s_flags & SF_OFS) ? &affs_aops_ofs : &affs_aops;
	error = affs_add_entry(dir, inode, dentry, ST_FILE);
	if (error) {
		clear_nlink(inode);
		iput(inode);
		return error;
	}
	return 0;
}

int
affs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct inode		*inode;
	int			 error;

	pr_debug("%s(%lu,\"%.*s\",0%ho)\n",
		 __func__, dir->i_ino, (int)dentry->d_name.len,
		 dentry->d_name.name, mode);

	inode = affs_new_inode(dir);
	if (!inode)
		return -ENOSPC;

	inode->i_mode = S_IFDIR | mode;
	mode_to_prot(inode);

	inode->i_op = &affs_dir_inode_operations;
	inode->i_fop = &affs_dir_operations;

	error = affs_add_entry(dir, inode, dentry, ST_USERDIR);
	if (error) {
		clear_nlink(inode);
		mark_inode_dirty(inode);
		iput(inode);
		return error;
	}
	return 0;
}

int
affs_rmdir(struct inode *dir, struct dentry *dentry)
{
	pr_debug("%s(dir=%u, %lu \"%.*s\")\n",
		__func__, (u32)dir->i_ino, dentry->d_inode->i_ino,
		 (int)dentry->d_name.len, dentry->d_name.name);

	return affs_remove_header(dentry);
}

int
affs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	struct super_block	*sb = dir->i_sb;
	struct buffer_head	*bh;
	struct inode		*inode;
	char			*p;
	int			 i, maxlen, error;
	char			 c, lc;

	pr_debug("%s(%lu,\"%.*s\" -> \"%s\")\n",
		 __func__, dir->i_ino, (int)dentry->d_name.len,
		 dentry->d_name.name, symname);

	maxlen = AFFS_SB(sb)->s_hashsize * sizeof(u32) - 1;
	inode  = affs_new_inode(dir);
	if (!inode)
		return -ENOSPC;

	inode->i_op = &affs_symlink_inode_operations;
	inode->i_data.a_ops = &affs_symlink_aops;
	inode->i_mode = S_IFLNK | 0777;
	mode_to_prot(inode);

	error = -EIO;
	bh = affs_bread(sb, inode->i_ino);
	if (!bh)
		goto err;
	i  = 0;
	p  = (char *)AFFS_HEAD(bh)->table;
	lc = '/';
	if (*symname == '/') {
		struct affs_sb_info *sbi = AFFS_SB(sb);
		while (*symname == '/')
			symname++;
		spin_lock(&sbi->symlink_lock);
		while (sbi->s_volume[i])	/* Cannot overflow */
			*p++ = sbi->s_volume[i++];
		spin_unlock(&sbi->symlink_lock);
	}
	while (i < maxlen && (c = *symname++)) {
		if (c == '.' && lc == '/' && *symname == '.' && symname[1] == '/') {
			*p++ = '/';
			i++;
			symname += 2;
			lc = '/';
		} else if (c == '.' && lc == '/' && *symname == '/') {
			symname++;
			lc = '/';
		} else {
			*p++ = c;
			lc   = c;
			i++;
		}
		if (lc == '/')
			while (*symname == '/')
				symname++;
	}
	*p = 0;
	mark_buffer_dirty_inode(bh, inode);
	affs_brelse(bh);
	mark_inode_dirty(inode);

	error = affs_add_entry(dir, inode, dentry, ST_SOFTLINK);
	if (error)
		goto err;

	return 0;

err:
	clear_nlink(inode);
	mark_inode_dirty(inode);
	iput(inode);
	return error;
}

int
affs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;

	pr_debug("%s(%u, %u, \"%.*s\")\n",
		 __func__, (u32)inode->i_ino, (u32)dir->i_ino,
		 (int)dentry->d_name.len,dentry->d_name.name);

	return affs_add_entry(dir, inode, dentry, ST_LINKFILE);
}

int
affs_rename(struct inode *old_dir, struct dentry *old_dentry,
	    struct inode *new_dir, struct dentry *new_dentry)
{
	struct super_block *sb = old_dir->i_sb;
	struct buffer_head *bh = NULL;
	int retval;

	pr_debug("%s(old=%u,\"%*s\" to new=%u,\"%*s\")\n",
		 __func__, (u32)old_dir->i_ino, (int)old_dentry->d_name.len,
		 old_dentry->d_name.name, (u32)new_dir->i_ino,
		(int)new_dentry->d_name.len, new_dentry->d_name.name);

	retval = affs_check_name(new_dentry->d_name.name,
				 new_dentry->d_name.len,
				 affs_nofilenametruncate(old_dentry));

	if (retval)
		return retval;

	/* Unlink destination if it already exists */
	if (new_dentry->d_inode) {
		retval = affs_remove_header(new_dentry);
		if (retval)
			return retval;
	}

	bh = affs_bread(sb, old_dentry->d_inode->i_ino);
	if (!bh)
		return -EIO;

	/* Remove header from its parent directory. */
	affs_lock_dir(old_dir);
	retval = affs_remove_hash(old_dir, bh);
	affs_unlock_dir(old_dir);
	if (retval)
		goto done;

	/* And insert it into the new directory with the new name. */
	affs_copy_name(AFFS_TAIL(sb, bh)->name, new_dentry);
	affs_fix_checksum(sb, bh);
	affs_lock_dir(new_dir);
	retval = affs_insert_hash(new_dir, bh);
	affs_unlock_dir(new_dir);
	/* TODO: move it back to old_dir, if error? */

done:
	mark_buffer_dirty_inode(bh, retval ? old_dir : new_dir);
	affs_brelse(bh);
	return retval;
}
/************************************************************/
/* ../linux-3.17/fs/affs/namei.c */
/************************************************************/
/*
 *  linux/fs/affs/inode.c
 *
 *  (c) 1996  Hans-Joachim Widmaier - Rewritten
 *
 *  (C) 1993  Ray Burr - Modified for Amiga FFS filesystem.
 *
 *  (C) 1992  Eric Youngdale Modified for ISO9660 filesystem.
 *
 *  (C) 1991  Linus Torvalds - minix filesystem
 */
// #include <linux/sched.h>
#include <linux/gfp.h>
// #include "affs.h"

extern const struct inode_operations affs_symlink_inode_operations;
extern struct timezone sys_tz;

struct inode *affs_iget(struct super_block *sb, unsigned long ino)
{
	struct affs_sb_info	*sbi = AFFS_SB(sb);
	struct buffer_head	*bh;
	struct affs_head	*head;
	struct affs_tail	*tail;
	struct inode		*inode;
	u32			 block;
	u32			 size;
	u32			 prot;
	u16			 id;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	pr_debug("affs_iget(%lu)\n", inode->i_ino);

	block = inode->i_ino;
	bh = affs_bread(sb, block);
	if (!bh) {
		affs_warning(sb, "read_inode", "Cannot read block %d", block);
		goto bad_inode;
	}
	if (affs_checksum_block(sb, bh) || be32_to_cpu(AFFS_HEAD(bh)->ptype) != T_SHORT) {
		affs_warning(sb,"read_inode",
			   "Checksum or type (ptype=%d) error on inode %d",
			   AFFS_HEAD(bh)->ptype, block);
		goto bad_inode;
	}

	head = AFFS_HEAD(bh);
	tail = AFFS_TAIL(sb, bh);
	prot = be32_to_cpu(tail->protect);

	inode->i_size = 0;
	set_nlink(inode, 1);
	inode->i_mode = 0;
	AFFS_I(inode)->i_extcnt = 1;
	AFFS_I(inode)->i_ext_last = ~1;
	AFFS_I(inode)->i_protect = prot;
	atomic_set(&AFFS_I(inode)->i_opencnt, 0);
	AFFS_I(inode)->i_blkcnt = 0;
	AFFS_I(inode)->i_lc = NULL;
	AFFS_I(inode)->i_lc_size = 0;
	AFFS_I(inode)->i_lc_shift = 0;
	AFFS_I(inode)->i_lc_mask = 0;
	AFFS_I(inode)->i_ac = NULL;
	AFFS_I(inode)->i_ext_bh = NULL;
	AFFS_I(inode)->mmu_private = 0;
	AFFS_I(inode)->i_lastalloc = 0;
	AFFS_I(inode)->i_pa_cnt = 0;

	if (sbi->s_flags & SF_SETMODE)
		inode->i_mode = sbi->s_mode;
	else
		inode->i_mode = prot_to_mode(prot);

	id = be16_to_cpu(tail->uid);
	if (id == 0 || sbi->s_flags & SF_SETUID)
		inode->i_uid = sbi->s_uid;
	else if (id == 0xFFFF && sbi->s_flags & SF_MUFS)
		i_uid_write(inode, 0);
	else
		i_uid_write(inode, id);

	id = be16_to_cpu(tail->gid);
	if (id == 0 || sbi->s_flags & SF_SETGID)
		inode->i_gid = sbi->s_gid;
	else if (id == 0xFFFF && sbi->s_flags & SF_MUFS)
		i_gid_write(inode, 0);
	else
		i_gid_write(inode, id);

	switch (be32_to_cpu(tail->stype)) {
	case ST_ROOT:
		inode->i_uid = sbi->s_uid;
		inode->i_gid = sbi->s_gid;
		/* fall through */
	case ST_USERDIR:
		if (be32_to_cpu(tail->stype) == ST_USERDIR ||
		    sbi->s_flags & SF_SETMODE) {
			if (inode->i_mode & S_IRUSR)
				inode->i_mode |= S_IXUSR;
			if (inode->i_mode & S_IRGRP)
				inode->i_mode |= S_IXGRP;
			if (inode->i_mode & S_IROTH)
				inode->i_mode |= S_IXOTH;
			inode->i_mode |= S_IFDIR;
		} else
			inode->i_mode = S_IRUGO | S_IXUGO | S_IWUSR | S_IFDIR;
		/* Maybe it should be controlled by mount parameter? */
		//inode->i_mode |= S_ISVTX;
		inode->i_op = &affs_dir_inode_operations;
		inode->i_fop = &affs_dir_operations;
		break;
	case ST_LINKDIR:
#if 0
		affs_warning(sb, "read_inode", "inode is LINKDIR");
		goto bad_inode;
#else
		inode->i_mode |= S_IFDIR;
		/* ... and leave ->i_op and ->i_fop pointing to empty */
		break;
#endif
	case ST_LINKFILE:
		affs_warning(sb, "read_inode", "inode is LINKFILE");
		goto bad_inode;
	case ST_FILE:
		size = be32_to_cpu(tail->size);
		inode->i_mode |= S_IFREG;
		AFFS_I(inode)->mmu_private = inode->i_size = size;
		if (inode->i_size) {
			AFFS_I(inode)->i_blkcnt = (size - 1) /
					       sbi->s_data_blksize + 1;
			AFFS_I(inode)->i_extcnt = (AFFS_I(inode)->i_blkcnt - 1) /
					       sbi->s_hashsize + 1;
		}
		if (tail->link_chain)
			set_nlink(inode, 2);
		inode->i_mapping->a_ops = (sbi->s_flags & SF_OFS) ? &affs_aops_ofs : &affs_aops;
		inode->i_op = &affs_file_inode_operations;
		inode->i_fop = &affs_file_operations;
		break;
	case ST_SOFTLINK:
		inode->i_mode |= S_IFLNK;
		inode->i_op = &affs_symlink_inode_operations;
		inode->i_data.a_ops = &affs_symlink_aops;
		break;
	}

	inode->i_mtime.tv_sec = inode->i_atime.tv_sec = inode->i_ctime.tv_sec
		       = (be32_to_cpu(tail->change.days) * (24 * 60 * 60) +
		         be32_to_cpu(tail->change.mins) * 60 +
			 be32_to_cpu(tail->change.ticks) / 50 +
			 ((8 * 365 + 2) * 24 * 60 * 60)) +
			 sys_tz.tz_minuteswest * 60;
	inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = inode->i_atime.tv_nsec = 0;
	affs_brelse(bh);
	unlock_new_inode(inode);
	return inode;

bad_inode:
	affs_brelse(bh);
	iget_failed(inode);
	return ERR_PTR(-EIO);
}

int
affs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct super_block	*sb = inode->i_sb;
	struct buffer_head	*bh;
	struct affs_tail	*tail;
	uid_t			 uid;
	gid_t			 gid;

	pr_debug("write_inode(%lu)\n", inode->i_ino);

	if (!inode->i_nlink)
		// possibly free block
		return 0;
	bh = affs_bread(sb, inode->i_ino);
	if (!bh) {
		affs_error(sb,"write_inode","Cannot read block %lu",inode->i_ino);
		return -EIO;
	}
	tail = AFFS_TAIL(sb, bh);
	if (tail->stype == cpu_to_be32(ST_ROOT)) {
		secs_to_datestamp(inode->i_mtime.tv_sec,&AFFS_ROOT_TAIL(sb, bh)->root_change);
	} else {
		tail->protect = cpu_to_be32(AFFS_I(inode)->i_protect);
		tail->size = cpu_to_be32(inode->i_size);
		secs_to_datestamp(inode->i_mtime.tv_sec,&tail->change);
		if (!(inode->i_ino == AFFS_SB(sb)->s_root_block)) {
			uid = i_uid_read(inode);
			gid = i_gid_read(inode);
			if (AFFS_SB(sb)->s_flags & SF_MUFS) {
				if (uid == 0 || uid == 0xFFFF)
					uid = uid ^ ~0;
				if (gid == 0 || gid == 0xFFFF)
					gid = gid ^ ~0;
			}
			if (!(AFFS_SB(sb)->s_flags & SF_SETUID))
				tail->uid = cpu_to_be16(uid);
			if (!(AFFS_SB(sb)->s_flags & SF_SETGID))
				tail->gid = cpu_to_be16(gid);
		}
	}
	affs_fix_checksum(sb, bh);
	mark_buffer_dirty_inode(bh, inode);
	affs_brelse(bh);
	affs_free_prealloc(inode);
	return 0;
}

int
affs_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error;

	pr_debug("notify_change(%lu,0x%x)\n", inode->i_ino, attr->ia_valid);

	error = inode_change_ok(inode,attr);
	if (error)
		goto out;

	if (((attr->ia_valid & ATTR_UID) && (AFFS_SB(inode->i_sb)->s_flags & SF_SETUID)) ||
	    ((attr->ia_valid & ATTR_GID) && (AFFS_SB(inode->i_sb)->s_flags & SF_SETGID)) ||
	    ((attr->ia_valid & ATTR_MODE) &&
	     (AFFS_SB(inode->i_sb)->s_flags & (SF_SETMODE | SF_IMMUTABLE)))) {
		if (!(AFFS_SB(inode->i_sb)->s_flags & SF_QUIET))
			error = -EPERM;
		goto out;
	}

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		error = inode_newsize_ok(inode, attr->ia_size);
		if (error)
			return error;

		truncate_setsize(inode, attr->ia_size);
		affs_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);

	if (attr->ia_valid & ATTR_MODE)
		mode_to_prot(inode);
out:
	return error;
}

void
affs_evict_inode(struct inode *inode)
{
	unsigned long cache_page;
	pr_debug("evict_inode(ino=%lu, nlink=%u)\n",
		 inode->i_ino, inode->i_nlink);
	truncate_inode_pages_final(&inode->i_data);

	if (!inode->i_nlink) {
		inode->i_size = 0;
		affs_truncate(inode);
	}

	invalidate_inode_buffers(inode);
	clear_inode(inode);
	affs_free_prealloc(inode);
	cache_page = (unsigned long)AFFS_I(inode)->i_lc;
	if (cache_page) {
		pr_debug("freeing ext cache\n");
		AFFS_I(inode)->i_lc = NULL;
		AFFS_I(inode)->i_ac = NULL;
		free_page(cache_page);
	}
	affs_brelse(AFFS_I(inode)->i_ext_bh);
	AFFS_I(inode)->i_ext_last = ~1;
	AFFS_I(inode)->i_ext_bh = NULL;

	if (!inode->i_nlink)
		affs_free_block(inode->i_sb, inode->i_ino);
}

struct inode *
affs_new_inode(struct inode *dir)
{
	struct super_block	*sb = dir->i_sb;
	struct inode		*inode;
	u32			 block;
	struct buffer_head	*bh;

	if (!(inode = new_inode(sb)))
		goto err_inode;

	if (!(block = affs_alloc_block(dir, dir->i_ino)))
		goto err_block;

	bh = affs_getzeroblk(sb, block);
	if (!bh)
		goto err_bh;
	mark_buffer_dirty_inode(bh, inode);
	affs_brelse(bh);

	inode->i_uid     = current_fsuid();
	inode->i_gid     = current_fsgid();
	inode->i_ino     = block;
	set_nlink(inode, 1);
	inode->i_mtime   = inode->i_atime = inode->i_ctime = CURRENT_TIME_SEC;
	atomic_set(&AFFS_I(inode)->i_opencnt, 0);
	AFFS_I(inode)->i_blkcnt = 0;
	AFFS_I(inode)->i_lc = NULL;
	AFFS_I(inode)->i_lc_size = 0;
	AFFS_I(inode)->i_lc_shift = 0;
	AFFS_I(inode)->i_lc_mask = 0;
	AFFS_I(inode)->i_ac = NULL;
	AFFS_I(inode)->i_ext_bh = NULL;
	AFFS_I(inode)->mmu_private = 0;
	AFFS_I(inode)->i_protect = 0;
	AFFS_I(inode)->i_lastalloc = 0;
	AFFS_I(inode)->i_pa_cnt = 0;
	AFFS_I(inode)->i_extcnt = 1;
	AFFS_I(inode)->i_ext_last = ~1;

	insert_inode_hash(inode);

	return inode;

err_bh:
	affs_free_block(sb, block);
err_block:
	iput(inode);
err_inode:
	return NULL;
}

/*
 * Add an entry to a directory. Create the header block
 * and insert it into the hash table.
 */

int
affs_add_entry(struct inode *dir, struct inode *inode, struct dentry *dentry, s32 type)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *inode_bh = NULL;
	struct buffer_head *bh = NULL;
	u32 block = 0;
	int retval;

	pr_debug("%s(dir=%u, inode=%u, \"%*s\", type=%d)\n",
		 __func__, (u32)dir->i_ino,
	         (u32)inode->i_ino, (int)dentry->d_name.len, dentry->d_name.name, type);

	retval = -EIO;
	bh = affs_bread(sb, inode->i_ino);
	if (!bh)
		goto done;

	affs_lock_link(inode);
	switch (type) {
	case ST_LINKFILE:
	case ST_LINKDIR:
		retval = -ENOSPC;
		block = affs_alloc_block(dir, dir->i_ino);
		if (!block)
			goto err;
		retval = -EIO;
		inode_bh = bh;
		bh = affs_getzeroblk(sb, block);
		if (!bh)
			goto err;
		break;
	default:
		break;
	}

	AFFS_HEAD(bh)->ptype = cpu_to_be32(T_SHORT);
	AFFS_HEAD(bh)->key = cpu_to_be32(bh->b_blocknr);
	affs_copy_name(AFFS_TAIL(sb, bh)->name, dentry);
	AFFS_TAIL(sb, bh)->stype = cpu_to_be32(type);
	AFFS_TAIL(sb, bh)->parent = cpu_to_be32(dir->i_ino);

	if (inode_bh) {
		__be32 chain;
	       	chain = AFFS_TAIL(sb, inode_bh)->link_chain;
		AFFS_TAIL(sb, bh)->original = cpu_to_be32(inode->i_ino);
		AFFS_TAIL(sb, bh)->link_chain = chain;
		AFFS_TAIL(sb, inode_bh)->link_chain = cpu_to_be32(block);
		affs_adjust_checksum(inode_bh, block - be32_to_cpu(chain));
		mark_buffer_dirty_inode(inode_bh, inode);
		set_nlink(inode, 2);
		ihold(inode);
	}
	affs_fix_checksum(sb, bh);
	mark_buffer_dirty_inode(bh, inode);
	dentry->d_fsdata = (void *)(long)bh->b_blocknr;

	affs_lock_dir(dir);
	retval = affs_insert_hash(dir, bh);
	mark_buffer_dirty_inode(bh, inode);
	affs_unlock_dir(dir);
	affs_unlock_link(inode);

	d_instantiate(dentry, inode);
done:
	affs_brelse(inode_bh);
	affs_brelse(bh);
	return retval;
err:
	if (block)
		affs_free_block(sb, block);
	affs_unlock_link(inode);
	goto done;
}
/************************************************************/
/* ../linux-3.17/fs/affs/inode.c */
/************************************************************/
/*
 *  linux/fs/affs/file.c
 *
 *  (c) 1996  Hans-Joachim Widmaier - Rewritten
 *
 *  (C) 1993  Ray Burr - Modified for Amiga FFS filesystem.
 *
 *  (C) 1992  Eric Youngdale Modified for ISO 9660 filesystem.
 *
 *  (C) 1991  Linus Torvalds - minix filesystem
 *
 *  affs regular file handling primitives
 */

// #include "affs.h"

#if PAGE_SIZE < 4096
#error PAGE_SIZE must be at least 4096
#endif

static int affs_grow_extcache(struct inode *inode, u32 lc_idx);
static struct buffer_head *affs_alloc_extblock(struct inode *inode, struct buffer_head *bh, u32 ext);
static inline struct buffer_head *affs_get_extblock(struct inode *inode, u32 ext);
static struct buffer_head *affs_get_extblock_slow(struct inode *inode, u32 ext);
static int affs_file_open(struct inode *inode, struct file *filp);
static int affs_file_release(struct inode *inode, struct file *filp);

const struct file_operations affs_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.open		= affs_file_open,
	.release	= affs_file_release,
	.fsync		= affs_file_fsync,
	.splice_read	= generic_file_splice_read,
};

const struct inode_operations affs_file_inode_operations = {
	.setattr	= affs_notify_change,
};

static int
affs_file_open(struct inode *inode, struct file *filp)
{
	pr_debug("open(%lu,%d)\n",
		 inode->i_ino, atomic_read(&AFFS_I(inode)->i_opencnt));
	atomic_inc(&AFFS_I(inode)->i_opencnt);
	return 0;
}

static int
affs_file_release(struct inode *inode, struct file *filp)
{
	pr_debug("release(%lu, %d)\n",
		 inode->i_ino, atomic_read(&AFFS_I(inode)->i_opencnt));

	if (atomic_dec_and_test(&AFFS_I(inode)->i_opencnt)) {
		mutex_lock(&inode->i_mutex);
		if (inode->i_size != AFFS_I(inode)->mmu_private)
			affs_truncate(inode);
		affs_free_prealloc(inode);
		mutex_unlock(&inode->i_mutex);
	}

	return 0;
}

static int
affs_grow_extcache(struct inode *inode, u32 lc_idx)
{
	struct super_block	*sb = inode->i_sb;
	struct buffer_head	*bh;
	u32 lc_max;
	int i, j, key;

	if (!AFFS_I(inode)->i_lc) {
		char *ptr = (char *)get_zeroed_page(GFP_NOFS);
		if (!ptr)
			return -ENOMEM;
		AFFS_I(inode)->i_lc = (u32 *)ptr;
		AFFS_I(inode)->i_ac = (struct affs_ext_key *)(ptr + AFFS_CACHE_SIZE / 2);
	}

	lc_max = AFFS_LC_SIZE << AFFS_I(inode)->i_lc_shift;

	if (AFFS_I(inode)->i_extcnt > lc_max) {
		u32 lc_shift, lc_mask, tmp, off;

		/* need to recalculate linear cache, start from old size */
		lc_shift = AFFS_I(inode)->i_lc_shift;
		tmp = (AFFS_I(inode)->i_extcnt / AFFS_LC_SIZE) >> lc_shift;
		for (; tmp; tmp >>= 1)
			lc_shift++;
		lc_mask = (1 << lc_shift) - 1;

		/* fix idx and old size to new shift */
		lc_idx >>= (lc_shift - AFFS_I(inode)->i_lc_shift);
		AFFS_I(inode)->i_lc_size >>= (lc_shift - AFFS_I(inode)->i_lc_shift);

		/* first shrink old cache to make more space */
		off = 1 << (lc_shift - AFFS_I(inode)->i_lc_shift);
		for (i = 1, j = off; j < AFFS_LC_SIZE; i++, j += off)
			AFFS_I(inode)->i_ac[i] = AFFS_I(inode)->i_ac[j];

		AFFS_I(inode)->i_lc_shift = lc_shift;
		AFFS_I(inode)->i_lc_mask = lc_mask;
	}

	/* fill cache to the needed index */
	i = AFFS_I(inode)->i_lc_size;
	AFFS_I(inode)->i_lc_size = lc_idx + 1;
	for (; i <= lc_idx; i++) {
		if (!i) {
			AFFS_I(inode)->i_lc[0] = inode->i_ino;
			continue;
		}
		key = AFFS_I(inode)->i_lc[i - 1];
		j = AFFS_I(inode)->i_lc_mask + 1;
		// unlock cache
		for (; j > 0; j--) {
			bh = affs_bread(sb, key);
			if (!bh)
				goto err;
			key = be32_to_cpu(AFFS_TAIL(sb, bh)->extension);
			affs_brelse(bh);
		}
		// lock cache
		AFFS_I(inode)->i_lc[i] = key;
	}

	return 0;

err:
	// lock cache
	return -EIO;
}

static struct buffer_head *
affs_alloc_extblock(struct inode *inode, struct buffer_head *bh, u32 ext)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *new_bh;
	u32 blocknr, tmp;

	blocknr = affs_alloc_block(inode, bh->b_blocknr);
	if (!blocknr)
		return ERR_PTR(-ENOSPC);

	new_bh = affs_getzeroblk(sb, blocknr);
	if (!new_bh) {
		affs_free_block(sb, blocknr);
		return ERR_PTR(-EIO);
	}

	AFFS_HEAD(new_bh)->ptype = cpu_to_be32(T_LIST);
	AFFS_HEAD(new_bh)->key = cpu_to_be32(blocknr);
	AFFS_TAIL(sb, new_bh)->stype = cpu_to_be32(ST_FILE);
	AFFS_TAIL(sb, new_bh)->parent = cpu_to_be32(inode->i_ino);
	affs_fix_checksum(sb, new_bh);

	mark_buffer_dirty_inode(new_bh, inode);

	tmp = be32_to_cpu(AFFS_TAIL(sb, bh)->extension);
	if (tmp)
		affs_warning(sb, "alloc_ext", "previous extension set (%x)", tmp);
	AFFS_TAIL(sb, bh)->extension = cpu_to_be32(blocknr);
	affs_adjust_checksum(bh, blocknr - tmp);
	mark_buffer_dirty_inode(bh, inode);

	AFFS_I(inode)->i_extcnt++;
	mark_inode_dirty(inode);

	return new_bh;
}

static inline struct buffer_head *
affs_get_extblock(struct inode *inode, u32 ext)
{
	/* inline the simplest case: same extended block as last time */
	struct buffer_head *bh = AFFS_I(inode)->i_ext_bh;
	if (ext == AFFS_I(inode)->i_ext_last)
		get_bh(bh);
	else
		/* we have to do more (not inlined) */
		bh = affs_get_extblock_slow(inode, ext);

	return bh;
}

static struct buffer_head *
affs_get_extblock_slow(struct inode *inode, u32 ext)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh;
	u32 ext_key;
	u32 lc_idx, lc_off, ac_idx;
	u32 tmp, idx;

	if (ext == AFFS_I(inode)->i_ext_last + 1) {
		/* read the next extended block from the current one */
		bh = AFFS_I(inode)->i_ext_bh;
		ext_key = be32_to_cpu(AFFS_TAIL(sb, bh)->extension);
		if (ext < AFFS_I(inode)->i_extcnt)
			goto read_ext;
		if (ext > AFFS_I(inode)->i_extcnt)
			BUG();
		bh = affs_alloc_extblock(inode, bh, ext);
		if (IS_ERR(bh))
			return bh;
		goto store_ext;
	}

	if (ext == 0) {
		/* we seek back to the file header block */
		ext_key = inode->i_ino;
		goto read_ext;
	}

	if (ext >= AFFS_I(inode)->i_extcnt) {
		struct buffer_head *prev_bh;

		/* allocate a new extended block */
		if (ext > AFFS_I(inode)->i_extcnt)
			BUG();

		/* get previous extended block */
		prev_bh = affs_get_extblock(inode, ext - 1);
		if (IS_ERR(prev_bh))
			return prev_bh;
		bh = affs_alloc_extblock(inode, prev_bh, ext);
		affs_brelse(prev_bh);
		if (IS_ERR(bh))
			return bh;
		goto store_ext;
	}

again:
	/* check if there is an extended cache and whether it's large enough */
	lc_idx = ext >> AFFS_I(inode)->i_lc_shift;
	lc_off = ext & AFFS_I(inode)->i_lc_mask;

	if (lc_idx >= AFFS_I(inode)->i_lc_size) {
		int err;

		err = affs_grow_extcache(inode, lc_idx);
		if (err)
			return ERR_PTR(err);
		goto again;
	}

	/* every n'th key we find in the linear cache */
	if (!lc_off) {
		ext_key = AFFS_I(inode)->i_lc[lc_idx];
		goto read_ext;
	}

	/* maybe it's still in the associative cache */
	ac_idx = (ext - lc_idx - 1) & AFFS_AC_MASK;
	if (AFFS_I(inode)->i_ac[ac_idx].ext == ext) {
		ext_key = AFFS_I(inode)->i_ac[ac_idx].key;
		goto read_ext;
	}

	/* try to find one of the previous extended blocks */
	tmp = ext;
	idx = ac_idx;
	while (--tmp, --lc_off > 0) {
		idx = (idx - 1) & AFFS_AC_MASK;
		if (AFFS_I(inode)->i_ac[idx].ext == tmp) {
			ext_key = AFFS_I(inode)->i_ac[idx].key;
			goto find_ext;
		}
	}

	/* fall back to the linear cache */
	ext_key = AFFS_I(inode)->i_lc[lc_idx];
find_ext:
	/* read all extended blocks until we find the one we need */
	//unlock cache
	do {
		bh = affs_bread(sb, ext_key);
		if (!bh)
			goto err_bread;
		ext_key = be32_to_cpu(AFFS_TAIL(sb, bh)->extension);
		affs_brelse(bh);
		tmp++;
	} while (tmp < ext);
	//lock cache

	/* store it in the associative cache */
	// recalculate ac_idx?
	AFFS_I(inode)->i_ac[ac_idx].ext = ext;
	AFFS_I(inode)->i_ac[ac_idx].key = ext_key;

read_ext:
	/* finally read the right extended block */
	//unlock cache
	bh = affs_bread(sb, ext_key);
	if (!bh)
		goto err_bread;
	//lock cache

store_ext:
	/* release old cached extended block and store the new one */
	affs_brelse(AFFS_I(inode)->i_ext_bh);
	AFFS_I(inode)->i_ext_last = ext;
	AFFS_I(inode)->i_ext_bh = bh;
	get_bh(bh);

	return bh;

err_bread:
	affs_brelse(bh);
	return ERR_PTR(-EIO);
}

static int
affs_get_block(struct inode *inode, sector_t block, struct buffer_head *bh_result, int create)
{
	struct super_block	*sb = inode->i_sb;
	struct buffer_head	*ext_bh;
	u32			 ext;

	pr_debug("%s(%u, %lu)\n",
		 __func__, (u32)inode->i_ino, (unsigned long)block);

	BUG_ON(block > (sector_t)0x7fffffffUL);

	if (block >= AFFS_I(inode)->i_blkcnt) {
		if (block > AFFS_I(inode)->i_blkcnt || !create)
			goto err_big;
	} else
		create = 0;

	//lock cache
	affs_lock_ext(inode);

	ext = (u32)block / AFFS_SB(sb)->s_hashsize;
	block -= ext * AFFS_SB(sb)->s_hashsize;
	ext_bh = affs_get_extblock(inode, ext);
	if (IS_ERR(ext_bh))
		goto err_ext;
	map_bh(bh_result, sb, (sector_t)be32_to_cpu(AFFS_BLOCK(sb, ext_bh, block)));

	if (create) {
		u32 blocknr = affs_alloc_block(inode, ext_bh->b_blocknr);
		if (!blocknr)
			goto err_alloc;
		set_buffer_new(bh_result);
		AFFS_I(inode)->mmu_private += AFFS_SB(sb)->s_data_blksize;
		AFFS_I(inode)->i_blkcnt++;

		/* store new block */
		if (bh_result->b_blocknr)
			affs_warning(sb, "get_block", "block already set (%x)", bh_result->b_blocknr);
		AFFS_BLOCK(sb, ext_bh, block) = cpu_to_be32(blocknr);
		AFFS_HEAD(ext_bh)->block_count = cpu_to_be32(block + 1);
		affs_adjust_checksum(ext_bh, blocknr - bh_result->b_blocknr + 1);
		bh_result->b_blocknr = blocknr;

		if (!block) {
			/* insert first block into header block */
			u32 tmp = be32_to_cpu(AFFS_HEAD(ext_bh)->first_data);
			if (tmp)
				affs_warning(sb, "get_block", "first block already set (%d)", tmp);
			AFFS_HEAD(ext_bh)->first_data = cpu_to_be32(blocknr);
			affs_adjust_checksum(ext_bh, blocknr - tmp);
		}
	}

	affs_brelse(ext_bh);
	//unlock cache
	affs_unlock_ext(inode);
	return 0;

err_big:
	affs_error(inode->i_sb,"get_block","strange block request %d", block);
	return -EIO;
err_ext:
	// unlock cache
	affs_unlock_ext(inode);
	return PTR_ERR(ext_bh);
err_alloc:
	brelse(ext_bh);
	clear_buffer_mapped(bh_result);
	bh_result->b_bdev = NULL;
	// unlock cache
	affs_unlock_ext(inode);
	return -ENOSPC;
}

static int affs_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, affs_get_block, wbc);
}

static int affs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, affs_get_block);
}

static void affs_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		affs_truncate(inode);
	}
}

static int affs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	*pagep = NULL;
	ret = cont_write_begin(file, mapping, pos, len, flags, pagep, fsdata,
				affs_get_block,
				&AFFS_I(mapping->host)->mmu_private);
	if (unlikely(ret))
		affs_write_failed(mapping, pos + len);

	return ret;
}

static sector_t _affs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping,block,affs_get_block);
}

const struct address_space_operations affs_aops = {
	.readpage = affs_readpage,
	.writepage = affs_writepage,
	.write_begin = affs_write_begin,
	.write_end = generic_write_end,
	.bmap = _affs_bmap
};

static inline struct buffer_head *
affs_bread_ino(struct inode *inode, int block, int create)
{
	struct buffer_head *bh, tmp_bh;
	int err;

	tmp_bh.b_state = 0;
	err = affs_get_block(inode, block, &tmp_bh, create);
	if (!err) {
		bh = affs_bread(inode->i_sb, tmp_bh.b_blocknr);
		if (bh) {
			bh->b_state |= tmp_bh.b_state;
			return bh;
		}
		err = -EIO;
	}
	return ERR_PTR(err);
}

static inline struct buffer_head *
affs_getzeroblk_ino(struct inode *inode, int block)
{
	struct buffer_head *bh, tmp_bh;
	int err;

	tmp_bh.b_state = 0;
	err = affs_get_block(inode, block, &tmp_bh, 1);
	if (!err) {
		bh = affs_getzeroblk(inode->i_sb, tmp_bh.b_blocknr);
		if (bh) {
			bh->b_state |= tmp_bh.b_state;
			return bh;
		}
		err = -EIO;
	}
	return ERR_PTR(err);
}

static inline struct buffer_head *
affs_getemptyblk_ino(struct inode *inode, int block)
{
	struct buffer_head *bh, tmp_bh;
	int err;

	tmp_bh.b_state = 0;
	err = affs_get_block(inode, block, &tmp_bh, 1);
	if (!err) {
		bh = affs_getemptyblk(inode->i_sb, tmp_bh.b_blocknr);
		if (bh) {
			bh->b_state |= tmp_bh.b_state;
			return bh;
		}
		err = -EIO;
	}
	return ERR_PTR(err);
}

static int
affs_do_readpage_ofs(struct page *page, unsigned to)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh;
	char *data;
	unsigned pos = 0;
	u32 bidx, boff, bsize;
	u32 tmp;

	pr_debug("%s(%u, %ld, 0, %d)\n", __func__, (u32)inode->i_ino,
		 page->index, to);
	BUG_ON(to > PAGE_CACHE_SIZE);
	kmap(page);
	data = page_address(page);
	bsize = AFFS_SB(sb)->s_data_blksize;
	tmp = page->index << PAGE_CACHE_SHIFT;
	bidx = tmp / bsize;
	boff = tmp % bsize;

	while (pos < to) {
		bh = affs_bread_ino(inode, bidx, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		tmp = min(bsize - boff, to - pos);
		BUG_ON(pos + tmp > to || tmp > bsize);
		memcpy(data + pos, AFFS_DATA(bh) + boff, tmp);
		affs_brelse(bh);
		bidx++;
		pos += tmp;
		boff = 0;
	}
	flush_dcache_page(page);
	kunmap(page);
	return 0;
}

static int
affs_extent_file_ofs(struct inode *inode, u32 newsize)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh, *prev_bh;
	u32 bidx, boff;
	u32 size, bsize;
	u32 tmp;

	pr_debug("%s(%u, %d)\n", __func__, (u32)inode->i_ino, newsize);
	bsize = AFFS_SB(sb)->s_data_blksize;
	bh = NULL;
	size = AFFS_I(inode)->mmu_private;
	bidx = size / bsize;
	boff = size % bsize;
	if (boff) {
		bh = affs_bread_ino(inode, bidx, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		tmp = min(bsize - boff, newsize - size);
		BUG_ON(boff + tmp > bsize || tmp > bsize);
		memset(AFFS_DATA(bh) + boff, 0, tmp);
		be32_add_cpu(&AFFS_DATA_HEAD(bh)->size, tmp);
		affs_fix_checksum(sb, bh);
		mark_buffer_dirty_inode(bh, inode);
		size += tmp;
		bidx++;
	} else if (bidx) {
		bh = affs_bread_ino(inode, bidx - 1, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
	}

	while (size < newsize) {
		prev_bh = bh;
		bh = affs_getzeroblk_ino(inode, bidx);
		if (IS_ERR(bh))
			goto out;
		tmp = min(bsize, newsize - size);
		BUG_ON(tmp > bsize);
		AFFS_DATA_HEAD(bh)->ptype = cpu_to_be32(T_DATA);
		AFFS_DATA_HEAD(bh)->key = cpu_to_be32(inode->i_ino);
		AFFS_DATA_HEAD(bh)->sequence = cpu_to_be32(bidx);
		AFFS_DATA_HEAD(bh)->size = cpu_to_be32(tmp);
		affs_fix_checksum(sb, bh);
		bh->b_state &= ~(1UL << BH_New);
		mark_buffer_dirty_inode(bh, inode);
		if (prev_bh) {
			u32 tmp = be32_to_cpu(AFFS_DATA_HEAD(prev_bh)->next);
			if (tmp)
				affs_warning(sb, "extent_file_ofs", "next block already set for %d (%d)", bidx, tmp);
			AFFS_DATA_HEAD(prev_bh)->next = cpu_to_be32(bh->b_blocknr);
			affs_adjust_checksum(prev_bh, bh->b_blocknr - tmp);
			mark_buffer_dirty_inode(prev_bh, inode);
			affs_brelse(prev_bh);
		}
		size += bsize;
		bidx++;
	}
	affs_brelse(bh);
	inode->i_size = AFFS_I(inode)->mmu_private = newsize;
	return 0;

out:
	inode->i_size = AFFS_I(inode)->mmu_private = newsize;
	return PTR_ERR(bh);
}

static int
affs_readpage_ofs(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	u32 to;
	int err;

	pr_debug("%s(%u, %ld)\n", __func__, (u32)inode->i_ino, page->index);
	to = PAGE_CACHE_SIZE;
	if (((page->index + 1) << PAGE_CACHE_SHIFT) > inode->i_size) {
		to = inode->i_size & ~PAGE_CACHE_MASK;
		memset(page_address(page) + to, 0, PAGE_CACHE_SIZE - to);
	}

	err = affs_do_readpage_ofs(page, to);
	if (!err)
		SetPageUptodate(page);
	unlock_page(page);
	return err;
}

static int affs_write_begin_ofs(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned flags,
				struct page **pagep, void **fsdata)
{
	struct inode *inode = mapping->host;
	struct page *page;
	pgoff_t index;
	int err = 0;

	pr_debug("%s(%u, %llu, %llu)\n", __func__, (u32)inode->i_ino,
		 (unsigned long long)pos, (unsigned long long)pos + len);
	if (pos > AFFS_I(inode)->mmu_private) {
		/* XXX: this probably leaves a too-big i_size in case of
		 * failure. Should really be updating i_size at write_end time
		 */
		err = affs_extent_file_ofs(inode, pos);
		if (err)
			return err;
	}

	index = pos >> PAGE_CACHE_SHIFT;
	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	if (PageUptodate(page))
		return 0;

	/* XXX: inefficient but safe in the face of short writes */
	err = affs_do_readpage_ofs(page, PAGE_CACHE_SIZE);
	if (err) {
		unlock_page(page);
		page_cache_release(page);
	}
	return err;
}

static int affs_write_end_ofs(struct file *file, struct address_space *mapping,
				loff_t pos, unsigned len, unsigned copied,
				struct page *page, void *fsdata)
{
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh, *prev_bh;
	char *data;
	u32 bidx, boff, bsize;
	unsigned from, to;
	u32 tmp;
	int written;

	from = pos & (PAGE_CACHE_SIZE - 1);
	to = pos + len;
	/*
	 * XXX: not sure if this can handle short copies (len < copied), but
	 * we don't have to, because the page should always be uptodate here,
	 * due to write_begin.
	 */

	pr_debug("%s(%u, %llu, %llu)\n",
		 __func__, (u32)inode->i_ino, (unsigned long long)pos,
		(unsigned long long)pos + len);
	bsize = AFFS_SB(sb)->s_data_blksize;
	data = page_address(page);

	bh = NULL;
	written = 0;
	tmp = (page->index << PAGE_CACHE_SHIFT) + from;
	bidx = tmp / bsize;
	boff = tmp % bsize;
	if (boff) {
		bh = affs_bread_ino(inode, bidx, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		tmp = min(bsize - boff, to - from);
		BUG_ON(boff + tmp > bsize || tmp > bsize);
		memcpy(AFFS_DATA(bh) + boff, data + from, tmp);
		be32_add_cpu(&AFFS_DATA_HEAD(bh)->size, tmp);
		affs_fix_checksum(sb, bh);
		mark_buffer_dirty_inode(bh, inode);
		written += tmp;
		from += tmp;
		bidx++;
	} else if (bidx) {
		bh = affs_bread_ino(inode, bidx - 1, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
	}
	while (from + bsize <= to) {
		prev_bh = bh;
		bh = affs_getemptyblk_ino(inode, bidx);
		if (IS_ERR(bh))
			goto out;
		memcpy(AFFS_DATA(bh), data + from, bsize);
		if (buffer_new(bh)) {
			AFFS_DATA_HEAD(bh)->ptype = cpu_to_be32(T_DATA);
			AFFS_DATA_HEAD(bh)->key = cpu_to_be32(inode->i_ino);
			AFFS_DATA_HEAD(bh)->sequence = cpu_to_be32(bidx);
			AFFS_DATA_HEAD(bh)->size = cpu_to_be32(bsize);
			AFFS_DATA_HEAD(bh)->next = 0;
			bh->b_state &= ~(1UL << BH_New);
			if (prev_bh) {
				u32 tmp = be32_to_cpu(AFFS_DATA_HEAD(prev_bh)->next);
				if (tmp)
					affs_warning(sb, "commit_write_ofs", "next block already set for %d (%d)", bidx, tmp);
				AFFS_DATA_HEAD(prev_bh)->next = cpu_to_be32(bh->b_blocknr);
				affs_adjust_checksum(prev_bh, bh->b_blocknr - tmp);
				mark_buffer_dirty_inode(prev_bh, inode);
			}
		}
		affs_brelse(prev_bh);
		affs_fix_checksum(sb, bh);
		mark_buffer_dirty_inode(bh, inode);
		written += bsize;
		from += bsize;
		bidx++;
	}
	if (from < to) {
		prev_bh = bh;
		bh = affs_bread_ino(inode, bidx, 1);
		if (IS_ERR(bh))
			goto out;
		tmp = min(bsize, to - from);
		BUG_ON(tmp > bsize);
		memcpy(AFFS_DATA(bh), data + from, tmp);
		if (buffer_new(bh)) {
			AFFS_DATA_HEAD(bh)->ptype = cpu_to_be32(T_DATA);
			AFFS_DATA_HEAD(bh)->key = cpu_to_be32(inode->i_ino);
			AFFS_DATA_HEAD(bh)->sequence = cpu_to_be32(bidx);
			AFFS_DATA_HEAD(bh)->size = cpu_to_be32(tmp);
			AFFS_DATA_HEAD(bh)->next = 0;
			bh->b_state &= ~(1UL << BH_New);
			if (prev_bh) {
				u32 tmp = be32_to_cpu(AFFS_DATA_HEAD(prev_bh)->next);
				if (tmp)
					affs_warning(sb, "commit_write_ofs", "next block already set for %d (%d)", bidx, tmp);
				AFFS_DATA_HEAD(prev_bh)->next = cpu_to_be32(bh->b_blocknr);
				affs_adjust_checksum(prev_bh, bh->b_blocknr - tmp);
				mark_buffer_dirty_inode(prev_bh, inode);
			}
		} else if (be32_to_cpu(AFFS_DATA_HEAD(bh)->size) < tmp)
			AFFS_DATA_HEAD(bh)->size = cpu_to_be32(tmp);
		affs_brelse(prev_bh);
		affs_fix_checksum(sb, bh);
		mark_buffer_dirty_inode(bh, inode);
		written += tmp;
		from += tmp;
		bidx++;
	}
	SetPageUptodate(page);

done:
	affs_brelse(bh);
	tmp = (page->index << PAGE_CACHE_SHIFT) + from;
	if (tmp > inode->i_size)
		inode->i_size = AFFS_I(inode)->mmu_private = tmp;

	unlock_page(page);
	page_cache_release(page);

	return written;

out:
	bh = prev_bh;
	if (!written)
		written = PTR_ERR(bh);
	goto done;
}

const struct address_space_operations affs_aops_ofs = {
	.readpage = affs_readpage_ofs,
	//.writepage = affs_writepage_ofs,
	.write_begin = affs_write_begin_ofs,
	.write_end = affs_write_end_ofs
};

/* Free any preallocated blocks. */

void
affs_free_prealloc(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	pr_debug("free_prealloc(ino=%lu)\n", inode->i_ino);

	while (AFFS_I(inode)->i_pa_cnt) {
		AFFS_I(inode)->i_pa_cnt--;
		affs_free_block(sb, ++AFFS_I(inode)->i_lastalloc);
	}
}

/* Truncate (or enlarge) a file to the requested size. */

void
affs_truncate(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	u32 ext, ext_key;
	u32 last_blk, blkcnt, blk;
	u32 size;
	struct buffer_head *ext_bh;
	int i;

	pr_debug("truncate(inode=%d, oldsize=%u, newsize=%u)\n",
		 (u32)inode->i_ino, (u32)AFFS_I(inode)->mmu_private, (u32)inode->i_size);

	last_blk = 0;
	ext = 0;
	if (inode->i_size) {
		last_blk = ((u32)inode->i_size - 1) / AFFS_SB(sb)->s_data_blksize;
		ext = last_blk / AFFS_SB(sb)->s_hashsize;
	}

	if (inode->i_size > AFFS_I(inode)->mmu_private) {
		struct address_space *mapping = inode->i_mapping;
		struct page *page;
		void *fsdata;
		loff_t size = inode->i_size;
		int res;

		res = mapping->a_ops->write_begin(NULL, mapping, size, 0, 0, &page, &fsdata);
		if (!res)
			res = mapping->a_ops->write_end(NULL, mapping, size, 0, 0, page, fsdata);
		else
			inode->i_size = AFFS_I(inode)->mmu_private;
		mark_inode_dirty(inode);
		return;
	} else if (inode->i_size == AFFS_I(inode)->mmu_private)
		return;

	// lock cache
	ext_bh = affs_get_extblock(inode, ext);
	if (IS_ERR(ext_bh)) {
		affs_warning(sb, "truncate", "unexpected read error for ext block %u (%d)",
			     ext, PTR_ERR(ext_bh));
		return;
	}
	if (AFFS_I(inode)->i_lc) {
		/* clear linear cache */
		i = (ext + 1) >> AFFS_I(inode)->i_lc_shift;
		if (AFFS_I(inode)->i_lc_size > i) {
			AFFS_I(inode)->i_lc_size = i;
			for (; i < AFFS_LC_SIZE; i++)
				AFFS_I(inode)->i_lc[i] = 0;
		}
		/* clear associative cache */
		for (i = 0; i < AFFS_AC_SIZE; i++)
			if (AFFS_I(inode)->i_ac[i].ext >= ext)
				AFFS_I(inode)->i_ac[i].ext = 0;
	}
	ext_key = be32_to_cpu(AFFS_TAIL(sb, ext_bh)->extension);

	blkcnt = AFFS_I(inode)->i_blkcnt;
	i = 0;
	blk = last_blk;
	if (inode->i_size) {
		i = last_blk % AFFS_SB(sb)->s_hashsize + 1;
		blk++;
	} else
		AFFS_HEAD(ext_bh)->first_data = 0;
	AFFS_HEAD(ext_bh)->block_count = cpu_to_be32(i);
	size = AFFS_SB(sb)->s_hashsize;
	if (size > blkcnt - blk + i)
		size = blkcnt - blk + i;
	for (; i < size; i++, blk++) {
		affs_free_block(sb, be32_to_cpu(AFFS_BLOCK(sb, ext_bh, i)));
		AFFS_BLOCK(sb, ext_bh, i) = 0;
	}
	AFFS_TAIL(sb, ext_bh)->extension = 0;
	affs_fix_checksum(sb, ext_bh);
	mark_buffer_dirty_inode(ext_bh, inode);
	affs_brelse(ext_bh);

	if (inode->i_size) {
		AFFS_I(inode)->i_blkcnt = last_blk + 1;
		AFFS_I(inode)->i_extcnt = ext + 1;
		if (AFFS_SB(sb)->s_flags & SF_OFS) {
			struct buffer_head *bh = affs_bread_ino(inode, last_blk, 0);
			u32 tmp;
			if (IS_ERR(bh)) {
				affs_warning(sb, "truncate", "unexpected read error for last block %u (%d)",
					     ext, PTR_ERR(bh));
				return;
			}
			tmp = be32_to_cpu(AFFS_DATA_HEAD(bh)->next);
			AFFS_DATA_HEAD(bh)->next = 0;
			affs_adjust_checksum(bh, -tmp);
			affs_brelse(bh);
		}
	} else {
		AFFS_I(inode)->i_blkcnt = 0;
		AFFS_I(inode)->i_extcnt = 1;
	}
	AFFS_I(inode)->mmu_private = inode->i_size;
	// unlock cache

	while (ext_key) {
		ext_bh = affs_bread(sb, ext_key);
		size = AFFS_SB(sb)->s_hashsize;
		if (size > blkcnt - blk)
			size = blkcnt - blk;
		for (i = 0; i < size; i++, blk++)
			affs_free_block(sb, be32_to_cpu(AFFS_BLOCK(sb, ext_bh, i)));
		affs_free_block(sb, ext_key);
		ext_key = be32_to_cpu(AFFS_TAIL(sb, ext_bh)->extension);
		affs_brelse(ext_bh);
	}
	affs_free_prealloc(inode);
}

int affs_file_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	int ret, err;

	err = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (err)
		return err;

	mutex_lock(&inode->i_mutex);
	ret = write_inode_now(inode, 0);
	err = sync_blockdev(inode->i_sb->s_bdev);
	if (!ret)
		ret = err;
	mutex_unlock(&inode->i_mutex);
	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/affs/file.c */
/************************************************************/
/*
 *  linux/fs/affs/dir.c
 *
 *  (c) 1996  Hans-Joachim Widmaier - Rewritten
 *
 *  (C) 1993  Ray Burr - Modified for Amiga FFS filesystem.
 *
 *  (C) 1992  Eric Youngdale Modified for ISO 9660 filesystem.
 *
 *  (C) 1991  Linus Torvalds - minix filesystem
 *
 *  affs directory handling functions
 *
 */

// #include "affs.h"

static int affs_readdir(struct file *, struct dir_context *);

const struct file_operations affs_dir_operations = {
	.read		= generic_read_dir,
	.llseek		= generic_file_llseek,
	.iterate	= affs_readdir,
	.fsync		= affs_file_fsync,
};

/*
 * directories can handle most operations...
 */
const struct inode_operations affs_dir_inode_operations = {
	.create		= affs_create,
	.lookup		= affs_lookup,
	.link		= affs_link,
	.unlink		= affs_unlink,
	.symlink	= affs_symlink,
	.mkdir		= affs_mkdir,
	.rmdir		= affs_rmdir,
	.rename		= affs_rename,
	.setattr	= affs_notify_change,
};

static int
affs_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode		*inode = file_inode(file);
	struct super_block	*sb = inode->i_sb;
	struct buffer_head	*dir_bh = NULL;
	struct buffer_head	*fh_bh = NULL;
	unsigned char		*name;
	int			 namelen;
	u32			 i;
	int			 hash_pos;
	int			 chain_pos;
	u32			 ino;
	int			 error = 0;

	pr_debug("%s(ino=%lu,f_pos=%lx)\n",
		 __func__, inode->i_ino, (unsigned long)ctx->pos);

	if (ctx->pos < 2) {
		file->private_data = (void *)0;
		if (!dir_emit_dots(file, ctx))
			return 0;
	}

	affs_lock_dir(inode);
	chain_pos = (ctx->pos - 2) & 0xffff;
	hash_pos  = (ctx->pos - 2) >> 16;
	if (chain_pos == 0xffff) {
		affs_warning(sb, "readdir", "More than 65535 entries in chain");
		chain_pos = 0;
		hash_pos++;
		ctx->pos = ((hash_pos << 16) | chain_pos) + 2;
	}
	dir_bh = affs_bread(sb, inode->i_ino);
	if (!dir_bh)
		goto out_unlock_dir;

	/* If the directory hasn't changed since the last call to readdir(),
	 * we can jump directly to where we left off.
	 */
	ino = (u32)(long)file->private_data;
	if (ino && file->f_version == inode->i_version) {
		pr_debug("readdir() left off=%d\n", ino);
		goto inside;
	}

	ino = be32_to_cpu(AFFS_HEAD(dir_bh)->table[hash_pos]);
	for (i = 0; ino && i < chain_pos; i++) {
		fh_bh = affs_bread(sb, ino);
		if (!fh_bh) {
			affs_error(sb, "readdir","Cannot read block %d", i);
			error = -EIO;
			goto out_brelse_dir;
		}
		ino = be32_to_cpu(AFFS_TAIL(sb, fh_bh)->hash_chain);
		affs_brelse(fh_bh);
		fh_bh = NULL;
	}
	if (ino)
		goto inside;
	hash_pos++;

	for (; hash_pos < AFFS_SB(sb)->s_hashsize; hash_pos++) {
		ino = be32_to_cpu(AFFS_HEAD(dir_bh)->table[hash_pos]);
		if (!ino)
			continue;
		ctx->pos = (hash_pos << 16) + 2;
inside:
		do {
			fh_bh = affs_bread(sb, ino);
			if (!fh_bh) {
				affs_error(sb, "readdir",
					   "Cannot read block %d", ino);
				break;
			}

			namelen = min(AFFS_TAIL(sb, fh_bh)->name[0], (u8)30);
			name = AFFS_TAIL(sb, fh_bh)->name + 1;
			pr_debug("readdir(): dir_emit(\"%.*s\", "
				 "ino=%u), hash=%d, f_pos=%x\n",
				 namelen, name, ino, hash_pos, (u32)ctx->pos);

			if (!dir_emit(ctx, name, namelen, ino, DT_UNKNOWN))
				goto done;
			ctx->pos++;
			ino = be32_to_cpu(AFFS_TAIL(sb, fh_bh)->hash_chain);
			affs_brelse(fh_bh);
			fh_bh = NULL;
		} while (ino);
	}
done:
	file->f_version = inode->i_version;
	file->private_data = (void *)(long)ino;
	affs_brelse(fh_bh);

out_brelse_dir:
	affs_brelse(dir_bh);

out_unlock_dir:
	affs_unlock_dir(inode);
	return error;
}
/************************************************************/
/* ../linux-3.17/fs/affs/dir.c */
/************************************************************/
/*
 *  linux/fs/affs/amigaffs.c
 *
 *  (c) 1996  Hans-Joachim Widmaier - Rewritten
 *
 *  (C) 1993  Ray Burr - Amiga FFS filesystem.
 *
 *  Please send bug reports to: hjw@zvw.de
 */

// #include "affs.h"

extern struct timezone sys_tz;

static char ErrorBuffer[256];

/*
 * Functions for accessing Amiga-FFS structures.
 */


/* Insert a header block bh into the directory dir
 * caller must hold AFFS_DIR->i_hash_lock!
 */

int
affs_insert_hash(struct inode *dir, struct buffer_head *bh)
{
	struct super_block *sb = dir->i_sb;
	struct buffer_head *dir_bh;
	u32 ino, hash_ino;
	int offset;

	ino = bh->b_blocknr;
	offset = affs_hash_name(sb, AFFS_TAIL(sb, bh)->name + 1, AFFS_TAIL(sb, bh)->name[0]);

	pr_debug("%s(dir=%u, ino=%d)\n", __func__, (u32)dir->i_ino, ino);

	dir_bh = affs_bread(sb, dir->i_ino);
	if (!dir_bh)
		return -EIO;

	hash_ino = be32_to_cpu(AFFS_HEAD(dir_bh)->table[offset]);
	while (hash_ino) {
		affs_brelse(dir_bh);
		dir_bh = affs_bread(sb, hash_ino);
		if (!dir_bh)
			return -EIO;
		hash_ino = be32_to_cpu(AFFS_TAIL(sb, dir_bh)->hash_chain);
	}
	AFFS_TAIL(sb, bh)->parent = cpu_to_be32(dir->i_ino);
	AFFS_TAIL(sb, bh)->hash_chain = 0;
	affs_fix_checksum(sb, bh);

	if (dir->i_ino == dir_bh->b_blocknr)
		AFFS_HEAD(dir_bh)->table[offset] = cpu_to_be32(ino);
	else
		AFFS_TAIL(sb, dir_bh)->hash_chain = cpu_to_be32(ino);

	affs_adjust_checksum(dir_bh, ino);
	mark_buffer_dirty_inode(dir_bh, dir);
	affs_brelse(dir_bh);

	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	dir->i_version++;
	mark_inode_dirty(dir);

	return 0;
}

/* Remove a header block from its directory.
 * caller must hold AFFS_DIR->i_hash_lock!
 */

int
affs_remove_hash(struct inode *dir, struct buffer_head *rem_bh)
{
	struct super_block *sb;
	struct buffer_head *bh;
	u32 rem_ino, hash_ino;
	__be32 ino;
	int offset, retval;

	sb = dir->i_sb;
	rem_ino = rem_bh->b_blocknr;
	offset = affs_hash_name(sb, AFFS_TAIL(sb, rem_bh)->name+1, AFFS_TAIL(sb, rem_bh)->name[0]);
	pr_debug("%s(dir=%d, ino=%d, hashval=%d)\n",
		 __func__, (u32)dir->i_ino, rem_ino, offset);

	bh = affs_bread(sb, dir->i_ino);
	if (!bh)
		return -EIO;

	retval = -ENOENT;
	hash_ino = be32_to_cpu(AFFS_HEAD(bh)->table[offset]);
	while (hash_ino) {
		if (hash_ino == rem_ino) {
			ino = AFFS_TAIL(sb, rem_bh)->hash_chain;
			if (dir->i_ino == bh->b_blocknr)
				AFFS_HEAD(bh)->table[offset] = ino;
			else
				AFFS_TAIL(sb, bh)->hash_chain = ino;
			affs_adjust_checksum(bh, be32_to_cpu(ino) - hash_ino);
			mark_buffer_dirty_inode(bh, dir);
			AFFS_TAIL(sb, rem_bh)->parent = 0;
			retval = 0;
			break;
		}
		affs_brelse(bh);
		bh = affs_bread(sb, hash_ino);
		if (!bh)
			return -EIO;
		hash_ino = be32_to_cpu(AFFS_TAIL(sb, bh)->hash_chain);
	}

	affs_brelse(bh);

	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	dir->i_version++;
	mark_inode_dirty(dir);

	return retval;
}

static void
affs_fix_dcache(struct inode *inode, u32 entry_ino)
{
	struct dentry *dentry;
	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		if (entry_ino == (u32)(long)dentry->d_fsdata) {
			dentry->d_fsdata = (void *)inode->i_ino;
			break;
		}
	}
	spin_unlock(&inode->i_lock);
}


/* Remove header from link chain */

static int
affs_remove_link(struct dentry *dentry)
{
	struct inode *dir, *inode = dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh = NULL, *link_bh = NULL;
	u32 link_ino, ino;
	int retval;

	pr_debug("%s(key=%ld)\n", __func__, inode->i_ino);
	retval = -EIO;
	bh = affs_bread(sb, inode->i_ino);
	if (!bh)
		goto done;

	link_ino = (u32)(long)dentry->d_fsdata;
	if (inode->i_ino == link_ino) {
		/* we can't remove the head of the link, as its blocknr is still used as ino,
		 * so we remove the block of the first link instead.
		 */
		link_ino = be32_to_cpu(AFFS_TAIL(sb, bh)->link_chain);
		link_bh = affs_bread(sb, link_ino);
		if (!link_bh)
			goto done;

		dir = affs_iget(sb, be32_to_cpu(AFFS_TAIL(sb, link_bh)->parent));
		if (IS_ERR(dir)) {
			retval = PTR_ERR(dir);
			goto done;
		}

		affs_lock_dir(dir);
		/*
		 * if there's a dentry for that block, make it
		 * refer to inode itself.
		 */
		affs_fix_dcache(inode, link_ino);
		retval = affs_remove_hash(dir, link_bh);
		if (retval) {
			affs_unlock_dir(dir);
			goto done;
		}
		mark_buffer_dirty_inode(link_bh, inode);

		memcpy(AFFS_TAIL(sb, bh)->name, AFFS_TAIL(sb, link_bh)->name, 32);
		retval = affs_insert_hash(dir, bh);
		if (retval) {
			affs_unlock_dir(dir);
			goto done;
		}
		mark_buffer_dirty_inode(bh, inode);

		affs_unlock_dir(dir);
		iput(dir);
	} else {
		link_bh = affs_bread(sb, link_ino);
		if (!link_bh)
			goto done;
	}

	while ((ino = be32_to_cpu(AFFS_TAIL(sb, bh)->link_chain)) != 0) {
		if (ino == link_ino) {
			__be32 ino2 = AFFS_TAIL(sb, link_bh)->link_chain;
			AFFS_TAIL(sb, bh)->link_chain = ino2;
			affs_adjust_checksum(bh, be32_to_cpu(ino2) - link_ino);
			mark_buffer_dirty_inode(bh, inode);
			retval = 0;
			/* Fix the link count, if bh is a normal header block without links */
			switch (be32_to_cpu(AFFS_TAIL(sb, bh)->stype)) {
			case ST_LINKDIR:
			case ST_LINKFILE:
				break;
			default:
				if (!AFFS_TAIL(sb, bh)->link_chain)
					set_nlink(inode, 1);
			}
			affs_free_block(sb, link_ino);
			goto done;
		}
		affs_brelse(bh);
		bh = affs_bread(sb, ino);
		if (!bh)
			goto done;
	}
	retval = -ENOENT;
done:
	affs_brelse(link_bh);
	affs_brelse(bh);
	return retval;
}


static int
affs_empty_dir(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh;
	int retval, size;

	retval = -EIO;
	bh = affs_bread(sb, inode->i_ino);
	if (!bh)
		goto done;

	retval = -ENOTEMPTY;
	for (size = AFFS_SB(sb)->s_hashsize - 1; size >= 0; size--)
		if (AFFS_HEAD(bh)->table[size])
			goto not_empty;
	retval = 0;
not_empty:
	affs_brelse(bh);
done:
	return retval;
}


/* Remove a filesystem object. If the object to be removed has
 * links to it, one of the links must be changed to inherit
 * the file or directory. As above, any inode will do.
 * The buffer will not be freed. If the header is a link, the
 * block will be marked as free.
 * This function returns a negative error number in case of
 * an error, else 0 if the inode is to be deleted or 1 if not.
 */

int
affs_remove_header(struct dentry *dentry)
{
	struct super_block *sb;
	struct inode *inode, *dir;
	struct buffer_head *bh = NULL;
	int retval;

	dir = dentry->d_parent->d_inode;
	sb = dir->i_sb;

	retval = -ENOENT;
	inode = dentry->d_inode;
	if (!inode)
		goto done;

	pr_debug("%s(key=%ld)\n", __func__, inode->i_ino);
	retval = -EIO;
	bh = affs_bread(sb, (u32)(long)dentry->d_fsdata);
	if (!bh)
		goto done;

	affs_lock_link(inode);
	affs_lock_dir(dir);
	switch (be32_to_cpu(AFFS_TAIL(sb, bh)->stype)) {
	case ST_USERDIR:
		/* if we ever want to support links to dirs
		 * i_hash_lock of the inode must only be
		 * taken after some checks
		 */
		affs_lock_dir(inode);
		retval = affs_empty_dir(inode);
		affs_unlock_dir(inode);
		if (retval)
			goto done_unlock;
		break;
	default:
		break;
	}

	retval = affs_remove_hash(dir, bh);
	if (retval)
		goto done_unlock;
	mark_buffer_dirty_inode(bh, inode);

	affs_unlock_dir(dir);

	if (inode->i_nlink > 1)
		retval = affs_remove_link(dentry);
	else
		clear_nlink(inode);
	affs_unlock_link(inode);
	inode->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);

done:
	affs_brelse(bh);
	return retval;

done_unlock:
	affs_unlock_dir(dir);
	affs_unlock_link(inode);
	goto done;
}

/* Checksum a block, do various consistency checks and optionally return
   the blocks type number.  DATA points to the block.  If their pointers
   are non-null, *PTYPE and *STYPE are set to the primary and secondary
   block types respectively, *HASHSIZE is set to the size of the hashtable
   (which lets us calculate the block size).
   Returns non-zero if the block is not consistent. */

u32
affs_checksum_block(struct super_block *sb, struct buffer_head *bh)
{
	__be32 *ptr = (__be32 *)bh->b_data;
	u32 sum;
	int bsize;

	sum = 0;
	for (bsize = sb->s_blocksize / sizeof(__be32); bsize > 0; bsize--)
		sum += be32_to_cpu(*ptr++);
	return sum;
}

/*
 * Calculate the checksum of a disk block and store it
 * at the indicated position.
 */

void
affs_fix_checksum(struct super_block *sb, struct buffer_head *bh)
{
	int cnt = sb->s_blocksize / sizeof(__be32);
	__be32 *ptr = (__be32 *)bh->b_data;
	u32 checksum;
	__be32 *checksumptr;

	checksumptr = ptr + 5;
	*checksumptr = 0;
	for (checksum = 0; cnt > 0; ptr++, cnt--)
		checksum += be32_to_cpu(*ptr);
	*checksumptr = cpu_to_be32(-checksum);
}

void
secs_to_datestamp(time_t secs, struct affs_date *ds)
{
	u32	 days;
	u32	 minute;

	secs -= sys_tz.tz_minuteswest * 60 + ((8 * 365 + 2) * 24 * 60 * 60);
	if (secs < 0)
		secs = 0;
	days    = secs / 86400;
	secs   -= days * 86400;
	minute  = secs / 60;
	secs   -= minute * 60;

	ds->days = cpu_to_be32(days);
	ds->mins = cpu_to_be32(minute);
	ds->ticks = cpu_to_be32(secs * 50);
}

umode_t
prot_to_mode(u32 prot)
{
	umode_t mode = 0;

	if (!(prot & FIBF_NOWRITE))
		mode |= S_IWUSR;
	if (!(prot & FIBF_NOREAD))
		mode |= S_IRUSR;
	if (!(prot & FIBF_NOEXECUTE))
		mode |= S_IXUSR;
	if (prot & FIBF_GRP_WRITE)
		mode |= S_IWGRP;
	if (prot & FIBF_GRP_READ)
		mode |= S_IRGRP;
	if (prot & FIBF_GRP_EXECUTE)
		mode |= S_IXGRP;
	if (prot & FIBF_OTR_WRITE)
		mode |= S_IWOTH;
	if (prot & FIBF_OTR_READ)
		mode |= S_IROTH;
	if (prot & FIBF_OTR_EXECUTE)
		mode |= S_IXOTH;

	return mode;
}

void
mode_to_prot(struct inode *inode)
{
	u32 prot = AFFS_I(inode)->i_protect;
	umode_t mode = inode->i_mode;

	if (!(mode & S_IXUSR))
		prot |= FIBF_NOEXECUTE;
	if (!(mode & S_IRUSR))
		prot |= FIBF_NOREAD;
	if (!(mode & S_IWUSR))
		prot |= FIBF_NOWRITE;
	if (mode & S_IXGRP)
		prot |= FIBF_GRP_EXECUTE;
	if (mode & S_IRGRP)
		prot |= FIBF_GRP_READ;
	if (mode & S_IWGRP)
		prot |= FIBF_GRP_WRITE;
	if (mode & S_IXOTH)
		prot |= FIBF_OTR_EXECUTE;
	if (mode & S_IROTH)
		prot |= FIBF_OTR_READ;
	if (mode & S_IWOTH)
		prot |= FIBF_OTR_WRITE;

	AFFS_I(inode)->i_protect = prot;
}

void
affs_error(struct super_block *sb, const char *function, const char *fmt, ...)
{
	va_list	 args;

	va_start(args,fmt);
	vsnprintf(ErrorBuffer,sizeof(ErrorBuffer),fmt,args);
	va_end(args);

	pr_crit("error (device %s): %s(): %s\n", sb->s_id,
		function,ErrorBuffer);
	if (!(sb->s_flags & MS_RDONLY))
		pr_warn("Remounting filesystem read-only\n");
	sb->s_flags |= MS_RDONLY;
}

void
affs_warning(struct super_block *sb, const char *function, const char *fmt, ...)
{
	va_list	 args;

	va_start(args,fmt);
	vsnprintf(ErrorBuffer,sizeof(ErrorBuffer),fmt,args);
	va_end(args);

	pr_warn("(device %s): %s(): %s\n", sb->s_id,
		function,ErrorBuffer);
}

bool
affs_nofilenametruncate(const struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	return AFFS_SB(inode->i_sb)->s_flags & SF_NO_TRUNCATE;

}

/* Check if the name is valid for a affs object. */

int
affs_check_name(const unsigned char *name, int len, bool notruncate)
{
	int	 i;

	if (len > 30) {
		if (notruncate)
			return -ENAMETOOLONG;
		else
			len = 30;
	}
	for (i = 0; i < len; i++) {
		if (name[i] < ' ' || name[i] == ':'
		    || (name[i] > 0x7e && name[i] < 0xa0))
			return -EINVAL;
	}

	return 0;
}

/* This function copies name to bstr, with at most 30
 * characters length. The bstr will be prepended by
 * a length byte.
 * NOTE: The name will must be already checked by
 *       affs_check_name()!
 */

int
affs_copy_name(unsigned char *bstr, struct dentry *dentry)
{
	int len = min(dentry->d_name.len, 30u);

	*bstr++ = len;
	memcpy(bstr, dentry->d_name.name, len);
	return len;
}
/************************************************************/
/* ../linux-3.17/fs/affs/amigaffs.c */
/************************************************************/
/*
 *  linux/fs/affs/bitmap.c
 *
 *  (c) 1996 Hans-Joachim Widmaier
 *
 *  bitmap.c contains the code that handles all bitmap related stuff -
 *  block allocation, deallocation, calculation of free space.
 */

// #include <linux/slab.h>
// #include "affs.h"

u32
affs_count_free_blocks(struct super_block *sb)
{
	struct affs_bm_info *bm;
	u32 free;
	int i;

	pr_debug("%s()\n", __func__);

	if (sb->s_flags & MS_RDONLY)
		return 0;

	mutex_lock(&AFFS_SB(sb)->s_bmlock);

	bm = AFFS_SB(sb)->s_bitmap;
	free = 0;
	for (i = AFFS_SB(sb)->s_bmap_count; i > 0; bm++, i--)
		free += bm->bm_free;

	mutex_unlock(&AFFS_SB(sb)->s_bmlock);

	return free;
}

void
affs_free_block(struct super_block *sb, u32 block)
{
	struct affs_sb_info *sbi = AFFS_SB(sb);
	struct affs_bm_info *bm;
	struct buffer_head *bh;
	u32 blk, bmap, bit, mask, tmp;
	__be32 *data;

	pr_debug("%s(%u)\n", __func__, block);

	if (block > sbi->s_partition_size)
		goto err_range;

	blk     = block - sbi->s_reserved;
	bmap    = blk / sbi->s_bmap_bits;
	bit     = blk % sbi->s_bmap_bits;
	bm      = &sbi->s_bitmap[bmap];

	mutex_lock(&sbi->s_bmlock);

	bh = sbi->s_bmap_bh;
	if (sbi->s_last_bmap != bmap) {
		affs_brelse(bh);
		bh = affs_bread(sb, bm->bm_key);
		if (!bh)
			goto err_bh_read;
		sbi->s_bmap_bh = bh;
		sbi->s_last_bmap = bmap;
	}

	mask = 1 << (bit & 31);
	data = (__be32 *)bh->b_data + bit / 32 + 1;

	/* mark block free */
	tmp = be32_to_cpu(*data);
	if (tmp & mask)
		goto err_free;
	*data = cpu_to_be32(tmp | mask);

	/* fix checksum */
	tmp = be32_to_cpu(*(__be32 *)bh->b_data);
	*(__be32 *)bh->b_data = cpu_to_be32(tmp - mask);

	mark_buffer_dirty(bh);
	affs_mark_sb_dirty(sb);
	bm->bm_free++;

	mutex_unlock(&sbi->s_bmlock);
	return;

err_free:
	affs_warning(sb,"affs_free_block","Trying to free block %u which is already free", block);
	mutex_unlock(&sbi->s_bmlock);
	return;

err_bh_read:
	affs_error(sb,"affs_free_block","Cannot read bitmap block %u", bm->bm_key);
	sbi->s_bmap_bh = NULL;
	sbi->s_last_bmap = ~0;
	mutex_unlock(&sbi->s_bmlock);
	return;

err_range:
	affs_error(sb, "affs_free_block","Block %u outside partition", block);
	return;
}

/*
 * Allocate a block in the given allocation zone.
 * Since we have to byte-swap the bitmap on little-endian
 * machines, this is rather expensive. Therefore we will
 * preallocate up to 16 blocks from the same word, if
 * possible. We are not doing preallocations in the
 * header zone, though.
 */

u32
affs_alloc_block(struct inode *inode, u32 goal)
{
	struct super_block *sb;
	struct affs_sb_info *sbi;
	struct affs_bm_info *bm;
	struct buffer_head *bh;
	__be32 *data, *enddata;
	u32 blk, bmap, bit, mask, mask2, tmp;
	int i;

	sb = inode->i_sb;
	sbi = AFFS_SB(sb);

	pr_debug("balloc(inode=%lu,goal=%u): ", inode->i_ino, goal);

	if (AFFS_I(inode)->i_pa_cnt) {
		pr_debug("%d\n", AFFS_I(inode)->i_lastalloc+1);
		AFFS_I(inode)->i_pa_cnt--;
		return ++AFFS_I(inode)->i_lastalloc;
	}

	if (!goal || goal > sbi->s_partition_size) {
		if (goal)
			affs_warning(sb, "affs_balloc", "invalid goal %d", goal);
		//if (!AFFS_I(inode)->i_last_block)
		//	affs_warning(sb, "affs_balloc", "no last alloc block");
		goal = sbi->s_reserved;
	}

	blk = goal - sbi->s_reserved;
	bmap = blk / sbi->s_bmap_bits;
	bm = &sbi->s_bitmap[bmap];

	mutex_lock(&sbi->s_bmlock);

	if (bm->bm_free)
		goto find_bmap_bit;

find_bmap:
	/* search for the next bmap buffer with free bits */
	i = sbi->s_bmap_count;
	do {
		if (--i < 0)
			goto err_full;
		bmap++;
		bm++;
		if (bmap < sbi->s_bmap_count)
			continue;
		/* restart search at zero */
		bmap = 0;
		bm = sbi->s_bitmap;
	} while (!bm->bm_free);
	blk = bmap * sbi->s_bmap_bits;

find_bmap_bit:

	bh = sbi->s_bmap_bh;
	if (sbi->s_last_bmap != bmap) {
		affs_brelse(bh);
		bh = affs_bread(sb, bm->bm_key);
		if (!bh)
			goto err_bh_read;
		sbi->s_bmap_bh = bh;
		sbi->s_last_bmap = bmap;
	}

	/* find an unused block in this bitmap block */
	bit = blk % sbi->s_bmap_bits;
	data = (__be32 *)bh->b_data + bit / 32 + 1;
	enddata = (__be32 *)((u8 *)bh->b_data + sb->s_blocksize);
	mask = ~0UL << (bit & 31);
	blk &= ~31UL;

	tmp = be32_to_cpu(*data);
	if (tmp & mask)
		goto find_bit;

	/* scan the rest of the buffer */
	do {
		blk += 32;
		if (++data >= enddata)
			/* didn't find something, can only happen
			 * if scan didn't start at 0, try next bmap
			 */
			goto find_bmap;
	} while (!*data);
	tmp = be32_to_cpu(*data);
	mask = ~0;

find_bit:
	/* finally look for a free bit in the word */
	bit = ffs(tmp & mask) - 1;
	blk += bit + sbi->s_reserved;
	mask2 = mask = 1 << (bit & 31);
	AFFS_I(inode)->i_lastalloc = blk;

	/* prealloc as much as possible within this word */
	while ((mask2 <<= 1)) {
		if (!(tmp & mask2))
			break;
		AFFS_I(inode)->i_pa_cnt++;
		mask |= mask2;
	}
	bm->bm_free -= AFFS_I(inode)->i_pa_cnt + 1;

	*data = cpu_to_be32(tmp & ~mask);

	/* fix checksum */
	tmp = be32_to_cpu(*(__be32 *)bh->b_data);
	*(__be32 *)bh->b_data = cpu_to_be32(tmp + mask);

	mark_buffer_dirty(bh);
	affs_mark_sb_dirty(sb);

	mutex_unlock(&sbi->s_bmlock);

	pr_debug("%d\n", blk);
	return blk;

err_bh_read:
	affs_error(sb,"affs_read_block","Cannot read bitmap block %u", bm->bm_key);
	sbi->s_bmap_bh = NULL;
	sbi->s_last_bmap = ~0;
err_full:
	mutex_unlock(&sbi->s_bmlock);
	pr_debug("failed\n");
	return 0;
}

int affs_init_bitmap(struct super_block *sb, int *flags)
{
	struct affs_bm_info *bm;
	struct buffer_head *bmap_bh = NULL, *bh = NULL;
	__be32 *bmap_blk;
	u32 size, blk, end, offset, mask;
	int i, res = 0;
	struct affs_sb_info *sbi = AFFS_SB(sb);

	if (*flags & MS_RDONLY)
		return 0;

	if (!AFFS_ROOT_TAIL(sb, sbi->s_root_bh)->bm_flag) {
		pr_notice("Bitmap invalid - mounting %s read only\n", sb->s_id);
		*flags |= MS_RDONLY;
		return 0;
	}

	sbi->s_last_bmap = ~0;
	sbi->s_bmap_bh = NULL;
	sbi->s_bmap_bits = sb->s_blocksize * 8 - 32;
	sbi->s_bmap_count = (sbi->s_partition_size - sbi->s_reserved +
				 sbi->s_bmap_bits - 1) / sbi->s_bmap_bits;
	size = sbi->s_bmap_count * sizeof(*bm);
	bm = sbi->s_bitmap = kzalloc(size, GFP_KERNEL);
	if (!sbi->s_bitmap) {
		pr_err("Bitmap allocation failed\n");
		return -ENOMEM;
	}

	bmap_blk = (__be32 *)sbi->s_root_bh->b_data;
	blk = sb->s_blocksize / 4 - 49;
	end = blk + 25;

	for (i = sbi->s_bmap_count; i > 0; bm++, i--) {
		affs_brelse(bh);

		bm->bm_key = be32_to_cpu(bmap_blk[blk]);
		bh = affs_bread(sb, bm->bm_key);
		if (!bh) {
			pr_err("Cannot read bitmap\n");
			res = -EIO;
			goto out;
		}
		if (affs_checksum_block(sb, bh)) {
			pr_warn("Bitmap %u invalid - mounting %s read only.\n",
				bm->bm_key, sb->s_id);
			*flags |= MS_RDONLY;
			goto out;
		}
		pr_debug("read bitmap block %d: %d\n", blk, bm->bm_key);
		bm->bm_free = memweight(bh->b_data + 4, sb->s_blocksize - 4);

		/* Don't try read the extension if this is the last block,
		 * but we also need the right bm pointer below
		 */
		if (++blk < end || i == 1)
			continue;
		if (bmap_bh)
			affs_brelse(bmap_bh);
		bmap_bh = affs_bread(sb, be32_to_cpu(bmap_blk[blk]));
		if (!bmap_bh) {
			pr_err("Cannot read bitmap extension\n");
			res = -EIO;
			goto out;
		}
		bmap_blk = (__be32 *)bmap_bh->b_data;
		blk = 0;
		end = sb->s_blocksize / 4 - 1;
	}

	offset = (sbi->s_partition_size - sbi->s_reserved) % sbi->s_bmap_bits;
	mask = ~(0xFFFFFFFFU << (offset & 31));
	pr_debug("last word: %d %d %d\n", offset, offset / 32 + 1, mask);
	offset = offset / 32 + 1;

	if (mask) {
		u32 old, new;

		/* Mark unused bits in the last word as allocated */
		old = be32_to_cpu(((__be32 *)bh->b_data)[offset]);
		new = old & mask;
		//if (old != new) {
			((__be32 *)bh->b_data)[offset] = cpu_to_be32(new);
			/* fix checksum */
			//new -= old;
			//old = be32_to_cpu(*(__be32 *)bh->b_data);
			//*(__be32 *)bh->b_data = cpu_to_be32(old - new);
			//mark_buffer_dirty(bh);
		//}
		/* correct offset for the bitmap count below */
		//offset++;
	}
	while (++offset < sb->s_blocksize / 4)
		((__be32 *)bh->b_data)[offset] = 0;
	((__be32 *)bh->b_data)[0] = 0;
	((__be32 *)bh->b_data)[0] = cpu_to_be32(-affs_checksum_block(sb, bh));
	mark_buffer_dirty(bh);

	/* recalculate bitmap count for last block */
	bm--;
	bm->bm_free = memweight(bh->b_data + 4, sb->s_blocksize - 4);

out:
	affs_brelse(bh);
	affs_brelse(bmap_bh);
	return res;
}

void affs_free_bitmap(struct super_block *sb)
{
	struct affs_sb_info *sbi = AFFS_SB(sb);

	if (!sbi->s_bitmap)
		return;

	affs_brelse(sbi->s_bmap_bh);
	sbi->s_bmap_bh = NULL;
	sbi->s_last_bmap = ~0;
	kfree(sbi->s_bitmap);
	sbi->s_bitmap = NULL;
}
/************************************************************/
/* ../linux-3.17/fs/affs/bitmap.c */
/************************************************************/
/*
 *  linux/fs/affs/symlink.c
 *
 *  1995  Hans-Joachim Widmaier - Modified for affs.
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  affs symlink handling code
 */

// #include "affs.h"

static int affs_symlink_readpage(struct file *file, struct page *page)
{
	struct buffer_head *bh;
	struct inode *inode = page->mapping->host;
	char *link = kmap(page);
	struct slink_front *lf;
	int err;
	int			 i, j;
	char			 c;
	char			 lc;

	pr_debug("follow_link(ino=%lu)\n", inode->i_ino);

	err = -EIO;
	bh = affs_bread(inode->i_sb, inode->i_ino);
	if (!bh)
		goto fail;
	i  = 0;
	j  = 0;
	lf = (struct slink_front *)bh->b_data;
	lc = 0;

	if (strchr(lf->symname,':')) {	/* Handle assign or volume name */
		struct affs_sb_info *sbi = AFFS_SB(inode->i_sb);
		char *pf;
		spin_lock(&sbi->symlink_lock);
		pf = sbi->s_prefix ? sbi->s_prefix : "/";
		while (i < 1023 && (c = pf[i]))
			link[i++] = c;
		spin_unlock(&sbi->symlink_lock);
		while (i < 1023 && lf->symname[j] != ':')
			link[i++] = lf->symname[j++];
		if (i < 1023)
			link[i++] = '/';
		j++;
		lc = '/';
	}
	while (i < 1023 && (c = lf->symname[j])) {
		if (c == '/' && lc == '/' && i < 1020) {	/* parent dir */
			link[i++] = '.';
			link[i++] = '.';
		}
		link[i++] = c;
		lc = c;
		j++;
	}
	link[i] = '\0';
	affs_brelse(bh);
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;
fail:
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	return err;
}

const struct address_space_operations affs_symlink_aops = {
	.readpage	= affs_symlink_readpage,
};

const struct inode_operations affs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= affs_notify_change,
};
/************************************************************/
/* ../linux-3.17/fs/affs/symlink.c */
/************************************************************/
