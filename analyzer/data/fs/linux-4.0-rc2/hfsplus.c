/*
 *  linux/fs/hfsplus/super.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/vfs.h>
#include <linux/nls.h>
#include "../../inc/__fss.h"

static struct inode *hfsplus_alloc_inode(struct super_block *sb);
static void hfsplus_destroy_inode(struct inode *inode);

#include "hfsplus_fs.h"
#include "xattr.h"
#include "../../inc/__fss.h"

static int hfsplus_system_read_inode(struct inode *inode)
{
	struct hfsplus_vh *vhdr = HFSPLUS_SB(inode->i_sb)->s_vhdr;

	switch (inode->i_ino) {
	case HFSPLUS_EXT_CNID:
		hfsplus_inode_read_fork(inode, &vhdr->ext_file);
		inode->i_mapping->a_ops = &hfsplus_btree_aops;
		break;
	case HFSPLUS_CAT_CNID:
		hfsplus_inode_read_fork(inode, &vhdr->cat_file);
		inode->i_mapping->a_ops = &hfsplus_btree_aops;
		break;
	case HFSPLUS_ALLOC_CNID:
		hfsplus_inode_read_fork(inode, &vhdr->alloc_file);
		inode->i_mapping->a_ops = &hfsplus_aops;
		break;
	case HFSPLUS_START_CNID:
		hfsplus_inode_read_fork(inode, &vhdr->start_file);
		break;
	case HFSPLUS_ATTR_CNID:
		hfsplus_inode_read_fork(inode, &vhdr->attr_file);
		inode->i_mapping->a_ops = &hfsplus_btree_aops;
		break;
	default:
		return -EIO;
	}

	return 0;
}

struct inode *hfsplus_iget(struct super_block *sb, unsigned long ino)
{
	struct hfs_find_data fd;
	struct inode *inode;
	int err;

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	INIT_LIST_HEAD(&HFSPLUS_I(inode)->open_dir_list);
	mutex_init(&HFSPLUS_I(inode)->extents_lock);
	HFSPLUS_I(inode)->flags = 0;
	HFSPLUS_I(inode)->extent_state = 0;
	HFSPLUS_I(inode)->rsrc_inode = NULL;
	atomic_set(&HFSPLUS_I(inode)->opencnt, 0);

	if (inode->i_ino >= HFSPLUS_FIRSTUSER_CNID ||
	    inode->i_ino == HFSPLUS_ROOT_CNID) {
		err = hfs_find_init(HFSPLUS_SB(inode->i_sb)->cat_tree, &fd);
		if (!err) {
			err = hfsplus_find_cat(inode->i_sb, inode->i_ino, &fd);
			if (!err)
				err = hfsplus_cat_read_inode(inode, &fd);
			hfs_find_exit(&fd);
		}
	} else {
		err = hfsplus_system_read_inode(inode);
	}

	if (err) {
		iget_failed(inode);
		return ERR_PTR(err);
	}

	unlock_new_inode(inode);
	return inode;
}

static int hfsplus_system_write_inode(struct inode *inode)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(inode->i_sb);
	struct hfsplus_vh *vhdr = sbi->s_vhdr;
	struct hfsplus_fork_raw *fork;
	struct hfs_btree *tree = NULL;

	switch (inode->i_ino) {
	case HFSPLUS_EXT_CNID:
		fork = &vhdr->ext_file;
		tree = sbi->ext_tree;
		break;
	case HFSPLUS_CAT_CNID:
		fork = &vhdr->cat_file;
		tree = sbi->cat_tree;
		break;
	case HFSPLUS_ALLOC_CNID:
		fork = &vhdr->alloc_file;
		break;
	case HFSPLUS_START_CNID:
		fork = &vhdr->start_file;
		break;
	case HFSPLUS_ATTR_CNID:
		fork = &vhdr->attr_file;
		tree = sbi->attr_tree;
		break;
	default:
		return -EIO;
	}

	if (fork->total_size != cpu_to_be64(inode->i_size)) {
		set_bit(HFSPLUS_SB_WRITEBACKUP, &sbi->flags);
		hfsplus_mark_mdb_dirty(inode->i_sb);
	}
	hfsplus_inode_write_fork(inode, fork);
	if (tree) {
		int err = hfs_btree_write(tree);

		if (err) {
			pr_err("b-tree write err: %d, ino %lu\n",
			       err, inode->i_ino);
			return err;
		}
	}
	return 0;
}

static int hfsplus_write_inode(struct inode *inode,
		struct writeback_control *wbc)
{
	int err;

	hfs_dbg(INODE, "hfsplus_write_inode: %lu\n", inode->i_ino);

	err = hfsplus_ext_write_extent(inode);
	if (err)
		return err;

	if (inode->i_ino >= HFSPLUS_FIRSTUSER_CNID ||
	    inode->i_ino == HFSPLUS_ROOT_CNID)
		return hfsplus_cat_write_inode(inode);
	else
		return hfsplus_system_write_inode(inode);
}

static void hfsplus_evict_inode(struct inode *inode)
{
	hfs_dbg(INODE, "hfsplus_evict_inode: %lu\n", inode->i_ino);
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	if (HFSPLUS_IS_RSRC(inode)) {
		HFSPLUS_I(HFSPLUS_I(inode)->rsrc_inode)->rsrc_inode = NULL;
		iput(HFSPLUS_I(inode)->rsrc_inode);
	}
}

static int hfsplus_sync_fs(struct super_block *sb, int wait)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct hfsplus_vh *vhdr = sbi->s_vhdr;
	int write_backup = 0;
	int error, error2;

	if (!wait)
		return 0;

	hfs_dbg(SUPER, "hfsplus_sync_fs\n");

	/*
	 * Explicitly write out the special metadata inodes.
	 *
	 * While these special inodes are marked as hashed and written
	 * out peridocically by the flusher threads we redirty them
	 * during writeout of normal inodes, and thus the life lock
	 * prevents us from getting the latest state to disk.
	 */
	error = filemap_write_and_wait(sbi->cat_tree->inode->i_mapping);
	error2 = filemap_write_and_wait(sbi->ext_tree->inode->i_mapping);
	if (!error)
		error = error2;
	if (sbi->attr_tree) {
		error2 =
		    filemap_write_and_wait(sbi->attr_tree->inode->i_mapping);
		if (!error)
			error = error2;
	}
	error2 = filemap_write_and_wait(sbi->alloc_file->i_mapping);
	if (!error)
		error = error2;

	mutex_lock(&sbi->vh_mutex);
	mutex_lock(&sbi->alloc_mutex);
	vhdr->free_blocks = cpu_to_be32(sbi->free_blocks);
	vhdr->next_cnid = cpu_to_be32(sbi->next_cnid);
	vhdr->folder_count = cpu_to_be32(sbi->folder_count);
	vhdr->file_count = cpu_to_be32(sbi->file_count);

	if (test_and_clear_bit(HFSPLUS_SB_WRITEBACKUP, &sbi->flags)) {
		memcpy(sbi->s_backup_vhdr, sbi->s_vhdr, sizeof(*sbi->s_vhdr));
		write_backup = 1;
	}

	error2 = hfsplus_submit_bio(sb,
				   sbi->part_start + HFSPLUS_VOLHEAD_SECTOR,
				   sbi->s_vhdr_buf, NULL, WRITE_SYNC);
	if (!error)
		error = error2;
	if (!write_backup)
		goto out;

	error2 = hfsplus_submit_bio(sb,
				  sbi->part_start + sbi->sect_count - 2,
				  sbi->s_backup_vhdr_buf, NULL, WRITE_SYNC);
	if (!error)
		error2 = error;
out:
	mutex_unlock(&sbi->alloc_mutex);
	mutex_unlock(&sbi->vh_mutex);

	if (!test_bit(HFSPLUS_SB_NOBARRIER, &sbi->flags))
		blkdev_issue_flush(sb->s_bdev, GFP_KERNEL, NULL);

	return error;
}

static void delayed_sync_fs(struct work_struct *work)
{
	int err;
	struct hfsplus_sb_info *sbi;

	sbi = container_of(work, struct hfsplus_sb_info, sync_work.work);

	spin_lock(&sbi->work_lock);
	sbi->work_queued = 0;
	spin_unlock(&sbi->work_lock);

	err = hfsplus_sync_fs(sbi->alloc_file->i_sb, 1);
	if (err)
		pr_err("delayed sync fs err %d\n", err);
}

void hfsplus_mark_mdb_dirty(struct super_block *sb)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	unsigned long delay;

	if (sb->s_flags & MS_RDONLY)
		return;

	spin_lock(&sbi->work_lock);
	if (!sbi->work_queued) {
		delay = msecs_to_jiffies(dirty_writeback_interval * 10);
		queue_delayed_work(system_long_wq, &sbi->sync_work, delay);
		sbi->work_queued = 1;
	}
	spin_unlock(&sbi->work_lock);
}

static void hfsplus_put_super(struct super_block *sb)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);

	hfs_dbg(SUPER, "hfsplus_put_super\n");

	cancel_delayed_work_sync(&sbi->sync_work);

	if (!(sb->s_flags & MS_RDONLY) && sbi->s_vhdr) {
		struct hfsplus_vh *vhdr = sbi->s_vhdr;

		vhdr->modify_date = hfsp_now2mt();
		vhdr->attributes |= cpu_to_be32(HFSPLUS_VOL_UNMNT);
		vhdr->attributes &= cpu_to_be32(~HFSPLUS_VOL_INCNSTNT);

		hfsplus_sync_fs(sb, 1);
	}

	hfs_btree_close(sbi->attr_tree);
	hfs_btree_close(sbi->cat_tree);
	hfs_btree_close(sbi->ext_tree);
	iput(sbi->alloc_file);
	iput(sbi->hidden_dir);
	kfree(sbi->s_vhdr_buf);
	kfree(sbi->s_backup_vhdr_buf);
	unload_nls(sbi->nls);
	kfree(sb->s_fs_info);
	sb->s_fs_info = NULL;
}

static int hfsplus_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	buf->f_type = HFSPLUS_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;
	buf->f_blocks = sbi->total_blocks << sbi->fs_shift;
	buf->f_bfree = sbi->free_blocks << sbi->fs_shift;
	buf->f_bavail = buf->f_bfree;
	buf->f_files = 0xFFFFFFFF;
	buf->f_ffree = 0xFFFFFFFF - sbi->next_cnid;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = HFSPLUS_MAX_STRLEN;

	return 0;
}

static int hfsplus_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	if ((*flags & MS_RDONLY) == (sb->s_flags & MS_RDONLY))
		return 0;
	if (!(*flags & MS_RDONLY)) {
		struct hfsplus_vh *vhdr = HFSPLUS_SB(sb)->s_vhdr;
		int force = 0;

		if (!hfsplus_parse_options_remount(data, &force))
			return -EINVAL;

		if (!(vhdr->attributes & cpu_to_be32(HFSPLUS_VOL_UNMNT))) {
			pr_warn("filesystem was not cleanly unmounted, running fsck.hfsplus is recommended.  leaving read-only.\n");
			sb->s_flags |= MS_RDONLY;
			*flags |= MS_RDONLY;
		} else if (force) {
			/* nothing */
		} else if (vhdr->attributes &
				cpu_to_be32(HFSPLUS_VOL_SOFTLOCK)) {
			pr_warn("filesystem is marked locked, leaving read-only.\n");
			sb->s_flags |= MS_RDONLY;
			*flags |= MS_RDONLY;
		} else if (vhdr->attributes &
				cpu_to_be32(HFSPLUS_VOL_JOURNALED)) {
			pr_warn("filesystem is marked journaled, leaving read-only.\n");
			sb->s_flags |= MS_RDONLY;
			*flags |= MS_RDONLY;
		}
	}
	return 0;
}

static const struct super_operations hfsplus_sops = {
	.alloc_inode	= hfsplus_alloc_inode,
	.destroy_inode	= hfsplus_destroy_inode,
	.write_inode	= hfsplus_write_inode,
	.evict_inode	= hfsplus_evict_inode,
	.put_super	= hfsplus_put_super,
	.sync_fs	= hfsplus_sync_fs,
	.statfs		= hfsplus_statfs,
	.remount_fs	= hfsplus_remount,
	.show_options	= hfsplus_show_options,
};

static int hfsplus_fill_super(struct super_block *sb, void *data, int silent)
{
	struct hfsplus_vh *vhdr;
	struct hfsplus_sb_info *sbi;
	hfsplus_cat_entry entry;
	struct hfs_find_data fd;
	struct inode *root, *inode;
	struct qstr str;
	struct nls_table *nls = NULL;
	u64 last_fs_block, last_fs_page;
	int err;

	err = -ENOMEM;
	sbi = kzalloc(sizeof(*sbi), GFP_KERNEL);
	if (!sbi)
		goto out;

	sb->s_fs_info = sbi;
	mutex_init(&sbi->alloc_mutex);
	mutex_init(&sbi->vh_mutex);
	spin_lock_init(&sbi->work_lock);
	INIT_DELAYED_WORK(&sbi->sync_work, delayed_sync_fs);
	hfsplus_fill_defaults(sbi);

	err = -EINVAL;
	if (!hfsplus_parse_options(data, sbi)) {
		pr_err("unable to parse mount options\n");
		goto out_unload_nls;
	}

	/* temporarily use utf8 to correctly find the hidden dir below */
	nls = sbi->nls;
	sbi->nls = load_nls("utf8");
	if (!sbi->nls) {
		pr_err("unable to load nls for utf8\n");
		goto out_unload_nls;
	}

	/* Grab the volume header */
	if (hfsplus_read_wrapper(sb)) {
		if (!silent)
			pr_warn("unable to find HFS+ superblock\n");
		goto out_unload_nls;
	}
	vhdr = sbi->s_vhdr;

	/* Copy parts of the volume header into the superblock */
	sb->s_magic = HFSPLUS_VOLHEAD_SIG;
	if (be16_to_cpu(vhdr->version) < HFSPLUS_MIN_VERSION ||
	    be16_to_cpu(vhdr->version) > HFSPLUS_CURRENT_VERSION) {
		pr_err("wrong filesystem version\n");
		goto out_free_vhdr;
	}
	sbi->total_blocks = be32_to_cpu(vhdr->total_blocks);
	sbi->free_blocks = be32_to_cpu(vhdr->free_blocks);
	sbi->next_cnid = be32_to_cpu(vhdr->next_cnid);
	sbi->file_count = be32_to_cpu(vhdr->file_count);
	sbi->folder_count = be32_to_cpu(vhdr->folder_count);
	sbi->data_clump_blocks =
		be32_to_cpu(vhdr->data_clump_sz) >> sbi->alloc_blksz_shift;
	if (!sbi->data_clump_blocks)
		sbi->data_clump_blocks = 1;
	sbi->rsrc_clump_blocks =
		be32_to_cpu(vhdr->rsrc_clump_sz) >> sbi->alloc_blksz_shift;
	if (!sbi->rsrc_clump_blocks)
		sbi->rsrc_clump_blocks = 1;

	err = -EFBIG;
	last_fs_block = sbi->total_blocks - 1;
	last_fs_page = (last_fs_block << sbi->alloc_blksz_shift) >>
			PAGE_CACHE_SHIFT;

	if ((last_fs_block > (sector_t)(~0ULL) >> (sbi->alloc_blksz_shift - 9)) ||
	    (last_fs_page > (pgoff_t)(~0ULL))) {
		pr_err("filesystem size too large\n");
		goto out_free_vhdr;
	}

	/* Set up operations so we can load metadata */
	sb->s_op = &hfsplus_sops;
	sb->s_maxbytes = MAX_LFS_FILESIZE;

	if (!(vhdr->attributes & cpu_to_be32(HFSPLUS_VOL_UNMNT))) {
		pr_warn("Filesystem was not cleanly unmounted, running fsck.hfsplus is recommended.  mounting read-only.\n");
		sb->s_flags |= MS_RDONLY;
	} else if (test_and_clear_bit(HFSPLUS_SB_FORCE, &sbi->flags)) {
		/* nothing */
	} else if (vhdr->attributes & cpu_to_be32(HFSPLUS_VOL_SOFTLOCK)) {
		pr_warn("Filesystem is marked locked, mounting read-only.\n");
		sb->s_flags |= MS_RDONLY;
	} else if ((vhdr->attributes & cpu_to_be32(HFSPLUS_VOL_JOURNALED)) &&
			!(sb->s_flags & MS_RDONLY)) {
		pr_warn("write access to a journaled filesystem is not supported, use the force option at your own risk, mounting read-only.\n");
		sb->s_flags |= MS_RDONLY;
	}

	err = -EINVAL;

	/* Load metadata objects (B*Trees) */
	sbi->ext_tree = hfs_btree_open(sb, HFSPLUS_EXT_CNID);
	if (!sbi->ext_tree) {
		pr_err("failed to load extents file\n");
		goto out_free_vhdr;
	}
	sbi->cat_tree = hfs_btree_open(sb, HFSPLUS_CAT_CNID);
	if (!sbi->cat_tree) {
		pr_err("failed to load catalog file\n");
		goto out_close_ext_tree;
	}
	atomic_set(&sbi->attr_tree_state, HFSPLUS_EMPTY_ATTR_TREE);
	if (vhdr->attr_file.total_blocks != 0) {
		sbi->attr_tree = hfs_btree_open(sb, HFSPLUS_ATTR_CNID);
		if (!sbi->attr_tree) {
			pr_err("failed to load attributes file\n");
			goto out_close_cat_tree;
		}
		atomic_set(&sbi->attr_tree_state, HFSPLUS_VALID_ATTR_TREE);
	}
	sb->s_xattr = hfsplus_xattr_handlers;

	inode = hfsplus_iget(sb, HFSPLUS_ALLOC_CNID);
	if (IS_ERR(inode)) {
		pr_err("failed to load allocation file\n");
		err = PTR_ERR(inode);
		goto out_close_attr_tree;
	}
	sbi->alloc_file = inode;

	/* Load the root directory */
	root = hfsplus_iget(sb, HFSPLUS_ROOT_CNID);
	if (IS_ERR(root)) {
		pr_err("failed to load root directory\n");
		err = PTR_ERR(root);
		goto out_put_alloc_file;
	}

	sb->s_d_op = &hfsplus_dentry_operations;
	sb->s_root = d_make_root(root);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_put_alloc_file;
	}

	str.len = sizeof(HFSP_HIDDENDIR_NAME) - 1;
	str.name = HFSP_HIDDENDIR_NAME;
	err = hfs_find_init(sbi->cat_tree, &fd);
	if (err)
		goto out_put_root;
	err = hfsplus_cat_build_key(sb, fd.search_key, HFSPLUS_ROOT_CNID, &str);
	if (unlikely(err < 0))
		goto out_put_root;
	if (!hfs_brec_read(&fd, &entry, sizeof(entry))) {
		hfs_find_exit(&fd);
		if (entry.type != cpu_to_be16(HFSPLUS_FOLDER))
			goto out_put_root;
		inode = hfsplus_iget(sb, be32_to_cpu(entry.folder.id));
		if (IS_ERR(inode)) {
			err = PTR_ERR(inode);
			goto out_put_root;
		}
		sbi->hidden_dir = inode;
	} else
		hfs_find_exit(&fd);

	if (!(sb->s_flags & MS_RDONLY)) {
		/*
		 * H+LX == hfsplusutils, H+Lx == this driver, H+lx is unused
		 * all three are registered with Apple for our use
		 */
		vhdr->last_mount_vers = cpu_to_be32(HFSP_MOUNT_VERSION);
		vhdr->modify_date = hfsp_now2mt();
		be32_add_cpu(&vhdr->write_count, 1);
		vhdr->attributes &= cpu_to_be32(~HFSPLUS_VOL_UNMNT);
		vhdr->attributes |= cpu_to_be32(HFSPLUS_VOL_INCNSTNT);
		hfsplus_sync_fs(sb, 1);

		if (!sbi->hidden_dir) {
			mutex_lock(&sbi->vh_mutex);
			sbi->hidden_dir = hfsplus_new_inode(sb, S_IFDIR);
			if (!sbi->hidden_dir) {
				mutex_unlock(&sbi->vh_mutex);
				err = -ENOMEM;
				goto out_put_root;
			}
			err = hfsplus_create_cat(sbi->hidden_dir->i_ino, root,
						 &str, sbi->hidden_dir);
			if (err) {
				mutex_unlock(&sbi->vh_mutex);
				goto out_put_hidden_dir;
			}

			err = hfsplus_init_inode_security(sbi->hidden_dir,
								root, &str);
			if (err == -EOPNOTSUPP)
				err = 0; /* Operation is not supported. */
			else if (err) {
				/*
				 * Try to delete anyway without
				 * error analysis.
				 */
				hfsplus_delete_cat(sbi->hidden_dir->i_ino,
							root, &str);
				mutex_unlock(&sbi->vh_mutex);
				goto out_put_hidden_dir;
			}

			mutex_unlock(&sbi->vh_mutex);
			hfsplus_mark_inode_dirty(sbi->hidden_dir,
						 HFSPLUS_I_CAT_DIRTY);
		}
	}

	unload_nls(sbi->nls);
	sbi->nls = nls;
	return 0;

out_put_hidden_dir:
	iput(sbi->hidden_dir);
out_put_root:
	dput(sb->s_root);
	sb->s_root = NULL;
out_put_alloc_file:
	iput(sbi->alloc_file);
out_close_attr_tree:
	hfs_btree_close(sbi->attr_tree);
out_close_cat_tree:
	hfs_btree_close(sbi->cat_tree);
out_close_ext_tree:
	hfs_btree_close(sbi->ext_tree);
out_free_vhdr:
	kfree(sbi->s_vhdr_buf);
	kfree(sbi->s_backup_vhdr_buf);
out_unload_nls:
	unload_nls(sbi->nls);
	unload_nls(nls);
	kfree(sbi);
out:
	return err;
}

MODULE_AUTHOR("Brad Boyer");
MODULE_DESCRIPTION("Extended Macintosh Filesystem");
MODULE_LICENSE("GPL");

static struct kmem_cache *hfsplus_inode_cachep;

static struct inode *hfsplus_alloc_inode(struct super_block *sb)
{
	struct hfsplus_inode_info *i;

	i = kmem_cache_alloc(hfsplus_inode_cachep, GFP_KERNEL);
	return i ? &i->vfs_inode : NULL;
}

static void hfsplus_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);

	kmem_cache_free(hfsplus_inode_cachep, HFSPLUS_I(inode));
}

static void hfsplus_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, hfsplus_i_callback);
}

#define HFSPLUS_INODE_SIZE	sizeof(struct hfsplus_inode_info)

static struct dentry *hfsplus_mount(struct file_system_type *fs_type,
			  int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, hfsplus_fill_super);
}

static struct file_system_type hfsplus_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "hfsplus",
	.mount		= hfsplus_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("hfsplus");

static void hfsplus_init_once(void *p)
{
	struct hfsplus_inode_info *i = p;

	inode_init_once(&i->vfs_inode);
}

static int __init init_hfsplus_fs(void)
{
	int err;

	hfsplus_inode_cachep = kmem_cache_create("hfsplus_icache",
		HFSPLUS_INODE_SIZE, 0, SLAB_HWCACHE_ALIGN,
		hfsplus_init_once);
	if (!hfsplus_inode_cachep)
		return -ENOMEM;
	err = hfsplus_create_attr_tree_cache();
	if (err)
		goto destroy_inode_cache;
	err = register_filesystem(&hfsplus_fs_type);
	if (err)
		goto destroy_attr_tree_cache;
	return 0;

destroy_attr_tree_cache:
	hfsplus_destroy_attr_tree_cache();

destroy_inode_cache:
	kmem_cache_destroy(hfsplus_inode_cachep);

	return err;
}

static void __exit exit_hfsplus_fs(void)
{
	unregister_filesystem(&hfsplus_fs_type);

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	hfsplus_destroy_attr_tree_cache();
	kmem_cache_destroy(hfsplus_inode_cachep);
}

module_init(init_hfsplus_fs)
module_exit(exit_hfsplus_fs)
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/super.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/options.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Option parsing
 */

#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/parser.h>
// #include <linux/nls.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
// #include <linux/slab.h>
// #include "hfsplus_fs.h"
#include "../../inc/__fss.h"

enum {
	opt_creator, opt_type,
	opt_umask, opt_uid, opt_gid,
	opt_part, opt_session, opt_nls,
	opt_nodecompose, opt_decompose,
	opt_barrier, opt_nobarrier,
	opt_force, opt_err
};

static const match_table_t tokens = {
	{ opt_creator, "creator=%s" },
	{ opt_type, "type=%s" },
	{ opt_umask, "umask=%o" },
	{ opt_uid, "uid=%u" },
	{ opt_gid, "gid=%u" },
	{ opt_part, "part=%u" },
	{ opt_session, "session=%u" },
	{ opt_nls, "nls=%s" },
	{ opt_decompose, "decompose" },
	{ opt_nodecompose, "nodecompose" },
	{ opt_barrier, "barrier" },
	{ opt_nobarrier, "nobarrier" },
	{ opt_force, "force" },
	{ opt_err, NULL }
};

/* Initialize an options object to reasonable defaults */
void hfsplus_fill_defaults(struct hfsplus_sb_info *opts)
{
	if (!opts)
		return;

	opts->creator = HFSPLUS_DEF_CR_TYPE;
	opts->type = HFSPLUS_DEF_CR_TYPE;
	opts->umask = current_umask();
	opts->uid = current_uid();
	opts->gid = current_gid();
	opts->part = -1;
	opts->session = -1;
}

/* convert a "four byte character" to a 32 bit int with error checks */
static inline int match_fourchar(substring_t *arg, u32 *result)
{
	if (arg->to - arg->from != 4)
		return -EINVAL;
	memcpy(result, arg->from, 4);
	return 0;
}

int hfsplus_parse_options_remount(char *input, int *force)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int token;

	if (!input)
		return 1;

	while ((p = strsep(&input, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case opt_force:
			*force = 1;
			break;
		default:
			break;
		}
	}

	return 1;
}

/* Parse options from mount. Returns 0 on failure */
/* input is the options passed to mount() as a string */
int hfsplus_parse_options(char *input, struct hfsplus_sb_info *sbi)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int tmp, token;

	if (!input)
		goto done;

	while ((p = strsep(&input, ",")) != NULL) {
		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case opt_creator:
			if (match_fourchar(&args[0], &sbi->creator)) {
				pr_err("creator requires a 4 character value\n");
				return 0;
			}
			break;
		case opt_type:
			if (match_fourchar(&args[0], &sbi->type)) {
				pr_err("type requires a 4 character value\n");
				return 0;
			}
			break;
		case opt_umask:
			if (match_octal(&args[0], &tmp)) {
				pr_err("umask requires a value\n");
				return 0;
			}
			sbi->umask = (umode_t)tmp;
			break;
		case opt_uid:
			if (match_int(&args[0], &tmp)) {
				pr_err("uid requires an argument\n");
				return 0;
			}
			sbi->uid = make_kuid(current_user_ns(), (uid_t)tmp);
			if (!uid_valid(sbi->uid)) {
				pr_err("invalid uid specified\n");
				return 0;
			}
			break;
		case opt_gid:
			if (match_int(&args[0], &tmp)) {
				pr_err("gid requires an argument\n");
				return 0;
			}
			sbi->gid = make_kgid(current_user_ns(), (gid_t)tmp);
			if (!gid_valid(sbi->gid)) {
				pr_err("invalid gid specified\n");
				return 0;
			}
			break;
		case opt_part:
			if (match_int(&args[0], &sbi->part)) {
				pr_err("part requires an argument\n");
				return 0;
			}
			break;
		case opt_session:
			if (match_int(&args[0], &sbi->session)) {
				pr_err("session requires an argument\n");
				return 0;
			}
			break;
		case opt_nls:
			if (sbi->nls) {
				pr_err("unable to change nls mapping\n");
				return 0;
			}
			p = match_strdup(&args[0]);
			if (p)
				sbi->nls = load_nls(p);
			if (!sbi->nls) {
				pr_err("unable to load nls mapping \"%s\"\n",
				       p);
				kfree(p);
				return 0;
			}
			kfree(p);
			break;
		case opt_decompose:
			clear_bit(HFSPLUS_SB_NODECOMPOSE, &sbi->flags);
			break;
		case opt_nodecompose:
			set_bit(HFSPLUS_SB_NODECOMPOSE, &sbi->flags);
			break;
		case opt_barrier:
			clear_bit(HFSPLUS_SB_NOBARRIER, &sbi->flags);
			break;
		case opt_nobarrier:
			set_bit(HFSPLUS_SB_NOBARRIER, &sbi->flags);
			break;
		case opt_force:
			set_bit(HFSPLUS_SB_FORCE, &sbi->flags);
			break;
		default:
			return 0;
		}
	}

done:
	if (!sbi->nls) {
		/* try utf8 first, as this is the old default behaviour */
		sbi->nls = load_nls("utf8");
		if (!sbi->nls)
			sbi->nls = load_nls_default();
		if (!sbi->nls)
			return 0;
	}

	return 1;
}

int hfsplus_show_options(struct seq_file *seq, struct dentry *root)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(root->d_sb);

	if (sbi->creator != HFSPLUS_DEF_CR_TYPE)
		seq_printf(seq, ",creator=%.4s", (char *)&sbi->creator);
	if (sbi->type != HFSPLUS_DEF_CR_TYPE)
		seq_printf(seq, ",type=%.4s", (char *)&sbi->type);
	seq_printf(seq, ",umask=%o,uid=%u,gid=%u", sbi->umask,
			from_kuid_munged(&init_user_ns, sbi->uid),
			from_kgid_munged(&init_user_ns, sbi->gid));
	if (sbi->part >= 0)
		seq_printf(seq, ",part=%u", sbi->part);
	if (sbi->session >= 0)
		seq_printf(seq, ",session=%u", sbi->session);
	if (sbi->nls)
		seq_printf(seq, ",nls=%s", sbi->nls->charset);
	if (test_bit(HFSPLUS_SB_NODECOMPOSE, &sbi->flags))
		seq_puts(seq, ",nodecompose");
	if (test_bit(HFSPLUS_SB_NOBARRIER, &sbi->flags))
		seq_puts(seq, ",nobarrier");
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/options.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/inode.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Inode handling routines
 */

// #include <linux/blkdev.h>
#include <linux/mm.h>
// #include <linux/fs.h>
// #include <linux/pagemap.h>
#include <linux/mpage.h>
// #include <linux/sched.h>
#include <linux/aio.h>
#include "../../inc/__fss.h"

// #include "hfsplus_fs.h"
#include "hfsplus_raw.h"
// #include "xattr.h"
#include "acl.h"
#include "../../inc/__fss.h"

static int hfsplus_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, hfsplus_get_block);
}

static int hfsplus_writepage(struct page *page, struct writeback_control *wbc)
{
	return block_write_full_page(page, hfsplus_get_block, wbc);
}

static void hfsplus_write_failed(struct address_space *mapping, loff_t to)
{
	struct inode *inode = mapping->host;

	if (to > inode->i_size) {
		truncate_pagecache(inode, inode->i_size);
		hfsplus_file_truncate(inode);
	}
}

static int hfsplus_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;

	*pagep = NULL;
	ret = cont_write_begin(file, mapping, pos, len, flags, pagep, fsdata,
				hfsplus_get_block,
				&HFSPLUS_I(mapping->host)->phys_size);
	if (unlikely(ret))
		hfsplus_write_failed(mapping, pos + len);

	return ret;
}

static sector_t hfsplus_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, hfsplus_get_block);
}

static int hfsplus_releasepage(struct page *page, gfp_t mask)
{
	struct inode *inode = page->mapping->host;
	struct super_block *sb = inode->i_sb;
	struct hfs_btree *tree;
	struct hfs_bnode *node;
	u32 nidx;
	int i, res = 1;

	switch (inode->i_ino) {
	case HFSPLUS_EXT_CNID:
		tree = HFSPLUS_SB(sb)->ext_tree;
		break;
	case HFSPLUS_CAT_CNID:
		tree = HFSPLUS_SB(sb)->cat_tree;
		break;
	case HFSPLUS_ATTR_CNID:
		tree = HFSPLUS_SB(sb)->attr_tree;
		break;
	default:
		BUG();
		return 0;
	}
	if (!tree)
		return 0;
	if (tree->node_size >= PAGE_CACHE_SIZE) {
		nidx = page->index >>
			(tree->node_size_shift - PAGE_CACHE_SHIFT);
		spin_lock(&tree->hash_lock);
		node = hfs_bnode_findhash(tree, nidx);
		if (!node)
			;
		else if (atomic_read(&node->refcnt))
			res = 0;
		if (res && node) {
			hfs_bnode_unhash(node);
			hfs_bnode_free(node);
		}
		spin_unlock(&tree->hash_lock);
	} else {
		nidx = page->index <<
			(PAGE_CACHE_SHIFT - tree->node_size_shift);
		i = 1 << (PAGE_CACHE_SHIFT - tree->node_size_shift);
		spin_lock(&tree->hash_lock);
		do {
			node = hfs_bnode_findhash(tree, nidx++);
			if (!node)
				continue;
			if (atomic_read(&node->refcnt)) {
				res = 0;
				break;
			}
			hfs_bnode_unhash(node);
			hfs_bnode_free(node);
		} while (--i && nidx < tree->node_count);
		spin_unlock(&tree->hash_lock);
	}
	return res ? try_to_free_buffers(page) : 0;
}

static ssize_t hfsplus_direct_IO(int rw, struct kiocb *iocb,
		struct iov_iter *iter, loff_t offset)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file_inode(file)->i_mapping->host;
	size_t count = iov_iter_count(iter);
	ssize_t ret;

	ret = blockdev_direct_IO(rw, iocb, inode, iter, offset, 
				 hfsplus_get_block);

	/*
	 * In case of error extending write may have instantiated a few
	 * blocks outside i_size. Trim these off again.
	 */
	if (unlikely((rw & WRITE) && ret < 0)) {
		loff_t isize = i_size_read(inode);
		loff_t end = offset + count;

		if (end > isize)
			hfsplus_write_failed(mapping, end);
	}

	return ret;
}

static int hfsplus_writepages(struct address_space *mapping,
			      struct writeback_control *wbc)
{
	return mpage_writepages(mapping, wbc, hfsplus_get_block);
}

const struct address_space_operations hfsplus_btree_aops = {
	.readpage	= hfsplus_readpage,
	.writepage	= hfsplus_writepage,
	.write_begin	= hfsplus_write_begin,
	.write_end	= generic_write_end,
	.bmap		= hfsplus_bmap,
	.releasepage	= hfsplus_releasepage,
};

const struct address_space_operations hfsplus_aops = {
	.readpage	= hfsplus_readpage,
	.writepage	= hfsplus_writepage,
	.write_begin	= hfsplus_write_begin,
	.write_end	= generic_write_end,
	.bmap		= hfsplus_bmap,
	.direct_IO	= hfsplus_direct_IO,
	.writepages	= hfsplus_writepages,
};

const struct dentry_operations hfsplus_dentry_operations = {
	.d_hash       = hfsplus_hash_dentry,
	.d_compare    = hfsplus_compare_dentry,
};

static void hfsplus_get_perms(struct inode *inode,
		struct hfsplus_perm *perms, int dir)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(inode->i_sb);
	u16 mode;

	mode = be16_to_cpu(perms->mode);

	i_uid_write(inode, be32_to_cpu(perms->owner));
	if (!i_uid_read(inode) && !mode)
		inode->i_uid = sbi->uid;

	i_gid_write(inode, be32_to_cpu(perms->group));
	if (!i_gid_read(inode) && !mode)
		inode->i_gid = sbi->gid;

	if (dir) {
		mode = mode ? (mode & S_IALLUGO) : (S_IRWXUGO & ~(sbi->umask));
		mode |= S_IFDIR;
	} else if (!mode)
		mode = S_IFREG | ((S_IRUGO|S_IWUGO) & ~(sbi->umask));
	inode->i_mode = mode;

	HFSPLUS_I(inode)->userflags = perms->userflags;
	if (perms->rootflags & HFSPLUS_FLG_IMMUTABLE)
		inode->i_flags |= S_IMMUTABLE;
	else
		inode->i_flags &= ~S_IMMUTABLE;
	if (perms->rootflags & HFSPLUS_FLG_APPEND)
		inode->i_flags |= S_APPEND;
	else
		inode->i_flags &= ~S_APPEND;
}

static int hfsplus_file_open(struct inode *inode, struct file *file)
{
	if (HFSPLUS_IS_RSRC(inode))
		inode = HFSPLUS_I(inode)->rsrc_inode;
	if (!(file->f_flags & O_LARGEFILE) && i_size_read(inode) > MAX_NON_LFS)
		return -EOVERFLOW;
	atomic_inc(&HFSPLUS_I(inode)->opencnt);
	return 0;
}

static int hfsplus_file_release(struct inode *inode, struct file *file)
{
	struct super_block *sb = inode->i_sb;

	if (HFSPLUS_IS_RSRC(inode))
		inode = HFSPLUS_I(inode)->rsrc_inode;
	if (atomic_dec_and_test(&HFSPLUS_I(inode)->opencnt)) {
		mutex_lock(&inode->i_mutex);
		hfsplus_file_truncate(inode);
		if (inode->i_flags & S_DEAD) {
			hfsplus_delete_cat(inode->i_ino,
					   HFSPLUS_SB(sb)->hidden_dir, NULL);
			hfsplus_delete_inode(inode);
		}
		mutex_unlock(&inode->i_mutex);
	}
	return 0;
}

static int hfsplus_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int error;

	error = inode_change_ok(inode, attr);
	if (error)
		return error;

	if ((attr->ia_valid & ATTR_SIZE) &&
	    attr->ia_size != i_size_read(inode)) {
		inode_dio_wait(inode);
		truncate_setsize(inode, attr->ia_size);
		hfsplus_file_truncate(inode);
	}

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);

	if (attr->ia_valid & ATTR_MODE) {
		error = posix_acl_chmod(inode, inode->i_mode);
		if (unlikely(error))
			return error;
	}

	return 0;
}

int hfsplus_file_fsync(struct file *file, loff_t start, loff_t end,
		       int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(inode->i_sb);
	int error = 0, error2;

	error = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (error)
		return error;
	mutex_lock(&inode->i_mutex);

	/*
	 * Sync inode metadata into the catalog and extent trees.
	 */
	sync_inode_metadata(inode, 1);

	/*
	 * And explicitly write out the btrees.
	 */
	if (test_and_clear_bit(HFSPLUS_I_CAT_DIRTY, &hip->flags))
		error = filemap_write_and_wait(sbi->cat_tree->inode->i_mapping);

	if (test_and_clear_bit(HFSPLUS_I_EXT_DIRTY, &hip->flags)) {
		error2 =
			filemap_write_and_wait(sbi->ext_tree->inode->i_mapping);
		if (!error)
			error = error2;
	}

	if (test_and_clear_bit(HFSPLUS_I_ATTR_DIRTY, &hip->flags)) {
		if (sbi->attr_tree) {
			error2 =
				filemap_write_and_wait(
					    sbi->attr_tree->inode->i_mapping);
			if (!error)
				error = error2;
		} else {
			pr_err("sync non-existent attributes tree\n");
		}
	}

	if (test_and_clear_bit(HFSPLUS_I_ALLOC_DIRTY, &hip->flags)) {
		error2 = filemap_write_and_wait(sbi->alloc_file->i_mapping);
		if (!error)
			error = error2;
	}

	if (!test_bit(HFSPLUS_SB_NOBARRIER, &sbi->flags))
		blkdev_issue_flush(inode->i_sb->s_bdev, GFP_KERNEL, NULL);

	mutex_unlock(&inode->i_mutex);

	return error;
}

static const struct inode_operations hfsplus_file_inode_operations = {
	.setattr	= hfsplus_setattr,
	.setxattr	= generic_setxattr,
	.getxattr	= generic_getxattr,
	.listxattr	= hfsplus_listxattr,
	.removexattr	= generic_removexattr,
#ifdef CONFIG_HFSPLUS_FS_POSIX_ACL
	.get_acl	= hfsplus_get_posix_acl,
	.set_acl	= hfsplus_set_posix_acl,
#endif
};

static const struct file_operations hfsplus_file_operations = {
	.llseek		= generic_file_llseek,
	.read		= new_sync_read,
	.read_iter	= generic_file_read_iter,
	.write		= new_sync_write,
	.write_iter	= generic_file_write_iter,
	.mmap		= generic_file_mmap,
	.splice_read	= generic_file_splice_read,
	.fsync		= hfsplus_file_fsync,
	.open		= hfsplus_file_open,
	.release	= hfsplus_file_release,
	.unlocked_ioctl = hfsplus_ioctl,
};

struct inode *hfsplus_new_inode(struct super_block *sb, umode_t mode)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct inode *inode = new_inode(sb);
	struct hfsplus_inode_info *hip;

	if (!inode)
		return NULL;

	inode->i_ino = sbi->next_cnid++;
	inode->i_mode = mode;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	set_nlink(inode, 1);
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME_SEC;

	hip = HFSPLUS_I(inode);
	INIT_LIST_HEAD(&hip->open_dir_list);
	mutex_init(&hip->extents_lock);
	atomic_set(&hip->opencnt, 0);
	hip->extent_state = 0;
	hip->flags = 0;
	hip->userflags = 0;
	hip->subfolders = 0;
	memset(hip->first_extents, 0, sizeof(hfsplus_extent_rec));
	memset(hip->cached_extents, 0, sizeof(hfsplus_extent_rec));
	hip->alloc_blocks = 0;
	hip->first_blocks = 0;
	hip->cached_start = 0;
	hip->cached_blocks = 0;
	hip->phys_size = 0;
	hip->fs_blocks = 0;
	hip->rsrc_inode = NULL;
	if (S_ISDIR(inode->i_mode)) {
		inode->i_size = 2;
		sbi->folder_count++;
		inode->i_op = &hfsplus_dir_inode_operations;
		inode->i_fop = &hfsplus_dir_operations;
	} else if (S_ISREG(inode->i_mode)) {
		sbi->file_count++;
		inode->i_op = &hfsplus_file_inode_operations;
		inode->i_fop = &hfsplus_file_operations;
		inode->i_mapping->a_ops = &hfsplus_aops;
		hip->clump_blocks = sbi->data_clump_blocks;
	} else if (S_ISLNK(inode->i_mode)) {
		sbi->file_count++;
		inode->i_op = &page_symlink_inode_operations;
		inode->i_mapping->a_ops = &hfsplus_aops;
		hip->clump_blocks = 1;
	} else
		sbi->file_count++;
	insert_inode_hash(inode);
	mark_inode_dirty(inode);
	hfsplus_mark_mdb_dirty(sb);

	return inode;
}

void hfsplus_delete_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (S_ISDIR(inode->i_mode)) {
		HFSPLUS_SB(sb)->folder_count--;
		hfsplus_mark_mdb_dirty(sb);
		return;
	}
	HFSPLUS_SB(sb)->file_count--;
	if (S_ISREG(inode->i_mode)) {
		if (!inode->i_nlink) {
			inode->i_size = 0;
			hfsplus_file_truncate(inode);
		}
	} else if (S_ISLNK(inode->i_mode)) {
		inode->i_size = 0;
		hfsplus_file_truncate(inode);
	}
	hfsplus_mark_mdb_dirty(sb);
}

void hfsplus_inode_read_fork(struct inode *inode, struct hfsplus_fork_raw *fork)
{
	struct super_block *sb = inode->i_sb;
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	u32 count;
	int i;

	memcpy(&hip->first_extents, &fork->extents, sizeof(hfsplus_extent_rec));
	for (count = 0, i = 0; i < 8; i++)
		count += be32_to_cpu(fork->extents[i].block_count);
	hip->first_blocks = count;
	memset(hip->cached_extents, 0, sizeof(hfsplus_extent_rec));
	hip->cached_start = 0;
	hip->cached_blocks = 0;

	hip->alloc_blocks = be32_to_cpu(fork->total_blocks);
	hip->phys_size = inode->i_size = be64_to_cpu(fork->total_size);
	hip->fs_blocks =
		(inode->i_size + sb->s_blocksize - 1) >> sb->s_blocksize_bits;
	inode_set_bytes(inode, hip->fs_blocks << sb->s_blocksize_bits);
	hip->clump_blocks =
		be32_to_cpu(fork->clump_size) >> sbi->alloc_blksz_shift;
	if (!hip->clump_blocks) {
		hip->clump_blocks = HFSPLUS_IS_RSRC(inode) ?
			sbi->rsrc_clump_blocks :
			sbi->data_clump_blocks;
	}
}

void hfsplus_inode_write_fork(struct inode *inode,
		struct hfsplus_fork_raw *fork)
{
	memcpy(&fork->extents, &HFSPLUS_I(inode)->first_extents,
	       sizeof(hfsplus_extent_rec));
	fork->total_size = cpu_to_be64(inode->i_size);
	fork->total_blocks = cpu_to_be32(HFSPLUS_I(inode)->alloc_blocks);
}

int hfsplus_cat_read_inode(struct inode *inode, struct hfs_find_data *fd)
{
	hfsplus_cat_entry entry;
	int res = 0;
	u16 type;

	type = hfs_bnode_read_u16(fd->bnode, fd->entryoffset);

	HFSPLUS_I(inode)->linkid = 0;
	if (type == HFSPLUS_FOLDER) {
		struct hfsplus_cat_folder *folder = &entry.folder;

		if (fd->entrylength < sizeof(struct hfsplus_cat_folder))
			/* panic? */;
		hfs_bnode_read(fd->bnode, &entry, fd->entryoffset,
					sizeof(struct hfsplus_cat_folder));
		hfsplus_get_perms(inode, &folder->permissions, 1);
		set_nlink(inode, 1);
		inode->i_size = 2 + be32_to_cpu(folder->valence);
		inode->i_atime = hfsp_mt2ut(folder->access_date);
		inode->i_mtime = hfsp_mt2ut(folder->content_mod_date);
		inode->i_ctime = hfsp_mt2ut(folder->attribute_mod_date);
		HFSPLUS_I(inode)->create_date = folder->create_date;
		HFSPLUS_I(inode)->fs_blocks = 0;
		if (folder->flags & cpu_to_be16(HFSPLUS_HAS_FOLDER_COUNT)) {
			HFSPLUS_I(inode)->subfolders =
				be32_to_cpu(folder->subfolders);
		}
		inode->i_op = &hfsplus_dir_inode_operations;
		inode->i_fop = &hfsplus_dir_operations;
	} else if (type == HFSPLUS_FILE) {
		struct hfsplus_cat_file *file = &entry.file;

		if (fd->entrylength < sizeof(struct hfsplus_cat_file))
			/* panic? */;
		hfs_bnode_read(fd->bnode, &entry, fd->entryoffset,
					sizeof(struct hfsplus_cat_file));

		hfsplus_inode_read_fork(inode, HFSPLUS_IS_RSRC(inode) ?
					&file->rsrc_fork : &file->data_fork);
		hfsplus_get_perms(inode, &file->permissions, 0);
		set_nlink(inode, 1);
		if (S_ISREG(inode->i_mode)) {
			if (file->permissions.dev)
				set_nlink(inode,
					  be32_to_cpu(file->permissions.dev));
			inode->i_op = &hfsplus_file_inode_operations;
			inode->i_fop = &hfsplus_file_operations;
			inode->i_mapping->a_ops = &hfsplus_aops;
		} else if (S_ISLNK(inode->i_mode)) {
			inode->i_op = &page_symlink_inode_operations;
			inode->i_mapping->a_ops = &hfsplus_aops;
		} else {
			init_special_inode(inode, inode->i_mode,
					   be32_to_cpu(file->permissions.dev));
		}
		inode->i_atime = hfsp_mt2ut(file->access_date);
		inode->i_mtime = hfsp_mt2ut(file->content_mod_date);
		inode->i_ctime = hfsp_mt2ut(file->attribute_mod_date);
		HFSPLUS_I(inode)->create_date = file->create_date;
	} else {
		pr_err("bad catalog entry used to create inode\n");
		res = -EIO;
	}
	return res;
}

int hfsplus_cat_write_inode(struct inode *inode)
{
	struct inode *main_inode = inode;
	struct hfs_find_data fd;
	hfsplus_cat_entry entry;

	if (HFSPLUS_IS_RSRC(inode))
		main_inode = HFSPLUS_I(inode)->rsrc_inode;

	if (!main_inode->i_nlink)
		return 0;

	if (hfs_find_init(HFSPLUS_SB(main_inode->i_sb)->cat_tree, &fd))
		/* panic? */
		return -EIO;

	if (hfsplus_find_cat(main_inode->i_sb, main_inode->i_ino, &fd))
		/* panic? */
		goto out;

	if (S_ISDIR(main_inode->i_mode)) {
		struct hfsplus_cat_folder *folder = &entry.folder;

		if (fd.entrylength < sizeof(struct hfsplus_cat_folder))
			/* panic? */;
		hfs_bnode_read(fd.bnode, &entry, fd.entryoffset,
					sizeof(struct hfsplus_cat_folder));
		/* simple node checks? */
		hfsplus_cat_set_perms(inode, &folder->permissions);
		folder->access_date = hfsp_ut2mt(inode->i_atime);
		folder->content_mod_date = hfsp_ut2mt(inode->i_mtime);
		folder->attribute_mod_date = hfsp_ut2mt(inode->i_ctime);
		folder->valence = cpu_to_be32(inode->i_size - 2);
		if (folder->flags & cpu_to_be16(HFSPLUS_HAS_FOLDER_COUNT)) {
			folder->subfolders =
				cpu_to_be32(HFSPLUS_I(inode)->subfolders);
		}
		hfs_bnode_write(fd.bnode, &entry, fd.entryoffset,
					 sizeof(struct hfsplus_cat_folder));
	} else if (HFSPLUS_IS_RSRC(inode)) {
		struct hfsplus_cat_file *file = &entry.file;
		hfs_bnode_read(fd.bnode, &entry, fd.entryoffset,
			       sizeof(struct hfsplus_cat_file));
		hfsplus_inode_write_fork(inode, &file->rsrc_fork);
		hfs_bnode_write(fd.bnode, &entry, fd.entryoffset,
				sizeof(struct hfsplus_cat_file));
	} else {
		struct hfsplus_cat_file *file = &entry.file;

		if (fd.entrylength < sizeof(struct hfsplus_cat_file))
			/* panic? */;
		hfs_bnode_read(fd.bnode, &entry, fd.entryoffset,
					sizeof(struct hfsplus_cat_file));
		hfsplus_inode_write_fork(inode, &file->data_fork);
		hfsplus_cat_set_perms(inode, &file->permissions);
		if (HFSPLUS_FLG_IMMUTABLE &
				(file->permissions.rootflags |
					file->permissions.userflags))
			file->flags |= cpu_to_be16(HFSPLUS_FILE_LOCKED);
		else
			file->flags &= cpu_to_be16(~HFSPLUS_FILE_LOCKED);
		file->access_date = hfsp_ut2mt(inode->i_atime);
		file->content_mod_date = hfsp_ut2mt(inode->i_mtime);
		file->attribute_mod_date = hfsp_ut2mt(inode->i_ctime);
		hfs_bnode_write(fd.bnode, &entry, fd.entryoffset,
					 sizeof(struct hfsplus_cat_file));
	}

	set_bit(HFSPLUS_I_CAT_DIRTY, &HFSPLUS_I(inode)->flags);
out:
	hfs_find_exit(&fd);
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/inode.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/ioctl.c
 *
 * Copyright (C) 2003
 * Ethan Benson <erbenson@alaska.net>
 * partially derived from linux/fs/ext2/ioctl.c
 * Copyright (C) 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 * hfsplus ioctls
 */

#include <linux/capability.h>
// #include <linux/fs.h>
// #include <linux/mount.h>
// #include <linux/sched.h>
#include <asm/uaccess.h>
// #include "hfsplus_fs.h"
#include "../../inc/__fss.h"

/*
 * "Blessing" an HFS+ filesystem writes metadata to the superblock informing
 * the platform firmware which file to boot from
 */
static int hfsplus_ioctl_bless(struct file *file, int __user *user_flags)
{
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(inode->i_sb);
	struct hfsplus_vh *vh = sbi->s_vhdr;
	struct hfsplus_vh *bvh = sbi->s_backup_vhdr;
	u32 cnid = (unsigned long)dentry->d_fsdata;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	mutex_lock(&sbi->vh_mutex);

	/* Directory containing the bootable system */
	vh->finder_info[0] = bvh->finder_info[0] =
		cpu_to_be32(parent_ino(dentry));

	/*
	 * Bootloader. Just using the inode here breaks in the case of
	 * hard links - the firmware wants the ID of the hard link file,
	 * but the inode points at the indirect inode
	 */
	vh->finder_info[1] = bvh->finder_info[1] = cpu_to_be32(cnid);

	/* Per spec, the OS X system folder - same as finder_info[0] here */
	vh->finder_info[5] = bvh->finder_info[5] =
		cpu_to_be32(parent_ino(dentry));

	mutex_unlock(&sbi->vh_mutex);
	return 0;
}

static int hfsplus_ioctl_getflags(struct file *file, int __user *user_flags)
{
	struct inode *inode = file_inode(file);
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	unsigned int flags = 0;

	if (inode->i_flags & S_IMMUTABLE)
		flags |= FS_IMMUTABLE_FL;
	if (inode->i_flags & S_APPEND)
		flags |= FS_APPEND_FL;
	if (hip->userflags & HFSPLUS_FLG_NODUMP)
		flags |= FS_NODUMP_FL;

	return put_user(flags, user_flags);
}

static int hfsplus_ioctl_setflags(struct file *file, int __user *user_flags)
{
	struct inode *inode = file_inode(file);
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	unsigned int flags;
	int err = 0;

	err = mnt_want_write_file(file);
	if (err)
		goto out;

	if (!inode_owner_or_capable(inode)) {
		err = -EACCES;
		goto out_drop_write;
	}

	if (get_user(flags, user_flags)) {
		err = -EFAULT;
		goto out_drop_write;
	}

	mutex_lock(&inode->i_mutex);

	if ((flags & (FS_IMMUTABLE_FL|FS_APPEND_FL)) ||
	    inode->i_flags & (S_IMMUTABLE|S_APPEND)) {
		if (!capable(CAP_LINUX_IMMUTABLE)) {
			err = -EPERM;
			goto out_unlock_inode;
		}
	}

	/* don't silently ignore unsupported ext2 flags */
	if (flags & ~(FS_IMMUTABLE_FL|FS_APPEND_FL|FS_NODUMP_FL)) {
		err = -EOPNOTSUPP;
		goto out_unlock_inode;
	}

	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	else
		inode->i_flags &= ~S_IMMUTABLE;

	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	else
		inode->i_flags &= ~S_APPEND;

	if (flags & FS_NODUMP_FL)
		hip->userflags |= HFSPLUS_FLG_NODUMP;
	else
		hip->userflags &= ~HFSPLUS_FLG_NODUMP;

	inode->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);

out_unlock_inode:
	mutex_unlock(&inode->i_mutex);
out_drop_write:
	mnt_drop_write_file(file);
out:
	return err;
}

long hfsplus_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case HFSPLUS_IOC_EXT2_GETFLAGS:
		return hfsplus_ioctl_getflags(file, argp);
	case HFSPLUS_IOC_EXT2_SETFLAGS:
		return hfsplus_ioctl_setflags(file, argp);
	case HFSPLUS_IOC_BLESS:
		return hfsplus_ioctl_bless(file, argp);
	default:
		return -ENOTTY;
	}
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/ioctl.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/extents.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handling of Extents both in catalog and extents overflow trees
 */

#include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/pagemap.h>
#include "../../inc/__fss.h"

// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"

/* Compare two extents keys, returns 0 on same, pos/neg for difference */
int hfsplus_ext_cmp_key(const hfsplus_btree_key *k1,
			const hfsplus_btree_key *k2)
{
	__be32 k1id, k2id;
	__be32 k1s, k2s;

	k1id = k1->ext.cnid;
	k2id = k2->ext.cnid;
	if (k1id != k2id)
		return be32_to_cpu(k1id) < be32_to_cpu(k2id) ? -1 : 1;

	if (k1->ext.fork_type != k2->ext.fork_type)
		return k1->ext.fork_type < k2->ext.fork_type ? -1 : 1;

	k1s = k1->ext.start_block;
	k2s = k2->ext.start_block;
	if (k1s == k2s)
		return 0;
	return be32_to_cpu(k1s) < be32_to_cpu(k2s) ? -1 : 1;
}

static void hfsplus_ext_build_key(hfsplus_btree_key *key, u32 cnid,
				  u32 block, u8 type)
{
	key->key_len = cpu_to_be16(HFSPLUS_EXT_KEYLEN - 2);
	key->ext.cnid = cpu_to_be32(cnid);
	key->ext.start_block = cpu_to_be32(block);
	key->ext.fork_type = type;
	key->ext.pad = 0;
}

static u32 hfsplus_ext_find_block(struct hfsplus_extent *ext, u32 off)
{
	int i;
	u32 count;

	for (i = 0; i < 8; ext++, i++) {
		count = be32_to_cpu(ext->block_count);
		if (off < count)
			return be32_to_cpu(ext->start_block) + off;
		off -= count;
	}
	/* panic? */
	return 0;
}

static int hfsplus_ext_block_count(struct hfsplus_extent *ext)
{
	int i;
	u32 count = 0;

	for (i = 0; i < 8; ext++, i++)
		count += be32_to_cpu(ext->block_count);
	return count;
}

static u32 hfsplus_ext_lastblock(struct hfsplus_extent *ext)
{
	int i;

	ext += 7;
	for (i = 0; i < 7; ext--, i++)
		if (ext->block_count)
			break;
	return be32_to_cpu(ext->start_block) + be32_to_cpu(ext->block_count);
}

static int __hfsplus_ext_write_extent(struct inode *inode,
		struct hfs_find_data *fd)
{
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	int res;

	WARN_ON(!mutex_is_locked(&hip->extents_lock));

	hfsplus_ext_build_key(fd->search_key, inode->i_ino, hip->cached_start,
			      HFSPLUS_IS_RSRC(inode) ?
				HFSPLUS_TYPE_RSRC : HFSPLUS_TYPE_DATA);

	res = hfs_brec_find(fd, hfs_find_rec_by_key);
	if (hip->extent_state & HFSPLUS_EXT_NEW) {
		if (res != -ENOENT)
			return res;
		hfs_brec_insert(fd, hip->cached_extents,
				sizeof(hfsplus_extent_rec));
		hip->extent_state &= ~(HFSPLUS_EXT_DIRTY | HFSPLUS_EXT_NEW);
	} else {
		if (res)
			return res;
		hfs_bnode_write(fd->bnode, hip->cached_extents,
				fd->entryoffset, fd->entrylength);
		hip->extent_state &= ~HFSPLUS_EXT_DIRTY;
	}

	/*
	 * We can't just use hfsplus_mark_inode_dirty here, because we
	 * also get called from hfsplus_write_inode, which should not
	 * redirty the inode.  Instead the callers have to be careful
	 * to explicily mark the inode dirty, too.
	 */
	set_bit(HFSPLUS_I_EXT_DIRTY, &hip->flags);

	return 0;
}

static int hfsplus_ext_write_extent_locked(struct inode *inode)
{
	int res = 0;

	if (HFSPLUS_I(inode)->extent_state & HFSPLUS_EXT_DIRTY) {
		struct hfs_find_data fd;

		res = hfs_find_init(HFSPLUS_SB(inode->i_sb)->ext_tree, &fd);
		if (res)
			return res;
		res = __hfsplus_ext_write_extent(inode, &fd);
		hfs_find_exit(&fd);
	}
	return res;
}

int hfsplus_ext_write_extent(struct inode *inode)
{
	int res;

	mutex_lock(&HFSPLUS_I(inode)->extents_lock);
	res = hfsplus_ext_write_extent_locked(inode);
	mutex_unlock(&HFSPLUS_I(inode)->extents_lock);

	return res;
}

static inline int __hfsplus_ext_read_extent(struct hfs_find_data *fd,
					    struct hfsplus_extent *extent,
					    u32 cnid, u32 block, u8 type)
{
	int res;

	hfsplus_ext_build_key(fd->search_key, cnid, block, type);
	fd->key->ext.cnid = 0;
	res = hfs_brec_find(fd, hfs_find_rec_by_key);
	if (res && res != -ENOENT)
		return res;
	if (fd->key->ext.cnid != fd->search_key->ext.cnid ||
	    fd->key->ext.fork_type != fd->search_key->ext.fork_type)
		return -ENOENT;
	if (fd->entrylength != sizeof(hfsplus_extent_rec))
		return -EIO;
	hfs_bnode_read(fd->bnode, extent, fd->entryoffset,
		sizeof(hfsplus_extent_rec));
	return 0;
}

static inline int __hfsplus_ext_cache_extent(struct hfs_find_data *fd,
		struct inode *inode, u32 block)
{
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	int res;

	WARN_ON(!mutex_is_locked(&hip->extents_lock));

	if (hip->extent_state & HFSPLUS_EXT_DIRTY) {
		res = __hfsplus_ext_write_extent(inode, fd);
		if (res)
			return res;
	}

	res = __hfsplus_ext_read_extent(fd, hip->cached_extents, inode->i_ino,
					block, HFSPLUS_IS_RSRC(inode) ?
						HFSPLUS_TYPE_RSRC :
						HFSPLUS_TYPE_DATA);
	if (!res) {
		hip->cached_start = be32_to_cpu(fd->key->ext.start_block);
		hip->cached_blocks =
			hfsplus_ext_block_count(hip->cached_extents);
	} else {
		hip->cached_start = hip->cached_blocks = 0;
		hip->extent_state &= ~(HFSPLUS_EXT_DIRTY | HFSPLUS_EXT_NEW);
	}
	return res;
}

static int hfsplus_ext_read_extent(struct inode *inode, u32 block)
{
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	struct hfs_find_data fd;
	int res;

	if (block >= hip->cached_start &&
	    block < hip->cached_start + hip->cached_blocks)
		return 0;

	res = hfs_find_init(HFSPLUS_SB(inode->i_sb)->ext_tree, &fd);
	if (!res) {
		res = __hfsplus_ext_cache_extent(&fd, inode, block);
		hfs_find_exit(&fd);
	}
	return res;
}

/* Get a block at iblock for inode, possibly allocating if create */
int hfsplus_get_block(struct inode *inode, sector_t iblock,
		      struct buffer_head *bh_result, int create)
{
	struct super_block *sb = inode->i_sb;
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	int res = -EIO;
	u32 ablock, dblock, mask;
	sector_t sector;
	int was_dirty = 0;

	/* Convert inode block to disk allocation block */
	ablock = iblock >> sbi->fs_shift;

	if (iblock >= hip->fs_blocks) {
		if (iblock > hip->fs_blocks || !create)
			return -EIO;
		if (ablock >= hip->alloc_blocks) {
			res = hfsplus_file_extend(inode, false);
			if (res)
				return res;
		}
	} else
		create = 0;

	if (ablock < hip->first_blocks) {
		dblock = hfsplus_ext_find_block(hip->first_extents, ablock);
		goto done;
	}

	if (inode->i_ino == HFSPLUS_EXT_CNID)
		return -EIO;

	mutex_lock(&hip->extents_lock);

	/*
	 * hfsplus_ext_read_extent will write out a cached extent into
	 * the extents btree.  In that case we may have to mark the inode
	 * dirty even for a pure read of an extent here.
	 */
	was_dirty = (hip->extent_state & HFSPLUS_EXT_DIRTY);
	res = hfsplus_ext_read_extent(inode, ablock);
	if (res) {
		mutex_unlock(&hip->extents_lock);
		return -EIO;
	}
	dblock = hfsplus_ext_find_block(hip->cached_extents,
					ablock - hip->cached_start);
	mutex_unlock(&hip->extents_lock);

done:
	hfs_dbg(EXTENT, "get_block(%lu): %llu - %u\n",
		inode->i_ino, (long long)iblock, dblock);

	mask = (1 << sbi->fs_shift) - 1;
	sector = ((sector_t)dblock << sbi->fs_shift) +
		  sbi->blockoffset + (iblock & mask);
	map_bh(bh_result, sb, sector);

	if (create) {
		set_buffer_new(bh_result);
		hip->phys_size += sb->s_blocksize;
		hip->fs_blocks++;
		inode_add_bytes(inode, sb->s_blocksize);
	}
	if (create || was_dirty)
		mark_inode_dirty(inode);
	return 0;
}

static void hfsplus_dump_extent(struct hfsplus_extent *extent)
{
	int i;

	hfs_dbg(EXTENT, "   ");
	for (i = 0; i < 8; i++)
		hfs_dbg_cont(EXTENT, " %u:%u",
			     be32_to_cpu(extent[i].start_block),
			     be32_to_cpu(extent[i].block_count));
	hfs_dbg_cont(EXTENT, "\n");
}

static int hfsplus_add_extent(struct hfsplus_extent *extent, u32 offset,
			      u32 alloc_block, u32 block_count)
{
	u32 count, start;
	int i;

	hfsplus_dump_extent(extent);
	for (i = 0; i < 8; extent++, i++) {
		count = be32_to_cpu(extent->block_count);
		if (offset == count) {
			start = be32_to_cpu(extent->start_block);
			if (alloc_block != start + count) {
				if (++i >= 8)
					return -ENOSPC;
				extent++;
				extent->start_block = cpu_to_be32(alloc_block);
			} else
				block_count += count;
			extent->block_count = cpu_to_be32(block_count);
			return 0;
		} else if (offset < count)
			break;
		offset -= count;
	}
	/* panic? */
	return -EIO;
}

static int hfsplus_free_extents(struct super_block *sb,
				struct hfsplus_extent *extent,
				u32 offset, u32 block_nr)
{
	u32 count, start;
	int i;
	int err = 0;

	hfsplus_dump_extent(extent);
	for (i = 0; i < 8; extent++, i++) {
		count = be32_to_cpu(extent->block_count);
		if (offset == count)
			goto found;
		else if (offset < count)
			break;
		offset -= count;
	}
	/* panic? */
	return -EIO;
found:
	for (;;) {
		start = be32_to_cpu(extent->start_block);
		if (count <= block_nr) {
			err = hfsplus_block_free(sb, start, count);
			if (err) {
				pr_err("can't free extent\n");
				hfs_dbg(EXTENT, " start: %u count: %u\n",
					start, count);
			}
			extent->block_count = 0;
			extent->start_block = 0;
			block_nr -= count;
		} else {
			count -= block_nr;
			err = hfsplus_block_free(sb, start + count, block_nr);
			if (err) {
				pr_err("can't free extent\n");
				hfs_dbg(EXTENT, " start: %u count: %u\n",
					start, count);
			}
			extent->block_count = cpu_to_be32(count);
			block_nr = 0;
		}
		if (!block_nr || !i) {
			/*
			 * Try to free all extents and
			 * return only last error
			 */
			return err;
		}
		i--;
		extent--;
		count = be32_to_cpu(extent->block_count);
	}
}

int hfsplus_free_fork(struct super_block *sb, u32 cnid,
		struct hfsplus_fork_raw *fork, int type)
{
	struct hfs_find_data fd;
	hfsplus_extent_rec ext_entry;
	u32 total_blocks, blocks, start;
	int res, i;

	total_blocks = be32_to_cpu(fork->total_blocks);
	if (!total_blocks)
		return 0;

	blocks = 0;
	for (i = 0; i < 8; i++)
		blocks += be32_to_cpu(fork->extents[i].block_count);

	res = hfsplus_free_extents(sb, fork->extents, blocks, blocks);
	if (res)
		return res;
	if (total_blocks == blocks)
		return 0;

	res = hfs_find_init(HFSPLUS_SB(sb)->ext_tree, &fd);
	if (res)
		return res;
	do {
		res = __hfsplus_ext_read_extent(&fd, ext_entry, cnid,
						total_blocks, type);
		if (res)
			break;
		start = be32_to_cpu(fd.key->ext.start_block);
		hfsplus_free_extents(sb, ext_entry,
				     total_blocks - start,
				     total_blocks);
		hfs_brec_remove(&fd);
		total_blocks = start;
	} while (total_blocks > blocks);
	hfs_find_exit(&fd);

	return res;
}

int hfsplus_file_extend(struct inode *inode, bool zeroout)
{
	struct super_block *sb = inode->i_sb;
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	u32 start, len, goal;
	int res;

	if (sbi->alloc_file->i_size * 8 <
	    sbi->total_blocks - sbi->free_blocks + 8) {
		/* extend alloc file */
		pr_err("extend alloc file! (%llu,%u,%u)\n",
		       sbi->alloc_file->i_size * 8,
		       sbi->total_blocks, sbi->free_blocks);
		return -ENOSPC;
	}

	mutex_lock(&hip->extents_lock);
	if (hip->alloc_blocks == hip->first_blocks)
		goal = hfsplus_ext_lastblock(hip->first_extents);
	else {
		res = hfsplus_ext_read_extent(inode, hip->alloc_blocks);
		if (res)
			goto out;
		goal = hfsplus_ext_lastblock(hip->cached_extents);
	}

	len = hip->clump_blocks;
	start = hfsplus_block_allocate(sb, sbi->total_blocks, goal, &len);
	if (start >= sbi->total_blocks) {
		start = hfsplus_block_allocate(sb, goal, 0, &len);
		if (start >= goal) {
			res = -ENOSPC;
			goto out;
		}
	}

	if (zeroout) {
		res = sb_issue_zeroout(sb, start, len, GFP_NOFS);
		if (res)
			goto out;
	}

	hfs_dbg(EXTENT, "extend %lu: %u,%u\n", inode->i_ino, start, len);

	if (hip->alloc_blocks <= hip->first_blocks) {
		if (!hip->first_blocks) {
			hfs_dbg(EXTENT, "first extents\n");
			/* no extents yet */
			hip->first_extents[0].start_block = cpu_to_be32(start);
			hip->first_extents[0].block_count = cpu_to_be32(len);
			res = 0;
		} else {
			/* try to append to extents in inode */
			res = hfsplus_add_extent(hip->first_extents,
						 hip->alloc_blocks,
						 start, len);
			if (res == -ENOSPC)
				goto insert_extent;
		}
		if (!res) {
			hfsplus_dump_extent(hip->first_extents);
			hip->first_blocks += len;
		}
	} else {
		res = hfsplus_add_extent(hip->cached_extents,
					 hip->alloc_blocks - hip->cached_start,
					 start, len);
		if (!res) {
			hfsplus_dump_extent(hip->cached_extents);
			hip->extent_state |= HFSPLUS_EXT_DIRTY;
			hip->cached_blocks += len;
		} else if (res == -ENOSPC)
			goto insert_extent;
	}
out:
	if (!res) {
		hip->alloc_blocks += len;
		mutex_unlock(&hip->extents_lock);
		hfsplus_mark_inode_dirty(inode, HFSPLUS_I_ALLOC_DIRTY);
		return 0;
	}
	mutex_unlock(&hip->extents_lock);
	return res;

insert_extent:
	hfs_dbg(EXTENT, "insert new extent\n");
	res = hfsplus_ext_write_extent_locked(inode);
	if (res)
		goto out;

	memset(hip->cached_extents, 0, sizeof(hfsplus_extent_rec));
	hip->cached_extents[0].start_block = cpu_to_be32(start);
	hip->cached_extents[0].block_count = cpu_to_be32(len);
	hfsplus_dump_extent(hip->cached_extents);
	hip->extent_state |= HFSPLUS_EXT_DIRTY | HFSPLUS_EXT_NEW;
	hip->cached_start = hip->alloc_blocks;
	hip->cached_blocks = len;

	res = 0;
	goto out;
}

void hfsplus_file_truncate(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
	struct hfs_find_data fd;
	u32 alloc_cnt, blk_cnt, start;
	int res;

	hfs_dbg(INODE, "truncate: %lu, %llu -> %llu\n",
		inode->i_ino, (long long)hip->phys_size, inode->i_size);

	if (inode->i_size > hip->phys_size) {
		struct address_space *mapping = inode->i_mapping;
		struct page *page;
		void *fsdata;
		loff_t size = inode->i_size;

		res = pagecache_write_begin(NULL, mapping, size, 0,
						AOP_FLAG_UNINTERRUPTIBLE,
						&page, &fsdata);
		if (res)
			return;
		res = pagecache_write_end(NULL, mapping, size,
			0, 0, page, fsdata);
		if (res < 0)
			return;
		mark_inode_dirty(inode);
		return;
	} else if (inode->i_size == hip->phys_size)
		return;

	blk_cnt = (inode->i_size + HFSPLUS_SB(sb)->alloc_blksz - 1) >>
			HFSPLUS_SB(sb)->alloc_blksz_shift;

	mutex_lock(&hip->extents_lock);

	alloc_cnt = hip->alloc_blocks;
	if (blk_cnt == alloc_cnt)
		goto out_unlock;

	res = hfs_find_init(HFSPLUS_SB(sb)->ext_tree, &fd);
	if (res) {
		mutex_unlock(&hip->extents_lock);
		/* XXX: We lack error handling of hfsplus_file_truncate() */
		return;
	}
	while (1) {
		if (alloc_cnt == hip->first_blocks) {
			hfsplus_free_extents(sb, hip->first_extents,
					     alloc_cnt, alloc_cnt - blk_cnt);
			hfsplus_dump_extent(hip->first_extents);
			hip->first_blocks = blk_cnt;
			break;
		}
		res = __hfsplus_ext_cache_extent(&fd, inode, alloc_cnt);
		if (res)
			break;
		start = hip->cached_start;
		hfsplus_free_extents(sb, hip->cached_extents,
				     alloc_cnt - start, alloc_cnt - blk_cnt);
		hfsplus_dump_extent(hip->cached_extents);
		if (blk_cnt > start) {
			hip->extent_state |= HFSPLUS_EXT_DIRTY;
			break;
		}
		alloc_cnt = start;
		hip->cached_start = hip->cached_blocks = 0;
		hip->extent_state &= ~(HFSPLUS_EXT_DIRTY | HFSPLUS_EXT_NEW);
		hfs_brec_remove(&fd);
	}
	hfs_find_exit(&fd);

	hip->alloc_blocks = blk_cnt;
out_unlock:
	mutex_unlock(&hip->extents_lock);
	hip->phys_size = inode->i_size;
	hip->fs_blocks = (inode->i_size + sb->s_blocksize - 1) >>
		sb->s_blocksize_bits;
	inode_set_bytes(inode, hip->fs_blocks << sb->s_blocksize_bits);
	hfsplus_mark_inode_dirty(inode, HFSPLUS_I_ALLOC_DIRTY);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/extents.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/catalog.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handling of catalog records
 */


// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"

int hfsplus_cat_case_cmp_key(const hfsplus_btree_key *k1,
			     const hfsplus_btree_key *k2)
{
	__be32 k1p, k2p;

	k1p = k1->cat.parent;
	k2p = k2->cat.parent;
	if (k1p != k2p)
		return be32_to_cpu(k1p) < be32_to_cpu(k2p) ? -1 : 1;

	return hfsplus_strcasecmp(&k1->cat.name, &k2->cat.name);
}

int hfsplus_cat_bin_cmp_key(const hfsplus_btree_key *k1,
			    const hfsplus_btree_key *k2)
{
	__be32 k1p, k2p;

	k1p = k1->cat.parent;
	k2p = k2->cat.parent;
	if (k1p != k2p)
		return be32_to_cpu(k1p) < be32_to_cpu(k2p) ? -1 : 1;

	return hfsplus_strcmp(&k1->cat.name, &k2->cat.name);
}

/* Generates key for catalog file/folders record. */
int hfsplus_cat_build_key(struct super_block *sb,
		hfsplus_btree_key *key, u32 parent, struct qstr *str)
{
	int len, err;

	key->cat.parent = cpu_to_be32(parent);
	err = hfsplus_asc2uni(sb, &key->cat.name, HFSPLUS_MAX_STRLEN,
			str->name, str->len);
	if (unlikely(err < 0))
		return err;

	len = be16_to_cpu(key->cat.name.length);
	key->key_len = cpu_to_be16(6 + 2 * len);
	return 0;
}

/* Generates key for catalog thread record. */
void hfsplus_cat_build_key_with_cnid(struct super_block *sb,
			hfsplus_btree_key *key, u32 parent)
{
	key->cat.parent = cpu_to_be32(parent);
	key->cat.name.length = 0;
	key->key_len = cpu_to_be16(6);
}

static void hfsplus_cat_build_key_uni(hfsplus_btree_key *key, u32 parent,
				      struct hfsplus_unistr *name)
{
	int ustrlen;

	ustrlen = be16_to_cpu(name->length);
	key->cat.parent = cpu_to_be32(parent);
	key->cat.name.length = cpu_to_be16(ustrlen);
	ustrlen *= 2;
	memcpy(key->cat.name.unicode, name->unicode, ustrlen);
	key->key_len = cpu_to_be16(6 + ustrlen);
}

void hfsplus_cat_set_perms(struct inode *inode, struct hfsplus_perm *perms)
{
	if (inode->i_flags & S_IMMUTABLE)
		perms->rootflags |= HFSPLUS_FLG_IMMUTABLE;
	else
		perms->rootflags &= ~HFSPLUS_FLG_IMMUTABLE;
	if (inode->i_flags & S_APPEND)
		perms->rootflags |= HFSPLUS_FLG_APPEND;
	else
		perms->rootflags &= ~HFSPLUS_FLG_APPEND;

	perms->userflags = HFSPLUS_I(inode)->userflags;
	perms->mode = cpu_to_be16(inode->i_mode);
	perms->owner = cpu_to_be32(i_uid_read(inode));
	perms->group = cpu_to_be32(i_gid_read(inode));

	if (S_ISREG(inode->i_mode))
		perms->dev = cpu_to_be32(inode->i_nlink);
	else if (S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode))
		perms->dev = cpu_to_be32(inode->i_rdev);
	else
		perms->dev = 0;
}

static int hfsplus_cat_build_record(hfsplus_cat_entry *entry,
		u32 cnid, struct inode *inode)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(inode->i_sb);

	if (S_ISDIR(inode->i_mode)) {
		struct hfsplus_cat_folder *folder;

		folder = &entry->folder;
		memset(folder, 0, sizeof(*folder));
		folder->type = cpu_to_be16(HFSPLUS_FOLDER);
		if (test_bit(HFSPLUS_SB_HFSX, &sbi->flags))
			folder->flags |= cpu_to_be16(HFSPLUS_HAS_FOLDER_COUNT);
		folder->id = cpu_to_be32(inode->i_ino);
		HFSPLUS_I(inode)->create_date =
			folder->create_date =
			folder->content_mod_date =
			folder->attribute_mod_date =
			folder->access_date = hfsp_now2mt();
		hfsplus_cat_set_perms(inode, &folder->permissions);
		if (inode == sbi->hidden_dir)
			/* invisible and namelocked */
			folder->user_info.frFlags = cpu_to_be16(0x5000);
		return sizeof(*folder);
	} else {
		struct hfsplus_cat_file *file;

		file = &entry->file;
		memset(file, 0, sizeof(*file));
		file->type = cpu_to_be16(HFSPLUS_FILE);
		file->flags = cpu_to_be16(HFSPLUS_FILE_THREAD_EXISTS);
		file->id = cpu_to_be32(cnid);
		HFSPLUS_I(inode)->create_date =
			file->create_date =
			file->content_mod_date =
			file->attribute_mod_date =
			file->access_date = hfsp_now2mt();
		if (cnid == inode->i_ino) {
			hfsplus_cat_set_perms(inode, &file->permissions);
			if (S_ISLNK(inode->i_mode)) {
				file->user_info.fdType =
					cpu_to_be32(HFSP_SYMLINK_TYPE);
				file->user_info.fdCreator =
					cpu_to_be32(HFSP_SYMLINK_CREATOR);
			} else {
				file->user_info.fdType =
					cpu_to_be32(sbi->type);
				file->user_info.fdCreator =
					cpu_to_be32(sbi->creator);
			}
			if (HFSPLUS_FLG_IMMUTABLE &
					(file->permissions.rootflags |
					file->permissions.userflags))
				file->flags |=
					cpu_to_be16(HFSPLUS_FILE_LOCKED);
		} else {
			file->user_info.fdType =
				cpu_to_be32(HFSP_HARDLINK_TYPE);
			file->user_info.fdCreator =
				cpu_to_be32(HFSP_HFSPLUS_CREATOR);
			file->user_info.fdFlags =
				cpu_to_be16(0x100);
			file->create_date =
				HFSPLUS_I(sbi->hidden_dir)->create_date;
			file->permissions.dev =
				cpu_to_be32(HFSPLUS_I(inode)->linkid);
		}
		return sizeof(*file);
	}
}

static int hfsplus_fill_cat_thread(struct super_block *sb,
				   hfsplus_cat_entry *entry, int type,
				   u32 parentid, struct qstr *str)
{
	int err;

	entry->type = cpu_to_be16(type);
	entry->thread.reserved = 0;
	entry->thread.parentID = cpu_to_be32(parentid);
	err = hfsplus_asc2uni(sb, &entry->thread.nodeName, HFSPLUS_MAX_STRLEN,
				str->name, str->len);
	if (unlikely(err < 0))
		return err;

	return 10 + be16_to_cpu(entry->thread.nodeName.length) * 2;
}

/* Try to get a catalog entry for given catalog id */
int hfsplus_find_cat(struct super_block *sb, u32 cnid,
		     struct hfs_find_data *fd)
{
	hfsplus_cat_entry tmp;
	int err;
	u16 type;

	hfsplus_cat_build_key_with_cnid(sb, fd->search_key, cnid);
	err = hfs_brec_read(fd, &tmp, sizeof(hfsplus_cat_entry));
	if (err)
		return err;

	type = be16_to_cpu(tmp.type);
	if (type != HFSPLUS_FOLDER_THREAD && type != HFSPLUS_FILE_THREAD) {
		pr_err("found bad thread record in catalog\n");
		return -EIO;
	}

	if (be16_to_cpu(tmp.thread.nodeName.length) > 255) {
		pr_err("catalog name length corrupted\n");
		return -EIO;
	}

	hfsplus_cat_build_key_uni(fd->search_key,
		be32_to_cpu(tmp.thread.parentID),
		&tmp.thread.nodeName);
	return hfs_brec_find(fd, hfs_find_rec_by_key);
}

static void hfsplus_subfolders_inc(struct inode *dir)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(dir->i_sb);

	if (test_bit(HFSPLUS_SB_HFSX, &sbi->flags)) {
		/*
		 * Increment subfolder count. Note, the value is only meaningful
		 * for folders with HFSPLUS_HAS_FOLDER_COUNT flag set.
		 */
		HFSPLUS_I(dir)->subfolders++;
	}
}

static void hfsplus_subfolders_dec(struct inode *dir)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(dir->i_sb);

	if (test_bit(HFSPLUS_SB_HFSX, &sbi->flags)) {
		/*
		 * Decrement subfolder count. Note, the value is only meaningful
		 * for folders with HFSPLUS_HAS_FOLDER_COUNT flag set.
		 *
		 * Check for zero. Some subfolders may have been created
		 * by an implementation ignorant of this counter.
		 */
		if (HFSPLUS_I(dir)->subfolders)
			HFSPLUS_I(dir)->subfolders--;
	}
}

int hfsplus_create_cat(u32 cnid, struct inode *dir,
		struct qstr *str, struct inode *inode)
{
	struct super_block *sb = dir->i_sb;
	struct hfs_find_data fd;
	hfsplus_cat_entry entry;
	int entry_size;
	int err;

	hfs_dbg(CAT_MOD, "create_cat: %s,%u(%d)\n",
		str->name, cnid, inode->i_nlink);
	err = hfs_find_init(HFSPLUS_SB(sb)->cat_tree, &fd);
	if (err)
		return err;

	hfsplus_cat_build_key_with_cnid(sb, fd.search_key, cnid);
	entry_size = hfsplus_fill_cat_thread(sb, &entry,
		S_ISDIR(inode->i_mode) ?
			HFSPLUS_FOLDER_THREAD : HFSPLUS_FILE_THREAD,
		dir->i_ino, str);
	if (unlikely(entry_size < 0)) {
		err = entry_size;
		goto err2;
	}

	err = hfs_brec_find(&fd, hfs_find_rec_by_key);
	if (err != -ENOENT) {
		if (!err)
			err = -EEXIST;
		goto err2;
	}
	err = hfs_brec_insert(&fd, &entry, entry_size);
	if (err)
		goto err2;

	err = hfsplus_cat_build_key(sb, fd.search_key, dir->i_ino, str);
	if (unlikely(err))
		goto err1;

	entry_size = hfsplus_cat_build_record(&entry, cnid, inode);
	err = hfs_brec_find(&fd, hfs_find_rec_by_key);
	if (err != -ENOENT) {
		/* panic? */
		if (!err)
			err = -EEXIST;
		goto err1;
	}
	err = hfs_brec_insert(&fd, &entry, entry_size);
	if (err)
		goto err1;

	dir->i_size++;
	if (S_ISDIR(inode->i_mode))
		hfsplus_subfolders_inc(dir);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	hfsplus_mark_inode_dirty(dir, HFSPLUS_I_CAT_DIRTY);

	hfs_find_exit(&fd);
	return 0;

err1:
	hfsplus_cat_build_key_with_cnid(sb, fd.search_key, cnid);
	if (!hfs_brec_find(&fd, hfs_find_rec_by_key))
		hfs_brec_remove(&fd);
err2:
	hfs_find_exit(&fd);
	return err;
}

int hfsplus_delete_cat(u32 cnid, struct inode *dir, struct qstr *str)
{
	struct super_block *sb = dir->i_sb;
	struct hfs_find_data fd;
	struct hfsplus_fork_raw fork;
	struct list_head *pos;
	int err, off;
	u16 type;

	hfs_dbg(CAT_MOD, "delete_cat: %s,%u\n", str ? str->name : NULL, cnid);
	err = hfs_find_init(HFSPLUS_SB(sb)->cat_tree, &fd);
	if (err)
		return err;

	if (!str) {
		int len;

		hfsplus_cat_build_key_with_cnid(sb, fd.search_key, cnid);
		err = hfs_brec_find(&fd, hfs_find_rec_by_key);
		if (err)
			goto out;

		off = fd.entryoffset +
			offsetof(struct hfsplus_cat_thread, nodeName);
		fd.search_key->cat.parent = cpu_to_be32(dir->i_ino);
		hfs_bnode_read(fd.bnode,
			&fd.search_key->cat.name.length, off, 2);
		len = be16_to_cpu(fd.search_key->cat.name.length) * 2;
		hfs_bnode_read(fd.bnode,
			&fd.search_key->cat.name.unicode,
			off + 2, len);
		fd.search_key->key_len = cpu_to_be16(6 + len);
	} else
		err = hfsplus_cat_build_key(sb, fd.search_key, dir->i_ino, str);
		if (unlikely(err))
			goto out;

	err = hfs_brec_find(&fd, hfs_find_rec_by_key);
	if (err)
		goto out;

	type = hfs_bnode_read_u16(fd.bnode, fd.entryoffset);
	if (type == HFSPLUS_FILE) {
#if 0
		off = fd.entryoffset + offsetof(hfsplus_cat_file, data_fork);
		hfs_bnode_read(fd.bnode, &fork, off, sizeof(fork));
		hfsplus_free_fork(sb, cnid, &fork, HFSPLUS_TYPE_DATA);
#endif

		off = fd.entryoffset +
			offsetof(struct hfsplus_cat_file, rsrc_fork);
		hfs_bnode_read(fd.bnode, &fork, off, sizeof(fork));
		hfsplus_free_fork(sb, cnid, &fork, HFSPLUS_TYPE_RSRC);
	}

	list_for_each(pos, &HFSPLUS_I(dir)->open_dir_list) {
		struct hfsplus_readdir_data *rd =
			list_entry(pos, struct hfsplus_readdir_data, list);
		if (fd.tree->keycmp(fd.search_key, (void *)&rd->key) < 0)
			rd->file->f_pos--;
	}

	err = hfs_brec_remove(&fd);
	if (err)
		goto out;

	hfsplus_cat_build_key_with_cnid(sb, fd.search_key, cnid);
	err = hfs_brec_find(&fd, hfs_find_rec_by_key);
	if (err)
		goto out;

	err = hfs_brec_remove(&fd);
	if (err)
		goto out;

	dir->i_size--;
	if (type == HFSPLUS_FOLDER)
		hfsplus_subfolders_dec(dir);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME_SEC;
	hfsplus_mark_inode_dirty(dir, HFSPLUS_I_CAT_DIRTY);

	if (type == HFSPLUS_FILE || type == HFSPLUS_FOLDER) {
		if (HFSPLUS_SB(sb)->attr_tree)
			hfsplus_delete_all_attrs(dir, cnid);
	}

out:
	hfs_find_exit(&fd);

	return err;
}

int hfsplus_rename_cat(u32 cnid,
		       struct inode *src_dir, struct qstr *src_name,
		       struct inode *dst_dir, struct qstr *dst_name)
{
	struct super_block *sb = src_dir->i_sb;
	struct hfs_find_data src_fd, dst_fd;
	hfsplus_cat_entry entry;
	int entry_size, type;
	int err;

	hfs_dbg(CAT_MOD, "rename_cat: %u - %lu,%s - %lu,%s\n",
		cnid, src_dir->i_ino, src_name->name,
		dst_dir->i_ino, dst_name->name);
	err = hfs_find_init(HFSPLUS_SB(sb)->cat_tree, &src_fd);
	if (err)
		return err;
	dst_fd = src_fd;

	/* find the old dir entry and read the data */
	err = hfsplus_cat_build_key(sb, src_fd.search_key,
			src_dir->i_ino, src_name);
	if (unlikely(err))
		goto out;

	err = hfs_brec_find(&src_fd, hfs_find_rec_by_key);
	if (err)
		goto out;
	if (src_fd.entrylength > sizeof(entry) || src_fd.entrylength < 0) {
		err = -EIO;
		goto out;
	}

	hfs_bnode_read(src_fd.bnode, &entry, src_fd.entryoffset,
				src_fd.entrylength);
	type = be16_to_cpu(entry.type);

	/* create new dir entry with the data from the old entry */
	err = hfsplus_cat_build_key(sb, dst_fd.search_key,
			dst_dir->i_ino, dst_name);
	if (unlikely(err))
		goto out;

	err = hfs_brec_find(&dst_fd, hfs_find_rec_by_key);
	if (err != -ENOENT) {
		if (!err)
			err = -EEXIST;
		goto out;
	}

	err = hfs_brec_insert(&dst_fd, &entry, src_fd.entrylength);
	if (err)
		goto out;
	dst_dir->i_size++;
	if (type == HFSPLUS_FOLDER)
		hfsplus_subfolders_inc(dst_dir);
	dst_dir->i_mtime = dst_dir->i_ctime = CURRENT_TIME_SEC;

	/* finally remove the old entry */
	err = hfsplus_cat_build_key(sb, src_fd.search_key,
			src_dir->i_ino, src_name);
	if (unlikely(err))
		goto out;

	err = hfs_brec_find(&src_fd, hfs_find_rec_by_key);
	if (err)
		goto out;
	err = hfs_brec_remove(&src_fd);
	if (err)
		goto out;
	src_dir->i_size--;
	if (type == HFSPLUS_FOLDER)
		hfsplus_subfolders_dec(src_dir);
	src_dir->i_mtime = src_dir->i_ctime = CURRENT_TIME_SEC;

	/* remove old thread entry */
	hfsplus_cat_build_key_with_cnid(sb, src_fd.search_key, cnid);
	err = hfs_brec_find(&src_fd, hfs_find_rec_by_key);
	if (err)
		goto out;
	type = hfs_bnode_read_u16(src_fd.bnode, src_fd.entryoffset);
	err = hfs_brec_remove(&src_fd);
	if (err)
		goto out;

	/* create new thread entry */
	hfsplus_cat_build_key_with_cnid(sb, dst_fd.search_key, cnid);
	entry_size = hfsplus_fill_cat_thread(sb, &entry, type,
		dst_dir->i_ino, dst_name);
	if (unlikely(entry_size < 0)) {
		err = entry_size;
		goto out;
	}

	err = hfs_brec_find(&dst_fd, hfs_find_rec_by_key);
	if (err != -ENOENT) {
		if (!err)
			err = -EEXIST;
		goto out;
	}
	err = hfs_brec_insert(&dst_fd, &entry, entry_size);

	hfsplus_mark_inode_dirty(dst_dir, HFSPLUS_I_CAT_DIRTY);
	hfsplus_mark_inode_dirty(src_dir, HFSPLUS_I_CAT_DIRTY);
out:
	hfs_bnode_put(dst_fd.bnode);
	hfs_find_exit(&src_fd);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/catalog.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/dir.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handling of directories
 */

// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/slab.h>
#include <linux/random.h>
// #include <linux/nls.h>
#include "../../inc/__fss.h"

// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"
// #include "xattr.h"
// #include "acl.h"

static inline void hfsplus_instantiate(struct dentry *dentry,
				       struct inode *inode, u32 cnid)
{
	dentry->d_fsdata = (void *)(unsigned long)cnid;
	d_instantiate(dentry, inode);
}

/* Find the entry inside dir named dentry->d_name */
static struct dentry *hfsplus_lookup(struct inode *dir, struct dentry *dentry,
				     unsigned int flags)
{
	struct inode *inode = NULL;
	struct hfs_find_data fd;
	struct super_block *sb;
	hfsplus_cat_entry entry;
	int err;
	u32 cnid, linkid = 0;
	u16 type;

	sb = dir->i_sb;

	dentry->d_fsdata = NULL;
	err = hfs_find_init(HFSPLUS_SB(sb)->cat_tree, &fd);
	if (err)
		return ERR_PTR(err);
	err = hfsplus_cat_build_key(sb, fd.search_key, dir->i_ino,
			&dentry->d_name);
	if (unlikely(err < 0))
		goto fail;
again:
	err = hfs_brec_read(&fd, &entry, sizeof(entry));
	if (err) {
		if (err == -ENOENT) {
			hfs_find_exit(&fd);
			/* No such entry */
			inode = NULL;
			goto out;
		}
		goto fail;
	}
	type = be16_to_cpu(entry.type);
	if (type == HFSPLUS_FOLDER) {
		if (fd.entrylength < sizeof(struct hfsplus_cat_folder)) {
			err = -EIO;
			goto fail;
		}
		cnid = be32_to_cpu(entry.folder.id);
		dentry->d_fsdata = (void *)(unsigned long)cnid;
	} else if (type == HFSPLUS_FILE) {
		if (fd.entrylength < sizeof(struct hfsplus_cat_file)) {
			err = -EIO;
			goto fail;
		}
		cnid = be32_to_cpu(entry.file.id);
		if (entry.file.user_info.fdType ==
				cpu_to_be32(HFSP_HARDLINK_TYPE) &&
				entry.file.user_info.fdCreator ==
				cpu_to_be32(HFSP_HFSPLUS_CREATOR) &&
				(entry.file.create_date ==
					HFSPLUS_I(HFSPLUS_SB(sb)->hidden_dir)->
						create_date ||
				entry.file.create_date ==
					HFSPLUS_I(sb->s_root->d_inode)->
						create_date) &&
				HFSPLUS_SB(sb)->hidden_dir) {
			struct qstr str;
			char name[32];

			if (dentry->d_fsdata) {
				/*
				 * We found a link pointing to another link,
				 * so ignore it and treat it as regular file.
				 */
				cnid = (unsigned long)dentry->d_fsdata;
				linkid = 0;
			} else {
				dentry->d_fsdata = (void *)(unsigned long)cnid;
				linkid =
					be32_to_cpu(entry.file.permissions.dev);
				str.len = sprintf(name, "iNode%d", linkid);
				str.name = name;
				err = hfsplus_cat_build_key(sb, fd.search_key,
					HFSPLUS_SB(sb)->hidden_dir->i_ino,
					&str);
				if (unlikely(err < 0))
					goto fail;
				goto again;
			}
		} else if (!dentry->d_fsdata)
			dentry->d_fsdata = (void *)(unsigned long)cnid;
	} else {
		pr_err("invalid catalog entry type in lookup\n");
		err = -EIO;
		goto fail;
	}
	hfs_find_exit(&fd);
	inode = hfsplus_iget(dir->i_sb, cnid);
	if (IS_ERR(inode))
		return ERR_CAST(inode);
	if (S_ISREG(inode->i_mode))
		HFSPLUS_I(inode)->linkid = linkid;
out:
	d_add(dentry, inode);
	return NULL;
fail:
	hfs_find_exit(&fd);
	return ERR_PTR(err);
}

static int hfsplus_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	int len, err;
	char *strbuf;
	hfsplus_cat_entry entry;
	struct hfs_find_data fd;
	struct hfsplus_readdir_data *rd;
	u16 type;

	if (file->f_pos >= inode->i_size)
		return 0;

	err = hfs_find_init(HFSPLUS_SB(sb)->cat_tree, &fd);
	if (err)
		return err;
	strbuf = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_MAX_STRLEN + 1, GFP_KERNEL);
	if (!strbuf) {
		err = -ENOMEM;
		goto out;
	}
	hfsplus_cat_build_key_with_cnid(sb, fd.search_key, inode->i_ino);
	err = hfs_brec_find(&fd, hfs_find_rec_by_key);
	if (err)
		goto out;

	if (ctx->pos == 0) {
		/* This is completely artificial... */
		if (!dir_emit_dot(file, ctx))
			goto out;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		if (fd.entrylength > sizeof(entry) || fd.entrylength < 0) {
			err = -EIO;
			goto out;
		}

		hfs_bnode_read(fd.bnode, &entry, fd.entryoffset,
			fd.entrylength);
		if (be16_to_cpu(entry.type) != HFSPLUS_FOLDER_THREAD) {
			pr_err("bad catalog folder thread\n");
			err = -EIO;
			goto out;
		}
		if (fd.entrylength < HFSPLUS_MIN_THREAD_SZ) {
			pr_err("truncated catalog thread\n");
			err = -EIO;
			goto out;
		}
		if (!dir_emit(ctx, "..", 2,
			    be32_to_cpu(entry.thread.parentID), DT_DIR))
			goto out;
		ctx->pos = 2;
	}
	if (ctx->pos >= inode->i_size)
		goto out;
	err = hfs_brec_goto(&fd, ctx->pos - 1);
	if (err)
		goto out;
	for (;;) {
		if (be32_to_cpu(fd.key->cat.parent) != inode->i_ino) {
			pr_err("walked past end of dir\n");
			err = -EIO;
			goto out;
		}

		if (fd.entrylength > sizeof(entry) || fd.entrylength < 0) {
			err = -EIO;
			goto out;
		}

		hfs_bnode_read(fd.bnode, &entry, fd.entryoffset,
			fd.entrylength);
		type = be16_to_cpu(entry.type);
		len = NLS_MAX_CHARSET_SIZE * HFSPLUS_MAX_STRLEN;
		err = hfsplus_uni2asc(sb, &fd.key->cat.name, strbuf, &len);
		if (err)
			goto out;
		if (type == HFSPLUS_FOLDER) {
			if (fd.entrylength <
					sizeof(struct hfsplus_cat_folder)) {
				pr_err("small dir entry\n");
				err = -EIO;
				goto out;
			}
			if (HFSPLUS_SB(sb)->hidden_dir &&
			    HFSPLUS_SB(sb)->hidden_dir->i_ino ==
					be32_to_cpu(entry.folder.id))
				goto next;
			if (!dir_emit(ctx, strbuf, len,
				    be32_to_cpu(entry.folder.id), DT_DIR))
				break;
		} else if (type == HFSPLUS_FILE) {
			u16 mode;
			unsigned type = DT_UNKNOWN;

			if (fd.entrylength < sizeof(struct hfsplus_cat_file)) {
				pr_err("small file entry\n");
				err = -EIO;
				goto out;
			}

			mode = be16_to_cpu(entry.file.permissions.mode);
			if (S_ISREG(mode))
				type = DT_REG;
			else if (S_ISLNK(mode))
				type = DT_LNK;
			else if (S_ISFIFO(mode))
				type = DT_FIFO;
			else if (S_ISCHR(mode))
				type = DT_CHR;
			else if (S_ISBLK(mode))
				type = DT_BLK;
			else if (S_ISSOCK(mode))
				type = DT_SOCK;

			if (!dir_emit(ctx, strbuf, len,
				      be32_to_cpu(entry.file.id), type))
				break;
		} else {
			pr_err("bad catalog entry type\n");
			err = -EIO;
			goto out;
		}
next:
		ctx->pos++;
		if (ctx->pos >= inode->i_size)
			goto out;
		err = hfs_brec_goto(&fd, 1);
		if (err)
			goto out;
	}
	rd = file->private_data;
	if (!rd) {
		rd = kmalloc(sizeof(struct hfsplus_readdir_data), GFP_KERNEL);
		if (!rd) {
			err = -ENOMEM;
			goto out;
		}
		file->private_data = rd;
		rd->file = file;
		list_add(&rd->list, &HFSPLUS_I(inode)->open_dir_list);
	}
	memcpy(&rd->key, fd.key, sizeof(struct hfsplus_cat_key));
out:
	kfree(strbuf);
	hfs_find_exit(&fd);
	return err;
}

static int hfsplus_dir_release(struct inode *inode, struct file *file)
{
	struct hfsplus_readdir_data *rd = file->private_data;
	if (rd) {
		mutex_lock(&inode->i_mutex);
		list_del(&rd->list);
		mutex_unlock(&inode->i_mutex);
		kfree(rd);
	}
	return 0;
}

static int hfsplus_link(struct dentry *src_dentry, struct inode *dst_dir,
			struct dentry *dst_dentry)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(dst_dir->i_sb);
	struct inode *inode = src_dentry->d_inode;
	struct inode *src_dir = src_dentry->d_parent->d_inode;
	struct qstr str;
	char name[32];
	u32 cnid, id;
	int res;

	if (HFSPLUS_IS_RSRC(inode))
		return -EPERM;
	if (!S_ISREG(inode->i_mode))
		return -EPERM;

	mutex_lock(&sbi->vh_mutex);
	if (inode->i_ino == (u32)(unsigned long)src_dentry->d_fsdata) {
		for (;;) {
			get_random_bytes(&id, sizeof(cnid));
			id &= 0x3fffffff;
			str.name = name;
			str.len = sprintf(name, "iNode%d", id);
			res = hfsplus_rename_cat(inode->i_ino,
						 src_dir, &src_dentry->d_name,
						 sbi->hidden_dir, &str);
			if (!res)
				break;
			if (res != -EEXIST)
				goto out;
		}
		HFSPLUS_I(inode)->linkid = id;
		cnid = sbi->next_cnid++;
		src_dentry->d_fsdata = (void *)(unsigned long)cnid;
		res = hfsplus_create_cat(cnid, src_dir,
			&src_dentry->d_name, inode);
		if (res)
			/* panic? */
			goto out;
		sbi->file_count++;
	}
	cnid = sbi->next_cnid++;
	res = hfsplus_create_cat(cnid, dst_dir, &dst_dentry->d_name, inode);
	if (res)
		goto out;

	inc_nlink(inode);
	hfsplus_instantiate(dst_dentry, inode, cnid);
	ihold(inode);
	inode->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);
	sbi->file_count++;
	hfsplus_mark_mdb_dirty(dst_dir->i_sb);
out:
	mutex_unlock(&sbi->vh_mutex);
	return res;
}

static int hfsplus_unlink(struct inode *dir, struct dentry *dentry)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(dir->i_sb);
	struct inode *inode = dentry->d_inode;
	struct qstr str;
	char name[32];
	u32 cnid;
	int res;

	if (HFSPLUS_IS_RSRC(inode))
		return -EPERM;

	mutex_lock(&sbi->vh_mutex);
	cnid = (u32)(unsigned long)dentry->d_fsdata;
	if (inode->i_ino == cnid &&
	    atomic_read(&HFSPLUS_I(inode)->opencnt)) {
		str.name = name;
		str.len = sprintf(name, "temp%lu", inode->i_ino);
		res = hfsplus_rename_cat(inode->i_ino,
					 dir, &dentry->d_name,
					 sbi->hidden_dir, &str);
		if (!res) {
			inode->i_flags |= S_DEAD;
			drop_nlink(inode);
		}
		goto out;
	}
	res = hfsplus_delete_cat(cnid, dir, &dentry->d_name);
	if (res)
		goto out;

	if (inode->i_nlink > 0)
		drop_nlink(inode);
	if (inode->i_ino == cnid)
		clear_nlink(inode);
	if (!inode->i_nlink) {
		if (inode->i_ino != cnid) {
			sbi->file_count--;
			if (!atomic_read(&HFSPLUS_I(inode)->opencnt)) {
				res = hfsplus_delete_cat(inode->i_ino,
							 sbi->hidden_dir,
							 NULL);
				if (!res)
					hfsplus_delete_inode(inode);
			} else
				inode->i_flags |= S_DEAD;
		} else
			hfsplus_delete_inode(inode);
	} else
		sbi->file_count--;
	inode->i_ctime = CURRENT_TIME_SEC;
	mark_inode_dirty(inode);
out:
	mutex_unlock(&sbi->vh_mutex);
	return res;
}

static int hfsplus_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(dir->i_sb);
	struct inode *inode = dentry->d_inode;
	int res;

	if (inode->i_size != 2)
		return -ENOTEMPTY;

	mutex_lock(&sbi->vh_mutex);
	res = hfsplus_delete_cat(inode->i_ino, dir, &dentry->d_name);
	if (res)
		goto out;
	clear_nlink(inode);
	inode->i_ctime = CURRENT_TIME_SEC;
	hfsplus_delete_inode(inode);
	mark_inode_dirty(inode);
out:
	mutex_unlock(&sbi->vh_mutex);
	return res;
}

static int hfsplus_symlink(struct inode *dir, struct dentry *dentry,
			   const char *symname)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(dir->i_sb);
	struct inode *inode;
	int res = -ENOSPC;

	mutex_lock(&sbi->vh_mutex);
	inode = hfsplus_new_inode(dir->i_sb, S_IFLNK | S_IRWXUGO);
	if (!inode)
		goto out;

	res = page_symlink(inode, symname, strlen(symname) + 1);
	if (res)
		goto out_err;

	res = hfsplus_create_cat(inode->i_ino, dir, &dentry->d_name, inode);
	if (res)
		goto out_err;

	res = hfsplus_init_inode_security(inode, dir, &dentry->d_name);
	if (res == -EOPNOTSUPP)
		res = 0; /* Operation is not supported. */
	else if (res) {
		/* Try to delete anyway without error analysis. */
		hfsplus_delete_cat(inode->i_ino, dir, &dentry->d_name);
		goto out_err;
	}

	hfsplus_instantiate(dentry, inode, inode->i_ino);
	mark_inode_dirty(inode);
	goto out;

out_err:
	clear_nlink(inode);
	hfsplus_delete_inode(inode);
	iput(inode);
out:
	mutex_unlock(&sbi->vh_mutex);
	return res;
}

static int hfsplus_mknod(struct inode *dir, struct dentry *dentry,
			 umode_t mode, dev_t rdev)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(dir->i_sb);
	struct inode *inode;
	int res = -ENOSPC;

	mutex_lock(&sbi->vh_mutex);
	inode = hfsplus_new_inode(dir->i_sb, mode);
	if (!inode)
		goto out;

	if (S_ISBLK(mode) || S_ISCHR(mode) || S_ISFIFO(mode) || S_ISSOCK(mode))
		init_special_inode(inode, mode, rdev);

	res = hfsplus_create_cat(inode->i_ino, dir, &dentry->d_name, inode);
	if (res)
		goto failed_mknod;

	res = hfsplus_init_inode_security(inode, dir, &dentry->d_name);
	if (res == -EOPNOTSUPP)
		res = 0; /* Operation is not supported. */
	else if (res) {
		/* Try to delete anyway without error analysis. */
		hfsplus_delete_cat(inode->i_ino, dir, &dentry->d_name);
		goto failed_mknod;
	}

	hfsplus_instantiate(dentry, inode, inode->i_ino);
	mark_inode_dirty(inode);
	goto out;

failed_mknod:
	clear_nlink(inode);
	hfsplus_delete_inode(inode);
	iput(inode);
out:
	mutex_unlock(&sbi->vh_mutex);
	return res;
}

static int hfsplus_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			  bool excl)
{
	return hfsplus_mknod(dir, dentry, mode, 0);
}

static int hfsplus_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	return hfsplus_mknod(dir, dentry, mode | S_IFDIR, 0);
}

static int hfsplus_rename(struct inode *old_dir, struct dentry *old_dentry,
			  struct inode *new_dir, struct dentry *new_dentry)
{
	int res;

	/* Unlink destination if it already exists */
	if (new_dentry->d_inode) {
		if (d_is_dir(new_dentry))
			res = hfsplus_rmdir(new_dir, new_dentry);
		else
			res = hfsplus_unlink(new_dir, new_dentry);
		if (res)
			return res;
	}

	res = hfsplus_rename_cat((u32)(unsigned long)old_dentry->d_fsdata,
				 old_dir, &old_dentry->d_name,
				 new_dir, &new_dentry->d_name);
	if (!res)
		new_dentry->d_fsdata = old_dentry->d_fsdata;
	return res;
}

const struct inode_operations hfsplus_dir_inode_operations = {
	.lookup			= hfsplus_lookup,
	.create			= hfsplus_create,
	.link			= hfsplus_link,
	.unlink			= hfsplus_unlink,
	.mkdir			= hfsplus_mkdir,
	.rmdir			= hfsplus_rmdir,
	.symlink		= hfsplus_symlink,
	.mknod			= hfsplus_mknod,
	.rename			= hfsplus_rename,
	.setxattr		= generic_setxattr,
	.getxattr		= generic_getxattr,
	.listxattr		= hfsplus_listxattr,
	.removexattr		= generic_removexattr,
#ifdef CONFIG_HFSPLUS_FS_POSIX_ACL
	.get_acl		= hfsplus_get_posix_acl,
	.set_acl		= hfsplus_set_posix_acl,
#endif
};

const struct file_operations hfsplus_dir_operations = {
	.fsync		= hfsplus_file_fsync,
	.read		= generic_read_dir,
	.iterate	= hfsplus_readdir,
	.unlocked_ioctl = hfsplus_ioctl,
	.llseek		= generic_file_llseek,
	.release	= hfsplus_dir_release,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/dir.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/btree.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handle opening/closing btree
 */

// #include <linux/slab.h>
// #include <linux/pagemap.h>
#include <linux/log2.h>
#include "../../inc/__fss.h"

// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"

/*
 * Initial source code of clump size calculation is gotten
 * from http://opensource.apple.com/tarballs/diskdev_cmds/
 */
#define CLUMP_ENTRIES	15

static short clumptbl[CLUMP_ENTRIES * 3] = {
/*
 *	    Volume	Attributes	 Catalog	 Extents
 *	     Size	Clump (MB)	Clump (MB)	Clump (MB)
 */
	/*   1GB */	  4,		  4,		 4,
	/*   2GB */	  6,		  6,		 4,
	/*   4GB */	  8,		  8,		 4,
	/*   8GB */	 11,		 11,		 5,
	/*
	 * For volumes 16GB and larger, we want to make sure that a full OS
	 * install won't require fragmentation of the Catalog or Attributes
	 * B-trees.  We do this by making the clump sizes sufficiently large,
	 * and by leaving a gap after the B-trees for them to grow into.
	 *
	 * For SnowLeopard 10A298, a FullNetInstall with all packages selected
	 * results in:
	 * Catalog B-tree Header
	 *	nodeSize:          8192
	 *	totalNodes:       31616
	 *	freeNodes:         1978
	 * (used = 231.55 MB)
	 * Attributes B-tree Header
	 *	nodeSize:          8192
	 *	totalNodes:       63232
	 *	freeNodes:          958
	 * (used = 486.52 MB)
	 *
	 * We also want Time Machine backup volumes to have a sufficiently
	 * large clump size to reduce fragmentation.
	 *
	 * The series of numbers for Catalog and Attribute form a geometric
	 * series. For Catalog (16GB to 512GB), each term is 8**(1/5) times
	 * the previous term.  For Attributes (16GB to 512GB), each term is
	 * 4**(1/5) times the previous term.  For 1TB to 16TB, each term is
	 * 2**(1/5) times the previous term.
	 */
	/*  16GB */	 64,		 32,		 5,
	/*  32GB */	 84,		 49,		 6,
	/*  64GB */	111,		 74,		 7,
	/* 128GB */	147,		111,		 8,
	/* 256GB */	194,		169,		 9,
	/* 512GB */	256,		256,		11,
	/*   1TB */	294,		294,		14,
	/*   2TB */	338,		338,		16,
	/*   4TB */	388,		388,		20,
	/*   8TB */	446,		446,		25,
	/*  16TB */	512,		512,		32
};

u32 hfsplus_calc_btree_clump_size(u32 block_size, u32 node_size,
					u64 sectors, int file_id)
{
	u32 mod = max(node_size, block_size);
	u32 clump_size;
	int column;
	int i;

	/* Figure out which column of the above table to use for this file. */
	switch (file_id) {
	case HFSPLUS_ATTR_CNID:
		column = 0;
		break;
	case HFSPLUS_CAT_CNID:
		column = 1;
		break;
	default:
		column = 2;
		break;
	}

	/*
	 * The default clump size is 0.8% of the volume size. And
	 * it must also be a multiple of the node and block size.
	 */
	if (sectors < 0x200000) {
		clump_size = sectors << 2;	/*  0.8 %  */
		if (clump_size < (8 * node_size))
			clump_size = 8 * node_size;
	} else {
		/* turn exponent into table index... */
		for (i = 0, sectors = sectors >> 22;
		     sectors && (i < CLUMP_ENTRIES - 1);
		     ++i, sectors = sectors >> 1) {
			/* empty body */
		}

		clump_size = clumptbl[column + (i) * 3] * 1024 * 1024;
	}

	/*
	 * Round the clump size to a multiple of node and block size.
	 * NOTE: This rounds down.
	 */
	clump_size /= mod;
	clump_size *= mod;

	/*
	 * Rounding down could have rounded down to 0 if the block size was
	 * greater than the clump size.  If so, just use one block or node.
	 */
	if (clump_size == 0)
		clump_size = mod;

	return clump_size;
}

/* Get a reference to a B*Tree and do some initial checks */
struct hfs_btree *hfs_btree_open(struct super_block *sb, u32 id)
{
	struct hfs_btree *tree;
	struct hfs_btree_header_rec *head;
	struct address_space *mapping;
	struct inode *inode;
	struct page *page;
	unsigned int size;

	tree = kzalloc(sizeof(*tree), GFP_KERNEL);
	if (!tree)
		return NULL;

	mutex_init(&tree->tree_lock);
	spin_lock_init(&tree->hash_lock);
	tree->sb = sb;
	tree->cnid = id;
	inode = hfsplus_iget(sb, id);
	if (IS_ERR(inode))
		goto free_tree;
	tree->inode = inode;

	if (!HFSPLUS_I(tree->inode)->first_blocks) {
		pr_err("invalid btree extent records (0 size)\n");
		goto free_inode;
	}

	mapping = tree->inode->i_mapping;
	page = read_mapping_page(mapping, 0, NULL);
	if (IS_ERR(page))
		goto free_inode;

	/* Load the header */
	head = (struct hfs_btree_header_rec *)(kmap(page) +
		sizeof(struct hfs_bnode_desc));
	tree->root = be32_to_cpu(head->root);
	tree->leaf_count = be32_to_cpu(head->leaf_count);
	tree->leaf_head = be32_to_cpu(head->leaf_head);
	tree->leaf_tail = be32_to_cpu(head->leaf_tail);
	tree->node_count = be32_to_cpu(head->node_count);
	tree->free_nodes = be32_to_cpu(head->free_nodes);
	tree->attributes = be32_to_cpu(head->attributes);
	tree->node_size = be16_to_cpu(head->node_size);
	tree->max_key_len = be16_to_cpu(head->max_key_len);
	tree->depth = be16_to_cpu(head->depth);

	/* Verify the tree and set the correct compare function */
	switch (id) {
	case HFSPLUS_EXT_CNID:
		if (tree->max_key_len != HFSPLUS_EXT_KEYLEN - sizeof(u16)) {
			pr_err("invalid extent max_key_len %d\n",
				tree->max_key_len);
			goto fail_page;
		}
		if (tree->attributes & HFS_TREE_VARIDXKEYS) {
			pr_err("invalid extent btree flag\n");
			goto fail_page;
		}

		tree->keycmp = hfsplus_ext_cmp_key;
		break;
	case HFSPLUS_CAT_CNID:
		if (tree->max_key_len != HFSPLUS_CAT_KEYLEN - sizeof(u16)) {
			pr_err("invalid catalog max_key_len %d\n",
				tree->max_key_len);
			goto fail_page;
		}
		if (!(tree->attributes & HFS_TREE_VARIDXKEYS)) {
			pr_err("invalid catalog btree flag\n");
			goto fail_page;
		}

		if (test_bit(HFSPLUS_SB_HFSX, &HFSPLUS_SB(sb)->flags) &&
		    (head->key_type == HFSPLUS_KEY_BINARY))
			tree->keycmp = hfsplus_cat_bin_cmp_key;
		else {
			tree->keycmp = hfsplus_cat_case_cmp_key;
			set_bit(HFSPLUS_SB_CASEFOLD, &HFSPLUS_SB(sb)->flags);
		}
		break;
	case HFSPLUS_ATTR_CNID:
		if (tree->max_key_len != HFSPLUS_ATTR_KEYLEN - sizeof(u16)) {
			pr_err("invalid attributes max_key_len %d\n",
				tree->max_key_len);
			goto fail_page;
		}
		tree->keycmp = hfsplus_attr_bin_cmp_key;
		break;
	default:
		pr_err("unknown B*Tree requested\n");
		goto fail_page;
	}

	if (!(tree->attributes & HFS_TREE_BIGKEYS)) {
		pr_err("invalid btree flag\n");
		goto fail_page;
	}

	size = tree->node_size;
	if (!is_power_of_2(size))
		goto fail_page;
	if (!tree->node_count)
		goto fail_page;

	tree->node_size_shift = ffs(size) - 1;

	tree->pages_per_bnode =
		(tree->node_size + PAGE_CACHE_SIZE - 1) >>
		PAGE_CACHE_SHIFT;

	kunmap(page);
	page_cache_release(page);
	return tree;

 fail_page:
	page_cache_release(page);
 free_inode:
	tree->inode->i_mapping->a_ops = &hfsplus_aops;
	iput(tree->inode);
 free_tree:
	kfree(tree);
	return NULL;
}

/* Release resources used by a btree */
void hfs_btree_close(struct hfs_btree *tree)
{
	struct hfs_bnode *node;
	int i;

	if (!tree)
		return;

	for (i = 0; i < NODE_HASH_SIZE; i++) {
		while ((node = tree->node_hash[i])) {
			tree->node_hash[i] = node->next_hash;
			if (atomic_read(&node->refcnt))
				pr_crit("node %d:%d "
						"still has %d user(s)!\n",
					node->tree->cnid, node->this,
					atomic_read(&node->refcnt));
			hfs_bnode_free(node);
			tree->node_hash_cnt--;
		}
	}
	iput(tree->inode);
	kfree(tree);
}

int hfs_btree_write(struct hfs_btree *tree)
{
	struct hfs_btree_header_rec *head;
	struct hfs_bnode *node;
	struct page *page;

	node = hfs_bnode_find(tree, 0);
	if (IS_ERR(node))
		/* panic? */
		return -EIO;
	/* Load the header */
	page = node->page[0];
	head = (struct hfs_btree_header_rec *)(kmap(page) +
		sizeof(struct hfs_bnode_desc));

	head->root = cpu_to_be32(tree->root);
	head->leaf_count = cpu_to_be32(tree->leaf_count);
	head->leaf_head = cpu_to_be32(tree->leaf_head);
	head->leaf_tail = cpu_to_be32(tree->leaf_tail);
	head->node_count = cpu_to_be32(tree->node_count);
	head->free_nodes = cpu_to_be32(tree->free_nodes);
	head->attributes = cpu_to_be32(tree->attributes);
	head->depth = cpu_to_be16(tree->depth);

	kunmap(page);
	set_page_dirty(page);
	hfs_bnode_put(node);
	return 0;
}

static struct hfs_bnode *hfs_bmap_new_bmap(struct hfs_bnode *prev, u32 idx)
{
	struct hfs_btree *tree = prev->tree;
	struct hfs_bnode *node;
	struct hfs_bnode_desc desc;
	__be32 cnid;

	node = hfs_bnode_create(tree, idx);
	if (IS_ERR(node))
		return node;

	tree->free_nodes--;
	prev->next = idx;
	cnid = cpu_to_be32(idx);
	hfs_bnode_write(prev, &cnid, offsetof(struct hfs_bnode_desc, next), 4);

	node->type = HFS_NODE_MAP;
	node->num_recs = 1;
	hfs_bnode_clear(node, 0, tree->node_size);
	desc.next = 0;
	desc.prev = 0;
	desc.type = HFS_NODE_MAP;
	desc.height = 0;
	desc.num_recs = cpu_to_be16(1);
	desc.reserved = 0;
	hfs_bnode_write(node, &desc, 0, sizeof(desc));
	hfs_bnode_write_u16(node, 14, 0x8000);
	hfs_bnode_write_u16(node, tree->node_size - 2, 14);
	hfs_bnode_write_u16(node, tree->node_size - 4, tree->node_size - 6);

	return node;
}

struct hfs_bnode *hfs_bmap_alloc(struct hfs_btree *tree)
{
	struct hfs_bnode *node, *next_node;
	struct page **pagep;
	u32 nidx, idx;
	unsigned off;
	u16 off16;
	u16 len;
	u8 *data, byte, m;
	int i;

	while (!tree->free_nodes) {
		struct inode *inode = tree->inode;
		struct hfsplus_inode_info *hip = HFSPLUS_I(inode);
		u32 count;
		int res;

		res = hfsplus_file_extend(inode, hfs_bnode_need_zeroout(tree));
		if (res)
			return ERR_PTR(res);
		hip->phys_size = inode->i_size =
			(loff_t)hip->alloc_blocks <<
				HFSPLUS_SB(tree->sb)->alloc_blksz_shift;
		hip->fs_blocks =
			hip->alloc_blocks << HFSPLUS_SB(tree->sb)->fs_shift;
		inode_set_bytes(inode, inode->i_size);
		count = inode->i_size >> tree->node_size_shift;
		tree->free_nodes = count - tree->node_count;
		tree->node_count = count;
	}

	nidx = 0;
	node = hfs_bnode_find(tree, nidx);
	if (IS_ERR(node))
		return node;
	len = hfs_brec_lenoff(node, 2, &off16);
	off = off16;

	off += node->page_offset;
	pagep = node->page + (off >> PAGE_CACHE_SHIFT);
	data = kmap(*pagep);
	off &= ~PAGE_CACHE_MASK;
	idx = 0;

	for (;;) {
		while (len) {
			byte = data[off];
			if (byte != 0xff) {
				for (m = 0x80, i = 0; i < 8; m >>= 1, i++) {
					if (!(byte & m)) {
						idx += i;
						data[off] |= m;
						set_page_dirty(*pagep);
						kunmap(*pagep);
						tree->free_nodes--;
						mark_inode_dirty(tree->inode);
						hfs_bnode_put(node);
						return hfs_bnode_create(tree,
							idx);
					}
				}
			}
			if (++off >= PAGE_CACHE_SIZE) {
				kunmap(*pagep);
				data = kmap(*++pagep);
				off = 0;
			}
			idx += 8;
			len--;
		}
		kunmap(*pagep);
		nidx = node->next;
		if (!nidx) {
			hfs_dbg(BNODE_MOD, "create new bmap node\n");
			next_node = hfs_bmap_new_bmap(node, idx);
		} else
			next_node = hfs_bnode_find(tree, nidx);
		hfs_bnode_put(node);
		if (IS_ERR(next_node))
			return next_node;
		node = next_node;

		len = hfs_brec_lenoff(node, 0, &off16);
		off = off16;
		off += node->page_offset;
		pagep = node->page + (off >> PAGE_CACHE_SHIFT);
		data = kmap(*pagep);
		off &= ~PAGE_CACHE_MASK;
	}
}

void hfs_bmap_free(struct hfs_bnode *node)
{
	struct hfs_btree *tree;
	struct page *page;
	u16 off, len;
	u32 nidx;
	u8 *data, byte, m;

	hfs_dbg(BNODE_MOD, "btree_free_node: %u\n", node->this);
	BUG_ON(!node->this);
	tree = node->tree;
	nidx = node->this;
	node = hfs_bnode_find(tree, 0);
	if (IS_ERR(node))
		return;
	len = hfs_brec_lenoff(node, 2, &off);
	while (nidx >= len * 8) {
		u32 i;

		nidx -= len * 8;
		i = node->next;
		hfs_bnode_put(node);
		if (!i) {
			/* panic */;
			pr_crit("unable to free bnode %u. "
					"bmap not found!\n",
				node->this);
			return;
		}
		node = hfs_bnode_find(tree, i);
		if (IS_ERR(node))
			return;
		if (node->type != HFS_NODE_MAP) {
			/* panic */;
			pr_crit("invalid bmap found! "
					"(%u,%d)\n",
				node->this, node->type);
			hfs_bnode_put(node);
			return;
		}
		len = hfs_brec_lenoff(node, 0, &off);
	}
	off += node->page_offset + nidx / 8;
	page = node->page[off >> PAGE_CACHE_SHIFT];
	data = kmap(page);
	off &= ~PAGE_CACHE_MASK;
	m = 1 << (~nidx & 7);
	byte = data[off];
	if (!(byte & m)) {
		pr_crit("trying to free free bnode "
				"%u(%d)\n",
			node->this, node->type);
		kunmap(page);
		hfs_bnode_put(node);
		return;
	}
	data[off] = byte & ~m;
	set_page_dirty(page);
	kunmap(page);
	hfs_bnode_put(node);
	tree->free_nodes++;
	mark_inode_dirty(tree->inode);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/btree.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/bnode.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handle basic btree node operations
 */

// #include <linux/string.h>
// #include <linux/slab.h>
// #include <linux/pagemap.h>
// #include <linux/fs.h>
#include <linux/swap.h>
#include "../../inc/__fss.h"

// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"

/* Copy a specified range of bytes from the raw data of a node */
void hfs_bnode_read(struct hfs_bnode *node, void *buf, int off, int len)
{
	struct page **pagep;
	int l;

	off += node->page_offset;
	pagep = node->page + (off >> PAGE_CACHE_SHIFT);
	off &= ~PAGE_CACHE_MASK;

	l = min_t(int, len, PAGE_CACHE_SIZE - off);
	memcpy(buf, kmap(*pagep) + off, l);
	kunmap(*pagep);

	while ((len -= l) != 0) {
		buf += l;
		l = min_t(int, len, PAGE_CACHE_SIZE);
		memcpy(buf, kmap(*++pagep), l);
		kunmap(*pagep);
	}
}

u16 hfs_bnode_read_u16(struct hfs_bnode *node, int off)
{
	__be16 data;
	/* TODO: optimize later... */
	hfs_bnode_read(node, &data, off, 2);
	return be16_to_cpu(data);
}

u8 hfs_bnode_read_u8(struct hfs_bnode *node, int off)
{
	u8 data;
	/* TODO: optimize later... */
	hfs_bnode_read(node, &data, off, 1);
	return data;
}

void hfs_bnode_read_key(struct hfs_bnode *node, void *key, int off)
{
	struct hfs_btree *tree;
	int key_len;

	tree = node->tree;
	if (node->type == HFS_NODE_LEAF ||
	    tree->attributes & HFS_TREE_VARIDXKEYS ||
	    node->tree->cnid == HFSPLUS_ATTR_CNID)
		key_len = hfs_bnode_read_u16(node, off) + 2;
	else
		key_len = tree->max_key_len + 2;

	hfs_bnode_read(node, key, off, key_len);
}

void hfs_bnode_write(struct hfs_bnode *node, void *buf, int off, int len)
{
	struct page **pagep;
	int l;

	off += node->page_offset;
	pagep = node->page + (off >> PAGE_CACHE_SHIFT);
	off &= ~PAGE_CACHE_MASK;

	l = min_t(int, len, PAGE_CACHE_SIZE - off);
	memcpy(kmap(*pagep) + off, buf, l);
	set_page_dirty(*pagep);
	kunmap(*pagep);

	while ((len -= l) != 0) {
		buf += l;
		l = min_t(int, len, PAGE_CACHE_SIZE);
		memcpy(kmap(*++pagep), buf, l);
		set_page_dirty(*pagep);
		kunmap(*pagep);
	}
}

void hfs_bnode_write_u16(struct hfs_bnode *node, int off, u16 data)
{
	__be16 v = cpu_to_be16(data);
	/* TODO: optimize later... */
	hfs_bnode_write(node, &v, off, 2);
}

void hfs_bnode_clear(struct hfs_bnode *node, int off, int len)
{
	struct page **pagep;
	int l;

	off += node->page_offset;
	pagep = node->page + (off >> PAGE_CACHE_SHIFT);
	off &= ~PAGE_CACHE_MASK;

	l = min_t(int, len, PAGE_CACHE_SIZE - off);
	memset(kmap(*pagep) + off, 0, l);
	set_page_dirty(*pagep);
	kunmap(*pagep);

	while ((len -= l) != 0) {
		l = min_t(int, len, PAGE_CACHE_SIZE);
		memset(kmap(*++pagep), 0, l);
		set_page_dirty(*pagep);
		kunmap(*pagep);
	}
}

void hfs_bnode_copy(struct hfs_bnode *dst_node, int dst,
		    struct hfs_bnode *src_node, int src, int len)
{
	struct hfs_btree *tree;
	struct page **src_page, **dst_page;
	int l;

	hfs_dbg(BNODE_MOD, "copybytes: %u,%u,%u\n", dst, src, len);
	if (!len)
		return;
	tree = src_node->tree;
	src += src_node->page_offset;
	dst += dst_node->page_offset;
	src_page = src_node->page + (src >> PAGE_CACHE_SHIFT);
	src &= ~PAGE_CACHE_MASK;
	dst_page = dst_node->page + (dst >> PAGE_CACHE_SHIFT);
	dst &= ~PAGE_CACHE_MASK;

	if (src == dst) {
		l = min_t(int, len, PAGE_CACHE_SIZE - src);
		memcpy(kmap(*dst_page) + src, kmap(*src_page) + src, l);
		kunmap(*src_page);
		set_page_dirty(*dst_page);
		kunmap(*dst_page);

		while ((len -= l) != 0) {
			l = min_t(int, len, PAGE_CACHE_SIZE);
			memcpy(kmap(*++dst_page), kmap(*++src_page), l);
			kunmap(*src_page);
			set_page_dirty(*dst_page);
			kunmap(*dst_page);
		}
	} else {
		void *src_ptr, *dst_ptr;

		do {
			src_ptr = kmap(*src_page) + src;
			dst_ptr = kmap(*dst_page) + dst;
			if (PAGE_CACHE_SIZE - src < PAGE_CACHE_SIZE - dst) {
				l = PAGE_CACHE_SIZE - src;
				src = 0;
				dst += l;
			} else {
				l = PAGE_CACHE_SIZE - dst;
				src += l;
				dst = 0;
			}
			l = min(len, l);
			memcpy(dst_ptr, src_ptr, l);
			kunmap(*src_page);
			set_page_dirty(*dst_page);
			kunmap(*dst_page);
			if (!dst)
				dst_page++;
			else
				src_page++;
		} while ((len -= l));
	}
}

void hfs_bnode_move(struct hfs_bnode *node, int dst, int src, int len)
{
	struct page **src_page, **dst_page;
	int l;

	hfs_dbg(BNODE_MOD, "movebytes: %u,%u,%u\n", dst, src, len);
	if (!len)
		return;
	src += node->page_offset;
	dst += node->page_offset;
	if (dst > src) {
		src += len - 1;
		src_page = node->page + (src >> PAGE_CACHE_SHIFT);
		src = (src & ~PAGE_CACHE_MASK) + 1;
		dst += len - 1;
		dst_page = node->page + (dst >> PAGE_CACHE_SHIFT);
		dst = (dst & ~PAGE_CACHE_MASK) + 1;

		if (src == dst) {
			while (src < len) {
				memmove(kmap(*dst_page), kmap(*src_page), src);
				kunmap(*src_page);
				set_page_dirty(*dst_page);
				kunmap(*dst_page);
				len -= src;
				src = PAGE_CACHE_SIZE;
				src_page--;
				dst_page--;
			}
			src -= len;
			memmove(kmap(*dst_page) + src,
				kmap(*src_page) + src, len);
			kunmap(*src_page);
			set_page_dirty(*dst_page);
			kunmap(*dst_page);
		} else {
			void *src_ptr, *dst_ptr;

			do {
				src_ptr = kmap(*src_page) + src;
				dst_ptr = kmap(*dst_page) + dst;
				if (src < dst) {
					l = src;
					src = PAGE_CACHE_SIZE;
					dst -= l;
				} else {
					l = dst;
					src -= l;
					dst = PAGE_CACHE_SIZE;
				}
				l = min(len, l);
				memmove(dst_ptr - l, src_ptr - l, l);
				kunmap(*src_page);
				set_page_dirty(*dst_page);
				kunmap(*dst_page);
				if (dst == PAGE_CACHE_SIZE)
					dst_page--;
				else
					src_page--;
			} while ((len -= l));
		}
	} else {
		src_page = node->page + (src >> PAGE_CACHE_SHIFT);
		src &= ~PAGE_CACHE_MASK;
		dst_page = node->page + (dst >> PAGE_CACHE_SHIFT);
		dst &= ~PAGE_CACHE_MASK;

		if (src == dst) {
			l = min_t(int, len, PAGE_CACHE_SIZE - src);
			memmove(kmap(*dst_page) + src,
				kmap(*src_page) + src, l);
			kunmap(*src_page);
			set_page_dirty(*dst_page);
			kunmap(*dst_page);

			while ((len -= l) != 0) {
				l = min_t(int, len, PAGE_CACHE_SIZE);
				memmove(kmap(*++dst_page),
					kmap(*++src_page), l);
				kunmap(*src_page);
				set_page_dirty(*dst_page);
				kunmap(*dst_page);
			}
		} else {
			void *src_ptr, *dst_ptr;

			do {
				src_ptr = kmap(*src_page) + src;
				dst_ptr = kmap(*dst_page) + dst;
				if (PAGE_CACHE_SIZE - src <
						PAGE_CACHE_SIZE - dst) {
					l = PAGE_CACHE_SIZE - src;
					src = 0;
					dst += l;
				} else {
					l = PAGE_CACHE_SIZE - dst;
					src += l;
					dst = 0;
				}
				l = min(len, l);
				memmove(dst_ptr, src_ptr, l);
				kunmap(*src_page);
				set_page_dirty(*dst_page);
				kunmap(*dst_page);
				if (!dst)
					dst_page++;
				else
					src_page++;
			} while ((len -= l));
		}
	}
}

void hfs_bnode_dump(struct hfs_bnode *node)
{
	struct hfs_bnode_desc desc;
	__be32 cnid;
	int i, off, key_off;

	hfs_dbg(BNODE_MOD, "bnode: %d\n", node->this);
	hfs_bnode_read(node, &desc, 0, sizeof(desc));
	hfs_dbg(BNODE_MOD, "%d, %d, %d, %d, %d\n",
		be32_to_cpu(desc.next), be32_to_cpu(desc.prev),
		desc.type, desc.height, be16_to_cpu(desc.num_recs));

	off = node->tree->node_size - 2;
	for (i = be16_to_cpu(desc.num_recs); i >= 0; off -= 2, i--) {
		key_off = hfs_bnode_read_u16(node, off);
		hfs_dbg(BNODE_MOD, " %d", key_off);
		if (i && node->type == HFS_NODE_INDEX) {
			int tmp;

			if (node->tree->attributes & HFS_TREE_VARIDXKEYS ||
					node->tree->cnid == HFSPLUS_ATTR_CNID)
				tmp = hfs_bnode_read_u16(node, key_off) + 2;
			else
				tmp = node->tree->max_key_len + 2;
			hfs_dbg_cont(BNODE_MOD, " (%d", tmp);
			hfs_bnode_read(node, &cnid, key_off + tmp, 4);
			hfs_dbg_cont(BNODE_MOD, ",%d)", be32_to_cpu(cnid));
		} else if (i && node->type == HFS_NODE_LEAF) {
			int tmp;

			tmp = hfs_bnode_read_u16(node, key_off);
			hfs_dbg_cont(BNODE_MOD, " (%d)", tmp);
		}
	}
	hfs_dbg_cont(BNODE_MOD, "\n");
}

void hfs_bnode_unlink(struct hfs_bnode *node)
{
	struct hfs_btree *tree;
	struct hfs_bnode *tmp;
	__be32 cnid;

	tree = node->tree;
	if (node->prev) {
		tmp = hfs_bnode_find(tree, node->prev);
		if (IS_ERR(tmp))
			return;
		tmp->next = node->next;
		cnid = cpu_to_be32(tmp->next);
		hfs_bnode_write(tmp, &cnid,
			offsetof(struct hfs_bnode_desc, next), 4);
		hfs_bnode_put(tmp);
	} else if (node->type == HFS_NODE_LEAF)
		tree->leaf_head = node->next;

	if (node->next) {
		tmp = hfs_bnode_find(tree, node->next);
		if (IS_ERR(tmp))
			return;
		tmp->prev = node->prev;
		cnid = cpu_to_be32(tmp->prev);
		hfs_bnode_write(tmp, &cnid,
			offsetof(struct hfs_bnode_desc, prev), 4);
		hfs_bnode_put(tmp);
	} else if (node->type == HFS_NODE_LEAF)
		tree->leaf_tail = node->prev;

	/* move down? */
	if (!node->prev && !node->next)
		hfs_dbg(BNODE_MOD, "hfs_btree_del_level\n");
	if (!node->parent) {
		tree->root = 0;
		tree->depth = 0;
	}
	set_bit(HFS_BNODE_DELETED, &node->flags);
}

static inline int hfs_bnode_hash(u32 num)
{
	num = (num >> 16) + num;
	num += num >> 8;
	return num & (NODE_HASH_SIZE - 1);
}

struct hfs_bnode *hfs_bnode_findhash(struct hfs_btree *tree, u32 cnid)
{
	struct hfs_bnode *node;

	if (cnid >= tree->node_count) {
		pr_err("request for non-existent node %d in B*Tree\n",
		       cnid);
		return NULL;
	}

	for (node = tree->node_hash[hfs_bnode_hash(cnid)];
			node; node = node->next_hash)
		if (node->this == cnid)
			return node;
	return NULL;
}

static struct hfs_bnode *__hfs_bnode_create(struct hfs_btree *tree, u32 cnid)
{
	struct super_block *sb;
	struct hfs_bnode *node, *node2;
	struct address_space *mapping;
	struct page *page;
	int size, block, i, hash;
	loff_t off;

	if (cnid >= tree->node_count) {
		pr_err("request for non-existent node %d in B*Tree\n",
		       cnid);
		return NULL;
	}

	sb = tree->inode->i_sb;
	size = sizeof(struct hfs_bnode) + tree->pages_per_bnode *
		sizeof(struct page *);
	node = kzalloc(size, GFP_KERNEL);
	if (!node)
		return NULL;
	node->tree = tree;
	node->this = cnid;
	set_bit(HFS_BNODE_NEW, &node->flags);
	atomic_set(&node->refcnt, 1);
	hfs_dbg(BNODE_REFS, "new_node(%d:%d): 1\n",
		node->tree->cnid, node->this);
	init_waitqueue_head(&node->lock_wq);
	spin_lock(&tree->hash_lock);
	node2 = hfs_bnode_findhash(tree, cnid);
	if (!node2) {
		hash = hfs_bnode_hash(cnid);
		node->next_hash = tree->node_hash[hash];
		tree->node_hash[hash] = node;
		tree->node_hash_cnt++;
	} else {
		spin_unlock(&tree->hash_lock);
		kfree(node);
		wait_event(node2->lock_wq,
			!test_bit(HFS_BNODE_NEW, &node2->flags));
		return node2;
	}
	spin_unlock(&tree->hash_lock);

	mapping = tree->inode->i_mapping;
	off = (loff_t)cnid << tree->node_size_shift;
	block = off >> PAGE_CACHE_SHIFT;
	node->page_offset = off & ~PAGE_CACHE_MASK;
	for (i = 0; i < tree->pages_per_bnode; block++, i++) {
		page = read_mapping_page(mapping, block, NULL);
		if (IS_ERR(page))
			goto fail;
		if (PageError(page)) {
			page_cache_release(page);
			goto fail;
		}
		page_cache_release(page);
		node->page[i] = page;
	}

	return node;
fail:
	set_bit(HFS_BNODE_ERROR, &node->flags);
	return node;
}

void hfs_bnode_unhash(struct hfs_bnode *node)
{
	struct hfs_bnode **p;

	hfs_dbg(BNODE_REFS, "remove_node(%d:%d): %d\n",
		node->tree->cnid, node->this, atomic_read(&node->refcnt));
	for (p = &node->tree->node_hash[hfs_bnode_hash(node->this)];
	     *p && *p != node; p = &(*p)->next_hash)
		;
	BUG_ON(!*p);
	*p = node->next_hash;
	node->tree->node_hash_cnt--;
}

/* Load a particular node out of a tree */
struct hfs_bnode *hfs_bnode_find(struct hfs_btree *tree, u32 num)
{
	struct hfs_bnode *node;
	struct hfs_bnode_desc *desc;
	int i, rec_off, off, next_off;
	int entry_size, key_size;

	spin_lock(&tree->hash_lock);
	node = hfs_bnode_findhash(tree, num);
	if (node) {
		hfs_bnode_get(node);
		spin_unlock(&tree->hash_lock);
		wait_event(node->lock_wq,
			!test_bit(HFS_BNODE_NEW, &node->flags));
		if (test_bit(HFS_BNODE_ERROR, &node->flags))
			goto node_error;
		return node;
	}
	spin_unlock(&tree->hash_lock);
	node = __hfs_bnode_create(tree, num);
	if (!node)
		return ERR_PTR(-ENOMEM);
	if (test_bit(HFS_BNODE_ERROR, &node->flags))
		goto node_error;
	if (!test_bit(HFS_BNODE_NEW, &node->flags))
		return node;

	desc = (struct hfs_bnode_desc *)(kmap(node->page[0]) +
			node->page_offset);
	node->prev = be32_to_cpu(desc->prev);
	node->next = be32_to_cpu(desc->next);
	node->num_recs = be16_to_cpu(desc->num_recs);
	node->type = desc->type;
	node->height = desc->height;
	kunmap(node->page[0]);

	switch (node->type) {
	case HFS_NODE_HEADER:
	case HFS_NODE_MAP:
		if (node->height != 0)
			goto node_error;
		break;
	case HFS_NODE_LEAF:
		if (node->height != 1)
			goto node_error;
		break;
	case HFS_NODE_INDEX:
		if (node->height <= 1 || node->height > tree->depth)
			goto node_error;
		break;
	default:
		goto node_error;
	}

	rec_off = tree->node_size - 2;
	off = hfs_bnode_read_u16(node, rec_off);
	if (off != sizeof(struct hfs_bnode_desc))
		goto node_error;
	for (i = 1; i <= node->num_recs; off = next_off, i++) {
		rec_off -= 2;
		next_off = hfs_bnode_read_u16(node, rec_off);
		if (next_off <= off ||
		    next_off > tree->node_size ||
		    next_off & 1)
			goto node_error;
		entry_size = next_off - off;
		if (node->type != HFS_NODE_INDEX &&
		    node->type != HFS_NODE_LEAF)
			continue;
		key_size = hfs_bnode_read_u16(node, off) + 2;
		if (key_size >= entry_size || key_size & 1)
			goto node_error;
	}
	clear_bit(HFS_BNODE_NEW, &node->flags);
	wake_up(&node->lock_wq);
	return node;

node_error:
	set_bit(HFS_BNODE_ERROR, &node->flags);
	clear_bit(HFS_BNODE_NEW, &node->flags);
	wake_up(&node->lock_wq);
	hfs_bnode_put(node);
	return ERR_PTR(-EIO);
}

void hfs_bnode_free(struct hfs_bnode *node)
{
#if 0
	int i;

	for (i = 0; i < node->tree->pages_per_bnode; i++)
		if (node->page[i])
			page_cache_release(node->page[i]);
#endif
	kfree(node);
}

struct hfs_bnode *hfs_bnode_create(struct hfs_btree *tree, u32 num)
{
	struct hfs_bnode *node;
	struct page **pagep;
	int i;

	spin_lock(&tree->hash_lock);
	node = hfs_bnode_findhash(tree, num);
	spin_unlock(&tree->hash_lock);
	if (node) {
		pr_crit("new node %u already hashed?\n", num);
		WARN_ON(1);
		return node;
	}
	node = __hfs_bnode_create(tree, num);
	if (!node)
		return ERR_PTR(-ENOMEM);
	if (test_bit(HFS_BNODE_ERROR, &node->flags)) {
		hfs_bnode_put(node);
		return ERR_PTR(-EIO);
	}

	pagep = node->page;
	memset(kmap(*pagep) + node->page_offset, 0,
	       min_t(int, PAGE_CACHE_SIZE, tree->node_size));
	set_page_dirty(*pagep);
	kunmap(*pagep);
	for (i = 1; i < tree->pages_per_bnode; i++) {
		memset(kmap(*++pagep), 0, PAGE_CACHE_SIZE);
		set_page_dirty(*pagep);
		kunmap(*pagep);
	}
	clear_bit(HFS_BNODE_NEW, &node->flags);
	wake_up(&node->lock_wq);

	return node;
}

void hfs_bnode_get(struct hfs_bnode *node)
{
	if (node) {
		atomic_inc(&node->refcnt);
		hfs_dbg(BNODE_REFS, "get_node(%d:%d): %d\n",
			node->tree->cnid, node->this,
			atomic_read(&node->refcnt));
	}
}

/* Dispose of resources used by a node */
void hfs_bnode_put(struct hfs_bnode *node)
{
	if (node) {
		struct hfs_btree *tree = node->tree;
		int i;

		hfs_dbg(BNODE_REFS, "put_node(%d:%d): %d\n",
			node->tree->cnid, node->this,
			atomic_read(&node->refcnt));
		BUG_ON(!atomic_read(&node->refcnt));
		if (!atomic_dec_and_lock(&node->refcnt, &tree->hash_lock))
			return;
		for (i = 0; i < tree->pages_per_bnode; i++) {
			if (!node->page[i])
				continue;
			mark_page_accessed(node->page[i]);
		}

		if (test_bit(HFS_BNODE_DELETED, &node->flags)) {
			hfs_bnode_unhash(node);
			spin_unlock(&tree->hash_lock);
			if (hfs_bnode_need_zeroout(tree))
				hfs_bnode_clear(node, 0, tree->node_size);
			hfs_bmap_free(node);
			hfs_bnode_free(node);
			return;
		}
		spin_unlock(&tree->hash_lock);
	}
}

/*
 * Unused nodes have to be zeroed if this is the catalog tree and
 * a corresponding flag in the volume header is set.
 */
bool hfs_bnode_need_zeroout(struct hfs_btree *tree)
{
	struct super_block *sb = tree->inode->i_sb;
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	const u32 volume_attr = be32_to_cpu(sbi->s_vhdr->attributes);

	return tree->cnid == HFSPLUS_CAT_CNID &&
		volume_attr & HFSPLUS_VOL_UNUSED_NODE_FIX;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/bnode.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/brec.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handle individual btree records
 */

// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"

static struct hfs_bnode *hfs_bnode_split(struct hfs_find_data *fd);
static int hfs_brec_update_parent(struct hfs_find_data *fd);
static int hfs_btree_inc_height(struct hfs_btree *);

/* Get the length and offset of the given record in the given node */
u16 hfs_brec_lenoff(struct hfs_bnode *node, u16 rec, u16 *off)
{
	__be16 retval[2];
	u16 dataoff;

	dataoff = node->tree->node_size - (rec + 2) * 2;
	hfs_bnode_read(node, retval, dataoff, 4);
	*off = be16_to_cpu(retval[1]);
	return be16_to_cpu(retval[0]) - *off;
}

/* Get the length of the key from a keyed record */
u16 hfs_brec_keylen(struct hfs_bnode *node, u16 rec)
{
	u16 retval, recoff;

	if (node->type != HFS_NODE_INDEX && node->type != HFS_NODE_LEAF)
		return 0;

	if ((node->type == HFS_NODE_INDEX) &&
	   !(node->tree->attributes & HFS_TREE_VARIDXKEYS) &&
	   (node->tree->cnid != HFSPLUS_ATTR_CNID)) {
		retval = node->tree->max_key_len + 2;
	} else {
		recoff = hfs_bnode_read_u16(node,
			node->tree->node_size - (rec + 1) * 2);
		if (!recoff)
			return 0;
		if (recoff > node->tree->node_size - 2) {
			pr_err("recoff %d too large\n", recoff);
			return 0;
		}

		retval = hfs_bnode_read_u16(node, recoff) + 2;
		if (retval > node->tree->max_key_len + 2) {
			pr_err("keylen %d too large\n",
				retval);
			retval = 0;
		}
	}
	return retval;
}

int hfs_brec_insert(struct hfs_find_data *fd, void *entry, int entry_len)
{
	struct hfs_btree *tree;
	struct hfs_bnode *node, *new_node;
	int size, key_len, rec;
	int data_off, end_off;
	int idx_rec_off, data_rec_off, end_rec_off;
	__be32 cnid;

	tree = fd->tree;
	if (!fd->bnode) {
		if (!tree->root)
			hfs_btree_inc_height(tree);
		fd->bnode = hfs_bnode_find(tree, tree->leaf_head);
		if (IS_ERR(fd->bnode))
			return PTR_ERR(fd->bnode);
		fd->record = -1;
	}
	new_node = NULL;
	key_len = be16_to_cpu(fd->search_key->key_len) + 2;
again:
	/* new record idx and complete record size */
	rec = fd->record + 1;
	size = key_len + entry_len;

	node = fd->bnode;
	hfs_bnode_dump(node);
	/* get last offset */
	end_rec_off = tree->node_size - (node->num_recs + 1) * 2;
	end_off = hfs_bnode_read_u16(node, end_rec_off);
	end_rec_off -= 2;
	hfs_dbg(BNODE_MOD, "insert_rec: %d, %d, %d, %d\n",
		rec, size, end_off, end_rec_off);
	if (size > end_rec_off - end_off) {
		if (new_node)
			panic("not enough room!\n");
		new_node = hfs_bnode_split(fd);
		if (IS_ERR(new_node))
			return PTR_ERR(new_node);
		goto again;
	}
	if (node->type == HFS_NODE_LEAF) {
		tree->leaf_count++;
		mark_inode_dirty(tree->inode);
	}
	node->num_recs++;
	/* write new last offset */
	hfs_bnode_write_u16(node,
		offsetof(struct hfs_bnode_desc, num_recs),
		node->num_recs);
	hfs_bnode_write_u16(node, end_rec_off, end_off + size);
	data_off = end_off;
	data_rec_off = end_rec_off + 2;
	idx_rec_off = tree->node_size - (rec + 1) * 2;
	if (idx_rec_off == data_rec_off)
		goto skip;
	/* move all following entries */
	do {
		data_off = hfs_bnode_read_u16(node, data_rec_off + 2);
		hfs_bnode_write_u16(node, data_rec_off, data_off + size);
		data_rec_off += 2;
	} while (data_rec_off < idx_rec_off);

	/* move data away */
	hfs_bnode_move(node, data_off + size, data_off,
		       end_off - data_off);

skip:
	hfs_bnode_write(node, fd->search_key, data_off, key_len);
	hfs_bnode_write(node, entry, data_off + key_len, entry_len);
	hfs_bnode_dump(node);

	if (new_node) {
		/* update parent key if we inserted a key
		 * at the start of the first node
		 */
		if (!rec && new_node != node)
			hfs_brec_update_parent(fd);

		hfs_bnode_put(fd->bnode);
		if (!new_node->parent) {
			hfs_btree_inc_height(tree);
			new_node->parent = tree->root;
		}
		fd->bnode = hfs_bnode_find(tree, new_node->parent);

		/* create index data entry */
		cnid = cpu_to_be32(new_node->this);
		entry = &cnid;
		entry_len = sizeof(cnid);

		/* get index key */
		hfs_bnode_read_key(new_node, fd->search_key, 14);
		__hfs_brec_find(fd->bnode, fd, hfs_find_rec_by_key);

		hfs_bnode_put(new_node);
		new_node = NULL;

		if ((tree->attributes & HFS_TREE_VARIDXKEYS) ||
				(tree->cnid == HFSPLUS_ATTR_CNID))
			key_len = be16_to_cpu(fd->search_key->key_len) + 2;
		else {
			fd->search_key->key_len =
				cpu_to_be16(tree->max_key_len);
			key_len = tree->max_key_len + 2;
		}
		goto again;
	}

	if (!rec)
		hfs_brec_update_parent(fd);

	return 0;
}

int hfs_brec_remove(struct hfs_find_data *fd)
{
	struct hfs_btree *tree;
	struct hfs_bnode *node, *parent;
	int end_off, rec_off, data_off, size;

	tree = fd->tree;
	node = fd->bnode;
again:
	rec_off = tree->node_size - (fd->record + 2) * 2;
	end_off = tree->node_size - (node->num_recs + 1) * 2;

	if (node->type == HFS_NODE_LEAF) {
		tree->leaf_count--;
		mark_inode_dirty(tree->inode);
	}
	hfs_bnode_dump(node);
	hfs_dbg(BNODE_MOD, "remove_rec: %d, %d\n",
		fd->record, fd->keylength + fd->entrylength);
	if (!--node->num_recs) {
		hfs_bnode_unlink(node);
		if (!node->parent)
			return 0;
		parent = hfs_bnode_find(tree, node->parent);
		if (IS_ERR(parent))
			return PTR_ERR(parent);
		hfs_bnode_put(node);
		node = fd->bnode = parent;

		__hfs_brec_find(node, fd, hfs_find_rec_by_key);
		goto again;
	}
	hfs_bnode_write_u16(node,
		offsetof(struct hfs_bnode_desc, num_recs),
		node->num_recs);

	if (rec_off == end_off)
		goto skip;
	size = fd->keylength + fd->entrylength;

	do {
		data_off = hfs_bnode_read_u16(node, rec_off);
		hfs_bnode_write_u16(node, rec_off + 2, data_off - size);
		rec_off -= 2;
	} while (rec_off >= end_off);

	/* fill hole */
	hfs_bnode_move(node, fd->keyoffset, fd->keyoffset + size,
		       data_off - fd->keyoffset - size);
skip:
	hfs_bnode_dump(node);
	if (!fd->record)
		hfs_brec_update_parent(fd);
	return 0;
}

static struct hfs_bnode *hfs_bnode_split(struct hfs_find_data *fd)
{
	struct hfs_btree *tree;
	struct hfs_bnode *node, *new_node, *next_node;
	struct hfs_bnode_desc node_desc;
	int num_recs, new_rec_off, new_off, old_rec_off;
	int data_start, data_end, size;

	tree = fd->tree;
	node = fd->bnode;
	new_node = hfs_bmap_alloc(tree);
	if (IS_ERR(new_node))
		return new_node;
	hfs_bnode_get(node);
	hfs_dbg(BNODE_MOD, "split_nodes: %d - %d - %d\n",
		node->this, new_node->this, node->next);
	new_node->next = node->next;
	new_node->prev = node->this;
	new_node->parent = node->parent;
	new_node->type = node->type;
	new_node->height = node->height;

	if (node->next)
		next_node = hfs_bnode_find(tree, node->next);
	else
		next_node = NULL;

	if (IS_ERR(next_node)) {
		hfs_bnode_put(node);
		hfs_bnode_put(new_node);
		return next_node;
	}

	size = tree->node_size / 2 - node->num_recs * 2 - 14;
	old_rec_off = tree->node_size - 4;
	num_recs = 1;
	for (;;) {
		data_start = hfs_bnode_read_u16(node, old_rec_off);
		if (data_start > size)
			break;
		old_rec_off -= 2;
		if (++num_recs < node->num_recs)
			continue;
		/* panic? */
		hfs_bnode_put(node);
		hfs_bnode_put(new_node);
		if (next_node)
			hfs_bnode_put(next_node);
		return ERR_PTR(-ENOSPC);
	}

	if (fd->record + 1 < num_recs) {
		/* new record is in the lower half,
		 * so leave some more space there
		 */
		old_rec_off += 2;
		num_recs--;
		data_start = hfs_bnode_read_u16(node, old_rec_off);
	} else {
		hfs_bnode_put(node);
		hfs_bnode_get(new_node);
		fd->bnode = new_node;
		fd->record -= num_recs;
		fd->keyoffset -= data_start - 14;
		fd->entryoffset -= data_start - 14;
	}
	new_node->num_recs = node->num_recs - num_recs;
	node->num_recs = num_recs;

	new_rec_off = tree->node_size - 2;
	new_off = 14;
	size = data_start - new_off;
	num_recs = new_node->num_recs;
	data_end = data_start;
	while (num_recs) {
		hfs_bnode_write_u16(new_node, new_rec_off, new_off);
		old_rec_off -= 2;
		new_rec_off -= 2;
		data_end = hfs_bnode_read_u16(node, old_rec_off);
		new_off = data_end - size;
		num_recs--;
	}
	hfs_bnode_write_u16(new_node, new_rec_off, new_off);
	hfs_bnode_copy(new_node, 14, node, data_start, data_end - data_start);

	/* update new bnode header */
	node_desc.next = cpu_to_be32(new_node->next);
	node_desc.prev = cpu_to_be32(new_node->prev);
	node_desc.type = new_node->type;
	node_desc.height = new_node->height;
	node_desc.num_recs = cpu_to_be16(new_node->num_recs);
	node_desc.reserved = 0;
	hfs_bnode_write(new_node, &node_desc, 0, sizeof(node_desc));

	/* update previous bnode header */
	node->next = new_node->this;
	hfs_bnode_read(node, &node_desc, 0, sizeof(node_desc));
	node_desc.next = cpu_to_be32(node->next);
	node_desc.num_recs = cpu_to_be16(node->num_recs);
	hfs_bnode_write(node, &node_desc, 0, sizeof(node_desc));

	/* update next bnode header */
	if (next_node) {
		next_node->prev = new_node->this;
		hfs_bnode_read(next_node, &node_desc, 0, sizeof(node_desc));
		node_desc.prev = cpu_to_be32(next_node->prev);
		hfs_bnode_write(next_node, &node_desc, 0, sizeof(node_desc));
		hfs_bnode_put(next_node);
	} else if (node->this == tree->leaf_tail) {
		/* if there is no next node, this might be the new tail */
		tree->leaf_tail = new_node->this;
		mark_inode_dirty(tree->inode);
	}

	hfs_bnode_dump(node);
	hfs_bnode_dump(new_node);
	hfs_bnode_put(node);

	return new_node;
}

static int hfs_brec_update_parent(struct hfs_find_data *fd)
{
	struct hfs_btree *tree;
	struct hfs_bnode *node, *new_node, *parent;
	int newkeylen, diff;
	int rec, rec_off, end_rec_off;
	int start_off, end_off;

	tree = fd->tree;
	node = fd->bnode;
	new_node = NULL;
	if (!node->parent)
		return 0;

again:
	parent = hfs_bnode_find(tree, node->parent);
	if (IS_ERR(parent))
		return PTR_ERR(parent);
	__hfs_brec_find(parent, fd, hfs_find_rec_by_key);
	hfs_bnode_dump(parent);
	rec = fd->record;

	/* size difference between old and new key */
	if ((tree->attributes & HFS_TREE_VARIDXKEYS) ||
				(tree->cnid == HFSPLUS_ATTR_CNID))
		newkeylen = hfs_bnode_read_u16(node, 14) + 2;
	else
		fd->keylength = newkeylen = tree->max_key_len + 2;
	hfs_dbg(BNODE_MOD, "update_rec: %d, %d, %d\n",
		rec, fd->keylength, newkeylen);

	rec_off = tree->node_size - (rec + 2) * 2;
	end_rec_off = tree->node_size - (parent->num_recs + 1) * 2;
	diff = newkeylen - fd->keylength;
	if (!diff)
		goto skip;
	if (diff > 0) {
		end_off = hfs_bnode_read_u16(parent, end_rec_off);
		if (end_rec_off - end_off < diff) {

			hfs_dbg(BNODE_MOD, "splitting index node\n");
			fd->bnode = parent;
			new_node = hfs_bnode_split(fd);
			if (IS_ERR(new_node))
				return PTR_ERR(new_node);
			parent = fd->bnode;
			rec = fd->record;
			rec_off = tree->node_size - (rec + 2) * 2;
			end_rec_off = tree->node_size -
				(parent->num_recs + 1) * 2;
		}
	}

	end_off = start_off = hfs_bnode_read_u16(parent, rec_off);
	hfs_bnode_write_u16(parent, rec_off, start_off + diff);
	start_off -= 4;	/* move previous cnid too */

	while (rec_off > end_rec_off) {
		rec_off -= 2;
		end_off = hfs_bnode_read_u16(parent, rec_off);
		hfs_bnode_write_u16(parent, rec_off, end_off + diff);
	}
	hfs_bnode_move(parent, start_off + diff, start_off,
		       end_off - start_off);
skip:
	hfs_bnode_copy(parent, fd->keyoffset, node, 14, newkeylen);
	hfs_bnode_dump(parent);

	hfs_bnode_put(node);
	node = parent;

	if (new_node) {
		__be32 cnid;

		fd->bnode = hfs_bnode_find(tree, new_node->parent);
		/* create index key and entry */
		hfs_bnode_read_key(new_node, fd->search_key, 14);
		cnid = cpu_to_be32(new_node->this);

		__hfs_brec_find(fd->bnode, fd, hfs_find_rec_by_key);
		hfs_brec_insert(fd, &cnid, sizeof(cnid));
		hfs_bnode_put(fd->bnode);
		hfs_bnode_put(new_node);

		if (!rec) {
			if (new_node == node)
				goto out;
			/* restore search_key */
			hfs_bnode_read_key(node, fd->search_key, 14);
		}
	}

	if (!rec && node->parent)
		goto again;
out:
	fd->bnode = node;
	return 0;
}

static int hfs_btree_inc_height(struct hfs_btree *tree)
{
	struct hfs_bnode *node, *new_node;
	struct hfs_bnode_desc node_desc;
	int key_size, rec;
	__be32 cnid;

	node = NULL;
	if (tree->root) {
		node = hfs_bnode_find(tree, tree->root);
		if (IS_ERR(node))
			return PTR_ERR(node);
	}
	new_node = hfs_bmap_alloc(tree);
	if (IS_ERR(new_node)) {
		hfs_bnode_put(node);
		return PTR_ERR(new_node);
	}

	tree->root = new_node->this;
	if (!tree->depth) {
		tree->leaf_head = tree->leaf_tail = new_node->this;
		new_node->type = HFS_NODE_LEAF;
		new_node->num_recs = 0;
	} else {
		new_node->type = HFS_NODE_INDEX;
		new_node->num_recs = 1;
	}
	new_node->parent = 0;
	new_node->next = 0;
	new_node->prev = 0;
	new_node->height = ++tree->depth;

	node_desc.next = cpu_to_be32(new_node->next);
	node_desc.prev = cpu_to_be32(new_node->prev);
	node_desc.type = new_node->type;
	node_desc.height = new_node->height;
	node_desc.num_recs = cpu_to_be16(new_node->num_recs);
	node_desc.reserved = 0;
	hfs_bnode_write(new_node, &node_desc, 0, sizeof(node_desc));

	rec = tree->node_size - 2;
	hfs_bnode_write_u16(new_node, rec, 14);

	if (node) {
		/* insert old root idx into new root */
		node->parent = tree->root;
		if (node->type == HFS_NODE_LEAF ||
				tree->attributes & HFS_TREE_VARIDXKEYS ||
				tree->cnid == HFSPLUS_ATTR_CNID)
			key_size = hfs_bnode_read_u16(node, 14) + 2;
		else
			key_size = tree->max_key_len + 2;
		hfs_bnode_copy(new_node, 14, node, 14, key_size);

		if (!(tree->attributes & HFS_TREE_VARIDXKEYS) &&
				(tree->cnid != HFSPLUS_ATTR_CNID)) {
			key_size = tree->max_key_len + 2;
			hfs_bnode_write_u16(new_node, 14, tree->max_key_len);
		}
		cnid = cpu_to_be32(node->this);
		hfs_bnode_write(new_node, &cnid, 14 + key_size, 4);

		rec -= 2;
		hfs_bnode_write_u16(new_node, rec, 14 + key_size + 4);

		hfs_bnode_put(node);
	}
	hfs_bnode_put(new_node);
	mark_inode_dirty(tree->inode);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/brec.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/bfind.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Search routines for btrees
 */

// #include <linux/slab.h>
// #include "hfsplus_fs.h"

int hfs_find_init(struct hfs_btree *tree, struct hfs_find_data *fd)
{
	void *ptr;

	fd->tree = tree;
	fd->bnode = NULL;
	ptr = kmalloc(tree->max_key_len * 2 + 4, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;
	fd->search_key = ptr;
	fd->key = ptr + tree->max_key_len + 2;
	hfs_dbg(BNODE_REFS, "find_init: %d (%p)\n",
		tree->cnid, __builtin_return_address(0));
	switch (tree->cnid) {
	case HFSPLUS_CAT_CNID:
		mutex_lock_nested(&tree->tree_lock, CATALOG_BTREE_MUTEX);
		break;
	case HFSPLUS_EXT_CNID:
		mutex_lock_nested(&tree->tree_lock, EXTENTS_BTREE_MUTEX);
		break;
	case HFSPLUS_ATTR_CNID:
		mutex_lock_nested(&tree->tree_lock, ATTR_BTREE_MUTEX);
		break;
	default:
		BUG();
	}
	return 0;
}

void hfs_find_exit(struct hfs_find_data *fd)
{
	hfs_bnode_put(fd->bnode);
	kfree(fd->search_key);
	hfs_dbg(BNODE_REFS, "find_exit: %d (%p)\n",
		fd->tree->cnid, __builtin_return_address(0));
	mutex_unlock(&fd->tree->tree_lock);
	fd->tree = NULL;
}

int hfs_find_1st_rec_by_cnid(struct hfs_bnode *bnode,
				struct hfs_find_data *fd,
				int *begin,
				int *end,
				int *cur_rec)
{
	__be32 cur_cnid;
	__be32 search_cnid;

	if (bnode->tree->cnid == HFSPLUS_EXT_CNID) {
		cur_cnid = fd->key->ext.cnid;
		search_cnid = fd->search_key->ext.cnid;
	} else if (bnode->tree->cnid == HFSPLUS_CAT_CNID) {
		cur_cnid = fd->key->cat.parent;
		search_cnid = fd->search_key->cat.parent;
	} else if (bnode->tree->cnid == HFSPLUS_ATTR_CNID) {
		cur_cnid = fd->key->attr.cnid;
		search_cnid = fd->search_key->attr.cnid;
	} else {
		cur_cnid = 0;	/* used-uninitialized warning */
		search_cnid = 0;
		BUG();
	}

	if (cur_cnid == search_cnid) {
		(*end) = (*cur_rec);
		if ((*begin) == (*end))
			return 1;
	} else {
		if (be32_to_cpu(cur_cnid) < be32_to_cpu(search_cnid))
			(*begin) = (*cur_rec) + 1;
		else
			(*end) = (*cur_rec) - 1;
	}

	return 0;
}

int hfs_find_rec_by_key(struct hfs_bnode *bnode,
				struct hfs_find_data *fd,
				int *begin,
				int *end,
				int *cur_rec)
{
	int cmpval;

	cmpval = bnode->tree->keycmp(fd->key, fd->search_key);
	if (!cmpval) {
		(*end) = (*cur_rec);
		return 1;
	}
	if (cmpval < 0)
		(*begin) = (*cur_rec) + 1;
	else
		*(end) = (*cur_rec) - 1;

	return 0;
}

/* Find the record in bnode that best matches key (not greater than...)*/
int __hfs_brec_find(struct hfs_bnode *bnode, struct hfs_find_data *fd,
					search_strategy_t rec_found)
{
	u16 off, len, keylen;
	int rec;
	int b, e;
	int res;

	if (!rec_found)
		BUG();

	b = 0;
	e = bnode->num_recs - 1;
	res = -ENOENT;
	do {
		rec = (e + b) / 2;
		len = hfs_brec_lenoff(bnode, rec, &off);
		keylen = hfs_brec_keylen(bnode, rec);
		if (keylen == 0) {
			res = -EINVAL;
			goto fail;
		}
		hfs_bnode_read(bnode, fd->key, off, keylen);
		if (rec_found(bnode, fd, &b, &e, &rec)) {
			res = 0;
			goto done;
		}
	} while (b <= e);

	if (rec != e && e >= 0) {
		len = hfs_brec_lenoff(bnode, e, &off);
		keylen = hfs_brec_keylen(bnode, e);
		if (keylen == 0) {
			res = -EINVAL;
			goto fail;
		}
		hfs_bnode_read(bnode, fd->key, off, keylen);
	}

done:
	fd->record = e;
	fd->keyoffset = off;
	fd->keylength = keylen;
	fd->entryoffset = off + keylen;
	fd->entrylength = len - keylen;

fail:
	return res;
}

/* Traverse a B*Tree from the root to a leaf finding best fit to key */
/* Return allocated copy of node found, set recnum to best record */
int hfs_brec_find(struct hfs_find_data *fd, search_strategy_t do_key_compare)
{
	struct hfs_btree *tree;
	struct hfs_bnode *bnode;
	u32 nidx, parent;
	__be32 data;
	int height, res;

	tree = fd->tree;
	if (fd->bnode)
		hfs_bnode_put(fd->bnode);
	fd->bnode = NULL;
	nidx = tree->root;
	if (!nidx)
		return -ENOENT;
	height = tree->depth;
	res = 0;
	parent = 0;
	for (;;) {
		bnode = hfs_bnode_find(tree, nidx);
		if (IS_ERR(bnode)) {
			res = PTR_ERR(bnode);
			bnode = NULL;
			break;
		}
		if (bnode->height != height)
			goto invalid;
		if (bnode->type != (--height ? HFS_NODE_INDEX : HFS_NODE_LEAF))
			goto invalid;
		bnode->parent = parent;

		res = __hfs_brec_find(bnode, fd, do_key_compare);
		if (!height)
			break;
		if (fd->record < 0)
			goto release;

		parent = nidx;
		hfs_bnode_read(bnode, &data, fd->entryoffset, 4);
		nidx = be32_to_cpu(data);
		hfs_bnode_put(bnode);
	}
	fd->bnode = bnode;
	return res;

invalid:
	pr_err("inconsistency in B*Tree (%d,%d,%d,%u,%u)\n",
		height, bnode->height, bnode->type, nidx, parent);
	res = -EIO;
release:
	hfs_bnode_put(bnode);
	return res;
}

int hfs_brec_read(struct hfs_find_data *fd, void *rec, int rec_len)
{
	int res;

	res = hfs_brec_find(fd, hfs_find_rec_by_key);
	if (res)
		return res;
	if (fd->entrylength > rec_len)
		return -EINVAL;
	hfs_bnode_read(fd->bnode, rec, fd->entryoffset, fd->entrylength);
	return 0;
}

int hfs_brec_goto(struct hfs_find_data *fd, int cnt)
{
	struct hfs_btree *tree;
	struct hfs_bnode *bnode;
	int idx, res = 0;
	u16 off, len, keylen;

	bnode = fd->bnode;
	tree = bnode->tree;

	if (cnt < 0) {
		cnt = -cnt;
		while (cnt > fd->record) {
			cnt -= fd->record + 1;
			fd->record = bnode->num_recs - 1;
			idx = bnode->prev;
			if (!idx) {
				res = -ENOENT;
				goto out;
			}
			hfs_bnode_put(bnode);
			bnode = hfs_bnode_find(tree, idx);
			if (IS_ERR(bnode)) {
				res = PTR_ERR(bnode);
				bnode = NULL;
				goto out;
			}
		}
		fd->record -= cnt;
	} else {
		while (cnt >= bnode->num_recs - fd->record) {
			cnt -= bnode->num_recs - fd->record;
			fd->record = 0;
			idx = bnode->next;
			if (!idx) {
				res = -ENOENT;
				goto out;
			}
			hfs_bnode_put(bnode);
			bnode = hfs_bnode_find(tree, idx);
			if (IS_ERR(bnode)) {
				res = PTR_ERR(bnode);
				bnode = NULL;
				goto out;
			}
		}
		fd->record += cnt;
	}

	len = hfs_brec_lenoff(bnode, fd->record, &off);
	keylen = hfs_brec_keylen(bnode, fd->record);
	if (keylen == 0) {
		res = -EINVAL;
		goto out;
	}
	fd->keyoffset = off;
	fd->keylength = keylen;
	fd->entryoffset = off + keylen;
	fd->entrylength = len - keylen;
	hfs_bnode_read(bnode, fd->key, off, keylen);
out:
	fd->bnode = bnode;
	return res;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/bfind.c */
/************************************************************/
/*
 * linux/fs/hfsplus/tables.c
 *
 * Various data tables
 */

// #include "hfsplus_fs.h"

/*
 *  Unicode case folding table taken from Apple Technote #1150
 *  (HFS Plus Volume Format)
 */

u16 hfsplus_case_fold_table[] = {
/*
 *  The lower case table consists of a 256-entry high-byte table followed by
 *  some number of 256-entry subtables. The high-byte table contains either an
 *  offset to the subtable for characters with that high byte or zero, which
 *  means that there are no case mappings or ignored characters in that block.
 *  Ignored characters are mapped to zero.
 */

    // High-byte indices ( == 0 iff no case mapping and no ignorables )


    /* 0 */ 0x0100, 0x0200, 0x0000, 0x0300, 0x0400, 0x0500, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 1 */ 0x0600, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 2 */ 0x0700, 0x0800, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 3 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 4 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 5 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 6 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 7 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 8 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 9 */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* A */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* B */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* C */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* D */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* E */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* F */ 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
            0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0900, 0x0A00,

    // Table 1 (for high byte 0x00)

    /* 0 */ 0xFFFF, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
            0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,
    /* 1 */ 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
            0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,
    /* 2 */ 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
            0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
    /* 3 */ 0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
            0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
    /* 4 */ 0x0040, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
            0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    /* 5 */ 0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
            0x0078, 0x0079, 0x007A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
    /* 6 */ 0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
            0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
    /* 7 */ 0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
            0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x007F,
    /* 8 */ 0x0080, 0x0081, 0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087,
            0x0088, 0x0089, 0x008A, 0x008B, 0x008C, 0x008D, 0x008E, 0x008F,
    /* 9 */ 0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
            0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F,
    /* A */ 0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7,
            0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF,
    /* B */ 0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7,
            0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF,
    /* C */ 0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00E6, 0x00C7,
            0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF,
    /* D */ 0x00F0, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7,
            0x00F8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00FE, 0x00DF,
    /* E */ 0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7,
            0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF,
    /* F */ 0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7,
            0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF,

    // Table 2 (for high byte 0x01)

    /* 0 */ 0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107,
            0x0108, 0x0109, 0x010A, 0x010B, 0x010C, 0x010D, 0x010E, 0x010F,
    /* 1 */ 0x0111, 0x0111, 0x0112, 0x0113, 0x0114, 0x0115, 0x0116, 0x0117,
            0x0118, 0x0119, 0x011A, 0x011B, 0x011C, 0x011D, 0x011E, 0x011F,
    /* 2 */ 0x0120, 0x0121, 0x0122, 0x0123, 0x0124, 0x0125, 0x0127, 0x0127,
            0x0128, 0x0129, 0x012A, 0x012B, 0x012C, 0x012D, 0x012E, 0x012F,
    /* 3 */ 0x0130, 0x0131, 0x0133, 0x0133, 0x0134, 0x0135, 0x0136, 0x0137,
            0x0138, 0x0139, 0x013A, 0x013B, 0x013C, 0x013D, 0x013E, 0x0140,
    /* 4 */ 0x0140, 0x0142, 0x0142, 0x0143, 0x0144, 0x0145, 0x0146, 0x0147,
            0x0148, 0x0149, 0x014B, 0x014B, 0x014C, 0x014D, 0x014E, 0x014F,
    /* 5 */ 0x0150, 0x0151, 0x0153, 0x0153, 0x0154, 0x0155, 0x0156, 0x0157,
            0x0158, 0x0159, 0x015A, 0x015B, 0x015C, 0x015D, 0x015E, 0x015F,
    /* 6 */ 0x0160, 0x0161, 0x0162, 0x0163, 0x0164, 0x0165, 0x0167, 0x0167,
            0x0168, 0x0169, 0x016A, 0x016B, 0x016C, 0x016D, 0x016E, 0x016F,
    /* 7 */ 0x0170, 0x0171, 0x0172, 0x0173, 0x0174, 0x0175, 0x0176, 0x0177,
            0x0178, 0x0179, 0x017A, 0x017B, 0x017C, 0x017D, 0x017E, 0x017F,
    /* 8 */ 0x0180, 0x0253, 0x0183, 0x0183, 0x0185, 0x0185, 0x0254, 0x0188,
            0x0188, 0x0256, 0x0257, 0x018C, 0x018C, 0x018D, 0x01DD, 0x0259,
    /* 9 */ 0x025B, 0x0192, 0x0192, 0x0260, 0x0263, 0x0195, 0x0269, 0x0268,
            0x0199, 0x0199, 0x019A, 0x019B, 0x026F, 0x0272, 0x019E, 0x0275,
    /* A */ 0x01A0, 0x01A1, 0x01A3, 0x01A3, 0x01A5, 0x01A5, 0x01A6, 0x01A8,
            0x01A8, 0x0283, 0x01AA, 0x01AB, 0x01AD, 0x01AD, 0x0288, 0x01AF,
    /* B */ 0x01B0, 0x028A, 0x028B, 0x01B4, 0x01B4, 0x01B6, 0x01B6, 0x0292,
            0x01B9, 0x01B9, 0x01BA, 0x01BB, 0x01BD, 0x01BD, 0x01BE, 0x01BF,
    /* C */ 0x01C0, 0x01C1, 0x01C2, 0x01C3, 0x01C6, 0x01C6, 0x01C6, 0x01C9,
            0x01C9, 0x01C9, 0x01CC, 0x01CC, 0x01CC, 0x01CD, 0x01CE, 0x01CF,
    /* D */ 0x01D0, 0x01D1, 0x01D2, 0x01D3, 0x01D4, 0x01D5, 0x01D6, 0x01D7,
            0x01D8, 0x01D9, 0x01DA, 0x01DB, 0x01DC, 0x01DD, 0x01DE, 0x01DF,
    /* E */ 0x01E0, 0x01E1, 0x01E2, 0x01E3, 0x01E5, 0x01E5, 0x01E6, 0x01E7,
            0x01E8, 0x01E9, 0x01EA, 0x01EB, 0x01EC, 0x01ED, 0x01EE, 0x01EF,
    /* F */ 0x01F0, 0x01F3, 0x01F3, 0x01F3, 0x01F4, 0x01F5, 0x01F6, 0x01F7,
            0x01F8, 0x01F9, 0x01FA, 0x01FB, 0x01FC, 0x01FD, 0x01FE, 0x01FF,

    // Table 3 (for high byte 0x03)

    /* 0 */ 0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x0305, 0x0306, 0x0307,
            0x0308, 0x0309, 0x030A, 0x030B, 0x030C, 0x030D, 0x030E, 0x030F,
    /* 1 */ 0x0310, 0x0311, 0x0312, 0x0313, 0x0314, 0x0315, 0x0316, 0x0317,
            0x0318, 0x0319, 0x031A, 0x031B, 0x031C, 0x031D, 0x031E, 0x031F,
    /* 2 */ 0x0320, 0x0321, 0x0322, 0x0323, 0x0324, 0x0325, 0x0326, 0x0327,
            0x0328, 0x0329, 0x032A, 0x032B, 0x032C, 0x032D, 0x032E, 0x032F,
    /* 3 */ 0x0330, 0x0331, 0x0332, 0x0333, 0x0334, 0x0335, 0x0336, 0x0337,
            0x0338, 0x0339, 0x033A, 0x033B, 0x033C, 0x033D, 0x033E, 0x033F,
    /* 4 */ 0x0340, 0x0341, 0x0342, 0x0343, 0x0344, 0x0345, 0x0346, 0x0347,
            0x0348, 0x0349, 0x034A, 0x034B, 0x034C, 0x034D, 0x034E, 0x034F,
    /* 5 */ 0x0350, 0x0351, 0x0352, 0x0353, 0x0354, 0x0355, 0x0356, 0x0357,
            0x0358, 0x0359, 0x035A, 0x035B, 0x035C, 0x035D, 0x035E, 0x035F,
    /* 6 */ 0x0360, 0x0361, 0x0362, 0x0363, 0x0364, 0x0365, 0x0366, 0x0367,
            0x0368, 0x0369, 0x036A, 0x036B, 0x036C, 0x036D, 0x036E, 0x036F,
    /* 7 */ 0x0370, 0x0371, 0x0372, 0x0373, 0x0374, 0x0375, 0x0376, 0x0377,
            0x0378, 0x0379, 0x037A, 0x037B, 0x037C, 0x037D, 0x037E, 0x037F,
    /* 8 */ 0x0380, 0x0381, 0x0382, 0x0383, 0x0384, 0x0385, 0x0386, 0x0387,
            0x0388, 0x0389, 0x038A, 0x038B, 0x038C, 0x038D, 0x038E, 0x038F,
    /* 9 */ 0x0390, 0x03B1, 0x03B2, 0x03B3, 0x03B4, 0x03B5, 0x03B6, 0x03B7,
            0x03B8, 0x03B9, 0x03BA, 0x03BB, 0x03BC, 0x03BD, 0x03BE, 0x03BF,
    /* A */ 0x03C0, 0x03C1, 0x03A2, 0x03C3, 0x03C4, 0x03C5, 0x03C6, 0x03C7,
            0x03C8, 0x03C9, 0x03AA, 0x03AB, 0x03AC, 0x03AD, 0x03AE, 0x03AF,
    /* B */ 0x03B0, 0x03B1, 0x03B2, 0x03B3, 0x03B4, 0x03B5, 0x03B6, 0x03B7,
            0x03B8, 0x03B9, 0x03BA, 0x03BB, 0x03BC, 0x03BD, 0x03BE, 0x03BF,
    /* C */ 0x03C0, 0x03C1, 0x03C2, 0x03C3, 0x03C4, 0x03C5, 0x03C6, 0x03C7,
            0x03C8, 0x03C9, 0x03CA, 0x03CB, 0x03CC, 0x03CD, 0x03CE, 0x03CF,
    /* D */ 0x03D0, 0x03D1, 0x03D2, 0x03D3, 0x03D4, 0x03D5, 0x03D6, 0x03D7,
            0x03D8, 0x03D9, 0x03DA, 0x03DB, 0x03DC, 0x03DD, 0x03DE, 0x03DF,
    /* E */ 0x03E0, 0x03E1, 0x03E3, 0x03E3, 0x03E5, 0x03E5, 0x03E7, 0x03E7,
            0x03E9, 0x03E9, 0x03EB, 0x03EB, 0x03ED, 0x03ED, 0x03EF, 0x03EF,
    /* F */ 0x03F0, 0x03F1, 0x03F2, 0x03F3, 0x03F4, 0x03F5, 0x03F6, 0x03F7,
            0x03F8, 0x03F9, 0x03FA, 0x03FB, 0x03FC, 0x03FD, 0x03FE, 0x03FF,

    // Table 4 (for high byte 0x04)

    /* 0 */ 0x0400, 0x0401, 0x0452, 0x0403, 0x0454, 0x0455, 0x0456, 0x0407,
            0x0458, 0x0459, 0x045A, 0x045B, 0x040C, 0x040D, 0x040E, 0x045F,
    /* 1 */ 0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,
            0x0438, 0x0419, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F,
    /* 2 */ 0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
            0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F,
    /* 3 */ 0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,
            0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F,
    /* 4 */ 0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
            0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F,
    /* 5 */ 0x0450, 0x0451, 0x0452, 0x0453, 0x0454, 0x0455, 0x0456, 0x0457,
            0x0458, 0x0459, 0x045A, 0x045B, 0x045C, 0x045D, 0x045E, 0x045F,
    /* 6 */ 0x0461, 0x0461, 0x0463, 0x0463, 0x0465, 0x0465, 0x0467, 0x0467,
            0x0469, 0x0469, 0x046B, 0x046B, 0x046D, 0x046D, 0x046F, 0x046F,
    /* 7 */ 0x0471, 0x0471, 0x0473, 0x0473, 0x0475, 0x0475, 0x0476, 0x0477,
            0x0479, 0x0479, 0x047B, 0x047B, 0x047D, 0x047D, 0x047F, 0x047F,
    /* 8 */ 0x0481, 0x0481, 0x0482, 0x0483, 0x0484, 0x0485, 0x0486, 0x0487,
            0x0488, 0x0489, 0x048A, 0x048B, 0x048C, 0x048D, 0x048E, 0x048F,
    /* 9 */ 0x0491, 0x0491, 0x0493, 0x0493, 0x0495, 0x0495, 0x0497, 0x0497,
            0x0499, 0x0499, 0x049B, 0x049B, 0x049D, 0x049D, 0x049F, 0x049F,
    /* A */ 0x04A1, 0x04A1, 0x04A3, 0x04A3, 0x04A5, 0x04A5, 0x04A7, 0x04A7,
            0x04A9, 0x04A9, 0x04AB, 0x04AB, 0x04AD, 0x04AD, 0x04AF, 0x04AF,
    /* B */ 0x04B1, 0x04B1, 0x04B3, 0x04B3, 0x04B5, 0x04B5, 0x04B7, 0x04B7,
            0x04B9, 0x04B9, 0x04BB, 0x04BB, 0x04BD, 0x04BD, 0x04BF, 0x04BF,
    /* C */ 0x04C0, 0x04C1, 0x04C2, 0x04C4, 0x04C4, 0x04C5, 0x04C6, 0x04C8,
            0x04C8, 0x04C9, 0x04CA, 0x04CC, 0x04CC, 0x04CD, 0x04CE, 0x04CF,
    /* D */ 0x04D0, 0x04D1, 0x04D2, 0x04D3, 0x04D4, 0x04D5, 0x04D6, 0x04D7,
            0x04D8, 0x04D9, 0x04DA, 0x04DB, 0x04DC, 0x04DD, 0x04DE, 0x04DF,
    /* E */ 0x04E0, 0x04E1, 0x04E2, 0x04E3, 0x04E4, 0x04E5, 0x04E6, 0x04E7,
            0x04E8, 0x04E9, 0x04EA, 0x04EB, 0x04EC, 0x04ED, 0x04EE, 0x04EF,
    /* F */ 0x04F0, 0x04F1, 0x04F2, 0x04F3, 0x04F4, 0x04F5, 0x04F6, 0x04F7,
            0x04F8, 0x04F9, 0x04FA, 0x04FB, 0x04FC, 0x04FD, 0x04FE, 0x04FF,

    // Table 5 (for high byte 0x05)

    /* 0 */ 0x0500, 0x0501, 0x0502, 0x0503, 0x0504, 0x0505, 0x0506, 0x0507,
            0x0508, 0x0509, 0x050A, 0x050B, 0x050C, 0x050D, 0x050E, 0x050F,
    /* 1 */ 0x0510, 0x0511, 0x0512, 0x0513, 0x0514, 0x0515, 0x0516, 0x0517,
            0x0518, 0x0519, 0x051A, 0x051B, 0x051C, 0x051D, 0x051E, 0x051F,
    /* 2 */ 0x0520, 0x0521, 0x0522, 0x0523, 0x0524, 0x0525, 0x0526, 0x0527,
            0x0528, 0x0529, 0x052A, 0x052B, 0x052C, 0x052D, 0x052E, 0x052F,
    /* 3 */ 0x0530, 0x0561, 0x0562, 0x0563, 0x0564, 0x0565, 0x0566, 0x0567,
            0x0568, 0x0569, 0x056A, 0x056B, 0x056C, 0x056D, 0x056E, 0x056F,
    /* 4 */ 0x0570, 0x0571, 0x0572, 0x0573, 0x0574, 0x0575, 0x0576, 0x0577,
            0x0578, 0x0579, 0x057A, 0x057B, 0x057C, 0x057D, 0x057E, 0x057F,
    /* 5 */ 0x0580, 0x0581, 0x0582, 0x0583, 0x0584, 0x0585, 0x0586, 0x0557,
            0x0558, 0x0559, 0x055A, 0x055B, 0x055C, 0x055D, 0x055E, 0x055F,
    /* 6 */ 0x0560, 0x0561, 0x0562, 0x0563, 0x0564, 0x0565, 0x0566, 0x0567,
            0x0568, 0x0569, 0x056A, 0x056B, 0x056C, 0x056D, 0x056E, 0x056F,
    /* 7 */ 0x0570, 0x0571, 0x0572, 0x0573, 0x0574, 0x0575, 0x0576, 0x0577,
            0x0578, 0x0579, 0x057A, 0x057B, 0x057C, 0x057D, 0x057E, 0x057F,
    /* 8 */ 0x0580, 0x0581, 0x0582, 0x0583, 0x0584, 0x0585, 0x0586, 0x0587,
            0x0588, 0x0589, 0x058A, 0x058B, 0x058C, 0x058D, 0x058E, 0x058F,
    /* 9 */ 0x0590, 0x0591, 0x0592, 0x0593, 0x0594, 0x0595, 0x0596, 0x0597,
            0x0598, 0x0599, 0x059A, 0x059B, 0x059C, 0x059D, 0x059E, 0x059F,
    /* A */ 0x05A0, 0x05A1, 0x05A2, 0x05A3, 0x05A4, 0x05A5, 0x05A6, 0x05A7,
            0x05A8, 0x05A9, 0x05AA, 0x05AB, 0x05AC, 0x05AD, 0x05AE, 0x05AF,
    /* B */ 0x05B0, 0x05B1, 0x05B2, 0x05B3, 0x05B4, 0x05B5, 0x05B6, 0x05B7,
            0x05B8, 0x05B9, 0x05BA, 0x05BB, 0x05BC, 0x05BD, 0x05BE, 0x05BF,
    /* C */ 0x05C0, 0x05C1, 0x05C2, 0x05C3, 0x05C4, 0x05C5, 0x05C6, 0x05C7,
            0x05C8, 0x05C9, 0x05CA, 0x05CB, 0x05CC, 0x05CD, 0x05CE, 0x05CF,
    /* D */ 0x05D0, 0x05D1, 0x05D2, 0x05D3, 0x05D4, 0x05D5, 0x05D6, 0x05D7,
            0x05D8, 0x05D9, 0x05DA, 0x05DB, 0x05DC, 0x05DD, 0x05DE, 0x05DF,
    /* E */ 0x05E0, 0x05E1, 0x05E2, 0x05E3, 0x05E4, 0x05E5, 0x05E6, 0x05E7,
            0x05E8, 0x05E9, 0x05EA, 0x05EB, 0x05EC, 0x05ED, 0x05EE, 0x05EF,
    /* F */ 0x05F0, 0x05F1, 0x05F2, 0x05F3, 0x05F4, 0x05F5, 0x05F6, 0x05F7,
            0x05F8, 0x05F9, 0x05FA, 0x05FB, 0x05FC, 0x05FD, 0x05FE, 0x05FF,

    // Table 6 (for high byte 0x10)

    /* 0 */ 0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007,
            0x1008, 0x1009, 0x100A, 0x100B, 0x100C, 0x100D, 0x100E, 0x100F,
    /* 1 */ 0x1010, 0x1011, 0x1012, 0x1013, 0x1014, 0x1015, 0x1016, 0x1017,
            0x1018, 0x1019, 0x101A, 0x101B, 0x101C, 0x101D, 0x101E, 0x101F,
    /* 2 */ 0x1020, 0x1021, 0x1022, 0x1023, 0x1024, 0x1025, 0x1026, 0x1027,
            0x1028, 0x1029, 0x102A, 0x102B, 0x102C, 0x102D, 0x102E, 0x102F,
    /* 3 */ 0x1030, 0x1031, 0x1032, 0x1033, 0x1034, 0x1035, 0x1036, 0x1037,
            0x1038, 0x1039, 0x103A, 0x103B, 0x103C, 0x103D, 0x103E, 0x103F,
    /* 4 */ 0x1040, 0x1041, 0x1042, 0x1043, 0x1044, 0x1045, 0x1046, 0x1047,
            0x1048, 0x1049, 0x104A, 0x104B, 0x104C, 0x104D, 0x104E, 0x104F,
    /* 5 */ 0x1050, 0x1051, 0x1052, 0x1053, 0x1054, 0x1055, 0x1056, 0x1057,
            0x1058, 0x1059, 0x105A, 0x105B, 0x105C, 0x105D, 0x105E, 0x105F,
    /* 6 */ 0x1060, 0x1061, 0x1062, 0x1063, 0x1064, 0x1065, 0x1066, 0x1067,
            0x1068, 0x1069, 0x106A, 0x106B, 0x106C, 0x106D, 0x106E, 0x106F,
    /* 7 */ 0x1070, 0x1071, 0x1072, 0x1073, 0x1074, 0x1075, 0x1076, 0x1077,
            0x1078, 0x1079, 0x107A, 0x107B, 0x107C, 0x107D, 0x107E, 0x107F,
    /* 8 */ 0x1080, 0x1081, 0x1082, 0x1083, 0x1084, 0x1085, 0x1086, 0x1087,
            0x1088, 0x1089, 0x108A, 0x108B, 0x108C, 0x108D, 0x108E, 0x108F,
    /* 9 */ 0x1090, 0x1091, 0x1092, 0x1093, 0x1094, 0x1095, 0x1096, 0x1097,
            0x1098, 0x1099, 0x109A, 0x109B, 0x109C, 0x109D, 0x109E, 0x109F,
    /* A */ 0x10D0, 0x10D1, 0x10D2, 0x10D3, 0x10D4, 0x10D5, 0x10D6, 0x10D7,
            0x10D8, 0x10D9, 0x10DA, 0x10DB, 0x10DC, 0x10DD, 0x10DE, 0x10DF,
    /* B */ 0x10E0, 0x10E1, 0x10E2, 0x10E3, 0x10E4, 0x10E5, 0x10E6, 0x10E7,
            0x10E8, 0x10E9, 0x10EA, 0x10EB, 0x10EC, 0x10ED, 0x10EE, 0x10EF,
    /* C */ 0x10F0, 0x10F1, 0x10F2, 0x10F3, 0x10F4, 0x10F5, 0x10C6, 0x10C7,
            0x10C8, 0x10C9, 0x10CA, 0x10CB, 0x10CC, 0x10CD, 0x10CE, 0x10CF,
    /* D */ 0x10D0, 0x10D1, 0x10D2, 0x10D3, 0x10D4, 0x10D5, 0x10D6, 0x10D7,
            0x10D8, 0x10D9, 0x10DA, 0x10DB, 0x10DC, 0x10DD, 0x10DE, 0x10DF,
    /* E */ 0x10E0, 0x10E1, 0x10E2, 0x10E3, 0x10E4, 0x10E5, 0x10E6, 0x10E7,
            0x10E8, 0x10E9, 0x10EA, 0x10EB, 0x10EC, 0x10ED, 0x10EE, 0x10EF,
    /* F */ 0x10F0, 0x10F1, 0x10F2, 0x10F3, 0x10F4, 0x10F5, 0x10F6, 0x10F7,
            0x10F8, 0x10F9, 0x10FA, 0x10FB, 0x10FC, 0x10FD, 0x10FE, 0x10FF,

    // Table 7 (for high byte 0x20)

    /* 0 */ 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
            0x2008, 0x2009, 0x200A, 0x200B, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 1 */ 0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2016, 0x2017,
            0x2018, 0x2019, 0x201A, 0x201B, 0x201C, 0x201D, 0x201E, 0x201F,
    /* 2 */ 0x2020, 0x2021, 0x2022, 0x2023, 0x2024, 0x2025, 0x2026, 0x2027,
            0x2028, 0x2029, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x202F,
    /* 3 */ 0x2030, 0x2031, 0x2032, 0x2033, 0x2034, 0x2035, 0x2036, 0x2037,
            0x2038, 0x2039, 0x203A, 0x203B, 0x203C, 0x203D, 0x203E, 0x203F,
    /* 4 */ 0x2040, 0x2041, 0x2042, 0x2043, 0x2044, 0x2045, 0x2046, 0x2047,
            0x2048, 0x2049, 0x204A, 0x204B, 0x204C, 0x204D, 0x204E, 0x204F,
    /* 5 */ 0x2050, 0x2051, 0x2052, 0x2053, 0x2054, 0x2055, 0x2056, 0x2057,
            0x2058, 0x2059, 0x205A, 0x205B, 0x205C, 0x205D, 0x205E, 0x205F,
    /* 6 */ 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x2065, 0x2066, 0x2067,
            0x2068, 0x2069, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    /* 7 */ 0x2070, 0x2071, 0x2072, 0x2073, 0x2074, 0x2075, 0x2076, 0x2077,
            0x2078, 0x2079, 0x207A, 0x207B, 0x207C, 0x207D, 0x207E, 0x207F,
    /* 8 */ 0x2080, 0x2081, 0x2082, 0x2083, 0x2084, 0x2085, 0x2086, 0x2087,
            0x2088, 0x2089, 0x208A, 0x208B, 0x208C, 0x208D, 0x208E, 0x208F,
    /* 9 */ 0x2090, 0x2091, 0x2092, 0x2093, 0x2094, 0x2095, 0x2096, 0x2097,
            0x2098, 0x2099, 0x209A, 0x209B, 0x209C, 0x209D, 0x209E, 0x209F,
    /* A */ 0x20A0, 0x20A1, 0x20A2, 0x20A3, 0x20A4, 0x20A5, 0x20A6, 0x20A7,
            0x20A8, 0x20A9, 0x20AA, 0x20AB, 0x20AC, 0x20AD, 0x20AE, 0x20AF,
    /* B */ 0x20B0, 0x20B1, 0x20B2, 0x20B3, 0x20B4, 0x20B5, 0x20B6, 0x20B7,
            0x20B8, 0x20B9, 0x20BA, 0x20BB, 0x20BC, 0x20BD, 0x20BE, 0x20BF,
    /* C */ 0x20C0, 0x20C1, 0x20C2, 0x20C3, 0x20C4, 0x20C5, 0x20C6, 0x20C7,
            0x20C8, 0x20C9, 0x20CA, 0x20CB, 0x20CC, 0x20CD, 0x20CE, 0x20CF,
    /* D */ 0x20D0, 0x20D1, 0x20D2, 0x20D3, 0x20D4, 0x20D5, 0x20D6, 0x20D7,
            0x20D8, 0x20D9, 0x20DA, 0x20DB, 0x20DC, 0x20DD, 0x20DE, 0x20DF,
    /* E */ 0x20E0, 0x20E1, 0x20E2, 0x20E3, 0x20E4, 0x20E5, 0x20E6, 0x20E7,
            0x20E8, 0x20E9, 0x20EA, 0x20EB, 0x20EC, 0x20ED, 0x20EE, 0x20EF,
    /* F */ 0x20F0, 0x20F1, 0x20F2, 0x20F3, 0x20F4, 0x20F5, 0x20F6, 0x20F7,
            0x20F8, 0x20F9, 0x20FA, 0x20FB, 0x20FC, 0x20FD, 0x20FE, 0x20FF,

    // Table 8 (for high byte 0x21)

    /* 0 */ 0x2100, 0x2101, 0x2102, 0x2103, 0x2104, 0x2105, 0x2106, 0x2107,
            0x2108, 0x2109, 0x210A, 0x210B, 0x210C, 0x210D, 0x210E, 0x210F,
    /* 1 */ 0x2110, 0x2111, 0x2112, 0x2113, 0x2114, 0x2115, 0x2116, 0x2117,
            0x2118, 0x2119, 0x211A, 0x211B, 0x211C, 0x211D, 0x211E, 0x211F,
    /* 2 */ 0x2120, 0x2121, 0x2122, 0x2123, 0x2124, 0x2125, 0x2126, 0x2127,
            0x2128, 0x2129, 0x212A, 0x212B, 0x212C, 0x212D, 0x212E, 0x212F,
    /* 3 */ 0x2130, 0x2131, 0x2132, 0x2133, 0x2134, 0x2135, 0x2136, 0x2137,
            0x2138, 0x2139, 0x213A, 0x213B, 0x213C, 0x213D, 0x213E, 0x213F,
    /* 4 */ 0x2140, 0x2141, 0x2142, 0x2143, 0x2144, 0x2145, 0x2146, 0x2147,
            0x2148, 0x2149, 0x214A, 0x214B, 0x214C, 0x214D, 0x214E, 0x214F,
    /* 5 */ 0x2150, 0x2151, 0x2152, 0x2153, 0x2154, 0x2155, 0x2156, 0x2157,
            0x2158, 0x2159, 0x215A, 0x215B, 0x215C, 0x215D, 0x215E, 0x215F,
    /* 6 */ 0x2170, 0x2171, 0x2172, 0x2173, 0x2174, 0x2175, 0x2176, 0x2177,
            0x2178, 0x2179, 0x217A, 0x217B, 0x217C, 0x217D, 0x217E, 0x217F,
    /* 7 */ 0x2170, 0x2171, 0x2172, 0x2173, 0x2174, 0x2175, 0x2176, 0x2177,
            0x2178, 0x2179, 0x217A, 0x217B, 0x217C, 0x217D, 0x217E, 0x217F,
    /* 8 */ 0x2180, 0x2181, 0x2182, 0x2183, 0x2184, 0x2185, 0x2186, 0x2187,
            0x2188, 0x2189, 0x218A, 0x218B, 0x218C, 0x218D, 0x218E, 0x218F,
    /* 9 */ 0x2190, 0x2191, 0x2192, 0x2193, 0x2194, 0x2195, 0x2196, 0x2197,
            0x2198, 0x2199, 0x219A, 0x219B, 0x219C, 0x219D, 0x219E, 0x219F,
    /* A */ 0x21A0, 0x21A1, 0x21A2, 0x21A3, 0x21A4, 0x21A5, 0x21A6, 0x21A7,
            0x21A8, 0x21A9, 0x21AA, 0x21AB, 0x21AC, 0x21AD, 0x21AE, 0x21AF,
    /* B */ 0x21B0, 0x21B1, 0x21B2, 0x21B3, 0x21B4, 0x21B5, 0x21B6, 0x21B7,
            0x21B8, 0x21B9, 0x21BA, 0x21BB, 0x21BC, 0x21BD, 0x21BE, 0x21BF,
    /* C */ 0x21C0, 0x21C1, 0x21C2, 0x21C3, 0x21C4, 0x21C5, 0x21C6, 0x21C7,
            0x21C8, 0x21C9, 0x21CA, 0x21CB, 0x21CC, 0x21CD, 0x21CE, 0x21CF,
    /* D */ 0x21D0, 0x21D1, 0x21D2, 0x21D3, 0x21D4, 0x21D5, 0x21D6, 0x21D7,
            0x21D8, 0x21D9, 0x21DA, 0x21DB, 0x21DC, 0x21DD, 0x21DE, 0x21DF,
    /* E */ 0x21E0, 0x21E1, 0x21E2, 0x21E3, 0x21E4, 0x21E5, 0x21E6, 0x21E7,
            0x21E8, 0x21E9, 0x21EA, 0x21EB, 0x21EC, 0x21ED, 0x21EE, 0x21EF,
    /* F */ 0x21F0, 0x21F1, 0x21F2, 0x21F3, 0x21F4, 0x21F5, 0x21F6, 0x21F7,
            0x21F8, 0x21F9, 0x21FA, 0x21FB, 0x21FC, 0x21FD, 0x21FE, 0x21FF,

    // Table 9 (for high byte 0xFE)

    /* 0 */ 0xFE00, 0xFE01, 0xFE02, 0xFE03, 0xFE04, 0xFE05, 0xFE06, 0xFE07,
            0xFE08, 0xFE09, 0xFE0A, 0xFE0B, 0xFE0C, 0xFE0D, 0xFE0E, 0xFE0F,
    /* 1 */ 0xFE10, 0xFE11, 0xFE12, 0xFE13, 0xFE14, 0xFE15, 0xFE16, 0xFE17,
            0xFE18, 0xFE19, 0xFE1A, 0xFE1B, 0xFE1C, 0xFE1D, 0xFE1E, 0xFE1F,
    /* 2 */ 0xFE20, 0xFE21, 0xFE22, 0xFE23, 0xFE24, 0xFE25, 0xFE26, 0xFE27,
            0xFE28, 0xFE29, 0xFE2A, 0xFE2B, 0xFE2C, 0xFE2D, 0xFE2E, 0xFE2F,
    /* 3 */ 0xFE30, 0xFE31, 0xFE32, 0xFE33, 0xFE34, 0xFE35, 0xFE36, 0xFE37,
            0xFE38, 0xFE39, 0xFE3A, 0xFE3B, 0xFE3C, 0xFE3D, 0xFE3E, 0xFE3F,
    /* 4 */ 0xFE40, 0xFE41, 0xFE42, 0xFE43, 0xFE44, 0xFE45, 0xFE46, 0xFE47,
            0xFE48, 0xFE49, 0xFE4A, 0xFE4B, 0xFE4C, 0xFE4D, 0xFE4E, 0xFE4F,
    /* 5 */ 0xFE50, 0xFE51, 0xFE52, 0xFE53, 0xFE54, 0xFE55, 0xFE56, 0xFE57,
            0xFE58, 0xFE59, 0xFE5A, 0xFE5B, 0xFE5C, 0xFE5D, 0xFE5E, 0xFE5F,
    /* 6 */ 0xFE60, 0xFE61, 0xFE62, 0xFE63, 0xFE64, 0xFE65, 0xFE66, 0xFE67,
            0xFE68, 0xFE69, 0xFE6A, 0xFE6B, 0xFE6C, 0xFE6D, 0xFE6E, 0xFE6F,
    /* 7 */ 0xFE70, 0xFE71, 0xFE72, 0xFE73, 0xFE74, 0xFE75, 0xFE76, 0xFE77,
            0xFE78, 0xFE79, 0xFE7A, 0xFE7B, 0xFE7C, 0xFE7D, 0xFE7E, 0xFE7F,
    /* 8 */ 0xFE80, 0xFE81, 0xFE82, 0xFE83, 0xFE84, 0xFE85, 0xFE86, 0xFE87,
            0xFE88, 0xFE89, 0xFE8A, 0xFE8B, 0xFE8C, 0xFE8D, 0xFE8E, 0xFE8F,
    /* 9 */ 0xFE90, 0xFE91, 0xFE92, 0xFE93, 0xFE94, 0xFE95, 0xFE96, 0xFE97,
            0xFE98, 0xFE99, 0xFE9A, 0xFE9B, 0xFE9C, 0xFE9D, 0xFE9E, 0xFE9F,
    /* A */ 0xFEA0, 0xFEA1, 0xFEA2, 0xFEA3, 0xFEA4, 0xFEA5, 0xFEA6, 0xFEA7,
            0xFEA8, 0xFEA9, 0xFEAA, 0xFEAB, 0xFEAC, 0xFEAD, 0xFEAE, 0xFEAF,
    /* B */ 0xFEB0, 0xFEB1, 0xFEB2, 0xFEB3, 0xFEB4, 0xFEB5, 0xFEB6, 0xFEB7,
            0xFEB8, 0xFEB9, 0xFEBA, 0xFEBB, 0xFEBC, 0xFEBD, 0xFEBE, 0xFEBF,
    /* C */ 0xFEC0, 0xFEC1, 0xFEC2, 0xFEC3, 0xFEC4, 0xFEC5, 0xFEC6, 0xFEC7,
            0xFEC8, 0xFEC9, 0xFECA, 0xFECB, 0xFECC, 0xFECD, 0xFECE, 0xFECF,
    /* D */ 0xFED0, 0xFED1, 0xFED2, 0xFED3, 0xFED4, 0xFED5, 0xFED6, 0xFED7,
            0xFED8, 0xFED9, 0xFEDA, 0xFEDB, 0xFEDC, 0xFEDD, 0xFEDE, 0xFEDF,
    /* E */ 0xFEE0, 0xFEE1, 0xFEE2, 0xFEE3, 0xFEE4, 0xFEE5, 0xFEE6, 0xFEE7,
            0xFEE8, 0xFEE9, 0xFEEA, 0xFEEB, 0xFEEC, 0xFEED, 0xFEEE, 0xFEEF,
    /* F */ 0xFEF0, 0xFEF1, 0xFEF2, 0xFEF3, 0xFEF4, 0xFEF5, 0xFEF6, 0xFEF7,
            0xFEF8, 0xFEF9, 0xFEFA, 0xFEFB, 0xFEFC, 0xFEFD, 0xFEFE, 0x0000,

    // Table 10 (for high byte 0xFF)

    /* 0 */ 0xFF00, 0xFF01, 0xFF02, 0xFF03, 0xFF04, 0xFF05, 0xFF06, 0xFF07,
            0xFF08, 0xFF09, 0xFF0A, 0xFF0B, 0xFF0C, 0xFF0D, 0xFF0E, 0xFF0F,
    /* 1 */ 0xFF10, 0xFF11, 0xFF12, 0xFF13, 0xFF14, 0xFF15, 0xFF16, 0xFF17,
            0xFF18, 0xFF19, 0xFF1A, 0xFF1B, 0xFF1C, 0xFF1D, 0xFF1E, 0xFF1F,
    /* 2 */ 0xFF20, 0xFF41, 0xFF42, 0xFF43, 0xFF44, 0xFF45, 0xFF46, 0xFF47,
            0xFF48, 0xFF49, 0xFF4A, 0xFF4B, 0xFF4C, 0xFF4D, 0xFF4E, 0xFF4F,
    /* 3 */ 0xFF50, 0xFF51, 0xFF52, 0xFF53, 0xFF54, 0xFF55, 0xFF56, 0xFF57,
            0xFF58, 0xFF59, 0xFF5A, 0xFF3B, 0xFF3C, 0xFF3D, 0xFF3E, 0xFF3F,
    /* 4 */ 0xFF40, 0xFF41, 0xFF42, 0xFF43, 0xFF44, 0xFF45, 0xFF46, 0xFF47,
            0xFF48, 0xFF49, 0xFF4A, 0xFF4B, 0xFF4C, 0xFF4D, 0xFF4E, 0xFF4F,
    /* 5 */ 0xFF50, 0xFF51, 0xFF52, 0xFF53, 0xFF54, 0xFF55, 0xFF56, 0xFF57,
            0xFF58, 0xFF59, 0xFF5A, 0xFF5B, 0xFF5C, 0xFF5D, 0xFF5E, 0xFF5F,
    /* 6 */ 0xFF60, 0xFF61, 0xFF62, 0xFF63, 0xFF64, 0xFF65, 0xFF66, 0xFF67,
            0xFF68, 0xFF69, 0xFF6A, 0xFF6B, 0xFF6C, 0xFF6D, 0xFF6E, 0xFF6F,
    /* 7 */ 0xFF70, 0xFF71, 0xFF72, 0xFF73, 0xFF74, 0xFF75, 0xFF76, 0xFF77,
            0xFF78, 0xFF79, 0xFF7A, 0xFF7B, 0xFF7C, 0xFF7D, 0xFF7E, 0xFF7F,
    /* 8 */ 0xFF80, 0xFF81, 0xFF82, 0xFF83, 0xFF84, 0xFF85, 0xFF86, 0xFF87,
            0xFF88, 0xFF89, 0xFF8A, 0xFF8B, 0xFF8C, 0xFF8D, 0xFF8E, 0xFF8F,
    /* 9 */ 0xFF90, 0xFF91, 0xFF92, 0xFF93, 0xFF94, 0xFF95, 0xFF96, 0xFF97,
            0xFF98, 0xFF99, 0xFF9A, 0xFF9B, 0xFF9C, 0xFF9D, 0xFF9E, 0xFF9F,
    /* A */ 0xFFA0, 0xFFA1, 0xFFA2, 0xFFA3, 0xFFA4, 0xFFA5, 0xFFA6, 0xFFA7,
            0xFFA8, 0xFFA9, 0xFFAA, 0xFFAB, 0xFFAC, 0xFFAD, 0xFFAE, 0xFFAF,
    /* B */ 0xFFB0, 0xFFB1, 0xFFB2, 0xFFB3, 0xFFB4, 0xFFB5, 0xFFB6, 0xFFB7,
            0xFFB8, 0xFFB9, 0xFFBA, 0xFFBB, 0xFFBC, 0xFFBD, 0xFFBE, 0xFFBF,
    /* C */ 0xFFC0, 0xFFC1, 0xFFC2, 0xFFC3, 0xFFC4, 0xFFC5, 0xFFC6, 0xFFC7,
            0xFFC8, 0xFFC9, 0xFFCA, 0xFFCB, 0xFFCC, 0xFFCD, 0xFFCE, 0xFFCF,
    /* D */ 0xFFD0, 0xFFD1, 0xFFD2, 0xFFD3, 0xFFD4, 0xFFD5, 0xFFD6, 0xFFD7,
            0xFFD8, 0xFFD9, 0xFFDA, 0xFFDB, 0xFFDC, 0xFFDD, 0xFFDE, 0xFFDF,
    /* E */ 0xFFE0, 0xFFE1, 0xFFE2, 0xFFE3, 0xFFE4, 0xFFE5, 0xFFE6, 0xFFE7,
            0xFFE8, 0xFFE9, 0xFFEA, 0xFFEB, 0xFFEC, 0xFFED, 0xFFEE, 0xFFEF,
    /* F */ 0xFFF0, 0xFFF1, 0xFFF2, 0xFFF3, 0xFFF4, 0xFFF5, 0xFFF6, 0xFFF7,
            0xFFF8, 0xFFF9, 0xFFFA, 0xFFFB, 0xFFFC, 0xFFFD, 0xFFFE, 0xFFFF,
};

u16 hfsplus_decompose_table[] = {
	/* base table */
	0x0010, 0x04c0, 0x0000, 0x06f0, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0xffff, 0xffff, 0xffff, 0xffff, 0x0000, 0x07b0,
	/* char table 0x0___ */
	0x0020, 0x0070, 0x0160, 0x0190, 0x0230, 0x0000, 0x0000, 0x0000,
	0x0000, 0x02d0, 0x0340, 0x0360, 0x03b0, 0x03e0, 0x0400, 0x0430,
	/* char table 0x00__ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0030, 0x0040, 0x0050, 0x0060,
	/* char values 0x00c_ */
	0x2042, 0x204a, 0x2052, 0x205a, 0x2062, 0x206a, 0x0000, 0x2072,
	0x207a, 0x2082, 0x208a, 0x2092, 0x209a, 0x20a2, 0x20aa, 0x20b2,
	/* char values 0x00d_ */
	0x0000, 0x20ba, 0x20c2, 0x20ca, 0x20d2, 0x20da, 0x20e2, 0x0000,
	0x0000, 0x20ea, 0x20f2, 0x20fa, 0x2102, 0x210a, 0x0000, 0x0000,
	/* char values 0x00e_ */
	0x2112, 0x211a, 0x2122, 0x212a, 0x2132, 0x213a, 0x0000, 0x2142,
	0x214a, 0x2152, 0x215a, 0x2162, 0x216a, 0x2172, 0x217a, 0x2182,
	/* char values 0x00f_ */
	0x0000, 0x218a, 0x2192, 0x219a, 0x21a2, 0x21aa, 0x21b2, 0x0000,
	0x0000, 0x21ba, 0x21c2, 0x21ca, 0x21d2, 0x21da, 0x0000, 0x21e2,
	/* char table 0x01__ */
	0x0080, 0x0090, 0x00a0, 0x00b0, 0x00c0, 0x00d0, 0x00e0, 0x00f0,
	0x0000, 0x0000, 0x0100, 0x0110, 0x0120, 0x0130, 0x0140, 0x0150,
	/* char values 0x010_ */
	0x21ea, 0x21f2, 0x21fa, 0x2202, 0x220a, 0x2212, 0x221a, 0x2222,
	0x222a, 0x2232, 0x223a, 0x2242, 0x224a, 0x2252, 0x225a, 0x2262,
	/* char values 0x011_ */
	0x0000, 0x0000, 0x226a, 0x2272, 0x227a, 0x2282, 0x228a, 0x2292,
	0x229a, 0x22a2, 0x22aa, 0x22b2, 0x22ba, 0x22c2, 0x22ca, 0x22d2,
	/* char values 0x012_ */
	0x22da, 0x22e2, 0x22ea, 0x22f2, 0x22fa, 0x2302, 0x0000, 0x0000,
	0x230a, 0x2312, 0x231a, 0x2322, 0x232a, 0x2332, 0x233a, 0x2342,
	/* char values 0x013_ */
	0x234a, 0x0000, 0x0000, 0x0000, 0x2352, 0x235a, 0x2362, 0x236a,
	0x0000, 0x2372, 0x237a, 0x2382, 0x238a, 0x2392, 0x239a, 0x0000,
	/* char values 0x014_ */
	0x0000, 0x0000, 0x0000, 0x23a2, 0x23aa, 0x23b2, 0x23ba, 0x23c2,
	0x23ca, 0x0000, 0x0000, 0x0000, 0x23d2, 0x23da, 0x23e2, 0x23ea,
	/* char values 0x015_ */
	0x23f2, 0x23fa, 0x0000, 0x0000, 0x2402, 0x240a, 0x2412, 0x241a,
	0x2422, 0x242a, 0x2432, 0x243a, 0x2442, 0x244a, 0x2452, 0x245a,
	/* char values 0x016_ */
	0x2462, 0x246a, 0x2472, 0x247a, 0x2482, 0x248a, 0x0000, 0x0000,
	0x2492, 0x249a, 0x24a2, 0x24aa, 0x24b2, 0x24ba, 0x24c2, 0x24ca,
	/* char values 0x017_ */
	0x24d2, 0x24da, 0x24e2, 0x24ea, 0x24f2, 0x24fa, 0x2502, 0x250a,
	0x2512, 0x251a, 0x2522, 0x252a, 0x2532, 0x253a, 0x2542, 0x0000,
	/* char values 0x01a_ */
	0x254a, 0x2552, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x255a,
	/* char values 0x01b_ */
	0x2562, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x01c_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x256a, 0x2572, 0x257a,
	/* char values 0x01d_ */
	0x2582, 0x258a, 0x2592, 0x259a, 0x25a2, 0x25ab, 0x25b7, 0x25c3,
	0x25cf, 0x25db, 0x25e7, 0x25f3, 0x25ff, 0x0000, 0x260b, 0x2617,
	/* char values 0x01e_ */
	0x2623, 0x262f, 0x263a, 0x2642, 0x0000, 0x0000, 0x264a, 0x2652,
	0x265a, 0x2662, 0x266a, 0x2672, 0x267b, 0x2687, 0x2692, 0x269a,
	/* char values 0x01f_ */
	0x26a2, 0x0000, 0x0000, 0x0000, 0x26aa, 0x26b2, 0x0000, 0x0000,
	0x0000, 0x0000, 0x26bb, 0x26c7, 0x26d2, 0x26da, 0x26e2, 0x26ea,
	/* char table 0x02__ */
	0x0170, 0x0180, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x020_ */
	0x26f2, 0x26fa, 0x2702, 0x270a, 0x2712, 0x271a, 0x2722, 0x272a,
	0x2732, 0x273a, 0x2742, 0x274a, 0x2752, 0x275a, 0x2762, 0x276a,
	/* char values 0x021_ */
	0x2772, 0x277a, 0x2782, 0x278a, 0x2792, 0x279a, 0x27a2, 0x27aa,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0x03__ */
	0x0000, 0x01a0, 0x0000, 0x0000, 0x01b0, 0x0000, 0x0000, 0x01c0,
	0x01d0, 0x01e0, 0x01f0, 0x0200, 0x0210, 0x0220, 0x0000, 0x0000,
	/* char values 0x031_ */
	0x27b2, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x034_ */
	0x27b9, 0x27bd, 0x0000, 0x27c1, 0x27c6, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x037_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x27cd, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x27d1, 0x0000,
	/* char values 0x038_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x27d6, 0x27de, 0x27e5,
	0x27ea, 0x27f2, 0x27fa, 0x0000, 0x2802, 0x0000, 0x280a, 0x2812,
	/* char values 0x039_ */
	0x281b, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x03a_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x2826, 0x282e, 0x2836, 0x283e, 0x2846, 0x284e,
	/* char values 0x03b_ */
	0x2857, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x03c_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x2862, 0x286a, 0x2872, 0x287a, 0x2882, 0x0000,
	/* char values 0x03d_ */
	0x0000, 0x0000, 0x0000, 0x288a, 0x2892, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0x04__ */
	0x0240, 0x0250, 0x0000, 0x0260, 0x0000, 0x0270, 0x0000, 0x0280,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0290, 0x02a0, 0x02b0, 0x02c0,
	/* char values 0x040_ */
	0x0000, 0x289a, 0x0000, 0x28a2, 0x0000, 0x0000, 0x0000, 0x28aa,
	0x0000, 0x0000, 0x0000, 0x0000, 0x28b2, 0x0000, 0x28ba, 0x0000,
	/* char values 0x041_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x28c2, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x043_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x28ca, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x045_ */
	0x0000, 0x28d2, 0x0000, 0x28da, 0x0000, 0x0000, 0x0000, 0x28e2,
	0x0000, 0x0000, 0x0000, 0x0000, 0x28ea, 0x0000, 0x28f2, 0x0000,
	/* char values 0x047_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x28fa, 0x2902,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x04c_ */
	0x0000, 0x290a, 0x2912, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x04d_ */
	0x291a, 0x2922, 0x292a, 0x2932, 0x2939, 0x293d, 0x2942, 0x294a,
	0x2951, 0x2955, 0x295a, 0x2962, 0x296a, 0x2972, 0x297a, 0x2982,
	/* char values 0x04e_ */
	0x2989, 0x298d, 0x2992, 0x299a, 0x29a2, 0x29aa, 0x29b2, 0x29ba,
	0x29c1, 0x29c5, 0x29ca, 0x29d2, 0x0000, 0x0000, 0x29da, 0x29e2,
	/* char values 0x04f_ */
	0x29ea, 0x29f2, 0x29fa, 0x2a02, 0x2a0a, 0x2a12, 0x0000, 0x0000,
	0x2a1a, 0x2a22, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0x09__ */
	0x0000, 0x0000, 0x02e0, 0x02f0, 0x0000, 0x0300, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0310, 0x0320, 0x0330, 0x0000, 0x0000,
	/* char values 0x092_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x2a2a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x093_ */
	0x0000, 0x2a32, 0x0000, 0x0000, 0x2a3a, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x095_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x2a42, 0x2a4a, 0x2a52, 0x2a5a, 0x2a62, 0x2a6a, 0x2a72, 0x2a7a,
	/* char values 0x09b_ */
	0x2a82, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x09c_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x2a8a, 0x2a92, 0x0000, 0x0000, 0x0000,
	/* char values 0x09d_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x2a9a, 0x2aa2, 0x0000, 0x2aaa,
	/* char table 0x0a__ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0350, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0a5_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x2ab2, 0x2aba, 0x2ac2, 0x2aca, 0x0000, 0x2ad2, 0x0000,
	/* char table 0x0b__ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0370, 0x0380, 0x0000, 0x0000,
	0x0000, 0x0390, 0x0000, 0x0000, 0x03a0, 0x0000, 0x0000, 0x0000,
	/* char values 0x0b4_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x2ada, 0x0000, 0x0000, 0x2ae2, 0x2aea, 0x0000, 0x0000, 0x0000,
	/* char values 0x0b5_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x2af2, 0x2afa, 0x0000, 0x2b02,
	/* char values 0x0b9_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x2b0a, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0bc_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x2b12, 0x2b1a, 0x2b22, 0x0000, 0x0000, 0x0000,
	/* char table 0x0c__ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x03c0, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x03d0, 0x0000, 0x0000, 0x0000,
	/* char values 0x0c4_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x2b2a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0cc_ */
	0x2b32, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x2b3a,
	0x2b42, 0x0000, 0x2b4a, 0x2b53, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0x0d__ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x03f0, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0d4_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x2b5e, 0x2b66, 0x2b6e, 0x0000, 0x0000, 0x0000,
	/* char table 0x0e__ */
	0x0000, 0x0000, 0x0000, 0x0410, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0420, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0e3_ */
	0x0000, 0x0000, 0x0000, 0x2b76, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0eb_ */
	0x0000, 0x0000, 0x0000, 0x2b7e, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0x0f__ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0440, 0x0450, 0x0460, 0x0470,
	0x0480, 0x0490, 0x04a0, 0x04b0, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0f4_ */
	0x0000, 0x0000, 0x0000, 0x2b86, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x2b8e, 0x0000, 0x0000,
	/* char values 0x0f5_ */
	0x0000, 0x0000, 0x2b96, 0x0000, 0x0000, 0x0000, 0x0000, 0x2b9e,
	0x0000, 0x0000, 0x0000, 0x0000, 0x2ba6, 0x0000, 0x0000, 0x0000,
	/* char values 0x0f6_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x2bae, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0f7_ */
	0x0000, 0x0000, 0x0000, 0x2bb6, 0x0000, 0x2bbe, 0x2bc6, 0x2bcf,
	0x2bda, 0x2be3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0f8_ */
	0x0000, 0x2bee, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x0f9_ */
	0x0000, 0x0000, 0x0000, 0x2bf6, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x2bfe, 0x0000, 0x0000,
	/* char values 0x0fa_ */
	0x0000, 0x0000, 0x2c06, 0x0000, 0x0000, 0x0000, 0x0000, 0x2c0e,
	0x0000, 0x0000, 0x0000, 0x0000, 0x2c16, 0x0000, 0x0000, 0x0000,
	/* char values 0x0fb_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x2c1e, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0x1___ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x04d0, 0x05e0,
	/* char table 0x1e__ */
	0x04e0, 0x04f0, 0x0500, 0x0510, 0x0520, 0x0530, 0x0540, 0x0550,
	0x0560, 0x0570, 0x0580, 0x0590, 0x05a0, 0x05b0, 0x05c0, 0x05d0,
	/* char values 0x1e0_ */
	0x2c26, 0x2c2e, 0x2c36, 0x2c3e, 0x2c46, 0x2c4e, 0x2c56, 0x2c5e,
	0x2c67, 0x2c73, 0x2c7e, 0x2c86, 0x2c8e, 0x2c96, 0x2c9e, 0x2ca6,
	/* char values 0x1e1_ */
	0x2cae, 0x2cb6, 0x2cbe, 0x2cc6, 0x2ccf, 0x2cdb, 0x2ce7, 0x2cf3,
	0x2cfe, 0x2d06, 0x2d0e, 0x2d16, 0x2d1f, 0x2d2b, 0x2d36, 0x2d3e,
	/* char values 0x1e2_ */
	0x2d46, 0x2d4e, 0x2d56, 0x2d5e, 0x2d66, 0x2d6e, 0x2d76, 0x2d7e,
	0x2d86, 0x2d8e, 0x2d96, 0x2d9e, 0x2da6, 0x2dae, 0x2db7, 0x2dc3,
	/* char values 0x1e3_ */
	0x2dce, 0x2dd6, 0x2dde, 0x2de6, 0x2dee, 0x2df6, 0x2dfe, 0x2e06,
	0x2e0f, 0x2e1b, 0x2e26, 0x2e2e, 0x2e36, 0x2e3e, 0x2e46, 0x2e4e,
	/* char values 0x1e4_ */
	0x2e56, 0x2e5e, 0x2e66, 0x2e6e, 0x2e76, 0x2e7e, 0x2e86, 0x2e8e,
	0x2e96, 0x2e9e, 0x2ea6, 0x2eae, 0x2eb7, 0x2ec3, 0x2ecf, 0x2edb,
	/* char values 0x1e5_ */
	0x2ee7, 0x2ef3, 0x2eff, 0x2f0b, 0x2f16, 0x2f1e, 0x2f26, 0x2f2e,
	0x2f36, 0x2f3e, 0x2f46, 0x2f4e, 0x2f57, 0x2f63, 0x2f6e, 0x2f76,
	/* char values 0x1e6_ */
	0x2f7e, 0x2f86, 0x2f8e, 0x2f96, 0x2f9f, 0x2fab, 0x2fb7, 0x2fc3,
	0x2fcf, 0x2fdb, 0x2fe6, 0x2fee, 0x2ff6, 0x2ffe, 0x3006, 0x300e,
	/* char values 0x1e7_ */
	0x3016, 0x301e, 0x3026, 0x302e, 0x3036, 0x303e, 0x3046, 0x304e,
	0x3057, 0x3063, 0x306f, 0x307b, 0x3086, 0x308e, 0x3096, 0x309e,
	/* char values 0x1e8_ */
	0x30a6, 0x30ae, 0x30b6, 0x30be, 0x30c6, 0x30ce, 0x30d6, 0x30de,
	0x30e6, 0x30ee, 0x30f6, 0x30fe, 0x3106, 0x310e, 0x3116, 0x311e,
	/* char values 0x1e9_ */
	0x3126, 0x312e, 0x3136, 0x313e, 0x3146, 0x314e, 0x3156, 0x315e,
	0x3166, 0x316e, 0x0000, 0x3176, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x1ea_ */
	0x317e, 0x3186, 0x318e, 0x3196, 0x319f, 0x31ab, 0x31b7, 0x31c3,
	0x31cf, 0x31db, 0x31e7, 0x31f3, 0x31ff, 0x320b, 0x3217, 0x3223,
	/* char values 0x1eb_ */
	0x322f, 0x323b, 0x3247, 0x3253, 0x325f, 0x326b, 0x3277, 0x3283,
	0x328e, 0x3296, 0x329e, 0x32a6, 0x32ae, 0x32b6, 0x32bf, 0x32cb,
	/* char values 0x1ec_ */
	0x32d7, 0x32e3, 0x32ef, 0x32fb, 0x3307, 0x3313, 0x331f, 0x332b,
	0x3336, 0x333e, 0x3346, 0x334e, 0x3356, 0x335e, 0x3366, 0x336e,
	/* char values 0x1ed_ */
	0x3377, 0x3383, 0x338f, 0x339b, 0x33a7, 0x33b3, 0x33bf, 0x33cb,
	0x33d7, 0x33e3, 0x33ef, 0x33fb, 0x3407, 0x3413, 0x341f, 0x342b,
	/* char values 0x1ee_ */
	0x3437, 0x3443, 0x344f, 0x345b, 0x3466, 0x346e, 0x3476, 0x347e,
	0x3487, 0x3493, 0x349f, 0x34ab, 0x34b7, 0x34c3, 0x34cf, 0x34db,
	/* char values 0x1ef_ */
	0x34e7, 0x34f3, 0x34fe, 0x3506, 0x350e, 0x3516, 0x351e, 0x3526,
	0x352e, 0x3536, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0x1f__ */
	0x05f0, 0x0600, 0x0610, 0x0620, 0x0630, 0x0640, 0x0650, 0x0660,
	0x0670, 0x0680, 0x0690, 0x06a0, 0x06b0, 0x06c0, 0x06d0, 0x06e0,
	/* char values 0x1f0_ */
	0x353e, 0x3546, 0x354f, 0x355b, 0x3567, 0x3573, 0x357f, 0x358b,
	0x3596, 0x359e, 0x35a7, 0x35b3, 0x35bf, 0x35cb, 0x35d7, 0x35e3,
	/* char values 0x1f1_ */
	0x35ee, 0x35f6, 0x35ff, 0x360b, 0x3617, 0x3623, 0x0000, 0x0000,
	0x362e, 0x3636, 0x363f, 0x364b, 0x3657, 0x3663, 0x0000, 0x0000,
	/* char values 0x1f2_ */
	0x366e, 0x3676, 0x367f, 0x368b, 0x3697, 0x36a3, 0x36af, 0x36bb,
	0x36c6, 0x36ce, 0x36d7, 0x36e3, 0x36ef, 0x36fb, 0x3707, 0x3713,
	/* char values 0x1f3_ */
	0x371e, 0x3726, 0x372f, 0x373b, 0x3747, 0x3753, 0x375f, 0x376b,
	0x3776, 0x377e, 0x3787, 0x3793, 0x379f, 0x37ab, 0x37b7, 0x37c3,
	/* char values 0x1f4_ */
	0x37ce, 0x37d6, 0x37df, 0x37eb, 0x37f7, 0x3803, 0x0000, 0x0000,
	0x380e, 0x3816, 0x381f, 0x382b, 0x3837, 0x3843, 0x0000, 0x0000,
	/* char values 0x1f5_ */
	0x384e, 0x3856, 0x385f, 0x386b, 0x3877, 0x3883, 0x388f, 0x389b,
	0x0000, 0x38a6, 0x0000, 0x38af, 0x0000, 0x38bb, 0x0000, 0x38c7,
	/* char values 0x1f6_ */
	0x38d2, 0x38da, 0x38e3, 0x38ef, 0x38fb, 0x3907, 0x3913, 0x391f,
	0x392a, 0x3932, 0x393b, 0x3947, 0x3953, 0x395f, 0x396b, 0x3977,
	/* char values 0x1f7_ */
	0x3982, 0x398a, 0x3992, 0x399a, 0x39a2, 0x39aa, 0x39b2, 0x39ba,
	0x39c2, 0x39ca, 0x39d2, 0x39da, 0x39e2, 0x39ea, 0x0000, 0x0000,
	/* char values 0x1f8_ */
	0x39f3, 0x39ff, 0x3a0c, 0x3a1c, 0x3a2c, 0x3a3c, 0x3a4c, 0x3a5c,
	0x3a6b, 0x3a77, 0x3a84, 0x3a94, 0x3aa4, 0x3ab4, 0x3ac4, 0x3ad4,
	/* char values 0x1f9_ */
	0x3ae3, 0x3aef, 0x3afc, 0x3b0c, 0x3b1c, 0x3b2c, 0x3b3c, 0x3b4c,
	0x3b5b, 0x3b67, 0x3b74, 0x3b84, 0x3b94, 0x3ba4, 0x3bb4, 0x3bc4,
	/* char values 0x1fa_ */
	0x3bd3, 0x3bdf, 0x3bec, 0x3bfc, 0x3c0c, 0x3c1c, 0x3c2c, 0x3c3c,
	0x3c4b, 0x3c57, 0x3c64, 0x3c74, 0x3c84, 0x3c94, 0x3ca4, 0x3cb4,
	/* char values 0x1fb_ */
	0x3cc2, 0x3cca, 0x3cd3, 0x3cde, 0x3ce7, 0x0000, 0x3cf2, 0x3cfb,
	0x3d06, 0x3d0e, 0x3d16, 0x3d1e, 0x3d26, 0x0000, 0x3d2d, 0x0000,
	/* char values 0x1fc_ */
	0x0000, 0x3d32, 0x3d3b, 0x3d46, 0x3d4f, 0x0000, 0x3d5a, 0x3d63,
	0x3d6e, 0x3d76, 0x3d7e, 0x3d86, 0x3d8e, 0x3d96, 0x3d9e, 0x3da6,
	/* char values 0x1fd_ */
	0x3dae, 0x3db6, 0x3dbf, 0x3dcb, 0x0000, 0x0000, 0x3dd6, 0x3ddf,
	0x3dea, 0x3df2, 0x3dfa, 0x3e02, 0x0000, 0x3e0a, 0x3e12, 0x3e1a,
	/* char values 0x1fe_ */
	0x3e22, 0x3e2a, 0x3e33, 0x3e3f, 0x3e4a, 0x3e52, 0x3e5a, 0x3e63,
	0x3e6e, 0x3e76, 0x3e7e, 0x3e86, 0x3e8e, 0x3e96, 0x3e9e, 0x3ea5,
	/* char values 0x1ff_ */
	0x0000, 0x0000, 0x3eab, 0x3eb6, 0x3ebf, 0x0000, 0x3eca, 0x3ed3,
	0x3ede, 0x3ee6, 0x3eee, 0x3ef6, 0x3efe, 0x3f05, 0x0000, 0x0000,
	/* char table 0x3___ */
	0x0700, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0x30__ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0710, 0x0720, 0x0730, 0x0740,
	0x0000, 0x0750, 0x0760, 0x0770, 0x0780, 0x0790, 0x0000, 0x07a0,
	/* char values 0x304_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x3f0a, 0x0000, 0x3f12, 0x0000,
	/* char values 0x305_ */
	0x3f1a, 0x0000, 0x3f22, 0x0000, 0x3f2a, 0x0000, 0x3f32, 0x0000,
	0x3f3a, 0x0000, 0x3f42, 0x0000, 0x3f4a, 0x0000, 0x3f52, 0x0000,
	/* char values 0x306_ */
	0x3f5a, 0x0000, 0x3f62, 0x0000, 0x0000, 0x3f6a, 0x0000, 0x3f72,
	0x0000, 0x3f7a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x307_ */
	0x3f82, 0x3f8a, 0x0000, 0x3f92, 0x3f9a, 0x0000, 0x3fa2, 0x3faa,
	0x0000, 0x3fb2, 0x3fba, 0x0000, 0x3fc2, 0x3fca, 0x0000, 0x0000,
	/* char values 0x309_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x3fd2, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x3fda, 0x0000,
	/* char values 0x30a_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x3fe2, 0x0000, 0x3fea, 0x0000,
	/* char values 0x30b_ */
	0x3ff2, 0x0000, 0x3ffa, 0x0000, 0x4002, 0x0000, 0x400a, 0x0000,
	0x4012, 0x0000, 0x401a, 0x0000, 0x4022, 0x0000, 0x402a, 0x0000,
	/* char values 0x30c_ */
	0x4032, 0x0000, 0x403a, 0x0000, 0x0000, 0x4042, 0x0000, 0x404a,
	0x0000, 0x4052, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0x30d_ */
	0x405a, 0x4062, 0x0000, 0x406a, 0x4072, 0x0000, 0x407a, 0x4082,
	0x0000, 0x408a, 0x4092, 0x0000, 0x409a, 0x40a2, 0x0000, 0x0000,
	/* char values 0x30f_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x40aa, 0x0000, 0x0000, 0x40b2,
	0x40ba, 0x40c2, 0x40ca, 0x0000, 0x0000, 0x0000, 0x40d2, 0x0000,
	/* char table 0xf___ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x07c0, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char table 0xfb__ */
	0x0000, 0x07d0, 0x07e0, 0x07f0, 0x0800, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	/* char values 0xfb1_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x40da,
	/* char values 0xfb2_ */
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
	0x0000, 0x0000, 0x40e2, 0x40ea, 0x40f3, 0x40ff, 0x410a, 0x4112,
	/* char values 0xfb3_ */
	0x411a, 0x4122, 0x412a, 0x4132, 0x413a, 0x4142, 0x414a, 0x0000,
	0x4152, 0x415a, 0x4162, 0x416a, 0x4172, 0x0000, 0x417a, 0x0000,
	/* char values 0xfb4_ */
	0x4182, 0x418a, 0x0000, 0x4192, 0x419a, 0x0000, 0x41a2, 0x41aa,
	0x41b2, 0x41ba, 0x41c2, 0x41ca, 0x41d2, 0x41da, 0x41e2, 0x0000,
	/* decomposed characters */
	0x0041, 0x0300, 0x0041, 0x0301, 0x0041, 0x0302, 0x0041, 0x0303,
	0x0041, 0x0308, 0x0041, 0x030a, 0x0043, 0x0327, 0x0045, 0x0300,
	0x0045, 0x0301, 0x0045, 0x0302, 0x0045, 0x0308, 0x0049, 0x0300,
	0x0049, 0x0301, 0x0049, 0x0302, 0x0049, 0x0308, 0x004e, 0x0303,
	0x004f, 0x0300, 0x004f, 0x0301, 0x004f, 0x0302, 0x004f, 0x0303,
	0x004f, 0x0308, 0x0055, 0x0300, 0x0055, 0x0301, 0x0055, 0x0302,
	0x0055, 0x0308, 0x0059, 0x0301, 0x0061, 0x0300, 0x0061, 0x0301,
	0x0061, 0x0302, 0x0061, 0x0303, 0x0061, 0x0308, 0x0061, 0x030a,
	0x0063, 0x0327, 0x0065, 0x0300, 0x0065, 0x0301, 0x0065, 0x0302,
	0x0065, 0x0308, 0x0069, 0x0300, 0x0069, 0x0301, 0x0069, 0x0302,
	0x0069, 0x0308, 0x006e, 0x0303, 0x006f, 0x0300, 0x006f, 0x0301,
	0x006f, 0x0302, 0x006f, 0x0303, 0x006f, 0x0308, 0x0075, 0x0300,
	0x0075, 0x0301, 0x0075, 0x0302, 0x0075, 0x0308, 0x0079, 0x0301,
	0x0079, 0x0308, 0x0041, 0x0304, 0x0061, 0x0304, 0x0041, 0x0306,
	0x0061, 0x0306, 0x0041, 0x0328, 0x0061, 0x0328, 0x0043, 0x0301,
	0x0063, 0x0301, 0x0043, 0x0302, 0x0063, 0x0302, 0x0043, 0x0307,
	0x0063, 0x0307, 0x0043, 0x030c, 0x0063, 0x030c, 0x0044, 0x030c,
	0x0064, 0x030c, 0x0045, 0x0304, 0x0065, 0x0304, 0x0045, 0x0306,
	0x0065, 0x0306, 0x0045, 0x0307, 0x0065, 0x0307, 0x0045, 0x0328,
	0x0065, 0x0328, 0x0045, 0x030c, 0x0065, 0x030c, 0x0047, 0x0302,
	0x0067, 0x0302, 0x0047, 0x0306, 0x0067, 0x0306, 0x0047, 0x0307,
	0x0067, 0x0307, 0x0047, 0x0327, 0x0067, 0x0327, 0x0048, 0x0302,
	0x0068, 0x0302, 0x0049, 0x0303, 0x0069, 0x0303, 0x0049, 0x0304,
	0x0069, 0x0304, 0x0049, 0x0306, 0x0069, 0x0306, 0x0049, 0x0328,
	0x0069, 0x0328, 0x0049, 0x0307, 0x004a, 0x0302, 0x006a, 0x0302,
	0x004b, 0x0327, 0x006b, 0x0327, 0x004c, 0x0301, 0x006c, 0x0301,
	0x004c, 0x0327, 0x006c, 0x0327, 0x004c, 0x030c, 0x006c, 0x030c,
	0x004e, 0x0301, 0x006e, 0x0301, 0x004e, 0x0327, 0x006e, 0x0327,
	0x004e, 0x030c, 0x006e, 0x030c, 0x004f, 0x0304, 0x006f, 0x0304,
	0x004f, 0x0306, 0x006f, 0x0306, 0x004f, 0x030b, 0x006f, 0x030b,
	0x0052, 0x0301, 0x0072, 0x0301, 0x0052, 0x0327, 0x0072, 0x0327,
	0x0052, 0x030c, 0x0072, 0x030c, 0x0053, 0x0301, 0x0073, 0x0301,
	0x0053, 0x0302, 0x0073, 0x0302, 0x0053, 0x0327, 0x0073, 0x0327,
	0x0053, 0x030c, 0x0073, 0x030c, 0x0054, 0x0327, 0x0074, 0x0327,
	0x0054, 0x030c, 0x0074, 0x030c, 0x0055, 0x0303, 0x0075, 0x0303,
	0x0055, 0x0304, 0x0075, 0x0304, 0x0055, 0x0306, 0x0075, 0x0306,
	0x0055, 0x030a, 0x0075, 0x030a, 0x0055, 0x030b, 0x0075, 0x030b,
	0x0055, 0x0328, 0x0075, 0x0328, 0x0057, 0x0302, 0x0077, 0x0302,
	0x0059, 0x0302, 0x0079, 0x0302, 0x0059, 0x0308, 0x005a, 0x0301,
	0x007a, 0x0301, 0x005a, 0x0307, 0x007a, 0x0307, 0x005a, 0x030c,
	0x007a, 0x030c, 0x004f, 0x031b, 0x006f, 0x031b, 0x0055, 0x031b,
	0x0075, 0x031b, 0x0041, 0x030c, 0x0061, 0x030c, 0x0049, 0x030c,
	0x0069, 0x030c, 0x004f, 0x030c, 0x006f, 0x030c, 0x0055, 0x030c,
	0x0075, 0x030c, 0x0055, 0x0308, 0x0304, 0x0075, 0x0308, 0x0304,
	0x0055, 0x0308, 0x0301, 0x0075, 0x0308, 0x0301, 0x0055, 0x0308,
	0x030c, 0x0075, 0x0308, 0x030c, 0x0055, 0x0308, 0x0300, 0x0075,
	0x0308, 0x0300, 0x0041, 0x0308, 0x0304, 0x0061, 0x0308, 0x0304,
	0x0041, 0x0307, 0x0304, 0x0061, 0x0307, 0x0304, 0x00c6, 0x0304,
	0x00e6, 0x0304, 0x0047, 0x030c, 0x0067, 0x030c, 0x004b, 0x030c,
	0x006b, 0x030c, 0x004f, 0x0328, 0x006f, 0x0328, 0x004f, 0x0328,
	0x0304, 0x006f, 0x0328, 0x0304, 0x01b7, 0x030c, 0x0292, 0x030c,
	0x006a, 0x030c, 0x0047, 0x0301, 0x0067, 0x0301, 0x0041, 0x030a,
	0x0301, 0x0061, 0x030a, 0x0301, 0x00c6, 0x0301, 0x00e6, 0x0301,
	0x00d8, 0x0301, 0x00f8, 0x0301, 0x0041, 0x030f, 0x0061, 0x030f,
	0x0041, 0x0311, 0x0061, 0x0311, 0x0045, 0x030f, 0x0065, 0x030f,
	0x0045, 0x0311, 0x0065, 0x0311, 0x0049, 0x030f, 0x0069, 0x030f,
	0x0049, 0x0311, 0x0069, 0x0311, 0x004f, 0x030f, 0x006f, 0x030f,
	0x004f, 0x0311, 0x006f, 0x0311, 0x0052, 0x030f, 0x0072, 0x030f,
	0x0052, 0x0311, 0x0072, 0x0311, 0x0055, 0x030f, 0x0075, 0x030f,
	0x0055, 0x0311, 0x0075, 0x0311, 0x0306, 0x0307, 0x0300, 0x0301,
	0x0313, 0x0308, 0x030d, 0x02b9, 0x003b, 0x00a8, 0x030d, 0x0391,
	0x030d, 0x00b7, 0x0395, 0x030d, 0x0397, 0x030d, 0x0399, 0x030d,
	0x039f, 0x030d, 0x03a5, 0x030d, 0x03a9, 0x030d, 0x03b9, 0x0308,
	0x030d, 0x0399, 0x0308, 0x03a5, 0x0308, 0x03b1, 0x030d, 0x03b5,
	0x030d, 0x03b7, 0x030d, 0x03b9, 0x030d, 0x03c5, 0x0308, 0x030d,
	0x03b9, 0x0308, 0x03c5, 0x0308, 0x03bf, 0x030d, 0x03c5, 0x030d,
	0x03c9, 0x030d, 0x03d2, 0x030d, 0x03d2, 0x0308, 0x0415, 0x0308,
	0x0413, 0x0301, 0x0406, 0x0308, 0x041a, 0x0301, 0x0423, 0x0306,
	0x0418, 0x0306, 0x0438, 0x0306, 0x0435, 0x0308, 0x0433, 0x0301,
	0x0456, 0x0308, 0x043a, 0x0301, 0x0443, 0x0306, 0x0474, 0x030f,
	0x0475, 0x030f, 0x0416, 0x0306, 0x0436, 0x0306, 0x0410, 0x0306,
	0x0430, 0x0306, 0x0410, 0x0308, 0x0430, 0x0308, 0x00c6, 0x00e6,
	0x0415, 0x0306, 0x0435, 0x0306, 0x018f, 0x0259, 0x018f, 0x0308,
	0x0259, 0x0308, 0x0416, 0x0308, 0x0436, 0x0308, 0x0417, 0x0308,
	0x0437, 0x0308, 0x01b7, 0x0292, 0x0418, 0x0304, 0x0438, 0x0304,
	0x0418, 0x0308, 0x0438, 0x0308, 0x041e, 0x0308, 0x043e, 0x0308,
	0x019f, 0x0275, 0x019f, 0x0308, 0x0275, 0x0308, 0x0423, 0x0304,
	0x0443, 0x0304, 0x0423, 0x0308, 0x0443, 0x0308, 0x0423, 0x030b,
	0x0443, 0x030b, 0x0427, 0x0308, 0x0447, 0x0308, 0x042b, 0x0308,
	0x044b, 0x0308, 0x0928, 0x093c, 0x0930, 0x093c, 0x0933, 0x093c,
	0x0915, 0x093c, 0x0916, 0x093c, 0x0917, 0x093c, 0x091c, 0x093c,
	0x0921, 0x093c, 0x0922, 0x093c, 0x092b, 0x093c, 0x092f, 0x093c,
	0x09ac, 0x09bc, 0x09c7, 0x09be, 0x09c7, 0x09d7, 0x09a1, 0x09bc,
	0x09a2, 0x09bc, 0x09af, 0x09bc, 0x0a16, 0x0a3c, 0x0a17, 0x0a3c,
	0x0a1c, 0x0a3c, 0x0a21, 0x0a3c, 0x0a2b, 0x0a3c, 0x0b47, 0x0b56,
	0x0b47, 0x0b3e, 0x0b47, 0x0b57, 0x0b21, 0x0b3c, 0x0b22, 0x0b3c,
	0x0b2f, 0x0b3c, 0x0b92, 0x0bd7, 0x0bc6, 0x0bbe, 0x0bc7, 0x0bbe,
	0x0bc6, 0x0bd7, 0x0c46, 0x0c56, 0x0cbf, 0x0cd5, 0x0cc6, 0x0cd5,
	0x0cc6, 0x0cd6, 0x0cc6, 0x0cc2, 0x0cc6, 0x0cc2, 0x0cd5, 0x0d46,
	0x0d3e, 0x0d47, 0x0d3e, 0x0d46, 0x0d57, 0x0e4d, 0x0e32, 0x0ecd,
	0x0eb2, 0x0f42, 0x0fb7, 0x0f4c, 0x0fb7, 0x0f51, 0x0fb7, 0x0f56,
	0x0fb7, 0x0f5b, 0x0fb7, 0x0f40, 0x0fb5, 0x0f72, 0x0f71, 0x0f74,
	0x0f71, 0x0fb2, 0x0f80, 0x0fb2, 0x0f80, 0x0f71, 0x0fb3, 0x0f80,
	0x0fb3, 0x0f80, 0x0f71, 0x0f80, 0x0f71, 0x0f92, 0x0fb7, 0x0f9c,
	0x0fb7, 0x0fa1, 0x0fb7, 0x0fa6, 0x0fb7, 0x0fab, 0x0fb7, 0x0f90,
	0x0fb5, 0x0041, 0x0325, 0x0061, 0x0325, 0x0042, 0x0307, 0x0062,
	0x0307, 0x0042, 0x0323, 0x0062, 0x0323, 0x0042, 0x0331, 0x0062,
	0x0331, 0x0043, 0x0327, 0x0301, 0x0063, 0x0327, 0x0301, 0x0044,
	0x0307, 0x0064, 0x0307, 0x0044, 0x0323, 0x0064, 0x0323, 0x0044,
	0x0331, 0x0064, 0x0331, 0x0044, 0x0327, 0x0064, 0x0327, 0x0044,
	0x032d, 0x0064, 0x032d, 0x0045, 0x0304, 0x0300, 0x0065, 0x0304,
	0x0300, 0x0045, 0x0304, 0x0301, 0x0065, 0x0304, 0x0301, 0x0045,
	0x032d, 0x0065, 0x032d, 0x0045, 0x0330, 0x0065, 0x0330, 0x0045,
	0x0327, 0x0306, 0x0065, 0x0327, 0x0306, 0x0046, 0x0307, 0x0066,
	0x0307, 0x0047, 0x0304, 0x0067, 0x0304, 0x0048, 0x0307, 0x0068,
	0x0307, 0x0048, 0x0323, 0x0068, 0x0323, 0x0048, 0x0308, 0x0068,
	0x0308, 0x0048, 0x0327, 0x0068, 0x0327, 0x0048, 0x032e, 0x0068,
	0x032e, 0x0049, 0x0330, 0x0069, 0x0330, 0x0049, 0x0308, 0x0301,
	0x0069, 0x0308, 0x0301, 0x004b, 0x0301, 0x006b, 0x0301, 0x004b,
	0x0323, 0x006b, 0x0323, 0x004b, 0x0331, 0x006b, 0x0331, 0x004c,
	0x0323, 0x006c, 0x0323, 0x004c, 0x0323, 0x0304, 0x006c, 0x0323,
	0x0304, 0x004c, 0x0331, 0x006c, 0x0331, 0x004c, 0x032d, 0x006c,
	0x032d, 0x004d, 0x0301, 0x006d, 0x0301, 0x004d, 0x0307, 0x006d,
	0x0307, 0x004d, 0x0323, 0x006d, 0x0323, 0x004e, 0x0307, 0x006e,
	0x0307, 0x004e, 0x0323, 0x006e, 0x0323, 0x004e, 0x0331, 0x006e,
	0x0331, 0x004e, 0x032d, 0x006e, 0x032d, 0x004f, 0x0303, 0x0301,
	0x006f, 0x0303, 0x0301, 0x004f, 0x0303, 0x0308, 0x006f, 0x0303,
	0x0308, 0x004f, 0x0304, 0x0300, 0x006f, 0x0304, 0x0300, 0x004f,
	0x0304, 0x0301, 0x006f, 0x0304, 0x0301, 0x0050, 0x0301, 0x0070,
	0x0301, 0x0050, 0x0307, 0x0070, 0x0307, 0x0052, 0x0307, 0x0072,
	0x0307, 0x0052, 0x0323, 0x0072, 0x0323, 0x0052, 0x0323, 0x0304,
	0x0072, 0x0323, 0x0304, 0x0052, 0x0331, 0x0072, 0x0331, 0x0053,
	0x0307, 0x0073, 0x0307, 0x0053, 0x0323, 0x0073, 0x0323, 0x0053,
	0x0301, 0x0307, 0x0073, 0x0301, 0x0307, 0x0053, 0x030c, 0x0307,
	0x0073, 0x030c, 0x0307, 0x0053, 0x0323, 0x0307, 0x0073, 0x0323,
	0x0307, 0x0054, 0x0307, 0x0074, 0x0307, 0x0054, 0x0323, 0x0074,
	0x0323, 0x0054, 0x0331, 0x0074, 0x0331, 0x0054, 0x032d, 0x0074,
	0x032d, 0x0055, 0x0324, 0x0075, 0x0324, 0x0055, 0x0330, 0x0075,
	0x0330, 0x0055, 0x032d, 0x0075, 0x032d, 0x0055, 0x0303, 0x0301,
	0x0075, 0x0303, 0x0301, 0x0055, 0x0304, 0x0308, 0x0075, 0x0304,
	0x0308, 0x0056, 0x0303, 0x0076, 0x0303, 0x0056, 0x0323, 0x0076,
	0x0323, 0x0057, 0x0300, 0x0077, 0x0300, 0x0057, 0x0301, 0x0077,
	0x0301, 0x0057, 0x0308, 0x0077, 0x0308, 0x0057, 0x0307, 0x0077,
	0x0307, 0x0057, 0x0323, 0x0077, 0x0323, 0x0058, 0x0307, 0x0078,
	0x0307, 0x0058, 0x0308, 0x0078, 0x0308, 0x0059, 0x0307, 0x0079,
	0x0307, 0x005a, 0x0302, 0x007a, 0x0302, 0x005a, 0x0323, 0x007a,
	0x0323, 0x005a, 0x0331, 0x007a, 0x0331, 0x0068, 0x0331, 0x0074,
	0x0308, 0x0077, 0x030a, 0x0079, 0x030a, 0x017f, 0x0307, 0x0041,
	0x0323, 0x0061, 0x0323, 0x0041, 0x0309, 0x0061, 0x0309, 0x0041,
	0x0302, 0x0301, 0x0061, 0x0302, 0x0301, 0x0041, 0x0302, 0x0300,
	0x0061, 0x0302, 0x0300, 0x0041, 0x0302, 0x0309, 0x0061, 0x0302,
	0x0309, 0x0041, 0x0302, 0x0303, 0x0061, 0x0302, 0x0303, 0x0041,
	0x0323, 0x0302, 0x0061, 0x0323, 0x0302, 0x0041, 0x0306, 0x0301,
	0x0061, 0x0306, 0x0301, 0x0041, 0x0306, 0x0300, 0x0061, 0x0306,
	0x0300, 0x0041, 0x0306, 0x0309, 0x0061, 0x0306, 0x0309, 0x0041,
	0x0306, 0x0303, 0x0061, 0x0306, 0x0303, 0x0041, 0x0323, 0x0306,
	0x0061, 0x0323, 0x0306, 0x0045, 0x0323, 0x0065, 0x0323, 0x0045,
	0x0309, 0x0065, 0x0309, 0x0045, 0x0303, 0x0065, 0x0303, 0x0045,
	0x0302, 0x0301, 0x0065, 0x0302, 0x0301, 0x0045, 0x0302, 0x0300,
	0x0065, 0x0302, 0x0300, 0x0045, 0x0302, 0x0309, 0x0065, 0x0302,
	0x0309, 0x0045, 0x0302, 0x0303, 0x0065, 0x0302, 0x0303, 0x0045,
	0x0323, 0x0302, 0x0065, 0x0323, 0x0302, 0x0049, 0x0309, 0x0069,
	0x0309, 0x0049, 0x0323, 0x0069, 0x0323, 0x004f, 0x0323, 0x006f,
	0x0323, 0x004f, 0x0309, 0x006f, 0x0309, 0x004f, 0x0302, 0x0301,
	0x006f, 0x0302, 0x0301, 0x004f, 0x0302, 0x0300, 0x006f, 0x0302,
	0x0300, 0x004f, 0x0302, 0x0309, 0x006f, 0x0302, 0x0309, 0x004f,
	0x0302, 0x0303, 0x006f, 0x0302, 0x0303, 0x004f, 0x0323, 0x0302,
	0x006f, 0x0323, 0x0302, 0x004f, 0x031b, 0x0301, 0x006f, 0x031b,
	0x0301, 0x004f, 0x031b, 0x0300, 0x006f, 0x031b, 0x0300, 0x004f,
	0x031b, 0x0309, 0x006f, 0x031b, 0x0309, 0x004f, 0x031b, 0x0303,
	0x006f, 0x031b, 0x0303, 0x004f, 0x031b, 0x0323, 0x006f, 0x031b,
	0x0323, 0x0055, 0x0323, 0x0075, 0x0323, 0x0055, 0x0309, 0x0075,
	0x0309, 0x0055, 0x031b, 0x0301, 0x0075, 0x031b, 0x0301, 0x0055,
	0x031b, 0x0300, 0x0075, 0x031b, 0x0300, 0x0055, 0x031b, 0x0309,
	0x0075, 0x031b, 0x0309, 0x0055, 0x031b, 0x0303, 0x0075, 0x031b,
	0x0303, 0x0055, 0x031b, 0x0323, 0x0075, 0x031b, 0x0323, 0x0059,
	0x0300, 0x0079, 0x0300, 0x0059, 0x0323, 0x0079, 0x0323, 0x0059,
	0x0309, 0x0079, 0x0309, 0x0059, 0x0303, 0x0079, 0x0303, 0x03b1,
	0x0313, 0x03b1, 0x0314, 0x03b1, 0x0313, 0x0300, 0x03b1, 0x0314,
	0x0300, 0x03b1, 0x0313, 0x0301, 0x03b1, 0x0314, 0x0301, 0x03b1,
	0x0313, 0x0342, 0x03b1, 0x0314, 0x0342, 0x0391, 0x0313, 0x0391,
	0x0314, 0x0391, 0x0313, 0x0300, 0x0391, 0x0314, 0x0300, 0x0391,
	0x0313, 0x0301, 0x0391, 0x0314, 0x0301, 0x0391, 0x0313, 0x0342,
	0x0391, 0x0314, 0x0342, 0x03b5, 0x0313, 0x03b5, 0x0314, 0x03b5,
	0x0313, 0x0300, 0x03b5, 0x0314, 0x0300, 0x03b5, 0x0313, 0x0301,
	0x03b5, 0x0314, 0x0301, 0x0395, 0x0313, 0x0395, 0x0314, 0x0395,
	0x0313, 0x0300, 0x0395, 0x0314, 0x0300, 0x0395, 0x0313, 0x0301,
	0x0395, 0x0314, 0x0301, 0x03b7, 0x0313, 0x03b7, 0x0314, 0x03b7,
	0x0313, 0x0300, 0x03b7, 0x0314, 0x0300, 0x03b7, 0x0313, 0x0301,
	0x03b7, 0x0314, 0x0301, 0x03b7, 0x0313, 0x0342, 0x03b7, 0x0314,
	0x0342, 0x0397, 0x0313, 0x0397, 0x0314, 0x0397, 0x0313, 0x0300,
	0x0397, 0x0314, 0x0300, 0x0397, 0x0313, 0x0301, 0x0397, 0x0314,
	0x0301, 0x0397, 0x0313, 0x0342, 0x0397, 0x0314, 0x0342, 0x03b9,
	0x0313, 0x03b9, 0x0314, 0x03b9, 0x0313, 0x0300, 0x03b9, 0x0314,
	0x0300, 0x03b9, 0x0313, 0x0301, 0x03b9, 0x0314, 0x0301, 0x03b9,
	0x0313, 0x0342, 0x03b9, 0x0314, 0x0342, 0x0399, 0x0313, 0x0399,
	0x0314, 0x0399, 0x0313, 0x0300, 0x0399, 0x0314, 0x0300, 0x0399,
	0x0313, 0x0301, 0x0399, 0x0314, 0x0301, 0x0399, 0x0313, 0x0342,
	0x0399, 0x0314, 0x0342, 0x03bf, 0x0313, 0x03bf, 0x0314, 0x03bf,
	0x0313, 0x0300, 0x03bf, 0x0314, 0x0300, 0x03bf, 0x0313, 0x0301,
	0x03bf, 0x0314, 0x0301, 0x039f, 0x0313, 0x039f, 0x0314, 0x039f,
	0x0313, 0x0300, 0x039f, 0x0314, 0x0300, 0x039f, 0x0313, 0x0301,
	0x039f, 0x0314, 0x0301, 0x03c5, 0x0313, 0x03c5, 0x0314, 0x03c5,
	0x0313, 0x0300, 0x03c5, 0x0314, 0x0300, 0x03c5, 0x0313, 0x0301,
	0x03c5, 0x0314, 0x0301, 0x03c5, 0x0313, 0x0342, 0x03c5, 0x0314,
	0x0342, 0x03a5, 0x0314, 0x03a5, 0x0314, 0x0300, 0x03a5, 0x0314,
	0x0301, 0x03a5, 0x0314, 0x0342, 0x03c9, 0x0313, 0x03c9, 0x0314,
	0x03c9, 0x0313, 0x0300, 0x03c9, 0x0314, 0x0300, 0x03c9, 0x0313,
	0x0301, 0x03c9, 0x0314, 0x0301, 0x03c9, 0x0313, 0x0342, 0x03c9,
	0x0314, 0x0342, 0x03a9, 0x0313, 0x03a9, 0x0314, 0x03a9, 0x0313,
	0x0300, 0x03a9, 0x0314, 0x0300, 0x03a9, 0x0313, 0x0301, 0x03a9,
	0x0314, 0x0301, 0x03a9, 0x0313, 0x0342, 0x03a9, 0x0314, 0x0342,
	0x03b1, 0x0300, 0x03b1, 0x0301, 0x03b5, 0x0300, 0x03b5, 0x0301,
	0x03b7, 0x0300, 0x03b7, 0x0301, 0x03b9, 0x0300, 0x03b9, 0x0301,
	0x03bf, 0x0300, 0x03bf, 0x0301, 0x03c5, 0x0300, 0x03c5, 0x0301,
	0x03c9, 0x0300, 0x03c9, 0x0301, 0x03b1, 0x0345, 0x0313, 0x03b1,
	0x0345, 0x0314, 0x03b1, 0x0345, 0x0313, 0x0300, 0x03b1, 0x0345,
	0x0314, 0x0300, 0x03b1, 0x0345, 0x0313, 0x0301, 0x03b1, 0x0345,
	0x0314, 0x0301, 0x03b1, 0x0345, 0x0313, 0x0342, 0x03b1, 0x0345,
	0x0314, 0x0342, 0x0391, 0x0345, 0x0313, 0x0391, 0x0345, 0x0314,
	0x0391, 0x0345, 0x0313, 0x0300, 0x0391, 0x0345, 0x0314, 0x0300,
	0x0391, 0x0345, 0x0313, 0x0301, 0x0391, 0x0345, 0x0314, 0x0301,
	0x0391, 0x0345, 0x0313, 0x0342, 0x0391, 0x0345, 0x0314, 0x0342,
	0x03b7, 0x0345, 0x0313, 0x03b7, 0x0345, 0x0314, 0x03b7, 0x0345,
	0x0313, 0x0300, 0x03b7, 0x0345, 0x0314, 0x0300, 0x03b7, 0x0345,
	0x0313, 0x0301, 0x03b7, 0x0345, 0x0314, 0x0301, 0x03b7, 0x0345,
	0x0313, 0x0342, 0x03b7, 0x0345, 0x0314, 0x0342, 0x0397, 0x0345,
	0x0313, 0x0397, 0x0345, 0x0314, 0x0397, 0x0345, 0x0313, 0x0300,
	0x0397, 0x0345, 0x0314, 0x0300, 0x0397, 0x0345, 0x0313, 0x0301,
	0x0397, 0x0345, 0x0314, 0x0301, 0x0397, 0x0345, 0x0313, 0x0342,
	0x0397, 0x0345, 0x0314, 0x0342, 0x03c9, 0x0345, 0x0313, 0x03c9,
	0x0345, 0x0314, 0x03c9, 0x0345, 0x0313, 0x0300, 0x03c9, 0x0345,
	0x0314, 0x0300, 0x03c9, 0x0345, 0x0313, 0x0301, 0x03c9, 0x0345,
	0x0314, 0x0301, 0x03c9, 0x0345, 0x0313, 0x0342, 0x03c9, 0x0345,
	0x0314, 0x0342, 0x03a9, 0x0345, 0x0313, 0x03a9, 0x0345, 0x0314,
	0x03a9, 0x0345, 0x0313, 0x0300, 0x03a9, 0x0345, 0x0314, 0x0300,
	0x03a9, 0x0345, 0x0313, 0x0301, 0x03a9, 0x0345, 0x0314, 0x0301,
	0x03a9, 0x0345, 0x0313, 0x0342, 0x03a9, 0x0345, 0x0314, 0x0342,
	0x03b1, 0x0306, 0x03b1, 0x0304, 0x03b1, 0x0345, 0x0300, 0x03b1,
	0x0345, 0x03b1, 0x0345, 0x0301, 0x03b1, 0x0342, 0x03b1, 0x0345,
	0x0342, 0x0391, 0x0306, 0x0391, 0x0304, 0x0391, 0x0300, 0x0391,
	0x0301, 0x0391, 0x0345, 0x03b9, 0x00a8, 0x0342, 0x03b7, 0x0345,
	0x0300, 0x03b7, 0x0345, 0x03b7, 0x0345, 0x0301, 0x03b7, 0x0342,
	0x03b7, 0x0345, 0x0342, 0x0395, 0x0300, 0x0395, 0x0301, 0x0397,
	0x0300, 0x0397, 0x0301, 0x0397, 0x0345, 0x1fbf, 0x0300, 0x1fbf,
	0x0301, 0x1fbf, 0x0342, 0x03b9, 0x0306, 0x03b9, 0x0304, 0x03b9,
	0x0308, 0x0300, 0x03b9, 0x0308, 0x0301, 0x03b9, 0x0342, 0x03b9,
	0x0308, 0x0342, 0x0399, 0x0306, 0x0399, 0x0304, 0x0399, 0x0300,
	0x0399, 0x0301, 0x1ffe, 0x0300, 0x1ffe, 0x0301, 0x1ffe, 0x0342,
	0x03c5, 0x0306, 0x03c5, 0x0304, 0x03c5, 0x0308, 0x0300, 0x03c5,
	0x0308, 0x0301, 0x03c1, 0x0313, 0x03c1, 0x0314, 0x03c5, 0x0342,
	0x03c5, 0x0308, 0x0342, 0x03a5, 0x0306, 0x03a5, 0x0304, 0x03a5,
	0x0300, 0x03a5, 0x0301, 0x03a1, 0x0314, 0x00a8, 0x0300, 0x00a8,
	0x0301, 0x0060, 0x03c9, 0x0345, 0x0300, 0x03c9, 0x0345, 0x03bf,
	0x0345, 0x0301, 0x03c9, 0x0342, 0x03c9, 0x0345, 0x0342, 0x039f,
	0x0300, 0x039f, 0x0301, 0x03a9, 0x0300, 0x03a9, 0x0301, 0x03a9,
	0x0345, 0x00b4, 0x304b, 0x3099, 0x304d, 0x3099, 0x304f, 0x3099,
	0x3051, 0x3099, 0x3053, 0x3099, 0x3055, 0x3099, 0x3057, 0x3099,
	0x3059, 0x3099, 0x305b, 0x3099, 0x305d, 0x3099, 0x305f, 0x3099,
	0x3061, 0x3099, 0x3064, 0x3099, 0x3066, 0x3099, 0x3068, 0x3099,
	0x306f, 0x3099, 0x306f, 0x309a, 0x3072, 0x3099, 0x3072, 0x309a,
	0x3075, 0x3099, 0x3075, 0x309a, 0x3078, 0x3099, 0x3078, 0x309a,
	0x307b, 0x3099, 0x307b, 0x309a, 0x3046, 0x3099, 0x309d, 0x3099,
	0x30ab, 0x3099, 0x30ad, 0x3099, 0x30af, 0x3099, 0x30b1, 0x3099,
	0x30b3, 0x3099, 0x30b5, 0x3099, 0x30b7, 0x3099, 0x30b9, 0x3099,
	0x30bb, 0x3099, 0x30bd, 0x3099, 0x30bf, 0x3099, 0x30c1, 0x3099,
	0x30c4, 0x3099, 0x30c6, 0x3099, 0x30c8, 0x3099, 0x30cf, 0x3099,
	0x30cf, 0x309a, 0x30d2, 0x3099, 0x30d2, 0x309a, 0x30d5, 0x3099,
	0x30d5, 0x309a, 0x30d8, 0x3099, 0x30d8, 0x309a, 0x30db, 0x3099,
	0x30db, 0x309a, 0x30a6, 0x3099, 0x30ef, 0x3099, 0x30f0, 0x3099,
	0x30f1, 0x3099, 0x30f2, 0x3099, 0x30fd, 0x3099, 0x05f2, 0x05b7,
	0x05e9, 0x05c1, 0x05e9, 0x05c2, 0x05e9, 0x05bc, 0x05c1, 0x05e9,
	0x05bc, 0x05c2, 0x05d0, 0x05b7, 0x05d0, 0x05b8, 0x05d0, 0x05bc,
	0x05d1, 0x05bc, 0x05d2, 0x05bc, 0x05d3, 0x05bc, 0x05d4, 0x05bc,
	0x05d5, 0x05bc, 0x05d6, 0x05bc, 0x05d8, 0x05bc, 0x05d9, 0x05bc,
	0x05da, 0x05bc, 0x05db, 0x05bc, 0x05dc, 0x05bc, 0x05de, 0x05bc,
	0x05e0, 0x05bc, 0x05e1, 0x05bc, 0x05e3, 0x05bc, 0x05e4, 0x05bc,
	0x05e6, 0x05bc, 0x05e7, 0x05bc, 0x05e8, 0x05bc, 0x05e9, 0x05bc,
	0x05ea, 0x05bc, 0x05d5, 0x05b9, 0x05d1, 0x05bf, 0x05db, 0x05bf,
	0x05e4, 0x05bf
};

u16 hfsplus_compose_table[] = {
	/* base */
	0x0000, 0x0050,  0x0300, 0x00a4,  0x0301, 0x00e4,  0x0302, 0x015c,
	0x0303, 0x0192,  0x0304, 0x01b4,  0x0306, 0x01e6,  0x0307, 0x0220,
	0x0308, 0x0270,  0x0309, 0x02d2,  0x030a, 0x02ec,  0x030b, 0x02fa,
	0x030c, 0x0308,  0x030d, 0x034c,  0x030f, 0x0370,  0x0311, 0x038e,
	0x0313, 0x03a8,  0x0314, 0x03c6,  0x031b, 0x03e8,  0x0323, 0x03f2,
	0x0324, 0x0440,  0x0325, 0x0446,  0x0327, 0x044c,  0x0328, 0x047a,
	0x032d, 0x0490,  0x032e, 0x04aa,  0x0330, 0x04b0,  0x0331, 0x04be,
	0x0342, 0x04e2,  0x0345, 0x04f4,  0x05b7, 0x0504,  0x05b8, 0x050a,
	0x05b9, 0x050e,  0x05bc, 0x0512,  0x05bf, 0x0540,  0x05c1, 0x0548,
	0x05c2, 0x054c,  0x093c, 0x0550,  0x09bc, 0x0568,  0x09be, 0x0572,
	0x09d7, 0x0576,  0x0a3c, 0x057a,  0x0b3c, 0x0586,  0x0b3e, 0x058e,
	0x0b56, 0x0592,  0x0b57, 0x0596,  0x0bbe, 0x059a,  0x0bd7, 0x05a0,
	0x0c56, 0x05a6,  0x0cc2, 0x05aa,  0x0cd5, 0x05ae,  0x0cd6, 0x05b4,
	0x0d3e, 0x05b8,  0x0d57, 0x05be,  0x0e32, 0x05c2,  0x0eb2, 0x05c6,
	0x0f71, 0x05ca,  0x0f80, 0x05d2,  0x0fb5, 0x05d8,  0x0fb7, 0x05de,
	0x1100, 0x00a2,  0x1101, 0x00a2,  0x1102, 0x00a2,  0x1103, 0x00a2,
	0x1104, 0x00a2,  0x1105, 0x00a2,  0x1106, 0x00a2,  0x1107, 0x00a2,
	0x1108, 0x00a2,  0x1109, 0x00a2,  0x110a, 0x00a2,  0x110b, 0x00a2,
	0x110c, 0x00a2,  0x110d, 0x00a2,  0x110e, 0x00a2,  0x110f, 0x00a2,
	0x1110, 0x00a2,  0x1111, 0x00a2,  0x1112, 0x00a2,  0x3099, 0x05f4,
	0x309a, 0x0656,
	/* hangul marker */
	0xffff, 0x0000,
	/* 0x0300 */
	0x0340, 0x001f,  0x0041, 0x066c,  0x0045, 0x066e,  0x0049, 0x0670,
	0x004f, 0x0672,  0x0055, 0x0674,  0x0057, 0x0676,  0x0059, 0x0678,
	0x0061, 0x067a,  0x0065, 0x067c,  0x0069, 0x067e,  0x006f, 0x0680,
	0x0075, 0x0682,  0x0077, 0x0684,  0x0079, 0x0686,  0x00a8, 0x0688,
	0x0391, 0x068a,  0x0395, 0x068c,  0x0397, 0x068e,  0x0399, 0x0690,
	0x039f, 0x0692,  0x03a5, 0x0694,  0x03a9, 0x0696,  0x03b1, 0x0698,
	0x03b5, 0x069a,  0x03b7, 0x069c,  0x03b9, 0x069e,  0x03bf, 0x06a0,
	0x03c5, 0x06a2,  0x03c9, 0x06a4,  0x1fbf, 0x06a6,  0x1ffe, 0x06a8,
	/* 0x0301 */
	0x0341, 0x003b,  0x0041, 0x06aa,  0x0043, 0x06ac,  0x0045, 0x06ae,
	0x0047, 0x06b0,  0x0049, 0x06b2,  0x004b, 0x06b4,  0x004c, 0x06b6,
	0x004d, 0x06b8,  0x004e, 0x06ba,  0x004f, 0x06bc,  0x0050, 0x06be,
	0x0052, 0x06c0,  0x0053, 0x06c2,  0x0055, 0x06c6,  0x0057, 0x06c8,
	0x0059, 0x06ca,  0x005a, 0x06cc,  0x0061, 0x06ce,  0x0063, 0x06d0,
	0x0065, 0x06d2,  0x0067, 0x06d4,  0x0069, 0x06d6,  0x006b, 0x06d8,
	0x006c, 0x06da,  0x006d, 0x06dc,  0x006e, 0x06de,  0x006f, 0x06e0,
	0x0070, 0x06e2,  0x0072, 0x06e4,  0x0073, 0x06e6,  0x0075, 0x06ea,
	0x0077, 0x06ec,  0x0079, 0x06ee,  0x007a, 0x06f0,  0x00a8, 0x06f2,
	0x00c6, 0x06f4,  0x00d8, 0x06f6,  0x00e6, 0x06f8,  0x00f8, 0x06fa,
	0x0391, 0x06fc,  0x0395, 0x06fe,  0x0397, 0x0700,  0x0399, 0x0702,
	0x039f, 0x0704,  0x03a5, 0x0706,  0x03a9, 0x0708,  0x03b1, 0x070a,
	0x03b5, 0x070c,  0x03b7, 0x070e,  0x03b9, 0x0710,  0x03bf, 0x0712,
	0x03c5, 0x0714,  0x03c9, 0x0716,  0x0413, 0x0718,  0x041a, 0x071a,
	0x0433, 0x071c,  0x043a, 0x071e,  0x1fbf, 0x0720,  0x1ffe, 0x0722,
	/* 0x0302 */
	0x0000, 0x001a,  0x0041, 0x0724,  0x0043, 0x072e,  0x0045, 0x0730,
	0x0047, 0x073a,  0x0048, 0x073c,  0x0049, 0x073e,  0x004a, 0x0740,
	0x004f, 0x0742,  0x0053, 0x074c,  0x0055, 0x074e,  0x0057, 0x0750,
	0x0059, 0x0752,  0x005a, 0x0754,  0x0061, 0x0756,  0x0063, 0x0760,
	0x0065, 0x0762,  0x0067, 0x076c,  0x0068, 0x076e,  0x0069, 0x0770,
	0x006a, 0x0772,  0x006f, 0x0774,  0x0073, 0x077e,  0x0075, 0x0780,
	0x0077, 0x0782,  0x0079, 0x0784,  0x007a, 0x0786,
	/* 0x0303 */
	0x0000, 0x0010,  0x0041, 0x0788,  0x0045, 0x078a,  0x0049, 0x078c,
	0x004e, 0x078e,  0x004f, 0x0790,  0x0055, 0x0796,  0x0056, 0x079a,
	0x0059, 0x079c,  0x0061, 0x079e,  0x0065, 0x07a0,  0x0069, 0x07a2,
	0x006e, 0x07a4,  0x006f, 0x07a6,  0x0075, 0x07ac,  0x0076, 0x07b0,
	0x0079, 0x07b2,
	/* 0x0304 */
	0x0000, 0x0018,  0x0041, 0x07b4,  0x0045, 0x07b6,  0x0047, 0x07bc,
	0x0049, 0x07be,  0x004f, 0x07c0,  0x0055, 0x07c6,  0x0061, 0x07ca,
	0x0065, 0x07cc,  0x0067, 0x07d2,  0x0069, 0x07d4,  0x006f, 0x07d6,
	0x0075, 0x07dc,  0x00c6, 0x07e0,  0x00e6, 0x07e2,  0x0391, 0x07e4,
	0x0399, 0x07e6,  0x03a5, 0x07e8,  0x03b1, 0x07ea,  0x03b9, 0x07ec,
	0x03c5, 0x07ee,  0x0418, 0x07f0,  0x0423, 0x07f2,  0x0438, 0x07f4,
	0x0443, 0x07f6,
	/* 0x0306 */
	0x0000, 0x001c,  0x0041, 0x07f8,  0x0045, 0x0802,  0x0047, 0x0804,
	0x0049, 0x0806,  0x004f, 0x0808,  0x0055, 0x080a,  0x0061, 0x080c,
	0x0065, 0x0816,  0x0067, 0x0818,  0x0069, 0x081a,  0x006f, 0x081c,
	0x0075, 0x081e,  0x0391, 0x0820,  0x0399, 0x0822,  0x03a5, 0x0824,
	0x03b1, 0x0826,  0x03b9, 0x0828,  0x03c5, 0x082a,  0x0410, 0x082c,
	0x0415, 0x082e,  0x0416, 0x0830,  0x0418, 0x0832,  0x0423, 0x0834,
	0x0430, 0x0836,  0x0435, 0x0838,  0x0436, 0x083a,  0x0438, 0x083c,
	0x0443, 0x083e,
	/* 0x0307 */
	0x0000, 0x0027,  0x0041, 0x0840,  0x0042, 0x0844,  0x0043, 0x0846,
	0x0044, 0x0848,  0x0045, 0x084a,  0x0046, 0x084c,  0x0047, 0x084e,
	0x0048, 0x0850,  0x0049, 0x0852,  0x004d, 0x0854,  0x004e, 0x0856,
	0x0050, 0x0858,  0x0052, 0x085a,  0x0053, 0x085c,  0x0054, 0x085e,
	0x0057, 0x0860,  0x0058, 0x0862,  0x0059, 0x0864,  0x005a, 0x0866,
	0x0061, 0x0868,  0x0062, 0x086c,  0x0063, 0x086e,  0x0064, 0x0870,
	0x0065, 0x0872,  0x0066, 0x0874,  0x0067, 0x0876,  0x0068, 0x0878,
	0x006d, 0x087a,  0x006e, 0x087c,  0x0070, 0x087e,  0x0072, 0x0880,
	0x0073, 0x0882,  0x0074, 0x0884,  0x0077, 0x0886,  0x0078, 0x0888,
	0x0079, 0x088a,  0x007a, 0x088c,  0x017f, 0x088e,  0x0306, 0x0890,
	/* 0x0308 */
	0x0000, 0x0030,  0x0041, 0x0892,  0x0045, 0x0896,  0x0048, 0x0898,
	0x0049, 0x089a,  0x004f, 0x089e,  0x0055, 0x08a0,  0x0057, 0x08aa,
	0x0058, 0x08ac,  0x0059, 0x08ae,  0x0061, 0x08b0,  0x0065, 0x08b4,
	0x0068, 0x08b6,  0x0069, 0x08b8,  0x006f, 0x08bc,  0x0074, 0x08be,
	0x0075, 0x08c0,  0x0077, 0x08ca,  0x0078, 0x08cc,  0x0079, 0x08ce,
	0x018f, 0x08d0,  0x019f, 0x08d2,  0x0259, 0x08d4,  0x0275, 0x08d6,
	0x0399, 0x08d8,  0x03a5, 0x08da,  0x03b9, 0x08dc,  0x03c5, 0x08e6,
	0x03d2, 0x08f0,  0x0406, 0x08f2,  0x0410, 0x08f4,  0x0415, 0x08f6,
	0x0416, 0x08f8,  0x0417, 0x08fa,  0x0418, 0x08fc,  0x041e, 0x08fe,
	0x0423, 0x0900,  0x0427, 0x0902,  0x042b, 0x0904,  0x0430, 0x0906,
	0x0435, 0x0908,  0x0436, 0x090a,  0x0437, 0x090c,  0x0438, 0x090e,
	0x043e, 0x0910,  0x0443, 0x0912,  0x0447, 0x0914,  0x044b, 0x0916,
	0x0456, 0x0918,
	/* 0x0309 */
	0x0000, 0x000c,  0x0041, 0x091a,  0x0045, 0x091c,  0x0049, 0x091e,
	0x004f, 0x0920,  0x0055, 0x0922,  0x0059, 0x0924,  0x0061, 0x0926,
	0x0065, 0x0928,  0x0069, 0x092a,  0x006f, 0x092c,  0x0075, 0x092e,
	0x0079, 0x0930,
	/* 0x030a */
	0x0000, 0x0006,  0x0041, 0x0932,  0x0055, 0x0936,  0x0061, 0x0938,
	0x0075, 0x093c,  0x0077, 0x093e,  0x0079, 0x0940,
	/* 0x030b */
	0x0000, 0x0006,  0x004f, 0x0942,  0x0055, 0x0944,  0x006f, 0x0946,
	0x0075, 0x0948,  0x0423, 0x094a,  0x0443, 0x094c,
	/* 0x030c */
	0x0000, 0x0021,  0x0041, 0x094e,  0x0043, 0x0950,  0x0044, 0x0952,
	0x0045, 0x0954,  0x0047, 0x0956,  0x0049, 0x0958,  0x004b, 0x095a,
	0x004c, 0x095c,  0x004e, 0x095e,  0x004f, 0x0960,  0x0052, 0x0962,
	0x0053, 0x0964,  0x0054, 0x0968,  0x0055, 0x096a,  0x005a, 0x096c,
	0x0061, 0x096e,  0x0063, 0x0970,  0x0064, 0x0972,  0x0065, 0x0974,
	0x0067, 0x0976,  0x0069, 0x0978,  0x006a, 0x097a,  0x006b, 0x097c,
	0x006c, 0x097e,  0x006e, 0x0980,  0x006f, 0x0982,  0x0072, 0x0984,
	0x0073, 0x0986,  0x0074, 0x098a,  0x0075, 0x098c,  0x007a, 0x098e,
	0x01b7, 0x0990,  0x0292, 0x0992,
	/* 0x030d */
	0x0000, 0x0011,  0x00a8, 0x0994,  0x0308, 0x0996,  0x0391, 0x0998,
	0x0395, 0x099a,  0x0397, 0x099c,  0x0399, 0x099e,  0x039f, 0x09a0,
	0x03a5, 0x09a2,  0x03a9, 0x09a4,  0x03b1, 0x09a6,  0x03b5, 0x09a8,
	0x03b7, 0x09aa,  0x03b9, 0x09ac,  0x03bf, 0x09ae,  0x03c5, 0x09b0,
	0x03c9, 0x09b2,  0x03d2, 0x09b4,
	/* 0x030f */
	0x0000, 0x000e,  0x0041, 0x09b6,  0x0045, 0x09b8,  0x0049, 0x09ba,
	0x004f, 0x09bc,  0x0052, 0x09be,  0x0055, 0x09c0,  0x0061, 0x09c2,
	0x0065, 0x09c4,  0x0069, 0x09c6,  0x006f, 0x09c8,  0x0072, 0x09ca,
	0x0075, 0x09cc,  0x0474, 0x09ce,  0x0475, 0x09d0,
	/* 0x0311 */
	0x0000, 0x000c,  0x0041, 0x09d2,  0x0045, 0x09d4,  0x0049, 0x09d6,
	0x004f, 0x09d8,  0x0052, 0x09da,  0x0055, 0x09dc,  0x0061, 0x09de,
	0x0065, 0x09e0,  0x0069, 0x09e2,  0x006f, 0x09e4,  0x0072, 0x09e6,
	0x0075, 0x09e8,
	/* 0x0313 */
	0x0343, 0x000e,  0x0391, 0x09ea,  0x0395, 0x09f2,  0x0397, 0x09f8,
	0x0399, 0x0a00,  0x039f, 0x0a08,  0x03a9, 0x0a0e,  0x03b1, 0x0a16,
	0x03b5, 0x0a1e,  0x03b7, 0x0a24,  0x03b9, 0x0a2c,  0x03bf, 0x0a34,
	0x03c1, 0x0a3a,  0x03c5, 0x0a3c,  0x03c9, 0x0a44,
	/* 0x0314 */
	0x0000, 0x0010,  0x0391, 0x0a4c,  0x0395, 0x0a54,  0x0397, 0x0a5a,
	0x0399, 0x0a62,  0x039f, 0x0a6a,  0x03a1, 0x0a70,  0x03a5, 0x0a72,
	0x03a9, 0x0a7a,  0x03b1, 0x0a82,  0x03b5, 0x0a8a,  0x03b7, 0x0a90,
	0x03b9, 0x0a98,  0x03bf, 0x0aa0,  0x03c1, 0x0aa6,  0x03c5, 0x0aa8,
	0x03c9, 0x0ab0,
	/* 0x031b */
	0x0000, 0x0004,  0x004f, 0x0ab8,  0x0055, 0x0ac4,  0x006f, 0x0ad0,
	0x0075, 0x0adc,
	/* 0x0323 */
	0x0000, 0x0026,  0x0041, 0x0ae8,  0x0042, 0x0aee,  0x0044, 0x0af0,
	0x0045, 0x0af2,  0x0048, 0x0af6,  0x0049, 0x0af8,  0x004b, 0x0afa,
	0x004c, 0x0afc,  0x004d, 0x0b00,  0x004e, 0x0b02,  0x004f, 0x0b04,
	0x0052, 0x0b08,  0x0053, 0x0b0c,  0x0054, 0x0b10,  0x0055, 0x0b12,
	0x0056, 0x0b14,  0x0057, 0x0b16,  0x0059, 0x0b18,  0x005a, 0x0b1a,
	0x0061, 0x0b1c,  0x0062, 0x0b22,  0x0064, 0x0b24,  0x0065, 0x0b26,
	0x0068, 0x0b2a,  0x0069, 0x0b2c,  0x006b, 0x0b2e,  0x006c, 0x0b30,
	0x006d, 0x0b34,  0x006e, 0x0b36,  0x006f, 0x0b38,  0x0072, 0x0b3c,
	0x0073, 0x0b40,  0x0074, 0x0b44,  0x0075, 0x0b46,  0x0076, 0x0b48,
	0x0077, 0x0b4a,  0x0079, 0x0b4c,  0x007a, 0x0b4e,
	/* 0x0324 */
	0x0000, 0x0002,  0x0055, 0x0b50,  0x0075, 0x0b52,
	/* 0x0325 */
	0x0000, 0x0002,  0x0041, 0x0b54,  0x0061, 0x0b56,
	/* 0x0327 */
	0x0000, 0x0016,  0x0043, 0x0b58,  0x0044, 0x0b5c,  0x0045, 0x0b5e,
	0x0047, 0x0b62,  0x0048, 0x0b64,  0x004b, 0x0b66,  0x004c, 0x0b68,
	0x004e, 0x0b6a,  0x0052, 0x0b6c,  0x0053, 0x0b6e,  0x0054, 0x0b70,
	0x0063, 0x0b72,  0x0064, 0x0b76,  0x0065, 0x0b78,  0x0067, 0x0b7c,
	0x0068, 0x0b7e,  0x006b, 0x0b80,  0x006c, 0x0b82,  0x006e, 0x0b84,
	0x0072, 0x0b86,  0x0073, 0x0b88,  0x0074, 0x0b8a,
	/* 0x0328 */
	0x0000, 0x000a,  0x0041, 0x0b8c,  0x0045, 0x0b8e,  0x0049, 0x0b90,
	0x004f, 0x0b92,  0x0055, 0x0b96,  0x0061, 0x0b98,  0x0065, 0x0b9a,
	0x0069, 0x0b9c,  0x006f, 0x0b9e,  0x0075, 0x0ba2,
	/* 0x032d */
	0x0000, 0x000c,  0x0044, 0x0ba4,  0x0045, 0x0ba6,  0x004c, 0x0ba8,
	0x004e, 0x0baa,  0x0054, 0x0bac,  0x0055, 0x0bae,  0x0064, 0x0bb0,
	0x0065, 0x0bb2,  0x006c, 0x0bb4,  0x006e, 0x0bb6,  0x0074, 0x0bb8,
	0x0075, 0x0bba,
	/* 0x032e */
	0x0000, 0x0002,  0x0048, 0x0bbc,  0x0068, 0x0bbe,
	/* 0x0330 */
	0x0000, 0x0006,  0x0045, 0x0bc0,  0x0049, 0x0bc2,  0x0055, 0x0bc4,
	0x0065, 0x0bc6,  0x0069, 0x0bc8,  0x0075, 0x0bca,
	/* 0x0331 */
	0x0000, 0x0011,  0x0042, 0x0bcc,  0x0044, 0x0bce,  0x004b, 0x0bd0,
	0x004c, 0x0bd2,  0x004e, 0x0bd4,  0x0052, 0x0bd6,  0x0054, 0x0bd8,
	0x005a, 0x0bda,  0x0062, 0x0bdc,  0x0064, 0x0bde,  0x0068, 0x0be0,
	0x006b, 0x0be2,  0x006c, 0x0be4,  0x006e, 0x0be6,  0x0072, 0x0be8,
	0x0074, 0x0bea,  0x007a, 0x0bec,
	/* 0x0342 */
	0x0000, 0x0008,  0x00a8, 0x0bee,  0x03b1, 0x0bf0,  0x03b7, 0x0bf2,
	0x03b9, 0x0bf4,  0x03c5, 0x0bf6,  0x03c9, 0x0bf8,  0x1fbf, 0x0bfa,
	0x1ffe, 0x0bfc,
	/* 0x0345 */
	0x0000, 0x0007,  0x0391, 0x0bfe,  0x0397, 0x0c04,  0x03a9, 0x0c0a,
	0x03b1, 0x0c10,  0x03b7, 0x0c1c,  0x03bf, 0x0c28,  0x03c9, 0x0c2c,
	/* 0x05b7 */
	0x0000, 0x0002,  0x05d0, 0x0c36,  0x05f2, 0x0c38,
	/* 0x05b8 */
	0x0000, 0x0001,  0x05d0, 0x0c3a,
	/* 0x05b9 */
	0x0000, 0x0001,  0x05d5, 0x0c3c,
	/* 0x05bc */
	0x0000, 0x0016,  0x05d0, 0x0c3e,  0x05d1, 0x0c40,  0x05d2, 0x0c42,
	0x05d3, 0x0c44,  0x05d4, 0x0c46,  0x05d5, 0x0c48,  0x05d6, 0x0c4a,
	0x05d8, 0x0c4c,  0x05d9, 0x0c4e,  0x05da, 0x0c50,  0x05db, 0x0c52,
	0x05dc, 0x0c54,  0x05de, 0x0c56,  0x05e0, 0x0c58,  0x05e1, 0x0c5a,
	0x05e3, 0x0c5c,  0x05e4, 0x0c5e,  0x05e6, 0x0c60,  0x05e7, 0x0c62,
	0x05e8, 0x0c64,  0x05e9, 0x0c66,  0x05ea, 0x0c6c,
	/* 0x05bf */
	0x0000, 0x0003,  0x05d1, 0x0c6e,  0x05db, 0x0c70,  0x05e4, 0x0c72,
	/* 0x05c1 */
	0x0000, 0x0001,  0x05e9, 0x0c74,
	/* 0x05c2 */
	0x0000, 0x0001,  0x05e9, 0x0c76,
	/* 0x093c */
	0x0000, 0x000b,  0x0915, 0x0c78,  0x0916, 0x0c7a,  0x0917, 0x0c7c,
	0x091c, 0x0c7e,  0x0921, 0x0c80,  0x0922, 0x0c82,  0x0928, 0x0c84,
	0x092b, 0x0c86,  0x092f, 0x0c88,  0x0930, 0x0c8a,  0x0933, 0x0c8c,
	/* 0x09bc */
	0x0000, 0x0004,  0x09a1, 0x0c8e,  0x09a2, 0x0c90,  0x09ac, 0x0c92,
	0x09af, 0x0c94,
	/* 0x09be */
	0x0000, 0x0001,  0x09c7, 0x0c96,
	/* 0x09d7 */
	0x0000, 0x0001,  0x09c7, 0x0c98,
	/* 0x0a3c */
	0x0000, 0x0005,  0x0a16, 0x0c9a,  0x0a17, 0x0c9c,  0x0a1c, 0x0c9e,
	0x0a21, 0x0ca0,  0x0a2b, 0x0ca2,
	/* 0x0b3c */
	0x0000, 0x0003,  0x0b21, 0x0ca4,  0x0b22, 0x0ca6,  0x0b2f, 0x0ca8,
	/* 0x0b3e */
	0x0000, 0x0001,  0x0b47, 0x0caa,
	/* 0x0b56 */
	0x0000, 0x0001,  0x0b47, 0x0cac,
	/* 0x0b57 */
	0x0000, 0x0001,  0x0b47, 0x0cae,
	/* 0x0bbe */
	0x0000, 0x0002,  0x0bc6, 0x0cb0,  0x0bc7, 0x0cb2,
	/* 0x0bd7 */
	0x0000, 0x0002,  0x0b92, 0x0cb4,  0x0bc6, 0x0cb6,
	/* 0x0c56 */
	0x0000, 0x0001,  0x0c46, 0x0cb8,
	/* 0x0cc2 */
	0x0000, 0x0001,  0x0cc6, 0x0cba,
	/* 0x0cd5 */
	0x0000, 0x0002,  0x0cbf, 0x0cbe,  0x0cc6, 0x0cc0,
	/* 0x0cd6 */
	0x0000, 0x0001,  0x0cc6, 0x0cc2,
	/* 0x0d3e */
	0x0000, 0x0002,  0x0d46, 0x0cc4,  0x0d47, 0x0cc6,
	/* 0x0d57 */
	0x0000, 0x0001,  0x0d46, 0x0cc8,
	/* 0x0e32 */
	0x0000, 0x0001,  0x0e4d, 0x0cca,
	/* 0x0eb2 */
	0x0000, 0x0001,  0x0ecd, 0x0ccc,
	/* 0x0f71 */
	0x0000, 0x0003,  0x0f72, 0x0cce,  0x0f74, 0x0cd0,  0x0f80, 0x0cd2,
	/* 0x0f80 */
	0x0000, 0x0002,  0x0fb2, 0x0cd4,  0x0fb3, 0x0cd8,
	/* 0x0fb5 */
	0x0000, 0x0002,  0x0f40, 0x0cdc,  0x0f90, 0x0cde,
	/* 0x0fb7 */
	0x0000, 0x000a,  0x0f42, 0x0ce0,  0x0f4c, 0x0ce2,  0x0f51, 0x0ce4,
	0x0f56, 0x0ce6,  0x0f5b, 0x0ce8,  0x0f92, 0x0cea,  0x0f9c, 0x0cec,
	0x0fa1, 0x0cee,  0x0fa6, 0x0cf0,  0x0fab, 0x0cf2,
	/* 0x3099 */
	0x0000, 0x0030,  0x3046, 0x0cf4,  0x304b, 0x0cf6,  0x304d, 0x0cf8,
	0x304f, 0x0cfa,  0x3051, 0x0cfc,  0x3053, 0x0cfe,  0x3055, 0x0d00,
	0x3057, 0x0d02,  0x3059, 0x0d04,  0x305b, 0x0d06,  0x305d, 0x0d08,
	0x305f, 0x0d0a,  0x3061, 0x0d0c,  0x3064, 0x0d0e,  0x3066, 0x0d10,
	0x3068, 0x0d12,  0x306f, 0x0d14,  0x3072, 0x0d16,  0x3075, 0x0d18,
	0x3078, 0x0d1a,  0x307b, 0x0d1c,  0x309d, 0x0d1e,  0x30a6, 0x0d20,
	0x30ab, 0x0d22,  0x30ad, 0x0d24,  0x30af, 0x0d26,  0x30b1, 0x0d28,
	0x30b3, 0x0d2a,  0x30b5, 0x0d2c,  0x30b7, 0x0d2e,  0x30b9, 0x0d30,
	0x30bb, 0x0d32,  0x30bd, 0x0d34,  0x30bf, 0x0d36,  0x30c1, 0x0d38,
	0x30c4, 0x0d3a,  0x30c6, 0x0d3c,  0x30c8, 0x0d3e,  0x30cf, 0x0d40,
	0x30d2, 0x0d42,  0x30d5, 0x0d44,  0x30d8, 0x0d46,  0x30db, 0x0d48,
	0x30ef, 0x0d4a,  0x30f0, 0x0d4c,  0x30f1, 0x0d4e,  0x30f2, 0x0d50,
	0x30fd, 0x0d52,
	/* 0x309a */
	0x0000, 0x000a,  0x306f, 0x0d54,  0x3072, 0x0d56,  0x3075, 0x0d58,
	0x3078, 0x0d5a,  0x307b, 0x0d5c,  0x30cf, 0x0d5e,  0x30d2, 0x0d60,
	0x30d5, 0x0d62,  0x30d8, 0x0d64,  0x30db, 0x0d66,
	/* 0x0041 0x0300 */
	0x00c0, 0x0000,
	/* 0x0045 0x0300 */
	0x00c8, 0x0000,
	/* 0x0049 0x0300 */
	0x00cc, 0x0000,
	/* 0x004f 0x0300 */
	0x00d2, 0x0000,
	/* 0x0055 0x0300 */
	0x00d9, 0x0000,
	/* 0x0057 0x0300 */
	0x1e80, 0x0000,
	/* 0x0059 0x0300 */
	0x1ef2, 0x0000,
	/* 0x0061 0x0300 */
	0x00e0, 0x0000,
	/* 0x0065 0x0300 */
	0x00e8, 0x0000,
	/* 0x0069 0x0300 */
	0x00ec, 0x0000,
	/* 0x006f 0x0300 */
	0x00f2, 0x0000,
	/* 0x0075 0x0300 */
	0x00f9, 0x0000,
	/* 0x0077 0x0300 */
	0x1e81, 0x0000,
	/* 0x0079 0x0300 */
	0x1ef3, 0x0000,
	/* 0x00a8 0x0300 */
	0x1fed, 0x0000,
	/* 0x0391 0x0300 */
	0x1fba, 0x0000,
	/* 0x0395 0x0300 */
	0x1fc8, 0x0000,
	/* 0x0397 0x0300 */
	0x1fca, 0x0000,
	/* 0x0399 0x0300 */
	0x1fda, 0x0000,
	/* 0x039f 0x0300 */
	0x1ff8, 0x0000,
	/* 0x03a5 0x0300 */
	0x1fea, 0x0000,
	/* 0x03a9 0x0300 */
	0x1ffa, 0x0000,
	/* 0x03b1 0x0300 */
	0x1f70, 0x0000,
	/* 0x03b5 0x0300 */
	0x1f72, 0x0000,
	/* 0x03b7 0x0300 */
	0x1f74, 0x0000,
	/* 0x03b9 0x0300 */
	0x1f76, 0x0000,
	/* 0x03bf 0x0300 */
	0x1f78, 0x0000,
	/* 0x03c5 0x0300 */
	0x1f7a, 0x0000,
	/* 0x03c9 0x0300 */
	0x1f7c, 0x0000,
	/* 0x1fbf 0x0300 */
	0x1fcd, 0x0000,
	/* 0x1ffe 0x0300 */
	0x1fdd, 0x0000,
	/* 0x0041 0x0301 */
	0x00c1, 0x0000,
	/* 0x0043 0x0301 */
	0x0106, 0x0000,
	/* 0x0045 0x0301 */
	0x00c9, 0x0000,
	/* 0x0047 0x0301 */
	0x01f4, 0x0000,
	/* 0x0049 0x0301 */
	0x00cd, 0x0000,
	/* 0x004b 0x0301 */
	0x1e30, 0x0000,
	/* 0x004c 0x0301 */
	0x0139, 0x0000,
	/* 0x004d 0x0301 */
	0x1e3e, 0x0000,
	/* 0x004e 0x0301 */
	0x0143, 0x0000,
	/* 0x004f 0x0301 */
	0x00d3, 0x0000,
	/* 0x0050 0x0301 */
	0x1e54, 0x0000,
	/* 0x0052 0x0301 */
	0x0154, 0x0000,
	/* 0x0053 0x0301 */
	0x015a, 0x0001,  0x0307, 0x0d68,
	/* 0x0055 0x0301 */
	0x00da, 0x0000,
	/* 0x0057 0x0301 */
	0x1e82, 0x0000,
	/* 0x0059 0x0301 */
	0x00dd, 0x0000,
	/* 0x005a 0x0301 */
	0x0179, 0x0000,
	/* 0x0061 0x0301 */
	0x00e1, 0x0000,
	/* 0x0063 0x0301 */
	0x0107, 0x0000,
	/* 0x0065 0x0301 */
	0x00e9, 0x0000,
	/* 0x0067 0x0301 */
	0x01f5, 0x0000,
	/* 0x0069 0x0301 */
	0x00ed, 0x0000,
	/* 0x006b 0x0301 */
	0x1e31, 0x0000,
	/* 0x006c 0x0301 */
	0x013a, 0x0000,
	/* 0x006d 0x0301 */
	0x1e3f, 0x0000,
	/* 0x006e 0x0301 */
	0x0144, 0x0000,
	/* 0x006f 0x0301 */
	0x00f3, 0x0000,
	/* 0x0070 0x0301 */
	0x1e55, 0x0000,
	/* 0x0072 0x0301 */
	0x0155, 0x0000,
	/* 0x0073 0x0301 */
	0x015b, 0x0001,  0x0307, 0x0d6a,
	/* 0x0075 0x0301 */
	0x00fa, 0x0000,
	/* 0x0077 0x0301 */
	0x1e83, 0x0000,
	/* 0x0079 0x0301 */
	0x00fd, 0x0000,
	/* 0x007a 0x0301 */
	0x017a, 0x0000,
	/* 0x00a8 0x0301 */
	0x1fee, 0x0000,
	/* 0x00c6 0x0301 */
	0x01fc, 0x0000,
	/* 0x00d8 0x0301 */
	0x01fe, 0x0000,
	/* 0x00e6 0x0301 */
	0x01fd, 0x0000,
	/* 0x00f8 0x0301 */
	0x01ff, 0x0000,
	/* 0x0391 0x0301 */
	0x1fbb, 0x0000,
	/* 0x0395 0x0301 */
	0x1fc9, 0x0000,
	/* 0x0397 0x0301 */
	0x1fcb, 0x0000,
	/* 0x0399 0x0301 */
	0x1fdb, 0x0000,
	/* 0x039f 0x0301 */
	0x1ff9, 0x0000,
	/* 0x03a5 0x0301 */
	0x1feb, 0x0000,
	/* 0x03a9 0x0301 */
	0x1ffb, 0x0000,
	/* 0x03b1 0x0301 */
	0x1f71, 0x0000,
	/* 0x03b5 0x0301 */
	0x1f73, 0x0000,
	/* 0x03b7 0x0301 */
	0x1f75, 0x0000,
	/* 0x03b9 0x0301 */
	0x1f77, 0x0000,
	/* 0x03bf 0x0301 */
	0x1f79, 0x0000,
	/* 0x03c5 0x0301 */
	0x1f7b, 0x0000,
	/* 0x03c9 0x0301 */
	0x1f7d, 0x0000,
	/* 0x0413 0x0301 */
	0x0403, 0x0000,
	/* 0x041a 0x0301 */
	0x040c, 0x0000,
	/* 0x0433 0x0301 */
	0x0453, 0x0000,
	/* 0x043a 0x0301 */
	0x045c, 0x0000,
	/* 0x1fbf 0x0301 */
	0x1fce, 0x0000,
	/* 0x1ffe 0x0301 */
	0x1fde, 0x0000,
	/* 0x0041 0x0302 */
	0x00c2, 0x0004,  0x0300, 0x0d6c,  0x0301, 0x0d6e,  0x0303, 0x0d70,
	0x0309, 0x0d72,
	/* 0x0043 0x0302 */
	0x0108, 0x0000,
	/* 0x0045 0x0302 */
	0x00ca, 0x0004,  0x0300, 0x0d74,  0x0301, 0x0d76,  0x0303, 0x0d78,
	0x0309, 0x0d7a,
	/* 0x0047 0x0302 */
	0x011c, 0x0000,
	/* 0x0048 0x0302 */
	0x0124, 0x0000,
	/* 0x0049 0x0302 */
	0x00ce, 0x0000,
	/* 0x004a 0x0302 */
	0x0134, 0x0000,
	/* 0x004f 0x0302 */
	0x00d4, 0x0004,  0x0300, 0x0d7c,  0x0301, 0x0d7e,  0x0303, 0x0d80,
	0x0309, 0x0d82,
	/* 0x0053 0x0302 */
	0x015c, 0x0000,
	/* 0x0055 0x0302 */
	0x00db, 0x0000,
	/* 0x0057 0x0302 */
	0x0174, 0x0000,
	/* 0x0059 0x0302 */
	0x0176, 0x0000,
	/* 0x005a 0x0302 */
	0x1e90, 0x0000,
	/* 0x0061 0x0302 */
	0x00e2, 0x0004,  0x0300, 0x0d84,  0x0301, 0x0d86,  0x0303, 0x0d88,
	0x0309, 0x0d8a,
	/* 0x0063 0x0302 */
	0x0109, 0x0000,
	/* 0x0065 0x0302 */
	0x00ea, 0x0004,  0x0300, 0x0d8c,  0x0301, 0x0d8e,  0x0303, 0x0d90,
	0x0309, 0x0d92,
	/* 0x0067 0x0302 */
	0x011d, 0x0000,
	/* 0x0068 0x0302 */
	0x0125, 0x0000,
	/* 0x0069 0x0302 */
	0x00ee, 0x0000,
	/* 0x006a 0x0302 */
	0x0135, 0x0000,
	/* 0x006f 0x0302 */
	0x00f4, 0x0004,  0x0300, 0x0d94,  0x0301, 0x0d96,  0x0303, 0x0d98,
	0x0309, 0x0d9a,
	/* 0x0073 0x0302 */
	0x015d, 0x0000,
	/* 0x0075 0x0302 */
	0x00fb, 0x0000,
	/* 0x0077 0x0302 */
	0x0175, 0x0000,
	/* 0x0079 0x0302 */
	0x0177, 0x0000,
	/* 0x007a 0x0302 */
	0x1e91, 0x0000,
	/* 0x0041 0x0303 */
	0x00c3, 0x0000,
	/* 0x0045 0x0303 */
	0x1ebc, 0x0000,
	/* 0x0049 0x0303 */
	0x0128, 0x0000,
	/* 0x004e 0x0303 */
	0x00d1, 0x0000,
	/* 0x004f 0x0303 */
	0x00d5, 0x0002,  0x0301, 0x0d9c,  0x0308, 0x0d9e,
	/* 0x0055 0x0303 */
	0x0168, 0x0001,  0x0301, 0x0da0,
	/* 0x0056 0x0303 */
	0x1e7c, 0x0000,
	/* 0x0059 0x0303 */
	0x1ef8, 0x0000,
	/* 0x0061 0x0303 */
	0x00e3, 0x0000,
	/* 0x0065 0x0303 */
	0x1ebd, 0x0000,
	/* 0x0069 0x0303 */
	0x0129, 0x0000,
	/* 0x006e 0x0303 */
	0x00f1, 0x0000,
	/* 0x006f 0x0303 */
	0x00f5, 0x0002,  0x0301, 0x0da2,  0x0308, 0x0da4,
	/* 0x0075 0x0303 */
	0x0169, 0x0001,  0x0301, 0x0da6,
	/* 0x0076 0x0303 */
	0x1e7d, 0x0000,
	/* 0x0079 0x0303 */
	0x1ef9, 0x0000,
	/* 0x0041 0x0304 */
	0x0100, 0x0000,
	/* 0x0045 0x0304 */
	0x0112, 0x0002,  0x0300, 0x0da8,  0x0301, 0x0daa,
	/* 0x0047 0x0304 */
	0x1e20, 0x0000,
	/* 0x0049 0x0304 */
	0x012a, 0x0000,
	/* 0x004f 0x0304 */
	0x014c, 0x0002,  0x0300, 0x0dac,  0x0301, 0x0dae,
	/* 0x0055 0x0304 */
	0x016a, 0x0001,  0x0308, 0x0db0,
	/* 0x0061 0x0304 */
	0x0101, 0x0000,
	/* 0x0065 0x0304 */
	0x0113, 0x0002,  0x0300, 0x0db2,  0x0301, 0x0db4,
	/* 0x0067 0x0304 */
	0x1e21, 0x0000,
	/* 0x0069 0x0304 */
	0x012b, 0x0000,
	/* 0x006f 0x0304 */
	0x014d, 0x0002,  0x0300, 0x0db6,  0x0301, 0x0db8,
	/* 0x0075 0x0304 */
	0x016b, 0x0001,  0x0308, 0x0dba,
	/* 0x00c6 0x0304 */
	0x01e2, 0x0000,
	/* 0x00e6 0x0304 */
	0x01e3, 0x0000,
	/* 0x0391 0x0304 */
	0x1fb9, 0x0000,
	/* 0x0399 0x0304 */
	0x1fd9, 0x0000,
	/* 0x03a5 0x0304 */
	0x1fe9, 0x0000,
	/* 0x03b1 0x0304 */
	0x1fb1, 0x0000,
	/* 0x03b9 0x0304 */
	0x1fd1, 0x0000,
	/* 0x03c5 0x0304 */
	0x1fe1, 0x0000,
	/* 0x0418 0x0304 */
	0x04e2, 0x0000,
	/* 0x0423 0x0304 */
	0x04ee, 0x0000,
	/* 0x0438 0x0304 */
	0x04e3, 0x0000,
	/* 0x0443 0x0304 */
	0x04ef, 0x0000,
	/* 0x0041 0x0306 */
	0x0102, 0x0004,  0x0300, 0x0dbc,  0x0301, 0x0dbe,  0x0303, 0x0dc0,
	0x0309, 0x0dc2,
	/* 0x0045 0x0306 */
	0x0114, 0x0000,
	/* 0x0047 0x0306 */
	0x011e, 0x0000,
	/* 0x0049 0x0306 */
	0x012c, 0x0000,
	/* 0x004f 0x0306 */
	0x014e, 0x0000,
	/* 0x0055 0x0306 */
	0x016c, 0x0000,
	/* 0x0061 0x0306 */
	0x0103, 0x0004,  0x0300, 0x0dc4,  0x0301, 0x0dc6,  0x0303, 0x0dc8,
	0x0309, 0x0dca,
	/* 0x0065 0x0306 */
	0x0115, 0x0000,
	/* 0x0067 0x0306 */
	0x011f, 0x0000,
	/* 0x0069 0x0306 */
	0x012d, 0x0000,
	/* 0x006f 0x0306 */
	0x014f, 0x0000,
	/* 0x0075 0x0306 */
	0x016d, 0x0000,
	/* 0x0391 0x0306 */
	0x1fb8, 0x0000,
	/* 0x0399 0x0306 */
	0x1fd8, 0x0000,
	/* 0x03a5 0x0306 */
	0x1fe8, 0x0000,
	/* 0x03b1 0x0306 */
	0x1fb0, 0x0000,
	/* 0x03b9 0x0306 */
	0x1fd0, 0x0000,
	/* 0x03c5 0x0306 */
	0x1fe0, 0x0000,
	/* 0x0410 0x0306 */
	0x04d0, 0x0000,
	/* 0x0415 0x0306 */
	0x04d6, 0x0000,
	/* 0x0416 0x0306 */
	0x04c1, 0x0000,
	/* 0x0418 0x0306 */
	0x0419, 0x0000,
	/* 0x0423 0x0306 */
	0x040e, 0x0000,
	/* 0x0430 0x0306 */
	0x04d1, 0x0000,
	/* 0x0435 0x0306 */
	0x04d7, 0x0000,
	/* 0x0436 0x0306 */
	0x04c2, 0x0000,
	/* 0x0438 0x0306 */
	0x0439, 0x0000,
	/* 0x0443 0x0306 */
	0x045e, 0x0000,
	/* 0x0041 0x0307 */
	0x0000, 0x0001,  0x0304, 0x0dcc,
	/* 0x0042 0x0307 */
	0x1e02, 0x0000,
	/* 0x0043 0x0307 */
	0x010a, 0x0000,
	/* 0x0044 0x0307 */
	0x1e0a, 0x0000,
	/* 0x0045 0x0307 */
	0x0116, 0x0000,
	/* 0x0046 0x0307 */
	0x1e1e, 0x0000,
	/* 0x0047 0x0307 */
	0x0120, 0x0000,
	/* 0x0048 0x0307 */
	0x1e22, 0x0000,
	/* 0x0049 0x0307 */
	0x0130, 0x0000,
	/* 0x004d 0x0307 */
	0x1e40, 0x0000,
	/* 0x004e 0x0307 */
	0x1e44, 0x0000,
	/* 0x0050 0x0307 */
	0x1e56, 0x0000,
	/* 0x0052 0x0307 */
	0x1e58, 0x0000,
	/* 0x0053 0x0307 */
	0x1e60, 0x0000,
	/* 0x0054 0x0307 */
	0x1e6a, 0x0000,
	/* 0x0057 0x0307 */
	0x1e86, 0x0000,
	/* 0x0058 0x0307 */
	0x1e8a, 0x0000,
	/* 0x0059 0x0307 */
	0x1e8e, 0x0000,
	/* 0x005a 0x0307 */
	0x017b, 0x0000,
	/* 0x0061 0x0307 */
	0x0000, 0x0001,  0x0304, 0x0dce,
	/* 0x0062 0x0307 */
	0x1e03, 0x0000,
	/* 0x0063 0x0307 */
	0x010b, 0x0000,
	/* 0x0064 0x0307 */
	0x1e0b, 0x0000,
	/* 0x0065 0x0307 */
	0x0117, 0x0000,
	/* 0x0066 0x0307 */
	0x1e1f, 0x0000,
	/* 0x0067 0x0307 */
	0x0121, 0x0000,
	/* 0x0068 0x0307 */
	0x1e23, 0x0000,
	/* 0x006d 0x0307 */
	0x1e41, 0x0000,
	/* 0x006e 0x0307 */
	0x1e45, 0x0000,
	/* 0x0070 0x0307 */
	0x1e57, 0x0000,
	/* 0x0072 0x0307 */
	0x1e59, 0x0000,
	/* 0x0073 0x0307 */
	0x1e61, 0x0000,
	/* 0x0074 0x0307 */
	0x1e6b, 0x0000,
	/* 0x0077 0x0307 */
	0x1e87, 0x0000,
	/* 0x0078 0x0307 */
	0x1e8b, 0x0000,
	/* 0x0079 0x0307 */
	0x1e8f, 0x0000,
	/* 0x007a 0x0307 */
	0x017c, 0x0000,
	/* 0x017f 0x0307 */
	0x1e9b, 0x0000,
	/* 0x0306 0x0307 */
	0x0310, 0x0000,
	/* 0x0041 0x0308 */
	0x00c4, 0x0001,  0x0304, 0x0dd0,
	/* 0x0045 0x0308 */
	0x00cb, 0x0000,
	/* 0x0048 0x0308 */
	0x1e26, 0x0000,
	/* 0x0049 0x0308 */
	0x00cf, 0x0001,  0x0301, 0x0dd2,
	/* 0x004f 0x0308 */
	0x00d6, 0x0000,
	/* 0x0055 0x0308 */
	0x00dc, 0x0004,  0x0300, 0x0dd4,  0x0301, 0x0dd6,  0x0304, 0x0dd8,
	0x030c, 0x0dda,
	/* 0x0057 0x0308 */
	0x1e84, 0x0000,
	/* 0x0058 0x0308 */
	0x1e8c, 0x0000,
	/* 0x0059 0x0308 */
	0x0178, 0x0000,
	/* 0x0061 0x0308 */
	0x00e4, 0x0001,  0x0304, 0x0ddc,
	/* 0x0065 0x0308 */
	0x00eb, 0x0000,
	/* 0x0068 0x0308 */
	0x1e27, 0x0000,
	/* 0x0069 0x0308 */
	0x00ef, 0x0001,  0x0301, 0x0dde,
	/* 0x006f 0x0308 */
	0x00f6, 0x0000,
	/* 0x0074 0x0308 */
	0x1e97, 0x0000,
	/* 0x0075 0x0308 */
	0x00fc, 0x0004,  0x0300, 0x0de0,  0x0301, 0x0de2,  0x0304, 0x0de4,
	0x030c, 0x0de6,
	/* 0x0077 0x0308 */
	0x1e85, 0x0000,
	/* 0x0078 0x0308 */
	0x1e8d, 0x0000,
	/* 0x0079 0x0308 */
	0x00ff, 0x0000,
	/* 0x018f 0x0308 */
	0x04da, 0x0000,
	/* 0x019f 0x0308 */
	0x04ea, 0x0000,
	/* 0x0259 0x0308 */
	0x04db, 0x0000,
	/* 0x0275 0x0308 */
	0x04eb, 0x0000,
	/* 0x0399 0x0308 */
	0x03aa, 0x0000,
	/* 0x03a5 0x0308 */
	0x03ab, 0x0000,
	/* 0x03b9 0x0308 */
	0x03ca, 0x0004,  0x0300, 0x0de8,  0x0301, 0x0dea,  0x030d, 0x0dec,
	0x0342, 0x0dee,
	/* 0x03c5 0x0308 */
	0x03cb, 0x0004,  0x0300, 0x0df0,  0x0301, 0x0df2,  0x030d, 0x0df4,
	0x0342, 0x0df6,
	/* 0x03d2 0x0308 */
	0x03d4, 0x0000,
	/* 0x0406 0x0308 */
	0x0407, 0x0000,
	/* 0x0410 0x0308 */
	0x04d2, 0x0000,
	/* 0x0415 0x0308 */
	0x0401, 0x0000,
	/* 0x0416 0x0308 */
	0x04dc, 0x0000,
	/* 0x0417 0x0308 */
	0x04de, 0x0000,
	/* 0x0418 0x0308 */
	0x04e4, 0x0000,
	/* 0x041e 0x0308 */
	0x04e6, 0x0000,
	/* 0x0423 0x0308 */
	0x04f0, 0x0000,
	/* 0x0427 0x0308 */
	0x04f4, 0x0000,
	/* 0x042b 0x0308 */
	0x04f8, 0x0000,
	/* 0x0430 0x0308 */
	0x04d3, 0x0000,
	/* 0x0435 0x0308 */
	0x0451, 0x0000,
	/* 0x0436 0x0308 */
	0x04dd, 0x0000,
	/* 0x0437 0x0308 */
	0x04df, 0x0000,
	/* 0x0438 0x0308 */
	0x04e5, 0x0000,
	/* 0x043e 0x0308 */
	0x04e7, 0x0000,
	/* 0x0443 0x0308 */
	0x04f1, 0x0000,
	/* 0x0447 0x0308 */
	0x04f5, 0x0000,
	/* 0x044b 0x0308 */
	0x04f9, 0x0000,
	/* 0x0456 0x0308 */
	0x0457, 0x0000,
	/* 0x0041 0x0309 */
	0x1ea2, 0x0000,
	/* 0x0045 0x0309 */
	0x1eba, 0x0000,
	/* 0x0049 0x0309 */
	0x1ec8, 0x0000,
	/* 0x004f 0x0309 */
	0x1ece, 0x0000,
	/* 0x0055 0x0309 */
	0x1ee6, 0x0000,
	/* 0x0059 0x0309 */
	0x1ef6, 0x0000,
	/* 0x0061 0x0309 */
	0x1ea3, 0x0000,
	/* 0x0065 0x0309 */
	0x1ebb, 0x0000,
	/* 0x0069 0x0309 */
	0x1ec9, 0x0000,
	/* 0x006f 0x0309 */
	0x1ecf, 0x0000,
	/* 0x0075 0x0309 */
	0x1ee7, 0x0000,
	/* 0x0079 0x0309 */
	0x1ef7, 0x0000,
	/* 0x0041 0x030a */
	0x00c5, 0x0001,  0x0301, 0x0df8,
	/* 0x0055 0x030a */
	0x016e, 0x0000,
	/* 0x0061 0x030a */
	0x00e5, 0x0001,  0x0301, 0x0dfa,
	/* 0x0075 0x030a */
	0x016f, 0x0000,
	/* 0x0077 0x030a */
	0x1e98, 0x0000,
	/* 0x0079 0x030a */
	0x1e99, 0x0000,
	/* 0x004f 0x030b */
	0x0150, 0x0000,
	/* 0x0055 0x030b */
	0x0170, 0x0000,
	/* 0x006f 0x030b */
	0x0151, 0x0000,
	/* 0x0075 0x030b */
	0x0171, 0x0000,
	/* 0x0423 0x030b */
	0x04f2, 0x0000,
	/* 0x0443 0x030b */
	0x04f3, 0x0000,
	/* 0x0041 0x030c */
	0x01cd, 0x0000,
	/* 0x0043 0x030c */
	0x010c, 0x0000,
	/* 0x0044 0x030c */
	0x010e, 0x0000,
	/* 0x0045 0x030c */
	0x011a, 0x0000,
	/* 0x0047 0x030c */
	0x01e6, 0x0000,
	/* 0x0049 0x030c */
	0x01cf, 0x0000,
	/* 0x004b 0x030c */
	0x01e8, 0x0000,
	/* 0x004c 0x030c */
	0x013d, 0x0000,
	/* 0x004e 0x030c */
	0x0147, 0x0000,
	/* 0x004f 0x030c */
	0x01d1, 0x0000,
	/* 0x0052 0x030c */
	0x0158, 0x0000,
	/* 0x0053 0x030c */
	0x0160, 0x0001,  0x0307, 0x0dfc,
	/* 0x0054 0x030c */
	0x0164, 0x0000,
	/* 0x0055 0x030c */
	0x01d3, 0x0000,
	/* 0x005a 0x030c */
	0x017d, 0x0000,
	/* 0x0061 0x030c */
	0x01ce, 0x0000,
	/* 0x0063 0x030c */
	0x010d, 0x0000,
	/* 0x0064 0x030c */
	0x010f, 0x0000,
	/* 0x0065 0x030c */
	0x011b, 0x0000,
	/* 0x0067 0x030c */
	0x01e7, 0x0000,
	/* 0x0069 0x030c */
	0x01d0, 0x0000,
	/* 0x006a 0x030c */
	0x01f0, 0x0000,
	/* 0x006b 0x030c */
	0x01e9, 0x0000,
	/* 0x006c 0x030c */
	0x013e, 0x0000,
	/* 0x006e 0x030c */
	0x0148, 0x0000,
	/* 0x006f 0x030c */
	0x01d2, 0x0000,
	/* 0x0072 0x030c */
	0x0159, 0x0000,
	/* 0x0073 0x030c */
	0x0161, 0x0001,  0x0307, 0x0dfe,
	/* 0x0074 0x030c */
	0x0165, 0x0000,
	/* 0x0075 0x030c */
	0x01d4, 0x0000,
	/* 0x007a 0x030c */
	0x017e, 0x0000,
	/* 0x01b7 0x030c */
	0x01ee, 0x0000,
	/* 0x0292 0x030c */
	0x01ef, 0x0000,
	/* 0x00a8 0x030d */
	0x0385, 0x0000,
	/* 0x0308 0x030d */
	0x0344, 0x0000,
	/* 0x0391 0x030d */
	0x0386, 0x0000,
	/* 0x0395 0x030d */
	0x0388, 0x0000,
	/* 0x0397 0x030d */
	0x0389, 0x0000,
	/* 0x0399 0x030d */
	0x038a, 0x0000,
	/* 0x039f 0x030d */
	0x038c, 0x0000,
	/* 0x03a5 0x030d */
	0x038e, 0x0000,
	/* 0x03a9 0x030d */
	0x038f, 0x0000,
	/* 0x03b1 0x030d */
	0x03ac, 0x0000,
	/* 0x03b5 0x030d */
	0x03ad, 0x0000,
	/* 0x03b7 0x030d */
	0x03ae, 0x0000,
	/* 0x03b9 0x030d */
	0x03af, 0x0000,
	/* 0x03bf 0x030d */
	0x03cc, 0x0000,
	/* 0x03c5 0x030d */
	0x03cd, 0x0000,
	/* 0x03c9 0x030d */
	0x03ce, 0x0000,
	/* 0x03d2 0x030d */
	0x03d3, 0x0000,
	/* 0x0041 0x030f */
	0x0200, 0x0000,
	/* 0x0045 0x030f */
	0x0204, 0x0000,
	/* 0x0049 0x030f */
	0x0208, 0x0000,
	/* 0x004f 0x030f */
	0x020c, 0x0000,
	/* 0x0052 0x030f */
	0x0210, 0x0000,
	/* 0x0055 0x030f */
	0x0214, 0x0000,
	/* 0x0061 0x030f */
	0x0201, 0x0000,
	/* 0x0065 0x030f */
	0x0205, 0x0000,
	/* 0x0069 0x030f */
	0x0209, 0x0000,
	/* 0x006f 0x030f */
	0x020d, 0x0000,
	/* 0x0072 0x030f */
	0x0211, 0x0000,
	/* 0x0075 0x030f */
	0x0215, 0x0000,
	/* 0x0474 0x030f */
	0x0476, 0x0000,
	/* 0x0475 0x030f */
	0x0477, 0x0000,
	/* 0x0041 0x0311 */
	0x0202, 0x0000,
	/* 0x0045 0x0311 */
	0x0206, 0x0000,
	/* 0x0049 0x0311 */
	0x020a, 0x0000,
	/* 0x004f 0x0311 */
	0x020e, 0x0000,
	/* 0x0052 0x0311 */
	0x0212, 0x0000,
	/* 0x0055 0x0311 */
	0x0216, 0x0000,
	/* 0x0061 0x0311 */
	0x0203, 0x0000,
	/* 0x0065 0x0311 */
	0x0207, 0x0000,
	/* 0x0069 0x0311 */
	0x020b, 0x0000,
	/* 0x006f 0x0311 */
	0x020f, 0x0000,
	/* 0x0072 0x0311 */
	0x0213, 0x0000,
	/* 0x0075 0x0311 */
	0x0217, 0x0000,
	/* 0x0391 0x0313 */
	0x1f08, 0x0003,  0x0300, 0x0e00,  0x0301, 0x0e02,  0x0342, 0x0e04,
	/* 0x0395 0x0313 */
	0x1f18, 0x0002,  0x0300, 0x0e06,  0x0301, 0x0e08,
	/* 0x0397 0x0313 */
	0x1f28, 0x0003,  0x0300, 0x0e0a,  0x0301, 0x0e0c,  0x0342, 0x0e0e,
	/* 0x0399 0x0313 */
	0x1f38, 0x0003,  0x0300, 0x0e10,  0x0301, 0x0e12,  0x0342, 0x0e14,
	/* 0x039f 0x0313 */
	0x1f48, 0x0002,  0x0300, 0x0e16,  0x0301, 0x0e18,
	/* 0x03a9 0x0313 */
	0x1f68, 0x0003,  0x0300, 0x0e1a,  0x0301, 0x0e1c,  0x0342, 0x0e1e,
	/* 0x03b1 0x0313 */
	0x1f00, 0x0003,  0x0300, 0x0e20,  0x0301, 0x0e22,  0x0342, 0x0e24,
	/* 0x03b5 0x0313 */
	0x1f10, 0x0002,  0x0300, 0x0e26,  0x0301, 0x0e28,
	/* 0x03b7 0x0313 */
	0x1f20, 0x0003,  0x0300, 0x0e2a,  0x0301, 0x0e2c,  0x0342, 0x0e2e,
	/* 0x03b9 0x0313 */
	0x1f30, 0x0003,  0x0300, 0x0e30,  0x0301, 0x0e32,  0x0342, 0x0e34,
	/* 0x03bf 0x0313 */
	0x1f40, 0x0002,  0x0300, 0x0e36,  0x0301, 0x0e38,
	/* 0x03c1 0x0313 */
	0x1fe4, 0x0000,
	/* 0x03c5 0x0313 */
	0x1f50, 0x0003,  0x0300, 0x0e3a,  0x0301, 0x0e3c,  0x0342, 0x0e3e,
	/* 0x03c9 0x0313 */
	0x1f60, 0x0003,  0x0300, 0x0e40,  0x0301, 0x0e42,  0x0342, 0x0e44,
	/* 0x0391 0x0314 */
	0x1f09, 0x0003,  0x0300, 0x0e46,  0x0301, 0x0e48,  0x0342, 0x0e4a,
	/* 0x0395 0x0314 */
	0x1f19, 0x0002,  0x0300, 0x0e4c,  0x0301, 0x0e4e,
	/* 0x0397 0x0314 */
	0x1f29, 0x0003,  0x0300, 0x0e50,  0x0301, 0x0e52,  0x0342, 0x0e54,
	/* 0x0399 0x0314 */
	0x1f39, 0x0003,  0x0300, 0x0e56,  0x0301, 0x0e58,  0x0342, 0x0e5a,
	/* 0x039f 0x0314 */
	0x1f49, 0x0002,  0x0300, 0x0e5c,  0x0301, 0x0e5e,
	/* 0x03a1 0x0314 */
	0x1fec, 0x0000,
	/* 0x03a5 0x0314 */
	0x1f59, 0x0003,  0x0300, 0x0e60,  0x0301, 0x0e62,  0x0342, 0x0e64,
	/* 0x03a9 0x0314 */
	0x1f69, 0x0003,  0x0300, 0x0e66,  0x0301, 0x0e68,  0x0342, 0x0e6a,
	/* 0x03b1 0x0314 */
	0x1f01, 0x0003,  0x0300, 0x0e6c,  0x0301, 0x0e6e,  0x0342, 0x0e70,
	/* 0x03b5 0x0314 */
	0x1f11, 0x0002,  0x0300, 0x0e72,  0x0301, 0x0e74,
	/* 0x03b7 0x0314 */
	0x1f21, 0x0003,  0x0300, 0x0e76,  0x0301, 0x0e78,  0x0342, 0x0e7a,
	/* 0x03b9 0x0314 */
	0x1f31, 0x0003,  0x0300, 0x0e7c,  0x0301, 0x0e7e,  0x0342, 0x0e80,
	/* 0x03bf 0x0314 */
	0x1f41, 0x0002,  0x0300, 0x0e82,  0x0301, 0x0e84,
	/* 0x03c1 0x0314 */
	0x1fe5, 0x0000,
	/* 0x03c5 0x0314 */
	0x1f51, 0x0003,  0x0300, 0x0e86,  0x0301, 0x0e88,  0x0342, 0x0e8a,
	/* 0x03c9 0x0314 */
	0x1f61, 0x0003,  0x0300, 0x0e8c,  0x0301, 0x0e8e,  0x0342, 0x0e90,
	/* 0x004f 0x031b */
	0x01a0, 0x0005,  0x0300, 0x0e92,  0x0301, 0x0e94,  0x0303, 0x0e96,
	0x0309, 0x0e98,  0x0323, 0x0e9a,
	/* 0x0055 0x031b */
	0x01af, 0x0005,  0x0300, 0x0e9c,  0x0301, 0x0e9e,  0x0303, 0x0ea0,
	0x0309, 0x0ea2,  0x0323, 0x0ea4,
	/* 0x006f 0x031b */
	0x01a1, 0x0005,  0x0300, 0x0ea6,  0x0301, 0x0ea8,  0x0303, 0x0eaa,
	0x0309, 0x0eac,  0x0323, 0x0eae,
	/* 0x0075 0x031b */
	0x01b0, 0x0005,  0x0300, 0x0eb0,  0x0301, 0x0eb2,  0x0303, 0x0eb4,
	0x0309, 0x0eb6,  0x0323, 0x0eb8,
	/* 0x0041 0x0323 */
	0x1ea0, 0x0002,  0x0302, 0x0eba,  0x0306, 0x0ebc,
	/* 0x0042 0x0323 */
	0x1e04, 0x0000,
	/* 0x0044 0x0323 */
	0x1e0c, 0x0000,
	/* 0x0045 0x0323 */
	0x1eb8, 0x0001,  0x0302, 0x0ebe,
	/* 0x0048 0x0323 */
	0x1e24, 0x0000,
	/* 0x0049 0x0323 */
	0x1eca, 0x0000,
	/* 0x004b 0x0323 */
	0x1e32, 0x0000,
	/* 0x004c 0x0323 */
	0x1e36, 0x0001,  0x0304, 0x0ec0,
	/* 0x004d 0x0323 */
	0x1e42, 0x0000,
	/* 0x004e 0x0323 */
	0x1e46, 0x0000,
	/* 0x004f 0x0323 */
	0x1ecc, 0x0001,  0x0302, 0x0ec2,
	/* 0x0052 0x0323 */
	0x1e5a, 0x0001,  0x0304, 0x0ec4,
	/* 0x0053 0x0323 */
	0x1e62, 0x0001,  0x0307, 0x0ec6,
	/* 0x0054 0x0323 */
	0x1e6c, 0x0000,
	/* 0x0055 0x0323 */
	0x1ee4, 0x0000,
	/* 0x0056 0x0323 */
	0x1e7e, 0x0000,
	/* 0x0057 0x0323 */
	0x1e88, 0x0000,
	/* 0x0059 0x0323 */
	0x1ef4, 0x0000,
	/* 0x005a 0x0323 */
	0x1e92, 0x0000,
	/* 0x0061 0x0323 */
	0x1ea1, 0x0002,  0x0302, 0x0ec8,  0x0306, 0x0eca,
	/* 0x0062 0x0323 */
	0x1e05, 0x0000,
	/* 0x0064 0x0323 */
	0x1e0d, 0x0000,
	/* 0x0065 0x0323 */
	0x1eb9, 0x0001,  0x0302, 0x0ecc,
	/* 0x0068 0x0323 */
	0x1e25, 0x0000,
	/* 0x0069 0x0323 */
	0x1ecb, 0x0000,
	/* 0x006b 0x0323 */
	0x1e33, 0x0000,
	/* 0x006c 0x0323 */
	0x1e37, 0x0001,  0x0304, 0x0ece,
	/* 0x006d 0x0323 */
	0x1e43, 0x0000,
	/* 0x006e 0x0323 */
	0x1e47, 0x0000,
	/* 0x006f 0x0323 */
	0x1ecd, 0x0001,  0x0302, 0x0ed0,
	/* 0x0072 0x0323 */
	0x1e5b, 0x0001,  0x0304, 0x0ed2,
	/* 0x0073 0x0323 */
	0x1e63, 0x0001,  0x0307, 0x0ed4,
	/* 0x0074 0x0323 */
	0x1e6d, 0x0000,
	/* 0x0075 0x0323 */
	0x1ee5, 0x0000,
	/* 0x0076 0x0323 */
	0x1e7f, 0x0000,
	/* 0x0077 0x0323 */
	0x1e89, 0x0000,
	/* 0x0079 0x0323 */
	0x1ef5, 0x0000,
	/* 0x007a 0x0323 */
	0x1e93, 0x0000,
	/* 0x0055 0x0324 */
	0x1e72, 0x0000,
	/* 0x0075 0x0324 */
	0x1e73, 0x0000,
	/* 0x0041 0x0325 */
	0x1e00, 0x0000,
	/* 0x0061 0x0325 */
	0x1e01, 0x0000,
	/* 0x0043 0x0327 */
	0x00c7, 0x0001,  0x0301, 0x0ed6,
	/* 0x0044 0x0327 */
	0x1e10, 0x0000,
	/* 0x0045 0x0327 */
	0x0000, 0x0001,  0x0306, 0x0ed8,
	/* 0x0047 0x0327 */
	0x0122, 0x0000,
	/* 0x0048 0x0327 */
	0x1e28, 0x0000,
	/* 0x004b 0x0327 */
	0x0136, 0x0000,
	/* 0x004c 0x0327 */
	0x013b, 0x0000,
	/* 0x004e 0x0327 */
	0x0145, 0x0000,
	/* 0x0052 0x0327 */
	0x0156, 0x0000,
	/* 0x0053 0x0327 */
	0x015e, 0x0000,
	/* 0x0054 0x0327 */
	0x0162, 0x0000,
	/* 0x0063 0x0327 */
	0x00e7, 0x0001,  0x0301, 0x0eda,
	/* 0x0064 0x0327 */
	0x1e11, 0x0000,
	/* 0x0065 0x0327 */
	0x0000, 0x0001,  0x0306, 0x0edc,
	/* 0x0067 0x0327 */
	0x0123, 0x0000,
	/* 0x0068 0x0327 */
	0x1e29, 0x0000,
	/* 0x006b 0x0327 */
	0x0137, 0x0000,
	/* 0x006c 0x0327 */
	0x013c, 0x0000,
	/* 0x006e 0x0327 */
	0x0146, 0x0000,
	/* 0x0072 0x0327 */
	0x0157, 0x0000,
	/* 0x0073 0x0327 */
	0x015f, 0x0000,
	/* 0x0074 0x0327 */
	0x0163, 0x0000,
	/* 0x0041 0x0328 */
	0x0104, 0x0000,
	/* 0x0045 0x0328 */
	0x0118, 0x0000,
	/* 0x0049 0x0328 */
	0x012e, 0x0000,
	/* 0x004f 0x0328 */
	0x01ea, 0x0001,  0x0304, 0x0ede,
	/* 0x0055 0x0328 */
	0x0172, 0x0000,
	/* 0x0061 0x0328 */
	0x0105, 0x0000,
	/* 0x0065 0x0328 */
	0x0119, 0x0000,
	/* 0x0069 0x0328 */
	0x012f, 0x0000,
	/* 0x006f 0x0328 */
	0x01eb, 0x0001,  0x0304, 0x0ee0,
	/* 0x0075 0x0328 */
	0x0173, 0x0000,
	/* 0x0044 0x032d */
	0x1e12, 0x0000,
	/* 0x0045 0x032d */
	0x1e18, 0x0000,
	/* 0x004c 0x032d */
	0x1e3c, 0x0000,
	/* 0x004e 0x032d */
	0x1e4a, 0x0000,
	/* 0x0054 0x032d */
	0x1e70, 0x0000,
	/* 0x0055 0x032d */
	0x1e76, 0x0000,
	/* 0x0064 0x032d */
	0x1e13, 0x0000,
	/* 0x0065 0x032d */
	0x1e19, 0x0000,
	/* 0x006c 0x032d */
	0x1e3d, 0x0000,
	/* 0x006e 0x032d */
	0x1e4b, 0x0000,
	/* 0x0074 0x032d */
	0x1e71, 0x0000,
	/* 0x0075 0x032d */
	0x1e77, 0x0000,
	/* 0x0048 0x032e */
	0x1e2a, 0x0000,
	/* 0x0068 0x032e */
	0x1e2b, 0x0000,
	/* 0x0045 0x0330 */
	0x1e1a, 0x0000,
	/* 0x0049 0x0330 */
	0x1e2c, 0x0000,
	/* 0x0055 0x0330 */
	0x1e74, 0x0000,
	/* 0x0065 0x0330 */
	0x1e1b, 0x0000,
	/* 0x0069 0x0330 */
	0x1e2d, 0x0000,
	/* 0x0075 0x0330 */
	0x1e75, 0x0000,
	/* 0x0042 0x0331 */
	0x1e06, 0x0000,
	/* 0x0044 0x0331 */
	0x1e0e, 0x0000,
	/* 0x004b 0x0331 */
	0x1e34, 0x0000,
	/* 0x004c 0x0331 */
	0x1e3a, 0x0000,
	/* 0x004e 0x0331 */
	0x1e48, 0x0000,
	/* 0x0052 0x0331 */
	0x1e5e, 0x0000,
	/* 0x0054 0x0331 */
	0x1e6e, 0x0000,
	/* 0x005a 0x0331 */
	0x1e94, 0x0000,
	/* 0x0062 0x0331 */
	0x1e07, 0x0000,
	/* 0x0064 0x0331 */
	0x1e0f, 0x0000,
	/* 0x0068 0x0331 */
	0x1e96, 0x0000,
	/* 0x006b 0x0331 */
	0x1e35, 0x0000,
	/* 0x006c 0x0331 */
	0x1e3b, 0x0000,
	/* 0x006e 0x0331 */
	0x1e49, 0x0000,
	/* 0x0072 0x0331 */
	0x1e5f, 0x0000,
	/* 0x0074 0x0331 */
	0x1e6f, 0x0000,
	/* 0x007a 0x0331 */
	0x1e95, 0x0000,
	/* 0x00a8 0x0342 */
	0x1fc1, 0x0000,
	/* 0x03b1 0x0342 */
	0x1fb6, 0x0000,
	/* 0x03b7 0x0342 */
	0x1fc6, 0x0000,
	/* 0x03b9 0x0342 */
	0x1fd6, 0x0000,
	/* 0x03c5 0x0342 */
	0x1fe6, 0x0000,
	/* 0x03c9 0x0342 */
	0x1ff6, 0x0000,
	/* 0x1fbf 0x0342 */
	0x1fcf, 0x0000,
	/* 0x1ffe 0x0342 */
	0x1fdf, 0x0000,
	/* 0x0391 0x0345 */
	0x1fbc, 0x0002,  0x0313, 0x0ee2,  0x0314, 0x0eea,
	/* 0x0397 0x0345 */
	0x1fcc, 0x0002,  0x0313, 0x0ef2,  0x0314, 0x0efa,
	/* 0x03a9 0x0345 */
	0x1ffc, 0x0002,  0x0313, 0x0f02,  0x0314, 0x0f0a,
	/* 0x03b1 0x0345 */
	0x1fb3, 0x0005,  0x0300, 0x0f12,  0x0301, 0x0f14,  0x0313, 0x0f16,
	0x0314, 0x0f1e,  0x0342, 0x0f26,
	/* 0x03b7 0x0345 */
	0x1fc3, 0x0005,  0x0300, 0x0f28,  0x0301, 0x0f2a,  0x0313, 0x0f2c,
	0x0314, 0x0f34,  0x0342, 0x0f3c,
	/* 0x03bf 0x0345 */
	0x0000, 0x0001,  0x0301, 0x0f3e,
	/* 0x03c9 0x0345 */
	0x1ff3, 0x0004,  0x0300, 0x0f40,  0x0313, 0x0f42,  0x0314, 0x0f4a,
	0x0342, 0x0f52,
	/* 0x05d0 0x05b7 */
	0xfb2e, 0x0000,
	/* 0x05f2 0x05b7 */
	0xfb1f, 0x0000,
	/* 0x05d0 0x05b8 */
	0xfb2f, 0x0000,
	/* 0x05d5 0x05b9 */
	0xfb4b, 0x0000,
	/* 0x05d0 0x05bc */
	0xfb30, 0x0000,
	/* 0x05d1 0x05bc */
	0xfb31, 0x0000,
	/* 0x05d2 0x05bc */
	0xfb32, 0x0000,
	/* 0x05d3 0x05bc */
	0xfb33, 0x0000,
	/* 0x05d4 0x05bc */
	0xfb34, 0x0000,
	/* 0x05d5 0x05bc */
	0xfb35, 0x0000,
	/* 0x05d6 0x05bc */
	0xfb36, 0x0000,
	/* 0x05d8 0x05bc */
	0xfb38, 0x0000,
	/* 0x05d9 0x05bc */
	0xfb39, 0x0000,
	/* 0x05da 0x05bc */
	0xfb3a, 0x0000,
	/* 0x05db 0x05bc */
	0xfb3b, 0x0000,
	/* 0x05dc 0x05bc */
	0xfb3c, 0x0000,
	/* 0x05de 0x05bc */
	0xfb3e, 0x0000,
	/* 0x05e0 0x05bc */
	0xfb40, 0x0000,
	/* 0x05e1 0x05bc */
	0xfb41, 0x0000,
	/* 0x05e3 0x05bc */
	0xfb43, 0x0000,
	/* 0x05e4 0x05bc */
	0xfb44, 0x0000,
	/* 0x05e6 0x05bc */
	0xfb46, 0x0000,
	/* 0x05e7 0x05bc */
	0xfb47, 0x0000,
	/* 0x05e8 0x05bc */
	0xfb48, 0x0000,
	/* 0x05e9 0x05bc */
	0xfb49, 0x0002,  0x05c1, 0x0f54,  0x05c2, 0x0f56,
	/* 0x05ea 0x05bc */
	0xfb4a, 0x0000,
	/* 0x05d1 0x05bf */
	0xfb4c, 0x0000,
	/* 0x05db 0x05bf */
	0xfb4d, 0x0000,
	/* 0x05e4 0x05bf */
	0xfb4e, 0x0000,
	/* 0x05e9 0x05c1 */
	0xfb2a, 0x0000,
	/* 0x05e9 0x05c2 */
	0xfb2b, 0x0000,
	/* 0x0915 0x093c */
	0x0958, 0x0000,
	/* 0x0916 0x093c */
	0x0959, 0x0000,
	/* 0x0917 0x093c */
	0x095a, 0x0000,
	/* 0x091c 0x093c */
	0x095b, 0x0000,
	/* 0x0921 0x093c */
	0x095c, 0x0000,
	/* 0x0922 0x093c */
	0x095d, 0x0000,
	/* 0x0928 0x093c */
	0x0929, 0x0000,
	/* 0x092b 0x093c */
	0x095e, 0x0000,
	/* 0x092f 0x093c */
	0x095f, 0x0000,
	/* 0x0930 0x093c */
	0x0931, 0x0000,
	/* 0x0933 0x093c */
	0x0934, 0x0000,
	/* 0x09a1 0x09bc */
	0x09dc, 0x0000,
	/* 0x09a2 0x09bc */
	0x09dd, 0x0000,
	/* 0x09ac 0x09bc */
	0x09b0, 0x0000,
	/* 0x09af 0x09bc */
	0x09df, 0x0000,
	/* 0x09c7 0x09be */
	0x09cb, 0x0000,
	/* 0x09c7 0x09d7 */
	0x09cc, 0x0000,
	/* 0x0a16 0x0a3c */
	0x0a59, 0x0000,
	/* 0x0a17 0x0a3c */
	0x0a5a, 0x0000,
	/* 0x0a1c 0x0a3c */
	0x0a5b, 0x0000,
	/* 0x0a21 0x0a3c */
	0x0a5c, 0x0000,
	/* 0x0a2b 0x0a3c */
	0x0a5e, 0x0000,
	/* 0x0b21 0x0b3c */
	0x0b5c, 0x0000,
	/* 0x0b22 0x0b3c */
	0x0b5d, 0x0000,
	/* 0x0b2f 0x0b3c */
	0x0b5f, 0x0000,
	/* 0x0b47 0x0b3e */
	0x0b4b, 0x0000,
	/* 0x0b47 0x0b56 */
	0x0b48, 0x0000,
	/* 0x0b47 0x0b57 */
	0x0b4c, 0x0000,
	/* 0x0bc6 0x0bbe */
	0x0bca, 0x0000,
	/* 0x0bc7 0x0bbe */
	0x0bcb, 0x0000,
	/* 0x0b92 0x0bd7 */
	0x0b94, 0x0000,
	/* 0x0bc6 0x0bd7 */
	0x0bcc, 0x0000,
	/* 0x0c46 0x0c56 */
	0x0c48, 0x0000,
	/* 0x0cc6 0x0cc2 */
	0x0cca, 0x0001,  0x0cd5, 0x0f58,
	/* 0x0cbf 0x0cd5 */
	0x0cc0, 0x0000,
	/* 0x0cc6 0x0cd5 */
	0x0cc7, 0x0000,
	/* 0x0cc6 0x0cd6 */
	0x0cc8, 0x0000,
	/* 0x0d46 0x0d3e */
	0x0d4a, 0x0000,
	/* 0x0d47 0x0d3e */
	0x0d4b, 0x0000,
	/* 0x0d46 0x0d57 */
	0x0d4c, 0x0000,
	/* 0x0e4d 0x0e32 */
	0x0e33, 0x0000,
	/* 0x0ecd 0x0eb2 */
	0x0eb3, 0x0000,
	/* 0x0f72 0x0f71 */
	0x0f73, 0x0000,
	/* 0x0f74 0x0f71 */
	0x0f75, 0x0000,
	/* 0x0f80 0x0f71 */
	0x0f81, 0x0000,
	/* 0x0fb2 0x0f80 */
	0x0f76, 0x0001,  0x0f71, 0x0f5a,
	/* 0x0fb3 0x0f80 */
	0x0f78, 0x0001,  0x0f71, 0x0f5c,
	/* 0x0f40 0x0fb5 */
	0x0f69, 0x0000,
	/* 0x0f90 0x0fb5 */
	0x0fb9, 0x0000,
	/* 0x0f42 0x0fb7 */
	0x0f43, 0x0000,
	/* 0x0f4c 0x0fb7 */
	0x0f4d, 0x0000,
	/* 0x0f51 0x0fb7 */
	0x0f52, 0x0000,
	/* 0x0f56 0x0fb7 */
	0x0f57, 0x0000,
	/* 0x0f5b 0x0fb7 */
	0x0f5c, 0x0000,
	/* 0x0f92 0x0fb7 */
	0x0f93, 0x0000,
	/* 0x0f9c 0x0fb7 */
	0x0f9d, 0x0000,
	/* 0x0fa1 0x0fb7 */
	0x0fa2, 0x0000,
	/* 0x0fa6 0x0fb7 */
	0x0fa7, 0x0000,
	/* 0x0fab 0x0fb7 */
	0x0fac, 0x0000,
	/* 0x3046 0x3099 */
	0x3094, 0x0000,
	/* 0x304b 0x3099 */
	0x304c, 0x0000,
	/* 0x304d 0x3099 */
	0x304e, 0x0000,
	/* 0x304f 0x3099 */
	0x3050, 0x0000,
	/* 0x3051 0x3099 */
	0x3052, 0x0000,
	/* 0x3053 0x3099 */
	0x3054, 0x0000,
	/* 0x3055 0x3099 */
	0x3056, 0x0000,
	/* 0x3057 0x3099 */
	0x3058, 0x0000,
	/* 0x3059 0x3099 */
	0x305a, 0x0000,
	/* 0x305b 0x3099 */
	0x305c, 0x0000,
	/* 0x305d 0x3099 */
	0x305e, 0x0000,
	/* 0x305f 0x3099 */
	0x3060, 0x0000,
	/* 0x3061 0x3099 */
	0x3062, 0x0000,
	/* 0x3064 0x3099 */
	0x3065, 0x0000,
	/* 0x3066 0x3099 */
	0x3067, 0x0000,
	/* 0x3068 0x3099 */
	0x3069, 0x0000,
	/* 0x306f 0x3099 */
	0x3070, 0x0000,
	/* 0x3072 0x3099 */
	0x3073, 0x0000,
	/* 0x3075 0x3099 */
	0x3076, 0x0000,
	/* 0x3078 0x3099 */
	0x3079, 0x0000,
	/* 0x307b 0x3099 */
	0x307c, 0x0000,
	/* 0x309d 0x3099 */
	0x309e, 0x0000,
	/* 0x30a6 0x3099 */
	0x30f4, 0x0000,
	/* 0x30ab 0x3099 */
	0x30ac, 0x0000,
	/* 0x30ad 0x3099 */
	0x30ae, 0x0000,
	/* 0x30af 0x3099 */
	0x30b0, 0x0000,
	/* 0x30b1 0x3099 */
	0x30b2, 0x0000,
	/* 0x30b3 0x3099 */
	0x30b4, 0x0000,
	/* 0x30b5 0x3099 */
	0x30b6, 0x0000,
	/* 0x30b7 0x3099 */
	0x30b8, 0x0000,
	/* 0x30b9 0x3099 */
	0x30ba, 0x0000,
	/* 0x30bb 0x3099 */
	0x30bc, 0x0000,
	/* 0x30bd 0x3099 */
	0x30be, 0x0000,
	/* 0x30bf 0x3099 */
	0x30c0, 0x0000,
	/* 0x30c1 0x3099 */
	0x30c2, 0x0000,
	/* 0x30c4 0x3099 */
	0x30c5, 0x0000,
	/* 0x30c6 0x3099 */
	0x30c7, 0x0000,
	/* 0x30c8 0x3099 */
	0x30c9, 0x0000,
	/* 0x30cf 0x3099 */
	0x30d0, 0x0000,
	/* 0x30d2 0x3099 */
	0x30d3, 0x0000,
	/* 0x30d5 0x3099 */
	0x30d6, 0x0000,
	/* 0x30d8 0x3099 */
	0x30d9, 0x0000,
	/* 0x30db 0x3099 */
	0x30dc, 0x0000,
	/* 0x30ef 0x3099 */
	0x30f7, 0x0000,
	/* 0x30f0 0x3099 */
	0x30f8, 0x0000,
	/* 0x30f1 0x3099 */
	0x30f9, 0x0000,
	/* 0x30f2 0x3099 */
	0x30fa, 0x0000,
	/* 0x30fd 0x3099 */
	0x30fe, 0x0000,
	/* 0x306f 0x309a */
	0x3071, 0x0000,
	/* 0x3072 0x309a */
	0x3074, 0x0000,
	/* 0x3075 0x309a */
	0x3077, 0x0000,
	/* 0x3078 0x309a */
	0x307a, 0x0000,
	/* 0x307b 0x309a */
	0x307d, 0x0000,
	/* 0x30cf 0x309a */
	0x30d1, 0x0000,
	/* 0x30d2 0x309a */
	0x30d4, 0x0000,
	/* 0x30d5 0x309a */
	0x30d7, 0x0000,
	/* 0x30d8 0x309a */
	0x30da, 0x0000,
	/* 0x30db 0x309a */
	0x30dd, 0x0000,
	/* 0x0307 0x0053 0x0301 */
	0x1e64, 0x0000,
	/* 0x0307 0x0073 0x0301 */
	0x1e65, 0x0000,
	/* 0x0300 0x0041 0x0302 */
	0x1ea6, 0x0000,
	/* 0x0301 0x0041 0x0302 */
	0x1ea4, 0x0000,
	/* 0x0303 0x0041 0x0302 */
	0x1eaa, 0x0000,
	/* 0x0309 0x0041 0x0302 */
	0x1ea8, 0x0000,
	/* 0x0300 0x0045 0x0302 */
	0x1ec0, 0x0000,
	/* 0x0301 0x0045 0x0302 */
	0x1ebe, 0x0000,
	/* 0x0303 0x0045 0x0302 */
	0x1ec4, 0x0000,
	/* 0x0309 0x0045 0x0302 */
	0x1ec2, 0x0000,
	/* 0x0300 0x004f 0x0302 */
	0x1ed2, 0x0000,
	/* 0x0301 0x004f 0x0302 */
	0x1ed0, 0x0000,
	/* 0x0303 0x004f 0x0302 */
	0x1ed6, 0x0000,
	/* 0x0309 0x004f 0x0302 */
	0x1ed4, 0x0000,
	/* 0x0300 0x0061 0x0302 */
	0x1ea7, 0x0000,
	/* 0x0301 0x0061 0x0302 */
	0x1ea5, 0x0000,
	/* 0x0303 0x0061 0x0302 */
	0x1eab, 0x0000,
	/* 0x0309 0x0061 0x0302 */
	0x1ea9, 0x0000,
	/* 0x0300 0x0065 0x0302 */
	0x1ec1, 0x0000,
	/* 0x0301 0x0065 0x0302 */
	0x1ebf, 0x0000,
	/* 0x0303 0x0065 0x0302 */
	0x1ec5, 0x0000,
	/* 0x0309 0x0065 0x0302 */
	0x1ec3, 0x0000,
	/* 0x0300 0x006f 0x0302 */
	0x1ed3, 0x0000,
	/* 0x0301 0x006f 0x0302 */
	0x1ed1, 0x0000,
	/* 0x0303 0x006f 0x0302 */
	0x1ed7, 0x0000,
	/* 0x0309 0x006f 0x0302 */
	0x1ed5, 0x0000,
	/* 0x0301 0x004f 0x0303 */
	0x1e4c, 0x0000,
	/* 0x0308 0x004f 0x0303 */
	0x1e4e, 0x0000,
	/* 0x0301 0x0055 0x0303 */
	0x1e78, 0x0000,
	/* 0x0301 0x006f 0x0303 */
	0x1e4d, 0x0000,
	/* 0x0308 0x006f 0x0303 */
	0x1e4f, 0x0000,
	/* 0x0301 0x0075 0x0303 */
	0x1e79, 0x0000,
	/* 0x0300 0x0045 0x0304 */
	0x1e14, 0x0000,
	/* 0x0301 0x0045 0x0304 */
	0x1e16, 0x0000,
	/* 0x0300 0x004f 0x0304 */
	0x1e50, 0x0000,
	/* 0x0301 0x004f 0x0304 */
	0x1e52, 0x0000,
	/* 0x0308 0x0055 0x0304 */
	0x1e7a, 0x0000,
	/* 0x0300 0x0065 0x0304 */
	0x1e15, 0x0000,
	/* 0x0301 0x0065 0x0304 */
	0x1e17, 0x0000,
	/* 0x0300 0x006f 0x0304 */
	0x1e51, 0x0000,
	/* 0x0301 0x006f 0x0304 */
	0x1e53, 0x0000,
	/* 0x0308 0x0075 0x0304 */
	0x1e7b, 0x0000,
	/* 0x0300 0x0041 0x0306 */
	0x1eb0, 0x0000,
	/* 0x0301 0x0041 0x0306 */
	0x1eae, 0x0000,
	/* 0x0303 0x0041 0x0306 */
	0x1eb4, 0x0000,
	/* 0x0309 0x0041 0x0306 */
	0x1eb2, 0x0000,
	/* 0x0300 0x0061 0x0306 */
	0x1eb1, 0x0000,
	/* 0x0301 0x0061 0x0306 */
	0x1eaf, 0x0000,
	/* 0x0303 0x0061 0x0306 */
	0x1eb5, 0x0000,
	/* 0x0309 0x0061 0x0306 */
	0x1eb3, 0x0000,
	/* 0x0304 0x0041 0x0307 */
	0x01e0, 0x0000,
	/* 0x0304 0x0061 0x0307 */
	0x01e1, 0x0000,
	/* 0x0304 0x0041 0x0308 */
	0x01de, 0x0000,
	/* 0x0301 0x0049 0x0308 */
	0x1e2e, 0x0000,
	/* 0x0300 0x0055 0x0308 */
	0x01db, 0x0000,
	/* 0x0301 0x0055 0x0308 */
	0x01d7, 0x0000,
	/* 0x0304 0x0055 0x0308 */
	0x01d5, 0x0000,
	/* 0x030c 0x0055 0x0308 */
	0x01d9, 0x0000,
	/* 0x0304 0x0061 0x0308 */
	0x01df, 0x0000,
	/* 0x0301 0x0069 0x0308 */
	0x1e2f, 0x0000,
	/* 0x0300 0x0075 0x0308 */
	0x01dc, 0x0000,
	/* 0x0301 0x0075 0x0308 */
	0x01d8, 0x0000,
	/* 0x0304 0x0075 0x0308 */
	0x01d6, 0x0000,
	/* 0x030c 0x0075 0x0308 */
	0x01da, 0x0000,
	/* 0x0300 0x03b9 0x0308 */
	0x1fd2, 0x0000,
	/* 0x0301 0x03b9 0x0308 */
	0x1fd3, 0x0000,
	/* 0x030d 0x03b9 0x0308 */
	0x0390, 0x0000,
	/* 0x0342 0x03b9 0x0308 */
	0x1fd7, 0x0000,
	/* 0x0300 0x03c5 0x0308 */
	0x1fe2, 0x0000,
	/* 0x0301 0x03c5 0x0308 */
	0x1fe3, 0x0000,
	/* 0x030d 0x03c5 0x0308 */
	0x03b0, 0x0000,
	/* 0x0342 0x03c5 0x0308 */
	0x1fe7, 0x0000,
	/* 0x0301 0x0041 0x030a */
	0x01fa, 0x0000,
	/* 0x0301 0x0061 0x030a */
	0x01fb, 0x0000,
	/* 0x0307 0x0053 0x030c */
	0x1e66, 0x0000,
	/* 0x0307 0x0073 0x030c */
	0x1e67, 0x0000,
	/* 0x0300 0x0391 0x0313 */
	0x1f0a, 0x0000,
	/* 0x0301 0x0391 0x0313 */
	0x1f0c, 0x0000,
	/* 0x0342 0x0391 0x0313 */
	0x1f0e, 0x0000,
	/* 0x0300 0x0395 0x0313 */
	0x1f1a, 0x0000,
	/* 0x0301 0x0395 0x0313 */
	0x1f1c, 0x0000,
	/* 0x0300 0x0397 0x0313 */
	0x1f2a, 0x0000,
	/* 0x0301 0x0397 0x0313 */
	0x1f2c, 0x0000,
	/* 0x0342 0x0397 0x0313 */
	0x1f2e, 0x0000,
	/* 0x0300 0x0399 0x0313 */
	0x1f3a, 0x0000,
	/* 0x0301 0x0399 0x0313 */
	0x1f3c, 0x0000,
	/* 0x0342 0x0399 0x0313 */
	0x1f3e, 0x0000,
	/* 0x0300 0x039f 0x0313 */
	0x1f4a, 0x0000,
	/* 0x0301 0x039f 0x0313 */
	0x1f4c, 0x0000,
	/* 0x0300 0x03a9 0x0313 */
	0x1f6a, 0x0000,
	/* 0x0301 0x03a9 0x0313 */
	0x1f6c, 0x0000,
	/* 0x0342 0x03a9 0x0313 */
	0x1f6e, 0x0000,
	/* 0x0300 0x03b1 0x0313 */
	0x1f02, 0x0000,
	/* 0x0301 0x03b1 0x0313 */
	0x1f04, 0x0000,
	/* 0x0342 0x03b1 0x0313 */
	0x1f06, 0x0000,
	/* 0x0300 0x03b5 0x0313 */
	0x1f12, 0x0000,
	/* 0x0301 0x03b5 0x0313 */
	0x1f14, 0x0000,
	/* 0x0300 0x03b7 0x0313 */
	0x1f22, 0x0000,
	/* 0x0301 0x03b7 0x0313 */
	0x1f24, 0x0000,
	/* 0x0342 0x03b7 0x0313 */
	0x1f26, 0x0000,
	/* 0x0300 0x03b9 0x0313 */
	0x1f32, 0x0000,
	/* 0x0301 0x03b9 0x0313 */
	0x1f34, 0x0000,
	/* 0x0342 0x03b9 0x0313 */
	0x1f36, 0x0000,
	/* 0x0300 0x03bf 0x0313 */
	0x1f42, 0x0000,
	/* 0x0301 0x03bf 0x0313 */
	0x1f44, 0x0000,
	/* 0x0300 0x03c5 0x0313 */
	0x1f52, 0x0000,
	/* 0x0301 0x03c5 0x0313 */
	0x1f54, 0x0000,
	/* 0x0342 0x03c5 0x0313 */
	0x1f56, 0x0000,
	/* 0x0300 0x03c9 0x0313 */
	0x1f62, 0x0000,
	/* 0x0301 0x03c9 0x0313 */
	0x1f64, 0x0000,
	/* 0x0342 0x03c9 0x0313 */
	0x1f66, 0x0000,
	/* 0x0300 0x0391 0x0314 */
	0x1f0b, 0x0000,
	/* 0x0301 0x0391 0x0314 */
	0x1f0d, 0x0000,
	/* 0x0342 0x0391 0x0314 */
	0x1f0f, 0x0000,
	/* 0x0300 0x0395 0x0314 */
	0x1f1b, 0x0000,
	/* 0x0301 0x0395 0x0314 */
	0x1f1d, 0x0000,
	/* 0x0300 0x0397 0x0314 */
	0x1f2b, 0x0000,
	/* 0x0301 0x0397 0x0314 */
	0x1f2d, 0x0000,
	/* 0x0342 0x0397 0x0314 */
	0x1f2f, 0x0000,
	/* 0x0300 0x0399 0x0314 */
	0x1f3b, 0x0000,
	/* 0x0301 0x0399 0x0314 */
	0x1f3d, 0x0000,
	/* 0x0342 0x0399 0x0314 */
	0x1f3f, 0x0000,
	/* 0x0300 0x039f 0x0314 */
	0x1f4b, 0x0000,
	/* 0x0301 0x039f 0x0314 */
	0x1f4d, 0x0000,
	/* 0x0300 0x03a5 0x0314 */
	0x1f5b, 0x0000,
	/* 0x0301 0x03a5 0x0314 */
	0x1f5d, 0x0000,
	/* 0x0342 0x03a5 0x0314 */
	0x1f5f, 0x0000,
	/* 0x0300 0x03a9 0x0314 */
	0x1f6b, 0x0000,
	/* 0x0301 0x03a9 0x0314 */
	0x1f6d, 0x0000,
	/* 0x0342 0x03a9 0x0314 */
	0x1f6f, 0x0000,
	/* 0x0300 0x03b1 0x0314 */
	0x1f03, 0x0000,
	/* 0x0301 0x03b1 0x0314 */
	0x1f05, 0x0000,
	/* 0x0342 0x03b1 0x0314 */
	0x1f07, 0x0000,
	/* 0x0300 0x03b5 0x0314 */
	0x1f13, 0x0000,
	/* 0x0301 0x03b5 0x0314 */
	0x1f15, 0x0000,
	/* 0x0300 0x03b7 0x0314 */
	0x1f23, 0x0000,
	/* 0x0301 0x03b7 0x0314 */
	0x1f25, 0x0000,
	/* 0x0342 0x03b7 0x0314 */
	0x1f27, 0x0000,
	/* 0x0300 0x03b9 0x0314 */
	0x1f33, 0x0000,
	/* 0x0301 0x03b9 0x0314 */
	0x1f35, 0x0000,
	/* 0x0342 0x03b9 0x0314 */
	0x1f37, 0x0000,
	/* 0x0300 0x03bf 0x0314 */
	0x1f43, 0x0000,
	/* 0x0301 0x03bf 0x0314 */
	0x1f45, 0x0000,
	/* 0x0300 0x03c5 0x0314 */
	0x1f53, 0x0000,
	/* 0x0301 0x03c5 0x0314 */
	0x1f55, 0x0000,
	/* 0x0342 0x03c5 0x0314 */
	0x1f57, 0x0000,
	/* 0x0300 0x03c9 0x0314 */
	0x1f63, 0x0000,
	/* 0x0301 0x03c9 0x0314 */
	0x1f65, 0x0000,
	/* 0x0342 0x03c9 0x0314 */
	0x1f67, 0x0000,
	/* 0x0300 0x004f 0x031b */
	0x1edc, 0x0000,
	/* 0x0301 0x004f 0x031b */
	0x1eda, 0x0000,
	/* 0x0303 0x004f 0x031b */
	0x1ee0, 0x0000,
	/* 0x0309 0x004f 0x031b */
	0x1ede, 0x0000,
	/* 0x0323 0x004f 0x031b */
	0x1ee2, 0x0000,
	/* 0x0300 0x0055 0x031b */
	0x1eea, 0x0000,
	/* 0x0301 0x0055 0x031b */
	0x1ee8, 0x0000,
	/* 0x0303 0x0055 0x031b */
	0x1eee, 0x0000,
	/* 0x0309 0x0055 0x031b */
	0x1eec, 0x0000,
	/* 0x0323 0x0055 0x031b */
	0x1ef0, 0x0000,
	/* 0x0300 0x006f 0x031b */
	0x1edd, 0x0000,
	/* 0x0301 0x006f 0x031b */
	0x1edb, 0x0000,
	/* 0x0303 0x006f 0x031b */
	0x1ee1, 0x0000,
	/* 0x0309 0x006f 0x031b */
	0x1edf, 0x0000,
	/* 0x0323 0x006f 0x031b */
	0x1ee3, 0x0000,
	/* 0x0300 0x0075 0x031b */
	0x1eeb, 0x0000,
	/* 0x0301 0x0075 0x031b */
	0x1ee9, 0x0000,
	/* 0x0303 0x0075 0x031b */
	0x1eef, 0x0000,
	/* 0x0309 0x0075 0x031b */
	0x1eed, 0x0000,
	/* 0x0323 0x0075 0x031b */
	0x1ef1, 0x0000,
	/* 0x0302 0x0041 0x0323 */
	0x1eac, 0x0000,
	/* 0x0306 0x0041 0x0323 */
	0x1eb6, 0x0000,
	/* 0x0302 0x0045 0x0323 */
	0x1ec6, 0x0000,
	/* 0x0304 0x004c 0x0323 */
	0x1e38, 0x0000,
	/* 0x0302 0x004f 0x0323 */
	0x1ed8, 0x0000,
	/* 0x0304 0x0052 0x0323 */
	0x1e5c, 0x0000,
	/* 0x0307 0x0053 0x0323 */
	0x1e68, 0x0000,
	/* 0x0302 0x0061 0x0323 */
	0x1ead, 0x0000,
	/* 0x0306 0x0061 0x0323 */
	0x1eb7, 0x0000,
	/* 0x0302 0x0065 0x0323 */
	0x1ec7, 0x0000,
	/* 0x0304 0x006c 0x0323 */
	0x1e39, 0x0000,
	/* 0x0302 0x006f 0x0323 */
	0x1ed9, 0x0000,
	/* 0x0304 0x0072 0x0323 */
	0x1e5d, 0x0000,
	/* 0x0307 0x0073 0x0323 */
	0x1e69, 0x0000,
	/* 0x0301 0x0043 0x0327 */
	0x1e08, 0x0000,
	/* 0x0306 0x0045 0x0327 */
	0x1e1c, 0x0000,
	/* 0x0301 0x0063 0x0327 */
	0x1e09, 0x0000,
	/* 0x0306 0x0065 0x0327 */
	0x1e1d, 0x0000,
	/* 0x0304 0x004f 0x0328 */
	0x01ec, 0x0000,
	/* 0x0304 0x006f 0x0328 */
	0x01ed, 0x0000,
	/* 0x0313 0x0391 0x0345 */
	0x1f88, 0x0003,  0x0300, 0x0f5e,  0x0301, 0x0f60,  0x0342, 0x0f62,
	/* 0x0314 0x0391 0x0345 */
	0x1f89, 0x0003,  0x0300, 0x0f64,  0x0301, 0x0f66,  0x0342, 0x0f68,
	/* 0x0313 0x0397 0x0345 */
	0x1f98, 0x0003,  0x0300, 0x0f6a,  0x0301, 0x0f6c,  0x0342, 0x0f6e,
	/* 0x0314 0x0397 0x0345 */
	0x1f99, 0x0003,  0x0300, 0x0f70,  0x0301, 0x0f72,  0x0342, 0x0f74,
	/* 0x0313 0x03a9 0x0345 */
	0x1fa8, 0x0003,  0x0300, 0x0f76,  0x0301, 0x0f78,  0x0342, 0x0f7a,
	/* 0x0314 0x03a9 0x0345 */
	0x1fa9, 0x0003,  0x0300, 0x0f7c,  0x0301, 0x0f7e,  0x0342, 0x0f80,
	/* 0x0300 0x03b1 0x0345 */
	0x1fb2, 0x0000,
	/* 0x0301 0x03b1 0x0345 */
	0x1fb4, 0x0000,
	/* 0x0313 0x03b1 0x0345 */
	0x1f80, 0x0003,  0x0300, 0x0f82,  0x0301, 0x0f84,  0x0342, 0x0f86,
	/* 0x0314 0x03b1 0x0345 */
	0x1f81, 0x0003,  0x0300, 0x0f88,  0x0301, 0x0f8a,  0x0342, 0x0f8c,
	/* 0x0342 0x03b1 0x0345 */
	0x1fb7, 0x0000,
	/* 0x0300 0x03b7 0x0345 */
	0x1fc2, 0x0000,
	/* 0x0301 0x03b7 0x0345 */
	0x1fc4, 0x0000,
	/* 0x0313 0x03b7 0x0345 */
	0x1f90, 0x0003,  0x0300, 0x0f8e,  0x0301, 0x0f90,  0x0342, 0x0f92,
	/* 0x0314 0x03b7 0x0345 */
	0x1f91, 0x0003,  0x0300, 0x0f94,  0x0301, 0x0f96,  0x0342, 0x0f98,
	/* 0x0342 0x03b7 0x0345 */
	0x1fc7, 0x0000,
	/* 0x0301 0x03bf 0x0345 */
	0x1ff4, 0x0000,
	/* 0x0300 0x03c9 0x0345 */
	0x1ff2, 0x0000,
	/* 0x0313 0x03c9 0x0345 */
	0x1fa0, 0x0003,  0x0300, 0x0f9a,  0x0301, 0x0f9c,  0x0342, 0x0f9e,
	/* 0x0314 0x03c9 0x0345 */
	0x1fa1, 0x0003,  0x0300, 0x0fa0,  0x0301, 0x0fa2,  0x0342, 0x0fa4,
	/* 0x0342 0x03c9 0x0345 */
	0x1ff7, 0x0000,
	/* 0x05c1 0x05e9 0x05bc */
	0xfb2c, 0x0000,
	/* 0x05c2 0x05e9 0x05bc */
	0xfb2d, 0x0000,
	/* 0x0cd5 0x0cc6 0x0cc2 */
	0x0ccb, 0x0000,
	/* 0x0f71 0x0fb2 0x0f80 */
	0x0f77, 0x0000,
	/* 0x0f71 0x0fb3 0x0f80 */
	0x0f79, 0x0000,
	/* 0x0300 0x0313 0x0391 0x0345 */
	0x1f8a, 0x0000,
	/* 0x0301 0x0313 0x0391 0x0345 */
	0x1f8c, 0x0000,
	/* 0x0342 0x0313 0x0391 0x0345 */
	0x1f8e, 0x0000,
	/* 0x0300 0x0314 0x0391 0x0345 */
	0x1f8b, 0x0000,
	/* 0x0301 0x0314 0x0391 0x0345 */
	0x1f8d, 0x0000,
	/* 0x0342 0x0314 0x0391 0x0345 */
	0x1f8f, 0x0000,
	/* 0x0300 0x0313 0x0397 0x0345 */
	0x1f9a, 0x0000,
	/* 0x0301 0x0313 0x0397 0x0345 */
	0x1f9c, 0x0000,
	/* 0x0342 0x0313 0x0397 0x0345 */
	0x1f9e, 0x0000,
	/* 0x0300 0x0314 0x0397 0x0345 */
	0x1f9b, 0x0000,
	/* 0x0301 0x0314 0x0397 0x0345 */
	0x1f9d, 0x0000,
	/* 0x0342 0x0314 0x0397 0x0345 */
	0x1f9f, 0x0000,
	/* 0x0300 0x0313 0x03a9 0x0345 */
	0x1faa, 0x0000,
	/* 0x0301 0x0313 0x03a9 0x0345 */
	0x1fac, 0x0000,
	/* 0x0342 0x0313 0x03a9 0x0345 */
	0x1fae, 0x0000,
	/* 0x0300 0x0314 0x03a9 0x0345 */
	0x1fab, 0x0000,
	/* 0x0301 0x0314 0x03a9 0x0345 */
	0x1fad, 0x0000,
	/* 0x0342 0x0314 0x03a9 0x0345 */
	0x1faf, 0x0000,
	/* 0x0300 0x0313 0x03b1 0x0345 */
	0x1f82, 0x0000,
	/* 0x0301 0x0313 0x03b1 0x0345 */
	0x1f84, 0x0000,
	/* 0x0342 0x0313 0x03b1 0x0345 */
	0x1f86, 0x0000,
	/* 0x0300 0x0314 0x03b1 0x0345 */
	0x1f83, 0x0000,
	/* 0x0301 0x0314 0x03b1 0x0345 */
	0x1f85, 0x0000,
	/* 0x0342 0x0314 0x03b1 0x0345 */
	0x1f87, 0x0000,
	/* 0x0300 0x0313 0x03b7 0x0345 */
	0x1f92, 0x0000,
	/* 0x0301 0x0313 0x03b7 0x0345 */
	0x1f94, 0x0000,
	/* 0x0342 0x0313 0x03b7 0x0345 */
	0x1f96, 0x0000,
	/* 0x0300 0x0314 0x03b7 0x0345 */
	0x1f93, 0x0000,
	/* 0x0301 0x0314 0x03b7 0x0345 */
	0x1f95, 0x0000,
	/* 0x0342 0x0314 0x03b7 0x0345 */
	0x1f97, 0x0000,
	/* 0x0300 0x0313 0x03c9 0x0345 */
	0x1fa2, 0x0000,
	/* 0x0301 0x0313 0x03c9 0x0345 */
	0x1fa4, 0x0000,
	/* 0x0342 0x0313 0x03c9 0x0345 */
	0x1fa6, 0x0000,
	/* 0x0300 0x0314 0x03c9 0x0345 */
	0x1fa3, 0x0000,
	/* 0x0301 0x0314 0x03c9 0x0345 */
	0x1fa5, 0x0000,
	/* 0x0342 0x0314 0x03c9 0x0345 */
	0x1fa7, 0x0000,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/tables.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/unicode.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handler routines for unicode strings
 */

#include <linux/types.h>
// #include <linux/nls.h>
// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"
#include "../../inc/__fss.h"

/* Fold the case of a unicode char, given the 16 bit value */
/* Returns folded char, or 0 if ignorable */
static inline u16 case_fold(u16 c)
{
	u16 tmp;

	tmp = hfsplus_case_fold_table[c >> 8];
	if (tmp)
		tmp = hfsplus_case_fold_table[tmp + (c & 0xff)];
	else
		tmp = c;
	return tmp;
}

/* Compare unicode strings, return values like normal strcmp */
int hfsplus_strcasecmp(const struct hfsplus_unistr *s1,
		       const struct hfsplus_unistr *s2)
{
	u16 len1, len2, c1, c2;
	const hfsplus_unichr *p1, *p2;

	len1 = be16_to_cpu(s1->length);
	len2 = be16_to_cpu(s2->length);
	p1 = s1->unicode;
	p2 = s2->unicode;

	while (1) {
		c1 = c2 = 0;

		while (len1 && !c1) {
			c1 = case_fold(be16_to_cpu(*p1));
			p1++;
			len1--;
		}
		while (len2 && !c2) {
			c2 = case_fold(be16_to_cpu(*p2));
			p2++;
			len2--;
		}

		if (c1 != c2)
			return (c1 < c2) ? -1 : 1;
		if (!c1 && !c2)
			return 0;
	}
}

/* Compare names as a sequence of 16-bit unsigned integers */
int hfsplus_strcmp(const struct hfsplus_unistr *s1,
		   const struct hfsplus_unistr *s2)
{
	u16 len1, len2, c1, c2;
	const hfsplus_unichr *p1, *p2;
	int len;

	len1 = be16_to_cpu(s1->length);
	len2 = be16_to_cpu(s2->length);
	p1 = s1->unicode;
	p2 = s2->unicode;

	for (len = min(len1, len2); len > 0; len--) {
		c1 = be16_to_cpu(*p1);
		c2 = be16_to_cpu(*p2);
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		p1++;
		p2++;
	}

	return len1 < len2 ? -1 :
	       len1 > len2 ? 1 : 0;
}


#define Hangul_SBase	0xac00
#define Hangul_LBase	0x1100
#define Hangul_VBase	0x1161
#define Hangul_TBase	0x11a7
#define Hangul_SCount	11172
#define Hangul_LCount	19
#define Hangul_VCount	21
#define Hangul_TCount	28
#define Hangul_NCount	(Hangul_VCount * Hangul_TCount)


static u16 *hfsplus_compose_lookup(u16 *p, u16 cc)
{
	int i, s, e;

	s = 1;
	e = p[1];
	if (!e || cc < p[s * 2] || cc > p[e * 2])
		return NULL;
	do {
		i = (s + e) / 2;
		if (cc > p[i * 2])
			s = i + 1;
		else if (cc < p[i * 2])
			e = i - 1;
		else
			return hfsplus_compose_table + p[i * 2 + 1];
	} while (s <= e);
	return NULL;
}

int hfsplus_uni2asc(struct super_block *sb,
		const struct hfsplus_unistr *ustr,
		char *astr, int *len_p)
{
	const hfsplus_unichr *ip;
	struct nls_table *nls = HFSPLUS_SB(sb)->nls;
	u8 *op;
	u16 cc, c0, c1;
	u16 *ce1, *ce2;
	int i, len, ustrlen, res, compose;

	op = astr;
	ip = ustr->unicode;
	ustrlen = be16_to_cpu(ustr->length);
	len = *len_p;
	ce1 = NULL;
	compose = !test_bit(HFSPLUS_SB_NODECOMPOSE, &HFSPLUS_SB(sb)->flags);

	while (ustrlen > 0) {
		c0 = be16_to_cpu(*ip++);
		ustrlen--;
		/* search for single decomposed char */
		if (likely(compose))
			ce1 = hfsplus_compose_lookup(hfsplus_compose_table, c0);
		if (ce1)
			cc = ce1[0];
		else
			cc = 0;
		if (cc) {
			/* start of a possibly decomposed Hangul char */
			if (cc != 0xffff)
				goto done;
			if (!ustrlen)
				goto same;
			c1 = be16_to_cpu(*ip) - Hangul_VBase;
			if (c1 < Hangul_VCount) {
				/* compose the Hangul char */
				cc = (c0 - Hangul_LBase) * Hangul_VCount;
				cc = (cc + c1) * Hangul_TCount;
				cc += Hangul_SBase;
				ip++;
				ustrlen--;
				if (!ustrlen)
					goto done;
				c1 = be16_to_cpu(*ip) - Hangul_TBase;
				if (c1 > 0 && c1 < Hangul_TCount) {
					cc += c1;
					ip++;
					ustrlen--;
				}
				goto done;
			}
		}
		while (1) {
			/* main loop for common case of not composed chars */
			if (!ustrlen)
				goto same;
			c1 = be16_to_cpu(*ip);
			if (likely(compose))
				ce1 = hfsplus_compose_lookup(
					hfsplus_compose_table, c1);
			if (ce1)
				break;
			switch (c0) {
			case 0:
				c0 = 0x2400;
				break;
			case '/':
				c0 = ':';
				break;
			}
			res = nls->uni2char(c0, op, len);
			if (res < 0) {
				if (res == -ENAMETOOLONG)
					goto out;
				*op = '?';
				res = 1;
			}
			op += res;
			len -= res;
			c0 = c1;
			ip++;
			ustrlen--;
		}
		ce2 = hfsplus_compose_lookup(ce1, c0);
		if (ce2) {
			i = 1;
			while (i < ustrlen) {
				ce1 = hfsplus_compose_lookup(ce2,
					be16_to_cpu(ip[i]));
				if (!ce1)
					break;
				i++;
				ce2 = ce1;
			}
			cc = ce2[0];
			if (cc) {
				ip += i;
				ustrlen -= i;
				goto done;
			}
		}
same:
		switch (c0) {
		case 0:
			cc = 0x2400;
			break;
		case '/':
			cc = ':';
			break;
		default:
			cc = c0;
		}
done:
		res = nls->uni2char(cc, op, len);
		if (res < 0) {
			if (res == -ENAMETOOLONG)
				goto out;
			*op = '?';
			res = 1;
		}
		op += res;
		len -= res;
	}
	res = 0;
out:
	*len_p = (char *)op - astr;
	return res;
}

/*
 * Convert one or more ASCII characters into a single unicode character.
 * Returns the number of ASCII characters corresponding to the unicode char.
 */
static inline int asc2unichar(struct super_block *sb, const char *astr, int len,
			      wchar_t *uc)
{
	int size = HFSPLUS_SB(sb)->nls->char2uni(astr, len, uc);
	if (size <= 0) {
		*uc = '?';
		size = 1;
	}
	switch (*uc) {
	case 0x2400:
		*uc = 0;
		break;
	case ':':
		*uc = '/';
		break;
	}
	return size;
}

/* Decomposes a single unicode character. */
static inline u16 *decompose_unichar(wchar_t uc, int *size)
{
	int off;

	off = hfsplus_decompose_table[(uc >> 12) & 0xf];
	if (off == 0 || off == 0xffff)
		return NULL;

	off = hfsplus_decompose_table[off + ((uc >> 8) & 0xf)];
	if (!off)
		return NULL;

	off = hfsplus_decompose_table[off + ((uc >> 4) & 0xf)];
	if (!off)
		return NULL;

	off = hfsplus_decompose_table[off + (uc & 0xf)];
	*size = off & 3;
	if (*size == 0)
		return NULL;
	return hfsplus_decompose_table + (off / 4);
}

int hfsplus_asc2uni(struct super_block *sb,
		    struct hfsplus_unistr *ustr, int max_unistr_len,
		    const char *astr, int len)
{
	int size, dsize, decompose;
	u16 *dstr, outlen = 0;
	wchar_t c;

	decompose = !test_bit(HFSPLUS_SB_NODECOMPOSE, &HFSPLUS_SB(sb)->flags);
	while (outlen < max_unistr_len && len > 0) {
		size = asc2unichar(sb, astr, len, &c);

		if (decompose)
			dstr = decompose_unichar(c, &dsize);
		else
			dstr = NULL;
		if (dstr) {
			if (outlen + dsize > max_unistr_len)
				break;
			do {
				ustr->unicode[outlen++] = cpu_to_be16(*dstr++);
			} while (--dsize > 0);
		} else
			ustr->unicode[outlen++] = cpu_to_be16(c);

		astr += size;
		len -= size;
	}
	ustr->length = cpu_to_be16(outlen);
	if (len > 0)
		return -ENAMETOOLONG;
	return 0;
}

/*
 * Hash a string to an integer as appropriate for the HFS+ filesystem.
 * Composed unicode characters are decomposed and case-folding is performed
 * if the appropriate bits are (un)set on the superblock.
 */
int hfsplus_hash_dentry(const struct dentry *dentry, struct qstr *str)
{
	struct super_block *sb = dentry->d_sb;
	const char *astr;
	const u16 *dstr;
	int casefold, decompose, size, len;
	unsigned long hash;
	wchar_t c;
	u16 c2;

	casefold = test_bit(HFSPLUS_SB_CASEFOLD, &HFSPLUS_SB(sb)->flags);
	decompose = !test_bit(HFSPLUS_SB_NODECOMPOSE, &HFSPLUS_SB(sb)->flags);
	hash = init_name_hash();
	astr = str->name;
	len = str->len;
	while (len > 0) {
		int uninitialized_var(dsize);
		size = asc2unichar(sb, astr, len, &c);
		astr += size;
		len -= size;

		if (decompose)
			dstr = decompose_unichar(c, &dsize);
		else
			dstr = NULL;
		if (dstr) {
			do {
				c2 = *dstr++;
				if (casefold)
					c2 = case_fold(c2);
				if (!casefold || c2)
					hash = partial_name_hash(c2, hash);
			} while (--dsize > 0);
		} else {
			c2 = c;
			if (casefold)
				c2 = case_fold(c2);
			if (!casefold || c2)
				hash = partial_name_hash(c2, hash);
		}
	}
	str->hash = end_name_hash(hash);

	return 0;
}

/*
 * Compare strings with HFS+ filename ordering.
 * Composed unicode characters are decomposed and case-folding is performed
 * if the appropriate bits are (un)set on the superblock.
 */
int hfsplus_compare_dentry(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	struct super_block *sb = parent->d_sb;
	int casefold, decompose, size;
	int dsize1, dsize2, len1, len2;
	const u16 *dstr1, *dstr2;
	const char *astr1, *astr2;
	u16 c1, c2;
	wchar_t c;

	casefold = test_bit(HFSPLUS_SB_CASEFOLD, &HFSPLUS_SB(sb)->flags);
	decompose = !test_bit(HFSPLUS_SB_NODECOMPOSE, &HFSPLUS_SB(sb)->flags);
	astr1 = str;
	len1 = len;
	astr2 = name->name;
	len2 = name->len;
	dsize1 = dsize2 = 0;
	dstr1 = dstr2 = NULL;

	while (len1 > 0 && len2 > 0) {
		if (!dsize1) {
			size = asc2unichar(sb, astr1, len1, &c);
			astr1 += size;
			len1 -= size;

			if (decompose)
				dstr1 = decompose_unichar(c, &dsize1);
			if (!decompose || !dstr1) {
				c1 = c;
				dstr1 = &c1;
				dsize1 = 1;
			}
		}

		if (!dsize2) {
			size = asc2unichar(sb, astr2, len2, &c);
			astr2 += size;
			len2 -= size;

			if (decompose)
				dstr2 = decompose_unichar(c, &dsize2);
			if (!decompose || !dstr2) {
				c2 = c;
				dstr2 = &c2;
				dsize2 = 1;
			}
		}

		c1 = *dstr1;
		c2 = *dstr2;
		if (casefold) {
			c1 = case_fold(c1);
			if (!c1) {
				dstr1++;
				dsize1--;
				continue;
			}
			c2 = case_fold(c2);
			if (!c2) {
				dstr2++;
				dsize2--;
				continue;
			}
		}
		if (c1 < c2)
			return -1;
		else if (c1 > c2)
			return 1;

		dstr1++;
		dsize1--;
		dstr2++;
		dsize2--;
	}

	if (len1 < len2)
		return -1;
	if (len1 > len2)
		return 1;
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/unicode.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/wrapper.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handling of HFS wrappers around HFS+ volumes
 */

// #include <linux/fs.h>
// #include <linux/blkdev.h>
#include <linux/cdrom.h>
#include <linux/genhd.h>
#include <asm/unaligned.h>
#include "../../inc/__fss.h"

// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"

struct hfsplus_wd {
	u32 ablk_size;
	u16 ablk_start;
	u16 embed_start;
	u16 embed_count;
};

/**
 * hfsplus_submit_bio - Perform block I/O
 * @sb: super block of volume for I/O
 * @sector: block to read or write, for blocks of HFSPLUS_SECTOR_SIZE bytes
 * @buf: buffer for I/O
 * @data: output pointer for location of requested data
 * @rw: direction of I/O
 *
 * The unit of I/O is hfsplus_min_io_size(sb), which may be bigger than
 * HFSPLUS_SECTOR_SIZE, and @buf must be sized accordingly. On reads
 * @data will return a pointer to the start of the requested sector,
 * which may not be the same location as @buf.
 *
 * If @sector is not aligned to the bdev logical block size it will
 * be rounded down. For writes this means that @buf should contain data
 * that starts at the rounded-down address. As long as the data was
 * read using hfsplus_submit_bio() and the same buffer is used things
 * will work correctly.
 */
int hfsplus_submit_bio(struct super_block *sb, sector_t sector,
		void *buf, void **data, int rw)
{
	struct bio *bio;
	int ret = 0;
	u64 io_size;
	loff_t start;
	int offset;

	/*
	 * Align sector to hardware sector size and find offset. We
	 * assume that io_size is a power of two, which _should_
	 * be true.
	 */
	io_size = hfsplus_min_io_size(sb);
	start = (loff_t)sector << HFSPLUS_SECTOR_SHIFT;
	offset = start & (io_size - 1);
	sector &= ~((io_size >> HFSPLUS_SECTOR_SHIFT) - 1);

	bio = bio_alloc(GFP_NOIO, 1);
	bio->bi_iter.bi_sector = sector;
	bio->bi_bdev = sb->s_bdev;

	if (!(rw & WRITE) && data)
		*data = (u8 *)buf + offset;

	while (io_size > 0) {
		unsigned int page_offset = offset_in_page(buf);
		unsigned int len = min_t(unsigned int, PAGE_SIZE - page_offset,
					 io_size);

		ret = bio_add_page(bio, virt_to_page(buf), len, page_offset);
		if (ret != len) {
			ret = -EIO;
			goto out;
		}
		io_size -= len;
		buf = (u8 *)buf + len;
	}

	ret = submit_bio_wait(rw, bio);
out:
	bio_put(bio);
	return ret < 0 ? ret : 0;
}

static int hfsplus_read_mdb(void *bufptr, struct hfsplus_wd *wd)
{
	u32 extent;
	u16 attrib;
	__be16 sig;

	sig = *(__be16 *)(bufptr + HFSP_WRAPOFF_EMBEDSIG);
	if (sig != cpu_to_be16(HFSPLUS_VOLHEAD_SIG) &&
	    sig != cpu_to_be16(HFSPLUS_VOLHEAD_SIGX))
		return 0;

	attrib = be16_to_cpu(*(__be16 *)(bufptr + HFSP_WRAPOFF_ATTRIB));
	if (!(attrib & HFSP_WRAP_ATTRIB_SLOCK) ||
	   !(attrib & HFSP_WRAP_ATTRIB_SPARED))
		return 0;

	wd->ablk_size =
		be32_to_cpu(*(__be32 *)(bufptr + HFSP_WRAPOFF_ABLKSIZE));
	if (wd->ablk_size < HFSPLUS_SECTOR_SIZE)
		return 0;
	if (wd->ablk_size % HFSPLUS_SECTOR_SIZE)
		return 0;
	wd->ablk_start =
		be16_to_cpu(*(__be16 *)(bufptr + HFSP_WRAPOFF_ABLKSTART));

	extent = get_unaligned_be32(bufptr + HFSP_WRAPOFF_EMBEDEXT);
	wd->embed_start = (extent >> 16) & 0xFFFF;
	wd->embed_count = extent & 0xFFFF;

	return 1;
}

static int hfsplus_get_last_session(struct super_block *sb,
				    sector_t *start, sector_t *size)
{
	struct cdrom_multisession ms_info;
	struct cdrom_tocentry te;
	int res;

	/* default values */
	*start = 0;
	*size = sb->s_bdev->bd_inode->i_size >> 9;

	if (HFSPLUS_SB(sb)->session >= 0) {
		te.cdte_track = HFSPLUS_SB(sb)->session;
		te.cdte_format = CDROM_LBA;
		res = ioctl_by_bdev(sb->s_bdev,
			CDROMREADTOCENTRY, (unsigned long)&te);
		if (!res && (te.cdte_ctrl & CDROM_DATA_TRACK) == 4) {
			*start = (sector_t)te.cdte_addr.lba << 2;
			return 0;
		}
		pr_err("invalid session number or type of track\n");
		return -EINVAL;
	}
	ms_info.addr_format = CDROM_LBA;
	res = ioctl_by_bdev(sb->s_bdev, CDROMMULTISESSION,
		(unsigned long)&ms_info);
	if (!res && ms_info.xa_flag)
		*start = (sector_t)ms_info.addr.lba << 2;
	return 0;
}

/* Find the volume header and fill in some minimum bits in superblock */
/* Takes in super block, returns true if good data read */
int hfsplus_read_wrapper(struct super_block *sb)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct hfsplus_wd wd;
	sector_t part_start, part_size;
	u32 blocksize;
	int error = 0;

	error = -EINVAL;
	blocksize = sb_min_blocksize(sb, HFSPLUS_SECTOR_SIZE);
	if (!blocksize)
		goto out;

	if (hfsplus_get_last_session(sb, &part_start, &part_size))
		goto out;

	error = -ENOMEM;
	sbi->s_vhdr_buf = kmalloc(hfsplus_min_io_size(sb), GFP_KERNEL);
	if (!sbi->s_vhdr_buf)
		goto out;
	sbi->s_backup_vhdr_buf = kmalloc(hfsplus_min_io_size(sb), GFP_KERNEL);
	if (!sbi->s_backup_vhdr_buf)
		goto out_free_vhdr;

reread:
	error = hfsplus_submit_bio(sb, part_start + HFSPLUS_VOLHEAD_SECTOR,
				   sbi->s_vhdr_buf, (void **)&sbi->s_vhdr,
				   READ);
	if (error)
		goto out_free_backup_vhdr;

	error = -EINVAL;
	switch (sbi->s_vhdr->signature) {
	case cpu_to_be16(HFSPLUS_VOLHEAD_SIGX):
		set_bit(HFSPLUS_SB_HFSX, &sbi->flags);
		/*FALLTHRU*/
	case cpu_to_be16(HFSPLUS_VOLHEAD_SIG):
		break;
	case cpu_to_be16(HFSP_WRAP_MAGIC):
		if (!hfsplus_read_mdb(sbi->s_vhdr, &wd))
			goto out_free_backup_vhdr;
		wd.ablk_size >>= HFSPLUS_SECTOR_SHIFT;
		part_start += (sector_t)wd.ablk_start +
			       (sector_t)wd.embed_start * wd.ablk_size;
		part_size = (sector_t)wd.embed_count * wd.ablk_size;
		goto reread;
	default:
		/*
		 * Check for a partition block.
		 *
		 * (should do this only for cdrom/loop though)
		 */
		if (hfs_part_find(sb, &part_start, &part_size))
			goto out_free_backup_vhdr;
		goto reread;
	}

	error = hfsplus_submit_bio(sb, part_start + part_size - 2,
				   sbi->s_backup_vhdr_buf,
				   (void **)&sbi->s_backup_vhdr, READ);
	if (error)
		goto out_free_backup_vhdr;

	error = -EINVAL;
	if (sbi->s_backup_vhdr->signature != sbi->s_vhdr->signature) {
		pr_warn("invalid secondary volume header\n");
		goto out_free_backup_vhdr;
	}

	blocksize = be32_to_cpu(sbi->s_vhdr->blocksize);

	/*
	 * Block size must be at least as large as a sector and a multiple of 2.
	 */
	if (blocksize < HFSPLUS_SECTOR_SIZE || ((blocksize - 1) & blocksize))
		goto out_free_backup_vhdr;
	sbi->alloc_blksz = blocksize;
	sbi->alloc_blksz_shift = ilog2(blocksize);
	blocksize = min_t(u32, sbi->alloc_blksz, PAGE_SIZE);

	/*
	 * Align block size to block offset.
	 */
	while (part_start & ((blocksize >> HFSPLUS_SECTOR_SHIFT) - 1))
		blocksize >>= 1;

	if (sb_set_blocksize(sb, blocksize) != blocksize) {
		pr_err("unable to set blocksize to %u!\n", blocksize);
		goto out_free_backup_vhdr;
	}

	sbi->blockoffset =
		part_start >> (sb->s_blocksize_bits - HFSPLUS_SECTOR_SHIFT);
	sbi->part_start = part_start;
	sbi->sect_count = part_size;
	sbi->fs_shift = sbi->alloc_blksz_shift - sb->s_blocksize_bits;
	return 0;

out_free_backup_vhdr:
	kfree(sbi->s_backup_vhdr_buf);
out_free_vhdr:
	kfree(sbi->s_vhdr_buf);
out:
	return error;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/wrapper.c */
/************************************************************/
/*
 *  linux/fs/hfsplus/bitmap.c
 *
 * Copyright (C) 2001
 * Brad Boyer (flar@allandria.com)
 * (C) 2003 Ardis Technologies <roman@ardistech.com>
 *
 * Handling of allocation file
 */

// #include <linux/pagemap.h>

// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"

#define PAGE_CACHE_BITS	(PAGE_CACHE_SIZE * 8)

int hfsplus_block_allocate(struct super_block *sb, u32 size,
		u32 offset, u32 *max)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct page *page;
	struct address_space *mapping;
	__be32 *pptr, *curr, *end;
	u32 mask, start, len, n;
	__be32 val;
	int i;

	len = *max;
	if (!len)
		return size;

	hfs_dbg(BITMAP, "block_allocate: %u,%u,%u\n", size, offset, len);
	mutex_lock(&sbi->alloc_mutex);
	mapping = sbi->alloc_file->i_mapping;
	page = read_mapping_page(mapping, offset / PAGE_CACHE_BITS, NULL);
	if (IS_ERR(page)) {
		start = size;
		goto out;
	}
	pptr = kmap(page);
	curr = pptr + (offset & (PAGE_CACHE_BITS - 1)) / 32;
	i = offset % 32;
	offset &= ~(PAGE_CACHE_BITS - 1);
	if ((size ^ offset) / PAGE_CACHE_BITS)
		end = pptr + PAGE_CACHE_BITS / 32;
	else
		end = pptr + ((size + 31) & (PAGE_CACHE_BITS - 1)) / 32;

	/* scan the first partial u32 for zero bits */
	val = *curr;
	if (~val) {
		n = be32_to_cpu(val);
		mask = (1U << 31) >> i;
		for (; i < 32; mask >>= 1, i++) {
			if (!(n & mask))
				goto found;
		}
	}
	curr++;

	/* scan complete u32s for the first zero bit */
	while (1) {
		while (curr < end) {
			val = *curr;
			if (~val) {
				n = be32_to_cpu(val);
				mask = 1 << 31;
				for (i = 0; i < 32; mask >>= 1, i++) {
					if (!(n & mask))
						goto found;
				}
			}
			curr++;
		}
		kunmap(page);
		offset += PAGE_CACHE_BITS;
		if (offset >= size)
			break;
		page = read_mapping_page(mapping, offset / PAGE_CACHE_BITS,
					 NULL);
		if (IS_ERR(page)) {
			start = size;
			goto out;
		}
		curr = pptr = kmap(page);
		if ((size ^ offset) / PAGE_CACHE_BITS)
			end = pptr + PAGE_CACHE_BITS / 32;
		else
			end = pptr + ((size + 31) & (PAGE_CACHE_BITS - 1)) / 32;
	}
	hfs_dbg(BITMAP, "bitmap full\n");
	start = size;
	goto out;

found:
	start = offset + (curr - pptr) * 32 + i;
	if (start >= size) {
		hfs_dbg(BITMAP, "bitmap full\n");
		goto out;
	}
	/* do any partial u32 at the start */
	len = min(size - start, len);
	while (1) {
		n |= mask;
		if (++i >= 32)
			break;
		mask >>= 1;
		if (!--len || n & mask)
			goto done;
	}
	if (!--len)
		goto done;
	*curr++ = cpu_to_be32(n);
	/* do full u32s */
	while (1) {
		while (curr < end) {
			n = be32_to_cpu(*curr);
			if (len < 32)
				goto last;
			if (n) {
				len = 32;
				goto last;
			}
			*curr++ = cpu_to_be32(0xffffffff);
			len -= 32;
		}
		set_page_dirty(page);
		kunmap(page);
		offset += PAGE_CACHE_BITS;
		page = read_mapping_page(mapping, offset / PAGE_CACHE_BITS,
					 NULL);
		if (IS_ERR(page)) {
			start = size;
			goto out;
		}
		pptr = kmap(page);
		curr = pptr;
		end = pptr + PAGE_CACHE_BITS / 32;
	}
last:
	/* do any partial u32 at end */
	mask = 1U << 31;
	for (i = 0; i < len; i++) {
		if (n & mask)
			break;
		n |= mask;
		mask >>= 1;
	}
done:
	*curr = cpu_to_be32(n);
	set_page_dirty(page);
	kunmap(page);
	*max = offset + (curr - pptr) * 32 + i - start;
	sbi->free_blocks -= *max;
	hfsplus_mark_mdb_dirty(sb);
	hfs_dbg(BITMAP, "-> %u,%u\n", start, *max);
out:
	mutex_unlock(&sbi->alloc_mutex);
	return start;
}

int hfsplus_block_free(struct super_block *sb, u32 offset, u32 count)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct page *page;
	struct address_space *mapping;
	__be32 *pptr, *curr, *end;
	u32 mask, len, pnr;
	int i;

	/* is there any actual work to be done? */
	if (!count)
		return 0;

	hfs_dbg(BITMAP, "block_free: %u,%u\n", offset, count);
	/* are all of the bits in range? */
	if ((offset + count) > sbi->total_blocks)
		return -ENOENT;

	mutex_lock(&sbi->alloc_mutex);
	mapping = sbi->alloc_file->i_mapping;
	pnr = offset / PAGE_CACHE_BITS;
	page = read_mapping_page(mapping, pnr, NULL);
	if (IS_ERR(page))
		goto kaboom;
	pptr = kmap(page);
	curr = pptr + (offset & (PAGE_CACHE_BITS - 1)) / 32;
	end = pptr + PAGE_CACHE_BITS / 32;
	len = count;

	/* do any partial u32 at the start */
	i = offset % 32;
	if (i) {
		int j = 32 - i;
		mask = 0xffffffffU << j;
		if (j > count) {
			mask |= 0xffffffffU >> (i + count);
			*curr++ &= cpu_to_be32(mask);
			goto out;
		}
		*curr++ &= cpu_to_be32(mask);
		count -= j;
	}

	/* do full u32s */
	while (1) {
		while (curr < end) {
			if (count < 32)
				goto done;
			*curr++ = 0;
			count -= 32;
		}
		if (!count)
			break;
		set_page_dirty(page);
		kunmap(page);
		page = read_mapping_page(mapping, ++pnr, NULL);
		if (IS_ERR(page))
			goto kaboom;
		pptr = kmap(page);
		curr = pptr;
		end = pptr + PAGE_CACHE_BITS / 32;
	}
done:
	/* do any partial u32 at end */
	if (count) {
		mask = 0xffffffffU >> count;
		*curr &= cpu_to_be32(mask);
	}
out:
	set_page_dirty(page);
	kunmap(page);
	sbi->free_blocks += len;
	hfsplus_mark_mdb_dirty(sb);
	mutex_unlock(&sbi->alloc_mutex);

	return 0;

kaboom:
	pr_crit("unable to mark blocks free: error %ld\n", PTR_ERR(page));
	mutex_unlock(&sbi->alloc_mutex);

	return -EIO;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/bitmap.c */
/************************************************************/
/*
 * linux/fs/hfsplus/part_tbl.c
 *
 * Copyright (C) 1996-1997  Paul H. Hargrove
 * This file may be distributed under the terms of
 * the GNU General Public License.
 *
 * Original code to handle the new style Mac partition table based on
 * a patch contributed by Holger Schemel (aeglos@valinor.owl.de).
 *
 * In function preconditions the term "valid" applied to a pointer to
 * a structure means that the pointer is non-NULL and the structure it
 * points to has all fields initialized to consistent values.
 *
 */

// #include <linux/slab.h>
// #include "hfsplus_fs.h"

/* offsets to various blocks */
#define HFS_DD_BLK		0 /* Driver Descriptor block */
#define HFS_PMAP_BLK		1 /* First block of partition map */
#define HFS_MDB_BLK		2 /* Block (w/i partition) of MDB */

/* magic numbers for various disk blocks */
#define HFS_DRVR_DESC_MAGIC	0x4552 /* "ER": driver descriptor map */
#define HFS_OLD_PMAP_MAGIC	0x5453 /* "TS": old-type partition map */
#define HFS_NEW_PMAP_MAGIC	0x504D /* "PM": new-type partition map */
#define HFS_SUPER_MAGIC		0x4244 /* "BD": HFS MDB (super block) */
#define HFS_MFS_SUPER_MAGIC	0xD2D7 /* MFS MDB (super block) */

/*
 * The new style Mac partition map
 *
 * For each partition on the media there is a physical block (512-byte
 * block) containing one of these structures.  These blocks are
 * contiguous starting at block 1.
 */
struct new_pmap {
	__be16	pmSig;		/* signature */
	__be16	reSigPad;	/* padding */
	__be32	pmMapBlkCnt;	/* partition blocks count */
	__be32	pmPyPartStart;	/* physical block start of partition */
	__be32	pmPartBlkCnt;	/* physical block count of partition */
	u8	pmPartName[32];	/* (null terminated?) string
				   giving the name of this
				   partition */
	u8	pmPartType[32];	/* (null terminated?) string
				   giving the type of this
				   partition */
	/* a bunch more stuff we don't need */
} __packed;

/*
 * The old style Mac partition map
 *
 * The partition map consists for a 2-byte signature followed by an
 * array of these structures.  The map is terminated with an all-zero
 * one of these.
 */
struct old_pmap {
	__be16		pdSig;	/* Signature bytes */
	struct old_pmap_entry {
		__be32	pdStart;
		__be32	pdSize;
		__be32	pdFSID;
	}	pdEntry[42];
} __packed;

static int hfs_parse_old_pmap(struct super_block *sb, struct old_pmap *pm,
		sector_t *part_start, sector_t *part_size)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	int i;

	for (i = 0; i < 42; i++) {
		struct old_pmap_entry *p = &pm->pdEntry[i];

		if (p->pdStart && p->pdSize &&
		    p->pdFSID == cpu_to_be32(0x54465331)/*"TFS1"*/ &&
		    (sbi->part < 0 || sbi->part == i)) {
			*part_start += be32_to_cpu(p->pdStart);
			*part_size = be32_to_cpu(p->pdSize);
			return 0;
		}
	}

	return -ENOENT;
}

static int hfs_parse_new_pmap(struct super_block *sb, void *buf,
		struct new_pmap *pm, sector_t *part_start, sector_t *part_size)
{
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	int size = be32_to_cpu(pm->pmMapBlkCnt);
	int buf_size = hfsplus_min_io_size(sb);
	int res;
	int i = 0;

	do {
		if (!memcmp(pm->pmPartType, "Apple_HFS", 9) &&
		    (sbi->part < 0 || sbi->part == i)) {
			*part_start += be32_to_cpu(pm->pmPyPartStart);
			*part_size = be32_to_cpu(pm->pmPartBlkCnt);
			return 0;
		}

		if (++i >= size)
			return -ENOENT;

		pm = (struct new_pmap *)((u8 *)pm + HFSPLUS_SECTOR_SIZE);
		if ((u8 *)pm - (u8 *)buf >= buf_size) {
			res = hfsplus_submit_bio(sb,
						 *part_start + HFS_PMAP_BLK + i,
						 buf, (void **)&pm, READ);
			if (res)
				return res;
		}
	} while (pm->pmSig == cpu_to_be16(HFS_NEW_PMAP_MAGIC));

	return -ENOENT;
}

/*
 * Parse the partition map looking for the start and length of a
 * HFS/HFS+ partition.
 */
int hfs_part_find(struct super_block *sb,
		sector_t *part_start, sector_t *part_size)
{
	void *buf, *data;
	int res;

	buf = kmalloc(hfsplus_min_io_size(sb), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	res = hfsplus_submit_bio(sb, *part_start + HFS_PMAP_BLK,
				 buf, &data, READ);
	if (res)
		goto out;

	switch (be16_to_cpu(*((__be16 *)data))) {
	case HFS_OLD_PMAP_MAGIC:
		res = hfs_parse_old_pmap(sb, data, part_start, part_size);
		break;
	case HFS_NEW_PMAP_MAGIC:
		res = hfs_parse_new_pmap(sb, buf, data, part_start, part_size);
		break;
	default:
		res = -ENOENT;
		break;
	}
out:
	kfree(buf);
	return res;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/part_tbl.c */
/************************************************************/
/*
 * linux/fs/hfsplus/attributes.c
 *
 * Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Handling of records in attributes tree
 */

// #include "hfsplus_fs.h"
// #include "hfsplus_raw.h"

static struct kmem_cache *hfsplus_attr_tree_cachep;

int __init hfsplus_create_attr_tree_cache(void)
{
	if (hfsplus_attr_tree_cachep)
		return -EEXIST;

	hfsplus_attr_tree_cachep =
		kmem_cache_create("hfsplus_attr_cache",
			sizeof(hfsplus_attr_entry), 0,
			SLAB_HWCACHE_ALIGN, NULL);
	if (!hfsplus_attr_tree_cachep)
		return -ENOMEM;

	return 0;
}

void hfsplus_destroy_attr_tree_cache(void)
{
	kmem_cache_destroy(hfsplus_attr_tree_cachep);
}

int hfsplus_attr_bin_cmp_key(const hfsplus_btree_key *k1,
				const hfsplus_btree_key *k2)
{
	__be32 k1_cnid, k2_cnid;

	k1_cnid = k1->attr.cnid;
	k2_cnid = k2->attr.cnid;
	if (k1_cnid != k2_cnid)
		return be32_to_cpu(k1_cnid) < be32_to_cpu(k2_cnid) ? -1 : 1;

	return hfsplus_strcmp(
			(const struct hfsplus_unistr *)&k1->attr.key_name,
			(const struct hfsplus_unistr *)&k2->attr.key_name);
}

int hfsplus_attr_build_key(struct super_block *sb, hfsplus_btree_key *key,
			u32 cnid, const char *name)
{
	int len;

	memset(key, 0, sizeof(struct hfsplus_attr_key));
	key->attr.cnid = cpu_to_be32(cnid);
	if (name) {
		int res = hfsplus_asc2uni(sb,
				(struct hfsplus_unistr *)&key->attr.key_name,
				HFSPLUS_ATTR_MAX_STRLEN, name, strlen(name));
		if (res)
			return res;
		len = be16_to_cpu(key->attr.key_name.length);
	} else {
		key->attr.key_name.length = 0;
		len = 0;
	}

	/* The length of the key, as stored in key_len field, does not include
	 * the size of the key_len field itself.
	 * So, offsetof(hfsplus_attr_key, key_name) is a trick because
	 * it takes into consideration key_len field (__be16) of
	 * hfsplus_attr_key structure instead of length field (__be16) of
	 * hfsplus_attr_unistr structure.
	 */
	key->key_len =
		cpu_to_be16(offsetof(struct hfsplus_attr_key, key_name) +
				2 * len);

	return 0;
}

hfsplus_attr_entry *hfsplus_alloc_attr_entry(void)
{
	return kmem_cache_alloc(hfsplus_attr_tree_cachep, GFP_KERNEL);
}

void hfsplus_destroy_attr_entry(hfsplus_attr_entry *entry)
{
	if (entry)
		kmem_cache_free(hfsplus_attr_tree_cachep, entry);
}

#define HFSPLUS_INVALID_ATTR_RECORD -1

static int hfsplus_attr_build_record(hfsplus_attr_entry *entry, int record_type,
				u32 cnid, const void *value, size_t size)
{
	if (record_type == HFSPLUS_ATTR_FORK_DATA) {
		/*
		 * Mac OS X supports only inline data attributes.
		 * Do nothing
		 */
		memset(entry, 0, sizeof(*entry));
		return sizeof(struct hfsplus_attr_fork_data);
	} else if (record_type == HFSPLUS_ATTR_EXTENTS) {
		/*
		 * Mac OS X supports only inline data attributes.
		 * Do nothing.
		 */
		memset(entry, 0, sizeof(*entry));
		return sizeof(struct hfsplus_attr_extents);
	} else if (record_type == HFSPLUS_ATTR_INLINE_DATA) {
		u16 len;

		memset(entry, 0, sizeof(struct hfsplus_attr_inline_data));
		entry->inline_data.record_type = cpu_to_be32(record_type);
		if (size <= HFSPLUS_MAX_INLINE_DATA_SIZE)
			len = size;
		else
			return HFSPLUS_INVALID_ATTR_RECORD;
		entry->inline_data.length = cpu_to_be16(len);
		memcpy(entry->inline_data.raw_bytes, value, len);
		/*
		 * Align len on two-byte boundary.
		 * It needs to add pad byte if we have odd len.
		 */
		len = round_up(len, 2);
		return offsetof(struct hfsplus_attr_inline_data, raw_bytes) +
					len;
	} else /* invalid input */
		memset(entry, 0, sizeof(*entry));

	return HFSPLUS_INVALID_ATTR_RECORD;
}

int hfsplus_find_attr(struct super_block *sb, u32 cnid,
			const char *name, struct hfs_find_data *fd)
{
	int err = 0;

	hfs_dbg(ATTR_MOD, "find_attr: %s,%d\n", name ? name : NULL, cnid);

	if (!HFSPLUS_SB(sb)->attr_tree) {
		pr_err("attributes file doesn't exist\n");
		return -EINVAL;
	}

	if (name) {
		err = hfsplus_attr_build_key(sb, fd->search_key, cnid, name);
		if (err)
			goto failed_find_attr;
		err = hfs_brec_find(fd, hfs_find_rec_by_key);
		if (err)
			goto failed_find_attr;
	} else {
		err = hfsplus_attr_build_key(sb, fd->search_key, cnid, NULL);
		if (err)
			goto failed_find_attr;
		err = hfs_brec_find(fd, hfs_find_1st_rec_by_cnid);
		if (err)
			goto failed_find_attr;
	}

failed_find_attr:
	return err;
}

int hfsplus_attr_exists(struct inode *inode, const char *name)
{
	int err = 0;
	struct super_block *sb = inode->i_sb;
	struct hfs_find_data fd;

	if (!HFSPLUS_SB(sb)->attr_tree)
		return 0;

	err = hfs_find_init(HFSPLUS_SB(sb)->attr_tree, &fd);
	if (err)
		return 0;

	err = hfsplus_find_attr(sb, inode->i_ino, name, &fd);
	if (err)
		goto attr_not_found;

	hfs_find_exit(&fd);
	return 1;

attr_not_found:
	hfs_find_exit(&fd);
	return 0;
}

int hfsplus_create_attr(struct inode *inode,
				const char *name,
				const void *value, size_t size)
{
	struct super_block *sb = inode->i_sb;
	struct hfs_find_data fd;
	hfsplus_attr_entry *entry_ptr;
	int entry_size;
	int err;

	hfs_dbg(ATTR_MOD, "create_attr: %s,%ld\n",
		name ? name : NULL, inode->i_ino);

	if (!HFSPLUS_SB(sb)->attr_tree) {
		pr_err("attributes file doesn't exist\n");
		return -EINVAL;
	}

	entry_ptr = hfsplus_alloc_attr_entry();
	if (!entry_ptr)
		return -ENOMEM;

	err = hfs_find_init(HFSPLUS_SB(sb)->attr_tree, &fd);
	if (err)
		goto failed_init_create_attr;

	if (name) {
		err = hfsplus_attr_build_key(sb, fd.search_key,
						inode->i_ino, name);
		if (err)
			goto failed_create_attr;
	} else {
		err = -EINVAL;
		goto failed_create_attr;
	}

	/* Mac OS X supports only inline data attributes. */
	entry_size = hfsplus_attr_build_record(entry_ptr,
					HFSPLUS_ATTR_INLINE_DATA,
					inode->i_ino,
					value, size);
	if (entry_size == HFSPLUS_INVALID_ATTR_RECORD) {
		err = -EINVAL;
		goto failed_create_attr;
	}

	err = hfs_brec_find(&fd, hfs_find_rec_by_key);
	if (err != -ENOENT) {
		if (!err)
			err = -EEXIST;
		goto failed_create_attr;
	}

	err = hfs_brec_insert(&fd, entry_ptr, entry_size);
	if (err)
		goto failed_create_attr;

	hfsplus_mark_inode_dirty(inode, HFSPLUS_I_ATTR_DIRTY);

failed_create_attr:
	hfs_find_exit(&fd);

failed_init_create_attr:
	hfsplus_destroy_attr_entry(entry_ptr);
	return err;
}

static int __hfsplus_delete_attr(struct inode *inode, u32 cnid,
					struct hfs_find_data *fd)
{
	int err = 0;
	__be32 found_cnid, record_type;

	hfs_bnode_read(fd->bnode, &found_cnid,
			fd->keyoffset +
			offsetof(struct hfsplus_attr_key, cnid),
			sizeof(__be32));
	if (cnid != be32_to_cpu(found_cnid))
		return -ENOENT;

	hfs_bnode_read(fd->bnode, &record_type,
			fd->entryoffset, sizeof(record_type));

	switch (be32_to_cpu(record_type)) {
	case HFSPLUS_ATTR_INLINE_DATA:
		/* All is OK. Do nothing. */
		break;
	case HFSPLUS_ATTR_FORK_DATA:
	case HFSPLUS_ATTR_EXTENTS:
		pr_err("only inline data xattr are supported\n");
		return -EOPNOTSUPP;
	default:
		pr_err("invalid extended attribute record\n");
		return -ENOENT;
	}

	err = hfs_brec_remove(fd);
	if (err)
		return err;

	hfsplus_mark_inode_dirty(inode, HFSPLUS_I_ATTR_DIRTY);
	return err;
}

int hfsplus_delete_attr(struct inode *inode, const char *name)
{
	int err = 0;
	struct super_block *sb = inode->i_sb;
	struct hfs_find_data fd;

	hfs_dbg(ATTR_MOD, "delete_attr: %s,%ld\n",
		name ? name : NULL, inode->i_ino);

	if (!HFSPLUS_SB(sb)->attr_tree) {
		pr_err("attributes file doesn't exist\n");
		return -EINVAL;
	}

	err = hfs_find_init(HFSPLUS_SB(sb)->attr_tree, &fd);
	if (err)
		return err;

	if (name) {
		err = hfsplus_attr_build_key(sb, fd.search_key,
						inode->i_ino, name);
		if (err)
			goto out;
	} else {
		pr_err("invalid extended attribute name\n");
		err = -EINVAL;
		goto out;
	}

	err = hfs_brec_find(&fd, hfs_find_rec_by_key);
	if (err)
		goto out;

	err = __hfsplus_delete_attr(inode, inode->i_ino, &fd);
	if (err)
		goto out;

out:
	hfs_find_exit(&fd);
	return err;
}

int hfsplus_delete_all_attrs(struct inode *dir, u32 cnid)
{
	int err = 0;
	struct hfs_find_data fd;

	hfs_dbg(ATTR_MOD, "delete_all_attrs: %d\n", cnid);

	if (!HFSPLUS_SB(dir->i_sb)->attr_tree) {
		pr_err("attributes file doesn't exist\n");
		return -EINVAL;
	}

	err = hfs_find_init(HFSPLUS_SB(dir->i_sb)->attr_tree, &fd);
	if (err)
		return err;

	for (;;) {
		err = hfsplus_find_attr(dir->i_sb, cnid, NULL, &fd);
		if (err) {
			if (err != -ENOENT)
				pr_err("xattr search failed\n");
			goto end_delete_all;
		}

		err = __hfsplus_delete_attr(dir, cnid, &fd);
		if (err)
			goto end_delete_all;
	}

end_delete_all:
	hfs_find_exit(&fd);
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/attributes.c */
/************************************************************/
/*
 * linux/fs/hfsplus/xattr.c
 *
 * Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Logic of processing extended attributes
 */

// #include "hfsplus_fs.h"
#include <linux/posix_acl_xattr.h>
// #include <linux/nls.h>
// #include "xattr.h"
// #include "acl.h"
#include "../../inc/__fss.h"

static int hfsplus_removexattr(struct inode *inode, const char *name);

const struct xattr_handler *hfsplus_xattr_handlers[] = {
	&hfsplus_xattr_osx_handler,
	&hfsplus_xattr_user_handler,
	&hfsplus_xattr_trusted_handler,
#ifdef CONFIG_HFSPLUS_FS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
	&hfsplus_xattr_security_handler,
	NULL
};

static int strcmp_xattr_finder_info(const char *name)
{
	if (name) {
		return strncmp(name, HFSPLUS_XATTR_FINDER_INFO_NAME,
				sizeof(HFSPLUS_XATTR_FINDER_INFO_NAME));
	}
	return -1;
}

static int strcmp_xattr_acl(const char *name)
{
	if (name) {
		return strncmp(name, HFSPLUS_XATTR_ACL_NAME,
				sizeof(HFSPLUS_XATTR_ACL_NAME));
	}
	return -1;
}

static inline int is_known_namespace(const char *name)
{
	if (strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN) &&
	    strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN) &&
	    strncmp(name, XATTR_SECURITY_PREFIX, XATTR_SECURITY_PREFIX_LEN) &&
	    strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN))
		return false;

	return true;
}

static void hfsplus_init_header_node(struct inode *attr_file,
					u32 clump_size,
					char *buf, u16 node_size)
{
	struct hfs_bnode_desc *desc;
	struct hfs_btree_header_rec *head;
	u16 offset;
	__be16 *rec_offsets;
	u32 hdr_node_map_rec_bits;
	char *bmp;
	u32 used_nodes;
	u32 used_bmp_bytes;
	u64 tmp;

	hfs_dbg(ATTR_MOD, "init_hdr_attr_file: clump %u, node_size %u\n",
		clump_size, node_size);

	/* The end of the node contains list of record offsets */
	rec_offsets = (__be16 *)(buf + node_size);

	desc = (struct hfs_bnode_desc *)buf;
	desc->type = HFS_NODE_HEADER;
	desc->num_recs = cpu_to_be16(HFSPLUS_BTREE_HDR_NODE_RECS_COUNT);
	offset = sizeof(struct hfs_bnode_desc);
	*--rec_offsets = cpu_to_be16(offset);

	head = (struct hfs_btree_header_rec *)(buf + offset);
	head->node_size = cpu_to_be16(node_size);
	tmp = i_size_read(attr_file);
	do_div(tmp, node_size);
	head->node_count = cpu_to_be32(tmp);
	head->free_nodes = cpu_to_be32(be32_to_cpu(head->node_count) - 1);
	head->clump_size = cpu_to_be32(clump_size);
	head->attributes |= cpu_to_be32(HFS_TREE_BIGKEYS | HFS_TREE_VARIDXKEYS);
	head->max_key_len = cpu_to_be16(HFSPLUS_ATTR_KEYLEN - sizeof(u16));
	offset += sizeof(struct hfs_btree_header_rec);
	*--rec_offsets = cpu_to_be16(offset);
	offset += HFSPLUS_BTREE_HDR_USER_BYTES;
	*--rec_offsets = cpu_to_be16(offset);

	hdr_node_map_rec_bits = 8 * (node_size - offset - (4 * sizeof(u16)));
	if (be32_to_cpu(head->node_count) > hdr_node_map_rec_bits) {
		u32 map_node_bits;
		u32 map_nodes;

		desc->next = cpu_to_be32(be32_to_cpu(head->leaf_tail) + 1);
		map_node_bits = 8 * (node_size - sizeof(struct hfs_bnode_desc) -
					(2 * sizeof(u16)) - 2);
		map_nodes = (be32_to_cpu(head->node_count) -
				hdr_node_map_rec_bits +
				(map_node_bits - 1)) / map_node_bits;
		be32_add_cpu(&head->free_nodes, 0 - map_nodes);
	}

	bmp = buf + offset;
	used_nodes =
		be32_to_cpu(head->node_count) - be32_to_cpu(head->free_nodes);
	used_bmp_bytes = used_nodes / 8;
	if (used_bmp_bytes) {
		memset(bmp, 0xFF, used_bmp_bytes);
		bmp += used_bmp_bytes;
		used_nodes %= 8;
	}
	*bmp = ~(0xFF >> used_nodes);
	offset += hdr_node_map_rec_bits / 8;
	*--rec_offsets = cpu_to_be16(offset);
}

static int hfsplus_create_attributes_file(struct super_block *sb)
{
	int err = 0;
	struct hfsplus_sb_info *sbi = HFSPLUS_SB(sb);
	struct inode *attr_file;
	struct hfsplus_inode_info *hip;
	u32 clump_size;
	u16 node_size = HFSPLUS_ATTR_TREE_NODE_SIZE;
	char *buf;
	int index, written;
	struct address_space *mapping;
	struct page *page;
	int old_state = HFSPLUS_EMPTY_ATTR_TREE;

	hfs_dbg(ATTR_MOD, "create_attr_file: ino %d\n", HFSPLUS_ATTR_CNID);

check_attr_tree_state_again:
	switch (atomic_read(&sbi->attr_tree_state)) {
	case HFSPLUS_EMPTY_ATTR_TREE:
		if (old_state != atomic_cmpxchg(&sbi->attr_tree_state,
						old_state,
						HFSPLUS_CREATING_ATTR_TREE))
			goto check_attr_tree_state_again;
		break;
	case HFSPLUS_CREATING_ATTR_TREE:
		/*
		 * This state means that another thread is in process
		 * of AttributesFile creation. Theoretically, it is
		 * possible to be here. But really __setxattr() method
		 * first of all calls hfs_find_init() for lookup in
		 * B-tree of CatalogFile. This method locks mutex of
		 * CatalogFile's B-tree. As a result, if some thread
		 * is inside AttributedFile creation operation then
		 * another threads will be waiting unlocking of
		 * CatalogFile's B-tree's mutex. However, if code will
		 * change then we will return error code (-EAGAIN) from
		 * here. Really, it means that first try to set of xattr
		 * fails with error but second attempt will have success.
		 */
		return -EAGAIN;
	case HFSPLUS_VALID_ATTR_TREE:
		return 0;
	case HFSPLUS_FAILED_ATTR_TREE:
		return -EOPNOTSUPP;
	default:
		BUG();
	}

	attr_file = hfsplus_iget(sb, HFSPLUS_ATTR_CNID);
	if (IS_ERR(attr_file)) {
		pr_err("failed to load attributes file\n");
		return PTR_ERR(attr_file);
	}

	BUG_ON(i_size_read(attr_file) != 0);

	hip = HFSPLUS_I(attr_file);

	clump_size = hfsplus_calc_btree_clump_size(sb->s_blocksize,
						    node_size,
						    sbi->sect_count,
						    HFSPLUS_ATTR_CNID);

	mutex_lock(&hip->extents_lock);
	hip->clump_blocks = clump_size >> sbi->alloc_blksz_shift;
	mutex_unlock(&hip->extents_lock);

	if (sbi->free_blocks <= (hip->clump_blocks << 1)) {
		err = -ENOSPC;
		goto end_attr_file_creation;
	}

	while (hip->alloc_blocks < hip->clump_blocks) {
		err = hfsplus_file_extend(attr_file, false);
		if (unlikely(err)) {
			pr_err("failed to extend attributes file\n");
			goto end_attr_file_creation;
		}
		hip->phys_size = attr_file->i_size =
			(loff_t)hip->alloc_blocks << sbi->alloc_blksz_shift;
		hip->fs_blocks = hip->alloc_blocks << sbi->fs_shift;
		inode_set_bytes(attr_file, attr_file->i_size);
	}

	buf = kzalloc(node_size, GFP_NOFS);
	if (!buf) {
		pr_err("failed to allocate memory for header node\n");
		err = -ENOMEM;
		goto end_attr_file_creation;
	}

	hfsplus_init_header_node(attr_file, clump_size, buf, node_size);

	mapping = attr_file->i_mapping;

	index = 0;
	written = 0;
	for (; written < node_size; index++, written += PAGE_CACHE_SIZE) {
		void *kaddr;

		page = read_mapping_page(mapping, index, NULL);
		if (IS_ERR(page)) {
			err = PTR_ERR(page);
			goto failed_header_node_init;
		}

		kaddr = kmap_atomic(page);
		memcpy(kaddr, buf + written,
			min_t(size_t, PAGE_CACHE_SIZE, node_size - written));
		kunmap_atomic(kaddr);

		set_page_dirty(page);
		page_cache_release(page);
	}

	hfsplus_mark_inode_dirty(attr_file, HFSPLUS_I_ATTR_DIRTY);

	sbi->attr_tree = hfs_btree_open(sb, HFSPLUS_ATTR_CNID);
	if (!sbi->attr_tree)
		pr_err("failed to load attributes file\n");

failed_header_node_init:
	kfree(buf);

end_attr_file_creation:
	iput(attr_file);

	if (!err)
		atomic_set(&sbi->attr_tree_state, HFSPLUS_VALID_ATTR_TREE);
	else if (err == -ENOSPC)
		atomic_set(&sbi->attr_tree_state, HFSPLUS_EMPTY_ATTR_TREE);
	else
		atomic_set(&sbi->attr_tree_state, HFSPLUS_FAILED_ATTR_TREE);

	return err;
}

int __hfsplus_setxattr(struct inode *inode, const char *name,
			const void *value, size_t size, int flags)
{
	int err = 0;
	struct hfs_find_data cat_fd;
	hfsplus_cat_entry entry;
	u16 cat_entry_flags, cat_entry_type;
	u16 folder_finderinfo_len = sizeof(struct DInfo) +
					sizeof(struct DXInfo);
	u16 file_finderinfo_len = sizeof(struct FInfo) +
					sizeof(struct FXInfo);

	if ((!S_ISREG(inode->i_mode) &&
			!S_ISDIR(inode->i_mode)) ||
				HFSPLUS_IS_RSRC(inode))
		return -EOPNOTSUPP;

	if (value == NULL)
		return hfsplus_removexattr(inode, name);

	err = hfs_find_init(HFSPLUS_SB(inode->i_sb)->cat_tree, &cat_fd);
	if (err) {
		pr_err("can't init xattr find struct\n");
		return err;
	}

	err = hfsplus_find_cat(inode->i_sb, inode->i_ino, &cat_fd);
	if (err) {
		pr_err("catalog searching failed\n");
		goto end_setxattr;
	}

	if (!strcmp_xattr_finder_info(name)) {
		if (flags & XATTR_CREATE) {
			pr_err("xattr exists yet\n");
			err = -EOPNOTSUPP;
			goto end_setxattr;
		}
		hfs_bnode_read(cat_fd.bnode, &entry, cat_fd.entryoffset,
					sizeof(hfsplus_cat_entry));
		if (be16_to_cpu(entry.type) == HFSPLUS_FOLDER) {
			if (size == folder_finderinfo_len) {
				memcpy(&entry.folder.user_info, value,
						folder_finderinfo_len);
				hfs_bnode_write(cat_fd.bnode, &entry,
					cat_fd.entryoffset,
					sizeof(struct hfsplus_cat_folder));
				hfsplus_mark_inode_dirty(inode,
						HFSPLUS_I_CAT_DIRTY);
			} else {
				err = -ERANGE;
				goto end_setxattr;
			}
		} else if (be16_to_cpu(entry.type) == HFSPLUS_FILE) {
			if (size == file_finderinfo_len) {
				memcpy(&entry.file.user_info, value,
						file_finderinfo_len);
				hfs_bnode_write(cat_fd.bnode, &entry,
					cat_fd.entryoffset,
					sizeof(struct hfsplus_cat_file));
				hfsplus_mark_inode_dirty(inode,
						HFSPLUS_I_CAT_DIRTY);
			} else {
				err = -ERANGE;
				goto end_setxattr;
			}
		} else {
			err = -EOPNOTSUPP;
			goto end_setxattr;
		}
		goto end_setxattr;
	}

	if (!HFSPLUS_SB(inode->i_sb)->attr_tree) {
		err = hfsplus_create_attributes_file(inode->i_sb);
		if (unlikely(err))
			goto end_setxattr;
	}

	if (hfsplus_attr_exists(inode, name)) {
		if (flags & XATTR_CREATE) {
			pr_err("xattr exists yet\n");
			err = -EOPNOTSUPP;
			goto end_setxattr;
		}
		err = hfsplus_delete_attr(inode, name);
		if (err)
			goto end_setxattr;
		err = hfsplus_create_attr(inode, name, value, size);
		if (err)
			goto end_setxattr;
	} else {
		if (flags & XATTR_REPLACE) {
			pr_err("cannot replace xattr\n");
			err = -EOPNOTSUPP;
			goto end_setxattr;
		}
		err = hfsplus_create_attr(inode, name, value, size);
		if (err)
			goto end_setxattr;
	}

	cat_entry_type = hfs_bnode_read_u16(cat_fd.bnode, cat_fd.entryoffset);
	if (cat_entry_type == HFSPLUS_FOLDER) {
		cat_entry_flags = hfs_bnode_read_u16(cat_fd.bnode,
				    cat_fd.entryoffset +
				    offsetof(struct hfsplus_cat_folder, flags));
		cat_entry_flags |= HFSPLUS_XATTR_EXISTS;
		if (!strcmp_xattr_acl(name))
			cat_entry_flags |= HFSPLUS_ACL_EXISTS;
		hfs_bnode_write_u16(cat_fd.bnode, cat_fd.entryoffset +
				offsetof(struct hfsplus_cat_folder, flags),
				cat_entry_flags);
		hfsplus_mark_inode_dirty(inode, HFSPLUS_I_CAT_DIRTY);
	} else if (cat_entry_type == HFSPLUS_FILE) {
		cat_entry_flags = hfs_bnode_read_u16(cat_fd.bnode,
				    cat_fd.entryoffset +
				    offsetof(struct hfsplus_cat_file, flags));
		cat_entry_flags |= HFSPLUS_XATTR_EXISTS;
		if (!strcmp_xattr_acl(name))
			cat_entry_flags |= HFSPLUS_ACL_EXISTS;
		hfs_bnode_write_u16(cat_fd.bnode, cat_fd.entryoffset +
				    offsetof(struct hfsplus_cat_file, flags),
				    cat_entry_flags);
		hfsplus_mark_inode_dirty(inode, HFSPLUS_I_CAT_DIRTY);
	} else {
		pr_err("invalid catalog entry type\n");
		err = -EIO;
		goto end_setxattr;
	}

end_setxattr:
	hfs_find_exit(&cat_fd);
	return err;
}

static int name_len(const char *xattr_name, int xattr_name_len)
{
	int len = xattr_name_len + 1;

	if (!is_known_namespace(xattr_name))
		len += XATTR_MAC_OSX_PREFIX_LEN;

	return len;
}

static int copy_name(char *buffer, const char *xattr_name, int name_len)
{
	int len = name_len;
	int offset = 0;

	if (!is_known_namespace(xattr_name)) {
		strncpy(buffer, XATTR_MAC_OSX_PREFIX, XATTR_MAC_OSX_PREFIX_LEN);
		offset += XATTR_MAC_OSX_PREFIX_LEN;
		len += XATTR_MAC_OSX_PREFIX_LEN;
	}

	strncpy(buffer + offset, xattr_name, name_len);
	memset(buffer + offset + name_len, 0, 1);
	len += 1;

	return len;
}

static ssize_t hfsplus_getxattr_finder_info(struct inode *inode,
						void *value, size_t size)
{
	ssize_t res = 0;
	struct hfs_find_data fd;
	u16 entry_type;
	u16 folder_rec_len = sizeof(struct DInfo) + sizeof(struct DXInfo);
	u16 file_rec_len = sizeof(struct FInfo) + sizeof(struct FXInfo);
	u16 record_len = max(folder_rec_len, file_rec_len);
	u8 folder_finder_info[sizeof(struct DInfo) + sizeof(struct DXInfo)];
	u8 file_finder_info[sizeof(struct FInfo) + sizeof(struct FXInfo)];

	if (size >= record_len) {
		res = hfs_find_init(HFSPLUS_SB(inode->i_sb)->cat_tree, &fd);
		if (res) {
			pr_err("can't init xattr find struct\n");
			return res;
		}
		res = hfsplus_find_cat(inode->i_sb, inode->i_ino, &fd);
		if (res)
			goto end_getxattr_finder_info;
		entry_type = hfs_bnode_read_u16(fd.bnode, fd.entryoffset);

		if (entry_type == HFSPLUS_FOLDER) {
			hfs_bnode_read(fd.bnode, folder_finder_info,
				fd.entryoffset +
				offsetof(struct hfsplus_cat_folder, user_info),
				folder_rec_len);
			memcpy(value, folder_finder_info, folder_rec_len);
			res = folder_rec_len;
		} else if (entry_type == HFSPLUS_FILE) {
			hfs_bnode_read(fd.bnode, file_finder_info,
				fd.entryoffset +
				offsetof(struct hfsplus_cat_file, user_info),
				file_rec_len);
			memcpy(value, file_finder_info, file_rec_len);
			res = file_rec_len;
		} else {
			res = -EOPNOTSUPP;
			goto end_getxattr_finder_info;
		}
	} else
		res = size ? -ERANGE : record_len;

end_getxattr_finder_info:
	if (size >= record_len)
		hfs_find_exit(&fd);
	return res;
}

ssize_t __hfsplus_getxattr(struct inode *inode, const char *name,
			 void *value, size_t size)
{
	struct hfs_find_data fd;
	hfsplus_attr_entry *entry;
	__be32 xattr_record_type;
	u32 record_type;
	u16 record_length = 0;
	ssize_t res = 0;

	if ((!S_ISREG(inode->i_mode) &&
			!S_ISDIR(inode->i_mode)) ||
				HFSPLUS_IS_RSRC(inode))
		return -EOPNOTSUPP;

	if (!strcmp_xattr_finder_info(name))
		return hfsplus_getxattr_finder_info(inode, value, size);

	if (!HFSPLUS_SB(inode->i_sb)->attr_tree)
		return -EOPNOTSUPP;

	entry = hfsplus_alloc_attr_entry();
	if (!entry) {
		pr_err("can't allocate xattr entry\n");
		return -ENOMEM;
	}

	res = hfs_find_init(HFSPLUS_SB(inode->i_sb)->attr_tree, &fd);
	if (res) {
		pr_err("can't init xattr find struct\n");
		goto failed_getxattr_init;
	}

	res = hfsplus_find_attr(inode->i_sb, inode->i_ino, name, &fd);
	if (res) {
		if (res == -ENOENT)
			res = -ENODATA;
		else
			pr_err("xattr searching failed\n");
		goto out;
	}

	hfs_bnode_read(fd.bnode, &xattr_record_type,
			fd.entryoffset, sizeof(xattr_record_type));
	record_type = be32_to_cpu(xattr_record_type);
	if (record_type == HFSPLUS_ATTR_INLINE_DATA) {
		record_length = hfs_bnode_read_u16(fd.bnode,
				fd.entryoffset +
				offsetof(struct hfsplus_attr_inline_data,
				length));
		if (record_length > HFSPLUS_MAX_INLINE_DATA_SIZE) {
			pr_err("invalid xattr record size\n");
			res = -EIO;
			goto out;
		}
	} else if (record_type == HFSPLUS_ATTR_FORK_DATA ||
			record_type == HFSPLUS_ATTR_EXTENTS) {
		pr_err("only inline data xattr are supported\n");
		res = -EOPNOTSUPP;
		goto out;
	} else {
		pr_err("invalid xattr record\n");
		res = -EIO;
		goto out;
	}

	if (size) {
		hfs_bnode_read(fd.bnode, entry, fd.entryoffset,
				offsetof(struct hfsplus_attr_inline_data,
					raw_bytes) + record_length);
	}

	if (size >= record_length) {
		memcpy(value, entry->inline_data.raw_bytes, record_length);
		res = record_length;
	} else
		res = size ? -ERANGE : record_length;

out:
	hfs_find_exit(&fd);

failed_getxattr_init:
	hfsplus_destroy_attr_entry(entry);
	return res;
}

static inline int can_list(const char *xattr_name)
{
	if (!xattr_name)
		return 0;

	return strncmp(xattr_name, XATTR_TRUSTED_PREFIX,
			XATTR_TRUSTED_PREFIX_LEN) ||
				capable(CAP_SYS_ADMIN);
}

static ssize_t hfsplus_listxattr_finder_info(struct dentry *dentry,
						char *buffer, size_t size)
{
	ssize_t res = 0;
	struct inode *inode = dentry->d_inode;
	struct hfs_find_data fd;
	u16 entry_type;
	u8 folder_finder_info[sizeof(struct DInfo) + sizeof(struct DXInfo)];
	u8 file_finder_info[sizeof(struct FInfo) + sizeof(struct FXInfo)];
	unsigned long len, found_bit;
	int xattr_name_len, symbols_count;

	res = hfs_find_init(HFSPLUS_SB(inode->i_sb)->cat_tree, &fd);
	if (res) {
		pr_err("can't init xattr find struct\n");
		return res;
	}

	res = hfsplus_find_cat(inode->i_sb, inode->i_ino, &fd);
	if (res)
		goto end_listxattr_finder_info;

	entry_type = hfs_bnode_read_u16(fd.bnode, fd.entryoffset);
	if (entry_type == HFSPLUS_FOLDER) {
		len = sizeof(struct DInfo) + sizeof(struct DXInfo);
		hfs_bnode_read(fd.bnode, folder_finder_info,
				fd.entryoffset +
				offsetof(struct hfsplus_cat_folder, user_info),
				len);
		found_bit = find_first_bit((void *)folder_finder_info, len*8);
	} else if (entry_type == HFSPLUS_FILE) {
		len = sizeof(struct FInfo) + sizeof(struct FXInfo);
		hfs_bnode_read(fd.bnode, file_finder_info,
				fd.entryoffset +
				offsetof(struct hfsplus_cat_file, user_info),
				len);
		found_bit = find_first_bit((void *)file_finder_info, len*8);
	} else {
		res = -EOPNOTSUPP;
		goto end_listxattr_finder_info;
	}

	if (found_bit >= (len*8))
		res = 0;
	else {
		symbols_count = sizeof(HFSPLUS_XATTR_FINDER_INFO_NAME) - 1;
		xattr_name_len =
			name_len(HFSPLUS_XATTR_FINDER_INFO_NAME, symbols_count);
		if (!buffer || !size) {
			if (can_list(HFSPLUS_XATTR_FINDER_INFO_NAME))
				res = xattr_name_len;
		} else if (can_list(HFSPLUS_XATTR_FINDER_INFO_NAME)) {
			if (size < xattr_name_len)
				res = -ERANGE;
			else {
				res = copy_name(buffer,
						HFSPLUS_XATTR_FINDER_INFO_NAME,
						symbols_count);
			}
		}
	}

end_listxattr_finder_info:
	hfs_find_exit(&fd);

	return res;
}

ssize_t hfsplus_listxattr(struct dentry *dentry, char *buffer, size_t size)
{
	ssize_t err;
	ssize_t res = 0;
	struct inode *inode = dentry->d_inode;
	struct hfs_find_data fd;
	u16 key_len = 0;
	struct hfsplus_attr_key attr_key;
	char *strbuf;
	int xattr_name_len;

	if ((!S_ISREG(inode->i_mode) &&
			!S_ISDIR(inode->i_mode)) ||
				HFSPLUS_IS_RSRC(inode))
		return -EOPNOTSUPP;

	res = hfsplus_listxattr_finder_info(dentry, buffer, size);
	if (res < 0)
		return res;
	else if (!HFSPLUS_SB(inode->i_sb)->attr_tree)
		return (res == 0) ? -EOPNOTSUPP : res;

	err = hfs_find_init(HFSPLUS_SB(inode->i_sb)->attr_tree, &fd);
	if (err) {
		pr_err("can't init xattr find struct\n");
		return err;
	}

	strbuf = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN +
			XATTR_MAC_OSX_PREFIX_LEN + 1, GFP_KERNEL);
	if (!strbuf) {
		res = -ENOMEM;
		goto out;
	}

	err = hfsplus_find_attr(inode->i_sb, inode->i_ino, NULL, &fd);
	if (err) {
		if (err == -ENOENT) {
			if (res == 0)
				res = -ENODATA;
			goto end_listxattr;
		} else {
			res = err;
			goto end_listxattr;
		}
	}

	for (;;) {
		key_len = hfs_bnode_read_u16(fd.bnode, fd.keyoffset);
		if (key_len == 0 || key_len > fd.tree->max_key_len) {
			pr_err("invalid xattr key length: %d\n", key_len);
			res = -EIO;
			goto end_listxattr;
		}

		hfs_bnode_read(fd.bnode, &attr_key,
				fd.keyoffset, key_len + sizeof(key_len));

		if (be32_to_cpu(attr_key.cnid) != inode->i_ino)
			goto end_listxattr;

		xattr_name_len = NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN;
		if (hfsplus_uni2asc(inode->i_sb,
			(const struct hfsplus_unistr *)&fd.key->attr.key_name,
					strbuf, &xattr_name_len)) {
			pr_err("unicode conversion failed\n");
			res = -EIO;
			goto end_listxattr;
		}

		if (!buffer || !size) {
			if (can_list(strbuf))
				res += name_len(strbuf, xattr_name_len);
		} else if (can_list(strbuf)) {
			if (size < (res + name_len(strbuf, xattr_name_len))) {
				res = -ERANGE;
				goto end_listxattr;
			} else
				res += copy_name(buffer + res,
						strbuf, xattr_name_len);
		}

		if (hfs_brec_goto(&fd, 1))
			goto end_listxattr;
	}

end_listxattr:
	kfree(strbuf);
out:
	hfs_find_exit(&fd);
	return res;
}

static int hfsplus_removexattr(struct inode *inode, const char *name)
{
	int err = 0;
	struct hfs_find_data cat_fd;
	u16 flags;
	u16 cat_entry_type;
	int is_xattr_acl_deleted = 0;
	int is_all_xattrs_deleted = 0;

	if (!HFSPLUS_SB(inode->i_sb)->attr_tree)
		return -EOPNOTSUPP;

	if (!strcmp_xattr_finder_info(name))
		return -EOPNOTSUPP;

	err = hfs_find_init(HFSPLUS_SB(inode->i_sb)->cat_tree, &cat_fd);
	if (err) {
		pr_err("can't init xattr find struct\n");
		return err;
	}

	err = hfsplus_find_cat(inode->i_sb, inode->i_ino, &cat_fd);
	if (err) {
		pr_err("catalog searching failed\n");
		goto end_removexattr;
	}

	err = hfsplus_delete_attr(inode, name);
	if (err)
		goto end_removexattr;

	is_xattr_acl_deleted = !strcmp_xattr_acl(name);
	is_all_xattrs_deleted = !hfsplus_attr_exists(inode, NULL);

	if (!is_xattr_acl_deleted && !is_all_xattrs_deleted)
		goto end_removexattr;

	cat_entry_type = hfs_bnode_read_u16(cat_fd.bnode, cat_fd.entryoffset);

	if (cat_entry_type == HFSPLUS_FOLDER) {
		flags = hfs_bnode_read_u16(cat_fd.bnode, cat_fd.entryoffset +
				offsetof(struct hfsplus_cat_folder, flags));
		if (is_xattr_acl_deleted)
			flags &= ~HFSPLUS_ACL_EXISTS;
		if (is_all_xattrs_deleted)
			flags &= ~HFSPLUS_XATTR_EXISTS;
		hfs_bnode_write_u16(cat_fd.bnode, cat_fd.entryoffset +
				offsetof(struct hfsplus_cat_folder, flags),
				flags);
		hfsplus_mark_inode_dirty(inode, HFSPLUS_I_CAT_DIRTY);
	} else if (cat_entry_type == HFSPLUS_FILE) {
		flags = hfs_bnode_read_u16(cat_fd.bnode, cat_fd.entryoffset +
				offsetof(struct hfsplus_cat_file, flags));
		if (is_xattr_acl_deleted)
			flags &= ~HFSPLUS_ACL_EXISTS;
		if (is_all_xattrs_deleted)
			flags &= ~HFSPLUS_XATTR_EXISTS;
		hfs_bnode_write_u16(cat_fd.bnode, cat_fd.entryoffset +
				offsetof(struct hfsplus_cat_file, flags),
				flags);
		hfsplus_mark_inode_dirty(inode, HFSPLUS_I_CAT_DIRTY);
	} else {
		pr_err("invalid catalog entry type\n");
		err = -EIO;
		goto end_removexattr;
	}

end_removexattr:
	hfs_find_exit(&cat_fd);
	return err;
}

static int hfsplus_osx_getxattr(struct dentry *dentry, const char *name,
					void *buffer, size_t size, int type)
{
	char *xattr_name;
	int res;

	if (!strcmp(name, ""))
		return -EINVAL;

	/*
	 * Don't allow retrieving properly prefixed attributes
	 * by prepending them with "osx."
	 */
	if (is_known_namespace(name))
		return -EOPNOTSUPP;
	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN
		+ XATTR_MAC_OSX_PREFIX_LEN + 1, GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	strcpy(xattr_name, XATTR_MAC_OSX_PREFIX);
	strcpy(xattr_name + XATTR_MAC_OSX_PREFIX_LEN, name);

	res = hfsplus_getxattr(dentry, xattr_name, buffer, size);
	kfree(xattr_name);
	return res;
}

static int hfsplus_osx_setxattr(struct dentry *dentry, const char *name,
		const void *buffer, size_t size, int flags, int type)
{
	char *xattr_name;
	int res;

	if (!strcmp(name, ""))
		return -EINVAL;

	/*
	 * Don't allow setting properly prefixed attributes
	 * by prepending them with "osx."
	 */
	if (is_known_namespace(name))
		return -EOPNOTSUPP;
	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN
		+ XATTR_MAC_OSX_PREFIX_LEN + 1, GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	strcpy(xattr_name, XATTR_MAC_OSX_PREFIX);
	strcpy(xattr_name + XATTR_MAC_OSX_PREFIX_LEN, name);

	res = hfsplus_setxattr(dentry, xattr_name, buffer, size, flags);
	kfree(xattr_name);
	return res;
}

static size_t hfsplus_osx_listxattr(struct dentry *dentry, char *list,
		size_t list_size, const char *name, size_t name_len, int type)
{
	/*
	 * This method is not used.
	 * It is used hfsplus_listxattr() instead of generic_listxattr().
	 */
	return -EOPNOTSUPP;
}

const struct xattr_handler hfsplus_xattr_osx_handler = {
	.prefix	= XATTR_MAC_OSX_PREFIX,
	.list	= hfsplus_osx_listxattr,
	.get	= hfsplus_osx_getxattr,
	.set	= hfsplus_osx_setxattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/xattr.c */
/************************************************************/
/*
 * linux/fs/hfsplus/xattr_user.c
 *
 * Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Handler for user extended attributes.
 */

// #include <linux/nls.h>

// #include "hfsplus_fs.h"
// #include "xattr.h"

static int hfsplus_user_getxattr(struct dentry *dentry, const char *name,
					void *buffer, size_t size, int type)
{
	char *xattr_name;
	int res;

	if (!strcmp(name, ""))
		return -EINVAL;

	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN + 1,
		GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	strcpy(xattr_name, XATTR_USER_PREFIX);
	strcpy(xattr_name + XATTR_USER_PREFIX_LEN, name);

	res = hfsplus_getxattr(dentry, xattr_name, buffer, size);
	kfree(xattr_name);
	return res;
}

static int hfsplus_user_setxattr(struct dentry *dentry, const char *name,
		const void *buffer, size_t size, int flags, int type)
{
	char *xattr_name;
	int res;

	if (!strcmp(name, ""))
		return -EINVAL;

	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN + 1,
		GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	strcpy(xattr_name, XATTR_USER_PREFIX);
	strcpy(xattr_name + XATTR_USER_PREFIX_LEN, name);

	res = hfsplus_setxattr(dentry, xattr_name, buffer, size, flags);
	kfree(xattr_name);
	return res;
}

static size_t hfsplus_user_listxattr(struct dentry *dentry, char *list,
		size_t list_size, const char *name, size_t name_len, int type)
{
	/*
	 * This method is not used.
	 * It is used hfsplus_listxattr() instead of generic_listxattr().
	 */
	return -EOPNOTSUPP;
}

const struct xattr_handler hfsplus_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= hfsplus_user_listxattr,
	.get	= hfsplus_user_getxattr,
	.set	= hfsplus_user_setxattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/xattr_user.c */
/************************************************************/
/*
 * linux/fs/hfsplus/xattr_trusted.c
 *
 * Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Handler for storing security labels as extended attributes.
 */

#include <linux/security.h>
// #include <linux/nls.h>
#include "../../inc/__fss.h"

// #include "hfsplus_fs.h"
// #include "xattr.h"
// #include "acl.h"

static int hfsplus_security_getxattr(struct dentry *dentry, const char *name,
					void *buffer, size_t size, int type)
{
	char *xattr_name;
	int res;

	if (!strcmp(name, ""))
		return -EINVAL;

	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN + 1,
		GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	strcpy(xattr_name, XATTR_SECURITY_PREFIX);
	strcpy(xattr_name + XATTR_SECURITY_PREFIX_LEN, name);

	res = hfsplus_getxattr(dentry, xattr_name, buffer, size);
	kfree(xattr_name);
	return res;
}

static int hfsplus_security_setxattr(struct dentry *dentry, const char *name,
		const void *buffer, size_t size, int flags, int type)
{
	char *xattr_name;
	int res;

	if (!strcmp(name, ""))
		return -EINVAL;

	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN + 1,
		GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	strcpy(xattr_name, XATTR_SECURITY_PREFIX);
	strcpy(xattr_name + XATTR_SECURITY_PREFIX_LEN, name);

	res = hfsplus_setxattr(dentry, xattr_name, buffer, size, flags);
	kfree(xattr_name);
	return res;
}

static size_t hfsplus_security_listxattr(struct dentry *dentry, char *list,
		size_t list_size, const char *name, size_t name_len, int type)
{
	/*
	 * This method is not used.
	 * It is used hfsplus_listxattr() instead of generic_listxattr().
	 */
	return -EOPNOTSUPP;
}

static int hfsplus_initxattrs(struct inode *inode,
				const struct xattr *xattr_array,
				void *fs_info)
{
	const struct xattr *xattr;
	char *xattr_name;
	int err = 0;

	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN + 1,
		GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	for (xattr = xattr_array; xattr->name != NULL; xattr++) {

		if (!strcmp(xattr->name, ""))
			continue;

		strcpy(xattr_name, XATTR_SECURITY_PREFIX);
		strcpy(xattr_name +
			XATTR_SECURITY_PREFIX_LEN, xattr->name);
		memset(xattr_name +
			XATTR_SECURITY_PREFIX_LEN + strlen(xattr->name), 0, 1);

		err = __hfsplus_setxattr(inode, xattr_name,
					xattr->value, xattr->value_len, 0);
		if (err)
			break;
	}
	kfree(xattr_name);
	return err;
}

int hfsplus_init_security(struct inode *inode, struct inode *dir,
				const struct qstr *qstr)
{
	return security_inode_init_security(inode, dir, qstr,
					&hfsplus_initxattrs, NULL);
}

int hfsplus_init_inode_security(struct inode *inode,
						struct inode *dir,
						const struct qstr *qstr)
{
	int err;

	err = hfsplus_init_posix_acl(inode, dir);
	if (!err)
		err = hfsplus_init_security(inode, dir, qstr);
	return err;
}

const struct xattr_handler hfsplus_xattr_security_handler = {
	.prefix	= XATTR_SECURITY_PREFIX,
	.list	= hfsplus_security_listxattr,
	.get	= hfsplus_security_getxattr,
	.set	= hfsplus_security_setxattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/xattr_security.c */
/************************************************************/
/*
 * linux/fs/hfsplus/xattr_trusted.c
 *
 * Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Handler for trusted extended attributes.
 */

// #include <linux/nls.h>

// #include "hfsplus_fs.h"
// #include "xattr.h"

static int hfsplus_trusted_getxattr(struct dentry *dentry, const char *name,
					void *buffer, size_t size, int type)
{
	char *xattr_name;
	int res;

	if (!strcmp(name, ""))
		return -EINVAL;

	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN + 1,
		GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	strcpy(xattr_name, XATTR_TRUSTED_PREFIX);
	strcpy(xattr_name + XATTR_TRUSTED_PREFIX_LEN, name);

	res = hfsplus_getxattr(dentry, xattr_name, buffer, size);
	kfree(xattr_name);
	return res;
}

static int hfsplus_trusted_setxattr(struct dentry *dentry, const char *name,
		const void *buffer, size_t size, int flags, int type)
{
	char *xattr_name;
	int res;

	if (!strcmp(name, ""))
		return -EINVAL;

	xattr_name = kmalloc(NLS_MAX_CHARSET_SIZE * HFSPLUS_ATTR_MAX_STRLEN + 1,
		GFP_KERNEL);
	if (!xattr_name)
		return -ENOMEM;
	strcpy(xattr_name, XATTR_TRUSTED_PREFIX);
	strcpy(xattr_name + XATTR_TRUSTED_PREFIX_LEN, name);

	res = hfsplus_setxattr(dentry, xattr_name, buffer, size, flags);
	kfree(xattr_name);
	return res;
}

static size_t hfsplus_trusted_listxattr(struct dentry *dentry, char *list,
		size_t list_size, const char *name, size_t name_len, int type)
{
	/*
	 * This method is not used.
	 * It is used hfsplus_listxattr() instead of generic_listxattr().
	 */
	return -EOPNOTSUPP;
}

const struct xattr_handler hfsplus_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= hfsplus_trusted_listxattr,
	.get	= hfsplus_trusted_getxattr,
	.set	= hfsplus_trusted_setxattr,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/xattr_trusted.c */
/************************************************************/
/*
 * linux/fs/hfsplus/posix_acl.c
 *
 * Vyacheslav Dubeyko <slava@dubeyko.com>
 *
 * Handler for Posix Access Control Lists (ACLs) support.
 */

// #include "hfsplus_fs.h"
// #include "xattr.h"
// #include "acl.h"

struct posix_acl *hfsplus_get_posix_acl(struct inode *inode, int type)
{
	struct posix_acl *acl;
	char *xattr_name;
	char *value = NULL;
	ssize_t size;

	hfs_dbg(ACL_MOD, "[%s]: ino %lu\n", __func__, inode->i_ino);

	switch (type) {
	case ACL_TYPE_ACCESS:
		xattr_name = POSIX_ACL_XATTR_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		xattr_name = POSIX_ACL_XATTR_DEFAULT;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	size = __hfsplus_getxattr(inode, xattr_name, NULL, 0);

	if (size > 0) {
		value = (char *)hfsplus_alloc_attr_entry();
		if (unlikely(!value))
			return ERR_PTR(-ENOMEM);
		size = __hfsplus_getxattr(inode, xattr_name, value, size);
	}

	if (size > 0)
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
	else if (size == -ENODATA)
		acl = NULL;
	else
		acl = ERR_PTR(size);

	hfsplus_destroy_attr_entry((hfsplus_attr_entry *)value);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}

int hfsplus_set_posix_acl(struct inode *inode, struct posix_acl *acl,
		int type)
{
	int err;
	char *xattr_name;
	size_t size = 0;
	char *value = NULL;

	hfs_dbg(ACL_MOD, "[%s]: ino %lu\n", __func__, inode->i_ino);

	switch (type) {
	case ACL_TYPE_ACCESS:
		xattr_name = POSIX_ACL_XATTR_ACCESS;
		if (acl) {
			err = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (err < 0)
				return err;
		}
		err = 0;
		break;

	case ACL_TYPE_DEFAULT:
		xattr_name = POSIX_ACL_XATTR_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;

	default:
		return -EINVAL;
	}

	if (acl) {
		size = posix_acl_xattr_size(acl->a_count);
		if (unlikely(size > HFSPLUS_MAX_INLINE_DATA_SIZE))
			return -ENOMEM;
		value = (char *)hfsplus_alloc_attr_entry();
		if (unlikely(!value))
			return -ENOMEM;
		err = posix_acl_to_xattr(&init_user_ns, acl, value, size);
		if (unlikely(err < 0))
			goto end_set_acl;
	}

	err = __hfsplus_setxattr(inode, xattr_name, value, size, 0);

end_set_acl:
	hfsplus_destroy_attr_entry((hfsplus_attr_entry *)value);

	if (!err)
		set_cached_acl(inode, type, acl);

	return err;
}

int hfsplus_init_posix_acl(struct inode *inode, struct inode *dir)
{
	int err = 0;
	struct posix_acl *default_acl, *acl;

	hfs_dbg(ACL_MOD,
		"[%s]: ino %lu, dir->ino %lu\n",
		__func__, inode->i_ino, dir->i_ino);

	if (S_ISLNK(inode->i_mode))
		return 0;

	err = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (err)
		return err;

	if (default_acl) {
		err = hfsplus_set_posix_acl(inode, default_acl,
					    ACL_TYPE_DEFAULT);
		posix_acl_release(default_acl);
	}

	if (acl) {
		if (!err)
			err = hfsplus_set_posix_acl(inode, acl,
						    ACL_TYPE_ACCESS);
		posix_acl_release(acl);
	}
	return err;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/hfsplus/posix_acl.c */
/************************************************************/
