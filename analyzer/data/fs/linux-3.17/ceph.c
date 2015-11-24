#include <linux/ceph/ceph_debug.h>

#include <linux/backing-dev.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/statfs.h>
#include <linux/string.h>

#include "super.h"
#include "mds_client.h"
#include "cache.h"

#include <linux/ceph/ceph_features.h>
#include <linux/ceph/decode.h>
#include <linux/ceph/mon_client.h>
#include <linux/ceph/auth.h>
#include <linux/ceph/debugfs.h>

/*
 * Ceph superblock operations
 *
 * Handle the basics of mounting, unmounting.
 */

/*
 * super ops
 */
static void ceph_put_super(struct super_block *s)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(s);

	dout("put_super\n");
	ceph_mdsc_close_sessions(fsc->mdsc);

	/*
	 * ensure we release the bdi before put_anon_super releases
	 * the device name.
	 */
	if (s->s_bdi == &fsc->backing_dev_info) {
		bdi_unregister(&fsc->backing_dev_info);
		s->s_bdi = NULL;
	}

	return;
}

static int ceph_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct ceph_fs_client *fsc = ceph_inode_to_client(dentry->d_inode);
	struct ceph_monmap *monmap = fsc->client->monc.monmap;
	struct ceph_statfs st;
	u64 fsid;
	int err;

	dout("statfs\n");
	err = ceph_monc_do_statfs(&fsc->client->monc, &st);
	if (err < 0)
		return err;

	/* fill in kstatfs */
	buf->f_type = CEPH_SUPER_MAGIC;  /* ?? */

	/*
	 * express utilization in terms of large blocks to avoid
	 * overflow on 32-bit machines.
	 *
	 * NOTE: for the time being, we make bsize == frsize to humor
	 * not-yet-ancient versions of glibc that are broken.
	 * Someday, we will probably want to report a real block
	 * size...  whatever that may mean for a network file system!
	 */
	buf->f_bsize = 1 << CEPH_BLOCK_SHIFT;
	buf->f_frsize = 1 << CEPH_BLOCK_SHIFT;
	buf->f_blocks = le64_to_cpu(st.kb) >> (CEPH_BLOCK_SHIFT-10);
	buf->f_bfree = le64_to_cpu(st.kb_avail) >> (CEPH_BLOCK_SHIFT-10);
	buf->f_bavail = le64_to_cpu(st.kb_avail) >> (CEPH_BLOCK_SHIFT-10);

	buf->f_files = le64_to_cpu(st.num_objects);
	buf->f_ffree = -1;
	buf->f_namelen = NAME_MAX;

	/* leave fsid little-endian, regardless of host endianness */
	fsid = *(u64 *)(&monmap->fsid) ^ *((u64 *)&monmap->fsid + 1);
	buf->f_fsid.val[0] = fsid & 0xffffffff;
	buf->f_fsid.val[1] = fsid >> 32;

	return 0;
}


static int ceph_sync_fs(struct super_block *sb, int wait)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(sb);

	if (!wait) {
		dout("sync_fs (non-blocking)\n");
		ceph_flush_dirty_caps(fsc->mdsc);
		dout("sync_fs (non-blocking) done\n");
		return 0;
	}

	dout("sync_fs (blocking)\n");
	ceph_osdc_sync(&fsc->client->osdc);
	ceph_mdsc_sync(fsc->mdsc);
	dout("sync_fs (blocking) done\n");
	return 0;
}

/*
 * mount options
 */
enum {
	Opt_wsize,
	Opt_rsize,
	Opt_rasize,
	Opt_caps_wanted_delay_min,
	Opt_caps_wanted_delay_max,
	Opt_cap_release_safety,
	Opt_readdir_max_entries,
	Opt_readdir_max_bytes,
	Opt_congestion_kb,
	Opt_last_int,
	/* int args above */
	Opt_snapdirname,
	Opt_last_string,
	/* string args above */
	Opt_dirstat,
	Opt_nodirstat,
	Opt_rbytes,
	Opt_norbytes,
	Opt_asyncreaddir,
	Opt_noasyncreaddir,
	Opt_dcache,
	Opt_nodcache,
	Opt_ino32,
	Opt_noino32,
	Opt_fscache,
	Opt_nofscache,
#ifdef CONFIG_CEPH_FS_POSIX_ACL
	Opt_acl,
#endif
	Opt_noacl
};

static match_table_t fsopt_tokens = {
	{Opt_wsize, "wsize=%d"},
	{Opt_rsize, "rsize=%d"},
	{Opt_rasize, "rasize=%d"},
	{Opt_caps_wanted_delay_min, "caps_wanted_delay_min=%d"},
	{Opt_caps_wanted_delay_max, "caps_wanted_delay_max=%d"},
	{Opt_cap_release_safety, "cap_release_safety=%d"},
	{Opt_readdir_max_entries, "readdir_max_entries=%d"},
	{Opt_readdir_max_bytes, "readdir_max_bytes=%d"},
	{Opt_congestion_kb, "write_congestion_kb=%d"},
	/* int args above */
	{Opt_snapdirname, "snapdirname=%s"},
	/* string args above */
	{Opt_dirstat, "dirstat"},
	{Opt_nodirstat, "nodirstat"},
	{Opt_rbytes, "rbytes"},
	{Opt_norbytes, "norbytes"},
	{Opt_asyncreaddir, "asyncreaddir"},
	{Opt_noasyncreaddir, "noasyncreaddir"},
	{Opt_dcache, "dcache"},
	{Opt_nodcache, "nodcache"},
	{Opt_ino32, "ino32"},
	{Opt_noino32, "noino32"},
	{Opt_fscache, "fsc"},
	{Opt_nofscache, "nofsc"},
#ifdef CONFIG_CEPH_FS_POSIX_ACL
	{Opt_acl, "acl"},
#endif
	{Opt_noacl, "noacl"},
	{-1, NULL}
};

static int parse_fsopt_token(char *c, void *private)
{
	struct ceph_mount_options *fsopt = private;
	substring_t argstr[MAX_OPT_ARGS];
	int token, intval, ret;

	token = match_token((char *)c, fsopt_tokens, argstr);
	if (token < 0)
		return -EINVAL;

	if (token < Opt_last_int) {
		ret = match_int(&argstr[0], &intval);
		if (ret < 0) {
			pr_err("bad mount option arg (not int) "
			       "at '%s'\n", c);
			return ret;
		}
		dout("got int token %d val %d\n", token, intval);
	} else if (token > Opt_last_int && token < Opt_last_string) {
		dout("got string token %d val %s\n", token,
		     argstr[0].from);
	} else {
		dout("got token %d\n", token);
	}

	switch (token) {
	case Opt_snapdirname:
		kfree(fsopt->snapdir_name);
		fsopt->snapdir_name = kstrndup(argstr[0].from,
					       argstr[0].to-argstr[0].from,
					       GFP_KERNEL);
		if (!fsopt->snapdir_name)
			return -ENOMEM;
		break;

		/* misc */
	case Opt_wsize:
		fsopt->wsize = intval;
		break;
	case Opt_rsize:
		fsopt->rsize = intval;
		break;
	case Opt_rasize:
		fsopt->rasize = intval;
		break;
	case Opt_caps_wanted_delay_min:
		fsopt->caps_wanted_delay_min = intval;
		break;
	case Opt_caps_wanted_delay_max:
		fsopt->caps_wanted_delay_max = intval;
		break;
	case Opt_readdir_max_entries:
		fsopt->max_readdir = intval;
		break;
	case Opt_readdir_max_bytes:
		fsopt->max_readdir_bytes = intval;
		break;
	case Opt_congestion_kb:
		fsopt->congestion_kb = intval;
		break;
	case Opt_dirstat:
		fsopt->flags |= CEPH_MOUNT_OPT_DIRSTAT;
		break;
	case Opt_nodirstat:
		fsopt->flags &= ~CEPH_MOUNT_OPT_DIRSTAT;
		break;
	case Opt_rbytes:
		fsopt->flags |= CEPH_MOUNT_OPT_RBYTES;
		break;
	case Opt_norbytes:
		fsopt->flags &= ~CEPH_MOUNT_OPT_RBYTES;
		break;
	case Opt_asyncreaddir:
		fsopt->flags &= ~CEPH_MOUNT_OPT_NOASYNCREADDIR;
		break;
	case Opt_noasyncreaddir:
		fsopt->flags |= CEPH_MOUNT_OPT_NOASYNCREADDIR;
		break;
	case Opt_dcache:
		fsopt->flags |= CEPH_MOUNT_OPT_DCACHE;
		break;
	case Opt_nodcache:
		fsopt->flags &= ~CEPH_MOUNT_OPT_DCACHE;
		break;
	case Opt_ino32:
		fsopt->flags |= CEPH_MOUNT_OPT_INO32;
		break;
	case Opt_noino32:
		fsopt->flags &= ~CEPH_MOUNT_OPT_INO32;
		break;
	case Opt_fscache:
		fsopt->flags |= CEPH_MOUNT_OPT_FSCACHE;
		break;
	case Opt_nofscache:
		fsopt->flags &= ~CEPH_MOUNT_OPT_FSCACHE;
		break;
#ifdef CONFIG_CEPH_FS_POSIX_ACL
	case Opt_acl:
		fsopt->sb_flags |= MS_POSIXACL;
		break;
#endif
	case Opt_noacl:
		fsopt->sb_flags &= ~MS_POSIXACL;
		break;
	default:
		BUG_ON(token);
	}
	return 0;
}

static void destroy_mount_options(struct ceph_mount_options *args)
{
	dout("destroy_mount_options %p\n", args);
	kfree(args->snapdir_name);
	kfree(args);
}

static int strcmp_null(const char *s1, const char *s2)
{
	if (!s1 && !s2)
		return 0;
	if (s1 && !s2)
		return -1;
	if (!s1 && s2)
		return 1;
	return strcmp(s1, s2);
}

static int compare_mount_options(struct ceph_mount_options *new_fsopt,
				 struct ceph_options *new_opt,
				 struct ceph_fs_client *fsc)
{
	struct ceph_mount_options *fsopt1 = new_fsopt;
	struct ceph_mount_options *fsopt2 = fsc->mount_options;
	int ofs = offsetof(struct ceph_mount_options, snapdir_name);
	int ret;

	ret = memcmp(fsopt1, fsopt2, ofs);
	if (ret)
		return ret;

	ret = strcmp_null(fsopt1->snapdir_name, fsopt2->snapdir_name);
	if (ret)
		return ret;

	return ceph_compare_options(new_opt, fsc->client);
}

static int parse_mount_options(struct ceph_mount_options **pfsopt,
			       struct ceph_options **popt,
			       int flags, char *options,
			       const char *dev_name,
			       const char **path)
{
	struct ceph_mount_options *fsopt;
	const char *dev_name_end;
	int err;

	if (!dev_name || !*dev_name)
		return -EINVAL;

	fsopt = kzalloc(sizeof(*fsopt), GFP_KERNEL);
	if (!fsopt)
		return -ENOMEM;

	dout("parse_mount_options %p, dev_name '%s'\n", fsopt, dev_name);

	fsopt->sb_flags = flags;
	fsopt->flags = CEPH_MOUNT_OPT_DEFAULT;

	fsopt->rsize = CEPH_RSIZE_DEFAULT;
	fsopt->rasize = CEPH_RASIZE_DEFAULT;
	fsopt->snapdir_name = kstrdup(CEPH_SNAPDIRNAME_DEFAULT, GFP_KERNEL);
	fsopt->caps_wanted_delay_min = CEPH_CAPS_WANTED_DELAY_MIN_DEFAULT;
	fsopt->caps_wanted_delay_max = CEPH_CAPS_WANTED_DELAY_MAX_DEFAULT;
	fsopt->cap_release_safety = CEPH_CAP_RELEASE_SAFETY_DEFAULT;
	fsopt->max_readdir = CEPH_MAX_READDIR_DEFAULT;
	fsopt->max_readdir_bytes = CEPH_MAX_READDIR_BYTES_DEFAULT;
	fsopt->congestion_kb = default_congestion_kb();

	/*
	 * Distinguish the server list from the path in "dev_name".
	 * Internally we do not include the leading '/' in the path.
	 *
	 * "dev_name" will look like:
	 *     <server_spec>[,<server_spec>...]:[<path>]
	 * where
	 *     <server_spec> is <ip>[:<port>]
	 *     <path> is optional, but if present must begin with '/'
	 */
	dev_name_end = strchr(dev_name, '/');
	if (dev_name_end) {
		/* skip over leading '/' for path */
		*path = dev_name_end + 1;
	} else {
		/* path is empty */
		dev_name_end = dev_name + strlen(dev_name);
		*path = dev_name_end;
	}
	err = -EINVAL;
	dev_name_end--;		/* back up to ':' separator */
	if (dev_name_end < dev_name || *dev_name_end != ':') {
		pr_err("device name is missing path (no : separator in %s)\n",
				dev_name);
		goto out;
	}
	dout("device name '%.*s'\n", (int)(dev_name_end - dev_name), dev_name);
	dout("server path '%s'\n", *path);

	*popt = ceph_parse_options(options, dev_name, dev_name_end,
				 parse_fsopt_token, (void *)fsopt);
	if (IS_ERR(*popt)) {
		err = PTR_ERR(*popt);
		goto out;
	}

	/* success */
	*pfsopt = fsopt;
	return 0;

out:
	destroy_mount_options(fsopt);
	return err;
}

/**
 * ceph_show_options - Show mount options in /proc/mounts
 * @m: seq_file to write to
 * @root: root of that (sub)tree
 */
static int ceph_show_options(struct seq_file *m, struct dentry *root)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(root->d_sb);
	struct ceph_mount_options *fsopt = fsc->mount_options;
	struct ceph_options *opt = fsc->client->options;

	if (opt->flags & CEPH_OPT_FSID)
		seq_printf(m, ",fsid=%pU", &opt->fsid);
	if (opt->flags & CEPH_OPT_NOSHARE)
		seq_puts(m, ",noshare");
	if (opt->flags & CEPH_OPT_NOCRC)
		seq_puts(m, ",nocrc");

	if (opt->name)
		seq_printf(m, ",name=%s", opt->name);
	if (opt->key)
		seq_puts(m, ",secret=<hidden>");

	if (opt->mount_timeout != CEPH_MOUNT_TIMEOUT_DEFAULT)
		seq_printf(m, ",mount_timeout=%d", opt->mount_timeout);
	if (opt->osd_idle_ttl != CEPH_OSD_IDLE_TTL_DEFAULT)
		seq_printf(m, ",osd_idle_ttl=%d", opt->osd_idle_ttl);
	if (opt->osd_keepalive_timeout != CEPH_OSD_KEEPALIVE_DEFAULT)
		seq_printf(m, ",osdkeepalivetimeout=%d",
			   opt->osd_keepalive_timeout);

	if (fsopt->flags & CEPH_MOUNT_OPT_DIRSTAT)
		seq_puts(m, ",dirstat");
	if ((fsopt->flags & CEPH_MOUNT_OPT_RBYTES) == 0)
		seq_puts(m, ",norbytes");
	if (fsopt->flags & CEPH_MOUNT_OPT_NOASYNCREADDIR)
		seq_puts(m, ",noasyncreaddir");
	if (fsopt->flags & CEPH_MOUNT_OPT_DCACHE)
		seq_puts(m, ",dcache");
	else
		seq_puts(m, ",nodcache");
	if (fsopt->flags & CEPH_MOUNT_OPT_FSCACHE)
		seq_puts(m, ",fsc");
	else
		seq_puts(m, ",nofsc");

#ifdef CONFIG_CEPH_FS_POSIX_ACL
	if (fsopt->sb_flags & MS_POSIXACL)
		seq_puts(m, ",acl");
	else
		seq_puts(m, ",noacl");
#endif

	if (fsopt->wsize)
		seq_printf(m, ",wsize=%d", fsopt->wsize);
	if (fsopt->rsize != CEPH_RSIZE_DEFAULT)
		seq_printf(m, ",rsize=%d", fsopt->rsize);
	if (fsopt->rasize != CEPH_RASIZE_DEFAULT)
		seq_printf(m, ",rasize=%d", fsopt->rasize);
	if (fsopt->congestion_kb != default_congestion_kb())
		seq_printf(m, ",write_congestion_kb=%d", fsopt->congestion_kb);
	if (fsopt->caps_wanted_delay_min != CEPH_CAPS_WANTED_DELAY_MIN_DEFAULT)
		seq_printf(m, ",caps_wanted_delay_min=%d",
			 fsopt->caps_wanted_delay_min);
	if (fsopt->caps_wanted_delay_max != CEPH_CAPS_WANTED_DELAY_MAX_DEFAULT)
		seq_printf(m, ",caps_wanted_delay_max=%d",
			   fsopt->caps_wanted_delay_max);
	if (fsopt->cap_release_safety != CEPH_CAP_RELEASE_SAFETY_DEFAULT)
		seq_printf(m, ",cap_release_safety=%d",
			   fsopt->cap_release_safety);
	if (fsopt->max_readdir != CEPH_MAX_READDIR_DEFAULT)
		seq_printf(m, ",readdir_max_entries=%d", fsopt->max_readdir);
	if (fsopt->max_readdir_bytes != CEPH_MAX_READDIR_BYTES_DEFAULT)
		seq_printf(m, ",readdir_max_bytes=%d", fsopt->max_readdir_bytes);
	if (strcmp(fsopt->snapdir_name, CEPH_SNAPDIRNAME_DEFAULT))
		seq_printf(m, ",snapdirname=%s", fsopt->snapdir_name);
	return 0;
}

/*
 * handle any mon messages the standard library doesn't understand.
 * return error if we don't either.
 */
static int extra_mon_dispatch(struct ceph_client *client, struct ceph_msg *msg)
{
	struct ceph_fs_client *fsc = client->private;
	int type = le16_to_cpu(msg->hdr.type);

	switch (type) {
	case CEPH_MSG_MDS_MAP:
		ceph_mdsc_handle_map(fsc->mdsc, msg);
		return 0;

	default:
		return -1;
	}
}

/*
 * create a new fs client
 */
static struct ceph_fs_client *create_fs_client(struct ceph_mount_options *fsopt,
					struct ceph_options *opt)
{
	struct ceph_fs_client *fsc;
	const u64 supported_features =
		CEPH_FEATURE_FLOCK |
		CEPH_FEATURE_DIRLAYOUTHASH;
	const u64 required_features = 0;
	int page_count;
	size_t size;
	int err = -ENOMEM;

	fsc = kzalloc(sizeof(*fsc), GFP_KERNEL);
	if (!fsc)
		return ERR_PTR(-ENOMEM);

	fsc->client = ceph_create_client(opt, fsc, supported_features,
					 required_features);
	if (IS_ERR(fsc->client)) {
		err = PTR_ERR(fsc->client);
		goto fail;
	}
	fsc->client->extra_mon_dispatch = extra_mon_dispatch;
	fsc->client->monc.want_mdsmap = 1;

	fsc->mount_options = fsopt;

	fsc->sb = NULL;
	fsc->mount_state = CEPH_MOUNT_MOUNTING;

	atomic_long_set(&fsc->writeback_count, 0);

	err = bdi_init(&fsc->backing_dev_info);
	if (err < 0)
		goto fail_client;

	err = -ENOMEM;
	/*
	 * The number of concurrent works can be high but they don't need
	 * to be processed in parallel, limit concurrency.
	 */
	fsc->wb_wq = alloc_workqueue("ceph-writeback", 0, 1);
	if (fsc->wb_wq == NULL)
		goto fail_bdi;
	fsc->pg_inv_wq = alloc_workqueue("ceph-pg-invalid", 0, 1);
	if (fsc->pg_inv_wq == NULL)
		goto fail_wb_wq;
	fsc->trunc_wq = alloc_workqueue("ceph-trunc", 0, 1);
	if (fsc->trunc_wq == NULL)
		goto fail_pg_inv_wq;

	/* set up mempools */
	err = -ENOMEM;
	page_count = fsc->mount_options->wsize >> PAGE_CACHE_SHIFT;
	size = sizeof (struct page *) * (page_count ? page_count : 1);
	fsc->wb_pagevec_pool = mempool_create_kmalloc_pool(10, size);
	if (!fsc->wb_pagevec_pool)
		goto fail_trunc_wq;

	/* setup fscache */
	if ((fsopt->flags & CEPH_MOUNT_OPT_FSCACHE) &&
	    (ceph_fscache_register_fs(fsc) != 0))
		goto fail_fscache;

	/* caps */
	fsc->min_caps = fsopt->max_readdir;

	return fsc;

fail_fscache:
	ceph_fscache_unregister_fs(fsc);
fail_trunc_wq:
	destroy_workqueue(fsc->trunc_wq);
fail_pg_inv_wq:
	destroy_workqueue(fsc->pg_inv_wq);
fail_wb_wq:
	destroy_workqueue(fsc->wb_wq);
fail_bdi:
	bdi_destroy(&fsc->backing_dev_info);
fail_client:
	ceph_destroy_client(fsc->client);
fail:
	kfree(fsc);
	return ERR_PTR(err);
}

static void destroy_fs_client(struct ceph_fs_client *fsc)
{
	dout("destroy_fs_client %p\n", fsc);

	ceph_fscache_unregister_fs(fsc);

	destroy_workqueue(fsc->wb_wq);
	destroy_workqueue(fsc->pg_inv_wq);
	destroy_workqueue(fsc->trunc_wq);

	bdi_destroy(&fsc->backing_dev_info);

	mempool_destroy(fsc->wb_pagevec_pool);

	destroy_mount_options(fsc->mount_options);

	ceph_fs_debugfs_cleanup(fsc);

	ceph_destroy_client(fsc->client);

	kfree(fsc);
	dout("destroy_fs_client %p done\n", fsc);
}

/*
 * caches
 */
struct kmem_cache *ceph_inode_cachep;
struct kmem_cache *ceph_cap_cachep;
struct kmem_cache *ceph_dentry_cachep;
struct kmem_cache *ceph_file_cachep;

static void ceph_inode_init_once(void *foo)
{
	struct ceph_inode_info *ci = foo;
	inode_init_once(&ci->vfs_inode);
}

static int __init init_caches(void)
{
	int error = -ENOMEM;

	ceph_inode_cachep = kmem_cache_create("ceph_inode_info",
				      sizeof(struct ceph_inode_info),
				      __alignof__(struct ceph_inode_info),
				      (SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD),
				      ceph_inode_init_once);
	if (ceph_inode_cachep == NULL)
		return -ENOMEM;

	ceph_cap_cachep = KMEM_CACHE(ceph_cap,
				     SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD);
	if (ceph_cap_cachep == NULL)
		goto bad_cap;

	ceph_dentry_cachep = KMEM_CACHE(ceph_dentry_info,
					SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD);
	if (ceph_dentry_cachep == NULL)
		goto bad_dentry;

	ceph_file_cachep = KMEM_CACHE(ceph_file_info,
				      SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD);
	if (ceph_file_cachep == NULL)
		goto bad_file;

	if ((error = ceph_fscache_register()))
		goto bad_file;

	return 0;
bad_file:
	kmem_cache_destroy(ceph_dentry_cachep);
bad_dentry:
	kmem_cache_destroy(ceph_cap_cachep);
bad_cap:
	kmem_cache_destroy(ceph_inode_cachep);
	return error;
}

static void destroy_caches(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();

	kmem_cache_destroy(ceph_inode_cachep);
	kmem_cache_destroy(ceph_cap_cachep);
	kmem_cache_destroy(ceph_dentry_cachep);
	kmem_cache_destroy(ceph_file_cachep);

	ceph_fscache_unregister();
}


/*
 * ceph_umount_begin - initiate forced umount.  Tear down down the
 * mount, skipping steps that may hang while waiting for server(s).
 */
static void ceph_umount_begin(struct super_block *sb)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(sb);

	dout("ceph_umount_begin - starting forced umount\n");
	if (!fsc)
		return;
	fsc->mount_state = CEPH_MOUNT_SHUTDOWN;
	return;
}

static const struct super_operations ceph_super_ops = {
	.alloc_inode	= ceph_alloc_inode,
	.destroy_inode	= ceph_destroy_inode,
	.write_inode    = ceph_write_inode,
	.drop_inode	= ceph_drop_inode,
	.sync_fs        = ceph_sync_fs,
	.put_super	= ceph_put_super,
	.show_options   = ceph_show_options,
	.statfs		= ceph_statfs,
	.umount_begin   = ceph_umount_begin,
};

/*
 * Bootstrap mount by opening the root directory.  Note the mount
 * @started time from caller, and time out if this takes too long.
 */
static struct dentry *open_root_dentry(struct ceph_fs_client *fsc,
				       const char *path,
				       unsigned long started)
{
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req = NULL;
	int err;
	struct dentry *root;

	/* open dir */
	dout("open_root_inode opening '%s'\n", path);
	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_GETATTR, USE_ANY_MDS);
	if (IS_ERR(req))
		return ERR_CAST(req);
	req->r_path1 = kstrdup(path, GFP_NOFS);
	req->r_ino1.ino = CEPH_INO_ROOT;
	req->r_ino1.snap = CEPH_NOSNAP;
	req->r_started = started;
	req->r_timeout = fsc->client->options->mount_timeout * HZ;
	req->r_args.getattr.mask = cpu_to_le32(CEPH_STAT_CAP_INODE);
	req->r_num_caps = 2;
	err = ceph_mdsc_do_request(mdsc, NULL, req);
	if (err == 0) {
		struct inode *inode = req->r_target_inode;
		req->r_target_inode = NULL;
		dout("open_root_inode success\n");
		if (ceph_ino(inode) == CEPH_INO_ROOT &&
		    fsc->sb->s_root == NULL) {
			root = d_make_root(inode);
			if (!root) {
				root = ERR_PTR(-ENOMEM);
				goto out;
			}
		} else {
			root = d_obtain_root(inode);
		}
		ceph_init_dentry(root);
		dout("open_root_inode success, root dentry is %p\n", root);
	} else {
		root = ERR_PTR(err);
	}
out:
	ceph_mdsc_put_request(req);
	return root;
}




/*
 * mount: join the ceph cluster, and open root directory.
 */
static struct dentry *ceph_real_mount(struct ceph_fs_client *fsc,
		      const char *path)
{
	int err;
	unsigned long started = jiffies;  /* note the start time */
	struct dentry *root;
	int first = 0;   /* first vfsmount for this super_block */

	dout("mount start\n");
	mutex_lock(&fsc->client->mount_mutex);

	err = __ceph_open_session(fsc->client, started);
	if (err < 0)
		goto out;

	dout("mount opening root\n");
	root = open_root_dentry(fsc, "", started);
	if (IS_ERR(root)) {
		err = PTR_ERR(root);
		goto out;
	}
	if (fsc->sb->s_root) {
		dput(root);
	} else {
		fsc->sb->s_root = root;
		first = 1;

		err = ceph_fs_debugfs_init(fsc);
		if (err < 0)
			goto fail;
	}

	if (path[0] == 0) {
		dget(root);
	} else {
		dout("mount opening base mountpoint\n");
		root = open_root_dentry(fsc, path, started);
		if (IS_ERR(root)) {
			err = PTR_ERR(root);
			goto fail;
		}
	}

	fsc->mount_state = CEPH_MOUNT_MOUNTED;
	dout("mount success\n");
	mutex_unlock(&fsc->client->mount_mutex);
	return root;

out:
	mutex_unlock(&fsc->client->mount_mutex);
	return ERR_PTR(err);

fail:
	if (first) {
		dput(fsc->sb->s_root);
		fsc->sb->s_root = NULL;
	}
	goto out;
}

static int ceph_set_super(struct super_block *s, void *data)
{
	struct ceph_fs_client *fsc = data;
	int ret;

	dout("set_super %p data %p\n", s, data);

	s->s_flags = fsc->mount_options->sb_flags;
	s->s_maxbytes = 1ULL << 40;  /* temp value until we get mdsmap */

	s->s_xattr = ceph_xattr_handlers;
	s->s_fs_info = fsc;
	fsc->sb = s;

	s->s_op = &ceph_super_ops;
	s->s_export_op = &ceph_export_ops;

	s->s_time_gran = 1000;  /* 1000 ns == 1 us */

	ret = set_anon_super(s, NULL);  /* what is that second arg for? */
	if (ret != 0)
		goto fail;

	return ret;

fail:
	s->s_fs_info = NULL;
	fsc->sb = NULL;
	return ret;
}

/*
 * share superblock if same fs AND options
 */
static int ceph_compare_super(struct super_block *sb, void *data)
{
	struct ceph_fs_client *new = data;
	struct ceph_mount_options *fsopt = new->mount_options;
	struct ceph_options *opt = new->client->options;
	struct ceph_fs_client *other = ceph_sb_to_client(sb);

	dout("ceph_compare_super %p\n", sb);

	if (compare_mount_options(fsopt, opt, other)) {
		dout("monitor(s)/mount options don't match\n");
		return 0;
	}
	if ((opt->flags & CEPH_OPT_FSID) &&
	    ceph_fsid_compare(&opt->fsid, &other->client->fsid)) {
		dout("fsid doesn't match\n");
		return 0;
	}
	if (fsopt->sb_flags != other->mount_options->sb_flags) {
		dout("flags differ\n");
		return 0;
	}
	return 1;
}

/*
 * construct our own bdi so we can control readahead, etc.
 */
static atomic_long_t bdi_seq = ATOMIC_LONG_INIT(0);

static int ceph_register_bdi(struct super_block *sb,
			     struct ceph_fs_client *fsc)
{
	int err;

	/* set ra_pages based on rasize mount option? */
	if (fsc->mount_options->rasize >= PAGE_CACHE_SIZE)
		fsc->backing_dev_info.ra_pages =
			(fsc->mount_options->rasize + PAGE_CACHE_SIZE - 1)
			>> PAGE_SHIFT;
	else
		fsc->backing_dev_info.ra_pages =
			default_backing_dev_info.ra_pages;

	err = bdi_register(&fsc->backing_dev_info, NULL, "ceph-%ld",
			   atomic_long_inc_return(&bdi_seq));
	if (!err)
		sb->s_bdi = &fsc->backing_dev_info;
	return err;
}

static struct dentry *ceph_mount(struct file_system_type *fs_type,
		       int flags, const char *dev_name, void *data)
{
	struct super_block *sb;
	struct ceph_fs_client *fsc;
	struct dentry *res;
	int err;
	int (*compare_super)(struct super_block *, void *) = ceph_compare_super;
	const char *path = NULL;
	struct ceph_mount_options *fsopt = NULL;
	struct ceph_options *opt = NULL;

	dout("ceph_mount\n");

#ifdef CONFIG_CEPH_FS_POSIX_ACL
	flags |= MS_POSIXACL;
#endif
	err = parse_mount_options(&fsopt, &opt, flags, data, dev_name, &path);
	if (err < 0) {
		res = ERR_PTR(err);
		goto out_final;
	}

	/* create client (which we may/may not use) */
	fsc = create_fs_client(fsopt, opt);
	if (IS_ERR(fsc)) {
		res = ERR_CAST(fsc);
		destroy_mount_options(fsopt);
		ceph_destroy_options(opt);
		goto out_final;
	}

	err = ceph_mdsc_init(fsc);
	if (err < 0) {
		res = ERR_PTR(err);
		goto out;
	}

	if (ceph_test_opt(fsc->client, NOSHARE))
		compare_super = NULL;
	sb = sget(fs_type, compare_super, ceph_set_super, flags, fsc);
	if (IS_ERR(sb)) {
		res = ERR_CAST(sb);
		goto out;
	}

	if (ceph_sb_to_client(sb) != fsc) {
		ceph_mdsc_destroy(fsc);
		destroy_fs_client(fsc);
		fsc = ceph_sb_to_client(sb);
		dout("get_sb got existing client %p\n", fsc);
	} else {
		dout("get_sb using new client %p\n", fsc);
		err = ceph_register_bdi(sb, fsc);
		if (err < 0) {
			res = ERR_PTR(err);
			goto out_splat;
		}
	}

	res = ceph_real_mount(fsc, path);
	if (IS_ERR(res))
		goto out_splat;
	dout("root %p inode %p ino %llx.%llx\n", res,
	     res->d_inode, ceph_vinop(res->d_inode));
	return res;

out_splat:
	ceph_mdsc_close_sessions(fsc->mdsc);
	deactivate_locked_super(sb);
	goto out_final;

out:
	ceph_mdsc_destroy(fsc);
	destroy_fs_client(fsc);
out_final:
	dout("ceph_mount fail %ld\n", PTR_ERR(res));
	return res;
}

static void ceph_kill_sb(struct super_block *s)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(s);
	dout("kill_sb %p\n", s);
	ceph_mdsc_pre_umount(fsc->mdsc);
	kill_anon_super(s);    /* will call put_super after sb is r/o */
	ceph_mdsc_destroy(fsc);
	destroy_fs_client(fsc);
}

static struct file_system_type ceph_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ceph",
	.mount		= ceph_mount,
	.kill_sb	= ceph_kill_sb,
	.fs_flags	= FS_RENAME_DOES_D_MOVE,
};
MODULE_ALIAS_FS("ceph");

#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

static int __init init_ceph(void)
{
	int ret = init_caches();
	if (ret)
		goto out;

	ceph_flock_init();
	ceph_xattr_init();
	ret = register_filesystem(&ceph_fs_type);
	if (ret)
		goto out_icache;

	pr_info("loaded (mds proto %d)\n", CEPH_MDSC_PROTOCOL);

	return 0;

out_icache:
	ceph_xattr_exit();
	destroy_caches();
out:
	return ret;
}

static void __exit exit_ceph(void)
{
	dout("exit_ceph\n");
	unregister_filesystem(&ceph_fs_type);
	ceph_xattr_exit();
	destroy_caches();
}

module_init(init_ceph);
module_exit(exit_ceph);

MODULE_AUTHOR("Sage Weil <sage@newdream.net>");
MODULE_AUTHOR("Yehuda Sadeh <yehuda@hq.newdream.net>");
MODULE_AUTHOR("Patience Warnick <patience@newdream.net>");
MODULE_DESCRIPTION("Ceph filesystem for Linux");
MODULE_LICENSE("GPL");
/************************************************************/
/* ../linux-3.17/fs/ceph/super.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

// #include <linux/module.h>
// #include <linux/fs.h>
// #include <linux/slab.h>
// #include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/namei.h>
#include <linux/writeback.h>
#include <linux/vmalloc.h>
#include <linux/posix_acl.h>
#include <linux/random.h>

// #include "super.h"
// #include "mds_client.h"
// #include "cache.h"
// #include <linux/ceph/decode.h>

/*
 * Ceph inode operations
 *
 * Implement basic inode helpers (get, alloc) and inode ops (getattr,
 * setattr, etc.), xattr helpers, and helpers for assimilating
 * metadata returned by the MDS into our cache.
 *
 * Also define helpers for doing asynchronous writeback, invalidation,
 * and truncation for the benefit of those who can't afford to block
 * (typically because they are in the message handler path).
 */

static const struct inode_operations ceph_symlink_iops;

static void ceph_invalidate_work(struct work_struct *work);
static void ceph_writeback_work(struct work_struct *work);
static void ceph_vmtruncate_work(struct work_struct *work);

/*
 * find or create an inode, given the ceph ino number
 */
static int ceph_set_ino_cb(struct inode *inode, void *data)
{
	ceph_inode(inode)->i_vino = *(struct ceph_vino *)data;
	inode->i_ino = ceph_vino_to_ino(*(struct ceph_vino *)data);
	return 0;
}

struct inode *ceph_get_inode(struct super_block *sb, struct ceph_vino vino)
{
	struct inode *inode;
	ino_t t = ceph_vino_to_ino(vino);

	inode = iget5_locked(sb, t, ceph_ino_compare, ceph_set_ino_cb, &vino);
	if (inode == NULL)
		return ERR_PTR(-ENOMEM);
	if (inode->i_state & I_NEW) {
		dout("get_inode created new inode %p %llx.%llx ino %llx\n",
		     inode, ceph_vinop(inode), (u64)inode->i_ino);
		unlock_new_inode(inode);
	}

	dout("get_inode on %lu=%llx.%llx got %p\n", inode->i_ino, vino.ino,
	     vino.snap, inode);
	return inode;
}

/*
 * get/constuct snapdir inode for a given directory
 */
struct inode *ceph_get_snapdir(struct inode *parent)
{
	struct ceph_vino vino = {
		.ino = ceph_ino(parent),
		.snap = CEPH_SNAPDIR,
	};
	struct inode *inode = ceph_get_inode(parent->i_sb, vino);
	struct ceph_inode_info *ci = ceph_inode(inode);

	BUG_ON(!S_ISDIR(parent->i_mode));
	if (IS_ERR(inode))
		return inode;
	inode->i_mode = parent->i_mode;
	inode->i_uid = parent->i_uid;
	inode->i_gid = parent->i_gid;
	inode->i_op = &ceph_dir_iops;
	inode->i_fop = &ceph_dir_fops;
	ci->i_snap_caps = CEPH_CAP_PIN; /* so we can open */
	ci->i_rbytes = 0;
	return inode;
}

const struct inode_operations ceph_file_iops = {
	.permission = ceph_permission,
	.setattr = ceph_setattr,
	.getattr = ceph_getattr,
	.setxattr = ceph_setxattr,
	.getxattr = ceph_getxattr,
	.listxattr = ceph_listxattr,
	.removexattr = ceph_removexattr,
	.get_acl = ceph_get_acl,
	.set_acl = ceph_set_acl,
};


/*
 * We use a 'frag tree' to keep track of the MDS's directory fragments
 * for a given inode (usually there is just a single fragment).  We
 * need to know when a child frag is delegated to a new MDS, or when
 * it is flagged as replicated, so we can direct our requests
 * accordingly.
 */

/*
 * find/create a frag in the tree
 */
static struct ceph_inode_frag *__get_or_create_frag(struct ceph_inode_info *ci,
						    u32 f)
{
	struct rb_node **p;
	struct rb_node *parent = NULL;
	struct ceph_inode_frag *frag;
	int c;

	p = &ci->i_fragtree.rb_node;
	while (*p) {
		parent = *p;
		frag = rb_entry(parent, struct ceph_inode_frag, node);
		c = ceph_frag_compare(f, frag->frag);
		if (c < 0)
			p = &(*p)->rb_left;
		else if (c > 0)
			p = &(*p)->rb_right;
		else
			return frag;
	}

	frag = kmalloc(sizeof(*frag), GFP_NOFS);
	if (!frag) {
		pr_err("__get_or_create_frag ENOMEM on %p %llx.%llx "
		       "frag %x\n", &ci->vfs_inode,
		       ceph_vinop(&ci->vfs_inode), f);
		return ERR_PTR(-ENOMEM);
	}
	frag->frag = f;
	frag->split_by = 0;
	frag->mds = -1;
	frag->ndist = 0;

	rb_link_node(&frag->node, parent, p);
	rb_insert_color(&frag->node, &ci->i_fragtree);

	dout("get_or_create_frag added %llx.%llx frag %x\n",
	     ceph_vinop(&ci->vfs_inode), f);
	return frag;
}

/*
 * find a specific frag @f
 */
struct ceph_inode_frag *__ceph_find_frag(struct ceph_inode_info *ci, u32 f)
{
	struct rb_node *n = ci->i_fragtree.rb_node;

	while (n) {
		struct ceph_inode_frag *frag =
			rb_entry(n, struct ceph_inode_frag, node);
		int c = ceph_frag_compare(f, frag->frag);
		if (c < 0)
			n = n->rb_left;
		else if (c > 0)
			n = n->rb_right;
		else
			return frag;
	}
	return NULL;
}

/*
 * Choose frag containing the given value @v.  If @pfrag is
 * specified, copy the frag delegation info to the caller if
 * it is present.
 */
static u32 __ceph_choose_frag(struct ceph_inode_info *ci, u32 v,
			      struct ceph_inode_frag *pfrag, int *found)
{
	u32 t = ceph_frag_make(0, 0);
	struct ceph_inode_frag *frag;
	unsigned nway, i;
	u32 n;

	if (found)
		*found = 0;

	while (1) {
		WARN_ON(!ceph_frag_contains_value(t, v));
		frag = __ceph_find_frag(ci, t);
		if (!frag)
			break; /* t is a leaf */
		if (frag->split_by == 0) {
			if (pfrag)
				memcpy(pfrag, frag, sizeof(*pfrag));
			if (found)
				*found = 1;
			break;
		}

		/* choose child */
		nway = 1 << frag->split_by;
		dout("choose_frag(%x) %x splits by %d (%d ways)\n", v, t,
		     frag->split_by, nway);
		for (i = 0; i < nway; i++) {
			n = ceph_frag_make_child(t, frag->split_by, i);
			if (ceph_frag_contains_value(n, v)) {
				t = n;
				break;
			}
		}
		BUG_ON(i == nway);
	}
	dout("choose_frag(%x) = %x\n", v, t);

	return t;
}

u32 ceph_choose_frag(struct ceph_inode_info *ci, u32 v,
		     struct ceph_inode_frag *pfrag, int *found)
{
	u32 ret;
	mutex_lock(&ci->i_fragtree_mutex);
	ret = __ceph_choose_frag(ci, v, pfrag, found);
	mutex_unlock(&ci->i_fragtree_mutex);
	return ret;
}

/*
 * Process dirfrag (delegation) info from the mds.  Include leaf
 * fragment in tree ONLY if ndist > 0.  Otherwise, only
 * branches/splits are included in i_fragtree)
 */
static int ceph_fill_dirfrag(struct inode *inode,
			     struct ceph_mds_reply_dirfrag *dirinfo)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_inode_frag *frag;
	u32 id = le32_to_cpu(dirinfo->frag);
	int mds = le32_to_cpu(dirinfo->auth);
	int ndist = le32_to_cpu(dirinfo->ndist);
	int diri_auth = -1;
	int i;
	int err = 0;

	spin_lock(&ci->i_ceph_lock);
	if (ci->i_auth_cap)
		diri_auth = ci->i_auth_cap->mds;
	spin_unlock(&ci->i_ceph_lock);

	mutex_lock(&ci->i_fragtree_mutex);
	if (ndist == 0 && mds == diri_auth) {
		/* no delegation info needed. */
		frag = __ceph_find_frag(ci, id);
		if (!frag)
			goto out;
		if (frag->split_by == 0) {
			/* tree leaf, remove */
			dout("fill_dirfrag removed %llx.%llx frag %x"
			     " (no ref)\n", ceph_vinop(inode), id);
			rb_erase(&frag->node, &ci->i_fragtree);
			kfree(frag);
		} else {
			/* tree branch, keep and clear */
			dout("fill_dirfrag cleared %llx.%llx frag %x"
			     " referral\n", ceph_vinop(inode), id);
			frag->mds = -1;
			frag->ndist = 0;
		}
		goto out;
	}


	/* find/add this frag to store mds delegation info */
	frag = __get_or_create_frag(ci, id);
	if (IS_ERR(frag)) {
		/* this is not the end of the world; we can continue
		   with bad/inaccurate delegation info */
		pr_err("fill_dirfrag ENOMEM on mds ref %llx.%llx fg %x\n",
		       ceph_vinop(inode), le32_to_cpu(dirinfo->frag));
		err = -ENOMEM;
		goto out;
	}

	frag->mds = mds;
	frag->ndist = min_t(u32, ndist, CEPH_MAX_DIRFRAG_REP);
	for (i = 0; i < frag->ndist; i++)
		frag->dist[i] = le32_to_cpu(dirinfo->dist[i]);
	dout("fill_dirfrag %llx.%llx frag %x ndist=%d\n",
	     ceph_vinop(inode), frag->frag, frag->ndist);

out:
	mutex_unlock(&ci->i_fragtree_mutex);
	return err;
}

static int ceph_fill_fragtree(struct inode *inode,
			      struct ceph_frag_tree_head *fragtree,
			      struct ceph_mds_reply_dirfrag *dirinfo)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_inode_frag *frag;
	struct rb_node *rb_node;
	int i;
	u32 id, nsplits;
	bool update = false;

	mutex_lock(&ci->i_fragtree_mutex);
	nsplits = le32_to_cpu(fragtree->nsplits);
	if (nsplits) {
		i = prandom_u32() % nsplits;
		id = le32_to_cpu(fragtree->splits[i].frag);
		if (!__ceph_find_frag(ci, id))
			update = true;
	} else if (!RB_EMPTY_ROOT(&ci->i_fragtree)) {
		rb_node = rb_first(&ci->i_fragtree);
		frag = rb_entry(rb_node, struct ceph_inode_frag, node);
		if (frag->frag != ceph_frag_make(0, 0) || rb_next(rb_node))
			update = true;
	}
	if (!update && dirinfo) {
		id = le32_to_cpu(dirinfo->frag);
		if (id != __ceph_choose_frag(ci, id, NULL, NULL))
			update = true;
	}
	if (!update)
		goto out_unlock;

	dout("fill_fragtree %llx.%llx\n", ceph_vinop(inode));
	rb_node = rb_first(&ci->i_fragtree);
	for (i = 0; i < nsplits; i++) {
		id = le32_to_cpu(fragtree->splits[i].frag);
		frag = NULL;
		while (rb_node) {
			frag = rb_entry(rb_node, struct ceph_inode_frag, node);
			if (ceph_frag_compare(frag->frag, id) >= 0) {
				if (frag->frag != id)
					frag = NULL;
				else
					rb_node = rb_next(rb_node);
				break;
			}
			rb_node = rb_next(rb_node);
			rb_erase(&frag->node, &ci->i_fragtree);
			kfree(frag);
			frag = NULL;
		}
		if (!frag) {
			frag = __get_or_create_frag(ci, id);
			if (IS_ERR(frag))
				continue;
		}
		frag->split_by = le32_to_cpu(fragtree->splits[i].by);
		dout(" frag %x split by %d\n", frag->frag, frag->split_by);
	}
	while (rb_node) {
		frag = rb_entry(rb_node, struct ceph_inode_frag, node);
		rb_node = rb_next(rb_node);
		rb_erase(&frag->node, &ci->i_fragtree);
		kfree(frag);
	}
out_unlock:
	mutex_unlock(&ci->i_fragtree_mutex);
	return 0;
}

/*
 * initialize a newly allocated inode.
 */
struct inode *ceph_alloc_inode(struct super_block *sb)
{
	struct ceph_inode_info *ci;
	int i;

	ci = kmem_cache_alloc(ceph_inode_cachep, GFP_NOFS);
	if (!ci)
		return NULL;

	dout("alloc_inode %p\n", &ci->vfs_inode);

	spin_lock_init(&ci->i_ceph_lock);

	ci->i_version = 0;
	ci->i_time_warp_seq = 0;
	ci->i_ceph_flags = 0;
	atomic_set(&ci->i_release_count, 1);
	atomic_set(&ci->i_complete_count, 0);
	ci->i_symlink = NULL;

	memset(&ci->i_dir_layout, 0, sizeof(ci->i_dir_layout));

	ci->i_fragtree = RB_ROOT;
	mutex_init(&ci->i_fragtree_mutex);

	ci->i_xattrs.blob = NULL;
	ci->i_xattrs.prealloc_blob = NULL;
	ci->i_xattrs.dirty = false;
	ci->i_xattrs.index = RB_ROOT;
	ci->i_xattrs.count = 0;
	ci->i_xattrs.names_size = 0;
	ci->i_xattrs.vals_size = 0;
	ci->i_xattrs.version = 0;
	ci->i_xattrs.index_version = 0;

	ci->i_caps = RB_ROOT;
	ci->i_auth_cap = NULL;
	ci->i_dirty_caps = 0;
	ci->i_flushing_caps = 0;
	INIT_LIST_HEAD(&ci->i_dirty_item);
	INIT_LIST_HEAD(&ci->i_flushing_item);
	ci->i_cap_flush_seq = 0;
	ci->i_cap_flush_last_tid = 0;
	memset(&ci->i_cap_flush_tid, 0, sizeof(ci->i_cap_flush_tid));
	init_waitqueue_head(&ci->i_cap_wq);
	ci->i_hold_caps_min = 0;
	ci->i_hold_caps_max = 0;
	INIT_LIST_HEAD(&ci->i_cap_delay_list);
	INIT_LIST_HEAD(&ci->i_cap_snaps);
	ci->i_head_snapc = NULL;
	ci->i_snap_caps = 0;

	for (i = 0; i < CEPH_FILE_MODE_NUM; i++)
		ci->i_nr_by_mode[i] = 0;

	mutex_init(&ci->i_truncate_mutex);
	ci->i_truncate_seq = 0;
	ci->i_truncate_size = 0;
	ci->i_truncate_pending = 0;

	ci->i_max_size = 0;
	ci->i_reported_size = 0;
	ci->i_wanted_max_size = 0;
	ci->i_requested_max_size = 0;

	ci->i_pin_ref = 0;
	ci->i_rd_ref = 0;
	ci->i_rdcache_ref = 0;
	ci->i_wr_ref = 0;
	ci->i_wb_ref = 0;
	ci->i_wrbuffer_ref = 0;
	ci->i_wrbuffer_ref_head = 0;
	ci->i_shared_gen = 0;
	ci->i_rdcache_gen = 0;
	ci->i_rdcache_revoking = 0;

	INIT_LIST_HEAD(&ci->i_unsafe_writes);
	INIT_LIST_HEAD(&ci->i_unsafe_dirops);
	spin_lock_init(&ci->i_unsafe_lock);

	ci->i_snap_realm = NULL;
	INIT_LIST_HEAD(&ci->i_snap_realm_item);
	INIT_LIST_HEAD(&ci->i_snap_flush_item);

	INIT_WORK(&ci->i_wb_work, ceph_writeback_work);
	INIT_WORK(&ci->i_pg_inv_work, ceph_invalidate_work);

	INIT_WORK(&ci->i_vmtruncate_work, ceph_vmtruncate_work);

	ceph_fscache_inode_init(ci);

	return &ci->vfs_inode;
}

static void ceph_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct ceph_inode_info *ci = ceph_inode(inode);

	kmem_cache_free(ceph_inode_cachep, ci);
}

void ceph_destroy_inode(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_inode_frag *frag;
	struct rb_node *n;

	dout("destroy_inode %p ino %llx.%llx\n", inode, ceph_vinop(inode));

	ceph_fscache_unregister_inode_cookie(ci);

	ceph_queue_caps_release(inode);

	/*
	 * we may still have a snap_realm reference if there are stray
	 * caps in i_snap_caps.
	 */
	if (ci->i_snap_realm) {
		struct ceph_mds_client *mdsc =
			ceph_sb_to_client(ci->vfs_inode.i_sb)->mdsc;
		struct ceph_snap_realm *realm = ci->i_snap_realm;

		dout(" dropping residual ref to snap realm %p\n", realm);
		spin_lock(&realm->inodes_with_caps_lock);
		list_del_init(&ci->i_snap_realm_item);
		spin_unlock(&realm->inodes_with_caps_lock);
		ceph_put_snap_realm(mdsc, realm);
	}

	kfree(ci->i_symlink);
	while ((n = rb_first(&ci->i_fragtree)) != NULL) {
		frag = rb_entry(n, struct ceph_inode_frag, node);
		rb_erase(n, &ci->i_fragtree);
		kfree(frag);
	}

	__ceph_destroy_xattrs(ci);
	if (ci->i_xattrs.blob)
		ceph_buffer_put(ci->i_xattrs.blob);
	if (ci->i_xattrs.prealloc_blob)
		ceph_buffer_put(ci->i_xattrs.prealloc_blob);

	call_rcu(&inode->i_rcu, ceph_i_callback);
}

int ceph_drop_inode(struct inode *inode)
{
	/*
	 * Positve dentry and corresponding inode are always accompanied
	 * in MDS reply. So no need to keep inode in the cache after
	 * dropping all its aliases.
	 */
	return 1;
}

/*
 * Helpers to fill in size, ctime, mtime, and atime.  We have to be
 * careful because either the client or MDS may have more up to date
 * info, depending on which capabilities are held, and whether
 * time_warp_seq or truncate_seq have increased.  (Ordinarily, mtime
 * and size are monotonically increasing, except when utimes() or
 * truncate() increments the corresponding _seq values.)
 */
int ceph_fill_file_size(struct inode *inode, int issued,
			u32 truncate_seq, u64 truncate_size, u64 size)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int queue_trunc = 0;

	if (ceph_seq_cmp(truncate_seq, ci->i_truncate_seq) > 0 ||
	    (truncate_seq == ci->i_truncate_seq && size > inode->i_size)) {
		dout("size %lld -> %llu\n", inode->i_size, size);
		inode->i_size = size;
		inode->i_blocks = (size + (1<<9) - 1) >> 9;
		ci->i_reported_size = size;
		if (truncate_seq != ci->i_truncate_seq) {
			dout("truncate_seq %u -> %u\n",
			     ci->i_truncate_seq, truncate_seq);
			ci->i_truncate_seq = truncate_seq;

			/* the MDS should have revoked these caps */
			WARN_ON_ONCE(issued & (CEPH_CAP_FILE_EXCL |
					       CEPH_CAP_FILE_RD |
					       CEPH_CAP_FILE_WR |
					       CEPH_CAP_FILE_LAZYIO));
			/*
			 * If we hold relevant caps, or in the case where we're
			 * not the only client referencing this file and we
			 * don't hold those caps, then we need to check whether
			 * the file is either opened or mmaped
			 */
			if ((issued & (CEPH_CAP_FILE_CACHE|
				       CEPH_CAP_FILE_BUFFER)) ||
			    mapping_mapped(inode->i_mapping) ||
			    __ceph_caps_file_wanted(ci)) {
				ci->i_truncate_pending++;
				queue_trunc = 1;
			}
		}
	}
	if (ceph_seq_cmp(truncate_seq, ci->i_truncate_seq) >= 0 &&
	    ci->i_truncate_size != truncate_size) {
		dout("truncate_size %lld -> %llu\n", ci->i_truncate_size,
		     truncate_size);
		ci->i_truncate_size = truncate_size;
	}

	if (queue_trunc)
		ceph_fscache_invalidate(inode);

	return queue_trunc;
}

void ceph_fill_file_time(struct inode *inode, int issued,
			 u64 time_warp_seq, struct timespec *ctime,
			 struct timespec *mtime, struct timespec *atime)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int warn = 0;

	if (issued & (CEPH_CAP_FILE_EXCL|
		      CEPH_CAP_FILE_WR|
		      CEPH_CAP_FILE_BUFFER|
		      CEPH_CAP_AUTH_EXCL|
		      CEPH_CAP_XATTR_EXCL)) {
		if (timespec_compare(ctime, &inode->i_ctime) > 0) {
			dout("ctime %ld.%09ld -> %ld.%09ld inc w/ cap\n",
			     inode->i_ctime.tv_sec, inode->i_ctime.tv_nsec,
			     ctime->tv_sec, ctime->tv_nsec);
			inode->i_ctime = *ctime;
		}
		if (ceph_seq_cmp(time_warp_seq, ci->i_time_warp_seq) > 0) {
			/* the MDS did a utimes() */
			dout("mtime %ld.%09ld -> %ld.%09ld "
			     "tw %d -> %d\n",
			     inode->i_mtime.tv_sec, inode->i_mtime.tv_nsec,
			     mtime->tv_sec, mtime->tv_nsec,
			     ci->i_time_warp_seq, (int)time_warp_seq);

			inode->i_mtime = *mtime;
			inode->i_atime = *atime;
			ci->i_time_warp_seq = time_warp_seq;
		} else if (time_warp_seq == ci->i_time_warp_seq) {
			/* nobody did utimes(); take the max */
			if (timespec_compare(mtime, &inode->i_mtime) > 0) {
				dout("mtime %ld.%09ld -> %ld.%09ld inc\n",
				     inode->i_mtime.tv_sec,
				     inode->i_mtime.tv_nsec,
				     mtime->tv_sec, mtime->tv_nsec);
				inode->i_mtime = *mtime;
			}
			if (timespec_compare(atime, &inode->i_atime) > 0) {
				dout("atime %ld.%09ld -> %ld.%09ld inc\n",
				     inode->i_atime.tv_sec,
				     inode->i_atime.tv_nsec,
				     atime->tv_sec, atime->tv_nsec);
				inode->i_atime = *atime;
			}
		} else if (issued & CEPH_CAP_FILE_EXCL) {
			/* we did a utimes(); ignore mds values */
		} else {
			warn = 1;
		}
	} else {
		/* we have no write|excl caps; whatever the MDS says is true */
		if (ceph_seq_cmp(time_warp_seq, ci->i_time_warp_seq) >= 0) {
			inode->i_ctime = *ctime;
			inode->i_mtime = *mtime;
			inode->i_atime = *atime;
			ci->i_time_warp_seq = time_warp_seq;
		} else {
			warn = 1;
		}
	}
	if (warn) /* time_warp_seq shouldn't go backwards */
		dout("%p mds time_warp_seq %llu < %u\n",
		     inode, time_warp_seq, ci->i_time_warp_seq);
}

/*
 * Populate an inode based on info from mds.  May be called on new or
 * existing inodes.
 */
static int fill_inode(struct inode *inode,
		      struct ceph_mds_reply_info_in *iinfo,
		      struct ceph_mds_reply_dirfrag *dirinfo,
		      struct ceph_mds_session *session,
		      unsigned long ttl_from, int cap_fmode,
		      struct ceph_cap_reservation *caps_reservation)
{
	struct ceph_mds_client *mdsc = ceph_inode_to_client(inode)->mdsc;
	struct ceph_mds_reply_inode *info = iinfo->in;
	struct ceph_inode_info *ci = ceph_inode(inode);
	int issued = 0, implemented, new_issued;
	struct timespec mtime, atime, ctime;
	struct ceph_buffer *xattr_blob = NULL;
	struct ceph_cap *new_cap = NULL;
	int err = 0;
	bool wake = false;
	bool queue_trunc = false;
	bool new_version = false;

	dout("fill_inode %p ino %llx.%llx v %llu had %llu\n",
	     inode, ceph_vinop(inode), le64_to_cpu(info->version),
	     ci->i_version);

	/* prealloc new cap struct */
	if (info->cap.caps && ceph_snap(inode) == CEPH_NOSNAP)
		new_cap = ceph_get_cap(mdsc, caps_reservation);

	/*
	 * prealloc xattr data, if it looks like we'll need it.  only
	 * if len > 4 (meaning there are actually xattrs; the first 4
	 * bytes are the xattr count).
	 */
	if (iinfo->xattr_len > 4) {
		xattr_blob = ceph_buffer_new(iinfo->xattr_len, GFP_NOFS);
		if (!xattr_blob)
			pr_err("fill_inode ENOMEM xattr blob %d bytes\n",
			       iinfo->xattr_len);
	}

	spin_lock(&ci->i_ceph_lock);

	/*
	 * provided version will be odd if inode value is projected,
	 * even if stable.  skip the update if we have newer stable
	 * info (ours>=theirs, e.g. due to racing mds replies), unless
	 * we are getting projected (unstable) info (in which case the
	 * version is odd, and we want ours>theirs).
	 *   us   them
	 *   2    2     skip
	 *   3    2     skip
	 *   3    3     update
	 */
	if (ci->i_version == 0 ||
	    ((info->cap.flags & CEPH_CAP_FLAG_AUTH) &&
	     le64_to_cpu(info->version) > (ci->i_version & ~1)))
		new_version = true;

	issued = __ceph_caps_issued(ci, &implemented);
	issued |= implemented | __ceph_caps_dirty(ci);
	new_issued = ~issued & le32_to_cpu(info->cap.caps);

	/* update inode */
	ci->i_version = le64_to_cpu(info->version);
	inode->i_version++;
	inode->i_rdev = le32_to_cpu(info->rdev);
	inode->i_blkbits = fls(le32_to_cpu(info->layout.fl_stripe_unit)) - 1;

	if ((new_version || (new_issued & CEPH_CAP_AUTH_SHARED)) &&
	    (issued & CEPH_CAP_AUTH_EXCL) == 0) {
		inode->i_mode = le32_to_cpu(info->mode);
		inode->i_uid = make_kuid(&init_user_ns, le32_to_cpu(info->uid));
		inode->i_gid = make_kgid(&init_user_ns, le32_to_cpu(info->gid));
		dout("%p mode 0%o uid.gid %d.%d\n", inode, inode->i_mode,
		     from_kuid(&init_user_ns, inode->i_uid),
		     from_kgid(&init_user_ns, inode->i_gid));
	}

	if ((new_version || (new_issued & CEPH_CAP_LINK_SHARED)) &&
	    (issued & CEPH_CAP_LINK_EXCL) == 0)
		set_nlink(inode, le32_to_cpu(info->nlink));

	if (new_version || (new_issued & CEPH_CAP_ANY_RD)) {
		/* be careful with mtime, atime, size */
		ceph_decode_timespec(&atime, &info->atime);
		ceph_decode_timespec(&mtime, &info->mtime);
		ceph_decode_timespec(&ctime, &info->ctime);
		ceph_fill_file_time(inode, issued,
				le32_to_cpu(info->time_warp_seq),
				&ctime, &mtime, &atime);
	}

	if (new_version ||
	    (new_issued & (CEPH_CAP_ANY_FILE_RD | CEPH_CAP_ANY_FILE_WR))) {
		ci->i_layout = info->layout;
		queue_trunc = ceph_fill_file_size(inode, issued,
					le32_to_cpu(info->truncate_seq),
					le64_to_cpu(info->truncate_size),
					le64_to_cpu(info->size));
		/* only update max_size on auth cap */
		if ((info->cap.flags & CEPH_CAP_FLAG_AUTH) &&
		    ci->i_max_size != le64_to_cpu(info->max_size)) {
			dout("max_size %lld -> %llu\n", ci->i_max_size,
					le64_to_cpu(info->max_size));
			ci->i_max_size = le64_to_cpu(info->max_size);
		}
	}

	/* xattrs */
	/* note that if i_xattrs.len <= 4, i_xattrs.data will still be NULL. */
	if ((issued & CEPH_CAP_XATTR_EXCL) == 0 &&
	    le64_to_cpu(info->xattr_version) > ci->i_xattrs.version) {
		if (ci->i_xattrs.blob)
			ceph_buffer_put(ci->i_xattrs.blob);
		ci->i_xattrs.blob = xattr_blob;
		if (xattr_blob)
			memcpy(ci->i_xattrs.blob->vec.iov_base,
			       iinfo->xattr_data, iinfo->xattr_len);
		ci->i_xattrs.version = le64_to_cpu(info->xattr_version);
		ceph_forget_all_cached_acls(inode);
		xattr_blob = NULL;
	}

	inode->i_mapping->a_ops = &ceph_aops;
	inode->i_mapping->backing_dev_info =
		&ceph_sb_to_client(inode->i_sb)->backing_dev_info;

	switch (inode->i_mode & S_IFMT) {
	case S_IFIFO:
	case S_IFBLK:
	case S_IFCHR:
	case S_IFSOCK:
		init_special_inode(inode, inode->i_mode, inode->i_rdev);
		inode->i_op = &ceph_file_iops;
		break;
	case S_IFREG:
		inode->i_op = &ceph_file_iops;
		inode->i_fop = &ceph_file_fops;
		break;
	case S_IFLNK:
		inode->i_op = &ceph_symlink_iops;
		if (!ci->i_symlink) {
			u32 symlen = iinfo->symlink_len;
			char *sym;

			spin_unlock(&ci->i_ceph_lock);

			err = -EINVAL;
			if (WARN_ON(symlen != inode->i_size))
				goto out;

			err = -ENOMEM;
			sym = kstrndup(iinfo->symlink, symlen, GFP_NOFS);
			if (!sym)
				goto out;

			spin_lock(&ci->i_ceph_lock);
			if (!ci->i_symlink)
				ci->i_symlink = sym;
			else
				kfree(sym); /* lost a race */
		}
		break;
	case S_IFDIR:
		inode->i_op = &ceph_dir_iops;
		inode->i_fop = &ceph_dir_fops;

		ci->i_dir_layout = iinfo->dir_layout;

		ci->i_files = le64_to_cpu(info->files);
		ci->i_subdirs = le64_to_cpu(info->subdirs);
		ci->i_rbytes = le64_to_cpu(info->rbytes);
		ci->i_rfiles = le64_to_cpu(info->rfiles);
		ci->i_rsubdirs = le64_to_cpu(info->rsubdirs);
		ceph_decode_timespec(&ci->i_rctime, &info->rctime);
		break;
	default:
		pr_err("fill_inode %llx.%llx BAD mode 0%o\n",
		       ceph_vinop(inode), inode->i_mode);
	}

	/* set dir completion flag? */
	if (S_ISDIR(inode->i_mode) &&
	    ci->i_files == 0 && ci->i_subdirs == 0 &&
	    ceph_snap(inode) == CEPH_NOSNAP &&
	    (le32_to_cpu(info->cap.caps) & CEPH_CAP_FILE_SHARED) &&
	    (issued & CEPH_CAP_FILE_EXCL) == 0 &&
	    !__ceph_dir_is_complete(ci)) {
		dout(" marking %p complete (empty)\n", inode);
		__ceph_dir_set_complete(ci, atomic_read(&ci->i_release_count));
	}

	/* were we issued a capability? */
	if (info->cap.caps) {
		if (ceph_snap(inode) == CEPH_NOSNAP) {
			ceph_add_cap(inode, session,
				     le64_to_cpu(info->cap.cap_id),
				     cap_fmode,
				     le32_to_cpu(info->cap.caps),
				     le32_to_cpu(info->cap.wanted),
				     le32_to_cpu(info->cap.seq),
				     le32_to_cpu(info->cap.mseq),
				     le64_to_cpu(info->cap.realm),
				     info->cap.flags, &new_cap);
			wake = true;
		} else {
			dout(" %p got snap_caps %s\n", inode,
			     ceph_cap_string(le32_to_cpu(info->cap.caps)));
			ci->i_snap_caps |= le32_to_cpu(info->cap.caps);
			if (cap_fmode >= 0)
				__ceph_get_fmode(ci, cap_fmode);
		}
	} else if (cap_fmode >= 0) {
		pr_warn("mds issued no caps on %llx.%llx\n",
			   ceph_vinop(inode));
		__ceph_get_fmode(ci, cap_fmode);
	}
	spin_unlock(&ci->i_ceph_lock);

	if (wake)
		wake_up_all(&ci->i_cap_wq);

	/* queue truncate if we saw i_size decrease */
	if (queue_trunc)
		ceph_queue_vmtruncate(inode);

	/* populate frag tree */
	if (S_ISDIR(inode->i_mode))
		ceph_fill_fragtree(inode, &info->fragtree, dirinfo);

	/* update delegation info? */
	if (dirinfo)
		ceph_fill_dirfrag(inode, dirinfo);

	err = 0;
out:
	if (new_cap)
		ceph_put_cap(mdsc, new_cap);
	if (xattr_blob)
		ceph_buffer_put(xattr_blob);
	return err;
}

/*
 * caller should hold session s_mutex.
 */
static void update_dentry_lease(struct dentry *dentry,
				struct ceph_mds_reply_lease *lease,
				struct ceph_mds_session *session,
				unsigned long from_time)
{
	struct ceph_dentry_info *di = ceph_dentry(dentry);
	long unsigned duration = le32_to_cpu(lease->duration_ms);
	long unsigned ttl = from_time + (duration * HZ) / 1000;
	long unsigned half_ttl = from_time + (duration * HZ / 2) / 1000;
	struct inode *dir;

	/* only track leases on regular dentries */
	if (dentry->d_op != &ceph_dentry_ops)
		return;

	spin_lock(&dentry->d_lock);
	dout("update_dentry_lease %p duration %lu ms ttl %lu\n",
	     dentry, duration, ttl);

	/* make lease_rdcache_gen match directory */
	dir = dentry->d_parent->d_inode;
	di->lease_shared_gen = ceph_inode(dir)->i_shared_gen;

	if (duration == 0)
		goto out_unlock;

	if (di->lease_gen == session->s_cap_gen &&
	    time_before(ttl, dentry->d_time))
		goto out_unlock;  /* we already have a newer lease. */

	if (di->lease_session && di->lease_session != session)
		goto out_unlock;

	ceph_dentry_lru_touch(dentry);

	if (!di->lease_session)
		di->lease_session = ceph_get_mds_session(session);
	di->lease_gen = session->s_cap_gen;
	di->lease_seq = le32_to_cpu(lease->seq);
	di->lease_renew_after = half_ttl;
	di->lease_renew_from = 0;
	dentry->d_time = ttl;
out_unlock:
	spin_unlock(&dentry->d_lock);
	return;
}

/*
 * splice a dentry to an inode.
 * caller must hold directory i_mutex for this to be safe.
 *
 * we will only rehash the resulting dentry if @prehash is
 * true; @prehash will be set to false (for the benefit of
 * the caller) if we fail.
 */
static struct dentry *splice_dentry(struct dentry *dn, struct inode *in,
				    bool *prehash)
{
	struct dentry *realdn;

	BUG_ON(dn->d_inode);

	/* dn must be unhashed */
	if (!d_unhashed(dn))
		d_drop(dn);
	realdn = d_materialise_unique(dn, in);
	if (IS_ERR(realdn)) {
		pr_err("splice_dentry error %ld %p inode %p ino %llx.%llx\n",
		       PTR_ERR(realdn), dn, in, ceph_vinop(in));
		if (prehash)
			*prehash = false; /* don't rehash on error */
		dn = realdn; /* note realdn contains the error */
		goto out;
	} else if (realdn) {
		dout("dn %p (%d) spliced with %p (%d) "
		     "inode %p ino %llx.%llx\n",
		     dn, d_count(dn),
		     realdn, d_count(realdn),
		     realdn->d_inode, ceph_vinop(realdn->d_inode));
		dput(dn);
		dn = realdn;
	} else {
		BUG_ON(!ceph_dentry(dn));
		dout("dn %p attached to %p ino %llx.%llx\n",
		     dn, dn->d_inode, ceph_vinop(dn->d_inode));
	}
	if ((!prehash || *prehash) && d_unhashed(dn))
		d_rehash(dn);
out:
	return dn;
}

/*
 * Incorporate results into the local cache.  This is either just
 * one inode, or a directory, dentry, and possibly linked-to inode (e.g.,
 * after a lookup).
 *
 * A reply may contain
 *         a directory inode along with a dentry.
 *  and/or a target inode
 *
 * Called with snap_rwsem (read).
 */
int ceph_fill_trace(struct super_block *sb, struct ceph_mds_request *req,
		    struct ceph_mds_session *session)
{
	struct ceph_mds_reply_info_parsed *rinfo = &req->r_reply_info;
	struct inode *in = NULL;
	struct ceph_vino vino;
	struct ceph_fs_client *fsc = ceph_sb_to_client(sb);
	int err = 0;

	dout("fill_trace %p is_dentry %d is_target %d\n", req,
	     rinfo->head->is_dentry, rinfo->head->is_target);

#if 0
	/*
	 * Debugging hook:
	 *
	 * If we resend completed ops to a recovering mds, we get no
	 * trace.  Since that is very rare, pretend this is the case
	 * to ensure the 'no trace' handlers in the callers behave.
	 *
	 * Fill in inodes unconditionally to avoid breaking cap
	 * invariants.
	 */
	if (rinfo->head->op & CEPH_MDS_OP_WRITE) {
		pr_info("fill_trace faking empty trace on %lld %s\n",
			req->r_tid, ceph_mds_op_name(rinfo->head->op));
		if (rinfo->head->is_dentry) {
			rinfo->head->is_dentry = 0;
			err = fill_inode(req->r_locked_dir,
					 &rinfo->diri, rinfo->dirfrag,
					 session, req->r_request_started, -1);
		}
		if (rinfo->head->is_target) {
			rinfo->head->is_target = 0;
			ininfo = rinfo->targeti.in;
			vino.ino = le64_to_cpu(ininfo->ino);
			vino.snap = le64_to_cpu(ininfo->snapid);
			in = ceph_get_inode(sb, vino);
			err = fill_inode(in, &rinfo->targeti, NULL,
					 session, req->r_request_started,
					 req->r_fmode);
			iput(in);
		}
	}
#endif

	if (!rinfo->head->is_target && !rinfo->head->is_dentry) {
		dout("fill_trace reply is empty!\n");
		if (rinfo->head->result == 0 && req->r_locked_dir)
			ceph_invalidate_dir_request(req);
		return 0;
	}

	if (rinfo->head->is_dentry) {
		struct inode *dir = req->r_locked_dir;

		if (dir) {
			err = fill_inode(dir, &rinfo->diri, rinfo->dirfrag,
					 session, req->r_request_started, -1,
					 &req->r_caps_reservation);
			if (err < 0)
				goto done;
		} else {
			WARN_ON_ONCE(1);
		}

		if (dir && req->r_op == CEPH_MDS_OP_LOOKUPNAME) {
			struct qstr dname;
			struct dentry *dn, *parent;

			BUG_ON(!rinfo->head->is_target);
			BUG_ON(req->r_dentry);

			parent = d_find_any_alias(dir);
			BUG_ON(!parent);

			dname.name = rinfo->dname;
			dname.len = rinfo->dname_len;
			dname.hash = full_name_hash(dname.name, dname.len);
			vino.ino = le64_to_cpu(rinfo->targeti.in->ino);
			vino.snap = le64_to_cpu(rinfo->targeti.in->snapid);
retry_lookup:
			dn = d_lookup(parent, &dname);
			dout("d_lookup on parent=%p name=%.*s got %p\n",
			     parent, dname.len, dname.name, dn);

			if (!dn) {
				dn = d_alloc(parent, &dname);
				dout("d_alloc %p '%.*s' = %p\n", parent,
				     dname.len, dname.name, dn);
				if (dn == NULL) {
					dput(parent);
					err = -ENOMEM;
					goto done;
				}
				err = ceph_init_dentry(dn);
				if (err < 0) {
					dput(dn);
					dput(parent);
					goto done;
				}
			} else if (dn->d_inode &&
				   (ceph_ino(dn->d_inode) != vino.ino ||
				    ceph_snap(dn->d_inode) != vino.snap)) {
				dout(" dn %p points to wrong inode %p\n",
				     dn, dn->d_inode);
				d_delete(dn);
				dput(dn);
				goto retry_lookup;
			}

			req->r_dentry = dn;
			dput(parent);
		}
	}

	if (rinfo->head->is_target) {
		vino.ino = le64_to_cpu(rinfo->targeti.in->ino);
		vino.snap = le64_to_cpu(rinfo->targeti.in->snapid);

		in = ceph_get_inode(sb, vino);
		if (IS_ERR(in)) {
			err = PTR_ERR(in);
			goto done;
		}
		req->r_target_inode = in;

		err = fill_inode(in, &rinfo->targeti, NULL,
				session, req->r_request_started,
				(!req->r_aborted && rinfo->head->result == 0) ?
				req->r_fmode : -1,
				&req->r_caps_reservation);
		if (err < 0) {
			pr_err("fill_inode badness %p %llx.%llx\n",
				in, ceph_vinop(in));
			goto done;
		}
	}

	/*
	 * ignore null lease/binding on snapdir ENOENT, or else we
	 * will have trouble splicing in the virtual snapdir later
	 */
	if (rinfo->head->is_dentry && !req->r_aborted &&
	    req->r_locked_dir &&
	    (rinfo->head->is_target || strncmp(req->r_dentry->d_name.name,
					       fsc->mount_options->snapdir_name,
					       req->r_dentry->d_name.len))) {
		/*
		 * lookup link rename   : null -> possibly existing inode
		 * mknod symlink mkdir  : null -> new inode
		 * unlink               : linked -> null
		 */
		struct inode *dir = req->r_locked_dir;
		struct dentry *dn = req->r_dentry;
		bool have_dir_cap, have_lease;

		BUG_ON(!dn);
		BUG_ON(!dir);
		BUG_ON(dn->d_parent->d_inode != dir);
		BUG_ON(ceph_ino(dir) !=
		       le64_to_cpu(rinfo->diri.in->ino));
		BUG_ON(ceph_snap(dir) !=
		       le64_to_cpu(rinfo->diri.in->snapid));

		/* do we have a lease on the whole dir? */
		have_dir_cap =
			(le32_to_cpu(rinfo->diri.in->cap.caps) &
			 CEPH_CAP_FILE_SHARED);

		/* do we have a dn lease? */
		have_lease = have_dir_cap ||
			le32_to_cpu(rinfo->dlease->duration_ms);
		if (!have_lease)
			dout("fill_trace  no dentry lease or dir cap\n");

		/* rename? */
		if (req->r_old_dentry && req->r_op == CEPH_MDS_OP_RENAME) {
			struct inode *olddir = req->r_old_dentry_dir;
			BUG_ON(!olddir);

			dout(" src %p '%.*s' dst %p '%.*s'\n",
			     req->r_old_dentry,
			     req->r_old_dentry->d_name.len,
			     req->r_old_dentry->d_name.name,
			     dn, dn->d_name.len, dn->d_name.name);
			dout("fill_trace doing d_move %p -> %p\n",
			     req->r_old_dentry, dn);

			d_move(req->r_old_dentry, dn);
			dout(" src %p '%.*s' dst %p '%.*s'\n",
			     req->r_old_dentry,
			     req->r_old_dentry->d_name.len,
			     req->r_old_dentry->d_name.name,
			     dn, dn->d_name.len, dn->d_name.name);

			/* ensure target dentry is invalidated, despite
			   rehashing bug in vfs_rename_dir */
			ceph_invalidate_dentry_lease(dn);

			/* d_move screws up sibling dentries' offsets */
			ceph_dir_clear_complete(dir);
			ceph_dir_clear_complete(olddir);

			dout("dn %p gets new offset %lld\n", req->r_old_dentry,
			     ceph_dentry(req->r_old_dentry)->offset);

			dn = req->r_old_dentry;  /* use old_dentry */
		}

		/* null dentry? */
		if (!rinfo->head->is_target) {
			dout("fill_trace null dentry\n");
			if (dn->d_inode) {
				dout("d_delete %p\n", dn);
				d_delete(dn);
			} else {
				dout("d_instantiate %p NULL\n", dn);
				d_instantiate(dn, NULL);
				if (have_lease && d_unhashed(dn))
					d_rehash(dn);
				update_dentry_lease(dn, rinfo->dlease,
						    session,
						    req->r_request_started);
			}
			goto done;
		}

		/* attach proper inode */
		if (!dn->d_inode) {
			ceph_dir_clear_complete(dir);
			ihold(in);
			dn = splice_dentry(dn, in, &have_lease);
			if (IS_ERR(dn)) {
				err = PTR_ERR(dn);
				goto done;
			}
			req->r_dentry = dn;  /* may have spliced */
		} else if (dn->d_inode && dn->d_inode != in) {
			dout(" %p links to %p %llx.%llx, not %llx.%llx\n",
			     dn, dn->d_inode, ceph_vinop(dn->d_inode),
			     ceph_vinop(in));
			have_lease = false;
		}

		if (have_lease)
			update_dentry_lease(dn, rinfo->dlease, session,
					    req->r_request_started);
		dout(" final dn %p\n", dn);
	} else if (!req->r_aborted &&
		   (req->r_op == CEPH_MDS_OP_LOOKUPSNAP ||
		    req->r_op == CEPH_MDS_OP_MKSNAP)) {
		struct dentry *dn = req->r_dentry;
		struct inode *dir = req->r_locked_dir;

		/* fill out a snapdir LOOKUPSNAP dentry */
		BUG_ON(!dn);
		BUG_ON(!dir);
		BUG_ON(ceph_snap(dir) != CEPH_SNAPDIR);
		dout(" linking snapped dir %p to dn %p\n", in, dn);
		ceph_dir_clear_complete(dir);
		ihold(in);
		dn = splice_dentry(dn, in, NULL);
		if (IS_ERR(dn)) {
			err = PTR_ERR(dn);
			goto done;
		}
		req->r_dentry = dn;  /* may have spliced */
	}
done:
	dout("fill_trace done err=%d\n", err);
	return err;
}

/*
 * Prepopulate our cache with readdir results, leases, etc.
 */
static int readdir_prepopulate_inodes_only(struct ceph_mds_request *req,
					   struct ceph_mds_session *session)
{
	struct ceph_mds_reply_info_parsed *rinfo = &req->r_reply_info;
	int i, err = 0;

	for (i = 0; i < rinfo->dir_nr; i++) {
		struct ceph_vino vino;
		struct inode *in;
		int rc;

		vino.ino = le64_to_cpu(rinfo->dir_in[i].in->ino);
		vino.snap = le64_to_cpu(rinfo->dir_in[i].in->snapid);

		in = ceph_get_inode(req->r_dentry->d_sb, vino);
		if (IS_ERR(in)) {
			err = PTR_ERR(in);
			dout("new_inode badness got %d\n", err);
			continue;
		}
		rc = fill_inode(in, &rinfo->dir_in[i], NULL, session,
				req->r_request_started, -1,
				&req->r_caps_reservation);
		if (rc < 0) {
			pr_err("fill_inode badness on %p got %d\n", in, rc);
			err = rc;
			continue;
		}
	}

	return err;
}

int ceph_readdir_prepopulate(struct ceph_mds_request *req,
			     struct ceph_mds_session *session)
{
	struct dentry *parent = req->r_dentry;
	struct ceph_mds_reply_info_parsed *rinfo = &req->r_reply_info;
	struct qstr dname;
	struct dentry *dn;
	struct inode *in;
	int err = 0, ret, i;
	struct inode *snapdir = NULL;
	struct ceph_mds_request_head *rhead = req->r_request->front.iov_base;
	struct ceph_dentry_info *di;
	u64 r_readdir_offset = req->r_readdir_offset;
	u32 frag = le32_to_cpu(rhead->args.readdir.frag);

	if (rinfo->dir_dir &&
	    le32_to_cpu(rinfo->dir_dir->frag) != frag) {
		dout("readdir_prepopulate got new frag %x -> %x\n",
		     frag, le32_to_cpu(rinfo->dir_dir->frag));
		frag = le32_to_cpu(rinfo->dir_dir->frag);
		if (ceph_frag_is_leftmost(frag))
			r_readdir_offset = 2;
		else
			r_readdir_offset = 0;
	}

	if (req->r_aborted)
		return readdir_prepopulate_inodes_only(req, session);

	if (le32_to_cpu(rinfo->head->op) == CEPH_MDS_OP_LSSNAP) {
		snapdir = ceph_get_snapdir(parent->d_inode);
		parent = d_find_alias(snapdir);
		dout("readdir_prepopulate %d items under SNAPDIR dn %p\n",
		     rinfo->dir_nr, parent);
	} else {
		dout("readdir_prepopulate %d items under dn %p\n",
		     rinfo->dir_nr, parent);
		if (rinfo->dir_dir)
			ceph_fill_dirfrag(parent->d_inode, rinfo->dir_dir);
	}

	/* FIXME: release caps/leases if error occurs */
	for (i = 0; i < rinfo->dir_nr; i++) {
		struct ceph_vino vino;

		dname.name = rinfo->dir_dname[i];
		dname.len = rinfo->dir_dname_len[i];
		dname.hash = full_name_hash(dname.name, dname.len);

		vino.ino = le64_to_cpu(rinfo->dir_in[i].in->ino);
		vino.snap = le64_to_cpu(rinfo->dir_in[i].in->snapid);

retry_lookup:
		dn = d_lookup(parent, &dname);
		dout("d_lookup on parent=%p name=%.*s got %p\n",
		     parent, dname.len, dname.name, dn);

		if (!dn) {
			dn = d_alloc(parent, &dname);
			dout("d_alloc %p '%.*s' = %p\n", parent,
			     dname.len, dname.name, dn);
			if (dn == NULL) {
				dout("d_alloc badness\n");
				err = -ENOMEM;
				goto out;
			}
			ret = ceph_init_dentry(dn);
			if (ret < 0) {
				dput(dn);
				err = ret;
				goto out;
			}
		} else if (dn->d_inode &&
			   (ceph_ino(dn->d_inode) != vino.ino ||
			    ceph_snap(dn->d_inode) != vino.snap)) {
			dout(" dn %p points to wrong inode %p\n",
			     dn, dn->d_inode);
			d_delete(dn);
			dput(dn);
			goto retry_lookup;
		} else {
			/* reorder parent's d_subdirs */
			spin_lock(&parent->d_lock);
			spin_lock_nested(&dn->d_lock, DENTRY_D_LOCK_NESTED);
			list_move(&dn->d_u.d_child, &parent->d_subdirs);
			spin_unlock(&dn->d_lock);
			spin_unlock(&parent->d_lock);
		}

		/* inode */
		if (dn->d_inode) {
			in = dn->d_inode;
		} else {
			in = ceph_get_inode(parent->d_sb, vino);
			if (IS_ERR(in)) {
				dout("new_inode badness\n");
				d_drop(dn);
				dput(dn);
				err = PTR_ERR(in);
				goto out;
			}
		}

		if (fill_inode(in, &rinfo->dir_in[i], NULL, session,
			       req->r_request_started, -1,
			       &req->r_caps_reservation) < 0) {
			pr_err("fill_inode badness on %p\n", in);
			if (!dn->d_inode)
				iput(in);
			d_drop(dn);
			goto next_item;
		}

		if (!dn->d_inode) {
			dn = splice_dentry(dn, in, NULL);
			if (IS_ERR(dn)) {
				err = PTR_ERR(dn);
				dn = NULL;
				goto next_item;
			}
		}

		di = dn->d_fsdata;
		di->offset = ceph_make_fpos(frag, i + r_readdir_offset);

		update_dentry_lease(dn, rinfo->dir_dlease[i],
				    req->r_session,
				    req->r_request_started);
next_item:
		if (dn)
			dput(dn);
	}
	if (err == 0)
		req->r_did_prepopulate = true;

out:
	if (snapdir) {
		iput(snapdir);
		dput(parent);
	}
	dout("readdir_prepopulate done\n");
	return err;
}

int ceph_inode_set_size(struct inode *inode, loff_t size)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int ret = 0;

	spin_lock(&ci->i_ceph_lock);
	dout("set_size %p %llu -> %llu\n", inode, inode->i_size, size);
	inode->i_size = size;
	inode->i_blocks = (size + (1 << 9) - 1) >> 9;

	/* tell the MDS if we are approaching max_size */
	if ((size << 1) >= ci->i_max_size &&
	    (ci->i_reported_size << 1) < ci->i_max_size)
		ret = 1;

	spin_unlock(&ci->i_ceph_lock);
	return ret;
}

/*
 * Write back inode data in a worker thread.  (This can't be done
 * in the message handler context.)
 */
void ceph_queue_writeback(struct inode *inode)
{
	ihold(inode);
	if (queue_work(ceph_inode_to_client(inode)->wb_wq,
		       &ceph_inode(inode)->i_wb_work)) {
		dout("ceph_queue_writeback %p\n", inode);
	} else {
		dout("ceph_queue_writeback %p failed\n", inode);
		iput(inode);
	}
}

static void ceph_writeback_work(struct work_struct *work)
{
	struct ceph_inode_info *ci = container_of(work, struct ceph_inode_info,
						  i_wb_work);
	struct inode *inode = &ci->vfs_inode;

	dout("writeback %p\n", inode);
	filemap_fdatawrite(&inode->i_data);
	iput(inode);
}

/*
 * queue an async invalidation
 */
void ceph_queue_invalidate(struct inode *inode)
{
	ihold(inode);
	if (queue_work(ceph_inode_to_client(inode)->pg_inv_wq,
		       &ceph_inode(inode)->i_pg_inv_work)) {
		dout("ceph_queue_invalidate %p\n", inode);
	} else {
		dout("ceph_queue_invalidate %p failed\n", inode);
		iput(inode);
	}
}

/*
 * Invalidate inode pages in a worker thread.  (This can't be done
 * in the message handler context.)
 */
static void ceph_invalidate_work(struct work_struct *work)
{
	struct ceph_inode_info *ci = container_of(work, struct ceph_inode_info,
						  i_pg_inv_work);
	struct inode *inode = &ci->vfs_inode;
	u32 orig_gen;
	int check = 0;

	mutex_lock(&ci->i_truncate_mutex);
	spin_lock(&ci->i_ceph_lock);
	dout("invalidate_pages %p gen %d revoking %d\n", inode,
	     ci->i_rdcache_gen, ci->i_rdcache_revoking);
	if (ci->i_rdcache_revoking != ci->i_rdcache_gen) {
		if (__ceph_caps_revoking_other(ci, NULL, CEPH_CAP_FILE_CACHE))
			check = 1;
		spin_unlock(&ci->i_ceph_lock);
		mutex_unlock(&ci->i_truncate_mutex);
		goto out;
	}
	orig_gen = ci->i_rdcache_gen;
	spin_unlock(&ci->i_ceph_lock);

	truncate_pagecache(inode, 0);

	spin_lock(&ci->i_ceph_lock);
	if (orig_gen == ci->i_rdcache_gen &&
	    orig_gen == ci->i_rdcache_revoking) {
		dout("invalidate_pages %p gen %d successful\n", inode,
		     ci->i_rdcache_gen);
		ci->i_rdcache_revoking--;
		check = 1;
	} else {
		dout("invalidate_pages %p gen %d raced, now %d revoking %d\n",
		     inode, orig_gen, ci->i_rdcache_gen,
		     ci->i_rdcache_revoking);
		if (__ceph_caps_revoking_other(ci, NULL, CEPH_CAP_FILE_CACHE))
			check = 1;
	}
	spin_unlock(&ci->i_ceph_lock);
	mutex_unlock(&ci->i_truncate_mutex);
out:
	if (check)
		ceph_check_caps(ci, 0, NULL);
	iput(inode);
}


/*
 * called by trunc_wq;
 *
 * We also truncate in a separate thread as well.
 */
static void ceph_vmtruncate_work(struct work_struct *work)
{
	struct ceph_inode_info *ci = container_of(work, struct ceph_inode_info,
						  i_vmtruncate_work);
	struct inode *inode = &ci->vfs_inode;

	dout("vmtruncate_work %p\n", inode);
	__ceph_do_pending_vmtruncate(inode);
	iput(inode);
}

/*
 * Queue an async vmtruncate.  If we fail to queue work, we will handle
 * the truncation the next time we call __ceph_do_pending_vmtruncate.
 */
void ceph_queue_vmtruncate(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);

	ihold(inode);

	if (queue_work(ceph_sb_to_client(inode->i_sb)->trunc_wq,
		       &ci->i_vmtruncate_work)) {
		dout("ceph_queue_vmtruncate %p\n", inode);
	} else {
		dout("ceph_queue_vmtruncate %p failed, pending=%d\n",
		     inode, ci->i_truncate_pending);
		iput(inode);
	}
}

/*
 * Make sure any pending truncation is applied before doing anything
 * that may depend on it.
 */
void __ceph_do_pending_vmtruncate(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	u64 to;
	int wrbuffer_refs, finish = 0;

	mutex_lock(&ci->i_truncate_mutex);
retry:
	spin_lock(&ci->i_ceph_lock);
	if (ci->i_truncate_pending == 0) {
		dout("__do_pending_vmtruncate %p none pending\n", inode);
		spin_unlock(&ci->i_ceph_lock);
		mutex_unlock(&ci->i_truncate_mutex);
		return;
	}

	/*
	 * make sure any dirty snapped pages are flushed before we
	 * possibly truncate them.. so write AND block!
	 */
	if (ci->i_wrbuffer_ref_head < ci->i_wrbuffer_ref) {
		dout("__do_pending_vmtruncate %p flushing snaps first\n",
		     inode);
		spin_unlock(&ci->i_ceph_lock);
		filemap_write_and_wait_range(&inode->i_data, 0,
					     inode->i_sb->s_maxbytes);
		goto retry;
	}

	/* there should be no reader or writer */
	WARN_ON_ONCE(ci->i_rd_ref || ci->i_wr_ref);

	to = ci->i_truncate_size;
	wrbuffer_refs = ci->i_wrbuffer_ref;
	dout("__do_pending_vmtruncate %p (%d) to %lld\n", inode,
	     ci->i_truncate_pending, to);
	spin_unlock(&ci->i_ceph_lock);

	truncate_pagecache(inode, to);

	spin_lock(&ci->i_ceph_lock);
	if (to == ci->i_truncate_size) {
		ci->i_truncate_pending = 0;
		finish = 1;
	}
	spin_unlock(&ci->i_ceph_lock);
	if (!finish)
		goto retry;

	mutex_unlock(&ci->i_truncate_mutex);

	if (wrbuffer_refs == 0)
		ceph_check_caps(ci, CHECK_CAPS_AUTHONLY, NULL);

	wake_up_all(&ci->i_cap_wq);
}

/*
 * symlinks
 */
static void *ceph_sym_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct ceph_inode_info *ci = ceph_inode(dentry->d_inode);
	nd_set_link(nd, ci->i_symlink);
	return NULL;
}

static const struct inode_operations ceph_symlink_iops = {
	.readlink = generic_readlink,
	.follow_link = ceph_sym_follow_link,
	.setattr = ceph_setattr,
	.getattr = ceph_getattr,
	.setxattr = ceph_setxattr,
	.getxattr = ceph_getxattr,
	.listxattr = ceph_listxattr,
	.removexattr = ceph_removexattr,
};

/*
 * setattr
 */
int ceph_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	const unsigned int ia_valid = attr->ia_valid;
	struct ceph_mds_request *req;
	struct ceph_mds_client *mdsc = ceph_sb_to_client(dentry->d_sb)->mdsc;
	int issued;
	int release = 0, dirtied = 0;
	int mask = 0;
	int err = 0;
	int inode_dirty_flags = 0;

	if (ceph_snap(inode) != CEPH_NOSNAP)
		return -EROFS;

	err = inode_change_ok(inode, attr);
	if (err != 0)
		return err;

	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_SETATTR,
				       USE_AUTH_MDS);
	if (IS_ERR(req))
		return PTR_ERR(req);

	spin_lock(&ci->i_ceph_lock);
	issued = __ceph_caps_issued(ci, NULL);
	dout("setattr %p issued %s\n", inode, ceph_cap_string(issued));

	if (ia_valid & ATTR_UID) {
		dout("setattr %p uid %d -> %d\n", inode,
		     from_kuid(&init_user_ns, inode->i_uid),
		     from_kuid(&init_user_ns, attr->ia_uid));
		if (issued & CEPH_CAP_AUTH_EXCL) {
			inode->i_uid = attr->ia_uid;
			dirtied |= CEPH_CAP_AUTH_EXCL;
		} else if ((issued & CEPH_CAP_AUTH_SHARED) == 0 ||
			   !uid_eq(attr->ia_uid, inode->i_uid)) {
			req->r_args.setattr.uid = cpu_to_le32(
				from_kuid(&init_user_ns, attr->ia_uid));
			mask |= CEPH_SETATTR_UID;
			release |= CEPH_CAP_AUTH_SHARED;
		}
	}
	if (ia_valid & ATTR_GID) {
		dout("setattr %p gid %d -> %d\n", inode,
		     from_kgid(&init_user_ns, inode->i_gid),
		     from_kgid(&init_user_ns, attr->ia_gid));
		if (issued & CEPH_CAP_AUTH_EXCL) {
			inode->i_gid = attr->ia_gid;
			dirtied |= CEPH_CAP_AUTH_EXCL;
		} else if ((issued & CEPH_CAP_AUTH_SHARED) == 0 ||
			   !gid_eq(attr->ia_gid, inode->i_gid)) {
			req->r_args.setattr.gid = cpu_to_le32(
				from_kgid(&init_user_ns, attr->ia_gid));
			mask |= CEPH_SETATTR_GID;
			release |= CEPH_CAP_AUTH_SHARED;
		}
	}
	if (ia_valid & ATTR_MODE) {
		dout("setattr %p mode 0%o -> 0%o\n", inode, inode->i_mode,
		     attr->ia_mode);
		if (issued & CEPH_CAP_AUTH_EXCL) {
			inode->i_mode = attr->ia_mode;
			dirtied |= CEPH_CAP_AUTH_EXCL;
		} else if ((issued & CEPH_CAP_AUTH_SHARED) == 0 ||
			   attr->ia_mode != inode->i_mode) {
			inode->i_mode = attr->ia_mode;
			req->r_args.setattr.mode = cpu_to_le32(attr->ia_mode);
			mask |= CEPH_SETATTR_MODE;
			release |= CEPH_CAP_AUTH_SHARED;
		}
	}

	if (ia_valid & ATTR_ATIME) {
		dout("setattr %p atime %ld.%ld -> %ld.%ld\n", inode,
		     inode->i_atime.tv_sec, inode->i_atime.tv_nsec,
		     attr->ia_atime.tv_sec, attr->ia_atime.tv_nsec);
		if (issued & CEPH_CAP_FILE_EXCL) {
			ci->i_time_warp_seq++;
			inode->i_atime = attr->ia_atime;
			dirtied |= CEPH_CAP_FILE_EXCL;
		} else if ((issued & CEPH_CAP_FILE_WR) &&
			   timespec_compare(&inode->i_atime,
					    &attr->ia_atime) < 0) {
			inode->i_atime = attr->ia_atime;
			dirtied |= CEPH_CAP_FILE_WR;
		} else if ((issued & CEPH_CAP_FILE_SHARED) == 0 ||
			   !timespec_equal(&inode->i_atime, &attr->ia_atime)) {
			ceph_encode_timespec(&req->r_args.setattr.atime,
					     &attr->ia_atime);
			mask |= CEPH_SETATTR_ATIME;
			release |= CEPH_CAP_FILE_CACHE | CEPH_CAP_FILE_RD |
				CEPH_CAP_FILE_WR;
		}
	}
	if (ia_valid & ATTR_MTIME) {
		dout("setattr %p mtime %ld.%ld -> %ld.%ld\n", inode,
		     inode->i_mtime.tv_sec, inode->i_mtime.tv_nsec,
		     attr->ia_mtime.tv_sec, attr->ia_mtime.tv_nsec);
		if (issued & CEPH_CAP_FILE_EXCL) {
			ci->i_time_warp_seq++;
			inode->i_mtime = attr->ia_mtime;
			dirtied |= CEPH_CAP_FILE_EXCL;
		} else if ((issued & CEPH_CAP_FILE_WR) &&
			   timespec_compare(&inode->i_mtime,
					    &attr->ia_mtime) < 0) {
			inode->i_mtime = attr->ia_mtime;
			dirtied |= CEPH_CAP_FILE_WR;
		} else if ((issued & CEPH_CAP_FILE_SHARED) == 0 ||
			   !timespec_equal(&inode->i_mtime, &attr->ia_mtime)) {
			ceph_encode_timespec(&req->r_args.setattr.mtime,
					     &attr->ia_mtime);
			mask |= CEPH_SETATTR_MTIME;
			release |= CEPH_CAP_FILE_SHARED | CEPH_CAP_FILE_RD |
				CEPH_CAP_FILE_WR;
		}
	}
	if (ia_valid & ATTR_SIZE) {
		dout("setattr %p size %lld -> %lld\n", inode,
		     inode->i_size, attr->ia_size);
		if (attr->ia_size > inode->i_sb->s_maxbytes) {
			err = -EINVAL;
			goto out;
		}
		if ((issued & CEPH_CAP_FILE_EXCL) &&
		    attr->ia_size > inode->i_size) {
			inode->i_size = attr->ia_size;
			inode->i_blocks =
				(attr->ia_size + (1 << 9) - 1) >> 9;
			inode->i_ctime = attr->ia_ctime;
			ci->i_reported_size = attr->ia_size;
			dirtied |= CEPH_CAP_FILE_EXCL;
		} else if ((issued & CEPH_CAP_FILE_SHARED) == 0 ||
			   attr->ia_size != inode->i_size) {
			req->r_args.setattr.size = cpu_to_le64(attr->ia_size);
			req->r_args.setattr.old_size =
				cpu_to_le64(inode->i_size);
			mask |= CEPH_SETATTR_SIZE;
			release |= CEPH_CAP_FILE_SHARED | CEPH_CAP_FILE_RD |
				CEPH_CAP_FILE_WR;
		}
	}

	/* these do nothing */
	if (ia_valid & ATTR_CTIME) {
		bool only = (ia_valid & (ATTR_SIZE|ATTR_MTIME|ATTR_ATIME|
					 ATTR_MODE|ATTR_UID|ATTR_GID)) == 0;
		dout("setattr %p ctime %ld.%ld -> %ld.%ld (%s)\n", inode,
		     inode->i_ctime.tv_sec, inode->i_ctime.tv_nsec,
		     attr->ia_ctime.tv_sec, attr->ia_ctime.tv_nsec,
		     only ? "ctime only" : "ignored");
		inode->i_ctime = attr->ia_ctime;
		if (only) {
			/*
			 * if kernel wants to dirty ctime but nothing else,
			 * we need to choose a cap to dirty under, or do
			 * a almost-no-op setattr
			 */
			if (issued & CEPH_CAP_AUTH_EXCL)
				dirtied |= CEPH_CAP_AUTH_EXCL;
			else if (issued & CEPH_CAP_FILE_EXCL)
				dirtied |= CEPH_CAP_FILE_EXCL;
			else if (issued & CEPH_CAP_XATTR_EXCL)
				dirtied |= CEPH_CAP_XATTR_EXCL;
			else
				mask |= CEPH_SETATTR_CTIME;
		}
	}
	if (ia_valid & ATTR_FILE)
		dout("setattr %p ATTR_FILE ... hrm!\n", inode);

	if (dirtied) {
		inode_dirty_flags = __ceph_mark_dirty_caps(ci, dirtied);
		inode->i_ctime = CURRENT_TIME;
	}

	release &= issued;
	spin_unlock(&ci->i_ceph_lock);

	if (inode_dirty_flags)
		__mark_inode_dirty(inode, inode_dirty_flags);

	if (ia_valid & ATTR_MODE) {
		err = posix_acl_chmod(inode, attr->ia_mode);
		if (err)
			goto out_put;
	}

	if (mask) {
		req->r_inode = inode;
		ihold(inode);
		req->r_inode_drop = release;
		req->r_args.setattr.mask = cpu_to_le32(mask);
		req->r_num_caps = 1;
		err = ceph_mdsc_do_request(mdsc, NULL, req);
	}
	dout("setattr %p result=%d (%s locally, %d remote)\n", inode, err,
	     ceph_cap_string(dirtied), mask);

	ceph_mdsc_put_request(req);
	if (mask & CEPH_SETATTR_SIZE)
		__ceph_do_pending_vmtruncate(inode);
	return err;
out:
	spin_unlock(&ci->i_ceph_lock);
out_put:
	ceph_mdsc_put_request(req);
	return err;
}

/*
 * Verify that we have a lease on the given mask.  If not,
 * do a getattr against an mds.
 */
int ceph_do_getattr(struct inode *inode, int mask)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(inode->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	int err;

	if (ceph_snap(inode) == CEPH_SNAPDIR) {
		dout("do_getattr inode %p SNAPDIR\n", inode);
		return 0;
	}

	dout("do_getattr inode %p mask %s mode 0%o\n", inode, ceph_cap_string(mask), inode->i_mode);
	if (ceph_caps_issued_mask(ceph_inode(inode), mask, 1))
		return 0;

	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_GETATTR, USE_ANY_MDS);
	if (IS_ERR(req))
		return PTR_ERR(req);
	req->r_inode = inode;
	ihold(inode);
	req->r_num_caps = 1;
	req->r_args.getattr.mask = cpu_to_le32(mask);
	err = ceph_mdsc_do_request(mdsc, NULL, req);
	ceph_mdsc_put_request(req);
	dout("do_getattr result=%d\n", err);
	return err;
}


/*
 * Check inode permissions.  We verify we have a valid value for
 * the AUTH cap, then call the generic handler.
 */
int ceph_permission(struct inode *inode, int mask)
{
	int err;

	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	err = ceph_do_getattr(inode, CEPH_CAP_AUTH_SHARED);

	if (!err)
		err = generic_permission(inode, mask);
	return err;
}

/*
 * Get all attributes.  Hopefully somedata we'll have a statlite()
 * and can limit the fields we require to be accurate.
 */
int ceph_getattr(struct vfsmount *mnt, struct dentry *dentry,
		 struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	int err;

	err = ceph_do_getattr(inode, CEPH_STAT_CAP_INODE_ALL);
	if (!err) {
		generic_fillattr(inode, stat);
		stat->ino = ceph_translate_ino(inode->i_sb, inode->i_ino);
		if (ceph_snap(inode) != CEPH_NOSNAP)
			stat->dev = ceph_snap(inode);
		else
			stat->dev = 0;
		if (S_ISDIR(inode->i_mode)) {
			if (ceph_test_mount_opt(ceph_sb_to_client(inode->i_sb),
						RBYTES))
				stat->size = ci->i_rbytes;
			else
				stat->size = ci->i_files + ci->i_subdirs;
			stat->blocks = 0;
			stat->blksize = 65536;
		}
	}
	return err;
}
/************************************************************/
/* ../linux-3.17/fs/ceph/inode.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

#include <linux/spinlock.h>
#include <linux/fs_struct.h>
// #include <linux/namei.h>
// #include <linux/slab.h>
// #include <linux/sched.h>

// #include "super.h"
// #include "mds_client.h"

/*
 * Directory operations: readdir, lookup, create, link, unlink,
 * rename, etc.
 */

/*
 * Ceph MDS operations are specified in terms of a base ino and
 * relative path.  Thus, the client can specify an operation on a
 * specific inode (e.g., a getattr due to fstat(2)), or as a path
 * relative to, say, the root directory.
 *
 * Normally, we limit ourselves to strict inode ops (no path component)
 * or dentry operations (a single path component relative to an ino).  The
 * exception to this is open_root_dentry(), which will open the mount
 * point by name.
 */

const struct inode_operations ceph_dir_iops;
const struct file_operations ceph_dir_fops;
const struct dentry_operations ceph_dentry_ops;

/*
 * Initialize ceph dentry state.
 */
int ceph_init_dentry(struct dentry *dentry)
{
	struct ceph_dentry_info *di;

	if (dentry->d_fsdata)
		return 0;

	di = kmem_cache_alloc(ceph_dentry_cachep, GFP_NOFS | __GFP_ZERO);
	if (!di)
		return -ENOMEM;          /* oh well */

	spin_lock(&dentry->d_lock);
	if (dentry->d_fsdata) {
		/* lost a race */
		kmem_cache_free(ceph_dentry_cachep, di);
		goto out_unlock;
	}

	if (ceph_snap(dentry->d_parent->d_inode) == CEPH_NOSNAP)
		d_set_d_op(dentry, &ceph_dentry_ops);
	else if (ceph_snap(dentry->d_parent->d_inode) == CEPH_SNAPDIR)
		d_set_d_op(dentry, &ceph_snapdir_dentry_ops);
	else
		d_set_d_op(dentry, &ceph_snap_dentry_ops);

	di->dentry = dentry;
	di->lease_session = NULL;
	dentry->d_time = jiffies;
	/* avoid reordering d_fsdata setup so that the check above is safe */
	smp_mb();
	dentry->d_fsdata = di;
	ceph_dentry_lru_add(dentry);
out_unlock:
	spin_unlock(&dentry->d_lock);
	return 0;
}

struct inode *ceph_get_dentry_parent_inode(struct dentry *dentry)
{
	struct inode *inode = NULL;

	if (!dentry)
		return NULL;

	spin_lock(&dentry->d_lock);
	if (!IS_ROOT(dentry)) {
		inode = dentry->d_parent->d_inode;
		ihold(inode);
	}
	spin_unlock(&dentry->d_lock);
	return inode;
}


/*
 * for readdir, we encode the directory frag and offset within that
 * frag into f_pos.
 */
static unsigned fpos_frag(loff_t p)
{
	return p >> 32;
}
static unsigned fpos_off(loff_t p)
{
	return p & 0xffffffff;
}

static int fpos_cmp(loff_t l, loff_t r)
{
	int v = ceph_frag_compare(fpos_frag(l), fpos_frag(r));
	if (v)
		return v;
	return (int)(fpos_off(l) - fpos_off(r));
}

/*
 * When possible, we try to satisfy a readdir by peeking at the
 * dcache.  We make this work by carefully ordering dentries on
 * d_u.d_child when we initially get results back from the MDS, and
 * falling back to a "normal" sync readdir if any dentries in the dir
 * are dropped.
 *
 * Complete dir indicates that we have all dentries in the dir.  It is
 * defined IFF we hold CEPH_CAP_FILE_SHARED (which will be revoked by
 * the MDS if/when the directory is modified).
 */
static int __dcache_readdir(struct file *file,  struct dir_context *ctx,
			    u32 shared_gen)
{
	struct ceph_file_info *fi = file->private_data;
	struct dentry *parent = file->f_dentry;
	struct inode *dir = parent->d_inode;
	struct list_head *p;
	struct dentry *dentry, *last;
	struct ceph_dentry_info *di;
	int err = 0;

	/* claim ref on last dentry we returned */
	last = fi->dentry;
	fi->dentry = NULL;

	dout("__dcache_readdir %p v%u at %llu (last %p)\n",
	     dir, shared_gen, ctx->pos, last);

	spin_lock(&parent->d_lock);

	/* start at beginning? */
	if (ctx->pos == 2 || last == NULL ||
	    fpos_cmp(ctx->pos, ceph_dentry(last)->offset) < 0) {
		if (list_empty(&parent->d_subdirs))
			goto out_unlock;
		p = parent->d_subdirs.prev;
		dout(" initial p %p/%p\n", p->prev, p->next);
	} else {
		p = last->d_u.d_child.prev;
	}

more:
	dentry = list_entry(p, struct dentry, d_u.d_child);
	di = ceph_dentry(dentry);
	while (1) {
		dout(" p %p/%p %s d_subdirs %p/%p\n", p->prev, p->next,
		     d_unhashed(dentry) ? "!hashed" : "hashed",
		     parent->d_subdirs.prev, parent->d_subdirs.next);
		if (p == &parent->d_subdirs) {
			fi->flags |= CEPH_F_ATEND;
			goto out_unlock;
		}
		spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
		if (di->lease_shared_gen == shared_gen &&
		    !d_unhashed(dentry) && dentry->d_inode &&
		    ceph_snap(dentry->d_inode) != CEPH_SNAPDIR &&
		    ceph_ino(dentry->d_inode) != CEPH_INO_CEPH &&
		    fpos_cmp(ctx->pos, di->offset) <= 0)
			break;
		dout(" skipping %p %.*s at %llu (%llu)%s%s\n", dentry,
		     dentry->d_name.len, dentry->d_name.name, di->offset,
		     ctx->pos, d_unhashed(dentry) ? " unhashed" : "",
		     !dentry->d_inode ? " null" : "");
		spin_unlock(&dentry->d_lock);
		p = p->prev;
		dentry = list_entry(p, struct dentry, d_u.d_child);
		di = ceph_dentry(dentry);
	}

	dget_dlock(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&parent->d_lock);

	/* make sure a dentry wasn't dropped while we didn't have parent lock */
	if (!ceph_dir_is_complete(dir)) {
		dout(" lost dir complete on %p; falling back to mds\n", dir);
		dput(dentry);
		err = -EAGAIN;
		goto out;
	}

	dout(" %llu (%llu) dentry %p %.*s %p\n", di->offset, ctx->pos,
	     dentry, dentry->d_name.len, dentry->d_name.name, dentry->d_inode);
	if (!dir_emit(ctx, dentry->d_name.name,
		      dentry->d_name.len,
		      ceph_translate_ino(dentry->d_sb, dentry->d_inode->i_ino),
		      dentry->d_inode->i_mode >> 12)) {
		if (last) {
			/* remember our position */
			fi->dentry = last;
			fi->next_offset = fpos_off(di->offset);
		}
		dput(dentry);
		return 0;
	}

	ctx->pos = di->offset + 1;

	if (last)
		dput(last);
	last = dentry;

	spin_lock(&parent->d_lock);
	p = p->prev;	/* advance to next dentry */
	goto more;

out_unlock:
	spin_unlock(&parent->d_lock);
out:
	if (last)
		dput(last);
	return err;
}

/*
 * make note of the last dentry we read, so we can
 * continue at the same lexicographical point,
 * regardless of what dir changes take place on the
 * server.
 */
static int note_last_dentry(struct ceph_file_info *fi, const char *name,
			    int len)
{
	kfree(fi->last_name);
	fi->last_name = kmalloc(len+1, GFP_NOFS);
	if (!fi->last_name)
		return -ENOMEM;
	memcpy(fi->last_name, name, len);
	fi->last_name[len] = 0;
	dout("note_last_dentry '%s'\n", fi->last_name);
	return 0;
}

static int ceph_readdir(struct file *file, struct dir_context *ctx)
{
	struct ceph_file_info *fi = file->private_data;
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	unsigned frag = fpos_frag(ctx->pos);
	int off = fpos_off(ctx->pos);
	int err;
	u32 ftype;
	struct ceph_mds_reply_info_parsed *rinfo;

	dout("readdir %p file %p frag %u off %u\n", inode, file, frag, off);
	if (fi->flags & CEPH_F_ATEND)
		return 0;

	/* always start with . and .. */
	if (ctx->pos == 0) {
		/* note dir version at start of readdir so we can tell
		 * if any dentries get dropped */
		fi->dir_release_count = atomic_read(&ci->i_release_count);

		dout("readdir off 0 -> '.'\n");
		if (!dir_emit(ctx, ".", 1,
			    ceph_translate_ino(inode->i_sb, inode->i_ino),
			    inode->i_mode >> 12))
			return 0;
		ctx->pos = 1;
		off = 1;
	}
	if (ctx->pos == 1) {
		ino_t ino = parent_ino(file->f_dentry);
		dout("readdir off 1 -> '..'\n");
		if (!dir_emit(ctx, "..", 2,
			    ceph_translate_ino(inode->i_sb, ino),
			    inode->i_mode >> 12))
			return 0;
		ctx->pos = 2;
		off = 2;
	}

	/* can we use the dcache? */
	spin_lock(&ci->i_ceph_lock);
	if ((ctx->pos == 2 || fi->dentry) &&
	    !ceph_test_mount_opt(fsc, NOASYNCREADDIR) &&
	    ceph_snap(inode) != CEPH_SNAPDIR &&
	    __ceph_dir_is_complete(ci) &&
	    __ceph_caps_issued_mask(ci, CEPH_CAP_FILE_SHARED, 1)) {
		u32 shared_gen = ci->i_shared_gen;
		spin_unlock(&ci->i_ceph_lock);
		err = __dcache_readdir(file, ctx, shared_gen);
		if (err != -EAGAIN)
			return err;
		frag = fpos_frag(ctx->pos);
		off = fpos_off(ctx->pos);
	} else {
		spin_unlock(&ci->i_ceph_lock);
	}
	if (fi->dentry) {
		err = note_last_dentry(fi, fi->dentry->d_name.name,
				       fi->dentry->d_name.len);
		if (err)
			return err;
		dput(fi->dentry);
		fi->dentry = NULL;
	}

	/* proceed with a normal readdir */

more:
	/* do we have the correct frag content buffered? */
	if (fi->frag != frag || fi->last_readdir == NULL) {
		struct ceph_mds_request *req;
		int op = ceph_snap(inode) == CEPH_SNAPDIR ?
			CEPH_MDS_OP_LSSNAP : CEPH_MDS_OP_READDIR;

		/* discard old result, if any */
		if (fi->last_readdir) {
			ceph_mdsc_put_request(fi->last_readdir);
			fi->last_readdir = NULL;
		}

		dout("readdir fetching %llx.%llx frag %x offset '%s'\n",
		     ceph_vinop(inode), frag, fi->last_name);
		req = ceph_mdsc_create_request(mdsc, op, USE_AUTH_MDS);
		if (IS_ERR(req))
			return PTR_ERR(req);
		err = ceph_alloc_readdir_reply_buffer(req, inode);
		if (err) {
			ceph_mdsc_put_request(req);
			return err;
		}
		req->r_inode = inode;
		ihold(inode);
		req->r_dentry = dget(file->f_dentry);
		/* hints to request -> mds selection code */
		req->r_direct_mode = USE_AUTH_MDS;
		req->r_direct_hash = ceph_frag_value(frag);
		req->r_direct_is_hash = true;
		req->r_path2 = kstrdup(fi->last_name, GFP_NOFS);
		req->r_readdir_offset = fi->next_offset;
		req->r_args.readdir.frag = cpu_to_le32(frag);
		err = ceph_mdsc_do_request(mdsc, NULL, req);
		if (err < 0) {
			ceph_mdsc_put_request(req);
			return err;
		}
		dout("readdir got and parsed readdir result=%d"
		     " on frag %x, end=%d, complete=%d\n", err, frag,
		     (int)req->r_reply_info.dir_end,
		     (int)req->r_reply_info.dir_complete);

		if (!req->r_did_prepopulate) {
			dout("readdir !did_prepopulate");
			/* preclude from marking dir complete */
			fi->dir_release_count--;
		}

		/* note next offset and last dentry name */
		rinfo = &req->r_reply_info;
		if (le32_to_cpu(rinfo->dir_dir->frag) != frag) {
			frag = le32_to_cpu(rinfo->dir_dir->frag);
			if (ceph_frag_is_leftmost(frag))
				fi->next_offset = 2;
			else
				fi->next_offset = 0;
			off = fi->next_offset;
		}
		fi->frag = frag;
		fi->offset = fi->next_offset;
		fi->last_readdir = req;

		if (req->r_reply_info.dir_end) {
			kfree(fi->last_name);
			fi->last_name = NULL;
			if (ceph_frag_is_rightmost(frag))
				fi->next_offset = 2;
			else
				fi->next_offset = 0;
		} else {
			err = note_last_dentry(fi,
				       rinfo->dir_dname[rinfo->dir_nr-1],
				       rinfo->dir_dname_len[rinfo->dir_nr-1]);
			if (err)
				return err;
			fi->next_offset += rinfo->dir_nr;
		}
	}

	rinfo = &fi->last_readdir->r_reply_info;
	dout("readdir frag %x num %d off %d chunkoff %d\n", frag,
	     rinfo->dir_nr, off, fi->offset);

	ctx->pos = ceph_make_fpos(frag, off);
	while (off >= fi->offset && off - fi->offset < rinfo->dir_nr) {
		struct ceph_mds_reply_inode *in =
			rinfo->dir_in[off - fi->offset].in;
		struct ceph_vino vino;
		ino_t ino;

		dout("readdir off %d (%d/%d) -> %lld '%.*s' %p\n",
		     off, off - fi->offset, rinfo->dir_nr, ctx->pos,
		     rinfo->dir_dname_len[off - fi->offset],
		     rinfo->dir_dname[off - fi->offset], in);
		BUG_ON(!in);
		ftype = le32_to_cpu(in->mode) >> 12;
		vino.ino = le64_to_cpu(in->ino);
		vino.snap = le64_to_cpu(in->snapid);
		ino = ceph_vino_to_ino(vino);
		if (!dir_emit(ctx,
			    rinfo->dir_dname[off - fi->offset],
			    rinfo->dir_dname_len[off - fi->offset],
			    ceph_translate_ino(inode->i_sb, ino), ftype)) {
			dout("filldir stopping us...\n");
			return 0;
		}
		off++;
		ctx->pos++;
	}

	if (fi->last_name) {
		ceph_mdsc_put_request(fi->last_readdir);
		fi->last_readdir = NULL;
		goto more;
	}

	/* more frags? */
	if (!ceph_frag_is_rightmost(frag)) {
		frag = ceph_frag_next(frag);
		off = 0;
		ctx->pos = ceph_make_fpos(frag, off);
		dout("readdir next frag is %x\n", frag);
		goto more;
	}
	fi->flags |= CEPH_F_ATEND;

	/*
	 * if dir_release_count still matches the dir, no dentries
	 * were released during the whole readdir, and we should have
	 * the complete dir contents in our cache.
	 */
	spin_lock(&ci->i_ceph_lock);
	if (atomic_read(&ci->i_release_count) == fi->dir_release_count) {
		dout(" marking %p complete\n", inode);
		__ceph_dir_set_complete(ci, fi->dir_release_count);
	}
	spin_unlock(&ci->i_ceph_lock);

	dout("readdir %p file %p done.\n", inode, file);
	return 0;
}

static void reset_readdir(struct ceph_file_info *fi, unsigned frag)
{
	if (fi->last_readdir) {
		ceph_mdsc_put_request(fi->last_readdir);
		fi->last_readdir = NULL;
	}
	kfree(fi->last_name);
	fi->last_name = NULL;
	if (ceph_frag_is_leftmost(frag))
		fi->next_offset = 2;  /* compensate for . and .. */
	else
		fi->next_offset = 0;
	if (fi->dentry) {
		dput(fi->dentry);
		fi->dentry = NULL;
	}
	fi->flags &= ~CEPH_F_ATEND;
}

static loff_t ceph_dir_llseek(struct file *file, loff_t offset, int whence)
{
	struct ceph_file_info *fi = file->private_data;
	struct inode *inode = file->f_mapping->host;
	loff_t old_offset = ceph_make_fpos(fi->frag, fi->next_offset);
	loff_t retval;

	mutex_lock(&inode->i_mutex);
	retval = -EINVAL;
	switch (whence) {
	case SEEK_END:
		offset += inode->i_size + 2;   /* FIXME */
		break;
	case SEEK_CUR:
		offset += file->f_pos;
	case SEEK_SET:
		break;
	default:
		goto out;
	}

	if (offset >= 0) {
		if (offset != file->f_pos) {
			file->f_pos = offset;
			file->f_version = 0;
			fi->flags &= ~CEPH_F_ATEND;
		}
		retval = offset;

		/*
		 * discard buffered readdir content on seekdir(0), or
		 * seek to new frag, or seek prior to current chunk.
		 */
		if (offset == 0 ||
		    fpos_frag(offset) != fi->frag ||
		    fpos_off(offset) < fi->offset) {
			dout("dir_llseek dropping %p content\n", file);
			reset_readdir(fi, fpos_frag(offset));
		}

		/* bump dir_release_count if we did a forward seek */
		if (fpos_cmp(offset, old_offset) > 0)
			fi->dir_release_count--;
	}
out:
	mutex_unlock(&inode->i_mutex);
	return retval;
}

/*
 * Handle lookups for the hidden .snap directory.
 */
int ceph_handle_snapdir(struct ceph_mds_request *req,
			struct dentry *dentry, int err)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dentry->d_sb);
	struct inode *parent = dentry->d_parent->d_inode; /* we hold i_mutex */

	/* .snap dir? */
	if (err == -ENOENT &&
	    ceph_snap(parent) == CEPH_NOSNAP &&
	    strcmp(dentry->d_name.name,
		   fsc->mount_options->snapdir_name) == 0) {
		struct inode *inode = ceph_get_snapdir(parent);
		dout("ENOENT on snapdir %p '%.*s', linking to snapdir %p\n",
		     dentry, dentry->d_name.len, dentry->d_name.name, inode);
		BUG_ON(!d_unhashed(dentry));
		d_add(dentry, inode);
		err = 0;
	}
	return err;
}

/*
 * Figure out final result of a lookup/open request.
 *
 * Mainly, make sure we return the final req->r_dentry (if it already
 * existed) in place of the original VFS-provided dentry when they
 * differ.
 *
 * Gracefully handle the case where the MDS replies with -ENOENT and
 * no trace (which it may do, at its discretion, e.g., if it doesn't
 * care to issue a lease on the negative dentry).
 */
struct dentry *ceph_finish_lookup(struct ceph_mds_request *req,
				  struct dentry *dentry, int err)
{
	if (err == -ENOENT) {
		/* no trace? */
		err = 0;
		if (!req->r_reply_info.head->is_dentry) {
			dout("ENOENT and no trace, dentry %p inode %p\n",
			     dentry, dentry->d_inode);
			if (dentry->d_inode) {
				d_drop(dentry);
				err = -ENOENT;
			} else {
				d_add(dentry, NULL);
			}
		}
	}
	if (err)
		dentry = ERR_PTR(err);
	else if (dentry != req->r_dentry)
		dentry = dget(req->r_dentry);   /* we got spliced */
	else
		dentry = NULL;
	return dentry;
}

static int is_root_ceph_dentry(struct inode *inode, struct dentry *dentry)
{
	return ceph_ino(inode) == CEPH_INO_ROOT &&
		strncmp(dentry->d_name.name, ".ceph", 5) == 0;
}

/*
 * Look up a single dir entry.  If there is a lookup intent, inform
 * the MDS so that it gets our 'caps wanted' value in a single op.
 */
static struct dentry *ceph_lookup(struct inode *dir, struct dentry *dentry,
				  unsigned int flags)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dir->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	int op;
	int err;

	dout("lookup %p dentry %p '%.*s'\n",
	     dir, dentry, dentry->d_name.len, dentry->d_name.name);

	if (dentry->d_name.len > NAME_MAX)
		return ERR_PTR(-ENAMETOOLONG);

	err = ceph_init_dentry(dentry);
	if (err < 0)
		return ERR_PTR(err);

	/* can we conclude ENOENT locally? */
	if (dentry->d_inode == NULL) {
		struct ceph_inode_info *ci = ceph_inode(dir);
		struct ceph_dentry_info *di = ceph_dentry(dentry);

		spin_lock(&ci->i_ceph_lock);
		dout(" dir %p flags are %d\n", dir, ci->i_ceph_flags);
		if (strncmp(dentry->d_name.name,
			    fsc->mount_options->snapdir_name,
			    dentry->d_name.len) &&
		    !is_root_ceph_dentry(dir, dentry) &&
		    __ceph_dir_is_complete(ci) &&
		    (__ceph_caps_issued_mask(ci, CEPH_CAP_FILE_SHARED, 1))) {
			spin_unlock(&ci->i_ceph_lock);
			dout(" dir %p complete, -ENOENT\n", dir);
			d_add(dentry, NULL);
			di->lease_shared_gen = ci->i_shared_gen;
			return NULL;
		}
		spin_unlock(&ci->i_ceph_lock);
	}

	op = ceph_snap(dir) == CEPH_SNAPDIR ?
		CEPH_MDS_OP_LOOKUPSNAP : CEPH_MDS_OP_LOOKUP;
	req = ceph_mdsc_create_request(mdsc, op, USE_ANY_MDS);
	if (IS_ERR(req))
		return ERR_CAST(req);
	req->r_dentry = dget(dentry);
	req->r_num_caps = 2;
	/* we only need inode linkage */
	req->r_args.getattr.mask = cpu_to_le32(CEPH_STAT_CAP_INODE);
	req->r_locked_dir = dir;
	err = ceph_mdsc_do_request(mdsc, NULL, req);
	err = ceph_handle_snapdir(req, dentry, err);
	dentry = ceph_finish_lookup(req, dentry, err);
	ceph_mdsc_put_request(req);  /* will dput(dentry) */
	dout("lookup result=%p\n", dentry);
	return dentry;
}

/*
 * If we do a create but get no trace back from the MDS, follow up with
 * a lookup (the VFS expects us to link up the provided dentry).
 */
int ceph_handle_notrace_create(struct inode *dir, struct dentry *dentry)
{
	struct dentry *result = ceph_lookup(dir, dentry, 0);

	if (result && !IS_ERR(result)) {
		/*
		 * We created the item, then did a lookup, and found
		 * it was already linked to another inode we already
		 * had in our cache (and thus got spliced).  Link our
		 * dentry to that inode, but don't hash it, just in
		 * case the VFS wants to dereference it.
		 */
		BUG_ON(!result->d_inode);
		d_instantiate(dentry, result->d_inode);
		return 0;
	}
	return PTR_ERR(result);
}

static int ceph_mknod(struct inode *dir, struct dentry *dentry,
		      umode_t mode, dev_t rdev)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dir->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	int err;

	if (ceph_snap(dir) != CEPH_NOSNAP)
		return -EROFS;

	dout("mknod in dir %p dentry %p mode 0%ho rdev %d\n",
	     dir, dentry, mode, rdev);
	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_MKNOD, USE_AUTH_MDS);
	if (IS_ERR(req)) {
		d_drop(dentry);
		return PTR_ERR(req);
	}
	req->r_dentry = dget(dentry);
	req->r_num_caps = 2;
	req->r_locked_dir = dir;
	req->r_args.mknod.mode = cpu_to_le32(mode);
	req->r_args.mknod.rdev = cpu_to_le32(rdev);
	req->r_dentry_drop = CEPH_CAP_FILE_SHARED;
	req->r_dentry_unless = CEPH_CAP_FILE_EXCL;
	err = ceph_mdsc_do_request(mdsc, dir, req);
	if (!err && !req->r_reply_info.head->is_dentry)
		err = ceph_handle_notrace_create(dir, dentry);
	ceph_mdsc_put_request(req);

	if (!err)
		ceph_init_acl(dentry, dentry->d_inode, dir);
	else
		d_drop(dentry);
	return err;
}

static int ceph_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		       bool excl)
{
	return ceph_mknod(dir, dentry, mode, 0);
}

static int ceph_symlink(struct inode *dir, struct dentry *dentry,
			    const char *dest)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dir->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	int err;

	if (ceph_snap(dir) != CEPH_NOSNAP)
		return -EROFS;

	dout("symlink in dir %p dentry %p to '%s'\n", dir, dentry, dest);
	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_SYMLINK, USE_AUTH_MDS);
	if (IS_ERR(req)) {
		d_drop(dentry);
		return PTR_ERR(req);
	}
	req->r_dentry = dget(dentry);
	req->r_num_caps = 2;
	req->r_path2 = kstrdup(dest, GFP_NOFS);
	req->r_locked_dir = dir;
	req->r_dentry_drop = CEPH_CAP_FILE_SHARED;
	req->r_dentry_unless = CEPH_CAP_FILE_EXCL;
	err = ceph_mdsc_do_request(mdsc, dir, req);
	if (!err && !req->r_reply_info.head->is_dentry)
		err = ceph_handle_notrace_create(dir, dentry);
	ceph_mdsc_put_request(req);
	if (!err)
		ceph_init_acl(dentry, dentry->d_inode, dir);
	else
		d_drop(dentry);
	return err;
}

static int ceph_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dir->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	int err = -EROFS;
	int op;

	if (ceph_snap(dir) == CEPH_SNAPDIR) {
		/* mkdir .snap/foo is a MKSNAP */
		op = CEPH_MDS_OP_MKSNAP;
		dout("mksnap dir %p snap '%.*s' dn %p\n", dir,
		     dentry->d_name.len, dentry->d_name.name, dentry);
	} else if (ceph_snap(dir) == CEPH_NOSNAP) {
		dout("mkdir dir %p dn %p mode 0%ho\n", dir, dentry, mode);
		op = CEPH_MDS_OP_MKDIR;
	} else {
		goto out;
	}
	req = ceph_mdsc_create_request(mdsc, op, USE_AUTH_MDS);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto out;
	}

	req->r_dentry = dget(dentry);
	req->r_num_caps = 2;
	req->r_locked_dir = dir;
	req->r_args.mkdir.mode = cpu_to_le32(mode);
	req->r_dentry_drop = CEPH_CAP_FILE_SHARED;
	req->r_dentry_unless = CEPH_CAP_FILE_EXCL;
	err = ceph_mdsc_do_request(mdsc, dir, req);
	if (!err && !req->r_reply_info.head->is_dentry)
		err = ceph_handle_notrace_create(dir, dentry);
	ceph_mdsc_put_request(req);
out:
	if (!err)
		ceph_init_acl(dentry, dentry->d_inode, dir);
	else
		d_drop(dentry);
	return err;
}

static int ceph_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dir->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	int err;

	if (ceph_snap(dir) != CEPH_NOSNAP)
		return -EROFS;

	dout("link in dir %p old_dentry %p dentry %p\n", dir,
	     old_dentry, dentry);
	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_LINK, USE_AUTH_MDS);
	if (IS_ERR(req)) {
		d_drop(dentry);
		return PTR_ERR(req);
	}
	req->r_dentry = dget(dentry);
	req->r_num_caps = 2;
	req->r_old_dentry = dget(old_dentry);
	req->r_locked_dir = dir;
	req->r_dentry_drop = CEPH_CAP_FILE_SHARED;
	req->r_dentry_unless = CEPH_CAP_FILE_EXCL;
	/* release LINK_SHARED on source inode (mds will lock it) */
	req->r_old_inode_drop = CEPH_CAP_LINK_SHARED;
	err = ceph_mdsc_do_request(mdsc, dir, req);
	if (err) {
		d_drop(dentry);
	} else if (!req->r_reply_info.head->is_dentry) {
		ihold(old_dentry->d_inode);
		d_instantiate(dentry, old_dentry->d_inode);
	}
	ceph_mdsc_put_request(req);
	return err;
}

/*
 * For a soon-to-be unlinked file, drop the AUTH_RDCACHE caps.  If it
 * looks like the link count will hit 0, drop any other caps (other
 * than PIN) we don't specifically want (due to the file still being
 * open).
 */
static int drop_caps_for_unlink(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int drop = CEPH_CAP_LINK_SHARED | CEPH_CAP_LINK_EXCL;

	spin_lock(&ci->i_ceph_lock);
	if (inode->i_nlink == 1) {
		drop |= ~(__ceph_caps_wanted(ci) | CEPH_CAP_PIN);
		ci->i_ceph_flags |= CEPH_I_NODELAY;
	}
	spin_unlock(&ci->i_ceph_lock);
	return drop;
}

/*
 * rmdir and unlink are differ only by the metadata op code
 */
static int ceph_unlink(struct inode *dir, struct dentry *dentry)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dir->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct inode *inode = dentry->d_inode;
	struct ceph_mds_request *req;
	int err = -EROFS;
	int op;

	if (ceph_snap(dir) == CEPH_SNAPDIR) {
		/* rmdir .snap/foo is RMSNAP */
		dout("rmsnap dir %p '%.*s' dn %p\n", dir, dentry->d_name.len,
		     dentry->d_name.name, dentry);
		op = CEPH_MDS_OP_RMSNAP;
	} else if (ceph_snap(dir) == CEPH_NOSNAP) {
		dout("unlink/rmdir dir %p dn %p inode %p\n",
		     dir, dentry, inode);
		op = S_ISDIR(dentry->d_inode->i_mode) ?
			CEPH_MDS_OP_RMDIR : CEPH_MDS_OP_UNLINK;
	} else
		goto out;
	req = ceph_mdsc_create_request(mdsc, op, USE_AUTH_MDS);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto out;
	}
	req->r_dentry = dget(dentry);
	req->r_num_caps = 2;
	req->r_locked_dir = dir;
	req->r_dentry_drop = CEPH_CAP_FILE_SHARED;
	req->r_dentry_unless = CEPH_CAP_FILE_EXCL;
	req->r_inode_drop = drop_caps_for_unlink(inode);
	err = ceph_mdsc_do_request(mdsc, dir, req);
	if (!err && !req->r_reply_info.head->is_dentry)
		d_delete(dentry);
	ceph_mdsc_put_request(req);
out:
	return err;
}

static int ceph_rename(struct inode *old_dir, struct dentry *old_dentry,
		       struct inode *new_dir, struct dentry *new_dentry)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(old_dir->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	int err;

	if (ceph_snap(old_dir) != ceph_snap(new_dir))
		return -EXDEV;
	if (ceph_snap(old_dir) != CEPH_NOSNAP ||
	    ceph_snap(new_dir) != CEPH_NOSNAP)
		return -EROFS;
	dout("rename dir %p dentry %p to dir %p dentry %p\n",
	     old_dir, old_dentry, new_dir, new_dentry);
	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_RENAME, USE_AUTH_MDS);
	if (IS_ERR(req))
		return PTR_ERR(req);
	ihold(old_dir);
	req->r_dentry = dget(new_dentry);
	req->r_num_caps = 2;
	req->r_old_dentry = dget(old_dentry);
	req->r_old_dentry_dir = old_dir;
	req->r_locked_dir = new_dir;
	req->r_old_dentry_drop = CEPH_CAP_FILE_SHARED;
	req->r_old_dentry_unless = CEPH_CAP_FILE_EXCL;
	req->r_dentry_drop = CEPH_CAP_FILE_SHARED;
	req->r_dentry_unless = CEPH_CAP_FILE_EXCL;
	/* release LINK_RDCACHE on source inode (mds will lock it) */
	req->r_old_inode_drop = CEPH_CAP_LINK_SHARED;
	if (new_dentry->d_inode)
		req->r_inode_drop = drop_caps_for_unlink(new_dentry->d_inode);
	err = ceph_mdsc_do_request(mdsc, old_dir, req);
	if (!err && !req->r_reply_info.head->is_dentry) {
		/*
		 * Normally d_move() is done by fill_trace (called by
		 * do_request, above).  If there is no trace, we need
		 * to do it here.
		 */

		d_move(old_dentry, new_dentry);

		/* ensure target dentry is invalidated, despite
		   rehashing bug in vfs_rename_dir */
		ceph_invalidate_dentry_lease(new_dentry);

		/* d_move screws up sibling dentries' offsets */
		ceph_dir_clear_complete(old_dir);
		ceph_dir_clear_complete(new_dir);

	}
	ceph_mdsc_put_request(req);
	return err;
}

/*
 * Ensure a dentry lease will no longer revalidate.
 */
void ceph_invalidate_dentry_lease(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	dentry->d_time = jiffies;
	ceph_dentry(dentry)->lease_shared_gen = 0;
	spin_unlock(&dentry->d_lock);
}

/*
 * Check if dentry lease is valid.  If not, delete the lease.  Try to
 * renew if the least is more than half up.
 */
static int dentry_lease_is_valid(struct dentry *dentry)
{
	struct ceph_dentry_info *di;
	struct ceph_mds_session *s;
	int valid = 0;
	u32 gen;
	unsigned long ttl;
	struct ceph_mds_session *session = NULL;
	struct inode *dir = NULL;
	u32 seq = 0;

	spin_lock(&dentry->d_lock);
	di = ceph_dentry(dentry);
	if (di->lease_session) {
		s = di->lease_session;
		spin_lock(&s->s_gen_ttl_lock);
		gen = s->s_cap_gen;
		ttl = s->s_cap_ttl;
		spin_unlock(&s->s_gen_ttl_lock);

		if (di->lease_gen == gen &&
		    time_before(jiffies, dentry->d_time) &&
		    time_before(jiffies, ttl)) {
			valid = 1;
			if (di->lease_renew_after &&
			    time_after(jiffies, di->lease_renew_after)) {
				/* we should renew */
				dir = dentry->d_parent->d_inode;
				session = ceph_get_mds_session(s);
				seq = di->lease_seq;
				di->lease_renew_after = 0;
				di->lease_renew_from = jiffies;
			}
		}
	}
	spin_unlock(&dentry->d_lock);

	if (session) {
		ceph_mdsc_lease_send_msg(session, dir, dentry,
					 CEPH_MDS_LEASE_RENEW, seq);
		ceph_put_mds_session(session);
	}
	dout("dentry_lease_is_valid - dentry %p = %d\n", dentry, valid);
	return valid;
}

/*
 * Check if directory-wide content lease/cap is valid.
 */
static int dir_lease_is_valid(struct inode *dir, struct dentry *dentry)
{
	struct ceph_inode_info *ci = ceph_inode(dir);
	struct ceph_dentry_info *di = ceph_dentry(dentry);
	int valid = 0;

	spin_lock(&ci->i_ceph_lock);
	if (ci->i_shared_gen == di->lease_shared_gen)
		valid = __ceph_caps_issued_mask(ci, CEPH_CAP_FILE_SHARED, 1);
	spin_unlock(&ci->i_ceph_lock);
	dout("dir_lease_is_valid dir %p v%u dentry %p v%u = %d\n",
	     dir, (unsigned)ci->i_shared_gen, dentry,
	     (unsigned)di->lease_shared_gen, valid);
	return valid;
}

/*
 * Check if cached dentry can be trusted.
 */
static int ceph_d_revalidate(struct dentry *dentry, unsigned int flags)
{
	int valid = 0;
	struct inode *dir;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	dout("d_revalidate %p '%.*s' inode %p offset %lld\n", dentry,
	     dentry->d_name.len, dentry->d_name.name, dentry->d_inode,
	     ceph_dentry(dentry)->offset);

	dir = ceph_get_dentry_parent_inode(dentry);

	/* always trust cached snapped dentries, snapdir dentry */
	if (ceph_snap(dir) != CEPH_NOSNAP) {
		dout("d_revalidate %p '%.*s' inode %p is SNAPPED\n", dentry,
		     dentry->d_name.len, dentry->d_name.name, dentry->d_inode);
		valid = 1;
	} else if (dentry->d_inode &&
		   ceph_snap(dentry->d_inode) == CEPH_SNAPDIR) {
		valid = 1;
	} else if (dentry_lease_is_valid(dentry) ||
		   dir_lease_is_valid(dir, dentry)) {
		if (dentry->d_inode)
			valid = ceph_is_any_caps(dentry->d_inode);
		else
			valid = 1;
	}

	dout("d_revalidate %p %s\n", dentry, valid ? "valid" : "invalid");
	if (valid) {
		ceph_dentry_lru_touch(dentry);
	} else {
		ceph_dir_clear_complete(dir);
		d_drop(dentry);
	}
	iput(dir);
	return valid;
}

/*
 * Release our ceph_dentry_info.
 */
static void ceph_d_release(struct dentry *dentry)
{
	struct ceph_dentry_info *di = ceph_dentry(dentry);

	dout("d_release %p\n", dentry);
	ceph_dentry_lru_del(dentry);
	if (di->lease_session)
		ceph_put_mds_session(di->lease_session);
	kmem_cache_free(ceph_dentry_cachep, di);
	dentry->d_fsdata = NULL;
}

static int ceph_snapdir_d_revalidate(struct dentry *dentry,
					  unsigned int flags)
{
	/*
	 * Eventually, we'll want to revalidate snapped metadata
	 * too... probably...
	 */
	return 1;
}

/*
 * When the VFS prunes a dentry from the cache, we need to clear the
 * complete flag on the parent directory.
 *
 * Called under dentry->d_lock.
 */
static void ceph_d_prune(struct dentry *dentry)
{
	dout("ceph_d_prune %p\n", dentry);

	/* do we have a valid parent? */
	if (IS_ROOT(dentry))
		return;

	/* if we are not hashed, we don't affect dir's completeness */
	if (d_unhashed(dentry))
		return;

	/*
	 * we hold d_lock, so d_parent is stable, and d_fsdata is never
	 * cleared until d_release
	 */
	ceph_dir_clear_complete(dentry->d_parent->d_inode);
}

/*
 * read() on a dir.  This weird interface hack only works if mounted
 * with '-o dirstat'.
 */
static ssize_t ceph_read_dir(struct file *file, char __user *buf, size_t size,
			     loff_t *ppos)
{
	struct ceph_file_info *cf = file->private_data;
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	int left;
	const int bufsize = 1024;

	if (!ceph_test_mount_opt(ceph_sb_to_client(inode->i_sb), DIRSTAT))
		return -EISDIR;

	if (!cf->dir_info) {
		cf->dir_info = kmalloc(bufsize, GFP_NOFS);
		if (!cf->dir_info)
			return -ENOMEM;
		cf->dir_info_len =
			snprintf(cf->dir_info, bufsize,
				"entries:   %20lld\n"
				" files:    %20lld\n"
				" subdirs:  %20lld\n"
				"rentries:  %20lld\n"
				" rfiles:   %20lld\n"
				" rsubdirs: %20lld\n"
				"rbytes:    %20lld\n"
				"rctime:    %10ld.%09ld\n",
				ci->i_files + ci->i_subdirs,
				ci->i_files,
				ci->i_subdirs,
				ci->i_rfiles + ci->i_rsubdirs,
				ci->i_rfiles,
				ci->i_rsubdirs,
				ci->i_rbytes,
				(long)ci->i_rctime.tv_sec,
				(long)ci->i_rctime.tv_nsec);
	}

	if (*ppos >= cf->dir_info_len)
		return 0;
	size = min_t(unsigned, size, cf->dir_info_len-*ppos);
	left = copy_to_user(buf, cf->dir_info + *ppos, size);
	if (left == size)
		return -EFAULT;
	*ppos += (size - left);
	return size - left;
}

/*
 * an fsync() on a dir will wait for any uncommitted directory
 * operations to commit.
 */
static int ceph_dir_fsync(struct file *file, loff_t start, loff_t end,
			  int datasync)
{
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct list_head *head = &ci->i_unsafe_dirops;
	struct ceph_mds_request *req;
	u64 last_tid;
	int ret = 0;

	dout("dir_fsync %p\n", inode);
	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;
	mutex_lock(&inode->i_mutex);

	spin_lock(&ci->i_unsafe_lock);
	if (list_empty(head))
		goto out;

	req = list_entry(head->prev,
			 struct ceph_mds_request, r_unsafe_dir_item);
	last_tid = req->r_tid;

	do {
		ceph_mdsc_get_request(req);
		spin_unlock(&ci->i_unsafe_lock);

		dout("dir_fsync %p wait on tid %llu (until %llu)\n",
		     inode, req->r_tid, last_tid);
		if (req->r_timeout) {
			ret = wait_for_completion_timeout(
				&req->r_safe_completion, req->r_timeout);
			if (ret > 0)
				ret = 0;
			else if (ret == 0)
				ret = -EIO;  /* timed out */
		} else {
			wait_for_completion(&req->r_safe_completion);
		}
		ceph_mdsc_put_request(req);

		spin_lock(&ci->i_unsafe_lock);
		if (ret || list_empty(head))
			break;
		req = list_entry(head->next,
				 struct ceph_mds_request, r_unsafe_dir_item);
	} while (req->r_tid < last_tid);
out:
	spin_unlock(&ci->i_unsafe_lock);
	mutex_unlock(&inode->i_mutex);

	return ret;
}

/*
 * We maintain a private dentry LRU.
 *
 * FIXME: this needs to be changed to a per-mds lru to be useful.
 */
void ceph_dentry_lru_add(struct dentry *dn)
{
	struct ceph_dentry_info *di = ceph_dentry(dn);
	struct ceph_mds_client *mdsc;

	dout("dentry_lru_add %p %p '%.*s'\n", di, dn,
	     dn->d_name.len, dn->d_name.name);
	mdsc = ceph_sb_to_client(dn->d_sb)->mdsc;
	spin_lock(&mdsc->dentry_lru_lock);
	list_add_tail(&di->lru, &mdsc->dentry_lru);
	mdsc->num_dentry++;
	spin_unlock(&mdsc->dentry_lru_lock);
}

void ceph_dentry_lru_touch(struct dentry *dn)
{
	struct ceph_dentry_info *di = ceph_dentry(dn);
	struct ceph_mds_client *mdsc;

	dout("dentry_lru_touch %p %p '%.*s' (offset %lld)\n", di, dn,
	     dn->d_name.len, dn->d_name.name, di->offset);
	mdsc = ceph_sb_to_client(dn->d_sb)->mdsc;
	spin_lock(&mdsc->dentry_lru_lock);
	list_move_tail(&di->lru, &mdsc->dentry_lru);
	spin_unlock(&mdsc->dentry_lru_lock);
}

void ceph_dentry_lru_del(struct dentry *dn)
{
	struct ceph_dentry_info *di = ceph_dentry(dn);
	struct ceph_mds_client *mdsc;

	dout("dentry_lru_del %p %p '%.*s'\n", di, dn,
	     dn->d_name.len, dn->d_name.name);
	mdsc = ceph_sb_to_client(dn->d_sb)->mdsc;
	spin_lock(&mdsc->dentry_lru_lock);
	list_del_init(&di->lru);
	mdsc->num_dentry--;
	spin_unlock(&mdsc->dentry_lru_lock);
}

/*
 * Return name hash for a given dentry.  This is dependent on
 * the parent directory's hash function.
 */
unsigned ceph_dentry_hash(struct inode *dir, struct dentry *dn)
{
	struct ceph_inode_info *dci = ceph_inode(dir);

	switch (dci->i_dir_layout.dl_dir_hash) {
	case 0:	/* for backward compat */
	case CEPH_STR_HASH_LINUX:
		return dn->d_name.hash;

	default:
		return ceph_str_hash(dci->i_dir_layout.dl_dir_hash,
				     dn->d_name.name, dn->d_name.len);
	}
}

const struct file_operations ceph_dir_fops = {
	.read = ceph_read_dir,
	.iterate = ceph_readdir,
	.llseek = ceph_dir_llseek,
	.open = ceph_open,
	.release = ceph_release,
	.unlocked_ioctl = ceph_ioctl,
	.fsync = ceph_dir_fsync,
};

const struct inode_operations ceph_dir_iops = {
	.lookup = ceph_lookup,
	.permission = ceph_permission,
	.getattr = ceph_getattr,
	.setattr = ceph_setattr,
	.setxattr = ceph_setxattr,
	.getxattr = ceph_getxattr,
	.listxattr = ceph_listxattr,
	.removexattr = ceph_removexattr,
	.get_acl = ceph_get_acl,
	.set_acl = ceph_set_acl,
	.mknod = ceph_mknod,
	.symlink = ceph_symlink,
	.mkdir = ceph_mkdir,
	.link = ceph_link,
	.unlink = ceph_unlink,
	.rmdir = ceph_unlink,
	.rename = ceph_rename,
	.create = ceph_create,
	.atomic_open = ceph_atomic_open,
};

const struct dentry_operations ceph_dentry_ops = {
	.d_revalidate = ceph_d_revalidate,
	.d_release = ceph_d_release,
	.d_prune = ceph_d_prune,
};

const struct dentry_operations ceph_snapdir_dentry_ops = {
	.d_revalidate = ceph_snapdir_d_revalidate,
	.d_release = ceph_d_release,
};

const struct dentry_operations ceph_snap_dentry_ops = {
	.d_release = ceph_d_release,
	.d_prune = ceph_d_prune,
};
/************************************************************/
/* ../linux-3.17/fs/ceph/dir.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

// #include <linux/module.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
#include <linux/file.h>
// #include <linux/mount.h>
// #include <linux/namei.h>
// #include <linux/writeback.h>
#include <linux/aio.h>
#include <linux/falloc.h>

// #include "super.h"
// #include "mds_client.h"
// #include "cache.h"

/*
 * Ceph file operations
 *
 * Implement basic open/close functionality, and implement
 * read/write.
 *
 * We implement three modes of file I/O:
 *  - buffered uses the generic_file_aio_{read,write} helpers
 *
 *  - synchronous is used when there is multi-client read/write
 *    sharing, avoids the page cache, and synchronously waits for an
 *    ack from the OSD.
 *
 *  - direct io takes the variant of the sync path that references
 *    user pages directly.
 *
 * fsync() flushes and waits on dirty pages, but just queues metadata
 * for writeback: since the MDS can recover size and mtime there is no
 * need to wait for MDS acknowledgement.
 */


/*
 * Prepare an open request.  Preallocate ceph_cap to avoid an
 * inopportune ENOMEM later.
 */
static struct ceph_mds_request *
prepare_open_request(struct super_block *sb, int flags, int create_mode)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	int want_auth = USE_ANY_MDS;
	int op = (flags & O_CREAT) ? CEPH_MDS_OP_CREATE : CEPH_MDS_OP_OPEN;

	if (flags & (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC))
		want_auth = USE_AUTH_MDS;

	req = ceph_mdsc_create_request(mdsc, op, want_auth);
	if (IS_ERR(req))
		goto out;
	req->r_fmode = ceph_flags_to_mode(flags);
	req->r_args.open.flags = cpu_to_le32(flags);
	req->r_args.open.mode = cpu_to_le32(create_mode);
out:
	return req;
}

/*
 * initialize private struct file data.
 * if we fail, clean up by dropping fmode reference on the ceph_inode
 */
static int ceph_init_file(struct inode *inode, struct file *file, int fmode)
{
	struct ceph_file_info *cf;
	int ret = 0;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_sb_to_client(inode->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		/* First file open request creates the cookie, we want to keep
		 * this cookie around for the filetime of the inode as not to
		 * have to worry about fscache register / revoke / operation
		 * races.
		 *
		 * Also, if we know the operation is going to invalidate data
		 * (non readonly) just nuke the cache right away.
		 */
		ceph_fscache_register_inode_cookie(mdsc->fsc, ci);
		if ((fmode & CEPH_FILE_MODE_WR))
			ceph_fscache_invalidate(inode);
	case S_IFDIR:
		dout("init_file %p %p 0%o (regular)\n", inode, file,
		     inode->i_mode);
		cf = kmem_cache_alloc(ceph_file_cachep, GFP_NOFS | __GFP_ZERO);
		if (cf == NULL) {
			ceph_put_fmode(ceph_inode(inode), fmode); /* clean up */
			return -ENOMEM;
		}
		cf->fmode = fmode;
		cf->next_offset = 2;
		file->private_data = cf;
		BUG_ON(inode->i_fop->release != ceph_release);
		break;

	case S_IFLNK:
		dout("init_file %p %p 0%o (symlink)\n", inode, file,
		     inode->i_mode);
		ceph_put_fmode(ceph_inode(inode), fmode); /* clean up */
		break;

	default:
		dout("init_file %p %p 0%o (special)\n", inode, file,
		     inode->i_mode);
		/*
		 * we need to drop the open ref now, since we don't
		 * have .release set to ceph_release.
		 */
		ceph_put_fmode(ceph_inode(inode), fmode); /* clean up */
		BUG_ON(inode->i_fop->release == ceph_release);

		/* call the proper open fop */
		ret = inode->i_fop->open(inode, file);
	}
	return ret;
}

/*
 * If we already have the requisite capabilities, we can satisfy
 * the open request locally (no need to request new caps from the
 * MDS).  We do, however, need to inform the MDS (asynchronously)
 * if our wanted caps set expands.
 */
int ceph_open(struct inode *inode, struct file *file)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_sb_to_client(inode->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	struct ceph_file_info *cf = file->private_data;
	struct inode *parent_inode = NULL;
	int err;
	int flags, fmode, wanted;

	if (cf) {
		dout("open file %p is already opened\n", file);
		return 0;
	}

	/* filter out O_CREAT|O_EXCL; vfs did that already.  yuck. */
	flags = file->f_flags & ~(O_CREAT|O_EXCL);
	if (S_ISDIR(inode->i_mode))
		flags = O_DIRECTORY;  /* mds likes to know */

	dout("open inode %p ino %llx.%llx file %p flags %d (%d)\n", inode,
	     ceph_vinop(inode), file, flags, file->f_flags);
	fmode = ceph_flags_to_mode(flags);
	wanted = ceph_caps_for_mode(fmode);

	/* snapped files are read-only */
	if (ceph_snap(inode) != CEPH_NOSNAP && (file->f_mode & FMODE_WRITE))
		return -EROFS;

	/* trivially open snapdir */
	if (ceph_snap(inode) == CEPH_SNAPDIR) {
		spin_lock(&ci->i_ceph_lock);
		__ceph_get_fmode(ci, fmode);
		spin_unlock(&ci->i_ceph_lock);
		return ceph_init_file(inode, file, fmode);
	}

	/*
	 * No need to block if we have caps on the auth MDS (for
	 * write) or any MDS (for read).  Update wanted set
	 * asynchronously.
	 */
	spin_lock(&ci->i_ceph_lock);
	if (__ceph_is_any_real_caps(ci) &&
	    (((fmode & CEPH_FILE_MODE_WR) == 0) || ci->i_auth_cap)) {
		int mds_wanted = __ceph_caps_mds_wanted(ci);
		int issued = __ceph_caps_issued(ci, NULL);

		dout("open %p fmode %d want %s issued %s using existing\n",
		     inode, fmode, ceph_cap_string(wanted),
		     ceph_cap_string(issued));
		__ceph_get_fmode(ci, fmode);
		spin_unlock(&ci->i_ceph_lock);

		/* adjust wanted? */
		if ((issued & wanted) != wanted &&
		    (mds_wanted & wanted) != wanted &&
		    ceph_snap(inode) != CEPH_SNAPDIR)
			ceph_check_caps(ci, 0, NULL);

		return ceph_init_file(inode, file, fmode);
	} else if (ceph_snap(inode) != CEPH_NOSNAP &&
		   (ci->i_snap_caps & wanted) == wanted) {
		__ceph_get_fmode(ci, fmode);
		spin_unlock(&ci->i_ceph_lock);
		return ceph_init_file(inode, file, fmode);
	}

	spin_unlock(&ci->i_ceph_lock);

	dout("open fmode %d wants %s\n", fmode, ceph_cap_string(wanted));
	req = prepare_open_request(inode->i_sb, flags, 0);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto out;
	}
	req->r_inode = inode;
	ihold(inode);

	req->r_num_caps = 1;
	if (flags & O_CREAT)
		parent_inode = ceph_get_dentry_parent_inode(file->f_dentry);
	err = ceph_mdsc_do_request(mdsc, parent_inode, req);
	iput(parent_inode);
	if (!err)
		err = ceph_init_file(inode, file, req->r_fmode);
	ceph_mdsc_put_request(req);
	dout("open result=%d on %llx.%llx\n", err, ceph_vinop(inode));
out:
	return err;
}


/*
 * Do a lookup + open with a single request.  If we get a non-existent
 * file or symlink, return 1 so the VFS can retry.
 */
int ceph_atomic_open(struct inode *dir, struct dentry *dentry,
		     struct file *file, unsigned flags, umode_t mode,
		     int *opened)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dir->i_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	struct dentry *dn;
	int err;

	dout("atomic_open %p dentry %p '%.*s' %s flags %d mode 0%o\n",
	     dir, dentry, dentry->d_name.len, dentry->d_name.name,
	     d_unhashed(dentry) ? "unhashed" : "hashed", flags, mode);

	if (dentry->d_name.len > NAME_MAX)
		return -ENAMETOOLONG;

	err = ceph_init_dentry(dentry);
	if (err < 0)
		return err;

	/* do the open */
	req = prepare_open_request(dir->i_sb, flags, mode);
	if (IS_ERR(req))
		return PTR_ERR(req);
	req->r_dentry = dget(dentry);
	req->r_num_caps = 2;
	if (flags & O_CREAT) {
		req->r_dentry_drop = CEPH_CAP_FILE_SHARED;
		req->r_dentry_unless = CEPH_CAP_FILE_EXCL;
	}
	req->r_locked_dir = dir;           /* caller holds dir->i_mutex */
	err = ceph_mdsc_do_request(mdsc,
				   (flags & (O_CREAT|O_TRUNC)) ? dir : NULL,
				   req);
	if (err)
		goto out_err;

	err = ceph_handle_snapdir(req, dentry, err);
	if (err == 0 && (flags & O_CREAT) && !req->r_reply_info.head->is_dentry)
		err = ceph_handle_notrace_create(dir, dentry);

	if (d_unhashed(dentry)) {
		dn = ceph_finish_lookup(req, dentry, err);
		if (IS_ERR(dn))
			err = PTR_ERR(dn);
	} else {
		/* we were given a hashed negative dentry */
		dn = NULL;
	}
	if (err)
		goto out_err;
	if (dn || dentry->d_inode == NULL || S_ISLNK(dentry->d_inode->i_mode)) {
		/* make vfs retry on splice, ENOENT, or symlink */
		dout("atomic_open finish_no_open on dn %p\n", dn);
		err = finish_no_open(file, dn);
	} else {
		dout("atomic_open finish_open on dn %p\n", dn);
		if (req->r_op == CEPH_MDS_OP_CREATE && req->r_reply_info.has_create_ino) {
			ceph_init_acl(dentry, dentry->d_inode, dir);
			*opened |= FILE_CREATED;
		}
		err = finish_open(file, dentry, ceph_open, opened);
	}
out_err:
	if (!req->r_err && req->r_target_inode)
		ceph_put_fmode(ceph_inode(req->r_target_inode), req->r_fmode);
	ceph_mdsc_put_request(req);
	dout("atomic_open result=%d\n", err);
	return err;
}

int ceph_release(struct inode *inode, struct file *file)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_file_info *cf = file->private_data;

	dout("release inode %p file %p\n", inode, file);
	ceph_put_fmode(ci, cf->fmode);
	if (cf->last_readdir)
		ceph_mdsc_put_request(cf->last_readdir);
	kfree(cf->last_name);
	kfree(cf->dir_info);
	dput(cf->dentry);
	kmem_cache_free(ceph_file_cachep, cf);

	/* wake up anyone waiting for caps on this inode */
	wake_up_all(&ci->i_cap_wq);
	return 0;
}

/*
 * Read a range of bytes striped over one or more objects.  Iterate over
 * objects we stripe over.  (That's not atomic, but good enough for now.)
 *
 * If we get a short result from the OSD, check against i_size; we need to
 * only return a short read to the caller if we hit EOF.
 */
static int striped_read(struct inode *inode,
			u64 off, u64 len,
			struct page **pages, int num_pages,
			int *checkeof, bool o_direct,
			unsigned long buf_align)
{
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	struct ceph_inode_info *ci = ceph_inode(inode);
	u64 pos, this_len, left;
	int io_align, page_align;
	int pages_left;
	int read;
	struct page **page_pos;
	int ret;
	bool hit_stripe, was_short;

	/*
	 * we may need to do multiple reads.  not atomic, unfortunately.
	 */
	pos = off;
	left = len;
	page_pos = pages;
	pages_left = num_pages;
	read = 0;
	io_align = off & ~PAGE_MASK;

more:
	if (o_direct)
		page_align = (pos - io_align + buf_align) & ~PAGE_MASK;
	else
		page_align = pos & ~PAGE_MASK;
	this_len = left;
	ret = ceph_osdc_readpages(&fsc->client->osdc, ceph_vino(inode),
				  &ci->i_layout, pos, &this_len,
				  ci->i_truncate_seq,
				  ci->i_truncate_size,
				  page_pos, pages_left, page_align);
	if (ret == -ENOENT)
		ret = 0;
	hit_stripe = this_len < left;
	was_short = ret >= 0 && ret < this_len;
	dout("striped_read %llu~%llu (read %u) got %d%s%s\n", pos, left, read,
	     ret, hit_stripe ? " HITSTRIPE" : "", was_short ? " SHORT" : "");

	if (ret >= 0) {
		int didpages;
		if (was_short && (pos + ret < inode->i_size)) {
			u64 tmp = min(this_len - ret,
					inode->i_size - pos - ret);
			dout(" zero gap %llu to %llu\n",
				pos + ret, pos + ret + tmp);
			ceph_zero_page_vector_range(page_align + read + ret,
							tmp, pages);
			ret += tmp;
		}

		didpages = (page_align + ret) >> PAGE_CACHE_SHIFT;
		pos += ret;
		read = pos - off;
		left -= ret;
		page_pos += didpages;
		pages_left -= didpages;

		/* hit stripe and need continue*/
		if (left && hit_stripe && pos < inode->i_size)
			goto more;
	}

	if (read > 0) {
		ret = read;
		/* did we bounce off eof? */
		if (pos + left > inode->i_size)
			*checkeof = 1;
	}

	dout("striped_read returns %d\n", ret);
	return ret;
}

/*
 * Completely synchronous read and write methods.  Direct from __user
 * buffer to osd, or directly to user pages (if O_DIRECT).
 *
 * If the read spans object boundary, just do multiple reads.
 */
static ssize_t ceph_sync_read(struct kiocb *iocb, struct iov_iter *i,
				int *checkeof)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct page **pages;
	u64 off = iocb->ki_pos;
	int num_pages, ret;
	size_t len = iov_iter_count(i);

	dout("sync_read on file %p %llu~%u %s\n", file, off,
	     (unsigned)len,
	     (file->f_flags & O_DIRECT) ? "O_DIRECT" : "");

	if (!len)
		return 0;
	/*
	 * flush any page cache pages in this range.  this
	 * will make concurrent normal and sync io slow,
	 * but it will at least behave sensibly when they are
	 * in sequence.
	 */
	ret = filemap_write_and_wait_range(inode->i_mapping, off,
						off + len);
	if (ret < 0)
		return ret;

	if (file->f_flags & O_DIRECT) {
		while (iov_iter_count(i)) {
			size_t start;
			ssize_t n;

			n = iov_iter_get_pages_alloc(i, &pages, INT_MAX, &start);
			if (n < 0)
				return n;

			num_pages = (n + start + PAGE_SIZE - 1) / PAGE_SIZE;

			ret = striped_read(inode, off, n,
					   pages, num_pages, checkeof,
					   1, start);

			ceph_put_page_vector(pages, num_pages, true);

			if (ret <= 0)
				break;
			off += ret;
			iov_iter_advance(i, ret);
			if (ret < n)
				break;
		}
	} else {
		num_pages = calc_pages_for(off, len);
		pages = ceph_alloc_page_vector(num_pages, GFP_NOFS);
		if (IS_ERR(pages))
			return PTR_ERR(pages);
		ret = striped_read(inode, off, len, pages,
					num_pages, checkeof, 0, 0);
		if (ret > 0) {
			int l, k = 0;
			size_t left = ret;

			while (left) {
				size_t page_off = off & ~PAGE_MASK;
				size_t copy = min_t(size_t,
						    PAGE_SIZE - page_off, left);
				l = copy_page_to_iter(pages[k++], page_off,
						      copy, i);
				off += l;
				left -= l;
				if (l < copy)
					break;
			}
		}
		ceph_release_page_vector(pages, num_pages);
	}

	if (off > iocb->ki_pos) {
		ret = off - iocb->ki_pos;
		iocb->ki_pos = off;
	}

	dout("sync_read result %d\n", ret);
	return ret;
}

/*
 * Write commit request unsafe callback, called to tell us when a
 * request is unsafe (that is, in flight--has been handed to the
 * messenger to send to its target osd).  It is called again when
 * we've received a response message indicating the request is
 * "safe" (its CEPH_OSD_FLAG_ONDISK flag is set), or when a request
 * is completed early (and unsuccessfully) due to a timeout or
 * interrupt.
 *
 * This is used if we requested both an ACK and ONDISK commit reply
 * from the OSD.
 */
static void ceph_sync_write_unsafe(struct ceph_osd_request *req, bool unsafe)
{
	struct ceph_inode_info *ci = ceph_inode(req->r_inode);

	dout("%s %p tid %llu %ssafe\n", __func__, req, req->r_tid,
		unsafe ? "un" : "");
	if (unsafe) {
		ceph_get_cap_refs(ci, CEPH_CAP_FILE_WR);
		spin_lock(&ci->i_unsafe_lock);
		list_add_tail(&req->r_unsafe_item,
			      &ci->i_unsafe_writes);
		spin_unlock(&ci->i_unsafe_lock);
	} else {
		spin_lock(&ci->i_unsafe_lock);
		list_del_init(&req->r_unsafe_item);
		spin_unlock(&ci->i_unsafe_lock);
		ceph_put_cap_refs(ci, CEPH_CAP_FILE_WR);
	}
}


/*
 * Synchronous write, straight from __user pointer or user pages.
 *
 * If write spans object boundary, just do multiple writes.  (For a
 * correct atomic write, we should e.g. take write locks on all
 * objects, rollback on failure, etc.)
 */
static ssize_t
ceph_sync_direct_write(struct kiocb *iocb, struct iov_iter *from, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	struct ceph_snap_context *snapc;
	struct ceph_vino vino;
	struct ceph_osd_request *req;
	struct page **pages;
	int num_pages;
	int written = 0;
	int flags;
	int check_caps = 0;
	int ret;
	struct timespec mtime = CURRENT_TIME;
	size_t count = iov_iter_count(from);

	if (ceph_snap(file_inode(file)) != CEPH_NOSNAP)
		return -EROFS;

	dout("sync_direct_write on file %p %lld~%u\n", file, pos,
	     (unsigned)count);

	ret = filemap_write_and_wait_range(inode->i_mapping, pos, pos + count);
	if (ret < 0)
		return ret;

	ret = invalidate_inode_pages2_range(inode->i_mapping,
					    pos >> PAGE_CACHE_SHIFT,
					    (pos + count) >> PAGE_CACHE_SHIFT);
	if (ret < 0)
		dout("invalidate_inode_pages2_range returned %d\n", ret);

	flags = CEPH_OSD_FLAG_ORDERSNAP |
		CEPH_OSD_FLAG_ONDISK |
		CEPH_OSD_FLAG_WRITE;

	while (iov_iter_count(from) > 0) {
		u64 len = iov_iter_single_seg_count(from);
		size_t start;
		ssize_t n;

		snapc = ci->i_snap_realm->cached_context;
		vino = ceph_vino(inode);
		req = ceph_osdc_new_request(&fsc->client->osdc, &ci->i_layout,
					    vino, pos, &len,
					    2,/*include a 'startsync' command*/
					    CEPH_OSD_OP_WRITE, flags, snapc,
					    ci->i_truncate_seq,
					    ci->i_truncate_size,
					    false);
		if (IS_ERR(req)) {
			ret = PTR_ERR(req);
			break;
		}

		n = iov_iter_get_pages_alloc(from, &pages, len, &start);
		if (unlikely(n < 0)) {
			ret = n;
			ceph_osdc_put_request(req);
			break;
		}

		num_pages = (n + start + PAGE_SIZE - 1) / PAGE_SIZE;
		/*
		 * throw out any page cache pages in this range. this
		 * may block.
		 */
		truncate_inode_pages_range(inode->i_mapping, pos,
				   (pos+n) | (PAGE_CACHE_SIZE-1));
		osd_req_op_extent_osd_data_pages(req, 0, pages, n, start,
						false, false);

		/* BUG_ON(vino.snap != CEPH_NOSNAP); */
		ceph_osdc_build_request(req, pos, snapc, vino.snap, &mtime);

		ret = ceph_osdc_start_request(&fsc->client->osdc, req, false);
		if (!ret)
			ret = ceph_osdc_wait_request(&fsc->client->osdc, req);

		ceph_put_page_vector(pages, num_pages, false);

		ceph_osdc_put_request(req);
		if (ret)
			break;
		pos += n;
		written += n;
		iov_iter_advance(from, n);

		if (pos > i_size_read(inode)) {
			check_caps = ceph_inode_set_size(inode, pos);
			if (check_caps)
				ceph_check_caps(ceph_inode(inode),
						CHECK_CAPS_AUTHONLY,
						NULL);
		}
	}

	if (ret != -EOLDSNAPC && written > 0) {
		iocb->ki_pos = pos;
		ret = written;
	}
	return ret;
}


/*
 * Synchronous write, straight from __user pointer or user pages.
 *
 * If write spans object boundary, just do multiple writes.  (For a
 * correct atomic write, we should e.g. take write locks on all
 * objects, rollback on failure, etc.)
 */
static ssize_t
ceph_sync_write(struct kiocb *iocb, struct iov_iter *from, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	struct ceph_snap_context *snapc;
	struct ceph_vino vino;
	struct ceph_osd_request *req;
	struct page **pages;
	u64 len;
	int num_pages;
	int written = 0;
	int flags;
	int check_caps = 0;
	int ret;
	struct timespec mtime = CURRENT_TIME;
	size_t count = iov_iter_count(from);

	if (ceph_snap(file_inode(file)) != CEPH_NOSNAP)
		return -EROFS;

	dout("sync_write on file %p %lld~%u\n", file, pos, (unsigned)count);

	ret = filemap_write_and_wait_range(inode->i_mapping, pos, pos + count);
	if (ret < 0)
		return ret;

	ret = invalidate_inode_pages2_range(inode->i_mapping,
					    pos >> PAGE_CACHE_SHIFT,
					    (pos + count) >> PAGE_CACHE_SHIFT);
	if (ret < 0)
		dout("invalidate_inode_pages2_range returned %d\n", ret);

	flags = CEPH_OSD_FLAG_ORDERSNAP |
		CEPH_OSD_FLAG_ONDISK |
		CEPH_OSD_FLAG_WRITE |
		CEPH_OSD_FLAG_ACK;

	while ((len = iov_iter_count(from)) > 0) {
		size_t left;
		int n;

		snapc = ci->i_snap_realm->cached_context;
		vino = ceph_vino(inode);
		req = ceph_osdc_new_request(&fsc->client->osdc, &ci->i_layout,
					    vino, pos, &len, 1,
					    CEPH_OSD_OP_WRITE, flags, snapc,
					    ci->i_truncate_seq,
					    ci->i_truncate_size,
					    false);
		if (IS_ERR(req)) {
			ret = PTR_ERR(req);
			break;
		}

		/*
		 * write from beginning of first page,
		 * regardless of io alignment
		 */
		num_pages = (len + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

		pages = ceph_alloc_page_vector(num_pages, GFP_NOFS);
		if (IS_ERR(pages)) {
			ret = PTR_ERR(pages);
			goto out;
		}

		left = len;
		for (n = 0; n < num_pages; n++) {
			size_t plen = min_t(size_t, left, PAGE_SIZE);
			ret = copy_page_from_iter(pages[n], 0, plen, from);
			if (ret != plen) {
				ret = -EFAULT;
				break;
			}
			left -= ret;
		}

		if (ret < 0) {
			ceph_release_page_vector(pages, num_pages);
			goto out;
		}

		/* get a second commit callback */
		req->r_unsafe_callback = ceph_sync_write_unsafe;
		req->r_inode = inode;

		osd_req_op_extent_osd_data_pages(req, 0, pages, len, 0,
						false, true);

		/* BUG_ON(vino.snap != CEPH_NOSNAP); */
		ceph_osdc_build_request(req, pos, snapc, vino.snap, &mtime);

		ret = ceph_osdc_start_request(&fsc->client->osdc, req, false);
		if (!ret)
			ret = ceph_osdc_wait_request(&fsc->client->osdc, req);

out:
		ceph_osdc_put_request(req);
		if (ret == 0) {
			pos += len;
			written += len;

			if (pos > i_size_read(inode)) {
				check_caps = ceph_inode_set_size(inode, pos);
				if (check_caps)
					ceph_check_caps(ceph_inode(inode),
							CHECK_CAPS_AUTHONLY,
							NULL);
			}
		} else
			break;
	}

	if (ret != -EOLDSNAPC && written > 0) {
		ret = written;
		iocb->ki_pos = pos;
	}
	return ret;
}

/*
 * Wrap generic_file_aio_read with checks for cap bits on the inode.
 * Atomically grab references, so that those bits are not released
 * back to the MDS mid-read.
 *
 * Hmm, the sync read case isn't actually async... should it be?
 */
static ssize_t ceph_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct file *filp = iocb->ki_filp;
	struct ceph_file_info *fi = filp->private_data;
	size_t len = iocb->ki_nbytes;
	struct inode *inode = file_inode(filp);
	struct ceph_inode_info *ci = ceph_inode(inode);
	ssize_t ret;
	int want, got = 0;
	int checkeof = 0, read = 0;

again:
	dout("aio_read %p %llx.%llx %llu~%u trying to get caps on %p\n",
	     inode, ceph_vinop(inode), iocb->ki_pos, (unsigned)len, inode);

	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want = CEPH_CAP_FILE_CACHE | CEPH_CAP_FILE_LAZYIO;
	else
		want = CEPH_CAP_FILE_CACHE;
	ret = ceph_get_caps(ci, CEPH_CAP_FILE_RD, want, &got, -1);
	if (ret < 0)
		return ret;

	if ((got & (CEPH_CAP_FILE_CACHE|CEPH_CAP_FILE_LAZYIO)) == 0 ||
	    (iocb->ki_filp->f_flags & O_DIRECT) ||
	    (fi->flags & CEPH_F_SYNC)) {

		dout("aio_sync_read %p %llx.%llx %llu~%u got cap refs on %s\n",
		     inode, ceph_vinop(inode), iocb->ki_pos, (unsigned)len,
		     ceph_cap_string(got));

		/* hmm, this isn't really async... */
		ret = ceph_sync_read(iocb, to, &checkeof);
	} else {
		dout("aio_read %p %llx.%llx %llu~%u got cap refs on %s\n",
		     inode, ceph_vinop(inode), iocb->ki_pos, (unsigned)len,
		     ceph_cap_string(got));

		ret = generic_file_read_iter(iocb, to);
	}
	dout("aio_read %p %llx.%llx dropping cap refs on %s = %d\n",
	     inode, ceph_vinop(inode), ceph_cap_string(got), (int)ret);
	ceph_put_cap_refs(ci, got);

	if (checkeof && ret >= 0) {
		int statret = ceph_do_getattr(inode,
					      CEPH_STAT_CAP_SIZE);

		/* hit EOF or hole? */
		if (statret == 0 && iocb->ki_pos < inode->i_size &&
			ret < len) {
			dout("sync_read hit hole, ppos %lld < size %lld"
			     ", reading more\n", iocb->ki_pos,
			     inode->i_size);

			iov_iter_advance(to, ret);
			read += ret;
			len -= ret;
			checkeof = 0;
			goto again;
		}
	}

	if (ret >= 0)
		ret += read;

	return ret;
}

/*
 * Take cap references to avoid releasing caps to MDS mid-write.
 *
 * If we are synchronous, and write with an old snap context, the OSD
 * may return EOLDSNAPC.  In that case, retry the write.. _after_
 * dropping our cap refs and allowing the pending snap to logically
 * complete _before_ this write occurs.
 *
 * If we are near ENOSPC, write synchronously.
 */
static ssize_t ceph_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct ceph_file_info *fi = file->private_data;
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_osd_client *osdc =
		&ceph_sb_to_client(inode->i_sb)->client->osdc;
	ssize_t count = iov_iter_count(from), written = 0;
	int err, want, got;
	loff_t pos = iocb->ki_pos;

	if (ceph_snap(inode) != CEPH_NOSNAP)
		return -EROFS;

	mutex_lock(&inode->i_mutex);

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = file->f_mapping->backing_dev_info;

	err = generic_write_checks(file, &pos, &count, S_ISBLK(inode->i_mode));
	if (err)
		goto out;

	if (count == 0)
		goto out;
	iov_iter_truncate(from, count);

	err = file_remove_suid(file);
	if (err)
		goto out;

	err = file_update_time(file);
	if (err)
		goto out;

retry_snap:
	if (ceph_osdmap_flag(osdc->osdmap, CEPH_OSDMAP_FULL)) {
		err = -ENOSPC;
		goto out;
	}

	dout("aio_write %p %llx.%llx %llu~%zd getting caps. i_size %llu\n",
	     inode, ceph_vinop(inode), pos, count, inode->i_size);
	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want = CEPH_CAP_FILE_BUFFER | CEPH_CAP_FILE_LAZYIO;
	else
		want = CEPH_CAP_FILE_BUFFER;
	got = 0;
	err = ceph_get_caps(ci, CEPH_CAP_FILE_WR, want, &got, pos + count);
	if (err < 0)
		goto out;

	dout("aio_write %p %llx.%llx %llu~%zd got cap refs on %s\n",
	     inode, ceph_vinop(inode), pos, count, ceph_cap_string(got));

	if ((got & (CEPH_CAP_FILE_BUFFER|CEPH_CAP_FILE_LAZYIO)) == 0 ||
	    (file->f_flags & O_DIRECT) || (fi->flags & CEPH_F_SYNC)) {
		struct iov_iter data;
		mutex_unlock(&inode->i_mutex);
		/* we might need to revert back to that point */
		data = *from;
		if (file->f_flags & O_DIRECT)
			written = ceph_sync_direct_write(iocb, &data, pos);
		else
			written = ceph_sync_write(iocb, &data, pos);
		if (written == -EOLDSNAPC) {
			dout("aio_write %p %llx.%llx %llu~%u"
				"got EOLDSNAPC, retrying\n",
				inode, ceph_vinop(inode),
				pos, (unsigned)count);
			mutex_lock(&inode->i_mutex);
			goto retry_snap;
		}
		if (written > 0)
			iov_iter_advance(from, written);
	} else {
		loff_t old_size = inode->i_size;
		/*
		 * No need to acquire the i_truncate_mutex. Because
		 * the MDS revokes Fwb caps before sending truncate
		 * message to us. We can't get Fwb cap while there
		 * are pending vmtruncate. So write and vmtruncate
		 * can not run at the same time
		 */
		written = generic_perform_write(file, from, pos);
		if (likely(written >= 0))
			iocb->ki_pos = pos + written;
		if (inode->i_size > old_size)
			ceph_fscache_update_objectsize(inode);
		mutex_unlock(&inode->i_mutex);
	}

	if (written >= 0) {
		int dirty;
		spin_lock(&ci->i_ceph_lock);
		dirty = __ceph_mark_dirty_caps(ci, CEPH_CAP_FILE_WR);
		spin_unlock(&ci->i_ceph_lock);
		if (dirty)
			__mark_inode_dirty(inode, dirty);
	}

	dout("aio_write %p %llx.%llx %llu~%u  dropping cap refs on %s\n",
	     inode, ceph_vinop(inode), pos, (unsigned)count,
	     ceph_cap_string(got));
	ceph_put_cap_refs(ci, got);

	if (written >= 0 &&
	    ((file->f_flags & O_SYNC) || IS_SYNC(file->f_mapping->host) ||
	     ceph_osdmap_flag(osdc->osdmap, CEPH_OSDMAP_NEARFULL))) {
		err = vfs_fsync_range(file, pos, pos + written - 1, 1);
		if (err < 0)
			written = err;
	}

	goto out_unlocked;

out:
	mutex_unlock(&inode->i_mutex);
out_unlocked:
	current->backing_dev_info = NULL;
	return written ? written : err;
}

/*
 * llseek.  be sure to verify file size on SEEK_END.
 */
static loff_t ceph_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	int ret;

	mutex_lock(&inode->i_mutex);

	if (whence == SEEK_END || whence == SEEK_DATA || whence == SEEK_HOLE) {
		ret = ceph_do_getattr(inode, CEPH_STAT_CAP_SIZE);
		if (ret < 0) {
			offset = ret;
			goto out;
		}
	}

	switch (whence) {
	case SEEK_END:
		offset += inode->i_size;
		break;
	case SEEK_CUR:
		/*
		 * Here we special-case the lseek(fd, 0, SEEK_CUR)
		 * position-querying operation.  Avoid rewriting the "same"
		 * f_pos value back to the file because a concurrent read(),
		 * write() or lseek() might have altered it
		 */
		if (offset == 0) {
			offset = file->f_pos;
			goto out;
		}
		offset += file->f_pos;
		break;
	case SEEK_DATA:
		if (offset >= inode->i_size) {
			ret = -ENXIO;
			goto out;
		}
		break;
	case SEEK_HOLE:
		if (offset >= inode->i_size) {
			ret = -ENXIO;
			goto out;
		}
		offset = inode->i_size;
		break;
	}

	offset = vfs_setpos(file, offset, inode->i_sb->s_maxbytes);

out:
	mutex_unlock(&inode->i_mutex);
	return offset;
}

static inline void ceph_zero_partial_page(
	struct inode *inode, loff_t offset, unsigned size)
{
	struct page *page;
	pgoff_t index = offset >> PAGE_CACHE_SHIFT;

	page = find_lock_page(inode->i_mapping, index);
	if (page) {
		wait_on_page_writeback(page);
		zero_user(page, offset & (PAGE_CACHE_SIZE - 1), size);
		unlock_page(page);
		page_cache_release(page);
	}
}

static void ceph_zero_pagecache_range(struct inode *inode, loff_t offset,
				      loff_t length)
{
	loff_t nearly = round_up(offset, PAGE_CACHE_SIZE);
	if (offset < nearly) {
		loff_t size = nearly - offset;
		if (length < size)
			size = length;
		ceph_zero_partial_page(inode, offset, size);
		offset += size;
		length -= size;
	}
	if (length >= PAGE_CACHE_SIZE) {
		loff_t size = round_down(length, PAGE_CACHE_SIZE);
		truncate_pagecache_range(inode, offset, offset + size - 1);
		offset += size;
		length -= size;
	}
	if (length)
		ceph_zero_partial_page(inode, offset, length);
}

static int ceph_zero_partial_object(struct inode *inode,
				    loff_t offset, loff_t *length)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	struct ceph_osd_request *req;
	int ret = 0;
	loff_t zero = 0;
	int op;

	if (!length) {
		op = offset ? CEPH_OSD_OP_DELETE : CEPH_OSD_OP_TRUNCATE;
		length = &zero;
	} else {
		op = CEPH_OSD_OP_ZERO;
	}

	req = ceph_osdc_new_request(&fsc->client->osdc, &ci->i_layout,
					ceph_vino(inode),
					offset, length,
					1, op,
					CEPH_OSD_FLAG_WRITE |
					CEPH_OSD_FLAG_ONDISK,
					NULL, 0, 0, false);
	if (IS_ERR(req)) {
		ret = PTR_ERR(req);
		goto out;
	}

	ceph_osdc_build_request(req, offset, NULL, ceph_vino(inode).snap,
				&inode->i_mtime);

	ret = ceph_osdc_start_request(&fsc->client->osdc, req, false);
	if (!ret) {
		ret = ceph_osdc_wait_request(&fsc->client->osdc, req);
		if (ret == -ENOENT)
			ret = 0;
	}
	ceph_osdc_put_request(req);

out:
	return ret;
}

static int ceph_zero_objects(struct inode *inode, loff_t offset, loff_t length)
{
	int ret = 0;
	struct ceph_inode_info *ci = ceph_inode(inode);
	s32 stripe_unit = ceph_file_layout_su(ci->i_layout);
	s32 stripe_count = ceph_file_layout_stripe_count(ci->i_layout);
	s32 object_size = ceph_file_layout_object_size(ci->i_layout);
	u64 object_set_size = object_size * stripe_count;
	u64 nearly, t;

	/* round offset up to next period boundary */
	nearly = offset + object_set_size - 1;
	t = nearly;
	nearly -= do_div(t, object_set_size);

	while (length && offset < nearly) {
		loff_t size = length;
		ret = ceph_zero_partial_object(inode, offset, &size);
		if (ret < 0)
			return ret;
		offset += size;
		length -= size;
	}
	while (length >= object_set_size) {
		int i;
		loff_t pos = offset;
		for (i = 0; i < stripe_count; ++i) {
			ret = ceph_zero_partial_object(inode, pos, NULL);
			if (ret < 0)
				return ret;
			pos += stripe_unit;
		}
		offset += object_set_size;
		length -= object_set_size;
	}
	while (length) {
		loff_t size = length;
		ret = ceph_zero_partial_object(inode, offset, &size);
		if (ret < 0)
			return ret;
		offset += size;
		length -= size;
	}
	return ret;
}

static long ceph_fallocate(struct file *file, int mode,
				loff_t offset, loff_t length)
{
	struct ceph_file_info *fi = file->private_data;
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_osd_client *osdc =
		&ceph_inode_to_client(inode)->client->osdc;
	int want, got = 0;
	int dirty;
	int ret = 0;
	loff_t endoff = 0;
	loff_t size;

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE))
		return -EOPNOTSUPP;

	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	mutex_lock(&inode->i_mutex);

	if (ceph_snap(inode) != CEPH_NOSNAP) {
		ret = -EROFS;
		goto unlock;
	}

	if (ceph_osdmap_flag(osdc->osdmap, CEPH_OSDMAP_FULL) &&
		!(mode & FALLOC_FL_PUNCH_HOLE)) {
		ret = -ENOSPC;
		goto unlock;
	}

	size = i_size_read(inode);
	if (!(mode & FALLOC_FL_KEEP_SIZE))
		endoff = offset + length;

	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want = CEPH_CAP_FILE_BUFFER | CEPH_CAP_FILE_LAZYIO;
	else
		want = CEPH_CAP_FILE_BUFFER;

	ret = ceph_get_caps(ci, CEPH_CAP_FILE_WR, want, &got, endoff);
	if (ret < 0)
		goto unlock;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		if (offset < size)
			ceph_zero_pagecache_range(inode, offset, length);
		ret = ceph_zero_objects(inode, offset, length);
	} else if (endoff > size) {
		truncate_pagecache_range(inode, size, -1);
		if (ceph_inode_set_size(inode, endoff))
			ceph_check_caps(ceph_inode(inode),
				CHECK_CAPS_AUTHONLY, NULL);
	}

	if (!ret) {
		spin_lock(&ci->i_ceph_lock);
		dirty = __ceph_mark_dirty_caps(ci, CEPH_CAP_FILE_WR);
		spin_unlock(&ci->i_ceph_lock);
		if (dirty)
			__mark_inode_dirty(inode, dirty);
	}

	ceph_put_cap_refs(ci, got);
unlock:
	mutex_unlock(&inode->i_mutex);
	return ret;
}

const struct file_operations ceph_file_fops = {
	.open = ceph_open,
	.release = ceph_release,
	.llseek = ceph_llseek,
	.read = new_sync_read,
	.write = new_sync_write,
	.read_iter = ceph_read_iter,
	.write_iter = ceph_write_iter,
	.mmap = ceph_mmap,
	.fsync = ceph_fsync,
	.lock = ceph_lock,
	.flock = ceph_flock,
	.splice_read = generic_file_splice_read,
	.splice_write = iter_file_splice_write,
	.unlocked_ioctl = ceph_ioctl,
	.compat_ioctl	= ceph_ioctl,
	.fallocate	= ceph_fallocate,
};
/************************************************************/
/* ../linux-3.17/fs/ceph/file.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

// #include <linux/file.h>
// #include <linux/namei.h>
// #include <linux/random.h>

// #include "super.h"
// #include "mds_client.h"
#include <linux/ceph/pagelist.h>

static u64 lock_secret;

static inline u64 secure_addr(void *addr)
{
	u64 v = lock_secret ^ (u64)(unsigned long)addr;
	/*
	 * Set the most significant bit, so that MDS knows the 'owner'
	 * is sufficient to identify the owner of lock. (old code uses
	 * both 'owner' and 'pid')
	 */
	v |= (1ULL << 63);
	return v;
}

void __init ceph_flock_init(void)
{
	get_random_bytes(&lock_secret, sizeof(lock_secret));
}

/**
 * Implement fcntl and flock locking functions.
 */
static int ceph_lock_message(u8 lock_type, u16 operation, struct file *file,
			     int cmd, u8 wait, struct file_lock *fl)
{
	struct inode *inode = file_inode(file);
	struct ceph_mds_client *mdsc = ceph_sb_to_client(inode->i_sb)->mdsc;
	struct ceph_mds_request *req;
	int err;
	u64 length = 0;
	u64 owner;

	req = ceph_mdsc_create_request(mdsc, operation, USE_AUTH_MDS);
	if (IS_ERR(req))
		return PTR_ERR(req);
	req->r_inode = inode;
	ihold(inode);
	req->r_num_caps = 1;

	/* mds requires start and length rather than start and end */
	if (LLONG_MAX == fl->fl_end)
		length = 0;
	else
		length = fl->fl_end - fl->fl_start + 1;

	owner = secure_addr(fl->fl_owner);

	dout("ceph_lock_message: rule: %d, op: %d, owner: %llx, pid: %llu, "
	     "start: %llu, length: %llu, wait: %d, type: %d", (int)lock_type,
	     (int)operation, owner, (u64)fl->fl_pid, fl->fl_start, length,
	     wait, fl->fl_type);

	req->r_args.filelock_change.rule = lock_type;
	req->r_args.filelock_change.type = cmd;
	req->r_args.filelock_change.owner = cpu_to_le64(owner);
	req->r_args.filelock_change.pid = cpu_to_le64((u64)fl->fl_pid);
	req->r_args.filelock_change.start = cpu_to_le64(fl->fl_start);
	req->r_args.filelock_change.length = cpu_to_le64(length);
	req->r_args.filelock_change.wait = wait;

	err = ceph_mdsc_do_request(mdsc, inode, req);

	if (operation == CEPH_MDS_OP_GETFILELOCK) {
		fl->fl_pid = le64_to_cpu(req->r_reply_info.filelock_reply->pid);
		if (CEPH_LOCK_SHARED == req->r_reply_info.filelock_reply->type)
			fl->fl_type = F_RDLCK;
		else if (CEPH_LOCK_EXCL == req->r_reply_info.filelock_reply->type)
			fl->fl_type = F_WRLCK;
		else
			fl->fl_type = F_UNLCK;

		fl->fl_start = le64_to_cpu(req->r_reply_info.filelock_reply->start);
		length = le64_to_cpu(req->r_reply_info.filelock_reply->start) +
						 le64_to_cpu(req->r_reply_info.filelock_reply->length);
		if (length >= 1)
			fl->fl_end = length -1;
		else
			fl->fl_end = 0;

	}
	ceph_mdsc_put_request(req);
	dout("ceph_lock_message: rule: %d, op: %d, pid: %llu, start: %llu, "
	     "length: %llu, wait: %d, type: %d, err code %d", (int)lock_type,
	     (int)operation, (u64)fl->fl_pid, fl->fl_start,
	     length, wait, fl->fl_type, err);
	return err;
}

/**
 * Attempt to set an fcntl lock.
 * For now, this just goes away to the server. Later it may be more awesome.
 */
int ceph_lock(struct file *file, int cmd, struct file_lock *fl)
{
	u8 lock_cmd;
	int err;
	u8 wait = 0;
	u16 op = CEPH_MDS_OP_SETFILELOCK;

	if (!(fl->fl_flags & FL_POSIX))
		return -ENOLCK;
	/* No mandatory locks */
	if (__mandatory_lock(file->f_mapping->host) && fl->fl_type != F_UNLCK)
		return -ENOLCK;

	dout("ceph_lock, fl_owner: %p", fl->fl_owner);

	/* set wait bit as appropriate, then make command as Ceph expects it*/
	if (IS_GETLK(cmd))
		op = CEPH_MDS_OP_GETFILELOCK;
	else if (IS_SETLKW(cmd))
		wait = 1;

	if (F_RDLCK == fl->fl_type)
		lock_cmd = CEPH_LOCK_SHARED;
	else if (F_WRLCK == fl->fl_type)
		lock_cmd = CEPH_LOCK_EXCL;
	else
		lock_cmd = CEPH_LOCK_UNLOCK;

	err = ceph_lock_message(CEPH_LOCK_FCNTL, op, file, lock_cmd, wait, fl);
	if (!err) {
		if (op != CEPH_MDS_OP_GETFILELOCK) {
			dout("mds locked, locking locally");
			err = posix_lock_file(file, fl, NULL);
			if (err && (CEPH_MDS_OP_SETFILELOCK == op)) {
				/* undo! This should only happen if
				 * the kernel detects local
				 * deadlock. */
				ceph_lock_message(CEPH_LOCK_FCNTL, op, file,
						  CEPH_LOCK_UNLOCK, 0, fl);
				dout("got %d on posix_lock_file, undid lock",
				     err);
			}
		}

	} else if (err == -ERESTARTSYS) {
		dout("undoing lock\n");
		ceph_lock_message(CEPH_LOCK_FCNTL, op, file,
				  CEPH_LOCK_UNLOCK, 0, fl);
	}
	return err;
}

int ceph_flock(struct file *file, int cmd, struct file_lock *fl)
{
	u8 lock_cmd;
	int err;
	u8 wait = 0;

	if (!(fl->fl_flags & FL_FLOCK))
		return -ENOLCK;
	/* No mandatory locks */
	if (__mandatory_lock(file->f_mapping->host) && fl->fl_type != F_UNLCK)
		return -ENOLCK;

	dout("ceph_flock, fl_file: %p", fl->fl_file);

	if (IS_SETLKW(cmd))
		wait = 1;

	if (F_RDLCK == fl->fl_type)
		lock_cmd = CEPH_LOCK_SHARED;
	else if (F_WRLCK == fl->fl_type)
		lock_cmd = CEPH_LOCK_EXCL;
	else
		lock_cmd = CEPH_LOCK_UNLOCK;

	err = ceph_lock_message(CEPH_LOCK_FLOCK, CEPH_MDS_OP_SETFILELOCK,
				file, lock_cmd, wait, fl);
	if (!err) {
		err = flock_lock_file_wait(file, fl);
		if (err) {
			ceph_lock_message(CEPH_LOCK_FLOCK,
					  CEPH_MDS_OP_SETFILELOCK,
					  file, CEPH_LOCK_UNLOCK, 0, fl);
			dout("got %d on flock_lock_file_wait, undid lock", err);
		}
	} else if (err == -ERESTARTSYS) {
		dout("undoing lock\n");
		ceph_lock_message(CEPH_LOCK_FLOCK,
				  CEPH_MDS_OP_SETFILELOCK,
				  file, CEPH_LOCK_UNLOCK, 0, fl);
	}
	return err;
}

/**
 * Must be called with lock_flocks() already held. Fills in the passed
 * counter variables, so you can prepare pagelist metadata before calling
 * ceph_encode_locks.
 */
void ceph_count_locks(struct inode *inode, int *fcntl_count, int *flock_count)
{
	struct file_lock *lock;

	*fcntl_count = 0;
	*flock_count = 0;

	for (lock = inode->i_flock; lock != NULL; lock = lock->fl_next) {
		if (lock->fl_flags & FL_POSIX)
			++(*fcntl_count);
		else if (lock->fl_flags & FL_FLOCK)
			++(*flock_count);
	}
	dout("counted %d flock locks and %d fcntl locks",
	     *flock_count, *fcntl_count);
}

/**
 * Encode the flock and fcntl locks for the given inode into the ceph_filelock
 * array. Must be called with inode->i_lock already held.
 * If we encounter more of a specific lock type than expected, return -ENOSPC.
 */
int ceph_encode_locks_to_buffer(struct inode *inode,
				struct ceph_filelock *flocks,
				int num_fcntl_locks, int num_flock_locks)
{
	struct file_lock *lock;
	int err = 0;
	int seen_fcntl = 0;
	int seen_flock = 0;
	int l = 0;

	dout("encoding %d flock and %d fcntl locks", num_flock_locks,
	     num_fcntl_locks);

	for (lock = inode->i_flock; lock != NULL; lock = lock->fl_next) {
		if (lock->fl_flags & FL_POSIX) {
			++seen_fcntl;
			if (seen_fcntl > num_fcntl_locks) {
				err = -ENOSPC;
				goto fail;
			}
			err = lock_to_ceph_filelock(lock, &flocks[l]);
			if (err)
				goto fail;
			++l;
		}
	}
	for (lock = inode->i_flock; lock != NULL; lock = lock->fl_next) {
		if (lock->fl_flags & FL_FLOCK) {
			++seen_flock;
			if (seen_flock > num_flock_locks) {
				err = -ENOSPC;
				goto fail;
			}
			err = lock_to_ceph_filelock(lock, &flocks[l]);
			if (err)
				goto fail;
			++l;
		}
	}
fail:
	return err;
}

/**
 * Copy the encoded flock and fcntl locks into the pagelist.
 * Format is: #fcntl locks, sequential fcntl locks, #flock locks,
 * sequential flock locks.
 * Returns zero on success.
 */
int ceph_locks_to_pagelist(struct ceph_filelock *flocks,
			   struct ceph_pagelist *pagelist,
			   int num_fcntl_locks, int num_flock_locks)
{
	int err = 0;
	__le32 nlocks;

	nlocks = cpu_to_le32(num_fcntl_locks);
	err = ceph_pagelist_append(pagelist, &nlocks, sizeof(nlocks));
	if (err)
		goto out_fail;

	err = ceph_pagelist_append(pagelist, flocks,
				   num_fcntl_locks * sizeof(*flocks));
	if (err)
		goto out_fail;

	nlocks = cpu_to_le32(num_flock_locks);
	err = ceph_pagelist_append(pagelist, &nlocks, sizeof(nlocks));
	if (err)
		goto out_fail;

	err = ceph_pagelist_append(pagelist,
				   &flocks[num_fcntl_locks],
				   num_flock_locks * sizeof(*flocks));
out_fail:
	return err;
}

/*
 * Given a pointer to a lock, convert it to a ceph filelock
 */
int lock_to_ceph_filelock(struct file_lock *lock,
			  struct ceph_filelock *cephlock)
{
	int err = 0;
	cephlock->start = cpu_to_le64(lock->fl_start);
	cephlock->length = cpu_to_le64(lock->fl_end - lock->fl_start + 1);
	cephlock->client = cpu_to_le64(0);
	cephlock->pid = cpu_to_le64((u64)lock->fl_pid);
	cephlock->owner = cpu_to_le64(secure_addr(lock->fl_owner));

	switch (lock->fl_type) {
	case F_RDLCK:
		cephlock->type = CEPH_LOCK_SHARED;
		break;
	case F_WRLCK:
		cephlock->type = CEPH_LOCK_EXCL;
		break;
	case F_UNLCK:
		cephlock->type = CEPH_LOCK_UNLOCK;
		break;
	default:
		dout("Have unknown lock type %d", lock->fl_type);
		err = -EINVAL;
	}

	return err;
}
/************************************************************/
/* ../linux-3.17/fs/ceph/locks.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

// #include <linux/backing-dev.h>
// #include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
// #include <linux/writeback.h>	/* generic_writepages */
// #include <linux/slab.h>
#include <linux/pagevec.h>
#include <linux/task_io_accounting_ops.h>

// #include "super.h"
// #include "mds_client.h"
// #include "cache.h"
#include <linux/ceph/osd_client.h>

/*
 * Ceph address space ops.
 *
 * There are a few funny things going on here.
 *
 * The page->private field is used to reference a struct
 * ceph_snap_context for _every_ dirty page.  This indicates which
 * snapshot the page was logically dirtied in, and thus which snap
 * context needs to be associated with the osd write during writeback.
 *
 * Similarly, struct ceph_inode_info maintains a set of counters to
 * count dirty pages on the inode.  In the absence of snapshots,
 * i_wrbuffer_ref == i_wrbuffer_ref_head == the dirty page count.
 *
 * When a snapshot is taken (that is, when the client receives
 * notification that a snapshot was taken), each inode with caps and
 * with dirty pages (dirty pages implies there is a cap) gets a new
 * ceph_cap_snap in the i_cap_snaps list (which is sorted in ascending
 * order, new snaps go to the tail).  The i_wrbuffer_ref_head count is
 * moved to capsnap->dirty. (Unless a sync write is currently in
 * progress.  In that case, the capsnap is said to be "pending", new
 * writes cannot start, and the capsnap isn't "finalized" until the
 * write completes (or fails) and a final size/mtime for the inode for
 * that snap can be settled upon.)  i_wrbuffer_ref_head is reset to 0.
 *
 * On writeback, we must submit writes to the osd IN SNAP ORDER.  So,
 * we look for the first capsnap in i_cap_snaps and write out pages in
 * that snap context _only_.  Then we move on to the next capsnap,
 * eventually reaching the "live" or "head" context (i.e., pages that
 * are not yet snapped) and are writing the most recently dirtied
 * pages.
 *
 * Invalidate and so forth must take care to ensure the dirty page
 * accounting is preserved.
 */

#define CONGESTION_ON_THRESH(congestion_kb) (congestion_kb >> (PAGE_SHIFT-10))
#define CONGESTION_OFF_THRESH(congestion_kb)				\
	(CONGESTION_ON_THRESH(congestion_kb) -				\
	 (CONGESTION_ON_THRESH(congestion_kb) >> 2))

static inline struct ceph_snap_context *page_snap_context(struct page *page)
{
	if (PagePrivate(page))
		return (void *)page->private;
	return NULL;
}

/*
 * Dirty a page.  Optimistically adjust accounting, on the assumption
 * that we won't race with invalidate.  If we do, readjust.
 */
static int ceph_set_page_dirty(struct page *page)
{
	struct address_space *mapping = page->mapping;
	struct inode *inode;
	struct ceph_inode_info *ci;
	struct ceph_snap_context *snapc;
	int ret;

	if (unlikely(!mapping))
		return !TestSetPageDirty(page);

	if (PageDirty(page)) {
		dout("%p set_page_dirty %p idx %lu -- already dirty\n",
		     mapping->host, page, page->index);
		BUG_ON(!PagePrivate(page));
		return 0;
	}

	inode = mapping->host;
	ci = ceph_inode(inode);

	/*
	 * Note that we're grabbing a snapc ref here without holding
	 * any locks!
	 */
	snapc = ceph_get_snap_context(ci->i_snap_realm->cached_context);

	/* dirty the head */
	spin_lock(&ci->i_ceph_lock);
	if (ci->i_head_snapc == NULL)
		ci->i_head_snapc = ceph_get_snap_context(snapc);
	++ci->i_wrbuffer_ref_head;
	if (ci->i_wrbuffer_ref == 0)
		ihold(inode);
	++ci->i_wrbuffer_ref;
	dout("%p set_page_dirty %p idx %lu head %d/%d -> %d/%d "
	     "snapc %p seq %lld (%d snaps)\n",
	     mapping->host, page, page->index,
	     ci->i_wrbuffer_ref-1, ci->i_wrbuffer_ref_head-1,
	     ci->i_wrbuffer_ref, ci->i_wrbuffer_ref_head,
	     snapc, snapc->seq, snapc->num_snaps);
	spin_unlock(&ci->i_ceph_lock);

	/*
	 * Reference snap context in page->private.  Also set
	 * PagePrivate so that we get invalidatepage callback.
	 */
	BUG_ON(PagePrivate(page));
	page->private = (unsigned long)snapc;
	SetPagePrivate(page);

	ret = __set_page_dirty_nobuffers(page);
	WARN_ON(!PageLocked(page));
	WARN_ON(!page->mapping);

	return ret;
}

/*
 * If we are truncating the full page (i.e. offset == 0), adjust the
 * dirty page counters appropriately.  Only called if there is private
 * data on the page.
 */
static void ceph_invalidatepage(struct page *page, unsigned int offset,
				unsigned int length)
{
	struct inode *inode;
	struct ceph_inode_info *ci;
	struct ceph_snap_context *snapc = page_snap_context(page);

	inode = page->mapping->host;
	ci = ceph_inode(inode);

	if (offset != 0 || length != PAGE_CACHE_SIZE) {
		dout("%p invalidatepage %p idx %lu partial dirty page %u~%u\n",
		     inode, page, page->index, offset, length);
		return;
	}

	ceph_invalidate_fscache_page(inode, page);

	if (!PagePrivate(page))
		return;

	/*
	 * We can get non-dirty pages here due to races between
	 * set_page_dirty and truncate_complete_page; just spit out a
	 * warning, in case we end up with accounting problems later.
	 */
	if (!PageDirty(page))
		pr_err("%p invalidatepage %p page not dirty\n", inode, page);

	ClearPageChecked(page);

	dout("%p invalidatepage %p idx %lu full dirty page\n",
	     inode, page, page->index);

	ceph_put_wrbuffer_cap_refs(ci, 1, snapc);
	ceph_put_snap_context(snapc);
	page->private = 0;
	ClearPagePrivate(page);
}

static int ceph_releasepage(struct page *page, gfp_t g)
{
	struct inode *inode = page->mapping ? page->mapping->host : NULL;
	dout("%p releasepage %p idx %lu\n", inode, page, page->index);
	WARN_ON(PageDirty(page));

	/* Can we release the page from the cache? */
	if (!ceph_release_fscache_page(page, g))
		return 0;

	return !PagePrivate(page);
}

/*
 * read a single page, without unlocking it.
 */
static int readpage_nounlock(struct file *filp, struct page *page)
{
	struct inode *inode = file_inode(filp);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_osd_client *osdc =
		&ceph_inode_to_client(inode)->client->osdc;
	int err = 0;
	u64 len = PAGE_CACHE_SIZE;

	err = ceph_readpage_from_fscache(inode, page);

	if (err == 0)
		goto out;

	dout("readpage inode %p file %p page %p index %lu\n",
	     inode, filp, page, page->index);
	err = ceph_osdc_readpages(osdc, ceph_vino(inode), &ci->i_layout,
				  (u64) page_offset(page), &len,
				  ci->i_truncate_seq, ci->i_truncate_size,
				  &page, 1, 0);
	if (err == -ENOENT)
		err = 0;
	if (err < 0) {
		SetPageError(page);
		ceph_fscache_readpage_cancel(inode, page);
		goto out;
	}
	if (err < PAGE_CACHE_SIZE)
		/* zero fill remainder of page */
		zero_user_segment(page, err, PAGE_CACHE_SIZE);
	else
		flush_dcache_page(page);

	SetPageUptodate(page);
	ceph_readpage_to_fscache(inode, page);

out:
	return err < 0 ? err : 0;
}

static int ceph_readpage(struct file *filp, struct page *page)
{
	int r = readpage_nounlock(filp, page);
	unlock_page(page);
	return r;
}

/*
 * Finish an async read(ahead) op.
 */
static void finish_read(struct ceph_osd_request *req, struct ceph_msg *msg)
{
	struct inode *inode = req->r_inode;
	struct ceph_osd_data *osd_data;
	int rc = req->r_result;
	int bytes = le32_to_cpu(msg->hdr.data_len);
	int num_pages;
	int i;

	dout("finish_read %p req %p rc %d bytes %d\n", inode, req, rc, bytes);

	/* unlock all pages, zeroing any data we didn't read */
	osd_data = osd_req_op_extent_osd_data(req, 0);
	BUG_ON(osd_data->type != CEPH_OSD_DATA_TYPE_PAGES);
	num_pages = calc_pages_for((u64)osd_data->alignment,
					(u64)osd_data->length);
	for (i = 0; i < num_pages; i++) {
		struct page *page = osd_data->pages[i];

		if (rc < 0)
			goto unlock;
		if (bytes < (int)PAGE_CACHE_SIZE) {
			/* zero (remainder of) page */
			int s = bytes < 0 ? 0 : bytes;
			zero_user_segment(page, s, PAGE_CACHE_SIZE);
		}
 		dout("finish_read %p uptodate %p idx %lu\n", inode, page,
		     page->index);
		flush_dcache_page(page);
		SetPageUptodate(page);
		ceph_readpage_to_fscache(inode, page);
unlock:
		unlock_page(page);
		page_cache_release(page);
		bytes -= PAGE_CACHE_SIZE;
	}
	kfree(osd_data->pages);
}

static void ceph_unlock_page_vector(struct page **pages, int num_pages)
{
	int i;

	for (i = 0; i < num_pages; i++)
		unlock_page(pages[i]);
}

/*
 * start an async read(ahead) operation.  return nr_pages we submitted
 * a read for on success, or negative error code.
 */
static int start_read(struct inode *inode, struct list_head *page_list, int max)
{
	struct ceph_osd_client *osdc =
		&ceph_inode_to_client(inode)->client->osdc;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct page *page = list_entry(page_list->prev, struct page, lru);
	struct ceph_vino vino;
	struct ceph_osd_request *req;
	u64 off;
	u64 len;
	int i;
	struct page **pages;
	pgoff_t next_index;
	int nr_pages = 0;
	int ret;

	off = (u64) page_offset(page);

	/* count pages */
	next_index = page->index;
	list_for_each_entry_reverse(page, page_list, lru) {
		if (page->index != next_index)
			break;
		nr_pages++;
		next_index++;
		if (max && nr_pages == max)
			break;
	}
	len = nr_pages << PAGE_CACHE_SHIFT;
	dout("start_read %p nr_pages %d is %lld~%lld\n", inode, nr_pages,
	     off, len);
	vino = ceph_vino(inode);
	req = ceph_osdc_new_request(osdc, &ci->i_layout, vino, off, &len,
				    1, CEPH_OSD_OP_READ,
				    CEPH_OSD_FLAG_READ, NULL,
				    ci->i_truncate_seq, ci->i_truncate_size,
				    false);
	if (IS_ERR(req))
		return PTR_ERR(req);

	/* build page vector */
	nr_pages = calc_pages_for(0, len);
	pages = kmalloc(sizeof(*pages) * nr_pages, GFP_NOFS);
	ret = -ENOMEM;
	if (!pages)
		goto out;
	for (i = 0; i < nr_pages; ++i) {
		page = list_entry(page_list->prev, struct page, lru);
		BUG_ON(PageLocked(page));
		list_del(&page->lru);

 		dout("start_read %p adding %p idx %lu\n", inode, page,
		     page->index);
		if (add_to_page_cache_lru(page, &inode->i_data, page->index,
					  GFP_NOFS)) {
			ceph_fscache_uncache_page(inode, page);
			page_cache_release(page);
			dout("start_read %p add_to_page_cache failed %p\n",
			     inode, page);
			nr_pages = i;
			goto out_pages;
		}
		pages[i] = page;
	}
	osd_req_op_extent_osd_data_pages(req, 0, pages, len, 0, false, false);
	req->r_callback = finish_read;
	req->r_inode = inode;

	ceph_osdc_build_request(req, off, NULL, vino.snap, NULL);

	dout("start_read %p starting %p %lld~%lld\n", inode, req, off, len);
	ret = ceph_osdc_start_request(osdc, req, false);
	if (ret < 0)
		goto out_pages;
	ceph_osdc_put_request(req);
	return nr_pages;

out_pages:
	ceph_unlock_page_vector(pages, nr_pages);
	ceph_release_page_vector(pages, nr_pages);
out:
	ceph_osdc_put_request(req);
	return ret;
}


/*
 * Read multiple pages.  Leave pages we don't read + unlock in page_list;
 * the caller (VM) cleans them up.
 */
static int ceph_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *page_list, unsigned nr_pages)
{
	struct inode *inode = file_inode(file);
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	int rc = 0;
	int max = 0;

	rc = ceph_readpages_from_fscache(mapping->host, mapping, page_list,
					 &nr_pages);

	if (rc == 0)
		goto out;

	if (fsc->mount_options->rsize >= PAGE_CACHE_SIZE)
		max = (fsc->mount_options->rsize + PAGE_CACHE_SIZE - 1)
			>> PAGE_SHIFT;

	dout("readpages %p file %p nr_pages %d max %d\n", inode,
		file, nr_pages,
	     max);
	while (!list_empty(page_list)) {
		rc = start_read(inode, page_list, max);
		if (rc < 0)
			goto out;
		BUG_ON(rc == 0);
	}
out:
	ceph_fscache_readpages_cancel(inode, page_list);

	dout("readpages %p file %p ret %d\n", inode, file, rc);
	return rc;
}

/*
 * Get ref for the oldest snapc for an inode with dirty data... that is, the
 * only snap context we are allowed to write back.
 */
static struct ceph_snap_context *get_oldest_context(struct inode *inode,
						    u64 *snap_size)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_snap_context *snapc = NULL;
	struct ceph_cap_snap *capsnap = NULL;

	spin_lock(&ci->i_ceph_lock);
	list_for_each_entry(capsnap, &ci->i_cap_snaps, ci_item) {
		dout(" cap_snap %p snapc %p has %d dirty pages\n", capsnap,
		     capsnap->context, capsnap->dirty_pages);
		if (capsnap->dirty_pages) {
			snapc = ceph_get_snap_context(capsnap->context);
			if (snap_size)
				*snap_size = capsnap->size;
			break;
		}
	}
	if (!snapc && ci->i_wrbuffer_ref_head) {
		snapc = ceph_get_snap_context(ci->i_head_snapc);
		dout(" head snapc %p has %d dirty pages\n",
		     snapc, ci->i_wrbuffer_ref_head);
	}
	spin_unlock(&ci->i_ceph_lock);
	return snapc;
}

/*
 * Write a single page, but leave the page locked.
 *
 * If we get a write error, set the page error bit, but still adjust the
 * dirty page accounting (i.e., page is no longer dirty).
 */
static int writepage_nounlock(struct page *page, struct writeback_control *wbc)
{
	struct inode *inode;
	struct ceph_inode_info *ci;
	struct ceph_fs_client *fsc;
	struct ceph_osd_client *osdc;
	struct ceph_snap_context *snapc, *oldest;
	loff_t page_off = page_offset(page);
	long writeback_stat;
	u64 truncate_size, snap_size = 0;
	u32 truncate_seq;
	int err = 0, len = PAGE_CACHE_SIZE;

	dout("writepage %p idx %lu\n", page, page->index);

	if (!page->mapping || !page->mapping->host) {
		dout("writepage %p - no mapping\n", page);
		return -EFAULT;
	}
	inode = page->mapping->host;
	ci = ceph_inode(inode);
	fsc = ceph_inode_to_client(inode);
	osdc = &fsc->client->osdc;

	/* verify this is a writeable snap context */
	snapc = page_snap_context(page);
	if (snapc == NULL) {
		dout("writepage %p page %p not dirty?\n", inode, page);
		goto out;
	}
	oldest = get_oldest_context(inode, &snap_size);
	if (snapc->seq > oldest->seq) {
		dout("writepage %p page %p snapc %p not writeable - noop\n",
		     inode, page, snapc);
		/* we should only noop if called by kswapd */
		WARN_ON((current->flags & PF_MEMALLOC) == 0);
		ceph_put_snap_context(oldest);
		goto out;
	}
	ceph_put_snap_context(oldest);

	spin_lock(&ci->i_ceph_lock);
	truncate_seq = ci->i_truncate_seq;
	truncate_size = ci->i_truncate_size;
	if (!snap_size)
		snap_size = i_size_read(inode);
	spin_unlock(&ci->i_ceph_lock);

	/* is this a partial page at end of file? */
	if (page_off >= snap_size) {
		dout("%p page eof %llu\n", page, snap_size);
		goto out;
	}
	if (snap_size < page_off + len)
		len = snap_size - page_off;

	dout("writepage %p page %p index %lu on %llu~%u snapc %p\n",
	     inode, page, page->index, page_off, len, snapc);

	writeback_stat = atomic_long_inc_return(&fsc->writeback_count);
	if (writeback_stat >
	    CONGESTION_ON_THRESH(fsc->mount_options->congestion_kb))
		set_bdi_congested(&fsc->backing_dev_info, BLK_RW_ASYNC);

	ceph_readpage_to_fscache(inode, page);

	set_page_writeback(page);
	err = ceph_osdc_writepages(osdc, ceph_vino(inode),
				   &ci->i_layout, snapc,
				   page_off, len,
				   truncate_seq, truncate_size,
				   &inode->i_mtime, &page, 1);
	if (err < 0) {
		dout("writepage setting page/mapping error %d %p\n", err, page);
		SetPageError(page);
		mapping_set_error(&inode->i_data, err);
		if (wbc)
			wbc->pages_skipped++;
	} else {
		dout("writepage cleaned page %p\n", page);
		err = 0;  /* vfs expects us to return 0 */
	}
	page->private = 0;
	ClearPagePrivate(page);
	end_page_writeback(page);
	ceph_put_wrbuffer_cap_refs(ci, 1, snapc);
	ceph_put_snap_context(snapc);  /* page's reference */
out:
	return err;
}

static int ceph_writepage(struct page *page, struct writeback_control *wbc)
{
	int err;
	struct inode *inode = page->mapping->host;
	BUG_ON(!inode);
	ihold(inode);
	err = writepage_nounlock(page, wbc);
	unlock_page(page);
	iput(inode);
	return err;
}


/*
 * lame release_pages helper.  release_pages() isn't exported to
 * modules.
 */
static void ceph_release_pages(struct page **pages, int num)
{
	struct pagevec pvec;
	int i;

	pagevec_init(&pvec, 0);
	for (i = 0; i < num; i++) {
		if (pagevec_add(&pvec, pages[i]) == 0)
			pagevec_release(&pvec);
	}
	pagevec_release(&pvec);
}

/*
 * async writeback completion handler.
 *
 * If we get an error, set the mapping error bit, but not the individual
 * page error bits.
 */
static void writepages_finish(struct ceph_osd_request *req,
			      struct ceph_msg *msg)
{
	struct inode *inode = req->r_inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_osd_data *osd_data;
	unsigned wrote;
	struct page *page;
	int num_pages;
	int i;
	struct ceph_snap_context *snapc = req->r_snapc;
	struct address_space *mapping = inode->i_mapping;
	int rc = req->r_result;
	u64 bytes = req->r_ops[0].extent.length;
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	long writeback_stat;
	unsigned issued = ceph_caps_issued(ci);

	osd_data = osd_req_op_extent_osd_data(req, 0);
	BUG_ON(osd_data->type != CEPH_OSD_DATA_TYPE_PAGES);
	num_pages = calc_pages_for((u64)osd_data->alignment,
					(u64)osd_data->length);
	if (rc >= 0) {
		/*
		 * Assume we wrote the pages we originally sent.  The
		 * osd might reply with fewer pages if our writeback
		 * raced with a truncation and was adjusted at the osd,
		 * so don't believe the reply.
		 */
		wrote = num_pages;
	} else {
		wrote = 0;
		mapping_set_error(mapping, rc);
	}
	dout("writepages_finish %p rc %d bytes %llu wrote %d (pages)\n",
	     inode, rc, bytes, wrote);

	/* clean all pages */
	for (i = 0; i < num_pages; i++) {
		page = osd_data->pages[i];
		BUG_ON(!page);
		WARN_ON(!PageUptodate(page));

		writeback_stat =
			atomic_long_dec_return(&fsc->writeback_count);
		if (writeback_stat <
		    CONGESTION_OFF_THRESH(fsc->mount_options->congestion_kb))
			clear_bdi_congested(&fsc->backing_dev_info,
					    BLK_RW_ASYNC);

		ceph_put_snap_context(page_snap_context(page));
		page->private = 0;
		ClearPagePrivate(page);
		dout("unlocking %d %p\n", i, page);
		end_page_writeback(page);

		/*
		 * We lost the cache cap, need to truncate the page before
		 * it is unlocked, otherwise we'd truncate it later in the
		 * page truncation thread, possibly losing some data that
		 * raced its way in
		 */
		if ((issued & (CEPH_CAP_FILE_CACHE|CEPH_CAP_FILE_LAZYIO)) == 0)
			generic_error_remove_page(inode->i_mapping, page);

		unlock_page(page);
	}
	dout("%p wrote+cleaned %d pages\n", inode, wrote);
	ceph_put_wrbuffer_cap_refs(ci, num_pages, snapc);

	ceph_release_pages(osd_data->pages, num_pages);
	if (osd_data->pages_from_pool)
		mempool_free(osd_data->pages,
			     ceph_sb_to_client(inode->i_sb)->wb_pagevec_pool);
	else
		kfree(osd_data->pages);
	ceph_osdc_put_request(req);
}

/*
 * initiate async writeback
 */
static int ceph_writepages_start(struct address_space *mapping,
				 struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	struct ceph_vino vino = ceph_vino(inode);
	pgoff_t index, start, end;
	int range_whole = 0;
	int should_loop = 1;
	pgoff_t max_pages = 0, max_pages_ever = 0;
	struct ceph_snap_context *snapc = NULL, *last_snapc = NULL, *pgsnapc;
	struct pagevec pvec;
	int done = 0;
	int rc = 0;
	unsigned wsize = 1 << inode->i_blkbits;
	struct ceph_osd_request *req = NULL;
	int do_sync;
	u64 truncate_size, snap_size;
	u32 truncate_seq;

	/*
	 * Include a 'sync' in the OSD request if this is a data
	 * integrity write (e.g., O_SYNC write or fsync()), or if our
	 * cap is being revoked.
	 */
	if ((wbc->sync_mode == WB_SYNC_ALL) ||
		ceph_caps_revoking(ci, CEPH_CAP_FILE_BUFFER))
		do_sync = 1;
	dout("writepages_start %p dosync=%d (mode=%s)\n",
	     inode, do_sync,
	     wbc->sync_mode == WB_SYNC_NONE ? "NONE" :
	     (wbc->sync_mode == WB_SYNC_ALL ? "ALL" : "HOLD"));

	if (fsc->mount_state == CEPH_MOUNT_SHUTDOWN) {
		pr_warn("writepage_start %p on forced umount\n", inode);
		return -EIO; /* we're in a forced umount, don't write! */
	}
	if (fsc->mount_options->wsize && fsc->mount_options->wsize < wsize)
		wsize = fsc->mount_options->wsize;
	if (wsize < PAGE_CACHE_SIZE)
		wsize = PAGE_CACHE_SIZE;
	max_pages_ever = wsize >> PAGE_CACHE_SHIFT;

	pagevec_init(&pvec, 0);

	/* where to start/end? */
	if (wbc->range_cyclic) {
		start = mapping->writeback_index; /* Start from prev offset */
		end = -1;
		dout(" cyclic, start at %lu\n", start);
	} else {
		start = wbc->range_start >> PAGE_CACHE_SHIFT;
		end = wbc->range_end >> PAGE_CACHE_SHIFT;
		if (wbc->range_start == 0 && wbc->range_end == LLONG_MAX)
			range_whole = 1;
		should_loop = 0;
		dout(" not cyclic, %lu to %lu\n", start, end);
	}
	index = start;

retry:
	/* find oldest snap context with dirty data */
	ceph_put_snap_context(snapc);
	snap_size = 0;
	snapc = get_oldest_context(inode, &snap_size);
	if (!snapc) {
		/* hmm, why does writepages get called when there
		   is no dirty data? */
		dout(" no snap context with dirty data?\n");
		goto out;
	}
	if (snap_size == 0)
		snap_size = i_size_read(inode);
	dout(" oldest snapc is %p seq %lld (%d snaps)\n",
	     snapc, snapc->seq, snapc->num_snaps);

	spin_lock(&ci->i_ceph_lock);
	truncate_seq = ci->i_truncate_seq;
	truncate_size = ci->i_truncate_size;
	if (!snap_size)
		snap_size = i_size_read(inode);
	spin_unlock(&ci->i_ceph_lock);

	if (last_snapc && snapc != last_snapc) {
		/* if we switched to a newer snapc, restart our scan at the
		 * start of the original file range. */
		dout("  snapc differs from last pass, restarting at %lu\n",
		     index);
		index = start;
	}
	last_snapc = snapc;

	while (!done && index <= end) {
		int num_ops = do_sync ? 2 : 1;
		unsigned i;
		int first;
		pgoff_t next;
		int pvec_pages, locked_pages;
		struct page **pages = NULL;
		mempool_t *pool = NULL;	/* Becomes non-null if mempool used */
		struct page *page;
		int want;
		u64 offset, len;
		long writeback_stat;

		next = 0;
		locked_pages = 0;
		max_pages = max_pages_ever;

get_more_pages:
		first = -1;
		want = min(end - index,
			   min((pgoff_t)PAGEVEC_SIZE,
			       max_pages - (pgoff_t)locked_pages) - 1)
			+ 1;
		pvec_pages = pagevec_lookup_tag(&pvec, mapping, &index,
						PAGECACHE_TAG_DIRTY,
						want);
		dout("pagevec_lookup_tag got %d\n", pvec_pages);
		if (!pvec_pages && !locked_pages)
			break;
		for (i = 0; i < pvec_pages && locked_pages < max_pages; i++) {
			page = pvec.pages[i];
			dout("? %p idx %lu\n", page, page->index);
			if (locked_pages == 0)
				lock_page(page);  /* first page */
			else if (!trylock_page(page))
				break;

			/* only dirty pages, or our accounting breaks */
			if (unlikely(!PageDirty(page)) ||
			    unlikely(page->mapping != mapping)) {
				dout("!dirty or !mapping %p\n", page);
				unlock_page(page);
				break;
			}
			if (!wbc->range_cyclic && page->index > end) {
				dout("end of range %p\n", page);
				done = 1;
				unlock_page(page);
				break;
			}
			if (next && (page->index != next)) {
				dout("not consecutive %p\n", page);
				unlock_page(page);
				break;
			}
			if (wbc->sync_mode != WB_SYNC_NONE) {
				dout("waiting on writeback %p\n", page);
				wait_on_page_writeback(page);
			}
			if (page_offset(page) >= snap_size) {
				dout("%p page eof %llu\n", page, snap_size);
				done = 1;
				unlock_page(page);
				break;
			}
			if (PageWriteback(page)) {
				dout("%p under writeback\n", page);
				unlock_page(page);
				break;
			}

			/* only if matching snap context */
			pgsnapc = page_snap_context(page);
			if (pgsnapc->seq > snapc->seq) {
				dout("page snapc %p %lld > oldest %p %lld\n",
				     pgsnapc, pgsnapc->seq, snapc, snapc->seq);
				unlock_page(page);
				if (!locked_pages)
					continue; /* keep looking for snap */
				break;
			}

			if (!clear_page_dirty_for_io(page)) {
				dout("%p !clear_page_dirty_for_io\n", page);
				unlock_page(page);
				break;
			}

			/*
			 * We have something to write.  If this is
			 * the first locked page this time through,
			 * allocate an osd request and a page array
			 * that it will use.
			 */
			if (locked_pages == 0) {
				BUG_ON(pages);
				/* prepare async write request */
				offset = (u64)page_offset(page);
				len = wsize;
				req = ceph_osdc_new_request(&fsc->client->osdc,
							&ci->i_layout, vino,
							offset, &len, num_ops,
							CEPH_OSD_OP_WRITE,
							CEPH_OSD_FLAG_WRITE |
							CEPH_OSD_FLAG_ONDISK,
							snapc, truncate_seq,
							truncate_size, true);
				if (IS_ERR(req)) {
					rc = PTR_ERR(req);
					unlock_page(page);
					break;
				}

				req->r_callback = writepages_finish;
				req->r_inode = inode;

				max_pages = calc_pages_for(0, (u64)len);
				pages = kmalloc(max_pages * sizeof (*pages),
						GFP_NOFS);
				if (!pages) {
					pool = fsc->wb_pagevec_pool;
					pages = mempool_alloc(pool, GFP_NOFS);
					BUG_ON(!pages);
				}
			}

			/* note position of first page in pvec */
			if (first < 0)
				first = i;
			dout("%p will write page %p idx %lu\n",
			     inode, page, page->index);

			writeback_stat =
			       atomic_long_inc_return(&fsc->writeback_count);
			if (writeback_stat > CONGESTION_ON_THRESH(
				    fsc->mount_options->congestion_kb)) {
				set_bdi_congested(&fsc->backing_dev_info,
						  BLK_RW_ASYNC);
			}

			set_page_writeback(page);
			pages[locked_pages] = page;
			locked_pages++;
			next = page->index + 1;
		}

		/* did we get anything? */
		if (!locked_pages)
			goto release_pvec_pages;
		if (i) {
			int j;
			BUG_ON(!locked_pages || first < 0);

			if (pvec_pages && i == pvec_pages &&
			    locked_pages < max_pages) {
				dout("reached end pvec, trying for more\n");
				pagevec_reinit(&pvec);
				goto get_more_pages;
			}

			/* shift unused pages over in the pvec...  we
			 * will need to release them below. */
			for (j = i; j < pvec_pages; j++) {
				dout(" pvec leftover page %p\n",
				     pvec.pages[j]);
				pvec.pages[j-i+first] = pvec.pages[j];
			}
			pvec.nr -= i-first;
		}

		/* Format the osd request message and submit the write */

		offset = page_offset(pages[0]);
		len = min(snap_size - offset,
			  (u64)locked_pages << PAGE_CACHE_SHIFT);
		dout("writepages got %d pages at %llu~%llu\n",
		     locked_pages, offset, len);

		osd_req_op_extent_osd_data_pages(req, 0, pages, len, 0,
							!!pool, false);

		pages = NULL;	/* request message now owns the pages array */
		pool = NULL;

		/* Update the write op length in case we changed it */

		osd_req_op_extent_update(req, 0, len);

		vino = ceph_vino(inode);
		ceph_osdc_build_request(req, offset, snapc, vino.snap,
					&inode->i_mtime);

		rc = ceph_osdc_start_request(&fsc->client->osdc, req, true);
		BUG_ON(rc);
		req = NULL;

		/* continue? */
		index = next;
		wbc->nr_to_write -= locked_pages;
		if (wbc->nr_to_write <= 0)
			done = 1;

release_pvec_pages:
		dout("pagevec_release on %d pages (%p)\n", (int)pvec.nr,
		     pvec.nr ? pvec.pages[0] : NULL);
		pagevec_release(&pvec);

		if (locked_pages && !done)
			goto retry;
	}

	if (should_loop && !done) {
		/* more to do; loop back to beginning of file */
		dout("writepages looping back to beginning of file\n");
		should_loop = 0;
		index = 0;
		goto retry;
	}

	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0))
		mapping->writeback_index = index;

out:
	if (req)
		ceph_osdc_put_request(req);
	ceph_put_snap_context(snapc);
	dout("writepages done, rc = %d\n", rc);
	return rc;
}



/*
 * See if a given @snapc is either writeable, or already written.
 */
static int context_is_writeable_or_written(struct inode *inode,
					   struct ceph_snap_context *snapc)
{
	struct ceph_snap_context *oldest = get_oldest_context(inode, NULL);
	int ret = !oldest || snapc->seq <= oldest->seq;

	ceph_put_snap_context(oldest);
	return ret;
}

/*
 * We are only allowed to write into/dirty the page if the page is
 * clean, or already dirty within the same snap context.
 *
 * called with page locked.
 * return success with page locked,
 * or any failure (incl -EAGAIN) with page unlocked.
 */
static int ceph_update_writeable_page(struct file *file,
			    loff_t pos, unsigned len,
			    struct page *page)
{
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_mds_client *mdsc = ceph_inode_to_client(inode)->mdsc;
	loff_t page_off = pos & PAGE_CACHE_MASK;
	int pos_in_page = pos & ~PAGE_CACHE_MASK;
	int end_in_page = pos_in_page + len;
	loff_t i_size;
	int r;
	struct ceph_snap_context *snapc, *oldest;

retry_locked:
	/* writepages currently holds page lock, but if we change that later, */
	wait_on_page_writeback(page);

	/* check snap context */
	BUG_ON(!ci->i_snap_realm);
	down_read(&mdsc->snap_rwsem);
	BUG_ON(!ci->i_snap_realm->cached_context);
	snapc = page_snap_context(page);
	if (snapc && snapc != ci->i_head_snapc) {
		/*
		 * this page is already dirty in another (older) snap
		 * context!  is it writeable now?
		 */
		oldest = get_oldest_context(inode, NULL);
		up_read(&mdsc->snap_rwsem);

		if (snapc->seq > oldest->seq) {
			ceph_put_snap_context(oldest);
			dout(" page %p snapc %p not current or oldest\n",
			     page, snapc);
			/*
			 * queue for writeback, and wait for snapc to
			 * be writeable or written
			 */
			snapc = ceph_get_snap_context(snapc);
			unlock_page(page);
			ceph_queue_writeback(inode);
			r = wait_event_interruptible(ci->i_cap_wq,
			       context_is_writeable_or_written(inode, snapc));
			ceph_put_snap_context(snapc);
			if (r == -ERESTARTSYS)
				return r;
			return -EAGAIN;
		}
		ceph_put_snap_context(oldest);

		/* yay, writeable, do it now (without dropping page lock) */
		dout(" page %p snapc %p not current, but oldest\n",
		     page, snapc);
		if (!clear_page_dirty_for_io(page))
			goto retry_locked;
		r = writepage_nounlock(page, NULL);
		if (r < 0)
			goto fail_nosnap;
		goto retry_locked;
	}

	if (PageUptodate(page)) {
		dout(" page %p already uptodate\n", page);
		return 0;
	}

	/* full page? */
	if (pos_in_page == 0 && len == PAGE_CACHE_SIZE)
		return 0;

	/* past end of file? */
	i_size = inode->i_size;   /* caller holds i_mutex */

	if (i_size + len > inode->i_sb->s_maxbytes) {
		/* file is too big */
		r = -EINVAL;
		goto fail;
	}

	if (page_off >= i_size ||
	    (pos_in_page == 0 && (pos+len) >= i_size &&
	     end_in_page - pos_in_page != PAGE_CACHE_SIZE)) {
		dout(" zeroing %p 0 - %d and %d - %d\n",
		     page, pos_in_page, end_in_page, (int)PAGE_CACHE_SIZE);
		zero_user_segments(page,
				   0, pos_in_page,
				   end_in_page, PAGE_CACHE_SIZE);
		return 0;
	}

	/* we need to read it. */
	up_read(&mdsc->snap_rwsem);
	r = readpage_nounlock(file, page);
	if (r < 0)
		goto fail_nosnap;
	goto retry_locked;

fail:
	up_read(&mdsc->snap_rwsem);
fail_nosnap:
	unlock_page(page);
	return r;
}

/*
 * We are only allowed to write into/dirty the page if the page is
 * clean, or already dirty within the same snap context.
 */
static int ceph_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
	struct inode *inode = file_inode(file);
	struct page *page;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	int r;

	do {
		/* get a page */
		page = grab_cache_page_write_begin(mapping, index, 0);
		if (!page)
			return -ENOMEM;
		*pagep = page;

		dout("write_begin file %p inode %p page %p %d~%d\n", file,
		     inode, page, (int)pos, (int)len);

		r = ceph_update_writeable_page(file, pos, len, page);
	} while (r == -EAGAIN);

	return r;
}

/*
 * we don't do anything in here that simple_write_end doesn't do
 * except adjust dirty page accounting and drop read lock on
 * mdsc->snap_rwsem.
 */
static int ceph_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{
	struct inode *inode = file_inode(file);
	struct ceph_fs_client *fsc = ceph_inode_to_client(inode);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	unsigned from = pos & (PAGE_CACHE_SIZE - 1);
	int check_cap = 0;

	dout("write_end file %p inode %p page %p %d~%d (%d)\n", file,
	     inode, page, (int)pos, (int)copied, (int)len);

	/* zero the stale part of the page if we did a short copy */
	if (copied < len)
		zero_user_segment(page, from+copied, len);

	/* did file size increase? */
	/* (no need for i_size_read(); we caller holds i_mutex */
	if (pos+copied > inode->i_size)
		check_cap = ceph_inode_set_size(inode, pos+copied);

	if (!PageUptodate(page))
		SetPageUptodate(page);

	set_page_dirty(page);

	unlock_page(page);
	up_read(&mdsc->snap_rwsem);
	page_cache_release(page);

	if (check_cap)
		ceph_check_caps(ceph_inode(inode), CHECK_CAPS_AUTHONLY, NULL);

	return copied;
}

/*
 * we set .direct_IO to indicate direct io is supported, but since we
 * intercept O_DIRECT reads and writes early, this function should
 * never get called.
 */
static ssize_t ceph_direct_io(int rw, struct kiocb *iocb,
			      struct iov_iter *iter,
			      loff_t pos)
{
	WARN_ON(1);
	return -EINVAL;
}

const struct address_space_operations ceph_aops = {
	.readpage = ceph_readpage,
	.readpages = ceph_readpages,
	.writepage = ceph_writepage,
	.writepages = ceph_writepages_start,
	.write_begin = ceph_write_begin,
	.write_end = ceph_write_end,
	.set_page_dirty = ceph_set_page_dirty,
	.invalidatepage = ceph_invalidatepage,
	.releasepage = ceph_releasepage,
	.direct_IO = ceph_direct_io,
};


/*
 * vm ops
 */
static int ceph_filemap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vma->vm_file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_file_info *fi = vma->vm_file->private_data;
	loff_t off = vmf->pgoff << PAGE_CACHE_SHIFT;
	int want, got, ret;

	dout("filemap_fault %p %llx.%llx %llu~%zd trying to get caps\n",
	     inode, ceph_vinop(inode), off, (size_t)PAGE_CACHE_SIZE);
	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want = CEPH_CAP_FILE_CACHE | CEPH_CAP_FILE_LAZYIO;
	else
		want = CEPH_CAP_FILE_CACHE;
	while (1) {
		got = 0;
		ret = ceph_get_caps(ci, CEPH_CAP_FILE_RD, want, &got, -1);
		if (ret == 0)
			break;
		if (ret != -ERESTARTSYS) {
			WARN_ON(1);
			return VM_FAULT_SIGBUS;
		}
	}
	dout("filemap_fault %p %llu~%zd got cap refs on %s\n",
	     inode, off, (size_t)PAGE_CACHE_SIZE, ceph_cap_string(got));

	ret = filemap_fault(vma, vmf);

	dout("filemap_fault %p %llu~%zd dropping cap refs on %s ret %d\n",
	     inode, off, (size_t)PAGE_CACHE_SIZE, ceph_cap_string(got), ret);
	ceph_put_cap_refs(ci, got);

	return ret;
}

/*
 * Reuse write_begin here for simplicity.
 */
static int ceph_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vma->vm_file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_file_info *fi = vma->vm_file->private_data;
	struct ceph_mds_client *mdsc = ceph_inode_to_client(inode)->mdsc;
	struct page *page = vmf->page;
	loff_t off = page_offset(page);
	loff_t size = i_size_read(inode);
	size_t len;
	int want, got, ret;

	if (off + PAGE_CACHE_SIZE <= size)
		len = PAGE_CACHE_SIZE;
	else
		len = size & ~PAGE_CACHE_MASK;

	dout("page_mkwrite %p %llx.%llx %llu~%zd getting caps i_size %llu\n",
	     inode, ceph_vinop(inode), off, len, size);
	if (fi->fmode & CEPH_FILE_MODE_LAZY)
		want = CEPH_CAP_FILE_BUFFER | CEPH_CAP_FILE_LAZYIO;
	else
		want = CEPH_CAP_FILE_BUFFER;
	while (1) {
		got = 0;
		ret = ceph_get_caps(ci, CEPH_CAP_FILE_WR, want, &got, off + len);
		if (ret == 0)
			break;
		if (ret != -ERESTARTSYS) {
			WARN_ON(1);
			return VM_FAULT_SIGBUS;
		}
	}
	dout("page_mkwrite %p %llu~%zd got cap refs on %s\n",
	     inode, off, len, ceph_cap_string(got));

	/* Update time before taking page lock */
	file_update_time(vma->vm_file);

	lock_page(page);

	ret = VM_FAULT_NOPAGE;
	if ((off > size) ||
	    (page->mapping != inode->i_mapping))
		goto out;

	ret = ceph_update_writeable_page(vma->vm_file, off, len, page);
	if (ret == 0) {
		/* success.  we'll keep the page locked. */
		set_page_dirty(page);
		up_read(&mdsc->snap_rwsem);
		ret = VM_FAULT_LOCKED;
	} else {
		if (ret == -ENOMEM)
			ret = VM_FAULT_OOM;
		else
			ret = VM_FAULT_SIGBUS;
	}
out:
	if (ret != VM_FAULT_LOCKED) {
		unlock_page(page);
	} else {
		int dirty;
		spin_lock(&ci->i_ceph_lock);
		dirty = __ceph_mark_dirty_caps(ci, CEPH_CAP_FILE_WR);
		spin_unlock(&ci->i_ceph_lock);
		if (dirty)
			__mark_inode_dirty(inode, dirty);
	}

	dout("page_mkwrite %p %llu~%zd dropping cap refs on %s ret %d\n",
	     inode, off, len, ceph_cap_string(got), ret);
	ceph_put_cap_refs(ci, got);

	return ret;
}

static struct vm_operations_struct ceph_vmops = {
	.fault		= ceph_filemap_fault,
	.page_mkwrite	= ceph_page_mkwrite,
	.remap_pages	= generic_file_remap_pages,
};

int ceph_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct address_space *mapping = file->f_mapping;

	if (!mapping->a_ops->readpage)
		return -ENOEXEC;
	file_accessed(file);
	vma->vm_ops = &ceph_vmops;
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/ceph/addr.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>
#include <linux/in.h>

// #include "super.h"
// #include "mds_client.h"
#include "ioctl.h"


/*
 * ioctls
 */

/*
 * get and set the file layout
 */
static long ceph_ioctl_get_layout(struct file *file, void __user *arg)
{
	struct ceph_inode_info *ci = ceph_inode(file_inode(file));
	struct ceph_ioctl_layout l;
	int err;

	err = ceph_do_getattr(file_inode(file), CEPH_STAT_CAP_LAYOUT);
	if (!err) {
		l.stripe_unit = ceph_file_layout_su(ci->i_layout);
		l.stripe_count = ceph_file_layout_stripe_count(ci->i_layout);
		l.object_size = ceph_file_layout_object_size(ci->i_layout);
		l.data_pool = le32_to_cpu(ci->i_layout.fl_pg_pool);
		l.preferred_osd = (s32)-1;
		if (copy_to_user(arg, &l, sizeof(l)))
			return -EFAULT;
	}

	return err;
}

static long __validate_layout(struct ceph_mds_client *mdsc,
			      struct ceph_ioctl_layout *l)
{
	int i, err;

	/* validate striping parameters */
	if ((l->object_size & ~PAGE_MASK) ||
	    (l->stripe_unit & ~PAGE_MASK) ||
	    (l->stripe_unit != 0 &&
	     ((unsigned)l->object_size % (unsigned)l->stripe_unit)))
		return -EINVAL;

	/* make sure it's a valid data pool */
	mutex_lock(&mdsc->mutex);
	err = -EINVAL;
	for (i = 0; i < mdsc->mdsmap->m_num_data_pg_pools; i++)
		if (mdsc->mdsmap->m_data_pg_pools[i] == l->data_pool) {
			err = 0;
			break;
		}
	mutex_unlock(&mdsc->mutex);
	if (err)
		return err;

	return 0;
}

static long ceph_ioctl_set_layout(struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ceph_mds_client *mdsc = ceph_sb_to_client(inode->i_sb)->mdsc;
	struct ceph_mds_request *req;
	struct ceph_ioctl_layout l;
	struct ceph_inode_info *ci = ceph_inode(file_inode(file));
	struct ceph_ioctl_layout nl;
	int err;

	if (copy_from_user(&l, arg, sizeof(l)))
		return -EFAULT;

	/* validate changed params against current layout */
	err = ceph_do_getattr(file_inode(file), CEPH_STAT_CAP_LAYOUT);
	if (err)
		return err;

	memset(&nl, 0, sizeof(nl));
	if (l.stripe_count)
		nl.stripe_count = l.stripe_count;
	else
		nl.stripe_count = ceph_file_layout_stripe_count(ci->i_layout);
	if (l.stripe_unit)
		nl.stripe_unit = l.stripe_unit;
	else
		nl.stripe_unit = ceph_file_layout_su(ci->i_layout);
	if (l.object_size)
		nl.object_size = l.object_size;
	else
		nl.object_size = ceph_file_layout_object_size(ci->i_layout);
	if (l.data_pool)
		nl.data_pool = l.data_pool;
	else
		nl.data_pool = ceph_file_layout_pg_pool(ci->i_layout);

	/* this is obsolete, and always -1 */
	nl.preferred_osd = le64_to_cpu(-1);

	err = __validate_layout(mdsc, &nl);
	if (err)
		return err;

	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_SETLAYOUT,
				       USE_AUTH_MDS);
	if (IS_ERR(req))
		return PTR_ERR(req);
	req->r_inode = inode;
	ihold(inode);
	req->r_num_caps = 1;

	req->r_inode_drop = CEPH_CAP_FILE_SHARED | CEPH_CAP_FILE_EXCL;

	req->r_args.setlayout.layout.fl_stripe_unit =
		cpu_to_le32(l.stripe_unit);
	req->r_args.setlayout.layout.fl_stripe_count =
		cpu_to_le32(l.stripe_count);
	req->r_args.setlayout.layout.fl_object_size =
		cpu_to_le32(l.object_size);
	req->r_args.setlayout.layout.fl_pg_pool = cpu_to_le32(l.data_pool);

	err = ceph_mdsc_do_request(mdsc, NULL, req);
	ceph_mdsc_put_request(req);
	return err;
}

/*
 * Set a layout policy on a directory inode. All items in the tree
 * rooted at this inode will inherit this layout on creation,
 * (It doesn't apply retroactively )
 * unless a subdirectory has its own layout policy.
 */
static long ceph_ioctl_set_layout_policy (struct file *file, void __user *arg)
{
	struct inode *inode = file_inode(file);
	struct ceph_mds_request *req;
	struct ceph_ioctl_layout l;
	int err;
	struct ceph_mds_client *mdsc = ceph_sb_to_client(inode->i_sb)->mdsc;

	/* copy and validate */
	if (copy_from_user(&l, arg, sizeof(l)))
		return -EFAULT;

	err = __validate_layout(mdsc, &l);
	if (err)
		return err;

	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_SETDIRLAYOUT,
				       USE_AUTH_MDS);

	if (IS_ERR(req))
		return PTR_ERR(req);
	req->r_inode = inode;
	ihold(inode);
	req->r_num_caps = 1;

	req->r_args.setlayout.layout.fl_stripe_unit =
			cpu_to_le32(l.stripe_unit);
	req->r_args.setlayout.layout.fl_stripe_count =
			cpu_to_le32(l.stripe_count);
	req->r_args.setlayout.layout.fl_object_size =
			cpu_to_le32(l.object_size);
	req->r_args.setlayout.layout.fl_pg_pool =
			cpu_to_le32(l.data_pool);

	err = ceph_mdsc_do_request(mdsc, inode, req);
	ceph_mdsc_put_request(req);
	return err;
}

/*
 * Return object name, size/offset information, and location (OSD
 * number, network address) for a given file offset.
 */
static long ceph_ioctl_get_dataloc(struct file *file, void __user *arg)
{
	struct ceph_ioctl_dataloc dl;
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_osd_client *osdc =
		&ceph_sb_to_client(inode->i_sb)->client->osdc;
	struct ceph_object_locator oloc;
	struct ceph_object_id oid;
	u64 len = 1, olen;
	u64 tmp;
	struct ceph_pg pgid;
	int r;

	/* copy and validate */
	if (copy_from_user(&dl, arg, sizeof(dl)))
		return -EFAULT;

	down_read(&osdc->map_sem);
	r = ceph_calc_file_object_mapping(&ci->i_layout, dl.file_offset, len,
					  &dl.object_no, &dl.object_offset,
					  &olen);
	if (r < 0) {
		up_read(&osdc->map_sem);
		return -EIO;
	}
	dl.file_offset -= dl.object_offset;
	dl.object_size = ceph_file_layout_object_size(ci->i_layout);
	dl.block_size = ceph_file_layout_su(ci->i_layout);

	/* block_offset = object_offset % block_size */
	tmp = dl.object_offset;
	dl.block_offset = do_div(tmp, dl.block_size);

	snprintf(dl.object_name, sizeof(dl.object_name), "%llx.%08llx",
		 ceph_ino(inode), dl.object_no);

	oloc.pool = ceph_file_layout_pg_pool(ci->i_layout);
	ceph_oid_set_name(&oid, dl.object_name);

	r = ceph_oloc_oid_to_pg(osdc->osdmap, &oloc, &oid, &pgid);
	if (r < 0) {
		up_read(&osdc->map_sem);
		return r;
	}

	dl.osd = ceph_calc_pg_primary(osdc->osdmap, pgid);
	if (dl.osd >= 0) {
		struct ceph_entity_addr *a =
			ceph_osd_addr(osdc->osdmap, dl.osd);
		if (a)
			memcpy(&dl.osd_addr, &a->in_addr, sizeof(dl.osd_addr));
	} else {
		memset(&dl.osd_addr, 0, sizeof(dl.osd_addr));
	}
	up_read(&osdc->map_sem);

	/* send result back to user */
	if (copy_to_user(arg, &dl, sizeof(dl)))
		return -EFAULT;

	return 0;
}

static long ceph_ioctl_lazyio(struct file *file)
{
	struct ceph_file_info *fi = file->private_data;
	struct inode *inode = file_inode(file);
	struct ceph_inode_info *ci = ceph_inode(inode);

	if ((fi->fmode & CEPH_FILE_MODE_LAZY) == 0) {
		spin_lock(&ci->i_ceph_lock);
		ci->i_nr_by_mode[fi->fmode]--;
		fi->fmode |= CEPH_FILE_MODE_LAZY;
		ci->i_nr_by_mode[fi->fmode]++;
		spin_unlock(&ci->i_ceph_lock);
		dout("ioctl_layzio: file %p marked lazy\n", file);

		ceph_check_caps(ci, 0, NULL);
	} else {
		dout("ioctl_layzio: file %p already lazy\n", file);
	}
	return 0;
}

static long ceph_ioctl_syncio(struct file *file)
{
	struct ceph_file_info *fi = file->private_data;

	fi->flags |= CEPH_F_SYNC;
	return 0;
}

long ceph_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	dout("ioctl file %p cmd %u arg %lu\n", file, cmd, arg);
	switch (cmd) {
	case CEPH_IOC_GET_LAYOUT:
		return ceph_ioctl_get_layout(file, (void __user *)arg);

	case CEPH_IOC_SET_LAYOUT:
		return ceph_ioctl_set_layout(file, (void __user *)arg);

	case CEPH_IOC_SET_LAYOUT_POLICY:
		return ceph_ioctl_set_layout_policy(file, (void __user *)arg);

	case CEPH_IOC_GET_DATALOC:
		return ceph_ioctl_get_dataloc(file, (void __user *)arg);

	case CEPH_IOC_LAZYIO:
		return ceph_ioctl_lazyio(file);

	case CEPH_IOC_SYNCIO:
		return ceph_ioctl_syncio(file);
	}

	return -ENOTTY;
}
/************************************************************/
/* ../linux-3.17/fs/ceph/ioctl.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

#include <linux/exportfs.h>
// #include <linux/slab.h>
#include <asm/unaligned.h>

// #include "super.h"
// #include "mds_client.h"

/*
 * Basic fh
 */
struct ceph_nfs_fh {
	u64 ino;
} __attribute__ ((packed));

/*
 * Larger fh that includes parent ino.
 */
struct ceph_nfs_confh {
	u64 ino, parent_ino;
} __attribute__ ((packed));

static int ceph_encode_fh(struct inode *inode, u32 *rawfh, int *max_len,
			  struct inode *parent_inode)
{
	int type;
	struct ceph_nfs_fh *fh = (void *)rawfh;
	struct ceph_nfs_confh *cfh = (void *)rawfh;
	int connected_handle_length = sizeof(*cfh)/4;
	int handle_length = sizeof(*fh)/4;

	/* don't re-export snaps */
	if (ceph_snap(inode) != CEPH_NOSNAP)
		return -EINVAL;

	if (parent_inode && (*max_len < connected_handle_length)) {
		*max_len = connected_handle_length;
		return FILEID_INVALID;
	} else if (*max_len < handle_length) {
		*max_len = handle_length;
		return FILEID_INVALID;
	}

	if (parent_inode) {
		dout("encode_fh %llx with parent %llx\n",
		     ceph_ino(inode), ceph_ino(parent_inode));
		cfh->ino = ceph_ino(inode);
		cfh->parent_ino = ceph_ino(parent_inode);
		*max_len = connected_handle_length;
		type = FILEID_INO32_GEN_PARENT;
	} else {
		dout("encode_fh %llx\n", ceph_ino(inode));
		fh->ino = ceph_ino(inode);
		*max_len = handle_length;
		type = FILEID_INO32_GEN;
	}
	return type;
}

static struct dentry *__fh_to_dentry(struct super_block *sb, u64 ino)
{
	struct ceph_mds_client *mdsc = ceph_sb_to_client(sb)->mdsc;
	struct inode *inode;
	struct dentry *dentry;
	struct ceph_vino vino;
	int err;

	vino.ino = ino;
	vino.snap = CEPH_NOSNAP;
	inode = ceph_find_inode(sb, vino);
	if (!inode) {
		struct ceph_mds_request *req;

		req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_LOOKUPINO,
					       USE_ANY_MDS);
		if (IS_ERR(req))
			return ERR_CAST(req);

		req->r_ino1 = vino;
		req->r_num_caps = 1;
		err = ceph_mdsc_do_request(mdsc, NULL, req);
		inode = req->r_target_inode;
		if (inode)
			ihold(inode);
		ceph_mdsc_put_request(req);
		if (!inode)
			return ERR_PTR(-ESTALE);
	}

	dentry = d_obtain_alias(inode);
	if (IS_ERR(dentry)) {
		iput(inode);
		return dentry;
	}
	err = ceph_init_dentry(dentry);
	if (err < 0) {
		dput(dentry);
		return ERR_PTR(err);
	}
	dout("__fh_to_dentry %llx %p dentry %p\n", ino, inode, dentry);
	return dentry;
}

/*
 * convert regular fh to dentry
 */
static struct dentry *ceph_fh_to_dentry(struct super_block *sb,
					struct fid *fid,
					int fh_len, int fh_type)
{
	struct ceph_nfs_fh *fh = (void *)fid->raw;

	if (fh_type != FILEID_INO32_GEN  &&
	    fh_type != FILEID_INO32_GEN_PARENT)
		return NULL;
	if (fh_len < sizeof(*fh) / 4)
		return NULL;

	dout("fh_to_dentry %llx\n", fh->ino);
	return __fh_to_dentry(sb, fh->ino);
}

static struct dentry *__get_parent(struct super_block *sb,
				   struct dentry *child, u64 ino)
{
	struct ceph_mds_client *mdsc = ceph_sb_to_client(sb)->mdsc;
	struct ceph_mds_request *req;
	struct inode *inode;
	struct dentry *dentry;
	int err;

	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_LOOKUPPARENT,
				       USE_ANY_MDS);
	if (IS_ERR(req))
		return ERR_CAST(req);

	if (child) {
		req->r_inode = child->d_inode;
		ihold(child->d_inode);
	} else {
		req->r_ino1 = (struct ceph_vino) {
			.ino = ino,
			.snap = CEPH_NOSNAP,
		};
	}
	req->r_num_caps = 1;
	err = ceph_mdsc_do_request(mdsc, NULL, req);
	inode = req->r_target_inode;
	if (inode)
		ihold(inode);
	ceph_mdsc_put_request(req);
	if (!inode)
		return ERR_PTR(-ENOENT);

	dentry = d_obtain_alias(inode);
	if (IS_ERR(dentry)) {
		iput(inode);
		return dentry;
	}
	err = ceph_init_dentry(dentry);
	if (err < 0) {
		dput(dentry);
		return ERR_PTR(err);
	}
	dout("__get_parent ino %llx parent %p ino %llx.%llx\n",
	     child ? ceph_ino(child->d_inode) : ino,
	     dentry, ceph_vinop(inode));
	return dentry;
}

static struct dentry *ceph_get_parent(struct dentry *child)
{
	/* don't re-export snaps */
	if (ceph_snap(child->d_inode) != CEPH_NOSNAP)
		return ERR_PTR(-EINVAL);

	dout("get_parent %p ino %llx.%llx\n",
	     child, ceph_vinop(child->d_inode));
	return __get_parent(child->d_sb, child, 0);
}

/*
 * convert regular fh to parent
 */
static struct dentry *ceph_fh_to_parent(struct super_block *sb,
					struct fid *fid,
					int fh_len, int fh_type)
{
	struct ceph_nfs_confh *cfh = (void *)fid->raw;
	struct dentry *dentry;

	if (fh_type != FILEID_INO32_GEN_PARENT)
		return NULL;
	if (fh_len < sizeof(*cfh) / 4)
		return NULL;

	dout("fh_to_parent %llx\n", cfh->parent_ino);
	dentry = __get_parent(sb, NULL, cfh->ino);
	if (IS_ERR(dentry) && PTR_ERR(dentry) == -ENOENT)
		dentry = __fh_to_dentry(sb, cfh->parent_ino);
	return dentry;
}

static int ceph_get_name(struct dentry *parent, char *name,
			 struct dentry *child)
{
	struct ceph_mds_client *mdsc;
	struct ceph_mds_request *req;
	int err;

	mdsc = ceph_inode_to_client(child->d_inode)->mdsc;
	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_LOOKUPNAME,
				       USE_ANY_MDS);
	if (IS_ERR(req))
		return PTR_ERR(req);

	mutex_lock(&parent->d_inode->i_mutex);

	req->r_inode = child->d_inode;
	ihold(child->d_inode);
	req->r_ino2 = ceph_vino(parent->d_inode);
	req->r_locked_dir = parent->d_inode;
	req->r_num_caps = 2;
	err = ceph_mdsc_do_request(mdsc, NULL, req);

	mutex_unlock(&parent->d_inode->i_mutex);

	if (!err) {
		struct ceph_mds_reply_info_parsed *rinfo = &req->r_reply_info;
		memcpy(name, rinfo->dname, rinfo->dname_len);
		name[rinfo->dname_len] = 0;
		dout("get_name %p ino %llx.%llx name %s\n",
		     child, ceph_vinop(child->d_inode), name);
	} else {
		dout("get_name %p ino %llx.%llx err %d\n",
		     child, ceph_vinop(child->d_inode), err);
	}

	ceph_mdsc_put_request(req);
	return err;
}

const struct export_operations ceph_export_ops = {
	.encode_fh = ceph_encode_fh,
	.fh_to_dentry = ceph_fh_to_dentry,
	.fh_to_parent = ceph_fh_to_parent,
	.get_parent = ceph_get_parent,
	.get_name = ceph_get_name,
};
/************************************************************/
/* ../linux-3.17/fs/ceph/export.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

// #include <linux/fs.h>
// #include <linux/kernel.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/vmalloc.h>
#include <linux/wait.h>
// #include <linux/writeback.h>

// #include "super.h"
// #include "mds_client.h"
// #include "cache.h"
// #include <linux/ceph/decode.h>
#include <linux/ceph/messenger.h>

/*
 * Capability management
 *
 * The Ceph metadata servers control client access to inode metadata
 * and file data by issuing capabilities, granting clients permission
 * to read and/or write both inode field and file data to OSDs
 * (storage nodes).  Each capability consists of a set of bits
 * indicating which operations are allowed.
 *
 * If the client holds a *_SHARED cap, the client has a coherent value
 * that can be safely read from the cached inode.
 *
 * In the case of a *_EXCL (exclusive) or FILE_WR capabilities, the
 * client is allowed to change inode attributes (e.g., file size,
 * mtime), note its dirty state in the ceph_cap, and asynchronously
 * flush that metadata change to the MDS.
 *
 * In the event of a conflicting operation (perhaps by another
 * client), the MDS will revoke the conflicting client capabilities.
 *
 * In order for a client to cache an inode, it must hold a capability
 * with at least one MDS server.  When inodes are released, release
 * notifications are batched and periodically sent en masse to the MDS
 * cluster to release server state.
 */


/*
 * Generate readable cap strings for debugging output.
 */
#define MAX_CAP_STR 20
static char cap_str[MAX_CAP_STR][40];
static DEFINE_SPINLOCK(cap_str_lock);
static int last_cap_str;

static char *gcap_string(char *s, int c)
{
	if (c & CEPH_CAP_GSHARED)
		*s++ = 's';
	if (c & CEPH_CAP_GEXCL)
		*s++ = 'x';
	if (c & CEPH_CAP_GCACHE)
		*s++ = 'c';
	if (c & CEPH_CAP_GRD)
		*s++ = 'r';
	if (c & CEPH_CAP_GWR)
		*s++ = 'w';
	if (c & CEPH_CAP_GBUFFER)
		*s++ = 'b';
	if (c & CEPH_CAP_GLAZYIO)
		*s++ = 'l';
	return s;
}

const char *ceph_cap_string(int caps)
{
	int i;
	char *s;
	int c;

	spin_lock(&cap_str_lock);
	i = last_cap_str++;
	if (last_cap_str == MAX_CAP_STR)
		last_cap_str = 0;
	spin_unlock(&cap_str_lock);

	s = cap_str[i];

	if (caps & CEPH_CAP_PIN)
		*s++ = 'p';

	c = (caps >> CEPH_CAP_SAUTH) & 3;
	if (c) {
		*s++ = 'A';
		s = gcap_string(s, c);
	}

	c = (caps >> CEPH_CAP_SLINK) & 3;
	if (c) {
		*s++ = 'L';
		s = gcap_string(s, c);
	}

	c = (caps >> CEPH_CAP_SXATTR) & 3;
	if (c) {
		*s++ = 'X';
		s = gcap_string(s, c);
	}

	c = caps >> CEPH_CAP_SFILE;
	if (c) {
		*s++ = 'F';
		s = gcap_string(s, c);
	}

	if (s == cap_str[i])
		*s++ = '-';
	*s = 0;
	return cap_str[i];
}

void ceph_caps_init(struct ceph_mds_client *mdsc)
{
	INIT_LIST_HEAD(&mdsc->caps_list);
	spin_lock_init(&mdsc->caps_list_lock);
}

void ceph_caps_finalize(struct ceph_mds_client *mdsc)
{
	struct ceph_cap *cap;

	spin_lock(&mdsc->caps_list_lock);
	while (!list_empty(&mdsc->caps_list)) {
		cap = list_first_entry(&mdsc->caps_list,
				       struct ceph_cap, caps_item);
		list_del(&cap->caps_item);
		kmem_cache_free(ceph_cap_cachep, cap);
	}
	mdsc->caps_total_count = 0;
	mdsc->caps_avail_count = 0;
	mdsc->caps_use_count = 0;
	mdsc->caps_reserve_count = 0;
	mdsc->caps_min_count = 0;
	spin_unlock(&mdsc->caps_list_lock);
}

void ceph_adjust_min_caps(struct ceph_mds_client *mdsc, int delta)
{
	spin_lock(&mdsc->caps_list_lock);
	mdsc->caps_min_count += delta;
	BUG_ON(mdsc->caps_min_count < 0);
	spin_unlock(&mdsc->caps_list_lock);
}

void ceph_reserve_caps(struct ceph_mds_client *mdsc,
		      struct ceph_cap_reservation *ctx, int need)
{
	int i;
	struct ceph_cap *cap;
	int have;
	int alloc = 0;
	LIST_HEAD(newcaps);

	dout("reserve caps ctx=%p need=%d\n", ctx, need);

	/* first reserve any caps that are already allocated */
	spin_lock(&mdsc->caps_list_lock);
	if (mdsc->caps_avail_count >= need)
		have = need;
	else
		have = mdsc->caps_avail_count;
	mdsc->caps_avail_count -= have;
	mdsc->caps_reserve_count += have;
	BUG_ON(mdsc->caps_total_count != mdsc->caps_use_count +
					 mdsc->caps_reserve_count +
					 mdsc->caps_avail_count);
	spin_unlock(&mdsc->caps_list_lock);

	for (i = have; i < need; i++) {
		cap = kmem_cache_alloc(ceph_cap_cachep, GFP_NOFS);
		if (!cap)
			break;
		list_add(&cap->caps_item, &newcaps);
		alloc++;
	}
	/* we didn't manage to reserve as much as we needed */
	if (have + alloc != need)
		pr_warn("reserve caps ctx=%p ENOMEM need=%d got=%d\n",
			ctx, need, have + alloc);

	spin_lock(&mdsc->caps_list_lock);
	mdsc->caps_total_count += alloc;
	mdsc->caps_reserve_count += alloc;
	list_splice(&newcaps, &mdsc->caps_list);

	BUG_ON(mdsc->caps_total_count != mdsc->caps_use_count +
					 mdsc->caps_reserve_count +
					 mdsc->caps_avail_count);
	spin_unlock(&mdsc->caps_list_lock);

	ctx->count = need;
	dout("reserve caps ctx=%p %d = %d used + %d resv + %d avail\n",
	     ctx, mdsc->caps_total_count, mdsc->caps_use_count,
	     mdsc->caps_reserve_count, mdsc->caps_avail_count);
}

int ceph_unreserve_caps(struct ceph_mds_client *mdsc,
			struct ceph_cap_reservation *ctx)
{
	dout("unreserve caps ctx=%p count=%d\n", ctx, ctx->count);
	if (ctx->count) {
		spin_lock(&mdsc->caps_list_lock);
		BUG_ON(mdsc->caps_reserve_count < ctx->count);
		mdsc->caps_reserve_count -= ctx->count;
		mdsc->caps_avail_count += ctx->count;
		ctx->count = 0;
		dout("unreserve caps %d = %d used + %d resv + %d avail\n",
		     mdsc->caps_total_count, mdsc->caps_use_count,
		     mdsc->caps_reserve_count, mdsc->caps_avail_count);
		BUG_ON(mdsc->caps_total_count != mdsc->caps_use_count +
						 mdsc->caps_reserve_count +
						 mdsc->caps_avail_count);
		spin_unlock(&mdsc->caps_list_lock);
	}
	return 0;
}

struct ceph_cap *ceph_get_cap(struct ceph_mds_client *mdsc,
			      struct ceph_cap_reservation *ctx)
{
	struct ceph_cap *cap = NULL;

	/* temporary, until we do something about cap import/export */
	if (!ctx) {
		cap = kmem_cache_alloc(ceph_cap_cachep, GFP_NOFS);
		if (cap) {
			spin_lock(&mdsc->caps_list_lock);
			mdsc->caps_use_count++;
			mdsc->caps_total_count++;
			spin_unlock(&mdsc->caps_list_lock);
		}
		return cap;
	}

	spin_lock(&mdsc->caps_list_lock);
	dout("get_cap ctx=%p (%d) %d = %d used + %d resv + %d avail\n",
	     ctx, ctx->count, mdsc->caps_total_count, mdsc->caps_use_count,
	     mdsc->caps_reserve_count, mdsc->caps_avail_count);
	BUG_ON(!ctx->count);
	BUG_ON(ctx->count > mdsc->caps_reserve_count);
	BUG_ON(list_empty(&mdsc->caps_list));

	ctx->count--;
	mdsc->caps_reserve_count--;
	mdsc->caps_use_count++;

	cap = list_first_entry(&mdsc->caps_list, struct ceph_cap, caps_item);
	list_del(&cap->caps_item);

	BUG_ON(mdsc->caps_total_count != mdsc->caps_use_count +
	       mdsc->caps_reserve_count + mdsc->caps_avail_count);
	spin_unlock(&mdsc->caps_list_lock);
	return cap;
}

void ceph_put_cap(struct ceph_mds_client *mdsc, struct ceph_cap *cap)
{
	spin_lock(&mdsc->caps_list_lock);
	dout("put_cap %p %d = %d used + %d resv + %d avail\n",
	     cap, mdsc->caps_total_count, mdsc->caps_use_count,
	     mdsc->caps_reserve_count, mdsc->caps_avail_count);
	mdsc->caps_use_count--;
	/*
	 * Keep some preallocated caps around (ceph_min_count), to
	 * avoid lots of free/alloc churn.
	 */
	if (mdsc->caps_avail_count >= mdsc->caps_reserve_count +
				      mdsc->caps_min_count) {
		mdsc->caps_total_count--;
		kmem_cache_free(ceph_cap_cachep, cap);
	} else {
		mdsc->caps_avail_count++;
		list_add(&cap->caps_item, &mdsc->caps_list);
	}

	BUG_ON(mdsc->caps_total_count != mdsc->caps_use_count +
	       mdsc->caps_reserve_count + mdsc->caps_avail_count);
	spin_unlock(&mdsc->caps_list_lock);
}

void ceph_reservation_status(struct ceph_fs_client *fsc,
			     int *total, int *avail, int *used, int *reserved,
			     int *min)
{
	struct ceph_mds_client *mdsc = fsc->mdsc;

	if (total)
		*total = mdsc->caps_total_count;
	if (avail)
		*avail = mdsc->caps_avail_count;
	if (used)
		*used = mdsc->caps_use_count;
	if (reserved)
		*reserved = mdsc->caps_reserve_count;
	if (min)
		*min = mdsc->caps_min_count;
}

/*
 * Find ceph_cap for given mds, if any.
 *
 * Called with i_ceph_lock held.
 */
static struct ceph_cap *__get_cap_for_mds(struct ceph_inode_info *ci, int mds)
{
	struct ceph_cap *cap;
	struct rb_node *n = ci->i_caps.rb_node;

	while (n) {
		cap = rb_entry(n, struct ceph_cap, ci_node);
		if (mds < cap->mds)
			n = n->rb_left;
		else if (mds > cap->mds)
			n = n->rb_right;
		else
			return cap;
	}
	return NULL;
}

struct ceph_cap *ceph_get_cap_for_mds(struct ceph_inode_info *ci, int mds)
{
	struct ceph_cap *cap;

	spin_lock(&ci->i_ceph_lock);
	cap = __get_cap_for_mds(ci, mds);
	spin_unlock(&ci->i_ceph_lock);
	return cap;
}

/*
 * Return id of any MDS with a cap, preferably FILE_WR|BUFFER|EXCL, else -1.
 */
static int __ceph_get_cap_mds(struct ceph_inode_info *ci)
{
	struct ceph_cap *cap;
	int mds = -1;
	struct rb_node *p;

	/* prefer mds with WR|BUFFER|EXCL caps */
	for (p = rb_first(&ci->i_caps); p; p = rb_next(p)) {
		cap = rb_entry(p, struct ceph_cap, ci_node);
		mds = cap->mds;
		if (cap->issued & (CEPH_CAP_FILE_WR |
				   CEPH_CAP_FILE_BUFFER |
				   CEPH_CAP_FILE_EXCL))
			break;
	}
	return mds;
}

int ceph_get_cap_mds(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int mds;
	spin_lock(&ci->i_ceph_lock);
	mds = __ceph_get_cap_mds(ceph_inode(inode));
	spin_unlock(&ci->i_ceph_lock);
	return mds;
}

/*
 * Called under i_ceph_lock.
 */
static void __insert_cap_node(struct ceph_inode_info *ci,
			      struct ceph_cap *new)
{
	struct rb_node **p = &ci->i_caps.rb_node;
	struct rb_node *parent = NULL;
	struct ceph_cap *cap = NULL;

	while (*p) {
		parent = *p;
		cap = rb_entry(parent, struct ceph_cap, ci_node);
		if (new->mds < cap->mds)
			p = &(*p)->rb_left;
		else if (new->mds > cap->mds)
			p = &(*p)->rb_right;
		else
			BUG();
	}

	rb_link_node(&new->ci_node, parent, p);
	rb_insert_color(&new->ci_node, &ci->i_caps);
}

/*
 * (re)set cap hold timeouts, which control the delayed release
 * of unused caps back to the MDS.  Should be called on cap use.
 */
static void __cap_set_timeouts(struct ceph_mds_client *mdsc,
			       struct ceph_inode_info *ci)
{
	struct ceph_mount_options *ma = mdsc->fsc->mount_options;

	ci->i_hold_caps_min = round_jiffies(jiffies +
					    ma->caps_wanted_delay_min * HZ);
	ci->i_hold_caps_max = round_jiffies(jiffies +
					    ma->caps_wanted_delay_max * HZ);
	dout("__cap_set_timeouts %p min %lu max %lu\n", &ci->vfs_inode,
	     ci->i_hold_caps_min - jiffies, ci->i_hold_caps_max - jiffies);
}

/*
 * (Re)queue cap at the end of the delayed cap release list.
 *
 * If I_FLUSH is set, leave the inode at the front of the list.
 *
 * Caller holds i_ceph_lock
 *    -> we take mdsc->cap_delay_lock
 */
static void __cap_delay_requeue(struct ceph_mds_client *mdsc,
				struct ceph_inode_info *ci)
{
	__cap_set_timeouts(mdsc, ci);
	dout("__cap_delay_requeue %p flags %d at %lu\n", &ci->vfs_inode,
	     ci->i_ceph_flags, ci->i_hold_caps_max);
	if (!mdsc->stopping) {
		spin_lock(&mdsc->cap_delay_lock);
		if (!list_empty(&ci->i_cap_delay_list)) {
			if (ci->i_ceph_flags & CEPH_I_FLUSH)
				goto no_change;
			list_del_init(&ci->i_cap_delay_list);
		}
		list_add_tail(&ci->i_cap_delay_list, &mdsc->cap_delay_list);
no_change:
		spin_unlock(&mdsc->cap_delay_lock);
	}
}

/*
 * Queue an inode for immediate writeback.  Mark inode with I_FLUSH,
 * indicating we should send a cap message to flush dirty metadata
 * asap, and move to the front of the delayed cap list.
 */
static void __cap_delay_requeue_front(struct ceph_mds_client *mdsc,
				      struct ceph_inode_info *ci)
{
	dout("__cap_delay_requeue_front %p\n", &ci->vfs_inode);
	spin_lock(&mdsc->cap_delay_lock);
	ci->i_ceph_flags |= CEPH_I_FLUSH;
	if (!list_empty(&ci->i_cap_delay_list))
		list_del_init(&ci->i_cap_delay_list);
	list_add(&ci->i_cap_delay_list, &mdsc->cap_delay_list);
	spin_unlock(&mdsc->cap_delay_lock);
}

/*
 * Cancel delayed work on cap.
 *
 * Caller must hold i_ceph_lock.
 */
static void __cap_delay_cancel(struct ceph_mds_client *mdsc,
			       struct ceph_inode_info *ci)
{
	dout("__cap_delay_cancel %p\n", &ci->vfs_inode);
	if (list_empty(&ci->i_cap_delay_list))
		return;
	spin_lock(&mdsc->cap_delay_lock);
	list_del_init(&ci->i_cap_delay_list);
	spin_unlock(&mdsc->cap_delay_lock);
}

/*
 * Common issue checks for add_cap, handle_cap_grant.
 */
static void __check_cap_issue(struct ceph_inode_info *ci, struct ceph_cap *cap,
			      unsigned issued)
{
	unsigned had = __ceph_caps_issued(ci, NULL);

	/*
	 * Each time we receive FILE_CACHE anew, we increment
	 * i_rdcache_gen.
	 */
	if ((issued & (CEPH_CAP_FILE_CACHE|CEPH_CAP_FILE_LAZYIO)) &&
	    (had & (CEPH_CAP_FILE_CACHE|CEPH_CAP_FILE_LAZYIO)) == 0) {
		ci->i_rdcache_gen++;
	}

	/*
	 * if we are newly issued FILE_SHARED, mark dir not complete; we
	 * don't know what happened to this directory while we didn't
	 * have the cap.
	 */
	if ((issued & CEPH_CAP_FILE_SHARED) &&
	    (had & CEPH_CAP_FILE_SHARED) == 0) {
		ci->i_shared_gen++;
		if (S_ISDIR(ci->vfs_inode.i_mode)) {
			dout(" marking %p NOT complete\n", &ci->vfs_inode);
			__ceph_dir_clear_complete(ci);
		}
	}
}

/*
 * Add a capability under the given MDS session.
 *
 * Caller should hold session snap_rwsem (read) and s_mutex.
 *
 * @fmode is the open file mode, if we are opening a file, otherwise
 * it is < 0.  (This is so we can atomically add the cap and add an
 * open file reference to it.)
 */
void ceph_add_cap(struct inode *inode,
		  struct ceph_mds_session *session, u64 cap_id,
		  int fmode, unsigned issued, unsigned wanted,
		  unsigned seq, unsigned mseq, u64 realmino, int flags,
		  struct ceph_cap **new_cap)
{
	struct ceph_mds_client *mdsc = ceph_inode_to_client(inode)->mdsc;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_cap *cap;
	int mds = session->s_mds;
	int actual_wanted;

	dout("add_cap %p mds%d cap %llx %s seq %d\n", inode,
	     session->s_mds, cap_id, ceph_cap_string(issued), seq);

	/*
	 * If we are opening the file, include file mode wanted bits
	 * in wanted.
	 */
	if (fmode >= 0)
		wanted |= ceph_caps_for_mode(fmode);

	cap = __get_cap_for_mds(ci, mds);
	if (!cap) {
		cap = *new_cap;
		*new_cap = NULL;

		cap->issued = 0;
		cap->implemented = 0;
		cap->mds = mds;
		cap->mds_wanted = 0;
		cap->mseq = 0;

		cap->ci = ci;
		__insert_cap_node(ci, cap);

		/* add to session cap list */
		cap->session = session;
		spin_lock(&session->s_cap_lock);
		list_add_tail(&cap->session_caps, &session->s_caps);
		session->s_nr_caps++;
		spin_unlock(&session->s_cap_lock);
	} else {
		/*
		 * auth mds of the inode changed. we received the cap export
		 * message, but still haven't received the cap import message.
		 * handle_cap_export() updated the new auth MDS' cap.
		 *
		 * "ceph_seq_cmp(seq, cap->seq) <= 0" means we are processing
		 * a message that was send before the cap import message. So
		 * don't remove caps.
		 */
		if (ceph_seq_cmp(seq, cap->seq) <= 0) {
			WARN_ON(cap != ci->i_auth_cap);
			WARN_ON(cap->cap_id != cap_id);
			seq = cap->seq;
			mseq = cap->mseq;
			issued |= cap->issued;
			flags |= CEPH_CAP_FLAG_AUTH;
		}
	}

	if (!ci->i_snap_realm) {
		/*
		 * add this inode to the appropriate snap realm
		 */
		struct ceph_snap_realm *realm = ceph_lookup_snap_realm(mdsc,
							       realmino);
		if (realm) {
			ceph_get_snap_realm(mdsc, realm);
			spin_lock(&realm->inodes_with_caps_lock);
			ci->i_snap_realm = realm;
			list_add(&ci->i_snap_realm_item,
				 &realm->inodes_with_caps);
			spin_unlock(&realm->inodes_with_caps_lock);
		} else {
			pr_err("ceph_add_cap: couldn't find snap realm %llx\n",
			       realmino);
			WARN_ON(!realm);
		}
	}

	__check_cap_issue(ci, cap, issued);

	/*
	 * If we are issued caps we don't want, or the mds' wanted
	 * value appears to be off, queue a check so we'll release
	 * later and/or update the mds wanted value.
	 */
	actual_wanted = __ceph_caps_wanted(ci);
	if ((wanted & ~actual_wanted) ||
	    (issued & ~actual_wanted & CEPH_CAP_ANY_WR)) {
		dout(" issued %s, mds wanted %s, actual %s, queueing\n",
		     ceph_cap_string(issued), ceph_cap_string(wanted),
		     ceph_cap_string(actual_wanted));
		__cap_delay_requeue(mdsc, ci);
	}

	if (flags & CEPH_CAP_FLAG_AUTH) {
		if (ci->i_auth_cap == NULL ||
		    ceph_seq_cmp(ci->i_auth_cap->mseq, mseq) < 0) {
			ci->i_auth_cap = cap;
			cap->mds_wanted = wanted;
		}
	} else {
		WARN_ON(ci->i_auth_cap == cap);
	}

	dout("add_cap inode %p (%llx.%llx) cap %p %s now %s seq %d mds%d\n",
	     inode, ceph_vinop(inode), cap, ceph_cap_string(issued),
	     ceph_cap_string(issued|cap->issued), seq, mds);
	cap->cap_id = cap_id;
	cap->issued = issued;
	cap->implemented |= issued;
	if (ceph_seq_cmp(mseq, cap->mseq) > 0)
		cap->mds_wanted = wanted;
	else
		cap->mds_wanted |= wanted;
	cap->seq = seq;
	cap->issue_seq = seq;
	cap->mseq = mseq;
	cap->cap_gen = session->s_cap_gen;

	if (fmode >= 0)
		__ceph_get_fmode(ci, fmode);
}

/*
 * Return true if cap has not timed out and belongs to the current
 * generation of the MDS session (i.e. has not gone 'stale' due to
 * us losing touch with the mds).
 */
static int __cap_is_valid(struct ceph_cap *cap)
{
	unsigned long ttl;
	u32 gen;

	spin_lock(&cap->session->s_gen_ttl_lock);
	gen = cap->session->s_cap_gen;
	ttl = cap->session->s_cap_ttl;
	spin_unlock(&cap->session->s_gen_ttl_lock);

	if (cap->cap_gen < gen || time_after_eq(jiffies, ttl)) {
		dout("__cap_is_valid %p cap %p issued %s "
		     "but STALE (gen %u vs %u)\n", &cap->ci->vfs_inode,
		     cap, ceph_cap_string(cap->issued), cap->cap_gen, gen);
		return 0;
	}

	return 1;
}

/*
 * Return set of valid cap bits issued to us.  Note that caps time
 * out, and may be invalidated in bulk if the client session times out
 * and session->s_cap_gen is bumped.
 */
int __ceph_caps_issued(struct ceph_inode_info *ci, int *implemented)
{
	int have = ci->i_snap_caps;
	struct ceph_cap *cap;
	struct rb_node *p;

	if (implemented)
		*implemented = 0;
	for (p = rb_first(&ci->i_caps); p; p = rb_next(p)) {
		cap = rb_entry(p, struct ceph_cap, ci_node);
		if (!__cap_is_valid(cap))
			continue;
		dout("__ceph_caps_issued %p cap %p issued %s\n",
		     &ci->vfs_inode, cap, ceph_cap_string(cap->issued));
		have |= cap->issued;
		if (implemented)
			*implemented |= cap->implemented;
	}
	/*
	 * exclude caps issued by non-auth MDS, but are been revoking
	 * by the auth MDS. The non-auth MDS should be revoking/exporting
	 * these caps, but the message is delayed.
	 */
	if (ci->i_auth_cap) {
		cap = ci->i_auth_cap;
		have &= ~cap->implemented | cap->issued;
	}
	return have;
}

/*
 * Get cap bits issued by caps other than @ocap
 */
int __ceph_caps_issued_other(struct ceph_inode_info *ci, struct ceph_cap *ocap)
{
	int have = ci->i_snap_caps;
	struct ceph_cap *cap;
	struct rb_node *p;

	for (p = rb_first(&ci->i_caps); p; p = rb_next(p)) {
		cap = rb_entry(p, struct ceph_cap, ci_node);
		if (cap == ocap)
			continue;
		if (!__cap_is_valid(cap))
			continue;
		have |= cap->issued;
	}
	return have;
}

/*
 * Move a cap to the end of the LRU (oldest caps at list head, newest
 * at list tail).
 */
static void __touch_cap(struct ceph_cap *cap)
{
	struct ceph_mds_session *s = cap->session;

	spin_lock(&s->s_cap_lock);
	if (s->s_cap_iterator == NULL) {
		dout("__touch_cap %p cap %p mds%d\n", &cap->ci->vfs_inode, cap,
		     s->s_mds);
		list_move_tail(&cap->session_caps, &s->s_caps);
	} else {
		dout("__touch_cap %p cap %p mds%d NOP, iterating over caps\n",
		     &cap->ci->vfs_inode, cap, s->s_mds);
	}
	spin_unlock(&s->s_cap_lock);
}

/*
 * Check if we hold the given mask.  If so, move the cap(s) to the
 * front of their respective LRUs.  (This is the preferred way for
 * callers to check for caps they want.)
 */
int __ceph_caps_issued_mask(struct ceph_inode_info *ci, int mask, int touch)
{
	struct ceph_cap *cap;
	struct rb_node *p;
	int have = ci->i_snap_caps;

	if ((have & mask) == mask) {
		dout("__ceph_caps_issued_mask %p snap issued %s"
		     " (mask %s)\n", &ci->vfs_inode,
		     ceph_cap_string(have),
		     ceph_cap_string(mask));
		return 1;
	}

	for (p = rb_first(&ci->i_caps); p; p = rb_next(p)) {
		cap = rb_entry(p, struct ceph_cap, ci_node);
		if (!__cap_is_valid(cap))
			continue;
		if ((cap->issued & mask) == mask) {
			dout("__ceph_caps_issued_mask %p cap %p issued %s"
			     " (mask %s)\n", &ci->vfs_inode, cap,
			     ceph_cap_string(cap->issued),
			     ceph_cap_string(mask));
			if (touch)
				__touch_cap(cap);
			return 1;
		}

		/* does a combination of caps satisfy mask? */
		have |= cap->issued;
		if ((have & mask) == mask) {
			dout("__ceph_caps_issued_mask %p combo issued %s"
			     " (mask %s)\n", &ci->vfs_inode,
			     ceph_cap_string(cap->issued),
			     ceph_cap_string(mask));
			if (touch) {
				struct rb_node *q;

				/* touch this + preceding caps */
				__touch_cap(cap);
				for (q = rb_first(&ci->i_caps); q != p;
				     q = rb_next(q)) {
					cap = rb_entry(q, struct ceph_cap,
						       ci_node);
					if (!__cap_is_valid(cap))
						continue;
					__touch_cap(cap);
				}
			}
			return 1;
		}
	}

	return 0;
}

/*
 * Return true if mask caps are currently being revoked by an MDS.
 */
int __ceph_caps_revoking_other(struct ceph_inode_info *ci,
			       struct ceph_cap *ocap, int mask)
{
	struct ceph_cap *cap;
	struct rb_node *p;

	for (p = rb_first(&ci->i_caps); p; p = rb_next(p)) {
		cap = rb_entry(p, struct ceph_cap, ci_node);
		if (cap != ocap &&
		    (cap->implemented & ~cap->issued & mask))
			return 1;
	}
	return 0;
}

int ceph_caps_revoking(struct ceph_inode_info *ci, int mask)
{
	struct inode *inode = &ci->vfs_inode;
	int ret;

	spin_lock(&ci->i_ceph_lock);
	ret = __ceph_caps_revoking_other(ci, NULL, mask);
	spin_unlock(&ci->i_ceph_lock);
	dout("ceph_caps_revoking %p %s = %d\n", inode,
	     ceph_cap_string(mask), ret);
	return ret;
}

int __ceph_caps_used(struct ceph_inode_info *ci)
{
	int used = 0;
	if (ci->i_pin_ref)
		used |= CEPH_CAP_PIN;
	if (ci->i_rd_ref)
		used |= CEPH_CAP_FILE_RD;
	if (ci->i_rdcache_ref || ci->vfs_inode.i_data.nrpages)
		used |= CEPH_CAP_FILE_CACHE;
	if (ci->i_wr_ref)
		used |= CEPH_CAP_FILE_WR;
	if (ci->i_wb_ref || ci->i_wrbuffer_ref)
		used |= CEPH_CAP_FILE_BUFFER;
	return used;
}

/*
 * wanted, by virtue of open file modes
 */
int __ceph_caps_file_wanted(struct ceph_inode_info *ci)
{
	int want = 0;
	int mode;
	for (mode = 0; mode < CEPH_FILE_MODE_NUM; mode++)
		if (ci->i_nr_by_mode[mode])
			want |= ceph_caps_for_mode(mode);
	return want;
}

/*
 * Return caps we have registered with the MDS(s) as 'wanted'.
 */
int __ceph_caps_mds_wanted(struct ceph_inode_info *ci)
{
	struct ceph_cap *cap;
	struct rb_node *p;
	int mds_wanted = 0;

	for (p = rb_first(&ci->i_caps); p; p = rb_next(p)) {
		cap = rb_entry(p, struct ceph_cap, ci_node);
		if (!__cap_is_valid(cap))
			continue;
		if (cap == ci->i_auth_cap)
			mds_wanted |= cap->mds_wanted;
		else
			mds_wanted |= (cap->mds_wanted & ~CEPH_CAP_ANY_FILE_WR);
	}
	return mds_wanted;
}

/*
 * called under i_ceph_lock
 */
static int __ceph_is_any_caps(struct ceph_inode_info *ci)
{
	return !RB_EMPTY_ROOT(&ci->i_caps);
}

int ceph_is_any_caps(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int ret;

	spin_lock(&ci->i_ceph_lock);
	ret = __ceph_is_any_caps(ci);
	spin_unlock(&ci->i_ceph_lock);

	return ret;
}

/*
 * Remove a cap.  Take steps to deal with a racing iterate_session_caps.
 *
 * caller should hold i_ceph_lock.
 * caller will not hold session s_mutex if called from destroy_inode.
 */
void __ceph_remove_cap(struct ceph_cap *cap, bool queue_release)
{
	struct ceph_mds_session *session = cap->session;
	struct ceph_inode_info *ci = cap->ci;
	struct ceph_mds_client *mdsc =
		ceph_sb_to_client(ci->vfs_inode.i_sb)->mdsc;
	int removed = 0;

	dout("__ceph_remove_cap %p from %p\n", cap, &ci->vfs_inode);

	/* remove from session list */
	spin_lock(&session->s_cap_lock);
	/*
	 * s_cap_reconnect is protected by s_cap_lock. no one changes
	 * s_cap_gen while session is in the reconnect state.
	 */
	if (queue_release &&
	    (!session->s_cap_reconnect ||
	     cap->cap_gen == session->s_cap_gen))
		__queue_cap_release(session, ci->i_vino.ino, cap->cap_id,
				    cap->mseq, cap->issue_seq);

	if (session->s_cap_iterator == cap) {
		/* not yet, we are iterating over this very cap */
		dout("__ceph_remove_cap  delaying %p removal from session %p\n",
		     cap, cap->session);
	} else {
		list_del_init(&cap->session_caps);
		session->s_nr_caps--;
		cap->session = NULL;
		removed = 1;
	}
	/* protect backpointer with s_cap_lock: see iterate_session_caps */
	cap->ci = NULL;
	spin_unlock(&session->s_cap_lock);

	/* remove from inode list */
	rb_erase(&cap->ci_node, &ci->i_caps);
	if (ci->i_auth_cap == cap)
		ci->i_auth_cap = NULL;

	if (removed)
		ceph_put_cap(mdsc, cap);

	if (!__ceph_is_any_caps(ci) && ci->i_snap_realm) {
		struct ceph_snap_realm *realm = ci->i_snap_realm;
		spin_lock(&realm->inodes_with_caps_lock);
		list_del_init(&ci->i_snap_realm_item);
		ci->i_snap_realm_counter++;
		ci->i_snap_realm = NULL;
		spin_unlock(&realm->inodes_with_caps_lock);
		ceph_put_snap_realm(mdsc, realm);
	}
	if (!__ceph_is_any_real_caps(ci))
		__cap_delay_cancel(mdsc, ci);
}

/*
 * Build and send a cap message to the given MDS.
 *
 * Caller should be holding s_mutex.
 */
static int send_cap_msg(struct ceph_mds_session *session,
			u64 ino, u64 cid, int op,
			int caps, int wanted, int dirty,
			u32 seq, u64 flush_tid, u32 issue_seq, u32 mseq,
			u64 size, u64 max_size,
			struct timespec *mtime, struct timespec *atime,
			u64 time_warp_seq,
			kuid_t uid, kgid_t gid, umode_t mode,
			u64 xattr_version,
			struct ceph_buffer *xattrs_buf,
			u64 follows)
{
	struct ceph_mds_caps *fc;
	struct ceph_msg *msg;

	dout("send_cap_msg %s %llx %llx caps %s wanted %s dirty %s"
	     " seq %u/%u mseq %u follows %lld size %llu/%llu"
	     " xattr_ver %llu xattr_len %d\n", ceph_cap_op_name(op),
	     cid, ino, ceph_cap_string(caps), ceph_cap_string(wanted),
	     ceph_cap_string(dirty),
	     seq, issue_seq, mseq, follows, size, max_size,
	     xattr_version, xattrs_buf ? (int)xattrs_buf->vec.iov_len : 0);

	msg = ceph_msg_new(CEPH_MSG_CLIENT_CAPS, sizeof(*fc), GFP_NOFS, false);
	if (!msg)
		return -ENOMEM;

	msg->hdr.tid = cpu_to_le64(flush_tid);

	fc = msg->front.iov_base;
	memset(fc, 0, sizeof(*fc));

	fc->cap_id = cpu_to_le64(cid);
	fc->op = cpu_to_le32(op);
	fc->seq = cpu_to_le32(seq);
	fc->issue_seq = cpu_to_le32(issue_seq);
	fc->migrate_seq = cpu_to_le32(mseq);
	fc->caps = cpu_to_le32(caps);
	fc->wanted = cpu_to_le32(wanted);
	fc->dirty = cpu_to_le32(dirty);
	fc->ino = cpu_to_le64(ino);
	fc->snap_follows = cpu_to_le64(follows);

	fc->size = cpu_to_le64(size);
	fc->max_size = cpu_to_le64(max_size);
	if (mtime)
		ceph_encode_timespec(&fc->mtime, mtime);
	if (atime)
		ceph_encode_timespec(&fc->atime, atime);
	fc->time_warp_seq = cpu_to_le32(time_warp_seq);

	fc->uid = cpu_to_le32(from_kuid(&init_user_ns, uid));
	fc->gid = cpu_to_le32(from_kgid(&init_user_ns, gid));
	fc->mode = cpu_to_le32(mode);

	fc->xattr_version = cpu_to_le64(xattr_version);
	if (xattrs_buf) {
		msg->middle = ceph_buffer_get(xattrs_buf);
		fc->xattr_len = cpu_to_le32(xattrs_buf->vec.iov_len);
		msg->hdr.middle_len = cpu_to_le32(xattrs_buf->vec.iov_len);
	}

	ceph_con_send(&session->s_con, msg);
	return 0;
}

void __queue_cap_release(struct ceph_mds_session *session,
			 u64 ino, u64 cap_id, u32 migrate_seq,
			 u32 issue_seq)
{
	struct ceph_msg *msg;
	struct ceph_mds_cap_release *head;
	struct ceph_mds_cap_item *item;

	BUG_ON(!session->s_num_cap_releases);
	msg = list_first_entry(&session->s_cap_releases,
			       struct ceph_msg, list_head);

	dout(" adding %llx release to mds%d msg %p (%d left)\n",
	     ino, session->s_mds, msg, session->s_num_cap_releases);

	BUG_ON(msg->front.iov_len + sizeof(*item) > PAGE_CACHE_SIZE);
	head = msg->front.iov_base;
	le32_add_cpu(&head->num, 1);
	item = msg->front.iov_base + msg->front.iov_len;
	item->ino = cpu_to_le64(ino);
	item->cap_id = cpu_to_le64(cap_id);
	item->migrate_seq = cpu_to_le32(migrate_seq);
	item->seq = cpu_to_le32(issue_seq);

	session->s_num_cap_releases--;

	msg->front.iov_len += sizeof(*item);
	if (le32_to_cpu(head->num) == CEPH_CAPS_PER_RELEASE) {
		dout(" release msg %p full\n", msg);
		list_move_tail(&msg->list_head, &session->s_cap_releases_done);
	} else {
		dout(" release msg %p at %d/%d (%d)\n", msg,
		     (int)le32_to_cpu(head->num),
		     (int)CEPH_CAPS_PER_RELEASE,
		     (int)msg->front.iov_len);
	}
}

/*
 * Queue cap releases when an inode is dropped from our cache.  Since
 * inode is about to be destroyed, there is no need for i_ceph_lock.
 */
void ceph_queue_caps_release(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct rb_node *p;

	p = rb_first(&ci->i_caps);
	while (p) {
		struct ceph_cap *cap = rb_entry(p, struct ceph_cap, ci_node);
		p = rb_next(p);
		__ceph_remove_cap(cap, true);
	}
}

/*
 * Send a cap msg on the given inode.  Update our caps state, then
 * drop i_ceph_lock and send the message.
 *
 * Make note of max_size reported/requested from mds, revoked caps
 * that have now been implemented.
 *
 * Make half-hearted attempt ot to invalidate page cache if we are
 * dropping RDCACHE.  Note that this will leave behind locked pages
 * that we'll then need to deal with elsewhere.
 *
 * Return non-zero if delayed release, or we experienced an error
 * such that the caller should requeue + retry later.
 *
 * called with i_ceph_lock, then drops it.
 * caller should hold snap_rwsem (read), s_mutex.
 */
static int __send_cap(struct ceph_mds_client *mdsc, struct ceph_cap *cap,
		      int op, int used, int want, int retain, int flushing,
		      unsigned *pflush_tid)
	__releases(cap->ci->i_ceph_lock)
{
	struct ceph_inode_info *ci = cap->ci;
	struct inode *inode = &ci->vfs_inode;
	u64 cap_id = cap->cap_id;
	int held, revoking, dropping, keep;
	u64 seq, issue_seq, mseq, time_warp_seq, follows;
	u64 size, max_size;
	struct timespec mtime, atime;
	int wake = 0;
	umode_t mode;
	kuid_t uid;
	kgid_t gid;
	struct ceph_mds_session *session;
	u64 xattr_version = 0;
	struct ceph_buffer *xattr_blob = NULL;
	int delayed = 0;
	u64 flush_tid = 0;
	int i;
	int ret;

	held = cap->issued | cap->implemented;
	revoking = cap->implemented & ~cap->issued;
	retain &= ~revoking;
	dropping = cap->issued & ~retain;

	dout("__send_cap %p cap %p session %p %s -> %s (revoking %s)\n",
	     inode, cap, cap->session,
	     ceph_cap_string(held), ceph_cap_string(held & retain),
	     ceph_cap_string(revoking));
	BUG_ON((retain & CEPH_CAP_PIN) == 0);

	session = cap->session;

	/* don't release wanted unless we've waited a bit. */
	if ((ci->i_ceph_flags & CEPH_I_NODELAY) == 0 &&
	    time_before(jiffies, ci->i_hold_caps_min)) {
		dout(" delaying issued %s -> %s, wanted %s -> %s on send\n",
		     ceph_cap_string(cap->issued),
		     ceph_cap_string(cap->issued & retain),
		     ceph_cap_string(cap->mds_wanted),
		     ceph_cap_string(want));
		want |= cap->mds_wanted;
		retain |= cap->issued;
		delayed = 1;
	}
	ci->i_ceph_flags &= ~(CEPH_I_NODELAY | CEPH_I_FLUSH);

	cap->issued &= retain;  /* drop bits we don't want */
	if (cap->implemented & ~cap->issued) {
		/*
		 * Wake up any waiters on wanted -> needed transition.
		 * This is due to the weird transition from buffered
		 * to sync IO... we need to flush dirty pages _before_
		 * allowing sync writes to avoid reordering.
		 */
		wake = 1;
	}
	cap->implemented &= cap->issued | used;
	cap->mds_wanted = want;

	if (flushing) {
		/*
		 * assign a tid for flush operations so we can avoid
		 * flush1 -> dirty1 -> flush2 -> flushack1 -> mark
		 * clean type races.  track latest tid for every bit
		 * so we can handle flush AxFw, flush Fw, and have the
		 * first ack clean Ax.
		 */
		flush_tid = ++ci->i_cap_flush_last_tid;
		if (pflush_tid)
			*pflush_tid = flush_tid;
		dout(" cap_flush_tid %d\n", (int)flush_tid);
		for (i = 0; i < CEPH_CAP_BITS; i++)
			if (flushing & (1 << i))
				ci->i_cap_flush_tid[i] = flush_tid;

		follows = ci->i_head_snapc->seq;
	} else {
		follows = 0;
	}

	keep = cap->implemented;
	seq = cap->seq;
	issue_seq = cap->issue_seq;
	mseq = cap->mseq;
	size = inode->i_size;
	ci->i_reported_size = size;
	max_size = ci->i_wanted_max_size;
	ci->i_requested_max_size = max_size;
	mtime = inode->i_mtime;
	atime = inode->i_atime;
	time_warp_seq = ci->i_time_warp_seq;
	uid = inode->i_uid;
	gid = inode->i_gid;
	mode = inode->i_mode;

	if (flushing & CEPH_CAP_XATTR_EXCL) {
		__ceph_build_xattrs_blob(ci);
		xattr_blob = ci->i_xattrs.blob;
		xattr_version = ci->i_xattrs.version;
	}

	spin_unlock(&ci->i_ceph_lock);

	ret = send_cap_msg(session, ceph_vino(inode).ino, cap_id,
		op, keep, want, flushing, seq, flush_tid, issue_seq, mseq,
		size, max_size, &mtime, &atime, time_warp_seq,
		uid, gid, mode, xattr_version, xattr_blob,
		follows);
	if (ret < 0) {
		dout("error sending cap msg, must requeue %p\n", inode);
		delayed = 1;
	}

	if (wake)
		wake_up_all(&ci->i_cap_wq);

	return delayed;
}

/*
 * When a snapshot is taken, clients accumulate dirty metadata on
 * inodes with capabilities in ceph_cap_snaps to describe the file
 * state at the time the snapshot was taken.  This must be flushed
 * asynchronously back to the MDS once sync writes complete and dirty
 * data is written out.
 *
 * Unless @again is true, skip cap_snaps that were already sent to
 * the MDS (i.e., during this session).
 *
 * Called under i_ceph_lock.  Takes s_mutex as needed.
 */
void __ceph_flush_snaps(struct ceph_inode_info *ci,
			struct ceph_mds_session **psession,
			int again)
		__releases(ci->i_ceph_lock)
		__acquires(ci->i_ceph_lock)
{
	struct inode *inode = &ci->vfs_inode;
	int mds;
	struct ceph_cap_snap *capsnap;
	u32 mseq;
	struct ceph_mds_client *mdsc = ceph_inode_to_client(inode)->mdsc;
	struct ceph_mds_session *session = NULL; /* if session != NULL, we hold
						    session->s_mutex */
	u64 next_follows = 0;  /* keep track of how far we've gotten through the
			     i_cap_snaps list, and skip these entries next time
			     around to avoid an infinite loop */

	if (psession)
		session = *psession;

	dout("__flush_snaps %p\n", inode);
retry:
	list_for_each_entry(capsnap, &ci->i_cap_snaps, ci_item) {
		/* avoid an infiniute loop after retry */
		if (capsnap->follows < next_follows)
			continue;
		/*
		 * we need to wait for sync writes to complete and for dirty
		 * pages to be written out.
		 */
		if (capsnap->dirty_pages || capsnap->writing)
			break;

		/*
		 * if cap writeback already occurred, we should have dropped
		 * the capsnap in ceph_put_wrbuffer_cap_refs.
		 */
		BUG_ON(capsnap->dirty == 0);

		/* pick mds, take s_mutex */
		if (ci->i_auth_cap == NULL) {
			dout("no auth cap (migrating?), doing nothing\n");
			goto out;
		}

		/* only flush each capsnap once */
		if (!again && !list_empty(&capsnap->flushing_item)) {
			dout("already flushed %p, skipping\n", capsnap);
			continue;
		}

		mds = ci->i_auth_cap->session->s_mds;
		mseq = ci->i_auth_cap->mseq;

		if (session && session->s_mds != mds) {
			dout("oops, wrong session %p mutex\n", session);
			mutex_unlock(&session->s_mutex);
			ceph_put_mds_session(session);
			session = NULL;
		}
		if (!session) {
			spin_unlock(&ci->i_ceph_lock);
			mutex_lock(&mdsc->mutex);
			session = __ceph_lookup_mds_session(mdsc, mds);
			mutex_unlock(&mdsc->mutex);
			if (session) {
				dout("inverting session/ino locks on %p\n",
				     session);
				mutex_lock(&session->s_mutex);
			}
			/*
			 * if session == NULL, we raced against a cap
			 * deletion or migration.  retry, and we'll
			 * get a better @mds value next time.
			 */
			spin_lock(&ci->i_ceph_lock);
			goto retry;
		}

		capsnap->flush_tid = ++ci->i_cap_flush_last_tid;
		atomic_inc(&capsnap->nref);
		if (!list_empty(&capsnap->flushing_item))
			list_del_init(&capsnap->flushing_item);
		list_add_tail(&capsnap->flushing_item,
			      &session->s_cap_snaps_flushing);
		spin_unlock(&ci->i_ceph_lock);

		dout("flush_snaps %p cap_snap %p follows %lld tid %llu\n",
		     inode, capsnap, capsnap->follows, capsnap->flush_tid);
		send_cap_msg(session, ceph_vino(inode).ino, 0,
			     CEPH_CAP_OP_FLUSHSNAP, capsnap->issued, 0,
			     capsnap->dirty, 0, capsnap->flush_tid, 0, mseq,
			     capsnap->size, 0,
			     &capsnap->mtime, &capsnap->atime,
			     capsnap->time_warp_seq,
			     capsnap->uid, capsnap->gid, capsnap->mode,
			     capsnap->xattr_version, capsnap->xattr_blob,
			     capsnap->follows);

		next_follows = capsnap->follows + 1;
		ceph_put_cap_snap(capsnap);

		spin_lock(&ci->i_ceph_lock);
		goto retry;
	}

	/* we flushed them all; remove this inode from the queue */
	spin_lock(&mdsc->snap_flush_lock);
	list_del_init(&ci->i_snap_flush_item);
	spin_unlock(&mdsc->snap_flush_lock);

out:
	if (psession)
		*psession = session;
	else if (session) {
		mutex_unlock(&session->s_mutex);
		ceph_put_mds_session(session);
	}
}

static void ceph_flush_snaps(struct ceph_inode_info *ci)
{
	spin_lock(&ci->i_ceph_lock);
	__ceph_flush_snaps(ci, NULL, 0);
	spin_unlock(&ci->i_ceph_lock);
}

/*
 * Mark caps dirty.  If inode is newly dirty, return the dirty flags.
 * Caller is then responsible for calling __mark_inode_dirty with the
 * returned flags value.
 */
int __ceph_mark_dirty_caps(struct ceph_inode_info *ci, int mask)
{
	struct ceph_mds_client *mdsc =
		ceph_sb_to_client(ci->vfs_inode.i_sb)->mdsc;
	struct inode *inode = &ci->vfs_inode;
	int was = ci->i_dirty_caps;
	int dirty = 0;

	dout("__mark_dirty_caps %p %s dirty %s -> %s\n", &ci->vfs_inode,
	     ceph_cap_string(mask), ceph_cap_string(was),
	     ceph_cap_string(was | mask));
	ci->i_dirty_caps |= mask;
	if (was == 0) {
		if (!ci->i_head_snapc)
			ci->i_head_snapc = ceph_get_snap_context(
				ci->i_snap_realm->cached_context);
		dout(" inode %p now dirty snapc %p auth cap %p\n",
		     &ci->vfs_inode, ci->i_head_snapc, ci->i_auth_cap);
		WARN_ON(!ci->i_auth_cap);
		BUG_ON(!list_empty(&ci->i_dirty_item));
		spin_lock(&mdsc->cap_dirty_lock);
		list_add(&ci->i_dirty_item, &mdsc->cap_dirty);
		spin_unlock(&mdsc->cap_dirty_lock);
		if (ci->i_flushing_caps == 0) {
			ihold(inode);
			dirty |= I_DIRTY_SYNC;
		}
	}
	BUG_ON(list_empty(&ci->i_dirty_item));
	if (((was | ci->i_flushing_caps) & CEPH_CAP_FILE_BUFFER) &&
	    (mask & CEPH_CAP_FILE_BUFFER))
		dirty |= I_DIRTY_DATASYNC;
	__cap_delay_requeue(mdsc, ci);
	return dirty;
}

/*
 * Add dirty inode to the flushing list.  Assigned a seq number so we
 * can wait for caps to flush without starving.
 *
 * Called under i_ceph_lock.
 */
static int __mark_caps_flushing(struct inode *inode,
				 struct ceph_mds_session *session)
{
	struct ceph_mds_client *mdsc = ceph_sb_to_client(inode->i_sb)->mdsc;
	struct ceph_inode_info *ci = ceph_inode(inode);
	int flushing;

	BUG_ON(ci->i_dirty_caps == 0);
	BUG_ON(list_empty(&ci->i_dirty_item));

	flushing = ci->i_dirty_caps;
	dout("__mark_caps_flushing flushing %s, flushing_caps %s -> %s\n",
	     ceph_cap_string(flushing),
	     ceph_cap_string(ci->i_flushing_caps),
	     ceph_cap_string(ci->i_flushing_caps | flushing));
	ci->i_flushing_caps |= flushing;
	ci->i_dirty_caps = 0;
	dout(" inode %p now !dirty\n", inode);

	spin_lock(&mdsc->cap_dirty_lock);
	list_del_init(&ci->i_dirty_item);

	ci->i_cap_flush_seq = ++mdsc->cap_flush_seq;
	if (list_empty(&ci->i_flushing_item)) {
		list_add_tail(&ci->i_flushing_item, &session->s_cap_flushing);
		mdsc->num_cap_flushing++;
		dout(" inode %p now flushing seq %lld\n", inode,
		     ci->i_cap_flush_seq);
	} else {
		list_move_tail(&ci->i_flushing_item, &session->s_cap_flushing);
		dout(" inode %p now flushing (more) seq %lld\n", inode,
		     ci->i_cap_flush_seq);
	}
	spin_unlock(&mdsc->cap_dirty_lock);

	return flushing;
}

/*
 * try to invalidate mapping pages without blocking.
 */
static int try_nonblocking_invalidate(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	u32 invalidating_gen = ci->i_rdcache_gen;

	spin_unlock(&ci->i_ceph_lock);
	invalidate_mapping_pages(&inode->i_data, 0, -1);
	spin_lock(&ci->i_ceph_lock);

	if (inode->i_data.nrpages == 0 &&
	    invalidating_gen == ci->i_rdcache_gen) {
		/* success. */
		dout("try_nonblocking_invalidate %p success\n", inode);
		/* save any racing async invalidate some trouble */
		ci->i_rdcache_revoking = ci->i_rdcache_gen - 1;
		return 0;
	}
	dout("try_nonblocking_invalidate %p failed\n", inode);
	return -1;
}

/*
 * Swiss army knife function to examine currently used and wanted
 * versus held caps.  Release, flush, ack revoked caps to mds as
 * appropriate.
 *
 *  CHECK_CAPS_NODELAY - caller is delayed work and we should not delay
 *    cap release further.
 *  CHECK_CAPS_AUTHONLY - we should only check the auth cap
 *  CHECK_CAPS_FLUSH - we should flush any dirty caps immediately, without
 *    further delay.
 */
void ceph_check_caps(struct ceph_inode_info *ci, int flags,
		     struct ceph_mds_session *session)
{
	struct ceph_fs_client *fsc = ceph_inode_to_client(&ci->vfs_inode);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct inode *inode = &ci->vfs_inode;
	struct ceph_cap *cap;
	int file_wanted, used, cap_used;
	int took_snap_rwsem = 0;             /* true if mdsc->snap_rwsem held */
	int issued, implemented, want, retain, revoking, flushing = 0;
	int mds = -1;   /* keep track of how far we've gone through i_caps list
			   to avoid an infinite loop on retry */
	struct rb_node *p;
	int tried_invalidate = 0;
	int delayed = 0, sent = 0, force_requeue = 0, num;
	int queue_invalidate = 0;
	int is_delayed = flags & CHECK_CAPS_NODELAY;

	/* if we are unmounting, flush any unused caps immediately. */
	if (mdsc->stopping)
		is_delayed = 1;

	spin_lock(&ci->i_ceph_lock);

	if (ci->i_ceph_flags & CEPH_I_FLUSH)
		flags |= CHECK_CAPS_FLUSH;

	/* flush snaps first time around only */
	if (!list_empty(&ci->i_cap_snaps))
		__ceph_flush_snaps(ci, &session, 0);
	goto retry_locked;
retry:
	spin_lock(&ci->i_ceph_lock);
retry_locked:
	file_wanted = __ceph_caps_file_wanted(ci);
	used = __ceph_caps_used(ci);
	want = file_wanted | used;
	issued = __ceph_caps_issued(ci, &implemented);
	revoking = implemented & ~issued;

	retain = want | CEPH_CAP_PIN;
	if (!mdsc->stopping && inode->i_nlink > 0) {
		if (want) {
			retain |= CEPH_CAP_ANY;       /* be greedy */
		} else {
			retain |= CEPH_CAP_ANY_SHARED;
			/*
			 * keep RD only if we didn't have the file open RW,
			 * because then the mds would revoke it anyway to
			 * journal max_size=0.
			 */
			if (ci->i_max_size == 0)
				retain |= CEPH_CAP_ANY_RD;
		}
	}

	dout("check_caps %p file_want %s used %s dirty %s flushing %s"
	     " issued %s revoking %s retain %s %s%s%s\n", inode,
	     ceph_cap_string(file_wanted),
	     ceph_cap_string(used), ceph_cap_string(ci->i_dirty_caps),
	     ceph_cap_string(ci->i_flushing_caps),
	     ceph_cap_string(issued), ceph_cap_string(revoking),
	     ceph_cap_string(retain),
	     (flags & CHECK_CAPS_AUTHONLY) ? " AUTHONLY" : "",
	     (flags & CHECK_CAPS_NODELAY) ? " NODELAY" : "",
	     (flags & CHECK_CAPS_FLUSH) ? " FLUSH" : "");

	/*
	 * If we no longer need to hold onto old our caps, and we may
	 * have cached pages, but don't want them, then try to invalidate.
	 * If we fail, it's because pages are locked.... try again later.
	 */
	if ((!is_delayed || mdsc->stopping) &&
	    ci->i_wrbuffer_ref == 0 &&               /* no dirty pages... */
	    inode->i_data.nrpages &&                 /* have cached pages */
	    (file_wanted == 0 ||                     /* no open files */
	     (revoking & (CEPH_CAP_FILE_CACHE|
			  CEPH_CAP_FILE_LAZYIO))) && /*  or revoking cache */
	    !tried_invalidate) {
		dout("check_caps trying to invalidate on %p\n", inode);
		if (try_nonblocking_invalidate(inode) < 0) {
			if (revoking & (CEPH_CAP_FILE_CACHE|
					CEPH_CAP_FILE_LAZYIO)) {
				dout("check_caps queuing invalidate\n");
				queue_invalidate = 1;
				ci->i_rdcache_revoking = ci->i_rdcache_gen;
			} else {
				dout("check_caps failed to invalidate pages\n");
				/* we failed to invalidate pages.  check these
				   caps again later. */
				force_requeue = 1;
				__cap_set_timeouts(mdsc, ci);
			}
		}
		tried_invalidate = 1;
		goto retry_locked;
	}

	num = 0;
	for (p = rb_first(&ci->i_caps); p; p = rb_next(p)) {
		cap = rb_entry(p, struct ceph_cap, ci_node);
		num++;

		/* avoid looping forever */
		if (mds >= cap->mds ||
		    ((flags & CHECK_CAPS_AUTHONLY) && cap != ci->i_auth_cap))
			continue;

		/* NOTE: no side-effects allowed, until we take s_mutex */

		cap_used = used;
		if (ci->i_auth_cap && cap != ci->i_auth_cap)
			cap_used &= ~ci->i_auth_cap->issued;

		revoking = cap->implemented & ~cap->issued;
		dout(" mds%d cap %p used %s issued %s implemented %s revoking %s\n",
		     cap->mds, cap, ceph_cap_string(cap->issued),
		     ceph_cap_string(cap_used),
		     ceph_cap_string(cap->implemented),
		     ceph_cap_string(revoking));

		if (cap == ci->i_auth_cap &&
		    (cap->issued & CEPH_CAP_FILE_WR)) {
			/* request larger max_size from MDS? */
			if (ci->i_wanted_max_size > ci->i_max_size &&
			    ci->i_wanted_max_size > ci->i_requested_max_size) {
				dout("requesting new max_size\n");
				goto ack;
			}

			/* approaching file_max? */
			if ((inode->i_size << 1) >= ci->i_max_size &&
			    (ci->i_reported_size << 1) < ci->i_max_size) {
				dout("i_size approaching max_size\n");
				goto ack;
			}
		}
		/* flush anything dirty? */
		if (cap == ci->i_auth_cap && (flags & CHECK_CAPS_FLUSH) &&
		    ci->i_dirty_caps) {
			dout("flushing dirty caps\n");
			goto ack;
		}

		/* completed revocation? going down and there are no caps? */
		if (revoking && (revoking & cap_used) == 0) {
			dout("completed revocation of %s\n",
			     ceph_cap_string(cap->implemented & ~cap->issued));
			goto ack;
		}

		/* want more caps from mds? */
		if (want & ~(cap->mds_wanted | cap->issued))
			goto ack;

		/* things we might delay */
		if ((cap->issued & ~retain) == 0 &&
		    cap->mds_wanted == want)
			continue;     /* nope, all good */

		if (is_delayed)
			goto ack;

		/* delay? */
		if ((ci->i_ceph_flags & CEPH_I_NODELAY) == 0 &&
		    time_before(jiffies, ci->i_hold_caps_max)) {
			dout(" delaying issued %s -> %s, wanted %s -> %s\n",
			     ceph_cap_string(cap->issued),
			     ceph_cap_string(cap->issued & retain),
			     ceph_cap_string(cap->mds_wanted),
			     ceph_cap_string(want));
			delayed++;
			continue;
		}

ack:
		if (ci->i_ceph_flags & CEPH_I_NOFLUSH) {
			dout(" skipping %p I_NOFLUSH set\n", inode);
			continue;
		}

		if (session && session != cap->session) {
			dout("oops, wrong session %p mutex\n", session);
			mutex_unlock(&session->s_mutex);
			session = NULL;
		}
		if (!session) {
			session = cap->session;
			if (mutex_trylock(&session->s_mutex) == 0) {
				dout("inverting session/ino locks on %p\n",
				     session);
				spin_unlock(&ci->i_ceph_lock);
				if (took_snap_rwsem) {
					up_read(&mdsc->snap_rwsem);
					took_snap_rwsem = 0;
				}
				mutex_lock(&session->s_mutex);
				goto retry;
			}
		}
		/* take snap_rwsem after session mutex */
		if (!took_snap_rwsem) {
			if (down_read_trylock(&mdsc->snap_rwsem) == 0) {
				dout("inverting snap/in locks on %p\n",
				     inode);
				spin_unlock(&ci->i_ceph_lock);
				down_read(&mdsc->snap_rwsem);
				took_snap_rwsem = 1;
				goto retry;
			}
			took_snap_rwsem = 1;
		}

		if (cap == ci->i_auth_cap && ci->i_dirty_caps)
			flushing = __mark_caps_flushing(inode, session);
		else
			flushing = 0;

		mds = cap->mds;  /* remember mds, so we don't repeat */
		sent++;

		/* __send_cap drops i_ceph_lock */
		delayed += __send_cap(mdsc, cap, CEPH_CAP_OP_UPDATE, cap_used,
				      want, retain, flushing, NULL);
		goto retry; /* retake i_ceph_lock and restart our cap scan. */
	}

	/*
	 * Reschedule delayed caps release if we delayed anything,
	 * otherwise cancel.
	 */
	if (delayed && is_delayed)
		force_requeue = 1;   /* __send_cap delayed release; requeue */
	if (!delayed && !is_delayed)
		__cap_delay_cancel(mdsc, ci);
	else if (!is_delayed || force_requeue)
		__cap_delay_requeue(mdsc, ci);

	spin_unlock(&ci->i_ceph_lock);

	if (queue_invalidate)
		ceph_queue_invalidate(inode);

	if (session)
		mutex_unlock(&session->s_mutex);
	if (took_snap_rwsem)
		up_read(&mdsc->snap_rwsem);
}

/*
 * Try to flush dirty caps back to the auth mds.
 */
static int try_flush_caps(struct inode *inode, unsigned *flush_tid)
{
	struct ceph_mds_client *mdsc = ceph_sb_to_client(inode->i_sb)->mdsc;
	struct ceph_inode_info *ci = ceph_inode(inode);
	int flushing = 0;
	struct ceph_mds_session *session = NULL;

retry:
	spin_lock(&ci->i_ceph_lock);
	if (ci->i_ceph_flags & CEPH_I_NOFLUSH) {
		dout("try_flush_caps skipping %p I_NOFLUSH set\n", inode);
		goto out;
	}
	if (ci->i_dirty_caps && ci->i_auth_cap) {
		struct ceph_cap *cap = ci->i_auth_cap;
		int used = __ceph_caps_used(ci);
		int want = __ceph_caps_wanted(ci);
		int delayed;

		if (!session || session != cap->session) {
			spin_unlock(&ci->i_ceph_lock);
			if (session)
				mutex_unlock(&session->s_mutex);
			session = cap->session;
			mutex_lock(&session->s_mutex);
			goto retry;
		}
		if (cap->session->s_state < CEPH_MDS_SESSION_OPEN)
			goto out;

		flushing = __mark_caps_flushing(inode, session);

		/* __send_cap drops i_ceph_lock */
		delayed = __send_cap(mdsc, cap, CEPH_CAP_OP_FLUSH, used, want,
				     cap->issued | cap->implemented, flushing,
				     flush_tid);
		if (!delayed)
			goto out_unlocked;

		spin_lock(&ci->i_ceph_lock);
		__cap_delay_requeue(mdsc, ci);
	}
out:
	spin_unlock(&ci->i_ceph_lock);
out_unlocked:
	if (session)
		mutex_unlock(&session->s_mutex);
	return flushing;
}

/*
 * Return true if we've flushed caps through the given flush_tid.
 */
static int caps_are_flushed(struct inode *inode, unsigned tid)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int i, ret = 1;

	spin_lock(&ci->i_ceph_lock);
	for (i = 0; i < CEPH_CAP_BITS; i++)
		if ((ci->i_flushing_caps & (1 << i)) &&
		    ci->i_cap_flush_tid[i] <= tid) {
			/* still flushing this bit */
			ret = 0;
			break;
		}
	spin_unlock(&ci->i_ceph_lock);
	return ret;
}

/*
 * Wait on any unsafe replies for the given inode.  First wait on the
 * newest request, and make that the upper bound.  Then, if there are
 * more requests, keep waiting on the oldest as long as it is still older
 * than the original request.
 */
static void sync_write_wait(struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct list_head *head = &ci->i_unsafe_writes;
	struct ceph_osd_request *req;
	u64 last_tid;

	spin_lock(&ci->i_unsafe_lock);
	if (list_empty(head))
		goto out;

	/* set upper bound as _last_ entry in chain */
	req = list_entry(head->prev, struct ceph_osd_request,
			 r_unsafe_item);
	last_tid = req->r_tid;

	do {
		ceph_osdc_get_request(req);
		spin_unlock(&ci->i_unsafe_lock);
		dout("sync_write_wait on tid %llu (until %llu)\n",
		     req->r_tid, last_tid);
		wait_for_completion(&req->r_safe_completion);
		spin_lock(&ci->i_unsafe_lock);
		ceph_osdc_put_request(req);

		/*
		 * from here on look at first entry in chain, since we
		 * only want to wait for anything older than last_tid
		 */
		if (list_empty(head))
			break;
		req = list_entry(head->next, struct ceph_osd_request,
				 r_unsafe_item);
	} while (req->r_tid < last_tid);
out:
	spin_unlock(&ci->i_unsafe_lock);
}

int ceph_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = file->f_mapping->host;
	struct ceph_inode_info *ci = ceph_inode(inode);
	unsigned flush_tid;
	int ret;
	int dirty;

	dout("fsync %p%s\n", inode, datasync ? " datasync" : "");
	sync_write_wait(inode);

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret < 0)
		return ret;
	mutex_lock(&inode->i_mutex);

	dirty = try_flush_caps(inode, &flush_tid);
	dout("fsync dirty caps are %s\n", ceph_cap_string(dirty));

	/*
	 * only wait on non-file metadata writeback (the mds
	 * can recover size and mtime, so we don't need to
	 * wait for that)
	 */
	if (!datasync && (dirty & ~CEPH_CAP_ANY_FILE_WR)) {
		dout("fsync waiting for flush_tid %u\n", flush_tid);
		ret = wait_event_interruptible(ci->i_cap_wq,
				       caps_are_flushed(inode, flush_tid));
	}

	dout("fsync %p%s done\n", inode, datasync ? " datasync" : "");
	mutex_unlock(&inode->i_mutex);
	return ret;
}

/*
 * Flush any dirty caps back to the mds.  If we aren't asked to wait,
 * queue inode for flush but don't do so immediately, because we can
 * get by with fewer MDS messages if we wait for data writeback to
 * complete first.
 */
int ceph_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	unsigned flush_tid;
	int err = 0;
	int dirty;
	int wait = wbc->sync_mode == WB_SYNC_ALL;

	dout("write_inode %p wait=%d\n", inode, wait);
	if (wait) {
		dirty = try_flush_caps(inode, &flush_tid);
		if (dirty)
			err = wait_event_interruptible(ci->i_cap_wq,
				       caps_are_flushed(inode, flush_tid));
	} else {
		struct ceph_mds_client *mdsc =
			ceph_sb_to_client(inode->i_sb)->mdsc;

		spin_lock(&ci->i_ceph_lock);
		if (__ceph_caps_dirty(ci))
			__cap_delay_requeue_front(mdsc, ci);
		spin_unlock(&ci->i_ceph_lock);
	}
	return err;
}

/*
 * After a recovering MDS goes active, we need to resend any caps
 * we were flushing.
 *
 * Caller holds session->s_mutex.
 */
static void kick_flushing_capsnaps(struct ceph_mds_client *mdsc,
				   struct ceph_mds_session *session)
{
	struct ceph_cap_snap *capsnap;

	dout("kick_flushing_capsnaps mds%d\n", session->s_mds);
	list_for_each_entry(capsnap, &session->s_cap_snaps_flushing,
			    flushing_item) {
		struct ceph_inode_info *ci = capsnap->ci;
		struct inode *inode = &ci->vfs_inode;
		struct ceph_cap *cap;

		spin_lock(&ci->i_ceph_lock);
		cap = ci->i_auth_cap;
		if (cap && cap->session == session) {
			dout("kick_flushing_caps %p cap %p capsnap %p\n", inode,
			     cap, capsnap);
			__ceph_flush_snaps(ci, &session, 1);
		} else {
			pr_err("%p auth cap %p not mds%d ???\n", inode,
			       cap, session->s_mds);
		}
		spin_unlock(&ci->i_ceph_lock);
	}
}

void ceph_kick_flushing_caps(struct ceph_mds_client *mdsc,
			     struct ceph_mds_session *session)
{
	struct ceph_inode_info *ci;

	kick_flushing_capsnaps(mdsc, session);

	dout("kick_flushing_caps mds%d\n", session->s_mds);
	list_for_each_entry(ci, &session->s_cap_flushing, i_flushing_item) {
		struct inode *inode = &ci->vfs_inode;
		struct ceph_cap *cap;
		int delayed = 0;

		spin_lock(&ci->i_ceph_lock);
		cap = ci->i_auth_cap;
		if (cap && cap->session == session) {
			dout("kick_flushing_caps %p cap %p %s\n", inode,
			     cap, ceph_cap_string(ci->i_flushing_caps));
			delayed = __send_cap(mdsc, cap, CEPH_CAP_OP_FLUSH,
					     __ceph_caps_used(ci),
					     __ceph_caps_wanted(ci),
					     cap->issued | cap->implemented,
					     ci->i_flushing_caps, NULL);
			if (delayed) {
				spin_lock(&ci->i_ceph_lock);
				__cap_delay_requeue(mdsc, ci);
				spin_unlock(&ci->i_ceph_lock);
			}
		} else {
			pr_err("%p auth cap %p not mds%d ???\n", inode,
			       cap, session->s_mds);
			spin_unlock(&ci->i_ceph_lock);
		}
	}
}

static void kick_flushing_inode_caps(struct ceph_mds_client *mdsc,
				     struct ceph_mds_session *session,
				     struct inode *inode)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_cap *cap;
	int delayed = 0;

	spin_lock(&ci->i_ceph_lock);
	cap = ci->i_auth_cap;
	dout("kick_flushing_inode_caps %p flushing %s flush_seq %lld\n", inode,
	     ceph_cap_string(ci->i_flushing_caps), ci->i_cap_flush_seq);

	__ceph_flush_snaps(ci, &session, 1);

	if (ci->i_flushing_caps) {
		spin_lock(&mdsc->cap_dirty_lock);
		list_move_tail(&ci->i_flushing_item,
			       &cap->session->s_cap_flushing);
		spin_unlock(&mdsc->cap_dirty_lock);

		delayed = __send_cap(mdsc, cap, CEPH_CAP_OP_FLUSH,
				     __ceph_caps_used(ci),
				     __ceph_caps_wanted(ci),
				     cap->issued | cap->implemented,
				     ci->i_flushing_caps, NULL);
		if (delayed) {
			spin_lock(&ci->i_ceph_lock);
			__cap_delay_requeue(mdsc, ci);
			spin_unlock(&ci->i_ceph_lock);
		}
	} else {
		spin_unlock(&ci->i_ceph_lock);
	}
}


/*
 * Take references to capabilities we hold, so that we don't release
 * them to the MDS prematurely.
 *
 * Protected by i_ceph_lock.
 */
static void __take_cap_refs(struct ceph_inode_info *ci, int got)
{
	if (got & CEPH_CAP_PIN)
		ci->i_pin_ref++;
	if (got & CEPH_CAP_FILE_RD)
		ci->i_rd_ref++;
	if (got & CEPH_CAP_FILE_CACHE)
		ci->i_rdcache_ref++;
	if (got & CEPH_CAP_FILE_WR)
		ci->i_wr_ref++;
	if (got & CEPH_CAP_FILE_BUFFER) {
		if (ci->i_wb_ref == 0)
			ihold(&ci->vfs_inode);
		ci->i_wb_ref++;
		dout("__take_cap_refs %p wb %d -> %d (?)\n",
		     &ci->vfs_inode, ci->i_wb_ref-1, ci->i_wb_ref);
	}
}

/*
 * Try to grab cap references.  Specify those refs we @want, and the
 * minimal set we @need.  Also include the larger offset we are writing
 * to (when applicable), and check against max_size here as well.
 * Note that caller is responsible for ensuring max_size increases are
 * requested from the MDS.
 */
static int try_get_cap_refs(struct ceph_inode_info *ci, int need, int want,
			    int *got, loff_t endoff, int *check_max, int *err)
{
	struct inode *inode = &ci->vfs_inode;
	int ret = 0;
	int have, implemented;
	int file_wanted;

	dout("get_cap_refs %p need %s want %s\n", inode,
	     ceph_cap_string(need), ceph_cap_string(want));
	spin_lock(&ci->i_ceph_lock);

	/* make sure file is actually open */
	file_wanted = __ceph_caps_file_wanted(ci);
	if ((file_wanted & need) == 0) {
		dout("try_get_cap_refs need %s file_wanted %s, EBADF\n",
		     ceph_cap_string(need), ceph_cap_string(file_wanted));
		*err = -EBADF;
		ret = 1;
		goto out;
	}

	/* finish pending truncate */
	while (ci->i_truncate_pending) {
		spin_unlock(&ci->i_ceph_lock);
		__ceph_do_pending_vmtruncate(inode);
		spin_lock(&ci->i_ceph_lock);
	}

	have = __ceph_caps_issued(ci, &implemented);

	if (have & need & CEPH_CAP_FILE_WR) {
		if (endoff >= 0 && endoff > (loff_t)ci->i_max_size) {
			dout("get_cap_refs %p endoff %llu > maxsize %llu\n",
			     inode, endoff, ci->i_max_size);
			if (endoff > ci->i_requested_max_size) {
				*check_max = 1;
				ret = 1;
			}
			goto out;
		}
		/*
		 * If a sync write is in progress, we must wait, so that we
		 * can get a final snapshot value for size+mtime.
		 */
		if (__ceph_have_pending_cap_snap(ci)) {
			dout("get_cap_refs %p cap_snap_pending\n", inode);
			goto out;
		}
	}

	if ((have & need) == need) {
		/*
		 * Look at (implemented & ~have & not) so that we keep waiting
		 * on transition from wanted -> needed caps.  This is needed
		 * for WRBUFFER|WR -> WR to avoid a new WR sync write from
		 * going before a prior buffered writeback happens.
		 */
		int not = want & ~(have & need);
		int revoking = implemented & ~have;
		dout("get_cap_refs %p have %s but not %s (revoking %s)\n",
		     inode, ceph_cap_string(have), ceph_cap_string(not),
		     ceph_cap_string(revoking));
		if ((revoking & not) == 0) {
			*got = need | (have & want);
			__take_cap_refs(ci, *got);
			ret = 1;
		}
	} else {
		dout("get_cap_refs %p have %s needed %s\n", inode,
		     ceph_cap_string(have), ceph_cap_string(need));
	}
out:
	spin_unlock(&ci->i_ceph_lock);
	dout("get_cap_refs %p ret %d got %s\n", inode,
	     ret, ceph_cap_string(*got));
	return ret;
}

/*
 * Check the offset we are writing up to against our current
 * max_size.  If necessary, tell the MDS we want to write to
 * a larger offset.
 */
static void check_max_size(struct inode *inode, loff_t endoff)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int check = 0;

	/* do we need to explicitly request a larger max_size? */
	spin_lock(&ci->i_ceph_lock);
	if (endoff >= ci->i_max_size && endoff > ci->i_wanted_max_size) {
		dout("write %p at large endoff %llu, req max_size\n",
		     inode, endoff);
		ci->i_wanted_max_size = endoff;
	}
	/* duplicate ceph_check_caps()'s logic */
	if (ci->i_auth_cap &&
	    (ci->i_auth_cap->issued & CEPH_CAP_FILE_WR) &&
	    ci->i_wanted_max_size > ci->i_max_size &&
	    ci->i_wanted_max_size > ci->i_requested_max_size)
		check = 1;
	spin_unlock(&ci->i_ceph_lock);
	if (check)
		ceph_check_caps(ci, CHECK_CAPS_AUTHONLY, NULL);
}

/*
 * Wait for caps, and take cap references.  If we can't get a WR cap
 * due to a small max_size, make sure we check_max_size (and possibly
 * ask the mds) so we don't get hung up indefinitely.
 */
int ceph_get_caps(struct ceph_inode_info *ci, int need, int want, int *got,
		  loff_t endoff)
{
	int check_max, ret, err;

retry:
	if (endoff > 0)
		check_max_size(&ci->vfs_inode, endoff);
	check_max = 0;
	err = 0;
	ret = wait_event_interruptible(ci->i_cap_wq,
				       try_get_cap_refs(ci, need, want,
							got, endoff,
							&check_max, &err));
	if (err)
		ret = err;
	if (check_max)
		goto retry;
	return ret;
}

/*
 * Take cap refs.  Caller must already know we hold at least one ref
 * on the caps in question or we don't know this is safe.
 */
void ceph_get_cap_refs(struct ceph_inode_info *ci, int caps)
{
	spin_lock(&ci->i_ceph_lock);
	__take_cap_refs(ci, caps);
	spin_unlock(&ci->i_ceph_lock);
}

/*
 * Release cap refs.
 *
 * If we released the last ref on any given cap, call ceph_check_caps
 * to release (or schedule a release).
 *
 * If we are releasing a WR cap (from a sync write), finalize any affected
 * cap_snap, and wake up any waiters.
 */
void ceph_put_cap_refs(struct ceph_inode_info *ci, int had)
{
	struct inode *inode = &ci->vfs_inode;
	int last = 0, put = 0, flushsnaps = 0, wake = 0;
	struct ceph_cap_snap *capsnap;

	spin_lock(&ci->i_ceph_lock);
	if (had & CEPH_CAP_PIN)
		--ci->i_pin_ref;
	if (had & CEPH_CAP_FILE_RD)
		if (--ci->i_rd_ref == 0)
			last++;
	if (had & CEPH_CAP_FILE_CACHE)
		if (--ci->i_rdcache_ref == 0)
			last++;
	if (had & CEPH_CAP_FILE_BUFFER) {
		if (--ci->i_wb_ref == 0) {
			last++;
			put++;
		}
		dout("put_cap_refs %p wb %d -> %d (?)\n",
		     inode, ci->i_wb_ref+1, ci->i_wb_ref);
	}
	if (had & CEPH_CAP_FILE_WR)
		if (--ci->i_wr_ref == 0) {
			last++;
			if (!list_empty(&ci->i_cap_snaps)) {
				capsnap = list_first_entry(&ci->i_cap_snaps,
						     struct ceph_cap_snap,
						     ci_item);
				if (capsnap->writing) {
					capsnap->writing = 0;
					flushsnaps =
						__ceph_finish_cap_snap(ci,
								       capsnap);
					wake = 1;
				}
			}
		}
	spin_unlock(&ci->i_ceph_lock);

	dout("put_cap_refs %p had %s%s%s\n", inode, ceph_cap_string(had),
	     last ? " last" : "", put ? " put" : "");

	if (last && !flushsnaps)
		ceph_check_caps(ci, 0, NULL);
	else if (flushsnaps)
		ceph_flush_snaps(ci);
	if (wake)
		wake_up_all(&ci->i_cap_wq);
	if (put)
		iput(inode);
}

/*
 * Release @nr WRBUFFER refs on dirty pages for the given @snapc snap
 * context.  Adjust per-snap dirty page accounting as appropriate.
 * Once all dirty data for a cap_snap is flushed, flush snapped file
 * metadata back to the MDS.  If we dropped the last ref, call
 * ceph_check_caps.
 */
void ceph_put_wrbuffer_cap_refs(struct ceph_inode_info *ci, int nr,
				struct ceph_snap_context *snapc)
{
	struct inode *inode = &ci->vfs_inode;
	int last = 0;
	int complete_capsnap = 0;
	int drop_capsnap = 0;
	int found = 0;
	struct ceph_cap_snap *capsnap = NULL;

	spin_lock(&ci->i_ceph_lock);
	ci->i_wrbuffer_ref -= nr;
	last = !ci->i_wrbuffer_ref;

	if (ci->i_head_snapc == snapc) {
		ci->i_wrbuffer_ref_head -= nr;
		if (ci->i_wrbuffer_ref_head == 0 &&
		    ci->i_dirty_caps == 0 && ci->i_flushing_caps == 0) {
			BUG_ON(!ci->i_head_snapc);
			ceph_put_snap_context(ci->i_head_snapc);
			ci->i_head_snapc = NULL;
		}
		dout("put_wrbuffer_cap_refs on %p head %d/%d -> %d/%d %s\n",
		     inode,
		     ci->i_wrbuffer_ref+nr, ci->i_wrbuffer_ref_head+nr,
		     ci->i_wrbuffer_ref, ci->i_wrbuffer_ref_head,
		     last ? " LAST" : "");
	} else {
		list_for_each_entry(capsnap, &ci->i_cap_snaps, ci_item) {
			if (capsnap->context == snapc) {
				found = 1;
				break;
			}
		}
		BUG_ON(!found);
		capsnap->dirty_pages -= nr;
		if (capsnap->dirty_pages == 0) {
			complete_capsnap = 1;
			if (capsnap->dirty == 0)
				/* cap writeback completed before we created
				 * the cap_snap; no FLUSHSNAP is needed */
				drop_capsnap = 1;
		}
		dout("put_wrbuffer_cap_refs on %p cap_snap %p "
		     " snap %lld %d/%d -> %d/%d %s%s%s\n",
		     inode, capsnap, capsnap->context->seq,
		     ci->i_wrbuffer_ref+nr, capsnap->dirty_pages + nr,
		     ci->i_wrbuffer_ref, capsnap->dirty_pages,
		     last ? " (wrbuffer last)" : "",
		     complete_capsnap ? " (complete capsnap)" : "",
		     drop_capsnap ? " (drop capsnap)" : "");
		if (drop_capsnap) {
			ceph_put_snap_context(capsnap->context);
			list_del(&capsnap->ci_item);
			list_del(&capsnap->flushing_item);
			ceph_put_cap_snap(capsnap);
		}
	}

	spin_unlock(&ci->i_ceph_lock);

	if (last) {
		ceph_check_caps(ci, CHECK_CAPS_AUTHONLY, NULL);
		iput(inode);
	} else if (complete_capsnap) {
		ceph_flush_snaps(ci);
		wake_up_all(&ci->i_cap_wq);
	}
	if (drop_capsnap)
		iput(inode);
}

/*
 * Invalidate unlinked inode's aliases, so we can drop the inode ASAP.
 */
static void invalidate_aliases(struct inode *inode)
{
	struct dentry *dn, *prev = NULL;

	dout("invalidate_aliases inode %p\n", inode);
	d_prune_aliases(inode);
	/*
	 * For non-directory inode, d_find_alias() only returns
	 * hashed dentry. After calling d_invalidate(), the
	 * dentry becomes unhashed.
	 *
	 * For directory inode, d_find_alias() can return
	 * unhashed dentry. But directory inode should have
	 * one alias at most.
	 */
	while ((dn = d_find_alias(inode))) {
		if (dn == prev) {
			dput(dn);
			break;
		}
		d_invalidate(dn);
		if (prev)
			dput(prev);
		prev = dn;
	}
	if (prev)
		dput(prev);
}

/*
 * Handle a cap GRANT message from the MDS.  (Note that a GRANT may
 * actually be a revocation if it specifies a smaller cap set.)
 *
 * caller holds s_mutex and i_ceph_lock, we drop both.
 */
static void handle_cap_grant(struct ceph_mds_client *mdsc,
			     struct inode *inode, struct ceph_mds_caps *grant,
			     void *snaptrace, int snaptrace_len,
			     struct ceph_buffer *xattr_buf,
			     struct ceph_mds_session *session,
			     struct ceph_cap *cap, int issued)
	__releases(ci->i_ceph_lock)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int mds = session->s_mds;
	int seq = le32_to_cpu(grant->seq);
	int newcaps = le32_to_cpu(grant->caps);
	int used, wanted, dirty;
	u64 size = le64_to_cpu(grant->size);
	u64 max_size = le64_to_cpu(grant->max_size);
	struct timespec mtime, atime, ctime;
	int check_caps = 0;
	bool wake = 0;
	bool writeback = 0;
	bool queue_trunc = 0;
	bool queue_invalidate = 0;
	bool queue_revalidate = 0;
	bool deleted_inode = 0;

	dout("handle_cap_grant inode %p cap %p mds%d seq %d %s\n",
	     inode, cap, mds, seq, ceph_cap_string(newcaps));
	dout(" size %llu max_size %llu, i_size %llu\n", size, max_size,
		inode->i_size);


	/*
	 * auth mds of the inode changed. we received the cap export message,
	 * but still haven't received the cap import message. handle_cap_export
	 * updated the new auth MDS' cap.
	 *
	 * "ceph_seq_cmp(seq, cap->seq) <= 0" means we are processing a message
	 * that was sent before the cap import message. So don't remove caps.
	 */
	if (ceph_seq_cmp(seq, cap->seq) <= 0) {
		WARN_ON(cap != ci->i_auth_cap);
		WARN_ON(cap->cap_id != le64_to_cpu(grant->cap_id));
		seq = cap->seq;
		newcaps |= cap->issued;
	}

	/*
	 * If CACHE is being revoked, and we have no dirty buffers,
	 * try to invalidate (once).  (If there are dirty buffers, we
	 * will invalidate _after_ writeback.)
	 */
	if (((cap->issued & ~newcaps) & CEPH_CAP_FILE_CACHE) &&
	    (newcaps & CEPH_CAP_FILE_LAZYIO) == 0 &&
	    !ci->i_wrbuffer_ref) {
		if (try_nonblocking_invalidate(inode)) {
			/* there were locked pages.. invalidate later
			   in a separate thread. */
			if (ci->i_rdcache_revoking != ci->i_rdcache_gen) {
				queue_invalidate = 1;
				ci->i_rdcache_revoking = ci->i_rdcache_gen;
			}
		}

		ceph_fscache_invalidate(inode);
	}

	/* side effects now are allowed */
	cap->cap_gen = session->s_cap_gen;
	cap->seq = seq;

	__check_cap_issue(ci, cap, newcaps);

	if ((newcaps & CEPH_CAP_AUTH_SHARED) &&
	    (issued & CEPH_CAP_AUTH_EXCL) == 0) {
		inode->i_mode = le32_to_cpu(grant->mode);
		inode->i_uid = make_kuid(&init_user_ns, le32_to_cpu(grant->uid));
		inode->i_gid = make_kgid(&init_user_ns, le32_to_cpu(grant->gid));
		dout("%p mode 0%o uid.gid %d.%d\n", inode, inode->i_mode,
		     from_kuid(&init_user_ns, inode->i_uid),
		     from_kgid(&init_user_ns, inode->i_gid));
	}

	if ((newcaps & CEPH_CAP_AUTH_SHARED) &&
	    (issued & CEPH_CAP_LINK_EXCL) == 0) {
		set_nlink(inode, le32_to_cpu(grant->nlink));
		if (inode->i_nlink == 0 &&
		    (newcaps & (CEPH_CAP_LINK_SHARED | CEPH_CAP_LINK_EXCL)))
			deleted_inode = 1;
	}

	if ((issued & CEPH_CAP_XATTR_EXCL) == 0 && grant->xattr_len) {
		int len = le32_to_cpu(grant->xattr_len);
		u64 version = le64_to_cpu(grant->xattr_version);

		if (version > ci->i_xattrs.version) {
			dout(" got new xattrs v%llu on %p len %d\n",
			     version, inode, len);
			if (ci->i_xattrs.blob)
				ceph_buffer_put(ci->i_xattrs.blob);
			ci->i_xattrs.blob = ceph_buffer_get(xattr_buf);
			ci->i_xattrs.version = version;
			ceph_forget_all_cached_acls(inode);
		}
	}

	/* Do we need to revalidate our fscache cookie. Don't bother on the
	 * first cache cap as we already validate at cookie creation time. */
	if ((issued & CEPH_CAP_FILE_CACHE) && ci->i_rdcache_gen > 1)
		queue_revalidate = 1;

	if (newcaps & CEPH_CAP_ANY_RD) {
		/* ctime/mtime/atime? */
		ceph_decode_timespec(&mtime, &grant->mtime);
		ceph_decode_timespec(&atime, &grant->atime);
		ceph_decode_timespec(&ctime, &grant->ctime);
		ceph_fill_file_time(inode, issued,
				    le32_to_cpu(grant->time_warp_seq),
				    &ctime, &mtime, &atime);
	}

	if (newcaps & (CEPH_CAP_ANY_FILE_RD | CEPH_CAP_ANY_FILE_WR)) {
		/* file layout may have changed */
		ci->i_layout = grant->layout;
		/* size/truncate_seq? */
		queue_trunc = ceph_fill_file_size(inode, issued,
					le32_to_cpu(grant->truncate_seq),
					le64_to_cpu(grant->truncate_size),
					size);
		/* max size increase? */
		if (ci->i_auth_cap == cap && max_size != ci->i_max_size) {
			dout("max_size %lld -> %llu\n",
			     ci->i_max_size, max_size);
			ci->i_max_size = max_size;
			if (max_size >= ci->i_wanted_max_size) {
				ci->i_wanted_max_size = 0;  /* reset */
				ci->i_requested_max_size = 0;
			}
			wake = 1;
		}
	}

	/* check cap bits */
	wanted = __ceph_caps_wanted(ci);
	used = __ceph_caps_used(ci);
	dirty = __ceph_caps_dirty(ci);
	dout(" my wanted = %s, used = %s, dirty %s\n",
	     ceph_cap_string(wanted),
	     ceph_cap_string(used),
	     ceph_cap_string(dirty));
	if (wanted != le32_to_cpu(grant->wanted)) {
		dout("mds wanted %s -> %s\n",
		     ceph_cap_string(le32_to_cpu(grant->wanted)),
		     ceph_cap_string(wanted));
		/* imported cap may not have correct mds_wanted */
		if (le32_to_cpu(grant->op) == CEPH_CAP_OP_IMPORT)
			check_caps = 1;
	}

	/* revocation, grant, or no-op? */
	if (cap->issued & ~newcaps) {
		int revoking = cap->issued & ~newcaps;

		dout("revocation: %s -> %s (revoking %s)\n",
		     ceph_cap_string(cap->issued),
		     ceph_cap_string(newcaps),
		     ceph_cap_string(revoking));
		if (revoking & used & CEPH_CAP_FILE_BUFFER)
			writeback = 1;  /* initiate writeback; will delay ack */
		else if (revoking == CEPH_CAP_FILE_CACHE &&
			 (newcaps & CEPH_CAP_FILE_LAZYIO) == 0 &&
			 queue_invalidate)
			; /* do nothing yet, invalidation will be queued */
		else if (cap == ci->i_auth_cap)
			check_caps = 1; /* check auth cap only */
		else
			check_caps = 2; /* check all caps */
		cap->issued = newcaps;
		cap->implemented |= newcaps;
	} else if (cap->issued == newcaps) {
		dout("caps unchanged: %s -> %s\n",
		     ceph_cap_string(cap->issued), ceph_cap_string(newcaps));
	} else {
		dout("grant: %s -> %s\n", ceph_cap_string(cap->issued),
		     ceph_cap_string(newcaps));
		/* non-auth MDS is revoking the newly grant caps ? */
		if (cap == ci->i_auth_cap &&
		    __ceph_caps_revoking_other(ci, cap, newcaps))
		    check_caps = 2;

		cap->issued = newcaps;
		cap->implemented |= newcaps; /* add bits only, to
					      * avoid stepping on a
					      * pending revocation */
		wake = 1;
	}
	BUG_ON(cap->issued & ~cap->implemented);

	spin_unlock(&ci->i_ceph_lock);

	if (le32_to_cpu(grant->op) == CEPH_CAP_OP_IMPORT) {
		down_write(&mdsc->snap_rwsem);
		ceph_update_snap_trace(mdsc, snaptrace,
				       snaptrace + snaptrace_len, false);
		downgrade_write(&mdsc->snap_rwsem);
		kick_flushing_inode_caps(mdsc, session, inode);
		up_read(&mdsc->snap_rwsem);
		if (newcaps & ~issued)
			wake = 1;
	}

	if (queue_trunc) {
		ceph_queue_vmtruncate(inode);
		ceph_queue_revalidate(inode);
	} else if (queue_revalidate)
		ceph_queue_revalidate(inode);

	if (writeback)
		/*
		 * queue inode for writeback: we can't actually call
		 * filemap_write_and_wait, etc. from message handler
		 * context.
		 */
		ceph_queue_writeback(inode);
	if (queue_invalidate)
		ceph_queue_invalidate(inode);
	if (deleted_inode)
		invalidate_aliases(inode);
	if (wake)
		wake_up_all(&ci->i_cap_wq);

	if (check_caps == 1)
		ceph_check_caps(ci, CHECK_CAPS_NODELAY|CHECK_CAPS_AUTHONLY,
				session);
	else if (check_caps == 2)
		ceph_check_caps(ci, CHECK_CAPS_NODELAY, session);
	else
		mutex_unlock(&session->s_mutex);
}

/*
 * Handle FLUSH_ACK from MDS, indicating that metadata we sent to the
 * MDS has been safely committed.
 */
static void handle_cap_flush_ack(struct inode *inode, u64 flush_tid,
				 struct ceph_mds_caps *m,
				 struct ceph_mds_session *session,
				 struct ceph_cap *cap)
	__releases(ci->i_ceph_lock)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_mds_client *mdsc = ceph_sb_to_client(inode->i_sb)->mdsc;
	unsigned seq = le32_to_cpu(m->seq);
	int dirty = le32_to_cpu(m->dirty);
	int cleaned = 0;
	int drop = 0;
	int i;

	for (i = 0; i < CEPH_CAP_BITS; i++)
		if ((dirty & (1 << i)) &&
		    flush_tid == ci->i_cap_flush_tid[i])
			cleaned |= 1 << i;

	dout("handle_cap_flush_ack inode %p mds%d seq %d on %s cleaned %s,"
	     " flushing %s -> %s\n",
	     inode, session->s_mds, seq, ceph_cap_string(dirty),
	     ceph_cap_string(cleaned), ceph_cap_string(ci->i_flushing_caps),
	     ceph_cap_string(ci->i_flushing_caps & ~cleaned));

	if (ci->i_flushing_caps == (ci->i_flushing_caps & ~cleaned))
		goto out;

	ci->i_flushing_caps &= ~cleaned;

	spin_lock(&mdsc->cap_dirty_lock);
	if (ci->i_flushing_caps == 0) {
		list_del_init(&ci->i_flushing_item);
		if (!list_empty(&session->s_cap_flushing))
			dout(" mds%d still flushing cap on %p\n",
			     session->s_mds,
			     &list_entry(session->s_cap_flushing.next,
					 struct ceph_inode_info,
					 i_flushing_item)->vfs_inode);
		mdsc->num_cap_flushing--;
		wake_up_all(&mdsc->cap_flushing_wq);
		dout(" inode %p now !flushing\n", inode);

		if (ci->i_dirty_caps == 0) {
			dout(" inode %p now clean\n", inode);
			BUG_ON(!list_empty(&ci->i_dirty_item));
			drop = 1;
			if (ci->i_wrbuffer_ref_head == 0) {
				BUG_ON(!ci->i_head_snapc);
				ceph_put_snap_context(ci->i_head_snapc);
				ci->i_head_snapc = NULL;
			}
		} else {
			BUG_ON(list_empty(&ci->i_dirty_item));
		}
	}
	spin_unlock(&mdsc->cap_dirty_lock);
	wake_up_all(&ci->i_cap_wq);

out:
	spin_unlock(&ci->i_ceph_lock);
	if (drop)
		iput(inode);
}

/*
 * Handle FLUSHSNAP_ACK.  MDS has flushed snap data to disk and we can
 * throw away our cap_snap.
 *
 * Caller hold s_mutex.
 */
static void handle_cap_flushsnap_ack(struct inode *inode, u64 flush_tid,
				     struct ceph_mds_caps *m,
				     struct ceph_mds_session *session)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	u64 follows = le64_to_cpu(m->snap_follows);
	struct ceph_cap_snap *capsnap;
	int drop = 0;

	dout("handle_cap_flushsnap_ack inode %p ci %p mds%d follows %lld\n",
	     inode, ci, session->s_mds, follows);

	spin_lock(&ci->i_ceph_lock);
	list_for_each_entry(capsnap, &ci->i_cap_snaps, ci_item) {
		if (capsnap->follows == follows) {
			if (capsnap->flush_tid != flush_tid) {
				dout(" cap_snap %p follows %lld tid %lld !="
				     " %lld\n", capsnap, follows,
				     flush_tid, capsnap->flush_tid);
				break;
			}
			WARN_ON(capsnap->dirty_pages || capsnap->writing);
			dout(" removing %p cap_snap %p follows %lld\n",
			     inode, capsnap, follows);
			ceph_put_snap_context(capsnap->context);
			list_del(&capsnap->ci_item);
			list_del(&capsnap->flushing_item);
			ceph_put_cap_snap(capsnap);
			drop = 1;
			break;
		} else {
			dout(" skipping cap_snap %p follows %lld\n",
			     capsnap, capsnap->follows);
		}
	}
	spin_unlock(&ci->i_ceph_lock);
	if (drop)
		iput(inode);
}

/*
 * Handle TRUNC from MDS, indicating file truncation.
 *
 * caller hold s_mutex.
 */
static void handle_cap_trunc(struct inode *inode,
			     struct ceph_mds_caps *trunc,
			     struct ceph_mds_session *session)
	__releases(ci->i_ceph_lock)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int mds = session->s_mds;
	int seq = le32_to_cpu(trunc->seq);
	u32 truncate_seq = le32_to_cpu(trunc->truncate_seq);
	u64 truncate_size = le64_to_cpu(trunc->truncate_size);
	u64 size = le64_to_cpu(trunc->size);
	int implemented = 0;
	int dirty = __ceph_caps_dirty(ci);
	int issued = __ceph_caps_issued(ceph_inode(inode), &implemented);
	int queue_trunc = 0;

	issued |= implemented | dirty;

	dout("handle_cap_trunc inode %p mds%d seq %d to %lld seq %d\n",
	     inode, mds, seq, truncate_size, truncate_seq);
	queue_trunc = ceph_fill_file_size(inode, issued,
					  truncate_seq, truncate_size, size);
	spin_unlock(&ci->i_ceph_lock);

	if (queue_trunc) {
		ceph_queue_vmtruncate(inode);
		ceph_fscache_invalidate(inode);
	}
}

/*
 * Handle EXPORT from MDS.  Cap is being migrated _from_ this mds to a
 * different one.  If we are the most recent migration we've seen (as
 * indicated by mseq), make note of the migrating cap bits for the
 * duration (until we see the corresponding IMPORT).
 *
 * caller holds s_mutex
 */
static void handle_cap_export(struct inode *inode, struct ceph_mds_caps *ex,
			      struct ceph_mds_cap_peer *ph,
			      struct ceph_mds_session *session)
{
	struct ceph_mds_client *mdsc = ceph_inode_to_client(inode)->mdsc;
	struct ceph_mds_session *tsession = NULL;
	struct ceph_cap *cap, *tcap, *new_cap = NULL;
	struct ceph_inode_info *ci = ceph_inode(inode);
	u64 t_cap_id;
	unsigned mseq = le32_to_cpu(ex->migrate_seq);
	unsigned t_seq, t_mseq;
	int target, issued;
	int mds = session->s_mds;

	if (ph) {
		t_cap_id = le64_to_cpu(ph->cap_id);
		t_seq = le32_to_cpu(ph->seq);
		t_mseq = le32_to_cpu(ph->mseq);
		target = le32_to_cpu(ph->mds);
	} else {
		t_cap_id = t_seq = t_mseq = 0;
		target = -1;
	}

	dout("handle_cap_export inode %p ci %p mds%d mseq %d target %d\n",
	     inode, ci, mds, mseq, target);
retry:
	spin_lock(&ci->i_ceph_lock);
	cap = __get_cap_for_mds(ci, mds);
	if (!cap || cap->cap_id != le64_to_cpu(ex->cap_id))
		goto out_unlock;

	if (target < 0) {
		__ceph_remove_cap(cap, false);
		goto out_unlock;
	}

	/*
	 * now we know we haven't received the cap import message yet
	 * because the exported cap still exist.
	 */

	issued = cap->issued;
	WARN_ON(issued != cap->implemented);

	tcap = __get_cap_for_mds(ci, target);
	if (tcap) {
		/* already have caps from the target */
		if (tcap->cap_id != t_cap_id ||
		    ceph_seq_cmp(tcap->seq, t_seq) < 0) {
			dout(" updating import cap %p mds%d\n", tcap, target);
			tcap->cap_id = t_cap_id;
			tcap->seq = t_seq - 1;
			tcap->issue_seq = t_seq - 1;
			tcap->mseq = t_mseq;
			tcap->issued |= issued;
			tcap->implemented |= issued;
			if (cap == ci->i_auth_cap)
				ci->i_auth_cap = tcap;
			if (ci->i_flushing_caps && ci->i_auth_cap == tcap) {
				spin_lock(&mdsc->cap_dirty_lock);
				list_move_tail(&ci->i_flushing_item,
					       &tcap->session->s_cap_flushing);
				spin_unlock(&mdsc->cap_dirty_lock);
			}
		}
		__ceph_remove_cap(cap, false);
		goto out_unlock;
	} else if (tsession) {
		/* add placeholder for the export tagert */
		int flag = (cap == ci->i_auth_cap) ? CEPH_CAP_FLAG_AUTH : 0;
		ceph_add_cap(inode, tsession, t_cap_id, -1, issued, 0,
			     t_seq - 1, t_mseq, (u64)-1, flag, &new_cap);

		__ceph_remove_cap(cap, false);
		goto out_unlock;
	}

	spin_unlock(&ci->i_ceph_lock);
	mutex_unlock(&session->s_mutex);

	/* open target session */
	tsession = ceph_mdsc_open_export_target_session(mdsc, target);
	if (!IS_ERR(tsession)) {
		if (mds > target) {
			mutex_lock(&session->s_mutex);
			mutex_lock_nested(&tsession->s_mutex,
					  SINGLE_DEPTH_NESTING);
		} else {
			mutex_lock(&tsession->s_mutex);
			mutex_lock_nested(&session->s_mutex,
					  SINGLE_DEPTH_NESTING);
		}
		ceph_add_cap_releases(mdsc, tsession);
		new_cap = ceph_get_cap(mdsc, NULL);
	} else {
		WARN_ON(1);
		tsession = NULL;
		target = -1;
	}
	goto retry;

out_unlock:
	spin_unlock(&ci->i_ceph_lock);
	mutex_unlock(&session->s_mutex);
	if (tsession) {
		mutex_unlock(&tsession->s_mutex);
		ceph_put_mds_session(tsession);
	}
	if (new_cap)
		ceph_put_cap(mdsc, new_cap);
}

/*
 * Handle cap IMPORT.
 *
 * caller holds s_mutex. acquires i_ceph_lock
 */
static void handle_cap_import(struct ceph_mds_client *mdsc,
			      struct inode *inode, struct ceph_mds_caps *im,
			      struct ceph_mds_cap_peer *ph,
			      struct ceph_mds_session *session,
			      struct ceph_cap **target_cap, int *old_issued)
	__acquires(ci->i_ceph_lock)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_cap *cap, *ocap, *new_cap = NULL;
	int mds = session->s_mds;
	int issued;
	unsigned caps = le32_to_cpu(im->caps);
	unsigned wanted = le32_to_cpu(im->wanted);
	unsigned seq = le32_to_cpu(im->seq);
	unsigned mseq = le32_to_cpu(im->migrate_seq);
	u64 realmino = le64_to_cpu(im->realm);
	u64 cap_id = le64_to_cpu(im->cap_id);
	u64 p_cap_id;
	int peer;

	if (ph) {
		p_cap_id = le64_to_cpu(ph->cap_id);
		peer = le32_to_cpu(ph->mds);
	} else {
		p_cap_id = 0;
		peer = -1;
	}

	dout("handle_cap_import inode %p ci %p mds%d mseq %d peer %d\n",
	     inode, ci, mds, mseq, peer);

retry:
	spin_lock(&ci->i_ceph_lock);
	cap = __get_cap_for_mds(ci, mds);
	if (!cap) {
		if (!new_cap) {
			spin_unlock(&ci->i_ceph_lock);
			new_cap = ceph_get_cap(mdsc, NULL);
			goto retry;
		}
		cap = new_cap;
	} else {
		if (new_cap) {
			ceph_put_cap(mdsc, new_cap);
			new_cap = NULL;
		}
	}

	__ceph_caps_issued(ci, &issued);
	issued |= __ceph_caps_dirty(ci);

	ceph_add_cap(inode, session, cap_id, -1, caps, wanted, seq, mseq,
		     realmino, CEPH_CAP_FLAG_AUTH, &new_cap);

	ocap = peer >= 0 ? __get_cap_for_mds(ci, peer) : NULL;
	if (ocap && ocap->cap_id == p_cap_id) {
		dout(" remove export cap %p mds%d flags %d\n",
		     ocap, peer, ph->flags);
		if ((ph->flags & CEPH_CAP_FLAG_AUTH) &&
		    (ocap->seq != le32_to_cpu(ph->seq) ||
		     ocap->mseq != le32_to_cpu(ph->mseq))) {
			pr_err("handle_cap_import: mismatched seq/mseq: "
			       "ino (%llx.%llx) mds%d seq %d mseq %d "
			       "importer mds%d has peer seq %d mseq %d\n",
			       ceph_vinop(inode), peer, ocap->seq,
			       ocap->mseq, mds, le32_to_cpu(ph->seq),
			       le32_to_cpu(ph->mseq));
		}
		__ceph_remove_cap(ocap, (ph->flags & CEPH_CAP_FLAG_RELEASE));
	}

	/* make sure we re-request max_size, if necessary */
	ci->i_wanted_max_size = 0;
	ci->i_requested_max_size = 0;

	*old_issued = issued;
	*target_cap = cap;
}

/*
 * Handle a caps message from the MDS.
 *
 * Identify the appropriate session, inode, and call the right handler
 * based on the cap op.
 */
void ceph_handle_caps(struct ceph_mds_session *session,
		      struct ceph_msg *msg)
{
	struct ceph_mds_client *mdsc = session->s_mdsc;
	struct super_block *sb = mdsc->fsc->sb;
	struct inode *inode;
	struct ceph_inode_info *ci;
	struct ceph_cap *cap;
	struct ceph_mds_caps *h;
	struct ceph_mds_cap_peer *peer = NULL;
	int mds = session->s_mds;
	int op, issued;
	u32 seq, mseq;
	struct ceph_vino vino;
	u64 cap_id;
	u64 size, max_size;
	u64 tid;
	void *snaptrace;
	size_t snaptrace_len;
	void *flock;
	void *end;
	u32 flock_len;

	dout("handle_caps from mds%d\n", mds);

	/* decode */
	end = msg->front.iov_base + msg->front.iov_len;
	tid = le64_to_cpu(msg->hdr.tid);
	if (msg->front.iov_len < sizeof(*h))
		goto bad;
	h = msg->front.iov_base;
	op = le32_to_cpu(h->op);
	vino.ino = le64_to_cpu(h->ino);
	vino.snap = CEPH_NOSNAP;
	cap_id = le64_to_cpu(h->cap_id);
	seq = le32_to_cpu(h->seq);
	mseq = le32_to_cpu(h->migrate_seq);
	size = le64_to_cpu(h->size);
	max_size = le64_to_cpu(h->max_size);

	snaptrace = h + 1;
	snaptrace_len = le32_to_cpu(h->snap_trace_len);

	if (le16_to_cpu(msg->hdr.version) >= 2) {
		void *p = snaptrace + snaptrace_len;
		ceph_decode_32_safe(&p, end, flock_len, bad);
		if (p + flock_len > end)
			goto bad;
		flock = p;
	} else {
		flock = NULL;
		flock_len = 0;
	}

	if (le16_to_cpu(msg->hdr.version) >= 3) {
		if (op == CEPH_CAP_OP_IMPORT) {
			void *p = flock + flock_len;
			if (p + sizeof(*peer) > end)
				goto bad;
			peer = p;
		} else if (op == CEPH_CAP_OP_EXPORT) {
			/* recorded in unused fields */
			peer = (void *)&h->size;
		}
	}

	mutex_lock(&session->s_mutex);
	session->s_seq++;
	dout(" mds%d seq %lld cap seq %u\n", session->s_mds, session->s_seq,
	     (unsigned)seq);

	if (op == CEPH_CAP_OP_IMPORT)
		ceph_add_cap_releases(mdsc, session);

	/* lookup ino */
	inode = ceph_find_inode(sb, vino);
	ci = ceph_inode(inode);
	dout(" op %s ino %llx.%llx inode %p\n", ceph_cap_op_name(op), vino.ino,
	     vino.snap, inode);
	if (!inode) {
		dout(" i don't have ino %llx\n", vino.ino);

		if (op == CEPH_CAP_OP_IMPORT) {
			spin_lock(&session->s_cap_lock);
			__queue_cap_release(session, vino.ino, cap_id,
					    mseq, seq);
			spin_unlock(&session->s_cap_lock);
		}
		goto flush_cap_releases;
	}

	/* these will work even if we don't have a cap yet */
	switch (op) {
	case CEPH_CAP_OP_FLUSHSNAP_ACK:
		handle_cap_flushsnap_ack(inode, tid, h, session);
		goto done;

	case CEPH_CAP_OP_EXPORT:
		handle_cap_export(inode, h, peer, session);
		goto done_unlocked;

	case CEPH_CAP_OP_IMPORT:
		handle_cap_import(mdsc, inode, h, peer, session,
				  &cap, &issued);
		handle_cap_grant(mdsc, inode, h,  snaptrace, snaptrace_len,
				 msg->middle, session, cap, issued);
		goto done_unlocked;
	}

	/* the rest require a cap */
	spin_lock(&ci->i_ceph_lock);
	cap = __get_cap_for_mds(ceph_inode(inode), mds);
	if (!cap) {
		dout(" no cap on %p ino %llx.%llx from mds%d\n",
		     inode, ceph_ino(inode), ceph_snap(inode), mds);
		spin_unlock(&ci->i_ceph_lock);
		goto flush_cap_releases;
	}

	/* note that each of these drops i_ceph_lock for us */
	switch (op) {
	case CEPH_CAP_OP_REVOKE:
	case CEPH_CAP_OP_GRANT:
		__ceph_caps_issued(ci, &issued);
		issued |= __ceph_caps_dirty(ci);
		handle_cap_grant(mdsc, inode, h, NULL, 0, msg->middle,
				 session, cap, issued);
		goto done_unlocked;

	case CEPH_CAP_OP_FLUSH_ACK:
		handle_cap_flush_ack(inode, tid, h, session, cap);
		break;

	case CEPH_CAP_OP_TRUNC:
		handle_cap_trunc(inode, h, session);
		break;

	default:
		spin_unlock(&ci->i_ceph_lock);
		pr_err("ceph_handle_caps: unknown cap op %d %s\n", op,
		       ceph_cap_op_name(op));
	}

	goto done;

flush_cap_releases:
	/*
	 * send any full release message to try to move things
	 * along for the mds (who clearly thinks we still have this
	 * cap).
	 */
	ceph_add_cap_releases(mdsc, session);
	ceph_send_cap_releases(mdsc, session);

done:
	mutex_unlock(&session->s_mutex);
done_unlocked:
	if (inode)
		iput(inode);
	return;

bad:
	pr_err("ceph_handle_caps: corrupt message\n");
	ceph_msg_dump(msg);
	return;
}

/*
 * Delayed work handler to process end of delayed cap release LRU list.
 */
void ceph_check_delayed_caps(struct ceph_mds_client *mdsc)
{
	struct ceph_inode_info *ci;
	int flags = CHECK_CAPS_NODELAY;

	dout("check_delayed_caps\n");
	while (1) {
		spin_lock(&mdsc->cap_delay_lock);
		if (list_empty(&mdsc->cap_delay_list))
			break;
		ci = list_first_entry(&mdsc->cap_delay_list,
				      struct ceph_inode_info,
				      i_cap_delay_list);
		if ((ci->i_ceph_flags & CEPH_I_FLUSH) == 0 &&
		    time_before(jiffies, ci->i_hold_caps_max))
			break;
		list_del_init(&ci->i_cap_delay_list);
		spin_unlock(&mdsc->cap_delay_lock);
		dout("check_delayed_caps on %p\n", &ci->vfs_inode);
		ceph_check_caps(ci, flags, NULL);
	}
	spin_unlock(&mdsc->cap_delay_lock);
}

/*
 * Flush all dirty caps to the mds
 */
void ceph_flush_dirty_caps(struct ceph_mds_client *mdsc)
{
	struct ceph_inode_info *ci;
	struct inode *inode;

	dout("flush_dirty_caps\n");
	spin_lock(&mdsc->cap_dirty_lock);
	while (!list_empty(&mdsc->cap_dirty)) {
		ci = list_first_entry(&mdsc->cap_dirty, struct ceph_inode_info,
				      i_dirty_item);
		inode = &ci->vfs_inode;
		ihold(inode);
		dout("flush_dirty_caps %p\n", inode);
		spin_unlock(&mdsc->cap_dirty_lock);
		ceph_check_caps(ci, CHECK_CAPS_NODELAY|CHECK_CAPS_FLUSH, NULL);
		iput(inode);
		spin_lock(&mdsc->cap_dirty_lock);
	}
	spin_unlock(&mdsc->cap_dirty_lock);
	dout("flush_dirty_caps done\n");
}

/*
 * Drop open file reference.  If we were the last open file,
 * we may need to release capabilities to the MDS (or schedule
 * their delayed release).
 */
void ceph_put_fmode(struct ceph_inode_info *ci, int fmode)
{
	struct inode *inode = &ci->vfs_inode;
	int last = 0;

	spin_lock(&ci->i_ceph_lock);
	dout("put_fmode %p fmode %d %d -> %d\n", inode, fmode,
	     ci->i_nr_by_mode[fmode], ci->i_nr_by_mode[fmode]-1);
	BUG_ON(ci->i_nr_by_mode[fmode] == 0);
	if (--ci->i_nr_by_mode[fmode] == 0)
		last++;
	spin_unlock(&ci->i_ceph_lock);

	if (last && ci->i_vino.snap == CEPH_NOSNAP)
		ceph_check_caps(ci, 0, NULL);
}

/*
 * Helpers for embedding cap and dentry lease releases into mds
 * requests.
 *
 * @force is used by dentry_release (below) to force inclusion of a
 * record for the directory inode, even when there aren't any caps to
 * drop.
 */
int ceph_encode_inode_release(void **p, struct inode *inode,
			      int mds, int drop, int unless, int force)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_cap *cap;
	struct ceph_mds_request_release *rel = *p;
	int used, dirty;
	int ret = 0;

	spin_lock(&ci->i_ceph_lock);
	used = __ceph_caps_used(ci);
	dirty = __ceph_caps_dirty(ci);

	dout("encode_inode_release %p mds%d used|dirty %s drop %s unless %s\n",
	     inode, mds, ceph_cap_string(used|dirty), ceph_cap_string(drop),
	     ceph_cap_string(unless));

	/* only drop unused, clean caps */
	drop &= ~(used | dirty);

	cap = __get_cap_for_mds(ci, mds);
	if (cap && __cap_is_valid(cap)) {
		if (force ||
		    ((cap->issued & drop) &&
		     (cap->issued & unless) == 0)) {
			if ((cap->issued & drop) &&
			    (cap->issued & unless) == 0) {
				int wanted = __ceph_caps_wanted(ci);
				if ((ci->i_ceph_flags & CEPH_I_NODELAY) == 0)
					wanted |= cap->mds_wanted;
				dout("encode_inode_release %p cap %p "
				     "%s -> %s, wanted %s -> %s\n", inode, cap,
				     ceph_cap_string(cap->issued),
				     ceph_cap_string(cap->issued & ~drop),
				     ceph_cap_string(cap->mds_wanted),
				     ceph_cap_string(wanted));

				cap->issued &= ~drop;
				cap->implemented &= ~drop;
				cap->mds_wanted = wanted;
			} else {
				dout("encode_inode_release %p cap %p %s"
				     " (force)\n", inode, cap,
				     ceph_cap_string(cap->issued));
			}

			rel->ino = cpu_to_le64(ceph_ino(inode));
			rel->cap_id = cpu_to_le64(cap->cap_id);
			rel->seq = cpu_to_le32(cap->seq);
			rel->issue_seq = cpu_to_le32(cap->issue_seq);
			rel->mseq = cpu_to_le32(cap->mseq);
			rel->caps = cpu_to_le32(cap->implemented);
			rel->wanted = cpu_to_le32(cap->mds_wanted);
			rel->dname_len = 0;
			rel->dname_seq = 0;
			*p += sizeof(*rel);
			ret = 1;
		} else {
			dout("encode_inode_release %p cap %p %s\n",
			     inode, cap, ceph_cap_string(cap->issued));
		}
	}
	spin_unlock(&ci->i_ceph_lock);
	return ret;
}

int ceph_encode_dentry_release(void **p, struct dentry *dentry,
			       int mds, int drop, int unless)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct ceph_mds_request_release *rel = *p;
	struct ceph_dentry_info *di = ceph_dentry(dentry);
	int force = 0;
	int ret;

	/*
	 * force an record for the directory caps if we have a dentry lease.
	 * this is racy (can't take i_ceph_lock and d_lock together), but it
	 * doesn't have to be perfect; the mds will revoke anything we don't
	 * release.
	 */
	spin_lock(&dentry->d_lock);
	if (di->lease_session && di->lease_session->s_mds == mds)
		force = 1;
	spin_unlock(&dentry->d_lock);

	ret = ceph_encode_inode_release(p, dir, mds, drop, unless, force);

	spin_lock(&dentry->d_lock);
	if (ret && di->lease_session && di->lease_session->s_mds == mds) {
		dout("encode_dentry_release %p mds%d seq %d\n",
		     dentry, mds, (int)di->lease_seq);
		rel->dname_len = cpu_to_le32(dentry->d_name.len);
		memcpy(*p, dentry->d_name.name, dentry->d_name.len);
		*p += dentry->d_name.len;
		rel->dname_seq = cpu_to_le32(di->lease_seq);
		__ceph_mdsc_drop_dentry_lease(dentry);
	}
	spin_unlock(&dentry->d_lock);
	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/ceph/caps.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

#include <linux/sort.h>
// #include <linux/slab.h>

// #include "super.h"
// #include "mds_client.h"

// #include <linux/ceph/decode.h>

/*
 * Snapshots in ceph are driven in large part by cooperation from the
 * client.  In contrast to local file systems or file servers that
 * implement snapshots at a single point in the system, ceph's
 * distributed access to storage requires clients to help decide
 * whether a write logically occurs before or after a recently created
 * snapshot.
 *
 * This provides a perfect instantanous client-wide snapshot.  Between
 * clients, however, snapshots may appear to be applied at slightly
 * different points in time, depending on delays in delivering the
 * snapshot notification.
 *
 * Snapshots are _not_ file system-wide.  Instead, each snapshot
 * applies to the subdirectory nested beneath some directory.  This
 * effectively divides the hierarchy into multiple "realms," where all
 * of the files contained by each realm share the same set of
 * snapshots.  An individual realm's snap set contains snapshots
 * explicitly created on that realm, as well as any snaps in its
 * parent's snap set _after_ the point at which the parent became it's
 * parent (due to, say, a rename).  Similarly, snaps from prior parents
 * during the time intervals during which they were the parent are included.
 *
 * The client is spared most of this detail, fortunately... it must only
 * maintains a hierarchy of realms reflecting the current parent/child
 * realm relationship, and for each realm has an explicit list of snaps
 * inherited from prior parents.
 *
 * A snap_realm struct is maintained for realms containing every inode
 * with an open cap in the system.  (The needed snap realm information is
 * provided by the MDS whenever a cap is issued, i.e., on open.)  A 'seq'
 * version number is used to ensure that as realm parameters change (new
 * snapshot, new parent, etc.) the client's realm hierarchy is updated.
 *
 * The realm hierarchy drives the generation of a 'snap context' for each
 * realm, which simply lists the resulting set of snaps for the realm.  This
 * is attached to any writes sent to OSDs.
 */
/*
 * Unfortunately error handling is a bit mixed here.  If we get a snap
 * update, but don't have enough memory to update our realm hierarchy,
 * it's not clear what we can do about it (besides complaining to the
 * console).
 */


/*
 * increase ref count for the realm
 *
 * caller must hold snap_rwsem for write.
 */
void ceph_get_snap_realm(struct ceph_mds_client *mdsc,
			 struct ceph_snap_realm *realm)
{
	dout("get_realm %p %d -> %d\n", realm,
	     atomic_read(&realm->nref), atomic_read(&realm->nref)+1);
	/*
	 * since we _only_ increment realm refs or empty the empty
	 * list with snap_rwsem held, adjusting the empty list here is
	 * safe.  we do need to protect against concurrent empty list
	 * additions, however.
	 */
	if (atomic_read(&realm->nref) == 0) {
		spin_lock(&mdsc->snap_empty_lock);
		list_del_init(&realm->empty_item);
		spin_unlock(&mdsc->snap_empty_lock);
	}

	atomic_inc(&realm->nref);
}

static void __insert_snap_realm(struct rb_root *root,
				struct ceph_snap_realm *new)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct ceph_snap_realm *r = NULL;

	while (*p) {
		parent = *p;
		r = rb_entry(parent, struct ceph_snap_realm, node);
		if (new->ino < r->ino)
			p = &(*p)->rb_left;
		else if (new->ino > r->ino)
			p = &(*p)->rb_right;
		else
			BUG();
	}

	rb_link_node(&new->node, parent, p);
	rb_insert_color(&new->node, root);
}

/*
 * create and get the realm rooted at @ino and bump its ref count.
 *
 * caller must hold snap_rwsem for write.
 */
static struct ceph_snap_realm *ceph_create_snap_realm(
	struct ceph_mds_client *mdsc,
	u64 ino)
{
	struct ceph_snap_realm *realm;

	realm = kzalloc(sizeof(*realm), GFP_NOFS);
	if (!realm)
		return ERR_PTR(-ENOMEM);

	atomic_set(&realm->nref, 0);    /* tree does not take a ref */
	realm->ino = ino;
	INIT_LIST_HEAD(&realm->children);
	INIT_LIST_HEAD(&realm->child_item);
	INIT_LIST_HEAD(&realm->empty_item);
	INIT_LIST_HEAD(&realm->dirty_item);
	INIT_LIST_HEAD(&realm->inodes_with_caps);
	spin_lock_init(&realm->inodes_with_caps_lock);
	__insert_snap_realm(&mdsc->snap_realms, realm);
	dout("create_snap_realm %llx %p\n", realm->ino, realm);
	return realm;
}

/*
 * lookup the realm rooted at @ino.
 *
 * caller must hold snap_rwsem for write.
 */
struct ceph_snap_realm *ceph_lookup_snap_realm(struct ceph_mds_client *mdsc,
					       u64 ino)
{
	struct rb_node *n = mdsc->snap_realms.rb_node;
	struct ceph_snap_realm *r;

	while (n) {
		r = rb_entry(n, struct ceph_snap_realm, node);
		if (ino < r->ino)
			n = n->rb_left;
		else if (ino > r->ino)
			n = n->rb_right;
		else {
			dout("lookup_snap_realm %llx %p\n", r->ino, r);
			return r;
		}
	}
	return NULL;
}

static void __put_snap_realm(struct ceph_mds_client *mdsc,
			     struct ceph_snap_realm *realm);

/*
 * called with snap_rwsem (write)
 */
static void __destroy_snap_realm(struct ceph_mds_client *mdsc,
				 struct ceph_snap_realm *realm)
{
	dout("__destroy_snap_realm %p %llx\n", realm, realm->ino);

	rb_erase(&realm->node, &mdsc->snap_realms);

	if (realm->parent) {
		list_del_init(&realm->child_item);
		__put_snap_realm(mdsc, realm->parent);
	}

	kfree(realm->prior_parent_snaps);
	kfree(realm->snaps);
	ceph_put_snap_context(realm->cached_context);
	kfree(realm);
}

/*
 * caller holds snap_rwsem (write)
 */
static void __put_snap_realm(struct ceph_mds_client *mdsc,
			     struct ceph_snap_realm *realm)
{
	dout("__put_snap_realm %llx %p %d -> %d\n", realm->ino, realm,
	     atomic_read(&realm->nref), atomic_read(&realm->nref)-1);
	if (atomic_dec_and_test(&realm->nref))
		__destroy_snap_realm(mdsc, realm);
}

/*
 * caller needn't hold any locks
 */
void ceph_put_snap_realm(struct ceph_mds_client *mdsc,
			 struct ceph_snap_realm *realm)
{
	dout("put_snap_realm %llx %p %d -> %d\n", realm->ino, realm,
	     atomic_read(&realm->nref), atomic_read(&realm->nref)-1);
	if (!atomic_dec_and_test(&realm->nref))
		return;

	if (down_write_trylock(&mdsc->snap_rwsem)) {
		__destroy_snap_realm(mdsc, realm);
		up_write(&mdsc->snap_rwsem);
	} else {
		spin_lock(&mdsc->snap_empty_lock);
		list_add(&realm->empty_item, &mdsc->snap_empty);
		spin_unlock(&mdsc->snap_empty_lock);
	}
}

/*
 * Clean up any realms whose ref counts have dropped to zero.  Note
 * that this does not include realms who were created but not yet
 * used.
 *
 * Called under snap_rwsem (write)
 */
static void __cleanup_empty_realms(struct ceph_mds_client *mdsc)
{
	struct ceph_snap_realm *realm;

	spin_lock(&mdsc->snap_empty_lock);
	while (!list_empty(&mdsc->snap_empty)) {
		realm = list_first_entry(&mdsc->snap_empty,
				   struct ceph_snap_realm, empty_item);
		list_del(&realm->empty_item);
		spin_unlock(&mdsc->snap_empty_lock);
		__destroy_snap_realm(mdsc, realm);
		spin_lock(&mdsc->snap_empty_lock);
	}
	spin_unlock(&mdsc->snap_empty_lock);
}

void ceph_cleanup_empty_realms(struct ceph_mds_client *mdsc)
{
	down_write(&mdsc->snap_rwsem);
	__cleanup_empty_realms(mdsc);
	up_write(&mdsc->snap_rwsem);
}

/*
 * adjust the parent realm of a given @realm.  adjust child list, and parent
 * pointers, and ref counts appropriately.
 *
 * return true if parent was changed, 0 if unchanged, <0 on error.
 *
 * caller must hold snap_rwsem for write.
 */
static int adjust_snap_realm_parent(struct ceph_mds_client *mdsc,
				    struct ceph_snap_realm *realm,
				    u64 parentino)
{
	struct ceph_snap_realm *parent;

	if (realm->parent_ino == parentino)
		return 0;

	parent = ceph_lookup_snap_realm(mdsc, parentino);
	if (!parent) {
		parent = ceph_create_snap_realm(mdsc, parentino);
		if (IS_ERR(parent))
			return PTR_ERR(parent);
	}
	dout("adjust_snap_realm_parent %llx %p: %llx %p -> %llx %p\n",
	     realm->ino, realm, realm->parent_ino, realm->parent,
	     parentino, parent);
	if (realm->parent) {
		list_del_init(&realm->child_item);
		ceph_put_snap_realm(mdsc, realm->parent);
	}
	realm->parent_ino = parentino;
	realm->parent = parent;
	ceph_get_snap_realm(mdsc, parent);
	list_add(&realm->child_item, &parent->children);
	return 1;
}


static int cmpu64_rev(const void *a, const void *b)
{
	if (*(u64 *)a < *(u64 *)b)
		return 1;
	if (*(u64 *)a > *(u64 *)b)
		return -1;
	return 0;
}

/*
 * build the snap context for a given realm.
 */
static int build_snap_context(struct ceph_snap_realm *realm)
{
	struct ceph_snap_realm *parent = realm->parent;
	struct ceph_snap_context *snapc;
	int err = 0;
	u32 num = realm->num_prior_parent_snaps + realm->num_snaps;

	/*
	 * build parent context, if it hasn't been built.
	 * conservatively estimate that all parent snaps might be
	 * included by us.
	 */
	if (parent) {
		if (!parent->cached_context) {
			err = build_snap_context(parent);
			if (err)
				goto fail;
		}
		num += parent->cached_context->num_snaps;
	}

	/* do i actually need to update?  not if my context seq
	   matches realm seq, and my parents' does to.  (this works
	   because we rebuild_snap_realms() works _downward_ in
	   hierarchy after each update.) */
	if (realm->cached_context &&
	    realm->cached_context->seq == realm->seq &&
	    (!parent ||
	     realm->cached_context->seq >= parent->cached_context->seq)) {
		dout("build_snap_context %llx %p: %p seq %lld (%u snaps)"
		     " (unchanged)\n",
		     realm->ino, realm, realm->cached_context,
		     realm->cached_context->seq,
		     (unsigned int) realm->cached_context->num_snaps);
		return 0;
	}

	/* alloc new snap context */
	err = -ENOMEM;
	if (num > (SIZE_MAX - sizeof(*snapc)) / sizeof(u64))
		goto fail;
	snapc = ceph_create_snap_context(num, GFP_NOFS);
	if (!snapc)
		goto fail;

	/* build (reverse sorted) snap vector */
	num = 0;
	snapc->seq = realm->seq;
	if (parent) {
		u32 i;

		/* include any of parent's snaps occurring _after_ my
		   parent became my parent */
		for (i = 0; i < parent->cached_context->num_snaps; i++)
			if (parent->cached_context->snaps[i] >=
			    realm->parent_since)
				snapc->snaps[num++] =
					parent->cached_context->snaps[i];
		if (parent->cached_context->seq > snapc->seq)
			snapc->seq = parent->cached_context->seq;
	}
	memcpy(snapc->snaps + num, realm->snaps,
	       sizeof(u64)*realm->num_snaps);
	num += realm->num_snaps;
	memcpy(snapc->snaps + num, realm->prior_parent_snaps,
	       sizeof(u64)*realm->num_prior_parent_snaps);
	num += realm->num_prior_parent_snaps;

	sort(snapc->snaps, num, sizeof(u64), cmpu64_rev, NULL);
	snapc->num_snaps = num;
	dout("build_snap_context %llx %p: %p seq %lld (%u snaps)\n",
	     realm->ino, realm, snapc, snapc->seq,
	     (unsigned int) snapc->num_snaps);

	if (realm->cached_context)
		ceph_put_snap_context(realm->cached_context);
	realm->cached_context = snapc;
	return 0;

fail:
	/*
	 * if we fail, clear old (incorrect) cached_context... hopefully
	 * we'll have better luck building it later
	 */
	if (realm->cached_context) {
		ceph_put_snap_context(realm->cached_context);
		realm->cached_context = NULL;
	}
	pr_err("build_snap_context %llx %p fail %d\n", realm->ino,
	       realm, err);
	return err;
}

/*
 * rebuild snap context for the given realm and all of its children.
 */
static void rebuild_snap_realms(struct ceph_snap_realm *realm)
{
	struct ceph_snap_realm *child;

	dout("rebuild_snap_realms %llx %p\n", realm->ino, realm);
	build_snap_context(realm);

	list_for_each_entry(child, &realm->children, child_item)
		rebuild_snap_realms(child);
}


/*
 * helper to allocate and decode an array of snapids.  free prior
 * instance, if any.
 */
static int dup_array(u64 **dst, __le64 *src, u32 num)
{
	u32 i;

	kfree(*dst);
	if (num) {
		*dst = kcalloc(num, sizeof(u64), GFP_NOFS);
		if (!*dst)
			return -ENOMEM;
		for (i = 0; i < num; i++)
			(*dst)[i] = get_unaligned_le64(src + i);
	} else {
		*dst = NULL;
	}
	return 0;
}


/*
 * When a snapshot is applied, the size/mtime inode metadata is queued
 * in a ceph_cap_snap (one for each snapshot) until writeback
 * completes and the metadata can be flushed back to the MDS.
 *
 * However, if a (sync) write is currently in-progress when we apply
 * the snapshot, we have to wait until the write succeeds or fails
 * (and a final size/mtime is known).  In this case the
 * cap_snap->writing = 1, and is said to be "pending."  When the write
 * finishes, we __ceph_finish_cap_snap().
 *
 * Caller must hold snap_rwsem for read (i.e., the realm topology won't
 * change).
 */
void ceph_queue_cap_snap(struct ceph_inode_info *ci)
{
	struct inode *inode = &ci->vfs_inode;
	struct ceph_cap_snap *capsnap;
	int used, dirty;

	capsnap = kzalloc(sizeof(*capsnap), GFP_NOFS);
	if (!capsnap) {
		pr_err("ENOMEM allocating ceph_cap_snap on %p\n", inode);
		return;
	}

	spin_lock(&ci->i_ceph_lock);
	used = __ceph_caps_used(ci);
	dirty = __ceph_caps_dirty(ci);

	/*
	 * If there is a write in progress, treat that as a dirty Fw,
	 * even though it hasn't completed yet; by the time we finish
	 * up this capsnap it will be.
	 */
	if (used & CEPH_CAP_FILE_WR)
		dirty |= CEPH_CAP_FILE_WR;

	if (__ceph_have_pending_cap_snap(ci)) {
		/* there is no point in queuing multiple "pending" cap_snaps,
		   as no new writes are allowed to start when pending, so any
		   writes in progress now were started before the previous
		   cap_snap.  lucky us. */
		dout("queue_cap_snap %p already pending\n", inode);
		kfree(capsnap);
	} else if (dirty & (CEPH_CAP_AUTH_EXCL|CEPH_CAP_XATTR_EXCL|
			    CEPH_CAP_FILE_EXCL|CEPH_CAP_FILE_WR)) {
		struct ceph_snap_context *snapc = ci->i_head_snapc;

		/*
		 * if we are a sync write, we may need to go to the snaprealm
		 * to get the current snapc.
		 */
		if (!snapc)
			snapc = ci->i_snap_realm->cached_context;

		dout("queue_cap_snap %p cap_snap %p queuing under %p %s\n",
		     inode, capsnap, snapc, ceph_cap_string(dirty));
		ihold(inode);

		atomic_set(&capsnap->nref, 1);
		capsnap->ci = ci;
		INIT_LIST_HEAD(&capsnap->ci_item);
		INIT_LIST_HEAD(&capsnap->flushing_item);

		capsnap->follows = snapc->seq;
		capsnap->issued = __ceph_caps_issued(ci, NULL);
		capsnap->dirty = dirty;

		capsnap->mode = inode->i_mode;
		capsnap->uid = inode->i_uid;
		capsnap->gid = inode->i_gid;

		if (dirty & CEPH_CAP_XATTR_EXCL) {
			__ceph_build_xattrs_blob(ci);
			capsnap->xattr_blob =
				ceph_buffer_get(ci->i_xattrs.blob);
			capsnap->xattr_version = ci->i_xattrs.version;
		} else {
			capsnap->xattr_blob = NULL;
			capsnap->xattr_version = 0;
		}

		/* dirty page count moved from _head to this cap_snap;
		   all subsequent writes page dirties occur _after_ this
		   snapshot. */
		capsnap->dirty_pages = ci->i_wrbuffer_ref_head;
		ci->i_wrbuffer_ref_head = 0;
		capsnap->context = snapc;
		ci->i_head_snapc =
			ceph_get_snap_context(ci->i_snap_realm->cached_context);
		dout(" new snapc is %p\n", ci->i_head_snapc);
		list_add_tail(&capsnap->ci_item, &ci->i_cap_snaps);

		if (used & CEPH_CAP_FILE_WR) {
			dout("queue_cap_snap %p cap_snap %p snapc %p"
			     " seq %llu used WR, now pending\n", inode,
			     capsnap, snapc, snapc->seq);
			capsnap->writing = 1;
		} else {
			/* note mtime, size NOW. */
			__ceph_finish_cap_snap(ci, capsnap);
		}
	} else {
		dout("queue_cap_snap %p nothing dirty|writing\n", inode);
		kfree(capsnap);
	}

	spin_unlock(&ci->i_ceph_lock);
}

/*
 * Finalize the size, mtime for a cap_snap.. that is, settle on final values
 * to be used for the snapshot, to be flushed back to the mds.
 *
 * If capsnap can now be flushed, add to snap_flush list, and return 1.
 *
 * Caller must hold i_ceph_lock.
 */
int __ceph_finish_cap_snap(struct ceph_inode_info *ci,
			    struct ceph_cap_snap *capsnap)
{
	struct inode *inode = &ci->vfs_inode;
	struct ceph_mds_client *mdsc = ceph_sb_to_client(inode->i_sb)->mdsc;

	BUG_ON(capsnap->writing);
	capsnap->size = inode->i_size;
	capsnap->mtime = inode->i_mtime;
	capsnap->atime = inode->i_atime;
	capsnap->ctime = inode->i_ctime;
	capsnap->time_warp_seq = ci->i_time_warp_seq;
	if (capsnap->dirty_pages) {
		dout("finish_cap_snap %p cap_snap %p snapc %p %llu %s s=%llu "
		     "still has %d dirty pages\n", inode, capsnap,
		     capsnap->context, capsnap->context->seq,
		     ceph_cap_string(capsnap->dirty), capsnap->size,
		     capsnap->dirty_pages);
		return 0;
	}
	dout("finish_cap_snap %p cap_snap %p snapc %p %llu %s s=%llu\n",
	     inode, capsnap, capsnap->context,
	     capsnap->context->seq, ceph_cap_string(capsnap->dirty),
	     capsnap->size);

	spin_lock(&mdsc->snap_flush_lock);
	list_add_tail(&ci->i_snap_flush_item, &mdsc->snap_flush_list);
	spin_unlock(&mdsc->snap_flush_lock);
	return 1;  /* caller may want to ceph_flush_snaps */
}

/*
 * Queue cap_snaps for snap writeback for this realm and its children.
 * Called under snap_rwsem, so realm topology won't change.
 */
static void queue_realm_cap_snaps(struct ceph_snap_realm *realm)
{
	struct ceph_inode_info *ci;
	struct inode *lastinode = NULL;
	struct ceph_snap_realm *child;

	dout("queue_realm_cap_snaps %p %llx inodes\n", realm, realm->ino);

	spin_lock(&realm->inodes_with_caps_lock);
	list_for_each_entry(ci, &realm->inodes_with_caps,
			    i_snap_realm_item) {
		struct inode *inode = igrab(&ci->vfs_inode);
		if (!inode)
			continue;
		spin_unlock(&realm->inodes_with_caps_lock);
		if (lastinode)
			iput(lastinode);
		lastinode = inode;
		ceph_queue_cap_snap(ci);
		spin_lock(&realm->inodes_with_caps_lock);
	}
	spin_unlock(&realm->inodes_with_caps_lock);
	if (lastinode)
		iput(lastinode);

	list_for_each_entry(child, &realm->children, child_item) {
		dout("queue_realm_cap_snaps %p %llx queue child %p %llx\n",
		     realm, realm->ino, child, child->ino);
		list_del_init(&child->dirty_item);
		list_add(&child->dirty_item, &realm->dirty_item);
	}

	list_del_init(&realm->dirty_item);
	dout("queue_realm_cap_snaps %p %llx done\n", realm, realm->ino);
}

/*
 * Parse and apply a snapblob "snap trace" from the MDS.  This specifies
 * the snap realm parameters from a given realm and all of its ancestors,
 * up to the root.
 *
 * Caller must hold snap_rwsem for write.
 */
int ceph_update_snap_trace(struct ceph_mds_client *mdsc,
			   void *p, void *e, bool deletion)
{
	struct ceph_mds_snap_realm *ri;    /* encoded */
	__le64 *snaps;                     /* encoded */
	__le64 *prior_parent_snaps;        /* encoded */
	struct ceph_snap_realm *realm;
	int invalidate = 0;
	int err = -ENOMEM;
	LIST_HEAD(dirty_realms);

	dout("update_snap_trace deletion=%d\n", deletion);
more:
	ceph_decode_need(&p, e, sizeof(*ri), bad);
	ri = p;
	p += sizeof(*ri);
	ceph_decode_need(&p, e, sizeof(u64)*(le32_to_cpu(ri->num_snaps) +
			    le32_to_cpu(ri->num_prior_parent_snaps)), bad);
	snaps = p;
	p += sizeof(u64) * le32_to_cpu(ri->num_snaps);
	prior_parent_snaps = p;
	p += sizeof(u64) * le32_to_cpu(ri->num_prior_parent_snaps);

	realm = ceph_lookup_snap_realm(mdsc, le64_to_cpu(ri->ino));
	if (!realm) {
		realm = ceph_create_snap_realm(mdsc, le64_to_cpu(ri->ino));
		if (IS_ERR(realm)) {
			err = PTR_ERR(realm);
			goto fail;
		}
	}

	/* ensure the parent is correct */
	err = adjust_snap_realm_parent(mdsc, realm, le64_to_cpu(ri->parent));
	if (err < 0)
		goto fail;
	invalidate += err;

	if (le64_to_cpu(ri->seq) > realm->seq) {
		dout("update_snap_trace updating %llx %p %lld -> %lld\n",
		     realm->ino, realm, realm->seq, le64_to_cpu(ri->seq));
		/* update realm parameters, snap lists */
		realm->seq = le64_to_cpu(ri->seq);
		realm->created = le64_to_cpu(ri->created);
		realm->parent_since = le64_to_cpu(ri->parent_since);

		realm->num_snaps = le32_to_cpu(ri->num_snaps);
		err = dup_array(&realm->snaps, snaps, realm->num_snaps);
		if (err < 0)
			goto fail;

		realm->num_prior_parent_snaps =
			le32_to_cpu(ri->num_prior_parent_snaps);
		err = dup_array(&realm->prior_parent_snaps, prior_parent_snaps,
				realm->num_prior_parent_snaps);
		if (err < 0)
			goto fail;

		/* queue realm for cap_snap creation */
		list_add(&realm->dirty_item, &dirty_realms);

		invalidate = 1;
	} else if (!realm->cached_context) {
		dout("update_snap_trace %llx %p seq %lld new\n",
		     realm->ino, realm, realm->seq);
		invalidate = 1;
	} else {
		dout("update_snap_trace %llx %p seq %lld unchanged\n",
		     realm->ino, realm, realm->seq);
	}

	dout("done with %llx %p, invalidated=%d, %p %p\n", realm->ino,
	     realm, invalidate, p, e);

	if (p < e)
		goto more;

	/* invalidate when we reach the _end_ (root) of the trace */
	if (invalidate)
		rebuild_snap_realms(realm);

	/*
	 * queue cap snaps _after_ we've built the new snap contexts,
	 * so that i_head_snapc can be set appropriately.
	 */
	while (!list_empty(&dirty_realms)) {
		realm = list_first_entry(&dirty_realms, struct ceph_snap_realm,
					 dirty_item);
		queue_realm_cap_snaps(realm);
	}

	__cleanup_empty_realms(mdsc);
	return 0;

bad:
	err = -EINVAL;
fail:
	pr_err("update_snap_trace error %d\n", err);
	return err;
}


/*
 * Send any cap_snaps that are queued for flush.  Try to carry
 * s_mutex across multiple snap flushes to avoid locking overhead.
 *
 * Caller holds no locks.
 */
static void flush_snaps(struct ceph_mds_client *mdsc)
{
	struct ceph_inode_info *ci;
	struct inode *inode;
	struct ceph_mds_session *session = NULL;

	dout("flush_snaps\n");
	spin_lock(&mdsc->snap_flush_lock);
	while (!list_empty(&mdsc->snap_flush_list)) {
		ci = list_first_entry(&mdsc->snap_flush_list,
				struct ceph_inode_info, i_snap_flush_item);
		inode = &ci->vfs_inode;
		ihold(inode);
		spin_unlock(&mdsc->snap_flush_lock);
		spin_lock(&ci->i_ceph_lock);
		__ceph_flush_snaps(ci, &session, 0);
		spin_unlock(&ci->i_ceph_lock);
		iput(inode);
		spin_lock(&mdsc->snap_flush_lock);
	}
	spin_unlock(&mdsc->snap_flush_lock);

	if (session) {
		mutex_unlock(&session->s_mutex);
		ceph_put_mds_session(session);
	}
	dout("flush_snaps done\n");
}


/*
 * Handle a snap notification from the MDS.
 *
 * This can take two basic forms: the simplest is just a snap creation
 * or deletion notification on an existing realm.  This should update the
 * realm and its children.
 *
 * The more difficult case is realm creation, due to snap creation at a
 * new point in the file hierarchy, or due to a rename that moves a file or
 * directory into another realm.
 */
void ceph_handle_snap(struct ceph_mds_client *mdsc,
		      struct ceph_mds_session *session,
		      struct ceph_msg *msg)
{
	struct super_block *sb = mdsc->fsc->sb;
	int mds = session->s_mds;
	u64 split;
	int op;
	int trace_len;
	struct ceph_snap_realm *realm = NULL;
	void *p = msg->front.iov_base;
	void *e = p + msg->front.iov_len;
	struct ceph_mds_snap_head *h;
	int num_split_inos, num_split_realms;
	__le64 *split_inos = NULL, *split_realms = NULL;
	int i;
	int locked_rwsem = 0;

	/* decode */
	if (msg->front.iov_len < sizeof(*h))
		goto bad;
	h = p;
	op = le32_to_cpu(h->op);
	split = le64_to_cpu(h->split);   /* non-zero if we are splitting an
					  * existing realm */
	num_split_inos = le32_to_cpu(h->num_split_inos);
	num_split_realms = le32_to_cpu(h->num_split_realms);
	trace_len = le32_to_cpu(h->trace_len);
	p += sizeof(*h);

	dout("handle_snap from mds%d op %s split %llx tracelen %d\n", mds,
	     ceph_snap_op_name(op), split, trace_len);

	mutex_lock(&session->s_mutex);
	session->s_seq++;
	mutex_unlock(&session->s_mutex);

	down_write(&mdsc->snap_rwsem);
	locked_rwsem = 1;

	if (op == CEPH_SNAP_OP_SPLIT) {
		struct ceph_mds_snap_realm *ri;

		/*
		 * A "split" breaks part of an existing realm off into
		 * a new realm.  The MDS provides a list of inodes
		 * (with caps) and child realms that belong to the new
		 * child.
		 */
		split_inos = p;
		p += sizeof(u64) * num_split_inos;
		split_realms = p;
		p += sizeof(u64) * num_split_realms;
		ceph_decode_need(&p, e, sizeof(*ri), bad);
		/* we will peek at realm info here, but will _not_
		 * advance p, as the realm update will occur below in
		 * ceph_update_snap_trace. */
		ri = p;

		realm = ceph_lookup_snap_realm(mdsc, split);
		if (!realm) {
			realm = ceph_create_snap_realm(mdsc, split);
			if (IS_ERR(realm))
				goto out;
		}
		ceph_get_snap_realm(mdsc, realm);

		dout("splitting snap_realm %llx %p\n", realm->ino, realm);
		for (i = 0; i < num_split_inos; i++) {
			struct ceph_vino vino = {
				.ino = le64_to_cpu(split_inos[i]),
				.snap = CEPH_NOSNAP,
			};
			struct inode *inode = ceph_find_inode(sb, vino);
			struct ceph_inode_info *ci;
			struct ceph_snap_realm *oldrealm;

			if (!inode)
				continue;
			ci = ceph_inode(inode);

			spin_lock(&ci->i_ceph_lock);
			if (!ci->i_snap_realm)
				goto skip_inode;
			/*
			 * If this inode belongs to a realm that was
			 * created after our new realm, we experienced
			 * a race (due to another split notifications
			 * arriving from a different MDS).  So skip
			 * this inode.
			 */
			if (ci->i_snap_realm->created >
			    le64_to_cpu(ri->created)) {
				dout(" leaving %p in newer realm %llx %p\n",
				     inode, ci->i_snap_realm->ino,
				     ci->i_snap_realm);
				goto skip_inode;
			}
			dout(" will move %p to split realm %llx %p\n",
			     inode, realm->ino, realm);
			/*
			 * Move the inode to the new realm
			 */
			spin_lock(&realm->inodes_with_caps_lock);
			list_del_init(&ci->i_snap_realm_item);
			list_add(&ci->i_snap_realm_item,
				 &realm->inodes_with_caps);
			oldrealm = ci->i_snap_realm;
			ci->i_snap_realm = realm;
			spin_unlock(&realm->inodes_with_caps_lock);
			spin_unlock(&ci->i_ceph_lock);

			ceph_get_snap_realm(mdsc, realm);
			ceph_put_snap_realm(mdsc, oldrealm);

			iput(inode);
			continue;

skip_inode:
			spin_unlock(&ci->i_ceph_lock);
			iput(inode);
		}

		/* we may have taken some of the old realm's children. */
		for (i = 0; i < num_split_realms; i++) {
			struct ceph_snap_realm *child =
				ceph_lookup_snap_realm(mdsc,
					   le64_to_cpu(split_realms[i]));
			if (!child)
				continue;
			adjust_snap_realm_parent(mdsc, child, realm->ino);
		}
	}

	/*
	 * update using the provided snap trace. if we are deleting a
	 * snap, we can avoid queueing cap_snaps.
	 */
	ceph_update_snap_trace(mdsc, p, e,
			       op == CEPH_SNAP_OP_DESTROY);

	if (op == CEPH_SNAP_OP_SPLIT)
		/* we took a reference when we created the realm, above */
		ceph_put_snap_realm(mdsc, realm);

	__cleanup_empty_realms(mdsc);

	up_write(&mdsc->snap_rwsem);

	flush_snaps(mdsc);
	return;

bad:
	pr_err("corrupt snap message from mds%d\n", mds);
	ceph_msg_dump(msg);
out:
	if (locked_rwsem)
		up_write(&mdsc->snap_rwsem);
	return;
}
/************************************************************/
/* ../linux-3.17/fs/ceph/snap.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

// #include "super.h"
// #include "mds_client.h"

// #include <linux/ceph/decode.h>

#include <linux/xattr.h>
#include <linux/posix_acl_xattr.h>
// #include <linux/slab.h>

#define XATTR_CEPH_PREFIX "ceph."
#define XATTR_CEPH_PREFIX_LEN (sizeof (XATTR_CEPH_PREFIX) - 1)

static int __remove_xattr(struct ceph_inode_info *ci,
			  struct ceph_inode_xattr *xattr);

/*
 * List of handlers for synthetic system.* attributes. Other
 * attributes are handled directly.
 */
const struct xattr_handler *ceph_xattr_handlers[] = {
#ifdef CONFIG_CEPH_FS_POSIX_ACL
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
#endif
	NULL,
};

static bool ceph_is_valid_xattr(const char *name)
{
	return !strncmp(name, XATTR_CEPH_PREFIX, XATTR_CEPH_PREFIX_LEN) ||
	       !strncmp(name, XATTR_SECURITY_PREFIX,
			XATTR_SECURITY_PREFIX_LEN) ||
	       !strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN) ||
	       !strncmp(name, XATTR_TRUSTED_PREFIX, XATTR_TRUSTED_PREFIX_LEN) ||
	       !strncmp(name, XATTR_USER_PREFIX, XATTR_USER_PREFIX_LEN);
}

/*
 * These define virtual xattrs exposing the recursive directory
 * statistics and layout metadata.
 */
struct ceph_vxattr {
	char *name;
	size_t name_size;	/* strlen(name) + 1 (for '\0') */
	size_t (*getxattr_cb)(struct ceph_inode_info *ci, char *val,
			      size_t size);
	bool readonly, hidden;
	bool (*exists_cb)(struct ceph_inode_info *ci);
};

/* layouts */

static bool ceph_vxattrcb_layout_exists(struct ceph_inode_info *ci)
{
	size_t s;
	char *p = (char *)&ci->i_layout;

	for (s = 0; s < sizeof(ci->i_layout); s++, p++)
		if (*p)
			return true;
	return false;
}

static size_t ceph_vxattrcb_layout(struct ceph_inode_info *ci, char *val,
				   size_t size)
{
	int ret;
	struct ceph_fs_client *fsc = ceph_sb_to_client(ci->vfs_inode.i_sb);
	struct ceph_osd_client *osdc = &fsc->client->osdc;
	s64 pool = ceph_file_layout_pg_pool(ci->i_layout);
	const char *pool_name;
	char buf[128];

	dout("ceph_vxattrcb_layout %p\n", &ci->vfs_inode);
	down_read(&osdc->map_sem);
	pool_name = ceph_pg_pool_name_by_id(osdc->osdmap, pool);
	if (pool_name) {
		size_t len = strlen(pool_name);
		ret = snprintf(buf, sizeof(buf),
		"stripe_unit=%lld stripe_count=%lld object_size=%lld pool=",
		(unsigned long long)ceph_file_layout_su(ci->i_layout),
		(unsigned long long)ceph_file_layout_stripe_count(ci->i_layout),
	        (unsigned long long)ceph_file_layout_object_size(ci->i_layout));
		if (!size) {
			ret += len;
		} else if (ret + len > size) {
			ret = -ERANGE;
		} else {
			memcpy(val, buf, ret);
			memcpy(val + ret, pool_name, len);
			ret += len;
		}
	} else {
		ret = snprintf(buf, sizeof(buf),
		"stripe_unit=%lld stripe_count=%lld object_size=%lld pool=%lld",
		(unsigned long long)ceph_file_layout_su(ci->i_layout),
		(unsigned long long)ceph_file_layout_stripe_count(ci->i_layout),
	        (unsigned long long)ceph_file_layout_object_size(ci->i_layout),
		(unsigned long long)pool);
		if (size) {
			if (ret <= size)
				memcpy(val, buf, ret);
			else
				ret = -ERANGE;
		}
	}
	up_read(&osdc->map_sem);
	return ret;
}

static size_t ceph_vxattrcb_layout_stripe_unit(struct ceph_inode_info *ci,
					       char *val, size_t size)
{
	return snprintf(val, size, "%lld",
			(unsigned long long)ceph_file_layout_su(ci->i_layout));
}

static size_t ceph_vxattrcb_layout_stripe_count(struct ceph_inode_info *ci,
						char *val, size_t size)
{
	return snprintf(val, size, "%lld",
	       (unsigned long long)ceph_file_layout_stripe_count(ci->i_layout));
}

static size_t ceph_vxattrcb_layout_object_size(struct ceph_inode_info *ci,
					       char *val, size_t size)
{
	return snprintf(val, size, "%lld",
	       (unsigned long long)ceph_file_layout_object_size(ci->i_layout));
}

static size_t ceph_vxattrcb_layout_pool(struct ceph_inode_info *ci,
					char *val, size_t size)
{
	int ret;
	struct ceph_fs_client *fsc = ceph_sb_to_client(ci->vfs_inode.i_sb);
	struct ceph_osd_client *osdc = &fsc->client->osdc;
	s64 pool = ceph_file_layout_pg_pool(ci->i_layout);
	const char *pool_name;

	down_read(&osdc->map_sem);
	pool_name = ceph_pg_pool_name_by_id(osdc->osdmap, pool);
	if (pool_name)
		ret = snprintf(val, size, "%s", pool_name);
	else
		ret = snprintf(val, size, "%lld", (unsigned long long)pool);
	up_read(&osdc->map_sem);
	return ret;
}

/* directories */

static size_t ceph_vxattrcb_dir_entries(struct ceph_inode_info *ci, char *val,
					size_t size)
{
	return snprintf(val, size, "%lld", ci->i_files + ci->i_subdirs);
}

static size_t ceph_vxattrcb_dir_files(struct ceph_inode_info *ci, char *val,
				      size_t size)
{
	return snprintf(val, size, "%lld", ci->i_files);
}

static size_t ceph_vxattrcb_dir_subdirs(struct ceph_inode_info *ci, char *val,
					size_t size)
{
	return snprintf(val, size, "%lld", ci->i_subdirs);
}

static size_t ceph_vxattrcb_dir_rentries(struct ceph_inode_info *ci, char *val,
					 size_t size)
{
	return snprintf(val, size, "%lld", ci->i_rfiles + ci->i_rsubdirs);
}

static size_t ceph_vxattrcb_dir_rfiles(struct ceph_inode_info *ci, char *val,
				       size_t size)
{
	return snprintf(val, size, "%lld", ci->i_rfiles);
}

static size_t ceph_vxattrcb_dir_rsubdirs(struct ceph_inode_info *ci, char *val,
					 size_t size)
{
	return snprintf(val, size, "%lld", ci->i_rsubdirs);
}

static size_t ceph_vxattrcb_dir_rbytes(struct ceph_inode_info *ci, char *val,
				       size_t size)
{
	return snprintf(val, size, "%lld", ci->i_rbytes);
}

static size_t ceph_vxattrcb_dir_rctime(struct ceph_inode_info *ci, char *val,
				       size_t size)
{
	return snprintf(val, size, "%ld.09%ld", (long)ci->i_rctime.tv_sec,
			(long)ci->i_rctime.tv_nsec);
}


#define CEPH_XATTR_NAME(_type, _name)	XATTR_CEPH_PREFIX #_type "." #_name
#define CEPH_XATTR_NAME2(_type, _name, _name2)	\
	XATTR_CEPH_PREFIX #_type "." #_name "." #_name2

#define XATTR_NAME_CEPH(_type, _name)					\
	{								\
		.name = CEPH_XATTR_NAME(_type, _name),			\
		.name_size = sizeof (CEPH_XATTR_NAME(_type, _name)), \
		.getxattr_cb = ceph_vxattrcb_ ## _type ## _ ## _name, \
		.readonly = true,				\
		.hidden = false,				\
		.exists_cb = NULL,			\
	}
#define XATTR_LAYOUT_FIELD(_type, _name, _field)			\
	{								\
		.name = CEPH_XATTR_NAME2(_type, _name, _field),	\
		.name_size = sizeof (CEPH_XATTR_NAME2(_type, _name, _field)), \
		.getxattr_cb = ceph_vxattrcb_ ## _name ## _ ## _field, \
		.readonly = false,				\
		.hidden = true,			\
		.exists_cb = ceph_vxattrcb_layout_exists,	\
	}

static struct ceph_vxattr ceph_dir_vxattrs[] = {
	{
		.name = "ceph.dir.layout",
		.name_size = sizeof("ceph.dir.layout"),
		.getxattr_cb = ceph_vxattrcb_layout,
		.readonly = false,
		.hidden = true,
		.exists_cb = ceph_vxattrcb_layout_exists,
	},
	XATTR_LAYOUT_FIELD(dir, layout, stripe_unit),
	XATTR_LAYOUT_FIELD(dir, layout, stripe_count),
	XATTR_LAYOUT_FIELD(dir, layout, object_size),
	XATTR_LAYOUT_FIELD(dir, layout, pool),
	XATTR_NAME_CEPH(dir, entries),
	XATTR_NAME_CEPH(dir, files),
	XATTR_NAME_CEPH(dir, subdirs),
	XATTR_NAME_CEPH(dir, rentries),
	XATTR_NAME_CEPH(dir, rfiles),
	XATTR_NAME_CEPH(dir, rsubdirs),
	XATTR_NAME_CEPH(dir, rbytes),
	XATTR_NAME_CEPH(dir, rctime),
	{ .name = NULL, 0 }	/* Required table terminator */
};
static size_t ceph_dir_vxattrs_name_size;	/* total size of all names */

/* files */

static struct ceph_vxattr ceph_file_vxattrs[] = {
	{
		.name = "ceph.file.layout",
		.name_size = sizeof("ceph.file.layout"),
		.getxattr_cb = ceph_vxattrcb_layout,
		.readonly = false,
		.hidden = true,
		.exists_cb = ceph_vxattrcb_layout_exists,
	},
	XATTR_LAYOUT_FIELD(file, layout, stripe_unit),
	XATTR_LAYOUT_FIELD(file, layout, stripe_count),
	XATTR_LAYOUT_FIELD(file, layout, object_size),
	XATTR_LAYOUT_FIELD(file, layout, pool),
	{ .name = NULL, 0 }	/* Required table terminator */
};
static size_t ceph_file_vxattrs_name_size;	/* total size of all names */

static struct ceph_vxattr *ceph_inode_vxattrs(struct inode *inode)
{
	if (S_ISDIR(inode->i_mode))
		return ceph_dir_vxattrs;
	else if (S_ISREG(inode->i_mode))
		return ceph_file_vxattrs;
	return NULL;
}

static size_t ceph_vxattrs_name_size(struct ceph_vxattr *vxattrs)
{
	if (vxattrs == ceph_dir_vxattrs)
		return ceph_dir_vxattrs_name_size;
	if (vxattrs == ceph_file_vxattrs)
		return ceph_file_vxattrs_name_size;
	BUG();

	return 0;
}

/*
 * Compute the aggregate size (including terminating '\0') of all
 * virtual extended attribute names in the given vxattr table.
 */
static size_t __init vxattrs_name_size(struct ceph_vxattr *vxattrs)
{
	struct ceph_vxattr *vxattr;
	size_t size = 0;

	for (vxattr = vxattrs; vxattr->name; vxattr++)
		if (!vxattr->hidden)
			size += vxattr->name_size;

	return size;
}

/* Routines called at initialization and exit time */

void __init ceph_xattr_init(void)
{
	ceph_dir_vxattrs_name_size = vxattrs_name_size(ceph_dir_vxattrs);
	ceph_file_vxattrs_name_size = vxattrs_name_size(ceph_file_vxattrs);
}

void ceph_xattr_exit(void)
{
	ceph_dir_vxattrs_name_size = 0;
	ceph_file_vxattrs_name_size = 0;
}

static struct ceph_vxattr *ceph_match_vxattr(struct inode *inode,
						const char *name)
{
	struct ceph_vxattr *vxattr = ceph_inode_vxattrs(inode);

	if (vxattr) {
		while (vxattr->name) {
			if (!strcmp(vxattr->name, name))
				return vxattr;
			vxattr++;
		}
	}

	return NULL;
}

static int __set_xattr(struct ceph_inode_info *ci,
			   const char *name, int name_len,
			   const char *val, int val_len,
			   int flags, int update_xattr,
			   struct ceph_inode_xattr **newxattr)
{
	struct rb_node **p;
	struct rb_node *parent = NULL;
	struct ceph_inode_xattr *xattr = NULL;
	int c;
	int new = 0;

	p = &ci->i_xattrs.index.rb_node;
	while (*p) {
		parent = *p;
		xattr = rb_entry(parent, struct ceph_inode_xattr, node);
		c = strncmp(name, xattr->name, min(name_len, xattr->name_len));
		if (c < 0)
			p = &(*p)->rb_left;
		else if (c > 0)
			p = &(*p)->rb_right;
		else {
			if (name_len == xattr->name_len)
				break;
			else if (name_len < xattr->name_len)
				p = &(*p)->rb_left;
			else
				p = &(*p)->rb_right;
		}
		xattr = NULL;
	}

	if (update_xattr) {
		int err = 0;
		if (xattr && (flags & XATTR_CREATE))
			err = -EEXIST;
		else if (!xattr && (flags & XATTR_REPLACE))
			err = -ENODATA;
		if (err) {
			kfree(name);
			kfree(val);
			return err;
		}
		if (update_xattr < 0) {
			if (xattr)
				__remove_xattr(ci, xattr);
			kfree(name);
			return 0;
		}
	}

	if (!xattr) {
		new = 1;
		xattr = *newxattr;
		xattr->name = name;
		xattr->name_len = name_len;
		xattr->should_free_name = update_xattr;

		ci->i_xattrs.count++;
		dout("__set_xattr count=%d\n", ci->i_xattrs.count);
	} else {
		kfree(*newxattr);
		*newxattr = NULL;
		if (xattr->should_free_val)
			kfree((void *)xattr->val);

		if (update_xattr) {
			kfree((void *)name);
			name = xattr->name;
		}
		ci->i_xattrs.names_size -= xattr->name_len;
		ci->i_xattrs.vals_size -= xattr->val_len;
	}
	ci->i_xattrs.names_size += name_len;
	ci->i_xattrs.vals_size += val_len;
	if (val)
		xattr->val = val;
	else
		xattr->val = "";

	xattr->val_len = val_len;
	xattr->dirty = update_xattr;
	xattr->should_free_val = (val && update_xattr);

	if (new) {
		rb_link_node(&xattr->node, parent, p);
		rb_insert_color(&xattr->node, &ci->i_xattrs.index);
		dout("__set_xattr_val p=%p\n", p);
	}

	dout("__set_xattr_val added %llx.%llx xattr %p %s=%.*s\n",
	     ceph_vinop(&ci->vfs_inode), xattr, name, val_len, val);

	return 0;
}

static struct ceph_inode_xattr *__get_xattr(struct ceph_inode_info *ci,
			   const char *name)
{
	struct rb_node **p;
	struct rb_node *parent = NULL;
	struct ceph_inode_xattr *xattr = NULL;
	int name_len = strlen(name);
	int c;

	p = &ci->i_xattrs.index.rb_node;
	while (*p) {
		parent = *p;
		xattr = rb_entry(parent, struct ceph_inode_xattr, node);
		c = strncmp(name, xattr->name, xattr->name_len);
		if (c == 0 && name_len > xattr->name_len)
			c = 1;
		if (c < 0)
			p = &(*p)->rb_left;
		else if (c > 0)
			p = &(*p)->rb_right;
		else {
			dout("__get_xattr %s: found %.*s\n", name,
			     xattr->val_len, xattr->val);
			return xattr;
		}
	}

	dout("__get_xattr %s: not found\n", name);

	return NULL;
}

static void __free_xattr(struct ceph_inode_xattr *xattr)
{
	BUG_ON(!xattr);

	if (xattr->should_free_name)
		kfree((void *)xattr->name);
	if (xattr->should_free_val)
		kfree((void *)xattr->val);

	kfree(xattr);
}

static int __remove_xattr(struct ceph_inode_info *ci,
			  struct ceph_inode_xattr *xattr)
{
	if (!xattr)
		return -ENODATA;

	rb_erase(&xattr->node, &ci->i_xattrs.index);

	if (xattr->should_free_name)
		kfree((void *)xattr->name);
	if (xattr->should_free_val)
		kfree((void *)xattr->val);

	ci->i_xattrs.names_size -= xattr->name_len;
	ci->i_xattrs.vals_size -= xattr->val_len;
	ci->i_xattrs.count--;
	kfree(xattr);

	return 0;
}

static int __remove_xattr_by_name(struct ceph_inode_info *ci,
			   const char *name)
{
	struct rb_node **p;
	struct ceph_inode_xattr *xattr;
	int err;

	p = &ci->i_xattrs.index.rb_node;
	xattr = __get_xattr(ci, name);
	err = __remove_xattr(ci, xattr);
	return err;
}

static char *__copy_xattr_names(struct ceph_inode_info *ci,
				char *dest)
{
	struct rb_node *p;
	struct ceph_inode_xattr *xattr = NULL;

	p = rb_first(&ci->i_xattrs.index);
	dout("__copy_xattr_names count=%d\n", ci->i_xattrs.count);

	while (p) {
		xattr = rb_entry(p, struct ceph_inode_xattr, node);
		memcpy(dest, xattr->name, xattr->name_len);
		dest[xattr->name_len] = '\0';

		dout("dest=%s %p (%s) (%d/%d)\n", dest, xattr, xattr->name,
		     xattr->name_len, ci->i_xattrs.names_size);

		dest += xattr->name_len + 1;
		p = rb_next(p);
	}

	return dest;
}

void __ceph_destroy_xattrs(struct ceph_inode_info *ci)
{
	struct rb_node *p, *tmp;
	struct ceph_inode_xattr *xattr = NULL;

	p = rb_first(&ci->i_xattrs.index);

	dout("__ceph_destroy_xattrs p=%p\n", p);

	while (p) {
		xattr = rb_entry(p, struct ceph_inode_xattr, node);
		tmp = p;
		p = rb_next(tmp);
		dout("__ceph_destroy_xattrs next p=%p (%.*s)\n", p,
		     xattr->name_len, xattr->name);
		rb_erase(tmp, &ci->i_xattrs.index);

		__free_xattr(xattr);
	}

	ci->i_xattrs.names_size = 0;
	ci->i_xattrs.vals_size = 0;
	ci->i_xattrs.index_version = 0;
	ci->i_xattrs.count = 0;
	ci->i_xattrs.index = RB_ROOT;
}

static int __build_xattrs(struct inode *inode)
	__releases(ci->i_ceph_lock)
	__acquires(ci->i_ceph_lock)
{
	u32 namelen;
	u32 numattr = 0;
	void *p, *end;
	u32 len;
	const char *name, *val;
	struct ceph_inode_info *ci = ceph_inode(inode);
	int xattr_version;
	struct ceph_inode_xattr **xattrs = NULL;
	int err = 0;
	int i;

	dout("__build_xattrs() len=%d\n",
	     ci->i_xattrs.blob ? (int)ci->i_xattrs.blob->vec.iov_len : 0);

	if (ci->i_xattrs.index_version >= ci->i_xattrs.version)
		return 0; /* already built */

	__ceph_destroy_xattrs(ci);

start:
	/* updated internal xattr rb tree */
	if (ci->i_xattrs.blob && ci->i_xattrs.blob->vec.iov_len > 4) {
		p = ci->i_xattrs.blob->vec.iov_base;
		end = p + ci->i_xattrs.blob->vec.iov_len;
		ceph_decode_32_safe(&p, end, numattr, bad);
		xattr_version = ci->i_xattrs.version;
		spin_unlock(&ci->i_ceph_lock);

		xattrs = kcalloc(numattr, sizeof(struct ceph_inode_xattr *),
				 GFP_NOFS);
		err = -ENOMEM;
		if (!xattrs)
			goto bad_lock;

		for (i = 0; i < numattr; i++) {
			xattrs[i] = kmalloc(sizeof(struct ceph_inode_xattr),
					    GFP_NOFS);
			if (!xattrs[i])
				goto bad_lock;
		}

		spin_lock(&ci->i_ceph_lock);
		if (ci->i_xattrs.version != xattr_version) {
			/* lost a race, retry */
			for (i = 0; i < numattr; i++)
				kfree(xattrs[i]);
			kfree(xattrs);
			xattrs = NULL;
			goto start;
		}
		err = -EIO;
		while (numattr--) {
			ceph_decode_32_safe(&p, end, len, bad);
			namelen = len;
			name = p;
			p += len;
			ceph_decode_32_safe(&p, end, len, bad);
			val = p;
			p += len;

			err = __set_xattr(ci, name, namelen, val, len,
					  0, 0, &xattrs[numattr]);

			if (err < 0)
				goto bad;
		}
		kfree(xattrs);
	}
	ci->i_xattrs.index_version = ci->i_xattrs.version;
	ci->i_xattrs.dirty = false;

	return err;
bad_lock:
	spin_lock(&ci->i_ceph_lock);
bad:
	if (xattrs) {
		for (i = 0; i < numattr; i++)
			kfree(xattrs[i]);
		kfree(xattrs);
	}
	ci->i_xattrs.names_size = 0;
	return err;
}

static int __get_required_blob_size(struct ceph_inode_info *ci, int name_size,
				    int val_size)
{
	/*
	 * 4 bytes for the length, and additional 4 bytes per each xattr name,
	 * 4 bytes per each value
	 */
	int size = 4 + ci->i_xattrs.count*(4 + 4) +
			     ci->i_xattrs.names_size +
			     ci->i_xattrs.vals_size;
	dout("__get_required_blob_size c=%d names.size=%d vals.size=%d\n",
	     ci->i_xattrs.count, ci->i_xattrs.names_size,
	     ci->i_xattrs.vals_size);

	if (name_size)
		size += 4 + 4 + name_size + val_size;

	return size;
}

/*
 * If there are dirty xattrs, reencode xattrs into the prealloc_blob
 * and swap into place.
 */
void __ceph_build_xattrs_blob(struct ceph_inode_info *ci)
{
	struct rb_node *p;
	struct ceph_inode_xattr *xattr = NULL;
	void *dest;

	dout("__build_xattrs_blob %p\n", &ci->vfs_inode);
	if (ci->i_xattrs.dirty) {
		int need = __get_required_blob_size(ci, 0, 0);

		BUG_ON(need > ci->i_xattrs.prealloc_blob->alloc_len);

		p = rb_first(&ci->i_xattrs.index);
		dest = ci->i_xattrs.prealloc_blob->vec.iov_base;

		ceph_encode_32(&dest, ci->i_xattrs.count);
		while (p) {
			xattr = rb_entry(p, struct ceph_inode_xattr, node);

			ceph_encode_32(&dest, xattr->name_len);
			memcpy(dest, xattr->name, xattr->name_len);
			dest += xattr->name_len;
			ceph_encode_32(&dest, xattr->val_len);
			memcpy(dest, xattr->val, xattr->val_len);
			dest += xattr->val_len;

			p = rb_next(p);
		}

		/* adjust buffer len; it may be larger than we need */
		ci->i_xattrs.prealloc_blob->vec.iov_len =
			dest - ci->i_xattrs.prealloc_blob->vec.iov_base;

		if (ci->i_xattrs.blob)
			ceph_buffer_put(ci->i_xattrs.blob);
		ci->i_xattrs.blob = ci->i_xattrs.prealloc_blob;
		ci->i_xattrs.prealloc_blob = NULL;
		ci->i_xattrs.dirty = false;
		ci->i_xattrs.version++;
	}
}

ssize_t __ceph_getxattr(struct inode *inode, const char *name, void *value,
		      size_t size)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int err;
	struct ceph_inode_xattr *xattr;
	struct ceph_vxattr *vxattr = NULL;

	if (!ceph_is_valid_xattr(name))
		return -ENODATA;

	/* let's see if a virtual xattr was requested */
	vxattr = ceph_match_vxattr(inode, name);
	if (vxattr && !(vxattr->exists_cb && !vxattr->exists_cb(ci))) {
		err = vxattr->getxattr_cb(ci, value, size);
		return err;
	}

	spin_lock(&ci->i_ceph_lock);
	dout("getxattr %p ver=%lld index_ver=%lld\n", inode,
	     ci->i_xattrs.version, ci->i_xattrs.index_version);

	if (__ceph_caps_issued_mask(ci, CEPH_CAP_XATTR_SHARED, 1) &&
	    (ci->i_xattrs.index_version >= ci->i_xattrs.version)) {
		goto get_xattr;
	} else {
		spin_unlock(&ci->i_ceph_lock);
		/* get xattrs from mds (if we don't already have them) */
		err = ceph_do_getattr(inode, CEPH_STAT_CAP_XATTR);
		if (err)
			return err;
	}

	spin_lock(&ci->i_ceph_lock);

	err = __build_xattrs(inode);
	if (err < 0)
		goto out;

get_xattr:
	err = -ENODATA;  /* == ENOATTR */
	xattr = __get_xattr(ci, name);
	if (!xattr)
		goto out;

	err = -ERANGE;
	if (size && size < xattr->val_len)
		goto out;

	err = xattr->val_len;
	if (size == 0)
		goto out;

	memcpy(value, xattr->val, xattr->val_len);

out:
	spin_unlock(&ci->i_ceph_lock);
	return err;
}

ssize_t ceph_getxattr(struct dentry *dentry, const char *name, void *value,
		      size_t size)
{
	if (!strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return generic_getxattr(dentry, name, value, size);

	return __ceph_getxattr(dentry->d_inode, name, value, size);
}

ssize_t ceph_listxattr(struct dentry *dentry, char *names, size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_vxattr *vxattrs = ceph_inode_vxattrs(inode);
	u32 vir_namelen = 0;
	u32 namelen;
	int err;
	u32 len;
	int i;

	spin_lock(&ci->i_ceph_lock);
	dout("listxattr %p ver=%lld index_ver=%lld\n", inode,
	     ci->i_xattrs.version, ci->i_xattrs.index_version);

	if (__ceph_caps_issued_mask(ci, CEPH_CAP_XATTR_SHARED, 1) &&
	    (ci->i_xattrs.index_version >= ci->i_xattrs.version)) {
		goto list_xattr;
	} else {
		spin_unlock(&ci->i_ceph_lock);
		err = ceph_do_getattr(inode, CEPH_STAT_CAP_XATTR);
		if (err)
			return err;
	}

	spin_lock(&ci->i_ceph_lock);

	err = __build_xattrs(inode);
	if (err < 0)
		goto out;

list_xattr:
	/*
	 * Start with virtual dir xattr names (if any) (including
	 * terminating '\0' characters for each).
	 */
	vir_namelen = ceph_vxattrs_name_size(vxattrs);

	/* adding 1 byte per each variable due to the null termination */
	namelen = ci->i_xattrs.names_size + ci->i_xattrs.count;
	err = -ERANGE;
	if (size && vir_namelen + namelen > size)
		goto out;

	err = namelen + vir_namelen;
	if (size == 0)
		goto out;

	names = __copy_xattr_names(ci, names);

	/* virtual xattr names, too */
	err = namelen;
	if (vxattrs) {
		for (i = 0; vxattrs[i].name; i++) {
			if (!vxattrs[i].hidden &&
			    !(vxattrs[i].exists_cb &&
			      !vxattrs[i].exists_cb(ci))) {
				len = sprintf(names, "%s", vxattrs[i].name);
				names += len + 1;
				err += len + 1;
			}
		}
	}

out:
	spin_unlock(&ci->i_ceph_lock);
	return err;
}

static int ceph_sync_setxattr(struct dentry *dentry, const char *name,
			      const char *value, size_t size, int flags)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dentry->d_sb);
	struct inode *inode = dentry->d_inode;
	struct ceph_inode_info *ci = ceph_inode(inode);
	struct ceph_mds_request *req;
	struct ceph_mds_client *mdsc = fsc->mdsc;
	int err;
	int i, nr_pages;
	struct page **pages = NULL;
	void *kaddr;

	/* copy value into some pages */
	nr_pages = calc_pages_for(0, size);
	if (nr_pages) {
		pages = kmalloc(sizeof(pages[0])*nr_pages, GFP_NOFS);
		if (!pages)
			return -ENOMEM;
		err = -ENOMEM;
		for (i = 0; i < nr_pages; i++) {
			pages[i] = __page_cache_alloc(GFP_NOFS);
			if (!pages[i]) {
				nr_pages = i;
				goto out;
			}
			kaddr = kmap(pages[i]);
			memcpy(kaddr, value + i*PAGE_CACHE_SIZE,
			       min(PAGE_CACHE_SIZE, size-i*PAGE_CACHE_SIZE));
		}
	}

	dout("setxattr value=%.*s\n", (int)size, value);

	if (!value)
		flags |= CEPH_XATTR_REMOVE;

	/* do request */
	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_SETXATTR,
				       USE_AUTH_MDS);
	if (IS_ERR(req)) {
		err = PTR_ERR(req);
		goto out;
	}
	req->r_inode = inode;
	ihold(inode);
	req->r_inode_drop = CEPH_CAP_XATTR_SHARED;
	req->r_num_caps = 1;
	req->r_args.setxattr.flags = cpu_to_le32(flags);
	req->r_path2 = kstrdup(name, GFP_NOFS);

	req->r_pages = pages;
	req->r_num_pages = nr_pages;
	req->r_data_len = size;

	dout("xattr.ver (before): %lld\n", ci->i_xattrs.version);
	err = ceph_mdsc_do_request(mdsc, NULL, req);
	ceph_mdsc_put_request(req);
	dout("xattr.ver (after): %lld\n", ci->i_xattrs.version);

out:
	if (pages) {
		for (i = 0; i < nr_pages; i++)
			__free_page(pages[i]);
		kfree(pages);
	}
	return err;
}

int __ceph_setxattr(struct dentry *dentry, const char *name,
			const void *value, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct ceph_vxattr *vxattr;
	struct ceph_inode_info *ci = ceph_inode(inode);
	int issued;
	int err;
	int dirty = 0;
	int name_len = strlen(name);
	int val_len = size;
	char *newname = NULL;
	char *newval = NULL;
	struct ceph_inode_xattr *xattr = NULL;
	int required_blob_size;

	if (!ceph_is_valid_xattr(name))
		return -EOPNOTSUPP;

	vxattr = ceph_match_vxattr(inode, name);
	if (vxattr && vxattr->readonly)
		return -EOPNOTSUPP;

	/* pass any unhandled ceph.* xattrs through to the MDS */
	if (!strncmp(name, XATTR_CEPH_PREFIX, XATTR_CEPH_PREFIX_LEN))
		goto do_sync_unlocked;

	/* preallocate memory for xattr name, value, index node */
	err = -ENOMEM;
	newname = kmemdup(name, name_len + 1, GFP_NOFS);
	if (!newname)
		goto out;

	if (val_len) {
		newval = kmemdup(value, val_len, GFP_NOFS);
		if (!newval)
			goto out;
	}

	xattr = kmalloc(sizeof(struct ceph_inode_xattr), GFP_NOFS);
	if (!xattr)
		goto out;

	spin_lock(&ci->i_ceph_lock);
retry:
	issued = __ceph_caps_issued(ci, NULL);
	dout("setxattr %p issued %s\n", inode, ceph_cap_string(issued));
	if (!(issued & CEPH_CAP_XATTR_EXCL))
		goto do_sync;
	__build_xattrs(inode);

	required_blob_size = __get_required_blob_size(ci, name_len, val_len);

	if (!ci->i_xattrs.prealloc_blob ||
	    required_blob_size > ci->i_xattrs.prealloc_blob->alloc_len) {
		struct ceph_buffer *blob;

		spin_unlock(&ci->i_ceph_lock);
		dout(" preaallocating new blob size=%d\n", required_blob_size);
		blob = ceph_buffer_new(required_blob_size, GFP_NOFS);
		if (!blob)
			goto out;
		spin_lock(&ci->i_ceph_lock);
		if (ci->i_xattrs.prealloc_blob)
			ceph_buffer_put(ci->i_xattrs.prealloc_blob);
		ci->i_xattrs.prealloc_blob = blob;
		goto retry;
	}

	err = __set_xattr(ci, newname, name_len, newval, val_len,
			  flags, value ? 1 : -1, &xattr);

	if (!err) {
		dirty = __ceph_mark_dirty_caps(ci, CEPH_CAP_XATTR_EXCL);
		ci->i_xattrs.dirty = true;
		inode->i_ctime = CURRENT_TIME;
	}

	spin_unlock(&ci->i_ceph_lock);
	if (dirty)
		__mark_inode_dirty(inode, dirty);
	return err;

do_sync:
	spin_unlock(&ci->i_ceph_lock);
do_sync_unlocked:
	err = ceph_sync_setxattr(dentry, name, value, size, flags);
out:
	kfree(newname);
	kfree(newval);
	kfree(xattr);
	return err;
}

int ceph_setxattr(struct dentry *dentry, const char *name,
		  const void *value, size_t size, int flags)
{
	if (ceph_snap(dentry->d_inode) != CEPH_NOSNAP)
		return -EROFS;

	if (!strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return generic_setxattr(dentry, name, value, size, flags);

	return __ceph_setxattr(dentry, name, value, size, flags);
}

static int ceph_send_removexattr(struct dentry *dentry, const char *name)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(dentry->d_sb);
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct inode *inode = dentry->d_inode;
	struct ceph_mds_request *req;
	int err;

	req = ceph_mdsc_create_request(mdsc, CEPH_MDS_OP_RMXATTR,
				       USE_AUTH_MDS);
	if (IS_ERR(req))
		return PTR_ERR(req);
	req->r_inode = inode;
	ihold(inode);
	req->r_inode_drop = CEPH_CAP_XATTR_SHARED;
	req->r_num_caps = 1;
	req->r_path2 = kstrdup(name, GFP_NOFS);

	err = ceph_mdsc_do_request(mdsc, NULL, req);
	ceph_mdsc_put_request(req);
	return err;
}

int __ceph_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
	struct ceph_vxattr *vxattr;
	struct ceph_inode_info *ci = ceph_inode(inode);
	int issued;
	int err;
	int required_blob_size;
	int dirty;

	if (!ceph_is_valid_xattr(name))
		return -EOPNOTSUPP;

	vxattr = ceph_match_vxattr(inode, name);
	if (vxattr && vxattr->readonly)
		return -EOPNOTSUPP;

	/* pass any unhandled ceph.* xattrs through to the MDS */
	if (!strncmp(name, XATTR_CEPH_PREFIX, XATTR_CEPH_PREFIX_LEN))
		goto do_sync_unlocked;

	err = -ENOMEM;
	spin_lock(&ci->i_ceph_lock);
retry:
	issued = __ceph_caps_issued(ci, NULL);
	dout("removexattr %p issued %s\n", inode, ceph_cap_string(issued));

	if (!(issued & CEPH_CAP_XATTR_EXCL))
		goto do_sync;
	__build_xattrs(inode);

	required_blob_size = __get_required_blob_size(ci, 0, 0);

	if (!ci->i_xattrs.prealloc_blob ||
	    required_blob_size > ci->i_xattrs.prealloc_blob->alloc_len) {
		struct ceph_buffer *blob;

		spin_unlock(&ci->i_ceph_lock);
		dout(" preaallocating new blob size=%d\n", required_blob_size);
		blob = ceph_buffer_new(required_blob_size, GFP_NOFS);
		if (!blob)
			goto out;
		spin_lock(&ci->i_ceph_lock);
		if (ci->i_xattrs.prealloc_blob)
			ceph_buffer_put(ci->i_xattrs.prealloc_blob);
		ci->i_xattrs.prealloc_blob = blob;
		goto retry;
	}

	err = __remove_xattr_by_name(ceph_inode(inode), name);

	dirty = __ceph_mark_dirty_caps(ci, CEPH_CAP_XATTR_EXCL);
	ci->i_xattrs.dirty = true;
	inode->i_ctime = CURRENT_TIME;
	spin_unlock(&ci->i_ceph_lock);
	if (dirty)
		__mark_inode_dirty(inode, dirty);
	return err;
do_sync:
	spin_unlock(&ci->i_ceph_lock);
do_sync_unlocked:
	err = ceph_send_removexattr(dentry, name);
out:
	return err;
}

int ceph_removexattr(struct dentry *dentry, const char *name)
{
	if (ceph_snap(dentry->d_inode) != CEPH_NOSNAP)
		return -EROFS;

	if (!strncmp(name, XATTR_SYSTEM_PREFIX, XATTR_SYSTEM_PREFIX_LEN))
		return generic_removexattr(dentry, name);

	return __ceph_removexattr(dentry, name);
}
/************************************************************/
/* ../linux-3.17/fs/ceph/xattr.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

// #include <linux/fs.h>
// #include <linux/wait.h>
// #include <linux/slab.h>
#include <linux/gfp.h>
// #include <linux/sched.h>
#include <linux/debugfs.h>
// #include <linux/seq_file.h>

// #include "super.h"
// #include "mds_client.h"

// #include <linux/ceph/ceph_features.h>
// #include <linux/ceph/messenger.h>
// #include <linux/ceph/decode.h>
// #include <linux/ceph/pagelist.h>
// #include <linux/ceph/auth.h>
// #include <linux/ceph/debugfs.h>

/*
 * A cluster of MDS (metadata server) daemons is responsible for
 * managing the file system namespace (the directory hierarchy and
 * inodes) and for coordinating shared access to storage.  Metadata is
 * partitioning hierarchically across a number of servers, and that
 * partition varies over time as the cluster adjusts the distribution
 * in order to balance load.
 *
 * The MDS client is primarily responsible to managing synchronous
 * metadata requests for operations like open, unlink, and so forth.
 * If there is a MDS failure, we find out about it when we (possibly
 * request and) receive a new MDS map, and can resubmit affected
 * requests.
 *
 * For the most part, though, we take advantage of a lossless
 * communications channel to the MDS, and do not need to worry about
 * timing out or resubmitting requests.
 *
 * We maintain a stateful "session" with each MDS we interact with.
 * Within each session, we sent periodic heartbeat messages to ensure
 * any capabilities or leases we have been issues remain valid.  If
 * the session times out and goes stale, our leases and capabilities
 * are no longer valid.
 */

struct ceph_reconnect_state {
	int nr_caps;
	struct ceph_pagelist *pagelist;
	bool flock;
};

static void __wake_requests(struct ceph_mds_client *mdsc,
			    struct list_head *head);

static const struct ceph_connection_operations mds_con_ops;


/*
 * mds reply parsing
 */

/*
 * parse individual inode info
 */
static int parse_reply_info_in(void **p, void *end,
			       struct ceph_mds_reply_info_in *info,
			       u64 features)
{
	int err = -EIO;

	info->in = *p;
	*p += sizeof(struct ceph_mds_reply_inode) +
		sizeof(*info->in->fragtree.splits) *
		le32_to_cpu(info->in->fragtree.nsplits);

	ceph_decode_32_safe(p, end, info->symlink_len, bad);
	ceph_decode_need(p, end, info->symlink_len, bad);
	info->symlink = *p;
	*p += info->symlink_len;

	if (features & CEPH_FEATURE_DIRLAYOUTHASH)
		ceph_decode_copy_safe(p, end, &info->dir_layout,
				      sizeof(info->dir_layout), bad);
	else
		memset(&info->dir_layout, 0, sizeof(info->dir_layout));

	ceph_decode_32_safe(p, end, info->xattr_len, bad);
	ceph_decode_need(p, end, info->xattr_len, bad);
	info->xattr_data = *p;
	*p += info->xattr_len;
	return 0;
bad:
	return err;
}

/*
 * parse a normal reply, which may contain a (dir+)dentry and/or a
 * target inode.
 */
static int parse_reply_info_trace(void **p, void *end,
				  struct ceph_mds_reply_info_parsed *info,
				  u64 features)
{
	int err;

	if (info->head->is_dentry) {
		err = parse_reply_info_in(p, end, &info->diri, features);
		if (err < 0)
			goto out_bad;

		if (unlikely(*p + sizeof(*info->dirfrag) > end))
			goto bad;
		info->dirfrag = *p;
		*p += sizeof(*info->dirfrag) +
			sizeof(u32)*le32_to_cpu(info->dirfrag->ndist);
		if (unlikely(*p > end))
			goto bad;

		ceph_decode_32_safe(p, end, info->dname_len, bad);
		ceph_decode_need(p, end, info->dname_len, bad);
		info->dname = *p;
		*p += info->dname_len;
		info->dlease = *p;
		*p += sizeof(*info->dlease);
	}

	if (info->head->is_target) {
		err = parse_reply_info_in(p, end, &info->targeti, features);
		if (err < 0)
			goto out_bad;
	}

	if (unlikely(*p != end))
		goto bad;
	return 0;

bad:
	err = -EIO;
out_bad:
	pr_err("problem parsing mds trace %d\n", err);
	return err;
}

/*
 * parse readdir results
 */
static int parse_reply_info_dir(void **p, void *end,
				struct ceph_mds_reply_info_parsed *info,
				u64 features)
{
	u32 num, i = 0;
	int err;

	info->dir_dir = *p;
	if (*p + sizeof(*info->dir_dir) > end)
		goto bad;
	*p += sizeof(*info->dir_dir) +
		sizeof(u32)*le32_to_cpu(info->dir_dir->ndist);
	if (*p > end)
		goto bad;

	ceph_decode_need(p, end, sizeof(num) + 2, bad);
	num = ceph_decode_32(p);
	info->dir_end = ceph_decode_8(p);
	info->dir_complete = ceph_decode_8(p);
	if (num == 0)
		goto done;

	BUG_ON(!info->dir_in);
	info->dir_dname = (void *)(info->dir_in + num);
	info->dir_dname_len = (void *)(info->dir_dname + num);
	info->dir_dlease = (void *)(info->dir_dname_len + num);
	if ((unsigned long)(info->dir_dlease + num) >
	    (unsigned long)info->dir_in + info->dir_buf_size) {
		pr_err("dir contents are larger than expected\n");
		WARN_ON(1);
		goto bad;
	}

	info->dir_nr = num;
	while (num) {
		/* dentry */
		ceph_decode_need(p, end, sizeof(u32)*2, bad);
		info->dir_dname_len[i] = ceph_decode_32(p);
		ceph_decode_need(p, end, info->dir_dname_len[i], bad);
		info->dir_dname[i] = *p;
		*p += info->dir_dname_len[i];
		dout("parsed dir dname '%.*s'\n", info->dir_dname_len[i],
		     info->dir_dname[i]);
		info->dir_dlease[i] = *p;
		*p += sizeof(struct ceph_mds_reply_lease);

		/* inode */
		err = parse_reply_info_in(p, end, &info->dir_in[i], features);
		if (err < 0)
			goto out_bad;
		i++;
		num--;
	}

done:
	if (*p != end)
		goto bad;
	return 0;

bad:
	err = -EIO;
out_bad:
	pr_err("problem parsing dir contents %d\n", err);
	return err;
}

/*
 * parse fcntl F_GETLK results
 */
static int parse_reply_info_filelock(void **p, void *end,
				     struct ceph_mds_reply_info_parsed *info,
				     u64 features)
{
	if (*p + sizeof(*info->filelock_reply) > end)
		goto bad;

	info->filelock_reply = *p;
	*p += sizeof(*info->filelock_reply);

	if (unlikely(*p != end))
		goto bad;
	return 0;

bad:
	return -EIO;
}

/*
 * parse create results
 */
static int parse_reply_info_create(void **p, void *end,
				  struct ceph_mds_reply_info_parsed *info,
				  u64 features)
{
	if (features & CEPH_FEATURE_REPLY_CREATE_INODE) {
		if (*p == end) {
			info->has_create_ino = false;
		} else {
			info->has_create_ino = true;
			info->ino = ceph_decode_64(p);
		}
	}

	if (unlikely(*p != end))
		goto bad;
	return 0;

bad:
	return -EIO;
}

/*
 * parse extra results
 */
static int parse_reply_info_extra(void **p, void *end,
				  struct ceph_mds_reply_info_parsed *info,
				  u64 features)
{
	if (info->head->op == CEPH_MDS_OP_GETFILELOCK)
		return parse_reply_info_filelock(p, end, info, features);
	else if (info->head->op == CEPH_MDS_OP_READDIR ||
		 info->head->op == CEPH_MDS_OP_LSSNAP)
		return parse_reply_info_dir(p, end, info, features);
	else if (info->head->op == CEPH_MDS_OP_CREATE)
		return parse_reply_info_create(p, end, info, features);
	else
		return -EIO;
}

/*
 * parse entire mds reply
 */
static int parse_reply_info(struct ceph_msg *msg,
			    struct ceph_mds_reply_info_parsed *info,
			    u64 features)
{
	void *p, *end;
	u32 len;
	int err;

	info->head = msg->front.iov_base;
	p = msg->front.iov_base + sizeof(struct ceph_mds_reply_head);
	end = p + msg->front.iov_len - sizeof(struct ceph_mds_reply_head);

	/* trace */
	ceph_decode_32_safe(&p, end, len, bad);
	if (len > 0) {
		ceph_decode_need(&p, end, len, bad);
		err = parse_reply_info_trace(&p, p+len, info, features);
		if (err < 0)
			goto out_bad;
	}

	/* extra */
	ceph_decode_32_safe(&p, end, len, bad);
	if (len > 0) {
		ceph_decode_need(&p, end, len, bad);
		err = parse_reply_info_extra(&p, p+len, info, features);
		if (err < 0)
			goto out_bad;
	}

	/* snap blob */
	ceph_decode_32_safe(&p, end, len, bad);
	info->snapblob_len = len;
	info->snapblob = p;
	p += len;

	if (p != end)
		goto bad;
	return 0;

bad:
	err = -EIO;
out_bad:
	pr_err("mds parse_reply err %d\n", err);
	return err;
}

static void destroy_reply_info(struct ceph_mds_reply_info_parsed *info)
{
	if (!info->dir_in)
		return;
	free_pages((unsigned long)info->dir_in, get_order(info->dir_buf_size));
}


/*
 * sessions
 */
static const char *session_state_name(int s)
{
	switch (s) {
	case CEPH_MDS_SESSION_NEW: return "new";
	case CEPH_MDS_SESSION_OPENING: return "opening";
	case CEPH_MDS_SESSION_OPEN: return "open";
	case CEPH_MDS_SESSION_HUNG: return "hung";
	case CEPH_MDS_SESSION_CLOSING: return "closing";
	case CEPH_MDS_SESSION_RESTARTING: return "restarting";
	case CEPH_MDS_SESSION_RECONNECTING: return "reconnecting";
	default: return "???";
	}
}

static struct ceph_mds_session *get_session(struct ceph_mds_session *s)
{
	if (atomic_inc_not_zero(&s->s_ref)) {
		dout("mdsc get_session %p %d -> %d\n", s,
		     atomic_read(&s->s_ref)-1, atomic_read(&s->s_ref));
		return s;
	} else {
		dout("mdsc get_session %p 0 -- FAIL", s);
		return NULL;
	}
}

void ceph_put_mds_session(struct ceph_mds_session *s)
{
	dout("mdsc put_session %p %d -> %d\n", s,
	     atomic_read(&s->s_ref), atomic_read(&s->s_ref)-1);
	if (atomic_dec_and_test(&s->s_ref)) {
		if (s->s_auth.authorizer)
			ceph_auth_destroy_authorizer(
				s->s_mdsc->fsc->client->monc.auth,
				s->s_auth.authorizer);
		kfree(s);
	}
}

/*
 * called under mdsc->mutex
 */
struct ceph_mds_session *__ceph_lookup_mds_session(struct ceph_mds_client *mdsc,
						   int mds)
{
	struct ceph_mds_session *session;

	if (mds >= mdsc->max_sessions || mdsc->sessions[mds] == NULL)
		return NULL;
	session = mdsc->sessions[mds];
	dout("lookup_mds_session %p %d\n", session,
	     atomic_read(&session->s_ref));
	get_session(session);
	return session;
}

static bool __have_session(struct ceph_mds_client *mdsc, int mds)
{
	if (mds >= mdsc->max_sessions)
		return false;
	return mdsc->sessions[mds];
}

static int __verify_registered_session(struct ceph_mds_client *mdsc,
				       struct ceph_mds_session *s)
{
	if (s->s_mds >= mdsc->max_sessions ||
	    mdsc->sessions[s->s_mds] != s)
		return -ENOENT;
	return 0;
}

/*
 * create+register a new session for given mds.
 * called under mdsc->mutex.
 */
static struct ceph_mds_session *register_session(struct ceph_mds_client *mdsc,
						 int mds)
{
	struct ceph_mds_session *s;

	if (mds >= mdsc->mdsmap->m_max_mds)
		return ERR_PTR(-EINVAL);

	s = kzalloc(sizeof(*s), GFP_NOFS);
	if (!s)
		return ERR_PTR(-ENOMEM);
	s->s_mdsc = mdsc;
	s->s_mds = mds;
	s->s_state = CEPH_MDS_SESSION_NEW;
	s->s_ttl = 0;
	s->s_seq = 0;
	mutex_init(&s->s_mutex);

	ceph_con_init(&s->s_con, s, &mds_con_ops, &mdsc->fsc->client->msgr);

	spin_lock_init(&s->s_gen_ttl_lock);
	s->s_cap_gen = 0;
	s->s_cap_ttl = jiffies - 1;

	spin_lock_init(&s->s_cap_lock);
	s->s_renew_requested = 0;
	s->s_renew_seq = 0;
	INIT_LIST_HEAD(&s->s_caps);
	s->s_nr_caps = 0;
	s->s_trim_caps = 0;
	atomic_set(&s->s_ref, 1);
	INIT_LIST_HEAD(&s->s_waiting);
	INIT_LIST_HEAD(&s->s_unsafe);
	s->s_num_cap_releases = 0;
	s->s_cap_reconnect = 0;
	s->s_cap_iterator = NULL;
	INIT_LIST_HEAD(&s->s_cap_releases);
	INIT_LIST_HEAD(&s->s_cap_releases_done);
	INIT_LIST_HEAD(&s->s_cap_flushing);
	INIT_LIST_HEAD(&s->s_cap_snaps_flushing);

	dout("register_session mds%d\n", mds);
	if (mds >= mdsc->max_sessions) {
		int newmax = 1 << get_count_order(mds+1);
		struct ceph_mds_session **sa;

		dout("register_session realloc to %d\n", newmax);
		sa = kcalloc(newmax, sizeof(void *), GFP_NOFS);
		if (sa == NULL)
			goto fail_realloc;
		if (mdsc->sessions) {
			memcpy(sa, mdsc->sessions,
			       mdsc->max_sessions * sizeof(void *));
			kfree(mdsc->sessions);
		}
		mdsc->sessions = sa;
		mdsc->max_sessions = newmax;
	}
	mdsc->sessions[mds] = s;
	atomic_inc(&s->s_ref);  /* one ref to sessions[], one to caller */

	ceph_con_open(&s->s_con, CEPH_ENTITY_TYPE_MDS, mds,
		      ceph_mdsmap_get_addr(mdsc->mdsmap, mds));

	return s;

fail_realloc:
	kfree(s);
	return ERR_PTR(-ENOMEM);
}

/*
 * called under mdsc->mutex
 */
static void __unregister_session(struct ceph_mds_client *mdsc,
			       struct ceph_mds_session *s)
{
	dout("__unregister_session mds%d %p\n", s->s_mds, s);
	BUG_ON(mdsc->sessions[s->s_mds] != s);
	mdsc->sessions[s->s_mds] = NULL;
	ceph_con_close(&s->s_con);
	ceph_put_mds_session(s);
}

/*
 * drop session refs in request.
 *
 * should be last request ref, or hold mdsc->mutex
 */
static void put_request_session(struct ceph_mds_request *req)
{
	if (req->r_session) {
		ceph_put_mds_session(req->r_session);
		req->r_session = NULL;
	}
}

void ceph_mdsc_release_request(struct kref *kref)
{
	struct ceph_mds_request *req = container_of(kref,
						    struct ceph_mds_request,
						    r_kref);
	destroy_reply_info(&req->r_reply_info);
	if (req->r_request)
		ceph_msg_put(req->r_request);
	if (req->r_reply)
		ceph_msg_put(req->r_reply);
	if (req->r_inode) {
		ceph_put_cap_refs(ceph_inode(req->r_inode), CEPH_CAP_PIN);
		iput(req->r_inode);
	}
	if (req->r_locked_dir)
		ceph_put_cap_refs(ceph_inode(req->r_locked_dir), CEPH_CAP_PIN);
	if (req->r_target_inode)
		iput(req->r_target_inode);
	if (req->r_dentry)
		dput(req->r_dentry);
	if (req->r_old_dentry)
		dput(req->r_old_dentry);
	if (req->r_old_dentry_dir) {
		/*
		 * track (and drop pins for) r_old_dentry_dir
		 * separately, since r_old_dentry's d_parent may have
		 * changed between the dir mutex being dropped and
		 * this request being freed.
		 */
		ceph_put_cap_refs(ceph_inode(req->r_old_dentry_dir),
				  CEPH_CAP_PIN);
		iput(req->r_old_dentry_dir);
	}
	kfree(req->r_path1);
	kfree(req->r_path2);
	put_request_session(req);
	ceph_unreserve_caps(req->r_mdsc, &req->r_caps_reservation);
	kfree(req);
}

/*
 * lookup session, bump ref if found.
 *
 * called under mdsc->mutex.
 */
static struct ceph_mds_request *__lookup_request(struct ceph_mds_client *mdsc,
					     u64 tid)
{
	struct ceph_mds_request *req;
	struct rb_node *n = mdsc->request_tree.rb_node;

	while (n) {
		req = rb_entry(n, struct ceph_mds_request, r_node);
		if (tid < req->r_tid)
			n = n->rb_left;
		else if (tid > req->r_tid)
			n = n->rb_right;
		else {
			ceph_mdsc_get_request(req);
			return req;
		}
	}
	return NULL;
}

static void __insert_request(struct ceph_mds_client *mdsc,
			     struct ceph_mds_request *new)
{
	struct rb_node **p = &mdsc->request_tree.rb_node;
	struct rb_node *parent = NULL;
	struct ceph_mds_request *req = NULL;

	while (*p) {
		parent = *p;
		req = rb_entry(parent, struct ceph_mds_request, r_node);
		if (new->r_tid < req->r_tid)
			p = &(*p)->rb_left;
		else if (new->r_tid > req->r_tid)
			p = &(*p)->rb_right;
		else
			BUG();
	}

	rb_link_node(&new->r_node, parent, p);
	rb_insert_color(&new->r_node, &mdsc->request_tree);
}

/*
 * Register an in-flight request, and assign a tid.  Link to directory
 * are modifying (if any).
 *
 * Called under mdsc->mutex.
 */
static void __register_request(struct ceph_mds_client *mdsc,
			       struct ceph_mds_request *req,
			       struct inode *dir)
{
	req->r_tid = ++mdsc->last_tid;
	if (req->r_num_caps)
		ceph_reserve_caps(mdsc, &req->r_caps_reservation,
				  req->r_num_caps);
	dout("__register_request %p tid %lld\n", req, req->r_tid);
	ceph_mdsc_get_request(req);
	__insert_request(mdsc, req);

	req->r_uid = current_fsuid();
	req->r_gid = current_fsgid();

	if (dir) {
		struct ceph_inode_info *ci = ceph_inode(dir);

		ihold(dir);
		spin_lock(&ci->i_unsafe_lock);
		req->r_unsafe_dir = dir;
		list_add_tail(&req->r_unsafe_dir_item, &ci->i_unsafe_dirops);
		spin_unlock(&ci->i_unsafe_lock);
	}
}

static void __unregister_request(struct ceph_mds_client *mdsc,
				 struct ceph_mds_request *req)
{
	dout("__unregister_request %p tid %lld\n", req, req->r_tid);
	rb_erase(&req->r_node, &mdsc->request_tree);
	RB_CLEAR_NODE(&req->r_node);

	if (req->r_unsafe_dir) {
		struct ceph_inode_info *ci = ceph_inode(req->r_unsafe_dir);

		spin_lock(&ci->i_unsafe_lock);
		list_del_init(&req->r_unsafe_dir_item);
		spin_unlock(&ci->i_unsafe_lock);

		iput(req->r_unsafe_dir);
		req->r_unsafe_dir = NULL;
	}

	complete_all(&req->r_safe_completion);

	ceph_mdsc_put_request(req);
}

/*
 * Choose mds to send request to next.  If there is a hint set in the
 * request (e.g., due to a prior forward hint from the mds), use that.
 * Otherwise, consult frag tree and/or caps to identify the
 * appropriate mds.  If all else fails, choose randomly.
 *
 * Called under mdsc->mutex.
 */
static struct dentry *get_nonsnap_parent(struct dentry *dentry)
{
	/*
	 * we don't need to worry about protecting the d_parent access
	 * here because we never renaming inside the snapped namespace
	 * except to resplice to another snapdir, and either the old or new
	 * result is a valid result.
	 */
	while (!IS_ROOT(dentry) && ceph_snap(dentry->d_inode) != CEPH_NOSNAP)
		dentry = dentry->d_parent;
	return dentry;
}

static int __choose_mds(struct ceph_mds_client *mdsc,
			struct ceph_mds_request *req)
{
	struct inode *inode;
	struct ceph_inode_info *ci;
	struct ceph_cap *cap;
	int mode = req->r_direct_mode;
	int mds = -1;
	u32 hash = req->r_direct_hash;
	bool is_hash = req->r_direct_is_hash;

	/*
	 * is there a specific mds we should try?  ignore hint if we have
	 * no session and the mds is not up (active or recovering).
	 */
	if (req->r_resend_mds >= 0 &&
	    (__have_session(mdsc, req->r_resend_mds) ||
	     ceph_mdsmap_get_state(mdsc->mdsmap, req->r_resend_mds) > 0)) {
		dout("choose_mds using resend_mds mds%d\n",
		     req->r_resend_mds);
		return req->r_resend_mds;
	}

	if (mode == USE_RANDOM_MDS)
		goto random;

	inode = NULL;
	if (req->r_inode) {
		inode = req->r_inode;
	} else if (req->r_dentry) {
		/* ignore race with rename; old or new d_parent is okay */
		struct dentry *parent = req->r_dentry->d_parent;
		struct inode *dir = parent->d_inode;

		if (dir->i_sb != mdsc->fsc->sb) {
			/* not this fs! */
			inode = req->r_dentry->d_inode;
		} else if (ceph_snap(dir) != CEPH_NOSNAP) {
			/* direct snapped/virtual snapdir requests
			 * based on parent dir inode */
			struct dentry *dn = get_nonsnap_parent(parent);
			inode = dn->d_inode;
			dout("__choose_mds using nonsnap parent %p\n", inode);
		} else {
			/* dentry target */
			inode = req->r_dentry->d_inode;
			if (!inode || mode == USE_AUTH_MDS) {
				/* dir + name */
				inode = dir;
				hash = ceph_dentry_hash(dir, req->r_dentry);
				is_hash = true;
			}
		}
	}

	dout("__choose_mds %p is_hash=%d (%d) mode %d\n", inode, (int)is_hash,
	     (int)hash, mode);
	if (!inode)
		goto random;
	ci = ceph_inode(inode);

	if (is_hash && S_ISDIR(inode->i_mode)) {
		struct ceph_inode_frag frag;
		int found;

		ceph_choose_frag(ci, hash, &frag, &found);
		if (found) {
			if (mode == USE_ANY_MDS && frag.ndist > 0) {
				u8 r;

				/* choose a random replica */
				get_random_bytes(&r, 1);
				r %= frag.ndist;
				mds = frag.dist[r];
				dout("choose_mds %p %llx.%llx "
				     "frag %u mds%d (%d/%d)\n",
				     inode, ceph_vinop(inode),
				     frag.frag, mds,
				     (int)r, frag.ndist);
				if (ceph_mdsmap_get_state(mdsc->mdsmap, mds) >=
				    CEPH_MDS_STATE_ACTIVE)
					return mds;
			}

			/* since this file/dir wasn't known to be
			 * replicated, then we want to look for the
			 * authoritative mds. */
			mode = USE_AUTH_MDS;
			if (frag.mds >= 0) {
				/* choose auth mds */
				mds = frag.mds;
				dout("choose_mds %p %llx.%llx "
				     "frag %u mds%d (auth)\n",
				     inode, ceph_vinop(inode), frag.frag, mds);
				if (ceph_mdsmap_get_state(mdsc->mdsmap, mds) >=
				    CEPH_MDS_STATE_ACTIVE)
					return mds;
			}
		}
	}

	spin_lock(&ci->i_ceph_lock);
	cap = NULL;
	if (mode == USE_AUTH_MDS)
		cap = ci->i_auth_cap;
	if (!cap && !RB_EMPTY_ROOT(&ci->i_caps))
		cap = rb_entry(rb_first(&ci->i_caps), struct ceph_cap, ci_node);
	if (!cap) {
		spin_unlock(&ci->i_ceph_lock);
		goto random;
	}
	mds = cap->session->s_mds;
	dout("choose_mds %p %llx.%llx mds%d (%scap %p)\n",
	     inode, ceph_vinop(inode), mds,
	     cap == ci->i_auth_cap ? "auth " : "", cap);
	spin_unlock(&ci->i_ceph_lock);
	return mds;

random:
	mds = ceph_mdsmap_get_random_mds(mdsc->mdsmap);
	dout("choose_mds chose random mds%d\n", mds);
	return mds;
}


/*
 * session messages
 */
static struct ceph_msg *create_session_msg(u32 op, u64 seq)
{
	struct ceph_msg *msg;
	struct ceph_mds_session_head *h;

	msg = ceph_msg_new(CEPH_MSG_CLIENT_SESSION, sizeof(*h), GFP_NOFS,
			   false);
	if (!msg) {
		pr_err("create_session_msg ENOMEM creating msg\n");
		return NULL;
	}
	h = msg->front.iov_base;
	h->op = cpu_to_le32(op);
	h->seq = cpu_to_le64(seq);
	return msg;
}

/*
 * send session open request.
 *
 * called under mdsc->mutex
 */
static int __open_session(struct ceph_mds_client *mdsc,
			  struct ceph_mds_session *session)
{
	struct ceph_msg *msg;
	int mstate;
	int mds = session->s_mds;

	/* wait for mds to go active? */
	mstate = ceph_mdsmap_get_state(mdsc->mdsmap, mds);
	dout("open_session to mds%d (%s)\n", mds,
	     ceph_mds_state_name(mstate));
	session->s_state = CEPH_MDS_SESSION_OPENING;
	session->s_renew_requested = jiffies;

	/* send connect message */
	msg = create_session_msg(CEPH_SESSION_REQUEST_OPEN, session->s_seq);
	if (!msg)
		return -ENOMEM;
	ceph_con_send(&session->s_con, msg);
	return 0;
}

/*
 * open sessions for any export targets for the given mds
 *
 * called under mdsc->mutex
 */
static struct ceph_mds_session *
__open_export_target_session(struct ceph_mds_client *mdsc, int target)
{
	struct ceph_mds_session *session;

	session = __ceph_lookup_mds_session(mdsc, target);
	if (!session) {
		session = register_session(mdsc, target);
		if (IS_ERR(session))
			return session;
	}
	if (session->s_state == CEPH_MDS_SESSION_NEW ||
	    session->s_state == CEPH_MDS_SESSION_CLOSING)
		__open_session(mdsc, session);

	return session;
}

struct ceph_mds_session *
ceph_mdsc_open_export_target_session(struct ceph_mds_client *mdsc, int target)
{
	struct ceph_mds_session *session;

	dout("open_export_target_session to mds%d\n", target);

	mutex_lock(&mdsc->mutex);
	session = __open_export_target_session(mdsc, target);
	mutex_unlock(&mdsc->mutex);

	return session;
}

static void __open_export_target_sessions(struct ceph_mds_client *mdsc,
					  struct ceph_mds_session *session)
{
	struct ceph_mds_info *mi;
	struct ceph_mds_session *ts;
	int i, mds = session->s_mds;

	if (mds >= mdsc->mdsmap->m_max_mds)
		return;

	mi = &mdsc->mdsmap->m_info[mds];
	dout("open_export_target_sessions for mds%d (%d targets)\n",
	     session->s_mds, mi->num_export_targets);

	for (i = 0; i < mi->num_export_targets; i++) {
		ts = __open_export_target_session(mdsc, mi->export_targets[i]);
		if (!IS_ERR(ts))
			ceph_put_mds_session(ts);
	}
}

void ceph_mdsc_open_export_target_sessions(struct ceph_mds_client *mdsc,
					   struct ceph_mds_session *session)
{
	mutex_lock(&mdsc->mutex);
	__open_export_target_sessions(mdsc, session);
	mutex_unlock(&mdsc->mutex);
}

/*
 * session caps
 */

/*
 * Free preallocated cap messages assigned to this session
 */
static void cleanup_cap_releases(struct ceph_mds_session *session)
{
	struct ceph_msg *msg;

	spin_lock(&session->s_cap_lock);
	while (!list_empty(&session->s_cap_releases)) {
		msg = list_first_entry(&session->s_cap_releases,
				       struct ceph_msg, list_head);
		list_del_init(&msg->list_head);
		ceph_msg_put(msg);
	}
	while (!list_empty(&session->s_cap_releases_done)) {
		msg = list_first_entry(&session->s_cap_releases_done,
				       struct ceph_msg, list_head);
		list_del_init(&msg->list_head);
		ceph_msg_put(msg);
	}
	spin_unlock(&session->s_cap_lock);
}

/*
 * Helper to safely iterate over all caps associated with a session, with
 * special care taken to handle a racing __ceph_remove_cap().
 *
 * Caller must hold session s_mutex.
 */
static int iterate_session_caps(struct ceph_mds_session *session,
				 int (*cb)(struct inode *, struct ceph_cap *,
					    void *), void *arg)
{
	struct list_head *p;
	struct ceph_cap *cap;
	struct inode *inode, *last_inode = NULL;
	struct ceph_cap *old_cap = NULL;
	int ret;

	dout("iterate_session_caps %p mds%d\n", session, session->s_mds);
	spin_lock(&session->s_cap_lock);
	p = session->s_caps.next;
	while (p != &session->s_caps) {
		cap = list_entry(p, struct ceph_cap, session_caps);
		inode = igrab(&cap->ci->vfs_inode);
		if (!inode) {
			p = p->next;
			continue;
		}
		session->s_cap_iterator = cap;
		spin_unlock(&session->s_cap_lock);

		if (last_inode) {
			iput(last_inode);
			last_inode = NULL;
		}
		if (old_cap) {
			ceph_put_cap(session->s_mdsc, old_cap);
			old_cap = NULL;
		}

		ret = cb(inode, cap, arg);
		last_inode = inode;

		spin_lock(&session->s_cap_lock);
		p = p->next;
		if (cap->ci == NULL) {
			dout("iterate_session_caps  finishing cap %p removal\n",
			     cap);
			BUG_ON(cap->session != session);
			list_del_init(&cap->session_caps);
			session->s_nr_caps--;
			cap->session = NULL;
			old_cap = cap;  /* put_cap it w/o locks held */
		}
		if (ret < 0)
			goto out;
	}
	ret = 0;
out:
	session->s_cap_iterator = NULL;
	spin_unlock(&session->s_cap_lock);

	if (last_inode)
		iput(last_inode);
	if (old_cap)
		ceph_put_cap(session->s_mdsc, old_cap);

	return ret;
}

static int remove_session_caps_cb(struct inode *inode, struct ceph_cap *cap,
				  void *arg)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int drop = 0;

	dout("removing cap %p, ci is %p, inode is %p\n",
	     cap, ci, &ci->vfs_inode);
	spin_lock(&ci->i_ceph_lock);
	__ceph_remove_cap(cap, false);
	if (!__ceph_is_any_real_caps(ci)) {
		struct ceph_mds_client *mdsc =
			ceph_sb_to_client(inode->i_sb)->mdsc;

		spin_lock(&mdsc->cap_dirty_lock);
		if (!list_empty(&ci->i_dirty_item)) {
			pr_info(" dropping dirty %s state for %p %lld\n",
				ceph_cap_string(ci->i_dirty_caps),
				inode, ceph_ino(inode));
			ci->i_dirty_caps = 0;
			list_del_init(&ci->i_dirty_item);
			drop = 1;
		}
		if (!list_empty(&ci->i_flushing_item)) {
			pr_info(" dropping dirty+flushing %s state for %p %lld\n",
				ceph_cap_string(ci->i_flushing_caps),
				inode, ceph_ino(inode));
			ci->i_flushing_caps = 0;
			list_del_init(&ci->i_flushing_item);
			mdsc->num_cap_flushing--;
			drop = 1;
		}
		if (drop && ci->i_wrbuffer_ref) {
			pr_info(" dropping dirty data for %p %lld\n",
				inode, ceph_ino(inode));
			ci->i_wrbuffer_ref = 0;
			ci->i_wrbuffer_ref_head = 0;
			drop++;
		}
		spin_unlock(&mdsc->cap_dirty_lock);
	}
	spin_unlock(&ci->i_ceph_lock);
	while (drop--)
		iput(inode);
	return 0;
}

/*
 * caller must hold session s_mutex
 */
static void remove_session_caps(struct ceph_mds_session *session)
{
	dout("remove_session_caps on %p\n", session);
	iterate_session_caps(session, remove_session_caps_cb, NULL);

	spin_lock(&session->s_cap_lock);
	if (session->s_nr_caps > 0) {
		struct super_block *sb = session->s_mdsc->fsc->sb;
		struct inode *inode;
		struct ceph_cap *cap, *prev = NULL;
		struct ceph_vino vino;
		/*
		 * iterate_session_caps() skips inodes that are being
		 * deleted, we need to wait until deletions are complete.
		 * __wait_on_freeing_inode() is designed for the job,
		 * but it is not exported, so use lookup inode function
		 * to access it.
		 */
		while (!list_empty(&session->s_caps)) {
			cap = list_entry(session->s_caps.next,
					 struct ceph_cap, session_caps);
			if (cap == prev)
				break;
			prev = cap;
			vino = cap->ci->i_vino;
			spin_unlock(&session->s_cap_lock);

			inode = ceph_find_inode(sb, vino);
			iput(inode);

			spin_lock(&session->s_cap_lock);
		}
	}
	spin_unlock(&session->s_cap_lock);

	BUG_ON(session->s_nr_caps > 0);
	BUG_ON(!list_empty(&session->s_cap_flushing));
	cleanup_cap_releases(session);
}

/*
 * wake up any threads waiting on this session's caps.  if the cap is
 * old (didn't get renewed on the client reconnect), remove it now.
 *
 * caller must hold s_mutex.
 */
static int wake_up_session_cb(struct inode *inode, struct ceph_cap *cap,
			      void *arg)
{
	struct ceph_inode_info *ci = ceph_inode(inode);

	wake_up_all(&ci->i_cap_wq);
	if (arg) {
		spin_lock(&ci->i_ceph_lock);
		ci->i_wanted_max_size = 0;
		ci->i_requested_max_size = 0;
		spin_unlock(&ci->i_ceph_lock);
	}
	return 0;
}

static void wake_up_session_caps(struct ceph_mds_session *session,
				 int reconnect)
{
	dout("wake_up_session_caps %p mds%d\n", session, session->s_mds);
	iterate_session_caps(session, wake_up_session_cb,
			     (void *)(unsigned long)reconnect);
}

/*
 * Send periodic message to MDS renewing all currently held caps.  The
 * ack will reset the expiration for all caps from this session.
 *
 * caller holds s_mutex
 */
static int send_renew_caps(struct ceph_mds_client *mdsc,
			   struct ceph_mds_session *session)
{
	struct ceph_msg *msg;
	int state;

	if (time_after_eq(jiffies, session->s_cap_ttl) &&
	    time_after_eq(session->s_cap_ttl, session->s_renew_requested))
		pr_info("mds%d caps stale\n", session->s_mds);
	session->s_renew_requested = jiffies;

	/* do not try to renew caps until a recovering mds has reconnected
	 * with its clients. */
	state = ceph_mdsmap_get_state(mdsc->mdsmap, session->s_mds);
	if (state < CEPH_MDS_STATE_RECONNECT) {
		dout("send_renew_caps ignoring mds%d (%s)\n",
		     session->s_mds, ceph_mds_state_name(state));
		return 0;
	}

	dout("send_renew_caps to mds%d (%s)\n", session->s_mds,
		ceph_mds_state_name(state));
	msg = create_session_msg(CEPH_SESSION_REQUEST_RENEWCAPS,
				 ++session->s_renew_seq);
	if (!msg)
		return -ENOMEM;
	ceph_con_send(&session->s_con, msg);
	return 0;
}

static int send_flushmsg_ack(struct ceph_mds_client *mdsc,
			     struct ceph_mds_session *session, u64 seq)
{
	struct ceph_msg *msg;

	dout("send_flushmsg_ack to mds%d (%s)s seq %lld\n",
	     session->s_mds, session_state_name(session->s_state), seq);
	msg = create_session_msg(CEPH_SESSION_FLUSHMSG_ACK, seq);
	if (!msg)
		return -ENOMEM;
	ceph_con_send(&session->s_con, msg);
	return 0;
}


/*
 * Note new cap ttl, and any transition from stale -> not stale (fresh?).
 *
 * Called under session->s_mutex
 */
static void renewed_caps(struct ceph_mds_client *mdsc,
			 struct ceph_mds_session *session, int is_renew)
{
	int was_stale;
	int wake = 0;

	spin_lock(&session->s_cap_lock);
	was_stale = is_renew && time_after_eq(jiffies, session->s_cap_ttl);

	session->s_cap_ttl = session->s_renew_requested +
		mdsc->mdsmap->m_session_timeout*HZ;

	if (was_stale) {
		if (time_before(jiffies, session->s_cap_ttl)) {
			pr_info("mds%d caps renewed\n", session->s_mds);
			wake = 1;
		} else {
			pr_info("mds%d caps still stale\n", session->s_mds);
		}
	}
	dout("renewed_caps mds%d ttl now %lu, was %s, now %s\n",
	     session->s_mds, session->s_cap_ttl, was_stale ? "stale" : "fresh",
	     time_before(jiffies, session->s_cap_ttl) ? "stale" : "fresh");
	spin_unlock(&session->s_cap_lock);

	if (wake)
		wake_up_session_caps(session, 0);
}

/*
 * send a session close request
 */
static int request_close_session(struct ceph_mds_client *mdsc,
				 struct ceph_mds_session *session)
{
	struct ceph_msg *msg;

	dout("request_close_session mds%d state %s seq %lld\n",
	     session->s_mds, session_state_name(session->s_state),
	     session->s_seq);
	msg = create_session_msg(CEPH_SESSION_REQUEST_CLOSE, session->s_seq);
	if (!msg)
		return -ENOMEM;
	ceph_con_send(&session->s_con, msg);
	return 0;
}

/*
 * Called with s_mutex held.
 */
static int __close_session(struct ceph_mds_client *mdsc,
			 struct ceph_mds_session *session)
{
	if (session->s_state >= CEPH_MDS_SESSION_CLOSING)
		return 0;
	session->s_state = CEPH_MDS_SESSION_CLOSING;
	return request_close_session(mdsc, session);
}

/*
 * Trim old(er) caps.
 *
 * Because we can't cache an inode without one or more caps, we do
 * this indirectly: if a cap is unused, we prune its aliases, at which
 * point the inode will hopefully get dropped to.
 *
 * Yes, this is a bit sloppy.  Our only real goal here is to respond to
 * memory pressure from the MDS, though, so it needn't be perfect.
 */
static int trim_caps_cb(struct inode *inode, struct ceph_cap *cap, void *arg)
{
	struct ceph_mds_session *session = arg;
	struct ceph_inode_info *ci = ceph_inode(inode);
	int used, wanted, oissued, mine;

	if (session->s_trim_caps <= 0)
		return -1;

	spin_lock(&ci->i_ceph_lock);
	mine = cap->issued | cap->implemented;
	used = __ceph_caps_used(ci);
	wanted = __ceph_caps_file_wanted(ci);
	oissued = __ceph_caps_issued_other(ci, cap);

	dout("trim_caps_cb %p cap %p mine %s oissued %s used %s wanted %s\n",
	     inode, cap, ceph_cap_string(mine), ceph_cap_string(oissued),
	     ceph_cap_string(used), ceph_cap_string(wanted));
	if (cap == ci->i_auth_cap) {
		if (ci->i_dirty_caps | ci->i_flushing_caps)
			goto out;
		if ((used | wanted) & CEPH_CAP_ANY_WR)
			goto out;
	}
	if ((used | wanted) & ~oissued & mine)
		goto out;   /* we need these caps */

	session->s_trim_caps--;
	if (oissued) {
		/* we aren't the only cap.. just remove us */
		__ceph_remove_cap(cap, true);
	} else {
		/* try to drop referring dentries */
		spin_unlock(&ci->i_ceph_lock);
		d_prune_aliases(inode);
		dout("trim_caps_cb %p cap %p  pruned, count now %d\n",
		     inode, cap, atomic_read(&inode->i_count));
		return 0;
	}

out:
	spin_unlock(&ci->i_ceph_lock);
	return 0;
}

/*
 * Trim session cap count down to some max number.
 */
static int trim_caps(struct ceph_mds_client *mdsc,
		     struct ceph_mds_session *session,
		     int max_caps)
{
	int trim_caps = session->s_nr_caps - max_caps;

	dout("trim_caps mds%d start: %d / %d, trim %d\n",
	     session->s_mds, session->s_nr_caps, max_caps, trim_caps);
	if (trim_caps > 0) {
		session->s_trim_caps = trim_caps;
		iterate_session_caps(session, trim_caps_cb, session);
		dout("trim_caps mds%d done: %d / %d, trimmed %d\n",
		     session->s_mds, session->s_nr_caps, max_caps,
			trim_caps - session->s_trim_caps);
		session->s_trim_caps = 0;
	}

	ceph_add_cap_releases(mdsc, session);
	ceph_send_cap_releases(mdsc, session);
	return 0;
}

/*
 * Allocate cap_release messages.  If there is a partially full message
 * in the queue, try to allocate enough to cover it's remainder, so that
 * we can send it immediately.
 *
 * Called under s_mutex.
 */
int ceph_add_cap_releases(struct ceph_mds_client *mdsc,
			  struct ceph_mds_session *session)
{
	struct ceph_msg *msg, *partial = NULL;
	struct ceph_mds_cap_release *head;
	int err = -ENOMEM;
	int extra = mdsc->fsc->mount_options->cap_release_safety;
	int num;

	dout("add_cap_releases %p mds%d extra %d\n", session, session->s_mds,
	     extra);

	spin_lock(&session->s_cap_lock);

	if (!list_empty(&session->s_cap_releases)) {
		msg = list_first_entry(&session->s_cap_releases,
				       struct ceph_msg,
				 list_head);
		head = msg->front.iov_base;
		num = le32_to_cpu(head->num);
		if (num) {
			dout(" partial %p with (%d/%d)\n", msg, num,
			     (int)CEPH_CAPS_PER_RELEASE);
			extra += CEPH_CAPS_PER_RELEASE - num;
			partial = msg;
		}
	}
	while (session->s_num_cap_releases < session->s_nr_caps + extra) {
		spin_unlock(&session->s_cap_lock);
		msg = ceph_msg_new(CEPH_MSG_CLIENT_CAPRELEASE, PAGE_CACHE_SIZE,
				   GFP_NOFS, false);
		if (!msg)
			goto out_unlocked;
		dout("add_cap_releases %p msg %p now %d\n", session, msg,
		     (int)msg->front.iov_len);
		head = msg->front.iov_base;
		head->num = cpu_to_le32(0);
		msg->front.iov_len = sizeof(*head);
		spin_lock(&session->s_cap_lock);
		list_add(&msg->list_head, &session->s_cap_releases);
		session->s_num_cap_releases += CEPH_CAPS_PER_RELEASE;
	}

	if (partial) {
		head = partial->front.iov_base;
		num = le32_to_cpu(head->num);
		dout(" queueing partial %p with %d/%d\n", partial, num,
		     (int)CEPH_CAPS_PER_RELEASE);
		list_move_tail(&partial->list_head,
			       &session->s_cap_releases_done);
		session->s_num_cap_releases -= CEPH_CAPS_PER_RELEASE - num;
	}
	err = 0;
	spin_unlock(&session->s_cap_lock);
out_unlocked:
	return err;
}

/*
 * flush all dirty inode data to disk.
 *
 * returns true if we've flushed through want_flush_seq
 */
static int check_cap_flush(struct ceph_mds_client *mdsc, u64 want_flush_seq)
{
	int mds, ret = 1;

	dout("check_cap_flush want %lld\n", want_flush_seq);
	mutex_lock(&mdsc->mutex);
	for (mds = 0; ret && mds < mdsc->max_sessions; mds++) {
		struct ceph_mds_session *session = mdsc->sessions[mds];

		if (!session)
			continue;
		get_session(session);
		mutex_unlock(&mdsc->mutex);

		mutex_lock(&session->s_mutex);
		if (!list_empty(&session->s_cap_flushing)) {
			struct ceph_inode_info *ci =
				list_entry(session->s_cap_flushing.next,
					   struct ceph_inode_info,
					   i_flushing_item);
			struct inode *inode = &ci->vfs_inode;

			spin_lock(&ci->i_ceph_lock);
			if (ci->i_cap_flush_seq <= want_flush_seq) {
				dout("check_cap_flush still flushing %p "
				     "seq %lld <= %lld to mds%d\n", inode,
				     ci->i_cap_flush_seq, want_flush_seq,
				     session->s_mds);
				ret = 0;
			}
			spin_unlock(&ci->i_ceph_lock);
		}
		mutex_unlock(&session->s_mutex);
		ceph_put_mds_session(session);

		if (!ret)
			return ret;
		mutex_lock(&mdsc->mutex);
	}

	mutex_unlock(&mdsc->mutex);
	dout("check_cap_flush ok, flushed thru %lld\n", want_flush_seq);
	return ret;
}

/*
 * called under s_mutex
 */
void ceph_send_cap_releases(struct ceph_mds_client *mdsc,
			    struct ceph_mds_session *session)
{
	struct ceph_msg *msg;

	dout("send_cap_releases mds%d\n", session->s_mds);
	spin_lock(&session->s_cap_lock);
	while (!list_empty(&session->s_cap_releases_done)) {
		msg = list_first_entry(&session->s_cap_releases_done,
				 struct ceph_msg, list_head);
		list_del_init(&msg->list_head);
		spin_unlock(&session->s_cap_lock);
		msg->hdr.front_len = cpu_to_le32(msg->front.iov_len);
		dout("send_cap_releases mds%d %p\n", session->s_mds, msg);
		ceph_con_send(&session->s_con, msg);
		spin_lock(&session->s_cap_lock);
	}
	spin_unlock(&session->s_cap_lock);
}

static void discard_cap_releases(struct ceph_mds_client *mdsc,
				 struct ceph_mds_session *session)
{
	struct ceph_msg *msg;
	struct ceph_mds_cap_release *head;
	unsigned num;

	dout("discard_cap_releases mds%d\n", session->s_mds);

	if (!list_empty(&session->s_cap_releases)) {
		/* zero out the in-progress message */
		msg = list_first_entry(&session->s_cap_releases,
					struct ceph_msg, list_head);
		head = msg->front.iov_base;
		num = le32_to_cpu(head->num);
		dout("discard_cap_releases mds%d %p %u\n",
		     session->s_mds, msg, num);
		head->num = cpu_to_le32(0);
		msg->front.iov_len = sizeof(*head);
		session->s_num_cap_releases += num;
	}

	/* requeue completed messages */
	while (!list_empty(&session->s_cap_releases_done)) {
		msg = list_first_entry(&session->s_cap_releases_done,
				 struct ceph_msg, list_head);
		list_del_init(&msg->list_head);

		head = msg->front.iov_base;
		num = le32_to_cpu(head->num);
		dout("discard_cap_releases mds%d %p %u\n", session->s_mds, msg,
		     num);
		session->s_num_cap_releases += num;
		head->num = cpu_to_le32(0);
		msg->front.iov_len = sizeof(*head);
		list_add(&msg->list_head, &session->s_cap_releases);
	}
}

/*
 * requests
 */

int ceph_alloc_readdir_reply_buffer(struct ceph_mds_request *req,
				    struct inode *dir)
{
	struct ceph_inode_info *ci = ceph_inode(dir);
	struct ceph_mds_reply_info_parsed *rinfo = &req->r_reply_info;
	struct ceph_mount_options *opt = req->r_mdsc->fsc->mount_options;
	size_t size = sizeof(*rinfo->dir_in) + sizeof(*rinfo->dir_dname_len) +
		      sizeof(*rinfo->dir_dname) + sizeof(*rinfo->dir_dlease);
	int order, num_entries;

	spin_lock(&ci->i_ceph_lock);
	num_entries = ci->i_files + ci->i_subdirs;
	spin_unlock(&ci->i_ceph_lock);
	num_entries = max(num_entries, 1);
	num_entries = min(num_entries, opt->max_readdir);

	order = get_order(size * num_entries);
	while (order >= 0) {
		rinfo->dir_in = (void*)__get_free_pages(GFP_NOFS | __GFP_NOWARN,
							order);
		if (rinfo->dir_in)
			break;
		order--;
	}
	if (!rinfo->dir_in)
		return -ENOMEM;

	num_entries = (PAGE_SIZE << order) / size;
	num_entries = min(num_entries, opt->max_readdir);

	rinfo->dir_buf_size = PAGE_SIZE << order;
	req->r_num_caps = num_entries + 1;
	req->r_args.readdir.max_entries = cpu_to_le32(num_entries);
	req->r_args.readdir.max_bytes = cpu_to_le32(opt->max_readdir_bytes);
	return 0;
}

/*
 * Create an mds request.
 */
struct ceph_mds_request *
ceph_mdsc_create_request(struct ceph_mds_client *mdsc, int op, int mode)
{
	struct ceph_mds_request *req = kzalloc(sizeof(*req), GFP_NOFS);

	if (!req)
		return ERR_PTR(-ENOMEM);

	mutex_init(&req->r_fill_mutex);
	req->r_mdsc = mdsc;
	req->r_started = jiffies;
	req->r_resend_mds = -1;
	INIT_LIST_HEAD(&req->r_unsafe_dir_item);
	req->r_fmode = -1;
	kref_init(&req->r_kref);
	INIT_LIST_HEAD(&req->r_wait);
	init_completion(&req->r_completion);
	init_completion(&req->r_safe_completion);
	INIT_LIST_HEAD(&req->r_unsafe_item);

	req->r_stamp = CURRENT_TIME;

	req->r_op = op;
	req->r_direct_mode = mode;
	return req;
}

/*
 * return oldest (lowest) request, tid in request tree, 0 if none.
 *
 * called under mdsc->mutex.
 */
static struct ceph_mds_request *__get_oldest_req(struct ceph_mds_client *mdsc)
{
	if (RB_EMPTY_ROOT(&mdsc->request_tree))
		return NULL;
	return rb_entry(rb_first(&mdsc->request_tree),
			struct ceph_mds_request, r_node);
}

static u64 __get_oldest_tid(struct ceph_mds_client *mdsc)
{
	struct ceph_mds_request *req = __get_oldest_req(mdsc);

	if (req)
		return req->r_tid;
	return 0;
}

/*
 * Build a dentry's path.  Allocate on heap; caller must kfree.  Based
 * on build_path_from_dentry in fs/cifs/dir.c.
 *
 * If @stop_on_nosnap, generate path relative to the first non-snapped
 * inode.
 *
 * Encode hidden .snap dirs as a double /, i.e.
 *   foo/.snap/bar -> foo//bar
 */
char *ceph_mdsc_build_path(struct dentry *dentry, int *plen, u64 *base,
			   int stop_on_nosnap)
{
	struct dentry *temp;
	char *path;
	int len, pos;
	unsigned seq;

	if (dentry == NULL)
		return ERR_PTR(-EINVAL);

retry:
	len = 0;
	seq = read_seqbegin(&rename_lock);
	rcu_read_lock();
	for (temp = dentry; !IS_ROOT(temp);) {
		struct inode *inode = temp->d_inode;
		if (inode && ceph_snap(inode) == CEPH_SNAPDIR)
			len++;  /* slash only */
		else if (stop_on_nosnap && inode &&
			 ceph_snap(inode) == CEPH_NOSNAP)
			break;
		else
			len += 1 + temp->d_name.len;
		temp = temp->d_parent;
	}
	rcu_read_unlock();
	if (len)
		len--;  /* no leading '/' */

	path = kmalloc(len+1, GFP_NOFS);
	if (path == NULL)
		return ERR_PTR(-ENOMEM);
	pos = len;
	path[pos] = 0;	/* trailing null */
	rcu_read_lock();
	for (temp = dentry; !IS_ROOT(temp) && pos != 0; ) {
		struct inode *inode;

		spin_lock(&temp->d_lock);
		inode = temp->d_inode;
		if (inode && ceph_snap(inode) == CEPH_SNAPDIR) {
			dout("build_path path+%d: %p SNAPDIR\n",
			     pos, temp);
		} else if (stop_on_nosnap && inode &&
			   ceph_snap(inode) == CEPH_NOSNAP) {
			spin_unlock(&temp->d_lock);
			break;
		} else {
			pos -= temp->d_name.len;
			if (pos < 0) {
				spin_unlock(&temp->d_lock);
				break;
			}
			strncpy(path + pos, temp->d_name.name,
				temp->d_name.len);
		}
		spin_unlock(&temp->d_lock);
		if (pos)
			path[--pos] = '/';
		temp = temp->d_parent;
	}
	rcu_read_unlock();
	if (pos != 0 || read_seqretry(&rename_lock, seq)) {
		pr_err("build_path did not end path lookup where "
		       "expected, namelen is %d, pos is %d\n", len, pos);
		/* presumably this is only possible if racing with a
		   rename of one of the parent directories (we can not
		   lock the dentries above us to prevent this, but
		   retrying should be harmless) */
		kfree(path);
		goto retry;
	}

	*base = ceph_ino(temp->d_inode);
	*plen = len;
	dout("build_path on %p %d built %llx '%.*s'\n",
	     dentry, d_count(dentry), *base, len, path);
	return path;
}

static int build_dentry_path(struct dentry *dentry,
			     const char **ppath, int *ppathlen, u64 *pino,
			     int *pfreepath)
{
	char *path;

	if (ceph_snap(dentry->d_parent->d_inode) == CEPH_NOSNAP) {
		*pino = ceph_ino(dentry->d_parent->d_inode);
		*ppath = dentry->d_name.name;
		*ppathlen = dentry->d_name.len;
		return 0;
	}
	path = ceph_mdsc_build_path(dentry, ppathlen, pino, 1);
	if (IS_ERR(path))
		return PTR_ERR(path);
	*ppath = path;
	*pfreepath = 1;
	return 0;
}

static int build_inode_path(struct inode *inode,
			    const char **ppath, int *ppathlen, u64 *pino,
			    int *pfreepath)
{
	struct dentry *dentry;
	char *path;

	if (ceph_snap(inode) == CEPH_NOSNAP) {
		*pino = ceph_ino(inode);
		*ppathlen = 0;
		return 0;
	}
	dentry = d_find_alias(inode);
	path = ceph_mdsc_build_path(dentry, ppathlen, pino, 1);
	dput(dentry);
	if (IS_ERR(path))
		return PTR_ERR(path);
	*ppath = path;
	*pfreepath = 1;
	return 0;
}

/*
 * request arguments may be specified via an inode *, a dentry *, or
 * an explicit ino+path.
 */
static int set_request_path_attr(struct inode *rinode, struct dentry *rdentry,
				  const char *rpath, u64 rino,
				  const char **ppath, int *pathlen,
				  u64 *ino, int *freepath)
{
	int r = 0;

	if (rinode) {
		r = build_inode_path(rinode, ppath, pathlen, ino, freepath);
		dout(" inode %p %llx.%llx\n", rinode, ceph_ino(rinode),
		     ceph_snap(rinode));
	} else if (rdentry) {
		r = build_dentry_path(rdentry, ppath, pathlen, ino, freepath);
		dout(" dentry %p %llx/%.*s\n", rdentry, *ino, *pathlen,
		     *ppath);
	} else if (rpath || rino) {
		*ino = rino;
		*ppath = rpath;
		*pathlen = rpath ? strlen(rpath) : 0;
		dout(" path %.*s\n", *pathlen, rpath);
	}

	return r;
}

/*
 * called under mdsc->mutex
 */
static struct ceph_msg *create_request_message(struct ceph_mds_client *mdsc,
					       struct ceph_mds_request *req,
					       int mds)
{
	struct ceph_msg *msg;
	struct ceph_mds_request_head *head;
	const char *path1 = NULL;
	const char *path2 = NULL;
	u64 ino1 = 0, ino2 = 0;
	int pathlen1 = 0, pathlen2 = 0;
	int freepath1 = 0, freepath2 = 0;
	int len;
	u16 releases;
	void *p, *end;
	int ret;

	ret = set_request_path_attr(req->r_inode, req->r_dentry,
			      req->r_path1, req->r_ino1.ino,
			      &path1, &pathlen1, &ino1, &freepath1);
	if (ret < 0) {
		msg = ERR_PTR(ret);
		goto out;
	}

	ret = set_request_path_attr(NULL, req->r_old_dentry,
			      req->r_path2, req->r_ino2.ino,
			      &path2, &pathlen2, &ino2, &freepath2);
	if (ret < 0) {
		msg = ERR_PTR(ret);
		goto out_free1;
	}

	len = sizeof(*head) +
		pathlen1 + pathlen2 + 2*(1 + sizeof(u32) + sizeof(u64)) +
		sizeof(struct timespec);

	/* calculate (max) length for cap releases */
	len += sizeof(struct ceph_mds_request_release) *
		(!!req->r_inode_drop + !!req->r_dentry_drop +
		 !!req->r_old_inode_drop + !!req->r_old_dentry_drop);
	if (req->r_dentry_drop)
		len += req->r_dentry->d_name.len;
	if (req->r_old_dentry_drop)
		len += req->r_old_dentry->d_name.len;

	msg = ceph_msg_new(CEPH_MSG_CLIENT_REQUEST, len, GFP_NOFS, false);
	if (!msg) {
		msg = ERR_PTR(-ENOMEM);
		goto out_free2;
	}

	msg->hdr.version = 2;
	msg->hdr.tid = cpu_to_le64(req->r_tid);

	head = msg->front.iov_base;
	p = msg->front.iov_base + sizeof(*head);
	end = msg->front.iov_base + msg->front.iov_len;

	head->mdsmap_epoch = cpu_to_le32(mdsc->mdsmap->m_epoch);
	head->op = cpu_to_le32(req->r_op);
	head->caller_uid = cpu_to_le32(from_kuid(&init_user_ns, req->r_uid));
	head->caller_gid = cpu_to_le32(from_kgid(&init_user_ns, req->r_gid));
	head->args = req->r_args;

	ceph_encode_filepath(&p, end, ino1, path1);
	ceph_encode_filepath(&p, end, ino2, path2);

	/* make note of release offset, in case we need to replay */
	req->r_request_release_offset = p - msg->front.iov_base;

	/* cap releases */
	releases = 0;
	if (req->r_inode_drop)
		releases += ceph_encode_inode_release(&p,
		      req->r_inode ? req->r_inode : req->r_dentry->d_inode,
		      mds, req->r_inode_drop, req->r_inode_unless, 0);
	if (req->r_dentry_drop)
		releases += ceph_encode_dentry_release(&p, req->r_dentry,
		       mds, req->r_dentry_drop, req->r_dentry_unless);
	if (req->r_old_dentry_drop)
		releases += ceph_encode_dentry_release(&p, req->r_old_dentry,
		       mds, req->r_old_dentry_drop, req->r_old_dentry_unless);
	if (req->r_old_inode_drop)
		releases += ceph_encode_inode_release(&p,
		      req->r_old_dentry->d_inode,
		      mds, req->r_old_inode_drop, req->r_old_inode_unless, 0);
	head->num_releases = cpu_to_le16(releases);

	/* time stamp */
	ceph_encode_copy(&p, &req->r_stamp, sizeof(req->r_stamp));

	BUG_ON(p > end);
	msg->front.iov_len = p - msg->front.iov_base;
	msg->hdr.front_len = cpu_to_le32(msg->front.iov_len);

	if (req->r_data_len) {
		/* outbound data set only by ceph_sync_setxattr() */
		BUG_ON(!req->r_pages);
		ceph_msg_data_add_pages(msg, req->r_pages, req->r_data_len, 0);
	}

	msg->hdr.data_len = cpu_to_le32(req->r_data_len);
	msg->hdr.data_off = cpu_to_le16(0);

out_free2:
	if (freepath2)
		kfree((char *)path2);
out_free1:
	if (freepath1)
		kfree((char *)path1);
out:
	return msg;
}

/*
 * called under mdsc->mutex if error, under no mutex if
 * success.
 */
static void complete_request(struct ceph_mds_client *mdsc,
			     struct ceph_mds_request *req)
{
	if (req->r_callback)
		req->r_callback(mdsc, req);
	else
		complete_all(&req->r_completion);
}

/*
 * called under mdsc->mutex
 */
static int __prepare_send_request(struct ceph_mds_client *mdsc,
				  struct ceph_mds_request *req,
				  int mds)
{
	struct ceph_mds_request_head *rhead;
	struct ceph_msg *msg;
	int flags = 0;

	req->r_attempts++;
	if (req->r_inode) {
		struct ceph_cap *cap =
			ceph_get_cap_for_mds(ceph_inode(req->r_inode), mds);

		if (cap)
			req->r_sent_on_mseq = cap->mseq;
		else
			req->r_sent_on_mseq = -1;
	}
	dout("prepare_send_request %p tid %lld %s (attempt %d)\n", req,
	     req->r_tid, ceph_mds_op_name(req->r_op), req->r_attempts);

	if (req->r_got_unsafe) {
		void *p;
		/*
		 * Replay.  Do not regenerate message (and rebuild
		 * paths, etc.); just use the original message.
		 * Rebuilding paths will break for renames because
		 * d_move mangles the src name.
		 */
		msg = req->r_request;
		rhead = msg->front.iov_base;

		flags = le32_to_cpu(rhead->flags);
		flags |= CEPH_MDS_FLAG_REPLAY;
		rhead->flags = cpu_to_le32(flags);

		if (req->r_target_inode)
			rhead->ino = cpu_to_le64(ceph_ino(req->r_target_inode));

		rhead->num_retry = req->r_attempts - 1;

		/* remove cap/dentry releases from message */
		rhead->num_releases = 0;

		/* time stamp */
		p = msg->front.iov_base + req->r_request_release_offset;
		ceph_encode_copy(&p, &req->r_stamp, sizeof(req->r_stamp));

		msg->front.iov_len = p - msg->front.iov_base;
		msg->hdr.front_len = cpu_to_le32(msg->front.iov_len);
		return 0;
	}

	if (req->r_request) {
		ceph_msg_put(req->r_request);
		req->r_request = NULL;
	}
	msg = create_request_message(mdsc, req, mds);
	if (IS_ERR(msg)) {
		req->r_err = PTR_ERR(msg);
		complete_request(mdsc, req);
		return PTR_ERR(msg);
	}
	req->r_request = msg;

	rhead = msg->front.iov_base;
	rhead->oldest_client_tid = cpu_to_le64(__get_oldest_tid(mdsc));
	if (req->r_got_unsafe)
		flags |= CEPH_MDS_FLAG_REPLAY;
	if (req->r_locked_dir)
		flags |= CEPH_MDS_FLAG_WANT_DENTRY;
	rhead->flags = cpu_to_le32(flags);
	rhead->num_fwd = req->r_num_fwd;
	rhead->num_retry = req->r_attempts - 1;
	rhead->ino = 0;

	dout(" r_locked_dir = %p\n", req->r_locked_dir);
	return 0;
}

/*
 * send request, or put it on the appropriate wait list.
 */
static int __do_request(struct ceph_mds_client *mdsc,
			struct ceph_mds_request *req)
{
	struct ceph_mds_session *session = NULL;
	int mds = -1;
	int err = -EAGAIN;

	if (req->r_err || req->r_got_result) {
		if (req->r_aborted)
			__unregister_request(mdsc, req);
		goto out;
	}

	if (req->r_timeout &&
	    time_after_eq(jiffies, req->r_started + req->r_timeout)) {
		dout("do_request timed out\n");
		err = -EIO;
		goto finish;
	}

	put_request_session(req);

	mds = __choose_mds(mdsc, req);
	if (mds < 0 ||
	    ceph_mdsmap_get_state(mdsc->mdsmap, mds) < CEPH_MDS_STATE_ACTIVE) {
		dout("do_request no mds or not active, waiting for map\n");
		list_add(&req->r_wait, &mdsc->waiting_for_map);
		goto out;
	}

	/* get, open session */
	session = __ceph_lookup_mds_session(mdsc, mds);
	if (!session) {
		session = register_session(mdsc, mds);
		if (IS_ERR(session)) {
			err = PTR_ERR(session);
			goto finish;
		}
	}
	req->r_session = get_session(session);

	dout("do_request mds%d session %p state %s\n", mds, session,
	     session_state_name(session->s_state));
	if (session->s_state != CEPH_MDS_SESSION_OPEN &&
	    session->s_state != CEPH_MDS_SESSION_HUNG) {
		if (session->s_state == CEPH_MDS_SESSION_NEW ||
		    session->s_state == CEPH_MDS_SESSION_CLOSING)
			__open_session(mdsc, session);
		list_add(&req->r_wait, &session->s_waiting);
		goto out_session;
	}

	/* send request */
	req->r_resend_mds = -1;   /* forget any previous mds hint */

	if (req->r_request_started == 0)   /* note request start time */
		req->r_request_started = jiffies;

	err = __prepare_send_request(mdsc, req, mds);
	if (!err) {
		ceph_msg_get(req->r_request);
		ceph_con_send(&session->s_con, req->r_request);
	}

out_session:
	ceph_put_mds_session(session);
out:
	return err;

finish:
	req->r_err = err;
	complete_request(mdsc, req);
	goto out;
}

/*
 * called under mdsc->mutex
 */
static void __wake_requests(struct ceph_mds_client *mdsc,
			    struct list_head *head)
{
	struct ceph_mds_request *req;
	LIST_HEAD(tmp_list);

	list_splice_init(head, &tmp_list);

	while (!list_empty(&tmp_list)) {
		req = list_entry(tmp_list.next,
				 struct ceph_mds_request, r_wait);
		list_del_init(&req->r_wait);
		dout(" wake request %p tid %llu\n", req, req->r_tid);
		__do_request(mdsc, req);
	}
}

/*
 * Wake up threads with requests pending for @mds, so that they can
 * resubmit their requests to a possibly different mds.
 */
static void kick_requests(struct ceph_mds_client *mdsc, int mds)
{
	struct ceph_mds_request *req;
	struct rb_node *p = rb_first(&mdsc->request_tree);

	dout("kick_requests mds%d\n", mds);
	while (p) {
		req = rb_entry(p, struct ceph_mds_request, r_node);
		p = rb_next(p);
		if (req->r_got_unsafe)
			continue;
		if (req->r_session &&
		    req->r_session->s_mds == mds) {
			dout(" kicking tid %llu\n", req->r_tid);
			__do_request(mdsc, req);
		}
	}
}

void ceph_mdsc_submit_request(struct ceph_mds_client *mdsc,
			      struct ceph_mds_request *req)
{
	dout("submit_request on %p\n", req);
	mutex_lock(&mdsc->mutex);
	__register_request(mdsc, req, NULL);
	__do_request(mdsc, req);
	mutex_unlock(&mdsc->mutex);
}

/*
 * Synchrously perform an mds request.  Take care of all of the
 * session setup, forwarding, retry details.
 */
int ceph_mdsc_do_request(struct ceph_mds_client *mdsc,
			 struct inode *dir,
			 struct ceph_mds_request *req)
{
	int err;

	dout("do_request on %p\n", req);

	/* take CAP_PIN refs for r_inode, r_locked_dir, r_old_dentry */
	if (req->r_inode)
		ceph_get_cap_refs(ceph_inode(req->r_inode), CEPH_CAP_PIN);
	if (req->r_locked_dir)
		ceph_get_cap_refs(ceph_inode(req->r_locked_dir), CEPH_CAP_PIN);
	if (req->r_old_dentry_dir)
		ceph_get_cap_refs(ceph_inode(req->r_old_dentry_dir),
				  CEPH_CAP_PIN);

	/* issue */
	mutex_lock(&mdsc->mutex);
	__register_request(mdsc, req, dir);
	__do_request(mdsc, req);

	if (req->r_err) {
		err = req->r_err;
		__unregister_request(mdsc, req);
		dout("do_request early error %d\n", err);
		goto out;
	}

	/* wait */
	mutex_unlock(&mdsc->mutex);
	dout("do_request waiting\n");
	if (req->r_timeout) {
		err = (long)wait_for_completion_killable_timeout(
			&req->r_completion, req->r_timeout);
		if (err == 0)
			err = -EIO;
	} else {
		err = wait_for_completion_killable(&req->r_completion);
	}
	dout("do_request waited, got %d\n", err);
	mutex_lock(&mdsc->mutex);

	/* only abort if we didn't race with a real reply */
	if (req->r_got_result) {
		err = le32_to_cpu(req->r_reply_info.head->result);
	} else if (err < 0) {
		dout("aborted request %lld with %d\n", req->r_tid, err);

		/*
		 * ensure we aren't running concurrently with
		 * ceph_fill_trace or ceph_readdir_prepopulate, which
		 * rely on locks (dir mutex) held by our caller.
		 */
		mutex_lock(&req->r_fill_mutex);
		req->r_err = err;
		req->r_aborted = true;
		mutex_unlock(&req->r_fill_mutex);

		if (req->r_locked_dir &&
		    (req->r_op & CEPH_MDS_OP_WRITE))
			ceph_invalidate_dir_request(req);
	} else {
		err = req->r_err;
	}

out:
	mutex_unlock(&mdsc->mutex);
	dout("do_request %p done, result %d\n", req, err);
	return err;
}

/*
 * Invalidate dir's completeness, dentry lease state on an aborted MDS
 * namespace request.
 */
void ceph_invalidate_dir_request(struct ceph_mds_request *req)
{
	struct inode *inode = req->r_locked_dir;

	dout("invalidate_dir_request %p (complete, lease(s))\n", inode);

	ceph_dir_clear_complete(inode);
	if (req->r_dentry)
		ceph_invalidate_dentry_lease(req->r_dentry);
	if (req->r_old_dentry)
		ceph_invalidate_dentry_lease(req->r_old_dentry);
}

/*
 * Handle mds reply.
 *
 * We take the session mutex and parse and process the reply immediately.
 * This preserves the logical ordering of replies, capabilities, etc., sent
 * by the MDS as they are applied to our local cache.
 */
static void handle_reply(struct ceph_mds_session *session, struct ceph_msg *msg)
{
	struct ceph_mds_client *mdsc = session->s_mdsc;
	struct ceph_mds_request *req;
	struct ceph_mds_reply_head *head = msg->front.iov_base;
	struct ceph_mds_reply_info_parsed *rinfo;  /* parsed reply info */
	u64 tid;
	int err, result;
	int mds = session->s_mds;

	if (msg->front.iov_len < sizeof(*head)) {
		pr_err("mdsc_handle_reply got corrupt (short) reply\n");
		ceph_msg_dump(msg);
		return;
	}

	/* get request, session */
	tid = le64_to_cpu(msg->hdr.tid);
	mutex_lock(&mdsc->mutex);
	req = __lookup_request(mdsc, tid);
	if (!req) {
		dout("handle_reply on unknown tid %llu\n", tid);
		mutex_unlock(&mdsc->mutex);
		return;
	}
	dout("handle_reply %p\n", req);

	/* correct session? */
	if (req->r_session != session) {
		pr_err("mdsc_handle_reply got %llu on session mds%d"
		       " not mds%d\n", tid, session->s_mds,
		       req->r_session ? req->r_session->s_mds : -1);
		mutex_unlock(&mdsc->mutex);
		goto out;
	}

	/* dup? */
	if ((req->r_got_unsafe && !head->safe) ||
	    (req->r_got_safe && head->safe)) {
		pr_warn("got a dup %s reply on %llu from mds%d\n",
			   head->safe ? "safe" : "unsafe", tid, mds);
		mutex_unlock(&mdsc->mutex);
		goto out;
	}
	if (req->r_got_safe && !head->safe) {
		pr_warn("got unsafe after safe on %llu from mds%d\n",
			   tid, mds);
		mutex_unlock(&mdsc->mutex);
		goto out;
	}

	result = le32_to_cpu(head->result);

	/*
	 * Handle an ESTALE
	 * if we're not talking to the authority, send to them
	 * if the authority has changed while we weren't looking,
	 * send to new authority
	 * Otherwise we just have to return an ESTALE
	 */
	if (result == -ESTALE) {
		dout("got ESTALE on request %llu", req->r_tid);
		req->r_resend_mds = -1;
		if (req->r_direct_mode != USE_AUTH_MDS) {
			dout("not using auth, setting for that now");
			req->r_direct_mode = USE_AUTH_MDS;
			__do_request(mdsc, req);
			mutex_unlock(&mdsc->mutex);
			goto out;
		} else  {
			int mds = __choose_mds(mdsc, req);
			if (mds >= 0 && mds != req->r_session->s_mds) {
				dout("but auth changed, so resending");
				__do_request(mdsc, req);
				mutex_unlock(&mdsc->mutex);
				goto out;
			}
		}
		dout("have to return ESTALE on request %llu", req->r_tid);
	}


	if (head->safe) {
		req->r_got_safe = true;
		__unregister_request(mdsc, req);

		if (req->r_got_unsafe) {
			/*
			 * We already handled the unsafe response, now do the
			 * cleanup.  No need to examine the response; the MDS
			 * doesn't include any result info in the safe
			 * response.  And even if it did, there is nothing
			 * useful we could do with a revised return value.
			 */
			dout("got safe reply %llu, mds%d\n", tid, mds);
			list_del_init(&req->r_unsafe_item);

			/* last unsafe request during umount? */
			if (mdsc->stopping && !__get_oldest_req(mdsc))
				complete_all(&mdsc->safe_umount_waiters);
			mutex_unlock(&mdsc->mutex);
			goto out;
		}
	} else {
		req->r_got_unsafe = true;
		list_add_tail(&req->r_unsafe_item, &req->r_session->s_unsafe);
	}

	dout("handle_reply tid %lld result %d\n", tid, result);
	rinfo = &req->r_reply_info;
	err = parse_reply_info(msg, rinfo, session->s_con.peer_features);
	mutex_unlock(&mdsc->mutex);

	mutex_lock(&session->s_mutex);
	if (err < 0) {
		pr_err("mdsc_handle_reply got corrupt reply mds%d(tid:%lld)\n", mds, tid);
		ceph_msg_dump(msg);
		goto out_err;
	}

	/* snap trace */
	if (rinfo->snapblob_len) {
		down_write(&mdsc->snap_rwsem);
		ceph_update_snap_trace(mdsc, rinfo->snapblob,
			       rinfo->snapblob + rinfo->snapblob_len,
			       le32_to_cpu(head->op) == CEPH_MDS_OP_RMSNAP);
		downgrade_write(&mdsc->snap_rwsem);
	} else {
		down_read(&mdsc->snap_rwsem);
	}

	/* insert trace into our cache */
	mutex_lock(&req->r_fill_mutex);
	err = ceph_fill_trace(mdsc->fsc->sb, req, req->r_session);
	if (err == 0) {
		if (result == 0 && (req->r_op == CEPH_MDS_OP_READDIR ||
				    req->r_op == CEPH_MDS_OP_LSSNAP))
			ceph_readdir_prepopulate(req, req->r_session);
		ceph_unreserve_caps(mdsc, &req->r_caps_reservation);
	}
	mutex_unlock(&req->r_fill_mutex);

	up_read(&mdsc->snap_rwsem);
out_err:
	mutex_lock(&mdsc->mutex);
	if (!req->r_aborted) {
		if (err) {
			req->r_err = err;
		} else {
			req->r_reply = msg;
			ceph_msg_get(msg);
			req->r_got_result = true;
		}
	} else {
		dout("reply arrived after request %lld was aborted\n", tid);
	}
	mutex_unlock(&mdsc->mutex);

	ceph_add_cap_releases(mdsc, req->r_session);
	mutex_unlock(&session->s_mutex);

	/* kick calling process */
	complete_request(mdsc, req);
out:
	ceph_mdsc_put_request(req);
	return;
}



/*
 * handle mds notification that our request has been forwarded.
 */
static void handle_forward(struct ceph_mds_client *mdsc,
			   struct ceph_mds_session *session,
			   struct ceph_msg *msg)
{
	struct ceph_mds_request *req;
	u64 tid = le64_to_cpu(msg->hdr.tid);
	u32 next_mds;
	u32 fwd_seq;
	int err = -EINVAL;
	void *p = msg->front.iov_base;
	void *end = p + msg->front.iov_len;

	ceph_decode_need(&p, end, 2*sizeof(u32), bad);
	next_mds = ceph_decode_32(&p);
	fwd_seq = ceph_decode_32(&p);

	mutex_lock(&mdsc->mutex);
	req = __lookup_request(mdsc, tid);
	if (!req) {
		dout("forward tid %llu to mds%d - req dne\n", tid, next_mds);
		goto out;  /* dup reply? */
	}

	if (req->r_aborted) {
		dout("forward tid %llu aborted, unregistering\n", tid);
		__unregister_request(mdsc, req);
	} else if (fwd_seq <= req->r_num_fwd) {
		dout("forward tid %llu to mds%d - old seq %d <= %d\n",
		     tid, next_mds, req->r_num_fwd, fwd_seq);
	} else {
		/* resend. forward race not possible; mds would drop */
		dout("forward tid %llu to mds%d (we resend)\n", tid, next_mds);
		BUG_ON(req->r_err);
		BUG_ON(req->r_got_result);
		req->r_num_fwd = fwd_seq;
		req->r_resend_mds = next_mds;
		put_request_session(req);
		__do_request(mdsc, req);
	}
	ceph_mdsc_put_request(req);
out:
	mutex_unlock(&mdsc->mutex);
	return;

bad:
	pr_err("mdsc_handle_forward decode error err=%d\n", err);
}

/*
 * handle a mds session control message
 */
static void handle_session(struct ceph_mds_session *session,
			   struct ceph_msg *msg)
{
	struct ceph_mds_client *mdsc = session->s_mdsc;
	u32 op;
	u64 seq;
	int mds = session->s_mds;
	struct ceph_mds_session_head *h = msg->front.iov_base;
	int wake = 0;

	/* decode */
	if (msg->front.iov_len != sizeof(*h))
		goto bad;
	op = le32_to_cpu(h->op);
	seq = le64_to_cpu(h->seq);

	mutex_lock(&mdsc->mutex);
	if (op == CEPH_SESSION_CLOSE)
		__unregister_session(mdsc, session);
	/* FIXME: this ttl calculation is generous */
	session->s_ttl = jiffies + HZ*mdsc->mdsmap->m_session_autoclose;
	mutex_unlock(&mdsc->mutex);

	mutex_lock(&session->s_mutex);

	dout("handle_session mds%d %s %p state %s seq %llu\n",
	     mds, ceph_session_op_name(op), session,
	     session_state_name(session->s_state), seq);

	if (session->s_state == CEPH_MDS_SESSION_HUNG) {
		session->s_state = CEPH_MDS_SESSION_OPEN;
		pr_info("mds%d came back\n", session->s_mds);
	}

	switch (op) {
	case CEPH_SESSION_OPEN:
		if (session->s_state == CEPH_MDS_SESSION_RECONNECTING)
			pr_info("mds%d reconnect success\n", session->s_mds);
		session->s_state = CEPH_MDS_SESSION_OPEN;
		renewed_caps(mdsc, session, 0);
		wake = 1;
		if (mdsc->stopping)
			__close_session(mdsc, session);
		break;

	case CEPH_SESSION_RENEWCAPS:
		if (session->s_renew_seq == seq)
			renewed_caps(mdsc, session, 1);
		break;

	case CEPH_SESSION_CLOSE:
		if (session->s_state == CEPH_MDS_SESSION_RECONNECTING)
			pr_info("mds%d reconnect denied\n", session->s_mds);
		remove_session_caps(session);
		wake = 1; /* for good measure */
		wake_up_all(&mdsc->session_close_wq);
		kick_requests(mdsc, mds);
		break;

	case CEPH_SESSION_STALE:
		pr_info("mds%d caps went stale, renewing\n",
			session->s_mds);
		spin_lock(&session->s_gen_ttl_lock);
		session->s_cap_gen++;
		session->s_cap_ttl = jiffies - 1;
		spin_unlock(&session->s_gen_ttl_lock);
		send_renew_caps(mdsc, session);
		break;

	case CEPH_SESSION_RECALL_STATE:
		trim_caps(mdsc, session, le32_to_cpu(h->max_caps));
		break;

	case CEPH_SESSION_FLUSHMSG:
		send_flushmsg_ack(mdsc, session, seq);
		break;

	default:
		pr_err("mdsc_handle_session bad op %d mds%d\n", op, mds);
		WARN_ON(1);
	}

	mutex_unlock(&session->s_mutex);
	if (wake) {
		mutex_lock(&mdsc->mutex);
		__wake_requests(mdsc, &session->s_waiting);
		mutex_unlock(&mdsc->mutex);
	}
	return;

bad:
	pr_err("mdsc_handle_session corrupt message mds%d len %d\n", mds,
	       (int)msg->front.iov_len);
	ceph_msg_dump(msg);
	return;
}


/*
 * called under session->mutex.
 */
static void replay_unsafe_requests(struct ceph_mds_client *mdsc,
				   struct ceph_mds_session *session)
{
	struct ceph_mds_request *req, *nreq;
	int err;

	dout("replay_unsafe_requests mds%d\n", session->s_mds);

	mutex_lock(&mdsc->mutex);
	list_for_each_entry_safe(req, nreq, &session->s_unsafe, r_unsafe_item) {
		err = __prepare_send_request(mdsc, req, session->s_mds);
		if (!err) {
			ceph_msg_get(req->r_request);
			ceph_con_send(&session->s_con, req->r_request);
		}
	}
	mutex_unlock(&mdsc->mutex);
}

/*
 * Encode information about a cap for a reconnect with the MDS.
 */
static int encode_caps_cb(struct inode *inode, struct ceph_cap *cap,
			  void *arg)
{
	union {
		struct ceph_mds_cap_reconnect v2;
		struct ceph_mds_cap_reconnect_v1 v1;
	} rec;
	size_t reclen;
	struct ceph_inode_info *ci;
	struct ceph_reconnect_state *recon_state = arg;
	struct ceph_pagelist *pagelist = recon_state->pagelist;
	char *path;
	int pathlen, err;
	u64 pathbase;
	struct dentry *dentry;

	ci = cap->ci;

	dout(" adding %p ino %llx.%llx cap %p %lld %s\n",
	     inode, ceph_vinop(inode), cap, cap->cap_id,
	     ceph_cap_string(cap->issued));
	err = ceph_pagelist_encode_64(pagelist, ceph_ino(inode));
	if (err)
		return err;

	dentry = d_find_alias(inode);
	if (dentry) {
		path = ceph_mdsc_build_path(dentry, &pathlen, &pathbase, 0);
		if (IS_ERR(path)) {
			err = PTR_ERR(path);
			goto out_dput;
		}
	} else {
		path = NULL;
		pathlen = 0;
	}
	err = ceph_pagelist_encode_string(pagelist, path, pathlen);
	if (err)
		goto out_free;

	spin_lock(&ci->i_ceph_lock);
	cap->seq = 0;        /* reset cap seq */
	cap->issue_seq = 0;  /* and issue_seq */
	cap->mseq = 0;       /* and migrate_seq */
	cap->cap_gen = cap->session->s_cap_gen;

	if (recon_state->flock) {
		rec.v2.cap_id = cpu_to_le64(cap->cap_id);
		rec.v2.wanted = cpu_to_le32(__ceph_caps_wanted(ci));
		rec.v2.issued = cpu_to_le32(cap->issued);
		rec.v2.snaprealm = cpu_to_le64(ci->i_snap_realm->ino);
		rec.v2.pathbase = cpu_to_le64(pathbase);
		rec.v2.flock_len = 0;
		reclen = sizeof(rec.v2);
	} else {
		rec.v1.cap_id = cpu_to_le64(cap->cap_id);
		rec.v1.wanted = cpu_to_le32(__ceph_caps_wanted(ci));
		rec.v1.issued = cpu_to_le32(cap->issued);
		rec.v1.size = cpu_to_le64(inode->i_size);
		ceph_encode_timespec(&rec.v1.mtime, &inode->i_mtime);
		ceph_encode_timespec(&rec.v1.atime, &inode->i_atime);
		rec.v1.snaprealm = cpu_to_le64(ci->i_snap_realm->ino);
		rec.v1.pathbase = cpu_to_le64(pathbase);
		reclen = sizeof(rec.v1);
	}
	spin_unlock(&ci->i_ceph_lock);

	if (recon_state->flock) {
		int num_fcntl_locks, num_flock_locks;
		struct ceph_filelock *flocks;

encode_again:
		spin_lock(&inode->i_lock);
		ceph_count_locks(inode, &num_fcntl_locks, &num_flock_locks);
		spin_unlock(&inode->i_lock);
		flocks = kmalloc((num_fcntl_locks+num_flock_locks) *
				 sizeof(struct ceph_filelock), GFP_NOFS);
		if (!flocks) {
			err = -ENOMEM;
			goto out_free;
		}
		spin_lock(&inode->i_lock);
		err = ceph_encode_locks_to_buffer(inode, flocks,
						  num_fcntl_locks,
						  num_flock_locks);
		spin_unlock(&inode->i_lock);
		if (err) {
			kfree(flocks);
			if (err == -ENOSPC)
				goto encode_again;
			goto out_free;
		}
		/*
		 * number of encoded locks is stable, so copy to pagelist
		 */
		rec.v2.flock_len = cpu_to_le32(2*sizeof(u32) +
				    (num_fcntl_locks+num_flock_locks) *
				    sizeof(struct ceph_filelock));
		err = ceph_pagelist_append(pagelist, &rec, reclen);
		if (!err)
			err = ceph_locks_to_pagelist(flocks, pagelist,
						     num_fcntl_locks,
						     num_flock_locks);
		kfree(flocks);
	} else {
		err = ceph_pagelist_append(pagelist, &rec, reclen);
	}

	recon_state->nr_caps++;
out_free:
	kfree(path);
out_dput:
	dput(dentry);
	return err;
}


/*
 * If an MDS fails and recovers, clients need to reconnect in order to
 * reestablish shared state.  This includes all caps issued through
 * this session _and_ the snap_realm hierarchy.  Because it's not
 * clear which snap realms the mds cares about, we send everything we
 * know about.. that ensures we'll then get any new info the
 * recovering MDS might have.
 *
 * This is a relatively heavyweight operation, but it's rare.
 *
 * called with mdsc->mutex held.
 */
static void send_mds_reconnect(struct ceph_mds_client *mdsc,
			       struct ceph_mds_session *session)
{
	struct ceph_msg *reply;
	struct rb_node *p;
	int mds = session->s_mds;
	int err = -ENOMEM;
	int s_nr_caps;
	struct ceph_pagelist *pagelist;
	struct ceph_reconnect_state recon_state;

	pr_info("mds%d reconnect start\n", mds);

	pagelist = kmalloc(sizeof(*pagelist), GFP_NOFS);
	if (!pagelist)
		goto fail_nopagelist;
	ceph_pagelist_init(pagelist);

	reply = ceph_msg_new(CEPH_MSG_CLIENT_RECONNECT, 0, GFP_NOFS, false);
	if (!reply)
		goto fail_nomsg;

	mutex_lock(&session->s_mutex);
	session->s_state = CEPH_MDS_SESSION_RECONNECTING;
	session->s_seq = 0;

	ceph_con_close(&session->s_con);
	ceph_con_open(&session->s_con,
		      CEPH_ENTITY_TYPE_MDS, mds,
		      ceph_mdsmap_get_addr(mdsc->mdsmap, mds));

	/* replay unsafe requests */
	replay_unsafe_requests(mdsc, session);

	down_read(&mdsc->snap_rwsem);

	dout("session %p state %s\n", session,
	     session_state_name(session->s_state));

	spin_lock(&session->s_gen_ttl_lock);
	session->s_cap_gen++;
	spin_unlock(&session->s_gen_ttl_lock);

	spin_lock(&session->s_cap_lock);
	/*
	 * notify __ceph_remove_cap() that we are composing cap reconnect.
	 * If a cap get released before being added to the cap reconnect,
	 * __ceph_remove_cap() should skip queuing cap release.
	 */
	session->s_cap_reconnect = 1;
	/* drop old cap expires; we're about to reestablish that state */
	discard_cap_releases(mdsc, session);
	spin_unlock(&session->s_cap_lock);

	/* traverse this session's caps */
	s_nr_caps = session->s_nr_caps;
	err = ceph_pagelist_encode_32(pagelist, s_nr_caps);
	if (err)
		goto fail;

	recon_state.nr_caps = 0;
	recon_state.pagelist = pagelist;
	recon_state.flock = session->s_con.peer_features & CEPH_FEATURE_FLOCK;
	err = iterate_session_caps(session, encode_caps_cb, &recon_state);
	if (err < 0)
		goto fail;

	spin_lock(&session->s_cap_lock);
	session->s_cap_reconnect = 0;
	spin_unlock(&session->s_cap_lock);

	/*
	 * snaprealms.  we provide mds with the ino, seq (version), and
	 * parent for all of our realms.  If the mds has any newer info,
	 * it will tell us.
	 */
	for (p = rb_first(&mdsc->snap_realms); p; p = rb_next(p)) {
		struct ceph_snap_realm *realm =
			rb_entry(p, struct ceph_snap_realm, node);
		struct ceph_mds_snaprealm_reconnect sr_rec;

		dout(" adding snap realm %llx seq %lld parent %llx\n",
		     realm->ino, realm->seq, realm->parent_ino);
		sr_rec.ino = cpu_to_le64(realm->ino);
		sr_rec.seq = cpu_to_le64(realm->seq);
		sr_rec.parent = cpu_to_le64(realm->parent_ino);
		err = ceph_pagelist_append(pagelist, &sr_rec, sizeof(sr_rec));
		if (err)
			goto fail;
	}

	if (recon_state.flock)
		reply->hdr.version = cpu_to_le16(2);

	/* raced with cap release? */
	if (s_nr_caps != recon_state.nr_caps) {
		struct page *page = list_first_entry(&pagelist->head,
						     struct page, lru);
		__le32 *addr = kmap_atomic(page);
		*addr = cpu_to_le32(recon_state.nr_caps);
		kunmap_atomic(addr);
	}

	reply->hdr.data_len = cpu_to_le32(pagelist->length);
	ceph_msg_data_add_pagelist(reply, pagelist);
	ceph_con_send(&session->s_con, reply);

	mutex_unlock(&session->s_mutex);

	mutex_lock(&mdsc->mutex);
	__wake_requests(mdsc, &session->s_waiting);
	mutex_unlock(&mdsc->mutex);

	up_read(&mdsc->snap_rwsem);
	return;

fail:
	ceph_msg_put(reply);
	up_read(&mdsc->snap_rwsem);
	mutex_unlock(&session->s_mutex);
fail_nomsg:
	ceph_pagelist_release(pagelist);
	kfree(pagelist);
fail_nopagelist:
	pr_err("error %d preparing reconnect for mds%d\n", err, mds);
	return;
}


/*
 * compare old and new mdsmaps, kicking requests
 * and closing out old connections as necessary
 *
 * called under mdsc->mutex.
 */
static void check_new_map(struct ceph_mds_client *mdsc,
			  struct ceph_mdsmap *newmap,
			  struct ceph_mdsmap *oldmap)
{
	int i;
	int oldstate, newstate;
	struct ceph_mds_session *s;

	dout("check_new_map new %u old %u\n",
	     newmap->m_epoch, oldmap->m_epoch);

	for (i = 0; i < oldmap->m_max_mds && i < mdsc->max_sessions; i++) {
		if (mdsc->sessions[i] == NULL)
			continue;
		s = mdsc->sessions[i];
		oldstate = ceph_mdsmap_get_state(oldmap, i);
		newstate = ceph_mdsmap_get_state(newmap, i);

		dout("check_new_map mds%d state %s%s -> %s%s (session %s)\n",
		     i, ceph_mds_state_name(oldstate),
		     ceph_mdsmap_is_laggy(oldmap, i) ? " (laggy)" : "",
		     ceph_mds_state_name(newstate),
		     ceph_mdsmap_is_laggy(newmap, i) ? " (laggy)" : "",
		     session_state_name(s->s_state));

		if (i >= newmap->m_max_mds ||
		    memcmp(ceph_mdsmap_get_addr(oldmap, i),
			   ceph_mdsmap_get_addr(newmap, i),
			   sizeof(struct ceph_entity_addr))) {
			if (s->s_state == CEPH_MDS_SESSION_OPENING) {
				/* the session never opened, just close it
				 * out now */
				__wake_requests(mdsc, &s->s_waiting);
				__unregister_session(mdsc, s);
			} else {
				/* just close it */
				mutex_unlock(&mdsc->mutex);
				mutex_lock(&s->s_mutex);
				mutex_lock(&mdsc->mutex);
				ceph_con_close(&s->s_con);
				mutex_unlock(&s->s_mutex);
				s->s_state = CEPH_MDS_SESSION_RESTARTING;
			}

			/* kick any requests waiting on the recovering mds */
			kick_requests(mdsc, i);
		} else if (oldstate == newstate) {
			continue;  /* nothing new with this mds */
		}

		/*
		 * send reconnect?
		 */
		if (s->s_state == CEPH_MDS_SESSION_RESTARTING &&
		    newstate >= CEPH_MDS_STATE_RECONNECT) {
			mutex_unlock(&mdsc->mutex);
			send_mds_reconnect(mdsc, s);
			mutex_lock(&mdsc->mutex);
		}

		/*
		 * kick request on any mds that has gone active.
		 */
		if (oldstate < CEPH_MDS_STATE_ACTIVE &&
		    newstate >= CEPH_MDS_STATE_ACTIVE) {
			if (oldstate != CEPH_MDS_STATE_CREATING &&
			    oldstate != CEPH_MDS_STATE_STARTING)
				pr_info("mds%d recovery completed\n", s->s_mds);
			kick_requests(mdsc, i);
			ceph_kick_flushing_caps(mdsc, s);
			wake_up_session_caps(s, 1);
		}
	}

	for (i = 0; i < newmap->m_max_mds && i < mdsc->max_sessions; i++) {
		s = mdsc->sessions[i];
		if (!s)
			continue;
		if (!ceph_mdsmap_is_laggy(newmap, i))
			continue;
		if (s->s_state == CEPH_MDS_SESSION_OPEN ||
		    s->s_state == CEPH_MDS_SESSION_HUNG ||
		    s->s_state == CEPH_MDS_SESSION_CLOSING) {
			dout(" connecting to export targets of laggy mds%d\n",
			     i);
			__open_export_target_sessions(mdsc, s);
		}
	}
}



/*
 * leases
 */

/*
 * caller must hold session s_mutex, dentry->d_lock
 */
void __ceph_mdsc_drop_dentry_lease(struct dentry *dentry)
{
	struct ceph_dentry_info *di = ceph_dentry(dentry);

	ceph_put_mds_session(di->lease_session);
	di->lease_session = NULL;
}

static void handle_lease(struct ceph_mds_client *mdsc,
			 struct ceph_mds_session *session,
			 struct ceph_msg *msg)
{
	struct super_block *sb = mdsc->fsc->sb;
	struct inode *inode;
	struct dentry *parent, *dentry;
	struct ceph_dentry_info *di;
	int mds = session->s_mds;
	struct ceph_mds_lease *h = msg->front.iov_base;
	u32 seq;
	struct ceph_vino vino;
	struct qstr dname;
	int release = 0;

	dout("handle_lease from mds%d\n", mds);

	/* decode */
	if (msg->front.iov_len < sizeof(*h) + sizeof(u32))
		goto bad;
	vino.ino = le64_to_cpu(h->ino);
	vino.snap = CEPH_NOSNAP;
	seq = le32_to_cpu(h->seq);
	dname.name = (void *)h + sizeof(*h) + sizeof(u32);
	dname.len = msg->front.iov_len - sizeof(*h) - sizeof(u32);
	if (dname.len != get_unaligned_le32(h+1))
		goto bad;

	mutex_lock(&session->s_mutex);
	session->s_seq++;

	/* lookup inode */
	inode = ceph_find_inode(sb, vino);
	dout("handle_lease %s, ino %llx %p %.*s\n",
	     ceph_lease_op_name(h->action), vino.ino, inode,
	     dname.len, dname.name);
	if (inode == NULL) {
		dout("handle_lease no inode %llx\n", vino.ino);
		goto release;
	}

	/* dentry */
	parent = d_find_alias(inode);
	if (!parent) {
		dout("no parent dentry on inode %p\n", inode);
		WARN_ON(1);
		goto release;  /* hrm... */
	}
	dname.hash = full_name_hash(dname.name, dname.len);
	dentry = d_lookup(parent, &dname);
	dput(parent);
	if (!dentry)
		goto release;

	spin_lock(&dentry->d_lock);
	di = ceph_dentry(dentry);
	switch (h->action) {
	case CEPH_MDS_LEASE_REVOKE:
		if (di->lease_session == session) {
			if (ceph_seq_cmp(di->lease_seq, seq) > 0)
				h->seq = cpu_to_le32(di->lease_seq);
			__ceph_mdsc_drop_dentry_lease(dentry);
		}
		release = 1;
		break;

	case CEPH_MDS_LEASE_RENEW:
		if (di->lease_session == session &&
		    di->lease_gen == session->s_cap_gen &&
		    di->lease_renew_from &&
		    di->lease_renew_after == 0) {
			unsigned long duration =
				le32_to_cpu(h->duration_ms) * HZ / 1000;

			di->lease_seq = seq;
			dentry->d_time = di->lease_renew_from + duration;
			di->lease_renew_after = di->lease_renew_from +
				(duration >> 1);
			di->lease_renew_from = 0;
		}
		break;
	}
	spin_unlock(&dentry->d_lock);
	dput(dentry);

	if (!release)
		goto out;

release:
	/* let's just reuse the same message */
	h->action = CEPH_MDS_LEASE_REVOKE_ACK;
	ceph_msg_get(msg);
	ceph_con_send(&session->s_con, msg);

out:
	iput(inode);
	mutex_unlock(&session->s_mutex);
	return;

bad:
	pr_err("corrupt lease message\n");
	ceph_msg_dump(msg);
}

void ceph_mdsc_lease_send_msg(struct ceph_mds_session *session,
			      struct inode *inode,
			      struct dentry *dentry, char action,
			      u32 seq)
{
	struct ceph_msg *msg;
	struct ceph_mds_lease *lease;
	int len = sizeof(*lease) + sizeof(u32);
	int dnamelen = 0;

	dout("lease_send_msg inode %p dentry %p %s to mds%d\n",
	     inode, dentry, ceph_lease_op_name(action), session->s_mds);
	dnamelen = dentry->d_name.len;
	len += dnamelen;

	msg = ceph_msg_new(CEPH_MSG_CLIENT_LEASE, len, GFP_NOFS, false);
	if (!msg)
		return;
	lease = msg->front.iov_base;
	lease->action = action;
	lease->ino = cpu_to_le64(ceph_vino(inode).ino);
	lease->first = lease->last = cpu_to_le64(ceph_vino(inode).snap);
	lease->seq = cpu_to_le32(seq);
	put_unaligned_le32(dnamelen, lease + 1);
	memcpy((void *)(lease + 1) + 4, dentry->d_name.name, dnamelen);

	/*
	 * if this is a preemptive lease RELEASE, no need to
	 * flush request stream, since the actual request will
	 * soon follow.
	 */
	msg->more_to_follow = (action == CEPH_MDS_LEASE_RELEASE);

	ceph_con_send(&session->s_con, msg);
}

/*
 * Preemptively release a lease we expect to invalidate anyway.
 * Pass @inode always, @dentry is optional.
 */
void ceph_mdsc_lease_release(struct ceph_mds_client *mdsc, struct inode *inode,
			     struct dentry *dentry)
{
	struct ceph_dentry_info *di;
	struct ceph_mds_session *session;
	u32 seq;

	BUG_ON(inode == NULL);
	BUG_ON(dentry == NULL);

	/* is dentry lease valid? */
	spin_lock(&dentry->d_lock);
	di = ceph_dentry(dentry);
	if (!di || !di->lease_session ||
	    di->lease_session->s_mds < 0 ||
	    di->lease_gen != di->lease_session->s_cap_gen ||
	    !time_before(jiffies, dentry->d_time)) {
		dout("lease_release inode %p dentry %p -- "
		     "no lease\n",
		     inode, dentry);
		spin_unlock(&dentry->d_lock);
		return;
	}

	/* we do have a lease on this dentry; note mds and seq */
	session = ceph_get_mds_session(di->lease_session);
	seq = di->lease_seq;
	__ceph_mdsc_drop_dentry_lease(dentry);
	spin_unlock(&dentry->d_lock);

	dout("lease_release inode %p dentry %p to mds%d\n",
	     inode, dentry, session->s_mds);
	ceph_mdsc_lease_send_msg(session, inode, dentry,
				 CEPH_MDS_LEASE_RELEASE, seq);
	ceph_put_mds_session(session);
}

/*
 * drop all leases (and dentry refs) in preparation for umount
 */
static void drop_leases(struct ceph_mds_client *mdsc)
{
	int i;

	dout("drop_leases\n");
	mutex_lock(&mdsc->mutex);
	for (i = 0; i < mdsc->max_sessions; i++) {
		struct ceph_mds_session *s = __ceph_lookup_mds_session(mdsc, i);
		if (!s)
			continue;
		mutex_unlock(&mdsc->mutex);
		mutex_lock(&s->s_mutex);
		mutex_unlock(&s->s_mutex);
		ceph_put_mds_session(s);
		mutex_lock(&mdsc->mutex);
	}
	mutex_unlock(&mdsc->mutex);
}



/*
 * delayed work -- periodically trim expired leases, renew caps with mds
 */
static void schedule_delayed(struct ceph_mds_client *mdsc)
{
	int delay = 5;
	unsigned hz = round_jiffies_relative(HZ * delay);
	schedule_delayed_work(&mdsc->delayed_work, hz);
}

static void delayed_work(struct work_struct *work)
{
	int i;
	struct ceph_mds_client *mdsc =
		container_of(work, struct ceph_mds_client, delayed_work.work);
	int renew_interval;
	int renew_caps;

	dout("mdsc delayed_work\n");
	ceph_check_delayed_caps(mdsc);

	mutex_lock(&mdsc->mutex);
	renew_interval = mdsc->mdsmap->m_session_timeout >> 2;
	renew_caps = time_after_eq(jiffies, HZ*renew_interval +
				   mdsc->last_renew_caps);
	if (renew_caps)
		mdsc->last_renew_caps = jiffies;

	for (i = 0; i < mdsc->max_sessions; i++) {
		struct ceph_mds_session *s = __ceph_lookup_mds_session(mdsc, i);
		if (s == NULL)
			continue;
		if (s->s_state == CEPH_MDS_SESSION_CLOSING) {
			dout("resending session close request for mds%d\n",
			     s->s_mds);
			request_close_session(mdsc, s);
			ceph_put_mds_session(s);
			continue;
		}
		if (s->s_ttl && time_after(jiffies, s->s_ttl)) {
			if (s->s_state == CEPH_MDS_SESSION_OPEN) {
				s->s_state = CEPH_MDS_SESSION_HUNG;
				pr_info("mds%d hung\n", s->s_mds);
			}
		}
		if (s->s_state < CEPH_MDS_SESSION_OPEN) {
			/* this mds is failed or recovering, just wait */
			ceph_put_mds_session(s);
			continue;
		}
		mutex_unlock(&mdsc->mutex);

		mutex_lock(&s->s_mutex);
		if (renew_caps)
			send_renew_caps(mdsc, s);
		else
			ceph_con_keepalive(&s->s_con);
		ceph_add_cap_releases(mdsc, s);
		if (s->s_state == CEPH_MDS_SESSION_OPEN ||
		    s->s_state == CEPH_MDS_SESSION_HUNG)
			ceph_send_cap_releases(mdsc, s);
		mutex_unlock(&s->s_mutex);
		ceph_put_mds_session(s);

		mutex_lock(&mdsc->mutex);
	}
	mutex_unlock(&mdsc->mutex);

	schedule_delayed(mdsc);
}

int ceph_mdsc_init(struct ceph_fs_client *fsc)

{
	struct ceph_mds_client *mdsc;

	mdsc = kzalloc(sizeof(struct ceph_mds_client), GFP_NOFS);
	if (!mdsc)
		return -ENOMEM;
	mdsc->fsc = fsc;
	fsc->mdsc = mdsc;
	mutex_init(&mdsc->mutex);
	mdsc->mdsmap = kzalloc(sizeof(*mdsc->mdsmap), GFP_NOFS);
	if (mdsc->mdsmap == NULL) {
		kfree(mdsc);
		return -ENOMEM;
	}

	init_completion(&mdsc->safe_umount_waiters);
	init_waitqueue_head(&mdsc->session_close_wq);
	INIT_LIST_HEAD(&mdsc->waiting_for_map);
	mdsc->sessions = NULL;
	mdsc->max_sessions = 0;
	mdsc->stopping = 0;
	init_rwsem(&mdsc->snap_rwsem);
	mdsc->snap_realms = RB_ROOT;
	INIT_LIST_HEAD(&mdsc->snap_empty);
	spin_lock_init(&mdsc->snap_empty_lock);
	mdsc->last_tid = 0;
	mdsc->request_tree = RB_ROOT;
	INIT_DELAYED_WORK(&mdsc->delayed_work, delayed_work);
	mdsc->last_renew_caps = jiffies;
	INIT_LIST_HEAD(&mdsc->cap_delay_list);
	spin_lock_init(&mdsc->cap_delay_lock);
	INIT_LIST_HEAD(&mdsc->snap_flush_list);
	spin_lock_init(&mdsc->snap_flush_lock);
	mdsc->cap_flush_seq = 0;
	INIT_LIST_HEAD(&mdsc->cap_dirty);
	INIT_LIST_HEAD(&mdsc->cap_dirty_migrating);
	mdsc->num_cap_flushing = 0;
	spin_lock_init(&mdsc->cap_dirty_lock);
	init_waitqueue_head(&mdsc->cap_flushing_wq);
	spin_lock_init(&mdsc->dentry_lru_lock);
	INIT_LIST_HEAD(&mdsc->dentry_lru);

	ceph_caps_init(mdsc);
	ceph_adjust_min_caps(mdsc, fsc->min_caps);

	return 0;
}

/*
 * Wait for safe replies on open mds requests.  If we time out, drop
 * all requests from the tree to avoid dangling dentry refs.
 */
static void wait_requests(struct ceph_mds_client *mdsc)
{
	struct ceph_mds_request *req;
	struct ceph_fs_client *fsc = mdsc->fsc;

	mutex_lock(&mdsc->mutex);
	if (__get_oldest_req(mdsc)) {
		mutex_unlock(&mdsc->mutex);

		dout("wait_requests waiting for requests\n");
		wait_for_completion_timeout(&mdsc->safe_umount_waiters,
				    fsc->client->options->mount_timeout * HZ);

		/* tear down remaining requests */
		mutex_lock(&mdsc->mutex);
		while ((req = __get_oldest_req(mdsc))) {
			dout("wait_requests timed out on tid %llu\n",
			     req->r_tid);
			__unregister_request(mdsc, req);
		}
	}
	mutex_unlock(&mdsc->mutex);
	dout("wait_requests done\n");
}

/*
 * called before mount is ro, and before dentries are torn down.
 * (hmm, does this still race with new lookups?)
 */
void ceph_mdsc_pre_umount(struct ceph_mds_client *mdsc)
{
	dout("pre_umount\n");
	mdsc->stopping = 1;

	drop_leases(mdsc);
	ceph_flush_dirty_caps(mdsc);
	wait_requests(mdsc);

	/*
	 * wait for reply handlers to drop their request refs and
	 * their inode/dcache refs
	 */
	ceph_msgr_flush();
}

/*
 * wait for all write mds requests to flush.
 */
static void wait_unsafe_requests(struct ceph_mds_client *mdsc, u64 want_tid)
{
	struct ceph_mds_request *req = NULL, *nextreq;
	struct rb_node *n;

	mutex_lock(&mdsc->mutex);
	dout("wait_unsafe_requests want %lld\n", want_tid);
restart:
	req = __get_oldest_req(mdsc);
	while (req && req->r_tid <= want_tid) {
		/* find next request */
		n = rb_next(&req->r_node);
		if (n)
			nextreq = rb_entry(n, struct ceph_mds_request, r_node);
		else
			nextreq = NULL;
		if ((req->r_op & CEPH_MDS_OP_WRITE)) {
			/* write op */
			ceph_mdsc_get_request(req);
			if (nextreq)
				ceph_mdsc_get_request(nextreq);
			mutex_unlock(&mdsc->mutex);
			dout("wait_unsafe_requests  wait on %llu (want %llu)\n",
			     req->r_tid, want_tid);
			wait_for_completion(&req->r_safe_completion);
			mutex_lock(&mdsc->mutex);
			ceph_mdsc_put_request(req);
			if (!nextreq)
				break;  /* next dne before, so we're done! */
			if (RB_EMPTY_NODE(&nextreq->r_node)) {
				/* next request was removed from tree */
				ceph_mdsc_put_request(nextreq);
				goto restart;
			}
			ceph_mdsc_put_request(nextreq);  /* won't go away */
		}
		req = nextreq;
	}
	mutex_unlock(&mdsc->mutex);
	dout("wait_unsafe_requests done\n");
}

void ceph_mdsc_sync(struct ceph_mds_client *mdsc)
{
	u64 want_tid, want_flush;

	if (mdsc->fsc->mount_state == CEPH_MOUNT_SHUTDOWN)
		return;

	dout("sync\n");
	mutex_lock(&mdsc->mutex);
	want_tid = mdsc->last_tid;
	want_flush = mdsc->cap_flush_seq;
	mutex_unlock(&mdsc->mutex);
	dout("sync want tid %lld flush_seq %lld\n", want_tid, want_flush);

	ceph_flush_dirty_caps(mdsc);

	wait_unsafe_requests(mdsc, want_tid);
	wait_event(mdsc->cap_flushing_wq, check_cap_flush(mdsc, want_flush));
}

/*
 * true if all sessions are closed, or we force unmount
 */
static bool done_closing_sessions(struct ceph_mds_client *mdsc)
{
	int i, n = 0;

	if (mdsc->fsc->mount_state == CEPH_MOUNT_SHUTDOWN)
		return true;

	mutex_lock(&mdsc->mutex);
	for (i = 0; i < mdsc->max_sessions; i++)
		if (mdsc->sessions[i])
			n++;
	mutex_unlock(&mdsc->mutex);
	return n == 0;
}

/*
 * called after sb is ro.
 */
void ceph_mdsc_close_sessions(struct ceph_mds_client *mdsc)
{
	struct ceph_mds_session *session;
	int i;
	struct ceph_fs_client *fsc = mdsc->fsc;
	unsigned long timeout = fsc->client->options->mount_timeout * HZ;

	dout("close_sessions\n");

	/* close sessions */
	mutex_lock(&mdsc->mutex);
	for (i = 0; i < mdsc->max_sessions; i++) {
		session = __ceph_lookup_mds_session(mdsc, i);
		if (!session)
			continue;
		mutex_unlock(&mdsc->mutex);
		mutex_lock(&session->s_mutex);
		__close_session(mdsc, session);
		mutex_unlock(&session->s_mutex);
		ceph_put_mds_session(session);
		mutex_lock(&mdsc->mutex);
	}
	mutex_unlock(&mdsc->mutex);

	dout("waiting for sessions to close\n");
	wait_event_timeout(mdsc->session_close_wq, done_closing_sessions(mdsc),
			   timeout);

	/* tear down remaining sessions */
	mutex_lock(&mdsc->mutex);
	for (i = 0; i < mdsc->max_sessions; i++) {
		if (mdsc->sessions[i]) {
			session = get_session(mdsc->sessions[i]);
			__unregister_session(mdsc, session);
			mutex_unlock(&mdsc->mutex);
			mutex_lock(&session->s_mutex);
			remove_session_caps(session);
			mutex_unlock(&session->s_mutex);
			ceph_put_mds_session(session);
			mutex_lock(&mdsc->mutex);
		}
	}
	WARN_ON(!list_empty(&mdsc->cap_delay_list));
	mutex_unlock(&mdsc->mutex);

	ceph_cleanup_empty_realms(mdsc);

	cancel_delayed_work_sync(&mdsc->delayed_work); /* cancel timer */

	dout("stopped\n");
}

static void ceph_mdsc_stop(struct ceph_mds_client *mdsc)
{
	dout("stop\n");
	cancel_delayed_work_sync(&mdsc->delayed_work); /* cancel timer */
	if (mdsc->mdsmap)
		ceph_mdsmap_destroy(mdsc->mdsmap);
	kfree(mdsc->sessions);
	ceph_caps_finalize(mdsc);
}

void ceph_mdsc_destroy(struct ceph_fs_client *fsc)
{
	struct ceph_mds_client *mdsc = fsc->mdsc;

	dout("mdsc_destroy %p\n", mdsc);
	ceph_mdsc_stop(mdsc);

	/* flush out any connection work with references to us */
	ceph_msgr_flush();

	fsc->mdsc = NULL;
	kfree(mdsc);
	dout("mdsc_destroy %p done\n", mdsc);
}


/*
 * handle mds map update.
 */
void ceph_mdsc_handle_map(struct ceph_mds_client *mdsc, struct ceph_msg *msg)
{
	u32 epoch;
	u32 maplen;
	void *p = msg->front.iov_base;
	void *end = p + msg->front.iov_len;
	struct ceph_mdsmap *newmap, *oldmap;
	struct ceph_fsid fsid;
	int err = -EINVAL;

	ceph_decode_need(&p, end, sizeof(fsid)+2*sizeof(u32), bad);
	ceph_decode_copy(&p, &fsid, sizeof(fsid));
	if (ceph_check_fsid(mdsc->fsc->client, &fsid) < 0)
		return;
	epoch = ceph_decode_32(&p);
	maplen = ceph_decode_32(&p);
	dout("handle_map epoch %u len %d\n", epoch, (int)maplen);

	/* do we need it? */
	ceph_monc_got_mdsmap(&mdsc->fsc->client->monc, epoch);
	mutex_lock(&mdsc->mutex);
	if (mdsc->mdsmap && epoch <= mdsc->mdsmap->m_epoch) {
		dout("handle_map epoch %u <= our %u\n",
		     epoch, mdsc->mdsmap->m_epoch);
		mutex_unlock(&mdsc->mutex);
		return;
	}

	newmap = ceph_mdsmap_decode(&p, end);
	if (IS_ERR(newmap)) {
		err = PTR_ERR(newmap);
		goto bad_unlock;
	}

	/* swap into place */
	if (mdsc->mdsmap) {
		oldmap = mdsc->mdsmap;
		mdsc->mdsmap = newmap;
		check_new_map(mdsc, newmap, oldmap);
		ceph_mdsmap_destroy(oldmap);
	} else {
		mdsc->mdsmap = newmap;  /* first mds map */
	}
	mdsc->fsc->sb->s_maxbytes = mdsc->mdsmap->m_max_file_size;

	__wake_requests(mdsc, &mdsc->waiting_for_map);

	mutex_unlock(&mdsc->mutex);
	schedule_delayed(mdsc);
	return;

bad_unlock:
	mutex_unlock(&mdsc->mutex);
bad:
	pr_err("error decoding mdsmap %d\n", err);
	return;
}

static struct ceph_connection *con_get(struct ceph_connection *con)
{
	struct ceph_mds_session *s = con->private;

	if (get_session(s)) {
		dout("mdsc con_get %p ok (%d)\n", s, atomic_read(&s->s_ref));
		return con;
	}
	dout("mdsc con_get %p FAIL\n", s);
	return NULL;
}

static void con_put(struct ceph_connection *con)
{
	struct ceph_mds_session *s = con->private;

	dout("mdsc con_put %p (%d)\n", s, atomic_read(&s->s_ref) - 1);
	ceph_put_mds_session(s);
}

/*
 * if the client is unresponsive for long enough, the mds will kill
 * the session entirely.
 */
static void peer_reset(struct ceph_connection *con)
{
	struct ceph_mds_session *s = con->private;
	struct ceph_mds_client *mdsc = s->s_mdsc;

	pr_warn("mds%d closed our session\n", s->s_mds);
	send_mds_reconnect(mdsc, s);
}

static void dispatch(struct ceph_connection *con, struct ceph_msg *msg)
{
	struct ceph_mds_session *s = con->private;
	struct ceph_mds_client *mdsc = s->s_mdsc;
	int type = le16_to_cpu(msg->hdr.type);

	mutex_lock(&mdsc->mutex);
	if (__verify_registered_session(mdsc, s) < 0) {
		mutex_unlock(&mdsc->mutex);
		goto out;
	}
	mutex_unlock(&mdsc->mutex);

	switch (type) {
	case CEPH_MSG_MDS_MAP:
		ceph_mdsc_handle_map(mdsc, msg);
		break;
	case CEPH_MSG_CLIENT_SESSION:
		handle_session(s, msg);
		break;
	case CEPH_MSG_CLIENT_REPLY:
		handle_reply(s, msg);
		break;
	case CEPH_MSG_CLIENT_REQUEST_FORWARD:
		handle_forward(mdsc, s, msg);
		break;
	case CEPH_MSG_CLIENT_CAPS:
		ceph_handle_caps(s, msg);
		break;
	case CEPH_MSG_CLIENT_SNAP:
		ceph_handle_snap(mdsc, s, msg);
		break;
	case CEPH_MSG_CLIENT_LEASE:
		handle_lease(mdsc, s, msg);
		break;

	default:
		pr_err("received unknown message type %d %s\n", type,
		       ceph_msg_type_name(type));
	}
out:
	ceph_msg_put(msg);
}

/*
 * authentication
 */

/*
 * Note: returned pointer is the address of a structure that's
 * managed separately.  Caller must *not* attempt to free it.
 */
static struct ceph_auth_handshake *get_authorizer(struct ceph_connection *con,
					int *proto, int force_new)
{
	struct ceph_mds_session *s = con->private;
	struct ceph_mds_client *mdsc = s->s_mdsc;
	struct ceph_auth_client *ac = mdsc->fsc->client->monc.auth;
	struct ceph_auth_handshake *auth = &s->s_auth;

	if (force_new && auth->authorizer) {
		ceph_auth_destroy_authorizer(ac, auth->authorizer);
		auth->authorizer = NULL;
	}
	if (!auth->authorizer) {
		int ret = ceph_auth_create_authorizer(ac, CEPH_ENTITY_TYPE_MDS,
						      auth);
		if (ret)
			return ERR_PTR(ret);
	} else {
		int ret = ceph_auth_update_authorizer(ac, CEPH_ENTITY_TYPE_MDS,
						      auth);
		if (ret)
			return ERR_PTR(ret);
	}
	*proto = ac->protocol;

	return auth;
}


static int verify_authorizer_reply(struct ceph_connection *con, int len)
{
	struct ceph_mds_session *s = con->private;
	struct ceph_mds_client *mdsc = s->s_mdsc;
	struct ceph_auth_client *ac = mdsc->fsc->client->monc.auth;

	return ceph_auth_verify_authorizer_reply(ac, s->s_auth.authorizer, len);
}

static int invalidate_authorizer(struct ceph_connection *con)
{
	struct ceph_mds_session *s = con->private;
	struct ceph_mds_client *mdsc = s->s_mdsc;
	struct ceph_auth_client *ac = mdsc->fsc->client->monc.auth;

	ceph_auth_invalidate_authorizer(ac, CEPH_ENTITY_TYPE_MDS);

	return ceph_monc_validate_auth(&mdsc->fsc->client->monc);
}

static struct ceph_msg *mds_alloc_msg(struct ceph_connection *con,
				struct ceph_msg_header *hdr, int *skip)
{
	struct ceph_msg *msg;
	int type = (int) le16_to_cpu(hdr->type);
	int front_len = (int) le32_to_cpu(hdr->front_len);

	if (con->in_msg)
		return con->in_msg;

	*skip = 0;
	msg = ceph_msg_new(type, front_len, GFP_NOFS, false);
	if (!msg) {
		pr_err("unable to allocate msg type %d len %d\n",
		       type, front_len);
		return NULL;
	}

	return msg;
}

static const struct ceph_connection_operations mds_con_ops = {
	.get = con_get,
	.put = con_put,
	.dispatch = dispatch,
	.get_authorizer = get_authorizer,
	.verify_authorizer_reply = verify_authorizer_reply,
	.invalidate_authorizer = invalidate_authorizer,
	.peer_reset = peer_reset,
	.alloc_msg = mds_alloc_msg,
};

/* eof */
/************************************************************/
/* ../linux-3.17/fs/ceph/mds_client.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

#include <linux/bug.h>
#include <linux/err.h>
// #include <linux/random.h>
// #include <linux/slab.h>
#include <linux/types.h>

#include <linux/ceph/mdsmap.h>
// #include <linux/ceph/messenger.h>
// #include <linux/ceph/decode.h>

// #include "super.h"


/*
 * choose a random mds that is "up" (i.e. has a state > 0), or -1.
 */
int ceph_mdsmap_get_random_mds(struct ceph_mdsmap *m)
{
	int n = 0;
	int i;

	/* special case for one mds */
	if (1 == m->m_max_mds && m->m_info[0].state > 0)
		return 0;

	/* count */
	for (i = 0; i < m->m_max_mds; i++)
		if (m->m_info[i].state > 0)
			n++;
	if (n == 0)
		return -1;

	/* pick */
	n = prandom_u32() % n;
	i = 0;
	for (i = 0; n > 0; i++, n--)
		while (m->m_info[i].state <= 0)
			i++;

	return i;
}

/*
 * Decode an MDS map
 *
 * Ignore any fields we don't care about (there are quite a few of
 * them).
 */
struct ceph_mdsmap *ceph_mdsmap_decode(void **p, void *end)
{
	struct ceph_mdsmap *m;
	const void *start = *p;
	int i, j, n;
	int err = -EINVAL;
	u16 version;

	m = kzalloc(sizeof(*m), GFP_NOFS);
	if (m == NULL)
		return ERR_PTR(-ENOMEM);

	ceph_decode_16_safe(p, end, version, bad);
	if (version > 3) {
		pr_warn("got mdsmap version %d > 3, failing", version);
		goto bad;
	}

	ceph_decode_need(p, end, 8*sizeof(u32) + sizeof(u64), bad);
	m->m_epoch = ceph_decode_32(p);
	m->m_client_epoch = ceph_decode_32(p);
	m->m_last_failure = ceph_decode_32(p);
	m->m_root = ceph_decode_32(p);
	m->m_session_timeout = ceph_decode_32(p);
	m->m_session_autoclose = ceph_decode_32(p);
	m->m_max_file_size = ceph_decode_64(p);
	m->m_max_mds = ceph_decode_32(p);

	m->m_info = kcalloc(m->m_max_mds, sizeof(*m->m_info), GFP_NOFS);
	if (m->m_info == NULL)
		goto badmem;

	/* pick out active nodes from mds_info (state > 0) */
	n = ceph_decode_32(p);
	for (i = 0; i < n; i++) {
		u64 global_id;
		u32 namelen;
		s32 mds, inc, state;
		u64 state_seq;
		u8 infoversion;
		struct ceph_entity_addr addr;
		u32 num_export_targets;
		void *pexport_targets = NULL;
		struct ceph_timespec laggy_since;
		struct ceph_mds_info *info;

		ceph_decode_need(p, end, sizeof(u64)*2 + 1 + sizeof(u32), bad);
		global_id = ceph_decode_64(p);
		infoversion = ceph_decode_8(p);
		*p += sizeof(u64);
		namelen = ceph_decode_32(p);  /* skip mds name */
		*p += namelen;

		ceph_decode_need(p, end,
				 4*sizeof(u32) + sizeof(u64) +
				 sizeof(addr) + sizeof(struct ceph_timespec),
				 bad);
		mds = ceph_decode_32(p);
		inc = ceph_decode_32(p);
		state = ceph_decode_32(p);
		state_seq = ceph_decode_64(p);
		ceph_decode_copy(p, &addr, sizeof(addr));
		ceph_decode_addr(&addr);
		ceph_decode_copy(p, &laggy_since, sizeof(laggy_since));
		*p += sizeof(u32);
		ceph_decode_32_safe(p, end, namelen, bad);
		*p += namelen;
		if (infoversion >= 2) {
			ceph_decode_32_safe(p, end, num_export_targets, bad);
			pexport_targets = *p;
			*p += num_export_targets * sizeof(u32);
		} else {
			num_export_targets = 0;
		}

		dout("mdsmap_decode %d/%d %lld mds%d.%d %s %s\n",
		     i+1, n, global_id, mds, inc,
		     ceph_pr_addr(&addr.in_addr),
		     ceph_mds_state_name(state));

		if (mds < 0 || mds >= m->m_max_mds || state <= 0)
			continue;

		info = &m->m_info[mds];
		info->global_id = global_id;
		info->state = state;
		info->addr = addr;
		info->laggy = (laggy_since.tv_sec != 0 ||
			       laggy_since.tv_nsec != 0);
		info->num_export_targets = num_export_targets;
		if (num_export_targets) {
			info->export_targets = kcalloc(num_export_targets,
						       sizeof(u32), GFP_NOFS);
			if (info->export_targets == NULL)
				goto badmem;
			for (j = 0; j < num_export_targets; j++)
				info->export_targets[j] =
				       ceph_decode_32(&pexport_targets);
		} else {
			info->export_targets = NULL;
		}
	}

	/* pg_pools */
	ceph_decode_32_safe(p, end, n, bad);
	m->m_num_data_pg_pools = n;
	m->m_data_pg_pools = kcalloc(n, sizeof(u64), GFP_NOFS);
	if (!m->m_data_pg_pools)
		goto badmem;
	ceph_decode_need(p, end, sizeof(u64)*(n+1), bad);
	for (i = 0; i < n; i++)
		m->m_data_pg_pools[i] = ceph_decode_64(p);
	m->m_cas_pg_pool = ceph_decode_64(p);

	/* ok, we don't care about the rest. */
	dout("mdsmap_decode success epoch %u\n", m->m_epoch);
	return m;

badmem:
	err = -ENOMEM;
bad:
	pr_err("corrupt mdsmap\n");
	print_hex_dump(KERN_DEBUG, "mdsmap: ",
		       DUMP_PREFIX_OFFSET, 16, 1,
		       start, end - start, true);
	ceph_mdsmap_destroy(m);
	return ERR_PTR(err);
}

void ceph_mdsmap_destroy(struct ceph_mdsmap *m)
{
	int i;

	for (i = 0; i < m->m_max_mds; i++)
		kfree(m->m_info[i].export_targets);
	kfree(m->m_info);
	kfree(m->m_data_pg_pools);
	kfree(m);
}
/************************************************************/
/* ../linux-3.17/fs/ceph/mdsmap.c */
/************************************************************/
/*
 * Ceph fs string constants
 */
// #include <linux/module.h>
#include <linux/ceph/types.h>


const char *ceph_mds_state_name(int s)
{
	switch (s) {
		/* down and out */
	case CEPH_MDS_STATE_DNE:        return "down:dne";
	case CEPH_MDS_STATE_STOPPED:    return "down:stopped";
		/* up and out */
	case CEPH_MDS_STATE_BOOT:       return "up:boot";
	case CEPH_MDS_STATE_STANDBY:    return "up:standby";
	case CEPH_MDS_STATE_STANDBY_REPLAY:    return "up:standby-replay";
	case CEPH_MDS_STATE_REPLAYONCE: return "up:oneshot-replay";
	case CEPH_MDS_STATE_CREATING:   return "up:creating";
	case CEPH_MDS_STATE_STARTING:   return "up:starting";
		/* up and in */
	case CEPH_MDS_STATE_REPLAY:     return "up:replay";
	case CEPH_MDS_STATE_RESOLVE:    return "up:resolve";
	case CEPH_MDS_STATE_RECONNECT:  return "up:reconnect";
	case CEPH_MDS_STATE_REJOIN:     return "up:rejoin";
	case CEPH_MDS_STATE_CLIENTREPLAY: return "up:clientreplay";
	case CEPH_MDS_STATE_ACTIVE:     return "up:active";
	case CEPH_MDS_STATE_STOPPING:   return "up:stopping";
	}
	return "???";
}

const char *ceph_session_op_name(int op)
{
	switch (op) {
	case CEPH_SESSION_REQUEST_OPEN: return "request_open";
	case CEPH_SESSION_OPEN: return "open";
	case CEPH_SESSION_REQUEST_CLOSE: return "request_close";
	case CEPH_SESSION_CLOSE: return "close";
	case CEPH_SESSION_REQUEST_RENEWCAPS: return "request_renewcaps";
	case CEPH_SESSION_RENEWCAPS: return "renewcaps";
	case CEPH_SESSION_STALE: return "stale";
	case CEPH_SESSION_RECALL_STATE: return "recall_state";
	case CEPH_SESSION_FLUSHMSG: return "flushmsg";
	case CEPH_SESSION_FLUSHMSG_ACK: return "flushmsg_ack";
	}
	return "???";
}

const char *ceph_mds_op_name(int op)
{
	switch (op) {
	case CEPH_MDS_OP_LOOKUP:  return "lookup";
	case CEPH_MDS_OP_LOOKUPHASH:  return "lookuphash";
	case CEPH_MDS_OP_LOOKUPPARENT:  return "lookupparent";
	case CEPH_MDS_OP_LOOKUPINO:  return "lookupino";
	case CEPH_MDS_OP_LOOKUPNAME:  return "lookupname";
	case CEPH_MDS_OP_GETATTR:  return "getattr";
	case CEPH_MDS_OP_SETXATTR: return "setxattr";
	case CEPH_MDS_OP_SETATTR: return "setattr";
	case CEPH_MDS_OP_RMXATTR: return "rmxattr";
	case CEPH_MDS_OP_SETLAYOUT: return "setlayou";
	case CEPH_MDS_OP_SETDIRLAYOUT: return "setdirlayout";
	case CEPH_MDS_OP_READDIR: return "readdir";
	case CEPH_MDS_OP_MKNOD: return "mknod";
	case CEPH_MDS_OP_LINK: return "link";
	case CEPH_MDS_OP_UNLINK: return "unlink";
	case CEPH_MDS_OP_RENAME: return "rename";
	case CEPH_MDS_OP_MKDIR: return "mkdir";
	case CEPH_MDS_OP_RMDIR: return "rmdir";
	case CEPH_MDS_OP_SYMLINK: return "symlink";
	case CEPH_MDS_OP_CREATE: return "create";
	case CEPH_MDS_OP_OPEN: return "open";
	case CEPH_MDS_OP_LOOKUPSNAP: return "lookupsnap";
	case CEPH_MDS_OP_LSSNAP: return "lssnap";
	case CEPH_MDS_OP_MKSNAP: return "mksnap";
	case CEPH_MDS_OP_RMSNAP: return "rmsnap";
	case CEPH_MDS_OP_SETFILELOCK: return "setfilelock";
	case CEPH_MDS_OP_GETFILELOCK: return "getfilelock";
	}
	return "???";
}

const char *ceph_cap_op_name(int op)
{
	switch (op) {
	case CEPH_CAP_OP_GRANT: return "grant";
	case CEPH_CAP_OP_REVOKE: return "revoke";
	case CEPH_CAP_OP_TRUNC: return "trunc";
	case CEPH_CAP_OP_EXPORT: return "export";
	case CEPH_CAP_OP_IMPORT: return "import";
	case CEPH_CAP_OP_UPDATE: return "update";
	case CEPH_CAP_OP_DROP: return "drop";
	case CEPH_CAP_OP_FLUSH: return "flush";
	case CEPH_CAP_OP_FLUSH_ACK: return "flush_ack";
	case CEPH_CAP_OP_FLUSHSNAP: return "flushsnap";
	case CEPH_CAP_OP_FLUSHSNAP_ACK: return "flushsnap_ack";
	case CEPH_CAP_OP_RELEASE: return "release";
	case CEPH_CAP_OP_RENEW: return "renew";
	}
	return "???";
}

const char *ceph_lease_op_name(int o)
{
	switch (o) {
	case CEPH_MDS_LEASE_REVOKE: return "revoke";
	case CEPH_MDS_LEASE_RELEASE: return "release";
	case CEPH_MDS_LEASE_RENEW: return "renew";
	case CEPH_MDS_LEASE_REVOKE_ACK: return "revoke_ack";
	}
	return "???";
}

const char *ceph_snap_op_name(int o)
{
	switch (o) {
	case CEPH_SNAP_OP_UPDATE: return "update";
	case CEPH_SNAP_OP_CREATE: return "create";
	case CEPH_SNAP_OP_DESTROY: return "destroy";
	case CEPH_SNAP_OP_SPLIT: return "split";
	}
	return "???";
}
/************************************************************/
/* ../linux-3.17/fs/ceph/strings.c */
/************************************************************/
/*
 * Ceph 'frag' type
 */
// #include <linux/module.h>
// #include <linux/ceph/types.h>

int ceph_frag_compare(__u32 a, __u32 b)
{
	unsigned va = ceph_frag_value(a);
	unsigned vb = ceph_frag_value(b);
	if (va < vb)
		return -1;
	if (va > vb)
		return 1;
	va = ceph_frag_bits(a);
	vb = ceph_frag_bits(b);
	if (va < vb)
		return -1;
	if (va > vb)
		return 1;
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/ceph/ceph_frag.c */
/************************************************************/
// #include <linux/ceph/ceph_debug.h>

#include <linux/device.h>
// #include <linux/slab.h>
// #include <linux/module.h>
// #include <linux/ctype.h>
// #include <linux/debugfs.h>
// #include <linux/seq_file.h>

#include <linux/ceph/libceph.h>
// #include <linux/ceph/mon_client.h>
// #include <linux/ceph/auth.h>
// #include <linux/ceph/debugfs.h>

// #include "super.h"

#ifdef CONFIG_DEBUG_FS

// #include "mds_client.h"

static int mdsmap_show(struct seq_file *s, void *p)
{
	int i;
	struct ceph_fs_client *fsc = s->private;

	if (fsc->mdsc == NULL || fsc->mdsc->mdsmap == NULL)
		return 0;
	seq_printf(s, "epoch %d\n", fsc->mdsc->mdsmap->m_epoch);
	seq_printf(s, "root %d\n", fsc->mdsc->mdsmap->m_root);
	seq_printf(s, "session_timeout %d\n",
		       fsc->mdsc->mdsmap->m_session_timeout);
	seq_printf(s, "session_autoclose %d\n",
		       fsc->mdsc->mdsmap->m_session_autoclose);
	for (i = 0; i < fsc->mdsc->mdsmap->m_max_mds; i++) {
		struct ceph_entity_addr *addr =
			&fsc->mdsc->mdsmap->m_info[i].addr;
		int state = fsc->mdsc->mdsmap->m_info[i].state;

		seq_printf(s, "\tmds%d\t%s\t(%s)\n", i,
			       ceph_pr_addr(&addr->in_addr),
			       ceph_mds_state_name(state));
	}
	return 0;
}

/*
 * mdsc debugfs
 */
static int mdsc_show(struct seq_file *s, void *p)
{
	struct ceph_fs_client *fsc = s->private;
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_mds_request *req;
	struct rb_node *rp;
	int pathlen;
	u64 pathbase;
	char *path;

	mutex_lock(&mdsc->mutex);
	for (rp = rb_first(&mdsc->request_tree); rp; rp = rb_next(rp)) {
		req = rb_entry(rp, struct ceph_mds_request, r_node);

		if (req->r_request && req->r_session)
			seq_printf(s, "%lld\tmds%d\t", req->r_tid,
				   req->r_session->s_mds);
		else if (!req->r_request)
			seq_printf(s, "%lld\t(no request)\t", req->r_tid);
		else
			seq_printf(s, "%lld\t(no session)\t", req->r_tid);

		seq_printf(s, "%s", ceph_mds_op_name(req->r_op));

		if (req->r_got_unsafe)
			seq_puts(s, "\t(unsafe)");
		else
			seq_puts(s, "\t");

		if (req->r_inode) {
			seq_printf(s, " #%llx", ceph_ino(req->r_inode));
		} else if (req->r_dentry) {
			path = ceph_mdsc_build_path(req->r_dentry, &pathlen,
						    &pathbase, 0);
			if (IS_ERR(path))
				path = NULL;
			spin_lock(&req->r_dentry->d_lock);
			seq_printf(s, " #%llx/%.*s (%s)",
				   ceph_ino(req->r_dentry->d_parent->d_inode),
				   req->r_dentry->d_name.len,
				   req->r_dentry->d_name.name,
				   path ? path : "");
			spin_unlock(&req->r_dentry->d_lock);
			kfree(path);
		} else if (req->r_path1) {
			seq_printf(s, " #%llx/%s", req->r_ino1.ino,
				   req->r_path1);
		} else {
			seq_printf(s, " #%llx", req->r_ino1.ino);
		}

		if (req->r_old_dentry) {
			path = ceph_mdsc_build_path(req->r_old_dentry, &pathlen,
						    &pathbase, 0);
			if (IS_ERR(path))
				path = NULL;
			spin_lock(&req->r_old_dentry->d_lock);
			seq_printf(s, " #%llx/%.*s (%s)",
				   req->r_old_dentry_dir ?
				   ceph_ino(req->r_old_dentry_dir) : 0,
				   req->r_old_dentry->d_name.len,
				   req->r_old_dentry->d_name.name,
				   path ? path : "");
			spin_unlock(&req->r_old_dentry->d_lock);
			kfree(path);
		} else if (req->r_path2) {
			if (req->r_ino2.ino)
				seq_printf(s, " #%llx/%s", req->r_ino2.ino,
					   req->r_path2);
			else
				seq_printf(s, " %s", req->r_path2);
		}

		seq_puts(s, "\n");
	}
	mutex_unlock(&mdsc->mutex);

	return 0;
}

static int caps_show(struct seq_file *s, void *p)
{
	struct ceph_fs_client *fsc = s->private;
	int total, avail, used, reserved, min;

	ceph_reservation_status(fsc, &total, &avail, &used, &reserved, &min);
	seq_printf(s, "total\t\t%d\n"
		   "avail\t\t%d\n"
		   "used\t\t%d\n"
		   "reserved\t%d\n"
		   "min\t%d\n",
		   total, avail, used, reserved, min);
	return 0;
}

static int dentry_lru_show(struct seq_file *s, void *ptr)
{
	struct ceph_fs_client *fsc = s->private;
	struct ceph_mds_client *mdsc = fsc->mdsc;
	struct ceph_dentry_info *di;

	spin_lock(&mdsc->dentry_lru_lock);
	list_for_each_entry(di, &mdsc->dentry_lru, lru) {
		struct dentry *dentry = di->dentry;
		seq_printf(s, "%p %p\t%.*s\n",
			   di, dentry, dentry->d_name.len, dentry->d_name.name);
	}
	spin_unlock(&mdsc->dentry_lru_lock);

	return 0;
}

CEPH_DEFINE_SHOW_FUNC(mdsmap_show)
CEPH_DEFINE_SHOW_FUNC(mdsc_show)
CEPH_DEFINE_SHOW_FUNC(caps_show)
CEPH_DEFINE_SHOW_FUNC(dentry_lru_show)


/*
 * debugfs
 */
static int congestion_kb_set(void *data, u64 val)
{
	struct ceph_fs_client *fsc = (struct ceph_fs_client *)data;

	fsc->mount_options->congestion_kb = (int)val;
	return 0;
}

static int congestion_kb_get(void *data, u64 *val)
{
	struct ceph_fs_client *fsc = (struct ceph_fs_client *)data;

	*val = (u64)fsc->mount_options->congestion_kb;
	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(congestion_kb_fops, congestion_kb_get,
			congestion_kb_set, "%llu\n");


void ceph_fs_debugfs_cleanup(struct ceph_fs_client *fsc)
{
	dout("ceph_fs_debugfs_cleanup\n");
	debugfs_remove(fsc->debugfs_bdi);
	debugfs_remove(fsc->debugfs_congestion_kb);
	debugfs_remove(fsc->debugfs_mdsmap);
	debugfs_remove(fsc->debugfs_caps);
	debugfs_remove(fsc->debugfs_mdsc);
	debugfs_remove(fsc->debugfs_dentry_lru);
}

int ceph_fs_debugfs_init(struct ceph_fs_client *fsc)
{
	char name[100];
	int err = -ENOMEM;

	dout("ceph_fs_debugfs_init\n");
	BUG_ON(!fsc->client->debugfs_dir);
	fsc->debugfs_congestion_kb =
		debugfs_create_file("writeback_congestion_kb",
				    0600,
				    fsc->client->debugfs_dir,
				    fsc,
				    &congestion_kb_fops);
	if (!fsc->debugfs_congestion_kb)
		goto out;

	snprintf(name, sizeof(name), "../../bdi/%s",
		 dev_name(fsc->backing_dev_info.dev));
	fsc->debugfs_bdi =
		debugfs_create_symlink("bdi",
				       fsc->client->debugfs_dir,
				       name);
	if (!fsc->debugfs_bdi)
		goto out;

	fsc->debugfs_mdsmap = debugfs_create_file("mdsmap",
					0600,
					fsc->client->debugfs_dir,
					fsc,
					&mdsmap_show_fops);
	if (!fsc->debugfs_mdsmap)
		goto out;

	fsc->debugfs_mdsc = debugfs_create_file("mdsc",
						0600,
						fsc->client->debugfs_dir,
						fsc,
						&mdsc_show_fops);
	if (!fsc->debugfs_mdsc)
		goto out;

	fsc->debugfs_caps = debugfs_create_file("caps",
						   0400,
						   fsc->client->debugfs_dir,
						   fsc,
						   &caps_show_fops);
	if (!fsc->debugfs_caps)
		goto out;

	fsc->debugfs_dentry_lru = debugfs_create_file("dentry_lru",
					0600,
					fsc->client->debugfs_dir,
					fsc,
					&dentry_lru_show_fops);
	if (!fsc->debugfs_dentry_lru)
		goto out;

	return 0;

out:
	ceph_fs_debugfs_cleanup(fsc);
	return err;
}


#else  /* CONFIG_DEBUG_FS */

int ceph_fs_debugfs_init(struct ceph_fs_client *fsc)
{
	return 0;
}

void ceph_fs_debugfs_cleanup(struct ceph_fs_client *fsc)
{
}

#endif  /* CONFIG_DEBUG_FS */
/************************************************************/
/* ../linux-3.17/fs/ceph/debugfs.c */
/************************************************************/
/*
 * Ceph cache definitions.
 *
 *  Copyright (C) 2013 by Adfin Solutions, Inc. All Rights Reserved.
 *  Written by Milosz Tanski (milosz@adfin.com)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to:
 *  Free Software Foundation
 *  51 Franklin Street, Fifth Floor
 *  Boston, MA  02111-1301  USA
 *
 */

// #include "super.h"
// #include "cache.h"

struct ceph_aux_inode {
	struct timespec	mtime;
	loff_t          size;
};

struct fscache_netfs ceph_cache_netfs = {
	.name		= "ceph",
	.version	= 0,
};

static uint16_t ceph_fscache_session_get_key(const void *cookie_netfs_data,
					     void *buffer, uint16_t maxbuf)
{
	const struct ceph_fs_client* fsc = cookie_netfs_data;
	uint16_t klen;

	klen = sizeof(fsc->client->fsid);
	if (klen > maxbuf)
		return 0;

	memcpy(buffer, &fsc->client->fsid, klen);
	return klen;
}

static const struct fscache_cookie_def ceph_fscache_fsid_object_def = {
	.name		= "CEPH.fsid",
	.type		= FSCACHE_COOKIE_TYPE_INDEX,
	.get_key	= ceph_fscache_session_get_key,
};

int ceph_fscache_register(void)
{
	return fscache_register_netfs(&ceph_cache_netfs);
}

void ceph_fscache_unregister(void)
{
	fscache_unregister_netfs(&ceph_cache_netfs);
}

int ceph_fscache_register_fs(struct ceph_fs_client* fsc)
{
	fsc->fscache = fscache_acquire_cookie(ceph_cache_netfs.primary_index,
					      &ceph_fscache_fsid_object_def,
					      fsc, true);

	if (fsc->fscache == NULL) {
		pr_err("Unable to resgister fsid: %p fscache cookie", fsc);
		return 0;
	}

	fsc->revalidate_wq = alloc_workqueue("ceph-revalidate", 0, 1);
	if (fsc->revalidate_wq == NULL)
		return -ENOMEM;

	return 0;
}

static uint16_t ceph_fscache_inode_get_key(const void *cookie_netfs_data,
					   void *buffer, uint16_t maxbuf)
{
	const struct ceph_inode_info* ci = cookie_netfs_data;
	uint16_t klen;

	/* use ceph virtual inode (id + snaphot) */
	klen = sizeof(ci->i_vino);
	if (klen > maxbuf)
		return 0;

	memcpy(buffer, &ci->i_vino, klen);
	return klen;
}

static uint16_t ceph_fscache_inode_get_aux(const void *cookie_netfs_data,
					   void *buffer, uint16_t bufmax)
{
	struct ceph_aux_inode aux;
	const struct ceph_inode_info* ci = cookie_netfs_data;
	const struct inode* inode = &ci->vfs_inode;

	memset(&aux, 0, sizeof(aux));
	aux.mtime = inode->i_mtime;
	aux.size = inode->i_size;

	memcpy(buffer, &aux, sizeof(aux));

	return sizeof(aux);
}

static void ceph_fscache_inode_get_attr(const void *cookie_netfs_data,
					uint64_t *size)
{
	const struct ceph_inode_info* ci = cookie_netfs_data;
	const struct inode* inode = &ci->vfs_inode;

	*size = inode->i_size;
}

static enum fscache_checkaux ceph_fscache_inode_check_aux(
	void *cookie_netfs_data, const void *data, uint16_t dlen)
{
	struct ceph_aux_inode aux;
	struct ceph_inode_info* ci = cookie_netfs_data;
	struct inode* inode = &ci->vfs_inode;

	if (dlen != sizeof(aux))
		return FSCACHE_CHECKAUX_OBSOLETE;

	memset(&aux, 0, sizeof(aux));
	aux.mtime = inode->i_mtime;
	aux.size = inode->i_size;

	if (memcmp(data, &aux, sizeof(aux)) != 0)
		return FSCACHE_CHECKAUX_OBSOLETE;

	dout("ceph inode 0x%p cached okay", ci);
	return FSCACHE_CHECKAUX_OKAY;
}

static void ceph_fscache_inode_now_uncached(void* cookie_netfs_data)
{
	struct ceph_inode_info* ci = cookie_netfs_data;
	struct pagevec pvec;
	pgoff_t first;
	int loop, nr_pages;

	pagevec_init(&pvec, 0);
	first = 0;

	dout("ceph inode 0x%p now uncached", ci);

	while (1) {
		nr_pages = pagevec_lookup(&pvec, ci->vfs_inode.i_mapping, first,
					  PAGEVEC_SIZE - pagevec_count(&pvec));

		if (!nr_pages)
			break;

		for (loop = 0; loop < nr_pages; loop++)
			ClearPageFsCache(pvec.pages[loop]);

		first = pvec.pages[nr_pages - 1]->index + 1;

		pvec.nr = nr_pages;
		pagevec_release(&pvec);
		cond_resched();
	}
}

static const struct fscache_cookie_def ceph_fscache_inode_object_def = {
	.name		= "CEPH.inode",
	.type		= FSCACHE_COOKIE_TYPE_DATAFILE,
	.get_key	= ceph_fscache_inode_get_key,
	.get_attr	= ceph_fscache_inode_get_attr,
	.get_aux	= ceph_fscache_inode_get_aux,
	.check_aux	= ceph_fscache_inode_check_aux,
	.now_uncached	= ceph_fscache_inode_now_uncached,
};

void ceph_fscache_register_inode_cookie(struct ceph_fs_client* fsc,
					struct ceph_inode_info* ci)
{
	struct inode* inode = &ci->vfs_inode;

	/* No caching for filesystem */
	if (fsc->fscache == NULL)
		return;

	/* Only cache for regular files that are read only */
	if ((ci->vfs_inode.i_mode & S_IFREG) == 0)
		return;

	/* Avoid multiple racing open requests */
	mutex_lock(&inode->i_mutex);

	if (ci->fscache)
		goto done;

	ci->fscache = fscache_acquire_cookie(fsc->fscache,
					     &ceph_fscache_inode_object_def,
					     ci, true);
	fscache_check_consistency(ci->fscache);
done:
	mutex_unlock(&inode->i_mutex);

}

void ceph_fscache_unregister_inode_cookie(struct ceph_inode_info* ci)
{
	struct fscache_cookie* cookie;

	if ((cookie = ci->fscache) == NULL)
		return;

	ci->fscache = NULL;

	fscache_uncache_all_inode_pages(cookie, &ci->vfs_inode);
	fscache_relinquish_cookie(cookie, 0);
}

static void ceph_vfs_readpage_complete(struct page *page, void *data, int error)
{
	if (!error)
		SetPageUptodate(page);
}

static void ceph_vfs_readpage_complete_unlock(struct page *page, void *data, int error)
{
	if (!error)
		SetPageUptodate(page);

	unlock_page(page);
}

static inline int cache_valid(struct ceph_inode_info *ci)
{
	return ((ceph_caps_issued(ci) & CEPH_CAP_FILE_CACHE) &&
		(ci->i_fscache_gen == ci->i_rdcache_gen));
}


/* Atempt to read from the fscache,
 *
 * This function is called from the readpage_nounlock context. DO NOT attempt to
 * unlock the page here (or in the callback).
 */
int ceph_readpage_from_fscache(struct inode *inode, struct page *page)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int ret;

	if (!cache_valid(ci))
		return -ENOBUFS;

	ret = fscache_read_or_alloc_page(ci->fscache, page,
					 ceph_vfs_readpage_complete, NULL,
					 GFP_KERNEL);

	switch (ret) {
		case 0: /* Page found */
			dout("page read submitted\n");
			return 0;
		case -ENOBUFS: /* Pages were not found, and can't be */
		case -ENODATA: /* Pages were not found */
			dout("page/inode not in cache\n");
			return ret;
		default:
			dout("%s: unknown error ret = %i\n", __func__, ret);
			return ret;
	}
}

int ceph_readpages_from_fscache(struct inode *inode,
				  struct address_space *mapping,
				  struct list_head *pages,
				  unsigned *nr_pages)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int ret;

	if (!cache_valid(ci))
		return -ENOBUFS;

	ret = fscache_read_or_alloc_pages(ci->fscache, mapping, pages, nr_pages,
					  ceph_vfs_readpage_complete_unlock,
					  NULL, mapping_gfp_mask(mapping));

	switch (ret) {
		case 0: /* All pages found */
			dout("all-page read submitted\n");
			return 0;
		case -ENOBUFS: /* Some pages were not found, and can't be */
		case -ENODATA: /* some pages were not found */
			dout("page/inode not in cache\n");
			return ret;
		default:
			dout("%s: unknown error ret = %i\n", __func__, ret);
			return ret;
	}
}

void ceph_readpage_to_fscache(struct inode *inode, struct page *page)
{
	struct ceph_inode_info *ci = ceph_inode(inode);
	int ret;

	if (!PageFsCache(page))
		return;

	if (!cache_valid(ci))
		return;

	ret = fscache_write_page(ci->fscache, page, GFP_KERNEL);
	if (ret)
		 fscache_uncache_page(ci->fscache, page);
}

void ceph_invalidate_fscache_page(struct inode* inode, struct page *page)
{
	struct ceph_inode_info *ci = ceph_inode(inode);

	if (!PageFsCache(page))
		return;

	fscache_wait_on_page_write(ci->fscache, page);
	fscache_uncache_page(ci->fscache, page);
}

void ceph_fscache_unregister_fs(struct ceph_fs_client* fsc)
{
	if (fsc->revalidate_wq)
		destroy_workqueue(fsc->revalidate_wq);

	fscache_relinquish_cookie(fsc->fscache, 0);
	fsc->fscache = NULL;
}

static void ceph_revalidate_work(struct work_struct *work)
{
	int issued;
	u32 orig_gen;
	struct ceph_inode_info *ci = container_of(work, struct ceph_inode_info,
						  i_revalidate_work);
	struct inode *inode = &ci->vfs_inode;

	spin_lock(&ci->i_ceph_lock);
	issued = __ceph_caps_issued(ci, NULL);
	orig_gen = ci->i_rdcache_gen;
	spin_unlock(&ci->i_ceph_lock);

	if (!(issued & CEPH_CAP_FILE_CACHE)) {
		dout("revalidate_work lost cache before validation %p\n",
		     inode);
		goto out;
	}

	if (!fscache_check_consistency(ci->fscache))
		fscache_invalidate(ci->fscache);

	spin_lock(&ci->i_ceph_lock);
	/* Update the new valid generation (backwards sanity check too) */
	if (orig_gen > ci->i_fscache_gen) {
		ci->i_fscache_gen = orig_gen;
	}
	spin_unlock(&ci->i_ceph_lock);

out:
	iput(&ci->vfs_inode);
}

void ceph_queue_revalidate(struct inode *inode)
{
	struct ceph_fs_client *fsc = ceph_sb_to_client(inode->i_sb);
	struct ceph_inode_info *ci = ceph_inode(inode);

	if (fsc->revalidate_wq == NULL || ci->fscache == NULL)
		return;

	ihold(inode);

	if (queue_work(ceph_sb_to_client(inode->i_sb)->revalidate_wq,
		       &ci->i_revalidate_work)) {
		dout("ceph_queue_revalidate %p\n", inode);
	} else {
		dout("ceph_queue_revalidate %p failed\n)", inode);
		iput(inode);
	}
}

void ceph_fscache_inode_init(struct ceph_inode_info *ci)
{
	ci->fscache = NULL;
	/* The first load is verifed cookie open time */
	ci->i_fscache_gen = 1;
	INIT_WORK(&ci->i_revalidate_work, ceph_revalidate_work);
}
/************************************************************/
/* ../linux-3.17/fs/ceph/cache.c */
/************************************************************/
