/*
 * Persistent Storage - ramfs parts.
 *
 * Copyright (C) 2010 Intel Corporation <tony.luck@intel.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/ramfs.h>
#include <linux/parser.h>
#include <linux/sched.h>
#include <linux/magic.h>
#include <linux/pstore.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

#include "internal.h"

#define	PSTORE_NAMELEN	64

static DEFINE_SPINLOCK(allpstore_lock);
static LIST_HEAD(allpstore);

struct pstore_private {
	struct list_head list;
	struct pstore_info *psi;
	enum pstore_type_id type;
	u64	id;
	int	count;
	ssize_t	size;
	char	data[];
};

struct pstore_ftrace_seq_data {
	const void *ptr;
	size_t off;
	size_t size;
};

#define REC_SIZE sizeof(struct pstore_ftrace_record)

static void *pstore_ftrace_seq_start(struct seq_file *s, loff_t *pos)
{
	struct pstore_private *ps = s->private;
	struct pstore_ftrace_seq_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	data->off = ps->size % REC_SIZE;
	data->off += *pos * REC_SIZE;
	if (data->off + REC_SIZE > ps->size) {
		kfree(data);
		return NULL;
	}

	return data;

}

static void pstore_ftrace_seq_stop(struct seq_file *s, void *v)
{
	kfree(v);
}

static void *pstore_ftrace_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct pstore_private *ps = s->private;
	struct pstore_ftrace_seq_data *data = v;

	data->off += REC_SIZE;
	if (data->off + REC_SIZE > ps->size)
		return NULL;

	(*pos)++;
	return data;
}

static int pstore_ftrace_seq_show(struct seq_file *s, void *v)
{
	struct pstore_private *ps = s->private;
	struct pstore_ftrace_seq_data *data = v;
	struct pstore_ftrace_record *rec = (void *)(ps->data + data->off);

	seq_printf(s, "%d %08lx  %08lx  %pf <- %pF\n",
		pstore_ftrace_decode_cpu(rec), rec->ip, rec->parent_ip,
		(void *)rec->ip, (void *)rec->parent_ip);

	return 0;
}

static const struct seq_operations pstore_ftrace_seq_ops = {
	.start	= pstore_ftrace_seq_start,
	.next	= pstore_ftrace_seq_next,
	.stop	= pstore_ftrace_seq_stop,
	.show	= pstore_ftrace_seq_show,
};

static ssize_t pstore_file_read(struct file *file, char __user *userbuf,
						size_t count, loff_t *ppos)
{
	struct seq_file *sf = file->private_data;
	struct pstore_private *ps = sf->private;

	if (ps->type == PSTORE_TYPE_FTRACE)
		return seq_read(file, userbuf, count, ppos);
	return simple_read_from_buffer(userbuf, count, ppos, ps->data, ps->size);
}

static int pstore_file_open(struct inode *inode, struct file *file)
{
	struct pstore_private *ps = inode->i_private;
	struct seq_file *sf;
	int err;
	const struct seq_operations *sops = NULL;

	if (ps->type == PSTORE_TYPE_FTRACE)
		sops = &pstore_ftrace_seq_ops;

	err = seq_open(file, sops);
	if (err < 0)
		return err;

	sf = file->private_data;
	sf->private = ps;

	return 0;
}

static loff_t pstore_file_llseek(struct file *file, loff_t off, int whence)
{
	struct seq_file *sf = file->private_data;

	if (sf->op)
		return seq_lseek(file, off, whence);
	return default_llseek(file, off, whence);
}

static const struct file_operations pstore_file_operations = {
	.open		= pstore_file_open,
	.read		= pstore_file_read,
	.llseek		= pstore_file_llseek,
	.release	= seq_release,
};

/*
 * When a file is unlinked from our file system we call the
 * platform driver to erase the record from persistent store.
 */
static int pstore_unlink(struct inode *dir, struct dentry *dentry)
{
	struct pstore_private *p = dentry->d_inode->i_private;

	if (p->psi->erase)
		p->psi->erase(p->type, p->id, p->count,
			      dentry->d_inode->i_ctime, p->psi);
	else
		return -EPERM;

	return simple_unlink(dir, dentry);
}

static void pstore_evict_inode(struct inode *inode)
{
	struct pstore_private	*p = inode->i_private;
	unsigned long		flags;

	clear_inode(inode);
	if (p) {
		spin_lock_irqsave(&allpstore_lock, flags);
		list_del(&p->list);
		spin_unlock_irqrestore(&allpstore_lock, flags);
		kfree(p);
	}
}

static const struct inode_operations pstore_dir_inode_operations = {
	.lookup		= simple_lookup,
	.unlink		= pstore_unlink,
};

static struct inode *pstore_get_inode(struct super_block *sb)
{
	struct inode *inode = new_inode(sb);
	if (inode) {
		inode->i_ino = get_next_ino();
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	}
	return inode;
}

enum {
	Opt_kmsg_bytes, Opt_err
};

static const match_table_t tokens = {
	{Opt_kmsg_bytes, "kmsg_bytes=%u"},
	{Opt_err, NULL}
};

static void parse_options(char *options)
{
	char		*p;
	substring_t	args[MAX_OPT_ARGS];
	int		option;

	if (!options)
		return;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_kmsg_bytes:
			if (!match_int(&args[0], &option))
				pstore_set_kmsg_bytes(option);
			break;
		}
	}
}

static int pstore_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	parse_options(data);

	return 0;
}

static const struct super_operations pstore_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= pstore_evict_inode,
	.remount_fs	= pstore_remount,
	.show_options	= generic_show_options,
};

static struct super_block *pstore_sb;

int pstore_is_mounted(void)
{
	return pstore_sb != NULL;
}

/*
 * Make a regular file in the root directory of our file system.
 * Load it up with "size" bytes of data from "buf".
 * Set the mtime & ctime to the date that this record was originally stored.
 */
int pstore_mkfile(enum pstore_type_id type, char *psname, u64 id, int count,
		  char *data, bool compressed, size_t size,
		  struct timespec time, struct pstore_info *psi)
{
	struct dentry		*root = pstore_sb->s_root;
	struct dentry		*dentry;
	struct inode		*inode;
	int			rc = 0;
	char			name[PSTORE_NAMELEN];
	struct pstore_private	*private, *pos;
	unsigned long		flags;

	spin_lock_irqsave(&allpstore_lock, flags);
	list_for_each_entry(pos, &allpstore, list) {
		if (pos->type == type &&
		    pos->id == id &&
		    pos->psi == psi) {
			rc = -EEXIST;
			break;
		}
	}
	spin_unlock_irqrestore(&allpstore_lock, flags);
	if (rc)
		return rc;

	rc = -ENOMEM;
	inode = pstore_get_inode(pstore_sb);
	if (!inode)
		goto fail;
	inode->i_mode = S_IFREG | 0444;
	inode->i_fop = &pstore_file_operations;
	private = kmalloc(sizeof *private + size, GFP_KERNEL);
	if (!private)
		goto fail_alloc;
	private->type = type;
	private->id = id;
	private->count = count;
	private->psi = psi;

	switch (type) {
	case PSTORE_TYPE_DMESG:
		sprintf(name, "dmesg-%s-%lld%s", psname, id,
						compressed ? ".enc.z" : "");
		break;
	case PSTORE_TYPE_CONSOLE:
		sprintf(name, "console-%s", psname);
		break;
	case PSTORE_TYPE_FTRACE:
		sprintf(name, "ftrace-%s", psname);
		break;
	case PSTORE_TYPE_MCE:
		sprintf(name, "mce-%s-%lld", psname, id);
		break;
	case PSTORE_TYPE_PPC_RTAS:
		sprintf(name, "rtas-%s-%lld", psname, id);
		break;
	case PSTORE_TYPE_PPC_OF:
		sprintf(name, "powerpc-ofw-%s-%lld", psname, id);
		break;
	case PSTORE_TYPE_PPC_COMMON:
		sprintf(name, "powerpc-common-%s-%lld", psname, id);
		break;
	case PSTORE_TYPE_UNKNOWN:
		sprintf(name, "unknown-%s-%lld", psname, id);
		break;
	default:
		sprintf(name, "type%d-%s-%lld", type, psname, id);
		break;
	}

	mutex_lock(&root->d_inode->i_mutex);

	dentry = d_alloc_name(root, name);
	if (!dentry)
		goto fail_lockedalloc;

	memcpy(private->data, data, size);
	inode->i_size = private->size = size;

	inode->i_private = private;

	if (time.tv_sec)
		inode->i_mtime = inode->i_ctime = time;

	d_add(dentry, inode);

	spin_lock_irqsave(&allpstore_lock, flags);
	list_add(&private->list, &allpstore);
	spin_unlock_irqrestore(&allpstore_lock, flags);

	mutex_unlock(&root->d_inode->i_mutex);

	return 0;

fail_lockedalloc:
	mutex_unlock(&root->d_inode->i_mutex);
	kfree(private);
fail_alloc:
	iput(inode);

fail:
	return rc;
}

static int pstore_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode;

	save_mount_options(sb, data);

	pstore_sb = sb;

	sb->s_maxbytes		= MAX_LFS_FILESIZE;
	sb->s_blocksize		= PAGE_CACHE_SIZE;
	sb->s_blocksize_bits	= PAGE_CACHE_SHIFT;
	sb->s_magic		= PSTOREFS_MAGIC;
	sb->s_op		= &pstore_ops;
	sb->s_time_gran		= 1;

	parse_options(data);

	inode = pstore_get_inode(sb);
	if (inode) {
		inode->i_mode = S_IFDIR | 0755;
		inode->i_op = &pstore_dir_inode_operations;
		inode->i_fop = &simple_dir_operations;
		inc_nlink(inode);
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root)
		return -ENOMEM;

	pstore_get_records(0);

	return 0;
}

static struct dentry *pstore_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, pstore_fill_super);
}

static void pstore_kill_sb(struct super_block *sb)
{
	kill_litter_super(sb);
	pstore_sb = NULL;
}

static struct file_system_type pstore_fs_type = {
	.name		= "pstore",
	.mount		= pstore_mount,
	.kill_sb	= pstore_kill_sb,
};

static struct kobject *pstore_kobj;

static int __init init_pstore_fs(void)
{
	int err = 0;

	/* Create a convenient mount point for people to access pstore */
	pstore_kobj = kobject_create_and_add("pstore", fs_kobj);
	if (!pstore_kobj) {
		err = -ENOMEM;
		goto out;
	}

	err = register_filesystem(&pstore_fs_type);
	if (err < 0)
		kobject_put(pstore_kobj);

out:
	return err;
}
module_init(init_pstore_fs)

MODULE_AUTHOR("Tony Luck <tony.luck@intel.com>");
MODULE_LICENSE("GPL");
/************************************************************/
/* ../linux-3.17/fs/pstore/inode.c */
/************************************************************/
/*
 * Persistent Storage - platform driver interface parts.
 *
 * Copyright (C) 2007-2008 Google, Inc.
 * Copyright (C) 2010 Intel Corporation <tony.luck@intel.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define pr_fmt(fmt) "pstore: " fmt

#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/errno.h>
// #include <linux/init.h>
#include <linux/kmsg_dump.h>
#include <linux/console.h>
// #include <linux/module.h>
// #include <linux/pstore.h>
#include <linux/zlib.h>
// #include <linux/string.h>
#include <linux/timer.h>
// #include <linux/slab.h>
// #include <linux/uaccess.h>
#include <linux/hardirq.h>
#include <linux/jiffies.h>
#include <linux/workqueue.h>

// #include "internal.h"

/*
 * We defer making "oops" entries appear in pstore - see
 * whether the system is actually still running well enough
 * to let someone see the entry
 */
static int pstore_update_ms = -1;
module_param_named(update_ms, pstore_update_ms, int, 0600);
MODULE_PARM_DESC(update_ms, "milliseconds before pstore updates its content "
		 "(default is -1, which means runtime updates are disabled; "
		 "enabling this option is not safe, it may lead to further "
		 "corruption on Oopses)");

static int pstore_new_entry;

static void pstore_timefunc(unsigned long);
static DEFINE_TIMER(pstore_timer, pstore_timefunc, 0, 0);

static void pstore_dowork(struct work_struct *);
static DECLARE_WORK(pstore_work, pstore_dowork);

/*
 * pstore_lock just protects "psinfo" during
 * calls to pstore_register()
 */
static DEFINE_SPINLOCK(pstore_lock);
struct pstore_info *psinfo;

static char *backend;

/* Compression parameters */
#define COMPR_LEVEL 6
#define WINDOW_BITS 12
#define MEM_LEVEL 4
static struct z_stream_s stream;

static char *big_oops_buf;
static size_t big_oops_buf_sz;

/* How much of the console log to snapshot */
static unsigned long kmsg_bytes = 10240;

void pstore_set_kmsg_bytes(int bytes)
{
	kmsg_bytes = bytes;
}

/* Tag each group of saved records with a sequence number */
static int	oopscount;

static const char *get_reason_str(enum kmsg_dump_reason reason)
{
	switch (reason) {
	case KMSG_DUMP_PANIC:
		return "Panic";
	case KMSG_DUMP_OOPS:
		return "Oops";
	case KMSG_DUMP_EMERG:
		return "Emergency";
	case KMSG_DUMP_RESTART:
		return "Restart";
	case KMSG_DUMP_HALT:
		return "Halt";
	case KMSG_DUMP_POWEROFF:
		return "Poweroff";
	default:
		return "Unknown";
	}
}

bool pstore_cannot_block_path(enum kmsg_dump_reason reason)
{
	/*
	 * In case of NMI path, pstore shouldn't be blocked
	 * regardless of reason.
	 */
	if (in_nmi())
		return true;

	switch (reason) {
	/* In panic case, other cpus are stopped by smp_send_stop(). */
	case KMSG_DUMP_PANIC:
	/* Emergency restart shouldn't be blocked by spin lock. */
	case KMSG_DUMP_EMERG:
		return true;
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(pstore_cannot_block_path);

/* Derived from logfs_compress() */
static int pstore_compress(const void *in, void *out, size_t inlen,
							size_t outlen)
{
	int err, ret;

	ret = -EIO;
	err = zlib_deflateInit2(&stream, COMPR_LEVEL, Z_DEFLATED, WINDOW_BITS,
						MEM_LEVEL, Z_DEFAULT_STRATEGY);
	if (err != Z_OK)
		goto error;

	stream.next_in = in;
	stream.avail_in = inlen;
	stream.total_in = 0;
	stream.next_out = out;
	stream.avail_out = outlen;
	stream.total_out = 0;

	err = zlib_deflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END)
		goto error;

	err = zlib_deflateEnd(&stream);
	if (err != Z_OK)
		goto error;

	if (stream.total_out >= stream.total_in)
		goto error;

	ret = stream.total_out;
error:
	return ret;
}

/* Derived from logfs_uncompress */
static int pstore_decompress(void *in, void *out, size_t inlen, size_t outlen)
{
	int err, ret;

	ret = -EIO;
	err = zlib_inflateInit2(&stream, WINDOW_BITS);
	if (err != Z_OK)
		goto error;

	stream.next_in = in;
	stream.avail_in = inlen;
	stream.total_in = 0;
	stream.next_out = out;
	stream.avail_out = outlen;
	stream.total_out = 0;

	err = zlib_inflate(&stream, Z_FINISH);
	if (err != Z_STREAM_END)
		goto error;

	err = zlib_inflateEnd(&stream);
	if (err != Z_OK)
		goto error;

	ret = stream.total_out;
error:
	return ret;
}

static void allocate_buf_for_compression(void)
{
	size_t size;
	size_t cmpr;

	switch (psinfo->bufsize) {
	/* buffer range for efivars */
	case 1000 ... 2000:
		cmpr = 56;
		break;
	case 2001 ... 3000:
		cmpr = 54;
		break;
	case 3001 ... 3999:
		cmpr = 52;
		break;
	/* buffer range for nvram, erst */
	case 4000 ... 10000:
		cmpr = 45;
		break;
	default:
		cmpr = 60;
		break;
	}

	big_oops_buf_sz = (psinfo->bufsize * 100) / cmpr;
	big_oops_buf = kmalloc(big_oops_buf_sz, GFP_KERNEL);
	if (big_oops_buf) {
		size = max(zlib_deflate_workspacesize(WINDOW_BITS, MEM_LEVEL),
			zlib_inflate_workspacesize());
		stream.workspace = kmalloc(size, GFP_KERNEL);
		if (!stream.workspace) {
			pr_err("No memory for compression workspace; skipping compression\n");
			kfree(big_oops_buf);
			big_oops_buf = NULL;
		}
	} else {
		pr_err("No memory for uncompressed data; skipping compression\n");
		stream.workspace = NULL;
	}

}

/*
 * Called when compression fails, since the printk buffer
 * would be fetched for compression calling it again when
 * compression fails would have moved the iterator of
 * printk buffer which results in fetching old contents.
 * Copy the recent messages from big_oops_buf to psinfo->buf
 */
static size_t copy_kmsg_to_buffer(int hsize, size_t len)
{
	size_t total_len;
	size_t diff;

	total_len = hsize + len;

	if (total_len > psinfo->bufsize) {
		diff = total_len - psinfo->bufsize + hsize;
		memcpy(psinfo->buf, big_oops_buf, hsize);
		memcpy(psinfo->buf + hsize, big_oops_buf + diff,
					psinfo->bufsize - hsize);
		total_len = psinfo->bufsize;
	} else
		memcpy(psinfo->buf, big_oops_buf, total_len);

	return total_len;
}

/*
 * callback from kmsg_dump. (s2,l2) has the most recently
 * written bytes, older bytes are in (s1,l1). Save as much
 * as we can from the end of the buffer.
 */
static void pstore_dump(struct kmsg_dumper *dumper,
			enum kmsg_dump_reason reason)
{
	unsigned long	total = 0;
	const char	*why;
	u64		id;
	unsigned int	part = 1;
	unsigned long	flags = 0;
	int		is_locked = 0;
	int		ret;

	why = get_reason_str(reason);

	if (pstore_cannot_block_path(reason)) {
		is_locked = spin_trylock_irqsave(&psinfo->buf_lock, flags);
		if (!is_locked) {
			pr_err("pstore dump routine blocked in %s path, may corrupt error record\n"
				       , in_nmi() ? "NMI" : why);
		}
	} else
		spin_lock_irqsave(&psinfo->buf_lock, flags);
	oopscount++;
	while (total < kmsg_bytes) {
		char *dst;
		unsigned long size;
		int hsize;
		int zipped_len = -1;
		size_t len;
		bool compressed;
		size_t total_len;

		if (big_oops_buf) {
			dst = big_oops_buf;
			hsize = sprintf(dst, "%s#%d Part%d\n", why,
							oopscount, part);
			size = big_oops_buf_sz - hsize;

			if (!kmsg_dump_get_buffer(dumper, true, dst + hsize,
								size, &len))
				break;

			zipped_len = pstore_compress(dst, psinfo->buf,
						hsize + len, psinfo->bufsize);

			if (zipped_len > 0) {
				compressed = true;
				total_len = zipped_len;
			} else {
				compressed = false;
				total_len = copy_kmsg_to_buffer(hsize, len);
			}
		} else {
			dst = psinfo->buf;
			hsize = sprintf(dst, "%s#%d Part%d\n", why, oopscount,
									part);
			size = psinfo->bufsize - hsize;
			dst += hsize;

			if (!kmsg_dump_get_buffer(dumper, true, dst,
								size, &len))
				break;

			compressed = false;
			total_len = hsize + len;
		}

		ret = psinfo->write(PSTORE_TYPE_DMESG, reason, &id, part,
				    oopscount, compressed, total_len, psinfo);
		if (ret == 0 && reason == KMSG_DUMP_OOPS && pstore_is_mounted())
			pstore_new_entry = 1;

		total += total_len;
		part++;
	}
	if (pstore_cannot_block_path(reason)) {
		if (is_locked)
			spin_unlock_irqrestore(&psinfo->buf_lock, flags);
	} else
		spin_unlock_irqrestore(&psinfo->buf_lock, flags);
}

static struct kmsg_dumper pstore_dumper = {
	.dump = pstore_dump,
};

#ifdef CONFIG_PSTORE_CONSOLE
static void pstore_console_write(struct console *con, const char *s, unsigned c)
{
	const char *e = s + c;

	while (s < e) {
		unsigned long flags;
		u64 id;

		if (c > psinfo->bufsize)
			c = psinfo->bufsize;

		if (oops_in_progress) {
			if (!spin_trylock_irqsave(&psinfo->buf_lock, flags))
				break;
		} else {
			spin_lock_irqsave(&psinfo->buf_lock, flags);
		}
		memcpy(psinfo->buf, s, c);
		psinfo->write(PSTORE_TYPE_CONSOLE, 0, &id, 0, 0, 0, c, psinfo);
		spin_unlock_irqrestore(&psinfo->buf_lock, flags);
		s += c;
		c = e - s;
	}
}

static struct console pstore_console = {
	.name	= "pstore",
	.write	= pstore_console_write,
	.flags	= CON_PRINTBUFFER | CON_ENABLED | CON_ANYTIME,
	.index	= -1,
};

static void pstore_register_console(void)
{
	register_console(&pstore_console);
}
#else
static void pstore_register_console(void) {}
#endif

static int pstore_write_compat(enum pstore_type_id type,
			       enum kmsg_dump_reason reason,
			       u64 *id, unsigned int part, int count,
			       bool compressed, size_t size,
			       struct pstore_info *psi)
{
	return psi->write_buf(type, reason, id, part, psinfo->buf, compressed,
			     size, psi);
}

/*
 * platform specific persistent storage driver registers with
 * us here. If pstore is already mounted, call the platform
 * read function right away to populate the file system. If not
 * then the pstore mount code will call us later to fill out
 * the file system.
 *
 * Register with kmsg_dump to save last part of console log on panic.
 */
int pstore_register(struct pstore_info *psi)
{
	struct module *owner = psi->owner;

	if (backend && strcmp(backend, psi->name))
		return -EPERM;

	spin_lock(&pstore_lock);
	if (psinfo) {
		spin_unlock(&pstore_lock);
		return -EBUSY;
	}

	if (!psi->write)
		psi->write = pstore_write_compat;
	psinfo = psi;
	mutex_init(&psinfo->read_mutex);
	spin_unlock(&pstore_lock);

	if (owner && !try_module_get(owner)) {
		psinfo = NULL;
		return -EINVAL;
	}

	allocate_buf_for_compression();

	if (pstore_is_mounted())
		pstore_get_records(0);

	kmsg_dump_register(&pstore_dumper);

	if ((psi->flags & PSTORE_FLAGS_FRAGILE) == 0) {
		pstore_register_console();
		pstore_register_ftrace();
	}

	if (pstore_update_ms >= 0) {
		pstore_timer.expires = jiffies +
			msecs_to_jiffies(pstore_update_ms);
		add_timer(&pstore_timer);
	}

	pr_info("Registered %s as persistent store backend\n", psi->name);

	return 0;
}
EXPORT_SYMBOL_GPL(pstore_register);

/*
 * Read all the records from the persistent store. Create
 * files in our filesystem.  Don't warn about -EEXIST errors
 * when we are re-scanning the backing store looking to add new
 * error records.
 */
void pstore_get_records(int quiet)
{
	struct pstore_info *psi = psinfo;
	char			*buf = NULL;
	ssize_t			size;
	u64			id;
	int			count;
	enum pstore_type_id	type;
	struct timespec		time;
	int			failed = 0, rc;
	bool			compressed;
	int			unzipped_len = -1;

	if (!psi)
		return;

	mutex_lock(&psi->read_mutex);
	if (psi->open && psi->open(psi))
		goto out;

	while ((size = psi->read(&id, &type, &count, &time, &buf, &compressed,
				psi)) > 0) {
		if (compressed && (type == PSTORE_TYPE_DMESG)) {
			if (big_oops_buf)
				unzipped_len = pstore_decompress(buf,
							big_oops_buf, size,
							big_oops_buf_sz);

			if (unzipped_len > 0) {
				kfree(buf);
				buf = big_oops_buf;
				size = unzipped_len;
				compressed = false;
			} else {
				pr_err("decompression failed;returned %d\n",
				       unzipped_len);
				compressed = true;
			}
		}
		rc = pstore_mkfile(type, psi->name, id, count, buf,
				  compressed, (size_t)size, time, psi);
		if (unzipped_len < 0) {
			/* Free buffer other than big oops */
			kfree(buf);
			buf = NULL;
		} else
			unzipped_len = -1;
		if (rc && (rc != -EEXIST || !quiet))
			failed++;
	}
	if (psi->close)
		psi->close(psi);
out:
	mutex_unlock(&psi->read_mutex);

	if (failed)
		pr_warn("failed to load %d record(s) from '%s'\n",
			failed, psi->name);
}

static void pstore_dowork(struct work_struct *work)
{
	pstore_get_records(1);
}

static void pstore_timefunc(unsigned long dummy)
{
	if (pstore_new_entry) {
		pstore_new_entry = 0;
		schedule_work(&pstore_work);
	}

	mod_timer(&pstore_timer, jiffies + msecs_to_jiffies(pstore_update_ms));
}

module_param(backend, charp, 0444);
MODULE_PARM_DESC(backend, "Pstore backend to use");
/************************************************************/
/* ../linux-3.17/fs/pstore/platform.c */
/************************************************************/
