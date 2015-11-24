/*
 *  dir.c
 *
 *  Copyright (C) 1995, 1996 by Volker Lendecke
 *  Modified for big endian by J.F. Chadima and David S. Miller
 *  Modified 1997 Peter Waltenberg, Bill Hawes, David Woodhouse for 2.1 dcache
 *  Modified 1998, 1999 Wolfram Pienkoss for NLS
 *  Modified 1999 Wolfram Pienkoss for directory caching
 *  Modified 2000 Ben Harris, University of Cambridge for NFS NS meta-info
 *
 */


#include <linux/time.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <asm/uaccess.h>
#include <asm/byteorder.h>
#include "../../inc/__fss.h"

#include "ncp_fs.h"
#include "../../inc/__fss.h"

static void ncp_read_volume_list(struct file *, struct dir_context *,
				struct ncp_cache_control *);
static void ncp_do_readdir(struct file *, struct dir_context *,
				struct ncp_cache_control *);

static int ncp_readdir(struct file *, struct dir_context *);

static int ncp_create(struct inode *, struct dentry *, umode_t, bool);
static struct dentry *ncp_lookup(struct inode *, struct dentry *, unsigned int);
static int ncp_unlink(struct inode *, struct dentry *);
static int ncp_mkdir(struct inode *, struct dentry *, umode_t);
static int ncp_rmdir(struct inode *, struct dentry *);
static int ncp_rename(struct inode *, struct dentry *,
	  	      struct inode *, struct dentry *);
static int ncp_mknod(struct inode * dir, struct dentry *dentry,
		     umode_t mode, dev_t rdev);
#if defined(CONFIG_NCPFS_EXTRAS) || defined(CONFIG_NCPFS_NFS_NS)
extern int ncp_symlink(struct inode *, struct dentry *, const char *);
#else
#define ncp_symlink NULL
#endif
		      
const struct file_operations ncp_dir_operations =
{
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= ncp_readdir,
	.unlocked_ioctl	= ncp_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ncp_compat_ioctl,
#endif
};

const struct inode_operations ncp_dir_inode_operations =
{
	.create		= ncp_create,
	.lookup		= ncp_lookup,
	.unlink		= ncp_unlink,
	.symlink	= ncp_symlink,
	.mkdir		= ncp_mkdir,
	.rmdir		= ncp_rmdir,
	.mknod		= ncp_mknod,
	.rename		= ncp_rename,
	.setattr	= ncp_notify_change,
};

/*
 * Dentry operations routines
 */
static int ncp_lookup_validate(struct dentry *, unsigned int);
static int ncp_hash_dentry(const struct dentry *, struct qstr *);
static int ncp_compare_dentry(const struct dentry *, const struct dentry *,
		unsigned int, const char *, const struct qstr *);
static int ncp_delete_dentry(const struct dentry *);
static void ncp_d_prune(struct dentry *dentry);

const struct dentry_operations ncp_dentry_operations =
{
	.d_revalidate	= ncp_lookup_validate,
	.d_hash		= ncp_hash_dentry,
	.d_compare	= ncp_compare_dentry,
	.d_delete	= ncp_delete_dentry,
	.d_prune	= ncp_d_prune,
};

#define ncp_namespace(i)	(NCP_SERVER(i)->name_space[NCP_FINFO(i)->volNumber])

static inline int ncp_preserve_entry_case(struct inode *i, __u32 nscreator)
{
#ifdef CONFIG_NCPFS_SMALLDOS
	int ns = ncp_namespace(i);

	if ((ns == NW_NS_DOS)
#ifdef CONFIG_NCPFS_OS2_NS
		|| ((ns == NW_NS_OS2) && (nscreator == NW_NS_DOS))
#endif /* CONFIG_NCPFS_OS2_NS */
	   )
		return 0;
#endif /* CONFIG_NCPFS_SMALLDOS */
	return 1;
}

#define ncp_preserve_case(i)	(ncp_namespace(i) != NW_NS_DOS)

static inline int ncp_case_sensitive(const struct inode *i)
{
#ifdef CONFIG_NCPFS_NFS_NS
	return ncp_namespace(i) == NW_NS_NFS;
#else
	return 0;
#endif /* CONFIG_NCPFS_NFS_NS */
}

/*
 * Note: leave the hash unchanged if the directory
 * is case-sensitive.
 *
 * Accessing the parent inode can be racy under RCU pathwalking.
 * Use ACCESS_ONCE() to make sure we use _one_ particular inode,
 * the callers will handle races.
 */
static int 
ncp_hash_dentry(const struct dentry *dentry, struct qstr *this)
{
	struct inode *inode = ACCESS_ONCE(dentry->d_inode);

	if (!inode)
		return 0;

	if (!ncp_case_sensitive(inode)) {
		struct super_block *sb = dentry->d_sb;
		struct nls_table *t;
		unsigned long hash;
		int i;

		t = NCP_IO_TABLE(sb);
		hash = init_name_hash();
		for (i=0; i<this->len ; i++)
			hash = partial_name_hash(ncp_tolower(t, this->name[i]),
									hash);
		this->hash = end_name_hash(hash);
	}
	return 0;
}

/*
 * Accessing the parent inode can be racy under RCU pathwalking.
 * Use ACCESS_ONCE() to make sure we use _one_ particular inode,
 * the callers will handle races.
 */
static int
ncp_compare_dentry(const struct dentry *parent, const struct dentry *dentry,
		unsigned int len, const char *str, const struct qstr *name)
{
	struct inode *pinode;

	if (len != name->len)
		return 1;

	pinode = ACCESS_ONCE(parent->d_inode);
	if (!pinode)
		return 1;

	if (ncp_case_sensitive(pinode))
		return strncmp(str, name->name, len);

	return ncp_strnicmp(NCP_IO_TABLE(pinode->i_sb), str, name->name, len);
}

/*
 * This is the callback from dput() when d_count is going to 0.
 * We use this to unhash dentries with bad inodes.
 * Closing files can be safely postponed until iput() - it's done there anyway.
 */
static int
ncp_delete_dentry(const struct dentry * dentry)
{
	struct inode *inode = dentry->d_inode;

	if (inode) {
		if (is_bad_inode(inode))
			return 1;
	} else
	{
	/* N.B. Unhash negative dentries? */
	}
	return 0;
}

static inline int
ncp_single_volume(struct ncp_server *server)
{
	return (server->m.mounted_vol[0] != '\0');
}

static inline int ncp_is_server_root(struct inode *inode)
{
	return !ncp_single_volume(NCP_SERVER(inode)) &&
		is_root_inode(inode);
}


/*
 * This is the callback when the dcache has a lookup hit.
 */


#ifdef CONFIG_NCPFS_STRONG
/* try to delete a readonly file (NW R bit set) */

static int
ncp_force_unlink(struct inode *dir, struct dentry* dentry)
{
        int res=0x9c,res2;
	struct nw_modify_dos_info info;
	__le32 old_nwattr;
	struct inode *inode;

	memset(&info, 0, sizeof(info));
	
        /* remove the Read-Only flag on the NW server */
	inode = dentry->d_inode;

	old_nwattr = NCP_FINFO(inode)->nwattr;
	info.attributes = old_nwattr & ~(aRONLY|aDELETEINHIBIT|aRENAMEINHIBIT);
	res2 = ncp_modify_file_or_subdir_dos_info_path(NCP_SERVER(inode), inode, NULL, DM_ATTRIBUTES, &info);
	if (res2)
		goto leave_me;

        /* now try again the delete operation */
        res = ncp_del_file_or_subdir2(NCP_SERVER(dir), dentry);

        if (res)  /* delete failed, set R bit again */
        {
		info.attributes = old_nwattr;
		res2 = ncp_modify_file_or_subdir_dos_info_path(NCP_SERVER(inode), inode, NULL, DM_ATTRIBUTES, &info);
		if (res2)
                        goto leave_me;
        }
leave_me:
        return(res);
}
#endif	/* CONFIG_NCPFS_STRONG */

#ifdef CONFIG_NCPFS_STRONG
static int
ncp_force_rename(struct inode *old_dir, struct dentry* old_dentry, char *_old_name,
                 struct inode *new_dir, struct dentry* new_dentry, char *_new_name)
{
	struct nw_modify_dos_info info;
        int res=0x90,res2;
	struct inode *old_inode = old_dentry->d_inode;
	__le32 old_nwattr = NCP_FINFO(old_inode)->nwattr;
	__le32 new_nwattr = 0; /* shut compiler warning */
	int old_nwattr_changed = 0;
	int new_nwattr_changed = 0;

	memset(&info, 0, sizeof(info));
	
        /* remove the Read-Only flag on the NW server */

	info.attributes = old_nwattr & ~(aRONLY|aRENAMEINHIBIT|aDELETEINHIBIT);
	res2 = ncp_modify_file_or_subdir_dos_info_path(NCP_SERVER(old_inode), old_inode, NULL, DM_ATTRIBUTES, &info);
	if (!res2)
		old_nwattr_changed = 1;
	if (new_dentry && new_dentry->d_inode) {
		new_nwattr = NCP_FINFO(new_dentry->d_inode)->nwattr;
		info.attributes = new_nwattr & ~(aRONLY|aRENAMEINHIBIT|aDELETEINHIBIT);
		res2 = ncp_modify_file_or_subdir_dos_info_path(NCP_SERVER(new_dir), new_dir, _new_name, DM_ATTRIBUTES, &info);
		if (!res2)
			new_nwattr_changed = 1;
	}
        /* now try again the rename operation */
	/* but only if something really happened */
	if (new_nwattr_changed || old_nwattr_changed) {
	        res = ncp_ren_or_mov_file_or_subdir(NCP_SERVER(old_dir),
        	                                    old_dir, _old_name,
                	                            new_dir, _new_name);
	} 
	if (res)
		goto leave_me;
	/* file was successfully renamed, so:
	   do not set attributes on old file - it no longer exists
	   copy attributes from old file to new */
	new_nwattr_changed = old_nwattr_changed;
	new_nwattr = old_nwattr;
	old_nwattr_changed = 0;
	
leave_me:;
	if (old_nwattr_changed) {
		info.attributes = old_nwattr;
		res2 = ncp_modify_file_or_subdir_dos_info_path(NCP_SERVER(old_inode), old_inode, NULL, DM_ATTRIBUTES, &info);
		/* ignore errors */
	}
	if (new_nwattr_changed)	{
		info.attributes = new_nwattr;
		res2 = ncp_modify_file_or_subdir_dos_info_path(NCP_SERVER(new_dir), new_dir, _new_name, DM_ATTRIBUTES, &info);
		/* ignore errors */
	}
        return(res);
}
#endif	/* CONFIG_NCPFS_STRONG */


static int
ncp_lookup_validate(struct dentry *dentry, unsigned int flags)
{
	struct ncp_server *server;
	struct dentry *parent;
	struct inode *dir;
	struct ncp_entry_info finfo;
	int res, val = 0, len;
	__u8 __name[NCP_MAXPATHLEN + 1];

	if (dentry == dentry->d_sb->s_root)
		return 1;

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	parent = dget_parent(dentry);
	dir = parent->d_inode;

	if (!dentry->d_inode)
		goto finished;

	server = NCP_SERVER(dir);

	/*
	 * Inspired by smbfs:
	 * The default validation is based on dentry age:
	 * We set the max age at mount time.  (But each
	 * successful server lookup renews the timestamp.)
	 */
	val = NCP_TEST_AGE(server, dentry);
	if (val)
		goto finished;

	ncp_dbg(2, "%pd2 not valid, age=%ld, server lookup\n",
		dentry, NCP_GET_AGE(dentry));

	len = sizeof(__name);
	if (ncp_is_server_root(dir)) {
		res = ncp_io2vol(server, __name, &len, dentry->d_name.name,
				 dentry->d_name.len, 1);
		if (!res) {
			res = ncp_lookup_volume(server, __name, &(finfo.i));
			if (!res)
				ncp_update_known_namespace(server, finfo.i.volNumber, NULL);
		}
	} else {
		res = ncp_io2vol(server, __name, &len, dentry->d_name.name,
				 dentry->d_name.len, !ncp_preserve_case(dir));
		if (!res)
			res = ncp_obtain_info(server, dir, __name, &(finfo.i));
	}
	finfo.volume = finfo.i.volNumber;
	ncp_dbg(2, "looked for %pd/%s, res=%d\n",
		dentry->d_parent, __name, res);
	/*
	 * If we didn't find it, or if it has a different dirEntNum to
	 * what we remember, it's not valid any more.
	 */
	if (!res) {
		struct inode *inode = dentry->d_inode;

		mutex_lock(&inode->i_mutex);
		if (finfo.i.dirEntNum == NCP_FINFO(inode)->dirEntNum) {
			ncp_new_dentry(dentry);
			val=1;
		} else
			ncp_dbg(2, "found, but dirEntNum changed\n");

		ncp_update_inode2(inode, &finfo);
		mutex_unlock(&inode->i_mutex);
	}

finished:
	ncp_dbg(2, "result=%d\n", val);
	dput(parent);
	return val;
}

static time_t ncp_obtain_mtime(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct ncp_server *server = NCP_SERVER(inode);
	struct nw_info_struct i;

	if (!ncp_conn_valid(server) || ncp_is_server_root(inode))
		return 0;

	if (ncp_obtain_info(server, inode, NULL, &i))
		return 0;

	return ncp_date_dos2unix(i.modifyTime, i.modifyDate);
}

static inline void
ncp_invalidate_dircache_entries(struct dentry *parent)
{
	struct ncp_server *server = NCP_SERVER(parent->d_inode);
	struct dentry *dentry;

	spin_lock(&parent->d_lock);
	list_for_each_entry(dentry, &parent->d_subdirs, d_child) {
		dentry->d_fsdata = NULL;
		ncp_age_dentry(server, dentry);
	}
	spin_unlock(&parent->d_lock);
}

static int ncp_readdir(struct file *file, struct dir_context *ctx)
{
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = dentry->d_inode;
	struct page *page = NULL;
	struct ncp_server *server = NCP_SERVER(inode);
	union  ncp_dir_cache *cache = NULL;
	struct ncp_cache_control ctl;
	int result, mtime_valid = 0;
	time_t mtime = 0;

	ctl.page  = NULL;
	ctl.cache = NULL;

	ncp_dbg(2, "reading %pD2, pos=%d\n", file, (int)ctx->pos);

	result = -EIO;
	/* Do not generate '.' and '..' when server is dead. */
	if (!ncp_conn_valid(server))
		goto out;

	result = 0;
	if (!dir_emit_dots(file, ctx))
		goto out;

	page = grab_cache_page(&inode->i_data, 0);
	if (!page)
		goto read_really;

	ctl.cache = cache = kmap(page);
	ctl.head  = cache->head;

	if (!PageUptodate(page) || !ctl.head.eof)
		goto init_cache;

	if (ctx->pos == 2) {
		if (jiffies - ctl.head.time >= NCP_MAX_AGE(server))
			goto init_cache;

		mtime = ncp_obtain_mtime(dentry);
		mtime_valid = 1;
		if ((!mtime) || (mtime != ctl.head.mtime))
			goto init_cache;
	}

	if (ctx->pos > ctl.head.end)
		goto finished;

	ctl.fpos = ctx->pos + (NCP_DIRCACHE_START - 2);
	ctl.ofs  = ctl.fpos / NCP_DIRCACHE_SIZE;
	ctl.idx  = ctl.fpos % NCP_DIRCACHE_SIZE;

	for (;;) {
		if (ctl.ofs != 0) {
			ctl.page = find_lock_page(&inode->i_data, ctl.ofs);
			if (!ctl.page)
				goto invalid_cache;
			ctl.cache = kmap(ctl.page);
			if (!PageUptodate(ctl.page))
				goto invalid_cache;
		}
		while (ctl.idx < NCP_DIRCACHE_SIZE) {
			struct dentry *dent;
			bool over;

			spin_lock(&dentry->d_lock);
			if (!(NCP_FINFO(inode)->flags & NCPI_DIR_CACHE)) { 
				spin_unlock(&dentry->d_lock);
				goto invalid_cache;
			}
			dent = ctl.cache->dentry[ctl.idx];
			if (unlikely(!lockref_get_not_dead(&dent->d_lockref))) {
				spin_unlock(&dentry->d_lock);
				goto invalid_cache;
			}
			spin_unlock(&dentry->d_lock);
			if (!dent->d_inode) {
				dput(dent);
				goto invalid_cache;
			}
			over = !dir_emit(ctx, dent->d_name.name,
					dent->d_name.len,
					dent->d_inode->i_ino, DT_UNKNOWN);
			dput(dent);
			if (over)
				goto finished;
			ctx->pos += 1;
			ctl.idx += 1;
			if (ctx->pos > ctl.head.end)
				goto finished;
		}
		if (ctl.page) {
			kunmap(ctl.page);
			SetPageUptodate(ctl.page);
			unlock_page(ctl.page);
			page_cache_release(ctl.page);
			ctl.page = NULL;
		}
		ctl.idx  = 0;
		ctl.ofs += 1;
	}
invalid_cache:
	if (ctl.page) {
		kunmap(ctl.page);
		unlock_page(ctl.page);
		page_cache_release(ctl.page);
		ctl.page = NULL;
	}
	ctl.cache = cache;
init_cache:
	ncp_invalidate_dircache_entries(dentry);
	if (!mtime_valid) {
		mtime = ncp_obtain_mtime(dentry);
		mtime_valid = 1;
	}
	ctl.head.mtime = mtime;
	ctl.head.time = jiffies;
	ctl.head.eof = 0;
	ctl.fpos = 2;
	ctl.ofs = 0;
	ctl.idx = NCP_DIRCACHE_START;
	ctl.filled = 0;
	ctl.valid  = 1;
read_really:
	spin_lock(&dentry->d_lock);
	NCP_FINFO(inode)->flags |= NCPI_DIR_CACHE;
	spin_unlock(&dentry->d_lock);
	if (ncp_is_server_root(inode)) {
		ncp_read_volume_list(file, ctx, &ctl);
	} else {
		ncp_do_readdir(file, ctx, &ctl);
	}
	ctl.head.end = ctl.fpos - 1;
	ctl.head.eof = ctl.valid;
finished:
	if (ctl.page) {
		kunmap(ctl.page);
		SetPageUptodate(ctl.page);
		unlock_page(ctl.page);
		page_cache_release(ctl.page);
	}
	if (page) {
		cache->head = ctl.head;
		kunmap(page);
		SetPageUptodate(page);
		unlock_page(page);
		page_cache_release(page);
	}
out:
	return result;
}

static void ncp_d_prune(struct dentry *dentry)
{
	if (!dentry->d_fsdata)	/* not referenced from page cache */
		return;
	NCP_FINFO(dentry->d_parent->d_inode)->flags &= ~NCPI_DIR_CACHE;
}

static int
ncp_fill_cache(struct file *file, struct dir_context *ctx,
		struct ncp_cache_control *ctrl, struct ncp_entry_info *entry,
		int inval_childs)
{
	struct dentry *newdent, *dentry = file->f_path.dentry;
	struct inode *dir = dentry->d_inode;
	struct ncp_cache_control ctl = *ctrl;
	struct qstr qname;
	int valid = 0;
	int hashed = 0;
	ino_t ino = 0;
	__u8 __name[NCP_MAXPATHLEN + 1];

	qname.len = sizeof(__name);
	if (ncp_vol2io(NCP_SERVER(dir), __name, &qname.len,
			entry->i.entryName, entry->i.nameLen,
			!ncp_preserve_entry_case(dir, entry->i.NSCreator)))
		return 1; /* I'm not sure */

	qname.name = __name;

	newdent = d_hash_and_lookup(dentry, &qname);
	if (unlikely(IS_ERR(newdent)))
		goto end_advance;
	if (!newdent) {
		newdent = d_alloc(dentry, &qname);
		if (!newdent)
			goto end_advance;
	} else {
		hashed = 1;

		/* If case sensitivity changed for this volume, all entries below this one
		   should be thrown away.  This entry itself is not affected, as its case
		   sensitivity is controlled by its own parent. */
		if (inval_childs)
			shrink_dcache_parent(newdent);

		/*
		 * NetWare's OS2 namespace is case preserving yet case
		 * insensitive.  So we update dentry's name as received from
		 * server. Parent dir's i_mutex is locked because we're in
		 * readdir.
		 */
		dentry_update_name_case(newdent, &qname);
	}

	if (!newdent->d_inode) {
		struct inode *inode;

		entry->opened = 0;
		entry->ino = iunique(dir->i_sb, 2);
		inode = ncp_iget(dir->i_sb, entry);
		if (inode) {
			d_instantiate(newdent, inode);
			if (!hashed)
				d_rehash(newdent);
		} else {
			spin_lock(&dentry->d_lock);
			NCP_FINFO(inode)->flags &= ~NCPI_DIR_CACHE;
			spin_unlock(&dentry->d_lock);
		}
	} else {
		struct inode *inode = newdent->d_inode;

		mutex_lock_nested(&inode->i_mutex, I_MUTEX_CHILD);
		ncp_update_inode2(inode, entry);
		mutex_unlock(&inode->i_mutex);
	}

	if (ctl.idx >= NCP_DIRCACHE_SIZE) {
		if (ctl.page) {
			kunmap(ctl.page);
			SetPageUptodate(ctl.page);
			unlock_page(ctl.page);
			page_cache_release(ctl.page);
		}
		ctl.cache = NULL;
		ctl.idx  -= NCP_DIRCACHE_SIZE;
		ctl.ofs  += 1;
		ctl.page  = grab_cache_page(&dir->i_data, ctl.ofs);
		if (ctl.page)
			ctl.cache = kmap(ctl.page);
	}
	if (ctl.cache) {
		if (newdent->d_inode) {
			newdent->d_fsdata = newdent;
			ctl.cache->dentry[ctl.idx] = newdent;
			ino = newdent->d_inode->i_ino;
			ncp_new_dentry(newdent);
		}
 		valid = 1;
	}
	dput(newdent);
end_advance:
	if (!valid)
		ctl.valid = 0;
	if (!ctl.filled && (ctl.fpos == ctx->pos)) {
		if (!ino)
			ino = iunique(dir->i_sb, 2);
		ctl.filled = !dir_emit(ctx, qname.name, qname.len,
				     ino, DT_UNKNOWN);
		if (!ctl.filled)
			ctx->pos += 1;
	}
	ctl.fpos += 1;
	ctl.idx  += 1;
	*ctrl = ctl;
	return (ctl.valid || !ctl.filled);
}

static void
ncp_read_volume_list(struct file *file, struct dir_context *ctx,
			struct ncp_cache_control *ctl)
{
	struct inode *inode = file_inode(file);
	struct ncp_server *server = NCP_SERVER(inode);
	struct ncp_volume_info info;
	struct ncp_entry_info entry;
	int i;

	ncp_dbg(1, "pos=%ld\n", (unsigned long)ctx->pos);

	for (i = 0; i < NCP_NUMBER_OF_VOLUMES; i++) {
		int inval_dentry;

		if (ncp_get_volume_info_with_number(server, i, &info) != 0)
			return;
		if (!strlen(info.volume_name))
			continue;

		ncp_dbg(1, "found vol: %s\n", info.volume_name);

		if (ncp_lookup_volume(server, info.volume_name,
					&entry.i)) {
			ncp_dbg(1, "could not lookup vol %s\n",
				info.volume_name);
			continue;
		}
		inval_dentry = ncp_update_known_namespace(server, entry.i.volNumber, NULL);
		entry.volume = entry.i.volNumber;
		if (!ncp_fill_cache(file, ctx, ctl, &entry, inval_dentry))
			return;
	}
}

static void
ncp_do_readdir(struct file *file, struct dir_context *ctx,
						struct ncp_cache_control *ctl)
{
	struct inode *dir = file_inode(file);
	struct ncp_server *server = NCP_SERVER(dir);
	struct nw_search_sequence seq;
	struct ncp_entry_info entry;
	int err;
	void* buf;
	int more;
	size_t bufsize;

	ncp_dbg(1, "%pD2, fpos=%ld\n", file, (unsigned long)ctx->pos);
	ncp_vdbg("init %pD, volnum=%d, dirent=%u\n",
		 file, NCP_FINFO(dir)->volNumber, NCP_FINFO(dir)->dirEntNum);

	err = ncp_initialize_search(server, dir, &seq);
	if (err) {
		ncp_dbg(1, "init failed, err=%d\n", err);
		return;
	}
	/* We MUST NOT use server->buffer_size handshaked with server if we are
	   using UDP, as for UDP server uses max. buffer size determined by
	   MTU, and for TCP server uses hardwired value 65KB (== 66560 bytes). 
	   So we use 128KB, just to be sure, as there is no way how to know
	   this value in advance. */
	bufsize = 131072;
	buf = vmalloc(bufsize);
	if (!buf)
		return;
	do {
		int cnt;
		char* rpl;
		size_t rpls;

		err = ncp_search_for_fileset(server, &seq, &more, &cnt, buf, bufsize, &rpl, &rpls);
		if (err)		/* Error */
			break;
		if (!cnt)		/* prevent endless loop */
			break;
		while (cnt--) {
			size_t onerpl;
			
			if (rpls < offsetof(struct nw_info_struct, entryName))
				break;	/* short packet */
			ncp_extract_file_info(rpl, &entry.i);
			onerpl = offsetof(struct nw_info_struct, entryName) + entry.i.nameLen;
			if (rpls < onerpl)
				break;	/* short packet */
			(void)ncp_obtain_nfs_info(server, &entry.i);
			rpl += onerpl;
			rpls -= onerpl;
			entry.volume = entry.i.volNumber;
			if (!ncp_fill_cache(file, ctx, ctl, &entry, 0))
				break;
		}
	} while (more);
	vfree(buf);
	return;
}

int ncp_conn_logged_in(struct super_block *sb)
{
	struct ncp_server* server = NCP_SBP(sb);
	int result;

	if (ncp_single_volume(server)) {
		int len;
		struct dentry* dent;
		__u32 volNumber;
		__le32 dirEntNum;
		__le32 DosDirNum;
		__u8 __name[NCP_MAXPATHLEN + 1];

		len = sizeof(__name);
		result = ncp_io2vol(server, __name, &len, server->m.mounted_vol,
				    strlen(server->m.mounted_vol), 1);
		if (result)
			goto out;
		result = -ENOENT;
		if (ncp_get_volume_root(server, __name, &volNumber, &dirEntNum, &DosDirNum)) {
			ncp_vdbg("%s not found\n", server->m.mounted_vol);
			goto out;
		}
		dent = sb->s_root;
		if (dent) {
			struct inode* ino = dent->d_inode;
			if (ino) {
				ncp_update_known_namespace(server, volNumber, NULL);
				NCP_FINFO(ino)->volNumber = volNumber;
				NCP_FINFO(ino)->dirEntNum = dirEntNum;
				NCP_FINFO(ino)->DosDirNum = DosDirNum;
				result = 0;
			} else {
				ncp_dbg(1, "sb->s_root->d_inode == NULL!\n");
			}
		} else {
			ncp_dbg(1, "sb->s_root == NULL!\n");
		}
	} else
		result = 0;

out:
	return result;
}

static struct dentry *ncp_lookup(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct ncp_server *server = NCP_SERVER(dir);
	struct inode *inode = NULL;
	struct ncp_entry_info finfo;
	int error, res, len;
	__u8 __name[NCP_MAXPATHLEN + 1];

	error = -EIO;
	if (!ncp_conn_valid(server))
		goto finished;

	ncp_vdbg("server lookup for %pd2\n", dentry);

	len = sizeof(__name);
	if (ncp_is_server_root(dir)) {
		res = ncp_io2vol(server, __name, &len, dentry->d_name.name,
				 dentry->d_name.len, 1);
		if (!res)
			res = ncp_lookup_volume(server, __name, &(finfo.i));
		if (!res)
			ncp_update_known_namespace(server, finfo.i.volNumber, NULL);
	} else {
		res = ncp_io2vol(server, __name, &len, dentry->d_name.name,
				 dentry->d_name.len, !ncp_preserve_case(dir));
		if (!res)
			res = ncp_obtain_info(server, dir, __name, &(finfo.i));
	}
	ncp_vdbg("looked for %pd2, res=%d\n", dentry, res);
	/*
	 * If we didn't find an entry, make a negative dentry.
	 */
	if (res)
		goto add_entry;

	/*
	 * Create an inode for the entry.
	 */
	finfo.opened = 0;
	finfo.ino = iunique(dir->i_sb, 2);
	finfo.volume = finfo.i.volNumber;
	error = -EACCES;
	inode = ncp_iget(dir->i_sb, &finfo);

	if (inode) {
		ncp_new_dentry(dentry);
add_entry:
		d_add(dentry, inode);
		error = 0;
	}

finished:
	ncp_vdbg("result=%d\n", error);
	return ERR_PTR(error);
}

/*
 * This code is common to create, mkdir, and mknod.
 */
static int ncp_instantiate(struct inode *dir, struct dentry *dentry,
			struct ncp_entry_info *finfo)
{
	struct inode *inode;
	int error = -EINVAL;

	finfo->ino = iunique(dir->i_sb, 2);
	inode = ncp_iget(dir->i_sb, finfo);
	if (!inode)
		goto out_close;
	d_instantiate(dentry,inode);
	error = 0;
out:
	return error;

out_close:
	ncp_vdbg("%pd2 failed, closing file\n", dentry);
	ncp_close_file(NCP_SERVER(dir), finfo->file_handle);
	goto out;
}

int ncp_create_new(struct inode *dir, struct dentry *dentry, umode_t mode,
		   dev_t rdev, __le32 attributes)
{
	struct ncp_server *server = NCP_SERVER(dir);
	struct ncp_entry_info finfo;
	int error, result, len;
	int opmode;
	__u8 __name[NCP_MAXPATHLEN + 1];
	
	ncp_vdbg("creating %pd2, mode=%hx\n", dentry, mode);

	ncp_age_dentry(server, dentry);
	len = sizeof(__name);
	error = ncp_io2vol(server, __name, &len, dentry->d_name.name,
			   dentry->d_name.len, !ncp_preserve_case(dir));
	if (error)
		goto out;

	error = -EACCES;
	
	if (S_ISREG(mode) && 
	    (server->m.flags & NCP_MOUNT_EXTRAS) && 
	    (mode & S_IXUGO))
		attributes |= aSYSTEM | aSHARED;
	
	result = ncp_open_create_file_or_subdir(server, dir, __name,
				OC_MODE_CREATE | OC_MODE_OPEN | OC_MODE_REPLACE,
				attributes, AR_READ | AR_WRITE, &finfo);
	opmode = O_RDWR;
	if (result) {
		result = ncp_open_create_file_or_subdir(server, dir, __name,
				OC_MODE_CREATE | OC_MODE_OPEN | OC_MODE_REPLACE,
				attributes, AR_WRITE, &finfo);
		if (result) {
			if (result == 0x87)
				error = -ENAMETOOLONG;
			else if (result < 0)
				error = result;
			ncp_dbg(1, "%pd2 failed\n", dentry);
			goto out;
		}
		opmode = O_WRONLY;
	}
	finfo.access = opmode;
	if (ncp_is_nfs_extras(server, finfo.volume)) {
		finfo.i.nfs.mode = mode;
		finfo.i.nfs.rdev = new_encode_dev(rdev);
		if (ncp_modify_nfs_info(server, finfo.volume,
					finfo.i.dirEntNum,
					mode, new_encode_dev(rdev)) != 0)
			goto out;
	}

	error = ncp_instantiate(dir, dentry, &finfo);
out:
	return error;
}

static int ncp_create(struct inode *dir, struct dentry *dentry, umode_t mode,
		bool excl)
{
	return ncp_create_new(dir, dentry, mode, 0, 0);
}

static int ncp_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct ncp_entry_info finfo;
	struct ncp_server *server = NCP_SERVER(dir);
	int error, len;
	__u8 __name[NCP_MAXPATHLEN + 1];

	ncp_dbg(1, "making %pd2\n", dentry);

	ncp_age_dentry(server, dentry);
	len = sizeof(__name);
	error = ncp_io2vol(server, __name, &len, dentry->d_name.name,
			   dentry->d_name.len, !ncp_preserve_case(dir));
	if (error)
		goto out;

	error = ncp_open_create_file_or_subdir(server, dir, __name,
					   OC_MODE_CREATE, aDIR,
					   cpu_to_le16(0xffff),
					   &finfo);
	if (error == 0) {
		if (ncp_is_nfs_extras(server, finfo.volume)) {
			mode |= S_IFDIR;
			finfo.i.nfs.mode = mode;
			if (ncp_modify_nfs_info(server,
						finfo.volume,
						finfo.i.dirEntNum,
						mode, 0) != 0)
				goto out;
		}
		error = ncp_instantiate(dir, dentry, &finfo);
	} else if (error > 0) {
		error = -EACCES;
	}
out:
	return error;
}

static int ncp_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct ncp_server *server = NCP_SERVER(dir);
	int error, result, len;
	__u8 __name[NCP_MAXPATHLEN + 1];

	ncp_dbg(1, "removing %pd2\n", dentry);

	len = sizeof(__name);
	error = ncp_io2vol(server, __name, &len, dentry->d_name.name,
			   dentry->d_name.len, !ncp_preserve_case(dir));
	if (error)
		goto out;

	result = ncp_del_file_or_subdir(server, dir, __name);
	switch (result) {
		case 0x00:
			error = 0;
			break;
		case 0x85:	/* unauthorized to delete file */
		case 0x8A:	/* unauthorized to delete file */
			error = -EACCES;
			break;
		case 0x8F:
		case 0x90:	/* read only */
			error = -EPERM;
			break;
		case 0x9F:	/* in use by another client */
			error = -EBUSY;
			break;
		case 0xA0:	/* directory not empty */
			error = -ENOTEMPTY;
			break;
		case 0xFF:	/* someone deleted file */
			error = -ENOENT;
			break;
		default:
			error = result < 0 ? result : -EACCES;
			break;
       	}
out:
	return error;
}

static int ncp_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct ncp_server *server;
	int error;

	server = NCP_SERVER(dir);
	ncp_dbg(1, "unlinking %pd2\n", dentry);
	
	/*
	 * Check whether to close the file ...
	 */
	if (inode) {
		ncp_vdbg("closing file\n");
		ncp_make_closed(inode);
	}

	error = ncp_del_file_or_subdir2(server, dentry);
#ifdef CONFIG_NCPFS_STRONG
	/* 9C is Invalid path.. It should be 8F, 90 - read only, but
	   it is not :-( */
	if ((error == 0x9C || error == 0x90) && server->m.flags & NCP_MOUNT_STRONG) { /* R/O */
		error = ncp_force_unlink(dir, dentry);
	}
#endif
	switch (error) {
		case 0x00:
			ncp_dbg(1, "removed %pd2\n", dentry);
			break;
		case 0x85:
		case 0x8A:
			error = -EACCES;
			break;
		case 0x8D:	/* some files in use */
		case 0x8E:	/* all files in use */
			error = -EBUSY;
			break;
		case 0x8F:	/* some read only */
		case 0x90:	/* all read only */
		case 0x9C:	/* !!! returned when in-use or read-only by NW4 */
			error = -EPERM;
			break;
		case 0xFF:
			error = -ENOENT;
			break;
		default:
			error = error < 0 ? error : -EACCES;
			break;
	}
	return error;
}

static int ncp_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	struct ncp_server *server = NCP_SERVER(old_dir);
	int error;
	int old_len, new_len;
	__u8 __old_name[NCP_MAXPATHLEN + 1], __new_name[NCP_MAXPATHLEN + 1];

	ncp_dbg(1, "%pd2 to %pd2\n", old_dentry, new_dentry);

	ncp_age_dentry(server, old_dentry);
	ncp_age_dentry(server, new_dentry);

	old_len = sizeof(__old_name);
	error = ncp_io2vol(server, __old_name, &old_len,
			   old_dentry->d_name.name, old_dentry->d_name.len,
			   !ncp_preserve_case(old_dir));
	if (error)
		goto out;

	new_len = sizeof(__new_name);
	error = ncp_io2vol(server, __new_name, &new_len,
			   new_dentry->d_name.name, new_dentry->d_name.len,
			   !ncp_preserve_case(new_dir));
	if (error)
		goto out;

	error = ncp_ren_or_mov_file_or_subdir(server, old_dir, __old_name,
						      new_dir, __new_name);
#ifdef CONFIG_NCPFS_STRONG
	if ((error == 0x90 || error == 0x8B || error == -EACCES) &&
			server->m.flags & NCP_MOUNT_STRONG) {	/* RO */
		error = ncp_force_rename(old_dir, old_dentry, __old_name,
					 new_dir, new_dentry, __new_name);
	}
#endif
	switch (error) {
		case 0x00:
			ncp_dbg(1, "renamed %pd -> %pd\n",
				old_dentry, new_dentry);
			break;
		case 0x9E:
			error = -ENAMETOOLONG;
			break;
		case 0xFF:
			error = -ENOENT;
			break;
		default:
			error = error < 0 ? error : -EACCES;
			break;
	}
out:
	return error;
}

static int ncp_mknod(struct inode * dir, struct dentry *dentry,
		     umode_t mode, dev_t rdev)
{
	if (!new_valid_dev(rdev))
		return -EINVAL;
	if (ncp_is_nfs_extras(NCP_SERVER(dir), NCP_FINFO(dir)->volNumber)) {
		ncp_dbg(1, "mode = 0%ho\n", mode);
		return ncp_create_new(dir, dentry, mode, rdev, 0);
	}
	return -EPERM; /* Strange, but true */
}

/* The following routines are taken directly from msdos-fs */

/* Linear day numbers of the respective 1sts in non-leap years. */

static int day_n[] =
{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0, 0};
/* Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec */

static int utc2local(int time)
{
	return time - sys_tz.tz_minuteswest * 60;
}

static int local2utc(int time)
{
	return time + sys_tz.tz_minuteswest * 60;
}

/* Convert a MS-DOS time/date pair to a UNIX date (seconds since 1 1 70). */
int
ncp_date_dos2unix(__le16 t, __le16 d)
{
	unsigned short time = le16_to_cpu(t), date = le16_to_cpu(d);
	int month, year, secs;

	/* first subtract and mask after that... Otherwise, if
	   date == 0, bad things happen */
	month = ((date >> 5) - 1) & 15;
	year = date >> 9;
	secs = (time & 31) * 2 + 60 * ((time >> 5) & 63) + (time >> 11) * 3600 +
		86400 * ((date & 31) - 1 + day_n[month] + (year / 4) + 
		year * 365 - ((year & 3) == 0 && month < 2 ? 1 : 0) + 3653);
	/* days since 1.1.70 plus 80's leap day */
	return local2utc(secs);
}


/* Convert linear UNIX date to a MS-DOS time/date pair. */
void
ncp_date_unix2dos(int unix_date, __le16 *time, __le16 *date)
{
	int day, year, nl_day, month;

	unix_date = utc2local(unix_date);
	*time = cpu_to_le16(
		(unix_date % 60) / 2 + (((unix_date / 60) % 60) << 5) +
		(((unix_date / 3600) % 24) << 11));
	day = unix_date / 86400 - 3652;
	year = day / 365;
	if ((year + 3) / 4 + 365 * year > day)
		year--;
	day -= (year + 3) / 4 + 365 * year;
	if (day == 59 && !(year & 3)) {
		nl_day = day;
		month = 2;
	} else {
		nl_day = (year & 3) || day <= 59 ? day : day - 1;
		for (month = 1; month < 12; month++)
			if (day_n[month] > nl_day)
				break;
	}
	*date = cpu_to_le16(nl_day - day_n[month - 1] + 1 + (month << 5) + (year << 9));
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/dir.c */
/************************************************************/
/*
 *  file.c
 *
 *  Copyright (C) 1995, 1996 by Volker Lendecke
 *  Modified 1997 Peter Waltenberg, Bill Hawes, David Woodhouse for 2.1 dcache
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <asm/uaccess.h>

// #include <linux/time.h>
// #include <linux/kernel.h>
// #include <linux/errno.h>
#include <linux/fcntl.h>
// #include <linux/stat.h>
// #include <linux/mm.h>
// #include <linux/vmalloc.h>
#include <linux/sched.h>
#include "../../inc/__fss.h"

// #include "ncp_fs.h"

static int ncp_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	return filemap_write_and_wait_range(file->f_mapping, start, end);
}

/*
 * Open a file with the specified read/write mode.
 */
int ncp_make_open(struct inode *inode, int right)
{
	int error;
	int access;

	error = -EINVAL;
	if (!inode) {
		pr_err("%s: got NULL inode\n", __func__);
		goto out;
	}

	ncp_dbg(1, "opened=%d, volume # %u, dir entry # %u\n",
		atomic_read(&NCP_FINFO(inode)->opened), 
		NCP_FINFO(inode)->volNumber, 
		NCP_FINFO(inode)->dirEntNum);
	error = -EACCES;
	mutex_lock(&NCP_FINFO(inode)->open_mutex);
	if (!atomic_read(&NCP_FINFO(inode)->opened)) {
		struct ncp_entry_info finfo;
		int result;

		/* tries max. rights */
		finfo.access = O_RDWR;
		result = ncp_open_create_file_or_subdir(NCP_SERVER(inode),
					inode, NULL, OC_MODE_OPEN,
					0, AR_READ | AR_WRITE, &finfo);
		if (!result)
			goto update;
		/* RDWR did not succeeded, try readonly or writeonly as requested */
		switch (right) {
			case O_RDONLY:
				finfo.access = O_RDONLY;
				result = ncp_open_create_file_or_subdir(NCP_SERVER(inode),
					inode, NULL, OC_MODE_OPEN,
					0, AR_READ, &finfo);
				break;
			case O_WRONLY:
				finfo.access = O_WRONLY;
				result = ncp_open_create_file_or_subdir(NCP_SERVER(inode),
					inode, NULL, OC_MODE_OPEN,
					0, AR_WRITE, &finfo);
				break;
		}
		if (result) {
			ncp_vdbg("failed, result=%d\n", result);
			goto out_unlock;
		}
		/*
		 * Update the inode information.
		 */
	update:
		ncp_update_inode(inode, &finfo);
		atomic_set(&NCP_FINFO(inode)->opened, 1);
	}

	access = NCP_FINFO(inode)->access;
	ncp_vdbg("file open, access=%x\n", access);
	if (access == right || access == O_RDWR) {
		atomic_inc(&NCP_FINFO(inode)->opened);
		error = 0;
	}

out_unlock:
	mutex_unlock(&NCP_FINFO(inode)->open_mutex);
out:
	return error;
}

static ssize_t
ncp_file_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	size_t already_read = 0;
	off_t pos;
	size_t bufsize;
	int error;
	void* freepage;
	size_t freelen;

	ncp_dbg(1, "enter %pD2\n", file);

	pos = *ppos;

	if ((ssize_t) count < 0) {
		return -EINVAL;
	}
	if (!count)
		return 0;
	if (pos > inode->i_sb->s_maxbytes)
		return 0;
	if (pos + count > inode->i_sb->s_maxbytes) {
		count = inode->i_sb->s_maxbytes - pos;
	}

	error = ncp_make_open(inode, O_RDONLY);
	if (error) {
		ncp_dbg(1, "open failed, error=%d\n", error);
		return error;
	}

	bufsize = NCP_SERVER(inode)->buffer_size;

	error = -EIO;
	freelen = ncp_read_bounce_size(bufsize);
	freepage = vmalloc(freelen);
	if (!freepage)
		goto outrel;
	error = 0;
	/* First read in as much as possible for each bufsize. */
	while (already_read < count) {
		int read_this_time;
		size_t to_read = min_t(unsigned int,
				     bufsize - (pos % bufsize),
				     count - already_read);

		error = ncp_read_bounce(NCP_SERVER(inode),
			 	NCP_FINFO(inode)->file_handle,
				pos, to_read, buf, &read_this_time, 
				freepage, freelen);
		if (error) {
			error = -EIO;	/* NW errno -> Linux errno */
			break;
		}
		pos += read_this_time;
		buf += read_this_time;
		already_read += read_this_time;

		if (read_this_time != to_read) {
			break;
		}
	}
	vfree(freepage);

	*ppos = pos;

	file_accessed(file);

	ncp_dbg(1, "exit %pD2\n", file);
outrel:
	ncp_inode_close(inode);		
	return already_read ? already_read : error;
}

static ssize_t
ncp_file_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	struct inode *inode = file_inode(file);
	size_t already_written = 0;
	off_t pos;
	size_t bufsize;
	int errno;
	void* bouncebuffer;

	ncp_dbg(1, "enter %pD2\n", file);
	if ((ssize_t) count < 0)
		return -EINVAL;
	pos = *ppos;
	if (file->f_flags & O_APPEND) {
		pos = i_size_read(inode);
	}

	if (pos + count > MAX_NON_LFS && !(file->f_flags&O_LARGEFILE)) {
		if (pos >= MAX_NON_LFS) {
			return -EFBIG;
		}
		if (count > MAX_NON_LFS - (u32)pos) {
			count = MAX_NON_LFS - (u32)pos;
		}
	}
	if (pos >= inode->i_sb->s_maxbytes) {
		if (count || pos > inode->i_sb->s_maxbytes) {
			return -EFBIG;
		}
	}
	if (pos + count > inode->i_sb->s_maxbytes) {
		count = inode->i_sb->s_maxbytes - pos;
	}
	
	if (!count)
		return 0;
	errno = ncp_make_open(inode, O_WRONLY);
	if (errno) {
		ncp_dbg(1, "open failed, error=%d\n", errno);
		return errno;
	}
	bufsize = NCP_SERVER(inode)->buffer_size;

	already_written = 0;

	errno = file_update_time(file);
	if (errno)
		goto outrel;

	bouncebuffer = vmalloc(bufsize);
	if (!bouncebuffer) {
		errno = -EIO;	/* -ENOMEM */
		goto outrel;
	}
	while (already_written < count) {
		int written_this_time;
		size_t to_write = min_t(unsigned int,
				      bufsize - (pos % bufsize),
				      count - already_written);

		if (copy_from_user(bouncebuffer, buf, to_write)) {
			errno = -EFAULT;
			break;
		}
		if (ncp_write_kernel(NCP_SERVER(inode), 
		    NCP_FINFO(inode)->file_handle,
		    pos, to_write, bouncebuffer, &written_this_time) != 0) {
			errno = -EIO;
			break;
		}
		pos += written_this_time;
		buf += written_this_time;
		already_written += written_this_time;

		if (written_this_time != to_write) {
			break;
		}
	}
	vfree(bouncebuffer);

	*ppos = pos;

	if (pos > i_size_read(inode)) {
		mutex_lock(&inode->i_mutex);
		if (pos > i_size_read(inode))
			i_size_write(inode, pos);
		mutex_unlock(&inode->i_mutex);
	}
	ncp_dbg(1, "exit %pD2\n", file);
outrel:
	ncp_inode_close(inode);		
	return already_written ? already_written : errno;
}

static int ncp_release(struct inode *inode, struct file *file) {
	if (ncp_make_closed(inode)) {
		ncp_dbg(1, "failed to close\n");
	}
	return 0;
}

const struct file_operations ncp_file_operations =
{
	.llseek		= generic_file_llseek,
	.read		= ncp_file_read,
	.write		= ncp_file_write,
	.unlocked_ioctl	= ncp_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ncp_compat_ioctl,
#endif
	.mmap		= ncp_mmap,
	.release	= ncp_release,
	.fsync		= ncp_fsync,
};

const struct inode_operations ncp_file_inode_operations =
{
	.setattr	= ncp_notify_change,
};
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/file.c */
/************************************************************/
/*
 *  inode.c
 *
 *  Copyright (C) 1995, 1996 by Volker Lendecke
 *  Modified for big endian by J.F. Chadima and David S. Miller
 *  Modified 1997 Peter Waltenberg, Bill Hawes, David Woodhouse for 2.1 dcache
 *  Modified 1998 Wolfram Pienkoss for NLS
 *  Modified 2000 Ben Harris, University of Cambridge for NFS NS meta-info
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include "../../inc/__fss.h"

// #include <asm/uaccess.h>
// #include <asm/byteorder.h>

// #include <linux/time.h>
// #include <linux/kernel.h>
// #include <linux/mm.h>
#include <linux/string.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
#include <linux/file.h>
// #include <linux/fcntl.h>
#include <linux/slab.h>
// #include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include <linux/seq_file.h>
// #include <linux/namei.h>
#include "../../inc/__fss.h"

#include <net/sock.h>
#include "../../inc/__fss.h"

// #include "ncp_fs.h"
#include "getopt.h"
#include "../../inc/__fss.h"

#define NCP_DEFAULT_FILE_MODE 0600
#define NCP_DEFAULT_DIR_MODE 0700
#define NCP_DEFAULT_TIME_OUT 10
#define NCP_DEFAULT_RETRY_COUNT 20

static void ncp_evict_inode(struct inode *);
static void ncp_put_super(struct super_block *);
static int  ncp_statfs(struct dentry *, struct kstatfs *);
static int  ncp_show_options(struct seq_file *, struct dentry *);

static struct kmem_cache * ncp_inode_cachep;

static struct inode *ncp_alloc_inode(struct super_block *sb)
{
	struct ncp_inode_info *ei;
	ei = (struct ncp_inode_info *)kmem_cache_alloc(ncp_inode_cachep, GFP_KERNEL);
	if (!ei)
		return NULL;
	return &ei->vfs_inode;
}

static void ncp_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(ncp_inode_cachep, NCP_FINFO(inode));
}

static void ncp_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, ncp_i_callback);
}

static void init_once(void *foo)
{
	struct ncp_inode_info *ei = (struct ncp_inode_info *) foo;

	mutex_init(&ei->open_mutex);
	inode_init_once(&ei->vfs_inode);
}

static int init_inodecache(void)
{
	ncp_inode_cachep = kmem_cache_create("ncp_inode_cache",
					     sizeof(struct ncp_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (ncp_inode_cachep == NULL)
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
	kmem_cache_destroy(ncp_inode_cachep);
}

static int ncp_remount(struct super_block *sb, int *flags, char* data)
{
	sync_filesystem(sb);
	*flags |= MS_NODIRATIME;
	return 0;
}

static const struct super_operations ncp_sops =
{
	.alloc_inode	= ncp_alloc_inode,
	.destroy_inode	= ncp_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.evict_inode	= ncp_evict_inode,
	.put_super	= ncp_put_super,
	.statfs		= ncp_statfs,
	.remount_fs	= ncp_remount,
	.show_options	= ncp_show_options,
};

/*
 * Fill in the ncpfs-specific information in the inode.
 */
static void ncp_update_dirent(struct inode *inode, struct ncp_entry_info *nwinfo)
{
	NCP_FINFO(inode)->DosDirNum = nwinfo->i.DosDirNum;
	NCP_FINFO(inode)->dirEntNum = nwinfo->i.dirEntNum;
	NCP_FINFO(inode)->volNumber = nwinfo->volume;
}

void ncp_update_inode(struct inode *inode, struct ncp_entry_info *nwinfo)
{
	ncp_update_dirent(inode, nwinfo);
	NCP_FINFO(inode)->nwattr = nwinfo->i.attributes;
	NCP_FINFO(inode)->access = nwinfo->access;
	memcpy(NCP_FINFO(inode)->file_handle, nwinfo->file_handle,
			sizeof(nwinfo->file_handle));
	ncp_dbg(1, "updated %s, volnum=%d, dirent=%u\n",
		nwinfo->i.entryName, NCP_FINFO(inode)->volNumber,
		NCP_FINFO(inode)->dirEntNum);
}

static void ncp_update_dates(struct inode *inode, struct nw_info_struct *nwi)
{
	/* NFS namespace mode overrides others if it's set. */
	ncp_dbg(1, "(%s) nfs.mode=0%o\n", nwi->entryName, nwi->nfs.mode);
	if (nwi->nfs.mode) {
		/* XXX Security? */
		inode->i_mode = nwi->nfs.mode;
	}

	inode->i_blocks = (i_size_read(inode) + NCP_BLOCK_SIZE - 1) >> NCP_BLOCK_SHIFT;

	inode->i_mtime.tv_sec = ncp_date_dos2unix(nwi->modifyTime, nwi->modifyDate);
	inode->i_ctime.tv_sec = ncp_date_dos2unix(nwi->creationTime, nwi->creationDate);
	inode->i_atime.tv_sec = ncp_date_dos2unix(0, nwi->lastAccessDate);
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
}

static void ncp_update_attrs(struct inode *inode, struct ncp_entry_info *nwinfo)
{
	struct nw_info_struct *nwi = &nwinfo->i;
	struct ncp_server *server = NCP_SERVER(inode);

	if (nwi->attributes & aDIR) {
		inode->i_mode = server->m.dir_mode;
		/* for directories dataStreamSize seems to be some
		   Object ID ??? */
		i_size_write(inode, NCP_BLOCK_SIZE);
	} else {
		u32 size;

		inode->i_mode = server->m.file_mode;
		size = le32_to_cpu(nwi->dataStreamSize);
		i_size_write(inode, size);
#ifdef CONFIG_NCPFS_EXTRAS
		if ((server->m.flags & (NCP_MOUNT_EXTRAS|NCP_MOUNT_SYMLINKS)) 
		 && (nwi->attributes & aSHARED)) {
			switch (nwi->attributes & (aHIDDEN|aSYSTEM)) {
				case aHIDDEN:
					if (server->m.flags & NCP_MOUNT_SYMLINKS) {
						if (/* (size >= NCP_MIN_SYMLINK_SIZE)
						 && */ (size <= NCP_MAX_SYMLINK_SIZE)) {
							inode->i_mode = (inode->i_mode & ~S_IFMT) | S_IFLNK;
							NCP_FINFO(inode)->flags |= NCPI_KLUDGE_SYMLINK;
							break;
						}
					}
					/* FALLTHROUGH */
				case 0:
					if (server->m.flags & NCP_MOUNT_EXTRAS)
						inode->i_mode |= S_IRUGO;
					break;
				case aSYSTEM:
					if (server->m.flags & NCP_MOUNT_EXTRAS)
						inode->i_mode |= (inode->i_mode >> 2) & S_IXUGO;
					break;
				/* case aSYSTEM|aHIDDEN: */
				default:
					/* reserved combination */
					break;
			}
		}
#endif
	}
	if (nwi->attributes & aRONLY) inode->i_mode &= ~S_IWUGO;
}

void ncp_update_inode2(struct inode* inode, struct ncp_entry_info *nwinfo)
{
	NCP_FINFO(inode)->flags = 0;
	if (!atomic_read(&NCP_FINFO(inode)->opened)) {
		NCP_FINFO(inode)->nwattr = nwinfo->i.attributes;
		ncp_update_attrs(inode, nwinfo);
	}

	ncp_update_dates(inode, &nwinfo->i);
	ncp_update_dirent(inode, nwinfo);
}

/*
 * Fill in the inode based on the ncp_entry_info structure.  Used only for brand new inodes.
 */
static void ncp_set_attr(struct inode *inode, struct ncp_entry_info *nwinfo)
{
	struct ncp_server *server = NCP_SERVER(inode);

	NCP_FINFO(inode)->flags = 0;
	
	ncp_update_attrs(inode, nwinfo);

	ncp_dbg(2, "inode->i_mode = %u\n", inode->i_mode);

	set_nlink(inode, 1);
	inode->i_uid = server->m.uid;
	inode->i_gid = server->m.gid;

	ncp_update_dates(inode, &nwinfo->i);
	ncp_update_inode(inode, nwinfo);
}

#if defined(CONFIG_NCPFS_EXTRAS) || defined(CONFIG_NCPFS_NFS_NS)
static const struct inode_operations ncp_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= page_follow_link_light,
	.put_link	= page_put_link,
	.setattr	= ncp_notify_change,
};
#endif

/*
 * Get a new inode.
 */
struct inode * 
ncp_iget(struct super_block *sb, struct ncp_entry_info *info)
{
	struct inode *inode;

	if (info == NULL) {
		pr_err("%s: info is NULL\n", __func__);
		return NULL;
	}

	inode = new_inode(sb);
	if (inode) {
		atomic_set(&NCP_FINFO(inode)->opened, info->opened);

		inode->i_ino = info->ino;
		ncp_set_attr(inode, info);
		if (S_ISREG(inode->i_mode)) {
			inode->i_op = &ncp_file_inode_operations;
			inode->i_fop = &ncp_file_operations;
		} else if (S_ISDIR(inode->i_mode)) {
			inode->i_op = &ncp_dir_inode_operations;
			inode->i_fop = &ncp_dir_operations;
#ifdef CONFIG_NCPFS_NFS_NS
		} else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) || S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
			init_special_inode(inode, inode->i_mode,
				new_decode_dev(info->i.nfs.rdev));
#endif
#if defined(CONFIG_NCPFS_EXTRAS) || defined(CONFIG_NCPFS_NFS_NS)
		} else if (S_ISLNK(inode->i_mode)) {
			inode->i_op = &ncp_symlink_inode_operations;
			inode->i_data.a_ops = &ncp_symlink_aops;
#endif
		} else {
			make_bad_inode(inode);
		}
		insert_inode_hash(inode);
	} else
		pr_err("%s: iget failed!\n", __func__);
	return inode;
}

static void
ncp_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);

	if (S_ISDIR(inode->i_mode)) {
		ncp_dbg(2, "put directory %ld\n", inode->i_ino);
	}

	if (ncp_make_closed(inode) != 0) {
		/* We can't do anything but complain. */
		pr_err("%s: could not close\n", __func__);
	}
}

static void ncp_stop_tasks(struct ncp_server *server) {
	struct sock* sk = server->ncp_sock->sk;

	lock_sock(sk);
	sk->sk_error_report = server->error_report;
	sk->sk_data_ready   = server->data_ready;
	sk->sk_write_space  = server->write_space;
	release_sock(sk);
	del_timer_sync(&server->timeout_tm);

	flush_work(&server->rcv.tq);
	if (sk->sk_socket->type == SOCK_STREAM)
		flush_work(&server->tx.tq);
	else
		flush_work(&server->timeout_tq);
}

static int  ncp_show_options(struct seq_file *seq, struct dentry *root)
{
	struct ncp_server *server = NCP_SBP(root->d_sb);
	unsigned int tmp;

	if (!uid_eq(server->m.uid, GLOBAL_ROOT_UID))
		seq_printf(seq, ",uid=%u",
			   from_kuid_munged(&init_user_ns, server->m.uid));
	if (!gid_eq(server->m.gid, GLOBAL_ROOT_GID))
		seq_printf(seq, ",gid=%u",
			   from_kgid_munged(&init_user_ns, server->m.gid));
	if (!uid_eq(server->m.mounted_uid, GLOBAL_ROOT_UID))
		seq_printf(seq, ",owner=%u",
			   from_kuid_munged(&init_user_ns, server->m.mounted_uid));
	tmp = server->m.file_mode & S_IALLUGO;
	if (tmp != NCP_DEFAULT_FILE_MODE)
		seq_printf(seq, ",mode=0%o", tmp);
	tmp = server->m.dir_mode & S_IALLUGO;
	if (tmp != NCP_DEFAULT_DIR_MODE)
		seq_printf(seq, ",dirmode=0%o", tmp);
	if (server->m.time_out != NCP_DEFAULT_TIME_OUT * HZ / 100) {
		tmp = server->m.time_out * 100 / HZ;
		seq_printf(seq, ",timeout=%u", tmp);
	}
	if (server->m.retry_count != NCP_DEFAULT_RETRY_COUNT)
		seq_printf(seq, ",retry=%u", server->m.retry_count);
	if (server->m.flags != 0)
		seq_printf(seq, ",flags=%lu", server->m.flags);
	if (server->m.wdog_pid != NULL)
		seq_printf(seq, ",wdogpid=%u", pid_vnr(server->m.wdog_pid));

	return 0;
}

static const struct ncp_option ncp_opts[] = {
	{ "uid",	OPT_INT,	'u' },
	{ "gid",	OPT_INT,	'g' },
	{ "owner",	OPT_INT,	'o' },
	{ "mode",	OPT_INT,	'm' },
	{ "dirmode",	OPT_INT,	'd' },
	{ "timeout",	OPT_INT,	't' },
	{ "retry",	OPT_INT,	'r' },
	{ "flags",	OPT_INT,	'f' },
	{ "wdogpid",	OPT_INT,	'w' },
	{ "ncpfd",	OPT_INT,	'n' },
	{ "infofd",	OPT_INT,	'i' },	/* v5 */
	{ "version",	OPT_INT,	'v' },
	{ NULL,		0,		0 } };

static int ncp_parse_options(struct ncp_mount_data_kernel *data, char *options) {
	int optval;
	char *optarg;
	unsigned long optint;
	int version = 0;
	int ret;

	data->flags = 0;
	data->int_flags = 0;
	data->mounted_uid = GLOBAL_ROOT_UID;
	data->wdog_pid = NULL;
	data->ncp_fd = ~0;
	data->time_out = NCP_DEFAULT_TIME_OUT;
	data->retry_count = NCP_DEFAULT_RETRY_COUNT;
	data->uid = GLOBAL_ROOT_UID;
	data->gid = GLOBAL_ROOT_GID;
	data->file_mode = NCP_DEFAULT_FILE_MODE;
	data->dir_mode = NCP_DEFAULT_DIR_MODE;
	data->info_fd = -1;
	data->mounted_vol[0] = 0;
	
	while ((optval = ncp_getopt("ncpfs", &options, ncp_opts, NULL, &optarg, &optint)) != 0) {
		ret = optval;
		if (ret < 0)
			goto err;
		switch (optval) {
			case 'u':
				data->uid = make_kuid(current_user_ns(), optint);
				if (!uid_valid(data->uid)) {
					ret = -EINVAL;
					goto err;
				}
				break;
			case 'g':
				data->gid = make_kgid(current_user_ns(), optint);
				if (!gid_valid(data->gid)) {
					ret = -EINVAL;
					goto err;
				}
				break;
			case 'o':
				data->mounted_uid = make_kuid(current_user_ns(), optint);
				if (!uid_valid(data->mounted_uid)) {
					ret = -EINVAL;
					goto err;
				}
				break;
			case 'm':
				data->file_mode = optint;
				break;
			case 'd':
				data->dir_mode = optint;
				break;
			case 't':
				data->time_out = optint;
				break;
			case 'r':
				data->retry_count = optint;
				break;
			case 'f':
				data->flags = optint;
				break;
			case 'w':
				data->wdog_pid = find_get_pid(optint);
				break;
			case 'n':
				data->ncp_fd = optint;
				break;
			case 'i':
				data->info_fd = optint;
				break;
			case 'v':
				ret = -ECHRNG;
				if (optint < NCP_MOUNT_VERSION_V4)
					goto err;
				if (optint > NCP_MOUNT_VERSION_V5)
					goto err;
				version = optint;
				break;
			
		}
	}
	return 0;
err:
	put_pid(data->wdog_pid);
	data->wdog_pid = NULL;
	return ret;
}

static int ncp_fill_super(struct super_block *sb, void *raw_data, int silent)
{
	struct ncp_mount_data_kernel data;
	struct ncp_server *server;
	struct inode *root_inode;
	struct socket *sock;
	int error;
	int default_bufsize;
#ifdef CONFIG_NCPFS_PACKET_SIGNING
	int options;
#endif
	struct ncp_entry_info finfo;

	memset(&data, 0, sizeof(data));
	server = kzalloc(sizeof(struct ncp_server), GFP_KERNEL);
	if (!server)
		return -ENOMEM;
	sb->s_fs_info = server;

	error = -EFAULT;
	if (raw_data == NULL)
		goto out;
	switch (*(int*)raw_data) {
		case NCP_MOUNT_VERSION:
			{
				struct ncp_mount_data* md = (struct ncp_mount_data*)raw_data;

				data.flags = md->flags;
				data.int_flags = NCP_IMOUNT_LOGGEDIN_POSSIBLE;
				data.mounted_uid = make_kuid(current_user_ns(), md->mounted_uid);
				data.wdog_pid = find_get_pid(md->wdog_pid);
				data.ncp_fd = md->ncp_fd;
				data.time_out = md->time_out;
				data.retry_count = md->retry_count;
				data.uid = make_kuid(current_user_ns(), md->uid);
				data.gid = make_kgid(current_user_ns(), md->gid);
				data.file_mode = md->file_mode;
				data.dir_mode = md->dir_mode;
				data.info_fd = -1;
				memcpy(data.mounted_vol, md->mounted_vol,
					NCP_VOLNAME_LEN+1);
			}
			break;
		case NCP_MOUNT_VERSION_V4:
			{
				struct ncp_mount_data_v4* md = (struct ncp_mount_data_v4*)raw_data;

				data.flags = md->flags;
				data.mounted_uid = make_kuid(current_user_ns(), md->mounted_uid);
				data.wdog_pid = find_get_pid(md->wdog_pid);
				data.ncp_fd = md->ncp_fd;
				data.time_out = md->time_out;
				data.retry_count = md->retry_count;
				data.uid = make_kuid(current_user_ns(), md->uid);
				data.gid = make_kgid(current_user_ns(), md->gid);
				data.file_mode = md->file_mode;
				data.dir_mode = md->dir_mode;
				data.info_fd = -1;
			}
			break;
		default:
			error = -ECHRNG;
			if (memcmp(raw_data, "vers", 4) == 0) {
				error = ncp_parse_options(&data, raw_data);
			}
			if (error)
				goto out;
			break;
	}
	error = -EINVAL;
	if (!uid_valid(data.mounted_uid) || !uid_valid(data.uid) ||
	    !gid_valid(data.gid))
		goto out;
	sock = sockfd_lookup(data.ncp_fd, &error);
	if (!sock)
		goto out;

	if (sock->type == SOCK_STREAM)
		default_bufsize = 0xF000;
	else
		default_bufsize = 1024;

	sb->s_flags |= MS_NODIRATIME;	/* probably even noatime */
	sb->s_maxbytes = 0xFFFFFFFFU;
	sb->s_blocksize = 1024;	/* Eh...  Is this correct? */
	sb->s_blocksize_bits = 10;
	sb->s_magic = NCP_SUPER_MAGIC;
	sb->s_op = &ncp_sops;
	sb->s_d_op = &ncp_dentry_operations;
	sb->s_bdi = &server->bdi;

	server = NCP_SBP(sb);
	memset(server, 0, sizeof(*server));

	error = bdi_setup_and_register(&server->bdi, "ncpfs");
	if (error)
		goto out_fput;

	server->ncp_sock = sock;
	
	if (data.info_fd != -1) {
		struct socket *info_sock = sockfd_lookup(data.info_fd, &error);
		if (!info_sock)
			goto out_bdi;
		server->info_sock = info_sock;
		error = -EBADFD;
		if (info_sock->type != SOCK_STREAM)
			goto out_fput2;
	}

/*	server->lock = 0;	*/
	mutex_init(&server->mutex);
	server->packet = NULL;
/*	server->buffer_size = 0;	*/
/*	server->conn_status = 0;	*/
/*	server->root_dentry = NULL;	*/
/*	server->root_setuped = 0;	*/
	mutex_init(&server->root_setup_lock);
#ifdef CONFIG_NCPFS_PACKET_SIGNING
/*	server->sign_wanted = 0;	*/
/*	server->sign_active = 0;	*/
#endif
	init_rwsem(&server->auth_rwsem);
	server->auth.auth_type = NCP_AUTH_NONE;
/*	server->auth.object_name_len = 0;	*/
/*	server->auth.object_name = NULL;	*/
/*	server->auth.object_type = 0;		*/
/*	server->priv.len = 0;			*/
/*	server->priv.data = NULL;		*/

	server->m = data;
	/* Although anything producing this is buggy, it happens
	   now because of PATH_MAX changes.. */
	if (server->m.time_out < 1) {
		server->m.time_out = 10;
		pr_info("You need to recompile your ncpfs utils..\n");
	}
	server->m.time_out = server->m.time_out * HZ / 100;
	server->m.file_mode = (server->m.file_mode & S_IRWXUGO) | S_IFREG;
	server->m.dir_mode = (server->m.dir_mode & S_IRWXUGO) | S_IFDIR;

#ifdef CONFIG_NCPFS_NLS
	/* load the default NLS charsets */
	server->nls_vol = load_nls_default();
	server->nls_io = load_nls_default();
#endif /* CONFIG_NCPFS_NLS */

	atomic_set(&server->dentry_ttl, 0);	/* no caching */

	INIT_LIST_HEAD(&server->tx.requests);
	mutex_init(&server->rcv.creq_mutex);
	server->tx.creq		= NULL;
	server->rcv.creq	= NULL;

	init_timer(&server->timeout_tm);
#undef NCP_PACKET_SIZE
#define NCP_PACKET_SIZE 131072
	error = -ENOMEM;
	server->packet_size = NCP_PACKET_SIZE;
	server->packet = vmalloc(NCP_PACKET_SIZE);
	if (server->packet == NULL)
		goto out_nls;
	server->txbuf = vmalloc(NCP_PACKET_SIZE);
	if (server->txbuf == NULL)
		goto out_packet;
	server->rxbuf = vmalloc(NCP_PACKET_SIZE);
	if (server->rxbuf == NULL)
		goto out_txbuf;

	lock_sock(sock->sk);
	server->data_ready	= sock->sk->sk_data_ready;
	server->write_space	= sock->sk->sk_write_space;
	server->error_report	= sock->sk->sk_error_report;
	sock->sk->sk_user_data	= server;
	sock->sk->sk_data_ready	  = ncp_tcp_data_ready;
	sock->sk->sk_error_report = ncp_tcp_error_report;
	if (sock->type == SOCK_STREAM) {
		server->rcv.ptr = (unsigned char*)&server->rcv.buf;
		server->rcv.len = 10;
		server->rcv.state = 0;
		INIT_WORK(&server->rcv.tq, ncp_tcp_rcv_proc);
		INIT_WORK(&server->tx.tq, ncp_tcp_tx_proc);
		sock->sk->sk_write_space = ncp_tcp_write_space;
	} else {
		INIT_WORK(&server->rcv.tq, ncpdgram_rcv_proc);
		INIT_WORK(&server->timeout_tq, ncpdgram_timeout_proc);
		server->timeout_tm.data = (unsigned long)server;
		server->timeout_tm.function = ncpdgram_timeout_call;
	}
	release_sock(sock->sk);

	ncp_lock_server(server);
	error = ncp_connect(server);
	ncp_unlock_server(server);
	if (error < 0)
		goto out_rxbuf;
	ncp_dbg(1, "NCP_SBP(sb) = %p\n", NCP_SBP(sb));

	error = -EMSGSIZE;	/* -EREMOTESIDEINCOMPATIBLE */
#ifdef CONFIG_NCPFS_PACKET_SIGNING
	if (ncp_negotiate_size_and_options(server, default_bufsize,
		NCP_DEFAULT_OPTIONS, &(server->buffer_size), &options) == 0)
	{
		if (options != NCP_DEFAULT_OPTIONS)
		{
			if (ncp_negotiate_size_and_options(server, 
				default_bufsize,
				options & 2, 
				&(server->buffer_size), &options) != 0)
				
			{
				goto out_disconnect;
			}
		}
		ncp_lock_server(server);
		if (options & 2)
			server->sign_wanted = 1;
		ncp_unlock_server(server);
	}
	else 
#endif	/* CONFIG_NCPFS_PACKET_SIGNING */
	if (ncp_negotiate_buffersize(server, default_bufsize,
  				     &(server->buffer_size)) != 0)
		goto out_disconnect;
	ncp_dbg(1, "bufsize = %d\n", server->buffer_size);

	memset(&finfo, 0, sizeof(finfo));
	finfo.i.attributes	= aDIR;
	finfo.i.dataStreamSize	= 0;	/* ignored */
	finfo.i.dirEntNum	= 0;
	finfo.i.DosDirNum	= 0;
#ifdef CONFIG_NCPFS_SMALLDOS
	finfo.i.NSCreator	= NW_NS_DOS;
#endif
	finfo.volume		= NCP_NUMBER_OF_VOLUMES;
	/* set dates of mountpoint to Jan 1, 1986; 00:00 */
	finfo.i.creationTime	= finfo.i.modifyTime
				= cpu_to_le16(0x0000);
	finfo.i.creationDate	= finfo.i.modifyDate
				= finfo.i.lastAccessDate
				= cpu_to_le16(0x0C21);
	finfo.i.nameLen		= 0;
	finfo.i.entryName[0]	= '\0';

	finfo.opened		= 0;
	finfo.ino		= 2;	/* tradition */

	server->name_space[finfo.volume] = NW_NS_DOS;

	error = -ENOMEM;
        root_inode = ncp_iget(sb, &finfo);
        if (!root_inode)
		goto out_disconnect;
	ncp_dbg(1, "root vol=%d\n", NCP_FINFO(root_inode)->volNumber);
	sb->s_root = d_make_root(root_inode);
        if (!sb->s_root)
		goto out_disconnect;
	return 0;

out_disconnect:
	ncp_lock_server(server);
	ncp_disconnect(server);
	ncp_unlock_server(server);
out_rxbuf:
	ncp_stop_tasks(server);
	vfree(server->rxbuf);
out_txbuf:
	vfree(server->txbuf);
out_packet:
	vfree(server->packet);
out_nls:
#ifdef CONFIG_NCPFS_NLS
	unload_nls(server->nls_io);
	unload_nls(server->nls_vol);
#endif
	mutex_destroy(&server->rcv.creq_mutex);
	mutex_destroy(&server->root_setup_lock);
	mutex_destroy(&server->mutex);
out_fput2:
	if (server->info_sock)
		sockfd_put(server->info_sock);
out_bdi:
	bdi_destroy(&server->bdi);
out_fput:
	sockfd_put(sock);
out:
	put_pid(data.wdog_pid);
	sb->s_fs_info = NULL;
	kfree(server);
	return error;
}

static void delayed_free(struct rcu_head *p)
{
	struct ncp_server *server = container_of(p, struct ncp_server, rcu);
#ifdef CONFIG_NCPFS_NLS
	/* unload the NLS charsets */
	unload_nls(server->nls_vol);
	unload_nls(server->nls_io);
#endif /* CONFIG_NCPFS_NLS */
	kfree(server);
}

static void ncp_put_super(struct super_block *sb)
{
	struct ncp_server *server = NCP_SBP(sb);

	ncp_lock_server(server);
	ncp_disconnect(server);
	ncp_unlock_server(server);

	ncp_stop_tasks(server);

	mutex_destroy(&server->rcv.creq_mutex);
	mutex_destroy(&server->root_setup_lock);
	mutex_destroy(&server->mutex);

	if (server->info_sock)
		sockfd_put(server->info_sock);
	sockfd_put(server->ncp_sock);
	kill_pid(server->m.wdog_pid, SIGTERM, 1);
	put_pid(server->m.wdog_pid);

	bdi_destroy(&server->bdi);
	kfree(server->priv.data);
	kfree(server->auth.object_name);
	vfree(server->rxbuf);
	vfree(server->txbuf);
	vfree(server->packet);
	call_rcu(&server->rcu, delayed_free);
}

static int ncp_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct dentry* d;
	struct inode* i;
	struct ncp_inode_info* ni;
	struct ncp_server* s;
	struct ncp_volume_info vi;
	struct super_block *sb = dentry->d_sb;
	int err;
	__u8 dh;
	
	d = sb->s_root;
	if (!d) {
		goto dflt;
	}
	i = d->d_inode;
	if (!i) {
		goto dflt;
	}
	ni = NCP_FINFO(i);
	if (!ni) {
		goto dflt;
	}
	s = NCP_SBP(sb);
	if (!s) {
		goto dflt;
	}
	if (!s->m.mounted_vol[0]) {
		goto dflt;
	}

	err = ncp_dirhandle_alloc(s, ni->volNumber, ni->DosDirNum, &dh);
	if (err) {
		goto dflt;
	}
	err = ncp_get_directory_info(s, dh, &vi);
	ncp_dirhandle_free(s, dh);
	if (err) {
		goto dflt;
	}
	buf->f_type = NCP_SUPER_MAGIC;
	buf->f_bsize = vi.sectors_per_block * 512;
	buf->f_blocks = vi.total_blocks;
	buf->f_bfree = vi.free_blocks;
	buf->f_bavail = vi.free_blocks;
	buf->f_files = vi.total_dir_entries;
	buf->f_ffree = vi.available_dir_entries;
	buf->f_namelen = 12;
	return 0;

	/* We cannot say how much disk space is left on a mounted
	   NetWare Server, because free space is distributed over
	   volumes, and the current user might have disk quotas. So
	   free space is not that simple to determine. Our decision
	   here is to err conservatively. */

dflt:;
	buf->f_type = NCP_SUPER_MAGIC;
	buf->f_bsize = NCP_BLOCK_SIZE;
	buf->f_blocks = 0;
	buf->f_bfree = 0;
	buf->f_bavail = 0;
	buf->f_namelen = 12;
	return 0;
}

int ncp_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	int result = 0;
	__le32 info_mask;
	struct nw_modify_dos_info info;
	struct ncp_server *server;

	result = -EIO;

	server = NCP_SERVER(inode);
	if (!server)	/* How this could happen? */
		goto out;

	result = -EPERM;
	if (IS_DEADDIR(dentry->d_inode))
		goto out;

	/* ageing the dentry to force validation */
	ncp_age_dentry(server, dentry);

	result = inode_change_ok(inode, attr);
	if (result < 0)
		goto out;

	result = -EPERM;
	if ((attr->ia_valid & ATTR_UID) && !uid_eq(attr->ia_uid, server->m.uid))
		goto out;

	if ((attr->ia_valid & ATTR_GID) && !gid_eq(attr->ia_gid, server->m.gid))
		goto out;

	if (((attr->ia_valid & ATTR_MODE) &&
	     (attr->ia_mode &
	      ~(S_IFREG | S_IFDIR | S_IRWXUGO))))
		goto out;

	info_mask = 0;
	memset(&info, 0, sizeof(info));

#if 1 
        if ((attr->ia_valid & ATTR_MODE) != 0)
        {
		umode_t newmode = attr->ia_mode;

		info_mask |= DM_ATTRIBUTES;

                if (S_ISDIR(inode->i_mode)) {
                	newmode &= server->m.dir_mode;
		} else {
#ifdef CONFIG_NCPFS_EXTRAS			
			if (server->m.flags & NCP_MOUNT_EXTRAS) {
				/* any non-default execute bit set */
				if (newmode & ~server->m.file_mode & S_IXUGO)
					info.attributes |= aSHARED | aSYSTEM;
				/* read for group/world and not in default file_mode */
				else if (newmode & ~server->m.file_mode & S_IRUGO)
					info.attributes |= aSHARED;
			} else
#endif
				newmode &= server->m.file_mode;			
                }
                if (newmode & S_IWUGO)
                	info.attributes &= ~(aRONLY|aRENAMEINHIBIT|aDELETEINHIBIT);
                else
			info.attributes |=  (aRONLY|aRENAMEINHIBIT|aDELETEINHIBIT);

#ifdef CONFIG_NCPFS_NFS_NS
		if (ncp_is_nfs_extras(server, NCP_FINFO(inode)->volNumber)) {
			result = ncp_modify_nfs_info(server,
						     NCP_FINFO(inode)->volNumber,
						     NCP_FINFO(inode)->dirEntNum,
						     attr->ia_mode, 0);
			if (result != 0)
				goto out;
			info.attributes &= ~(aSHARED | aSYSTEM);
			{
				/* mark partial success */
				struct iattr tmpattr;
				
				tmpattr.ia_valid = ATTR_MODE;
				tmpattr.ia_mode = attr->ia_mode;

				setattr_copy(inode, &tmpattr);
				mark_inode_dirty(inode);
			}
		}
#endif
        }
#endif

	/* Do SIZE before attributes, otherwise mtime together with size does not work...
	 */
	if ((attr->ia_valid & ATTR_SIZE) != 0) {
		int written;

		ncp_dbg(1, "trying to change size to %llu\n", attr->ia_size);

		if ((result = ncp_make_open(inode, O_WRONLY)) < 0) {
			result = -EACCES;
			goto out;
		}
		ncp_write_kernel(NCP_SERVER(inode), NCP_FINFO(inode)->file_handle,
			  attr->ia_size, 0, "", &written);

		/* According to ndir, the changes only take effect after
		   closing the file */
		ncp_inode_close(inode);
		result = ncp_make_closed(inode);
		if (result)
			goto out;

		if (attr->ia_size != i_size_read(inode)) {
			truncate_setsize(inode, attr->ia_size);
			mark_inode_dirty(inode);
		}
	}
	if ((attr->ia_valid & ATTR_CTIME) != 0) {
		info_mask |= (DM_CREATE_TIME | DM_CREATE_DATE);
		ncp_date_unix2dos(attr->ia_ctime.tv_sec,
			     &info.creationTime, &info.creationDate);
	}
	if ((attr->ia_valid & ATTR_MTIME) != 0) {
		info_mask |= (DM_MODIFY_TIME | DM_MODIFY_DATE);
		ncp_date_unix2dos(attr->ia_mtime.tv_sec,
				  &info.modifyTime, &info.modifyDate);
	}
	if ((attr->ia_valid & ATTR_ATIME) != 0) {
		__le16 dummy;
		info_mask |= (DM_LAST_ACCESS_DATE);
		ncp_date_unix2dos(attr->ia_atime.tv_sec,
				  &dummy, &info.lastAccessDate);
	}
	if (info_mask != 0) {
		result = ncp_modify_file_or_subdir_dos_info(NCP_SERVER(inode),
				      inode, info_mask, &info);
		if (result != 0) {
			if (info_mask == (DM_CREATE_TIME | DM_CREATE_DATE)) {
				/* NetWare seems not to allow this. I
				   do not know why. So, just tell the
				   user everything went fine. This is
				   a terrible hack, but I do not know
				   how to do this correctly. */
				result = 0;
			} else
				goto out;
		}
#ifdef CONFIG_NCPFS_STRONG		
		if ((!result) && (info_mask & DM_ATTRIBUTES))
			NCP_FINFO(inode)->nwattr = info.attributes;
#endif
	}
	if (result)
		goto out;

	setattr_copy(inode, attr);
	mark_inode_dirty(inode);

out:
	if (result > 0)
		result = -EACCES;
	return result;
}

static struct dentry *ncp_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_nodev(fs_type, flags, data, ncp_fill_super);
}

static struct file_system_type ncp_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "ncpfs",
	.mount		= ncp_mount,
	.kill_sb	= kill_anon_super,
	.fs_flags	= FS_BINARY_MOUNTDATA,
};
MODULE_ALIAS_FS("ncpfs");

static int __init init_ncp_fs(void)
{
	int err;
	ncp_dbg(1, "called\n");

	err = init_inodecache();
	if (err)
		goto out1;
	err = register_filesystem(&ncp_fs_type);
	if (err)
		goto out;
	return 0;
out:
	destroy_inodecache();
out1:
	return err;
}

static void __exit exit_ncp_fs(void)
{
	ncp_dbg(1, "called\n");
	unregister_filesystem(&ncp_fs_type);
	destroy_inodecache();
}

module_init(init_ncp_fs)
module_exit(exit_ncp_fs)
MODULE_LICENSE("GPL");
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/inode.c */
/************************************************************/
/*
 *  ioctl.c
 *
 *  Copyright (C) 1995, 1996 by Volker Lendecke
 *  Modified 1997 Peter Waltenberg, Bill Hawes, David Woodhouse for 2.1 dcache
 *  Modified 1998, 1999 Wolfram Pienkoss for NLS
 *
 */

#include <linux/capability.h>
#include <linux/compat.h>
// #include <linux/errno.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
// #include <linux/time.h>
// #include <linux/mm.h>
// #include <linux/mount.h>
// #include <linux/slab.h>
#include <linux/highuid.h>
// #include <linux/vmalloc.h>
// #include <linux/sched.h>
#include "../../inc/__fss.h"

// #include <asm/uaccess.h>

// #include "ncp_fs.h"

/* maximum limit for ncp_objectname_ioctl */
#define NCP_OBJECT_NAME_MAX_LEN	4096
/* maximum limit for ncp_privatedata_ioctl */
#define NCP_PRIVATE_DATA_MAX_LEN 8192
/* maximum negotiable packet size */
#define NCP_PACKET_SIZE_INTERNAL 65536

static int
ncp_get_fs_info(struct ncp_server * server, struct inode *inode,
		struct ncp_fs_info __user *arg)
{
	struct ncp_fs_info info;

	if (copy_from_user(&info, arg, sizeof(info)))
		return -EFAULT;

	if (info.version != NCP_GET_FS_INFO_VERSION) {
		ncp_dbg(1, "info.version invalid: %d\n", info.version);
		return -EINVAL;
	}
	/* TODO: info.addr = server->m.serv_addr; */
	SET_UID(info.mounted_uid, from_kuid_munged(current_user_ns(), server->m.mounted_uid));
	info.connection		= server->connection;
	info.buffer_size	= server->buffer_size;
	info.volume_number	= NCP_FINFO(inode)->volNumber;
	info.directory_id	= NCP_FINFO(inode)->DosDirNum;

	if (copy_to_user(arg, &info, sizeof(info)))
		return -EFAULT;
	return 0;
}

static int
ncp_get_fs_info_v2(struct ncp_server * server, struct inode *inode,
		   struct ncp_fs_info_v2 __user * arg)
{
	struct ncp_fs_info_v2 info2;

	if (copy_from_user(&info2, arg, sizeof(info2)))
		return -EFAULT;

	if (info2.version != NCP_GET_FS_INFO_VERSION_V2) {
		ncp_dbg(1, "info.version invalid: %d\n", info2.version);
		return -EINVAL;
	}
	info2.mounted_uid   = from_kuid_munged(current_user_ns(), server->m.mounted_uid);
	info2.connection    = server->connection;
	info2.buffer_size   = server->buffer_size;
	info2.volume_number = NCP_FINFO(inode)->volNumber;
	info2.directory_id  = NCP_FINFO(inode)->DosDirNum;
	info2.dummy1 = info2.dummy2 = info2.dummy3 = 0;

	if (copy_to_user(arg, &info2, sizeof(info2)))
		return -EFAULT;
	return 0;
}

#ifdef CONFIG_COMPAT
struct compat_ncp_objectname_ioctl
{
	s32		auth_type;
	u32		object_name_len;
	compat_caddr_t	object_name;	/* a userspace data, in most cases user name */
};

struct compat_ncp_fs_info_v2 {
	s32 version;
	u32 mounted_uid;
	u32 connection;
	u32 buffer_size;

	u32 volume_number;
	u32 directory_id;

	u32 dummy1;
	u32 dummy2;
	u32 dummy3;
};

struct compat_ncp_ioctl_request {
	u32 function;
	u32 size;
	compat_caddr_t data;
};

struct compat_ncp_privatedata_ioctl
{
	u32		len;
	compat_caddr_t	data;		/* ~1000 for NDS */
};

#define NCP_IOC_GET_FS_INFO_V2_32	_IOWR('n', 4, struct compat_ncp_fs_info_v2)
#define NCP_IOC_NCPREQUEST_32		_IOR('n', 1, struct compat_ncp_ioctl_request)
#define NCP_IOC_GETOBJECTNAME_32	_IOWR('n', 9, struct compat_ncp_objectname_ioctl)
#define NCP_IOC_SETOBJECTNAME_32	_IOR('n', 9, struct compat_ncp_objectname_ioctl)
#define NCP_IOC_GETPRIVATEDATA_32	_IOWR('n', 10, struct compat_ncp_privatedata_ioctl)
#define NCP_IOC_SETPRIVATEDATA_32	_IOR('n', 10, struct compat_ncp_privatedata_ioctl)

static int
ncp_get_compat_fs_info_v2(struct ncp_server * server, struct inode *inode,
		   struct compat_ncp_fs_info_v2 __user * arg)
{
	struct compat_ncp_fs_info_v2 info2;

	if (copy_from_user(&info2, arg, sizeof(info2)))
		return -EFAULT;

	if (info2.version != NCP_GET_FS_INFO_VERSION_V2) {
		ncp_dbg(1, "info.version invalid: %d\n", info2.version);
		return -EINVAL;
	}
	info2.mounted_uid   = from_kuid_munged(current_user_ns(), server->m.mounted_uid);
	info2.connection    = server->connection;
	info2.buffer_size   = server->buffer_size;
	info2.volume_number = NCP_FINFO(inode)->volNumber;
	info2.directory_id  = NCP_FINFO(inode)->DosDirNum;
	info2.dummy1 = info2.dummy2 = info2.dummy3 = 0;

	if (copy_to_user(arg, &info2, sizeof(info2)))
		return -EFAULT;
	return 0;
}
#endif

#define NCP_IOC_GETMOUNTUID16		_IOW('n', 2, u16)
#define NCP_IOC_GETMOUNTUID32		_IOW('n', 2, u32)
#define NCP_IOC_GETMOUNTUID64		_IOW('n', 2, u64)

#ifdef CONFIG_NCPFS_NLS
/* Here we are select the iocharset and the codepage for NLS.
 * Thanks Petr Vandrovec for idea and many hints.
 */
static int
ncp_set_charsets(struct ncp_server* server, struct ncp_nls_ioctl __user *arg)
{
	struct ncp_nls_ioctl user;
	struct nls_table *codepage;
	struct nls_table *iocharset;
	struct nls_table *oldset_io;
	struct nls_table *oldset_cp;
	int utf8;
	int err;

	if (copy_from_user(&user, arg, sizeof(user)))
		return -EFAULT;

	codepage = NULL;
	user.codepage[NCP_IOCSNAME_LEN] = 0;
	if (!user.codepage[0] || !strcmp(user.codepage, "default"))
		codepage = load_nls_default();
	else {
		codepage = load_nls(user.codepage);
		if (!codepage) {
			return -EBADRQC;
		}
	}

	iocharset = NULL;
	user.iocharset[NCP_IOCSNAME_LEN] = 0;
	if (!user.iocharset[0] || !strcmp(user.iocharset, "default")) {
		iocharset = load_nls_default();
		utf8 = 0;
	} else if (!strcmp(user.iocharset, "utf8")) {
		iocharset = load_nls_default();
		utf8 = 1;
	} else {
		iocharset = load_nls(user.iocharset);
		if (!iocharset) {
			unload_nls(codepage);
			return -EBADRQC;
		}
		utf8 = 0;
	}

	mutex_lock(&server->root_setup_lock);
	if (server->root_setuped) {
		oldset_cp = codepage;
		oldset_io = iocharset;
		err = -EBUSY;
	} else {
		if (utf8)
			NCP_SET_FLAG(server, NCP_FLAG_UTF8);
		else
			NCP_CLR_FLAG(server, NCP_FLAG_UTF8);
		oldset_cp = server->nls_vol;
		server->nls_vol = codepage;
		oldset_io = server->nls_io;
		server->nls_io = iocharset;
		err = 0;
	}
	mutex_unlock(&server->root_setup_lock);
	unload_nls(oldset_cp);
	unload_nls(oldset_io);

	return err;
}

static int
ncp_get_charsets(struct ncp_server* server, struct ncp_nls_ioctl __user *arg)
{
	struct ncp_nls_ioctl user;
	int len;

	memset(&user, 0, sizeof(user));
	mutex_lock(&server->root_setup_lock);
	if (server->nls_vol && server->nls_vol->charset) {
		len = strlen(server->nls_vol->charset);
		if (len > NCP_IOCSNAME_LEN)
			len = NCP_IOCSNAME_LEN;
		strncpy(user.codepage, server->nls_vol->charset, len);
		user.codepage[len] = 0;
	}

	if (NCP_IS_FLAG(server, NCP_FLAG_UTF8))
		strcpy(user.iocharset, "utf8");
	else if (server->nls_io && server->nls_io->charset) {
		len = strlen(server->nls_io->charset);
		if (len > NCP_IOCSNAME_LEN)
			len = NCP_IOCSNAME_LEN;
		strncpy(user.iocharset,	server->nls_io->charset, len);
		user.iocharset[len] = 0;
	}
	mutex_unlock(&server->root_setup_lock);

	if (copy_to_user(arg, &user, sizeof(user)))
		return -EFAULT;
	return 0;
}
#endif /* CONFIG_NCPFS_NLS */

static long __ncp_ioctl(struct inode *inode, unsigned int cmd, unsigned long arg)
{
	struct ncp_server *server = NCP_SERVER(inode);
	int result;
	struct ncp_ioctl_request request;
	char* bouncebuffer;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
#ifdef CONFIG_COMPAT
	case NCP_IOC_NCPREQUEST_32:
#endif
	case NCP_IOC_NCPREQUEST:
#ifdef CONFIG_COMPAT
		if (cmd == NCP_IOC_NCPREQUEST_32) {
			struct compat_ncp_ioctl_request request32;
			if (copy_from_user(&request32, argp, sizeof(request32)))
				return -EFAULT;
			request.function = request32.function;
			request.size = request32.size;
			request.data = compat_ptr(request32.data);
		} else
#endif
		if (copy_from_user(&request, argp, sizeof(request)))
			return -EFAULT;

		if ((request.function > 255)
		    || (request.size >
		  NCP_PACKET_SIZE - sizeof(struct ncp_request_header))) {
			return -EINVAL;
		}
		bouncebuffer = vmalloc(NCP_PACKET_SIZE_INTERNAL);
		if (!bouncebuffer)
			return -ENOMEM;
		if (copy_from_user(bouncebuffer, request.data, request.size)) {
			vfree(bouncebuffer);
			return -EFAULT;
		}
		ncp_lock_server(server);

		/* FIXME: We hack around in the server's structures
		   here to be able to use ncp_request */

		server->has_subfunction = 0;
		server->current_size = request.size;
		memcpy(server->packet, bouncebuffer, request.size);

		result = ncp_request2(server, request.function,
			bouncebuffer, NCP_PACKET_SIZE_INTERNAL);
		if (result < 0)
			result = -EIO;
		else
			result = server->reply_size;
		ncp_unlock_server(server);
		ncp_dbg(1, "copy %d bytes\n", result);
		if (result >= 0)
			if (copy_to_user(request.data, bouncebuffer, result))
				result = -EFAULT;
		vfree(bouncebuffer);
		return result;

	case NCP_IOC_CONN_LOGGED_IN:

		if (!(server->m.int_flags & NCP_IMOUNT_LOGGEDIN_POSSIBLE))
			return -EINVAL;
		mutex_lock(&server->root_setup_lock);
		if (server->root_setuped)
			result = -EBUSY;
		else {
			result = ncp_conn_logged_in(inode->i_sb);
			if (result == 0)
				server->root_setuped = 1;
		}
		mutex_unlock(&server->root_setup_lock);
		return result;

	case NCP_IOC_GET_FS_INFO:
		return ncp_get_fs_info(server, inode, argp);

	case NCP_IOC_GET_FS_INFO_V2:
		return ncp_get_fs_info_v2(server, inode, argp);

#ifdef CONFIG_COMPAT
	case NCP_IOC_GET_FS_INFO_V2_32:
		return ncp_get_compat_fs_info_v2(server, inode, argp);
#endif
	/* we have too many combinations of CONFIG_COMPAT,
	 * CONFIG_64BIT and CONFIG_UID16, so just handle
	 * any of the possible ioctls */
	case NCP_IOC_GETMOUNTUID16:
		{
			u16 uid;

			SET_UID(uid, from_kuid_munged(current_user_ns(), server->m.mounted_uid));
			if (put_user(uid, (u16 __user *)argp))
				return -EFAULT;
			return 0;
		}
	case NCP_IOC_GETMOUNTUID32:
	{
		uid_t uid = from_kuid_munged(current_user_ns(), server->m.mounted_uid);
		if (put_user(uid, (u32 __user *)argp))
			return -EFAULT;
		return 0;
	}
	case NCP_IOC_GETMOUNTUID64:
	{
		uid_t uid = from_kuid_munged(current_user_ns(), server->m.mounted_uid);
		if (put_user(uid, (u64 __user *)argp))
			return -EFAULT;
		return 0;
	}
	case NCP_IOC_GETROOT:
		{
			struct ncp_setroot_ioctl sr;

			result = -EACCES;
			mutex_lock(&server->root_setup_lock);
			if (server->m.mounted_vol[0]) {
				struct dentry* dentry = inode->i_sb->s_root;

				if (dentry) {
					struct inode* s_inode = dentry->d_inode;

					if (s_inode) {
						sr.volNumber = NCP_FINFO(s_inode)->volNumber;
						sr.dirEntNum = NCP_FINFO(s_inode)->dirEntNum;
						sr.namespace = server->name_space[sr.volNumber];
						result = 0;
					} else
						ncp_dbg(1, "s_root->d_inode==NULL\n");
				} else
					ncp_dbg(1, "s_root==NULL\n");
			} else {
				sr.volNumber = -1;
				sr.namespace = 0;
				sr.dirEntNum = 0;
				result = 0;
			}
			mutex_unlock(&server->root_setup_lock);
			if (!result && copy_to_user(argp, &sr, sizeof(sr)))
				result = -EFAULT;
			return result;
		}

	case NCP_IOC_SETROOT:
		{
			struct ncp_setroot_ioctl sr;
			__u32 vnum;
			__le32 de;
			__le32 dosde;
			struct dentry* dentry;

			if (copy_from_user(&sr, argp, sizeof(sr)))
				return -EFAULT;
			mutex_lock(&server->root_setup_lock);
			if (server->root_setuped)
				result = -EBUSY;
			else {
				if (sr.volNumber < 0) {
					server->m.mounted_vol[0] = 0;
					vnum = NCP_NUMBER_OF_VOLUMES;
					de = 0;
					dosde = 0;
					result = 0;
				} else if (sr.volNumber >= NCP_NUMBER_OF_VOLUMES) {
					result = -EINVAL;
				} else if (ncp_mount_subdir(server, sr.volNumber,
							sr.namespace, sr.dirEntNum,
							&vnum, &de, &dosde)) {
					result = -ENOENT;
				} else
					result = 0;

				if (result == 0) {
					dentry = inode->i_sb->s_root;
					if (dentry) {
						struct inode* s_inode = dentry->d_inode;

						if (s_inode) {
							NCP_FINFO(s_inode)->volNumber = vnum;
							NCP_FINFO(s_inode)->dirEntNum = de;
							NCP_FINFO(s_inode)->DosDirNum = dosde;
							server->root_setuped = 1;
						} else {
							ncp_dbg(1, "s_root->d_inode==NULL\n");
							result = -EIO;
						}
					} else {
						ncp_dbg(1, "s_root==NULL\n");
						result = -EIO;
					}
				}
			}
			mutex_unlock(&server->root_setup_lock);

			return result;
		}

#ifdef CONFIG_NCPFS_PACKET_SIGNING
	case NCP_IOC_SIGN_INIT:
		{
			struct ncp_sign_init sign;

			if (argp)
				if (copy_from_user(&sign, argp, sizeof(sign)))
					return -EFAULT;
			ncp_lock_server(server);
			mutex_lock(&server->rcv.creq_mutex);
			if (argp) {
				if (server->sign_wanted) {
					memcpy(server->sign_root,sign.sign_root,8);
					memcpy(server->sign_last,sign.sign_last,16);
					server->sign_active = 1;
				}
				/* ignore when signatures not wanted */
			} else {
				server->sign_active = 0;
			}
			mutex_unlock(&server->rcv.creq_mutex);
			ncp_unlock_server(server);
			return 0;
		}

        case NCP_IOC_SIGN_WANTED:
		{
			int state;

			ncp_lock_server(server);
			state = server->sign_wanted;
			ncp_unlock_server(server);
			if (put_user(state, (int __user *)argp))
				return -EFAULT;
			return 0;
		}

	case NCP_IOC_SET_SIGN_WANTED:
		{
			int newstate;

			/* get only low 8 bits... */
			if (get_user(newstate, (unsigned char __user *)argp))
				return -EFAULT;
			result = 0;
			ncp_lock_server(server);
			if (server->sign_active) {
				/* cannot turn signatures OFF when active */
				if (!newstate)
					result = -EINVAL;
			} else {
				server->sign_wanted = newstate != 0;
			}
			ncp_unlock_server(server);
			return result;
		}

#endif /* CONFIG_NCPFS_PACKET_SIGNING */

#ifdef CONFIG_NCPFS_IOCTL_LOCKING
	case NCP_IOC_LOCKUNLOCK:
		{
			struct ncp_lock_ioctl	 rqdata;

			if (copy_from_user(&rqdata, argp, sizeof(rqdata)))
				return -EFAULT;
			if (rqdata.origin != 0)
				return -EINVAL;
			/* check for cmd */
			switch (rqdata.cmd) {
				case NCP_LOCK_EX:
				case NCP_LOCK_SH:
						if (rqdata.timeout == 0)
							rqdata.timeout = NCP_LOCK_DEFAULT_TIMEOUT;
						else if (rqdata.timeout > NCP_LOCK_MAX_TIMEOUT)
							rqdata.timeout = NCP_LOCK_MAX_TIMEOUT;
						break;
				case NCP_LOCK_LOG:
						rqdata.timeout = NCP_LOCK_DEFAULT_TIMEOUT;	/* has no effect */
				case NCP_LOCK_CLEAR:
						break;
				default:
						return -EINVAL;
			}
			/* locking needs both read and write access */
			if ((result = ncp_make_open(inode, O_RDWR)) != 0)
			{
				return result;
			}
			result = -EISDIR;
			if (!S_ISREG(inode->i_mode))
				goto outrel;
			if (rqdata.cmd == NCP_LOCK_CLEAR)
			{
				result = ncp_ClearPhysicalRecord(NCP_SERVER(inode),
							NCP_FINFO(inode)->file_handle,
							rqdata.offset,
							rqdata.length);
				if (result > 0) result = 0;	/* no such lock */
			}
			else
			{
				int lockcmd;

				switch (rqdata.cmd)
				{
					case NCP_LOCK_EX:  lockcmd=1; break;
					case NCP_LOCK_SH:  lockcmd=3; break;
					default:	   lockcmd=0; break;
				}
				result = ncp_LogPhysicalRecord(NCP_SERVER(inode),
							NCP_FINFO(inode)->file_handle,
							lockcmd,
							rqdata.offset,
							rqdata.length,
							rqdata.timeout);
				if (result > 0) result = -EAGAIN;
			}
outrel:
			ncp_inode_close(inode);
			return result;
		}
#endif	/* CONFIG_NCPFS_IOCTL_LOCKING */

#ifdef CONFIG_COMPAT
	case NCP_IOC_GETOBJECTNAME_32:
		{
			struct compat_ncp_objectname_ioctl user;
			size_t outl;

			if (copy_from_user(&user, argp, sizeof(user)))
				return -EFAULT;
			down_read(&server->auth_rwsem);
			user.auth_type = server->auth.auth_type;
			outl = user.object_name_len;
			user.object_name_len = server->auth.object_name_len;
			if (outl > user.object_name_len)
				outl = user.object_name_len;
			result = 0;
			if (outl) {
				if (copy_to_user(compat_ptr(user.object_name),
						 server->auth.object_name,
						 outl))
					result = -EFAULT;
			}
			up_read(&server->auth_rwsem);
			if (!result && copy_to_user(argp, &user, sizeof(user)))
				result = -EFAULT;
			return result;
		}
#endif

	case NCP_IOC_GETOBJECTNAME:
		{
			struct ncp_objectname_ioctl user;
			size_t outl;

			if (copy_from_user(&user, argp, sizeof(user)))
				return -EFAULT;
			down_read(&server->auth_rwsem);
			user.auth_type = server->auth.auth_type;
			outl = user.object_name_len;
			user.object_name_len = server->auth.object_name_len;
			if (outl > user.object_name_len)
				outl = user.object_name_len;
			result = 0;
			if (outl) {
				if (copy_to_user(user.object_name,
						 server->auth.object_name,
						 outl))
					result = -EFAULT;
			}
			up_read(&server->auth_rwsem);
			if (!result && copy_to_user(argp, &user, sizeof(user)))
				result = -EFAULT;
			return result;
		}

#ifdef CONFIG_COMPAT
	case NCP_IOC_SETOBJECTNAME_32:
#endif
	case NCP_IOC_SETOBJECTNAME:
		{
			struct ncp_objectname_ioctl user;
			void* newname;
			void* oldname;
			size_t oldnamelen;
			void* oldprivate;
			size_t oldprivatelen;

#ifdef CONFIG_COMPAT
			if (cmd == NCP_IOC_SETOBJECTNAME_32) {
				struct compat_ncp_objectname_ioctl user32;
				if (copy_from_user(&user32, argp, sizeof(user32)))
					return -EFAULT;
				user.auth_type = user32.auth_type;
				user.object_name_len = user32.object_name_len;
				user.object_name = compat_ptr(user32.object_name);
			} else
#endif
			if (copy_from_user(&user, argp, sizeof(user)))
				return -EFAULT;

			if (user.object_name_len > NCP_OBJECT_NAME_MAX_LEN)
				return -ENOMEM;
			if (user.object_name_len) {
				newname = memdup_user(user.object_name,
						      user.object_name_len);
				if (IS_ERR(newname))
					return PTR_ERR(newname);
			} else {
				newname = NULL;
			}
			down_write(&server->auth_rwsem);
			oldname = server->auth.object_name;
			oldnamelen = server->auth.object_name_len;
			oldprivate = server->priv.data;
			oldprivatelen = server->priv.len;
			server->auth.auth_type = user.auth_type;
			server->auth.object_name_len = user.object_name_len;
			server->auth.object_name = newname;
			server->priv.len = 0;
			server->priv.data = NULL;
			up_write(&server->auth_rwsem);
			kfree(oldprivate);
			kfree(oldname);
			return 0;
		}

#ifdef CONFIG_COMPAT
	case NCP_IOC_GETPRIVATEDATA_32:
#endif
	case NCP_IOC_GETPRIVATEDATA:
		{
			struct ncp_privatedata_ioctl user;
			size_t outl;

#ifdef CONFIG_COMPAT
			if (cmd == NCP_IOC_GETPRIVATEDATA_32) {
				struct compat_ncp_privatedata_ioctl user32;
				if (copy_from_user(&user32, argp, sizeof(user32)))
					return -EFAULT;
				user.len = user32.len;
				user.data = compat_ptr(user32.data);
			} else
#endif
			if (copy_from_user(&user, argp, sizeof(user)))
				return -EFAULT;

			down_read(&server->auth_rwsem);
			outl = user.len;
			user.len = server->priv.len;
			if (outl > user.len) outl = user.len;
			result = 0;
			if (outl) {
				if (copy_to_user(user.data,
						 server->priv.data,
						 outl))
					result = -EFAULT;
			}
			up_read(&server->auth_rwsem);
			if (result)
				return result;
#ifdef CONFIG_COMPAT
			if (cmd == NCP_IOC_GETPRIVATEDATA_32) {
				struct compat_ncp_privatedata_ioctl user32;
				user32.len = user.len;
				user32.data = (unsigned long) user.data;
				if (copy_to_user(argp, &user32, sizeof(user32)))
					return -EFAULT;
			} else
#endif
			if (copy_to_user(argp, &user, sizeof(user)))
				return -EFAULT;

			return 0;
		}

#ifdef CONFIG_COMPAT
	case NCP_IOC_SETPRIVATEDATA_32:
#endif
	case NCP_IOC_SETPRIVATEDATA:
		{
			struct ncp_privatedata_ioctl user;
			void* new;
			void* old;
			size_t oldlen;

#ifdef CONFIG_COMPAT
			if (cmd == NCP_IOC_SETPRIVATEDATA_32) {
				struct compat_ncp_privatedata_ioctl user32;
				if (copy_from_user(&user32, argp, sizeof(user32)))
					return -EFAULT;
				user.len = user32.len;
				user.data = compat_ptr(user32.data);
			} else
#endif
			if (copy_from_user(&user, argp, sizeof(user)))
				return -EFAULT;

			if (user.len > NCP_PRIVATE_DATA_MAX_LEN)
				return -ENOMEM;
			if (user.len) {
				new = memdup_user(user.data, user.len);
				if (IS_ERR(new))
					return PTR_ERR(new);
			} else {
				new = NULL;
			}
			down_write(&server->auth_rwsem);
			old = server->priv.data;
			oldlen = server->priv.len;
			server->priv.len = user.len;
			server->priv.data = new;
			up_write(&server->auth_rwsem);
			kfree(old);
			return 0;
		}

#ifdef CONFIG_NCPFS_NLS
	case NCP_IOC_SETCHARSETS:
		return ncp_set_charsets(server, argp);

	case NCP_IOC_GETCHARSETS:
		return ncp_get_charsets(server, argp);

#endif /* CONFIG_NCPFS_NLS */

	case NCP_IOC_SETDENTRYTTL:
		{
			u_int32_t user;

			if (copy_from_user(&user, argp, sizeof(user)))
				return -EFAULT;
			/* 20 secs at most... */
			if (user > 20000)
				return -EINVAL;
			user = (user * HZ) / 1000;
			atomic_set(&server->dentry_ttl, user);
			return 0;
		}

	case NCP_IOC_GETDENTRYTTL:
		{
			u_int32_t user = (atomic_read(&server->dentry_ttl) * 1000) / HZ;
			if (copy_to_user(argp, &user, sizeof(user)))
				return -EFAULT;
			return 0;
		}

	}
	return -EINVAL;
}

long ncp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct ncp_server *server = NCP_SERVER(inode);
	kuid_t uid = current_uid();
	int need_drop_write = 0;
	long ret;

	switch (cmd) {
	case NCP_IOC_SETCHARSETS:
	case NCP_IOC_CONN_LOGGED_IN:
	case NCP_IOC_SETROOT:
		if (!capable(CAP_SYS_ADMIN)) {
			ret = -EPERM;
			goto out;
		}
		break;
	}
	if (!uid_eq(server->m.mounted_uid, uid)) {
		switch (cmd) {
		/*
		 * Only mount owner can issue these ioctls.  Information
		 * necessary to authenticate to other NDS servers are
		 * stored here.
		 */
		case NCP_IOC_GETOBJECTNAME:
		case NCP_IOC_SETOBJECTNAME:
		case NCP_IOC_GETPRIVATEDATA:
		case NCP_IOC_SETPRIVATEDATA:
#ifdef CONFIG_COMPAT
		case NCP_IOC_GETOBJECTNAME_32:
		case NCP_IOC_SETOBJECTNAME_32:
		case NCP_IOC_GETPRIVATEDATA_32:
		case NCP_IOC_SETPRIVATEDATA_32:
#endif
			ret = -EACCES;
			goto out;
		/*
		 * These require write access on the inode if user id
		 * does not match.  Note that they do not write to the
		 * file...  But old code did mnt_want_write, so I keep
		 * it as is.  Of course not for mountpoint owner, as
		 * that breaks read-only mounts altogether as ncpmount
		 * needs working NCP_IOC_NCPREQUEST and
		 * NCP_IOC_GET_FS_INFO.  Some of these codes (setdentryttl,
		 * signinit, setsignwanted) should be probably restricted
		 * to owner only, or even more to CAP_SYS_ADMIN).
		 */
		case NCP_IOC_GET_FS_INFO:
		case NCP_IOC_GET_FS_INFO_V2:
		case NCP_IOC_NCPREQUEST:
		case NCP_IOC_SETDENTRYTTL:
		case NCP_IOC_SIGN_INIT:
		case NCP_IOC_LOCKUNLOCK:
		case NCP_IOC_SET_SIGN_WANTED:
#ifdef CONFIG_COMPAT
		case NCP_IOC_GET_FS_INFO_V2_32:
		case NCP_IOC_NCPREQUEST_32:
#endif
			ret = mnt_want_write_file(filp);
			if (ret)
				goto out;
			need_drop_write = 1;
			ret = inode_permission(inode, MAY_WRITE);
			if (ret)
				goto outDropWrite;
			break;
		/*
		 * Read access required.
		 */
		case NCP_IOC_GETMOUNTUID16:
		case NCP_IOC_GETMOUNTUID32:
		case NCP_IOC_GETMOUNTUID64:
		case NCP_IOC_GETROOT:
		case NCP_IOC_SIGN_WANTED:
			ret = inode_permission(inode, MAY_READ);
			if (ret)
				goto out;
			break;
		/*
		 * Anybody can read these.
		 */
		case NCP_IOC_GETCHARSETS:
		case NCP_IOC_GETDENTRYTTL:
		default:
		/* Three codes below are protected by CAP_SYS_ADMIN above. */
		case NCP_IOC_SETCHARSETS:
		case NCP_IOC_CONN_LOGGED_IN:
		case NCP_IOC_SETROOT:
			break;
		}
	}
	ret = __ncp_ioctl(inode, cmd, arg);
outDropWrite:
	if (need_drop_write)
		mnt_drop_write_file(filp);
out:
	return ret;
}

#ifdef CONFIG_COMPAT
long ncp_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret;

	arg = (unsigned long) compat_ptr(arg);
	ret = ncp_ioctl(file, cmd, arg);
	return ret;
}
#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/ioctl.c */
/************************************************************/
/*
 *  mmap.c
 *
 *  Copyright (C) 1995, 1996 by Volker Lendecke
 *  Modified 1997 Peter Waltenberg, Bill Hawes, David Woodhouse for 2.1 dcache
 *
 */

// #include <linux/stat.h>
// #include <linux/time.h>
// #include <linux/kernel.h>
#include <linux/gfp.h>
// #include <linux/mm.h>
#include <linux/shm.h>
// #include <linux/errno.h>
#include <linux/mman.h>
// #include <linux/string.h>
// #include <linux/fcntl.h>
#include <linux/memcontrol.h>
#include "../../inc/__fss.h"

// #include <asm/uaccess.h>

// #include "ncp_fs.h"

/*
 * Fill in the supplied page for mmap
 * XXX: how are we excluding truncate/invalidate here? Maybe need to lock
 * page?
 */
static int ncp_file_mmap_fault(struct vm_area_struct *area,
					struct vm_fault *vmf)
{
	struct inode *inode = file_inode(area->vm_file);
	char *pg_addr;
	unsigned int already_read;
	unsigned int count;
	int bufsize;
	int pos; /* XXX: loff_t ? */

	/*
	 * ncpfs has nothing against high pages as long
	 * as recvmsg and memset works on it
	 */
	vmf->page = alloc_page(GFP_HIGHUSER);
	if (!vmf->page)
		return VM_FAULT_OOM;
	pg_addr = kmap(vmf->page);
	pos = vmf->pgoff << PAGE_SHIFT;

	count = PAGE_SIZE;
	/* what we can read in one go */
	bufsize = NCP_SERVER(inode)->buffer_size;

	already_read = 0;
	if (ncp_make_open(inode, O_RDONLY) >= 0) {
		while (already_read < count) {
			int read_this_time;
			int to_read;

			to_read = bufsize - (pos % bufsize);

			to_read = min_t(unsigned int, to_read, count - already_read);

			if (ncp_read_kernel(NCP_SERVER(inode),
				     NCP_FINFO(inode)->file_handle,
				     pos, to_read,
				     pg_addr + already_read,
				     &read_this_time) != 0) {
				read_this_time = 0;
			}
			pos += read_this_time;
			already_read += read_this_time;

			if (read_this_time < to_read) {
				break;
			}
		}
		ncp_inode_close(inode);

	}

	if (already_read < PAGE_SIZE)
		memset(pg_addr + already_read, 0, PAGE_SIZE - already_read);
	flush_dcache_page(vmf->page);
	kunmap(vmf->page);

	/*
	 * If I understand ncp_read_kernel() properly, the above always
	 * fetches from the network, here the analogue of disk.
	 * -- nyc
	 */
	count_vm_event(PGMAJFAULT);
	mem_cgroup_count_vm_event(area->vm_mm, PGMAJFAULT);
	return VM_FAULT_MAJOR;
}

static const struct vm_operations_struct ncp_file_mmap =
{
	.fault = ncp_file_mmap_fault,
};


/* This is used for a general mmap of a ncp file */
int ncp_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);
	
	ncp_dbg(1, "called\n");

	if (!ncp_conn_valid(NCP_SERVER(inode)))
		return -EIO;

	/* only PAGE_COW or read-only supported now */
	if (vma->vm_flags & VM_SHARED)
		return -EINVAL;
	/* we do not support files bigger than 4GB... We eventually 
	   supports just 4GB... */
	if (vma_pages(vma) + vma->vm_pgoff
	   > (1U << (32 - PAGE_SHIFT)))
		return -EFBIG;

	vma->vm_ops = &ncp_file_mmap;
	file_accessed(file);
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/mmap.c */
/************************************************************/
/*
 *  ncplib_kernel.c
 *
 *  Copyright (C) 1995, 1996 by Volker Lendecke
 *  Modified for big endian by J.F. Chadima and David S. Miller
 *  Modified 1997 Peter Waltenberg, Bill Hawes, David Woodhouse for 2.1 dcache
 *  Modified 1999 Wolfram Pienkoss for NLS
 *  Modified 2000 Ben Harris, University of Cambridge for NFS NS meta-info
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include "ncp_fs.h"

static inline void assert_server_locked(struct ncp_server *server)
{
	if (server->lock == 0) {
		ncp_dbg(1, "server not locked!\n");
	}
}

static void ncp_add_byte(struct ncp_server *server, __u8 x)
{
	assert_server_locked(server);
	*(__u8 *) (&(server->packet[server->current_size])) = x;
	server->current_size += 1;
	return;
}

static void ncp_add_word(struct ncp_server *server, __le16 x)
{
	assert_server_locked(server);
	put_unaligned(x, (__le16 *) (&(server->packet[server->current_size])));
	server->current_size += 2;
	return;
}

static void ncp_add_be16(struct ncp_server *server, __u16 x)
{
	assert_server_locked(server);
	put_unaligned(cpu_to_be16(x), (__be16 *) (&(server->packet[server->current_size])));
	server->current_size += 2;
}

static void ncp_add_dword(struct ncp_server *server, __le32 x)
{
	assert_server_locked(server);
	put_unaligned(x, (__le32 *) (&(server->packet[server->current_size])));
	server->current_size += 4;
	return;
}

static void ncp_add_be32(struct ncp_server *server, __u32 x)
{
	assert_server_locked(server);
	put_unaligned(cpu_to_be32(x), (__be32 *)(&(server->packet[server->current_size])));
	server->current_size += 4;
}

static inline void ncp_add_dword_lh(struct ncp_server *server, __u32 x) {
	ncp_add_dword(server, cpu_to_le32(x));
}

static void ncp_add_mem(struct ncp_server *server, const void *source, int size)
{
	assert_server_locked(server);
	memcpy(&(server->packet[server->current_size]), source, size);
	server->current_size += size;
	return;
}

static void ncp_add_pstring(struct ncp_server *server, const char *s)
{
	int len = strlen(s);
	assert_server_locked(server);
	if (len > 255) {
		ncp_dbg(1, "string too long: %s\n", s);
		len = 255;
	}
	ncp_add_byte(server, len);
	ncp_add_mem(server, s, len);
	return;
}

static inline void ncp_init_request(struct ncp_server *server)
{
	ncp_lock_server(server);

	server->current_size = sizeof(struct ncp_request_header);
	server->has_subfunction = 0;
}

static inline void ncp_init_request_s(struct ncp_server *server, int subfunction)
{
	ncp_lock_server(server);
	
	server->current_size = sizeof(struct ncp_request_header) + 2;
	ncp_add_byte(server, subfunction);

	server->has_subfunction = 1;
}

static inline char *
ncp_reply_data(struct ncp_server *server, int offset)
{
	return &(server->packet[sizeof(struct ncp_reply_header) + offset]);
}

static inline u8 BVAL(const void *data)
{
	return *(const u8 *)data;
}

static u8 ncp_reply_byte(struct ncp_server *server, int offset)
{
	return *(const u8 *)ncp_reply_data(server, offset);
}

static inline u16 WVAL_LH(const void *data)
{
	return get_unaligned_le16(data);
}

static u16
ncp_reply_le16(struct ncp_server *server, int offset)
{
	return get_unaligned_le16(ncp_reply_data(server, offset));
}

static u16
ncp_reply_be16(struct ncp_server *server, int offset)
{
	return get_unaligned_be16(ncp_reply_data(server, offset));
}

static inline u32 DVAL_LH(const void *data)
{
	return get_unaligned_le32(data);
}

static __le32
ncp_reply_dword(struct ncp_server *server, int offset)
{
	return get_unaligned((__le32 *)ncp_reply_data(server, offset));
}

static inline __u32 ncp_reply_dword_lh(struct ncp_server* server, int offset) {
	return le32_to_cpu(ncp_reply_dword(server, offset));
}

int
ncp_negotiate_buffersize(struct ncp_server *server, int size, int *target)
{
	int result;

	ncp_init_request(server);
	ncp_add_be16(server, size);

	if ((result = ncp_request(server, 33)) != 0) {
		ncp_unlock_server(server);
		return result;
	}
	*target = min_t(unsigned int, ncp_reply_be16(server, 0), size);

	ncp_unlock_server(server);
	return 0;
}


/* options: 
 *	bit 0	ipx checksum
 *	bit 1	packet signing
 */
int
ncp_negotiate_size_and_options(struct ncp_server *server, 
	int size, int options, int *ret_size, int *ret_options) {
	int result;

	/* there is minimum */
	if (size < NCP_BLOCK_SIZE) size = NCP_BLOCK_SIZE;

	ncp_init_request(server);
	ncp_add_be16(server, size);
	ncp_add_byte(server, options);
	
	if ((result = ncp_request(server, 0x61)) != 0)
	{
		ncp_unlock_server(server);
		return result;
	}

	/* NCP over UDP returns 0 (!!!) */
	result = ncp_reply_be16(server, 0);
	if (result >= NCP_BLOCK_SIZE)
		size = min(result, size);
	*ret_size = size;
	*ret_options = ncp_reply_byte(server, 4);

	ncp_unlock_server(server);
	return 0;
}

int ncp_get_volume_info_with_number(struct ncp_server* server,
			     int n, struct ncp_volume_info* target) {
	int result;
	int len;

	ncp_init_request_s(server, 44);
	ncp_add_byte(server, n);

	if ((result = ncp_request(server, 22)) != 0) {
		goto out;
	}
	target->total_blocks = ncp_reply_dword_lh(server, 0);
	target->free_blocks = ncp_reply_dword_lh(server, 4);
	target->purgeable_blocks = ncp_reply_dword_lh(server, 8);
	target->not_yet_purgeable_blocks = ncp_reply_dword_lh(server, 12);
	target->total_dir_entries = ncp_reply_dword_lh(server, 16);
	target->available_dir_entries = ncp_reply_dword_lh(server, 20);
	target->sectors_per_block = ncp_reply_byte(server, 28);

	memset(&(target->volume_name), 0, sizeof(target->volume_name));

	result = -EIO;
	len = ncp_reply_byte(server, 29);
	if (len > NCP_VOLNAME_LEN) {
		ncp_dbg(1, "volume name too long: %d\n", len);
		goto out;
	}
	memcpy(&(target->volume_name), ncp_reply_data(server, 30), len);
	result = 0;
out:
	ncp_unlock_server(server);
	return result;
}

int ncp_get_directory_info(struct ncp_server* server, __u8 n, 
			   struct ncp_volume_info* target) {
	int result;
	int len;

	ncp_init_request_s(server, 45);
	ncp_add_byte(server, n);

	if ((result = ncp_request(server, 22)) != 0) {
		goto out;
	}
	target->total_blocks = ncp_reply_dword_lh(server, 0);
	target->free_blocks = ncp_reply_dword_lh(server, 4);
	target->purgeable_blocks = 0;
	target->not_yet_purgeable_blocks = 0;
	target->total_dir_entries = ncp_reply_dword_lh(server, 8);
	target->available_dir_entries = ncp_reply_dword_lh(server, 12);
	target->sectors_per_block = ncp_reply_byte(server, 20);

	memset(&(target->volume_name), 0, sizeof(target->volume_name));

	result = -EIO;
	len = ncp_reply_byte(server, 21);
	if (len > NCP_VOLNAME_LEN) {
		ncp_dbg(1, "volume name too long: %d\n", len);
		goto out;
	}
	memcpy(&(target->volume_name), ncp_reply_data(server, 22), len);
	result = 0;
out:
	ncp_unlock_server(server);
	return result;
}

int
ncp_close_file(struct ncp_server *server, const char *file_id)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 0);
	ncp_add_mem(server, file_id, 6);

	result = ncp_request(server, 66);
	ncp_unlock_server(server);
	return result;
}

int
ncp_make_closed(struct inode *inode)
{
	int err;

	err = 0;
	mutex_lock(&NCP_FINFO(inode)->open_mutex);
	if (atomic_read(&NCP_FINFO(inode)->opened) == 1) {
		atomic_set(&NCP_FINFO(inode)->opened, 0);
		err = ncp_close_file(NCP_SERVER(inode), NCP_FINFO(inode)->file_handle);

		if (!err)
			ncp_vdbg("volnum=%d, dirent=%u, error=%d\n",
				 NCP_FINFO(inode)->volNumber,
				 NCP_FINFO(inode)->dirEntNum, err);
	}
	mutex_unlock(&NCP_FINFO(inode)->open_mutex);
	return err;
}

static void ncp_add_handle_path(struct ncp_server *server, __u8 vol_num,
				__le32 dir_base, int have_dir_base, 
				const char *path)
{
	ncp_add_byte(server, vol_num);
	ncp_add_dword(server, dir_base);
	if (have_dir_base != 0) {
		ncp_add_byte(server, 1);	/* dir_base */
	} else {
		ncp_add_byte(server, 0xff);	/* no handle */
	}
	if (path != NULL) {
		ncp_add_byte(server, 1);	/* 1 component */
		ncp_add_pstring(server, path);
	} else {
		ncp_add_byte(server, 0);
	}
}

int ncp_dirhandle_alloc(struct ncp_server* server, __u8 volnum, __le32 dirent,
			__u8* dirhandle) {
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 12);		/* subfunction */
	ncp_add_byte(server, NW_NS_DOS);
	ncp_add_byte(server, 0);
	ncp_add_word(server, 0);
	ncp_add_handle_path(server, volnum, dirent, 1, NULL);
	if ((result = ncp_request(server, 87)) == 0) {
		*dirhandle = ncp_reply_byte(server, 0);
	}
	ncp_unlock_server(server);
	return result;
}

int ncp_dirhandle_free(struct ncp_server* server, __u8 dirhandle) {
	int result;
	
	ncp_init_request_s(server, 20);
	ncp_add_byte(server, dirhandle);
	result = ncp_request(server, 22);
	ncp_unlock_server(server);
	return result;
}

void ncp_extract_file_info(const void *structure, struct nw_info_struct *target)
{
	const __u8 *name_len;
	const int info_struct_size = offsetof(struct nw_info_struct, nameLen);

	memcpy(target, structure, info_struct_size);
	name_len = structure + info_struct_size;
	target->nameLen = *name_len;
	memcpy(target->entryName, name_len + 1, *name_len);
	target->entryName[*name_len] = '\0';
	target->volNumber = le32_to_cpu(target->volNumber);
	return;
}

#ifdef CONFIG_NCPFS_NFS_NS
static inline void ncp_extract_nfs_info(const unsigned char *structure,
				 struct nw_nfs_info *target)
{
	target->mode = DVAL_LH(structure);
	target->rdev = DVAL_LH(structure + 8);
}
#endif

int ncp_obtain_nfs_info(struct ncp_server *server,
		        struct nw_info_struct *target)

{
	int result = 0;
#ifdef CONFIG_NCPFS_NFS_NS
	__u32 volnum = target->volNumber;

	if (ncp_is_nfs_extras(server, volnum)) {
		ncp_init_request(server);
		ncp_add_byte(server, 19);	/* subfunction */
		ncp_add_byte(server, server->name_space[volnum]);
		ncp_add_byte(server, NW_NS_NFS);
		ncp_add_byte(server, 0);
		ncp_add_byte(server, volnum);
		ncp_add_dword(server, target->dirEntNum);
		/* We must retrieve both nlinks and rdev, otherwise some server versions
		   report zeroes instead of valid data */
		ncp_add_dword_lh(server, NSIBM_NFS_MODE | NSIBM_NFS_NLINKS | NSIBM_NFS_RDEV);

		if ((result = ncp_request(server, 87)) == 0) {
			ncp_extract_nfs_info(ncp_reply_data(server, 0), &target->nfs);
			ncp_dbg(1, "(%s) mode=0%o, rdev=0x%x\n",
				target->entryName, target->nfs.mode,
				target->nfs.rdev);
		} else {
			target->nfs.mode = 0;
			target->nfs.rdev = 0;
		}
	        ncp_unlock_server(server);

	} else
#endif
	{
		target->nfs.mode = 0;
		target->nfs.rdev = 0;
	}
	return result;
}

/*
 * Returns information for a (one-component) name relative to
 * the specified directory.
 */
int ncp_obtain_info(struct ncp_server *server, struct inode *dir, const char *path,
			struct nw_info_struct *target)
{
	__u8  volnum = NCP_FINFO(dir)->volNumber;
	__le32 dirent = NCP_FINFO(dir)->dirEntNum;
	int result;

	if (target == NULL) {
		pr_err("%s: invalid call\n", __func__);
		return -EINVAL;
	}
	ncp_init_request(server);
	ncp_add_byte(server, 6);	/* subfunction */
	ncp_add_byte(server, server->name_space[volnum]);
	ncp_add_byte(server, server->name_space[volnum]); /* N.B. twice ?? */
	ncp_add_word(server, cpu_to_le16(0x8006));	/* get all */
	ncp_add_dword(server, RIM_ALL);
	ncp_add_handle_path(server, volnum, dirent, 1, path);

	if ((result = ncp_request(server, 87)) != 0)
		goto out;
	ncp_extract_file_info(ncp_reply_data(server, 0), target);
	ncp_unlock_server(server);
	
	result = ncp_obtain_nfs_info(server, target);
	return result;

out:
	ncp_unlock_server(server);
	return result;
}

#ifdef CONFIG_NCPFS_NFS_NS
static int
ncp_obtain_DOS_dir_base(struct ncp_server *server,
		__u8 ns, __u8 volnum, __le32 dirent,
		const char *path, /* At most 1 component */
		__le32 *DOS_dir_base)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 6); /* subfunction */
	ncp_add_byte(server, ns);
	ncp_add_byte(server, ns);
	ncp_add_word(server, cpu_to_le16(0x8006)); /* get all */
	ncp_add_dword(server, RIM_DIRECTORY);
	ncp_add_handle_path(server, volnum, dirent, 1, path);

	if ((result = ncp_request(server, 87)) == 0)
	{
	   	if (DOS_dir_base) *DOS_dir_base=ncp_reply_dword(server, 0x34);
	}
	ncp_unlock_server(server);
	return result;
}
#endif /* CONFIG_NCPFS_NFS_NS */

static inline int
ncp_get_known_namespace(struct ncp_server *server, __u8 volume)
{
#if defined(CONFIG_NCPFS_OS2_NS) || defined(CONFIG_NCPFS_NFS_NS)
	int result;
	__u8 *namespace;
	__u16 no_namespaces;

	ncp_init_request(server);
	ncp_add_byte(server, 24);	/* Subfunction: Get Name Spaces Loaded */
	ncp_add_word(server, 0);
	ncp_add_byte(server, volume);

	if ((result = ncp_request(server, 87)) != 0) {
		ncp_unlock_server(server);
		return NW_NS_DOS; /* not result ?? */
	}

	result = NW_NS_DOS;
	no_namespaces = ncp_reply_le16(server, 0);
	namespace = ncp_reply_data(server, 2);

	while (no_namespaces > 0) {
		ncp_dbg(1, "found %d on %d\n", *namespace, volume);

#ifdef CONFIG_NCPFS_NFS_NS
		if ((*namespace == NW_NS_NFS) && !(server->m.flags&NCP_MOUNT_NO_NFS)) 
		{
			result = NW_NS_NFS;
			break;
		}
#endif	/* CONFIG_NCPFS_NFS_NS */
#ifdef CONFIG_NCPFS_OS2_NS
		if ((*namespace == NW_NS_OS2) && !(server->m.flags&NCP_MOUNT_NO_OS2))
		{
			result = NW_NS_OS2;
		}
#endif	/* CONFIG_NCPFS_OS2_NS */
		namespace += 1;
		no_namespaces -= 1;
	}
	ncp_unlock_server(server);
	return result;
#else	/* neither OS2 nor NFS - only DOS */
	return NW_NS_DOS;
#endif	/* defined(CONFIG_NCPFS_OS2_NS) || defined(CONFIG_NCPFS_NFS_NS) */
}

int
ncp_update_known_namespace(struct ncp_server *server, __u8 volume, int *ret_ns)
{
	int ns = ncp_get_known_namespace(server, volume);

	if (ret_ns)
		*ret_ns = ns;

	ncp_dbg(1, "namespace[%d] = %d\n", volume, server->name_space[volume]);

	if (server->name_space[volume] == ns)
		return 0;
	server->name_space[volume] = ns;
	return 1;
}

static int
ncp_ObtainSpecificDirBase(struct ncp_server *server,
		__u8 nsSrc, __u8 nsDst, __u8 vol_num, __le32 dir_base,
		const char *path, /* At most 1 component */
		__le32 *dirEntNum, __le32 *DosDirNum)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 6); /* subfunction */
	ncp_add_byte(server, nsSrc);
	ncp_add_byte(server, nsDst);
	ncp_add_word(server, cpu_to_le16(0x8006)); /* get all */
	ncp_add_dword(server, RIM_ALL);
	ncp_add_handle_path(server, vol_num, dir_base, 1, path);

	if ((result = ncp_request(server, 87)) != 0)
	{
		ncp_unlock_server(server);
		return result;
	}

	if (dirEntNum)
		*dirEntNum = ncp_reply_dword(server, 0x30);
	if (DosDirNum)
		*DosDirNum = ncp_reply_dword(server, 0x34);
	ncp_unlock_server(server);
	return 0;
}

int
ncp_mount_subdir(struct ncp_server *server,
		 __u8 volNumber, __u8 srcNS, __le32 dirEntNum,
		 __u32* volume, __le32* newDirEnt, __le32* newDosEnt)
{
	int dstNS;
	int result;

	ncp_update_known_namespace(server, volNumber, &dstNS);
	if ((result = ncp_ObtainSpecificDirBase(server, srcNS, dstNS, volNumber, 
				      dirEntNum, NULL, newDirEnt, newDosEnt)) != 0)
	{
		return result;
	}
	*volume = volNumber;
	server->m.mounted_vol[1] = 0;
	server->m.mounted_vol[0] = 'X';
	return 0;
}

int 
ncp_get_volume_root(struct ncp_server *server,
		    const char *volname, __u32* volume, __le32* dirent, __le32* dosdirent)
{
	int result;

	ncp_dbg(1, "looking up vol %s\n", volname);

	ncp_init_request(server);
	ncp_add_byte(server, 22);	/* Subfunction: Generate dir handle */
	ncp_add_byte(server, 0);	/* DOS namespace */
	ncp_add_byte(server, 0);	/* reserved */
	ncp_add_byte(server, 0);	/* reserved */
	ncp_add_byte(server, 0);	/* reserved */

	ncp_add_byte(server, 0);	/* faked volume number */
	ncp_add_dword(server, 0);	/* faked dir_base */
	ncp_add_byte(server, 0xff);	/* Don't have a dir_base */
	ncp_add_byte(server, 1);	/* 1 path component */
	ncp_add_pstring(server, volname);

	if ((result = ncp_request(server, 87)) != 0) {
		ncp_unlock_server(server);
		return result;
	}
	*dirent = *dosdirent = ncp_reply_dword(server, 4);
	*volume = ncp_reply_byte(server, 8);
	ncp_unlock_server(server);
	return 0;
}

int
ncp_lookup_volume(struct ncp_server *server,
		  const char *volname, struct nw_info_struct *target)
{
	int result;

	memset(target, 0, sizeof(*target));
	result = ncp_get_volume_root(server, volname,
			&target->volNumber, &target->dirEntNum, &target->DosDirNum);
	if (result) {
		return result;
	}
	ncp_update_known_namespace(server, target->volNumber, NULL);
	target->nameLen = strlen(volname);
	memcpy(target->entryName, volname, target->nameLen+1);
	target->attributes = aDIR;
	/* set dates to Jan 1, 1986  00:00 */
	target->creationTime = target->modifyTime = cpu_to_le16(0x0000);
	target->creationDate = target->modifyDate = target->lastAccessDate = cpu_to_le16(0x0C21);
	target->nfs.mode = 0;
	return 0;
}

int ncp_modify_file_or_subdir_dos_info_path(struct ncp_server *server,
					    struct inode *dir,
					    const char *path,
					    __le32 info_mask,
					    const struct nw_modify_dos_info *info)
{
	__u8  volnum = NCP_FINFO(dir)->volNumber;
	__le32 dirent = NCP_FINFO(dir)->dirEntNum;
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 7);	/* subfunction */
	ncp_add_byte(server, server->name_space[volnum]);
	ncp_add_byte(server, 0);	/* reserved */
	ncp_add_word(server, cpu_to_le16(0x8006));	/* search attribs: all */

	ncp_add_dword(server, info_mask);
	ncp_add_mem(server, info, sizeof(*info));
	ncp_add_handle_path(server, volnum, dirent, 1, path);

	result = ncp_request(server, 87);
	ncp_unlock_server(server);
	return result;
}

int ncp_modify_file_or_subdir_dos_info(struct ncp_server *server,
				       struct inode *dir,
				       __le32 info_mask,
				       const struct nw_modify_dos_info *info)
{
	return ncp_modify_file_or_subdir_dos_info_path(server, dir, NULL,
		info_mask, info);
}

#ifdef CONFIG_NCPFS_NFS_NS
int ncp_modify_nfs_info(struct ncp_server *server, __u8 volnum, __le32 dirent,
			       __u32 mode, __u32 rdev)

{
	int result = 0;

	ncp_init_request(server);
	if (server->name_space[volnum] == NW_NS_NFS) {
		ncp_add_byte(server, 25);	/* subfunction */
		ncp_add_byte(server, server->name_space[volnum]);
		ncp_add_byte(server, NW_NS_NFS);
		ncp_add_byte(server, volnum);
		ncp_add_dword(server, dirent);
		/* we must always operate on both nlinks and rdev, otherwise
		   rdev is not set */
		ncp_add_dword_lh(server, NSIBM_NFS_MODE | NSIBM_NFS_NLINKS | NSIBM_NFS_RDEV);
		ncp_add_dword_lh(server, mode);
		ncp_add_dword_lh(server, 1);	/* nlinks */
		ncp_add_dword_lh(server, rdev);
		result = ncp_request(server, 87);
	}
	ncp_unlock_server(server);
	return result;
}
#endif


static int
ncp_DeleteNSEntry(struct ncp_server *server,
		  __u8 have_dir_base, __u8 volnum, __le32 dirent,
		  const char* name, __u8 ns, __le16 attr)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 8);	/* subfunction */
	ncp_add_byte(server, ns);
	ncp_add_byte(server, 0);	/* reserved */
	ncp_add_word(server, attr);	/* search attribs: all */
	ncp_add_handle_path(server, volnum, dirent, have_dir_base, name);

	result = ncp_request(server, 87);
	ncp_unlock_server(server);
	return result;
}

int
ncp_del_file_or_subdir2(struct ncp_server *server,
			struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	__u8  volnum;
	__le32 dirent;

	if (!inode) {
		return 0xFF;	/* Any error */
	}
	volnum = NCP_FINFO(inode)->volNumber;
	dirent = NCP_FINFO(inode)->DosDirNum;
	return ncp_DeleteNSEntry(server, 1, volnum, dirent, NULL, NW_NS_DOS, cpu_to_le16(0x8006));
}

int
ncp_del_file_or_subdir(struct ncp_server *server,
		       struct inode *dir, const char *name)
{
	__u8  volnum = NCP_FINFO(dir)->volNumber;
	__le32 dirent = NCP_FINFO(dir)->dirEntNum;
	int name_space;

	name_space = server->name_space[volnum];
#ifdef CONFIG_NCPFS_NFS_NS
	if (name_space == NW_NS_NFS)
 	{
 		int result;
 
		result=ncp_obtain_DOS_dir_base(server, name_space, volnum, dirent, name, &dirent);
 		if (result) return result;
		name = NULL;
		name_space = NW_NS_DOS;
 	}
#endif	/* CONFIG_NCPFS_NFS_NS */
	return ncp_DeleteNSEntry(server, 1, volnum, dirent, name, name_space, cpu_to_le16(0x8006));
}

static inline void ConvertToNWfromDWORD(__u16 v0, __u16 v1, __u8 ret[6])
{
	__le16 *dest = (__le16 *) ret;
	dest[1] = cpu_to_le16(v0);
	dest[2] = cpu_to_le16(v1);
	dest[0] = cpu_to_le16(v0 + 1);
	return;
}

/* If both dir and name are NULL, then in target there's already a
   looked-up entry that wants to be opened. */
int ncp_open_create_file_or_subdir(struct ncp_server *server,
				   struct inode *dir, const char *name,
				   int open_create_mode,
				   __le32 create_attributes,
				   __le16 desired_acc_rights,
				   struct ncp_entry_info *target)
{
	__le16 search_attribs = cpu_to_le16(0x0006);
	__u8  volnum;
	__le32 dirent;
	int result;

	volnum = NCP_FINFO(dir)->volNumber;
	dirent = NCP_FINFO(dir)->dirEntNum;

	if ((create_attributes & aDIR) != 0) {
		search_attribs |= cpu_to_le16(0x8000);
	}
	ncp_init_request(server);
	ncp_add_byte(server, 1);	/* subfunction */
	ncp_add_byte(server, server->name_space[volnum]);
	ncp_add_byte(server, open_create_mode);
	ncp_add_word(server, search_attribs);
	ncp_add_dword(server, RIM_ALL);
	ncp_add_dword(server, create_attributes);
	/* The desired acc rights seem to be the inherited rights mask
	   for directories */
	ncp_add_word(server, desired_acc_rights);
	ncp_add_handle_path(server, volnum, dirent, 1, name);

	if ((result = ncp_request(server, 87)) != 0)
		goto out;
	if (!(create_attributes & aDIR))
		target->opened = 1;

	/* in target there's a new finfo to fill */
	ncp_extract_file_info(ncp_reply_data(server, 6), &(target->i));
	target->volume = target->i.volNumber;
	ConvertToNWfromDWORD(ncp_reply_le16(server, 0),
			     ncp_reply_le16(server, 2),
			     target->file_handle);
	
	ncp_unlock_server(server);

	(void)ncp_obtain_nfs_info(server, &(target->i));
	return 0;

out:
	ncp_unlock_server(server);
	return result;
}

int
ncp_initialize_search(struct ncp_server *server, struct inode *dir,
			struct nw_search_sequence *target)
{
	__u8  volnum = NCP_FINFO(dir)->volNumber;
	__le32 dirent = NCP_FINFO(dir)->dirEntNum;
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 2);	/* subfunction */
	ncp_add_byte(server, server->name_space[volnum]);
	ncp_add_byte(server, 0);	/* reserved */
	ncp_add_handle_path(server, volnum, dirent, 1, NULL);

	result = ncp_request(server, 87);
	if (result)
		goto out;
	memcpy(target, ncp_reply_data(server, 0), sizeof(*target));

out:
	ncp_unlock_server(server);
	return result;
}

int ncp_search_for_fileset(struct ncp_server *server,
			   struct nw_search_sequence *seq,
			   int* more,
			   int* cnt,
			   char* buffer,
			   size_t bufsize,
			   char** rbuf,
			   size_t* rsize)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 20);
	ncp_add_byte(server, server->name_space[seq->volNumber]);
	ncp_add_byte(server, 0);		/* datastream */
	ncp_add_word(server, cpu_to_le16(0x8006));
	ncp_add_dword(server, RIM_ALL);
	ncp_add_word(server, cpu_to_le16(32767));	/* max returned items */
	ncp_add_mem(server, seq, 9);
#ifdef CONFIG_NCPFS_NFS_NS
	if (server->name_space[seq->volNumber] == NW_NS_NFS) {
		ncp_add_byte(server, 0);	/* 0 byte pattern */
	} else 
#endif
	{
		ncp_add_byte(server, 2);	/* 2 byte pattern */
		ncp_add_byte(server, 0xff);	/* following is a wildcard */
		ncp_add_byte(server, '*');
	}
	result = ncp_request2(server, 87, buffer, bufsize);
	if (result) {
		ncp_unlock_server(server);
		return result;
	}
	if (server->ncp_reply_size < 12) {
		ncp_unlock_server(server);
		return 0xFF;
	}
	*rsize = server->ncp_reply_size - 12;
	ncp_unlock_server(server);
	buffer = buffer + sizeof(struct ncp_reply_header);
	*rbuf = buffer + 12;
	*cnt = WVAL_LH(buffer + 10);
	*more = BVAL(buffer + 9);
	memcpy(seq, buffer, 9);
	return 0;
}

static int
ncp_RenameNSEntry(struct ncp_server *server,
		  struct inode *old_dir, const char *old_name, __le16 old_type,
		  struct inode *new_dir, const char *new_name)
{
	int result = -EINVAL;

	if ((old_dir == NULL) || (old_name == NULL) ||
	    (new_dir == NULL) || (new_name == NULL))
		goto out;

	ncp_init_request(server);
	ncp_add_byte(server, 4);	/* subfunction */
	ncp_add_byte(server, server->name_space[NCP_FINFO(old_dir)->volNumber]);
	ncp_add_byte(server, 1);	/* rename flag */
	ncp_add_word(server, old_type);	/* search attributes */

	/* source Handle Path */
	ncp_add_byte(server, NCP_FINFO(old_dir)->volNumber);
	ncp_add_dword(server, NCP_FINFO(old_dir)->dirEntNum);
	ncp_add_byte(server, 1);
	ncp_add_byte(server, 1);	/* 1 source component */

	/* dest Handle Path */
	ncp_add_byte(server, NCP_FINFO(new_dir)->volNumber);
	ncp_add_dword(server, NCP_FINFO(new_dir)->dirEntNum);
	ncp_add_byte(server, 1);
	ncp_add_byte(server, 1);	/* 1 destination component */

	/* source path string */
	ncp_add_pstring(server, old_name);
	/* dest path string */
	ncp_add_pstring(server, new_name);

	result = ncp_request(server, 87);
	ncp_unlock_server(server);
out:
	return result;
}

int ncp_ren_or_mov_file_or_subdir(struct ncp_server *server,
				struct inode *old_dir, const char *old_name,
				struct inode *new_dir, const char *new_name)
{
        int result;
        __le16 old_type = cpu_to_le16(0x06);

/* If somebody can do it atomic, call me... vandrove@vc.cvut.cz */
	result = ncp_RenameNSEntry(server, old_dir, old_name, old_type,
	                                   new_dir, new_name);
        if (result == 0xFF)	/* File Not Found, try directory */
	{
		old_type = cpu_to_le16(0x16);
		result = ncp_RenameNSEntry(server, old_dir, old_name, old_type,
						   new_dir, new_name);
	}
	if (result != 0x92) return result;	/* All except NO_FILES_RENAMED */
	result = ncp_del_file_or_subdir(server, new_dir, new_name);
	if (result != 0) return -EACCES;
	result = ncp_RenameNSEntry(server, old_dir, old_name, old_type,
					   new_dir, new_name);
	return result;
}
	

/* We have to transfer to/from user space */
int
ncp_read_kernel(struct ncp_server *server, const char *file_id,
	     __u32 offset, __u16 to_read, char *target, int *bytes_read)
{
	const char *source;
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 0);
	ncp_add_mem(server, file_id, 6);
	ncp_add_be32(server, offset);
	ncp_add_be16(server, to_read);

	if ((result = ncp_request(server, 72)) != 0) {
		goto out;
	}
	*bytes_read = ncp_reply_be16(server, 0);
	source = ncp_reply_data(server, 2 + (offset & 1));

	memcpy(target, source, *bytes_read);
out:
	ncp_unlock_server(server);
	return result;
}

/* There is a problem... egrep and some other silly tools do:
	x = mmap(NULL, MAP_PRIVATE, PROT_READ|PROT_WRITE, <ncpfs fd>, 32768);
	read(<ncpfs fd>, x, 32768);
   Now copying read result by copy_to_user causes pagefault. This pagefault
   could not be handled because of server was locked due to read. So we have
   to use temporary buffer. So ncp_unlock_server must be done before
   copy_to_user (and for write, copy_from_user must be done before 
   ncp_init_request... same applies for send raw packet ioctl). Because of
   file is normally read in bigger chunks, caller provides kmalloced 
   (vmalloced) chunk of memory with size >= to_read...
 */
int
ncp_read_bounce(struct ncp_server *server, const char *file_id,
	 __u32 offset, __u16 to_read, char __user *target, int *bytes_read,
	 void* bounce, __u32 bufsize)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 0);
	ncp_add_mem(server, file_id, 6);
	ncp_add_be32(server, offset);
	ncp_add_be16(server, to_read);
	result = ncp_request2(server, 72, bounce, bufsize);
	ncp_unlock_server(server);
	if (!result) {
		int len = get_unaligned_be16((char *)bounce +
			  sizeof(struct ncp_reply_header));
		result = -EIO;
		if (len <= to_read) {
			char* source;

			source = (char*)bounce + 
			         sizeof(struct ncp_reply_header) + 2 + 
			         (offset & 1);
			*bytes_read = len;
			result = 0;
			if (copy_to_user(target, source, len))
				result = -EFAULT;
		}
	}
	return result;
}

int
ncp_write_kernel(struct ncp_server *server, const char *file_id,
		 __u32 offset, __u16 to_write,
		 const char *source, int *bytes_written)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 0);
	ncp_add_mem(server, file_id, 6);
	ncp_add_be32(server, offset);
	ncp_add_be16(server, to_write);
	ncp_add_mem(server, source, to_write);
	
	if ((result = ncp_request(server, 73)) == 0)
		*bytes_written = to_write;
	ncp_unlock_server(server);
	return result;
}

#ifdef CONFIG_NCPFS_IOCTL_LOCKING
int
ncp_LogPhysicalRecord(struct ncp_server *server, const char *file_id,
	  __u8 locktype, __u32 offset, __u32 length, __u16 timeout)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, locktype);
	ncp_add_mem(server, file_id, 6);
	ncp_add_be32(server, offset);
	ncp_add_be32(server, length);
	ncp_add_be16(server, timeout);

	if ((result = ncp_request(server, 0x1A)) != 0)
	{
		ncp_unlock_server(server);
		return result;
	}
	ncp_unlock_server(server);
	return 0;
}

int
ncp_ClearPhysicalRecord(struct ncp_server *server, const char *file_id,
	  __u32 offset, __u32 length)
{
	int result;

	ncp_init_request(server);
	ncp_add_byte(server, 0);	/* who knows... lanalyzer says that */
	ncp_add_mem(server, file_id, 6);
	ncp_add_be32(server, offset);
	ncp_add_be32(server, length);

	if ((result = ncp_request(server, 0x1E)) != 0)
	{
		ncp_unlock_server(server);
		return result;
	}
	ncp_unlock_server(server);
	return 0;
}
#endif	/* CONFIG_NCPFS_IOCTL_LOCKING */

#ifdef CONFIG_NCPFS_NLS
/* This are the NLS conversion routines with inspirations and code parts
 * from the vfat file system and hints from Petr Vandrovec.
 */

int
ncp__io2vol(struct ncp_server *server, unsigned char *vname, unsigned int *vlen,
		const unsigned char *iname, unsigned int ilen, int cc)
{
	struct nls_table *in = server->nls_io;
	struct nls_table *out = server->nls_vol;
	unsigned char *vname_start;
	unsigned char *vname_end;
	const unsigned char *iname_end;

	iname_end = iname + ilen;
	vname_start = vname;
	vname_end = vname + *vlen - 1;

	while (iname < iname_end) {
		int chl;
		wchar_t ec;

		if (NCP_IS_FLAG(server, NCP_FLAG_UTF8)) {
			int k;
			unicode_t u;

			k = utf8_to_utf32(iname, iname_end - iname, &u);
			if (k < 0 || u > MAX_WCHAR_T)
				return -EINVAL;
			iname += k;
			ec = u;
		} else {
			if (*iname == NCP_ESC) {
				int k;

				if (iname_end - iname < 5)
					goto nospec;

				ec = 0;
				for (k = 1; k < 5; k++) {
					unsigned char nc;

					nc = iname[k] - '0';
					if (nc >= 10) {
						nc -= 'A' - '0' - 10;
						if ((nc < 10) || (nc > 15)) {
							goto nospec;
						}
					}
					ec = (ec << 4) | nc;
				}
				iname += 5;
			} else {
nospec:;			
				if ( (chl = in->char2uni(iname, iname_end - iname, &ec)) < 0)
					return chl;
				iname += chl;
			}
		}

		/* unitoupper should be here! */

		chl = out->uni2char(ec, vname, vname_end - vname);
		if (chl < 0)
			return chl;

		/* this is wrong... */
		if (cc) {
			int chi;

			for (chi = 0; chi < chl; chi++){
				vname[chi] = ncp_toupper(out, vname[chi]);
			}
		}
		vname += chl;
	}

	*vname = 0;
	*vlen = vname - vname_start;
	return 0;
}

int
ncp__vol2io(struct ncp_server *server, unsigned char *iname, unsigned int *ilen,
		const unsigned char *vname, unsigned int vlen, int cc)
{
	struct nls_table *in = server->nls_vol;
	struct nls_table *out = server->nls_io;
	const unsigned char *vname_end;
	unsigned char *iname_start;
	unsigned char *iname_end;
	unsigned char *vname_cc;
	int err;

	vname_cc = NULL;

	if (cc) {
		int i;

		/* this is wrong! */
		vname_cc = kmalloc(vlen, GFP_KERNEL);
		if (!vname_cc)
			return -ENOMEM;
		for (i = 0; i < vlen; i++)
			vname_cc[i] = ncp_tolower(in, vname[i]);
		vname = vname_cc;
	}

	iname_start = iname;
	iname_end = iname + *ilen - 1;
	vname_end = vname + vlen;

	while (vname < vname_end) {
		wchar_t ec;
		int chl;

		if ( (chl = in->char2uni(vname, vname_end - vname, &ec)) < 0) {
			err = chl;
			goto quit;
		}
		vname += chl;

		/* unitolower should be here! */

		if (NCP_IS_FLAG(server, NCP_FLAG_UTF8)) {
			int k;

			k = utf32_to_utf8(ec, iname, iname_end - iname);
			if (k < 0) {
				err = -ENAMETOOLONG;
				goto quit;
			}
			iname += k;
		} else {
			if ( (chl = out->uni2char(ec, iname, iname_end - iname)) >= 0) {
				iname += chl;
			} else {
				int k;

				if (iname_end - iname < 5) {
					err = -ENAMETOOLONG;
					goto quit;
				}
				*iname = NCP_ESC;
				for (k = 4; k > 0; k--) {
					unsigned char v;
					
					v = (ec & 0xF) + '0';
					if (v > '9') {
						v += 'A' - '9' - 1;
					}
					iname[k] = v;
					ec >>= 4;
				}
				iname += 5;
			}
		}
	}

	*iname = 0;
	*ilen = iname - iname_start;
	err = 0;
quit:;
	if (cc)
		kfree(vname_cc);
	return err;
}

#else

int
ncp__io2vol(unsigned char *vname, unsigned int *vlen,
		const unsigned char *iname, unsigned int ilen, int cc)
{
	int i;

	if (*vlen <= ilen)
		return -ENAMETOOLONG;

	if (cc)
		for (i = 0; i < ilen; i++) {
			*vname = toupper(*iname);
			vname++;
			iname++;
		}
	else {
		memmove(vname, iname, ilen);
		vname += ilen;
	}

	*vlen = ilen;
	*vname = 0;
	return 0;
}

int
ncp__vol2io(unsigned char *iname, unsigned int *ilen,
		const unsigned char *vname, unsigned int vlen, int cc)
{
	int i;

	if (*ilen <= vlen)
		return -ENAMETOOLONG;

	if (cc)
		for (i = 0; i < vlen; i++) {
			*iname = tolower(*vname);
			iname++;
			vname++;
		}
	else {
		memmove(iname, vname, vlen);
		iname += vlen;
	}

	*ilen = vlen;
	*iname = 0;
	return 0;
}

#endif
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/ncplib_kernel.c */
/************************************************************/
/*
 *  linux/fs/ncpfs/sock.c
 *
 *  Copyright (C) 1992, 1993  Rick Sladkey
 *
 *  Modified 1995, 1996 by Volker Lendecke to be usable for ncp
 *  Modified 1997 Peter Waltenberg, Bill Hawes, David Woodhouse for 2.1 dcache
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/time.h>
// #include <linux/errno.h>
#include <linux/socket.h>
// #include <linux/fcntl.h>
// #include <linux/stat.h>
// #include <linux/string.h>
// #include <asm/uaccess.h>
#include <linux/in.h>
#include <linux/net.h>
// #include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/signal.h>
// #include <linux/slab.h>
#include <net/scm.h>
// #include <net/sock.h>
#include <linux/ipx.h>
#include <linux/poll.h>
// #include <linux/file.h>
#include "../../inc/__fss.h"

// #include "ncp_fs.h"

#include "ncpsign_kernel.h"
#include "../../inc/__fss.h"

static int _recv(struct socket *sock, void *buf, int size, unsigned flags)
{
	struct msghdr msg = {NULL, };
	struct kvec iov = {buf, size};
	return kernel_recvmsg(sock, &msg, &iov, 1, size, flags);
}

static inline int do_send(struct socket *sock, struct kvec *vec, int count,
			  int len, unsigned flags)
{
	struct msghdr msg = { .msg_flags = flags };
	return kernel_sendmsg(sock, &msg, vec, count, len);
}

static int _send(struct socket *sock, const void *buff, int len)
{
	struct kvec vec;
	vec.iov_base = (void *) buff;
	vec.iov_len = len;
	return do_send(sock, &vec, 1, len, 0);
}

struct ncp_request_reply {
	struct list_head req;
	wait_queue_head_t wq;
	atomic_t refs;
	unsigned char* reply_buf;
	size_t datalen;
	int result;
	enum { RQ_DONE, RQ_INPROGRESS, RQ_QUEUED, RQ_IDLE, RQ_ABANDONED } status;
	struct kvec* tx_ciov;
	size_t tx_totallen;
	size_t tx_iovlen;
	struct kvec tx_iov[3];
	u_int16_t tx_type;
	u_int32_t sign[6];
};

static inline struct ncp_request_reply* ncp_alloc_req(void)
{
	struct ncp_request_reply *req;

	req = kmalloc(sizeof(struct ncp_request_reply), GFP_KERNEL);
	if (!req)
		return NULL;

	init_waitqueue_head(&req->wq);
	atomic_set(&req->refs, (1));
	req->status = RQ_IDLE;

	return req;
}

static void ncp_req_get(struct ncp_request_reply *req)
{
	atomic_inc(&req->refs);
}

static void ncp_req_put(struct ncp_request_reply *req)
{
	if (atomic_dec_and_test(&req->refs))
		kfree(req);
}

void ncp_tcp_data_ready(struct sock *sk)
{
	struct ncp_server *server = sk->sk_user_data;

	server->data_ready(sk);
	schedule_work(&server->rcv.tq);
}

void ncp_tcp_error_report(struct sock *sk)
{
	struct ncp_server *server = sk->sk_user_data;
	
	server->error_report(sk);
	schedule_work(&server->rcv.tq);
}

void ncp_tcp_write_space(struct sock *sk)
{
	struct ncp_server *server = sk->sk_user_data;
	
	/* We do not need any locking: we first set tx.creq, and then we do sendmsg,
	   not vice versa... */
	server->write_space(sk);
	if (server->tx.creq)
		schedule_work(&server->tx.tq);
}

void ncpdgram_timeout_call(unsigned long v)
{
	struct ncp_server *server = (void*)v;
	
	schedule_work(&server->timeout_tq);
}

static inline void ncp_finish_request(struct ncp_server *server, struct ncp_request_reply *req, int result)
{
	req->result = result;
	if (req->status != RQ_ABANDONED)
		memcpy(req->reply_buf, server->rxbuf, req->datalen);
	req->status = RQ_DONE;
	wake_up_all(&req->wq);
	ncp_req_put(req);
}

static void __abort_ncp_connection(struct ncp_server *server)
{
	struct ncp_request_reply *req;

	ncp_invalidate_conn(server);
	del_timer(&server->timeout_tm);
	while (!list_empty(&server->tx.requests)) {
		req = list_entry(server->tx.requests.next, struct ncp_request_reply, req);
		
		list_del_init(&req->req);
		ncp_finish_request(server, req, -EIO);
	}
	req = server->rcv.creq;
	if (req) {
		server->rcv.creq = NULL;
		ncp_finish_request(server, req, -EIO);
		server->rcv.ptr = NULL;
		server->rcv.state = 0;
	}
	req = server->tx.creq;
	if (req) {
		server->tx.creq = NULL;
		ncp_finish_request(server, req, -EIO);
	}
}

static inline int get_conn_number(struct ncp_reply_header *rp)
{
	return rp->conn_low | (rp->conn_high << 8);
}

static inline void __ncp_abort_request(struct ncp_server *server, struct ncp_request_reply *req, int err)
{
	/* If req is done, we got signal, but we also received answer... */
	switch (req->status) {
		case RQ_IDLE:
		case RQ_DONE:
			break;
		case RQ_QUEUED:
			list_del_init(&req->req);
			ncp_finish_request(server, req, err);
			break;
		case RQ_INPROGRESS:
			req->status = RQ_ABANDONED;
			break;
		case RQ_ABANDONED:
			break;
	}
}

static inline void ncp_abort_request(struct ncp_server *server, struct ncp_request_reply *req, int err)
{
	mutex_lock(&server->rcv.creq_mutex);
	__ncp_abort_request(server, req, err);
	mutex_unlock(&server->rcv.creq_mutex);
}

static inline void __ncptcp_abort(struct ncp_server *server)
{
	__abort_ncp_connection(server);
}

static int ncpdgram_send(struct socket *sock, struct ncp_request_reply *req)
{
	struct kvec vec[3];
	/* sock_sendmsg updates iov pointers for us :-( */
	memcpy(vec, req->tx_ciov, req->tx_iovlen * sizeof(vec[0]));
	return do_send(sock, vec, req->tx_iovlen,
		       req->tx_totallen, MSG_DONTWAIT);
}

static void __ncptcp_try_send(struct ncp_server *server)
{
	struct ncp_request_reply *rq;
	struct kvec *iov;
	struct kvec iovc[3];
	int result;

	rq = server->tx.creq;
	if (!rq)
		return;

	/* sock_sendmsg updates iov pointers for us :-( */
	memcpy(iovc, rq->tx_ciov, rq->tx_iovlen * sizeof(iov[0]));
	result = do_send(server->ncp_sock, iovc, rq->tx_iovlen,
			 rq->tx_totallen, MSG_NOSIGNAL | MSG_DONTWAIT);

	if (result == -EAGAIN)
		return;

	if (result < 0) {
		pr_err("tcp: Send failed: %d\n", result);
		__ncp_abort_request(server, rq, result);
		return;
	}
	if (result >= rq->tx_totallen) {
		server->rcv.creq = rq;
		server->tx.creq = NULL;
		return;
	}
	rq->tx_totallen -= result;
	iov = rq->tx_ciov;
	while (iov->iov_len <= result) {
		result -= iov->iov_len;
		iov++;
		rq->tx_iovlen--;
	}
	iov->iov_base += result;
	iov->iov_len -= result;
	rq->tx_ciov = iov;
}

static inline void ncp_init_header(struct ncp_server *server, struct ncp_request_reply *req, struct ncp_request_header *h)
{
	req->status = RQ_INPROGRESS;
	h->conn_low = server->connection;
	h->conn_high = server->connection >> 8;
	h->sequence = ++server->sequence;
}
	
static void ncpdgram_start_request(struct ncp_server *server, struct ncp_request_reply *req)
{
	size_t signlen;
	struct ncp_request_header* h;
	
	req->tx_ciov = req->tx_iov + 1;

	h = req->tx_iov[1].iov_base;
	ncp_init_header(server, req, h);
	signlen = sign_packet(server, req->tx_iov[1].iov_base + sizeof(struct ncp_request_header) - 1, 
			req->tx_iov[1].iov_len - sizeof(struct ncp_request_header) + 1,
			cpu_to_le32(req->tx_totallen), req->sign);
	if (signlen) {
		req->tx_ciov[1].iov_base = req->sign;
		req->tx_ciov[1].iov_len = signlen;
		req->tx_iovlen += 1;
		req->tx_totallen += signlen;
	}
	server->rcv.creq = req;
	server->timeout_last = server->m.time_out;
	server->timeout_retries = server->m.retry_count;
	ncpdgram_send(server->ncp_sock, req);
	mod_timer(&server->timeout_tm, jiffies + server->m.time_out);
}

#define NCP_TCP_XMIT_MAGIC	(0x446D6454)
#define NCP_TCP_XMIT_VERSION	(1)
#define NCP_TCP_RCVD_MAGIC	(0x744E6350)

static void ncptcp_start_request(struct ncp_server *server, struct ncp_request_reply *req)
{
	size_t signlen;
	struct ncp_request_header* h;

	req->tx_ciov = req->tx_iov;
	h = req->tx_iov[1].iov_base;
	ncp_init_header(server, req, h);
	signlen = sign_packet(server, req->tx_iov[1].iov_base + sizeof(struct ncp_request_header) - 1,
			req->tx_iov[1].iov_len - sizeof(struct ncp_request_header) + 1,
			cpu_to_be32(req->tx_totallen + 24), req->sign + 4) + 16;

	req->sign[0] = htonl(NCP_TCP_XMIT_MAGIC);
	req->sign[1] = htonl(req->tx_totallen + signlen);
	req->sign[2] = htonl(NCP_TCP_XMIT_VERSION);
	req->sign[3] = htonl(req->datalen + 8);
	req->tx_iov[0].iov_base = req->sign;
	req->tx_iov[0].iov_len = signlen;
	req->tx_iovlen += 1;
	req->tx_totallen += signlen;

	server->tx.creq = req;
	__ncptcp_try_send(server);
}

static inline void __ncp_start_request(struct ncp_server *server, struct ncp_request_reply *req)
{
	/* we copy the data so that we do not depend on the caller
	   staying alive */
	memcpy(server->txbuf, req->tx_iov[1].iov_base, req->tx_iov[1].iov_len);
	req->tx_iov[1].iov_base = server->txbuf;

	if (server->ncp_sock->type == SOCK_STREAM)
		ncptcp_start_request(server, req);
	else
		ncpdgram_start_request(server, req);
}

static int ncp_add_request(struct ncp_server *server, struct ncp_request_reply *req)
{
	mutex_lock(&server->rcv.creq_mutex);
	if (!ncp_conn_valid(server)) {
		mutex_unlock(&server->rcv.creq_mutex);
		pr_err("tcp: Server died\n");
		return -EIO;
	}
	ncp_req_get(req);
	if (server->tx.creq || server->rcv.creq) {
		req->status = RQ_QUEUED;
		list_add_tail(&req->req, &server->tx.requests);
		mutex_unlock(&server->rcv.creq_mutex);
		return 0;
	}
	__ncp_start_request(server, req);
	mutex_unlock(&server->rcv.creq_mutex);
	return 0;
}

static void __ncp_next_request(struct ncp_server *server)
{
	struct ncp_request_reply *req;

	server->rcv.creq = NULL;
	if (list_empty(&server->tx.requests)) {
		return;
	}
	req = list_entry(server->tx.requests.next, struct ncp_request_reply, req);
	list_del_init(&req->req);
	__ncp_start_request(server, req);
}

static void info_server(struct ncp_server *server, unsigned int id, const void * data, size_t len)
{
	if (server->info_sock) {
		struct kvec iov[2];
		__be32 hdr[2];
	
		hdr[0] = cpu_to_be32(len + 8);
		hdr[1] = cpu_to_be32(id);
	
		iov[0].iov_base = hdr;
		iov[0].iov_len = 8;
		iov[1].iov_base = (void *) data;
		iov[1].iov_len = len;

		do_send(server->info_sock, iov, 2, len + 8, MSG_NOSIGNAL);
	}
}

void ncpdgram_rcv_proc(struct work_struct *work)
{
	struct ncp_server *server =
		container_of(work, struct ncp_server, rcv.tq);
	struct socket* sock;
	
	sock = server->ncp_sock;
	
	while (1) {
		struct ncp_reply_header reply;
		int result;

		result = _recv(sock, &reply, sizeof(reply), MSG_PEEK | MSG_DONTWAIT);
		if (result < 0) {
			break;
		}
		if (result >= sizeof(reply)) {
			struct ncp_request_reply *req;
	
			if (reply.type == NCP_WATCHDOG) {
				unsigned char buf[10];

				if (server->connection != get_conn_number(&reply)) {
					goto drop;
				}
				result = _recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
				if (result < 0) {
					ncp_dbg(1, "recv failed with %d\n", result);
					continue;
				}
				if (result < 10) {
					ncp_dbg(1, "too short (%u) watchdog packet\n", result);
					continue;
				}
				if (buf[9] != '?') {
					ncp_dbg(1, "bad signature (%02X) in watchdog packet\n", buf[9]);
					continue;
				}
				buf[9] = 'Y';
				_send(sock, buf, sizeof(buf));
				continue;
			}
			if (reply.type != NCP_POSITIVE_ACK && reply.type != NCP_REPLY) {
				result = _recv(sock, server->unexpected_packet.data, sizeof(server->unexpected_packet.data), MSG_DONTWAIT);
				if (result < 0) {
					continue;
				}
				info_server(server, 0, server->unexpected_packet.data, result);
				continue;
			}
			mutex_lock(&server->rcv.creq_mutex);
			req = server->rcv.creq;
			if (req && (req->tx_type == NCP_ALLOC_SLOT_REQUEST || (server->sequence == reply.sequence && 
					server->connection == get_conn_number(&reply)))) {
				if (reply.type == NCP_POSITIVE_ACK) {
					server->timeout_retries = server->m.retry_count;
					server->timeout_last = NCP_MAX_RPC_TIMEOUT;
					mod_timer(&server->timeout_tm, jiffies + NCP_MAX_RPC_TIMEOUT);
				} else if (reply.type == NCP_REPLY) {
					result = _recv(sock, server->rxbuf, req->datalen, MSG_DONTWAIT);
#ifdef CONFIG_NCPFS_PACKET_SIGNING
					if (result >= 0 && server->sign_active && req->tx_type != NCP_DEALLOC_SLOT_REQUEST) {
						if (result < 8 + 8) {
							result = -EIO;
						} else {
							unsigned int hdrl;
							
							result -= 8;
							hdrl = sock->sk->sk_family == AF_INET ? 8 : 6;
							if (sign_verify_reply(server, server->rxbuf + hdrl, result - hdrl, cpu_to_le32(result), server->rxbuf + result)) {
								pr_info("Signature violation\n");
								result = -EIO;
							}
						}
					}
#endif
					del_timer(&server->timeout_tm);
				     	server->rcv.creq = NULL;
					ncp_finish_request(server, req, result);
					__ncp_next_request(server);
					mutex_unlock(&server->rcv.creq_mutex);
					continue;
				}
			}
			mutex_unlock(&server->rcv.creq_mutex);
		}
drop:;		
		_recv(sock, &reply, sizeof(reply), MSG_DONTWAIT);
	}
}

static void __ncpdgram_timeout_proc(struct ncp_server *server)
{
	/* If timer is pending, we are processing another request... */
	if (!timer_pending(&server->timeout_tm)) {
		struct ncp_request_reply* req;
		
		req = server->rcv.creq;
		if (req) {
			int timeout;
			
			if (server->m.flags & NCP_MOUNT_SOFT) {
				if (server->timeout_retries-- == 0) {
					__ncp_abort_request(server, req, -ETIMEDOUT);
					return;
				}
			}
			/* Ignore errors */
			ncpdgram_send(server->ncp_sock, req);
			timeout = server->timeout_last << 1;
			if (timeout > NCP_MAX_RPC_TIMEOUT) {
				timeout = NCP_MAX_RPC_TIMEOUT;
			}
			server->timeout_last = timeout;
			mod_timer(&server->timeout_tm, jiffies + timeout);
		}
	}
}

void ncpdgram_timeout_proc(struct work_struct *work)
{
	struct ncp_server *server =
		container_of(work, struct ncp_server, timeout_tq);
	mutex_lock(&server->rcv.creq_mutex);
	__ncpdgram_timeout_proc(server);
	mutex_unlock(&server->rcv.creq_mutex);
}

static int do_tcp_rcv(struct ncp_server *server, void *buffer, size_t len)
{
	int result;
	
	if (buffer) {
		result = _recv(server->ncp_sock, buffer, len, MSG_DONTWAIT);
	} else {
		static unsigned char dummy[1024];
			
		if (len > sizeof(dummy)) {
			len = sizeof(dummy);
		}
		result = _recv(server->ncp_sock, dummy, len, MSG_DONTWAIT);
	}
	if (result < 0) {
		return result;
	}
	if (result > len) {
		pr_err("tcp: bug in recvmsg (%u > %Zu)\n", result, len);
		return -EIO;			
	}
	return result;
}	

static int __ncptcp_rcv_proc(struct ncp_server *server)
{
	/* We have to check the result, so store the complete header */
	while (1) {
		int result;
		struct ncp_request_reply *req;
		int datalen;
		int type;

		while (server->rcv.len) {
			result = do_tcp_rcv(server, server->rcv.ptr, server->rcv.len);
			if (result == -EAGAIN) {
				return 0;
			}
			if (result <= 0) {
				req = server->rcv.creq;
				if (req) {
					__ncp_abort_request(server, req, -EIO);
				} else {
					__ncptcp_abort(server);
				}
				if (result < 0) {
					pr_err("tcp: error in recvmsg: %d\n", result);
				} else {
					ncp_dbg(1, "tcp: EOF\n");
				}
				return -EIO;
			}
			if (server->rcv.ptr) {
				server->rcv.ptr += result;
			}
			server->rcv.len -= result;
		}
		switch (server->rcv.state) {
			case 0:
				if (server->rcv.buf.magic != htonl(NCP_TCP_RCVD_MAGIC)) {
					pr_err("tcp: Unexpected reply type %08X\n", ntohl(server->rcv.buf.magic));
					__ncptcp_abort(server);
					return -EIO;
				}
				datalen = ntohl(server->rcv.buf.len) & 0x0FFFFFFF;
				if (datalen < 10) {
					pr_err("tcp: Unexpected reply len %d\n", datalen);
					__ncptcp_abort(server);
					return -EIO;
				}
#ifdef CONFIG_NCPFS_PACKET_SIGNING				
				if (server->sign_active) {
					if (datalen < 18) {
						pr_err("tcp: Unexpected reply len %d\n", datalen);
						__ncptcp_abort(server);
						return -EIO;
					}
					server->rcv.buf.len = datalen - 8;
					server->rcv.ptr = (unsigned char*)&server->rcv.buf.p1;
					server->rcv.len = 8;
					server->rcv.state = 4;
					break;
				}
#endif				
				type = ntohs(server->rcv.buf.type);
#ifdef CONFIG_NCPFS_PACKET_SIGNING				
cont:;				
#endif
				if (type != NCP_REPLY) {
					if (datalen - 8 <= sizeof(server->unexpected_packet.data)) {
						*(__u16*)(server->unexpected_packet.data) = htons(type);
						server->unexpected_packet.len = datalen - 8;

						server->rcv.state = 5;
						server->rcv.ptr = server->unexpected_packet.data + 2;
						server->rcv.len = datalen - 10;
						break;
					}					
					ncp_dbg(1, "tcp: Unexpected NCP type %02X\n", type);
skipdata2:;
					server->rcv.state = 2;
skipdata:;
					server->rcv.ptr = NULL;
					server->rcv.len = datalen - 10;
					break;
				}
				req = server->rcv.creq;
				if (!req) {
					ncp_dbg(1, "Reply without appropriate request\n");
					goto skipdata2;
				}
				if (datalen > req->datalen + 8) {
					pr_err("tcp: Unexpected reply len %d (expected at most %Zd)\n", datalen, req->datalen + 8);
					server->rcv.state = 3;
					goto skipdata;
				}
				req->datalen = datalen - 8;
				((struct ncp_reply_header*)server->rxbuf)->type = NCP_REPLY;
				server->rcv.ptr = server->rxbuf + 2;
				server->rcv.len = datalen - 10;
				server->rcv.state = 1;
				break;
#ifdef CONFIG_NCPFS_PACKET_SIGNING				
			case 4:
				datalen = server->rcv.buf.len;
				type = ntohs(server->rcv.buf.type2);
				goto cont;
#endif
			case 1:
				req = server->rcv.creq;
				if (req->tx_type != NCP_ALLOC_SLOT_REQUEST) {
					if (((struct ncp_reply_header*)server->rxbuf)->sequence != server->sequence) {
						pr_err("tcp: Bad sequence number\n");
						__ncp_abort_request(server, req, -EIO);
						return -EIO;
					}
					if ((((struct ncp_reply_header*)server->rxbuf)->conn_low | (((struct ncp_reply_header*)server->rxbuf)->conn_high << 8)) != server->connection) {
						pr_err("tcp: Connection number mismatch\n");
						__ncp_abort_request(server, req, -EIO);
						return -EIO;
					}
				}
#ifdef CONFIG_NCPFS_PACKET_SIGNING				
				if (server->sign_active && req->tx_type != NCP_DEALLOC_SLOT_REQUEST) {
					if (sign_verify_reply(server, server->rxbuf + 6, req->datalen - 6, cpu_to_be32(req->datalen + 16), &server->rcv.buf.type)) {
						pr_err("tcp: Signature violation\n");
						__ncp_abort_request(server, req, -EIO);
						return -EIO;
					}
				}
#endif				
				ncp_finish_request(server, req, req->datalen);
			nextreq:;
				__ncp_next_request(server);
			case 2:
			next:;
				server->rcv.ptr = (unsigned char*)&server->rcv.buf;
				server->rcv.len = 10;
				server->rcv.state = 0;
				break;
			case 3:
				ncp_finish_request(server, server->rcv.creq, -EIO);
				goto nextreq;
			case 5:
				info_server(server, 0, server->unexpected_packet.data, server->unexpected_packet.len);
				goto next;
		}
	}
}

void ncp_tcp_rcv_proc(struct work_struct *work)
{
	struct ncp_server *server =
		container_of(work, struct ncp_server, rcv.tq);

	mutex_lock(&server->rcv.creq_mutex);
	__ncptcp_rcv_proc(server);
	mutex_unlock(&server->rcv.creq_mutex);
}

void ncp_tcp_tx_proc(struct work_struct *work)
{
	struct ncp_server *server =
		container_of(work, struct ncp_server, tx.tq);
	
	mutex_lock(&server->rcv.creq_mutex);
	__ncptcp_try_send(server);
	mutex_unlock(&server->rcv.creq_mutex);
}

static int do_ncp_rpc_call(struct ncp_server *server, int size,
		unsigned char* reply_buf, int max_reply_size)
{
	int result;
	struct ncp_request_reply *req;

	req = ncp_alloc_req();
	if (!req)
		return -ENOMEM;

	req->reply_buf = reply_buf;
	req->datalen = max_reply_size;
	req->tx_iov[1].iov_base = server->packet;
	req->tx_iov[1].iov_len = size;
	req->tx_iovlen = 1;
	req->tx_totallen = size;
	req->tx_type = *(u_int16_t*)server->packet;

	result = ncp_add_request(server, req);
	if (result < 0)
		goto out;

	if (wait_event_interruptible(req->wq, req->status == RQ_DONE)) {
		ncp_abort_request(server, req, -EINTR);
		result = -EINTR;
		goto out;
	}

	result = req->result;

out:
	ncp_req_put(req);

	return result;
}

/*
 * We need the server to be locked here, so check!
 */

static int ncp_do_request(struct ncp_server *server, int size,
		void* reply, int max_reply_size)
{
	int result;

	if (server->lock == 0) {
		pr_err("Server not locked!\n");
		return -EIO;
	}
	if (!ncp_conn_valid(server)) {
		return -EIO;
	}
	{
		sigset_t old_set;
		unsigned long mask, flags;

		spin_lock_irqsave(&current->sighand->siglock, flags);
		old_set = current->blocked;
		if (current->flags & PF_EXITING)
			mask = 0;
		else
			mask = sigmask(SIGKILL);
		if (server->m.flags & NCP_MOUNT_INTR) {
			/* FIXME: This doesn't seem right at all.  So, like,
			   we can't handle SIGINT and get whatever to stop?
			   What if we've blocked it ourselves?  What about
			   alarms?  Why, in fact, are we mucking with the
			   sigmask at all? -- r~ */
			if (current->sighand->action[SIGINT - 1].sa.sa_handler == SIG_DFL)
				mask |= sigmask(SIGINT);
			if (current->sighand->action[SIGQUIT - 1].sa.sa_handler == SIG_DFL)
				mask |= sigmask(SIGQUIT);
		}
		siginitsetinv(&current->blocked, mask);
		recalc_sigpending();
		spin_unlock_irqrestore(&current->sighand->siglock, flags);
		
		result = do_ncp_rpc_call(server, size, reply, max_reply_size);

		spin_lock_irqsave(&current->sighand->siglock, flags);
		current->blocked = old_set;
		recalc_sigpending();
		spin_unlock_irqrestore(&current->sighand->siglock, flags);
	}

	ncp_dbg(2, "do_ncp_rpc_call returned %d\n", result);

	return result;
}

/* ncp_do_request assures that at least a complete reply header is
 * received. It assumes that server->current_size contains the ncp
 * request size
 */
int ncp_request2(struct ncp_server *server, int function, 
		void* rpl, int size)
{
	struct ncp_request_header *h;
	struct ncp_reply_header* reply = rpl;
	int result;

	h = (struct ncp_request_header *) (server->packet);
	if (server->has_subfunction != 0) {
		*(__u16 *) & (h->data[0]) = htons(server->current_size - sizeof(*h) - 2);
	}
	h->type = NCP_REQUEST;
	/*
	 * The server shouldn't know or care what task is making a
	 * request, so we always use the same task number.
	 */
	h->task = 2; /* (current->pid) & 0xff; */
	h->function = function;

	result = ncp_do_request(server, server->current_size, reply, size);
	if (result < 0) {
		ncp_dbg(1, "ncp_request_error: %d\n", result);
		goto out;
	}
	server->completion = reply->completion_code;
	server->conn_status = reply->connection_state;
	server->reply_size = result;
	server->ncp_reply_size = result - sizeof(struct ncp_reply_header);

	result = reply->completion_code;

	if (result != 0)
		ncp_vdbg("completion code=%x\n", result);
out:
	return result;
}

int ncp_connect(struct ncp_server *server)
{
	struct ncp_request_header *h;
	int result;

	server->connection = 0xFFFF;
	server->sequence = 255;

	h = (struct ncp_request_header *) (server->packet);
	h->type = NCP_ALLOC_SLOT_REQUEST;
	h->task		= 2; /* see above */
	h->function	= 0;

	result = ncp_do_request(server, sizeof(*h), server->packet, server->packet_size);
	if (result < 0)
		goto out;
	server->connection = h->conn_low + (h->conn_high * 256);
	result = 0;
out:
	return result;
}

int ncp_disconnect(struct ncp_server *server)
{
	struct ncp_request_header *h;

	h = (struct ncp_request_header *) (server->packet);
	h->type = NCP_DEALLOC_SLOT_REQUEST;
	h->task		= 2; /* see above */
	h->function	= 0;

	return ncp_do_request(server, sizeof(*h), server->packet, server->packet_size);
}

void ncp_lock_server(struct ncp_server *server)
{
	mutex_lock(&server->mutex);
	if (server->lock)
		pr_warn("%s: was locked!\n", __func__);
	server->lock = 1;
}

void ncp_unlock_server(struct ncp_server *server)
{
	if (!server->lock) {
		pr_warn("%s: was not locked!\n", __func__);
		return;
	}
	server->lock = 0;
	mutex_unlock(&server->mutex);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/sock.c */
/************************************************************/
/*
 *  ncpsign_kernel.c
 *
 *  Arne de Bruijn (arne@knoware.nl), 1997
 *
 */


#ifdef CONFIG_NCPFS_PACKET_SIGNING

// #include <linux/string.h>
#include <linux/ncp.h>
#include <linux/bitops.h>
// #include "ncp_fs.h"
// #include "ncpsign_kernel.h"
#include "../../inc/__fss.h"

/* i386: 32-bit, little endian, handles mis-alignment */
#ifdef __i386__
#define GET_LE32(p) (*(const int *)(p))
#define PUT_LE32(p,v) { *(int *)(p)=v; }
#else
/* from include/ncplib.h */
#define BVAL(buf,pos) (((const __u8 *)(buf))[pos])
#define PVAL(buf,pos) ((unsigned)BVAL(buf,pos))
#define BSET(buf,pos,val) (((__u8 *)(buf))[pos] = (val))

static inline __u16
WVAL_LH_ncpsign_kernel_c(const __u8 * buf, int pos)
{
	return PVAL(buf, pos) | PVAL(buf, pos + 1) << 8;
}
static inline __u32
DVAL_LH_ncpsign_kernel_c(const __u8 * buf, int pos)
{
	return WVAL_LH_ncpsign_kernel_c(buf, pos) | WVAL_LH_ncpsign_kernel_c(buf, pos + 2) << 16;
}
static inline void
WSET_LH(__u8 * buf, int pos, __u16 val)
{
	BSET(buf, pos, val & 0xff);
	BSET(buf, pos + 1, val >> 8);
}
static inline void
DSET_LH(__u8 * buf, int pos, __u32 val)
{
	WSET_LH(buf, pos, val & 0xffff);
	WSET_LH(buf, pos + 2, val >> 16);
}

#define GET_LE32(p) DVAL_LH_ncpsign_kernel_c(p,0)
#define PUT_LE32(p,v) DSET_LH(p,0,v)
#endif

static void nwsign(char *r_data1, char *r_data2, char *outdata) {
 int i;
 unsigned int w0,w1,w2,w3;
 static int rbit[4]={0, 2, 1, 3};
#ifdef __i386__
 unsigned int *data2=(unsigned int *)r_data2;
#else
 unsigned int data2[16];
 for (i=0;i<16;i++)
  data2[i]=GET_LE32(r_data2+(i<<2));
#endif 
 w0=GET_LE32(r_data1);
 w1=GET_LE32(r_data1+4);
 w2=GET_LE32(r_data1+8);
 w3=GET_LE32(r_data1+12);
 for (i=0;i<16;i+=4) {
  w0=rol32(w0 + ((w1 & w2) | ((~w1) & w3)) + data2[i+0],3);
  w3=rol32(w3 + ((w0 & w1) | ((~w0) & w2)) + data2[i+1],7);
  w2=rol32(w2 + ((w3 & w0) | ((~w3) & w1)) + data2[i+2],11);
  w1=rol32(w1 + ((w2 & w3) | ((~w2) & w0)) + data2[i+3],19);
 }
 for (i=0;i<4;i++) {
  w0=rol32(w0 + (((w2 | w3) & w1) | (w2 & w3)) + 0x5a827999 + data2[i+0],3);
  w3=rol32(w3 + (((w1 | w2) & w0) | (w1 & w2)) + 0x5a827999 + data2[i+4],5);
  w2=rol32(w2 + (((w0 | w1) & w3) | (w0 & w1)) + 0x5a827999 + data2[i+8],9);
  w1=rol32(w1 + (((w3 | w0) & w2) | (w3 & w0)) + 0x5a827999 + data2[i+12],13);
 }
 for (i=0;i<4;i++) {
  w0=rol32(w0 + ((w1 ^ w2) ^ w3) + 0x6ed9eba1 + data2[rbit[i]+0],3);
  w3=rol32(w3 + ((w0 ^ w1) ^ w2) + 0x6ed9eba1 + data2[rbit[i]+8],9);
  w2=rol32(w2 + ((w3 ^ w0) ^ w1) + 0x6ed9eba1 + data2[rbit[i]+4],11);
  w1=rol32(w1 + ((w2 ^ w3) ^ w0) + 0x6ed9eba1 + data2[rbit[i]+12],15);
 }
 PUT_LE32(outdata,(w0+GET_LE32(r_data1)) & 0xffffffff);
 PUT_LE32(outdata+4,(w1+GET_LE32(r_data1+4)) & 0xffffffff);
 PUT_LE32(outdata+8,(w2+GET_LE32(r_data1+8)) & 0xffffffff);
 PUT_LE32(outdata+12,(w3+GET_LE32(r_data1+12)) & 0xffffffff);
}

/* Make a signature for the current packet and add it at the end of the */
/* packet. */
void __sign_packet(struct ncp_server *server, const char *packet, size_t size, __u32 totalsize, void *sign_buff) {
	unsigned char data[64];

	memcpy(data, server->sign_root, 8);
	*(__u32*)(data + 8) = totalsize;
	if (size < 52) {
		memcpy(data + 12, packet, size);
		memset(data + 12 + size, 0, 52 - size);
	} else {
		memcpy(data + 12, packet, 52);
	}
	nwsign(server->sign_last, data, server->sign_last);
	memcpy(sign_buff, server->sign_last, 8);
}

int sign_verify_reply(struct ncp_server *server, const char *packet, size_t size, __u32 totalsize, const void *sign_buff) {
	unsigned char data[64];
	unsigned char hash[16];

	memcpy(data, server->sign_root, 8);
	*(__u32*)(data + 8) = totalsize;
	if (size < 52) {
		memcpy(data + 12, packet, size);
		memset(data + 12 + size, 0, 52 - size);
	} else {
		memcpy(data + 12, packet, 52);
	}
	nwsign(server->sign_last, data, hash);
	return memcmp(sign_buff, hash, 8);
}

#endif	/* CONFIG_NCPFS_PACKET_SIGNING */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/ncpsign_kernel.c */
/************************************************************/
/*
 * getopt.c
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/string.h>

#include <asm/errno.h>
#include "../../inc/__fss.h"

// #include "getopt.h"

/**
 *	ncp_getopt - option parser
 *	@caller: name of the caller, for error messages
 *	@options: the options string
 *	@opts: an array of &struct option entries controlling parser operations
 *	@optopt: output; will contain the current option
 *	@optarg: output; will contain the value (if one exists)
 *	@value: output; may be NULL; will be overwritten with the integer value
 *		of the current argument.
 *
 *	Helper to parse options on the format used by mount ("a=b,c=d,e,f").
 *	Returns opts->val if a matching entry in the 'opts' array is found,
 *	0 when no more tokens are found, -1 if an error is encountered.
 */
int ncp_getopt(const char *caller, char **options, const struct ncp_option *opts,
	       char **optopt, char **optarg, unsigned long *value)
{
	char *token;
	char *val;

	do {
		if ((token = strsep(options, ",")) == NULL)
			return 0;
	} while (*token == '\0');
	if (optopt)
		*optopt = token;

	if ((val = strchr (token, '=')) != NULL) {
		*val++ = 0;
	}
	*optarg = val;
	for (; opts->name; opts++) {
		if (!strcmp(opts->name, token)) {
			if (!val) {
				if (opts->has_arg & OPT_NOPARAM) {
					return opts->val;
				}
				pr_info("%s: the %s option requires an argument\n",
					caller, token);
				return -EINVAL;
			}
			if (opts->has_arg & OPT_INT) {
				int rc = kstrtoul(val, 0, value);

				if (rc) {
					pr_info("%s: invalid numeric value in %s=%s\n",
						caller, token, val);
					return rc;
				}
				return opts->val;
			}
			if (opts->has_arg & OPT_STRING) {
				return opts->val;
			}
			pr_info("%s: unexpected argument %s to the %s option\n",
				caller, val, token);
			return -EINVAL;
		}
	}
	pr_info("%s: Unrecognized mount option %s\n", caller, token);
	return -EOPNOTSUPP;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/getopt.c */
/************************************************************/
/*
 *  linux/fs/ncpfs/symlink.c
 *
 *  Code for allowing symbolic links on NCPFS (i.e. NetWare)
 *  Symbolic links are not supported on native NetWare, so we use an
 *  infrequently-used flag (Sh) and store a two-word magic header in
 *  the file to make sure we don't accidentally use a non-link file
 *  as a link.
 *
 *  When using the NFS namespace, we set the mode to indicate a symlink and
 *  don't bother with the magic numbers.
 *
 *  from linux/fs/ext2/symlink.c
 *
 *  Copyright (C) 1998-99, Frank A. Vorstenbosch
 *
 *  ncpfs symlink handling code
 *  NLS support (c) 1999 Petr Vandrovec
 *  Modified 2000 Ben Harris, University of Cambridge for NFS NS meta-info
 *
 */


// #include <asm/uaccess.h>

// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/time.h>
// #include <linux/slab.h>
// #include <linux/mm.h>
// #include <linux/stat.h>
// #include "ncp_fs.h"

/* these magic numbers must appear in the symlink file -- this makes it a bit
   more resilient against the magic attributes being set on random files. */

#define NCP_SYMLINK_MAGIC0	cpu_to_le32(0x6c6d7973)     /* "symlnk->" */
#define NCP_SYMLINK_MAGIC1	cpu_to_le32(0x3e2d6b6e)

/* ----- read a symbolic link ------------------------------------------ */

static int ncp_symlink_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	int error, length, len;
	char *link, *rawlink;
	char *buf = kmap(page);

	error = -ENOMEM;
	rawlink = kmalloc(NCP_MAX_SYMLINK_SIZE, GFP_KERNEL);
	if (!rawlink)
		goto fail;

	if (ncp_make_open(inode,O_RDONLY))
		goto failEIO;

	error=ncp_read_kernel(NCP_SERVER(inode),NCP_FINFO(inode)->file_handle,
                         0,NCP_MAX_SYMLINK_SIZE,rawlink,&length);

	ncp_inode_close(inode);
	/* Close file handle if no other users... */
	ncp_make_closed(inode);
	if (error)
		goto failEIO;

	if (NCP_FINFO(inode)->flags & NCPI_KLUDGE_SYMLINK) {
		if (length<NCP_MIN_SYMLINK_SIZE || 
		    ((__le32 *)rawlink)[0]!=NCP_SYMLINK_MAGIC0 ||
		    ((__le32 *)rawlink)[1]!=NCP_SYMLINK_MAGIC1)
		    	goto failEIO;
		link = rawlink + 8;
		length -= 8;
	} else {
		link = rawlink;
	}

	len = NCP_MAX_SYMLINK_SIZE;
	error = ncp_vol2io(NCP_SERVER(inode), buf, &len, link, length, 0);
	kfree(rawlink);
	if (error)
		goto fail;
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;

failEIO:
	error = -EIO;
	kfree(rawlink);
fail:
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	return error;
}

/*
 * symlinks can't do much...
 */
const struct address_space_operations ncp_symlink_aops = {
	.readpage	= ncp_symlink_readpage,
};
	
/* ----- create a new symbolic link -------------------------------------- */
 
int ncp_symlink(struct inode *dir, struct dentry *dentry, const char *symname) {
	struct inode *inode;
	char *rawlink;
	int length, err, i, outlen;
	int kludge;
	umode_t mode;
	__le32 attr;
	unsigned int hdr;

	ncp_dbg(1, "dir=%p, dentry=%p, symname=%s\n", dir, dentry, symname);

	if (ncp_is_nfs_extras(NCP_SERVER(dir), NCP_FINFO(dir)->volNumber))
		kludge = 0;
	else
#ifdef CONFIG_NCPFS_EXTRAS
	if (NCP_SERVER(dir)->m.flags & NCP_MOUNT_SYMLINKS)
		kludge = 1;
	else
#endif
	/* EPERM is returned by VFS if symlink procedure does not exist */
		return -EPERM;
  
	rawlink = kmalloc(NCP_MAX_SYMLINK_SIZE, GFP_KERNEL);
	if (!rawlink)
		return -ENOMEM;

	if (kludge) {
		mode = 0;
		attr = aSHARED | aHIDDEN;
		((__le32 *)rawlink)[0]=NCP_SYMLINK_MAGIC0;
		((__le32 *)rawlink)[1]=NCP_SYMLINK_MAGIC1;
		hdr = 8;
	} else {
		mode = S_IFLNK | S_IRWXUGO;
		attr = 0;
		hdr = 0;
	}			

	length = strlen(symname);
	/* map to/from server charset, do not touch upper/lower case as
	   symlink can point out of ncp filesystem */
	outlen = NCP_MAX_SYMLINK_SIZE - hdr;
	err = ncp_io2vol(NCP_SERVER(dir), rawlink + hdr, &outlen, symname, length, 0);
	if (err)
		goto failfree;

	outlen += hdr;

	err = -EIO;
	if (ncp_create_new(dir,dentry,mode,0,attr)) {
		goto failfree;
	}

	inode=dentry->d_inode;

	if (ncp_make_open(inode, O_WRONLY))
		goto failfree;

	if (ncp_write_kernel(NCP_SERVER(inode), NCP_FINFO(inode)->file_handle, 
			     0, outlen, rawlink, &i) || i!=outlen) {
		goto fail;
	}

	ncp_inode_close(inode);
	ncp_make_closed(inode);
	kfree(rawlink);
	return 0;
fail:;
	ncp_inode_close(inode);
	ncp_make_closed(inode);
failfree:;
	kfree(rawlink);
	return err;
}

/* ----- EOF ----- */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/symlink.c */
/************************************************************/
/*
 *  linux/fs/ncpfs/symlink.c
 *
 *  Code for allowing symbolic links on NCPFS (i.e. NetWare)
 *  Symbolic links are not supported on native NetWare, so we use an
 *  infrequently-used flag (Sh) and store a two-word magic header in
 *  the file to make sure we don't accidentally use a non-link file
 *  as a link.
 *
 *  When using the NFS namespace, we set the mode to indicate a symlink and
 *  don't bother with the magic numbers.
 *
 *  from linux/fs/ext2/symlink.c
 *
 *  Copyright (C) 1998-99, Frank A. Vorstenbosch
 *
 *  ncpfs symlink handling code
 *  NLS support (c) 1999 Petr Vandrovec
 *  Modified 2000 Ben Harris, University of Cambridge for NFS NS meta-info
 *
 */


// #include <asm/uaccess.h>

// #include <linux/errno.h>
// #include <linux/fs.h>
// #include <linux/time.h>
// #include <linux/slab.h>
// #include <linux/mm.h>
// #include <linux/stat.h>
// #include "ncp_fs.h"

/* these magic numbers must appear in the symlink file -- this makes it a bit
   more resilient against the magic attributes being set on random files. */

#define NCP_SYMLINK_MAGIC0	cpu_to_le32(0x6c6d7973)     /* "symlnk->" */
#define NCP_SYMLINK_MAGIC1	cpu_to_le32(0x3e2d6b6e)

/* ----- read a symbolic link ------------------------------------------ */

static int ncp_symlink_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	int error, length, len;
	char *link, *rawlink;
	char *buf = kmap(page);

	error = -ENOMEM;
	rawlink = kmalloc(NCP_MAX_SYMLINK_SIZE, GFP_KERNEL);
	if (!rawlink)
		goto fail;

	if (ncp_make_open(inode,O_RDONLY))
		goto failEIO;

	error=ncp_read_kernel(NCP_SERVER(inode),NCP_FINFO(inode)->file_handle,
                         0,NCP_MAX_SYMLINK_SIZE,rawlink,&length);

	ncp_inode_close(inode);
	/* Close file handle if no other users... */
	ncp_make_closed(inode);
	if (error)
		goto failEIO;

	if (NCP_FINFO(inode)->flags & NCPI_KLUDGE_SYMLINK) {
		if (length<NCP_MIN_SYMLINK_SIZE || 
		    ((__le32 *)rawlink)[0]!=NCP_SYMLINK_MAGIC0 ||
		    ((__le32 *)rawlink)[1]!=NCP_SYMLINK_MAGIC1)
		    	goto failEIO;
		link = rawlink + 8;
		length -= 8;
	} else {
		link = rawlink;
	}

	len = NCP_MAX_SYMLINK_SIZE;
	error = ncp_vol2io(NCP_SERVER(inode), buf, &len, link, length, 0);
	kfree(rawlink);
	if (error)
		goto fail;
	SetPageUptodate(page);
	kunmap(page);
	unlock_page(page);
	return 0;

failEIO:
	error = -EIO;
	kfree(rawlink);
fail:
	SetPageError(page);
	kunmap(page);
	unlock_page(page);
	return error;
}

/*
 * symlinks can't do much...
 */
const struct address_space_operations ncp_symlink_aops = {
	.readpage	= ncp_symlink_readpage,
};
	
/* ----- create a new symbolic link -------------------------------------- */
 
int ncp_symlink(struct inode *dir, struct dentry *dentry, const char *symname) {
	struct inode *inode;
	char *rawlink;
	int length, err, i, outlen;
	int kludge;
	umode_t mode;
	__le32 attr;
	unsigned int hdr;

	ncp_dbg(1, "dir=%p, dentry=%p, symname=%s\n", dir, dentry, symname);

	if (ncp_is_nfs_extras(NCP_SERVER(dir), NCP_FINFO(dir)->volNumber))
		kludge = 0;
	else
#ifdef CONFIG_NCPFS_EXTRAS
	if (NCP_SERVER(dir)->m.flags & NCP_MOUNT_SYMLINKS)
		kludge = 1;
	else
#endif
	/* EPERM is returned by VFS if symlink procedure does not exist */
		return -EPERM;
  
	rawlink = kmalloc(NCP_MAX_SYMLINK_SIZE, GFP_KERNEL);
	if (!rawlink)
		return -ENOMEM;

	if (kludge) {
		mode = 0;
		attr = aSHARED | aHIDDEN;
		((__le32 *)rawlink)[0]=NCP_SYMLINK_MAGIC0;
		((__le32 *)rawlink)[1]=NCP_SYMLINK_MAGIC1;
		hdr = 8;
	} else {
		mode = S_IFLNK | S_IRWXUGO;
		attr = 0;
		hdr = 0;
	}			

	length = strlen(symname);
	/* map to/from server charset, do not touch upper/lower case as
	   symlink can point out of ncp filesystem */
	outlen = NCP_MAX_SYMLINK_SIZE - hdr;
	err = ncp_io2vol(NCP_SERVER(dir), rawlink + hdr, &outlen, symname, length, 0);
	if (err)
		goto failfree;

	outlen += hdr;

	err = -EIO;
	if (ncp_create_new(dir,dentry,mode,0,attr)) {
		goto failfree;
	}

	inode=dentry->d_inode;

	if (ncp_make_open(inode, O_WRONLY))
		goto failfree;

	if (ncp_write_kernel(NCP_SERVER(inode), NCP_FINFO(inode)->file_handle, 
			     0, outlen, rawlink, &i) || i!=outlen) {
		goto fail;
	}

	ncp_inode_close(inode);
	ncp_make_closed(inode);
	kfree(rawlink);
	return 0;
fail:;
	ncp_inode_close(inode);
	ncp_make_closed(inode);
failfree:;
	kfree(rawlink);
	return err;
}

/* ----- EOF ----- */
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/ncpfs/symlink.c */
/************************************************************/
