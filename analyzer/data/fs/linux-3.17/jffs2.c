/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 * Copyright © 2004 Ferenc Havasi <havasi@inf.u-szeged.hu>,
 *		    University of Szeged, Hungary
 *
 * Created by Arjan van de Ven <arjan@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "compr.h"

static DEFINE_SPINLOCK(jffs2_compressor_list_lock);

/* Available compressors are on this list */
static LIST_HEAD(jffs2_compressor_list);

/* Actual compression mode */
static int jffs2_compression_mode = JFFS2_COMPR_MODE_PRIORITY;

/* Statistics for blocks stored without compression */
static uint32_t none_stat_compr_blocks=0,none_stat_decompr_blocks=0,none_stat_compr_size=0;


/*
 * Return 1 to use this compression
 */
static int jffs2_is_best_compression(struct jffs2_compressor *this,
		struct jffs2_compressor *best, uint32_t size, uint32_t bestsize)
{
	switch (jffs2_compression_mode) {
	case JFFS2_COMPR_MODE_SIZE:
		if (bestsize > size)
			return 1;
		return 0;
	case JFFS2_COMPR_MODE_FAVOURLZO:
		if ((this->compr == JFFS2_COMPR_LZO) && (bestsize > size))
			return 1;
		if ((best->compr != JFFS2_COMPR_LZO) && (bestsize > size))
			return 1;
		if ((this->compr == JFFS2_COMPR_LZO) && (bestsize > (size * FAVOUR_LZO_PERCENT / 100)))
			return 1;
		if ((bestsize * FAVOUR_LZO_PERCENT / 100) > size)
			return 1;

		return 0;
	}
	/* Shouldn't happen */
	return 0;
}

/*
 * jffs2_selected_compress:
 * @compr: Explicit compression type to use (ie, JFFS2_COMPR_ZLIB).
 *	If 0, just take the first available compression mode.
 * @data_in: Pointer to uncompressed data
 * @cpage_out: Pointer to returned pointer to buffer for compressed data
 * @datalen: On entry, holds the amount of data available for compression.
 *	On exit, expected to hold the amount of data actually compressed.
 * @cdatalen: On entry, holds the amount of space available for compressed
 *	data. On exit, expected to hold the actual size of the compressed
 *	data.
 *
 * Returns: the compression type used.  Zero is used to show that the data
 * could not be compressed; probably because we couldn't find the requested
 * compression mode.
 */
static int jffs2_selected_compress(u8 compr, unsigned char *data_in,
		unsigned char **cpage_out, u32 *datalen, u32 *cdatalen)
{
	struct jffs2_compressor *this;
	int err, ret = JFFS2_COMPR_NONE;
	uint32_t orig_slen, orig_dlen;
	char *output_buf;

	output_buf = kmalloc(*cdatalen, GFP_KERNEL);
	if (!output_buf) {
		pr_warn("No memory for compressor allocation. Compression failed.\n");
		return ret;
	}
	orig_slen = *datalen;
	orig_dlen = *cdatalen;
	spin_lock(&jffs2_compressor_list_lock);
	list_for_each_entry(this, &jffs2_compressor_list, list) {
		/* Skip decompress-only and disabled modules */
		if (!this->compress || this->disabled)
			continue;

		/* Skip if not the desired compression type */
		if (compr && (compr != this->compr))
			continue;

		/*
		 * Either compression type was unspecified, or we found our
		 * compressor; either way, we're good to go.
		 */
		this->usecount++;
		spin_unlock(&jffs2_compressor_list_lock);

		*datalen  = orig_slen;
		*cdatalen = orig_dlen;
		err = this->compress(data_in, output_buf, datalen, cdatalen);

		spin_lock(&jffs2_compressor_list_lock);
		this->usecount--;
		if (!err) {
			/* Success */
			ret = this->compr;
			this->stat_compr_blocks++;
			this->stat_compr_orig_size += *datalen;
			this->stat_compr_new_size += *cdatalen;
			break;
		}
	}
	spin_unlock(&jffs2_compressor_list_lock);
	if (ret == JFFS2_COMPR_NONE)
		kfree(output_buf);
	else
		*cpage_out = output_buf;

	return ret;
}

/* jffs2_compress:
 * @data_in: Pointer to uncompressed data
 * @cpage_out: Pointer to returned pointer to buffer for compressed data
 * @datalen: On entry, holds the amount of data available for compression.
 *	On exit, expected to hold the amount of data actually compressed.
 * @cdatalen: On entry, holds the amount of space available for compressed
 *	data. On exit, expected to hold the actual size of the compressed
 *	data.
 *
 * Returns: Lower byte to be stored with data indicating compression type used.
 * Zero is used to show that the data could not be compressed - the
 * compressed version was actually larger than the original.
 * Upper byte will be used later. (soon)
 *
 * If the cdata buffer isn't large enough to hold all the uncompressed data,
 * jffs2_compress should compress as much as will fit, and should set
 * *datalen accordingly to show the amount of data which were compressed.
 */
uint16_t jffs2_compress(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
			unsigned char *data_in, unsigned char **cpage_out,
			uint32_t *datalen, uint32_t *cdatalen)
{
	int ret = JFFS2_COMPR_NONE;
	int mode, compr_ret;
	struct jffs2_compressor *this, *best=NULL;
	unsigned char *output_buf = NULL, *tmp_buf;
	uint32_t orig_slen, orig_dlen;
	uint32_t best_slen=0, best_dlen=0;

	if (c->mount_opts.override_compr)
		mode = c->mount_opts.compr;
	else
		mode = jffs2_compression_mode;

	switch (mode) {
	case JFFS2_COMPR_MODE_NONE:
		break;
	case JFFS2_COMPR_MODE_PRIORITY:
		ret = jffs2_selected_compress(0, data_in, cpage_out, datalen,
				cdatalen);
		break;
	case JFFS2_COMPR_MODE_SIZE:
	case JFFS2_COMPR_MODE_FAVOURLZO:
		orig_slen = *datalen;
		orig_dlen = *cdatalen;
		spin_lock(&jffs2_compressor_list_lock);
		list_for_each_entry(this, &jffs2_compressor_list, list) {
			/* Skip decompress-only backwards-compatibility and disabled modules */
			if ((!this->compress)||(this->disabled))
				continue;
			/* Allocating memory for output buffer if necessary */
			if ((this->compr_buf_size < orig_slen) && (this->compr_buf)) {
				spin_unlock(&jffs2_compressor_list_lock);
				kfree(this->compr_buf);
				spin_lock(&jffs2_compressor_list_lock);
				this->compr_buf_size=0;
				this->compr_buf=NULL;
			}
			if (!this->compr_buf) {
				spin_unlock(&jffs2_compressor_list_lock);
				tmp_buf = kmalloc(orig_slen, GFP_KERNEL);
				spin_lock(&jffs2_compressor_list_lock);
				if (!tmp_buf) {
					pr_warn("No memory for compressor allocation. (%d bytes)\n",
						orig_slen);
					continue;
				}
				else {
					this->compr_buf = tmp_buf;
					this->compr_buf_size = orig_slen;
				}
			}
			this->usecount++;
			spin_unlock(&jffs2_compressor_list_lock);
			*datalen  = orig_slen;
			*cdatalen = orig_dlen;
			compr_ret = this->compress(data_in, this->compr_buf, datalen, cdatalen);
			spin_lock(&jffs2_compressor_list_lock);
			this->usecount--;
			if (!compr_ret) {
				if (((!best_dlen) || jffs2_is_best_compression(this, best, *cdatalen, best_dlen))
						&& (*cdatalen < *datalen)) {
					best_dlen = *cdatalen;
					best_slen = *datalen;
					best = this;
				}
			}
		}
		if (best_dlen) {
			*cdatalen = best_dlen;
			*datalen  = best_slen;
			output_buf = best->compr_buf;
			best->compr_buf = NULL;
			best->compr_buf_size = 0;
			best->stat_compr_blocks++;
			best->stat_compr_orig_size += best_slen;
			best->stat_compr_new_size  += best_dlen;
			ret = best->compr;
			*cpage_out = output_buf;
		}
		spin_unlock(&jffs2_compressor_list_lock);
		break;
	case JFFS2_COMPR_MODE_FORCELZO:
		ret = jffs2_selected_compress(JFFS2_COMPR_LZO, data_in,
				cpage_out, datalen, cdatalen);
		break;
	case JFFS2_COMPR_MODE_FORCEZLIB:
		ret = jffs2_selected_compress(JFFS2_COMPR_ZLIB, data_in,
				cpage_out, datalen, cdatalen);
		break;
	default:
		pr_err("unknown compression mode\n");
	}

	if (ret == JFFS2_COMPR_NONE) {
		*cpage_out = data_in;
		*datalen = *cdatalen;
		none_stat_compr_blocks++;
		none_stat_compr_size += *datalen;
	}
	return ret;
}

int jffs2_decompress(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
		     uint16_t comprtype, unsigned char *cdata_in,
		     unsigned char *data_out, uint32_t cdatalen, uint32_t datalen)
{
	struct jffs2_compressor *this;
	int ret;

	/* Older code had a bug where it would write non-zero 'usercompr'
	   fields. Deal with it. */
	if ((comprtype & 0xff) <= JFFS2_COMPR_ZLIB)
		comprtype &= 0xff;

	switch (comprtype & 0xff) {
	case JFFS2_COMPR_NONE:
		/* This should be special-cased elsewhere, but we might as well deal with it */
		memcpy(data_out, cdata_in, datalen);
		none_stat_decompr_blocks++;
		break;
	case JFFS2_COMPR_ZERO:
		memset(data_out, 0, datalen);
		break;
	default:
		spin_lock(&jffs2_compressor_list_lock);
		list_for_each_entry(this, &jffs2_compressor_list, list) {
			if (comprtype == this->compr) {
				this->usecount++;
				spin_unlock(&jffs2_compressor_list_lock);
				ret = this->decompress(cdata_in, data_out, cdatalen, datalen);
				spin_lock(&jffs2_compressor_list_lock);
				if (ret) {
					pr_warn("Decompressor \"%s\" returned %d\n",
						this->name, ret);
				}
				else {
					this->stat_decompr_blocks++;
				}
				this->usecount--;
				spin_unlock(&jffs2_compressor_list_lock);
				return ret;
			}
		}
		pr_warn("compression type 0x%02x not available\n", comprtype);
		spin_unlock(&jffs2_compressor_list_lock);
		return -EIO;
	}
	return 0;
}

int jffs2_register_compressor(struct jffs2_compressor *comp)
{
	struct jffs2_compressor *this;

	if (!comp->name) {
		pr_warn("NULL compressor name at registering JFFS2 compressor. Failed.\n");
		return -1;
	}
	comp->compr_buf_size=0;
	comp->compr_buf=NULL;
	comp->usecount=0;
	comp->stat_compr_orig_size=0;
	comp->stat_compr_new_size=0;
	comp->stat_compr_blocks=0;
	comp->stat_decompr_blocks=0;
	jffs2_dbg(1, "Registering JFFS2 compressor \"%s\"\n", comp->name);

	spin_lock(&jffs2_compressor_list_lock);

	list_for_each_entry(this, &jffs2_compressor_list, list) {
		if (this->priority < comp->priority) {
			list_add(&comp->list, this->list.prev);
			goto out;
		}
	}
	list_add_tail(&comp->list, &jffs2_compressor_list);
out:
	D2(list_for_each_entry(this, &jffs2_compressor_list, list) {
		printk(KERN_DEBUG "Compressor \"%s\", prio %d\n", this->name, this->priority);
	})

	spin_unlock(&jffs2_compressor_list_lock);

	return 0;
}

int jffs2_unregister_compressor(struct jffs2_compressor *comp)
{
	D2(struct jffs2_compressor *this);

	jffs2_dbg(1, "Unregistering JFFS2 compressor \"%s\"\n", comp->name);

	spin_lock(&jffs2_compressor_list_lock);

	if (comp->usecount) {
		spin_unlock(&jffs2_compressor_list_lock);
		pr_warn("Compressor module is in use. Unregister failed.\n");
		return -1;
	}
	list_del(&comp->list);

	D2(list_for_each_entry(this, &jffs2_compressor_list, list) {
		printk(KERN_DEBUG "Compressor \"%s\", prio %d\n", this->name, this->priority);
	})
	spin_unlock(&jffs2_compressor_list_lock);
	return 0;
}

void jffs2_free_comprbuf(unsigned char *comprbuf, unsigned char *orig)
{
	if (orig != comprbuf)
		kfree(comprbuf);
}

int __init jffs2_compressors_init(void)
{
/* Registering compressors */
#ifdef CONFIG_JFFS2_ZLIB
	jffs2_zlib_init();
#endif
#ifdef CONFIG_JFFS2_RTIME
	jffs2_rtime_init();
#endif
#ifdef CONFIG_JFFS2_RUBIN
	jffs2_rubinmips_init();
	jffs2_dynrubin_init();
#endif
#ifdef CONFIG_JFFS2_LZO
	jffs2_lzo_init();
#endif
/* Setting default compression mode */
#ifdef CONFIG_JFFS2_CMODE_NONE
	jffs2_compression_mode = JFFS2_COMPR_MODE_NONE;
	jffs2_dbg(1, "default compression mode: none\n");
#else
#ifdef CONFIG_JFFS2_CMODE_SIZE
	jffs2_compression_mode = JFFS2_COMPR_MODE_SIZE;
	jffs2_dbg(1, "default compression mode: size\n");
#else
#ifdef CONFIG_JFFS2_CMODE_FAVOURLZO
	jffs2_compression_mode = JFFS2_COMPR_MODE_FAVOURLZO;
	jffs2_dbg(1, "default compression mode: favourlzo\n");
#else
	jffs2_dbg(1, "default compression mode: priority\n");
#endif
#endif
#endif
	return 0;
}

int jffs2_compressors_exit(void)
{
/* Unregistering compressors */
#ifdef CONFIG_JFFS2_LZO
	jffs2_lzo_exit();
#endif
#ifdef CONFIG_JFFS2_RUBIN
	jffs2_dynrubin_exit();
	jffs2_rubinmips_exit();
#endif
#ifdef CONFIG_JFFS2_RTIME
	jffs2_rtime_exit();
#endif
#ifdef CONFIG_JFFS2_ZLIB
	jffs2_zlib_exit();
#endif
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/compr.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/crc32.h>
#include <linux/jffs2.h>
#include "jffs2_fs_i.h"
#include "jffs2_fs_sb.h"
#include <linux/time.h>
#include "nodelist.h"

static int jffs2_readdir (struct file *, struct dir_context *);

static int jffs2_create (struct inode *,struct dentry *,umode_t,
			 bool);
static struct dentry *jffs2_lookup (struct inode *,struct dentry *,
				    unsigned int);
static int jffs2_link (struct dentry *,struct inode *,struct dentry *);
static int jffs2_unlink (struct inode *,struct dentry *);
static int jffs2_symlink (struct inode *,struct dentry *,const char *);
static int jffs2_mkdir (struct inode *,struct dentry *,umode_t);
static int jffs2_rmdir (struct inode *,struct dentry *);
static int jffs2_mknod (struct inode *,struct dentry *,umode_t,dev_t);
static int jffs2_rename (struct inode *, struct dentry *,
			 struct inode *, struct dentry *);

const struct file_operations jffs2_dir_operations =
{
	.read =		generic_read_dir,
	.iterate =	jffs2_readdir,
	.unlocked_ioctl=jffs2_ioctl,
	.fsync =	jffs2_fsync,
	.llseek =	generic_file_llseek,
};


const struct inode_operations jffs2_dir_inode_operations =
{
	.create =	jffs2_create,
	.lookup =	jffs2_lookup,
	.link =		jffs2_link,
	.unlink =	jffs2_unlink,
	.symlink =	jffs2_symlink,
	.mkdir =	jffs2_mkdir,
	.rmdir =	jffs2_rmdir,
	.mknod =	jffs2_mknod,
	.rename =	jffs2_rename,
	.get_acl =	jffs2_get_acl,
	.set_acl =	jffs2_set_acl,
	.setattr =	jffs2_setattr,
	.setxattr =	jffs2_setxattr,
	.getxattr =	jffs2_getxattr,
	.listxattr =	jffs2_listxattr,
	.removexattr =	jffs2_removexattr
};

/***********************************************************************/


/* We keep the dirent list sorted in increasing order of name hash,
   and we use the same hash function as the dentries. Makes this
   nice and simple
*/
static struct dentry *jffs2_lookup(struct inode *dir_i, struct dentry *target,
				   unsigned int flags)
{
	struct jffs2_inode_info *dir_f;
	struct jffs2_full_dirent *fd = NULL, *fd_list;
	uint32_t ino = 0;
	struct inode *inode = NULL;

	jffs2_dbg(1, "jffs2_lookup()\n");

	if (target->d_name.len > JFFS2_MAX_NAME_LEN)
		return ERR_PTR(-ENAMETOOLONG);

	dir_f = JFFS2_INODE_INFO(dir_i);

	mutex_lock(&dir_f->sem);

	/* NB: The 2.2 backport will need to explicitly check for '.' and '..' here */
	for (fd_list = dir_f->dents; fd_list && fd_list->nhash <= target->d_name.hash; fd_list = fd_list->next) {
		if (fd_list->nhash == target->d_name.hash &&
		    (!fd || fd_list->version > fd->version) &&
		    strlen(fd_list->name) == target->d_name.len &&
		    !strncmp(fd_list->name, target->d_name.name, target->d_name.len)) {
			fd = fd_list;
		}
	}
	if (fd)
		ino = fd->ino;
	mutex_unlock(&dir_f->sem);
	if (ino) {
		inode = jffs2_iget(dir_i->i_sb, ino);
		if (IS_ERR(inode))
			pr_warn("iget() failed for ino #%u\n", ino);
	}

	return d_splice_alias(inode, target);
}

/***********************************************************************/


static int jffs2_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(inode);
	struct jffs2_full_dirent *fd;
	unsigned long curofs = 1;

	jffs2_dbg(1, "jffs2_readdir() for dir_i #%lu\n", inode->i_ino);

	if (!dir_emit_dots(file, ctx))
		return 0;

	mutex_lock(&f->sem);
	for (fd = f->dents; fd; fd = fd->next) {
		curofs++;
		/* First loop: curofs = 2; pos = 2 */
		if (curofs < ctx->pos) {
			jffs2_dbg(2, "Skipping dirent: \"%s\", ino #%u, type %d, because curofs %ld < offset %ld\n",
				  fd->name, fd->ino, fd->type, curofs, (unsigned long)ctx->pos);
			continue;
		}
		if (!fd->ino) {
			jffs2_dbg(2, "Skipping deletion dirent \"%s\"\n",
				  fd->name);
			ctx->pos++;
			continue;
		}
		jffs2_dbg(2, "Dirent %ld: \"%s\", ino #%u, type %d\n",
			  (unsigned long)ctx->pos, fd->name, fd->ino, fd->type);
		if (!dir_emit(ctx, fd->name, strlen(fd->name), fd->ino, fd->type))
			break;
		ctx->pos++;
	}
	mutex_unlock(&f->sem);
	return 0;
}

/***********************************************************************/


static int jffs2_create(struct inode *dir_i, struct dentry *dentry,
			umode_t mode, bool excl)
{
	struct jffs2_raw_inode *ri;
	struct jffs2_inode_info *f, *dir_f;
	struct jffs2_sb_info *c;
	struct inode *inode;
	int ret;

	ri = jffs2_alloc_raw_inode();
	if (!ri)
		return -ENOMEM;

	c = JFFS2_SB_INFO(dir_i->i_sb);

	jffs2_dbg(1, "%s()\n", __func__);

	inode = jffs2_new_inode(dir_i, mode, ri);

	if (IS_ERR(inode)) {
		jffs2_dbg(1, "jffs2_new_inode() failed\n");
		jffs2_free_raw_inode(ri);
		return PTR_ERR(inode);
	}

	inode->i_op = &jffs2_file_inode_operations;
	inode->i_fop = &jffs2_file_operations;
	inode->i_mapping->a_ops = &jffs2_file_address_operations;
	inode->i_mapping->nrpages = 0;

	f = JFFS2_INODE_INFO(inode);
	dir_f = JFFS2_INODE_INFO(dir_i);

	/* jffs2_do_create() will want to lock it, _after_ reserving
	   space and taking c-alloc_sem. If we keep it locked here,
	   lockdep gets unhappy (although it's a false positive;
	   nothing else will be looking at this inode yet so there's
	   no chance of AB-BA deadlock involving its f->sem). */
	mutex_unlock(&f->sem);

	ret = jffs2_do_create(c, dir_f, f, ri, &dentry->d_name);
	if (ret)
		goto fail;

	dir_i->i_mtime = dir_i->i_ctime = ITIME(je32_to_cpu(ri->ctime));

	jffs2_free_raw_inode(ri);

	jffs2_dbg(1, "%s(): Created ino #%lu with mode %o, nlink %d(%d). nrpages %ld\n",
		  __func__, inode->i_ino, inode->i_mode, inode->i_nlink,
		  f->inocache->pino_nlink, inode->i_mapping->nrpages);

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);
	return 0;

 fail:
	iget_failed(inode);
	jffs2_free_raw_inode(ri);
	return ret;
}

/***********************************************************************/


static int jffs2_unlink(struct inode *dir_i, struct dentry *dentry)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(dir_i->i_sb);
	struct jffs2_inode_info *dir_f = JFFS2_INODE_INFO(dir_i);
	struct jffs2_inode_info *dead_f = JFFS2_INODE_INFO(dentry->d_inode);
	int ret;
	uint32_t now = get_seconds();

	ret = jffs2_do_unlink(c, dir_f, dentry->d_name.name,
			      dentry->d_name.len, dead_f, now);
	if (dead_f->inocache)
		set_nlink(dentry->d_inode, dead_f->inocache->pino_nlink);
	if (!ret)
		dir_i->i_mtime = dir_i->i_ctime = ITIME(now);
	return ret;
}
/***********************************************************************/


static int jffs2_link (struct dentry *old_dentry, struct inode *dir_i, struct dentry *dentry)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(old_dentry->d_inode->i_sb);
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(old_dentry->d_inode);
	struct jffs2_inode_info *dir_f = JFFS2_INODE_INFO(dir_i);
	int ret;
	uint8_t type;
	uint32_t now;

	/* Don't let people make hard links to bad inodes. */
	if (!f->inocache)
		return -EIO;

	if (S_ISDIR(old_dentry->d_inode->i_mode))
		return -EPERM;

	/* XXX: This is ugly */
	type = (old_dentry->d_inode->i_mode & S_IFMT) >> 12;
	if (!type) type = DT_REG;

	now = get_seconds();
	ret = jffs2_do_link(c, dir_f, f->inocache->ino, type, dentry->d_name.name, dentry->d_name.len, now);

	if (!ret) {
		mutex_lock(&f->sem);
		set_nlink(old_dentry->d_inode, ++f->inocache->pino_nlink);
		mutex_unlock(&f->sem);
		d_instantiate(dentry, old_dentry->d_inode);
		dir_i->i_mtime = dir_i->i_ctime = ITIME(now);
		ihold(old_dentry->d_inode);
	}
	return ret;
}

/***********************************************************************/

static int jffs2_symlink (struct inode *dir_i, struct dentry *dentry, const char *target)
{
	struct jffs2_inode_info *f, *dir_f;
	struct jffs2_sb_info *c;
	struct inode *inode;
	struct jffs2_raw_inode *ri;
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dnode *fn;
	struct jffs2_full_dirent *fd;
	int namelen;
	uint32_t alloclen;
	int ret, targetlen = strlen(target);

	/* FIXME: If you care. We'd need to use frags for the target
	   if it grows much more than this */
	if (targetlen > 254)
		return -ENAMETOOLONG;

	ri = jffs2_alloc_raw_inode();

	if (!ri)
		return -ENOMEM;

	c = JFFS2_SB_INFO(dir_i->i_sb);

	/* Try to reserve enough space for both node and dirent.
	 * Just the node will do for now, though
	 */
	namelen = dentry->d_name.len;
	ret = jffs2_reserve_space(c, sizeof(*ri) + targetlen, &alloclen,
				  ALLOC_NORMAL, JFFS2_SUMMARY_INODE_SIZE);

	if (ret) {
		jffs2_free_raw_inode(ri);
		return ret;
	}

	inode = jffs2_new_inode(dir_i, S_IFLNK | S_IRWXUGO, ri);

	if (IS_ERR(inode)) {
		jffs2_free_raw_inode(ri);
		jffs2_complete_reservation(c);
		return PTR_ERR(inode);
	}

	inode->i_op = &jffs2_symlink_inode_operations;

	f = JFFS2_INODE_INFO(inode);

	inode->i_size = targetlen;
	ri->isize = ri->dsize = ri->csize = cpu_to_je32(inode->i_size);
	ri->totlen = cpu_to_je32(sizeof(*ri) + inode->i_size);
	ri->hdr_crc = cpu_to_je32(crc32(0, ri, sizeof(struct jffs2_unknown_node)-4));

	ri->compr = JFFS2_COMPR_NONE;
	ri->data_crc = cpu_to_je32(crc32(0, target, targetlen));
	ri->node_crc = cpu_to_je32(crc32(0, ri, sizeof(*ri)-8));

	fn = jffs2_write_dnode(c, f, ri, target, targetlen, ALLOC_NORMAL);

	jffs2_free_raw_inode(ri);

	if (IS_ERR(fn)) {
		/* Eeek. Wave bye bye */
		mutex_unlock(&f->sem);
		jffs2_complete_reservation(c);
		ret = PTR_ERR(fn);
		goto fail;
	}

	/* We use f->target field to store the target path. */
	f->target = kmemdup(target, targetlen + 1, GFP_KERNEL);
	if (!f->target) {
		pr_warn("Can't allocate %d bytes of memory\n", targetlen + 1);
		mutex_unlock(&f->sem);
		jffs2_complete_reservation(c);
		ret = -ENOMEM;
		goto fail;
	}

	jffs2_dbg(1, "%s(): symlink's target '%s' cached\n",
		  __func__, (char *)f->target);

	/* No data here. Only a metadata node, which will be
	   obsoleted by the first data write
	*/
	f->metadata = fn;
	mutex_unlock(&f->sem);

	jffs2_complete_reservation(c);

	ret = jffs2_init_security(inode, dir_i, &dentry->d_name);
	if (ret)
		goto fail;

	ret = jffs2_init_acl_post(inode);
	if (ret)
		goto fail;

	ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &alloclen,
				  ALLOC_NORMAL, JFFS2_SUMMARY_DIRENT_SIZE(namelen));
	if (ret)
		goto fail;

	rd = jffs2_alloc_raw_dirent();
	if (!rd) {
		/* Argh. Now we treat it like a normal delete */
		jffs2_complete_reservation(c);
		ret = -ENOMEM;
		goto fail;
	}

	dir_f = JFFS2_INODE_INFO(dir_i);
	mutex_lock(&dir_f->sem);

	rd->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	rd->nodetype = cpu_to_je16(JFFS2_NODETYPE_DIRENT);
	rd->totlen = cpu_to_je32(sizeof(*rd) + namelen);
	rd->hdr_crc = cpu_to_je32(crc32(0, rd, sizeof(struct jffs2_unknown_node)-4));

	rd->pino = cpu_to_je32(dir_i->i_ino);
	rd->version = cpu_to_je32(++dir_f->highest_version);
	rd->ino = cpu_to_je32(inode->i_ino);
	rd->mctime = cpu_to_je32(get_seconds());
	rd->nsize = namelen;
	rd->type = DT_LNK;
	rd->node_crc = cpu_to_je32(crc32(0, rd, sizeof(*rd)-8));
	rd->name_crc = cpu_to_je32(crc32(0, dentry->d_name.name, namelen));

	fd = jffs2_write_dirent(c, dir_f, rd, dentry->d_name.name, namelen, ALLOC_NORMAL);

	if (IS_ERR(fd)) {
		/* dirent failed to write. Delete the inode normally
		   as if it were the final unlink() */
		jffs2_complete_reservation(c);
		jffs2_free_raw_dirent(rd);
		mutex_unlock(&dir_f->sem);
		ret = PTR_ERR(fd);
		goto fail;
	}

	dir_i->i_mtime = dir_i->i_ctime = ITIME(je32_to_cpu(rd->mctime));

	jffs2_free_raw_dirent(rd);

	/* Link the fd into the inode's list, obsoleting an old
	   one if necessary. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);

	mutex_unlock(&dir_f->sem);
	jffs2_complete_reservation(c);

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);
	return 0;

 fail:
	iget_failed(inode);
	return ret;
}


static int jffs2_mkdir (struct inode *dir_i, struct dentry *dentry, umode_t mode)
{
	struct jffs2_inode_info *f, *dir_f;
	struct jffs2_sb_info *c;
	struct inode *inode;
	struct jffs2_raw_inode *ri;
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dnode *fn;
	struct jffs2_full_dirent *fd;
	int namelen;
	uint32_t alloclen;
	int ret;

	mode |= S_IFDIR;

	ri = jffs2_alloc_raw_inode();
	if (!ri)
		return -ENOMEM;

	c = JFFS2_SB_INFO(dir_i->i_sb);

	/* Try to reserve enough space for both node and dirent.
	 * Just the node will do for now, though
	 */
	namelen = dentry->d_name.len;
	ret = jffs2_reserve_space(c, sizeof(*ri), &alloclen, ALLOC_NORMAL,
				  JFFS2_SUMMARY_INODE_SIZE);

	if (ret) {
		jffs2_free_raw_inode(ri);
		return ret;
	}

	inode = jffs2_new_inode(dir_i, mode, ri);

	if (IS_ERR(inode)) {
		jffs2_free_raw_inode(ri);
		jffs2_complete_reservation(c);
		return PTR_ERR(inode);
	}

	inode->i_op = &jffs2_dir_inode_operations;
	inode->i_fop = &jffs2_dir_operations;

	f = JFFS2_INODE_INFO(inode);

	/* Directories get nlink 2 at start */
	set_nlink(inode, 2);
	/* but ic->pino_nlink is the parent ino# */
	f->inocache->pino_nlink = dir_i->i_ino;

	ri->data_crc = cpu_to_je32(0);
	ri->node_crc = cpu_to_je32(crc32(0, ri, sizeof(*ri)-8));

	fn = jffs2_write_dnode(c, f, ri, NULL, 0, ALLOC_NORMAL);

	jffs2_free_raw_inode(ri);

	if (IS_ERR(fn)) {
		/* Eeek. Wave bye bye */
		mutex_unlock(&f->sem);
		jffs2_complete_reservation(c);
		ret = PTR_ERR(fn);
		goto fail;
	}
	/* No data here. Only a metadata node, which will be
	   obsoleted by the first data write
	*/
	f->metadata = fn;
	mutex_unlock(&f->sem);

	jffs2_complete_reservation(c);

	ret = jffs2_init_security(inode, dir_i, &dentry->d_name);
	if (ret)
		goto fail;

	ret = jffs2_init_acl_post(inode);
	if (ret)
		goto fail;

	ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &alloclen,
				  ALLOC_NORMAL, JFFS2_SUMMARY_DIRENT_SIZE(namelen));
	if (ret)
		goto fail;

	rd = jffs2_alloc_raw_dirent();
	if (!rd) {
		/* Argh. Now we treat it like a normal delete */
		jffs2_complete_reservation(c);
		ret = -ENOMEM;
		goto fail;
	}

	dir_f = JFFS2_INODE_INFO(dir_i);
	mutex_lock(&dir_f->sem);

	rd->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	rd->nodetype = cpu_to_je16(JFFS2_NODETYPE_DIRENT);
	rd->totlen = cpu_to_je32(sizeof(*rd) + namelen);
	rd->hdr_crc = cpu_to_je32(crc32(0, rd, sizeof(struct jffs2_unknown_node)-4));

	rd->pino = cpu_to_je32(dir_i->i_ino);
	rd->version = cpu_to_je32(++dir_f->highest_version);
	rd->ino = cpu_to_je32(inode->i_ino);
	rd->mctime = cpu_to_je32(get_seconds());
	rd->nsize = namelen;
	rd->type = DT_DIR;
	rd->node_crc = cpu_to_je32(crc32(0, rd, sizeof(*rd)-8));
	rd->name_crc = cpu_to_je32(crc32(0, dentry->d_name.name, namelen));

	fd = jffs2_write_dirent(c, dir_f, rd, dentry->d_name.name, namelen, ALLOC_NORMAL);

	if (IS_ERR(fd)) {
		/* dirent failed to write. Delete the inode normally
		   as if it were the final unlink() */
		jffs2_complete_reservation(c);
		jffs2_free_raw_dirent(rd);
		mutex_unlock(&dir_f->sem);
		ret = PTR_ERR(fd);
		goto fail;
	}

	dir_i->i_mtime = dir_i->i_ctime = ITIME(je32_to_cpu(rd->mctime));
	inc_nlink(dir_i);

	jffs2_free_raw_dirent(rd);

	/* Link the fd into the inode's list, obsoleting an old
	   one if necessary. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);

	mutex_unlock(&dir_f->sem);
	jffs2_complete_reservation(c);

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);
	return 0;

 fail:
	iget_failed(inode);
	return ret;
}

static int jffs2_rmdir (struct inode *dir_i, struct dentry *dentry)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(dir_i->i_sb);
	struct jffs2_inode_info *dir_f = JFFS2_INODE_INFO(dir_i);
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(dentry->d_inode);
	struct jffs2_full_dirent *fd;
	int ret;
	uint32_t now = get_seconds();

	for (fd = f->dents ; fd; fd = fd->next) {
		if (fd->ino)
			return -ENOTEMPTY;
	}

	ret = jffs2_do_unlink(c, dir_f, dentry->d_name.name,
			      dentry->d_name.len, f, now);
	if (!ret) {
		dir_i->i_mtime = dir_i->i_ctime = ITIME(now);
		clear_nlink(dentry->d_inode);
		drop_nlink(dir_i);
	}
	return ret;
}

static int jffs2_mknod (struct inode *dir_i, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct jffs2_inode_info *f, *dir_f;
	struct jffs2_sb_info *c;
	struct inode *inode;
	struct jffs2_raw_inode *ri;
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dnode *fn;
	struct jffs2_full_dirent *fd;
	int namelen;
	union jffs2_device_node dev;
	int devlen = 0;
	uint32_t alloclen;
	int ret;

	if (!new_valid_dev(rdev))
		return -EINVAL;

	ri = jffs2_alloc_raw_inode();
	if (!ri)
		return -ENOMEM;

	c = JFFS2_SB_INFO(dir_i->i_sb);

	if (S_ISBLK(mode) || S_ISCHR(mode))
		devlen = jffs2_encode_dev(&dev, rdev);

	/* Try to reserve enough space for both node and dirent.
	 * Just the node will do for now, though
	 */
	namelen = dentry->d_name.len;
	ret = jffs2_reserve_space(c, sizeof(*ri) + devlen, &alloclen,
				  ALLOC_NORMAL, JFFS2_SUMMARY_INODE_SIZE);

	if (ret) {
		jffs2_free_raw_inode(ri);
		return ret;
	}

	inode = jffs2_new_inode(dir_i, mode, ri);

	if (IS_ERR(inode)) {
		jffs2_free_raw_inode(ri);
		jffs2_complete_reservation(c);
		return PTR_ERR(inode);
	}
	inode->i_op = &jffs2_file_inode_operations;
	init_special_inode(inode, inode->i_mode, rdev);

	f = JFFS2_INODE_INFO(inode);

	ri->dsize = ri->csize = cpu_to_je32(devlen);
	ri->totlen = cpu_to_je32(sizeof(*ri) + devlen);
	ri->hdr_crc = cpu_to_je32(crc32(0, ri, sizeof(struct jffs2_unknown_node)-4));

	ri->compr = JFFS2_COMPR_NONE;
	ri->data_crc = cpu_to_je32(crc32(0, &dev, devlen));
	ri->node_crc = cpu_to_je32(crc32(0, ri, sizeof(*ri)-8));

	fn = jffs2_write_dnode(c, f, ri, (char *)&dev, devlen, ALLOC_NORMAL);

	jffs2_free_raw_inode(ri);

	if (IS_ERR(fn)) {
		/* Eeek. Wave bye bye */
		mutex_unlock(&f->sem);
		jffs2_complete_reservation(c);
		ret = PTR_ERR(fn);
		goto fail;
	}
	/* No data here. Only a metadata node, which will be
	   obsoleted by the first data write
	*/
	f->metadata = fn;
	mutex_unlock(&f->sem);

	jffs2_complete_reservation(c);

	ret = jffs2_init_security(inode, dir_i, &dentry->d_name);
	if (ret)
		goto fail;

	ret = jffs2_init_acl_post(inode);
	if (ret)
		goto fail;

	ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &alloclen,
				  ALLOC_NORMAL, JFFS2_SUMMARY_DIRENT_SIZE(namelen));
	if (ret)
		goto fail;

	rd = jffs2_alloc_raw_dirent();
	if (!rd) {
		/* Argh. Now we treat it like a normal delete */
		jffs2_complete_reservation(c);
		ret = -ENOMEM;
		goto fail;
	}

	dir_f = JFFS2_INODE_INFO(dir_i);
	mutex_lock(&dir_f->sem);

	rd->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	rd->nodetype = cpu_to_je16(JFFS2_NODETYPE_DIRENT);
	rd->totlen = cpu_to_je32(sizeof(*rd) + namelen);
	rd->hdr_crc = cpu_to_je32(crc32(0, rd, sizeof(struct jffs2_unknown_node)-4));

	rd->pino = cpu_to_je32(dir_i->i_ino);
	rd->version = cpu_to_je32(++dir_f->highest_version);
	rd->ino = cpu_to_je32(inode->i_ino);
	rd->mctime = cpu_to_je32(get_seconds());
	rd->nsize = namelen;

	/* XXX: This is ugly. */
	rd->type = (mode & S_IFMT) >> 12;

	rd->node_crc = cpu_to_je32(crc32(0, rd, sizeof(*rd)-8));
	rd->name_crc = cpu_to_je32(crc32(0, dentry->d_name.name, namelen));

	fd = jffs2_write_dirent(c, dir_f, rd, dentry->d_name.name, namelen, ALLOC_NORMAL);

	if (IS_ERR(fd)) {
		/* dirent failed to write. Delete the inode normally
		   as if it were the final unlink() */
		jffs2_complete_reservation(c);
		jffs2_free_raw_dirent(rd);
		mutex_unlock(&dir_f->sem);
		ret = PTR_ERR(fd);
		goto fail;
	}

	dir_i->i_mtime = dir_i->i_ctime = ITIME(je32_to_cpu(rd->mctime));

	jffs2_free_raw_dirent(rd);

	/* Link the fd into the inode's list, obsoleting an old
	   one if necessary. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);

	mutex_unlock(&dir_f->sem);
	jffs2_complete_reservation(c);

	unlock_new_inode(inode);
	d_instantiate(dentry, inode);
	return 0;

 fail:
	iget_failed(inode);
	return ret;
}

static int jffs2_rename (struct inode *old_dir_i, struct dentry *old_dentry,
			 struct inode *new_dir_i, struct dentry *new_dentry)
{
	int ret;
	struct jffs2_sb_info *c = JFFS2_SB_INFO(old_dir_i->i_sb);
	struct jffs2_inode_info *victim_f = NULL;
	uint8_t type;
	uint32_t now;

	/* The VFS will check for us and prevent trying to rename a
	 * file over a directory and vice versa, but if it's a directory,
	 * the VFS can't check whether the victim is empty. The filesystem
	 * needs to do that for itself.
	 */
	if (new_dentry->d_inode) {
		victim_f = JFFS2_INODE_INFO(new_dentry->d_inode);
		if (S_ISDIR(new_dentry->d_inode->i_mode)) {
			struct jffs2_full_dirent *fd;

			mutex_lock(&victim_f->sem);
			for (fd = victim_f->dents; fd; fd = fd->next) {
				if (fd->ino) {
					mutex_unlock(&victim_f->sem);
					return -ENOTEMPTY;
				}
			}
			mutex_unlock(&victim_f->sem);
		}
	}

	/* XXX: We probably ought to alloc enough space for
	   both nodes at the same time. Writing the new link,
	   then getting -ENOSPC, is quite bad :)
	*/

	/* Make a hard link */

	/* XXX: This is ugly */
	type = (old_dentry->d_inode->i_mode & S_IFMT) >> 12;
	if (!type) type = DT_REG;

	now = get_seconds();
	ret = jffs2_do_link(c, JFFS2_INODE_INFO(new_dir_i),
			    old_dentry->d_inode->i_ino, type,
			    new_dentry->d_name.name, new_dentry->d_name.len, now);

	if (ret)
		return ret;

	if (victim_f) {
		/* There was a victim. Kill it off nicely */
		if (S_ISDIR(new_dentry->d_inode->i_mode))
			clear_nlink(new_dentry->d_inode);
		else
			drop_nlink(new_dentry->d_inode);
		/* Don't oops if the victim was a dirent pointing to an
		   inode which didn't exist. */
		if (victim_f->inocache) {
			mutex_lock(&victim_f->sem);
			if (S_ISDIR(new_dentry->d_inode->i_mode))
				victim_f->inocache->pino_nlink = 0;
			else
				victim_f->inocache->pino_nlink--;
			mutex_unlock(&victim_f->sem);
		}
	}

	/* If it was a directory we moved, and there was no victim,
	   increase i_nlink on its new parent */
	if (S_ISDIR(old_dentry->d_inode->i_mode) && !victim_f)
		inc_nlink(new_dir_i);

	/* Unlink the original */
	ret = jffs2_do_unlink(c, JFFS2_INODE_INFO(old_dir_i),
			      old_dentry->d_name.name, old_dentry->d_name.len, NULL, now);

	/* We don't touch inode->i_nlink */

	if (ret) {
		/* Oh shit. We really ought to make a single node which can do both atomically */
		struct jffs2_inode_info *f = JFFS2_INODE_INFO(old_dentry->d_inode);
		mutex_lock(&f->sem);
		inc_nlink(old_dentry->d_inode);
		if (f->inocache && !S_ISDIR(old_dentry->d_inode->i_mode))
			f->inocache->pino_nlink++;
		mutex_unlock(&f->sem);

		pr_notice("%s(): Link succeeded, unlink failed (err %d). You now have a hard link\n",
			  __func__, ret);
		/* Might as well let the VFS know */
		d_instantiate(new_dentry, old_dentry->d_inode);
		ihold(old_dentry->d_inode);
		new_dir_i->i_mtime = new_dir_i->i_ctime = ITIME(now);
		return ret;
	}

	if (S_ISDIR(old_dentry->d_inode->i_mode))
		drop_nlink(old_dir_i);

	new_dir_i->i_mtime = new_dir_i->i_ctime = old_dir_i->i_mtime = old_dir_i->i_ctime = ITIME(now);

	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/dir.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/fs.h>
// #include <linux/time.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
// #include <linux/crc32.h>
// #include <linux/jffs2.h>
// #include "nodelist.h"

static int jffs2_write_end(struct file *filp, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *pg, void *fsdata);
static int jffs2_write_begin(struct file *filp, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata);
static int jffs2_readpage (struct file *filp, struct page *pg);

int jffs2_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	struct inode *inode = filp->f_mapping->host;
	struct jffs2_sb_info *c = JFFS2_SB_INFO(inode->i_sb);
	int ret;

	ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
	if (ret)
		return ret;

	mutex_lock(&inode->i_mutex);
	/* Trigger GC to flush any pending writes for this inode */
	jffs2_flush_wbuf_gc(c, inode->i_ino);
	mutex_unlock(&inode->i_mutex);

	return 0;
}

const struct file_operations jffs2_file_operations =
{
	.llseek =	generic_file_llseek,
	.open =		generic_file_open,
 	.read =		new_sync_read,
 	.read_iter =	generic_file_read_iter,
 	.write =	new_sync_write,
 	.write_iter =	generic_file_write_iter,
	.unlocked_ioctl=jffs2_ioctl,
	.mmap =		generic_file_readonly_mmap,
	.fsync =	jffs2_fsync,
	.splice_read =	generic_file_splice_read,
};

/* jffs2_file_inode_operations */

const struct inode_operations jffs2_file_inode_operations =
{
	.get_acl =	jffs2_get_acl,
	.set_acl =	jffs2_set_acl,
	.setattr =	jffs2_setattr,
	.setxattr =	jffs2_setxattr,
	.getxattr =	jffs2_getxattr,
	.listxattr =	jffs2_listxattr,
	.removexattr =	jffs2_removexattr
};

const struct address_space_operations jffs2_file_address_operations =
{
	.readpage =	jffs2_readpage,
	.write_begin =	jffs2_write_begin,
	.write_end =	jffs2_write_end,
};

static int jffs2_do_readpage_nolock (struct inode *inode, struct page *pg)
{
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(inode);
	struct jffs2_sb_info *c = JFFS2_SB_INFO(inode->i_sb);
	unsigned char *pg_buf;
	int ret;

	jffs2_dbg(2, "%s(): ino #%lu, page at offset 0x%lx\n",
		  __func__, inode->i_ino, pg->index << PAGE_CACHE_SHIFT);

	BUG_ON(!PageLocked(pg));

	pg_buf = kmap(pg);
	/* FIXME: Can kmap fail? */

	ret = jffs2_read_inode_range(c, f, pg_buf, pg->index << PAGE_CACHE_SHIFT, PAGE_CACHE_SIZE);

	if (ret) {
		ClearPageUptodate(pg);
		SetPageError(pg);
	} else {
		SetPageUptodate(pg);
		ClearPageError(pg);
	}

	flush_dcache_page(pg);
	kunmap(pg);

	jffs2_dbg(2, "readpage finished\n");
	return ret;
}

int jffs2_do_readpage_unlock(struct inode *inode, struct page *pg)
{
	int ret = jffs2_do_readpage_nolock(inode, pg);
	unlock_page(pg);
	return ret;
}


static int jffs2_readpage (struct file *filp, struct page *pg)
{
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(pg->mapping->host);
	int ret;

	mutex_lock(&f->sem);
	ret = jffs2_do_readpage_unlock(pg->mapping->host, pg);
	mutex_unlock(&f->sem);
	return ret;
}

static int jffs2_write_begin(struct file *filp, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	struct page *pg;
	struct inode *inode = mapping->host;
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(inode);
	struct jffs2_sb_info *c = JFFS2_SB_INFO(inode->i_sb);
	struct jffs2_raw_inode ri;
	uint32_t alloc_len = 0;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	uint32_t pageofs = index << PAGE_CACHE_SHIFT;
	int ret = 0;

	jffs2_dbg(1, "%s()\n", __func__);

	if (pageofs > inode->i_size) {
		ret = jffs2_reserve_space(c, sizeof(ri), &alloc_len,
					  ALLOC_NORMAL, JFFS2_SUMMARY_INODE_SIZE);
		if (ret)
			return ret;
	}

	mutex_lock(&f->sem);
	pg = grab_cache_page_write_begin(mapping, index, flags);
	if (!pg) {
		if (alloc_len)
			jffs2_complete_reservation(c);
		mutex_unlock(&f->sem);
		return -ENOMEM;
	}
	*pagep = pg;

	if (alloc_len) {
		/* Make new hole frag from old EOF to new page */
		struct jffs2_full_dnode *fn;

		jffs2_dbg(1, "Writing new hole frag 0x%x-0x%x between current EOF and new page\n",
			  (unsigned int)inode->i_size, pageofs);

		memset(&ri, 0, sizeof(ri));

		ri.magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
		ri.nodetype = cpu_to_je16(JFFS2_NODETYPE_INODE);
		ri.totlen = cpu_to_je32(sizeof(ri));
		ri.hdr_crc = cpu_to_je32(crc32(0, &ri, sizeof(struct jffs2_unknown_node)-4));

		ri.ino = cpu_to_je32(f->inocache->ino);
		ri.version = cpu_to_je32(++f->highest_version);
		ri.mode = cpu_to_jemode(inode->i_mode);
		ri.uid = cpu_to_je16(i_uid_read(inode));
		ri.gid = cpu_to_je16(i_gid_read(inode));
		ri.isize = cpu_to_je32(max((uint32_t)inode->i_size, pageofs));
		ri.atime = ri.ctime = ri.mtime = cpu_to_je32(get_seconds());
		ri.offset = cpu_to_je32(inode->i_size);
		ri.dsize = cpu_to_je32(pageofs - inode->i_size);
		ri.csize = cpu_to_je32(0);
		ri.compr = JFFS2_COMPR_ZERO;
		ri.node_crc = cpu_to_je32(crc32(0, &ri, sizeof(ri)-8));
		ri.data_crc = cpu_to_je32(0);

		fn = jffs2_write_dnode(c, f, &ri, NULL, 0, ALLOC_NORMAL);

		if (IS_ERR(fn)) {
			ret = PTR_ERR(fn);
			jffs2_complete_reservation(c);
			goto out_page;
		}
		ret = jffs2_add_full_dnode_to_inode(c, f, fn);
		if (f->metadata) {
			jffs2_mark_node_obsolete(c, f->metadata->raw);
			jffs2_free_full_dnode(f->metadata);
			f->metadata = NULL;
		}
		if (ret) {
			jffs2_dbg(1, "Eep. add_full_dnode_to_inode() failed in write_begin, returned %d\n",
				  ret);
			jffs2_mark_node_obsolete(c, fn->raw);
			jffs2_free_full_dnode(fn);
			jffs2_complete_reservation(c);
			goto out_page;
		}
		jffs2_complete_reservation(c);
		inode->i_size = pageofs;
	}

	/*
	 * Read in the page if it wasn't already present. Cannot optimize away
	 * the whole page write case until jffs2_write_end can handle the
	 * case of a short-copy.
	 */
	if (!PageUptodate(pg)) {
		ret = jffs2_do_readpage_nolock(inode, pg);
		if (ret)
			goto out_page;
	}
	mutex_unlock(&f->sem);
	jffs2_dbg(1, "end write_begin(). pg->flags %lx\n", pg->flags);
	return ret;

out_page:
	unlock_page(pg);
	page_cache_release(pg);
	mutex_unlock(&f->sem);
	return ret;
}

static int jffs2_write_end(struct file *filp, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *pg, void *fsdata)
{
	/* Actually commit the write from the page cache page we're looking at.
	 * For now, we write the full page out each time. It sucks, but it's simple
	 */
	struct inode *inode = mapping->host;
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(inode);
	struct jffs2_sb_info *c = JFFS2_SB_INFO(inode->i_sb);
	struct jffs2_raw_inode *ri;
	unsigned start = pos & (PAGE_CACHE_SIZE - 1);
	unsigned end = start + copied;
	unsigned aligned_start = start & ~3;
	int ret = 0;
	uint32_t writtenlen = 0;

	jffs2_dbg(1, "%s(): ino #%lu, page at 0x%lx, range %d-%d, flags %lx\n",
		  __func__, inode->i_ino, pg->index << PAGE_CACHE_SHIFT,
		  start, end, pg->flags);

	/* We need to avoid deadlock with page_cache_read() in
	   jffs2_garbage_collect_pass(). So the page must be
	   up to date to prevent page_cache_read() from trying
	   to re-lock it. */
	BUG_ON(!PageUptodate(pg));

	if (end == PAGE_CACHE_SIZE) {
		/* When writing out the end of a page, write out the
		   _whole_ page. This helps to reduce the number of
		   nodes in files which have many short writes, like
		   syslog files. */
		aligned_start = 0;
	}

	ri = jffs2_alloc_raw_inode();

	if (!ri) {
		jffs2_dbg(1, "%s(): Allocation of raw inode failed\n",
			  __func__);
		unlock_page(pg);
		page_cache_release(pg);
		return -ENOMEM;
	}

	/* Set the fields that the generic jffs2_write_inode_range() code can't find */
	ri->ino = cpu_to_je32(inode->i_ino);
	ri->mode = cpu_to_jemode(inode->i_mode);
	ri->uid = cpu_to_je16(i_uid_read(inode));
	ri->gid = cpu_to_je16(i_gid_read(inode));
	ri->isize = cpu_to_je32((uint32_t)inode->i_size);
	ri->atime = ri->ctime = ri->mtime = cpu_to_je32(get_seconds());

	/* In 2.4, it was already kmapped by generic_file_write(). Doesn't
	   hurt to do it again. The alternative is ifdefs, which are ugly. */
	kmap(pg);

	ret = jffs2_write_inode_range(c, f, ri, page_address(pg) + aligned_start,
				      (pg->index << PAGE_CACHE_SHIFT) + aligned_start,
				      end - aligned_start, &writtenlen);

	kunmap(pg);

	if (ret) {
		/* There was an error writing. */
		SetPageError(pg);
	}

	/* Adjust writtenlen for the padding we did, so we don't confuse our caller */
	writtenlen -= min(writtenlen, (start - aligned_start));

	if (writtenlen) {
		if (inode->i_size < pos + writtenlen) {
			inode->i_size = pos + writtenlen;
			inode->i_blocks = (inode->i_size + 511) >> 9;

			inode->i_ctime = inode->i_mtime = ITIME(je32_to_cpu(ri->ctime));
		}
	}

	jffs2_free_raw_inode(ri);

	if (start+writtenlen < end) {
		/* generic_file_write has written more to the page cache than we've
		   actually written to the medium. Mark the page !Uptodate so that
		   it gets reread */
		jffs2_dbg(1, "%s(): Not all bytes written. Marking page !uptodate\n",
			__func__);
		SetPageError(pg);
		ClearPageUptodate(pg);
	}

	jffs2_dbg(1, "%s() returning %d\n",
		  __func__, writtenlen > 0 ? writtenlen : ret);
	unlock_page(pg);
	page_cache_release(pg);
	return writtenlen > 0 ? writtenlen : ret;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/file.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

// #include <linux/fs.h>
// #include "nodelist.h"

long jffs2_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Later, this will provide for lsattr.jffs2 and chattr.jffs2, which
	   will include compression support etc. */
	return -ENOTTY;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/ioctl.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
#include <linux/sched.h>
// #include <linux/fs.h>
#include <linux/mtd/mtd.h>
#include <linux/rbtree.h>
// #include <linux/crc32.h>
// #include <linux/pagemap.h>
// #include "nodelist.h"

static void jffs2_obsolete_node_frag(struct jffs2_sb_info *c,
				     struct jffs2_node_frag *this);

void jffs2_add_fd_to_list(struct jffs2_sb_info *c, struct jffs2_full_dirent *new, struct jffs2_full_dirent **list)
{
	struct jffs2_full_dirent **prev = list;

	dbg_dentlist("add dirent \"%s\", ino #%u\n", new->name, new->ino);

	while ((*prev) && (*prev)->nhash <= new->nhash) {
		if ((*prev)->nhash == new->nhash && !strcmp((*prev)->name, new->name)) {
			/* Duplicate. Free one */
			if (new->version < (*prev)->version) {
				dbg_dentlist("Eep! Marking new dirent node obsolete, old is \"%s\", ino #%u\n",
					(*prev)->name, (*prev)->ino);
				jffs2_mark_node_obsolete(c, new->raw);
				jffs2_free_full_dirent(new);
			} else {
				dbg_dentlist("marking old dirent \"%s\", ino #%u obsolete\n",
					(*prev)->name, (*prev)->ino);
				new->next = (*prev)->next;
				/* It may have been a 'placeholder' deletion dirent,
				   if jffs2_can_mark_obsolete() (see jffs2_do_unlink()) */
				if ((*prev)->raw)
					jffs2_mark_node_obsolete(c, ((*prev)->raw));
				jffs2_free_full_dirent(*prev);
				*prev = new;
			}
			return;
		}
		prev = &((*prev)->next);
	}
	new->next = *prev;
	*prev = new;
}

uint32_t jffs2_truncate_fragtree(struct jffs2_sb_info *c, struct rb_root *list, uint32_t size)
{
	struct jffs2_node_frag *frag = jffs2_lookup_node_frag(list, size);

	dbg_fragtree("truncating fragtree to 0x%08x bytes\n", size);

	/* We know frag->ofs <= size. That's what lookup does for us */
	if (frag && frag->ofs != size) {
		if (frag->ofs+frag->size > size) {
			frag->size = size - frag->ofs;
		}
		frag = frag_next(frag);
	}
	while (frag && frag->ofs >= size) {
		struct jffs2_node_frag *next = frag_next(frag);

		frag_erase(frag, list);
		jffs2_obsolete_node_frag(c, frag);
		frag = next;
	}

	if (size == 0)
		return 0;

	frag = frag_last(list);

	/* Sanity check for truncation to longer than we started with... */
	if (!frag)
		return 0;
	if (frag->ofs + frag->size < size)
		return frag->ofs + frag->size;

	/* If the last fragment starts at the RAM page boundary, it is
	 * REF_PRISTINE irrespective of its size. */
	if (frag->node && (frag->ofs & (PAGE_CACHE_SIZE - 1)) == 0) {
		dbg_fragtree2("marking the last fragment 0x%08x-0x%08x REF_PRISTINE.\n",
			frag->ofs, frag->ofs + frag->size);
		frag->node->raw->flash_offset = ref_offset(frag->node->raw) | REF_PRISTINE;
	}
	return size;
}

static void jffs2_obsolete_node_frag(struct jffs2_sb_info *c,
				     struct jffs2_node_frag *this)
{
	if (this->node) {
		this->node->frags--;
		if (!this->node->frags) {
			/* The node has no valid frags left. It's totally obsoleted */
			dbg_fragtree2("marking old node @0x%08x (0x%04x-0x%04x) obsolete\n",
				ref_offset(this->node->raw), this->node->ofs, this->node->ofs+this->node->size);
			jffs2_mark_node_obsolete(c, this->node->raw);
			jffs2_free_full_dnode(this->node);
		} else {
			dbg_fragtree2("marking old node @0x%08x (0x%04x-0x%04x) REF_NORMAL. frags is %d\n",
				ref_offset(this->node->raw), this->node->ofs, this->node->ofs+this->node->size, this->node->frags);
			mark_ref_normal(this->node->raw);
		}

	}
	jffs2_free_node_frag(this);
}

static void jffs2_fragtree_insert(struct jffs2_node_frag *newfrag, struct jffs2_node_frag *base)
{
	struct rb_node *parent = &base->rb;
	struct rb_node **link = &parent;

	dbg_fragtree2("insert frag (0x%04x-0x%04x)\n", newfrag->ofs, newfrag->ofs + newfrag->size);

	while (*link) {
		parent = *link;
		base = rb_entry(parent, struct jffs2_node_frag, rb);

		if (newfrag->ofs > base->ofs)
			link = &base->rb.rb_right;
		else if (newfrag->ofs < base->ofs)
			link = &base->rb.rb_left;
		else {
			JFFS2_ERROR("duplicate frag at %08x (%p,%p)\n", newfrag->ofs, newfrag, base);
			BUG();
		}
	}

	rb_link_node(&newfrag->rb, &base->rb, link);
}

/*
 * Allocate and initializes a new fragment.
 */
static struct jffs2_node_frag * new_fragment(struct jffs2_full_dnode *fn, uint32_t ofs, uint32_t size)
{
	struct jffs2_node_frag *newfrag;

	newfrag = jffs2_alloc_node_frag();
	if (likely(newfrag)) {
		newfrag->ofs = ofs;
		newfrag->size = size;
		newfrag->node = fn;
	} else {
		JFFS2_ERROR("cannot allocate a jffs2_node_frag object\n");
	}

	return newfrag;
}

/*
 * Called when there is no overlapping fragment exist. Inserts a hole before the new
 * fragment and inserts the new fragment to the fragtree.
 */
static int no_overlapping_node(struct jffs2_sb_info *c, struct rb_root *root,
		 	       struct jffs2_node_frag *newfrag,
			       struct jffs2_node_frag *this, uint32_t lastend)
{
	if (lastend < newfrag->node->ofs) {
		/* put a hole in before the new fragment */
		struct jffs2_node_frag *holefrag;

		holefrag= new_fragment(NULL, lastend, newfrag->node->ofs - lastend);
		if (unlikely(!holefrag)) {
			jffs2_free_node_frag(newfrag);
			return -ENOMEM;
		}

		if (this) {
			/* By definition, the 'this' node has no right-hand child,
			   because there are no frags with offset greater than it.
			   So that's where we want to put the hole */
			dbg_fragtree2("add hole frag %#04x-%#04x on the right of the new frag.\n",
				holefrag->ofs, holefrag->ofs + holefrag->size);
			rb_link_node(&holefrag->rb, &this->rb, &this->rb.rb_right);
		} else {
			dbg_fragtree2("Add hole frag %#04x-%#04x to the root of the tree.\n",
				holefrag->ofs, holefrag->ofs + holefrag->size);
			rb_link_node(&holefrag->rb, NULL, &root->rb_node);
		}
		rb_insert_color(&holefrag->rb, root);
		this = holefrag;
	}

	if (this) {
		/* By definition, the 'this' node has no right-hand child,
		   because there are no frags with offset greater than it.
		   So that's where we want to put new fragment */
		dbg_fragtree2("add the new node at the right\n");
		rb_link_node(&newfrag->rb, &this->rb, &this->rb.rb_right);
	} else {
		dbg_fragtree2("insert the new node at the root of the tree\n");
		rb_link_node(&newfrag->rb, NULL, &root->rb_node);
	}
	rb_insert_color(&newfrag->rb, root);

	return 0;
}

/* Doesn't set inode->i_size */
static int jffs2_add_frag_to_fragtree(struct jffs2_sb_info *c, struct rb_root *root, struct jffs2_node_frag *newfrag)
{
	struct jffs2_node_frag *this;
	uint32_t lastend;

	/* Skip all the nodes which are completed before this one starts */
	this = jffs2_lookup_node_frag(root, newfrag->node->ofs);

	if (this) {
		dbg_fragtree2("lookup gave frag 0x%04x-0x%04x; phys 0x%08x (*%p)\n",
			  this->ofs, this->ofs+this->size, this->node?(ref_offset(this->node->raw)):0xffffffff, this);
		lastend = this->ofs + this->size;
	} else {
		dbg_fragtree2("lookup gave no frag\n");
		lastend = 0;
	}

	/* See if we ran off the end of the fragtree */
	if (lastend <= newfrag->ofs) {
		/* We did */

		/* Check if 'this' node was on the same page as the new node.
		   If so, both 'this' and the new node get marked REF_NORMAL so
		   the GC can take a look.
		*/
		if (lastend && (lastend-1) >> PAGE_CACHE_SHIFT == newfrag->ofs >> PAGE_CACHE_SHIFT) {
			if (this->node)
				mark_ref_normal(this->node->raw);
			mark_ref_normal(newfrag->node->raw);
		}

		return no_overlapping_node(c, root, newfrag, this, lastend);
	}

	if (this->node)
		dbg_fragtree2("dealing with frag %u-%u, phys %#08x(%d).\n",
		this->ofs, this->ofs + this->size,
		ref_offset(this->node->raw), ref_flags(this->node->raw));
	else
		dbg_fragtree2("dealing with hole frag %u-%u.\n",
		this->ofs, this->ofs + this->size);

	/* OK. 'this' is pointing at the first frag that newfrag->ofs at least partially obsoletes,
	 * - i.e. newfrag->ofs < this->ofs+this->size && newfrag->ofs >= this->ofs
	 */
	if (newfrag->ofs > this->ofs) {
		/* This node isn't completely obsoleted. The start of it remains valid */

		/* Mark the new node and the partially covered node REF_NORMAL -- let
		   the GC take a look at them */
		mark_ref_normal(newfrag->node->raw);
		if (this->node)
			mark_ref_normal(this->node->raw);

		if (this->ofs + this->size > newfrag->ofs + newfrag->size) {
			/* The new node splits 'this' frag into two */
			struct jffs2_node_frag *newfrag2;

			if (this->node)
				dbg_fragtree2("split old frag 0x%04x-0x%04x, phys 0x%08x\n",
					this->ofs, this->ofs+this->size, ref_offset(this->node->raw));
			else
				dbg_fragtree2("split old hole frag 0x%04x-0x%04x\n",
					this->ofs, this->ofs+this->size);

			/* New second frag pointing to this's node */
			newfrag2 = new_fragment(this->node, newfrag->ofs + newfrag->size,
						this->ofs + this->size - newfrag->ofs - newfrag->size);
			if (unlikely(!newfrag2))
				return -ENOMEM;
			if (this->node)
				this->node->frags++;

			/* Adjust size of original 'this' */
			this->size = newfrag->ofs - this->ofs;

			/* Now, we know there's no node with offset
			   greater than this->ofs but smaller than
			   newfrag2->ofs or newfrag->ofs, for obvious
			   reasons. So we can do a tree insert from
			   'this' to insert newfrag, and a tree insert
			   from newfrag to insert newfrag2. */
			jffs2_fragtree_insert(newfrag, this);
			rb_insert_color(&newfrag->rb, root);

			jffs2_fragtree_insert(newfrag2, newfrag);
			rb_insert_color(&newfrag2->rb, root);

			return 0;
		}
		/* New node just reduces 'this' frag in size, doesn't split it */
		this->size = newfrag->ofs - this->ofs;

		/* Again, we know it lives down here in the tree */
		jffs2_fragtree_insert(newfrag, this);
		rb_insert_color(&newfrag->rb, root);
	} else {
		/* New frag starts at the same point as 'this' used to. Replace
		   it in the tree without doing a delete and insertion */
		dbg_fragtree2("inserting newfrag (*%p),%d-%d in before 'this' (*%p),%d-%d\n",
			  newfrag, newfrag->ofs, newfrag->ofs+newfrag->size, this, this->ofs, this->ofs+this->size);

		rb_replace_node(&this->rb, &newfrag->rb, root);

		if (newfrag->ofs + newfrag->size >= this->ofs+this->size) {
			dbg_fragtree2("obsoleting node frag %p (%x-%x)\n", this, this->ofs, this->ofs+this->size);
			jffs2_obsolete_node_frag(c, this);
		} else {
			this->ofs += newfrag->size;
			this->size -= newfrag->size;

			jffs2_fragtree_insert(this, newfrag);
			rb_insert_color(&this->rb, root);
			return 0;
		}
	}
	/* OK, now we have newfrag added in the correct place in the tree, but
	   frag_next(newfrag) may be a fragment which is overlapped by it
	*/
	while ((this = frag_next(newfrag)) && newfrag->ofs + newfrag->size >= this->ofs + this->size) {
		/* 'this' frag is obsoleted completely. */
		dbg_fragtree2("obsoleting node frag %p (%x-%x) and removing from tree\n",
			this, this->ofs, this->ofs+this->size);
		rb_erase(&this->rb, root);
		jffs2_obsolete_node_frag(c, this);
	}
	/* Now we're pointing at the first frag which isn't totally obsoleted by
	   the new frag */

	if (!this || newfrag->ofs + newfrag->size == this->ofs)
		return 0;

	/* Still some overlap but we don't need to move it in the tree */
	this->size = (this->ofs + this->size) - (newfrag->ofs + newfrag->size);
	this->ofs = newfrag->ofs + newfrag->size;

	/* And mark them REF_NORMAL so the GC takes a look at them */
	if (this->node)
		mark_ref_normal(this->node->raw);
	mark_ref_normal(newfrag->node->raw);

	return 0;
}

/*
 * Given an inode, probably with existing tree of fragments, add the new node
 * to the fragment tree.
 */
int jffs2_add_full_dnode_to_inode(struct jffs2_sb_info *c, struct jffs2_inode_info *f, struct jffs2_full_dnode *fn)
{
	int ret;
	struct jffs2_node_frag *newfrag;

	if (unlikely(!fn->size))
		return 0;

	newfrag = new_fragment(fn, fn->ofs, fn->size);
	if (unlikely(!newfrag))
		return -ENOMEM;
	newfrag->node->frags = 1;

	dbg_fragtree("adding node %#04x-%#04x @0x%08x on flash, newfrag *%p\n",
		  fn->ofs, fn->ofs+fn->size, ref_offset(fn->raw), newfrag);

	ret = jffs2_add_frag_to_fragtree(c, &f->fragtree, newfrag);
	if (unlikely(ret))
		return ret;

	/* If we now share a page with other nodes, mark either previous
	   or next node REF_NORMAL, as appropriate.  */
	if (newfrag->ofs & (PAGE_CACHE_SIZE-1)) {
		struct jffs2_node_frag *prev = frag_prev(newfrag);

		mark_ref_normal(fn->raw);
		/* If we don't start at zero there's _always_ a previous */
		if (prev->node)
			mark_ref_normal(prev->node->raw);
	}

	if ((newfrag->ofs+newfrag->size) & (PAGE_CACHE_SIZE-1)) {
		struct jffs2_node_frag *next = frag_next(newfrag);

		if (next) {
			mark_ref_normal(fn->raw);
			if (next->node)
				mark_ref_normal(next->node->raw);
		}
	}
	jffs2_dbg_fragtree_paranoia_check_nolock(f);

	return 0;
}

void jffs2_set_inocache_state(struct jffs2_sb_info *c, struct jffs2_inode_cache *ic, int state)
{
	spin_lock(&c->inocache_lock);
	ic->state = state;
	wake_up(&c->inocache_wq);
	spin_unlock(&c->inocache_lock);
}

/* During mount, this needs no locking. During normal operation, its
   callers want to do other stuff while still holding the inocache_lock.
   Rather than introducing special case get_ino_cache functions or
   callbacks, we just let the caller do the locking itself. */

struct jffs2_inode_cache *jffs2_get_ino_cache(struct jffs2_sb_info *c, uint32_t ino)
{
	struct jffs2_inode_cache *ret;

	ret = c->inocache_list[ino % c->inocache_hashsize];
	while (ret && ret->ino < ino) {
		ret = ret->next;
	}

	if (ret && ret->ino != ino)
		ret = NULL;

	return ret;
}

void jffs2_add_ino_cache (struct jffs2_sb_info *c, struct jffs2_inode_cache *new)
{
	struct jffs2_inode_cache **prev;

	spin_lock(&c->inocache_lock);
	if (!new->ino)
		new->ino = ++c->highest_ino;

	dbg_inocache("add %p (ino #%u)\n", new, new->ino);

	prev = &c->inocache_list[new->ino % c->inocache_hashsize];

	while ((*prev) && (*prev)->ino < new->ino) {
		prev = &(*prev)->next;
	}
	new->next = *prev;
	*prev = new;

	spin_unlock(&c->inocache_lock);
}

void jffs2_del_ino_cache(struct jffs2_sb_info *c, struct jffs2_inode_cache *old)
{
	struct jffs2_inode_cache **prev;

#ifdef CONFIG_JFFS2_FS_XATTR
	BUG_ON(old->xref);
#endif
	dbg_inocache("del %p (ino #%u)\n", old, old->ino);
	spin_lock(&c->inocache_lock);

	prev = &c->inocache_list[old->ino % c->inocache_hashsize];

	while ((*prev) && (*prev)->ino < old->ino) {
		prev = &(*prev)->next;
	}
	if ((*prev) == old) {
		*prev = old->next;
	}

	/* Free it now unless it's in READING or CLEARING state, which
	   are the transitions upon read_inode() and clear_inode(). The
	   rest of the time we know nobody else is looking at it, and
	   if it's held by read_inode() or clear_inode() they'll free it
	   for themselves. */
	if (old->state != INO_STATE_READING && old->state != INO_STATE_CLEARING)
		jffs2_free_inode_cache(old);

	spin_unlock(&c->inocache_lock);
}

void jffs2_free_ino_caches(struct jffs2_sb_info *c)
{
	int i;
	struct jffs2_inode_cache *this, *next;

	for (i=0; i < c->inocache_hashsize; i++) {
		this = c->inocache_list[i];
		while (this) {
			next = this->next;
			jffs2_xattr_free_inode(c, this);
			jffs2_free_inode_cache(this);
			this = next;
		}
		c->inocache_list[i] = NULL;
	}
}

void jffs2_free_raw_node_refs(struct jffs2_sb_info *c)
{
	int i;
	struct jffs2_raw_node_ref *this, *next;

	for (i=0; i<c->nr_blocks; i++) {
		this = c->blocks[i].first_node;
		while (this) {
			if (this[REFS_PER_BLOCK].flash_offset == REF_LINK_NODE)
				next = this[REFS_PER_BLOCK].next_in_ino;
			else
				next = NULL;

			jffs2_free_refblock(this);
			this = next;
		}
		c->blocks[i].first_node = c->blocks[i].last_node = NULL;
	}
}

struct jffs2_node_frag *jffs2_lookup_node_frag(struct rb_root *fragtree, uint32_t offset)
{
	/* The common case in lookup is that there will be a node
	   which precisely matches. So we go looking for that first */
	struct rb_node *next;
	struct jffs2_node_frag *prev = NULL;
	struct jffs2_node_frag *frag = NULL;

	dbg_fragtree2("root %p, offset %d\n", fragtree, offset);

	next = fragtree->rb_node;

	while(next) {
		frag = rb_entry(next, struct jffs2_node_frag, rb);

		if (frag->ofs + frag->size <= offset) {
			/* Remember the closest smaller match on the way down */
			if (!prev || frag->ofs > prev->ofs)
				prev = frag;
			next = frag->rb.rb_right;
		} else if (frag->ofs > offset) {
			next = frag->rb.rb_left;
		} else {
			return frag;
		}
	}

	/* Exact match not found. Go back up looking at each parent,
	   and return the closest smaller one */

	if (prev)
		dbg_fragtree2("no match. Returning frag %#04x-%#04x, closest previous\n",
			  prev->ofs, prev->ofs+prev->size);
	else
		dbg_fragtree2("returning NULL, empty fragtree\n");

	return prev;
}

/* Pass 'c' argument to indicate that nodes should be marked obsolete as
   they're killed. */
void jffs2_kill_fragtree(struct rb_root *root, struct jffs2_sb_info *c)
{
	struct jffs2_node_frag *frag, *next;

	dbg_fragtree("killing\n");
	rbtree_postorder_for_each_entry_safe(frag, next, root, rb) {
		if (frag->node && !(--frag->node->frags)) {
			/* Not a hole, and it's the final remaining frag
			   of this node. Free the node */
			if (c)
				jffs2_mark_node_obsolete(c, frag->node->raw);

			jffs2_free_full_dnode(frag->node);
		}

		jffs2_free_node_frag(frag);
		cond_resched();
	}
}

struct jffs2_raw_node_ref *jffs2_link_node_ref(struct jffs2_sb_info *c,
					       struct jffs2_eraseblock *jeb,
					       uint32_t ofs, uint32_t len,
					       struct jffs2_inode_cache *ic)
{
	struct jffs2_raw_node_ref *ref;

	BUG_ON(!jeb->allocated_refs);
	jeb->allocated_refs--;

	ref = jeb->last_node;

	dbg_noderef("Last node at %p is (%08x,%p)\n", ref, ref->flash_offset,
		    ref->next_in_ino);

	while (ref->flash_offset != REF_EMPTY_NODE) {
		if (ref->flash_offset == REF_LINK_NODE)
			ref = ref->next_in_ino;
		else
			ref++;
	}

	dbg_noderef("New ref is %p (%08x becomes %08x,%p) len 0x%x\n", ref,
		    ref->flash_offset, ofs, ref->next_in_ino, len);

	ref->flash_offset = ofs;

	if (!jeb->first_node) {
		jeb->first_node = ref;
		BUG_ON(ref_offset(ref) != jeb->offset);
	} else if (unlikely(ref_offset(ref) != jeb->offset + c->sector_size - jeb->free_size)) {
		uint32_t last_len = ref_totlen(c, jeb, jeb->last_node);

		JFFS2_ERROR("Adding new ref %p at (0x%08x-0x%08x) not immediately after previous (0x%08x-0x%08x)\n",
			    ref, ref_offset(ref), ref_offset(ref)+len,
			    ref_offset(jeb->last_node),
			    ref_offset(jeb->last_node)+last_len);
		BUG();
	}
	jeb->last_node = ref;

	if (ic) {
		ref->next_in_ino = ic->nodes;
		ic->nodes = ref;
	} else {
		ref->next_in_ino = NULL;
	}

	switch(ref_flags(ref)) {
	case REF_UNCHECKED:
		c->unchecked_size += len;
		jeb->unchecked_size += len;
		break;

	case REF_NORMAL:
	case REF_PRISTINE:
		c->used_size += len;
		jeb->used_size += len;
		break;

	case REF_OBSOLETE:
		c->dirty_size += len;
		jeb->dirty_size += len;
		break;
	}
	c->free_size -= len;
	jeb->free_size -= len;

#ifdef TEST_TOTLEN
	/* Set (and test) __totlen field... for now */
	ref->__totlen = len;
	ref_totlen(c, jeb, ref);
#endif
	return ref;
}

/* No locking, no reservation of 'ref'. Do not use on a live file system */
int jffs2_scan_dirty_space(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
			   uint32_t size)
{
	if (!size)
		return 0;
	if (unlikely(size > jeb->free_size)) {
		pr_crit("Dirty space 0x%x larger then free_size 0x%x (wasted 0x%x)\n",
			size, jeb->free_size, jeb->wasted_size);
		BUG();
	}
	/* REF_EMPTY_NODE is !obsolete, so that works OK */
	if (jeb->last_node && ref_obsolete(jeb->last_node)) {
#ifdef TEST_TOTLEN
		jeb->last_node->__totlen += size;
#endif
		c->dirty_size += size;
		c->free_size -= size;
		jeb->dirty_size += size;
		jeb->free_size -= size;
	} else {
		uint32_t ofs = jeb->offset + c->sector_size - jeb->free_size;
		ofs |= REF_OBSOLETE;

		jffs2_link_node_ref(c, jeb, ofs, size, NULL);
	}

	return 0;
}

/* Calculate totlen from surrounding nodes or eraseblock */
static inline uint32_t __ref_totlen(struct jffs2_sb_info *c,
				    struct jffs2_eraseblock *jeb,
				    struct jffs2_raw_node_ref *ref)
{
	uint32_t ref_end;
	struct jffs2_raw_node_ref *next_ref = ref_next(ref);

	if (next_ref)
		ref_end = ref_offset(next_ref);
	else {
		if (!jeb)
			jeb = &c->blocks[ref->flash_offset / c->sector_size];

		/* Last node in block. Use free_space */
		if (unlikely(ref != jeb->last_node)) {
			pr_crit("ref %p @0x%08x is not jeb->last_node (%p @0x%08x)\n",
				ref, ref_offset(ref), jeb->last_node,
				jeb->last_node ?
				ref_offset(jeb->last_node) : 0);
			BUG();
		}
		ref_end = jeb->offset + c->sector_size - jeb->free_size;
	}
	return ref_end - ref_offset(ref);
}

uint32_t __jffs2_ref_totlen(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
			    struct jffs2_raw_node_ref *ref)
{
	uint32_t ret;

	ret = __ref_totlen(c, jeb, ref);

#ifdef TEST_TOTLEN
	if (unlikely(ret != ref->__totlen)) {
		if (!jeb)
			jeb = &c->blocks[ref->flash_offset / c->sector_size];

		pr_crit("Totlen for ref at %p (0x%08x-0x%08x) miscalculated as 0x%x instead of %x\n",
			ref, ref_offset(ref), ref_offset(ref) + ref->__totlen,
			ret, ref->__totlen);
		if (ref_next(ref)) {
			pr_crit("next %p (0x%08x-0x%08x)\n",
				ref_next(ref), ref_offset(ref_next(ref)),
				ref_offset(ref_next(ref)) + ref->__totlen);
		} else
			pr_crit("No next ref. jeb->last_node is %p\n",
				jeb->last_node);

		pr_crit("jeb->wasted_size %x, dirty_size %x, used_size %x, free_size %x\n",
			jeb->wasted_size, jeb->dirty_size, jeb->used_size,
			jeb->free_size);

#if defined(JFFS2_DBG_DUMPS) || defined(JFFS2_DBG_PARANOIA_CHECKS)
		__jffs2_dbg_dump_node_refs_nolock(c, jeb);
#endif

		WARN_ON(1);

		ret = ref->__totlen;
	}
#endif /* TEST_TOTLEN */
	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/nodelist.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/slab.h>
#include <linux/init.h>
// #include <linux/jffs2.h>
// #include "nodelist.h"

/* These are initialised to NULL in the kernel startup code.
   If you're porting to other operating systems, beware */
static struct kmem_cache *full_dnode_slab;
static struct kmem_cache *raw_dirent_slab;
static struct kmem_cache *raw_inode_slab;
static struct kmem_cache *tmp_dnode_info_slab;
static struct kmem_cache *raw_node_ref_slab;
static struct kmem_cache *node_frag_slab;
static struct kmem_cache *inode_cache_slab;
#ifdef CONFIG_JFFS2_FS_XATTR
static struct kmem_cache *xattr_datum_cache;
static struct kmem_cache *xattr_ref_cache;
#endif

int __init jffs2_create_slab_caches(void)
{
	full_dnode_slab = kmem_cache_create("jffs2_full_dnode",
					    sizeof(struct jffs2_full_dnode),
					    0, 0, NULL);
	if (!full_dnode_slab)
		goto err;

	raw_dirent_slab = kmem_cache_create("jffs2_raw_dirent",
					    sizeof(struct jffs2_raw_dirent),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!raw_dirent_slab)
		goto err;

	raw_inode_slab = kmem_cache_create("jffs2_raw_inode",
					   sizeof(struct jffs2_raw_inode),
					   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!raw_inode_slab)
		goto err;

	tmp_dnode_info_slab = kmem_cache_create("jffs2_tmp_dnode",
						sizeof(struct jffs2_tmp_dnode_info),
						0, 0, NULL);
	if (!tmp_dnode_info_slab)
		goto err;

	raw_node_ref_slab = kmem_cache_create("jffs2_refblock",
					      sizeof(struct jffs2_raw_node_ref) * (REFS_PER_BLOCK + 1),
					      0, 0, NULL);
	if (!raw_node_ref_slab)
		goto err;

	node_frag_slab = kmem_cache_create("jffs2_node_frag",
					   sizeof(struct jffs2_node_frag),
					   0, 0, NULL);
	if (!node_frag_slab)
		goto err;

	inode_cache_slab = kmem_cache_create("jffs2_inode_cache",
					     sizeof(struct jffs2_inode_cache),
					     0, 0, NULL);
	if (!inode_cache_slab)
		goto err;

#ifdef CONFIG_JFFS2_FS_XATTR
	xattr_datum_cache = kmem_cache_create("jffs2_xattr_datum",
					     sizeof(struct jffs2_xattr_datum),
					     0, 0, NULL);
	if (!xattr_datum_cache)
		goto err;

	xattr_ref_cache = kmem_cache_create("jffs2_xattr_ref",
					   sizeof(struct jffs2_xattr_ref),
					   0, 0, NULL);
	if (!xattr_ref_cache)
		goto err;
#endif

	return 0;
 err:
	jffs2_destroy_slab_caches();
	return -ENOMEM;
}

void jffs2_destroy_slab_caches(void)
{
	if(full_dnode_slab)
		kmem_cache_destroy(full_dnode_slab);
	if(raw_dirent_slab)
		kmem_cache_destroy(raw_dirent_slab);
	if(raw_inode_slab)
		kmem_cache_destroy(raw_inode_slab);
	if(tmp_dnode_info_slab)
		kmem_cache_destroy(tmp_dnode_info_slab);
	if(raw_node_ref_slab)
		kmem_cache_destroy(raw_node_ref_slab);
	if(node_frag_slab)
		kmem_cache_destroy(node_frag_slab);
	if(inode_cache_slab)
		kmem_cache_destroy(inode_cache_slab);
#ifdef CONFIG_JFFS2_FS_XATTR
	if (xattr_datum_cache)
		kmem_cache_destroy(xattr_datum_cache);
	if (xattr_ref_cache)
		kmem_cache_destroy(xattr_ref_cache);
#endif
}

struct jffs2_full_dirent *jffs2_alloc_full_dirent(int namesize)
{
	struct jffs2_full_dirent *ret;
	ret = kmalloc(sizeof(struct jffs2_full_dirent) + namesize, GFP_KERNEL);
	dbg_memalloc("%p\n", ret);
	return ret;
}

void jffs2_free_full_dirent(struct jffs2_full_dirent *x)
{
	dbg_memalloc("%p\n", x);
	kfree(x);
}

struct jffs2_full_dnode *jffs2_alloc_full_dnode(void)
{
	struct jffs2_full_dnode *ret;
	ret = kmem_cache_alloc(full_dnode_slab, GFP_KERNEL);
	dbg_memalloc("%p\n", ret);
	return ret;
}

void jffs2_free_full_dnode(struct jffs2_full_dnode *x)
{
	dbg_memalloc("%p\n", x);
	kmem_cache_free(full_dnode_slab, x);
}

struct jffs2_raw_dirent *jffs2_alloc_raw_dirent(void)
{
	struct jffs2_raw_dirent *ret;
	ret = kmem_cache_alloc(raw_dirent_slab, GFP_KERNEL);
	dbg_memalloc("%p\n", ret);
	return ret;
}

void jffs2_free_raw_dirent(struct jffs2_raw_dirent *x)
{
	dbg_memalloc("%p\n", x);
	kmem_cache_free(raw_dirent_slab, x);
}

struct jffs2_raw_inode *jffs2_alloc_raw_inode(void)
{
	struct jffs2_raw_inode *ret;
	ret = kmem_cache_alloc(raw_inode_slab, GFP_KERNEL);
	dbg_memalloc("%p\n", ret);
	return ret;
}

void jffs2_free_raw_inode(struct jffs2_raw_inode *x)
{
	dbg_memalloc("%p\n", x);
	kmem_cache_free(raw_inode_slab, x);
}

struct jffs2_tmp_dnode_info *jffs2_alloc_tmp_dnode_info(void)
{
	struct jffs2_tmp_dnode_info *ret;
	ret = kmem_cache_alloc(tmp_dnode_info_slab, GFP_KERNEL);
	dbg_memalloc("%p\n",
		ret);
	return ret;
}

void jffs2_free_tmp_dnode_info(struct jffs2_tmp_dnode_info *x)
{
	dbg_memalloc("%p\n", x);
	kmem_cache_free(tmp_dnode_info_slab, x);
}

static struct jffs2_raw_node_ref *jffs2_alloc_refblock(void)
{
	struct jffs2_raw_node_ref *ret;

	ret = kmem_cache_alloc(raw_node_ref_slab, GFP_KERNEL);
	if (ret) {
		int i = 0;
		for (i=0; i < REFS_PER_BLOCK; i++) {
			ret[i].flash_offset = REF_EMPTY_NODE;
			ret[i].next_in_ino = NULL;
		}
		ret[i].flash_offset = REF_LINK_NODE;
		ret[i].next_in_ino = NULL;
	}
	return ret;
}

int jffs2_prealloc_raw_node_refs(struct jffs2_sb_info *c,
				 struct jffs2_eraseblock *jeb, int nr)
{
	struct jffs2_raw_node_ref **p, *ref;
	int i = nr;

	dbg_memalloc("%d\n", nr);

	p = &jeb->last_node;
	ref = *p;

	dbg_memalloc("Reserving %d refs for block @0x%08x\n", nr, jeb->offset);

	/* If jeb->last_node is really a valid node then skip over it */
	if (ref && ref->flash_offset != REF_EMPTY_NODE)
		ref++;

	while (i) {
		if (!ref) {
			dbg_memalloc("Allocating new refblock linked from %p\n", p);
			ref = *p = jffs2_alloc_refblock();
			if (!ref)
				return -ENOMEM;
		}
		if (ref->flash_offset == REF_LINK_NODE) {
			p = &ref->next_in_ino;
			ref = *p;
			continue;
		}
		i--;
		ref++;
	}
	jeb->allocated_refs = nr;

	dbg_memalloc("Reserved %d refs for block @0x%08x, last_node is %p (%08x,%p)\n",
		  nr, jeb->offset, jeb->last_node, jeb->last_node->flash_offset,
		  jeb->last_node->next_in_ino);

	return 0;
}

void jffs2_free_refblock(struct jffs2_raw_node_ref *x)
{
	dbg_memalloc("%p\n", x);
	kmem_cache_free(raw_node_ref_slab, x);
}

struct jffs2_node_frag *jffs2_alloc_node_frag(void)
{
	struct jffs2_node_frag *ret;
	ret = kmem_cache_alloc(node_frag_slab, GFP_KERNEL);
	dbg_memalloc("%p\n", ret);
	return ret;
}

void jffs2_free_node_frag(struct jffs2_node_frag *x)
{
	dbg_memalloc("%p\n", x);
	kmem_cache_free(node_frag_slab, x);
}

struct jffs2_inode_cache *jffs2_alloc_inode_cache(void)
{
	struct jffs2_inode_cache *ret;
	ret = kmem_cache_alloc(inode_cache_slab, GFP_KERNEL);
	dbg_memalloc("%p\n", ret);
	return ret;
}

void jffs2_free_inode_cache(struct jffs2_inode_cache *x)
{
	dbg_memalloc("%p\n", x);
	kmem_cache_free(inode_cache_slab, x);
}

#ifdef CONFIG_JFFS2_FS_XATTR
struct jffs2_xattr_datum *jffs2_alloc_xattr_datum(void)
{
	struct jffs2_xattr_datum *xd;
	xd = kmem_cache_zalloc(xattr_datum_cache, GFP_KERNEL);
	dbg_memalloc("%p\n", xd);
	if (!xd)
		return NULL;

	xd->class = RAWNODE_CLASS_XATTR_DATUM;
	xd->node = (void *)xd;
	INIT_LIST_HEAD(&xd->xindex);
	return xd;
}

void jffs2_free_xattr_datum(struct jffs2_xattr_datum *xd)
{
	dbg_memalloc("%p\n", xd);
	kmem_cache_free(xattr_datum_cache, xd);
}

struct jffs2_xattr_ref *jffs2_alloc_xattr_ref(void)
{
	struct jffs2_xattr_ref *ref;
	ref = kmem_cache_zalloc(xattr_ref_cache, GFP_KERNEL);
	dbg_memalloc("%p\n", ref);
	if (!ref)
		return NULL;

	ref->class = RAWNODE_CLASS_XATTR_REF;
	ref->node = (void *)ref;
	return ref;
}

void jffs2_free_xattr_ref(struct jffs2_xattr_ref *ref)
{
	dbg_memalloc("%p\n", ref);
	kmem_cache_free(xattr_ref_cache, ref);
}
#endif
/************************************************************/
/* ../linux-3.17/fs/jffs2/malloc.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/slab.h>
// #include <linux/crc32.h>
// #include <linux/pagemap.h>
// #include <linux/mtd/mtd.h>
#include <linux/compiler.h>
// #include "nodelist.h"
// #include "compr.h"

int jffs2_read_dnode(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
		     struct jffs2_full_dnode *fd, unsigned char *buf,
		     int ofs, int len)
{
	struct jffs2_raw_inode *ri;
	size_t readlen;
	uint32_t crc;
	unsigned char *decomprbuf = NULL;
	unsigned char *readbuf = NULL;
	int ret = 0;

	ri = jffs2_alloc_raw_inode();
	if (!ri)
		return -ENOMEM;

	ret = jffs2_flash_read(c, ref_offset(fd->raw), sizeof(*ri), &readlen, (char *)ri);
	if (ret) {
		jffs2_free_raw_inode(ri);
		pr_warn("Error reading node from 0x%08x: %d\n",
			ref_offset(fd->raw), ret);
		return ret;
	}
	if (readlen != sizeof(*ri)) {
		jffs2_free_raw_inode(ri);
		pr_warn("Short read from 0x%08x: wanted 0x%zx bytes, got 0x%zx\n",
			ref_offset(fd->raw), sizeof(*ri), readlen);
		return -EIO;
	}
	crc = crc32(0, ri, sizeof(*ri)-8);

	jffs2_dbg(1, "Node read from %08x: node_crc %08x, calculated CRC %08x. dsize %x, csize %x, offset %x, buf %p\n",
		  ref_offset(fd->raw), je32_to_cpu(ri->node_crc),
		  crc, je32_to_cpu(ri->dsize), je32_to_cpu(ri->csize),
		  je32_to_cpu(ri->offset), buf);
	if (crc != je32_to_cpu(ri->node_crc)) {
		pr_warn("Node CRC %08x != calculated CRC %08x for node at %08x\n",
			je32_to_cpu(ri->node_crc), crc, ref_offset(fd->raw));
		ret = -EIO;
		goto out_ri;
	}
	/* There was a bug where we wrote hole nodes out with csize/dsize
	   swapped. Deal with it */
	if (ri->compr == JFFS2_COMPR_ZERO && !je32_to_cpu(ri->dsize) &&
	    je32_to_cpu(ri->csize)) {
		ri->dsize = ri->csize;
		ri->csize = cpu_to_je32(0);
	}

	D1(if(ofs + len > je32_to_cpu(ri->dsize)) {
			pr_warn("jffs2_read_dnode() asked for %d bytes at %d from %d-byte node\n",
				len, ofs, je32_to_cpu(ri->dsize));
		ret = -EINVAL;
		goto out_ri;
	});


	if (ri->compr == JFFS2_COMPR_ZERO) {
		memset(buf, 0, len);
		goto out_ri;
	}

	/* Cases:
	   Reading whole node and it's uncompressed - read directly to buffer provided, check CRC.
	   Reading whole node and it's compressed - read into comprbuf, check CRC and decompress to buffer provided
	   Reading partial node and it's uncompressed - read into readbuf, check CRC, and copy
	   Reading partial node and it's compressed - read into readbuf, check checksum, decompress to decomprbuf and copy
	*/
	if (ri->compr == JFFS2_COMPR_NONE && len == je32_to_cpu(ri->dsize)) {
		readbuf = buf;
	} else {
		readbuf = kmalloc(je32_to_cpu(ri->csize), GFP_KERNEL);
		if (!readbuf) {
			ret = -ENOMEM;
			goto out_ri;
		}
	}
	if (ri->compr != JFFS2_COMPR_NONE) {
		if (len < je32_to_cpu(ri->dsize)) {
			decomprbuf = kmalloc(je32_to_cpu(ri->dsize), GFP_KERNEL);
			if (!decomprbuf) {
				ret = -ENOMEM;
				goto out_readbuf;
			}
		} else {
			decomprbuf = buf;
		}
	} else {
		decomprbuf = readbuf;
	}

	jffs2_dbg(2, "Read %d bytes to %p\n", je32_to_cpu(ri->csize),
		  readbuf);
	ret = jffs2_flash_read(c, (ref_offset(fd->raw)) + sizeof(*ri),
			       je32_to_cpu(ri->csize), &readlen, readbuf);

	if (!ret && readlen != je32_to_cpu(ri->csize))
		ret = -EIO;
	if (ret)
		goto out_decomprbuf;

	crc = crc32(0, readbuf, je32_to_cpu(ri->csize));
	if (crc != je32_to_cpu(ri->data_crc)) {
		pr_warn("Data CRC %08x != calculated CRC %08x for node at %08x\n",
			je32_to_cpu(ri->data_crc), crc, ref_offset(fd->raw));
		ret = -EIO;
		goto out_decomprbuf;
	}
	jffs2_dbg(2, "Data CRC matches calculated CRC %08x\n", crc);
	if (ri->compr != JFFS2_COMPR_NONE) {
		jffs2_dbg(2, "Decompress %d bytes from %p to %d bytes at %p\n",
			  je32_to_cpu(ri->csize), readbuf,
			  je32_to_cpu(ri->dsize), decomprbuf);
		ret = jffs2_decompress(c, f, ri->compr | (ri->usercompr << 8), readbuf, decomprbuf, je32_to_cpu(ri->csize), je32_to_cpu(ri->dsize));
		if (ret) {
			pr_warn("Error: jffs2_decompress returned %d\n", ret);
			goto out_decomprbuf;
		}
	}

	if (len < je32_to_cpu(ri->dsize)) {
		memcpy(buf, decomprbuf+ofs, len);
	}
 out_decomprbuf:
	if(decomprbuf != buf && decomprbuf != readbuf)
		kfree(decomprbuf);
 out_readbuf:
	if(readbuf != buf)
		kfree(readbuf);
 out_ri:
	jffs2_free_raw_inode(ri);

	return ret;
}

int jffs2_read_inode_range(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
			   unsigned char *buf, uint32_t offset, uint32_t len)
{
	uint32_t end = offset + len;
	struct jffs2_node_frag *frag;
	int ret;

	jffs2_dbg(1, "%s(): ino #%u, range 0x%08x-0x%08x\n",
		  __func__, f->inocache->ino, offset, offset + len);

	frag = jffs2_lookup_node_frag(&f->fragtree, offset);

	/* XXX FIXME: Where a single physical node actually shows up in two
	   frags, we read it twice. Don't do that. */
	/* Now we're pointing at the first frag which overlaps our page
	 * (or perhaps is before it, if we've been asked to read off the
	 * end of the file). */
	while(offset < end) {
		jffs2_dbg(2, "%s(): offset %d, end %d\n",
			  __func__, offset, end);
		if (unlikely(!frag || frag->ofs > offset ||
			     frag->ofs + frag->size <= offset)) {
			uint32_t holesize = end - offset;
			if (frag && frag->ofs > offset) {
				jffs2_dbg(1, "Eep. Hole in ino #%u fraglist. frag->ofs = 0x%08x, offset = 0x%08x\n",
					  f->inocache->ino, frag->ofs, offset);
				holesize = min(holesize, frag->ofs - offset);
			}
			jffs2_dbg(1, "Filling non-frag hole from %d-%d\n",
				  offset, offset + holesize);
			memset(buf, 0, holesize);
			buf += holesize;
			offset += holesize;
			continue;
		} else if (unlikely(!frag->node)) {
			uint32_t holeend = min(end, frag->ofs + frag->size);
			jffs2_dbg(1, "Filling frag hole from %d-%d (frag 0x%x 0x%x)\n",
				  offset, holeend, frag->ofs,
				  frag->ofs + frag->size);
			memset(buf, 0, holeend - offset);
			buf += holeend - offset;
			offset = holeend;
			frag = frag_next(frag);
			continue;
		} else {
			uint32_t readlen;
			uint32_t fragofs; /* offset within the frag to start reading */

			fragofs = offset - frag->ofs;
			readlen = min(frag->size - fragofs, end - offset);
			jffs2_dbg(1, "Reading %d-%d from node at 0x%08x (%d)\n",
				  frag->ofs+fragofs,
				  frag->ofs + fragofs+readlen,
				  ref_offset(frag->node->raw),
				  ref_flags(frag->node->raw));
			ret = jffs2_read_dnode(c, f, frag->node, buf, fragofs + frag->ofs - frag->node->ofs, readlen);
			jffs2_dbg(2, "node read done\n");
			if (ret) {
				jffs2_dbg(1, "%s(): error %d\n",
					  __func__, ret);
				memset(buf, 0, readlen);
				return ret;
			}
			buf += readlen;
			offset += readlen;
			frag = frag_next(frag);
			jffs2_dbg(2, "node read was OK. Looping\n");
		}
	}
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/read.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/mtd/mtd.h>
// #include <linux/compiler.h>
// #include <linux/sched.h> /* For cond_resched() */
// #include "nodelist.h"
#include "debug.h"

/*
 * Check whether the user is allowed to write.
 */
static int jffs2_rp_can_write(struct jffs2_sb_info *c)
{
	uint32_t avail;
	struct jffs2_mount_opts *opts = &c->mount_opts;

	avail = c->dirty_size + c->free_size + c->unchecked_size +
		c->erasing_size - c->resv_blocks_write * c->sector_size
		- c->nospc_dirty_size;

	if (avail < 2 * opts->rp_size)
		jffs2_dbg(1, "rpsize %u, dirty_size %u, free_size %u, "
			  "erasing_size %u, unchecked_size %u, "
			  "nr_erasing_blocks %u, avail %u, resrv %u\n",
			  opts->rp_size, c->dirty_size, c->free_size,
			  c->erasing_size, c->unchecked_size,
			  c->nr_erasing_blocks, avail, c->nospc_dirty_size);

	if (avail > opts->rp_size)
		return 1;

	/* Always allow root */
	if (capable(CAP_SYS_RESOURCE))
		return 1;

	jffs2_dbg(1, "forbid writing\n");
	return 0;
}

/**
 *	jffs2_reserve_space - request physical space to write nodes to flash
 *	@c: superblock info
 *	@minsize: Minimum acceptable size of allocation
 *	@len: Returned value of allocation length
 *	@prio: Allocation type - ALLOC_{NORMAL,DELETION}
 *
 *	Requests a block of physical space on the flash. Returns zero for success
 *	and puts 'len' into the appropriate place, or returns -ENOSPC or other
 *	error if appropriate. Doesn't return len since that's
 *
 *	If it returns zero, jffs2_reserve_space() also downs the per-filesystem
 *	allocation semaphore, to prevent more than one allocation from being
 *	active at any time. The semaphore is later released by jffs2_commit_allocation()
 *
 *	jffs2_reserve_space() may trigger garbage collection in order to make room
 *	for the requested allocation.
 */

static int jffs2_do_reserve_space(struct jffs2_sb_info *c,  uint32_t minsize,
				  uint32_t *len, uint32_t sumsize);

int jffs2_reserve_space(struct jffs2_sb_info *c, uint32_t minsize,
			uint32_t *len, int prio, uint32_t sumsize)
{
	int ret = -EAGAIN;
	int blocksneeded = c->resv_blocks_write;
	/* align it */
	minsize = PAD(minsize);

	jffs2_dbg(1, "%s(): Requested 0x%x bytes\n", __func__, minsize);
	mutex_lock(&c->alloc_sem);

	jffs2_dbg(1, "%s(): alloc sem got\n", __func__);

	spin_lock(&c->erase_completion_lock);

	/*
	 * Check if the free space is greater then size of the reserved pool.
	 * If not, only allow root to proceed with writing.
	 */
	if (prio != ALLOC_DELETION && !jffs2_rp_can_write(c)) {
		ret = -ENOSPC;
		goto out;
	}

	/* this needs a little more thought (true <tglx> :)) */
	while(ret == -EAGAIN) {
		while(c->nr_free_blocks + c->nr_erasing_blocks < blocksneeded) {
			uint32_t dirty, avail;

			/* calculate real dirty size
			 * dirty_size contains blocks on erase_pending_list
			 * those blocks are counted in c->nr_erasing_blocks.
			 * If one block is actually erased, it is not longer counted as dirty_space
			 * but it is counted in c->nr_erasing_blocks, so we add it and subtract it
			 * with c->nr_erasing_blocks * c->sector_size again.
			 * Blocks on erasable_list are counted as dirty_size, but not in c->nr_erasing_blocks
			 * This helps us to force gc and pick eventually a clean block to spread the load.
			 * We add unchecked_size here, as we hopefully will find some space to use.
			 * This will affect the sum only once, as gc first finishes checking
			 * of nodes.
			 */
			dirty = c->dirty_size + c->erasing_size - c->nr_erasing_blocks * c->sector_size + c->unchecked_size;
			if (dirty < c->nospc_dirty_size) {
				if (prio == ALLOC_DELETION && c->nr_free_blocks + c->nr_erasing_blocks >= c->resv_blocks_deletion) {
					jffs2_dbg(1, "%s(): Low on dirty space to GC, but it's a deletion. Allowing...\n",
						  __func__);
					break;
				}
				jffs2_dbg(1, "dirty size 0x%08x + unchecked_size 0x%08x < nospc_dirty_size 0x%08x, returning -ENOSPC\n",
					  dirty, c->unchecked_size,
					  c->sector_size);

				spin_unlock(&c->erase_completion_lock);
				mutex_unlock(&c->alloc_sem);
				return -ENOSPC;
			}

			/* Calc possibly available space. Possibly available means that we
			 * don't know, if unchecked size contains obsoleted nodes, which could give us some
			 * more usable space. This will affect the sum only once, as gc first finishes checking
			 * of nodes.
			 + Return -ENOSPC, if the maximum possibly available space is less or equal than
			 * blocksneeded * sector_size.
			 * This blocks endless gc looping on a filesystem, which is nearly full, even if
			 * the check above passes.
			 */
			avail = c->free_size + c->dirty_size + c->erasing_size + c->unchecked_size;
			if ( (avail / c->sector_size) <= blocksneeded) {
				if (prio == ALLOC_DELETION && c->nr_free_blocks + c->nr_erasing_blocks >= c->resv_blocks_deletion) {
					jffs2_dbg(1, "%s(): Low on possibly available space, but it's a deletion. Allowing...\n",
						  __func__);
					break;
				}

				jffs2_dbg(1, "max. available size 0x%08x  < blocksneeded * sector_size 0x%08x, returning -ENOSPC\n",
					  avail, blocksneeded * c->sector_size);
				spin_unlock(&c->erase_completion_lock);
				mutex_unlock(&c->alloc_sem);
				return -ENOSPC;
			}

			mutex_unlock(&c->alloc_sem);

			jffs2_dbg(1, "Triggering GC pass. nr_free_blocks %d, nr_erasing_blocks %d, free_size 0x%08x, dirty_size 0x%08x, wasted_size 0x%08x, used_size 0x%08x, erasing_size 0x%08x, bad_size 0x%08x (total 0x%08x of 0x%08x)\n",
				  c->nr_free_blocks, c->nr_erasing_blocks,
				  c->free_size, c->dirty_size, c->wasted_size,
				  c->used_size, c->erasing_size, c->bad_size,
				  c->free_size + c->dirty_size +
				  c->wasted_size + c->used_size +
				  c->erasing_size + c->bad_size,
				  c->flash_size);
			spin_unlock(&c->erase_completion_lock);

			ret = jffs2_garbage_collect_pass(c);

			if (ret == -EAGAIN) {
				spin_lock(&c->erase_completion_lock);
				if (c->nr_erasing_blocks &&
				    list_empty(&c->erase_pending_list) &&
				    list_empty(&c->erase_complete_list)) {
					DECLARE_WAITQUEUE(wait, current);
					set_current_state(TASK_UNINTERRUPTIBLE);
					add_wait_queue(&c->erase_wait, &wait);
					jffs2_dbg(1, "%s waiting for erase to complete\n",
						  __func__);
					spin_unlock(&c->erase_completion_lock);

					schedule();
					remove_wait_queue(&c->erase_wait, &wait);
				} else
					spin_unlock(&c->erase_completion_lock);
			} else if (ret)
				return ret;

			cond_resched();

			if (signal_pending(current))
				return -EINTR;

			mutex_lock(&c->alloc_sem);
			spin_lock(&c->erase_completion_lock);
		}

		ret = jffs2_do_reserve_space(c, minsize, len, sumsize);
		if (ret) {
			jffs2_dbg(1, "%s(): ret is %d\n", __func__, ret);
		}
	}

out:
	spin_unlock(&c->erase_completion_lock);
	if (!ret)
		ret = jffs2_prealloc_raw_node_refs(c, c->nextblock, 1);
	if (ret)
		mutex_unlock(&c->alloc_sem);
	return ret;
}

int jffs2_reserve_space_gc(struct jffs2_sb_info *c, uint32_t minsize,
			   uint32_t *len, uint32_t sumsize)
{
	int ret;
	minsize = PAD(minsize);

	jffs2_dbg(1, "%s(): Requested 0x%x bytes\n", __func__, minsize);

	while (true) {
		spin_lock(&c->erase_completion_lock);
		ret = jffs2_do_reserve_space(c, minsize, len, sumsize);
		if (ret) {
			jffs2_dbg(1, "%s(): looping, ret is %d\n",
				  __func__, ret);
		}
		spin_unlock(&c->erase_completion_lock);

		if (ret == -EAGAIN)
			cond_resched();
		else
			break;
	}
	if (!ret)
		ret = jffs2_prealloc_raw_node_refs(c, c->nextblock, 1);

	return ret;
}


/* Classify nextblock (clean, dirty of verydirty) and force to select an other one */

static void jffs2_close_nextblock(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb)
{

	if (c->nextblock == NULL) {
		jffs2_dbg(1, "%s(): Erase block at 0x%08x has already been placed in a list\n",
			  __func__, jeb->offset);
		return;
	}
	/* Check, if we have a dirty block now, or if it was dirty already */
	if (ISDIRTY (jeb->wasted_size + jeb->dirty_size)) {
		c->dirty_size += jeb->wasted_size;
		c->wasted_size -= jeb->wasted_size;
		jeb->dirty_size += jeb->wasted_size;
		jeb->wasted_size = 0;
		if (VERYDIRTY(c, jeb->dirty_size)) {
			jffs2_dbg(1, "Adding full erase block at 0x%08x to very_dirty_list (free 0x%08x, dirty 0x%08x, used 0x%08x\n",
				  jeb->offset, jeb->free_size, jeb->dirty_size,
				  jeb->used_size);
			list_add_tail(&jeb->list, &c->very_dirty_list);
		} else {
			jffs2_dbg(1, "Adding full erase block at 0x%08x to dirty_list (free 0x%08x, dirty 0x%08x, used 0x%08x\n",
				  jeb->offset, jeb->free_size, jeb->dirty_size,
				  jeb->used_size);
			list_add_tail(&jeb->list, &c->dirty_list);
		}
	} else {
		jffs2_dbg(1, "Adding full erase block at 0x%08x to clean_list (free 0x%08x, dirty 0x%08x, used 0x%08x\n",
			  jeb->offset, jeb->free_size, jeb->dirty_size,
			  jeb->used_size);
		list_add_tail(&jeb->list, &c->clean_list);
	}
	c->nextblock = NULL;

}

/* Select a new jeb for nextblock */

static int jffs2_find_nextblock(struct jffs2_sb_info *c)
{
	struct list_head *next;

	/* Take the next block off the 'free' list */

	if (list_empty(&c->free_list)) {

		if (!c->nr_erasing_blocks &&
			!list_empty(&c->erasable_list)) {
			struct jffs2_eraseblock *ejeb;

			ejeb = list_entry(c->erasable_list.next, struct jffs2_eraseblock, list);
			list_move_tail(&ejeb->list, &c->erase_pending_list);
			c->nr_erasing_blocks++;
			jffs2_garbage_collect_trigger(c);
			jffs2_dbg(1, "%s(): Triggering erase of erasable block at 0x%08x\n",
				  __func__, ejeb->offset);
		}

		if (!c->nr_erasing_blocks &&
			!list_empty(&c->erasable_pending_wbuf_list)) {
			jffs2_dbg(1, "%s(): Flushing write buffer\n",
				  __func__);
			/* c->nextblock is NULL, no update to c->nextblock allowed */
			spin_unlock(&c->erase_completion_lock);
			jffs2_flush_wbuf_pad(c);
			spin_lock(&c->erase_completion_lock);
			/* Have another go. It'll be on the erasable_list now */
			return -EAGAIN;
		}

		if (!c->nr_erasing_blocks) {
			/* Ouch. We're in GC, or we wouldn't have got here.
			   And there's no space left. At all. */
			pr_crit("Argh. No free space left for GC. nr_erasing_blocks is %d. nr_free_blocks is %d. (erasableempty: %s, erasingempty: %s, erasependingempty: %s)\n",
				c->nr_erasing_blocks, c->nr_free_blocks,
				list_empty(&c->erasable_list) ? "yes" : "no",
				list_empty(&c->erasing_list) ? "yes" : "no",
				list_empty(&c->erase_pending_list) ? "yes" : "no");
			return -ENOSPC;
		}

		spin_unlock(&c->erase_completion_lock);
		/* Don't wait for it; just erase one right now */
		jffs2_erase_pending_blocks(c, 1);
		spin_lock(&c->erase_completion_lock);

		/* An erase may have failed, decreasing the
		   amount of free space available. So we must
		   restart from the beginning */
		return -EAGAIN;
	}

	next = c->free_list.next;
	list_del(next);
	c->nextblock = list_entry(next, struct jffs2_eraseblock, list);
	c->nr_free_blocks--;

	jffs2_sum_reset_collected(c->summary); /* reset collected summary */

#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
	/* adjust write buffer offset, else we get a non contiguous write bug */
	if (!(c->wbuf_ofs % c->sector_size) && !c->wbuf_len)
		c->wbuf_ofs = 0xffffffff;
#endif

	jffs2_dbg(1, "%s(): new nextblock = 0x%08x\n",
		  __func__, c->nextblock->offset);

	return 0;
}

/* Called with alloc sem _and_ erase_completion_lock */
static int jffs2_do_reserve_space(struct jffs2_sb_info *c, uint32_t minsize,
				  uint32_t *len, uint32_t sumsize)
{
	struct jffs2_eraseblock *jeb = c->nextblock;
	uint32_t reserved_size;				/* for summary information at the end of the jeb */
	int ret;

 restart:
	reserved_size = 0;

	if (jffs2_sum_active() && (sumsize != JFFS2_SUMMARY_NOSUM_SIZE)) {
							/* NOSUM_SIZE means not to generate summary */

		if (jeb) {
			reserved_size = PAD(sumsize + c->summary->sum_size + JFFS2_SUMMARY_FRAME_SIZE);
			dbg_summary("minsize=%d , jeb->free=%d ,"
						"summary->size=%d , sumsize=%d\n",
						minsize, jeb->free_size,
						c->summary->sum_size, sumsize);
		}

		/* Is there enough space for writing out the current node, or we have to
		   write out summary information now, close this jeb and select new nextblock? */
		if (jeb && (PAD(minsize) + PAD(c->summary->sum_size + sumsize +
					JFFS2_SUMMARY_FRAME_SIZE) > jeb->free_size)) {

			/* Has summary been disabled for this jeb? */
			if (jffs2_sum_is_disabled(c->summary)) {
				sumsize = JFFS2_SUMMARY_NOSUM_SIZE;
				goto restart;
			}

			/* Writing out the collected summary information */
			dbg_summary("generating summary for 0x%08x.\n", jeb->offset);
			ret = jffs2_sum_write_sumnode(c);

			if (ret)
				return ret;

			if (jffs2_sum_is_disabled(c->summary)) {
				/* jffs2_write_sumnode() couldn't write out the summary information
				   diabling summary for this jeb and free the collected information
				 */
				sumsize = JFFS2_SUMMARY_NOSUM_SIZE;
				goto restart;
			}

			jffs2_close_nextblock(c, jeb);
			jeb = NULL;
			/* keep always valid value in reserved_size */
			reserved_size = PAD(sumsize + c->summary->sum_size + JFFS2_SUMMARY_FRAME_SIZE);
		}
	} else {
		if (jeb && minsize > jeb->free_size) {
			uint32_t waste;

			/* Skip the end of this block and file it as having some dirty space */
			/* If there's a pending write to it, flush now */

			if (jffs2_wbuf_dirty(c)) {
				spin_unlock(&c->erase_completion_lock);
				jffs2_dbg(1, "%s(): Flushing write buffer\n",
					  __func__);
				jffs2_flush_wbuf_pad(c);
				spin_lock(&c->erase_completion_lock);
				jeb = c->nextblock;
				goto restart;
			}

			spin_unlock(&c->erase_completion_lock);

			ret = jffs2_prealloc_raw_node_refs(c, jeb, 1);

			/* Just lock it again and continue. Nothing much can change because
			   we hold c->alloc_sem anyway. In fact, it's not entirely clear why
			   we hold c->erase_completion_lock in the majority of this function...
			   but that's a question for another (more caffeine-rich) day. */
			spin_lock(&c->erase_completion_lock);

			if (ret)
				return ret;

			waste = jeb->free_size;
			jffs2_link_node_ref(c, jeb,
					    (jeb->offset + c->sector_size - waste) | REF_OBSOLETE,
					    waste, NULL);
			/* FIXME: that made it count as dirty. Convert to wasted */
			jeb->dirty_size -= waste;
			c->dirty_size -= waste;
			jeb->wasted_size += waste;
			c->wasted_size += waste;

			jffs2_close_nextblock(c, jeb);
			jeb = NULL;
		}
	}

	if (!jeb) {

		ret = jffs2_find_nextblock(c);
		if (ret)
			return ret;

		jeb = c->nextblock;

		if (jeb->free_size != c->sector_size - c->cleanmarker_size) {
			pr_warn("Eep. Block 0x%08x taken from free_list had free_size of 0x%08x!!\n",
				jeb->offset, jeb->free_size);
			goto restart;
		}
	}
	/* OK, jeb (==c->nextblock) is now pointing at a block which definitely has
	   enough space */
	*len = jeb->free_size - reserved_size;

	if (c->cleanmarker_size && jeb->used_size == c->cleanmarker_size &&
	    !jeb->first_node->next_in_ino) {
		/* Only node in it beforehand was a CLEANMARKER node (we think).
		   So mark it obsolete now that there's going to be another node
		   in the block. This will reduce used_size to zero but We've
		   already set c->nextblock so that jffs2_mark_node_obsolete()
		   won't try to refile it to the dirty_list.
		*/
		spin_unlock(&c->erase_completion_lock);
		jffs2_mark_node_obsolete(c, jeb->first_node);
		spin_lock(&c->erase_completion_lock);
	}

	jffs2_dbg(1, "%s(): Giving 0x%x bytes at 0x%x\n",
		  __func__,
		  *len, jeb->offset + (c->sector_size - jeb->free_size));
	return 0;
}

/**
 *	jffs2_add_physical_node_ref - add a physical node reference to the list
 *	@c: superblock info
 *	@new: new node reference to add
 *	@len: length of this physical node
 *
 *	Should only be used to report nodes for which space has been allocated
 *	by jffs2_reserve_space.
 *
 *	Must be called with the alloc_sem held.
 */

struct jffs2_raw_node_ref *jffs2_add_physical_node_ref(struct jffs2_sb_info *c,
						       uint32_t ofs, uint32_t len,
						       struct jffs2_inode_cache *ic)
{
	struct jffs2_eraseblock *jeb;
	struct jffs2_raw_node_ref *new;

	jeb = &c->blocks[ofs / c->sector_size];

	jffs2_dbg(1, "%s(): Node at 0x%x(%d), size 0x%x\n",
		  __func__, ofs & ~3, ofs & 3, len);
#if 1
	/* Allow non-obsolete nodes only to be added at the end of c->nextblock,
	   if c->nextblock is set. Note that wbuf.c will file obsolete nodes
	   even after refiling c->nextblock */
	if ((c->nextblock || ((ofs & 3) != REF_OBSOLETE))
	    && (jeb != c->nextblock || (ofs & ~3) != jeb->offset + (c->sector_size - jeb->free_size))) {
		pr_warn("argh. node added in wrong place at 0x%08x(%d)\n",
			ofs & ~3, ofs & 3);
		if (c->nextblock)
			pr_warn("nextblock 0x%08x", c->nextblock->offset);
		else
			pr_warn("No nextblock");
		pr_cont(", expected at %08x\n",
			jeb->offset + (c->sector_size - jeb->free_size));
		return ERR_PTR(-EINVAL);
	}
#endif
	spin_lock(&c->erase_completion_lock);

	new = jffs2_link_node_ref(c, jeb, ofs, len, ic);

	if (!jeb->free_size && !jeb->dirty_size && !ISDIRTY(jeb->wasted_size)) {
		/* If it lives on the dirty_list, jffs2_reserve_space will put it there */
		jffs2_dbg(1, "Adding full erase block at 0x%08x to clean_list (free 0x%08x, dirty 0x%08x, used 0x%08x\n",
			  jeb->offset, jeb->free_size, jeb->dirty_size,
			  jeb->used_size);
		if (jffs2_wbuf_dirty(c)) {
			/* Flush the last write in the block if it's outstanding */
			spin_unlock(&c->erase_completion_lock);
			jffs2_flush_wbuf_pad(c);
			spin_lock(&c->erase_completion_lock);
		}

		list_add_tail(&jeb->list, &c->clean_list);
		c->nextblock = NULL;
	}
	jffs2_dbg_acct_sanity_check_nolock(c,jeb);
	jffs2_dbg_acct_paranoia_check_nolock(c, jeb);

	spin_unlock(&c->erase_completion_lock);

	return new;
}


void jffs2_complete_reservation(struct jffs2_sb_info *c)
{
	jffs2_dbg(1, "jffs2_complete_reservation()\n");
	spin_lock(&c->erase_completion_lock);
	jffs2_garbage_collect_trigger(c);
	spin_unlock(&c->erase_completion_lock);
	mutex_unlock(&c->alloc_sem);
}

static inline int on_list(struct list_head *obj, struct list_head *head)
{
	struct list_head *this;

	list_for_each(this, head) {
		if (this == obj) {
			jffs2_dbg(1, "%p is on list at %p\n", obj, head);
			return 1;

		}
	}
	return 0;
}

void jffs2_mark_node_obsolete(struct jffs2_sb_info *c, struct jffs2_raw_node_ref *ref)
{
	struct jffs2_eraseblock *jeb;
	int blocknr;
	struct jffs2_unknown_node n;
	int ret, addedsize;
	size_t retlen;
	uint32_t freed_len;

	if(unlikely(!ref)) {
		pr_notice("EEEEEK. jffs2_mark_node_obsolete called with NULL node\n");
		return;
	}
	if (ref_obsolete(ref)) {
		jffs2_dbg(1, "%s(): called with already obsolete node at 0x%08x\n",
			  __func__, ref_offset(ref));
		return;
	}
	blocknr = ref->flash_offset / c->sector_size;
	if (blocknr >= c->nr_blocks) {
		pr_notice("raw node at 0x%08x is off the end of device!\n",
			  ref->flash_offset);
		BUG();
	}
	jeb = &c->blocks[blocknr];

	if (jffs2_can_mark_obsolete(c) && !jffs2_is_readonly(c) &&
	    !(c->flags & (JFFS2_SB_FLAG_SCANNING | JFFS2_SB_FLAG_BUILDING))) {
		/* Hm. This may confuse static lock analysis. If any of the above
		   three conditions is false, we're going to return from this
		   function without actually obliterating any nodes or freeing
		   any jffs2_raw_node_refs. So we don't need to stop erases from
		   happening, or protect against people holding an obsolete
		   jffs2_raw_node_ref without the erase_completion_lock. */
		mutex_lock(&c->erase_free_sem);
	}

	spin_lock(&c->erase_completion_lock);

	freed_len = ref_totlen(c, jeb, ref);

	if (ref_flags(ref) == REF_UNCHECKED) {
		D1(if (unlikely(jeb->unchecked_size < freed_len)) {
				pr_notice("raw unchecked node of size 0x%08x freed from erase block %d at 0x%08x, but unchecked_size was already 0x%08x\n",
					  freed_len, blocknr,
					  ref->flash_offset, jeb->used_size);
			BUG();
		})
			jffs2_dbg(1, "Obsoleting previously unchecked node at 0x%08x of len %x\n",
				  ref_offset(ref), freed_len);
		jeb->unchecked_size -= freed_len;
		c->unchecked_size -= freed_len;
	} else {
		D1(if (unlikely(jeb->used_size < freed_len)) {
				pr_notice("raw node of size 0x%08x freed from erase block %d at 0x%08x, but used_size was already 0x%08x\n",
					  freed_len, blocknr,
					  ref->flash_offset, jeb->used_size);
			BUG();
		})
			jffs2_dbg(1, "Obsoleting node at 0x%08x of len %#x: ",
				  ref_offset(ref), freed_len);
		jeb->used_size -= freed_len;
		c->used_size -= freed_len;
	}

	// Take care, that wasted size is taken into concern
	if ((jeb->dirty_size || ISDIRTY(jeb->wasted_size + freed_len)) && jeb != c->nextblock) {
		jffs2_dbg(1, "Dirtying\n");
		addedsize = freed_len;
		jeb->dirty_size += freed_len;
		c->dirty_size += freed_len;

		/* Convert wasted space to dirty, if not a bad block */
		if (jeb->wasted_size) {
			if (on_list(&jeb->list, &c->bad_used_list)) {
				jffs2_dbg(1, "Leaving block at %08x on the bad_used_list\n",
					  jeb->offset);
				addedsize = 0; /* To fool the refiling code later */
			} else {
				jffs2_dbg(1, "Converting %d bytes of wasted space to dirty in block at %08x\n",
					  jeb->wasted_size, jeb->offset);
				addedsize += jeb->wasted_size;
				jeb->dirty_size += jeb->wasted_size;
				c->dirty_size += jeb->wasted_size;
				c->wasted_size -= jeb->wasted_size;
				jeb->wasted_size = 0;
			}
		}
	} else {
		jffs2_dbg(1, "Wasting\n");
		addedsize = 0;
		jeb->wasted_size += freed_len;
		c->wasted_size += freed_len;
	}
	ref->flash_offset = ref_offset(ref) | REF_OBSOLETE;

	jffs2_dbg_acct_sanity_check_nolock(c, jeb);
	jffs2_dbg_acct_paranoia_check_nolock(c, jeb);

	if (c->flags & JFFS2_SB_FLAG_SCANNING) {
		/* Flash scanning is in progress. Don't muck about with the block
		   lists because they're not ready yet, and don't actually
		   obliterate nodes that look obsolete. If they weren't
		   marked obsolete on the flash at the time they _became_
		   obsolete, there was probably a reason for that. */
		spin_unlock(&c->erase_completion_lock);
		/* We didn't lock the erase_free_sem */
		return;
	}

	if (jeb == c->nextblock) {
		jffs2_dbg(2, "Not moving nextblock 0x%08x to dirty/erase_pending list\n",
			  jeb->offset);
	} else if (!jeb->used_size && !jeb->unchecked_size) {
		if (jeb == c->gcblock) {
			jffs2_dbg(1, "gcblock at 0x%08x completely dirtied. Clearing gcblock...\n",
				  jeb->offset);
			c->gcblock = NULL;
		} else {
			jffs2_dbg(1, "Eraseblock at 0x%08x completely dirtied. Removing from (dirty?) list...\n",
				  jeb->offset);
			list_del(&jeb->list);
		}
		if (jffs2_wbuf_dirty(c)) {
			jffs2_dbg(1, "...and adding to erasable_pending_wbuf_list\n");
			list_add_tail(&jeb->list, &c->erasable_pending_wbuf_list);
		} else {
			if (jiffies & 127) {
				/* Most of the time, we just erase it immediately. Otherwise we
				   spend ages scanning it on mount, etc. */
				jffs2_dbg(1, "...and adding to erase_pending_list\n");
				list_add_tail(&jeb->list, &c->erase_pending_list);
				c->nr_erasing_blocks++;
				jffs2_garbage_collect_trigger(c);
			} else {
				/* Sometimes, however, we leave it elsewhere so it doesn't get
				   immediately reused, and we spread the load a bit. */
				jffs2_dbg(1, "...and adding to erasable_list\n");
				list_add_tail(&jeb->list, &c->erasable_list);
			}
		}
		jffs2_dbg(1, "Done OK\n");
	} else if (jeb == c->gcblock) {
		jffs2_dbg(2, "Not moving gcblock 0x%08x to dirty_list\n",
			  jeb->offset);
	} else if (ISDIRTY(jeb->dirty_size) && !ISDIRTY(jeb->dirty_size - addedsize)) {
		jffs2_dbg(1, "Eraseblock at 0x%08x is freshly dirtied. Removing from clean list...\n",
			  jeb->offset);
		list_del(&jeb->list);
		jffs2_dbg(1, "...and adding to dirty_list\n");
		list_add_tail(&jeb->list, &c->dirty_list);
	} else if (VERYDIRTY(c, jeb->dirty_size) &&
		   !VERYDIRTY(c, jeb->dirty_size - addedsize)) {
		jffs2_dbg(1, "Eraseblock at 0x%08x is now very dirty. Removing from dirty list...\n",
			  jeb->offset);
		list_del(&jeb->list);
		jffs2_dbg(1, "...and adding to very_dirty_list\n");
		list_add_tail(&jeb->list, &c->very_dirty_list);
	} else {
		jffs2_dbg(1, "Eraseblock at 0x%08x not moved anywhere. (free 0x%08x, dirty 0x%08x, used 0x%08x)\n",
			  jeb->offset, jeb->free_size, jeb->dirty_size,
			  jeb->used_size);
	}

	spin_unlock(&c->erase_completion_lock);

	if (!jffs2_can_mark_obsolete(c) || jffs2_is_readonly(c) ||
		(c->flags & JFFS2_SB_FLAG_BUILDING)) {
		/* We didn't lock the erase_free_sem */
		return;
	}

	/* The erase_free_sem is locked, and has been since before we marked the node obsolete
	   and potentially put its eraseblock onto the erase_pending_list. Thus, we know that
	   the block hasn't _already_ been erased, and that 'ref' itself hasn't been freed yet
	   by jffs2_free_jeb_node_refs() in erase.c. Which is nice. */

	jffs2_dbg(1, "obliterating obsoleted node at 0x%08x\n",
		  ref_offset(ref));
	ret = jffs2_flash_read(c, ref_offset(ref), sizeof(n), &retlen, (char *)&n);
	if (ret) {
		pr_warn("Read error reading from obsoleted node at 0x%08x: %d\n",
			ref_offset(ref), ret);
		goto out_erase_sem;
	}
	if (retlen != sizeof(n)) {
		pr_warn("Short read from obsoleted node at 0x%08x: %zd\n",
			ref_offset(ref), retlen);
		goto out_erase_sem;
	}
	if (PAD(je32_to_cpu(n.totlen)) != PAD(freed_len)) {
		pr_warn("Node totlen on flash (0x%08x) != totlen from node ref (0x%08x)\n",
			je32_to_cpu(n.totlen), freed_len);
		goto out_erase_sem;
	}
	if (!(je16_to_cpu(n.nodetype) & JFFS2_NODE_ACCURATE)) {
		jffs2_dbg(1, "Node at 0x%08x was already marked obsolete (nodetype 0x%04x)\n",
			  ref_offset(ref), je16_to_cpu(n.nodetype));
		goto out_erase_sem;
	}
	/* XXX FIXME: This is ugly now */
	n.nodetype = cpu_to_je16(je16_to_cpu(n.nodetype) & ~JFFS2_NODE_ACCURATE);
	ret = jffs2_flash_write(c, ref_offset(ref), sizeof(n), &retlen, (char *)&n);
	if (ret) {
		pr_warn("Write error in obliterating obsoleted node at 0x%08x: %d\n",
			ref_offset(ref), ret);
		goto out_erase_sem;
	}
	if (retlen != sizeof(n)) {
		pr_warn("Short write in obliterating obsoleted node at 0x%08x: %zd\n",
			ref_offset(ref), retlen);
		goto out_erase_sem;
	}

	/* Nodes which have been marked obsolete no longer need to be
	   associated with any inode. Remove them from the per-inode list.

	   Note we can't do this for NAND at the moment because we need
	   obsolete dirent nodes to stay on the lists, because of the
	   horridness in jffs2_garbage_collect_deletion_dirent(). Also
	   because we delete the inocache, and on NAND we need that to
	   stay around until all the nodes are actually erased, in order
	   to stop us from giving the same inode number to another newly
	   created inode. */
	if (ref->next_in_ino) {
		struct jffs2_inode_cache *ic;
		struct jffs2_raw_node_ref **p;

		spin_lock(&c->erase_completion_lock);

		ic = jffs2_raw_ref_to_ic(ref);
		for (p = &ic->nodes; (*p) != ref; p = &((*p)->next_in_ino))
			;

		*p = ref->next_in_ino;
		ref->next_in_ino = NULL;

		switch (ic->class) {
#ifdef CONFIG_JFFS2_FS_XATTR
			case RAWNODE_CLASS_XATTR_DATUM:
				jffs2_release_xattr_datum(c, (struct jffs2_xattr_datum *)ic);
				break;
			case RAWNODE_CLASS_XATTR_REF:
				jffs2_release_xattr_ref(c, (struct jffs2_xattr_ref *)ic);
				break;
#endif
			default:
				if (ic->nodes == (void *)ic && ic->pino_nlink == 0)
					jffs2_del_ino_cache(c, ic);
				break;
		}
		spin_unlock(&c->erase_completion_lock);
	}

 out_erase_sem:
	mutex_unlock(&c->erase_free_sem);
}

int jffs2_thread_should_wake(struct jffs2_sb_info *c)
{
	int ret = 0;
	uint32_t dirty;
	int nr_very_dirty = 0;
	struct jffs2_eraseblock *jeb;

	if (!list_empty(&c->erase_complete_list) ||
	    !list_empty(&c->erase_pending_list))
		return 1;

	if (c->unchecked_size) {
		jffs2_dbg(1, "jffs2_thread_should_wake(): unchecked_size %d, checked_ino #%d\n",
			  c->unchecked_size, c->checked_ino);
		return 1;
	}

	/* dirty_size contains blocks on erase_pending_list
	 * those blocks are counted in c->nr_erasing_blocks.
	 * If one block is actually erased, it is not longer counted as dirty_space
	 * but it is counted in c->nr_erasing_blocks, so we add it and subtract it
	 * with c->nr_erasing_blocks * c->sector_size again.
	 * Blocks on erasable_list are counted as dirty_size, but not in c->nr_erasing_blocks
	 * This helps us to force gc and pick eventually a clean block to spread the load.
	 */
	dirty = c->dirty_size + c->erasing_size - c->nr_erasing_blocks * c->sector_size;

	if (c->nr_free_blocks + c->nr_erasing_blocks < c->resv_blocks_gctrigger &&
			(dirty > c->nospc_dirty_size))
		ret = 1;

	list_for_each_entry(jeb, &c->very_dirty_list, list) {
		nr_very_dirty++;
		if (nr_very_dirty == c->vdirty_blocks_gctrigger) {
			ret = 1;
			/* In debug mode, actually go through and count them all */
			D1(continue);
			break;
		}
	}

	jffs2_dbg(1, "%s(): nr_free_blocks %d, nr_erasing_blocks %d, dirty_size 0x%x, vdirty_blocks %d: %s\n",
		  __func__, c->nr_free_blocks, c->nr_erasing_blocks,
		  c->dirty_size, nr_very_dirty, ret ? "yes" : "no");

	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/nodemgmt.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/fs.h>
// #include <linux/crc32.h>
// #include <linux/pagemap.h>
// #include <linux/mtd/mtd.h>
// #include <linux/compiler.h>
// #include "nodelist.h"

/*
 * Check the data CRC of the node.
 *
 * Returns: 0 if the data CRC is correct;
 * 	    1 - if incorrect;
 *	    error code if an error occurred.
 */
static int check_node_data(struct jffs2_sb_info *c, struct jffs2_tmp_dnode_info *tn)
{
	struct jffs2_raw_node_ref *ref = tn->fn->raw;
	int err = 0, pointed = 0;
	struct jffs2_eraseblock *jeb;
	unsigned char *buffer;
	uint32_t crc, ofs, len;
	size_t retlen;

	BUG_ON(tn->csize == 0);

	/* Calculate how many bytes were already checked */
	ofs = ref_offset(ref) + sizeof(struct jffs2_raw_inode);
	len = tn->csize;

	if (jffs2_is_writebuffered(c)) {
		int adj = ofs % c->wbuf_pagesize;
		if (likely(adj))
			adj = c->wbuf_pagesize - adj;

		if (adj >= tn->csize) {
			dbg_readinode("no need to check node at %#08x, data length %u, data starts at %#08x - it has already been checked.\n",
				      ref_offset(ref), tn->csize, ofs);
			goto adj_acc;
		}

		ofs += adj;
		len -= adj;
	}

	dbg_readinode("check node at %#08x, data length %u, partial CRC %#08x, correct CRC %#08x, data starts at %#08x, start checking from %#08x - %u bytes.\n",
		ref_offset(ref), tn->csize, tn->partial_crc, tn->data_crc, ofs - len, ofs, len);

#ifndef __ECOS
	/* TODO: instead, incapsulate point() stuff to jffs2_flash_read(),
	 * adding and jffs2_flash_read_end() interface. */
	err = mtd_point(c->mtd, ofs, len, &retlen, (void **)&buffer, NULL);
	if (!err && retlen < len) {
		JFFS2_WARNING("MTD point returned len too short: %zu instead of %u.\n", retlen, tn->csize);
		mtd_unpoint(c->mtd, ofs, retlen);
	} else if (err) {
		if (err != -EOPNOTSUPP)
			JFFS2_WARNING("MTD point failed: error code %d.\n", err);
	} else
		pointed = 1; /* succefully pointed to device */
#endif

	if (!pointed) {
		buffer = kmalloc(len, GFP_KERNEL);
		if (unlikely(!buffer))
			return -ENOMEM;

		/* TODO: this is very frequent pattern, make it a separate
		 * routine */
		err = jffs2_flash_read(c, ofs, len, &retlen, buffer);
		if (err) {
			JFFS2_ERROR("can not read %d bytes from 0x%08x, error code: %d.\n", len, ofs, err);
			goto free_out;
		}

		if (retlen != len) {
			JFFS2_ERROR("short read at %#08x: %zd instead of %d.\n", ofs, retlen, len);
			err = -EIO;
			goto free_out;
		}
	}

	/* Continue calculating CRC */
	crc = crc32(tn->partial_crc, buffer, len);
	if(!pointed)
		kfree(buffer);
#ifndef __ECOS
	else
		mtd_unpoint(c->mtd, ofs, len);
#endif

	if (crc != tn->data_crc) {
		JFFS2_NOTICE("wrong data CRC in data node at 0x%08x: read %#08x, calculated %#08x.\n",
			     ref_offset(ref), tn->data_crc, crc);
		return 1;
	}

adj_acc:
	jeb = &c->blocks[ref->flash_offset / c->sector_size];
	len = ref_totlen(c, jeb, ref);
	/* If it should be REF_NORMAL, it'll get marked as such when
	   we build the fragtree, shortly. No need to worry about GC
	   moving it while it's marked REF_PRISTINE -- GC won't happen
	   till we've finished checking every inode anyway. */
	ref->flash_offset |= REF_PRISTINE;
	/*
	 * Mark the node as having been checked and fix the
	 * accounting accordingly.
	 */
	spin_lock(&c->erase_completion_lock);
	jeb->used_size += len;
	jeb->unchecked_size -= len;
	c->used_size += len;
	c->unchecked_size -= len;
	jffs2_dbg_acct_paranoia_check_nolock(c, jeb);
	spin_unlock(&c->erase_completion_lock);

	return 0;

free_out:
	if(!pointed)
		kfree(buffer);
#ifndef __ECOS
	else
		mtd_unpoint(c->mtd, ofs, len);
#endif
	return err;
}

/*
 * Helper function for jffs2_add_older_frag_to_fragtree().
 *
 * Checks the node if we are in the checking stage.
 */
static int check_tn_node(struct jffs2_sb_info *c, struct jffs2_tmp_dnode_info *tn)
{
	int ret;

	BUG_ON(ref_obsolete(tn->fn->raw));

	/* We only check the data CRC of unchecked nodes */
	if (ref_flags(tn->fn->raw) != REF_UNCHECKED)
		return 0;

	dbg_readinode("check node %#04x-%#04x, phys offs %#08x\n",
		      tn->fn->ofs, tn->fn->ofs + tn->fn->size, ref_offset(tn->fn->raw));

	ret = check_node_data(c, tn);
	if (unlikely(ret < 0)) {
		JFFS2_ERROR("check_node_data() returned error: %d.\n",
			ret);
	} else if (unlikely(ret > 0)) {
		dbg_readinode("CRC error, mark it obsolete.\n");
		jffs2_mark_node_obsolete(c, tn->fn->raw);
	}

	return ret;
}

static struct jffs2_tmp_dnode_info *jffs2_lookup_tn(struct rb_root *tn_root, uint32_t offset)
{
	struct rb_node *next;
	struct jffs2_tmp_dnode_info *tn = NULL;

	dbg_readinode("root %p, offset %d\n", tn_root, offset);

	next = tn_root->rb_node;

	while (next) {
		tn = rb_entry(next, struct jffs2_tmp_dnode_info, rb);

		if (tn->fn->ofs < offset)
			next = tn->rb.rb_right;
		else if (tn->fn->ofs >= offset)
			next = tn->rb.rb_left;
		else
			break;
	}

	return tn;
}


static void jffs2_kill_tn(struct jffs2_sb_info *c, struct jffs2_tmp_dnode_info *tn)
{
	jffs2_mark_node_obsolete(c, tn->fn->raw);
	jffs2_free_full_dnode(tn->fn);
	jffs2_free_tmp_dnode_info(tn);
}
/*
 * This function is used when we read an inode. Data nodes arrive in
 * arbitrary order -- they may be older or newer than the nodes which
 * are already in the tree. Where overlaps occur, the older node can
 * be discarded as long as the newer passes the CRC check. We don't
 * bother to keep track of holes in this rbtree, and neither do we deal
 * with frags -- we can have multiple entries starting at the same
 * offset, and the one with the smallest length will come first in the
 * ordering.
 *
 * Returns 0 if the node was handled (including marking it obsolete)
 *	 < 0 an if error occurred
 */
static int jffs2_add_tn_to_tree(struct jffs2_sb_info *c,
				struct jffs2_readinode_info *rii,
				struct jffs2_tmp_dnode_info *tn)
{
	uint32_t fn_end = tn->fn->ofs + tn->fn->size;
	struct jffs2_tmp_dnode_info *this, *ptn;

	dbg_readinode("insert fragment %#04x-%#04x, ver %u at %08x\n", tn->fn->ofs, fn_end, tn->version, ref_offset(tn->fn->raw));

	/* If a node has zero dsize, we only have to keep if it if it might be the
	   node with highest version -- i.e. the one which will end up as f->metadata.
	   Note that such nodes won't be REF_UNCHECKED since there are no data to
	   check anyway. */
	if (!tn->fn->size) {
		if (rii->mdata_tn) {
			if (rii->mdata_tn->version < tn->version) {
				/* We had a candidate mdata node already */
				dbg_readinode("kill old mdata with ver %d\n", rii->mdata_tn->version);
				jffs2_kill_tn(c, rii->mdata_tn);
			} else {
				dbg_readinode("kill new mdata with ver %d (older than existing %d\n",
					      tn->version, rii->mdata_tn->version);
				jffs2_kill_tn(c, tn);
				return 0;
			}
		}
		rii->mdata_tn = tn;
		dbg_readinode("keep new mdata with ver %d\n", tn->version);
		return 0;
	}

	/* Find the earliest node which _may_ be relevant to this one */
	this = jffs2_lookup_tn(&rii->tn_root, tn->fn->ofs);
	if (this) {
		/* If the node is coincident with another at a lower address,
		   back up until the other node is found. It may be relevant */
		while (this->overlapped) {
			ptn = tn_prev(this);
			if (!ptn) {
				/*
				 * We killed a node which set the overlapped
				 * flags during the scan. Fix it up.
				 */
				this->overlapped = 0;
				break;
			}
			this = ptn;
		}
		dbg_readinode("'this' found %#04x-%#04x (%s)\n", this->fn->ofs, this->fn->ofs + this->fn->size, this->fn ? "data" : "hole");
	}

	while (this) {
		if (this->fn->ofs > fn_end)
			break;
		dbg_readinode("Ponder this ver %d, 0x%x-0x%x\n",
			      this->version, this->fn->ofs, this->fn->size);

		if (this->version == tn->version) {
			/* Version number collision means REF_PRISTINE GC. Accept either of them
			   as long as the CRC is correct. Check the one we have already...  */
			if (!check_tn_node(c, this)) {
				/* The one we already had was OK. Keep it and throw away the new one */
				dbg_readinode("Like old node. Throw away new\n");
				jffs2_kill_tn(c, tn);
				return 0;
			} else {
				/* Who cares if the new one is good; keep it for now anyway. */
				dbg_readinode("Like new node. Throw away old\n");
				rb_replace_node(&this->rb, &tn->rb, &rii->tn_root);
				jffs2_kill_tn(c, this);
				/* Same overlapping from in front and behind */
				return 0;
			}
		}
		if (this->version < tn->version &&
		    this->fn->ofs >= tn->fn->ofs &&
		    this->fn->ofs + this->fn->size <= fn_end) {
			/* New node entirely overlaps 'this' */
			if (check_tn_node(c, tn)) {
				dbg_readinode("new node bad CRC\n");
				jffs2_kill_tn(c, tn);
				return 0;
			}
			/* ... and is good. Kill 'this' and any subsequent nodes which are also overlapped */
			while (this && this->fn->ofs + this->fn->size <= fn_end) {
				struct jffs2_tmp_dnode_info *next = tn_next(this);
				if (this->version < tn->version) {
					tn_erase(this, &rii->tn_root);
					dbg_readinode("Kill overlapped ver %d, 0x%x-0x%x\n",
						      this->version, this->fn->ofs,
						      this->fn->ofs+this->fn->size);
					jffs2_kill_tn(c, this);
				}
				this = next;
			}
			dbg_readinode("Done killing overlapped nodes\n");
			continue;
		}
		if (this->version > tn->version &&
		    this->fn->ofs <= tn->fn->ofs &&
		    this->fn->ofs+this->fn->size >= fn_end) {
			/* New node entirely overlapped by 'this' */
			if (!check_tn_node(c, this)) {
				dbg_readinode("Good CRC on old node. Kill new\n");
				jffs2_kill_tn(c, tn);
				return 0;
			}
			/* ... but 'this' was bad. Replace it... */
			dbg_readinode("Bad CRC on old overlapping node. Kill it\n");
			tn_erase(this, &rii->tn_root);
			jffs2_kill_tn(c, this);
			break;
		}

		this = tn_next(this);
	}

	/* We neither completely obsoleted nor were completely
	   obsoleted by an earlier node. Insert into the tree */
	{
		struct rb_node *parent;
		struct rb_node **link = &rii->tn_root.rb_node;
		struct jffs2_tmp_dnode_info *insert_point = NULL;

		while (*link) {
			parent = *link;
			insert_point = rb_entry(parent, struct jffs2_tmp_dnode_info, rb);
			if (tn->fn->ofs > insert_point->fn->ofs)
				link = &insert_point->rb.rb_right;
			else if (tn->fn->ofs < insert_point->fn->ofs ||
				 tn->fn->size < insert_point->fn->size)
				link = &insert_point->rb.rb_left;
			else
				link = &insert_point->rb.rb_right;
		}
		rb_link_node(&tn->rb, &insert_point->rb, link);
		rb_insert_color(&tn->rb, &rii->tn_root);
	}

	/* If there's anything behind that overlaps us, note it */
	this = tn_prev(tn);
	if (this) {
		while (1) {
			if (this->fn->ofs + this->fn->size > tn->fn->ofs) {
				dbg_readinode("Node is overlapped by %p (v %d, 0x%x-0x%x)\n",
					      this, this->version, this->fn->ofs,
					      this->fn->ofs+this->fn->size);
				tn->overlapped = 1;
				break;
			}
			if (!this->overlapped)
				break;

			ptn = tn_prev(this);
			if (!ptn) {
				/*
				 * We killed a node which set the overlapped
				 * flags during the scan. Fix it up.
				 */
				this->overlapped = 0;
				break;
			}
			this = ptn;
		}
	}

	/* If the new node overlaps anything ahead, note it */
	this = tn_next(tn);
	while (this && this->fn->ofs < fn_end) {
		this->overlapped = 1;
		dbg_readinode("Node ver %d, 0x%x-0x%x is overlapped\n",
			      this->version, this->fn->ofs,
			      this->fn->ofs+this->fn->size);
		this = tn_next(this);
	}
	return 0;
}

/* Trivial function to remove the last node in the tree. Which by definition
   has no right-hand child — so can be removed just by making its left-hand
   child (if any) take its place under its parent. Since this is only done
   when we're consuming the whole tree, there's no need to use rb_erase()
   and let it worry about adjusting colours and balancing the tree. That
   would just be a waste of time. */
static void eat_last(struct rb_root *root, struct rb_node *node)
{
	struct rb_node *parent = rb_parent(node);
	struct rb_node **link;

	/* LAST! */
	BUG_ON(node->rb_right);

	if (!parent)
		link = &root->rb_node;
	else if (node == parent->rb_left)
		link = &parent->rb_left;
	else
		link = &parent->rb_right;

	*link = node->rb_left;
	if (node->rb_left)
		node->rb_left->__rb_parent_color = node->__rb_parent_color;
}

/* We put the version tree in reverse order, so we can use the same eat_last()
   function that we use to consume the tmpnode tree (tn_root). */
static void ver_insert(struct rb_root *ver_root, struct jffs2_tmp_dnode_info *tn)
{
	struct rb_node **link = &ver_root->rb_node;
	struct rb_node *parent = NULL;
	struct jffs2_tmp_dnode_info *this_tn;

	while (*link) {
		parent = *link;
		this_tn = rb_entry(parent, struct jffs2_tmp_dnode_info, rb);

		if (tn->version > this_tn->version)
			link = &parent->rb_left;
		else
			link = &parent->rb_right;
	}
	dbg_readinode("Link new node at %p (root is %p)\n", link, ver_root);
	rb_link_node(&tn->rb, parent, link);
	rb_insert_color(&tn->rb, ver_root);
}

/* Build final, normal fragtree from tn tree. It doesn't matter which order
   we add nodes to the real fragtree, as long as they don't overlap. And
   having thrown away the majority of overlapped nodes as we went, there
   really shouldn't be many sets of nodes which do overlap. If we start at
   the end, we can use the overlap markers -- we can just eat nodes which
   aren't overlapped, and when we encounter nodes which _do_ overlap we
   sort them all into a temporary tree in version order before replaying them. */
static int jffs2_build_inode_fragtree(struct jffs2_sb_info *c,
				      struct jffs2_inode_info *f,
				      struct jffs2_readinode_info *rii)
{
	struct jffs2_tmp_dnode_info *pen, *last, *this;
	struct rb_root ver_root = RB_ROOT;
	uint32_t high_ver = 0;

	if (rii->mdata_tn) {
		dbg_readinode("potential mdata is ver %d at %p\n", rii->mdata_tn->version, rii->mdata_tn);
		high_ver = rii->mdata_tn->version;
		rii->latest_ref = rii->mdata_tn->fn->raw;
	}
#ifdef JFFS2_DBG_READINODE_MESSAGES
	this = tn_last(&rii->tn_root);
	while (this) {
		dbg_readinode("tn %p ver %d range 0x%x-0x%x ov %d\n", this, this->version, this->fn->ofs,
			      this->fn->ofs+this->fn->size, this->overlapped);
		this = tn_prev(this);
	}
#endif
	pen = tn_last(&rii->tn_root);
	while ((last = pen)) {
		pen = tn_prev(last);

		eat_last(&rii->tn_root, &last->rb);
		ver_insert(&ver_root, last);

		if (unlikely(last->overlapped)) {
			if (pen)
				continue;
			/*
			 * We killed a node which set the overlapped
			 * flags during the scan. Fix it up.
			 */
			last->overlapped = 0;
		}

		/* Now we have a bunch of nodes in reverse version
		   order, in the tree at ver_root. Most of the time,
		   there'll actually be only one node in the 'tree',
		   in fact. */
		this = tn_last(&ver_root);

		while (this) {
			struct jffs2_tmp_dnode_info *vers_next;
			int ret;
			vers_next = tn_prev(this);
			eat_last(&ver_root, &this->rb);
			if (check_tn_node(c, this)) {
				dbg_readinode("node ver %d, 0x%x-0x%x failed CRC\n",
					     this->version, this->fn->ofs,
					     this->fn->ofs+this->fn->size);
				jffs2_kill_tn(c, this);
			} else {
				if (this->version > high_ver) {
					/* Note that this is different from the other
					   highest_version, because this one is only
					   counting _valid_ nodes which could give the
					   latest inode metadata */
					high_ver = this->version;
					rii->latest_ref = this->fn->raw;
				}
				dbg_readinode("Add %p (v %d, 0x%x-0x%x, ov %d) to fragtree\n",
					     this, this->version, this->fn->ofs,
					     this->fn->ofs+this->fn->size, this->overlapped);

				ret = jffs2_add_full_dnode_to_inode(c, f, this->fn);
				if (ret) {
					/* Free the nodes in vers_root; let the caller
					   deal with the rest */
					JFFS2_ERROR("Add node to tree failed %d\n", ret);
					while (1) {
						vers_next = tn_prev(this);
						if (check_tn_node(c, this))
							jffs2_mark_node_obsolete(c, this->fn->raw);
						jffs2_free_full_dnode(this->fn);
						jffs2_free_tmp_dnode_info(this);
						this = vers_next;
						if (!this)
							break;
						eat_last(&ver_root, &vers_next->rb);
					}
					return ret;
				}
				jffs2_free_tmp_dnode_info(this);
			}
			this = vers_next;
		}
	}
	return 0;
}

static void jffs2_free_tmp_dnode_info_list(struct rb_root *list)
{
	struct jffs2_tmp_dnode_info *tn, *next;

	rbtree_postorder_for_each_entry_safe(tn, next, list, rb) {
			jffs2_free_full_dnode(tn->fn);
			jffs2_free_tmp_dnode_info(tn);
	}

	*list = RB_ROOT;
}

static void jffs2_free_full_dirent_list(struct jffs2_full_dirent *fd)
{
	struct jffs2_full_dirent *next;

	while (fd) {
		next = fd->next;
		jffs2_free_full_dirent(fd);
		fd = next;
	}
}

/* Returns first valid node after 'ref'. May return 'ref' */
static struct jffs2_raw_node_ref *jffs2_first_valid_node(struct jffs2_raw_node_ref *ref)
{
	while (ref && ref->next_in_ino) {
		if (!ref_obsolete(ref))
			return ref;
		dbg_noderef("node at 0x%08x is obsoleted. Ignoring.\n", ref_offset(ref));
		ref = ref->next_in_ino;
	}
	return NULL;
}

/*
 * Helper function for jffs2_get_inode_nodes().
 * It is called every time an directory entry node is found.
 *
 * Returns: 0 on success;
 * 	    negative error code on failure.
 */
static inline int read_direntry(struct jffs2_sb_info *c, struct jffs2_raw_node_ref *ref,
				struct jffs2_raw_dirent *rd, size_t read,
				struct jffs2_readinode_info *rii)
{
	struct jffs2_full_dirent *fd;
	uint32_t crc;

	/* Obsoleted. This cannot happen, surely? dwmw2 20020308 */
	BUG_ON(ref_obsolete(ref));

	crc = crc32(0, rd, sizeof(*rd) - 8);
	if (unlikely(crc != je32_to_cpu(rd->node_crc))) {
		JFFS2_NOTICE("header CRC failed on dirent node at %#08x: read %#08x, calculated %#08x\n",
			     ref_offset(ref), je32_to_cpu(rd->node_crc), crc);
		jffs2_mark_node_obsolete(c, ref);
		return 0;
	}

	/* If we've never checked the CRCs on this node, check them now */
	if (ref_flags(ref) == REF_UNCHECKED) {
		struct jffs2_eraseblock *jeb;
		int len;

		/* Sanity check */
		if (unlikely(PAD((rd->nsize + sizeof(*rd))) != PAD(je32_to_cpu(rd->totlen)))) {
			JFFS2_ERROR("illegal nsize in node at %#08x: nsize %#02x, totlen %#04x\n",
				    ref_offset(ref), rd->nsize, je32_to_cpu(rd->totlen));
			jffs2_mark_node_obsolete(c, ref);
			return 0;
		}

		jeb = &c->blocks[ref->flash_offset / c->sector_size];
		len = ref_totlen(c, jeb, ref);

		spin_lock(&c->erase_completion_lock);
		jeb->used_size += len;
		jeb->unchecked_size -= len;
		c->used_size += len;
		c->unchecked_size -= len;
		ref->flash_offset = ref_offset(ref) | dirent_node_state(rd);
		spin_unlock(&c->erase_completion_lock);
	}

	fd = jffs2_alloc_full_dirent(rd->nsize + 1);
	if (unlikely(!fd))
		return -ENOMEM;

	fd->raw = ref;
	fd->version = je32_to_cpu(rd->version);
	fd->ino = je32_to_cpu(rd->ino);
	fd->type = rd->type;

	if (fd->version > rii->highest_version)
		rii->highest_version = fd->version;

	/* Pick out the mctime of the latest dirent */
	if(fd->version > rii->mctime_ver && je32_to_cpu(rd->mctime)) {
		rii->mctime_ver = fd->version;
		rii->latest_mctime = je32_to_cpu(rd->mctime);
	}

	/*
	 * Copy as much of the name as possible from the raw
	 * dirent we've already read from the flash.
	 */
	if (read > sizeof(*rd))
		memcpy(&fd->name[0], &rd->name[0],
		       min_t(uint32_t, rd->nsize, (read - sizeof(*rd)) ));

	/* Do we need to copy any more of the name directly from the flash? */
	if (rd->nsize + sizeof(*rd) > read) {
		/* FIXME: point() */
		int err;
		int already = read - sizeof(*rd);

		err = jffs2_flash_read(c, (ref_offset(ref)) + read,
				rd->nsize - already, &read, &fd->name[already]);
		if (unlikely(read != rd->nsize - already) && likely(!err))
			return -EIO;

		if (unlikely(err)) {
			JFFS2_ERROR("read remainder of name: error %d\n", err);
			jffs2_free_full_dirent(fd);
			return -EIO;
		}
	}

	fd->nhash = full_name_hash(fd->name, rd->nsize);
	fd->next = NULL;
	fd->name[rd->nsize] = '\0';

	/*
	 * Wheee. We now have a complete jffs2_full_dirent structure, with
	 * the name in it and everything. Link it into the list
	 */
	jffs2_add_fd_to_list(c, fd, &rii->fds);

	return 0;
}

/*
 * Helper function for jffs2_get_inode_nodes().
 * It is called every time an inode node is found.
 *
 * Returns: 0 on success (possibly after marking a bad node obsolete);
 * 	    negative error code on failure.
 */
static inline int read_dnode(struct jffs2_sb_info *c, struct jffs2_raw_node_ref *ref,
			     struct jffs2_raw_inode *rd, int rdlen,
			     struct jffs2_readinode_info *rii)
{
	struct jffs2_tmp_dnode_info *tn;
	uint32_t len, csize;
	int ret = 0;
	uint32_t crc;

	/* Obsoleted. This cannot happen, surely? dwmw2 20020308 */
	BUG_ON(ref_obsolete(ref));

	crc = crc32(0, rd, sizeof(*rd) - 8);
	if (unlikely(crc != je32_to_cpu(rd->node_crc))) {
		JFFS2_NOTICE("node CRC failed on dnode at %#08x: read %#08x, calculated %#08x\n",
			     ref_offset(ref), je32_to_cpu(rd->node_crc), crc);
		jffs2_mark_node_obsolete(c, ref);
		return 0;
	}

	tn = jffs2_alloc_tmp_dnode_info();
	if (!tn) {
		JFFS2_ERROR("failed to allocate tn (%zu bytes).\n", sizeof(*tn));
		return -ENOMEM;
	}

	tn->partial_crc = 0;
	csize = je32_to_cpu(rd->csize);

	/* If we've never checked the CRCs on this node, check them now */
	if (ref_flags(ref) == REF_UNCHECKED) {

		/* Sanity checks */
		if (unlikely(je32_to_cpu(rd->offset) > je32_to_cpu(rd->isize)) ||
		    unlikely(PAD(je32_to_cpu(rd->csize) + sizeof(*rd)) != PAD(je32_to_cpu(rd->totlen)))) {
			JFFS2_WARNING("inode node header CRC is corrupted at %#08x\n", ref_offset(ref));
			jffs2_dbg_dump_node(c, ref_offset(ref));
			jffs2_mark_node_obsolete(c, ref);
			goto free_out;
		}

		if (jffs2_is_writebuffered(c) && csize != 0) {
			/* At this point we are supposed to check the data CRC
			 * of our unchecked node. But thus far, we do not
			 * know whether the node is valid or obsolete. To
			 * figure this out, we need to walk all the nodes of
			 * the inode and build the inode fragtree. We don't
			 * want to spend time checking data of nodes which may
			 * later be found to be obsolete. So we put off the full
			 * data CRC checking until we have read all the inode
			 * nodes and have started building the fragtree.
			 *
			 * The fragtree is being built starting with nodes
			 * having the highest version number, so we'll be able
			 * to detect whether a node is valid (i.e., it is not
			 * overlapped by a node with higher version) or not.
			 * And we'll be able to check only those nodes, which
			 * are not obsolete.
			 *
			 * Of course, this optimization only makes sense in case
			 * of NAND flashes (or other flashes with
			 * !jffs2_can_mark_obsolete()), since on NOR flashes
			 * nodes are marked obsolete physically.
			 *
			 * Since NAND flashes (or other flashes with
			 * jffs2_is_writebuffered(c)) are anyway read by
			 * fractions of c->wbuf_pagesize, and we have just read
			 * the node header, it is likely that the starting part
			 * of the node data is also read when we read the
			 * header. So we don't mind to check the CRC of the
			 * starting part of the data of the node now, and check
			 * the second part later (in jffs2_check_node_data()).
			 * Of course, we will not need to re-read and re-check
			 * the NAND page which we have just read. This is why we
			 * read the whole NAND page at jffs2_get_inode_nodes(),
			 * while we needed only the node header.
			 */
			unsigned char *buf;

			/* 'buf' will point to the start of data */
			buf = (unsigned char *)rd + sizeof(*rd);
			/* len will be the read data length */
			len = min_t(uint32_t, rdlen - sizeof(*rd), csize);
			tn->partial_crc = crc32(0, buf, len);

			dbg_readinode("Calculates CRC (%#08x) for %d bytes, csize %d\n", tn->partial_crc, len, csize);

			/* If we actually calculated the whole data CRC
			 * and it is wrong, drop the node. */
			if (len >= csize && unlikely(tn->partial_crc != je32_to_cpu(rd->data_crc))) {
				JFFS2_NOTICE("wrong data CRC in data node at 0x%08x: read %#08x, calculated %#08x.\n",
					ref_offset(ref), tn->partial_crc, je32_to_cpu(rd->data_crc));
				jffs2_mark_node_obsolete(c, ref);
				goto free_out;
			}

		} else if (csize == 0) {
			/*
			 * We checked the header CRC. If the node has no data, adjust
			 * the space accounting now. For other nodes this will be done
			 * later either when the node is marked obsolete or when its
			 * data is checked.
			 */
			struct jffs2_eraseblock *jeb;

			dbg_readinode("the node has no data.\n");
			jeb = &c->blocks[ref->flash_offset / c->sector_size];
			len = ref_totlen(c, jeb, ref);

			spin_lock(&c->erase_completion_lock);
			jeb->used_size += len;
			jeb->unchecked_size -= len;
			c->used_size += len;
			c->unchecked_size -= len;
			ref->flash_offset = ref_offset(ref) | REF_NORMAL;
			spin_unlock(&c->erase_completion_lock);
		}
	}

	tn->fn = jffs2_alloc_full_dnode();
	if (!tn->fn) {
		JFFS2_ERROR("alloc fn failed\n");
		ret = -ENOMEM;
		goto free_out;
	}

	tn->version = je32_to_cpu(rd->version);
	tn->fn->ofs = je32_to_cpu(rd->offset);
	tn->data_crc = je32_to_cpu(rd->data_crc);
	tn->csize = csize;
	tn->fn->raw = ref;
	tn->overlapped = 0;

	if (tn->version > rii->highest_version)
		rii->highest_version = tn->version;

	/* There was a bug where we wrote hole nodes out with
	   csize/dsize swapped. Deal with it */
	if (rd->compr == JFFS2_COMPR_ZERO && !je32_to_cpu(rd->dsize) && csize)
		tn->fn->size = csize;
	else // normal case...
		tn->fn->size = je32_to_cpu(rd->dsize);

	dbg_readinode2("dnode @%08x: ver %u, offset %#04x, dsize %#04x, csize %#04x\n",
		       ref_offset(ref), je32_to_cpu(rd->version),
		       je32_to_cpu(rd->offset), je32_to_cpu(rd->dsize), csize);

	ret = jffs2_add_tn_to_tree(c, rii, tn);

	if (ret) {
		jffs2_free_full_dnode(tn->fn);
	free_out:
		jffs2_free_tmp_dnode_info(tn);
		return ret;
	}
#ifdef JFFS2_DBG_READINODE2_MESSAGES
	dbg_readinode2("After adding ver %d:\n", je32_to_cpu(rd->version));
	tn = tn_first(&rii->tn_root);
	while (tn) {
		dbg_readinode2("%p: v %d r 0x%x-0x%x ov %d\n",
			       tn, tn->version, tn->fn->ofs,
			       tn->fn->ofs+tn->fn->size, tn->overlapped);
		tn = tn_next(tn);
	}
#endif
	return 0;
}

/*
 * Helper function for jffs2_get_inode_nodes().
 * It is called every time an unknown node is found.
 *
 * Returns: 0 on success;
 * 	    negative error code on failure.
 */
static inline int read_unknown(struct jffs2_sb_info *c, struct jffs2_raw_node_ref *ref, struct jffs2_unknown_node *un)
{
	/* We don't mark unknown nodes as REF_UNCHECKED */
	if (ref_flags(ref) == REF_UNCHECKED) {
		JFFS2_ERROR("REF_UNCHECKED but unknown node at %#08x\n",
			    ref_offset(ref));
		JFFS2_ERROR("Node is {%04x,%04x,%08x,%08x}. Please report this error.\n",
			    je16_to_cpu(un->magic), je16_to_cpu(un->nodetype),
			    je32_to_cpu(un->totlen), je32_to_cpu(un->hdr_crc));
		jffs2_mark_node_obsolete(c, ref);
		return 0;
	}

	un->nodetype = cpu_to_je16(JFFS2_NODE_ACCURATE | je16_to_cpu(un->nodetype));

	switch(je16_to_cpu(un->nodetype) & JFFS2_COMPAT_MASK) {

	case JFFS2_FEATURE_INCOMPAT:
		JFFS2_ERROR("unknown INCOMPAT nodetype %#04X at %#08x\n",
			    je16_to_cpu(un->nodetype), ref_offset(ref));
		/* EEP */
		BUG();
		break;

	case JFFS2_FEATURE_ROCOMPAT:
		JFFS2_ERROR("unknown ROCOMPAT nodetype %#04X at %#08x\n",
			    je16_to_cpu(un->nodetype), ref_offset(ref));
		BUG_ON(!(c->flags & JFFS2_SB_FLAG_RO));
		break;

	case JFFS2_FEATURE_RWCOMPAT_COPY:
		JFFS2_NOTICE("unknown RWCOMPAT_COPY nodetype %#04X at %#08x\n",
			     je16_to_cpu(un->nodetype), ref_offset(ref));
		break;

	case JFFS2_FEATURE_RWCOMPAT_DELETE:
		JFFS2_NOTICE("unknown RWCOMPAT_DELETE nodetype %#04X at %#08x\n",
			     je16_to_cpu(un->nodetype), ref_offset(ref));
		jffs2_mark_node_obsolete(c, ref);
		return 0;
	}

	return 0;
}

/*
 * Helper function for jffs2_get_inode_nodes().
 * The function detects whether more data should be read and reads it if yes.
 *
 * Returns: 0 on success;
 * 	    negative error code on failure.
 */
static int read_more(struct jffs2_sb_info *c, struct jffs2_raw_node_ref *ref,
		     int needed_len, int *rdlen, unsigned char *buf)
{
	int err, to_read = needed_len - *rdlen;
	size_t retlen;
	uint32_t offs;

	if (jffs2_is_writebuffered(c)) {
		int rem = to_read % c->wbuf_pagesize;

		if (rem)
			to_read += c->wbuf_pagesize - rem;
	}

	/* We need to read more data */
	offs = ref_offset(ref) + *rdlen;

	dbg_readinode("read more %d bytes\n", to_read);

	err = jffs2_flash_read(c, offs, to_read, &retlen, buf + *rdlen);
	if (err) {
		JFFS2_ERROR("can not read %d bytes from 0x%08x, "
			"error code: %d.\n", to_read, offs, err);
		return err;
	}

	if (retlen < to_read) {
		JFFS2_ERROR("short read at %#08x: %zu instead of %d.\n",
				offs, retlen, to_read);
		return -EIO;
	}

	*rdlen += to_read;
	return 0;
}

/* Get tmp_dnode_info and full_dirent for all non-obsolete nodes associated
   with this ino. Perform a preliminary ordering on data nodes, throwing away
   those which are completely obsoleted by newer ones. The naïve approach we
   use to take of just returning them _all_ in version order will cause us to
   run out of memory in certain degenerate cases. */
static int jffs2_get_inode_nodes(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
				 struct jffs2_readinode_info *rii)
{
	struct jffs2_raw_node_ref *ref, *valid_ref;
	unsigned char *buf = NULL;
	union jffs2_node_union *node;
	size_t retlen;
	int len, err;

	rii->mctime_ver = 0;

	dbg_readinode("ino #%u\n", f->inocache->ino);

	/* FIXME: in case of NOR and available ->point() this
	 * needs to be fixed. */
	len = sizeof(union jffs2_node_union) + c->wbuf_pagesize;
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	spin_lock(&c->erase_completion_lock);
	valid_ref = jffs2_first_valid_node(f->inocache->nodes);
	if (!valid_ref && f->inocache->ino != 1)
		JFFS2_WARNING("Eep. No valid nodes for ino #%u.\n", f->inocache->ino);
	while (valid_ref) {
		/* We can hold a pointer to a non-obsolete node without the spinlock,
		   but _obsolete_ nodes may disappear at any time, if the block
		   they're in gets erased. So if we mark 'ref' obsolete while we're
		   not holding the lock, it can go away immediately. For that reason,
		   we find the next valid node first, before processing 'ref'.
		*/
		ref = valid_ref;
		valid_ref = jffs2_first_valid_node(ref->next_in_ino);
		spin_unlock(&c->erase_completion_lock);

		cond_resched();

		/*
		 * At this point we don't know the type of the node we're going
		 * to read, so we do not know the size of its header. In order
		 * to minimize the amount of flash IO we assume the header is
		 * of size = JFFS2_MIN_NODE_HEADER.
		 */
		len = JFFS2_MIN_NODE_HEADER;
		if (jffs2_is_writebuffered(c)) {
			int end, rem;

			/*
			 * We are about to read JFFS2_MIN_NODE_HEADER bytes,
			 * but this flash has some minimal I/O unit. It is
			 * possible that we'll need to read more soon, so read
			 * up to the next min. I/O unit, in order not to
			 * re-read the same min. I/O unit twice.
			 */
			end = ref_offset(ref) + len;
			rem = end % c->wbuf_pagesize;
			if (rem)
				end += c->wbuf_pagesize - rem;
			len = end - ref_offset(ref);
		}

		dbg_readinode("read %d bytes at %#08x(%d).\n", len, ref_offset(ref), ref_flags(ref));

		/* FIXME: point() */
		err = jffs2_flash_read(c, ref_offset(ref), len, &retlen, buf);
		if (err) {
			JFFS2_ERROR("can not read %d bytes from 0x%08x, error code: %d.\n", len, ref_offset(ref), err);
			goto free_out;
		}

		if (retlen < len) {
			JFFS2_ERROR("short read at %#08x: %zu instead of %d.\n", ref_offset(ref), retlen, len);
			err = -EIO;
			goto free_out;
		}

		node = (union jffs2_node_union *)buf;

		/* No need to mask in the valid bit; it shouldn't be invalid */
		if (je32_to_cpu(node->u.hdr_crc) != crc32(0, node, sizeof(node->u)-4)) {
			JFFS2_NOTICE("Node header CRC failed at %#08x. {%04x,%04x,%08x,%08x}\n",
				     ref_offset(ref), je16_to_cpu(node->u.magic),
				     je16_to_cpu(node->u.nodetype),
				     je32_to_cpu(node->u.totlen),
				     je32_to_cpu(node->u.hdr_crc));
			jffs2_dbg_dump_node(c, ref_offset(ref));
			jffs2_mark_node_obsolete(c, ref);
			goto cont;
		}
		if (je16_to_cpu(node->u.magic) != JFFS2_MAGIC_BITMASK) {
			/* Not a JFFS2 node, whinge and move on */
			JFFS2_NOTICE("Wrong magic bitmask 0x%04x in node header at %#08x.\n",
				     je16_to_cpu(node->u.magic), ref_offset(ref));
			jffs2_mark_node_obsolete(c, ref);
			goto cont;
		}

		switch (je16_to_cpu(node->u.nodetype)) {

		case JFFS2_NODETYPE_DIRENT:

			if (JFFS2_MIN_NODE_HEADER < sizeof(struct jffs2_raw_dirent) &&
			    len < sizeof(struct jffs2_raw_dirent)) {
				err = read_more(c, ref, sizeof(struct jffs2_raw_dirent), &len, buf);
				if (unlikely(err))
					goto free_out;
			}

			err = read_direntry(c, ref, &node->d, retlen, rii);
			if (unlikely(err))
				goto free_out;

			break;

		case JFFS2_NODETYPE_INODE:

			if (JFFS2_MIN_NODE_HEADER < sizeof(struct jffs2_raw_inode) &&
			    len < sizeof(struct jffs2_raw_inode)) {
				err = read_more(c, ref, sizeof(struct jffs2_raw_inode), &len, buf);
				if (unlikely(err))
					goto free_out;
			}

			err = read_dnode(c, ref, &node->i, len, rii);
			if (unlikely(err))
				goto free_out;

			break;

		default:
			if (JFFS2_MIN_NODE_HEADER < sizeof(struct jffs2_unknown_node) &&
			    len < sizeof(struct jffs2_unknown_node)) {
				err = read_more(c, ref, sizeof(struct jffs2_unknown_node), &len, buf);
				if (unlikely(err))
					goto free_out;
			}

			err = read_unknown(c, ref, &node->u);
			if (unlikely(err))
				goto free_out;

		}
	cont:
		spin_lock(&c->erase_completion_lock);
	}

	spin_unlock(&c->erase_completion_lock);
	kfree(buf);

	f->highest_version = rii->highest_version;

	dbg_readinode("nodes of inode #%u were read, the highest version is %u, latest_mctime %u, mctime_ver %u.\n",
		      f->inocache->ino, rii->highest_version, rii->latest_mctime,
		      rii->mctime_ver);
	return 0;

 free_out:
	jffs2_free_tmp_dnode_info_list(&rii->tn_root);
	jffs2_free_full_dirent_list(rii->fds);
	rii->fds = NULL;
	kfree(buf);
	return err;
}

static int jffs2_do_read_inode_internal(struct jffs2_sb_info *c,
					struct jffs2_inode_info *f,
					struct jffs2_raw_inode *latest_node)
{
	struct jffs2_readinode_info rii;
	uint32_t crc, new_size;
	size_t retlen;
	int ret;

	dbg_readinode("ino #%u pino/nlink is %d\n", f->inocache->ino,
		      f->inocache->pino_nlink);

	memset(&rii, 0, sizeof(rii));

	/* Grab all nodes relevant to this ino */
	ret = jffs2_get_inode_nodes(c, f, &rii);

	if (ret) {
		JFFS2_ERROR("cannot read nodes for ino %u, returned error is %d\n", f->inocache->ino, ret);
		if (f->inocache->state == INO_STATE_READING)
			jffs2_set_inocache_state(c, f->inocache, INO_STATE_CHECKEDABSENT);
		return ret;
	}

	ret = jffs2_build_inode_fragtree(c, f, &rii);
	if (ret) {
		JFFS2_ERROR("Failed to build final fragtree for inode #%u: error %d\n",
			    f->inocache->ino, ret);
		if (f->inocache->state == INO_STATE_READING)
			jffs2_set_inocache_state(c, f->inocache, INO_STATE_CHECKEDABSENT);
		jffs2_free_tmp_dnode_info_list(&rii.tn_root);
		/* FIXME: We could at least crc-check them all */
		if (rii.mdata_tn) {
			jffs2_free_full_dnode(rii.mdata_tn->fn);
			jffs2_free_tmp_dnode_info(rii.mdata_tn);
			rii.mdata_tn = NULL;
		}
		return ret;
	}

	if (rii.mdata_tn) {
		if (rii.mdata_tn->fn->raw == rii.latest_ref) {
			f->metadata = rii.mdata_tn->fn;
			jffs2_free_tmp_dnode_info(rii.mdata_tn);
		} else {
			jffs2_kill_tn(c, rii.mdata_tn);
		}
		rii.mdata_tn = NULL;
	}

	f->dents = rii.fds;

	jffs2_dbg_fragtree_paranoia_check_nolock(f);

	if (unlikely(!rii.latest_ref)) {
		/* No data nodes for this inode. */
		if (f->inocache->ino != 1) {
			JFFS2_WARNING("no data nodes found for ino #%u\n", f->inocache->ino);
			if (!rii.fds) {
				if (f->inocache->state == INO_STATE_READING)
					jffs2_set_inocache_state(c, f->inocache, INO_STATE_CHECKEDABSENT);
				return -EIO;
			}
			JFFS2_NOTICE("but it has children so we fake some modes for it\n");
		}
		latest_node->mode = cpu_to_jemode(S_IFDIR|S_IRUGO|S_IWUSR|S_IXUGO);
		latest_node->version = cpu_to_je32(0);
		latest_node->atime = latest_node->ctime = latest_node->mtime = cpu_to_je32(0);
		latest_node->isize = cpu_to_je32(0);
		latest_node->gid = cpu_to_je16(0);
		latest_node->uid = cpu_to_je16(0);
		if (f->inocache->state == INO_STATE_READING)
			jffs2_set_inocache_state(c, f->inocache, INO_STATE_PRESENT);
		return 0;
	}

	ret = jffs2_flash_read(c, ref_offset(rii.latest_ref), sizeof(*latest_node), &retlen, (void *)latest_node);
	if (ret || retlen != sizeof(*latest_node)) {
		JFFS2_ERROR("failed to read from flash: error %d, %zd of %zd bytes read\n",
			ret, retlen, sizeof(*latest_node));
		/* FIXME: If this fails, there seems to be a memory leak. Find it. */
		mutex_unlock(&f->sem);
		jffs2_do_clear_inode(c, f);
		return ret?ret:-EIO;
	}

	crc = crc32(0, latest_node, sizeof(*latest_node)-8);
	if (crc != je32_to_cpu(latest_node->node_crc)) {
		JFFS2_ERROR("CRC failed for read_inode of inode %u at physical location 0x%x\n",
			f->inocache->ino, ref_offset(rii.latest_ref));
		mutex_unlock(&f->sem);
		jffs2_do_clear_inode(c, f);
		return -EIO;
	}

	switch(jemode_to_cpu(latest_node->mode) & S_IFMT) {
	case S_IFDIR:
		if (rii.mctime_ver > je32_to_cpu(latest_node->version)) {
			/* The times in the latest_node are actually older than
			   mctime in the latest dirent. Cheat. */
			latest_node->ctime = latest_node->mtime = cpu_to_je32(rii.latest_mctime);
		}
		break;


	case S_IFREG:
		/* If it was a regular file, truncate it to the latest node's isize */
		new_size = jffs2_truncate_fragtree(c, &f->fragtree, je32_to_cpu(latest_node->isize));
		if (new_size != je32_to_cpu(latest_node->isize)) {
			JFFS2_WARNING("Truncating ino #%u to %d bytes failed because it only had %d bytes to start with!\n",
				      f->inocache->ino, je32_to_cpu(latest_node->isize), new_size);
			latest_node->isize = cpu_to_je32(new_size);
		}
		break;

	case S_IFLNK:
		/* Hack to work around broken isize in old symlink code.
		   Remove this when dwmw2 comes to his senses and stops
		   symlinks from being an entirely gratuitous special
		   case. */
		if (!je32_to_cpu(latest_node->isize))
			latest_node->isize = latest_node->dsize;

		if (f->inocache->state != INO_STATE_CHECKING) {
			/* Symlink's inode data is the target path. Read it and
			 * keep in RAM to facilitate quick follow symlink
			 * operation. */
			uint32_t csize = je32_to_cpu(latest_node->csize);
			if (csize > JFFS2_MAX_NAME_LEN) {
				mutex_unlock(&f->sem);
				jffs2_do_clear_inode(c, f);
				return -ENAMETOOLONG;
			}
			f->target = kmalloc(csize + 1, GFP_KERNEL);
			if (!f->target) {
				JFFS2_ERROR("can't allocate %u bytes of memory for the symlink target path cache\n", csize);
				mutex_unlock(&f->sem);
				jffs2_do_clear_inode(c, f);
				return -ENOMEM;
			}

			ret = jffs2_flash_read(c, ref_offset(rii.latest_ref) + sizeof(*latest_node),
					       csize, &retlen, (char *)f->target);

			if (ret || retlen != csize) {
				if (retlen != csize)
					ret = -EIO;
				kfree(f->target);
				f->target = NULL;
				mutex_unlock(&f->sem);
				jffs2_do_clear_inode(c, f);
				return ret;
			}

			f->target[csize] = '\0';
			dbg_readinode("symlink's target '%s' cached\n", f->target);
		}

		/* fall through... */

	case S_IFBLK:
	case S_IFCHR:
		/* Certain inode types should have only one data node, and it's
		   kept as the metadata node */
		if (f->metadata) {
			JFFS2_ERROR("Argh. Special inode #%u with mode 0%o had metadata node\n",
			       f->inocache->ino, jemode_to_cpu(latest_node->mode));
			mutex_unlock(&f->sem);
			jffs2_do_clear_inode(c, f);
			return -EIO;
		}
		if (!frag_first(&f->fragtree)) {
			JFFS2_ERROR("Argh. Special inode #%u with mode 0%o has no fragments\n",
			       f->inocache->ino, jemode_to_cpu(latest_node->mode));
			mutex_unlock(&f->sem);
			jffs2_do_clear_inode(c, f);
			return -EIO;
		}
		/* ASSERT: f->fraglist != NULL */
		if (frag_next(frag_first(&f->fragtree))) {
			JFFS2_ERROR("Argh. Special inode #%u with mode 0x%x had more than one node\n",
			       f->inocache->ino, jemode_to_cpu(latest_node->mode));
			/* FIXME: Deal with it - check crc32, check for duplicate node, check times and discard the older one */
			mutex_unlock(&f->sem);
			jffs2_do_clear_inode(c, f);
			return -EIO;
		}
		/* OK. We're happy */
		f->metadata = frag_first(&f->fragtree)->node;
		jffs2_free_node_frag(frag_first(&f->fragtree));
		f->fragtree = RB_ROOT;
		break;
	}
	if (f->inocache->state == INO_STATE_READING)
		jffs2_set_inocache_state(c, f->inocache, INO_STATE_PRESENT);

	return 0;
}

/* Scan the list of all nodes present for this ino, build map of versions, etc. */
int jffs2_do_read_inode(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
			uint32_t ino, struct jffs2_raw_inode *latest_node)
{
	dbg_readinode("read inode #%u\n", ino);

 retry_inocache:
	spin_lock(&c->inocache_lock);
	f->inocache = jffs2_get_ino_cache(c, ino);

	if (f->inocache) {
		/* Check its state. We may need to wait before we can use it */
		switch(f->inocache->state) {
		case INO_STATE_UNCHECKED:
		case INO_STATE_CHECKEDABSENT:
			f->inocache->state = INO_STATE_READING;
			break;

		case INO_STATE_CHECKING:
		case INO_STATE_GC:
			/* If it's in either of these states, we need
			   to wait for whoever's got it to finish and
			   put it back. */
			dbg_readinode("waiting for ino #%u in state %d\n", ino, f->inocache->state);
			sleep_on_spinunlock(&c->inocache_wq, &c->inocache_lock);
			goto retry_inocache;

		case INO_STATE_READING:
		case INO_STATE_PRESENT:
			/* Eep. This should never happen. It can
			happen if Linux calls read_inode() again
			before clear_inode() has finished though. */
			JFFS2_ERROR("Eep. Trying to read_inode #%u when it's already in state %d!\n", ino, f->inocache->state);
			/* Fail. That's probably better than allowing it to succeed */
			f->inocache = NULL;
			break;

		default:
			BUG();
		}
	}
	spin_unlock(&c->inocache_lock);

	if (!f->inocache && ino == 1) {
		/* Special case - no root inode on medium */
		f->inocache = jffs2_alloc_inode_cache();
		if (!f->inocache) {
			JFFS2_ERROR("cannot allocate inocache for root inode\n");
			return -ENOMEM;
		}
		dbg_readinode("creating inocache for root inode\n");
		memset(f->inocache, 0, sizeof(struct jffs2_inode_cache));
		f->inocache->ino = f->inocache->pino_nlink = 1;
		f->inocache->nodes = (struct jffs2_raw_node_ref *)f->inocache;
		f->inocache->state = INO_STATE_READING;
		jffs2_add_ino_cache(c, f->inocache);
	}
	if (!f->inocache) {
		JFFS2_ERROR("requestied to read an nonexistent ino %u\n", ino);
		return -ENOENT;
	}

	return jffs2_do_read_inode_internal(c, f, latest_node);
}

int jffs2_do_crccheck_inode(struct jffs2_sb_info *c, struct jffs2_inode_cache *ic)
{
	struct jffs2_raw_inode n;
	struct jffs2_inode_info *f = kzalloc(sizeof(*f), GFP_KERNEL);
	int ret;

	if (!f)
		return -ENOMEM;

	mutex_init(&f->sem);
	mutex_lock(&f->sem);
	f->inocache = ic;

	ret = jffs2_do_read_inode_internal(c, f, &n);
	if (!ret) {
		mutex_unlock(&f->sem);
		jffs2_do_clear_inode(c, f);
	}
	jffs2_xattr_do_crccheck_inode(c, ic);
	kfree (f);
	return ret;
}

void jffs2_do_clear_inode(struct jffs2_sb_info *c, struct jffs2_inode_info *f)
{
	struct jffs2_full_dirent *fd, *fds;
	int deleted;

	jffs2_xattr_delete_inode(c, f->inocache);
	mutex_lock(&f->sem);
	deleted = f->inocache && !f->inocache->pino_nlink;

	if (f->inocache && f->inocache->state != INO_STATE_CHECKING)
		jffs2_set_inocache_state(c, f->inocache, INO_STATE_CLEARING);

	if (f->metadata) {
		if (deleted)
			jffs2_mark_node_obsolete(c, f->metadata->raw);
		jffs2_free_full_dnode(f->metadata);
	}

	jffs2_kill_fragtree(&f->fragtree, deleted?c:NULL);

	if (f->target) {
		kfree(f->target);
		f->target = NULL;
	}

	fds = f->dents;
	while(fds) {
		fd = fds;
		fds = fd->next;
		jffs2_free_full_dirent(fd);
	}

	if (f->inocache && f->inocache->state != INO_STATE_CHECKING) {
		jffs2_set_inocache_state(c, f->inocache, INO_STATE_CHECKEDABSENT);
		if (f->inocache->nodes == (void *)f->inocache)
			jffs2_del_ino_cache(c, f->inocache);
	}

	mutex_unlock(&f->sem);
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/readinode.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/fs.h>
// #include <linux/crc32.h>
// #include <linux/pagemap.h>
// #include <linux/mtd/mtd.h>
// #include "nodelist.h"
// #include "compr.h"


int jffs2_do_new_inode(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
		       uint32_t mode, struct jffs2_raw_inode *ri)
{
	struct jffs2_inode_cache *ic;

	ic = jffs2_alloc_inode_cache();
	if (!ic) {
		return -ENOMEM;
	}

	memset(ic, 0, sizeof(*ic));

	f->inocache = ic;
	f->inocache->pino_nlink = 1; /* Will be overwritten shortly for directories */
	f->inocache->nodes = (struct jffs2_raw_node_ref *)f->inocache;
	f->inocache->state = INO_STATE_PRESENT;

	jffs2_add_ino_cache(c, f->inocache);
	jffs2_dbg(1, "%s(): Assigned ino# %d\n", __func__, f->inocache->ino);
	ri->ino = cpu_to_je32(f->inocache->ino);

	ri->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	ri->nodetype = cpu_to_je16(JFFS2_NODETYPE_INODE);
	ri->totlen = cpu_to_je32(PAD(sizeof(*ri)));
	ri->hdr_crc = cpu_to_je32(crc32(0, ri, sizeof(struct jffs2_unknown_node)-4));
	ri->mode = cpu_to_jemode(mode);

	f->highest_version = 1;
	ri->version = cpu_to_je32(f->highest_version);

	return 0;
}

/* jffs2_write_dnode - given a raw_inode, allocate a full_dnode for it,
   write it to the flash, link it into the existing inode/fragment list */

struct jffs2_full_dnode *jffs2_write_dnode(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
					   struct jffs2_raw_inode *ri, const unsigned char *data,
					   uint32_t datalen, int alloc_mode)

{
	struct jffs2_full_dnode *fn;
	size_t retlen;
	uint32_t flash_ofs;
	struct kvec vecs[2];
	int ret;
	int retried = 0;
	unsigned long cnt = 2;

	D1(if(je32_to_cpu(ri->hdr_crc) != crc32(0, ri, sizeof(struct jffs2_unknown_node)-4)) {
		pr_crit("Eep. CRC not correct in jffs2_write_dnode()\n");
		BUG();
	}
	   );
	vecs[0].iov_base = ri;
	vecs[0].iov_len = sizeof(*ri);
	vecs[1].iov_base = (unsigned char *)data;
	vecs[1].iov_len = datalen;

	if (je32_to_cpu(ri->totlen) != sizeof(*ri) + datalen) {
		pr_warn("%s(): ri->totlen (0x%08x) != sizeof(*ri) (0x%08zx) + datalen (0x%08x)\n",
			__func__, je32_to_cpu(ri->totlen),
			sizeof(*ri), datalen);
	}

	fn = jffs2_alloc_full_dnode();
	if (!fn)
		return ERR_PTR(-ENOMEM);

	/* check number of valid vecs */
	if (!datalen || !data)
		cnt = 1;
 retry:
	flash_ofs = write_ofs(c);

	jffs2_dbg_prewrite_paranoia_check(c, flash_ofs, vecs[0].iov_len + vecs[1].iov_len);

	if ((alloc_mode!=ALLOC_GC) && (je32_to_cpu(ri->version) < f->highest_version)) {
		BUG_ON(!retried);
		jffs2_dbg(1, "%s(): dnode_version %d, highest version %d -> updating dnode\n",
			  __func__,
			  je32_to_cpu(ri->version), f->highest_version);
		ri->version = cpu_to_je32(++f->highest_version);
		ri->node_crc = cpu_to_je32(crc32(0, ri, sizeof(*ri)-8));
	}

	ret = jffs2_flash_writev(c, vecs, cnt, flash_ofs, &retlen,
				 (alloc_mode==ALLOC_GC)?0:f->inocache->ino);

	if (ret || (retlen != sizeof(*ri) + datalen)) {
		pr_notice("Write of %zd bytes at 0x%08x failed. returned %d, retlen %zd\n",
			  sizeof(*ri) + datalen, flash_ofs, ret, retlen);

		/* Mark the space as dirtied */
		if (retlen) {
			/* Don't change raw->size to match retlen. We may have
			   written the node header already, and only the data will
			   seem corrupted, in which case the scan would skip over
			   any node we write before the original intended end of
			   this node */
			jffs2_add_physical_node_ref(c, flash_ofs | REF_OBSOLETE, PAD(sizeof(*ri)+datalen), NULL);
		} else {
			pr_notice("Not marking the space at 0x%08x as dirty because the flash driver returned retlen zero\n",
				  flash_ofs);
		}
		if (!retried && alloc_mode != ALLOC_NORETRY) {
			/* Try to reallocate space and retry */
			uint32_t dummy;
			struct jffs2_eraseblock *jeb = &c->blocks[flash_ofs / c->sector_size];

			retried = 1;

			jffs2_dbg(1, "Retrying failed write.\n");

			jffs2_dbg_acct_sanity_check(c,jeb);
			jffs2_dbg_acct_paranoia_check(c, jeb);

			if (alloc_mode == ALLOC_GC) {
				ret = jffs2_reserve_space_gc(c, sizeof(*ri) + datalen, &dummy,
							     JFFS2_SUMMARY_INODE_SIZE);
			} else {
				/* Locking pain */
				mutex_unlock(&f->sem);
				jffs2_complete_reservation(c);

				ret = jffs2_reserve_space(c, sizeof(*ri) + datalen, &dummy,
							  alloc_mode, JFFS2_SUMMARY_INODE_SIZE);
				mutex_lock(&f->sem);
			}

			if (!ret) {
				flash_ofs = write_ofs(c);
				jffs2_dbg(1, "Allocated space at 0x%08x to retry failed write.\n",
					  flash_ofs);

				jffs2_dbg_acct_sanity_check(c,jeb);
				jffs2_dbg_acct_paranoia_check(c, jeb);

				goto retry;
			}
			jffs2_dbg(1, "Failed to allocate space to retry failed write: %d!\n",
				  ret);
		}
		/* Release the full_dnode which is now useless, and return */
		jffs2_free_full_dnode(fn);
		return ERR_PTR(ret?ret:-EIO);
	}
	/* Mark the space used */
	/* If node covers at least a whole page, or if it starts at the
	   beginning of a page and runs to the end of the file, or if
	   it's a hole node, mark it REF_PRISTINE, else REF_NORMAL.
	*/
	if ((je32_to_cpu(ri->dsize) >= PAGE_CACHE_SIZE) ||
	    ( ((je32_to_cpu(ri->offset)&(PAGE_CACHE_SIZE-1))==0) &&
	      (je32_to_cpu(ri->dsize)+je32_to_cpu(ri->offset) ==  je32_to_cpu(ri->isize)))) {
		flash_ofs |= REF_PRISTINE;
	} else {
		flash_ofs |= REF_NORMAL;
	}
	fn->raw = jffs2_add_physical_node_ref(c, flash_ofs, PAD(sizeof(*ri)+datalen), f->inocache);
	if (IS_ERR(fn->raw)) {
		void *hold_err = fn->raw;
		/* Release the full_dnode which is now useless, and return */
		jffs2_free_full_dnode(fn);
		return ERR_CAST(hold_err);
	}
	fn->ofs = je32_to_cpu(ri->offset);
	fn->size = je32_to_cpu(ri->dsize);
	fn->frags = 0;

	jffs2_dbg(1, "jffs2_write_dnode wrote node at 0x%08x(%d) with dsize 0x%x, csize 0x%x, node_crc 0x%08x, data_crc 0x%08x, totlen 0x%08x\n",
		  flash_ofs & ~3, flash_ofs & 3, je32_to_cpu(ri->dsize),
		  je32_to_cpu(ri->csize), je32_to_cpu(ri->node_crc),
		  je32_to_cpu(ri->data_crc), je32_to_cpu(ri->totlen));

	if (retried) {
		jffs2_dbg_acct_sanity_check(c,NULL);
	}

	return fn;
}

struct jffs2_full_dirent *jffs2_write_dirent(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
					     struct jffs2_raw_dirent *rd, const unsigned char *name,
					     uint32_t namelen, int alloc_mode)
{
	struct jffs2_full_dirent *fd;
	size_t retlen;
	struct kvec vecs[2];
	uint32_t flash_ofs;
	int retried = 0;
	int ret;

	jffs2_dbg(1, "%s(ino #%u, name at *0x%p \"%s\"->ino #%u, name_crc 0x%08x)\n",
		  __func__,
		  je32_to_cpu(rd->pino), name, name, je32_to_cpu(rd->ino),
		  je32_to_cpu(rd->name_crc));

	D1(if(je32_to_cpu(rd->hdr_crc) != crc32(0, rd, sizeof(struct jffs2_unknown_node)-4)) {
		pr_crit("Eep. CRC not correct in jffs2_write_dirent()\n");
		BUG();
	   });

	if (strnlen(name, namelen) != namelen) {
		/* This should never happen, but seems to have done on at least one
		   occasion: https://dev.laptop.org/ticket/4184 */
		pr_crit("Error in jffs2_write_dirent() -- name contains zero bytes!\n");
		pr_crit("Directory inode #%u, name at *0x%p \"%s\"->ino #%u, name_crc 0x%08x\n",
			je32_to_cpu(rd->pino), name, name, je32_to_cpu(rd->ino),
			je32_to_cpu(rd->name_crc));
		WARN_ON(1);
		return ERR_PTR(-EIO);
	}

	vecs[0].iov_base = rd;
	vecs[0].iov_len = sizeof(*rd);
	vecs[1].iov_base = (unsigned char *)name;
	vecs[1].iov_len = namelen;

	fd = jffs2_alloc_full_dirent(namelen+1);
	if (!fd)
		return ERR_PTR(-ENOMEM);

	fd->version = je32_to_cpu(rd->version);
	fd->ino = je32_to_cpu(rd->ino);
	fd->nhash = full_name_hash(name, namelen);
	fd->type = rd->type;
	memcpy(fd->name, name, namelen);
	fd->name[namelen]=0;

 retry:
	flash_ofs = write_ofs(c);

	jffs2_dbg_prewrite_paranoia_check(c, flash_ofs, vecs[0].iov_len + vecs[1].iov_len);

	if ((alloc_mode!=ALLOC_GC) && (je32_to_cpu(rd->version) < f->highest_version)) {
		BUG_ON(!retried);
		jffs2_dbg(1, "%s(): dirent_version %d, highest version %d -> updating dirent\n",
			  __func__,
			  je32_to_cpu(rd->version), f->highest_version);
		rd->version = cpu_to_je32(++f->highest_version);
		fd->version = je32_to_cpu(rd->version);
		rd->node_crc = cpu_to_je32(crc32(0, rd, sizeof(*rd)-8));
	}

	ret = jffs2_flash_writev(c, vecs, 2, flash_ofs, &retlen,
				 (alloc_mode==ALLOC_GC)?0:je32_to_cpu(rd->pino));
	if (ret || (retlen != sizeof(*rd) + namelen)) {
		pr_notice("Write of %zd bytes at 0x%08x failed. returned %d, retlen %zd\n",
			  sizeof(*rd) + namelen, flash_ofs, ret, retlen);
		/* Mark the space as dirtied */
		if (retlen) {
			jffs2_add_physical_node_ref(c, flash_ofs | REF_OBSOLETE, PAD(sizeof(*rd)+namelen), NULL);
		} else {
			pr_notice("Not marking the space at 0x%08x as dirty because the flash driver returned retlen zero\n",
				  flash_ofs);
		}
		if (!retried) {
			/* Try to reallocate space and retry */
			uint32_t dummy;
			struct jffs2_eraseblock *jeb = &c->blocks[flash_ofs / c->sector_size];

			retried = 1;

			jffs2_dbg(1, "Retrying failed write.\n");

			jffs2_dbg_acct_sanity_check(c,jeb);
			jffs2_dbg_acct_paranoia_check(c, jeb);

			if (alloc_mode == ALLOC_GC) {
				ret = jffs2_reserve_space_gc(c, sizeof(*rd) + namelen, &dummy,
							     JFFS2_SUMMARY_DIRENT_SIZE(namelen));
			} else {
				/* Locking pain */
				mutex_unlock(&f->sem);
				jffs2_complete_reservation(c);

				ret = jffs2_reserve_space(c, sizeof(*rd) + namelen, &dummy,
							  alloc_mode, JFFS2_SUMMARY_DIRENT_SIZE(namelen));
				mutex_lock(&f->sem);
			}

			if (!ret) {
				flash_ofs = write_ofs(c);
				jffs2_dbg(1, "Allocated space at 0x%08x to retry failed write\n",
					  flash_ofs);
				jffs2_dbg_acct_sanity_check(c,jeb);
				jffs2_dbg_acct_paranoia_check(c, jeb);
				goto retry;
			}
			jffs2_dbg(1, "Failed to allocate space to retry failed write: %d!\n",
				  ret);
		}
		/* Release the full_dnode which is now useless, and return */
		jffs2_free_full_dirent(fd);
		return ERR_PTR(ret?ret:-EIO);
	}
	/* Mark the space used */
	fd->raw = jffs2_add_physical_node_ref(c, flash_ofs | dirent_node_state(rd),
					      PAD(sizeof(*rd)+namelen), f->inocache);
	if (IS_ERR(fd->raw)) {
		void *hold_err = fd->raw;
		/* Release the full_dirent which is now useless, and return */
		jffs2_free_full_dirent(fd);
		return ERR_CAST(hold_err);
	}

	if (retried) {
		jffs2_dbg_acct_sanity_check(c,NULL);
	}

	return fd;
}

/* The OS-specific code fills in the metadata in the jffs2_raw_inode for us, so that
   we don't have to go digging in struct inode or its equivalent. It should set:
   mode, uid, gid, (starting)isize, atime, ctime, mtime */
int jffs2_write_inode_range(struct jffs2_sb_info *c, struct jffs2_inode_info *f,
			    struct jffs2_raw_inode *ri, unsigned char *buf,
			    uint32_t offset, uint32_t writelen, uint32_t *retlen)
{
	int ret = 0;
	uint32_t writtenlen = 0;

	jffs2_dbg(1, "%s(): Ino #%u, ofs 0x%x, len 0x%x\n",
		  __func__, f->inocache->ino, offset, writelen);

	while(writelen) {
		struct jffs2_full_dnode *fn;
		unsigned char *comprbuf = NULL;
		uint16_t comprtype = JFFS2_COMPR_NONE;
		uint32_t alloclen;
		uint32_t datalen, cdatalen;
		int retried = 0;

	retry:
		jffs2_dbg(2, "jffs2_commit_write() loop: 0x%x to write to 0x%x\n",
			  writelen, offset);

		ret = jffs2_reserve_space(c, sizeof(*ri) + JFFS2_MIN_DATA_LEN,
					&alloclen, ALLOC_NORMAL, JFFS2_SUMMARY_INODE_SIZE);
		if (ret) {
			jffs2_dbg(1, "jffs2_reserve_space returned %d\n", ret);
			break;
		}
		mutex_lock(&f->sem);
		datalen = min_t(uint32_t, writelen, PAGE_CACHE_SIZE - (offset & (PAGE_CACHE_SIZE-1)));
		cdatalen = min_t(uint32_t, alloclen - sizeof(*ri), datalen);

		comprtype = jffs2_compress(c, f, buf, &comprbuf, &datalen, &cdatalen);

		ri->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
		ri->nodetype = cpu_to_je16(JFFS2_NODETYPE_INODE);
		ri->totlen = cpu_to_je32(sizeof(*ri) + cdatalen);
		ri->hdr_crc = cpu_to_je32(crc32(0, ri, sizeof(struct jffs2_unknown_node)-4));

		ri->ino = cpu_to_je32(f->inocache->ino);
		ri->version = cpu_to_je32(++f->highest_version);
		ri->isize = cpu_to_je32(max(je32_to_cpu(ri->isize), offset + datalen));
		ri->offset = cpu_to_je32(offset);
		ri->csize = cpu_to_je32(cdatalen);
		ri->dsize = cpu_to_je32(datalen);
		ri->compr = comprtype & 0xff;
		ri->usercompr = (comprtype >> 8 ) & 0xff;
		ri->node_crc = cpu_to_je32(crc32(0, ri, sizeof(*ri)-8));
		ri->data_crc = cpu_to_je32(crc32(0, comprbuf, cdatalen));

		fn = jffs2_write_dnode(c, f, ri, comprbuf, cdatalen, ALLOC_NORETRY);

		jffs2_free_comprbuf(comprbuf, buf);

		if (IS_ERR(fn)) {
			ret = PTR_ERR(fn);
			mutex_unlock(&f->sem);
			jffs2_complete_reservation(c);
			if (!retried) {
				/* Write error to be retried */
				retried = 1;
				jffs2_dbg(1, "Retrying node write in jffs2_write_inode_range()\n");
				goto retry;
			}
			break;
		}
		ret = jffs2_add_full_dnode_to_inode(c, f, fn);
		if (f->metadata) {
			jffs2_mark_node_obsolete(c, f->metadata->raw);
			jffs2_free_full_dnode(f->metadata);
			f->metadata = NULL;
		}
		if (ret) {
			/* Eep */
			jffs2_dbg(1, "Eep. add_full_dnode_to_inode() failed in commit_write, returned %d\n",
				  ret);
			jffs2_mark_node_obsolete(c, fn->raw);
			jffs2_free_full_dnode(fn);

			mutex_unlock(&f->sem);
			jffs2_complete_reservation(c);
			break;
		}
		mutex_unlock(&f->sem);
		jffs2_complete_reservation(c);
		if (!datalen) {
			pr_warn("Eep. We didn't actually write any data in jffs2_write_inode_range()\n");
			ret = -EIO;
			break;
		}
		jffs2_dbg(1, "increasing writtenlen by %d\n", datalen);
		writtenlen += datalen;
		offset += datalen;
		writelen -= datalen;
		buf += datalen;
	}
	*retlen = writtenlen;
	return ret;
}

int jffs2_do_create(struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f,
		    struct jffs2_inode_info *f, struct jffs2_raw_inode *ri,
		    const struct qstr *qstr)
{
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dnode *fn;
	struct jffs2_full_dirent *fd;
	uint32_t alloclen;
	int ret;

	/* Try to reserve enough space for both node and dirent.
	 * Just the node will do for now, though
	 */
	ret = jffs2_reserve_space(c, sizeof(*ri), &alloclen, ALLOC_NORMAL,
				JFFS2_SUMMARY_INODE_SIZE);
	jffs2_dbg(1, "%s(): reserved 0x%x bytes\n", __func__, alloclen);
	if (ret)
		return ret;

	mutex_lock(&f->sem);

	ri->data_crc = cpu_to_je32(0);
	ri->node_crc = cpu_to_je32(crc32(0, ri, sizeof(*ri)-8));

	fn = jffs2_write_dnode(c, f, ri, NULL, 0, ALLOC_NORMAL);

	jffs2_dbg(1, "jffs2_do_create created file with mode 0x%x\n",
		  jemode_to_cpu(ri->mode));

	if (IS_ERR(fn)) {
		jffs2_dbg(1, "jffs2_write_dnode() failed\n");
		/* Eeek. Wave bye bye */
		mutex_unlock(&f->sem);
		jffs2_complete_reservation(c);
		return PTR_ERR(fn);
	}
	/* No data here. Only a metadata node, which will be
	   obsoleted by the first data write
	*/
	f->metadata = fn;

	mutex_unlock(&f->sem);
	jffs2_complete_reservation(c);

	ret = jffs2_init_security(&f->vfs_inode, &dir_f->vfs_inode, qstr);
	if (ret)
		return ret;
	ret = jffs2_init_acl_post(&f->vfs_inode);
	if (ret)
		return ret;

	ret = jffs2_reserve_space(c, sizeof(*rd)+qstr->len, &alloclen,
				ALLOC_NORMAL, JFFS2_SUMMARY_DIRENT_SIZE(qstr->len));

	if (ret) {
		/* Eep. */
		jffs2_dbg(1, "jffs2_reserve_space() for dirent failed\n");
		return ret;
	}

	rd = jffs2_alloc_raw_dirent();
	if (!rd) {
		/* Argh. Now we treat it like a normal delete */
		jffs2_complete_reservation(c);
		return -ENOMEM;
	}

	mutex_lock(&dir_f->sem);

	rd->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	rd->nodetype = cpu_to_je16(JFFS2_NODETYPE_DIRENT);
	rd->totlen = cpu_to_je32(sizeof(*rd) + qstr->len);
	rd->hdr_crc = cpu_to_je32(crc32(0, rd, sizeof(struct jffs2_unknown_node)-4));

	rd->pino = cpu_to_je32(dir_f->inocache->ino);
	rd->version = cpu_to_je32(++dir_f->highest_version);
	rd->ino = ri->ino;
	rd->mctime = ri->ctime;
	rd->nsize = qstr->len;
	rd->type = DT_REG;
	rd->node_crc = cpu_to_je32(crc32(0, rd, sizeof(*rd)-8));
	rd->name_crc = cpu_to_je32(crc32(0, qstr->name, qstr->len));

	fd = jffs2_write_dirent(c, dir_f, rd, qstr->name, qstr->len, ALLOC_NORMAL);

	jffs2_free_raw_dirent(rd);

	if (IS_ERR(fd)) {
		/* dirent failed to write. Delete the inode normally
		   as if it were the final unlink() */
		jffs2_complete_reservation(c);
		mutex_unlock(&dir_f->sem);
		return PTR_ERR(fd);
	}

	/* Link the fd into the inode's list, obsoleting an old
	   one if necessary. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);

	jffs2_complete_reservation(c);
	mutex_unlock(&dir_f->sem);

	return 0;
}


int jffs2_do_unlink(struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f,
		    const char *name, int namelen, struct jffs2_inode_info *dead_f,
		    uint32_t time)
{
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dirent *fd;
	uint32_t alloclen;
	int ret;

	if (!jffs2_can_mark_obsolete(c)) {
		/* We can't mark stuff obsolete on the medium. We need to write a deletion dirent */

		rd = jffs2_alloc_raw_dirent();
		if (!rd)
			return -ENOMEM;

		ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &alloclen,
					ALLOC_DELETION, JFFS2_SUMMARY_DIRENT_SIZE(namelen));
		if (ret) {
			jffs2_free_raw_dirent(rd);
			return ret;
		}

		mutex_lock(&dir_f->sem);

		/* Build a deletion node */
		rd->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
		rd->nodetype = cpu_to_je16(JFFS2_NODETYPE_DIRENT);
		rd->totlen = cpu_to_je32(sizeof(*rd) + namelen);
		rd->hdr_crc = cpu_to_je32(crc32(0, rd, sizeof(struct jffs2_unknown_node)-4));

		rd->pino = cpu_to_je32(dir_f->inocache->ino);
		rd->version = cpu_to_je32(++dir_f->highest_version);
		rd->ino = cpu_to_je32(0);
		rd->mctime = cpu_to_je32(time);
		rd->nsize = namelen;
		rd->type = DT_UNKNOWN;
		rd->node_crc = cpu_to_je32(crc32(0, rd, sizeof(*rd)-8));
		rd->name_crc = cpu_to_je32(crc32(0, name, namelen));

		fd = jffs2_write_dirent(c, dir_f, rd, name, namelen, ALLOC_DELETION);

		jffs2_free_raw_dirent(rd);

		if (IS_ERR(fd)) {
			jffs2_complete_reservation(c);
			mutex_unlock(&dir_f->sem);
			return PTR_ERR(fd);
		}

		/* File it. This will mark the old one obsolete. */
		jffs2_add_fd_to_list(c, fd, &dir_f->dents);
		mutex_unlock(&dir_f->sem);
	} else {
		uint32_t nhash = full_name_hash(name, namelen);

		fd = dir_f->dents;
		/* We don't actually want to reserve any space, but we do
		   want to be holding the alloc_sem when we write to flash */
		mutex_lock(&c->alloc_sem);
		mutex_lock(&dir_f->sem);

		for (fd = dir_f->dents; fd; fd = fd->next) {
			if (fd->nhash == nhash &&
			    !memcmp(fd->name, name, namelen) &&
			    !fd->name[namelen]) {

				jffs2_dbg(1, "Marking old dirent node (ino #%u) @%08x obsolete\n",
					  fd->ino, ref_offset(fd->raw));
				jffs2_mark_node_obsolete(c, fd->raw);
				/* We don't want to remove it from the list immediately,
				   because that screws up getdents()/seek() semantics even
				   more than they're screwed already. Turn it into a
				   node-less deletion dirent instead -- a placeholder */
				fd->raw = NULL;
				fd->ino = 0;
				break;
			}
		}
		mutex_unlock(&dir_f->sem);
	}

	/* dead_f is NULL if this was a rename not a real unlink */
	/* Also catch the !f->inocache case, where there was a dirent
	   pointing to an inode which didn't exist. */
	if (dead_f && dead_f->inocache) {

		mutex_lock(&dead_f->sem);

		if (S_ISDIR(OFNI_EDONI_2SFFJ(dead_f)->i_mode)) {
			while (dead_f->dents) {
				/* There can be only deleted ones */
				fd = dead_f->dents;

				dead_f->dents = fd->next;

				if (fd->ino) {
					pr_warn("Deleting inode #%u with active dentry \"%s\"->ino #%u\n",
						dead_f->inocache->ino,
						fd->name, fd->ino);
				} else {
					jffs2_dbg(1, "Removing deletion dirent for \"%s\" from dir ino #%u\n",
						  fd->name,
						  dead_f->inocache->ino);
				}
				if (fd->raw)
					jffs2_mark_node_obsolete(c, fd->raw);
				jffs2_free_full_dirent(fd);
			}
			dead_f->inocache->pino_nlink = 0;
		} else
			dead_f->inocache->pino_nlink--;
		/* NB: Caller must set inode nlink if appropriate */
		mutex_unlock(&dead_f->sem);
	}

	jffs2_complete_reservation(c);

	return 0;
}


int jffs2_do_link (struct jffs2_sb_info *c, struct jffs2_inode_info *dir_f, uint32_t ino, uint8_t type, const char *name, int namelen, uint32_t time)
{
	struct jffs2_raw_dirent *rd;
	struct jffs2_full_dirent *fd;
	uint32_t alloclen;
	int ret;

	rd = jffs2_alloc_raw_dirent();
	if (!rd)
		return -ENOMEM;

	ret = jffs2_reserve_space(c, sizeof(*rd)+namelen, &alloclen,
				ALLOC_NORMAL, JFFS2_SUMMARY_DIRENT_SIZE(namelen));
	if (ret) {
		jffs2_free_raw_dirent(rd);
		return ret;
	}

	mutex_lock(&dir_f->sem);

	/* Build a deletion node */
	rd->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	rd->nodetype = cpu_to_je16(JFFS2_NODETYPE_DIRENT);
	rd->totlen = cpu_to_je32(sizeof(*rd) + namelen);
	rd->hdr_crc = cpu_to_je32(crc32(0, rd, sizeof(struct jffs2_unknown_node)-4));

	rd->pino = cpu_to_je32(dir_f->inocache->ino);
	rd->version = cpu_to_je32(++dir_f->highest_version);
	rd->ino = cpu_to_je32(ino);
	rd->mctime = cpu_to_je32(time);
	rd->nsize = namelen;

	rd->type = type;

	rd->node_crc = cpu_to_je32(crc32(0, rd, sizeof(*rd)-8));
	rd->name_crc = cpu_to_je32(crc32(0, name, namelen));

	fd = jffs2_write_dirent(c, dir_f, rd, name, namelen, ALLOC_NORMAL);

	jffs2_free_raw_dirent(rd);

	if (IS_ERR(fd)) {
		jffs2_complete_reservation(c);
		mutex_unlock(&dir_f->sem);
		return PTR_ERR(fd);
	}

	/* File it. This will mark the old one obsolete. */
	jffs2_add_fd_to_list(c, fd, &dir_f->dents);

	jffs2_complete_reservation(c);
	mutex_unlock(&dir_f->sem);

	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/write.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
// #include <linux/mtd/mtd.h>
// #include <linux/pagemap.h>
// #include <linux/crc32.h>
// #include <linux/compiler.h>
// #include "nodelist.h"
#include "summary.h"
// #include "debug.h"

#define DEFAULT_EMPTY_SCAN_SIZE 256

#define noisy_printk(noise, fmt, ...)					\
do {									\
	if (*(noise)) {							\
		pr_notice(fmt, ##__VA_ARGS__);				\
		(*(noise))--;						\
		if (!(*(noise)))					\
			pr_notice("Further such events for this erase block will not be printed\n"); \
	}								\
} while (0)

static uint32_t pseudo_random;

static int jffs2_scan_eraseblock (struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				  unsigned char *buf, uint32_t buf_size, struct jffs2_summary *s);

/* These helper functions _must_ increase ofs and also do the dirty/used space accounting.
 * Returning an error will abort the mount - bad checksums etc. should just mark the space
 * as dirty.
 */
static int jffs2_scan_inode_node(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				 struct jffs2_raw_inode *ri, uint32_t ofs, struct jffs2_summary *s);
static int jffs2_scan_dirent_node(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				 struct jffs2_raw_dirent *rd, uint32_t ofs, struct jffs2_summary *s);

static inline int min_free(struct jffs2_sb_info *c)
{
	uint32_t min = 2 * sizeof(struct jffs2_raw_inode);
#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
	if (!jffs2_can_mark_obsolete(c) && min < c->wbuf_pagesize)
		return c->wbuf_pagesize;
#endif
	return min;

}

static inline uint32_t EMPTY_SCAN_SIZE(uint32_t sector_size) {
	if (sector_size < DEFAULT_EMPTY_SCAN_SIZE)
		return sector_size;
	else
		return DEFAULT_EMPTY_SCAN_SIZE;
}

static int file_dirty(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb)
{
	int ret;

	if ((ret = jffs2_prealloc_raw_node_refs(c, jeb, 1)))
		return ret;
	if ((ret = jffs2_scan_dirty_space(c, jeb, jeb->free_size)))
		return ret;
	/* Turned wasted size into dirty, since we apparently
	   think it's recoverable now. */
	jeb->dirty_size += jeb->wasted_size;
	c->dirty_size += jeb->wasted_size;
	c->wasted_size -= jeb->wasted_size;
	jeb->wasted_size = 0;
	if (VERYDIRTY(c, jeb->dirty_size)) {
		list_add(&jeb->list, &c->very_dirty_list);
	} else {
		list_add(&jeb->list, &c->dirty_list);
	}
	return 0;
}

int jffs2_scan_medium(struct jffs2_sb_info *c)
{
	int i, ret;
	uint32_t empty_blocks = 0, bad_blocks = 0;
	unsigned char *flashbuf = NULL;
	uint32_t buf_size = 0;
	struct jffs2_summary *s = NULL; /* summary info collected by the scan process */
#ifndef __ECOS
	size_t pointlen, try_size;

	ret = mtd_point(c->mtd, 0, c->mtd->size, &pointlen,
			(void **)&flashbuf, NULL);
	if (!ret && pointlen < c->mtd->size) {
		/* Don't muck about if it won't let us point to the whole flash */
		jffs2_dbg(1, "MTD point returned len too short: 0x%zx\n",
			  pointlen);
		mtd_unpoint(c->mtd, 0, pointlen);
		flashbuf = NULL;
	}
	if (ret && ret != -EOPNOTSUPP)
		jffs2_dbg(1, "MTD point failed %d\n", ret);
#endif
	if (!flashbuf) {
		/* For NAND it's quicker to read a whole eraseblock at a time,
		   apparently */
		if (jffs2_cleanmarker_oob(c))
			try_size = c->sector_size;
		else
			try_size = PAGE_SIZE;

		jffs2_dbg(1, "Trying to allocate readbuf of %zu "
			  "bytes\n", try_size);

		flashbuf = mtd_kmalloc_up_to(c->mtd, &try_size);
		if (!flashbuf)
			return -ENOMEM;

		jffs2_dbg(1, "Allocated readbuf of %zu bytes\n",
			  try_size);

		buf_size = (uint32_t)try_size;
	}

	if (jffs2_sum_active()) {
		s = kzalloc(sizeof(struct jffs2_summary), GFP_KERNEL);
		if (!s) {
			JFFS2_WARNING("Can't allocate memory for summary\n");
			ret = -ENOMEM;
			goto out;
		}
	}

	for (i=0; i<c->nr_blocks; i++) {
		struct jffs2_eraseblock *jeb = &c->blocks[i];

		cond_resched();

		/* reset summary info for next eraseblock scan */
		jffs2_sum_reset_collected(s);

		ret = jffs2_scan_eraseblock(c, jeb, buf_size?flashbuf:(flashbuf+jeb->offset),
						buf_size, s);

		if (ret < 0)
			goto out;

		jffs2_dbg_acct_paranoia_check_nolock(c, jeb);

		/* Now decide which list to put it on */
		switch(ret) {
		case BLK_STATE_ALLFF:
			/*
			 * Empty block.   Since we can't be sure it
			 * was entirely erased, we just queue it for erase
			 * again.  It will be marked as such when the erase
			 * is complete.  Meanwhile we still count it as empty
			 * for later checks.
			 */
			empty_blocks++;
			list_add(&jeb->list, &c->erase_pending_list);
			c->nr_erasing_blocks++;
			break;

		case BLK_STATE_CLEANMARKER:
			/* Only a CLEANMARKER node is valid */
			if (!jeb->dirty_size) {
				/* It's actually free */
				list_add(&jeb->list, &c->free_list);
				c->nr_free_blocks++;
			} else {
				/* Dirt */
				jffs2_dbg(1, "Adding all-dirty block at 0x%08x to erase_pending_list\n",
					  jeb->offset);
				list_add(&jeb->list, &c->erase_pending_list);
				c->nr_erasing_blocks++;
			}
			break;

		case BLK_STATE_CLEAN:
			/* Full (or almost full) of clean data. Clean list */
			list_add(&jeb->list, &c->clean_list);
			break;

		case BLK_STATE_PARTDIRTY:
			/* Some data, but not full. Dirty list. */
			/* We want to remember the block with most free space
			and stick it in the 'nextblock' position to start writing to it. */
			if (jeb->free_size > min_free(c) &&
					(!c->nextblock || c->nextblock->free_size < jeb->free_size)) {
				/* Better candidate for the next writes to go to */
				if (c->nextblock) {
					ret = file_dirty(c, c->nextblock);
					if (ret)
						goto out;
					/* deleting summary information of the old nextblock */
					jffs2_sum_reset_collected(c->summary);
				}
				/* update collected summary information for the current nextblock */
				jffs2_sum_move_collected(c, s);
				jffs2_dbg(1, "%s(): new nextblock = 0x%08x\n",
					  __func__, jeb->offset);
				c->nextblock = jeb;
			} else {
				ret = file_dirty(c, jeb);
				if (ret)
					goto out;
			}
			break;

		case BLK_STATE_ALLDIRTY:
			/* Nothing valid - not even a clean marker. Needs erasing. */
			/* For now we just put it on the erasing list. We'll start the erases later */
			jffs2_dbg(1, "Erase block at 0x%08x is not formatted. It will be erased\n",
				  jeb->offset);
			list_add(&jeb->list, &c->erase_pending_list);
			c->nr_erasing_blocks++;
			break;

		case BLK_STATE_BADBLOCK:
			jffs2_dbg(1, "Block at 0x%08x is bad\n", jeb->offset);
			list_add(&jeb->list, &c->bad_list);
			c->bad_size += c->sector_size;
			c->free_size -= c->sector_size;
			bad_blocks++;
			break;
		default:
			pr_warn("%s(): unknown block state\n", __func__);
			BUG();
		}
	}

	/* Nextblock dirty is always seen as wasted, because we cannot recycle it now */
	if (c->nextblock && (c->nextblock->dirty_size)) {
		c->nextblock->wasted_size += c->nextblock->dirty_size;
		c->wasted_size += c->nextblock->dirty_size;
		c->dirty_size -= c->nextblock->dirty_size;
		c->nextblock->dirty_size = 0;
	}
#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
	if (!jffs2_can_mark_obsolete(c) && c->wbuf_pagesize && c->nextblock && (c->nextblock->free_size % c->wbuf_pagesize)) {
		/* If we're going to start writing into a block which already
		   contains data, and the end of the data isn't page-aligned,
		   skip a little and align it. */

		uint32_t skip = c->nextblock->free_size % c->wbuf_pagesize;

		jffs2_dbg(1, "%s(): Skipping %d bytes in nextblock to ensure page alignment\n",
			  __func__, skip);
		jffs2_prealloc_raw_node_refs(c, c->nextblock, 1);
		jffs2_scan_dirty_space(c, c->nextblock, skip);
	}
#endif
	if (c->nr_erasing_blocks) {
		if ( !c->used_size && ((c->nr_free_blocks+empty_blocks+bad_blocks)!= c->nr_blocks || bad_blocks == c->nr_blocks) ) {
			pr_notice("Cowardly refusing to erase blocks on filesystem with no valid JFFS2 nodes\n");
			pr_notice("empty_blocks %d, bad_blocks %d, c->nr_blocks %d\n",
				  empty_blocks, bad_blocks, c->nr_blocks);
			ret = -EIO;
			goto out;
		}
		spin_lock(&c->erase_completion_lock);
		jffs2_garbage_collect_trigger(c);
		spin_unlock(&c->erase_completion_lock);
	}
	ret = 0;
 out:
	if (buf_size)
		kfree(flashbuf);
#ifndef __ECOS
	else
		mtd_unpoint(c->mtd, 0, c->mtd->size);
#endif
	kfree(s);
	return ret;
}

static int jffs2_fill_scan_buf(struct jffs2_sb_info *c, void *buf,
			       uint32_t ofs, uint32_t len)
{
	int ret;
	size_t retlen;

	ret = jffs2_flash_read(c, ofs, len, &retlen, buf);
	if (ret) {
		jffs2_dbg(1, "mtd->read(0x%x bytes from 0x%x) returned %d\n",
			  len, ofs, ret);
		return ret;
	}
	if (retlen < len) {
		jffs2_dbg(1, "Read at 0x%x gave only 0x%zx bytes\n",
			  ofs, retlen);
		return -EIO;
	}
	return 0;
}

int jffs2_scan_classify_jeb(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb)
{
	if ((jeb->used_size + jeb->unchecked_size) == PAD(c->cleanmarker_size) && !jeb->dirty_size
	    && (!jeb->first_node || !ref_next(jeb->first_node)) )
		return BLK_STATE_CLEANMARKER;

	/* move blocks with max 4 byte dirty space to cleanlist */
	else if (!ISDIRTY(c->sector_size - (jeb->used_size + jeb->unchecked_size))) {
		c->dirty_size -= jeb->dirty_size;
		c->wasted_size += jeb->dirty_size;
		jeb->wasted_size += jeb->dirty_size;
		jeb->dirty_size = 0;
		return BLK_STATE_CLEAN;
	} else if (jeb->used_size || jeb->unchecked_size)
		return BLK_STATE_PARTDIRTY;
	else
		return BLK_STATE_ALLDIRTY;
}

#ifdef CONFIG_JFFS2_FS_XATTR
static int jffs2_scan_xattr_node(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				 struct jffs2_raw_xattr *rx, uint32_t ofs,
				 struct jffs2_summary *s)
{
	struct jffs2_xattr_datum *xd;
	uint32_t xid, version, totlen, crc;
	int err;

	crc = crc32(0, rx, sizeof(struct jffs2_raw_xattr) - 4);
	if (crc != je32_to_cpu(rx->node_crc)) {
		JFFS2_WARNING("node CRC failed at %#08x, read=%#08x, calc=%#08x\n",
			      ofs, je32_to_cpu(rx->node_crc), crc);
		if ((err = jffs2_scan_dirty_space(c, jeb, je32_to_cpu(rx->totlen))))
			return err;
		return 0;
	}

	xid = je32_to_cpu(rx->xid);
	version = je32_to_cpu(rx->version);

	totlen = PAD(sizeof(struct jffs2_raw_xattr)
			+ rx->name_len + 1 + je16_to_cpu(rx->value_len));
	if (totlen != je32_to_cpu(rx->totlen)) {
		JFFS2_WARNING("node length mismatch at %#08x, read=%u, calc=%u\n",
			      ofs, je32_to_cpu(rx->totlen), totlen);
		if ((err = jffs2_scan_dirty_space(c, jeb, je32_to_cpu(rx->totlen))))
			return err;
		return 0;
	}

	xd = jffs2_setup_xattr_datum(c, xid, version);
	if (IS_ERR(xd))
		return PTR_ERR(xd);

	if (xd->version > version) {
		struct jffs2_raw_node_ref *raw
			= jffs2_link_node_ref(c, jeb, ofs | REF_PRISTINE, totlen, NULL);
		raw->next_in_ino = xd->node->next_in_ino;
		xd->node->next_in_ino = raw;
	} else {
		xd->version = version;
		xd->xprefix = rx->xprefix;
		xd->name_len = rx->name_len;
		xd->value_len = je16_to_cpu(rx->value_len);
		xd->data_crc = je32_to_cpu(rx->data_crc);

		jffs2_link_node_ref(c, jeb, ofs | REF_PRISTINE, totlen, (void *)xd);
	}

	if (jffs2_sum_active())
		jffs2_sum_add_xattr_mem(s, rx, ofs - jeb->offset);
	dbg_xattr("scanning xdatum at %#08x (xid=%u, version=%u)\n",
		  ofs, xd->xid, xd->version);
	return 0;
}

static int jffs2_scan_xref_node(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				struct jffs2_raw_xref *rr, uint32_t ofs,
				struct jffs2_summary *s)
{
	struct jffs2_xattr_ref *ref;
	uint32_t crc;
	int err;

	crc = crc32(0, rr, sizeof(*rr) - 4);
	if (crc != je32_to_cpu(rr->node_crc)) {
		JFFS2_WARNING("node CRC failed at %#08x, read=%#08x, calc=%#08x\n",
			      ofs, je32_to_cpu(rr->node_crc), crc);
		if ((err = jffs2_scan_dirty_space(c, jeb, PAD(je32_to_cpu(rr->totlen)))))
			return err;
		return 0;
	}

	if (PAD(sizeof(struct jffs2_raw_xref)) != je32_to_cpu(rr->totlen)) {
		JFFS2_WARNING("node length mismatch at %#08x, read=%u, calc=%zd\n",
			      ofs, je32_to_cpu(rr->totlen),
			      PAD(sizeof(struct jffs2_raw_xref)));
		if ((err = jffs2_scan_dirty_space(c, jeb, je32_to_cpu(rr->totlen))))
			return err;
		return 0;
	}

	ref = jffs2_alloc_xattr_ref();
	if (!ref)
		return -ENOMEM;

	/* BEFORE jffs2_build_xattr_subsystem() called,
	 * and AFTER xattr_ref is marked as a dead xref,
	 * ref->xid is used to store 32bit xid, xd is not used
	 * ref->ino is used to store 32bit inode-number, ic is not used
	 * Thoes variables are declared as union, thus using those
	 * are exclusive. In a similar way, ref->next is temporarily
	 * used to chain all xattr_ref object. It's re-chained to
	 * jffs2_inode_cache in jffs2_build_xattr_subsystem() correctly.
	 */
	ref->ino = je32_to_cpu(rr->ino);
	ref->xid = je32_to_cpu(rr->xid);
	ref->xseqno = je32_to_cpu(rr->xseqno);
	if (ref->xseqno > c->highest_xseqno)
		c->highest_xseqno = (ref->xseqno & ~XREF_DELETE_MARKER);
	ref->next = c->xref_temp;
	c->xref_temp = ref;

	jffs2_link_node_ref(c, jeb, ofs | REF_PRISTINE, PAD(je32_to_cpu(rr->totlen)), (void *)ref);

	if (jffs2_sum_active())
		jffs2_sum_add_xref_mem(s, rr, ofs - jeb->offset);
	dbg_xattr("scan xref at %#08x (xid=%u, ino=%u)\n",
		  ofs, ref->xid, ref->ino);
	return 0;
}
#endif

/* Called with 'buf_size == 0' if buf is in fact a pointer _directly_ into
   the flash, XIP-style */
static int jffs2_scan_eraseblock (struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				  unsigned char *buf, uint32_t buf_size, struct jffs2_summary *s) {
	struct jffs2_unknown_node *node;
	struct jffs2_unknown_node crcnode;
	uint32_t ofs, prevofs, max_ofs;
	uint32_t hdr_crc, buf_ofs, buf_len;
	int err;
	int noise = 0;


#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
	int cleanmarkerfound = 0;
#endif

	ofs = jeb->offset;
	prevofs = jeb->offset - 1;

	jffs2_dbg(1, "%s(): Scanning block at 0x%x\n", __func__, ofs);

#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
	if (jffs2_cleanmarker_oob(c)) {
		int ret;

		if (mtd_block_isbad(c->mtd, jeb->offset))
			return BLK_STATE_BADBLOCK;

		ret = jffs2_check_nand_cleanmarker(c, jeb);
		jffs2_dbg(2, "jffs_check_nand_cleanmarker returned %d\n", ret);

		/* Even if it's not found, we still scan to see
		   if the block is empty. We use this information
		   to decide whether to erase it or not. */
		switch (ret) {
		case 0:		cleanmarkerfound = 1; break;
		case 1: 	break;
		default: 	return ret;
		}
	}
#endif

	if (jffs2_sum_active()) {
		struct jffs2_sum_marker *sm;
		void *sumptr = NULL;
		uint32_t sumlen;

		if (!buf_size) {
			/* XIP case. Just look, point at the summary if it's there */
			sm = (void *)buf + c->sector_size - sizeof(*sm);
			if (je32_to_cpu(sm->magic) == JFFS2_SUM_MAGIC) {
				sumptr = buf + je32_to_cpu(sm->offset);
				sumlen = c->sector_size - je32_to_cpu(sm->offset);
			}
		} else {
			/* If NAND flash, read a whole page of it. Else just the end */
			if (c->wbuf_pagesize)
				buf_len = c->wbuf_pagesize;
			else
				buf_len = sizeof(*sm);

			/* Read as much as we want into the _end_ of the preallocated buffer */
			err = jffs2_fill_scan_buf(c, buf + buf_size - buf_len,
						  jeb->offset + c->sector_size - buf_len,
						  buf_len);
			if (err)
				return err;

			sm = (void *)buf + buf_size - sizeof(*sm);
			if (je32_to_cpu(sm->magic) == JFFS2_SUM_MAGIC) {
				sumlen = c->sector_size - je32_to_cpu(sm->offset);
				sumptr = buf + buf_size - sumlen;

				/* Now, make sure the summary itself is available */
				if (sumlen > buf_size) {
					/* Need to kmalloc for this. */
					sumptr = kmalloc(sumlen, GFP_KERNEL);
					if (!sumptr)
						return -ENOMEM;
					memcpy(sumptr + sumlen - buf_len, buf + buf_size - buf_len, buf_len);
				}
				if (buf_len < sumlen) {
					/* Need to read more so that the entire summary node is present */
					err = jffs2_fill_scan_buf(c, sumptr,
								  jeb->offset + c->sector_size - sumlen,
								  sumlen - buf_len);
					if (err)
						return err;
				}
			}

		}

		if (sumptr) {
			err = jffs2_sum_scan_sumnode(c, jeb, sumptr, sumlen, &pseudo_random);

			if (buf_size && sumlen > buf_size)
				kfree(sumptr);
			/* If it returns with a real error, bail.
			   If it returns positive, that's a block classification
			   (i.e. BLK_STATE_xxx) so return that too.
			   If it returns zero, fall through to full scan. */
			if (err)
				return err;
		}
	}

	buf_ofs = jeb->offset;

	if (!buf_size) {
		/* This is the XIP case -- we're reading _directly_ from the flash chip */
		buf_len = c->sector_size;
	} else {
		buf_len = EMPTY_SCAN_SIZE(c->sector_size);
		err = jffs2_fill_scan_buf(c, buf, buf_ofs, buf_len);
		if (err)
			return err;
	}

	/* We temporarily use 'ofs' as a pointer into the buffer/jeb */
	ofs = 0;
	max_ofs = EMPTY_SCAN_SIZE(c->sector_size);
	/* Scan only EMPTY_SCAN_SIZE of 0xFF before declaring it's empty */
	while(ofs < max_ofs && *(uint32_t *)(&buf[ofs]) == 0xFFFFFFFF)
		ofs += 4;

	if (ofs == max_ofs) {
#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
		if (jffs2_cleanmarker_oob(c)) {
			/* scan oob, take care of cleanmarker */
			int ret = jffs2_check_oob_empty(c, jeb, cleanmarkerfound);
			jffs2_dbg(2, "jffs2_check_oob_empty returned %d\n",
				  ret);
			switch (ret) {
			case 0:		return cleanmarkerfound ? BLK_STATE_CLEANMARKER : BLK_STATE_ALLFF;
			case 1: 	return BLK_STATE_ALLDIRTY;
			default: 	return ret;
			}
		}
#endif
		jffs2_dbg(1, "Block at 0x%08x is empty (erased)\n",
			  jeb->offset);
		if (c->cleanmarker_size == 0)
			return BLK_STATE_CLEANMARKER;	/* don't bother with re-erase */
		else
			return BLK_STATE_ALLFF;	/* OK to erase if all blocks are like this */
	}
	if (ofs) {
		jffs2_dbg(1, "Free space at %08x ends at %08x\n", jeb->offset,
			  jeb->offset + ofs);
		if ((err = jffs2_prealloc_raw_node_refs(c, jeb, 1)))
			return err;
		if ((err = jffs2_scan_dirty_space(c, jeb, ofs)))
			return err;
	}

	/* Now ofs is a complete physical flash offset as it always was... */
	ofs += jeb->offset;

	noise = 10;

	dbg_summary("no summary found in jeb 0x%08x. Apply original scan.\n",jeb->offset);

scan_more:
	while(ofs < jeb->offset + c->sector_size) {

		jffs2_dbg_acct_paranoia_check_nolock(c, jeb);

		/* Make sure there are node refs available for use */
		err = jffs2_prealloc_raw_node_refs(c, jeb, 2);
		if (err)
			return err;

		cond_resched();

		if (ofs & 3) {
			pr_warn("Eep. ofs 0x%08x not word-aligned!\n", ofs);
			ofs = PAD(ofs);
			continue;
		}
		if (ofs == prevofs) {
			pr_warn("ofs 0x%08x has already been seen. Skipping\n",
				ofs);
			if ((err = jffs2_scan_dirty_space(c, jeb, 4)))
				return err;
			ofs += 4;
			continue;
		}
		prevofs = ofs;

		if (jeb->offset + c->sector_size < ofs + sizeof(*node)) {
			jffs2_dbg(1, "Fewer than %zd bytes left to end of block. (%x+%x<%x+%zx) Not reading\n",
				  sizeof(struct jffs2_unknown_node),
				  jeb->offset, c->sector_size, ofs,
				  sizeof(*node));
			if ((err = jffs2_scan_dirty_space(c, jeb, (jeb->offset + c->sector_size)-ofs)))
				return err;
			break;
		}

		if (buf_ofs + buf_len < ofs + sizeof(*node)) {
			buf_len = min_t(uint32_t, buf_size, jeb->offset + c->sector_size - ofs);
			jffs2_dbg(1, "Fewer than %zd bytes (node header) left to end of buf. Reading 0x%x at 0x%08x\n",
				  sizeof(struct jffs2_unknown_node),
				  buf_len, ofs);
			err = jffs2_fill_scan_buf(c, buf, ofs, buf_len);
			if (err)
				return err;
			buf_ofs = ofs;
		}

		node = (struct jffs2_unknown_node *)&buf[ofs-buf_ofs];

		if (*(uint32_t *)(&buf[ofs-buf_ofs]) == 0xffffffff) {
			uint32_t inbuf_ofs;
			uint32_t empty_start, scan_end;

			empty_start = ofs;
			ofs += 4;
			scan_end = min_t(uint32_t, EMPTY_SCAN_SIZE(c->sector_size)/8, buf_len);

			jffs2_dbg(1, "Found empty flash at 0x%08x\n", ofs);
		more_empty:
			inbuf_ofs = ofs - buf_ofs;
			while (inbuf_ofs < scan_end) {
				if (unlikely(*(uint32_t *)(&buf[inbuf_ofs]) != 0xffffffff)) {
					pr_warn("Empty flash at 0x%08x ends at 0x%08x\n",
						empty_start, ofs);
					if ((err = jffs2_scan_dirty_space(c, jeb, ofs-empty_start)))
						return err;
					goto scan_more;
				}

				inbuf_ofs+=4;
				ofs += 4;
			}
			/* Ran off end. */
			jffs2_dbg(1, "Empty flash to end of buffer at 0x%08x\n",
				  ofs);

			/* If we're only checking the beginning of a block with a cleanmarker,
			   bail now */
			if (buf_ofs == jeb->offset && jeb->used_size == PAD(c->cleanmarker_size) &&
			    c->cleanmarker_size && !jeb->dirty_size && !ref_next(jeb->first_node)) {
				jffs2_dbg(1, "%d bytes at start of block seems clean... assuming all clean\n",
					  EMPTY_SCAN_SIZE(c->sector_size));
				return BLK_STATE_CLEANMARKER;
			}
			if (!buf_size && (scan_end != buf_len)) {/* XIP/point case */
				scan_end = buf_len;
				goto more_empty;
			}

			/* See how much more there is to read in this eraseblock... */
			buf_len = min_t(uint32_t, buf_size, jeb->offset + c->sector_size - ofs);
			if (!buf_len) {
				/* No more to read. Break out of main loop without marking
				   this range of empty space as dirty (because it's not) */
				jffs2_dbg(1, "Empty flash at %08x runs to end of block. Treating as free_space\n",
					  empty_start);
				break;
			}
			/* point never reaches here */
			scan_end = buf_len;
			jffs2_dbg(1, "Reading another 0x%x at 0x%08x\n",
				  buf_len, ofs);
			err = jffs2_fill_scan_buf(c, buf, ofs, buf_len);
			if (err)
				return err;
			buf_ofs = ofs;
			goto more_empty;
		}

		if (ofs == jeb->offset && je16_to_cpu(node->magic) == KSAMTIB_CIGAM_2SFFJ) {
			pr_warn("Magic bitmask is backwards at offset 0x%08x. Wrong endian filesystem?\n",
				ofs);
			if ((err = jffs2_scan_dirty_space(c, jeb, 4)))
				return err;
			ofs += 4;
			continue;
		}
		if (je16_to_cpu(node->magic) == JFFS2_DIRTY_BITMASK) {
			jffs2_dbg(1, "Dirty bitmask at 0x%08x\n", ofs);
			if ((err = jffs2_scan_dirty_space(c, jeb, 4)))
				return err;
			ofs += 4;
			continue;
		}
		if (je16_to_cpu(node->magic) == JFFS2_OLD_MAGIC_BITMASK) {
			pr_warn("Old JFFS2 bitmask found at 0x%08x\n", ofs);
			pr_warn("You cannot use older JFFS2 filesystems with newer kernels\n");
			if ((err = jffs2_scan_dirty_space(c, jeb, 4)))
				return err;
			ofs += 4;
			continue;
		}
		if (je16_to_cpu(node->magic) != JFFS2_MAGIC_BITMASK) {
			/* OK. We're out of possibilities. Whinge and move on */
			noisy_printk(&noise, "%s(): Magic bitmask 0x%04x not found at 0x%08x: 0x%04x instead\n",
				     __func__,
				     JFFS2_MAGIC_BITMASK, ofs,
				     je16_to_cpu(node->magic));
			if ((err = jffs2_scan_dirty_space(c, jeb, 4)))
				return err;
			ofs += 4;
			continue;
		}
		/* We seem to have a node of sorts. Check the CRC */
		crcnode.magic = node->magic;
		crcnode.nodetype = cpu_to_je16( je16_to_cpu(node->nodetype) | JFFS2_NODE_ACCURATE);
		crcnode.totlen = node->totlen;
		hdr_crc = crc32(0, &crcnode, sizeof(crcnode)-4);

		if (hdr_crc != je32_to_cpu(node->hdr_crc)) {
			noisy_printk(&noise, "%s(): Node at 0x%08x {0x%04x, 0x%04x, 0x%08x) has invalid CRC 0x%08x (calculated 0x%08x)\n",
				     __func__,
				     ofs, je16_to_cpu(node->magic),
				     je16_to_cpu(node->nodetype),
				     je32_to_cpu(node->totlen),
				     je32_to_cpu(node->hdr_crc),
				     hdr_crc);
			if ((err = jffs2_scan_dirty_space(c, jeb, 4)))
				return err;
			ofs += 4;
			continue;
		}

		if (ofs + je32_to_cpu(node->totlen) > jeb->offset + c->sector_size) {
			/* Eep. Node goes over the end of the erase block. */
			pr_warn("Node at 0x%08x with length 0x%08x would run over the end of the erase block\n",
				ofs, je32_to_cpu(node->totlen));
			pr_warn("Perhaps the file system was created with the wrong erase size?\n");
			if ((err = jffs2_scan_dirty_space(c, jeb, 4)))
				return err;
			ofs += 4;
			continue;
		}

		if (!(je16_to_cpu(node->nodetype) & JFFS2_NODE_ACCURATE)) {
			/* Wheee. This is an obsoleted node */
			jffs2_dbg(2, "Node at 0x%08x is obsolete. Skipping\n",
				  ofs);
			if ((err = jffs2_scan_dirty_space(c, jeb, PAD(je32_to_cpu(node->totlen)))))
				return err;
			ofs += PAD(je32_to_cpu(node->totlen));
			continue;
		}

		switch(je16_to_cpu(node->nodetype)) {
		case JFFS2_NODETYPE_INODE:
			if (buf_ofs + buf_len < ofs + sizeof(struct jffs2_raw_inode)) {
				buf_len = min_t(uint32_t, buf_size, jeb->offset + c->sector_size - ofs);
				jffs2_dbg(1, "Fewer than %zd bytes (inode node) left to end of buf. Reading 0x%x at 0x%08x\n",
					  sizeof(struct jffs2_raw_inode),
					  buf_len, ofs);
				err = jffs2_fill_scan_buf(c, buf, ofs, buf_len);
				if (err)
					return err;
				buf_ofs = ofs;
				node = (void *)buf;
			}
			err = jffs2_scan_inode_node(c, jeb, (void *)node, ofs, s);
			if (err) return err;
			ofs += PAD(je32_to_cpu(node->totlen));
			break;

		case JFFS2_NODETYPE_DIRENT:
			if (buf_ofs + buf_len < ofs + je32_to_cpu(node->totlen)) {
				buf_len = min_t(uint32_t, buf_size, jeb->offset + c->sector_size - ofs);
				jffs2_dbg(1, "Fewer than %d bytes (dirent node) left to end of buf. Reading 0x%x at 0x%08x\n",
					  je32_to_cpu(node->totlen), buf_len,
					  ofs);
				err = jffs2_fill_scan_buf(c, buf, ofs, buf_len);
				if (err)
					return err;
				buf_ofs = ofs;
				node = (void *)buf;
			}
			err = jffs2_scan_dirent_node(c, jeb, (void *)node, ofs, s);
			if (err) return err;
			ofs += PAD(je32_to_cpu(node->totlen));
			break;

#ifdef CONFIG_JFFS2_FS_XATTR
		case JFFS2_NODETYPE_XATTR:
			if (buf_ofs + buf_len < ofs + je32_to_cpu(node->totlen)) {
				buf_len = min_t(uint32_t, buf_size, jeb->offset + c->sector_size - ofs);
				jffs2_dbg(1, "Fewer than %d bytes (xattr node) left to end of buf. Reading 0x%x at 0x%08x\n",
					  je32_to_cpu(node->totlen), buf_len,
					  ofs);
				err = jffs2_fill_scan_buf(c, buf, ofs, buf_len);
				if (err)
					return err;
				buf_ofs = ofs;
				node = (void *)buf;
			}
			err = jffs2_scan_xattr_node(c, jeb, (void *)node, ofs, s);
			if (err)
				return err;
			ofs += PAD(je32_to_cpu(node->totlen));
			break;
		case JFFS2_NODETYPE_XREF:
			if (buf_ofs + buf_len < ofs + je32_to_cpu(node->totlen)) {
				buf_len = min_t(uint32_t, buf_size, jeb->offset + c->sector_size - ofs);
				jffs2_dbg(1, "Fewer than %d bytes (xref node) left to end of buf. Reading 0x%x at 0x%08x\n",
					  je32_to_cpu(node->totlen), buf_len,
					  ofs);
				err = jffs2_fill_scan_buf(c, buf, ofs, buf_len);
				if (err)
					return err;
				buf_ofs = ofs;
				node = (void *)buf;
			}
			err = jffs2_scan_xref_node(c, jeb, (void *)node, ofs, s);
			if (err)
				return err;
			ofs += PAD(je32_to_cpu(node->totlen));
			break;
#endif	/* CONFIG_JFFS2_FS_XATTR */

		case JFFS2_NODETYPE_CLEANMARKER:
			jffs2_dbg(1, "CLEANMARKER node found at 0x%08x\n", ofs);
			if (je32_to_cpu(node->totlen) != c->cleanmarker_size) {
				pr_notice("CLEANMARKER node found at 0x%08x has totlen 0x%x != normal 0x%x\n",
					  ofs, je32_to_cpu(node->totlen),
					  c->cleanmarker_size);
				if ((err = jffs2_scan_dirty_space(c, jeb, PAD(sizeof(struct jffs2_unknown_node)))))
					return err;
				ofs += PAD(sizeof(struct jffs2_unknown_node));
			} else if (jeb->first_node) {
				pr_notice("CLEANMARKER node found at 0x%08x, not first node in block (0x%08x)\n",
					  ofs, jeb->offset);
				if ((err = jffs2_scan_dirty_space(c, jeb, PAD(sizeof(struct jffs2_unknown_node)))))
					return err;
				ofs += PAD(sizeof(struct jffs2_unknown_node));
			} else {
				jffs2_link_node_ref(c, jeb, ofs | REF_NORMAL, c->cleanmarker_size, NULL);

				ofs += PAD(c->cleanmarker_size);
			}
			break;

		case JFFS2_NODETYPE_PADDING:
			if (jffs2_sum_active())
				jffs2_sum_add_padding_mem(s, je32_to_cpu(node->totlen));
			if ((err = jffs2_scan_dirty_space(c, jeb, PAD(je32_to_cpu(node->totlen)))))
				return err;
			ofs += PAD(je32_to_cpu(node->totlen));
			break;

		default:
			switch (je16_to_cpu(node->nodetype) & JFFS2_COMPAT_MASK) {
			case JFFS2_FEATURE_ROCOMPAT:
				pr_notice("Read-only compatible feature node (0x%04x) found at offset 0x%08x\n",
					  je16_to_cpu(node->nodetype), ofs);
				c->flags |= JFFS2_SB_FLAG_RO;
				if (!(jffs2_is_readonly(c)))
					return -EROFS;
				if ((err = jffs2_scan_dirty_space(c, jeb, PAD(je32_to_cpu(node->totlen)))))
					return err;
				ofs += PAD(je32_to_cpu(node->totlen));
				break;

			case JFFS2_FEATURE_INCOMPAT:
				pr_notice("Incompatible feature node (0x%04x) found at offset 0x%08x\n",
					  je16_to_cpu(node->nodetype), ofs);
				return -EINVAL;

			case JFFS2_FEATURE_RWCOMPAT_DELETE:
				jffs2_dbg(1, "Unknown but compatible feature node (0x%04x) found at offset 0x%08x\n",
					  je16_to_cpu(node->nodetype), ofs);
				if ((err = jffs2_scan_dirty_space(c, jeb, PAD(je32_to_cpu(node->totlen)))))
					return err;
				ofs += PAD(je32_to_cpu(node->totlen));
				break;

			case JFFS2_FEATURE_RWCOMPAT_COPY: {
				jffs2_dbg(1, "Unknown but compatible feature node (0x%04x) found at offset 0x%08x\n",
					  je16_to_cpu(node->nodetype), ofs);

				jffs2_link_node_ref(c, jeb, ofs | REF_PRISTINE, PAD(je32_to_cpu(node->totlen)), NULL);

				/* We can't summarise nodes we don't grok */
				jffs2_sum_disable_collecting(s);
				ofs += PAD(je32_to_cpu(node->totlen));
				break;
				}
			}
		}
	}

	if (jffs2_sum_active()) {
		if (PAD(s->sum_size + JFFS2_SUMMARY_FRAME_SIZE) > jeb->free_size) {
			dbg_summary("There is not enough space for "
				"summary information, disabling for this jeb!\n");
			jffs2_sum_disable_collecting(s);
		}
	}

	jffs2_dbg(1, "Block at 0x%08x: free 0x%08x, dirty 0x%08x, unchecked 0x%08x, used 0x%08x, wasted 0x%08x\n",
		  jeb->offset, jeb->free_size, jeb->dirty_size,
		  jeb->unchecked_size, jeb->used_size, jeb->wasted_size);

	/* mark_node_obsolete can add to wasted !! */
	if (jeb->wasted_size) {
		jeb->dirty_size += jeb->wasted_size;
		c->dirty_size += jeb->wasted_size;
		c->wasted_size -= jeb->wasted_size;
		jeb->wasted_size = 0;
	}

	return jffs2_scan_classify_jeb(c, jeb);
}

struct jffs2_inode_cache *jffs2_scan_make_ino_cache(struct jffs2_sb_info *c, uint32_t ino)
{
	struct jffs2_inode_cache *ic;

	ic = jffs2_get_ino_cache(c, ino);
	if (ic)
		return ic;

	if (ino > c->highest_ino)
		c->highest_ino = ino;

	ic = jffs2_alloc_inode_cache();
	if (!ic) {
		pr_notice("%s(): allocation of inode cache failed\n", __func__);
		return NULL;
	}
	memset(ic, 0, sizeof(*ic));

	ic->ino = ino;
	ic->nodes = (void *)ic;
	jffs2_add_ino_cache(c, ic);
	if (ino == 1)
		ic->pino_nlink = 1;
	return ic;
}

static int jffs2_scan_inode_node(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				 struct jffs2_raw_inode *ri, uint32_t ofs, struct jffs2_summary *s)
{
	struct jffs2_inode_cache *ic;
	uint32_t crc, ino = je32_to_cpu(ri->ino);

	jffs2_dbg(1, "%s(): Node at 0x%08x\n", __func__, ofs);

	/* We do very little here now. Just check the ino# to which we should attribute
	   this node; we can do all the CRC checking etc. later. There's a tradeoff here --
	   we used to scan the flash once only, reading everything we want from it into
	   memory, then building all our in-core data structures and freeing the extra
	   information. Now we allow the first part of the mount to complete a lot quicker,
	   but we have to go _back_ to the flash in order to finish the CRC checking, etc.
	   Which means that the _full_ amount of time to get to proper write mode with GC
	   operational may actually be _longer_ than before. Sucks to be me. */

	/* Check the node CRC in any case. */
	crc = crc32(0, ri, sizeof(*ri)-8);
	if (crc != je32_to_cpu(ri->node_crc)) {
		pr_notice("%s(): CRC failed on node at 0x%08x: Read 0x%08x, calculated 0x%08x\n",
			  __func__, ofs, je32_to_cpu(ri->node_crc), crc);
		/*
		 * We believe totlen because the CRC on the node
		 * _header_ was OK, just the node itself failed.
		 */
		return jffs2_scan_dirty_space(c, jeb,
					      PAD(je32_to_cpu(ri->totlen)));
	}

	ic = jffs2_get_ino_cache(c, ino);
	if (!ic) {
		ic = jffs2_scan_make_ino_cache(c, ino);
		if (!ic)
			return -ENOMEM;
	}

	/* Wheee. It worked */
	jffs2_link_node_ref(c, jeb, ofs | REF_UNCHECKED, PAD(je32_to_cpu(ri->totlen)), ic);

	jffs2_dbg(1, "Node is ino #%u, version %d. Range 0x%x-0x%x\n",
		  je32_to_cpu(ri->ino), je32_to_cpu(ri->version),
		  je32_to_cpu(ri->offset),
		  je32_to_cpu(ri->offset)+je32_to_cpu(ri->dsize));

	pseudo_random += je32_to_cpu(ri->version);

	if (jffs2_sum_active()) {
		jffs2_sum_add_inode_mem(s, ri, ofs - jeb->offset);
	}

	return 0;
}

static int jffs2_scan_dirent_node(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				  struct jffs2_raw_dirent *rd, uint32_t ofs, struct jffs2_summary *s)
{
	struct jffs2_full_dirent *fd;
	struct jffs2_inode_cache *ic;
	uint32_t checkedlen;
	uint32_t crc;
	int err;

	jffs2_dbg(1, "%s(): Node at 0x%08x\n", __func__, ofs);

	/* We don't get here unless the node is still valid, so we don't have to
	   mask in the ACCURATE bit any more. */
	crc = crc32(0, rd, sizeof(*rd)-8);

	if (crc != je32_to_cpu(rd->node_crc)) {
		pr_notice("%s(): Node CRC failed on node at 0x%08x: Read 0x%08x, calculated 0x%08x\n",
			  __func__, ofs, je32_to_cpu(rd->node_crc), crc);
		/* We believe totlen because the CRC on the node _header_ was OK, just the node itself failed. */
		if ((err = jffs2_scan_dirty_space(c, jeb, PAD(je32_to_cpu(rd->totlen)))))
			return err;
		return 0;
	}

	pseudo_random += je32_to_cpu(rd->version);

	/* Should never happen. Did. (OLPC trac #4184)*/
	checkedlen = strnlen(rd->name, rd->nsize);
	if (checkedlen < rd->nsize) {
		pr_err("Dirent at %08x has zeroes in name. Truncating to %d chars\n",
		       ofs, checkedlen);
	}
	fd = jffs2_alloc_full_dirent(checkedlen+1);
	if (!fd) {
		return -ENOMEM;
	}
	memcpy(&fd->name, rd->name, checkedlen);
	fd->name[checkedlen] = 0;

	crc = crc32(0, fd->name, rd->nsize);
	if (crc != je32_to_cpu(rd->name_crc)) {
		pr_notice("%s(): Name CRC failed on node at 0x%08x: Read 0x%08x, calculated 0x%08x\n",
			  __func__, ofs, je32_to_cpu(rd->name_crc), crc);
		jffs2_dbg(1, "Name for which CRC failed is (now) '%s', ino #%d\n",
			  fd->name, je32_to_cpu(rd->ino));
		jffs2_free_full_dirent(fd);
		/* FIXME: Why do we believe totlen? */
		/* We believe totlen because the CRC on the node _header_ was OK, just the name failed. */
		if ((err = jffs2_scan_dirty_space(c, jeb, PAD(je32_to_cpu(rd->totlen)))))
			return err;
		return 0;
	}
	ic = jffs2_scan_make_ino_cache(c, je32_to_cpu(rd->pino));
	if (!ic) {
		jffs2_free_full_dirent(fd);
		return -ENOMEM;
	}

	fd->raw = jffs2_link_node_ref(c, jeb, ofs | dirent_node_state(rd),
				      PAD(je32_to_cpu(rd->totlen)), ic);

	fd->next = NULL;
	fd->version = je32_to_cpu(rd->version);
	fd->ino = je32_to_cpu(rd->ino);
	fd->nhash = full_name_hash(fd->name, checkedlen);
	fd->type = rd->type;
	jffs2_add_fd_to_list(c, fd, &ic->scan_dents);

	if (jffs2_sum_active()) {
		jffs2_sum_add_dirent_mem(s, rd, ofs - jeb->offset);
	}

	return 0;
}

static int count_list(struct list_head *l)
{
	uint32_t count = 0;
	struct list_head *tmp;

	list_for_each(tmp, l) {
		count++;
	}
	return count;
}

/* Note: This breaks if list_empty(head). I don't care. You
   might, if you copy this code and use it elsewhere :) */
static void rotate_list(struct list_head *head, uint32_t count)
{
	struct list_head *n = head->next;

	list_del(head);
	while(count--) {
		n = n->next;
	}
	list_add(head, n);
}

void jffs2_rotate_lists(struct jffs2_sb_info *c)
{
	uint32_t x;
	uint32_t rotateby;

	x = count_list(&c->clean_list);
	if (x) {
		rotateby = pseudo_random % x;
		rotate_list((&c->clean_list), rotateby);
	}

	x = count_list(&c->very_dirty_list);
	if (x) {
		rotateby = pseudo_random % x;
		rotate_list((&c->very_dirty_list), rotateby);
	}

	x = count_list(&c->dirty_list);
	if (x) {
		rotateby = pseudo_random % x;
		rotate_list((&c->dirty_list), rotateby);
	}

	x = count_list(&c->erasable_list);
	if (x) {
		rotateby = pseudo_random % x;
		rotate_list((&c->erasable_list), rotateby);
	}

	if (c->nr_erasing_blocks) {
		rotateby = pseudo_random % c->nr_erasing_blocks;
		rotate_list((&c->erase_pending_list), rotateby);
	}

	if (c->nr_free_blocks) {
		rotateby = pseudo_random % c->nr_free_blocks;
		rotate_list((&c->free_list), rotateby);
	}
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/scan.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/mtd/mtd.h>
// #include <linux/slab.h>
// #include <linux/pagemap.h>
// #include <linux/crc32.h>
// #include <linux/compiler.h>
#include <linux/stat.h>
// #include "nodelist.h"
// #include "compr.h"

static int jffs2_garbage_collect_pristine(struct jffs2_sb_info *c,
					  struct jffs2_inode_cache *ic,
					  struct jffs2_raw_node_ref *raw);
static int jffs2_garbage_collect_metadata(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
					struct jffs2_inode_info *f, struct jffs2_full_dnode *fd);
static int jffs2_garbage_collect_dirent(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
					struct jffs2_inode_info *f, struct jffs2_full_dirent *fd);
static int jffs2_garbage_collect_deletion_dirent(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
					struct jffs2_inode_info *f, struct jffs2_full_dirent *fd);
static int jffs2_garbage_collect_hole(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				      struct jffs2_inode_info *f, struct jffs2_full_dnode *fn,
				      uint32_t start, uint32_t end);
static int jffs2_garbage_collect_dnode(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				       struct jffs2_inode_info *f, struct jffs2_full_dnode *fn,
				       uint32_t start, uint32_t end);
static int jffs2_garbage_collect_live(struct jffs2_sb_info *c,  struct jffs2_eraseblock *jeb,
			       struct jffs2_raw_node_ref *raw, struct jffs2_inode_info *f);

/* Called with erase_completion_lock held */
static struct jffs2_eraseblock *jffs2_find_gc_block(struct jffs2_sb_info *c)
{
	struct jffs2_eraseblock *ret;
	struct list_head *nextlist = NULL;
	int n = jiffies % 128;

	/* Pick an eraseblock to garbage collect next. This is where we'll
	   put the clever wear-levelling algorithms. Eventually.  */
	/* We possibly want to favour the dirtier blocks more when the
	   number of free blocks is low. */
again:
	if (!list_empty(&c->bad_used_list) && c->nr_free_blocks > c->resv_blocks_gcbad) {
		jffs2_dbg(1, "Picking block from bad_used_list to GC next\n");
		nextlist = &c->bad_used_list;
	} else if (n < 50 && !list_empty(&c->erasable_list)) {
		/* Note that most of them will have gone directly to be erased.
		   So don't favour the erasable_list _too_ much. */
		jffs2_dbg(1, "Picking block from erasable_list to GC next\n");
		nextlist = &c->erasable_list;
	} else if (n < 110 && !list_empty(&c->very_dirty_list)) {
		/* Most of the time, pick one off the very_dirty list */
		jffs2_dbg(1, "Picking block from very_dirty_list to GC next\n");
		nextlist = &c->very_dirty_list;
	} else if (n < 126 && !list_empty(&c->dirty_list)) {
		jffs2_dbg(1, "Picking block from dirty_list to GC next\n");
		nextlist = &c->dirty_list;
	} else if (!list_empty(&c->clean_list)) {
		jffs2_dbg(1, "Picking block from clean_list to GC next\n");
		nextlist = &c->clean_list;
	} else if (!list_empty(&c->dirty_list)) {
		jffs2_dbg(1, "Picking block from dirty_list to GC next (clean_list was empty)\n");

		nextlist = &c->dirty_list;
	} else if (!list_empty(&c->very_dirty_list)) {
		jffs2_dbg(1, "Picking block from very_dirty_list to GC next (clean_list and dirty_list were empty)\n");
		nextlist = &c->very_dirty_list;
	} else if (!list_empty(&c->erasable_list)) {
		jffs2_dbg(1, "Picking block from erasable_list to GC next (clean_list and {very_,}dirty_list were empty)\n");

		nextlist = &c->erasable_list;
	} else if (!list_empty(&c->erasable_pending_wbuf_list)) {
		/* There are blocks are wating for the wbuf sync */
		jffs2_dbg(1, "Synching wbuf in order to reuse erasable_pending_wbuf_list blocks\n");
		spin_unlock(&c->erase_completion_lock);
		jffs2_flush_wbuf_pad(c);
		spin_lock(&c->erase_completion_lock);
		goto again;
	} else {
		/* Eep. All were empty */
		jffs2_dbg(1, "No clean, dirty _or_ erasable blocks to GC from! Where are they all?\n");
		return NULL;
	}

	ret = list_entry(nextlist->next, struct jffs2_eraseblock, list);
	list_del(&ret->list);
	c->gcblock = ret;
	ret->gc_node = ret->first_node;
	if (!ret->gc_node) {
		pr_warn("Eep. ret->gc_node for block at 0x%08x is NULL\n",
			ret->offset);
		BUG();
	}

	/* Have we accidentally picked a clean block with wasted space ? */
	if (ret->wasted_size) {
		jffs2_dbg(1, "Converting wasted_size %08x to dirty_size\n",
			  ret->wasted_size);
		ret->dirty_size += ret->wasted_size;
		c->wasted_size -= ret->wasted_size;
		c->dirty_size += ret->wasted_size;
		ret->wasted_size = 0;
	}

	return ret;
}

/* jffs2_garbage_collect_pass
 * Make a single attempt to progress GC. Move one node, and possibly
 * start erasing one eraseblock.
 */
int jffs2_garbage_collect_pass(struct jffs2_sb_info *c)
{
	struct jffs2_inode_info *f;
	struct jffs2_inode_cache *ic;
	struct jffs2_eraseblock *jeb;
	struct jffs2_raw_node_ref *raw;
	uint32_t gcblock_dirty;
	int ret = 0, inum, nlink;
	int xattr = 0;

	if (mutex_lock_interruptible(&c->alloc_sem))
		return -EINTR;

	for (;;) {
		spin_lock(&c->erase_completion_lock);
		if (!c->unchecked_size)
			break;

		/* We can't start doing GC yet. We haven't finished checking
		   the node CRCs etc. Do it now. */

		/* checked_ino is protected by the alloc_sem */
		if (c->checked_ino > c->highest_ino && xattr) {
			pr_crit("Checked all inodes but still 0x%x bytes of unchecked space?\n",
				c->unchecked_size);
			jffs2_dbg_dump_block_lists_nolock(c);
			spin_unlock(&c->erase_completion_lock);
			mutex_unlock(&c->alloc_sem);
			return -ENOSPC;
		}

		spin_unlock(&c->erase_completion_lock);

		if (!xattr)
			xattr = jffs2_verify_xattr(c);

		spin_lock(&c->inocache_lock);

		ic = jffs2_get_ino_cache(c, c->checked_ino++);

		if (!ic) {
			spin_unlock(&c->inocache_lock);
			continue;
		}

		if (!ic->pino_nlink) {
			jffs2_dbg(1, "Skipping check of ino #%d with nlink/pino zero\n",
				  ic->ino);
			spin_unlock(&c->inocache_lock);
			jffs2_xattr_delete_inode(c, ic);
			continue;
		}
		switch(ic->state) {
		case INO_STATE_CHECKEDABSENT:
		case INO_STATE_PRESENT:
			jffs2_dbg(1, "Skipping ino #%u already checked\n",
				  ic->ino);
			spin_unlock(&c->inocache_lock);
			continue;

		case INO_STATE_GC:
		case INO_STATE_CHECKING:
			pr_warn("Inode #%u is in state %d during CRC check phase!\n",
				ic->ino, ic->state);
			spin_unlock(&c->inocache_lock);
			BUG();

		case INO_STATE_READING:
			/* We need to wait for it to finish, lest we move on
			   and trigger the BUG() above while we haven't yet
			   finished checking all its nodes */
			jffs2_dbg(1, "Waiting for ino #%u to finish reading\n",
				  ic->ino);
			/* We need to come back again for the _same_ inode. We've
			 made no progress in this case, but that should be OK */
			c->checked_ino--;

			mutex_unlock(&c->alloc_sem);
			sleep_on_spinunlock(&c->inocache_wq, &c->inocache_lock);
			return 0;

		default:
			BUG();

		case INO_STATE_UNCHECKED:
			;
		}
		ic->state = INO_STATE_CHECKING;
		spin_unlock(&c->inocache_lock);

		jffs2_dbg(1, "%s(): triggering inode scan of ino#%u\n",
			  __func__, ic->ino);

		ret = jffs2_do_crccheck_inode(c, ic);
		if (ret)
			pr_warn("Returned error for crccheck of ino #%u. Expect badness...\n",
				ic->ino);

		jffs2_set_inocache_state(c, ic, INO_STATE_CHECKEDABSENT);
		mutex_unlock(&c->alloc_sem);
		return ret;
	}

	/* If there are any blocks which need erasing, erase them now */
	if (!list_empty(&c->erase_complete_list) ||
	    !list_empty(&c->erase_pending_list)) {
		spin_unlock(&c->erase_completion_lock);
		mutex_unlock(&c->alloc_sem);
		jffs2_dbg(1, "%s(): erasing pending blocks\n", __func__);
		if (jffs2_erase_pending_blocks(c, 1))
			return 0;

		jffs2_dbg(1, "No progress from erasing block; doing GC anyway\n");
		mutex_lock(&c->alloc_sem);
		spin_lock(&c->erase_completion_lock);
	}

	/* First, work out which block we're garbage-collecting */
	jeb = c->gcblock;

	if (!jeb)
		jeb = jffs2_find_gc_block(c);

	if (!jeb) {
		/* Couldn't find a free block. But maybe we can just erase one and make 'progress'? */
		if (c->nr_erasing_blocks) {
			spin_unlock(&c->erase_completion_lock);
			mutex_unlock(&c->alloc_sem);
			return -EAGAIN;
		}
		jffs2_dbg(1, "Couldn't find erase block to garbage collect!\n");
		spin_unlock(&c->erase_completion_lock);
		mutex_unlock(&c->alloc_sem);
		return -EIO;
	}

	jffs2_dbg(1, "GC from block %08x, used_size %08x, dirty_size %08x, free_size %08x\n",
		  jeb->offset, jeb->used_size, jeb->dirty_size, jeb->free_size);
	D1(if (c->nextblock)
	   printk(KERN_DEBUG "Nextblock at  %08x, used_size %08x, dirty_size %08x, wasted_size %08x, free_size %08x\n", c->nextblock->offset, c->nextblock->used_size, c->nextblock->dirty_size, c->nextblock->wasted_size, c->nextblock->free_size));

	if (!jeb->used_size) {
		mutex_unlock(&c->alloc_sem);
		goto eraseit;
	}

	raw = jeb->gc_node;
	gcblock_dirty = jeb->dirty_size;

	while(ref_obsolete(raw)) {
		jffs2_dbg(1, "Node at 0x%08x is obsolete... skipping\n",
			  ref_offset(raw));
		raw = ref_next(raw);
		if (unlikely(!raw)) {
			pr_warn("eep. End of raw list while still supposedly nodes to GC\n");
			pr_warn("erase block at 0x%08x. free_size 0x%08x, dirty_size 0x%08x, used_size 0x%08x\n",
				jeb->offset, jeb->free_size,
				jeb->dirty_size, jeb->used_size);
			jeb->gc_node = raw;
			spin_unlock(&c->erase_completion_lock);
			mutex_unlock(&c->alloc_sem);
			BUG();
		}
	}
	jeb->gc_node = raw;

	jffs2_dbg(1, "Going to garbage collect node at 0x%08x\n",
		  ref_offset(raw));

	if (!raw->next_in_ino) {
		/* Inode-less node. Clean marker, snapshot or something like that */
		spin_unlock(&c->erase_completion_lock);
		if (ref_flags(raw) == REF_PRISTINE) {
			/* It's an unknown node with JFFS2_FEATURE_RWCOMPAT_COPY */
			jffs2_garbage_collect_pristine(c, NULL, raw);
		} else {
			/* Just mark it obsolete */
			jffs2_mark_node_obsolete(c, raw);
		}
		mutex_unlock(&c->alloc_sem);
		goto eraseit_lock;
	}

	ic = jffs2_raw_ref_to_ic(raw);

#ifdef CONFIG_JFFS2_FS_XATTR
	/* When 'ic' refers xattr_datum/xattr_ref, this node is GCed as xattr.
	 * We can decide whether this node is inode or xattr by ic->class.     */
	if (ic->class == RAWNODE_CLASS_XATTR_DATUM
	    || ic->class == RAWNODE_CLASS_XATTR_REF) {
		spin_unlock(&c->erase_completion_lock);

		if (ic->class == RAWNODE_CLASS_XATTR_DATUM) {
			ret = jffs2_garbage_collect_xattr_datum(c, (struct jffs2_xattr_datum *)ic, raw);
		} else {
			ret = jffs2_garbage_collect_xattr_ref(c, (struct jffs2_xattr_ref *)ic, raw);
		}
		goto test_gcnode;
	}
#endif

	/* We need to hold the inocache. Either the erase_completion_lock or
	   the inocache_lock are sufficient; we trade down since the inocache_lock
	   causes less contention. */
	spin_lock(&c->inocache_lock);

	spin_unlock(&c->erase_completion_lock);

	jffs2_dbg(1, "%s(): collecting from block @0x%08x. Node @0x%08x(%d), ino #%u\n",
		  __func__, jeb->offset, ref_offset(raw), ref_flags(raw),
		  ic->ino);

	/* Three possibilities:
	   1. Inode is already in-core. We must iget it and do proper
	      updating to its fragtree, etc.
	   2. Inode is not in-core, node is REF_PRISTINE. We lock the
	      inocache to prevent a read_inode(), copy the node intact.
	   3. Inode is not in-core, node is not pristine. We must iget()
	      and take the slow path.
	*/

	switch(ic->state) {
	case INO_STATE_CHECKEDABSENT:
		/* It's been checked, but it's not currently in-core.
		   We can just copy any pristine nodes, but have
		   to prevent anyone else from doing read_inode() while
		   we're at it, so we set the state accordingly */
		if (ref_flags(raw) == REF_PRISTINE)
			ic->state = INO_STATE_GC;
		else {
			jffs2_dbg(1, "Ino #%u is absent but node not REF_PRISTINE. Reading.\n",
				  ic->ino);
		}
		break;

	case INO_STATE_PRESENT:
		/* It's in-core. GC must iget() it. */
		break;

	case INO_STATE_UNCHECKED:
	case INO_STATE_CHECKING:
	case INO_STATE_GC:
		/* Should never happen. We should have finished checking
		   by the time we actually start doing any GC, and since
		   we're holding the alloc_sem, no other garbage collection
		   can happen.
		*/
		pr_crit("Inode #%u already in state %d in jffs2_garbage_collect_pass()!\n",
			ic->ino, ic->state);
		mutex_unlock(&c->alloc_sem);
		spin_unlock(&c->inocache_lock);
		BUG();

	case INO_STATE_READING:
		/* Someone's currently trying to read it. We must wait for
		   them to finish and then go through the full iget() route
		   to do the GC. However, sometimes read_inode() needs to get
		   the alloc_sem() (for marking nodes invalid) so we must
		   drop the alloc_sem before sleeping. */

		mutex_unlock(&c->alloc_sem);
		jffs2_dbg(1, "%s(): waiting for ino #%u in state %d\n",
			  __func__, ic->ino, ic->state);
		sleep_on_spinunlock(&c->inocache_wq, &c->inocache_lock);
		/* And because we dropped the alloc_sem we must start again from the
		   beginning. Ponder chance of livelock here -- we're returning success
		   without actually making any progress.

		   Q: What are the chances that the inode is back in INO_STATE_READING
		   again by the time we next enter this function? And that this happens
		   enough times to cause a real delay?

		   A: Small enough that I don't care :)
		*/
		return 0;
	}

	/* OK. Now if the inode is in state INO_STATE_GC, we are going to copy the
	   node intact, and we don't have to muck about with the fragtree etc.
	   because we know it's not in-core. If it _was_ in-core, we go through
	   all the iget() crap anyway */

	if (ic->state == INO_STATE_GC) {
		spin_unlock(&c->inocache_lock);

		ret = jffs2_garbage_collect_pristine(c, ic, raw);

		spin_lock(&c->inocache_lock);
		ic->state = INO_STATE_CHECKEDABSENT;
		wake_up(&c->inocache_wq);

		if (ret != -EBADFD) {
			spin_unlock(&c->inocache_lock);
			goto test_gcnode;
		}

		/* Fall through if it wanted us to, with inocache_lock held */
	}

	/* Prevent the fairly unlikely race where the gcblock is
	   entirely obsoleted by the final close of a file which had
	   the only valid nodes in the block, followed by erasure,
	   followed by freeing of the ic because the erased block(s)
	   held _all_ the nodes of that inode.... never been seen but
	   it's vaguely possible. */

	inum = ic->ino;
	nlink = ic->pino_nlink;
	spin_unlock(&c->inocache_lock);

	f = jffs2_gc_fetch_inode(c, inum, !nlink);
	if (IS_ERR(f)) {
		ret = PTR_ERR(f);
		goto release_sem;
	}
	if (!f) {
		ret = 0;
		goto release_sem;
	}

	ret = jffs2_garbage_collect_live(c, jeb, raw, f);

	jffs2_gc_release_inode(c, f);

 test_gcnode:
	if (jeb->dirty_size == gcblock_dirty && !ref_obsolete(jeb->gc_node)) {
		/* Eep. This really should never happen. GC is broken */
		pr_err("Error garbage collecting node at %08x!\n",
		       ref_offset(jeb->gc_node));
		ret = -ENOSPC;
	}
 release_sem:
	mutex_unlock(&c->alloc_sem);

 eraseit_lock:
	/* If we've finished this block, start it erasing */
	spin_lock(&c->erase_completion_lock);

 eraseit:
	if (c->gcblock && !c->gcblock->used_size) {
		jffs2_dbg(1, "Block at 0x%08x completely obsoleted by GC. Moving to erase_pending_list\n",
			  c->gcblock->offset);
		/* We're GC'ing an empty block? */
		list_add_tail(&c->gcblock->list, &c->erase_pending_list);
		c->gcblock = NULL;
		c->nr_erasing_blocks++;
		jffs2_garbage_collect_trigger(c);
	}
	spin_unlock(&c->erase_completion_lock);

	return ret;
}

static int jffs2_garbage_collect_live(struct jffs2_sb_info *c,  struct jffs2_eraseblock *jeb,
				      struct jffs2_raw_node_ref *raw, struct jffs2_inode_info *f)
{
	struct jffs2_node_frag *frag;
	struct jffs2_full_dnode *fn = NULL;
	struct jffs2_full_dirent *fd;
	uint32_t start = 0, end = 0, nrfrags = 0;
	int ret = 0;

	mutex_lock(&f->sem);

	/* Now we have the lock for this inode. Check that it's still the one at the head
	   of the list. */

	spin_lock(&c->erase_completion_lock);

	if (c->gcblock != jeb) {
		spin_unlock(&c->erase_completion_lock);
		jffs2_dbg(1, "GC block is no longer gcblock. Restart\n");
		goto upnout;
	}
	if (ref_obsolete(raw)) {
		spin_unlock(&c->erase_completion_lock);
		jffs2_dbg(1, "node to be GC'd was obsoleted in the meantime.\n");
		/* They'll call again */
		goto upnout;
	}
	spin_unlock(&c->erase_completion_lock);

	/* OK. Looks safe. And nobody can get us now because we have the semaphore. Move the block */
	if (f->metadata && f->metadata->raw == raw) {
		fn = f->metadata;
		ret = jffs2_garbage_collect_metadata(c, jeb, f, fn);
		goto upnout;
	}

	/* FIXME. Read node and do lookup? */
	for (frag = frag_first(&f->fragtree); frag; frag = frag_next(frag)) {
		if (frag->node && frag->node->raw == raw) {
			fn = frag->node;
			end = frag->ofs + frag->size;
			if (!nrfrags++)
				start = frag->ofs;
			if (nrfrags == frag->node->frags)
				break; /* We've found them all */
		}
	}
	if (fn) {
		if (ref_flags(raw) == REF_PRISTINE) {
			ret = jffs2_garbage_collect_pristine(c, f->inocache, raw);
			if (!ret) {
				/* Urgh. Return it sensibly. */
				frag->node->raw = f->inocache->nodes;
			}
			if (ret != -EBADFD)
				goto upnout;
		}
		/* We found a datanode. Do the GC */
		if((start >> PAGE_CACHE_SHIFT) < ((end-1) >> PAGE_CACHE_SHIFT)) {
			/* It crosses a page boundary. Therefore, it must be a hole. */
			ret = jffs2_garbage_collect_hole(c, jeb, f, fn, start, end);
		} else {
			/* It could still be a hole. But we GC the page this way anyway */
			ret = jffs2_garbage_collect_dnode(c, jeb, f, fn, start, end);
		}
		goto upnout;
	}

	/* Wasn't a dnode. Try dirent */
	for (fd = f->dents; fd; fd=fd->next) {
		if (fd->raw == raw)
			break;
	}

	if (fd && fd->ino) {
		ret = jffs2_garbage_collect_dirent(c, jeb, f, fd);
	} else if (fd) {
		ret = jffs2_garbage_collect_deletion_dirent(c, jeb, f, fd);
	} else {
		pr_warn("Raw node at 0x%08x wasn't in node lists for ino #%u\n",
			ref_offset(raw), f->inocache->ino);
		if (ref_obsolete(raw)) {
			pr_warn("But it's obsolete so we don't mind too much\n");
		} else {
			jffs2_dbg_dump_node(c, ref_offset(raw));
			BUG();
		}
	}
 upnout:
	mutex_unlock(&f->sem);

	return ret;
}

static int jffs2_garbage_collect_pristine(struct jffs2_sb_info *c,
					  struct jffs2_inode_cache *ic,
					  struct jffs2_raw_node_ref *raw)
{
	union jffs2_node_union *node;
	size_t retlen;
	int ret;
	uint32_t phys_ofs, alloclen;
	uint32_t crc, rawlen;
	int retried = 0;

	jffs2_dbg(1, "Going to GC REF_PRISTINE node at 0x%08x\n",
		  ref_offset(raw));

	alloclen = rawlen = ref_totlen(c, c->gcblock, raw);

	/* Ask for a small amount of space (or the totlen if smaller) because we
	   don't want to force wastage of the end of a block if splitting would
	   work. */
	if (ic && alloclen > sizeof(struct jffs2_raw_inode) + JFFS2_MIN_DATA_LEN)
		alloclen = sizeof(struct jffs2_raw_inode) + JFFS2_MIN_DATA_LEN;

	ret = jffs2_reserve_space_gc(c, alloclen, &alloclen, rawlen);
	/* 'rawlen' is not the exact summary size; it is only an upper estimation */

	if (ret)
		return ret;

	if (alloclen < rawlen) {
		/* Doesn't fit untouched. We'll go the old route and split it */
		return -EBADFD;
	}

	node = kmalloc(rawlen, GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	ret = jffs2_flash_read(c, ref_offset(raw), rawlen, &retlen, (char *)node);
	if (!ret && retlen != rawlen)
		ret = -EIO;
	if (ret)
		goto out_node;

	crc = crc32(0, node, sizeof(struct jffs2_unknown_node)-4);
	if (je32_to_cpu(node->u.hdr_crc) != crc) {
		pr_warn("Header CRC failed on REF_PRISTINE node at 0x%08x: Read 0x%08x, calculated 0x%08x\n",
			ref_offset(raw), je32_to_cpu(node->u.hdr_crc), crc);
		goto bail;
	}

	switch(je16_to_cpu(node->u.nodetype)) {
	case JFFS2_NODETYPE_INODE:
		crc = crc32(0, node, sizeof(node->i)-8);
		if (je32_to_cpu(node->i.node_crc) != crc) {
			pr_warn("Node CRC failed on REF_PRISTINE data node at 0x%08x: Read 0x%08x, calculated 0x%08x\n",
				ref_offset(raw), je32_to_cpu(node->i.node_crc),
				crc);
			goto bail;
		}

		if (je32_to_cpu(node->i.dsize)) {
			crc = crc32(0, node->i.data, je32_to_cpu(node->i.csize));
			if (je32_to_cpu(node->i.data_crc) != crc) {
				pr_warn("Data CRC failed on REF_PRISTINE data node at 0x%08x: Read 0x%08x, calculated 0x%08x\n",
					ref_offset(raw),
					je32_to_cpu(node->i.data_crc), crc);
				goto bail;
			}
		}
		break;

	case JFFS2_NODETYPE_DIRENT:
		crc = crc32(0, node, sizeof(node->d)-8);
		if (je32_to_cpu(node->d.node_crc) != crc) {
			pr_warn("Node CRC failed on REF_PRISTINE dirent node at 0x%08x: Read 0x%08x, calculated 0x%08x\n",
				ref_offset(raw),
				je32_to_cpu(node->d.node_crc), crc);
			goto bail;
		}

		if (strnlen(node->d.name, node->d.nsize) != node->d.nsize) {
			pr_warn("Name in dirent node at 0x%08x contains zeroes\n",
				ref_offset(raw));
			goto bail;
		}

		if (node->d.nsize) {
			crc = crc32(0, node->d.name, node->d.nsize);
			if (je32_to_cpu(node->d.name_crc) != crc) {
				pr_warn("Name CRC failed on REF_PRISTINE dirent node at 0x%08x: Read 0x%08x, calculated 0x%08x\n",
					ref_offset(raw),
					je32_to_cpu(node->d.name_crc), crc);
				goto bail;
			}
		}
		break;
	default:
		/* If it's inode-less, we don't _know_ what it is. Just copy it intact */
		if (ic) {
			pr_warn("Unknown node type for REF_PRISTINE node at 0x%08x: 0x%04x\n",
				ref_offset(raw), je16_to_cpu(node->u.nodetype));
			goto bail;
		}
	}

	/* OK, all the CRCs are good; this node can just be copied as-is. */
 retry:
	phys_ofs = write_ofs(c);

	ret = jffs2_flash_write(c, phys_ofs, rawlen, &retlen, (char *)node);

	if (ret || (retlen != rawlen)) {
		pr_notice("Write of %d bytes at 0x%08x failed. returned %d, retlen %zd\n",
			  rawlen, phys_ofs, ret, retlen);
		if (retlen) {
			jffs2_add_physical_node_ref(c, phys_ofs | REF_OBSOLETE, rawlen, NULL);
		} else {
			pr_notice("Not marking the space at 0x%08x as dirty because the flash driver returned retlen zero\n",
				  phys_ofs);
		}
		if (!retried) {
			/* Try to reallocate space and retry */
			uint32_t dummy;
			struct jffs2_eraseblock *jeb = &c->blocks[phys_ofs / c->sector_size];

			retried = 1;

			jffs2_dbg(1, "Retrying failed write of REF_PRISTINE node.\n");

			jffs2_dbg_acct_sanity_check(c,jeb);
			jffs2_dbg_acct_paranoia_check(c, jeb);

			ret = jffs2_reserve_space_gc(c, rawlen, &dummy, rawlen);
						/* this is not the exact summary size of it,
							it is only an upper estimation */

			if (!ret) {
				jffs2_dbg(1, "Allocated space at 0x%08x to retry failed write.\n",
					  phys_ofs);

				jffs2_dbg_acct_sanity_check(c,jeb);
				jffs2_dbg_acct_paranoia_check(c, jeb);

				goto retry;
			}
			jffs2_dbg(1, "Failed to allocate space to retry failed write: %d!\n",
				  ret);
		}

		if (!ret)
			ret = -EIO;
		goto out_node;
	}
	jffs2_add_physical_node_ref(c, phys_ofs | REF_PRISTINE, rawlen, ic);

	jffs2_mark_node_obsolete(c, raw);
	jffs2_dbg(1, "WHEEE! GC REF_PRISTINE node at 0x%08x succeeded\n",
		  ref_offset(raw));

 out_node:
	kfree(node);
	return ret;
 bail:
	ret = -EBADFD;
	goto out_node;
}

static int jffs2_garbage_collect_metadata(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
					struct jffs2_inode_info *f, struct jffs2_full_dnode *fn)
{
	struct jffs2_full_dnode *new_fn;
	struct jffs2_raw_inode ri;
	struct jffs2_node_frag *last_frag;
	union jffs2_device_node dev;
	char *mdata = NULL;
	int mdatalen = 0;
	uint32_t alloclen, ilen;
	int ret;

	if (S_ISBLK(JFFS2_F_I_MODE(f)) ||
	    S_ISCHR(JFFS2_F_I_MODE(f)) ) {
		/* For these, we don't actually need to read the old node */
		mdatalen = jffs2_encode_dev(&dev, JFFS2_F_I_RDEV(f));
		mdata = (char *)&dev;
		jffs2_dbg(1, "%s(): Writing %d bytes of kdev_t\n",
			  __func__, mdatalen);
	} else if (S_ISLNK(JFFS2_F_I_MODE(f))) {
		mdatalen = fn->size;
		mdata = kmalloc(fn->size, GFP_KERNEL);
		if (!mdata) {
			pr_warn("kmalloc of mdata failed in jffs2_garbage_collect_metadata()\n");
			return -ENOMEM;
		}
		ret = jffs2_read_dnode(c, f, fn, mdata, 0, mdatalen);
		if (ret) {
			pr_warn("read of old metadata failed in jffs2_garbage_collect_metadata(): %d\n",
				ret);
			kfree(mdata);
			return ret;
		}
		jffs2_dbg(1, "%s(): Writing %d bites of symlink target\n",
			  __func__, mdatalen);

	}

	ret = jffs2_reserve_space_gc(c, sizeof(ri) + mdatalen, &alloclen,
				JFFS2_SUMMARY_INODE_SIZE);
	if (ret) {
		pr_warn("jffs2_reserve_space_gc of %zd bytes for garbage_collect_metadata failed: %d\n",
			sizeof(ri) + mdatalen, ret);
		goto out;
	}

	last_frag = frag_last(&f->fragtree);
	if (last_frag)
		/* Fetch the inode length from the fragtree rather then
		 * from i_size since i_size may have not been updated yet */
		ilen = last_frag->ofs + last_frag->size;
	else
		ilen = JFFS2_F_I_SIZE(f);

	memset(&ri, 0, sizeof(ri));
	ri.magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	ri.nodetype = cpu_to_je16(JFFS2_NODETYPE_INODE);
	ri.totlen = cpu_to_je32(sizeof(ri) + mdatalen);
	ri.hdr_crc = cpu_to_je32(crc32(0, &ri, sizeof(struct jffs2_unknown_node)-4));

	ri.ino = cpu_to_je32(f->inocache->ino);
	ri.version = cpu_to_je32(++f->highest_version);
	ri.mode = cpu_to_jemode(JFFS2_F_I_MODE(f));
	ri.uid = cpu_to_je16(JFFS2_F_I_UID(f));
	ri.gid = cpu_to_je16(JFFS2_F_I_GID(f));
	ri.isize = cpu_to_je32(ilen);
	ri.atime = cpu_to_je32(JFFS2_F_I_ATIME(f));
	ri.ctime = cpu_to_je32(JFFS2_F_I_CTIME(f));
	ri.mtime = cpu_to_je32(JFFS2_F_I_MTIME(f));
	ri.offset = cpu_to_je32(0);
	ri.csize = cpu_to_je32(mdatalen);
	ri.dsize = cpu_to_je32(mdatalen);
	ri.compr = JFFS2_COMPR_NONE;
	ri.node_crc = cpu_to_je32(crc32(0, &ri, sizeof(ri)-8));
	ri.data_crc = cpu_to_je32(crc32(0, mdata, mdatalen));

	new_fn = jffs2_write_dnode(c, f, &ri, mdata, mdatalen, ALLOC_GC);

	if (IS_ERR(new_fn)) {
		pr_warn("Error writing new dnode: %ld\n", PTR_ERR(new_fn));
		ret = PTR_ERR(new_fn);
		goto out;
	}
	jffs2_mark_node_obsolete(c, fn->raw);
	jffs2_free_full_dnode(fn);
	f->metadata = new_fn;
 out:
	if (S_ISLNK(JFFS2_F_I_MODE(f)))
		kfree(mdata);
	return ret;
}

static int jffs2_garbage_collect_dirent(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
					struct jffs2_inode_info *f, struct jffs2_full_dirent *fd)
{
	struct jffs2_full_dirent *new_fd;
	struct jffs2_raw_dirent rd;
	uint32_t alloclen;
	int ret;

	rd.magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	rd.nodetype = cpu_to_je16(JFFS2_NODETYPE_DIRENT);
	rd.nsize = strlen(fd->name);
	rd.totlen = cpu_to_je32(sizeof(rd) + rd.nsize);
	rd.hdr_crc = cpu_to_je32(crc32(0, &rd, sizeof(struct jffs2_unknown_node)-4));

	rd.pino = cpu_to_je32(f->inocache->ino);
	rd.version = cpu_to_je32(++f->highest_version);
	rd.ino = cpu_to_je32(fd->ino);
	/* If the times on this inode were set by explicit utime() they can be different,
	   so refrain from splatting them. */
	if (JFFS2_F_I_MTIME(f) == JFFS2_F_I_CTIME(f))
		rd.mctime = cpu_to_je32(JFFS2_F_I_MTIME(f));
	else
		rd.mctime = cpu_to_je32(0);
	rd.type = fd->type;
	rd.node_crc = cpu_to_je32(crc32(0, &rd, sizeof(rd)-8));
	rd.name_crc = cpu_to_je32(crc32(0, fd->name, rd.nsize));

	ret = jffs2_reserve_space_gc(c, sizeof(rd)+rd.nsize, &alloclen,
				JFFS2_SUMMARY_DIRENT_SIZE(rd.nsize));
	if (ret) {
		pr_warn("jffs2_reserve_space_gc of %zd bytes for garbage_collect_dirent failed: %d\n",
			sizeof(rd)+rd.nsize, ret);
		return ret;
	}
	new_fd = jffs2_write_dirent(c, f, &rd, fd->name, rd.nsize, ALLOC_GC);

	if (IS_ERR(new_fd)) {
		pr_warn("jffs2_write_dirent in garbage_collect_dirent failed: %ld\n",
			PTR_ERR(new_fd));
		return PTR_ERR(new_fd);
	}
	jffs2_add_fd_to_list(c, new_fd, &f->dents);
	return 0;
}

static int jffs2_garbage_collect_deletion_dirent(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
					struct jffs2_inode_info *f, struct jffs2_full_dirent *fd)
{
	struct jffs2_full_dirent **fdp = &f->dents;
	int found = 0;

	/* On a medium where we can't actually mark nodes obsolete
	   pernamently, such as NAND flash, we need to work out
	   whether this deletion dirent is still needed to actively
	   delete a 'real' dirent with the same name that's still
	   somewhere else on the flash. */
	if (!jffs2_can_mark_obsolete(c)) {
		struct jffs2_raw_dirent *rd;
		struct jffs2_raw_node_ref *raw;
		int ret;
		size_t retlen;
		int name_len = strlen(fd->name);
		uint32_t name_crc = crc32(0, fd->name, name_len);
		uint32_t rawlen = ref_totlen(c, jeb, fd->raw);

		rd = kmalloc(rawlen, GFP_KERNEL);
		if (!rd)
			return -ENOMEM;

		/* Prevent the erase code from nicking the obsolete node refs while
		   we're looking at them. I really don't like this extra lock but
		   can't see any alternative. Suggestions on a postcard to... */
		mutex_lock(&c->erase_free_sem);

		for (raw = f->inocache->nodes; raw != (void *)f->inocache; raw = raw->next_in_ino) {

			cond_resched();

			/* We only care about obsolete ones */
			if (!(ref_obsolete(raw)))
				continue;

			/* Any dirent with the same name is going to have the same length... */
			if (ref_totlen(c, NULL, raw) != rawlen)
				continue;

			/* Doesn't matter if there's one in the same erase block. We're going to
			   delete it too at the same time. */
			if (SECTOR_ADDR(raw->flash_offset) == SECTOR_ADDR(fd->raw->flash_offset))
				continue;

			jffs2_dbg(1, "Check potential deletion dirent at %08x\n",
				  ref_offset(raw));

			/* This is an obsolete node belonging to the same directory, and it's of the right
			   length. We need to take a closer look...*/
			ret = jffs2_flash_read(c, ref_offset(raw), rawlen, &retlen, (char *)rd);
			if (ret) {
				pr_warn("%s(): Read error (%d) reading obsolete node at %08x\n",
					__func__, ret, ref_offset(raw));
				/* If we can't read it, we don't need to continue to obsolete it. Continue */
				continue;
			}
			if (retlen != rawlen) {
				pr_warn("%s(): Short read (%zd not %u) reading header from obsolete node at %08x\n",
					__func__, retlen, rawlen,
					ref_offset(raw));
				continue;
			}

			if (je16_to_cpu(rd->nodetype) != JFFS2_NODETYPE_DIRENT)
				continue;

			/* If the name CRC doesn't match, skip */
			if (je32_to_cpu(rd->name_crc) != name_crc)
				continue;

			/* If the name length doesn't match, or it's another deletion dirent, skip */
			if (rd->nsize != name_len || !je32_to_cpu(rd->ino))
				continue;

			/* OK, check the actual name now */
			if (memcmp(rd->name, fd->name, name_len))
				continue;

			/* OK. The name really does match. There really is still an older node on
			   the flash which our deletion dirent obsoletes. So we have to write out
			   a new deletion dirent to replace it */
			mutex_unlock(&c->erase_free_sem);

			jffs2_dbg(1, "Deletion dirent at %08x still obsoletes real dirent \"%s\" at %08x for ino #%u\n",
				  ref_offset(fd->raw), fd->name,
				  ref_offset(raw), je32_to_cpu(rd->ino));
			kfree(rd);

			return jffs2_garbage_collect_dirent(c, jeb, f, fd);
		}

		mutex_unlock(&c->erase_free_sem);
		kfree(rd);
	}

	/* FIXME: If we're deleting a dirent which contains the current mtime and ctime,
	   we should update the metadata node with those times accordingly */

	/* No need for it any more. Just mark it obsolete and remove it from the list */
	while (*fdp) {
		if ((*fdp) == fd) {
			found = 1;
			*fdp = fd->next;
			break;
		}
		fdp = &(*fdp)->next;
	}
	if (!found) {
		pr_warn("Deletion dirent \"%s\" not found in list for ino #%u\n",
			fd->name, f->inocache->ino);
	}
	jffs2_mark_node_obsolete(c, fd->raw);
	jffs2_free_full_dirent(fd);
	return 0;
}

static int jffs2_garbage_collect_hole(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb,
				      struct jffs2_inode_info *f, struct jffs2_full_dnode *fn,
				      uint32_t start, uint32_t end)
{
	struct jffs2_raw_inode ri;
	struct jffs2_node_frag *frag;
	struct jffs2_full_dnode *new_fn;
	uint32_t alloclen, ilen;
	int ret;

	jffs2_dbg(1, "Writing replacement hole node for ino #%u from offset 0x%x to 0x%x\n",
		  f->inocache->ino, start, end);

	memset(&ri, 0, sizeof(ri));

	if(fn->frags > 1) {
		size_t readlen;
		uint32_t crc;
		/* It's partially obsoleted by a later write. So we have to
		   write it out again with the _same_ version as before */
		ret = jffs2_flash_read(c, ref_offset(fn->raw), sizeof(ri), &readlen, (char *)&ri);
		if (readlen != sizeof(ri) || ret) {
			pr_warn("Node read failed in jffs2_garbage_collect_hole. Ret %d, retlen %zd. Data will be lost by writing new hole node\n",
				ret, readlen);
			goto fill;
		}
		if (je16_to_cpu(ri.nodetype) != JFFS2_NODETYPE_INODE) {
			pr_warn("%s(): Node at 0x%08x had node type 0x%04x instead of JFFS2_NODETYPE_INODE(0x%04x)\n",
				__func__, ref_offset(fn->raw),
				je16_to_cpu(ri.nodetype), JFFS2_NODETYPE_INODE);
			return -EIO;
		}
		if (je32_to_cpu(ri.totlen) != sizeof(ri)) {
			pr_warn("%s(): Node at 0x%08x had totlen 0x%x instead of expected 0x%zx\n",
				__func__, ref_offset(fn->raw),
				je32_to_cpu(ri.totlen), sizeof(ri));
			return -EIO;
		}
		crc = crc32(0, &ri, sizeof(ri)-8);
		if (crc != je32_to_cpu(ri.node_crc)) {
			pr_warn("%s: Node at 0x%08x had CRC 0x%08x which doesn't match calculated CRC 0x%08x\n",
				__func__, ref_offset(fn->raw),
				je32_to_cpu(ri.node_crc), crc);
			/* FIXME: We could possibly deal with this by writing new holes for each frag */
			pr_warn("Data in the range 0x%08x to 0x%08x of inode #%u will be lost\n",
				start, end, f->inocache->ino);
			goto fill;
		}
		if (ri.compr != JFFS2_COMPR_ZERO) {
			pr_warn("%s(): Node 0x%08x wasn't a hole node!\n",
				__func__, ref_offset(fn->raw));
			pr_warn("Data in the range 0x%08x to 0x%08x of inode #%u will be lost\n",
				start, end, f->inocache->ino);
			goto fill;
		}
	} else {
	fill:
		ri.magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
		ri.nodetype = cpu_to_je16(JFFS2_NODETYPE_INODE);
		ri.totlen = cpu_to_je32(sizeof(ri));
		ri.hdr_crc = cpu_to_je32(crc32(0, &ri, sizeof(struct jffs2_unknown_node)-4));

		ri.ino = cpu_to_je32(f->inocache->ino);
		ri.version = cpu_to_je32(++f->highest_version);
		ri.offset = cpu_to_je32(start);
		ri.dsize = cpu_to_je32(end - start);
		ri.csize = cpu_to_je32(0);
		ri.compr = JFFS2_COMPR_ZERO;
	}

	frag = frag_last(&f->fragtree);
	if (frag)
		/* Fetch the inode length from the fragtree rather then
		 * from i_size since i_size may have not been updated yet */
		ilen = frag->ofs + frag->size;
	else
		ilen = JFFS2_F_I_SIZE(f);

	ri.mode = cpu_to_jemode(JFFS2_F_I_MODE(f));
	ri.uid = cpu_to_je16(JFFS2_F_I_UID(f));
	ri.gid = cpu_to_je16(JFFS2_F_I_GID(f));
	ri.isize = cpu_to_je32(ilen);
	ri.atime = cpu_to_je32(JFFS2_F_I_ATIME(f));
	ri.ctime = cpu_to_je32(JFFS2_F_I_CTIME(f));
	ri.mtime = cpu_to_je32(JFFS2_F_I_MTIME(f));
	ri.data_crc = cpu_to_je32(0);
	ri.node_crc = cpu_to_je32(crc32(0, &ri, sizeof(ri)-8));

	ret = jffs2_reserve_space_gc(c, sizeof(ri), &alloclen,
				     JFFS2_SUMMARY_INODE_SIZE);
	if (ret) {
		pr_warn("jffs2_reserve_space_gc of %zd bytes for garbage_collect_hole failed: %d\n",
			sizeof(ri), ret);
		return ret;
	}
	new_fn = jffs2_write_dnode(c, f, &ri, NULL, 0, ALLOC_GC);

	if (IS_ERR(new_fn)) {
		pr_warn("Error writing new hole node: %ld\n", PTR_ERR(new_fn));
		return PTR_ERR(new_fn);
	}
	if (je32_to_cpu(ri.version) == f->highest_version) {
		jffs2_add_full_dnode_to_inode(c, f, new_fn);
		if (f->metadata) {
			jffs2_mark_node_obsolete(c, f->metadata->raw);
			jffs2_free_full_dnode(f->metadata);
			f->metadata = NULL;
		}
		return 0;
	}

	/*
	 * We should only get here in the case where the node we are
	 * replacing had more than one frag, so we kept the same version
	 * number as before. (Except in case of error -- see 'goto fill;'
	 * above.)
	 */
	D1(if(unlikely(fn->frags <= 1)) {
			pr_warn("%s(): Replacing fn with %d frag(s) but new ver %d != highest_version %d of ino #%d\n",
				__func__, fn->frags, je32_to_cpu(ri.version),
				f->highest_version, je32_to_cpu(ri.ino));
	});

	/* This is a partially-overlapped hole node. Mark it REF_NORMAL not REF_PRISTINE */
	mark_ref_normal(new_fn->raw);

	for (frag = jffs2_lookup_node_frag(&f->fragtree, fn->ofs);
	     frag; frag = frag_next(frag)) {
		if (frag->ofs > fn->size + fn->ofs)
			break;
		if (frag->node == fn) {
			frag->node = new_fn;
			new_fn->frags++;
			fn->frags--;
		}
	}
	if (fn->frags) {
		pr_warn("%s(): Old node still has frags!\n", __func__);
		BUG();
	}
	if (!new_fn->frags) {
		pr_warn("%s(): New node has no frags!\n", __func__);
		BUG();
	}

	jffs2_mark_node_obsolete(c, fn->raw);
	jffs2_free_full_dnode(fn);

	return 0;
}

static int jffs2_garbage_collect_dnode(struct jffs2_sb_info *c, struct jffs2_eraseblock *orig_jeb,
				       struct jffs2_inode_info *f, struct jffs2_full_dnode *fn,
				       uint32_t start, uint32_t end)
{
	struct jffs2_full_dnode *new_fn;
	struct jffs2_raw_inode ri;
	uint32_t alloclen, offset, orig_end, orig_start;
	int ret = 0;
	unsigned char *comprbuf = NULL, *writebuf;
	unsigned long pg;
	unsigned char *pg_ptr;

	memset(&ri, 0, sizeof(ri));

	jffs2_dbg(1, "Writing replacement dnode for ino #%u from offset 0x%x to 0x%x\n",
		  f->inocache->ino, start, end);

	orig_end = end;
	orig_start = start;

	if (c->nr_free_blocks + c->nr_erasing_blocks > c->resv_blocks_gcmerge) {
		/* Attempt to do some merging. But only expand to cover logically
		   adjacent frags if the block containing them is already considered
		   to be dirty. Otherwise we end up with GC just going round in
		   circles dirtying the nodes it already wrote out, especially
		   on NAND where we have small eraseblocks and hence a much higher
		   chance of nodes having to be split to cross boundaries. */

		struct jffs2_node_frag *frag;
		uint32_t min, max;

		min = start & ~(PAGE_CACHE_SIZE-1);
		max = min + PAGE_CACHE_SIZE;

		frag = jffs2_lookup_node_frag(&f->fragtree, start);

		/* BUG_ON(!frag) but that'll happen anyway... */

		BUG_ON(frag->ofs != start);

		/* First grow down... */
		while((frag = frag_prev(frag)) && frag->ofs >= min) {

			/* If the previous frag doesn't even reach the beginning, there's
			   excessive fragmentation. Just merge. */
			if (frag->ofs > min) {
				jffs2_dbg(1, "Expanding down to cover partial frag (0x%x-0x%x)\n",
					  frag->ofs, frag->ofs+frag->size);
				start = frag->ofs;
				continue;
			}
			/* OK. This frag holds the first byte of the page. */
			if (!frag->node || !frag->node->raw) {
				jffs2_dbg(1, "First frag in page is hole (0x%x-0x%x). Not expanding down.\n",
					  frag->ofs, frag->ofs+frag->size);
				break;
			} else {

				/* OK, it's a frag which extends to the beginning of the page. Does it live
				   in a block which is still considered clean? If so, don't obsolete it.
				   If not, cover it anyway. */

				struct jffs2_raw_node_ref *raw = frag->node->raw;
				struct jffs2_eraseblock *jeb;

				jeb = &c->blocks[raw->flash_offset / c->sector_size];

				if (jeb == c->gcblock) {
					jffs2_dbg(1, "Expanding down to cover frag (0x%x-0x%x) in gcblock at %08x\n",
						  frag->ofs,
						  frag->ofs + frag->size,
						  ref_offset(raw));
					start = frag->ofs;
					break;
				}
				if (!ISDIRTY(jeb->dirty_size + jeb->wasted_size)) {
					jffs2_dbg(1, "Not expanding down to cover frag (0x%x-0x%x) in clean block %08x\n",
						  frag->ofs,
						  frag->ofs + frag->size,
						  jeb->offset);
					break;
				}

				jffs2_dbg(1, "Expanding down to cover frag (0x%x-0x%x) in dirty block %08x\n",
					  frag->ofs,
					  frag->ofs + frag->size,
					  jeb->offset);
				start = frag->ofs;
				break;
			}
		}

		/* ... then up */

		/* Find last frag which is actually part of the node we're to GC. */
		frag = jffs2_lookup_node_frag(&f->fragtree, end-1);

		while((frag = frag_next(frag)) && frag->ofs+frag->size <= max) {

			/* If the previous frag doesn't even reach the beginning, there's lots
			   of fragmentation. Just merge. */
			if (frag->ofs+frag->size < max) {
				jffs2_dbg(1, "Expanding up to cover partial frag (0x%x-0x%x)\n",
					  frag->ofs, frag->ofs+frag->size);
				end = frag->ofs + frag->size;
				continue;
			}

			if (!frag->node || !frag->node->raw) {
				jffs2_dbg(1, "Last frag in page is hole (0x%x-0x%x). Not expanding up.\n",
					  frag->ofs, frag->ofs+frag->size);
				break;
			} else {

				/* OK, it's a frag which extends to the beginning of the page. Does it live
				   in a block which is still considered clean? If so, don't obsolete it.
				   If not, cover it anyway. */

				struct jffs2_raw_node_ref *raw = frag->node->raw;
				struct jffs2_eraseblock *jeb;

				jeb = &c->blocks[raw->flash_offset / c->sector_size];

				if (jeb == c->gcblock) {
					jffs2_dbg(1, "Expanding up to cover frag (0x%x-0x%x) in gcblock at %08x\n",
						  frag->ofs,
						  frag->ofs + frag->size,
						  ref_offset(raw));
					end = frag->ofs + frag->size;
					break;
				}
				if (!ISDIRTY(jeb->dirty_size + jeb->wasted_size)) {
					jffs2_dbg(1, "Not expanding up to cover frag (0x%x-0x%x) in clean block %08x\n",
						  frag->ofs,
						  frag->ofs + frag->size,
						  jeb->offset);
					break;
				}

				jffs2_dbg(1, "Expanding up to cover frag (0x%x-0x%x) in dirty block %08x\n",
					  frag->ofs,
					  frag->ofs + frag->size,
					  jeb->offset);
				end = frag->ofs + frag->size;
				break;
			}
		}
		jffs2_dbg(1, "Expanded dnode to write from (0x%x-0x%x) to (0x%x-0x%x)\n",
			  orig_start, orig_end, start, end);

		D1(BUG_ON(end > frag_last(&f->fragtree)->ofs + frag_last(&f->fragtree)->size));
		BUG_ON(end < orig_end);
		BUG_ON(start > orig_start);
	}

	/* First, use readpage() to read the appropriate page into the page cache */
	/* Q: What happens if we actually try to GC the _same_ page for which commit_write()
	 *    triggered garbage collection in the first place?
	 * A: I _think_ it's OK. read_cache_page shouldn't deadlock, we'll write out the
	 *    page OK. We'll actually write it out again in commit_write, which is a little
	 *    suboptimal, but at least we're correct.
	 */
	pg_ptr = jffs2_gc_fetch_page(c, f, start, &pg);

	if (IS_ERR(pg_ptr)) {
		pr_warn("read_cache_page() returned error: %ld\n",
			PTR_ERR(pg_ptr));
		return PTR_ERR(pg_ptr);
	}

	offset = start;
	while(offset < orig_end) {
		uint32_t datalen;
		uint32_t cdatalen;
		uint16_t comprtype = JFFS2_COMPR_NONE;

		ret = jffs2_reserve_space_gc(c, sizeof(ri) + JFFS2_MIN_DATA_LEN,
					&alloclen, JFFS2_SUMMARY_INODE_SIZE);

		if (ret) {
			pr_warn("jffs2_reserve_space_gc of %zd bytes for garbage_collect_dnode failed: %d\n",
				sizeof(ri) + JFFS2_MIN_DATA_LEN, ret);
			break;
		}
		cdatalen = min_t(uint32_t, alloclen - sizeof(ri), end - offset);
		datalen = end - offset;

		writebuf = pg_ptr + (offset & (PAGE_CACHE_SIZE -1));

		comprtype = jffs2_compress(c, f, writebuf, &comprbuf, &datalen, &cdatalen);

		ri.magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
		ri.nodetype = cpu_to_je16(JFFS2_NODETYPE_INODE);
		ri.totlen = cpu_to_je32(sizeof(ri) + cdatalen);
		ri.hdr_crc = cpu_to_je32(crc32(0, &ri, sizeof(struct jffs2_unknown_node)-4));

		ri.ino = cpu_to_je32(f->inocache->ino);
		ri.version = cpu_to_je32(++f->highest_version);
		ri.mode = cpu_to_jemode(JFFS2_F_I_MODE(f));
		ri.uid = cpu_to_je16(JFFS2_F_I_UID(f));
		ri.gid = cpu_to_je16(JFFS2_F_I_GID(f));
		ri.isize = cpu_to_je32(JFFS2_F_I_SIZE(f));
		ri.atime = cpu_to_je32(JFFS2_F_I_ATIME(f));
		ri.ctime = cpu_to_je32(JFFS2_F_I_CTIME(f));
		ri.mtime = cpu_to_je32(JFFS2_F_I_MTIME(f));
		ri.offset = cpu_to_je32(offset);
		ri.csize = cpu_to_je32(cdatalen);
		ri.dsize = cpu_to_je32(datalen);
		ri.compr = comprtype & 0xff;
		ri.usercompr = (comprtype >> 8) & 0xff;
		ri.node_crc = cpu_to_je32(crc32(0, &ri, sizeof(ri)-8));
		ri.data_crc = cpu_to_je32(crc32(0, comprbuf, cdatalen));

		new_fn = jffs2_write_dnode(c, f, &ri, comprbuf, cdatalen, ALLOC_GC);

		jffs2_free_comprbuf(comprbuf, writebuf);

		if (IS_ERR(new_fn)) {
			pr_warn("Error writing new dnode: %ld\n",
				PTR_ERR(new_fn));
			ret = PTR_ERR(new_fn);
			break;
		}
		ret = jffs2_add_full_dnode_to_inode(c, f, new_fn);
		offset += datalen;
		if (f->metadata) {
			jffs2_mark_node_obsolete(c, f->metadata->raw);
			jffs2_free_full_dnode(f->metadata);
			f->metadata = NULL;
		}
	}

	jffs2_gc_release_page(c, pg_ptr, &pg);
	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/gc.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/fs.h>
#include <linux/namei.h>
// #include "nodelist.h"

static void *jffs2_follow_link(struct dentry *dentry, struct nameidata *nd);

const struct inode_operations jffs2_symlink_inode_operations =
{
	.readlink =	generic_readlink,
	.follow_link =	jffs2_follow_link,
	.setattr =	jffs2_setattr,
	.setxattr =	jffs2_setxattr,
	.getxattr =	jffs2_getxattr,
	.listxattr =	jffs2_listxattr,
	.removexattr =	jffs2_removexattr
};

static void *jffs2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(dentry->d_inode);
	char *p = (char *)f->target;

	/*
	 * We don't acquire the f->sem mutex here since the only data we
	 * use is f->target.
	 *
	 * 1. If we are here the inode has already built and f->target has
	 * to point to the target path.
	 * 2. Nobody uses f->target (if the inode is symlink's inode). The
	 * exception is inode freeing function which frees f->target. But
	 * it can't be called while we are here and before VFS has
	 * stopped using our f->target string which we provide by means of
	 * nd_set_link() call.
	 */

	if (!p) {
		pr_err("%s(): can't find symlink target\n", __func__);
		p = ERR_PTR(-EIO);
	}
	jffs2_dbg(1, "%s(): target path is '%s'\n",
		  __func__, (char *)f->target);

	nd_set_link(nd, p);

	/*
	 * We will unlock the f->sem mutex but VFS will use the f->target string. This is safe
	 * since the only way that may cause f->target to be changed is iput() operation.
	 * But VFS will not use f->target after iput() has been called.
	 */
	return NULL;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/symlink.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/sched.h>
// #include <linux/slab.h>
#include <linux/vmalloc.h>
// #include <linux/mtd/mtd.h>
// #include "nodelist.h"

static void jffs2_build_remove_unlinked_inode(struct jffs2_sb_info *,
		struct jffs2_inode_cache *, struct jffs2_full_dirent **);

static inline struct jffs2_inode_cache *
first_inode_chain(int *i, struct jffs2_sb_info *c)
{
	for (; *i < c->inocache_hashsize; (*i)++) {
		if (c->inocache_list[*i])
			return c->inocache_list[*i];
	}
	return NULL;
}

static inline struct jffs2_inode_cache *
next_inode(int *i, struct jffs2_inode_cache *ic, struct jffs2_sb_info *c)
{
	/* More in this chain? */
	if (ic->next)
		return ic->next;
	(*i)++;
	return first_inode_chain(i, c);
}

#define for_each_inode(i, c, ic)			\
	for (i = 0, ic = first_inode_chain(&i, (c));	\
	     ic;					\
	     ic = next_inode(&i, ic, (c)))


static void jffs2_build_inode_pass1(struct jffs2_sb_info *c,
				    struct jffs2_inode_cache *ic)
{
	struct jffs2_full_dirent *fd;

	dbg_fsbuild("building directory inode #%u\n", ic->ino);

	/* For each child, increase nlink */
	for(fd = ic->scan_dents; fd; fd = fd->next) {
		struct jffs2_inode_cache *child_ic;
		if (!fd->ino)
			continue;

		/* we can get high latency here with huge directories */

		child_ic = jffs2_get_ino_cache(c, fd->ino);
		if (!child_ic) {
			dbg_fsbuild("child \"%s\" (ino #%u) of dir ino #%u doesn't exist!\n",
				  fd->name, fd->ino, ic->ino);
			jffs2_mark_node_obsolete(c, fd->raw);
			continue;
		}

		if (fd->type == DT_DIR) {
			if (child_ic->pino_nlink) {
				JFFS2_ERROR("child dir \"%s\" (ino #%u) of dir ino #%u appears to be a hard link\n",
					    fd->name, fd->ino, ic->ino);
				/* TODO: What do we do about it? */
			} else {
				child_ic->pino_nlink = ic->ino;
			}
		} else
			child_ic->pino_nlink++;

		dbg_fsbuild("increased nlink for child \"%s\" (ino #%u)\n", fd->name, fd->ino);
		/* Can't free scan_dents so far. We might need them in pass 2 */
	}
}

/* Scan plan:
 - Scan physical nodes. Build map of inodes/dirents. Allocate inocaches as we go
 - Scan directory tree from top down, setting nlink in inocaches
 - Scan inocaches for inodes with nlink==0
*/
static int jffs2_build_filesystem(struct jffs2_sb_info *c)
{
	int ret;
	int i;
	struct jffs2_inode_cache *ic;
	struct jffs2_full_dirent *fd;
	struct jffs2_full_dirent *dead_fds = NULL;

	dbg_fsbuild("build FS data structures\n");

	/* First, scan the medium and build all the inode caches with
	   lists of physical nodes */

	c->flags |= JFFS2_SB_FLAG_SCANNING;
	ret = jffs2_scan_medium(c);
	c->flags &= ~JFFS2_SB_FLAG_SCANNING;
	if (ret)
		goto exit;

	dbg_fsbuild("scanned flash completely\n");
	jffs2_dbg_dump_block_lists_nolock(c);

	dbg_fsbuild("pass 1 starting\n");
	c->flags |= JFFS2_SB_FLAG_BUILDING;
	/* Now scan the directory tree, increasing nlink according to every dirent found. */
	for_each_inode(i, c, ic) {
		if (ic->scan_dents) {
			jffs2_build_inode_pass1(c, ic);
			cond_resched();
		}
	}

	dbg_fsbuild("pass 1 complete\n");

	/* Next, scan for inodes with nlink == 0 and remove them. If
	   they were directories, then decrement the nlink of their
	   children too, and repeat the scan. As that's going to be
	   a fairly uncommon occurrence, it's not so evil to do it this
	   way. Recursion bad. */
	dbg_fsbuild("pass 2 starting\n");

	for_each_inode(i, c, ic) {
		if (ic->pino_nlink)
			continue;

		jffs2_build_remove_unlinked_inode(c, ic, &dead_fds);
		cond_resched();
	}

	dbg_fsbuild("pass 2a starting\n");

	while (dead_fds) {
		fd = dead_fds;
		dead_fds = fd->next;

		ic = jffs2_get_ino_cache(c, fd->ino);

		if (ic)
			jffs2_build_remove_unlinked_inode(c, ic, &dead_fds);
		jffs2_free_full_dirent(fd);
	}

	dbg_fsbuild("pass 2a complete\n");
	dbg_fsbuild("freeing temporary data structures\n");

	/* Finally, we can scan again and free the dirent structs */
	for_each_inode(i, c, ic) {
		while(ic->scan_dents) {
			fd = ic->scan_dents;
			ic->scan_dents = fd->next;
			jffs2_free_full_dirent(fd);
		}
		ic->scan_dents = NULL;
		cond_resched();
	}
	jffs2_build_xattr_subsystem(c);
	c->flags &= ~JFFS2_SB_FLAG_BUILDING;

	dbg_fsbuild("FS build complete\n");

	/* Rotate the lists by some number to ensure wear levelling */
	jffs2_rotate_lists(c);

	ret = 0;

exit:
	if (ret) {
		for_each_inode(i, c, ic) {
			while(ic->scan_dents) {
				fd = ic->scan_dents;
				ic->scan_dents = fd->next;
				jffs2_free_full_dirent(fd);
			}
		}
		jffs2_clear_xattr_subsystem(c);
	}

	return ret;
}

static void jffs2_build_remove_unlinked_inode(struct jffs2_sb_info *c,
					struct jffs2_inode_cache *ic,
					struct jffs2_full_dirent **dead_fds)
{
	struct jffs2_raw_node_ref *raw;
	struct jffs2_full_dirent *fd;

	dbg_fsbuild("removing ino #%u with nlink == zero.\n", ic->ino);

	raw = ic->nodes;
	while (raw != (void *)ic) {
		struct jffs2_raw_node_ref *next = raw->next_in_ino;
		dbg_fsbuild("obsoleting node at 0x%08x\n", ref_offset(raw));
		jffs2_mark_node_obsolete(c, raw);
		raw = next;
	}

	if (ic->scan_dents) {
		int whinged = 0;
		dbg_fsbuild("inode #%u was a directory which may have children...\n", ic->ino);

		while(ic->scan_dents) {
			struct jffs2_inode_cache *child_ic;

			fd = ic->scan_dents;
			ic->scan_dents = fd->next;

			if (!fd->ino) {
				/* It's a deletion dirent. Ignore it */
				dbg_fsbuild("child \"%s\" is a deletion dirent, skipping...\n", fd->name);
				jffs2_free_full_dirent(fd);
				continue;
			}
			if (!whinged)
				whinged = 1;

			dbg_fsbuild("removing child \"%s\", ino #%u\n", fd->name, fd->ino);

			child_ic = jffs2_get_ino_cache(c, fd->ino);
			if (!child_ic) {
				dbg_fsbuild("cannot remove child \"%s\", ino #%u, because it doesn't exist\n",
						fd->name, fd->ino);
				jffs2_free_full_dirent(fd);
				continue;
			}

			/* Reduce nlink of the child. If it's now zero, stick it on the
			   dead_fds list to be cleaned up later. Else just free the fd */

			if (fd->type == DT_DIR)
				child_ic->pino_nlink = 0;
			else
				child_ic->pino_nlink--;

			if (!child_ic->pino_nlink) {
				dbg_fsbuild("inode #%u (\"%s\") now has no links; adding to dead_fds list.\n",
					  fd->ino, fd->name);
				fd->next = *dead_fds;
				*dead_fds = fd;
			} else {
				dbg_fsbuild("inode #%u (\"%s\") has now got nlink %d. Ignoring.\n",
					  fd->ino, fd->name, child_ic->pino_nlink);
				jffs2_free_full_dirent(fd);
			}
		}
	}

	/*
	   We don't delete the inocache from the hash list and free it yet.
	   The erase code will do that, when all the nodes are completely gone.
	*/
}

static void jffs2_calc_trigger_levels(struct jffs2_sb_info *c)
{
	uint32_t size;

	/* Deletion should almost _always_ be allowed. We're fairly
	   buggered once we stop allowing people to delete stuff
	   because there's not enough free space... */
	c->resv_blocks_deletion = 2;

	/* Be conservative about how much space we need before we allow writes.
	   On top of that which is required for deletia, require an extra 2%
	   of the medium to be available, for overhead caused by nodes being
	   split across blocks, etc. */

	size = c->flash_size / 50; /* 2% of flash size */
	size += c->nr_blocks * 100; /* And 100 bytes per eraseblock */
	size += c->sector_size - 1; /* ... and round up */

	c->resv_blocks_write = c->resv_blocks_deletion + (size / c->sector_size);

	/* When do we let the GC thread run in the background */

	c->resv_blocks_gctrigger = c->resv_blocks_write + 1;

	/* When do we allow garbage collection to merge nodes to make
	   long-term progress at the expense of short-term space exhaustion? */
	c->resv_blocks_gcmerge = c->resv_blocks_deletion + 1;

	/* When do we allow garbage collection to eat from bad blocks rather
	   than actually making progress? */
	c->resv_blocks_gcbad = 0;//c->resv_blocks_deletion + 2;

	/* What number of 'very dirty' eraseblocks do we allow before we
	   trigger the GC thread even if we don't _need_ the space. When we
	   can't mark nodes obsolete on the medium, the old dirty nodes cause
	   performance problems because we have to inspect and discard them. */
	c->vdirty_blocks_gctrigger = c->resv_blocks_gctrigger;
	if (jffs2_can_mark_obsolete(c))
		c->vdirty_blocks_gctrigger *= 10;

	/* If there's less than this amount of dirty space, don't bother
	   trying to GC to make more space. It'll be a fruitless task */
	c->nospc_dirty_size = c->sector_size + (c->flash_size / 100);

	dbg_fsbuild("trigger levels (size %d KiB, block size %d KiB, %d blocks)\n",
		    c->flash_size / 1024, c->sector_size / 1024, c->nr_blocks);
	dbg_fsbuild("Blocks required to allow deletion:    %d (%d KiB)\n",
		  c->resv_blocks_deletion, c->resv_blocks_deletion*c->sector_size/1024);
	dbg_fsbuild("Blocks required to allow writes:      %d (%d KiB)\n",
		  c->resv_blocks_write, c->resv_blocks_write*c->sector_size/1024);
	dbg_fsbuild("Blocks required to quiesce GC thread: %d (%d KiB)\n",
		  c->resv_blocks_gctrigger, c->resv_blocks_gctrigger*c->sector_size/1024);
	dbg_fsbuild("Blocks required to allow GC merges:   %d (%d KiB)\n",
		  c->resv_blocks_gcmerge, c->resv_blocks_gcmerge*c->sector_size/1024);
	dbg_fsbuild("Blocks required to GC bad blocks:     %d (%d KiB)\n",
		  c->resv_blocks_gcbad, c->resv_blocks_gcbad*c->sector_size/1024);
	dbg_fsbuild("Amount of dirty space required to GC: %d bytes\n",
		  c->nospc_dirty_size);
	dbg_fsbuild("Very dirty blocks before GC triggered: %d\n",
		  c->vdirty_blocks_gctrigger);
}

int jffs2_do_mount_fs(struct jffs2_sb_info *c)
{
	int ret;
	int i;
	int size;

	c->free_size = c->flash_size;
	c->nr_blocks = c->flash_size / c->sector_size;
	size = sizeof(struct jffs2_eraseblock) * c->nr_blocks;
#ifndef __ECOS
	if (jffs2_blocks_use_vmalloc(c))
		c->blocks = vzalloc(size);
	else
#endif
		c->blocks = kzalloc(size, GFP_KERNEL);
	if (!c->blocks)
		return -ENOMEM;

	for (i=0; i<c->nr_blocks; i++) {
		INIT_LIST_HEAD(&c->blocks[i].list);
		c->blocks[i].offset = i * c->sector_size;
		c->blocks[i].free_size = c->sector_size;
	}

	INIT_LIST_HEAD(&c->clean_list);
	INIT_LIST_HEAD(&c->very_dirty_list);
	INIT_LIST_HEAD(&c->dirty_list);
	INIT_LIST_HEAD(&c->erasable_list);
	INIT_LIST_HEAD(&c->erasing_list);
	INIT_LIST_HEAD(&c->erase_checking_list);
	INIT_LIST_HEAD(&c->erase_pending_list);
	INIT_LIST_HEAD(&c->erasable_pending_wbuf_list);
	INIT_LIST_HEAD(&c->erase_complete_list);
	INIT_LIST_HEAD(&c->free_list);
	INIT_LIST_HEAD(&c->bad_list);
	INIT_LIST_HEAD(&c->bad_used_list);
	c->highest_ino = 1;
	c->summary = NULL;

	ret = jffs2_sum_init(c);
	if (ret)
		goto out_free;

	if (jffs2_build_filesystem(c)) {
		dbg_fsbuild("build_fs failed\n");
		jffs2_free_ino_caches(c);
		jffs2_free_raw_node_refs(c);
		ret = -EIO;
		goto out_free;
	}

	jffs2_calc_trigger_levels(c);

	return 0;

 out_free:
#ifndef __ECOS
	if (jffs2_blocks_use_vmalloc(c))
		vfree(c->blocks);
	else
#endif
		kfree(c->blocks);

	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/build.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/slab.h>
// #include <linux/mtd/mtd.h>
// #include <linux/compiler.h>
// #include <linux/crc32.h>
// #include <linux/sched.h>
// #include <linux/pagemap.h>
// #include "nodelist.h"

struct erase_priv_struct {
	struct jffs2_eraseblock *jeb;
	struct jffs2_sb_info *c;
};

#ifndef __ECOS
static void jffs2_erase_callback(struct erase_info *);
#endif
static void jffs2_erase_failed(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb, uint32_t bad_offset);
static void jffs2_erase_succeeded(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb);
static void jffs2_mark_erased_block(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb);

static void jffs2_erase_block(struct jffs2_sb_info *c,
			      struct jffs2_eraseblock *jeb)
{
	int ret;
	uint32_t bad_offset;
#ifdef __ECOS
       ret = jffs2_flash_erase(c, jeb);
       if (!ret) {
	       jffs2_erase_succeeded(c, jeb);
	       return;
       }
       bad_offset = jeb->offset;
#else /* Linux */
	struct erase_info *instr;

	jffs2_dbg(1, "%s(): erase block %#08x (range %#08x-%#08x)\n",
		  __func__,
		  jeb->offset, jeb->offset, jeb->offset + c->sector_size);
	instr = kmalloc(sizeof(struct erase_info) + sizeof(struct erase_priv_struct), GFP_KERNEL);
	if (!instr) {
		pr_warn("kmalloc for struct erase_info in jffs2_erase_block failed. Refiling block for later\n");
		mutex_lock(&c->erase_free_sem);
		spin_lock(&c->erase_completion_lock);
		list_move(&jeb->list, &c->erase_pending_list);
		c->erasing_size -= c->sector_size;
		c->dirty_size += c->sector_size;
		jeb->dirty_size = c->sector_size;
		spin_unlock(&c->erase_completion_lock);
		mutex_unlock(&c->erase_free_sem);
		return;
	}

	memset(instr, 0, sizeof(*instr));

	instr->mtd = c->mtd;
	instr->addr = jeb->offset;
	instr->len = c->sector_size;
	instr->callback = jffs2_erase_callback;
	instr->priv = (unsigned long)(&instr[1]);

	((struct erase_priv_struct *)instr->priv)->jeb = jeb;
	((struct erase_priv_struct *)instr->priv)->c = c;

	ret = mtd_erase(c->mtd, instr);
	if (!ret)
		return;

	bad_offset = instr->fail_addr;
	kfree(instr);
#endif /* __ECOS */

	if (ret == -ENOMEM || ret == -EAGAIN) {
		/* Erase failed immediately. Refile it on the list */
		jffs2_dbg(1, "Erase at 0x%08x failed: %d. Refiling on erase_pending_list\n",
			  jeb->offset, ret);
		mutex_lock(&c->erase_free_sem);
		spin_lock(&c->erase_completion_lock);
		list_move(&jeb->list, &c->erase_pending_list);
		c->erasing_size -= c->sector_size;
		c->dirty_size += c->sector_size;
		jeb->dirty_size = c->sector_size;
		spin_unlock(&c->erase_completion_lock);
		mutex_unlock(&c->erase_free_sem);
		return;
	}

	if (ret == -EROFS)
		pr_warn("Erase at 0x%08x failed immediately: -EROFS. Is the sector locked?\n",
			jeb->offset);
	else
		pr_warn("Erase at 0x%08x failed immediately: errno %d\n",
			jeb->offset, ret);

	jffs2_erase_failed(c, jeb, bad_offset);
}

int jffs2_erase_pending_blocks(struct jffs2_sb_info *c, int count)
{
	struct jffs2_eraseblock *jeb;
	int work_done = 0;

	mutex_lock(&c->erase_free_sem);

	spin_lock(&c->erase_completion_lock);

	while (!list_empty(&c->erase_complete_list) ||
	       !list_empty(&c->erase_pending_list)) {

		if (!list_empty(&c->erase_complete_list)) {
			jeb = list_entry(c->erase_complete_list.next, struct jffs2_eraseblock, list);
			list_move(&jeb->list, &c->erase_checking_list);
			spin_unlock(&c->erase_completion_lock);
			mutex_unlock(&c->erase_free_sem);
			jffs2_mark_erased_block(c, jeb);

			work_done++;
			if (!--count) {
				jffs2_dbg(1, "Count reached. jffs2_erase_pending_blocks leaving\n");
				goto done;
			}

		} else if (!list_empty(&c->erase_pending_list)) {
			jeb = list_entry(c->erase_pending_list.next, struct jffs2_eraseblock, list);
			jffs2_dbg(1, "Starting erase of pending block 0x%08x\n",
				  jeb->offset);
			list_del(&jeb->list);
			c->erasing_size += c->sector_size;
			c->wasted_size -= jeb->wasted_size;
			c->free_size -= jeb->free_size;
			c->used_size -= jeb->used_size;
			c->dirty_size -= jeb->dirty_size;
			jeb->wasted_size = jeb->used_size = jeb->dirty_size = jeb->free_size = 0;
			jffs2_free_jeb_node_refs(c, jeb);
			list_add(&jeb->list, &c->erasing_list);
			spin_unlock(&c->erase_completion_lock);
			mutex_unlock(&c->erase_free_sem);

			jffs2_erase_block(c, jeb);

		} else {
			BUG();
		}

		/* Be nice */
		cond_resched();
		mutex_lock(&c->erase_free_sem);
		spin_lock(&c->erase_completion_lock);
	}

	spin_unlock(&c->erase_completion_lock);
	mutex_unlock(&c->erase_free_sem);
 done:
	jffs2_dbg(1, "jffs2_erase_pending_blocks completed\n");
	return work_done;
}

static void jffs2_erase_succeeded(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb)
{
	jffs2_dbg(1, "Erase completed successfully at 0x%08x\n", jeb->offset);
	mutex_lock(&c->erase_free_sem);
	spin_lock(&c->erase_completion_lock);
	list_move_tail(&jeb->list, &c->erase_complete_list);
	/* Wake the GC thread to mark them clean */
	jffs2_garbage_collect_trigger(c);
	spin_unlock(&c->erase_completion_lock);
	mutex_unlock(&c->erase_free_sem);
	wake_up(&c->erase_wait);
}

static void jffs2_erase_failed(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb, uint32_t bad_offset)
{
	/* For NAND, if the failure did not occur at the device level for a
	   specific physical page, don't bother updating the bad block table. */
	if (jffs2_cleanmarker_oob(c) && (bad_offset != (uint32_t)MTD_FAIL_ADDR_UNKNOWN)) {
		/* We had a device-level failure to erase.  Let's see if we've
		   failed too many times. */
		if (!jffs2_write_nand_badblock(c, jeb, bad_offset)) {
			/* We'd like to give this block another try. */
			mutex_lock(&c->erase_free_sem);
			spin_lock(&c->erase_completion_lock);
			list_move(&jeb->list, &c->erase_pending_list);
			c->erasing_size -= c->sector_size;
			c->dirty_size += c->sector_size;
			jeb->dirty_size = c->sector_size;
			spin_unlock(&c->erase_completion_lock);
			mutex_unlock(&c->erase_free_sem);
			return;
		}
	}

	mutex_lock(&c->erase_free_sem);
	spin_lock(&c->erase_completion_lock);
	c->erasing_size -= c->sector_size;
	c->bad_size += c->sector_size;
	list_move(&jeb->list, &c->bad_list);
	c->nr_erasing_blocks--;
	spin_unlock(&c->erase_completion_lock);
	mutex_unlock(&c->erase_free_sem);
	wake_up(&c->erase_wait);
}

#ifndef __ECOS
static void jffs2_erase_callback(struct erase_info *instr)
{
	struct erase_priv_struct *priv = (void *)instr->priv;

	if(instr->state != MTD_ERASE_DONE) {
		pr_warn("Erase at 0x%08llx finished, but state != MTD_ERASE_DONE. State is 0x%x instead.\n",
			(unsigned long long)instr->addr, instr->state);
		jffs2_erase_failed(priv->c, priv->jeb, instr->fail_addr);
	} else {
		jffs2_erase_succeeded(priv->c, priv->jeb);
	}
	kfree(instr);
}
#endif /* !__ECOS */

/* Hmmm. Maybe we should accept the extra space it takes and make
   this a standard doubly-linked list? */
static inline void jffs2_remove_node_refs_from_ino_list(struct jffs2_sb_info *c,
			struct jffs2_raw_node_ref *ref, struct jffs2_eraseblock *jeb)
{
	struct jffs2_inode_cache *ic = NULL;
	struct jffs2_raw_node_ref **prev;

	prev = &ref->next_in_ino;

	/* Walk the inode's list once, removing any nodes from this eraseblock */
	while (1) {
		if (!(*prev)->next_in_ino) {
			/* We're looking at the jffs2_inode_cache, which is
			   at the end of the linked list. Stash it and continue
			   from the beginning of the list */
			ic = (struct jffs2_inode_cache *)(*prev);
			prev = &ic->nodes;
			continue;
		}

		if (SECTOR_ADDR((*prev)->flash_offset) == jeb->offset) {
			/* It's in the block we're erasing */
			struct jffs2_raw_node_ref *this;

			this = *prev;
			*prev = this->next_in_ino;
			this->next_in_ino = NULL;

			if (this == ref)
				break;

			continue;
		}
		/* Not to be deleted. Skip */
		prev = &((*prev)->next_in_ino);
	}

	/* PARANOIA */
	if (!ic) {
		JFFS2_WARNING("inode_cache/xattr_datum/xattr_ref"
			      " not found in remove_node_refs()!!\n");
		return;
	}

	jffs2_dbg(1, "Removed nodes in range 0x%08x-0x%08x from ino #%u\n",
		  jeb->offset, jeb->offset + c->sector_size, ic->ino);

	D2({
		int i=0;
		struct jffs2_raw_node_ref *this;
		printk(KERN_DEBUG "After remove_node_refs_from_ino_list: \n");

		this = ic->nodes;

		printk(KERN_DEBUG);
		while(this) {
			pr_cont("0x%08x(%d)->",
			       ref_offset(this), ref_flags(this));
			if (++i == 5) {
				printk(KERN_DEBUG);
				i=0;
			}
			this = this->next_in_ino;
		}
		pr_cont("\n");
	});

	switch (ic->class) {
#ifdef CONFIG_JFFS2_FS_XATTR
		case RAWNODE_CLASS_XATTR_DATUM:
			jffs2_release_xattr_datum(c, (struct jffs2_xattr_datum *)ic);
			break;
		case RAWNODE_CLASS_XATTR_REF:
			jffs2_release_xattr_ref(c, (struct jffs2_xattr_ref *)ic);
			break;
#endif
		default:
			if (ic->nodes == (void *)ic && ic->pino_nlink == 0)
				jffs2_del_ino_cache(c, ic);
	}
}

void jffs2_free_jeb_node_refs(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb)
{
	struct jffs2_raw_node_ref *block, *ref;
	jffs2_dbg(1, "Freeing all node refs for eraseblock offset 0x%08x\n",
		  jeb->offset);

	block = ref = jeb->first_node;

	while (ref) {
		if (ref->flash_offset == REF_LINK_NODE) {
			ref = ref->next_in_ino;
			jffs2_free_refblock(block);
			block = ref;
			continue;
		}
		if (ref->flash_offset != REF_EMPTY_NODE && ref->next_in_ino)
			jffs2_remove_node_refs_from_ino_list(c, ref, jeb);
		/* else it was a non-inode node or already removed, so don't bother */

		ref++;
	}
	jeb->first_node = jeb->last_node = NULL;
}

static int jffs2_block_check_erase(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb, uint32_t *bad_offset)
{
	void *ebuf;
	uint32_t ofs;
	size_t retlen;
	int ret;
	unsigned long *wordebuf;

	ret = mtd_point(c->mtd, jeb->offset, c->sector_size, &retlen,
			&ebuf, NULL);
	if (ret != -EOPNOTSUPP) {
		if (ret) {
			jffs2_dbg(1, "MTD point failed %d\n", ret);
			goto do_flash_read;
		}
		if (retlen < c->sector_size) {
			/* Don't muck about if it won't let us point to the whole erase sector */
			jffs2_dbg(1, "MTD point returned len too short: 0x%zx\n",
				  retlen);
			mtd_unpoint(c->mtd, jeb->offset, retlen);
			goto do_flash_read;
		}
		wordebuf = ebuf-sizeof(*wordebuf);
		retlen /= sizeof(*wordebuf);
		do {
		   if (*++wordebuf != ~0)
			   break;
		} while(--retlen);
		mtd_unpoint(c->mtd, jeb->offset, c->sector_size);
		if (retlen) {
			pr_warn("Newly-erased block contained word 0x%lx at offset 0x%08tx\n",
				*wordebuf,
				jeb->offset +
				c->sector_size-retlen * sizeof(*wordebuf));
			return -EIO;
		}
		return 0;
	}
 do_flash_read:
	ebuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ebuf) {
		pr_warn("Failed to allocate page buffer for verifying erase at 0x%08x. Refiling\n",
			jeb->offset);
		return -EAGAIN;
	}

	jffs2_dbg(1, "Verifying erase at 0x%08x\n", jeb->offset);

	for (ofs = jeb->offset; ofs < jeb->offset + c->sector_size; ) {
		uint32_t readlen = min((uint32_t)PAGE_SIZE, jeb->offset + c->sector_size - ofs);
		int i;

		*bad_offset = ofs;

		ret = mtd_read(c->mtd, ofs, readlen, &retlen, ebuf);
		if (ret) {
			pr_warn("Read of newly-erased block at 0x%08x failed: %d. Putting on bad_list\n",
				ofs, ret);
			ret = -EIO;
			goto fail;
		}
		if (retlen != readlen) {
			pr_warn("Short read from newly-erased block at 0x%08x. Wanted %d, got %zd\n",
				ofs, readlen, retlen);
			ret = -EIO;
			goto fail;
		}
		for (i=0; i<readlen; i += sizeof(unsigned long)) {
			/* It's OK. We know it's properly aligned */
			unsigned long *datum = ebuf + i;
			if (*datum + 1) {
				*bad_offset += i;
				pr_warn("Newly-erased block contained word 0x%lx at offset 0x%08x\n",
					*datum, *bad_offset);
				ret = -EIO;
				goto fail;
			}
		}
		ofs += readlen;
		cond_resched();
	}
	ret = 0;
fail:
	kfree(ebuf);
	return ret;
}

static void jffs2_mark_erased_block(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb)
{
	size_t retlen;
	int ret;
	uint32_t uninitialized_var(bad_offset);

	switch (jffs2_block_check_erase(c, jeb, &bad_offset)) {
	case -EAGAIN:	goto refile;
	case -EIO:	goto filebad;
	}

	/* Write the erase complete marker */
	jffs2_dbg(1, "Writing erased marker to block at 0x%08x\n", jeb->offset);
	bad_offset = jeb->offset;

	/* Cleanmarker in oob area or no cleanmarker at all ? */
	if (jffs2_cleanmarker_oob(c) || c->cleanmarker_size == 0) {

		if (jffs2_cleanmarker_oob(c)) {
			if (jffs2_write_nand_cleanmarker(c, jeb))
				goto filebad;
		}
	} else {

		struct kvec vecs[1];
		struct jffs2_unknown_node marker = {
			.magic =	cpu_to_je16(JFFS2_MAGIC_BITMASK),
			.nodetype =	cpu_to_je16(JFFS2_NODETYPE_CLEANMARKER),
			.totlen =	cpu_to_je32(c->cleanmarker_size)
		};

		jffs2_prealloc_raw_node_refs(c, jeb, 1);

		marker.hdr_crc = cpu_to_je32(crc32(0, &marker, sizeof(struct jffs2_unknown_node)-4));

		vecs[0].iov_base = (unsigned char *) &marker;
		vecs[0].iov_len = sizeof(marker);
		ret = jffs2_flash_direct_writev(c, vecs, 1, jeb->offset, &retlen);

		if (ret || retlen != sizeof(marker)) {
			if (ret)
				pr_warn("Write clean marker to block at 0x%08x failed: %d\n",
				       jeb->offset, ret);
			else
				pr_warn("Short write to newly-erased block at 0x%08x: Wanted %zd, got %zd\n",
				       jeb->offset, sizeof(marker), retlen);

			goto filebad;
		}
	}
	/* Everything else got zeroed before the erase */
	jeb->free_size = c->sector_size;

	mutex_lock(&c->erase_free_sem);
	spin_lock(&c->erase_completion_lock);

	c->erasing_size -= c->sector_size;
	c->free_size += c->sector_size;

	/* Account for cleanmarker now, if it's in-band */
	if (c->cleanmarker_size && !jffs2_cleanmarker_oob(c))
		jffs2_link_node_ref(c, jeb, jeb->offset | REF_NORMAL, c->cleanmarker_size, NULL);

	list_move_tail(&jeb->list, &c->free_list);
	c->nr_erasing_blocks--;
	c->nr_free_blocks++;

	jffs2_dbg_acct_sanity_check_nolock(c, jeb);
	jffs2_dbg_acct_paranoia_check_nolock(c, jeb);

	spin_unlock(&c->erase_completion_lock);
	mutex_unlock(&c->erase_free_sem);
	wake_up(&c->erase_wait);
	return;

filebad:
	jffs2_erase_failed(c, jeb, bad_offset);
	return;

refile:
	/* Stick it back on the list from whence it came and come back later */
	mutex_lock(&c->erase_free_sem);
	spin_lock(&c->erase_completion_lock);
	jffs2_garbage_collect_trigger(c);
	list_move(&jeb->list, &c->erase_complete_list);
	spin_unlock(&c->erase_completion_lock);
	mutex_unlock(&c->erase_free_sem);
	return;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/erase.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/jffs2.h>
// #include <linux/mtd/mtd.h>
#include <linux/completion.h>
// #include <linux/sched.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
// #include "nodelist.h"


static int jffs2_garbage_collect_thread(void *);

void jffs2_garbage_collect_trigger(struct jffs2_sb_info *c)
{
	assert_spin_locked(&c->erase_completion_lock);
	if (c->gc_task && jffs2_thread_should_wake(c))
		send_sig(SIGHUP, c->gc_task, 1);
}

/* This must only ever be called when no GC thread is currently running */
int jffs2_start_garbage_collect_thread(struct jffs2_sb_info *c)
{
	struct task_struct *tsk;
	int ret = 0;

	BUG_ON(c->gc_task);

	init_completion(&c->gc_thread_start);
	init_completion(&c->gc_thread_exit);

	tsk = kthread_run(jffs2_garbage_collect_thread, c, "jffs2_gcd_mtd%d", c->mtd->index);
	if (IS_ERR(tsk)) {
		pr_warn("fork failed for JFFS2 garbage collect thread: %ld\n",
			-PTR_ERR(tsk));
		complete(&c->gc_thread_exit);
		ret = PTR_ERR(tsk);
	} else {
		/* Wait for it... */
		jffs2_dbg(1, "Garbage collect thread is pid %d\n", tsk->pid);
		wait_for_completion(&c->gc_thread_start);
		ret = tsk->pid;
	}

	return ret;
}

void jffs2_stop_garbage_collect_thread(struct jffs2_sb_info *c)
{
	int wait = 0;
	spin_lock(&c->erase_completion_lock);
	if (c->gc_task) {
		jffs2_dbg(1, "Killing GC task %d\n", c->gc_task->pid);
		send_sig(SIGKILL, c->gc_task, 1);
		wait = 1;
	}
	spin_unlock(&c->erase_completion_lock);
	if (wait)
		wait_for_completion(&c->gc_thread_exit);
}

static int jffs2_garbage_collect_thread(void *_c)
{
	struct jffs2_sb_info *c = _c;
	sigset_t hupmask;

	siginitset(&hupmask, sigmask(SIGHUP));
	allow_signal(SIGKILL);
	allow_signal(SIGSTOP);
	allow_signal(SIGCONT);
	allow_signal(SIGHUP);

	c->gc_task = current;
	complete(&c->gc_thread_start);

	set_user_nice(current, 10);

	set_freezable();
	for (;;) {
		sigprocmask(SIG_UNBLOCK, &hupmask, NULL);
	again:
		spin_lock(&c->erase_completion_lock);
		if (!jffs2_thread_should_wake(c)) {
			set_current_state (TASK_INTERRUPTIBLE);
			spin_unlock(&c->erase_completion_lock);
			jffs2_dbg(1, "%s(): sleeping...\n", __func__);
			schedule();
		} else {
			spin_unlock(&c->erase_completion_lock);
		}
		/* Problem - immediately after bootup, the GCD spends a lot
		 * of time in places like jffs2_kill_fragtree(); so much so
		 * that userspace processes (like gdm and X) are starved
		 * despite plenty of cond_resched()s and renicing.  Yield()
		 * doesn't help, either (presumably because userspace and GCD
		 * are generally competing for a higher latency resource -
		 * disk).
		 * This forces the GCD to slow the hell down.   Pulling an
		 * inode in with read_inode() is much preferable to having
		 * the GC thread get there first. */
		schedule_timeout_interruptible(msecs_to_jiffies(50));

		if (kthread_should_stop()) {
			jffs2_dbg(1, "%s(): kthread_stop() called\n", __func__);
			goto die;
		}

		/* Put_super will send a SIGKILL and then wait on the sem.
		 */
		while (signal_pending(current) || freezing(current)) {
			siginfo_t info;
			unsigned long signr;

			if (try_to_freeze())
				goto again;

			signr = dequeue_signal_lock(current, &current->blocked, &info);

			switch(signr) {
			case SIGSTOP:
				jffs2_dbg(1, "%s(): SIGSTOP received\n",
					  __func__);
				set_current_state(TASK_STOPPED);
				schedule();
				break;

			case SIGKILL:
				jffs2_dbg(1, "%s(): SIGKILL received\n",
					  __func__);
				goto die;

			case SIGHUP:
				jffs2_dbg(1, "%s(): SIGHUP received\n",
					  __func__);
				break;
			default:
				jffs2_dbg(1, "%s(): signal %ld received\n",
					  __func__, signr);
			}
		}
		/* We don't want SIGHUP to interrupt us. STOP and KILL are OK though. */
		sigprocmask(SIG_BLOCK, &hupmask, NULL);

		jffs2_dbg(1, "%s(): pass\n", __func__);
		if (jffs2_garbage_collect_pass(c) == -ENOSPC) {
			pr_notice("No space for garbage collection. Aborting GC thread\n");
			goto die;
		}
	}
 die:
	spin_lock(&c->erase_completion_lock);
	c->gc_task = NULL;
	spin_unlock(&c->erase_completion_lock);
	complete_and_exit(&c->gc_thread_exit, 0);
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/background.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/capability.h>
// #include <linux/kernel.h>
// #include <linux/sched.h>
// #include <linux/fs.h>
#include <linux/list.h>
// #include <linux/mtd/mtd.h>
// #include <linux/pagemap.h>
// #include <linux/slab.h>
// #include <linux/vmalloc.h>
#include <linux/vfs.h>
// #include <linux/crc32.h>
// #include "nodelist.h"

static int jffs2_flash_setup(struct jffs2_sb_info *c);

int jffs2_do_setattr (struct inode *inode, struct iattr *iattr)
{
	struct jffs2_full_dnode *old_metadata, *new_metadata;
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(inode);
	struct jffs2_sb_info *c = JFFS2_SB_INFO(inode->i_sb);
	struct jffs2_raw_inode *ri;
	union jffs2_device_node dev;
	unsigned char *mdata = NULL;
	int mdatalen = 0;
	unsigned int ivalid;
	uint32_t alloclen;
	int ret;
	int alloc_type = ALLOC_NORMAL;

	jffs2_dbg(1, "%s(): ino #%lu\n", __func__, inode->i_ino);

	/* Special cases - we don't want more than one data node
	   for these types on the medium at any time. So setattr
	   must read the original data associated with the node
	   (i.e. the device numbers or the target name) and write
	   it out again with the appropriate data attached */
	if (S_ISBLK(inode->i_mode) || S_ISCHR(inode->i_mode)) {
		/* For these, we don't actually need to read the old node */
		mdatalen = jffs2_encode_dev(&dev, inode->i_rdev);
		mdata = (char *)&dev;
		jffs2_dbg(1, "%s(): Writing %d bytes of kdev_t\n",
			  __func__, mdatalen);
	} else if (S_ISLNK(inode->i_mode)) {
		mutex_lock(&f->sem);
		mdatalen = f->metadata->size;
		mdata = kmalloc(f->metadata->size, GFP_USER);
		if (!mdata) {
			mutex_unlock(&f->sem);
			return -ENOMEM;
		}
		ret = jffs2_read_dnode(c, f, f->metadata, mdata, 0, mdatalen);
		if (ret) {
			mutex_unlock(&f->sem);
			kfree(mdata);
			return ret;
		}
		mutex_unlock(&f->sem);
		jffs2_dbg(1, "%s(): Writing %d bytes of symlink target\n",
			  __func__, mdatalen);
	}

	ri = jffs2_alloc_raw_inode();
	if (!ri) {
		if (S_ISLNK(inode->i_mode))
			kfree(mdata);
		return -ENOMEM;
	}

	ret = jffs2_reserve_space(c, sizeof(*ri) + mdatalen, &alloclen,
				  ALLOC_NORMAL, JFFS2_SUMMARY_INODE_SIZE);
	if (ret) {
		jffs2_free_raw_inode(ri);
		if (S_ISLNK(inode->i_mode))
			 kfree(mdata);
		return ret;
	}
	mutex_lock(&f->sem);
	ivalid = iattr->ia_valid;

	ri->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
	ri->nodetype = cpu_to_je16(JFFS2_NODETYPE_INODE);
	ri->totlen = cpu_to_je32(sizeof(*ri) + mdatalen);
	ri->hdr_crc = cpu_to_je32(crc32(0, ri, sizeof(struct jffs2_unknown_node)-4));

	ri->ino = cpu_to_je32(inode->i_ino);
	ri->version = cpu_to_je32(++f->highest_version);

	ri->uid = cpu_to_je16((ivalid & ATTR_UID)?
		from_kuid(&init_user_ns, iattr->ia_uid):i_uid_read(inode));
	ri->gid = cpu_to_je16((ivalid & ATTR_GID)?
		from_kgid(&init_user_ns, iattr->ia_gid):i_gid_read(inode));

	if (ivalid & ATTR_MODE)
		ri->mode = cpu_to_jemode(iattr->ia_mode);
	else
		ri->mode = cpu_to_jemode(inode->i_mode);


	ri->isize = cpu_to_je32((ivalid & ATTR_SIZE)?iattr->ia_size:inode->i_size);
	ri->atime = cpu_to_je32(I_SEC((ivalid & ATTR_ATIME)?iattr->ia_atime:inode->i_atime));
	ri->mtime = cpu_to_je32(I_SEC((ivalid & ATTR_MTIME)?iattr->ia_mtime:inode->i_mtime));
	ri->ctime = cpu_to_je32(I_SEC((ivalid & ATTR_CTIME)?iattr->ia_ctime:inode->i_ctime));

	ri->offset = cpu_to_je32(0);
	ri->csize = ri->dsize = cpu_to_je32(mdatalen);
	ri->compr = JFFS2_COMPR_NONE;
	if (ivalid & ATTR_SIZE && inode->i_size < iattr->ia_size) {
		/* It's an extension. Make it a hole node */
		ri->compr = JFFS2_COMPR_ZERO;
		ri->dsize = cpu_to_je32(iattr->ia_size - inode->i_size);
		ri->offset = cpu_to_je32(inode->i_size);
	} else if (ivalid & ATTR_SIZE && !iattr->ia_size) {
		/* For truncate-to-zero, treat it as deletion because
		   it'll always be obsoleting all previous nodes */
		alloc_type = ALLOC_DELETION;
	}
	ri->node_crc = cpu_to_je32(crc32(0, ri, sizeof(*ri)-8));
	if (mdatalen)
		ri->data_crc = cpu_to_je32(crc32(0, mdata, mdatalen));
	else
		ri->data_crc = cpu_to_je32(0);

	new_metadata = jffs2_write_dnode(c, f, ri, mdata, mdatalen, alloc_type);
	if (S_ISLNK(inode->i_mode))
		kfree(mdata);

	if (IS_ERR(new_metadata)) {
		jffs2_complete_reservation(c);
		jffs2_free_raw_inode(ri);
		mutex_unlock(&f->sem);
		return PTR_ERR(new_metadata);
	}
	/* It worked. Update the inode */
	inode->i_atime = ITIME(je32_to_cpu(ri->atime));
	inode->i_ctime = ITIME(je32_to_cpu(ri->ctime));
	inode->i_mtime = ITIME(je32_to_cpu(ri->mtime));
	inode->i_mode = jemode_to_cpu(ri->mode);
	i_uid_write(inode, je16_to_cpu(ri->uid));
	i_gid_write(inode, je16_to_cpu(ri->gid));


	old_metadata = f->metadata;

	if (ivalid & ATTR_SIZE && inode->i_size > iattr->ia_size)
		jffs2_truncate_fragtree (c, &f->fragtree, iattr->ia_size);

	if (ivalid & ATTR_SIZE && inode->i_size < iattr->ia_size) {
		jffs2_add_full_dnode_to_inode(c, f, new_metadata);
		inode->i_size = iattr->ia_size;
		inode->i_blocks = (inode->i_size + 511) >> 9;
		f->metadata = NULL;
	} else {
		f->metadata = new_metadata;
	}
	if (old_metadata) {
		jffs2_mark_node_obsolete(c, old_metadata->raw);
		jffs2_free_full_dnode(old_metadata);
	}
	jffs2_free_raw_inode(ri);

	mutex_unlock(&f->sem);
	jffs2_complete_reservation(c);

	/* We have to do the truncate_setsize() without f->sem held, since
	   some pages may be locked and waiting for it in readpage().
	   We are protected from a simultaneous write() extending i_size
	   back past iattr->ia_size, because do_truncate() holds the
	   generic inode semaphore. */
	if (ivalid & ATTR_SIZE && inode->i_size > iattr->ia_size) {
		truncate_setsize(inode, iattr->ia_size);
		inode->i_blocks = (inode->i_size + 511) >> 9;
	}

	return 0;
}

int jffs2_setattr(struct dentry *dentry, struct iattr *iattr)
{
	struct inode *inode = dentry->d_inode;
	int rc;

	rc = inode_change_ok(inode, iattr);
	if (rc)
		return rc;

	rc = jffs2_do_setattr(inode, iattr);
	if (!rc && (iattr->ia_valid & ATTR_MODE))
		rc = posix_acl_chmod(inode, inode->i_mode);

	return rc;
}

int jffs2_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(dentry->d_sb);
	unsigned long avail;

	buf->f_type = JFFS2_SUPER_MAGIC;
	buf->f_bsize = 1 << PAGE_SHIFT;
	buf->f_blocks = c->flash_size >> PAGE_SHIFT;
	buf->f_files = 0;
	buf->f_ffree = 0;
	buf->f_namelen = JFFS2_MAX_NAME_LEN;
	buf->f_fsid.val[0] = JFFS2_SUPER_MAGIC;
	buf->f_fsid.val[1] = c->mtd->index;

	spin_lock(&c->erase_completion_lock);
	avail = c->dirty_size + c->free_size;
	if (avail > c->sector_size * c->resv_blocks_write)
		avail -= c->sector_size * c->resv_blocks_write;
	else
		avail = 0;
	spin_unlock(&c->erase_completion_lock);

	buf->f_bavail = buf->f_bfree = avail >> PAGE_SHIFT;

	return 0;
}


void jffs2_evict_inode (struct inode *inode)
{
	/* We can forget about this inode for now - drop all
	 *  the nodelists associated with it, etc.
	 */
	struct jffs2_sb_info *c = JFFS2_SB_INFO(inode->i_sb);
	struct jffs2_inode_info *f = JFFS2_INODE_INFO(inode);

	jffs2_dbg(1, "%s(): ino #%lu mode %o\n",
		  __func__, inode->i_ino, inode->i_mode);
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	jffs2_do_clear_inode(c, f);
}

struct inode *jffs2_iget(struct super_block *sb, unsigned long ino)
{
	struct jffs2_inode_info *f;
	struct jffs2_sb_info *c;
	struct jffs2_raw_inode latest_node;
	union jffs2_device_node jdev;
	struct inode *inode;
	dev_t rdev = 0;
	int ret;

	jffs2_dbg(1, "%s(): ino == %lu\n", __func__, ino);

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	f = JFFS2_INODE_INFO(inode);
	c = JFFS2_SB_INFO(inode->i_sb);

	jffs2_init_inode_info(f);
	mutex_lock(&f->sem);

	ret = jffs2_do_read_inode(c, f, inode->i_ino, &latest_node);

	if (ret) {
		mutex_unlock(&f->sem);
		iget_failed(inode);
		return ERR_PTR(ret);
	}
	inode->i_mode = jemode_to_cpu(latest_node.mode);
	i_uid_write(inode, je16_to_cpu(latest_node.uid));
	i_gid_write(inode, je16_to_cpu(latest_node.gid));
	inode->i_size = je32_to_cpu(latest_node.isize);
	inode->i_atime = ITIME(je32_to_cpu(latest_node.atime));
	inode->i_mtime = ITIME(je32_to_cpu(latest_node.mtime));
	inode->i_ctime = ITIME(je32_to_cpu(latest_node.ctime));

	set_nlink(inode, f->inocache->pino_nlink);

	inode->i_blocks = (inode->i_size + 511) >> 9;

	switch (inode->i_mode & S_IFMT) {

	case S_IFLNK:
		inode->i_op = &jffs2_symlink_inode_operations;
		break;

	case S_IFDIR:
	{
		struct jffs2_full_dirent *fd;
		set_nlink(inode, 2); /* parent and '.' */

		for (fd=f->dents; fd; fd = fd->next) {
			if (fd->type == DT_DIR && fd->ino)
				inc_nlink(inode);
		}
		/* Root dir gets i_nlink 3 for some reason */
		if (inode->i_ino == 1)
			inc_nlink(inode);

		inode->i_op = &jffs2_dir_inode_operations;
		inode->i_fop = &jffs2_dir_operations;
		break;
	}
	case S_IFREG:
		inode->i_op = &jffs2_file_inode_operations;
		inode->i_fop = &jffs2_file_operations;
		inode->i_mapping->a_ops = &jffs2_file_address_operations;
		inode->i_mapping->nrpages = 0;
		break;

	case S_IFBLK:
	case S_IFCHR:
		/* Read the device numbers from the media */
		if (f->metadata->size != sizeof(jdev.old_id) &&
		    f->metadata->size != sizeof(jdev.new_id)) {
			pr_notice("Device node has strange size %d\n",
				  f->metadata->size);
			goto error_io;
		}
		jffs2_dbg(1, "Reading device numbers from flash\n");
		ret = jffs2_read_dnode(c, f, f->metadata, (char *)&jdev, 0, f->metadata->size);
		if (ret < 0) {
			/* Eep */
			pr_notice("Read device numbers for inode %lu failed\n",
				  (unsigned long)inode->i_ino);
			goto error;
		}
		if (f->metadata->size == sizeof(jdev.old_id))
			rdev = old_decode_dev(je16_to_cpu(jdev.old_id));
		else
			rdev = new_decode_dev(je32_to_cpu(jdev.new_id));

	case S_IFSOCK:
	case S_IFIFO:
		inode->i_op = &jffs2_file_inode_operations;
		init_special_inode(inode, inode->i_mode, rdev);
		break;

	default:
		pr_warn("%s(): Bogus i_mode %o for ino %lu\n",
			__func__, inode->i_mode, (unsigned long)inode->i_ino);
	}

	mutex_unlock(&f->sem);

	jffs2_dbg(1, "jffs2_read_inode() returning\n");
	unlock_new_inode(inode);
	return inode;

error_io:
	ret = -EIO;
error:
	mutex_unlock(&f->sem);
	jffs2_do_clear_inode(c, f);
	iget_failed(inode);
	return ERR_PTR(ret);
}

void jffs2_dirty_inode(struct inode *inode, int flags)
{
	struct iattr iattr;

	if (!(inode->i_state & I_DIRTY_DATASYNC)) {
		jffs2_dbg(2, "%s(): not calling setattr() for ino #%lu\n",
			  __func__, inode->i_ino);
		return;
	}

	jffs2_dbg(1, "%s(): calling setattr() for ino #%lu\n",
		  __func__, inode->i_ino);

	iattr.ia_valid = ATTR_MODE|ATTR_UID|ATTR_GID|ATTR_ATIME|ATTR_MTIME|ATTR_CTIME;
	iattr.ia_mode = inode->i_mode;
	iattr.ia_uid = inode->i_uid;
	iattr.ia_gid = inode->i_gid;
	iattr.ia_atime = inode->i_atime;
	iattr.ia_mtime = inode->i_mtime;
	iattr.ia_ctime = inode->i_ctime;

	jffs2_do_setattr(inode, &iattr);
}

int jffs2_do_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(sb);

	if (c->flags & JFFS2_SB_FLAG_RO && !(sb->s_flags & MS_RDONLY))
		return -EROFS;

	/* We stop if it was running, then restart if it needs to.
	   This also catches the case where it was stopped and this
	   is just a remount to restart it.
	   Flush the writebuffer, if neccecary, else we loose it */
	if (!(sb->s_flags & MS_RDONLY)) {
		jffs2_stop_garbage_collect_thread(c);
		mutex_lock(&c->alloc_sem);
		jffs2_flush_wbuf_pad(c);
		mutex_unlock(&c->alloc_sem);
	}

	if (!(*flags & MS_RDONLY))
		jffs2_start_garbage_collect_thread(c);

	*flags |= MS_NOATIME;
	return 0;
}

/* jffs2_new_inode: allocate a new inode and inocache, add it to the hash,
   fill in the raw_inode while you're at it. */
struct inode *jffs2_new_inode (struct inode *dir_i, umode_t mode, struct jffs2_raw_inode *ri)
{
	struct inode *inode;
	struct super_block *sb = dir_i->i_sb;
	struct jffs2_sb_info *c;
	struct jffs2_inode_info *f;
	int ret;

	jffs2_dbg(1, "%s(): dir_i %ld, mode 0x%x\n",
		  __func__, dir_i->i_ino, mode);

	c = JFFS2_SB_INFO(sb);

	inode = new_inode(sb);

	if (!inode)
		return ERR_PTR(-ENOMEM);

	f = JFFS2_INODE_INFO(inode);
	jffs2_init_inode_info(f);
	mutex_lock(&f->sem);

	memset(ri, 0, sizeof(*ri));
	/* Set OS-specific defaults for new inodes */
	ri->uid = cpu_to_je16(from_kuid(&init_user_ns, current_fsuid()));

	if (dir_i->i_mode & S_ISGID) {
		ri->gid = cpu_to_je16(i_gid_read(dir_i));
		if (S_ISDIR(mode))
			mode |= S_ISGID;
	} else {
		ri->gid = cpu_to_je16(from_kgid(&init_user_ns, current_fsgid()));
	}

	/* POSIX ACLs have to be processed now, at least partly.
	   The umask is only applied if there's no default ACL */
	ret = jffs2_init_acl_pre(dir_i, inode, &mode);
	if (ret) {
		mutex_unlock(&f->sem);
		make_bad_inode(inode);
		iput(inode);
		return ERR_PTR(ret);
	}
	ret = jffs2_do_new_inode (c, f, mode, ri);
	if (ret) {
		mutex_unlock(&f->sem);
		make_bad_inode(inode);
		iput(inode);
		return ERR_PTR(ret);
	}
	set_nlink(inode, 1);
	inode->i_ino = je32_to_cpu(ri->ino);
	inode->i_mode = jemode_to_cpu(ri->mode);
	i_gid_write(inode, je16_to_cpu(ri->gid));
	i_uid_write(inode, je16_to_cpu(ri->uid));
	inode->i_atime = inode->i_ctime = inode->i_mtime = CURRENT_TIME_SEC;
	ri->atime = ri->mtime = ri->ctime = cpu_to_je32(I_SEC(inode->i_mtime));

	inode->i_blocks = 0;
	inode->i_size = 0;

	if (insert_inode_locked(inode) < 0) {
		mutex_unlock(&f->sem);
		make_bad_inode(inode);
		iput(inode);
		return ERR_PTR(-EINVAL);
	}

	return inode;
}

static int calculate_inocache_hashsize(uint32_t flash_size)
{
	/*
	 * Pick a inocache hash size based on the size of the medium.
	 * Count how many megabytes we're dealing with, apply a hashsize twice
	 * that size, but rounding down to the usual big powers of 2. And keep
	 * to sensible bounds.
	 */

	int size_mb = flash_size / 1024 / 1024;
	int hashsize = (size_mb * 2) & ~0x3f;

	if (hashsize < INOCACHE_HASHSIZE_MIN)
		return INOCACHE_HASHSIZE_MIN;
	if (hashsize > INOCACHE_HASHSIZE_MAX)
		return INOCACHE_HASHSIZE_MAX;

	return hashsize;
}

int jffs2_do_fill_super(struct super_block *sb, void *data, int silent)
{
	struct jffs2_sb_info *c;
	struct inode *root_i;
	int ret;
	size_t blocks;

	c = JFFS2_SB_INFO(sb);

	/* Do not support the MLC nand */
	if (c->mtd->type == MTD_MLCNANDFLASH)
		return -EINVAL;

#ifndef CONFIG_JFFS2_FS_WRITEBUFFER
	if (c->mtd->type == MTD_NANDFLASH) {
		pr_err("Cannot operate on NAND flash unless jffs2 NAND support is compiled in\n");
		return -EINVAL;
	}
	if (c->mtd->type == MTD_DATAFLASH) {
		pr_err("Cannot operate on DataFlash unless jffs2 DataFlash support is compiled in\n");
		return -EINVAL;
	}
#endif

	c->flash_size = c->mtd->size;
	c->sector_size = c->mtd->erasesize;
	blocks = c->flash_size / c->sector_size;

	/*
	 * Size alignment check
	 */
	if ((c->sector_size * blocks) != c->flash_size) {
		c->flash_size = c->sector_size * blocks;
		pr_info("Flash size not aligned to erasesize, reducing to %dKiB\n",
			c->flash_size / 1024);
	}

	if (c->flash_size < 5*c->sector_size) {
		pr_err("Too few erase blocks (%d)\n",
		       c->flash_size / c->sector_size);
		return -EINVAL;
	}

	c->cleanmarker_size = sizeof(struct jffs2_unknown_node);

	/* NAND (or other bizarre) flash... do setup accordingly */
	ret = jffs2_flash_setup(c);
	if (ret)
		return ret;

	c->inocache_hashsize = calculate_inocache_hashsize(c->flash_size);
	c->inocache_list = kcalloc(c->inocache_hashsize, sizeof(struct jffs2_inode_cache *), GFP_KERNEL);
	if (!c->inocache_list) {
		ret = -ENOMEM;
		goto out_wbuf;
	}

	jffs2_init_xattr_subsystem(c);

	if ((ret = jffs2_do_mount_fs(c)))
		goto out_inohash;

	jffs2_dbg(1, "%s(): Getting root inode\n", __func__);
	root_i = jffs2_iget(sb, 1);
	if (IS_ERR(root_i)) {
		jffs2_dbg(1, "get root inode failed\n");
		ret = PTR_ERR(root_i);
		goto out_root;
	}

	ret = -ENOMEM;

	jffs2_dbg(1, "%s(): d_make_root()\n", __func__);
	sb->s_root = d_make_root(root_i);
	if (!sb->s_root)
		goto out_root;

	sb->s_maxbytes = 0xFFFFFFFF;
	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = JFFS2_SUPER_MAGIC;
	if (!(sb->s_flags & MS_RDONLY))
		jffs2_start_garbage_collect_thread(c);
	return 0;

out_root:
	jffs2_free_ino_caches(c);
	jffs2_free_raw_node_refs(c);
	if (jffs2_blocks_use_vmalloc(c))
		vfree(c->blocks);
	else
		kfree(c->blocks);
 out_inohash:
	jffs2_clear_xattr_subsystem(c);
	kfree(c->inocache_list);
 out_wbuf:
	jffs2_flash_cleanup(c);

	return ret;
}

void jffs2_gc_release_inode(struct jffs2_sb_info *c,
				   struct jffs2_inode_info *f)
{
	iput(OFNI_EDONI_2SFFJ(f));
}

struct jffs2_inode_info *jffs2_gc_fetch_inode(struct jffs2_sb_info *c,
					      int inum, int unlinked)
{
	struct inode *inode;
	struct jffs2_inode_cache *ic;

	if (unlinked) {
		/* The inode has zero nlink but its nodes weren't yet marked
		   obsolete. This has to be because we're still waiting for
		   the final (close() and) iput() to happen.

		   There's a possibility that the final iput() could have
		   happened while we were contemplating. In order to ensure
		   that we don't cause a new read_inode() (which would fail)
		   for the inode in question, we use ilookup() in this case
		   instead of iget().

		   The nlink can't _become_ zero at this point because we're
		   holding the alloc_sem, and jffs2_do_unlink() would also
		   need that while decrementing nlink on any inode.
		*/
		inode = ilookup(OFNI_BS_2SFFJ(c), inum);
		if (!inode) {
			jffs2_dbg(1, "ilookup() failed for ino #%u; inode is probably deleted.\n",
				  inum);

			spin_lock(&c->inocache_lock);
			ic = jffs2_get_ino_cache(c, inum);
			if (!ic) {
				jffs2_dbg(1, "Inode cache for ino #%u is gone\n",
					  inum);
				spin_unlock(&c->inocache_lock);
				return NULL;
			}
			if (ic->state != INO_STATE_CHECKEDABSENT) {
				/* Wait for progress. Don't just loop */
				jffs2_dbg(1, "Waiting for ino #%u in state %d\n",
					  ic->ino, ic->state);
				sleep_on_spinunlock(&c->inocache_wq, &c->inocache_lock);
			} else {
				spin_unlock(&c->inocache_lock);
			}

			return NULL;
		}
	} else {
		/* Inode has links to it still; they're not going away because
		   jffs2_do_unlink() would need the alloc_sem and we have it.
		   Just iget() it, and if read_inode() is necessary that's OK.
		*/
		inode = jffs2_iget(OFNI_BS_2SFFJ(c), inum);
		if (IS_ERR(inode))
			return ERR_CAST(inode);
	}
	if (is_bad_inode(inode)) {
		pr_notice("Eep. read_inode() failed for ino #%u. unlinked %d\n",
			  inum, unlinked);
		/* NB. This will happen again. We need to do something appropriate here. */
		iput(inode);
		return ERR_PTR(-EIO);
	}

	return JFFS2_INODE_INFO(inode);
}

unsigned char *jffs2_gc_fetch_page(struct jffs2_sb_info *c,
				   struct jffs2_inode_info *f,
				   unsigned long offset,
				   unsigned long *priv)
{
	struct inode *inode = OFNI_EDONI_2SFFJ(f);
	struct page *pg;

	pg = read_cache_page(inode->i_mapping, offset >> PAGE_CACHE_SHIFT,
			     (void *)jffs2_do_readpage_unlock, inode);
	if (IS_ERR(pg))
		return (void *)pg;

	*priv = (unsigned long)pg;
	return kmap(pg);
}

void jffs2_gc_release_page(struct jffs2_sb_info *c,
			   unsigned char *ptr,
			   unsigned long *priv)
{
	struct page *pg = (void *)*priv;

	kunmap(pg);
	page_cache_release(pg);
}

static int jffs2_flash_setup(struct jffs2_sb_info *c) {
	int ret = 0;

	if (jffs2_cleanmarker_oob(c)) {
		/* NAND flash... do setup accordingly */
		ret = jffs2_nand_flash_setup(c);
		if (ret)
			return ret;
	}

	/* and Dataflash */
	if (jffs2_dataflash(c)) {
		ret = jffs2_dataflash_setup(c);
		if (ret)
			return ret;
	}

	/* and Intel "Sibley" flash */
	if (jffs2_nor_wbuf_flash(c)) {
		ret = jffs2_nor_wbuf_flash_setup(c);
		if (ret)
			return ret;
	}

	/* and an UBI volume */
	if (jffs2_ubivol(c)) {
		ret = jffs2_ubivol_setup(c);
		if (ret)
			return ret;
	}

	return ret;
}

void jffs2_flash_cleanup(struct jffs2_sb_info *c) {

	if (jffs2_cleanmarker_oob(c)) {
		jffs2_nand_flash_cleanup(c);
	}

	/* and DataFlash */
	if (jffs2_dataflash(c)) {
		jffs2_dataflash_cleanup(c);
	}

	/* and Intel "Sibley" flash */
	if (jffs2_nor_wbuf_flash(c)) {
		jffs2_nor_wbuf_flash_cleanup(c);
	}

	/* and an UBI volume */
	if (jffs2_ubivol(c)) {
		jffs2_ubivol_cleanup(c);
	}
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/fs.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

// #include <linux/kernel.h>
// #include <linux/mtd/mtd.h>
// #include "nodelist.h"

int jffs2_flash_direct_writev(struct jffs2_sb_info *c, const struct kvec *vecs,
			      unsigned long count, loff_t to, size_t *retlen)
{
	if (!jffs2_is_writebuffered(c)) {
		if (jffs2_sum_active()) {
			int res;
			res = jffs2_sum_add_kvec(c, vecs, count, (uint32_t) to);
			if (res) {
				return res;
			}
		}
	}

	return mtd_writev(c->mtd, vecs, count, to, retlen);
}

int jffs2_flash_direct_write(struct jffs2_sb_info *c, loff_t ofs, size_t len,
			size_t *retlen, const u_char *buf)
{
	int ret;
	ret = mtd_write(c->mtd, ofs, len, retlen, buf);

	if (jffs2_sum_active()) {
		struct kvec vecs[1];
		int res;

		vecs[0].iov_base = (unsigned char *) buf;
		vecs[0].iov_len = len;

		res = jffs2_sum_add_kvec(c, vecs, 1, (uint32_t) ofs);
		if (res) {
			return res;
		}
	}
	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/writev.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
#include <linux/module.h>
// #include <linux/slab.h>
// #include <linux/init.h>
// #include <linux/list.h>
// #include <linux/fs.h>
#include <linux/err.h>
#include <linux/mount.h>
#include <linux/parser.h>
// #include <linux/jffs2.h>
// #include <linux/pagemap.h>
#include <linux/mtd/super.h>
#include <linux/ctype.h>
// #include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/exportfs.h>
// #include "compr.h"
// #include "nodelist.h"

static void jffs2_put_super(struct super_block *);

static struct kmem_cache *jffs2_inode_cachep;

static struct inode *jffs2_alloc_inode(struct super_block *sb)
{
	struct jffs2_inode_info *f;

	f = kmem_cache_alloc(jffs2_inode_cachep, GFP_KERNEL);
	if (!f)
		return NULL;
	return &f->vfs_inode;
}

static void jffs2_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(jffs2_inode_cachep, JFFS2_INODE_INFO(inode));
}

static void jffs2_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, jffs2_i_callback);
}

static void jffs2_i_init_once(void *foo)
{
	struct jffs2_inode_info *f = foo;

	mutex_init(&f->sem);
	inode_init_once(&f->vfs_inode);
}

static const char *jffs2_compr_name(unsigned int compr)
{
	switch (compr) {
	case JFFS2_COMPR_MODE_NONE:
		return "none";
#ifdef CONFIG_JFFS2_LZO
	case JFFS2_COMPR_MODE_FORCELZO:
		return "lzo";
#endif
#ifdef CONFIG_JFFS2_ZLIB
	case JFFS2_COMPR_MODE_FORCEZLIB:
		return "zlib";
#endif
	default:
		/* should never happen; programmer error */
		WARN_ON(1);
		return "";
	}
}

static int jffs2_show_options(struct seq_file *s, struct dentry *root)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(root->d_sb);
	struct jffs2_mount_opts *opts = &c->mount_opts;

	if (opts->override_compr)
		seq_printf(s, ",compr=%s", jffs2_compr_name(opts->compr));
	if (opts->rp_size)
		seq_printf(s, ",rp_size=%u", opts->rp_size / 1024);

	return 0;
}

static int jffs2_sync_fs(struct super_block *sb, int wait)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(sb);

#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
	cancel_delayed_work_sync(&c->wbuf_dwork);
#endif

	mutex_lock(&c->alloc_sem);
	jffs2_flush_wbuf_pad(c);
	mutex_unlock(&c->alloc_sem);
	return 0;
}

static struct inode *jffs2_nfs_get_inode(struct super_block *sb, uint64_t ino,
					 uint32_t generation)
{
	/* We don't care about i_generation. We'll destroy the flash
	   before we start re-using inode numbers anyway. And even
	   if that wasn't true, we'd have other problems...*/
	return jffs2_iget(sb, ino);
}

static struct dentry *jffs2_fh_to_dentry(struct super_block *sb, struct fid *fid,
					 int fh_len, int fh_type)
{
        return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
                                    jffs2_nfs_get_inode);
}

static struct dentry *jffs2_fh_to_parent(struct super_block *sb, struct fid *fid,
					 int fh_len, int fh_type)
{
        return generic_fh_to_parent(sb, fid, fh_len, fh_type,
                                    jffs2_nfs_get_inode);
}

static struct dentry *jffs2_get_parent(struct dentry *child)
{
	struct jffs2_inode_info *f;
	uint32_t pino;

	BUG_ON(!S_ISDIR(child->d_inode->i_mode));

	f = JFFS2_INODE_INFO(child->d_inode);

	pino = f->inocache->pino_nlink;

	JFFS2_DEBUG("Parent of directory ino #%u is #%u\n",
		    f->inocache->ino, pino);

	return d_obtain_alias(jffs2_iget(child->d_inode->i_sb, pino));
}

static const struct export_operations jffs2_export_ops = {
	.get_parent = jffs2_get_parent,
	.fh_to_dentry = jffs2_fh_to_dentry,
	.fh_to_parent = jffs2_fh_to_parent,
};

/*
 * JFFS2 mount options.
 *
 * Opt_override_compr: override default compressor
 * Opt_rp_size: size of reserved pool in KiB
 * Opt_err: just end of array marker
 */
enum {
	Opt_override_compr,
	Opt_rp_size,
	Opt_err,
};

static const match_table_t tokens = {
	{Opt_override_compr, "compr=%s"},
	{Opt_rp_size, "rp_size=%u"},
	{Opt_err, NULL},
};

static int jffs2_parse_options(struct jffs2_sb_info *c, char *data)
{
	substring_t args[MAX_OPT_ARGS];
	char *p, *name;
	unsigned int opt;

	if (!data)
		return 0;

	while ((p = strsep(&data, ","))) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_override_compr:
			name = match_strdup(&args[0]);

			if (!name)
				return -ENOMEM;
			if (!strcmp(name, "none"))
				c->mount_opts.compr = JFFS2_COMPR_MODE_NONE;
#ifdef CONFIG_JFFS2_LZO
			else if (!strcmp(name, "lzo"))
				c->mount_opts.compr = JFFS2_COMPR_MODE_FORCELZO;
#endif
#ifdef CONFIG_JFFS2_ZLIB
			else if (!strcmp(name, "zlib"))
				c->mount_opts.compr =
						JFFS2_COMPR_MODE_FORCEZLIB;
#endif
			else {
				pr_err("Error: unknown compressor \"%s\"\n",
				       name);
				kfree(name);
				return -EINVAL;
			}
			kfree(name);
			c->mount_opts.override_compr = true;
			break;
		case Opt_rp_size:
			if (match_int(&args[0], &opt))
				return -EINVAL;
			opt *= 1024;
			if (opt > c->mtd->size) {
				pr_warn("Too large reserve pool specified, max "
					"is %llu KB\n", c->mtd->size / 1024);
				return -EINVAL;
			}
			c->mount_opts.rp_size = opt;
			break;
		default:
			pr_err("Error: unrecognized mount option '%s' or missing value\n",
			       p);
			return -EINVAL;
		}
	}

	return 0;
}

static int jffs2_remount_fs(struct super_block *sb, int *flags, char *data)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(sb);
	int err;

	sync_filesystem(sb);
	err = jffs2_parse_options(c, data);
	if (err)
		return -EINVAL;

	return jffs2_do_remount_fs(sb, flags, data);
}

static const struct super_operations jffs2_super_operations =
{
	.alloc_inode =	jffs2_alloc_inode,
	.destroy_inode =jffs2_destroy_inode,
	.put_super =	jffs2_put_super,
	.statfs =	jffs2_statfs,
	.remount_fs =	jffs2_remount_fs,
	.evict_inode =	jffs2_evict_inode,
	.dirty_inode =	jffs2_dirty_inode,
	.show_options =	jffs2_show_options,
	.sync_fs =	jffs2_sync_fs,
};

/*
 * fill in the superblock
 */
static int jffs2_fill_super(struct super_block *sb, void *data, int silent)
{
	struct jffs2_sb_info *c;
	int ret;

	jffs2_dbg(1, "jffs2_get_sb_mtd():"
		  " New superblock for device %d (\"%s\")\n",
		  sb->s_mtd->index, sb->s_mtd->name);

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;

	c->mtd = sb->s_mtd;
	c->os_priv = sb;
	sb->s_fs_info = c;

	ret = jffs2_parse_options(c, data);
	if (ret) {
		kfree(c);
		return -EINVAL;
	}

	/* Initialize JFFS2 superblock locks, the further initialization will
	 * be done later */
	mutex_init(&c->alloc_sem);
	mutex_init(&c->erase_free_sem);
	init_waitqueue_head(&c->erase_wait);
	init_waitqueue_head(&c->inocache_wq);
	spin_lock_init(&c->erase_completion_lock);
	spin_lock_init(&c->inocache_lock);

	sb->s_op = &jffs2_super_operations;
	sb->s_export_op = &jffs2_export_ops;
	sb->s_flags = sb->s_flags | MS_NOATIME;
	sb->s_xattr = jffs2_xattr_handlers;
#ifdef CONFIG_JFFS2_FS_POSIX_ACL
	sb->s_flags |= MS_POSIXACL;
#endif
	ret = jffs2_do_fill_super(sb, data, silent);
	return ret;
}

static struct dentry *jffs2_mount(struct file_system_type *fs_type,
			int flags, const char *dev_name,
			void *data)
{
	return mount_mtd(fs_type, flags, dev_name, data, jffs2_fill_super);
}

static void jffs2_put_super (struct super_block *sb)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(sb);

	jffs2_dbg(2, "%s()\n", __func__);

	mutex_lock(&c->alloc_sem);
	jffs2_flush_wbuf_pad(c);
	mutex_unlock(&c->alloc_sem);

	jffs2_sum_exit(c);

	jffs2_free_ino_caches(c);
	jffs2_free_raw_node_refs(c);
	if (jffs2_blocks_use_vmalloc(c))
		vfree(c->blocks);
	else
		kfree(c->blocks);
	jffs2_flash_cleanup(c);
	kfree(c->inocache_list);
	jffs2_clear_xattr_subsystem(c);
	mtd_sync(c->mtd);
	jffs2_dbg(1, "%s(): returning\n", __func__);
}

static void jffs2_kill_sb(struct super_block *sb)
{
	struct jffs2_sb_info *c = JFFS2_SB_INFO(sb);
	if (!(sb->s_flags & MS_RDONLY))
		jffs2_stop_garbage_collect_thread(c);
	kill_mtd_super(sb);
	kfree(c);
}

static struct file_system_type jffs2_fs_type = {
	.owner =	THIS_MODULE,
	.name =		"jffs2",
	.mount =	jffs2_mount,
	.kill_sb =	jffs2_kill_sb,
};
MODULE_ALIAS_FS("jffs2");

static int __init init_jffs2_fs(void)
{
	int ret;

	/* Paranoia checks for on-medium structures. If we ask GCC
	   to pack them with __attribute__((packed)) then it _also_
	   assumes that they're not aligned -- so it emits crappy
	   code on some architectures. Ideally we want an attribute
	   which means just 'no padding', without the alignment
	   thing. But GCC doesn't have that -- we have to just
	   hope the structs are the right sizes, instead. */
	BUILD_BUG_ON(sizeof(struct jffs2_unknown_node) != 12);
	BUILD_BUG_ON(sizeof(struct jffs2_raw_dirent) != 40);
	BUILD_BUG_ON(sizeof(struct jffs2_raw_inode) != 68);
	BUILD_BUG_ON(sizeof(struct jffs2_raw_summary) != 32);

	pr_info("version 2.2."
#ifdef CONFIG_JFFS2_FS_WRITEBUFFER
	       " (NAND)"
#endif
#ifdef CONFIG_JFFS2_SUMMARY
	       " (SUMMARY) "
#endif
	       " © 2001-2006 Red Hat, Inc.\n");

	jffs2_inode_cachep = kmem_cache_create("jffs2_i",
					     sizeof(struct jffs2_inode_info),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     jffs2_i_init_once);
	if (!jffs2_inode_cachep) {
		pr_err("error: Failed to initialise inode cache\n");
		return -ENOMEM;
	}
	ret = jffs2_compressors_init();
	if (ret) {
		pr_err("error: Failed to initialise compressors\n");
		goto out;
	}
	ret = jffs2_create_slab_caches();
	if (ret) {
		pr_err("error: Failed to initialise slab caches\n");
		goto out_compressors;
	}
	ret = register_filesystem(&jffs2_fs_type);
	if (ret) {
		pr_err("error: Failed to register filesystem\n");
		goto out_slab;
	}
	return 0;

 out_slab:
	jffs2_destroy_slab_caches();
 out_compressors:
	jffs2_compressors_exit();
 out:
	kmem_cache_destroy(jffs2_inode_cachep);
	return ret;
}

static void __exit exit_jffs2_fs(void)
{
	unregister_filesystem(&jffs2_fs_type);
	jffs2_destroy_slab_caches();
	jffs2_compressors_exit();

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(jffs2_inode_cachep);
}

module_init(init_jffs2_fs);
module_exit(exit_jffs2_fs);

MODULE_DESCRIPTION("The Journalling Flash File System, v2");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL"); // Actually dual-licensed, but it doesn't matter for
		       // the sake of this tag. It's Free Software.
/************************************************************/
/* ../linux-3.17/fs/jffs2/super.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
#include <linux/types.h>
// #include <linux/pagemap.h>
// #include <linux/crc32.h>
// #include <linux/jffs2.h>
// #include <linux/mtd/mtd.h>
// #include <linux/slab.h>
// #include "nodelist.h"
// #include "debug.h"

#ifdef JFFS2_DBG_SANITY_CHECKS

void
__jffs2_dbg_acct_sanity_check_nolock(struct jffs2_sb_info *c,
				     struct jffs2_eraseblock *jeb)
{
	if (unlikely(jeb && jeb->used_size + jeb->dirty_size +
			jeb->free_size + jeb->wasted_size +
			jeb->unchecked_size != c->sector_size)) {
		JFFS2_ERROR("eeep, space accounting for block at 0x%08x is screwed.\n", jeb->offset);
		JFFS2_ERROR("free %#08x + dirty %#08x + used %#08x + wasted %#08x + unchecked %#08x != total %#08x.\n",
			jeb->free_size, jeb->dirty_size, jeb->used_size,
			jeb->wasted_size, jeb->unchecked_size, c->sector_size);
		BUG();
	}

	if (unlikely(c->used_size + c->dirty_size + c->free_size + c->erasing_size + c->bad_size
				+ c->wasted_size + c->unchecked_size != c->flash_size)) {
		JFFS2_ERROR("eeep, space accounting superblock info is screwed.\n");
		JFFS2_ERROR("free %#08x + dirty %#08x + used %#08x + erasing %#08x + bad %#08x + wasted %#08x + unchecked %#08x != total %#08x.\n",
			c->free_size, c->dirty_size, c->used_size, c->erasing_size, c->bad_size,
			c->wasted_size, c->unchecked_size, c->flash_size);
		BUG();
	}
}

void
__jffs2_dbg_acct_sanity_check(struct jffs2_sb_info *c,
			      struct jffs2_eraseblock *jeb)
{
	spin_lock(&c->erase_completion_lock);
	jffs2_dbg_acct_sanity_check_nolock(c, jeb);
	spin_unlock(&c->erase_completion_lock);
}

#endif /* JFFS2_DBG_SANITY_CHECKS */

#ifdef JFFS2_DBG_PARANOIA_CHECKS
/*
 * Check the fragtree.
 */
void
__jffs2_dbg_fragtree_paranoia_check(struct jffs2_inode_info *f)
{
	mutex_lock(&f->sem);
	__jffs2_dbg_fragtree_paranoia_check_nolock(f);
	mutex_unlock(&f->sem);
}

void
__jffs2_dbg_fragtree_paranoia_check_nolock(struct jffs2_inode_info *f)
{
	struct jffs2_node_frag *frag;
	int bitched = 0;

	for (frag = frag_first(&f->fragtree); frag; frag = frag_next(frag)) {
		struct jffs2_full_dnode *fn = frag->node;

		if (!fn || !fn->raw)
			continue;

		if (ref_flags(fn->raw) == REF_PRISTINE) {
			if (fn->frags > 1) {
				JFFS2_ERROR("REF_PRISTINE node at 0x%08x had %d frags. Tell dwmw2.\n",
					ref_offset(fn->raw), fn->frags);
				bitched = 1;
			}

			/* A hole node which isn't multi-page should be garbage-collected
			   and merged anyway, so we just check for the frag size here,
			   rather than mucking around with actually reading the node
			   and checking the compression type, which is the real way
			   to tell a hole node. */
			if (frag->ofs & (PAGE_CACHE_SIZE-1) && frag_prev(frag)
					&& frag_prev(frag)->size < PAGE_CACHE_SIZE && frag_prev(frag)->node) {
				JFFS2_ERROR("REF_PRISTINE node at 0x%08x had a previous non-hole frag in the same page. Tell dwmw2.\n",
					ref_offset(fn->raw));
				bitched = 1;
			}

			if ((frag->ofs+frag->size) & (PAGE_CACHE_SIZE-1) && frag_next(frag)
					&& frag_next(frag)->size < PAGE_CACHE_SIZE && frag_next(frag)->node) {
				JFFS2_ERROR("REF_PRISTINE node at 0x%08x (%08x-%08x) had a following non-hole frag in the same page. Tell dwmw2.\n",
				       ref_offset(fn->raw), frag->ofs, frag->ofs+frag->size);
				bitched = 1;
			}
		}
	}

	if (bitched) {
		JFFS2_ERROR("fragtree is corrupted.\n");
		__jffs2_dbg_dump_fragtree_nolock(f);
		BUG();
	}
}

/*
 * Check if the flash contains all 0xFF before we start writing.
 */
void
__jffs2_dbg_prewrite_paranoia_check(struct jffs2_sb_info *c,
				    uint32_t ofs, int len)
{
	size_t retlen;
	int ret, i;
	unsigned char *buf;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return;

	ret = jffs2_flash_read(c, ofs, len, &retlen, buf);
	if (ret || (retlen != len)) {
		JFFS2_WARNING("read %d bytes failed or short. ret %d, retlen %zd.\n",
				len, ret, retlen);
		kfree(buf);
		return;
	}

	ret = 0;
	for (i = 0; i < len; i++)
		if (buf[i] != 0xff)
			ret = 1;

	if (ret) {
		JFFS2_ERROR("argh, about to write node to %#08x on flash, but there are data already there. The first corrupted byte is at %#08x offset.\n",
			ofs, ofs + i);
		__jffs2_dbg_dump_buffer(buf, len, ofs);
		kfree(buf);
		BUG();
	}

	kfree(buf);
}

void __jffs2_dbg_superblock_counts(struct jffs2_sb_info *c)
{
	struct jffs2_eraseblock *jeb;
	uint32_t free = 0, dirty = 0, used = 0, wasted = 0,
		erasing = 0, bad = 0, unchecked = 0;
	int nr_counted = 0;
	int dump = 0;

	if (c->gcblock) {
		nr_counted++;
		free += c->gcblock->free_size;
		dirty += c->gcblock->dirty_size;
		used += c->gcblock->used_size;
		wasted += c->gcblock->wasted_size;
		unchecked += c->gcblock->unchecked_size;
	}
	if (c->nextblock) {
		nr_counted++;
		free += c->nextblock->free_size;
		dirty += c->nextblock->dirty_size;
		used += c->nextblock->used_size;
		wasted += c->nextblock->wasted_size;
		unchecked += c->nextblock->unchecked_size;
	}
	list_for_each_entry(jeb, &c->clean_list, list) {
		nr_counted++;
		free += jeb->free_size;
		dirty += jeb->dirty_size;
		used += jeb->used_size;
		wasted += jeb->wasted_size;
		unchecked += jeb->unchecked_size;
	}
	list_for_each_entry(jeb, &c->very_dirty_list, list) {
		nr_counted++;
		free += jeb->free_size;
		dirty += jeb->dirty_size;
		used += jeb->used_size;
		wasted += jeb->wasted_size;
		unchecked += jeb->unchecked_size;
	}
	list_for_each_entry(jeb, &c->dirty_list, list) {
		nr_counted++;
		free += jeb->free_size;
		dirty += jeb->dirty_size;
		used += jeb->used_size;
		wasted += jeb->wasted_size;
		unchecked += jeb->unchecked_size;
	}
	list_for_each_entry(jeb, &c->erasable_list, list) {
		nr_counted++;
		free += jeb->free_size;
		dirty += jeb->dirty_size;
		used += jeb->used_size;
		wasted += jeb->wasted_size;
		unchecked += jeb->unchecked_size;
	}
	list_for_each_entry(jeb, &c->erasable_pending_wbuf_list, list) {
		nr_counted++;
		free += jeb->free_size;
		dirty += jeb->dirty_size;
		used += jeb->used_size;
		wasted += jeb->wasted_size;
		unchecked += jeb->unchecked_size;
	}
	list_for_each_entry(jeb, &c->erase_pending_list, list) {
		nr_counted++;
		free += jeb->free_size;
		dirty += jeb->dirty_size;
		used += jeb->used_size;
		wasted += jeb->wasted_size;
		unchecked += jeb->unchecked_size;
	}
	list_for_each_entry(jeb, &c->free_list, list) {
		nr_counted++;
		free += jeb->free_size;
		dirty += jeb->dirty_size;
		used += jeb->used_size;
		wasted += jeb->wasted_size;
		unchecked += jeb->unchecked_size;
	}
	list_for_each_entry(jeb, &c->bad_used_list, list) {
		nr_counted++;
		free += jeb->free_size;
		dirty += jeb->dirty_size;
		used += jeb->used_size;
		wasted += jeb->wasted_size;
		unchecked += jeb->unchecked_size;
	}

	list_for_each_entry(jeb, &c->erasing_list, list) {
		nr_counted++;
		erasing += c->sector_size;
	}
	list_for_each_entry(jeb, &c->erase_checking_list, list) {
		nr_counted++;
		erasing += c->sector_size;
	}
	list_for_each_entry(jeb, &c->erase_complete_list, list) {
		nr_counted++;
		erasing += c->sector_size;
	}
	list_for_each_entry(jeb, &c->bad_list, list) {
		nr_counted++;
		bad += c->sector_size;
	}

#define check(sz)							\
do {									\
	if (sz != c->sz##_size) {					\
		pr_warn("%s_size mismatch counted 0x%x, c->%s_size 0x%x\n", \
			#sz, sz, #sz, c->sz##_size);			\
		dump = 1;						\
	}								\
} while (0)

	check(free);
	check(dirty);
	check(used);
	check(wasted);
	check(unchecked);
	check(bad);
	check(erasing);

#undef check

	if (nr_counted != c->nr_blocks) {
		pr_warn("%s counted only 0x%x blocks of 0x%x. Where are the others?\n",
			__func__, nr_counted, c->nr_blocks);
		dump = 1;
	}

	if (dump) {
		__jffs2_dbg_dump_block_lists_nolock(c);
		BUG();
	}
}

/*
 * Check the space accounting and node_ref list correctness for the JFFS2 erasable block 'jeb'.
 */
void
__jffs2_dbg_acct_paranoia_check(struct jffs2_sb_info *c,
				struct jffs2_eraseblock *jeb)
{
	spin_lock(&c->erase_completion_lock);
	__jffs2_dbg_acct_paranoia_check_nolock(c, jeb);
	spin_unlock(&c->erase_completion_lock);
}

void
__jffs2_dbg_acct_paranoia_check_nolock(struct jffs2_sb_info *c,
				       struct jffs2_eraseblock *jeb)
{
	uint32_t my_used_size = 0;
	uint32_t my_unchecked_size = 0;
	uint32_t my_dirty_size = 0;
	struct jffs2_raw_node_ref *ref2 = jeb->first_node;

	while (ref2) {
		uint32_t totlen = ref_totlen(c, jeb, ref2);

		if (ref_offset(ref2) < jeb->offset ||
				ref_offset(ref2) > jeb->offset + c->sector_size) {
			JFFS2_ERROR("node_ref %#08x shouldn't be in block at %#08x.\n",
				ref_offset(ref2), jeb->offset);
			goto error;

		}
		if (ref_flags(ref2) == REF_UNCHECKED)
			my_unchecked_size += totlen;
		else if (!ref_obsolete(ref2))
			my_used_size += totlen;
		else
			my_dirty_size += totlen;

		if ((!ref_next(ref2)) != (ref2 == jeb->last_node)) {
			JFFS2_ERROR("node_ref for node at %#08x (mem %p) has next at %#08x (mem %p), last_node is at %#08x (mem %p).\n",
				    ref_offset(ref2), ref2, ref_offset(ref_next(ref2)), ref_next(ref2),
				    ref_offset(jeb->last_node), jeb->last_node);
			goto error;
		}
		ref2 = ref_next(ref2);
	}

	if (my_used_size != jeb->used_size) {
		JFFS2_ERROR("Calculated used size %#08x != stored used size %#08x.\n",
			my_used_size, jeb->used_size);
		goto error;
	}

	if (my_unchecked_size != jeb->unchecked_size) {
		JFFS2_ERROR("Calculated unchecked size %#08x != stored unchecked size %#08x.\n",
			my_unchecked_size, jeb->unchecked_size);
		goto error;
	}

#if 0
	/* This should work when we implement ref->__totlen elemination */
	if (my_dirty_size != jeb->dirty_size + jeb->wasted_size) {
		JFFS2_ERROR("Calculated dirty+wasted size %#08x != stored dirty + wasted size %#08x\n",
			my_dirty_size, jeb->dirty_size + jeb->wasted_size);
		goto error;
	}

	if (jeb->free_size == 0
		&& my_used_size + my_unchecked_size + my_dirty_size != c->sector_size) {
		JFFS2_ERROR("The sum of all nodes in block (%#x) != size of block (%#x)\n",
			my_used_size + my_unchecked_size + my_dirty_size,
			c->sector_size);
		goto error;
	}
#endif

	if (!(c->flags & (JFFS2_SB_FLAG_BUILDING|JFFS2_SB_FLAG_SCANNING)))
		__jffs2_dbg_superblock_counts(c);

	return;

error:
	__jffs2_dbg_dump_node_refs_nolock(c, jeb);
	__jffs2_dbg_dump_jeb_nolock(jeb);
	__jffs2_dbg_dump_block_lists_nolock(c);
	BUG();

}
#endif /* JFFS2_DBG_PARANOIA_CHECKS */

#if defined(JFFS2_DBG_DUMPS) || defined(JFFS2_DBG_PARANOIA_CHECKS)
/*
 * Dump the node_refs of the 'jeb' JFFS2 eraseblock.
 */
void
__jffs2_dbg_dump_node_refs(struct jffs2_sb_info *c,
			   struct jffs2_eraseblock *jeb)
{
	spin_lock(&c->erase_completion_lock);
	__jffs2_dbg_dump_node_refs_nolock(c, jeb);
	spin_unlock(&c->erase_completion_lock);
}

void
__jffs2_dbg_dump_node_refs_nolock(struct jffs2_sb_info *c,
				  struct jffs2_eraseblock *jeb)
{
	struct jffs2_raw_node_ref *ref;
	int i = 0;

	printk(JFFS2_DBG_MSG_PREFIX " Dump node_refs of the eraseblock %#08x\n", jeb->offset);
	if (!jeb->first_node) {
		printk(JFFS2_DBG_MSG_PREFIX " no nodes in the eraseblock %#08x\n", jeb->offset);
		return;
	}

	printk(JFFS2_DBG);
	for (ref = jeb->first_node; ; ref = ref_next(ref)) {
		printk("%#08x", ref_offset(ref));
#ifdef TEST_TOTLEN
		printk("(%x)", ref->__totlen);
#endif
		if (ref_next(ref))
			printk("->");
		else
			break;
		if (++i == 4) {
			i = 0;
			printk("\n" JFFS2_DBG);
		}
	}
	printk("\n");
}

/*
 * Dump an eraseblock's space accounting.
 */
void
__jffs2_dbg_dump_jeb(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb)
{
	spin_lock(&c->erase_completion_lock);
	__jffs2_dbg_dump_jeb_nolock(jeb);
	spin_unlock(&c->erase_completion_lock);
}

void
__jffs2_dbg_dump_jeb_nolock(struct jffs2_eraseblock *jeb)
{
	if (!jeb)
		return;

	printk(JFFS2_DBG_MSG_PREFIX " dump space accounting for the eraseblock at %#08x:\n",
			jeb->offset);

	printk(JFFS2_DBG "used_size: %#08x\n",		jeb->used_size);
	printk(JFFS2_DBG "dirty_size: %#08x\n",		jeb->dirty_size);
	printk(JFFS2_DBG "wasted_size: %#08x\n",	jeb->wasted_size);
	printk(JFFS2_DBG "unchecked_size: %#08x\n",	jeb->unchecked_size);
	printk(JFFS2_DBG "free_size: %#08x\n",		jeb->free_size);
}

void
__jffs2_dbg_dump_block_lists(struct jffs2_sb_info *c)
{
	spin_lock(&c->erase_completion_lock);
	__jffs2_dbg_dump_block_lists_nolock(c);
	spin_unlock(&c->erase_completion_lock);
}

void
__jffs2_dbg_dump_block_lists_nolock(struct jffs2_sb_info *c)
{
	printk(JFFS2_DBG_MSG_PREFIX " dump JFFS2 blocks lists:\n");

	printk(JFFS2_DBG "flash_size: %#08x\n",		c->flash_size);
	printk(JFFS2_DBG "used_size: %#08x\n",		c->used_size);
	printk(JFFS2_DBG "dirty_size: %#08x\n",		c->dirty_size);
	printk(JFFS2_DBG "wasted_size: %#08x\n",	c->wasted_size);
	printk(JFFS2_DBG "unchecked_size: %#08x\n",	c->unchecked_size);
	printk(JFFS2_DBG "free_size: %#08x\n",		c->free_size);
	printk(JFFS2_DBG "erasing_size: %#08x\n",	c->erasing_size);
	printk(JFFS2_DBG "bad_size: %#08x\n",		c->bad_size);
	printk(JFFS2_DBG "sector_size: %#08x\n",	c->sector_size);
	printk(JFFS2_DBG "jffs2_reserved_blocks size: %#08x\n",
				c->sector_size * c->resv_blocks_write);

	if (c->nextblock)
		printk(JFFS2_DBG "nextblock: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
			c->nextblock->offset, c->nextblock->used_size,
			c->nextblock->dirty_size, c->nextblock->wasted_size,
			c->nextblock->unchecked_size, c->nextblock->free_size);
	else
		printk(JFFS2_DBG "nextblock: NULL\n");

	if (c->gcblock)
		printk(JFFS2_DBG "gcblock: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
			c->gcblock->offset, c->gcblock->used_size, c->gcblock->dirty_size,
			c->gcblock->wasted_size, c->gcblock->unchecked_size, c->gcblock->free_size);
	else
		printk(JFFS2_DBG "gcblock: NULL\n");

	if (list_empty(&c->clean_list)) {
		printk(JFFS2_DBG "clean_list: empty\n");
	} else {
		struct list_head *this;
		int numblocks = 0;
		uint32_t dirty = 0;

		list_for_each(this, &c->clean_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);
			numblocks ++;
			dirty += jeb->wasted_size;
			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "clean_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}

		printk (JFFS2_DBG "Contains %d blocks with total wasted size %u, average wasted size: %u\n",
			numblocks, dirty, dirty / numblocks);
	}

	if (list_empty(&c->very_dirty_list)) {
		printk(JFFS2_DBG "very_dirty_list: empty\n");
	} else {
		struct list_head *this;
		int numblocks = 0;
		uint32_t dirty = 0;

		list_for_each(this, &c->very_dirty_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			numblocks ++;
			dirty += jeb->dirty_size;
			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "very_dirty_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}

		printk (JFFS2_DBG "Contains %d blocks with total dirty size %u, average dirty size: %u\n",
			numblocks, dirty, dirty / numblocks);
	}

	if (list_empty(&c->dirty_list)) {
		printk(JFFS2_DBG "dirty_list: empty\n");
	} else {
		struct list_head *this;
		int numblocks = 0;
		uint32_t dirty = 0;

		list_for_each(this, &c->dirty_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			numblocks ++;
			dirty += jeb->dirty_size;
			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "dirty_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}

		printk (JFFS2_DBG "contains %d blocks with total dirty size %u, average dirty size: %u\n",
			numblocks, dirty, dirty / numblocks);
	}

	if (list_empty(&c->erasable_list)) {
		printk(JFFS2_DBG "erasable_list: empty\n");
	} else {
		struct list_head *this;

		list_for_each(this, &c->erasable_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "erasable_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}
	}

	if (list_empty(&c->erasing_list)) {
		printk(JFFS2_DBG "erasing_list: empty\n");
	} else {
		struct list_head *this;

		list_for_each(this, &c->erasing_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "erasing_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}
	}
	if (list_empty(&c->erase_checking_list)) {
		printk(JFFS2_DBG "erase_checking_list: empty\n");
	} else {
		struct list_head *this;

		list_for_each(this, &c->erase_checking_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "erase_checking_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}
	}

	if (list_empty(&c->erase_pending_list)) {
		printk(JFFS2_DBG "erase_pending_list: empty\n");
	} else {
		struct list_head *this;

		list_for_each(this, &c->erase_pending_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "erase_pending_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}
	}

	if (list_empty(&c->erasable_pending_wbuf_list)) {
		printk(JFFS2_DBG "erasable_pending_wbuf_list: empty\n");
	} else {
		struct list_head *this;

		list_for_each(this, &c->erasable_pending_wbuf_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "erasable_pending_wbuf_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}
	}

	if (list_empty(&c->free_list)) {
		printk(JFFS2_DBG "free_list: empty\n");
	} else {
		struct list_head *this;

		list_for_each(this, &c->free_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "free_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}
	}

	if (list_empty(&c->bad_list)) {
		printk(JFFS2_DBG "bad_list: empty\n");
	} else {
		struct list_head *this;

		list_for_each(this, &c->bad_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "bad_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}
	}

	if (list_empty(&c->bad_used_list)) {
		printk(JFFS2_DBG "bad_used_list: empty\n");
	} else {
		struct list_head *this;

		list_for_each(this, &c->bad_used_list) {
			struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

			if (!(jeb->used_size == 0 && jeb->dirty_size == 0 && jeb->wasted_size == 0)) {
				printk(JFFS2_DBG "bad_used_list: %#08x (used %#08x, dirty %#08x, wasted %#08x, unchecked %#08x, free %#08x)\n",
					jeb->offset, jeb->used_size, jeb->dirty_size, jeb->wasted_size,
					jeb->unchecked_size, jeb->free_size);
			}
		}
	}
}

void
__jffs2_dbg_dump_fragtree(struct jffs2_inode_info *f)
{
	mutex_lock(&f->sem);
	jffs2_dbg_dump_fragtree_nolock(f);
	mutex_unlock(&f->sem);
}

void
__jffs2_dbg_dump_fragtree_nolock(struct jffs2_inode_info *f)
{
	struct jffs2_node_frag *this = frag_first(&f->fragtree);
	uint32_t lastofs = 0;
	int buggy = 0;

	printk(JFFS2_DBG_MSG_PREFIX " dump fragtree of ino #%u\n", f->inocache->ino);
	while(this) {
		if (this->node)
			printk(JFFS2_DBG "frag %#04x-%#04x: %#08x(%d) on flash (*%p), left (%p), right (%p), parent (%p)\n",
				this->ofs, this->ofs+this->size, ref_offset(this->node->raw),
				ref_flags(this->node->raw), this, frag_left(this), frag_right(this),
				frag_parent(this));
		else
			printk(JFFS2_DBG "frag %#04x-%#04x: hole (*%p). left (%p), right (%p), parent (%p)\n",
				this->ofs, this->ofs+this->size, this, frag_left(this),
				frag_right(this), frag_parent(this));
		if (this->ofs != lastofs)
			buggy = 1;
		lastofs = this->ofs + this->size;
		this = frag_next(this);
	}

	if (f->metadata)
		printk(JFFS2_DBG "metadata at 0x%08x\n", ref_offset(f->metadata->raw));

	if (buggy) {
		JFFS2_ERROR("frag tree got a hole in it.\n");
		BUG();
	}
}

#define JFFS2_BUFDUMP_BYTES_PER_LINE	32
void
__jffs2_dbg_dump_buffer(unsigned char *buf, int len, uint32_t offs)
{
	int skip;
	int i;

	printk(JFFS2_DBG_MSG_PREFIX " dump from offset %#08x to offset %#08x (%x bytes).\n",
		offs, offs + len, len);
	i = skip = offs % JFFS2_BUFDUMP_BYTES_PER_LINE;
	offs = offs & ~(JFFS2_BUFDUMP_BYTES_PER_LINE - 1);

	if (skip != 0)
		printk(JFFS2_DBG "%#08x: ", offs);

	while (skip--)
		printk("   ");

	while (i < len) {
		if ((i % JFFS2_BUFDUMP_BYTES_PER_LINE) == 0 && i != len -1) {
			if (i != 0)
				printk("\n");
			offs += JFFS2_BUFDUMP_BYTES_PER_LINE;
			printk(JFFS2_DBG "%0#8x: ", offs);
		}

		printk("%02x ", buf[i]);

		i += 1;
	}

	printk("\n");
}

/*
 * Dump a JFFS2 node.
 */
void
__jffs2_dbg_dump_node(struct jffs2_sb_info *c, uint32_t ofs)
{
	union jffs2_node_union node;
	int len = sizeof(union jffs2_node_union);
	size_t retlen;
	uint32_t crc;
	int ret;

	printk(JFFS2_DBG_MSG_PREFIX " dump node at offset %#08x.\n", ofs);

	ret = jffs2_flash_read(c, ofs, len, &retlen, (unsigned char *)&node);
	if (ret || (retlen != len)) {
		JFFS2_ERROR("read %d bytes failed or short. ret %d, retlen %zd.\n",
			len, ret, retlen);
		return;
	}

	printk(JFFS2_DBG "magic:\t%#04x\n", je16_to_cpu(node.u.magic));
	printk(JFFS2_DBG "nodetype:\t%#04x\n", je16_to_cpu(node.u.nodetype));
	printk(JFFS2_DBG "totlen:\t%#08x\n", je32_to_cpu(node.u.totlen));
	printk(JFFS2_DBG "hdr_crc:\t%#08x\n", je32_to_cpu(node.u.hdr_crc));

	crc = crc32(0, &node.u, sizeof(node.u) - 4);
	if (crc != je32_to_cpu(node.u.hdr_crc)) {
		JFFS2_ERROR("wrong common header CRC.\n");
		return;
	}

	if (je16_to_cpu(node.u.magic) != JFFS2_MAGIC_BITMASK &&
		je16_to_cpu(node.u.magic) != JFFS2_OLD_MAGIC_BITMASK)
	{
		JFFS2_ERROR("wrong node magic: %#04x instead of %#04x.\n",
			je16_to_cpu(node.u.magic), JFFS2_MAGIC_BITMASK);
		return;
	}

	switch(je16_to_cpu(node.u.nodetype)) {

	case JFFS2_NODETYPE_INODE:

		printk(JFFS2_DBG "the node is inode node\n");
		printk(JFFS2_DBG "ino:\t%#08x\n", je32_to_cpu(node.i.ino));
		printk(JFFS2_DBG "version:\t%#08x\n", je32_to_cpu(node.i.version));
		printk(JFFS2_DBG "mode:\t%#08x\n", node.i.mode.m);
		printk(JFFS2_DBG "uid:\t%#04x\n", je16_to_cpu(node.i.uid));
		printk(JFFS2_DBG "gid:\t%#04x\n", je16_to_cpu(node.i.gid));
		printk(JFFS2_DBG "isize:\t%#08x\n", je32_to_cpu(node.i.isize));
		printk(JFFS2_DBG "atime:\t%#08x\n", je32_to_cpu(node.i.atime));
		printk(JFFS2_DBG "mtime:\t%#08x\n", je32_to_cpu(node.i.mtime));
		printk(JFFS2_DBG "ctime:\t%#08x\n", je32_to_cpu(node.i.ctime));
		printk(JFFS2_DBG "offset:\t%#08x\n", je32_to_cpu(node.i.offset));
		printk(JFFS2_DBG "csize:\t%#08x\n", je32_to_cpu(node.i.csize));
		printk(JFFS2_DBG "dsize:\t%#08x\n", je32_to_cpu(node.i.dsize));
		printk(JFFS2_DBG "compr:\t%#02x\n", node.i.compr);
		printk(JFFS2_DBG "usercompr:\t%#02x\n", node.i.usercompr);
		printk(JFFS2_DBG "flags:\t%#04x\n", je16_to_cpu(node.i.flags));
		printk(JFFS2_DBG "data_crc:\t%#08x\n", je32_to_cpu(node.i.data_crc));
		printk(JFFS2_DBG "node_crc:\t%#08x\n", je32_to_cpu(node.i.node_crc));

		crc = crc32(0, &node.i, sizeof(node.i) - 8);
		if (crc != je32_to_cpu(node.i.node_crc)) {
			JFFS2_ERROR("wrong node header CRC.\n");
			return;
		}
		break;

	case JFFS2_NODETYPE_DIRENT:

		printk(JFFS2_DBG "the node is dirent node\n");
		printk(JFFS2_DBG "pino:\t%#08x\n", je32_to_cpu(node.d.pino));
		printk(JFFS2_DBG "version:\t%#08x\n", je32_to_cpu(node.d.version));
		printk(JFFS2_DBG "ino:\t%#08x\n", je32_to_cpu(node.d.ino));
		printk(JFFS2_DBG "mctime:\t%#08x\n", je32_to_cpu(node.d.mctime));
		printk(JFFS2_DBG "nsize:\t%#02x\n", node.d.nsize);
		printk(JFFS2_DBG "type:\t%#02x\n", node.d.type);
		printk(JFFS2_DBG "node_crc:\t%#08x\n", je32_to_cpu(node.d.node_crc));
		printk(JFFS2_DBG "name_crc:\t%#08x\n", je32_to_cpu(node.d.name_crc));

		node.d.name[node.d.nsize] = '\0';
		printk(JFFS2_DBG "name:\t\"%s\"\n", node.d.name);

		crc = crc32(0, &node.d, sizeof(node.d) - 8);
		if (crc != je32_to_cpu(node.d.node_crc)) {
			JFFS2_ERROR("wrong node header CRC.\n");
			return;
		}
		break;

	default:
		printk(JFFS2_DBG "node type is unknown\n");
		break;
	}
}
#endif /* JFFS2_DBG_DUMPS || JFFS2_DBG_PARANOIA_CHECKS */
/************************************************************/
/* ../linux-3.17/fs/jffs2/debug.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004 Thomas Gleixner <tglx@linutronix.de>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 * Modified debugged and enhanced by Thomas Gleixner <tglx@linutronix.de>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
// #include <linux/slab.h>
// #include <linux/mtd/mtd.h>
// #include <linux/crc32.h>
#include <linux/mtd/nand.h>
#include <linux/jiffies.h>
// #include <linux/sched.h>
#include <linux/writeback.h>

// #include "nodelist.h"

/* For testing write failures */
#undef BREAKME
#undef BREAKMEHEADER

#ifdef BREAKME
static unsigned char *brokenbuf;
#endif

#define PAGE_DIV(x) ( ((unsigned long)(x) / (unsigned long)(c->wbuf_pagesize)) * (unsigned long)(c->wbuf_pagesize) )
#define PAGE_MOD(x) ( (unsigned long)(x) % (unsigned long)(c->wbuf_pagesize) )

/* max. erase failures before we mark a block bad */
#define MAX_ERASE_FAILURES 	2

struct jffs2_inodirty {
	uint32_t ino;
	struct jffs2_inodirty *next;
};

static struct jffs2_inodirty inodirty_nomem;

static int jffs2_wbuf_pending_for_ino(struct jffs2_sb_info *c, uint32_t ino)
{
	struct jffs2_inodirty *this = c->wbuf_inodes;

	/* If a malloc failed, consider _everything_ dirty */
	if (this == &inodirty_nomem)
		return 1;

	/* If ino == 0, _any_ non-GC writes mean 'yes' */
	if (this && !ino)
		return 1;

	/* Look to see if the inode in question is pending in the wbuf */
	while (this) {
		if (this->ino == ino)
			return 1;
		this = this->next;
	}
	return 0;
}

static void jffs2_clear_wbuf_ino_list(struct jffs2_sb_info *c)
{
	struct jffs2_inodirty *this;

	this = c->wbuf_inodes;

	if (this != &inodirty_nomem) {
		while (this) {
			struct jffs2_inodirty *next = this->next;
			kfree(this);
			this = next;
		}
	}
	c->wbuf_inodes = NULL;
}

static void jffs2_wbuf_dirties_inode(struct jffs2_sb_info *c, uint32_t ino)
{
	struct jffs2_inodirty *new;

	/* Schedule delayed write-buffer write-out */
	jffs2_dirty_trigger(c);

	if (jffs2_wbuf_pending_for_ino(c, ino))
		return;

	new = kmalloc(sizeof(*new), GFP_KERNEL);
	if (!new) {
		jffs2_dbg(1, "No memory to allocate inodirty. Fallback to all considered dirty\n");
		jffs2_clear_wbuf_ino_list(c);
		c->wbuf_inodes = &inodirty_nomem;
		return;
	}
	new->ino = ino;
	new->next = c->wbuf_inodes;
	c->wbuf_inodes = new;
	return;
}

static inline void jffs2_refile_wbuf_blocks(struct jffs2_sb_info *c)
{
	struct list_head *this, *next;
	static int n;

	if (list_empty(&c->erasable_pending_wbuf_list))
		return;

	list_for_each_safe(this, next, &c->erasable_pending_wbuf_list) {
		struct jffs2_eraseblock *jeb = list_entry(this, struct jffs2_eraseblock, list);

		jffs2_dbg(1, "Removing eraseblock at 0x%08x from erasable_pending_wbuf_list...\n",
			  jeb->offset);
		list_del(this);
		if ((jiffies + (n++)) & 127) {
			/* Most of the time, we just erase it immediately. Otherwise we
			   spend ages scanning it on mount, etc. */
			jffs2_dbg(1, "...and adding to erase_pending_list\n");
			list_add_tail(&jeb->list, &c->erase_pending_list);
			c->nr_erasing_blocks++;
			jffs2_garbage_collect_trigger(c);
		} else {
			/* Sometimes, however, we leave it elsewhere so it doesn't get
			   immediately reused, and we spread the load a bit. */
			jffs2_dbg(1, "...and adding to erasable_list\n");
			list_add_tail(&jeb->list, &c->erasable_list);
		}
	}
}

#define REFILE_NOTEMPTY 0
#define REFILE_ANYWAY   1

static void jffs2_block_refile(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb, int allow_empty)
{
	jffs2_dbg(1, "About to refile bad block at %08x\n", jeb->offset);

	/* File the existing block on the bad_used_list.... */
	if (c->nextblock == jeb)
		c->nextblock = NULL;
	else /* Not sure this should ever happen... need more coffee */
		list_del(&jeb->list);
	if (jeb->first_node) {
		jffs2_dbg(1, "Refiling block at %08x to bad_used_list\n",
			  jeb->offset);
		list_add(&jeb->list, &c->bad_used_list);
	} else {
		BUG_ON(allow_empty == REFILE_NOTEMPTY);
		/* It has to have had some nodes or we couldn't be here */
		jffs2_dbg(1, "Refiling block at %08x to erase_pending_list\n",
			  jeb->offset);
		list_add(&jeb->list, &c->erase_pending_list);
		c->nr_erasing_blocks++;
		jffs2_garbage_collect_trigger(c);
	}

	if (!jffs2_prealloc_raw_node_refs(c, jeb, 1)) {
		uint32_t oldfree = jeb->free_size;

		jffs2_link_node_ref(c, jeb,
				    (jeb->offset+c->sector_size-oldfree) | REF_OBSOLETE,
				    oldfree, NULL);
		/* convert to wasted */
		c->wasted_size += oldfree;
		jeb->wasted_size += oldfree;
		c->dirty_size -= oldfree;
		jeb->dirty_size -= oldfree;
	}

	jffs2_dbg_dump_block_lists_nolock(c);
	jffs2_dbg_acct_sanity_check_nolock(c,jeb);
	jffs2_dbg_acct_paranoia_check_nolock(c, jeb);
}

static struct jffs2_raw_node_ref **jffs2_incore_replace_raw(struct jffs2_sb_info *c,
							    struct jffs2_inode_info *f,
							    struct jffs2_raw_node_ref *raw,
							    union jffs2_node_union *node)
{
	struct jffs2_node_frag *frag;
	struct jffs2_full_dirent *fd;

	dbg_noderef("incore_replace_raw: node at %p is {%04x,%04x}\n",
		    node, je16_to_cpu(node->u.magic), je16_to_cpu(node->u.nodetype));

	BUG_ON(je16_to_cpu(node->u.magic) != 0x1985 &&
	       je16_to_cpu(node->u.magic) != 0);

	switch (je16_to_cpu(node->u.nodetype)) {
	case JFFS2_NODETYPE_INODE:
		if (f->metadata && f->metadata->raw == raw) {
			dbg_noderef("Will replace ->raw in f->metadata at %p\n", f->metadata);
			return &f->metadata->raw;
		}
		frag = jffs2_lookup_node_frag(&f->fragtree, je32_to_cpu(node->i.offset));
		BUG_ON(!frag);
		/* Find a frag which refers to the full_dnode we want to modify */
		while (!frag->node || frag->node->raw != raw) {
			frag = frag_next(frag);
			BUG_ON(!frag);
		}
		dbg_noderef("Will replace ->raw in full_dnode at %p\n", frag->node);
		return &frag->node->raw;

	case JFFS2_NODETYPE_DIRENT:
		for (fd = f->dents; fd; fd = fd->next) {
			if (fd->raw == raw) {
				dbg_noderef("Will replace ->raw in full_dirent at %p\n", fd);
				return &fd->raw;
			}
		}
		BUG();

	default:
		dbg_noderef("Don't care about replacing raw for nodetype %x\n",
			    je16_to_cpu(node->u.nodetype));
		break;
	}
	return NULL;
}

#ifdef CONFIG_JFFS2_FS_WBUF_VERIFY
static int jffs2_verify_write(struct jffs2_sb_info *c, unsigned char *buf,
			      uint32_t ofs)
{
	int ret;
	size_t retlen;
	char *eccstr;

	ret = mtd_read(c->mtd, ofs, c->wbuf_pagesize, &retlen, c->wbuf_verify);
	if (ret && ret != -EUCLEAN && ret != -EBADMSG) {
		pr_warn("%s(): Read back of page at %08x failed: %d\n",
			__func__, c->wbuf_ofs, ret);
		return ret;
	} else if (retlen != c->wbuf_pagesize) {
		pr_warn("%s(): Read back of page at %08x gave short read: %zd not %d\n",
			__func__, ofs, retlen, c->wbuf_pagesize);
		return -EIO;
	}
	if (!memcmp(buf, c->wbuf_verify, c->wbuf_pagesize))
		return 0;

	if (ret == -EUCLEAN)
		eccstr = "corrected";
	else if (ret == -EBADMSG)
		eccstr = "correction failed";
	else
		eccstr = "OK or unused";

	pr_warn("Write verify error (ECC %s) at %08x. Wrote:\n",
		eccstr, c->wbuf_ofs);
	print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_OFFSET, 16, 1,
		       c->wbuf, c->wbuf_pagesize, 0);

	pr_warn("Read back:\n");
	print_hex_dump(KERN_WARNING, "", DUMP_PREFIX_OFFSET, 16, 1,
		       c->wbuf_verify, c->wbuf_pagesize, 0);

	return -EIO;
}
#else
#define jffs2_verify_write(c,b,o) (0)
#endif

/* Recover from failure to write wbuf. Recover the nodes up to the
 * wbuf, not the one which we were starting to try to write. */

static void jffs2_wbuf_recover(struct jffs2_sb_info *c)
{
	struct jffs2_eraseblock *jeb, *new_jeb;
	struct jffs2_raw_node_ref *raw, *next, *first_raw = NULL;
	size_t retlen;
	int ret;
	int nr_refile = 0;
	unsigned char *buf;
	uint32_t start, end, ofs, len;

	jeb = &c->blocks[c->wbuf_ofs / c->sector_size];

	spin_lock(&c->erase_completion_lock);
	if (c->wbuf_ofs % c->mtd->erasesize)
		jffs2_block_refile(c, jeb, REFILE_NOTEMPTY);
	else
		jffs2_block_refile(c, jeb, REFILE_ANYWAY);
	spin_unlock(&c->erase_completion_lock);

	BUG_ON(!ref_obsolete(jeb->last_node));

	/* Find the first node to be recovered, by skipping over every
	   node which ends before the wbuf starts, or which is obsolete. */
	for (next = raw = jeb->first_node; next; raw = next) {
		next = ref_next(raw);

		if (ref_obsolete(raw) ||
		    (next && ref_offset(next) <= c->wbuf_ofs)) {
			dbg_noderef("Skipping node at 0x%08x(%d)-0x%08x which is either before 0x%08x or obsolete\n",
				    ref_offset(raw), ref_flags(raw),
				    (ref_offset(raw) + ref_totlen(c, jeb, raw)),
				    c->wbuf_ofs);
			continue;
		}
		dbg_noderef("First node to be recovered is at 0x%08x(%d)-0x%08x\n",
			    ref_offset(raw), ref_flags(raw),
			    (ref_offset(raw) + ref_totlen(c, jeb, raw)));

		first_raw = raw;
		break;
	}

	if (!first_raw) {
		/* All nodes were obsolete. Nothing to recover. */
		jffs2_dbg(1, "No non-obsolete nodes to be recovered. Just filing block bad\n");
		c->wbuf_len = 0;
		return;
	}

	start = ref_offset(first_raw);
	end = ref_offset(jeb->last_node);
	nr_refile = 1;

	/* Count the number of refs which need to be copied */
	while ((raw = ref_next(raw)) != jeb->last_node)
		nr_refile++;

	dbg_noderef("wbuf recover %08x-%08x (%d bytes in %d nodes)\n",
		    start, end, end - start, nr_refile);

	buf = NULL;
	if (start < c->wbuf_ofs) {
		/* First affected node was already partially written.
		 * Attempt to reread the old data into our buffer. */

		buf = kmalloc(end - start, GFP_KERNEL);
		if (!buf) {
			pr_crit("Malloc failure in wbuf recovery. Data loss ensues.\n");

			goto read_failed;
		}

		/* Do the read... */
		ret = mtd_read(c->mtd, start, c->wbuf_ofs - start, &retlen,
			       buf);

		/* ECC recovered ? */
		if ((ret == -EUCLEAN || ret == -EBADMSG) &&
		    (retlen == c->wbuf_ofs - start))
			ret = 0;

		if (ret || retlen != c->wbuf_ofs - start) {
			pr_crit("Old data are already lost in wbuf recovery. Data loss ensues.\n");

			kfree(buf);
			buf = NULL;
		read_failed:
			first_raw = ref_next(first_raw);
			nr_refile--;
			while (first_raw && ref_obsolete(first_raw)) {
				first_raw = ref_next(first_raw);
				nr_refile--;
			}

			/* If this was the only node to be recovered, give up */
			if (!first_raw) {
				c->wbuf_len = 0;
				return;
			}

			/* It wasn't. Go on and try to recover nodes complete in the wbuf */
			start = ref_offset(first_raw);
			dbg_noderef("wbuf now recover %08x-%08x (%d bytes in %d nodes)\n",
				    start, end, end - start, nr_refile);

		} else {
			/* Read succeeded. Copy the remaining data from the wbuf */
			memcpy(buf + (c->wbuf_ofs - start), c->wbuf, end - c->wbuf_ofs);
		}
	}
	/* OK... we're to rewrite (end-start) bytes of data from first_raw onwards.
	   Either 'buf' contains the data, or we find it in the wbuf */

	/* ... and get an allocation of space from a shiny new block instead */
	ret = jffs2_reserve_space_gc(c, end-start, &len, JFFS2_SUMMARY_NOSUM_SIZE);
	if (ret) {
		pr_warn("Failed to allocate space for wbuf recovery. Data loss ensues.\n");
		kfree(buf);
		return;
	}

	/* The summary is not recovered, so it must be disabled for this erase block */
	jffs2_sum_disable_collecting(c->summary);

	ret = jffs2_prealloc_raw_node_refs(c, c->nextblock, nr_refile);
	if (ret) {
		pr_warn("Failed to allocate node refs for wbuf recovery. Data loss ensues.\n");
		kfree(buf);
		return;
	}

	ofs = write_ofs(c);

	if (end-start >= c->wbuf_pagesize) {
		/* Need to do another write immediately, but it's possible
		   that this is just because the wbuf itself is completely
		   full, and there's nothing earlier read back from the
		   flash. Hence 'buf' isn't necessarily what we're writing
		   from. */
		unsigned char *rewrite_buf = buf?:c->wbuf;
		uint32_t towrite = (end-start) - ((end-start)%c->wbuf_pagesize);

		jffs2_dbg(1, "Write 0x%x bytes at 0x%08x in wbuf recover\n",
			  towrite, ofs);

#ifdef BREAKMEHEADER
		static int breakme;
		if (breakme++ == 20) {
			pr_notice("Faking write error at 0x%08x\n", ofs);
			breakme = 0;
			mtd_write(c->mtd, ofs, towrite, &retlen, brokenbuf);
			ret = -EIO;
		} else
#endif
			ret = mtd_write(c->mtd, ofs, towrite, &retlen,
					rewrite_buf);

		if (ret || retlen != towrite || jffs2_verify_write(c, rewrite_buf, ofs)) {
			/* Argh. We tried. Really we did. */
			pr_crit("Recovery of wbuf failed due to a second write error\n");
			kfree(buf);

			if (retlen)
				jffs2_add_physical_node_ref(c, ofs | REF_OBSOLETE, ref_totlen(c, jeb, first_raw), NULL);

			return;
		}
		pr_notice("Recovery of wbuf succeeded to %08x\n", ofs);

		c->wbuf_len = (end - start) - towrite;
		c->wbuf_ofs = ofs + towrite;
		memmove(c->wbuf, rewrite_buf + towrite, c->wbuf_len);
		/* Don't muck about with c->wbuf_inodes. False positives are harmless. */
	} else {
		/* OK, now we're left with the dregs in whichever buffer we're using */
		if (buf) {
			memcpy(c->wbuf, buf, end-start);
		} else {
			memmove(c->wbuf, c->wbuf + (start - c->wbuf_ofs), end - start);
		}
		c->wbuf_ofs = ofs;
		c->wbuf_len = end - start;
	}

	/* Now sort out the jffs2_raw_node_refs, moving them from the old to the next block */
	new_jeb = &c->blocks[ofs / c->sector_size];

	spin_lock(&c->erase_completion_lock);
	for (raw = first_raw; raw != jeb->last_node; raw = ref_next(raw)) {
		uint32_t rawlen = ref_totlen(c, jeb, raw);
		struct jffs2_inode_cache *ic;
		struct jffs2_raw_node_ref *new_ref;
		struct jffs2_raw_node_ref **adjust_ref = NULL;
		struct jffs2_inode_info *f = NULL;

		jffs2_dbg(1, "Refiling block of %08x at %08x(%d) to %08x\n",
			  rawlen, ref_offset(raw), ref_flags(raw), ofs);

		ic = jffs2_raw_ref_to_ic(raw);

		/* Ick. This XATTR mess should be fixed shortly... */
		if (ic && ic->class == RAWNODE_CLASS_XATTR_DATUM) {
			struct jffs2_xattr_datum *xd = (void *)ic;
			BUG_ON(xd->node != raw);
			adjust_ref = &xd->node;
			raw->next_in_ino = NULL;
			ic = NULL;
		} else if (ic && ic->class == RAWNODE_CLASS_XATTR_REF) {
			struct jffs2_xattr_datum *xr = (void *)ic;
			BUG_ON(xr->node != raw);
			adjust_ref = &xr->node;
			raw->next_in_ino = NULL;
			ic = NULL;
		} else if (ic && ic->class == RAWNODE_CLASS_INODE_CACHE) {
			struct jffs2_raw_node_ref **p = &ic->nodes;

			/* Remove the old node from the per-inode list */
			while (*p && *p != (void *)ic) {
				if (*p == raw) {
					(*p) = (raw->next_in_ino);
					raw->next_in_ino = NULL;
					break;
				}
				p = &((*p)->next_in_ino);
			}

			if (ic->state == INO_STATE_PRESENT && !ref_obsolete(raw)) {
				/* If it's an in-core inode, then we have to adjust any
				   full_dirent or full_dnode structure to point to the
				   new version instead of the old */
				f = jffs2_gc_fetch_inode(c, ic->ino, !ic->pino_nlink);
				if (IS_ERR(f)) {
					/* Should never happen; it _must_ be present */
					JFFS2_ERROR("Failed to iget() ino #%u, err %ld\n",
						    ic->ino, PTR_ERR(f));
					BUG();
				}
				/* We don't lock f->sem. There's a number of ways we could
				   end up in here with it already being locked, and nobody's
				   going to modify it on us anyway because we hold the
				   alloc_sem. We're only changing one ->raw pointer too,
				   which we can get away with without upsetting readers. */
				adjust_ref = jffs2_incore_replace_raw(c, f, raw,
								      (void *)(buf?:c->wbuf) + (ref_offset(raw) - start));
			} else if (unlikely(ic->state != INO_STATE_PRESENT &&
					    ic->state != INO_STATE_CHECKEDABSENT &&
					    ic->state != INO_STATE_GC)) {
				JFFS2_ERROR("Inode #%u is in strange state %d!\n", ic->ino, ic->state);
				BUG();
			}
		}

		new_ref = jffs2_link_node_ref(c, new_jeb, ofs | ref_flags(raw), rawlen, ic);

		if (adjust_ref) {
			BUG_ON(*adjust_ref != raw);
			*adjust_ref = new_ref;
		}
		if (f)
			jffs2_gc_release_inode(c, f);

		if (!ref_obsolete(raw)) {
			jeb->dirty_size += rawlen;
			jeb->used_size  -= rawlen;
			c->dirty_size += rawlen;
			c->used_size -= rawlen;
			raw->flash_offset = ref_offset(raw) | REF_OBSOLETE;
			BUG_ON(raw->next_in_ino);
		}
		ofs += rawlen;
	}

	kfree(buf);

	/* Fix up the original jeb now it's on the bad_list */
	if (first_raw == jeb->first_node) {
		jffs2_dbg(1, "Failing block at %08x is now empty. Moving to erase_pending_list\n",
			  jeb->offset);
		list_move(&jeb->list, &c->erase_pending_list);
		c->nr_erasing_blocks++;
		jffs2_garbage_collect_trigger(c);
	}

	jffs2_dbg_acct_sanity_check_nolock(c, jeb);
	jffs2_dbg_acct_paranoia_check_nolock(c, jeb);

	jffs2_dbg_acct_sanity_check_nolock(c, new_jeb);
	jffs2_dbg_acct_paranoia_check_nolock(c, new_jeb);

	spin_unlock(&c->erase_completion_lock);

	jffs2_dbg(1, "wbuf recovery completed OK. wbuf_ofs 0x%08x, len 0x%x\n",
		  c->wbuf_ofs, c->wbuf_len);

}

/* Meaning of pad argument:
   0: Do not pad. Probably pointless - we only ever use this when we can't pad anyway.
   1: Pad, do not adjust nextblock free_size
   2: Pad, adjust nextblock free_size
*/
#define NOPAD		0
#define PAD_NOACCOUNT	1
#define PAD_ACCOUNTING	2

static int __jffs2_flush_wbuf(struct jffs2_sb_info *c, int pad)
{
	struct jffs2_eraseblock *wbuf_jeb;
	int ret;
	size_t retlen;

	/* Nothing to do if not write-buffering the flash. In particular, we shouldn't
	   del_timer() the timer we never initialised. */
	if (!jffs2_is_writebuffered(c))
		return 0;

	if (!mutex_is_locked(&c->alloc_sem)) {
		pr_crit("jffs2_flush_wbuf() called with alloc_sem not locked!\n");
		BUG();
	}

	if (!c->wbuf_len)	/* already checked c->wbuf above */
		return 0;

	wbuf_jeb = &c->blocks[c->wbuf_ofs / c->sector_size];
	if (jffs2_prealloc_raw_node_refs(c, wbuf_jeb, c->nextblock->allocated_refs + 1))
		return -ENOMEM;

	/* claim remaining space on the page
	   this happens, if we have a change to a new block,
	   or if fsync forces us to flush the writebuffer.
	   if we have a switch to next page, we will not have
	   enough remaining space for this.
	*/
	if (pad ) {
		c->wbuf_len = PAD(c->wbuf_len);

		/* Pad with JFFS2_DIRTY_BITMASK initially.  this helps out ECC'd NOR
		   with 8 byte page size */
		memset(c->wbuf + c->wbuf_len, 0, c->wbuf_pagesize - c->wbuf_len);

		if ( c->wbuf_len + sizeof(struct jffs2_unknown_node) < c->wbuf_pagesize) {
			struct jffs2_unknown_node *padnode = (void *)(c->wbuf + c->wbuf_len);
			padnode->magic = cpu_to_je16(JFFS2_MAGIC_BITMASK);
			padnode->nodetype = cpu_to_je16(JFFS2_NODETYPE_PADDING);
			padnode->totlen = cpu_to_je32(c->wbuf_pagesize - c->wbuf_len);
			padnode->hdr_crc = cpu_to_je32(crc32(0, padnode, sizeof(*padnode)-4));
		}
	}
	/* else jffs2_flash_writev has actually filled in the rest of the
	   buffer for us, and will deal with the node refs etc. later. */

#ifdef BREAKME
	static int breakme;
	if (breakme++ == 20) {
		pr_notice("Faking write error at 0x%08x\n", c->wbuf_ofs);
		breakme = 0;
		mtd_write(c->mtd, c->wbuf_ofs, c->wbuf_pagesize, &retlen,
			  brokenbuf);
		ret = -EIO;
	} else
#endif

		ret = mtd_write(c->mtd, c->wbuf_ofs, c->wbuf_pagesize,
				&retlen, c->wbuf);

	if (ret) {
		pr_warn("jffs2_flush_wbuf(): Write failed with %d\n", ret);
		goto wfail;
	} else if (retlen != c->wbuf_pagesize) {
		pr_warn("jffs2_flush_wbuf(): Write was short: %zd instead of %d\n",
			retlen, c->wbuf_pagesize);
		ret = -EIO;
		goto wfail;
	} else if ((ret = jffs2_verify_write(c, c->wbuf, c->wbuf_ofs))) {
	wfail:
		jffs2_wbuf_recover(c);

		return ret;
	}

	/* Adjust free size of the block if we padded. */
	if (pad) {
		uint32_t waste = c->wbuf_pagesize - c->wbuf_len;

		jffs2_dbg(1, "jffs2_flush_wbuf() adjusting free_size of %sblock at %08x\n",
			  (wbuf_jeb == c->nextblock) ? "next" : "",
			  wbuf_jeb->offset);

		/* wbuf_pagesize - wbuf_len is the amount of space that's to be
		   padded. If there is less free space in the block than that,
		   something screwed up */
		if (wbuf_jeb->free_size < waste) {
			pr_crit("jffs2_flush_wbuf(): Accounting error. wbuf at 0x%08x has 0x%03x bytes, 0x%03x left.\n",
				c->wbuf_ofs, c->wbuf_len, waste);
			pr_crit("jffs2_flush_wbuf(): But free_size for block at 0x%08x is only 0x%08x\n",
				wbuf_jeb->offset, wbuf_jeb->free_size);
			BUG();
		}

		spin_lock(&c->erase_completion_lock);

		jffs2_link_node_ref(c, wbuf_jeb, (c->wbuf_ofs + c->wbuf_len) | REF_OBSOLETE, waste, NULL);
		/* FIXME: that made it count as dirty. Convert to wasted */
		wbuf_jeb->dirty_size -= waste;
		c->dirty_size -= waste;
		wbuf_jeb->wasted_size += waste;
		c->wasted_size += waste;
	} else
		spin_lock(&c->erase_completion_lock);

	/* Stick any now-obsoleted blocks on the erase_pending_list */
	jffs2_refile_wbuf_blocks(c);
	jffs2_clear_wbuf_ino_list(c);
	spin_unlock(&c->erase_completion_lock);

	memset(c->wbuf,0xff,c->wbuf_pagesize);
	/* adjust write buffer offset, else we get a non contiguous write bug */
	c->wbuf_ofs += c->wbuf_pagesize;
	c->wbuf_len = 0;
	return 0;
}

/* Trigger garbage collection to flush the write-buffer.
   If ino arg is zero, do it if _any_ real (i.e. not GC) writes are
   outstanding. If ino arg non-zero, do it only if a write for the
   given inode is outstanding. */
int jffs2_flush_wbuf_gc(struct jffs2_sb_info *c, uint32_t ino)
{
	uint32_t old_wbuf_ofs;
	uint32_t old_wbuf_len;
	int ret = 0;

	jffs2_dbg(1, "jffs2_flush_wbuf_gc() called for ino #%u...\n", ino);

	if (!c->wbuf)
		return 0;

	mutex_lock(&c->alloc_sem);
	if (!jffs2_wbuf_pending_for_ino(c, ino)) {
		jffs2_dbg(1, "Ino #%d not pending in wbuf. Returning\n", ino);
		mutex_unlock(&c->alloc_sem);
		return 0;
	}

	old_wbuf_ofs = c->wbuf_ofs;
	old_wbuf_len = c->wbuf_len;

	if (c->unchecked_size) {
		/* GC won't make any progress for a while */
		jffs2_dbg(1, "%s(): padding. Not finished checking\n",
			  __func__);
		down_write(&c->wbuf_sem);
		ret = __jffs2_flush_wbuf(c, PAD_ACCOUNTING);
		/* retry flushing wbuf in case jffs2_wbuf_recover
		   left some data in the wbuf */
		if (ret)
			ret = __jffs2_flush_wbuf(c, PAD_ACCOUNTING);
		up_write(&c->wbuf_sem);
	} else while (old_wbuf_len &&
		      old_wbuf_ofs == c->wbuf_ofs) {

		mutex_unlock(&c->alloc_sem);

		jffs2_dbg(1, "%s(): calls gc pass\n", __func__);

		ret = jffs2_garbage_collect_pass(c);
		if (ret) {
			/* GC failed. Flush it with padding instead */
			mutex_lock(&c->alloc_sem);
			down_write(&c->wbuf_sem);
			ret = __jffs2_flush_wbuf(c, PAD_ACCOUNTING);
			/* retry flushing wbuf in case jffs2_wbuf_recover
			   left some data in the wbuf */
			if (ret)
				ret = __jffs2_flush_wbuf(c, PAD_ACCOUNTING);
			up_write(&c->wbuf_sem);
			break;
		}
		mutex_lock(&c->alloc_sem);
	}

	jffs2_dbg(1, "%s(): ends...\n", __func__);

	mutex_unlock(&c->alloc_sem);
	return ret;
}

/* Pad write-buffer to end and write it, wasting space. */
int jffs2_flush_wbuf_pad(struct jffs2_sb_info *c)
{
	int ret;

	if (!c->wbuf)
		return 0;

	down_write(&c->wbuf_sem);
	ret = __jffs2_flush_wbuf(c, PAD_NOACCOUNT);
	/* retry - maybe wbuf recover left some data in wbuf. */
	if (ret)
		ret = __jffs2_flush_wbuf(c, PAD_NOACCOUNT);
	up_write(&c->wbuf_sem);

	return ret;
}

static size_t jffs2_fill_wbuf(struct jffs2_sb_info *c, const uint8_t *buf,
			      size_t len)
{
	if (len && !c->wbuf_len && (len >= c->wbuf_pagesize))
		return 0;

	if (len > (c->wbuf_pagesize - c->wbuf_len))
		len = c->wbuf_pagesize - c->wbuf_len;
	memcpy(c->wbuf + c->wbuf_len, buf, len);
	c->wbuf_len += (uint32_t) len;
	return len;
}

int jffs2_flash_writev(struct jffs2_sb_info *c, const struct kvec *invecs,
		       unsigned long count, loff_t to, size_t *retlen,
		       uint32_t ino)
{
	struct jffs2_eraseblock *jeb;
	size_t wbuf_retlen, donelen = 0;
	uint32_t outvec_to = to;
	int ret, invec;

	/* If not writebuffered flash, don't bother */
	if (!jffs2_is_writebuffered(c))
		return jffs2_flash_direct_writev(c, invecs, count, to, retlen);

	down_write(&c->wbuf_sem);

	/* If wbuf_ofs is not initialized, set it to target address */
	if (c->wbuf_ofs == 0xFFFFFFFF) {
		c->wbuf_ofs = PAGE_DIV(to);
		c->wbuf_len = PAGE_MOD(to);
		memset(c->wbuf,0xff,c->wbuf_pagesize);
	}

	/*
	 * Sanity checks on target address.  It's permitted to write
	 * at PAD(c->wbuf_len+c->wbuf_ofs), and it's permitted to
	 * write at the beginning of a new erase block. Anything else,
	 * and you die.  New block starts at xxx000c (0-b = block
	 * header)
	 */
	if (SECTOR_ADDR(to) != SECTOR_ADDR(c->wbuf_ofs)) {
		/* It's a write to a new block */
		if (c->wbuf_len) {
			jffs2_dbg(1, "%s(): to 0x%lx causes flush of wbuf at 0x%08x\n",
				  __func__, (unsigned long)to, c->wbuf_ofs);
			ret = __jffs2_flush_wbuf(c, PAD_NOACCOUNT);
			if (ret)
				goto outerr;
		}
		/* set pointer to new block */
		c->wbuf_ofs = PAGE_DIV(to);
		c->wbuf_len = PAGE_MOD(to);
	}

	if (to != PAD(c->wbuf_ofs + c->wbuf_len)) {
		/* We're not writing immediately after the writebuffer. Bad. */
		pr_crit("%s(): Non-contiguous write to %08lx\n",
			__func__, (unsigned long)to);
		if (c->wbuf_len)
			pr_crit("wbuf was previously %08x-%08x\n",
				c->wbuf_ofs, c->wbuf_ofs + c->wbuf_len);
		BUG();
	}

	/* adjust alignment offset */
	if (c->wbuf_len != PAGE_MOD(to)) {
		c->wbuf_len = PAGE_MOD(to);
		/* take care of alignment to next page */
		if (!c->wbuf_len) {
			c->wbuf_len = c->wbuf_pagesize;
			ret = __jffs2_flush_wbuf(c, NOPAD);
			if (ret)
				goto outerr;
		}
	}

	for (invec = 0; invec < count; invec++) {
		int vlen = invecs[invec].iov_len;
		uint8_t *v = invecs[invec].iov_base;

		wbuf_retlen = jffs2_fill_wbuf(c, v, vlen);

		if (c->wbuf_len == c->wbuf_pagesize) {
			ret = __jffs2_flush_wbuf(c, NOPAD);
			if (ret)
				goto outerr;
		}
		vlen -= wbuf_retlen;
		outvec_to += wbuf_retlen;
		donelen += wbuf_retlen;
		v += wbuf_retlen;

		if (vlen >= c->wbuf_pagesize) {
			ret = mtd_write(c->mtd, outvec_to, PAGE_DIV(vlen),
					&wbuf_retlen, v);
			if (ret < 0 || wbuf_retlen != PAGE_DIV(vlen))
				goto outfile;

			vlen -= wbuf_retlen;
			outvec_to += wbuf_retlen;
			c->wbuf_ofs = outvec_to;
			donelen += wbuf_retlen;
			v += wbuf_retlen;
		}

		wbuf_retlen = jffs2_fill_wbuf(c, v, vlen);
		if (c->wbuf_len == c->wbuf_pagesize) {
			ret = __jffs2_flush_wbuf(c, NOPAD);
			if (ret)
				goto outerr;
		}

		outvec_to += wbuf_retlen;
		donelen += wbuf_retlen;
	}

	/*
	 * If there's a remainder in the wbuf and it's a non-GC write,
	 * remember that the wbuf affects this ino
	 */
	*retlen = donelen;

	if (jffs2_sum_active()) {
		int res = jffs2_sum_add_kvec(c, invecs, count, (uint32_t) to);
		if (res)
			return res;
	}

	if (c->wbuf_len && ino)
		jffs2_wbuf_dirties_inode(c, ino);

	ret = 0;
	up_write(&c->wbuf_sem);
	return ret;

outfile:
	/*
	 * At this point we have no problem, c->wbuf is empty. However
	 * refile nextblock to avoid writing again to same address.
	 */

	spin_lock(&c->erase_completion_lock);

	jeb = &c->blocks[outvec_to / c->sector_size];
	jffs2_block_refile(c, jeb, REFILE_ANYWAY);

	spin_unlock(&c->erase_completion_lock);

outerr:
	*retlen = 0;
	up_write(&c->wbuf_sem);
	return ret;
}

/*
 *	This is the entry for flash write.
 *	Check, if we work on NAND FLASH, if so build an kvec and write it via vritev
*/
int jffs2_flash_write(struct jffs2_sb_info *c, loff_t ofs, size_t len,
		      size_t *retlen, const u_char *buf)
{
	struct kvec vecs[1];

	if (!jffs2_is_writebuffered(c))
		return jffs2_flash_direct_write(c, ofs, len, retlen, buf);

	vecs[0].iov_base = (unsigned char *) buf;
	vecs[0].iov_len = len;
	return jffs2_flash_writev(c, vecs, 1, ofs, retlen, 0);
}

/*
	Handle readback from writebuffer and ECC failure return
*/
int jffs2_flash_read(struct jffs2_sb_info *c, loff_t ofs, size_t len, size_t *retlen, u_char *buf)
{
	loff_t	orbf = 0, owbf = 0, lwbf = 0;
	int	ret;

	if (!jffs2_is_writebuffered(c))
		return mtd_read(c->mtd, ofs, len, retlen, buf);

	/* Read flash */
	down_read(&c->wbuf_sem);
	ret = mtd_read(c->mtd, ofs, len, retlen, buf);

	if ( (ret == -EBADMSG || ret == -EUCLEAN) && (*retlen == len) ) {
		if (ret == -EBADMSG)
			pr_warn("mtd->read(0x%zx bytes from 0x%llx) returned ECC error\n",
				len, ofs);
		/*
		 * We have the raw data without ECC correction in the buffer,
		 * maybe we are lucky and all data or parts are correct. We
		 * check the node.  If data are corrupted node check will sort
		 * it out.  We keep this block, it will fail on write or erase
		 * and the we mark it bad. Or should we do that now? But we
		 * should give him a chance.  Maybe we had a system crash or
		 * power loss before the ecc write or a erase was completed.
		 * So we return success. :)
		 */
		ret = 0;
	}

	/* if no writebuffer available or write buffer empty, return */
	if (!c->wbuf_pagesize || !c->wbuf_len)
		goto exit;

	/* if we read in a different block, return */
	if (SECTOR_ADDR(ofs) != SECTOR_ADDR(c->wbuf_ofs))
		goto exit;

	if (ofs >= c->wbuf_ofs) {
		owbf = (ofs - c->wbuf_ofs);	/* offset in write buffer */
		if (owbf > c->wbuf_len)		/* is read beyond write buffer ? */
			goto exit;
		lwbf = c->wbuf_len - owbf;	/* number of bytes to copy */
		if (lwbf > len)
			lwbf = len;
	} else {
		orbf = (c->wbuf_ofs - ofs);	/* offset in read buffer */
		if (orbf > len)			/* is write beyond write buffer ? */
			goto exit;
		lwbf = len - orbf;		/* number of bytes to copy */
		if (lwbf > c->wbuf_len)
			lwbf = c->wbuf_len;
	}
	if (lwbf > 0)
		memcpy(buf+orbf,c->wbuf+owbf,lwbf);

exit:
	up_read(&c->wbuf_sem);
	return ret;
}

#define NR_OOB_SCAN_PAGES 4

/* For historical reasons we use only 8 bytes for OOB clean marker */
#define OOB_CM_SIZE 8

static const struct jffs2_unknown_node oob_cleanmarker =
{
	.magic = constant_cpu_to_je16(JFFS2_MAGIC_BITMASK),
	.nodetype = constant_cpu_to_je16(JFFS2_NODETYPE_CLEANMARKER),
	.totlen = constant_cpu_to_je32(8)
};

/*
 * Check, if the out of band area is empty. This function knows about the clean
 * marker and if it is present in OOB, treats the OOB as empty anyway.
 */
int jffs2_check_oob_empty(struct jffs2_sb_info *c,
			  struct jffs2_eraseblock *jeb, int mode)
{
	int i, ret;
	int cmlen = min_t(int, c->oobavail, OOB_CM_SIZE);
	struct mtd_oob_ops ops;

	ops.mode = MTD_OPS_AUTO_OOB;
	ops.ooblen = NR_OOB_SCAN_PAGES * c->oobavail;
	ops.oobbuf = c->oobbuf;
	ops.len = ops.ooboffs = ops.retlen = ops.oobretlen = 0;
	ops.datbuf = NULL;

	ret = mtd_read_oob(c->mtd, jeb->offset, &ops);
	if ((ret && !mtd_is_bitflip(ret)) || ops.oobretlen != ops.ooblen) {
		pr_err("cannot read OOB for EB at %08x, requested %zd bytes, read %zd bytes, error %d\n",
		       jeb->offset, ops.ooblen, ops.oobretlen, ret);
		if (!ret || mtd_is_bitflip(ret))
			ret = -EIO;
		return ret;
	}

	for(i = 0; i < ops.ooblen; i++) {
		if (mode && i < cmlen)
			/* Yeah, we know about the cleanmarker */
			continue;

		if (ops.oobbuf[i] != 0xFF) {
			jffs2_dbg(2, "Found %02x at %x in OOB for "
				  "%08x\n", ops.oobbuf[i], i, jeb->offset);
			return 1;
		}
	}

	return 0;
}

/*
 * Check for a valid cleanmarker.
 * Returns: 0 if a valid cleanmarker was found
 *	    1 if no cleanmarker was found
 *	    negative error code if an error occurred
 */
int jffs2_check_nand_cleanmarker(struct jffs2_sb_info *c,
				 struct jffs2_eraseblock *jeb)
{
	struct mtd_oob_ops ops;
	int ret, cmlen = min_t(int, c->oobavail, OOB_CM_SIZE);

	ops.mode = MTD_OPS_AUTO_OOB;
	ops.ooblen = cmlen;
	ops.oobbuf = c->oobbuf;
	ops.len = ops.ooboffs = ops.retlen = ops.oobretlen = 0;
	ops.datbuf = NULL;

	ret = mtd_read_oob(c->mtd, jeb->offset, &ops);
	if ((ret && !mtd_is_bitflip(ret)) || ops.oobretlen != ops.ooblen) {
		pr_err("cannot read OOB for EB at %08x, requested %zd bytes, read %zd bytes, error %d\n",
		       jeb->offset, ops.ooblen, ops.oobretlen, ret);
		if (!ret || mtd_is_bitflip(ret))
			ret = -EIO;
		return ret;
	}

	return !!memcmp(&oob_cleanmarker, c->oobbuf, cmlen);
}

int jffs2_write_nand_cleanmarker(struct jffs2_sb_info *c,
				 struct jffs2_eraseblock *jeb)
{
	int ret;
	struct mtd_oob_ops ops;
	int cmlen = min_t(int, c->oobavail, OOB_CM_SIZE);

	ops.mode = MTD_OPS_AUTO_OOB;
	ops.ooblen = cmlen;
	ops.oobbuf = (uint8_t *)&oob_cleanmarker;
	ops.len = ops.ooboffs = ops.retlen = ops.oobretlen = 0;
	ops.datbuf = NULL;

	ret = mtd_write_oob(c->mtd, jeb->offset, &ops);
	if (ret || ops.oobretlen != ops.ooblen) {
		pr_err("cannot write OOB for EB at %08x, requested %zd bytes, read %zd bytes, error %d\n",
		       jeb->offset, ops.ooblen, ops.oobretlen, ret);
		if (!ret)
			ret = -EIO;
		return ret;
	}

	return 0;
}

/*
 * On NAND we try to mark this block bad. If the block was erased more
 * than MAX_ERASE_FAILURES we mark it finally bad.
 * Don't care about failures. This block remains on the erase-pending
 * or badblock list as long as nobody manipulates the flash with
 * a bootloader or something like that.
 */

int jffs2_write_nand_badblock(struct jffs2_sb_info *c, struct jffs2_eraseblock *jeb, uint32_t bad_offset)
{
	int 	ret;

	/* if the count is < max, we try to write the counter to the 2nd page oob area */
	if( ++jeb->bad_count < MAX_ERASE_FAILURES)
		return 0;

	pr_warn("marking eraseblock at %08x as bad\n", bad_offset);
	ret = mtd_block_markbad(c->mtd, bad_offset);

	if (ret) {
		jffs2_dbg(1, "%s(): Write failed for block at %08x: error %d\n",
			  __func__, jeb->offset, ret);
		return ret;
	}
	return 1;
}

static struct jffs2_sb_info *work_to_sb(struct work_struct *work)
{
	struct delayed_work *dwork;

	dwork = container_of(work, struct delayed_work, work);
	return container_of(dwork, struct jffs2_sb_info, wbuf_dwork);
}

static void delayed_wbuf_sync(struct work_struct *work)
{
	struct jffs2_sb_info *c = work_to_sb(work);
	struct super_block *sb = OFNI_BS_2SFFJ(c);

	spin_lock(&c->wbuf_dwork_lock);
	c->wbuf_queued = 0;
	spin_unlock(&c->wbuf_dwork_lock);

	if (!(sb->s_flags & MS_RDONLY)) {
		jffs2_dbg(1, "%s()\n", __func__);
		jffs2_flush_wbuf_gc(c, 0);
	}
}

void jffs2_dirty_trigger(struct jffs2_sb_info *c)
{
	struct super_block *sb = OFNI_BS_2SFFJ(c);
	unsigned long delay;

	if (sb->s_flags & MS_RDONLY)
		return;

	spin_lock(&c->wbuf_dwork_lock);
	if (!c->wbuf_queued) {
		jffs2_dbg(1, "%s()\n", __func__);
		delay = msecs_to_jiffies(dirty_writeback_interval * 10);
		queue_delayed_work(system_long_wq, &c->wbuf_dwork, delay);
		c->wbuf_queued = 1;
	}
	spin_unlock(&c->wbuf_dwork_lock);
}

int jffs2_nand_flash_setup(struct jffs2_sb_info *c)
{
	struct nand_ecclayout *oinfo = c->mtd->ecclayout;

	if (!c->mtd->oobsize)
		return 0;

	/* Cleanmarker is out-of-band, so inline size zero */
	c->cleanmarker_size = 0;

	if (!oinfo || oinfo->oobavail == 0) {
		pr_err("inconsistent device description\n");
		return -EINVAL;
	}

	jffs2_dbg(1, "using OOB on NAND\n");

	c->oobavail = oinfo->oobavail;

	/* Initialise write buffer */
	init_rwsem(&c->wbuf_sem);
	spin_lock_init(&c->wbuf_dwork_lock);
	INIT_DELAYED_WORK(&c->wbuf_dwork, delayed_wbuf_sync);
	c->wbuf_pagesize = c->mtd->writesize;
	c->wbuf_ofs = 0xFFFFFFFF;

	c->wbuf = kmalloc(c->wbuf_pagesize, GFP_KERNEL);
	if (!c->wbuf)
		return -ENOMEM;

	c->oobbuf = kmalloc(NR_OOB_SCAN_PAGES * c->oobavail, GFP_KERNEL);
	if (!c->oobbuf) {
		kfree(c->wbuf);
		return -ENOMEM;
	}

#ifdef CONFIG_JFFS2_FS_WBUF_VERIFY
	c->wbuf_verify = kmalloc(c->wbuf_pagesize, GFP_KERNEL);
	if (!c->wbuf_verify) {
		kfree(c->oobbuf);
		kfree(c->wbuf);
		return -ENOMEM;
	}
#endif
	return 0;
}

void jffs2_nand_flash_cleanup(struct jffs2_sb_info *c)
{
#ifdef CONFIG_JFFS2_FS_WBUF_VERIFY
	kfree(c->wbuf_verify);
#endif
	kfree(c->wbuf);
	kfree(c->oobbuf);
}

int jffs2_dataflash_setup(struct jffs2_sb_info *c) {
	c->cleanmarker_size = 0;		/* No cleanmarkers needed */

	/* Initialize write buffer */
	init_rwsem(&c->wbuf_sem);
	spin_lock_init(&c->wbuf_dwork_lock);
	INIT_DELAYED_WORK(&c->wbuf_dwork, delayed_wbuf_sync);
	c->wbuf_pagesize =  c->mtd->erasesize;

	/* Find a suitable c->sector_size
	 * - Not too much sectors
	 * - Sectors have to be at least 4 K + some bytes
	 * - All known dataflashes have erase sizes of 528 or 1056
	 * - we take at least 8 eraseblocks and want to have at least 8K size
	 * - The concatenation should be a power of 2
	*/

	c->sector_size = 8 * c->mtd->erasesize;

	while (c->sector_size < 8192) {
		c->sector_size *= 2;
	}

	/* It may be necessary to adjust the flash size */
	c->flash_size = c->mtd->size;

	if ((c->flash_size % c->sector_size) != 0) {
		c->flash_size = (c->flash_size / c->sector_size) * c->sector_size;
		pr_warn("flash size adjusted to %dKiB\n", c->flash_size);
	};

	c->wbuf_ofs = 0xFFFFFFFF;
	c->wbuf = kmalloc(c->wbuf_pagesize, GFP_KERNEL);
	if (!c->wbuf)
		return -ENOMEM;

#ifdef CONFIG_JFFS2_FS_WBUF_VERIFY
	c->wbuf_verify = kmalloc(c->wbuf_pagesize, GFP_KERNEL);
	if (!c->wbuf_verify) {
		kfree(c->oobbuf);
		kfree(c->wbuf);
		return -ENOMEM;
	}
#endif

	pr_info("write-buffering enabled buffer (%d) erasesize (%d)\n",
		c->wbuf_pagesize, c->sector_size);

	return 0;
}

void jffs2_dataflash_cleanup(struct jffs2_sb_info *c) {
#ifdef CONFIG_JFFS2_FS_WBUF_VERIFY
	kfree(c->wbuf_verify);
#endif
	kfree(c->wbuf);
}

int jffs2_nor_wbuf_flash_setup(struct jffs2_sb_info *c) {
	/* Cleanmarker currently occupies whole programming regions,
	 * either one or 2 for 8Byte STMicro flashes. */
	c->cleanmarker_size = max(16u, c->mtd->writesize);

	/* Initialize write buffer */
	init_rwsem(&c->wbuf_sem);
	spin_lock_init(&c->wbuf_dwork_lock);
	INIT_DELAYED_WORK(&c->wbuf_dwork, delayed_wbuf_sync);

	c->wbuf_pagesize = c->mtd->writesize;
	c->wbuf_ofs = 0xFFFFFFFF;

	c->wbuf = kmalloc(c->wbuf_pagesize, GFP_KERNEL);
	if (!c->wbuf)
		return -ENOMEM;

#ifdef CONFIG_JFFS2_FS_WBUF_VERIFY
	c->wbuf_verify = kmalloc(c->wbuf_pagesize, GFP_KERNEL);
	if (!c->wbuf_verify) {
		kfree(c->wbuf);
		return -ENOMEM;
	}
#endif
	return 0;
}

void jffs2_nor_wbuf_flash_cleanup(struct jffs2_sb_info *c) {
#ifdef CONFIG_JFFS2_FS_WBUF_VERIFY
	kfree(c->wbuf_verify);
#endif
	kfree(c->wbuf);
}

int jffs2_ubivol_setup(struct jffs2_sb_info *c) {
	c->cleanmarker_size = 0;

	if (c->mtd->writesize == 1)
		/* We do not need write-buffer */
		return 0;

	init_rwsem(&c->wbuf_sem);
	spin_lock_init(&c->wbuf_dwork_lock);
	INIT_DELAYED_WORK(&c->wbuf_dwork, delayed_wbuf_sync);

	c->wbuf_pagesize =  c->mtd->writesize;
	c->wbuf_ofs = 0xFFFFFFFF;
	c->wbuf = kmalloc(c->wbuf_pagesize, GFP_KERNEL);
	if (!c->wbuf)
		return -ENOMEM;

	pr_info("write-buffering enabled buffer (%d) erasesize (%d)\n",
		c->wbuf_pagesize, c->sector_size);

	return 0;
}

void jffs2_ubivol_cleanup(struct jffs2_sb_info *c) {
	kfree(c->wbuf);
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/wbuf.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by Arjan van de Ven <arjanv@redhat.com>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 *
 *
 * Very simple lz77-ish encoder.
 *
 * Theory of operation: Both encoder and decoder have a list of "last
 * occurrences" for every possible source-value; after sending the
 * first source-byte, the second byte indicated the "run" length of
 * matches
 *
 * The algorithm is intended to only send "whole bytes", no bit-messing.
 *
 */

// #include <linux/kernel.h>
// #include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
// #include <linux/jffs2.h>
// #include "compr.h"

/* _compress returns the compressed size, -1 if bigger */
static int jffs2_rtime_compress(unsigned char *data_in,
				unsigned char *cpage_out,
				uint32_t *sourcelen, uint32_t *dstlen)
{
	unsigned short positions[256];
	int outpos = 0;
	int pos=0;

	memset(positions,0,sizeof(positions));

	while (pos < (*sourcelen) && outpos <= (*dstlen)-2) {
		int backpos, runlen=0;
		unsigned char value;

		value = data_in[pos];

		cpage_out[outpos++] = data_in[pos++];

		backpos = positions[value];
		positions[value]=pos;

		while ((backpos < pos) && (pos < (*sourcelen)) &&
		       (data_in[pos]==data_in[backpos++]) && (runlen<255)) {
			pos++;
			runlen++;
		}
		cpage_out[outpos++] = runlen;
	}

	if (outpos >= pos) {
		/* We failed */
		return -1;
	}

	/* Tell the caller how much we managed to compress, and how much space it took */
	*sourcelen = pos;
	*dstlen = outpos;
	return 0;
}


static int jffs2_rtime_decompress(unsigned char *data_in,
				  unsigned char *cpage_out,
				  uint32_t srclen, uint32_t destlen)
{
	unsigned short positions[256];
	int outpos = 0;
	int pos=0;

	memset(positions,0,sizeof(positions));

	while (outpos<destlen) {
		unsigned char value;
		int backoffs;
		int repeat;

		value = data_in[pos++];
		cpage_out[outpos++] = value; /* first the verbatim copied byte */
		repeat = data_in[pos++];
		backoffs = positions[value];

		positions[value]=outpos;
		if (repeat) {
			if (backoffs + repeat >= outpos) {
				while(repeat) {
					cpage_out[outpos++] = cpage_out[backoffs++];
					repeat--;
				}
			} else {
				memcpy(&cpage_out[outpos],&cpage_out[backoffs],repeat);
				outpos+=repeat;
			}
		}
	}
	return 0;
}

static struct jffs2_compressor jffs2_rtime_comp = {
    .priority = JFFS2_RTIME_PRIORITY,
    .name = "rtime",
    .compr = JFFS2_COMPR_RTIME,
    .compress = &jffs2_rtime_compress,
    .decompress = &jffs2_rtime_decompress,
#ifdef JFFS2_RTIME_DISABLED
    .disabled = 1,
#else
    .disabled = 0,
#endif
};

int jffs2_rtime_init(void)
{
    return jffs2_register_compressor(&jffs2_rtime_comp);
}

void jffs2_rtime_exit(void)
{
    jffs2_unregister_compressor(&jffs2_rtime_comp);
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/compr_rtime.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2001-2007 Red Hat, Inc.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by David Woodhouse <dwmw2@infradead.org>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

#if !defined(__KERNEL__) && !defined(__ECOS)
#error "The userspace support got too messy and was removed. Update your mkfs.jffs2"
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

// #include <linux/kernel.h>
#include <linux/zlib.h>
#include <linux/zutil.h>
// #include "nodelist.h"
// #include "compr.h"

	/* Plan: call deflate() with avail_in == *sourcelen,
		avail_out = *dstlen - 12 and flush == Z_FINISH.
		If it doesn't manage to finish,	call it again with
		avail_in == 0 and avail_out set to the remaining 12
		bytes for it to clean up.
	   Q: Is 12 bytes sufficient?
	*/
#define STREAM_END_SPACE 12

static DEFINE_MUTEX(deflate_mutex);
static DEFINE_MUTEX(inflate_mutex);
static z_stream inf_strm, def_strm;

#ifdef __KERNEL__ /* Linux-only */
// #include <linux/vmalloc.h>
// #include <linux/init.h>
#include <linux/mutex.h>

static int __init alloc_workspaces(void)
{
	def_strm.workspace = vmalloc(zlib_deflate_workspacesize(MAX_WBITS,
							MAX_MEM_LEVEL));
	if (!def_strm.workspace)
		return -ENOMEM;

	jffs2_dbg(1, "Allocated %d bytes for deflate workspace\n",
		  zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL));
	inf_strm.workspace = vmalloc(zlib_inflate_workspacesize());
	if (!inf_strm.workspace) {
		vfree(def_strm.workspace);
		return -ENOMEM;
	}
	jffs2_dbg(1, "Allocated %d bytes for inflate workspace\n",
		  zlib_inflate_workspacesize());
	return 0;
}

static void free_workspaces(void)
{
	vfree(def_strm.workspace);
	vfree(inf_strm.workspace);
}
#else
#define alloc_workspaces() (0)
#define free_workspaces() do { } while(0)
#endif /* __KERNEL__ */

static int jffs2_zlib_compress(unsigned char *data_in,
			       unsigned char *cpage_out,
			       uint32_t *sourcelen, uint32_t *dstlen)
{
	int ret;

	if (*dstlen <= STREAM_END_SPACE)
		return -1;

	mutex_lock(&deflate_mutex);

	if (Z_OK != zlib_deflateInit(&def_strm, 3)) {
		pr_warn("deflateInit failed\n");
		mutex_unlock(&deflate_mutex);
		return -1;
	}

	def_strm.next_in = data_in;
	def_strm.total_in = 0;

	def_strm.next_out = cpage_out;
	def_strm.total_out = 0;

	while (def_strm.total_out < *dstlen - STREAM_END_SPACE && def_strm.total_in < *sourcelen) {
		def_strm.avail_out = *dstlen - (def_strm.total_out + STREAM_END_SPACE);
		def_strm.avail_in = min_t(unsigned long,
			(*sourcelen-def_strm.total_in), def_strm.avail_out);
		jffs2_dbg(1, "calling deflate with avail_in %ld, avail_out %ld\n",
			  def_strm.avail_in, def_strm.avail_out);
		ret = zlib_deflate(&def_strm, Z_PARTIAL_FLUSH);
		jffs2_dbg(1, "deflate returned with avail_in %ld, avail_out %ld, total_in %ld, total_out %ld\n",
			  def_strm.avail_in, def_strm.avail_out,
			  def_strm.total_in, def_strm.total_out);
		if (ret != Z_OK) {
			jffs2_dbg(1, "deflate in loop returned %d\n", ret);
			zlib_deflateEnd(&def_strm);
			mutex_unlock(&deflate_mutex);
			return -1;
		}
	}
	def_strm.avail_out += STREAM_END_SPACE;
	def_strm.avail_in = 0;
	ret = zlib_deflate(&def_strm, Z_FINISH);
	zlib_deflateEnd(&def_strm);

	if (ret != Z_STREAM_END) {
		jffs2_dbg(1, "final deflate returned %d\n", ret);
		ret = -1;
		goto out;
	}

	if (def_strm.total_out >= def_strm.total_in) {
		jffs2_dbg(1, "zlib compressed %ld bytes into %ld; failing\n",
			  def_strm.total_in, def_strm.total_out);
		ret = -1;
		goto out;
	}

	jffs2_dbg(1, "zlib compressed %ld bytes into %ld\n",
		  def_strm.total_in, def_strm.total_out);

	*dstlen = def_strm.total_out;
	*sourcelen = def_strm.total_in;
	ret = 0;
 out:
	mutex_unlock(&deflate_mutex);
	return ret;
}

static int jffs2_zlib_decompress(unsigned char *data_in,
				 unsigned char *cpage_out,
				 uint32_t srclen, uint32_t destlen)
{
	int ret;
	int wbits = MAX_WBITS;

	mutex_lock(&inflate_mutex);

	inf_strm.next_in = data_in;
	inf_strm.avail_in = srclen;
	inf_strm.total_in = 0;

	inf_strm.next_out = cpage_out;
	inf_strm.avail_out = destlen;
	inf_strm.total_out = 0;

	/* If it's deflate, and it's got no preset dictionary, then
	   we can tell zlib to skip the adler32 check. */
	if (srclen > 2 && !(data_in[1] & PRESET_DICT) &&
	    ((data_in[0] & 0x0f) == Z_DEFLATED) &&
	    !(((data_in[0]<<8) + data_in[1]) % 31)) {

		jffs2_dbg(2, "inflate skipping adler32\n");
		wbits = -((data_in[0] >> 4) + 8);
		inf_strm.next_in += 2;
		inf_strm.avail_in -= 2;
	} else {
		/* Let this remain D1 for now -- it should never happen */
		jffs2_dbg(1, "inflate not skipping adler32\n");
	}


	if (Z_OK != zlib_inflateInit2(&inf_strm, wbits)) {
		pr_warn("inflateInit failed\n");
		mutex_unlock(&inflate_mutex);
		return 1;
	}

	while((ret = zlib_inflate(&inf_strm, Z_FINISH)) == Z_OK)
		;
	if (ret != Z_STREAM_END) {
		pr_notice("inflate returned %d\n", ret);
	}
	zlib_inflateEnd(&inf_strm);
	mutex_unlock(&inflate_mutex);
	return 0;
}

static struct jffs2_compressor jffs2_zlib_comp = {
    .priority = JFFS2_ZLIB_PRIORITY,
    .name = "zlib",
    .compr = JFFS2_COMPR_ZLIB,
    .compress = &jffs2_zlib_compress,
    .decompress = &jffs2_zlib_decompress,
#ifdef JFFS2_ZLIB_DISABLED
    .disabled = 1,
#else
    .disabled = 0,
#endif
};

int __init jffs2_zlib_init(void)
{
    int ret;

    ret = alloc_workspaces();
    if (ret)
	    return ret;

    ret = jffs2_register_compressor(&jffs2_zlib_comp);
    if (ret)
	    free_workspaces();

    return ret;
}

void jffs2_zlib_exit(void)
{
    jffs2_unregister_compressor(&jffs2_zlib_comp);
    free_workspaces();
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/compr_zlib.c */
/************************************************************/
/*
 * JFFS2 -- Journalling Flash File System, Version 2.
 *
 * Copyright © 2007 Nokia Corporation. All rights reserved.
 * Copyright © 2004-2010 David Woodhouse <dwmw2@infradead.org>
 *
 * Created by Richard Purdie <rpurdie@openedhand.com>
 *
 * For licensing information, see the file 'LICENCE' in this directory.
 *
 */

// #include <linux/kernel.h>
// #include <linux/sched.h>
// #include <linux/vmalloc.h>
// #include <linux/init.h>
#include <linux/lzo.h>
// #include "compr.h"

static void *lzo_mem;
static void *lzo_compress_buf;
static DEFINE_MUTEX(deflate_mutex);	/* for lzo_mem and lzo_compress_buf */

static void free_workspace(void)
{
	vfree(lzo_mem);
	vfree(lzo_compress_buf);
}

static int __init alloc_workspace(void)
{
	lzo_mem = vmalloc(LZO1X_MEM_COMPRESS);
	lzo_compress_buf = vmalloc(lzo1x_worst_compress(PAGE_SIZE));

	if (!lzo_mem || !lzo_compress_buf) {
		free_workspace();
		return -ENOMEM;
	}

	return 0;
}

static int jffs2_lzo_compress(unsigned char *data_in, unsigned char *cpage_out,
			      uint32_t *sourcelen, uint32_t *dstlen)
{
	size_t compress_size;
	int ret;

	mutex_lock(&deflate_mutex);
	ret = lzo1x_1_compress(data_in, *sourcelen, lzo_compress_buf, &compress_size, lzo_mem);
	if (ret != LZO_E_OK)
		goto fail;

	if (compress_size > *dstlen)
		goto fail;

	memcpy(cpage_out, lzo_compress_buf, compress_size);
	mutex_unlock(&deflate_mutex);

	*dstlen = compress_size;
	return 0;

 fail:
	mutex_unlock(&deflate_mutex);
	return -1;
}

static int jffs2_lzo_decompress(unsigned char *data_in, unsigned char *cpage_out,
				 uint32_t srclen, uint32_t destlen)
{
	size_t dl = destlen;
	int ret;

	ret = lzo1x_decompress_safe(data_in, srclen, cpage_out, &dl);

	if (ret != LZO_E_OK || dl != destlen)
		return -1;

	return 0;
}

static struct jffs2_compressor jffs2_lzo_comp = {
	.priority = JFFS2_LZO_PRIORITY,
	.name = "lzo",
	.compr = JFFS2_COMPR_LZO,
	.compress = &jffs2_lzo_compress,
	.decompress = &jffs2_lzo_decompress,
	.disabled = 0,
};

int __init jffs2_lzo_init(void)
{
	int ret;

	ret = alloc_workspace();
	if (ret < 0)
		return ret;

	ret = jffs2_register_compressor(&jffs2_lzo_comp);
	if (ret)
		free_workspace();

	return ret;
}

void jffs2_lzo_exit(void)
{
	jffs2_unregister_compressor(&jffs2_lzo_comp);
	free_workspace();
}
/************************************************************/
/* ../linux-3.17/fs/jffs2/compr_lzo.c */
/************************************************************/
