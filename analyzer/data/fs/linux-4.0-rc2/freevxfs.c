/*
 * Copyright (c) 2000-2001 Christoph Hellwig.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Veritas filesystem driver - filesystem to disk block mapping.
 */
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/kernel.h>
#include "../../inc/__fss.h"

#include "vxfs.h"
#include "vxfs_inode.h"
#include "vxfs_extern.h"
#include "../../inc/__fss.h"


#ifdef DIAGNOSTIC
static void
vxfs_typdump(struct vxfs_typed *typ)
{
	printk(KERN_DEBUG "type=%Lu ", typ->vt_hdr >> VXFS_TYPED_TYPESHIFT);
	printk("offset=%Lx ", typ->vt_hdr & VXFS_TYPED_OFFSETMASK);
	printk("block=%x ", typ->vt_block);
	printk("size=%x\n", typ->vt_size);
}
#endif

/**
 * vxfs_bmap_ext4 - do bmap for ext4 extents
 * @ip:		pointer to the inode we do bmap for
 * @iblock:	logical block.
 *
 * Description:
 *   vxfs_bmap_ext4 performs the bmap operation for inodes with
 *   ext4-style extents (which are much like the traditional UNIX
 *   inode organisation).
 *
 * Returns:
 *   The physical block number on success, else Zero.
 */
static daddr_t
vxfs_bmap_ext4(struct inode *ip, long bn)
{
	struct super_block *sb = ip->i_sb;
	struct vxfs_inode_info *vip = VXFS_INO(ip);
	unsigned long bsize = sb->s_blocksize;
	u32 indsize = vip->vii_ext4.ve4_indsize;
	int i;

	if (indsize > sb->s_blocksize)
		goto fail_size;

	for (i = 0; i < VXFS_NDADDR; i++) {
		struct direct *d = vip->vii_ext4.ve4_direct + i;
		if (bn >= 0 && bn < d->size)
			return (bn + d->extent);
		bn -= d->size;
	}

	if ((bn / (indsize * indsize * bsize / 4)) == 0) {
		struct buffer_head *buf;
		daddr_t	bno;
		u32 *indir;

		buf = sb_bread(sb, vip->vii_ext4.ve4_indir[0]);
		if (!buf || !buffer_mapped(buf))
			goto fail_buf;

		indir = (u32 *)buf->b_data;
		bno = indir[(bn/indsize) % (indsize*bn)] + (bn%indsize);

		brelse(buf);
		return bno;
	} else
		printk(KERN_WARNING "no matching indir?");

	return 0;

fail_size:
	printk("vxfs: indirect extent too big!\n");
fail_buf:
	return 0;
}

/**
 * vxfs_bmap_indir - recursion for vxfs_bmap_typed
 * @ip:		pointer to the inode we do bmap for
 * @indir:	indirect block we start reading at
 * @size:	size of the typed area to search
 * @block:	partially result from further searches
 *
 * Description:
 *   vxfs_bmap_indir reads a &struct vxfs_typed at @indir
 *   and performs the type-defined action.
 *
 * Return Value:
 *   The physical block number on success, else Zero.
 *
 * Note:
 *   Kernelstack is rare.  Unrecurse?
 */
static daddr_t
vxfs_bmap_indir(struct inode *ip, long indir, int size, long block)
{
	struct buffer_head		*bp = NULL;
	daddr_t				pblock = 0;
	int				i;

	for (i = 0; i < size * VXFS_TYPED_PER_BLOCK(ip->i_sb); i++) {
		struct vxfs_typed	*typ;
		int64_t			off;

		bp = sb_bread(ip->i_sb,
				indir + (i / VXFS_TYPED_PER_BLOCK(ip->i_sb)));
		if (!bp || !buffer_mapped(bp))
			return 0;

		typ = ((struct vxfs_typed *)bp->b_data) +
			(i % VXFS_TYPED_PER_BLOCK(ip->i_sb));
		off = (typ->vt_hdr & VXFS_TYPED_OFFSETMASK);

		if (block < off) {
			brelse(bp);
			continue;
		}

		switch ((u_int32_t)(typ->vt_hdr >> VXFS_TYPED_TYPESHIFT)) {
		case VXFS_TYPED_INDIRECT:
			pblock = vxfs_bmap_indir(ip, typ->vt_block,
					typ->vt_size, block - off);
			if (pblock == -2)
				break;
			goto out;
		case VXFS_TYPED_DATA:
			if ((block - off) >= typ->vt_size)
				break;
			pblock = (typ->vt_block + block - off);
			goto out;
		case VXFS_TYPED_INDIRECT_DEV4:
		case VXFS_TYPED_DATA_DEV4: {
			struct vxfs_typed_dev4	*typ4 =
				(struct vxfs_typed_dev4 *)typ;

			printk(KERN_INFO "\n\nTYPED_DEV4 detected!\n");
			printk(KERN_INFO "block: %Lu\tsize: %Ld\tdev: %d\n",
			       (unsigned long long) typ4->vd4_block,
			       (unsigned long long) typ4->vd4_size,
			       typ4->vd4_dev);
			goto fail;
		}
		default:
			BUG();
		}
		brelse(bp);
	}

fail:
	pblock = 0;
out:
	brelse(bp);
	return (pblock);
}

/**
 * vxfs_bmap_typed - bmap for typed extents
 * @ip:		pointer to the inode we do bmap for
 * @iblock:	logical block
 *
 * Description:
 *   Performs the bmap operation for typed extents.
 *
 * Return Value:
 *   The physical block number on success, else Zero.
 */
static daddr_t
vxfs_bmap_typed(struct inode *ip, long iblock)
{
	struct vxfs_inode_info		*vip = VXFS_INO(ip);
	daddr_t				pblock = 0;
	int				i;

	for (i = 0; i < VXFS_NTYPED; i++) {
		struct vxfs_typed	*typ = vip->vii_org.typed + i;
		int64_t			off = (typ->vt_hdr & VXFS_TYPED_OFFSETMASK);

#ifdef DIAGNOSTIC
		vxfs_typdump(typ);
#endif
		if (iblock < off)
			continue;
		switch ((u_int32_t)(typ->vt_hdr >> VXFS_TYPED_TYPESHIFT)) {
		case VXFS_TYPED_INDIRECT:
			pblock = vxfs_bmap_indir(ip, typ->vt_block,
					typ->vt_size, iblock - off);
			if (pblock == -2)
				break;
			return (pblock);
		case VXFS_TYPED_DATA:
			if ((iblock - off) < typ->vt_size)
				return (typ->vt_block + iblock - off);
			break;
		case VXFS_TYPED_INDIRECT_DEV4:
		case VXFS_TYPED_DATA_DEV4: {
			struct vxfs_typed_dev4	*typ4 =
				(struct vxfs_typed_dev4 *)typ;

			printk(KERN_INFO "\n\nTYPED_DEV4 detected!\n");
			printk(KERN_INFO "block: %Lu\tsize: %Ld\tdev: %d\n",
			       (unsigned long long) typ4->vd4_block,
			       (unsigned long long) typ4->vd4_size,
			       typ4->vd4_dev);
			return 0;
		}
		default:
			BUG();
		}
	}

	return 0;
}

/**
 * vxfs_bmap1 - vxfs-internal bmap operation
 * @ip:			pointer to the inode we do bmap for
 * @iblock:		logical block
 *
 * Description:
 *   vxfs_bmap1 perfoms a logical to physical block mapping
 *   for vxfs-internal purposes.
 *
 * Return Value:
 *   The physical block number on success, else Zero.
 */
daddr_t
vxfs_bmap1(struct inode *ip, long iblock)
{
	struct vxfs_inode_info		*vip = VXFS_INO(ip);

	if (VXFS_ISEXT4(vip))
		return vxfs_bmap_ext4(ip, iblock);
	if (VXFS_ISTYPED(vip))
		return vxfs_bmap_typed(ip, iblock);
	if (VXFS_ISNONE(vip))
		goto unsupp;
	if (VXFS_ISIMMED(vip))
		goto unsupp;

	printk(KERN_WARNING "vxfs: inode %ld has no valid orgtype (%x)\n",
			ip->i_ino, vip->vii_orgtype);
	BUG();

unsupp:
	printk(KERN_WARNING "vxfs: inode %ld has an unsupported orgtype (%x)\n",
			ip->i_ino, vip->vii_orgtype);
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/freevxfs/vxfs_bmap.c */
/************************************************************/
/*
 * Copyright (c) 2000-2001 Christoph Hellwig.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Veritas filesystem driver - fileset header routines.
 */
// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "../../inc/__fss.h"

// #include "vxfs.h"
// #include "vxfs_inode.h"
// #include "vxfs_extern.h"
#include "vxfs_fshead.h"
#include "../../inc/__fss.h"


#ifdef DIAGNOSTIC
static void
vxfs_dumpfsh(struct vxfs_fsh *fhp)
{
	printk("\n\ndumping fileset header:\n");
	printk("----------------------------\n");
	printk("version: %u\n", fhp->fsh_version);
	printk("fsindex: %u\n", fhp->fsh_fsindex);
	printk("iauino: %u\tninodes:%u\n",
			fhp->fsh_iauino, fhp->fsh_ninodes);
	printk("maxinode: %u\tlctino: %u\n",
			fhp->fsh_maxinode, fhp->fsh_lctino);
	printk("nau: %u\n", fhp->fsh_nau);
	printk("ilistino[0]: %u\tilistino[1]: %u\n",
			fhp->fsh_ilistino[0], fhp->fsh_ilistino[1]);
}
#endif

/**
 * vxfs_getfsh - read fileset header into memory
 * @ip:		the (fake) fileset header inode
 * @which:	0 for the structural, 1 for the primary fsh.
 *
 * Description:
 *   vxfs_getfsh reads either the structural or primary fileset header
 *   described by @ip into memory.
 *
 * Returns:
 *   The fileset header structure on success, else Zero.
 */
static struct vxfs_fsh *
vxfs_getfsh(struct inode *ip, int which)
{
	struct buffer_head		*bp;

	bp = vxfs_bread(ip, which);
	if (bp) {
		struct vxfs_fsh		*fhp;

		if (!(fhp = kmalloc(sizeof(*fhp), GFP_KERNEL)))
			goto out;
		memcpy(fhp, bp->b_data, sizeof(*fhp));

		put_bh(bp);
		return (fhp);
	}
out:
	brelse(bp);
	return NULL;
}

/**
 * vxfs_read_fshead - read the fileset headers
 * @sbp:	superblock to which the fileset belongs
 *
 * Description:
 *   vxfs_read_fshead will fill the inode and structural inode list in @sb.
 *
 * Returns:
 *   Zero on success, else a negative error code (-EINVAL).
 */
int
vxfs_read_fshead(struct super_block *sbp)
{
	struct vxfs_sb_info		*infp = VXFS_SBI(sbp);
	struct vxfs_fsh			*pfp, *sfp;
	struct vxfs_inode_info		*vip, *tip;

	vip = vxfs_blkiget(sbp, infp->vsi_iext, infp->vsi_fshino);
	if (!vip) {
		printk(KERN_ERR "vxfs: unable to read fsh inode\n");
		return -EINVAL;
	}
	if (!VXFS_ISFSH(vip)) {
		printk(KERN_ERR "vxfs: fsh list inode is of wrong type (%x)\n",
				vip->vii_mode & VXFS_TYPE_MASK); 
		goto out_free_fship;
	}


#ifdef DIAGNOSTIC
	printk("vxfs: fsh inode dump:\n");
	vxfs_dumpi(vip, infp->vsi_fshino);
#endif

	infp->vsi_fship = vxfs_get_fake_inode(sbp, vip);
	if (!infp->vsi_fship) {
		printk(KERN_ERR "vxfs: unable to get fsh inode\n");
		goto out_free_fship;
	}

	sfp = vxfs_getfsh(infp->vsi_fship, 0);
	if (!sfp) {
		printk(KERN_ERR "vxfs: unable to get structural fsh\n");
		goto out_iput_fship;
	} 

#ifdef DIAGNOSTIC
	vxfs_dumpfsh(sfp);
#endif

	pfp = vxfs_getfsh(infp->vsi_fship, 1);
	if (!pfp) {
		printk(KERN_ERR "vxfs: unable to get primary fsh\n");
		goto out_free_sfp;
	}

#ifdef DIAGNOSTIC
	vxfs_dumpfsh(pfp);
#endif

	tip = vxfs_blkiget(sbp, infp->vsi_iext, sfp->fsh_ilistino[0]);
	if (!tip)
		goto out_free_pfp;

	infp->vsi_stilist = vxfs_get_fake_inode(sbp, tip);
	if (!infp->vsi_stilist) {
		printk(KERN_ERR "vxfs: unable to get structural list inode\n");
		kfree(tip);
		goto out_free_pfp;
	}
	if (!VXFS_ISILT(VXFS_INO(infp->vsi_stilist))) {
		printk(KERN_ERR "vxfs: structural list inode is of wrong type (%x)\n",
				VXFS_INO(infp->vsi_stilist)->vii_mode & VXFS_TYPE_MASK); 
		goto out_iput_stilist;
	}

	tip = vxfs_stiget(sbp, pfp->fsh_ilistino[0]);
	if (!tip)
		goto out_iput_stilist;
	infp->vsi_ilist = vxfs_get_fake_inode(sbp, tip);
	if (!infp->vsi_ilist) {
		printk(KERN_ERR "vxfs: unable to get inode list inode\n");
		kfree(tip);
		goto out_iput_stilist;
	}
	if (!VXFS_ISILT(VXFS_INO(infp->vsi_ilist))) {
		printk(KERN_ERR "vxfs: inode list inode is of wrong type (%x)\n",
				VXFS_INO(infp->vsi_ilist)->vii_mode & VXFS_TYPE_MASK);
		goto out_iput_ilist;
	}

	return 0;

 out_iput_ilist:
 	iput(infp->vsi_ilist);
 out_iput_stilist:
 	iput(infp->vsi_stilist);
 out_free_pfp:
	kfree(pfp);
 out_free_sfp:
 	kfree(sfp);
 out_iput_fship:
	iput(infp->vsi_fship);
	return -EINVAL;
 out_free_fship:
 	kfree(vip);
	return -EINVAL;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/freevxfs/vxfs_fshead.c */
/************************************************************/
/*
 * Copyright (c) 2000-2001 Christoph Hellwig.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Veritas filesystem driver - support for 'immed' inodes.
 */
// #include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/namei.h>
#include "../../inc/__fss.h"

// #include "vxfs.h"
// #include "vxfs_extern.h"
// #include "vxfs_inode.h"


static void *	vxfs_immed_follow_link(struct dentry *, struct nameidata *);

static int	vxfs_immed_readpage(struct file *, struct page *);

/*
 * Inode operations for immed symlinks.
 *
 * Unliked all other operations we do not go through the pagecache,
 * but do all work directly on the inode.
 */
const struct inode_operations vxfs_immed_symlink_iops = {
	.readlink =		generic_readlink,
	.follow_link =		vxfs_immed_follow_link,
};

/*
 * Address space operations for immed files and directories.
 */
const struct address_space_operations vxfs_immed_aops = {
	.readpage =		vxfs_immed_readpage,
};

/**
 * vxfs_immed_follow_link - follow immed symlink
 * @dp:		dentry for the link
 * @np:		pathname lookup data for the current path walk
 *
 * Description:
 *   vxfs_immed_follow_link restarts the pathname lookup with
 *   the data obtained from @dp.
 *
 * Returns:
 *   Zero on success, else a negative error code.
 */
static void *
vxfs_immed_follow_link(struct dentry *dp, struct nameidata *np)
{
	struct vxfs_inode_info		*vip = VXFS_INO(dp->d_inode);
	nd_set_link(np, vip->vii_immed.vi_immed);
	return NULL;
}

/**
 * vxfs_immed_readpage - read part of an immed inode into pagecache
 * @file:	file context (unused)
 * @page:	page frame to fill in.
 *
 * Description:
 *   vxfs_immed_readpage reads a part of the immed area of the
 *   file that hosts @pp into the pagecache.
 *
 * Returns:
 *   Zero on success, else a negative error code.
 *
 * Locking status:
 *   @page is locked and will be unlocked.
 */
static int
vxfs_immed_readpage(struct file *fp, struct page *pp)
{
	struct vxfs_inode_info	*vip = VXFS_INO(pp->mapping->host);
	u_int64_t	offset = (u_int64_t)pp->index << PAGE_CACHE_SHIFT;
	caddr_t		kaddr;

	kaddr = kmap(pp);
	memcpy(kaddr, vip->vii_immed.vi_immed + offset, PAGE_CACHE_SIZE);
	kunmap(pp);
	
	flush_dcache_page(pp);
	SetPageUptodate(pp);
        unlock_page(pp);

	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/freevxfs/vxfs_immed.c */
/************************************************************/
/*
 * Copyright (c) 2000-2001 Christoph Hellwig.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Veritas filesystem driver - inode routines.
 */
// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/pagemap.h>
// #include <linux/kernel.h>
// #include <linux/slab.h>

// #include "vxfs.h"
// #include "vxfs_inode.h"
// #include "vxfs_extern.h"


struct kmem_cache		*vxfs_inode_cachep;


#ifdef DIAGNOSTIC
/*
 * Dump inode contents (partially).
 */
void
vxfs_dumpi(struct vxfs_inode_info *vip, ino_t ino)
{
	printk(KERN_DEBUG "\n\n");
	if (ino)
		printk(KERN_DEBUG "dumping vxfs inode %ld\n", ino);
	else
		printk(KERN_DEBUG "dumping unknown vxfs inode\n");

	printk(KERN_DEBUG "---------------------------\n");
	printk(KERN_DEBUG "mode is %x\n", vip->vii_mode);
	printk(KERN_DEBUG "nlink:%u, uid:%u, gid:%u\n",
			vip->vii_nlink, vip->vii_uid, vip->vii_gid);
	printk(KERN_DEBUG "size:%Lx, blocks:%u\n",
			vip->vii_size, vip->vii_blocks);
	printk(KERN_DEBUG "orgtype:%u\n", vip->vii_orgtype);
}
#endif


/**
 * vxfs_blkiget - find inode based on extent #
 * @sbp:	superblock of the filesystem we search in
 * @extent:	number of the extent to search
 * @ino:	inode number to search
 *
 * Description:
 *  vxfs_blkiget searches inode @ino in the filesystem described by
 *  @sbp in the extent @extent.
 *  Returns the matching VxFS inode on success, else a NULL pointer.
 *
 * NOTE:
 *  While __vxfs_iget uses the pagecache vxfs_blkiget uses the
 *  buffercache.  This function should not be used outside the
 *  read_super() method, otherwise the data may be incoherent.
 */
struct vxfs_inode_info *
vxfs_blkiget(struct super_block *sbp, u_long extent, ino_t ino)
{
	struct buffer_head		*bp;
	u_long				block, offset;

	block = extent + ((ino * VXFS_ISIZE) / sbp->s_blocksize);
	offset = ((ino % (sbp->s_blocksize / VXFS_ISIZE)) * VXFS_ISIZE);
	bp = sb_bread(sbp, block);

	if (bp && buffer_mapped(bp)) {
		struct vxfs_inode_info	*vip;
		struct vxfs_dinode	*dip;

		if (!(vip = kmem_cache_alloc(vxfs_inode_cachep, GFP_KERNEL)))
			goto fail;
		dip = (struct vxfs_dinode *)(bp->b_data + offset);
		memcpy(vip, dip, sizeof(*vip));
#ifdef DIAGNOSTIC
		vxfs_dumpi(vip, ino);
#endif
		brelse(bp);
		return (vip);
	}

fail:
	printk(KERN_WARNING "vxfs: unable to read block %ld\n", block);
	brelse(bp);
	return NULL;
}

/**
 * __vxfs_iget - generic find inode facility
 * @sbp:		VFS superblock
 * @ino:		inode number
 * @ilistp:		inode list
 *
 * Description:
 *  Search the for inode number @ino in the filesystem
 *  described by @sbp.  Use the specified inode table (@ilistp).
 *  Returns the matching VxFS inode on success, else an error code.
 */
static struct vxfs_inode_info *
__vxfs_iget(ino_t ino, struct inode *ilistp)
{
	struct page			*pp;
	u_long				offset;

	offset = (ino % (PAGE_SIZE / VXFS_ISIZE)) * VXFS_ISIZE;
	pp = vxfs_get_page(ilistp->i_mapping, ino * VXFS_ISIZE / PAGE_SIZE);

	if (!IS_ERR(pp)) {
		struct vxfs_inode_info	*vip;
		struct vxfs_dinode	*dip;
		caddr_t			kaddr = (char *)page_address(pp);

		if (!(vip = kmem_cache_alloc(vxfs_inode_cachep, GFP_KERNEL)))
			goto fail;
		dip = (struct vxfs_dinode *)(kaddr + offset);
		memcpy(vip, dip, sizeof(*vip));
#ifdef DIAGNOSTIC
		vxfs_dumpi(vip, ino);
#endif
		vxfs_put_page(pp);
		return (vip);
	}

	printk(KERN_WARNING "vxfs: error on page %p\n", pp);
	return ERR_CAST(pp);

fail:
	printk(KERN_WARNING "vxfs: unable to read inode %ld\n", (unsigned long)ino);
	vxfs_put_page(pp);
	return ERR_PTR(-ENOMEM);
}

/**
 * vxfs_stiget - find inode using the structural inode list
 * @sbp:	VFS superblock
 * @ino:	inode #
 *
 * Description:
 *  Find inode @ino in the filesystem described by @sbp using
 *  the structural inode list.
 *  Returns the matching VxFS inode on success, else a NULL pointer.
 */
struct vxfs_inode_info *
vxfs_stiget(struct super_block *sbp, ino_t ino)
{
	struct vxfs_inode_info *vip;

	vip = __vxfs_iget(ino, VXFS_SBI(sbp)->vsi_stilist);
	return IS_ERR(vip) ? NULL : vip;
}

/**
 * vxfs_transmod - mode for a VxFS inode
 * @vip:	VxFS inode
 *
 * Description:
 *  vxfs_transmod returns a Linux mode_t for a given
 *  VxFS inode structure.
 */
static __inline__ umode_t
vxfs_transmod(struct vxfs_inode_info *vip)
{
	umode_t			ret = vip->vii_mode & ~VXFS_TYPE_MASK;

	if (VXFS_ISFIFO(vip))
		ret |= S_IFIFO;
	if (VXFS_ISCHR(vip))
		ret |= S_IFCHR;
	if (VXFS_ISDIR(vip))
		ret |= S_IFDIR;
	if (VXFS_ISBLK(vip))
		ret |= S_IFBLK;
	if (VXFS_ISLNK(vip))
		ret |= S_IFLNK;
	if (VXFS_ISREG(vip))
		ret |= S_IFREG;
	if (VXFS_ISSOC(vip))
		ret |= S_IFSOCK;

	return (ret);
}

/**
 * vxfs_iinit- helper to fill inode fields
 * @ip:		VFS inode
 * @vip:	VxFS inode
 *
 * Description:
 *  vxfs_instino is a helper function to fill in all relevant
 *  fields in @ip from @vip.
 */
static void
vxfs_iinit(struct inode *ip, struct vxfs_inode_info *vip)
{

	ip->i_mode = vxfs_transmod(vip);
	i_uid_write(ip, (uid_t)vip->vii_uid);
	i_gid_write(ip, (gid_t)vip->vii_gid);

	set_nlink(ip, vip->vii_nlink);
	ip->i_size = vip->vii_size;

	ip->i_atime.tv_sec = vip->vii_atime;
	ip->i_ctime.tv_sec = vip->vii_ctime;
	ip->i_mtime.tv_sec = vip->vii_mtime;
	ip->i_atime.tv_nsec = 0;
	ip->i_ctime.tv_nsec = 0;
	ip->i_mtime.tv_nsec = 0;

	ip->i_blocks = vip->vii_blocks;
	ip->i_generation = vip->vii_gen;

	ip->i_private = vip;
	
}

/**
 * vxfs_get_fake_inode - get fake inode structure
 * @sbp:		filesystem superblock
 * @vip:		fspriv inode
 *
 * Description:
 *  vxfs_fake_inode gets a fake inode (not in the inode hash) for a
 *  superblock, vxfs_inode pair.
 *  Returns the filled VFS inode.
 */
struct inode *
vxfs_get_fake_inode(struct super_block *sbp, struct vxfs_inode_info *vip)
{
	struct inode			*ip = NULL;

	if ((ip = new_inode(sbp))) {
		ip->i_ino = get_next_ino();
		vxfs_iinit(ip, vip);
		ip->i_mapping->a_ops = &vxfs_aops;
	}
	return (ip);
}

/**
 * vxfs_put_fake_inode - free faked inode
 * *ip:			VFS inode
 *
 * Description:
 *  vxfs_put_fake_inode frees all data associated with @ip.
 */
void
vxfs_put_fake_inode(struct inode *ip)
{
	iput(ip);
}

/**
 * vxfs_iget - get an inode
 * @sbp:	the superblock to get the inode for
 * @ino:	the number of the inode to get
 *
 * Description:
 *  vxfs_read_inode creates an inode, reads the disk inode for @ino and fills
 *  in all relevant fields in the new inode.
 */
struct inode *
vxfs_iget(struct super_block *sbp, ino_t ino)
{
	struct vxfs_inode_info		*vip;
	const struct address_space_operations	*aops;
	struct inode *ip;

	ip = iget_locked(sbp, ino);
	if (!ip)
		return ERR_PTR(-ENOMEM);
	if (!(ip->i_state & I_NEW))
		return ip;

	vip = __vxfs_iget(ino, VXFS_SBI(sbp)->vsi_ilist);
	if (IS_ERR(vip)) {
		iget_failed(ip);
		return ERR_CAST(vip);
	}

	vxfs_iinit(ip, vip);

	if (VXFS_ISIMMED(vip))
		aops = &vxfs_immed_aops;
	else
		aops = &vxfs_aops;

	if (S_ISREG(ip->i_mode)) {
		ip->i_fop = &generic_ro_fops;
		ip->i_mapping->a_ops = aops;
	} else if (S_ISDIR(ip->i_mode)) {
		ip->i_op = &vxfs_dir_inode_ops;
		ip->i_fop = &vxfs_dir_operations;
		ip->i_mapping->a_ops = aops;
	} else if (S_ISLNK(ip->i_mode)) {
		if (!VXFS_ISIMMED(vip)) {
			ip->i_op = &page_symlink_inode_operations;
			ip->i_mapping->a_ops = &vxfs_aops;
		} else {
			ip->i_op = &vxfs_immed_symlink_iops;
			vip->vii_immed.vi_immed[ip->i_size] = '\0';
		}
	} else
		init_special_inode(ip, ip->i_mode, old_decode_dev(vip->vii_rdev));

	unlock_new_inode(ip);
	return ip;
}

static void vxfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(vxfs_inode_cachep, inode->i_private);
}

/**
 * vxfs_evict_inode - remove inode from main memory
 * @ip:		inode to discard.
 *
 * Description:
 *  vxfs_evict_inode() is called on the final iput and frees the private
 *  inode area.
 */
void
vxfs_evict_inode(struct inode *ip)
{
	truncate_inode_pages_final(&ip->i_data);
	clear_inode(ip);
	call_rcu(&ip->i_rcu, vxfs_i_callback);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/freevxfs/vxfs_inode.c */
/************************************************************/
/*
 * Copyright (c) 2000-2001 Christoph Hellwig.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Veritas filesystem driver - lookup and other directory related code.
 */
// #include <linux/fs.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/highmem.h>
// #include <linux/kernel.h>
// #include <linux/pagemap.h>
#include "../../inc/__fss.h"

// #include "vxfs.h"
#include "vxfs_dir.h"
// #include "vxfs_inode.h"
// #include "vxfs_extern.h"
#include "../../inc/__fss.h"

/*
 * Number of VxFS blocks per page.
 */
#define VXFS_BLOCK_PER_PAGE(sbp)  ((PAGE_CACHE_SIZE / (sbp)->s_blocksize))


static struct dentry *	vxfs_lookup(struct inode *, struct dentry *, unsigned int);
static int		vxfs_readdir(struct file *, struct dir_context *);

const struct inode_operations vxfs_dir_inode_ops = {
	.lookup =		vxfs_lookup,
};

const struct file_operations vxfs_dir_operations = {
	.llseek =		generic_file_llseek,
	.read =			generic_read_dir,
	.iterate =		vxfs_readdir,
};

 
static inline u_long
dir_pages(struct inode *inode)
{
	return (inode->i_size + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
}
 
static inline u_long
dir_blocks(struct inode *ip)
{
	u_long			bsize = ip->i_sb->s_blocksize;
	return (ip->i_size + bsize - 1) & ~(bsize - 1);
}

/*
 * NOTE! unlike strncmp, vxfs_match returns 1 for success, 0 for failure.
 *
 * len <= VXFS_NAMELEN and de != NULL are guaranteed by caller.
 */
static inline int
vxfs_match(int len, const char * const name, struct vxfs_direct *de)
{
	if (len != de->d_namelen)
		return 0;
	if (!de->d_ino)
		return 0;
	return !memcmp(name, de->d_name, len);
}

static inline struct vxfs_direct *
vxfs_next_entry(struct vxfs_direct *de)
{
	return ((struct vxfs_direct *)((char*)de + de->d_reclen));
}

/**
 * vxfs_find_entry - find a mathing directory entry for a dentry
 * @ip:		directory inode
 * @dp:		dentry for which we want to find a direct
 * @ppp:	gets filled with the page the return value sits in
 *
 * Description:
 *   vxfs_find_entry finds a &struct vxfs_direct for the VFS directory
 *   cache entry @dp.  @ppp will be filled with the page the return
 *   value resides in.
 *
 * Returns:
 *   The wanted direct on success, else a NULL pointer.
 */
static struct vxfs_direct *
vxfs_find_entry(struct inode *ip, struct dentry *dp, struct page **ppp)
{
	u_long				npages, page, nblocks, pblocks, block;
	u_long				bsize = ip->i_sb->s_blocksize;
	const char			*name = dp->d_name.name;
	int				namelen = dp->d_name.len;

	npages = dir_pages(ip);
	nblocks = dir_blocks(ip);
	pblocks = VXFS_BLOCK_PER_PAGE(ip->i_sb);
	
	for (page = 0; page < npages; page++) {
		caddr_t			kaddr;
		struct page		*pp;

		pp = vxfs_get_page(ip->i_mapping, page);
		if (IS_ERR(pp))
			continue;
		kaddr = (caddr_t)page_address(pp);

		for (block = 0; block <= nblocks && block <= pblocks; block++) {
			caddr_t			baddr, limit;
			struct vxfs_dirblk	*dbp;
			struct vxfs_direct	*de;

			baddr = kaddr + (block * bsize);
			limit = baddr + bsize - VXFS_DIRLEN(1);
			
			dbp = (struct vxfs_dirblk *)baddr;
			de = (struct vxfs_direct *)(baddr + VXFS_DIRBLKOV(dbp));

			for (; (caddr_t)de <= limit; de = vxfs_next_entry(de)) {
				if (!de->d_reclen)
					break;
				if (!de->d_ino)
					continue;
				if (vxfs_match(namelen, name, de)) {
					*ppp = pp;
					return (de);
				}
			}
		}
		vxfs_put_page(pp);
	}

	return NULL;
}

/**
 * vxfs_inode_by_name - find inode number for dentry
 * @dip:	directory to search in
 * @dp:		dentry we search for
 *
 * Description:
 *   vxfs_inode_by_name finds out the inode number of
 *   the path component described by @dp in @dip.
 *
 * Returns:
 *   The wanted inode number on success, else Zero.
 */
static ino_t
vxfs_inode_by_name(struct inode *dip, struct dentry *dp)
{
	struct vxfs_direct		*de;
	struct page			*pp;
	ino_t				ino = 0;

	de = vxfs_find_entry(dip, dp, &pp);
	if (de) {
		ino = de->d_ino;
		kunmap(pp);
		page_cache_release(pp);
	}
	
	return (ino);
}

/**
 * vxfs_lookup - lookup pathname component
 * @dip:	dir in which we lookup
 * @dp:		dentry we lookup
 * @flags:	lookup flags
 *
 * Description:
 *   vxfs_lookup tries to lookup the pathname component described
 *   by @dp in @dip.
 *
 * Returns:
 *   A NULL-pointer on success, else an negative error code encoded
 *   in the return pointer.
 */
static struct dentry *
vxfs_lookup(struct inode *dip, struct dentry *dp, unsigned int flags)
{
	struct inode		*ip = NULL;
	ino_t			ino;
			 
	if (dp->d_name.len > VXFS_NAMELEN)
		return ERR_PTR(-ENAMETOOLONG);
				 
	ino = vxfs_inode_by_name(dip, dp);
	if (ino) {
		ip = vxfs_iget(dip->i_sb, ino);
		if (IS_ERR(ip))
			return ERR_CAST(ip);
	}
	d_add(dp, ip);
	return NULL;
}

/**
 * vxfs_readdir - read a directory
 * @fp:		the directory to read
 * @retp:	return buffer
 * @filler:	filldir callback
 *
 * Description:
 *   vxfs_readdir fills @retp with directory entries from @fp
 *   using the VFS supplied callback @filler.
 *
 * Returns:
 *   Zero.
 */
static int
vxfs_readdir(struct file *fp, struct dir_context *ctx)
{
	struct inode		*ip = file_inode(fp);
	struct super_block	*sbp = ip->i_sb;
	u_long			bsize = sbp->s_blocksize;
	u_long			page, npages, block, pblocks, nblocks, offset;
	loff_t			pos;

	if (ctx->pos == 0) {
		if (!dir_emit_dot(fp, ctx))
			return 0;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		if (!dir_emit(ctx, "..", 2, VXFS_INO(ip)->vii_dotdot, DT_DIR))
			return 0;
		ctx->pos = 2;
	}
	pos = ctx->pos - 2;
	
	if (pos > VXFS_DIRROUND(ip->i_size))
		return 0;

	npages = dir_pages(ip);
	nblocks = dir_blocks(ip);
	pblocks = VXFS_BLOCK_PER_PAGE(sbp);

	page = pos >> PAGE_CACHE_SHIFT;
	offset = pos & ~PAGE_CACHE_MASK;
	block = (u_long)(pos >> sbp->s_blocksize_bits) % pblocks;

	for (; page < npages; page++, block = 0) {
		char			*kaddr;
		struct page		*pp;

		pp = vxfs_get_page(ip->i_mapping, page);
		if (IS_ERR(pp))
			continue;
		kaddr = (char *)page_address(pp);

		for (; block <= nblocks && block <= pblocks; block++) {
			char			*baddr, *limit;
			struct vxfs_dirblk	*dbp;
			struct vxfs_direct	*de;

			baddr = kaddr + (block * bsize);
			limit = baddr + bsize - VXFS_DIRLEN(1);
	
			dbp = (struct vxfs_dirblk *)baddr;
			de = (struct vxfs_direct *)
				(offset ?
				 (kaddr + offset) :
				 (baddr + VXFS_DIRBLKOV(dbp)));

			for (; (char *)de <= limit; de = vxfs_next_entry(de)) {
				if (!de->d_reclen)
					break;
				if (!de->d_ino)
					continue;

				offset = (char *)de - kaddr;
				ctx->pos = ((page << PAGE_CACHE_SHIFT) | offset) + 2;
				if (!dir_emit(ctx, de->d_name, de->d_namelen,
					de->d_ino, DT_UNKNOWN)) {
					vxfs_put_page(pp);
					return 0;
				}
			}
			offset = 0;
		}
		vxfs_put_page(pp);
		offset = 0;
	}
	ctx->pos = ((page << PAGE_CACHE_SHIFT) | offset) + 2;
	return 0;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/freevxfs/vxfs_lookup.c */
/************************************************************/
/*
 * Copyright (c) 2000-2001 Christoph Hellwig.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* 
 * Veritas filesystem driver - object location table support.
 */
// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/kernel.h>

// #include "vxfs.h"
#include "vxfs_olt.h"
// #include "vxfs_extern.h"
#include "../../inc/__fss.h"


static inline void
vxfs_get_fshead(struct vxfs_oltfshead *fshp, struct vxfs_sb_info *infp)
{
	BUG_ON(infp->vsi_fshino);
	infp->vsi_fshino = fshp->olt_fsino[0];
}

static inline void
vxfs_get_ilist(struct vxfs_oltilist *ilistp, struct vxfs_sb_info *infp)
{
	BUG_ON(infp->vsi_iext);
	infp->vsi_iext = ilistp->olt_iext[0]; 
}

static inline u_long
vxfs_oblock(struct super_block *sbp, daddr_t block, u_long bsize)
{
	BUG_ON(sbp->s_blocksize % bsize);
	return (block * (sbp->s_blocksize / bsize));
}


/**
 * vxfs_read_olt - read olt
 * @sbp:	superblock of the filesystem
 * @bsize:	blocksize of the filesystem
 *
 * Description:
 *   vxfs_read_olt reads the olt of the filesystem described by @sbp
 *   into main memory and does some basic setup.
 *
 * Returns:
 *   Zero on success, else a negative error code.
 */
int
vxfs_read_olt(struct super_block *sbp, u_long bsize)
{
	struct vxfs_sb_info	*infp = VXFS_SBI(sbp);
	struct buffer_head	*bp;
	struct vxfs_olt		*op;
	char			*oaddr, *eaddr;


	bp = sb_bread(sbp, vxfs_oblock(sbp, infp->vsi_oltext, bsize));
	if (!bp || !bp->b_data)
		goto fail;

	op = (struct vxfs_olt *)bp->b_data;
	if (op->olt_magic != VXFS_OLT_MAGIC) {
		printk(KERN_NOTICE "vxfs: ivalid olt magic number\n");
		goto fail;
	}

	/*
	 * It is in theory possible that vsi_oltsize is > 1.
	 * I've not seen any such filesystem yet and I'm lazy..  --hch
	 */
	if (infp->vsi_oltsize > 1) {
		printk(KERN_NOTICE "vxfs: oltsize > 1 detected.\n");
		printk(KERN_NOTICE "vxfs: please notify hch@infradead.org\n");
		goto fail;
	}

	oaddr = bp->b_data + op->olt_size;
	eaddr = bp->b_data + (infp->vsi_oltsize * sbp->s_blocksize);

	while (oaddr < eaddr) {
		struct vxfs_oltcommon	*ocp =
			(struct vxfs_oltcommon *)oaddr;
		
		switch (ocp->olt_type) {
		case VXFS_OLT_FSHEAD:
			vxfs_get_fshead((struct vxfs_oltfshead *)oaddr, infp);
			break;
		case VXFS_OLT_ILIST:
			vxfs_get_ilist((struct vxfs_oltilist *)oaddr, infp);
			break;
		}

		oaddr += ocp->olt_size;
	}

	brelse(bp);
	return 0;

fail:
	brelse(bp);
	return -EINVAL;
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/freevxfs/vxfs_olt.c */
/************************************************************/
/*
 * Copyright (c) 2000-2001 Christoph Hellwig.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Veritas filesystem driver - shared subroutines.
 */
// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/kernel.h>
// #include <linux/pagemap.h>

// #include "vxfs_extern.h"


static int		vxfs_readpage(struct file *, struct page *);
static sector_t		vxfs_bmap(struct address_space *, sector_t);

const struct address_space_operations vxfs_aops = {
	.readpage =		vxfs_readpage,
	.bmap =			vxfs_bmap,
};

inline void
vxfs_put_page(struct page *pp)
{
	kunmap(pp);
	page_cache_release(pp);
}

/**
 * vxfs_get_page - read a page into memory.
 * @ip:		inode to read from
 * @n:		page number
 *
 * Description:
 *   vxfs_get_page reads the @n th page of @ip into the pagecache.
 *
 * Returns:
 *   The wanted page on success, else a NULL pointer.
 */
struct page *
vxfs_get_page(struct address_space *mapping, u_long n)
{
	struct page *			pp;

	pp = read_mapping_page(mapping, n, NULL);

	if (!IS_ERR(pp)) {
		kmap(pp);
		/** if (!PageChecked(pp)) **/
			/** vxfs_check_page(pp); **/
		if (PageError(pp))
			goto fail;
	}
	
	return (pp);
		 
fail:
	vxfs_put_page(pp);
	return ERR_PTR(-EIO);
}

/**
 * vxfs_bread - read buffer for a give inode,block tuple
 * @ip:		inode
 * @block:	logical block
 *
 * Description:
 *   The vxfs_bread function reads block no @block  of
 *   @ip into the buffercache.
 *
 * Returns:
 *   The resulting &struct buffer_head.
 */
struct buffer_head *
vxfs_bread(struct inode *ip, int block)
{
	struct buffer_head	*bp;
	daddr_t			pblock;

	pblock = vxfs_bmap1(ip, block);
	bp = sb_bread(ip->i_sb, pblock);

	return (bp);
}

/**
 * vxfs_get_block - locate buffer for given inode,block tuple 
 * @ip:		inode
 * @iblock:	logical block
 * @bp:		buffer skeleton
 * @create:	%TRUE if blocks may be newly allocated.
 *
 * Description:
 *   The vxfs_get_block function fills @bp with the right physical
 *   block and device number to perform a lowlevel read/write on
 *   it.
 *
 * Returns:
 *   Zero on success, else a negativ error code (-EIO).
 */
static int
vxfs_getblk(struct inode *ip, sector_t iblock,
	    struct buffer_head *bp, int create)
{
	daddr_t			pblock;

	pblock = vxfs_bmap1(ip, iblock);
	if (pblock != 0) {
		map_bh(bp, ip->i_sb, pblock);
		return 0;
	}

	return -EIO;
}

/**
 * vxfs_readpage - read one page synchronously into the pagecache
 * @file:	file context (unused)
 * @page:	page frame to fill in.
 *
 * Description:
 *   The vxfs_readpage routine reads @page synchronously into the
 *   pagecache.
 *
 * Returns:
 *   Zero on success, else a negative error code.
 *
 * Locking status:
 *   @page is locked and will be unlocked.
 */
static int
vxfs_readpage(struct file *file, struct page *page)
{
	return block_read_full_page(page, vxfs_getblk);
}
 
/**
 * vxfs_bmap - perform logical to physical block mapping
 * @mapping:	logical to physical mapping to use
 * @block:	logical block (relative to @mapping).
 *
 * Description:
 *   Vxfs_bmap find out the corresponding phsical block to the
 *   @mapping, @block pair.
 *
 * Returns:
 *   Physical block number on success, else Zero.
 *
 * Locking status:
 *   We are under the bkl.
 */
static sector_t
vxfs_bmap(struct address_space *mapping, sector_t block)
{
	return generic_block_bmap(mapping, block, vxfs_getblk);
}
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/freevxfs/vxfs_subr.c */
/************************************************************/
/*
 * Copyright (c) 2000-2001 Christoph Hellwig.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL").
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Veritas filesystem driver - superblock related routines.
 */
#include <linux/init.h>
#include <linux/module.h>
#include "../../inc/__fss.h"

#include <linux/blkdev.h>
// #include <linux/fs.h>
// #include <linux/buffer_head.h>
// #include <linux/kernel.h>
// #include <linux/slab.h>
#include <linux/stat.h>
#include <linux/vfs.h>
#include <linux/mount.h>
#include "../../inc/__fss.h"

// #include "vxfs.h"
// #include "vxfs_extern.h"
// #include "vxfs_dir.h"
// #include "vxfs_inode.h"


MODULE_AUTHOR("Christoph Hellwig");
MODULE_DESCRIPTION("Veritas Filesystem (VxFS) driver");
MODULE_LICENSE("Dual BSD/GPL");



static void		vxfs_put_super(struct super_block *);
static int		vxfs_statfs(struct dentry *, struct kstatfs *);
static int		vxfs_remount(struct super_block *, int *, char *);

static const struct super_operations vxfs_super_ops = {
	.evict_inode =		vxfs_evict_inode,
	.put_super =		vxfs_put_super,
	.statfs =		vxfs_statfs,
	.remount_fs =		vxfs_remount,
};

/**
 * vxfs_put_super - free superblock resources
 * @sbp:	VFS superblock.
 *
 * Description:
 *   vxfs_put_super frees all resources allocated for @sbp
 *   after the last instance of the filesystem is unmounted.
 */

static void
vxfs_put_super(struct super_block *sbp)
{
	struct vxfs_sb_info	*infp = VXFS_SBI(sbp);

	vxfs_put_fake_inode(infp->vsi_fship);
	vxfs_put_fake_inode(infp->vsi_ilist);
	vxfs_put_fake_inode(infp->vsi_stilist);

	brelse(infp->vsi_bp);
	kfree(infp);
}

/**
 * vxfs_statfs - get filesystem information
 * @dentry:	VFS dentry to locate superblock
 * @bufp:	output buffer
 *
 * Description:
 *   vxfs_statfs fills the statfs buffer @bufp with information
 *   about the filesystem described by @dentry.
 *
 * Returns:
 *   Zero.
 *
 * Locking:
 *   No locks held.
 *
 * Notes:
 *   This is everything but complete...
 */
static int
vxfs_statfs(struct dentry *dentry, struct kstatfs *bufp)
{
	struct vxfs_sb_info		*infp = VXFS_SBI(dentry->d_sb);

	bufp->f_type = VXFS_SUPER_MAGIC;
	bufp->f_bsize = dentry->d_sb->s_blocksize;
	bufp->f_blocks = infp->vsi_raw->vs_dsize;
	bufp->f_bfree = infp->vsi_raw->vs_free;
	bufp->f_bavail = 0;
	bufp->f_files = 0;
	bufp->f_ffree = infp->vsi_raw->vs_ifree;
	bufp->f_namelen = VXFS_NAMELEN;

	return 0;
}

static int vxfs_remount(struct super_block *sb, int *flags, char *data)
{
	sync_filesystem(sb);
	*flags |= MS_RDONLY;
	return 0;
}

/**
 * vxfs_read_super - read superblock into memory and initialize filesystem
 * @sbp:		VFS superblock (to fill)
 * @dp:			fs private mount data
 * @silent:		do not complain loudly when sth is wrong
 *
 * Description:
 *   We are called on the first mount of a filesystem to read the
 *   superblock into memory and do some basic setup.
 *
 * Returns:
 *   The superblock on success, else %NULL.
 *
 * Locking:
 *   We are under @sbp->s_lock.
 */
static int vxfs_fill_super(struct super_block *sbp, void *dp, int silent)
{
	struct vxfs_sb_info	*infp;
	struct vxfs_sb		*rsbp;
	struct buffer_head	*bp = NULL;
	u_long			bsize;
	struct inode *root;
	int ret = -EINVAL;

	sbp->s_flags |= MS_RDONLY;

	infp = kzalloc(sizeof(*infp), GFP_KERNEL);
	if (!infp) {
		printk(KERN_WARNING "vxfs: unable to allocate incore superblock\n");
		return -ENOMEM;
	}

	bsize = sb_min_blocksize(sbp, BLOCK_SIZE);
	if (!bsize) {
		printk(KERN_WARNING "vxfs: unable to set blocksize\n");
		goto out;
	}

	bp = sb_bread(sbp, 1);
	if (!bp || !buffer_mapped(bp)) {
		if (!silent) {
			printk(KERN_WARNING
				"vxfs: unable to read disk superblock\n");
		}
		goto out;
	}

	rsbp = (struct vxfs_sb *)bp->b_data;
	if (rsbp->vs_magic != VXFS_SUPER_MAGIC) {
		if (!silent)
			printk(KERN_NOTICE "vxfs: WRONG superblock magic\n");
		goto out;
	}

	if ((rsbp->vs_version < 2 || rsbp->vs_version > 4) && !silent) {
		printk(KERN_NOTICE "vxfs: unsupported VxFS version (%d)\n",
		       rsbp->vs_version);
		goto out;
	}

#ifdef DIAGNOSTIC
	printk(KERN_DEBUG "vxfs: supported VxFS version (%d)\n", rsbp->vs_version);
	printk(KERN_DEBUG "vxfs: blocksize: %d\n", rsbp->vs_bsize);
#endif

	sbp->s_magic = rsbp->vs_magic;
	sbp->s_fs_info = infp;

	infp->vsi_raw = rsbp;
	infp->vsi_bp = bp;
	infp->vsi_oltext = rsbp->vs_oltext[0];
	infp->vsi_oltsize = rsbp->vs_oltsize;

	if (!sb_set_blocksize(sbp, rsbp->vs_bsize)) {
		printk(KERN_WARNING "vxfs: unable to set final block size\n");
		goto out;
	}

	if (vxfs_read_olt(sbp, bsize)) {
		printk(KERN_WARNING "vxfs: unable to read olt\n");
		goto out;
	}

	if (vxfs_read_fshead(sbp)) {
		printk(KERN_WARNING "vxfs: unable to read fshead\n");
		goto out;
	}

	sbp->s_op = &vxfs_super_ops;
	root = vxfs_iget(sbp, VXFS_ROOT_INO);
	if (IS_ERR(root)) {
		ret = PTR_ERR(root);
		goto out;
	}
	sbp->s_root = d_make_root(root);
	if (!sbp->s_root) {
		printk(KERN_WARNING "vxfs: unable to get root dentry.\n");
		goto out_free_ilist;
	}

	return 0;
	
out_free_ilist:
	vxfs_put_fake_inode(infp->vsi_fship);
	vxfs_put_fake_inode(infp->vsi_ilist);
	vxfs_put_fake_inode(infp->vsi_stilist);
out:
	brelse(bp);
	kfree(infp);
	return ret;
}

/*
 * The usual module blurb.
 */
static struct dentry *vxfs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *data)
{
	return mount_bdev(fs_type, flags, dev_name, data, vxfs_fill_super);
}

static struct file_system_type vxfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "vxfs",
	.mount		= vxfs_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};
MODULE_ALIAS_FS("vxfs"); /* makes mount -t vxfs autoload the module */
MODULE_ALIAS("vxfs");

static int __init
vxfs_init(void)
{
	int rv;

	vxfs_inode_cachep = kmem_cache_create("vxfs_inode",
			sizeof(struct vxfs_inode_info), 0,
			SLAB_RECLAIM_ACCOUNT|SLAB_MEM_SPREAD, NULL);
	if (!vxfs_inode_cachep)
		return -ENOMEM;
	rv = register_filesystem(&vxfs_fs_type);
	if (rv < 0)
		kmem_cache_destroy(vxfs_inode_cachep);
	return rv;
}

static void __exit
vxfs_cleanup(void)
{
	unregister_filesystem(&vxfs_fs_type);
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(vxfs_inode_cachep);
}

module_init(vxfs_init);
module_exit(vxfs_cleanup);
/************************************************************/
/* ../../fs-linux/linux-4.0-rc2/fs/freevxfs/vxfs_super.c */
/************************************************************/
