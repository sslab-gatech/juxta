/*
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/efi.h>
#include <linux/fs.h>
#include <linux/ctype.h>
#include <linux/slab.h>

#include "internal.h"

struct inode *efivarfs_get_inode(struct super_block *sb,
				const struct inode *dir, int mode, dev_t dev)
{
	struct inode *inode = new_inode(sb);

	if (inode) {
		inode->i_ino = get_next_ino();
		inode->i_mode = mode;
		inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
		switch (mode & S_IFMT) {
		case S_IFREG:
			inode->i_fop = &efivarfs_file_operations;
			break;
		case S_IFDIR:
			inode->i_op = &efivarfs_dir_inode_operations;
			inode->i_fop = &simple_dir_operations;
			inc_nlink(inode);
			break;
		}
	}
	return inode;
}

/*
 * Return true if 'str' is a valid efivarfs filename of the form,
 *
 *	VariableName-12345678-1234-1234-1234-1234567891bc
 */
bool efivarfs_valid_name(const char *str, int len)
{
	static const char dashes[EFI_VARIABLE_GUID_LEN] = {
		[8] = 1, [13] = 1, [18] = 1, [23] = 1
	};
	const char *s = str + len - EFI_VARIABLE_GUID_LEN;
	int i;

	/*
	 * We need a GUID, plus at least one letter for the variable name,
	 * plus the '-' separator
	 */
	if (len < EFI_VARIABLE_GUID_LEN + 2)
		return false;

	/* GUID must be preceded by a '-' */
	if (*(s - 1) != '-')
		return false;

	/*
	 * Validate that 's' is of the correct format, e.g.
	 *
	 *	12345678-1234-1234-1234-123456789abc
	 */
	for (i = 0; i < EFI_VARIABLE_GUID_LEN; i++) {
		if (dashes[i]) {
			if (*s++ != '-')
				return false;
		} else {
			if (!isxdigit(*s++))
				return false;
		}
	}

	return true;
}

static void efivarfs_hex_to_guid(const char *str, efi_guid_t *guid)
{
	guid->b[0] = hex_to_bin(str[6]) << 4 | hex_to_bin(str[7]);
	guid->b[1] = hex_to_bin(str[4]) << 4 | hex_to_bin(str[5]);
	guid->b[2] = hex_to_bin(str[2]) << 4 | hex_to_bin(str[3]);
	guid->b[3] = hex_to_bin(str[0]) << 4 | hex_to_bin(str[1]);
	guid->b[4] = hex_to_bin(str[11]) << 4 | hex_to_bin(str[12]);
	guid->b[5] = hex_to_bin(str[9]) << 4 | hex_to_bin(str[10]);
	guid->b[6] = hex_to_bin(str[16]) << 4 | hex_to_bin(str[17]);
	guid->b[7] = hex_to_bin(str[14]) << 4 | hex_to_bin(str[15]);
	guid->b[8] = hex_to_bin(str[19]) << 4 | hex_to_bin(str[20]);
	guid->b[9] = hex_to_bin(str[21]) << 4 | hex_to_bin(str[22]);
	guid->b[10] = hex_to_bin(str[24]) << 4 | hex_to_bin(str[25]);
	guid->b[11] = hex_to_bin(str[26]) << 4 | hex_to_bin(str[27]);
	guid->b[12] = hex_to_bin(str[28]) << 4 | hex_to_bin(str[29]);
	guid->b[13] = hex_to_bin(str[30]) << 4 | hex_to_bin(str[31]);
	guid->b[14] = hex_to_bin(str[32]) << 4 | hex_to_bin(str[33]);
	guid->b[15] = hex_to_bin(str[34]) << 4 | hex_to_bin(str[35]);
}

static int efivarfs_create(struct inode *dir, struct dentry *dentry,
			  umode_t mode, bool excl)
{
	struct inode *inode;
	struct efivar_entry *var;
	int namelen, i = 0, err = 0;

	if (!efivarfs_valid_name(dentry->d_name.name, dentry->d_name.len))
		return -EINVAL;

	inode = efivarfs_get_inode(dir->i_sb, dir, mode, 0);
	if (!inode)
		return -ENOMEM;

	var = kzalloc(sizeof(struct efivar_entry), GFP_KERNEL);
	if (!var) {
		err = -ENOMEM;
		goto out;
	}

	/* length of the variable name itself: remove GUID and separator */
	namelen = dentry->d_name.len - EFI_VARIABLE_GUID_LEN - 1;

	efivarfs_hex_to_guid(dentry->d_name.name + namelen + 1,
			&var->var.VendorGuid);

	for (i = 0; i < namelen; i++)
		var->var.VariableName[i] = dentry->d_name.name[i];

	var->var.VariableName[i] = '\0';

	inode->i_private = var;

	efivar_entry_add(var, &efivarfs_list);
	d_instantiate(dentry, inode);
	dget(dentry);
out:
	if (err) {
		kfree(var);
		iput(inode);
	}
	return err;
}

static int efivarfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct efivar_entry *var = dentry->d_inode->i_private;

	if (efivar_entry_delete(var))
		return -EINVAL;

	drop_nlink(dentry->d_inode);
	dput(dentry);
	return 0;
};

const struct inode_operations efivarfs_dir_inode_operations = {
	.lookup = simple_lookup,
	.unlink = efivarfs_unlink,
	.create = efivarfs_create,
};
/************************************************************/
/* ../linux-3.17/fs/efivarfs/inode.c */
/************************************************************/
/*
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

// #include <linux/efi.h>
// #include <linux/fs.h>
// #include <linux/slab.h>

// #include "internal.h"

static ssize_t efivarfs_file_write(struct file *file,
		const char __user *userbuf, size_t count, loff_t *ppos)
{
	struct efivar_entry *var = file->private_data;
	void *data;
	u32 attributes;
	struct inode *inode = file->f_mapping->host;
	unsigned long datasize = count - sizeof(attributes);
	ssize_t bytes;
	bool set = false;

	if (count < sizeof(attributes))
		return -EINVAL;

	if (copy_from_user(&attributes, userbuf, sizeof(attributes)))
		return -EFAULT;

	if (attributes & ~(EFI_VARIABLE_MASK))
		return -EINVAL;

	data = memdup_user(userbuf + sizeof(attributes), datasize);
	if (IS_ERR(data))
		return PTR_ERR(data);

	bytes = efivar_entry_set_get_size(var, attributes, &datasize,
					  data, &set);
	if (!set && bytes) {
		if (bytes == -ENOENT)
			bytes = -EIO;
		goto out;
	}

	if (bytes == -ENOENT) {
		drop_nlink(inode);
		d_delete(file->f_dentry);
		dput(file->f_dentry);
	} else {
		mutex_lock(&inode->i_mutex);
		i_size_write(inode, datasize + sizeof(attributes));
		mutex_unlock(&inode->i_mutex);
	}

	bytes = count;

out:
	kfree(data);

	return bytes;
}

static ssize_t efivarfs_file_read(struct file *file, char __user *userbuf,
		size_t count, loff_t *ppos)
{
	struct efivar_entry *var = file->private_data;
	unsigned long datasize = 0;
	u32 attributes;
	void *data;
	ssize_t size = 0;
	int err;

	err = efivar_entry_size(var, &datasize);

	/*
	 * efivarfs represents uncommitted variables with
	 * zero-length files. Reading them should return EOF.
	 */
	if (err == -ENOENT)
		return 0;
	else if (err)
		return err;

	data = kmalloc(datasize + sizeof(attributes), GFP_KERNEL);

	if (!data)
		return -ENOMEM;

	size = efivar_entry_get(var, &attributes, &datasize,
				data + sizeof(attributes));
	if (size)
		goto out_free;

	memcpy(data, &attributes, sizeof(attributes));
	size = simple_read_from_buffer(userbuf, count, ppos,
				       data, datasize + sizeof(attributes));
out_free:
	kfree(data);

	return size;
}

const struct file_operations efivarfs_file_operations = {
	.open	= simple_open,
	.read	= efivarfs_file_read,
	.write	= efivarfs_file_write,
	.llseek	= no_llseek,
};
/************************************************************/
/* ../linux-3.17/fs/efivarfs/file.c */
/************************************************************/
/*
 * Copyright (C) 2012 Red Hat, Inc.
 * Copyright (C) 2012 Jeremy Kerr <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

// #include <linux/ctype.h>
// #include <linux/efi.h>
// #include <linux/fs.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/ucs2_string.h>
// #include <linux/slab.h>
#include <linux/magic.h>

// #include "internal.h"

LIST_HEAD(efivarfs_list);

static void efivarfs_evict_inode(struct inode *inode)
{
	clear_inode(inode);
}

static const struct super_operations efivarfs_ops = {
	.statfs = simple_statfs,
	.drop_inode = generic_delete_inode,
	.evict_inode = efivarfs_evict_inode,
	.show_options = generic_show_options,
};

static struct super_block *efivarfs_sb;

/*
 * Compare two efivarfs file names.
 *
 * An efivarfs filename is composed of two parts,
 *
 *	1. A case-sensitive variable name
 *	2. A case-insensitive GUID
 *
 * So we need to perform a case-sensitive match on part 1 and a
 * case-insensitive match on part 2.
 */
static int efivarfs_d_compare(const struct dentry *parent,
			      const struct dentry *dentry,
			      unsigned int len, const char *str,
			      const struct qstr *name)
{
	int guid = len - EFI_VARIABLE_GUID_LEN;

	if (name->len != len)
		return 1;

	/* Case-sensitive compare for the variable name */
	if (memcmp(str, name->name, guid))
		return 1;

	/* Case-insensitive compare for the GUID */
	return strncasecmp(name->name + guid, str + guid, EFI_VARIABLE_GUID_LEN);
}

static int efivarfs_d_hash(const struct dentry *dentry, struct qstr *qstr)
{
	unsigned long hash = init_name_hash();
	const unsigned char *s = qstr->name;
	unsigned int len = qstr->len;

	if (!efivarfs_valid_name(s, len))
		return -EINVAL;

	while (len-- > EFI_VARIABLE_GUID_LEN)
		hash = partial_name_hash(*s++, hash);

	/* GUID is case-insensitive. */
	while (len--)
		hash = partial_name_hash(tolower(*s++), hash);

	qstr->hash = end_name_hash(hash);
	return 0;
}

static const struct dentry_operations efivarfs_d_ops = {
	.d_compare = efivarfs_d_compare,
	.d_hash = efivarfs_d_hash,
	.d_delete = always_delete_dentry,
};

static struct dentry *efivarfs_alloc_dentry(struct dentry *parent, char *name)
{
	struct dentry *d;
	struct qstr q;
	int err;

	q.name = name;
	q.len = strlen(name);

	err = efivarfs_d_hash(NULL, &q);
	if (err)
		return ERR_PTR(err);

	d = d_alloc(parent, &q);
	if (d)
		return d;

	return ERR_PTR(-ENOMEM);
}

static int efivarfs_callback(efi_char16_t *name16, efi_guid_t vendor,
			     unsigned long name_size, void *data)
{
	struct super_block *sb = (struct super_block *)data;
	struct efivar_entry *entry;
	struct inode *inode = NULL;
	struct dentry *dentry, *root = sb->s_root;
	unsigned long size = 0;
	char *name;
	int len, i;
	int err = -ENOMEM;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return err;

	memcpy(entry->var.VariableName, name16, name_size);
	memcpy(&(entry->var.VendorGuid), &vendor, sizeof(efi_guid_t));

	len = ucs2_strlen(entry->var.VariableName);

	/* name, plus '-', plus GUID, plus NUL*/
	name = kmalloc(len + 1 + EFI_VARIABLE_GUID_LEN + 1, GFP_KERNEL);
	if (!name)
		goto fail;

	for (i = 0; i < len; i++)
		name[i] = entry->var.VariableName[i] & 0xFF;

	name[len] = '-';

	efi_guid_unparse(&entry->var.VendorGuid, name + len + 1);

	name[len + EFI_VARIABLE_GUID_LEN+1] = '\0';

	inode = efivarfs_get_inode(sb, root->d_inode, S_IFREG | 0644, 0);
	if (!inode)
		goto fail_name;

	dentry = efivarfs_alloc_dentry(root, name);
	if (IS_ERR(dentry)) {
		err = PTR_ERR(dentry);
		goto fail_inode;
	}

	/* copied by the above to local storage in the dentry. */
	kfree(name);

	efivar_entry_size(entry, &size);
	efivar_entry_add(entry, &efivarfs_list);

	mutex_lock(&inode->i_mutex);
	inode->i_private = entry;
	i_size_write(inode, size + sizeof(entry->var.Attributes));
	mutex_unlock(&inode->i_mutex);
	d_add(dentry, inode);

	return 0;

fail_inode:
	iput(inode);
fail_name:
	kfree(name);
fail:
	kfree(entry);
	return err;
}

static int efivarfs_destroy(struct efivar_entry *entry, void *data)
{
	efivar_entry_remove(entry);
	kfree(entry);
	return 0;
}

static int efivarfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct inode *inode = NULL;
	struct dentry *root;
	int err;

	efivarfs_sb = sb;

	sb->s_maxbytes          = MAX_LFS_FILESIZE;
	sb->s_blocksize         = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits    = PAGE_CACHE_SHIFT;
	sb->s_magic             = EFIVARFS_MAGIC;
	sb->s_op                = &efivarfs_ops;
	sb->s_d_op		= &efivarfs_d_ops;
	sb->s_time_gran         = 1;

	inode = efivarfs_get_inode(sb, NULL, S_IFDIR | 0755, 0);
	if (!inode)
		return -ENOMEM;
	inode->i_op = &efivarfs_dir_inode_operations;

	root = d_make_root(inode);
	sb->s_root = root;
	if (!root)
		return -ENOMEM;

	INIT_LIST_HEAD(&efivarfs_list);

	err = efivar_init(efivarfs_callback, (void *)sb, false,
			  true, &efivarfs_list);
	if (err)
		__efivar_entry_iter(efivarfs_destroy, &efivarfs_list, NULL, NULL);

	return err;
}

static struct dentry *efivarfs_mount(struct file_system_type *fs_type,
				    int flags, const char *dev_name, void *data)
{
	return mount_single(fs_type, flags, data, efivarfs_fill_super);
}

static void efivarfs_kill_sb(struct super_block *sb)
{
	kill_litter_super(sb);
	efivarfs_sb = NULL;

	/* Remove all entries and destroy */
	__efivar_entry_iter(efivarfs_destroy, &efivarfs_list, NULL, NULL);
}

static struct file_system_type efivarfs_type = {
	.name    = "efivarfs",
	.mount   = efivarfs_mount,
	.kill_sb = efivarfs_kill_sb,
};

static __init int efivarfs_init(void)
{
	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return 0;

	if (!efivars_kobject())
		return 0;

	return register_filesystem(&efivarfs_type);
}

MODULE_AUTHOR("Matthew Garrett, Jeremy Kerr");
MODULE_DESCRIPTION("EFI Variable Filesystem");
MODULE_LICENSE("GPL");
MODULE_ALIAS_FS("efivarfs");

module_init(efivarfs_init);
/************************************************************/
/* ../linux-3.17/fs/efivarfs/super.c */
/************************************************************/
