#include "common.h"

int p;
int read_block_for_search(void *trans, void *root)
{
	return p;
}

int btrfs_search_slot(void *trans, struct btrfs_root *root, struct btrfs_key *key,
					  struct btrfs_path *path, int ins_len, int cow)
{
	int ret;

	ret = read_block_for_search(trans, root);

	ret = 1;
	return ret;
}

struct btrfs_path *path;
struct btrfs_path *btrfs_alloc_path(void)
{
	return path;
}

inline struct btrfs_inode *BTRFS_I(struct inode *inode)
{
  struct btrfs_inode *bi = (struct btrfs_inode*)inode;
  return bi;
}

struct dentry *d;
struct dentry *btrfs_iget(struct super_block *s, struct btrfs_key *location,
						  struct btrfs_root *root, int *new)
{
	return d;
}

static struct dentry *btrfs_get_parent(struct dentry *child)
{
	struct inode *dir = child->d_inode;
	struct btrfs_root *root = BTRFS_I(dir)->root;
	struct btrfs_path *path;
	struct extent_buffer *leaf;
	struct btrfs_root_ref *ref;
	struct btrfs_key key;
	struct btrfs_key found_key;
	int ret;

	path = btrfs_alloc_path();
	if (!path)
		return ERR_PTR(-ENOMEM);

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		goto fail;

	if (path->slots[0] == 0) {
		ret = -ENOENT;
		goto fail;
	}

	if (found_key.objectid != key.objectid || found_key.type != key.type) {
		ret = -ENOENT;
		goto fail;
	}

	return d_obtain_alias(btrfs_iget(root->fs_info->sb, &key, root, NULL));
fail:
	return ERR_PTR(ret);
}


