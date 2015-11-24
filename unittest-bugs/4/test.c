/* commit 0de90876c6cb774d4a424dafc1fc9ec50071b81b */

/*
 * This test is about the missing break condition for
 * the switch case.
 */

#include "../fs.h"
#include <string.h>

#define ENOMEM	12
#define EINVAL	22

enum {
	Opt_degraded, Opt_subvol, Opt_subvolid, Opt_device, Opt_nodatasum,
	Opt_nodatacow, Opt_max_inline, Opt_alloc_start, Opt_nobarrier, Opt_ssd,
	Opt_nossd, Opt_ssd_spread, Opt_thread_pool, Opt_noacl, Opt_compress,
	Opt_compress_type, Opt_compress_force, Opt_compress_force_type,
	Opt_notreelog, Opt_ratio, Opt_flushoncommit, Opt_discard,
	Opt_space_cache, Opt_clear_cache, Opt_user_subvol_rm_allowed,
	Opt_enospc_debug, Opt_subvolrootid, Opt_defrag, Opt_inode_cache,
	Opt_no_space_cache, Opt_recovery, Opt_skip_balance,
	Opt_check_integrity, Opt_check_integrity_including_extent_data,
	Opt_check_integrity_print_mask, Opt_fatal_errors, Opt_rescan_uuid_tree,
	Opt_commit_interval, Opt_barrier, Opt_nodefrag, Opt_nodiscard,
	Opt_noenospc_debug, Opt_noflushoncommit, Opt_acl, Opt_datacow,
	Opt_datasum, Opt_treelog, Opt_noinode_cache,
	Opt_err,
};

struct btrfs_root {
	unsigned long state;
};

volatile struct btrfs_root *root;
volatile char options[1024];

int match_token()
{
	return 0;
}

void btrfs_set_and_info(void) {}

void btrfs_set_opt(void) {}

int btrfs_parse_options(struct btrfs_root *root, char *options)
{

	char *p = NULL;
	int ret = 0;

	options = strdup(options);

	while ((p = strsep(&options, ",")) != NULL) 
	{
		int token;
		token = match_token();

		switch(token) {
		case Opt_acl:
			printf("support for ACL not compiled in!");
			ret = -EINVAL;
			goto out;
		case Opt_space_cache:
			btrfs_set_and_info();
#ifdef __PATCH__
			break;
#endif
		case Opt_clear_cache:
			btrfs_set_opt();
			break;
		case Opt_err:
			printf("issue");
			ret = -EINVAL;
			goto out;
		default:
			break;
		}
	}

 out:

	return ret;
}

int main(int argc, char *argv[])
{
	int v;
	v = btrfs_parse_options(root, options);
	return 0;
}
