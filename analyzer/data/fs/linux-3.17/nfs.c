/* client.c: NFS client sharing and management code
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */


#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/stats.h>
#include <linux/sunrpc/metrics.h>
#include <linux/sunrpc/xprtsock.h>
#include <linux/sunrpc/xprtrdma.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_mount.h>
#include <linux/nfs4_mount.h>
#include <linux/lockd/bind.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/nfs_idmap.h>
#include <linux/vfs.h>
#include <linux/inet.h>
#include <linux/in6.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <net/ipv6.h>
#include <linux/nfs_xdr.h>
#include <linux/sunrpc/bc_xprt.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>


#include "nfs4_fs.h"
#include "callback.h"
#include "delegation.h"
#include "iostat.h"
#include "internal.h"
#include "fscache.h"
#include "pnfs.h"
#include "nfs.h"
#include "netns.h"

#define NFSDBG_FACILITY		NFSDBG_CLIENT

static DECLARE_WAIT_QUEUE_HEAD(nfs_client_active_wq);
static DEFINE_SPINLOCK(nfs_version_lock);
static DEFINE_MUTEX(nfs_version_mutex);
static LIST_HEAD(nfs_versions);

/*
 * RPC cruft for NFS
 */
static const struct rpc_version *nfs_version[5] = {
	[2] = NULL,
	[3] = NULL,
	[4] = NULL,
};

const struct rpc_program nfs_program = {
	.name			= "nfs",
	.number			= NFS_PROGRAM,
	.nrvers			= ARRAY_SIZE(nfs_version),
	.version		= nfs_version,
	.stats			= &nfs_rpcstat,
	.pipe_dir_name		= NFS_PIPE_DIRNAME,
};

struct rpc_stat nfs_rpcstat = {
	.program		= &nfs_program
};

static struct nfs_subversion *find_nfs_version(unsigned int version)
{
	struct nfs_subversion *nfs;
	spin_lock(&nfs_version_lock);

	list_for_each_entry(nfs, &nfs_versions, list) {
		if (nfs->rpc_ops->version == version) {
			spin_unlock(&nfs_version_lock);
			return nfs;
		}
	}

	spin_unlock(&nfs_version_lock);
	return ERR_PTR(-EPROTONOSUPPORT);
}

struct nfs_subversion *get_nfs_version(unsigned int version)
{
	struct nfs_subversion *nfs = find_nfs_version(version);

	if (IS_ERR(nfs)) {
		mutex_lock(&nfs_version_mutex);
		request_module("nfsv%d", version);
		nfs = find_nfs_version(version);
		mutex_unlock(&nfs_version_mutex);
	}

	if (!IS_ERR(nfs) && !try_module_get(nfs->owner))
		return ERR_PTR(-EAGAIN);
	return nfs;
}

void put_nfs_version(struct nfs_subversion *nfs)
{
	module_put(nfs->owner);
}

void register_nfs_version(struct nfs_subversion *nfs)
{
	spin_lock(&nfs_version_lock);

	list_add(&nfs->list, &nfs_versions);
	nfs_version[nfs->rpc_ops->version] = nfs->rpc_vers;

	spin_unlock(&nfs_version_lock);
}
EXPORT_SYMBOL_GPL(register_nfs_version);

void unregister_nfs_version(struct nfs_subversion *nfs)
{
	spin_lock(&nfs_version_lock);

	nfs_version[nfs->rpc_ops->version] = NULL;
	list_del(&nfs->list);

	spin_unlock(&nfs_version_lock);
}
EXPORT_SYMBOL_GPL(unregister_nfs_version);

/*
 * Allocate a shared client record
 *
 * Since these are allocated/deallocated very rarely, we don't
 * bother putting them in a slab cache...
 */
struct nfs_client *nfs_alloc_client(const struct nfs_client_initdata *cl_init)
{
	struct nfs_client *clp;
	struct rpc_cred *cred;
	int err = -ENOMEM;

	if ((clp = kzalloc(sizeof(*clp), GFP_KERNEL)) == NULL)
		goto error_0;

	clp->cl_nfs_mod = cl_init->nfs_mod;
	if (!try_module_get(clp->cl_nfs_mod->owner))
		goto error_dealloc;

	clp->rpc_ops = clp->cl_nfs_mod->rpc_ops;

	atomic_set(&clp->cl_count, 1);
	clp->cl_cons_state = NFS_CS_INITING;

	memcpy(&clp->cl_addr, cl_init->addr, cl_init->addrlen);
	clp->cl_addrlen = cl_init->addrlen;

	if (cl_init->hostname) {
		err = -ENOMEM;
		clp->cl_hostname = kstrdup(cl_init->hostname, GFP_KERNEL);
		if (!clp->cl_hostname)
			goto error_cleanup;
	}

	INIT_LIST_HEAD(&clp->cl_superblocks);
	clp->cl_rpcclient = ERR_PTR(-EINVAL);

	clp->cl_proto = cl_init->proto;
	clp->cl_net = get_net(cl_init->net);

	cred = rpc_lookup_machine_cred("*");
	if (!IS_ERR(cred))
		clp->cl_machine_cred = cred;
	nfs_fscache_get_client_cookie(clp);

	return clp;

error_cleanup:
	put_nfs_version(clp->cl_nfs_mod);
error_dealloc:
	kfree(clp);
error_0:
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(nfs_alloc_client);

#if IS_ENABLED(CONFIG_NFS_V4)
void nfs_cleanup_cb_ident_idr(struct net *net)
{
	struct nfs_net *nn = net_generic(net, nfs_net_id);

	idr_destroy(&nn->cb_ident_idr);
}

/* nfs_client_lock held */
static void nfs_cb_idr_remove_locked(struct nfs_client *clp)
{
	struct nfs_net *nn = net_generic(clp->cl_net, nfs_net_id);

	if (clp->cl_cb_ident)
		idr_remove(&nn->cb_ident_idr, clp->cl_cb_ident);
}

static void pnfs_init_server(struct nfs_server *server)
{
	rpc_init_wait_queue(&server->roc_rpcwaitq, "pNFS ROC");
}

#else
void nfs_cleanup_cb_ident_idr(struct net *net)
{
}

static void nfs_cb_idr_remove_locked(struct nfs_client *clp)
{
}

static void pnfs_init_server(struct nfs_server *server)
{
}

#endif /* CONFIG_NFS_V4 */

/*
 * Destroy a shared client record
 */
void nfs_free_client(struct nfs_client *clp)
{
	dprintk("--> nfs_free_client(%u)\n", clp->rpc_ops->version);

	nfs_fscache_release_client_cookie(clp);

	/* -EIO all pending I/O */
	if (!IS_ERR(clp->cl_rpcclient))
		rpc_shutdown_client(clp->cl_rpcclient);

	if (clp->cl_machine_cred != NULL)
		put_rpccred(clp->cl_machine_cred);

	put_net(clp->cl_net);
	put_nfs_version(clp->cl_nfs_mod);
	kfree(clp->cl_hostname);
	kfree(clp->cl_acceptor);
	kfree(clp);

	dprintk("<-- nfs_free_client()\n");
}
EXPORT_SYMBOL_GPL(nfs_free_client);

/*
 * Release a reference to a shared client record
 */
void nfs_put_client(struct nfs_client *clp)
{
	struct nfs_net *nn;

	if (!clp)
		return;

	dprintk("--> nfs_put_client({%d})\n", atomic_read(&clp->cl_count));
	nn = net_generic(clp->cl_net, nfs_net_id);

	if (atomic_dec_and_lock(&clp->cl_count, &nn->nfs_client_lock)) {
		list_del(&clp->cl_share_link);
		nfs_cb_idr_remove_locked(clp);
		spin_unlock(&nn->nfs_client_lock);

		WARN_ON_ONCE(!list_empty(&clp->cl_superblocks));

		clp->rpc_ops->free_client(clp);
	}
}
EXPORT_SYMBOL_GPL(nfs_put_client);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
/*
 * Test if two ip6 socket addresses refer to the same socket by
 * comparing relevant fields. The padding bytes specifically, are not
 * compared. sin6_flowinfo is not compared because it only affects QoS
 * and sin6_scope_id is only compared if the address is "link local"
 * because "link local" addresses need only be unique to a specific
 * link. Conversely, ordinary unicast addresses might have different
 * sin6_scope_id.
 *
 * The caller should ensure both socket addresses are AF_INET6.
 */
static int nfs_sockaddr_match_ipaddr6(const struct sockaddr *sa1,
				      const struct sockaddr *sa2)
{
	const struct sockaddr_in6 *sin1 = (const struct sockaddr_in6 *)sa1;
	const struct sockaddr_in6 *sin2 = (const struct sockaddr_in6 *)sa2;

	if (!ipv6_addr_equal(&sin1->sin6_addr, &sin2->sin6_addr))
		return 0;
	else if (ipv6_addr_type(&sin1->sin6_addr) & IPV6_ADDR_LINKLOCAL)
		return sin1->sin6_scope_id == sin2->sin6_scope_id;

	return 1;
}
#else	/* !defined(CONFIG_IPV6) && !defined(CONFIG_IPV6_MODULE) */
static int nfs_sockaddr_match_ipaddr6(const struct sockaddr *sa1,
				      const struct sockaddr *sa2)
{
	return 0;
}
#endif

/*
 * Test if two ip4 socket addresses refer to the same socket, by
 * comparing relevant fields. The padding bytes specifically, are
 * not compared.
 *
 * The caller should ensure both socket addresses are AF_INET.
 */
static int nfs_sockaddr_match_ipaddr4(const struct sockaddr *sa1,
				      const struct sockaddr *sa2)
{
	const struct sockaddr_in *sin1 = (const struct sockaddr_in *)sa1;
	const struct sockaddr_in *sin2 = (const struct sockaddr_in *)sa2;

	return sin1->sin_addr.s_addr == sin2->sin_addr.s_addr;
}

static int nfs_sockaddr_cmp_ip6(const struct sockaddr *sa1,
				const struct sockaddr *sa2)
{
	const struct sockaddr_in6 *sin1 = (const struct sockaddr_in6 *)sa1;
	const struct sockaddr_in6 *sin2 = (const struct sockaddr_in6 *)sa2;

	return nfs_sockaddr_match_ipaddr6(sa1, sa2) &&
		(sin1->sin6_port == sin2->sin6_port);
}

static int nfs_sockaddr_cmp_ip4(const struct sockaddr *sa1,
				const struct sockaddr *sa2)
{
	const struct sockaddr_in *sin1 = (const struct sockaddr_in *)sa1;
	const struct sockaddr_in *sin2 = (const struct sockaddr_in *)sa2;

	return nfs_sockaddr_match_ipaddr4(sa1, sa2) &&
		(sin1->sin_port == sin2->sin_port);
}

#if defined(CONFIG_NFS_V4_1)
/*
 * Test if two socket addresses represent the same actual socket,
 * by comparing (only) relevant fields, excluding the port number.
 */
int nfs_sockaddr_match_ipaddr(const struct sockaddr *sa1,
			      const struct sockaddr *sa2)
{
	if (sa1->sa_family != sa2->sa_family)
		return 0;

	switch (sa1->sa_family) {
	case AF_INET:
		return nfs_sockaddr_match_ipaddr4(sa1, sa2);
	case AF_INET6:
		return nfs_sockaddr_match_ipaddr6(sa1, sa2);
	}
	return 0;
}
EXPORT_SYMBOL_GPL(nfs_sockaddr_match_ipaddr);
#endif /* CONFIG_NFS_V4_1 */

/*
 * Test if two socket addresses represent the same actual socket,
 * by comparing (only) relevant fields, including the port number.
 */
static int nfs_sockaddr_cmp(const struct sockaddr *sa1,
			    const struct sockaddr *sa2)
{
	if (sa1->sa_family != sa2->sa_family)
		return 0;

	switch (sa1->sa_family) {
	case AF_INET:
		return nfs_sockaddr_cmp_ip4(sa1, sa2);
	case AF_INET6:
		return nfs_sockaddr_cmp_ip6(sa1, sa2);
	}
	return 0;
}

/*
 * Find an nfs_client on the list that matches the initialisation data
 * that is supplied.
 */
static struct nfs_client *nfs_match_client(const struct nfs_client_initdata *data)
{
	struct nfs_client *clp;
	const struct sockaddr *sap = data->addr;
	struct nfs_net *nn = net_generic(data->net, nfs_net_id);

	list_for_each_entry(clp, &nn->nfs_client_list, cl_share_link) {
	        const struct sockaddr *clap = (struct sockaddr *)&clp->cl_addr;
		/* Don't match clients that failed to initialise properly */
		if (clp->cl_cons_state < 0)
			continue;

		/* Different NFS versions cannot share the same nfs_client */
		if (clp->rpc_ops != data->nfs_mod->rpc_ops)
			continue;

		if (clp->cl_proto != data->proto)
			continue;
		/* Match nfsv4 minorversion */
		if (clp->cl_minorversion != data->minorversion)
			continue;
		/* Match the full socket address */
		if (!nfs_sockaddr_cmp(sap, clap))
			continue;

		atomic_inc(&clp->cl_count);
		return clp;
	}
	return NULL;
}

static bool nfs_client_init_is_complete(const struct nfs_client *clp)
{
	return clp->cl_cons_state != NFS_CS_INITING;
}

int nfs_wait_client_init_complete(const struct nfs_client *clp)
{
	return wait_event_killable(nfs_client_active_wq,
			nfs_client_init_is_complete(clp));
}
EXPORT_SYMBOL_GPL(nfs_wait_client_init_complete);

/*
 * Found an existing client.  Make sure it's ready before returning.
 */
static struct nfs_client *
nfs_found_client(const struct nfs_client_initdata *cl_init,
		 struct nfs_client *clp)
{
	int error;

	error = nfs_wait_client_init_complete(clp);
	if (error < 0) {
		nfs_put_client(clp);
		return ERR_PTR(-ERESTARTSYS);
	}

	if (clp->cl_cons_state < NFS_CS_READY) {
		error = clp->cl_cons_state;
		nfs_put_client(clp);
		return ERR_PTR(error);
	}

	smp_rmb();

	dprintk("<-- %s found nfs_client %p for %s\n",
		__func__, clp, cl_init->hostname ?: "");
	return clp;
}

/*
 * Look up a client by IP address and protocol version
 * - creates a new record if one doesn't yet exist
 */
struct nfs_client *
nfs_get_client(const struct nfs_client_initdata *cl_init,
	       const struct rpc_timeout *timeparms,
	       const char *ip_addr,
	       rpc_authflavor_t authflavour)
{
	struct nfs_client *clp, *new = NULL;
	struct nfs_net *nn = net_generic(cl_init->net, nfs_net_id);
	const struct nfs_rpc_ops *rpc_ops = cl_init->nfs_mod->rpc_ops;

	if (cl_init->hostname == NULL) {
		WARN_ON(1);
		return NULL;
	}

	dprintk("--> nfs_get_client(%s,v%u)\n",
		cl_init->hostname, rpc_ops->version);

	/* see if the client already exists */
	do {
		spin_lock(&nn->nfs_client_lock);

		clp = nfs_match_client(cl_init);
		if (clp) {
			spin_unlock(&nn->nfs_client_lock);
			if (new)
				new->rpc_ops->free_client(new);
			return nfs_found_client(cl_init, clp);
		}
		if (new) {
			list_add_tail(&new->cl_share_link,
					&nn->nfs_client_list);
			spin_unlock(&nn->nfs_client_lock);
			new->cl_flags = cl_init->init_flags;
			return rpc_ops->init_client(new, timeparms, ip_addr);
		}

		spin_unlock(&nn->nfs_client_lock);

		new = rpc_ops->alloc_client(cl_init);
	} while (!IS_ERR(new));

	dprintk("<-- nfs_get_client() Failed to find %s (%ld)\n",
		cl_init->hostname, PTR_ERR(new));
	return new;
}
EXPORT_SYMBOL_GPL(nfs_get_client);

/*
 * Mark a server as ready or failed
 */
void nfs_mark_client_ready(struct nfs_client *clp, int state)
{
	smp_wmb();
	clp->cl_cons_state = state;
	wake_up_all(&nfs_client_active_wq);
}
EXPORT_SYMBOL_GPL(nfs_mark_client_ready);

/*
 * Initialise the timeout values for a connection
 */
void nfs_init_timeout_values(struct rpc_timeout *to, int proto,
				    unsigned int timeo, unsigned int retrans)
{
	to->to_initval = timeo * HZ / 10;
	to->to_retries = retrans;

	switch (proto) {
	case XPRT_TRANSPORT_TCP:
	case XPRT_TRANSPORT_RDMA:
		if (to->to_retries == 0)
			to->to_retries = NFS_DEF_TCP_RETRANS;
		if (to->to_initval == 0)
			to->to_initval = NFS_DEF_TCP_TIMEO * HZ / 10;
		if (to->to_initval > NFS_MAX_TCP_TIMEOUT)
			to->to_initval = NFS_MAX_TCP_TIMEOUT;
		to->to_increment = to->to_initval;
		to->to_maxval = to->to_initval + (to->to_increment * to->to_retries);
		if (to->to_maxval > NFS_MAX_TCP_TIMEOUT)
			to->to_maxval = NFS_MAX_TCP_TIMEOUT;
		if (to->to_maxval < to->to_initval)
			to->to_maxval = to->to_initval;
		to->to_exponential = 0;
		break;
	case XPRT_TRANSPORT_UDP:
		if (to->to_retries == 0)
			to->to_retries = NFS_DEF_UDP_RETRANS;
		if (!to->to_initval)
			to->to_initval = NFS_DEF_UDP_TIMEO * HZ / 10;
		if (to->to_initval > NFS_MAX_UDP_TIMEOUT)
			to->to_initval = NFS_MAX_UDP_TIMEOUT;
		to->to_maxval = NFS_MAX_UDP_TIMEOUT;
		to->to_exponential = 1;
		break;
	default:
		BUG();
	}
}
EXPORT_SYMBOL_GPL(nfs_init_timeout_values);

/*
 * Create an RPC client handle
 */
int nfs_create_rpc_client(struct nfs_client *clp,
			  const struct rpc_timeout *timeparms,
			  rpc_authflavor_t flavor)
{
	struct rpc_clnt		*clnt = NULL;
	struct rpc_create_args args = {
		.net		= clp->cl_net,
		.protocol	= clp->cl_proto,
		.address	= (struct sockaddr *)&clp->cl_addr,
		.addrsize	= clp->cl_addrlen,
		.timeout	= timeparms,
		.servername	= clp->cl_hostname,
		.program	= &nfs_program,
		.version	= clp->rpc_ops->version,
		.authflavor	= flavor,
	};

	if (test_bit(NFS_CS_DISCRTRY, &clp->cl_flags))
		args.flags |= RPC_CLNT_CREATE_DISCRTRY;
	if (test_bit(NFS_CS_NO_RETRANS_TIMEOUT, &clp->cl_flags))
		args.flags |= RPC_CLNT_CREATE_NO_RETRANS_TIMEOUT;
	if (test_bit(NFS_CS_NORESVPORT, &clp->cl_flags))
		args.flags |= RPC_CLNT_CREATE_NONPRIVPORT;
	if (test_bit(NFS_CS_INFINITE_SLOTS, &clp->cl_flags))
		args.flags |= RPC_CLNT_CREATE_INFINITE_SLOTS;

	if (!IS_ERR(clp->cl_rpcclient))
		return 0;

	clnt = rpc_create(&args);
	if (IS_ERR(clnt)) {
		dprintk("%s: cannot create RPC client. Error = %ld\n",
				__func__, PTR_ERR(clnt));
		return PTR_ERR(clnt);
	}

	clp->cl_rpcclient = clnt;
	return 0;
}
EXPORT_SYMBOL_GPL(nfs_create_rpc_client);

/*
 * Version 2 or 3 client destruction
 */
static void nfs_destroy_server(struct nfs_server *server)
{
	if (server->nlm_host)
		nlmclnt_done(server->nlm_host);
}

/*
 * Version 2 or 3 lockd setup
 */
static int nfs_start_lockd(struct nfs_server *server)
{
	struct nlm_host *host;
	struct nfs_client *clp = server->nfs_client;
	struct nlmclnt_initdata nlm_init = {
		.hostname	= clp->cl_hostname,
		.address	= (struct sockaddr *)&clp->cl_addr,
		.addrlen	= clp->cl_addrlen,
		.nfs_version	= clp->rpc_ops->version,
		.noresvport	= server->flags & NFS_MOUNT_NORESVPORT ?
					1 : 0,
		.net		= clp->cl_net,
	};

	if (nlm_init.nfs_version > 3)
		return 0;
	if ((server->flags & NFS_MOUNT_LOCAL_FLOCK) &&
			(server->flags & NFS_MOUNT_LOCAL_FCNTL))
		return 0;

	switch (clp->cl_proto) {
		default:
			nlm_init.protocol = IPPROTO_TCP;
			break;
		case XPRT_TRANSPORT_UDP:
			nlm_init.protocol = IPPROTO_UDP;
	}

	host = nlmclnt_init(&nlm_init);
	if (IS_ERR(host))
		return PTR_ERR(host);

	server->nlm_host = host;
	server->destroy = nfs_destroy_server;
	return 0;
}

/*
 * Create a general RPC client
 */
int nfs_init_server_rpcclient(struct nfs_server *server,
		const struct rpc_timeout *timeo,
		rpc_authflavor_t pseudoflavour)
{
	struct nfs_client *clp = server->nfs_client;

	server->client = rpc_clone_client_set_auth(clp->cl_rpcclient,
							pseudoflavour);
	if (IS_ERR(server->client)) {
		dprintk("%s: couldn't create rpc_client!\n", __func__);
		return PTR_ERR(server->client);
	}

	memcpy(&server->client->cl_timeout_default,
			timeo,
			sizeof(server->client->cl_timeout_default));
	server->client->cl_timeout = &server->client->cl_timeout_default;
	server->client->cl_softrtry = 0;
	if (server->flags & NFS_MOUNT_SOFT)
		server->client->cl_softrtry = 1;

	return 0;
}
EXPORT_SYMBOL_GPL(nfs_init_server_rpcclient);

/**
 * nfs_init_client - Initialise an NFS2 or NFS3 client
 *
 * @clp: nfs_client to initialise
 * @timeparms: timeout parameters for underlying RPC transport
 * @ip_addr: IP presentation address (not used)
 *
 * Returns pointer to an NFS client, or an ERR_PTR value.
 */
struct nfs_client *nfs_init_client(struct nfs_client *clp,
		    const struct rpc_timeout *timeparms,
		    const char *ip_addr)
{
	int error;

	if (clp->cl_cons_state == NFS_CS_READY) {
		/* the client is already initialised */
		dprintk("<-- nfs_init_client() = 0 [already %p]\n", clp);
		return clp;
	}

	/*
	 * Create a client RPC handle for doing FSSTAT with UNIX auth only
	 * - RFC 2623, sec 2.3.2
	 */
	error = nfs_create_rpc_client(clp, timeparms, RPC_AUTH_UNIX);
	if (error < 0)
		goto error;
	nfs_mark_client_ready(clp, NFS_CS_READY);
	return clp;

error:
	nfs_mark_client_ready(clp, error);
	nfs_put_client(clp);
	dprintk("<-- nfs_init_client() = xerror %d\n", error);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(nfs_init_client);

/*
 * Create a version 2 or 3 client
 */
static int nfs_init_server(struct nfs_server *server,
			   const struct nfs_parsed_mount_data *data,
			   struct nfs_subversion *nfs_mod)
{
	struct nfs_client_initdata cl_init = {
		.hostname = data->nfs_server.hostname,
		.addr = (const struct sockaddr *)&data->nfs_server.address,
		.addrlen = data->nfs_server.addrlen,
		.nfs_mod = nfs_mod,
		.proto = data->nfs_server.protocol,
		.net = data->net,
	};
	struct rpc_timeout timeparms;
	struct nfs_client *clp;
	int error;

	dprintk("--> nfs_init_server()\n");

	nfs_init_timeout_values(&timeparms, data->nfs_server.protocol,
			data->timeo, data->retrans);
	if (data->flags & NFS_MOUNT_NORESVPORT)
		set_bit(NFS_CS_NORESVPORT, &cl_init.init_flags);

	/* Allocate or find a client reference we can use */
	clp = nfs_get_client(&cl_init, &timeparms, NULL, RPC_AUTH_UNIX);
	if (IS_ERR(clp)) {
		dprintk("<-- nfs_init_server() = error %ld\n", PTR_ERR(clp));
		return PTR_ERR(clp);
	}

	server->nfs_client = clp;

	/* Initialise the client representation from the mount data */
	server->flags = data->flags;
	server->options = data->options;
	server->caps |= NFS_CAP_HARDLINKS|NFS_CAP_SYMLINKS|NFS_CAP_FILEID|
		NFS_CAP_MODE|NFS_CAP_NLINK|NFS_CAP_OWNER|NFS_CAP_OWNER_GROUP|
		NFS_CAP_ATIME|NFS_CAP_CTIME|NFS_CAP_MTIME|NFS_CAP_CHANGE_ATTR;

	if (data->rsize)
		server->rsize = nfs_block_size(data->rsize, NULL);
	if (data->wsize)
		server->wsize = nfs_block_size(data->wsize, NULL);

	server->acregmin = data->acregmin * HZ;
	server->acregmax = data->acregmax * HZ;
	server->acdirmin = data->acdirmin * HZ;
	server->acdirmax = data->acdirmax * HZ;

	/* Start lockd here, before we might error out */
	error = nfs_start_lockd(server);
	if (error < 0)
		goto error;

	server->port = data->nfs_server.port;
	server->auth_info = data->auth_info;

	error = nfs_init_server_rpcclient(server, &timeparms,
					  data->selected_flavor);
	if (error < 0)
		goto error;

	/* Preserve the values of mount_server-related mount options */
	if (data->mount_server.addrlen) {
		memcpy(&server->mountd_address, &data->mount_server.address,
			data->mount_server.addrlen);
		server->mountd_addrlen = data->mount_server.addrlen;
	}
	server->mountd_version = data->mount_server.version;
	server->mountd_port = data->mount_server.port;
	server->mountd_protocol = data->mount_server.protocol;

	server->namelen  = data->namlen;
	dprintk("<-- nfs_init_server() = 0 [new %p]\n", clp);
	return 0;

error:
	server->nfs_client = NULL;
	nfs_put_client(clp);
	dprintk("<-- nfs_init_server() = xerror %d\n", error);
	return error;
}

/*
 * Load up the server record from information gained in an fsinfo record
 */
static void nfs_server_set_fsinfo(struct nfs_server *server,
				  struct nfs_fh *mntfh,
				  struct nfs_fsinfo *fsinfo)
{
	unsigned long max_rpc_payload;

	/* Work out a lot of parameters */
	if (server->rsize == 0)
		server->rsize = nfs_block_size(fsinfo->rtpref, NULL);
	if (server->wsize == 0)
		server->wsize = nfs_block_size(fsinfo->wtpref, NULL);

	if (fsinfo->rtmax >= 512 && server->rsize > fsinfo->rtmax)
		server->rsize = nfs_block_size(fsinfo->rtmax, NULL);
	if (fsinfo->wtmax >= 512 && server->wsize > fsinfo->wtmax)
		server->wsize = nfs_block_size(fsinfo->wtmax, NULL);

	max_rpc_payload = nfs_block_size(rpc_max_payload(server->client), NULL);
	if (server->rsize > max_rpc_payload)
		server->rsize = max_rpc_payload;
	if (server->rsize > NFS_MAX_FILE_IO_SIZE)
		server->rsize = NFS_MAX_FILE_IO_SIZE;
	server->rpages = (server->rsize + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	server->backing_dev_info.name = "nfs";
	server->backing_dev_info.ra_pages = server->rpages * NFS_MAX_READAHEAD;

	if (server->wsize > max_rpc_payload)
		server->wsize = max_rpc_payload;
	if (server->wsize > NFS_MAX_FILE_IO_SIZE)
		server->wsize = NFS_MAX_FILE_IO_SIZE;
	server->wpages = (server->wsize + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;

	server->wtmult = nfs_block_bits(fsinfo->wtmult, NULL);

	server->dtsize = nfs_block_size(fsinfo->dtpref, NULL);
	if (server->dtsize > PAGE_CACHE_SIZE * NFS_MAX_READDIR_PAGES)
		server->dtsize = PAGE_CACHE_SIZE * NFS_MAX_READDIR_PAGES;
	if (server->dtsize > server->rsize)
		server->dtsize = server->rsize;

	if (server->flags & NFS_MOUNT_NOAC) {
		server->acregmin = server->acregmax = 0;
		server->acdirmin = server->acdirmax = 0;
	}

	server->maxfilesize = fsinfo->maxfilesize;

	server->time_delta = fsinfo->time_delta;

	/* We're airborne Set socket buffersize */
	rpc_setbufsize(server->client, server->wsize + 100, server->rsize + 100);
}

/*
 * Probe filesystem information, including the FSID on v2/v3
 */
int nfs_probe_fsinfo(struct nfs_server *server, struct nfs_fh *mntfh, struct nfs_fattr *fattr)
{
	struct nfs_fsinfo fsinfo;
	struct nfs_client *clp = server->nfs_client;
	int error;

	dprintk("--> nfs_probe_fsinfo()\n");

	if (clp->rpc_ops->set_capabilities != NULL) {
		error = clp->rpc_ops->set_capabilities(server, mntfh);
		if (error < 0)
			goto out_error;
	}

	fsinfo.fattr = fattr;
	fsinfo.layouttype = 0;
	error = clp->rpc_ops->fsinfo(server, mntfh, &fsinfo);
	if (error < 0)
		goto out_error;

	nfs_server_set_fsinfo(server, mntfh, &fsinfo);

	/* Get some general file system info */
	if (server->namelen == 0) {
		struct nfs_pathconf pathinfo;

		pathinfo.fattr = fattr;
		nfs_fattr_init(fattr);

		if (clp->rpc_ops->pathconf(server, mntfh, &pathinfo) >= 0)
			server->namelen = pathinfo.max_namelen;
	}

	dprintk("<-- nfs_probe_fsinfo() = 0\n");
	return 0;

out_error:
	dprintk("nfs_probe_fsinfo: error = %d\n", -error);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_probe_fsinfo);

/*
 * Copy useful information when duplicating a server record
 */
void nfs_server_copy_userdata(struct nfs_server *target, struct nfs_server *source)
{
	target->flags = source->flags;
	target->rsize = source->rsize;
	target->wsize = source->wsize;
	target->acregmin = source->acregmin;
	target->acregmax = source->acregmax;
	target->acdirmin = source->acdirmin;
	target->acdirmax = source->acdirmax;
	target->caps = source->caps;
	target->options = source->options;
	target->auth_info = source->auth_info;
}
EXPORT_SYMBOL_GPL(nfs_server_copy_userdata);

void nfs_server_insert_lists(struct nfs_server *server)
{
	struct nfs_client *clp = server->nfs_client;
	struct nfs_net *nn = net_generic(clp->cl_net, nfs_net_id);

	spin_lock(&nn->nfs_client_lock);
	list_add_tail_rcu(&server->client_link, &clp->cl_superblocks);
	list_add_tail(&server->master_link, &nn->nfs_volume_list);
	clear_bit(NFS_CS_STOP_RENEW, &clp->cl_res_state);
	spin_unlock(&nn->nfs_client_lock);

}
EXPORT_SYMBOL_GPL(nfs_server_insert_lists);

void nfs_server_remove_lists(struct nfs_server *server)
{
	struct nfs_client *clp = server->nfs_client;
	struct nfs_net *nn;

	if (clp == NULL)
		return;
	nn = net_generic(clp->cl_net, nfs_net_id);
	spin_lock(&nn->nfs_client_lock);
	list_del_rcu(&server->client_link);
	if (list_empty(&clp->cl_superblocks))
		set_bit(NFS_CS_STOP_RENEW, &clp->cl_res_state);
	list_del(&server->master_link);
	spin_unlock(&nn->nfs_client_lock);

	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(nfs_server_remove_lists);

/*
 * Allocate and initialise a server record
 */
struct nfs_server *nfs_alloc_server(void)
{
	struct nfs_server *server;

	server = kzalloc(sizeof(struct nfs_server), GFP_KERNEL);
	if (!server)
		return NULL;

	server->client = server->client_acl = ERR_PTR(-EINVAL);

	/* Zero out the NFS state stuff */
	INIT_LIST_HEAD(&server->client_link);
	INIT_LIST_HEAD(&server->master_link);
	INIT_LIST_HEAD(&server->delegations);
	INIT_LIST_HEAD(&server->layouts);
	INIT_LIST_HEAD(&server->state_owners_lru);

	atomic_set(&server->active, 0);

	server->io_stats = nfs_alloc_iostats();
	if (!server->io_stats) {
		kfree(server);
		return NULL;
	}

	if (bdi_init(&server->backing_dev_info)) {
		nfs_free_iostats(server->io_stats);
		kfree(server);
		return NULL;
	}

	ida_init(&server->openowner_id);
	ida_init(&server->lockowner_id);
	pnfs_init_server(server);

	return server;
}
EXPORT_SYMBOL_GPL(nfs_alloc_server);

/*
 * Free up a server record
 */
void nfs_free_server(struct nfs_server *server)
{
	dprintk("--> nfs_free_server()\n");

	nfs_server_remove_lists(server);

	if (server->destroy != NULL)
		server->destroy(server);

	if (!IS_ERR(server->client_acl))
		rpc_shutdown_client(server->client_acl);
	if (!IS_ERR(server->client))
		rpc_shutdown_client(server->client);

	nfs_put_client(server->nfs_client);

	ida_destroy(&server->lockowner_id);
	ida_destroy(&server->openowner_id);
	nfs_free_iostats(server->io_stats);
	bdi_destroy(&server->backing_dev_info);
	kfree(server);
	nfs_release_automount_timer();
	dprintk("<-- nfs_free_server()\n");
}
EXPORT_SYMBOL_GPL(nfs_free_server);

/*
 * Create a version 2 or 3 volume record
 * - keyed on server and FSID
 */
struct nfs_server *nfs_create_server(struct nfs_mount_info *mount_info,
				     struct nfs_subversion *nfs_mod)
{
	struct nfs_server *server;
	struct nfs_fattr *fattr;
	int error;

	server = nfs_alloc_server();
	if (!server)
		return ERR_PTR(-ENOMEM);

	error = -ENOMEM;
	fattr = nfs_alloc_fattr();
	if (fattr == NULL)
		goto error;

	/* Get a client representation */
	error = nfs_init_server(server, mount_info->parsed, nfs_mod);
	if (error < 0)
		goto error;

	/* Probe the root fh to retrieve its FSID */
	error = nfs_probe_fsinfo(server, mount_info->mntfh, fattr);
	if (error < 0)
		goto error;
	if (server->nfs_client->rpc_ops->version == 3) {
		if (server->namelen == 0 || server->namelen > NFS3_MAXNAMLEN)
			server->namelen = NFS3_MAXNAMLEN;
		if (!(mount_info->parsed->flags & NFS_MOUNT_NORDIRPLUS))
			server->caps |= NFS_CAP_READDIRPLUS;
	} else {
		if (server->namelen == 0 || server->namelen > NFS2_MAXNAMLEN)
			server->namelen = NFS2_MAXNAMLEN;
	}

	if (!(fattr->valid & NFS_ATTR_FATTR)) {
		error = nfs_mod->rpc_ops->getattr(server, mount_info->mntfh, fattr, NULL);
		if (error < 0) {
			dprintk("nfs_create_server: getattr error = %d\n", -error);
			goto error;
		}
	}
	memcpy(&server->fsid, &fattr->fsid, sizeof(server->fsid));

	dprintk("Server FSID: %llx:%llx\n",
		(unsigned long long) server->fsid.major,
		(unsigned long long) server->fsid.minor);

	nfs_server_insert_lists(server);
	server->mount_time = jiffies;
	nfs_free_fattr(fattr);
	return server;

error:
	nfs_free_fattr(fattr);
	nfs_free_server(server);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(nfs_create_server);

/*
 * Clone an NFS2, NFS3 or NFS4 server record
 */
struct nfs_server *nfs_clone_server(struct nfs_server *source,
				    struct nfs_fh *fh,
				    struct nfs_fattr *fattr,
				    rpc_authflavor_t flavor)
{
	struct nfs_server *server;
	struct nfs_fattr *fattr_fsinfo;
	int error;

	dprintk("--> nfs_clone_server(,%llx:%llx,)\n",
		(unsigned long long) fattr->fsid.major,
		(unsigned long long) fattr->fsid.minor);

	server = nfs_alloc_server();
	if (!server)
		return ERR_PTR(-ENOMEM);

	error = -ENOMEM;
	fattr_fsinfo = nfs_alloc_fattr();
	if (fattr_fsinfo == NULL)
		goto out_free_server;

	/* Copy data from the source */
	server->nfs_client = source->nfs_client;
	server->destroy = source->destroy;
	atomic_inc(&server->nfs_client->cl_count);
	nfs_server_copy_userdata(server, source);

	server->fsid = fattr->fsid;

	error = nfs_init_server_rpcclient(server,
			source->client->cl_timeout,
			flavor);
	if (error < 0)
		goto out_free_server;

	/* probe the filesystem info for this server filesystem */
	error = nfs_probe_fsinfo(server, fh, fattr_fsinfo);
	if (error < 0)
		goto out_free_server;

	if (server->namelen == 0 || server->namelen > NFS4_MAXNAMLEN)
		server->namelen = NFS4_MAXNAMLEN;

	dprintk("Cloned FSID: %llx:%llx\n",
		(unsigned long long) server->fsid.major,
		(unsigned long long) server->fsid.minor);

	error = nfs_start_lockd(server);
	if (error < 0)
		goto out_free_server;

	nfs_server_insert_lists(server);
	server->mount_time = jiffies;

	nfs_free_fattr(fattr_fsinfo);
	dprintk("<-- nfs_clone_server() = %p\n", server);
	return server;

out_free_server:
	nfs_free_fattr(fattr_fsinfo);
	nfs_free_server(server);
	dprintk("<-- nfs_clone_server() = error %d\n", error);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(nfs_clone_server);

void nfs_clients_init(struct net *net)
{
	struct nfs_net *nn = net_generic(net, nfs_net_id);

	INIT_LIST_HEAD(&nn->nfs_client_list);
	INIT_LIST_HEAD(&nn->nfs_volume_list);
#if IS_ENABLED(CONFIG_NFS_V4)
	idr_init(&nn->cb_ident_idr);
#endif
	spin_lock_init(&nn->nfs_client_lock);
	nn->boot_time = CURRENT_TIME;
}

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *proc_fs_nfs;

static int nfs_server_list_open(struct inode *inode, struct file *file);
static void *nfs_server_list_start(struct seq_file *p, loff_t *pos);
static void *nfs_server_list_next(struct seq_file *p, void *v, loff_t *pos);
static void nfs_server_list_stop(struct seq_file *p, void *v);
static int nfs_server_list_show(struct seq_file *m, void *v);

static const struct seq_operations nfs_server_list_ops = {
	.start	= nfs_server_list_start,
	.next	= nfs_server_list_next,
	.stop	= nfs_server_list_stop,
	.show	= nfs_server_list_show,
};

static const struct file_operations nfs_server_list_fops = {
	.open		= nfs_server_list_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_net,
	.owner		= THIS_MODULE,
};

static int nfs_volume_list_open(struct inode *inode, struct file *file);
static void *nfs_volume_list_start(struct seq_file *p, loff_t *pos);
static void *nfs_volume_list_next(struct seq_file *p, void *v, loff_t *pos);
static void nfs_volume_list_stop(struct seq_file *p, void *v);
static int nfs_volume_list_show(struct seq_file *m, void *v);

static const struct seq_operations nfs_volume_list_ops = {
	.start	= nfs_volume_list_start,
	.next	= nfs_volume_list_next,
	.stop	= nfs_volume_list_stop,
	.show	= nfs_volume_list_show,
};

static const struct file_operations nfs_volume_list_fops = {
	.open		= nfs_volume_list_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release_net,
	.owner		= THIS_MODULE,
};

/*
 * open "/proc/fs/nfsfs/servers" which provides a summary of servers with which
 * we're dealing
 */
static int nfs_server_list_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &nfs_server_list_ops,
			   sizeof(struct seq_net_private));
}

/*
 * set up the iterator to start reading from the server list and return the first item
 */
static void *nfs_server_list_start(struct seq_file *m, loff_t *_pos)
{
	struct nfs_net *nn = net_generic(seq_file_net(m), nfs_net_id);

	/* lock the list against modification */
	spin_lock(&nn->nfs_client_lock);
	return seq_list_start_head(&nn->nfs_client_list, *_pos);
}

/*
 * move to next server
 */
static void *nfs_server_list_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct nfs_net *nn = net_generic(seq_file_net(p), nfs_net_id);

	return seq_list_next(v, &nn->nfs_client_list, pos);
}

/*
 * clean up after reading from the transports list
 */
static void nfs_server_list_stop(struct seq_file *p, void *v)
{
	struct nfs_net *nn = net_generic(seq_file_net(p), nfs_net_id);

	spin_unlock(&nn->nfs_client_lock);
}

/*
 * display a header line followed by a load of call lines
 */
static int nfs_server_list_show(struct seq_file *m, void *v)
{
	struct nfs_client *clp;
	struct nfs_net *nn = net_generic(seq_file_net(m), nfs_net_id);

	/* display header on line 1 */
	if (v == &nn->nfs_client_list) {
		seq_puts(m, "NV SERVER   PORT USE HOSTNAME\n");
		return 0;
	}

	/* display one transport per line on subsequent lines */
	clp = list_entry(v, struct nfs_client, cl_share_link);

	/* Check if the client is initialized */
	if (clp->cl_cons_state != NFS_CS_READY)
		return 0;

	rcu_read_lock();
	seq_printf(m, "v%u %s %s %3d %s\n",
		   clp->rpc_ops->version,
		   rpc_peeraddr2str(clp->cl_rpcclient, RPC_DISPLAY_HEX_ADDR),
		   rpc_peeraddr2str(clp->cl_rpcclient, RPC_DISPLAY_HEX_PORT),
		   atomic_read(&clp->cl_count),
		   clp->cl_hostname);
	rcu_read_unlock();

	return 0;
}

/*
 * open "/proc/fs/nfsfs/volumes" which provides a summary of extant volumes
 */
static int nfs_volume_list_open(struct inode *inode, struct file *file)
{
	return seq_open_net(inode, file, &nfs_server_list_ops,
			   sizeof(struct seq_net_private));
}

/*
 * set up the iterator to start reading from the volume list and return the first item
 */
static void *nfs_volume_list_start(struct seq_file *m, loff_t *_pos)
{
	struct nfs_net *nn = net_generic(seq_file_net(m), nfs_net_id);

	/* lock the list against modification */
	spin_lock(&nn->nfs_client_lock);
	return seq_list_start_head(&nn->nfs_volume_list, *_pos);
}

/*
 * move to next volume
 */
static void *nfs_volume_list_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct nfs_net *nn = net_generic(seq_file_net(p), nfs_net_id);

	return seq_list_next(v, &nn->nfs_volume_list, pos);
}

/*
 * clean up after reading from the transports list
 */
static void nfs_volume_list_stop(struct seq_file *p, void *v)
{
	struct nfs_net *nn = net_generic(seq_file_net(p), nfs_net_id);

	spin_unlock(&nn->nfs_client_lock);
}

/*
 * display a header line followed by a load of call lines
 */
static int nfs_volume_list_show(struct seq_file *m, void *v)
{
	struct nfs_server *server;
	struct nfs_client *clp;
	char dev[8], fsid[17];
	struct nfs_net *nn = net_generic(seq_file_net(m), nfs_net_id);

	/* display header on line 1 */
	if (v == &nn->nfs_volume_list) {
		seq_puts(m, "NV SERVER   PORT DEV     FSID              FSC\n");
		return 0;
	}
	/* display one transport per line on subsequent lines */
	server = list_entry(v, struct nfs_server, master_link);
	clp = server->nfs_client;

	snprintf(dev, 8, "%u:%u",
		 MAJOR(server->s_dev), MINOR(server->s_dev));

	snprintf(fsid, 17, "%llx:%llx",
		 (unsigned long long) server->fsid.major,
		 (unsigned long long) server->fsid.minor);

	rcu_read_lock();
	seq_printf(m, "v%u %s %s %-7s %-17s %s\n",
		   clp->rpc_ops->version,
		   rpc_peeraddr2str(clp->cl_rpcclient, RPC_DISPLAY_HEX_ADDR),
		   rpc_peeraddr2str(clp->cl_rpcclient, RPC_DISPLAY_HEX_PORT),
		   dev,
		   fsid,
		   nfs_server_fscache_state(server));
	rcu_read_unlock();

	return 0;
}

int nfs_fs_proc_net_init(struct net *net)
{
	struct nfs_net *nn = net_generic(net, nfs_net_id);
	struct proc_dir_entry *p;

	nn->proc_nfsfs = proc_net_mkdir(net, "nfsfs", net->proc_net);
	if (!nn->proc_nfsfs)
		goto error_0;

	/* a file of servers with which we're dealing */
	p = proc_create("servers", S_IFREG|S_IRUGO,
			nn->proc_nfsfs, &nfs_server_list_fops);
	if (!p)
		goto error_1;

	/* a file of volumes that we have mounted */
	p = proc_create("volumes", S_IFREG|S_IRUGO,
			nn->proc_nfsfs, &nfs_volume_list_fops);
	if (!p)
		goto error_2;
	return 0;

error_2:
	remove_proc_entry("servers", nn->proc_nfsfs);
error_1:
	remove_proc_entry("fs/nfsfs", NULL);
error_0:
	return -ENOMEM;
}

void nfs_fs_proc_net_exit(struct net *net)
{
	struct nfs_net *nn = net_generic(net, nfs_net_id);

	remove_proc_entry("volumes", nn->proc_nfsfs);
	remove_proc_entry("servers", nn->proc_nfsfs);
	remove_proc_entry("fs/nfsfs", NULL);
}

/*
 * initialise the /proc/fs/nfsfs/ directory
 */
int __init nfs_fs_proc_init(void)
{
	struct proc_dir_entry *p;

	proc_fs_nfs = proc_mkdir("fs/nfsfs", NULL);
	if (!proc_fs_nfs)
		goto error_0;

	/* a file of servers with which we're dealing */
	p = proc_symlink("servers", proc_fs_nfs, "../../net/nfsfs/servers");
	if (!p)
		goto error_1;

	/* a file of volumes that we have mounted */
	p = proc_symlink("volumes", proc_fs_nfs, "../../net/nfsfs/volumes");
	if (!p)
		goto error_2;
	return 0;

error_2:
	remove_proc_entry("servers", proc_fs_nfs);
error_1:
	remove_proc_entry("fs/nfsfs", NULL);
error_0:
	return -ENOMEM;
}

/*
 * clean up the /proc/fs/nfsfs/ directory
 */
void nfs_fs_proc_exit(void)
{
	remove_proc_entry("volumes", proc_fs_nfs);
	remove_proc_entry("servers", proc_fs_nfs);
	remove_proc_entry("fs/nfsfs", NULL);
}

#endif /* CONFIG_PROC_FS */
/************************************************************/
/* ../linux-3.17/fs/nfs/client.c */
/************************************************************/
/*
 *  linux/fs/nfs/dir.c
 *
 *  Copyright (C) 1992  Rick Sladkey
 *
 *  nfs directory handling functions
 *
 * 10 Apr 1996	Added silly rename for unlink	--okir
 * 28 Sep 1996	Improved directory cache --okir
 * 23 Aug 1997  Claus Heine claus@momo.math.rwth-aachen.de
 *              Re-implemented silly rename for unlink, newly implemented
 *              silly rename for nfs_rename() following the suggestions
 *              of Olaf Kirch (okir) found in this file.
 *              Following Linus comments on my original hack, this version
 *              depends only on the dcache stuff and doesn't touch the inode
 *              layer (iput() and friends).
 *  6 Jun 1999	Cache readdir lookups in the page cache. -DaveM
 */

// #include <linux/module.h>
// #include <linux/time.h>
// #include <linux/errno.h>
// #include <linux/stat.h>
#include <linux/fcntl.h>
// #include <linux/string.h>
// #include <linux/kernel.h>
// #include <linux/slab.h>
// #include <linux/mm.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/nfs_fs.h>
// #include <linux/nfs_mount.h>
#include <linux/pagemap.h>
#include <linux/pagevec.h>
#include <linux/namei.h>
// #include <linux/mount.h>
#include <linux/swap.h>
// #include <linux/sched.h>
#include <linux/kmemleak.h>
#include <linux/xattr.h>

// #include "delegation.h"
// #include "iostat.h"
// #include "internal.h"
// #include "fscache.h"

#include "nfstrace.h"

/* #define NFS_DEBUG_VERBOSE 1 */

static int nfs_opendir(struct inode *, struct file *);
static int nfs_closedir(struct inode *, struct file *);
static int nfs_readdir(struct file *, struct dir_context *);
static int nfs_fsync_dir(struct file *, loff_t, loff_t, int);
static loff_t nfs_llseek_dir(struct file *, loff_t, int);
static void nfs_readdir_clear_array(struct page*);

const struct file_operations nfs_dir_operations = {
	.llseek		= nfs_llseek_dir,
	.read		= generic_read_dir,
	.iterate	= nfs_readdir,
	.open		= nfs_opendir,
	.release	= nfs_closedir,
	.fsync		= nfs_fsync_dir,
};

const struct address_space_operations nfs_dir_aops = {
	.freepage = nfs_readdir_clear_array,
};

static struct nfs_open_dir_context *alloc_nfs_open_dir_context(struct inode *dir, struct rpc_cred *cred)
{
	struct nfs_inode *nfsi = NFS_I(dir);
	struct nfs_open_dir_context *ctx;
	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (ctx != NULL) {
		ctx->duped = 0;
		ctx->attr_gencount = nfsi->attr_gencount;
		ctx->dir_cookie = 0;
		ctx->dup_cookie = 0;
		ctx->cred = get_rpccred(cred);
		spin_lock(&dir->i_lock);
		list_add(&ctx->list, &nfsi->open_files);
		spin_unlock(&dir->i_lock);
		return ctx;
	}
	return  ERR_PTR(-ENOMEM);
}

static void put_nfs_open_dir_context(struct inode *dir, struct nfs_open_dir_context *ctx)
{
	spin_lock(&dir->i_lock);
	list_del(&ctx->list);
	spin_unlock(&dir->i_lock);
	put_rpccred(ctx->cred);
	kfree(ctx);
}

/*
 * Open file
 */
static int
nfs_opendir(struct inode *inode, struct file *filp)
{
	int res = 0;
	struct nfs_open_dir_context *ctx;
	struct rpc_cred *cred;

	dfprintk(FILE, "NFS: open dir(%pD2)\n", filp);

	nfs_inc_stats(inode, NFSIOS_VFSOPEN);

	cred = rpc_lookup_cred();
	if (IS_ERR(cred))
		return PTR_ERR(cred);
	ctx = alloc_nfs_open_dir_context(inode, cred);
	if (IS_ERR(ctx)) {
		res = PTR_ERR(ctx);
		goto out;
	}
	filp->private_data = ctx;
	if (filp->f_path.dentry == filp->f_path.mnt->mnt_root) {
		/* This is a mountpoint, so d_revalidate will never
		 * have been called, so we need to refresh the
		 * inode (for close-open consistency) ourselves.
		 */
		__nfs_revalidate_inode(NFS_SERVER(inode), inode);
	}
out:
	put_rpccred(cred);
	return res;
}

static int
nfs_closedir(struct inode *inode, struct file *filp)
{
	put_nfs_open_dir_context(filp->f_path.dentry->d_inode, filp->private_data);
	return 0;
}

struct nfs_cache_array_entry {
	u64 cookie;
	u64 ino;
	struct qstr string;
	unsigned char d_type;
};

struct nfs_cache_array {
	int size;
	int eof_index;
	u64 last_cookie;
	struct nfs_cache_array_entry array[0];
};

typedef int (*decode_dirent_t)(struct xdr_stream *, struct nfs_entry *, int);
typedef struct {
	struct file	*file;
	struct page	*page;
	struct dir_context *ctx;
	unsigned long	page_index;
	u64		*dir_cookie;
	u64		last_cookie;
	loff_t		current_index;
	decode_dirent_t	decode;

	unsigned long	timestamp;
	unsigned long	gencount;
	unsigned int	cache_entry_index;
	unsigned int	plus:1;
	unsigned int	eof:1;
} nfs_readdir_descriptor_t;

/*
 * The caller is responsible for calling nfs_readdir_release_array(page)
 */
static
struct nfs_cache_array *nfs_readdir_get_array(struct page *page)
{
	void *ptr;
	if (page == NULL)
		return ERR_PTR(-EIO);
	ptr = kmap(page);
	if (ptr == NULL)
		return ERR_PTR(-ENOMEM);
	return ptr;
}

static
void nfs_readdir_release_array(struct page *page)
{
	kunmap(page);
}

/*
 * we are freeing strings created by nfs_add_to_readdir_array()
 */
static
void nfs_readdir_clear_array(struct page *page)
{
	struct nfs_cache_array *array;
	int i;

	array = kmap_atomic(page);
	for (i = 0; i < array->size; i++)
		kfree(array->array[i].string.name);
	kunmap_atomic(array);
}

/*
 * the caller is responsible for freeing qstr.name
 * when called by nfs_readdir_add_to_array, the strings will be freed in
 * nfs_clear_readdir_array()
 */
static
int nfs_readdir_make_qstr(struct qstr *string, const char *name, unsigned int len)
{
	string->len = len;
	string->name = kmemdup(name, len, GFP_KERNEL);
	if (string->name == NULL)
		return -ENOMEM;
	/*
	 * Avoid a kmemleak false positive. The pointer to the name is stored
	 * in a page cache page which kmemleak does not scan.
	 */
	kmemleak_not_leak(string->name);
	string->hash = full_name_hash(name, len);
	return 0;
}

static
int nfs_readdir_add_to_array(struct nfs_entry *entry, struct page *page)
{
	struct nfs_cache_array *array = nfs_readdir_get_array(page);
	struct nfs_cache_array_entry *cache_entry;
	int ret;

	if (IS_ERR(array))
		return PTR_ERR(array);

	cache_entry = &array->array[array->size];

	/* Check that this entry lies within the page bounds */
	ret = -ENOSPC;
	if ((char *)&cache_entry[1] - (char *)page_address(page) > PAGE_SIZE)
		goto out;

	cache_entry->cookie = entry->prev_cookie;
	cache_entry->ino = entry->ino;
	cache_entry->d_type = entry->d_type;
	ret = nfs_readdir_make_qstr(&cache_entry->string, entry->name, entry->len);
	if (ret)
		goto out;
	array->last_cookie = entry->cookie;
	array->size++;
	if (entry->eof != 0)
		array->eof_index = array->size;
out:
	nfs_readdir_release_array(page);
	return ret;
}

static
int nfs_readdir_search_for_pos(struct nfs_cache_array *array, nfs_readdir_descriptor_t *desc)
{
	loff_t diff = desc->ctx->pos - desc->current_index;
	unsigned int index;

	if (diff < 0)
		goto out_eof;
	if (diff >= array->size) {
		if (array->eof_index >= 0)
			goto out_eof;
		return -EAGAIN;
	}

	index = (unsigned int)diff;
	*desc->dir_cookie = array->array[index].cookie;
	desc->cache_entry_index = index;
	return 0;
out_eof:
	desc->eof = 1;
	return -EBADCOOKIE;
}

static bool
nfs_readdir_inode_mapping_valid(struct nfs_inode *nfsi)
{
	if (nfsi->cache_validity & (NFS_INO_INVALID_ATTR|NFS_INO_INVALID_DATA))
		return false;
	smp_rmb();
	return !test_bit(NFS_INO_INVALIDATING, &nfsi->flags);
}

static
int nfs_readdir_search_for_cookie(struct nfs_cache_array *array, nfs_readdir_descriptor_t *desc)
{
	int i;
	loff_t new_pos;
	int status = -EAGAIN;

	for (i = 0; i < array->size; i++) {
		if (array->array[i].cookie == *desc->dir_cookie) {
			struct nfs_inode *nfsi = NFS_I(file_inode(desc->file));
			struct nfs_open_dir_context *ctx = desc->file->private_data;

			new_pos = desc->current_index + i;
			if (ctx->attr_gencount != nfsi->attr_gencount ||
			    !nfs_readdir_inode_mapping_valid(nfsi)) {
				ctx->duped = 0;
				ctx->attr_gencount = nfsi->attr_gencount;
			} else if (new_pos < desc->ctx->pos) {
				if (ctx->duped > 0
				    && ctx->dup_cookie == *desc->dir_cookie) {
					if (printk_ratelimit()) {
						pr_notice("NFS: directory %pD2 contains a readdir loop."
								"Please contact your server vendor.  "
								"The file: %.*s has duplicate cookie %llu\n",
								desc->file, array->array[i].string.len,
								array->array[i].string.name, *desc->dir_cookie);
					}
					status = -ELOOP;
					goto out;
				}
				ctx->dup_cookie = *desc->dir_cookie;
				ctx->duped = -1;
			}
			desc->ctx->pos = new_pos;
			desc->cache_entry_index = i;
			return 0;
		}
	}
	if (array->eof_index >= 0) {
		status = -EBADCOOKIE;
		if (*desc->dir_cookie == array->last_cookie)
			desc->eof = 1;
	}
out:
	return status;
}

static
int nfs_readdir_search_array(nfs_readdir_descriptor_t *desc)
{
	struct nfs_cache_array *array;
	int status;

	array = nfs_readdir_get_array(desc->page);
	if (IS_ERR(array)) {
		status = PTR_ERR(array);
		goto out;
	}

	if (*desc->dir_cookie == 0)
		status = nfs_readdir_search_for_pos(array, desc);
	else
		status = nfs_readdir_search_for_cookie(array, desc);

	if (status == -EAGAIN) {
		desc->last_cookie = array->last_cookie;
		desc->current_index += array->size;
		desc->page_index++;
	}
	nfs_readdir_release_array(desc->page);
out:
	return status;
}

/* Fill a page with xdr information before transferring to the cache page */
static
int nfs_readdir_xdr_filler(struct page **pages, nfs_readdir_descriptor_t *desc,
			struct nfs_entry *entry, struct file *file, struct inode *inode)
{
	struct nfs_open_dir_context *ctx = file->private_data;
	struct rpc_cred	*cred = ctx->cred;
	unsigned long	timestamp, gencount;
	int		error;

 again:
	timestamp = jiffies;
	gencount = nfs_inc_attr_generation_counter();
	error = NFS_PROTO(inode)->readdir(file->f_path.dentry, cred, entry->cookie, pages,
					  NFS_SERVER(inode)->dtsize, desc->plus);
	if (error < 0) {
		/* We requested READDIRPLUS, but the server doesn't grok it */
		if (error == -ENOTSUPP && desc->plus) {
			NFS_SERVER(inode)->caps &= ~NFS_CAP_READDIRPLUS;
			clear_bit(NFS_INO_ADVISE_RDPLUS, &NFS_I(inode)->flags);
			desc->plus = 0;
			goto again;
		}
		goto error;
	}
	desc->timestamp = timestamp;
	desc->gencount = gencount;
error:
	return error;
}

static int xdr_decode(nfs_readdir_descriptor_t *desc,
		      struct nfs_entry *entry, struct xdr_stream *xdr)
{
	int error;

	error = desc->decode(xdr, entry, desc->plus);
	if (error)
		return error;
	entry->fattr->time_start = desc->timestamp;
	entry->fattr->gencount = desc->gencount;
	return 0;
}

static
int nfs_same_file(struct dentry *dentry, struct nfs_entry *entry)
{
	if (dentry->d_inode == NULL)
		goto different;
	if (nfs_compare_fh(entry->fh, NFS_FH(dentry->d_inode)) != 0)
		goto different;
	return 1;
different:
	return 0;
}

static
bool nfs_use_readdirplus(struct inode *dir, struct dir_context *ctx)
{
	if (!nfs_server_capable(dir, NFS_CAP_READDIRPLUS))
		return false;
	if (test_and_clear_bit(NFS_INO_ADVISE_RDPLUS, &NFS_I(dir)->flags))
		return true;
	if (ctx->pos == 0)
		return true;
	return false;
}

/*
 * This function is called by the lookup code to request the use of
 * readdirplus to accelerate any future lookups in the same
 * directory.
 */
static
void nfs_advise_use_readdirplus(struct inode *dir)
{
	set_bit(NFS_INO_ADVISE_RDPLUS, &NFS_I(dir)->flags);
}

/*
 * This function is mainly for use by nfs_getattr().
 *
 * If this is an 'ls -l', we want to force use of readdirplus.
 * Do this by checking if there is an active file descriptor
 * and calling nfs_advise_use_readdirplus, then forcing a
 * cache flush.
 */
void nfs_force_use_readdirplus(struct inode *dir)
{
	if (!list_empty(&NFS_I(dir)->open_files)) {
		nfs_advise_use_readdirplus(dir);
		nfs_zap_mapping(dir, dir->i_mapping);
	}
}

static
void nfs_prime_dcache(struct dentry *parent, struct nfs_entry *entry)
{
	struct qstr filename = QSTR_INIT(entry->name, entry->len);
	struct dentry *dentry;
	struct dentry *alias;
	struct inode *dir = parent->d_inode;
	struct inode *inode;
	int status;

	if (filename.name[0] == '.') {
		if (filename.len == 1)
			return;
		if (filename.len == 2 && filename.name[1] == '.')
			return;
	}
	filename.hash = full_name_hash(filename.name, filename.len);

	dentry = d_lookup(parent, &filename);
	if (dentry != NULL) {
		if (nfs_same_file(dentry, entry)) {
			nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
			status = nfs_refresh_inode(dentry->d_inode, entry->fattr);
			if (!status)
				nfs_setsecurity(dentry->d_inode, entry->fattr, entry->label);
			goto out;
		} else {
			if (d_invalidate(dentry) != 0)
				goto out;
			dput(dentry);
		}
	}

	dentry = d_alloc(parent, &filename);
	if (dentry == NULL)
		return;

	inode = nfs_fhget(dentry->d_sb, entry->fh, entry->fattr, entry->label);
	if (IS_ERR(inode))
		goto out;

	alias = d_materialise_unique(dentry, inode);
	if (IS_ERR(alias))
		goto out;
	else if (alias) {
		nfs_set_verifier(alias, nfs_save_change_attribute(dir));
		dput(alias);
	} else
		nfs_set_verifier(dentry, nfs_save_change_attribute(dir));

out:
	dput(dentry);
}

/* Perform conversion from xdr to cache array */
static
int nfs_readdir_page_filler(nfs_readdir_descriptor_t *desc, struct nfs_entry *entry,
				struct page **xdr_pages, struct page *page, unsigned int buflen)
{
	struct xdr_stream stream;
	struct xdr_buf buf;
	struct page *scratch;
	struct nfs_cache_array *array;
	unsigned int count = 0;
	int status;

	scratch = alloc_page(GFP_KERNEL);
	if (scratch == NULL)
		return -ENOMEM;

	xdr_init_decode_pages(&stream, &buf, xdr_pages, buflen);
	xdr_set_scratch_buffer(&stream, page_address(scratch), PAGE_SIZE);

	do {
		status = xdr_decode(desc, entry, &stream);
		if (status != 0) {
			if (status == -EAGAIN)
				status = 0;
			break;
		}

		count++;

		if (desc->plus != 0)
			nfs_prime_dcache(desc->file->f_path.dentry, entry);

		status = nfs_readdir_add_to_array(entry, page);
		if (status != 0)
			break;
	} while (!entry->eof);

	if (count == 0 || (status == -EBADCOOKIE && entry->eof != 0)) {
		array = nfs_readdir_get_array(page);
		if (!IS_ERR(array)) {
			array->eof_index = array->size;
			status = 0;
			nfs_readdir_release_array(page);
		} else
			status = PTR_ERR(array);
	}

	put_page(scratch);
	return status;
}

static
void nfs_readdir_free_pagearray(struct page **pages, unsigned int npages)
{
	unsigned int i;
	for (i = 0; i < npages; i++)
		put_page(pages[i]);
}

static
void nfs_readdir_free_large_page(void *ptr, struct page **pages,
		unsigned int npages)
{
	nfs_readdir_free_pagearray(pages, npages);
}

/*
 * nfs_readdir_large_page will allocate pages that must be freed with a call
 * to nfs_readdir_free_large_page
 */
static
int nfs_readdir_large_page(struct page **pages, unsigned int npages)
{
	unsigned int i;

	for (i = 0; i < npages; i++) {
		struct page *page = alloc_page(GFP_KERNEL);
		if (page == NULL)
			goto out_freepages;
		pages[i] = page;
	}
	return 0;

out_freepages:
	nfs_readdir_free_pagearray(pages, i);
	return -ENOMEM;
}

static
int nfs_readdir_xdr_to_array(nfs_readdir_descriptor_t *desc, struct page *page, struct inode *inode)
{
	struct page *pages[NFS_MAX_READDIR_PAGES];
	void *pages_ptr = NULL;
	struct nfs_entry entry;
	struct file	*file = desc->file;
	struct nfs_cache_array *array;
	int status = -ENOMEM;
	unsigned int array_size = ARRAY_SIZE(pages);

	entry.prev_cookie = 0;
	entry.cookie = desc->last_cookie;
	entry.eof = 0;
	entry.fh = nfs_alloc_fhandle();
	entry.fattr = nfs_alloc_fattr();
	entry.server = NFS_SERVER(inode);
	if (entry.fh == NULL || entry.fattr == NULL)
		goto out;

	entry.label = nfs4_label_alloc(NFS_SERVER(inode), GFP_NOWAIT);
	if (IS_ERR(entry.label)) {
		status = PTR_ERR(entry.label);
		goto out;
	}

	array = nfs_readdir_get_array(page);
	if (IS_ERR(array)) {
		status = PTR_ERR(array);
		goto out_label_free;
	}
	memset(array, 0, sizeof(struct nfs_cache_array));
	array->eof_index = -1;

	status = nfs_readdir_large_page(pages, array_size);
	if (status < 0)
		goto out_release_array;
	do {
		unsigned int pglen;
		status = nfs_readdir_xdr_filler(pages, desc, &entry, file, inode);

		if (status < 0)
			break;
		pglen = status;
		status = nfs_readdir_page_filler(desc, &entry, pages, page, pglen);
		if (status < 0) {
			if (status == -ENOSPC)
				status = 0;
			break;
		}
	} while (array->eof_index < 0);

	nfs_readdir_free_large_page(pages_ptr, pages, array_size);
out_release_array:
	nfs_readdir_release_array(page);
out_label_free:
	nfs4_label_free(entry.label);
out:
	nfs_free_fattr(entry.fattr);
	nfs_free_fhandle(entry.fh);
	return status;
}

/*
 * Now we cache directories properly, by converting xdr information
 * to an array that can be used for lookups later.  This results in
 * fewer cache pages, since we can store more information on each page.
 * We only need to convert from xdr once so future lookups are much simpler
 */
static
int nfs_readdir_filler(nfs_readdir_descriptor_t *desc, struct page* page)
{
	struct inode	*inode = file_inode(desc->file);
	int ret;

	ret = nfs_readdir_xdr_to_array(desc, page, inode);
	if (ret < 0)
		goto error;
	SetPageUptodate(page);

	if (invalidate_inode_pages2_range(inode->i_mapping, page->index + 1, -1) < 0) {
		/* Should never happen */
		nfs_zap_mapping(inode, inode->i_mapping);
	}
	unlock_page(page);
	return 0;
 error:
	unlock_page(page);
	return ret;
}

static
void cache_page_release(nfs_readdir_descriptor_t *desc)
{
	if (!desc->page->mapping)
		nfs_readdir_clear_array(desc->page);
	page_cache_release(desc->page);
	desc->page = NULL;
}

static
struct page *get_cache_page(nfs_readdir_descriptor_t *desc)
{
	return read_cache_page(file_inode(desc->file)->i_mapping,
			desc->page_index, (filler_t *)nfs_readdir_filler, desc);
}

/*
 * Returns 0 if desc->dir_cookie was found on page desc->page_index
 */
static
int find_cache_page(nfs_readdir_descriptor_t *desc)
{
	int res;

	desc->page = get_cache_page(desc);
	if (IS_ERR(desc->page))
		return PTR_ERR(desc->page);

	res = nfs_readdir_search_array(desc);
	if (res != 0)
		cache_page_release(desc);
	return res;
}

/* Search for desc->dir_cookie from the beginning of the page cache */
static inline
int readdir_search_pagecache(nfs_readdir_descriptor_t *desc)
{
	int res;

	if (desc->page_index == 0) {
		desc->current_index = 0;
		desc->last_cookie = 0;
	}
	do {
		res = find_cache_page(desc);
	} while (res == -EAGAIN);
	return res;
}

/*
 * Once we've found the start of the dirent within a page: fill 'er up...
 */
static
int nfs_do_filldir(nfs_readdir_descriptor_t *desc)
{
	struct file	*file = desc->file;
	int i = 0;
	int res = 0;
	struct nfs_cache_array *array = NULL;
	struct nfs_open_dir_context *ctx = file->private_data;

	array = nfs_readdir_get_array(desc->page);
	if (IS_ERR(array)) {
		res = PTR_ERR(array);
		goto out;
	}

	for (i = desc->cache_entry_index; i < array->size; i++) {
		struct nfs_cache_array_entry *ent;

		ent = &array->array[i];
		if (!dir_emit(desc->ctx, ent->string.name, ent->string.len,
		    nfs_compat_user_ino64(ent->ino), ent->d_type)) {
			desc->eof = 1;
			break;
		}
		desc->ctx->pos++;
		if (i < (array->size-1))
			*desc->dir_cookie = array->array[i+1].cookie;
		else
			*desc->dir_cookie = array->last_cookie;
		if (ctx->duped != 0)
			ctx->duped = 1;
	}
	if (array->eof_index >= 0)
		desc->eof = 1;

	nfs_readdir_release_array(desc->page);
out:
	cache_page_release(desc);
	dfprintk(DIRCACHE, "NFS: nfs_do_filldir() filling ended @ cookie %Lu; returning = %d\n",
			(unsigned long long)*desc->dir_cookie, res);
	return res;
}

/*
 * If we cannot find a cookie in our cache, we suspect that this is
 * because it points to a deleted file, so we ask the server to return
 * whatever it thinks is the next entry. We then feed this to filldir.
 * If all goes well, we should then be able to find our way round the
 * cache on the next call to readdir_search_pagecache();
 *
 * NOTE: we cannot add the anonymous page to the pagecache because
 *	 the data it contains might not be page aligned. Besides,
 *	 we should already have a complete representation of the
 *	 directory in the page cache by the time we get here.
 */
static inline
int uncached_readdir(nfs_readdir_descriptor_t *desc)
{
	struct page	*page = NULL;
	int		status;
	struct inode *inode = file_inode(desc->file);
	struct nfs_open_dir_context *ctx = desc->file->private_data;

	dfprintk(DIRCACHE, "NFS: uncached_readdir() searching for cookie %Lu\n",
			(unsigned long long)*desc->dir_cookie);

	page = alloc_page(GFP_HIGHUSER);
	if (!page) {
		status = -ENOMEM;
		goto out;
	}

	desc->page_index = 0;
	desc->last_cookie = *desc->dir_cookie;
	desc->page = page;
	ctx->duped = 0;

	status = nfs_readdir_xdr_to_array(desc, page, inode);
	if (status < 0)
		goto out_release;

	status = nfs_do_filldir(desc);

 out:
	dfprintk(DIRCACHE, "NFS: %s: returns %d\n",
			__func__, status);
	return status;
 out_release:
	cache_page_release(desc);
	goto out;
}

static bool nfs_dir_mapping_need_revalidate(struct inode *dir)
{
	struct nfs_inode *nfsi = NFS_I(dir);

	if (nfs_attribute_cache_expired(dir))
		return true;
	if (nfsi->cache_validity & NFS_INO_INVALID_DATA)
		return true;
	return false;
}

/* The file offset position represents the dirent entry number.  A
   last cookie cache takes care of the common case of reading the
   whole directory.
 */
static int nfs_readdir(struct file *file, struct dir_context *ctx)
{
	struct dentry	*dentry = file->f_path.dentry;
	struct inode	*inode = dentry->d_inode;
	nfs_readdir_descriptor_t my_desc,
			*desc = &my_desc;
	struct nfs_open_dir_context *dir_ctx = file->private_data;
	int res = 0;

	dfprintk(FILE, "NFS: readdir(%pD2) starting at cookie %llu\n",
			file, (long long)ctx->pos);
	nfs_inc_stats(inode, NFSIOS_VFSGETDENTS);

	/*
	 * ctx->pos points to the dirent entry number.
	 * *desc->dir_cookie has the cookie for the next entry. We have
	 * to either find the entry with the appropriate number or
	 * revalidate the cookie.
	 */
	memset(desc, 0, sizeof(*desc));

	desc->file = file;
	desc->ctx = ctx;
	desc->dir_cookie = &dir_ctx->dir_cookie;
	desc->decode = NFS_PROTO(inode)->decode_dirent;
	desc->plus = nfs_use_readdirplus(inode, ctx) ? 1 : 0;

	nfs_block_sillyrename(dentry);
	if (ctx->pos == 0 || nfs_dir_mapping_need_revalidate(inode))
		res = nfs_revalidate_mapping(inode, file->f_mapping);
	if (res < 0)
		goto out;

	do {
		res = readdir_search_pagecache(desc);

		if (res == -EBADCOOKIE) {
			res = 0;
			/* This means either end of directory */
			if (*desc->dir_cookie && desc->eof == 0) {
				/* Or that the server has 'lost' a cookie */
				res = uncached_readdir(desc);
				if (res == 0)
					continue;
			}
			break;
		}
		if (res == -ETOOSMALL && desc->plus) {
			clear_bit(NFS_INO_ADVISE_RDPLUS, &NFS_I(inode)->flags);
			nfs_zap_caches(inode);
			desc->page_index = 0;
			desc->plus = 0;
			desc->eof = 0;
			continue;
		}
		if (res < 0)
			break;

		res = nfs_do_filldir(desc);
		if (res < 0)
			break;
	} while (!desc->eof);
out:
	nfs_unblock_sillyrename(dentry);
	if (res > 0)
		res = 0;
	dfprintk(FILE, "NFS: readdir(%pD2) returns %d\n", file, res);
	return res;
}

static loff_t nfs_llseek_dir(struct file *filp, loff_t offset, int whence)
{
	struct inode *inode = file_inode(filp);
	struct nfs_open_dir_context *dir_ctx = filp->private_data;

	dfprintk(FILE, "NFS: llseek dir(%pD2, %lld, %d)\n",
			filp, offset, whence);

	mutex_lock(&inode->i_mutex);
	switch (whence) {
		case 1:
			offset += filp->f_pos;
		case 0:
			if (offset >= 0)
				break;
		default:
			offset = -EINVAL;
			goto out;
	}
	if (offset != filp->f_pos) {
		filp->f_pos = offset;
		dir_ctx->dir_cookie = 0;
		dir_ctx->duped = 0;
	}
out:
	mutex_unlock(&inode->i_mutex);
	return offset;
}

/*
 * All directory operations under NFS are synchronous, so fsync()
 * is a dummy operation.
 */
static int nfs_fsync_dir(struct file *filp, loff_t start, loff_t end,
			 int datasync)
{
	struct inode *inode = file_inode(filp);

	dfprintk(FILE, "NFS: fsync dir(%pD2) datasync %d\n", filp, datasync);

	mutex_lock(&inode->i_mutex);
	nfs_inc_stats(inode, NFSIOS_VFSFSYNC);
	mutex_unlock(&inode->i_mutex);
	return 0;
}

/**
 * nfs_force_lookup_revalidate - Mark the directory as having changed
 * @dir - pointer to directory inode
 *
 * This forces the revalidation code in nfs_lookup_revalidate() to do a
 * full lookup on all child dentries of 'dir' whenever a change occurs
 * on the server that might have invalidated our dcache.
 *
 * The caller should be holding dir->i_lock
 */
void nfs_force_lookup_revalidate(struct inode *dir)
{
	NFS_I(dir)->cache_change_attribute++;
}
EXPORT_SYMBOL_GPL(nfs_force_lookup_revalidate);

/*
 * A check for whether or not the parent directory has changed.
 * In the case it has, we assume that the dentries are untrustworthy
 * and may need to be looked up again.
 * If rcu_walk prevents us from performing a full check, return 0.
 */
static int nfs_check_verifier(struct inode *dir, struct dentry *dentry,
			      int rcu_walk)
{
	int ret;

	if (IS_ROOT(dentry))
		return 1;
	if (NFS_SERVER(dir)->flags & NFS_MOUNT_LOOKUP_CACHE_NONE)
		return 0;
	if (!nfs_verify_change_attribute(dir, dentry->d_time))
		return 0;
	/* Revalidate nfsi->cache_change_attribute before we declare a match */
	if (rcu_walk)
		ret = nfs_revalidate_inode_rcu(NFS_SERVER(dir), dir);
	else
		ret = nfs_revalidate_inode(NFS_SERVER(dir), dir);
	if (ret < 0)
		return 0;
	if (!nfs_verify_change_attribute(dir, dentry->d_time))
		return 0;
	return 1;
}

/*
 * Use intent information to check whether or not we're going to do
 * an O_EXCL create using this path component.
 */
static int nfs_is_exclusive_create(struct inode *dir, unsigned int flags)
{
	if (NFS_PROTO(dir)->version == 2)
		return 0;
	return flags & LOOKUP_EXCL;
}

/*
 * Inode and filehandle revalidation for lookups.
 *
 * We force revalidation in the cases where the VFS sets LOOKUP_REVAL,
 * or if the intent information indicates that we're about to open this
 * particular file and the "nocto" mount flag is not set.
 *
 */
static
int nfs_lookup_verify_inode(struct inode *inode, unsigned int flags)
{
	struct nfs_server *server = NFS_SERVER(inode);
	int ret;

	if (IS_AUTOMOUNT(inode))
		return 0;
	/* VFS wants an on-the-wire revalidation */
	if (flags & LOOKUP_REVAL)
		goto out_force;
	/* This is an open(2) */
	if ((flags & LOOKUP_OPEN) && !(server->flags & NFS_MOUNT_NOCTO) &&
	    (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)))
		goto out_force;
out:
	return (inode->i_nlink == 0) ? -ENOENT : 0;
out_force:
	if (flags & LOOKUP_RCU)
		return -ECHILD;
	ret = __nfs_revalidate_inode(server, inode);
	if (ret != 0)
		return ret;
	goto out;
}

/*
 * We judge how long we want to trust negative
 * dentries by looking at the parent inode mtime.
 *
 * If parent mtime has changed, we revalidate, else we wait for a
 * period corresponding to the parent's attribute cache timeout value.
 *
 * If LOOKUP_RCU prevents us from performing a full check, return 1
 * suggesting a reval is needed.
 */
static inline
int nfs_neg_need_reval(struct inode *dir, struct dentry *dentry,
		       unsigned int flags)
{
	/* Don't revalidate a negative dentry if we're creating a new file */
	if (flags & LOOKUP_CREATE)
		return 0;
	if (NFS_SERVER(dir)->flags & NFS_MOUNT_LOOKUP_CACHE_NONEG)
		return 1;
	return !nfs_check_verifier(dir, dentry, flags & LOOKUP_RCU);
}

/*
 * This is called every time the dcache has a lookup hit,
 * and we should check whether we can really trust that
 * lookup.
 *
 * NOTE! The hit can be a negative hit too, don't assume
 * we have an inode!
 *
 * If the parent directory is seen to have changed, we throw out the
 * cached dentry and do a new lookup.
 */
static int nfs_lookup_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct inode *dir;
	struct inode *inode;
	struct dentry *parent;
	struct nfs_fh *fhandle = NULL;
	struct nfs_fattr *fattr = NULL;
	struct nfs4_label *label = NULL;
	int error;

	if (flags & LOOKUP_RCU) {
		parent = ACCESS_ONCE(dentry->d_parent);
		dir = ACCESS_ONCE(parent->d_inode);
		if (!dir)
			return -ECHILD;
	} else {
		parent = dget_parent(dentry);
		dir = parent->d_inode;
	}
	nfs_inc_stats(dir, NFSIOS_DENTRYREVALIDATE);
	inode = dentry->d_inode;

	if (!inode) {
		if (nfs_neg_need_reval(dir, dentry, flags)) {
			if (flags & LOOKUP_RCU)
				return -ECHILD;
			goto out_bad;
		}
		goto out_valid_noent;
	}

	if (is_bad_inode(inode)) {
		if (flags & LOOKUP_RCU)
			return -ECHILD;
		dfprintk(LOOKUPCACHE, "%s: %pd2 has dud inode\n",
				__func__, dentry);
		goto out_bad;
	}

	if (NFS_PROTO(dir)->have_delegation(inode, FMODE_READ))
		goto out_set_verifier;

	/* Force a full look up iff the parent directory has changed */
	if (!nfs_is_exclusive_create(dir, flags) &&
	    nfs_check_verifier(dir, dentry, flags & LOOKUP_RCU)) {

		if (nfs_lookup_verify_inode(inode, flags)) {
			if (flags & LOOKUP_RCU)
				return -ECHILD;
			goto out_zap_parent;
		}
		goto out_valid;
	}

	if (flags & LOOKUP_RCU)
		return -ECHILD;

	if (NFS_STALE(inode))
		goto out_bad;

	error = -ENOMEM;
	fhandle = nfs_alloc_fhandle();
	fattr = nfs_alloc_fattr();
	if (fhandle == NULL || fattr == NULL)
		goto out_error;

	label = nfs4_label_alloc(NFS_SERVER(inode), GFP_NOWAIT);
	if (IS_ERR(label))
		goto out_error;

	trace_nfs_lookup_revalidate_enter(dir, dentry, flags);
	error = NFS_PROTO(dir)->lookup(dir, &dentry->d_name, fhandle, fattr, label);
	trace_nfs_lookup_revalidate_exit(dir, dentry, flags, error);
	if (error)
		goto out_bad;
	if (nfs_compare_fh(NFS_FH(inode), fhandle))
		goto out_bad;
	if ((error = nfs_refresh_inode(inode, fattr)) != 0)
		goto out_bad;

	nfs_setsecurity(inode, fattr, label);

	nfs_free_fattr(fattr);
	nfs_free_fhandle(fhandle);
	nfs4_label_free(label);

out_set_verifier:
	nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
 out_valid:
	/* Success: notify readdir to use READDIRPLUS */
	nfs_advise_use_readdirplus(dir);
 out_valid_noent:
	if (flags & LOOKUP_RCU) {
		if (parent != ACCESS_ONCE(dentry->d_parent))
			return -ECHILD;
	} else
		dput(parent);
	dfprintk(LOOKUPCACHE, "NFS: %s(%pd2) is valid\n",
			__func__, dentry);
	return 1;
out_zap_parent:
	nfs_zap_caches(dir);
 out_bad:
	WARN_ON(flags & LOOKUP_RCU);
	nfs_free_fattr(fattr);
	nfs_free_fhandle(fhandle);
	nfs4_label_free(label);
	nfs_mark_for_revalidate(dir);
	if (inode && S_ISDIR(inode->i_mode)) {
		/* Purge readdir caches. */
		nfs_zap_caches(inode);
		/*
		 * We can't d_drop the root of a disconnected tree:
		 * its d_hash is on the s_anon list and d_drop() would hide
		 * it from shrink_dcache_for_unmount(), leading to busy
		 * inodes on unmount and further oopses.
		 */
		if (IS_ROOT(dentry))
			goto out_valid;
	}
	/* If we have submounts, don't unhash ! */
	if (check_submounts_and_drop(dentry) != 0)
		goto out_valid;

	dput(parent);
	dfprintk(LOOKUPCACHE, "NFS: %s(%pd2) is invalid\n",
			__func__, dentry);
	return 0;
out_error:
	WARN_ON(flags & LOOKUP_RCU);
	nfs_free_fattr(fattr);
	nfs_free_fhandle(fhandle);
	nfs4_label_free(label);
	dput(parent);
	dfprintk(LOOKUPCACHE, "NFS: %s(%pd2) lookup returned error %d\n",
			__func__, dentry, error);
	return error;
}

/*
 * A weaker form of d_revalidate for revalidating just the dentry->d_inode
 * when we don't really care about the dentry name. This is called when a
 * pathwalk ends on a dentry that was not found via a normal lookup in the
 * parent dir (e.g.: ".", "..", procfs symlinks or mountpoint traversals).
 *
 * In this situation, we just want to verify that the inode itself is OK
 * since the dentry might have changed on the server.
 */
static int nfs_weak_revalidate(struct dentry *dentry, unsigned int flags)
{
	int error;
	struct inode *inode = dentry->d_inode;

	/*
	 * I believe we can only get a negative dentry here in the case of a
	 * procfs-style symlink. Just assume it's correct for now, but we may
	 * eventually need to do something more here.
	 */
	if (!inode) {
		dfprintk(LOOKUPCACHE, "%s: %pd2 has negative inode\n",
				__func__, dentry);
		return 1;
	}

	if (is_bad_inode(inode)) {
		dfprintk(LOOKUPCACHE, "%s: %pd2 has dud inode\n",
				__func__, dentry);
		return 0;
	}

	error = nfs_revalidate_inode(NFS_SERVER(inode), inode);
	dfprintk(LOOKUPCACHE, "NFS: %s: inode %lu is %s\n",
			__func__, inode->i_ino, error ? "invalid" : "valid");
	return !error;
}

/*
 * This is called from dput() when d_count is going to 0.
 */
static int nfs_dentry_delete(const struct dentry *dentry)
{
	dfprintk(VFS, "NFS: dentry_delete(%pd2, %x)\n",
		dentry, dentry->d_flags);

	/* Unhash any dentry with a stale inode */
	if (dentry->d_inode != NULL && NFS_STALE(dentry->d_inode))
		return 1;

	if (dentry->d_flags & DCACHE_NFSFS_RENAMED) {
		/* Unhash it, so that ->d_iput() would be called */
		return 1;
	}
	if (!(dentry->d_sb->s_flags & MS_ACTIVE)) {
		/* Unhash it, so that ancestors of killed async unlink
		 * files will be cleaned up during umount */
		return 1;
	}
	return 0;

}

/* Ensure that we revalidate inode->i_nlink */
static void nfs_drop_nlink(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	/* drop the inode if we're reasonably sure this is the last link */
	if (inode->i_nlink == 1)
		clear_nlink(inode);
	NFS_I(inode)->cache_validity |= NFS_INO_INVALID_ATTR;
	spin_unlock(&inode->i_lock);
}

/*
 * Called when the dentry loses inode.
 * We use it to clean up silly-renamed files.
 */
static void nfs_dentry_iput(struct dentry *dentry, struct inode *inode)
{
	if (S_ISDIR(inode->i_mode))
		/* drop any readdir cache as it could easily be old */
		NFS_I(inode)->cache_validity |= NFS_INO_INVALID_DATA;

	if (dentry->d_flags & DCACHE_NFSFS_RENAMED) {
		nfs_complete_unlink(dentry, inode);
		nfs_drop_nlink(inode);
	}
	iput(inode);
}

static void nfs_d_release(struct dentry *dentry)
{
	/* free cached devname value, if it survived that far */
	if (unlikely(dentry->d_fsdata)) {
		if (dentry->d_flags & DCACHE_NFSFS_RENAMED)
			WARN_ON(1);
		else
			kfree(dentry->d_fsdata);
	}
}

const struct dentry_operations nfs_dentry_operations = {
	.d_revalidate	= nfs_lookup_revalidate,
	.d_weak_revalidate	= nfs_weak_revalidate,
	.d_delete	= nfs_dentry_delete,
	.d_iput		= nfs_dentry_iput,
	.d_automount	= nfs_d_automount,
	.d_release	= nfs_d_release,
};
EXPORT_SYMBOL_GPL(nfs_dentry_operations);

struct dentry *nfs_lookup(struct inode *dir, struct dentry * dentry, unsigned int flags)
{
	struct dentry *res;
	struct dentry *parent;
	struct inode *inode = NULL;
	struct nfs_fh *fhandle = NULL;
	struct nfs_fattr *fattr = NULL;
	struct nfs4_label *label = NULL;
	int error;

	dfprintk(VFS, "NFS: lookup(%pd2)\n", dentry);
	nfs_inc_stats(dir, NFSIOS_VFSLOOKUP);

	res = ERR_PTR(-ENAMETOOLONG);
	if (dentry->d_name.len > NFS_SERVER(dir)->namelen)
		goto out;

	/*
	 * If we're doing an exclusive create, optimize away the lookup
	 * but don't hash the dentry.
	 */
	if (nfs_is_exclusive_create(dir, flags)) {
		d_instantiate(dentry, NULL);
		res = NULL;
		goto out;
	}

	res = ERR_PTR(-ENOMEM);
	fhandle = nfs_alloc_fhandle();
	fattr = nfs_alloc_fattr();
	if (fhandle == NULL || fattr == NULL)
		goto out;

	label = nfs4_label_alloc(NFS_SERVER(dir), GFP_NOWAIT);
	if (IS_ERR(label))
		goto out;

	parent = dentry->d_parent;
	/* Protect against concurrent sillydeletes */
	trace_nfs_lookup_enter(dir, dentry, flags);
	nfs_block_sillyrename(parent);
	error = NFS_PROTO(dir)->lookup(dir, &dentry->d_name, fhandle, fattr, label);
	if (error == -ENOENT)
		goto no_entry;
	if (error < 0) {
		res = ERR_PTR(error);
		goto out_unblock_sillyrename;
	}
	inode = nfs_fhget(dentry->d_sb, fhandle, fattr, label);
	res = ERR_CAST(inode);
	if (IS_ERR(res))
		goto out_unblock_sillyrename;

	/* Success: notify readdir to use READDIRPLUS */
	nfs_advise_use_readdirplus(dir);

no_entry:
	res = d_materialise_unique(dentry, inode);
	if (res != NULL) {
		if (IS_ERR(res))
			goto out_unblock_sillyrename;
		dentry = res;
	}
	nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
out_unblock_sillyrename:
	nfs_unblock_sillyrename(parent);
	trace_nfs_lookup_exit(dir, dentry, flags, error);
	nfs4_label_free(label);
out:
	nfs_free_fattr(fattr);
	nfs_free_fhandle(fhandle);
	return res;
}
EXPORT_SYMBOL_GPL(nfs_lookup);

#if IS_ENABLED(CONFIG_NFS_V4)
static int nfs4_lookup_revalidate(struct dentry *, unsigned int);

const struct dentry_operations nfs4_dentry_operations = {
	.d_revalidate	= nfs4_lookup_revalidate,
	.d_delete	= nfs_dentry_delete,
	.d_iput		= nfs_dentry_iput,
	.d_automount	= nfs_d_automount,
	.d_release	= nfs_d_release,
};
EXPORT_SYMBOL_GPL(nfs4_dentry_operations);

static fmode_t flags_to_mode(int flags)
{
	fmode_t res = (__force fmode_t)flags & FMODE_EXEC;
	if ((flags & O_ACCMODE) != O_WRONLY)
		res |= FMODE_READ;
	if ((flags & O_ACCMODE) != O_RDONLY)
		res |= FMODE_WRITE;
	return res;
}

static struct nfs_open_context *create_nfs_open_context(struct dentry *dentry, int open_flags)
{
	return alloc_nfs_open_context(dentry, flags_to_mode(open_flags));
}

static int do_open(struct inode *inode, struct file *filp)
{
	nfs_fscache_open_file(inode, filp);
	return 0;
}

static int nfs_finish_open(struct nfs_open_context *ctx,
			   struct dentry *dentry,
			   struct file *file, unsigned open_flags,
			   int *opened)
{
	int err;

	if ((open_flags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
		*opened |= FILE_CREATED;

	err = finish_open(file, dentry, do_open, opened);
	if (err)
		goto out;
	nfs_file_set_open_context(file, ctx);

out:
	return err;
}

int nfs_atomic_open(struct inode *dir, struct dentry *dentry,
		    struct file *file, unsigned open_flags,
		    umode_t mode, int *opened)
{
	struct nfs_open_context *ctx;
	struct dentry *res;
	struct iattr attr = { .ia_valid = ATTR_OPEN };
	struct inode *inode;
	unsigned int lookup_flags = 0;
	int err;

	/* Expect a negative dentry */
	BUG_ON(dentry->d_inode);

	dfprintk(VFS, "NFS: atomic_open(%s/%lu), %pd\n",
			dir->i_sb->s_id, dir->i_ino, dentry);

	err = nfs_check_flags(open_flags);
	if (err)
		return err;

	/* NFS only supports OPEN on regular files */
	if ((open_flags & O_DIRECTORY)) {
		if (!d_unhashed(dentry)) {
			/*
			 * Hashed negative dentry with O_DIRECTORY: dentry was
			 * revalidated and is fine, no need to perform lookup
			 * again
			 */
			return -ENOENT;
		}
		lookup_flags = LOOKUP_OPEN|LOOKUP_DIRECTORY;
		goto no_open;
	}

	if (dentry->d_name.len > NFS_SERVER(dir)->namelen)
		return -ENAMETOOLONG;

	if (open_flags & O_CREAT) {
		attr.ia_valid |= ATTR_MODE;
		attr.ia_mode = mode & ~current_umask();
	}
	if (open_flags & O_TRUNC) {
		attr.ia_valid |= ATTR_SIZE;
		attr.ia_size = 0;
	}

	ctx = create_nfs_open_context(dentry, open_flags);
	err = PTR_ERR(ctx);
	if (IS_ERR(ctx))
		goto out;

	trace_nfs_atomic_open_enter(dir, ctx, open_flags);
	nfs_block_sillyrename(dentry->d_parent);
	inode = NFS_PROTO(dir)->open_context(dir, ctx, open_flags, &attr, opened);
	nfs_unblock_sillyrename(dentry->d_parent);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		trace_nfs_atomic_open_exit(dir, ctx, open_flags, err);
		put_nfs_open_context(ctx);
		switch (err) {
		case -ENOENT:
			d_drop(dentry);
			d_add(dentry, NULL);
			break;
		case -EISDIR:
		case -ENOTDIR:
			goto no_open;
		case -ELOOP:
			if (!(open_flags & O_NOFOLLOW))
				goto no_open;
			break;
			/* case -EINVAL: */
		default:
			break;
		}
		goto out;
	}

	err = nfs_finish_open(ctx, ctx->dentry, file, open_flags, opened);
	trace_nfs_atomic_open_exit(dir, ctx, open_flags, err);
	put_nfs_open_context(ctx);
out:
	return err;

no_open:
	res = nfs_lookup(dir, dentry, lookup_flags);
	err = PTR_ERR(res);
	if (IS_ERR(res))
		goto out;

	return finish_no_open(file, res);
}
EXPORT_SYMBOL_GPL(nfs_atomic_open);

static int nfs4_lookup_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct inode *inode;
	int ret = 0;

	if (!(flags & LOOKUP_OPEN) || (flags & LOOKUP_DIRECTORY))
		goto no_open;
	if (d_mountpoint(dentry))
		goto no_open;
	if (NFS_SB(dentry->d_sb)->caps & NFS_CAP_ATOMIC_OPEN_V1)
		goto no_open;

	inode = dentry->d_inode;

	/* We can't create new files in nfs_open_revalidate(), so we
	 * optimize away revalidation of negative dentries.
	 */
	if (inode == NULL) {
		struct dentry *parent;
		struct inode *dir;

		if (flags & LOOKUP_RCU) {
			parent = ACCESS_ONCE(dentry->d_parent);
			dir = ACCESS_ONCE(parent->d_inode);
			if (!dir)
				return -ECHILD;
		} else {
			parent = dget_parent(dentry);
			dir = parent->d_inode;
		}
		if (!nfs_neg_need_reval(dir, dentry, flags))
			ret = 1;
		else if (flags & LOOKUP_RCU)
			ret = -ECHILD;
		if (!(flags & LOOKUP_RCU))
			dput(parent);
		else if (parent != ACCESS_ONCE(dentry->d_parent))
			return -ECHILD;
		goto out;
	}

	/* NFS only supports OPEN on regular files */
	if (!S_ISREG(inode->i_mode))
		goto no_open;
	/* We cannot do exclusive creation on a positive dentry */
	if (flags & LOOKUP_EXCL)
		goto no_open;

	/* Let f_op->open() actually open (and revalidate) the file */
	ret = 1;

out:
	return ret;

no_open:
	return nfs_lookup_revalidate(dentry, flags);
}

#endif /* CONFIG_NFSV4 */

/*
 * Code common to create, mkdir, and mknod.
 */
int nfs_instantiate(struct dentry *dentry, struct nfs_fh *fhandle,
				struct nfs_fattr *fattr,
				struct nfs4_label *label)
{
	struct dentry *parent = dget_parent(dentry);
	struct inode *dir = parent->d_inode;
	struct inode *inode;
	int error = -EACCES;

	d_drop(dentry);

	/* We may have been initialized further down */
	if (dentry->d_inode)
		goto out;
	if (fhandle->size == 0) {
		error = NFS_PROTO(dir)->lookup(dir, &dentry->d_name, fhandle, fattr, NULL);
		if (error)
			goto out_error;
	}
	nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
	if (!(fattr->valid & NFS_ATTR_FATTR)) {
		struct nfs_server *server = NFS_SB(dentry->d_sb);
		error = server->nfs_client->rpc_ops->getattr(server, fhandle, fattr, NULL);
		if (error < 0)
			goto out_error;
	}
	inode = nfs_fhget(dentry->d_sb, fhandle, fattr, label);
	error = PTR_ERR(inode);
	if (IS_ERR(inode))
		goto out_error;
	d_add(dentry, inode);
out:
	dput(parent);
	return 0;
out_error:
	nfs_mark_for_revalidate(dir);
	dput(parent);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_instantiate);

/*
 * Following a failed create operation, we drop the dentry rather
 * than retain a negative dentry. This avoids a problem in the event
 * that the operation succeeded on the server, but an error in the
 * reply path made it appear to have failed.
 */
int nfs_create(struct inode *dir, struct dentry *dentry,
		umode_t mode, bool excl)
{
	struct iattr attr;
	int open_flags = excl ? O_CREAT | O_EXCL : O_CREAT;
	int error;

	dfprintk(VFS, "NFS: create(%s/%lu), %pd\n",
			dir->i_sb->s_id, dir->i_ino, dentry);

	attr.ia_mode = mode;
	attr.ia_valid = ATTR_MODE;

	trace_nfs_create_enter(dir, dentry, open_flags);
	error = NFS_PROTO(dir)->create(dir, dentry, &attr, open_flags);
	trace_nfs_create_exit(dir, dentry, open_flags, error);
	if (error != 0)
		goto out_err;
	return 0;
out_err:
	d_drop(dentry);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_create);

/*
 * See comments for nfs_proc_create regarding failed operations.
 */
int
nfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t rdev)
{
	struct iattr attr;
	int status;

	dfprintk(VFS, "NFS: mknod(%s/%lu), %pd\n",
			dir->i_sb->s_id, dir->i_ino, dentry);

	if (!new_valid_dev(rdev))
		return -EINVAL;

	attr.ia_mode = mode;
	attr.ia_valid = ATTR_MODE;

	trace_nfs_mknod_enter(dir, dentry);
	status = NFS_PROTO(dir)->mknod(dir, dentry, &attr, rdev);
	trace_nfs_mknod_exit(dir, dentry, status);
	if (status != 0)
		goto out_err;
	return 0;
out_err:
	d_drop(dentry);
	return status;
}
EXPORT_SYMBOL_GPL(nfs_mknod);

/*
 * See comments for nfs_proc_create regarding failed operations.
 */
int nfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct iattr attr;
	int error;

	dfprintk(VFS, "NFS: mkdir(%s/%lu), %pd\n",
			dir->i_sb->s_id, dir->i_ino, dentry);

	attr.ia_valid = ATTR_MODE;
	attr.ia_mode = mode | S_IFDIR;

	trace_nfs_mkdir_enter(dir, dentry);
	error = NFS_PROTO(dir)->mkdir(dir, dentry, &attr);
	trace_nfs_mkdir_exit(dir, dentry, error);
	if (error != 0)
		goto out_err;
	return 0;
out_err:
	d_drop(dentry);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_mkdir);

static void nfs_dentry_handle_enoent(struct dentry *dentry)
{
	if (dentry->d_inode != NULL && !d_unhashed(dentry))
		d_delete(dentry);
}

int nfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	int error;

	dfprintk(VFS, "NFS: rmdir(%s/%lu), %pd\n",
			dir->i_sb->s_id, dir->i_ino, dentry);

	trace_nfs_rmdir_enter(dir, dentry);
	if (dentry->d_inode) {
		nfs_wait_on_sillyrename(dentry);
		error = NFS_PROTO(dir)->rmdir(dir, &dentry->d_name);
		/* Ensure the VFS deletes this inode */
		switch (error) {
		case 0:
			clear_nlink(dentry->d_inode);
			break;
		case -ENOENT:
			nfs_dentry_handle_enoent(dentry);
		}
	} else
		error = NFS_PROTO(dir)->rmdir(dir, &dentry->d_name);
	trace_nfs_rmdir_exit(dir, dentry, error);

	return error;
}
EXPORT_SYMBOL_GPL(nfs_rmdir);

/*
 * Remove a file after making sure there are no pending writes,
 * and after checking that the file has only one user.
 *
 * We invalidate the attribute cache and free the inode prior to the operation
 * to avoid possible races if the server reuses the inode.
 */
static int nfs_safe_remove(struct dentry *dentry)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct inode *inode = dentry->d_inode;
	int error = -EBUSY;

	dfprintk(VFS, "NFS: safe_remove(%pd2)\n", dentry);

	/* If the dentry was sillyrenamed, we simply call d_delete() */
	if (dentry->d_flags & DCACHE_NFSFS_RENAMED) {
		error = 0;
		goto out;
	}

	trace_nfs_remove_enter(dir, dentry);
	if (inode != NULL) {
		NFS_PROTO(inode)->return_delegation(inode);
		error = NFS_PROTO(dir)->remove(dir, &dentry->d_name);
		if (error == 0)
			nfs_drop_nlink(inode);
	} else
		error = NFS_PROTO(dir)->remove(dir, &dentry->d_name);
	if (error == -ENOENT)
		nfs_dentry_handle_enoent(dentry);
	trace_nfs_remove_exit(dir, dentry, error);
out:
	return error;
}

/*  We do silly rename. In case sillyrename() returns -EBUSY, the inode
 *  belongs to an active ".nfs..." file and we return -EBUSY.
 *
 *  If sillyrename() returns 0, we do nothing, otherwise we unlink.
 */
int nfs_unlink(struct inode *dir, struct dentry *dentry)
{
	int error;
	int need_rehash = 0;

	dfprintk(VFS, "NFS: unlink(%s/%lu, %pd)\n", dir->i_sb->s_id,
		dir->i_ino, dentry);

	trace_nfs_unlink_enter(dir, dentry);
	spin_lock(&dentry->d_lock);
	if (d_count(dentry) > 1) {
		spin_unlock(&dentry->d_lock);
		/* Start asynchronous writeout of the inode */
		write_inode_now(dentry->d_inode, 0);
		error = nfs_sillyrename(dir, dentry);
		goto out;
	}
	if (!d_unhashed(dentry)) {
		__d_drop(dentry);
		need_rehash = 1;
	}
	spin_unlock(&dentry->d_lock);
	error = nfs_safe_remove(dentry);
	if (!error || error == -ENOENT) {
		nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
	} else if (need_rehash)
		d_rehash(dentry);
out:
	trace_nfs_unlink_exit(dir, dentry, error);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_unlink);

/*
 * To create a symbolic link, most file systems instantiate a new inode,
 * add a page to it containing the path, then write it out to the disk
 * using prepare_write/commit_write.
 *
 * Unfortunately the NFS client can't create the in-core inode first
 * because it needs a file handle to create an in-core inode (see
 * fs/nfs/inode.c:nfs_fhget).  We only have a file handle *after* the
 * symlink request has completed on the server.
 *
 * So instead we allocate a raw page, copy the symname into it, then do
 * the SYMLINK request with the page as the buffer.  If it succeeds, we
 * now have a new file handle and can instantiate an in-core NFS inode
 * and move the raw page into its mapping.
 */
int nfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	struct page *page;
	char *kaddr;
	struct iattr attr;
	unsigned int pathlen = strlen(symname);
	int error;

	dfprintk(VFS, "NFS: symlink(%s/%lu, %pd, %s)\n", dir->i_sb->s_id,
		dir->i_ino, dentry, symname);

	if (pathlen > PAGE_SIZE)
		return -ENAMETOOLONG;

	attr.ia_mode = S_IFLNK | S_IRWXUGO;
	attr.ia_valid = ATTR_MODE;

	page = alloc_page(GFP_HIGHUSER);
	if (!page)
		return -ENOMEM;

	kaddr = kmap_atomic(page);
	memcpy(kaddr, symname, pathlen);
	if (pathlen < PAGE_SIZE)
		memset(kaddr + pathlen, 0, PAGE_SIZE - pathlen);
	kunmap_atomic(kaddr);

	trace_nfs_symlink_enter(dir, dentry);
	error = NFS_PROTO(dir)->symlink(dir, dentry, page, pathlen, &attr);
	trace_nfs_symlink_exit(dir, dentry, error);
	if (error != 0) {
		dfprintk(VFS, "NFS: symlink(%s/%lu, %pd, %s) error %d\n",
			dir->i_sb->s_id, dir->i_ino,
			dentry, symname, error);
		d_drop(dentry);
		__free_page(page);
		return error;
	}

	/*
	 * No big deal if we can't add this page to the page cache here.
	 * READLINK will get the missing page from the server if needed.
	 */
	if (!add_to_page_cache_lru(page, dentry->d_inode->i_mapping, 0,
							GFP_KERNEL)) {
		SetPageUptodate(page);
		unlock_page(page);
		/*
		 * add_to_page_cache_lru() grabs an extra page refcount.
		 * Drop it here to avoid leaking this page later.
		 */
		page_cache_release(page);
	} else
		__free_page(page);

	return 0;
}
EXPORT_SYMBOL_GPL(nfs_symlink);

int
nfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = old_dentry->d_inode;
	int error;

	dfprintk(VFS, "NFS: link(%pd2 -> %pd2)\n",
		old_dentry, dentry);

	trace_nfs_link_enter(inode, dir, dentry);
	NFS_PROTO(inode)->return_delegation(inode);

	d_drop(dentry);
	error = NFS_PROTO(dir)->link(inode, dir, &dentry->d_name);
	if (error == 0) {
		ihold(inode);
		d_add(dentry, inode);
	}
	trace_nfs_link_exit(inode, dir, dentry, error);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_link);

/*
 * RENAME
 * FIXME: Some nfsds, like the Linux user space nfsd, may generate a
 * different file handle for the same inode after a rename (e.g. when
 * moving to a different directory). A fail-safe method to do so would
 * be to look up old_dir/old_name, create a link to new_dir/new_name and
 * rename the old file using the sillyrename stuff. This way, the original
 * file in old_dir will go away when the last process iput()s the inode.
 *
 * FIXED.
 *
 * It actually works quite well. One needs to have the possibility for
 * at least one ".nfs..." file in each directory the file ever gets
 * moved or linked to which happens automagically with the new
 * implementation that only depends on the dcache stuff instead of
 * using the inode layer
 *
 * Unfortunately, things are a little more complicated than indicated
 * above. For a cross-directory move, we want to make sure we can get
 * rid of the old inode after the operation.  This means there must be
 * no pending writes (if it's a file), and the use count must be 1.
 * If these conditions are met, we can drop the dentries before doing
 * the rename.
 */
int nfs_rename(struct inode *old_dir, struct dentry *old_dentry,
		      struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct dentry *dentry = NULL, *rehash = NULL;
	struct rpc_task *task;
	int error = -EBUSY;

	dfprintk(VFS, "NFS: rename(%pd2 -> %pd2, ct=%d)\n",
		 old_dentry, new_dentry,
		 d_count(new_dentry));

	trace_nfs_rename_enter(old_dir, old_dentry, new_dir, new_dentry);
	/*
	 * For non-directories, check whether the target is busy and if so,
	 * make a copy of the dentry and then do a silly-rename. If the
	 * silly-rename succeeds, the copied dentry is hashed and becomes
	 * the new target.
	 */
	if (new_inode && !S_ISDIR(new_inode->i_mode)) {
		/*
		 * To prevent any new references to the target during the
		 * rename, we unhash the dentry in advance.
		 */
		if (!d_unhashed(new_dentry)) {
			d_drop(new_dentry);
			rehash = new_dentry;
		}

		if (d_count(new_dentry) > 2) {
			int err;

			/* copy the target dentry's name */
			dentry = d_alloc(new_dentry->d_parent,
					 &new_dentry->d_name);
			if (!dentry)
				goto out;

			/* silly-rename the existing target ... */
			err = nfs_sillyrename(new_dir, new_dentry);
			if (err)
				goto out;

			new_dentry = dentry;
			rehash = NULL;
			new_inode = NULL;
		}
	}

	NFS_PROTO(old_inode)->return_delegation(old_inode);
	if (new_inode != NULL)
		NFS_PROTO(new_inode)->return_delegation(new_inode);

	task = nfs_async_rename(old_dir, new_dir, old_dentry, new_dentry, NULL);
	if (IS_ERR(task)) {
		error = PTR_ERR(task);
		goto out;
	}

	error = rpc_wait_for_completion_task(task);
	if (error == 0)
		error = task->tk_status;
	rpc_put_task(task);
	nfs_mark_for_revalidate(old_inode);
out:
	if (rehash)
		d_rehash(rehash);
	trace_nfs_rename_exit(old_dir, old_dentry,
			new_dir, new_dentry, error);
	if (!error) {
		if (new_inode != NULL)
			nfs_drop_nlink(new_inode);
		d_move(old_dentry, new_dentry);
		nfs_set_verifier(new_dentry,
					nfs_save_change_attribute(new_dir));
	} else if (error == -ENOENT)
		nfs_dentry_handle_enoent(old_dentry);

	/* new dentry created? */
	if (dentry)
		dput(dentry);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_rename);

static DEFINE_SPINLOCK(nfs_access_lru_lock);
static LIST_HEAD_dir_c(nfs_access_lru_list);
static atomic_long_t nfs_access_nr_entries;

static unsigned long nfs_access_max_cachesize = ULONG_MAX;
module_param(nfs_access_max_cachesize, ulong, 0644);
MODULE_PARM_DESC(nfs_access_max_cachesize, "NFS access maximum total cache length");

static void nfs_access_free_entry(struct nfs_access_entry *entry)
{
	put_rpccred(entry->cred);
	kfree_rcu(entry, rcu_head);
	smp_mb__before_atomic();
	atomic_long_dec(&nfs_access_nr_entries);
	smp_mb__after_atomic();
}

static void nfs_access_free_list(struct list_head *head)
{
	struct nfs_access_entry *cache;

	while (!list_empty(head)) {
		cache = list_entry(head->next, struct nfs_access_entry, lru);
		list_del(&cache->lru);
		nfs_access_free_entry(cache);
	}
}

static unsigned long
nfs_do_access_cache_scan(unsigned int nr_to_scan)
{
	LIST_HEAD_dir_c(head);
	struct nfs_inode *nfsi, *next;
	struct nfs_access_entry *cache;
	long freed = 0;

	spin_lock(&nfs_access_lru_lock);
	list_for_each_entry_safe(nfsi, next, &nfs_access_lru_list, access_cache_inode_lru) {
		struct inode *inode;

		if (nr_to_scan-- == 0)
			break;
		inode = &nfsi->vfs_inode;
		spin_lock(&inode->i_lock);
		if (list_empty(&nfsi->access_cache_entry_lru))
			goto remove_lru_entry;
		cache = list_entry(nfsi->access_cache_entry_lru.next,
				struct nfs_access_entry, lru);
		list_move(&cache->lru, &head);
		rb_erase(&cache->rb_node, &nfsi->access_cache);
		freed++;
		if (!list_empty(&nfsi->access_cache_entry_lru))
			list_move_tail(&nfsi->access_cache_inode_lru,
					&nfs_access_lru_list);
		else {
remove_lru_entry:
			list_del_init(&nfsi->access_cache_inode_lru);
			smp_mb__before_atomic();
			clear_bit(NFS_INO_ACL_LRU_SET, &nfsi->flags);
			smp_mb__after_atomic();
		}
		spin_unlock(&inode->i_lock);
	}
	spin_unlock(&nfs_access_lru_lock);
	nfs_access_free_list(&head);
	return freed;
}

unsigned long
nfs_access_cache_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	int nr_to_scan = sc->nr_to_scan;
	gfp_t gfp_mask = sc->gfp_mask;

	if ((gfp_mask & GFP_KERNEL) != GFP_KERNEL)
		return SHRINK_STOP;
	return nfs_do_access_cache_scan(nr_to_scan);
}


unsigned long
nfs_access_cache_count(struct shrinker *shrink, struct shrink_control *sc)
{
	return vfs_pressure_ratio(atomic_long_read(&nfs_access_nr_entries));
}

static void
nfs_access_cache_enforce_limit(void)
{
	long nr_entries = atomic_long_read(&nfs_access_nr_entries);
	unsigned long diff;
	unsigned int nr_to_scan;

	if (nr_entries < 0 || nr_entries <= nfs_access_max_cachesize)
		return;
	nr_to_scan = 100;
	diff = nr_entries - nfs_access_max_cachesize;
	if (diff < nr_to_scan)
		nr_to_scan = diff;
	nfs_do_access_cache_scan(nr_to_scan);
}

static void __nfs_access_zap_cache(struct nfs_inode *nfsi, struct list_head *head)
{
	struct rb_root *root_node = &nfsi->access_cache;
	struct rb_node *n;
	struct nfs_access_entry *entry;

	/* Unhook entries from the cache */
	while ((n = rb_first(root_node)) != NULL) {
		entry = rb_entry(n, struct nfs_access_entry, rb_node);
		rb_erase(n, root_node);
		list_move(&entry->lru, head);
	}
	nfsi->cache_validity &= ~NFS_INO_INVALID_ACCESS;
}

void nfs_access_zap_cache(struct inode *inode)
{
	LIST_HEAD_dir_c(head);

	if (test_bit(NFS_INO_ACL_LRU_SET, &NFS_I(inode)->flags) == 0)
		return;
	/* Remove from global LRU init */
	spin_lock(&nfs_access_lru_lock);
	if (test_and_clear_bit(NFS_INO_ACL_LRU_SET, &NFS_I(inode)->flags))
		list_del_init(&NFS_I(inode)->access_cache_inode_lru);

	spin_lock(&inode->i_lock);
	__nfs_access_zap_cache(NFS_I(inode), &head);
	spin_unlock(&inode->i_lock);
	spin_unlock(&nfs_access_lru_lock);
	nfs_access_free_list(&head);
}
EXPORT_SYMBOL_GPL(nfs_access_zap_cache);

static struct nfs_access_entry *nfs_access_search_rbtree(struct inode *inode, struct rpc_cred *cred)
{
	struct rb_node *n = NFS_I(inode)->access_cache.rb_node;
	struct nfs_access_entry *entry;

	while (n != NULL) {
		entry = rb_entry(n, struct nfs_access_entry, rb_node);

		if (cred < entry->cred)
			n = n->rb_left;
		else if (cred > entry->cred)
			n = n->rb_right;
		else
			return entry;
	}
	return NULL;
}

static int nfs_access_get_cached(struct inode *inode, struct rpc_cred *cred, struct nfs_access_entry *res)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	struct nfs_access_entry *cache;
	int err = -ENOENT;

	spin_lock(&inode->i_lock);
	if (nfsi->cache_validity & NFS_INO_INVALID_ACCESS)
		goto out_zap;
	cache = nfs_access_search_rbtree(inode, cred);
	if (cache == NULL)
		goto out;
	if (!nfs_have_delegated_attributes(inode) &&
	    !time_in_range_open(jiffies, cache->jiffies, cache->jiffies + nfsi->attrtimeo))
		goto out_stale;
	res->jiffies = cache->jiffies;
	res->cred = cache->cred;
	res->mask = cache->mask;
	list_move_tail(&cache->lru, &nfsi->access_cache_entry_lru);
	err = 0;
out:
	spin_unlock(&inode->i_lock);
	return err;
out_stale:
	rb_erase(&cache->rb_node, &nfsi->access_cache);
	list_del(&cache->lru);
	spin_unlock(&inode->i_lock);
	nfs_access_free_entry(cache);
	return -ENOENT;
out_zap:
	spin_unlock(&inode->i_lock);
	nfs_access_zap_cache(inode);
	return -ENOENT;
}

static int nfs_access_get_cached_rcu(struct inode *inode, struct rpc_cred *cred, struct nfs_access_entry *res)
{
	/* Only check the most recently returned cache entry,
	 * but do it without locking.
	 */
	struct nfs_inode *nfsi = NFS_I(inode);
	struct nfs_access_entry *cache;
	int err = -ECHILD;
	struct list_head *lh;

	rcu_read_lock();
	if (nfsi->cache_validity & NFS_INO_INVALID_ACCESS)
		goto out;
	lh = rcu_dereference(nfsi->access_cache_entry_lru.prev);
	cache = list_entry(lh, struct nfs_access_entry, lru);
	if (lh == &nfsi->access_cache_entry_lru ||
	    cred != cache->cred)
		cache = NULL;
	if (cache == NULL)
		goto out;
	if (!nfs_have_delegated_attributes(inode) &&
	    !time_in_range_open(jiffies, cache->jiffies, cache->jiffies + nfsi->attrtimeo))
		goto out;
	res->jiffies = cache->jiffies;
	res->cred = cache->cred;
	res->mask = cache->mask;
	err = 0;
out:
	rcu_read_unlock();
	return err;
}

static void nfs_access_add_rbtree(struct inode *inode, struct nfs_access_entry *set)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	struct rb_root *root_node = &nfsi->access_cache;
	struct rb_node **p = &root_node->rb_node;
	struct rb_node *parent = NULL;
	struct nfs_access_entry *entry;

	spin_lock(&inode->i_lock);
	while (*p != NULL) {
		parent = *p;
		entry = rb_entry(parent, struct nfs_access_entry, rb_node);

		if (set->cred < entry->cred)
			p = &parent->rb_left;
		else if (set->cred > entry->cred)
			p = &parent->rb_right;
		else
			goto found;
	}
	rb_link_node(&set->rb_node, parent, p);
	rb_insert_color(&set->rb_node, root_node);
	list_add_tail(&set->lru, &nfsi->access_cache_entry_lru);
	spin_unlock(&inode->i_lock);
	return;
found:
	rb_replace_node(parent, &set->rb_node, root_node);
	list_add_tail(&set->lru, &nfsi->access_cache_entry_lru);
	list_del(&entry->lru);
	spin_unlock(&inode->i_lock);
	nfs_access_free_entry(entry);
}

void nfs_access_add_cache(struct inode *inode, struct nfs_access_entry *set)
{
	struct nfs_access_entry *cache = kmalloc(sizeof(*cache), GFP_KERNEL);
	if (cache == NULL)
		return;
	RB_CLEAR_NODE(&cache->rb_node);
	cache->jiffies = set->jiffies;
	cache->cred = get_rpccred(set->cred);
	cache->mask = set->mask;

	/* The above field assignments must be visible
	 * before this item appears on the lru.  We cannot easily
	 * use rcu_assign_pointer, so just force the memory barrier.
	 */
	smp_wmb();
	nfs_access_add_rbtree(inode, cache);

	/* Update accounting */
	smp_mb__before_atomic();
	atomic_long_inc(&nfs_access_nr_entries);
	smp_mb__after_atomic();

	/* Add inode to global LRU list */
	if (!test_bit(NFS_INO_ACL_LRU_SET, &NFS_I(inode)->flags)) {
		spin_lock(&nfs_access_lru_lock);
		if (!test_and_set_bit(NFS_INO_ACL_LRU_SET, &NFS_I(inode)->flags))
			list_add_tail(&NFS_I(inode)->access_cache_inode_lru,
					&nfs_access_lru_list);
		spin_unlock(&nfs_access_lru_lock);
	}
	nfs_access_cache_enforce_limit();
}
EXPORT_SYMBOL_GPL(nfs_access_add_cache);

void nfs_access_set_mask(struct nfs_access_entry *entry, u32 access_result)
{
	entry->mask = 0;
	if (access_result & NFS4_ACCESS_READ)
		entry->mask |= MAY_READ;
	if (access_result &
	    (NFS4_ACCESS_MODIFY | NFS4_ACCESS_EXTEND | NFS4_ACCESS_DELETE))
		entry->mask |= MAY_WRITE;
	if (access_result & (NFS4_ACCESS_LOOKUP|NFS4_ACCESS_EXECUTE))
		entry->mask |= MAY_EXEC;
}
EXPORT_SYMBOL_GPL(nfs_access_set_mask);

static int nfs_do_access(struct inode *inode, struct rpc_cred *cred, int mask)
{
	struct nfs_access_entry cache;
	int status;

	trace_nfs_access_enter(inode);

	status = nfs_access_get_cached_rcu(inode, cred, &cache);
	if (status != 0)
		status = nfs_access_get_cached(inode, cred, &cache);
	if (status == 0)
		goto out_cached;

	status = -ECHILD;
	if (mask & MAY_NOT_BLOCK)
		goto out;

	/* Be clever: ask server to check for all possible rights */
	cache.mask = MAY_EXEC | MAY_WRITE | MAY_READ;
	cache.cred = cred;
	cache.jiffies = jiffies;
	status = NFS_PROTO(inode)->access(inode, &cache);
	if (status != 0) {
		if (status == -ESTALE) {
			nfs_zap_caches(inode);
			if (!S_ISDIR(inode->i_mode))
				set_bit(NFS_INO_STALE, &NFS_I(inode)->flags);
		}
		goto out;
	}
	nfs_access_add_cache(inode, &cache);
out_cached:
	if ((mask & ~cache.mask & (MAY_READ | MAY_WRITE | MAY_EXEC)) != 0)
		status = -EACCES;
out:
	trace_nfs_access_exit(inode, status);
	return status;
}

static int nfs_open_permission_mask(int openflags)
{
	int mask = 0;

	if (openflags & __FMODE_EXEC) {
		/* ONLY check exec rights */
		mask = MAY_EXEC;
	} else {
		if ((openflags & O_ACCMODE) != O_WRONLY)
			mask |= MAY_READ;
		if ((openflags & O_ACCMODE) != O_RDONLY)
			mask |= MAY_WRITE;
	}

	return mask;
}

int nfs_may_open(struct inode *inode, struct rpc_cred *cred, int openflags)
{
	return nfs_do_access(inode, cred, nfs_open_permission_mask(openflags));
}
EXPORT_SYMBOL_GPL(nfs_may_open);

int nfs_permission(struct inode *inode, int mask)
{
	struct rpc_cred *cred;
	int res = 0;

	nfs_inc_stats(inode, NFSIOS_VFSACCESS);

	if ((mask & (MAY_READ | MAY_WRITE | MAY_EXEC)) == 0)
		goto out;
	/* Is this sys_access() ? */
	if (mask & (MAY_ACCESS | MAY_CHDIR))
		goto force_lookup;

	switch (inode->i_mode & S_IFMT) {
		case S_IFLNK:
			goto out;
		case S_IFREG:
			break;
		case S_IFDIR:
			/*
			 * Optimize away all write operations, since the server
			 * will check permissions when we perform the op.
			 */
			if ((mask & MAY_WRITE) && !(mask & MAY_READ))
				goto out;
	}

force_lookup:
	if (!NFS_PROTO(inode)->access)
		goto out_notsup;

	/* Always try fast lookups first */
	rcu_read_lock();
	cred = rpc_lookup_cred_nonblock();
	if (!IS_ERR(cred))
		res = nfs_do_access(inode, cred, mask|MAY_NOT_BLOCK);
	else
		res = PTR_ERR(cred);
	rcu_read_unlock();
	if (res == -ECHILD && !(mask & MAY_NOT_BLOCK)) {
		/* Fast lookup failed, try the slow way */
		cred = rpc_lookup_cred();
		if (!IS_ERR(cred)) {
			res = nfs_do_access(inode, cred, mask);
			put_rpccred(cred);
		} else
			res = PTR_ERR(cred);
	}
out:
	if (!res && (mask & MAY_EXEC) && !execute_ok(inode))
		res = -EACCES;

	dfprintk(VFS, "NFS: permission(%s/%lu), mask=0x%x, res=%d\n",
		inode->i_sb->s_id, inode->i_ino, mask, res);
	return res;
out_notsup:
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;

	res = nfs_revalidate_inode(NFS_SERVER(inode), inode);
	if (res == 0)
		res = generic_permission(inode, mask);
	goto out;
}
EXPORT_SYMBOL_GPL(nfs_permission);

/*
 * Local variables:
 *  version-control: t
 *  kept-new-versions: 5
 * End:
 */
/************************************************************/
/* ../linux-3.17/fs/nfs/dir.c */
/************************************************************/
/*
 *  linux/fs/nfs/file.c
 *
 *  Copyright (C) 1992  Rick Sladkey
 *
 *  Changes Copyright (C) 1994 by Florian La Roche
 *   - Do not copy data too often around in the kernel.
 *   - In nfs_file_read the return value of kmalloc wasn't checked.
 *   - Put in a better version of read look-ahead buffering. Original idea
 *     and implementation by Wai S Kok elekokws@ee.nus.sg.
 *
 *  Expire cache on write to a file by Wai S Kok (Oct 1994).
 *
 *  Total rewrite of read side for new NFS buffer cache.. Linus.
 *
 *  nfs regular file handling functions
 */

// #include <linux/module.h>
// #include <linux/time.h>
// #include <linux/kernel.h>
// #include <linux/errno.h>
// #include <linux/fcntl.h>
// #include <linux/stat.h>
// #include <linux/nfs_fs.h>
// #include <linux/nfs_mount.h>
// #include <linux/mm.h>
// #include <linux/pagemap.h>
#include <linux/aio.h>
#include <linux/gfp.h>
// #include <linux/swap.h>

#include <asm/uaccess.h>

// #include "delegation.h"
// #include "internal.h"
// #include "iostat.h"
// #include "fscache.h"

// #include "nfstrace.h"

#define NFSDBG_FACILITY		NFSDBG_FILE

static const struct vm_operations_struct nfs_file_vm_ops;

/* Hack for future NFS swap support */
#ifndef IS_SWAPFILE
# define IS_SWAPFILE(inode)	(0)
#endif

int nfs_check_flags(int flags)
{
	if ((flags & (O_APPEND | O_DIRECT)) == (O_APPEND | O_DIRECT))
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(nfs_check_flags);

/*
 * Open file
 */
static int
nfs_file_open(struct inode *inode, struct file *filp)
{
	int res;

	dprintk("NFS: open file(%pD2)\n", filp);

	nfs_inc_stats(inode, NFSIOS_VFSOPEN);
	res = nfs_check_flags(filp->f_flags);
	if (res)
		return res;

	res = nfs_open(inode, filp);
	return res;
}

int
nfs_file_release(struct inode *inode, struct file *filp)
{
	dprintk("NFS: release(%pD2)\n", filp);

	nfs_inc_stats(inode, NFSIOS_VFSRELEASE);
	return nfs_release(inode, filp);
}
EXPORT_SYMBOL_GPL(nfs_file_release);

/**
 * nfs_revalidate_size - Revalidate the file size
 * @inode - pointer to inode struct
 * @file - pointer to struct file
 *
 * Revalidates the file length. This is basically a wrapper around
 * nfs_revalidate_inode() that takes into account the fact that we may
 * have cached writes (in which case we don't care about the server's
 * idea of what the file length is), or O_DIRECT (in which case we
 * shouldn't trust the cache).
 */
static int nfs_revalidate_file_size(struct inode *inode, struct file *filp)
{
	struct nfs_server *server = NFS_SERVER(inode);
	struct nfs_inode *nfsi = NFS_I(inode);

	if (nfs_have_delegated_attributes(inode))
		goto out_noreval;

	if (filp->f_flags & O_DIRECT)
		goto force_reval;
	if (nfsi->cache_validity & NFS_INO_REVAL_PAGECACHE)
		goto force_reval;
	if (nfs_attribute_timeout(inode))
		goto force_reval;
out_noreval:
	return 0;
force_reval:
	return __nfs_revalidate_inode(server, inode);
}

loff_t nfs_file_llseek(struct file *filp, loff_t offset, int whence)
{
	dprintk("NFS: llseek file(%pD2, %lld, %d)\n",
			filp, offset, whence);

	/*
	 * whence == SEEK_END || SEEK_DATA || SEEK_HOLE => we must revalidate
	 * the cached file length
	 */
	if (whence != SEEK_SET && whence != SEEK_CUR) {
		struct inode *inode = filp->f_mapping->host;

		int retval = nfs_revalidate_file_size(inode, filp);
		if (retval < 0)
			return (loff_t)retval;
	}

	return generic_file_llseek(filp, offset, whence);
}
EXPORT_SYMBOL_GPL(nfs_file_llseek);

/*
 * Flush all dirty pages, and check for write errors.
 */
int
nfs_file_flush(struct file *file, fl_owner_t id)
{
	struct inode	*inode = file_inode(file);

	dprintk("NFS: flush(%pD2)\n", file);

	nfs_inc_stats(inode, NFSIOS_VFSFLUSH);
	if ((file->f_mode & FMODE_WRITE) == 0)
		return 0;

	/*
	 * If we're holding a write delegation, then just start the i/o
	 * but don't wait for completion (or send a commit).
	 */
	if (NFS_PROTO(inode)->have_delegation(inode, FMODE_WRITE))
		return filemap_fdatawrite(file->f_mapping);

	/* Flush writes to the server and return any errors */
	return vfs_fsync(file, 0);
}
EXPORT_SYMBOL_GPL(nfs_file_flush);

ssize_t
nfs_file_read(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t result;

	if (iocb->ki_filp->f_flags & O_DIRECT)
		return nfs_file_direct_read(iocb, to, iocb->ki_pos, true);

	dprintk("NFS: read(%pD2, %zu@%lu)\n",
		iocb->ki_filp,
		iov_iter_count(to), (unsigned long) iocb->ki_pos);

	result = nfs_revalidate_mapping(inode, iocb->ki_filp->f_mapping);
	if (!result) {
		result = generic_file_read_iter(iocb, to);
		if (result > 0)
			nfs_add_stats(inode, NFSIOS_NORMALREADBYTES, result);
	}
	return result;
}
EXPORT_SYMBOL_GPL(nfs_file_read);

ssize_t
nfs_file_splice_read(struct file *filp, loff_t *ppos,
		     struct pipe_inode_info *pipe, size_t count,
		     unsigned int flags)
{
	struct inode *inode = file_inode(filp);
	ssize_t res;

	dprintk("NFS: splice_read(%pD2, %lu@%Lu)\n",
		filp, (unsigned long) count, (unsigned long long) *ppos);

	res = nfs_revalidate_mapping(inode, filp->f_mapping);
	if (!res) {
		res = generic_file_splice_read(filp, ppos, pipe, count, flags);
		if (res > 0)
			nfs_add_stats(inode, NFSIOS_NORMALREADBYTES, res);
	}
	return res;
}
EXPORT_SYMBOL_GPL(nfs_file_splice_read);

int
nfs_file_mmap(struct file * file, struct vm_area_struct * vma)
{
	struct inode *inode = file_inode(file);
	int	status;

	dprintk("NFS: mmap(%pD2)\n", file);

	/* Note: generic_file_mmap() returns ENOSYS on nommu systems
	 *       so we call that before revalidating the mapping
	 */
	status = generic_file_mmap(file, vma);
	if (!status) {
		vma->vm_ops = &nfs_file_vm_ops;
		status = nfs_revalidate_mapping(inode, file->f_mapping);
	}
	return status;
}
EXPORT_SYMBOL_GPL(nfs_file_mmap);

/*
 * Flush any dirty pages for this process, and check for write errors.
 * The return status from this call provides a reliable indication of
 * whether any write errors occurred for this process.
 *
 * Notice that it clears the NFS_CONTEXT_ERROR_WRITE before synching to
 * disk, but it retrieves and clears ctx->error after synching, despite
 * the two being set at the same time in nfs_context_set_write_error().
 * This is because the former is used to notify the _next_ call to
 * nfs_file_write() that a write error occurred, and hence cause it to
 * fall back to doing a synchronous write.
 */
int
nfs_file_fsync_commit(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct nfs_open_context *ctx = nfs_file_open_context(file);
	struct inode *inode = file_inode(file);
	int have_error, do_resend, status;
	int ret = 0;

	dprintk("NFS: fsync file(%pD2) datasync %d\n", file, datasync);

	nfs_inc_stats(inode, NFSIOS_VFSFSYNC);
	do_resend = test_and_clear_bit(NFS_CONTEXT_RESEND_WRITES, &ctx->flags);
	have_error = test_and_clear_bit(NFS_CONTEXT_ERROR_WRITE, &ctx->flags);
	status = nfs_commit_inode(inode, FLUSH_SYNC);
	have_error |= test_bit(NFS_CONTEXT_ERROR_WRITE, &ctx->flags);
	if (have_error) {
		ret = xchg(&ctx->error, 0);
		if (ret)
			goto out;
	}
	if (status < 0) {
		ret = status;
		goto out;
	}
	do_resend |= test_bit(NFS_CONTEXT_RESEND_WRITES, &ctx->flags);
	if (do_resend)
		ret = -EAGAIN;
out:
	return ret;
}
EXPORT_SYMBOL_GPL(nfs_file_fsync_commit);

static int
nfs_file_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	int ret;
	struct inode *inode = file_inode(file);

	trace_nfs_fsync_enter(inode);

	do {
		ret = filemap_write_and_wait_range(inode->i_mapping, start, end);
		if (ret != 0)
			break;
		mutex_lock(&inode->i_mutex);
		ret = nfs_file_fsync_commit(file, start, end, datasync);
		mutex_unlock(&inode->i_mutex);
		/*
		 * If nfs_file_fsync_commit detected a server reboot, then
		 * resend all dirty pages that might have been covered by
		 * the NFS_CONTEXT_RESEND_WRITES flag
		 */
		start = 0;
		end = LLONG_MAX;
	} while (ret == -EAGAIN);

	trace_nfs_fsync_exit(inode, ret);
	return ret;
}

/*
 * Decide whether a read/modify/write cycle may be more efficient
 * then a modify/write/read cycle when writing to a page in the
 * page cache.
 *
 * The modify/write/read cycle may occur if a page is read before
 * being completely filled by the writer.  In this situation, the
 * page must be completely written to stable storage on the server
 * before it can be refilled by reading in the page from the server.
 * This can lead to expensive, small, FILE_SYNC mode writes being
 * done.
 *
 * It may be more efficient to read the page first if the file is
 * open for reading in addition to writing, the page is not marked
 * as Uptodate, it is not dirty or waiting to be committed,
 * indicating that it was previously allocated and then modified,
 * that there were valid bytes of data in that range of the file,
 * and that the new data won't completely replace the old data in
 * that range of the file.
 */
static int nfs_want_read_modify_write(struct file *file, struct page *page,
			loff_t pos, unsigned len)
{
	unsigned int pglen = nfs_page_length(page);
	unsigned int offset = pos & (PAGE_CACHE_SIZE - 1);
	unsigned int end = offset + len;

	if ((file->f_mode & FMODE_READ) &&	/* open for read? */
	    !PageUptodate(page) &&		/* Uptodate? */
	    !PagePrivate(page) &&		/* i/o request already? */
	    pglen &&				/* valid bytes of file? */
	    (end < pglen || offset))		/* replace all valid bytes? */
		return 1;
	return 0;
}

/*
 * This does the "real" work of the write. We must allocate and lock the
 * page to be sent back to the generic routine, which then copies the
 * data from user space.
 *
 * If the writer ends up delaying the write, the writer needs to
 * increment the page use counts until he is done with the page.
 */
static int nfs_write_begin(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned flags,
			struct page **pagep, void **fsdata)
{
	int ret;
	pgoff_t index = pos >> PAGE_CACHE_SHIFT;
	struct page *page;
	int once_thru = 0;

	dfprintk(PAGECACHE, "NFS: write_begin(%pD2(%lu), %u@%lld)\n",
		file, mapping->host->i_ino, len, (long long) pos);

start:
	/*
	 * Prevent starvation issues if someone is doing a consistency
	 * sync-to-disk
	 */
	ret = wait_on_bit_action(&NFS_I(mapping->host)->flags, NFS_INO_FLUSHING,
				 nfs_wait_bit_killable, TASK_KILLABLE);
	if (ret)
		return ret;

	page = grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;
	*pagep = page;

	ret = nfs_flush_incompatible(file, page);
	if (ret) {
		unlock_page(page);
		page_cache_release(page);
	} else if (!once_thru &&
		   nfs_want_read_modify_write(file, page, pos, len)) {
		once_thru = 1;
		ret = nfs_readpage(file, page);
		page_cache_release(page);
		if (!ret)
			goto start;
	}
	return ret;
}

static int nfs_write_end(struct file *file, struct address_space *mapping,
			loff_t pos, unsigned len, unsigned copied,
			struct page *page, void *fsdata)
{
	unsigned offset = pos & (PAGE_CACHE_SIZE - 1);
	struct nfs_open_context *ctx = nfs_file_open_context(file);
	int status;

	dfprintk(PAGECACHE, "NFS: write_end(%pD2(%lu), %u@%lld)\n",
		file, mapping->host->i_ino, len, (long long) pos);

	/*
	 * Zero any uninitialised parts of the page, and then mark the page
	 * as up to date if it turns out that we're extending the file.
	 */
	if (!PageUptodate(page)) {
		unsigned pglen = nfs_page_length(page);
		unsigned end = offset + len;

		if (pglen == 0) {
			zero_user_segments(page, 0, offset,
					end, PAGE_CACHE_SIZE);
			SetPageUptodate(page);
		} else if (end >= pglen) {
			zero_user_segment(page, end, PAGE_CACHE_SIZE);
			if (offset == 0)
				SetPageUptodate(page);
		} else
			zero_user_segment(page, pglen, PAGE_CACHE_SIZE);
	}

	status = nfs_updatepage(file, page, offset, copied);

	unlock_page(page);
	page_cache_release(page);

	if (status < 0)
		return status;
	NFS_I(mapping->host)->write_io += copied;

	if (nfs_ctx_key_to_expire(ctx)) {
		status = nfs_wb_all(mapping->host);
		if (status < 0)
			return status;
	}

	return copied;
}

/*
 * Partially or wholly invalidate a page
 * - Release the private state associated with a page if undergoing complete
 *   page invalidation
 * - Called if either PG_private or PG_fscache is set on the page
 * - Caller holds page lock
 */
static void nfs_invalidate_page(struct page *page, unsigned int offset,
				unsigned int length)
{
	dfprintk(PAGECACHE, "NFS: invalidate_page(%p, %u, %u)\n",
		 page, offset, length);

	if (offset != 0 || length < PAGE_CACHE_SIZE)
		return;
	/* Cancel any unstarted writes on this page */
	nfs_wb_page_cancel(page_file_mapping(page)->host, page);

	nfs_fscache_invalidate_page(page, page->mapping->host);
}

/*
 * Attempt to release the private state associated with a page
 * - Called if either PG_private or PG_fscache is set on the page
 * - Caller holds page lock
 * - Return true (may release page) or false (may not)
 */
static int nfs_release_page(struct page *page, gfp_t gfp)
{
	struct address_space *mapping = page->mapping;

	dfprintk(PAGECACHE, "NFS: release_page(%p)\n", page);

	/* Only do I/O if gfp is a superset of GFP_KERNEL, and we're not
	 * doing this memory reclaim for a fs-related allocation.
	 */
	if (mapping && (gfp & GFP_KERNEL) == GFP_KERNEL &&
	    !(current->flags & PF_FSTRANS)) {
		int how = FLUSH_SYNC;

		/* Don't let kswapd deadlock waiting for OOM RPC calls */
		if (current_is_kswapd())
			how = 0;
		nfs_commit_inode(mapping->host, how);
	}
	/* If PagePrivate() is set, then the page is not freeable */
	if (PagePrivate(page))
		return 0;
	return nfs_fscache_release_page(page, gfp);
}

static void nfs_check_dirty_writeback(struct page *page,
				bool *dirty, bool *writeback)
{
	struct nfs_inode *nfsi;
	struct address_space *mapping = page_file_mapping(page);

	if (!mapping || PageSwapCache(page))
		return;

	/*
	 * Check if an unstable page is currently being committed and
	 * if so, have the VM treat it as if the page is under writeback
	 * so it will not block due to pages that will shortly be freeable.
	 */
	nfsi = NFS_I(mapping->host);
	if (test_bit(NFS_INO_COMMIT, &nfsi->flags)) {
		*writeback = true;
		return;
	}

	/*
	 * If PagePrivate() is set, then the page is not freeable and as the
	 * inode is not being committed, it's not going to be cleaned in the
	 * near future so treat it as dirty
	 */
	if (PagePrivate(page))
		*dirty = true;
}

/*
 * Attempt to clear the private state associated with a page when an error
 * occurs that requires the cached contents of an inode to be written back or
 * destroyed
 * - Called if either PG_private or fscache is set on the page
 * - Caller holds page lock
 * - Return 0 if successful, -error otherwise
 */
static int nfs_launder_page(struct page *page)
{
	struct inode *inode = page_file_mapping(page)->host;
	struct nfs_inode *nfsi = NFS_I(inode);

	dfprintk(PAGECACHE, "NFS: launder_page(%ld, %llu)\n",
		inode->i_ino, (long long)page_offset(page));

	nfs_fscache_wait_on_page_write(nfsi, page);
	return nfs_wb_page(inode, page);
}

#ifdef CONFIG_NFS_SWAP
static int nfs_swap_activate(struct swap_info_struct *sis, struct file *file,
						sector_t *span)
{
	*span = sis->pages;
	return xs_swapper(NFS_CLIENT(file->f_mapping->host)->cl_xprt, 1);
}

static void nfs_swap_deactivate(struct file *file)
{
	xs_swapper(NFS_CLIENT(file->f_mapping->host)->cl_xprt, 0);
}
#endif

const struct address_space_operations nfs_file_aops = {
	.readpage = nfs_readpage,
	.readpages = nfs_readpages,
	.set_page_dirty = __set_page_dirty_nobuffers,
	.writepage = nfs_writepage,
	.writepages = nfs_writepages,
	.write_begin = nfs_write_begin,
	.write_end = nfs_write_end,
	.invalidatepage = nfs_invalidate_page,
	.releasepage = nfs_release_page,
	.direct_IO = nfs_direct_IO,
	.migratepage = nfs_migrate_page,
	.launder_page = nfs_launder_page,
	.is_dirty_writeback = nfs_check_dirty_writeback,
	.error_remove_page = generic_error_remove_page,
#ifdef CONFIG_NFS_SWAP
	.swap_activate = nfs_swap_activate,
	.swap_deactivate = nfs_swap_deactivate,
#endif
};

/*
 * Notification that a PTE pointing to an NFS page is about to be made
 * writable, implying that someone is about to modify the page through a
 * shared-writable mapping
 */
static int nfs_vm_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct file *filp = vma->vm_file;
	struct inode *inode = file_inode(filp);
	unsigned pagelen;
	int ret = VM_FAULT_NOPAGE;
	struct address_space *mapping;

	dfprintk(PAGECACHE, "NFS: vm_page_mkwrite(%pD2(%lu), offset %lld)\n",
		filp, filp->f_mapping->host->i_ino,
		(long long)page_offset(page));

	/* make sure the cache has finished storing the page */
	nfs_fscache_wait_on_page_write(NFS_I(inode), page);

	lock_page(page);
	mapping = page_file_mapping(page);
	if (mapping != inode->i_mapping)
		goto out_unlock;

	wait_on_page_writeback(page);

	pagelen = nfs_page_length(page);
	if (pagelen == 0)
		goto out_unlock;

	ret = VM_FAULT_LOCKED;
	if (nfs_flush_incompatible(filp, page) == 0 &&
	    nfs_updatepage(filp, page, 0, pagelen) == 0)
		goto out;

	ret = VM_FAULT_SIGBUS;
out_unlock:
	unlock_page(page);
out:
	return ret;
}

static const struct vm_operations_struct nfs_file_vm_ops = {
	.fault = filemap_fault,
	.map_pages = filemap_map_pages,
	.page_mkwrite = nfs_vm_page_mkwrite,
	.remap_pages = generic_file_remap_pages,
};

static int nfs_need_sync_write(struct file *filp, struct inode *inode)
{
	struct nfs_open_context *ctx;

	if (IS_SYNC(inode) || (filp->f_flags & O_DSYNC))
		return 1;
	ctx = nfs_file_open_context(filp);
	if (test_bit(NFS_CONTEXT_ERROR_WRITE, &ctx->flags) ||
	    nfs_ctx_key_to_expire(ctx))
		return 1;
	return 0;
}

ssize_t nfs_file_write(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	unsigned long written = 0;
	ssize_t result;
	size_t count = iov_iter_count(from);
	loff_t pos = iocb->ki_pos;

	result = nfs_key_timeout_notify(file, inode);
	if (result)
		return result;

	if (file->f_flags & O_DIRECT)
		return nfs_file_direct_write(iocb, from, pos, true);

	dprintk("NFS: write(%pD2, %zu@%Ld)\n",
		file, count, (long long) pos);

	result = -EBUSY;
	if (IS_SWAPFILE(inode))
		goto out_swapfile;
	/*
	 * O_APPEND implies that we must revalidate the file length.
	 */
	if (file->f_flags & O_APPEND) {
		result = nfs_revalidate_file_size(inode, file);
		if (result)
			goto out;
	}

	result = count;
	if (!count)
		goto out;

	result = generic_file_write_iter(iocb, from);
	if (result > 0)
		written = result;

	/* Return error values for O_DSYNC and IS_SYNC() */
	if (result >= 0 && nfs_need_sync_write(file, inode)) {
		int err = vfs_fsync(file, 0);
		if (err < 0)
			result = err;
	}
	if (result > 0)
		nfs_add_stats(inode, NFSIOS_NORMALWRITTENBYTES, written);
out:
	return result;

out_swapfile:
	printk(KERN_INFO "NFS: attempt to write to active swap file!\n");
	goto out;
}
EXPORT_SYMBOL_GPL(nfs_file_write);

static int
do_getlk(struct file *filp, int cmd, struct file_lock *fl, int is_local)
{
	struct inode *inode = filp->f_mapping->host;
	int status = 0;
	unsigned int saved_type = fl->fl_type;

	/* Try local locking first */
	posix_test_lock(filp, fl);
	if (fl->fl_type != F_UNLCK) {
		/* found a conflict */
		goto out;
	}
	fl->fl_type = saved_type;

	if (NFS_PROTO(inode)->have_delegation(inode, FMODE_READ))
		goto out_noconflict;

	if (is_local)
		goto out_noconflict;

	status = NFS_PROTO(inode)->lock(filp, cmd, fl);
out:
	return status;
out_noconflict:
	fl->fl_type = F_UNLCK;
	goto out;
}

static int do_vfs_lock(struct file *file, struct file_lock *fl)
{
	int res = 0;
	switch (fl->fl_flags & (FL_POSIX|FL_FLOCK)) {
		case FL_POSIX:
			res = posix_lock_file_wait(file, fl);
			break;
		case FL_FLOCK:
			res = flock_lock_file_wait(file, fl);
			break;
		default:
			BUG();
	}
	return res;
}

static int
do_unlk(struct file *filp, int cmd, struct file_lock *fl, int is_local)
{
	struct inode *inode = filp->f_mapping->host;
	struct nfs_lock_context *l_ctx;
	int status;

	/*
	 * Flush all pending writes before doing anything
	 * with locks..
	 */
	nfs_sync_mapping(filp->f_mapping);

	l_ctx = nfs_get_lock_context(nfs_file_open_context(filp));
	if (!IS_ERR(l_ctx)) {
		status = nfs_iocounter_wait(&l_ctx->io_count);
		nfs_put_lock_context(l_ctx);
		if (status < 0)
			return status;
	}

	/* NOTE: special case
	 * 	If we're signalled while cleaning up locks on process exit, we
	 * 	still need to complete the unlock.
	 */
	/*
	 * Use local locking if mounted with "-onolock" or with appropriate
	 * "-olocal_lock="
	 */
	if (!is_local)
		status = NFS_PROTO(inode)->lock(filp, cmd, fl);
	else
		status = do_vfs_lock(filp, fl);
	return status;
}

static int
is_time_granular(struct timespec *ts) {
	return ((ts->tv_sec == 0) && (ts->tv_nsec <= 1000));
}

static int
do_setlk(struct file *filp, int cmd, struct file_lock *fl, int is_local)
{
	struct inode *inode = filp->f_mapping->host;
	int status;

	/*
	 * Flush all pending writes before doing anything
	 * with locks..
	 */
	status = nfs_sync_mapping(filp->f_mapping);
	if (status != 0)
		goto out;

	/*
	 * Use local locking if mounted with "-onolock" or with appropriate
	 * "-olocal_lock="
	 */
	if (!is_local)
		status = NFS_PROTO(inode)->lock(filp, cmd, fl);
	else
		status = do_vfs_lock(filp, fl);
	if (status < 0)
		goto out;

	/*
	 * Revalidate the cache if the server has time stamps granular
	 * enough to detect subsecond changes.  Otherwise, clear the
	 * cache to prevent missing any changes.
	 *
	 * This makes locking act as a cache coherency point.
	 */
	nfs_sync_mapping(filp->f_mapping);
	if (!NFS_PROTO(inode)->have_delegation(inode, FMODE_READ)) {
		if (is_time_granular(&NFS_SERVER(inode)->time_delta))
			__nfs_revalidate_inode(NFS_SERVER(inode), inode);
		else
			nfs_zap_caches(inode);
	}
out:
	return status;
}

/*
 * Lock a (portion of) a file
 */
int nfs_lock(struct file *filp, int cmd, struct file_lock *fl)
{
	struct inode *inode = filp->f_mapping->host;
	int ret = -ENOLCK;
	int is_local = 0;

	dprintk("NFS: lock(%pD2, t=%x, fl=%x, r=%lld:%lld)\n",
			filp, fl->fl_type, fl->fl_flags,
			(long long)fl->fl_start, (long long)fl->fl_end);

	nfs_inc_stats(inode, NFSIOS_VFSLOCK);

	/* No mandatory locks over NFS */
	if (__mandatory_lock(inode) && fl->fl_type != F_UNLCK)
		goto out_err;

	if (NFS_SERVER(inode)->flags & NFS_MOUNT_LOCAL_FCNTL)
		is_local = 1;

	if (NFS_PROTO(inode)->lock_check_bounds != NULL) {
		ret = NFS_PROTO(inode)->lock_check_bounds(fl);
		if (ret < 0)
			goto out_err;
	}

	if (IS_GETLK(cmd))
		ret = do_getlk(filp, cmd, fl, is_local);
	else if (fl->fl_type == F_UNLCK)
		ret = do_unlk(filp, cmd, fl, is_local);
	else
		ret = do_setlk(filp, cmd, fl, is_local);
out_err:
	return ret;
}
EXPORT_SYMBOL_GPL(nfs_lock);

/*
 * Lock a (portion of) a file
 */
int nfs_flock(struct file *filp, int cmd, struct file_lock *fl)
{
	struct inode *inode = filp->f_mapping->host;
	int is_local = 0;

	dprintk("NFS: flock(%pD2, t=%x, fl=%x)\n",
			filp, fl->fl_type, fl->fl_flags);

	if (!(fl->fl_flags & FL_FLOCK))
		return -ENOLCK;

	/*
	 * The NFSv4 protocol doesn't support LOCK_MAND, which is not part of
	 * any standard. In principle we might be able to support LOCK_MAND
	 * on NFSv2/3 since NLMv3/4 support DOS share modes, but for now the
	 * NFS code is not set up for it.
	 */
	if (fl->fl_type & LOCK_MAND)
		return -EINVAL;

	if (NFS_SERVER(inode)->flags & NFS_MOUNT_LOCAL_FLOCK)
		is_local = 1;

	/* We're simulating flock() locks using posix locks on the server */
	if (fl->fl_type == F_UNLCK)
		return do_unlk(filp, cmd, fl, is_local);
	return do_setlk(filp, cmd, fl, is_local);
}
EXPORT_SYMBOL_GPL(nfs_flock);

/*
 * There is no protocol support for leases, so we have no way to implement
 * them correctly in the face of opens by other clients.
 */
int nfs_setlease(struct file *file, long arg, struct file_lock **fl)
{
	dprintk("NFS: setlease(%pD2, arg=%ld)\n", file, arg);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(nfs_setlease);

const struct file_operations nfs_file_operations = {
	.llseek		= nfs_file_llseek,
	.read		= new_sync_read,
	.write		= new_sync_write,
	.read_iter	= nfs_file_read,
	.write_iter	= nfs_file_write,
	.mmap		= nfs_file_mmap,
	.open		= nfs_file_open,
	.flush		= nfs_file_flush,
	.release	= nfs_file_release,
	.fsync		= nfs_file_fsync,
	.lock		= nfs_lock,
	.flock		= nfs_flock,
	.splice_read	= nfs_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.check_flags	= nfs_check_flags,
	.setlease	= nfs_setlease,
};
EXPORT_SYMBOL_GPL(nfs_file_operations);
/************************************************************/
/* ../linux-3.17/fs/nfs/file.c */
/************************************************************/
/* getroot.c: get the root dentry for an NFS mount
 *
 * Copyright (C) 2006 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

// #include <linux/module.h>
// #include <linux/init.h>

// #include <linux/time.h>
// #include <linux/kernel.h>
// #include <linux/mm.h>
// #include <linux/string.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
// #include <linux/unistd.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/stats.h>
// #include <linux/nfs_fs.h>
// #include <linux/nfs_mount.h>
// #include <linux/lockd/bind.h>
// #include <linux/seq_file.h>
// #include <linux/mount.h>
// #include <linux/vfs.h>
// #include <linux/namei.h>
#include <linux/security.h>

// #include <asm/uaccess.h>

// #include "internal.h"

#define NFSDBG_FACILITY		NFSDBG_CLIENT

/*
 * Set the superblock root dentry.
 * Note that this function frees the inode in case of error.
 */
static int nfs_superblock_set_dummy_root(struct super_block *sb, struct inode *inode)
{
	/* The mntroot acts as the dummy root dentry for this superblock */
	if (sb->s_root == NULL) {
		sb->s_root = d_make_root(inode);
		if (sb->s_root == NULL)
			return -ENOMEM;
		ihold(inode);
		/*
		 * Ensure that this dentry is invisible to d_find_alias().
		 * Otherwise, it may be spliced into the tree by
		 * d_materialise_unique if a parent directory from the same
		 * filesystem gets mounted at a later time.
		 * This again causes shrink_dcache_for_umount_subtree() to
		 * Oops, since the test for IS_ROOT() will fail.
		 */
		spin_lock(&sb->s_root->d_inode->i_lock);
		spin_lock(&sb->s_root->d_lock);
		hlist_del_init(&sb->s_root->d_alias);
		spin_unlock(&sb->s_root->d_lock);
		spin_unlock(&sb->s_root->d_inode->i_lock);
	}
	return 0;
}

/*
 * get an NFS2/NFS3 root dentry from the root filehandle
 */
struct dentry *nfs_get_root(struct super_block *sb, struct nfs_fh *mntfh,
			    const char *devname)
{
	struct nfs_server *server = NFS_SB(sb);
	struct nfs_fsinfo fsinfo;
	struct dentry *ret;
	struct inode *inode;
	void *name = kstrdup(devname, GFP_KERNEL);
	int error;

	if (!name)
		return ERR_PTR(-ENOMEM);

	/* get the actual root for this mount */
	fsinfo.fattr = nfs_alloc_fattr();
	if (fsinfo.fattr == NULL) {
		kfree(name);
		return ERR_PTR(-ENOMEM);
	}

	error = server->nfs_client->rpc_ops->getroot(server, mntfh, &fsinfo);
	if (error < 0) {
		dprintk("nfs_get_root: getattr error = %d\n", -error);
		ret = ERR_PTR(error);
		goto out;
	}

	inode = nfs_fhget(sb, mntfh, fsinfo.fattr, NULL);
	if (IS_ERR(inode)) {
		dprintk("nfs_get_root: get root inode failed\n");
		ret = ERR_CAST(inode);
		goto out;
	}

	error = nfs_superblock_set_dummy_root(sb, inode);
	if (error != 0) {
		ret = ERR_PTR(error);
		goto out;
	}

	/* root dentries normally start off anonymous and get spliced in later
	 * if the dentry tree reaches them; however if the dentry already
	 * exists, we'll pick it up at this point and use it as the root
	 */
	ret = d_obtain_root(inode);
	if (IS_ERR(ret)) {
		dprintk("nfs_get_root: get root dentry failed\n");
		goto out;
	}

	security_d_instantiate(ret, inode);
	spin_lock(&ret->d_lock);
	if (IS_ROOT(ret) && !ret->d_fsdata &&
	    !(ret->d_flags & DCACHE_NFSFS_RENAMED)) {
		ret->d_fsdata = name;
		name = NULL;
	}
	spin_unlock(&ret->d_lock);
out:
	kfree(name);
	nfs_free_fattr(fsinfo.fattr);
	return ret;
}
/************************************************************/
/* ../linux-3.17/fs/nfs/getroot.c */
/************************************************************/
/*
 *  linux/fs/nfs/inode.c
 *
 *  Copyright (C) 1992  Rick Sladkey
 *
 *  nfs inode and superblock handling functions
 *
 *  Modularised by Alan Cox <alan@lxorguk.ukuu.org.uk>, while hacking some
 *  experimental NFS changes. Modularisation taken straight from SYS5 fs.
 *
 *  Change to nfs_read_super() to permit NFS mounts to multi-homed hosts.
 *  J.S.Peatfield@damtp.cam.ac.uk
 *
 */

// #include <linux/module.h>
// #include <linux/init.h>
// #include <linux/sched.h>
// #include <linux/time.h>
// #include <linux/kernel.h>
// #include <linux/mm.h>
// #include <linux/string.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
// #include <linux/unistd.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/stats.h>
// #include <linux/sunrpc/metrics.h>
// #include <linux/nfs_fs.h>
// #include <linux/nfs_mount.h>
// #include <linux/nfs4_mount.h>
// #include <linux/lockd/bind.h>
// #include <linux/seq_file.h>
// #include <linux/mount.h>
// #include <linux/vfs.h>
// #include <linux/inet.h>
// #include <linux/nfs_xdr.h>
// #include <linux/slab.h>
#include <linux/compat.h>
#include <linux/freezer.h>

// #include <asm/uaccess.h>

// #include "nfs4_fs.h"
// #include "callback.h"
// #include "delegation.h"
// #include "iostat.h"
// #include "internal.h"
// #include "fscache.h"
// #include "pnfs.h"
// #include "nfs.h"
// #include "netns.h"

// #include "nfstrace.h"

#define NFSDBG_FACILITY		NFSDBG_VFS

#define NFS_64_BIT_INODE_NUMBERS_ENABLED	1

/* Default is to see 64-bit inode numbers */
static bool enable_ino64 = NFS_64_BIT_INODE_NUMBERS_ENABLED;

static void nfs_invalidate_inode(struct inode *);
static int nfs_update_inode(struct inode *, struct nfs_fattr *);

static struct kmem_cache * nfs_inode_cachep;

static inline unsigned long
nfs_fattr_to_ino_t(struct nfs_fattr *fattr)
{
	return nfs_fileid_to_ino_t(fattr->fileid);
}

/**
 * nfs_wait_bit_killable - helper for functions that are sleeping on bit locks
 * @word: long word containing the bit lock
 */
int nfs_wait_bit_killable(struct wait_bit_key *key)
{
	if (fatal_signal_pending(current))
		return -ERESTARTSYS;
	freezable_schedule_unsafe();
	return 0;
}
EXPORT_SYMBOL_GPL(nfs_wait_bit_killable);

/**
 * nfs_compat_user_ino64 - returns the user-visible inode number
 * @fileid: 64-bit fileid
 *
 * This function returns a 32-bit inode number if the boot parameter
 * nfs.enable_ino64 is zero.
 */
u64 nfs_compat_user_ino64(u64 fileid)
{
#ifdef CONFIG_COMPAT
	compat_ulong_t ino;
#else
	unsigned long ino;
#endif

	if (enable_ino64)
		return fileid;
	ino = fileid;
	if (sizeof(ino) < sizeof(fileid))
		ino ^= fileid >> (sizeof(fileid)-sizeof(ino)) * 8;
	return ino;
}

int nfs_drop_inode(struct inode *inode)
{
	return NFS_STALE(inode) || generic_drop_inode(inode);
}
EXPORT_SYMBOL_GPL(nfs_drop_inode);

void nfs_clear_inode(struct inode *inode)
{
	/*
	 * The following should never happen...
	 */
	WARN_ON_ONCE(nfs_have_writebacks(inode));
	WARN_ON_ONCE(!list_empty(&NFS_I(inode)->open_files));
	nfs_zap_acl_cache(inode);
	nfs_access_zap_cache(inode);
	nfs_fscache_clear_inode(inode);
}
EXPORT_SYMBOL_GPL(nfs_clear_inode);

void nfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	clear_inode(inode);
	nfs_clear_inode(inode);
}

/**
 * nfs_sync_mapping - helper to flush all mmapped dirty data to disk
 */
int nfs_sync_mapping(struct address_space *mapping)
{
	int ret = 0;

	if (mapping->nrpages != 0) {
		unmap_mapping_range(mapping, 0, 0, 0);
		ret = nfs_wb_all(mapping->host);
	}
	return ret;
}

static void nfs_set_cache_invalid(struct inode *inode, unsigned long flags)
{
	struct nfs_inode *nfsi = NFS_I(inode);

	if (inode->i_mapping->nrpages == 0)
		flags &= ~NFS_INO_INVALID_DATA;
	nfsi->cache_validity |= flags;
	if (flags & NFS_INO_INVALID_DATA)
		nfs_fscache_invalidate(inode);
}

/*
 * Invalidate the local caches
 */
static void nfs_zap_caches_locked(struct inode *inode)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	int mode = inode->i_mode;

	nfs_inc_stats(inode, NFSIOS_ATTRINVALIDATE);

	nfsi->attrtimeo = NFS_MINATTRTIMEO(inode);
	nfsi->attrtimeo_timestamp = jiffies;

	memset(NFS_I(inode)->cookieverf, 0, sizeof(NFS_I(inode)->cookieverf));
	if (S_ISREG(mode) || S_ISDIR(mode) || S_ISLNK(mode)) {
		nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR
					| NFS_INO_INVALID_DATA
					| NFS_INO_INVALID_ACCESS
					| NFS_INO_INVALID_ACL
					| NFS_INO_REVAL_PAGECACHE);
	} else
		nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR
					| NFS_INO_INVALID_ACCESS
					| NFS_INO_INVALID_ACL
					| NFS_INO_REVAL_PAGECACHE);
	nfs_zap_label_cache_locked(nfsi);
}

void nfs_zap_caches(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	nfs_zap_caches_locked(inode);
	spin_unlock(&inode->i_lock);
}

void nfs_zap_mapping(struct inode *inode, struct address_space *mapping)
{
	if (mapping->nrpages != 0) {
		spin_lock(&inode->i_lock);
		nfs_set_cache_invalid(inode, NFS_INO_INVALID_DATA);
		spin_unlock(&inode->i_lock);
	}
}

void nfs_zap_acl_cache(struct inode *inode)
{
	void (*clear_acl_cache)(struct inode *);

	clear_acl_cache = NFS_PROTO(inode)->clear_acl_cache;
	if (clear_acl_cache != NULL)
		clear_acl_cache(inode);
	spin_lock(&inode->i_lock);
	NFS_I(inode)->cache_validity &= ~NFS_INO_INVALID_ACL;
	spin_unlock(&inode->i_lock);
}
EXPORT_SYMBOL_GPL(nfs_zap_acl_cache);

void nfs_invalidate_atime(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATIME);
	spin_unlock(&inode->i_lock);
}
EXPORT_SYMBOL_GPL(nfs_invalidate_atime);

/*
 * Invalidate, but do not unhash, the inode.
 * NB: must be called with inode->i_lock held!
 */
static void nfs_invalidate_inode(struct inode *inode)
{
	set_bit(NFS_INO_STALE, &NFS_I(inode)->flags);
	nfs_zap_caches_locked(inode);
}

struct nfs_find_desc {
	struct nfs_fh		*fh;
	struct nfs_fattr	*fattr;
};

/*
 * In NFSv3 we can have 64bit inode numbers. In order to support
 * this, and re-exported directories (also seen in NFSv2)
 * we are forced to allow 2 different inodes to have the same
 * i_ino.
 */
static int
nfs_find_actor(struct inode *inode, void *opaque)
{
	struct nfs_find_desc	*desc = (struct nfs_find_desc *)opaque;
	struct nfs_fh		*fh = desc->fh;
	struct nfs_fattr	*fattr = desc->fattr;

	if (NFS_FILEID(inode) != fattr->fileid)
		return 0;
	if ((S_IFMT & inode->i_mode) != (S_IFMT & fattr->mode))
		return 0;
	if (nfs_compare_fh(NFS_FH(inode), fh))
		return 0;
	if (is_bad_inode(inode) || NFS_STALE(inode))
		return 0;
	return 1;
}

static int
nfs_init_locked(struct inode *inode, void *opaque)
{
	struct nfs_find_desc	*desc = (struct nfs_find_desc *)opaque;
	struct nfs_fattr	*fattr = desc->fattr;

	set_nfs_fileid(inode, fattr->fileid);
	nfs_copy_fh(NFS_FH(inode), desc->fh);
	return 0;
}

#ifdef CONFIG_NFS_V4_SECURITY_LABEL
static void nfs_clear_label_invalid(struct inode *inode)
{
	spin_lock(&inode->i_lock);
	NFS_I(inode)->cache_validity &= ~NFS_INO_INVALID_LABEL;
	spin_unlock(&inode->i_lock);
}

void nfs_setsecurity(struct inode *inode, struct nfs_fattr *fattr,
					struct nfs4_label *label)
{
	int error;

	if (label == NULL)
		return;

	if ((fattr->valid & NFS_ATTR_FATTR_V4_SECURITY_LABEL) && inode->i_security) {
		error = security_inode_notifysecctx(inode, label->label,
				label->len);
		if (error)
			printk(KERN_ERR "%s() %s %d "
					"security_inode_notifysecctx() %d\n",
					__func__,
					(char *)label->label,
					label->len, error);
		nfs_clear_label_invalid(inode);
	}
}

struct nfs4_label *nfs4_label_alloc(struct nfs_server *server, gfp_t flags)
{
	struct nfs4_label *label = NULL;
	int minor_version = server->nfs_client->cl_minorversion;

	if (minor_version < 2)
		return label;

	if (!(server->caps & NFS_CAP_SECURITY_LABEL))
		return label;

	label = kzalloc(sizeof(struct nfs4_label), flags);
	if (label == NULL)
		return ERR_PTR(-ENOMEM);

	label->label = kzalloc(NFS4_MAXLABELLEN, flags);
	if (label->label == NULL) {
		kfree(label);
		return ERR_PTR(-ENOMEM);
	}
	label->len = NFS4_MAXLABELLEN;

	return label;
}
EXPORT_SYMBOL_GPL(nfs4_label_alloc);
#else
void nfs_setsecurity(struct inode *inode, struct nfs_fattr *fattr,
					struct nfs4_label *label)
{
}
#endif
EXPORT_SYMBOL_GPL(nfs_setsecurity);

/*
 * This is our front-end to iget that looks up inodes by file handle
 * instead of inode number.
 */
struct inode *
nfs_fhget(struct super_block *sb, struct nfs_fh *fh, struct nfs_fattr *fattr, struct nfs4_label *label)
{
	struct nfs_find_desc desc = {
		.fh	= fh,
		.fattr	= fattr
	};
	struct inode *inode = ERR_PTR(-ENOENT);
	unsigned long hash;

	nfs_attr_check_mountpoint(sb, fattr);

	if (((fattr->valid & NFS_ATTR_FATTR_FILEID) == 0) &&
	    !nfs_attr_use_mounted_on_fileid(fattr))
		goto out_no_inode;
	if ((fattr->valid & NFS_ATTR_FATTR_TYPE) == 0)
		goto out_no_inode;

	hash = nfs_fattr_to_ino_t(fattr);

	inode = iget5_locked(sb, hash, nfs_find_actor, nfs_init_locked, &desc);
	if (inode == NULL) {
		inode = ERR_PTR(-ENOMEM);
		goto out_no_inode;
	}

	if (inode->i_state & I_NEW) {
		struct nfs_inode *nfsi = NFS_I(inode);
		unsigned long now = jiffies;

		/* We set i_ino for the few things that still rely on it,
		 * such as stat(2) */
		inode->i_ino = hash;

		/* We can't support update_atime(), since the server will reset it */
		inode->i_flags |= S_NOATIME|S_NOCMTIME;
		inode->i_mode = fattr->mode;
		if ((fattr->valid & NFS_ATTR_FATTR_MODE) == 0
				&& nfs_server_capable(inode, NFS_CAP_MODE))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR);
		/* Why so? Because we want revalidate for devices/FIFOs, and
		 * that's precisely what we have in nfs_file_inode_operations.
		 */
		inode->i_op = NFS_SB(sb)->nfs_client->rpc_ops->file_inode_ops;
		if (S_ISREG(inode->i_mode)) {
			inode->i_fop = NFS_SB(sb)->nfs_client->rpc_ops->file_ops;
			inode->i_data.a_ops = &nfs_file_aops;
			inode->i_data.backing_dev_info = &NFS_SB(sb)->backing_dev_info;
		} else if (S_ISDIR(inode->i_mode)) {
			inode->i_op = NFS_SB(sb)->nfs_client->rpc_ops->dir_inode_ops;
			inode->i_fop = &nfs_dir_operations;
			inode->i_data.a_ops = &nfs_dir_aops;
			/* Deal with crossing mountpoints */
			if (fattr->valid & NFS_ATTR_FATTR_MOUNTPOINT ||
					fattr->valid & NFS_ATTR_FATTR_V4_REFERRAL) {
				if (fattr->valid & NFS_ATTR_FATTR_V4_REFERRAL)
					inode->i_op = &nfs_referral_inode_operations;
				else
					inode->i_op = &nfs_mountpoint_inode_operations;
				inode->i_fop = NULL;
				inode->i_flags |= S_AUTOMOUNT;
			}
		} else if (S_ISLNK(inode->i_mode))
			inode->i_op = &nfs_symlink_inode_operations;
		else
			init_special_inode(inode, inode->i_mode, fattr->rdev);

		memset(&inode->i_atime, 0, sizeof(inode->i_atime));
		memset(&inode->i_mtime, 0, sizeof(inode->i_mtime));
		memset(&inode->i_ctime, 0, sizeof(inode->i_ctime));
		inode->i_version = 0;
		inode->i_size = 0;
		clear_nlink(inode);
		inode->i_uid = make_kuid(&init_user_ns, -2);
		inode->i_gid = make_kgid(&init_user_ns, -2);
		inode->i_blocks = 0;
		memset(nfsi->cookieverf, 0, sizeof(nfsi->cookieverf));
		nfsi->write_io = 0;
		nfsi->read_io = 0;

		nfsi->read_cache_jiffies = fattr->time_start;
		nfsi->attr_gencount = fattr->gencount;
		if (fattr->valid & NFS_ATTR_FATTR_ATIME)
			inode->i_atime = fattr->atime;
		else if (nfs_server_capable(inode, NFS_CAP_ATIME))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR);
		if (fattr->valid & NFS_ATTR_FATTR_MTIME)
			inode->i_mtime = fattr->mtime;
		else if (nfs_server_capable(inode, NFS_CAP_MTIME))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR);
		if (fattr->valid & NFS_ATTR_FATTR_CTIME)
			inode->i_ctime = fattr->ctime;
		else if (nfs_server_capable(inode, NFS_CAP_CTIME))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR);
		if (fattr->valid & NFS_ATTR_FATTR_CHANGE)
			inode->i_version = fattr->change_attr;
		else if (nfs_server_capable(inode, NFS_CAP_CHANGE_ATTR))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR);
		if (fattr->valid & NFS_ATTR_FATTR_SIZE)
			inode->i_size = nfs_size_to_loff_t(fattr->size);
		else
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR
				| NFS_INO_REVAL_PAGECACHE);
		if (fattr->valid & NFS_ATTR_FATTR_NLINK)
			set_nlink(inode, fattr->nlink);
		else if (nfs_server_capable(inode, NFS_CAP_NLINK))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR);
		if (fattr->valid & NFS_ATTR_FATTR_OWNER)
			inode->i_uid = fattr->uid;
		else if (nfs_server_capable(inode, NFS_CAP_OWNER))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR);
		if (fattr->valid & NFS_ATTR_FATTR_GROUP)
			inode->i_gid = fattr->gid;
		else if (nfs_server_capable(inode, NFS_CAP_OWNER_GROUP))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_ATTR);
		if (fattr->valid & NFS_ATTR_FATTR_BLOCKS_USED)
			inode->i_blocks = fattr->du.nfs2.blocks;
		if (fattr->valid & NFS_ATTR_FATTR_SPACE_USED) {
			/*
			 * report the blocks in 512byte units
			 */
			inode->i_blocks = nfs_calc_block_size(fattr->du.nfs3.used);
		}

		nfs_setsecurity(inode, fattr, label);

		nfsi->attrtimeo = NFS_MINATTRTIMEO(inode);
		nfsi->attrtimeo_timestamp = now;
		nfsi->access_cache = RB_ROOT;

		nfs_fscache_init_inode(inode);

		unlock_new_inode(inode);
	} else
		nfs_refresh_inode(inode, fattr);
	dprintk("NFS: nfs_fhget(%s/%Lu fh_crc=0x%08x ct=%d)\n",
		inode->i_sb->s_id,
		(unsigned long long)NFS_FILEID(inode),
		nfs_display_fhandle_hash(fh),
		atomic_read(&inode->i_count));

out:
	return inode;

out_no_inode:
	dprintk("nfs_fhget: iget failed with error %ld\n", PTR_ERR(inode));
	goto out;
}
EXPORT_SYMBOL_GPL(nfs_fhget);

#define NFS_VALID_ATTRS (ATTR_MODE|ATTR_UID|ATTR_GID|ATTR_SIZE|ATTR_ATIME|ATTR_ATIME_SET|ATTR_MTIME|ATTR_MTIME_SET|ATTR_FILE|ATTR_OPEN)

int
nfs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct nfs_fattr *fattr;
	int error = -ENOMEM;

	nfs_inc_stats(inode, NFSIOS_VFSSETATTR);

	/* skip mode change if it's just for clearing setuid/setgid */
	if (attr->ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		attr->ia_valid &= ~ATTR_MODE;

	if (attr->ia_valid & ATTR_SIZE) {
		if (!S_ISREG(inode->i_mode) || attr->ia_size == i_size_read(inode))
			attr->ia_valid &= ~ATTR_SIZE;
	}

	/* Optimization: if the end result is no change, don't RPC */
	attr->ia_valid &= NFS_VALID_ATTRS;
	if ((attr->ia_valid & ~(ATTR_FILE|ATTR_OPEN)) == 0)
		return 0;

	trace_nfs_setattr_enter(inode);

	/* Write all dirty data */
	if (S_ISREG(inode->i_mode)) {
		nfs_inode_dio_wait(inode);
		nfs_wb_all(inode);
	}

	fattr = nfs_alloc_fattr();
	if (fattr == NULL)
		goto out;
	/*
	 * Return any delegations if we're going to change ACLs
	 */
	if ((attr->ia_valid & (ATTR_MODE|ATTR_UID|ATTR_GID)) != 0)
		NFS_PROTO(inode)->return_delegation(inode);
	error = NFS_PROTO(inode)->setattr(dentry, fattr, attr);
	if (error == 0)
		error = nfs_refresh_inode(inode, fattr);
	nfs_free_fattr(fattr);
out:
	trace_nfs_setattr_exit(inode, error);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_setattr);

/**
 * nfs_vmtruncate - unmap mappings "freed" by truncate() syscall
 * @inode: inode of the file used
 * @offset: file offset to start truncating
 *
 * This is a copy of the common vmtruncate, but with the locking
 * corrected to take into account the fact that NFS requires
 * inode->i_size to be updated under the inode->i_lock.
 */
static int nfs_vmtruncate(struct inode * inode, loff_t offset)
{
	int err;

	err = inode_newsize_ok(inode, offset);
	if (err)
		goto out;

	spin_lock(&inode->i_lock);
	i_size_write(inode, offset);
	/* Optimisation */
	if (offset == 0)
		NFS_I(inode)->cache_validity &= ~NFS_INO_INVALID_DATA;
	spin_unlock(&inode->i_lock);

	truncate_pagecache(inode, offset);
out:
	return err;
}

/**
 * nfs_setattr_update_inode - Update inode metadata after a setattr call.
 * @inode: pointer to struct inode
 * @attr: pointer to struct iattr
 *
 * Note: we do this in the *proc.c in order to ensure that
 *       it works for things like exclusive creates too.
 */
void nfs_setattr_update_inode(struct inode *inode, struct iattr *attr)
{
	if ((attr->ia_valid & (ATTR_MODE|ATTR_UID|ATTR_GID)) != 0) {
		spin_lock(&inode->i_lock);
		if ((attr->ia_valid & ATTR_MODE) != 0) {
			int mode = attr->ia_mode & S_IALLUGO;
			mode |= inode->i_mode & ~S_IALLUGO;
			inode->i_mode = mode;
		}
		if ((attr->ia_valid & ATTR_UID) != 0)
			inode->i_uid = attr->ia_uid;
		if ((attr->ia_valid & ATTR_GID) != 0)
			inode->i_gid = attr->ia_gid;
		nfs_set_cache_invalid(inode, NFS_INO_INVALID_ACCESS
				| NFS_INO_INVALID_ACL);
		spin_unlock(&inode->i_lock);
	}
	if ((attr->ia_valid & ATTR_SIZE) != 0) {
		nfs_inc_stats(inode, NFSIOS_SETATTRTRUNC);
		nfs_vmtruncate(inode, attr->ia_size);
	}
}
EXPORT_SYMBOL_GPL(nfs_setattr_update_inode);

static void nfs_request_parent_use_readdirplus(struct dentry *dentry)
{
	struct dentry *parent;

	parent = dget_parent(dentry);
	nfs_force_use_readdirplus(parent->d_inode);
	dput(parent);
}

static bool nfs_need_revalidate_inode(struct inode *inode)
{
	if (NFS_I(inode)->cache_validity &
			(NFS_INO_INVALID_ATTR|NFS_INO_INVALID_LABEL))
		return true;
	if (nfs_attribute_cache_expired(inode))
		return true;
	return false;
}

int nfs_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	int need_atime = NFS_I(inode)->cache_validity & NFS_INO_INVALID_ATIME;
	int err;

	trace_nfs_getattr_enter(inode);
	/* Flush out writes to the server in order to update c/mtime.  */
	if (S_ISREG(inode->i_mode)) {
		nfs_inode_dio_wait(inode);
		err = filemap_write_and_wait(inode->i_mapping);
		if (err)
			goto out;
	}

	/*
	 * We may force a getattr if the user cares about atime.
	 *
	 * Note that we only have to check the vfsmount flags here:
	 *  - NFS always sets S_NOATIME by so checking it would give a
	 *    bogus result
	 *  - NFS never sets MS_NOATIME or MS_NODIRATIME so there is
	 *    no point in checking those.
	 */
 	if ((mnt->mnt_flags & MNT_NOATIME) ||
 	    ((mnt->mnt_flags & MNT_NODIRATIME) && S_ISDIR(inode->i_mode)))
		need_atime = 0;

	if (need_atime || nfs_need_revalidate_inode(inode)) {
		struct nfs_server *server = NFS_SERVER(inode);

		if (server->caps & NFS_CAP_READDIRPLUS)
			nfs_request_parent_use_readdirplus(dentry);
		err = __nfs_revalidate_inode(server, inode);
	}
	if (!err) {
		generic_fillattr(inode, stat);
		stat->ino = nfs_compat_user_ino64(NFS_FILEID(inode));
	}
out:
	trace_nfs_getattr_exit(inode, err);
	return err;
}
EXPORT_SYMBOL_GPL(nfs_getattr);

static void nfs_init_lock_context(struct nfs_lock_context *l_ctx)
{
	atomic_set(&l_ctx->count, 1);
	l_ctx->lockowner.l_owner = current->files;
	l_ctx->lockowner.l_pid = current->tgid;
	INIT_LIST_HEAD(&l_ctx->list);
	nfs_iocounter_init(&l_ctx->io_count);
}

static struct nfs_lock_context *__nfs_find_lock_context(struct nfs_open_context *ctx)
{
	struct nfs_lock_context *head = &ctx->lock_context;
	struct nfs_lock_context *pos = head;

	do {
		if (pos->lockowner.l_owner != current->files)
			continue;
		if (pos->lockowner.l_pid != current->tgid)
			continue;
		atomic_inc(&pos->count);
		return pos;
	} while ((pos = list_entry(pos->list.next, typeof(*pos), list)) != head);
	return NULL;
}

struct nfs_lock_context *nfs_get_lock_context(struct nfs_open_context *ctx)
{
	struct nfs_lock_context *res, *new = NULL;
	struct inode *inode = ctx->dentry->d_inode;

	spin_lock(&inode->i_lock);
	res = __nfs_find_lock_context(ctx);
	if (res == NULL) {
		spin_unlock(&inode->i_lock);
		new = kmalloc(sizeof(*new), GFP_KERNEL);
		if (new == NULL)
			return ERR_PTR(-ENOMEM);
		nfs_init_lock_context(new);
		spin_lock(&inode->i_lock);
		res = __nfs_find_lock_context(ctx);
		if (res == NULL) {
			list_add_tail(&new->list, &ctx->lock_context.list);
			new->open_context = ctx;
			res = new;
			new = NULL;
		}
	}
	spin_unlock(&inode->i_lock);
	kfree(new);
	return res;
}

void nfs_put_lock_context(struct nfs_lock_context *l_ctx)
{
	struct nfs_open_context *ctx = l_ctx->open_context;
	struct inode *inode = ctx->dentry->d_inode;

	if (!atomic_dec_and_lock(&l_ctx->count, &inode->i_lock))
		return;
	list_del(&l_ctx->list);
	spin_unlock(&inode->i_lock);
	kfree(l_ctx);
}

/**
 * nfs_close_context - Common close_context() routine NFSv2/v3
 * @ctx: pointer to context
 * @is_sync: is this a synchronous close
 *
 * always ensure that the attributes are up to date if we're mounted
 * with close-to-open semantics
 */
void nfs_close_context(struct nfs_open_context *ctx, int is_sync)
{
	struct inode *inode;
	struct nfs_server *server;

	if (!(ctx->mode & FMODE_WRITE))
		return;
	if (!is_sync)
		return;
	inode = ctx->dentry->d_inode;
	if (!list_empty(&NFS_I(inode)->open_files))
		return;
	server = NFS_SERVER(inode);
	if (server->flags & NFS_MOUNT_NOCTO)
		return;
	nfs_revalidate_inode(server, inode);
}
EXPORT_SYMBOL_GPL(nfs_close_context);

struct nfs_open_context *alloc_nfs_open_context(struct dentry *dentry, fmode_t f_mode)
{
	struct nfs_open_context *ctx;
	struct rpc_cred *cred = rpc_lookup_cred();
	if (IS_ERR(cred))
		return ERR_CAST(cred);

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		put_rpccred(cred);
		return ERR_PTR(-ENOMEM);
	}
	nfs_sb_active(dentry->d_sb);
	ctx->dentry = dget(dentry);
	ctx->cred = cred;
	ctx->state = NULL;
	ctx->mode = f_mode;
	ctx->flags = 0;
	ctx->error = 0;
	nfs_init_lock_context(&ctx->lock_context);
	ctx->lock_context.open_context = ctx;
	INIT_LIST_HEAD(&ctx->list);
	ctx->mdsthreshold = NULL;
	return ctx;
}
EXPORT_SYMBOL_GPL(alloc_nfs_open_context);

struct nfs_open_context *get_nfs_open_context(struct nfs_open_context *ctx)
{
	if (ctx != NULL)
		atomic_inc(&ctx->lock_context.count);
	return ctx;
}
EXPORT_SYMBOL_GPL(get_nfs_open_context);

static void __put_nfs_open_context(struct nfs_open_context *ctx, int is_sync)
{
	struct inode *inode = ctx->dentry->d_inode;
	struct super_block *sb = ctx->dentry->d_sb;

	if (!list_empty(&ctx->list)) {
		if (!atomic_dec_and_lock(&ctx->lock_context.count, &inode->i_lock))
			return;
		list_del(&ctx->list);
		spin_unlock(&inode->i_lock);
	} else if (!atomic_dec_and_test(&ctx->lock_context.count))
		return;
	if (inode != NULL)
		NFS_PROTO(inode)->close_context(ctx, is_sync);
	if (ctx->cred != NULL)
		put_rpccred(ctx->cred);
	dput(ctx->dentry);
	nfs_sb_deactive(sb);
	kfree(ctx->mdsthreshold);
	kfree(ctx);
}

void put_nfs_open_context(struct nfs_open_context *ctx)
{
	__put_nfs_open_context(ctx, 0);
}
EXPORT_SYMBOL_GPL(put_nfs_open_context);

/*
 * Ensure that mmap has a recent RPC credential for use when writing out
 * shared pages
 */
void nfs_inode_attach_open_context(struct nfs_open_context *ctx)
{
	struct inode *inode = ctx->dentry->d_inode;
	struct nfs_inode *nfsi = NFS_I(inode);

	spin_lock(&inode->i_lock);
	list_add(&ctx->list, &nfsi->open_files);
	spin_unlock(&inode->i_lock);
}
EXPORT_SYMBOL_GPL(nfs_inode_attach_open_context);

void nfs_file_set_open_context(struct file *filp, struct nfs_open_context *ctx)
{
	filp->private_data = get_nfs_open_context(ctx);
	if (list_empty(&ctx->list))
		nfs_inode_attach_open_context(ctx);
}
EXPORT_SYMBOL_GPL(nfs_file_set_open_context);

/*
 * Given an inode, search for an open context with the desired characteristics
 */
struct nfs_open_context *nfs_find_open_context(struct inode *inode, struct rpc_cred *cred, fmode_t mode)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	struct nfs_open_context *pos, *ctx = NULL;

	spin_lock(&inode->i_lock);
	list_for_each_entry(pos, &nfsi->open_files, list) {
		if (cred != NULL && pos->cred != cred)
			continue;
		if ((pos->mode & (FMODE_READ|FMODE_WRITE)) != mode)
			continue;
		ctx = get_nfs_open_context(pos);
		break;
	}
	spin_unlock(&inode->i_lock);
	return ctx;
}

static void nfs_file_clear_open_context(struct file *filp)
{
	struct nfs_open_context *ctx = nfs_file_open_context(filp);

	if (ctx) {
		struct inode *inode = ctx->dentry->d_inode;

		filp->private_data = NULL;
		spin_lock(&inode->i_lock);
		list_move_tail(&ctx->list, &NFS_I(inode)->open_files);
		spin_unlock(&inode->i_lock);
		__put_nfs_open_context(ctx, filp->f_flags & O_DIRECT ? 0 : 1);
	}
}

/*
 * These allocate and release file read/write context information.
 */
int nfs_open(struct inode *inode, struct file *filp)
{
	struct nfs_open_context *ctx;

	ctx = alloc_nfs_open_context(filp->f_path.dentry, filp->f_mode);
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);
	nfs_file_set_open_context(filp, ctx);
	put_nfs_open_context(ctx);
	nfs_fscache_open_file(inode, filp);
	return 0;
}

int nfs_release(struct inode *inode, struct file *filp)
{
	nfs_file_clear_open_context(filp);
	return 0;
}

/*
 * This function is called whenever some part of NFS notices that
 * the cached attributes have to be refreshed.
 */
int
__nfs_revalidate_inode(struct nfs_server *server, struct inode *inode)
{
	int		 status = -ESTALE;
	struct nfs4_label *label = NULL;
	struct nfs_fattr *fattr = NULL;
	struct nfs_inode *nfsi = NFS_I(inode);

	dfprintk(PAGECACHE, "NFS: revalidating (%s/%Lu)\n",
		inode->i_sb->s_id, (unsigned long long)NFS_FILEID(inode));

	trace_nfs_revalidate_inode_enter(inode);

	if (is_bad_inode(inode))
		goto out;
	if (NFS_STALE(inode))
		goto out;

	status = -ENOMEM;
	fattr = nfs_alloc_fattr();
	if (fattr == NULL)
		goto out;

	nfs_inc_stats(inode, NFSIOS_INODEREVALIDATE);

	label = nfs4_label_alloc(NFS_SERVER(inode), GFP_KERNEL);
	if (IS_ERR(label)) {
		status = PTR_ERR(label);
		goto out;
	}

	status = NFS_PROTO(inode)->getattr(server, NFS_FH(inode), fattr, label);
	if (status != 0) {
		dfprintk(PAGECACHE, "nfs_revalidate_inode: (%s/%Lu) getattr failed, error=%d\n",
			 inode->i_sb->s_id,
			 (unsigned long long)NFS_FILEID(inode), status);
		if (status == -ESTALE) {
			nfs_zap_caches(inode);
			if (!S_ISDIR(inode->i_mode))
				set_bit(NFS_INO_STALE, &NFS_I(inode)->flags);
		}
		goto err_out;
	}

	status = nfs_refresh_inode(inode, fattr);
	if (status) {
		dfprintk(PAGECACHE, "nfs_revalidate_inode: (%s/%Lu) refresh failed, error=%d\n",
			 inode->i_sb->s_id,
			 (unsigned long long)NFS_FILEID(inode), status);
		goto err_out;
	}

	if (nfsi->cache_validity & NFS_INO_INVALID_ACL)
		nfs_zap_acl_cache(inode);

	nfs_setsecurity(inode, fattr, label);

	dfprintk(PAGECACHE, "NFS: (%s/%Lu) revalidation complete\n",
		inode->i_sb->s_id,
		(unsigned long long)NFS_FILEID(inode));

err_out:
	nfs4_label_free(label);
out:
	nfs_free_fattr(fattr);
	trace_nfs_revalidate_inode_exit(inode, status);
	return status;
}

int nfs_attribute_timeout(struct inode *inode)
{
	struct nfs_inode *nfsi = NFS_I(inode);

	return !time_in_range_open(jiffies, nfsi->read_cache_jiffies, nfsi->read_cache_jiffies + nfsi->attrtimeo);
}

int nfs_attribute_cache_expired(struct inode *inode)
{
	if (nfs_have_delegated_attributes(inode))
		return 0;
	return nfs_attribute_timeout(inode);
}

/**
 * nfs_revalidate_inode - Revalidate the inode attributes
 * @server - pointer to nfs_server struct
 * @inode - pointer to inode struct
 *
 * Updates inode attribute information by retrieving the data from the server.
 */
int nfs_revalidate_inode(struct nfs_server *server, struct inode *inode)
{
	if (!nfs_need_revalidate_inode(inode))
		return NFS_STALE(inode) ? -ESTALE : 0;
	return __nfs_revalidate_inode(server, inode);
}
EXPORT_SYMBOL_GPL(nfs_revalidate_inode);

int nfs_revalidate_inode_rcu(struct nfs_server *server, struct inode *inode)
{
	if (!(NFS_I(inode)->cache_validity &
			(NFS_INO_INVALID_ATTR|NFS_INO_INVALID_LABEL))
			&& !nfs_attribute_cache_expired(inode))
		return NFS_STALE(inode) ? -ESTALE : 0;
	return -ECHILD;
}

static int nfs_invalidate_mapping(struct inode *inode, struct address_space *mapping)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	int ret;

	if (mapping->nrpages != 0) {
		if (S_ISREG(inode->i_mode)) {
			ret = nfs_sync_mapping(mapping);
			if (ret < 0)
				return ret;
		}
		ret = invalidate_inode_pages2(mapping);
		if (ret < 0)
			return ret;
	}
	if (S_ISDIR(inode->i_mode)) {
		spin_lock(&inode->i_lock);
		memset(nfsi->cookieverf, 0, sizeof(nfsi->cookieverf));
		spin_unlock(&inode->i_lock);
	}
	nfs_inc_stats(inode, NFSIOS_DATAINVALIDATE);
	nfs_fscache_wait_on_invalidate(inode);

	dfprintk(PAGECACHE, "NFS: (%s/%Lu) data cache invalidated\n",
			inode->i_sb->s_id,
			(unsigned long long)NFS_FILEID(inode));
	return 0;
}

static bool nfs_mapping_need_revalidate_inode(struct inode *inode)
{
	if (nfs_have_delegated_attributes(inode))
		return false;
	return (NFS_I(inode)->cache_validity & NFS_INO_REVAL_PAGECACHE)
		|| nfs_attribute_timeout(inode)
		|| NFS_STALE(inode);
}

/**
 * nfs_revalidate_mapping - Revalidate the pagecache
 * @inode - pointer to host inode
 * @mapping - pointer to mapping
 */
int nfs_revalidate_mapping(struct inode *inode, struct address_space *mapping)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	unsigned long *bitlock = &nfsi->flags;
	int ret = 0;

	/* swapfiles are not supposed to be shared. */
	if (IS_SWAPFILE(inode))
		goto out;

	if (nfs_mapping_need_revalidate_inode(inode)) {
		ret = __nfs_revalidate_inode(NFS_SERVER(inode), inode);
		if (ret < 0)
			goto out;
	}

	/*
	 * We must clear NFS_INO_INVALID_DATA first to ensure that
	 * invalidations that come in while we're shooting down the mappings
	 * are respected. But, that leaves a race window where one revalidator
	 * can clear the flag, and then another checks it before the mapping
	 * gets invalidated. Fix that by serializing access to this part of
	 * the function.
	 *
	 * At the same time, we need to allow other tasks to see whether we
	 * might be in the middle of invalidating the pages, so we only set
	 * the bit lock here if it looks like we're going to be doing that.
	 */
	for (;;) {
		ret = wait_on_bit_action(bitlock, NFS_INO_INVALIDATING,
					 nfs_wait_bit_killable, TASK_KILLABLE);
		if (ret)
			goto out;
		spin_lock(&inode->i_lock);
		if (test_bit(NFS_INO_INVALIDATING, bitlock)) {
			spin_unlock(&inode->i_lock);
			continue;
		}
		if (nfsi->cache_validity & NFS_INO_INVALID_DATA)
			break;
		spin_unlock(&inode->i_lock);
		goto out;
	}

	set_bit(NFS_INO_INVALIDATING, bitlock);
	smp_wmb();
	nfsi->cache_validity &= ~NFS_INO_INVALID_DATA;
	spin_unlock(&inode->i_lock);
	trace_nfs_invalidate_mapping_enter(inode);
	ret = nfs_invalidate_mapping(inode, mapping);
	trace_nfs_invalidate_mapping_exit(inode, ret);

	clear_bit_unlock(NFS_INO_INVALIDATING, bitlock);
	smp_mb__after_atomic();
	wake_up_bit(bitlock, NFS_INO_INVALIDATING);
out:
	return ret;
}

static unsigned long nfs_wcc_update_inode(struct inode *inode, struct nfs_fattr *fattr)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	unsigned long ret = 0;

	if ((fattr->valid & NFS_ATTR_FATTR_PRECHANGE)
			&& (fattr->valid & NFS_ATTR_FATTR_CHANGE)
			&& inode->i_version == fattr->pre_change_attr) {
		inode->i_version = fattr->change_attr;
		if (S_ISDIR(inode->i_mode))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_DATA);
		ret |= NFS_INO_INVALID_ATTR;
	}
	/* If we have atomic WCC data, we may update some attributes */
	if ((fattr->valid & NFS_ATTR_FATTR_PRECTIME)
			&& (fattr->valid & NFS_ATTR_FATTR_CTIME)
			&& timespec_equal(&inode->i_ctime, &fattr->pre_ctime)) {
		memcpy(&inode->i_ctime, &fattr->ctime, sizeof(inode->i_ctime));
		ret |= NFS_INO_INVALID_ATTR;
	}

	if ((fattr->valid & NFS_ATTR_FATTR_PREMTIME)
			&& (fattr->valid & NFS_ATTR_FATTR_MTIME)
			&& timespec_equal(&inode->i_mtime, &fattr->pre_mtime)) {
		memcpy(&inode->i_mtime, &fattr->mtime, sizeof(inode->i_mtime));
		if (S_ISDIR(inode->i_mode))
			nfs_set_cache_invalid(inode, NFS_INO_INVALID_DATA);
		ret |= NFS_INO_INVALID_ATTR;
	}
	if ((fattr->valid & NFS_ATTR_FATTR_PRESIZE)
			&& (fattr->valid & NFS_ATTR_FATTR_SIZE)
			&& i_size_read(inode) == nfs_size_to_loff_t(fattr->pre_size)
			&& nfsi->npages == 0) {
		i_size_write(inode, nfs_size_to_loff_t(fattr->size));
		ret |= NFS_INO_INVALID_ATTR;
	}

	return ret;
}

/**
 * nfs_check_inode_attributes - verify consistency of the inode attribute cache
 * @inode - pointer to inode
 * @fattr - updated attributes
 *
 * Verifies the attribute cache. If we have just changed the attributes,
 * so that fattr carries weak cache consistency data, then it may
 * also update the ctime/mtime/change_attribute.
 */
static int nfs_check_inode_attributes(struct inode *inode, struct nfs_fattr *fattr)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	loff_t cur_size, new_isize;
	unsigned long invalid = 0;


	if (nfs_have_delegated_attributes(inode))
		return 0;
	/* Has the inode gone and changed behind our back? */
	if ((fattr->valid & NFS_ATTR_FATTR_FILEID) && nfsi->fileid != fattr->fileid)
		return -EIO;
	if ((fattr->valid & NFS_ATTR_FATTR_TYPE) && (inode->i_mode & S_IFMT) != (fattr->mode & S_IFMT))
		return -EIO;

	if ((fattr->valid & NFS_ATTR_FATTR_CHANGE) != 0 &&
			inode->i_version != fattr->change_attr)
		invalid |= NFS_INO_INVALID_ATTR|NFS_INO_REVAL_PAGECACHE;

	/* Verify a few of the more important attributes */
	if ((fattr->valid & NFS_ATTR_FATTR_MTIME) && !timespec_equal(&inode->i_mtime, &fattr->mtime))
		invalid |= NFS_INO_INVALID_ATTR;

	if (fattr->valid & NFS_ATTR_FATTR_SIZE) {
		cur_size = i_size_read(inode);
		new_isize = nfs_size_to_loff_t(fattr->size);
		if (cur_size != new_isize && nfsi->npages == 0)
			invalid |= NFS_INO_INVALID_ATTR|NFS_INO_REVAL_PAGECACHE;
	}

	/* Have any file permissions changed? */
	if ((fattr->valid & NFS_ATTR_FATTR_MODE) && (inode->i_mode & S_IALLUGO) != (fattr->mode & S_IALLUGO))
		invalid |= NFS_INO_INVALID_ATTR | NFS_INO_INVALID_ACCESS | NFS_INO_INVALID_ACL;
	if ((fattr->valid & NFS_ATTR_FATTR_OWNER) && !uid_eq(inode->i_uid, fattr->uid))
		invalid |= NFS_INO_INVALID_ATTR | NFS_INO_INVALID_ACCESS | NFS_INO_INVALID_ACL;
	if ((fattr->valid & NFS_ATTR_FATTR_GROUP) && !gid_eq(inode->i_gid, fattr->gid))
		invalid |= NFS_INO_INVALID_ATTR | NFS_INO_INVALID_ACCESS | NFS_INO_INVALID_ACL;

	/* Has the link count changed? */
	if ((fattr->valid & NFS_ATTR_FATTR_NLINK) && inode->i_nlink != fattr->nlink)
		invalid |= NFS_INO_INVALID_ATTR;

	if ((fattr->valid & NFS_ATTR_FATTR_ATIME) && !timespec_equal(&inode->i_atime, &fattr->atime))
		invalid |= NFS_INO_INVALID_ATIME;

	if (invalid != 0)
		nfs_set_cache_invalid(inode, invalid);

	nfsi->read_cache_jiffies = fattr->time_start;
	return 0;
}

static int nfs_ctime_need_update(const struct inode *inode, const struct nfs_fattr *fattr)
{
	if (!(fattr->valid & NFS_ATTR_FATTR_CTIME))
		return 0;
	return timespec_compare(&fattr->ctime, &inode->i_ctime) > 0;
}

static int nfs_size_need_update(const struct inode *inode, const struct nfs_fattr *fattr)
{
	if (!(fattr->valid & NFS_ATTR_FATTR_SIZE))
		return 0;
	return nfs_size_to_loff_t(fattr->size) > i_size_read(inode);
}

static atomic_long_t nfs_attr_generation_counter;

static unsigned long nfs_read_attr_generation_counter(void)
{
	return atomic_long_read(&nfs_attr_generation_counter);
}

unsigned long nfs_inc_attr_generation_counter(void)
{
	return atomic_long_inc_return(&nfs_attr_generation_counter);
}

void nfs_fattr_init(struct nfs_fattr *fattr)
{
	fattr->valid = 0;
	fattr->time_start = jiffies;
	fattr->gencount = nfs_inc_attr_generation_counter();
	fattr->owner_name = NULL;
	fattr->group_name = NULL;
}
EXPORT_SYMBOL_GPL(nfs_fattr_init);

struct nfs_fattr *nfs_alloc_fattr(void)
{
	struct nfs_fattr *fattr;

	fattr = kmalloc(sizeof(*fattr), GFP_NOFS);
	if (fattr != NULL)
		nfs_fattr_init(fattr);
	return fattr;
}
EXPORT_SYMBOL_GPL(nfs_alloc_fattr);

struct nfs_fh *nfs_alloc_fhandle(void)
{
	struct nfs_fh *fh;

	fh = kmalloc(sizeof(struct nfs_fh), GFP_NOFS);
	if (fh != NULL)
		fh->size = 0;
	return fh;
}
EXPORT_SYMBOL_GPL(nfs_alloc_fhandle);

#ifdef NFS_DEBUG
/*
 * _nfs_display_fhandle_hash - calculate the crc32 hash for the filehandle
 *                             in the same way that wireshark does
 *
 * @fh: file handle
 *
 * For debugging only.
 */
u32 _nfs_display_fhandle_hash(const struct nfs_fh *fh)
{
	/* wireshark uses 32-bit AUTODIN crc and does a bitwise
	 * not on the result */
	return nfs_fhandle_hash(fh);
}
EXPORT_SYMBOL_GPL(_nfs_display_fhandle_hash);

/*
 * _nfs_display_fhandle - display an NFS file handle on the console
 *
 * @fh: file handle to display
 * @caption: display caption
 *
 * For debugging only.
 */
void _nfs_display_fhandle(const struct nfs_fh *fh, const char *caption)
{
	unsigned short i;

	if (fh == NULL || fh->size == 0) {
		printk(KERN_DEFAULT "%s at %p is empty\n", caption, fh);
		return;
	}

	printk(KERN_DEFAULT "%s at %p is %u bytes, crc: 0x%08x:\n",
	       caption, fh, fh->size, _nfs_display_fhandle_hash(fh));
	for (i = 0; i < fh->size; i += 16) {
		__be32 *pos = (__be32 *)&fh->data[i];

		switch ((fh->size - i - 1) >> 2) {
		case 0:
			printk(KERN_DEFAULT " %08x\n",
				be32_to_cpup(pos));
			break;
		case 1:
			printk(KERN_DEFAULT " %08x %08x\n",
				be32_to_cpup(pos), be32_to_cpup(pos + 1));
			break;
		case 2:
			printk(KERN_DEFAULT " %08x %08x %08x\n",
				be32_to_cpup(pos), be32_to_cpup(pos + 1),
				be32_to_cpup(pos + 2));
			break;
		default:
			printk(KERN_DEFAULT " %08x %08x %08x %08x\n",
				be32_to_cpup(pos), be32_to_cpup(pos + 1),
				be32_to_cpup(pos + 2), be32_to_cpup(pos + 3));
		}
	}
}
EXPORT_SYMBOL_GPL(_nfs_display_fhandle);
#endif

/**
 * nfs_inode_attrs_need_update - check if the inode attributes need updating
 * @inode - pointer to inode
 * @fattr - attributes
 *
 * Attempt to divine whether or not an RPC call reply carrying stale
 * attributes got scheduled after another call carrying updated ones.
 *
 * To do so, the function first assumes that a more recent ctime means
 * that the attributes in fattr are newer, however it also attempt to
 * catch the case where ctime either didn't change, or went backwards
 * (if someone reset the clock on the server) by looking at whether
 * or not this RPC call was started after the inode was last updated.
 * Note also the check for wraparound of 'attr_gencount'
 *
 * The function returns 'true' if it thinks the attributes in 'fattr' are
 * more recent than the ones cached in the inode.
 *
 */
static int nfs_inode_attrs_need_update(const struct inode *inode, const struct nfs_fattr *fattr)
{
	const struct nfs_inode *nfsi = NFS_I(inode);

	return ((long)fattr->gencount - (long)nfsi->attr_gencount) > 0 ||
		nfs_ctime_need_update(inode, fattr) ||
		nfs_size_need_update(inode, fattr) ||
		((long)nfsi->attr_gencount - (long)nfs_read_attr_generation_counter() > 0);
}

/*
 * Don't trust the change_attribute, mtime, ctime or size if
 * a pnfs LAYOUTCOMMIT is outstanding
 */
static void nfs_inode_attrs_handle_layoutcommit(struct inode *inode,
		struct nfs_fattr *fattr)
{
	if (pnfs_layoutcommit_outstanding(inode))
		fattr->valid &= ~(NFS_ATTR_FATTR_CHANGE |
				NFS_ATTR_FATTR_MTIME |
				NFS_ATTR_FATTR_CTIME |
				NFS_ATTR_FATTR_SIZE);
}

static int nfs_refresh_inode_locked(struct inode *inode, struct nfs_fattr *fattr)
{
	int ret;

	trace_nfs_refresh_inode_enter(inode);

	nfs_inode_attrs_handle_layoutcommit(inode, fattr);

	if (nfs_inode_attrs_need_update(inode, fattr))
		ret = nfs_update_inode(inode, fattr);
	else
		ret = nfs_check_inode_attributes(inode, fattr);

	trace_nfs_refresh_inode_exit(inode, ret);
	return ret;
}

/**
 * nfs_refresh_inode - try to update the inode attribute cache
 * @inode - pointer to inode
 * @fattr - updated attributes
 *
 * Check that an RPC call that returned attributes has not overlapped with
 * other recent updates of the inode metadata, then decide whether it is
 * safe to do a full update of the inode attributes, or whether just to
 * call nfs_check_inode_attributes.
 */
int nfs_refresh_inode(struct inode *inode, struct nfs_fattr *fattr)
{
	int status;

	if ((fattr->valid & NFS_ATTR_FATTR) == 0)
		return 0;
	spin_lock(&inode->i_lock);
	status = nfs_refresh_inode_locked(inode, fattr);
	spin_unlock(&inode->i_lock);

	return status;
}
EXPORT_SYMBOL_GPL(nfs_refresh_inode);

static int nfs_post_op_update_inode_locked(struct inode *inode, struct nfs_fattr *fattr)
{
	unsigned long invalid = NFS_INO_INVALID_ATTR|NFS_INO_REVAL_PAGECACHE;

	if (S_ISDIR(inode->i_mode))
		invalid |= NFS_INO_INVALID_DATA;
	nfs_set_cache_invalid(inode, invalid);
	if ((fattr->valid & NFS_ATTR_FATTR) == 0)
		return 0;
	return nfs_refresh_inode_locked(inode, fattr);
}

/**
 * nfs_post_op_update_inode - try to update the inode attribute cache
 * @inode - pointer to inode
 * @fattr - updated attributes
 *
 * After an operation that has changed the inode metadata, mark the
 * attribute cache as being invalid, then try to update it.
 *
 * NB: if the server didn't return any post op attributes, this
 * function will force the retrieval of attributes before the next
 * NFS request.  Thus it should be used only for operations that
 * are expected to change one or more attributes, to avoid
 * unnecessary NFS requests and trips through nfs_update_inode().
 */
int nfs_post_op_update_inode(struct inode *inode, struct nfs_fattr *fattr)
{
	int status;

	spin_lock(&inode->i_lock);
	status = nfs_post_op_update_inode_locked(inode, fattr);
	spin_unlock(&inode->i_lock);

	return status;
}
EXPORT_SYMBOL_GPL(nfs_post_op_update_inode);

/**
 * nfs_post_op_update_inode_force_wcc - try to update the inode attribute cache
 * @inode - pointer to inode
 * @fattr - updated attributes
 *
 * After an operation that has changed the inode metadata, mark the
 * attribute cache as being invalid, then try to update it. Fake up
 * weak cache consistency data, if none exist.
 *
 * This function is mainly designed to be used by the ->write_done() functions.
 */
int nfs_post_op_update_inode_force_wcc(struct inode *inode, struct nfs_fattr *fattr)
{
	int status;

	spin_lock(&inode->i_lock);
	/* Don't do a WCC update if these attributes are already stale */
	if ((fattr->valid & NFS_ATTR_FATTR) == 0 ||
			!nfs_inode_attrs_need_update(inode, fattr)) {
		fattr->valid &= ~(NFS_ATTR_FATTR_PRECHANGE
				| NFS_ATTR_FATTR_PRESIZE
				| NFS_ATTR_FATTR_PREMTIME
				| NFS_ATTR_FATTR_PRECTIME);
		goto out_noforce;
	}
	if ((fattr->valid & NFS_ATTR_FATTR_CHANGE) != 0 &&
			(fattr->valid & NFS_ATTR_FATTR_PRECHANGE) == 0) {
		fattr->pre_change_attr = inode->i_version;
		fattr->valid |= NFS_ATTR_FATTR_PRECHANGE;
	}
	if ((fattr->valid & NFS_ATTR_FATTR_CTIME) != 0 &&
			(fattr->valid & NFS_ATTR_FATTR_PRECTIME) == 0) {
		memcpy(&fattr->pre_ctime, &inode->i_ctime, sizeof(fattr->pre_ctime));
		fattr->valid |= NFS_ATTR_FATTR_PRECTIME;
	}
	if ((fattr->valid & NFS_ATTR_FATTR_MTIME) != 0 &&
			(fattr->valid & NFS_ATTR_FATTR_PREMTIME) == 0) {
		memcpy(&fattr->pre_mtime, &inode->i_mtime, sizeof(fattr->pre_mtime));
		fattr->valid |= NFS_ATTR_FATTR_PREMTIME;
	}
	if ((fattr->valid & NFS_ATTR_FATTR_SIZE) != 0 &&
			(fattr->valid & NFS_ATTR_FATTR_PRESIZE) == 0) {
		fattr->pre_size = i_size_read(inode);
		fattr->valid |= NFS_ATTR_FATTR_PRESIZE;
	}
out_noforce:
	status = nfs_post_op_update_inode_locked(inode, fattr);
	spin_unlock(&inode->i_lock);
	return status;
}
EXPORT_SYMBOL_GPL(nfs_post_op_update_inode_force_wcc);

/*
 * Many nfs protocol calls return the new file attributes after
 * an operation.  Here we update the inode to reflect the state
 * of the server's inode.
 *
 * This is a bit tricky because we have to make sure all dirty pages
 * have been sent off to the server before calling invalidate_inode_pages.
 * To make sure no other process adds more write requests while we try
 * our best to flush them, we make them sleep during the attribute refresh.
 *
 * A very similar scenario holds for the dir cache.
 */
static int nfs_update_inode(struct inode *inode, struct nfs_fattr *fattr)
{
	struct nfs_server *server;
	struct nfs_inode *nfsi = NFS_I(inode);
	loff_t cur_isize, new_isize;
	unsigned long invalid = 0;
	unsigned long now = jiffies;
	unsigned long save_cache_validity;

	dfprintk(VFS, "NFS: %s(%s/%lu fh_crc=0x%08x ct=%d info=0x%x)\n",
			__func__, inode->i_sb->s_id, inode->i_ino,
			nfs_display_fhandle_hash(NFS_FH(inode)),
			atomic_read(&inode->i_count), fattr->valid);

	if ((fattr->valid & NFS_ATTR_FATTR_FILEID) && nfsi->fileid != fattr->fileid) {
		printk(KERN_ERR "NFS: server %s error: fileid changed\n"
			"fsid %s: expected fileid 0x%Lx, got 0x%Lx\n",
			NFS_SERVER(inode)->nfs_client->cl_hostname,
			inode->i_sb->s_id, (long long)nfsi->fileid,
			(long long)fattr->fileid);
		goto out_err;
	}

	/*
	 * Make sure the inode's type hasn't changed.
	 */
	if ((fattr->valid & NFS_ATTR_FATTR_TYPE) && (inode->i_mode & S_IFMT) != (fattr->mode & S_IFMT)) {
		/*
		* Big trouble! The inode has become a different object.
		*/
		printk(KERN_DEBUG "NFS: %s: inode %lu mode changed, %07o to %07o\n",
				__func__, inode->i_ino, inode->i_mode, fattr->mode);
		goto out_err;
	}

	server = NFS_SERVER(inode);
	/* Update the fsid? */
	if (S_ISDIR(inode->i_mode) && (fattr->valid & NFS_ATTR_FATTR_FSID) &&
			!nfs_fsid_equal(&server->fsid, &fattr->fsid) &&
			!IS_AUTOMOUNT(inode))
		server->fsid = fattr->fsid;

	/*
	 * Update the read time so we don't revalidate too often.
	 */
	nfsi->read_cache_jiffies = fattr->time_start;

	save_cache_validity = nfsi->cache_validity;
	nfsi->cache_validity &= ~(NFS_INO_INVALID_ATTR
			| NFS_INO_INVALID_ATIME
			| NFS_INO_REVAL_FORCED
			| NFS_INO_REVAL_PAGECACHE);

	/* Do atomic weak cache consistency updates */
	invalid |= nfs_wcc_update_inode(inode, fattr);

	/* More cache consistency checks */
	if (fattr->valid & NFS_ATTR_FATTR_CHANGE) {
		if (inode->i_version != fattr->change_attr) {
			dprintk("NFS: change_attr change on server for file %s/%ld\n",
					inode->i_sb->s_id, inode->i_ino);
			invalid |= NFS_INO_INVALID_ATTR
				| NFS_INO_INVALID_DATA
				| NFS_INO_INVALID_ACCESS
				| NFS_INO_INVALID_ACL
				| NFS_INO_REVAL_PAGECACHE;
			if (S_ISDIR(inode->i_mode))
				nfs_force_lookup_revalidate(inode);
			inode->i_version = fattr->change_attr;
		}
	} else if (server->caps & NFS_CAP_CHANGE_ATTR)
		nfsi->cache_validity |= save_cache_validity;

	if (fattr->valid & NFS_ATTR_FATTR_MTIME) {
		memcpy(&inode->i_mtime, &fattr->mtime, sizeof(inode->i_mtime));
	} else if (server->caps & NFS_CAP_MTIME)
		nfsi->cache_validity |= save_cache_validity &
				(NFS_INO_INVALID_ATTR
				| NFS_INO_REVAL_FORCED);

	if (fattr->valid & NFS_ATTR_FATTR_CTIME) {
		memcpy(&inode->i_ctime, &fattr->ctime, sizeof(inode->i_ctime));
	} else if (server->caps & NFS_CAP_CTIME)
		nfsi->cache_validity |= save_cache_validity &
				(NFS_INO_INVALID_ATTR
				| NFS_INO_REVAL_FORCED);

	/* Check if our cached file size is stale */
	if (fattr->valid & NFS_ATTR_FATTR_SIZE) {
		new_isize = nfs_size_to_loff_t(fattr->size);
		cur_isize = i_size_read(inode);
		if (new_isize != cur_isize) {
			/* Do we perhaps have any outstanding writes, or has
			 * the file grown beyond our last write? */
			if ((nfsi->npages == 0) || new_isize > cur_isize) {
				i_size_write(inode, new_isize);
				invalid |= NFS_INO_INVALID_ATTR|NFS_INO_INVALID_DATA;
				invalid &= ~NFS_INO_REVAL_PAGECACHE;
			}
			dprintk("NFS: isize change on server for file %s/%ld "
					"(%Ld to %Ld)\n",
					inode->i_sb->s_id,
					inode->i_ino,
					(long long)cur_isize,
					(long long)new_isize);
		}
	} else
		nfsi->cache_validity |= save_cache_validity &
				(NFS_INO_INVALID_ATTR
				| NFS_INO_REVAL_PAGECACHE
				| NFS_INO_REVAL_FORCED);


	if (fattr->valid & NFS_ATTR_FATTR_ATIME)
		memcpy(&inode->i_atime, &fattr->atime, sizeof(inode->i_atime));
	else if (server->caps & NFS_CAP_ATIME)
		nfsi->cache_validity |= save_cache_validity &
				(NFS_INO_INVALID_ATIME
				| NFS_INO_REVAL_FORCED);

	if (fattr->valid & NFS_ATTR_FATTR_MODE) {
		if ((inode->i_mode & S_IALLUGO) != (fattr->mode & S_IALLUGO)) {
			umode_t newmode = inode->i_mode & S_IFMT;
			newmode |= fattr->mode & S_IALLUGO;
			inode->i_mode = newmode;
			invalid |= NFS_INO_INVALID_ATTR|NFS_INO_INVALID_ACCESS|NFS_INO_INVALID_ACL;
		}
	} else if (server->caps & NFS_CAP_MODE)
		nfsi->cache_validity |= save_cache_validity &
				(NFS_INO_INVALID_ATTR
				| NFS_INO_INVALID_ACCESS
				| NFS_INO_INVALID_ACL
				| NFS_INO_REVAL_FORCED);

	if (fattr->valid & NFS_ATTR_FATTR_OWNER) {
		if (!uid_eq(inode->i_uid, fattr->uid)) {
			invalid |= NFS_INO_INVALID_ATTR|NFS_INO_INVALID_ACCESS|NFS_INO_INVALID_ACL;
			inode->i_uid = fattr->uid;
		}
	} else if (server->caps & NFS_CAP_OWNER)
		nfsi->cache_validity |= save_cache_validity &
				(NFS_INO_INVALID_ATTR
				| NFS_INO_INVALID_ACCESS
				| NFS_INO_INVALID_ACL
				| NFS_INO_REVAL_FORCED);

	if (fattr->valid & NFS_ATTR_FATTR_GROUP) {
		if (!gid_eq(inode->i_gid, fattr->gid)) {
			invalid |= NFS_INO_INVALID_ATTR|NFS_INO_INVALID_ACCESS|NFS_INO_INVALID_ACL;
			inode->i_gid = fattr->gid;
		}
	} else if (server->caps & NFS_CAP_OWNER_GROUP)
		nfsi->cache_validity |= save_cache_validity &
				(NFS_INO_INVALID_ATTR
				| NFS_INO_INVALID_ACCESS
				| NFS_INO_INVALID_ACL
				| NFS_INO_REVAL_FORCED);

	if (fattr->valid & NFS_ATTR_FATTR_NLINK) {
		if (inode->i_nlink != fattr->nlink) {
			invalid |= NFS_INO_INVALID_ATTR;
			if (S_ISDIR(inode->i_mode))
				invalid |= NFS_INO_INVALID_DATA;
			set_nlink(inode, fattr->nlink);
		}
	} else if (server->caps & NFS_CAP_NLINK)
		nfsi->cache_validity |= save_cache_validity &
				(NFS_INO_INVALID_ATTR
				| NFS_INO_REVAL_FORCED);

	if (fattr->valid & NFS_ATTR_FATTR_SPACE_USED) {
		/*
		 * report the blocks in 512byte units
		 */
		inode->i_blocks = nfs_calc_block_size(fattr->du.nfs3.used);
 	}
	if (fattr->valid & NFS_ATTR_FATTR_BLOCKS_USED)
		inode->i_blocks = fattr->du.nfs2.blocks;

	/* Update attrtimeo value if we're out of the unstable period */
	if (invalid & NFS_INO_INVALID_ATTR) {
		nfs_inc_stats(inode, NFSIOS_ATTRINVALIDATE);
		nfsi->attrtimeo = NFS_MINATTRTIMEO(inode);
		nfsi->attrtimeo_timestamp = now;
		nfsi->attr_gencount = nfs_inc_attr_generation_counter();
	} else {
		if (!time_in_range_open(now, nfsi->attrtimeo_timestamp, nfsi->attrtimeo_timestamp + nfsi->attrtimeo)) {
			if ((nfsi->attrtimeo <<= 1) > NFS_MAXATTRTIMEO(inode))
				nfsi->attrtimeo = NFS_MAXATTRTIMEO(inode);
			nfsi->attrtimeo_timestamp = now;
		}
	}
	invalid &= ~NFS_INO_INVALID_ATTR;
	/* Don't invalidate the data if we were to blame */
	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode)
				|| S_ISLNK(inode->i_mode)))
		invalid &= ~NFS_INO_INVALID_DATA;
	if (!NFS_PROTO(inode)->have_delegation(inode, FMODE_READ) ||
			(save_cache_validity & NFS_INO_REVAL_FORCED))
		nfs_set_cache_invalid(inode, invalid);

	return 0;
 out_err:
	/*
	 * No need to worry about unhashing the dentry, as the
	 * lookup validation will know that the inode is bad.
	 * (But we fall through to invalidate the caches.)
	 */
	nfs_invalidate_inode(inode);
	return -ESTALE;
}

struct inode *nfs_alloc_inode(struct super_block *sb)
{
	struct nfs_inode *nfsi;
	nfsi = (struct nfs_inode *)kmem_cache_alloc(nfs_inode_cachep, GFP_KERNEL);
	if (!nfsi)
		return NULL;
	nfsi->flags = 0UL;
	nfsi->cache_validity = 0UL;
#if IS_ENABLED(CONFIG_NFS_V4)
	nfsi->nfs4_acl = NULL;
#endif /* CONFIG_NFS_V4 */
	return &nfsi->vfs_inode;
}
EXPORT_SYMBOL_GPL(nfs_alloc_inode);

static void nfs_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	kmem_cache_free(nfs_inode_cachep, NFS_I(inode));
}

void nfs_destroy_inode(struct inode *inode)
{
	call_rcu(&inode->i_rcu, nfs_i_callback);
}
EXPORT_SYMBOL_GPL(nfs_destroy_inode);

static inline void nfs4_init_once(struct nfs_inode *nfsi)
{
#if IS_ENABLED(CONFIG_NFS_V4)
	INIT_LIST_HEAD(&nfsi->open_states);
	nfsi->delegation = NULL;
	nfsi->delegation_state = 0;
	init_rwsem(&nfsi->rwsem);
	nfsi->layout = NULL;
#endif
}

static void init_once(void *foo)
{
	struct nfs_inode *nfsi = (struct nfs_inode *) foo;

	inode_init_once(&nfsi->vfs_inode);
	INIT_LIST_HEAD(&nfsi->open_files);
	INIT_LIST_HEAD(&nfsi->access_cache_entry_lru);
	INIT_LIST_HEAD(&nfsi->access_cache_inode_lru);
	INIT_LIST_HEAD(&nfsi->commit_info.list);
	nfsi->npages = 0;
	nfsi->commit_info.ncommit = 0;
	atomic_set(&nfsi->commit_info.rpcs_out, 0);
	atomic_set(&nfsi->silly_count, 1);
	INIT_HLIST_HEAD(&nfsi->silly_list);
	init_waitqueue_head(&nfsi->waitqueue);
	nfs4_init_once(nfsi);
}

static int __init nfs_init_inodecache(void)
{
	nfs_inode_cachep = kmem_cache_create("nfs_inode_cache",
					     sizeof(struct nfs_inode),
					     0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					     init_once);
	if (nfs_inode_cachep == NULL)
		return -ENOMEM;

	return 0;
}

static void nfs_destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(nfs_inode_cachep);
}

struct workqueue_struct *nfsiod_workqueue;
EXPORT_SYMBOL_GPL(nfsiod_workqueue);

/*
 * start up the nfsiod workqueue
 */
static int nfsiod_start(void)
{
	struct workqueue_struct *wq;
	dprintk("RPC:       creating workqueue nfsiod\n");
	wq = alloc_workqueue("nfsiod", WQ_MEM_RECLAIM, 0);
	if (wq == NULL)
		return -ENOMEM;
	nfsiod_workqueue = wq;
	return 0;
}

/*
 * Destroy the nfsiod workqueue
 */
static void nfsiod_stop(void)
{
	struct workqueue_struct *wq;

	wq = nfsiod_workqueue;
	if (wq == NULL)
		return;
	nfsiod_workqueue = NULL;
	destroy_workqueue(wq);
}

int nfs_net_id;
EXPORT_SYMBOL_GPL(nfs_net_id);

static int nfs_net_init(struct net *net)
{
	nfs_clients_init(net);
	return nfs_fs_proc_net_init(net);
}

static void nfs_net_exit(struct net *net)
{
	nfs_fs_proc_net_exit(net);
	nfs_cleanup_cb_ident_idr(net);
}

static struct pernet_operations nfs_net_ops = {
	.init = nfs_net_init,
	.exit = nfs_net_exit,
	.id   = &nfs_net_id,
	.size = sizeof(struct nfs_net),
};

/*
 * Initialize NFS
 */
static int __init init_nfs_fs(void)
{
	int err;

	err = register_pernet_subsys(&nfs_net_ops);
	if (err < 0)
		goto out9;

	err = nfs_fscache_register();
	if (err < 0)
		goto out8;

	err = nfsiod_start();
	if (err)
		goto out7;

	err = nfs_fs_proc_init();
	if (err)
		goto out6;

	err = nfs_init_nfspagecache();
	if (err)
		goto out5;

	err = nfs_init_inodecache();
	if (err)
		goto out4;

	err = nfs_init_readpagecache();
	if (err)
		goto out3;

	err = nfs_init_writepagecache();
	if (err)
		goto out2;

	err = nfs_init_directcache();
	if (err)
		goto out1;

#ifdef CONFIG_PROC_FS
	rpc_proc_register(&init_net, &nfs_rpcstat);
#endif
	if ((err = register_nfs_fs()) != 0)
		goto out0;

	return 0;
out0:
#ifdef CONFIG_PROC_FS
	rpc_proc_unregister(&init_net, "nfs");
#endif
	nfs_destroy_directcache();
out1:
	nfs_destroy_writepagecache();
out2:
	nfs_destroy_readpagecache();
out3:
	nfs_destroy_inodecache();
out4:
	nfs_destroy_nfspagecache();
out5:
	nfs_fs_proc_exit();
out6:
	nfsiod_stop();
out7:
	nfs_fscache_unregister();
out8:
	unregister_pernet_subsys(&nfs_net_ops);
out9:
	return err;
}

static void __exit exit_nfs_fs(void)
{
	nfs_destroy_directcache();
	nfs_destroy_writepagecache();
	nfs_destroy_readpagecache();
	nfs_destroy_inodecache();
	nfs_destroy_nfspagecache();
	nfs_fscache_unregister();
	unregister_pernet_subsys(&nfs_net_ops);
#ifdef CONFIG_PROC_FS
	rpc_proc_unregister(&init_net, "nfs");
#endif
	unregister_nfs_fs();
	nfs_fs_proc_exit();
	nfsiod_stop();
}

/* Not quite true; I just maintain it */
MODULE_AUTHOR("Olaf Kirch <okir@monad.swb.de>");
MODULE_LICENSE("GPL");
module_param(enable_ino64, bool, 0644);

module_init(init_nfs_fs)
module_exit(exit_nfs_fs)
/************************************************************/
/* ../linux-3.17/fs/nfs/inode.c */
/************************************************************/
/*
 *  linux/fs/nfs/super.c
 *
 *  Copyright (C) 1992  Rick Sladkey
 *
 *  nfs superblock handling functions
 *
 *  Modularised by Alan Cox <alan@lxorguk.ukuu.org.uk>, while hacking some
 *  experimental NFS changes. Modularisation taken straight from SYS5 fs.
 *
 *  Change to nfs_read_super() to permit NFS mounts to multi-homed hosts.
 *  J.S.Peatfield@damtp.cam.ac.uk
 *
 *  Split from inode.c by David Howells <dhowells@redhat.com>
 *
 * - superblocks are indexed on server only - all inodes, dentries, etc. associated with a
 *   particular server are held in the same superblock
 * - NFS superblocks can have several effective roots to the dentry tree
 * - directory type roots are spliced into the tree when a path from one root reaches the root
 *   of another (see nfs_lookup())
 */

// #include <linux/module.h>
// #include <linux/init.h>

// #include <linux/time.h>
// #include <linux/kernel.h>
// #include <linux/mm.h>
// #include <linux/string.h>
// #include <linux/stat.h>
// #include <linux/errno.h>
// #include <linux/unistd.h>
// #include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/addr.h>
// #include <linux/sunrpc/stats.h>
// #include <linux/sunrpc/metrics.h>
// #include <linux/sunrpc/xprtsock.h>
// #include <linux/sunrpc/xprtrdma.h>
// #include <linux/nfs_fs.h>
// #include <linux/nfs_mount.h>
// #include <linux/nfs4_mount.h>
// #include <linux/lockd/bind.h>
// #include <linux/seq_file.h>
// #include <linux/mount.h>
// #include <linux/namei.h>
// #include <linux/nfs_idmap.h>
// #include <linux/vfs.h>
// #include <linux/inet.h>
// #include <linux/in6.h>
// #include <linux/slab.h>
// #include <net/ipv6.h>
#include <linux/netdevice.h>
// #include <linux/nfs_xdr.h>
#include <linux/magic.h>
#include <linux/parser.h>
// #include <linux/nsproxy.h>
#include <linux/rcupdate.h>

// #include <asm/uaccess.h>

// #include "nfs4_fs.h"
// #include "callback.h"
// #include "delegation.h"
// #include "iostat.h"
// #include "internal.h"
// #include "fscache.h"
#include "nfs4session.h"
// #include "pnfs.h"
// #include "nfs.h"

#define NFSDBG_FACILITY		NFSDBG_VFS
#define NFS_TEXT_DATA		1

#if IS_ENABLED(CONFIG_NFS_V3)
#define NFS_DEFAULT_VERSION 3
#else
#define NFS_DEFAULT_VERSION 2
#endif

enum {
	/* Mount options that take no arguments */
	Opt_soft, Opt_hard,
	Opt_posix, Opt_noposix,
	Opt_cto, Opt_nocto,
	Opt_ac, Opt_noac,
	Opt_lock, Opt_nolock,
	Opt_udp, Opt_tcp, Opt_rdma,
	Opt_acl, Opt_noacl,
	Opt_rdirplus, Opt_nordirplus,
	Opt_sharecache, Opt_nosharecache,
	Opt_resvport, Opt_noresvport,
	Opt_fscache, Opt_nofscache,
	Opt_migration, Opt_nomigration,

	/* Mount options that take integer arguments */
	Opt_port,
	Opt_rsize, Opt_wsize, Opt_bsize,
	Opt_timeo, Opt_retrans,
	Opt_acregmin, Opt_acregmax,
	Opt_acdirmin, Opt_acdirmax,
	Opt_actimeo,
	Opt_namelen,
	Opt_mountport,
	Opt_mountvers,
	Opt_minorversion,

	/* Mount options that take string arguments */
	Opt_nfsvers,
	Opt_sec, Opt_proto, Opt_mountproto, Opt_mounthost,
	Opt_addr, Opt_mountaddr, Opt_clientaddr,
	Opt_lookupcache,
	Opt_fscache_uniq,
	Opt_local_lock,

	/* Special mount options */
	Opt_userspace, Opt_deprecated, Opt_sloppy,

	Opt_err
};

static const match_table_t nfs_mount_option_tokens = {
	{ Opt_userspace, "bg" },
	{ Opt_userspace, "fg" },
	{ Opt_userspace, "retry=%s" },

	{ Opt_sloppy, "sloppy" },

	{ Opt_soft, "soft" },
	{ Opt_hard, "hard" },
	{ Opt_deprecated, "intr" },
	{ Opt_deprecated, "nointr" },
	{ Opt_posix, "posix" },
	{ Opt_noposix, "noposix" },
	{ Opt_cto, "cto" },
	{ Opt_nocto, "nocto" },
	{ Opt_ac, "ac" },
	{ Opt_noac, "noac" },
	{ Opt_lock, "lock" },
	{ Opt_nolock, "nolock" },
	{ Opt_udp, "udp" },
	{ Opt_tcp, "tcp" },
	{ Opt_rdma, "rdma" },
	{ Opt_acl, "acl" },
	{ Opt_noacl, "noacl" },
	{ Opt_rdirplus, "rdirplus" },
	{ Opt_nordirplus, "nordirplus" },
	{ Opt_sharecache, "sharecache" },
	{ Opt_nosharecache, "nosharecache" },
	{ Opt_resvport, "resvport" },
	{ Opt_noresvport, "noresvport" },
	{ Opt_fscache, "fsc" },
	{ Opt_nofscache, "nofsc" },
	{ Opt_migration, "migration" },
	{ Opt_nomigration, "nomigration" },

	{ Opt_port, "port=%s" },
	{ Opt_rsize, "rsize=%s" },
	{ Opt_wsize, "wsize=%s" },
	{ Opt_bsize, "bsize=%s" },
	{ Opt_timeo, "timeo=%s" },
	{ Opt_retrans, "retrans=%s" },
	{ Opt_acregmin, "acregmin=%s" },
	{ Opt_acregmax, "acregmax=%s" },
	{ Opt_acdirmin, "acdirmin=%s" },
	{ Opt_acdirmax, "acdirmax=%s" },
	{ Opt_actimeo, "actimeo=%s" },
	{ Opt_namelen, "namlen=%s" },
	{ Opt_mountport, "mountport=%s" },
	{ Opt_mountvers, "mountvers=%s" },
	{ Opt_minorversion, "minorversion=%s" },

	{ Opt_nfsvers, "nfsvers=%s" },
	{ Opt_nfsvers, "vers=%s" },

	{ Opt_sec, "sec=%s" },
	{ Opt_proto, "proto=%s" },
	{ Opt_mountproto, "mountproto=%s" },
	{ Opt_addr, "addr=%s" },
	{ Opt_clientaddr, "clientaddr=%s" },
	{ Opt_mounthost, "mounthost=%s" },
	{ Opt_mountaddr, "mountaddr=%s" },

	{ Opt_lookupcache, "lookupcache=%s" },
	{ Opt_fscache_uniq, "fsc=%s" },
	{ Opt_local_lock, "local_lock=%s" },

	/* The following needs to be listed after all other options */
	{ Opt_nfsvers, "v%s" },

	{ Opt_err, NULL }
};

enum {
	Opt_xprt_udp, Opt_xprt_udp6, Opt_xprt_tcp, Opt_xprt_tcp6, Opt_xprt_rdma,

	Opt_xprt_err
};

static const match_table_t nfs_xprt_protocol_tokens = {
	{ Opt_xprt_udp, "udp" },
	{ Opt_xprt_udp6, "udp6" },
	{ Opt_xprt_tcp, "tcp" },
	{ Opt_xprt_tcp6, "tcp6" },
	{ Opt_xprt_rdma, "rdma" },

	{ Opt_xprt_err, NULL }
};

enum {
	Opt_sec_none, Opt_sec_sys,
	Opt_sec_krb5, Opt_sec_krb5i, Opt_sec_krb5p,
	Opt_sec_lkey, Opt_sec_lkeyi, Opt_sec_lkeyp,
	Opt_sec_spkm, Opt_sec_spkmi, Opt_sec_spkmp,

	Opt_sec_err
};

static const match_table_t nfs_secflavor_tokens = {
	{ Opt_sec_none, "none" },
	{ Opt_sec_none, "null" },
	{ Opt_sec_sys, "sys" },

	{ Opt_sec_krb5, "krb5" },
	{ Opt_sec_krb5i, "krb5i" },
	{ Opt_sec_krb5p, "krb5p" },

	{ Opt_sec_lkey, "lkey" },
	{ Opt_sec_lkeyi, "lkeyi" },
	{ Opt_sec_lkeyp, "lkeyp" },

	{ Opt_sec_spkm, "spkm3" },
	{ Opt_sec_spkmi, "spkm3i" },
	{ Opt_sec_spkmp, "spkm3p" },

	{ Opt_sec_err, NULL }
};

enum {
	Opt_lookupcache_all, Opt_lookupcache_positive,
	Opt_lookupcache_none,

	Opt_lookupcache_err
};

static match_table_t nfs_lookupcache_tokens = {
	{ Opt_lookupcache_all, "all" },
	{ Opt_lookupcache_positive, "pos" },
	{ Opt_lookupcache_positive, "positive" },
	{ Opt_lookupcache_none, "none" },

	{ Opt_lookupcache_err, NULL }
};

enum {
	Opt_local_lock_all, Opt_local_lock_flock, Opt_local_lock_posix,
	Opt_local_lock_none,

	Opt_local_lock_err
};

static match_table_t nfs_local_lock_tokens = {
	{ Opt_local_lock_all, "all" },
	{ Opt_local_lock_flock, "flock" },
	{ Opt_local_lock_posix, "posix" },
	{ Opt_local_lock_none, "none" },

	{ Opt_local_lock_err, NULL }
};

enum {
	Opt_vers_2, Opt_vers_3, Opt_vers_4, Opt_vers_4_0,
	Opt_vers_4_1, Opt_vers_4_2,

	Opt_vers_err
};

static match_table_t nfs_vers_tokens = {
	{ Opt_vers_2, "2" },
	{ Opt_vers_3, "3" },
	{ Opt_vers_4, "4" },
	{ Opt_vers_4_0, "4.0" },
	{ Opt_vers_4_1, "4.1" },
	{ Opt_vers_4_2, "4.2" },

	{ Opt_vers_err, NULL }
};

static struct dentry *nfs_xdev_mount(struct file_system_type *fs_type,
		int flags, const char *dev_name, void *raw_data);

struct file_system_type nfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "nfs",
	.mount		= nfs_fs_mount,
	.kill_sb	= nfs_kill_super,
	.fs_flags	= FS_RENAME_DOES_D_MOVE|FS_BINARY_MOUNTDATA,
};
MODULE_ALIAS_FS("nfs");
EXPORT_SYMBOL_GPL(nfs_fs_type);

struct file_system_type nfs_xdev_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "nfs",
	.mount		= nfs_xdev_mount,
	.kill_sb	= nfs_kill_super,
	.fs_flags	= FS_RENAME_DOES_D_MOVE|FS_BINARY_MOUNTDATA,
};

const struct super_operations nfs_sops = {
	.alloc_inode	= nfs_alloc_inode,
	.destroy_inode	= nfs_destroy_inode,
	.write_inode	= nfs_write_inode,
	.drop_inode	= nfs_drop_inode,
	.put_super	= nfs_put_super,
	.statfs		= nfs_statfs,
	.evict_inode	= nfs_evict_inode,
	.umount_begin	= nfs_umount_begin,
	.show_options	= nfs_show_options,
	.show_devname	= nfs_show_devname,
	.show_path	= nfs_show_path,
	.show_stats	= nfs_show_stats,
	.remount_fs	= nfs_remount,
};
EXPORT_SYMBOL_GPL(nfs_sops);

#if IS_ENABLED(CONFIG_NFS_V4)
static void nfs4_validate_mount_flags(struct nfs_parsed_mount_data *);
static int nfs4_validate_mount_data(void *options,
	struct nfs_parsed_mount_data *args, const char *dev_name);

struct file_system_type nfs4_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "nfs4",
	.mount		= nfs_fs_mount,
	.kill_sb	= nfs_kill_super,
	.fs_flags	= FS_RENAME_DOES_D_MOVE|FS_BINARY_MOUNTDATA,
};
MODULE_ALIAS_FS("nfs4");
MODULE_ALIAS("nfs4");
EXPORT_SYMBOL_GPL(nfs4_fs_type);

static int __init register_nfs4_fs(void)
{
	return register_filesystem(&nfs4_fs_type);
}

static void unregister_nfs4_fs(void)
{
	unregister_filesystem(&nfs4_fs_type);
}
#else
static int __init register_nfs4_fs(void)
{
	return 0;
}

static void unregister_nfs4_fs(void)
{
}
#endif

static struct shrinker acl_shrinker = {
	.count_objects	= nfs_access_cache_count,
	.scan_objects	= nfs_access_cache_scan,
	.seeks		= DEFAULT_SEEKS,
};

/*
 * Register the NFS filesystems
 */
int __init register_nfs_fs(void)
{
	int ret;

        ret = register_filesystem(&nfs_fs_type);
	if (ret < 0)
		goto error_0;

	ret = register_nfs4_fs();
	if (ret < 0)
		goto error_1;

	ret = nfs_register_sysctl();
	if (ret < 0)
		goto error_2;
	register_shrinker(&acl_shrinker);
	return 0;

error_2:
	unregister_nfs4_fs();
error_1:
	unregister_filesystem(&nfs_fs_type);
error_0:
	return ret;
}

/*
 * Unregister the NFS filesystems
 */
void __exit unregister_nfs_fs(void)
{
	unregister_shrinker(&acl_shrinker);
	nfs_unregister_sysctl();
	unregister_nfs4_fs();
	unregister_filesystem(&nfs_fs_type);
}

void nfs_sb_active(struct super_block *sb)
{
	struct nfs_server *server = NFS_SB(sb);

	if (atomic_inc_return(&server->active) == 1)
		atomic_inc(&sb->s_active);
}
EXPORT_SYMBOL_GPL(nfs_sb_active);

void nfs_sb_deactive(struct super_block *sb)
{
	struct nfs_server *server = NFS_SB(sb);

	if (atomic_dec_and_test(&server->active))
		deactivate_super(sb);
}
EXPORT_SYMBOL_GPL(nfs_sb_deactive);

/*
 * Deliver file system statistics to userspace
 */
int nfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct nfs_server *server = NFS_SB(dentry->d_sb);
	unsigned char blockbits;
	unsigned long blockres;
	struct nfs_fh *fh = NFS_FH(dentry->d_inode);
	struct nfs_fsstat res;
	int error = -ENOMEM;

	res.fattr = nfs_alloc_fattr();
	if (res.fattr == NULL)
		goto out_err;

	error = server->nfs_client->rpc_ops->statfs(server, fh, &res);
	if (unlikely(error == -ESTALE)) {
		struct dentry *pd_dentry;

		pd_dentry = dget_parent(dentry);
		if (pd_dentry != NULL) {
			nfs_zap_caches(pd_dentry->d_inode);
			dput(pd_dentry);
		}
	}
	nfs_free_fattr(res.fattr);
	if (error < 0)
		goto out_err;

	buf->f_type = NFS_SUPER_MAGIC;

	/*
	 * Current versions of glibc do not correctly handle the
	 * case where f_frsize != f_bsize.  Eventually we want to
	 * report the value of wtmult in this field.
	 */
	buf->f_frsize = dentry->d_sb->s_blocksize;

	/*
	 * On most *nix systems, f_blocks, f_bfree, and f_bavail
	 * are reported in units of f_frsize.  Linux hasn't had
	 * an f_frsize field in its statfs struct until recently,
	 * thus historically Linux's sys_statfs reports these
	 * fields in units of f_bsize.
	 */
	buf->f_bsize = dentry->d_sb->s_blocksize;
	blockbits = dentry->d_sb->s_blocksize_bits;
	blockres = (1 << blockbits) - 1;
	buf->f_blocks = (res.tbytes + blockres) >> blockbits;
	buf->f_bfree = (res.fbytes + blockres) >> blockbits;
	buf->f_bavail = (res.abytes + blockres) >> blockbits;

	buf->f_files = res.tfiles;
	buf->f_ffree = res.afiles;

	buf->f_namelen = server->namelen;

	return 0;

 out_err:
	dprintk("%s: statfs error = %d\n", __func__, -error);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_statfs);

/*
 * Map the security flavour number to a name
 */
static const char *nfs_pseudoflavour_to_name(rpc_authflavor_t flavour)
{
	static const struct {
		rpc_authflavor_t flavour;
		const char *str;
	} sec_flavours[NFS_AUTH_INFO_MAX_FLAVORS] = {
		/* update NFS_AUTH_INFO_MAX_FLAVORS when this list changes! */
		{ RPC_AUTH_NULL, "null" },
		{ RPC_AUTH_UNIX, "sys" },
		{ RPC_AUTH_GSS_KRB5, "krb5" },
		{ RPC_AUTH_GSS_KRB5I, "krb5i" },
		{ RPC_AUTH_GSS_KRB5P, "krb5p" },
		{ RPC_AUTH_GSS_LKEY, "lkey" },
		{ RPC_AUTH_GSS_LKEYI, "lkeyi" },
		{ RPC_AUTH_GSS_LKEYP, "lkeyp" },
		{ RPC_AUTH_GSS_SPKM, "spkm" },
		{ RPC_AUTH_GSS_SPKMI, "spkmi" },
		{ RPC_AUTH_GSS_SPKMP, "spkmp" },
		{ UINT_MAX, "unknown" }
	};
	int i;

	for (i = 0; sec_flavours[i].flavour != UINT_MAX; i++) {
		if (sec_flavours[i].flavour == flavour)
			break;
	}
	return sec_flavours[i].str;
}

static void nfs_show_mountd_netid(struct seq_file *m, struct nfs_server *nfss,
				  int showdefaults)
{
	struct sockaddr *sap = (struct sockaddr *) &nfss->mountd_address;

	seq_printf(m, ",mountproto=");
	switch (sap->sa_family) {
	case AF_INET:
		switch (nfss->mountd_protocol) {
		case IPPROTO_UDP:
			seq_printf(m, RPCBIND_NETID_UDP);
			break;
		case IPPROTO_TCP:
			seq_printf(m, RPCBIND_NETID_TCP);
			break;
		default:
			if (showdefaults)
				seq_printf(m, "auto");
		}
		break;
	case AF_INET6:
		switch (nfss->mountd_protocol) {
		case IPPROTO_UDP:
			seq_printf(m, RPCBIND_NETID_UDP6);
			break;
		case IPPROTO_TCP:
			seq_printf(m, RPCBIND_NETID_TCP6);
			break;
		default:
			if (showdefaults)
				seq_printf(m, "auto");
		}
		break;
	default:
		if (showdefaults)
			seq_printf(m, "auto");
	}
}

static void nfs_show_mountd_options(struct seq_file *m, struct nfs_server *nfss,
				    int showdefaults)
{
	struct sockaddr *sap = (struct sockaddr *)&nfss->mountd_address;

	if (nfss->flags & NFS_MOUNT_LEGACY_INTERFACE)
		return;

	switch (sap->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sap;
		seq_printf(m, ",mountaddr=%pI4", &sin->sin_addr.s_addr);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sap;
		seq_printf(m, ",mountaddr=%pI6c", &sin6->sin6_addr);
		break;
	}
	default:
		if (showdefaults)
			seq_printf(m, ",mountaddr=unspecified");
	}

	if (nfss->mountd_version || showdefaults)
		seq_printf(m, ",mountvers=%u", nfss->mountd_version);
	if ((nfss->mountd_port &&
		nfss->mountd_port != (unsigned short)NFS_UNSPEC_PORT) ||
		showdefaults)
		seq_printf(m, ",mountport=%u", nfss->mountd_port);

	nfs_show_mountd_netid(m, nfss, showdefaults);
}

#if IS_ENABLED(CONFIG_NFS_V4)
static void nfs_show_nfsv4_options(struct seq_file *m, struct nfs_server *nfss,
				    int showdefaults)
{
	struct nfs_client *clp = nfss->nfs_client;

	seq_printf(m, ",clientaddr=%s", clp->cl_ipaddr);
}
#else
static void nfs_show_nfsv4_options(struct seq_file *m, struct nfs_server *nfss,
				    int showdefaults)
{
}
#endif

static void nfs_show_nfs_version(struct seq_file *m,
		unsigned int version,
		unsigned int minorversion)
{
	seq_printf(m, ",vers=%u", version);
	if (version == 4)
		seq_printf(m, ".%u", minorversion);
}

/*
 * Describe the mount options in force on this server representation
 */
static void nfs_show_mount_options(struct seq_file *m, struct nfs_server *nfss,
				   int showdefaults)
{
	static const struct proc_nfs_info {
		int flag;
		const char *str;
		const char *nostr;
	} nfs_info[] = {
		{ NFS_MOUNT_SOFT, ",soft", ",hard" },
		{ NFS_MOUNT_POSIX, ",posix", "" },
		{ NFS_MOUNT_NOCTO, ",nocto", "" },
		{ NFS_MOUNT_NOAC, ",noac", "" },
		{ NFS_MOUNT_NONLM, ",nolock", "" },
		{ NFS_MOUNT_NOACL, ",noacl", "" },
		{ NFS_MOUNT_NORDIRPLUS, ",nordirplus", "" },
		{ NFS_MOUNT_UNSHARED, ",nosharecache", "" },
		{ NFS_MOUNT_NORESVPORT, ",noresvport", "" },
		{ 0, NULL, NULL }
	};
	const struct proc_nfs_info *nfs_infop;
	struct nfs_client *clp = nfss->nfs_client;
	u32 version = clp->rpc_ops->version;
	int local_flock, local_fcntl;

	nfs_show_nfs_version(m, version, clp->cl_minorversion);
	seq_printf(m, ",rsize=%u", nfss->rsize);
	seq_printf(m, ",wsize=%u", nfss->wsize);
	if (nfss->bsize != 0)
		seq_printf(m, ",bsize=%u", nfss->bsize);
	seq_printf(m, ",namlen=%u", nfss->namelen);
	if (nfss->acregmin != NFS_DEF_ACREGMIN*HZ || showdefaults)
		seq_printf(m, ",acregmin=%u", nfss->acregmin/HZ);
	if (nfss->acregmax != NFS_DEF_ACREGMAX*HZ || showdefaults)
		seq_printf(m, ",acregmax=%u", nfss->acregmax/HZ);
	if (nfss->acdirmin != NFS_DEF_ACDIRMIN*HZ || showdefaults)
		seq_printf(m, ",acdirmin=%u", nfss->acdirmin/HZ);
	if (nfss->acdirmax != NFS_DEF_ACDIRMAX*HZ || showdefaults)
		seq_printf(m, ",acdirmax=%u", nfss->acdirmax/HZ);
	for (nfs_infop = nfs_info; nfs_infop->flag; nfs_infop++) {
		if (nfss->flags & nfs_infop->flag)
			seq_puts(m, nfs_infop->str);
		else
			seq_puts(m, nfs_infop->nostr);
	}
	rcu_read_lock();
	seq_printf(m, ",proto=%s",
		   rpc_peeraddr2str(nfss->client, RPC_DISPLAY_NETID));
	rcu_read_unlock();
	if (version == 4) {
		if (nfss->port != NFS_PORT)
			seq_printf(m, ",port=%u", nfss->port);
	} else
		if (nfss->port)
			seq_printf(m, ",port=%u", nfss->port);

	seq_printf(m, ",timeo=%lu", 10U * nfss->client->cl_timeout->to_initval / HZ);
	seq_printf(m, ",retrans=%u", nfss->client->cl_timeout->to_retries);
	seq_printf(m, ",sec=%s", nfs_pseudoflavour_to_name(nfss->client->cl_auth->au_flavor));

	if (version != 4)
		nfs_show_mountd_options(m, nfss, showdefaults);
	else
		nfs_show_nfsv4_options(m, nfss, showdefaults);

	if (nfss->options & NFS_OPTION_FSCACHE)
		seq_printf(m, ",fsc");

	if (nfss->options & NFS_OPTION_MIGRATION)
		seq_printf(m, ",migration");

	if (nfss->flags & NFS_MOUNT_LOOKUP_CACHE_NONEG) {
		if (nfss->flags & NFS_MOUNT_LOOKUP_CACHE_NONE)
			seq_printf(m, ",lookupcache=none");
		else
			seq_printf(m, ",lookupcache=pos");
	}

	local_flock = nfss->flags & NFS_MOUNT_LOCAL_FLOCK;
	local_fcntl = nfss->flags & NFS_MOUNT_LOCAL_FCNTL;

	if (!local_flock && !local_fcntl)
		seq_printf(m, ",local_lock=none");
	else if (local_flock && local_fcntl)
		seq_printf(m, ",local_lock=all");
	else if (local_flock)
		seq_printf(m, ",local_lock=flock");
	else
		seq_printf(m, ",local_lock=posix");
}

/*
 * Describe the mount options on this VFS mountpoint
 */
int nfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct nfs_server *nfss = NFS_SB(root->d_sb);

	nfs_show_mount_options(m, nfss, 0);

	rcu_read_lock();
	seq_printf(m, ",addr=%s",
			rpc_peeraddr2str(nfss->nfs_client->cl_rpcclient,
							RPC_DISPLAY_ADDR));
	rcu_read_unlock();

	return 0;
}
EXPORT_SYMBOL_GPL(nfs_show_options);

#if IS_ENABLED(CONFIG_NFS_V4)
#ifdef CONFIG_NFS_V4_1
static void show_sessions(struct seq_file *m, struct nfs_server *server)
{
	if (nfs4_has_session(server->nfs_client))
		seq_printf(m, ",sessions");
}
#else
static void show_sessions(struct seq_file *m, struct nfs_server *server) {}
#endif
#endif

#ifdef CONFIG_NFS_V4_1
static void show_pnfs(struct seq_file *m, struct nfs_server *server)
{
	seq_printf(m, ",pnfs=");
	if (server->pnfs_curr_ld)
		seq_printf(m, "%s", server->pnfs_curr_ld->name);
	else
		seq_printf(m, "not configured");
}

static void show_implementation_id(struct seq_file *m, struct nfs_server *nfss)
{
	if (nfss->nfs_client && nfss->nfs_client->cl_implid) {
		struct nfs41_impl_id *impl_id = nfss->nfs_client->cl_implid;
		seq_printf(m, "\n\timpl_id:\tname='%s',domain='%s',"
			   "date='%llu,%u'",
			   impl_id->name, impl_id->domain,
			   impl_id->date.seconds, impl_id->date.nseconds);
	}
}
#else
#if IS_ENABLED(CONFIG_NFS_V4)
static void show_pnfs(struct seq_file *m, struct nfs_server *server)
{
}
#endif
static void show_implementation_id(struct seq_file *m, struct nfs_server *nfss)
{
}
#endif

int nfs_show_devname(struct seq_file *m, struct dentry *root)
{
	char *page = (char *) __get_free_page(GFP_KERNEL);
	char *devname, *dummy;
	int err = 0;
	if (!page)
		return -ENOMEM;
	devname = nfs_path(&dummy, root, page, PAGE_SIZE, 0);
	if (IS_ERR(devname))
		err = PTR_ERR(devname);
	else
		seq_escape(m, devname, " \t\n\\");
	free_page((unsigned long)page);
	return err;
}
EXPORT_SYMBOL_GPL(nfs_show_devname);

int nfs_show_path(struct seq_file *m, struct dentry *dentry)
{
	seq_puts(m, "/");
	return 0;
}
EXPORT_SYMBOL_GPL(nfs_show_path);

/*
 * Present statistical information for this VFS mountpoint
 */
int nfs_show_stats(struct seq_file *m, struct dentry *root)
{
	int i, cpu;
	struct nfs_server *nfss = NFS_SB(root->d_sb);
	struct rpc_auth *auth = nfss->client->cl_auth;
	struct nfs_iostats totals = { };

	seq_printf(m, "statvers=%s", NFS_IOSTAT_VERS);

	/*
	 * Display all mount option settings
	 */
	seq_printf(m, "\n\topts:\t");
	seq_puts(m, root->d_sb->s_flags & MS_RDONLY ? "ro" : "rw");
	seq_puts(m, root->d_sb->s_flags & MS_SYNCHRONOUS ? ",sync" : "");
	seq_puts(m, root->d_sb->s_flags & MS_NOATIME ? ",noatime" : "");
	seq_puts(m, root->d_sb->s_flags & MS_NODIRATIME ? ",nodiratime" : "");
	nfs_show_mount_options(m, nfss, 1);

	seq_printf(m, "\n\tage:\t%lu", (jiffies - nfss->mount_time) / HZ);

	show_implementation_id(m, nfss);

	seq_printf(m, "\n\tcaps:\t");
	seq_printf(m, "caps=0x%x", nfss->caps);
	seq_printf(m, ",wtmult=%u", nfss->wtmult);
	seq_printf(m, ",dtsize=%u", nfss->dtsize);
	seq_printf(m, ",bsize=%u", nfss->bsize);
	seq_printf(m, ",namlen=%u", nfss->namelen);

#if IS_ENABLED(CONFIG_NFS_V4)
	if (nfss->nfs_client->rpc_ops->version == 4) {
		seq_printf(m, "\n\tnfsv4:\t");
		seq_printf(m, "bm0=0x%x", nfss->attr_bitmask[0]);
		seq_printf(m, ",bm1=0x%x", nfss->attr_bitmask[1]);
		seq_printf(m, ",bm2=0x%x", nfss->attr_bitmask[2]);
		seq_printf(m, ",acl=0x%x", nfss->acl_bitmask);
		show_sessions(m, nfss);
		show_pnfs(m, nfss);
	}
#endif

	/*
	 * Display security flavor in effect for this mount
	 */
	seq_printf(m, "\n\tsec:\tflavor=%u", auth->au_ops->au_flavor);
	if (auth->au_flavor)
		seq_printf(m, ",pseudoflavor=%u", auth->au_flavor);

	/*
	 * Display superblock I/O counters
	 */
	for_each_possible_cpu(cpu) {
		struct nfs_iostats *stats;

		preempt_disable();
		stats = per_cpu_ptr(nfss->io_stats, cpu);

		for (i = 0; i < __NFSIOS_COUNTSMAX; i++)
			totals.events[i] += stats->events[i];
		for (i = 0; i < __NFSIOS_BYTESMAX; i++)
			totals.bytes[i] += stats->bytes[i];
#ifdef CONFIG_NFS_FSCACHE
		for (i = 0; i < __NFSIOS_FSCACHEMAX; i++)
			totals.fscache[i] += stats->fscache[i];
#endif

		preempt_enable();
	}

	seq_printf(m, "\n\tevents:\t");
	for (i = 0; i < __NFSIOS_COUNTSMAX; i++)
		seq_printf(m, "%lu ", totals.events[i]);
	seq_printf(m, "\n\tbytes:\t");
	for (i = 0; i < __NFSIOS_BYTESMAX; i++)
		seq_printf(m, "%Lu ", totals.bytes[i]);
#ifdef CONFIG_NFS_FSCACHE
	if (nfss->options & NFS_OPTION_FSCACHE) {
		seq_printf(m, "\n\tfsc:\t");
		for (i = 0; i < __NFSIOS_FSCACHEMAX; i++)
			seq_printf(m, "%Lu ", totals.bytes[i]);
	}
#endif
	seq_printf(m, "\n");

	rpc_print_iostats(m, nfss->client);

	return 0;
}
EXPORT_SYMBOL_GPL(nfs_show_stats);

/*
 * Begin unmount by attempting to remove all automounted mountpoints we added
 * in response to xdev traversals and referrals
 */
void nfs_umount_begin(struct super_block *sb)
{
	struct nfs_server *server;
	struct rpc_clnt *rpc;

	server = NFS_SB(sb);
	/* -EIO all pending I/O */
	rpc = server->client_acl;
	if (!IS_ERR(rpc))
		rpc_killall_tasks(rpc);
	rpc = server->client;
	if (!IS_ERR(rpc))
		rpc_killall_tasks(rpc);
}
EXPORT_SYMBOL_GPL(nfs_umount_begin);

static struct nfs_parsed_mount_data *nfs_alloc_parsed_mount_data(void)
{
	struct nfs_parsed_mount_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data) {
		data->acregmin		= NFS_DEF_ACREGMIN;
		data->acregmax		= NFS_DEF_ACREGMAX;
		data->acdirmin		= NFS_DEF_ACDIRMIN;
		data->acdirmax		= NFS_DEF_ACDIRMAX;
		data->mount_server.port	= NFS_UNSPEC_PORT;
		data->nfs_server.port	= NFS_UNSPEC_PORT;
		data->nfs_server.protocol = XPRT_TRANSPORT_TCP;
		data->selected_flavor	= RPC_AUTH_MAXFLAVOR;
		data->minorversion	= 0;
		data->need_mount	= true;
		data->net		= current->nsproxy->net_ns;
		security_init_mnt_opts(&data->lsm_opts);
	}
	return data;
}

static void nfs_free_parsed_mount_data(struct nfs_parsed_mount_data *data)
{
	if (data) {
		kfree(data->client_address);
		kfree(data->mount_server.hostname);
		kfree(data->nfs_server.export_path);
		kfree(data->nfs_server.hostname);
		kfree(data->fscache_uniq);
		security_free_mnt_opts(&data->lsm_opts);
		kfree(data);
	}
}

/*
 * Sanity-check a server address provided by the mount command.
 *
 * Address family must be initialized, and address must not be
 * the ANY address for that family.
 */
static int nfs_verify_server_address(struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sa = (struct sockaddr_in *)addr;
		return sa->sin_addr.s_addr != htonl(INADDR_ANY);
	}
	case AF_INET6: {
		struct in6_addr *sa = &((struct sockaddr_in6 *)addr)->sin6_addr;
		return !ipv6_addr_any(sa);
	}
	}

	dfprintk(MOUNT, "NFS: Invalid IP address specified\n");
	return 0;
}

/*
 * Select between a default port value and a user-specified port value.
 * If a zero value is set, then autobind will be used.
 */
static void nfs_set_port(struct sockaddr *sap, int *port,
				 const unsigned short default_port)
{
	if (*port == NFS_UNSPEC_PORT)
		*port = default_port;

	rpc_set_port(sap, *port);
}

/*
 * Sanity check the NFS transport protocol.
 *
 */
static void nfs_validate_transport_protocol(struct nfs_parsed_mount_data *mnt)
{
	switch (mnt->nfs_server.protocol) {
	case XPRT_TRANSPORT_UDP:
	case XPRT_TRANSPORT_TCP:
	case XPRT_TRANSPORT_RDMA:
		break;
	default:
		mnt->nfs_server.protocol = XPRT_TRANSPORT_TCP;
	}
}

/*
 * For text based NFSv2/v3 mounts, the mount protocol transport default
 * settings should depend upon the specified NFS transport.
 */
static void nfs_set_mount_transport_protocol(struct nfs_parsed_mount_data *mnt)
{
	nfs_validate_transport_protocol(mnt);

	if (mnt->mount_server.protocol == XPRT_TRANSPORT_UDP ||
	    mnt->mount_server.protocol == XPRT_TRANSPORT_TCP)
			return;
	switch (mnt->nfs_server.protocol) {
	case XPRT_TRANSPORT_UDP:
		mnt->mount_server.protocol = XPRT_TRANSPORT_UDP;
		break;
	case XPRT_TRANSPORT_TCP:
	case XPRT_TRANSPORT_RDMA:
		mnt->mount_server.protocol = XPRT_TRANSPORT_TCP;
	}
}

/*
 * Add 'flavor' to 'auth_info' if not already present.
 * Returns true if 'flavor' ends up in the list, false otherwise
 */
static bool nfs_auth_info_add(struct nfs_auth_info *auth_info,
			      rpc_authflavor_t flavor)
{
	unsigned int i;
	unsigned int max_flavor_len = ARRAY_SIZE(auth_info->flavors);

	/* make sure this flavor isn't already in the list */
	for (i = 0; i < auth_info->flavor_len; i++) {
		if (flavor == auth_info->flavors[i])
			return true;
	}

	if (auth_info->flavor_len + 1 >= max_flavor_len) {
		dfprintk(MOUNT, "NFS: too many sec= flavors\n");
		return false;
	}

	auth_info->flavors[auth_info->flavor_len++] = flavor;
	return true;
}

/*
 * Return true if 'match' is in auth_info or auth_info is empty.
 * Return false otherwise.
 */
bool nfs_auth_info_match(const struct nfs_auth_info *auth_info,
			 rpc_authflavor_t match)
{
	int i;

	if (!auth_info->flavor_len)
		return true;

	for (i = 0; i < auth_info->flavor_len; i++) {
		if (auth_info->flavors[i] == match)
			return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(nfs_auth_info_match);

/*
 * Parse the value of the 'sec=' option.
 */
static int nfs_parse_security_flavors(char *value,
				      struct nfs_parsed_mount_data *mnt)
{
	substring_t args[MAX_OPT_ARGS];
	rpc_authflavor_t pseudoflavor;
	char *p;

	dfprintk(MOUNT, "NFS: parsing sec=%s option\n", value);

	while ((p = strsep(&value, ":")) != NULL) {
		switch (match_token(p, nfs_secflavor_tokens, args)) {
		case Opt_sec_none:
			pseudoflavor = RPC_AUTH_NULL;
			break;
		case Opt_sec_sys:
			pseudoflavor = RPC_AUTH_UNIX;
			break;
		case Opt_sec_krb5:
			pseudoflavor = RPC_AUTH_GSS_KRB5;
			break;
		case Opt_sec_krb5i:
			pseudoflavor = RPC_AUTH_GSS_KRB5I;
			break;
		case Opt_sec_krb5p:
			pseudoflavor = RPC_AUTH_GSS_KRB5P;
			break;
		case Opt_sec_lkey:
			pseudoflavor = RPC_AUTH_GSS_LKEY;
			break;
		case Opt_sec_lkeyi:
			pseudoflavor = RPC_AUTH_GSS_LKEYI;
			break;
		case Opt_sec_lkeyp:
			pseudoflavor = RPC_AUTH_GSS_LKEYP;
			break;
		case Opt_sec_spkm:
			pseudoflavor = RPC_AUTH_GSS_SPKM;
			break;
		case Opt_sec_spkmi:
			pseudoflavor = RPC_AUTH_GSS_SPKMI;
			break;
		case Opt_sec_spkmp:
			pseudoflavor = RPC_AUTH_GSS_SPKMP;
			break;
		default:
			dfprintk(MOUNT,
				 "NFS: sec= option '%s' not recognized\n", p);
			return 0;
		}

		if (!nfs_auth_info_add(&mnt->auth_info, pseudoflavor))
			return 0;
	}

	return 1;
}

static int nfs_parse_version_string(char *string,
		struct nfs_parsed_mount_data *mnt,
		substring_t *args)
{
	mnt->flags &= ~NFS_MOUNT_VER3;
	switch (match_token(string, nfs_vers_tokens, args)) {
	case Opt_vers_2:
		mnt->version = 2;
		break;
	case Opt_vers_3:
		mnt->flags |= NFS_MOUNT_VER3;
		mnt->version = 3;
		break;
	case Opt_vers_4:
		/* Backward compatibility option. In future,
		 * the mount program should always supply
		 * a NFSv4 minor version number.
		 */
		mnt->version = 4;
		break;
	case Opt_vers_4_0:
		mnt->version = 4;
		mnt->minorversion = 0;
		break;
	case Opt_vers_4_1:
		mnt->version = 4;
		mnt->minorversion = 1;
		break;
	case Opt_vers_4_2:
		mnt->version = 4;
		mnt->minorversion = 2;
		break;
	default:
		return 0;
	}
	return 1;
}

static int nfs_get_option_str(substring_t args[], char **option)
{
	kfree(*option);
	*option = match_strdup(args);
	return !*option;
}

static int nfs_get_option_ul(substring_t args[], unsigned long *option)
{
	int rc;
	char *string;

	string = match_strdup(args);
	if (string == NULL)
		return -ENOMEM;
	rc = kstrtoul(string, 10, option);
	kfree(string);

	return rc;
}

/*
 * Error-check and convert a string of mount options from user space into
 * a data structure.  The whole mount string is processed; bad options are
 * skipped as they are encountered.  If there were no errors, return 1;
 * otherwise return 0 (zero).
 */
static int nfs_parse_mount_options(char *raw,
				   struct nfs_parsed_mount_data *mnt)
{
	char *p, *string, *secdata;
	int rc, sloppy = 0, invalid_option = 0;
	unsigned short protofamily = AF_UNSPEC;
	unsigned short mountfamily = AF_UNSPEC;

	if (!raw) {
		dfprintk(MOUNT, "NFS: mount options string was NULL.\n");
		return 1;
	}
	dfprintk(MOUNT, "NFS: nfs mount opts='%s'\n", raw);

	secdata = alloc_secdata();
	if (!secdata)
		goto out_nomem;

	rc = security_sb_copy_data(raw, secdata);
	if (rc)
		goto out_security_failure;

	rc = security_sb_parse_opts_str(secdata, &mnt->lsm_opts);
	if (rc)
		goto out_security_failure;

	free_secdata(secdata);

	while ((p = strsep(&raw, ",")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		unsigned long option;
		int token;

		if (!*p)
			continue;

		dfprintk(MOUNT, "NFS:   parsing nfs mount option '%s'\n", p);

		token = match_token(p, nfs_mount_option_tokens, args);
		switch (token) {

		/*
		 * boolean options:  foo/nofoo
		 */
		case Opt_soft:
			mnt->flags |= NFS_MOUNT_SOFT;
			break;
		case Opt_hard:
			mnt->flags &= ~NFS_MOUNT_SOFT;
			break;
		case Opt_posix:
			mnt->flags |= NFS_MOUNT_POSIX;
			break;
		case Opt_noposix:
			mnt->flags &= ~NFS_MOUNT_POSIX;
			break;
		case Opt_cto:
			mnt->flags &= ~NFS_MOUNT_NOCTO;
			break;
		case Opt_nocto:
			mnt->flags |= NFS_MOUNT_NOCTO;
			break;
		case Opt_ac:
			mnt->flags &= ~NFS_MOUNT_NOAC;
			break;
		case Opt_noac:
			mnt->flags |= NFS_MOUNT_NOAC;
			break;
		case Opt_lock:
			mnt->flags &= ~NFS_MOUNT_NONLM;
			mnt->flags &= ~(NFS_MOUNT_LOCAL_FLOCK |
					NFS_MOUNT_LOCAL_FCNTL);
			break;
		case Opt_nolock:
			mnt->flags |= NFS_MOUNT_NONLM;
			mnt->flags |= (NFS_MOUNT_LOCAL_FLOCK |
				       NFS_MOUNT_LOCAL_FCNTL);
			break;
		case Opt_udp:
			mnt->flags &= ~NFS_MOUNT_TCP;
			mnt->nfs_server.protocol = XPRT_TRANSPORT_UDP;
			break;
		case Opt_tcp:
			mnt->flags |= NFS_MOUNT_TCP;
			mnt->nfs_server.protocol = XPRT_TRANSPORT_TCP;
			break;
		case Opt_rdma:
			mnt->flags |= NFS_MOUNT_TCP; /* for side protocols */
			mnt->nfs_server.protocol = XPRT_TRANSPORT_RDMA;
			xprt_load_transport(p);
			break;
		case Opt_acl:
			mnt->flags &= ~NFS_MOUNT_NOACL;
			break;
		case Opt_noacl:
			mnt->flags |= NFS_MOUNT_NOACL;
			break;
		case Opt_rdirplus:
			mnt->flags &= ~NFS_MOUNT_NORDIRPLUS;
			break;
		case Opt_nordirplus:
			mnt->flags |= NFS_MOUNT_NORDIRPLUS;
			break;
		case Opt_sharecache:
			mnt->flags &= ~NFS_MOUNT_UNSHARED;
			break;
		case Opt_nosharecache:
			mnt->flags |= NFS_MOUNT_UNSHARED;
			break;
		case Opt_resvport:
			mnt->flags &= ~NFS_MOUNT_NORESVPORT;
			break;
		case Opt_noresvport:
			mnt->flags |= NFS_MOUNT_NORESVPORT;
			break;
		case Opt_fscache:
			mnt->options |= NFS_OPTION_FSCACHE;
			kfree(mnt->fscache_uniq);
			mnt->fscache_uniq = NULL;
			break;
		case Opt_nofscache:
			mnt->options &= ~NFS_OPTION_FSCACHE;
			kfree(mnt->fscache_uniq);
			mnt->fscache_uniq = NULL;
			break;
		case Opt_migration:
			mnt->options |= NFS_OPTION_MIGRATION;
			break;
		case Opt_nomigration:
			mnt->options &= NFS_OPTION_MIGRATION;
			break;

		/*
		 * options that take numeric values
		 */
		case Opt_port:
			if (nfs_get_option_ul(args, &option) ||
			    option > USHRT_MAX)
				goto out_invalid_value;
			mnt->nfs_server.port = option;
			break;
		case Opt_rsize:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->rsize = option;
			break;
		case Opt_wsize:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->wsize = option;
			break;
		case Opt_bsize:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->bsize = option;
			break;
		case Opt_timeo:
			if (nfs_get_option_ul(args, &option) || option == 0)
				goto out_invalid_value;
			mnt->timeo = option;
			break;
		case Opt_retrans:
			if (nfs_get_option_ul(args, &option) || option == 0)
				goto out_invalid_value;
			mnt->retrans = option;
			break;
		case Opt_acregmin:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->acregmin = option;
			break;
		case Opt_acregmax:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->acregmax = option;
			break;
		case Opt_acdirmin:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->acdirmin = option;
			break;
		case Opt_acdirmax:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->acdirmax = option;
			break;
		case Opt_actimeo:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->acregmin = mnt->acregmax =
			mnt->acdirmin = mnt->acdirmax = option;
			break;
		case Opt_namelen:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			mnt->namlen = option;
			break;
		case Opt_mountport:
			if (nfs_get_option_ul(args, &option) ||
			    option > USHRT_MAX)
				goto out_invalid_value;
			mnt->mount_server.port = option;
			break;
		case Opt_mountvers:
			if (nfs_get_option_ul(args, &option) ||
			    option < NFS_MNT_VERSION ||
			    option > NFS_MNT3_VERSION)
				goto out_invalid_value;
			mnt->mount_server.version = option;
			break;
		case Opt_minorversion:
			if (nfs_get_option_ul(args, &option))
				goto out_invalid_value;
			if (option > NFS4_MAX_MINOR_VERSION)
				goto out_invalid_value;
			mnt->minorversion = option;
			break;

		/*
		 * options that take text values
		 */
		case Opt_nfsvers:
			string = match_strdup(args);
			if (string == NULL)
				goto out_nomem;
			rc = nfs_parse_version_string(string, mnt, args);
			kfree(string);
			if (!rc)
				goto out_invalid_value;
			break;
		case Opt_sec:
			string = match_strdup(args);
			if (string == NULL)
				goto out_nomem;
			rc = nfs_parse_security_flavors(string, mnt);
			kfree(string);
			if (!rc) {
				dfprintk(MOUNT, "NFS:   unrecognized "
						"security flavor\n");
				return 0;
			}
			break;
		case Opt_proto:
			string = match_strdup(args);
			if (string == NULL)
				goto out_nomem;
			token = match_token(string,
					    nfs_xprt_protocol_tokens, args);

			protofamily = AF_INET;
			switch (token) {
			case Opt_xprt_udp6:
				protofamily = AF_INET6;
			case Opt_xprt_udp:
				mnt->flags &= ~NFS_MOUNT_TCP;
				mnt->nfs_server.protocol = XPRT_TRANSPORT_UDP;
				break;
			case Opt_xprt_tcp6:
				protofamily = AF_INET6;
			case Opt_xprt_tcp:
				mnt->flags |= NFS_MOUNT_TCP;
				mnt->nfs_server.protocol = XPRT_TRANSPORT_TCP;
				break;
			case Opt_xprt_rdma:
				/* vector side protocols to TCP */
				mnt->flags |= NFS_MOUNT_TCP;
				mnt->nfs_server.protocol = XPRT_TRANSPORT_RDMA;
				xprt_load_transport(string);
				break;
			default:
				dfprintk(MOUNT, "NFS:   unrecognized "
						"transport protocol\n");
				kfree(string);
				return 0;
			}
			kfree(string);
			break;
		case Opt_mountproto:
			string = match_strdup(args);
			if (string == NULL)
				goto out_nomem;
			token = match_token(string,
					    nfs_xprt_protocol_tokens, args);
			kfree(string);

			mountfamily = AF_INET;
			switch (token) {
			case Opt_xprt_udp6:
				mountfamily = AF_INET6;
			case Opt_xprt_udp:
				mnt->mount_server.protocol = XPRT_TRANSPORT_UDP;
				break;
			case Opt_xprt_tcp6:
				mountfamily = AF_INET6;
			case Opt_xprt_tcp:
				mnt->mount_server.protocol = XPRT_TRANSPORT_TCP;
				break;
			case Opt_xprt_rdma: /* not used for side protocols */
			default:
				dfprintk(MOUNT, "NFS:   unrecognized "
						"transport protocol\n");
				return 0;
			}
			break;
		case Opt_addr:
			string = match_strdup(args);
			if (string == NULL)
				goto out_nomem;
			mnt->nfs_server.addrlen =
				rpc_pton(mnt->net, string, strlen(string),
					(struct sockaddr *)
					&mnt->nfs_server.address,
					sizeof(mnt->nfs_server.address));
			kfree(string);
			if (mnt->nfs_server.addrlen == 0)
				goto out_invalid_address;
			break;
		case Opt_clientaddr:
			if (nfs_get_option_str(args, &mnt->client_address))
				goto out_nomem;
			break;
		case Opt_mounthost:
			if (nfs_get_option_str(args,
					       &mnt->mount_server.hostname))
				goto out_nomem;
			break;
		case Opt_mountaddr:
			string = match_strdup(args);
			if (string == NULL)
				goto out_nomem;
			mnt->mount_server.addrlen =
				rpc_pton(mnt->net, string, strlen(string),
					(struct sockaddr *)
					&mnt->mount_server.address,
					sizeof(mnt->mount_server.address));
			kfree(string);
			if (mnt->mount_server.addrlen == 0)
				goto out_invalid_address;
			break;
		case Opt_lookupcache:
			string = match_strdup(args);
			if (string == NULL)
				goto out_nomem;
			token = match_token(string,
					nfs_lookupcache_tokens, args);
			kfree(string);
			switch (token) {
				case Opt_lookupcache_all:
					mnt->flags &= ~(NFS_MOUNT_LOOKUP_CACHE_NONEG|NFS_MOUNT_LOOKUP_CACHE_NONE);
					break;
				case Opt_lookupcache_positive:
					mnt->flags &= ~NFS_MOUNT_LOOKUP_CACHE_NONE;
					mnt->flags |= NFS_MOUNT_LOOKUP_CACHE_NONEG;
					break;
				case Opt_lookupcache_none:
					mnt->flags |= NFS_MOUNT_LOOKUP_CACHE_NONEG|NFS_MOUNT_LOOKUP_CACHE_NONE;
					break;
				default:
					dfprintk(MOUNT, "NFS:   invalid "
							"lookupcache argument\n");
					return 0;
			};
			break;
		case Opt_fscache_uniq:
			if (nfs_get_option_str(args, &mnt->fscache_uniq))
				goto out_nomem;
			mnt->options |= NFS_OPTION_FSCACHE;
			break;
		case Opt_local_lock:
			string = match_strdup(args);
			if (string == NULL)
				goto out_nomem;
			token = match_token(string, nfs_local_lock_tokens,
					args);
			kfree(string);
			switch (token) {
			case Opt_local_lock_all:
				mnt->flags |= (NFS_MOUNT_LOCAL_FLOCK |
					       NFS_MOUNT_LOCAL_FCNTL);
				break;
			case Opt_local_lock_flock:
				mnt->flags |= NFS_MOUNT_LOCAL_FLOCK;
				break;
			case Opt_local_lock_posix:
				mnt->flags |= NFS_MOUNT_LOCAL_FCNTL;
				break;
			case Opt_local_lock_none:
				mnt->flags &= ~(NFS_MOUNT_LOCAL_FLOCK |
						NFS_MOUNT_LOCAL_FCNTL);
				break;
			default:
				dfprintk(MOUNT, "NFS:	invalid	"
						"local_lock argument\n");
				return 0;
			};
			break;

		/*
		 * Special options
		 */
		case Opt_sloppy:
			sloppy = 1;
			dfprintk(MOUNT, "NFS:   relaxing parsing rules\n");
			break;
		case Opt_userspace:
		case Opt_deprecated:
			dfprintk(MOUNT, "NFS:   ignoring mount option "
					"'%s'\n", p);
			break;

		default:
			invalid_option = 1;
			dfprintk(MOUNT, "NFS:   unrecognized mount option "
					"'%s'\n", p);
		}
	}

	if (!sloppy && invalid_option)
		return 0;

	if (mnt->minorversion && mnt->version != 4)
		goto out_minorversion_mismatch;

	if (mnt->options & NFS_OPTION_MIGRATION &&
	    (mnt->version != 4 || mnt->minorversion != 0))
		goto out_migration_misuse;

	/*
	 * verify that any proto=/mountproto= options match the address
	 * families in the addr=/mountaddr= options.
	 */
	if (protofamily != AF_UNSPEC &&
	    protofamily != mnt->nfs_server.address.ss_family)
		goto out_proto_mismatch;

	if (mountfamily != AF_UNSPEC) {
		if (mnt->mount_server.addrlen) {
			if (mountfamily != mnt->mount_server.address.ss_family)
				goto out_mountproto_mismatch;
		} else {
			if (mountfamily != mnt->nfs_server.address.ss_family)
				goto out_mountproto_mismatch;
		}
	}

	return 1;

out_mountproto_mismatch:
	printk(KERN_INFO "NFS: mount server address does not match mountproto= "
			 "option\n");
	return 0;
out_proto_mismatch:
	printk(KERN_INFO "NFS: server address does not match proto= option\n");
	return 0;
out_invalid_address:
	printk(KERN_INFO "NFS: bad IP address specified: %s\n", p);
	return 0;
out_invalid_value:
	printk(KERN_INFO "NFS: bad mount option value specified: %s\n", p);
	return 0;
out_minorversion_mismatch:
	printk(KERN_INFO "NFS: mount option vers=%u does not support "
			 "minorversion=%u\n", mnt->version, mnt->minorversion);
	return 0;
out_migration_misuse:
	printk(KERN_INFO
		"NFS: 'migration' not supported for this NFS version\n");
	return 0;
out_nomem:
	printk(KERN_INFO "NFS: not enough memory to parse option\n");
	return 0;
out_security_failure:
	free_secdata(secdata);
	printk(KERN_INFO "NFS: security options invalid: %d\n", rc);
	return 0;
}

/*
 * Ensure that a specified authtype in args->auth_info is supported by
 * the server. Returns 0 and sets args->selected_flavor if it's ok, and
 * -EACCES if not.
 */
static int nfs_verify_authflavors(struct nfs_parsed_mount_data *args,
			rpc_authflavor_t *server_authlist, unsigned int count)
{
	rpc_authflavor_t flavor = RPC_AUTH_MAXFLAVOR;
	unsigned int i;

	/*
	 * If the sec= mount option is used, the specified flavor or AUTH_NULL
	 * must be in the list returned by the server.
	 *
	 * AUTH_NULL has a special meaning when it's in the server list - it
	 * means that the server will ignore the rpc creds, so any flavor
	 * can be used.
	 */
	for (i = 0; i < count; i++) {
		flavor = server_authlist[i];

		if (nfs_auth_info_match(&args->auth_info, flavor) ||
		    flavor == RPC_AUTH_NULL)
			goto out;
	}

	dfprintk(MOUNT,
		 "NFS: specified auth flavors not supported by server\n");
	return -EACCES;

out:
	args->selected_flavor = flavor;
	dfprintk(MOUNT, "NFS: using auth flavor %u\n", args->selected_flavor);
	return 0;
}

/*
 * Use the remote server's MOUNT service to request the NFS file handle
 * corresponding to the provided path.
 */
static int nfs_request_mount(struct nfs_parsed_mount_data *args,
			     struct nfs_fh *root_fh,
			     rpc_authflavor_t *server_authlist,
			     unsigned int *server_authlist_len)
{
	struct nfs_mount_request request = {
		.sap		= (struct sockaddr *)
						&args->mount_server.address,
		.dirpath	= args->nfs_server.export_path,
		.protocol	= args->mount_server.protocol,
		.fh		= root_fh,
		.noresvport	= args->flags & NFS_MOUNT_NORESVPORT,
		.auth_flav_len	= server_authlist_len,
		.auth_flavs	= server_authlist,
		.net		= args->net,
	};
	int status;

	if (args->mount_server.version == 0) {
		switch (args->version) {
			default:
				args->mount_server.version = NFS_MNT3_VERSION;
				break;
			case 2:
				args->mount_server.version = NFS_MNT_VERSION;
		}
	}
	request.version = args->mount_server.version;

	if (args->mount_server.hostname)
		request.hostname = args->mount_server.hostname;
	else
		request.hostname = args->nfs_server.hostname;

	/*
	 * Construct the mount server's address.
	 */
	if (args->mount_server.address.ss_family == AF_UNSPEC) {
		memcpy(request.sap, &args->nfs_server.address,
		       args->nfs_server.addrlen);
		args->mount_server.addrlen = args->nfs_server.addrlen;
	}
	request.salen = args->mount_server.addrlen;
	nfs_set_port(request.sap, &args->mount_server.port, 0);

	/*
	 * Now ask the mount server to map our export path
	 * to a file handle.
	 */
	status = nfs_mount(&request);
	if (status != 0) {
		dfprintk(MOUNT, "NFS: unable to mount server %s, error %d\n",
				request.hostname, status);
		return status;
	}

	return 0;
}

static struct nfs_server *nfs_try_mount_request(struct nfs_mount_info *mount_info,
					struct nfs_subversion *nfs_mod)
{
	int status;
	unsigned int i;
	bool tried_auth_unix = false;
	bool auth_null_in_list = false;
	struct nfs_server *server = ERR_PTR(-EACCES);
	struct nfs_parsed_mount_data *args = mount_info->parsed;
	rpc_authflavor_t authlist[NFS_MAX_SECFLAVORS];
	unsigned int authlist_len = ARRAY_SIZE(authlist);

	status = nfs_request_mount(args, mount_info->mntfh, authlist,
					&authlist_len);
	if (status)
		return ERR_PTR(status);

	/*
	 * Was a sec= authflavor specified in the options? First, verify
	 * whether the server supports it, and then just try to use it if so.
	 */
	if (args->auth_info.flavor_len > 0) {
		status = nfs_verify_authflavors(args, authlist, authlist_len);
		dfprintk(MOUNT, "NFS: using auth flavor %u\n",
			 args->selected_flavor);
		if (status)
			return ERR_PTR(status);
		return nfs_mod->rpc_ops->create_server(mount_info, nfs_mod);
	}

	/*
	 * No sec= option was provided. RFC 2623, section 2.7 suggests we
	 * SHOULD prefer the flavor listed first. However, some servers list
	 * AUTH_NULL first. Avoid ever choosing AUTH_NULL.
	 */
	for (i = 0; i < authlist_len; ++i) {
		rpc_authflavor_t flavor;
		struct rpcsec_gss_info info;

		flavor = authlist[i];
		switch (flavor) {
		case RPC_AUTH_UNIX:
			tried_auth_unix = true;
			break;
		case RPC_AUTH_NULL:
			auth_null_in_list = true;
			continue;
		default:
			if (rpcauth_get_gssinfo(flavor, &info) != 0)
				continue;
			/* Fallthrough */
		}
		dfprintk(MOUNT, "NFS: attempting to use auth flavor %u\n", flavor);
		args->selected_flavor = flavor;
		server = nfs_mod->rpc_ops->create_server(mount_info, nfs_mod);
		if (!IS_ERR(server))
			return server;
	}

	/*
	 * Nothing we tried so far worked. At this point, give up if we've
	 * already tried AUTH_UNIX or if the server's list doesn't contain
	 * AUTH_NULL
	 */
	if (tried_auth_unix || !auth_null_in_list)
		return server;

	/* Last chance! Try AUTH_UNIX */
	dfprintk(MOUNT, "NFS: attempting to use auth flavor %u\n", RPC_AUTH_UNIX);
	args->selected_flavor = RPC_AUTH_UNIX;
	return nfs_mod->rpc_ops->create_server(mount_info, nfs_mod);
}

struct dentry *nfs_try_mount(int flags, const char *dev_name,
			     struct nfs_mount_info *mount_info,
			     struct nfs_subversion *nfs_mod)
{
	struct nfs_server *server;

	if (mount_info->parsed->need_mount)
		server = nfs_try_mount_request(mount_info, nfs_mod);
	else
		server = nfs_mod->rpc_ops->create_server(mount_info, nfs_mod);

	if (IS_ERR(server))
		return ERR_CAST(server);

	return nfs_fs_mount_common(server, flags, dev_name, mount_info, nfs_mod);
}
EXPORT_SYMBOL_GPL(nfs_try_mount);

/*
 * Split "dev_name" into "hostname:export_path".
 *
 * The leftmost colon demarks the split between the server's hostname
 * and the export path.  If the hostname starts with a left square
 * bracket, then it may contain colons.
 *
 * Note: caller frees hostname and export path, even on error.
 */
static int nfs_parse_devname(const char *dev_name,
			     char **hostname, size_t maxnamlen,
			     char **export_path, size_t maxpathlen)
{
	size_t len;
	char *end;

	/* Is the host name protected with square brakcets? */
	if (*dev_name == '[') {
		end = strchr(++dev_name, ']');
		if (end == NULL || end[1] != ':')
			goto out_bad_devname;

		len = end - dev_name;
		end++;
	} else {
		char *comma;

		end = strchr(dev_name, ':');
		if (end == NULL)
			goto out_bad_devname;
		len = end - dev_name;

		/* kill possible hostname list: not supported */
		comma = strchr(dev_name, ',');
		if (comma != NULL && comma < end)
			*comma = 0;
	}

	if (len > maxnamlen)
		goto out_hostname;

	/* N.B. caller will free nfs_server.hostname in all cases */
	*hostname = kstrndup(dev_name, len, GFP_KERNEL);
	if (*hostname == NULL)
		goto out_nomem;
	len = strlen(++end);
	if (len > maxpathlen)
		goto out_path;
	*export_path = kstrndup(end, len, GFP_KERNEL);
	if (!*export_path)
		goto out_nomem;

	dfprintk(MOUNT, "NFS: MNTPATH: '%s'\n", *export_path);
	return 0;

out_bad_devname:
	dfprintk(MOUNT, "NFS: device name not in host:path format\n");
	return -EINVAL;

out_nomem:
	dfprintk(MOUNT, "NFS: not enough memory to parse device name\n");
	return -ENOMEM;

out_hostname:
	dfprintk(MOUNT, "NFS: server hostname too long\n");
	return -ENAMETOOLONG;

out_path:
	dfprintk(MOUNT, "NFS: export pathname too long\n");
	return -ENAMETOOLONG;
}

/*
 * Validate the NFS2/NFS3 mount data
 * - fills in the mount root filehandle
 *
 * For option strings, user space handles the following behaviors:
 *
 * + DNS: mapping server host name to IP address ("addr=" option)
 *
 * + failure mode: how to behave if a mount request can't be handled
 *   immediately ("fg/bg" option)
 *
 * + retry: how often to retry a mount request ("retry=" option)
 *
 * + breaking back: trying proto=udp after proto=tcp, v2 after v3,
 *   mountproto=tcp after mountproto=udp, and so on
 */
static int nfs23_validate_mount_data(void *options,
				     struct nfs_parsed_mount_data *args,
				     struct nfs_fh *mntfh,
				     const char *dev_name)
{
	struct nfs_mount_data *data = (struct nfs_mount_data *)options;
	struct sockaddr *sap = (struct sockaddr *)&args->nfs_server.address;
	int extra_flags = NFS_MOUNT_LEGACY_INTERFACE;

	if (data == NULL)
		goto out_no_data;

	args->version = NFS_DEFAULT_VERSION;
	switch (data->version) {
	case 1:
		data->namlen = 0;
	case 2:
		data->bsize = 0;
	case 3:
		if (data->flags & NFS_MOUNT_VER3)
			goto out_no_v3;
		data->root.size = NFS2_FHSIZE;
		memcpy(data->root.data, data->old_root.data, NFS2_FHSIZE);
		/* Turn off security negotiation */
		extra_flags |= NFS_MOUNT_SECFLAVOUR;
	case 4:
		if (data->flags & NFS_MOUNT_SECFLAVOUR)
			goto out_no_sec;
	case 5:
		memset(data->context, 0, sizeof(data->context));
	case 6:
		if (data->flags & NFS_MOUNT_VER3) {
			if (data->root.size > NFS3_FHSIZE || data->root.size == 0)
				goto out_invalid_fh;
			mntfh->size = data->root.size;
			args->version = 3;
		} else {
			mntfh->size = NFS2_FHSIZE;
			args->version = 2;
		}


		memcpy(mntfh->data, data->root.data, mntfh->size);
		if (mntfh->size < sizeof(mntfh->data))
			memset(mntfh->data + mntfh->size, 0,
			       sizeof(mntfh->data) - mntfh->size);

		/*
		 * Translate to nfs_parsed_mount_data, which nfs_fill_super
		 * can deal with.
		 */
		args->flags		= data->flags & NFS_MOUNT_FLAGMASK;
		args->flags		|= extra_flags;
		args->rsize		= data->rsize;
		args->wsize		= data->wsize;
		args->timeo		= data->timeo;
		args->retrans		= data->retrans;
		args->acregmin		= data->acregmin;
		args->acregmax		= data->acregmax;
		args->acdirmin		= data->acdirmin;
		args->acdirmax		= data->acdirmax;
		args->need_mount	= false;

		memcpy(sap, &data->addr, sizeof(data->addr));
		args->nfs_server.addrlen = sizeof(data->addr);
		args->nfs_server.port = ntohs(data->addr.sin_port);
		if (!nfs_verify_server_address(sap))
			goto out_no_address;

		if (!(data->flags & NFS_MOUNT_TCP))
			args->nfs_server.protocol = XPRT_TRANSPORT_UDP;
		/* N.B. caller will free nfs_server.hostname in all cases */
		args->nfs_server.hostname = kstrdup(data->hostname, GFP_KERNEL);
		args->namlen		= data->namlen;
		args->bsize		= data->bsize;

		if (data->flags & NFS_MOUNT_SECFLAVOUR)
			args->selected_flavor = data->pseudoflavor;
		else
			args->selected_flavor = RPC_AUTH_UNIX;
		if (!args->nfs_server.hostname)
			goto out_nomem;

		if (!(data->flags & NFS_MOUNT_NONLM))
			args->flags &= ~(NFS_MOUNT_LOCAL_FLOCK|
					 NFS_MOUNT_LOCAL_FCNTL);
		else
			args->flags |= (NFS_MOUNT_LOCAL_FLOCK|
					NFS_MOUNT_LOCAL_FCNTL);
		/*
		 * The legacy version 6 binary mount data from userspace has a
		 * field used only to transport selinux information into the
		 * the kernel.  To continue to support that functionality we
		 * have a touch of selinux knowledge here in the NFS code. The
		 * userspace code converted context=blah to just blah so we are
		 * converting back to the full string selinux understands.
		 */
		if (data->context[0]){
#ifdef CONFIG_SECURITY_SELINUX
			int rc;
			char *opts_str = kmalloc(sizeof(data->context) + 8, GFP_KERNEL);
			if (!opts_str)
				return -ENOMEM;
			strcpy(opts_str, "context=");
			data->context[NFS_MAX_CONTEXT_LEN] = '\0';
			strcat(opts_str, &data->context[0]);
			rc = security_sb_parse_opts_str(opts_str, &args->lsm_opts);
			kfree(opts_str);
			if (rc)
				return rc;
#else
			return -EINVAL;
#endif
		}

		break;
	default:
		return NFS_TEXT_DATA;
	}

#if !IS_ENABLED(CONFIG_NFS_V3)
	if (args->version == 3)
		goto out_v3_not_compiled;
#endif /* !CONFIG_NFS_V3 */

	return 0;

out_no_data:
	dfprintk(MOUNT, "NFS: mount program didn't pass any mount data\n");
	return -EINVAL;

out_no_v3:
	dfprintk(MOUNT, "NFS: nfs_mount_data version %d does not support v3\n",
		 data->version);
	return -EINVAL;

out_no_sec:
	dfprintk(MOUNT, "NFS: nfs_mount_data version supports only AUTH_SYS\n");
	return -EINVAL;

#if !IS_ENABLED(CONFIG_NFS_V3)
out_v3_not_compiled:
	dfprintk(MOUNT, "NFS: NFSv3 is not compiled into kernel\n");
	return -EPROTONOSUPPORT;
#endif /* !CONFIG_NFS_V3 */

out_nomem:
	dfprintk(MOUNT, "NFS: not enough memory to handle mount options\n");
	return -ENOMEM;

out_no_address:
	dfprintk(MOUNT, "NFS: mount program didn't pass remote address\n");
	return -EINVAL;

out_invalid_fh:
	dfprintk(MOUNT, "NFS: invalid root filehandle\n");
	return -EINVAL;
}

#if IS_ENABLED(CONFIG_NFS_V4)
static int nfs_validate_mount_data(struct file_system_type *fs_type,
				   void *options,
				   struct nfs_parsed_mount_data *args,
				   struct nfs_fh *mntfh,
				   const char *dev_name)
{
	if (fs_type == &nfs_fs_type)
		return nfs23_validate_mount_data(options, args, mntfh, dev_name);
	return nfs4_validate_mount_data(options, args, dev_name);
}
#else
static int nfs_validate_mount_data(struct file_system_type *fs_type,
				   void *options,
				   struct nfs_parsed_mount_data *args,
				   struct nfs_fh *mntfh,
				   const char *dev_name)
{
	return nfs23_validate_mount_data(options, args, mntfh, dev_name);
}
#endif

static int nfs_validate_text_mount_data(void *options,
					struct nfs_parsed_mount_data *args,
					const char *dev_name)
{
	int port = 0;
	int max_namelen = PAGE_SIZE;
	int max_pathlen = NFS_MAXPATHLEN;
	struct sockaddr *sap = (struct sockaddr *)&args->nfs_server.address;

	if (nfs_parse_mount_options((char *)options, args) == 0)
		return -EINVAL;

	if (!nfs_verify_server_address(sap))
		goto out_no_address;

	if (args->version == 4) {
#if IS_ENABLED(CONFIG_NFS_V4)
		port = NFS_PORT;
		max_namelen = NFS4_MAXNAMLEN;
		max_pathlen = NFS4_MAXPATHLEN;
		nfs_validate_transport_protocol(args);
		if (args->nfs_server.protocol == XPRT_TRANSPORT_UDP)
			goto out_invalid_transport_udp;
		nfs4_validate_mount_flags(args);
#else
		goto out_v4_not_compiled;
#endif /* CONFIG_NFS_V4 */
	} else
		nfs_set_mount_transport_protocol(args);

	nfs_set_port(sap, &args->nfs_server.port, port);

	return nfs_parse_devname(dev_name,
				   &args->nfs_server.hostname,
				   max_namelen,
				   &args->nfs_server.export_path,
				   max_pathlen);

#if !IS_ENABLED(CONFIG_NFS_V4)
out_v4_not_compiled:
	dfprintk(MOUNT, "NFS: NFSv4 is not compiled into kernel\n");
	return -EPROTONOSUPPORT;
#else
out_invalid_transport_udp:
	dfprintk(MOUNT, "NFSv4: Unsupported transport protocol udp\n");
	return -EINVAL;
#endif /* !CONFIG_NFS_V4 */

out_no_address:
	dfprintk(MOUNT, "NFS: mount program didn't pass remote address\n");
	return -EINVAL;
}

#define NFS_REMOUNT_CMP_FLAGMASK ~(NFS_MOUNT_INTR \
		| NFS_MOUNT_SECURE \
		| NFS_MOUNT_TCP \
		| NFS_MOUNT_VER3 \
		| NFS_MOUNT_KERBEROS \
		| NFS_MOUNT_NONLM \
		| NFS_MOUNT_BROKEN_SUID \
		| NFS_MOUNT_STRICTLOCK \
		| NFS_MOUNT_LEGACY_INTERFACE)

#define NFS_MOUNT_CMP_FLAGMASK (NFS_REMOUNT_CMP_FLAGMASK & \
		~(NFS_MOUNT_UNSHARED | NFS_MOUNT_NORESVPORT))

static int
nfs_compare_remount_data(struct nfs_server *nfss,
			 struct nfs_parsed_mount_data *data)
{
	if ((data->flags ^ nfss->flags) & NFS_REMOUNT_CMP_FLAGMASK ||
	    data->rsize != nfss->rsize ||
	    data->wsize != nfss->wsize ||
	    data->version != nfss->nfs_client->rpc_ops->version ||
	    data->minorversion != nfss->nfs_client->cl_minorversion ||
	    data->retrans != nfss->client->cl_timeout->to_retries ||
	    data->selected_flavor != nfss->client->cl_auth->au_flavor ||
	    data->acregmin != nfss->acregmin / HZ ||
	    data->acregmax != nfss->acregmax / HZ ||
	    data->acdirmin != nfss->acdirmin / HZ ||
	    data->acdirmax != nfss->acdirmax / HZ ||
	    data->timeo != (10U * nfss->client->cl_timeout->to_initval / HZ) ||
	    data->nfs_server.port != nfss->port ||
	    data->nfs_server.addrlen != nfss->nfs_client->cl_addrlen ||
	    !rpc_cmp_addr((struct sockaddr *)&data->nfs_server.address,
			  (struct sockaddr *)&nfss->nfs_client->cl_addr))
		return -EINVAL;

	return 0;
}

int
nfs_remount(struct super_block *sb, int *flags, char *raw_data)
{
	int error;
	struct nfs_server *nfss = sb->s_fs_info;
	struct nfs_parsed_mount_data *data;
	struct nfs_mount_data *options = (struct nfs_mount_data *)raw_data;
	struct nfs4_mount_data *options4 = (struct nfs4_mount_data *)raw_data;
	u32 nfsvers = nfss->nfs_client->rpc_ops->version;

	sync_filesystem(sb);

	/*
	 * Userspace mount programs that send binary options generally send
	 * them populated with default values. We have no way to know which
	 * ones were explicitly specified. Fall back to legacy behavior and
	 * just return success.
	 */
	if ((nfsvers == 4 && (!options4 || options4->version == 1)) ||
	    (nfsvers <= 3 && (!options || (options->version >= 1 &&
					   options->version <= 6))))
		return 0;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	/* fill out struct with values from existing mount */
	data->flags = nfss->flags;
	data->rsize = nfss->rsize;
	data->wsize = nfss->wsize;
	data->retrans = nfss->client->cl_timeout->to_retries;
	data->selected_flavor = nfss->client->cl_auth->au_flavor;
	data->auth_info = nfss->auth_info;
	data->acregmin = nfss->acregmin / HZ;
	data->acregmax = nfss->acregmax / HZ;
	data->acdirmin = nfss->acdirmin / HZ;
	data->acdirmax = nfss->acdirmax / HZ;
	data->timeo = 10U * nfss->client->cl_timeout->to_initval / HZ;
	data->nfs_server.port = nfss->port;
	data->nfs_server.addrlen = nfss->nfs_client->cl_addrlen;
	data->version = nfsvers;
	data->minorversion = nfss->nfs_client->cl_minorversion;
	data->net = current->nsproxy->net_ns;
	memcpy(&data->nfs_server.address, &nfss->nfs_client->cl_addr,
		data->nfs_server.addrlen);

	/* overwrite those values with any that were specified */
	error = -EINVAL;
	if (!nfs_parse_mount_options((char *)options, data))
		goto out;

	/*
	 * noac is a special case. It implies -o sync, but that's not
	 * necessarily reflected in the mtab options. do_remount_sb
	 * will clear MS_SYNCHRONOUS if -o sync wasn't specified in the
	 * remount options, so we have to explicitly reset it.
	 */
	if (data->flags & NFS_MOUNT_NOAC)
		*flags |= MS_SYNCHRONOUS;

	/* compare new mount options with old ones */
	error = nfs_compare_remount_data(nfss, data);
out:
	kfree(data);
	return error;
}
EXPORT_SYMBOL_GPL(nfs_remount);

/*
 * Initialise the common bits of the superblock
 */
inline void nfs_initialise_sb(struct super_block *sb)
{
	struct nfs_server *server = NFS_SB(sb);

	sb->s_magic = NFS_SUPER_MAGIC;

	/* We probably want something more informative here */
	snprintf(sb->s_id, sizeof(sb->s_id),
		 "%u:%u", MAJOR(sb->s_dev), MINOR(sb->s_dev));

	if (sb->s_blocksize == 0)
		sb->s_blocksize = nfs_block_bits(server->wsize,
						 &sb->s_blocksize_bits);

	sb->s_bdi = &server->backing_dev_info;

	nfs_super_set_maxbytes(sb, server->maxfilesize);
}

/*
 * Finish setting up an NFS2/3 superblock
 */
void nfs_fill_super(struct super_block *sb, struct nfs_mount_info *mount_info)
{
	struct nfs_parsed_mount_data *data = mount_info->parsed;
	struct nfs_server *server = NFS_SB(sb);

	sb->s_blocksize_bits = 0;
	sb->s_blocksize = 0;
	sb->s_xattr = server->nfs_client->cl_nfs_mod->xattr;
	sb->s_op = server->nfs_client->cl_nfs_mod->sops;
	if (data && data->bsize)
		sb->s_blocksize = nfs_block_size(data->bsize, &sb->s_blocksize_bits);

	if (server->nfs_client->rpc_ops->version != 2) {
		/* The VFS shouldn't apply the umask to mode bits. We will do
		 * so ourselves when necessary.
		 */
		sb->s_flags |= MS_POSIXACL;
		sb->s_time_gran = 1;
	}

 	nfs_initialise_sb(sb);
}
EXPORT_SYMBOL_GPL(nfs_fill_super);

/*
 * Finish setting up a cloned NFS2/3/4 superblock
 */
void nfs_clone_super(struct super_block *sb, struct nfs_mount_info *mount_info)
{
	const struct super_block *old_sb = mount_info->cloned->sb;
	struct nfs_server *server = NFS_SB(sb);

	sb->s_blocksize_bits = old_sb->s_blocksize_bits;
	sb->s_blocksize = old_sb->s_blocksize;
	sb->s_maxbytes = old_sb->s_maxbytes;
	sb->s_xattr = old_sb->s_xattr;
	sb->s_op = old_sb->s_op;
	sb->s_time_gran = 1;

	if (server->nfs_client->rpc_ops->version != 2) {
		/* The VFS shouldn't apply the umask to mode bits. We will do
		 * so ourselves when necessary.
		 */
		sb->s_flags |= MS_POSIXACL;
	}

 	nfs_initialise_sb(sb);
}

static int nfs_compare_mount_options(const struct super_block *s, const struct nfs_server *b, int flags)
{
	const struct nfs_server *a = s->s_fs_info;
	const struct rpc_clnt *clnt_a = a->client;
	const struct rpc_clnt *clnt_b = b->client;

	if ((s->s_flags & NFS_MS_MASK) != (flags & NFS_MS_MASK))
		goto Ebusy;
	if (a->nfs_client != b->nfs_client)
		goto Ebusy;
	if ((a->flags ^ b->flags) & NFS_MOUNT_CMP_FLAGMASK)
		goto Ebusy;
	if (a->wsize != b->wsize)
		goto Ebusy;
	if (a->rsize != b->rsize)
		goto Ebusy;
	if (a->acregmin != b->acregmin)
		goto Ebusy;
	if (a->acregmax != b->acregmax)
		goto Ebusy;
	if (a->acdirmin != b->acdirmin)
		goto Ebusy;
	if (a->acdirmax != b->acdirmax)
		goto Ebusy;
	if (b->auth_info.flavor_len > 0 &&
	   clnt_a->cl_auth->au_flavor != clnt_b->cl_auth->au_flavor)
		goto Ebusy;
	return 1;
Ebusy:
	return 0;
}

struct nfs_sb_mountdata {
	struct nfs_server *server;
	int mntflags;
};

static int nfs_set_super(struct super_block *s, void *data)
{
	struct nfs_sb_mountdata *sb_mntdata = data;
	struct nfs_server *server = sb_mntdata->server;
	int ret;

	s->s_flags = sb_mntdata->mntflags;
	s->s_fs_info = server;
	s->s_d_op = server->nfs_client->rpc_ops->dentry_ops;
	ret = set_anon_super(s, server);
	if (ret == 0)
		server->s_dev = s->s_dev;
	return ret;
}

static int nfs_compare_super_address(struct nfs_server *server1,
				     struct nfs_server *server2)
{
	struct sockaddr *sap1, *sap2;

	sap1 = (struct sockaddr *)&server1->nfs_client->cl_addr;
	sap2 = (struct sockaddr *)&server2->nfs_client->cl_addr;

	if (sap1->sa_family != sap2->sa_family)
		return 0;

	switch (sap1->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin1 = (struct sockaddr_in *)sap1;
		struct sockaddr_in *sin2 = (struct sockaddr_in *)sap2;
		if (sin1->sin_addr.s_addr != sin2->sin_addr.s_addr)
			return 0;
		if (sin1->sin_port != sin2->sin_port)
			return 0;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin1 = (struct sockaddr_in6 *)sap1;
		struct sockaddr_in6 *sin2 = (struct sockaddr_in6 *)sap2;
		if (!ipv6_addr_equal(&sin1->sin6_addr, &sin2->sin6_addr))
			return 0;
		if (sin1->sin6_port != sin2->sin6_port)
			return 0;
		break;
	}
	default:
		return 0;
	}

	return 1;
}

static int nfs_compare_super(struct super_block *sb, void *data)
{
	struct nfs_sb_mountdata *sb_mntdata = data;
	struct nfs_server *server = sb_mntdata->server, *old = NFS_SB(sb);
	int mntflags = sb_mntdata->mntflags;

	if (!nfs_compare_super_address(old, server))
		return 0;
	/* Note: NFS_MOUNT_UNSHARED == NFS4_MOUNT_UNSHARED */
	if (old->flags & NFS_MOUNT_UNSHARED)
		return 0;
	if (memcmp(&old->fsid, &server->fsid, sizeof(old->fsid)) != 0)
		return 0;
	return nfs_compare_mount_options(sb, server, mntflags);
}

#ifdef CONFIG_NFS_FSCACHE
static void nfs_get_cache_cookie(struct super_block *sb,
				 struct nfs_parsed_mount_data *parsed,
				 struct nfs_clone_mount *cloned)
{
	struct nfs_server *nfss = NFS_SB(sb);
	char *uniq = NULL;
	int ulen = 0;

	nfss->fscache_key = NULL;
	nfss->fscache = NULL;

	if (parsed) {
		if (!(parsed->options & NFS_OPTION_FSCACHE))
			return;
		if (parsed->fscache_uniq) {
			uniq = parsed->fscache_uniq;
			ulen = strlen(parsed->fscache_uniq);
		}
	} else if (cloned) {
		struct nfs_server *mnt_s = NFS_SB(cloned->sb);
		if (!(mnt_s->options & NFS_OPTION_FSCACHE))
			return;
		if (mnt_s->fscache_key) {
			uniq = mnt_s->fscache_key->key.uniquifier;
			ulen = mnt_s->fscache_key->key.uniq_len;
		};
	} else
		return;

	nfs_fscache_get_super_cookie(sb, uniq, ulen);
}
#else
static void nfs_get_cache_cookie(struct super_block *sb,
				 struct nfs_parsed_mount_data *parsed,
				 struct nfs_clone_mount *cloned)
{
}
#endif

static int nfs_bdi_register(struct nfs_server *server)
{
	return bdi_register_dev(&server->backing_dev_info, server->s_dev);
}

int nfs_set_sb_security(struct super_block *s, struct dentry *mntroot,
			struct nfs_mount_info *mount_info)
{
	int error;
	unsigned long kflags = 0, kflags_out = 0;
	if (NFS_SB(s)->caps & NFS_CAP_SECURITY_LABEL)
		kflags |= SECURITY_LSM_NATIVE_LABELS;

	error = security_sb_set_mnt_opts(s, &mount_info->parsed->lsm_opts,
						kflags, &kflags_out);
	if (error)
		goto err;

	if (NFS_SB(s)->caps & NFS_CAP_SECURITY_LABEL &&
		!(kflags_out & SECURITY_LSM_NATIVE_LABELS))
		NFS_SB(s)->caps &= ~NFS_CAP_SECURITY_LABEL;
err:
	return error;
}
EXPORT_SYMBOL_GPL(nfs_set_sb_security);

int nfs_clone_sb_security(struct super_block *s, struct dentry *mntroot,
			  struct nfs_mount_info *mount_info)
{
	/* clone any lsm security options from the parent to the new sb */
	if (mntroot->d_inode->i_op != NFS_SB(s)->nfs_client->rpc_ops->dir_inode_ops)
		return -ESTALE;
	return security_sb_clone_mnt_opts(mount_info->cloned->sb, s);
}
EXPORT_SYMBOL_GPL(nfs_clone_sb_security);

struct dentry *nfs_fs_mount_common(struct nfs_server *server,
				   int flags, const char *dev_name,
				   struct nfs_mount_info *mount_info,
				   struct nfs_subversion *nfs_mod)
{
	struct super_block *s;
	struct dentry *mntroot = ERR_PTR(-ENOMEM);
	int (*compare_super)(struct super_block *, void *) = nfs_compare_super;
	struct nfs_sb_mountdata sb_mntdata = {
		.mntflags = flags,
		.server = server,
	};
	int error;

	if (server->flags & NFS_MOUNT_UNSHARED)
		compare_super = NULL;

	/* -o noac implies -o sync */
	if (server->flags & NFS_MOUNT_NOAC)
		sb_mntdata.mntflags |= MS_SYNCHRONOUS;

	if (mount_info->cloned != NULL && mount_info->cloned->sb != NULL)
		if (mount_info->cloned->sb->s_flags & MS_SYNCHRONOUS)
			sb_mntdata.mntflags |= MS_SYNCHRONOUS;

	/* Get a superblock - note that we may end up sharing one that already exists */
	s = sget(nfs_mod->nfs_fs, compare_super, nfs_set_super, flags, &sb_mntdata);
	if (IS_ERR(s)) {
		mntroot = ERR_CAST(s);
		goto out_err_nosb;
	}

	if (s->s_fs_info != server) {
		nfs_free_server(server);
		server = NULL;
	} else {
		error = nfs_bdi_register(server);
		if (error) {
			mntroot = ERR_PTR(error);
			goto error_splat_bdi;
		}
		server->super = s;
	}

	if (!s->s_root) {
		/* initial superblock/root creation */
		mount_info->fill_super(s, mount_info);
		nfs_get_cache_cookie(s, mount_info->parsed, mount_info->cloned);
	}

	mntroot = nfs_get_root(s, mount_info->mntfh, dev_name);
	if (IS_ERR(mntroot))
		goto error_splat_super;

	error = mount_info->set_security(s, mntroot, mount_info);
	if (error)
		goto error_splat_root;

	s->s_flags |= MS_ACTIVE;

out:
	return mntroot;

out_err_nosb:
	nfs_free_server(server);
	goto out;

error_splat_root:
	dput(mntroot);
	mntroot = ERR_PTR(error);
error_splat_super:
	if (server && !s->s_root)
		bdi_unregister(&server->backing_dev_info);
error_splat_bdi:
	deactivate_locked_super(s);
	goto out;
}
EXPORT_SYMBOL_GPL(nfs_fs_mount_common);

struct dentry *nfs_fs_mount(struct file_system_type *fs_type,
	int flags, const char *dev_name, void *raw_data)
{
	struct nfs_mount_info mount_info = {
		.fill_super = nfs_fill_super,
		.set_security = nfs_set_sb_security,
	};
	struct dentry *mntroot = ERR_PTR(-ENOMEM);
	struct nfs_subversion *nfs_mod;
	int error;

	mount_info.parsed = nfs_alloc_parsed_mount_data();
	mount_info.mntfh = nfs_alloc_fhandle();
	if (mount_info.parsed == NULL || mount_info.mntfh == NULL)
		goto out;

	/* Validate the mount data */
	error = nfs_validate_mount_data(fs_type, raw_data, mount_info.parsed, mount_info.mntfh, dev_name);
	if (error == NFS_TEXT_DATA)
		error = nfs_validate_text_mount_data(raw_data, mount_info.parsed, dev_name);
	if (error < 0) {
		mntroot = ERR_PTR(error);
		goto out;
	}

	nfs_mod = get_nfs_version(mount_info.parsed->version);
	if (IS_ERR(nfs_mod)) {
		mntroot = ERR_CAST(nfs_mod);
		goto out;
	}

	mntroot = nfs_mod->rpc_ops->try_mount(flags, dev_name, &mount_info, nfs_mod);

	put_nfs_version(nfs_mod);
out:
	nfs_free_parsed_mount_data(mount_info.parsed);
	nfs_free_fhandle(mount_info.mntfh);
	return mntroot;
}
EXPORT_SYMBOL_GPL(nfs_fs_mount);

/*
 * Ensure that we unregister the bdi before kill_anon_super
 * releases the device name
 */
void nfs_put_super(struct super_block *s)
{
	struct nfs_server *server = NFS_SB(s);

	bdi_unregister(&server->backing_dev_info);
}
EXPORT_SYMBOL_GPL(nfs_put_super);

/*
 * Destroy an NFS2/3 superblock
 */
void nfs_kill_super(struct super_block *s)
{
	struct nfs_server *server = NFS_SB(s);

	kill_anon_super(s);
	nfs_fscache_release_super_cookie(s);
	nfs_free_server(server);
}
EXPORT_SYMBOL_GPL(nfs_kill_super);

/*
 * Clone an NFS2/3/4 server record on xdev traversal (FSID-change)
 */
static struct dentry *
nfs_xdev_mount(struct file_system_type *fs_type, int flags,
		const char *dev_name, void *raw_data)
{
	struct nfs_clone_mount *data = raw_data;
	struct nfs_mount_info mount_info = {
		.fill_super = nfs_clone_super,
		.set_security = nfs_clone_sb_security,
		.cloned = data,
	};
	struct nfs_server *server;
	struct dentry *mntroot = ERR_PTR(-ENOMEM);
	struct nfs_subversion *nfs_mod = NFS_SB(data->sb)->nfs_client->cl_nfs_mod;

	dprintk("--> nfs_xdev_mount()\n");

	mount_info.mntfh = mount_info.cloned->fh;

	/* create a new volume representation */
	server = nfs_mod->rpc_ops->clone_server(NFS_SB(data->sb), data->fh, data->fattr, data->authflavor);

	if (IS_ERR(server))
		mntroot = ERR_CAST(server);
	else
		mntroot = nfs_fs_mount_common(server, flags,
				dev_name, &mount_info, nfs_mod);

	dprintk("<-- nfs_xdev_mount() = %ld\n",
			IS_ERR(mntroot) ? PTR_ERR(mntroot) : 0L);
	return mntroot;
}

#if IS_ENABLED(CONFIG_NFS_V4)

static void nfs4_validate_mount_flags(struct nfs_parsed_mount_data *args)
{
	args->flags &= ~(NFS_MOUNT_NONLM|NFS_MOUNT_NOACL|NFS_MOUNT_VER3|
			 NFS_MOUNT_LOCAL_FLOCK|NFS_MOUNT_LOCAL_FCNTL);
}

/*
 * Validate NFSv4 mount options
 */
static int nfs4_validate_mount_data(void *options,
				    struct nfs_parsed_mount_data *args,
				    const char *dev_name)
{
	struct sockaddr *sap = (struct sockaddr *)&args->nfs_server.address;
	struct nfs4_mount_data *data = (struct nfs4_mount_data *)options;
	char *c;

	if (data == NULL)
		goto out_no_data;

	args->version = 4;

	switch (data->version) {
	case 1:
		if (data->host_addrlen > sizeof(args->nfs_server.address))
			goto out_no_address;
		if (data->host_addrlen == 0)
			goto out_no_address;
		args->nfs_server.addrlen = data->host_addrlen;
		if (copy_from_user(sap, data->host_addr, data->host_addrlen))
			return -EFAULT;
		if (!nfs_verify_server_address(sap))
			goto out_no_address;
		args->nfs_server.port = ntohs(((struct sockaddr_in *)sap)->sin_port);

		if (data->auth_flavourlen) {
			rpc_authflavor_t pseudoflavor;
			if (data->auth_flavourlen > 1)
				goto out_inval_auth;
			if (copy_from_user(&pseudoflavor,
					   data->auth_flavours,
					   sizeof(pseudoflavor)))
				return -EFAULT;
			args->selected_flavor = pseudoflavor;
		} else
			args->selected_flavor = RPC_AUTH_UNIX;

		c = strndup_user(data->hostname.data, NFS4_MAXNAMLEN);
		if (IS_ERR(c))
			return PTR_ERR(c);
		args->nfs_server.hostname = c;

		c = strndup_user(data->mnt_path.data, NFS4_MAXPATHLEN);
		if (IS_ERR(c))
			return PTR_ERR(c);
		args->nfs_server.export_path = c;
		dfprintk(MOUNT, "NFS: MNTPATH: '%s'\n", c);

		c = strndup_user(data->client_addr.data, 16);
		if (IS_ERR(c))
			return PTR_ERR(c);
		args->client_address = c;

		/*
		 * Translate to nfs_parsed_mount_data, which nfs4_fill_super
		 * can deal with.
		 */

		args->flags	= data->flags & NFS4_MOUNT_FLAGMASK;
		args->rsize	= data->rsize;
		args->wsize	= data->wsize;
		args->timeo	= data->timeo;
		args->retrans	= data->retrans;
		args->acregmin	= data->acregmin;
		args->acregmax	= data->acregmax;
		args->acdirmin	= data->acdirmin;
		args->acdirmax	= data->acdirmax;
		args->nfs_server.protocol = data->proto;
		nfs_validate_transport_protocol(args);
		if (args->nfs_server.protocol == XPRT_TRANSPORT_UDP)
			goto out_invalid_transport_udp;

		break;
	default:
		return NFS_TEXT_DATA;
	}

	return 0;

out_no_data:
	dfprintk(MOUNT, "NFS4: mount program didn't pass any mount data\n");
	return -EINVAL;

out_inval_auth:
	dfprintk(MOUNT, "NFS4: Invalid number of RPC auth flavours %d\n",
		 data->auth_flavourlen);
	return -EINVAL;

out_no_address:
	dfprintk(MOUNT, "NFS4: mount program didn't pass remote address\n");
	return -EINVAL;

out_invalid_transport_udp:
	dfprintk(MOUNT, "NFSv4: Unsupported transport protocol udp\n");
	return -EINVAL;
}

/*
 * NFS v4 module parameters need to stay in the
 * NFS client for backwards compatibility
 */
unsigned int nfs_callback_set_tcpport;
unsigned short nfs_callback_tcpport;
/* Default cache timeout is 10 minutes */
unsigned int nfs_idmap_cache_timeout = 600;
/* Turn off NFSv4 uid/gid mapping when using AUTH_SYS */
bool nfs4_disable_idmapping = true;
unsigned short max_session_slots = NFS4_DEF_SLOT_TABLE_SIZE;
unsigned short send_implementation_id = 1;
char nfs4_client_id_uniquifier[NFS4_CLIENT_ID_UNIQ_LEN] = "";
bool recover_lost_locks = false;

EXPORT_SYMBOL_GPL(nfs_callback_set_tcpport);
EXPORT_SYMBOL_GPL(nfs_callback_tcpport);
EXPORT_SYMBOL_GPL(nfs_idmap_cache_timeout);
EXPORT_SYMBOL_GPL(nfs4_disable_idmapping);
EXPORT_SYMBOL_GPL(max_session_slots);
EXPORT_SYMBOL_GPL(send_implementation_id);
EXPORT_SYMBOL_GPL(nfs4_client_id_uniquifier);
EXPORT_SYMBOL_GPL(recover_lost_locks);

#define NFS_CALLBACK_MAXPORTNR (65535U)

static int param_set_portnr(const char *val, const struct kernel_param *kp)
{
	unsigned long num;
	int ret;

	if (!val)
		return -EINVAL;
	ret = kstrtoul(val, 0, &num);
	if (ret == -EINVAL || num > NFS_CALLBACK_MAXPORTNR)
		return -EINVAL;
	*((unsigned int *)kp->arg) = num;
	return 0;
}
static struct kernel_param_ops param_ops_portnr = {
	.set = param_set_portnr,
	.get = param_get_uint,
};
#define param_check_portnr(name, p) __param_check(name, p, unsigned int);

module_param_named(callback_tcpport, nfs_callback_set_tcpport, portnr, 0644);
module_param(nfs_idmap_cache_timeout, int, 0644);
module_param(nfs4_disable_idmapping, bool, 0644);
module_param_string(nfs4_unique_id, nfs4_client_id_uniquifier,
			NFS4_CLIENT_ID_UNIQ_LEN, 0600);
MODULE_PARM_DESC(nfs4_disable_idmapping,
		"Turn off NFSv4 idmapping when using 'sec=sys'");
module_param(max_session_slots, ushort, 0644);
MODULE_PARM_DESC(max_session_slots, "Maximum number of outstanding NFSv4.1 "
		"requests the client will negotiate");
module_param(send_implementation_id, ushort, 0644);
MODULE_PARM_DESC(send_implementation_id,
		"Send implementation ID with NFSv4.1 exchange_id");
MODULE_PARM_DESC(nfs4_unique_id, "nfs_client_id4 uniquifier string");

module_param(recover_lost_locks, bool, 0644);
MODULE_PARM_DESC(recover_lost_locks,
		 "If the server reports that a lock might be lost, "
		 "try to recover it risking data corruption.");


#endif /* CONFIG_NFS_V4 */
/************************************************************/
/* ../linux-3.17/fs/nfs/super.c */
/************************************************************/
/*
 * linux/fs/nfs/direct.c
 *
 * Copyright (C) 2003 by Chuck Lever <cel@netapp.com>
 *
 * High-performance uncached I/O for the Linux NFS client
 *
 * There are important applications whose performance or correctness
 * depends on uncached access to file data.  Database clusters
 * (multiple copies of the same instance running on separate hosts)
 * implement their own cache coherency protocol that subsumes file
 * system cache protocols.  Applications that process datasets
 * considerably larger than the client's memory do not always benefit
 * from a local cache.  A streaming video server, for instance, has no
 * need to cache the contents of a file.
 *
 * When an application requests uncached I/O, all read and write requests
 * are made directly to the server; data stored or fetched via these
 * requests is not cached in the Linux page cache.  The client does not
 * correct unaligned requests from applications.  All requested bytes are
 * held on permanent storage before a direct write system call returns to
 * an application.
 *
 * Solaris implements an uncached I/O facility called directio() that
 * is used for backups and sequential I/O to very large files.  Solaris
 * also supports uncaching whole NFS partitions with "-o forcedirectio,"
 * an undocumented mount option.
 *
 * Designed by Jeff Kimmel, Chuck Lever, and Trond Myklebust, with
 * help from Andrew Morton.
 *
 * 18 Dec 2001	Initial implementation for 2.4  --cel
 * 08 Jul 2002	Version for 2.4.19, with bug fixes --trondmy
 * 08 Jun 2003	Port to 2.5 APIs  --cel
 * 31 Mar 2004	Handle direct I/O without VFS support  --cel
 * 15 Sep 2004	Parallel async reads  --cel
 * 04 May 2005	support O_DIRECT with aio  --cel
 *
 */

// #include <linux/errno.h>
// #include <linux/sched.h>
// #include <linux/kernel.h>
#include <linux/file.h>
// #include <linux/pagemap.h>
#include <linux/kref.h>
// #include <linux/slab.h>
#include <linux/task_io_accounting_ops.h>
// #include <linux/module.h>

// #include <linux/nfs_fs.h>
#include <linux/nfs_page.h>
// #include <linux/sunrpc/clnt.h>

// #include <asm/uaccess.h>
#include <linux/atomic.h>

// #include "internal.h"
// #include "iostat.h"
// #include "pnfs.h"

#define NFSDBG_FACILITY		NFSDBG_VFS

static struct kmem_cache *nfs_direct_cachep;

/*
 * This represents a set of asynchronous requests that we're waiting on
 */
struct nfs_direct_req {
	struct kref		kref;		/* release manager */

	/* I/O parameters */
	struct nfs_open_context	*ctx;		/* file open context info */
	struct nfs_lock_context *l_ctx;		/* Lock context info */
	struct kiocb *		iocb;		/* controlling i/o request */
	struct inode *		inode;		/* target file of i/o */

	/* completion state */
	atomic_t		io_count;	/* i/os we're waiting for */
	spinlock_t		lock;		/* protect completion state */
	ssize_t			count,		/* bytes actually processed */
				bytes_left,	/* bytes left to be sent */
				error;		/* any reported error */
	struct completion	completion;	/* wait for i/o completion */

	/* commit state */
	struct nfs_mds_commit_info mds_cinfo;	/* Storage for cinfo */
	struct pnfs_ds_commit_info ds_cinfo;	/* Storage for cinfo */
	struct work_struct	work;
	int			flags;
#define NFS_ODIRECT_DO_COMMIT		(1)	/* an unstable reply was received */
#define NFS_ODIRECT_RESCHED_WRITES	(2)	/* write verification failed */
	struct nfs_writeverf	verf;		/* unstable write verifier */
};

static const struct nfs_pgio_completion_ops nfs_direct_write_completion_ops;
static const struct nfs_commit_completion_ops nfs_direct_commit_completion_ops;
static void nfs_direct_write_complete(struct nfs_direct_req *dreq, struct inode *inode);
static void nfs_direct_write_schedule_work(struct work_struct *work);

static inline void get_dreq(struct nfs_direct_req *dreq)
{
	atomic_inc(&dreq->io_count);
}

static inline int put_dreq(struct nfs_direct_req *dreq)
{
	return atomic_dec_and_test(&dreq->io_count);
}

/*
 * nfs_direct_select_verf - select the right verifier
 * @dreq - direct request possibly spanning multiple servers
 * @ds_clp - nfs_client of data server or NULL if MDS / non-pnfs
 * @ds_idx - index of data server in data server list, only valid if ds_clp set
 *
 * returns the correct verifier to use given the role of the server
 */
static struct nfs_writeverf *
nfs_direct_select_verf(struct nfs_direct_req *dreq,
		       struct nfs_client *ds_clp,
		       int ds_idx)
{
	struct nfs_writeverf *verfp = &dreq->verf;

#ifdef CONFIG_NFS_V4_1
	if (ds_clp) {
		/* pNFS is in use, use the DS verf */
		if (ds_idx >= 0 && ds_idx < dreq->ds_cinfo.nbuckets)
			verfp = &dreq->ds_cinfo.buckets[ds_idx].direct_verf;
		else
			WARN_ON_ONCE(1);
	}
#endif
	return verfp;
}


/*
 * nfs_direct_set_hdr_verf - set the write/commit verifier
 * @dreq - direct request possibly spanning multiple servers
 * @hdr - pageio header to validate against previously seen verfs
 *
 * Set the server's (MDS or DS) "seen" verifier
 */
static void nfs_direct_set_hdr_verf(struct nfs_direct_req *dreq,
				    struct nfs_pgio_header *hdr)
{
	struct nfs_writeverf *verfp;

	verfp = nfs_direct_select_verf(dreq, hdr->ds_clp,
				      hdr->ds_idx);
	WARN_ON_ONCE(verfp->committed >= 0);
	memcpy(verfp, &hdr->verf, sizeof(struct nfs_writeverf));
	WARN_ON_ONCE(verfp->committed < 0);
}

/*
 * nfs_direct_cmp_hdr_verf - compare verifier for pgio header
 * @dreq - direct request possibly spanning multiple servers
 * @hdr - pageio header to validate against previously seen verf
 *
 * set the server's "seen" verf if not initialized.
 * returns result of comparison between @hdr->verf and the "seen"
 * verf of the server used by @hdr (DS or MDS)
 */
static int nfs_direct_set_or_cmp_hdr_verf(struct nfs_direct_req *dreq,
					  struct nfs_pgio_header *hdr)
{
	struct nfs_writeverf *verfp;

	verfp = nfs_direct_select_verf(dreq, hdr->ds_clp,
					 hdr->ds_idx);
	if (verfp->committed < 0) {
		nfs_direct_set_hdr_verf(dreq, hdr);
		return 0;
	}
	return memcmp(verfp, &hdr->verf, sizeof(struct nfs_writeverf));
}

#if IS_ENABLED(CONFIG_NFS_V3) || IS_ENABLED(CONFIG_NFS_V4)
/*
 * nfs_direct_cmp_commit_data_verf - compare verifier for commit data
 * @dreq - direct request possibly spanning multiple servers
 * @data - commit data to validate against previously seen verf
 *
 * returns result of comparison between @data->verf and the verf of
 * the server used by @data (DS or MDS)
 */
static int nfs_direct_cmp_commit_data_verf(struct nfs_direct_req *dreq,
					   struct nfs_commit_data *data)
{
	struct nfs_writeverf *verfp;

	verfp = nfs_direct_select_verf(dreq, data->ds_clp,
					 data->ds_commit_index);
	WARN_ON_ONCE(verfp->committed < 0);
	return memcmp(verfp, &data->verf, sizeof(struct nfs_writeverf));
}
#endif

/**
 * nfs_direct_IO - NFS address space operation for direct I/O
 * @rw: direction (read or write)
 * @iocb: target I/O control block
 * @iov: array of vectors that define I/O buffer
 * @pos: offset in file to begin the operation
 * @nr_segs: size of iovec array
 *
 * The presence of this routine in the address space ops vector means
 * the NFS client supports direct I/O. However, for most direct IO, we
 * shunt off direct read and write requests before the VFS gets them,
 * so this method is only ever called for swap.
 */
ssize_t nfs_direct_IO(int rw, struct kiocb *iocb, struct iov_iter *iter, loff_t pos)
{
#ifndef CONFIG_NFS_SWAP
	dprintk("NFS: nfs_direct_IO (%pD) off/no(%Ld/%lu) EINVAL\n",
			iocb->ki_filp, (long long) pos, iter->nr_segs);

	return -EINVAL;
#else
	VM_BUG_ON(iocb->ki_nbytes != PAGE_SIZE);

	if (rw == READ || rw == KERNEL_READ)
		return nfs_file_direct_read(iocb, iter, pos,
				rw == READ ? true : false);
	return nfs_file_direct_write(iocb, iter, pos,
				rw == WRITE ? true : false);
#endif /* CONFIG_NFS_SWAP */
}

static void nfs_direct_release_pages(struct page **pages, unsigned int npages)
{
	unsigned int i;
	for (i = 0; i < npages; i++)
		page_cache_release(pages[i]);
}

void nfs_init_cinfo_from_dreq(struct nfs_commit_info *cinfo,
			      struct nfs_direct_req *dreq)
{
	cinfo->lock = &dreq->lock;
	cinfo->mds = &dreq->mds_cinfo;
	cinfo->ds = &dreq->ds_cinfo;
	cinfo->dreq = dreq;
	cinfo->completion_ops = &nfs_direct_commit_completion_ops;
}

static inline struct nfs_direct_req *nfs_direct_req_alloc(void)
{
	struct nfs_direct_req *dreq;

	dreq = kmem_cache_zalloc(nfs_direct_cachep, GFP_KERNEL);
	if (!dreq)
		return NULL;

	kref_init(&dreq->kref);
	kref_get(&dreq->kref);
	init_completion(&dreq->completion);
	INIT_LIST_HEAD(&dreq->mds_cinfo.list);
	dreq->verf.committed = NFS_INVALID_STABLE_HOW;	/* not set yet */
	INIT_WORK(&dreq->work, nfs_direct_write_schedule_work);
	spin_lock_init(&dreq->lock);

	return dreq;
}

static void nfs_direct_req_free(struct kref *kref)
{
	struct nfs_direct_req *dreq = container_of(kref, struct nfs_direct_req, kref);

	if (dreq->l_ctx != NULL)
		nfs_put_lock_context(dreq->l_ctx);
	if (dreq->ctx != NULL)
		put_nfs_open_context(dreq->ctx);
	kmem_cache_free(nfs_direct_cachep, dreq);
}

static void nfs_direct_req_release(struct nfs_direct_req *dreq)
{
	kref_put(&dreq->kref, nfs_direct_req_free);
}

ssize_t nfs_dreq_bytes_left(struct nfs_direct_req *dreq)
{
	return dreq->bytes_left;
}
EXPORT_SYMBOL_GPL(nfs_dreq_bytes_left);

/*
 * Collects and returns the final error value/byte-count.
 */
static ssize_t nfs_direct_wait(struct nfs_direct_req *dreq)
{
	ssize_t result = -EIOCBQUEUED;

	/* Async requests don't wait here */
	if (dreq->iocb)
		goto out;

	result = wait_for_completion_killable(&dreq->completion);

	if (!result)
		result = dreq->error;
	if (!result)
		result = dreq->count;

out:
	return (ssize_t) result;
}

/*
 * Synchronous I/O uses a stack-allocated iocb.  Thus we can't trust
 * the iocb is still valid here if this is a synchronous request.
 */
static void nfs_direct_complete(struct nfs_direct_req *dreq, bool write)
{
	struct inode *inode = dreq->inode;

	if (dreq->iocb && write) {
		loff_t pos = dreq->iocb->ki_pos + dreq->count;

		spin_lock(&inode->i_lock);
		if (i_size_read(inode) < pos)
			i_size_write(inode, pos);
		spin_unlock(&inode->i_lock);
	}

	if (write)
		nfs_zap_mapping(inode, inode->i_mapping);

	inode_dio_done(inode);

	if (dreq->iocb) {
		long res = (long) dreq->error;
		if (!res)
			res = (long) dreq->count;
		aio_complete(dreq->iocb, res, 0);
	}

	complete_all(&dreq->completion);

	nfs_direct_req_release(dreq);
}

static void nfs_direct_readpage_release(struct nfs_page *req)
{
	dprintk("NFS: direct read done (%s/%llu %d@%lld)\n",
		req->wb_context->dentry->d_inode->i_sb->s_id,
		(unsigned long long)NFS_FILEID(req->wb_context->dentry->d_inode),
		req->wb_bytes,
		(long long)req_offset(req));
	nfs_release_request(req);
}

static void nfs_direct_read_completion(struct nfs_pgio_header *hdr)
{
	unsigned long bytes = 0;
	struct nfs_direct_req *dreq = hdr->dreq;

	if (test_bit(NFS_IOHDR_REDO, &hdr->flags))
		goto out_put;

	spin_lock(&dreq->lock);
	if (test_bit(NFS_IOHDR_ERROR, &hdr->flags) && (hdr->good_bytes == 0))
		dreq->error = hdr->error;
	else
		dreq->count += hdr->good_bytes;
	spin_unlock(&dreq->lock);

	while (!list_empty(&hdr->pages)) {
		struct nfs_page *req = nfs_list_entry(hdr->pages.next);
		struct page *page = req->wb_page;

		if (!PageCompound(page) && bytes < hdr->good_bytes)
			set_page_dirty(page);
		bytes += req->wb_bytes;
		nfs_list_remove_request(req);
		nfs_direct_readpage_release(req);
	}
out_put:
	if (put_dreq(dreq))
		nfs_direct_complete(dreq, false);
	hdr->release(hdr);
}

static void nfs_read_sync_pgio_error(struct list_head *head)
{
	struct nfs_page *req;

	while (!list_empty(head)) {
		req = nfs_list_entry(head->next);
		nfs_list_remove_request(req);
		nfs_release_request(req);
	}
}

static void nfs_direct_pgio_init(struct nfs_pgio_header *hdr)
{
	get_dreq(hdr->dreq);
}

static const struct nfs_pgio_completion_ops nfs_direct_read_completion_ops = {
	.error_cleanup = nfs_read_sync_pgio_error,
	.init_hdr = nfs_direct_pgio_init,
	.completion = nfs_direct_read_completion,
};

/*
 * For each rsize'd chunk of the user's buffer, dispatch an NFS READ
 * operation.  If nfs_readdata_alloc() or get_user_pages() fails,
 * bail and stop sending more reads.  Read length accounting is
 * handled automatically by nfs_direct_read_result().  Otherwise, if
 * no requests have been sent, just return an error.
 */

static ssize_t nfs_direct_read_schedule_iovec(struct nfs_direct_req *dreq,
					      struct iov_iter *iter,
					      loff_t pos)
{
	struct nfs_pageio_descriptor desc;
	struct inode *inode = dreq->inode;
	ssize_t result = -EINVAL;
	size_t requested_bytes = 0;
	size_t rsize = max_t(size_t, NFS_SERVER(inode)->rsize, PAGE_SIZE);

	nfs_pageio_init_read(&desc, dreq->inode, false,
			     &nfs_direct_read_completion_ops);
	get_dreq(dreq);
	desc.pg_dreq = dreq;
	atomic_inc(&inode->i_dio_count);

	while (iov_iter_count(iter)) {
		struct page **pagevec;
		size_t bytes;
		size_t pgbase;
		unsigned npages, i;

		result = iov_iter_get_pages_alloc(iter, &pagevec,
						  rsize, &pgbase);
		if (result < 0)
			break;

		bytes = result;
		iov_iter_advance(iter, bytes);
		npages = (result + pgbase + PAGE_SIZE - 1) / PAGE_SIZE;
		for (i = 0; i < npages; i++) {
			struct nfs_page *req;
			unsigned int req_len = min_t(size_t, bytes, PAGE_SIZE - pgbase);
			/* XXX do we need to do the eof zeroing found in async_filler? */
			req = nfs_create_request(dreq->ctx, pagevec[i], NULL,
						 pgbase, req_len);
			if (IS_ERR(req)) {
				result = PTR_ERR(req);
				break;
			}
			req->wb_index = pos >> PAGE_SHIFT;
			req->wb_offset = pos & ~PAGE_MASK;
			if (!nfs_pageio_add_request(&desc, req)) {
				result = desc.pg_error;
				nfs_release_request(req);
				break;
			}
			pgbase = 0;
			bytes -= req_len;
			requested_bytes += req_len;
			pos += req_len;
			dreq->bytes_left -= req_len;
		}
		nfs_direct_release_pages(pagevec, npages);
		kvfree(pagevec);
		if (result < 0)
			break;
	}

	nfs_pageio_complete(&desc);

	/*
	 * If no bytes were started, return the error, and let the
	 * generic layer handle the completion.
	 */
	if (requested_bytes == 0) {
		inode_dio_done(inode);
		nfs_direct_req_release(dreq);
		return result < 0 ? result : -EIO;
	}

	if (put_dreq(dreq))
		nfs_direct_complete(dreq, false);
	return 0;
}

/**
 * nfs_file_direct_read - file direct read operation for NFS files
 * @iocb: target I/O control block
 * @iter: vector of user buffers into which to read data
 * @pos: byte offset in file where reading starts
 *
 * We use this function for direct reads instead of calling
 * generic_file_aio_read() in order to avoid gfar's check to see if
 * the request starts before the end of the file.  For that check
 * to work, we must generate a GETATTR before each direct read, and
 * even then there is a window between the GETATTR and the subsequent
 * READ where the file size could change.  Our preference is simply
 * to do all reads the application wants, and the server will take
 * care of managing the end of file boundary.
 *
 * This function also eliminates unnecessarily updating the file's
 * atime locally, as the NFS server sets the file's atime, and this
 * client must read the updated atime from the server back into its
 * cache.
 */
ssize_t nfs_file_direct_read(struct kiocb *iocb, struct iov_iter *iter,
				loff_t pos, bool uio)
{
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct nfs_direct_req *dreq;
	struct nfs_lock_context *l_ctx;
	ssize_t result = -EINVAL;
	size_t count = iov_iter_count(iter);
	nfs_add_stats(mapping->host, NFSIOS_DIRECTREADBYTES, count);

	dfprintk(FILE, "NFS: direct read(%pD2, %zd@%Ld)\n",
		file, count, (long long) pos);

	result = 0;
	if (!count)
		goto out;

	mutex_lock(&inode->i_mutex);
	result = nfs_sync_mapping(mapping);
	if (result)
		goto out_unlock;

	task_io_account_read(count);

	result = -ENOMEM;
	dreq = nfs_direct_req_alloc();
	if (dreq == NULL)
		goto out_unlock;

	dreq->inode = inode;
	dreq->bytes_left = count;
	dreq->ctx = get_nfs_open_context(nfs_file_open_context(iocb->ki_filp));
	l_ctx = nfs_get_lock_context(dreq->ctx);
	if (IS_ERR(l_ctx)) {
		result = PTR_ERR(l_ctx);
		goto out_release;
	}
	dreq->l_ctx = l_ctx;
	if (!is_sync_kiocb(iocb))
		dreq->iocb = iocb;

	NFS_I(inode)->read_io += count;
	result = nfs_direct_read_schedule_iovec(dreq, iter, pos);

	mutex_unlock(&inode->i_mutex);

	if (!result) {
		result = nfs_direct_wait(dreq);
		if (result > 0)
			iocb->ki_pos = pos + result;
	}

	nfs_direct_req_release(dreq);
	return result;

out_release:
	nfs_direct_req_release(dreq);
out_unlock:
	mutex_unlock(&inode->i_mutex);
out:
	return result;
}

#if IS_ENABLED(CONFIG_NFS_V3) || IS_ENABLED(CONFIG_NFS_V4)
static void nfs_direct_write_reschedule(struct nfs_direct_req *dreq)
{
	struct nfs_pageio_descriptor desc;
	struct nfs_page *req, *tmp;
	LIST_HEAD(reqs);
	struct nfs_commit_info cinfo;
	LIST_HEAD(failed);

	nfs_init_cinfo_from_dreq(&cinfo, dreq);
	pnfs_recover_commit_reqs(dreq->inode, &reqs, &cinfo);
	spin_lock(cinfo.lock);
	nfs_scan_commit_list(&cinfo.mds->list, &reqs, &cinfo, 0);
	spin_unlock(cinfo.lock);

	dreq->count = 0;
	get_dreq(dreq);

	nfs_pageio_init_write(&desc, dreq->inode, FLUSH_STABLE, false,
			      &nfs_direct_write_completion_ops);
	desc.pg_dreq = dreq;

	list_for_each_entry_safe(req, tmp, &reqs, wb_list) {
		if (!nfs_pageio_add_request(&desc, req)) {
			nfs_list_remove_request(req);
			nfs_list_add_request(req, &failed);
			spin_lock(cinfo.lock);
			dreq->flags = 0;
			dreq->error = -EIO;
			spin_unlock(cinfo.lock);
		}
		nfs_release_request(req);
	}
	nfs_pageio_complete(&desc);

	while (!list_empty(&failed)) {
		req = nfs_list_entry(failed.next);
		nfs_list_remove_request(req);
		nfs_unlock_and_release_request(req);
	}

	if (put_dreq(dreq))
		nfs_direct_write_complete(dreq, dreq->inode);
}

static void nfs_direct_commit_complete(struct nfs_commit_data *data)
{
	struct nfs_direct_req *dreq = data->dreq;
	struct nfs_commit_info cinfo;
	struct nfs_page *req;
	int status = data->task.tk_status;

	nfs_init_cinfo_from_dreq(&cinfo, dreq);
	if (status < 0) {
		dprintk("NFS: %5u commit failed with error %d.\n",
			data->task.tk_pid, status);
		dreq->flags = NFS_ODIRECT_RESCHED_WRITES;
	} else if (nfs_direct_cmp_commit_data_verf(dreq, data)) {
		dprintk("NFS: %5u commit verify failed\n", data->task.tk_pid);
		dreq->flags = NFS_ODIRECT_RESCHED_WRITES;
	}

	dprintk("NFS: %5u commit returned %d\n", data->task.tk_pid, status);
	while (!list_empty(&data->pages)) {
		req = nfs_list_entry(data->pages.next);
		nfs_list_remove_request(req);
		if (dreq->flags == NFS_ODIRECT_RESCHED_WRITES) {
			/* Note the rewrite will go through mds */
			nfs_mark_request_commit(req, NULL, &cinfo);
		} else
			nfs_release_request(req);
		nfs_unlock_and_release_request(req);
	}

	if (atomic_dec_and_test(&cinfo.mds->rpcs_out))
		nfs_direct_write_complete(dreq, data->inode);
}

static void nfs_direct_error_cleanup(struct nfs_inode *nfsi)
{
	/* There is no lock to clear */
}

static const struct nfs_commit_completion_ops nfs_direct_commit_completion_ops = {
	.completion = nfs_direct_commit_complete,
	.error_cleanup = nfs_direct_error_cleanup,
};

static void nfs_direct_commit_schedule(struct nfs_direct_req *dreq)
{
	int res;
	struct nfs_commit_info cinfo;
	LIST_HEAD(mds_list);

	nfs_init_cinfo_from_dreq(&cinfo, dreq);
	nfs_scan_commit(dreq->inode, &mds_list, &cinfo);
	res = nfs_generic_commit_list(dreq->inode, &mds_list, 0, &cinfo);
	if (res < 0) /* res == -ENOMEM */
		nfs_direct_write_reschedule(dreq);
}

static void nfs_direct_write_schedule_work(struct work_struct *work)
{
	struct nfs_direct_req *dreq = container_of(work, struct nfs_direct_req, work);
	int flags = dreq->flags;

	dreq->flags = 0;
	switch (flags) {
		case NFS_ODIRECT_DO_COMMIT:
			nfs_direct_commit_schedule(dreq);
			break;
		case NFS_ODIRECT_RESCHED_WRITES:
			nfs_direct_write_reschedule(dreq);
			break;
		default:
			nfs_direct_complete(dreq, true);
	}
}

static void nfs_direct_write_complete(struct nfs_direct_req *dreq, struct inode *inode)
{
	schedule_work(&dreq->work); /* Calls nfs_direct_write_schedule_work */
}

#else
static void nfs_direct_write_schedule_work(struct work_struct *work)
{
}

static void nfs_direct_write_complete(struct nfs_direct_req *dreq, struct inode *inode)
{
	nfs_direct_complete(dreq, true);
}
#endif

static void nfs_direct_write_completion(struct nfs_pgio_header *hdr)
{
	struct nfs_direct_req *dreq = hdr->dreq;
	struct nfs_commit_info cinfo;
	bool request_commit = false;
	struct nfs_page *req = nfs_list_entry(hdr->pages.next);

	if (test_bit(NFS_IOHDR_REDO, &hdr->flags))
		goto out_put;

	nfs_init_cinfo_from_dreq(&cinfo, dreq);

	spin_lock(&dreq->lock);

	if (test_bit(NFS_IOHDR_ERROR, &hdr->flags)) {
		dreq->flags = 0;
		dreq->error = hdr->error;
	}
	if (dreq->error == 0) {
		dreq->count += hdr->good_bytes;
		if (nfs_write_need_commit(hdr)) {
			if (dreq->flags == NFS_ODIRECT_RESCHED_WRITES)
				request_commit = true;
			else if (dreq->flags == 0) {
				nfs_direct_set_hdr_verf(dreq, hdr);
				request_commit = true;
				dreq->flags = NFS_ODIRECT_DO_COMMIT;
			} else if (dreq->flags == NFS_ODIRECT_DO_COMMIT) {
				request_commit = true;
				if (nfs_direct_set_or_cmp_hdr_verf(dreq, hdr))
					dreq->flags =
						NFS_ODIRECT_RESCHED_WRITES;
			}
		}
	}
	spin_unlock(&dreq->lock);

	while (!list_empty(&hdr->pages)) {

		req = nfs_list_entry(hdr->pages.next);
		nfs_list_remove_request(req);
		if (request_commit) {
			kref_get(&req->wb_kref);
			nfs_mark_request_commit(req, hdr->lseg, &cinfo);
		}
		nfs_unlock_and_release_request(req);
	}

out_put:
	if (put_dreq(dreq))
		nfs_direct_write_complete(dreq, hdr->inode);
	hdr->release(hdr);
}

static void nfs_write_sync_pgio_error(struct list_head *head)
{
	struct nfs_page *req;

	while (!list_empty(head)) {
		req = nfs_list_entry(head->next);
		nfs_list_remove_request(req);
		nfs_unlock_and_release_request(req);
	}
}

static const struct nfs_pgio_completion_ops nfs_direct_write_completion_ops = {
	.error_cleanup = nfs_write_sync_pgio_error,
	.init_hdr = nfs_direct_pgio_init,
	.completion = nfs_direct_write_completion,
};


/*
 * NB: Return the value of the first error return code.  Subsequent
 *     errors after the first one are ignored.
 */
/*
 * For each wsize'd chunk of the user's buffer, dispatch an NFS WRITE
 * operation.  If nfs_writedata_alloc() or get_user_pages() fails,
 * bail and stop sending more writes.  Write length accounting is
 * handled automatically by nfs_direct_write_result().  Otherwise, if
 * no requests have been sent, just return an error.
 */
static ssize_t nfs_direct_write_schedule_iovec(struct nfs_direct_req *dreq,
					       struct iov_iter *iter,
					       loff_t pos)
{
	struct nfs_pageio_descriptor desc;
	struct inode *inode = dreq->inode;
	ssize_t result = 0;
	size_t requested_bytes = 0;
	size_t wsize = max_t(size_t, NFS_SERVER(inode)->wsize, PAGE_SIZE);

	nfs_pageio_init_write(&desc, inode, FLUSH_COND_STABLE, false,
			      &nfs_direct_write_completion_ops);
	desc.pg_dreq = dreq;
	get_dreq(dreq);
	atomic_inc(&inode->i_dio_count);

	NFS_I(inode)->write_io += iov_iter_count(iter);
	while (iov_iter_count(iter)) {
		struct page **pagevec;
		size_t bytes;
		size_t pgbase;
		unsigned npages, i;

		result = iov_iter_get_pages_alloc(iter, &pagevec,
						  wsize, &pgbase);
		if (result < 0)
			break;

		bytes = result;
		iov_iter_advance(iter, bytes);
		npages = (result + pgbase + PAGE_SIZE - 1) / PAGE_SIZE;
		for (i = 0; i < npages; i++) {
			struct nfs_page *req;
			unsigned int req_len = min_t(size_t, bytes, PAGE_SIZE - pgbase);

			req = nfs_create_request(dreq->ctx, pagevec[i], NULL,
						 pgbase, req_len);
			if (IS_ERR(req)) {
				result = PTR_ERR(req);
				break;
			}
			nfs_lock_request(req);
			req->wb_index = pos >> PAGE_SHIFT;
			req->wb_offset = pos & ~PAGE_MASK;
			if (!nfs_pageio_add_request(&desc, req)) {
				result = desc.pg_error;
				nfs_unlock_and_release_request(req);
				break;
			}
			pgbase = 0;
			bytes -= req_len;
			requested_bytes += req_len;
			pos += req_len;
			dreq->bytes_left -= req_len;
		}
		nfs_direct_release_pages(pagevec, npages);
		kvfree(pagevec);
		if (result < 0)
			break;
	}
	nfs_pageio_complete(&desc);

	/*
	 * If no bytes were started, return the error, and let the
	 * generic layer handle the completion.
	 */
	if (requested_bytes == 0) {
		inode_dio_done(inode);
		nfs_direct_req_release(dreq);
		return result < 0 ? result : -EIO;
	}

	if (put_dreq(dreq))
		nfs_direct_write_complete(dreq, dreq->inode);
	return 0;
}

/**
 * nfs_file_direct_write - file direct write operation for NFS files
 * @iocb: target I/O control block
 * @iter: vector of user buffers from which to write data
 * @pos: byte offset in file where writing starts
 *
 * We use this function for direct writes instead of calling
 * generic_file_aio_write() in order to avoid taking the inode
 * semaphore and updating the i_size.  The NFS server will set
 * the new i_size and this client must read the updated size
 * back into its cache.  We let the server do generic write
 * parameter checking and report problems.
 *
 * We eliminate local atime updates, see direct read above.
 *
 * We avoid unnecessary page cache invalidations for normal cached
 * readers of this file.
 *
 * Note that O_APPEND is not supported for NFS direct writes, as there
 * is no atomic O_APPEND write facility in the NFS protocol.
 */
ssize_t nfs_file_direct_write(struct kiocb *iocb, struct iov_iter *iter,
				loff_t pos, bool uio)
{
	ssize_t result = -EINVAL;
	struct file *file = iocb->ki_filp;
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = mapping->host;
	struct nfs_direct_req *dreq;
	struct nfs_lock_context *l_ctx;
	loff_t end;
	size_t count = iov_iter_count(iter);
	end = (pos + count - 1) >> PAGE_CACHE_SHIFT;

	nfs_add_stats(mapping->host, NFSIOS_DIRECTWRITTENBYTES, count);

	dfprintk(FILE, "NFS: direct write(%pD2, %zd@%Ld)\n",
		file, count, (long long) pos);

	result = generic_write_checks(file, &pos, &count, 0);
	if (result)
		goto out;

	result = -EINVAL;
	if ((ssize_t) count < 0)
		goto out;
	result = 0;
	if (!count)
		goto out;

	mutex_lock(&inode->i_mutex);

	result = nfs_sync_mapping(mapping);
	if (result)
		goto out_unlock;

	if (mapping->nrpages) {
		result = invalidate_inode_pages2_range(mapping,
					pos >> PAGE_CACHE_SHIFT, end);
		if (result)
			goto out_unlock;
	}

	task_io_account_write(count);

	result = -ENOMEM;
	dreq = nfs_direct_req_alloc();
	if (!dreq)
		goto out_unlock;

	dreq->inode = inode;
	dreq->bytes_left = count;
	dreq->ctx = get_nfs_open_context(nfs_file_open_context(iocb->ki_filp));
	l_ctx = nfs_get_lock_context(dreq->ctx);
	if (IS_ERR(l_ctx)) {
		result = PTR_ERR(l_ctx);
		goto out_release;
	}
	dreq->l_ctx = l_ctx;
	if (!is_sync_kiocb(iocb))
		dreq->iocb = iocb;

	result = nfs_direct_write_schedule_iovec(dreq, iter, pos);

	if (mapping->nrpages) {
		invalidate_inode_pages2_range(mapping,
					      pos >> PAGE_CACHE_SHIFT, end);
	}

	mutex_unlock(&inode->i_mutex);

	if (!result) {
		result = nfs_direct_wait(dreq);
		if (result > 0) {
			struct inode *inode = mapping->host;

			iocb->ki_pos = pos + result;
			spin_lock(&inode->i_lock);
			if (i_size_read(inode) < iocb->ki_pos)
				i_size_write(inode, iocb->ki_pos);
			spin_unlock(&inode->i_lock);
		}
	}
	nfs_direct_req_release(dreq);
	return result;

out_release:
	nfs_direct_req_release(dreq);
out_unlock:
	mutex_unlock(&inode->i_mutex);
out:
	return result;
}

/**
 * nfs_init_directcache - create a slab cache for nfs_direct_req structures
 *
 */
int __init nfs_init_directcache(void)
{
	nfs_direct_cachep = kmem_cache_create("nfs_direct_cache",
						sizeof(struct nfs_direct_req),
						0, (SLAB_RECLAIM_ACCOUNT|
							SLAB_MEM_SPREAD),
						NULL);
	if (nfs_direct_cachep == NULL)
		return -ENOMEM;

	return 0;
}

/**
 * nfs_destroy_directcache - destroy the slab cache for nfs_direct_req structures
 *
 */
void nfs_destroy_directcache(void)
{
	kmem_cache_destroy(nfs_direct_cachep);
}
/************************************************************/
/* ../linux-3.17/fs/nfs/direct.c */
/************************************************************/
/*
 * linux/fs/nfs/pagelist.c
 *
 * A set of helper functions for managing NFS read and write requests.
 * The main purpose of these routines is to provide support for the
 * coalescing of several requests into a single RPC call.
 *
 * Copyright 2000, 2001 (c) Trond Myklebust <trond.myklebust@fys.uio.no>
 *
 */

// #include <linux/slab.h>
// #include <linux/file.h>
// #include <linux/sched.h>
// #include <linux/sunrpc/clnt.h>
#include <linux/nfs.h>
#include <linux/nfs3.h>
#include <linux/nfs4.h>
// #include <linux/nfs_page.h>
// #include <linux/nfs_fs.h>
// #include <linux/nfs_mount.h>
#include <linux/export.h>

// #include "internal.h"
// #include "pnfs.h"

#define NFSDBG_FACILITY		NFSDBG_PAGECACHE

static struct kmem_cache *nfs_page_cachep;
static const struct rpc_call_ops nfs_pgio_common_ops;

static bool nfs_pgarray_set(struct nfs_page_array *p, unsigned int pagecount)
{
	p->npages = pagecount;
	if (pagecount <= ARRAY_SIZE(p->page_array))
		p->pagevec = p->page_array;
	else {
		p->pagevec = kcalloc(pagecount, sizeof(struct page *), GFP_KERNEL);
		if (!p->pagevec)
			p->npages = 0;
	}
	return p->pagevec != NULL;
}

void nfs_pgheader_init(struct nfs_pageio_descriptor *desc,
		       struct nfs_pgio_header *hdr,
		       void (*release)(struct nfs_pgio_header *hdr))
{
	hdr->req = nfs_list_entry(desc->pg_list.next);
	hdr->inode = desc->pg_inode;
	hdr->cred = hdr->req->wb_context->cred;
	hdr->io_start = req_offset(hdr->req);
	hdr->good_bytes = desc->pg_count;
	hdr->dreq = desc->pg_dreq;
	hdr->layout_private = desc->pg_layout_private;
	hdr->release = release;
	hdr->completion_ops = desc->pg_completion_ops;
	if (hdr->completion_ops->init_hdr)
		hdr->completion_ops->init_hdr(hdr);
}
EXPORT_SYMBOL_GPL(nfs_pgheader_init);

void nfs_set_pgio_error(struct nfs_pgio_header *hdr, int error, loff_t pos)
{
	spin_lock(&hdr->lock);
	if (pos < hdr->io_start + hdr->good_bytes) {
		set_bit(NFS_IOHDR_ERROR, &hdr->flags);
		clear_bit(NFS_IOHDR_EOF, &hdr->flags);
		hdr->good_bytes = pos - hdr->io_start;
		hdr->error = error;
	}
	spin_unlock(&hdr->lock);
}

static inline struct nfs_page *
nfs_page_alloc(void)
{
	struct nfs_page	*p = kmem_cache_zalloc(nfs_page_cachep, GFP_NOIO);
	if (p)
		INIT_LIST_HEAD(&p->wb_list);
	return p;
}

static inline void
nfs_page_free(struct nfs_page *p)
{
	kmem_cache_free(nfs_page_cachep, p);
}

static void
nfs_iocounter_inc(struct nfs_io_counter *c)
{
	atomic_inc(&c->io_count);
}

static void
nfs_iocounter_dec(struct nfs_io_counter *c)
{
	if (atomic_dec_and_test(&c->io_count)) {
		clear_bit(NFS_IO_INPROGRESS, &c->flags);
		smp_mb__after_atomic();
		wake_up_bit(&c->flags, NFS_IO_INPROGRESS);
	}
}

static int
__nfs_iocounter_wait(struct nfs_io_counter *c)
{
	wait_queue_head_t *wq = bit_waitqueue(&c->flags, NFS_IO_INPROGRESS);
	DEFINE_WAIT_BIT(q, &c->flags, NFS_IO_INPROGRESS);
	int ret = 0;

	do {
		prepare_to_wait(wq, &q.wait, TASK_KILLABLE);
		set_bit(NFS_IO_INPROGRESS, &c->flags);
		if (atomic_read(&c->io_count) == 0)
			break;
		ret = nfs_wait_bit_killable(&q.key);
	} while (atomic_read(&c->io_count) != 0 && !ret);
	finish_wait(wq, &q.wait);
	return ret;
}

/**
 * nfs_iocounter_wait - wait for i/o to complete
 * @c: nfs_io_counter to use
 *
 * returns -ERESTARTSYS if interrupted by a fatal signal.
 * Otherwise returns 0 once the io_count hits 0.
 */
int
nfs_iocounter_wait(struct nfs_io_counter *c)
{
	if (atomic_read(&c->io_count) == 0)
		return 0;
	return __nfs_iocounter_wait(c);
}

/*
 * nfs_page_group_lock - lock the head of the page group
 * @req - request in group that is to be locked
 * @nonblock - if true don't block waiting for lock
 *
 * this lock must be held if modifying the page group list
 *
 * return 0 on success, < 0 on error: -EDELAY if nonblocking or the
 * result from wait_on_bit_lock
 *
 * NOTE: calling with nonblock=false should always have set the
 *       lock bit (see fs/buffer.c and other uses of wait_on_bit_lock
 *       with TASK_UNINTERRUPTIBLE), so there is no need to check the result.
 */
int
nfs_page_group_lock(struct nfs_page *req, bool nonblock)
{
	struct nfs_page *head = req->wb_head;

	WARN_ON_ONCE(head != head->wb_head);

	if (!test_and_set_bit(PG_HEADLOCK, &head->wb_flags))
		return 0;

	if (!nonblock)
		return wait_on_bit_lock(&head->wb_flags, PG_HEADLOCK,
				TASK_UNINTERRUPTIBLE);

	return -EAGAIN;
}

/*
 * nfs_page_group_lock_wait - wait for the lock to clear, but don't grab it
 * @req - a request in the group
 *
 * This is a blocking call to wait for the group lock to be cleared.
 */
void
nfs_page_group_lock_wait(struct nfs_page *req)
{
	struct nfs_page *head = req->wb_head;

	WARN_ON_ONCE(head != head->wb_head);

	wait_on_bit(&head->wb_flags, PG_HEADLOCK,
		TASK_UNINTERRUPTIBLE);
}

/*
 * nfs_page_group_unlock - unlock the head of the page group
 * @req - request in group that is to be unlocked
 */
void
nfs_page_group_unlock(struct nfs_page *req)
{
	struct nfs_page *head = req->wb_head;

	WARN_ON_ONCE(head != head->wb_head);

	smp_mb__before_atomic();
	clear_bit(PG_HEADLOCK, &head->wb_flags);
	smp_mb__after_atomic();
	wake_up_bit(&head->wb_flags, PG_HEADLOCK);
}

/*
 * nfs_page_group_sync_on_bit_locked
 *
 * must be called with page group lock held
 */
static bool
nfs_page_group_sync_on_bit_locked(struct nfs_page *req, unsigned int bit)
{
	struct nfs_page *head = req->wb_head;
	struct nfs_page *tmp;

	WARN_ON_ONCE(!test_bit(PG_HEADLOCK, &head->wb_flags));
	WARN_ON_ONCE(test_and_set_bit(bit, &req->wb_flags));

	tmp = req->wb_this_page;
	while (tmp != req) {
		if (!test_bit(bit, &tmp->wb_flags))
			return false;
		tmp = tmp->wb_this_page;
	}

	/* true! reset all bits */
	tmp = req;
	do {
		clear_bit(bit, &tmp->wb_flags);
		tmp = tmp->wb_this_page;
	} while (tmp != req);

	return true;
}

/*
 * nfs_page_group_sync_on_bit - set bit on current request, but only
 *   return true if the bit is set for all requests in page group
 * @req - request in page group
 * @bit - PG_* bit that is used to sync page group
 */
bool nfs_page_group_sync_on_bit(struct nfs_page *req, unsigned int bit)
{
	bool ret;

	nfs_page_group_lock(req, false);
	ret = nfs_page_group_sync_on_bit_locked(req, bit);
	nfs_page_group_unlock(req);

	return ret;
}

/*
 * nfs_page_group_init - Initialize the page group linkage for @req
 * @req - a new nfs request
 * @prev - the previous request in page group, or NULL if @req is the first
 *         or only request in the group (the head).
 */
static inline void
nfs_page_group_init(struct nfs_page *req, struct nfs_page *prev)
{
	WARN_ON_ONCE(prev == req);

	if (!prev) {
		/* a head request */
		req->wb_head = req;
		req->wb_this_page = req;
	} else {
		/* a subrequest */
		WARN_ON_ONCE(prev->wb_this_page != prev->wb_head);
		WARN_ON_ONCE(!test_bit(PG_HEADLOCK, &prev->wb_head->wb_flags));
		req->wb_head = prev->wb_head;
		req->wb_this_page = prev->wb_this_page;
		prev->wb_this_page = req;

		/* All subrequests take a ref on the head request until
		 * nfs_page_group_destroy is called */
		kref_get(&req->wb_head->wb_kref);

		/* grab extra ref if head request has extra ref from
		 * the write/commit path to handle handoff between write
		 * and commit lists */
		if (test_bit(PG_INODE_REF, &prev->wb_head->wb_flags)) {
			set_bit(PG_INODE_REF, &req->wb_flags);
			kref_get(&req->wb_kref);
		}
	}
}

/*
 * nfs_page_group_destroy - sync the destruction of page groups
 * @req - request that no longer needs the page group
 *
 * releases the page group reference from each member once all
 * members have called this function.
 */
static void
nfs_page_group_destroy(struct kref *kref)
{
	struct nfs_page *req = container_of(kref, struct nfs_page, wb_kref);
	struct nfs_page *tmp, *next;

	/* subrequests must release the ref on the head request */
	if (req->wb_head != req)
		nfs_release_request(req->wb_head);

	if (!nfs_page_group_sync_on_bit(req, PG_TEARDOWN))
		return;

	tmp = req;
	do {
		next = tmp->wb_this_page;
		/* unlink and free */
		tmp->wb_this_page = tmp;
		tmp->wb_head = tmp;
		nfs_free_request(tmp);
		tmp = next;
	} while (tmp != req);
}

/**
 * nfs_create_request - Create an NFS read/write request.
 * @ctx: open context to use
 * @page: page to write
 * @last: last nfs request created for this page group or NULL if head
 * @offset: starting offset within the page for the write
 * @count: number of bytes to read/write
 *
 * The page must be locked by the caller. This makes sure we never
 * create two different requests for the same page.
 * User should ensure it is safe to sleep in this function.
 */
struct nfs_page *
nfs_create_request(struct nfs_open_context *ctx, struct page *page,
		   struct nfs_page *last, unsigned int offset,
		   unsigned int count)
{
	struct nfs_page		*req;
	struct nfs_lock_context *l_ctx;

	if (test_bit(NFS_CONTEXT_BAD, &ctx->flags))
		return ERR_PTR(-EBADF);
	/* try to allocate the request struct */
	req = nfs_page_alloc();
	if (req == NULL)
		return ERR_PTR(-ENOMEM);

	/* get lock context early so we can deal with alloc failures */
	l_ctx = nfs_get_lock_context(ctx);
	if (IS_ERR(l_ctx)) {
		nfs_page_free(req);
		return ERR_CAST(l_ctx);
	}
	req->wb_lock_context = l_ctx;
	nfs_iocounter_inc(&l_ctx->io_count);

	/* Initialize the request struct. Initially, we assume a
	 * long write-back delay. This will be adjusted in
	 * update_nfs_request below if the region is not locked. */
	req->wb_page    = page;
	req->wb_index	= page_file_index(page);
	page_cache_get(page);
	req->wb_offset  = offset;
	req->wb_pgbase	= offset;
	req->wb_bytes   = count;
	req->wb_context = get_nfs_open_context(ctx);
	kref_init(&req->wb_kref);
	nfs_page_group_init(req, last);
	return req;
}

/**
 * nfs_unlock_request - Unlock request and wake up sleepers.
 * @req:
 */
void nfs_unlock_request(struct nfs_page *req)
{
	if (!NFS_WBACK_BUSY(req)) {
		printk(KERN_ERR "NFS: Invalid unlock attempted\n");
		BUG();
	}
	smp_mb__before_atomic();
	clear_bit(PG_BUSY, &req->wb_flags);
	smp_mb__after_atomic();
	wake_up_bit(&req->wb_flags, PG_BUSY);
}

/**
 * nfs_unlock_and_release_request - Unlock request and release the nfs_page
 * @req:
 */
void nfs_unlock_and_release_request(struct nfs_page *req)
{
	nfs_unlock_request(req);
	nfs_release_request(req);
}

/*
 * nfs_clear_request - Free up all resources allocated to the request
 * @req:
 *
 * Release page and open context resources associated with a read/write
 * request after it has completed.
 */
static void nfs_clear_request(struct nfs_page *req)
{
	struct page *page = req->wb_page;
	struct nfs_open_context *ctx = req->wb_context;
	struct nfs_lock_context *l_ctx = req->wb_lock_context;

	if (page != NULL) {
		page_cache_release(page);
		req->wb_page = NULL;
	}
	if (l_ctx != NULL) {
		nfs_iocounter_dec(&l_ctx->io_count);
		nfs_put_lock_context(l_ctx);
		req->wb_lock_context = NULL;
	}
	if (ctx != NULL) {
		put_nfs_open_context(ctx);
		req->wb_context = NULL;
	}
}

/**
 * nfs_release_request - Release the count on an NFS read/write request
 * @req: request to release
 *
 * Note: Should never be called with the spinlock held!
 */
void nfs_free_request(struct nfs_page *req)
{
	WARN_ON_ONCE(req->wb_this_page != req);

	/* extra debug: make sure no sync bits are still set */
	WARN_ON_ONCE(test_bit(PG_TEARDOWN, &req->wb_flags));
	WARN_ON_ONCE(test_bit(PG_UNLOCKPAGE, &req->wb_flags));
	WARN_ON_ONCE(test_bit(PG_UPTODATE, &req->wb_flags));
	WARN_ON_ONCE(test_bit(PG_WB_END, &req->wb_flags));
	WARN_ON_ONCE(test_bit(PG_REMOVE, &req->wb_flags));

	/* Release struct file and open context */
	nfs_clear_request(req);
	nfs_page_free(req);
}

void nfs_release_request(struct nfs_page *req)
{
	kref_put(&req->wb_kref, nfs_page_group_destroy);
}

/**
 * nfs_wait_on_request - Wait for a request to complete.
 * @req: request to wait upon.
 *
 * Interruptible by fatal signals only.
 * The user is responsible for holding a count on the request.
 */
int
nfs_wait_on_request(struct nfs_page *req)
{
	return wait_on_bit_io(&req->wb_flags, PG_BUSY,
			      TASK_UNINTERRUPTIBLE);
}

/*
 * nfs_generic_pg_test - determine if requests can be coalesced
 * @desc: pointer to descriptor
 * @prev: previous request in desc, or NULL
 * @req: this request
 *
 * Returns zero if @req can be coalesced into @desc, otherwise it returns
 * the size of the request.
 */
size_t nfs_generic_pg_test(struct nfs_pageio_descriptor *desc,
			   struct nfs_page *prev, struct nfs_page *req)
{
	if (desc->pg_count > desc->pg_bsize) {
		/* should never happen */
		WARN_ON_ONCE(1);
		return 0;
	}

	return min(desc->pg_bsize - desc->pg_count, (size_t)req->wb_bytes);
}
EXPORT_SYMBOL_GPL(nfs_generic_pg_test);

struct nfs_pgio_header *nfs_pgio_header_alloc(const struct nfs_rw_ops *ops)
{
	struct nfs_pgio_header *hdr = ops->rw_alloc_header();

	if (hdr) {
		INIT_LIST_HEAD(&hdr->pages);
		spin_lock_init(&hdr->lock);
		hdr->rw_ops = ops;
	}
	return hdr;
}
EXPORT_SYMBOL_GPL(nfs_pgio_header_alloc);

/*
 * nfs_pgio_header_free - Free a read or write header
 * @hdr: The header to free
 */
void nfs_pgio_header_free(struct nfs_pgio_header *hdr)
{
	hdr->rw_ops->rw_free_header(hdr);
}
EXPORT_SYMBOL_GPL(nfs_pgio_header_free);

/**
 * nfs_pgio_data_destroy - make @hdr suitable for reuse
 *
 * Frees memory and releases refs from nfs_generic_pgio, so that it may
 * be called again.
 *
 * @hdr: A header that has had nfs_generic_pgio called
 */
void nfs_pgio_data_destroy(struct nfs_pgio_header *hdr)
{
	put_nfs_open_context(hdr->args.context);
	if (hdr->page_array.pagevec != hdr->page_array.page_array)
		kfree(hdr->page_array.pagevec);
}
EXPORT_SYMBOL_GPL(nfs_pgio_data_destroy);

/**
 * nfs_pgio_rpcsetup - Set up arguments for a pageio call
 * @hdr: The pageio hdr
 * @count: Number of bytes to read
 * @offset: Initial offset
 * @how: How to commit data (writes only)
 * @cinfo: Commit information for the call (writes only)
 */
static void nfs_pgio_rpcsetup(struct nfs_pgio_header *hdr,
			      unsigned int count, unsigned int offset,
			      int how, struct nfs_commit_info *cinfo)
{
	struct nfs_page *req = hdr->req;

	/* Set up the RPC argument and reply structs
	 * NB: take care not to mess about with hdr->commit et al. */

	hdr->args.fh     = NFS_FH(hdr->inode);
	hdr->args.offset = req_offset(req) + offset;
	/* pnfs_set_layoutcommit needs this */
	hdr->mds_offset = hdr->args.offset;
	hdr->args.pgbase = req->wb_pgbase + offset;
	hdr->args.pages  = hdr->page_array.pagevec;
	hdr->args.count  = count;
	hdr->args.context = get_nfs_open_context(req->wb_context);
	hdr->args.lock_context = req->wb_lock_context;
	hdr->args.stable  = NFS_UNSTABLE;
	switch (how & (FLUSH_STABLE | FLUSH_COND_STABLE)) {
	case 0:
		break;
	case FLUSH_COND_STABLE:
		if (nfs_reqs_to_commit(cinfo))
			break;
	default:
		hdr->args.stable = NFS_FILE_SYNC;
	}

	hdr->res.fattr   = &hdr->fattr;
	hdr->res.count   = count;
	hdr->res.eof     = 0;
	hdr->res.verf    = &hdr->verf;
	nfs_fattr_init(&hdr->fattr);
}

/**
 * nfs_pgio_prepare - Prepare pageio hdr to go over the wire
 * @task: The current task
 * @calldata: pageio header to prepare
 */
static void nfs_pgio_prepare(struct rpc_task *task, void *calldata)
{
	struct nfs_pgio_header *hdr = calldata;
	int err;
	err = NFS_PROTO(hdr->inode)->pgio_rpc_prepare(task, hdr);
	if (err)
		rpc_exit(task, err);
}

int nfs_initiate_pgio(struct rpc_clnt *clnt, struct nfs_pgio_header *hdr,
		      const struct rpc_call_ops *call_ops, int how, int flags)
{
	struct rpc_task *task;
	struct rpc_message msg = {
		.rpc_argp = &hdr->args,
		.rpc_resp = &hdr->res,
		.rpc_cred = hdr->cred,
	};
	struct rpc_task_setup task_setup_data = {
		.rpc_client = clnt,
		.task = &hdr->task,
		.rpc_message = &msg,
		.callback_ops = call_ops,
		.callback_data = hdr,
		.workqueue = nfsiod_workqueue,
		.flags = RPC_TASK_ASYNC | flags,
	};
	int ret = 0;

	hdr->rw_ops->rw_initiate(hdr, &msg, &task_setup_data, how);

	dprintk("NFS: %5u initiated pgio call "
		"(req %s/%llu, %u bytes @ offset %llu)\n",
		hdr->task.tk_pid,
		hdr->inode->i_sb->s_id,
		(unsigned long long)NFS_FILEID(hdr->inode),
		hdr->args.count,
		(unsigned long long)hdr->args.offset);

	task = rpc_run_task(&task_setup_data);
	if (IS_ERR(task)) {
		ret = PTR_ERR(task);
		goto out;
	}
	if (how & FLUSH_SYNC) {
		ret = rpc_wait_for_completion_task(task);
		if (ret == 0)
			ret = task->tk_status;
	}
	rpc_put_task(task);
out:
	return ret;
}
EXPORT_SYMBOL_GPL(nfs_initiate_pgio);

/**
 * nfs_pgio_error - Clean up from a pageio error
 * @desc: IO descriptor
 * @hdr: pageio header
 */
static int nfs_pgio_error(struct nfs_pageio_descriptor *desc,
			  struct nfs_pgio_header *hdr)
{
	set_bit(NFS_IOHDR_REDO, &hdr->flags);
	nfs_pgio_data_destroy(hdr);
	hdr->completion_ops->completion(hdr);
	desc->pg_completion_ops->error_cleanup(&desc->pg_list);
	return -ENOMEM;
}

/**
 * nfs_pgio_release - Release pageio data
 * @calldata: The pageio header to release
 */
static void nfs_pgio_release(void *calldata)
{
	struct nfs_pgio_header *hdr = calldata;
	if (hdr->rw_ops->rw_release)
		hdr->rw_ops->rw_release(hdr);
	nfs_pgio_data_destroy(hdr);
	hdr->completion_ops->completion(hdr);
}

/**
 * nfs_pageio_init - initialise a page io descriptor
 * @desc: pointer to descriptor
 * @inode: pointer to inode
 * @doio: pointer to io function
 * @bsize: io block size
 * @io_flags: extra parameters for the io function
 */
void nfs_pageio_init(struct nfs_pageio_descriptor *desc,
		     struct inode *inode,
		     const struct nfs_pageio_ops *pg_ops,
		     const struct nfs_pgio_completion_ops *compl_ops,
		     const struct nfs_rw_ops *rw_ops,
		     size_t bsize,
		     int io_flags)
{
	INIT_LIST_HEAD(&desc->pg_list);
	desc->pg_bytes_written = 0;
	desc->pg_count = 0;
	desc->pg_bsize = bsize;
	desc->pg_base = 0;
	desc->pg_moreio = 0;
	desc->pg_recoalesce = 0;
	desc->pg_inode = inode;
	desc->pg_ops = pg_ops;
	desc->pg_completion_ops = compl_ops;
	desc->pg_rw_ops = rw_ops;
	desc->pg_ioflags = io_flags;
	desc->pg_error = 0;
	desc->pg_lseg = NULL;
	desc->pg_dreq = NULL;
	desc->pg_layout_private = NULL;
}
EXPORT_SYMBOL_GPL(nfs_pageio_init);

/**
 * nfs_pgio_result - Basic pageio error handling
 * @task: The task that ran
 * @calldata: Pageio header to check
 */
static void nfs_pgio_result(struct rpc_task *task, void *calldata)
{
	struct nfs_pgio_header *hdr = calldata;
	struct inode *inode = hdr->inode;

	dprintk("NFS: %s: %5u, (status %d)\n", __func__,
		task->tk_pid, task->tk_status);

	if (hdr->rw_ops->rw_done(task, hdr, inode) != 0)
		return;
	if (task->tk_status < 0)
		nfs_set_pgio_error(hdr, task->tk_status, hdr->args.offset);
	else
		hdr->rw_ops->rw_result(task, hdr);
}

/*
 * Create an RPC task for the given read or write request and kick it.
 * The page must have been locked by the caller.
 *
 * It may happen that the page we're passed is not marked dirty.
 * This is the case if nfs_updatepage detects a conflicting request
 * that has been written but not committed.
 */
int nfs_generic_pgio(struct nfs_pageio_descriptor *desc,
		     struct nfs_pgio_header *hdr)
{
	struct nfs_page		*req;
	struct page		**pages,
				*last_page;
	struct list_head *head = &desc->pg_list;
	struct nfs_commit_info cinfo;
	unsigned int pagecount, pageused;

	pagecount = nfs_page_array_len(desc->pg_base, desc->pg_count);
	if (!nfs_pgarray_set(&hdr->page_array, pagecount))
		return nfs_pgio_error(desc, hdr);

	nfs_init_cinfo(&cinfo, desc->pg_inode, desc->pg_dreq);
	pages = hdr->page_array.pagevec;
	last_page = NULL;
	pageused = 0;
	while (!list_empty(head)) {
		req = nfs_list_entry(head->next);
		nfs_list_remove_request(req);
		nfs_list_add_request(req, &hdr->pages);

		if (WARN_ON_ONCE(pageused >= pagecount))
			return nfs_pgio_error(desc, hdr);

		if (!last_page || last_page != req->wb_page) {
			*pages++ = last_page = req->wb_page;
			pageused++;
		}
	}
	if (WARN_ON_ONCE(pageused != pagecount))
		return nfs_pgio_error(desc, hdr);

	if ((desc->pg_ioflags & FLUSH_COND_STABLE) &&
	    (desc->pg_moreio || nfs_reqs_to_commit(&cinfo)))
		desc->pg_ioflags &= ~FLUSH_COND_STABLE;

	/* Set up the argument struct */
	nfs_pgio_rpcsetup(hdr, desc->pg_count, 0, desc->pg_ioflags, &cinfo);
	desc->pg_rpc_callops = &nfs_pgio_common_ops;
	return 0;
}
EXPORT_SYMBOL_GPL(nfs_generic_pgio);

static int nfs_generic_pg_pgios(struct nfs_pageio_descriptor *desc)
{
	struct nfs_pgio_header *hdr;
	int ret;

	hdr = nfs_pgio_header_alloc(desc->pg_rw_ops);
	if (!hdr) {
		desc->pg_completion_ops->error_cleanup(&desc->pg_list);
		return -ENOMEM;
	}
	nfs_pgheader_init(desc, hdr, nfs_pgio_header_free);
	ret = nfs_generic_pgio(desc, hdr);
	if (ret == 0)
		ret = nfs_initiate_pgio(NFS_CLIENT(hdr->inode),
					hdr, desc->pg_rpc_callops,
					desc->pg_ioflags, 0);
	return ret;
}

static bool nfs_match_open_context(const struct nfs_open_context *ctx1,
		const struct nfs_open_context *ctx2)
{
	return ctx1->cred == ctx2->cred && ctx1->state == ctx2->state;
}

static bool nfs_match_lock_context(const struct nfs_lock_context *l1,
		const struct nfs_lock_context *l2)
{
	return l1->lockowner.l_owner == l2->lockowner.l_owner
		&& l1->lockowner.l_pid == l2->lockowner.l_pid;
}

/**
 * nfs_can_coalesce_requests - test two requests for compatibility
 * @prev: pointer to nfs_page
 * @req: pointer to nfs_page
 *
 * The nfs_page structures 'prev' and 'req' are compared to ensure that the
 * page data area they describe is contiguous, and that their RPC
 * credentials, NFSv4 open state, and lockowners are the same.
 *
 * Return 'true' if this is the case, else return 'false'.
 */
static bool nfs_can_coalesce_requests(struct nfs_page *prev,
				      struct nfs_page *req,
				      struct nfs_pageio_descriptor *pgio)
{
	size_t size;

	if (prev) {
		if (!nfs_match_open_context(req->wb_context, prev->wb_context))
			return false;
		if (req->wb_context->dentry->d_inode->i_flock != NULL &&
		    !nfs_match_lock_context(req->wb_lock_context,
					    prev->wb_lock_context))
			return false;
		if (req_offset(req) != req_offset(prev) + prev->wb_bytes)
			return false;
		if (req->wb_page == prev->wb_page) {
			if (req->wb_pgbase != prev->wb_pgbase + prev->wb_bytes)
				return false;
		} else {
			if (req->wb_pgbase != 0 ||
			    prev->wb_pgbase + prev->wb_bytes != PAGE_CACHE_SIZE)
				return false;
		}
	}
	size = pgio->pg_ops->pg_test(pgio, prev, req);
	WARN_ON_ONCE(size > req->wb_bytes);
	if (size && size < req->wb_bytes)
		req->wb_bytes = size;
	return size > 0;
}

/**
 * nfs_pageio_do_add_request - Attempt to coalesce a request into a page list.
 * @desc: destination io descriptor
 * @req: request
 *
 * Returns true if the request 'req' was successfully coalesced into the
 * existing list of pages 'desc'.
 */
static int nfs_pageio_do_add_request(struct nfs_pageio_descriptor *desc,
				     struct nfs_page *req)
{
	struct nfs_page *prev = NULL;
	if (desc->pg_count != 0) {
		prev = nfs_list_entry(desc->pg_list.prev);
	} else {
		if (desc->pg_ops->pg_init)
			desc->pg_ops->pg_init(desc, req);
		desc->pg_base = req->wb_pgbase;
	}
	if (!nfs_can_coalesce_requests(prev, req, desc))
		return 0;
	nfs_list_remove_request(req);
	nfs_list_add_request(req, &desc->pg_list);
	desc->pg_count += req->wb_bytes;
	return 1;
}

/*
 * Helper for nfs_pageio_add_request and nfs_pageio_complete
 */
static void nfs_pageio_doio(struct nfs_pageio_descriptor *desc)
{
	if (!list_empty(&desc->pg_list)) {
		int error = desc->pg_ops->pg_doio(desc);
		if (error < 0)
			desc->pg_error = error;
		else
			desc->pg_bytes_written += desc->pg_count;
	}
	if (list_empty(&desc->pg_list)) {
		desc->pg_count = 0;
		desc->pg_base = 0;
	}
}

/**
 * nfs_pageio_add_request - Attempt to coalesce a request into a page list.
 * @desc: destination io descriptor
 * @req: request
 *
 * This may split a request into subrequests which are all part of the
 * same page group.
 *
 * Returns true if the request 'req' was successfully coalesced into the
 * existing list of pages 'desc'.
 */
static int __nfs_pageio_add_request(struct nfs_pageio_descriptor *desc,
			   struct nfs_page *req)
{
	struct nfs_page *subreq;
	unsigned int bytes_left = 0;
	unsigned int offset, pgbase;

	nfs_page_group_lock(req, false);

	subreq = req;
	bytes_left = subreq->wb_bytes;
	offset = subreq->wb_offset;
	pgbase = subreq->wb_pgbase;

	do {
		if (!nfs_pageio_do_add_request(desc, subreq)) {
			/* make sure pg_test call(s) did nothing */
			WARN_ON_ONCE(subreq->wb_bytes != bytes_left);
			WARN_ON_ONCE(subreq->wb_offset != offset);
			WARN_ON_ONCE(subreq->wb_pgbase != pgbase);

			nfs_page_group_unlock(req);
			desc->pg_moreio = 1;
			nfs_pageio_doio(desc);
			if (desc->pg_error < 0)
				return 0;
			if (desc->pg_recoalesce)
				return 0;
			/* retry add_request for this subreq */
			nfs_page_group_lock(req, false);
			continue;
		}

		/* check for buggy pg_test call(s) */
		WARN_ON_ONCE(subreq->wb_bytes + subreq->wb_pgbase > PAGE_SIZE);
		WARN_ON_ONCE(subreq->wb_bytes > bytes_left);
		WARN_ON_ONCE(subreq->wb_bytes == 0);

		bytes_left -= subreq->wb_bytes;
		offset += subreq->wb_bytes;
		pgbase += subreq->wb_bytes;

		if (bytes_left) {
			subreq = nfs_create_request(req->wb_context,
					req->wb_page,
					subreq, pgbase, bytes_left);
			if (IS_ERR(subreq))
				goto err_ptr;
			nfs_lock_request(subreq);
			subreq->wb_offset  = offset;
			subreq->wb_index = req->wb_index;
		}
	} while (bytes_left > 0);

	nfs_page_group_unlock(req);
	return 1;
err_ptr:
	desc->pg_error = PTR_ERR(subreq);
	nfs_page_group_unlock(req);
	return 0;
}

static int nfs_do_recoalesce(struct nfs_pageio_descriptor *desc)
{
	LIST_HEAD(head);

	do {
		list_splice_init(&desc->pg_list, &head);
		desc->pg_bytes_written -= desc->pg_count;
		desc->pg_count = 0;
		desc->pg_base = 0;
		desc->pg_recoalesce = 0;
		desc->pg_moreio = 0;

		while (!list_empty(&head)) {
			struct nfs_page *req;

			req = list_first_entry(&head, struct nfs_page, wb_list);
			nfs_list_remove_request(req);
			if (__nfs_pageio_add_request(desc, req))
				continue;
			if (desc->pg_error < 0)
				return 0;
			break;
		}
	} while (desc->pg_recoalesce);
	return 1;
}

int nfs_pageio_add_request(struct nfs_pageio_descriptor *desc,
		struct nfs_page *req)
{
	int ret;

	do {
		ret = __nfs_pageio_add_request(desc, req);
		if (ret)
			break;
		if (desc->pg_error < 0)
			break;
		ret = nfs_do_recoalesce(desc);
	} while (ret);
	return ret;
}

/*
 * nfs_pageio_resend - Transfer requests to new descriptor and resend
 * @hdr - the pgio header to move request from
 * @desc - the pageio descriptor to add requests to
 *
 * Try to move each request (nfs_page) from @hdr to @desc then attempt
 * to send them.
 *
 * Returns 0 on success and < 0 on error.
 */
int nfs_pageio_resend(struct nfs_pageio_descriptor *desc,
		      struct nfs_pgio_header *hdr)
{
	LIST_HEAD(failed);

	desc->pg_dreq = hdr->dreq;
	while (!list_empty(&hdr->pages)) {
		struct nfs_page *req = nfs_list_entry(hdr->pages.next);

		nfs_list_remove_request(req);
		if (!nfs_pageio_add_request(desc, req))
			nfs_list_add_request(req, &failed);
	}
	nfs_pageio_complete(desc);
	if (!list_empty(&failed)) {
		list_move(&failed, &hdr->pages);
		return -EIO;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(nfs_pageio_resend);

/**
 * nfs_pageio_complete - Complete I/O on an nfs_pageio_descriptor
 * @desc: pointer to io descriptor
 */
void nfs_pageio_complete(struct nfs_pageio_descriptor *desc)
{
	for (;;) {
		nfs_pageio_doio(desc);
		if (!desc->pg_recoalesce)
			break;
		if (!nfs_do_recoalesce(desc))
			break;
	}
}

/**
 * nfs_pageio_cond_complete - Conditional I/O completion
 * @desc: pointer to io descriptor
 * @index: page index
 *
 * It is important to ensure that processes don't try to take locks
 * on non-contiguous ranges of pages as that might deadlock. This
 * function should be called before attempting to wait on a locked
 * nfs_page. It will complete the I/O if the page index 'index'
 * is not contiguous with the existing list of pages in 'desc'.
 */
void nfs_pageio_cond_complete(struct nfs_pageio_descriptor *desc, pgoff_t index)
{
	if (!list_empty(&desc->pg_list)) {
		struct nfs_page *prev = nfs_list_entry(desc->pg_list.prev);
		if (index != prev->wb_index + 1)
			nfs_pageio_complete(desc);
	}
}

int __init nfs_init_nfspagecache(void)
{
	nfs_page_cachep = kmem_cache_create("nfs_page",
					    sizeof(struct nfs_page),
					    0, SLAB_HWCACHE_ALIGN,
					    NULL);
	if (nfs_page_cachep == NULL)
		return -ENOMEM;

	return 0;
}

void nfs_destroy_nfspagecache(void)
{
	kmem_cache_destroy(nfs_page_cachep);
}

static const struct rpc_call_ops nfs_pgio_common_ops = {
	.rpc_call_prepare = nfs_pgio_prepare,
	.rpc_call_done = nfs_pgio_result,
	.rpc_release = nfs_pgio_release,
};

const struct nfs_pageio_ops nfs_pgio_rw_ops = {
	.pg_test = nfs_generic_pg_test,
	.pg_doio = nfs_generic_pg_pgios,
};
/************************************************************/
/* ../linux-3.17/fs/nfs/pagelist.c */
/************************************************************/
/*
 * linux/fs/nfs/read.c
 *
 * Block I/O for NFS
 *
 * Partial copy of Linus' read cache modifications to fs/nfs/file.c
 * modified for async RPC by okir@monad.swb.de
 */

// #include <linux/time.h>
// #include <linux/kernel.h>
// #include <linux/errno.h>
// #include <linux/fcntl.h>
// #include <linux/stat.h>
// #include <linux/mm.h>
// #include <linux/slab.h>
// #include <linux/pagemap.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/nfs_fs.h>
// #include <linux/nfs_page.h>
// #include <linux/module.h>

// #include "nfs4_fs.h"
// #include "internal.h"
// #include "iostat.h"
// #include "fscache.h"
// #include "pnfs.h"

#define NFSDBG_FACILITY		NFSDBG_PAGECACHE

static const struct nfs_pgio_completion_ops nfs_async_read_completion_ops;
static const struct nfs_rw_ops nfs_rw_read_ops;

static struct kmem_cache *nfs_rdata_cachep;

static struct nfs_pgio_header *nfs_readhdr_alloc(void)
{
	return kmem_cache_zalloc(nfs_rdata_cachep, GFP_KERNEL);
}

static void nfs_readhdr_free(struct nfs_pgio_header *rhdr)
{
	kmem_cache_free(nfs_rdata_cachep, rhdr);
}

static
int nfs_return_empty_page(struct page *page)
{
	zero_user(page, 0, PAGE_CACHE_SIZE);
	SetPageUptodate(page);
	unlock_page(page);
	return 0;
}

void nfs_pageio_init_read(struct nfs_pageio_descriptor *pgio,
			      struct inode *inode, bool force_mds,
			      const struct nfs_pgio_completion_ops *compl_ops)
{
	struct nfs_server *server = NFS_SERVER(inode);
	const struct nfs_pageio_ops *pg_ops = &nfs_pgio_rw_ops;

#ifdef CONFIG_NFS_V4_1
	if (server->pnfs_curr_ld && !force_mds)
		pg_ops = server->pnfs_curr_ld->pg_read_ops;
#endif
	nfs_pageio_init(pgio, inode, pg_ops, compl_ops, &nfs_rw_read_ops,
			server->rsize, 0);
}
EXPORT_SYMBOL_GPL(nfs_pageio_init_read);

void nfs_pageio_reset_read_mds(struct nfs_pageio_descriptor *pgio)
{
	pgio->pg_ops = &nfs_pgio_rw_ops;
	pgio->pg_bsize = NFS_SERVER(pgio->pg_inode)->rsize;
}
EXPORT_SYMBOL_GPL(nfs_pageio_reset_read_mds);

int nfs_readpage_async(struct nfs_open_context *ctx, struct inode *inode,
		       struct page *page)
{
	struct nfs_page	*new;
	unsigned int len;
	struct nfs_pageio_descriptor pgio;

	len = nfs_page_length(page);
	if (len == 0)
		return nfs_return_empty_page(page);
	new = nfs_create_request(ctx, page, NULL, 0, len);
	if (IS_ERR(new)) {
		unlock_page(page);
		return PTR_ERR(new);
	}
	if (len < PAGE_CACHE_SIZE)
		zero_user_segment(page, len, PAGE_CACHE_SIZE);

	nfs_pageio_init_read(&pgio, inode, false,
			     &nfs_async_read_completion_ops);
	nfs_pageio_add_request(&pgio, new);
	nfs_pageio_complete(&pgio);
	NFS_I(inode)->read_io += pgio.pg_bytes_written;
	return 0;
}

static void nfs_readpage_release(struct nfs_page *req)
{
	struct inode *d_inode = req->wb_context->dentry->d_inode;

	dprintk("NFS: read done (%s/%llu %d@%lld)\n", d_inode->i_sb->s_id,
		(unsigned long long)NFS_FILEID(d_inode), req->wb_bytes,
		(long long)req_offset(req));

	if (nfs_page_group_sync_on_bit(req, PG_UNLOCKPAGE)) {
		if (PageUptodate(req->wb_page))
			nfs_readpage_to_fscache(d_inode, req->wb_page, 0);

		unlock_page(req->wb_page);
	}
	nfs_release_request(req);
}

static void nfs_page_group_set_uptodate(struct nfs_page *req)
{
	if (nfs_page_group_sync_on_bit(req, PG_UPTODATE))
		SetPageUptodate(req->wb_page);
}

static void nfs_read_completion(struct nfs_pgio_header *hdr)
{
	unsigned long bytes = 0;

	if (test_bit(NFS_IOHDR_REDO, &hdr->flags))
		goto out;
	while (!list_empty(&hdr->pages)) {
		struct nfs_page *req = nfs_list_entry(hdr->pages.next);
		struct page *page = req->wb_page;
		unsigned long start = req->wb_pgbase;
		unsigned long end = req->wb_pgbase + req->wb_bytes;

		if (test_bit(NFS_IOHDR_EOF, &hdr->flags)) {
			/* note: regions of the page not covered by a
			 * request are zeroed in nfs_readpage_async /
			 * readpage_async_filler */
			if (bytes > hdr->good_bytes) {
				/* nothing in this request was good, so zero
				 * the full extent of the request */
				zero_user_segment(page, start, end);

			} else if (hdr->good_bytes - bytes < req->wb_bytes) {
				/* part of this request has good bytes, but
				 * not all. zero the bad bytes */
				start += hdr->good_bytes - bytes;
				WARN_ON(start < req->wb_pgbase);
				zero_user_segment(page, start, end);
			}
		}
		bytes += req->wb_bytes;
		if (test_bit(NFS_IOHDR_ERROR, &hdr->flags)) {
			if (bytes <= hdr->good_bytes)
				nfs_page_group_set_uptodate(req);
		} else
			nfs_page_group_set_uptodate(req);
		nfs_list_remove_request(req);
		nfs_readpage_release(req);
	}
out:
	hdr->release(hdr);
}

static void nfs_initiate_read(struct nfs_pgio_header *hdr,
			      struct rpc_message *msg,
			      struct rpc_task_setup *task_setup_data, int how)
{
	struct inode *inode = hdr->inode;
	int swap_flags = IS_SWAPFILE(inode) ? NFS_RPC_SWAPFLAGS : 0;

	task_setup_data->flags |= swap_flags;
	NFS_PROTO(inode)->read_setup(hdr, msg);
}

static void
nfs_async_read_error(struct list_head *head)
{
	struct nfs_page	*req;

	while (!list_empty(head)) {
		req = nfs_list_entry(head->next);
		nfs_list_remove_request(req);
		nfs_readpage_release(req);
	}
}

static const struct nfs_pgio_completion_ops nfs_async_read_completion_ops = {
	.error_cleanup = nfs_async_read_error,
	.completion = nfs_read_completion,
};

/*
 * This is the callback from RPC telling us whether a reply was
 * received or some error occurred (timeout or socket shutdown).
 */
static int nfs_readpage_done(struct rpc_task *task,
			     struct nfs_pgio_header *hdr,
			     struct inode *inode)
{
	int status = NFS_PROTO(inode)->read_done(task, hdr);
	if (status != 0)
		return status;

	nfs_add_stats(inode, NFSIOS_SERVERREADBYTES, hdr->res.count);

	if (task->tk_status == -ESTALE) {
		set_bit(NFS_INO_STALE, &NFS_I(inode)->flags);
		nfs_mark_for_revalidate(inode);
	}
	return 0;
}

static void nfs_readpage_retry(struct rpc_task *task,
			       struct nfs_pgio_header *hdr)
{
	struct nfs_pgio_args *argp = &hdr->args;
	struct nfs_pgio_res  *resp = &hdr->res;

	/* This is a short read! */
	nfs_inc_stats(hdr->inode, NFSIOS_SHORTREAD);
	/* Has the server at least made some progress? */
	if (resp->count == 0) {
		nfs_set_pgio_error(hdr, -EIO, argp->offset);
		return;
	}
	/* Yes, so retry the read at the end of the hdr */
	hdr->mds_offset += resp->count;
	argp->offset += resp->count;
	argp->pgbase += resp->count;
	argp->count -= resp->count;
	rpc_restart_call_prepare(task);
}

static void nfs_readpage_result(struct rpc_task *task,
				struct nfs_pgio_header *hdr)
{
	if (hdr->res.eof) {
		loff_t bound;

		bound = hdr->args.offset + hdr->res.count;
		spin_lock(&hdr->lock);
		if (bound < hdr->io_start + hdr->good_bytes) {
			set_bit(NFS_IOHDR_EOF, &hdr->flags);
			clear_bit(NFS_IOHDR_ERROR, &hdr->flags);
			hdr->good_bytes = bound - hdr->io_start;
		}
		spin_unlock(&hdr->lock);
	} else if (hdr->res.count != hdr->args.count)
		nfs_readpage_retry(task, hdr);
}

/*
 * Read a page over NFS.
 * We read the page synchronously in the following case:
 *  -	The error flag is set for this page. This happens only when a
 *	previous async read operation failed.
 */
int nfs_readpage(struct file *file, struct page *page)
{
	struct nfs_open_context *ctx;
	struct inode *inode = page_file_mapping(page)->host;
	int		error;

	dprintk("NFS: nfs_readpage (%p %ld@%lu)\n",
		page, PAGE_CACHE_SIZE, page_file_index(page));
	nfs_inc_stats(inode, NFSIOS_VFSREADPAGE);
	nfs_add_stats(inode, NFSIOS_READPAGES, 1);

	/*
	 * Try to flush any pending writes to the file..
	 *
	 * NOTE! Because we own the page lock, there cannot
	 * be any new pending writes generated at this point
	 * for this page (other pages can be written to).
	 */
	error = nfs_wb_page(inode, page);
	if (error)
		goto out_unlock;
	if (PageUptodate(page))
		goto out_unlock;

	error = -ESTALE;
	if (NFS_STALE(inode))
		goto out_unlock;

	if (file == NULL) {
		error = -EBADF;
		ctx = nfs_find_open_context(inode, NULL, FMODE_READ);
		if (ctx == NULL)
			goto out_unlock;
	} else
		ctx = get_nfs_open_context(nfs_file_open_context(file));

	if (!IS_SYNC(inode)) {
		error = nfs_readpage_from_fscache(ctx, inode, page);
		if (error == 0)
			goto out;
	}

	error = nfs_readpage_async(ctx, inode, page);

out:
	put_nfs_open_context(ctx);
	return error;
out_unlock:
	unlock_page(page);
	return error;
}

struct nfs_readdesc {
	struct nfs_pageio_descriptor *pgio;
	struct nfs_open_context *ctx;
};

static int
readpage_async_filler(void *data, struct page *page)
{
	struct nfs_readdesc *desc = (struct nfs_readdesc *)data;
	struct nfs_page *new;
	unsigned int len;
	int error;

	len = nfs_page_length(page);
	if (len == 0)
		return nfs_return_empty_page(page);

	new = nfs_create_request(desc->ctx, page, NULL, 0, len);
	if (IS_ERR(new))
		goto out_error;

	if (len < PAGE_CACHE_SIZE)
		zero_user_segment(page, len, PAGE_CACHE_SIZE);
	if (!nfs_pageio_add_request(desc->pgio, new)) {
		error = desc->pgio->pg_error;
		goto out_unlock;
	}
	return 0;
out_error:
	error = PTR_ERR(new);
out_unlock:
	unlock_page(page);
	return error;
}

int nfs_readpages(struct file *filp, struct address_space *mapping,
		struct list_head *pages, unsigned nr_pages)
{
	struct nfs_pageio_descriptor pgio;
	struct nfs_readdesc desc = {
		.pgio = &pgio,
	};
	struct inode *inode = mapping->host;
	unsigned long npages;
	int ret = -ESTALE;

	dprintk("NFS: nfs_readpages (%s/%Lu %d)\n",
			inode->i_sb->s_id,
			(unsigned long long)NFS_FILEID(inode),
			nr_pages);
	nfs_inc_stats(inode, NFSIOS_VFSREADPAGES);

	if (NFS_STALE(inode))
		goto out;

	if (filp == NULL) {
		desc.ctx = nfs_find_open_context(inode, NULL, FMODE_READ);
		if (desc.ctx == NULL)
			return -EBADF;
	} else
		desc.ctx = get_nfs_open_context(nfs_file_open_context(filp));

	/* attempt to read as many of the pages as possible from the cache
	 * - this returns -ENOBUFS immediately if the cookie is negative
	 */
	ret = nfs_readpages_from_fscache(desc.ctx, inode, mapping,
					 pages, &nr_pages);
	if (ret == 0)
		goto read_complete; /* all pages were read */

	nfs_pageio_init_read(&pgio, inode, false,
			     &nfs_async_read_completion_ops);

	ret = read_cache_pages(mapping, pages, readpage_async_filler, &desc);

	nfs_pageio_complete(&pgio);
	NFS_I(inode)->read_io += pgio.pg_bytes_written;
	npages = (pgio.pg_bytes_written + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	nfs_add_stats(inode, NFSIOS_READPAGES, npages);
read_complete:
	put_nfs_open_context(desc.ctx);
out:
	return ret;
}

int __init nfs_init_readpagecache(void)
{
	nfs_rdata_cachep = kmem_cache_create("nfs_read_data",
					     sizeof(struct nfs_pgio_header),
					     0, SLAB_HWCACHE_ALIGN,
					     NULL);
	if (nfs_rdata_cachep == NULL)
		return -ENOMEM;

	return 0;
}

void nfs_destroy_readpagecache(void)
{
	kmem_cache_destroy(nfs_rdata_cachep);
}

static const struct nfs_rw_ops nfs_rw_read_ops = {
	.rw_mode		= FMODE_READ,
	.rw_alloc_header	= nfs_readhdr_alloc,
	.rw_free_header		= nfs_readhdr_free,
	.rw_done		= nfs_readpage_done,
	.rw_result		= nfs_readpage_result,
	.rw_initiate		= nfs_initiate_read,
};
/************************************************************/
/* ../linux-3.17/fs/nfs/read.c */
/************************************************************/
/*
 *  linux/fs/nfs/symlink.c
 *
 *  Copyright (C) 1992  Rick Sladkey
 *
 *  Optimization changes Copyright (C) 1994 Florian La Roche
 *
 *  Jun 7 1999, cache symlink lookups in the page cache.  -DaveM
 *
 *  nfs symlink handling code
 */

// #include <linux/time.h>
// #include <linux/errno.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/nfs.h>
#include <linux/nfs2.h>
// #include <linux/nfs_fs.h>
// #include <linux/pagemap.h>
// #include <linux/stat.h>
// #include <linux/mm.h>
// #include <linux/string.h>
// #include <linux/namei.h>

/* Symlink caching in the page cache is even more simplistic
 * and straight-forward than readdir caching.
 */

static int nfs_symlink_filler(struct inode *inode, struct page *page)
{
	int error;

	error = NFS_PROTO(inode)->readlink(inode, page, 0, PAGE_SIZE);
	if (error < 0)
		goto error;
	SetPageUptodate(page);
	unlock_page(page);
	return 0;

error:
	SetPageError(page);
	unlock_page(page);
	return -EIO;
}

static void *nfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct inode *inode = dentry->d_inode;
	struct page *page;
	void *err;

	err = ERR_PTR(nfs_revalidate_mapping(inode, inode->i_mapping));
	if (err)
		goto read_failed;
	page = read_cache_page(&inode->i_data, 0,
				(filler_t *)nfs_symlink_filler, inode);
	if (IS_ERR(page)) {
		err = page;
		goto read_failed;
	}
	nd_set_link(nd, kmap(page));
	return page;

read_failed:
	nd_set_link(nd, err);
	return NULL;
}

/*
 * symlinks can't do much...
 */
const struct inode_operations nfs_symlink_inode_operations = {
	.readlink	= generic_readlink,
	.follow_link	= nfs_follow_link,
	.put_link	= page_put_link,
	.getattr	= nfs_getattr,
	.setattr	= nfs_setattr,
};
/************************************************************/
/* ../linux-3.17/fs/nfs/symlink.c */
/************************************************************/
/*
 *  linux/fs/nfs/unlink.c
 *
 * nfs sillydelete handling
 *
 */

// #include <linux/slab.h>
// #include <linux/string.h>
#include <linux/dcache.h>
#include <linux/sunrpc/sched.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/nfs_fs.h>
// #include <linux/sched.h>
#include <linux/wait.h>
// #include <linux/namei.h>
#include <linux/fsnotify.h>

// #include "internal.h"
// #include "nfs4_fs.h"
// #include "iostat.h"
// #include "delegation.h"

// #include "nfstrace.h"

/**
 * nfs_free_unlinkdata - release data from a sillydelete operation.
 * @data: pointer to unlink structure.
 */
static void
nfs_free_unlinkdata(struct nfs_unlinkdata *data)
{
	iput(data->dir);
	put_rpccred(data->cred);
	kfree(data->args.name.name);
	kfree(data);
}

#define NAME_ALLOC_LEN(len)	((len+16) & ~15)
/**
 * nfs_copy_dname - copy dentry name to data structure
 * @dentry: pointer to dentry
 * @data: nfs_unlinkdata
 */
static int nfs_copy_dname(struct dentry *dentry, struct nfs_unlinkdata *data)
{
	char		*str;
	int		len = dentry->d_name.len;

	str = kmemdup(dentry->d_name.name, NAME_ALLOC_LEN(len), GFP_KERNEL);
	if (!str)
		return -ENOMEM;
	data->args.name.len = len;
	data->args.name.name = str;
	return 0;
}

static void nfs_free_dname(struct nfs_unlinkdata *data)
{
	kfree(data->args.name.name);
	data->args.name.name = NULL;
	data->args.name.len = 0;
}

static void nfs_dec_sillycount(struct inode *dir)
{
	struct nfs_inode *nfsi = NFS_I(dir);
	if (atomic_dec_return(&nfsi->silly_count) == 1)
		wake_up(&nfsi->waitqueue);
}

/**
 * nfs_async_unlink_done - Sillydelete post-processing
 * @task: rpc_task of the sillydelete
 *
 * Do the directory attribute update.
 */
static void nfs_async_unlink_done(struct rpc_task *task, void *calldata)
{
	struct nfs_unlinkdata *data = calldata;
	struct inode *dir = data->dir;

	trace_nfs_sillyrename_unlink(data, task->tk_status);
	if (!NFS_PROTO(dir)->unlink_done(task, dir))
		rpc_restart_call_prepare(task);
}

/**
 * nfs_async_unlink_release - Release the sillydelete data.
 * @task: rpc_task of the sillydelete
 *
 * We need to call nfs_put_unlinkdata as a 'tk_release' task since the
 * rpc_task would be freed too.
 */
static void nfs_async_unlink_release(void *calldata)
{
	struct nfs_unlinkdata	*data = calldata;
	struct super_block *sb = data->dir->i_sb;

	nfs_dec_sillycount(data->dir);
	nfs_free_unlinkdata(data);
	nfs_sb_deactive(sb);
}

static void nfs_unlink_prepare(struct rpc_task *task, void *calldata)
{
	struct nfs_unlinkdata *data = calldata;
	NFS_PROTO(data->dir)->unlink_rpc_prepare(task, data);
}

static const struct rpc_call_ops nfs_unlink_ops = {
	.rpc_call_done = nfs_async_unlink_done,
	.rpc_release = nfs_async_unlink_release,
	.rpc_call_prepare = nfs_unlink_prepare,
};

static int nfs_do_call_unlink(struct dentry *parent, struct inode *dir, struct nfs_unlinkdata *data)
{
	struct rpc_message msg = {
		.rpc_argp = &data->args,
		.rpc_resp = &data->res,
		.rpc_cred = data->cred,
	};
	struct rpc_task_setup task_setup_data = {
		.rpc_message = &msg,
		.callback_ops = &nfs_unlink_ops,
		.callback_data = data,
		.workqueue = nfsiod_workqueue,
		.flags = RPC_TASK_ASYNC,
	};
	struct rpc_task *task;
	struct dentry *alias;

	alias = d_lookup(parent, &data->args.name);
	if (alias != NULL) {
		int ret;
		void *devname_garbage = NULL;

		/*
		 * Hey, we raced with lookup... See if we need to transfer
		 * the sillyrename information to the aliased dentry.
		 */
		nfs_free_dname(data);
		ret = nfs_copy_dname(alias, data);
		spin_lock(&alias->d_lock);
		if (ret == 0 && alias->d_inode != NULL &&
		    !(alias->d_flags & DCACHE_NFSFS_RENAMED)) {
			devname_garbage = alias->d_fsdata;
			alias->d_fsdata = data;
			alias->d_flags |= DCACHE_NFSFS_RENAMED;
			ret = 1;
		} else
			ret = 0;
		spin_unlock(&alias->d_lock);
		nfs_dec_sillycount(dir);
		dput(alias);
		/*
		 * If we'd displaced old cached devname, free it.  At that
		 * point dentry is definitely not a root, so we won't need
		 * that anymore.
		 */
		kfree(devname_garbage);
		return ret;
	}
	data->dir = igrab(dir);
	if (!data->dir) {
		nfs_dec_sillycount(dir);
		return 0;
	}
	nfs_sb_active(dir->i_sb);
	data->args.fh = NFS_FH(dir);
	nfs_fattr_init(data->res.dir_attr);

	NFS_PROTO(dir)->unlink_setup(&msg, dir);

	task_setup_data.rpc_client = NFS_CLIENT(dir);
	task = rpc_run_task(&task_setup_data);
	if (!IS_ERR(task))
		rpc_put_task_async(task);
	return 1;
}

static int nfs_call_unlink(struct dentry *dentry, struct nfs_unlinkdata *data)
{
	struct dentry *parent;
	struct inode *dir;
	int ret = 0;


	parent = dget_parent(dentry);
	if (parent == NULL)
		goto out_free;
	dir = parent->d_inode;
	/* Non-exclusive lock protects against concurrent lookup() calls */
	spin_lock(&dir->i_lock);
	if (atomic_inc_not_zero(&NFS_I(dir)->silly_count) == 0) {
		/* Deferred delete */
		hlist_add_head(&data->list, &NFS_I(dir)->silly_list);
		spin_unlock(&dir->i_lock);
		ret = 1;
		goto out_dput;
	}
	spin_unlock(&dir->i_lock);
	ret = nfs_do_call_unlink(parent, dir, data);
out_dput:
	dput(parent);
out_free:
	return ret;
}

void nfs_wait_on_sillyrename(struct dentry *dentry)
{
	struct nfs_inode *nfsi = NFS_I(dentry->d_inode);

	wait_event(nfsi->waitqueue, atomic_read(&nfsi->silly_count) <= 1);
}

void nfs_block_sillyrename(struct dentry *dentry)
{
	struct nfs_inode *nfsi = NFS_I(dentry->d_inode);

	wait_event(nfsi->waitqueue, atomic_cmpxchg(&nfsi->silly_count, 1, 0) == 1);
}

void nfs_unblock_sillyrename(struct dentry *dentry)
{
	struct inode *dir = dentry->d_inode;
	struct nfs_inode *nfsi = NFS_I(dir);
	struct nfs_unlinkdata *data;

	atomic_inc(&nfsi->silly_count);
	spin_lock(&dir->i_lock);
	while (!hlist_empty(&nfsi->silly_list)) {
		if (!atomic_inc_not_zero(&nfsi->silly_count))
			break;
		data = hlist_entry(nfsi->silly_list.first, struct nfs_unlinkdata, list);
		hlist_del(&data->list);
		spin_unlock(&dir->i_lock);
		if (nfs_do_call_unlink(dentry, dir, data) == 0)
			nfs_free_unlinkdata(data);
		spin_lock(&dir->i_lock);
	}
	spin_unlock(&dir->i_lock);
}

/**
 * nfs_async_unlink - asynchronous unlinking of a file
 * @dir: parent directory of dentry
 * @dentry: dentry to unlink
 */
static int
nfs_async_unlink(struct inode *dir, struct dentry *dentry)
{
	struct nfs_unlinkdata *data;
	int status = -ENOMEM;
	void *devname_garbage = NULL;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		goto out;

	data->cred = rpc_lookup_cred();
	if (IS_ERR(data->cred)) {
		status = PTR_ERR(data->cred);
		goto out_free;
	}
	data->res.dir_attr = &data->dir_attr;

	status = -EBUSY;
	spin_lock(&dentry->d_lock);
	if (dentry->d_flags & DCACHE_NFSFS_RENAMED)
		goto out_unlock;
	dentry->d_flags |= DCACHE_NFSFS_RENAMED;
	devname_garbage = dentry->d_fsdata;
	dentry->d_fsdata = data;
	spin_unlock(&dentry->d_lock);
	/*
	 * If we'd displaced old cached devname, free it.  At that
	 * point dentry is definitely not a root, so we won't need
	 * that anymore.
	 */
	kfree(devname_garbage);
	return 0;
out_unlock:
	spin_unlock(&dentry->d_lock);
	put_rpccred(data->cred);
out_free:
	kfree(data);
out:
	return status;
}

/**
 * nfs_complete_unlink - Initialize completion of the sillydelete
 * @dentry: dentry to delete
 * @inode: inode
 *
 * Since we're most likely to be called by dentry_iput(), we
 * only use the dentry to find the sillydelete. We then copy the name
 * into the qstr.
 */
void
nfs_complete_unlink(struct dentry *dentry, struct inode *inode)
{
	struct nfs_unlinkdata	*data = NULL;

	spin_lock(&dentry->d_lock);
	if (dentry->d_flags & DCACHE_NFSFS_RENAMED) {
		dentry->d_flags &= ~DCACHE_NFSFS_RENAMED;
		data = dentry->d_fsdata;
		dentry->d_fsdata = NULL;
	}
	spin_unlock(&dentry->d_lock);

	if (data != NULL && (NFS_STALE(inode) || !nfs_call_unlink(dentry, data)))
		nfs_free_unlinkdata(data);
}

/* Cancel a queued async unlink. Called when a sillyrename run fails. */
static void
nfs_cancel_async_unlink(struct dentry *dentry)
{
	spin_lock(&dentry->d_lock);
	if (dentry->d_flags & DCACHE_NFSFS_RENAMED) {
		struct nfs_unlinkdata *data = dentry->d_fsdata;

		dentry->d_flags &= ~DCACHE_NFSFS_RENAMED;
		dentry->d_fsdata = NULL;
		spin_unlock(&dentry->d_lock);
		nfs_free_unlinkdata(data);
		return;
	}
	spin_unlock(&dentry->d_lock);
}

/**
 * nfs_async_rename_done - Sillyrename post-processing
 * @task: rpc_task of the sillyrename
 * @calldata: nfs_renamedata for the sillyrename
 *
 * Do the directory attribute updates and the d_move
 */
static void nfs_async_rename_done(struct rpc_task *task, void *calldata)
{
	struct nfs_renamedata *data = calldata;
	struct inode *old_dir = data->old_dir;
	struct inode *new_dir = data->new_dir;
	struct dentry *old_dentry = data->old_dentry;

	trace_nfs_sillyrename_rename(old_dir, old_dentry,
			new_dir, data->new_dentry, task->tk_status);
	if (!NFS_PROTO(old_dir)->rename_done(task, old_dir, new_dir)) {
		rpc_restart_call_prepare(task);
		return;
	}

	if (data->complete)
		data->complete(task, data);
}

/**
 * nfs_async_rename_release - Release the sillyrename data.
 * @calldata: the struct nfs_renamedata to be released
 */
static void nfs_async_rename_release(void *calldata)
{
	struct nfs_renamedata	*data = calldata;
	struct super_block *sb = data->old_dir->i_sb;

	if (data->old_dentry->d_inode)
		nfs_mark_for_revalidate(data->old_dentry->d_inode);

	dput(data->old_dentry);
	dput(data->new_dentry);
	iput(data->old_dir);
	iput(data->new_dir);
	nfs_sb_deactive(sb);
	put_rpccred(data->cred);
	kfree(data);
}

static void nfs_rename_prepare(struct rpc_task *task, void *calldata)
{
	struct nfs_renamedata *data = calldata;
	NFS_PROTO(data->old_dir)->rename_rpc_prepare(task, data);
}

static const struct rpc_call_ops nfs_rename_ops = {
	.rpc_call_done = nfs_async_rename_done,
	.rpc_release = nfs_async_rename_release,
	.rpc_call_prepare = nfs_rename_prepare,
};

/**
 * nfs_async_rename - perform an asynchronous rename operation
 * @old_dir: directory that currently holds the dentry to be renamed
 * @new_dir: target directory for the rename
 * @old_dentry: original dentry to be renamed
 * @new_dentry: dentry to which the old_dentry should be renamed
 *
 * It's expected that valid references to the dentries and inodes are held
 */
struct rpc_task *
nfs_async_rename(struct inode *old_dir, struct inode *new_dir,
		 struct dentry *old_dentry, struct dentry *new_dentry,
		 void (*complete)(struct rpc_task *, struct nfs_renamedata *))
{
	struct nfs_renamedata *data;
	struct rpc_message msg = { };
	struct rpc_task_setup task_setup_data = {
		.rpc_message = &msg,
		.callback_ops = &nfs_rename_ops,
		.workqueue = nfsiod_workqueue,
		.rpc_client = NFS_CLIENT(old_dir),
		.flags = RPC_TASK_ASYNC,
	};

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data == NULL)
		return ERR_PTR(-ENOMEM);
	task_setup_data.callback_data = data;

	data->cred = rpc_lookup_cred();
	if (IS_ERR(data->cred)) {
		struct rpc_task *task = ERR_CAST(data->cred);
		kfree(data);
		return task;
	}

	msg.rpc_argp = &data->args;
	msg.rpc_resp = &data->res;
	msg.rpc_cred = data->cred;

	/* set up nfs_renamedata */
	data->old_dir = old_dir;
	ihold(old_dir);
	data->new_dir = new_dir;
	ihold(new_dir);
	data->old_dentry = dget(old_dentry);
	data->new_dentry = dget(new_dentry);
	nfs_fattr_init(&data->old_fattr);
	nfs_fattr_init(&data->new_fattr);
	data->complete = complete;

	/* set up nfs_renameargs */
	data->args.old_dir = NFS_FH(old_dir);
	data->args.old_name = &old_dentry->d_name;
	data->args.new_dir = NFS_FH(new_dir);
	data->args.new_name = &new_dentry->d_name;

	/* set up nfs_renameres */
	data->res.old_fattr = &data->old_fattr;
	data->res.new_fattr = &data->new_fattr;

	nfs_sb_active(old_dir->i_sb);

	NFS_PROTO(data->old_dir)->rename_setup(&msg, old_dir);

	return rpc_run_task(&task_setup_data);
}

/*
 * Perform tasks needed when a sillyrename is done such as cancelling the
 * queued async unlink if it failed.
 */
static void
nfs_complete_sillyrename(struct rpc_task *task, struct nfs_renamedata *data)
{
	struct dentry *dentry = data->old_dentry;

	if (task->tk_status != 0) {
		nfs_cancel_async_unlink(dentry);
		return;
	}

	/*
	 * vfs_unlink and the like do not issue this when a file is
	 * sillyrenamed, so do it here.
	 */
	fsnotify_nameremove(dentry, 0);
}

#define SILLYNAME_PREFIX ".nfs"
#define SILLYNAME_PREFIX_LEN ((unsigned)sizeof(SILLYNAME_PREFIX) - 1)
#define SILLYNAME_FILEID_LEN ((unsigned)sizeof(u64) << 1)
#define SILLYNAME_COUNTER_LEN ((unsigned)sizeof(unsigned int) << 1)
#define SILLYNAME_LEN (SILLYNAME_PREFIX_LEN + \
		SILLYNAME_FILEID_LEN + \
		SILLYNAME_COUNTER_LEN)

/**
 * nfs_sillyrename - Perform a silly-rename of a dentry
 * @dir: inode of directory that contains dentry
 * @dentry: dentry to be sillyrenamed
 *
 * NFSv2/3 is stateless and the server doesn't know when the client is
 * holding a file open. To prevent application problems when a file is
 * unlinked while it's still open, the client performs a "silly-rename".
 * That is, it renames the file to a hidden file in the same directory,
 * and only performs the unlink once the last reference to it is put.
 *
 * The final cleanup is done during dentry_iput.
 *
 * (Note: NFSv4 is stateful, and has opens, so in theory an NFSv4 server
 * could take responsibility for keeping open files referenced.  The server
 * would also need to ensure that opened-but-deleted files were kept over
 * reboots.  However, we may not assume a server does so.  (RFC 5661
 * does provide an OPEN4_RESULT_PRESERVE_UNLINKED flag that a server can
 * use to advertise that it does this; some day we may take advantage of
 * it.))
 */
int
nfs_sillyrename(struct inode *dir, struct dentry *dentry)
{
	static unsigned int sillycounter;
	unsigned char silly[SILLYNAME_LEN + 1];
	unsigned long long fileid;
	struct dentry *sdentry;
	struct rpc_task *task;
	int            error = -EBUSY;

	dfprintk(VFS, "NFS: silly-rename(%pd2, ct=%d)\n",
		dentry, d_count(dentry));
	nfs_inc_stats(dir, NFSIOS_SILLYRENAME);

	/*
	 * We don't allow a dentry to be silly-renamed twice.
	 */
	if (dentry->d_flags & DCACHE_NFSFS_RENAMED)
		goto out;

	fileid = NFS_FILEID(dentry->d_inode);

	/* Return delegation in anticipation of the rename */
	NFS_PROTO(dentry->d_inode)->return_delegation(dentry->d_inode);

	sdentry = NULL;
	do {
		int slen;
		dput(sdentry);
		sillycounter++;
		slen = scnprintf(silly, sizeof(silly),
				SILLYNAME_PREFIX "%0*llx%0*x",
				SILLYNAME_FILEID_LEN, fileid,
				SILLYNAME_COUNTER_LEN, sillycounter);

		dfprintk(VFS, "NFS: trying to rename %pd to %s\n",
				dentry, silly);

		sdentry = lookup_one_len(silly, dentry->d_parent, slen);
		/*
		 * N.B. Better to return EBUSY here ... it could be
		 * dangerous to delete the file while it's in use.
		 */
		if (IS_ERR(sdentry))
			goto out;
	} while (sdentry->d_inode != NULL); /* need negative lookup */

	/* queue unlink first. Can't do this from rpc_release as it
	 * has to allocate memory
	 */
	error = nfs_async_unlink(dir, dentry);
	if (error)
		goto out_dput;

	/* populate unlinkdata with the right dname */
	error = nfs_copy_dname(sdentry,
				(struct nfs_unlinkdata *)dentry->d_fsdata);
	if (error) {
		nfs_cancel_async_unlink(dentry);
		goto out_dput;
	}

	/* run the rename task, undo unlink if it fails */
	task = nfs_async_rename(dir, dir, dentry, sdentry,
					nfs_complete_sillyrename);
	if (IS_ERR(task)) {
		error = -EBUSY;
		nfs_cancel_async_unlink(dentry);
		goto out_dput;
	}

	/* wait for the RPC task to complete, unless a SIGKILL intervenes */
	error = rpc_wait_for_completion_task(task);
	if (error == 0)
		error = task->tk_status;
	switch (error) {
	case 0:
		/* The rename succeeded */
		nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
		d_move(dentry, sdentry);
		break;
	case -ERESTARTSYS:
		/* The result of the rename is unknown. Play it safe by
		 * forcing a new lookup */
		d_drop(dentry);
		d_drop(sdentry);
	}
	rpc_put_task(task);
out_dput:
	dput(sdentry);
out:
	return error;
}
/************************************************************/
/* ../linux-3.17/fs/nfs/unlink.c */
/************************************************************/
/*
 * linux/fs/nfs/write.c
 *
 * Write file data over NFS.
 *
 * Copyright (C) 1996, 1997, Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/types.h>
// #include <linux/slab.h>
// #include <linux/mm.h>
// #include <linux/pagemap.h>
// #include <linux/file.h>
#include <linux/writeback.h>
// #include <linux/swap.h>
#include <linux/migrate.h>

// #include <linux/sunrpc/clnt.h>
// #include <linux/nfs_fs.h>
// #include <linux/nfs_mount.h>
// #include <linux/nfs_page.h>
#include <linux/backing-dev.h>
// #include <linux/export.h>

// #include <asm/uaccess.h>

// #include "delegation.h"
// #include "internal.h"
// #include "iostat.h"
// #include "nfs4_fs.h"
// #include "fscache.h"
// #include "pnfs.h"

// #include "nfstrace.h"

#define NFSDBG_FACILITY		NFSDBG_PAGECACHE

#define MIN_POOL_WRITE		(32)
#define MIN_POOL_COMMIT		(4)

/*
 * Local function declarations
 */
static void nfs_redirty_request(struct nfs_page *req);
static const struct rpc_call_ops nfs_commit_ops;
static const struct nfs_pgio_completion_ops nfs_async_write_completion_ops;
static const struct nfs_commit_completion_ops nfs_commit_completion_ops;
static const struct nfs_rw_ops nfs_rw_write_ops;
static void nfs_clear_request_commit(struct nfs_page *req);
static void nfs_init_cinfo_from_inode(struct nfs_commit_info *cinfo,
				      struct inode *inode);

static struct kmem_cache *nfs_wdata_cachep;
static mempool_t *nfs_wdata_mempool;
static struct kmem_cache *nfs_cdata_cachep;
static mempool_t *nfs_commit_mempool;

struct nfs_commit_data *nfs_commitdata_alloc(void)
{
	struct nfs_commit_data *p = mempool_alloc(nfs_commit_mempool, GFP_NOIO);

	if (p) {
		memset(p, 0, sizeof(*p));
		INIT_LIST_HEAD(&p->pages);
	}
	return p;
}
EXPORT_SYMBOL_GPL(nfs_commitdata_alloc);

void nfs_commit_free(struct nfs_commit_data *p)
{
	mempool_free(p, nfs_commit_mempool);
}
EXPORT_SYMBOL_GPL(nfs_commit_free);

static struct nfs_pgio_header *nfs_writehdr_alloc(void)
{
	struct nfs_pgio_header *p = mempool_alloc(nfs_wdata_mempool, GFP_NOIO);

	if (p)
		memset(p, 0, sizeof(*p));
	return p;
}

static void nfs_writehdr_free(struct nfs_pgio_header *hdr)
{
	mempool_free(hdr, nfs_wdata_mempool);
}

static void nfs_context_set_write_error(struct nfs_open_context *ctx, int error)
{
	ctx->error = error;
	smp_wmb();
	set_bit(NFS_CONTEXT_ERROR_WRITE, &ctx->flags);
}

/*
 * nfs_page_search_commits_for_head_request_locked
 *
 * Search through commit lists on @inode for the head request for @page.
 * Must be called while holding the inode (which is cinfo) lock.
 *
 * Returns the head request if found, or NULL if not found.
 */
static struct nfs_page *
nfs_page_search_commits_for_head_request_locked(struct nfs_inode *nfsi,
						struct page *page)
{
	struct nfs_page *freq, *t;
	struct nfs_commit_info cinfo;
	struct inode *inode = &nfsi->vfs_inode;

	nfs_init_cinfo_from_inode(&cinfo, inode);

	/* search through pnfs commit lists */
	freq = pnfs_search_commit_reqs(inode, &cinfo, page);
	if (freq)
		return freq->wb_head;

	/* Linearly search the commit list for the correct request */
	list_for_each_entry_safe(freq, t, &cinfo.mds->list, wb_list) {
		if (freq->wb_page == page)
			return freq->wb_head;
	}

	return NULL;
}

/*
 * nfs_page_find_head_request_locked - find head request associated with @page
 *
 * must be called while holding the inode lock.
 *
 * returns matching head request with reference held, or NULL if not found.
 */
static struct nfs_page *
nfs_page_find_head_request_locked(struct nfs_inode *nfsi, struct page *page)
{
	struct nfs_page *req = NULL;

	if (PagePrivate(page))
		req = (struct nfs_page *)page_private(page);
	else if (unlikely(PageSwapCache(page)))
		req = nfs_page_search_commits_for_head_request_locked(nfsi,
			page);

	if (req) {
		WARN_ON_ONCE(req->wb_head != req);
		kref_get(&req->wb_kref);
	}

	return req;
}

/*
 * nfs_page_find_head_request - find head request associated with @page
 *
 * returns matching head request with reference held, or NULL if not found.
 */
static struct nfs_page *nfs_page_find_head_request(struct page *page)
{
	struct inode *inode = page_file_mapping(page)->host;
	struct nfs_page *req = NULL;

	spin_lock(&inode->i_lock);
	req = nfs_page_find_head_request_locked(NFS_I(inode), page);
	spin_unlock(&inode->i_lock);
	return req;
}

/* Adjust the file length if we're writing beyond the end */
static void nfs_grow_file(struct page *page, unsigned int offset, unsigned int count)
{
	struct inode *inode = page_file_mapping(page)->host;
	loff_t end, i_size;
	pgoff_t end_index;

	spin_lock(&inode->i_lock);
	i_size = i_size_read(inode);
	end_index = (i_size - 1) >> PAGE_CACHE_SHIFT;
	if (i_size > 0 && page_file_index(page) < end_index)
		goto out;
	end = page_file_offset(page) + ((loff_t)offset+count);
	if (i_size >= end)
		goto out;
	i_size_write(inode, end);
	nfs_inc_stats(inode, NFSIOS_EXTENDWRITE);
out:
	spin_unlock(&inode->i_lock);
}

/* A writeback failed: mark the page as bad, and invalidate the page cache */
static void nfs_set_pageerror(struct page *page)
{
	nfs_zap_mapping(page_file_mapping(page)->host, page_file_mapping(page));
}

/*
 * nfs_page_group_search_locked
 * @head - head request of page group
 * @page_offset - offset into page
 *
 * Search page group with head @head to find a request that contains the
 * page offset @page_offset.
 *
 * Returns a pointer to the first matching nfs request, or NULL if no
 * match is found.
 *
 * Must be called with the page group lock held
 */
static struct nfs_page *
nfs_page_group_search_locked(struct nfs_page *head, unsigned int page_offset)
{
	struct nfs_page *req;

	WARN_ON_ONCE(head != head->wb_head);
	WARN_ON_ONCE(!test_bit(PG_HEADLOCK, &head->wb_head->wb_flags));

	req = head;
	do {
		if (page_offset >= req->wb_pgbase &&
		    page_offset < (req->wb_pgbase + req->wb_bytes))
			return req;

		req = req->wb_this_page;
	} while (req != head);

	return NULL;
}

/*
 * nfs_page_group_covers_page
 * @head - head request of page group
 *
 * Return true if the page group with head @head covers the whole page,
 * returns false otherwise
 */
static bool nfs_page_group_covers_page(struct nfs_page *req)
{
	struct nfs_page *tmp;
	unsigned int pos = 0;
	unsigned int len = nfs_page_length(req->wb_page);

	nfs_page_group_lock(req, false);

	do {
		tmp = nfs_page_group_search_locked(req->wb_head, pos);
		if (tmp) {
			/* no way this should happen */
			WARN_ON_ONCE(tmp->wb_pgbase != pos);
			pos += tmp->wb_bytes - (pos - tmp->wb_pgbase);
		}
	} while (tmp && pos < len);

	nfs_page_group_unlock(req);
	WARN_ON_ONCE(pos > len);
	return pos == len;
}

/* We can set the PG_uptodate flag if we see that a write request
 * covers the full page.
 */
static void nfs_mark_uptodate(struct nfs_page *req)
{
	if (PageUptodate(req->wb_page))
		return;
	if (!nfs_page_group_covers_page(req))
		return;
	SetPageUptodate(req->wb_page);
}

static int wb_priority(struct writeback_control *wbc)
{
	if (wbc->for_reclaim)
		return FLUSH_HIGHPRI | FLUSH_STABLE;
	if (wbc->for_kupdate || wbc->for_background)
		return FLUSH_LOWPRI | FLUSH_COND_STABLE;
	return FLUSH_COND_STABLE;
}

/*
 * NFS congestion control
 */

int nfs_congestion_kb;

#define NFS_CONGESTION_ON_THRESH 	(nfs_congestion_kb >> (PAGE_SHIFT-10))
#define NFS_CONGESTION_OFF_THRESH	\
	(NFS_CONGESTION_ON_THRESH - (NFS_CONGESTION_ON_THRESH >> 2))

static void nfs_set_page_writeback(struct page *page)
{
	struct nfs_server *nfss = NFS_SERVER(page_file_mapping(page)->host);
	int ret = test_set_page_writeback(page);

	WARN_ON_ONCE(ret != 0);

	if (atomic_long_inc_return(&nfss->writeback) >
			NFS_CONGESTION_ON_THRESH) {
		set_bdi_congested(&nfss->backing_dev_info,
					BLK_RW_ASYNC);
	}
}

static void nfs_end_page_writeback(struct nfs_page *req)
{
	struct inode *inode = page_file_mapping(req->wb_page)->host;
	struct nfs_server *nfss = NFS_SERVER(inode);

	if (!nfs_page_group_sync_on_bit(req, PG_WB_END))
		return;

	end_page_writeback(req->wb_page);
	if (atomic_long_dec_return(&nfss->writeback) < NFS_CONGESTION_OFF_THRESH)
		clear_bdi_congested(&nfss->backing_dev_info, BLK_RW_ASYNC);
}


/* nfs_page_group_clear_bits
 *   @req - an nfs request
 * clears all page group related bits from @req
 */
static void
nfs_page_group_clear_bits(struct nfs_page *req)
{
	clear_bit(PG_TEARDOWN, &req->wb_flags);
	clear_bit(PG_UNLOCKPAGE, &req->wb_flags);
	clear_bit(PG_UPTODATE, &req->wb_flags);
	clear_bit(PG_WB_END, &req->wb_flags);
	clear_bit(PG_REMOVE, &req->wb_flags);
}


/*
 * nfs_unroll_locks_and_wait -  unlock all newly locked reqs and wait on @req
 *
 * this is a helper function for nfs_lock_and_join_requests
 *
 * @inode - inode associated with request page group, must be holding inode lock
 * @head  - head request of page group, must be holding head lock
 * @req   - request that couldn't lock and needs to wait on the req bit lock
 * @nonblock - if true, don't actually wait
 *
 * NOTE: this must be called holding page_group bit lock and inode spin lock
 *       and BOTH will be released before returning.
 *
 * returns 0 on success, < 0 on error.
 */
static int
nfs_unroll_locks_and_wait(struct inode *inode, struct nfs_page *head,
			  struct nfs_page *req, bool nonblock)
	__releases(&inode->i_lock)
{
	struct nfs_page *tmp;
	int ret;

	/* relinquish all the locks successfully grabbed this run */
	for (tmp = head ; tmp != req; tmp = tmp->wb_this_page)
		nfs_unlock_request(tmp);

	WARN_ON_ONCE(test_bit(PG_TEARDOWN, &req->wb_flags));

	/* grab a ref on the request that will be waited on */
	kref_get(&req->wb_kref);

	nfs_page_group_unlock(head);
	spin_unlock(&inode->i_lock);

	/* release ref from nfs_page_find_head_request_locked */
	nfs_release_request(head);

	if (!nonblock)
		ret = nfs_wait_on_request(req);
	else
		ret = -EAGAIN;
	nfs_release_request(req);

	return ret;
}

/*
 * nfs_destroy_unlinked_subrequests - destroy recently unlinked subrequests
 *
 * @destroy_list - request list (using wb_this_page) terminated by @old_head
 * @old_head - the old head of the list
 *
 * All subrequests must be locked and removed from all lists, so at this point
 * they are only "active" in this function, and possibly in nfs_wait_on_request
 * with a reference held by some other context.
 */
static void
nfs_destroy_unlinked_subrequests(struct nfs_page *destroy_list,
				 struct nfs_page *old_head)
{
	while (destroy_list) {
		struct nfs_page *subreq = destroy_list;

		destroy_list = (subreq->wb_this_page == old_head) ?
				   NULL : subreq->wb_this_page;

		WARN_ON_ONCE(old_head != subreq->wb_head);

		/* make sure old group is not used */
		subreq->wb_head = subreq;
		subreq->wb_this_page = subreq;

		/* subreq is now totally disconnected from page group or any
		 * write / commit lists. last chance to wake any waiters */
		nfs_unlock_request(subreq);

		if (!test_bit(PG_TEARDOWN, &subreq->wb_flags)) {
			/* release ref on old head request */
			nfs_release_request(old_head);

			nfs_page_group_clear_bits(subreq);

			/* release the PG_INODE_REF reference */
			if (test_and_clear_bit(PG_INODE_REF, &subreq->wb_flags))
				nfs_release_request(subreq);
			else
				WARN_ON_ONCE(1);
		} else {
			WARN_ON_ONCE(test_bit(PG_CLEAN, &subreq->wb_flags));
			/* zombie requests have already released the last
			 * reference and were waiting on the rest of the
			 * group to complete. Since it's no longer part of a
			 * group, simply free the request */
			nfs_page_group_clear_bits(subreq);
			nfs_free_request(subreq);
		}
	}
}

/*
 * nfs_lock_and_join_requests - join all subreqs to the head req and return
 *                              a locked reference, cancelling any pending
 *                              operations for this page.
 *
 * @page - the page used to lookup the "page group" of nfs_page structures
 * @nonblock - if true, don't block waiting for request locks
 *
 * This function joins all sub requests to the head request by first
 * locking all requests in the group, cancelling any pending operations
 * and finally updating the head request to cover the whole range covered by
 * the (former) group.  All subrequests are removed from any write or commit
 * lists, unlinked from the group and destroyed.
 *
 * Returns a locked, referenced pointer to the head request - which after
 * this call is guaranteed to be the only request associated with the page.
 * Returns NULL if no requests are found for @page, or a ERR_PTR if an
 * error was encountered.
 */
static struct nfs_page *
nfs_lock_and_join_requests(struct page *page, bool nonblock)
{
	struct inode *inode = page_file_mapping(page)->host;
	struct nfs_page *head, *subreq;
	struct nfs_page *destroy_list = NULL;
	unsigned int total_bytes;
	int ret;

try_again:
	total_bytes = 0;

	WARN_ON_ONCE(destroy_list);

	spin_lock(&inode->i_lock);

	/*
	 * A reference is taken only on the head request which acts as a
	 * reference to the whole page group - the group will not be destroyed
	 * until the head reference is released.
	 */
	head = nfs_page_find_head_request_locked(NFS_I(inode), page);

	if (!head) {
		spin_unlock(&inode->i_lock);
		return NULL;
	}

	/* holding inode lock, so always make a non-blocking call to try the
	 * page group lock */
	ret = nfs_page_group_lock(head, true);
	if (ret < 0) {
		spin_unlock(&inode->i_lock);

		if (!nonblock && ret == -EAGAIN) {
			nfs_page_group_lock_wait(head);
			nfs_release_request(head);
			goto try_again;
		}

		nfs_release_request(head);
		return ERR_PTR(ret);
	}

	/* lock each request in the page group */
	subreq = head;
	do {
		/*
		 * Subrequests are always contiguous, non overlapping
		 * and in order. If not, it's a programming error.
		 */
		WARN_ON_ONCE(subreq->wb_offset !=
		     (head->wb_offset + total_bytes));

		/* keep track of how many bytes this group covers */
		total_bytes += subreq->wb_bytes;

		if (!nfs_lock_request(subreq)) {
			/* releases page group bit lock and
			 * inode spin lock and all references */
			ret = nfs_unroll_locks_and_wait(inode, head,
				subreq, nonblock);

			if (ret == 0)
				goto try_again;

			return ERR_PTR(ret);
		}

		subreq = subreq->wb_this_page;
	} while (subreq != head);

	/* Now that all requests are locked, make sure they aren't on any list.
	 * Commit list removal accounting is done after locks are dropped */
	subreq = head;
	do {
		nfs_clear_request_commit(subreq);
		subreq = subreq->wb_this_page;
	} while (subreq != head);

	/* unlink subrequests from head, destroy them later */
	if (head->wb_this_page != head) {
		/* destroy list will be terminated by head */
		destroy_list = head->wb_this_page;
		head->wb_this_page = head;

		/* change head request to cover whole range that
		 * the former page group covered */
		head->wb_bytes = total_bytes;
	}

	/*
	 * prepare head request to be added to new pgio descriptor
	 */
	nfs_page_group_clear_bits(head);

	/*
	 * some part of the group was still on the inode list - otherwise
	 * the group wouldn't be involved in async write.
	 * grab a reference for the head request, iff it needs one.
	 */
	if (!test_and_set_bit(PG_INODE_REF, &head->wb_flags))
		kref_get(&head->wb_kref);

	nfs_page_group_unlock(head);

	/* drop lock to clean uprequests on destroy list */
	spin_unlock(&inode->i_lock);

	nfs_destroy_unlinked_subrequests(destroy_list, head);

	/* still holds ref on head from nfs_page_find_head_request_locked
	 * and still has lock on head from lock loop */
	return head;
}

/*
 * Find an associated nfs write request, and prepare to flush it out
 * May return an error if the user signalled nfs_wait_on_request().
 */
static int nfs_page_async_flush(struct nfs_pageio_descriptor *pgio,
				struct page *page, bool nonblock)
{
	struct nfs_page *req;
	int ret = 0;

	req = nfs_lock_and_join_requests(page, nonblock);
	if (!req)
		goto out;
	ret = PTR_ERR(req);
	if (IS_ERR(req))
		goto out;

	nfs_set_page_writeback(page);
	WARN_ON_ONCE(test_bit(PG_CLEAN, &req->wb_flags));

	ret = 0;
	if (!nfs_pageio_add_request(pgio, req)) {
		nfs_redirty_request(req);
		ret = pgio->pg_error;
	}
out:
	return ret;
}

static int nfs_do_writepage(struct page *page, struct writeback_control *wbc, struct nfs_pageio_descriptor *pgio)
{
	struct inode *inode = page_file_mapping(page)->host;
	int ret;

	nfs_inc_stats(inode, NFSIOS_VFSWRITEPAGE);
	nfs_add_stats(inode, NFSIOS_WRITEPAGES, 1);

	nfs_pageio_cond_complete(pgio, page_file_index(page));
	ret = nfs_page_async_flush(pgio, page, wbc->sync_mode == WB_SYNC_NONE);
	if (ret == -EAGAIN) {
		redirty_page_for_writepage(wbc, page);
		ret = 0;
	}
	return ret;
}

/*
 * Write an mmapped page to the server.
 */
static int nfs_writepage_locked(struct page *page, struct writeback_control *wbc)
{
	struct nfs_pageio_descriptor pgio;
	int err;

	nfs_pageio_init_write(&pgio, page->mapping->host, wb_priority(wbc),
				false, &nfs_async_write_completion_ops);
	err = nfs_do_writepage(page, wbc, &pgio);
	nfs_pageio_complete(&pgio);
	if (err < 0)
		return err;
	if (pgio.pg_error < 0)
		return pgio.pg_error;
	return 0;
}

int nfs_writepage(struct page *page, struct writeback_control *wbc)
{
	int ret;

	ret = nfs_writepage_locked(page, wbc);
	unlock_page(page);
	return ret;
}

static int nfs_writepages_callback(struct page *page, struct writeback_control *wbc, void *data)
{
	int ret;

	ret = nfs_do_writepage(page, wbc, data);
	unlock_page(page);
	return ret;
}

int nfs_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	unsigned long *bitlock = &NFS_I(inode)->flags;
	struct nfs_pageio_descriptor pgio;
	int err;

	/* Stop dirtying of new pages while we sync */
	err = wait_on_bit_lock_action(bitlock, NFS_INO_FLUSHING,
			nfs_wait_bit_killable, TASK_KILLABLE);
	if (err)
		goto out_err;

	nfs_inc_stats(inode, NFSIOS_VFSWRITEPAGES);

	nfs_pageio_init_write(&pgio, inode, wb_priority(wbc), false,
				&nfs_async_write_completion_ops);
	err = write_cache_pages(mapping, wbc, nfs_writepages_callback, &pgio);
	nfs_pageio_complete(&pgio);

	clear_bit_unlock(NFS_INO_FLUSHING, bitlock);
	smp_mb__after_atomic();
	wake_up_bit(bitlock, NFS_INO_FLUSHING);

	if (err < 0)
		goto out_err;
	err = pgio.pg_error;
	if (err < 0)
		goto out_err;
	return 0;
out_err:
	return err;
}

/*
 * Insert a write request into an inode
 */
static void nfs_inode_add_request(struct inode *inode, struct nfs_page *req)
{
	struct nfs_inode *nfsi = NFS_I(inode);

	WARN_ON_ONCE(req->wb_this_page != req);

	/* Lock the request! */
	nfs_lock_request(req);

	spin_lock(&inode->i_lock);
	if (!nfsi->npages && NFS_PROTO(inode)->have_delegation(inode, FMODE_WRITE))
		inode->i_version++;
	/*
	 * Swap-space should not get truncated. Hence no need to plug the race
	 * with invalidate/truncate.
	 */
	if (likely(!PageSwapCache(req->wb_page))) {
		set_bit(PG_MAPPED, &req->wb_flags);
		SetPagePrivate(req->wb_page);
		set_page_private(req->wb_page, (unsigned long)req);
	}
	nfsi->npages++;
	/* this a head request for a page group - mark it as having an
	 * extra reference so sub groups can follow suit */
	WARN_ON(test_and_set_bit(PG_INODE_REF, &req->wb_flags));
	kref_get(&req->wb_kref);
	spin_unlock(&inode->i_lock);
}

/*
 * Remove a write request from an inode
 */
static void nfs_inode_remove_request(struct nfs_page *req)
{
	struct inode *inode = req->wb_context->dentry->d_inode;
	struct nfs_inode *nfsi = NFS_I(inode);
	struct nfs_page *head;

	if (nfs_page_group_sync_on_bit(req, PG_REMOVE)) {
		head = req->wb_head;

		spin_lock(&inode->i_lock);
		if (likely(!PageSwapCache(head->wb_page))) {
			set_page_private(head->wb_page, 0);
			ClearPagePrivate(head->wb_page);
			clear_bit(PG_MAPPED, &head->wb_flags);
		}
		nfsi->npages--;
		spin_unlock(&inode->i_lock);
	}

	if (test_and_clear_bit(PG_INODE_REF, &req->wb_flags))
		nfs_release_request(req);
	else
		WARN_ON_ONCE(1);
}

static void
nfs_mark_request_dirty(struct nfs_page *req)
{
	__set_page_dirty_nobuffers(req->wb_page);
}

#if IS_ENABLED(CONFIG_NFS_V3) || IS_ENABLED(CONFIG_NFS_V4)
/**
 * nfs_request_add_commit_list - add request to a commit list
 * @req: pointer to a struct nfs_page
 * @dst: commit list head
 * @cinfo: holds list lock and accounting info
 *
 * This sets the PG_CLEAN bit, updates the cinfo count of
 * number of outstanding requests requiring a commit as well as
 * the MM page stats.
 *
 * The caller must _not_ hold the cinfo->lock, but must be
 * holding the nfs_page lock.
 */
void
nfs_request_add_commit_list(struct nfs_page *req, struct list_head *dst,
			    struct nfs_commit_info *cinfo)
{
	set_bit(PG_CLEAN, &(req)->wb_flags);
	spin_lock(cinfo->lock);
	nfs_list_add_request(req, dst);
	cinfo->mds->ncommit++;
	spin_unlock(cinfo->lock);
	if (!cinfo->dreq) {
		inc_zone_page_state(req->wb_page, NR_UNSTABLE_NFS);
		inc_bdi_stat(page_file_mapping(req->wb_page)->backing_dev_info,
			     BDI_RECLAIMABLE);
		__mark_inode_dirty(req->wb_context->dentry->d_inode,
				   I_DIRTY_DATASYNC);
	}
}
EXPORT_SYMBOL_GPL(nfs_request_add_commit_list);

/**
 * nfs_request_remove_commit_list - Remove request from a commit list
 * @req: pointer to a nfs_page
 * @cinfo: holds list lock and accounting info
 *
 * This clears the PG_CLEAN bit, and updates the cinfo's count of
 * number of outstanding requests requiring a commit
 * It does not update the MM page stats.
 *
 * The caller _must_ hold the cinfo->lock and the nfs_page lock.
 */
void
nfs_request_remove_commit_list(struct nfs_page *req,
			       struct nfs_commit_info *cinfo)
{
	if (!test_and_clear_bit(PG_CLEAN, &(req)->wb_flags))
		return;
	nfs_list_remove_request(req);
	cinfo->mds->ncommit--;
}
EXPORT_SYMBOL_GPL(nfs_request_remove_commit_list);

static void nfs_init_cinfo_from_inode(struct nfs_commit_info *cinfo,
				      struct inode *inode)
{
	cinfo->lock = &inode->i_lock;
	cinfo->mds = &NFS_I(inode)->commit_info;
	cinfo->ds = pnfs_get_ds_info(inode);
	cinfo->dreq = NULL;
	cinfo->completion_ops = &nfs_commit_completion_ops;
}

void nfs_init_cinfo(struct nfs_commit_info *cinfo,
		    struct inode *inode,
		    struct nfs_direct_req *dreq)
{
	if (dreq)
		nfs_init_cinfo_from_dreq(cinfo, dreq);
	else
		nfs_init_cinfo_from_inode(cinfo, inode);
}
EXPORT_SYMBOL_GPL(nfs_init_cinfo);

/*
 * Add a request to the inode's commit list.
 */
void
nfs_mark_request_commit(struct nfs_page *req, struct pnfs_layout_segment *lseg,
			struct nfs_commit_info *cinfo)
{
	if (pnfs_mark_request_commit(req, lseg, cinfo))
		return;
	nfs_request_add_commit_list(req, &cinfo->mds->list, cinfo);
}

static void
nfs_clear_page_commit(struct page *page)
{
	dec_zone_page_state(page, NR_UNSTABLE_NFS);
	dec_bdi_stat(page_file_mapping(page)->backing_dev_info, BDI_RECLAIMABLE);
}

/* Called holding inode (/cinfo) lock */
static void
nfs_clear_request_commit(struct nfs_page *req)
{
	if (test_bit(PG_CLEAN, &req->wb_flags)) {
		struct inode *inode = req->wb_context->dentry->d_inode;
		struct nfs_commit_info cinfo;

		nfs_init_cinfo_from_inode(&cinfo, inode);
		if (!pnfs_clear_request_commit(req, &cinfo)) {
			nfs_request_remove_commit_list(req, &cinfo);
		}
		nfs_clear_page_commit(req->wb_page);
	}
}

int nfs_write_need_commit(struct nfs_pgio_header *hdr)
{
	if (hdr->verf.committed == NFS_DATA_SYNC)
		return hdr->lseg == NULL;
	return hdr->verf.committed != NFS_FILE_SYNC;
}

#else
static void nfs_init_cinfo_from_inode(struct nfs_commit_info *cinfo,
				      struct inode *inode)
{
}

void nfs_init_cinfo(struct nfs_commit_info *cinfo,
		    struct inode *inode,
		    struct nfs_direct_req *dreq)
{
}

void
nfs_mark_request_commit(struct nfs_page *req, struct pnfs_layout_segment *lseg,
			struct nfs_commit_info *cinfo)
{
}

static void
nfs_clear_request_commit(struct nfs_page *req)
{
}

int nfs_write_need_commit(struct nfs_pgio_header *hdr)
{
	return 0;
}

#endif

static void nfs_write_completion(struct nfs_pgio_header *hdr)
{
	struct nfs_commit_info cinfo;
	unsigned long bytes = 0;

	if (test_bit(NFS_IOHDR_REDO, &hdr->flags))
		goto out;
	nfs_init_cinfo_from_inode(&cinfo, hdr->inode);
	while (!list_empty(&hdr->pages)) {
		struct nfs_page *req = nfs_list_entry(hdr->pages.next);

		bytes += req->wb_bytes;
		nfs_list_remove_request(req);
		if (test_bit(NFS_IOHDR_ERROR, &hdr->flags) &&
		    (hdr->good_bytes < bytes)) {
			nfs_set_pageerror(req->wb_page);
			nfs_context_set_write_error(req->wb_context, hdr->error);
			goto remove_req;
		}
		if (nfs_write_need_commit(hdr)) {
			memcpy(&req->wb_verf, &hdr->verf.verifier, sizeof(req->wb_verf));
			nfs_mark_request_commit(req, hdr->lseg, &cinfo);
			goto next;
		}
remove_req:
		nfs_inode_remove_request(req);
next:
		nfs_unlock_request(req);
		nfs_end_page_writeback(req);
		nfs_release_request(req);
	}
out:
	hdr->release(hdr);
}

#if  IS_ENABLED(CONFIG_NFS_V3) || IS_ENABLED(CONFIG_NFS_V4)
unsigned long
nfs_reqs_to_commit(struct nfs_commit_info *cinfo)
{
	return cinfo->mds->ncommit;
}

/* cinfo->lock held by caller */
int
nfs_scan_commit_list(struct list_head *src, struct list_head *dst,
		     struct nfs_commit_info *cinfo, int max)
{
	struct nfs_page *req, *tmp;
	int ret = 0;

	list_for_each_entry_safe(req, tmp, src, wb_list) {
		if (!nfs_lock_request(req))
			continue;
		kref_get(&req->wb_kref);
		if (cond_resched_lock(cinfo->lock))
			list_safe_reset_next(req, tmp, wb_list);
		nfs_request_remove_commit_list(req, cinfo);
		nfs_list_add_request(req, dst);
		ret++;
		if ((ret == max) && !cinfo->dreq)
			break;
	}
	return ret;
}

/*
 * nfs_scan_commit - Scan an inode for commit requests
 * @inode: NFS inode to scan
 * @dst: mds destination list
 * @cinfo: mds and ds lists of reqs ready to commit
 *
 * Moves requests from the inode's 'commit' request list.
 * The requests are *not* checked to ensure that they form a contiguous set.
 */
int
nfs_scan_commit(struct inode *inode, struct list_head *dst,
		struct nfs_commit_info *cinfo)
{
	int ret = 0;

	spin_lock(cinfo->lock);
	if (cinfo->mds->ncommit > 0) {
		const int max = INT_MAX;

		ret = nfs_scan_commit_list(&cinfo->mds->list, dst,
					   cinfo, max);
		ret += pnfs_scan_commit_lists(inode, cinfo, max - ret);
	}
	spin_unlock(cinfo->lock);
	return ret;
}

#else
unsigned long nfs_reqs_to_commit(struct nfs_commit_info *cinfo)
{
	return 0;
}

int nfs_scan_commit(struct inode *inode, struct list_head *dst,
		    struct nfs_commit_info *cinfo)
{
	return 0;
}
#endif

/*
 * Search for an existing write request, and attempt to update
 * it to reflect a new dirty region on a given page.
 *
 * If the attempt fails, then the existing request is flushed out
 * to disk.
 */
static struct nfs_page *nfs_try_to_update_request(struct inode *inode,
		struct page *page,
		unsigned int offset,
		unsigned int bytes)
{
	struct nfs_page *req;
	unsigned int rqend;
	unsigned int end;
	int error;

	if (!PagePrivate(page))
		return NULL;

	end = offset + bytes;
	spin_lock(&inode->i_lock);

	for (;;) {
		req = nfs_page_find_head_request_locked(NFS_I(inode), page);
		if (req == NULL)
			goto out_unlock;

		/* should be handled by nfs_flush_incompatible */
		WARN_ON_ONCE(req->wb_head != req);
		WARN_ON_ONCE(req->wb_this_page != req);

		rqend = req->wb_offset + req->wb_bytes;
		/*
		 * Tell the caller to flush out the request if
		 * the offsets are non-contiguous.
		 * Note: nfs_flush_incompatible() will already
		 * have flushed out requests having wrong owners.
		 */
		if (offset > rqend
		    || end < req->wb_offset)
			goto out_flushme;

		if (nfs_lock_request(req))
			break;

		/* The request is locked, so wait and then retry */
		spin_unlock(&inode->i_lock);
		error = nfs_wait_on_request(req);
		nfs_release_request(req);
		if (error != 0)
			goto out_err;
		spin_lock(&inode->i_lock);
	}

	/* Okay, the request matches. Update the region */
	if (offset < req->wb_offset) {
		req->wb_offset = offset;
		req->wb_pgbase = offset;
	}
	if (end > rqend)
		req->wb_bytes = end - req->wb_offset;
	else
		req->wb_bytes = rqend - req->wb_offset;
out_unlock:
	if (req)
		nfs_clear_request_commit(req);
	spin_unlock(&inode->i_lock);
	return req;
out_flushme:
	spin_unlock(&inode->i_lock);
	nfs_release_request(req);
	error = nfs_wb_page(inode, page);
out_err:
	return ERR_PTR(error);
}

/*
 * Try to update an existing write request, or create one if there is none.
 *
 * Note: Should always be called with the Page Lock held to prevent races
 * if we have to add a new request. Also assumes that the caller has
 * already called nfs_flush_incompatible() if necessary.
 */
static struct nfs_page * nfs_setup_write_request(struct nfs_open_context* ctx,
		struct page *page, unsigned int offset, unsigned int bytes)
{
	struct inode *inode = page_file_mapping(page)->host;
	struct nfs_page	*req;

	req = nfs_try_to_update_request(inode, page, offset, bytes);
	if (req != NULL)
		goto out;
	req = nfs_create_request(ctx, page, NULL, offset, bytes);
	if (IS_ERR(req))
		goto out;
	nfs_inode_add_request(inode, req);
out:
	return req;
}

static int nfs_writepage_setup(struct nfs_open_context *ctx, struct page *page,
		unsigned int offset, unsigned int count)
{
	struct nfs_page	*req;

	req = nfs_setup_write_request(ctx, page, offset, count);
	if (IS_ERR(req))
		return PTR_ERR(req);
	/* Update file length */
	nfs_grow_file(page, offset, count);
	nfs_mark_uptodate(req);
	nfs_mark_request_dirty(req);
	nfs_unlock_and_release_request(req);
	return 0;
}

int nfs_flush_incompatible(struct file *file, struct page *page)
{
	struct nfs_open_context *ctx = nfs_file_open_context(file);
	struct nfs_lock_context *l_ctx;
	struct nfs_page	*req;
	int do_flush, status;
	/*
	 * Look for a request corresponding to this page. If there
	 * is one, and it belongs to another file, we flush it out
	 * before we try to copy anything into the page. Do this
	 * due to the lack of an ACCESS-type call in NFSv2.
	 * Also do the same if we find a request from an existing
	 * dropped page.
	 */
	do {
		req = nfs_page_find_head_request(page);
		if (req == NULL)
			return 0;
		l_ctx = req->wb_lock_context;
		do_flush = req->wb_page != page || req->wb_context != ctx;
		/* for now, flush if more than 1 request in page_group */
		do_flush |= req->wb_this_page != req;
		if (l_ctx && ctx->dentry->d_inode->i_flock != NULL) {
			do_flush |= l_ctx->lockowner.l_owner != current->files
				|| l_ctx->lockowner.l_pid != current->tgid;
		}
		nfs_release_request(req);
		if (!do_flush)
			return 0;
		status = nfs_wb_page(page_file_mapping(page)->host, page);
	} while (status == 0);
	return status;
}

/*
 * Avoid buffered writes when a open context credential's key would
 * expire soon.
 *
 * Returns -EACCES if the key will expire within RPC_KEY_EXPIRE_FAIL.
 *
 * Return 0 and set a credential flag which triggers the inode to flush
 * and performs  NFS_FILE_SYNC writes if the key will expired within
 * RPC_KEY_EXPIRE_TIMEO.
 */
int
nfs_key_timeout_notify(struct file *filp, struct inode *inode)
{
	struct nfs_open_context *ctx = nfs_file_open_context(filp);
	struct rpc_auth *auth = NFS_SERVER(inode)->client->cl_auth;

	return rpcauth_key_timeout_notify(auth, ctx->cred);
}

/*
 * Test if the open context credential key is marked to expire soon.
 */
bool nfs_ctx_key_to_expire(struct nfs_open_context *ctx)
{
	return rpcauth_cred_key_to_expire(ctx->cred);
}

/*
 * If the page cache is marked as unsafe or invalid, then we can't rely on
 * the PageUptodate() flag. In this case, we will need to turn off
 * write optimisations that depend on the page contents being correct.
 */
static bool nfs_write_pageuptodate(struct page *page, struct inode *inode)
{
	struct nfs_inode *nfsi = NFS_I(inode);

	if (nfs_have_delegated_attributes(inode))
		goto out;
	if (nfsi->cache_validity & NFS_INO_REVAL_PAGECACHE)
		return false;
	smp_rmb();
	if (test_bit(NFS_INO_INVALIDATING, &nfsi->flags))
		return false;
out:
	if (nfsi->cache_validity & NFS_INO_INVALID_DATA)
		return false;
	return PageUptodate(page) != 0;
}

/* If we know the page is up to date, and we're not using byte range locks (or
 * if we have the whole file locked for writing), it may be more efficient to
 * extend the write to cover the entire page in order to avoid fragmentation
 * inefficiencies.
 *
 * If the file is opened for synchronous writes then we can just skip the rest
 * of the checks.
 */
static int nfs_can_extend_write(struct file *file, struct page *page, struct inode *inode)
{
	if (file->f_flags & O_DSYNC)
		return 0;
	if (!nfs_write_pageuptodate(page, inode))
		return 0;
	if (NFS_PROTO(inode)->have_delegation(inode, FMODE_WRITE))
		return 1;
	if (inode->i_flock == NULL || (inode->i_flock->fl_start == 0 &&
			inode->i_flock->fl_end == OFFSET_MAX &&
			inode->i_flock->fl_type != F_RDLCK))
		return 1;
	return 0;
}

/*
 * Update and possibly write a cached page of an NFS file.
 *
 * XXX: Keep an eye on generic_file_read to make sure it doesn't do bad
 * things with a page scheduled for an RPC call (e.g. invalidate it).
 */
int nfs_updatepage(struct file *file, struct page *page,
		unsigned int offset, unsigned int count)
{
	struct nfs_open_context *ctx = nfs_file_open_context(file);
	struct inode	*inode = page_file_mapping(page)->host;
	int		status = 0;

	nfs_inc_stats(inode, NFSIOS_VFSUPDATEPAGE);

	dprintk("NFS:       nfs_updatepage(%pD2 %d@%lld)\n",
		file, count, (long long)(page_file_offset(page) + offset));

	if (nfs_can_extend_write(file, page, inode)) {
		count = max(count + offset, nfs_page_length(page));
		offset = 0;
	}

	status = nfs_writepage_setup(ctx, page, offset, count);
	if (status < 0)
		nfs_set_pageerror(page);
	else
		__set_page_dirty_nobuffers(page);

	dprintk("NFS:       nfs_updatepage returns %d (isize %lld)\n",
			status, (long long)i_size_read(inode));
	return status;
}

static int flush_task_priority(int how)
{
	switch (how & (FLUSH_HIGHPRI|FLUSH_LOWPRI)) {
		case FLUSH_HIGHPRI:
			return RPC_PRIORITY_HIGH;
		case FLUSH_LOWPRI:
			return RPC_PRIORITY_LOW;
	}
	return RPC_PRIORITY_NORMAL;
}

static void nfs_initiate_write(struct nfs_pgio_header *hdr,
			       struct rpc_message *msg,
			       struct rpc_task_setup *task_setup_data, int how)
{
	struct inode *inode = hdr->inode;
	int priority = flush_task_priority(how);

	task_setup_data->priority = priority;
	NFS_PROTO(inode)->write_setup(hdr, msg);

	nfs4_state_protect_write(NFS_SERVER(inode)->nfs_client,
				 &task_setup_data->rpc_client, msg, hdr);
}

/* If a nfs_flush_* function fails, it should remove reqs from @head and
 * call this on each, which will prepare them to be retried on next
 * writeback using standard nfs.
 */
static void nfs_redirty_request(struct nfs_page *req)
{
	nfs_mark_request_dirty(req);
	nfs_unlock_request(req);
	nfs_end_page_writeback(req);
	nfs_release_request(req);
}

static void nfs_async_write_error(struct list_head *head)
{
	struct nfs_page	*req;

	while (!list_empty(head)) {
		req = nfs_list_entry(head->next);
		nfs_list_remove_request(req);
		nfs_redirty_request(req);
	}
}

static const struct nfs_pgio_completion_ops nfs_async_write_completion_ops = {
	.error_cleanup = nfs_async_write_error,
	.completion = nfs_write_completion,
};

void nfs_pageio_init_write(struct nfs_pageio_descriptor *pgio,
			       struct inode *inode, int ioflags, bool force_mds,
			       const struct nfs_pgio_completion_ops *compl_ops)
{
	struct nfs_server *server = NFS_SERVER(inode);
	const struct nfs_pageio_ops *pg_ops = &nfs_pgio_rw_ops;

#ifdef CONFIG_NFS_V4_1
	if (server->pnfs_curr_ld && !force_mds)
		pg_ops = server->pnfs_curr_ld->pg_write_ops;
#endif
	nfs_pageio_init(pgio, inode, pg_ops, compl_ops, &nfs_rw_write_ops,
			server->wsize, ioflags);
}
EXPORT_SYMBOL_GPL(nfs_pageio_init_write);

void nfs_pageio_reset_write_mds(struct nfs_pageio_descriptor *pgio)
{
	pgio->pg_ops = &nfs_pgio_rw_ops;
	pgio->pg_bsize = NFS_SERVER(pgio->pg_inode)->wsize;
}
EXPORT_SYMBOL_GPL(nfs_pageio_reset_write_mds);


void nfs_commit_prepare(struct rpc_task *task, void *calldata)
{
	struct nfs_commit_data *data = calldata;

	NFS_PROTO(data->inode)->commit_rpc_prepare(task, data);
}

static void nfs_writeback_release_common(struct nfs_pgio_header *hdr)
{
	/* do nothing! */
}

/*
 * Special version of should_remove_suid() that ignores capabilities.
 */
static int nfs_should_remove_suid(const struct inode *inode)
{
	umode_t mode = inode->i_mode;
	int kill = 0;

	/* suid always must be killed */
	if (unlikely(mode & S_ISUID))
		kill = ATTR_KILL_SUID;

	/*
	 * sgid without any exec bits is just a mandatory locking mark; leave
	 * it alone.  If some exec bits are set, it's a real sgid; kill it.
	 */
	if (unlikely((mode & S_ISGID) && (mode & S_IXGRP)))
		kill |= ATTR_KILL_SGID;

	if (unlikely(kill && S_ISREG(mode)))
		return kill;

	return 0;
}

/*
 * This function is called when the WRITE call is complete.
 */
static int nfs_writeback_done(struct rpc_task *task,
			      struct nfs_pgio_header *hdr,
			      struct inode *inode)
{
	int status;

	/*
	 * ->write_done will attempt to use post-op attributes to detect
	 * conflicting writes by other clients.  A strict interpretation
	 * of close-to-open would allow us to continue caching even if
	 * another writer had changed the file, but some applications
	 * depend on tighter cache coherency when writing.
	 */
	status = NFS_PROTO(inode)->write_done(task, hdr);
	if (status != 0)
		return status;
	nfs_add_stats(inode, NFSIOS_SERVERWRITTENBYTES, hdr->res.count);

#if IS_ENABLED(CONFIG_NFS_V3) || IS_ENABLED(CONFIG_NFS_V4)
	if (hdr->res.verf->committed < hdr->args.stable &&
	    task->tk_status >= 0) {
		/* We tried a write call, but the server did not
		 * commit data to stable storage even though we
		 * requested it.
		 * Note: There is a known bug in Tru64 < 5.0 in which
		 *	 the server reports NFS_DATA_SYNC, but performs
		 *	 NFS_FILE_SYNC. We therefore implement this checking
		 *	 as a dprintk() in order to avoid filling syslog.
		 */
		static unsigned long    complain;

		/* Note this will print the MDS for a DS write */
		if (time_before(complain, jiffies)) {
			dprintk("NFS:       faulty NFS server %s:"
				" (committed = %d) != (stable = %d)\n",
				NFS_SERVER(inode)->nfs_client->cl_hostname,
				hdr->res.verf->committed, hdr->args.stable);
			complain = jiffies + 300 * HZ;
		}
	}
#endif

	/* Deal with the suid/sgid bit corner case */
	if (nfs_should_remove_suid(inode))
		nfs_mark_for_revalidate(inode);
	return 0;
}

/*
 * This function is called when the WRITE call is complete.
 */
static void nfs_writeback_result(struct rpc_task *task,
				 struct nfs_pgio_header *hdr)
{
	struct nfs_pgio_args	*argp = &hdr->args;
	struct nfs_pgio_res	*resp = &hdr->res;

	if (resp->count < argp->count) {
		static unsigned long    complain;

		/* This a short write! */
		nfs_inc_stats(hdr->inode, NFSIOS_SHORTWRITE);

		/* Has the server at least made some progress? */
		if (resp->count == 0) {
			if (time_before(complain, jiffies)) {
				printk(KERN_WARNING
				       "NFS: Server wrote zero bytes, expected %u.\n",
				       argp->count);
				complain = jiffies + 300 * HZ;
			}
			nfs_set_pgio_error(hdr, -EIO, argp->offset);
			task->tk_status = -EIO;
			return;
		}
		/* Was this an NFSv2 write or an NFSv3 stable write? */
		if (resp->verf->committed != NFS_UNSTABLE) {
			/* Resend from where the server left off */
			hdr->mds_offset += resp->count;
			argp->offset += resp->count;
			argp->pgbase += resp->count;
			argp->count -= resp->count;
		} else {
			/* Resend as a stable write in order to avoid
			 * headaches in the case of a server crash.
			 */
			argp->stable = NFS_FILE_SYNC;
		}
		rpc_restart_call_prepare(task);
	}
}


#if IS_ENABLED(CONFIG_NFS_V3) || IS_ENABLED(CONFIG_NFS_V4)
static int nfs_commit_set_lock(struct nfs_inode *nfsi, int may_wait)
{
	int ret;

	if (!test_and_set_bit(NFS_INO_COMMIT, &nfsi->flags))
		return 1;
	if (!may_wait)
		return 0;
	ret = out_of_line_wait_on_bit_lock(&nfsi->flags,
				NFS_INO_COMMIT,
				nfs_wait_bit_killable,
				TASK_KILLABLE);
	return (ret < 0) ? ret : 1;
}

static void nfs_commit_clear_lock(struct nfs_inode *nfsi)
{
	clear_bit(NFS_INO_COMMIT, &nfsi->flags);
	smp_mb__after_atomic();
	wake_up_bit(&nfsi->flags, NFS_INO_COMMIT);
}

void nfs_commitdata_release(struct nfs_commit_data *data)
{
	put_nfs_open_context(data->context);
	nfs_commit_free(data);
}
EXPORT_SYMBOL_GPL(nfs_commitdata_release);

int nfs_initiate_commit(struct rpc_clnt *clnt, struct nfs_commit_data *data,
			const struct rpc_call_ops *call_ops,
			int how, int flags)
{
	struct rpc_task *task;
	int priority = flush_task_priority(how);
	struct rpc_message msg = {
		.rpc_argp = &data->args,
		.rpc_resp = &data->res,
		.rpc_cred = data->cred,
	};
	struct rpc_task_setup task_setup_data = {
		.task = &data->task,
		.rpc_client = clnt,
		.rpc_message = &msg,
		.callback_ops = call_ops,
		.callback_data = data,
		.workqueue = nfsiod_workqueue,
		.flags = RPC_TASK_ASYNC | flags,
		.priority = priority,
	};
	/* Set up the initial task struct.  */
	NFS_PROTO(data->inode)->commit_setup(data, &msg);

	dprintk("NFS: %5u initiated commit call\n", data->task.tk_pid);

	nfs4_state_protect(NFS_SERVER(data->inode)->nfs_client,
		NFS_SP4_MACH_CRED_COMMIT, &task_setup_data.rpc_client, &msg);

	task = rpc_run_task(&task_setup_data);
	if (IS_ERR(task))
		return PTR_ERR(task);
	if (how & FLUSH_SYNC)
		rpc_wait_for_completion_task(task);
	rpc_put_task(task);
	return 0;
}
EXPORT_SYMBOL_GPL(nfs_initiate_commit);

/*
 * Set up the argument/result storage required for the RPC call.
 */
void nfs_init_commit(struct nfs_commit_data *data,
		     struct list_head *head,
		     struct pnfs_layout_segment *lseg,
		     struct nfs_commit_info *cinfo)
{
	struct nfs_page *first = nfs_list_entry(head->next);
	struct inode *inode = first->wb_context->dentry->d_inode;

	/* Set up the RPC argument and reply structs
	 * NB: take care not to mess about with data->commit et al. */

	list_splice_init(head, &data->pages);

	data->inode	  = inode;
	data->cred	  = first->wb_context->cred;
	data->lseg	  = lseg; /* reference transferred */
	data->mds_ops     = &nfs_commit_ops;
	data->completion_ops = cinfo->completion_ops;
	data->dreq	  = cinfo->dreq;

	data->args.fh     = NFS_FH(data->inode);
	/* Note: we always request a commit of the entire inode */
	data->args.offset = 0;
	data->args.count  = 0;
	data->context     = get_nfs_open_context(first->wb_context);
	data->res.fattr   = &data->fattr;
	data->res.verf    = &data->verf;
	nfs_fattr_init(&data->fattr);
}
EXPORT_SYMBOL_GPL(nfs_init_commit);

void nfs_retry_commit(struct list_head *page_list,
		      struct pnfs_layout_segment *lseg,
		      struct nfs_commit_info *cinfo)
{
	struct nfs_page *req;

	while (!list_empty(page_list)) {
		req = nfs_list_entry(page_list->next);
		nfs_list_remove_request(req);
		nfs_mark_request_commit(req, lseg, cinfo);
		if (!cinfo->dreq) {
			dec_zone_page_state(req->wb_page, NR_UNSTABLE_NFS);
			dec_bdi_stat(page_file_mapping(req->wb_page)->backing_dev_info,
				     BDI_RECLAIMABLE);
		}
		nfs_unlock_and_release_request(req);
	}
}
EXPORT_SYMBOL_GPL(nfs_retry_commit);

/*
 * Commit dirty pages
 */
static int
nfs_commit_list(struct inode *inode, struct list_head *head, int how,
		struct nfs_commit_info *cinfo)
{
	struct nfs_commit_data	*data;

	data = nfs_commitdata_alloc();

	if (!data)
		goto out_bad;

	/* Set up the argument struct */
	nfs_init_commit(data, head, NULL, cinfo);
	atomic_inc(&cinfo->mds->rpcs_out);
	return nfs_initiate_commit(NFS_CLIENT(inode), data, data->mds_ops,
				   how, 0);
 out_bad:
	nfs_retry_commit(head, NULL, cinfo);
	cinfo->completion_ops->error_cleanup(NFS_I(inode));
	return -ENOMEM;
}

/*
 * COMMIT call returned
 */
static void nfs_commit_done(struct rpc_task *task, void *calldata)
{
	struct nfs_commit_data	*data = calldata;

        dprintk("NFS: %5u nfs_commit_done (status %d)\n",
                                task->tk_pid, task->tk_status);

	/* Call the NFS version-specific code */
	NFS_PROTO(data->inode)->commit_done(task, data);
}

static void nfs_commit_release_pages(struct nfs_commit_data *data)
{
	struct nfs_page	*req;
	int status = data->task.tk_status;
	struct nfs_commit_info cinfo;

	while (!list_empty(&data->pages)) {
		req = nfs_list_entry(data->pages.next);
		nfs_list_remove_request(req);
		nfs_clear_page_commit(req->wb_page);

		dprintk("NFS:       commit (%s/%llu %d@%lld)",
			req->wb_context->dentry->d_sb->s_id,
			(unsigned long long)NFS_FILEID(req->wb_context->dentry->d_inode),
			req->wb_bytes,
			(long long)req_offset(req));
		if (status < 0) {
			nfs_context_set_write_error(req->wb_context, status);
			nfs_inode_remove_request(req);
			dprintk(", error = %d\n", status);
			goto next;
		}

		/* Okay, COMMIT succeeded, apparently. Check the verifier
		 * returned by the server against all stored verfs. */
		if (!memcmp(&req->wb_verf, &data->verf.verifier, sizeof(req->wb_verf))) {
			/* We have a match */
			nfs_inode_remove_request(req);
			dprintk(" OK\n");
			goto next;
		}
		/* We have a mismatch. Write the page again */
		dprintk(" mismatch\n");
		nfs_mark_request_dirty(req);
		set_bit(NFS_CONTEXT_RESEND_WRITES, &req->wb_context->flags);
	next:
		nfs_unlock_and_release_request(req);
	}
	nfs_init_cinfo(&cinfo, data->inode, data->dreq);
	if (atomic_dec_and_test(&cinfo.mds->rpcs_out))
		nfs_commit_clear_lock(NFS_I(data->inode));
}

static void nfs_commit_release(void *calldata)
{
	struct nfs_commit_data *data = calldata;

	data->completion_ops->completion(data);
	nfs_commitdata_release(calldata);
}

static const struct rpc_call_ops nfs_commit_ops = {
	.rpc_call_prepare = nfs_commit_prepare,
	.rpc_call_done = nfs_commit_done,
	.rpc_release = nfs_commit_release,
};

static const struct nfs_commit_completion_ops nfs_commit_completion_ops = {
	.completion = nfs_commit_release_pages,
	.error_cleanup = nfs_commit_clear_lock,
};

int nfs_generic_commit_list(struct inode *inode, struct list_head *head,
			    int how, struct nfs_commit_info *cinfo)
{
	int status;

	status = pnfs_commit_list(inode, head, how, cinfo);
	if (status == PNFS_NOT_ATTEMPTED)
		status = nfs_commit_list(inode, head, how, cinfo);
	return status;
}

int nfs_commit_inode(struct inode *inode, int how)
{
	LIST_HEAD(head);
	struct nfs_commit_info cinfo;
	int may_wait = how & FLUSH_SYNC;
	int res;

	res = nfs_commit_set_lock(NFS_I(inode), may_wait);
	if (res <= 0)
		goto out_mark_dirty;
	nfs_init_cinfo_from_inode(&cinfo, inode);
	res = nfs_scan_commit(inode, &head, &cinfo);
	if (res) {
		int error;

		error = nfs_generic_commit_list(inode, &head, how, &cinfo);
		if (error < 0)
			return error;
		if (!may_wait)
			goto out_mark_dirty;
		error = wait_on_bit_action(&NFS_I(inode)->flags,
				NFS_INO_COMMIT,
				nfs_wait_bit_killable,
				TASK_KILLABLE);
		if (error < 0)
			return error;
	} else
		nfs_commit_clear_lock(NFS_I(inode));
	return res;
	/* Note: If we exit without ensuring that the commit is complete,
	 * we must mark the inode as dirty. Otherwise, future calls to
	 * sync_inode() with the WB_SYNC_ALL flag set will fail to ensure
	 * that the data is on the disk.
	 */
out_mark_dirty:
	__mark_inode_dirty(inode, I_DIRTY_DATASYNC);
	return res;
}

static int nfs_commit_unstable_pages(struct inode *inode, struct writeback_control *wbc)
{
	struct nfs_inode *nfsi = NFS_I(inode);
	int flags = FLUSH_SYNC;
	int ret = 0;

	/* no commits means nothing needs to be done */
	if (!nfsi->commit_info.ncommit)
		return ret;

	if (wbc->sync_mode == WB_SYNC_NONE) {
		/* Don't commit yet if this is a non-blocking flush and there
		 * are a lot of outstanding writes for this mapping.
		 */
		if (nfsi->commit_info.ncommit <= (nfsi->npages >> 1))
			goto out_mark_dirty;

		/* don't wait for the COMMIT response */
		flags = 0;
	}

	ret = nfs_commit_inode(inode, flags);
	if (ret >= 0) {
		if (wbc->sync_mode == WB_SYNC_NONE) {
			if (ret < wbc->nr_to_write)
				wbc->nr_to_write -= ret;
			else
				wbc->nr_to_write = 0;
		}
		return 0;
	}
out_mark_dirty:
	__mark_inode_dirty(inode, I_DIRTY_DATASYNC);
	return ret;
}
#else
static int nfs_commit_unstable_pages(struct inode *inode, struct writeback_control *wbc)
{
	return 0;
}
#endif

int nfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return nfs_commit_unstable_pages(inode, wbc);
}
EXPORT_SYMBOL_GPL(nfs_write_inode);

/*
 * flush the inode to disk.
 */
int nfs_wb_all(struct inode *inode)
{
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = LONG_MAX,
		.range_start = 0,
		.range_end = LLONG_MAX,
	};
	int ret;

	trace_nfs_writeback_inode_enter(inode);

	ret = sync_inode(inode, &wbc);

	trace_nfs_writeback_inode_exit(inode, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(nfs_wb_all);

int nfs_wb_page_cancel(struct inode *inode, struct page *page)
{
	struct nfs_page *req;
	int ret = 0;

	wait_on_page_writeback(page);

	/* blocking call to cancel all requests and join to a single (head)
	 * request */
	req = nfs_lock_and_join_requests(page, false);

	if (IS_ERR(req)) {
		ret = PTR_ERR(req);
	} else if (req) {
		/* all requests from this page have been cancelled by
		 * nfs_lock_and_join_requests, so just remove the head
		 * request from the inode / page_private pointer and
		 * release it */
		nfs_inode_remove_request(req);
		/*
		 * In case nfs_inode_remove_request has marked the
		 * page as being dirty
		 */
		cancel_dirty_page(page, PAGE_CACHE_SIZE);
		nfs_unlock_and_release_request(req);
	}

	return ret;
}

/*
 * Write back all requests on one page - we do this before reading it.
 */
int nfs_wb_page(struct inode *inode, struct page *page)
{
	loff_t range_start = page_file_offset(page);
	loff_t range_end = range_start + (loff_t)(PAGE_CACHE_SIZE - 1);
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = 0,
		.range_start = range_start,
		.range_end = range_end,
	};
	int ret;

	trace_nfs_writeback_page_enter(inode);

	for (;;) {
		wait_on_page_writeback(page);
		if (clear_page_dirty_for_io(page)) {
			ret = nfs_writepage_locked(page, &wbc);
			if (ret < 0)
				goto out_error;
			continue;
		}
		ret = 0;
		if (!PagePrivate(page))
			break;
		ret = nfs_commit_inode(inode, FLUSH_SYNC);
		if (ret < 0)
			goto out_error;
	}
out_error:
	trace_nfs_writeback_page_exit(inode, ret);
	return ret;
}

#ifdef CONFIG_MIGRATION
int nfs_migrate_page(struct address_space *mapping, struct page *newpage,
		struct page *page, enum migrate_mode mode)
{
	/*
	 * If PagePrivate is set, then the page is currently associated with
	 * an in-progress read or write request. Don't try to migrate it.
	 *
	 * FIXME: we could do this in principle, but we'll need a way to ensure
	 *        that we can safely release the inode reference while holding
	 *        the page lock.
	 */
	if (PagePrivate(page))
		return -EBUSY;

	if (!nfs_fscache_release_page(page, GFP_KERNEL))
		return -EBUSY;

	return migrate_page(mapping, newpage, page, mode);
}
#endif

int __init nfs_init_writepagecache(void)
{
	nfs_wdata_cachep = kmem_cache_create("nfs_write_data",
					     sizeof(struct nfs_pgio_header),
					     0, SLAB_HWCACHE_ALIGN,
					     NULL);
	if (nfs_wdata_cachep == NULL)
		return -ENOMEM;

	nfs_wdata_mempool = mempool_create_slab_pool(MIN_POOL_WRITE,
						     nfs_wdata_cachep);
	if (nfs_wdata_mempool == NULL)
		goto out_destroy_write_cache;

	nfs_cdata_cachep = kmem_cache_create("nfs_commit_data",
					     sizeof(struct nfs_commit_data),
					     0, SLAB_HWCACHE_ALIGN,
					     NULL);
	if (nfs_cdata_cachep == NULL)
		goto out_destroy_write_mempool;

	nfs_commit_mempool = mempool_create_slab_pool(MIN_POOL_COMMIT,
						      nfs_cdata_cachep);
	if (nfs_commit_mempool == NULL)
		goto out_destroy_commit_cache;

	/*
	 * NFS congestion size, scale with available memory.
	 *
	 *  64MB:    8192k
	 * 128MB:   11585k
	 * 256MB:   16384k
	 * 512MB:   23170k
	 *   1GB:   32768k
	 *   2GB:   46340k
	 *   4GB:   65536k
	 *   8GB:   92681k
	 *  16GB:  131072k
	 *
	 * This allows larger machines to have larger/more transfers.
	 * Limit the default to 256M
	 */
	nfs_congestion_kb = (16*int_sqrt(totalram_pages)) << (PAGE_SHIFT-10);
	if (nfs_congestion_kb > 256*1024)
		nfs_congestion_kb = 256*1024;

	return 0;

out_destroy_commit_cache:
	kmem_cache_destroy(nfs_cdata_cachep);
out_destroy_write_mempool:
	mempool_destroy(nfs_wdata_mempool);
out_destroy_write_cache:
	kmem_cache_destroy(nfs_wdata_cachep);
	return -ENOMEM;
}

void nfs_destroy_writepagecache(void)
{
	mempool_destroy(nfs_commit_mempool);
	kmem_cache_destroy(nfs_cdata_cachep);
	mempool_destroy(nfs_wdata_mempool);
	kmem_cache_destroy(nfs_wdata_cachep);
}

static const struct nfs_rw_ops nfs_rw_write_ops = {
	.rw_mode		= FMODE_WRITE,
	.rw_alloc_header	= nfs_writehdr_alloc,
	.rw_free_header		= nfs_writehdr_free,
	.rw_release		= nfs_writeback_release_common,
	.rw_done		= nfs_writeback_done,
	.rw_result		= nfs_writeback_result,
	.rw_initiate		= nfs_initiate_write,
};
/************************************************************/
/* ../linux-3.17/fs/nfs/write.c */
/************************************************************/
/*
 * linux/fs/nfs/namespace.c
 *
 * Copyright (C) 2005 Trond Myklebust <Trond.Myklebust@netapp.com>
 * - Modified by David Howells <dhowells@redhat.com>
 *
 * NFS namespace
 */

// #include <linux/module.h>
// #include <linux/dcache.h>
// #include <linux/gfp.h>
// #include <linux/mount.h>
// #include <linux/namei.h>
// #include <linux/nfs_fs.h>
// #include <linux/string.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/vfs.h>
#include <linux/sunrpc/gss_api.h>
// #include "internal.h"

#define NFSDBG_FACILITY		NFSDBG_VFS

static void nfs_expire_automounts(struct work_struct *work);

static LIST_HEAD_namespace_c(nfs_automount_list);
static DECLARE_DELAYED_WORK(nfs_automount_task, nfs_expire_automounts);
int nfs_mountpoint_expiry_timeout = 500 * HZ;

/*
 * nfs_path - reconstruct the path given an arbitrary dentry
 * @base - used to return pointer to the end of devname part of path
 * @dentry - pointer to dentry
 * @buffer - result buffer
 * @buflen - length of buffer
 * @flags - options (see below)
 *
 * Helper function for constructing the server pathname
 * by arbitrary hashed dentry.
 *
 * This is mainly for use in figuring out the path on the
 * server side when automounting on top of an existing partition
 * and in generating /proc/mounts and friends.
 *
 * Supported flags:
 * NFS_PATH_CANONICAL: ensure there is exactly one slash after
 *		       the original device (export) name
 *		       (if unset, the original name is returned verbatim)
 */
char *nfs_path(char **p, struct dentry *dentry, char *buffer, ssize_t buflen,
	       unsigned flags)
{
	char *end;
	int namelen;
	unsigned seq;
	const char *base;

rename_retry:
	end = buffer+buflen;
	*--end = '\0';
	buflen--;

	seq = read_seqbegin(&rename_lock);
	rcu_read_lock();
	while (1) {
		spin_lock(&dentry->d_lock);
		if (IS_ROOT(dentry))
			break;
		namelen = dentry->d_name.len;
		buflen -= namelen + 1;
		if (buflen < 0)
			goto Elong_unlock;
		end -= namelen;
		memcpy(end, dentry->d_name.name, namelen);
		*--end = '/';
		spin_unlock(&dentry->d_lock);
		dentry = dentry->d_parent;
	}
	if (read_seqretry(&rename_lock, seq)) {
		spin_unlock(&dentry->d_lock);
		rcu_read_unlock();
		goto rename_retry;
	}
	if ((flags & NFS_PATH_CANONICAL) && *end != '/') {
		if (--buflen < 0) {
			spin_unlock(&dentry->d_lock);
			rcu_read_unlock();
			goto Elong;
		}
		*--end = '/';
	}
	*p = end;
	base = dentry->d_fsdata;
	if (!base) {
		spin_unlock(&dentry->d_lock);
		rcu_read_unlock();
		WARN_ON(1);
		return end;
	}
	namelen = strlen(base);
	if (flags & NFS_PATH_CANONICAL) {
		/* Strip off excess slashes in base string */
		while (namelen > 0 && base[namelen - 1] == '/')
			namelen--;
	}
	buflen -= namelen;
	if (buflen < 0) {
		spin_unlock(&dentry->d_lock);
		rcu_read_unlock();
		goto Elong;
	}
	end -= namelen;
	memcpy(end, base, namelen);
	spin_unlock(&dentry->d_lock);
	rcu_read_unlock();
	return end;
Elong_unlock:
	spin_unlock(&dentry->d_lock);
	rcu_read_unlock();
	if (read_seqretry(&rename_lock, seq))
		goto rename_retry;
Elong:
	return ERR_PTR(-ENAMETOOLONG);
}
EXPORT_SYMBOL_GPL(nfs_path);

/*
 * nfs_d_automount - Handle crossing a mountpoint on the server
 * @path - The mountpoint
 *
 * When we encounter a mountpoint on the server, we want to set up
 * a mountpoint on the client too, to prevent inode numbers from
 * colliding, and to allow "df" to work properly.
 * On NFSv4, we also want to allow for the fact that different
 * filesystems may be migrated to different servers in a failover
 * situation, and that different filesystems may want to use
 * different security flavours.
 */
struct vfsmount *nfs_d_automount(struct path *path)
{
	struct vfsmount *mnt;
	struct nfs_server *server = NFS_SERVER(path->dentry->d_inode);
	struct nfs_fh *fh = NULL;
	struct nfs_fattr *fattr = NULL;

	dprintk("--> nfs_d_automount()\n");

	mnt = ERR_PTR(-ESTALE);
	if (IS_ROOT(path->dentry))
		goto out_nofree;

	mnt = ERR_PTR(-ENOMEM);
	fh = nfs_alloc_fhandle();
	fattr = nfs_alloc_fattr();
	if (fh == NULL || fattr == NULL)
		goto out;

	dprintk("%s: enter\n", __func__);

	mnt = server->nfs_client->rpc_ops->submount(server, path->dentry, fh, fattr);
	if (IS_ERR(mnt))
		goto out;

	dprintk("%s: done, success\n", __func__);
	mntget(mnt); /* prevent immediate expiration */
	mnt_set_expiry(mnt, &nfs_automount_list);
	schedule_delayed_work(&nfs_automount_task, nfs_mountpoint_expiry_timeout);

out:
	nfs_free_fattr(fattr);
	nfs_free_fhandle(fh);
out_nofree:
	if (IS_ERR(mnt))
		dprintk("<-- %s(): error %ld\n", __func__, PTR_ERR(mnt));
	else
		dprintk("<-- %s() = %p\n", __func__, mnt);
	return mnt;
}

static int
nfs_namespace_getattr(struct vfsmount *mnt, struct dentry *dentry, struct kstat *stat)
{
	if (NFS_FH(dentry->d_inode)->size != 0)
		return nfs_getattr(mnt, dentry, stat);
	generic_fillattr(dentry->d_inode, stat);
	return 0;
}

static int
nfs_namespace_setattr(struct dentry *dentry, struct iattr *attr)
{
	if (NFS_FH(dentry->d_inode)->size != 0)
		return nfs_setattr(dentry, attr);
	return -EACCES;
}

const struct inode_operations nfs_mountpoint_inode_operations = {
	.getattr	= nfs_getattr,
	.setattr	= nfs_setattr,
};

const struct inode_operations nfs_referral_inode_operations = {
	.getattr	= nfs_namespace_getattr,
	.setattr	= nfs_namespace_setattr,
};

static void nfs_expire_automounts(struct work_struct *work)
{
	struct list_head *list = &nfs_automount_list;

	mark_mounts_for_expiry(list);
	if (!list_empty(list))
		schedule_delayed_work(&nfs_automount_task, nfs_mountpoint_expiry_timeout);
}

void nfs_release_automount_timer(void)
{
	if (list_empty(&nfs_automount_list))
		cancel_delayed_work(&nfs_automount_task);
}

/*
 * Clone a mountpoint of the appropriate type
 */
static struct vfsmount *nfs_do_clone_mount(struct nfs_server *server,
					   const char *devname,
					   struct nfs_clone_mount *mountdata)
{
	return vfs_kern_mount(&nfs_xdev_fs_type, 0, devname, mountdata);
}

/**
 * nfs_do_submount - set up mountpoint when crossing a filesystem boundary
 * @dentry - parent directory
 * @fh - filehandle for new root dentry
 * @fattr - attributes for new root inode
 * @authflavor - security flavor to use when performing the mount
 *
 */
struct vfsmount *nfs_do_submount(struct dentry *dentry, struct nfs_fh *fh,
				 struct nfs_fattr *fattr, rpc_authflavor_t authflavor)
{
	struct nfs_clone_mount mountdata = {
		.sb = dentry->d_sb,
		.dentry = dentry,
		.fh = fh,
		.fattr = fattr,
		.authflavor = authflavor,
	};
	struct vfsmount *mnt = ERR_PTR(-ENOMEM);
	char *page = (char *) __get_free_page(GFP_USER);
	char *devname;

	dprintk("--> nfs_do_submount()\n");

	dprintk("%s: submounting on %pd2\n", __func__,
			dentry);
	if (page == NULL)
		goto out;
	devname = nfs_devname(dentry, page, PAGE_SIZE);
	mnt = (struct vfsmount *)devname;
	if (IS_ERR(devname))
		goto free_page;
	mnt = nfs_do_clone_mount(NFS_SB(dentry->d_sb), devname, &mountdata);
free_page:
	free_page((unsigned long)page);
out:
	dprintk("%s: done\n", __func__);

	dprintk("<-- nfs_do_submount() = %p\n", mnt);
	return mnt;
}
EXPORT_SYMBOL_GPL(nfs_do_submount);

struct vfsmount *nfs_submount(struct nfs_server *server, struct dentry *dentry,
			      struct nfs_fh *fh, struct nfs_fattr *fattr)
{
	int err;
	struct dentry *parent = dget_parent(dentry);

	/* Look it up again to get its attributes */
	err = server->nfs_client->rpc_ops->lookup(parent->d_inode, &dentry->d_name, fh, fattr, NULL);
	dput(parent);
	if (err != 0)
		return ERR_PTR(err);

	return nfs_do_submount(dentry, fh, fattr, server->client->cl_auth->au_flavor);
}
EXPORT_SYMBOL_GPL(nfs_submount);
/************************************************************/
/* ../linux-3.17/fs/nfs/namespace.c */
/************************************************************/
/*
 * In-kernel MOUNT protocol client
 *
 * Copyright (C) 1997, Olaf Kirch <okir@monad.swb.de>
 */

// #include <linux/types.h>
#include <linux/socket.h>
// #include <linux/kernel.h>
// #include <linux/errno.h>
#include <linux/uio.h>
#include <linux/net.h>
#include <linux/in.h>
// #include <linux/sunrpc/clnt.h>
// #include <linux/sunrpc/sched.h>
// #include <linux/nfs_fs.h>
// #include "internal.h"

#ifdef NFS_DEBUG
# define NFSDBG_FACILITY	NFSDBG_MOUNT
#endif

/*
 * Defined by RFC 1094, section A.3; and RFC 1813, section 5.1.4
 */
#define MNTPATHLEN		(1024)

/*
 * XDR data type sizes
 */
#define encode_dirpath_sz	(1 + XDR_QUADLEN(MNTPATHLEN))
#define MNT_status_sz		(1)
#define MNT_fhs_status_sz	(1)
#define MNT_fhandle_sz		XDR_QUADLEN(NFS2_FHSIZE)
#define MNT_fhandle3_sz		(1 + XDR_QUADLEN(NFS3_FHSIZE))
#define MNT_authflav3_sz	(1 + NFS_MAX_SECFLAVORS)

/*
 * XDR argument and result sizes
 */
#define MNT_enc_dirpath_sz	encode_dirpath_sz
#define MNT_dec_mountres_sz	(MNT_status_sz + MNT_fhandle_sz)
#define MNT_dec_mountres3_sz	(MNT_status_sz + MNT_fhandle_sz + \
				 MNT_authflav3_sz)

/*
 * Defined by RFC 1094, section A.5
 */
enum {
	MOUNTPROC_NULL		= 0,
	MOUNTPROC_MNT		= 1,
	MOUNTPROC_DUMP		= 2,
	MOUNTPROC_UMNT		= 3,
	MOUNTPROC_UMNTALL	= 4,
	MOUNTPROC_EXPORT	= 5,
};

/*
 * Defined by RFC 1813, section 5.2
 */
enum {
	MOUNTPROC3_NULL		= 0,
	MOUNTPROC3_MNT		= 1,
	MOUNTPROC3_DUMP		= 2,
	MOUNTPROC3_UMNT		= 3,
	MOUNTPROC3_UMNTALL	= 4,
	MOUNTPROC3_EXPORT	= 5,
};

static const struct rpc_program mnt_program;

/*
 * Defined by OpenGroup XNFS Version 3W, chapter 8
 */
enum mountstat {
	MNT_OK			= 0,
	MNT_EPERM		= 1,
	MNT_ENOENT		= 2,
	MNT_EACCES		= 13,
	MNT_EINVAL		= 22,
};

static struct {
	u32 status;
	int errno;
} mnt_errtbl[] = {
	{ .status = MNT_OK,			.errno = 0,		},
	{ .status = MNT_EPERM,			.errno = -EPERM,	},
	{ .status = MNT_ENOENT,			.errno = -ENOENT,	},
	{ .status = MNT_EACCES,			.errno = -EACCES,	},
	{ .status = MNT_EINVAL,			.errno = -EINVAL,	},
};

/*
 * Defined by RFC 1813, section 5.1.5
 */
enum mountstat3 {
	MNT3_OK			= 0,		/* no error */
	MNT3ERR_PERM		= 1,		/* Not owner */
	MNT3ERR_NOENT		= 2,		/* No such file or directory */
	MNT3ERR_IO		= 5,		/* I/O error */
	MNT3ERR_ACCES		= 13,		/* Permission denied */
	MNT3ERR_NOTDIR		= 20,		/* Not a directory */
	MNT3ERR_INVAL		= 22,		/* Invalid argument */
	MNT3ERR_NAMETOOLONG	= 63,		/* Filename too long */
	MNT3ERR_NOTSUPP		= 10004,	/* Operation not supported */
	MNT3ERR_SERVERFAULT	= 10006,	/* A failure on the server */
};

static struct {
	u32 status;
	int errno;
} mnt3_errtbl[] = {
	{ .status = MNT3_OK,			.errno = 0,		},
	{ .status = MNT3ERR_PERM,		.errno = -EPERM,	},
	{ .status = MNT3ERR_NOENT,		.errno = -ENOENT,	},
	{ .status = MNT3ERR_IO,			.errno = -EIO,		},
	{ .status = MNT3ERR_ACCES,		.errno = -EACCES,	},
	{ .status = MNT3ERR_NOTDIR,		.errno = -ENOTDIR,	},
	{ .status = MNT3ERR_INVAL,		.errno = -EINVAL,	},
	{ .status = MNT3ERR_NAMETOOLONG,	.errno = -ENAMETOOLONG,	},
	{ .status = MNT3ERR_NOTSUPP,		.errno = -ENOTSUPP,	},
	{ .status = MNT3ERR_SERVERFAULT,	.errno = -EREMOTEIO,	},
};

struct mountres {
	int errno;
	struct nfs_fh *fh;
	unsigned int *auth_count;
	rpc_authflavor_t *auth_flavors;
};

struct mnt_fhstatus {
	u32 status;
	struct nfs_fh *fh;
};

/**
 * nfs_mount - Obtain an NFS file handle for the given host and path
 * @info: pointer to mount request arguments
 *
 * Uses default timeout parameters specified by underlying transport. On
 * successful return, the auth_flavs list and auth_flav_len will be populated
 * with the list from the server or a faked-up list if the server didn't
 * provide one.
 */
int nfs_mount(struct nfs_mount_request *info)
{
	struct mountres	result = {
		.fh		= info->fh,
		.auth_count	= info->auth_flav_len,
		.auth_flavors	= info->auth_flavs,
	};
	struct rpc_message msg	= {
		.rpc_argp	= info->dirpath,
		.rpc_resp	= &result,
	};
	struct rpc_create_args args = {
		.net		= info->net,
		.protocol	= info->protocol,
		.address	= info->sap,
		.addrsize	= info->salen,
		.servername	= info->hostname,
		.program	= &mnt_program,
		.version	= info->version,
		.authflavor	= RPC_AUTH_UNIX,
	};
	struct rpc_clnt		*mnt_clnt;
	int			status;

	dprintk("NFS: sending MNT request for %s:%s\n",
		(info->hostname ? info->hostname : "server"),
			info->dirpath);

	if (strlen(info->dirpath) > MNTPATHLEN)
		return -ENAMETOOLONG;

	if (info->noresvport)
		args.flags |= RPC_CLNT_CREATE_NONPRIVPORT;

	mnt_clnt = rpc_create(&args);
	if (IS_ERR(mnt_clnt))
		goto out_clnt_err;

	if (info->version == NFS_MNT3_VERSION)
		msg.rpc_proc = &mnt_clnt->cl_procinfo[MOUNTPROC3_MNT];
	else
		msg.rpc_proc = &mnt_clnt->cl_procinfo[MOUNTPROC_MNT];

	status = rpc_call_sync(mnt_clnt, &msg, RPC_TASK_SOFT|RPC_TASK_TIMEOUT);
	rpc_shutdown_client(mnt_clnt);

	if (status < 0)
		goto out_call_err;
	if (result.errno != 0)
		goto out_mnt_err;

	dprintk("NFS: MNT request succeeded\n");
	status = 0;

	/*
	 * If the server didn't provide a flavor list, allow the
	 * client to try any flavor.
	 */
	if (info->version != NFS_MNT3_VERSION || *info->auth_flav_len == 0) {
		dprintk("NFS: Faking up auth_flavs list\n");
		info->auth_flavs[0] = RPC_AUTH_NULL;
		*info->auth_flav_len = 1;
	}
out:
	return status;

out_clnt_err:
	status = PTR_ERR(mnt_clnt);
	dprintk("NFS: failed to create MNT RPC client, status=%d\n", status);
	goto out;

out_call_err:
	dprintk("NFS: MNT request failed, status=%d\n", status);
	goto out;

out_mnt_err:
	dprintk("NFS: MNT server returned result %d\n", result.errno);
	status = result.errno;
	goto out;
}

/**
 * nfs_umount - Notify a server that we have unmounted this export
 * @info: pointer to umount request arguments
 *
 * MOUNTPROC_UMNT is advisory, so we set a short timeout, and always
 * use UDP.
 */
void nfs_umount(const struct nfs_mount_request *info)
{
	static const struct rpc_timeout nfs_umnt_timeout = {
		.to_initval = 1 * HZ,
		.to_maxval = 3 * HZ,
		.to_retries = 2,
	};
	struct rpc_create_args args = {
		.net		= info->net,
		.protocol	= IPPROTO_UDP,
		.address	= info->sap,
		.addrsize	= info->salen,
		.timeout	= &nfs_umnt_timeout,
		.servername	= info->hostname,
		.program	= &mnt_program,
		.version	= info->version,
		.authflavor	= RPC_AUTH_UNIX,
		.flags		= RPC_CLNT_CREATE_NOPING,
	};
	struct rpc_message msg	= {
		.rpc_argp	= info->dirpath,
	};
	struct rpc_clnt *clnt;
	int status;

	if (strlen(info->dirpath) > MNTPATHLEN)
		return;

	if (info->noresvport)
		args.flags |= RPC_CLNT_CREATE_NONPRIVPORT;

	clnt = rpc_create(&args);
	if (IS_ERR(clnt))
		goto out_clnt_err;

	dprintk("NFS: sending UMNT request for %s:%s\n",
		(info->hostname ? info->hostname : "server"), info->dirpath);

	if (info->version == NFS_MNT3_VERSION)
		msg.rpc_proc = &clnt->cl_procinfo[MOUNTPROC3_UMNT];
	else
		msg.rpc_proc = &clnt->cl_procinfo[MOUNTPROC_UMNT];

	status = rpc_call_sync(clnt, &msg, 0);
	rpc_shutdown_client(clnt);

	if (unlikely(status < 0))
		goto out_call_err;

	return;

out_clnt_err:
	dprintk("NFS: failed to create UMNT RPC client, status=%ld\n",
			PTR_ERR(clnt));
	return;

out_call_err:
	dprintk("NFS: UMNT request failed, status=%d\n", status);
}

/*
 * XDR encode/decode functions for MOUNT
 */

static void encode_mntdirpath(struct xdr_stream *xdr, const char *pathname)
{
	const u32 pathname_len = strlen(pathname);
	__be32 *p;

	p = xdr_reserve_space(xdr, 4 + pathname_len);
	xdr_encode_opaque(p, pathname, pathname_len);
}

static void mnt_xdr_enc_dirpath(struct rpc_rqst *req, struct xdr_stream *xdr,
				const char *dirpath)
{
	encode_mntdirpath(xdr, dirpath);
}

/*
 * RFC 1094: "A non-zero status indicates some sort of error.  In this
 * case, the status is a UNIX error number."  This can be problematic
 * if the server and client use different errno values for the same
 * error.
 *
 * However, the OpenGroup XNFS spec provides a simple mapping that is
 * independent of local errno values on the server and the client.
 */
static int decode_status(struct xdr_stream *xdr, struct mountres *res)
{
	unsigned int i;
	u32 status;
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		return -EIO;
	status = be32_to_cpup(p);

	for (i = 0; i < ARRAY_SIZE(mnt_errtbl); i++) {
		if (mnt_errtbl[i].status == status) {
			res->errno = mnt_errtbl[i].errno;
			return 0;
		}
	}

	dprintk("NFS: unrecognized MNT status code: %u\n", status);
	res->errno = -EACCES;
	return 0;
}

static int decode_fhandle(struct xdr_stream *xdr, struct mountres *res)
{
	struct nfs_fh *fh = res->fh;
	__be32 *p;

	p = xdr_inline_decode(xdr, NFS2_FHSIZE);
	if (unlikely(p == NULL))
		return -EIO;

	fh->size = NFS2_FHSIZE;
	memcpy(fh->data, p, NFS2_FHSIZE);
	return 0;
}

static int mnt_xdr_dec_mountres(struct rpc_rqst *req,
				struct xdr_stream *xdr,
				struct mountres *res)
{
	int status;

	status = decode_status(xdr, res);
	if (unlikely(status != 0 || res->errno != 0))
		return status;
	return decode_fhandle(xdr, res);
}

static int decode_fhs_status(struct xdr_stream *xdr, struct mountres *res)
{
	unsigned int i;
	u32 status;
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		return -EIO;
	status = be32_to_cpup(p);

	for (i = 0; i < ARRAY_SIZE(mnt3_errtbl); i++) {
		if (mnt3_errtbl[i].status == status) {
			res->errno = mnt3_errtbl[i].errno;
			return 0;
		}
	}

	dprintk("NFS: unrecognized MNT3 status code: %u\n", status);
	res->errno = -EACCES;
	return 0;
}

static int decode_fhandle3(struct xdr_stream *xdr, struct mountres *res)
{
	struct nfs_fh *fh = res->fh;
	u32 size;
	__be32 *p;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		return -EIO;

	size = be32_to_cpup(p);
	if (size > NFS3_FHSIZE || size == 0)
		return -EIO;

	p = xdr_inline_decode(xdr, size);
	if (unlikely(p == NULL))
		return -EIO;

	fh->size = size;
	memcpy(fh->data, p, size);
	return 0;
}

static int decode_auth_flavors(struct xdr_stream *xdr, struct mountres *res)
{
	rpc_authflavor_t *flavors = res->auth_flavors;
	unsigned int *count = res->auth_count;
	u32 entries, i;
	__be32 *p;

	if (*count == 0)
		return 0;

	p = xdr_inline_decode(xdr, 4);
	if (unlikely(p == NULL))
		return -EIO;
	entries = be32_to_cpup(p);
	dprintk("NFS: received %u auth flavors\n", entries);
	if (entries > NFS_MAX_SECFLAVORS)
		entries = NFS_MAX_SECFLAVORS;

	p = xdr_inline_decode(xdr, 4 * entries);
	if (unlikely(p == NULL))
		return -EIO;

	if (entries > *count)
		entries = *count;

	for (i = 0; i < entries; i++) {
		flavors[i] = be32_to_cpup(p++);
		dprintk("NFS:   auth flavor[%u]: %d\n", i, flavors[i]);
	}
	*count = i;

	return 0;
}

static int mnt_xdr_dec_mountres3(struct rpc_rqst *req,
				 struct xdr_stream *xdr,
				 struct mountres *res)
{
	int status;

	status = decode_fhs_status(xdr, res);
	if (unlikely(status != 0 || res->errno != 0))
		return status;
	status = decode_fhandle3(xdr, res);
	if (unlikely(status != 0)) {
		res->errno = -EBADHANDLE;
		return 0;
	}
	return decode_auth_flavors(xdr, res);
}

static struct rpc_procinfo mnt_procedures[] = {
	[MOUNTPROC_MNT] = {
		.p_proc		= MOUNTPROC_MNT,
		.p_encode	= (kxdreproc_t)mnt_xdr_enc_dirpath,
		.p_decode	= (kxdrdproc_t)mnt_xdr_dec_mountres,
		.p_arglen	= MNT_enc_dirpath_sz,
		.p_replen	= MNT_dec_mountres_sz,
		.p_statidx	= MOUNTPROC_MNT,
		.p_name		= "MOUNT",
	},
	[MOUNTPROC_UMNT] = {
		.p_proc		= MOUNTPROC_UMNT,
		.p_encode	= (kxdreproc_t)mnt_xdr_enc_dirpath,
		.p_arglen	= MNT_enc_dirpath_sz,
		.p_statidx	= MOUNTPROC_UMNT,
		.p_name		= "UMOUNT",
	},
};

static struct rpc_procinfo mnt3_procedures[] = {
	[MOUNTPROC3_MNT] = {
		.p_proc		= MOUNTPROC3_MNT,
		.p_encode	= (kxdreproc_t)mnt_xdr_enc_dirpath,
		.p_decode	= (kxdrdproc_t)mnt_xdr_dec_mountres3,
		.p_arglen	= MNT_enc_dirpath_sz,
		.p_replen	= MNT_dec_mountres3_sz,
		.p_statidx	= MOUNTPROC3_MNT,
		.p_name		= "MOUNT",
	},
	[MOUNTPROC3_UMNT] = {
		.p_proc		= MOUNTPROC3_UMNT,
		.p_encode	= (kxdreproc_t)mnt_xdr_enc_dirpath,
		.p_arglen	= MNT_enc_dirpath_sz,
		.p_statidx	= MOUNTPROC3_UMNT,
		.p_name		= "UMOUNT",
	},
};


static const struct rpc_version mnt_version1 = {
	.number		= 1,
	.nrprocs	= ARRAY_SIZE(mnt_procedures),
	.procs		= mnt_procedures,
};

static const struct rpc_version mnt_version3 = {
	.number		= 3,
	.nrprocs	= ARRAY_SIZE(mnt3_procedures),
	.procs		= mnt3_procedures,
};

static const struct rpc_version *mnt_version[] = {
	NULL,
	&mnt_version1,
	NULL,
	&mnt_version3,
};

static struct rpc_stat mnt_stats;

static const struct rpc_program mnt_program = {
	.name		= "mount",
	.number		= NFS_MNT_PROGRAM,
	.nrvers		= ARRAY_SIZE(mnt_version),
	.version	= mnt_version,
	.stats		= &mnt_stats,
};
/************************************************************/
/* ../linux-3.17/fs/nfs/mount_clnt.c */
/************************************************************/
/*
 * Copyright (c) 2013 Trond Myklebust <Trond.Myklebust@netapp.com>
 */
// #include <linux/nfs_fs.h>
// #include <linux/namei.h>
// #include "internal.h"

#define CREATE_TRACE_POINTS
// #include "nfstrace.h"
/************************************************************/
/* ../linux-3.17/fs/nfs/nfstrace.c */
/************************************************************/
/*
 *  Copyright (C) 1995, 1996  Gero Kuhlmann <gero@gkminix.han.de>
 *
 *  Allow an NFS filesystem to be mounted as root. The way this works is:
 *     (1) Use the IP autoconfig mechanism to set local IP addresses and routes.
 *     (2) Construct the device string and the options string using DHCP
 *         option 17 and/or kernel command line options.
 *     (3) When mount_root() sets up the root file system, pass these strings
 *         to the NFS client's regular mount interface via sys_mount().
 *
 *
 *	Changes:
 *
 *	Alan Cox	:	Removed get_address name clash with FPU.
 *	Alan Cox	:	Reformatted a bit.
 *	Gero Kuhlmann	:	Code cleanup
 *	Michael Rausch  :	Fixed recognition of an incoming RARP answer.
 *	Martin Mares	: (2.0)	Auto-configuration via BOOTP supported.
 *	Martin Mares	:	Manual selection of interface & BOOTP/RARP.
 *	Martin Mares	:	Using network routes instead of host routes,
 *				allowing the default configuration to be used
 *				for normal operation of the host.
 *	Martin Mares	:	Randomized timer with exponential backoff
 *				installed to minimize network congestion.
 *	Martin Mares	:	Code cleanup.
 *	Martin Mares	: (2.1)	BOOTP and RARP made configuration options.
 *	Martin Mares	:	Server hostname generation fixed.
 *	Gerd Knorr	:	Fixed wired inode handling
 *	Martin Mares	: (2.2)	"0.0.0.0" addresses from command line ignored.
 *	Martin Mares	:	RARP replies not tested for server address.
 *	Gero Kuhlmann	: (2.3) Some bug fixes and code cleanup again (please
 *				send me your new patches _before_ bothering
 *				Linus so that I don' always have to cleanup
 *				_afterwards_ - thanks)
 *	Gero Kuhlmann	:	Last changes of Martin Mares undone.
 *	Gero Kuhlmann	: 	RARP replies are tested for specified server
 *				again. However, it's now possible to have
 *				different RARP and NFS servers.
 *	Gero Kuhlmann	:	"0.0.0.0" addresses from command line are
 *				now mapped to INADDR_NONE.
 *	Gero Kuhlmann	:	Fixed a bug which prevented BOOTP path name
 *				from being used (thanks to Leo Spiekman)
 *	Andy Walker	:	Allow to specify the NFS server in nfs_root
 *				without giving a path name
 *	Swen Thümmler	:	Allow to specify the NFS options in nfs_root
 *				without giving a path name. Fix BOOTP request
 *				for domainname (domainname is NIS domain, not
 *				DNS domain!). Skip dummy devices for BOOTP.
 *	Jacek Zapala	:	Fixed a bug which prevented server-ip address
 *				from nfsroot parameter from being used.
 *	Olaf Kirch	:	Adapted to new NFS code.
 *	Jakub Jelinek	:	Free used code segment.
 *	Marko Kohtala	:	Fixed some bugs.
 *	Martin Mares	:	Debug message cleanup
 *	Martin Mares	:	Changed to use the new generic IP layer autoconfig
 *				code. BOOTP and RARP moved there.
 *	Martin Mares	:	Default path now contains host name instead of
 *				host IP address (but host name defaults to IP
 *				address anyway).
 *	Martin Mares	:	Use root_server_addr appropriately during setup.
 *	Martin Mares	:	Rewrote parameter parsing, now hopefully giving
 *				correct overriding.
 *	Trond Myklebust :	Add in preliminary support for NFSv3 and TCP.
 *				Fix bug in root_nfs_addr(). nfs_data.namlen
 *				is NOT for the length of the hostname.
 *	Hua Qin		:	Support for mounting root file system via
 *				NFS over TCP.
 *	Fabian Frederick:	Option parser rebuilt (using parser lib)
 *	Chuck Lever	:	Use super.c's text-based mount option parsing
 *	Chuck Lever	:	Add "nfsrootdebug".
 */

// #include <linux/types.h>
// #include <linux/string.h>
// #include <linux/init.h>
// #include <linux/nfs.h>
// #include <linux/nfs_fs.h>
#include <linux/utsname.h>
#include <linux/root_dev.h>
#include <net/ipconfig.h>

// #include "internal.h"

#define NFSDBG_FACILITY NFSDBG_ROOT

/* Default path we try to mount. "%s" gets replaced by our IP address */
#define NFS_ROOT		"/tftpboot/%s"

/* Default NFSROOT mount options. */
#define NFS_DEF_OPTIONS		"vers=2,udp,rsize=4096,wsize=4096"

/* Parameters passed from the kernel command line */
static char nfs_root_parms[256] __initdata = "";

/* Text-based mount options passed to super.c */
static char nfs_root_options[256] __initdata = NFS_DEF_OPTIONS;

/* Address of NFS server */
static __be32 servaddr __initdata = htonl(INADDR_NONE);

/* Name of directory to mount */
static char nfs_export_path[NFS_MAXPATHLEN + 1] __initdata = "";

/* server:export path string passed to super.c */
static char nfs_root_device[NFS_MAXPATHLEN + 1] __initdata = "";

#ifdef NFS_DEBUG
/*
 * When the "nfsrootdebug" kernel command line option is specified,
 * enable debugging messages for NFSROOT.
 */
static int __init nfs_root_debug(char *__unused)
{
	nfs_debug |= NFSDBG_ROOT | NFSDBG_MOUNT;
	return 1;
}

__setup("nfsrootdebug", nfs_root_debug);
#endif

/*
 *  Parse NFS server and directory information passed on the kernel
 *  command line.
 *
 *  nfsroot=[<server-ip>:]<root-dir>[,<nfs-options>]
 *
 *  If there is a "%s" token in the <root-dir> string, it is replaced
 *  by the ASCII-representation of the client's IP address.
 */
static int __init nfs_root_setup(char *line)
{
	ROOT_DEV = Root_NFS;

	if (line[0] == '/' || line[0] == ',' || (line[0] >= '0' && line[0] <= '9')) {
		strlcpy(nfs_root_parms, line, sizeof(nfs_root_parms));
	} else {
		size_t n = strlen(line) + sizeof(NFS_ROOT) - 1;
		if (n >= sizeof(nfs_root_parms))
			line[sizeof(nfs_root_parms) - sizeof(NFS_ROOT) - 2] = '\0';
		sprintf(nfs_root_parms, NFS_ROOT, line);
	}

	/*
	 * Extract the IP address of the NFS server containing our
	 * root file system, if one was specified.
	 *
	 * Note: root_nfs_parse_addr() removes the server-ip from
	 *	 nfs_root_parms, if it exists.
	 */
	root_server_addr = root_nfs_parse_addr(nfs_root_parms);

	return 1;
}

__setup("nfsroot=", nfs_root_setup);

static int __init root_nfs_copy(char *dest, const char *src,
				     const size_t destlen)
{
	if (strlcpy(dest, src, destlen) > destlen)
		return -1;
	return 0;
}

static int __init root_nfs_cat(char *dest, const char *src,
			       const size_t destlen)
{
	size_t len = strlen(dest);

	if (len && dest[len - 1] != ',')
		if (strlcat(dest, ",", destlen) > destlen)
			return -1;

	if (strlcat(dest, src, destlen) > destlen)
		return -1;
	return 0;
}

/*
 * Parse out root export path and mount options from
 * passed-in string @incoming.
 *
 * Copy the export path into @exppath.
 */
static int __init root_nfs_parse_options(char *incoming, char *exppath,
					 const size_t exppathlen)
{
	char *p;

	/*
	 * Set the NFS remote path
	 */
	p = strsep(&incoming, ",");
	if (*p != '\0' && strcmp(p, "default") != 0)
		if (root_nfs_copy(exppath, p, exppathlen))
			return -1;

	/*
	 * @incoming now points to the rest of the string; if it
	 * contains something, append it to our root options buffer
	 */
	if (incoming != NULL && *incoming != '\0')
		if (root_nfs_cat(nfs_root_options, incoming,
						sizeof(nfs_root_options)))
			return -1;
	return 0;
}

/*
 *  Decode the export directory path name and NFS options from
 *  the kernel command line.  This has to be done late in order to
 *  use a dynamically acquired client IP address for the remote
 *  root directory path.
 *
 *  Returns zero if successful; otherwise -1 is returned.
 */
static int __init root_nfs_data(char *cmdline)
{
	char mand_options[sizeof("nolock,addr=") + INET_ADDRSTRLEN + 1];
	int len, retval = -1;
	char *tmp = NULL;
	const size_t tmplen = sizeof(nfs_export_path);

	tmp = kzalloc(tmplen, GFP_KERNEL);
	if (tmp == NULL)
		goto out_nomem;
	strcpy(tmp, NFS_ROOT);

	if (root_server_path[0] != '\0') {
		dprintk("Root-NFS: DHCPv4 option 17: %s\n",
			root_server_path);
		if (root_nfs_parse_options(root_server_path, tmp, tmplen))
			goto out_optionstoolong;
	}

	if (cmdline[0] != '\0') {
		dprintk("Root-NFS: nfsroot=%s\n", cmdline);
		if (root_nfs_parse_options(cmdline, tmp, tmplen))
			goto out_optionstoolong;
	}

	/*
	 * Append mandatory options for nfsroot so they override
	 * what has come before
	 */
	snprintf(mand_options, sizeof(mand_options), "nolock,addr=%pI4",
			&servaddr);
	if (root_nfs_cat(nfs_root_options, mand_options,
						sizeof(nfs_root_options)))
		goto out_optionstoolong;

	/*
	 * Set up nfs_root_device.  For NFS mounts, this looks like
	 *
	 *	server:/path
	 *
	 * At this point, utsname()->nodename contains our local
	 * IP address or hostname, set by ipconfig.  If "%s" exists
	 * in tmp, substitute the nodename, then shovel the whole
	 * mess into nfs_root_device.
	 */
	len = snprintf(nfs_export_path, sizeof(nfs_export_path),
				tmp, utsname()->nodename);
	if (len > (int)sizeof(nfs_export_path))
		goto out_devnametoolong;
	len = snprintf(nfs_root_device, sizeof(nfs_root_device),
				"%pI4:%s", &servaddr, nfs_export_path);
	if (len > (int)sizeof(nfs_root_device))
		goto out_devnametoolong;

	retval = 0;

out:
	kfree(tmp);
	return retval;
out_nomem:
	printk(KERN_ERR "Root-NFS: could not allocate memory\n");
	goto out;
out_optionstoolong:
	printk(KERN_ERR "Root-NFS: mount options string too long\n");
	goto out;
out_devnametoolong:
	printk(KERN_ERR "Root-NFS: root device name too long.\n");
	goto out;
}

/**
 * nfs_root_data - Return prepared 'data' for NFSROOT mount
 * @root_device: OUT: address of string containing NFSROOT device
 * @root_data: OUT: address of string containing NFSROOT mount options
 *
 * Returns zero and sets @root_device and @root_data if successful,
 * otherwise -1 is returned.
 */
int __init nfs_root_data(char **root_device, char **root_data)
{
	servaddr = root_server_addr;
	if (servaddr == htonl(INADDR_NONE)) {
		printk(KERN_ERR "Root-NFS: no NFS server address\n");
		return -1;
	}

	if (root_nfs_data(nfs_root_parms) < 0)
		return -1;

	*root_device = nfs_root_device;
	*root_data = nfs_root_options;
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/nfs/nfsroot.c */
/************************************************************/
/*
 * linux/fs/nfs/sysctl.c
 *
 * Sysctl interface to NFS parameters
 */
// #include <linux/types.h>
#include <linux/linkage.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/sysctl.h>
// #include <linux/module.h>
// #include <linux/nfs_fs.h>

static struct ctl_table_header *nfs_callback_sysctl_table;

static struct ctl_table nfs_cb_sysctls[] = {
	{
		.procname	= "nfs_mountpoint_timeout",
		.data		= &nfs_mountpoint_expiry_timeout,
		.maxlen		= sizeof(nfs_mountpoint_expiry_timeout),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_jiffies,
	},
	{
		.procname	= "nfs_congestion_kb",
		.data		= &nfs_congestion_kb,
		.maxlen		= sizeof(nfs_congestion_kb),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static struct ctl_table nfs_cb_sysctl_dir[] = {
	{
		.procname = "nfs",
		.mode = 0555,
		.child = nfs_cb_sysctls,
	},
	{ }
};

static struct ctl_table nfs_cb_sysctl_root[] = {
	{
		.procname = "fs",
		.mode = 0555,
		.child = nfs_cb_sysctl_dir,
	},
	{ }
};

int nfs_register_sysctl(void)
{
	nfs_callback_sysctl_table = register_sysctl_table(nfs_cb_sysctl_root);
	if (nfs_callback_sysctl_table == NULL)
		return -ENOMEM;
	return 0;
}

void nfs_unregister_sysctl(void)
{
	unregister_sysctl_table(nfs_callback_sysctl_table);
	nfs_callback_sysctl_table = NULL;
}
/************************************************************/
/* ../linux-3.17/fs/nfs/sysctl.c */
/************************************************************/
