/************************************************************/
/* ../linux-3.17/fs/fscache/cache.c */
/************************************************************/
/* FS-Cache cache handling
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define FSCACHE_DEBUG_LEVEL CACHE
#include <linux/module.h>
#include <linux/slab.h>
#include "internal.h"

LIST_HEAD(fscache_cache_list);
DECLARE_RWSEM(fscache_addremove_sem);
DECLARE_WAIT_QUEUE_HEAD(fscache_cache_cleared_wq);
EXPORT_SYMBOL(fscache_cache_cleared_wq);

static LIST_HEAD(fscache_cache_tag_list);

/*
 * look up a cache tag
 */
struct fscache_cache_tag *__fscache_lookup_cache_tag(const char *name)
{
	struct fscache_cache_tag *tag, *xtag;

	/* firstly check for the existence of the tag under read lock */
	down_read(&fscache_addremove_sem);

	list_for_each_entry(tag, &fscache_cache_tag_list, link) {
		if (strcmp(tag->name, name) == 0) {
			atomic_inc(&tag->usage);
			up_read(&fscache_addremove_sem);
			return tag;
		}
	}

	up_read(&fscache_addremove_sem);

	/* the tag does not exist - create a candidate */
	xtag = kzalloc(sizeof(*xtag) + strlen(name) + 1, GFP_KERNEL);
	if (!xtag)
		/* return a dummy tag if out of memory */
		return ERR_PTR(-ENOMEM);

	atomic_set(&xtag->usage, 1);
	strcpy(xtag->name, name);

	/* write lock, search again and add if still not present */
	down_write(&fscache_addremove_sem);

	list_for_each_entry(tag, &fscache_cache_tag_list, link) {
		if (strcmp(tag->name, name) == 0) {
			atomic_inc(&tag->usage);
			up_write(&fscache_addremove_sem);
			kfree(xtag);
			return tag;
		}
	}

	list_add_tail(&xtag->link, &fscache_cache_tag_list);
	up_write(&fscache_addremove_sem);
	return xtag;
}

/*
 * release a reference to a cache tag
 */
void __fscache_release_cache_tag(struct fscache_cache_tag *tag)
{
	if (tag != ERR_PTR(-ENOMEM)) {
		down_write(&fscache_addremove_sem);

		if (atomic_dec_and_test(&tag->usage))
			list_del_init(&tag->link);
		else
			tag = NULL;

		up_write(&fscache_addremove_sem);

		kfree(tag);
	}
}

/*
 * select a cache in which to store an object
 * - the cache addremove semaphore must be at least read-locked by the caller
 * - the object will never be an index
 */
struct fscache_cache *fscache_select_cache_for_object(
	struct fscache_cookie *cookie)
{
	struct fscache_cache_tag *tag;
	struct fscache_object *object;
	struct fscache_cache *cache;

	_enter("");

	if (list_empty(&fscache_cache_list)) {
		_leave(" = NULL [no cache]");
		return NULL;
	}

	/* we check the parent to determine the cache to use */
	spin_lock(&cookie->lock);

	/* the first in the parent's backing list should be the preferred
	 * cache */
	if (!hlist_empty(&cookie->backing_objects)) {
		object = hlist_entry(cookie->backing_objects.first,
				     struct fscache_object, cookie_link);

		cache = object->cache;
		if (fscache_object_is_dying(object) ||
		    test_bit(FSCACHE_IOERROR, &cache->flags))
			cache = NULL;

		spin_unlock(&cookie->lock);
		_leave(" = %p [parent]", cache);
		return cache;
	}

	/* the parent is unbacked */
	if (cookie->def->type != FSCACHE_COOKIE_TYPE_INDEX) {
		/* cookie not an index and is unbacked */
		spin_unlock(&cookie->lock);
		_leave(" = NULL [cookie ub,ni]");
		return NULL;
	}

	spin_unlock(&cookie->lock);

	if (!cookie->def->select_cache)
		goto no_preference;

	/* ask the netfs for its preference */
	tag = cookie->def->select_cache(cookie->parent->netfs_data,
					cookie->netfs_data);
	if (!tag)
		goto no_preference;

	if (tag == ERR_PTR(-ENOMEM)) {
		_leave(" = NULL [nomem tag]");
		return NULL;
	}

	if (!tag->cache) {
		_leave(" = NULL [unbacked tag]");
		return NULL;
	}

	if (test_bit(FSCACHE_IOERROR, &tag->cache->flags))
		return NULL;

	_leave(" = %p [specific]", tag->cache);
	return tag->cache;

no_preference:
	/* netfs has no preference - just select first cache */
	cache = list_entry(fscache_cache_list.next,
			   struct fscache_cache, link);
	_leave(" = %p [first]", cache);
	return cache;
}

/**
 * fscache_init_cache - Initialise a cache record
 * @cache: The cache record to be initialised
 * @ops: The cache operations to be installed in that record
 * @idfmt: Format string to define identifier
 * @...: sprintf-style arguments
 *
 * Initialise a record of a cache and fill in the name.
 *
 * See Documentation/filesystems/caching/backend-api.txt for a complete
 * description.
 */
void fscache_init_cache(struct fscache_cache *cache,
			const struct fscache_cache_ops *ops,
			const char *idfmt,
			...)
{
	va_list va;

	memset(cache, 0, sizeof(*cache));

	cache->ops = ops;

	va_start(va, idfmt);
	vsnprintf(cache->identifier, sizeof(cache->identifier), idfmt, va);
	va_end(va);

	INIT_WORK(&cache->op_gc, fscache_operation_gc);
	INIT_LIST_HEAD(&cache->link);
	INIT_LIST_HEAD(&cache->object_list);
	INIT_LIST_HEAD(&cache->op_gc_list);
	spin_lock_init(&cache->object_list_lock);
	spin_lock_init(&cache->op_gc_list_lock);
}
EXPORT_SYMBOL(fscache_init_cache);

/**
 * fscache_add_cache - Declare a cache as being open for business
 * @cache: The record describing the cache
 * @ifsdef: The record of the cache object describing the top-level index
 * @tagname: The tag describing this cache
 *
 * Add a cache to the system, making it available for netfs's to use.
 *
 * See Documentation/filesystems/caching/backend-api.txt for a complete
 * description.
 */
int fscache_add_cache(struct fscache_cache *cache,
		      struct fscache_object *ifsdef,
		      const char *tagname)
{
	struct fscache_cache_tag *tag;

	BUG_ON(!cache->ops);
	BUG_ON(!ifsdef);

	cache->flags = 0;
	ifsdef->event_mask =
		((1 << NR_FSCACHE_OBJECT_EVENTS) - 1) &
		~(1 << FSCACHE_OBJECT_EV_CLEARED);
	__set_bit(FSCACHE_OBJECT_IS_AVAILABLE, &ifsdef->flags);

	if (!tagname)
		tagname = cache->identifier;

	BUG_ON(!tagname[0]);

	_enter("{%s.%s},,%s", cache->ops->name, cache->identifier, tagname);

	/* we use the cache tag to uniquely identify caches */
	tag = __fscache_lookup_cache_tag(tagname);
	if (IS_ERR(tag))
		goto nomem;

	if (test_and_set_bit(FSCACHE_TAG_RESERVED, &tag->flags))
		goto tag_in_use;

	cache->kobj = kobject_create_and_add(tagname, fscache_root);
	if (!cache->kobj)
		goto error;

	ifsdef->cookie = &fscache_fsdef_index;
	ifsdef->cache = cache;
	cache->fsdef = ifsdef;

	down_write(&fscache_addremove_sem);

	tag->cache = cache;
	cache->tag = tag;

	/* add the cache to the list */
	list_add(&cache->link, &fscache_cache_list);

	/* add the cache's netfs definition index object to the cache's
	 * list */
	spin_lock(&cache->object_list_lock);
	list_add_tail(&ifsdef->cache_link, &cache->object_list);
	spin_unlock(&cache->object_list_lock);
	fscache_objlist_add(ifsdef);

	/* add the cache's netfs definition index object to the top level index
	 * cookie as a known backing object */
	spin_lock(&fscache_fsdef_index.lock);

	hlist_add_head(&ifsdef->cookie_link,
		       &fscache_fsdef_index.backing_objects);

	atomic_inc(&fscache_fsdef_index.usage);

	/* done */
	spin_unlock(&fscache_fsdef_index.lock);
	up_write(&fscache_addremove_sem);

	pr_notice("Cache \"%s\" added (type %s)\n",
		  cache->tag->name, cache->ops->name);
	kobject_uevent(cache->kobj, KOBJ_ADD);

	_leave(" = 0 [%s]", cache->identifier);
	return 0;

tag_in_use:
	pr_err("Cache tag '%s' already in use\n", tagname);
	__fscache_release_cache_tag(tag);
	_leave(" = -EXIST");
	return -EEXIST;

error:
	__fscache_release_cache_tag(tag);
	_leave(" = -EINVAL");
	return -EINVAL;

nomem:
	_leave(" = -ENOMEM");
	return -ENOMEM;
}
EXPORT_SYMBOL(fscache_add_cache);

/**
 * fscache_io_error - Note a cache I/O error
 * @cache: The record describing the cache
 *
 * Note that an I/O error occurred in a cache and that it should no longer be
 * used for anything.  This also reports the error into the kernel log.
 *
 * See Documentation/filesystems/caching/backend-api.txt for a complete
 * description.
 */
void fscache_io_error(struct fscache_cache *cache)
{
	if (!test_and_set_bit(FSCACHE_IOERROR, &cache->flags))
		pr_err("Cache '%s' stopped due to I/O error\n",
		       cache->ops->name);
}
EXPORT_SYMBOL(fscache_io_error);

/*
 * request withdrawal of all the objects in a cache
 * - all the objects being withdrawn are moved onto the supplied list
 */
static void fscache_withdraw_all_objects(struct fscache_cache *cache,
					 struct list_head *dying_objects)
{
	struct fscache_object *object;

	while (!list_empty(&cache->object_list)) {
		spin_lock(&cache->object_list_lock);

		if (!list_empty(&cache->object_list)) {
			object = list_entry(cache->object_list.next,
					    struct fscache_object, cache_link);
			list_move_tail(&object->cache_link, dying_objects);

			_debug("withdraw %p", object->cookie);

			/* This must be done under object_list_lock to prevent
			 * a race with fscache_drop_object().
			 */
			fscache_raise_event(object, FSCACHE_OBJECT_EV_KILL);
		}

		spin_unlock(&cache->object_list_lock);
		cond_resched();
	}
}

/**
 * fscache_withdraw_cache - Withdraw a cache from the active service
 * @cache: The record describing the cache
 *
 * Withdraw a cache from service, unbinding all its cache objects from the
 * netfs cookies they're currently representing.
 *
 * See Documentation/filesystems/caching/backend-api.txt for a complete
 * description.
 */
void fscache_withdraw_cache(struct fscache_cache *cache)
{
	LIST_HEAD(dying_objects);

	_enter("");

	pr_notice("Withdrawing cache \"%s\"\n",
		  cache->tag->name);

	/* make the cache unavailable for cookie acquisition */
	if (test_and_set_bit(FSCACHE_CACHE_WITHDRAWN, &cache->flags))
		BUG();

	down_write(&fscache_addremove_sem);
	list_del_init(&cache->link);
	cache->tag->cache = NULL;
	up_write(&fscache_addremove_sem);

	/* make sure all pages pinned by operations on behalf of the netfs are
	 * written to disk */
	fscache_stat(&fscache_n_cop_sync_cache);
	cache->ops->sync_cache(cache);
	fscache_stat_d(&fscache_n_cop_sync_cache);

	/* dissociate all the netfs pages backed by this cache from the block
	 * mappings in the cache */
	fscache_stat(&fscache_n_cop_dissociate_pages);
	cache->ops->dissociate_pages(cache);
	fscache_stat_d(&fscache_n_cop_dissociate_pages);

	/* we now have to destroy all the active objects pertaining to this
	 * cache - which we do by passing them off to thread pool to be
	 * disposed of */
	_debug("destroy");

	fscache_withdraw_all_objects(cache, &dying_objects);

	/* wait for all extant objects to finish their outstanding operations
	 * and go away */
	_debug("wait for finish");
	wait_event(fscache_cache_cleared_wq,
		   atomic_read(&cache->object_count) == 0);
	_debug("wait for clearance");
	wait_event(fscache_cache_cleared_wq,
		   list_empty(&cache->object_list));
	_debug("cleared");
	ASSERT(list_empty(&dying_objects));

	kobject_put(cache->kobj);

	clear_bit(FSCACHE_TAG_RESERVED, &cache->tag->flags);
	fscache_release_cache_tag(cache->tag);
	cache->tag = NULL;

	_leave("");
}
EXPORT_SYMBOL(fscache_withdraw_cache);
/************************************************************/
/* ../linux-3.17/fs/fscache/cookie.c */
/************************************************************/
/* netfs cookie management
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * See Documentation/filesystems/caching/netfs-api.txt for more information on
 * the netfs API.
 */

#define FSCACHE_DEBUG_LEVEL COOKIE
// #include <linux/module.h>
// #include <linux/slab.h>
// #include "internal.h"

struct kmem_cache *fscache_cookie_jar;

static atomic_t fscache_object_debug_id = ATOMIC_INIT(0);

static int fscache_acquire_non_index_cookie(struct fscache_cookie *cookie);
static int fscache_alloc_object(struct fscache_cache *cache,
				struct fscache_cookie *cookie);
static int fscache_attach_object(struct fscache_cookie *cookie,
				 struct fscache_object *object);

/*
 * initialise an cookie jar slab element prior to any use
 */
void fscache_cookie_init_once(void *_cookie)
{
	struct fscache_cookie *cookie = _cookie;

	memset(cookie, 0, sizeof(*cookie));
	spin_lock_init(&cookie->lock);
	spin_lock_init(&cookie->stores_lock);
	INIT_HLIST_HEAD(&cookie->backing_objects);
}

/*
 * request a cookie to represent an object (index, datafile, xattr, etc)
 * - parent specifies the parent object
 *   - the top level index cookie for each netfs is stored in the fscache_netfs
 *     struct upon registration
 * - def points to the definition
 * - the netfs_data will be passed to the functions pointed to in *def
 * - all attached caches will be searched to see if they contain this object
 * - index objects aren't stored on disk until there's a dependent file that
 *   needs storing
 * - other objects are stored in a selected cache immediately, and all the
 *   indices forming the path to it are instantiated if necessary
 * - we never let on to the netfs about errors
 *   - we may set a negative cookie pointer, but that's okay
 */
struct fscache_cookie *__fscache_acquire_cookie(
	struct fscache_cookie *parent,
	const struct fscache_cookie_def *def,
	void *netfs_data,
	bool enable)
{
	struct fscache_cookie *cookie;

	BUG_ON(!def);

	_enter("{%s},{%s},%p,%u",
	       parent ? (char *) parent->def->name : "<no-parent>",
	       def->name, netfs_data, enable);

	fscache_stat(&fscache_n_acquires);

	/* if there's no parent cookie, then we don't create one here either */
	if (!parent) {
		fscache_stat(&fscache_n_acquires_null);
		_leave(" [no parent]");
		return NULL;
	}

	/* validate the definition */
	BUG_ON(!def->get_key);
	BUG_ON(!def->name[0]);

	BUG_ON(def->type == FSCACHE_COOKIE_TYPE_INDEX &&
	       parent->def->type != FSCACHE_COOKIE_TYPE_INDEX);

	/* allocate and initialise a cookie */
	cookie = kmem_cache_alloc(fscache_cookie_jar, GFP_KERNEL);
	if (!cookie) {
		fscache_stat(&fscache_n_acquires_oom);
		_leave(" [ENOMEM]");
		return NULL;
	}

	atomic_set(&cookie->usage, 1);
	atomic_set(&cookie->n_children, 0);

	/* We keep the active count elevated until relinquishment to prevent an
	 * attempt to wake up every time the object operations queue quiesces.
	 */
	atomic_set(&cookie->n_active, 1);

	atomic_inc(&parent->usage);
	atomic_inc(&parent->n_children);

	cookie->def		= def;
	cookie->parent		= parent;
	cookie->netfs_data	= netfs_data;
	cookie->flags		= (1 << FSCACHE_COOKIE_NO_DATA_YET);

	/* radix tree insertion won't use the preallocation pool unless it's
	 * told it may not wait */
	INIT_RADIX_TREE(&cookie->stores, GFP_NOFS & ~__GFP_WAIT);

	switch (cookie->def->type) {
	case FSCACHE_COOKIE_TYPE_INDEX:
		fscache_stat(&fscache_n_cookie_index);
		break;
	case FSCACHE_COOKIE_TYPE_DATAFILE:
		fscache_stat(&fscache_n_cookie_data);
		break;
	default:
		fscache_stat(&fscache_n_cookie_special);
		break;
	}

	if (enable) {
		/* if the object is an index then we need do nothing more here
		 * - we create indices on disk when we need them as an index
		 * may exist in multiple caches */
		if (cookie->def->type != FSCACHE_COOKIE_TYPE_INDEX) {
			if (fscache_acquire_non_index_cookie(cookie) == 0) {
				set_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
			} else {
				atomic_dec(&parent->n_children);
				__fscache_cookie_put(cookie);
				fscache_stat(&fscache_n_acquires_nobufs);
				_leave(" = NULL");
				return NULL;
			}
		} else {
			set_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
		}
	}

	fscache_stat(&fscache_n_acquires_ok);
	_leave(" = %p", cookie);
	return cookie;
}
EXPORT_SYMBOL(__fscache_acquire_cookie);

/*
 * Enable a cookie to permit it to accept new operations.
 */
void __fscache_enable_cookie(struct fscache_cookie *cookie,
			     bool (*can_enable)(void *data),
			     void *data)
{
	_enter("%p", cookie);

	wait_on_bit_lock(&cookie->flags, FSCACHE_COOKIE_ENABLEMENT_LOCK,
			 TASK_UNINTERRUPTIBLE);

	if (test_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags))
		goto out_unlock;

	if (can_enable && !can_enable(data)) {
		/* The netfs decided it didn't want to enable after all */
	} else if (cookie->def->type != FSCACHE_COOKIE_TYPE_INDEX) {
		/* Wait for outstanding disablement to complete */
		__fscache_wait_on_invalidate(cookie);

		if (fscache_acquire_non_index_cookie(cookie) == 0)
			set_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
	} else {
		set_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags);
	}

out_unlock:
	clear_bit_unlock(FSCACHE_COOKIE_ENABLEMENT_LOCK, &cookie->flags);
	wake_up_bit(&cookie->flags, FSCACHE_COOKIE_ENABLEMENT_LOCK);
}
EXPORT_SYMBOL(__fscache_enable_cookie);

/*
 * acquire a non-index cookie
 * - this must make sure the index chain is instantiated and instantiate the
 *   object representation too
 */
static int fscache_acquire_non_index_cookie(struct fscache_cookie *cookie)
{
	struct fscache_object *object;
	struct fscache_cache *cache;
	uint64_t i_size;
	int ret;

	_enter("");

	set_bit(FSCACHE_COOKIE_UNAVAILABLE, &cookie->flags);

	/* now we need to see whether the backing objects for this cookie yet
	 * exist, if not there'll be nothing to search */
	down_read(&fscache_addremove_sem);

	if (list_empty(&fscache_cache_list)) {
		up_read(&fscache_addremove_sem);
		_leave(" = 0 [no caches]");
		return 0;
	}

	/* select a cache in which to store the object */
	cache = fscache_select_cache_for_object(cookie->parent);
	if (!cache) {
		up_read(&fscache_addremove_sem);
		fscache_stat(&fscache_n_acquires_no_cache);
		_leave(" = -ENOMEDIUM [no cache]");
		return -ENOMEDIUM;
	}

	_debug("cache %s", cache->tag->name);

	set_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags);

	/* ask the cache to allocate objects for this cookie and its parent
	 * chain */
	ret = fscache_alloc_object(cache, cookie);
	if (ret < 0) {
		up_read(&fscache_addremove_sem);
		_leave(" = %d", ret);
		return ret;
	}

	/* pass on how big the object we're caching is supposed to be */
	cookie->def->get_attr(cookie->netfs_data, &i_size);

	spin_lock(&cookie->lock);
	if (hlist_empty(&cookie->backing_objects)) {
		spin_unlock(&cookie->lock);
		goto unavailable;
	}

	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	fscache_set_store_limit(object, i_size);

	/* initiate the process of looking up all the objects in the chain
	 * (done by fscache_initialise_object()) */
	fscache_raise_event(object, FSCACHE_OBJECT_EV_NEW_CHILD);

	spin_unlock(&cookie->lock);

	/* we may be required to wait for lookup to complete at this point */
	if (!fscache_defer_lookup) {
		_debug("non-deferred lookup %p", &cookie->flags);
		wait_on_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP,
			    TASK_UNINTERRUPTIBLE);
		_debug("complete");
		if (test_bit(FSCACHE_COOKIE_UNAVAILABLE, &cookie->flags))
			goto unavailable;
	}

	up_read(&fscache_addremove_sem);
	_leave(" = 0 [deferred]");
	return 0;

unavailable:
	up_read(&fscache_addremove_sem);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}

/*
 * recursively allocate cache object records for a cookie/cache combination
 * - caller must be holding the addremove sem
 */
static int fscache_alloc_object(struct fscache_cache *cache,
				struct fscache_cookie *cookie)
{
	struct fscache_object *object;
	int ret;

	_enter("%p,%p{%s}", cache, cookie, cookie->def->name);

	spin_lock(&cookie->lock);
	hlist_for_each_entry(object, &cookie->backing_objects,
			     cookie_link) {
		if (object->cache == cache)
			goto object_already_extant;
	}
	spin_unlock(&cookie->lock);

	/* ask the cache to allocate an object (we may end up with duplicate
	 * objects at this stage, but we sort that out later) */
	fscache_stat(&fscache_n_cop_alloc_object);
	object = cache->ops->alloc_object(cache, cookie);
	fscache_stat_d(&fscache_n_cop_alloc_object);
	if (IS_ERR(object)) {
		fscache_stat(&fscache_n_object_no_alloc);
		ret = PTR_ERR(object);
		goto error;
	}

	fscache_stat(&fscache_n_object_alloc);

	object->debug_id = atomic_inc_return(&fscache_object_debug_id);

	_debug("ALLOC OBJ%x: %s {%lx}",
	       object->debug_id, cookie->def->name, object->events);

	ret = fscache_alloc_object(cache, cookie->parent);
	if (ret < 0)
		goto error_put;

	/* only attach if we managed to allocate all we needed, otherwise
	 * discard the object we just allocated and instead use the one
	 * attached to the cookie */
	if (fscache_attach_object(cookie, object) < 0) {
		fscache_stat(&fscache_n_cop_put_object);
		cache->ops->put_object(object);
		fscache_stat_d(&fscache_n_cop_put_object);
	}

	_leave(" = 0");
	return 0;

object_already_extant:
	ret = -ENOBUFS;
	if (fscache_object_is_dead(object)) {
		spin_unlock(&cookie->lock);
		goto error;
	}
	spin_unlock(&cookie->lock);
	_leave(" = 0 [found]");
	return 0;

error_put:
	fscache_stat(&fscache_n_cop_put_object);
	cache->ops->put_object(object);
	fscache_stat_d(&fscache_n_cop_put_object);
error:
	_leave(" = %d", ret);
	return ret;
}

/*
 * attach a cache object to a cookie
 */
static int fscache_attach_object(struct fscache_cookie *cookie,
				 struct fscache_object *object)
{
	struct fscache_object *p;
	struct fscache_cache *cache = object->cache;
	int ret;

	_enter("{%s},{OBJ%x}", cookie->def->name, object->debug_id);

	spin_lock(&cookie->lock);

	/* there may be multiple initial creations of this object, but we only
	 * want one */
	ret = -EEXIST;
	hlist_for_each_entry(p, &cookie->backing_objects, cookie_link) {
		if (p->cache == object->cache) {
			if (fscache_object_is_dying(p))
				ret = -ENOBUFS;
			goto cant_attach_object;
		}
	}

	/* pin the parent object */
	spin_lock_nested(&cookie->parent->lock, 1);
	hlist_for_each_entry(p, &cookie->parent->backing_objects,
			     cookie_link) {
		if (p->cache == object->cache) {
			if (fscache_object_is_dying(p)) {
				ret = -ENOBUFS;
				spin_unlock(&cookie->parent->lock);
				goto cant_attach_object;
			}
			object->parent = p;
			spin_lock(&p->lock);
			p->n_children++;
			spin_unlock(&p->lock);
			break;
		}
	}
	spin_unlock(&cookie->parent->lock);

	/* attach to the cache's object list */
	if (list_empty(&object->cache_link)) {
		spin_lock(&cache->object_list_lock);
		list_add(&object->cache_link, &cache->object_list);
		spin_unlock(&cache->object_list_lock);
	}

	/* attach to the cookie */
	object->cookie = cookie;
	atomic_inc(&cookie->usage);
	hlist_add_head(&object->cookie_link, &cookie->backing_objects);

	fscache_objlist_add(object);
	ret = 0;

cant_attach_object:
	spin_unlock(&cookie->lock);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Invalidate an object.  Callable with spinlocks held.
 */
void __fscache_invalidate(struct fscache_cookie *cookie)
{
	struct fscache_object *object;

	_enter("{%s}", cookie->def->name);

	fscache_stat(&fscache_n_invalidates);

	/* Only permit invalidation of data files.  Invalidating an index will
	 * require the caller to release all its attachments to the tree rooted
	 * there, and if it's doing that, it may as well just retire the
	 * cookie.
	 */
	ASSERTCMP(cookie->def->type, ==, FSCACHE_COOKIE_TYPE_DATAFILE);

	/* We will be updating the cookie too. */
	BUG_ON(!cookie->def->get_aux);

	/* If there's an object, we tell the object state machine to handle the
	 * invalidation on our behalf, otherwise there's nothing to do.
	 */
	if (!hlist_empty(&cookie->backing_objects)) {
		spin_lock(&cookie->lock);

		if (fscache_cookie_enabled(cookie) &&
		    !hlist_empty(&cookie->backing_objects) &&
		    !test_and_set_bit(FSCACHE_COOKIE_INVALIDATING,
				      &cookie->flags)) {
			object = hlist_entry(cookie->backing_objects.first,
					     struct fscache_object,
					     cookie_link);
			if (fscache_object_is_live(object))
				fscache_raise_event(
					object, FSCACHE_OBJECT_EV_INVALIDATE);
		}

		spin_unlock(&cookie->lock);
	}

	_leave("");
}
EXPORT_SYMBOL(__fscache_invalidate);

/*
 * Wait for object invalidation to complete.
 */
void __fscache_wait_on_invalidate(struct fscache_cookie *cookie)
{
	_enter("%p", cookie);

	wait_on_bit(&cookie->flags, FSCACHE_COOKIE_INVALIDATING,
		    TASK_UNINTERRUPTIBLE);

	_leave("");
}
EXPORT_SYMBOL(__fscache_wait_on_invalidate);

/*
 * update the index entries backing a cookie
 */
void __fscache_update_cookie(struct fscache_cookie *cookie)
{
	struct fscache_object *object;

	fscache_stat(&fscache_n_updates);

	if (!cookie) {
		fscache_stat(&fscache_n_updates_null);
		_leave(" [no cookie]");
		return;
	}

	_enter("{%s}", cookie->def->name);

	BUG_ON(!cookie->def->get_aux);

	spin_lock(&cookie->lock);

	if (fscache_cookie_enabled(cookie)) {
		/* update the index entry on disk in each cache backing this
		 * cookie.
		 */
		hlist_for_each_entry(object,
				     &cookie->backing_objects, cookie_link) {
			fscache_raise_event(object, FSCACHE_OBJECT_EV_UPDATE);
		}
	}

	spin_unlock(&cookie->lock);
	_leave("");
}
EXPORT_SYMBOL(__fscache_update_cookie);

/*
 * Disable a cookie to stop it from accepting new requests from the netfs.
 */
void __fscache_disable_cookie(struct fscache_cookie *cookie, bool invalidate)
{
	struct fscache_object *object;
	bool awaken = false;

	_enter("%p,%u", cookie, invalidate);

	ASSERTCMP(atomic_read(&cookie->n_active), >, 0);

	if (atomic_read(&cookie->n_children) != 0) {
		pr_err("Cookie '%s' still has children\n",
		       cookie->def->name);
		BUG();
	}

	wait_on_bit_lock(&cookie->flags, FSCACHE_COOKIE_ENABLEMENT_LOCK,
			 TASK_UNINTERRUPTIBLE);
	if (!test_and_clear_bit(FSCACHE_COOKIE_ENABLED, &cookie->flags))
		goto out_unlock_enable;

	/* If the cookie is being invalidated, wait for that to complete first
	 * so that we can reuse the flag.
	 */
	__fscache_wait_on_invalidate(cookie);

	/* Dispose of the backing objects */
	set_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags);

	spin_lock(&cookie->lock);
	if (!hlist_empty(&cookie->backing_objects)) {
		hlist_for_each_entry(object, &cookie->backing_objects, cookie_link) {
			if (invalidate)
				set_bit(FSCACHE_OBJECT_RETIRED, &object->flags);
			fscache_raise_event(object, FSCACHE_OBJECT_EV_KILL);
		}
	} else {
		if (test_and_clear_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags))
			awaken = true;
	}
	spin_unlock(&cookie->lock);
	if (awaken)
		wake_up_bit(&cookie->flags, FSCACHE_COOKIE_INVALIDATING);

	/* Wait for cessation of activity requiring access to the netfs (when
	 * n_active reaches 0).  This makes sure outstanding reads and writes
	 * have completed.
	 */
	if (!atomic_dec_and_test(&cookie->n_active))
		wait_on_atomic_t(&cookie->n_active, fscache_wait_atomic_t,
				 TASK_UNINTERRUPTIBLE);

	/* Reset the cookie state if it wasn't relinquished */
	if (!test_bit(FSCACHE_COOKIE_RELINQUISHED, &cookie->flags)) {
		atomic_inc(&cookie->n_active);
		set_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);
	}

out_unlock_enable:
	clear_bit_unlock(FSCACHE_COOKIE_ENABLEMENT_LOCK, &cookie->flags);
	wake_up_bit(&cookie->flags, FSCACHE_COOKIE_ENABLEMENT_LOCK);
	_leave("");
}
EXPORT_SYMBOL(__fscache_disable_cookie);

/*
 * release a cookie back to the cache
 * - the object will be marked as recyclable on disk if retire is true
 * - all dependents of this cookie must have already been unregistered
 *   (indices/files/pages)
 */
void __fscache_relinquish_cookie(struct fscache_cookie *cookie, bool retire)
{
	fscache_stat(&fscache_n_relinquishes);
	if (retire)
		fscache_stat(&fscache_n_relinquishes_retire);

	if (!cookie) {
		fscache_stat(&fscache_n_relinquishes_null);
		_leave(" [no cookie]");
		return;
	}

	_enter("%p{%s,%p,%d},%d",
	       cookie, cookie->def->name, cookie->netfs_data,
	       atomic_read(&cookie->n_active), retire);

	/* No further netfs-accessing operations on this cookie permitted */
	set_bit(FSCACHE_COOKIE_RELINQUISHED, &cookie->flags);

	__fscache_disable_cookie(cookie, retire);

	/* Clear pointers back to the netfs */
	cookie->netfs_data	= NULL;
	cookie->def		= NULL;
	BUG_ON(cookie->stores.rnode);

	if (cookie->parent) {
		ASSERTCMP(atomic_read(&cookie->parent->usage), >, 0);
		ASSERTCMP(atomic_read(&cookie->parent->n_children), >, 0);
		atomic_dec(&cookie->parent->n_children);
	}

	/* Dispose of the netfs's link to the cookie */
	ASSERTCMP(atomic_read(&cookie->usage), >, 0);
	fscache_cookie_put(cookie);

	_leave("");
}
EXPORT_SYMBOL(__fscache_relinquish_cookie);

/*
 * destroy a cookie
 */
void __fscache_cookie_put(struct fscache_cookie *cookie)
{
	struct fscache_cookie *parent;

	_enter("%p", cookie);

	for (;;) {
		_debug("FREE COOKIE %p", cookie);
		parent = cookie->parent;
		BUG_ON(!hlist_empty(&cookie->backing_objects));
		kmem_cache_free(fscache_cookie_jar, cookie);

		if (!parent)
			break;

		cookie = parent;
		BUG_ON(atomic_read(&cookie->usage) <= 0);
		if (!atomic_dec_and_test(&cookie->usage))
			break;
	}

	_leave("");
}

/*
 * check the consistency between the netfs inode and the backing cache
 *
 * NOTE: it only serves no-index type
 */
int __fscache_check_consistency(struct fscache_cookie *cookie)
{
	struct fscache_operation *op;
	struct fscache_object *object;
	bool wake_cookie = false;
	int ret;

	_enter("%p,", cookie);

	ASSERTCMP(cookie->def->type, ==, FSCACHE_COOKIE_TYPE_DATAFILE);

	if (fscache_wait_for_deferred_lookup(cookie) < 0)
		return -ERESTARTSYS;

	if (hlist_empty(&cookie->backing_objects))
		return 0;

	op = kzalloc(sizeof(*op), GFP_NOIO | __GFP_NOMEMALLOC | __GFP_NORETRY);
	if (!op)
		return -ENOMEM;

	fscache_operation_init(op, NULL, NULL);
	op->flags = FSCACHE_OP_MYTHREAD |
		(1 << FSCACHE_OP_WAITING) |
		(1 << FSCACHE_OP_UNUSE_COOKIE);

	spin_lock(&cookie->lock);

	if (!fscache_cookie_enabled(cookie) ||
	    hlist_empty(&cookie->backing_objects))
		goto inconsistent;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);
	if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
		goto inconsistent;

	op->debug_id = atomic_inc_return(&fscache_op_debug_id);

	__fscache_use_cookie(cookie);
	if (fscache_submit_op(object, op) < 0)
		goto submit_failed;

	/* the work queue now carries its own ref on the object */
	spin_unlock(&cookie->lock);

	ret = fscache_wait_for_operation_activation(object, op,
						    NULL, NULL, NULL);
	if (ret == 0) {
		/* ask the cache to honour the operation */
		ret = object->cache->ops->check_consistency(op);
		fscache_op_complete(op, false);
	} else if (ret == -ENOBUFS) {
		ret = 0;
	}

	fscache_put_operation(op);
	_leave(" = %d", ret);
	return ret;

submit_failed:
	wake_cookie = __fscache_unuse_cookie(cookie);
inconsistent:
	spin_unlock(&cookie->lock);
	if (wake_cookie)
		__fscache_wake_unused_cookie(cookie);
	kfree(op);
	_leave(" = -ESTALE");
	return -ESTALE;
}
EXPORT_SYMBOL(__fscache_check_consistency);
/************************************************************/
/* ../linux-3.17/fs/fscache/fsdef.c */
/************************************************************/
/* Filesystem index definition
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define FSCACHE_DEBUG_LEVEL CACHE
// #include <linux/module.h>
// #include "internal.h"

static uint16_t fscache_fsdef_netfs_get_key(const void *cookie_netfs_data,
					    void *buffer, uint16_t bufmax);

static uint16_t fscache_fsdef_netfs_get_aux(const void *cookie_netfs_data,
					    void *buffer, uint16_t bufmax);

static
enum fscache_checkaux fscache_fsdef_netfs_check_aux(void *cookie_netfs_data,
						    const void *data,
						    uint16_t datalen);

/*
 * The root index is owned by FS-Cache itself.
 *
 * When a netfs requests caching facilities, FS-Cache will, if one doesn't
 * already exist, create an entry in the root index with the key being the name
 * of the netfs ("AFS" for example), and the auxiliary data holding the index
 * structure version supplied by the netfs:
 *
 *				     FSDEF
 *				       |
 *				 +-----------+
 *				 |           |
 *				NFS         AFS
 *			       [v=1]       [v=1]
 *
 * If an entry with the appropriate name does already exist, the version is
 * compared.  If the version is different, the entire subtree from that entry
 * will be discarded and a new entry created.
 *
 * The new entry will be an index, and a cookie referring to it will be passed
 * to the netfs.  This is then the root handle by which the netfs accesses the
 * cache.  It can create whatever objects it likes in that index, including
 * further indices.
 */
static struct fscache_cookie_def fscache_fsdef_index_def = {
	.name		= ".FS-Cache",
	.type		= FSCACHE_COOKIE_TYPE_INDEX,
};

struct fscache_cookie fscache_fsdef_index = {
	.usage		= ATOMIC_INIT(1),
	.n_active	= ATOMIC_INIT(1),
	.lock		= __SPIN_LOCK_UNLOCKED(fscache_fsdef_index.lock),
	.backing_objects = HLIST_HEAD_INIT,
	.def		= &fscache_fsdef_index_def,
	.flags		= 1 << FSCACHE_COOKIE_ENABLED,
};
EXPORT_SYMBOL(fscache_fsdef_index);

/*
 * Definition of an entry in the root index.  Each entry is an index, keyed to
 * a specific netfs and only applicable to a particular version of the index
 * structure used by that netfs.
 */
struct fscache_cookie_def fscache_fsdef_netfs_def = {
	.name		= "FSDEF.netfs",
	.type		= FSCACHE_COOKIE_TYPE_INDEX,
	.get_key	= fscache_fsdef_netfs_get_key,
	.get_aux	= fscache_fsdef_netfs_get_aux,
	.check_aux	= fscache_fsdef_netfs_check_aux,
};

/*
 * get the key data for an FSDEF index record - this is the name of the netfs
 * for which this entry is created
 */
static uint16_t fscache_fsdef_netfs_get_key(const void *cookie_netfs_data,
					    void *buffer, uint16_t bufmax)
{
	const struct fscache_netfs *netfs = cookie_netfs_data;
	unsigned klen;

	_enter("{%s.%u},", netfs->name, netfs->version);

	klen = strlen(netfs->name);
	if (klen > bufmax)
		return 0;

	memcpy(buffer, netfs->name, klen);
	return klen;
}

/*
 * get the auxiliary data for an FSDEF index record - this is the index
 * structure version number of the netfs for which this version is created
 */
static uint16_t fscache_fsdef_netfs_get_aux(const void *cookie_netfs_data,
					    void *buffer, uint16_t bufmax)
{
	const struct fscache_netfs *netfs = cookie_netfs_data;
	unsigned dlen;

	_enter("{%s.%u},", netfs->name, netfs->version);

	dlen = sizeof(uint32_t);
	if (dlen > bufmax)
		return 0;

	memcpy(buffer, &netfs->version, dlen);
	return dlen;
}

/*
 * check that the index structure version number stored in the auxiliary data
 * matches the one the netfs gave us
 */
static enum fscache_checkaux fscache_fsdef_netfs_check_aux(
	void *cookie_netfs_data,
	const void *data,
	uint16_t datalen)
{
	struct fscache_netfs *netfs = cookie_netfs_data;
	uint32_t version;

	_enter("{%s},,%hu", netfs->name, datalen);

	if (datalen != sizeof(version)) {
		_leave(" = OBSOLETE [dl=%d v=%zu]", datalen, sizeof(version));
		return FSCACHE_CHECKAUX_OBSOLETE;
	}

	memcpy(&version, data, sizeof(version));
	if (version != netfs->version) {
		_leave(" = OBSOLETE [ver=%x net=%x]", version, netfs->version);
		return FSCACHE_CHECKAUX_OBSOLETE;
	}

	_leave(" = OKAY");
	return FSCACHE_CHECKAUX_OKAY;
}
/************************************************************/
/* ../linux-3.17/fs/fscache/main.c */
/************************************************************/
/* General filesystem local caching manager
 *
 * Copyright (C) 2004-2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define FSCACHE_DEBUG_LEVEL CACHE
// #include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/completion.h>
// #include <linux/slab.h>
#include <linux/seq_file.h>
// #include "internal.h"

MODULE_DESCRIPTION("FS Cache Manager");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

unsigned fscache_defer_lookup = 1;
module_param_named(defer_lookup, fscache_defer_lookup, uint,
		   S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(fscache_defer_lookup,
		 "Defer cookie lookup to background thread");

unsigned fscache_defer_create = 1;
module_param_named(defer_create, fscache_defer_create, uint,
		   S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(fscache_defer_create,
		 "Defer cookie creation to background thread");

unsigned fscache_debug;
module_param_named(debug, fscache_debug, uint,
		   S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(fscache_debug,
		 "FS-Cache debugging mask");

struct kobject *fscache_root;
struct workqueue_struct *fscache_object_wq;
struct workqueue_struct *fscache_op_wq;

DEFINE_PER_CPU(wait_queue_head_t, fscache_object_cong_wait);

/* these values serve as lower bounds, will be adjusted in fscache_init() */
static unsigned fscache_object_max_active = 4;
static unsigned fscache_op_max_active = 2;

#ifdef CONFIG_SYSCTL
static struct ctl_table_header *fscache_sysctl_header;

static int fscache_max_active_sysctl(struct ctl_table *table, int write,
				     void __user *buffer,
				     size_t *lenp, loff_t *ppos)
{
	struct workqueue_struct **wqp = table->extra1;
	unsigned int *datap = table->data;
	int ret;

	ret = proc_dointvec(table, write, buffer, lenp, ppos);
	if (ret == 0)
		workqueue_set_max_active(*wqp, *datap);
	return ret;
}

static struct ctl_table fscache_sysctls[] = {
	{
		.procname	= "object_max_active",
		.data		= &fscache_object_max_active,
		.maxlen		= sizeof(unsigned),
		.mode		= 0644,
		.proc_handler	= fscache_max_active_sysctl,
		.extra1		= &fscache_object_wq,
	},
	{
		.procname	= "operation_max_active",
		.data		= &fscache_op_max_active,
		.maxlen		= sizeof(unsigned),
		.mode		= 0644,
		.proc_handler	= fscache_max_active_sysctl,
		.extra1		= &fscache_op_wq,
	},
	{}
};

static struct ctl_table fscache_sysctls_root[] = {
	{
		.procname	= "fscache",
		.mode		= 0555,
		.child		= fscache_sysctls,
	},
	{}
};
#endif

/*
 * initialise the fs caching module
 */
static int __init fscache_init(void)
{
	unsigned int nr_cpus = num_possible_cpus();
	unsigned int cpu;
	int ret;

	fscache_object_max_active =
		clamp_val(nr_cpus,
			  fscache_object_max_active, WQ_UNBOUND_MAX_ACTIVE);

	ret = -ENOMEM;
	fscache_object_wq = alloc_workqueue("fscache_object", WQ_UNBOUND,
					    fscache_object_max_active);
	if (!fscache_object_wq)
		goto error_object_wq;

	fscache_op_max_active =
		clamp_val(fscache_object_max_active / 2,
			  fscache_op_max_active, WQ_UNBOUND_MAX_ACTIVE);

	ret = -ENOMEM;
	fscache_op_wq = alloc_workqueue("fscache_operation", WQ_UNBOUND,
					fscache_op_max_active);
	if (!fscache_op_wq)
		goto error_op_wq;

	for_each_possible_cpu(cpu)
		init_waitqueue_head(&per_cpu(fscache_object_cong_wait, cpu));

	ret = fscache_proc_init();
	if (ret < 0)
		goto error_proc;

#ifdef CONFIG_SYSCTL
	ret = -ENOMEM;
	fscache_sysctl_header = register_sysctl_table(fscache_sysctls_root);
	if (!fscache_sysctl_header)
		goto error_sysctl;
#endif

	fscache_cookie_jar = kmem_cache_create("fscache_cookie_jar",
					       sizeof(struct fscache_cookie),
					       0,
					       0,
					       fscache_cookie_init_once);
	if (!fscache_cookie_jar) {
		pr_notice("Failed to allocate a cookie jar\n");
		ret = -ENOMEM;
		goto error_cookie_jar;
	}

	fscache_root = kobject_create_and_add("fscache", kernel_kobj);
	if (!fscache_root)
		goto error_kobj;

	pr_notice("Loaded\n");
	return 0;

error_kobj:
	kmem_cache_destroy(fscache_cookie_jar);
error_cookie_jar:
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(fscache_sysctl_header);
error_sysctl:
#endif
	fscache_proc_cleanup();
error_proc:
	destroy_workqueue(fscache_op_wq);
error_op_wq:
	destroy_workqueue(fscache_object_wq);
error_object_wq:
	return ret;
}

fs_initcall(fscache_init);

/*
 * clean up on module removal
 */
static void __exit fscache_exit(void)
{
	_enter("");

	kobject_put(fscache_root);
	kmem_cache_destroy(fscache_cookie_jar);
#ifdef CONFIG_SYSCTL
	unregister_sysctl_table(fscache_sysctl_header);
#endif
	fscache_proc_cleanup();
	destroy_workqueue(fscache_op_wq);
	destroy_workqueue(fscache_object_wq);
	pr_notice("Unloaded\n");
}

module_exit(fscache_exit);

/*
 * wait_on_atomic_t() sleep function for uninterruptible waiting
 */
int fscache_wait_atomic_t(atomic_t *p)
{
	schedule();
	return 0;
}
/************************************************************/
/* ../linux-3.17/fs/fscache/netfs.c */
/************************************************************/
/* FS-Cache netfs (client) registration
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define FSCACHE_DEBUG_LEVEL COOKIE
// #include <linux/module.h>
// #include <linux/slab.h>
// #include "internal.h"

static LIST_HEAD_netfs_c(fscache_netfs_list);

/*
 * register a network filesystem for caching
 */
int __fscache_register_netfs(struct fscache_netfs *netfs)
{
	struct fscache_netfs *ptr;
	int ret;

	_enter("{%s}", netfs->name);

	INIT_LIST_HEAD(&netfs->link);

	/* allocate a cookie for the primary index */
	netfs->primary_index =
		kmem_cache_zalloc(fscache_cookie_jar, GFP_KERNEL);

	if (!netfs->primary_index) {
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	/* initialise the primary index cookie */
	atomic_set(&netfs->primary_index->usage, 1);
	atomic_set(&netfs->primary_index->n_children, 0);
	atomic_set(&netfs->primary_index->n_active, 1);

	netfs->primary_index->def		= &fscache_fsdef_netfs_def;
	netfs->primary_index->parent		= &fscache_fsdef_index;
	netfs->primary_index->netfs_data	= netfs;
	netfs->primary_index->flags		= 1 << FSCACHE_COOKIE_ENABLED;

	atomic_inc(&netfs->primary_index->parent->usage);
	atomic_inc(&netfs->primary_index->parent->n_children);

	spin_lock_init(&netfs->primary_index->lock);
	INIT_HLIST_HEAD(&netfs->primary_index->backing_objects);

	/* check the netfs type is not already present */
	down_write(&fscache_addremove_sem);

	ret = -EEXIST;
	list_for_each_entry(ptr, &fscache_netfs_list, link) {
		if (strcmp(ptr->name, netfs->name) == 0)
			goto already_registered;
	}

	list_add(&netfs->link, &fscache_netfs_list);
	ret = 0;

	pr_notice("Netfs '%s' registered for caching\n", netfs->name);

already_registered:
	up_write(&fscache_addremove_sem);

	if (ret < 0) {
		netfs->primary_index->parent = NULL;
		__fscache_cookie_put(netfs->primary_index);
		netfs->primary_index = NULL;
	}

	_leave(" = %d", ret);
	return ret;
}
EXPORT_SYMBOL(__fscache_register_netfs);

/*
 * unregister a network filesystem from the cache
 * - all cookies must have been released first
 */
void __fscache_unregister_netfs(struct fscache_netfs *netfs)
{
	_enter("{%s.%u}", netfs->name, netfs->version);

	down_write(&fscache_addremove_sem);

	list_del(&netfs->link);
	fscache_relinquish_cookie(netfs->primary_index, 0);

	up_write(&fscache_addremove_sem);

	pr_notice("Netfs '%s' unregistered from caching\n",
		  netfs->name);

	_leave("");
}
EXPORT_SYMBOL(__fscache_unregister_netfs);
/************************************************************/
/* ../linux-3.17/fs/fscache/object.c */
/************************************************************/
/* FS-Cache object state machine handler
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * See Documentation/filesystems/caching/object.txt for a description of the
 * object state machine and the in-kernel representations.
 */

#define FSCACHE_DEBUG_LEVEL COOKIE
// #include <linux/module.h>
// #include <linux/slab.h>
#include <linux/prefetch.h>
// #include "internal.h"

static const struct fscache_state *fscache_abort_initialisation(struct fscache_object *, int);
static const struct fscache_state *fscache_kill_dependents(struct fscache_object *, int);
static const struct fscache_state *fscache_drop_object(struct fscache_object *, int);
static const struct fscache_state *fscache_initialise_object(struct fscache_object *, int);
static const struct fscache_state *fscache_invalidate_object(struct fscache_object *, int);
static const struct fscache_state *fscache_jumpstart_dependents(struct fscache_object *, int);
static const struct fscache_state *fscache_kill_object(struct fscache_object *, int);
static const struct fscache_state *fscache_lookup_failure(struct fscache_object *, int);
static const struct fscache_state *fscache_look_up_object(struct fscache_object *, int);
static const struct fscache_state *fscache_object_available(struct fscache_object *, int);
static const struct fscache_state *fscache_parent_ready(struct fscache_object *, int);
static const struct fscache_state *fscache_update_object(struct fscache_object *, int);

#define __STATE_NAME(n) fscache_osm_##n
#define STATE(n) (&__STATE_NAME(n))

/*
 * Define a work state.  Work states are execution states.  No event processing
 * is performed by them.  The function attached to a work state returns a
 * pointer indicating the next state to which the state machine should
 * transition.  Returning NO_TRANSIT repeats the current state, but goes back
 * to the scheduler first.
 */
#define WORK_STATE(n, sn, f) \
	const struct fscache_state __STATE_NAME(n) = {			\
		.name = #n,						\
		.short_name = sn,					\
		.work = f						\
	}

/*
 * Returns from work states.
 */
#define transit_to(state) ({ prefetch(&STATE(state)->work); STATE(state); })

#define NO_TRANSIT ((struct fscache_state *)NULL)

/*
 * Define a wait state.  Wait states are event processing states.  No execution
 * is performed by them.  Wait states are just tables of "if event X occurs,
 * clear it and transition to state Y".  The dispatcher returns to the
 * scheduler if none of the events in which the wait state has an interest are
 * currently pending.
 */
#define WAIT_STATE(n, sn, ...) \
	const struct fscache_state __STATE_NAME(n) = {			\
		.name = #n,						\
		.short_name = sn,					\
		.work = NULL,						\
		.transitions = { __VA_ARGS__, { 0, NULL } }		\
	}

#define TRANSIT_TO(state, emask) \
	{ .events = (emask), .transit_to = STATE(state) }

/*
 * The object state machine.
 */
static WORK_STATE(INIT_OBJECT,		"INIT", fscache_initialise_object);
static WORK_STATE(PARENT_READY,		"PRDY", fscache_parent_ready);
static WORK_STATE(ABORT_INIT,		"ABRT", fscache_abort_initialisation);
static WORK_STATE(LOOK_UP_OBJECT,	"LOOK", fscache_look_up_object);
static WORK_STATE(CREATE_OBJECT,	"CRTO", fscache_look_up_object);
static WORK_STATE(OBJECT_AVAILABLE,	"AVBL", fscache_object_available);
static WORK_STATE(JUMPSTART_DEPS,	"JUMP", fscache_jumpstart_dependents);

static WORK_STATE(INVALIDATE_OBJECT,	"INVL", fscache_invalidate_object);
static WORK_STATE(UPDATE_OBJECT,	"UPDT", fscache_update_object);

static WORK_STATE(LOOKUP_FAILURE,	"LCFL", fscache_lookup_failure);
static WORK_STATE(KILL_OBJECT,		"KILL", fscache_kill_object);
static WORK_STATE(KILL_DEPENDENTS,	"KDEP", fscache_kill_dependents);
static WORK_STATE(DROP_OBJECT,		"DROP", fscache_drop_object);
static WORK_STATE(OBJECT_DEAD,		"DEAD", (void*)2UL);

static WAIT_STATE(WAIT_FOR_INIT,	"?INI",
		  TRANSIT_TO(INIT_OBJECT,	1 << FSCACHE_OBJECT_EV_NEW_CHILD));

static WAIT_STATE(WAIT_FOR_PARENT,	"?PRN",
		  TRANSIT_TO(PARENT_READY,	1 << FSCACHE_OBJECT_EV_PARENT_READY));

static WAIT_STATE(WAIT_FOR_CMD,		"?CMD",
		  TRANSIT_TO(INVALIDATE_OBJECT,	1 << FSCACHE_OBJECT_EV_INVALIDATE),
		  TRANSIT_TO(UPDATE_OBJECT,	1 << FSCACHE_OBJECT_EV_UPDATE),
		  TRANSIT_TO(JUMPSTART_DEPS,	1 << FSCACHE_OBJECT_EV_NEW_CHILD));

static WAIT_STATE(WAIT_FOR_CLEARANCE,	"?CLR",
		  TRANSIT_TO(KILL_OBJECT,	1 << FSCACHE_OBJECT_EV_CLEARED));

/*
 * Out-of-band event transition tables.  These are for handling unexpected
 * events, such as an I/O error.  If an OOB event occurs, the state machine
 * clears and disables the event and forces a transition to the nominated work
 * state (acurrently executing work states will complete first).
 *
 * In such a situation, object->state remembers the state the machine should
 * have been in/gone to and returning NO_TRANSIT returns to that.
 */
static const struct fscache_transition fscache_osm_init_oob[] = {
	   TRANSIT_TO(ABORT_INIT,
		      (1 << FSCACHE_OBJECT_EV_ERROR) |
		      (1 << FSCACHE_OBJECT_EV_KILL)),
	   { 0, NULL }
};

static const struct fscache_transition fscache_osm_lookup_oob[] = {
	   TRANSIT_TO(LOOKUP_FAILURE,
		      (1 << FSCACHE_OBJECT_EV_ERROR) |
		      (1 << FSCACHE_OBJECT_EV_KILL)),
	   { 0, NULL }
};

static const struct fscache_transition fscache_osm_run_oob[] = {
	   TRANSIT_TO(KILL_OBJECT,
		      (1 << FSCACHE_OBJECT_EV_ERROR) |
		      (1 << FSCACHE_OBJECT_EV_KILL)),
	   { 0, NULL }
};

static int  fscache_get_object(struct fscache_object *);
static void fscache_put_object(struct fscache_object *);
static bool fscache_enqueue_dependents(struct fscache_object *, int);
static void fscache_dequeue_object(struct fscache_object *);

/*
 * we need to notify the parent when an op completes that we had outstanding
 * upon it
 */
static inline void fscache_done_parent_op(struct fscache_object *object)
{
	struct fscache_object *parent = object->parent;

	_enter("OBJ%x {OBJ%x,%x}",
	       object->debug_id, parent->debug_id, parent->n_ops);

	spin_lock_nested(&parent->lock, 1);
	parent->n_obj_ops--;
	parent->n_ops--;
	if (parent->n_ops == 0)
		fscache_raise_event(parent, FSCACHE_OBJECT_EV_CLEARED);
	spin_unlock(&parent->lock);
}

/*
 * Object state machine dispatcher.
 */
static void fscache_object_sm_dispatcher(struct fscache_object *object)
{
	const struct fscache_transition *t;
	const struct fscache_state *state, *new_state;
	unsigned long events, event_mask;
	int event = -1;

	ASSERT(object != NULL);

	_enter("{OBJ%x,%s,%lx}",
	       object->debug_id, object->state->name, object->events);

	event_mask = object->event_mask;
restart:
	object->event_mask = 0; /* Mask normal event handling */
	state = object->state;
restart_masked:
	events = object->events;

	/* Handle any out-of-band events (typically an error) */
	if (events & object->oob_event_mask) {
		_debug("{OBJ%x} oob %lx",
		       object->debug_id, events & object->oob_event_mask);
		for (t = object->oob_table; t->events; t++) {
			if (events & t->events) {
				state = t->transit_to;
				ASSERT(state->work != NULL);
				event = fls(events & t->events) - 1;
				__clear_bit(event, &object->oob_event_mask);
				clear_bit(event, &object->events);
				goto execute_work_state;
			}
		}
	}

	/* Wait states are just transition tables */
	if (!state->work) {
		if (events & event_mask) {
			for (t = state->transitions; t->events; t++) {
				if (events & t->events) {
					new_state = t->transit_to;
					event = fls(events & t->events) - 1;
					clear_bit(event, &object->events);
					_debug("{OBJ%x} ev %d: %s -> %s",
					       object->debug_id, event,
					       state->name, new_state->name);
					object->state = state = new_state;
					goto execute_work_state;
				}
			}

			/* The event mask didn't include all the tabled bits */
			BUG();
		}
		/* Randomly woke up */
		goto unmask_events;
	}

execute_work_state:
	_debug("{OBJ%x} exec %s", object->debug_id, state->name);

	new_state = state->work(object, event);
	event = -1;
	if (new_state == NO_TRANSIT) {
		_debug("{OBJ%x} %s notrans", object->debug_id, state->name);
		fscache_enqueue_object(object);
		event_mask = object->oob_event_mask;
		goto unmask_events;
	}

	_debug("{OBJ%x} %s -> %s",
	       object->debug_id, state->name, new_state->name);
	object->state = state = new_state;

	if (state->work) {
		if (unlikely(state->work == ((void *)2UL))) {
			_leave(" [dead]");
			return;
		}
		goto restart_masked;
	}

	/* Transited to wait state */
	event_mask = object->oob_event_mask;
	for (t = state->transitions; t->events; t++)
		event_mask |= t->events;

unmask_events:
	object->event_mask = event_mask;
	smp_mb();
	events = object->events;
	if (events & event_mask)
		goto restart;
	_leave(" [msk %lx]", event_mask);
}

/*
 * execute an object
 */
static void fscache_object_work_func(struct work_struct *work)
{
	struct fscache_object *object =
		container_of(work, struct fscache_object, work);
	unsigned long start;

	_enter("{OBJ%x}", object->debug_id);

	start = jiffies;
	fscache_object_sm_dispatcher(object);
	fscache_hist(fscache_objs_histogram, start);
	fscache_put_object(object);
}

/**
 * fscache_object_init - Initialise a cache object description
 * @object: Object description
 * @cookie: Cookie object will be attached to
 * @cache: Cache in which backing object will be found
 *
 * Initialise a cache object description to its basic values.
 *
 * See Documentation/filesystems/caching/backend-api.txt for a complete
 * description.
 */
void fscache_object_init(struct fscache_object *object,
			 struct fscache_cookie *cookie,
			 struct fscache_cache *cache)
{
	const struct fscache_transition *t;

	atomic_inc(&cache->object_count);

	object->state = STATE(WAIT_FOR_INIT);
	object->oob_table = fscache_osm_init_oob;
	object->flags = 1 << FSCACHE_OBJECT_IS_LIVE;
	spin_lock_init(&object->lock);
	INIT_LIST_HEAD(&object->cache_link);
	INIT_HLIST_NODE(&object->cookie_link);
	INIT_WORK(&object->work, fscache_object_work_func);
	INIT_LIST_HEAD(&object->dependents);
	INIT_LIST_HEAD(&object->dep_link);
	INIT_LIST_HEAD(&object->pending_ops);
	object->n_children = 0;
	object->n_ops = object->n_in_progress = object->n_exclusive = 0;
	object->events = 0;
	object->store_limit = 0;
	object->store_limit_l = 0;
	object->cache = cache;
	object->cookie = cookie;
	object->parent = NULL;
#ifdef CONFIG_FSCACHE_OBJECT_LIST
	RB_CLEAR_NODE(&object->objlist_link);
#endif

	object->oob_event_mask = 0;
	for (t = object->oob_table; t->events; t++)
		object->oob_event_mask |= t->events;
	object->event_mask = object->oob_event_mask;
	for (t = object->state->transitions; t->events; t++)
		object->event_mask |= t->events;
}
EXPORT_SYMBOL(fscache_object_init);

/*
 * Abort object initialisation before we start it.
 */
static const struct fscache_state *fscache_abort_initialisation(struct fscache_object *object,
								int event)
{
	_enter("{OBJ%x},%d", object->debug_id, event);

	object->oob_event_mask = 0;
	fscache_dequeue_object(object);
	return transit_to(KILL_OBJECT);
}

/*
 * initialise an object
 * - check the specified object's parent to see if we can make use of it
 *   immediately to do a creation
 * - we may need to start the process of creating a parent and we need to wait
 *   for the parent's lookup and creation to complete if it's not there yet
 */
static const struct fscache_state *fscache_initialise_object(struct fscache_object *object,
							     int event)
{
	struct fscache_object *parent;
	bool success;

	_enter("{OBJ%x},%d", object->debug_id, event);

	ASSERT(list_empty(&object->dep_link));

	parent = object->parent;
	if (!parent) {
		_leave(" [no parent]");
		return transit_to(DROP_OBJECT);
	}

	_debug("parent: %s of:%lx", parent->state->name, parent->flags);

	if (fscache_object_is_dying(parent)) {
		_leave(" [bad parent]");
		return transit_to(DROP_OBJECT);
	}

	if (fscache_object_is_available(parent)) {
		_leave(" [ready]");
		return transit_to(PARENT_READY);
	}

	_debug("wait");

	spin_lock(&parent->lock);
	fscache_stat(&fscache_n_cop_grab_object);
	success = false;
	if (fscache_object_is_live(parent) &&
	    object->cache->ops->grab_object(object)) {
		list_add(&object->dep_link, &parent->dependents);
		success = true;
	}
	fscache_stat_d(&fscache_n_cop_grab_object);
	spin_unlock(&parent->lock);
	if (!success) {
		_leave(" [grab failed]");
		return transit_to(DROP_OBJECT);
	}

	/* fscache_acquire_non_index_cookie() uses this
	 * to wake the chain up */
	fscache_raise_event(parent, FSCACHE_OBJECT_EV_NEW_CHILD);
	_leave(" [wait]");
	return transit_to(WAIT_FOR_PARENT);
}

/*
 * Once the parent object is ready, we should kick off our lookup op.
 */
static const struct fscache_state *fscache_parent_ready(struct fscache_object *object,
							int event)
{
	struct fscache_object *parent = object->parent;

	_enter("{OBJ%x},%d", object->debug_id, event);

	ASSERT(parent != NULL);

	spin_lock(&parent->lock);
	parent->n_ops++;
	parent->n_obj_ops++;
	object->lookup_jif = jiffies;
	spin_unlock(&parent->lock);

	_leave("");
	return transit_to(LOOK_UP_OBJECT);
}

/*
 * look an object up in the cache from which it was allocated
 * - we hold an "access lock" on the parent object, so the parent object cannot
 *   be withdrawn by either party till we've finished
 */
static const struct fscache_state *fscache_look_up_object(struct fscache_object *object,
							  int event)
{
	struct fscache_cookie *cookie = object->cookie;
	struct fscache_object *parent = object->parent;
	int ret;

	_enter("{OBJ%x},%d", object->debug_id, event);

	object->oob_table = fscache_osm_lookup_oob;

	ASSERT(parent != NULL);
	ASSERTCMP(parent->n_ops, >, 0);
	ASSERTCMP(parent->n_obj_ops, >, 0);

	/* make sure the parent is still available */
	ASSERT(fscache_object_is_available(parent));

	if (fscache_object_is_dying(parent) ||
	    test_bit(FSCACHE_IOERROR, &object->cache->flags) ||
	    !fscache_use_cookie(object)) {
		_leave(" [unavailable]");
		return transit_to(LOOKUP_FAILURE);
	}

	_debug("LOOKUP \"%s\" in \"%s\"",
	       cookie->def->name, object->cache->tag->name);

	fscache_stat(&fscache_n_object_lookups);
	fscache_stat(&fscache_n_cop_lookup_object);
	ret = object->cache->ops->lookup_object(object);
	fscache_stat_d(&fscache_n_cop_lookup_object);

	fscache_unuse_cookie(object);

	if (ret == -ETIMEDOUT) {
		/* probably stuck behind another object, so move this one to
		 * the back of the queue */
		fscache_stat(&fscache_n_object_lookups_timed_out);
		_leave(" [timeout]");
		return NO_TRANSIT;
	}

	if (ret < 0) {
		_leave(" [error]");
		return transit_to(LOOKUP_FAILURE);
	}

	_leave(" [ok]");
	return transit_to(OBJECT_AVAILABLE);
}

/**
 * fscache_object_lookup_negative - Note negative cookie lookup
 * @object: Object pointing to cookie to mark
 *
 * Note negative lookup, permitting those waiting to read data from an already
 * existing backing object to continue as there's no data for them to read.
 */
void fscache_object_lookup_negative(struct fscache_object *object)
{
	struct fscache_cookie *cookie = object->cookie;

	_enter("{OBJ%x,%s}", object->debug_id, object->state->name);

	if (!test_and_set_bit(FSCACHE_OBJECT_IS_LOOKED_UP, &object->flags)) {
		fscache_stat(&fscache_n_object_lookups_negative);

		/* Allow write requests to begin stacking up and read requests to begin
		 * returning ENODATA.
		 */
		set_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);
		clear_bit(FSCACHE_COOKIE_UNAVAILABLE, &cookie->flags);

		_debug("wake up lookup %p", &cookie->flags);
		clear_bit_unlock(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags);
		wake_up_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP);
	}
	_leave("");
}
EXPORT_SYMBOL(fscache_object_lookup_negative);

/**
 * fscache_obtained_object - Note successful object lookup or creation
 * @object: Object pointing to cookie to mark
 *
 * Note successful lookup and/or creation, permitting those waiting to write
 * data to a backing object to continue.
 *
 * Note that after calling this, an object's cookie may be relinquished by the
 * netfs, and so must be accessed with object lock held.
 */
void fscache_obtained_object(struct fscache_object *object)
{
	struct fscache_cookie *cookie = object->cookie;

	_enter("{OBJ%x,%s}", object->debug_id, object->state->name);

	/* if we were still looking up, then we must have a positive lookup
	 * result, in which case there may be data available */
	if (!test_and_set_bit(FSCACHE_OBJECT_IS_LOOKED_UP, &object->flags)) {
		fscache_stat(&fscache_n_object_lookups_positive);

		/* We do (presumably) have data */
		clear_bit_unlock(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);
		clear_bit(FSCACHE_COOKIE_UNAVAILABLE, &cookie->flags);

		/* Allow write requests to begin stacking up and read requests
		 * to begin shovelling data.
		 */
		clear_bit_unlock(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags);
		wake_up_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP);
	} else {
		fscache_stat(&fscache_n_object_created);
	}

	set_bit(FSCACHE_OBJECT_IS_AVAILABLE, &object->flags);
	_leave("");
}
EXPORT_SYMBOL(fscache_obtained_object);

/*
 * handle an object that has just become available
 */
static const struct fscache_state *fscache_object_available(struct fscache_object *object,
							    int event)
{
	_enter("{OBJ%x},%d", object->debug_id, event);

	object->oob_table = fscache_osm_run_oob;

	spin_lock(&object->lock);

	fscache_done_parent_op(object);
	if (object->n_in_progress == 0) {
		if (object->n_ops > 0) {
			ASSERTCMP(object->n_ops, >=, object->n_obj_ops);
			fscache_start_operations(object);
		} else {
			ASSERT(list_empty(&object->pending_ops));
		}
	}
	spin_unlock(&object->lock);

	fscache_stat(&fscache_n_cop_lookup_complete);
	object->cache->ops->lookup_complete(object);
	fscache_stat_d(&fscache_n_cop_lookup_complete);

	fscache_hist(fscache_obj_instantiate_histogram, object->lookup_jif);
	fscache_stat(&fscache_n_object_avail);

	_leave("");
	return transit_to(JUMPSTART_DEPS);
}

/*
 * Wake up this object's dependent objects now that we've become available.
 */
static const struct fscache_state *fscache_jumpstart_dependents(struct fscache_object *object,
								int event)
{
	_enter("{OBJ%x},%d", object->debug_id, event);

	if (!fscache_enqueue_dependents(object, FSCACHE_OBJECT_EV_PARENT_READY))
		return NO_TRANSIT; /* Not finished; requeue */
	return transit_to(WAIT_FOR_CMD);
}

/*
 * Handle lookup or creation failute.
 */
static const struct fscache_state *fscache_lookup_failure(struct fscache_object *object,
							  int event)
{
	struct fscache_cookie *cookie;

	_enter("{OBJ%x},%d", object->debug_id, event);

	object->oob_event_mask = 0;

	fscache_stat(&fscache_n_cop_lookup_complete);
	object->cache->ops->lookup_complete(object);
	fscache_stat_d(&fscache_n_cop_lookup_complete);

	cookie = object->cookie;
	set_bit(FSCACHE_COOKIE_UNAVAILABLE, &cookie->flags);
	if (test_and_clear_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags))
		wake_up_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP);

	fscache_done_parent_op(object);
	return transit_to(KILL_OBJECT);
}

/*
 * Wait for completion of all active operations on this object and the death of
 * all child objects of this object.
 */
static const struct fscache_state *fscache_kill_object(struct fscache_object *object,
						       int event)
{
	_enter("{OBJ%x,%d,%d},%d",
	       object->debug_id, object->n_ops, object->n_children, event);

	clear_bit(FSCACHE_OBJECT_IS_LIVE, &object->flags);
	object->oob_event_mask = 0;

	if (list_empty(&object->dependents) &&
	    object->n_ops == 0 &&
	    object->n_children == 0)
		return transit_to(DROP_OBJECT);

	if (object->n_in_progress == 0) {
		spin_lock(&object->lock);
		if (object->n_ops > 0 && object->n_in_progress == 0)
			fscache_start_operations(object);
		spin_unlock(&object->lock);
	}

	if (!list_empty(&object->dependents))
		return transit_to(KILL_DEPENDENTS);

	return transit_to(WAIT_FOR_CLEARANCE);
}

/*
 * Kill dependent objects.
 */
static const struct fscache_state *fscache_kill_dependents(struct fscache_object *object,
							   int event)
{
	_enter("{OBJ%x},%d", object->debug_id, event);

	if (!fscache_enqueue_dependents(object, FSCACHE_OBJECT_EV_KILL))
		return NO_TRANSIT; /* Not finished */
	return transit_to(WAIT_FOR_CLEARANCE);
}

/*
 * Drop an object's attachments
 */
static const struct fscache_state *fscache_drop_object(struct fscache_object *object,
						       int event)
{
	struct fscache_object *parent = object->parent;
	struct fscache_cookie *cookie = object->cookie;
	struct fscache_cache *cache = object->cache;
	bool awaken = false;

	_enter("{OBJ%x,%d},%d", object->debug_id, object->n_children, event);

	ASSERT(cookie != NULL);
	ASSERT(!hlist_unhashed(&object->cookie_link));

	/* Make sure the cookie no longer points here and that the netfs isn't
	 * waiting for us.
	 */
	spin_lock(&cookie->lock);
	hlist_del_init(&object->cookie_link);
	if (hlist_empty(&cookie->backing_objects) &&
	    test_and_clear_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags))
		awaken = true;
	spin_unlock(&cookie->lock);

	if (awaken)
		wake_up_bit(&cookie->flags, FSCACHE_COOKIE_INVALIDATING);

	/* Prevent a race with our last child, which has to signal EV_CLEARED
	 * before dropping our spinlock.
	 */
	spin_lock(&object->lock);
	spin_unlock(&object->lock);

	/* Discard from the cache's collection of objects */
	spin_lock(&cache->object_list_lock);
	list_del_init(&object->cache_link);
	spin_unlock(&cache->object_list_lock);

	fscache_stat(&fscache_n_cop_drop_object);
	cache->ops->drop_object(object);
	fscache_stat_d(&fscache_n_cop_drop_object);

	/* The parent object wants to know when all it dependents have gone */
	if (parent) {
		_debug("release parent OBJ%x {%d}",
		       parent->debug_id, parent->n_children);

		spin_lock(&parent->lock);
		parent->n_children--;
		if (parent->n_children == 0)
			fscache_raise_event(parent, FSCACHE_OBJECT_EV_CLEARED);
		spin_unlock(&parent->lock);
		object->parent = NULL;
	}

	/* this just shifts the object release to the work processor */
	fscache_put_object(object);
	fscache_stat(&fscache_n_object_dead);

	_leave("");
	return transit_to(OBJECT_DEAD);
}

/*
 * get a ref on an object
 */
static int fscache_get_object(struct fscache_object *object)
{
	int ret;

	fscache_stat(&fscache_n_cop_grab_object);
	ret = object->cache->ops->grab_object(object) ? 0 : -EAGAIN;
	fscache_stat_d(&fscache_n_cop_grab_object);
	return ret;
}

/*
 * Discard a ref on an object
 */
static void fscache_put_object(struct fscache_object *object)
{
	fscache_stat(&fscache_n_cop_put_object);
	object->cache->ops->put_object(object);
	fscache_stat_d(&fscache_n_cop_put_object);
}

/**
 * fscache_object_destroy - Note that a cache object is about to be destroyed
 * @object: The object to be destroyed
 *
 * Note the imminent destruction and deallocation of a cache object record.
 */
void fscache_object_destroy(struct fscache_object *object)
{
	fscache_objlist_remove(object);

	/* We can get rid of the cookie now */
	fscache_cookie_put(object->cookie);
	object->cookie = NULL;
}
EXPORT_SYMBOL(fscache_object_destroy);

/*
 * enqueue an object for metadata-type processing
 */
void fscache_enqueue_object(struct fscache_object *object)
{
	_enter("{OBJ%x}", object->debug_id);

	if (fscache_get_object(object) >= 0) {
		wait_queue_head_t *cong_wq =
			&get_cpu_var(fscache_object_cong_wait);

		if (queue_work(fscache_object_wq, &object->work)) {
			if (fscache_object_congested())
				wake_up(cong_wq);
		} else
			fscache_put_object(object);

		put_cpu_var(fscache_object_cong_wait);
	}
}

/**
 * fscache_object_sleep_till_congested - Sleep until object wq is congested
 * @timeoutp: Scheduler sleep timeout
 *
 * Allow an object handler to sleep until the object workqueue is congested.
 *
 * The caller must set up a wake up event before calling this and must have set
 * the appropriate sleep mode (such as TASK_UNINTERRUPTIBLE) and tested its own
 * condition before calling this function as no test is made here.
 *
 * %true is returned if the object wq is congested, %false otherwise.
 */
bool fscache_object_sleep_till_congested(signed long *timeoutp)
{
	wait_queue_head_t *cong_wq = this_cpu_ptr(&fscache_object_cong_wait);
	DEFINE_WAIT(wait);

	if (fscache_object_congested())
		return true;

	add_wait_queue_exclusive(cong_wq, &wait);
	if (!fscache_object_congested())
		*timeoutp = schedule_timeout(*timeoutp);
	finish_wait(cong_wq, &wait);

	return fscache_object_congested();
}
EXPORT_SYMBOL_GPL(fscache_object_sleep_till_congested);

/*
 * Enqueue the dependents of an object for metadata-type processing.
 *
 * If we don't manage to finish the list before the scheduler wants to run
 * again then return false immediately.  We return true if the list was
 * cleared.
 */
static bool fscache_enqueue_dependents(struct fscache_object *object, int event)
{
	struct fscache_object *dep;
	bool ret = true;

	_enter("{OBJ%x}", object->debug_id);

	if (list_empty(&object->dependents))
		return true;

	spin_lock(&object->lock);

	while (!list_empty(&object->dependents)) {
		dep = list_entry(object->dependents.next,
				 struct fscache_object, dep_link);
		list_del_init(&dep->dep_link);

		fscache_raise_event(dep, event);
		fscache_put_object(dep);

		if (!list_empty(&object->dependents) && need_resched()) {
			ret = false;
			break;
		}
	}

	spin_unlock(&object->lock);
	return ret;
}

/*
 * remove an object from whatever queue it's waiting on
 */
static void fscache_dequeue_object(struct fscache_object *object)
{
	_enter("{OBJ%x}", object->debug_id);

	if (!list_empty(&object->dep_link)) {
		spin_lock(&object->parent->lock);
		list_del_init(&object->dep_link);
		spin_unlock(&object->parent->lock);
	}

	_leave("");
}

/**
 * fscache_check_aux - Ask the netfs whether an object on disk is still valid
 * @object: The object to ask about
 * @data: The auxiliary data for the object
 * @datalen: The size of the auxiliary data
 *
 * This function consults the netfs about the coherency state of an object.
 * The caller must be holding a ref on cookie->n_active (held by
 * fscache_look_up_object() on behalf of the cache backend during object lookup
 * and creation).
 */
enum fscache_checkaux fscache_check_aux(struct fscache_object *object,
					const void *data, uint16_t datalen)
{
	enum fscache_checkaux result;

	if (!object->cookie->def->check_aux) {
		fscache_stat(&fscache_n_checkaux_none);
		return FSCACHE_CHECKAUX_OKAY;
	}

	result = object->cookie->def->check_aux(object->cookie->netfs_data,
						data, datalen);
	switch (result) {
		/* entry okay as is */
	case FSCACHE_CHECKAUX_OKAY:
		fscache_stat(&fscache_n_checkaux_okay);
		break;

		/* entry requires update */
	case FSCACHE_CHECKAUX_NEEDS_UPDATE:
		fscache_stat(&fscache_n_checkaux_update);
		break;

		/* entry requires deletion */
	case FSCACHE_CHECKAUX_OBSOLETE:
		fscache_stat(&fscache_n_checkaux_obsolete);
		break;

	default:
		BUG();
	}

	return result;
}
EXPORT_SYMBOL(fscache_check_aux);

/*
 * Asynchronously invalidate an object.
 */
static const struct fscache_state *_fscache_invalidate_object(struct fscache_object *object,
							      int event)
{
	struct fscache_operation *op;
	struct fscache_cookie *cookie = object->cookie;

	_enter("{OBJ%x},%d", object->debug_id, event);

	/* We're going to need the cookie.  If the cookie is not available then
	 * retire the object instead.
	 */
	if (!fscache_use_cookie(object)) {
		ASSERT(object->cookie->stores.rnode == NULL);
		set_bit(FSCACHE_OBJECT_RETIRED, &object->flags);
		_leave(" [no cookie]");
		return transit_to(KILL_OBJECT);
	}

	/* Reject any new read/write ops and abort any that are pending. */
	fscache_invalidate_writes(cookie);
	clear_bit(FSCACHE_OBJECT_PENDING_WRITE, &object->flags);
	fscache_cancel_all_ops(object);

	/* Now we have to wait for in-progress reads and writes */
	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op)
		goto nomem;

	fscache_operation_init(op, object->cache->ops->invalidate_object, NULL);
	op->flags = FSCACHE_OP_ASYNC |
		(1 << FSCACHE_OP_EXCLUSIVE) |
		(1 << FSCACHE_OP_UNUSE_COOKIE);

	spin_lock(&cookie->lock);
	if (fscache_submit_exclusive_op(object, op) < 0)
		goto submit_op_failed;
	spin_unlock(&cookie->lock);
	fscache_put_operation(op);

	/* Once we've completed the invalidation, we know there will be no data
	 * stored in the cache and thus we can reinstate the data-check-skip
	 * optimisation.
	 */
	set_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);

	/* We can allow read and write requests to come in once again.  They'll
	 * queue up behind our exclusive invalidation operation.
	 */
	if (test_and_clear_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags))
		wake_up_bit(&cookie->flags, FSCACHE_COOKIE_INVALIDATING);
	_leave(" [ok]");
	return transit_to(UPDATE_OBJECT);

nomem:
	clear_bit(FSCACHE_OBJECT_IS_LIVE, &object->flags);
	fscache_unuse_cookie(object);
	_leave(" [ENOMEM]");
	return transit_to(KILL_OBJECT);

submit_op_failed:
	clear_bit(FSCACHE_OBJECT_IS_LIVE, &object->flags);
	spin_unlock(&cookie->lock);
	kfree(op);
	_leave(" [EIO]");
	return transit_to(KILL_OBJECT);
}

static const struct fscache_state *fscache_invalidate_object(struct fscache_object *object,
							     int event)
{
	const struct fscache_state *s;

	fscache_stat(&fscache_n_invalidates_run);
	fscache_stat(&fscache_n_cop_invalidate_object);
	s = _fscache_invalidate_object(object, event);
	fscache_stat_d(&fscache_n_cop_invalidate_object);
	return s;
}

/*
 * Asynchronously update an object.
 */
static const struct fscache_state *fscache_update_object(struct fscache_object *object,
							 int event)
{
	_enter("{OBJ%x},%d", object->debug_id, event);

	fscache_stat(&fscache_n_updates_run);
	fscache_stat(&fscache_n_cop_update_object);
	object->cache->ops->update_object(object);
	fscache_stat_d(&fscache_n_cop_update_object);

	_leave("");
	return transit_to(WAIT_FOR_CMD);
}
/************************************************************/
/* ../linux-3.17/fs/fscache/operation.c */
/************************************************************/
/* FS-Cache worker operation management routines
 *
 * Copyright (C) 2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * See Documentation/filesystems/caching/operations.txt
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
// #include <linux/module.h>
// #include <linux/seq_file.h>
// #include <linux/slab.h>
// #include "internal.h"

atomic_t fscache_op_debug_id;
EXPORT_SYMBOL(fscache_op_debug_id);

/**
 * fscache_enqueue_operation - Enqueue an operation for processing
 * @op: The operation to enqueue
 *
 * Enqueue an operation for processing by the FS-Cache thread pool.
 *
 * This will get its own ref on the object.
 */
void fscache_enqueue_operation(struct fscache_operation *op)
{
	_enter("{OBJ%x OP%x,%u}",
	       op->object->debug_id, op->debug_id, atomic_read(&op->usage));

	ASSERT(list_empty(&op->pend_link));
	ASSERT(op->processor != NULL);
	ASSERT(fscache_object_is_available(op->object));
	ASSERTCMP(atomic_read(&op->usage), >, 0);
	ASSERTCMP(op->state, ==, FSCACHE_OP_ST_IN_PROGRESS);

	fscache_stat(&fscache_n_op_enqueue);
	switch (op->flags & FSCACHE_OP_TYPE) {
	case FSCACHE_OP_ASYNC:
		_debug("queue async");
		atomic_inc(&op->usage);
		if (!queue_work(fscache_op_wq, &op->work))
			fscache_put_operation(op);
		break;
	case FSCACHE_OP_MYTHREAD:
		_debug("queue for caller's attention");
		break;
	default:
		pr_err("Unexpected op type %lx", op->flags);
		BUG();
		break;
	}
}
EXPORT_SYMBOL(fscache_enqueue_operation);

/*
 * start an op running
 */
static void fscache_run_op(struct fscache_object *object,
			   struct fscache_operation *op)
{
	ASSERTCMP(op->state, ==, FSCACHE_OP_ST_PENDING);

	op->state = FSCACHE_OP_ST_IN_PROGRESS;
	object->n_in_progress++;
	if (test_and_clear_bit(FSCACHE_OP_WAITING, &op->flags))
		wake_up_bit(&op->flags, FSCACHE_OP_WAITING);
	if (op->processor)
		fscache_enqueue_operation(op);
	fscache_stat(&fscache_n_op_run);
}

/*
 * submit an exclusive operation for an object
 * - other ops are excluded from running simultaneously with this one
 * - this gets any extra refs it needs on an op
 */
int fscache_submit_exclusive_op(struct fscache_object *object,
				struct fscache_operation *op)
{
	int ret;

	_enter("{OBJ%x OP%x},", object->debug_id, op->debug_id);

	ASSERTCMP(op->state, ==, FSCACHE_OP_ST_INITIALISED);
	ASSERTCMP(atomic_read(&op->usage), >, 0);

	spin_lock(&object->lock);
	ASSERTCMP(object->n_ops, >=, object->n_in_progress);
	ASSERTCMP(object->n_ops, >=, object->n_exclusive);
	ASSERT(list_empty(&op->pend_link));

	op->state = FSCACHE_OP_ST_PENDING;
	if (fscache_object_is_active(object)) {
		op->object = object;
		object->n_ops++;
		object->n_exclusive++;	/* reads and writes must wait */

		if (object->n_in_progress > 0) {
			atomic_inc(&op->usage);
			list_add_tail(&op->pend_link, &object->pending_ops);
			fscache_stat(&fscache_n_op_pend);
		} else if (!list_empty(&object->pending_ops)) {
			atomic_inc(&op->usage);
			list_add_tail(&op->pend_link, &object->pending_ops);
			fscache_stat(&fscache_n_op_pend);
			fscache_start_operations(object);
		} else {
			ASSERTCMP(object->n_in_progress, ==, 0);
			fscache_run_op(object, op);
		}

		/* need to issue a new write op after this */
		clear_bit(FSCACHE_OBJECT_PENDING_WRITE, &object->flags);
		ret = 0;
	} else if (test_bit(FSCACHE_OBJECT_IS_LOOKED_UP, &object->flags)) {
		op->object = object;
		object->n_ops++;
		object->n_exclusive++;	/* reads and writes must wait */
		atomic_inc(&op->usage);
		list_add_tail(&op->pend_link, &object->pending_ops);
		fscache_stat(&fscache_n_op_pend);
		ret = 0;
	} else {
		/* If we're in any other state, there must have been an I/O
		 * error of some nature.
		 */
		ASSERT(test_bit(FSCACHE_IOERROR, &object->cache->flags));
		ret = -EIO;
	}

	spin_unlock(&object->lock);
	return ret;
}

/*
 * report an unexpected submission
 */
static void fscache_report_unexpected_submission(struct fscache_object *object,
						 struct fscache_operation *op,
						 const struct fscache_state *ostate)
{
	static bool once_only;
	struct fscache_operation *p;
	unsigned n;

	if (once_only)
		return;
	once_only = true;

	kdebug("unexpected submission OP%x [OBJ%x %s]",
	       op->debug_id, object->debug_id, object->state->name);
	kdebug("objstate=%s [%s]", object->state->name, ostate->name);
	kdebug("objflags=%lx", object->flags);
	kdebug("objevent=%lx [%lx]", object->events, object->event_mask);
	kdebug("ops=%u inp=%u exc=%u",
	       object->n_ops, object->n_in_progress, object->n_exclusive);

	if (!list_empty(&object->pending_ops)) {
		n = 0;
		list_for_each_entry(p, &object->pending_ops, pend_link) {
			ASSERTCMP(p->object, ==, object);
			kdebug("%p %p", op->processor, op->release);
			n++;
		}

		kdebug("n=%u", n);
	}

	dump_stack();
}

/*
 * submit an operation for an object
 * - objects may be submitted only in the following states:
 *   - during object creation (write ops may be submitted)
 *   - whilst the object is active
 *   - after an I/O error incurred in one of the two above states (op rejected)
 * - this gets any extra refs it needs on an op
 */
int fscache_submit_op(struct fscache_object *object,
		      struct fscache_operation *op)
{
	const struct fscache_state *ostate;
	int ret;

	_enter("{OBJ%x OP%x},{%u}",
	       object->debug_id, op->debug_id, atomic_read(&op->usage));

	ASSERTCMP(op->state, ==, FSCACHE_OP_ST_INITIALISED);
	ASSERTCMP(atomic_read(&op->usage), >, 0);

	spin_lock(&object->lock);
	ASSERTCMP(object->n_ops, >=, object->n_in_progress);
	ASSERTCMP(object->n_ops, >=, object->n_exclusive);
	ASSERT(list_empty(&op->pend_link));

	ostate = object->state;
	smp_rmb();

	op->state = FSCACHE_OP_ST_PENDING;
	if (fscache_object_is_active(object)) {
		op->object = object;
		object->n_ops++;

		if (object->n_exclusive > 0) {
			atomic_inc(&op->usage);
			list_add_tail(&op->pend_link, &object->pending_ops);
			fscache_stat(&fscache_n_op_pend);
		} else if (!list_empty(&object->pending_ops)) {
			atomic_inc(&op->usage);
			list_add_tail(&op->pend_link, &object->pending_ops);
			fscache_stat(&fscache_n_op_pend);
			fscache_start_operations(object);
		} else {
			ASSERTCMP(object->n_exclusive, ==, 0);
			fscache_run_op(object, op);
		}
		ret = 0;
	} else if (test_bit(FSCACHE_OBJECT_IS_LOOKED_UP, &object->flags)) {
		op->object = object;
		object->n_ops++;
		atomic_inc(&op->usage);
		list_add_tail(&op->pend_link, &object->pending_ops);
		fscache_stat(&fscache_n_op_pend);
		ret = 0;
	} else if (fscache_object_is_dying(object)) {
		fscache_stat(&fscache_n_op_rejected);
		op->state = FSCACHE_OP_ST_CANCELLED;
		ret = -ENOBUFS;
	} else if (!test_bit(FSCACHE_IOERROR, &object->cache->flags)) {
		fscache_report_unexpected_submission(object, op, ostate);
		ASSERT(!fscache_object_is_active(object));
		op->state = FSCACHE_OP_ST_CANCELLED;
		ret = -ENOBUFS;
	} else {
		op->state = FSCACHE_OP_ST_CANCELLED;
		ret = -ENOBUFS;
	}

	spin_unlock(&object->lock);
	return ret;
}

/*
 * queue an object for withdrawal on error, aborting all following asynchronous
 * operations
 */
void fscache_abort_object(struct fscache_object *object)
{
	_enter("{OBJ%x}", object->debug_id);

	fscache_raise_event(object, FSCACHE_OBJECT_EV_ERROR);
}

/*
 * Jump start the operation processing on an object.  The caller must hold
 * object->lock.
 */
void fscache_start_operations(struct fscache_object *object)
{
	struct fscache_operation *op;
	bool stop = false;

	while (!list_empty(&object->pending_ops) && !stop) {
		op = list_entry(object->pending_ops.next,
				struct fscache_operation, pend_link);

		if (test_bit(FSCACHE_OP_EXCLUSIVE, &op->flags)) {
			if (object->n_in_progress > 0)
				break;
			stop = true;
		}
		list_del_init(&op->pend_link);
		fscache_run_op(object, op);

		/* the pending queue was holding a ref on the object */
		fscache_put_operation(op);
	}

	ASSERTCMP(object->n_in_progress, <=, object->n_ops);

	_debug("woke %d ops on OBJ%x",
	       object->n_in_progress, object->debug_id);
}

/*
 * cancel an operation that's pending on an object
 */
int fscache_cancel_op(struct fscache_operation *op,
		      void (*do_cancel)(struct fscache_operation *))
{
	struct fscache_object *object = op->object;
	int ret;

	_enter("OBJ%x OP%x}", op->object->debug_id, op->debug_id);

	ASSERTCMP(op->state, >=, FSCACHE_OP_ST_PENDING);
	ASSERTCMP(op->state, !=, FSCACHE_OP_ST_CANCELLED);
	ASSERTCMP(atomic_read(&op->usage), >, 0);

	spin_lock(&object->lock);

	ret = -EBUSY;
	if (op->state == FSCACHE_OP_ST_PENDING) {
		ASSERT(!list_empty(&op->pend_link));
		fscache_stat(&fscache_n_op_cancelled);
		list_del_init(&op->pend_link);
		if (do_cancel)
			do_cancel(op);
		op->state = FSCACHE_OP_ST_CANCELLED;
		if (test_bit(FSCACHE_OP_EXCLUSIVE, &op->flags))
			object->n_exclusive--;
		if (test_and_clear_bit(FSCACHE_OP_WAITING, &op->flags))
			wake_up_bit(&op->flags, FSCACHE_OP_WAITING);
		fscache_put_operation(op);
		ret = 0;
	}

	spin_unlock(&object->lock);
	_leave(" = %d", ret);
	return ret;
}

/*
 * Cancel all pending operations on an object
 */
void fscache_cancel_all_ops(struct fscache_object *object)
{
	struct fscache_operation *op;

	_enter("OBJ%x", object->debug_id);

	spin_lock(&object->lock);

	while (!list_empty(&object->pending_ops)) {
		op = list_entry(object->pending_ops.next,
				struct fscache_operation, pend_link);
		fscache_stat(&fscache_n_op_cancelled);
		list_del_init(&op->pend_link);

		ASSERTCMP(op->state, ==, FSCACHE_OP_ST_PENDING);
		op->state = FSCACHE_OP_ST_CANCELLED;

		if (test_bit(FSCACHE_OP_EXCLUSIVE, &op->flags))
			object->n_exclusive--;
		if (test_and_clear_bit(FSCACHE_OP_WAITING, &op->flags))
			wake_up_bit(&op->flags, FSCACHE_OP_WAITING);
		fscache_put_operation(op);
		cond_resched_lock(&object->lock);
	}

	spin_unlock(&object->lock);
	_leave("");
}

/*
 * Record the completion or cancellation of an in-progress operation.
 */
void fscache_op_complete(struct fscache_operation *op, bool cancelled)
{
	struct fscache_object *object = op->object;

	_enter("OBJ%x", object->debug_id);

	ASSERTCMP(op->state, ==, FSCACHE_OP_ST_IN_PROGRESS);
	ASSERTCMP(object->n_in_progress, >, 0);
	ASSERTIFCMP(test_bit(FSCACHE_OP_EXCLUSIVE, &op->flags),
		    object->n_exclusive, >, 0);
	ASSERTIFCMP(test_bit(FSCACHE_OP_EXCLUSIVE, &op->flags),
		    object->n_in_progress, ==, 1);

	spin_lock(&object->lock);

	op->state = cancelled ?
		FSCACHE_OP_ST_CANCELLED : FSCACHE_OP_ST_COMPLETE;

	if (test_bit(FSCACHE_OP_EXCLUSIVE, &op->flags))
		object->n_exclusive--;
	object->n_in_progress--;
	if (object->n_in_progress == 0)
		fscache_start_operations(object);

	spin_unlock(&object->lock);
	_leave("");
}
EXPORT_SYMBOL(fscache_op_complete);

/*
 * release an operation
 * - queues pending ops if this is the last in-progress op
 */
void fscache_put_operation(struct fscache_operation *op)
{
	struct fscache_object *object;
	struct fscache_cache *cache;

	_enter("{OBJ%x OP%x,%d}",
	       op->object->debug_id, op->debug_id, atomic_read(&op->usage));

	ASSERTCMP(atomic_read(&op->usage), >, 0);

	if (!atomic_dec_and_test(&op->usage))
		return;

	_debug("PUT OP");
	ASSERTIFCMP(op->state != FSCACHE_OP_ST_COMPLETE,
		    op->state, ==, FSCACHE_OP_ST_CANCELLED);
	op->state = FSCACHE_OP_ST_DEAD;

	fscache_stat(&fscache_n_op_release);

	if (op->release) {
		op->release(op);
		op->release = NULL;
	}

	object = op->object;

	if (test_bit(FSCACHE_OP_DEC_READ_CNT, &op->flags))
		atomic_dec(&object->n_reads);
	if (test_bit(FSCACHE_OP_UNUSE_COOKIE, &op->flags))
		fscache_unuse_cookie(object);

	/* now... we may get called with the object spinlock held, so we
	 * complete the cleanup here only if we can immediately acquire the
	 * lock, and defer it otherwise */
	if (!spin_trylock(&object->lock)) {
		_debug("defer put");
		fscache_stat(&fscache_n_op_deferred_release);

		cache = object->cache;
		spin_lock(&cache->op_gc_list_lock);
		list_add_tail(&op->pend_link, &cache->op_gc_list);
		spin_unlock(&cache->op_gc_list_lock);
		schedule_work(&cache->op_gc);
		_leave(" [defer]");
		return;
	}

	ASSERTCMP(object->n_ops, >, 0);
	object->n_ops--;
	if (object->n_ops == 0)
		fscache_raise_event(object, FSCACHE_OBJECT_EV_CLEARED);

	spin_unlock(&object->lock);

	kfree(op);
	_leave(" [done]");
}
EXPORT_SYMBOL(fscache_put_operation);

/*
 * garbage collect operations that have had their release deferred
 */
void fscache_operation_gc(struct work_struct *work)
{
	struct fscache_operation *op;
	struct fscache_object *object;
	struct fscache_cache *cache =
		container_of(work, struct fscache_cache, op_gc);
	int count = 0;

	_enter("");

	do {
		spin_lock(&cache->op_gc_list_lock);
		if (list_empty(&cache->op_gc_list)) {
			spin_unlock(&cache->op_gc_list_lock);
			break;
		}

		op = list_entry(cache->op_gc_list.next,
				struct fscache_operation, pend_link);
		list_del(&op->pend_link);
		spin_unlock(&cache->op_gc_list_lock);

		object = op->object;
		spin_lock(&object->lock);

		_debug("GC DEFERRED REL OBJ%x OP%x",
		       object->debug_id, op->debug_id);
		fscache_stat(&fscache_n_op_gc);

		ASSERTCMP(atomic_read(&op->usage), ==, 0);
		ASSERTCMP(op->state, ==, FSCACHE_OP_ST_DEAD);

		ASSERTCMP(object->n_ops, >, 0);
		object->n_ops--;
		if (object->n_ops == 0)
			fscache_raise_event(object, FSCACHE_OBJECT_EV_CLEARED);

		spin_unlock(&object->lock);
		kfree(op);

	} while (count++ < 20);

	if (!list_empty(&cache->op_gc_list))
		schedule_work(&cache->op_gc);

	_leave("");
}

/*
 * execute an operation using fs_op_wq to provide processing context -
 * the caller holds a ref to this object, so we don't need to hold one
 */
void fscache_op_work_func(struct work_struct *work)
{
	struct fscache_operation *op =
		container_of(work, struct fscache_operation, work);
	unsigned long start;

	_enter("{OBJ%x OP%x,%d}",
	       op->object->debug_id, op->debug_id, atomic_read(&op->usage));

	ASSERT(op->processor != NULL);
	start = jiffies;
	op->processor(op);
	fscache_hist(fscache_ops_histogram, start);
	fscache_put_operation(op);

	_leave("");
}
/************************************************************/
/* ../linux-3.17/fs/fscache/page.c */
/************************************************************/
/* Cache page management and data I/O routines
 *
 * Copyright (C) 2004-2008 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define FSCACHE_DEBUG_LEVEL PAGE
// #include <linux/module.h>
#include <linux/fscache-cache.h>
#include <linux/buffer_head.h>
#include <linux/pagevec.h>
// #include <linux/slab.h>
// #include "internal.h"

/*
 * check to see if a page is being written to the cache
 */
bool __fscache_check_page_write(struct fscache_cookie *cookie, struct page *page)
{
	void *val;

	rcu_read_lock();
	val = radix_tree_lookup(&cookie->stores, page->index);
	rcu_read_unlock();

	return val != NULL;
}
EXPORT_SYMBOL(__fscache_check_page_write);

/*
 * wait for a page to finish being written to the cache
 */
void __fscache_wait_on_page_write(struct fscache_cookie *cookie, struct page *page)
{
	wait_queue_head_t *wq = bit_waitqueue(&cookie->flags, 0);

	wait_event(*wq, !__fscache_check_page_write(cookie, page));
}
EXPORT_SYMBOL(__fscache_wait_on_page_write);

/*
 * decide whether a page can be released, possibly by cancelling a store to it
 * - we're allowed to sleep if __GFP_WAIT is flagged
 */
bool __fscache_maybe_release_page(struct fscache_cookie *cookie,
				  struct page *page,
				  gfp_t gfp)
{
	struct page *xpage;
	void *val;

	_enter("%p,%p,%x", cookie, page, gfp);

try_again:
	rcu_read_lock();
	val = radix_tree_lookup(&cookie->stores, page->index);
	if (!val) {
		rcu_read_unlock();
		fscache_stat(&fscache_n_store_vmscan_not_storing);
		__fscache_uncache_page(cookie, page);
		return true;
	}

	/* see if the page is actually undergoing storage - if so we can't get
	 * rid of it till the cache has finished with it */
	if (radix_tree_tag_get(&cookie->stores, page->index,
			       FSCACHE_COOKIE_STORING_TAG)) {
		rcu_read_unlock();
		goto page_busy;
	}

	/* the page is pending storage, so we attempt to cancel the store and
	 * discard the store request so that the page can be reclaimed */
	spin_lock(&cookie->stores_lock);
	rcu_read_unlock();

	if (radix_tree_tag_get(&cookie->stores, page->index,
			       FSCACHE_COOKIE_STORING_TAG)) {
		/* the page started to undergo storage whilst we were looking,
		 * so now we can only wait or return */
		spin_unlock(&cookie->stores_lock);
		goto page_busy;
	}

	xpage = radix_tree_delete(&cookie->stores, page->index);
	spin_unlock(&cookie->stores_lock);

	if (xpage) {
		fscache_stat(&fscache_n_store_vmscan_cancelled);
		fscache_stat(&fscache_n_store_radix_deletes);
		ASSERTCMP(xpage, ==, page);
	} else {
		fscache_stat(&fscache_n_store_vmscan_gone);
	}

	wake_up_bit(&cookie->flags, 0);
	if (xpage)
		page_cache_release(xpage);
	__fscache_uncache_page(cookie, page);
	return true;

page_busy:
	/* We will wait here if we're allowed to, but that could deadlock the
	 * allocator as the work threads writing to the cache may all end up
	 * sleeping on memory allocation, so we may need to impose a timeout
	 * too. */
	if (!(gfp & __GFP_WAIT) || !(gfp & __GFP_FS)) {
		fscache_stat(&fscache_n_store_vmscan_busy);
		return false;
	}

	fscache_stat(&fscache_n_store_vmscan_wait);
	__fscache_wait_on_page_write(cookie, page);
	gfp &= ~__GFP_WAIT;
	goto try_again;
}
EXPORT_SYMBOL(__fscache_maybe_release_page);

/*
 * note that a page has finished being written to the cache
 */
static void fscache_end_page_write(struct fscache_object *object,
				   struct page *page)
{
	struct fscache_cookie *cookie;
	struct page *xpage = NULL;

	spin_lock(&object->lock);
	cookie = object->cookie;
	if (cookie) {
		/* delete the page from the tree if it is now no longer
		 * pending */
		spin_lock(&cookie->stores_lock);
		radix_tree_tag_clear(&cookie->stores, page->index,
				     FSCACHE_COOKIE_STORING_TAG);
		if (!radix_tree_tag_get(&cookie->stores, page->index,
					FSCACHE_COOKIE_PENDING_TAG)) {
			fscache_stat(&fscache_n_store_radix_deletes);
			xpage = radix_tree_delete(&cookie->stores, page->index);
		}
		spin_unlock(&cookie->stores_lock);
		wake_up_bit(&cookie->flags, 0);
	}
	spin_unlock(&object->lock);
	if (xpage)
		page_cache_release(xpage);
}

/*
 * actually apply the changed attributes to a cache object
 */
static void fscache_attr_changed_op(struct fscache_operation *op)
{
	struct fscache_object *object = op->object;
	int ret;

	_enter("{OBJ%x OP%x}", object->debug_id, op->debug_id);

	fscache_stat(&fscache_n_attr_changed_calls);

	if (fscache_object_is_active(object)) {
		fscache_stat(&fscache_n_cop_attr_changed);
		ret = object->cache->ops->attr_changed(object);
		fscache_stat_d(&fscache_n_cop_attr_changed);
		if (ret < 0)
			fscache_abort_object(object);
	}

	fscache_op_complete(op, true);
	_leave("");
}

/*
 * notification that the attributes on an object have changed
 */
int __fscache_attr_changed(struct fscache_cookie *cookie)
{
	struct fscache_operation *op;
	struct fscache_object *object;
	bool wake_cookie;

	_enter("%p", cookie);

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);

	fscache_stat(&fscache_n_attr_changed);

	op = kzalloc(sizeof(*op), GFP_KERNEL);
	if (!op) {
		fscache_stat(&fscache_n_attr_changed_nomem);
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}

	fscache_operation_init(op, fscache_attr_changed_op, NULL);
	op->flags = FSCACHE_OP_ASYNC |
		(1 << FSCACHE_OP_EXCLUSIVE) |
		(1 << FSCACHE_OP_UNUSE_COOKIE);

	spin_lock(&cookie->lock);

	if (!fscache_cookie_enabled(cookie) ||
	    hlist_empty(&cookie->backing_objects))
		goto nobufs;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	__fscache_use_cookie(cookie);
	if (fscache_submit_exclusive_op(object, op) < 0)
		goto nobufs;
	spin_unlock(&cookie->lock);
	fscache_stat(&fscache_n_attr_changed_ok);
	fscache_put_operation(op);
	_leave(" = 0");
	return 0;

nobufs:
	wake_cookie = __fscache_unuse_cookie(cookie);
	spin_unlock(&cookie->lock);
	kfree(op);
	if (wake_cookie)
		__fscache_wake_unused_cookie(cookie);
	fscache_stat(&fscache_n_attr_changed_nobufs);
	_leave(" = %d", -ENOBUFS);
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_attr_changed);

/*
 * release a retrieval op reference
 */
static void fscache_release_retrieval_op(struct fscache_operation *_op)
{
	struct fscache_retrieval *op =
		container_of(_op, struct fscache_retrieval, op);

	_enter("{OP%x}", op->op.debug_id);

	ASSERTCMP(atomic_read(&op->n_pages), ==, 0);

	fscache_hist(fscache_retrieval_histogram, op->start_time);
	if (op->context)
		fscache_put_context(op->op.object->cookie, op->context);

	_leave("");
}

/*
 * allocate a retrieval op
 */
static struct fscache_retrieval *fscache_alloc_retrieval(
	struct fscache_cookie *cookie,
	struct address_space *mapping,
	fscache_rw_complete_t end_io_func,
	void *context)
{
	struct fscache_retrieval *op;

	/* allocate a retrieval operation and attempt to submit it */
	op = kzalloc(sizeof(*op), GFP_NOIO);
	if (!op) {
		fscache_stat(&fscache_n_retrievals_nomem);
		return NULL;
	}

	fscache_operation_init(&op->op, NULL, fscache_release_retrieval_op);
	op->op.flags	= FSCACHE_OP_MYTHREAD |
		(1UL << FSCACHE_OP_WAITING) |
		(1UL << FSCACHE_OP_UNUSE_COOKIE);
	op->mapping	= mapping;
	op->end_io_func	= end_io_func;
	op->context	= context;
	op->start_time	= jiffies;
	INIT_LIST_HEAD(&op->to_do);
	return op;
}

/*
 * wait for a deferred lookup to complete
 */
int fscache_wait_for_deferred_lookup(struct fscache_cookie *cookie)
{
	unsigned long jif;

	_enter("");

	if (!test_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags)) {
		_leave(" = 0 [imm]");
		return 0;
	}

	fscache_stat(&fscache_n_retrievals_wait);

	jif = jiffies;
	if (wait_on_bit(&cookie->flags, FSCACHE_COOKIE_LOOKING_UP,
			TASK_INTERRUPTIBLE) != 0) {
		fscache_stat(&fscache_n_retrievals_intr);
		_leave(" = -ERESTARTSYS");
		return -ERESTARTSYS;
	}

	ASSERT(!test_bit(FSCACHE_COOKIE_LOOKING_UP, &cookie->flags));

	smp_rmb();
	fscache_hist(fscache_retrieval_delay_histogram, jif);
	_leave(" = 0 [dly]");
	return 0;
}

/*
 * Handle cancellation of a pending retrieval op
 */
static void fscache_do_cancel_retrieval(struct fscache_operation *_op)
{
	struct fscache_retrieval *op =
		container_of(_op, struct fscache_retrieval, op);

	atomic_set(&op->n_pages, 0);
}

/*
 * wait for an object to become active (or dead)
 */
int fscache_wait_for_operation_activation(struct fscache_object *object,
					  struct fscache_operation *op,
					  atomic_t *stat_op_waits,
					  atomic_t *stat_object_dead,
					  void (*do_cancel)(struct fscache_operation *))
{
	int ret;

	if (!test_bit(FSCACHE_OP_WAITING, &op->flags))
		goto check_if_dead;

	_debug(">>> WT");
	if (stat_op_waits)
		fscache_stat(stat_op_waits);
	if (wait_on_bit(&op->flags, FSCACHE_OP_WAITING,
			TASK_INTERRUPTIBLE) != 0) {
		ret = fscache_cancel_op(op, do_cancel);
		if (ret == 0)
			return -ERESTARTSYS;

		/* it's been removed from the pending queue by another party,
		 * so we should get to run shortly */
		wait_on_bit(&op->flags, FSCACHE_OP_WAITING,
			    TASK_UNINTERRUPTIBLE);
	}
	_debug("<<< GO");

check_if_dead:
	if (op->state == FSCACHE_OP_ST_CANCELLED) {
		if (stat_object_dead)
			fscache_stat(stat_object_dead);
		_leave(" = -ENOBUFS [cancelled]");
		return -ENOBUFS;
	}
	if (unlikely(fscache_object_is_dead(object))) {
		pr_err("%s() = -ENOBUFS [obj dead %d]\n", __func__, op->state);
		fscache_cancel_op(op, do_cancel);
		if (stat_object_dead)
			fscache_stat(stat_object_dead);
		return -ENOBUFS;
	}
	return 0;
}

/*
 * read a page from the cache or allocate a block in which to store it
 * - we return:
 *   -ENOMEM	- out of memory, nothing done
 *   -ERESTARTSYS - interrupted
 *   -ENOBUFS	- no backing object available in which to cache the block
 *   -ENODATA	- no data available in the backing object for this block
 *   0		- dispatched a read - it'll call end_io_func() when finished
 */
int __fscache_read_or_alloc_page(struct fscache_cookie *cookie,
				 struct page *page,
				 fscache_rw_complete_t end_io_func,
				 void *context,
				 gfp_t gfp)
{
	struct fscache_retrieval *op;
	struct fscache_object *object;
	bool wake_cookie = false;
	int ret;

	_enter("%p,%p,,,", cookie, page);

	fscache_stat(&fscache_n_retrievals);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;

	if (test_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags)) {
		_leave(" = -ENOBUFS [invalidating]");
		return -ENOBUFS;
	}

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERTCMP(page, !=, NULL);

	if (fscache_wait_for_deferred_lookup(cookie) < 0)
		return -ERESTARTSYS;

	op = fscache_alloc_retrieval(cookie, page->mapping,
				     end_io_func, context);
	if (!op) {
		_leave(" = -ENOMEM");
		return -ENOMEM;
	}
	atomic_set(&op->n_pages, 1);

	spin_lock(&cookie->lock);

	if (!fscache_cookie_enabled(cookie) ||
	    hlist_empty(&cookie->backing_objects))
		goto nobufs_unlock;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	ASSERT(test_bit(FSCACHE_OBJECT_IS_LOOKED_UP, &object->flags));

	__fscache_use_cookie(cookie);
	atomic_inc(&object->n_reads);
	__set_bit(FSCACHE_OP_DEC_READ_CNT, &op->op.flags);

	if (fscache_submit_op(object, &op->op) < 0)
		goto nobufs_unlock_dec;
	spin_unlock(&cookie->lock);

	fscache_stat(&fscache_n_retrieval_ops);

	/* pin the netfs read context in case we need to do the actual netfs
	 * read because we've encountered a cache read failure */
	fscache_get_context(object->cookie, op->context);

	/* we wait for the operation to become active, and then process it
	 * *here*, in this thread, and not in the thread pool */
	ret = fscache_wait_for_operation_activation(
		object, &op->op,
		__fscache_stat(&fscache_n_retrieval_op_waits),
		__fscache_stat(&fscache_n_retrievals_object_dead),
		fscache_do_cancel_retrieval);
	if (ret < 0)
		goto error;

	/* ask the cache to honour the operation */
	if (test_bit(FSCACHE_COOKIE_NO_DATA_YET, &object->cookie->flags)) {
		fscache_stat(&fscache_n_cop_allocate_page);
		ret = object->cache->ops->allocate_page(op, page, gfp);
		fscache_stat_d(&fscache_n_cop_allocate_page);
		if (ret == 0)
			ret = -ENODATA;
	} else {
		fscache_stat(&fscache_n_cop_read_or_alloc_page);
		ret = object->cache->ops->read_or_alloc_page(op, page, gfp);
		fscache_stat_d(&fscache_n_cop_read_or_alloc_page);
	}

error:
	if (ret == -ENOMEM)
		fscache_stat(&fscache_n_retrievals_nomem);
	else if (ret == -ERESTARTSYS)
		fscache_stat(&fscache_n_retrievals_intr);
	else if (ret == -ENODATA)
		fscache_stat(&fscache_n_retrievals_nodata);
	else if (ret < 0)
		fscache_stat(&fscache_n_retrievals_nobufs);
	else
		fscache_stat(&fscache_n_retrievals_ok);

	fscache_put_retrieval(op);
	_leave(" = %d", ret);
	return ret;

nobufs_unlock_dec:
	atomic_dec(&object->n_reads);
	wake_cookie = __fscache_unuse_cookie(cookie);
nobufs_unlock:
	spin_unlock(&cookie->lock);
	if (wake_cookie)
		__fscache_wake_unused_cookie(cookie);
	kfree(op);
nobufs:
	fscache_stat(&fscache_n_retrievals_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_read_or_alloc_page);

/*
 * read a list of page from the cache or allocate a block in which to store
 * them
 * - we return:
 *   -ENOMEM	- out of memory, some pages may be being read
 *   -ERESTARTSYS - interrupted, some pages may be being read
 *   -ENOBUFS	- no backing object or space available in which to cache any
 *                pages not being read
 *   -ENODATA	- no data available in the backing object for some or all of
 *                the pages
 *   0		- dispatched a read on all pages
 *
 * end_io_func() will be called for each page read from the cache as it is
 * finishes being read
 *
 * any pages for which a read is dispatched will be removed from pages and
 * nr_pages
 */
int __fscache_read_or_alloc_pages(struct fscache_cookie *cookie,
				  struct address_space *mapping,
				  struct list_head *pages,
				  unsigned *nr_pages,
				  fscache_rw_complete_t end_io_func,
				  void *context,
				  gfp_t gfp)
{
	struct fscache_retrieval *op;
	struct fscache_object *object;
	bool wake_cookie = false;
	int ret;

	_enter("%p,,%d,,,", cookie, *nr_pages);

	fscache_stat(&fscache_n_retrievals);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;

	if (test_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags)) {
		_leave(" = -ENOBUFS [invalidating]");
		return -ENOBUFS;
	}

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERTCMP(*nr_pages, >, 0);
	ASSERT(!list_empty(pages));

	if (fscache_wait_for_deferred_lookup(cookie) < 0)
		return -ERESTARTSYS;

	op = fscache_alloc_retrieval(cookie, mapping, end_io_func, context);
	if (!op)
		return -ENOMEM;
	atomic_set(&op->n_pages, *nr_pages);

	spin_lock(&cookie->lock);

	if (!fscache_cookie_enabled(cookie) ||
	    hlist_empty(&cookie->backing_objects))
		goto nobufs_unlock;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	__fscache_use_cookie(cookie);
	atomic_inc(&object->n_reads);
	__set_bit(FSCACHE_OP_DEC_READ_CNT, &op->op.flags);

	if (fscache_submit_op(object, &op->op) < 0)
		goto nobufs_unlock_dec;
	spin_unlock(&cookie->lock);

	fscache_stat(&fscache_n_retrieval_ops);

	/* pin the netfs read context in case we need to do the actual netfs
	 * read because we've encountered a cache read failure */
	fscache_get_context(object->cookie, op->context);

	/* we wait for the operation to become active, and then process it
	 * *here*, in this thread, and not in the thread pool */
	ret = fscache_wait_for_operation_activation(
		object, &op->op,
		__fscache_stat(&fscache_n_retrieval_op_waits),
		__fscache_stat(&fscache_n_retrievals_object_dead),
		fscache_do_cancel_retrieval);
	if (ret < 0)
		goto error;

	/* ask the cache to honour the operation */
	if (test_bit(FSCACHE_COOKIE_NO_DATA_YET, &object->cookie->flags)) {
		fscache_stat(&fscache_n_cop_allocate_pages);
		ret = object->cache->ops->allocate_pages(
			op, pages, nr_pages, gfp);
		fscache_stat_d(&fscache_n_cop_allocate_pages);
	} else {
		fscache_stat(&fscache_n_cop_read_or_alloc_pages);
		ret = object->cache->ops->read_or_alloc_pages(
			op, pages, nr_pages, gfp);
		fscache_stat_d(&fscache_n_cop_read_or_alloc_pages);
	}

error:
	if (ret == -ENOMEM)
		fscache_stat(&fscache_n_retrievals_nomem);
	else if (ret == -ERESTARTSYS)
		fscache_stat(&fscache_n_retrievals_intr);
	else if (ret == -ENODATA)
		fscache_stat(&fscache_n_retrievals_nodata);
	else if (ret < 0)
		fscache_stat(&fscache_n_retrievals_nobufs);
	else
		fscache_stat(&fscache_n_retrievals_ok);

	fscache_put_retrieval(op);
	_leave(" = %d", ret);
	return ret;

nobufs_unlock_dec:
	atomic_dec(&object->n_reads);
	wake_cookie = __fscache_unuse_cookie(cookie);
nobufs_unlock:
	spin_unlock(&cookie->lock);
	kfree(op);
	if (wake_cookie)
		__fscache_wake_unused_cookie(cookie);
nobufs:
	fscache_stat(&fscache_n_retrievals_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_read_or_alloc_pages);

/*
 * allocate a block in the cache on which to store a page
 * - we return:
 *   -ENOMEM	- out of memory, nothing done
 *   -ERESTARTSYS - interrupted
 *   -ENOBUFS	- no backing object available in which to cache the block
 *   0		- block allocated
 */
int __fscache_alloc_page(struct fscache_cookie *cookie,
			 struct page *page,
			 gfp_t gfp)
{
	struct fscache_retrieval *op;
	struct fscache_object *object;
	bool wake_cookie = false;
	int ret;

	_enter("%p,%p,,,", cookie, page);

	fscache_stat(&fscache_n_allocs);

	if (hlist_empty(&cookie->backing_objects))
		goto nobufs;

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERTCMP(page, !=, NULL);

	if (test_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags)) {
		_leave(" = -ENOBUFS [invalidating]");
		return -ENOBUFS;
	}

	if (fscache_wait_for_deferred_lookup(cookie) < 0)
		return -ERESTARTSYS;

	op = fscache_alloc_retrieval(cookie, page->mapping, NULL, NULL);
	if (!op)
		return -ENOMEM;
	atomic_set(&op->n_pages, 1);

	spin_lock(&cookie->lock);

	if (!fscache_cookie_enabled(cookie) ||
	    hlist_empty(&cookie->backing_objects))
		goto nobufs_unlock;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	__fscache_use_cookie(cookie);
	if (fscache_submit_op(object, &op->op) < 0)
		goto nobufs_unlock_dec;
	spin_unlock(&cookie->lock);

	fscache_stat(&fscache_n_alloc_ops);

	ret = fscache_wait_for_operation_activation(
		object, &op->op,
		__fscache_stat(&fscache_n_alloc_op_waits),
		__fscache_stat(&fscache_n_allocs_object_dead),
		fscache_do_cancel_retrieval);
	if (ret < 0)
		goto error;

	/* ask the cache to honour the operation */
	fscache_stat(&fscache_n_cop_allocate_page);
	ret = object->cache->ops->allocate_page(op, page, gfp);
	fscache_stat_d(&fscache_n_cop_allocate_page);

error:
	if (ret == -ERESTARTSYS)
		fscache_stat(&fscache_n_allocs_intr);
	else if (ret < 0)
		fscache_stat(&fscache_n_allocs_nobufs);
	else
		fscache_stat(&fscache_n_allocs_ok);

	fscache_put_retrieval(op);
	_leave(" = %d", ret);
	return ret;

nobufs_unlock_dec:
	wake_cookie = __fscache_unuse_cookie(cookie);
nobufs_unlock:
	spin_unlock(&cookie->lock);
	kfree(op);
	if (wake_cookie)
		__fscache_wake_unused_cookie(cookie);
nobufs:
	fscache_stat(&fscache_n_allocs_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;
}
EXPORT_SYMBOL(__fscache_alloc_page);

/*
 * Unmark pages allocate in the readahead code path (via:
 * fscache_readpages_or_alloc) after delegating to the base filesystem
 */
void __fscache_readpages_cancel(struct fscache_cookie *cookie,
				struct list_head *pages)
{
	struct page *page;

	list_for_each_entry(page, pages, lru) {
		if (PageFsCache(page))
			__fscache_uncache_page(cookie, page);
	}
}
EXPORT_SYMBOL(__fscache_readpages_cancel);

/*
 * release a write op reference
 */
static void fscache_release_write_op(struct fscache_operation *_op)
{
	_enter("{OP%x}", _op->debug_id);
}

/*
 * perform the background storage of a page into the cache
 */
static void fscache_write_op(struct fscache_operation *_op)
{
	struct fscache_storage *op =
		container_of(_op, struct fscache_storage, op);
	struct fscache_object *object = op->op.object;
	struct fscache_cookie *cookie;
	struct page *page;
	unsigned n;
	void *results[1];
	int ret;

	_enter("{OP%x,%d}", op->op.debug_id, atomic_read(&op->op.usage));

	spin_lock(&object->lock);
	cookie = object->cookie;

	if (!fscache_object_is_active(object)) {
		/* If we get here, then the on-disk cache object likely longer
		 * exists, so we should just cancel this write operation.
		 */
		spin_unlock(&object->lock);
		fscache_op_complete(&op->op, false);
		_leave(" [inactive]");
		return;
	}

	if (!cookie) {
		/* If we get here, then the cookie belonging to the object was
		 * detached, probably by the cookie being withdrawn due to
		 * memory pressure, which means that the pages we might write
		 * to the cache from no longer exist - therefore, we can just
		 * cancel this write operation.
		 */
		spin_unlock(&object->lock);
		fscache_op_complete(&op->op, false);
		_leave(" [cancel] op{f=%lx s=%u} obj{s=%s f=%lx}",
		       _op->flags, _op->state, object->state->short_name,
		       object->flags);
		return;
	}

	spin_lock(&cookie->stores_lock);

	fscache_stat(&fscache_n_store_calls);

	/* find a page to store */
	page = NULL;
	n = radix_tree_gang_lookup_tag(&cookie->stores, results, 0, 1,
				       FSCACHE_COOKIE_PENDING_TAG);
	if (n != 1)
		goto superseded;
	page = results[0];
	_debug("gang %d [%lx]", n, page->index);
	if (page->index > op->store_limit) {
		fscache_stat(&fscache_n_store_pages_over_limit);
		goto superseded;
	}

	radix_tree_tag_set(&cookie->stores, page->index,
			   FSCACHE_COOKIE_STORING_TAG);
	radix_tree_tag_clear(&cookie->stores, page->index,
			     FSCACHE_COOKIE_PENDING_TAG);

	spin_unlock(&cookie->stores_lock);
	spin_unlock(&object->lock);

	fscache_stat(&fscache_n_store_pages);
	fscache_stat(&fscache_n_cop_write_page);
	ret = object->cache->ops->write_page(op, page);
	fscache_stat_d(&fscache_n_cop_write_page);
	fscache_end_page_write(object, page);
	if (ret < 0) {
		fscache_abort_object(object);
		fscache_op_complete(&op->op, true);
	} else {
		fscache_enqueue_operation(&op->op);
	}

	_leave("");
	return;

superseded:
	/* this writer is going away and there aren't any more things to
	 * write */
	_debug("cease");
	spin_unlock(&cookie->stores_lock);
	clear_bit(FSCACHE_OBJECT_PENDING_WRITE, &object->flags);
	spin_unlock(&object->lock);
	fscache_op_complete(&op->op, true);
	_leave("");
}

/*
 * Clear the pages pending writing for invalidation
 */
void fscache_invalidate_writes(struct fscache_cookie *cookie)
{
	struct page *page;
	void *results[16];
	int n, i;

	_enter("");

	for (;;) {
		spin_lock(&cookie->stores_lock);
		n = radix_tree_gang_lookup_tag(&cookie->stores, results, 0,
					       ARRAY_SIZE(results),
					       FSCACHE_COOKIE_PENDING_TAG);
		if (n == 0) {
			spin_unlock(&cookie->stores_lock);
			break;
		}

		for (i = n - 1; i >= 0; i--) {
			page = results[i];
			radix_tree_delete(&cookie->stores, page->index);
		}

		spin_unlock(&cookie->stores_lock);

		for (i = n - 1; i >= 0; i--)
			page_cache_release(results[i]);
	}

	_leave("");
}

/*
 * request a page be stored in the cache
 * - returns:
 *   -ENOMEM	- out of memory, nothing done
 *   -ENOBUFS	- no backing object available in which to cache the page
 *   0		- dispatched a write - it'll call end_io_func() when finished
 *
 * if the cookie still has a backing object at this point, that object can be
 * in one of a few states with respect to storage processing:
 *
 *  (1) negative lookup, object not yet created (FSCACHE_COOKIE_CREATING is
 *      set)
 *
 *	(a) no writes yet
 *
 *	(b) writes deferred till post-creation (mark page for writing and
 *	    return immediately)
 *
 *  (2) negative lookup, object created, initial fill being made from netfs
 *
 *	(a) fill point not yet reached this page (mark page for writing and
 *          return)
 *
 *	(b) fill point passed this page (queue op to store this page)
 *
 *  (3) object extant (queue op to store this page)
 *
 * any other state is invalid
 */
int __fscache_write_page(struct fscache_cookie *cookie,
			 struct page *page,
			 gfp_t gfp)
{
	struct fscache_storage *op;
	struct fscache_object *object;
	bool wake_cookie = false;
	int ret;

	_enter("%p,%x,", cookie, (u32) page->flags);

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERT(PageFsCache(page));

	fscache_stat(&fscache_n_stores);

	if (test_bit(FSCACHE_COOKIE_INVALIDATING, &cookie->flags)) {
		_leave(" = -ENOBUFS [invalidating]");
		return -ENOBUFS;
	}

	op = kzalloc(sizeof(*op), GFP_NOIO | __GFP_NOMEMALLOC | __GFP_NORETRY);
	if (!op)
		goto nomem;

	fscache_operation_init(&op->op, fscache_write_op,
			       fscache_release_write_op);
	op->op.flags = FSCACHE_OP_ASYNC |
		(1 << FSCACHE_OP_WAITING) |
		(1 << FSCACHE_OP_UNUSE_COOKIE);

	ret = radix_tree_maybe_preload(gfp & ~__GFP_HIGHMEM);
	if (ret < 0)
		goto nomem_free;

	ret = -ENOBUFS;
	spin_lock(&cookie->lock);

	if (!fscache_cookie_enabled(cookie) ||
	    hlist_empty(&cookie->backing_objects))
		goto nobufs;
	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);
	if (test_bit(FSCACHE_IOERROR, &object->cache->flags))
		goto nobufs;

	/* add the page to the pending-storage radix tree on the backing
	 * object */
	spin_lock(&object->lock);
	spin_lock(&cookie->stores_lock);

	_debug("store limit %llx", (unsigned long long) object->store_limit);

	ret = radix_tree_insert(&cookie->stores, page->index, page);
	if (ret < 0) {
		if (ret == -EEXIST)
			goto already_queued;
		_debug("insert failed %d", ret);
		goto nobufs_unlock_obj;
	}

	radix_tree_tag_set(&cookie->stores, page->index,
			   FSCACHE_COOKIE_PENDING_TAG);
	page_cache_get(page);

	/* we only want one writer at a time, but we do need to queue new
	 * writers after exclusive ops */
	if (test_and_set_bit(FSCACHE_OBJECT_PENDING_WRITE, &object->flags))
		goto already_pending;

	spin_unlock(&cookie->stores_lock);
	spin_unlock(&object->lock);

	op->op.debug_id	= atomic_inc_return(&fscache_op_debug_id);
	op->store_limit = object->store_limit;

	__fscache_use_cookie(cookie);
	if (fscache_submit_op(object, &op->op) < 0)
		goto submit_failed;

	spin_unlock(&cookie->lock);
	radix_tree_preload_end();
	fscache_stat(&fscache_n_store_ops);
	fscache_stat(&fscache_n_stores_ok);

	/* the work queue now carries its own ref on the object */
	fscache_put_operation(&op->op);
	_leave(" = 0");
	return 0;

already_queued:
	fscache_stat(&fscache_n_stores_again);
already_pending:
	spin_unlock(&cookie->stores_lock);
	spin_unlock(&object->lock);
	spin_unlock(&cookie->lock);
	radix_tree_preload_end();
	kfree(op);
	fscache_stat(&fscache_n_stores_ok);
	_leave(" = 0");
	return 0;

submit_failed:
	spin_lock(&cookie->stores_lock);
	radix_tree_delete(&cookie->stores, page->index);
	spin_unlock(&cookie->stores_lock);
	wake_cookie = __fscache_unuse_cookie(cookie);
	page_cache_release(page);
	ret = -ENOBUFS;
	goto nobufs;

nobufs_unlock_obj:
	spin_unlock(&cookie->stores_lock);
	spin_unlock(&object->lock);
nobufs:
	spin_unlock(&cookie->lock);
	radix_tree_preload_end();
	kfree(op);
	if (wake_cookie)
		__fscache_wake_unused_cookie(cookie);
	fscache_stat(&fscache_n_stores_nobufs);
	_leave(" = -ENOBUFS");
	return -ENOBUFS;

nomem_free:
	kfree(op);
nomem:
	fscache_stat(&fscache_n_stores_oom);
	_leave(" = -ENOMEM");
	return -ENOMEM;
}
EXPORT_SYMBOL(__fscache_write_page);

/*
 * remove a page from the cache
 */
void __fscache_uncache_page(struct fscache_cookie *cookie, struct page *page)
{
	struct fscache_object *object;

	_enter(",%p", page);

	ASSERTCMP(cookie->def->type, !=, FSCACHE_COOKIE_TYPE_INDEX);
	ASSERTCMP(page, !=, NULL);

	fscache_stat(&fscache_n_uncaches);

	/* cache withdrawal may beat us to it */
	if (!PageFsCache(page))
		goto done;

	/* get the object */
	spin_lock(&cookie->lock);

	if (hlist_empty(&cookie->backing_objects)) {
		ClearPageFsCache(page);
		goto done_unlock;
	}

	object = hlist_entry(cookie->backing_objects.first,
			     struct fscache_object, cookie_link);

	/* there might now be stuff on disk we could read */
	clear_bit(FSCACHE_COOKIE_NO_DATA_YET, &cookie->flags);

	/* only invoke the cache backend if we managed to mark the page
	 * uncached here; this deals with synchronisation vs withdrawal */
	if (TestClearPageFsCache(page) &&
	    object->cache->ops->uncache_page) {
		/* the cache backend releases the cookie lock */
		fscache_stat(&fscache_n_cop_uncache_page);
		object->cache->ops->uncache_page(object, page);
		fscache_stat_d(&fscache_n_cop_uncache_page);
		goto done;
	}

done_unlock:
	spin_unlock(&cookie->lock);
done:
	_leave("");
}
EXPORT_SYMBOL(__fscache_uncache_page);

/**
 * fscache_mark_page_cached - Mark a page as being cached
 * @op: The retrieval op pages are being marked for
 * @page: The page to be marked
 *
 * Mark a netfs page as being cached.  After this is called, the netfs
 * must call fscache_uncache_page() to remove the mark.
 */
void fscache_mark_page_cached(struct fscache_retrieval *op, struct page *page)
{
	struct fscache_cookie *cookie = op->op.object->cookie;

#ifdef CONFIG_FSCACHE_STATS
	atomic_inc(&fscache_n_marks);
#endif

	_debug("- mark %p{%lx}", page, page->index);
	if (TestSetPageFsCache(page)) {
		static bool once_only;
		if (!once_only) {
			once_only = true;
			pr_warn("Cookie type %s marked page %lx multiple times\n",
				cookie->def->name, page->index);
		}
	}

	if (cookie->def->mark_page_cached)
		cookie->def->mark_page_cached(cookie->netfs_data,
					      op->mapping, page);
}
EXPORT_SYMBOL(fscache_mark_page_cached);

/**
 * fscache_mark_pages_cached - Mark pages as being cached
 * @op: The retrieval op pages are being marked for
 * @pagevec: The pages to be marked
 *
 * Mark a bunch of netfs pages as being cached.  After this is called,
 * the netfs must call fscache_uncache_page() to remove the mark.
 */
void fscache_mark_pages_cached(struct fscache_retrieval *op,
			       struct pagevec *pagevec)
{
	unsigned long loop;

	for (loop = 0; loop < pagevec->nr; loop++)
		fscache_mark_page_cached(op, pagevec->pages[loop]);

	pagevec_reinit(pagevec);
}
EXPORT_SYMBOL(fscache_mark_pages_cached);

/*
 * Uncache all the pages in an inode that are marked PG_fscache, assuming them
 * to be associated with the given cookie.
 */
void __fscache_uncache_all_inode_pages(struct fscache_cookie *cookie,
				       struct inode *inode)
{
	struct address_space *mapping = inode->i_mapping;
	struct pagevec pvec;
	pgoff_t next;
	int i;

	_enter("%p,%p", cookie, inode);

	if (!mapping || mapping->nrpages == 0) {
		_leave(" [no pages]");
		return;
	}

	pagevec_init(&pvec, 0);
	next = 0;
	do {
		if (!pagevec_lookup(&pvec, mapping, next, PAGEVEC_SIZE))
			break;
		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			next = page->index;
			if (PageFsCache(page)) {
				__fscache_wait_on_page_write(cookie, page);
				__fscache_uncache_page(cookie, page);
			}
		}
		pagevec_release(&pvec);
		cond_resched();
	} while (++next);

	_leave("");
}
EXPORT_SYMBOL(__fscache_uncache_all_inode_pages);
/************************************************************/
/* ../linux-3.17/fs/fscache/proc.c */
/************************************************************/
/* FS-Cache statistics viewing interface
 *
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#define FSCACHE_DEBUG_LEVEL OPERATION
// #include <linux/module.h>
#include <linux/proc_fs.h>
// #include <linux/seq_file.h>
// #include "internal.h"

/*
 * initialise the /proc/fs/fscache/ directory
 */
int __init fscache_proc_init(void)
{
	_enter("");

	if (!proc_mkdir("fs/fscache", NULL))
		goto error_dir;

#ifdef CONFIG_FSCACHE_STATS
	if (!proc_create("fs/fscache/stats", S_IFREG | 0444, NULL,
			 &fscache_stats_fops))
		goto error_stats;
#endif

#ifdef CONFIG_FSCACHE_HISTOGRAM
	if (!proc_create("fs/fscache/histogram", S_IFREG | 0444, NULL,
			 &fscache_histogram_fops))
		goto error_histogram;
#endif

#ifdef CONFIG_FSCACHE_OBJECT_LIST
	if (!proc_create("fs/fscache/objects", S_IFREG | 0444, NULL,
			 &fscache_objlist_fops))
		goto error_objects;
#endif

	_leave(" = 0");
	return 0;

#ifdef CONFIG_FSCACHE_OBJECT_LIST
error_objects:
#endif
#ifdef CONFIG_FSCACHE_HISTOGRAM
	remove_proc_entry("fs/fscache/histogram", NULL);
error_histogram:
#endif
#ifdef CONFIG_FSCACHE_STATS
	remove_proc_entry("fs/fscache/stats", NULL);
error_stats:
#endif
	remove_proc_entry("fs/fscache", NULL);
error_dir:
	_leave(" = -ENOMEM");
	return -ENOMEM;
}

/*
 * clean up the /proc/fs/fscache/ directory
 */
void fscache_proc_cleanup(void)
{
#ifdef CONFIG_FSCACHE_OBJECT_LIST
	remove_proc_entry("fs/fscache/objects", NULL);
#endif
#ifdef CONFIG_FSCACHE_HISTOGRAM
	remove_proc_entry("fs/fscache/histogram", NULL);
#endif
#ifdef CONFIG_FSCACHE_STATS
	remove_proc_entry("fs/fscache/stats", NULL);
#endif
	remove_proc_entry("fs/fscache", NULL);
}
