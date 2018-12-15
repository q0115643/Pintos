#include "filesys/cache.h"
#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <list.h>
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

//#define DEBUG

#define CACHE_LIMIT 64	/* limited to a cache no greater than 64 sectors in size */

static struct lock cache_lock;
static struct list cache_list;
static struct list read_ahead_list;
static struct lock read_ahead_lock;
static struct condition read_ahead_cond;

/* private function declarations */
static void cache_write_behind(void);
static void thread_func_write_behind(void);
static void thread_func_read_ahead(void);
static void cache_acquire(void);
static void cache_release(void);
static bool cache_full(void);
static void cache_insert(struct cache* cache);
static void cache_delete(struct cache* cache);
static void cache_evict(void);
static struct cache * cache_create(disk_sector_t sector_idx);
static struct cache * cache_find(disk_sector_t sector_idx);
static struct cache * cache_get(disk_sector_t sector_idx);


void
cache_init(void)
{
	lock_init(&cache_lock);
	list_init(&cache_list);
	cond_init(&read_ahead_cond);
	lock_init(&read_ahead_lock);
	list_init(&read_ahead_list);
	thread_create("write_behind", PRI_DEFAULT, thread_func_write_behind, NULL);
	thread_create("read_ahead", PRI_DEFAULT, thread_func_read_ahead, NULL);
}

void
cache_read(disk_sector_t sector_idx, uint8_t* buffer, int sector_ofs, int chunk_size)
{
#ifdef DEBUG
	printf("cache_read(): 진입\n");
#endif
	struct cache *cache;
	cache_acquire();
	cache = cache_get(sector_idx);
	memcpy(buffer, cache->buffer + sector_ofs, chunk_size);
	cache->accessed = true;
	cache_release();
}

void
cache_write(disk_sector_t sector_idx, uint8_t* buffer, int sector_ofs, int chunk_size)
{
#ifdef DEBUG
	printf("cache_write(): 진입\n");
#endif
	struct cache *cache;
	cache_acquire();
	cache = cache_get(sector_idx);
	memcpy(cache->buffer + sector_ofs, buffer, chunk_size);
	cache->accessed = true;
	cache->dirty = true;
	cache_release();
}

void
cache_clear(void)
{
	struct cache *cache;
	cache_acquire();
	while(!list_empty(&cache_list))
	{
		cache = list_entry(list_pop_front(&cache_list), struct cache, elem);
		cache_delete(cache);
	}
	cache_release();
}

void
cache_read_ahead(disk_sector_t sector_idx)
{
	cache_acquire();
	if(cache_find(sector_idx))
	{
		cache_release();
		return;
	}
	cache_release();
	lock_acquire(&read_ahead_lock);
	struct read_ahead_entry* read_ahead_entry = malloc(sizeof(struct read_ahead_entry));
	read_ahead_entry->sector_idx = sector_idx;
	list_push_back(&read_ahead_list, &read_ahead_entry->elem);
	cond_signal(&read_ahead_cond, &read_ahead_lock);
	lock_release(&read_ahead_lock);
}

static void
cache_delete(struct cache* cache)
{
#ifdef DEBUG
	printf("cache_delete(): 진입\n");
#endif
	if(cache->dirty) disk_write(filesys_disk, cache->sector_idx, cache->buffer);
	free(cache->buffer);
	free(cache);
}

static void
cache_evict(void)
{
#ifdef DEBUG
	printf("cache_evict(): 진입\n");
#endif
	struct cache *cache = NULL;
	struct list_elem *e;
	e = list_begin(&cache_list);
	while(true)
	{
		cache = list_entry(e, struct cache, elem);
		if(cache->accessed) cache->accessed = false;
		else
		{
			list_remove(e);
			cache_delete(cache);
			return;
	  }
	  e = list_next(e);
	  if(e==list_end(&cache_list)) e=list_begin(&cache_list);
	}
}

static struct cache *
cache_create(disk_sector_t sector_idx)
{
#ifdef DEBUG
	printf("cache_create(): 진입\n");
#endif
	struct cache *cache;
	if(cache_full()) cache_evict();
	cache = malloc(sizeof(struct cache));
	cache->sector_idx = sector_idx;
	cache->buffer = malloc(DISK_SECTOR_SIZE);
	disk_read(filesys_disk, sector_idx, cache->buffer);
	cache->accessed = false;
	cache->dirty = false;
	cache_insert(cache);
	return cache;
}

static struct cache *
cache_find(disk_sector_t sector_idx)
{
#ifdef DEBUG
	printf("cache_find(): 진입\n");
#endif
	struct cache *cache;
	struct list_elem *e;
	for(e = list_begin(&cache_list); e != list_end(&cache_list); e = list_next(e))
	{
		cache = list_entry(e, struct cache, elem);
		if(cache->sector_idx == sector_idx)
			return cache;
	}
	return NULL;
}

static struct cache *
cache_get(disk_sector_t sector_idx)
{
#ifdef DEBUG
	printf("cache_get(): 진입\n");
#endif
	struct cache *cache;
	cache = cache_find(sector_idx);
	if(!cache) cache = cache_create(sector_idx);
	return cache;
}

static void
cache_acquire(void)
{
	lock_acquire(&cache_lock);
}

static void
cache_release(void)
{
	lock_release(&cache_lock);
}

static bool
cache_full(void)
{
#ifdef DEBUG
	printf("cache_full(): 진입\n");
#endif
	return list_size(&cache_list)==CACHE_LIMIT;
}

static void
cache_insert(struct cache* cache)
{
	list_push_back(&cache_list, &cache->elem);
}

static void
thread_func_write_behind(void)
{
  while(true)
  {
    timer_sleep(WRITE_BEHIND_DELAY);
    cache_write_behind();
  }
}

static void
cache_write_behind(void)
{
	struct cache *cache;
	struct list_elem *e;
	for(e = list_begin(&cache_list); e != list_end(&cache_list); e = list_next(e))
	{
		cache = list_entry(e, struct cache, elem);
		if(cache->dirty) disk_write(filesys_disk, cache->sector_idx, cache->buffer);
		cache->dirty = false;
	}
}

static void
thread_func_read_ahead(void)
{
  while(true)
  {
		struct read_ahead_entry* read_ahead_entry;
	  lock_acquire(&read_ahead_lock);
	  cond_wait(&read_ahead_cond, &read_ahead_lock);
	  read_ahead_entry = list_entry(list_pop_front(&read_ahead_list), struct read_ahead_entry, elem);
		struct cache *cache;
		cache_acquire();
		cache = cache_get(read_ahead_entry->sector_idx);
		cache_release();
		free(read_ahead_entry);
		lock_release(&read_ahead_lock);
  }
}




