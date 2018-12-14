#include "filesys/cache.h"
#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <list.h>
#include "threads/synch.h"

//#define DEBUG

static struct lock cache_lock;

void
cache_init(void)
{
	lock_init(&cache_lock);
}

void
cache_acquire(void)
{
	lock_acquire(&cache_lock);
}

void
cache_release(void)
{
	lock_release(&cache_lock);
}

