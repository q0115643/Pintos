#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <list.h>
#include <stdbool.h>
#include <stdint.h>
#include "devices/disk.h"
#include "devices/timer.h"

#define WRITE_BEHIND_DELAY 5*TIMER_FREQ

struct cache
{
	struct list_elem elem;
	disk_sector_t sector_idx;
	bool dirty;
	bool accessed;
	uint8_t *buffer;
};

struct read_ahead_entry
{
	struct list_elem elem;
	disk_sector_t sector_idx;
};

void cache_init(void);
void cache_read(disk_sector_t sector_idx, uint8_t* buffer, int sector_ofs, int chunk_size);
void cache_write(disk_sector_t sector_idx, uint8_t* buffer, int sector_ofs, int chunk_size);
void cache_clear(void);
void cache_read_ahead(disk_sector_t sector_idx);

#endif /* filesys/cache.h */
