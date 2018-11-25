#include "vm/swap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/disk.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

void 
swap_acquire(void)
{
	lock_acquire(&swap_table_lock);
}

void
swap_release(void)
{
	lock_release(&swap_table_lock);
}

/* swap table init */
void 
swap_init(void)
{
	struct disk *disk = disk_get(1, 1);
	list_init(&swap_table);
	lock_init(&swap_table_lock);
	int i;
	for(i = 0; i < (disk_size(disk) * DISK_SECTOR_SIZE / PGSIZE); i++)
	{
		struct swap *swap_space  = malloc(sizeof(struct swap));
		swap_space->is_empty = true;
		swap_space->table_index = i + 1;
		if(swap_space == NULL) return;
		list_push_back(&swap_table, &swap_space->elem);
	}
	return;
}


size_t
swap_out(void *frame_addr)
{
	swap_init();
	struct disk *disk_block = disk_get(1, 1);
	size_t table_index;
	swap_acquire();
	struct list_elem *e;
	for(e = list_begin(&swap_table); e != list_end(&swap_table); e = list_next(e))
	{
		struct swap *swap_elem = list_entry(e, struct swap, elem);
		if(swap_elem->is_empty)
		{
			swap_elem->is_empty = false;
			table_index = swap_elem->table_index;
			break;
		}
	}
	if(table_index == NULL || table_index == list_size(&swap_table))
	{
		swap_release();
		printf("SWAP FULL!!!!\n");
		return -1;
	}
	disk_sector_t disk_sector;
	for(disk_sector = 0; disk_sector < (PGSIZE / DISK_SECTOR_SIZE); disk_sector++)
	{
		disk_write(disk_block, table_index * (PGSIZE / DISK_SECTOR_SIZE) + disk_sector, frame_addr + disk_sector * DISK_SECTOR_SIZE);
	}
	swap_release();
	return table_index;
}

struct swap *
swap_get_from_index(size_t swap_index)
{
	if(list_empty(&swap_table))
	{
		return NULL;
	}
	struct list_elem *e;
	struct list_elem *next;
	for(e = list_begin(&swap_table); e != list_end(&swap_table);)
	{
		next = list_next(e);
		struct swap *tmp_swap = list_entry(e, struct swap, elem);
		if(tmp_swap->table_index == swap_index)
			return tmp_swap;
		e = next;
	}
	return NULL;
}

void 
swap_in(struct page *page, void *addr)
{
	struct disk *disk_block = disk_get(1, 1);
	swap_acquire();
	struct swap *swap_elem = swap_get_from_index(page->swap_index);
	if (!swap_elem || swap_elem->is_empty)
	{
		swap_release();
		return;
	}
	swap_elem->is_empty = true;
	disk_sector_t disk_sector;
	for (disk_sector = 0; disk_sector < (PGSIZE / DISK_SECTOR_SIZE); disk_sector++) 
	{
		disk_read(disk_block, page->swap_index * PGSIZE / DISK_SECTOR_SIZE + disk_sector, addr + disk_sector * DISK_SECTOR_SIZE);
	}
	swap_release();
}
