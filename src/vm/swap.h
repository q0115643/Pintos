#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <list.h>
#include <stdbool.h>
#include <stdint.h>
#include "vm/page.h"

struct list swap_table;
struct lock swap_table_lock;

static bool swap_init_check = false;

struct swap
{
	struct list_elem elem;
	bool is_empty;
	size_t table_index;
};

void swap_acquire(void);
void swap_release(void);
void swap_init(void);
size_t swap_out(void *upage);
struct swap * swap_get_from_index(size_t swap_index);
void swap_in(struct page *page, void *addr);

#endif /* vm/swap.h */