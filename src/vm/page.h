#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <hash.h>
#include <list.h>
#include <user/syscall.h>
#include "filesys/file.h"
#include "filesys/off_t.h"

struct page
{
	void *upage;	/* Virtual address */
	struct hash_elem hash_elem;	/* Hash element */
	struct list_elem list_elem;
	struct thread *page_owner;
	struct file *file;
	off_t offset;
	size_t read_bytes;
	size_t zero_bytes;
	bool writable;
	bool loaded;
	bool swaped;
	bool mmaped;
	int mapid;
	size_t swap_index;
	
};

void ptable_init(struct hash *ptable);
struct page* page_create(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
bool ptable_insert(struct page *page);
struct page* ptable_lookup(void* addr);
bool page_load_file(struct page *page);
void ptable_clear(void);
#endif /* vm/page.h */