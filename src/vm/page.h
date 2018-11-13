#include "vm/frame.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include <list.h>

#define PAGE_FILE 0;
#define PAGE_SWAP 1;


struct page_elem
{
	size_t state;

	struct thread *page_owner;
	struct list_elem elem;
	void * addr;

	/* Project 3-1, file */
	struct file * file;
	off_t offset;
  	size_t read_bytes;
  	size_t zero_bytes;

  	bool writable;
  	bool check_loaded;


};

void page_table_init(void);
void page_table_clear(void);
bool page_create(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);
bool page_fault_handler(struct page_elem * page);
struct page_elem* page_get_elem_from_addr(void *addr);
bool page_load_file(struct page_elem *page);
bool page_load_swap(struct page_elem *page);
bool page_init(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

