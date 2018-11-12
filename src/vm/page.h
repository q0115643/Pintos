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

#define PAGE_FILE 1;


struct page_elem
{
	size_t state;

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

void page_table_init();
bool page_fault_handler(void *addr);
bool page_load_file(struct page_elem *page);
bool page_init(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

