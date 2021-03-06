#include "vm/page.h"
#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <hash.h>
#include <user/syscall.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"
#include "vm/page.h"
#include "userprog/process.h"

//#define DEBUG

static void
page_destroy_function (struct hash_elem *e, void *aux UNUSED);

/* page 구조체에서 upage를 이용하여 hashing */
unsigned
ptable_hash (const struct hash_elem *p_, void *aux UNUSED)
{
  const struct page *p = hash_entry(p_, struct page, hash_elem);
  return hash_bytes (&p->upage, sizeof p->upage); // hash_bytes: Returns a hash of the size bytes starting at buf
}

/* less 함수는 upage 주소를 비교 */
bool
ptable_less (const struct hash_elem *a_, const struct hash_elem *b_,
           void *aux UNUSED)
{
  const struct page *a = hash_entry(a_, struct page, hash_elem);
  const struct page *b = hash_entry(b_, struct page, hash_elem);

  return a->upage < b->upage;
}

void
ptable_init(struct hash *ptable)
{
	if(!hash_init(ptable, ptable_hash, ptable_less, NULL)) system_exit(-1);
}

struct page *
page_create(struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, bool writable)
{
	struct page *page = malloc(sizeof(struct page));
	if(!page) return NULL;
	page->file = file;
	page->offset = ofs;
	page->upage = upage;
	page->read_bytes = read_bytes;
	page->writable = writable;
	page->loaded = false;
	page->swaped = false;
	page->mmaped = false;
	page->mapid = -1;
	page->busy = false;
	return page;
}

bool
ptable_insert(struct page *page)
{
	if(!hash_insert(&thread_current()->page_table, &page->hash_elem))
	{
    return true;
	}
  return false;
}

struct page*
ptable_lookup(void* addr)
{
	void* rounded_addr;
	rounded_addr = pg_round_down(addr);
	struct page page;
	struct hash_elem *e;
	page.upage = rounded_addr;
	e = hash_find(&thread_current()->page_table, &page.hash_elem);
	if(e)
		return hash_entry(e, struct page, hash_elem);
	return NULL;
}

bool
page_load_file(struct page *page)
{
	struct thread *cur = thread_current();
	enum palloc_flags flags = PAL_USER;
	if (page->read_bytes == 0)
	{
		flags |= PAL_ZERO;
	}
	uint8_t *kpage = frame_alloc(flags, page); // 여기에 ZERO가 붙으면 다 0로 초기화되서 옴. 무조건.
	if(!kpage) return false;
	if(page->read_bytes > 0)
	{
		filesys_acquire();
		if(file_read_at(page->file, kpage, page->read_bytes, page->offset) != (int) page->read_bytes)
		{
			filesys_release();
			frame_free(kpage);
			return false;
		}
		filesys_release();
    memset(kpage + page->read_bytes, 0, PGSIZE - page->read_bytes);
	}
	if(!install_page(page->upage, kpage, page->writable))
	{
		frame_free(kpage);
		return false;
	}
	page->loaded = true;
	pagedir_set_accessed(cur->pagedir, page->upage, true);
	return true;
}

bool
page_load_zero(struct page *page)
{
  struct thread *t = thread_current();
  void *kpage = frame_alloc(PAL_ZERO, page);
  bool success;
  if (kpage == NULL) return false;
  success = install_page(page->upage, kpage, true);
  if (!success)
  {
  	frame_free (kpage);
  	return false;
  }
  page->loaded = true;
  pagedir_set_accessed(t->pagedir, page->upage, true);
  return true;
}

bool
page_load_swap(struct page *page)
{
	struct thread *cur = thread_current();
	void *kpage = frame_alloc(PAL_USER, page);
	if(!kpage) return false;
	if(!install_page(page->upage, kpage, true))
	{
	  frame_free(kpage);
	  return false;
	}
	swap_in(page, kpage);
	page->swaped = false;
	page->loaded = true;
	pagedir_set_dirty(cur->pagedir, page->upage, true);
  pagedir_set_accessed(cur->pagedir, page->upage, true);
  return true;
}

void
ptable_clear()
{
	struct list *page_table = &thread_current()->page_table;
	hash_destroy(page_table, page_destroy_function);
}

/* destroy & free elements in page table */
static void
page_destroy_function (struct hash_elem *e, void *aux UNUSED)
{
  struct thread *cur = thread_current();
  struct page *page;
  void *kpage;
  page = hash_entry(e, struct page, hash_elem);
  frame_free(pagedir_get_page(cur->pagedir, page->upage));
  pagedir_clear_page(cur->pagedir, page->upage);
  free(page);
}

bool
page_load(struct page *page)
{
  if(page->loaded)
    return false;
  if(page->swaped)
    return page_load_swap(page);
  if(page->file)
    return page_load_file(page);
  else
    return page_load_zero(page);
}

bool
stack_growth(void* fault_addr)
{
  uint8_t *stack_page_addr = pg_round_down(fault_addr);
  while(stack_page_addr < ((uint8_t *) PHYS_BASE) - PGSIZE)
  {
    if(ptable_lookup(stack_page_addr))
    {
      stack_page_addr += PGSIZE;
      continue;
    }
    struct page *s_page = malloc(sizeof(struct page));
    s_page->upage = stack_page_addr;
    s_page->writable = true;
    s_page->loaded = true;
    s_page->file = NULL;
    s_page->swaped = false;
    s_page->mapid = -1;
    s_page->busy = true;
    uint8_t *tmp_kpage = frame_alloc(PAL_USER | PAL_ZERO, s_page);
    if (!tmp_kpage)
    {
      free(s_page);
      return false;
    }
    if(!install_page(stack_page_addr, tmp_kpage, true))
    {
      frame_free(tmp_kpage);
      free(s_page);
      return false;
    }
    if(!ptable_insert(s_page))
    {
      frame_free(tmp_kpage);
      free(s_page);
      return false;
    }
    s_page->busy = false;
    stack_page_addr += PGSIZE;
  }
  return true;
}
