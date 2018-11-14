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
#ifdef DEBUG
	printf("ptable_init(): 진입\n");
#endif
	if(!hash_init(ptable, ptable_hash, ptable_less, NULL)) system_exit(-1);
}

struct page*
page_create(struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
#ifdef DEBUG
	printf("page_create(): 진입\n");
#endif
	struct page *page = malloc(sizeof(struct page));
  page->file = file;
  page->offset = ofs;
  page->upage = upage;
  page->read_bytes = read_bytes;
  page->zero_bytes = zero_bytes;
  page->writable = writable;
  page->loaded = false;
  return page;
}

bool
ptable_insert(struct page *page)
{
#ifdef DEBUG
	printf("ptable_insert(): 진입\n");
#endif
	if(!hash_insert(&thread_current()->page_table, &page->hash_elem))
	{
#ifdef DEBUG
		printf("ptable_insert(): 성공\n");
#endif
    return true;
	}
  return false;
}

struct page*
ptable_lookup(void* addr)
{
#ifdef DEBUG
	printf("ptable_lookup(): 진입\n");
#endif
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
#ifdef DEBUG
	printf("page_load_file(): 진입\n");
#endif
	struct thread *cur = thread_current();
	uint8_t *kpage = frame_alloc(PAL_USER); // 여기에 ZERO가 붙으면 다 0로 초기화되서 옴. 무조건.
	if(!kpage) return false;
	filesys_acquire();
	if(file_read_at(page->file, kpage, page->read_bytes, page->offset) != page->read_bytes)
	{
#ifdef DEBUG
		printf("page_load_file(): file_read_at()이 실패 -> return false******\\n");
#endif
		filesys_release();
		frame_free(kpage);
		return false;
	}
	filesys_release();
	memset(kpage + page->read_bytes, 0, page->zero_bytes);
	if(!install_page(page->upage, kpage, page->writable))
	{
#ifdef DEBUG
		printf("page_load_file(): install_page()이 실패 -> return false******\\n");
#endif
		filesys_acquire();
		frame_free(kpage);
		filesys_release();
		return false;
	}
	page->loaded = true;
	pagedir_set_accessed(cur->pagedir, page->upage, true);
	return true;
}

void
ptable_clear()
{
	struct list *page_table = &thread_current()->page_table;
	hash_destroy (page_table, page_destroy_function);
}

/* destroy & free elements in page table */
static void
page_destroy_function (struct hash_elem *e, void *aux UNUSED)
{
	struct thread *cur = thread_current();
  struct page *page;
  void *kpage;
  page = hash_entry(e, struct page, hash_elem);
  kpage = pagedir_get_page(cur->pagedir, page->upage);
  if (kpage != NULL)
  {
      pagedir_clear_page(cur->pagedir, page->upage);
      frame_free(kpage);
  }
  free(page);
}

