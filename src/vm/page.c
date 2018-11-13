#include "threads/thread.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "userprog/process.h"

#define DEBUG

void
page_table_init(void)
{
	struct thread *t = thread_current();
	list_init(&t->page_table);
	lock_init(&t->page_table_lock);
}


void
page_table_clear(void)
{
	struct list *page_table = &thread_current()->page_table;

	struct list_elem *e;
	for (e = list_begin(page_table); e != list_end(page_table); e = list_next(e))
	{
		struct page_elem *page = list_entry(e, struct page_elem, elem);
		frame_free(pagedir_get_page(thread_current()->pagedir, page->addr));
		pagedir_clear_page(thread_current()->pagedir, page->addr);

	}
}

bool
page_create(struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
	struct page_elem *page = malloc(sizeof(struct page_elem));
    if(page == NULL) return false;
    //printf("LOAD HERE!!!!");

	page->page_owner = thread_current();
	page->file = file;
	page->offset = ofs;
	page->addr = upage;
	page->read_bytes = read_bytes;
	page->zero_bytes = zero_bytes;
	page->writable = writable;
	page->check_loaded = false;
	page->state = PAGE_FILE;

	struct list *page_table = &thread_current()->page_table;
	struct lock *page_table_lock = &thread_current()->page_table_lock;

	lock_acquire(page_table_lock);
	list_push_back(page_table, &page->elem);
	lock_release(page_table_lock);

	return true;

}

struct page_elem* 
page_get_elem_from_addr(void *addr)
{
	struct thread *t = thread_current();
	struct list *page_table = &t->page_table;
	struct list_elem *e;
	addr = pg_round_down(addr);
	for(e = list_begin(page_table); e != list_end(page_table); e = list_next(e))
	{
		struct page_elem *tmp_page = list_entry(e, struct page_elem, elem);
		if(tmp_page->addr == addr)
		{
			return tmp_page;
		}
	}

	return NULL;

}

bool
page_load_file(struct page_elem *page)
{
	uint8_t *frame = frame_alloc(PAL_USER);
	if(frame == NULL) return false;
	if(page->read_bytes == 0) return false;

	file_seek(page->file, page->offset);
	if(file_read_at(page->file, frame, page->read_bytes, page->offset) != page->read_bytes)
	{
		frame_free(frame);
		return false;
	}

	memset(frame + page->read_bytes, 0, page->zero_bytes);
	if(!install_page(page->addr, frame, page->writable))
	{
		frame_free(frame);
		return false;
	}

	page->check_loaded = true;
	return true;

}

bool
page_load_swap(struct page_elem *page)
{
	return false;
}



bool
page_fault_handler(struct page_elem * page)
{
#ifdef DEBUG
	printf("[page fault handler]\n");
#endif

	bool success = false;
	if(page->state == 0)
	{
		success = page_load_file(page);
		return success;
	}
	else if(page->state == 1)
	{
		success = page_load_swap(page);
		return success;

	} else {

		return success;
	}
	frame_lock_release();
	return false;

}


