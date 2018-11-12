#include "threads/thread.h"
#include "vm/frame.h"
#include "vm/page.h"


void
page_table_init()
{
	struct thread *t = thread_current();
	list_init(&t->page_table);
	lock_init(&t->page_table_lock);
}

static struct page_elem* 
page_get_elem_from_addr(void *addr)
{
	struct thread *t = thread_current();
	struct list *page_table = &t->page_table;
	struct list_elem *e;
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
	return false;

}



bool
page_fault_handler(void * addr)
{
	struct page_elem *page = page_get_elem_from_addr(addr);
	if(page == NULL) return false;

	bool success = false;
	if(page->state == PAGE_FILE)
	{
		success = page_load_file(page);
		return success;
	}

	return false;

}
