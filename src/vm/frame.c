#include "vm/frame.h"
#include <stdbool.h>
#include <stddef.h>
#include <list.h>
#include <user/syscall.h>
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/swap.h"

static struct lock frame_lock;

//#define DEBUG

/* frame table manage를 위해, table(list)와 manager(lock) 초기화 */
void
frame_init(void)
{
	lock_init(&frame_lock);
	list_init(&frame_table);
}

/* frame manager(lock) 관련, acquire 및 release */
void
frame_acquire(void)
{
	lock_acquire(&frame_lock);
}

void
frame_release(void)
{
	lock_release(&frame_lock);
}

/* frame table에 새로운 frame 넣기 */
void
frame_set_elem(void *frame, struct page* page)
{
	/* page frame mapping table 구성 */
	/* frame elem 구성 */
	struct frame *new_frame = malloc(sizeof(struct frame));
	new_frame->kpage = frame;
	new_frame->frame_owner = thread_current();
	new_frame->alloc_page = page;
	/* frame table(list)에 넣어야 함 */
	frame_acquire();
	list_push_back(&frame_table, &new_frame->elem);
	frame_release();
	return;
}

void *
frame_victim(enum palloc_flags flags)
{
	frame_acquire();
	struct frame *frame = NULL;
	struct page *page;
	struct thread *owner;
	struct list_elem *e;
	e = list_begin(&frame_table);
// 	while(true)
// 	{
// 		frame = list_entry(e, struct frame, elem);
// 		owner = frame->frame_owner;
// 		page = frame->alloc_page;
// 		if(!page->busy)
// 		{
// 			if(pagedir_is_dirty(owner->pagedir, page->upage) || page->swaped)
// 			{
// 				if (page->mapid != MAP_FAILED)
// 				{
// 					filesys_acquire ();
// 					file_write_at(page->file, page->upage, page->read_bytes, page->offset);
// 					filesys_release ();
// 				}
// 				else
// 				{
// 					page->swaped = true;
// 					page->swap_index = swap_out(frame->kpage);
// 				}
// 			}
// 			page->loaded = false;
// 			list_remove(e);
// 			pagedir_clear_page(owner->pagedir, page->upage);
// 			palloc_free_page(frame->kpage);
// 			free(frame);
// #ifdef DEBUG
// 			printf("frame_victim에서 누구 쫓아내고 return\n");
// #endif
// 			return palloc_get_page(PAL_USER | flags);
// 		}
// 		e = list_next(e);
// 		if(e==list_end(&frame_table)) return NULL;
// 	}
	while(true)
	{
		frame = list_entry(e, struct frame, elem);
		owner = frame->frame_owner;
		page = frame->alloc_page;
		if(!page->busy)
		{
			if(pagedir_is_accessed(owner->pagedir, page->upage))
				pagedir_set_accessed(owner->pagedir, page->upage, false);
			else
			{	
				if(pagedir_is_dirty(owner->pagedir, page->upage))
				{
					if(page->mapid != MAP_FAILED)
	        {
	          filesys_acquire();
	          file_write_at(page->file, page->upage, page->read_bytes, page->offset);
	          filesys_release();
	        }
	        else
	        {
						page->swaped = true;
						page->swap_index = swap_out(frame->kpage);
					}
				}
				page->loaded = false;
				list_remove(e);
				pagedir_clear_page(owner->pagedir, page->upage);
				palloc_free_page(frame->kpage);
				free(frame);
				return palloc_get_page(PAL_USER | flags);
		  }
		}
	  e = list_next(e);
	  if(e==list_end(&frame_table)) e=list_begin(&frame_table);
	}
}

/* frame table 생성을 위함 */
/* palloc_get_page --> frame_alloc으로 바꿔줘야 함 */
void *
frame_alloc(enum palloc_flags flags, struct page* page)
{
	void *frame = palloc_get_page(PAL_USER | flags);
	/* page 할당 성공한 경우, */
	if(frame)
	{
		/* page frame mapping table 구성 */
		frame_set_elem(frame, page);
		return frame;
	}
	else
	{ /* 실패한 경우, victim 선정해야 함 */
		/* victim 선정 */
		while(!frame)
		{
			frame = frame_victim(flags);
			frame_release();
		}
		frame_set_elem(frame, page);
		return frame;
	}
}

void
frame_free(void *frame)
{
	frame_acquire();
	struct list_elem *e;
	for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
	{
		struct frame *tmp_frame = list_entry(e, struct frame, elem);
		if(tmp_frame->kpage == frame)
		{
			list_remove(e);
			palloc_free_page(tmp_frame->kpage);
			free(tmp_frame);
			break;
		}
	}
	frame_release();
}
