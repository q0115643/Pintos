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
frame_set_elem(void *frame)
{
	/* page frame mapping table 구성 */
	/* frame elem 구성 */
	struct frame *new_frame = malloc(sizeof(struct frame));
	new_frame->page = frame;
	new_frame->frame_owner = thread_current();
	new_frame->alloc_page = NULL;
	/* frame table(list)에 넣어야 함 */
	list_push_back(&frame_table, &new_frame->elem);
	return;
}

/* find */
struct frame *
frame_get_from_addr(void *addr)
{
	struct list_elem *e;
	for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
	{
		struct frame *tmp_frame = list_entry(e, struct frame, elem);
		if(tmp_frame->page == addr)
		{
			return tmp_frame;
		}
	}
	return NULL;
}

struct frame *
frame_select_victim(enum palloc_flags flags)
{
	printf("[frame_select_victim] : victim 선정 시작 \n");
	struct list_elem *e;
	struct frame *frame;
	struct page *page;

	/* Second chance algorithm. */
	e = list_begin (&frame_table);
	while(true)
	{
		printf("[frame_select_victim] : while문 입성 \n");
		frame = list_entry (e, struct frame, elem);
		page = frame->alloc_page;
		printf("[frame_select_victim] : while문 입성2 \n");
		//frame_acquire();
		if (pagedir_is_accessed (frame->frame_owner->pagedir, page->upage))
		{
			printf("[frame_select_victim] : access 입성 \n");
			pagedir_set_accessed (frame->frame_owner->pagedir, page->upage, false);
			printf("[frame_select_victim] : set access 완료 \n");

		} else {
			printf("[frame_select_victim] : else문 입성 \n");
			if (pagedir_is_dirty (frame->frame_owner->pagedir, page->upage))
			{
				printf("[frame_select_victim] : victim 선정 완료! \n");
				return frame;
			}
			printf("흠.. \n");
		}

		e = list_next (e);
      	if(e == list_end(&frame_table)) e = list_begin(&frame_table);
      	//frame_release();

	}
	printf("[frame_select_victim] : victim 선정 실패! \n");
	return NULL;
}

/* frame victim 선정 */
bool
frame_evict(enum palloc_flags flags)
{
	printf("[frame_evict] : evict 시작 \n");
	/* frame victim 선정하긔 */
	struct frame *victim;
	/* TO DO : victim 선정 알고리즘 -- 문서 읽어보자...*/
	//frame_acquire();
	victim = frame_select_victim(flags);
	//frame_release();

	printf("[frame_evict] : victim 선정 완료 \n");
	if(victim == NULL) return false;
	size_t table_index = swap_out(victim->page);
	if(table_index == -1)
		printf("[frame_evict] : swap_out 실패!! \n");
	list_remove(&victim->elem);
	palloc_free_page(victim->page);
	free(victim);

#ifdef DEBUG
	printf("[frame_evict] : victim 선정 후 free 성공 \n");
#endif

	/* victim frame에 연결된 page 상태 변경!! */
	/* victim frame에 연결된 page 상태를 swap out되어 있다고 말해줘야 해 */
	struct page *alloc_page = victim->alloc_page;
	alloc_page->loaded = false;
	alloc_page->swaped = true;
	alloc_page->swap_index = table_index;

	return true;
}

void *
frame_victim(enum palloc_flags flags)
{
	printf("[frame_victim] : 입장! \n");
	struct frame *frame = NULL;
	struct page *page;
	struct thread *owner;

	/* Second chance algorithm. */
	struct list_elem *e;
	e = list_begin (&frame_table);
	printf("[frame_victim] : while 입장 전! \n");
	while(true)
	{
		printf("[frame_victim] : while 입장! \n");
		frame = list_entry(e, struct frame, elem);
		owner = frame->frame_owner;
		page = frame->alloc_page;

		printf("[frame_victim] : if 문 입장 전! \n");
		if (pagedir_is_accessed (owner->pagedir, page->upage))
		{
			printf("[frame_victim] : pagedir_is_accessed 문 입장! \n");
			pagedir_set_accessed (owner->pagedir, page->upage, false);

		} else {
			
			printf("[frame_victim] : else 문 입장! \n");
			if (pagedir_is_dirty (owner->pagedir, page->upage))
			{
	      	/*
	          if (page->mapid != MAP_FAILED)
	            {
	              filesys_acquire ();
	              file_write_at (page->file, page->addr, page->file_read_bytes,
	                             page->file_ofs);
	              filesys_release ();
	              page->loaded = false;
	            }*/
	          //else
	          //  {
				page->swaped = true;
				page->swap_index = swap_out(frame->page);
				page->loaded = false;

	          //  }
			} else { 

				page->loaded = false;

			}

			list_remove (e);
			pagedir_clear_page (owner->pagedir, page->upage);
			palloc_free_page(frame->page);
			free(frame);
			return palloc_get_page (PAL_USER | flags);

	    }

	    e = list_next (e);
	    if (e == list_end (&frame_table)) e = list_begin (&frame_table);

	}
	printf("[frame_victim] : 퇴장! \n");
}

/* frame table 생성을 위함 */
/* palloc_get_page --> frame_alloc으로 바꿔줘야 함 */
void *
frame_alloc(enum palloc_flags flags)
{
	if(!(flags & PAL_USER))
	{
		printf("VM/ FRAME : NOT USER POOL!!\n");
		return NULL;
	}
	void *frame = palloc_get_page(flags);
	/* page 할당 성공한 경우, */
	if(frame != NULL)
	{
		/* page frame mapping table 구성 */
		frame_set_elem(frame);
		return frame;
	}
	else
	{ /* 실패한 경우, victim 선정해야 함 */
		/* victim 선정 */
		frame = frame_victim(flags);
		frame_set_elem(frame);
		if(!frame)
		{
			// victim 선정을 실패할 경우 --> 패닉;
			PANIC ("VM / FRAME : [FAIL] Couldn't select the victim frame...");
		}

#ifdef DEBUG
		printf("[frame_alloc] : frame_evict 성공 \n");
#endif
		/* 다시 page 할당 */
		/* page frame mapping table 구성 */
		//frame = palloc_get_page(flags);
		//frame_set_elem(frame);
		return frame;

	}

}

void
frame_free(void *frame)
{
	struct list_elem *e;
	for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
	{
		struct frame *tmp_frame = list_entry(e, struct frame, elem);
		if(tmp_frame->page == frame)
		{
			list_remove(e);
			palloc_free_page(tmp_frame->page);
			free(tmp_frame);
			break;
		}
	}
}