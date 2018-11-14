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
	/* frame table(list)에 넣어야 함 */
	list_push_back(&frame_table, &new_frame->elem);
	return;
}
/* frame victim 선정 */
bool
frame_victim(void)
{
	/* frame victim 선정하긔 */
	struct frame *victim;
	/* TO DO : victim 선정 알고리즘 -- 문서 읽어보자...*/
	return false;
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
	} else {  /* 실패한 경우, victim 선정해야 함 */
		/* victim 선정 */
		bool success = frame_victim();
		if(!success)
		{
			// victim 선정을 실패할 경우 --> 패닉;
			PANIC ("VM / FRAME : [FAIL] Couldn't select the victim frame...");
		} 
		/* 다시 page 할당 */
		/* page frame mapping table 구성 */
		frame = palloc_get_page(flags);
		frame_set_elem(frame);
		return frame;
	}
}

void
frame_delete_elem(void *frame)
{
	struct list_elem *e;
	for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
	{
		struct frame *tmp_frame = list_entry(e, struct frame, elem);
		if(tmp_frame->page == frame)
		{
			list_remove(e);
			free(tmp_frame);
			palloc_free_page(tmp_frame->page);
			break;
		}
	}
}

/* frame table에서 frame 해제 */
/* free page --> frame_free */
void
frame_free(void *frame)
{
	/* frame table에서 삭제, palloc시켜주기 */
	frame_delete_elem(frame);
}