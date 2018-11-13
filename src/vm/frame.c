#include "vm/frame.h"
#include <stdlib.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"


/* frame table manage를 위해, table(list)와 manager(lock) 초기화 */
void
frame_init(void)
{
	lock_init(&frame_manager);
	list_init(&frame_table);
}

/* frame manager(lock) 관련, acquire 및 release */
void
frame_lock_acquire(void)
{
	lock_acquire(&frame_manager);
}

void
frame_lock_release(void)
{
	lock_release(&frame_manager);
}

/* frame table에 새로운 frame 넣기 */
void
frame_set_elem(void *frame)
{
	/* page frame mapping table 구성 */
	/* frame elem 구성 */
	struct frame_elem *new_frame = malloc(sizeof(struct frame_elem));
	new_frame->page = frame;
	new_frame->frame_owner = thread_current();

	/* frame table(list)에 넣어야 함 */
	/* lock 안걸어주면, panic */
	frame_lock_acquire();
	list_push_back(&frame_table, &new_frame->elem);
	frame_lock_release();

	return;

}

/* frame victim 선정 */
bool
frame_victim(void)
{
	/* frame victim 선정하긔 */
	struct frame_elem *victim;
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
	/* lock 안걸어주면, panic */
	frame_lock_acquire();
	for(e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e))
	{
		struct frame_elem *tmp_frame = list_entry(e, struct frame_elem, elem);
		if(tmp_frame->page == frame)
		{
			list_remove(e);
			free(tmp_frame);
			palloc_free_page(tmp_frame->page);
			break;
		}
	}
	frame_lock_release();
}

/* frame table에서 frame 해제 */
/* free page --> frame_free */
void
frame_free(void *frame)
{
	//struct list_elem *frame_elem;

	/* frame table에서 삭제, palloc시켜주기 */
	//lock_acquire(&frame_manager);
	frame_delete_elem(frame);
	//lock_release(&frame_manager);

}