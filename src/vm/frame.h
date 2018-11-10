#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"

#include <list.h>


struct list frame_table;
struct lock frame_manager;

struct frame_elem {
	struct thread *frame_owner;
	void *page;
	struct list_elem elem;
};

void frame_init(void);
void frame_set_elem(void *frame);
void * frame_alloc(enum palloc_flags flags);
bool frame_victim(void);
void frame_delete_elem(void *frame);
void frame_free(void *frame);

#endif /* vm/frame.h */