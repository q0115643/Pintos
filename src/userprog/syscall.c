#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "vm/page.h"

void free(void *ptr);
void *malloc(size_t);

static void syscall_handler (struct intr_frame *);
static void system_halt(void);
static pid_t system_exec(const char* cmd_line);
static int system_wait(pid_t pid);
static bool system_create(const char* file, unsigned initial_size);
static bool system_remove(const char* file);
static int system_open(const char* file);
static int system_filesize(int fd);
static int system_read(int fd, void* buffer, unsigned size);
static int system_write(int fd, const void* buffer, unsigned size);
static void system_seek(int fd, unsigned position);
static unsigned system_tell(int fd);
static void system_close(int fd);
static int system_mmap (int fd, void *addr);
static void system_munmap (int mapid);

//#define DEBUG

static int add_thread_file_descriptor(struct file *file);
static struct file * get_file_from_fd(int fd);
static void remove_file(int fd);

static struct lock file_lock;

void
filesys_acquire(void)
{
	lock_acquire(&file_lock);
}
void
filesys_release(void)
{
	lock_release(&file_lock);
}

static inline void
get_arguments(int32_t* esp, int32_t* args, unsigned int argc)
{
	while(argc--)
	{
		if(!is_user_vaddr((void *)esp)) system_exit(-1);
  	*(args++) = *(++esp);
	}
	if(!is_user_vaddr((void *)esp)) system_exit(-1);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int32_t args[3];
  unsigned int argc;
  if(!is_user_vaddr(f->esp)) system_exit(-1);
#ifdef VM
  thread_current()->esp = f->esp;
#endif
  switch(*(int*)f->esp)
  {
  	case SYS_HALT:
  	{
  		system_halt();
  		break;
  	}
  	case SYS_EXIT:
  	{		
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		system_exit(args[0]);
  		break;
  	}
  	case SYS_EXEC:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_exec((const char *)args[0]);
  		break;
  	}
  	case SYS_WAIT:
  	{		
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_wait((pid_t)args[0]);
  		break;
  	}
  	case SYS_CREATE:
  	{
  		argc = 2;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_create((const char*)args[0], (unsigned)args[1]);
  		break;
  	}
  	case SYS_REMOVE:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_remove((const char*)args[0]);
  		break;
  	}
  	case SYS_OPEN:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_open((const char*)args[0]);
  		break;
  	}
  	case SYS_FILESIZE:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
      f->eax = system_filesize((int)args[0]);
      break;
  	}
  	case SYS_READ:
  	{
  		argc = 3;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_read((int)args[0], (void*)args[1], (unsigned)args[2]);
  		break;
  	}
  	case SYS_WRITE:
  	{
  		argc = 3;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_write((int)args[0], (const void*)args[1], (unsigned)args[2]);
  		break;
  	}
  	case SYS_SEEK:
  	{
  		argc = 2;
  		get_arguments(f->esp, args, argc);
  		system_seek((int)args[0], (unsigned)args[1]);
  		break;
  	}
  	case SYS_TELL:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_tell((int)args[0]);
  		break;
  	}
  	case SYS_CLOSE:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		system_close((int)args[0]);
  		break;
  	}
  	case SYS_MMAP:
  	{
  		argc = 2;
  		get_arguments(f->esp, args, argc);
  		f->eax = system_mmap((int) args[0], (void *) args[1]);
  		break;
  	}
  	case SYS_MUNMAP:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		system_munmap((int) args[0]);
  		break;
  	}

  }

}

static void
system_halt(void)
{
#ifdef DEBUG
	printf("system_halt(): 진입\n");
#endif
	power_off();
}

void system_exit(int status)
{
#ifdef DEBUG
	printf("system_exit(): 진입\n");
#endif
	struct thread *cur = thread_current();
	printf("%s: exit(%d)\n", thread_current()->name, status);
	cur->exit_status = status;
	thread_exit();
}

static pid_t
system_exec(const char* cmd_line)
{
#ifdef DEBUG
	printf("system_exec(): 진입\n");
#endif
	if(!is_user_vaddr((void*)cmd_line)) system_exit(-1);
	pid_t pid;
	struct thread* t = thread_current();
	pid = process_execute(cmd_line);
	sema_down(&t->load_sema);
	return t->child_status == LOAD_FAILED ? TID_ERROR : pid;
}

static int
system_wait(pid_t pid)
{
#ifdef DEBUG
	printf("system_wait(): 진입\n");
#endif
	return process_wait(pid);
}

static bool
system_create(const char* file, unsigned initial_size)
{
#ifdef DEBUG
	printf("system_create(): 진입\n");
#endif
	if(file==NULL || !is_user_vaddr((void *)file))
		system_exit(-1);
	filesys_acquire();
	bool result = filesys_create(file, initial_size);
	filesys_release();
	return result;
}

static bool
system_remove(const char* file)
{
#ifdef DEBUG
	printf("system_remove(): 진입\n");
#endif
	if(file==NULL || !is_user_vaddr((void *)file))
		system_exit(-1);
	filesys_acquire();
	bool result = filesys_remove(file);
	filesys_release();
	return result;
}

static int
system_open(const char* file)
{	
#ifdef DEBUG
	printf("system_open(): 진입\n");
#endif
	int fd = -1;
	if(file==NULL || !is_user_vaddr((void *)file))
		system_exit(-1);
	filesys_acquire();
	struct file *f = filesys_open(file);
	if(f) fd = add_thread_file_descriptor(f);
	filesys_release();
	return fd;
}

static int
system_filesize(int fd)
{
#ifdef DEBUG
	printf("system_filesize(): 진입\n");
#endif
	int size;
	struct file *file;
	file = get_file_from_fd(fd);
	if(file==NULL) system_exit(-1);
	filesys_acquire();
	size = file_length(file);
	filesys_release();
	return size;
}

static int
system_read(int fd, void* buffer, unsigned size)
{
#ifdef DEBUG
	printf("system_read(): 진입\n");
#endif
	struct file *file;
	unsigned i;
	int bytes = -1;
	if((void*)buffer==NULL || (void *)(buffer+size)==NULL || !is_user_vaddr(buffer))
		system_exit(-1);
	if(fd==STDIN_FILENO)
	{
		for(i=0; i<size; i++)
		{
			*((uint8_t*)buffer + 1) = input_getc();
			if(*((uint8_t*)buffer + 1) == 0) break;
		}
		bytes = i;
	}
	else
	{
		if(!is_user_vaddr(buffer+size)) system_exit(-1);
		else
		{
			file = get_file_from_fd(fd);
			if(file)
			{
				filesys_acquire();
				bytes = file_read(file, buffer, size);
				filesys_release();
			}
		}
	}
	return bytes;
}

static int
system_write(int fd, const void* buffer, unsigned size)
{
#ifdef DEBUG
	printf("system_write(): 진입\n");
#endif
	struct file *file;
	int result = -1;
	if((void*)buffer==NULL || (void*)(buffer+size)==NULL || !is_user_vaddr(buffer)) system_exit(-1);
	if(fd==STDOUT_FILENO)
	{
		putbuf(buffer, size);
		result = size;
	}
	else
	{
		if(!is_user_vaddr((void*)(buffer+size))) system_exit(-1);
		else
		{
			file = get_file_from_fd(fd);
			if(file)
			{
				filesys_acquire();
				result = file_write(file, buffer, size);
				filesys_release();
			}
			else result = 0;
		}
	}
	return result;
}

static void
system_seek(int fd, unsigned position)
{
#ifdef DEBUG
	printf("system_seek(): 진입\n");
#endif
	if(fd==STDIN_FILENO || fd==STDOUT_FILENO) system_exit(-1);
	struct file *file;
	file = get_file_from_fd(fd);
	if(file)
	{
		filesys_acquire();
		file_seek(file, position);
		filesys_release();
	}
}

static unsigned
system_tell(int fd)
{
#ifdef DEBUG
	printf("system_tell(): 진입\n");
#endif
	if(fd==STDIN_FILENO || fd==STDOUT_FILENO) system_exit(-1);
	struct file *file;
	unsigned int tell = 0;
	file = get_file_from_fd(fd);
	if(file)
	{
		filesys_acquire();
		tell = file_tell(file);
		filesys_release();
	}
	return tell;
}

static void
system_close(int fd)
{
#ifdef DEBUG
	printf("system_close(): 진입\n");
#endif
	if(fd==STDIN_FILENO || fd==STDOUT_FILENO) system_exit(-1);
	struct file *file;
	file = get_file_from_fd(fd);
	if(file)
	{
		filesys_acquire();
		file_close(file);
		remove_file(fd);
		filesys_release();
	}
}

bool 
mmap_page_create(struct file *file, int32_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes)
{
  struct thread *curr = thread_current();
  struct page *page = malloc(sizeof(struct page));
  if (!page) return false;

  page->file = file;
  page->offset = ofs;
  page->upage = upage;
  page->read_bytes = read_bytes;
  page->zero_bytes = zero_bytes;
  page->loaded = false;
  page->mmaped = true;
  page->writable = true;

  if(!ptable_insert(page)) 
  {
  	free(page);
  	return false;
  }

  list_push_back (&curr->mmap_list, &page->list_elem);
  return true;

}


static int
system_mmap (int fd, void *addr)
{
	/* thread에서  fd 이용하여 file 가져오기 */
	struct file *f;
	f = get_file_from_fd(fd);
	if(!f) return -1;
	struct file *file = file_reopen(f);
	/* file의 length 알아오기 */
	off_t read_bytes;
	read_bytes = file_length(file);
	if(read_bytes == 0) return -1;
	/* address 검사 */
	if (!is_user_vaddr(addr) || addr < USER_VADDR_BOTTOM || ((uint32_t) addr % PGSIZE) != 0) return -1;
	off_t offset = 0;
	struct page *mmap_page;
	int mapid;
	frame_acquire ();
	struct thread *curr = thread_current();
	mapid = curr->mapid++;

	while (read_bytes > 0)
	{
	  	uint32_t page_read_bytes = (read_bytes < PGSIZE ? read_bytes : PGSIZE);
	  	uint32_t page_zero_bytes = PGSIZE - page_read_bytes;

	  	if(!mmap_page_create(file, offset, addr, page_read_bytes, page_zero_bytes))
	  	{
	  		frame_release();
	  		system_munmap(curr->mapid);
	  		return -1;
	  	}

	  	read_bytes -= page_read_bytes;
      	offset += page_read_bytes;
      	addr += PGSIZE;


  	}

  	frame_release ();
	return curr->mapid;

}

static void
system_munmap (int mapid)
{
	struct thread *curr = thread_current();
	struct list_elem *e;
	struct page *page;
	void *kpage;
	struct file *file = NULL;
	struct list_elem *next;
	if(list_empty(&curr->mmap_list))
	{
		return;
	}

	int closed = 0;
	e = list_begin(&curr->mmap_list);
	while(e != list_end(&curr->mmap_list))
	{
		next = list_next(e);
		page = list_entry(e, struct page, list_elem);
		if(page->mapid < mapid)
    {
      e = next;
      continue;
    }
	  else if(page->mapid > mapid)
	    break;
		else
		{
			list_remove(&page->list_elem);
			kpage = pagedir_get_page(curr->pagedir, page->upage);
			if(!kpage)
			{
				hash_delete(&curr->page_table, &page->hash_elem);
			}
			if(page->loaded == true)
			{
				if (pagedir_is_dirty(curr->pagedir, page->upage))
				{
		  			filesys_acquire();
		  			file_write_at(page->file, page->upage, page->read_bytes, page->offset);
		  			filesys_release();
				}
      			pagedir_clear_page(curr->pagedir, page->upage);
			}

			if(page->mapid != closed)
			{
				if(file)
				{
					filesys_acquire();
					file_close(file);
					filesys_release();
				}
				closed = page->mapid;
				file = page->file;
			}

			free(page);
		}
		e = next;
	}
	if(file)
	{
		filesys_acquire();
		file_close(file);
		filesys_release();
	}
	return;
}


/* help function */

static int
add_thread_file_descriptor(struct file *file)
{
	struct thread *cur = thread_current();
	struct thread_fd *t_fd = (struct thread_fd *) malloc (sizeof (struct thread_fd));
	t_fd->fd = cur->fd_count++; // 현재 최대 번호가 주어지고 count 늘어남 => 다음 번에는 다른 번호.
	t_fd->file = file;
	list_push_back(&cur->fd_list, &t_fd->elem);
	return t_fd->fd;
}

static struct file *
get_file_from_fd(int fd)
{
	struct thread *cur = thread_current();
	struct thread_fd *t_fd;
	struct list_elem *e;
	if(fd<2 || fd>cur->fd_count) return NULL;
	for(e=list_begin(&cur->fd_list); e!=list_end(&cur->fd_list);
			e=list_next(e))
	{
		t_fd = list_entry(e, struct thread_fd, elem);
		if(t_fd->fd ==fd) return t_fd->file;
	}
	return NULL;
}

static void
remove_file(int fd)
{
	struct thread *cur = thread_current();
	struct thread_fd *t_fd;
	struct list_elem *e;
	for(e=list_begin(&cur->fd_list); e!=list_end(&cur->fd_list); e=list_next(e))
	{
		t_fd = list_entry(e, struct thread_fd, elem);
		if(t_fd->fd == fd)
		{
			list_remove(e);
			free(t_fd);
			break;
		}
	}
}












