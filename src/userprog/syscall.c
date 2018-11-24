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
static void unbusy_addr(void* addr);
static void unbusy_string(void* addr);
static void unbusy_buffer(void* addr, unsigned size);

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


static struct page*
check_addr_valid(const void *addr, void *esp)
{
	if(!is_user_vaddr(addr)) system_exit(-1);
	struct page *page = ptable_lookup(addr);
	bool success = false;
	if(page)
	{
    page->busy = true;
    success = page_load(success, page);
    success = page->loaded;
	}
	else
	{
    if(addr >= esp - 32)
    {
      success = stack_growth(success, addr);
      // 여기서 새로 만든 페이지 busy true로 유지
    }
	}
	if(!success)
		system_exit(-1);
	return page;
}

static inline void
get_arguments(int32_t* esp, int32_t* args, unsigned int argc)
{
	void* base_esp = esp;
	while(argc--)
	{
		check_addr_valid(esp, base_esp);
  	*(args++) = *(++esp);
	}
	check_addr_valid(esp, base_esp);
}


void check_string_valid (const void* str, void* esp)
{
  check_addr_valid(str, esp);
  while (* (char *) str != 0)
    {
      str = (char *) str + 1;
      check_addr_valid(str, esp);
    }
}

void check_buffer_valid (void* buffer, unsigned size, void* esp, bool to_write)
{
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
  {
    struct page *page = check_addr_valid((const void*)local_buffer, esp);
    if(page && to_write)
		{
	  	if(!page->writable)
	    {
	      system_exit(-1);
	    }
		}
    local_buffer++;
  }
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
  check_addr_valid((const void*) f->esp, f->esp);
  thread_current()->esp = f->esp;
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
  		check_string_valid((const void*) args[0], f->esp);
  		f->eax = system_exec((const char *)args[0]);
  		unbusy_string((void *)args[0]);
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
  		check_string_valid((const void*) args[0], f->esp);
  		f->eax = system_create((const char*)args[0], (unsigned)args[1]);
  		unbusy_string((void *)args[0]);
  		break;
  	}
  	case SYS_REMOVE:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		check_string_valid((const void*) args[0], f->esp);
  		f->eax = system_remove((const char*)args[0]);
  		break;
  	}
  	case SYS_OPEN:
  	{
  		argc = 1;
  		get_arguments(f->esp, args, argc);
  		check_string_valid((const void*) args[0], f->esp);
  		f->eax = system_open((const char*)args[0]);
  		unbusy_string((void *)args[0]);
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
  		check_buffer_valid((void *) args[1], (unsigned) args[2], f->esp, true);
  		f->eax = system_read((int)args[0], (void*)args[1], (unsigned)args[2]);
  		unbusy_buffer((void*)args[1], (unsigned)args[2]);
  		break;
  	}
  	case SYS_WRITE:
  	{
  		argc = 3;
  		get_arguments(f->esp, args, argc);
  		check_buffer_valid((void *) args[1], (unsigned) args[2], f->esp, false);
  		f->eax = system_write((int)args[0], (const void*)args[1], (unsigned)args[2]);
  		unbusy_buffer((void*)args[1], (unsigned)args[2]);
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
  unbusy_addr(f->esp);
}

static void
system_halt(void)
{
	power_off();
}

void system_exit(int status)
{
	struct thread *cur = thread_current();
	printf("%s: exit(%d)\n", thread_current()->name, status);
	cur->exit_status = status;
	thread_exit();
}

static pid_t
system_exec(const char* cmd_line)
{
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
	return process_wait(pid);
}

static bool
system_create(const char* file, unsigned initial_size)
{
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
	int size;
	struct file *file;
	filesys_acquire();
	file = get_file_from_fd(fd);
	if(file==NULL)
	{
		filesys_release();
		system_exit(-1);
	}
	size = file_length(file);
	filesys_release();
	return size;
}

static int
system_read(int fd, void* buffer, unsigned size)
{
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
			filesys_acquire();
			file = get_file_from_fd(fd);
			if(file)
			{
				bytes = file_read(file, buffer, size);
			}
			filesys_release();
		}
	}
	return bytes;
}

static int
system_write(int fd, const void* buffer, unsigned size)
{
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
			filesys_acquire();
			file = get_file_from_fd(fd);
			if(file)
			{
				result = file_write(file, buffer, size);
			}
			else result = 0;
			filesys_release();
		}
	}
	return result;
}

static void
system_seek(int fd, unsigned position)
{
	if(fd==STDIN_FILENO || fd==STDOUT_FILENO) system_exit(-1);
	struct file *file;
	filesys_acquire();
	file = get_file_from_fd(fd);
	if(file)
	{
		file_seek(file, position);
	}
	filesys_release();
}

static unsigned
system_tell(int fd)
{
	if(fd==STDIN_FILENO || fd==STDOUT_FILENO) system_exit(-1);
	struct file *file;
	unsigned int tell = 0;
	filesys_acquire();
	file = get_file_from_fd(fd);
	if(file)
	{
		tell = file_tell(file);
	}
	filesys_release();
	return tell;
}

static void
system_close(int fd)
{
	if(fd==STDIN_FILENO || fd==STDOUT_FILENO) system_exit(-1);
	struct file *file;
	filesys_acquire();
	file = get_file_from_fd(fd);
	if(file)
	{
		file_close(file);
		remove_file(fd);
	}
	filesys_release();
}

bool 
mmap_page_create(struct file *file, int32_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, int mapid)
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
  page->mapid = mapid;
  page->busy = false;

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
	struct page *page;
	filesys_acquire();
	f = get_file_from_fd(fd);
	filesys_release();
	if(!f) return -1;
	/* address 검사 */
	if(!is_user_vaddr(addr) || addr < USER_VADDR_BOTTOM || ((uint32_t) addr % PGSIZE) != 0) return -1;
	struct file *file = file_reopen(f);
	if(!file) return -1;
	/* file의 length 알아오기 */
	off_t read_bytes;
	read_bytes = file_length(f);
	if(read_bytes == 0) return -1;
	read_bytes = file_length(file);
	off_t offset = 0;
	struct page *mmap_page;
	int mapid = thread_current()->mapid++;
	while (read_bytes > 0)
	{
  	uint32_t page_read_bytes = (read_bytes < PGSIZE ? read_bytes : PGSIZE);
  	uint32_t page_zero_bytes = PGSIZE - page_read_bytes;
  	if(!mmap_page_create(file, offset, addr, page_read_bytes, page_zero_bytes, mapid))
  	{
	    system_munmap(mapid);
  		return -1;
  	}
  	read_bytes -= page_read_bytes;
    offset += page_read_bytes;
    addr += PGSIZE;
	}
	return thread_current()->mapid;
}

static void
system_munmap(int mapid)
{
	struct thread *curr = thread_current();
	struct list_elem *e;
	struct list_elem *next;
	struct page *page;
	void *kpage;
	struct file *file = NULL;
	if(list_empty(&curr->mmap_list))
		return;
  int closed = 0;
	e = list_front(&curr->mmap_list);
	bool file_put = false;
	while(e != list_end(&curr->mmap_list))
	{
		next = list_next(e);
		page = list_entry(e, struct page, list_elem);
		if(page->mapid != mapid)
    {
      e = next;
      continue;
    }
	  page->busy = true;
		list_remove(&page->list_elem);
		if(pagedir_is_dirty(curr->pagedir, page->upage))
		{
			filesys_acquire();
			file_write_at(page->file, page->upage, page->read_bytes, page->offset);
			filesys_release();
		}
		frame_free(pagedir_get_page(curr->pagedir, page->upage));
		pagedir_clear_page(curr->pagedir, page->upage);
		hash_delete(&curr->page_table, &page->hash_elem);
    if (page->mapid != closed)
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
		frame_free(kpage);
		e = next;
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

static void
unbusy_addr(void* addr)
{
  struct page *page = ptable_lookup(addr);
  if(page) page->busy = false;
}

static void
unbusy_string(void* addr)
{
	unbusy_addr(addr);
	while(*(char*)addr!=0)
	{
		addr = (char*) addr + 1;
		unbusy_addr(addr);
	}
}
static void
unbusy_buffer(void* addr, unsigned size)
{
  unsigned i;
  char* tmp_addr = (char *) addr;
  for (i = 0; i < size; i++)
    {
      unbusy_addr(tmp_addr);
      tmp_addr++;
    }
}






