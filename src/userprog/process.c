#include "userprog/process.h"
#include "userprog/syscall.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <user/syscall.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#ifdef VM
#include "vm/frame.h"
#include "vm/page.h"
#endif

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp, char** token_ptr);
void free(void *ptr);
void *malloc(size_t);
void *realloc(void *ptr, size_t size);

//#define DEBUG

void close_all_files(void)
{
#ifdef DEBUG
  printf("close_all_files(): 진입\n");
#endif
  struct thread *cur = thread_current();
  struct list_elem *e;
  struct thread_fd *t_fd;
  if(!list_empty(&cur->fd_list))
  {
    e = list_front(&cur->fd_list);
    while(e!=list_end(&cur->fd_list))
    {
      t_fd = list_entry(e, struct thread_fd, elem);
      e = list_remove(e);
      filesys_acquire();
      file_close(t_fd->file); // thread의 file descriptor들 다 닫기
      filesys_release();
      free(t_fd);
    }
  }
  filesys_acquire();
  file_close(cur->executable);
  filesys_release();
}

int wait_child(tid_t child_tid)
{
#ifdef DEBUG
  printf("wait_child(): 진입\n");
#endif
  struct thread *cur = thread_current();
  struct thread_child *child;
  struct list_elem *e;
  int status = TID_ERROR;
  for(e=list_begin(&cur->child_list); e!=list_end(&cur->child_list); e=list_next(e))
  {
    child = list_entry(e, struct thread_child, elem);
    if(child->tid == child_tid)
    {
      sema_down(&child->sema); //child exit할 때까지 기다린다. (process_exit에서)
      status = child->status;
      list_remove(e);
      free(child);
      break;
    }
  }
  return status;
}
void alert_parent(void)
{
#ifdef DEBUG
  printf("alert_parent(): 진입\n");
#endif
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct thread_child *child;
  for(e=list_begin(&cur->parent->child_list); e!=list_end(&cur->parent->child_list); e=list_next(e))
  {
    child = list_entry(e, struct thread_child, elem);
    if(child->tid==cur->tid)
    {
      child->exit = true;
      child->status = cur->exit_status;
      sema_up(&child->sema);
      break;
    }
  }
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline) 
{
  char *cmd_copy;
  char *cmd_copy2;
  char *file_name;
  char *token_ptr = NULL;
  tid_t tid;
  struct file *file;
  struct thread *cur = thread_current();

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  cmd_copy = palloc_get_page (0);
  if (cmd_copy == NULL)
    return TID_ERROR;
  strlcpy(cmd_copy, cmdline, PGSIZE);

  /* 맨 앞의 단어가 file name */
  cmd_copy2 = palloc_get_page (0);
  if (cmd_copy2 == NULL)
    return TID_ERROR;
  strlcpy(cmd_copy2, cmdline, PGSIZE);
  file_name = strtok_r(cmd_copy2, " ", &token_ptr);

  /* file 열어보고 없으면 load fail */
  file = filesys_open(file_name);
  if (file == NULL)
  {
    palloc_free_page(cmd_copy);
    palloc_free_page(cmd_copy2);
    cur->child_status = LOAD_FAILED;
    sema_up(&cur->load_sema); // load_sema는 syscall의 system_exec에서 기다리는 중
    return TID_ERROR;
  }
  file_close(file);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, cmd_copy);
  if (tid == TID_ERROR)
  {
    palloc_free_page(cmd_copy);
    palloc_free_page(cmd_copy2);
    cur->child_status = LOAD_FAILED;
    free(file_name); // file name은 여기서 free되므로 아래 다른 함수들에서 안 해줘도 됨
    sema_up(&cur->load_sema);
  }
  palloc_free_page(cmd_copy2);
  return tid;
}

/* A thread function that loads a user process and makes it start
   running. */
static void
start_process (void *f_name)
{
#ifdef DEBUG
  printf("start_process(): 진입\n");
#endif
  char *file_name = (char *)f_name;
  char *token_ptr = NULL;
  struct intr_frame if_;
  bool success;
  struct thread *cur = thread_current();

#ifdef VM
  ptable_init(&cur->page_table);
#endif

  file_name = strtok_r(file_name, " ", &token_ptr); //file_name 뽑기

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  // pagedir 생성, 인자로 넘어온 이름의 실행파일 오픈, 코드 읽음
  // setup_stack()으로 stack 초기화하고 eip에 다음 실행 명령어 주소 설정
  // token_ptr이 나머지 cmdline argument 뽑을 수 있게 해줌.
  success = load(file_name, &if_.eip, &if_.esp, &token_ptr);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
  {
#ifdef DEBUG
    printf("start_process: load() 실패********\n");
#endif
    cur->parent->child_status = LOAD_FAILED;
    sema_up(&cur->parent->load_sema);
    system_exit(-1);
  }
  else
  {
#ifdef DEBUG
    printf("start_process: load() 성공\n");
#endif
    cur->parent->child_status = LOAD_DONE;
    sema_up(&cur->parent->load_sema);
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
#ifdef DEBUG
  printf("process_wait(): 진입\n");
#endif
  int status = wait_child(child_tid);
  return status;
}

#ifdef VM
void
mmap_clear()
{
#ifdef DEBUG
  printf("mmap_clear(): 진입\n");
#endif
  struct thread *curr = thread_current();
  struct list_elem *e;
  struct page *page;
  struct file *file = NULL;
  if(list_empty(&curr->mmap_list)) return;
  int prev_mapid = 0;
  for(e=list_front(&curr->mmap_list);e!=list_end(&curr->mmap_list);)
  {
    page = list_entry(e, struct page, list_elem);
    e = list_next(e);
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
    if(page->mapid != prev_mapid)
    {
      if(file)
      {
        filesys_acquire();
        file_close(file);
        filesys_release();
      }
      prev_mapid = page->mapid;
      file = page->file;
    }
    free(page);
  }
  if(file)
  {
    filesys_acquire();
    file_close(file);
    filesys_release();
  }
  return;
}
#endif

/* Free the current process's resources. */
void
process_exit (void)
{
#ifdef DEBUG
  printf("process_exit(): 진입\n");
#endif
  struct thread *cur = thread_current ();
  uint32_t *pd;
  alert_parent();  // change parent->child_list의 child->exit true로.
  close_all_files();
#ifdef VM
  mmap_clear();
  ptable_clear();
#endif
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);
static bool argument_setup(void **esp, const char *file_name, char **token_ptr);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp, char **token_ptr) 
{
#ifdef DEBUG
  printf("load(): 진입\n");
#endif
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();
  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }
  /* file 열었으니 deny_write */
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
              {
#ifdef DEBUG
                printf("load(): load_segment() 확인 결과 false => goto done******\\n");
#endif
                goto done;
              }
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* stack 생겼으니 argument 가져다 채우기 */
  success = argument_setup(esp, file_name, token_ptr);
  if(!success) free((char *)file_name);

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if(success)
    t->executable = file;
  else
    file_close(file);
  return success;
}

static void push_argv_stack(void **esp, const char *file_name, char *token, char **token_ptr, char ***argv, int* argc, int default_arg_num);
static void word_alignment(void **esp);
static void push_argv_addr_stack(void **esp, char ***argv, int argc);
static void push_argc_stack(void **esp, int *argc);
static void push_fake_return_addr_stack(void **esp);

static bool
argument_setup(void **esp, const char *file_name, char **token_ptr)
{
  char *token = NULL;
  int argc = 0;
  int default_arg_num = 4;
  char **argv = malloc(default_arg_num * sizeof(char*));
  push_argv_stack(esp, file_name, token, token_ptr, &argv, &argc, default_arg_num);
  word_alignment(esp);
  push_argv_addr_stack(esp, &argv, argc);
  push_argc_stack(esp, &argc);
  push_fake_return_addr_stack(esp);
  free(argv);
  return true;
}
static void
push_argv_stack(void **esp, const char *file_name, char *token, char **token_ptr, char ***argv, int* argc, int default_arg_num)
{
  for (token = (char *) file_name; token != NULL; token = strtok_r(NULL, " ", token_ptr))
  {
    int argument_length = strlen(token);
    *esp -= argument_length + 1;
    (*argv)[*argc] = *esp;
    (*argc)++; // arg 수 세기
    // argc 예상보다 더 많으면 2배 메모리 realloc
    if ((*argc) >=  default_arg_num)
    {
      default_arg_num *= 2;
      (*argv) = realloc((*argv), default_arg_num * sizeof(char *));
    }
    // argument stack
    memcpy(*esp, token, argument_length+1);
  }
  (*argv)[*argc] = 0;
}
static void
word_alignment(void **esp)
{
  unsigned int word_align = 0;
  if((word_align = (unsigned int) *esp %4) != 0)
  {
    *esp -= word_align;
    memset(*esp, 0, word_align);
  }
}
static void
push_argv_addr_stack(void **esp, char ***argv, int argc)
{
  int i;
  for (i=argc; i>=0; i--)
  {
    *esp -= sizeof(char *);
    memcpy(*esp, &(*argv)[i], sizeof(char *));
  }
  char *token = *esp;
  *esp -= sizeof(char **);
  memcpy(*esp, &token, sizeof(char **));
}
static void
push_argc_stack(void **esp, int *argc)
{
  *esp -= sizeof(int);
  memcpy(*esp, argc, sizeof(int));
}
static void
push_fake_return_addr_stack(void **esp)
{
  *esp -= sizeof(void *);
  memset(*esp, 0, sizeof(void *));
}


/* load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Do calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
#ifdef VM
      struct page *page;
      if((page=page_create(file, ofs, upage, page_read_bytes, writable)) == NULL)
        return false;
      if(!ptable_insert(page))
        return false;
#else
      uint8_t *kpage = palloc_get_page(PAL_USER);
      if(!kpage) return false;
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }
#endif
      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
#ifdef VM
      ofs += PGSIZE;
#endif
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{

  uint8_t *kpage;
  uint8_t *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
#ifdef VM
  struct page *page = malloc(sizeof(struct page));
  page->upage = upage;
  page->writable = true;
  page->loaded = true;
  page->file = NULL;
  page->swaped = false;
  page->mapid = -1;
  page->busy = false;
  kpage = frame_alloc(PAL_USER | PAL_ZERO, page);
#else
  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
#endif
  if(!kpage)
  {
#ifdef VM
    free(page);
#endif
    return false;
  }
  if(!install_page(upage, kpage, true))
  {
#ifdef VM
    frame_free(kpage);
    free(page);
#else
    palloc_free_page(kpage);
#endif
    return false;
  }
#ifdef VM
  if(!ptable_insert(page))
  {
    frame_free(kpage);
    free(page);
    return false;
  }
#endif
  *esp = PHYS_BASE;
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */

bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
