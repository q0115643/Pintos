#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

#define USER_VADDR_BOTTOM ((void *) 0x08048000)

void syscall_init (void);
void system_exit(int status);
void filesys_acquire(void);
void filesys_release(void);

#endif /* userprog/syscall.h */
