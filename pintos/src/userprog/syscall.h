#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "userprog/process.h"

void syscall_init (void);
int sys_write(int fd, const void *buffer, unsigned size);
int sys_read(int fd, const void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
void close_extra_files(int fd_num);
void close_thread_files(tid_t tid);
void sys_close(int fd);

#endif /* userprog/syscall.h */
