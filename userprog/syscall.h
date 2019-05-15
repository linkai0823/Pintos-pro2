#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void *addr_useful(void *addr);
void syscall_exit(int status);
void syscall_halt(void);
int syscall_create(char *name, unsigned initial_size);
int syscall_remove(char *file);
int syscall_exec(const char *file_name);
int syscall_open(char *name);
int syscall_write(int fd, const void *buffer ,unsigned size);
void syscall_seek(int fd_num, unsigned position);

int syscall_read(int fd_num, void *buffer, unsigned size);

int syscall_filesize(int fd_num);
int syscall_tell(int fd_num);

void syscall_close(int fd);
#endif /* userprog/syscall.h */

