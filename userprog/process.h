#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct process_file
{
    int fd;
    struct file *fd_file;
    struct list_elem fd_elem;
};

#endif /* userprog/process.h */
