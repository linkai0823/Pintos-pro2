#include "userprog/syscall.h"
#include "threads/thread.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "filesys/off_t.h"
#include "kernel/list.h"

static void syscall_handler(struct intr_frame *);
void pop_stack(struct intr_frame *f, int *data, int offset)
{
  int *temp = f->esp;
  *data = *((int *)addr_useful(temp + offset));
}
void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  if (!addr_useful(f->esp))
  {
    syscall_exit(-1);
  }

  int *p = f->esp;
  // printf("choice is %d\n", (int)*p);
  switch (*p)
  {
  case SYS_HALT: //task2
    syscall_halt();
    break;
  case SYS_EXIT: //task2
  {

    if (addr_useful(f->esp + 4))
    {
      int status = *(int *)(f->esp + 4);
      syscall_exit(status);
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  case SYS_EXEC: //task2
  {
    if (addr_useful(f->esp + 4))
    {
      const char *file_name = (char *)*(unsigned int *)(f->esp + 4);
      f->eax = syscall_exec(file_name);
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;

  case SYS_WAIT: //task2
  {
    if (addr_useful(f->esp + 4))
    {
      tid_t child_tid = *(int *)(f->esp + 4);
      f->eax = process_wait(child_tid);
    }
    else
    {
      syscall_exit(-1);
    }
  }

  break;
  case SYS_CREATE:
  {
    if (addr_useful(f->esp + 4) && addr_useful(f->esp + 8))
    {
      unsigned initial_size = *(unsigned int *)(f->esp + 8);
      char *name = (char *)*(unsigned int *)(f->esp + 4);
      f->eax = syscall_create(name, initial_size);
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  case SYS_REMOVE:
  {
    if (addr_useful(f->esp + 4))
    {
      char *name = (char *)*(unsigned int *)(f->esp + 4);
      int ret = syscall_remove(name);
      f->eax = ret;
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  case SYS_OPEN:
  {
    if (addr_useful(f->esp + 4))
    {
      char *name = (char *)*(unsigned int *)(f->esp + 4);
      f->eax = syscall_open(name);
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  case SYS_FILESIZE:
  {

    if (addr_useful(f->esp + 4))
    {
      int fd = *(int *)(f->esp + 4);
      int ret = syscall_filesize(fd);
      f->eax = ret;
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  case SYS_READ:
  {

    if (addr_useful(f->esp + 4) && addr_useful(f->esp + 8) && addr_useful(f->esp + 12))
    {
      int fd = *(int *)(f->esp + 4);
      const char *buffer = (char *)*(unsigned int *)(f->esp + 8);
      unsigned int size = *(unsigned int *)(f->esp + 12);
      int ret = syscall_read(fd, buffer, size);
      f->eax = ret;
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  case SYS_WRITE:
  {
    if (addr_useful(f->esp + 4) && addr_useful(f->esp + 8) && addr_useful(f->esp + 12))
    {
      int fd = *(int *)(f->esp + 4);
      const char *buffer = (char *)*(unsigned int *)(f->esp + 8);
      unsigned int size = *(unsigned int *)(f->esp + 12);
      f->eax = syscall_write(fd, buffer, size);
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  case SYS_SEEK:
    if (addr_useful(f->esp + 4) && addr_useful(f->esp + 8))
    {
      int fd = *(int *)(f->esp + 4);
      unsigned int position = *(unsigned int *)(f->esp + 8);
      syscall_seek(fd, position);
    }
    else
    {
      syscall_exit(-1);
    }

    break;
  case SYS_TELL:
  {
    if (addr_useful(f->esp + 4))
    {
      int fd = *(int *)(f->esp + 4);
      int ret = syscall_tell(fd);
      f->eax = ret;
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  case SYS_CLOSE:
  {
    if (addr_useful(f->esp + 4))
    {
      int fd = *(int *)(f->esp + 4);
      syscall_close(fd);
    }
    else
    {
      syscall_exit(-1);
    }
  }
  break;
  }
}

void *
addr_useful(void *addr)
{
  void *pagedir = NULL;

  if (!is_user_vaddr(addr) || !(pagedir = pagedir_get_page(thread_current()->pagedir, addr)))
  {
    syscall_exit(-1);
    return 0;
  }
  return pagedir;
}
void syscall_exit(int status)
{
  struct thread *cur_thread = thread_current();
  struct list_elem *temp = list_begin(&cur_thread->parent->children);
  cur_thread->exit_status = status;
  cur_thread->write_exit = 1;
  printf("%s: exit(%d)\n", cur_thread->name, cur_thread->exit_status);
  for (; temp != list_end(&cur_thread->parent->children); temp = list_next(temp))
  {
    struct child_thread *child = list_entry(temp, struct child_thread, child_elem);
    if (child->tid == cur_thread->tid)
    {
      child->have_work = true;
      // printf("find\n=====================");
      child->exit_status = status;
      if (cur_thread->parent->waiting_child->tid == cur_thread->tid)
      {
        sema_up(&child->child_have_work);
      }
      break;
    }
  }
  close_all_files();

  thread_exit();
}
void syscall_halt(void)
{
  shutdown_power_off();
}
int syscall_exec(const char *file_name)
{
  if (!addr_useful((void *)file_name))
  {
    return -1;
    // syscall_exit(-1);
  }
  return process_execute(file_name);
}

int syscall_create(char *name, unsigned initial_size)
{
  if (!addr_useful((void *)name))
  {
    syscall_exit(-1);
  }
  int ret;
  lock_acquire(&filesys_lock);
  ret = filesys_create(name, initial_size);
  lock_release(&filesys_lock);
  return ret;
}
int syscall_remove(char *file)
{
  if (!addr_useful((void *)file))
  {
    syscall_exit(-1);
  }
  int ret;
  ret = filesys_remove(file);
  return ret;
}
int syscall_filesize(int fd_num)
{
  int ret = -1;
  struct thread *cur = thread_current();
  struct process_file *fd = malloc(sizeof(struct process_file));
  struct list *open_files = &cur->open_files;
  struct list_elem *temp = list_begin(open_files);
  lock_acquire(&filesys_lock);
  for (; temp != list_end(open_files); temp = list_next(open_files))
  {
    // get the file_descriptor in file_descriptors
    fd = list_entry(temp, struct process_file, fd_elem);

    if (fd_num == fd->fd)
    {
      ret = file_length(fd->fd_file);
      break;
    }
  }
  lock_release(&filesys_lock);

  return ret;
}
int syscall_open(char *name)
{
  if (!addr_useful((void *)name))
  {
    return -1;
  }
  struct file *f = filesys_open(name);
  struct process_file *pfile = malloc(sizeof(*pfile));
  struct thread *cur = thread_current();
  if (f == NULL)
  {
    return -1;
  }

  pfile->fd_file = f;

  pfile->fd = cur->fd_num;
  cur->fd_num = cur->fd_num + 1;
  list_push_back(&cur->open_files, &pfile->fd_elem);
  if ((strcmp(name, cur->name)) == 0)
  {
    file_deny_write(pfile->fd_file);
  }
  return pfile->fd;
}
int syscall_read(int fd_num, void *buffer, unsigned size)
{
  int ret = -1;
  struct thread *cur = thread_current();
  struct process_file *fd = malloc(sizeof(struct process_file));
  struct list *open_files = &cur->open_files;
  struct list_elem *temp = list_begin(open_files);
  if (!addr_useful((void *)buffer))
  {
    syscall_exit(-1);
  }

  if (fd_num == 0)
  {
    for (int i = 0; i < size; i++)
    {
      *(char *)buffer = input_getc();
      buffer++;
    }

    return size;
  }
  lock_acquire(&filesys_lock);
  for (; temp != list_end(open_files); temp = list_next(open_files))
  {
    // get the file_descriptor in file_descriptors
    fd = list_entry(temp, struct process_file, fd_elem);

    if (fd_num == fd->fd)
    {
      ret = file_read(fd->fd_file, buffer, size);
      break;
    }
  }
  lock_release(&filesys_lock);

  return ret;
}
int syscall_write(int fd, const void *buffer, unsigned size)
{
  if (!addr_useful(buffer))
  {
    syscall_exit(-1);
  }

  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }

  struct process_file *pf = NULL;
  struct thread *cur = thread_current();
  struct list_elem *temp;
  temp = list_begin(&cur->open_files);
  int flag;
  flag = 0;

  lock_acquire(&filesys_lock);
  for (; temp != list_end(&cur->open_files); temp = list_next(&cur->open_files))
  {
    pf = list_entry(temp, struct process_file, fd_elem);
    if (fd == pf->fd)
    {
      lock_release(&filesys_lock);
      return file_write(pf->fd_file, buffer, size);
    }
  }
  lock_release(&filesys_lock);

  syscall_exit(-1);
}
void syscall_seek(int fd_num, unsigned position)
{
  struct thread *cur = thread_current();
  struct process_file *fd = malloc(sizeof(struct process_file));
  struct list *open_files = &cur->open_files;
  struct list_elem *temp = list_begin(open_files);

  lock_acquire(&filesys_lock);
  for (; temp != list_end(open_files); temp = list_next(open_files))
  {
    // get the file_descriptor in file_descriptors
    fd = list_entry(temp, struct process_file, fd_elem);

    if (fd_num == fd->fd)
    {
      file_seek(fd->fd_file, position);
      break;
    }
  }
  lock_release(&filesys_lock);
}
int syscall_tell(int fd_num)
{
  int ret = -1;
  struct thread *cur = thread_current();
  struct process_file *fd = malloc(sizeof(struct process_file));
  struct list *open_files = &cur->open_files;
  struct list_elem *temp = list_begin(open_files);
  if (fd_num == 0)
  {
    return input_getc();
  }
  lock_acquire(&filesys_lock);
  for (; temp != list_end(open_files); temp = list_next(open_files))
  {
    // get the file_descriptor in file_descriptors
    fd = list_entry(temp, struct process_file, fd_elem);

    if (fd_num == fd->fd)
    {
      ret = file_tell(fd->fd_file);
      break;
    }
  }
  lock_release(&filesys_lock);

  return ret;
}
void syscall_close(int fd)
{
  struct process_file *pf = NULL;
  struct thread *cur = thread_current();
  struct list_elem *temp;
  temp = list_begin(&cur->open_files);
  int flag;
  flag = 0;
  lock_acquire(&filesys_lock);
  for (; temp != list_end(&cur->open_files); temp = list_next(&cur->open_files))
  {
    pf = list_entry(temp, struct process_file, fd_elem);
    if (fd == pf->fd)
    {
      list_remove(&pf->fd_elem);
      file_close(pf->fd_file);
      break;
    }
  }
  lock_release(&filesys_lock);
}
void close_all_files()
{
  struct thread *cur = thread_current();
  struct process_file *fd;
  struct list *file_descriptors = &cur->open_files;
  struct list_elem *e;

  while (!list_empty(file_descriptors))
  {
    // get the file_descriptor in file_descriptors
    e = list_pop_front(file_descriptors);
    fd = list_entry(e, struct process_file, fd_elem);
    list_remove(&fd->fd_elem);
    file_close(fd->fd_file);
  }
}