#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *f UNUSED);

int check_address(void *addr);
void get_argument(void *esp, int *arg, int count);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

struct lock file_lock;

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  void *esp = f->esp;
  int number = *(int *)esp;
  if (check_address((void *)esp))
    exit(-1);
  switch (number)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    if (check_address(esp + 4))
      exit(-1);
    exit(*(uint32_t *)(esp + 4));
    break;
  case SYS_EXEC:
    if (check_address(esp + 4))
      exit(-1);
    f->eax = exec((const char *)*(uint32_t *)(esp + 4));
    break;
  case SYS_WAIT:
    if (check_address(esp + 4))
      exit(-1);
    f->eax = wait((tid_t) * (uint32_t *)(esp + 4));
    break;
  case SYS_CREATE:
    if (check_address(esp + 4))
      exit(-1);
    if (check_address(esp + 8))
      exit(-1);
    f->eax = create((const char *)*(uint32_t *)(esp + 4), (unsigned)*(uint32_t *)(esp + 8));
    break;
  case SYS_REMOVE:
    if (check_address(esp + 4))
      exit(-1);
    f->eax = remove((const char *)*(uint32_t *)(esp + 4));
    break;
  case SYS_OPEN:
    if (check_address(esp + 4))
      exit(-1);
    f->eax = open((const char *)*(uint32_t *)(esp + 4));
    break;
  case SYS_FILESIZE:
    if (check_address(esp + 4))
      exit(-1);
    f->eax = filesize((int)*(uint32_t *)(esp + 4));
    break;
  case SYS_READ:
    if (check_address(esp + 4))
      exit(-1);
    if (check_address(esp + 8))
      exit(-1);
    if (check_address(esp + 12))
      exit(-1);
    f->eax = read((int)*(uint32_t *)(esp + 4), (void *)*(uint32_t *)(esp + 8), (unsigned)*((uint32_t *)(esp + 12)));
    break;
  case SYS_WRITE:
    if (check_address(esp + 4))
      exit(-1);
    if (check_address(esp + 8))
      exit(-1);
    if (check_address(esp + 12))
      exit(-1);
    f->eax = write((int)*(uint32_t *)(esp + 4),
                   (void *)*(uint32_t *)(f->esp + 8),
                   (unsigned)*((uint32_t *)(f->esp + 12)));
    break;
  case SYS_SEEK:
    if (check_address(esp + 4))
      exit(-1);
    if (check_address(esp + 8))
      exit(-1);
    seek((int)*(uint32_t *)(esp + 4), (unsigned)*(uint32_t *)(esp + 8));
    break;
  case SYS_TELL:
    if (check_address(esp + 4))
      exit(-1);
    f->eax = tell((int)*(uint32_t *)(esp + 4));
    break;
  case SYS_CLOSE:
    if (check_address(esp + 4))
      exit(-1);
    close((int)*(uint32_t *)(esp + 4));
    break;

  default:
    break;
  }
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  int i;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_current()->exit_status = status;
  for (i = 3; i < 128; i++)
  {
    if (thread_current()->fd[i] != NULL)
    {
      close(i);
    }
  }

  thread_exit();
}

tid_t exec(const char *cmd_line)
{
  tid_t tid = process_execute(cmd_line);
  struct thread *child;

  struct list_elem *elem;
  for (elem = list_begin(&thread_current()->child_list);
       elem != list_end(&thread_current()->child_list);
       elem = list_next(elem))
  {
    child = list_entry(elem, struct thread, child_elem);

    if (child->tid == tid)
    {
      sema_down(&child->load_sema);
      int is_loaded = child->loaded;
      if (is_loaded)
        return tid;
      else
        return -1;
    }
  }
  return -1;
}

int wait(tid_t tid)
{
  return process_wait(tid);
}

bool create(const char *file, unsigned initial_size)
{
  if (file == NULL)
  {
    exit(-1);
  }
  return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
  if (file == NULL)
  {
    exit(-1);
  }
  return filesys_remove(file);
}

int open(const char *file)
{
  if (file == NULL)
  {
    exit(-1);
  }
  int i;
  struct file *fp = filesys_open(file);
  if (fp == NULL)
  {
    return -1;
  }
  else
  {
    for (i = 3; i < 128; i++)
    {
      if (thread_current()->fd[i] == NULL)
      {
        if (strcmp(thread_current()->name, file) == 0)
        {
          file_deny_write(fp);
        }
        thread_current()->fd[i] = fp;
        return i;
      }
    }
  }
  return -1;
}

int filesize(int fd)
{
  if (thread_current()->fd[fd] == NULL)
  {
    exit(-1);
  }
  return file_length(thread_current()->fd[fd]);
}

int read(int fd, void *buffer, unsigned size)
{
  int i;
  if (check_address(buffer))
  {
    exit(-1);
  }
  if (fd == 0)
  {
    for (i = 0; i < size; i++)
    {
      if (((char *)buffer)[i] == '\0')
      {
        break;
      }
    }
  }
  else if (fd > 2)
  {
    if (thread_current()->fd[fd] == NULL)
    {
      exit(-1);
    }
    return file_read(thread_current()->fd[fd], buffer, size);
  }
  return i;
}

int write(int fd, const void *buffer, unsigned size)
{
  if (check_address(buffer))
  {
    exit(-1);
  }
  if (fd == 1)
  {
    putbuf((const char *)buffer, size);
    return size;
  }
  else if (fd > 2)
  {
    if (thread_current()->fd[fd] == NULL)
    {
      exit(-1);
    }
    if (thread_current()->fd[fd]->deny_write)
    {
      file_deny_write(thread_current()->fd[fd]);
    }
    return file_write(thread_current()->fd[fd], buffer, size);
  }
  return -1;
}

void seek(int fd, unsigned position)
{
  if (thread_current()->fd[fd] == NULL)
  {
    exit(-1);
  }
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell(int fd)
{
  if (thread_current()->fd[fd] == NULL)
  {
    exit(-1);
  }
  return file_tell(thread_current()->fd[fd]);
}

void close(int fd)
{
  struct file *fp;
  if (thread_current()->fd[fd] == NULL)
  {
    exit(-1);
  }
  fp = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  return file_close(fp);
}

int check_address(void *addr)
{
  if (addr >= 0xc0000000 || addr <= 0x8048000)
  {
    return 1;
  }
  else
  {
    return 0;
  }
}