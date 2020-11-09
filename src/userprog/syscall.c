#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *f UNUSED);

void check_address(void *addr);
void get_argument(void *esp, int *arg, int count);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  void *esp = f->esp;
  int number = *(int *)esp;
  switch (number)
  {
  case SYS_HALT:
    printf("SYS HALT");
    halt();
    break;
  case SYS_EXIT:
    check_address(esp + 4);
    exit(*(uint32_t *)(esp + 4));
    printf("SYS_EXIT");
    break;
  case SYS_EXEC:
    check_address(esp + 4);
    exec((const char *)*(uint32_t *)(esp + 4));
    printf("SYS_EXEC");
    break;
  case SYS_WAIT:
    check_address(esp + 4);
    wait((pid_t) * (uint32_t *)(esp + 4));
    printf("SYS_WAIT");
    break;
  case SYS_CREATE:
    printf("SYS_CREATE");
    break;
  case SYS_REMOVE:
    printf("SYS_REMOVE");
    break;
  case SYS_OPEN:
    printf("SYS_OPEN");
    break;
  case SYS_FILESIZE:
    printf("SYS_FILESIZE");
    break;
  case SYS_READ:
    check_address(esp + 20);
    check_address(esp + 24);
    check_address(esp + 28);
    read((int)*(uint32_t *)(esp + 20), (void *)*(uint32_t *)(esp + 24), (unsigned)*((uint32_t *)(esp + 28)));
    printf("SYS_READ");
    break;
  case SYS_WRITE:
    printf("SYS_WRITE");
    break;
  case SYS_SEEK:
    printf("SYS_SEEK");
    break;
  case SYS_TELL:
    printf("SYS_TELL");
    break;
  case SYS_CLOSE:
    printf("SYS_CLOSE");
    break;

  default:
    break;
  }
  printf("system call!\n");
  thread_exit();
}

void halt(void)
{
  shutdown_power_off();
}

void exit(int status)
{
  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

int read(int fd, void *buffer, unsigned size)
{
  int i;
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
  return i;
}

int write(int fd, const void *buffer, unsigned size)
{

  if (fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  return -1;
}

void check_address(void *addr)
{
  if (!is_user_vaddr(addr))
  {
    exit(-1);
  }
}