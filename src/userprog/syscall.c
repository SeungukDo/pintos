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

struct lock file_lock;

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  void *esp = f->esp;
  int number = *(int *)esp;
  //printf("\nsyscall %d\n", number);
  //hex_dump(f->esp, f->esp, 100, 1);
  switch (number)
  {
  case SYS_HALT:
    //printf("\nSYS HALT\n");
    halt();
    break;
  case SYS_EXIT:
    //printf("\nSYS_EXIT\n");

    check_address(esp + 4);
    exit(*(uint32_t *)(esp + 4));
    break;
  case SYS_EXEC:
    //printf("\nSYS_EXEC\n");

    check_address(esp + 4);
    exec((const char *)*(uint32_t *)(esp + 4));
    break;
  case SYS_WAIT:
    //printf("\nSYS_WAIT\n");

    check_address(esp + 4);
    wait((pid_t) * (uint32_t *)(esp + 4));
    break;
  case SYS_CREATE:
    check_address(esp + 4);
    check_address(esp + 8);
    f->eax = create((const char *)*(uint32_t *)(esp + 4), (unsigned)*(uint32_t *)(esp + 8));
    break;
  case SYS_REMOVE:
    check_address(esp + 4);
    f->eax = remove((const char*)*(uint32_t *)(esp + 4));
    break;
  case SYS_OPEN:
    check_address(esp + 4);
    f->eax = open((const char*)*(uint32_t *)(esp + 4));
    break;
  case SYS_FILESIZE:
    check_address(esp + 4);
    f->eax = filesize((int)*(uint32_t *)(esp + 4));
    break;
  case SYS_READ:
    check_address(esp + 4);
    check_address(esp + 8);
    check_address(esp + 12);
    read((int)*(uint32_t *)(esp + 20), (void *)*(uint32_t *)(esp + 24), (unsigned)*((uint32_t *)(esp + 28)));
    break;
  case SYS_WRITE:
    check_address(esp + 4);
    check_address(esp + 8);
    check_address(esp + 12);
    write((int)*(uint32_t *)(esp+4), 
    (void *)*(uint32_t *)(f->esp + 8), 
    (unsigned)*((uint32_t *)(f->esp + 12)));
    break;
  case SYS_SEEK:
    check_address(esp + 4);
    check_address(esp + 8);
    seek((int)*(uint32_t *)(esp + 4), (unsigned)*(uint32_t *)(esp + 8));
    break;
  case SYS_TELL:
    check_address(esp + 4);
    f->eax = tell((int)*(uint32_t *)(esp + 4));
    break;
  case SYS_CLOSE:
    check_address(esp + 4);
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
  for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] != NULL) {
          close(i);
      }   
  }   

  thread_exit();
}

pid_t exec(const char *cmd_line)
{
  pid_t pid = process_execute(cmd_line);
  struct thread* child;

  struct list_elem* elem;
  for(elem = list_begin(&thread_current()->child_list);
      elem != list_end(&thread_current()->child_list);
      elem = list_next(elem)){

    child = list_entry(elem, struct thread, child_elem);

    if(child->tid == pid) {
      sema_down(&child->load_sema);

      if(child->loaded)
        return pid;
      else
        return -1;
    }
  }
  return -1;
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
  return filesys_create(file, initial_size);
}

bool remove (const char *file) {
  return filesys_remove(file);
}

int open (const char *file) {
  int i;
  struct file* fp = filesys_open(file);
  if (fp == NULL) {
      return -1; 
  } else {
    for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] == NULL) {
        thread_current()->fd[i] = fp; 
        return i;
      }   
    }   
  }
  return -1; 
}

int filesize (int fd) {
  return file_length(thread_current()->fd[fd]);
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
    putbuf((const char*)buffer, size);
    return size;
  }
  return -1;
}

void seek (int fd, unsigned position) {
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell (int fd) {
  return file_tell(thread_current()->fd[fd]);
}

void close (int fd) {
  return file_close(thread_current()->fd[fd]);
}

void check_address(void *addr)
{
  if((unsigned int)addr >= 0x8048000){
    if((unsigned int)addr < 0xc0000000){
      return;
    }
  }
	else{
		exit(-1);
	}
}