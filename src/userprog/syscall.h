#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#define bool _Bool
#include "filesys/off_t.h"
#include "filesys/file.h"

typedef int tid_t;

struct file
{
    struct inode *inode; /* File's inode. */
    off_t pos;           /* Current position. */
    bool deny_write;     /* Has file_deny_write() been called? */
};

void syscall_init(void);
void halt(void);
void exit(int status);
tid_t exec(const char *cmd_line);
int wait(tid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

#endif /* userprog/syscall.h */
