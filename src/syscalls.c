#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdint.h>

extern char _end;
static char *heap_end;

void *_sbrk(ptrdiff_t increment)
{
    char *previous;
    const uintptr_t stack_guard = 0x2001c000u;
    if (heap_end == 0) heap_end = &_end;
    previous = heap_end;
    if ((uintptr_t)(heap_end + increment) >= stack_guard) {
        errno = ENOMEM;
        return (void *)-1;
    }
    heap_end += increment;
    return previous;
}

int _close(int file){(void)file;return -1;}
int _fstat(int file,struct stat *st){(void)file;st->st_mode=S_IFCHR;return 0;}
int _isatty(int file){(void)file;return 1;}
off_t _lseek(int file,off_t offset,int whence){(void)file;(void)offset;(void)whence;return 0;}
int _read(int file,char *ptr,int len){(void)file;(void)ptr;(void)len;return 0;}
int _write(int file,char *ptr,int len){(void)file;(void)ptr;return len;}
void _exit(int status){(void)status;for(;;){}}
int _kill(int pid,int sig){(void)pid;(void)sig;errno=EINVAL;return -1;}
int _getpid(void){return 1;}
