// Without _DEFAULT_SOURCE, brk and sbrk are NOT declared in <unistd.h> (for Linux/glibc)
#define  _DEFAULT_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#ifndef TESTING 
#if defined(__clang__)
    #pragma clang diagnostic push 
    #pragma clang diagnostic ignored "-Wdeprecated-declarations" 
#elif defined(__GNUC__) 
    #pragma GCC diagnostic push 
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations" 
#endif 


// use for small allocations < 128 KiB
void* mm_sbrk(intptr_t inc){
    return sbrk(inc);
}
int mm_brk(void* addr){
/*
 * brk/sbrk are legacy, non-POSIX system calls with different prototypes
 * across UNIX descendants:
 *
 *   - Linux/glibc uses System V semantics:
 *        int brk(void *addr);           // 0 on success, -1 on error
 *        void *sbrk(intptr_t inc);      // old break or (void*)-1 on error
 *
 *   - macOS/BSD expose older BSD variants:
 *        void *brk(const void *addr);   // new break or (void*)-1 on error
 * 
 *       void *_LIBC_UNSAFE_INDEXABLE brk(const void *_LIBC_UNSAFE_INDEXABLE);
 *          to be specific
 * 
 *        void *sbrk(int inc);           // old break or (void*)-1 on error
 *
 * Because POSIX does not specify brk/sbrk, both are valid.
 * We normalize behavior by providing our own wrapper mm_brk()
 * which always returns 0 on success and -1 on error regardless of platform.
*/
#if defined(__APPLE__)
    void* res = brk(addr);
    if (res == (void*)-1) {
        return -1;          // error, errno already set by brk/sbrk
    }
    return 0;               // success
#else
    // POSIX / glibc style: int brk(void*)
    return brk(addr);   // glibc: 0 on success, -1 on error 
#endif
}
void* mm_mmap(size_t n){ (void)n; return NULL; }
int   mm_munmap(void* p, size_t n){ (void)p; (void)n; return 0; }

#if defined(__clang__)
    #pragma clang diagnostic pop
#elif defined(__GNUC__) 
    #pragma GCC diagnostic pop
#endif 
#else 

#define BUFFER_SIZE 65536
static char underlying_test_buffer[BUFFER_SIZE] = {0};
static intptr_t current_brk = 0;
static char* buf_start = &underlying_test_buffer[0];
static char* buf_end = &underlying_test_buffer[BUFFER_SIZE-1];

void* mm_sbrk(intptr_t inc){
    if (inc == 0) {
        return &underlying_test_buffer[current_brk];
    }

    intptr_t new_brk = current_brk + inc;

    if ((new_brk >= BUFFER_SIZE) || (new_brk < 0)) return (void*)(-1);

    current_brk = new_brk;
    return &underlying_test_buffer[current_brk];
}

static int is_addr_in_buffer(void* addr) {
    return ((buf_start > (char*) addr) || (buf_end < (char*) addr));
}

int mm_brk(void* addr){
    if (!is_addr_in_buffer(addr)) return -1;
    current_brk = (char*) addr - &underlying_test_buffer[current_brk];
    return 0;
}
void* mm_mmap(size_t n){ (void)n; return NULL; }
int   mm_munmap(void* p, size_t n){ (void)p; (void)n; return 0; }

#endif
