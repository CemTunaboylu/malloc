// Without _DEFAULT_SOURCE, brk and sbrk are NOT declared in <unistd.h> (for Linux/glibc)
#define  _DEFAULT_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

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
