#include <sys/types.h>
#include <unistd.h>

#if defined(__clang__)
    #pragma clang diagnostic push 
    #pragma clang diagnostic ignored "-Wdeprecated-declarations" 
#elif defined(__GNUC__) 
    #pragma GCC diagnostic push 
    #pragma GCC diagnostic ignored "-Wdeprecated-declarations" 
#endif 

// use for small allocations < 128 KiB
void* mm_sbrk(long inc){
    return sbrk(inc);
}
void* mm_brk(const void* p){
    return brk(p);
}
void* mm_mmap(size_t n){ (void)n; return NULL; }
int   mm_munmap(void* p, size_t n){ (void)p; (void)n; return 0; }

#if defined(__clang__)
    #pragma clang diagnostic pop
#elif defined(__GNUC__) 
    #pragma GCC diagnostic pop
#endif 
