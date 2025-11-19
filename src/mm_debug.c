#ifdef TESTING
    #ifdef TRACK_RET_ADDR 
        #include <stddef.h>
        #include <mm_debug.h>
        mm_callsite_entry mm_callsites[1024];
        size_t mm_callsite_count;
    #endif
    int calloc_called = 0;
    int free_called = 0;
    int freed = 0;
    int malloc_called = 0;
    int realloc_called = 0;
    int realloc_enough_size = 0;
    int fuse_fwd_called = 0;
    int fuse_bwd_called = 0;
#endif
