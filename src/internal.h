#pragma once

#include <sys/types.h>
#include <stdint.h>

// since blocks are always used with pointers, we define the type as a pointer type
typedef struct s_block *block;

// structs ara aligned by default, so cannot make free smaller at this point
struct s_block {
    size_t size;
    block next;
    block prev;
    int free;
    // points to end of the allocated user memory to add another check 
    // for reconstructing the block from given pointer
    void* end_of_alloc_mem; 
}; 
/* Note: We assume sizeof(struct s_block) is a multiple of MAX_ALIGNMENT so that
    start_of_alloc_mem is suitably aligned for any fundamental type.
    This is tested in test_malloc in case it is missed later on. 
*/ 


void* allocated_memory(block b); 
block reconstruct_from_user_memory(const void* p); 

#ifdef TESTING
    extern size_t size_of_block(void);
    void deep_copy_block(block src, block to);
    int is_addr_valid_heap_addr(void *p);
    void fuse_fwd(block);
    void fuse_bwd(block*);
#endif

// test probes use head, thus we need to make it external
extern block head; 
extern const size_t MAX_ALIGNMENT;

size_t align_up_fundamental(size_t);
static inline size_t align(size_t s) {
    return align_up_fundamental(s);
}

/*
The allocator calls these wrappers. In tests, they can be 
replaced with deterministic stubs (or counters) so that
we can assert “one mmap for big alloc,” “no sbrk for free,” etc.
*/

// used for small allocations < 128 KiB
void* mm_sbrk(intptr_t inc);
int mm_brk(void* p);
// if more than one page, use this
void* mm_mmap(size_t n);
int   mm_munmap(void* p, size_t n);
