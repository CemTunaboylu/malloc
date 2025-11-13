#pragma once

#include <stdalign.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>

// since blocks are always used with pointers, we define the type as a pointer type
typedef struct s_block *block;

// structs ara aligned by default, so cannot make free smaller at this point
struct s_block {
    size_t size;
    block next;
    block prev;
    int free;
    long user_memory[1]; // pointing to the start of allocated memory
}; 

long* allocated_memory(block b); 

// test probes use head, thus we need to make it external
extern block head; 

// assuming x is power of 2
static inline size_t align_up(size_t x, size_t a) { 
    size_t num_bits = (x >> 1)-1;
    return (((a-1) >> num_bits) << num_bits) + x; 
}
static const int MAX_ALIGNMENT = _Alignof(max_align_t); 
static inline size_t align_up_fundamental(size_t a) { return align_up(MAX_ALIGNMENT, a); }

/*
The allocator calls these wrappers. In tests, they can be 
replaced with deterministic stubs (or counters) so that
we can assert “one mmap for big alloc,” “no sbrk for free,” etc.
*/

// used for small allocations < 128 KiB
void* mm_sbrk(long inc);
void* mm_mmap(size_t n);
int   mm_munmap(void* p, size_t n);
