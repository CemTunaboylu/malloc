#pragma once

#include <sys/types.h>
#include <unistd.h>

// since blocks are always used with pointers, we define the type as a pointer type
typedef struct s_block *block;

// structs ara aligned by default, so cannot make free smaller at this point
// block is 32-bit aligned until data
struct s_block {
    size_t size;
    block next;
    block prev;
    int free;
    char data[1]; // pointing to the start of allocated memory
}; 

// test probes use head, thus we need to make it external
extern block head; 

/*
Make the allocator call these wrappers.
In tests, they can be replaced with deterministic stubs (or counters)
so that we can assert “one mmap for big alloc,” “no sbrk for free,” etc.
*/

// used for small allocations < 128 KiB
void* mm_sbrk(long inc);
void* mm_mmap(size_t n);
int   mm_munmap(void* p, size_t n);