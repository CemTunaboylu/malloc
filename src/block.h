#pragma once

#include <sys/types.h>
#include <stdint.h>

// since blocks are always used with pointers, we define the type as a pointer type
typedef struct s_block *block;

// since we are aligned, we can use the least-significant-bits to encode information
#define __LSB_ENCODED

struct s_block {
    size_t __LSB_ENCODED size;
    block next;
    block prev;
    int free;
    // points to end of the allocated user memory to add another check 
    // for reconstructing the block from given pointer
    void* end_of_alloc_mem; 
}; 


block reconstruct_from_user_memory(const void*); 
int do_ends_hold(block);
int fuse_next(block);
int is_mmapped(block);
int is_next_fusable(block);
int is_splittable(block, size_t);
size_t get_real_size(block);
void deep_copy_block(block, block);
void fuse_bwd(block*);
void fuse_fwd(block);
void split_block(block, size_t);
void* allocated_memory(block); 
void* end(block);
