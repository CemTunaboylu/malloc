#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include "internal.h"
#include "mm_debug.h"

#define MIN_SPLIT_REMAINING_PAYLOAD (MAX_ALIGNMENT)

size_t SIZE_OF_BLOCK;

__attribute__((constructor))
void init_aligned_size_of_block(void) {
    SIZE_OF_BLOCK = align(sizeof(struct s_block));
}

/* ----- mmap support ----- */

#define MMAPPED 0x1

void* allocated_memory(block b) {
    char* e = (char*)b + SIZE_OF_BLOCK;
    return ((void*)e);
}

void *end(block b) {
    return (void*)((char*) allocated_memory(b) + b->size);}

int do_ends_hold(block b) {
    return (end(b) == b->end_of_alloc_mem);
}

void deep_copy_block(block src, block to) {
    // int* seems to be UB, to be safe and truly type agnostic, we treat it byte by byte
    unsigned char* src_user_mem = (unsigned char*) allocated_memory(src);
    unsigned char* to_user_mem = (unsigned char*) allocated_memory(to);

    size_t min = src->size < to->size ? src->size : to->size;
    // hopefully the compiler will vectorize this loop, unroll it and use wider loads/stores internally to optimize
    for (size_t i = 0; i < min; i++ )
    {
        to_user_mem[i] = src_user_mem[i];
    }
}

/* ----- fusion ----- */ 

int fuse_next(block b){
    if (b->next == NULL) {
        return -1;
    }
    block next = b->next;
    if(!next->free) {
        return -1;
    }
    b->size += SIZE_OF_BLOCK + next->size;
    b->next = next->next;
    b->end_of_alloc_mem = end(b);
    if (next->next)
        next->next->prev = b;
    return 0;
}

void fuse_fwd(block b){
    if (b->free == 0) {
        return;
    }
    if (b->next == NULL || b->next->free == 0) {
        return;
    }
    block cursor = b;
    do {
        b->size += SIZE_OF_BLOCK + cursor->next->size;
        cursor=cursor->next;
        MM_FUSE_FWD_CALL();
    } while( cursor->next && cursor->next->free );
    b->next=cursor->next;
    b->end_of_alloc_mem = end(b);
    if (cursor->next)
        cursor->next->prev = b;
}

void fuse_bwd(block* b){
    if ((*b)->free == 0) {
        return;
    }
    if ((*b)->prev == NULL) {
        return;
    }
    block cursor = *b;
    block next = (*b)->next;
    while (cursor->prev && cursor->prev->free) {
        block prev = cursor->prev;
        prev->size += SIZE_OF_BLOCK + cursor->size;
        cursor = prev;
        MM_FUSE_BWD_CALL();
    }
    cursor->next = next;
    if (next) 
        next->prev = cursor;
    *b = cursor;
    (*b)->end_of_alloc_mem = end(*b);
}

int is_next_fusable(block b) {
    block next = b->next;
    return ((next != NULL) && (next->free == 1));
}


/* ----- LSB encoding ------ */ 

size_t get_real_size(block b){
    return (b->size & (~MMAPPED));
}

int is_mmapped(block b) {
    return (b->size & MMAPPED) > 0;
}

/* ----- splitting ------ */ 

int is_splittable(block blk, size_t aligned_size) {
    size_t remaining_size = blk->size - aligned_size;
    size_t min_splittable_total_block_size = SIZE_OF_BLOCK + MIN_SPLIT_REMAINING_PAYLOAD;
    return (remaining_size > min_splittable_total_block_size); 
}

void split_block(block b, size_t aligned_size_to_shrink){
    block rem_free = (block)((char*)allocated_memory(b) + aligned_size_to_shrink);
    rem_free->size =  b->size - aligned_size_to_shrink - SIZE_OF_BLOCK;
    rem_free->next = b->next;
    rem_free->prev= b;
    if (b->next) {
        b->next->prev = rem_free;
    }
    rem_free->free = 1;
    rem_free->end_of_alloc_mem = end(rem_free);
    b->size = aligned_size_to_shrink;
    b->next = rem_free;
    b->end_of_alloc_mem = end(b);
}

block reconstruct_from_user_memory(const void* p) {
    char* b = (char*)p - SIZE_OF_BLOCK; 
    return ((block)b);
}

