#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

#include "internal.h"

#define CURRENT_BRK mm_sbrk(0)
#define SIZE_OF_BLOCK sizeof(struct s_block)

#define align4(x) ((((x-1) >> 2) << 2) + 4)

block head = NULL; 

void split_block(block b, size_t aligned_size_to_shrink){
    // b->data is *char so the pointer arithmetic below has 4 bytes precision 
    block rem_free = (block)(b->data + aligned_size_to_shrink);

    rem_free->size =  b->size - aligned_size_to_shrink - SIZE_OF_BLOCK;
    rem_free->next = b->next;
    rem_free->prev= b;
    if (b->next) {
        b->next->prev = rem_free;
    }
    rem_free->free = 1;

    b->size = aligned_size_to_shrink;
    b->next = rem_free;
}

void fuse_fwd(block b){
    for (block cursor=b; cursor->next && cursor->next->free; cursor=cursor->next) {
        b->size = SIZE_OF_BLOCK + cursor->next->size;
        b->next = cursor;
        cursor->prev=b;
    }
}

void fuse_bwd(block* b){
    if ((*b)->free) {
        return;
    }
    block cursor = *b;
    block next = (*b)->next;
    for (; cursor->prev && cursor->free; cursor=cursor->prev) {
        block prev = cursor->prev;
        prev->size = SIZE_OF_BLOCK + cursor->size;
        cursor = prev;
    }
    cursor->next = next;
    *b = cursor;
}

block first_fit_find(block head, block* tail, size_t aligned_size){
    block curr = head;
    // as long as we have block at hand, and it's either NOT free or NOT big enough
    while (curr && !(curr->free && curr->size >= aligned_size)) {
        // if we cannot find a suitable block, we keep track of the last block 
        // so that malloc can append a new block at the end 
        *tail = curr;
        curr = curr->next;
    }
    return curr;
}

block extend_heap(block* last, size_t aligned_size){
    block brk = CURRENT_BRK;
    if (mm_sbrk(SIZE_OF_BLOCK + aligned_size) == (void*) -1) {
        perror("failed to allocate memory");
        return NULL;
    }
    brk->size = aligned_size;
    brk->next = NULL;
    brk->prev= NULL;
    if (*last) {
        (*last)->next = (block)brk;
        brk->prev = *last;
    }
    brk->free = 0;
    return brk;
}

void* malloc(size_t size) {
    block tail = head;
    size_t aligned_size = align4(size); 
    block blk = first_fit_find(head, &tail, aligned_size);
    if (blk == NULL) {
        // if failed nothing to do, if not block is not larger than size
        blk = extend_heap(&tail, aligned_size); 
    } 
    if (blk == NULL) {
        return NULL;
    }
    // assert alignment
    // MM_ASSERT(is_aligned(blk));
    blk->free = 0;
    // if size is larger such that it can allocate at least 
    // a new block and an additional 4 bytes, split the block
    if ((blk->size-aligned_size) > (SIZE_OF_BLOCK+4)) {
        split_block(blk, aligned_size);
    }
    return (void*)blk->data;
} 

// allocate memory for an array of length len consisting of 
// memory chunks of size size_of (of objects of size_of)
// properly aligned for object
// if succeeds, initialize all bytes to 0.
void* calloc(size_t len, size_t size_of) {
    if (size_of != 0 && len > (SIZE_MAX / size_of)) {
        return NULL;
    }
    size_t total_bytes = len * size_of;
    unsigned char* p= (unsigned char*) malloc(total_bytes);
    if (p == NULL) {
        return NULL;
    }
    for (size_t i=0; i<total_bytes; i++) {
        p[i] = 0;
    }
    return p;
}