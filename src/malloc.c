#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

#include "internal.h"
#include "mm_debug.h"

#define CALLOC calloc
#define FREE free
#define MALLOC malloc   
#define REALLOC realloc   

#define align(x) (align_up_fundamental(x))
#define CURRENT_BRK mm_sbrk(0)
#define SIZE_OF_BLOCK (align_up_fundamental(sizeof(struct s_block)))
#define BLOCK_OFFSET (offsetof(struct s_block, start_of_alloc_mem))
#define ADDITIONAL_BYTES_FOR_SPLITTING MAX_ALIGNMENT

block head = NULL; 
static long allocated_bytes;

long* allocated_memory(block b) {
    return b->start_of_alloc_mem;
}

void *end(block b) {
    return (void*)((char*) allocated_memory(b) + b->size);
}

int do_ends_hold(block b) {
    return (end(b) == b->end_of_alloc_mem);
}

void deep_copy_block(block src, block to) {
    int* src_user_mem = (int*) allocated_memory(src);
    int* to_user_mem = (int*) allocated_memory(to);

    size_t min = src->size > to->size ? to->size : src->size;

    for (size_t i = 0; i < min; i++ )
    {
        to_user_mem[i] = src_user_mem[i];
    }
}

block extend_heap(block* last, size_t aligned_size){
    block brk = CURRENT_BRK;
    size_t total_bytes_to_allocate = SIZE_OF_BLOCK + aligned_size;
    if (mm_sbrk(total_bytes_to_allocate) == (void*) -1) {
        perror("failed to allocate memory");
        return NULL;
    }
    brk->size = aligned_size;
    brk->next = NULL;
    brk->prev= NULL;
    brk->end_of_alloc_mem = end(brk); 
    if (*last) {
        (*last)->next = (block)brk;
        brk->prev = *last;
    }
    allocated_bytes += total_bytes_to_allocate;
    return brk;
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

void fuse_next(block b){
    if (b->free == 0) {
        return;
    }
    if (b->next == NULL) {
        return;
    }
    block next = b->next;
    if(next->free) {
        b->size += SIZE_OF_BLOCK + next->size;
    }
    b->next = next->next;
    b->end_of_alloc_mem = end(b);
    if (next->next)
        next->next->prev = b;
}

void fuse_fwd(block b){
    if (b->free == 0) {
        return;
    }
    if (b->next == NULL) {
        return;
    }
    block cursor = b;
    MM_FUSE_FWD_CALL();
    while( cursor->next && cursor->next->free ) {
        b->size += SIZE_OF_BLOCK + cursor->next->size;
        cursor=cursor->next;
    }
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
    MM_FUSE_BWD_CALL();
    while (cursor->prev && cursor->prev->free) {
        block prev = cursor->prev;
        prev->size += SIZE_OF_BLOCK + cursor->size;
        cursor = prev;
    }
    cursor->next = next;
    if (next) 
        next->prev = cursor;
    *b = cursor;
    (*b)->end_of_alloc_mem = end(*b);
}

int is_addr_valid_heap_addr(void* p) {
    if (head == NULL) return 0;
    if ((void*) head > p || CURRENT_BRK < p) return 0;

    block blk = reconstruct_from_user_memory(p);
    if (!do_ends_hold(blk)) return 0;
    return (p == (void*)allocated_memory(blk));
}

int is_splittable(block blk, size_t aligned_size) {
    size_t remaining_size = blk->size - aligned_size;
    size_t min_splittable_total_block_size = SIZE_OF_BLOCK+ADDITIONAL_BYTES_FOR_SPLITTING;
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

block reconstruct_from_user_memory(void* p) {
    return (block)((char*)p - BLOCK_OFFSET);
}

/* ----- allocators ----- */

void* malloc(size_t);

// allocate memory for an array of length len consisting of 
// memory chunks of size size_of (of objects of size_of)
// properly aligned for object
// if succeeds, initialize all bytes to 0.
void* CALLOC(size_t len, size_t size_of) {
    MM_CALLOC_CALL();
    if (size_of != 0 && len > (SIZE_MAX / size_of)) {
        return NULL;
    }
    size_t total_bytes = len * size_of;
    unsigned char* p= (unsigned char*) MALLOC(total_bytes);
    if (p == NULL) {
        return NULL;
    }
    for (size_t i=0; i<total_bytes; i++) {
        p[i] = 0;
    }
    return p;
}

void FREE(void* p) {
    if (p == NULL) return;
    MM_FREE_CALL();
    if (!is_addr_valid_heap_addr(p)) {
        return;
    }
    block blk = reconstruct_from_user_memory(p);

    blk->free = 1;
    MM_FREED();

    fuse_fwd(blk);
    fuse_bwd(&blk);

    int is_at_tail = (!blk->next);
    int is_at_head = (!blk->prev);

    if (is_at_tail) {
        if (!is_at_head)
            blk->prev->next = NULL;
        else  
            head = NULL;
        
#ifdef ENABLE_MM_SBRK
    long back = SIZE_OF_BLOCK + blk->size; 
    void* old_tail = CURRENT_BRK;
    MM_ASSERT(allocated_bytes - back >= 0);
    void* ok = mm_sbrk(-back);
    if (ok == (void*) -1) {
        perror("error while releasing the tail");
        return; 
    }

    // iff we truly release some pages, then we can project the change
    if ((char*) old_tail > (char*) CURRENT_BRK)
        allocated_bytes -= back;
    #ifdef SHOW_SBRK_RELEASE_FAIL
        MM_ASSERT((char*) old_tail == (char*) CURRENT_BRK); 
    #endif
#elif defined(ENABLE_MM_BRK)
    void* ok = mm_brk(blk);
    if (ok == (void*) -1) {
        perror("error while releasing the tail");
        return;
    }
#endif
    }
}

void* MALLOC(size_t size) {
    MM_MALLOC_CALL();
    if (size == 0) return NULL; 

    block tail = head;
    size_t aligned_size = align(size); 
    block blk;

    if (head == NULL) {
        blk = extend_heap(&tail, aligned_size); 
        head = blk;
    } else {
        blk = first_fit_find(head, &tail, aligned_size);
        if (blk == NULL) {
            // if failed nothing to do, if not block is not larger than size
            blk = extend_heap(&tail, aligned_size); 
        } 
    }

    if (blk == NULL) {
        return NULL;
    }

    blk->free = 0;

    if (is_splittable(blk, aligned_size)) {
        split_block(blk, aligned_size);
    }
    return (void*)allocated_memory(blk);
} 

void* realloc(void* p, size_t size){
    MM_REALLOC_CALL();
    // if we don't have anywhere to realloc, it is effectively a malloc
    if (p == NULL) return malloc(size); 

    if (!is_addr_valid_heap_addr(p)) return NULL;

    block blk = reconstruct_from_user_memory(p);

    // the block must be aligned
    size = align_up_fundamental(size);

    if (blk->size == size ) return p;

    if (blk->size > size) {
        MM_REALLOC_ENOUGH_SIZE();
        if (is_splittable(blk, size)) split_block(blk, size);
        return p;
    }

    while (blk->next && blk->size < size) {
        fuse_next(blk);
    }
    // we have done all that work for nothing...
    if (blk->size < size) {
        void* n = MALLOC(size);
        if (n == NULL) {return p;}
        block blk_n = reconstruct_from_user_memory(n);
        block blk_p = reconstruct_from_user_memory(p);
        deep_copy_block(blk_p, blk_n);
        free(p);
        return n;
    }
    else if (is_splittable(blk, size)) split_block(blk,size);

    return p;
}
