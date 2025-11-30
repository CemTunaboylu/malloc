#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

#include "internal.h"
#include "block.h"
#include "mm_debug.h"

/* NOTE:
    We define CALLOC/FREE/MALLOC/REALLOC macros so that:
    - inside this file we can call MALLOC(...) and FREE(...)
    - but after preprocessing, these become the real exported malloc/calloc/etc.
    This lets us override the libc allocator cleanly in one translation unit.
*/

#ifdef TESTING 
    #define CALLOC mm_calloc
    #define FREE mm_free
    #define MALLOC mm_malloc
    #define REALLOC mm_realloc
#else 
    #define CALLOC calloc
    #define FREE free
    #define MALLOC malloc   
    #define REALLOC realloc   
#endif

#define CURRENT_BRK mm_sbrk(0)

void* MALLOC(size_t);

extern size_t SIZE_OF_BLOCK;

/* ----- arena ----- */

ArenaPtr a_head;
static char head_buffer[sizeof(Arena)] = {0}; 

__attribute__((constructor))
void init_arena_head(void) {
    a_head = (ArenaPtr) &head_buffer;
}

// in case update < 0, it is assumed that |update| bytes are released i.e. returned to OS/munmapped 
void allocated_bytes_update(ArenaPtr ar_ptr, int update) {
    size_t allocated_bytes = ar_ptr->total_bytes_allocated;
    if (update >= 0) {
        allocated_bytes += update;
    } else {
        size_t decrement = (size_t)(-update);
        MM_ASSERT(allocated_bytes >= decrement);
        allocated_bytes -= decrement;
    }
     ar_ptr->total_bytes_allocated = allocated_bytes;
}

BlockPtr extend_heap(ArenaPtr ar_ptr, size_t aligned_size){
    BlockPtr brk = CURRENT_BRK;
    size_t total_bytes_to_allocate = SIZE_OF_BLOCK + aligned_size;
    void* requested = mm_sbrk(total_bytes_to_allocate);
    if ( requested == (void*) -1) {
        perror("failed to allocate memory");
        return NULL;
    }
    MM_ASSERT((void*) brk == requested);
    brk->size = aligned_size;
    brk->next = NULL;
    brk->prev= NULL;
    brk->end_of_alloc_mem = end(brk); 
    // if I have last, append this block there
    if (ar_ptr->tail) {
        ar_ptr->tail->next = (BlockPtr)brk;
        brk->prev = ar_ptr->tail;
    }
    ar_ptr->tail= brk;
    allocated_bytes_update(ar_ptr, total_bytes_to_allocate);
    return brk;
}

BlockPtr first_fit_find(ArenaPtr ar_ptr, size_t aligned_size){
    BlockPtr curr = ar_ptr->head;
    // as long as we have block at hand, and it's either NOT free or NOT big enough
    while (curr && !(curr->free && curr->size >= aligned_size)) {
        curr = curr->next;
    }
    return curr;
}

int is_addr_valid_heap_addr(ArenaPtr ar_ptr, void* p) {
    BlockPtr head = ar_ptr->head;
    BlockPtr tail = ar_ptr->tail;
    if (head == NULL) return 0;

    void* the_end_of_arena_tail = (char*)tail + (tail->size + SIZE_OF_BLOCK); 
    if ((void*) head > p || the_end_of_arena_tail < p) return 0;

    BlockPtr blk = reconstruct_from_user_memory(p);
    if (!do_ends_hold(blk)) return 0;
    return (p == (void*)allocated_memory(blk));
}

/* ----- allocators ----- */

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
    if (!is_addr_valid_heap_addr(a_head, p)) {
        return;
    }
    BlockPtr blk = reconstruct_from_user_memory((const void*)p);

    // guard for double free
    if (blk->free == 1) {
        #ifdef TESTING 
            MM_ASSERT(0);
        #else
            debug_write_str("double free: ");
            debug_write_ptr(p);
            debug_write_str("\n");
        #endif
        return;
    }

    blk->free = 1;
    MM_FREED();

    fuse_fwd(blk);
    fuse_bwd(&blk);

    int is_at_tail = (!blk->next);
    int is_at_head = (!blk->prev);

    if (is_at_tail) {
        size_t back = SIZE_OF_BLOCK + blk->size; 
        // TODO:  we must find delegate freeing to which ever arena this chunk is from
        void* old_tail = CURRENT_BRK;
        BlockPtr prev_of_tail = a_head->tail->prev;
        if (mm_sbrk(-back) == (void*) -1) {
            perror("error while releasing the tail");
            return; 
        }

        // iff we truly release some pages, then we can project the change
        MM_ASSERT((char*) old_tail > (char*) CURRENT_BRK); 
        MM_RELEASED();
        MM_ASSERT(a_head->total_bytes_allocated >= back);
        a_head->tail = prev_of_tail;
        allocated_bytes_update(a_head, -back);
        if (!is_at_head)
            a_head->tail->next = NULL;
        else  
            a_head->head = NULL;
    }
}

void* MALLOC(size_t size) {
    MM_MALLOC_CALL();
    if (size == 0) return NULL; 

    BlockPtr head = a_head->head;
    size_t aligned_size = align(size); 
    BlockPtr blk;

    if (head == NULL) {
        blk = extend_heap(a_head, aligned_size); 
        head = blk;
        a_head->head = head;
        a_head->tail = head;
    } else {
        blk = first_fit_find(a_head, aligned_size);
        if (blk == NULL) {
            // if failed nothing to do, if not block is not larger than size
            blk = extend_heap(a_head, aligned_size); 
        } 
    }

    if (blk == NULL) {
        return NULL;
    }

    blk->free = 0;
    if (is_splittable(blk, aligned_size)) {
        split_block(blk, aligned_size);
        if (a_head->tail == blk) {
            a_head->tail = blk->next;
        }
    }
    return (void*)allocated_memory(blk);
} 

void* REALLOC(void* p, size_t size){
    MM_REALLOC_CALL();
    // if we don't have anywhere to realloc, it is effectively a malloc
    if (p == NULL) return MALLOC(size); 

    if (size == 0) {
        FREE(p);
        return NULL;
    }
    if (!is_addr_valid_heap_addr(a_head, p)) return NULL;

    BlockPtr blk = reconstruct_from_user_memory((const void*)p);

    // the block must be aligned
    size = align_up_fundamental(size);

    if (blk->size == size ) return p;

    // try to grow in-place
    while (blk->size < size && is_next_fusable(blk)) {
        if (fuse_next(blk) == -1) break;
    }
    // could not grow in place enough, allocate new and copy, free old
    if (blk->size < size) {
        void* n = MALLOC(size);
        if (n == NULL) {return p;} // current policy: keep old ptr in case out-of-memory 
        BlockPtr blk_n = reconstruct_from_user_memory((const void*)n);
        BlockPtr blk_p = reconstruct_from_user_memory((const void*)p);
        deep_copy_block(blk_p, blk_n);
        FREE(p);
        return n;
    }
    // grew enough but may need splitting now
    else if (is_splittable(blk, size)) {
        MM_REALLOC_ENOUGH_SIZE();
        split_block(blk,size);
    } 

    return p;
}
