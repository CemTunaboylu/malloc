#ifdef TESTING
#include <internal.h>

extern block head;

block _mm_block_header(void){
    return head;
}

// Global counter for bytes obtained from the OS during TESTING builds.
static size_t total_global_bytes_from_os = 0;
size_t _mm_bytes_obtained_from_os(void) { return total_global_bytes_from_os; }

// Predicate type: functions that inspect a block and return non-zero if it matches.
typedef int (*block_predicate_t)(block* b);

// Example predicates used by tests.
static int pred_is_free(block b) { return b->free; }
static int pred_is_used(block b) { return !b->free; }

// Count blocks that satisfy a given predicate.
size_t _mm_blocks(int (*predicate)(block)) {
    size_t c = 0;
    for (block b = head; b; b = b->next) {
        if (predicate(b)) c++;
    } 
    return c;
}

size_t _mm_free_blocks(void)     { return _mm_blocks(pred_is_free); }
size_t _mm_non_free_blocks(void) { return _mm_blocks(pred_is_used); }

#endif
