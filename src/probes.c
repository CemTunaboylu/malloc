#ifdef TESTING
#include <internal.h>
#include <malloc/malloc.h>

extern struct Arena a_head;

BlockPtr _mm_block_header(void) { return a_head.head; }

// Global counter for bytes obtained from the OS during TESTING builds.
static size_t total_global_bytes_from_os = 0;
size_t _mm_bytes_obtained_from_os(void) { return total_global_bytes_from_os; }

// Predicate type: functions that inspect a block and return non-zero if it
// matches.
typedef int (*block_predicate_t)(BlockPtr *b);

// Example predicates used by tests.
static int pred_is_free(BlockPtr b) { return is_free(b); }
static int pred_is_used(BlockPtr b) { return !is_free(b); }
static int pred_true(BlockPtr b) {
  (void)b;
  return 1;
}

// Count blocks that satisfy a given predicate.
size_t _mm_blocks(int (*predicate)(BlockPtr)) {
  if (a_head.head == NULL)
    return 0;
  size_t c = 0;
  for (BlockPtr b = a_head.head; !is_at_brk(b); b = next(b)) {
    if (predicate(b))
      c++;
  }
  return c;
}

size_t _mm_free_blocks(void) { return _mm_blocks(pred_is_free); }
size_t _mm_non_free_blocks(void) { return _mm_blocks(pred_is_used); }
size_t _mm_total_blocks(void) { return _mm_blocks(pred_true); }

void _mm_tear_down_allocator(void) {
  if (a_head.head == NULL)
    return;
  for (BlockPtr b = a_head.head; !is_at_brk(b); b = next(b)) {
    free(b);
  }
}
#endif
