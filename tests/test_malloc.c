#ifdef TESTING

#include <stdalign.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

static void pre_test_sanity(void);
static void post_test_sanity(void);

// run tests in the same process, no fork/exec per test
#define TEST_NO_EXEC 1

#define TEST_INIT pre_test_sanity()
#define TEST_FINI post_test_sanity()

#include "acutest.h"
#include "mm_debug.h"
#include <arena.h>
#include <block.h>
#include <internal.h>

size_t markers[NUM_MARKERS] = {0};

extern struct Arena a_head;
extern struct MMapArena ma_head;
extern size_t SIZE_OF_BLOCK;

extern void *mm_calloc(size_t, size_t);
extern void mm_free(void *);
extern void *mm_malloc(size_t);
extern void *mm_realloc(void *, size_t);

#define CALLOC_UNDER_TESTING mm_calloc
#define FREE_UNDER_TESTING mm_free
#define MALLOC_UNDER_TESTING mm_malloc
#define REALLOC_UNDER_TESTING mm_realloc
#define CURRENT_BRK mm_sbrk(0)

#define POPULATE_PTR_ARR_VIA_MALLOC(num_blocks, ptrs, block_size)              \
  {                                                                            \
    for (size_t i = 0; i < num_blocks; i++) {                                  \
      void *p = ensuring_malloc(block_size);                                   \
      TEST_ASSERT(NULL != p);                                                  \
      ptrs[i] = p;                                                             \
    }                                                                          \
    for (size_t i = 1; i < num_blocks; i++) {                                  \
      TEST_ASSERT(ptrs[i] != ptrs[i - 1]);                                     \
    }                                                                          \
  }

#define MARK_AS_FREE_BLKS_UNTIL(num_blocks, ptrs)                              \
  {                                                                            \
    for (size_t i = 0; i < num_blocks; i++) {                                  \
      void *p = ptrs[i];                                                       \
      BlockPtr blk = reconstruct_from_user_memory(p);                          \
      mark_as_free(blk);                                                       \
      TEST_ASSERT_(get_true_size(blk) == *((size_t *)next(blk) - 1),           \
                   "true size is not put in the footer");                      \
    }                                                                          \
  }

#define MARK_AS_FREE_BLKS_EXCEPT(num_blocks, ptrs, except)                     \
  {                                                                            \
    MARK_AS_FREE_BLKS_UNTIL(except, ptrs);                                     \
    MARK_AS_FREE_BLKS_UNTIL(num_blocks - except - 1,                           \
                            (void *)(ptrs + except + 1));                      \
  }

#define FREE_BLKS_EXCEPT(num_blocks, ptrs, except)                             \
  {                                                                            \
    for (size_t i = 0; i < num_blocks; i++) {                                  \
      if (i == except)                                                         \
        continue;                                                              \
      ensuring_free(ptrs[i]);                                                  \
    }                                                                          \
  }

#define SET_BYTES_INCREMENTALLY(ptr, blk_size)                                 \
  {                                                                            \
    for (size_t i = 0; i < blk_size; i++) {                                    \
      ptr[i] = (char)i;                                                        \
    }                                                                          \
  }

#define ASSERT_BYTES_ARE_INCREMENTALLY_SET(ptr, blk_size)                      \
  {                                                                            \
    for (size_t i = 0; i < blk_size; i++) {                                    \
      TEST_ASSERT_(ptr[i] == (char)i, "%lu th byte %c is not equal to %c", i,  \
                   ptr[i], (char)i);                                           \
    }                                                                          \
  }

#define ASSERT_FASTBIN_HAS(f_idx, num)                                         \
  {                                                                            \
    const BlockPtr head = a_head.fastbins[f_idx];                              \
    if (num == 0) {                                                            \
      TEST_ASSERT_(NULL == head, "fast bin head must be NULL");                \
    } else if (NULL == head) {                                                 \
      TEST_ASSERT_(NULL == head, "fast bin head must NOT be NULL");            \
    } else {                                                                   \
      BlockPtr cursor = head->next;                                            \
      size_t counter = 1;                                                      \
      while (NULL != cursor && NULL != cursor->next) {                         \
        counter += 1;                                                          \
        cursor = cursor->next;                                                 \
      }                                                                        \
      TEST_ASSERT_(counter == num, "fast bin must have %lu chunks, got %lu",   \
                   num, counter);                                              \
    }                                                                          \
  }

#define ASSERT_FASTBINS_EMPTY()                                                \
  for (size_t f_idx = 0; f_idx < NUM_FAST_BINS; f_idx++) {                     \
    TEST_ASSERT_(NULL == a_head.fastbins[f_idx],                               \
                 "fastbins[%lu] should have been empty", f_idx);               \
  }

#define ASSERT_UNSORTED_BIN_EMPTY()                                            \
  {                                                                            \
    TEST_ASSERT_(IS_LONE_SENTINEL(BLK_PTR_OF_UNSORTED(a_head)),                \
                 "unsorted bin should have been empty");                       \
  }

#ifdef ENABLE_LOG
#define LOG(...)                                                               \
  do {                                                                         \
    logf_nonalloc(__VA_ARGS__);                                                \
    print_list_into_test_file();                                               \
  } while (0)
#else
#define LOG(...)                                                               \
  do {                                                                         \
  } while (0)
#endif

static void check_and_reset_all_markers_unset(void) {
  for (size_t ix = 0; ix < NUM_MARKERS; ix++) {
    TEST_CHECK_(0 == markers[ix],
                "marker %lu should have been 0, but it is %lu", ix,
                markers[ix]);
    markers[ix] = 0;
  }
}

void ensuring_free(void *p);

static void tear_heap_down(void) {
  const size_t pre_num_in_unsorted = num_blocks_in_unsorted_bin(&a_head);
  consolidate_fastbins();
  size_t num_in_unsorted = num_blocks_in_unsorted_bin(&a_head);
  const size_t diff = (num_in_unsorted - pre_num_in_unsorted);
  TEST_CHECK_(markers[CONSOLIDATED] >= diff, "consolidated %lu != %lu",
              markers[CONSOLIDATED], diff);
  MM_RESET_MARKER(CONSOLIDATED);
  TEST_CHECK(markers[PUT_IN_UNSORTED_BIN] >= diff);
  MM_RESET_MARKER(PUT_IN_UNSORTED_BIN);
  // Everything in fastbins are put in unsorted bin. Let's ask for a memory that
  // is way too big so that all will be put in their appropriate bins (small or
  // large bins).
  BlockPtr blk = search_in_unsorted_consolidating((size_t)MIN_CAP_FOR_MMAP);
  TEST_CHECK_(
      NULL == blk,
      "[tear_down] search_in_unsorted_consolidating should have returned NULL");
  BlockPtr unsorted_sentinel = BLK_PTR_OF_UNSORTED(a_head);
  TEST_CHECK_(IS_LONE_SENTINEL(unsorted_sentinel),
              "[tear_down] unsorted bin should have been emptied");

  BlockPtr head = a_head.head;
  if (head) {
    fuse_fwd(head);
    remove_from_linkedlist(head);
    if (!is_free(head)) {
      ensuring_free(allocated_memory(head));
    } else {
      release(head);
    }
    if (num_in_unsorted > 0)
      num_in_unsorted--;
    MM_ASSERT_MARKER(RELEASED, 1);
    TEST_CHECK_(markers[FUSE_FWD_CALLED] >= num_in_unsorted,
                "fuse_fwd %lu != %lu", markers[FUSE_FWD_CALLED],
                num_in_unsorted);
    MM_RESET_MARKER(FUSE_FWD_CALLED);
    MM_RESET_MARKER(FUSE_BWD_CALLED);
  }
}

static void check_main_arena_bins_are_empty(void) {
  for (size_t i = 0; i < SLOTS_FOR_BLOCK_OFFSET_ALIGNMENT; i++) {
    TEST_CHECK_(0 == a_head.bins[i], "block offset must have been null");
  }
  ASSERT_UNSORTED_BIN_EMPTY();
  ASSERT_FASTBINS_EMPTY();

  BlockPtr bin;
  for (size_t i = 0; i < NUM_BINS; i++) {
    bin = BLK_PTR_IN_BIN_AT(a_head, i);
    TEST_CHECK_(IS_LONE_SENTINEL(bin), "bin[%lu] must point to itself", i);
  }
}

static void assert_all_arena_heads_are_null(void) {
  TEST_ASSERT(NULL == a_head.head);
  TEST_ASSERT(NULL == a_head.tail);
  TEST_ASSERT(0 == ma_head.num_mmapped_regions);
  TEST_ASSERT(0 == ma_head.total_bytes_allocated);
}

static void assert_total_number_of_blocks(const size_t num) {
  const size_t total_blocks = _mm_total_blocks();
  TEST_ASSERT_(total_blocks == num,
               "total number of blocks must be %lu, got %lu instead", num,
               total_blocks);
}

static void assert_empty_heap(void) {
  check_main_arena_bins_are_empty();
  assert_all_arena_heads_are_null();
  assert_total_number_of_blocks(0);
}

static void pre_test_sanity(void) {
  LOG("\t pre_test_sanity \n");
  check_and_reset_all_markers_unset();
}

static void post_test_sanity(void) {
  LOG("\t post_test_sanity \n");
  tear_heap_down();
  assert_empty_heap();
  check_and_reset_all_markers_unset();
}

static inline int is_aligned(void *p) {
  return ((uintptr_t)p % _Alignof(max_align_t)) == 0;
}

void check_block_header_shape(BlockPtr head) {
  TEST_CHECK(sizeof(head->size) == 8);
  TEST_CHECK(is_aligned(head));
}

BlockPtr recons_blk_from_user_mem_ptr(void *p) {
  BlockPtr head = reconstruct_from_user_memory((const void *)p);
  check_block_header_shape(head);
  TEST_CHECK_((void *)allocated_memory(head) == p,
              "head=%p, p=%p, alloc(head)=%p", (void *)head, p,
              (void *)allocated_memory(head));
  return head;
}

void *ensuring_calloc(size_t len, size_t size_of) {
  MM_RESET_MARKER(CALLOC_CALLED);
  MM_RESET_MARKER(MALLOC_CALLED);
  int *q = (int *)CALLOC_UNDER_TESTING(len, size_of);
  MM_ASSERT_MARKER(CALLOC_CALLED, 1);
  MM_ASSERT_MARKER(MALLOC_CALLED, 1);
  return q;
}

void ensure_freed(void) { MM_ASSERT_MARKER(FREED, 1); }

void ensuring_free(void *p) {
  MM_RESET_MARKER(FREE_CALLED);
  FREE_UNDER_TESTING(p);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  ensure_freed();
}

void *ensuring_malloc(size_t size) {
  MM_RESET_MARKER(MALLOC_CALLED);
  void *p = MALLOC_UNDER_TESTING(size);
  MM_ASSERT_MARKER(MALLOC_CALLED, 1);
  return p;
}

void *ensuring_realloc(void *p, size_t size) {
  MM_RESET_MARKER(REALLOC_CALLED);
  void *r = REALLOC_UNDER_TESTING(p, size);
  MM_ASSERT_MARKER(REALLOC_CALLED, 1);
  return r;
}

static void test_align(void) {
  for (size_t any = 1; any <= MAX_ALIGNMENT; any++)
    TEST_ASSERT((MAX_ALIGNMENT) == align(any));

  const size_t two_max_alg = (MAX_ALIGNMENT * 2);
  for (size_t any = MAX_ALIGNMENT + 1; any <= two_max_alg; any++)
    TEST_ASSERT_(align(any) == two_max_alg, "%lu != %lu ", any, align(any));

  const size_t multiple = MAX_ALIGNMENT * 4;
  TEST_ASSERT(align(multiple) == multiple);

  size_t large = MAX_ALIGNMENT * 4 - (MAX_ALIGNMENT / 2);
  TEST_ASSERT((MAX_ALIGNMENT * 4) == align(large));
}

static void test_encode(void) {
  size_t size = 3;
  size_t aligned_size = align(size);
  void *p = ensuring_malloc(size);
  TEST_ASSERT(NULL != p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  BlockPtr b = reconstruct_from_user_memory(p);
  TEST_ASSERT(!is_free(b));
  TEST_ASSERT(!is_mmapped(b));
  TEST_ASSERT_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
               aligned_size);

  mark_as_free(b);
  TEST_ASSERT(is_free(b));
  TEST_ASSERT(!is_mmapped(b));
  TEST_ASSERT_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
               aligned_size);

  mark_as_used(b);
  TEST_ASSERT(!is_free(b));
  TEST_ASSERT(!is_mmapped(b));
  TEST_ASSERT_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
               aligned_size);

  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  assert_empty_heap();
}

static void test_true_size(void) {
  size_t size = 3;
  size_t aligned_size = align(size);
  void *p = ensuring_malloc(size);
  TEST_ASSERT(NULL != p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  BlockPtr b = reconstruct_from_user_memory(p);
  TEST_ASSERT(!is_free(b));
  TEST_ASSERT_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
               aligned_size);

  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  assert_empty_heap();
}

static void test_invalid_addr_outside_before_for_is_valid_addr(void) {
  void *p = ensuring_malloc(1);
  TEST_ASSERT(NULL != p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  BlockPtr head = a_head.head;
  void *invalid = (char *)head + sizeof(struct SBlock) * 9;
  TEST_ASSERT_(
      get_block_from_main_arena(&a_head, invalid) == NULL,
      "address %p should have been invalid since it is before list head %p",
      invalid, (void *)head);
  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  assert_empty_heap();
}

static void test_invalid_addr_outside_after_for_is_valid_addr(void) {
  void *p = ensuring_malloc(1);
  TEST_ASSERT(NULL != p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  void *invalid = (char *)p + sizeof(struct SBlock);
  TEST_ASSERT(get_block_from_main_arena(&a_head, invalid) == NULL);
  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  assert_empty_heap();
}

static void test_valid_addr_for_is_valid_addr(void) {
  void *p = ensuring_malloc(1);
  TEST_ASSERT(NULL != p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  TEST_ASSERT(get_block_from_main_arena(&a_head, p));
  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  assert_empty_heap();
}

// malloc(0) is expected to return NULL pointer
static void test_malloc_zero(void) {
  void *p = ensuring_malloc(0);
  TEST_ASSERT(NULL == p);
  FREE_UNDER_TESTING(p);
  MM_ASSERT_MARKER(FREE_CALLED, 0);
  MM_ASSERT_MARKER(FREED, 0);
  assert_empty_heap();
}

static void test_first_malloc_new_head(void) {
  TEST_ASSERT(a_head.head == NULL);
  const size_t size = 5;
  void *p = ensuring_malloc(size);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  TEST_ASSERT(NULL != p);
  TEST_ASSERT(NULL != a_head.head);
  BlockPtr b = recons_blk_from_user_mem_ptr(p);
  const size_t aligned_size = align(size);
  TEST_ASSERT_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
               aligned_size);
  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  TEST_ASSERT(NULL == a_head.head);
  assert_empty_heap();
}

static void test_header_alignment_and_size(void) {
  size_t requested_bytes = 1;
  void *p = ensuring_malloc(requested_bytes);
  TEST_ASSERT(NULL != p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  BlockPtr head = recons_blk_from_user_mem_ptr(p);
  TEST_ASSERT(get_true_size(head) == align(requested_bytes));
  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  assert_empty_heap();
}

static void test_malloc_allocated_memory_aligned(void) {
  const size_t size = 31;
  void *p = ensuring_malloc(size);
  TEST_ASSERT(NULL != p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  TEST_ASSERT(is_aligned(p));

  BlockPtr b = recons_blk_from_user_mem_ptr(p);
  const size_t aligned_size = align(size);
  TEST_ASSERT_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
               aligned_size);

  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  assert_empty_heap();
}

static void test_calloc_zero_fill(void) {
  size_t n = 16, sz = 8;
  unsigned char *p = (unsigned char *)ensuring_calloc(n, sz);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  TEST_ASSERT(NULL != p);
  for (size_t i = 0; i < n * sz; ++i)
    TEST_ASSERT(0 == p[i]);

  BlockPtr b = recons_blk_from_user_mem_ptr(p);
  const size_t aligned_size = align(n * sz);
  TEST_ASSERT_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
               aligned_size);

  ensuring_free(p);
  MM_ASSERT_MARKER(RELEASED, 1);
  assert_empty_heap();
}

static void test_forward_fusion_2_blocks(void) {
  LOG("=== %s: start ===\n", __func__);

  size_t num_blocks = 3;
  void *ptrs[num_blocks];
  size_t base_bytes = 10;

  POPULATE_PTR_ARR_VIA_MALLOC(num_blocks, ptrs, base_bytes);
  MM_ASSERT_MARKER(BY_SBRKING, num_blocks);

  LOG("\tpost-malloc ===\n");

  MARK_AS_FREE_BLKS_UNTIL(num_blocks, ptrs);
  BlockPtr b = recons_blk_from_user_mem_ptr(ptrs[0]);
  mark_as_used(b);

  LOG("\tafter artificially freeing blocks ===\n");

  void *p = ptrs[0];
  BlockPtr blk = reconstruct_from_user_memory(p);

  fuse_fwd(blk);
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, num_blocks - 1);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 0);
  ASSERT_FASTBINS_EMPTY();
  ASSERT_UNSORTED_BIN_EMPTY();

  LOG("\tpost-fwd-fusion ===\n");

  size_t aligned_base_bytes = align(base_bytes);
  size_t expected_size =
      (aligned_base_bytes * num_blocks + (SIZE_OF_BLOCK * (num_blocks - 1)));
  TEST_ASSERT_(get_true_size(blk) == expected_size, "size must be %lu, got %lu",
               expected_size, get_true_size(blk));
}

static void test_backward_fusion_2_blocks(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t num_blocks = 3;
  void *ptrs[num_blocks];
  size_t base_bytes = 10;

  POPULATE_PTR_ARR_VIA_MALLOC(num_blocks, ptrs, base_bytes);
  MM_ASSERT_MARKER(BY_SBRKING, num_blocks);

  LOG("\tpost-malloc ===\n");

  MARK_AS_FREE_BLKS_UNTIL(num_blocks - 1, ptrs);
  LOG("\t after artificially freeing blocks ===\n");

  void *p = ptrs[num_blocks - 1];
  BlockPtr blk = reconstruct_from_user_memory(p);

  mark_as_free(blk);
  fuse_bwd(&blk);
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, 0);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, num_blocks - 1);
  ASSERT_FASTBINS_EMPTY();
  LOG("\t post-bwd-fusion ===\n");

  size_t aligned_base_bytes = align(base_bytes);
  size_t expected_size =
      (aligned_base_bytes * num_blocks + SIZE_OF_BLOCK * (num_blocks - 1));
  TEST_ASSERT_(get_true_size(blk) == expected_size, "size must be %lu, got %lu",
               expected_size, get_true_size(blk));
}

static void test_free_no_release_or_fusion_in_the_middle(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t num_blocks = 5;
  void *ptrs[num_blocks];
  size_t base_bytes = 30;

  POPULATE_PTR_ARR_VIA_MALLOC(num_blocks, ptrs, base_bytes);
  MM_ASSERT_MARKER(BY_SBRKING, num_blocks);

  LOG("\tpost-malloc ===\n");

  void *p = ptrs[1];

  ensuring_free(p);
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, 0);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 0);
  MM_ASSERT_MARKER(RELEASED, 0);
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);

  LOG("\tpost-free ===\n");

  BlockPtr blk = recons_blk_from_user_mem_ptr(p);
  // Because it is in fast bin.
  TEST_ASSERT(!is_free(blk));
  const size_t f_idx = GET_FAST_BIN_IDX(get_true_size(blk));

  FREE_BLKS_EXCEPT(num_blocks, ptrs, (size_t)1);
  ASSERT_UNSORTED_BIN_EMPTY();
  // Each block will be put in the fast bin except the last one.
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 0);
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, num_blocks - 2);
  MM_ASSERT_MARKER(RELEASED, 1);

  ASSERT_FASTBIN_HAS(f_idx, num_blocks - 2);
}

static void test_free_no_release_or_fusion_when_neighbors_are_free(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t num_blocks = 5;
  void *ptrs[num_blocks];
  size_t base_bytes = 30;

  POPULATE_PTR_ARR_VIA_MALLOC(num_blocks, ptrs, base_bytes);
  MM_ASSERT_MARKER(BY_SBRKING, num_blocks);

  LOG("\tpost-malloc ===\n");

  const size_t to_free = num_blocks / 2;

  MARK_AS_FREE_BLKS_EXCEPT(num_blocks - 1, ptrs, to_free);

  LOG("\tafter artificially freeing blocks ===\n");

  void *p = ptrs[to_free];
  BlockPtr blk = reconstruct_from_user_memory(p);
  TEST_ASSERT_(!is_free(blk), "block to free should not have been free");
  // It will directly put in the fast bin even though the neighbors are free.
  ensuring_free(p);
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, 0);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 0);
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);
  LOG("\tpost-free middle ===\n");

  void *last = ptrs[num_blocks - 1];
  BlockPtr last_blk = reconstruct_from_user_memory(last);
  TEST_ASSERT_(!is_free(last_blk), "last block must not be free");
  TEST_ASSERT_(is_prev_free(last_blk), "last block's prev must be free");
  ensuring_free(last);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 1);
  MM_ASSERT_MARKER(RELEASED, 1);
}

static void test_copy_block(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t src_len = 9;
  const size_t src_size_of = 4;
  const size_t src_n = src_len * src_size_of;

  char *p = (char *)ensuring_malloc(src_n);
  TEST_ASSERT(p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  SET_BYTES_INCREMENTALLY(p, src_n);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", src_n);

  const size_t to_copy_len = 9;
  const size_t to_copy_size_of = 4;

  char *q = (char *)ensuring_calloc(to_copy_len, to_copy_size_of);
  TEST_ASSERT(NULL != q);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  BlockPtr p_blk = reconstruct_from_user_memory(p);
  BlockPtr q_blk = reconstruct_from_user_memory(q);

  TEST_ASSERT(get_true_size(p_blk) == get_true_size(q_blk));

  deep_copy_user_memory(p_blk, q_blk);
  LOG("\tafter deep copy block ===\n");

  size_t min = src_len > to_copy_len ? to_copy_len : src_len;
  for (size_t i = 0; i < min; i++)
    TEST_ASSERT_(p[i] == q[i], "%d != %d", p[i], q[i]);

  TEST_ASSERT(CAN_BE_FAST_BINNED(get_true_size(p_blk)));
  ensuring_free(p);
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);
  ensuring_free(q);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 0);
  MM_ASSERT_MARKER(RELEASED, 1);
  TEST_ASSERT(a_head.head == a_head.tail);
}

static void test_realloc_grow_and_shrink(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 10;

  char *p = (char *)ensuring_malloc(n);
  TEST_ASSERT(p);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  SET_BYTES_INCREMENTALLY(p, n);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  const size_t re_grow_n = 100;

  char *q = (char *)ensuring_realloc(p, re_grow_n);
  MM_ASSERT_MARKER(MALLOC_CALLED, 1);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  ensure_freed();
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);
  TEST_ASSERT(NULL != q);
  ASSERT_BYTES_ARE_INCREMENTALLY_SET(q, n);

  LOG("\tafter growing realloc with %lu ===\n", re_grow_n);

  const size_t re_shrink_n = 5;
  char *r = (char *)ensuring_realloc(q, re_shrink_n);
  MM_ASSERT_MARKER(REALLOC_ENOUGH_SIZE, 1);
  MM_ASSERT_MARKER(MALLOC_CALLED, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 0);
  // Small enough to be put in the fast bin.
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);
  TEST_ASSERT(NULL != r);
  ASSERT_BYTES_ARE_INCREMENTALLY_SET(r, re_shrink_n);

  LOG("\tafter shrinking realloc with %lu ===\n", re_shrink_n);
  ensuring_free(r);
  // Since it is in the middle, it will be directly put in the fast bin.
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, 0);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 0);
  MM_ASSERT_MARKER(RELEASED, 0);
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);
}

static void test_realloc_with_size_zero(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 10;
  char *p = (char *)ensuring_malloc(n);
  TEST_ASSERT(p);
  MM_RESET_MARKER(MALLOC_CALLED);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  const size_t zero = 0;

  char *q = (char *)ensuring_realloc(p, zero);
  MM_ASSERT_MARKER(MALLOC_CALLED, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  MM_ASSERT_MARKER(RELEASED, 1);
  ensure_freed();
  TEST_ASSERT(NULL == q);
}

static void test_mmap(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = MIN_CAP_FOR_MMAP + 1;
  char *p = (char *)ensuring_malloc(n);
  TEST_ASSERT(p);

  MM_ASSERT_MARKER(BY_MMAPPING, 1);
  TEST_ASSERT(1 == ma_head.num_mmapped_regions);
  MM_ASSERT_MARKER(BY_SBRKING, 0);

  ensuring_free(p);
  MM_ASSERT_MARKER(MUNMAPPED, 1);
}

static void test_bin_macros(void) {
  size_t exp_num_elms = 4;
  TEST_ASSERT(NUM_ELMNTS_NECESSARY_TO_MAP == exp_num_elms);
  for (size_t i = 0; i < MAP_STEP_BY_TYPE_WIDTH; i++) {
    TEST_ASSERT(i == CORRESPONDING_BIT_INDEX(i));
    TEST_ASSERT(0 == BIN_MAP_INDEX(i));
  }
  for (size_t i = MAP_STEP_BY_TYPE_WIDTH; i < (MAP_STEP_BY_TYPE_WIDTH * 2);
       i++) {
    TEST_ASSERT(i % MAP_STEP_BY_TYPE_WIDTH == CORRESPONDING_BIT_INDEX(i));
    TEST_ASSERT(1 == BIN_MAP_INDEX(i));
  }
  for (size_t i = 1; i < (exp_num_elms + 1); i++) {
    TEST_ASSERT(i == BIN_MAP_INDEX(i * MAP_STEP_BY_TYPE_WIDTH));
  }
}

static void test_mark_unmark_binmap(void) {
  for (size_t i = 0; i < NUM_BINS; i++) {
    MARK_BIN(a_head, i);
    uint32_t exp_val = ((size_t)1 << (i % MAP_STEP_BY_TYPE_WIDTH));
    uint32_t read_val = READ_BINMAP(a_head, i);

    TEST_ASSERT_(read_val == exp_val,
                 "bin %lu has bit value %u, should have been %u", i, read_val,
                 exp_val);

    UNMARK_BIN(a_head, i);

    read_val = READ_BINMAP(a_head, i);

    TEST_ASSERT_(0 == read_val, "bin %lu has bit value %u, should have been %u",
                 i, read_val, 0);
  }
}

static void test_bin_repositioning_trick(void) {
  for (size_t i = 0; i < SLOTS_FOR_BLOCK_OFFSET_ALIGNMENT; i++) {
    TEST_ASSERT_(0 == a_head.bins[i], "block offset must have been null");
  }

  BlockPtr bin;
  for (size_t i = 0; i < NUM_BINS; i++) {
    bin = BLK_PTR_IN_BIN_AT(a_head, i);
    TEST_ASSERT_(IS_LONE_SENTINEL(bin), "bin[%lu] must point to itself", i);
  }
}

static void test_fast_bin(void) {
  for (size_t i = 0; i < NUM_FAST_BINS; i++) {
    TEST_ASSERT_(NULL == a_head.fastbins[i], "fast bin must be null");
    const size_t size = FAST_BIN_SIZE_START + FAST_BIN_STEP * i;
    const size_t f_idx = GET_FAST_BIN_IDX(size);
    TEST_ASSERT_(1 == CAN_BE_FAST_BINNED(size), "must be fastbinned");
    TEST_ASSERT_(f_idx == i, "fast bin index for %lu != %lu", f_idx, i);
  }
}

#define MMAP_SIZE(n) (MIN_CAP_FOR_MMAP + n)

static void test_mremap(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = MMAP_SIZE(1);
  char *p = (char *)ensuring_malloc(n);
  TEST_ASSERT(p);
  TEST_ASSERT(1 == ma_head.num_mmapped_regions);

  SET_BYTES_INCREMENTALLY(p, n);

  MM_ASSERT_MARKER(BY_MMAPPING, 1);
  MM_ASSERT_MARKER(BY_SBRKING, 0);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  const size_t re_grow_n = MMAP_SIZE(100);
  char *q = (char *)ensuring_realloc(p, re_grow_n);
  TEST_ASSERT_(p != q, "returned mremapped pointer must be different");
  TEST_ASSERT(1 == ma_head.num_mmapped_regions);

  MM_ASSERT_MARKER(MMAPPED_BIGGER, 1);
  MM_ASSERT_MARKER(MALLOC_CALLED, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 0);
  TEST_ASSERT(NULL != q);

  ASSERT_BYTES_ARE_INCREMENTALLY_SET(q, n);

  SET_BYTES_INCREMENTALLY(q, re_grow_n);
  LOG("\tafter growing mremap with %lu ===\n", re_grow_n);

  const size_t re_shrink_n = MMAP_SIZE(5);
  char *r = (char *)ensuring_realloc(q, re_shrink_n);
  TEST_ASSERT(1 == ma_head.num_mmapped_regions);
  MM_ASSERT_MARKER(MUNMAPPED_EXCESS, 1);
  MM_ASSERT_MARKER(MALLOC_CALLED, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 0);
  TEST_ASSERT(NULL != r);

  ASSERT_BYTES_ARE_INCREMENTALLY_SET(r, re_shrink_n);

  LOG("\tafter shrinking mremap with %lu ===\n", re_shrink_n);
  ensuring_free(r);
  MM_ASSERT_MARKER(MUNMAPPED, 1);
  TEST_ASSERT(0 == ma_head.num_mmapped_regions);
}

static void test_realloc_from_main_to_mmapped(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 5;
  char *p = (char *)ensuring_malloc(n);
  TEST_ASSERT(p);
  SET_BYTES_INCREMENTALLY(p, n);

  MM_ASSERT_MARKER(BY_MMAPPING, 0);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  const size_t re_grow_n = MMAP_SIZE(5);
  char *q = (char *)ensuring_realloc(p, re_grow_n);
  TEST_ASSERT(NULL != q);
  TEST_ASSERT_(p != q, "returned mremapped pointer must be different");

  MM_ASSERT_MARKER(SBRK_TO_MMAP, 1);
  MM_ASSERT_MARKER(MMAPPED_BIGGER, 0);
  MM_ASSERT_MARKER(MUNMAPPED_EXCESS, 0);
  MM_ASSERT_MARKER(MALLOC_CALLED, 1);
  MM_ASSERT_MARKER(BY_MMAPPING, 1);
  MM_ASSERT_MARKER(BY_SBRKING, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  MM_ASSERT_MARKER(RELEASED, 1);
  ensure_freed();

  ASSERT_BYTES_ARE_INCREMENTALLY_SET(q, n);

  ensuring_free(q);
  MM_ASSERT_MARKER(MUNMAPPED, 1);
}

static void test_realloc_from_mmapped_to_main(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = MMAP_SIZE(5);
  char *p = (char *)ensuring_malloc(n);
  TEST_ASSERT(p);
  SET_BYTES_INCREMENTALLY(p, n);

  MM_ASSERT_MARKER(BY_MMAPPING, 1);
  MM_ASSERT_MARKER(BY_SBRKING, 0);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  const size_t re_grow_n = 5;
  char *q = (char *)ensuring_realloc(p, re_grow_n);
  TEST_ASSERT(NULL != q);
  TEST_ASSERT_(p != q, "returned mremapped pointer must be different");

  MM_ASSERT_MARKER(MMAP_TO_SBRK, 1);
  MM_ASSERT_MARKER(MMAPPED_BIGGER, 0);
  MM_ASSERT_MARKER(MUNMAPPED, 1);
  MM_ASSERT_MARKER(MUNMAPPED_EXCESS, 0);
  MM_ASSERT_MARKER(MALLOC_CALLED, 1);
  MM_ASSERT_MARKER(BY_MMAPPING, 0);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  ensure_freed();

  ASSERT_BYTES_ARE_INCREMENTALLY_SET(q, re_grow_n);

  ensuring_free(q);
  MM_ASSERT_MARKER(RELEASED, 1);
}

static void test_bare_bin_index(void) {
  for (size_t ix = 0; ix < NUM_SMALL_BINS; ix++) {
    const size_t real = SMALL_BIN_SIZE_START + (ix * SMALL_BIN_STEP);
    const size_t bare_bin_idx = GET_BARE_BIN_IDX(real);
    const size_t exp = ix + 1;
    TEST_ASSERT_(bare_bin_idx == exp, "[small bin] idx: %lu != %lu",
                 bare_bin_idx, exp);
  }

  TEST_ASSERT_(GET_BARE_BIN_IDX(SMALL_BIN_SIZE_CAP + ALIGNMENT) ==
                   LARGE_BIN_IDX_SHIFT(0),
               "large bin first size fails %lu != %lu",
               GET_BARE_BIN_IDX(SMALL_BIN_SIZE_CAP + ALIGNMENT),
               LARGE_BIN_IDX_SHIFT(0));
  TEST_ASSERT_(GET_BARE_BIN_IDX(LARGE_BIN_SIZE_START + LARGE_BIN_STEP -
                                ALIGNMENT) == LARGE_BIN_IDX_SHIFT(0),
               "large bin first size fails, %lu != %lu",
               GET_BARE_BIN_IDX(LARGE_BIN_SIZE_START - ALIGNMENT),
               LARGE_BIN_IDX_SHIFT(0));

  for (size_t ix = 1; ix <= NUM_LARGE_BINS; ix++) {
    const size_t real = LARGE_BIN_SIZE_START + ix * LARGE_BIN_STEP;
    const size_t bare_bin_idx = GET_BARE_BIN_IDX(real);
    const size_t exp = LARGE_BIN_IDX_SHIFT(ix);
    TEST_ASSERT_(bare_bin_idx == exp, "[large bin] idx: %lu != %lu",
                 bare_bin_idx, exp);
  }

  TEST_ASSERT_(!CAN_BE_FAST_BINNED(FAST_BIN_SIZE_START - ALIGNMENT),
               "too small for fast bin failed %lu",
               FAST_BIN_SIZE_START - ALIGNMENT);
  TEST_ASSERT_(!CAN_BE_FAST_BINNED(FAST_BIN_SIZE_CAP + ALIGNMENT),
               "too big for fast bin failed %lu",
               FAST_BIN_SIZE_CAP + ALIGNMENT);

  for (size_t ix = 0; ix < NUM_LARGE_BINS; ix++) {
    const size_t real = FAST_BIN_SIZE_START + ix * FAST_BIN_STEP;
    const size_t fast_bin_idx = GET_FAST_BIN_IDX(real);
    TEST_ASSERT_(fast_bin_idx == ix, "[fast bin] idx: %lu != %lu", fast_bin_idx,
                 ix);
  }
}

static void test_best_find_fast_bin(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 5;
  void *put_in_fast_bin = ensuring_malloc(n);
  TEST_ASSERT(put_in_fast_bin);
  MM_ASSERT_MARKER(BY_MMAPPING, 0);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  // Artificially put it in the appropriate fast-bin
  BlockPtr to_fast_bin = recons_blk_from_user_mem_ptr(put_in_fast_bin);
  const size_t idx = GET_FAST_BIN_IDX(get_true_size(to_fast_bin));
  TEST_ASSERT_(NULL == a_head.fastbins[idx],
               "fastbin[%lu] should have been NULL, got %p", idx,
               (void *)a_head.fastbins[idx]);

  insert_in_fastbin(to_fast_bin);
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);

  void *fast_binned = ensuring_malloc(n);
  TEST_ASSERT(fast_binned);
  MM_ASSERT_MARKER(FASTBINNED, 1);

  const BlockPtr from_fast_bin = recons_blk_from_user_mem_ptr(fast_binned);
  TEST_ASSERT(from_fast_bin == to_fast_bin);
  TEST_ASSERT(get_true_size(to_fast_bin) == get_true_size(from_fast_bin));
  TEST_ASSERT(NULL == a_head.fastbins[idx]);

  ensuring_free(fast_binned);
  MM_ASSERT_MARKER(RELEASED, 1);
}

static void test_best_find_bin(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 5;
  void *put_in_bin = ensuring_malloc(n);
  TEST_ASSERT(put_in_bin);
  MM_ASSERT_MARKER(BY_MMAPPING, 0);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  // Artificially put it in the appropriate bin
  BlockPtr to_bin = recons_blk_from_user_mem_ptr(put_in_bin);
  const size_t bare_idx = GET_BARE_BIN_IDX(get_true_size(to_bin));
  TEST_ASSERT_(1 == bare_idx, "bare_idx %lu should have been 1", bare_idx);

  BlockPtr bin_sentinel = BLK_PTR_IN_BIN_AT(a_head, bare_idx);
  mark_as_free(to_bin);
  TEST_ASSERT_(IS_LONE_SENTINEL(bin_sentinel),
               "sentinal for bin[%lu] should be pointing to itself got "
               "next:%p, prev:%p",
               bare_idx, (void *)bin_sentinel->next,
               (void *)bin_sentinel->prev);

  TEST_ASSERT_(0 == READ_BINMAP(a_head, bare_idx),
               "bin map for bin[%lu] should be 0", bare_idx);

  append(bin_sentinel, to_bin);
  MARK_BIN(a_head, bare_idx);

  void *binned = ensuring_malloc(n);
  TEST_ASSERT(binned);
  MM_ASSERT_MARKER(SMALL_BINNED, 1);

  const BlockPtr from_bin = recons_blk_from_user_mem_ptr(binned);
  TEST_ASSERT(from_bin == to_bin);
  TEST_ASSERT(get_true_size(to_bin) == get_true_size(from_bin));
  TEST_ASSERT_(
      IS_LONE_SENTINEL(bin_sentinel),
      "sentinal for bin[%lu] should be pointing to itself got next:%p, prev:%p",
      bare_idx, (void *)bin_sentinel->next, (void *)bin_sentinel->prev);

  ensuring_free(binned);
  MM_ASSERT_MARKER(RELEASED, 1);
}

#define PUT_ONE_BLOCK_INTO_EACH_FASTBIN(ptrs)                                  \
  {                                                                            \
    for (size_t i = 0; i < NUM_FAST_BINS; i++) {                               \
      const size_t size = FAST_BIN_SIZE_START + i * FAST_BIN_STEP;             \
      void *p = ensuring_malloc(size);                                         \
      TEST_ASSERT(p);                                                          \
      MM_ASSERT_MARKER(BY_SBRKING, 1);                                         \
      ptrs[i] = p;                                                             \
    }                                                                          \
    for (size_t i = 0; i < NUM_FAST_BINS; i++) {                               \
      void *p = ptrs[i];                                                       \
      BlockPtr blk = recons_blk_from_user_mem_ptr(p);                          \
      insert_in_fastbin(blk);                                                  \
      MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);                                     \
    }                                                                          \
  }

static void test_consolidate_fastbins(void) {
  // Put one block into each fastbin
  void *ptrs[NUM_FAST_BINS];
  PUT_ONE_BLOCK_INTO_EACH_FASTBIN(ptrs);

  // Ensure unsorted bin is empty
  BlockPtr unsorted_bin_sentinel = BLK_PTR_OF_UNSORTED(a_head);
  TEST_ASSERT_(
      IS_LONE_SENTINEL(unsorted_bin_sentinel),
      "unsorted bin sentinal should be pointing to itself got next:%p, prev:%p",
      (void *)unsorted_bin_sentinel->next, (void *)unsorted_bin_sentinel->prev);

  TEST_ASSERT_(0 == READ_BINMAP(a_head, 0),
               "bin map for unsorted bin should be 0");

  // Since all bins are in a fast bin and contiguous to each other,
  // each block consolidating will fuse with the one before which has been put
  // to the unsorted bin, either solely (first one), or fused with the ones
  // before it (as this case).
  consolidate_fastbins();
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, 0);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, NUM_FAST_BINS - 1);
  MM_ASSERT_MARKER(CONSOLIDATED, NUM_FAST_BINS);
  MM_ASSERT_MARKER(PUT_IN_UNSORTED_BIN, NUM_FAST_BINS);
  ASSERT_FASTBINS_EMPTY();

  TEST_ASSERT_(!IS_LONE_SENTINEL(unsorted_bin_sentinel),
               "unsorted bin should not be empty");

  size_t counter = 0;
  BlockPtr cursor = unsorted_bin_sentinel->next;
  while (cursor != unsorted_bin_sentinel) {
    if (cursor->next == cursor) {
      printf("cursor points to itself %p", (void *)cursor);
      break;
    }
    counter++;
    cursor = cursor->next;
  }

  // There will only be one block with all others merged.
  TEST_ASSERT_(1 == counter,
               "only single block should be prepended to the unsorted bin, but"
               " got %lu blocks",
               counter);

  BlockPtr consolidated = unsorted_bin_sentinel->next;
  const size_t exp_consolidated_size =
      (FAST_BIN_SIZE_START + FAST_BIN_SIZE_CAP) * (NUM_FAST_BINS) / 2 +
      SIZE_OF_BLOCK * (NUM_FAST_BINS - 1);
  TEST_ASSERT_(get_true_size(consolidated) == exp_consolidated_size,
               "consolidated block must have size %lu, got %lu",
               exp_consolidated_size, get_true_size(consolidated));

  // To avoid double free
  mark_as_used(consolidated);
  // If it is used, it should not be in unsorted bin
  remove_from_linkedlist(consolidated);
  ensuring_free(allocated_memory(consolidated));
  MM_ASSERT_MARKER(RELEASED, 1);
}

static void test_search_in_unsorted_consolidating(void) {
  // Put one block into each fastbin
  void *ptrs[NUM_FAST_BINS];
  PUT_ONE_BLOCK_INTO_EACH_FASTBIN(ptrs);

  // Ensure unsorted bin is empty
  BlockPtr unsorted_bin_sentinel = BLK_PTR_OF_UNSORTED(a_head);
  TEST_ASSERT_(
      IS_LONE_SENTINEL(unsorted_bin_sentinel),
      "unsorted bin sentinal should be pointing to itself got next:%p, prev:%p",
      (void *)unsorted_bin_sentinel->next, (void *)unsorted_bin_sentinel->prev);

  TEST_ASSERT_(0 == READ_BINMAP(a_head, 0),
               "bin map for unsorted bin should be 0");

  const size_t size_all_fast_bins_combined =
      (FAST_BIN_SIZE_CAP + FAST_BIN_SIZE_START) * (NUM_FAST_BINS) / 2 +
      (SIZE_OF_BLOCK * (NUM_FAST_BINS - 1));

  // It will have to consolidate all fast bins, and then start search in
  // unsorted bins while fusing and placing in appropriate bins.
  void *all_combined = ensuring_malloc(size_all_fast_bins_combined);
  TEST_ASSERT(all_combined);
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, 0);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, NUM_FAST_BINS - 1);
  MM_ASSERT_MARKER(CONSOLIDATED, NUM_FAST_BINS);
  MM_ASSERT_MARKER(PUT_IN_UNSORTED_BIN, NUM_FAST_BINS);
  MM_ASSERT_MARKER(UNSORTED_BINNED, 1);

  ASSERT_FASTBINS_EMPTY();
  TEST_ASSERT_(IS_LONE_SENTINEL(unsorted_bin_sentinel),
               "unsorted bin should be empty");
}

static void test_first_find_unsorted_bin(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 5;
  void *put_in_bin = ensuring_malloc(n);
  TEST_ASSERT(put_in_bin);
  MM_ASSERT_MARKER(BY_MMAPPING, 0);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);
  // Artificially put it in the appropriate bin
  BlockPtr to_bin = recons_blk_from_user_mem_ptr(put_in_bin);
  const size_t bare_idx = GET_BARE_BIN_IDX(get_true_size(to_bin));
  TEST_ASSERT_(1 == bare_idx, "bare_idx %lu should have been 1", bare_idx);

  BlockPtr unsorted_sentinel = BLK_PTR_OF_UNSORTED(a_head);
  remove_from_linkedlist(to_bin);
  mark_as_free(to_bin);
  TEST_ASSERT_(
      IS_LONE_SENTINEL(unsorted_sentinel),
      "unsorted bin sentinal should be pointing to itself got next:%p, prev:%p",
      (void *)unsorted_sentinel->next, (void *)unsorted_sentinel->prev);
  TEST_ASSERT_(0 == READ_BINMAP(a_head, bare_idx),
               "bin map for bin[%lu] should be 0", bare_idx);

  append(unsorted_sentinel, to_bin);
  MARK_BIN(a_head, 0);

  void *unsorted_binned = ensuring_malloc(n);
  TEST_ASSERT(unsorted_binned);
  MM_ASSERT_MARKER(UNSORTED_BINNED, 1);

  const BlockPtr from_bin = recons_blk_from_user_mem_ptr(unsorted_binned);
  TEST_ASSERT(from_bin == to_bin);
  TEST_ASSERT(get_true_size(to_bin) == get_true_size(from_bin));
  TEST_ASSERT_(IS_LONE_SENTINEL(unsorted_sentinel),
               "unsorted bin sentinal should be pointing to itself got "
               "next:%p, prev:%p",
               (void *)unsorted_sentinel->next,
               (void *)unsorted_sentinel->prev);
  ensuring_free(unsorted_binned);
  MM_ASSERT_MARKER(RELEASED, 1);
}

extern void print_bin(ArenaPtr ar, const size_t ix);

static void test_full_flow_consolidation_and_free(void) {
  LOG("=== %s: start ===\n", __func__);
  void *ptrs[NUM_FAST_BINS];
  PUT_ONE_BLOCK_INTO_EACH_FASTBIN(ptrs);

  ASSERT_UNSORTED_BIN_EMPTY();
  for (size_t f_idx = 0; f_idx < NUM_FAST_BINS; f_idx++) {
    ASSERT_FASTBIN_HAS(f_idx, (size_t)1);
  }

  void *from_first_fast_bin = ensuring_malloc(FAST_BIN_SIZE_START);
  TEST_ASSERT(from_first_fast_bin);
  MM_ASSERT_MARKER(FASTBINNED, 1);

  const size_t f_idx = 0;
  ASSERT_FASTBIN_HAS(f_idx, (size_t)0);

  // We will try to grow in place but won't be able to because all neighbors are
  // in fastbins. We will free from_first_fast_bin and pick the block from the
  // second fast bin.
  void *new_realloced = ensuring_realloc(from_first_fast_bin,
                                         FAST_BIN_SIZE_START + FAST_BIN_STEP);
  TEST_ASSERT(new_realloced);
  // from_first_fast_bin should be put back to its fastbin
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  MM_ASSERT_MARKER(FREED, 1);
  MM_ASSERT_MARKER(PUT_IN_FASTBIN, 1);
  ASSERT_FASTBIN_HAS(f_idx, (size_t)1);
  ASSERT_FASTBIN_HAS(f_idx + 1, (size_t)0);

  // The size requires malloc to pick a block from the second fast bin.
  MM_ASSERT_MARKER(FASTBINNED, 1);

  const size_t size_all_fast_bins_combined =
      (FAST_BIN_SIZE_CAP + FAST_BIN_SIZE_START) * (NUM_FAST_BINS) / 2 +
      (SIZE_OF_BLOCK * (NUM_FAST_BINS - 1));

  void *all_fast_bins_combined = ensuring_malloc(size_all_fast_bins_combined);
  TEST_ASSERT(all_fast_bins_combined);
  // new_realloced is in use thus -1.
  MM_ASSERT_MARKER(CONSOLIDATED, NUM_FAST_BINS - 1);
  MM_ASSERT_MARKER(BY_SBRKING, 1);

  BlockPtr blk = recons_blk_from_user_mem_ptr(all_fast_bins_combined);

  ASSERT_FASTBINS_EMPTY();

  TEST_ASSERT_(size_all_fast_bins_combined == get_true_size(blk), "%lu != %lu",
               size_all_fast_bins_combined, get_true_size(blk));
  TEST_ASSERT(a_head.tail == blk);

  // Should fuse everything in unsorted bins together
  ensuring_free(all_fast_bins_combined);
  ASSERT_UNSORTED_BIN_EMPTY();
  MM_ASSERT_MARKER(RELEASED, 1);
}

TEST_LIST = {
    {"test_align", test_align},
    {"test_true_size", test_true_size},
    {"test_encode", test_encode},
    {"test_invalid_addr_outside_before_for_is_valid_addr",
     test_invalid_addr_outside_before_for_is_valid_addr},
    {"test_invalid_addr_outside_after_for_is_valid_addr",
     test_invalid_addr_outside_after_for_is_valid_addr},
    {"test_valid_addr_for_is_valid_addr", test_valid_addr_for_is_valid_addr},
    {"test_malloc_zero", test_malloc_zero},
    {"test_first_malloc_new_head", test_first_malloc_new_head},
    {"test_header_alignment_and_size", test_header_alignment_and_size},
    {"test_forward_fusion_2_blocks", test_forward_fusion_2_blocks},
    {"test_backward_fusion_2_blocks", test_backward_fusion_2_blocks},
    {"test_malloc_allocated_memory_aligned",
     test_malloc_allocated_memory_aligned},
    {"test_calloc_zero_fill", test_calloc_zero_fill},
    {"test_free_no_release_or_fusion_in_the_middle",
     test_free_no_release_or_fusion_in_the_middle},
    {"test_free_no_release_or_fusion_when_neighbors_are_free",
     test_free_no_release_or_fusion_when_neighbors_are_free},
    {"test_copy_block", test_copy_block},
    {"test_realloc_grow_and_shrink", test_realloc_grow_and_shrink},
    {"test_realloc_with_size_zero", test_realloc_with_size_zero},
    {"test_mmap", test_mmap},
    {"test_bin_macros", test_bin_macros},
    {"test_mark_unmark_binmap", test_mark_unmark_binmap},
    {"test_bin_repositioning_trick", test_bin_repositioning_trick},
    {"test_fast_bin", test_fast_bin},
    {"test_mremap", test_mremap},
    {"test_realloc_from_main_to_mmapped", test_realloc_from_main_to_mmapped},
    {"test_realloc_from_mmapped_to_main", test_realloc_from_mmapped_to_main},
    {"test_bare_bin_index", test_bare_bin_index},
    {"test_best_find_fast_bin", test_best_find_fast_bin},
    {"test_best_find_bin", test_best_find_bin},
    {"test_consolidate_fastbins", test_consolidate_fastbins},
    {"test_first_find_unsorted_bin", test_first_find_unsorted_bin},
    {"test_search_in_unsorted_consolidating",
     test_search_in_unsorted_consolidating},
    {"test_full_flow_consolidation_and_free",
     test_full_flow_consolidation_and_free},
    {NULL, NULL}};
#endif
