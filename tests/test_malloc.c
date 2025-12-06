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

static size_t base_total_blocks;
static size_t base_free_blocks;

static void reset_markers(void) {
  for (size_t ix = 0; ix < NUM_MARKERS; ix++)
    markers[ix] = 0;
}

static void check_all_arena_heads_are_null(void) {
  TEST_CHECK(a_head.head == NULL);
  TEST_CHECK(a_head.tail == NULL);
  TEST_CHECK(ma_head.head == NULL);
  TEST_CHECK(ma_head.tail == NULL);
}

static void pre_test_sanity(void) {
  reset_markers();

  base_total_blocks = _mm_total_blocks();
  base_free_blocks = _mm_free_blocks();
  check_all_arena_heads_are_null();
  TEST_CHECK(base_total_blocks == 0);
  TEST_CHECK(base_free_blocks == 0);
}

static void post_test_sanity(void) {
  // No new permanent blocks, anything allocated during the tests are new
  // extended blocks, they will be released at the end of each test because they
  // will be fused
  TEST_CHECK(_mm_total_blocks() == base_total_blocks);
  TEST_MSG("block leak: %zu -> %zu", base_total_blocks, _mm_total_blocks());

  // Free count should also match baseline
  TEST_CHECK(_mm_free_blocks() == base_free_blocks);
  TEST_MSG("free block mismatch: %zu -> %zu", base_free_blocks,
           _mm_free_blocks());

  check_all_arena_heads_are_null();
}

static inline int is_aligned(void *p) {
  return ((uintptr_t)p % _Alignof(max_align_t)) == 0;
}

void check_block_header_shape(BlockPtr head) {
  TEST_CHECK(sizeof(head->size) == 8);
  TEST_CHECK(sizeof(head->next) == 8);
  TEST_CHECK(sizeof(head->prev) == 8);
  TEST_CHECK(sizeof(head->end_of_alloc_mem) == 8);
  TEST_CHECK(is_aligned(head));
}

BlockPtr recons_blk_from_user_mem_ptr(void *p) {
  BlockPtr head = reconstruct_from_user_memory((const void *)p);
  check_block_header_shape(head);
  TEST_CHECK_(p == (void *)allocated_memory(head),
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

void ensure_freed(void) {
  MM_ASSERT_MARKER(FREED, 1);
  MM_RESET_MARKER(FREED);
}

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

void ensure_fuse_fwd_is_called(size_t exp) {
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, exp);
  MM_RESET_MARKER(FUSE_FWD_CALLED);
}

void ensure_fuse_bwd_is_called(size_t exp) {
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, exp);
  MM_RESET_MARKER(FUSE_BWD_CALLED);
}

void *ensuring_realloc(void *p, size_t size) {
  MM_RESET_MARKER(MALLOC_CALLED);
  MM_RESET_MARKER(REALLOC_CALLED);
  void *r = REALLOC_UNDER_TESTING(p, size);
  MM_ASSERT_MARKER(REALLOC_CALLED, 1);
  return r;
}

void ensure_realloc_enough_size(void) {
  MM_ASSERT_MARKER(REALLOC_ENOUGH_SIZE, 1);
  MM_RESET_MARKER(REALLOC_ENOUGH_SIZE);
}

static void test_align(void) {
  for (size_t any = 1; any <= MAX_ALIGNMENT; any++)
    TEST_CHECK((MAX_ALIGNMENT) == align(any));

  size_t two_max_alg = (MAX_ALIGNMENT * 2);
  for (size_t any = MAX_ALIGNMENT + 1; any <= two_max_alg; any++)
    TEST_CHECK_(two_max_alg == align(any), "%lu != %lu ", any, align(any));

  size_t multiple = MAX_ALIGNMENT * 4;
  TEST_CHECK(multiple == align(multiple));

  size_t large = MAX_ALIGNMENT * 4 - (MAX_ALIGNMENT / 2);
  TEST_CHECK((MAX_ALIGNMENT * 4) == align(large));
}

static void test_encode(void) {
  size_t size = 3;
  size_t aligned_size = align(size);
  void *p = ensuring_malloc(size);
  TEST_CHECK(p != NULL);

  BlockPtr b = reconstruct_from_user_memory(p);
  TEST_CHECK(!is_free(b));
  TEST_CHECK(!is_mmapped(b));
  TEST_CHECK_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
              aligned_size);

  mark_as_free(b);
  TEST_CHECK(is_free(b));
  TEST_CHECK(!is_mmapped(b));
  TEST_CHECK_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
              aligned_size);

  mark_as_used(b);
  TEST_CHECK(!is_free(b));
  TEST_CHECK(!is_mmapped(b));
  TEST_CHECK_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
              aligned_size);

  ensuring_free(p);
}

static void test_true_size(void) {
  size_t size = 3;
  size_t aligned_size = align(size);
  void *p = ensuring_malloc(size);
  TEST_CHECK(p != NULL);

  BlockPtr b = reconstruct_from_user_memory(p);
  TEST_CHECK(!is_free(b));
  TEST_CHECK_(get_true_size(b) == aligned_size, "%lu != %lu", get_true_size(b),
              aligned_size);

  ensuring_free(p);
}

static void test_invalid_addr_outside_before_for_is_valid_addr(void) {
  void *p = ensuring_malloc(1);
  TEST_CHECK(p != NULL);
  BlockPtr head = a_head.head;
  void *invalid = (char *)head + sizeof(struct SBlock) * 9;
  TEST_CHECK_(
      get_block_from_main_arena(&a_head, invalid) == NULL,
      "address %p should have been invalid since it is before list head %p",
      invalid, (void *)head);
  ensuring_free(p);
}

static void test_invalid_addr_outside_after_for_is_valid_addr(void) {
  void *p = ensuring_malloc(1);
  TEST_CHECK(p != NULL);
  void *invalid = (char *)p + sizeof(struct SBlock);
  TEST_CHECK(get_block_from_main_arena(&a_head, invalid) == NULL);
  ensuring_free(p);
}

static void test_valid_addr_for_is_valid_addr(void) {
  void *p = ensuring_malloc(1);
  TEST_CHECK(p != NULL);
  TEST_CHECK(get_block_from_main_arena(&a_head, p));
  ensuring_free(p);
}

// malloc(0) is expected to return NULL pointer
static void test_malloc_zero(void) {
  void *p = ensuring_malloc(0);
  TEST_CHECK(p == NULL);
  FREE_UNDER_TESTING(p);
  MM_ASSERT_MARKER(FREE_CALLED, 0);
  MM_ASSERT_MARKER(FREED, 0);
}

static void test_first_malloc_new_head(void) {
  TEST_CHECK(a_head.head == NULL);
  void *p = ensuring_malloc(5);
  TEST_CHECK(p != NULL);
  TEST_CHECK(a_head.head != NULL);
  ensuring_free(p);
  TEST_CHECK(a_head.head == NULL);
}

static void test_header_alignment_and_size(void) {
  size_t requested_bytes = 1;
  void *p = ensuring_malloc(requested_bytes);
  TEST_CHECK(p != NULL);

  BlockPtr head = recons_blk_from_user_mem_ptr(p);
  TEST_CHECK(get_true_size(head) == align(requested_bytes));
  ensuring_free(p);
}

static void test_malloc_allocated_memory_aligned(void) {
  void *p = ensuring_malloc(31);
  TEST_CHECK(p != NULL);
  TEST_CHECK(is_aligned(p));
  ensuring_free(p);
}

static void test_calloc_zero_fill(void) {
  size_t n = 16, sz = 8;
  unsigned char *p = (unsigned char *)ensuring_calloc(n, sz);
  TEST_ASSERT(p != NULL);
  for (size_t i = 0; i < n * sz; ++i)
    TEST_CHECK(p[i] == 0);
  ensuring_free(p);
}

static void test_forward_fusion_2_blocks(void) {
  LOG("=== %s: start ===\n", __func__);

  size_t num_blocks = 3;
  void *ptrs[num_blocks];
  size_t base_bytes = 10;

  for (size_t i = 0; i < num_blocks; i++) {
    void *p = ensuring_malloc(base_bytes);
    TEST_CHECK(p != NULL);
    ptrs[i] = p;
  }

  LOG("\tpost-malloc ===\n");

  for (size_t i = 0; i < num_blocks - 1; i++) {
    void *p = ptrs[i];
    BlockPtr blk = reconstruct_from_user_memory(p);
    mark_as_free(blk);
  }

  LOG("\tafter artificially freeing blocks ===\n");

  void *p = ptrs[0];
  BlockPtr blk = reconstruct_from_user_memory(p);

  fuse_fwd(blk);
  ensure_fuse_fwd_is_called(1);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 0);

  LOG("\tpost-fwd-fusion ===\n");

  size_t aligned_base_bytes = align(base_bytes);
  size_t expected_size = (aligned_base_bytes * 2 + SIZE_OF_BLOCK);
  TEST_CHECK_(get_true_size(blk) == expected_size, "size must be %lu, got %lu",
              expected_size, get_true_size(blk));

  BlockPtr last = ptrs[num_blocks - 1];
  TEST_CHECK_(!is_free(last), "last block should not have been freed");
  ensuring_free(last);
}

static void test_backward_fusion_2_blocks(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 3;
  void *ptrs[n];
  size_t base_bytes = 10;

  for (size_t i = 0; i < n; i++) {
    void *p = ensuring_malloc(base_bytes);
    TEST_CHECK(p != NULL);
    ptrs[i] = p;
  }

  LOG("\tpost-malloc ===\n");

  for (size_t i = 0; i < n - 1; i++) {
    void *p = ptrs[i];
    BlockPtr blk = reconstruct_from_user_memory(p);
    mark_as_free(blk);
  }

  LOG("\t after artificially freeing blocks ===\n");

  void *p = ptrs[n - 2];
  BlockPtr blk = reconstruct_from_user_memory(p);

  fuse_bwd(&blk);
  ensure_fuse_bwd_is_called(1);
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, 0);

  LOG("\t post-bwd-fusion ===\n");

  size_t aligned_base_bytes = align(base_bytes);
  size_t expected_size = (aligned_base_bytes * (n - 1) + SIZE_OF_BLOCK);
  TEST_CHECK_(get_true_size(blk) == expected_size, "size must be %lu, got %lu",
              expected_size, get_true_size(blk));

  void *last = ptrs[n - 1];
  ensuring_free(last);
}

static void test_free_no_release_or_fusion(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 3;
  void *ptrs[n];
  size_t base_bytes = 30;

  for (size_t i = 0; i < n; i++) {
    void *p = ensuring_malloc(base_bytes);
    TEST_CHECK(p != NULL);
    ptrs[i] = p;
  }

  LOG("\tpost-malloc ===\n");

  void *p = ptrs[1];

  ensuring_free(p);
  MM_ASSERT_MARKER(FUSE_FWD_CALLED, 0);
  MM_ASSERT_MARKER(FUSE_BWD_CALLED, 0);
  MM_ASSERT_MARKER(RELEASED, 0);

  LOG("\tpost-free ===\n");

  BlockPtr blk = recons_blk_from_user_mem_ptr(p);
  TEST_CHECK(is_free(blk));

  for (size_t i = 0; i < n; i++) {
    if (i == 1)
      continue;
    ensuring_free(ptrs[i]);
  }
}

static void test_free_with_fusion_no_release(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 5;
  void *ptrs[n];
  size_t base_bytes = 30;

  for (size_t i = 0; i < n; i++) {
    void *p = ensuring_malloc(base_bytes);
    TEST_CHECK(p != NULL);
    ptrs[i] = p;
  }

  LOG("\tpost-malloc ===\n");

  const size_t to_free = n / 2;
  // leave the last block unfree to avoid release
  for (size_t i = 0; i < n - 1; i++) {
    if (to_free == i)
      continue;
    void *p = ptrs[i];
    BlockPtr blk = reconstruct_from_user_memory(p);
    mark_as_free(blk);
  }

  LOG("\tafter artificially freeing blocks ===\n");

  void *p = ptrs[to_free];
  BlockPtr blk = reconstruct_from_user_memory(p);
  BlockPtr after_fusion_head = blk->prev->prev;
  TEST_CHECK_(!is_free(blk), "block to free should not have been free");
  ensuring_free(p);
  ensure_fuse_fwd_is_called(1);
  ensure_fuse_bwd_is_called(2);
  MM_ASSERT_MARKER(RELEASED, 0);

  LOG("\tpost-free middle ===\n");

  size_t total_block_sizes = SIZE_OF_BLOCK * (n - 2);
  size_t total_allocated = align(base_bytes) * (n - 1);
  size_t total_bytes_after_fusion = total_allocated + total_block_sizes;
  TEST_CHECK_(get_true_size(after_fusion_head) == total_bytes_after_fusion,
              "size of after_fusion_head should add up to %lu, not %lu",
              total_bytes_after_fusion, get_true_size(after_fusion_head));

  void *last = ptrs[n - 1];
  ensuring_free(last);
}

static void test_copy_block(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t src_len = 9;
  const size_t src_size_of = 4;
  const size_t src_n = src_len * src_size_of;

  int *p = (int *)ensuring_malloc(src_n);
  TEST_CHECK(p);
  for (size_t i = 0; i < src_len; i++)
    p[i] = i;

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", src_n);

  const size_t to_copy_len = 9;
  const size_t to_copy_size_of = 4;

  int *q = (int *)ensuring_calloc(to_copy_len, to_copy_size_of);
  TEST_ASSERT(q != NULL);

  BlockPtr p_blk = reconstruct_from_user_memory(p);
  BlockPtr q_blk = reconstruct_from_user_memory(q);

  deep_copy_user_memory(p_blk, q_blk);
  LOG("\tafter deep copy block ===\n");

  size_t min = src_len > to_copy_len ? to_copy_len : src_len;
  for (size_t i = 0; i < min; i++)
    TEST_CHECK_(p[i] == q[i], "%d != %d", p[i], q[i]);

  ensuring_free(p);
  ensuring_free(q);
}

static void test_realloc_grow_and_shrink(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 10;

  char *p = (char *)ensuring_malloc(n);
  TEST_CHECK(p);
  for (int i = 0; i < (int)n; i++)
    p[i] = (char)i;

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  const size_t re_grow_n = 100;

  char *q = (char *)ensuring_realloc(p, re_grow_n);
  MM_ASSERT_MARKER(MALLOC_CALLED, 1);
  MM_RESET_MARKER(MALLOC_CALLED);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  ensure_freed();
  MM_RESET_MARKER(FREE_CALLED);
  TEST_ASSERT(q != NULL);
  for (int i = 0; i < (int)n; i++)
    TEST_CHECK(q[i] == (char)i);

  LOG("\tafter growing realloc with %lu ===\n", re_grow_n);

  const size_t re_shrink_n = 5;
  char *r = (char *)REALLOC_UNDER_TESTING(q, re_shrink_n);
  ensure_realloc_enough_size();
  MM_ASSERT_MARKER(MALLOC_CALLED, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 0);
  TEST_ASSERT(r != NULL);
  for (int i = 0; i < (int)re_shrink_n; i++)
    TEST_CHECK(r[i] == (char)i);

  LOG("\tafter shrinking realloc with %lu ===\n", re_shrink_n);
  // this should free the whole thing, since it will fuse bk and fw
  ensuring_free(r);
}

static void test_realloc_with_size_zero(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 10;
  char *p = (char *)ensuring_malloc(n);
  TEST_CHECK(p);
  MM_RESET_MARKER(MALLOC_CALLED);

  const size_t zero = 0;

  char *q = (char *)ensuring_realloc(p, zero);
  MM_ASSERT_MARKER(MALLOC_CALLED, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  MM_RESET_MARKER(FREE_CALLED);
  ensure_freed();
  TEST_ASSERT(q == NULL);
}

static void test_mmap(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = MIN_CAP_FOR_MMAP + 1;
  char *p = (char *)ensuring_malloc(n);
  TEST_CHECK(p);

  MM_ASSERT_MARKER(BY_MMAPPING, 1);
  MM_RESET_MARKER(BY_MMAPPING);
  MM_RESET_MARKER(MALLOC_CALLED);

  ensuring_free(p);
  MM_ASSERT_MARKER(MUNMAPPED, 1);
}

static void test_bin_macros(void) {
  size_t exp_num_elms = 4;
  TEST_ASSERT(NUM_ELMNTS_NECESSARY_TO_MAP == exp_num_elms);
  for (size_t i = 0; i < MAP_STEP_BY_TYPE_WIDTH; i++) {
    TEST_ASSERT(CORRESPONDING_BIT_INDEX(i) == i);
    TEST_ASSERT(BIN_MAP_INDEX(i) == 0);
  }
  for (size_t i = MAP_STEP_BY_TYPE_WIDTH; i < (MAP_STEP_BY_TYPE_WIDTH * 2);
       i++) {
    TEST_ASSERT(CORRESPONDING_BIT_INDEX(i) == i % MAP_STEP_BY_TYPE_WIDTH);
    TEST_ASSERT(BIN_MAP_INDEX(i) == 1);
  }
  for (size_t i = 1; i < (exp_num_elms + 1); i++) {
    TEST_ASSERT(BIN_MAP_INDEX(i * MAP_STEP_BY_TYPE_WIDTH) == i);
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

    TEST_ASSERT_(read_val == 0, "bin %lu has bit value %u, should have been %u",
                 i, read_val, 0);
  }
}

static void test_bin_repositioning_trick(void) {
  for (size_t i = 0; i < SLOTS_FOR_BLOCK_OFFSET_ALIGNMENT; i++) {
    a_head.bins[i] = 0;
  }

  BlockPtr bin;
  for (size_t i = 0; i < NUM_BINS; i++) {
    bin = BLK_PTR_IN_BIN_AT(a_head, i);
    TEST_ASSERT_(bin == bin->next,
                 "next must point to itself, exp:%p != got:%p", (void *)bin,
                 (void *)bin->next);
    TEST_ASSERT_(bin == bin->prev,
                 "prev must point to itself, exp:%p != got:%p", (void *)bin,
                 (void *)bin->prev);
  }
}

#define MMAP_SIZE(n) (MIN_CAP_FOR_MMAP + n)

static void test_mremap(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = MMAP_SIZE(1);
  char *p = (char *)ensuring_malloc(n);
  TEST_CHECK(p);
  for (size_t i = 0; i < n; i++)
    p[i] = (char)(i % 128);

  MM_ASSERT_MARKER(BY_MMAPPING, 1);
  MM_ASSERT_MARKER(BY_SBRKING, 0);
  MM_RESET_MARKER(BY_MMAPPING);
  MM_RESET_MARKER(MALLOC_CALLED);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  const size_t re_grow_n = MMAP_SIZE(100);
  char *q = (char *)ensuring_realloc(p, re_grow_n);
  TEST_ASSERT_(p != q, "returned mremapped pointer must be different");

  MM_ASSERT_MARKER(MMAPPED_BIGGER, 1);
  MM_ASSERT_MARKER(MALLOC_CALLED, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 0);
  TEST_ASSERT(q != NULL);

  for (size_t i = 0; i < n; i++) {
    TEST_CHECK_(q[i] == (char)(i % 128), "[%lu] exp: '%c' != got: '%c'", i,
                (char)(i % 128), q[i]);
  }

  for (size_t i = n; i < re_grow_n; i++) {
    q[i] = (char)(i % 128);
  }
  LOG("\tafter growing mremap with %lu ===\n", re_grow_n);

  const size_t re_shrink_n = MMAP_SIZE(5);
  char *r = (char *)REALLOC_UNDER_TESTING(q, re_shrink_n);
  MM_ASSERT_MARKER(MUNMAPPED_EXCESS, 1);
  MM_ASSERT_MARKER(MALLOC_CALLED, 0);
  MM_ASSERT_MARKER(FREE_CALLED, 0);
  TEST_ASSERT(r != NULL);
  for (size_t i = 0; i < re_shrink_n; i++)
    TEST_CHECK_(r[i] == (char)(i % 128), "[%lu] exp: '%c' != got: '%c'", i,
                (char)(i % 128), r[i]);

  LOG("\tafter shrinking mremap with %lu ===\n", re_shrink_n);
  ensuring_free(r);
}

static void test_realloc_from_main_to_mmapped(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = 5;
  char *p = (char *)ensuring_malloc(n);
  TEST_CHECK(p);
  for (size_t i = 0; i < n; i++)
    p[i] = (char)(i % 128);

  MM_ASSERT_MARKER(BY_MMAPPING, 0);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  MM_RESET_MARKER(BY_SBRKING);
  MM_RESET_MARKER(MALLOC_CALLED);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  const size_t re_grow_n = MMAP_SIZE(5);
  char *q = (char *)ensuring_realloc(p, re_grow_n);
  TEST_ASSERT(q != NULL);
  TEST_ASSERT_(p != q, "returned mremapped pointer must be different");

  MM_ASSERT_MARKER(SBRK_TO_MMAP, 1);
  MM_ASSERT_MARKER(MMAPPED_BIGGER, 0);
  MM_ASSERT_MARKER(MUNMAPPED_EXCESS, 0);
  MM_ASSERT_MARKER(MALLOC_CALLED, 1);
  MM_ASSERT_MARKER(BY_MMAPPING, 1);
  MM_ASSERT_MARKER(BY_SBRKING, 0);
  MM_RESET_MARKER(BY_MMAPPING);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  ensure_freed();
  MM_RESET_MARKER(FREE_CALLED);

  for (size_t i = 0; i < n; i++) {
    TEST_CHECK_(q[i] == (char)(i % 128), "[%lu] exp: '%c' != got: '%c'", i,
                (char)(i % 128), q[i]);
  }

  ensuring_free(q);
}

static void test_realloc_from_mmapped_to_main(void) {
  LOG("=== %s: start ===\n", __func__);

  const size_t n = MMAP_SIZE(5);
  char *p = (char *)ensuring_malloc(n);
  TEST_CHECK(p);
  for (size_t i = 0; i < n; i++)
    p[i] = (char)(i % 128);

  MM_ASSERT_MARKER(BY_MMAPPING, 1);
  MM_ASSERT_MARKER(BY_SBRKING, 0);
  MM_RESET_MARKER(BY_MMAPPING);
  MM_RESET_MARKER(MALLOC_CALLED);

  LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

  const size_t re_grow_n = 5;
  char *q = (char *)ensuring_realloc(p, re_grow_n);
  TEST_ASSERT(q != NULL);
  TEST_ASSERT_(p != q, "returned mremapped pointer must be different");

  MM_ASSERT_MARKER(MMAP_TO_SBRK, 1);
  MM_ASSERT_MARKER(MMAPPED_BIGGER, 0);
  MM_ASSERT_MARKER(MUNMAPPED_EXCESS, 0);
  MM_ASSERT_MARKER(MALLOC_CALLED, 1);
  MM_ASSERT_MARKER(BY_MMAPPING, 0);
  MM_ASSERT_MARKER(BY_SBRKING, 1);
  MM_RESET_MARKER(BY_SBRKING);
  MM_ASSERT_MARKER(FREE_CALLED, 1);
  ensure_freed();
  MM_RESET_MARKER(FREE_CALLED);

  for (size_t i = 0; i < re_grow_n; i++) {
    TEST_CHECK_(q[i] == (char)(i % 128), "[%lu] exp: '%c' != got: '%c'", i,
                (char)(i % 128), q[i]);
  }

  ensuring_free(q);
}

static void test_bare_bin_index(void) {
  for (size_t ix = 0; ix < NUM_SMALL_BINS; ix++) {
    size_t real = SMALL_BIN_SIZE_START + (ix * SMALL_BIN_STEP);
    size_t bare_bin_idx = GET_BARE_BIN_IDX(real);
    size_t exp = ix + 1;
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
    size_t real = LARGE_BIN_SIZE_START + ix * LARGE_BIN_STEP;
    size_t bare_bin_idx = GET_BARE_BIN_IDX(real);
    size_t exp = LARGE_BIN_IDX_SHIFT(ix);
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
    size_t real = FAST_BIN_SIZE_START + ix * FAST_BIN_STEP;
    size_t fast_bin_idx = GET_FAST_BIN_IDX(real);
    TEST_ASSERT_(fast_bin_idx == ix, "[fast bin] idx: %lu != %lu", fast_bin_idx,
                 ix);
  }
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
    {"test_free_no_release_or_fusion", test_free_no_release_or_fusion},
    {"test_free_with_fusion_no_release", test_free_with_fusion_no_release},
    {"test_copy_block", test_copy_block},
    {"test_realloc_grow_and_shrink", test_realloc_grow_and_shrink},
    {"test_realloc_with_size_zero", test_realloc_with_size_zero},
    {"test_mmap", test_mmap},
    {"test_bin_macros", test_bin_macros},
    {"test_mark_unmark_binmap", test_mark_unmark_binmap},
    {"test_bin_repositioning_trick", test_bin_repositioning_trick},
    {"test_mremap", test_mremap},
    {"test_realloc_from_main_to_mmapped", test_realloc_from_main_to_mmapped},
    {"test_realloc_from_mmapped_to_main", test_realloc_from_mmapped_to_main},
    {"test_bare_bin_index", test_bare_bin_index},
    {NULL, NULL}};
#endif
