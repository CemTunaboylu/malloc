#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include "arena.h"
#include "block.h"
#include "internal.h"
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

enum Allocation {
  SBRK,
  MMAP,
};

enum Allocation allocation_type_for(const size_t aligned_size) {
  return ((aligned_size > MIN_CAP_FOR_MMAP) ? MMAP : SBRK);
}

void *CALLOC(size_t len, size_t size_of);
void FREE(void *p);
void *MALLOC(size_t);
void *REALLOC(void *p, size_t size);

extern size_t SIZE_OF_BLOCK;
extern int is_at_brk(const BlockPtr);

/* ----- arena ----- */

#ifndef TESTING
static
#endif
    struct Arena a_head = {.head = NULL,
                           .tail = NULL,
                           .bins = {NULL},
                           .binmap = {0},
                           .fastbins = {NULL},
                           .total_bytes_allocated = 0};

#ifndef TESTING
static
#endif
    struct MMapArena ma_head = {.total_bytes_allocated = 0,
                                .num_mmapped_regions = 0};

__attribute__((constructor)) void init_main_arena_bins(void) {
  BlockPtr bin;
  for (size_t i = 0; i < NUM_BINS; i++) {
    bin = BLK_PTR_IN_BIN_AT(a_head, i);
    bin->next = bin;
    bin->prev = bin;
  }
}

static inline int is_at_main_arena_tail(const BlockPtr blk) {
  return (blk == a_head.tail);
}

static inline int is_at_main_arena_head(const BlockPtr blk) {
  return (blk == a_head.head);
}

static inline BlockPtr get_block_from_arenas(void *p) {
  BlockPtr bp = get_block_from_main_arena(&a_head, p);
  // try mmap arena
  if (NULL == bp)
    bp = get_block_from_mmapped_arena(&ma_head, p);
  return bp;
}

#ifndef TESTING
static inline
#endif
    void correct_tail_if_eaten(const BlockPtr blk) {
  int is_tail_eaten =
      (blk < a_head.tail) && ((void *)a_head.tail <= (void *)next(blk));
  if (is_tail_eaten)
    a_head.tail = blk;
}

static inline void
insert_into_belonging_arena(BlockPtr b, const size_t total_bytes_to_allocated,
                            enum Allocation allocation) {
  size_t *allocated_bytes_ptr;
  BlockPtr *tail;
  if (MMAP == allocation) {
    allocated_bytes_ptr = &(ma_head.total_bytes_allocated);
    ma_head.num_mmapped_regions += 1;
  } else {
    if (!a_head.head) {
      a_head.head = b;
    }
    tail = &(a_head.tail);
    allocated_bytes_ptr = &(a_head.total_bytes_allocated);
    // if there is a last, append this block there
    if (*tail && is_free(*tail)) {
      propagate_free_to_next(*tail);
    }
    *tail = b;
  }

  allocated_bytes_update(allocated_bytes_ptr, total_bytes_to_allocated);
}

BlockPtr extend_heap(const size_t aligned_size, enum Allocation allocation) {
  BlockPtr b = CURRENT_BRK;
  const size_t total_bytes_to_allocate = SIZE_OF_BLOCK + aligned_size;
  void *requested;
  if (MMAP == allocation) {
    requested = mm_mmap(total_bytes_to_allocate);
    MM_MARK(BY_MMAPPING);
  } else {
    requested = mm_sbrk(total_bytes_to_allocate);
    MM_MARK(BY_SBRKING);
  }
  if (IS_FAILED_BY_PTR(requested)) {
    perror("failed to allocate memory");
    return NULL;
  }

  if (SBRK == allocation)
    MM_ASSERT((void *)b == requested);

  b = (BlockPtr)requested;
  b->size = aligned_size;

  if (MMAP == allocation)
    mark_as_mmapped(b);

  b->next = b->prev = NULL;
  insert_into_belonging_arena(b, total_bytes_to_allocate, allocation);

  return b;
}

/*
 * from:
 *   _____     _____
 *  |__s__|<->|__n__|
 *
 *  to:
 *   _____     _____     _____
 *  |__s__|<->|__N__|<->|__n__|
 */
#ifndef TESTING
static inline
#endif
    void append(BlockPtr sentinel, BlockPtr new_next) {
  BlockPtr next = sentinel->next;
  sentinel->next = new_next;
  new_next->next = next;
  next->prev = new_next;
  new_next->prev = sentinel;
}

static inline void insert_in_unsorted_bin(BlockPtr blk) {
  BlockPtr unsorted_sentinel = BLK_PTR_OF_UNSORTED(a_head);
  append(unsorted_sentinel, blk);
  // We don't normally check on unsorted bin's bitmap, thus we don't housekeep.
  MM_MARK(PUT_IN_UNSORTED_BIN);
}

#ifndef TESTING
static inline
#endif
    void insert_in_fastbin(BlockPtr blk) {
  // Fastbins are not meant to be fused with other chunks, except we
  // consolidate them on purpose. Thus, we keep it as 'used' to avoid
  // pre-mature fusion.
  mark_as_used(blk);
  const size_t true_size = get_true_size(blk);
  const size_t idx = GET_FAST_BIN_IDX(true_size);
  if (NULL == a_head.fastbins[idx])
    a_head.fastbins[idx] = blk;
  else {
    blk->next = a_head.fastbins[idx];
    a_head.fastbins[idx] = blk;
  }
  MM_MARK(PUT_IN_FASTBIN);
}

static inline void hot_insert_in_appropriate_bin(BlockPtr blk) {
  const size_t true_size = get_true_size(blk);
  if (CAN_BE_FAST_BINNED(true_size))
    insert_in_fastbin(blk);
  else
    insert_in_unsorted_bin(blk);
}

static inline BlockPtr fast_find(const size_t aligned_size) {
  if (!CAN_BE_FAST_BINNED(aligned_size)) {
    return NULL;
  }
  const size_t idx = GET_FAST_BIN_IDX(aligned_size);
  // NOTE: fastbins are singly-linked
  const BlockPtr head = a_head.fastbins[idx];
  if (NULL == head)
    return NULL;

  MOVE_FAST_BIN_TO_NEXT(a_head, idx);
  MM_MARK(FASTBINNED);
  head->next = NULL;
  return head;
}

static inline int detaching_fuse_fwd(BlockPtr blk) {
  // The only chunks that can be fused together are from bins. Fastbin chunkss
  // prevent pre-mature fusion by marking themselves 'used'. When they are being
  // deliberately consolidated, they are moved one by one to unsorted bin, thus
  // they will be merged from there.
  const int did_fuse_next = fuse_next(blk);
  if (-1 == did_fuse_next)
    return -1;
  // fuse_next removes the chunk from the list but does not check if it gets
  // emptied. We intentionally are lazy as glibc to not fix the bitmap
  // immediately.
  // See the binmap notes on arena.h.
  return 0;
}

static inline int detaching_fuse_bwd(BlockPtr *blk) {
  // The only chunks that can be fused together are from bins. Fastbin chunkss
  // prevent pre-mature fusion by marking themselves 'used'. When they are being
  // deliberately consolidated, they are moved one by one to unsorted bin, thus
  // they will be merged from there.
  const int did_fuse_prev = fuse_prev(blk);
  if (-1 == did_fuse_prev)
    return -1;
  // fuse_prev removes the chunk from the list but does not check if it gets
  // emptied. We intentionally are lazy as glibc to not fix the bitmap
  // immediately.
  // See the binmap notes on arena.h.
  return 0;
}

#ifndef TESTING
static inline
#endif
    void fuse_fwd(BlockPtr b) {
  while (detaching_fuse_fwd(b) == 0) {
    MM_MARK(FUSE_FWD_CALLED);
  }
  correct_tail_if_eaten(b);
}

#ifndef TESTING
static inline
#endif
    void fuse_bwd(BlockPtr *b) {
  while (detaching_fuse_bwd(b) == 0) {
    MM_MARK(FUSE_BWD_CALLED);
  }
  correct_tail_if_eaten(*b);
}

#ifndef TESTING
static inline
#endif
    void fuse_with_neighbors(BlockPtr *b) {
  fuse_fwd(*b);
  fuse_bwd(b);
}

// Remove each block from each fast bin, fuse them as you go, put them into
// unsorted bin.
#ifndef TESTING
static inline
#endif
    void consolidate_fastbins(void) {
  // Move blocks from fast bins while fusing along the way to unsorted bin.
  for (size_t f_idx = 0; f_idx < NUM_FAST_BINS; f_idx++) {
    BlockPtr head;
    while (NULL != a_head.fastbins[f_idx]) {
      MM_MARK(CONSOLIDATED);
      head = a_head.fastbins[f_idx];
      MM_ASSERT(head->next != head);
      MOVE_FAST_BIN_TO_NEXT(a_head, f_idx);
      // Fastbins are marked as used to prevent premature coalescing, thus we
      // first need to mark them as free.
      mark_as_free(head);
      fuse_with_neighbors(&head);
      MM_ASSERT(is_free(head));
      insert_in_unsorted_bin(head);
    }
  }
}

static inline BlockPtr
find_smallest_fitting_large_bin_block(BlockPtr sentinel,
                                      const size_t true_size) {
  // We are in the large bin that the block should be put.
  BlockPtr large = sentinel->next;
  while (sentinel != large->next && get_true_size(large->next) > true_size) {
    large = large->next;
  }
  return large;
}

#define IS_BLOCKS_SIZE_ENOUGH(blk, size) (get_true_size(blk) >= size)

#ifndef TESTING
static inline
#endif
    // Searches for a best fit, while consolidating failed attempts i.e. if size
    // is not enough, fuse and check again, if not put in the appropriate bin
    // (small or large).
    // NOTE: To keep things simple, we pay the price of sorted insertion to
    // large bins.
    BlockPtr search_in_unsorted_consolidating(const size_t aligned_size) {
  const BlockPtr sentinel = BLK_PTR_OF_UNSORTED(a_head);
  if (IS_LONE_SENTINEL(sentinel))
    return NULL;
  BlockPtr blk = sentinel->next;
  BlockPtr nxt = NULL;
  while (sentinel != blk) {
    nxt = blk->next;
    MM_ASSERT(is_free(blk));
    remove_from_linkedlist(blk);
    if (IS_BLOCKS_SIZE_ENOUGH(blk, aligned_size)) {
      MM_MARK(UNSORTED_BINNED);
      return blk;
    }
    fuse_with_neighbors(&blk);
    if (IS_BLOCKS_SIZE_ENOUGH(blk, aligned_size)) {
      MM_MARK(UNSORTED_BINNED);
      return blk;
    }
    const size_t true_size = get_true_size(blk);
    const size_t bin_idx = GET_BARE_BIN_IDX(true_size);
    BlockPtr bin_sentinel = BLK_PTR_IN_BIN_AT(a_head, bin_idx);

    if (IS_SMALL(true_size)) {
      append(bin_sentinel, blk);
    } else {
      // We are in the large bin that the block should be put.
      BlockPtr append_after =
          find_smallest_fitting_large_bin_block(bin_sentinel, true_size);
      // get_true_size(append_after->next) <= true_size, thus we should append
      // blk here.
      append(append_after, blk);
    }
    if (0 == READ_BINMAP(a_head, bin_idx))
      MARK_BIN(a_head, bin_idx);

    blk = nxt;
  }
  // We don't normally check on unsorted bin's bitmap, thus we don't housekeep.

  return NULL;
}

static inline BlockPtr get_from_small_bin(const size_t aligned_size) {
  size_t bare_idx = GET_BARE_BIN_IDX(aligned_size);
  // Check if the exact sized bin has a chunk from bitmap.
  if (READ_BINMAP(a_head, bare_idx) == 0)
    return NULL;

  BlockPtr sentinel = BLK_PTR_IN_BIN_AT(a_head, bare_idx);
  if (IS_LONE_SENTINEL(sentinel)) {
    // We housekeep so that next calls don't have to.
    UNMARK_BIN(a_head, bare_idx);
    return NULL;
  }
  BlockPtr tail = sentinel->prev;
  remove_from_linkedlist(tail);
  MM_MARK(SMALL_BINNED);
  return tail;
}

static inline BlockPtr get_from_large_bin(const size_t aligned_size) {
  size_t bare_idx = GET_BARE_BIN_IDX(aligned_size);
  // The bin has an element
  if (READ_BINMAP(a_head, bare_idx) == 0)
    return NULL;

  const BlockPtr sentinel = BLK_PTR_IN_BIN_AT(a_head, bare_idx);
  if (IS_LONE_SENTINEL(sentinel)) {
    // We housekeep so that next calls don't have to.
    UNMARK_BIN(a_head, bare_idx);
    return NULL;
  }
  BlockPtr larger =
      find_smallest_fitting_large_bin_block(sentinel, aligned_size);

  if (get_true_size(larger) < aligned_size)
    return NULL;
  BlockPtr larger_next = larger->next;
  if (larger_next && larger_next != sentinel &&
      get_true_size(larger_next) == aligned_size)
    larger = larger_next;
  remove_from_linkedlist(larger);
  MM_MARK(LARGE_BINNED);
  return larger;
}

// Assuming that, we alreaedy checked for < MIN_CAP_FOR_MMAP.
static inline BlockPtr find_in_bins(const size_t aligned_size) {
  if (IS_SMALL(aligned_size)) {
    BlockPtr small = get_from_small_bin(aligned_size);
    if (small)
      return small;

    BlockPtr from_unsorted = search_in_unsorted_consolidating(aligned_size);
    if (from_unsorted)
      return from_unsorted;
    // If we cannot fast bin this (larger than bigger fast bin), but small
    // enough to small bin, try consolidating fast bins and check again in
    // unsorted bin.
    consolidate_fastbins();
    // Try unsorted bins again.
    from_unsorted = search_in_unsorted_consolidating(aligned_size);
    if (from_unsorted)
      return from_unsorted;
    return NULL;
  }
  // At this point, we know that aligned_size must be large i.e. cannot be fast
  // or small binned. We consolidate fast bins with the hope of finding one.
  consolidate_fastbins();
  BlockPtr blk = search_in_unsorted_consolidating(aligned_size);
  if (blk)
    return blk;

  return get_from_large_bin(aligned_size);
}

// We don't search on mmapped arenas, cannot find a free block in it's list
// because when it is freed, we munmap it immediately.
BlockPtr best_fit_find(size_t aligned_size) {
  // first check the fast bins
  BlockPtr blk = fast_find(aligned_size);

  if (blk)
    return blk;

  return find_in_bins(aligned_size);
}

/* ----- allocators ----- */

// Allocate memory for an array of length len consisting of
// memory chunks of size size_of (of objects of size_of)
// properly aligned for object.
// If succeeds, initialize all bytes to 0.
void *CALLOC(size_t len, size_t size_of) {
  MM_MARK(CALLOC_CALLED);
  if (0 != size_of && len > (SIZE_MAX / size_of)) {
    return NULL;
  }
  const size_t total_bytes = len * size_of;
  unsigned char *p = (unsigned char *)MALLOC(total_bytes);
  if (NULL == p) {
    return NULL;
  }
  for (size_t i = 0; i < total_bytes; i++) {
    p[i] = 0;
  }
  return p;
}

static inline void munmap(const BlockPtr blk) {
  const size_t back = SIZE_OF_BLOCK + get_true_size(blk);

  MM_ASSERT(ma_head.total_bytes_allocated >= back);
  int result = mm_munmap((void *)blk, back);
  if (-1 == result) {
    perror("error while munmapping");
    return;
  }
  MM_MARK(MUNMAPPED);
  ma_head.num_mmapped_regions -= 1;
  allocated_bytes_update(&(ma_head.total_bytes_allocated), -back);
}

#ifndef TESTING
static inline
#endif
    void release(BlockPtr blk) {
  remove_from_linkedlist(blk);
  const int is_at_head = is_at_main_arena_head(blk);
  const size_t back = SIZE_OF_BLOCK + get_true_size(blk);

  void *old_tail = CURRENT_BRK;
  MM_ASSERT((BlockPtr)old_tail == next(a_head.tail));
  BlockPtr prev_of_tail = is_at_head ? NULL : prev(a_head.tail);

  if (IS_FAILED_BY_PTR(mm_sbrk(-back))) {
    perror("error while releasing the tail");
    return;
  }

  MM_ASSERT((char *)old_tail > (char *)CURRENT_BRK);
  MM_MARK(RELEASED);
  MM_ASSERT(a_head.total_bytes_allocated >= back);

  a_head.tail = prev_of_tail;
  allocated_bytes_update(&(a_head.total_bytes_allocated), -back);
  if (is_at_head) {
    a_head.head = NULL;
  }
}

static inline void free_or_maybe_release_sbrked(BlockPtr blk) {
  int is_tail = is_at_main_arena_tail(blk);
  // If not at tail and small enough to fast bin, put it in the
  // fast bin without fusing with any neighbors.
  if (!is_tail && CAN_BE_FAST_BINNED(get_true_size(blk))) {
    insert_in_fastbin(blk);
    return;
  }

  fuse_fwd(blk);
  fuse_bwd(&blk);
  correct_tail_if_eaten(blk);

  is_tail = is_at_main_arena_tail(blk);

  if (!is_tail) {
    insert_in_unsorted_bin(blk);
    return;
  }
  release(blk);
}

static inline int is_double_free(BlockPtr blk) {
  if (!is_free(blk))
    return 0;
#ifdef TESTING
  MM_MARK(DOUBLE_FREE);
#else
  debug_write_str("double free: ");
  debug_write_ptr(p);
  debug_write_str("\n");
#endif
  return 1;
}

void FREE(void *p) {
  if (NULL == p)
    return;
  MM_MARK(FREE_CALLED);

  BlockPtr blk = get_block_from_arenas(p);
  if (NULL == blk) {
#ifdef TESTING
    MM_MARK(FREE_ON_BAD_PTR);
#endif
    return;
  }

  // guard for double free
  if (is_double_free(blk))
    return;

  mark_as_free(blk);
  MM_MARK(FREED);

  // if it is mmapped, just munmap it
  if (is_mmapped(blk)) {
    munmap(blk);
    return;
  }

  free_or_maybe_release_sbrked(blk);
}

static inline void split(BlockPtr blk, const size_t aligned_size) {
  split_block(blk, aligned_size);
  BlockPtr nxt = next(blk);
  if (is_at_main_arena_tail(blk)) {
    a_head.tail = nxt;
  }
  hot_insert_in_appropriate_bin(nxt);
}

void *MALLOC(size_t size) {
  MM_MARK(MALLOC_CALLED);
  if (0 == size)
    return NULL;

  const size_t aligned_size = align(size);
  const enum Allocation allocation = allocation_type_for(aligned_size);
  BlockPtr blk;

  if (MMAP == allocation || NULL == a_head.head) {
    // extend_heap sets the head if it finds out that it is null
    blk = extend_heap(aligned_size, allocation);
  } else {
    blk = best_fit_find(aligned_size);
    if ((NULL == blk) || is_at_brk(blk)) {
      // if failed nothing to do, if not block is not larger than size
      blk = extend_heap(aligned_size, allocation);
    }
  }

  if (NULL == blk) {
    return NULL;
  }

  if (is_splittable(blk, aligned_size)) {
    split(blk, aligned_size);
  }

  mark_as_used(blk);
  return (void *)allocated_memory(blk);
}

static inline void *realloc_from_mmap_to_mmap(BlockPtr blk,
                                              const size_t aligned_size) {
  const size_t true_size = get_true_size(blk);
  void *p = allocated_memory(blk);
  // We have more than we need, munmap the unneeded part from the end, and
  // return the same pointer. Nothing in the arena linkedlist changes.
  const size_t full_aligned_size = SIZE_OF_BLOCK + aligned_size;
  const size_t full_old_size = SIZE_OF_BLOCK + true_size;

  void *new = mm_mremap((void *)blk, full_old_size, full_aligned_size);
  if (IS_FAILED_BY_PTR(new)) {
    perror("mremap failed");
    return p;
  }
  if (true_size >= aligned_size) {
    MM_MARK(MUNMAPPED_EXCESS);
  } else {
    MM_MARK(MMAPPED_BIGGER);
  }
  const size_t flagged_size = blk->size;
  const size_t size_update = aligned_size - true_size;
  allocated_bytes_update(&ma_head.total_bytes_allocated, size_update);

  BlockPtr new_blk = (BlockPtr)new;
  // do not have to re-set the flags since alignment protects their values
  if (new_blk == blk) {
    new_blk->size += size_update;
  } else {
    new_blk->size = flagged_size + size_update;
  }
  return allocated_memory(new_blk);
}

static inline void *realloc_btw_main_and_mmapped(BlockPtr blk,
                                                 const size_t aligned_size) {
  void *new = MALLOC(aligned_size);
  if (IS_FAILED_BY_PTR(new))
    return allocated_memory(blk);

  BlockPtr new_blk = reconstruct_from_user_memory(new);
  deep_copy_user_memory(blk, new_blk);

  FREE(allocated_memory(blk));
  return allocated_memory(new_blk);
}

static inline void *realloc_from_sbrk_to_mmap(BlockPtr blk,
                                              const size_t aligned_size) {
  MM_MARK(SBRK_TO_MMAP);
  return realloc_btw_main_and_mmapped(blk, aligned_size);
}
static inline void *realloc_from_mmap_to_sbrk(BlockPtr blk,
                                              const size_t aligned_size) {
  MM_MARK(MMAP_TO_SBRK);
  return realloc_btw_main_and_mmapped(blk, aligned_size);
}

void *realloc_from_sbrk_to_sbrk(BlockPtr blk, const size_t aligned_size) {
  // Try to grow in-place (if needed), note that we only try to grow forward.
  while (get_true_size(blk) < aligned_size && detaching_fuse_fwd(blk) != -1) {
  }
  correct_tail_if_eaten(blk);

  void *p = allocated_memory(blk);
  // could not grow in place enough, allocate new and copy, free old
  if (get_true_size(blk) < aligned_size) {
    void *n = MALLOC(aligned_size);
    if (n == NULL) {
      return p;
    } // current policy: keep old ptr in case out-of-memory
    BlockPtr new_blk = reconstruct_from_user_memory((const void *)n);
    deep_copy_user_memory(blk, new_blk);
    transfer_flags(blk, new_blk);
    BlockPtr prv = prev(blk);
    if (prv && is_free(prv))
      propagate_free_to_next(prv);
    else
      propagate_used_to_next(prv);

    FREE(p);
    return n;
  }
  // grew or had enough but may need splitting now
  if (is_splittable(blk, aligned_size)) {
    MM_MARK(REALLOC_ENOUGH_SIZE);
    split(blk, aligned_size);
  }
  return p;
}

void *REALLOC(void *p, size_t size) {
  MM_MARK(REALLOC_CALLED);
  // If we don't have anywhere to realloc, it is effectively a malloc.
  if (NULL == p)
    return MALLOC(size);

  // If size is not given, it effectively is a free.
  if (0 == size) {
    FREE(p);
    return NULL;
  }
  BlockPtr blk = get_block_from_arenas(p);
  if (NULL == blk)
    return NULL;

  size = align_up_fundamental(size);

  if (get_true_size(blk) == size)
    return p;

  enum Allocation new_allocation = allocation_type_for(size);
  const int from_mmapped = is_mmapped(blk);
  const int to_mmapped = MMAP == new_allocation;

  // <is currently mmapped><will be mapped>
  const int from_to = (from_mmapped << 1) | to_mmapped;

  switch (from_to) {
  case 0: // 00 : SBRK->SBRK
    return realloc_from_sbrk_to_sbrk(blk, size);
  case 1: // 01 : SBRK->MMAP
    return realloc_from_sbrk_to_mmap(blk, size);
  case 2: // 10 : MMAP->SBRK
    return realloc_from_mmap_to_sbrk(blk, size);
  case 3: // 11 : MMAP->MMAP
    return realloc_from_mmap_to_mmap(blk, size);
  default:
    debug_write_str("unreachable reallocation scenario reached");
    break;
  }
  return p;
}
