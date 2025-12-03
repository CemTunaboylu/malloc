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

#define CURRENT_BRK mm_sbrk(0)

enum Allocation {
  SBRK,
  MMAP,
};

enum Allocation allocation_type_for(size_t aligned_size) {
  return ((aligned_size > MIN_CAP_FOR_MMAP) ? MMAP : SBRK);
}

void *MALLOC(size_t);

extern size_t SIZE_OF_BLOCK;

/* ----- arena ----- */

ArenaPtr a_head;
static char head_buffer[sizeof(struct Arena)] = {0};

MMapArenaPtr ma_head;
static char mm_head_buffer[sizeof(struct MMapArena)] = {0};

__attribute__((constructor)) void init_arena_heads(void) {
  a_head = (ArenaPtr)&head_buffer;
  ma_head = (MMapArenaPtr)&mm_head_buffer;
}

BlockPtr get_block_from_arenas(void *p) {
  BlockPtr bp = get_block_from_main_arena(a_head, p);
  // try mmap arena
  if (bp == NULL)
    bp = get_block_from_mmapped_arena(ma_head, p);
  return bp;
}

void correct_tail_if_eaten(BlockPtr blk) {
  int is_tail_eaten =
      (blk < a_head->tail) && ((void *)a_head->tail < (void *)end(blk));
  if (is_tail_eaten)
    a_head->tail = blk;
}

void insert_into_belonging_arena(BlockPtr b, size_t total_bytes_to_allocated,
                                 enum Allocation allocation) {
  size_t *allocated_bytes_ptr;
  BlockPtr *tail;
  if (allocation == MMAP) {
    if (!ma_head->head) {
      ma_head->head = b;
    }
    tail = &(ma_head->tail);
    allocated_bytes_ptr = &(ma_head->total_bytes_allocated);
  } else {
    if (!a_head->head) {
      a_head->head = b;
    }
    tail = &(a_head->tail);
    allocated_bytes_ptr = &(a_head->total_bytes_allocated);
  }

  // if there is a last, append this block there
  if (*tail) {
    (*tail)->next = b;
    b->prev = *tail;
  }
  *tail = b;
  allocated_bytes_update(allocated_bytes_ptr, total_bytes_to_allocated);
}

BlockPtr extend_heap(size_t aligned_size, enum Allocation allocation) {
  BlockPtr b = CURRENT_BRK;
  size_t total_bytes_to_allocate = SIZE_OF_BLOCK + aligned_size;
  void *requested;
  if (allocation == MMAP) {
    requested = mm_mmap(total_bytes_to_allocate);
  } else {
    requested = mm_sbrk(total_bytes_to_allocate);
  }
  if (IS_FAILED_BY_PTR(requested)) {
    perror("failed to allocate memory");
    return NULL;
  }

  if (allocation == SBRK)
    MM_ASSERT((void *)b == requested);

  b = (BlockPtr)requested;
  b->size = aligned_size;
  if (allocation == MMAP)
    mark_as_mmapped(b);
  b->next = NULL;
  b->prev = NULL;
  b->end_of_alloc_mem = end(b);

  insert_into_belonging_arena(b, total_bytes_to_allocate, allocation);

  return b;
}

// we don't search on mmapped arenas, if it is freed, we munmap it immediately.
BlockPtr first_fit_find(size_t aligned_size) {
  BlockPtr curr = a_head->head;
  // as long as we have block at hand, and it's either NOT free or NOT big
  // enough
  while (curr && !(is_free(curr) && get_true_size(curr) >= aligned_size)) {
    curr = curr->next;
  }
  return curr;
}

/* ----- allocators ----- */

// allocate memory for an array of length len consisting of
// memory chunks of size size_of (of objects of size_of)
// properly aligned for object
// if succeeds, initialize all bytes to 0.
void *CALLOC(size_t len, size_t size_of) {
  MM_MARK(CALLOC_CALLED);
  if (size_of != 0 && len > (SIZE_MAX / size_of)) {
    return NULL;
  }
  size_t total_bytes = len * size_of;
  unsigned char *p = (unsigned char *)MALLOC(total_bytes);
  if (p == NULL) {
    return NULL;
  }
  for (size_t i = 0; i < total_bytes; i++) {
    p[i] = 0;
  }
  return p;
}

void FREE(void *p) {
  if (p == NULL)
    return;
  MM_MARK(FREE_CALLED);
  BlockPtr blk = get_block_from_arenas(p);
  if (blk == NULL)
    return;

  // guard for double free
  if (is_free(blk)) {
#ifdef TESTING
    MM_ASSERT(0);
#else
    debug_write_str("double free: ");
    debug_write_ptr(p);
    debug_write_str("\n");
#endif
    return;
  }

  mark_as_free(blk);
  MM_MARK(FREED);

  if (!is_mmapped(blk)) {
    fuse_fwd(blk);
    fuse_bwd(&blk);
    correct_tail_if_eaten(blk);
  }

  int is_at_tail = (!blk->next);
  int is_at_head = (!blk->prev);

  size_t back = SIZE_OF_BLOCK + get_true_size(blk);
  // if it is mmapped, just munmap it
  // TODO: add mmap marker
  if (is_mmapped(blk)) {
    MM_ASSERT(ma_head->total_bytes_allocated >= back);
    if (is_at_tail)
      ma_head->tail = blk->prev;
    if (blk->prev)
      blk->prev->next = blk->next;
    if (blk->next)
      blk->next->prev = blk->prev;
    mm_munmap((void *)blk, get_true_size(blk) + SIZE_OF_BLOCK);
    MM_MARK(MUNMAPPED);
    allocated_bytes_update(&(ma_head->total_bytes_allocated), -back);
    return;
  }

  if (!is_at_tail) {
    return;
  }

  // TODO:  we must find delegate freeing to which ever arena this chunk is
  // from
  void *old_tail = CURRENT_BRK;
  BlockPtr prev_of_tail = a_head->tail->prev;
  if (mm_sbrk(-back) == (void *)-1) {
    perror("error while releasing the tail");
    return;
  }

  // iff we truly release some pages, then we can project the change
  MM_ASSERT((char *)old_tail > (char *)CURRENT_BRK);
  MM_MARK(RELEASED);
  MM_ASSERT(a_head->total_bytes_allocated >= back);
  a_head->tail = prev_of_tail;
  allocated_bytes_update(&(a_head->total_bytes_allocated), -back);
  if (!is_at_head)
    a_head->tail->next = NULL;
  else {
    a_head->head = NULL;
    a_head->tail = NULL;
  }
}

static inline void split(BlockPtr blk, size_t aligned_size) {
  split_block(blk, aligned_size);
  if (a_head->tail == blk) {
    a_head->tail = blk->next;
  }
}

void *MALLOC(size_t size) {
  MM_MARK(MALLOC_CALLED);
  if (size == 0)
    return NULL;

  size_t aligned_size = align(size);
  enum Allocation allocation = allocation_type_for(aligned_size);
  BlockPtr blk;

  if (allocation == MMAP || a_head->head == NULL) {
    // extend_heap sets the head if it finds out that it is null
    blk = extend_heap(aligned_size, allocation);
  } else {
    blk = first_fit_find(aligned_size);
    if (blk == NULL) {
      // if failed nothing to do, if not block is not larger than size
      blk = extend_heap(aligned_size, allocation);
    }
  }

  if (blk == NULL) {
    return NULL;
  }

  if (SBRK == allocation && is_splittable(blk, aligned_size)) {
    split(blk, aligned_size);
  }
  mark_as_used(blk);
  return (void *)allocated_memory(blk);
}

static inline void *realloc_from_mmap_to_mmap(BlockPtr blk,
                                              size_t aligned_size) {
  size_t true_size = get_true_size(blk);
  void *p = allocated_memory(blk);
  // We have more than we need, munmap the unneeded part from the end, and
  // return the same pointer. Nothing in the arena linkedlist changes.
  if (true_size > aligned_size) {
    MM_MARK(MUNMAPPED_EXCESS);
    size_t to_munmap_size = true_size - aligned_size;
    void *moved_p = ((char *)p + aligned_size);
    mm_munmap(moved_p, to_munmap_size);
    // do not have to re-set the flags since alignment protects their values
    blk->size -= to_munmap_size;
    // update the user memory pointer
    blk->end_of_alloc_mem = end(blk);
    return p;
  }
  // Has to mmap a bigger chunk.
  void *new = MALLOC(aligned_size);
  BlockPtr new_blk = (BlockPtr)new;
  deep_copy_user_memory(blk, new_blk);
  transfer_flags(blk, new_blk);
  switch_places_in_list(blk, new_blk);
  // Since this is new memory, arena's head/tail must be updated if necessary
  if (ma_head->head == blk) {
    ma_head->head = new_blk;
  } else if (ma_head->tail == blk) {
    ma_head->tail = new_blk;
  }
  MM_MARK(MMAPPED_BIGGER);
  FREE(p);
  return new;
}

/* static inline void prepend_to_main_arena(BlockPtr b) { */
/*   // already at the head */
/*   if (b->prev == NULL) */
/*     return; */
/*   // remove b from the middle */
/*   b->next->prev = b->prev; */
/*   b->prev->next = b->next; */
/*   // prepend b to head */
/*   a_head->head->prev = b; */
/*   b->next = a_head->head; */
/*   a_head->head = b; */
/* } */

/* static inline void append_to_main_arena(BlockPtr b) { */
/*   // already at the tail */
/*   if (b->next == NULL) */
/*     return; */
/*   // remove b from the middle */
/*   b->next->prev = b->prev; */
/*   b->prev->next = b->next; */
/*   // append b to tail */
/*   a_head->tail->next = b; */
/*   b->prev = a_head->tail; */
/*   a_head->tail = b; */
/* } */

void *realloc_from_sbrk_to_mmap(BlockPtr blk, size_t aligned_size);
void *realloc_from_mmap_to_sbrk(BlockPtr blk, size_t aligned_size);

void *realloc_from_sbrk_to_sbrk(BlockPtr blk, size_t aligned_size) {
  // try to grow in-place
  // TODO: can grow backwards as well, but will change this anyway
  while (get_true_size(blk) < aligned_size && is_next_fusable(blk)) {
    if (fuse_next(blk) == -1)
      break;
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
    FREE(p);
    return n;
  }
  // grew or had enough but may need splitting now
  else if (is_splittable(blk, aligned_size)) {
    MM_MARK(REALLOC_ENOUGH_SIZE);
    split(blk, aligned_size);
  }
  return p;
}

// TODO: if mmaped, what to do?
void *REALLOC(void *p, size_t size) {
  MM_MARK(REALLOC_CALLED);
  // if we don't have anywhere to realloc, it is effectively a malloc
  if (p == NULL)
    return MALLOC(size);

  if (size == 0) {
    FREE(p);
    return NULL;
  }
  BlockPtr blk = get_block_from_arenas(p);
  if (blk == NULL)
    return NULL;

  // the block must be aligned
  size = align_up_fundamental(size);

  size_t true_size = get_true_size(blk);

  if (true_size == size)
    return p;

  enum Allocation new_allocation = allocation_type_for(size);
  int from_mmapped = is_mmapped(blk);
  int to_mmapped = MMAP == new_allocation;

  // <from_mmap_or_sbrk><to_mmap_or_sbrk>
  int from_to = (from_mmapped << 0) | to_mmapped;

  switch (from_to) {
  case 0: // 00 : SBRK->SBRK
    return realloc_from_sbrk_to_sbrk(blk, size);
  case 1: // 01 : SBRK->MMAP
    debug_write_str("sbrk to mmap is not implemented yet");
    break;
  case 2: // 10 : MMAP->SBRK
    debug_write_str("mmap to sbrk is not implemented yet");
    break;
  case 3: // 11 : MMAP->MMAP
    return realloc_from_mmap_to_mmap(blk, size);
  default:
    debug_write_str("unreachable reallocation scenario reached");
    break;
  }
  return p;
}
