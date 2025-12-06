#pragma once

#include <block.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct Arena *ArenaPtr;
typedef struct MMapArena *MMapArenaPtr;

extern const size_t MAX_ALIGNMENT;
#define ALIGNMENT MAX_ALIGNMENT

#define MAP_ELMNT_TYPE uint32_t
#define MIN_CAP_FOR_MMAP (131072) // 128 KiB
#define NUM_BINS (1 + NUM_SMALL_BINS + NUM_LARGE_BINS)
// To be able to pull the repositioning trick to first element,
// we need a buffer with the size of the rest of the block.
#define OFFSET_OF_NEXT offsetof(struct SBlock, next)
#define SLOTS_FOR_BLOCK_OFFSET_ALIGNMENT (OFFSET_OF_NEXT / sizeof(size_t))
#define BLOCK_OFFSET_ALIGNED_IX(ix) (ix + SLOTS_FOR_BLOCK_OFFSET_ALIGNMENT)

#define NUM_SLOTS_IN_BIN (SLOTS_FOR_BLOCK_OFFSET_ALIGNMENT + NUM_BINS * 2)

#define NUM_SMALL_BINS (64)
#define SMALL_BIN_SIZE_START (ALIGNMENT)
#define SMALL_BIN_STEP (ALIGNMENT)
#define SMALL_BIN_SIZE_CAP                                                     \
  (SMALL_BIN_SIZE_START + NUM_SMALL_BINS * SMALL_BIN_STEP - 1)

#define NUM_LARGE_BINS (63)
#define LARGE_BIN_SIZE_START (SMALL_BIN_SIZE_CAP + ALIGNMENT)
// In glibc malloc, spacing seems to vary, 64, 512, 4096 etc. but for simplicity
// ours is constant, [512+step:131_072-step:step] where we choose the step as
// 2048. The largest memory size we will have is 129_536. The largest bin,
// will have the sizes btw. 129_536 to 131_072 (128KiB). Above that is mmaps
// territory.
#define LARGE_BIN_STEP (2048)
#define LARGE_BIN_SIZE_CAP                                                     \
  (LARGE_BIN_SIZE_START + LARGE_BIN_STEP * NUM_LARGE_BINS - 1)
#define LARGE_BIN_IDX_SHIFT(idx) (size_t)(1 + NUM_SMALL_BINS + idx)

#define NUM_FAST_BINS (10)
#define FAST_BIN_SIZE_START (ALIGNMENT)
#define FAST_BIN_STEP (ALIGNMENT)
#define FAST_BIN_SIZE_CAP (FAST_BIN_SIZE_START + ALIGNMENT * FAST_BIN_STEP - 1)

#define MAP_STEP_BY_TYPE_WIDTH (sizeof(MAP_ELMNT_TYPE) * 8)
#define NUM_ELMNTS_NECESSARY_TO_MAP ((NUM_BINS) / MAP_STEP_BY_TYPE_WIDTH)

#define BIN_MAP_INDEX(b) (b / MAP_STEP_BY_TYPE_WIDTH)
#define CORRESPONDING_BIT_INDEX(bin_ix) (bin_ix & (MAP_STEP_BY_TYPE_WIDTH - 1))
#define CORRESPONDING_BIT(bin_ix) ((size_t)1 << CORRESPONDING_BIT_INDEX(bin_ix))

#define MARK_BIN(a, bin_ix)                                                    \
  (a.binmap[BIN_MAP_INDEX(bin_ix)] |= (CORRESPONDING_BIT(bin_ix)))

#define UNMARK_BIN(a, bin_ix)                                                  \
  (a.binmap[BIN_MAP_INDEX(bin_ix)] &= ~CORRESPONDING_BIT(bin_ix))

#define READ_BINMAP(a, bin_ix)                                                 \
  (a.binmap[BIN_MAP_INDEX(bin_ix)] & CORRESPONDING_BIT(bin_ix))

// The repositioning trick glibc leverages for faking BlockPtr's in bins
// NOTE: first element of the list (bin[0], bin[1]) are for unsorted bin
#define BLK_PTR_IN_BIN_AT(a, i) ((BlockPtr)(&a.bins[i * 2]))

// Bare in the sense that SLOTS_FOR_BLOCK_OFFSET_ALIGNMENT is not accounted for,
// the index returned must be retrieved with BLK_PTR_IN_BIN_AT to
// properly index the corresponding bin.
// NOTE: small bin starts at index 1, thus we don't -1.
#define GET_LARGE_BIN_IDX(aligned_req_size)                                    \
  ((aligned_req_size < LARGE_BIN_SIZE_START)                                   \
       ? 0                                                                     \
       : ((aligned_req_size - LARGE_BIN_SIZE_START) / LARGE_BIN_STEP))
#define GET_BARE_BIN_IDX(aligned_req_size)                                     \
  (aligned_req_size <= SMALL_BIN_SIZE_CAP                                      \
       ? (aligned_req_size / SMALL_BIN_STEP)                                   \
       : LARGE_BIN_IDX_SHIFT(GET_LARGE_BIN_IDX(aligned_req_size)))

// Note: thread-safety is not a concern at the moment,
// thus we only have 2 arenas: sbrk arena and mmap arena.
struct Arena {
  BlockPtr head;
  BlockPtr tail;
  /*
   * unsorted bin: bins[0]
   * small bins: bins[1:NUM_SMALL_BINS+1] with values
   *    [SMALL_BIN_SIZE_START : SMALL_BIN_SIZE_CAP : MIN_ALIGNMENT]
   *    where generally SMALL_BIN_SIZE_CAP <= 512
   * large bins:
   *    bins[NUM_SMALL_BINS*2 : NUM_SLOTS_IN_BIN : LARGE_BIN_SIZE_SPACING]
   *    reversely sorted (desc. order). range of sizes, >
   * 512 bytes each bin has 2 pointers fw, bk to line up a doubly linkedlist,
   * thus the multiplication
   */
  BlockPtr bins[NUM_SLOTS_IN_BIN];
  // If a bin is empty, the bit that the corresponds to the index of that bin is
  // set to 0. Since we have NUM_CHUNK_SIZES bins and not all architectures have
  // a type that can  support it we "dynamically" arrange an array if we need
  // more than one.
  MAP_ELMNT_TYPE binmap[NUM_ELMNTS_NECESSARY_TO_MAP];
  // range of [FAST_BIN_SIZE_START : FAST_BIN_SIZE_CAP : MIN_ALIGNMENT] bytes,
  // no 2 contiguous chunks are fusied.
  BlockPtr fastbins[NUM_FAST_BINS];
  size_t total_bytes_allocated;
  size_t total_free_bytes;
};

struct MMapArena {
  BlockPtr head;
  BlockPtr tail;
  size_t total_bytes_allocated;
  size_t total_free_bytes;
};

BlockPtr get_block_from_main_arena(ArenaPtr, void *);
BlockPtr get_block_from_mmapped_arena(MMapArenaPtr, void *);
void allocated_bytes_update(size_t *, int);

extern void debug_write_str(const char *);
extern void debug_write_ptr(const void *);
