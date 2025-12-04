#pragma once

#include <block.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct Arena *ArenaPtr;
typedef struct MMapArena *MMapArenaPtr;

#define MAP_ELMNT_TYPE uint32_t
#define MIN_CAP_FOR_MMAP (131072) // 128 KiB
#define NUM_CHUNK_SIZES (128)
#define NUM_FAST_BINS (7)

#define MAP_STEP_BY_TYPE_WIDTH (sizeof(MAP_ELMNT_TYPE) * 8)
#define NUM_ELMNTS_NECESSARY_TO_MAP ((NUM_CHUNK_SIZES) / MAP_STEP_BY_TYPE_WIDTH)

#define BIN_MAP_INDEX(b) (b / MAP_STEP_BY_TYPE_WIDTH)
#define CORRESPONDING_BIT_INDEX(bin_ix) (bin_ix & (MAP_STEP_BY_TYPE_WIDTH - 1))
#define CORRESPONDING_BIT(bin_ix) (1 << CORRESPONDING_BIT_INDEX(bin_ix))

#define MARK_BIN(a, bin_ix)                                                    \
  (a->binmap[BIN_MAP_INDEX(bin_ix)] |= (CORRESPONDING_BIT(bin_ix)))

#define UNMARK_BIN(a, bin_ix)                                                  \
  (a->binmap[BIN_MAP_INDEX(bin_ix)] &= ~CORRESPONDING_BIT(bin_ix))

#define READ_BINMAP(a, bin_ix)                                                 \
  (a->binmap[BIN_MAP_INDEX(bin_ix)] & CORRESPONDING_BIT(bin_ix))

// Note: thread-safety is not a concern at the moment,
// thus we only have 2 arenas: sbrk arena and mmap arena.
struct Arena {
  BlockPtr head;
  BlockPtr tail;
  /*
   * unsorted bin: bins[0]
   * small bins: bins[1:63] [16,24,..., 512] bytes
   * large bins: bins[64:127] sorted range of sizes, > 512 bytes
   * each bin has 2 pointers fw, bk to line up a doubly linkedlist, thus the
   * multiplication
   */
  BlockPtr bins[NUM_CHUNK_SIZES * 2];
  // If a bin is empty, the bit that the corresponds to the index of that bin is
  // set to 0. Since we have NUM_CHUNK_SIZES bins and not all architectures have
  // a type that can  support it we "dynamically" arrange an array if we need
  // more than one.
  MAP_ELMNT_TYPE binmap[NUM_ELMNTS_NECESSARY_TO_MAP];
  // range of 16-80 bytes
  BlockPtr fastbin[NUM_FAST_BINS];
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
