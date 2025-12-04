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

// Note: thread-safety is not a concern at the moment,
// thus we only have 2 arenas: sbrk arena and mmap arena.
struct Arena {
  BlockPtr head;
  BlockPtr tail;
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
