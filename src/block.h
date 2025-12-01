#pragma once

#include <stdint.h>
#include <sys/types.h>

typedef struct SBlock *BlockPtr;

// since we are aligned, we can use the least-significant-bits to encode
// information
#define __LSB_ENCODED
// must be smaller than alignment requirement e.g. if 8 bytes, size_in_bytes % 8
// = 0, (last 3 bits of size_in_bytes must be 0), thus __LSB_ENCODABLE must be
// smaller than 8 (1000).
#define __LSB_ENCODABLE

enum LSB_Flag {
  MMAPPED = 0x1,
  FREE = 0x2,
};

struct SBlock {
  size_t __LSB_ENCODED size;
  BlockPtr next;
  BlockPtr prev;
  // points to end of the allocated user memory to add another check
  // for reconstructing the block from given pointer
  void *end_of_alloc_mem;
};

BlockPtr reconstruct_from_user_memory(const void *);
int do_ends_hold(BlockPtr);
int fuse_next(BlockPtr);
int is_free(BlockPtr);
int is_mmapped(BlockPtr);
int is_next_fusable(BlockPtr);
int is_splittable(BlockPtr, size_t);
size_t get_true_size(BlockPtr);
void *allocated_memory(BlockPtr);
void *end(BlockPtr);
void deep_copy_block(BlockPtr, BlockPtr);
void fuse_bwd(BlockPtr *);
void fuse_fwd(BlockPtr);
void mark_as_free(BlockPtr b);
void mark_as_mmapped(BlockPtr);
void mark_as_used(BlockPtr b);
void split_block(BlockPtr, size_t);
