#pragma once

#include <stdint.h>
#include <sys/types.h>

typedef struct SBlock *BlockPtr;

// since we are aligned, we can use the least-significant-bits to encode
// information
#define __LSB_ENCODED

struct SBlock {
  size_t __LSB_ENCODED size;
  BlockPtr next;
  BlockPtr prev;
  int free;
  // points to end of the allocated user memory to add another check
  // for reconstructing the block from given pointer
  void *end_of_alloc_mem;
};

BlockPtr reconstruct_from_user_memory(const void *);
int do_ends_hold(BlockPtr);
int fuse_next(BlockPtr);
int is_mmapped(BlockPtr);
int is_next_fusable(BlockPtr);
int is_splittable(BlockPtr, size_t);
size_t get_real_size(BlockPtr);
void deep_copy_block(BlockPtr, BlockPtr);
void fuse_bwd(BlockPtr *);
void fuse_fwd(BlockPtr);
void split_block(BlockPtr, size_t);
void *allocated_memory(BlockPtr);
void *end(BlockPtr);
