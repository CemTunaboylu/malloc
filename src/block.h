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
  PREV_FREE = 0x4,
};

/* Layout of Block headers
 *
 * |  previous' size |      prev. (contiguous) block's size if free right on top
 * -- block header --
 * |  flagged size  |       each bit encodes: <prev_free><is_free><mmapped>
 * |  next block*   |       (within the bin its in) when free
 * |  prev block*   |       (within the bin its in) when free
 * |  true size     |       puts (unflagged) size @footer when freed
 */

struct SBlock {
  size_t __LSB_ENCODED size;
  BlockPtr next;
  BlockPtr prev;
};

BlockPtr prev(BlockPtr);
BlockPtr reconstruct_from_user_memory(const void *);
int fuse_next(BlockPtr);
int is_at_brk(BlockPtr);
int is_free(BlockPtr);
int is_mmapped(BlockPtr);
int is_next_fusable(BlockPtr);
int is_prev_free(BlockPtr);
int is_splittable(BlockPtr, size_t);
size_t get_flags(BlockPtr);
size_t get_true_size(BlockPtr);
size_t prev_size(BlockPtr);
void *allocated_memory(BlockPtr);
void *next(BlockPtr);
void deep_copy_user_memory(BlockPtr src, BlockPtr to);
void fuse_bwd(BlockPtr *);
void fuse_fwd(BlockPtr);
void mark_as_free(BlockPtr);
void mark_as_mmapped(BlockPtr);
void mark_as_used(BlockPtr);
void propagate_free_to_next(BlockPtr);
void propagate_used_to_next(BlockPtr);
void remove_from_linkedlist(BlockPtr);
void split_block(BlockPtr, size_t);
void switch_places_in_list(BlockPtr rem, BlockPtr put);
void transfer_flags(BlockPtr from, BlockPtr to);
