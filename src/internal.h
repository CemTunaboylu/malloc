#pragma once

#include <arena.h>
#include <block.h>
#include <stdint.h>
#include <sys/types.h>

extern void debug_write_str(const char *);
extern void debug_write_ptr(const void *);
extern void print_list_into_stderr(void);

#ifdef TESTING
// non-allocating writes
extern void debug_write_ptr_fd(int, const void *);
extern void debug_write_str_fd(int, const char *);
extern void debug_write_u64(size_t);
extern void debug_write_u64_fd(int, size_t);
extern void logf_nonalloc(const char *, ...);
extern void print_list_into_test_file(void);

// testing probes
extern BlockPtr _mm_block_header(void);
extern size_t _mm_bytes_obtained_from_os(void);
extern size_t _mm_free_blocks(void);     // current free blocks
extern size_t _mm_non_free_blocks(void); // current non-free blocks
extern size_t _mm_total_blocks(void);    // current free blocks
extern void _mm_tear_down_allocator(void);

// test probes use a_head, thus we need to make it external
extern struct Arena a_head;
extern struct MMapArena ma_head;

BlockPtr search_in_unsorted_consolidating(const size_t);
void append(BlockPtr sentinel, BlockPtr new_next);
void consolidate_fastbins(void);
void correct_tail_if_eaten(const BlockPtr);
void fuse_bwd(BlockPtr *);
void fuse_fwd(BlockPtr);
void insert_in_fastbin(BlockPtr);
void release(BlockPtr);
#endif

#define CURRENT_BRK mm_sbrk(0)

extern const size_t MAX_ALIGNMENT;
extern size_t NUM_BITS_SPARED_FROM_ALIGNMENT;

#define MIN_SPLIT_REMAINING_PAYLOAD (MAX_ALIGNMENT)
#define IS_FAILED_BY_PTR(p) ((p) == (void *)-1)

size_t align_up_fundamental(const size_t);
static inline size_t align(const size_t s) { return align_up_fundamental(s); }

/*
The allocator calls these wrappers. In tests, they can be
replaced with deterministic stubs (or counters) so that
we can assert “one mmap for big alloc,” “no sbrk for free,” etc.
*/

// used for small allocations < 128 KiB
void *mm_sbrk(intptr_t inc);
int mm_brk(void *p);
// if more than one page, use this
void *mm_mmap(size_t n);
void *mm_mremap(void *op, size_t o, size_t n);
int mm_munmap(void *p, size_t n);
