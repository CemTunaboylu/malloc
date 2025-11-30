#pragma once

#include <block.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct Arena *ArenaPtr;

struct Arena {
  BlockPtr top;
  ArenaPtr next;
  BlockPtr head;
  BlockPtr tail;
  size_t total_bytes_allocated;
  size_t total_free_bytes;
} Arena;

extern void debug_write_str(const char *);
extern void debug_write_ptr(const void *);

#ifdef TESTING
int is_addr_valid_heap_addr(ArenaPtr, void *);
void allocated_bytes_update(ArenaPtr, int);

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
#endif

// test probes use head, thus we need to make it external
extern ArenaPtr a_head;
extern const size_t MAX_ALIGNMENT;

#define MIN_SPLIT_REMAINING_PAYLOAD (MAX_ALIGNMENT)

size_t align_up_fundamental(size_t);
static inline size_t align(size_t s) { return align_up_fundamental(s); }

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
int mm_munmap(void *p, size_t n);
