#pragma once

#include <arena.h>
#include <block.h>
#include <stdint.h>
#include <sys/types.h>

extern void debug_write_str(const char *);
extern void debug_write_ptr(const void *);

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
#endif

extern const size_t MAX_ALIGNMENT;
extern size_t NUM_BITS_SPARED_FROM_ALIGNMENT;

#define MIN_SPLIT_REMAINING_PAYLOAD (MAX_ALIGNMENT)
#define IS_FAILED_BY_PTR(p) ((p) == (void *)-1)

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
