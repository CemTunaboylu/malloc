#pragma once

#define CALLOC_CALLED 0
#define FREE_CALLED 1
#define FREED 2
#define MALLOC_CALLED 3
#define REALLOC_CALLED 4
#define REALLOC_ENOUGH_SIZE 5
#define RELEASED 6
#define FUSE_FWD_CALLED 7
#define FUSE_BWD_CALLED 8
#define MUNMAPPED 9
#define MUNMAPPED_EXCESS 10
#define MMAPPED_BIGGER 11
#define BY_MMAPPING 12
#define BY_SBRKING 13
#define SBRK_TO_MMAP 14
#define MMAP_TO_SBRK 15
#define NEXT_PREV_FREED 16
#define NEXT_PREV_USED 17
#define PUT_IN_UNSORTED_BIN 18
#define FASTBINNED 19
#define PUT_IN_FASTBIN 20
#define DOUBLE_FREE 21
#define CONSOLIDATED 22
#define SMALL_BINNED 23
#define LARGE_BINNED 24
#define UNSORTED_BINNED 25
#define END_MARKERS 26

#ifdef TESTING
#include <internal.h>
#include <unistd.h>

static inline void mm_fatal(const char *msg) {
  debug_write_str(msg);
  debug_write_str("\n");
  _exit(1); // or __builtin_trap();
}

#define MM_ASSERT(x)                                                           \
  do {                                                                         \
    if (!(x))                                                                  \
      mm_fatal("MM_ASSERT failed: " #x);                                       \
  } while (0)
#define MM_UNREACHABLE() assert(!"unreachable")

#ifdef ENABLE_LOG
#define MM_ASSERT_LOG(label, actual, expected)                                 \
  do {                                                                         \
    if ((actual) != (expected)) {                                              \
      debug_write_str("[MM_ASSERT] ");                                         \
      debug_write_str(label);                                                  \
      debug_write_str(": actual=");                                            \
      debug_write_u64(actual);                                                 \
      debug_write_str(", expected=");                                          \
      debug_write_u64(expected);                                               \
      debug_write_str("\n");                                                   \
    }                                                                          \
  } while (0);
#else
#define MM_ASSERT_LOG(label, actual, expected)                                 \
  {                                                                            \
    (void)label;                                                               \
    (void)actual;                                                              \
    (void)expected;                                                            \
  }
#endif

#define MM_ASSERT_EQ_INT(label, actual, expected)                              \
  {                                                                            \
    do {                                                                       \
      MM_ASSERT_LOG((label), (actual), (expected))                             \
      MM_ASSERT((actual) == (expected));                                       \
    } while (0);                                                               \
  }

#define NUM_MARKERS END_MARKERS
extern size_t markers[NUM_MARKERS];

#define MM_MARK(ix) markers[ix] += 1
#define MM_RESET_MARKER(ix) markers[ix] = 0
#define MM_ASSERT_MARKER(ix, times)                                            \
  {                                                                            \
    MM_ASSERT_EQ_INT("", markers[ix], (times));                                \
    MM_RESET_MARKER(ix);                                                       \
  }

#else
#if defined(__GNUC__)
#define MM_ASSERT(x) ((void)0)
#define MM_UNREACHABLE() __builtin_unreachable()
#else
#define MM_ASSERT(x) ((void)0)
#define MM_UNREACHABLE() ((void)0)
#endif

#define MM_CALL(ix) ((void)ix)
#define MM_RESET_MARKER(ix) ((void)ix)
#define MM_ASSERT_CALLED(name, ix, times)                                      \
  {                                                                            \
    (void)name;                                                                \
    ((void)ix);                                                                \
    ((void)times);                                                             \
  }

#endif
