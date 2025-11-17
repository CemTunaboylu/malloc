#pragma once

#ifdef TESTING
  #include <assert.h>
  #define MM_ASSERT(x) assert(x)
  #define MM_UNREACHABLE() assert(!"unreachable")

  #define MM_ASSERT_EQ_INT(label, actual, expected)           \
    do {                                                      \
      if ((actual) != (expected)) {                           \
        fprintf(stderr,                                       \
                "[MM_ASSERT] %s: actual=%d expected=%d\n",    \
                (label), (int)(actual), (int)(expected));     \
        assert((actual) == (expected));                       \
      }                                                       \
    } while (0)

  extern int calloc_called;
  #define MM_CALLOC_CALL() (calloc_called += 1)
  #define MM_RESET_CALLOC_CALL_MARKER() (calloc_called = 0)
  #define MM_ASSERT_CALLOC_CALLED(times) \
    MM_ASSERT_EQ_INT("calloc_called", calloc_called, (times))

  extern int free_called;
  #define MM_FREE_CALL() (free_called += 1)
  #define MM_RESET_FREE_CALL_MARKER() (free_called = 0)
  #define MM_ASSERT_FREE_CALLED(times) \
    MM_ASSERT_EQ_INT("free_called", free_called, (times))

  extern int freed;
  #define MM_FREED() (freed += 1)
  #define MM_RESET_FREED_MARKER() (freed = 0)
  #define MM_ASSERT_FREED(times) \
    MM_ASSERT_EQ_INT("freed", freed, (times))

  extern int malloc_called;
  #define MM_MALLOC_CALL() (malloc_called += 1)
  #define MM_RESET_MALLOC_CALL_MARKER() (malloc_called = 0)
  #define MM_ASSERT_MALLOC_CALLED(times) \
    MM_ASSERT_EQ_INT("malloc_called", malloc_called, (times))

  extern int realloc_called;
  #define MM_REALLOC_CALL() (realloc_called += 1)
  #define MM_RESET_REALLOC_MARKER() (realloc_called = 0)
  #define MM_ASSERT_REALLOC_CALLED(times) \
    MM_ASSERT_EQ_INT("realloc_called", realloc_called, (times))

  extern int realloc_enough_size;
  #define MM_REALLOC_ENOUGH_SIZE() (realloc_enough_size += 1)
  #define MM_RESET_REALLOC_ENOUGH_SIZE_MARKER() (realloc_enough_size = 0)
  #define MM_ASSERT_REALLOC_ENOUGH_SIZE(times) \
    MM_ASSERT_EQ_INT("realloc_enough_size", realloc_enough_size, (times))

  extern int fuse_fwd_called;
  #define MM_FUSE_FWD_CALL() (fuse_fwd_called += 1)
  #define MM_RESET_FUSE_FWD_CALL_MARKER() (fuse_fwd_called = 0)
  #define MM_ASSERT_FUSE_FWD_CALLED(times) \
    MM_ASSERT_EQ_INT("fuse_fwd_called", fuse_fwd_called, (times))

  extern int fuse_bwd_called;
  #define MM_FUSE_BWD_CALL() (fuse_bwd_called += 1)
  #define MM_RESET_FUSE_BWD_CALL_MARKER() (fuse_bwd_called = 0)
  #define MM_ASSERT_FUSE_BWD_CALLED(times) \
    MM_ASSERT_EQ_INT("fuse_bwd_called", fuse_bwd_called, (times))

#else
  #if defined(__GNUC__)
    #define MM_ASSERT(x) ((void)0)
    #define MM_UNREACHABLE() __builtin_unreachable()
  #else
    #define MM_ASSERT(x) ((void)0)
    #define MM_UNREACHABLE() ((void)0)
  #endif

  #define MM_CALLOC_CALL() ((void)0)
  #define MM_RESET_CALLOC_CALL_MARKER() ((void)0)
  #define MM_ASSERT_CALLOC_CALLED() ((void)0)

  #define MM_FREED() ((void)0)
  #define MM_RESET_FREED_MARKER() ((void)0)
  #define MM_ASSERT_FREED(times) ((void)0)

  #define MM_FREE_CALL() ((void)0)
  #define MM_RESET_FREE_CALL_MARKER() ((void)0)
  #define MM_ASSERT_FREE_CALLED(times)  ((void)0)

  #define MM_MALLOC_CALL() ((void)0)
  #define MM_RESET_MALLOC_CALL_MARKER() ((void)0)
  #define MM_ASSERT_MALLOC_CALLED() ((void)0)

  #define MM_REALLOC_CALL() ((void)0)
  #define MM_RESET_REALLOC_MARKER() ((void)0)
  #define MM_ASSERT_REALLOC_CALLED(times) ((void)0)

  #define MM_REALLOC_ENOUGH_SIZE() ((void)0)
  #define MM_RESET_REALLOC_ENOUGH_SIZE_MARKER() ((void)0)
  #define MM_ASSERT_REALLOC_ENOUGH_SIZE(times) ((void)0)

  #define MM_FUSE_FWD_CALL() ((void)0)
  #define MM_RESET_FUSE_FWD_CALL_MARKER() ((void)0) 
  #define MM_ASSERT_FUSE_FWD_CALLED(times) ((void)0) 

  #define MM_FUSE_BWD_CALL() ((void)0)
  #define MM_RESET_FUSE_BWD_CALL_MARKER() ((void)0)
  #define MM_ASSERT_FUSE_BWD_CALLED(times) ((void)0)

#endif
