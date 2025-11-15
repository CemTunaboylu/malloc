#pragma once

#ifdef TESTING
  #include <assert.h>
  #define MM_ASSERT(x) assert(x)
  #define MM_UNREACHABLE() assert(!"unreachable")

  int calloc_called;
  #define MM_CALLOC_CALL() (calloc_called += 1)
  #define MM_RESET_CALLOC_CALL_MARKER() (calloc_called = 0)
  #define MM_ASSERT_CALLOC_CALLED(times) assert(calloc_called == times)

  int free_called;
  #define MM_FREE_CALL() (free_called += 1)
  #define MM_RESET_FREE_CALL_MARKER() (free_called = 0)
  #define MM_ASSERT_FREE_CALLED(times) assert(free_called == times)

  int freed;
  #define MM_FREED() (freed += 1)
  #define MM_RESET_FREED_MARKER() (freed = 0)
  #define MM_ASSERT_FREED(times) assert(freed == times)

  int malloc_called;
  #define MM_MALLOC_CALL() (malloc_called += 1)
  #define MM_RESET_MALLOC_CALL_MARKER() (malloc_called = 0)
  #define MM_ASSERT_MALLOC_CALLED(times) assert(malloc_called == times)

  int fuse_fwd_called;
  #define MM_FUSE_FWD_CALL() (fuse_fwd_called += 1)
  #define MM_RESET_FUSE_FWD_CALL_MARKER() (fuse_fwd_called = 0)
  #define MM_ASSERT_FUSE_FWD_CALLED(times) assert(fuse_fwd_called == times)

  int fuse_bwd_called;
  #define MM_FUSE_BWD_CALL() (fuse_bwd_called += 1)
  #define MM_RESET_FUSE_BWD_CALL_MARKER() (fuse_bwd_called = 0)
  #define MM_ASSERT_FUSE_BWD_CALLED(times) assert(fuse_bwd_called == times)

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

  #define MM_FUSE_FWD_CALL() ((void)0)
  #define MM_RESET_FUSE_FWD_CALL_MARKER() ((void)0) 
  #define MM_ASSERT_FUSE_FWD_CALLED(times) ((void)0) 

  #define MM_FUSE_BWD_CALL() ((void)0)
  #define MM_RESET_FUSE_BWD_CALL_MARKER() ((void)0)
  #define MM_ASSERT_FUSE_BWD_CALLED(times) ((void)0)

#endif
