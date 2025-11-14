#pragma once

#ifdef TESTING
  #include <assert.h>
  #define MM_ASSERT(x) assert(x)
  #define MM_UNREACHABLE() assert(!"unreachable")

  int malloc_called;
  #define MM_MALLOC_CALL() (malloc_called = 1)
  #define MM_RESET_MALLOC_CALL_MARKER() (malloc_called = 0)
  #define MM_ASSERT_MALLOC_CALLED(times) assert(malloc_called == times)

  int free_called;
  #define MM_FREE_CALL() (free_called = 1)
  #define MM_RESET_FREE_CALL_MARKER() (free_called = 0)
  #define MM_ASSERT_FREE_CALLED(times) assert(free_called == times)

  int calloc_called;
  #define MM_CALLOC_CALL() (calloc_called = 1)
  #define MM_RESET_CALLOC_CALL_MARKER() (calloc_called = 0)
  #define MM_ASSERT_CALLOC_CALLED(times) assert(calloc_called == times)

#else
  #if defined(__GNUC__)
    #define MM_ASSERT(x) ((void)0)
    #define MM_UNREACHABLE() __builtin_unreachable()
  #else
    #define MM_ASSERT(x) ((void)0)
    #define MM_UNREACHABLE() ((void)0)
  #endif

  #define MM_MALLOC_CALL() ((void)0)
  #define MM_RESET_MALLOC_CALL_MARKER() ((void)0)
  #define MM_ASSERT_MALLOC_CALLED() ((void)0)

  #define MM_FREE_CALL() ((void)0)
  #define MM_RESET_FREE_CALL_MARKER() ((void)0)
  #define MM_ASSERT_FREE_CALLED(times)  ((void)0)

  #define MM_CALLOC_CALL() ((void)0)
  #define MM_RESET_CALLOC_CALL_MARKER() ((void)0)
  #define MM_ASSERT_CALLOC_CALLED() ((void)0)

#endif
