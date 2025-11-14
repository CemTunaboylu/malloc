#pragma once

#ifdef TESTING
  #include <assert.h>
  #define MM_ASSERT(x) assert(x)
  #define MM_UNREACHABLE() assert(!"unreachable")

  int malloc_called;
  #define MM_MALLOC_CALL() (malloc_called = 1)
  #define MM_RESET_MALLOC_CALL_MARKER() (malloc_called = 0)
  #define MM_ASSERT_MALLOC_CALLED(times) assert(malloc_called == times)

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
#endif
