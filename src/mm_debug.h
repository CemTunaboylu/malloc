#pragma once

#ifdef TESTING
  #include <unistd.h>

  extern void debug_write_str(const char *s);
  extern void debug_write_ptr(const void *p);
  extern void debug_write_u64(size_t v);

  static inline void mm_fatal(const char *msg) {
      debug_write_str(msg);
      debug_write_str("\n");
      _exit(1);   // or __builtin_trap();
  }

  #define MM_ASSERT(x) \
    do { if (!(x)) mm_fatal("MM_ASSERT failed: " #x); } while (0)
  #define MM_UNREACHABLE() assert(!"unreachable")

  #ifdef ENABLE_LOG
    #define MM_ASSERT_LOG(label, actual, expected)           \
      do {                                                      \
        if ((actual) != (expected)) {                           \
            debug_write_str("[MM_ASSERT] ");                                \
            debug_write_str(label);                                         \
            debug_write_str(": actual=");                                   \
            debug_write_u64(actual);                                        \
            debug_write_str(", expected=");                                 \
            debug_write_u64(expected);                                      \
            debug_write_str("\n");                                          \
        }                                                       \
      } while (0);
  #else
    #define MM_ASSERT_LOG(label, actual, expected) ((void)label; (void)actual, (void)expected)
  #endif

    #if defined(TRACK_RET_ADDR) 
      #include <internal.h>
      #ifdef __GNUC__
        #define MM_RET_ADDR() __builtin_extract_return_addr(__builtin_return_address(0))
        // #define MM_RET_ADDR() __builtin_return_address(0)
      #else
        #define MM_RET_ADDR() NULL
      #endif

      typedef struct {
          block blk;
          void *ret_addr;
      } mm_callsite_entry;

      extern mm_callsite_entry mm_callsites[1024];
      extern size_t mm_callsite_count;

      #define LATEST_CALLERS()                                              {\
        do {                                                                 \
        for (size_t i = 0; i < mm_callsite_count ; i++)                      \
        {                                                                    \
          mm_callsite_entry cse = mm_callsites[i];                           \
          if (!cse.blk) continue;                                            \
          debug_write_str("[MM_RET_ADDR] (");                                \
          debug_write_u64(i);                                                \
          debug_write_str(") size=");                                        \
          debug_write_u64(cse.blk->size);                                    \
          debug_write_str(" ret_addr=");                                     \
          debug_write_ptr(cse.ret_addr);                                     \
          debug_write_str(" free:");                                         \
          debug_write_u64(cse.blk->free);                                    \
          debug_write_str("\n---------\n");                                  \
        }                                                                    \
      }while(0);                                                             \
      }

      #define MM_ASSERT_EQ_INT_W_CALLERS(label, actual, expected)          {\
        do {                                                                \
            MM_ASSERT_LOG((label), (actual), (expected))                   \
            LATEST_CALLERS()                                                \
            MM_ASSERT((actual) == (expected));                                 \
        } while (0);                                                        \
      }
    #endif

  #define MM_ASSERT_EQ_INT(label, actual, expected)          {\
    do {                                                                \
        MM_ASSERT_LOG((label), (actual), (expected))                   \
        MM_ASSERT((actual) == (expected));                                 \
    } while (0);                                                        \
  }

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

  #ifdef TRACK_RET_ADDR
    #define MM_ASSERT_MALLOC_CALLED(times) \
      MM_ASSERT_EQ_INT_W_CALLERS("malloc_called_with_caller", malloc_called, (times))
  #else 
    #define MM_ASSERT_MALLOC_CALLED(times) \
      MM_ASSERT_EQ_INT("malloc_called", malloc_called, (times))
  #endif

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
  #define MM_ASSERT_CALLOC_CALLED(times) ((void)times)

  #define MM_FREED() ((void)0)
  #define MM_RESET_FREED_MARKER() ((void)0)
  #define MM_ASSERT_FREED(times) ((void)times)

  #define MM_FREE_CALL() ((void)0)
  #define MM_RESET_FREE_CALL_MARKER() ((void)0)
  #define MM_ASSERT_FREE_CALLED(times)  ((void)times)

  #define MM_MALLOC_CALL() ((void)0)
  #define MM_RESET_MALLOC_CALL_MARKER() ((void)0)
  #define MM_ASSERT_MALLOC_CALLED(times) ((void)times)

  #define MM_REALLOC_CALL() ((void)0)
  #define MM_RESET_REALLOC_MARKER() ((void)0)
  #define MM_ASSERT_REALLOC_CALLED(times) ((void)times)

  #define MM_REALLOC_ENOUGH_SIZE() ((void)0)
  #define MM_RESET_REALLOC_ENOUGH_SIZE_MARKER() ((void)0)
  #define MM_ASSERT_REALLOC_ENOUGH_SIZE(times) ((void)times)

  #define MM_FUSE_FWD_CALL() ((void)0)
  #define MM_RESET_FUSE_FWD_CALL_MARKER() ((void)0) 
  #define MM_ASSERT_FUSE_FWD_CALLED(times) ((void)times) 

  #define MM_FUSE_BWD_CALL() ((void)0)
  #define MM_RESET_FUSE_BWD_CALL_MARKER() ((void)0)
  #define MM_ASSERT_FUSE_BWD_CALLED(times) ((void)times)

#endif
