#pragma once

void* malloc(size_t size);
void* calloc(size_t len, size_t size_of);

#ifdef TESTING
    #include <assert.h>
    #define MM_ASSERT(x) assert(x)
    #define MM_UNREACHABLE() assert(!"unreachable")
#else
    #if defined(__GNUC__)
        #define MM_ASSERT(x) ((void)0)
        #define MM_UNREACHABLE() __builtin_unreachable()
    #else
        #define MM_ASSERT(x) ((void)0)
        #define MM_UNREACHABLE() ((void)0)
    #endif
#endif