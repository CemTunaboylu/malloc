#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#ifdef __APPLE__
    #include <malloc/malloc.h>
#endif

extern void  interposing_free(void* p);
extern void* interposing_calloc(size_t len, size_t size_of);
extern void* interposing_malloc(size_t size);
extern void* interposing_realloc(void* p, size_t size);
// if we don't interpose this, objc will try to check the size of its allocated memory 
// with malloc_size which won't be intercepted and directly go to Apple's libmalloc
// e.g.: objc[...]: realized class 0x... has corrupt data pointer: malloc_size(<malloc_allocated_ptr>) = 0
extern size_t interposing_malloc_size(const void* p);

#ifdef INTERPOSE_LOG 
    extern void debug_write_str(const char *s);
    extern void debug_write_ptr(const void *p);
    extern void debug_write_u64(size_t v);

    static void log_malloc(size_t size) {
        debug_write_str("[interpose] malloc ");
        debug_write_u64(size);
        debug_write_str("\n");
    }

    static void log_malloc_size(const void* p) {
        debug_write_str("[interpose] malloc_size \n");
    }

    static void log_free(void *p) {
        debug_write_str("[interpose] free \n");
    }

static void debug_print_replacee_and_replacing(const char *str, const void* replacing, const void* replacee) {
    debug_write_str("[interpose] ");
    debug_write_str(str);
    debug_write_str(" replaced: ");
    debug_write_ptr(replacee);
    debug_write_str(" by: ");
    debug_write_ptr(replacing);
    debug_write_str("\n");
}
#else
    static void debug_print_replacee_and_replacing(const char *str, const void* replacing, const void* replacee) { (void)str; (void)replacee; (void)replacing; }
    static void log_malloc(size_t size) { (void)size; }
    static void log_free(void *p)       { (void)p;    }
    static void log_malloc_size(const void* p) { (void)p; } 
#endif

static void* my_calloc(size_t len, size_t size_of) {
    debug_print_replacee_and_replacing("calloc", (const void*) calloc, (const void*) interposing_calloc);
    return interposing_calloc(len, size_of);
}

static void my_free(void *p) {
    log_free(p);
    debug_print_replacee_and_replacing("free", (const void*) free, (const void*) interposing_free);
    interposing_free(p);
}

static void* my_malloc(size_t size) {
    log_malloc(size);
    debug_print_replacee_and_replacing("malloc", (const void*) malloc, (const void*) interposing_malloc);
    return interposing_malloc(size);
}

static size_t my_malloc_size(const void* p) {
    log_malloc_size(p);
    debug_print_replacee_and_replacing("malloc_size", (const void*) malloc_size, (const void*) interposing_malloc_size);
    return interposing_malloc_size(p);
}

static void* my_realloc(void* p, size_t size) {
    debug_print_replacee_and_replacing("realloc", (const void*) realloc, (const void*) interposing_realloc);
    return interposing_realloc(p, size);
}

__attribute__((used))
static struct {
    const void *replacement;
    const void *original;
} interposers[] __attribute__((section("__DATA,__interpose"))) = {
    { (const void *)my_malloc,  (const void *)malloc  },
    { (const void *)my_free,    (const void *)free    },
    { (const void *)my_calloc,  (const void *)calloc  },
    { (const void *)my_realloc, (const void *)realloc },
    { (const void *)my_malloc_size, (const void *)malloc_size },
};
