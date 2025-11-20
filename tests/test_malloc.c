#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>

static void pre_test_sanity(void);
static void post_test_sanity(void);

// run tests in the same process, no fork/exec per test
#define TEST_NO_EXEC 1

#define TEST_INIT  pre_test_sanity()
#define TEST_FINI  post_test_sanity()

#include "acutest.h"
#include <internal.h>
#include <malloc/malloc.h>
#include "mm_debug.h"
#include "probe.h"

extern block head;

#define CALLOC_UNDER_TESTING calloc
#define FREE_UNDER_TESTING free
#define MALLOC_UNDER_TESTING malloc
#define REALLOC_UNDER_TESTING realloc
#define CURRENT_BRK mm_sbrk(0)

static size_t base_total_blocks;
static size_t base_free_blocks;
static void  *base_brk;

#ifdef ENABLE_LOG
    extern void debug_write_ptr(const void *p);
    extern void debug_write_str(const char *s);
    extern void debug_write_u64(size_t v);
    static FILE *global_test_log;

    static void logf_nonalloc(const char *fmt, ...) {
        char buf[256];
        va_list ap;
        va_start(ap, fmt);
        int n = vsnprintf(buf, sizeof buf, fmt, ap);
        va_end(ap);
        if (n < 0) {
            return;
        }
        if ((size_t)n >= sizeof buf) {
            n = (int)sizeof(buf) - 1;
        }
        buf[n] = '\0';
        debug_write_str(buf);
    }

    #define LOG(...) do { logf_nonalloc(__VA_ARGS__); print_list_into_file(global_test_log); } while (0)
    static void free_resources(void){ fclose(global_test_log); }
#else
    #define LOG(...) do{}while(0)
    #define PRINT_BLOCK_LIST() do{}while(0)
#endif

static void pre_test_sanity(void) {
#ifdef ENABLE_LOG
    static int atexit_registered = 0;

    if (!atexit_registered) {
        atexit(free_resources);
        atexit_registered = 1;
    }
    if (!global_test_log){
        global_test_log = fopen("tests/malloc_tests.log", "a");
        TEST_CHECK_(global_test_log, "cannot open test_log_file, but tests will continue");
    }
#endif

    MM_RESET_MALLOC_CALL_MARKER();
    MM_RESET_FREE_CALL_MARKER();
    MM_RESET_FREED_MARKER();
    MM_RESET_CALLOC_CALL_MARKER();

    base_total_blocks = _mm_total_blocks();
    base_free_blocks  = _mm_free_blocks();
    base_brk          = CURRENT_BRK;

#ifdef TRACK_CALLER
    LATEST_CALLERS();
#endif
}

static void post_test_sanity(void) {
#ifdef EXPECT_RELEASE
    // No *new* permanent blocks
    TEST_CHECK_(_mm_total_blocks() == base_total_blocks, 
        "block leak: %zu -> %zu", base_total_blocks, _mm_total_blocks());
    // Free count should also match baseline
    TEST_CHECK_(_mm_free_blocks() == base_free_blocks,
        "free block mismatch: %zu -> %zu",base_free_blocks, _mm_free_blocks());
#endif

#ifdef TRACK_CALLER
    if (_mm_total_blocks() != base_total_blocks) {
        LATEST_CALLERS();
    }
#endif
}

static inline int is_aligned(void* p) {
    return ((uintptr_t)p % _Alignof(max_align_t)) == 0;
}

void check_block_header_shape(block head) {
    TEST_CHECK(is_aligned(head));
    TEST_CHECK(sizeof(head->size) == 8);
    TEST_CHECK(sizeof(head->next) == 8);
    TEST_CHECK(sizeof(head->prev) == 8);
    TEST_CHECK(sizeof(head->end_of_alloc_mem) == 8);
    TEST_CHECK(sizeof(head->free) == 4);
    size_t block_size = sizeof(struct s_block);
    TEST_CHECK(block_size == align(block_size));
}

block recons_blk_from_user_mem_ptr(void* p) {
    block head = reconstruct_from_user_memory((const void*)p);
    check_block_header_shape(head);
    TEST_CHECK_(p == (void*)allocated_memory(head),"head=%p, p=%p, alloc(head)=%p",
         (void*)head, p, (void*)allocated_memory(head));
    return head;
}

void ensure_my_malloc_is_called(void) {
    MM_ASSERT_MALLOC_CALLED(1);
    MM_RESET_MALLOC_CALL_MARKER();
}

void ensure_my_free_is_called(void) {
    MM_ASSERT_FREE_CALLED(1);
    MM_RESET_FREE_CALL_MARKER();
}

void ensure_fuse_fwd_is_called(void) {
    MM_ASSERT_FUSE_FWD_CALLED(1);
    MM_RESET_FUSE_FWD_CALL_MARKER(); 
}

void ensure_fuse_bwd_is_called(void) {
    MM_ASSERT_FUSE_BWD_CALLED(1);
    MM_RESET_FUSE_BWD_CALL_MARKER(); 
}

void ensure_freed(void) {
    MM_ASSERT_FREED(1);
    MM_RESET_FREED_MARKER();
}

void ensure_my_calloc_is_called(void) {
    MM_ASSERT_CALLOC_CALLED(1);
    MM_RESET_CALLOC_CALL_MARKER();
}

void ensure_my_realloc_called(void) {
    MM_ASSERT_REALLOC_CALLED(1);
    MM_RESET_REALLOC_MARKER();
}

void ensure_realloc_enough_size(void) {
    MM_ASSERT_REALLOC_ENOUGH_SIZE(1);
    MM_RESET_REALLOC_ENOUGH_SIZE_MARKER();
}


static void test_align(void) {

    for (size_t any = 1; any<= MAX_ALIGNMENT; any++) 
        TEST_CHECK((MAX_ALIGNMENT) == align(any));

    size_t two_max_alg =  (MAX_ALIGNMENT*2);
    for (size_t any = MAX_ALIGNMENT+1; any <= two_max_alg; any++) 
        TEST_CHECK_(two_max_alg == align(any), 
            "%lu != %lu " , any, align(any));

    size_t multiple = MAX_ALIGNMENT*4;
    TEST_CHECK(multiple == align(multiple));

    size_t large = MAX_ALIGNMENT*4-(MAX_ALIGNMENT/2);
    TEST_CHECK((MAX_ALIGNMENT*4)== align(large));
}

static void test_invalid_addr_outside_before_for_is_valid_addr(void) {
    void *p = MALLOC_UNDER_TESTING(1);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    void *invalid = (char*)head + sizeof(struct s_block)*9;
    TEST_CHECK_(is_addr_valid_heap_addr(invalid) == 0, 
        "address %p should have been invalid since it is before list head %p", invalid, (void*)head);
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();
}

static void test_invalid_addr_outside_after_for_is_valid_addr(void) {
    void *p = MALLOC_UNDER_TESTING(1);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    void *invalid = (char*)p + sizeof(struct s_block);
    TEST_CHECK(is_addr_valid_heap_addr(invalid) == 0);
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();
}

static void test_valid_addr_for_is_valid_addr(void) {
    void *p = MALLOC_UNDER_TESTING(1);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    TEST_CHECK(is_addr_valid_heap_addr(p) == 1);
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();
}

// malloc(0) is expected to return NULL pointer
static void test_malloc_zero(void) {
    void *p = MALLOC_UNDER_TESTING(0);
    ensure_my_malloc_is_called();
    TEST_CHECK(p == NULL);
    FREE_UNDER_TESTING(p);
}

static void test_header_alignment_and_size(void) {
    size_t requested_bytes = 1;
    void *p = MALLOC_UNDER_TESTING(requested_bytes);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);

    block head = recons_blk_from_user_mem_ptr(p);
    TEST_CHECK(head->size == align(requested_bytes));

    size_t size_of_block = sizeof(struct s_block);
    // 4*8 + (4 but max_align_t aligned so 8) = 40
    size_t expected_block_size = (5*8);
    TEST_CHECK_( size_of_block == expected_block_size,
        "size_of_block must be %lu, got %lu",
            expected_block_size,
            size_of_block);
    TEST_CHECK_( size_of_block == align(size_of_block),
        "size_of_block must aligned %lu != %lu",
            expected_block_size,
            align(size_of_block));
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();
}

static void test_malloc_allocated_memory_aligned(void) {
    void *p = MALLOC_UNDER_TESTING(31);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    TEST_CHECK(is_aligned(p));
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();
}

static void test_calloc_zero_fill(void) {
    size_t n = 16, sz = 8;
    unsigned char *p = (unsigned char *)CALLOC_UNDER_TESTING(n, sz);
    ensure_my_calloc_is_called();
    ensure_my_malloc_is_called();
    TEST_ASSERT(p != NULL);
    for (size_t i = 0; i < n*sz; ++i) TEST_CHECK(p[i] == 0);
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();
}

static void test_forward_fusion_2_blocks(void) {
    LOG("=== %s: start ===\n", __func__);

    size_t num_blocks = 2;
    void* ptrs[2] = {NULL};
    size_t base_bytes = 10;

    for(size_t i=0; i<num_blocks; i++) {
        void *p = MALLOC_UNDER_TESTING(base_bytes+i);
        ensure_my_malloc_is_called();
        TEST_CHECK(p != NULL);
        ptrs[i] = p;
    }

    LOG("\tpost-malloc ===\n");

    for(size_t i=0; i<num_blocks; i++) {
        void *p = ptrs[i];
        block blk = reconstruct_from_user_memory(p);
        blk->free = 1;
    }

    LOG("\tafter artificially freeing blocks ===\n");

    void *p = ptrs[0];
    block blk = reconstruct_from_user_memory(p);

    fuse_fwd(blk);
    ensure_fuse_fwd_is_called();

    LOG("\tpost-fwd-fusion ===\n");

    size_t aligned_base_bytes = align(base_bytes);
    size_t block_size = sizeof(struct s_block);
    size_t expected_size = (aligned_base_bytes*2+block_size);
    TEST_CHECK_(blk->size == expected_size,
        "size must be %lu, got %lu", expected_size, head->size);
    TEST_CHECK_(blk->next == NULL,
        "tail shoud have been merged into head, but head->next: %p", (void*)head->next);

    // should free the first block
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();

    LOG("=== %s: end ===\n", __func__);
}

static void test_backward_fusion_2_blocks(void) {
    LOG("=== %s: start ===\n", __func__);

    const size_t n = 2;
    void* ptrs[n] = {NULL};
    size_t base_bytes = 10;

    for(size_t i=0; i<n; i++) {
        void *p = MALLOC_UNDER_TESTING(base_bytes+i);
        ensure_my_malloc_is_called();
        TEST_CHECK(p != NULL);
        ptrs[i] = p;
    }

    LOG("\tpost-malloc ===\n");

    for(size_t i=0; i<n; i++) {
        void *p = ptrs[i];
        block blk = reconstruct_from_user_memory(p);
        blk->free = 1;
    }

    LOG("\t after artificially freeing blocks ===\n");

    void *p = ptrs[1];
    block blk = reconstruct_from_user_memory(p);

    fuse_bwd(&blk);
    ensure_fuse_bwd_is_called();

    LOG("\t post-bwd-fusion ===\n");

    size_t aligned_base_bytes = align_up_fundamental(base_bytes);
    size_t block_size = sizeof(struct s_block);
    size_t expected_size = (aligned_base_bytes*2+block_size);
    TEST_CHECK_(blk->size == expected_size,
        "size must be %lu, got %lu", expected_size, head->size);
    TEST_CHECK_(blk->next == NULL,
        "tail shoud have been merged into head, but head->next: %p", (void*)head->next);

    p = ptrs[0];
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();

    LOG("=== %s: end ===\n", __func__);
}

static void test_free_no_release_or_fusion(void) {
    LOG("=== %s: start ===\n", __func__);

    const size_t n = 2;
    void* ptrs[n] = {NULL};
    size_t base_bytes = 30;

    for(size_t i=0; i<n; i++) {
        void *p = MALLOC_UNDER_TESTING(base_bytes+i);
        ensure_my_malloc_is_called();
        TEST_CHECK(p != NULL);
        ptrs[i] = p;
    }

    LOG("\tpost-malloc ===\n");

    void* p = ptrs[0];

    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();

    LOG("\tpost-free ===\n");

    block blk = recons_blk_from_user_mem_ptr(p);
    TEST_CHECK(blk->free);

    for(size_t i=1; i<n; i++) {
        FREE_UNDER_TESTING(ptrs[i]);
        ensure_my_free_is_called();
        ensure_freed();
    }

    LOG("=== %s: end ===\n", __func__);
}

static void test_free_with_fusion_no_release(void) {
    LOG("=== %s: start ===\n", __func__);

    const size_t n = 5;
    void* ptrs[n] = {NULL};
    size_t base_bytes = 30;

    for(size_t i=0; i<n; i++) {
        void *p = MALLOC_UNDER_TESTING(base_bytes);
        ensure_my_malloc_is_called();
        TEST_CHECK(p != NULL);
        ptrs[i] = p;
    }

    LOG("\tpost-malloc ===\n");

    // leave the last block unfree to avoid release
    for(size_t i=0; i<n-1; i++) {
        void *p = ptrs[i];
        block blk = reconstruct_from_user_memory(p);
        blk->free = 1;
    }

    LOG("\tafter artificially freeing blocks ===\n");

    void* p = ptrs[n/2];
    block blk = reconstruct_from_user_memory(p);
    block after_fusion_head = blk->prev->prev;
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();
    ensure_fuse_fwd_is_called();
    ensure_fuse_bwd_is_called();

    LOG("\tpost-free middle ===\n");

    size_t total_bytes_after_fusion = align_up_fundamental(base_bytes)*(n-1) + sizeof(struct s_block)*(n-2);
    TEST_CHECK_(after_fusion_head->size == total_bytes_after_fusion,
        "size of after_fusion_head should add up to %lu, not %lu",
        total_bytes_after_fusion,
        after_fusion_head->size);

    void *last = ptrs[n-1];
    FREE_UNDER_TESTING(last);
    ensure_my_free_is_called();
    ensure_freed();

    LOG("=== %s: end ===\n", __func__);
}

static void test_copy_block(void) {
    LOG("=== %s: start ===\n", __func__);

    const size_t src_len = 9;
    const size_t src_size_of = 4;
    const size_t src_n = src_len * src_size_of;

    int *p = (int*)MALLOC_UNDER_TESTING(src_n);
    ensure_my_malloc_is_called();
    TEST_CHECK(p);
    for (size_t i=0;i<src_len;i++) p[i]=i;

    LOG("\tpost-malloc with size %lu and setting values for data ===\n", src_n);

    const size_t to_copy_len = 9;
    const size_t to_copy_size_of = 4;

    int *q = (int*)CALLOC_UNDER_TESTING(to_copy_len, to_copy_size_of);
    ensure_my_calloc_is_called();
    TEST_ASSERT(q);

    block p_blk = reconstruct_from_user_memory(p);
    block q_blk = reconstruct_from_user_memory(q);

    deep_copy_block(p_blk, q_blk);
    LOG("\tafter deep copy block ===\n");

    size_t min = src_len > to_copy_len ? to_copy_len : src_len;
    for (size_t i=0;i<min;i++) TEST_CHECK_(p[i] == q[i], "%d != %d", p[i], q[i]);

    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();

    FREE_UNDER_TESTING(q);
    ensure_my_free_is_called();
    ensure_freed();
    LOG("=== %s: end ===\n", __func__);
}

static void test_realloc_grow_and_shrink(void) {
    LOG("=== %s: start ===\n", __func__);

    const size_t n = 10;

    char *p = (char*)MALLOC_UNDER_TESTING(n);
    ensure_my_malloc_is_called();
    TEST_CHECK(p);
    for (int i=0;i<(int)n;i++) p[i]=(char)i;

    LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

    const size_t re_grow_n = 100;

    char *q = (char*)REALLOC_UNDER_TESTING(p, re_grow_n);
    ensure_my_realloc_called();
    ensure_my_malloc_is_called();
    ensure_my_free_is_called();
    ensure_freed();
    TEST_ASSERT(q);
    for (int i=0;i<(int)n;i++) TEST_CHECK(q[i]==(char)i);

    LOG("\tafter growing realloc with %lu ===\n", re_grow_n);

    const size_t re_shrink_n = 5;
    char *r = (char*)REALLOC_UNDER_TESTING(q, re_shrink_n);
    ensure_my_realloc_called();
    ensure_realloc_enough_size();
    TEST_ASSERT(r);
    for (int i=0;i<(int)re_shrink_n;i++) TEST_CHECK(r[i]==(char)i);

    LOG("\tafter shrinking realloc with %lu ===\n", re_shrink_n);

    FREE_UNDER_TESTING(r);
    ensure_my_free_is_called();
    ensure_freed();
    LOG("=== %s: end ===\n", __func__);
}

TEST_LIST = {
    { "test_align",                       test_align },
    { "test_invalid_addr_outside_before_for_is_valid_addr",                       test_invalid_addr_outside_before_for_is_valid_addr },
    { "test_invalid_addr_outside_after_for_is_valid_addr",                       test_invalid_addr_outside_after_for_is_valid_addr },
    { "test_valid_addr_for_is_valid_addr",                       test_valid_addr_for_is_valid_addr },
    { "test_malloc_zero",                       test_malloc_zero },
    { "test_header_alignment_and_size",                  test_header_alignment_and_size },
    { "test_forward_fusion_2_blocks",              test_forward_fusion_2_blocks },
    { "test_backward_fusion_2_blocks",              test_backward_fusion_2_blocks },
    { "test_malloc_allocated_memory_aligned",   test_malloc_allocated_memory_aligned },
    { "test_calloc_zero_fill",              test_calloc_zero_fill },
    { "test_free_no_release_or_fusion",              test_free_no_release_or_fusion },
    { "test_free_with_fusion_no_release",              test_free_with_fusion_no_release },
    { "test_copy_block",  test_copy_block },
    { "realloc_grow_shrink",  test_realloc_grow_and_shrink },
    { NULL, NULL }
};
