#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

static void pre_test_sanity(void);
static void post_test_sanity(void);

// Acutest will run this before every test
#define TEST_INIT  pre_test_sanity()
// Acutest will run this after every test
#define TEST_FINI  post_test_sanity()


#include "acutest.h"
#include <internal.h>
#include "mm_debug.h"
#include "probe.h"

extern block head;

#define MALLOC_UNDER_TESTING mm_malloc
#define CALLOC_UNDER_TESTING mm_calloc
#define FREE_UNDER_TESTING mm_free

static void pre_test_sanity(void) {
    // Example: ensure debug markers are reset
    MM_RESET_MALLOC_CALL_MARKER();
    MM_RESET_FREE_CALL_MARKER();
    MM_RESET_FREED_MARKER();
    MM_RESET_CALLOC_CALL_MARKER();

    assert(head == NULL);
}

static void post_test_sanity(void) {
    _mm_tear_down_allocator();
    assert(head == NULL);
}

FILE* open_file_for_test(const char* test_name) {
    FILE *fp = fopen(test_name, "w");
    return fp;
}

static inline int is_aligned(void* p) {
    return ((uintptr_t)p % _Alignof(max_align_t)) == 0;
}

block recons_blk_from_user_mem_ptr(void* p) {
    block head = reconstruct_from_user_memory(p);
    TEST_CHECK(is_aligned(head));
    TEST_CHECK(p == (void*)allocated_memory(head));
    TEST_MSG("head=%p, p=%p, alloc(head)=%p",
         (void*)head, p, (void*)allocated_memory(head));
    TEST_CHECK(sizeof(head->size) == 8);
    TEST_CHECK(sizeof(head->next) == 8);
    TEST_CHECK(sizeof(head->prev) == 8);
    TEST_CHECK(sizeof(head->free) == 4);
    TEST_CHECK(sizeof(head->user_memory) == 8);
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

static void test_align_up(void) {
    size_t one_short = MAX_ALIGNMENT - 1;
    TEST_CHECK((one_short+1) == align_up_fundamental(one_short));

    size_t one_long = MAX_ALIGNMENT + 1;
    TEST_CHECK((one_long+(MAX_ALIGNMENT-1)) == align_up_fundamental(one_long));
    TEST_MSG("%lu != %lu " ,one_long+(MAX_ALIGNMENT-1), align_up_fundamental(one_long));

    size_t exact = MAX_ALIGNMENT;
    TEST_CHECK(exact == align_up_fundamental(exact));

    size_t multiple = MAX_ALIGNMENT*4;
    TEST_CHECK(multiple == align_up_fundamental(multiple));
}


static void test_invalid_addr_outside_before_for_is_valid_addr(void) {
    void *p = MALLOC_UNDER_TESTING(1);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    void *invalid = (char*)head + sizeof(struct s_block);
    TEST_CHECK(is_addr_valid_heap_addr(invalid) == 0);
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
}

// malloc(0) is expected to return NULL pointer
static void test_malloc_zero(void) {
    void *p = MALLOC_UNDER_TESTING(0);
    ensure_my_malloc_is_called();
    TEST_CHECK(p == NULL);
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
}

static void test_header_alignment_and_size(void) {
    size_t requested_bytes = 1;
    void *p = MALLOC_UNDER_TESTING(requested_bytes);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);

    block head = recons_blk_from_user_mem_ptr(p);
    TEST_CHECK(head->size == align_up_fundamental(requested_bytes));

    size_t size_of_block = sizeof(struct s_block);
    // 4*8 + (4 but max_align_t aligned so 8) = 40
    size_t expected_block_size = 40;
    TEST_CHECK( size_of_block == expected_block_size);
    TEST_MSG("size_of_block must be %lu, got %lu",
         expected_block_size,
         size_of_block);
    TEST_CHECK( size_of_block == align_up_fundamental(size_of_block));
    TEST_MSG("size_of_block must aligned %lu != %lu",
         expected_block_size,
         align_up_fundamental(size_of_block));
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
}

static void test_malloc_allocated_memory_aligned(void) {
    void *p = MALLOC_UNDER_TESTING(31);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    TEST_CHECK(is_aligned(p));
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
}

static void test_calloc_zero_fill(void) {
    size_t n = 16, sz = 8;
    unsigned char *p = (unsigned char *)CALLOC_UNDER_TESTING(n, sz);
    ensure_my_calloc_is_called();
    TEST_ASSERT(p != NULL);
    for (size_t i = 0; i < n*sz; ++i) TEST_CHECK(p[i] == 0);
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
}

static void test_forward_fusion_2_blocks(void) {
    FILE* test_file = open_file_for_test(__func__);
    print_list_into_file(test_file);

    size_t num_blocks = 2;
    void* ptrs[2] = {NULL};
    size_t base_bytes = 10;

    for(size_t i=0; i<num_blocks; i++) {
        void *p = MALLOC_UNDER_TESTING(base_bytes+i);
        ensure_my_malloc_is_called();
        TEST_CHECK(p != NULL);
        ptrs[i] = p;
    }

    fprintf(test_file, "after malloc\n");
    print_list_into_file(test_file);

    for(size_t i=0; i<num_blocks; i++) {
        void *p = ptrs[i];
        block blk = reconstruct_from_user_memory(p);
        blk->free = 1;
    }

    fprintf(test_file, "after artificially freeing blocks\n");
    print_list_into_file(test_file);

    void *p = ptrs[0];
    block blk = reconstruct_from_user_memory(p);

    fuse_fwd(blk);
    ensure_fuse_fwd_is_called();

    fprintf(test_file, "after forward fusion\n");
    print_list_into_file(test_file);

    TEST_CHECK(head->free);
    size_t aligned_base_bytes = align_up_fundamental(base_bytes);
    size_t block_size = sizeof(struct s_block);
    size_t expected_size = (aligned_base_bytes*2+block_size);
    TEST_CHECK(head->size == expected_size);
    TEST_MSG("size must be %lu, got %lu", expected_size, head->size);
    TEST_CHECK(head->next == NULL);
    TEST_MSG("tail shoud have been merged into head, but head->next: %p", (void*)head->next);
    TEST_CHECK(head->prev == NULL);
    TEST_MSG("head should have prev null but head->prev: %p", (void*)head->prev);

    // should free the first block
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();

    fprintf(test_file, "after free\n");

    print_list_into_file(test_file);
    TEST_CHECK(head == NULL);

    fclose(test_file);
}

static void test_backward_fusion_2_blocks(void) {
    FILE* test_file = open_file_for_test(__func__);
    print_list_into_file(test_file);

    size_t num_blocks = 2;
    void* ptrs[2] = {NULL};
    size_t base_bytes = 10;

    for(size_t i=0; i<num_blocks; i++) {
        void *p = MALLOC_UNDER_TESTING(base_bytes+i);
        ensure_my_malloc_is_called();
        TEST_CHECK(p != NULL);
        ptrs[i] = p;
    }

    fprintf(test_file, "after malloc\n");
    print_list_into_file(test_file);

    for(size_t i=0; i<num_blocks; i++) {
        void *p = ptrs[i];
        block blk = reconstruct_from_user_memory(p);
        blk->free = 1;
    }

    fprintf(test_file, "after artificially freeing blocks\n");
    print_list_into_file(test_file);

    void *p = ptrs[1];
    block blk = reconstruct_from_user_memory(p);

    fuse_bwd(&blk);
    ensure_fuse_bwd_is_called();

    fprintf(test_file, "after forward fusion\n");
    print_list_into_file(test_file);

    TEST_CHECK(head->free);
    size_t aligned_base_bytes = align_up_fundamental(base_bytes);
    size_t block_size = sizeof(struct s_block);
    size_t expected_size = (aligned_base_bytes*2+block_size);
    TEST_CHECK(head->size == expected_size);
    TEST_MSG("size must be %lu, got %lu", expected_size, head->size);
    TEST_CHECK(head->next == NULL);
    TEST_MSG("tail shoud have been merged into head, but head->next: %p", (void*)head->next);
    TEST_CHECK(head->prev == NULL);
    TEST_MSG("head should have prev null but head->prev: %p", (void*)head->prev);

    // should free the first block
    p = ptrs[0];
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();

    fprintf(test_file, "after free\n");

    print_list_into_file(test_file);
    TEST_CHECK(head == NULL);

    fclose(test_file);
}

static void test_free_no_release_or_fusion(void) {
    FILE* test_file = open_file_for_test(__func__);
    print_list_into_file(test_file);
    size_t requested_bytes = 1;
    void *p = MALLOC_UNDER_TESTING(requested_bytes);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);

    fprintf(test_file, "after malloc\n");
    size_t requested_bytes_2 = 24;
    void *l = MALLOC_UNDER_TESTING(requested_bytes_2);
    ensure_my_malloc_is_called();
    TEST_CHECK(l != NULL);

    print_list_into_file(test_file);

    // should free the first block
    FREE_UNDER_TESTING(p);
    ensure_my_free_is_called();
    ensure_freed();

    fprintf(test_file, "after free\n");

    print_list_into_file(test_file);

    // ensure we set the block free 
    block head = recons_blk_from_user_mem_ptr(p);
    TEST_CHECK(head->free);
    fclose(test_file);

    FREE_UNDER_TESTING(l);
    ensure_my_free_is_called();
    ensure_freed();
}

static void test_free_with_fusion_no_release(void) {
    size_t total_blocks = _mm_total_blocks();
    size_t total_free_blocks = _mm_free_blocks();

    void* ptrs[3] = {NULL};
    size_t base_bytes = 30;

    for(size_t i=0; i<3; i++) {
        void *p = MALLOC_UNDER_TESTING(base_bytes+i);
        ensure_my_malloc_is_called();
        TEST_CHECK(p != NULL);
        ptrs[i] = p;
    }

    TEST_CHECK((total_blocks + 3) == _mm_total_blocks());

    for(size_t i=0; i<2; i++) {
        void *p = ptrs[0];
        FREE_UNDER_TESTING(p);
        ensure_my_free_is_called();
        ensure_freed();
    }

    TEST_CHECK((total_free_blocks + 2) == _mm_free_blocks());
    TEST_MSG("total_free_blocks should be 2 more %zu != %lu, total blocks: %zu",
         total_free_blocks+2,
         _mm_free_blocks(),
         total_blocks);

    void* p = ptrs[0];
    block head = recons_blk_from_user_mem_ptr(p);
    TEST_CHECK(head->free);

    size_t total_bytes_after_fusion = align_up_fundamental(base_bytes) + sizeof(struct s_block) + align_up_fundamental(base_bytes+1);
    TEST_CHECK(head->size == total_bytes_after_fusion);
    TEST_MSG("size of head add up to %lu != %lu",
         total_bytes_after_fusion,
         head->size);

    for(size_t i=0; i<3; i++) {
        void *p = ptrs[0];
        FREE_UNDER_TESTING(p);
        ensure_my_free_is_called();
        ensure_freed();
    }
}

TEST_LIST = {
    { "test_align_up",                       test_align_up },
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
    // { "realloc_grow_shrink",  test_realloc_grow_and_shrink },
    { NULL, NULL }
};
