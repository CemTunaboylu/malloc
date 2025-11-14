#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include "acutest.h"
#include <internal.h>
#include <malloc/malloc.h>
#include "mm_debug.h"

extern block head;

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

static void test_invalid_addr_for_is_valid_addr(void) {
    void *p = malloc(1);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    p = (char*)p + sizeof(struct s_block);
    TEST_CHECK(is_addr_valid_heap_addr(p) == 0);
    free(p);
    ensure_my_free_is_called();
}

static void test_valid_addr_for_is_valid_addr(void) {
    void *p = malloc(1);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    TEST_CHECK(is_addr_valid_heap_addr(p) == 1);
    free(p);
    ensure_my_free_is_called();
}

// malloc(0) is expected to return NULL pointer
static void test_malloc_zero(void) {
    void *p = malloc(0);
    ensure_my_malloc_is_called();
    TEST_CHECK(p == NULL);
    free(p);
    ensure_my_free_is_called();
}

static void test_header_alignment_and_size(void) {
    size_t requested_bytes = 1;
    void *p = malloc(requested_bytes);
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
    free(p);
    ensure_my_free_is_called();
}

static void test_malloc_allocated_memory_aligned(void) {
    void *p = malloc(31);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    TEST_CHECK(is_aligned(p));
    free(p);
    ensure_my_free_is_called();
}

static void test_calloc_zero_fill(void) {
    size_t n = 16, sz = 8;
    unsigned char *p = (unsigned char *)calloc(n, sz);
    ensure_my_calloc_is_called();
    TEST_ASSERT(p != NULL);
    for (size_t i = 0; i < n*sz; ++i) TEST_CHECK(p[i] == 0);
    free(p);
    ensure_my_free_is_called();
}

static void test_free(void) {
    size_t requested_bytes = 1;
    void *p = malloc(requested_bytes);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    free(p);
    ensure_my_free_is_called();

    // ensure we set the block free 
    block head = recons_blk_from_user_mem_ptr(p);
    TEST_CHECK(head->free);
}

TEST_LIST = {
    { "test_align_up",                       test_align_up },
    { "test_invalid_addr_for_is_valid_addr",                       test_invalid_addr_for_is_valid_addr },
    { "test_valid_addr_for_is_valid_addr",                       test_valid_addr_for_is_valid_addr },
    { "test_malloc_zero",                       test_malloc_zero },
    { "test_header_alignment_and_size",                  test_header_alignment_and_size },
    { "test_malloc_allocated_memory_aligned",   test_malloc_allocated_memory_aligned },
    { "test_calloc_zero_fill",              test_calloc_zero_fill },
    { "test_free",              test_free },
    // { "realloc_grow_shrink",  test_realloc_grow_and_shrink },
    { NULL, NULL }
};
