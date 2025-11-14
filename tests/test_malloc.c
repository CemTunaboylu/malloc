#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include "acutest.h"
#include <internal.h>
#include <malloc/malloc.h>
#include "mm_debug.h"

extern block head;

/* 
    _Alignof: operator returns the alignment requirement (in bytes) of type T
    max_align_t: is a type whose alignment is at least as strict as any 
        fundamental type on the platform (e.g. long double (16 bytes) 
        or 8 bytes on certain cases)

    C standard requires that memory returned by `malloc` be suitably
        aligned for ANY object type with "fundamental alignment", i.e. any
        "normal" object can be stored there safely. 
        A "normal" object has a type that doesn't have extended or over-aligned
        requirements i.e. objects composed of standard fundamental C types
        and aggregates (structs, arrays).

        | The pointer returned by malloc is suitably aligned so that it may be assigned 
        | to a pointer to any type of object with a fundamental alignment requirement.
        - C standard (C17)

    Other over-aligned types such as special SIMD types may require `aligned_alloc`.
*/
// for now check if it is 4 bytes aligned
static inline int is_aligned(void* p) {
    return ((uintptr_t)p % _Alignof(max_align_t)) == 0;
}

void ensure_my_malloc_is_called() {
    MM_ASSERT_MALLOC_CALLED(1);
    MM_RESET_MALLOC_CALL_MARKER();
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

// malloc(0) is expected to return NULL pointer
static void test_malloc_zero(void) {
    void *p = malloc(0);
    ensure_my_malloc_is_called();
    TEST_CHECK(p == NULL);
    free(p);
}

static void test_header_alignment_and_size(void) {
    size_t requested_bytes = 1;
    void *p = malloc(requested_bytes);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);

    size_t offset = offsetof(struct s_block, user_memory);
    block head = (block)((char*)p - offset);
    TEST_CHECK(is_aligned(head));
    TEST_CHECK(p == (void*)allocated_memory(head));
    TEST_MSG("head=%p, p=%p, alloc(head)=%p",
         (void*)head, p, (void*)allocated_memory(head));
    TEST_CHECK(sizeof(head->size) == 8);
    TEST_CHECK(head->size == align_up_fundamental(requested_bytes));
    TEST_CHECK(sizeof(head->next) == 8);
    TEST_CHECK(sizeof(head->prev) == 8);
    TEST_CHECK(sizeof(head->free) == 4);
    TEST_CHECK(sizeof(head->user_memory) == 8);

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
}

static void test_malloc_allocated_memory_aligned(void) {
    void *p = malloc(31);
    ensure_my_malloc_is_called();
    TEST_CHECK(p != NULL);
    TEST_CHECK(is_aligned(p));
    free(p);
}


TEST_LIST = {
    { "test_align_up",                       test_align_up },
    { "test_malloc_zero",                       test_malloc_zero },
    { "test_header_alignment_and_size",                  test_header_alignment_and_size },
    { "test_malloc_allocated_memory_aligned",   test_malloc_allocated_memory_aligned },
    // { "calloc_zero_fill",              test_calloc_zero_fill },
    // { "realloc_grow_shrink",  test_realloc_grow_and_shrink },
    { NULL, NULL }
};
