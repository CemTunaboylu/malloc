#ifdef TESTING 

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
    #include "mm_debug.h"

    extern block head;
    extern size_t SIZE_OF_BLOCK;

    extern void* mm_calloc(size_t, size_t);
    extern void mm_free(void*);
    extern void* mm_malloc(size_t);
    extern void* mm_realloc(void*, size_t);

    #define CALLOC_UNDER_TESTING mm_calloc
    #define FREE_UNDER_TESTING mm_free
    #define MALLOC_UNDER_TESTING mm_malloc
    #define REALLOC_UNDER_TESTING mm_realloc
    #define CURRENT_BRK mm_sbrk(0)

    #ifdef ENABLE_LOG 
    #define LOG(...) do { logf_nonalloc(__VA_ARGS__); print_list_into_test_file(); } while (0)
    #else
        #define LOG(...) do{}while(0)
    #endif


    static size_t base_total_blocks;
    static size_t base_free_blocks;

    static void reset_markers(void) {
        MM_RESET_MALLOC_CALL_MARKER();
        MM_RESET_FREE_CALL_MARKER();
        MM_RESET_FREED_MARKER();
        MM_RESET_CALLOC_CALL_MARKER();
        MM_RESET_FUSE_FWD_CALL_MARKER();
        MM_RESET_FUSE_BWD_CALL_MARKER();
    }

    static void pre_test_sanity(void) {
        reset_markers();

        base_total_blocks = _mm_total_blocks();
        base_free_blocks  = _mm_free_blocks();

        TEST_CHECK(head == NULL);
        TEST_CHECK(base_total_blocks == 0);
        TEST_CHECK(base_free_blocks == 0);
    }

    static void post_test_sanity(void) {
        // No new permanent blocks, anything allocated during the tests are new extended blocks,
        // they will be released at the end of each test because they will be fused
        TEST_CHECK(_mm_total_blocks() == base_total_blocks);
        TEST_MSG("block leak: %zu -> %zu",
            base_total_blocks, _mm_total_blocks());

        // Free count should also match baseline
        TEST_CHECK(_mm_free_blocks() == base_free_blocks);
        TEST_MSG("free block mismatch: %zu -> %zu",
            base_free_blocks, _mm_free_blocks());

        TEST_CHECK(head == NULL);
    }

    static inline int is_aligned(void* p) {
        return ((uintptr_t)p % _Alignof(max_align_t)) == 0;
    }

    void check_block_header_shape(block head) {
        TEST_CHECK(sizeof(head->size) == 8);
        TEST_CHECK(sizeof(head->next) == 8);
        TEST_CHECK(sizeof(head->prev) == 8);
        TEST_CHECK(sizeof(head->end_of_alloc_mem) == 8);
        TEST_CHECK(sizeof(head->free) == 4);
        TEST_CHECK(is_aligned(head));
    }

    block recons_blk_from_user_mem_ptr(void* p) {
        block head = reconstruct_from_user_memory((const void*)p);
        check_block_header_shape(head);
        TEST_CHECK_(p == (void*)allocated_memory(head),"head=%p, p=%p, alloc(head)=%p",
            (void*)head, p, (void*)allocated_memory(head));
        return head;
    }

    void* ensuring_calloc(size_t len, size_t size_of) {
        MM_RESET_CALLOC_CALL_MARKER();
        MM_RESET_MALLOC_CALL_MARKER();
        int *q = (int*)CALLOC_UNDER_TESTING(len, size_of);
        MM_ASSERT_CALLOC_CALLED(1);
        MM_ASSERT_MALLOC_CALLED(1);
        return q;
    }

    void ensure_freed(void) {
        MM_ASSERT_FREED(1);
        MM_RESET_FREED_MARKER();
    }

    void ensuring_free(void* p) {
        MM_RESET_FREE_CALL_MARKER();
        FREE_UNDER_TESTING(p);
        MM_ASSERT_FREE_CALLED(1);
        ensure_freed();
    }

    void* ensuring_malloc(size_t size) {
        MM_RESET_MALLOC_CALL_MARKER();
        void* p = MALLOC_UNDER_TESTING(size);
        MM_ASSERT_MALLOC_CALLED(1);
        return p;
    }

    void ensure_fuse_fwd_is_called(int exp) {
        MM_ASSERT_FUSE_FWD_CALLED(exp);
        MM_RESET_FUSE_FWD_CALL_MARKER(); 
    }

    void ensure_fuse_bwd_is_called(int exp) {
        MM_ASSERT_FUSE_BWD_CALLED(exp);
        MM_RESET_FUSE_BWD_CALL_MARKER(); 
    }

    void* ensuring_realloc(void* p, size_t size) {
        MM_RESET_REALLOC_MARKER();
        void *r = REALLOC_UNDER_TESTING(p, size);
        MM_ASSERT_REALLOC_CALLED(1);
        return r;
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
        void *p = ensuring_malloc(1);
        TEST_CHECK(p != NULL);
        void *invalid = (char*)head + sizeof(struct s_block)*9;
        TEST_CHECK_(is_addr_valid_heap_addr(invalid) == 0, 
            "address %p should have been invalid since it is before list head %p", invalid, (void*)head);
        ensuring_free(p);
    }

    static void test_invalid_addr_outside_after_for_is_valid_addr(void) {
        void *p = ensuring_malloc(1);
        TEST_CHECK(p != NULL);
        void *invalid = (char*)p + sizeof(struct s_block);
        TEST_CHECK(is_addr_valid_heap_addr(invalid) == 0);
        ensuring_free(p);
    }

    static void test_valid_addr_for_is_valid_addr(void) {
        void *p = ensuring_malloc(1);
        TEST_CHECK(p != NULL);
        TEST_CHECK(is_addr_valid_heap_addr(p) == 1);
        ensuring_free(p);
    }

    // malloc(0) is expected to return NULL pointer
    static void test_malloc_zero(void) {
        void *p = ensuring_malloc(0);
        TEST_CHECK(p == NULL);
        FREE_UNDER_TESTING(p);
        MM_ASSERT_FREE_CALLED(0);
        MM_ASSERT_FREED(0);
    }

    static void test_first_malloc_new_head(void) {
        TEST_CHECK(head == NULL);
        void *p = ensuring_malloc(5);
        TEST_CHECK(p != NULL);
        TEST_CHECK(head != NULL);
        ensuring_free(p);
        TEST_CHECK(head == NULL);
    }

    static void test_header_alignment_and_size(void) {
        size_t requested_bytes = 1;
        void *p = ensuring_malloc(requested_bytes);
        TEST_CHECK(p != NULL);

        block head = recons_blk_from_user_mem_ptr(p);
        TEST_CHECK(head->size == align(requested_bytes));
        ensuring_free(p);
    }

    static void test_malloc_allocated_memory_aligned(void) {
        void *p = ensuring_malloc(31);
        TEST_CHECK(p != NULL);
        TEST_CHECK(is_aligned(p));
        ensuring_free(p);
    }

    static void test_calloc_zero_fill(void) {
        size_t n = 16, sz = 8;
        unsigned char *p = (unsigned char *)ensuring_calloc(n, sz);
        TEST_ASSERT(p != NULL);
        for (size_t i = 0; i < n*sz; ++i) TEST_CHECK(p[i] == 0);
        ensuring_free(p);
    }

    static void test_forward_fusion_2_blocks(void) {
        LOG("=== %s: start ===\n", __func__);

        size_t num_blocks = 3;
        void* ptrs[num_blocks];
        size_t base_bytes = 10;

        for(size_t i=0; i<num_blocks; i++) {
            void *p = ensuring_malloc(base_bytes);
            TEST_CHECK(p != NULL);
            ptrs[i] = p;
        }

        LOG("\tpost-malloc ===\n");

        for(size_t i=0; i<num_blocks-1; i++) {
            void *p = ptrs[i];
            block blk = reconstruct_from_user_memory(p);
            blk->free = 1;
            allocated_bytes_update(-blk->size);
        }

        LOG("\tafter artificially freeing blocks ===\n");

        void *p = ptrs[0];
        block blk = reconstruct_from_user_memory(p);

        fuse_fwd(blk);
        ensure_fuse_fwd_is_called(1);
        MM_ASSERT_FUSE_BWD_CALLED(0);

        LOG("\tpost-fwd-fusion ===\n");

        size_t aligned_base_bytes = align(base_bytes);
        size_t expected_size = (aligned_base_bytes * 2 + SIZE_OF_BLOCK);
        TEST_CHECK_(blk->size == expected_size,
            "size must be %lu, got %lu", expected_size, blk->size);

        block last = ptrs[num_blocks-1];
        TEST_CHECK_(last->free == 0, "last block should not have been freed");
        ensuring_free(last);
    }

    static void test_backward_fusion_2_blocks(void) {
        LOG("=== %s: start ===\n", __func__);

        const size_t n = 3;
        void* ptrs[n];
        size_t base_bytes = 10;

        for(size_t i=0; i<n; i++) {
            void *p = ensuring_malloc(base_bytes);
            TEST_CHECK(p != NULL);
            ptrs[i] = p;
        }

        LOG("\tpost-malloc ===\n");

        for(size_t i=0; i<n-1; i++) {
            void *p = ptrs[i];
            block blk = reconstruct_from_user_memory(p);
            blk->free = 1;
            allocated_bytes_update(-blk->size);
        }

        LOG("\t after artificially freeing blocks ===\n");

        void *p = ptrs[n-2];
        block blk = reconstruct_from_user_memory(p);
        
        fuse_bwd(&blk);
        ensure_fuse_bwd_is_called(1);
        MM_ASSERT_FUSE_FWD_CALLED(0);

        LOG("\t post-bwd-fusion ===\n");

        size_t aligned_base_bytes = align(base_bytes);
        size_t expected_size = (aligned_base_bytes * (n-1) + SIZE_OF_BLOCK);
        TEST_CHECK_(blk->size == expected_size,
            "size must be %lu, got %lu", expected_size, blk->size);
        
        void* last = ptrs[n-1];
        ensuring_free(last);
    }

    static void test_free_no_release_or_fusion(void) {
        LOG("=== %s: start ===\n", __func__);

        const size_t n = 3;
        void* ptrs[n];
        size_t base_bytes = 30;

        for(size_t i=0; i<n; i++) {
            void *p = ensuring_malloc(base_bytes);
            TEST_CHECK(p != NULL);
            ptrs[i] = p;
        }

        LOG("\tpost-malloc ===\n");

        void* p = ptrs[1];

        ensuring_free(p);
        MM_ASSERT_FUSE_FWD_CALLED(0);
        MM_ASSERT_FUSE_BWD_CALLED(0);
        MM_ASSERT_RELEASED(0);

        LOG("\tpost-free ===\n");

        block blk = recons_blk_from_user_mem_ptr(p);
        TEST_CHECK(blk->free);

        for(size_t i=0; i<n; i++) {
            if (i==1) continue;
            ensuring_free(ptrs[i]);
        }
    }

    static void test_free_with_fusion_no_release(void) {
        LOG("=== %s: start ===\n", __func__);

        const size_t n = 5;
        void* ptrs[n];
        size_t base_bytes = 30;

        for(size_t i=0; i<n; i++) {
            void *p = ensuring_malloc(base_bytes);
            TEST_CHECK(p != NULL);
            ptrs[i] = p;
        }

        LOG("\tpost-malloc ===\n");

        const size_t to_free = n/2;
        // leave the last block unfree to avoid release
        for(size_t i=0; i<n-1; i++) {
            if (to_free == i) continue;
            void *p = ptrs[i];
            block blk = reconstruct_from_user_memory(p);
            blk->free = 1;
            allocated_bytes_update(-blk->size);
        }

        LOG("\tafter artificially freeing blocks ===\n");

        void* p = ptrs[to_free];
        block blk = reconstruct_from_user_memory(p);
        block after_fusion_head = blk->prev->prev;
        TEST_CHECK_(blk->free == 0, "block to free should have been free");
        ensuring_free(p);
        ensure_fuse_fwd_is_called(1);
        ensure_fuse_bwd_is_called(2);
        MM_ASSERT_RELEASED(0);

        LOG("\tpost-free middle ===\n");

        size_t total_block_sizes = SIZE_OF_BLOCK*(n-2);
        size_t total_allocated = align(base_bytes)*(n-1);
        size_t total_bytes_after_fusion = total_allocated + total_block_sizes;
        TEST_CHECK_(after_fusion_head->size == total_bytes_after_fusion,
            "size of after_fusion_head should add up to %lu, not %lu",
            total_bytes_after_fusion,
            after_fusion_head->size);

        void *last = ptrs[n-1];
        ensuring_free(last);
    }

    static void test_copy_block(void) {
        LOG("=== %s: start ===\n", __func__);

        const size_t src_len = 9;
        const size_t src_size_of = 4;
        const size_t src_n = src_len * src_size_of;

        int *p = (int*)ensuring_malloc(src_n);
        TEST_CHECK(p);
        for (size_t i=0;i<src_len;i++) p[i]=i;

        LOG("\tpost-malloc with size %lu and setting values for data ===\n", src_n);

        const size_t to_copy_len = 9;
        const size_t to_copy_size_of = 4;

        int *q = (int*)ensuring_calloc(to_copy_len, to_copy_size_of);
        TEST_ASSERT(q != NULL);

        block p_blk = reconstruct_from_user_memory(p);
        block q_blk = reconstruct_from_user_memory(q);

        deep_copy_block(p_blk, q_blk);
        LOG("\tafter deep copy block ===\n");

        size_t min = src_len > to_copy_len ? to_copy_len : src_len;
        for (size_t i=0;i<min;i++) TEST_CHECK_(p[i] == q[i], "%d != %d", p[i], q[i]);

        ensuring_free(p);
        ensuring_free(q);
    }

    static void test_realloc_grow_and_shrink(void) {
        LOG("=== %s: start ===\n", __func__);

        const size_t n = 10;

        char *p = (char*)ensuring_malloc(n);
        TEST_CHECK(p);
        for (int i=0;i<(int)n;i++) p[i]=(char)i;

        MM_RESET_MALLOC_CALL_MARKER();
        LOG("\tpost-malloc with size %lu and setting values for data ===\n", n);

        const size_t re_grow_n = 100;

        char *q = (char*)ensuring_realloc(p, re_grow_n);
        MM_ASSERT_MALLOC_CALLED(1);
        MM_RESET_MALLOC_CALL_MARKER();
        MM_ASSERT_FREE_CALLED(1);
        MM_RESET_FREE_CALL_MARKER();
        ensure_freed();
        TEST_ASSERT(q != NULL);
        for (int i=0;i<(int)n;i++) TEST_CHECK(q[i]==(char)i);

        LOG("\tafter growing realloc with %lu ===\n", re_grow_n);

        const size_t re_shrink_n = 5;
        char *r = (char*)REALLOC_UNDER_TESTING(q, re_shrink_n);
        ensure_realloc_enough_size();
        MM_ASSERT_MALLOC_CALLED(0);
        MM_ASSERT_FREE_CALLED(0);
        TEST_ASSERT(r != NULL);
        for (int i=0;i<(int)re_shrink_n;i++) TEST_CHECK(r[i]==(char)i);

        LOG("\tafter shrinking realloc with %lu ===\n", re_shrink_n);
        ensuring_free(r);
    }

    static void test_realloc_with_size_zero(void) {
        LOG("=== %s: start ===\n", __func__);

        const size_t n = 10;
        char *p = (char*)ensuring_malloc(n);
        TEST_CHECK(p);
        MM_RESET_MALLOC_CALL_MARKER();

        const size_t zero = 0;

        char *q = (char*)ensuring_realloc(p, zero);
        MM_ASSERT_MALLOC_CALLED(0);
        MM_ASSERT_FREE_CALLED(1);
        MM_RESET_FREE_CALL_MARKER();
        ensure_freed();
        TEST_ASSERT(q == NULL);
    }

    TEST_LIST = {
        { "test_align",                       test_align },
        { "test_invalid_addr_outside_before_for_is_valid_addr",                       test_invalid_addr_outside_before_for_is_valid_addr },
        { "test_invalid_addr_outside_after_for_is_valid_addr",                       test_invalid_addr_outside_after_for_is_valid_addr },
        { "test_valid_addr_for_is_valid_addr",                       test_valid_addr_for_is_valid_addr },
        { "test_malloc_zero",                       test_malloc_zero },
        { "test_first_malloc_new_head",                       test_first_malloc_new_head },
        { "test_header_alignment_and_size",                  test_header_alignment_and_size },
        { "test_forward_fusion_2_blocks",              test_forward_fusion_2_blocks },
        { "test_backward_fusion_2_blocks",              test_backward_fusion_2_blocks },
        { "test_malloc_allocated_memory_aligned",   test_malloc_allocated_memory_aligned },
        { "test_calloc_zero_fill",              test_calloc_zero_fill },
        { "test_free_no_release_or_fusion",              test_free_no_release_or_fusion },
        { "test_free_with_fusion_no_release",              test_free_with_fusion_no_release },
        { "test_copy_block",  test_copy_block },
        { "test_realloc_grow_shrink",  test_realloc_grow_and_shrink },
        { "test_realloc_with_size_zero",  test_realloc_with_size_zero },
        { NULL, NULL }
    };
#endif
