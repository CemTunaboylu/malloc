#ifdef TESTING
    #define _POSIX_C_SOURCE 200809L

    #include <internal.h>
    #include <malloc/malloc.h>
    #include <stdio.h>

    extern block head;

    extern void debug_write_str_fd(int fd, const char *s);
    extern void debug_write_ptr_fd(int fd, const void *p);
    extern void debug_write_u64_fd(int fd, size_t v);

    block _mm_block_header(void){
        return head;
    }

    // Global counter for bytes obtained from the OS during TESTING builds.
    static size_t total_global_bytes_from_os = 0;
    size_t _mm_bytes_obtained_from_os(void) { return total_global_bytes_from_os; }

    // Predicate type: functions that inspect a block and return non-zero if it matches.
    typedef int (*block_predicate_t)(block* b);

    // Example predicates used by tests.
    static int pred_is_free(block b) { return b->free; }
    static int pred_is_used(block b) { return !b->free; }
    static int pred_true(block b) { (void)b; return 1; }

    // Count blocks that satisfy a given predicate.
    size_t _mm_blocks(int (*predicate)(block)) {
        size_t c = 0;
        for (block b = head; b; b = b->next) {
            if (predicate(b)) c++;
        } 
        return c;
    }

    size_t _mm_free_blocks(void)     { return _mm_blocks(pred_is_free); }
    size_t _mm_non_free_blocks(void) { return _mm_blocks(pred_is_used); }
    size_t _mm_total_blocks(void)     { return _mm_blocks(pred_true); }

    void _mm_tear_down_allocator(void){
        for(block b=head; b; b=b->next) {
            free(b);
        }
    }

    void print_list_into_file(FILE* f) {
        if (head == NULL) return;
        int fd = fileno(f);
        for (block b = head; b; b = b->next) {
            debug_write_str_fd(fd, "[ size:"); 
            debug_write_u64_fd(fd, b->size); 
            debug_write_str_fd(fd, " - free:"); 
            debug_write_u64_fd(fd, b->free); 
            debug_write_str_fd(fd, "]\n");
        } 
    }

#endif
