#ifdef ENABLE_LOG
    #define _POSIX_C_SOURCE 200809L

    #include <internal.h>
    #include <stdarg.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <sys/types.h>

    static FILE *global_test_log;
    static int global_test_log_fd;
    static void free_resources(void){ if (global_test_log != NULL) fclose(global_test_log); }

    __attribute__((constructor))
    void init_global_test_log(void) {
        global_test_log = fopen("tests/malloc_tests.log", "a");
        if (global_test_log == NULL) {
            global_test_log_fd = fileno(stderr);
            return;
        } 
        global_test_log_fd = fileno(global_test_log);
        atexit(free_resources);
    }

    void logf_nonalloc(const char *fmt, ...) {
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
        debug_write_str_fd(global_test_log_fd, buf);
    }

void print_list_into_test_file(void) {
  BlockPtr head = a_head.head;
  if (head == NULL)
    return;
  for (BlockPtr b = head; b; b = b->next) {
    debug_write_str_fd(global_test_log_fd, "[ size:");
    debug_write_u64_fd(global_test_log_fd, get_true_size(b));
    debug_write_str_fd(global_test_log_fd, " - free:");
    debug_write_u64_fd(global_test_log_fd, is_free(b));
    debug_write_str_fd(global_test_log_fd, "]\n");
  }
}

    #define LOG(...) do { logf_nonalloc(__VA_ARGS__); print_list_into_file(); } while (0)
#else
    #define LOG(...) do{}while(0)
#endif
