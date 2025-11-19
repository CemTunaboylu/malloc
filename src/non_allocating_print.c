#include <sys/types.h>

#ifdef ENABLE_LOG 
    #include <stdint.h>
    #include <string.h>
    #include <unistd.h>

    static const int stderr_fd = 2;

    static void debug_write_hex_uintptr(uintptr_t v) {
        char buf[2 + sizeof(uintptr_t) * 2]; // "0x" + 2 hex chars per byte
        char *p = buf + sizeof buf;
        static const char hex[] = "0123456789abcdef";

        if (v == 0) {
            *--p = '0';
        } else {
            while (v > 0) {
                *--p = hex[v & 0xf];
                v >>= 4;
            }
        }
        *--p = 'x';
        *--p = '0';

        write(stderr_fd, p, (buf + sizeof buf) - p);
    }

    void debug_write_str(const char *s) {
        if (!s) return;
        write(stderr_fd, s, strlen(s));
    }

    void debug_write_ptr(const void* p) {
        debug_write_hex_uintptr((uintptr_t)p);
    }

    void debug_write_u64(size_t v) {
        char buf[32];
        char *p = buf + sizeof buf;
        *--p = '\n';
        if (v == 0) {
            *--p = '0';
        } else {
            while (v > 0) {
                *--p = '0' + (v % 10);
                v /= 10;
            }
        }
        write(stderr_fd, p, (buf + sizeof buf) - p);
    }
#else 
    void debug_write_ptr(const void *p) { (void)p; }
    void debug_write_str(const char *s) { (void)s; }
    void debug_write_u64(size_t v) { (void)v; }
#endif
