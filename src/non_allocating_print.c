#include <sys/types.h>

#ifdef ENABLE_LOG 
    #include <stdint.h>
    #include <string.h>
    #include <unistd.h>

    static const int stderr_fd = 2;

    static void debug_write_hex_uintptr_fd(int fd, uintptr_t v) {
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

        write(fd, p, (buf + sizeof buf) - p);
    }

    static void debug_write_hex_uintptr(uintptr_t v) {
        debug_write_hex_uintptr_fd(stderr_fd, v); 
    }

    void debug_write_str_fd(int fd, const char *s) {
        if (!s) return;
        write(fd, s, strlen(s));
    }

    void debug_write_str(const char *s) {
        debug_write_str_fd(stderr_fd, s);
    }

    void debug_write_ptr_fd(int fd, const void* p) {
        debug_write_hex_uintptr_fd(fd, (uintptr_t)p);
    }

    void debug_write_ptr(const void* p) {
        debug_write_hex_uintptr((uintptr_t)p);
    }

    void debug_write_u64_fd(int fd, size_t v) {
        char buf[32];
        char *p = buf + sizeof buf;
        if (v == 0) {
            *--p = '0';
        } else {
            while (v > 0) {
                *--p = '0' + (v % 10);
                v /= 10;
            }
        }
        write(fd, p, (buf + sizeof buf) - p);
    }

    void debug_write_u64(size_t v) {
        debug_write_u64_fd(stderr_fd, v); 
    }
#else 
    void debug_write_ptr_fd(int fd, const void *p) { (void)fd; (void)p; }
    void debug_write_str_fd(int fd, const char *s) { (void)fd; (void)s; }
    void debug_write_u64_fd(int fd, size_t v) { (void)fd; (void)v; }
    void debug_write_ptr(const void *p) { (void)p; }
    void debug_write_str(const char *s) { (void)s; }
    void debug_write_u64(size_t v) { (void)v; }
#endif
