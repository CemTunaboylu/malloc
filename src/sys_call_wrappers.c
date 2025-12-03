// Without _DEFAULT_SOURCE, brk and sbrk are NOT declared in <unistd.h> (for
// Linux/glibc)
#define _DEFAULT_SOURCE
#include <stdint.h>
#include <sys/types.h>

#ifdef TESTING
#include <arena.h>
#include <internal.h>
#include <stddef.h>

#define SBRK_REGION_SIZE 65536
#define MMAP_REGION_SIZE (MIN_CAP_FOR_MMAP * 8)
#define BUFFER_SIZE (SBRK_REGION_SIZE + MMAP_REGION_SIZE)

typedef union {
  max_align_t _align;
  unsigned char buf[BUFFER_SIZE];
} aligned_test_buffer_t;

static aligned_test_buffer_t underlying_test_buffer = {0};
static intptr_t current_brk = 0;
static unsigned char *const buf_start_sbrk = underlying_test_buffer.buf;
static unsigned char *const buf_end_sbrk =
    underlying_test_buffer.buf + SBRK_REGION_SIZE;

static int is_addr_in_sbrk_buffer(void *addr) {
  unsigned char *p = (unsigned char *)addr;
  return (p >= buf_start_sbrk) && (p <= buf_end_sbrk);
}

// will grow backwards
static intptr_t mmap_brk;

__attribute__((constructor)) void init_mmap_brk(void) {
  mmap_brk = BUFFER_SIZE;
}
static unsigned char *const buf_start_mmap =
    underlying_test_buffer.buf + SBRK_REGION_SIZE + 16;
static unsigned char *const buf_end_mmap =
    underlying_test_buffer.buf + BUFFER_SIZE;

static int is_addr_in_mmap_buffer(void *addr) {
  unsigned char *p = (unsigned char *)addr;
  return (p >= buf_start_mmap) && (p <= buf_end_mmap);
}

void *mm_sbrk(intptr_t inc) {
  if (inc == 0) {
    return buf_start_sbrk + current_brk;
  }

  intptr_t new_brk = current_brk + inc;

  if (new_brk < 0 || new_brk > BUFFER_SIZE) {
    return (void *)(-1);
  }
  unsigned char *old_brk = buf_start_sbrk + current_brk;
  current_brk = new_brk;
  return (void *)old_brk;
}

int mm_brk(void *addr) {
  if (!is_addr_in_sbrk_buffer(addr)) {
    return -1;
  }
  current_brk = (unsigned char *)addr - buf_start_sbrk;
  return 0;
}
// there is a threshold for mmap, the chunk must be larger so that we can mimick
// it
void *mm_mmap(size_t n) {
  intptr_t new_brk = mmap_brk - n;

  if (new_brk <= SBRK_REGION_SIZE || new_brk > BUFFER_SIZE) {
    return (void *)(-1);
  }
  mmap_brk -= n;
  unsigned char *p = buf_end_mmap - mmap_brk;
  return (void *)p;
}

int mm_munmap(void *p, size_t n) {
  if (!is_addr_in_mmap_buffer(p)) {
    return -1;
  }
  if (((unsigned char *)p + n) >= buf_end_mmap) {
    return -1;
  }
  mmap_brk += (intptr_t)n;
  return 0;
}
#else

#include <sys/mman.h>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

// use for small allocations < 128 KiB
void *mm_sbrk(intptr_t inc) { return sbrk(inc); }
int mm_brk(void *addr) {
/*
 * brk/sbrk are legacy, non-POSIX system calls with different prototypes
 * across UNIX descendants:
 *
 *   - Linux/glibc uses System V semantics:
 *        int brk(void *addr);           // 0 on success, -1 on error
 *        void *sbrk(intptr_t inc);      // old break or (void*)-1 on error
 *
 *   - macOS/BSD expose older BSD variants:
 *        void *brk(const void *addr);   // new break or (void*)-1 on error
 *
 *       void *_LIBC_UNSAFE_INDEXABLE brk(const void *_LIBC_UNSAFE_INDEXABLE);
 *          to be specific
 *
 *        void *sbrk(int inc);           // old break or (void*)-1 on error
 *
 * Because POSIX does not specify brk/sbrk, both are valid.
 * We normalize behavior by providing our own wrapper mm_brk()
 * which always returns 0 on success and -1 on error regardless of platform.
 */
#if defined(__APPLE__)
  void *res = brk(addr);
  if (res == (void *)-1) {
    return -1; // error, errno already set by brk/sbrk
  }
  return 0; // success
#else
  // POSIX / glibc style: int brk(void*)
  return brk(addr); // glibc: 0 on success, -1 on error
#endif
}

static const int READ_AND_WRITE = PROT_READ | PROT_WRITE;
static const int PRIVATE_AND_ANON = MAP_PRIVATE | MAP_ANONYMOUS;
#define DEV_ZERO -1
#define OFFSET 0

void *mm_mmap(size_t n) {
  return mmap(0, n, READ_AND_WRITE, PRIVATE_AND_ANON, DEV_ZERO, OFFSET);
}
int mm_munmap(void *p, size_t n) { return munmap(p, n); }

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#endif
