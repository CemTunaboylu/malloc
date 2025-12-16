// Without _DEFAULT_SOURCE, brk and sbrk are NOT declared in <unistd.h> (for
// Linux/glibc)
#define _DEFAULT_SOURCE
#include <stdint.h>
#include <sys/types.h>

#ifdef TESTING
#include <arena.h>
#include <internal.h>
#include <stddef.h>
#include <string.h>

#define SBRK_REGION_SIZE 65536
#define MMAP_REGION_SIZE (MIN_CAP_FOR_MMAP * 8)
#define BUFFER_SIZE (SBRK_REGION_SIZE + MMAP_REGION_SIZE)

typedef union {
  max_align_t _align;
  unsigned char buf[BUFFER_SIZE];
} aligned_test_buffer_t;

static aligned_test_buffer_t underlying_test_buffer = {0};
static unsigned char *const sbrk_lo = underlying_test_buffer.buf;
static unsigned char *const sbrk_hi =
    underlying_test_buffer.buf + SBRK_REGION_SIZE;
static unsigned char *brk_curr = underlying_test_buffer.buf;

static int is_addr_in_sbrk_buffer(void *addr) {
  unsigned char *p = (unsigned char *)addr;
  return (p >= sbrk_lo) && (p <= sbrk_hi);
}

static unsigned char *const mmap_lo =
    underlying_test_buffer.buf + SBRK_REGION_SIZE;
static unsigned char *const mmap_hi = underlying_test_buffer.buf + BUFFER_SIZE;
static unsigned char *mmap_curr = mmap_hi;

static int is_addr_in_mmap_buffer(void *addr) {
  unsigned char *p = (unsigned char *)addr;
  return (p >= mmap_lo) && (p <= mmap_hi);
}

void *mm_sbrk(intptr_t inc) {
  if (inc == 0) {
    return brk_curr;
  }

  unsigned char *new_brk = brk_curr + inc;

  if (!is_addr_in_sbrk_buffer(new_brk)) {
    return (void *)(-1);
  }
  unsigned char *old_brk = brk_curr;
  brk_curr = new_brk;
  return (void *)old_brk;
}

int mm_brk(void *addr) {
  if (!is_addr_in_sbrk_buffer(addr)) {
    return -1;
  }
  brk_curr = (unsigned char *)addr;
  return 0;
}

// there is a threshold for mmap, the chunk must be larger so that we can mimick
// it
void *mm_mmap(size_t n) {
  if (n == 0) {
    return (void *)(-1);
  }

  if (mmap_curr - n < mmap_lo) {
    // No space left in fake mmap region
    return (void *)(-1);
  }

  // grow backwards
  mmap_curr -= n;
  // mapping is [mmap_curr, mmap_curr + n)
  return (void *)mmap_curr;
}

void *mm_mremap(void *old_p, size_t old_size, size_t new_size) {
  if (new_size == old_size) {
    return old_p;
  }

  // Shrink in place: trivial
  if (new_size < old_size) {
    return old_p;
  }

  // Grow: simplest semantics — always move, never in-place.
  void *new_p = mm_mmap(new_size);
  if (new_p == (void *)(-1)) {
    return (void *)(-1);
  }

  // Copy the old region into the new one
  unsigned char *old_base = (unsigned char *)old_p;
  unsigned char *new_base = (unsigned char *)new_p;

  // to handle overlapping memory regions
  memmove(new_base, old_base, old_size);

  // We could call mm_munmap(old_p, old_size) or just "leak" it.
  // For tests, leaking is usually fine; or:
  // (void)mm_munmap(old_p, old_size);

  return new_p;
}

int mm_munmap(void *p, size_t n) {

  if (!is_addr_in_mmap_buffer(p)) {
    return -1;
  }

  unsigned char *addr = (unsigned char *)p;
  // Only reclaim if this is the topmost chunk
  if (addr + n == mmap_curr) {
    mmap_curr += n;
  }

  // Otherwise we just leak it in the test buffer; that’s okay.
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

void *mm_mremap(void *op, size_t o, size_t n) {
  return mremap(op, o, n, MREMAP_MAYMOVE);
}
int mm_munmap(void *p, size_t n) { return munmap(p, n); }

#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#endif
