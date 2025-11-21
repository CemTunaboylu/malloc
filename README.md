# malloc — A Minimal Educational Memory Allocator

[![C Standard](https://img.shields.io/badge/C-17-blue.svg)](https://en.cppreference.com/w/c/17)
![GCC](https://img.shields.io/badge/gcc-%3E%3D%2013-blue)
![Clang](https://img.shields.io/badge/clang-%3E%3D%2017-blue)
![Tests](https://img.shields.io/badge/tests-Acutest-green.svg)

A small, test-driven, single-translation-unit implementation of `malloc`, `calloc`, `realloc`, and `free`.
This project is intentionally simple, heavily instrumented, and designed as a learning tool for understanding heap allocators, block splitting/merging, alignment, and system call wrappers.

The allocator overrides the global symbols (malloc, etc.) inside its own translation unit, enabling tests to exercise the implementation without using `LD_PRELOAD` tricks via statically linking.

## Features

✔ Fundamental alignment

All user pointers returned by `malloc()` satisfy `alignof(max_align_t)`.

✔ First-fit allocation strategy

The allocator maintains a doubly-linked list of blocks:

`[block][block][block]...`

✔ Block splitting

A free block that is larger than needed is split into:

`[allocated block][free remainder block]`

✔ Forward and backward coalescing

When `free()` marks a block as free, adjacent free blocks are merged:

- Forward: blk -> next
- Backward: prev <- blk

✔ Debug counters (TESTING-only)

In TESTING builds, the allocator tracks calls to:

- `malloc`
- `free`
- `realloc`
- `calloc`
- `fuse_fwd` / `fuse_bwd`
- `realloc` grow/shrink events

✔ System call abstraction

All OS interactions are funneled through:

- `mm_sbrk`
- `mm_brk`
- `mm_mmap`
- `mm_munmap`

These are fully stubbed for testing and demonstrate differences between glibc and older BSD/macOS prototypes.

✔ Deterministic, single-process Acutest suite

Tests don’t fork; everything runs inside one process for determinism.

## Project Layout

```md
malloc/
├── README.md                ← you are here
├── Makefile                 ← builds allocator + tests
├── Dockerfile               ← reproducible build environment
├── Dockerfile.investigation ← reproducible investigation environment
├── include/
│   └── malloc/malloc.h      ← exported API symbols
├── src/
│   ├── malloc.c             ← main allocator
│   ├── alignment.c          ← alignment helpers
│   ├── internal.h           ← block structure + allocator internals
│   ├── mm_debug.*           ← debug counters (TESTING)
│   ├── probes.c             ← test inspection helpers
│   └── sys_call_wrappers.c  ← brk/sbrk/mmap wrappers
├── tests/
│  ├── acutest.h
│  ├── test_malloc.c
│  └── probe.h
└── githooks/                ← githooks (here for version control), `make install-git-hooks` to install them
    └── pre-push             ← pre-push hook, runs `test-interpose` if on mac + `make test-container` as guard before pushing
```

## Building & Running

### Prerequisites

- GNU Make
- GCC or Clang
- Linux or macOS

### Build + Run Tests

`make clean test`

### Build and test inside Docker

```sh
make test-container 
```

### Build an interactive investigation container

If `USE_GDB` is set, directly execs into the gdb session of the test binary, otherwise execs into the container

```sh
make investigation-container  [USE_GDB=] 
```

## Design Overview

### Block Layout

Each block in the heap has the following layout:

```md
+-----------------------------+
| size                        |  ← bytes in payload
| next                        |  ← pointer to next block
| prev                        |  ← pointer to previous block
| end_of_alloc_mem            |  ← end of user memory
| free (int)                  |
+-----------------------------+
```

The block header is intentionally aligned and verified in tests.

## Allocation Flow

1. Align the requested size
2. Search for a suitable free block (first-fit)
3. Split the block if large enough
4. Return pointer to start of the requested allocated memory

## Freeing Flow

1. Validate pointer belongs to the allocator
2. Mark block as free
3. Fuse forward
4. Fuse backward
5. If block is at the heap tail, attempt to shrink the heap (may fail on modern OSes)

**Note**: Modern kernels rarely shrink the program break — the test suite accounts for this.

## Interposition Mode (macOS)

On macOS, the project can be built in interposition mode, where a dylib transparently intercepts calls to:

- `malloc`
- `free`
- `calloc`
- `realloc`
- `malloc_size`

This allows testing application-level behavior by routing all calls to our allocators.

We use a `DYLD_INSERT_LIBRARIES=...` mechanism and a dedicated interposer defined in `src/interpose.c`.

Note: Interposed tests are intentionally limited: tests that rely on precise block layout control (fusion, exact counter assertions, etc.) are disabled under interposition because system libraries consistently allocate between test steps.

## Testing

Tests live in `tests/test_malloc.c` and cover:

- alignment
- block shape introspection
- invalid/valid pointer validation
- fusion logic
- calloc zeroing
- realloc grow/shrink semantics
- data copy correctness
- releasing memory (on container)
- interposition of `calloc`, `free`, `malloc`, `realloc` on MacOS

All tests enforce strict debug counters in TESTING mode.

## Debugging & Investigation Tools

The project includes several tools to help inspect allocator behavior:

### Non-allocating print helpers   (src/non_allocating_print.c)

Safe logging routines that do not allocate, used when debugging allocator internals.

### Callsite tracking

Enabled via `-DTRACK_RET_ADDR`. Records return addresses and block metadata for up to 1024 malloc callsites, printed via `LATEST_CALLERS()`.

### OS Interaction Logs

All system call wrappers (mm_sbrk, mm_brk, mm_mmap, etc.) can be logged for deterministic behavior in testing.

### Investigation container

Build and drop into a GDB-capable environment:

```sh
make investigation-container USE_GDB=1
```

or disable GDB to explore the container:

```sh
make investigation-container USE_GDB=
```

## Limitations / Non-Goals

### Notes on Determinism and Test Environment

The tests (counters) rely on deterministic allocator behavior, which are unfortunately hard to satisfy consistently. In best effort, all tests try to measure the delta between initial conditions to test the given behavior.

Some tests that require particularly deterministic allocator behavior are:

a. fusion of free blocks
b. release of free tail block

If a slipping allocation takes place, the test will fail:

a. contiguity of free blocks are interrupted, thus fusion behaviour changes
b. the block to be released may no longer be the tail, and won't be released (cannot be)

In our tests:

- Linux test binaries override malloc globally, causing system libraries to use the allocator as well. This is achieved by function interposition on Mac, by intercepting all calls within the process to libc implementations and injecting our implementations.
- This results in additional allocations during process startup or stdio initialization.
- Tests relying on precise counter equality or block list shape may fail under:
  - interposition mode
  - unforeseen glibc allocations
  - sanitizer runtimes

The test suite is structured so these tests are excluded when running under interposition (fusion to be specific). Other tests try to isolate call counters to specific callsites, and assert deltas rather than absolute values.

## Design Guarantees

The allocator guarantees:

- All the memory allocated by the allocators satisfy max alignment required by the system that it runs on dynamically
  - `malloc()`, `calloc()` and `realloc` returns aligned memory (`_Alignof(max_align_t)`)
- First-fit search
- Deterministic block header layout
- Fusion (forward and backward)
- Optional callsite tracking
- OS interactions abstracted through deterministic wrappers
- Single-threaded correctness
- Strict block structure and pointer validity checking in TESTING mode

This project intentionally avoids:

- Thread safety (for now)
- Per-thread arenas (for now)
- mmap-backed large allocations (stubbed only, for now)
- ASan compatibility (we override malloc)
- Production-grade fragmentation handling

The goal is educational clarity, not completeness.

## Future Work

- Real mmap large-allocation path
- Proper return of freed pages using mmap/munmap
- Over-aligned `aligned_alloc`
- Stress tests + randomized fuzzing
- Git hooks for formatting/linting

## License

This repository is for educational use.
Acutest is MIT-licensed by Martin Mitáš and Garrett D’Amore.
