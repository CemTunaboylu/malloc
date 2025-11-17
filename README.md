# malloc — A Minimal Educational Memory Allocator

[![C Standard](https://img.shields.io/badge/C-17-blue.svg)](https://en.cppreference.com/w/c/17)
![GCC](https://img.shields.io/badge/gcc-%3E%3D%2013-blue)
![Clang](https://img.shields.io/badge/clang-%3E%3D%2017-blue)
![Tests](https://img.shields.io/badge/tests-Acutest-green.svg)

A small, test-driven, single-translation-unit implementation of `malloc`, `calloc`, `realloc`, and `free`.
This project is intentionally simple, heavily instrumented, and designed as a learning tool for understanding heap allocators, block splitting/merging, alignment, and system call wrappers.

The allocator overrides the global symbols (malloc, etc.) inside its own translation unit, enabling tests to exercise the implementation without using `LD_PRELOAD` tricks via statically linking.

⸻

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

⸻

## Project Layout

```
malloc/
├── README.md                ← you are here
├── Makefile                 ← builds allocator + tests
├── include/
│   └── malloc/malloc.h      ← exported API symbols
├── src/
│   ├── malloc.c             ← main allocator
│   ├── alignment.c          ← alignment helpers
│   ├── internal.h           ← block structure + allocator internals
│   ├── mm_debug.*           ← debug counters (TESTING)
│   ├── probes.c             ← test inspection helpers
│   └── sys_call_wrappers.c  ← brk/sbrk/mmap wrappers
└── tests/
    ├── acutest.h
    ├── test_malloc.c
    └── probe.h
```

⸻

## Building & Running

### Prerequisites

- GNU Make
- GCC or Clang
- Linux or macOS

### Build + Run Tests

`make clean test`

⸻

## Design Overview

### Block Layout

Each block in the heap has the following layout:

```
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

⸻

## Testing

Tests live in tests/test_malloc.c and cover:

- alignment
- block shape introspection
- invalid/valid pointer validation
- fusion logic
- calloc zeroing
- realloc grow/shrink semantics
- data copy correctness
- no persistent leaks between tests

All tests enforce strict debug counters in TESTING mode.

⸻

## Limitations / Non-Goals

This project intentionally avoids:

- Thread safety (for now)
- Per-thread arenas (for now)
- mmap-backed large allocations (stubbed only, for now)
- ASan compatibility (we override malloc)
- Production-grade fragmentation handling

The goal is educational clarity, not completeness.

⸻

## Future Work

- Real mmap large-allocation path
- Proper return of freed pages using mmap/munmap
- Over-aligned `aligned_alloc`
- Stress tests + randomized fuzzing
- Git hooks for formatting/linting

⸻

## License

This repository is for educational use.
Acutest is MIT-licensed by Martin Mitáš and Garrett D’Amore.
