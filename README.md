# malloc (Educational Memory Allocator)

[![C Standard](https://img.shields.io/badge/C-17-blue.svg)](https://en.cppreference.com/w/c/17)
![GCC](https://img.shields.io/badge/gcc-%3E%3D%2013-blue)
![Clang](https://img.shields.io/badge/clang-%3E%3D%2017-blue)
![Tests](https://img.shields.io/badge/tests-Acutest-green.svg)

This project is a from-scratch implementation of `calloc` / `free` / `malloc` / `realloc` in C, inspired by glibc malloc internals.

It is intended as an educational and experimental allocator,
focusing on understanding real-world allocator design
tradeoffs rather than covering every edge case required by
production allocators.

The codebase is heavily instrumented and unit-tested,
and many design choices mirror glibc behavior
(e.g. its laziness in some bookkeeping paths).

## Updates

- We no longer override the global libc allocator symbols (malloc, etc.) inside its own translation unit. We replaced the testing mechanism with mock syscalls operating on a pre-allocated stack buffer for custom allocator calls. The previous version with function interposing and overriden global symbols resides in branch [first_find_free_list_with_deprecated_sbrk](../../tree/first_find_free_list_with_deprecated_sbrk).

- Latest branch with [mocked syscals and deprecated `brk` APIs](../../tree/sys_call_mocks)

📘 **Deep Dive: Linux vs macOS Dynamic Linking Behavior**

👉 See the full investigation in the project wiki: The full process (ELF symbol resolution, Mach-O two-level namespaces, `PLT`/`GOT`, and `dyld` interposition and the allocator dynamics) with proofs reside in **[Dynamic Linking Deep Dive](../../wiki/Dynamic_Linking_Deep_Dive)**

### Goals

- Implement a realistic allocator with behavior comparable to glibc
- Support `calloc`, `free`, `malloc`, `realloc`
- Model fastbins, unsorted bins, and coalescing semantics
- Support sbrk-backed and mmap-backed allocations
- Make allocator invariants explicit and testable
- Not losing clarity and debuggability over raw performance concerns

### Non-goals

- Full POSIX / glibc ABI compatibility
- Thread safety
- Absolute peak performance

## High-Level Design

### Arenas

The allocator maintains a primary arena which owns:

- Fastbins (singly-linked lists for small chunks)
- Unsorted bin
- Bookkeeping metadata (bin bitmaps, total allocated memory, debug markers)

There is no multi-arena or per-thread arena support. Just an additional arena for
mmapped memory chunks.

### Chunk / Block Layout

Each block in the heap has the following layout:

```md
| prev true size              |  ← prev. chunks true size (flags removed) if it is free
+-----------------------------+
| flagged size                |  ← bytes in payload with LSBs marking <is prev. free><is free><is mmapped>
| next                        |  ← pointer to next block if free and in any bin
| prev                        |  ← pointer to previous block if free and in any bin
+-----------------------------+
|                             |  ← user memory of aligned requested size
|                             |
|                             |
| true size                   |  ← size (flags removed) i.e. true size if block is free
+-----------------------------+
```

Each allocation is represented by a Block:

- Header contains size and flags
- User memory immediately follows the header
- When a block is free, its size is also written to its footer so that next contiguous header can easily retrieve it when coalescing/fusing.

This enables:

- O(1) backward coalescing
- Minimize cache misses under heavy pressure (to be proved with benchmarks)
- Encoding `prev_free` information without storing an explicit prev pointer

Flags & Metadata

- Allocation state is encoded using low bits in the size field (alignment requirements spare 3-4 least significand bits)
- `prev_free` is propagated eagerly/lazily depending on context
- Fastbin chunks are treated as “in use” to avoid premature fusion until they are consolidated

## Allocation Strategy

### Implemented malloc algorithm

Given the requested size `size`:

1. Align the size.
2. If aligned size is larger than `MIN_CAP_FOR_MMAP` (128 KiB), mmap.
3. Else if arena does not have any allocated chunks, allocate aligned size with sbrk.
4. Else
	1. If aligned size is small/eligible for fast bins.
		1. Try fast bin, if found return that block.
		2. If no chunk is found in fastbins, try small bins (check small bin for exact size), if found return that chunk.
		3. If no chunk is found in that small bin, do not go to next larger small bin (glibc does the same), try unsorted bin, if a chunk as big as (split before returning) or larger than aligned size is found, return that.
		4. If still no chunk found, consolidate fastbins (fuse them and put them to unsorted bin).
		5. Try unsorted again as above step.
		6. If still no chunk is found, request new chunk via sbrk from OS i.e. sysmalloc.
	2. If aligned size is large.
		1. Consolidate fast bins.
		2. Try unsorted bins and fuse as you go to satisfy the required aligned size, if found return that. If the found one is large enouhg, split first.
		3. If not found, try the large bin with the appropriate range of sizes, if found split if necessary and return.

🔑 The unsorted bin searches mentioned above fuses blocks at hand if possible and if it does not satisfy the requirement,
it is put in the appropriate bin (either a small or large bin).

### Small Allocations

- Sizes eligible for fastbins are placed into fastbins on free
- Fastbins are singly-linked and LIFO
- No immediate coalescing

### Fastbin Consolidation

- Fastbins are periodically consolidated into the unsorted bin
- During consolidation:
	- Chunks are moved one-by-one
	- Full forward and backward coalescing is performed
	- Bin bitmaps are updated lazily (mirroring glibc behavior)

### Large Allocations

- Requests above MIN_CAP_FOR_MMAP are fulfilled via mmap
- Large reallocations may transition between sbrk and mmap

### Reallocation

realloc supports all four transitions:

- SBRK → SBRK (in-place growth or move)
- SBRK → MMAP
- MMAP → SBRK
- MMAP → MMAP (via mremap)

If in-place growth is not possible:

1. A new block is allocated
2. User memory is deep-copied
3. Metadata flags are transferred
4. The old block is freed

### Implemented realloc algorithm

1. Check for edge cases
	1. If given pointer is null, malloc the given size
	2. If given size is 0, free the pointer
	3. If cannot reconstruct header from the given memory chunk, return NULL
	3. If the given size and the blocks size is equal, do nothing and return the given pointer
2. Switch over 4 possibilities given above
	1. SBRK → SBRK 
		1. Try growing in place by fusing with forward blocks until enough size is obtained (larger is fine, split before returning )
		2. If cannot still satisfy the requirement: perform malloc new, deep-copy, free old routine
		3. If satisfies split if too large, and return (no mem move needed)
	2. SBRK → MMAP
		1. perform malloc new (mmap), deep-copy, free sbrk (release occurs only if the block is the top block i.e. tangent to the heap's BRK) chunk routine
	3. MMAP → SBRK
		1. perform malloc new (sbrk), deep-copy, free (munmap) chunk routine
	4.  MMAP → MMAP (via mremap)
		1. mremap (handles deep-copy and freeing itself)

Any error during the syscalls fails and halts the given allocation attempt.

🔑 Deep copy routine uses memmove which handles overlapping memory regions.

### Implemented free algorithm

1. Handle edge cases
	1. If given pointer is null, do nothing silently return
	2. If cannot reconstruct the header, do nothing silently return (in tests, `FREE_ON_BAD_PTR` is marked )
	3. If alraedy free (double free), print a message (during testing `DOUBLE_FREE` is marked) and do nothing.
2. Mark the block as free and propagate the information via putting the true size in footer and setting the next blocks bit flag if not the top block
3. If mmapped, munmap
4. If not the top chunk and is eligible for fast bins (size fits), insert the block in appropriate fast bin and return. 
4. If the top chunk or large, fuse with contiguous chunks
5. If not the top chunk, insert the block in unsorted bin and return
5. If the top chunk, release the block i.e. return the memory region back to OS. 

🔑 Modern kernels rarely shrink the program break. To make testing this path easier, we diverge here.

## Testing & Debugging

### Unit Tests

- Deterministic, single process Acutest testing suite. Tests don’t fork; everything runs inside one process for determinism.
- Tests cover:
	- Allocation and freeing
	- Fastbin behavior
	- Coalescing correctness
	- Reallocation edge cases
	- Accounting invariants

### Instrumentation
- Extensive internal debug markers (MM_MARK)
- Optional verbose logging
- Designed to be run under:
	- UBSan
	- gdb / lldb
- (`mm_sbrk`, `mm_brk`, `mm_mmap`, etc.) system call wrappers are used to mock the syscalls for deterministic behavior in testing.


🔑 AddressSanitizer is intentionally disabled when overriding system malloc.

### Prerequisites

- GNU Make
- GCC or Clang
- Linux or macOS

## Build + Run Tests

```sh
make clean test
```

### Build and test inside Docker

```sh
make test-container 
```

### Build an interactive investigation container

If `USE_GDB` is set, directly execs into the gdb session of the test binary, otherwise execs into the container

```sh
make investigation-container  [USE_GDB=] 
```

Common flags:

- `ENABLE_LOG` – enable verbose allocator logging
- `TESTING` – enable test-only hooks and assertions
- `SHOW_SBRK_RELEASE_SUCCEEDS` – emulate successful memory release in tests

## Project Status

This project is actively developed and frequently refactored as allocator behavior
is refined and better understood.

Expect:

- Breaking internal changes
- Additional invariants
- More glibc-inspired behavior over time

## Disclaimer

This allocator is not intended for production use.

It is designed for:

- Learning how real allocators work
- Experimenting with allocator policies
- Testing ideas in a controlled environment

Use at your own risk.

## Allocator Invariants

The following invariants are relied upon throughout the codebase. Many unit tests implicitly assert these properties.

### Structural Invariants

- Blocks are contiguous within an arena
- Each block knows its true size via its header
- If a block is free, its size is also written to its footer
- A block can only be coalesced with neighbors that are also free (fastbins excluded)

### Metadata Invariants

- Allocation state is encoded in low bits of the size field
- `prev_free` information projects the next block’s metadata
- Fastbin chunks are temporarily marked as “in use” to prevent premature fusion

### Bin Invariants

- Fastbins are singly-linked and LIFO
- Unsorted bin may temporarily contain chunks of any size
- Bin bitmaps may be stale until a full consolidation pass

🔑 As glibc does it, bitmaps are lazily bookkept. An unset bit is a definite indicator of an empty bin,
but a set bit does not guarantee the bin is populated. The first try that unravels the false guarantee unsets the bit.

### Violating any of these invariants usually manifests as:

- Invalid backward coalescing
- Footer corruption
- Crashes during fastbin consolidation

## Codebase Tour

A rough guide to where things live:

- block.* – block layout, headers, footers, and basic navigation
- malloc.c – main allocation/free paths and fastbin logic
- arena.* – arena state, bin maps, and global bookkeeping
- mm_debug.* – debug counters, markers, and instrumentation
- tests/ – unit tests (Acutest-based)

The core allocator logic resides in malloc.c, start from there to understand the allocator’s core behavior.

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
│   ├── alignment.c          ← alignment helpers
│   ├── arena.c              ← procedures concerning Arenas 
│   ├── arena.h              ← macros, declarations and structures concerning Blocks 
│   ├── block.c              ← procedures concerning Blocks 
│   ├── block.h              ← declarations and structures concerning Blocks 
│   ├── internal.h           ← block structure + allocator internals
│   ├── malloc.c             ← main allocator
│   ├── mm_debug.*           ← debug counters (TESTING)
│   ├── non_allocating_print.c
│   ├── probes.c             ← test inspection helpers
│   └── sys_call_wrappers.c  ← brk/sbrk/mmap wrappers
├── tests/
│   ├── acutest.h
│   ├── log.c                ← logging mechanisms for testing 
│   └── test_malloc.c  
└── githooks/                ← githooks (here for version control), `make install-git-hooks` to install them
    └── pre-push             ← pre-push hook, runs `test-interpose` if on mac + `make test-container` as guard before pushing
```

### Design Notes & Glibc Parallels

This allocator intentionally mirrors several glibc behaviors:

- Lazy bin bitmap updates
- Fastbins delaying coalescing
- Unsorted bin as a staging area
- Small and large bin behaviors, granularity

However, it also diverges deliberately:

- Single arena only (mmap-arena is separate)
- No thread safety
- Reduced header size experiments
- Strong emphasis on explicit invariants

These differences are intentional and serve educational clarity.

## Development Workflow Tips

- Prefer running tests under UBSan
- Enable ENABLE_LOG when debugging fusion issues
- Use MM_MARK counters to trace allocator decisions
- When debugging corruption, verify:
	- footer placement
	- prev_free propagation
	- fastbin → unsorted transitions

## Future Directions

Planned or possible extensions:

- Giving away the `next`, `prev` pointers to the user when in use, as glibc squeezes in more performance like this.
- Reducing worst-case large bin insertions/retrievals by 2D linkedlists, grouping same sizes chunks as a 'fork' in that bin's linkedlist.
- Experimenting with some heuristics e.g. moving averages of allocated sizes, rate of change in allocated sizes.
- Additional integrity checks in debug builds
- Better visualization of arena state
- Experimental policies (e.g. different fastbin thresholds).

The project is expected to evolve as allocator understanding deepens :slightly_smiling_face:.
