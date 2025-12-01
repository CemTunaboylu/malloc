#include <math.h>
#include <stdalign.h>
#include <stddef.h>
#include <sys/types.h>

/* 
    _Alignof: operator returns the alignment requirement (in bytes) of type T
    max_align_t: is a type whose alignment is at least as strict as any 
        fundamental type on the platform (e.g. long double (16 bytes) 
        or 8 bytes on certain cases)

    C standard requires that memory returned by `malloc` be suitably
        aligned for ANY object type with "fundamental alignment", i.e. any
        "normal" object can be stored there safely. 
        A "normal" object has a type that doesn't have extended or over-aligned
        requirements i.e. objects composed of standard fundamental C types
        and aggregates (structs, arrays).

        | The pointer returned by malloc is suitably aligned so that it may be assigned 
        | to a pointer to any type of object with a fundamental alignment requirement.
        - C standard (C17)

    Other over-aligned types such as special SIMD types may require `aligned_alloc`.
*/

const size_t MAX_ALIGNMENT = _Alignof(max_align_t);
size_t NUM_BITS_SPARED_FROM_ALIGNMENT;

__attribute__((constructor))
void init_num_bits_spared_from_alignment(void) {
    NUM_BITS_SPARED_FROM_ALIGNMENT = log2(MAX_ALIGNMENT);
}

static size_t align_up(size_t any, size_t to) { 
    size_t shft = NUM_BITS_SPARED_FROM_ALIGNMENT;
    return (((any-1) >> shft)  << shft) + to;
}
size_t align_up_fundamental(size_t a) { return align_up(a, MAX_ALIGNMENT); }
