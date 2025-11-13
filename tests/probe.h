#pragma once 

#include <stddef.h>

#include <internal.h>

block _mm_block_header(void);
size_t _mm_bytes_obtained_from_os(void);
size_t _mm_free_blocks(void);   // current free blocks
size_t _mm_non_free_blocks(void);   // current non-free blocks