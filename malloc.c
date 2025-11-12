#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define CURRENT_BRK sbrk(0)
#define SIZE_OF_BLOCK sizeof(struct s_block)

#define align4(x) ((((x-1) >> 2) << 2) + 4)

// since blocks are always used with pointers, we define the type as a pointer type
typedef struct s_block *block;

// structs ara aligned by default, so cannot make free smaller at this point
// block is 32-bit aligned until data
struct s_block {
    size_t size;
    block next;
    int free;
    char data[1]; // pointing to the start of allocated memory
}; 

void split_block(block b, size_t aligned_size_to_shrink){
    // b->data is *char so the pointer arithmetic below has 4 bytes precision 
    block rem_free = (block)(b->data + aligned_size_to_shrink);

    rem_free->size =  b->size - aligned_size_to_shrink - SIZE_OF_BLOCK;
    rem_free->next = b->next;
    rem_free->free = 1;

    b->size = aligned_size_to_shrink;
    b->next = rem_free;
}

block first_fit_find(block head, block* tail, size_t aligned_size){
    block curr = head;
    // as long as we have block at hand, and it's either NOT free or NOT big enough
    while (curr && !(curr->free && curr->size >= aligned_size)) {
        // if we cannot find a suitable block, we keep track of the last block 
        // so that malloc can append a new block at the end 
        *tail = curr;
        curr = curr->next;
    }
    return curr;
}

block extend_heap(block* last, size_t aligned_size){
    block brk = CURRENT_BRK;
    if (sbrk(SIZE_OF_BLOCK + aligned_size) == (void*) -1) {
        perror("failed to allocate memory");
        return NULL;
    }
    brk->size = aligned_size;
    brk->next = NULL;
    if (*last) {
        (*last)->next = (block)brk;
    }
    brk->free = 0;
    return brk;
}

void* head = NULL; 

void* malloc(size_t size) {
    void* tail = head;
    size_t aligned_size = align4(size); 
    block blk = first_fit_find(head, tail, aligned_size);
    if (blk == NULL) {
        // if failed nothing to do, if not block is not larger than size
        blk = extend_heap(&tail, aligned_size); 
    } 
    if (blk == NULL) {
        return blk;
    }
    blk->free = 0;
    // if size is larger such that it can allocate at least 
    // a new block and an additional 4 bytes, split the block
    if ((blk->size-aligned_size) > (SIZE_OF_BLOCK+4)) {
        split_block(blk, aligned_size);
    }
    return blk;
} 

// allocate memory for an array of length len consisting of 
// memory chunks of size size_of (of objects of size_of)
// properly aligned for object
// if succeeds, initialize all bytes to 0.
void* calloc(size_t len, size_t size_of) {
    size_t total = len * size_of;
    block* new = malloc(total);
    if (new == NULL) {
        return NULL;
    }
    int num_bytes = align4(total) << 2; // new->data is *char which is 1 byte
    for (size_t i=0; i<num_bytes; i++) {
        new[i] = 0;
    }
    return new;
}