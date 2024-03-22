// MIT License

// Copyright (c) 2024 ramsy0dev

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <stddef.h>
#include <stdbool.h>

// ------------------------------------------------------------------------- //
//                           Memory pool                                     //
// ------------------------------------------------------------------------- //

typedef struct MemoryPoolVector {
    void *pool;        // Pointer to the memory pool
    size_t poolSize;   // Total size of the pool
    size_t used;       // Memory used so far
} MemoryPoolVector;


static MemoryPoolVector *ma_memory_pool_create(size_t size);
static void *ma_memory_pool_allocate(MemoryPoolVector *pool, size_t size);
static void ma_memory_pool_destroy(MemoryPoolVector *pool);

// ------------------------------------------------------------------------- //
//                          CPP vectors in C                                 //
// ------------------------------------------------------------------------- //

typedef struct Vector Vector;

struct Vector {
    void* items;
    size_t size;
    size_t capacitySize;
    size_t itemSize;
    MemoryPoolVector *pool;
};

Vector* ma_vector_create(size_t itemSize);                                         // Initializes and returns a new vector with specified item size.

bool ma_vector_is_equal(const Vector* vec1, const Vector* vec2);                   // Checks if two vectors are equal in content.
bool ma_vector_is_less(const Vector* vec1, const Vector* vec2);                    // Checks if vec1 is lexicographically less than vec2.
bool ma_vector_is_greater(const Vector* vec1, const Vector* vec2);                 // Checks if vec1 is lexicographically greater than vec2.
bool ma_vector_is_not_equal(const Vector* vec1, const Vector* vec2);               // Checks if two vectors are not equal.
bool ma_vector_is_greater_or_equal(const Vector* vec1, const Vector* vec2);        // Checks if vec1 is lexicographically greater than or equal to vec2.
bool ma_vector_is_less_or_equal(const Vector* vec1, const Vector* vec2);           // Checks if vec1 is lexicographically less than or equal to vec2.
bool ma_vector_is_empty(Vector* vec);                                              // Determines if the vector is empty.
bool ma_vector_reserve(Vector* vec, size_t size);                                  // Erases a range of elements from the vector.
bool ma_vector_push_back(Vector* vec, const void* item);                           // Inserts an item into the vector at a specified position.
bool ma_vector_emplace_back(Vector *vec, void *item, size_t itemSize);             // Reserves memory to enhance vector capacity.

void ma_vector_erase(Vector* vec, size_t pos, size_t len);                         // Erases a range of elements from the vector.
void ma_vector_insert(Vector* vec, size_t pos, void* item);                        // Inserts an item into the vector at a specified position.
void ma_vector_resize(Vector* vec, size_t size);                                   // Resizes the vector to contain a specific number of elements.
void ma_vector_shrink_to_fit(Vector* vec);                                         // Reduces the capacity of the vector to fit its size.
void ma_vector_clear(Vector* vec);                                                 // Clears the contents of the vector.
void ma_vector_swap(Vector* vec1, Vector* vec2);                                   // Swaps the contents of two vectors.
void ma_vector_assign(Vector* vec, size_t pos, void* item);                        // Assigns a new value to an element at a specified position.
void ma_vector_emplace(Vector* vec, size_t pos, void* item, size_t itemSize);      // Constructs an element in-place at a specified position.
void ma_vector_deallocate(Vector* vec);                                            // Frees the memory occupied by the vector.

const void* ma_vector_cbegin(Vector* vec);                                         // Returns a constant pointer to the beginning of the vector.
const void* ma_vector_cend(Vector* vec);                                           // Returns a constant pointer to the end of the vector.
const void* ma_vector_crbegin(Vector* vec);                                        // Returns a constant pointer to the beginning of the reversed vector.
const void* ma_vector_crend(Vector* vec);                                          // Returns a constant pointer to the end of the reversed vector.

void* ma_vector_begin(Vector* vec);                                                // Returns a pointer to the first element.
void* ma_vector_end(Vector* vec);                                                  // Returns a pointer to the element following the last element.
void* ma_vector_pop_back(Vector* vec);                                             // Removes the last element and returns a pointer to it.
void* ma_vector_front(Vector* vec);                                                // Accesses the first element.
void* ma_vector_back(Vector* vec);                                                 // Accesses the last element.
void* ma_vector_data(Vector* vec);                                                 // Returns a pointer to the underlying array.
void* ma_vector_at(const Vector* vec, size_t pos);                                 // Accesses an element at a specific position.
void* ma_vector_rbegin(Vector* vec);                                               // Returns a pointer to the beginning of the reversed vector.
void* ma_vector_rend(Vector* vec);                                                 // Returns a pointer to the end of the reversed vector.

size_t ma_vector_size(const Vector* vec);                                          // Returns the number of elements.
size_t ma_vector_capacity(Vector* vec);                                            // Returns the capacity of the vector.
size_t ma_vector_max_size(Vector* vec);                                            // Returns the maximum number of elements the vector can hold.

