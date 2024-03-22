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
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <locale.h>

// ------------------------------------------------------------------------- //
//                           Memory pool                                     //
// ------------------------------------------------------------------------- //

// Vector memory pool
typedef struct MemoryPoolVector {
    void *pool;        // Pointer to the memory pool
    size_t poolSize;   // Total size of the pool
    size_t used;       // Memory used so far
} MemoryPoolVector;


static MemoryPoolVector *ma_vector_memory_pool_create(size_t size);
static void *ma_vector_memory_pool_allocate(MemoryPoolVector *pool, size_t size);
static void ma_vector_memory_pool_destroy(MemoryPoolVector *pool);

// String memory pool
typedef struct MemoryPoolString {
    void *pool;        // Pointer to the memory pool
    size_t poolSize;   // Total size of the pool
    size_t used;       // Memory used so far
} MemoryPoolString;

MemoryPoolString* ma_string_memory_pool_create(size_t size);
void* ma_string_memory_pool_allocate(MemoryPoolString *pool, size_t size);
void ma_string_memory_pool_destroy(MemoryPoolString *pool);

// ------------------------------------------------------------------------ //
//                                 Encoding                                 //
// ------------------------------------------------------------------------ //

#if defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <wchar.h>
#endif

enum ascii85_errs_e {
    ascii85_err_out_buf_too_small = -255,
    ascii85_err_in_buf_too_large,
    ascii85_err_bad_decode_char,
    ascii85_err_decode_overflow
};

typedef enum {
    conversionOK,      /* Conversion successful */
    sourceExhausted,   /* Partial character in source, but hit end */
    targetExhausted,   /* Insufficient room in target for conversion */
    sourceIllegal      /* Source sequence is illegal/malformed */
} ConversionResult;

typedef enum {
    strictConversion,
    lenientConversion
} ConversionFlags;

void ma_encoding_hex_dump(const void *data, size_t size);                                  //
void ma_encoding_initialize(void);                                                         //

#if defined(_WIN32) || defined(_WIN64)
    wchar_t* ma_encoding_utf8_to_wchar(const char* utf8Str);                               //
    char* ma_encoding_wchar_to_utf8(const wchar_t* wstr);                                  //
#endif

char* ma_encoding_base64_encode(const char* input, size_t length);                         //
char* ma_encoding_base64_decode(const char* input, size_t length);                         //
char* ma_encoding_url_encode(const char* input, size_t length);                            //
char* ma_encoding_url_decode(const char* input, size_t lenght);                            //
char* ma_encoding_base32_encode(const char* input, size_t length);                         //
char* ma_encoding_base32_decode(const char* input, size_t length);                         //
char* ma_encoding_base16_encode(const char* input, size_t length);                         //
char* ma_encoding_base16_decode(const char* input, size_t length);                         //
char* ma_encoding_base58_encode(const void *data, size_t binsz);                           //
char* ma_encoding_base58_decode(const char *b58, size_t *binszp);                          //
char* ma_encoding_base91_encode(const uint8_t* data, size_t length);                       //
char* ma_encoding_base85_encode(const uint8_t* input, size_t length);                      //

uint16_t* ma_encoding_utf8_to_utf16(const uint8_t* input, size_t length);                  //
uint16_t* ma_encoding_utf32_to_utf16(const uint32_t* input, size_t length);                //

uint32_t* ma_encoding_utf16_to_utf32(const uint16_t* input, size_t length);                //
uint32_t* ma_encoding_utf8_to_utf32(const uint8_t* input, size_t length);                  //

uint8_t* ma_encoding_utf16_to_utf8(const uint16_t* input, size_t length);                  //
uint8_t* ma_encoding_utf32_to_utf8(const uint32_t* input, size_t length);                  //

uint8_t* ma_encododing_base85_decode(const char* input, size_t length);                    //
uint8_t* ma_encoding_base91_decode(const char* encoded, size_t* decoded_length);           //

bool ma_encoding_is_utf8(const uint8_t* input, size_t length);                             //
bool ma_encododing_is_utf8_string(const uint8_t** input, size_t length);                     //

// ------------------------------------------------------------------------ //
//                                  String                                  //
// ------------------------------------------------------------------------ //

extern const char* STRING_ASCII_LETTERS;
extern const char* STRING_ASCII_LOWERCASE;
extern const char* STRING_ASCII_UPPERCASE;
extern const char* STRING_DIGITS;
extern const char* STRING_HEXDIGITS;
extern const char* STRING_WHITESPACE;
extern const char* STRING_PUNCTUATION;

typedef struct String String;
struct String
{
    char* dataStr;
    size_t size;
    size_t capacitySize;
    MemoryPoolString* pool;
};

char ma_string_at(String* str, size_t index);                                           //
float ma_string_to_float(String *str);                                                  //
double ma_string_to_double(String* str);                                                //
wchar_t* ma_string_to_unicode(const char* str);                                         //

String* ma_string_create(const char* initialStr);                                       // Creates a new String object with an initial value.
String* ma_string_create_with_pool(size_t size);                                        // Creates a new String object with a specified memory pool size.
String* ma_string_substr(String* str, size_t pos, size_t len);                          // Creates a substring from a String object.
String** ma_string_split(String *str, const char *delimiter, int *count);               // Splits a String into an array of String objects.
String* ma_string_join(String **strings, int count, const char *delimiter);             // Joins several String objects into one.
String* ma_string_from_int(int value);                                                  // Creates a String from an integer.
String* ma_string_from_float(float value);                                              // Creates a String from a float.
String* ma_string_from_double(double value);                                            // Creates a String from a double.
String** ma_string_tokenize(String* str, const char* delimiters, int* count);           // Splits a string into tokens based on multiple delimiters.
String* ma_string_from_unicode(const wchar_t* wstr);                                    // Converts a wide string back to a regular string.
String** ma_string_create_from_initializer(size_t count, ...);                          // The string_create_from_initializer function dynamically creates an array of String pointers, each initialized with a string passed as a variadic argument.
String* ma_string_to_hex(String *str);                                                  // Converts a String to its hexadecimal representation.
String* ma_string_from_hex(String *hexStr);                                             // Converts a hexadecimal String back to the original string.
String* ma_string_base64_encode(const String *input);                                   // Encodes a String to base64 format.
String* ma_string_base64_decode(const String* input);                                   // Decodes a base64 encoded String.
String* ma_string_repeat(const String* str, size_t count);                              // Creates a new String by repeating the original String a specified number of times.
String* ma_string_join_variadic(size_t count, ...);                                     // Concatenates multiple Strings (variadic function).

bool ma_string_is_equal(String* str1, String* str2);                                    // Checks if two Strings are equal.
bool ma_string_is_less(String* str1, String* str2);                                     // Checks if the first String is less than the second.
bool ma_string_is_greater(String* str1, String* str2);                                  // Checks if the first String is greater than the second.
bool ma_string_is_less_or_equal(String* str1, String* str2);                            // Checks if the first String is less than or equal to the second.
bool ma_string_is_greater_or_equal(String* str1, String* str2);                         // Checks if the first String is greater than or equal to the second.
bool ma_string_is_not_equal(String* str1, String* str2);                                // Checks if two Strings are not equal.
bool ma_string_is_alpha(String* str);                                                   // Checks if a String contains only alphabetic characters.
bool ma_string_is_digit(String* str);                                                   // Checks if a String contains only digits.
bool ma_string_is_lower(String* str);                                                   // Checks if all characters in a String are lowercase.
bool ma_string_is_upper(String* str);                                                   // Checks if all characters in a String are uppercase.
bool ma_string_empty(String* str);                                                      // Checks if a String is empty.
bool ma_string_contains(String* str, const char* substr);                               // Checks if a String contains a specific substring.
bool ma_string_set_pool_size(String* str, size_t newSize);                              // Sets the size of the memory pool for a String.
bool ma_string_starts_with(const String* str, const char* substr);                      // Checks if a String starts with a specified substring.
bool ma_string_ends_with(const String* str, const char* substr);                        // Checks if a String ends with a specified substring.
bool ma_string_to_bool_from_cstr(const char* boolstr);                                  //

int ma_string_compare(const String* str1, const String* str2);                          // Compares two Strings.
int ma_string_find(String* str, const char* buffer, size_t pos);                        // Finds string in String and return position.
int ma_string_rfind(String* str, const char* buffer, size_t pos);                       //
int ma_string_find_first_of(String* str, const char* buffer, size_t pos);               // Finds the first occurrence of any of the characters in the given string.
int ma_string_find_last_of(String* str, const char* buffer, size_t pos);                // Finds the last occurrence of any of the characters in the given string.
int ma_string_find_first_not_of(String* str, const char* buffer, size_t pos);           // Finds the first character that does not match any of the characters in the given string.
int ma_string_find_last_not_of(String* str, const char* buffer, size_t pos);            // Finds the last character that does not match any of the characters in the given string.
int ma_string_compare_ignore_case(String* str1, String* str2);                          // Compares two Strings, ignoring case differences.
int ma_string_to_int(String *str);                                                      // Converts a String to an integer.

void ma_string_reverse(String* str);                                                    // Reverses the content of a String.
void ma_string_resize(String* str, size_t newSize);                                     // Resizes a String to a specified size.
void ma_string_shrink_to_fit(String* str);                                              // Reduces the capacity of a String to fit its size.
void ma_string_append(String* str, const char* strItem);                                // Appends a string to the end of a String.
void ma_string_push_back(String* str, const char chItem);                               // Appends a character to the end of a String.
void ma_string_assign(String* str, const char* newStr);                                 // Assigns a new value to a String.
void ma_string_insert(String* str, size_t pos, const char* strItem);                    // Inserts a string at a specified position.
void ma_string_erase(String* str, size_t pos, size_t len);                              // Erases a portion of a String.
void ma_string_replace(String* str1, const char* oldStr, const char* newStr);           // Replaces occurrences of a substring.
void ma_string_swap(String* str1, String* str2);                                        // Swaps the contents of two String objects.
void ma_string_pop_back(String* str);                                                   // Removes the last character of a String.
void ma_string_deallocate(String* str);                                                 // Deallocates the memory used by a String object.
void ma_string_clear(String* str);                                                      // Clears the contents of a String object.

char* ma_string_to_upper(String* str);                                                  // Converts a String to uppercase.
char* ma_string_to_lower(String* str);                                                  // Converts a String to lowercase.
char* ma_string_begin(String* str);                                                     // Returns an iterator to the beginning.
char* ma_string_end(String* str);                                                       // Returns an iterator to the end.
char* ma_string_rbegin(String* str);                                                    // Returns a reverse iterator to the beginning.
char* ma_string_rend(String* str);                                                      // Returns a reverse iterator to the end.
char* ma_string_back(String* str);                                                      // Returns a reference to the last character.
char* ma_string_front(String* str);                                                     // Returns a reference to the first character.
char* ma_string_strdup(const char* s);                                                  //
char* ma_string_from_int_cstr(int value);                                               //

size_t ma_string_length_cstr(const char* str);                                          // Returns the length of a char*.
size_t ma_string_length_utf8(const char* str);                                          // Return the length of utf-8 char*.
size_t ma_string_length(String* str);                                                   // Returns the length of a String.
size_t ma_string_capacity(String* str);                                                 // Returns the capacity of a String.
size_t ma_string_max_size(String* str);                                                 // Returns the maximum size of a String.
size_t ma_string_copy(String* str, char* buffer, size_t pos, size_t len);               // Copies parts of a string into an other.
size_t ma_string_count(String* str, const char* substr);                                // Count number of substr appears in String object 'str'.
size_t ma_string_utf8_char_len(char c);                                                 // Return the len of each unicode character.

const char* ma_string_data(String* str);                                                // Returns a pointer to the data stored in a String.
const char* ma_string_c_str(const String* str);                                         // Returns a pointer to the null-terminated sequence of characters.
const char* ma_string_cbegin(String* str);                                              // Returns a constant iterator to the beginning.
const char* ma_string_cend(String* str);                                                // Returns a constant iterator to the end.
const char* ma_string_crbegin(String* str);                                             // Returns a constant reverse iterator to the beginning.
const char* ma_string_crend(String* str);                                               // Returns a constant reverse iterator to the end.

void ma_string_deallocate(String *str);                                                 // Deallocates the memory used by a String object.
void ma_string_concatenate(String *str1, const String *str2);                           // Concatenates two String objects.
void ma_string_trim_left(String *str);                                                  // Trims leading whitespace characters from the beginning of the String object str.
void ma_string_trim_right(String *str);                                                 // Trims trailing whitespace characters from the end of the String object str
void ma_string_trim(String *str);                                                       // Trims whitespace from both ends of a String.
void ma_string_replace_all(String *str, const char *oldStr, const char *newStr);        // Replace occurrences of all substr in String object.
void ma_string_pad_left(String *str, size_t totalLength, char padChar);                 // Pads a String from the left.
void ma_string_pad_right(String *str, size_t totalLength, char padChar);                // Pads a String from the right.
void ma_string_trim_characters(String* str, const char* chars);                         // Trims specified characters from both ends of a String.
void ma_string_shuffle(String* str);                                                    // Randomly shuffle character of String object
void ma_string_to_title(String* str);                                                   // Converts each word in the String to title case.
void ma_string_to_capitalize(String* str);                                              // Capitalizes the first character of a String.
void ma_string_to_casefold(String* str);                                                // Converts a String to a case-insensitive form for comparisons.
void ma_string_format(String* str, const char* format, ...);                            // Formats a String using given format specifiers.
void ma_string_remove(String* str, const char* substr);                                 // Removes all occurrences of a substring.
void ma_string_remove_range(String* str, size_t startPos, size_t endPos);               // Removes a range of characters from a String object, starting from startPos and ending at endPos.
void ma_string_swap_case(String* str);                                                  // Swaps the case of each character in a String.

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

// ------------------------------------------------------------------------- //
//                          File IO                                          //
// ------------------------------------------------------------------------- //

// File Writer
typedef enum {
    POS_BEGIN,
    POS_END,
    POS_CURRENT,
} CursorPosition;

typedef enum {
    WRITE_ENCODING_UTF16,
    WRITE_ENCODING_UTF32,
} WriteEncodingType;

typedef enum {
    WRITE_TEXT,          // Open for writing in text mode
    WRITE_BINARY,        // Open for writing in binary mode
    WRITE_UNICODE,       // Open for writing Unicode text (may involve encoding conversions)
    WRITE_BUFFERED,      // Open for buffered writing (optimizes write operations)
    WRITE_UNBUFFERED,    // Open for unbuffered writing (direct write operations)
    WRITE_LINE,          // Open for line-by-line writing (useful for text files)
    WRITE_APPEND,
} WriteMode;

typedef struct {
    FILE* file_writer;
    WriteMode mode;
    bool is_open;
    WriteEncodingType encoding;
    char* file_path;
} FileWriter;

FileWriter* ma_file_writer_open(const char* filename, const WriteMode mode);                // Opens a file for writing in the specified mode.
FileWriter* ma_file_writer_append(const char* filename, const WriteMode mode);              // Opens an existing file for appending, or creates it if it doesn't exist.

size_t ma_file_writer_get_position(FileWriter* writer);                                     // Returns the current position in the file.
size_t ma_file_writer_write(void* buffer, size_t size, size_t count, FileWriter* writer);   // Writes data to the file.
size_t ma_file_writer_write_fmt(FileWriter* writer, const char* format, ...);               // Writes formatted data to the file.
size_t ma_file_writer_get_size(FileWriter* writer);                                         // Gets the size of the file.

bool ma_file_writer_write_line(char* buffer, size_t size, FileWriter* writer);              // Writes a line of text to the file.
bool ma_file_writer_close(FileWriter* writer);                                              // Closes the given FileWriter.
bool ma_file_writer_is_open(FileWriter* writer);                                            // Checks if the FileWriter is open.
bool ma_file_writer_flush(FileWriter* writer);                                              // Flushes the FileWriter's buffer.
bool ma_file_writer_set_encoding(FileWriter* writer, const WriteEncodingType encoding);     // Sets the character encoding for writing.
bool ma_file_writer_copy(FileWriter* src_writer, FileWriter* dest_writer);                  // Copies content from one FileWriter to another.
bool ma_file_writer_lock(FileWriter* writer);                                               // Locks the file to prevent other processes from modifying it.
bool ma_file_writer_unlock(FileWriter* writer);                                             // Unlocks the file.
bool ma_file_writer_seek(FileWriter* writer, long offset, const CursorPosition cursor_pos); // Moves the file pointer to a specific location.
bool ma_file_writer_truncate(FileWriter* writer, size_t size);                              // Appends formatted text to a file.
bool ma_file_writer_write_batch(FileWriter* writer, const void** buffers, const size_t* sizes, size_t count); // Writes multiple buffers in a single operation.
bool ma_file_writer_append_fmt(FileWriter* writer, const char* format, ...);                // Appends formatted text to a file.

const char* ma_file_writer_get_file_name(FileWriter* writer);                               // Retrieves the file path associated with the FileWriter.
const char* ma_file_writer_get_encoding(FileWriter* writer);                                // Gets the encoding type of the FileWriter.

// File Reader
typedef enum {
    READ_TEXT,          // Open for reading in text mode
    READ_BINARY,        // Open for reading in binary mode
    READ_UNICODE,       // Open for reading Unicode text (may involve encoding conversions)
    READ_BUFFERED,      // Open for buffered reading (optimizes read operations)
    READ_UNBUFFERED,    // Open for unbuffered reading (direct read operations)
    READ_LINE,          // Open for line-by-line reading (useful for text files)
} ReadMode;

typedef enum {
    READ_ENCODING_UTF16,
    READ_ENCODING_UTF32,
} ReadEncodingType;

typedef struct {
    FILE* file_reader;
    ReadMode mode;
    bool is_open;
    ReadEncodingType encoding;
    char* file_path;
} FileReader;

FileReader* ma_file_reader_open(const char* filename, const ReadMode mode);                 // Opens a file for reading in the specified mode.

bool ma_file_reader_close(FileReader* reader);                                              // Closes the FileReader.
bool ma_file_reader_set_encoding(FileReader* reader, const ReadEncodingType encoding);      // Sets the character encoding for reading.
bool ma_file_reader_seek(FileReader* reader, long offset, const CursorPosition cursor_pos); // Moves the file pointer to a specific location.
bool ma_file_reader_is_open(FileReader* reader);                                            // Checks if the FileReader is open.
bool ma_file_reader_eof(FileReader* reader);                                                // Checks if the end of the file has been reached.
bool ma_file_reader_copy(FileReader* src_reader, FileWriter* dest_writer);                  // Copies content from a FileReader to a FileWriter.
bool ma_file_reader_read_line(char* buffer, size_t size, FileReader* reader);               // Reads a line of text from the file.
bool ma_file_reader_read_lines(FileReader* reader, char*** buffer, size_t num_lines);       // Reads a specified number of lines from the file.

size_t ma_file_reader_get_position(FileReader* reader);                                     // Returns the current position in the file.
size_t ma_file_reader_read(void* buffer, size_t size, size_t count, FileReader* reader);    // Reads data from the file.
size_t ma_file_reader_get_size(FileReader* reader);                                         // Gets the size of the file.
size_t ma_file_reader_read_fmt(FileReader* reader, const char* format, ...);                // Reads formatted data from the file.

const char* ma_file_reader_get_file_name(FileReader* reader);                               // Retrieves the file path associated with the FileReader.

