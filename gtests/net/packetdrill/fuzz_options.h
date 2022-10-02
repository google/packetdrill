#ifndef __FUZZ_OPTIONS_H__
#define __FUZZ_OPTIONS_H__

#include "types.h"

struct fuzz_options {
    struct fuzz_option *options;  // Pointer to first fuzz_option
    u8 capacity;    // Allocated space in the buffer 
    u8 size;        // Size (in bytes) of items in the buffer
    u8 count;       // Count of fuzz instructions in the buffer
};


enum fuzz_type_t {
    OP_MUTATE = 0,
    OP_TRUNCATE = 1,
    OP_INSERT = 2
};

struct fuzz_option {
    enum fuzz_type_t fuzz_type;
    u8 header_type;
    u8 fuzz_offset;
    u8 fuzz_length;
} __packed;

struct fuzz_field {
    u8 fuzz_offset;
    u8 fuzz_length;
};


enum header_type_t {
    IPv4,
    IPv6,
    xTCP
};

extern struct fuzz_options* fuzz_options_new(void);

extern void fuzz_options_grow(struct fuzz_options *fuzz_options, size_t capacity);

extern int fuzz_options_append(struct fuzz_options *fuzz_options, struct fuzz_option *option);

extern struct fuzz_option* fuzz_option_new(enum fuzz_type_t fuzz_type, enum header_type_t header_type, u8 fuzz_offset, u8 fuzz_length);

#endif /* __FUZZ_OPTIONS_H__ */