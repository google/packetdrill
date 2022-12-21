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
    OP_REPLACE = 0,
    OP_TRUNCATE = 1,
    OP_INSERT = 2
};

enum field_name_t {
    F_SOURCE_PORT = 0,
    F_DST_PORT = 1,
    F_SEQ_NUM = 2,
    F_ACK_NUM = 3,
    F_TCP_HDR_LEN = 4,
    F_FLAGS = 5,
    F_WIN_SIZE = 6,
    F_TCP_CHECKSUM = 7,
    F_URG_POINTER = 8,
    F_VERSION_IHL = 9,
    F_DSCP_ESN = 10,
    F_TOT_LEN = 11,
    F_IDEN = 12,
    F_FLAGS_FLAGOFF = 13,
    F_TTL = 14,
    F_PROTOCOL = 15,
    F_IP_CHECKSUM = 16,
    F_SRC_IP = 17,
    F_DEST_IP = 18
};



enum header_type_t {
    IPv4 = 0,
    IPv6 = 1,
    xTCP = 2
};

struct fuzz_option {
    enum fuzz_type_t fuzz_type;
    enum header_type_t header_type;
    u8 fuzz_field;
    char *fuzz_value;
    u8 fuzz_value_byte_count;
} __packed;

struct fuzz_value_t {
    char *value;
    u8 byte_count;
};

struct fuzz_field {
    u8 fuzz_offset;
    u8 fuzz_length;
};

extern struct fuzz_options* fuzz_options_new(void);

extern void fuzz_options_grow(struct fuzz_options *fuzz_options, size_t capacity);

extern int fuzz_options_append(struct fuzz_options *fuzz_options, struct fuzz_option *option);

extern struct fuzz_option* fuzz_option_new(enum fuzz_type_t fuzz_type, enum header_type_t header_type, u8 fuzz_field, struct fuzz_value_t fuzz_value);

#endif /* __FUZZ_OPTIONS_H__ */