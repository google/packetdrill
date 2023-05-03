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
    F_SRC_PORT = 0,
    F_DST_PORT = 1,
    F_SEQ_NUM = 2,
    F_ACK_NUM = 3,
    F_DATA_OFF = 4,
    F_RESERVED = 5,
    F_FLAGS = 6,
    F_CWR_FLAG = 7,
    F_ECE_FLAG = 8,
    F_URG_FLAG = 9,
    F_ACK_FLAG = 10,
    F_PSH_FLAG = 11,
    F_RST_FLAG = 12,
    F_SYN_FLAG = 13,
    F_FIN_FLAG = 14,
    F_WIN_SIZE = 15,
    F_CHECKSUM = 16,
    F_URG_POINTER = 17,
    F_UDP_LEN = 18,
    F_VERSION = 19,
    F_IHL = 20,
    F_DSCP = 21,
    F_ECN = 22,
    F_TOT_LEN = 23,
    F_IDEN = 24,
    F_RSV_FLAG = 25,
    F_DF_FLAG = 26,
    F_MF_FLAG = 27,
    F_FRAG_OFF = 28,
    F_TTL = 29,
    F_PROTOCOL = 30,
    F_SRC_ADDR = 31,
    F_DST_ADDR = 32,
    F_TRF_CLASS = 33,
    F_FLOW_LABEL = 34,
    F_PYLD_LEN = 35,
    F_NEXT_HEADER = 36,
    F_HOP_LIMIT = 37
};



enum header_type_t {
    IPv4 = 0,
    IPv6 = 1,
    xTCP = 2,
    xUDP = 3
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