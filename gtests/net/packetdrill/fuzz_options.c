#include "fuzz_options.h"

#include <stdlib.h>
#include <string.h>

struct fuzz_options* fuzz_options_new(void) {
    struct fuzz_options *options = (struct fuzz_options *) malloc(sizeof(struct fuzz_options));

    options->options = malloc(sizeof(struct fuzz_option));
    options->capacity = sizeof(struct fuzz_option);
    options->count = 0;

    return options;
} 

void fuzz_options_grow(struct fuzz_options *fuzz_options, size_t capacity) {
    if (capacity > fuzz_options->capacity) {
        fuzz_options->options = realloc(fuzz_options->options, capacity);
        fuzz_options->capacity = capacity;
    }
}

int fuzz_options_append(struct fuzz_options *fuzz_options, struct fuzz_option *option) {
    size_t fuzz_option_size = sizeof(struct fuzz_option);
    if (fuzz_option_size + fuzz_options->size > fuzz_options->capacity) {
        fuzz_options_grow(fuzz_options, fuzz_options->capacity * 2);
    }

    memcpy(fuzz_options->options + fuzz_options->size, option, fuzz_option_size);
    fuzz_options->size += fuzz_option_size;
    fuzz_options->count += 1;

    free(option);

    return STATUS_OK;
}

struct fuzz_option* fuzz_option_new(enum fuzz_type_t fuzz_type, enum header_type_t header_type, u8 fuzz_offset, u8 fuzz_length) {
    struct fuzz_option *option = calloc(1, sizeof(struct fuzz_option));

    option->fuzz_type = fuzz_type;
    option->header_type = header_type;
    option->fuzz_offset = fuzz_offset;
    option->fuzz_length = fuzz_length;

    return option;
}