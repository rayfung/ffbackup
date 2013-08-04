#ifndef HELPER_H
#define HELPER_H

#include <stdint.h>

void dump_data(void *data, size_t size);

uint16_t ntoh16(uint16_t net);

uint16_t hton16(uint16_t host);

uint32_t ntoh32(uint32_t net);

uint32_t hton32(uint32_t host);

uint64_t ntoh64(uint64_t net);

uint64_t hton64(uint64_t host);

#endif
