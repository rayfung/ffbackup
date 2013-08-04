#include <stdio.h>
#include <arpa/inet.h>
#include "helper.h"

#define FF_LITTLE_ENDIAN 0
#define FF_BIG_ENDIAN 1

void dump_data(void *data, size_t size)
{
    unsigned char *ptr = (unsigned char *)data;
    size_t i;
    for(i = 0; i < size; ++i)
        fprintf(stderr, "%02X ", (int)ptr[i]);
}

int get_byte_order()
{
    uint16_t k = 0x0102;
    unsigned char *ptr = (unsigned char *)&k;
    if(ptr[0] == 0x02)
        return FF_LITTLE_ENDIAN;
    else
        return FF_BIG_ENDIAN;
}

uint16_t ntoh16(uint16_t net)
{
    return ntohs(net);
}

uint16_t hton16(uint16_t host)
{
    return htons(host);
}

uint32_t ntoh32(uint32_t net)
{
    return ntohl(net);
}

uint32_t hton32(uint32_t host)
{
    return htonl(host);
}

uint64_t ntoh64(uint64_t net)
{
    uint64_t u = net;
    if(get_byte_order() == FF_LITTLE_ENDIAN)
    {
        uint8_t *ptr_net = (uint8_t *)&net;
        uint8_t *ptr_u = (uint8_t *)&u;
        int i, j;
        for(i = 0, j = 7; i < 8; ++i, --j)
            ptr_u[i] = ptr_net[j];
    }
    return u;
}

uint64_t hton64(uint64_t host)
{
    uint64_t u = host;
    if(get_byte_order() == FF_LITTLE_ENDIAN)
    {
        uint8_t *ptr_host = (uint8_t *)&host;
        uint8_t *ptr_u = (uint8_t *)&u;
        int i, j;
        for(i = 0, j = 7; i < 8; ++i, --j)
            ptr_u[i] = ptr_host[j];
    }
    return u;
}
