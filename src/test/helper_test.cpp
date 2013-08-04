#include <stdio.h>
#include "../helper.h"

int main()
{
    uint16_t u16 = 0x0102;
    uint32_t u32 = 0x01020304L;
    uint64_t u64 = 0x0102030405060708LL;

    printf("ntoh16(%04x) = %04x\n", (int)u16, (int)ntoh16(u16));
    printf("ntoh32(%08lx) = %08lx\n", (long)u32, (long)ntoh32(u32));
    printf("ntoh64(%016llx) = %016llx\n\n", (long long)u64, (long long)ntoh64(u64));

    printf("hton16(%04x) = %04x\n", (int)u16, (int)hton16(u16));
    printf("hton32(%08lx) = %08lx\n", (long)u32, (long)hton32(u32));
    printf("hton64(%016llx) = %016llx\n", (long long)u64, (long long)hton64(u64));
    return 0;
}
