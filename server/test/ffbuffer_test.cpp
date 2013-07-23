/*
 * =====================================================================================
 *
 *       Filename:  ffbuffer_test.cpp
 *
 *    Description:  Test case for server/ffbuffer class
 *
 *        Version:  1.0
 *        Created:  2013年07月23日 20时35分57秒
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Ray Fung
 *
 * =====================================================================================
 */

#include <stdio.h>
#include <string.h>
#include "../ffbuffer.h"

void normal()
{
    ffbuffer buffer;
    puts("========== normal ==============");
    printf("empty ffbuffer size: %d\n", (int)buffer.get_size());
    puts("perform clear()");
    buffer.clear();
    printf("after clear(), ffbuffer size: %d\n", (int)buffer.get_size());
    puts("================================\n");
}

void put_some_small_data()
{
    ffbuffer buffer;
    char data[1024];
    char result[1024] = {0};
    size_t n;

    puts("========== put_some_small_data ===========");
    puts("try to get 100 bytes from empty buffer");
    printf("it returns %d bytes\n", (int)buffer.get(data, 0, 100));

    puts("put some strings into the buffer, then get the data");
    data[0] = '\0';
    for(int i = 0; i < 5; ++i)
        strcat(data, "Hello, I am Ray Fung.\n");
    n = strlen(data) + 1;
    printf("these strings are %d bytes in total\n", (int)n);
    buffer.push_back(data, n);

    printf("it returns %d bytes:\n", buffer.get(result, 0, n));
    printf("%s\n", result);

    puts("perform clear()");
    buffer.clear();
    printf("now, there are %d bytes in the buffer\n", (int)buffer.get_size());
    puts("==========================================\n");
}

void put_many_data()
{
    ffbuffer buffer;
    char data[] = "Welcome to Linux\t";
    int n = 200;

    puts("================ put_many_data ===================");
    printf("put string \"%s\" %d times(not including null terminator)\n", data, n);
    for(int i = 0; i < n; ++i)
        buffer.push_back(data, sizeof(data) - 1);
    printf("put null terminator into the buffer\n");
    buffer.push_back("\0", 1);
    printf("%d bytes data have already put into the buffer\n", n * (sizeof(data) - 1) + 1);
    printf("now, there are %d bytes in the buffer\n", buffer.get_size());

    printf("remove 65 bytes from the buffer\n");
    buffer.pop_front(65);
    printf("now, there are %d bytes in the buffer\n", buffer.get_size());

    printf("remove 8900 bytes from the buffer\n");
    buffer.pop_front(8900);
    printf("now, there are %d bytes in the buffer\n", buffer.get_size());
    puts("==================================================");
}

int main()
{
    normal();
    put_some_small_data();
    put_many_data();
    return 0;
}
