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
    char data[] = "Welcome to Linux;";
    char *large_data = NULL;
    int n = 200;
    size_t size;

    puts("================ put_many_data ===================");
    printf("put string \"%s\" %d times(not including null terminator)\n", data, n);
    for(int i = 0; i < n; ++i)
        buffer.push_back(data, sizeof(data) - 1);
    printf("put null terminator into the buffer\n");
    buffer.push_back("\0", 1);
    printf("%d bytes data have already put into the buffer\n", n * (sizeof(data) - 1) + 1);
    printf("now, there are %d bytes in the buffer\n", buffer.get_size());

    printf("now, buffer info:\n");
    buffer.print_chunk_info();

    printf("remove 128 bytes from the buffer\n");
    buffer.pop_front(128);
    printf("now, there are %d bytes in the buffer\n", buffer.get_size());

    printf("now, buffer info:\n");
    buffer.print_chunk_info();

    printf("remove 65 bytes from the buffer\n");
    buffer.pop_front(65);
    printf("now, there are %d bytes in the buffer\n", buffer.get_size());

    printf("now, buffer info:\n");
    buffer.print_chunk_info();

    printf("remove 8900 bytes from the buffer\n");
    buffer.pop_front(8900);
    printf("now, there are %d bytes in the buffer\n", buffer.get_size());
    puts("==================================================");
}

void random_read()
{
    ffbuffer buf;
    char data[] = "Linux";
    char large_data[99];
    size_t n;
    int k = 100;
    int pos;

    puts("================ random_read ==================");
    n = strlen(data);
    for(int i = 0; i < k; ++i)
        buf.push_back(data, n);
    printf("put %d bytes data into buffer\n", n * k);
    printf("now, there are %d bytes in the buffer\n", buf.get_size());
    n = buf.get(large_data, 66, sizeof(large_data));
    printf("get %d bytes from offset 66\n", sizeof(large_data));
    printf("%.*s", n, large_data);
    printf("\n");

    n = buf.get_size();
    printf("print all the data(%d bytes):\n", n);
    pos = 0;
    while((n = buf.get(large_data, pos, sizeof(large_data))) > 0)
    {
        printf("%.*s", n, large_data);
        pos += n;
    }
    printf("\n");
    puts("===============================================");
}

void test_find()
{
    ffbuffer buf;
    char msg_found[] = "Hello, 你好\nFFBackup\n";
    char msg_not_found[] = "Linux Kernel";
    char msg_repeat[] = "pascal 语言";
    size_t index;
    bool found;

    puts("==================== test_find ==================");
    buf.push_back(msg_found, sizeof(msg_found));
    printf("put the following bytes to buffer(size = %d)\n", (int)buf.get_size());
    puts(msg_found);
    index = buf.find('\n', &found);
    printf("'\\n' ");
    if(found)
        printf("found, index = %ld\n", (long)index);
    else
        printf("not found, index = %ld\n", (long)index);
    puts("");
    buf.clear();

    buf.push_back(msg_not_found, sizeof(msg_not_found));
    printf("put the following bytes to buffer(size = %d)\n", (int)buf.get_size());
    puts(msg_not_found);
    index = buf.find('k', &found);
    printf("'k' ");
    if(found)
        printf("found, index = %ld\n", (long)index);
    else
        printf("not found, index = %ld\n", (long)index);

    puts("");
    buf.clear();
    for(int i = 0; i < 80; ++i)
        buf.push_back(msg_repeat, sizeof(msg_repeat));
    buf.push_back("GCC", 3);
    index = buf.find('C', &found);
    if(found)
        printf("'C' found, index = %ld\n", (long)index);
    else
        printf("'C' not found, index = %ld\n", (long)index);
    printf("index should be 1121\n");

    index = buf.find('\0', &found);
    if(found)
        printf("'\\0' found, index = %ld\n", (long)index);
    else
        printf("'\\0' not found, index = %ld\n", (long)index);
    printf("index should be 13\n");

    index = buf.find('z', &found);
    if(found)
        printf("'z' found, index = %ld\n", (long)index);
    else
        printf("'z' not found, index = %ld\n", (long)index);
    puts("=================================================");
}

int main()
{
    normal();
    put_some_small_data();
    put_many_data();
    random_read();
    test_find();
    return 0;
}
