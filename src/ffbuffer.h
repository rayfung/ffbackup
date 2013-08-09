#ifndef FFBUFFER_H
#define FFBUFFER_H

#define CHUNK_MAX_SIZE 64

#include <sys/types.h>

class ffchunk
{
public:
    ffchunk();

public:
    size_t size; /* the size of data stored in the chunk */
    unsigned char data[CHUNK_MAX_SIZE];
    ffchunk *link;
};

class ffbuffer
{
public:
    ffbuffer();
    ~ffbuffer();
    size_t get_size();
    void push_back(const void *buf, size_t size);
    void pop_front(size_t size);
    size_t get(void *buf, size_t pos, size_t size);
    void clear();
    void print_chunk_info();
    size_t find(unsigned char ch, bool *found);
    unsigned char at(size_t index);

private:
    size_t buffer_size;
    ffchunk *head_ptr;
    ffchunk *tail_ptr;
};

#endif
