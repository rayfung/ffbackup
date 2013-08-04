#include <stdio.h>
#include <string.h>
#include "ffbuffer.h"

ffchunk::ffchunk()
{
    this->size = 0;
    this->link = NULL;
}

ffbuffer::ffbuffer()
{
    this->head_ptr = this->tail_ptr = NULL;
    this->buffer_size = 0;
}

ffbuffer::~ffbuffer()
{
    this->clear();
}

void ffbuffer::print_chunk_info()
{
    ffchunk *ptr = this->head_ptr;
    int n = 1;
    while(ptr != NULL)
    {
        printf("chunk #%d: %d bytes\n", n, ptr->size);
        ++n;
        ptr = ptr->link;
    }
}

/* free all the memory used by this ffbuffer object */
void ffbuffer::clear()
{
    ffchunk *ptr = this->head_ptr;
    ffchunk *chunk_to_free;
    while(ptr != NULL)
    {
        chunk_to_free = ptr;
        ptr = ptr->link;
        delete chunk_to_free;
    }
    this->buffer_size = 0;
    this->head_ptr = NULL;
    this->tail_ptr = NULL;
}

/* return the bytes of all chunks */
size_t ffbuffer::get_size()
{
    return this->buffer_size;
}

/* insert the buffer data at the end of ffbuffer */
void ffbuffer::push_back(const void *buf, size_t size)
{
    size_t pos = 0;
    if(this->tail_ptr != NULL && this->tail_ptr->size < CHUNK_MAX_SIZE)
    {
        size_t n = CHUNK_MAX_SIZE - this->tail_ptr->size;
        if(n > size)
            n = size;
        memcpy(this->tail_ptr->data + this->tail_ptr->size, buf, n);
        this->tail_ptr->size += n;
        this->buffer_size += n;
        pos += n;
    }
    for(; pos < size; pos += CHUNK_MAX_SIZE)
    {
        ffchunk *chunk = new ffchunk();
        size_t n = CHUNK_MAX_SIZE;

        if(pos + n > size)
            n = size - pos;
        memcpy(chunk->data, (unsigned char *)buf + pos, n);
        chunk->size = n;
        if(this->head_ptr == NULL)
            this->head_ptr = this->tail_ptr = chunk;
        else
        {
            this->tail_ptr->link = chunk;
            this->tail_ptr = chunk;
        }
        this->buffer_size += chunk->size;
    }
}

/* delete first size bytes of the ffbuffer */
void ffbuffer::pop_front(size_t size)
{
    ffchunk *to_be_free;
    if(size >= this->buffer_size)
    {
        this->clear();
        return;
    }
    this->buffer_size -= size;
    while(size > 0 && this->head_ptr != NULL)
    {
        if(size >= this->head_ptr->size)
        {
            size -= this->head_ptr->size;
            to_be_free = this->head_ptr;
            this->head_ptr = this->head_ptr->link;
            delete to_be_free;
        }
        else
        {
            memmove(this->head_ptr->data,
                    this->head_ptr->data + size,
                    this->head_ptr->size - size);
            this->head_ptr->size -= size;
            size = 0;
        }
    }
    if(this->head_ptr == NULL)
        this->tail_ptr = NULL;
}

/**
 * get size bytes data from offset pos,
 * there are at least size bytes memory available in buf
 *
 * @return the bytes that are copied into buf,
 *         it may be smaller than `size`
 */
size_t ffbuffer::get(void *buf, size_t pos, size_t size)
{
    ffchunk *ptr;
    size_t i; /* iterator of buf */
    if(pos >= this->buffer_size)
        return 0;
    if(pos + size > this->buffer_size)
        size = this->buffer_size - pos;
    ptr = this->head_ptr;
    i = 0;
    while(pos > 0)
    {
        if(pos >= ptr->size)
        {
            pos -= ptr->size;
            ptr = ptr->link;
        }
        else
        {
            size_t n = ptr->size - pos;
            if(n > size)
                n = size;
            memcpy((unsigned char *)buf + i, ptr->data + pos, n);
            ptr = ptr->link;
            i += n;
            break;
        }
    }
    while(i < size)
    {
        size_t n = ptr->size;
        if(n > size - i)
            n = size - i;
        memcpy((unsigned char *)buf + i, ptr->data, n);
        i += n;
        ptr = ptr->link;
    }
    return size;
}
