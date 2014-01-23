#ifndef SERVER_H
#define SERVER_H

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include "ffbuffer.h"
#include "ffprotocol.h"

class connection
{
public:
    SSL *ssl;
    int sockfd;
    enum conn_state
    {
        state_accepting, state_close, state_processing
    } state;
    ffprotocol processor;
    ffbuffer in_buffer;
    ffbuffer out_buffer;
    struct timespec tcp_accept_time;
};

#endif
