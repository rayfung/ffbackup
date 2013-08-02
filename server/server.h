#ifndef SERVER_H
#define SERVER_H

#include "ffbuffer.h"

class connection
{
public:
    SSL *ssl;
    int sockfd;
    enum conn_state
    {
        state_accepting, state_close, state_done,
        state_recv_request_hdr, state_recv_request_body,
        state_recv_response_hdr, state_recv_response_body
    } state;
    int op;
    ffbuffer buffer;
};

class server_config
{
public:
    int max_connection;
};

#endif
