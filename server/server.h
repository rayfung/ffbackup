#ifndef SERVER_H
#define SERVER_H

#include "ffbuffer.h"

class connection
{
public:
    SSL *ssl;
    int sockfd;
    enum conn_state
    {state_accepting, state_read, state_write, state_close} state;
    ffbuffer buffer;
};

class server_config
{
public:
    int max_connection;
};

#endif
