#ifndef SERVER_H
#define SERVER_H

class connection
{
public:
    SSL *ssl;
    int sockfd;
    enum conn_state
    {state_accepting, state_read, state_write, state_close} state;
    char *buffer;
    int len;
    int pos;
};

class server_config
{
public:
    int max_connection;
};

#endif
