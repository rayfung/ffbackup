#include <stdio.h>
#include <queue>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "server.h"
#include "task.h"

using namespace std;

extern connection *conns;

connection::conn_state read_task(int sockfd)
{
    SSL *ssl = conns[sockfd].ssl;
    int len = 0;
    int ret;
    char buffer[16];
    int i;

    fprintf(stderr, "entering read_task(%d)\n", sockfd);
    do
    {
        fprintf(stderr, "entering read_task(%d)::while\n", sockfd);
        ret = SSL_read(ssl, buffer, 16);
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                len = ret;
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                if(conns[sockfd].len > 0)
                {
                    conns[sockfd].pos = 0;
                    return connection::state_write;
                }
                else
                    return connection::state_read;
            default:
                return connection::state_close;
        }
        conns[sockfd].buffer = (char *)realloc(conns[sockfd].buffer, conns[sockfd].len + len);
        for(i = 0; i < len; ++i)
            conns[sockfd].buffer[conns[sockfd].len + i] = buffer[i];
        conns[sockfd].len += len;
    }while(SSL_pending(ssl));
    fprintf(stderr, "leaving read_task(%d)\n", sockfd);
    if(conns[sockfd].len > 0)
    {
        conns[sockfd].pos = 0;
        return connection::state_write;
    }
    else
        return connection::state_read;
}

connection::conn_state write_task(int sockfd)
{
    SSL *ssl = conns[sockfd].ssl;
    int ret;
    int len;
    fprintf(stderr, "entering write_task(%d)\n", sockfd);
    ret = SSL_write(ssl, conns[sockfd].buffer + conns[sockfd].pos, conns[sockfd].len);
    switch( SSL_get_error( ssl, ret ) )
    {
        case SSL_ERROR_NONE:
            len = ret;
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            len = 0;
            break;
        default:
            return connection::state_close;
    }
    conns[sockfd].pos += len;
    conns[sockfd].len -= len;
    if(conns[sockfd].len > 0)
        return connection::state_write;
    else
    {
        conns[sockfd].len = 0;
        return connection::state_read;
    }
}
#if 0
static void ssl_service( SSL *ssl, int sock_c )
{
    char ibuff[ 1024 ];
    char obuff[ 1024 ];
    int len, r;

    while(1)
    {
        r = SSL_read(ssl, ibuff, sizeof(ibuff) - 1);
        switch( SSL_get_error( ssl, r ) )
        {
            case SSL_ERROR_NONE:
                len = r;
                break;
            case SSL_ERROR_ZERO_RETURN:
                len = 0;
                break;
            default:
                ssl_err_exit( "SSL read problem" );
        }

        if(len == 0)
            break;

        ibuff[len] = '\0';
        snprintf(obuff, sizeof(obuff), "%s%s\r\n", RESPONSE_TEMPLATE, ibuff);
        r = SSL_write(ssl, obuff, strlen(obuff));
        switch( SSL_get_error( ssl, r ) )
        {
            case SSL_ERROR_NONE:
                len = r;
                break;
            default:
                ssl_err_exit( "SSL write problem" );
        }
    }

    r = SSL_shutdown( ssl );
    SSL_free( ssl );
    close( sock_c );
}
#endif
