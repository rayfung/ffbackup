#include <stdio.h>
#include <queue>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "ffprotocol.h"
#include "server.h"
#include "task.h"

extern connection *conns;

void read_task(int sockfd)
{
    connection *conn = &conns[sockfd];
    SSL *ssl = conn->ssl;
    int len = 0;
    int ret;
    char buffer[2048];

    if(!conn->processor.wait_for_readable())
        return;

    do
    {
        fprintf(stderr, "do-while in read_task(%d)\n", sockfd);
        ret = SSL_read(ssl, buffer, sizeof(buffer));
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                len = ret;
                break;
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
                return;
            default:
                conn->state = connection::state_close;
                return;
        }
        conn->in_buffer.push_back(buffer, len);
        conn->processor.update(conn);
        if(conn->state == connection::state_close)
            return;
    }while(SSL_pending(ssl));
}

void write_task(int sockfd)
{
    connection *conn = &conns[sockfd];
    SSL *ssl = conns[sockfd].ssl;
    int ret;
    int len;
    char buffer[1024];

    if(conn->processor.wait_for_writable())
        conn->processor.update(conn);
    if(conn->state == connection::state_close)
        return;

    len = conn->out_buffer.get_size();
    if(len == 0)
        return;

    fprintf(stderr, "write buffer size = %d\n", len);

    len = conn->out_buffer.get(buffer, 0, sizeof(buffer));
    ret = SSL_write(ssl, buffer, len);
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
            conn->state = connection::state_close;
            return;
    }
    conn->out_buffer.pop_front(len);
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
