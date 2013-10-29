#include <stdio.h>
#include <queue>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "ffprotocol.h"
#include "server.h"
#include "task.h"

extern connection *conns;

/* 从 SSL 缓冲区读取数据并处理 */
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

/* 处理数据之后再将应用缓冲区中的数据发送出去 */
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
