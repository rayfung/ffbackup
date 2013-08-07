#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <assert.h>

#include "ffprotocol.h"
#include "server.h"
#include "task.h"
#include "ffbuffer.h"
#include "config.h"

extern char *optarg;
static BIO  *bio_err = NULL;

static int  ssl_err_exit( const char * );
static void sigpipe_handle( int );
static int  password_cb( char *, int, int, void * );
static int  tcp_listen(const char *host, const char *serv, socklen_t *len);

server_config server_cfg;
connection *conns;

static void set_nonblocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

SSL_CTX *init_ssl(int argc, char **argv)
{
    SSL_CTX *ctx;
    const SSL_METHOD *meth;

    /* Initialize SSL library */
    SSL_library_init();
    SSL_load_error_strings();

    /* Error message output */
    bio_err = BIO_new_fp( stderr, BIO_NOCLOSE );

    /* Set up a SIGPIPE handler */
    signal( SIGPIPE, sigpipe_handle );

    /* Create SSL context*/
    if ( server_cfg.get_protocol() == server_config::tlsv1 )
        meth = TLSv1_method();
    else
        meth = SSLv23_method();

    ctx = SSL_CTX_new( meth );

    /* Load certificates */
    if ( ! SSL_CTX_use_certificate_chain_file( ctx, server_cfg.get_cert_file() ) )
        ssl_err_exit( "Can't read certificate file" );

    /* Set pass phrase callback routine */
    SSL_CTX_set_default_passwd_cb( ctx, password_cb );

    /* Load private key */
    if ( ! SSL_CTX_use_PrivateKey_file( ctx, server_cfg.get_key_file(), SSL_FILETYPE_PEM ) )
        ssl_err_exit( "Can't read key file" );

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if( !SSL_CTX_load_verify_locations(ctx, server_cfg.get_ca_file(), NULL))
        ssl_err_exit("Can't read CA file");

    /* make it possible to retry SSL_write() with different buffer
     * which contains the same content */
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    return ctx;
}

connection::conn_state ssl_accept_then_verify(SSL *ssl)
{
    int r;
    /* Perform SSL server accept handshake */
    r = SSL_accept( ssl );
    switch( SSL_get_error(ssl, r) )
    {
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return connection::state_accepting;
        default:
            return connection::state_close;
    }

    /* Verify server certificate */
    if ( SSL_get_verify_result( ssl ) != X509_V_OK ||
            ! SSL_get_peer_certificate( ssl ) )
        return connection::state_close;
    else
        return connection::state_processing;
}

void clean_up_connection(int sockfd)
{
    fprintf(stderr, "clean_up_connection(%d)\n", sockfd);
    conns[sockfd].sockfd = -1;
    SSL_shutdown(conns[sockfd].ssl);
    close(sockfd);
    SSL_free(conns[sockfd].ssl);
    conns[sockfd].processor.reset();
    conns[sockfd].in_buffer.clear();
    conns[sockfd].out_buffer.clear();
}

void main_loop(SSL_CTX *ctx, int sock_s)
{
    fd_set rset_bak;
    fd_set wset_bak;
    fd_set rset;
    fd_set wset;
    int maxfd;
    int temp;

    FD_ZERO(&rset_bak);
    FD_ZERO(&wset_bak);
    FD_SET(sock_s, &rset_bak);
    maxfd = sock_s;
    while( 1 )
    {
        int sock_c;
        int n;

        rset = rset_bak;
        wset = wset_bak;
        n = select(maxfd + 1, &rset, &wset, NULL, NULL);
        if(n <= 0)
            continue;

        temp = maxfd;
        if(FD_ISSET(sock_s, &rset))
        {
            --n;
            FD_CLR(sock_s, &rset);
            while(1)
            {
                if ( (sock_c = accept( sock_s, NULL, NULL )) < 0 )
                    break;
                if(sock_c >= server_cfg.get_max_connection())
                {
                    close(sock_c);
                    break;
                }

                set_nonblocking(sock_c);

                /* Associate SSL connection with client socket */
                BIO *sbio = BIO_new_socket( sock_c, BIO_NOCLOSE );
                SSL *ssl = SSL_new( ctx );

                SSL_set_bio( ssl, sbio, sbio );

                conns[sock_c].sockfd = sock_c;
                conns[sock_c].ssl = ssl;
                conns[sock_c].state = ssl_accept_then_verify(ssl);
                conns[sock_c].processor.reset();
                conns[sock_c].in_buffer.clear();
                conns[sock_c].out_buffer.clear();
                if(conns[sock_c].state == connection::state_close)
                {
                    clean_up_connection(sock_c);
                    fprintf(stderr, "failed to accept or verify\n");
                }
                else
                {
                    FD_SET(sock_c, &rset_bak);
                    if(sock_c > temp)
                        temp = sock_c;
                }
            }
        }

        /* accepted sockfd */
        for(int i = 0; i <= maxfd && n > 0; ++i)
        {
            bool r_ok = false, w_ok = false;
            if(FD_ISSET(i, &rset))
            {
                --n;
                r_ok = true;
            }
            if(FD_ISSET(i, &wset))
            {
                --n;
                w_ok = true;
            }

            if(r_ok || w_ok)
            {
                if(conns[i].state == connection::state_accepting)
                {
                    conns[i].state = ssl_accept_then_verify(conns[i].ssl);
                    if(conns[i].state == connection::state_processing)
                        fprintf(stderr, "accepted, %d r=%d w=%d\n\n", i, (int)r_ok, (int)w_ok);
                }
                else if(conns[i].state == connection::state_processing)
                {
                    if(r_ok)
                        read_task(i);
                    if(w_ok)
                        write_task(i);

                    /* 避免频繁地被暂时不关注的事件触发，造成CPU资源的浪费 */
                    if(conns[i].out_buffer.get_size() > 0 ||
                            conns[i].processor.wait_for_writable())
                        FD_SET(i, &wset_bak);
                    else
                        FD_CLR(i, &wset_bak);
                    if(conns[i].processor.wait_for_readable())
                        FD_SET(i, &rset_bak);
                    else
                        FD_CLR(i, &rset_bak);
                }

                if(conns[i].state == connection::state_close)
                {
                    clean_up_connection(i);
                    FD_CLR(i, &rset_bak);
                    FD_CLR(i, &wset_bak);
                    fprintf(stderr, "close, %d r=%d w=%d\n\n", i, (int)r_ok, (int)w_ok);
                }
            }
        }
        maxfd = temp;
    }
}

int main( int argc, char **argv )
{
    int sock_s;
    SSL_CTX *ctx;

    conns = new connection[server_cfg.get_max_connection()];
    assert(conns != NULL);
    for(int i = 0; i < server_cfg.get_max_connection(); ++i)
        conns[i].sockfd = -1;

    ctx = init_ssl(argc, argv);
    sock_s = tcp_listen( server_cfg.get_host(), server_cfg.get_service(), NULL );
    if(sock_s < 0)
        exit(EXIT_FAILURE);

    set_nonblocking(sock_s);

    main_loop(ctx, sock_s);

    /* Free SSL context */
    SSL_CTX_free( ctx );
    delete[] conns;
    exit(0);
}

static int ssl_err_exit( const char *str )
{
    BIO_printf( bio_err, "%s\n", str );
    ERR_print_errors( bio_err );
    exit(EXIT_FAILURE);
}

static void sigpipe_handle( int x )
{
}

static int password_cb( char *buf, int num, int rwflag, void *userdata )
{
    const char *password = server_cfg.get_key_file_password();
    int len = strlen( password );

    if ( num < len + 1 )
        len = 0;
    else
        strcpy( buf, password );

    return( len );
}

/**
 * create a new socket and bind to host:serv, finally listen()
 * this function also set the SO_REUSEADDR socket option
 *
 * len: the length of address is returned
 * via this parameter after the call (if len is not NULL)
 *
 * On success, a file descriptor for the new socket is returned
 * On error, -1 is returned
 */
int tcp_listen(const char *host, const char *serv, socklen_t *len)
{
    struct addrinfo *res, *saved, hints;
    int n, listenfd;
    const int on = 1;

    bzero(&hints, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    n = getaddrinfo(host, serv, &hints, &res);
    if(n != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(n));
        return -1;
    }
    saved = res;
    while(res)
    {
        listenfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if(listenfd >= 0)
        {
            if(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
                perror("setsockopt");
            if(bind(listenfd, res->ai_addr, res->ai_addrlen) == 0)
            {
                if(listen(listenfd, 128) == 0)
                    break;
            }
            close(listenfd);
        }
        res = res->ai_next;
    }
    if(res == NULL)
    {
        perror("tcp_listen");
        freeaddrinfo(saved);
        return -1;
    }
    else
    {
        if(len)
            *len = res->ai_addrlen;
        freeaddrinfo(saved);
        return listenfd;
    }
}
