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

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define SSL_DFLT_PORT   "16903"

static const char *RESPONSE_TEMPLATE =
    "Your request: ";

extern char *optarg;
static BIO  *bio_err = NULL;
static int  verbose = 0;
static const char *password = "password";

static int  err_exit( const char * );
static int  ssl_err_exit( const char * );
static void sigpipe_handle( int );
static int  password_cb( char *, int, int, void * );
static int  tcp_listen(const char *host, const char *serv, socklen_t *len);
static void ssl_service( SSL *, int );

int main( int argc, char **argv )
{
    int c, sock_s;
    SSL_CTX *ctx;
    const SSL_METHOD *meth;
    char *certfile = NULL;
    char *keyfile = NULL;
    char *cafile = NULL;
    int tlsv1 = 0;
    const char *host = NULL;
    const char *port = SSL_DFLT_PORT;

    while( (c = getopt( argc, argv, "b:c:hk:e:p:P:Tv" )) != -1 )
    {
        switch( c )
        {
            case 'h':
                printf( "-T\t\tTLS v1 protocol\n" );
                printf( "-b <address>\tBind address\n" );
                printf( "-p <port>\tListen port number (default %s)\n", SSL_DFLT_PORT );
                printf( "-c <file>\tCA certificate file\n" );
                printf( "-e <file>\tCertificate file\n" );
                printf( "-k <file>\tPrivate key file (defaults to certificate file)\n" );
                printf( "-P <pwd>\tPassword for private key (defaults to 'password')\n" );
                printf( "-v\t\tVerbose\n" );
                exit(0);

            case 'b':   /* Address */
                if ( ! (host = strdup( optarg )) )
                    err_exit( "Invalid address specified" );
                break;

            case 'p':   /* Port */
                if ( ! (port = strdup( optarg )) )
                    err_exit( "Invalid port specified" );
                break;

            case 'e':   /* Certificate File */
                if ( ! (certfile = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;

            case 'c':   /* CA File */
                if ( ! (cafile = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;

            case 'k':   /* Private Key File */
                if ( ! (keyfile = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;

            case 'P':   /* Private Key Password */
                if ( ! (password = strdup( optarg )) )
                    err_exit( "Out of memory" );
                break;

            case 'T':  tlsv1 = 1;       break;
            case 'v':  verbose = 1;     break;
        }
    }

    if ( ! keyfile )  keyfile = certfile;   /* Default to certfile */

    /* Initialize SSL library */
    SSL_library_init();
    SSL_load_error_strings();

    /* Error message output */
    bio_err = BIO_new_fp( stderr, BIO_NOCLOSE );

    /* Set up a SIGPIPE handler */
    signal( SIGPIPE, sigpipe_handle );

    /* Create SSL context*/
    if ( tlsv1 )
        meth = TLSv1_method();
    else
        meth = SSLv23_method();

    ctx = SSL_CTX_new( meth );

    /* Load certificates */
    if ( certfile  &&  ! SSL_CTX_use_certificate_chain_file( ctx, certfile ) )
        ssl_err_exit( "Can't read certificate file" );

    if ( keyfile )
    {
        /* Set pass phrase callback routine */
        SSL_CTX_set_default_passwd_cb( ctx, password_cb );

        /* Load private key */
        if ( ! SSL_CTX_use_PrivateKey_file( ctx, keyfile, SSL_FILETYPE_PEM ) )
            ssl_err_exit( "Can't read key file" );
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if( cafile && !SSL_CTX_load_verify_locations(ctx, cafile, NULL))
        ssl_err_exit("Can't read CA file");

    sock_s = tcp_listen( host, port, NULL );

    while( 1 )
    {
        int sock_c;

        if ( (sock_c = accept( sock_s, 0, 0 )) < 0 )
            err_exit( "Problem accepting" );

        if ( fork() )
            close( sock_c );
        else
        {
            /* Associate SSL connection with client socket */
            BIO *sbio = BIO_new_socket( sock_c, BIO_NOCLOSE );
            SSL *ssl = SSL_new( ctx );

            SSL_set_bio( ssl, sbio, sbio );

            /* Perform SSL server accept handshake */
            if ( SSL_accept( ssl ) <= 0 )
                ssl_err_exit( "SSL accept error" );

            /* Verify server certificate */
            if ( SSL_get_verify_result( ssl ) != X509_V_OK )
                ssl_err_exit( "Certificate doesn't verify" );

            if ( ! SSL_get_peer_certificate( ssl ) )
                err_exit( "No peer certificate" );

            if ( verbose )
            {
                printf( "Cipher: %s\n", SSL_get_cipher( ssl ) );
            }

            ssl_service( ssl, sock_c );
            exit(0);
        }
    }

    /* Free SSL context */
    SSL_CTX_free( ctx );
    exit(0);
}

static int err_exit( const char *str )
{
    fprintf( stderr, "%s\n", str );
    exit(0);
}

static int ssl_err_exit( const char *str )
{
    BIO_printf( bio_err, "%s\n", str );
    ERR_print_errors( bio_err );
    exit(0);
}

static void sigpipe_handle( int x )
{
}

static int password_cb( char *buf, int num, int rwflag, void *userdata )
{
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
