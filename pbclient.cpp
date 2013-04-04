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

#define	SSL_DFLT_HOST  "localhost"
#define	SSL_DFLT_PORT  "16903"

extern char	*optarg;
static BIO	*bio_err = 0;
static int	verbose = 0;

static const char *REQUEST_TEMPLATE =
	"SSL Echo Client: openssl\r\n"
	"BEGIN\r\n"
	"SSL Client/Server Echo Test\r\n"
	"Host: %s:%d\r\n"
	"END\r\n";

static int	err_exit( const char * );
static int	ssl_err_exit( const char * );
static void	sigpipe_handle( int );
static int	ip_connect(int type, int protocol, const char *host, const char *serv);
static void	check_certificate( SSL *, int );
static void	client_request( SSL *, const char *, int );
static void	hexdump( char *, int );

int main( int argc, char **argv )
{
	int c, sock;
	SSL_CTX *ctx;
	const SSL_METHOD *meth;
	SSL *ssl;
	BIO *sbio;
	char *cafile = NULL;
	char *cadir = NULL;
	char *certfile = NULL;
	char *keyfile = NULL;
	const char *host = SSL_DFLT_HOST;
	const char *port = SSL_DFLT_PORT;
	int tlsv1 = 0;

	while( (c = getopt( argc, argv, "c:e:k:d:hp:t:Tv" )) != -1 )
	{
		switch(c)
		{
			case 'h':
				printf( "-T\t\tTLS v1 protocol\n" );
				printf( "-t <host>\tTarget host name (default 'localhost')\n" );
				printf( "-p <port>\tTarget port number (default 16903)\n" );
				printf( "-c <file>\tCA certificate file\n" );
				printf( "-e <file>\tCertificate file\n" );
				printf( "-k <file>\tPrivate key file\n" );
				printf( "-d <dir>\tCA certificate directory\n" );
				printf( "-v\t\tVerbose\n" );
				exit(0);

			case 't':
				if ( ! (host = strdup( optarg )) )
					err_exit( "Out of memory" );
				break;

			case 'p':
				if ( ! (port = strdup( optarg )) )
					err_exit( "Invalid port specified" );
				break;

			case 'd':
				if ( ! (cadir = strdup( optarg )) )
					err_exit( "Out of memory" );
				break;

			case 'c':
				if ( ! (cafile = strdup( optarg )) )
					err_exit( "Out of memory" );
				break;

			case 'e':	/* Certificate File */
				if ( ! (certfile = strdup( optarg )) )
					err_exit( "Out of memory" );
				break;

			case 'k':
				if ( ! (keyfile = strdup( optarg )) )
					err_exit( "Out of memory" );
				break;

			case 'T':  tlsv1 = 1;		break;
			case 'v':  verbose = 1;		break;
		}
	}

	/* Initialize SSL Library */
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

	/* Load the CAs we trust*/
	if ( (cafile || cadir)  &&
			! SSL_CTX_load_verify_locations( ctx, cafile, cadir ) )
		ssl_err_exit( "Can't read CA list" );

	/* Load certificates */
	if ( certfile && ! SSL_CTX_use_certificate_chain_file( ctx, certfile ) )
		ssl_err_exit( "Can't read certificate file" );

	if ( keyfile )
	{
		printf("load key file %s\n", keyfile);
		/* Load private key */
		if ( ! SSL_CTX_use_PrivateKey_file( ctx, keyfile, SSL_FILETYPE_PEM ) )
			ssl_err_exit( "Can't read key file" );
	}

	sock = ip_connect( SOCK_STREAM, IPPROTO_TCP, host, port );

	/* Associate SSL connection with server socket */
	ssl = SSL_new( ctx );
	sbio = BIO_new_socket( sock, BIO_NOCLOSE );
	SSL_set_bio( ssl, sbio, sbio );

	if ( verbose )
	{
		const char *str;
		int i;

		printf( "Ciphers: \n" );

		for( i = 0; (str = SSL_get_cipher_list( ssl, i )); i++ )
			printf( "    %s\n", str );
	}

	/* Perform SSL client connect handshake */
	if ( SSL_connect( ssl ) <= 0 )
		ssl_err_exit( "SSL connect error" );

	check_certificate( ssl, 1 );

	if ( verbose )
		printf( "Cipher: %s\n", SSL_get_cipher( ssl ) );

	/* Now make our request */
	client_request( ssl, host, atoi(port) );

	/* Shutdown SSL connection */
	if( SSL_shutdown( ssl ) != 1 )
		ssl_err_exit( "Shutdown failed" );

	SSL_free( ssl );
	SSL_CTX_free(ctx);
	close( sock );

	exit(0);
}

static int err_exit( const char *string )
{
	fprintf( stderr, "%s\n", string );
	exit(0);
}

static int ssl_err_exit( const char *string )
{
	BIO_printf( bio_err, "%s\n", string );
	ERR_print_errors( bio_err );
	exit(0);
}

static void sigpipe_handle( int x )
{
}

/**
 * create a socket
 * and connect to host:serv (TCP)
 * or set the default destination host:serv (UDP)
 *
 * type: SOCK_STREAM or SOCK_DGRAM
 * protocol: IPPROTO_TCP or IPPROTO_UDP
 * host: host name of remote host
 * serv: service name
 *
 * On success, a file descriptor for the new socket is returned
 * On error, -1 is returned
 */
static int ip_connect(int type, int protocol, const char *host, const char *serv)
{
    struct addrinfo hints, *res, *saved;
    int n, sockfd;

    bzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = type;
    hints.ai_protocol = protocol;
    n = getaddrinfo(host, serv, &hints, &res);
    if(n != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(n));
        return -1;
    }
    saved = res;
    while(res)
    {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if(sockfd >= 0)
        {
            if(connect(sockfd, res->ai_addr, res->ai_addrlen) == 0)
                break;
        }
        res = res->ai_next;
    }
    if(res == NULL)
    {
        perror("ip_connect");
        sockfd = -1;
    }
    freeaddrinfo(saved);
    return sockfd;
}

static void check_certificate( SSL *ssl, int required )
{
	X509 *peer;

	/* Verify server certificate */
	if ( SSL_get_verify_result( ssl ) != X509_V_OK )
		ssl_err_exit( "Certificate doesn't verify" );

	/* Check the common name */
	peer = SSL_get_peer_certificate( ssl );

	if ( ! peer  &&  required )
		err_exit( "No peer certificate" );
}

static void client_request( SSL *ssl, const char *host, int port )
{
	BIO *io, *ssl_bio;
	char buf[ 1024 ];
	int r, len;
	int echo = 0;

	/* Now construct our request */
	snprintf( buf, sizeof( buf ), REQUEST_TEMPLATE, host, port );
	len = strlen( buf );

	/* Send request to server */
	if ( verbose )
	{
		printf( "Sending %d bytes: \n", len );
		hexdump( buf, len );
	}

	r = SSL_write( ssl, buf, len );

	switch( SSL_get_error( ssl, r ) )
	{
		case SSL_ERROR_NONE:
			if ( len != r )
				err_exit("Incomplete write!");
			break;

		default:
			ssl_err_exit( "SSL write problem" );
	}

	/* Setup SSL buffers for reading server socket */
	io = BIO_new( BIO_f_buffer() );
	ssl_bio = BIO_new( BIO_f_ssl() );
	BIO_set_ssl( ssl_bio, ssl, BIO_CLOSE );
	BIO_push( io, ssl_bio );

	while(1)
	{
		/* Read a line from server socket */
		r = BIO_gets( io, buf, sizeof( buf ) - 1 );

		switch( SSL_get_error( ssl, r ) )
		{
			case SSL_ERROR_NONE:
				len = r;
				break;
			case SSL_ERROR_ZERO_RETURN:
				return;
			case SSL_ERROR_SYSCALL:
				ssl_err_exit( "SSL Error: Premature close" );
			default:
				ssl_err_exit( "SSL read problem" );
		}

		if ( verbose )
		{
			printf( "Received %d: \n", len );
			hexdump( buf, len );
		}

		/*
		 ** Display response between 'BEGIN' and 'END'
		 */
		if ( ! echo )
		{
			/* Echo starts with 'BEGIN' */
			if ( ! strcmp( buf, "BEGIN\r\n" ) || ! strcmp( buf, "BEGIN\n" ) )
				echo = 1;
		}
		else
		{
			/* Echo finishes with 'END' */
			if ( ! strcmp( buf, "END\r\n" )  ||  ! strcmp( buf, "END\n" ) )
				break;

			fwrite( buf, 1, len, stdout );
		}
	}

	/*
	 ** Skip any additional response until done.
	 */
	while(1)
	{
		/* Read a line from server socket */
		r = BIO_gets( io, buf, sizeof( buf ) - 1 );

		switch( SSL_get_error( ssl, r ) )
		{
			case SSL_ERROR_NONE:
				len = r;
				break;
			case SSL_ERROR_ZERO_RETURN:
				return;
			case SSL_ERROR_SYSCALL:
				ssl_err_exit( "SSL Error: Premature close" );
			default:
				ssl_err_exit( "SSL read problem" );
		}

		if ( verbose )
		{
			printf( "Received %d (extra) bytes: \n", len );
			hexdump( buf, len );
		}
	}
}

static void hexdump( char *buffer, int length )
{
	int		cnt, idx;
	const char *digits = "0123456789ABCDEF";
	char	line[ 100 ];

	for( idx = 0; length; length -= cnt, buffer += cnt, idx += cnt )
	{
		char *ptr;
		int  i;

		cnt = (length > 16) ? 16 : length;

		sprintf( line, "%4.4x: ", idx );
		ptr = line + 6;

		for( i = 0; i < cnt; i++ )
		{
			*ptr++ = digits[ buffer[i] >> 4 ];
			*ptr++ = digits[ buffer[i] & 0x0f ];
			*ptr++ = (i == 7) ? ':' : ' ';
		}

		for( ; i < 16; i++ )
		{
			*ptr++ = ' ';
			*ptr++ = ' ';
			*ptr++ = ' ';
		}

		*ptr++ = ' ';

		for( i = 0; i < cnt; i++ )
			if ( buffer[i] < 32  ||  buffer[i] > 126 )
				*ptr++ = '.';
			else
				*ptr++ = buffer[i];

		*ptr = 0;
		printf( "%s\n", line );
	}
}
