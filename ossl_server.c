/*
 ** Demo SSL Echo Server
 **
 ** Establishes an SSL listen port.  Reads client text lines 
 ** and responds with server header and echo's client request 
 ** between lines 'BEGIN' and 'END' (inclusive).
 **
 ** Arguments:
 **	-T		TLS v1 protocol
 **	-p <port>	Listen port number (default 16903)
 **	-c <file>	Server certificate file
 **	-k <file>	Server key file (defaults to certificate file)
 **	-P <pwd>	Password for private key (defaults to 'password')
 **	-V		Verbose
 **	-h		Help
 **
 ** Derived from an example SSL server:
 **   Created by Eric Rescorla, January 10, 2002
 **   http://www.rtfm.com/openssl-examples/
 **   Copyright (C) 2001 RTFM, Inc.
 */

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

#define	SSL_DFLT_PORT	16903

static char	*RESPONSE_TEMPLATE =
	"SSL Echo Server: openssl\r\n";

extern char	*optarg;
static BIO	*bio_err = NULL;
static char	*password = "password";
static int	verbose = 0;

static int	err_exit( char * );
static int	ssl_err_exit( char * );
static void	sigpipe_handle( int );
static int	password_cb( char *, int, int, void * );
static int	tcp_listen( int );
static void	ssl_service( SSL *, int );
static void	hexdump( char *, int );

int main( int argc, char **argv )
{
	int c, sock_s;
	SSL_CTX *ctx;
	const SSL_METHOD *meth;
	char *certfile = NULL;
	char *keyfile = NULL;
	int tlsv1 = 0;
	int port = SSL_DFLT_PORT;

	while( (c = getopt( argc, argv, "c:hk:p:P:TV" )) != -1 )
	{
		switch( c )
		{
			case 'h':
				printf( "-T\t\tTLS v1 protocol\n" );
				printf( "-p <port>\tListen port number (default %d)\n", SSL_DFLT_PORT );
				printf( "-c <file>\tServer certificate file\n" );
				printf( "-k <file>\tServer key file (defaults to certificate file)\n" );
				printf( "-P <pwd>\tPassword for private key (defaults to 'password')\n" );
				printf( "-V\t\tVerbose\n" );
				exit(0);

			case 'p':	/* Port */
				if ( ! (port = atoi( optarg )) )
					err_exit( "Invalid port specified" );
				break;

			case 'c':	/* Certificate File */
				if ( ! (certfile = strdup( optarg )) )
					err_exit( "Out of memory" );
				break;

			case 'k':	/* Private Key File */
				if ( ! (keyfile = strdup( optarg )) )
					err_exit( "Out of memory" );
				break;

			case 'P':	/* Private Key Password */
				if ( ! (password = strdup( optarg )) )
					err_exit( "Out of memory" );
				break;

			case 'T':  tlsv1 = 1;		break;
			case 'V':  verbose = 1;		break;
		}
	}

	if ( ! keyfile )  keyfile = certfile;	/* Default to certfile */

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

	sock_s = tcp_listen( port );

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

static int err_exit( char *str )
{
	fprintf( stderr, "%s\n", str );
	exit(0);
}

static int ssl_err_exit( char *str )
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

static int tcp_listen( int port )
{
	struct sockaddr_in sin;
	int sock;
	int val = 1;

	if ( (sock = socket( AF_INET, SOCK_STREAM, 0 )) < 0 )
		err_exit( "Couldn't create socket" );

	memset( &sin, 0, sizeof( sin ) );
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_family = AF_INET;
	sin.sin_port = htons( port );
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof( val ) );

	if ( bind( sock, (struct sockaddr *)&sin, sizeof( sin ) ) < 0 )
		err_exit( "Couldn't bind socket to port" );

	listen( sock, 5 );  
	return( sock );
}

static void ssl_service( SSL *ssl, int sock_c )
{
	BIO *io,*ssl_bio;
	char ibuff[ 1024 ];
#ifdef BUFFER_RESPONSE
	char obuff[ 1024 ];
#endif
	int len, r;
	int echo = 0;

	/* Setup SSL buffers for reading client socket */
	io = BIO_new( BIO_f_buffer() );
	ssl_bio = BIO_new( BIO_f_ssl() );
	BIO_set_ssl( ssl_bio, ssl, BIO_CLOSE );
	BIO_push( io, ssl_bio );

	while(1)
	{
		/* Read a line from client socket */
		r = BIO_gets( io, ibuff, sizeof( ibuff ) - 1 );

		switch( SSL_get_error( ssl, r ) )
		{
			case SSL_ERROR_NONE:
				len = r;
				break;
			default:
				ssl_err_exit( "SSL read problem" );
		}

		if ( verbose )
		{
			printf( "Received %d bytes: \n", len );
			hexdump( ibuff, len );
		}

		if ( ! echo )
		{
			/* Echo client text starting with 'BEGIN' */
			if ( ! strcmp(ibuff, "BEGIN\r\n")  ||  ! strcmp(ibuff, "BEGIN\n") )
			{
				/* Initiate server response */
#ifdef BUFFER_RESPONSE
				sprintf( obuff, RESPONSE_TEMPLATE );
#else
				if ( verbose )
				{
					int len = strlen( RESPONSE_TEMPLATE );
					printf( "Sending %d bytes: \n", len );
					hexdump( RESPONSE_TEMPLATE, len );
				}

				if ( BIO_puts( io, RESPONSE_TEMPLATE ) <= 0 )
					ssl_err_exit( "Write error" );
#endif
				echo = 1;
			}
		}

		if ( echo )
		{
			/* Echo client text back to client */
#ifdef BUFFER_RESPONSE
			strcat( obuff, ibuff );
#else
			if ( verbose )
			{
				int len = strlen( ibuff );
				printf( "Sending %d bytes: \n", len );
				hexdump( ibuff, len );
			}

			if ( BIO_puts( io, ibuff ) <= 0 )
				ssl_err_exit( "Write error" );
#endif

			/* Echo ends when 'END' is received */
			if ( ! strcmp( ibuff, "END\r\n" )  || ! strcmp( ibuff, "END\n" ) )
				break;
		}
	}

#if BUFFER_RESPONSE
	/* Send message back to client */
	if ( verbose )
	{
		int len = strlen( obuff );
		printf( "Sending %d bytes: \n", len );
		hexdump( obuff, len );
	}

	if ( BIO_puts( io, obuff ) <= 0 )
		ssl_err_exit( "Write error" );
#endif

	/* Make sure client output has been flushed */
	if ( BIO_flush( io ) < 0 )
		ssl_err_exit( "Error flushing BIO" );

	/* Terminate SSL connection */
	if ( ! (r = SSL_shutdown( ssl )) )
	{
		/*
		 ** If we called SSL_shutdown() first, we always get
		 ** return value of '0'. In this case, try again, but
		 ** first send a TCP FIN to trigger the other side's
		 ** close_notify.
		 */
		shutdown( sock_c, 1 );
		r = SSL_shutdown( ssl );
	}

	switch(r)
	{
		case 1:
		case 0:	/* Success */	break;

		case -1:
		default:	ssl_err_exit( "Shutdown failed" );
	}

	SSL_free( ssl );
	close( sock_c );
}

static void hexdump( char *buffer, int length )
{
	int		cnt, idx;
	char	*digits = "0123456789ABCDEF";
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
