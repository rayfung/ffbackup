/*
** Demo SSL Echo Server
**
** Establishes an SSL listen port.  Reads client text lines 
** and responds with server header and echo's client request 
** between lines 'BEGIN' and 'END' (inclusive).
**
** Arguments:
**	-T		TLS v1 protocol
**	-S		SSL v2 protocol
**	-p <port>	Listen port number (default 16903)
**	-g		Generate private key & certificate
**	-c <file>	Server certificate file
**	-k <file>	Server key file (defaults to certificate file)
**	-P <pwd>	Password for private key (defaults to 'password')
**	-d <file>	DH parameter file (enables anonymous ciphers)
**	-a		Enable anonymous (no certificate) ciphers
**	-n		Enable null (no encryption) ciphers
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
#include <openssl/err.h>
#include <openssl/rand.h>

#define	SSL_DFLT_PORT	16903

#define SUB_COUNTRY	"US"
#define	SUB_ST_PROV	"California"
#define	SUB_LOCAL	"Redwood City"
#define	SUB_ORG		"Actian Corporation"
#define	SUB_UNIT	"Development"
#define	SUB_COMMON	"GCF-SSL"

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
static void	generate_certificate( SSL_CTX * );
static void	load_dh_params( SSL_CTX *, char * );
static int	tcp_listen( int );
static void	ssl_service( SSL *, int );
static void	hexdump( char *, int );

int 
main( int argc, char **argv )
{
    int c, sock_s;
    SSL_CTX *ctx;
    const SSL_METHOD *meth;
    char *certfile = NULL;
    char *keyfile = NULL;
    char *dhpfile = NULL;
    int tlsv1 = 0;
    int sslv2 = 0;
    int generate = 0;
    int anonCipher = 0;
    int nullCipher = 0;
    int certificate = 0;
    int port = SSL_DFLT_PORT;
    
    while( (c = getopt( argc, argv, "ac:d:ghk:np:P:STV" )) != -1 )
	switch( c )
	{
	case 'h':
	    printf( "-T\t\tTLS v1 protocol\n" );
	    printf( "-S\t\tSSL v2 protocol\n" );
	    printf( "-p <port>\tListen port number (default %d)\n", SSL_DFLT_PORT );
	    printf( "-g\t\tGenerate private key and certificate\n" );
            printf( "-c <file>\tServer certificate file\n" );
	    printf( "-k <file>\tServer key file (defaults to certificate file)\n" );
	    printf( "-P <pwd>\tPassword for private key (defaults to 'password')\n" );
	    printf( "-d <file>\tDH parameter file (enables anonymous ciphers)\n" );
	    printf( "-a\t\tEnable anonymous (no certificate) ciphers\n" );
	    printf( "-n\t\tEnable null (no encryption) ciphers\n" );
	    printf( "-V\t\tVerbose\n" );
	    exit(0);

	case 'p':	/* Port */
            if ( ! (port = atoi( optarg )) )
		err_exit( "Invalid port specified" );
            break;

	case 'g':	/* Generate Certificate */
	    generate = 1;
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

	case 'd':	/* DH Param File */
            if ( ! (dhpfile = strdup( optarg )) )
		err_exit( "Out of memory" );
	    break;

	case 'T':  tlsv1 = 1;		break;
	case 'S':  sslv2 = 1;		break;
	case 'a':  anonCipher = 1;	break;
	case 'n':  nullCipher = 1;	break;
	case 'V':  verbose = 1;		break;
	}

    if ( tlsv1  &&  sslv2 )
	err_exit( "Both -T and -S defined" );

    if ( certfile  ||  generate )  certificate = 1;
    if ( ! keyfile )  keyfile = certfile;	/* Default to certfile */
    if ( dhpfile )  anonCipher = 1;		/* Need anonymous ciphers */
    if ( certfile )  generate = 0;		/* Use provided certificate */
    if ( nullCipher  &&  ! certificate )	/* Need certificate */
	generate = 1;

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
    else  if ( sslv2 )
	meth = NULL /* SSLv2_method() */ ;
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

    /* Enable additional ciphers as needed */
    if ( anonCipher )
    {
	if ( nullCipher )
	{
	    if ( certificate )
	    {
		if ( SSL_CTX_set_cipher_list( ctx, "ALL:eNULL" ) <= 0 )
		    ssl_err_exit( "SSL cipher list error" );
	    }
	    else
	    {
		if ( SSL_CTX_set_cipher_list( ctx, "aNULL:eNULL" ) <= 0 )
		    ssl_err_exit( "SSL cipher list error" );
	    }
	}
	else  if ( certificate )
	{
	    if ( SSL_CTX_set_cipher_list( ctx, "ALL" ) <= 0 )
		ssl_err_exit( "SSL cipher list error" );
	}
	else
	{
	    if ( SSL_CTX_set_cipher_list( ctx, "aNULL" ) <= 0 )
		ssl_err_exit( "SSL cipher list error" );
	}
    }
    else  if ( nullCipher )
    {
	if ( certificate )
	{
	    if ( SSL_CTX_set_cipher_list( ctx, "ALL:!aNULL:eNULL" ) <= 0 )
		ssl_err_exit( "SSL cipher list error" );
	}
	else
	{
	    if ( SSL_CTX_set_cipher_list( ctx, "eNULL" ) <= 0 )
		ssl_err_exit( "SSL cipher list error" );
	}
    }

    if ( generate )  generate_certificate( ctx );
    if ( anonCipher )  load_dh_params( ctx, dhpfile );

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

static int 
err_exit( char *str )
{
    fprintf( stderr, "%s\n", str );
    exit(0);
}

static int 
ssl_err_exit( char *str )
{
    BIO_printf( bio_err, "%s\n", str );
    ERR_print_errors( bio_err );
    exit(0);
}

static void 
sigpipe_handle( int x )
{
}

static int 
password_cb( char *buf, int num, int rwflag, void *userdata )
{
    int len = strlen( password );

    if ( num < len + 1 )
	len = 0;
    else
	strcpy( buf, password );

    return( len );
}

static void 
generate_certificate( SSL_CTX *ctx )
{
    RSA			*rsa = NULL;
    X509		*x509ss = NULL;
    EVP_PKEY		*prikey = NULL;
    X509_REQ		*x509rq = NULL;
    ASN1_INTEGER	*serial = NULL;
    EVP_PKEY		*pubkey = NULL;

    /* Make sure random number generator is seeded */
    if ( RAND_status() <= 0 )
	err_exit("RAND not seeded");

    /* Generate Private Key */
    if ( ! (rsa = RSA_generate_key( 1024, 65537, NULL, NULL )) )
	err_exit( "Error generating RSA key" );

    if ( ! (prikey = EVP_PKEY_new()) )
	err_exit( "Out of memory" );

    EVP_PKEY_set1_RSA( prikey, rsa );

    /* Generate Certificate Request for self-signed certificate */
    if ( ! (x509rq = X509_REQ_new()) )
	err_exit( "Out of memory" );

    if ( ! X509_REQ_set_version( x509rq, 0L ) )
	err_exit("Error seting X509 version");

    /* Our identify as issuer/subject */
    X509_NAME *subject = X509_REQ_get_subject_name( x509rq );

    if ( 
         ! X509_NAME_add_entry_by_NID( subject, NID_countryName, 
			MBSTRING_ASC, SUB_COUNTRY, -1, -1, 0 )  ||
         ! X509_NAME_add_entry_by_NID( subject, NID_stateOrProvinceName, 
			MBSTRING_ASC, SUB_ST_PROV, -1, -1, 0 )  ||
         ! X509_NAME_add_entry_by_NID( subject, NID_localityName, 
			MBSTRING_ASC, SUB_LOCAL, -1, -1, 0 )  ||
         ! X509_NAME_add_entry_by_NID( subject, NID_organizationName, 
			MBSTRING_ASC, SUB_ORG, -1, -1, 0 )  ||
         ! X509_NAME_add_entry_by_NID( subject, NID_organizationalUnitName, 
			MBSTRING_ASC, SUB_UNIT, -1, -1, 0 )  ||
         ! X509_NAME_add_entry_by_NID( subject, NID_commonName, 
			MBSTRING_ASC, SUB_COMMON, -1, -1, 0 )
       )
	err_exit( "Error setting X509 name" );

    if ( ! X509_REQ_set_pubkey( x509rq, prikey ) )
	err_exit( "Error setting public key" );

    /* Generate self-signed certificate */
    if ( ! (x509ss = X509_new()) )
	err_exit( "Out of memory" );

    if ( ! (serial = M_ASN1_INTEGER_new()) )
	err_exit( "Out of memory" );

    if ( ! ASN1_INTEGER_set( serial, 1L )  ||
         ! X509_set_serialNumber( x509ss, serial ) )
	err_exit( "Error setting X509 serial number" );

    if ( ! X509_set_issuer_name( x509ss,
		X509_REQ_get_subject_name( x509rq ) ) )
	err_exit( "Error setting X509 issuer" );

    long window = 60*60*25;	/* 25 Hours */

    if ( ! X509_gmtime_adj( X509_get_notBefore( x509ss ), -window )  ||
         ! X509_gmtime_adj( X509_get_notAfter( x509ss ), window ) )
	err_exit( "Error setting certificate lifetime" );

    if ( ! X509_set_subject_name( x509ss,
		X509_REQ_get_subject_name( x509rq ) ) )
	err_exit( "Error setting X509 subject" );

    if ( ! (pubkey = X509_REQ_get_pubkey( x509rq ))  ||
	 ! X509_set_pubkey( x509ss, pubkey ) )
	err_exit( "Error setting X509 pubkey" );

    /* TODO: V3 context */

    const EVP_MD *digest = NULL;

    if ( ! (digest = EVP_get_digestbyname( "md5" )) )
	err_exit( "Error retrieving digest" );

    if ( ! X509_sign( x509ss, prikey, digest ) )
	err_exit( "Error signing certificate" );

    /* Use generated private key and self-signed certificate */
    if ( ! SSL_CTX_use_PrivateKey( ctx, prikey ) )
	err_exit( "Error saving private key" );

    if ( ! SSL_CTX_use_certificate( ctx, x509ss ) )
	err_exit( "Error saving certificate" );

    if ( pubkey )  EVP_PKEY_free( pubkey );
    if ( serial )  ASN1_INTEGER_free( serial );
    if ( x509rq )  X509_REQ_free( x509rq );
}

static void
load_dh_params( SSL_CTX *ctx, char *dhpfile )
{
    DH *dhp = NULL;

    if ( dhpfile )
    {
	/* Load DH param file */
	BIO *bio;

	if ( ! (bio = BIO_new_file( dhpfile, "r" )) )
	    ssl_err_exit( "Couldn't open DH param file" );

	dhp = PEM_read_bio_DHparams( bio, NULL, NULL, NULL );
	BIO_free(bio);
    }
    else
    {
	/* Generate runtime DH params */
	if ( RAND_status() <= 0 )  err_exit("RAND not seeded");

	if ( ! (dhp = DH_generate_parameters( 512, 2, NULL, NULL )) )
	    ssl_err_exit("Error generating DH parameters");
    }

    /* Save DH params */
    if ( SSL_CTX_set_tmp_dh( ctx, dhp ) <= 0 )
	ssl_err_exit( "Couldn't set DH parameters" );
}

static int 
tcp_listen( int port )
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

static void
ssl_service( SSL *ssl, int sock_c )
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
        case SSL_ERROR_NONE:	len = r;	break;
        default:		ssl_err_exit( "SSL read problem" );
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

static void
hexdump( char *buffer, int length )
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

