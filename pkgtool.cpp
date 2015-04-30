// ----------------------------------------------------------------------------
// pkgtool.cpp
// ----------------------------------------------------------------------------
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string>

#include "fd.h"
#include "common.h"

#include "crc.h"

static const char * const CA_CERT_PATH		= "/etc/outernet/ca.crt";

// ----------------------------------------------------------------------------
// function prototypes
// ----------------------------------------------------------------------------
static bool check( int fd );
static void log_printf( int l, const char *fmt, ... );

// ----------------------------------------------------------------------------
// main()
// ----------------------------------------------------------------------------
int main( int argc, const char **argv )
{
	std::string pkg_file;
	bool install = false;

	for( int i = 1; i < argc; i++ )
	{
		if( 0 == strcmp( argv[ i ], "-V" ))
		{
			printf( "pkgtool v%s\n", VERSION );
			return 0;
		}
		else if( 0 == strcmp( argv[ i ], "-i" ))
			install = true;
		else
		{
			if( !pkg_file.empty() )
			{
				printf( "pkg file already specified\n" );
				return -1;
			}
			pkg_file = argv[ i ];
		}
	}

	openlog( "pkgtool", LOG_PID, LOG_DAEMON );
	log_printf( LOG_INFO, "v%s", VERSION );

	if( pkg_file.empty() )
	{
		printf( "Missing firmware file\n" );
		return 1;
	}

	OpenSSL_add_all_algorithms();

	wpt::fd fd;
	fd = open( pkg_file.c_str(), O_RDONLY | O_CLOEXEC );
	if( !fd )
	{
		log_printf( LOG_ERR, "open( %s ) failed: (%i) %m", pkg_file.c_str(), errno );
		return -1;
	}

	log_printf( LOG_INFO, "checking pkg file %s", pkg_file.c_str() );
	if( !check( fd ) )
		return 1;

	if( install )
	{
		if( -1 == fchmod( fd, 0755 ))
			log_printf( LOG_WARNING, "fchmod() failed: (%i) %m", errno );
		log_printf( LOG_INFO, "Installing frmware" );
		execl( pkg_file.c_str(), "installer", NULL );
		log_printf( LOG_ERR, "exec() failed: (%i) %m", errno );
		return -1;
	}

	return 0;
}

// ----------------------------------------------------------------------------
// check() - check a firmware file
// ----------------------------------------------------------------------------
bool check( int fd )
{
	X509_STORE *ca_store = X509_STORE_new();

	FILE *fp = 0;
	fp = fopen( CA_CERT_PATH, "r" );
	if( 0 == fp )
	{
		log_printf( LOG_ERR, "failed to open CA cert" );
		return false;
	}
	X509 *ca_cert = PEM_read_X509( fp, 0, 0, 0 );
	fclose( fp );
	if( 0 == ca_cert )
	{
		log_printf( LOG_ERR, "failed to load CA cert" );
		return false;
	}
	X509_STORE_add_cert( ca_store, ca_cert );

	// Seek to the end of payload and read the footer
	off_t size = lseek( fd, -sizeof( footer_t ), SEEK_END );
	if( (off_t)-1 == size )
	{
		log_printf( LOG_ERR, "lseek() failed: (%i) %m", errno );
		return false;
	}

	footer_t footer;
	if( sizeof( footer_t ) != read( fd, &footer, sizeof( footer )) )
	{
		log_printf( LOG_ERR, "read() failed: (%i) %m", errno );
		return false;
	}

	// Check footer crc first
	if( 0 != crc32( &footer, sizeof( footer )))
	{
		log_printf( LOG_ERR, "footer corrupt" );
		return false;
	}

	// Match signature
	if( FTR_IDENT_V2 != footer.ident )
	{
		log_printf( LOG_ERR, "footer signature incorrct" );
		return false;
	}

	// Now hash the payload
	SHA256_CTX sha256;
	memset( &sha256, 0, sizeof( sha256 ));
	SHA256_Init( &sha256 );
	lseek( fd, 0, SEEK_SET );
	while( size )
	{
		unsigned char buffer[ 8192 ];

		ssize_t bytes_read = read( fd, buffer, sizeof( buffer ) < (size_t)size ? sizeof( buffer ) : size );
		SHA256_Update( &sha256, buffer, bytes_read );
		size -= bytes_read;
	}
	unsigned char hash[ 32 ];
	SHA256_Final( hash, &sha256 );

	// Load signing certificate
	off_t cert_offset = footer.index_offset + ( footer.index_count * sizeof( entry_t ) );
	if( (off_t)-1 == lseek( fd, cert_offset, SEEK_SET ) )
	{
		log_printf( LOG_ERR, "lseek() failed: (%i) %m", errno );
		return false;
	}
	BIO *bio = BIO_new_fd( fd, BIO_NOCLOSE );
	X509 *sig_cert = d2i_X509_bio( bio, 0 );
	BIO_free( bio );
	if( 0 == sig_cert )
	{
		log_printf( LOG_ERR, "failed to read signing certificate" );
		return false;
	}

	// Verify signing certificate
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init( ctx, ca_store, sig_cert, 0 );
	int valid_cert = X509_verify_cert( ctx );
	X509_STORE_CTX_free( ctx );
	if( 0 == valid_cert )
	{
		log_printf( LOG_ERR, "invalid signing certificate" );
		X509_free( sig_cert );
		return false;
	}

	// Setup pub key
	EVP_PKEY *evp_key = X509_get_pubkey( sig_cert );
	X509_free( sig_cert );
	if( 0 == evp_key )
	{
		log_printf( LOG_ERR, "failed to get public key" );
		return false;
	}
	RSA *pub_key = EVP_PKEY_get1_RSA( evp_key );
	EVP_PKEY_free( evp_key );
	if( 0 == pub_key )
	{
		log_printf( LOG_ERR, "failed to get RSA key" );
		return false;
	}

	// Verify signature
	int verified = RSA_verify( NID_sha1, hash, sizeof( hash ), footer.sig, sizeof( footer.sig ), pub_key );
	RSA_free( pub_key );

	if( 0 == verified )
	{
		log_printf( LOG_ERR, "failed signature check" );
		return false;
	}

	return true;
}

static void log_printf( int l, const char *fmt, ... )
{
	char s[ 2048 ];

	va_list va;
	va_start( va, fmt );
	vsnprintf( s, sizeof( s ), fmt, va );
	va_end( va );

	syslog( l, "%s", s );
	printf( "%s\n", s );
}
