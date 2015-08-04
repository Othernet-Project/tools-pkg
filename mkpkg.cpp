// ----------------------------------------------------------------------------
// mkpkg.cpp - Create package file
// ----------------------------------------------------------------------------
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <string>
#include <list>

#include "common.h"
#include "fd.h"

#include "crc.h"

// ----------------------------------------------------------------------------
// function prototypes
// ----------------------------------------------------------------------------
static bool add_file( std::string &image, int fd, SHA256_CTX &sha256, entry_t &entry );

extern "C" {
	extern char _binary_installer_bin_start[];
	extern char _binary_installer_bin_end[];
	extern char _binary_installer_bin_size[];
};

static int password_cb( char *buf, int size, int rwflag, void *userdata )
{
	if( 0 == userdata )
		return -1;
	std::string &pass = *(std::string *)userdata;
	return snprintf( buf, size, "%s", pass.c_str() );
}

// ----------------------------------------------------------------------------
// main()
// ----------------------------------------------------------------------------
int main( int argc, const char **argv )
{
	typedef std::list< std::string > file_list_t;
	file_list_t files;
	std::string pkg_file, cert_file, key_pass;

	for( int i = 1; i < argc; i++ )
	{
		if( 0 == strcmp( argv[ i ], "-V" ))
		{
			printf( "mkpkg v%s\n", VERSION );
			return 0;
		}
		else if( 0 == strcmp( argv[ i ], "-k" ))
		{
			if( argc == ++i )
			{
				printf( "-k: missing argument\n" );
				return 1;
			}
			cert_file = argv[ i ];
		}
		else if( 0 == strcmp( argv[ i ], "-p" ))
		{
			if( argc == ++i )
			{
				printf( "-p: missing argument\n" );
				return 1;
			}
			key_pass = argv[ i ];
		}
		else if( 0 == strcmp( argv[ i ], "-o" ))
		{
			if( argc == ++i )
			{
				printf( "-o: missing argument\n" );
				return 1;
			}
			pkg_file = argv[ i ];
		}
		else
			files.push_back( argv[ i ] );
	}

	if( pkg_file.empty() )
	{
		printf( "Missing package file name\n" );
		return 1;
	}
	if( cert_file.empty() )
		printf( " *** Package will not be signed ***\n" );
	if( files.empty() )
	{
		printf( "Missing package image files\n" );
		return 1;
	}

	OpenSSL_add_all_algorithms();

	// Load signing certificate
	X509 *cert = 0;
	RSA *key = 0;
	if( !cert_file.empty() )
	{
		FILE *fp = fopen( cert_file.c_str(), "r" );
		if( 0 == fp )
		{
			printf( "Failed to open signing cert: %s\n", cert_file.c_str() );
			return 1;
		}
		cert = PEM_read_X509( fp, 0, 0, 0 );
		key = PEM_read_RSAPrivateKey( fp, 0, password_cb, &key_pass );
		if( 0 == cert || 0 == key )
		{
			printf( "Failed to read signing cert\n" );
			return false;
		}
	}

	// Open the output file for writing
	wpt::fd fd;
	fd = open( pkg_file.c_str(), O_CREAT | O_RDWR | O_TRUNC, 0744 );
	if( !fd )
	{
		printf( "open( %s ) failed: (%i) %m\n", pkg_file.c_str(), errno );
		return 1;
	}

	// Begin hash
	SHA256_CTX sha256;
	memset( &sha256, 0, sizeof( sha256 ));
	SHA256_Init( &sha256 );

	// Write out installer...
	printf( "Writing installer.bin ... " );
	char *installer_data = _binary_installer_bin_start;
	unsigned int installer_size = (unsigned int)(unsigned long)&_binary_installer_bin_size;
	if( installer_size != write( fd, installer_data, installer_size ) )
	{
		printf( "write() failed: (%i) %m\n", errno );
		unlink( pkg_file.c_str() );
		return 1;
	}
	SHA256_Update( &sha256, installer_data, installer_size );
	printf( "done\n" );

	// Write out the files
	typedef std::list< entry_t > index_t;
	index_t index;
	for( file_list_t::iterator iter = files.begin(); iter != files.end(); iter++ )
	{
		std::string::size_type p = iter->find_first_of( ":" );
		std::string file = ( p != std::string::npos ? iter->substr( 0, p ) : *iter );
		std::string name = ( p != std::string::npos ? iter->substr( p + 1 ) : basename( iter->c_str() ) );

		entry_t entry;
		memset( &entry, 0, sizeof( entry ));
		snprintf( entry.name, sizeof( entry.name ), "%s", name.c_str() );

		printf( "Writing %s => %s ... ", file.c_str(), name.c_str() );
		if( !add_file( file, fd, sha256, entry ))
		{
			unlink( pkg_file.c_str() );
			return 1;
		}
		index.push_back( entry );
		printf( "done\n" );
	}

	// write out index
	printf( "Writing index ... " );
	unsigned int index_offset = lseek( fd, 0, SEEK_CUR );
	for( index_t::iterator i = index.begin(); i != index.end(); i++ )
	{
		entry_t &entry = *i;
		if( sizeof( entry ) != write( fd, &entry, sizeof( entry )))
		{
			unlink( pkg_file.c_str() );
			return 1;
		}
		SHA256_Update( &sha256, &entry, sizeof( entry ) );
	}
	printf( "done\n" );

	// Write signing certificate
	if( cert )
	{
		printf( "Writing signing certificate ... " );
		unsigned char cert_buffer[ 2048 ];
		unsigned char *p = cert_buffer;
		int len = i2d_X509( cert, &p );
		if( -1 == write( fd, cert_buffer, len ))
		{
			printf( "write() failed: (%i) %m\n", errno );
			unlink( pkg_file.c_str() );
			return 1;
		}
		SHA256_Update( &sha256, cert_buffer, len );
		X509_free( cert );
		printf( "done\n" );
	}

	// Add the footer
	printf( "Writing footer ... " );
	footer_t footer;
	memset( &footer, 0, sizeof( footer ));
	footer.ident = FTR_IDENT_V2;
	footer.index_offset = index_offset;
	footer.index_count = index.size();

	unsigned char hash[ 32 ];
	SHA256_Final( hash, &sha256 );

	// Sign
	if( key )
	{
		unsigned int sig_size = 0;
		int ret = RSA_sign( NID_sha1, hash, sizeof( hash ), footer.sig, &sig_size, key );
		RSA_free( key );
		if( 0 == ret )
		{
			printf( "RSA_sign() failed\n" );
			unlink( pkg_file.c_str() );
			return 1;
		}
	}

	footer.crc = ntohl( crc32( &footer, sizeof( footer ) - 4 ) );
	if( sizeof( footer_t ) != write( fd, &footer, sizeof( footer )) )
	{
		printf( "write() failed: (%i) %m\n", errno );
		unlink( pkg_file.c_str() );
		return 1;
	}
	printf( "done\n" );

	// done
	return 0;
}

bool add_file( std::string &image, int fd, SHA256_CTX &sha256, entry_t &entry )
{
	wpt::fd img;
	img = open( image.c_str(), O_RDONLY );
	if( !img )
	{
		printf( "open( %s ) failed: (%i) %m\n", image.c_str(), errno );
		return false;
	}

	struct stat st;
	if( -1 == fstat( img, &st ))
	{
		printf( "fstat( %s ) failed: (%i) %m\n", image.c_str(), errno );
		return false;
	}

	entry.size = st.st_size;
	if( st.st_mode & ( S_IXUSR | S_IXGRP | S_IXOTH ))
		entry.flags = FLAG_EXEC;
	entry.offset = lseek( fd, 0, SEEK_CUR );

	// Read source file chunk at a time, hashing it, then writing out to destination file.
	while( true )
	{
		unsigned char buffer[ 8192 ];

		ssize_t bytes_read = read( img, buffer, sizeof( buffer ));
		if( -1 == bytes_read )
		{
			printf( "read() failed: (%i) %m\n", errno );
			return false;
		}
		if( bytes_read == 0 )
			break;
		SHA256_Update( &sha256, buffer, bytes_read );
		if( bytes_read != write( fd, buffer, bytes_read ) )
		{
			printf( "write() failed: (%i) %m\n", errno );
			return false;
		}
	}

	return true;
}
