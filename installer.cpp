// ----------------------------------------------------------------------------
// install.cpp - FW installer
// ----------------------------------------------------------------------------
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

#include <mtd/mtd-user.h>
#include <mtd/ubi-user.h>

#include <openssl/sha.h>

#include <string>
#include <list>

#include "fd.h"
#include "crc.h"
#include "common.h"

// ----------------------------------------------------------------------------
// types
// ----------------------------------------------------------------------------
typedef std::list< entry_t > index_t;

// ----------------------------------------------------------------------------
// Local functions
// ----------------------------------------------------------------------------
static int list();
static int install();
static int extract( const char *file, const char *path );
static int flash( const char *file, int mtd );
static int ubi( const char *file, const char *target );

static bool load_index( index_t &index );

static void log_printf( int l, const char *fmt, ... );

// ----------------------------------------------------------------------------
// main()
// ----------------------------------------------------------------------------
int main( int argc, const char **argv )
{
	openlog( "fw", LOG_PID, LOG_DAEMON );

	for( int i = 1; i < argc; i++ )
	{
		if( 0 == strcmp( argv[ i ], "-V" ))
		{
			printf( "installer v%s\n", VERSION );
			return 0;
		}
		else if( 0 == strcmp( argv[ i ], "--list" ))
			return list();
		else if( 0 == strcmp( argv[ i ], "--extract" ))
		{
			if( i+2 >= argc )
			{
				printf( "missing arguments\n" );
				return -1;
			}
			return extract( argv[ i+1 ], argv[ i+2 ] );
		}
		else if( 0 == strcmp( argv[ i ], "--flash" ))
		{
			if( i+2 >= argc )
			{
				printf( "missing arguments\n" );
				return -1;
			}
			return flash( argv[ i+1 ], strtoul( argv[ i+2 ], 0, 10 ) );
		}
		else if( 0 == strcmp( argv[ i ], "--ubi" ))
		{
			if( i+2 >= argc )
			{
				printf( "missing argument\n" );
				return -1;
			}
			return ubi( argv[ i+1 ], argv[ i+2 ] );
		}
	}

	return install();
}

int list()
{
	index_t index;
	load_index( index );

	for( index_t::iterator i = index.begin(); i != index.end(); i++ )
		printf( "%s\n", i->name );

	return 0;
}

int install()
{
	if( 0 != extract( "run.sh", "/tmp/" ))
	{
		log_printf( LOG_ERR, "no run.sh script" );
		return -1;
	}

	char path[ 256 ];
	memset( path, 0, sizeof( path ));
	if( -1 == readlink( "/proc/self/exe", path, sizeof( path )))
	{
		log_printf( LOG_ERR, "readlink() failed: (%i) %m", errno );
		return -1;
	}

	if( -1 == execlp( "/tmp/run.sh", "run.sh", path, NULL ) )
		log_printf( LOG_ERR, "execlp() failed: (%i) %m", errno );
	return -1;
}

int extract( const char *file, const char *path )
{
	index_t index;
	load_index( index );

	// Look for the file requested
	entry_t entry;
	memset( &entry, 0, sizeof( entry ));

	for( index_t::iterator i = index.begin(); i != index.end(); i++ )
	{
		if( 0 == strcmp( i->name, file ))
		{
			entry = *i;
			break;
		}
	}

	if( 0 == entry.size )
	{
		log_printf( LOG_ERR, "%s not found in package", file );
		return -1;
	}

	// Open ourself so we can extract the file
	wpt::fd fd;
	if( -1 == ( fd = open( "/proc/self/exe", O_RDONLY | O_CLOEXEC, 0 )))
	{
		log_printf( LOG_ERR, "open( /proc/self/exe ) failed: (%i) %m", errno );
		return -1;
	}

	// seek to file
	if( (off_t)-1 == lseek( fd, entry.offset, SEEK_SET ))
	{
		log_printf( LOG_ERR, "lseek() failed: (%i) %m", errno );
		return -1;
	}

	// Figure out target
	wpt::fd out;
	int out_fd = -1;
	char tmp_file[ 256 ], target[ 256 ];
	if( path[ 0 ] == '-' && path[ 1 ] == '\0' )
		out_fd = 1;
	else
	{
		snprintf( target, sizeof( target ), "%s", path );
		struct stat st;
		if( 0 == stat( path, &st ))
		{
			if( S_ISDIR( st.st_mode ) )
				snprintf( target, sizeof( target ), "%s/%s", path, file );
		}

		// Open temporary output file
		snprintf( tmp_file, sizeof( tmp_file ), "%s_", target );
		out = open( tmp_file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, entry.flags & FLAG_EXEC ? 0755 : 0644 );
		if( !out )
		{
			log_printf( LOG_ERR, "open( %s ) failed: (%i) %m", tmp_file, errno );
			return -1;
		}
		out_fd = out;

		log_printf( LOG_INFO, "extracting %s to %s", file, target );
	}

	// Copy file
	unsigned int size = entry.size;
	while( size )
	{
		char buffer[ 8192 ];
		ssize_t bytes_read = read( fd, buffer, size > sizeof( buffer ) ? sizeof( buffer ) : size );
		if( -1 == bytes_read )
		{
			log_printf( LOG_ERR, "read() failed: (%i) %m", errno );
			if( out ) unlink( tmp_file );
			return -1;
		}
		ssize_t bytes_written = write( out_fd, buffer, bytes_read );
		if( bytes_written != bytes_read )
		{
			log_printf( LOG_ERR, "write() failed: (%i) %m", errno );
			if( out ) unlink( tmp_file );
			return -1;
		}
		size -= bytes_read;
	}

	// Rename tmp to final
	if( out )
	{
		out.close();
		if( -1 == rename( tmp_file, target ) )
		{
			log_printf( LOG_ERR, "rename() failed: (%i) %m", errno );
			unlink( tmp_file );
		}
	}

	return 0;
}

int flash( const char *file, int mtd )
{
	index_t index;
	load_index( index );

	// Look for the file requested
	entry_t entry;
	memset( &entry, 0, sizeof( entry ));

	for( index_t::iterator i = index.begin(); i != index.end(); i++ )
	{
		if( 0 == strcmp( i->name, file ))
		{
			entry = *i;
			break;
		}
	}

	if( 0 == entry.size )
	{
		log_printf( LOG_ERR, "%s not found in package", file );
		return -1;
	}

	// Open ourself so we can extract the file
	wpt::fd fd_self;
	if( -1 == ( fd_self = open( "/proc/self/exe", O_RDONLY | O_CLOEXEC, 0 )))
	{
		log_printf( LOG_ERR, "open( /proc/self/exe ) failed: (%i) %m", errno );
		return -1;
	}

	// seek to file
	if( (off_t)-1 == lseek( fd_self, entry.offset, SEEK_SET ))
	{
		log_printf( LOG_ERR, "lseek() failed: (%i) %m", errno );
		return -1;
	}

	// Open the MTD device
	wpt::fd fd_mtd;
	char s[ 128 ];
	snprintf( s, sizeof( s ), "/dev/mtd%i", mtd );
	if( -1 == ( fd_mtd = open( s, O_RDWR | O_CLOEXEC ) ))
	{
		log_printf( LOG_ERR, "open( %s ) failed: (%i) %m", s, errno );
		return -1;
	}

	log_printf( LOG_INFO, "flashing %s to %s ... ", file, s );

	// Query info
	struct mtd_info_user mtd_info;
	memset( &mtd_info, 0, sizeof( mtd_info ));
	if( -1 == ioctl( fd_mtd, MEMGETINFO, &mtd_info ) )
	{
		log_printf( LOG_ERR, "ioctl( MEMGETINFO ) failed: (%i) %m", errno );
		return -1;
	}

	// Check that we do not have data larger than the partition
	if( entry.size > mtd_info.size )
	{
		log_printf( LOG_ERR, "data size is larger than partition size" );
		return -1;
	}

	SHA256_CTX sha256;
	memset( &sha256, 0, sizeof( sha256 ));
	SHA256_Init( &sha256 );

	// Write data to flash
	unsigned int bytes_remain = entry.size;
	loff_t offset = 0;
	while( bytes_remain )
	{
		// If this is a NAND device, check for and skip bad blocks
		if( mtd_info.type == MTD_NANDFLASH )
		{
			int retval = ioctl( fd_mtd, MEMGETBADBLOCK, &offset );
			if( retval == 1 )
			{
				// Block is bad, skip
				log_printf( LOG_WARNING, "Skipping bad block 0x%x", offset );
				offset += mtd_info.erasesize;
				continue;
			}
			else if( retval == -1 )
			{
				if( errno )
				{
					log_printf( LOG_ERR, "ioctl( MEMGETBADBLOCK ) failed: (%i) %m", errno );
					return -1;
				}
			}
		}

		erase_info_t erase;
		erase.length = mtd_info.erasesize;
		erase.start = offset;

		// Unlock the block
		ioctl( fd_mtd, MEMUNLOCK, &erase );

		// Erase the block
		if( -1 == ioctl( fd_mtd, MEMERASE, &erase ))
		{
			// Is the block now bad?
			if( mtd_info.type == MTD_NANDFLASH )
			{
				if( 1 == ioctl( fd_mtd, MEMGETBADBLOCK, &offset ) )
				{
					log_printf( LOG_WARNING, "Skipping bad block 0x%x", offset );
					offset += mtd_info.erasesize;
					continue;
				}
			}
			log_printf( LOG_ERR, "ioctl( MEMERASE ) failed: (%i) %m", errno );
			return -1;
		}

		// Seek to block we intend to write
		if( offset != lseek( fd_mtd, offset, SEEK_SET ))
		{
			log_printf( LOG_ERR, "lseek() failed" );
			return -1;
		}

		// Read data block to write
		char buffer[ mtd_info.erasesize ];
		memset( buffer, 0, sizeof( buffer ));
		ssize_t bytes_read = read( fd_self, buffer, sizeof( buffer ) > bytes_remain ? bytes_remain : sizeof( buffer ) );
		if( 0 == bytes_read )
		{
			log_printf( LOG_ERR, "Unexpected EOF" );
			return -1;
		}
		if( -1 == bytes_read )
		{
			log_printf( LOG_ERR, "read() failed: (%i) %m", errno );
			return -1;
		}
		SHA256_Update( &sha256, buffer, bytes_read );
		bytes_remain -= bytes_read;

		// Enforce minimum write size
		if( bytes_read % mtd_info.writesize )
			bytes_read = (( bytes_read / mtd_info.writesize ) + 1 ) * mtd_info.writesize;

		// Write the new data
		if( bytes_read != write( fd_mtd, buffer, bytes_read ))
		{
			log_printf( LOG_ERR, "write() failed: (%i) %m", errno );
			return -1;
		}

		// Lock the block
		ioctl( fd_mtd, MEMLOCK, &erase );

		offset += mtd_info.erasesize;
		if( offset > mtd_info.size )
		{
			log_printf( LOG_ERR, "Not enough blocks remain to write data" );
			return -1;
		}
	}

	// Finish the hash of the data we read from the update
	unsigned char file_hash[ 32 ];
	SHA256_Final( file_hash, &sha256 );

	// read back from the device and hash the results
	log_printf( LOG_INFO, "checking %s ... ", s );

	memset( &sha256, 0, sizeof( sha256 ));
	SHA256_Init( &sha256 );

	snprintf( s, sizeof( s ), "/dev/mtd%iro", mtd );
	if( -1 == ( fd_mtd = open( s, O_RDONLY | O_CLOEXEC )))
	{
		log_printf( LOG_ERR, "open( %s ) failed: (%i) %m", s, errno );
		return -1;
	}

	bytes_remain = entry.size;
	while( bytes_remain )
	{
		// If this is a NAND device, check for and skip bad blocks
		if( mtd_info.type == MTD_NANDFLASH )
		{
			offset = lseek( fd_mtd, 0, SEEK_CUR );
			int retval =  ioctl( fd_mtd, MEMGETBADBLOCK, &offset );
			if( retval == 1 )
			{
				// Block is bad, skip
				lseek( fd_mtd, mtd_info.erasesize, SEEK_CUR );
				continue;
			}
			else if( retval == -1 )
			{
				if( errno )
				{
					log_printf( LOG_ERR, "ioctl( MEMGETBADBLOCK ) failed: (%i) %m", errno );
					return -1;
				}
			}
		}

		char buffer[ mtd_info.erasesize ];
		ssize_t bytes_read = read( fd_mtd, buffer, sizeof( buffer ) > bytes_remain ? bytes_remain : sizeof( buffer ) );
		if( 0 == bytes_read )
		{
			log_printf( LOG_ERR, "Unexpected EOF" );
			return -1;
		}
		if( -1 == bytes_read )
		{
			log_printf( LOG_ERR, "read() failed: (%i) %m", errno );
			return -1;
		}
		SHA256_Update( &sha256, buffer, bytes_read );
		bytes_remain -= bytes_read;
	}

	// Finish the hash of the data we read from the mtd
	unsigned char mtd_hash[ 32 ];
	SHA256_Final( mtd_hash, &sha256 );

	if( 0 != memcmp( file_hash, mtd_hash, 32 ))
	{
		log_printf( LOG_ERR, "Flash write failed!" );
		return -1;
	}

	return 0;
}

static int lookup_ubivol_id( const char *name, int dev )
{
	// There is no simple ioctl to map a name to a volume id, so we need to scan sysfs.
	int vol_id = -1;
	char s[ 128 ];
	snprintf( s, sizeof( s ), "/sys/class/ubi/ubi%i/", dev );
	DIR *handle = opendir( s );
	if( 0 == handle )
	{
		log_printf( LOG_ERR, "opendir() failed: (%i) %m", errno );
		return -1;
	}
	struct dirent *ent = 0;
	while(( ent = readdir( handle ) ))
	{
		int id = 0;
		if( 1 == sscanf( ent->d_name, "ubi%*i_%i", &id ))
		{
			wpt::fd fd;
			snprintf( s, sizeof( s ), "/sys/class/ubi/ubi%i/ubi%i_%i/name", dev, dev, id );
			fd = open( s, O_RDONLY | O_CLOEXEC );
			if( fd )
			{
				char buf[ 32 ] = "";
				int len = read( fd, buf, sizeof( buf ) );
				if ( len > 0 )
				{
					if( 0 == strncmp( buf, name, len - 1 ))
					{
						vol_id = id;
						break;
					}
				}
				fd.close();
			}
		}
	}
	closedir( handle );
	return vol_id;
}

int ubi( const char *file, const char *target )
{
	int dev = 0;
	char name[ 32 ];
	if( 2 != sscanf( target, "ubi%i:%31s", &dev, name ))
	{
		printf( "Bad ubi target\n" );
		return -1;
	}

	index_t index;
	load_index( index );

	// Look for the file requested
	entry_t entry;
	memset( &entry, 0, sizeof( entry ));
	for( index_t::iterator i = index.begin(); i != index.end(); i++ )
	{
		if( 0 == strcmp( i->name, file ))
		{
			entry = *i;
			break;
		}
	}
	if( 0 == entry.size )
	{
		log_printf( LOG_ERR, "%s not found in package", file );
		return -1;
	}

	// Open ourself so we can extract the file
	wpt::fd fd_self;
	if( -1 == ( fd_self = open( "/proc/self/exe", O_RDONLY | O_CLOEXEC, 0 )))
	{
		log_printf( LOG_ERR, "open( /proc/self/exe ) failed: (%i) %m", errno );
		return -1;
	}

	// seek to file
	if( (off_t)-1 == lseek( fd_self, entry.offset, SEEK_SET ))
	{
		log_printf( LOG_ERR, "lseek() failed: (%i) %m", errno );
		return -1;
	}

	log_printf( LOG_INFO, "writing %s to ubi volume %s", file, name );

	// Open ubi device
	wpt::fd fd_ubi;
	char s[ 128 ];
	snprintf( s, sizeof( s ), "/dev/ubi%i", dev );
	if( -1 == ( fd_ubi = open( s, O_RDONLY | O_CLOEXEC, 0 )))
	{
		log_printf( LOG_ERR, "open( %s ) failed: (%i) %m", s, errno );
		return -1;
	}

	// Lookup the volume id of the secondary volume
	snprintf( s, sizeof( s ), "_%s", name );
	int vol_id = lookup_ubivol_id( s, dev );
	if( -1 == vol_id )
		vol_id = UBI_VOL_NUM_AUTO;
	else
	{
		// Need to delete the old volume as sizes may not match
		if( -1 == ioctl( fd_ubi, UBI_IOCRMVOL, &vol_id ) )
		{
			log_printf( LOG_ERR, "ioctl( UBI_IOCRMVOL ) failed: (%i) %m", errno );
			return -1;
		}
	}

	// Create the new volume
	struct ubi_mkvol_req vol_req;
	memset( &vol_req, 0, sizeof( vol_req ) );
	vol_req.vol_id = vol_id;
	vol_req.alignment = 1;
	vol_req.bytes = entry.size;
	vol_req.vol_type = UBI_STATIC_VOLUME;
	vol_req.name_len = snprintf( vol_req.name, sizeof( vol_req.name ), "_%s", name );
	if( -1 == ioctl( fd_ubi, UBI_IOCMKVOL, &vol_req ) )
	{
		log_printf( LOG_ERR, "ioctl( UBI_IOCMKVOL ) failed: (%i) %m", errno );
		return -1;
	}
	vol_id = vol_req.vol_id;

	// Open volume
	wpt::fd fd_vol;
	snprintf( s, sizeof( s ), "/dev/ubi%i_%i", dev, vol_id );
	if( -1 == ( fd_vol = open( s, O_RDWR | O_CLOEXEC, 0 )))
	{
		log_printf( LOG_ERR, "open( %s ) failed: (%i) %m", s, errno );
		return -1;
	}

	// Initiate volume update
	long long bytes = entry.size;
	if( -1 == ioctl( fd_vol, UBI_IOCVOLUP, &bytes ))
	{
		log_printf( LOG_ERR, "ioctl( UBI_IOCVOLUP ) failed: (%i) %m", errno );
		return -1;
	}

	// Write volume data
	unsigned int size = entry.size;
	while( size )
	{
		char buffer[ 8192 ];
		ssize_t bytes_read = read( fd_self, buffer, size > sizeof( buffer ) ? sizeof( buffer ) : size );
		if( -1 == bytes_read )
		{
			log_printf( LOG_ERR, "read() failed: (%i) %m", errno );
			return -1;
		}
		ssize_t bytes_written = write( fd_vol, buffer, bytes_read );
		if( bytes_written != bytes_read )
		{
			log_printf( LOG_ERR, "write() failed: (%i) %m", errno );
			return -1;
		}
		size -= bytes_read;
	}

	fd_vol.close();
	fd_self.close();

	// Swap primary and secondary volumes
	int old_vol_id = lookup_ubivol_id( name, dev );
	struct ubi_rnvol_req ren_req;
	memset( &ren_req, 0, sizeof( ren_req ));
	ren_req.count = ( old_vol_id != -1 ? 2 : 1 );
	ren_req.ents[ 0 ].vol_id = vol_id;
	ren_req.ents[ 0 ].name_len = snprintf( ren_req.ents[ 0 ].name, sizeof( ren_req.ents[ 0 ].name ), "%s", name );
	if( -1 != old_vol_id )
	{
		ren_req.ents[ 1 ].vol_id = old_vol_id;
		ren_req.ents[ 1 ].name_len = snprintf( ren_req.ents[ 1 ].name, sizeof( ren_req.ents[ 1 ].name ), "_%s", name );
	}
	if( -1 == ioctl( fd_ubi, UBI_IOCRNVOL, &ren_req ))
	{
		log_printf( LOG_ERR, "ioctl( UBI_IOCRNVOL ) failed: (%i) %m", errno );
		return -1;
	}

	return 0;
}

bool load_index( index_t &index )
{
	// Open ourself
	wpt::fd fd;
	if( -1 == ( fd = open( "/proc/self/exe", O_RDONLY | O_CLOEXEC, 0 )))
	{
		log_printf( LOG_ERR, "open( /proc/self/exe ) failed: (%i) %m", errno );
		return false;
	}

	// Seek to the end and read the footer
	off_t footer_offset = lseek( fd, -sizeof( footer_t ), SEEK_END );
	if( -1 == footer_offset )
	{
		log_printf( LOG_ERR, "lseek() failed: (%i) %m", errno );
		return false;
	}

	// Read in footer
	footer_t footer;
	if( sizeof( footer_t ) != read( fd, &footer, sizeof( footer )) )
	{
		log_printf( LOG_ERR, "read( footer ) failed: (%i) %m", errno );
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

	// Seek to the start of the index
	if( -1 == lseek( fd, footer.index_offset, SEEK_SET ))
	{
		log_printf( LOG_ERR, "lseek() failed: (%i) %m", errno );
		return false;
	}

	for( unsigned int i = 0; i < footer.index_count; i++ )
	{
		entry_t entry;
		if( sizeof( entry ) != read( fd, &entry, sizeof( entry )))
		{
			log_printf( LOG_ERR, "read() failed: (%i) %m", errno );
			return false;
		}
		index.push_back( entry );
	}

	return true;
}

void log_printf( int l, const char *fmt, ... )
{
	char s[ 2048 ];

	va_list va;
	va_start( va, fmt );
	vsnprintf( s, sizeof( s ), fmt, va );
	va_end( va );

	syslog( l, "%s", s );
	printf( "%s\n", s );
}
