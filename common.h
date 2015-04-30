// ----------------------------------------------------------------------------
// common.h - firmware file structures
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// constants
// ----------------------------------------------------------------------------
static const char *VERSION = "0.5.0";
static const unsigned int FTR_IDENT_V2 = 0x32565746;

/*  ********************
    *  installer bin   *
    ********************
	*     object 0     *
    ********************
	*     object n     *
    ********************
    *      index       *
    ********************
    *   certificate    *
    ********************
	*      footer      *
    ********************
*/

static const unsigned char FLAG_EXEC = 0x01;		// This entry is an executable, and should be written out and executed

// ----------------------------------------------------------------------------
// structures and types
// ----------------------------------------------------------------------------
typedef struct
{
	unsigned int   ident;			// ident, will be 0x32565746 for v2
	unsigned int   index_offset;	// Offset to index
	unsigned short index_count;		// Number of entries in index
	unsigned char  reserved[ 2 ];	// Reserved, set to 0
	unsigned char  sig[ 256 ];		// Signature
	unsigned int   crc;				// crc of header
} footer_t;

typedef struct
{
	unsigned int size;				// Size of entry
	unsigned int offset;			// Location fo file in payload
	unsigned char flags;			// flags for object
	unsigned char padding[ 3 ];		// padding, should be 0
	char name[ 36 ];				// file name
} entry_t;
