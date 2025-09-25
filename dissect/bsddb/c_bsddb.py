# References:
# - libdb
from __future__ import annotations

from dissect.cstruct import cstruct

db_def = """
typedef uint8 u_int8_t;
typedef uint16 u_int16_t;
typedef uint32 u_int32_t;

typedef u_int32_t db_pgno_t;                    /* Page number type. */
typedef u_int16_t db_indx_t;                    /* Page offset type. */
#define DB_MAX_PAGES            0xffffffff      /* >= # of pages in a file */

typedef u_int32_t db_recno_t;                   /* Record number type. */
#define DB_MAX_RECORDS          0xffffffff      /* >= # of records in a tree */

typedef struct _db_lsn {
    uint32      file;
    uint32      offset;
} DB_LSN;

#define DB_FILE_ID_LEN          20              /* Unique file ID length. */

/*******************************************************
 * Crypto.
 *******************************************************/
#define DB_IV_BYTES             16              /* Bytes per IV */
#define DB_MAC_KEY              20              /* Bytes per MAC checksum */

#define DB_RENAMEMAGIC          0x030800        /* File has been renamed. */

#define DB_BTREEVERSION         9               /* Current btree version. */
#define DB_BTREEOLDVER          8               /* Oldest btree version supported. */
#define DB_BTREEMAGIC           0x053162

#define DB_HASHVERSION          9               /* Current hash version. */
#define DB_HASHOLDVER           7               /* Oldest hash version supported. */
#define DB_HASHMAGIC            0x061561

#define DB_HEAPVERSION          1               /* Current heap version. */
#define DB_HEAPOLDVER           1               /* Oldest heap version supported. */
#define DB_HEAPMAGIC            0x074582

#define DB_QAMVERSION           4               /* Current queue version. */
#define DB_QAMOLDVER            3               /* Oldest queue version supported. */
#define DB_QAMMAGIC             0x042253

#define DB_SEQUENCE_VERSION     2               /* Current sequence version. */
#define DB_SEQUENCE_OLDVER      1               /* Oldest sequence version supported. */

#define DB_AM_CHKSUM            0x00000001      /* Checksumming */
#define DB_AM_COMPENSATE        0x00000002      /* Created by compensating txn */
#define DB_AM_COMPRESS          0x00000004      /* Compressed BTree */
#define DB_AM_CREATED           0x00000008      /* Database was created upon open */
#define DB_AM_CREATED_MSTR      0x00000010      /* Encompassing file was created */
#define DB_AM_DBM_ERROR         0x00000020      /* Error in DBM/NDBM database */
#define DB_AM_DELIMITER         0x00000040      /* Variable length delimiter set */
#define DB_AM_DISCARD           0x00000080      /* Discard any cached pages */
#define DB_AM_DUP               0x00000100      /* DB_DUP */
#define DB_AM_DUPSORT           0x00000200      /* DB_DUPSORT */
#define DB_AM_ENCRYPT           0x00000400      /* Encryption */
#define DB_AM_FIXEDLEN          0x00000800      /* Fixed-length records */
#define DB_AM_INMEM             0x00001000      /* In-memory; no sync on close */
#define DB_AM_INORDER           0x00002000      /* DB_INORDER */
#define DB_AM_IN_RENAME         0x00004000      /* File is being renamed */
#define DB_AM_NOT_DURABLE       0x00008000      /* Do not log changes */
#define DB_AM_OPEN_CALLED       0x00010000      /* DB->open called */
#define DB_AM_PAD               0x00020000      /* Fixed-length record pad */
#define DB_AM_PARTDB            0x00040000      /* Handle for a database partition */
#define DB_AM_PGDEF             0x00080000      /* Page size was defaulted */
#define DB_AM_RDONLY            0x00100000      /* Database is readonly */
#define DB_AM_READ_UNCOMMITTED  0x00200000      /* Support degree 1 isolation */
#define DB_AM_RECNUM            0x00400000      /* DB_RECNUM */
#define DB_AM_RECOVER           0x00800000      /* DB opened by recovery routine */
#define DB_AM_RENUMBER          0x01000000      /* DB_RENUMBER */
#define DB_AM_REVSPLITOFF       0x02000000      /* DB_REVSPLITOFF */
#define DB_AM_SECONDARY         0x04000000      /* Database is a secondary index */
#define DB_AM_SNAPSHOT          0x08000000      /* DB_SNAPSHOT */
#define DB_AM_SUBDB             0x10000000      /* Subdatabases supported */
#define DB_AM_SWAP              0x20000000      /* Pages need to be byte-swapped */
#define DB_AM_TXN               0x40000000      /* Opened in a transaction */
#define DB_AM_VERIFYING         0x80000000      /* DB handle is in the verifier */

/*
 * DB page formats.
 *
 * !!!
 * This implementation requires that values within the following structures
 * NOT be padded -- note, ANSI C permits random padding within structures.
 * If your compiler pads randomly you can just forget ever making DB run on
 * your system.  In addition, no data type can require larger alignment than
 * its own size, e.g., a 4-byte data element may not require 8-byte alignment.
 *
 * Note that key/data lengths are often stored in db_indx_t's -- this is
 * not accidental, nor does it limit the key/data size.  If the key/data
 * item fits on a page, it's guaranteed to be small enough to fit into a
 * db_indx_t, and storing it in one saves space.
 */

#define PGNO_INVALID            0               /* Invalid page number in any database. */
#define PGNO_BASE_MD            0               /* Base database: metadata page number. */

/* Page types. */
#define P_INVALID               0               /* Invalid page type. */
#define __P_DUPLICATE           1               /* Duplicate. DEPRECATED in 3.1 */
#define P_HASH_UNSORTED         2               /* Hash pages created pre 4.6. DEPRECATED */
#define P_IBTREE                3               /* Btree internal. */
#define P_IRECNO                4               /* Recno internal. */
#define P_LBTREE                5               /* Btree leaf. */
#define P_LRECNO                6               /* Recno leaf. */
#define P_OVERFLOW              7               /* Overflow. */
#define P_HASHMETA              8               /* Hash metadata page. */
#define P_BTREEMETA             9               /* Btree metadata page. */
#define P_QAMMETA               10              /* Queue metadata page. */
#define P_QAMDATA               11              /* Queue data page. */
#define P_LDUP                  12              /* Off-page duplicate leaf. */
#define P_HASH                  13              /* Sorted hash page. */
#define P_HEAPMETA              14              /* Heap metadata page. */
#define P_HEAP                  15              /* Heap data page. */
#define P_IHEAP                 16              /* Heap internal. */
#define P_PAGETYPE_MAX          17

/*
 * When we create pages in mpool, we ask mpool to clear some number of bytes
 * in the header.  This number must be at least as big as the regular page
 * headers and cover enough of the btree and hash meta-data pages to obliterate
 * the page type.
 */
#define DB_PAGE_DB_LEN          32
#define DB_PAGE_QUEUE_LEN       0

#define DBMETA_CHKSUM           0x01
#define DBMETA_PART_RANGE       0x02
#define DBMETA_PART_CALLBACK    0x04

/************************************************************************
 GENERIC METADATA PAGE HEADER
 *
 * !!!
 * The magic and version numbers have to be in the same place in all versions
 * of the metadata page as the application may not have upgraded the database.
 ************************************************************************/
typedef struct _dbmeta33 {
    DB_LSN      lsn;                            /* 00-07: LSN. */
    db_pgno_t   pgno;                           /* 08-11: Current page number. */
    u_int32_t   magic;                          /* 12-15: Magic number. */
    u_int32_t   version;                        /* 16-19: Version. */
    u_int32_t   pagesize;                       /* 20-23: Pagesize. */
    u_int8_t    encrypt_alg;                    /*    24: Encryption algorithm. */
    u_int8_t    type;                           /*    25: Page type. */
    u_int8_t    metaflags;                      /* 26: Meta-only flags */
    u_int8_t    unused1;                        /* 27: Unused. */
    u_int32_t   free;                           /* 28-31: Free list page number. */
    db_pgno_t   last_pgno;                      /* 32-35: Page number of last page in db. */
    u_int32_t   nparts;                         /* 36-39: Number of partitions. */
    u_int32_t   key_count;                      /* 40-43: Cached key count. */
    u_int32_t   record_count;                   /* 44-47: Cached record count. */
    u_int32_t   flags;                          /* 48-51: Flags: unique to each AM. */
    u_int8_t    uid[DB_FILE_ID_LEN];            /* 52-71: Unique file ID. */
} DBMETA33, DBMETA;

/************************************************************************
 BTREE METADATA PAGE LAYOUT
 ************************************************************************/
#define BTM_DUP                 0x001           /*   Duplicates. */
#define BTM_RECNO               0x002           /*   Recno tree. */
#define BTM_RECNUM              0x004           /*   Btree: maintain record count. */
#define BTM_FIXEDLEN            0x008           /*   Recno: fixed length records. */
#define BTM_RENUMBER            0x010           /*   Recno: renumber on insert/delete. */
#define BTM_SUBDB               0x020           /*   Subdatabases. */
#define BTM_DUPSORT             0x040           /*   Duplicates are sorted. */
#define BTM_COMPRESS            0x080           /*   Compressed. */
#define BTM_MASK                0x0ff

typedef struct _btmeta33 {
    DBMETA      dbmeta;                         /* 00-71: Generic meta-data header. */

    u_int32_t   unused1;                        /* 72-75: Unused space. */
    u_int32_t   minkey;                         /* 76-79: Btree: Minkey. */
    u_int32_t   re_len;                         /* 80-83: Recno: fixed-length record length. */
    u_int32_t   re_pad;                         /* 84-87: Recno: fixed-length record pad. */
    u_int32_t   root;                           /* 88-91: Root page. */
    u_int32_t   unused2[92];                    /* 92-459: Unused space. */
    u_int32_t   crypto_magic;                   /* 460-463: Crypto magic number */
    u_int32_t   trash[3];                       /* 464-475: Trash space - Do not use */
    u_int8_t    iv[DB_IV_BYTES];                /* 476-495: Crypto IV */
    u_int8_t    chksum[DB_MAC_KEY];             /* 496-511: Page chksum */

    /*
     * Minimum page size is 512.
     */
} BTMETA33, BTMETA;

/************************************************************************
 HASH METADATA PAGE LAYOUT
 ************************************************************************/
#define DB_HASH_DUP             0x01            /*   Duplicates. */
#define DB_HASH_SUBDB           0x02            /*   Subdatabases. */
#define DB_HASH_DUPSORT         0x04            /*   Duplicates are sorted. */
#define NCACHED                 32              /* number of spare points */

typedef struct _hashmeta33 {
    DBMETA      dbmeta;                         /* 00-71: Generic meta-data page header. */

    u_int32_t   max_bucket;                     /* 72-75: ID of Maximum bucket in use */
    u_int32_t   high_mask;                      /* 76-79: Modulo mask into table */
    u_int32_t   low_mask;                       /* 80-83: Modulo mask into table lower half */
    u_int32_t   ffactor;                        /* 84-87: Fill factor */
    u_int32_t   nelem;                          /* 88-91: Number of keys in hash table */
    u_int32_t   h_charkey;                      /* 92-95: Value of hash(CHARKEY) */

    u_int32_t   spares[NCACHED];                /* 96-223: Spare pages for overflow */
    u_int32_t   unused[59];                     /* 224-459: Unused space */
    u_int32_t   crypto_magic;                   /* 460-463: Crypto magic number */
    u_int32_t   trash[3];                       /* 464-475: Trash space - Do not use */
    u_int8_t    iv[DB_IV_BYTES];                /* 476-495: Crypto IV */
    u_int8_t    chksum[DB_MAC_KEY];             /* 496-511: Page chksum */

    /*
     * Minimum page size is 512.
     */
} HMETA33, HMETA;

/************************************************************************
 HEAP METADATA PAGE LAYOUT
*************************************************************************/
/*
 * Heap Meta data page structure
 *
 */
typedef struct _heapmeta {
    DBMETA      dbmeta;                         /* 00-71: Generic meta-data header. */

    db_pgno_t   curregion;                      /* 72-75: Current region pgno. */
    u_int32_t   nregions;                       /* 76-79: Number of regions. */
    u_int32_t   gbytes;                         /* 80-83: GBytes for fixed size heap. */
    u_int32_t   bytes;                          /* 84-87: Bytes for fixed size heap. */
    u_int32_t   region_size;                    /* 88-91: Max region size. */
    u_int32_t   unused2[92];                    /* 92-459: Unused space.*/
    u_int32_t   crypto_magic;                   /* 460-463: Crypto magic number */
    u_int32_t   trash[3];                       /* 464-475: Trash space - Do not use */
    u_int8_t    iv[DB_IV_BYTES];                /* 476-495: Crypto IV */
    u_int8_t    chksum[DB_MAC_KEY];             /* 496-511: Page chksum */

    /*
     * Minimum page size is 512.
     */
} HEAPMETA;

/************************************************************************
 QUEUE METADATA PAGE LAYOUT
 ************************************************************************/
/*
 * QAM Meta data page structure
 *
 */
typedef struct _qmeta33 {
    DBMETA      dbmeta;                         /* 00-71: Generic meta-data header. */

    u_int32_t   first_recno;                    /* 72-75: First not deleted record. */
    u_int32_t   cur_recno;                      /* 76-79: Next recno to be allocated. */
    u_int32_t   re_len;                         /* 80-83: Fixed-length record length. */
    u_int32_t   re_pad;                         /* 84-87: Fixed-length record pad. */
    u_int32_t   rec_page;                       /* 88-91: Records Per Page. */
    u_int32_t   page_ext;                       /* 92-95: Pages per extent */

    u_int32_t   unused[91];                     /* 96-459: Unused space */
    u_int32_t   crypto_magic;                   /* 460-463: Crypto magic number */
    u_int32_t   trash[3];                       /* 464-475: Trash space - Do not use */
    u_int8_t    iv[DB_IV_BYTES];                /* 476-495: Crypto IV */
    u_int8_t    chksum[DB_MAC_KEY];             /* 496-511: Page chksum */

    /*
     * Minimum page size is 512.
     */
} QMETA33, QMETA;

/*
 * DBMETASIZE is a constant used by __db_file_setup and DB->verify
 * as a buffer which is guaranteed to be larger than any possible
 * metadata page size and smaller than any disk sector.
 */
#define DBMETASIZE              512

/************************************************************************
 BTREE/HASH MAIN PAGE LAYOUT
 ************************************************************************/
/*
 *  +-----------------------------------+
 *  |    lsn    |   pgno    | prev pgno |
 *  +-----------------------------------+
 *  | next pgno |  entries  | hf offset |
 *  +-----------------------------------+
 *  |   level   |   type    |   chksum  |
 *  +-----------------------------------+
 *  |    iv     |   index   | free -->  |
 *  +-----------+-----------------------+
 *  |         F R E E A R E A           |
 *  +-----------------------------------+
 *  |              <-- free |   item    |
 *  +-----------------------------------+
 *  |   item    |   item    |   item    |
 *  +-----------------------------------+
 *
 * sizeof(PAGE) == 26 bytes + possibly 20 bytes of checksum and possibly
 * 16 bytes of IV (+ 2 bytes for alignment), and the following indices
 * are guaranteed to be two-byte aligned.  If we aren't doing crypto or
 * checksumming the bytes are reclaimed for data storage.
 *
 * For hash and btree leaf pages, index items are paired, e.g., inp[0] is the
 * key for inp[1]'s data.  All other types of pages only contain single items.
 */
typedef struct __pg_chksum {
    u_int8_t    unused[2];                      /* 26-27: For alignment */
    u_int8_t    chksum[4];                      /* 28-31: Checksum */
} PG_CHKSUM;

typedef struct __pg_crypto {
    u_int8_t    unused[2];                      /* 26-27: For alignment */
    u_int8_t    chksum[DB_MAC_KEY];             /* 28-47: Checksum */
    u_int8_t    iv[DB_IV_BYTES];                /* 48-63: IV */
    /* !!!
     * Must be 16-byte aligned for crypto
     */
} PG_CRYPTO;

#define LEAFLEVEL   1
#define MAXBTREELEVEL 255

typedef struct _db_page {
    DB_LSN      lsn;                            /* 00-07: Log sequence number. */
    db_pgno_t   pgno;                           /* 08-11: Current page number. */
    db_pgno_t   prev_pgno;                      /* 12-15: Previous page number. */
    db_pgno_t   next_pgno;                      /* 16-19: Next page number. */
    db_indx_t   entries;                        /* 20-21: Number of items on the page. */
    db_indx_t   hf_offset;                      /* 22-23: High free byte page offset. */

    /*
     * The btree levels are numbered from the leaf to the root, starting
     * with 1, so the leaf is level 1, its parent is level 2, and so on.
     * We maintain this level on all btree pages, but the only place that
     * we actually need it is on the root page.  It would not be difficult
     * to hide the byte on the root page once it becomes an internal page,
     * so we could get this byte back if we needed it for something else.
     */
    u_int8_t  level;                            /*    24: Btree tree level. */
    u_int8_t  type;                             /*    25: Page type. */
} PAGE;

/*
 * With many compilers sizeof(PAGE) == 28, while SIZEOF_PAGE == 26.
 * We add in other things directly after the page header and need
 * the SIZEOF_PAGE.  When giving the sizeof(), many compilers will
 * pad it out to the next 4-byte boundary.
 */
#define SIZEOF_PAGE             26

/************************************************************************
 HEAP PAGE LAYOUT
 ************************************************************************/
#define HEAPPG_NORMAL           26
#define HEAPPG_CHKSUM           48
#define HEAPPG_SEC              64

/*
 *  +0-----------2------------4-----------6-----------7+
 *  |                        lsn                       |
 *  +-------------------------+------------------------+
 *  |           pgno          |         unused0        |
 *  +-------------+-----------+-----------+------------+
 *  |  high_indx  | free_indx |  entries  |  hf offset |
 *  +-------+-----+-----------+-----------+------------+
 *  |unused2|type |  unused3  |      ...chksum...      |
 *  +-------+-----+-----------+------------------------+
 *  |  ...iv...   |   offset table / free space map    |
 *  +-------------+------------------------------------+
 *  |free->            F R E E A R E A                 |
 *  +--------------------------------------------------+
 *  |                <-- free |          item          |
 *  +-------------------------+------------------------+
 *  |           item          |          item          |
 *  +-------------------------+------------------------+
 *
 * The page layout of both heap internal and data pages.  If not using
 * crypto, iv will be overwritten with data.  If not using checksumming,
 * unused3 and chksum will also be overwritten with data and data will start at
 * 26.  Note that this layout lets us re-use a lot of the PAGE element macros
 * defined above.
 */
typedef struct _heappg {
    DB_LSN      lsn;                            /* 00-07: Log sequence number. */
    db_pgno_t   pgno;                           /* 08-11: Current page number. */
    u_int32_t   high_pgno;                      /* 12-15: Highest page in region. */
    u_int16_t   high_indx;                      /* 16-17: Highest index in the offset table. */
    db_indx_t   free_indx;                      /* 18-19: First available index. */
    db_indx_t   entries;                        /* 20-21: Number of items on the page. */
    db_indx_t   hf_offset;                      /* 22-23: High free byte page offset. */
    u_int8_t    unused2[1];                     /*    24: Unused. */
    u_int8_t    type;                           /*    25: Page type. */
    u_int8_t    unused3[2];                     /* 26-27: Never used, just checksum alignment. */
    u_int8_t    chksum[DB_MAC_KEY];             /* 28-47: Checksum */
    u_int8_t    iv[DB_IV_BYTES];                /* 48-63: IV */
} HEAPPG;

/* Define first possible data page for heap, 0 is metapage, 1 is region page */
#define FIRST_HEAP_RPAGE        1
#define FIRST_HEAP_DPAGE        2

#define HEAP_RECSPLIT           0x01            /* Heap data record is split */
#define HEAP_RECFIRST           0x02            /* First piece of a split record */
#define HEAP_RECLAST            0x04            /* Last piece of a split record */

typedef struct __heaphdr {
    u_int8_t    flags;                          /* 00: Flags describing record. */
    u_int8_t    unused;                         /* 01: Padding. */
    u_int16_t   size;                           /* 02-03: The size of the stored data piece. */
} HEAPHDR;

typedef struct __heaphdrsplt {
    HEAPHDR     std_hdr;                        /* 00-03: The standard data header */
    u_int32_t   tsize;                          /* 04-07: Total record size, 1st piece only */
    db_pgno_t   nextpg;                         /* 08-11: RID.pgno of the next record piece */
    db_indx_t   nextindx;                       /* 12-13: RID.indx of the next record piece */
    u_int16_t   unused;                         /* 14-15: Padding. */
} HEAPSPLITHDR;

/************************************************************************
 QUEUE MAIN PAGE LAYOUT
 ************************************************************************/
/*
 * Sizes of page below.  Used to reclaim space if not doing
 * crypto or checksumming.  If you change the QPAGE below you
 * MUST adjust this too.
 */
#define QPAGE_NORMAL            28
#define QPAGE_CHKSUM            48
#define QPAGE_SEC               64

typedef struct _qpage {
    DB_LSN      lsn;                            /* 00-07: Log sequence number. */
    db_pgno_t   pgno;                           /* 08-11: Current page number. */
    u_int32_t   unused0[3];                     /* 12-23: Unused. */
    u_int8_t    unused1[1];                     /*    24: Unused. */
    u_int8_t    type;                           /*    25: Page type. */
    u_int8_t    unused2[2];                     /* 26-27: Unused. */
    u_int8_t    chksum[DB_MAC_KEY];             /* 28-47: Checksum */
    u_int8_t    iv[DB_IV_BYTES];                /* 48-63: IV */
} QPAGE;

/************************************************************************
 OVERFLOW PAGE LAYOUT
 ************************************************************************/

/*
 * Overflow items are referenced by HOFFPAGE and BOVERFLOW structures, which
 * store a page number (the first page of the overflow item) and a length
 * (the total length of the overflow item).  The overflow item consists of
 * some number of overflow pages, linked by the next_pgno field of the page.
 * A next_pgno field of PGNO_INVALID flags the end of the overflow item.
 *
 * Overflow page overloads:
 * The amount of overflow data stored on each page is stored in the
 * hf_offset field.
 *
 * The implementation reference counts overflow items as it's possible
 * for them to be promoted onto btree internal pages.  The reference
 * count is stored in the entries field.
 */

/************************************************************************
 HASH PAGE LAYOUT
 ************************************************************************/

/* Each index references a group of bytes on the page. */
#define H_KEYDATA               1               /* Key/data item. */
#define H_DUPLICATE             2               /* Duplicate key/data item. */
#define H_OFFPAGE               3               /* Overflow key/data item. */
#define H_OFFDUP                4               /* Overflow page of duplicates. */

/*
 * The first and second types are H_KEYDATA and H_DUPLICATE, represented
 * by the HKEYDATA structure:
 *
 *  +-----------------------------------+
 *  |    type   | key/data ...          |
 *  +-----------------------------------+
 *
 * For duplicates, the data field encodes duplicate elements in the data
 * field:
 *
 *  +---------------------------------------------------------------+
 *  |    type   | len1 | element1 | len1 | len2 | element2 | len2   |
 *  +---------------------------------------------------------------+
 *
 * Thus, by keeping track of the offset in the element, we can do both
 * backward and forward traversal.
 */
typedef struct _hkeydata {
    u_int8_t    type;                           /*    00: Page type. */
    u_int8_t    data[0];                        /* Variable length key/data item. */
} HKEYDATA;

/*
 * The third type is the H_OFFPAGE, represented by the HOFFPAGE structure:
 */
typedef struct _hoffpage {
    u_int8_t    type;                           /*    00: Page type and delete flag. */
    u_int8_t    unused[3];                      /* 01-03: Padding, unused. */
    db_pgno_t   pgno;                           /* 04-07: Offpage page number. */
    u_int32_t   tlen;                           /* 08-11: Total length of item. */
} HOFFPAGE;

/*
 * The fourth type is H_OFFDUP represented by the HOFFDUP structure:
 */
typedef struct _hoffdup {
    u_int8_t    type;                           /*    00: Page type and delete flag. */
    u_int8_t    unused[3];                      /* 01-03: Padding, unused. */
    db_pgno_t   pgno;                           /* 04-07: Offpage page number. */
} HOFFDUP;

/************************************************************************
 BTREE PAGE LAYOUT
 ************************************************************************/

/* Each index references a group of bytes on the page. */
#define B_KEYDATA               1               /* Key/data item. */
#define B_DUPLICATE             2               /* Duplicate key/data item. */
#define B_OVERFLOW              3               /* Overflow key/data item. */

/*
 * We have to store a deleted entry flag in the page.   The reason is complex,
 * but the simple version is that we can't delete on-page items referenced by
 * a cursor -- the return order of subsequent insertions might be wrong.  The
 * delete flag is an overload of the top bit of the type byte.
 */
#define	B_DELETE	            (0x80)

/*
 * The first type is B_KEYDATA, represented by the BKEYDATA structure:
 */
typedef struct _bkeydata {
    db_indx_t   len;                            /* 00-01: Key/data item length. */
    u_int8_t    type;                           /*    02: Page type AND DELETE FLAG. */
    u_int8_t    data[0];                        /* Variable length key/data item. */
} BKEYDATA;

/*
 * The second and third types are B_DUPLICATE and B_OVERFLOW, represented
 * by the BOVERFLOW structure.
 */
typedef struct _boverflow {
    db_indx_t   unused1;                        /* 00-01: Padding, unused. */
    u_int8_t    type;                           /*    02: Page type AND DELETE FLAG. */
    u_int8_t    unused2;                        /*    03: Padding, unused. */
    db_pgno_t   pgno;                           /* 04-07: Next page number. */
    u_int32_t   tlen;                           /* 08-11: Total length of item. */
} BOVERFLOW;

/*
 * Btree leaf and hash page layouts group indices in sets of two, one for the
 * key and one for the data.  Everything else does it in sets of one to save
 * space.  Use the following macros so that it's real obvious what's going on.
 */
#define O_INDX                  1
#define P_INDX                  2

/************************************************************************
 BTREE INTERNAL PAGE LAYOUT
 ************************************************************************/

/*
 * Btree internal entry.
 */
typedef struct _binternal {
    db_indx_t   len;                            /* 00-01: Key/data item length. */
    u_int8_t    type;                           /*    02: Page type AND DELETE FLAG. */
    u_int8_t    unused;                         /*    03: Padding, unused. */
    db_pgno_t   pgno;                           /* 04-07: Page number of referenced page. */
    db_recno_t  nrecs;                          /* 08-11: Subtree record count. */
    u_int8_t    data[0];                        /* Variable length key item. */
} BINTERNAL;

/************************************************************************
 RECNO INTERNAL PAGE LAYOUT
 ************************************************************************/

/*
 * The recno internal entry.
 */
typedef struct _rinternal {
    db_pgno_t   pgno;                           /* 00-03: Page number of referenced page. */
    db_recno_t  nrecs;                          /* 04-07: Subtree record count. */
} RINTERNAL;
"""
c_db = cstruct().load(db_def)
