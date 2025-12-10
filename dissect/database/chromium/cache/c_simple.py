from __future__ import annotations

from dissect.cstruct import cstruct

# References:
# - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/simple/simple_index_file.h
# - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/simple/simple_entry_format.h
simple_def = """
/* Simple Indexes */

#define kSimpleIndexMagicNumber     0x656e74657220796f

struct FakeIndexHeader {
    uint64      magic;              // kSimpleIndexMagicNumber
    uint32      version;
    int32       padding[2];
};

struct IndexTableEntry {
    uint64     hash;
    int64      last_used;
    int64      size;
};

struct RealIndexHeader {
    uint32     size;
    uint32     crc32;
    uint64     magic;               // kSimpleIndexMagicNumber
    uint32     version;
    int64      num_entries;
    int64      cache_size;
    int32      unknown;
    IndexTableEntry entries[num_entries];
};

/* Simple File Headers. */

#define kSimpleInitialMagicNumber   0xfcfb6d1ba7725c30
#define kSimpleFinalMagicNumber     0xf4fa6f45970d41d8

struct SimpleFileHeader {
    uint64     magic;               // kSimpleInitialMagicNumber
    uint32     version;
    uint32     key_length;
    uint32     key_hash;            // md5
    uint32     unused_padding;
    char       key[key_length];

    // followed by SimpleFileStream_*
};

#define kSimpleEOFSize              24

struct SimpleFileEOF {
    uint64      magic;              // kSimpleFinalMagicNumber
    uint32      flags;              // hash type: 0 = ?, 1 = crc32, 2 = sha256, 3 = 1 + 2
    uint32      crc32;
    int32       stream_size;        // only used in the EOF record for stream 0.
};

struct SimpleFileStream_0_1 {
    // preceded by SimpleFileHeader
    // char    data_stream_1[];
    // SimpleFileEOF
    // char    data_stream_0[];
    // SHA256 if flags = 2 or 3
    // SimpleFileEOF
};

struct SimpleFileStream_2 {
    // preceded by SimpleFileHeader
    // char     data_stream_2[];
    // SimpleFileEOF
};

#define kSimpleSparseRangeMagicNumber 0xeb97bf016553676b

struct SimpleFileSparseRangeHeader {
    uint64      magic;                // kSimpleSparseRangeMagicNumber
    int64       offset;
    int64       length;
    uint32      crc32;
    // char     data[length];
};
"""

c_simple = cstruct(endian="<").load(simple_def)
