from __future__ import annotations

from dissect.cstruct import cstruct

# References:
# - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/blockfile/addr.h
# - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/blockfile/disk_format_base.h
# - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/blockfile/disk_format.h
cache_def = """

/* Cache Address format. */

enum FileType {
    EXTERNAL = 0,
    RANKINGS = 1,
    BLOCK_256 = 2,
    BLOCK_1K = 3,
    BLOCK_4K = 4,
    BLOCK_FILES = 5,
    BLOCK_ENTRIES = 6,
    BLOCK_EVICTED = 7
};

// int kMaxBlockSize = 4096 * 4;
// int16_t kMaxBlockFile = 255;
// int kMaxNumBlocks = 4;
// int16_t kFirstAdditionalBlockFile = 4;

#define kInitializedMask        0x80000000
#define kFileTypeMask           0x70000000
#define kFileTypeOffset         28
#define kReservedBitsMask       0x0c000000
#define kNumBlocksMask          0x03000000
#define kNumBlocksOffset        24
#define kFileSelectorMask       0x00ff0000
#define kFileSelectorOffset     16
#define kStartBlockMask         0x0000FFFF
#define kFileNameMask           0x0FFFFFFF

/* Cache types. */

/* Index file format. */
typedef uint32_t CacheAddr;

struct LruData {
    int32       padding_1[2];
    int32       filled;             // Flag to tell when we filled the cache.
    int32       sizes[5];
    CacheAddr   heads[5];
    CacheAddr   tails[5];
    CacheAddr   transaction;        // In-flight operation target.
    int32       operation;          // Actual in-flight operation.
    int32       operation_list;     // In-flight operation list.
    int32       padding_2[7];
};

struct IndexHeader {
    uint32      magic;              // 0xc3ca03c1
    uint32      version;
    int32       num_entries;
    int32       num_bytes_legacy;
    int32       last_file;          // f_######
    int32       dirty_flag;
    CacheAddr   stats;
    int32       table_len;
    int32       crash_flag;
    int32       experiment_flag;
    uint64      create_time;
    int64       num_bytes;
    int32       corruption_flag;
    int32       padding[49];
    LruData     lru_data;
    // CacheAddr   table[table_len];     // max is kIndexTablesize (0x10000)
};

/* Data Block File Format. */
#define kBlockHeaderSize                8192

struct BlockFileHeader {
    uint32      magic;                  // 0xc3ca04c1
    uint32      version;
    int16       this_file;              // Index of this file (data_#).
    int16       next_file;              // Next file when this one is full (data_#).
    int32       entry_size;             // Size of the blocks of this file.
    int32       num_entries;            // Number of stored entries.
    int32       max_entries;            // Current maximum number of entries.
    int32       empty[4];
    int32       hints[4];
    int32       updating;
    int32       user[5];
    // char        allocation_map[4 * 2028];
    // total header should be exactly kBlockHeaderSize bytes long (8192).
};

/* Cache Entry Format. */

enum EntryState {
    ENTRY_NORMAL = 0,
    ENTRY_EVICTED,                      // The entry was recently evicted from the cache.
    ENTRY_DOOMED                        // The entry was doomed.
};

enum EntryFlags {
    PARENT_ENTRY = 1,                   // This entry has children (sparse) entries.
    CHILD_ENTRY = 1 << 1                // Child entry that stores sparse data.
};

struct EntryStore {
    uint32      hash;                   // Full hash of the key.
    CacheAddr   next;                   // Next entry with the same hash or bucket.
    CacheAddr   rankings_node;          // Rankings node for this entry.
    int32       reuse_count;            // How often is this entry used.
    int32       refetch_count;          // How often is this fetched from the net.
    int32       state;                  // Current state.
    uint64      creation_time;
    int32       key_len;
    CacheAddr   long_key;               // Optional address of a long key.

    int32       data_size[4];           // We can store up to 4 data streams for
    CacheAddr   data_addr[4];           // each entry.

    uint32      flags;                  // Any combination of EntryFlags.
    int32       padding[4];
    uint32      self_hash;              // The hash of EntryStore up to this point.
    char        key[256 - 24 * 4];      // null terminated
};
"""

c_cache = cstruct(endian="<").load(cache_def)


def BlockSizeForFileType(file_type: int) -> int:
    if file_type == 1:  # RANKINGS
        return 36

    if file_type == 2:  # BLOCK_256
        return 256

    if file_type == 3:  # BLOCK_1K
        return 1024

    if file_type == 4:  # BLOCK_4K
        return 4096

    if file_type == 5:  # BLOCK_FILES
        return 8

    if file_type == 6:  # BLOCK_ENTRIES
        return 104

    if file_type == 7:  # BLOCK_EVICETED
        return 48

    raise ValueError(f"Unknown file_type {file_type!r}")
