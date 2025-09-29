from __future__ import annotations

from dissect.cstruct import cstruct

from dissect.database.util.protobuf import ProtobufVarint, ProtobufVarint32

indexeddb_def = """
enum KeyPrefixType : uint8 {
    GLOBAL_METADATA                     = 0,
    DATABASE_METADATA                   = 1,
    OBJECT_STORE_DATA                   = 2,
    EXISTS_ENTRY                        = 3,
    INDEX_DATA                          = 4,
    INVALID_TYPE                        = 5,
    BLOB_ENTRY                          = 6,
};

enum GlobalMetaDataType : uint8 {
    SchemaVersionKey                    = 0,
    MaxDatabaseIdKey                    = 1,
    DataVersionKey                      = 2,
    RecoveryBlobJournalKey              = 3,
    ActiveBlobJournalKey                = 4,
    EarliestSweepKey                    = 5,
    EarliestCompactionKey               = 6,
    DatabaseFreeListKey                 = 100,
    DatabaseNameKey                     = 201,
};

enum DatabaseMetaDataType {
    ORIGIN_NAME                         = 0,
    DATABASE_NAME                       = 1,
    USER_STRING_VERSION                 = 2,        // Obsolete
    MAX_OBJECT_STORE_ID                 = 3,
    USER_VERSION                        = 4,
    BLOB_KEY_GENERATOR_CURRENT_NUMBER   = 5,
    MAX_SIMPLE_METADATA_TYPE            = 6,

    ObjectStoreMetaData                 = 50,
};

enum IndexIdType {
    ObjectStoreData                     = 1,
    ExistsEntry                         = 2,
    BlobEntry                           = 3,
};

#define kMaximumDepth                   2000
#define kMaximumArraySize               1000000

enum IdbKeyType {
    Null                                = 0,
    String                              = 1,
    Date                                = 2,
    Number                              = 3,
    Array                               = 4,
    MinKey                              = 5,
    Binary                              = 6,
};

struct KeyPrefix {
    uint8                               lengths;
    char                                database_id[((lengths >> 5) & 0x07) + 1];
    char                                object_store_id[((lengths >> 2) & 0x07) + 1];
    char                                index_id[(lengths & 0x03) + 1];
};

#define kMinWireFormatVersion           21

struct IdbValueHeader {
    varint                              version;
    uint8                               blink_tag;          // 0xff
    varint                              blink_version;
};

struct IdbValueBlob {
    varint                              size;
    varint                              index;
};
"""

c_indexeddb = cstruct()
c_indexeddb.add_custom_type("varint", ProtobufVarint, size=None, alignment=1, signed=False)
c_indexeddb.add_custom_type("varint64", ProtobufVarint, size=None, alignment=1, signed=False)
c_indexeddb.add_custom_type("varint32", ProtobufVarint32, size=None, alignment=1, signed=False)
c_indexeddb.load(indexeddb_def)
