from __future__ import annotations

from dissect.cstruct import cstruct

# References:
# - https://github.com/etcd-io/bbolt/blob/main/internal/common/types.go
# - https://github.com/etcd-io/bbolt/blob/main/internal/common/meta.go
# - https://github.com/etcd-io/bbolt/blob/main/internal/common/bucket.go
# - https://github.com/etcd-io/bbolt/blob/main/internal/common/page.go
bbolt_def = """
typedef uint64 Pgid;    // page identifier
typedef uint64 Txid;    // transaction identifier

#define Magic 0xED0CDAED

enum PageFlag: uint16 {
    Branch          = 0x01,
    Leaf            = 0x02,
    Meta            = 0x04,
    Freelist        = 0x10,
};

struct InBucket {
    Pgid            root;
    uint64          sequence;
};

struct Page {
    Pgid            id;
    PageFlag        flags;      // type of the page: branch, leaf, meta or freelist
    uint16          count;      // number of key/value pairs in this page
    uint32          overflow;   // number of overflow pages
};

struct Meta {
    Page            page;
    uint32          magic;
    uint32          version;
    uint32          pageSize;
    uint32          flags;
    InBucket        root;
    Pgid            freelist;
    Pgid            pgid;
    Txid            txid;
    uint64          checksum;
};

struct branchPageElement {
    uint32          pos;        // relative
    uint32          ksize;
    Pgid            pgid;
};

struct leafPageElement {
    uint32          flags;      // 0x01 = BucketLeafFlag
    uint32          pos;        // relative
    uint32          ksize;
    uint32          vsize;
};

struct Inode {
    uint32          flags;
    Pgid            pgid;
};
"""

c_bbolt = cstruct().load(bbolt_def)
