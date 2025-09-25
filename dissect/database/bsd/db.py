from __future__ import annotations

from functools import cached_property, lru_cache
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.bsd.c_db import c_db

if TYPE_CHECKING:
    from collections.abc import Iterator


DBT = tuple[
    c_db.HOFFPAGE | c_db.HKEYDATA | c_db.HEAPHDR | c_db.BKEYDATA | c_db.BOVERFLOW | c_db.BINTERNAL | c_db.RINTERNAL,
    bytes,
]
"""An internal page entry structure + data (loosely related to Data-Base Thang)."""


class DB:
    """Berkeley DB.

    Args:
        fh: File-like object containing the Berkeley DB data.
    """

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.fh.seek(0)

        meta = c_db.DBMETA(self.fh)
        self.fh.seek(0)

        if meta.magic == c_db.DB_BTREEMAGIC and meta.type == c_db.P_BTREEMETA:
            self.meta = c_db.BTMETA(self.fh)
        elif meta.magic == c_db.DB_HASHMAGIC and meta.type == c_db.P_HASHMETA:
            self.meta = c_db.HMETA(self.fh)
        else:
            raise NotImplementedError(f"Unsupported DB type: {meta.magic:#x} {meta.type}")

        self.page_size = self.meta.dbmeta.pagesize

        page_overhead = len(c_db.PAGE)
        if self.meta.dbmeta.flags & c_db.DB_AM_ENCRYPT:
            page_overhead += len(c_db.PG_CRYPTO)
        elif self.meta.dbmeta.flags & c_db.DB_AM_CHKSUM:
            page_overhead += len(c_db.PG_CHKSUM)
        self._page_overhead = page_overhead

        self.page = lru_cache(128)(self.page)

    @property
    def is_btree(self) -> bool:
        """Return whether the database of a ``DB_BTREE`` type."""
        return self.meta.dbmeta.magic == c_db.DB_BTREEMAGIC

    @property
    def is_recno(self) -> bool:
        """Return whether the database is a ``DB_RECNO`` type."""
        return self.is_btree and (self.meta.dbmeta.flags & c_db.BTM_RECNO) != 0

    @property
    def is_hash(self) -> bool:
        """Return whether the database is a ``DB_HASH`` type."""
        return self.meta.dbmeta.magic == c_db.DB_HASHMAGIC

    def page(self, pgno: int) -> Page:
        """Get a single page by page number.

        Args:
            pgno: Page number to retrieve.
        """
        return Page(self, pgno)

    def records(self) -> Iterator[tuple[bytes | int, bytes]]:
        """Iterate over all records in the database."""
        it = self._iter_db()

        if (self.is_btree and not self.is_recno) or self.is_hash:
            # Hash and Btree are stored in pairs
            while entry := next(it, None):
                _, key = entry
                _, data = next(it)
                yield bytes(key), bytes(data)
        elif self.is_recno:
            i = 0
            while entry := next(it, None):
                i += 1
                dbt, data = entry
                if dbt.type & c_db.B_DELETE:
                    continue
                yield i, bytes(data)

    def _iter_db(self) -> Iterator[DBT]:
        if self.is_btree:
            yield from self._iter_btree()
        elif self.is_hash:
            yield from self._iter_hash()
        else:
            raise NotImplementedError("Unsupported DB type")

    def _iter_btree(self) -> Iterator[DBT]:
        yield from self._walk_btree(self.meta.root)

    def _walk_btree(self, pgno: int) -> Iterator[DBT]:
        page = self.page(pgno)
        if page.header.type in (c_db.P_IBTREE, c_db.P_IRECNO):
            # Internal page
            for entry, _ in page.entries():
                yield from self._walk_btree(entry.pgno)
        elif page.header.type in (c_db.P_LBTREE, c_db.P_LRECNO):
            # Leaf page
            yield from page.entries()

    def _iter_hash(self) -> Iterator[DBT]:
        for i in range(self.meta.max_bucket + 1):
            pgno = BUCKET_TO_PAGE(self, i)
            yield from self._walk_hash(pgno)

    def _walk_hash(self, pgno: int) -> Iterator[DBT]:
        page = self.page(pgno)
        yield from page.entries()

        if page.header.next_pgno:
            yield from self._walk_hash(page.header.next_pgno)


class Page:
    """A single page in a Berkeley DB.

    Args:
        db: The parent ``DB`` instance.
        pgno: The page number to load.
    """

    def __init__(self, db: DB, pgno: int):
        self.db = db
        self.pgno = pgno
        self.offset = pgno * self.db.page_size

    @cached_property
    def raw(self) -> bytes:
        """Raw page data."""
        self.db.fh.seek(self.offset)
        return self.db.fh.read(self.db.page_size)

    @cached_property
    def data(self) -> memoryview:
        """Page data, excluding any overhead (headers)."""
        return memoryview(self.raw)[self.db._page_overhead :]

    @cached_property
    def header(self) -> c_db.PAGE:
        """Page header."""
        return c_db.PAGE(self.raw)

    @property
    def type(self) -> int:
        """Page type."""
        return self.header.type

    @cached_property
    def lookup(self) -> list[int]:
        """List of offsets to entries in the page."""
        if self.type in (c_db.P_LBTREE, c_db.P_IBTREE, c_db.P_LRECNO, c_db.P_IRECNO, c_db.P_HASH):
            return c_db.uint16[self.header.entries](self.data)
        return []

    def entry(self, index: int) -> DBT:
        """Get a single entry by index. Type depends on page type.

        Also returns the associated data (DBT, Data-Base Thang, or key/data buffer) if applicable.

        References:
            - ``__db_ret``

        Args:
            index: Index of the entry to retrieve.
        """
        if index >= len(self.lookup):
            raise IndexError("Index out of range")

        buf = memoryview(self.raw)[self.lookup[index] :]
        # These are the types that can be DBTs
        if self.header.type in (c_db.P_HASH_UNSORTED, c_db.P_HASH):
            if buf[0] == c_db.H_OFFPAGE:
                entry = c_db.HOFFPAGE(buf)
                return entry, overflow_data(self.db, entry.pgno, entry.tlen)

            next_offset = self.db.page_size if index == 0 else self.lookup[index - 1]
            data_length = (next_offset - self.lookup[index]) - len(c_db.HKEYDATA)

            return c_db.HKEYDATA(buf), buf[len(c_db.HKEYDATA) : len(c_db.HKEYDATA) + data_length]

        if self.header.type == c_db.P_HEAP:
            entry = c_db.HEAPHDR(buf)
            if entry.flags & (c_db.HEAP_RECSPLIT | c_db.HEAP_RECFIRST):
                raise NotImplementedError("Heap split records not implemented")
            return entry, buf[len(c_db.HEAPHDR) : len(c_db.HEAPHDR) + entry.size]

        if self.header.type in (c_db.P_LBTREE, c_db.P_LDUP, c_db.P_LRECNO):
            entry = c_db.BKEYDATA(buf)
            if entry.type == c_db.B_OVERFLOW:
                entry = c_db.BOVERFLOW(buf)
                return entry, overflow_data(self.db, entry.pgno, entry.tlen)

            return entry, buf[len(c_db.BKEYDATA) : len(c_db.BKEYDATA) + entry.len]

        # These are more internal types, but we still want to parse them
        if self.header.type == c_db.P_IBTREE:
            entry = c_db.BINTERNAL(buf)
            return entry, buf[len(c_db.BINTERNAL) : len(c_db.BINTERNAL) + entry.len]

        if self.header.type == c_db.P_IRECNO:
            return c_db.RINTERNAL(buf), b""

        raise NotImplementedError(f"Page type not implemented: {self.header.type}")

    def entries(self) -> Iterator[DBT]:
        """Iterate over all entries in the page."""
        if not self.header.entries:
            raise TypeError("Page doesn't have iterable entries")

        for idx in range(self.header.entries):
            yield self.entry(idx)


def overflow_data(db: DB, pgno: int, size: int) -> bytes:
    """Get off-page data.

    References:
        - ``__db_goff``

    Args:
        db: The parent ``DB`` instance.
        pgno: The starting page number of the overflow data.
        size: The total size of the overflow data to read.
    """
    result = []
    while size > 0 and pgno != c_db.PGNO_INVALID:
        page = db.page(pgno)
        if page.type != c_db.P_OVERFLOW:
            raise ValueError(f"Expected overflow page, got {page.type} (pgno={pgno})")

        read_size = min(size, page.header.hf_offset)
        result.append(page.data[:read_size])
        size -= read_size

        pgno = page.header.next_pgno

    return b"".join(result)


def _db_log2(num: int) -> int:
    i = 0
    limit = 1
    while limit < num:
        i += 1
        limit = limit << 1

    return i


def BS_TO_PAGE(bucket: int, spares: list[int]) -> int:
    return bucket + spares[_db_log2(bucket + 1)]


def BUCKET_TO_PAGE(db: DB, bucket: int) -> int:
    return BS_TO_PAGE(bucket, db.meta.spares)
