from __future__ import annotations

import gzip
import os
import zlib
from enum import IntEnum
from typing import TYPE_CHECKING

from cramjam import brotli
from dissect.util.ts import webkittimestamp

from dissect.database.chromium.cache.c_simple import c_simple

if TYPE_CHECKING:
    from pathlib import Path


class SimpleDiskCache:
    """Chromium Very Simple Disk Cache Backend implementation.

    References:
        - https://www.chromium.org/developers/design-documents/network-stack/disk-cache/very-simple-backend/
        - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/simple/
    """

    def __init__(self, path: Path):
        if not path.exists():
            raise ValueError(f"Provided path does not exist: {path!r}")

        if not path.is_dir():
            raise ValueError(f"Provided path is not a directory: {path!r}")

        # Sanity check for expected directory structure.
        files = {"index-dir", "index"}
        self.children = set(path.iterdir())
        if not files.issubset({file.name for file in self.children}):
            raise ValueError(f"Provided directory does not contain expected disk cache files: {path!r}")

        self.path = path
        self.index = SimpleIndexFile(self, path.joinpath("index-dir/the-real-index"))
        self.cache_files = [
            SimpleCacheFile(self, child) for child in self.children if len(child.name) == 18 and "_" in child.name
        ]

    def __repr__(self) -> str:
        return f"<SimpleDiskCache path='{self.path!s}' cache_files={len(self.cache_files)!r}>"

    def get(self, key: str) -> SimpleCacheFile | None:
        """Return the first matching :class:`SimpleCacheFile` for the given key identifier."""
        for cache_file in self.cache_files:
            if cache_file.key == key:
                return cache_file
        return None


class SimpleIndexFile:
    """Represents a Chromium Very Simple Disk Cache Backend index file."""

    def __init__(self, disk_cache: SimpleDiskCache, path: Path):
        self.disk_cache = disk_cache
        self.path = path

        self.fh = path.open("rb")
        self.header = c_simple.RealIndexHeader(self.fh)

        if self.header.magic != c_simple.kSimpleIndexMagicNumber:
            raise ValueError(f"Unexpected magic header for {path!s}: {self.header.magic!r}")

        self.entries = self.header.entries

        if len(self.entries) != self.header.num_entries:
            raise ValueError(f"Mismatch in amount of expected entries for {path!s}")

        self.last_used = webkittimestamp(self.entries[-1].last_used)

    def __repr__(self):
        return f"<SimpleIndexFile path='{self.path.name!s}' entries={len(self.entries)!r} last_used={self.last_used!s}>"


class SimpleCacheFile:
    """Represents a Chromium Very Simple Disk Cache Backend cache file.

    References:
        - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/simple/simple_entry_format.h
        - https://github.com/schorlet/simplecache
    """

    def __init__(self, disk_cache: SimpleDiskCache, path: Path):
        self.disk_cache = disk_cache
        self.path = path

        self.fh = path.open("rb")
        self.header = c_simple.SimpleFileHeader(self.fh)
        self.header_size = len(self.header.dumps())
        self.type = infer_file_type(self.path.name)
        self.key = self.header.key.decode("latin1")

    def __repr__(self) -> str:
        return f"<SimpleCacheFile key={self.key!r} type={self.type.name!r} path='{self.path.name!s}'>"

    def _streams(self) -> None:
        """Parse the stream(s) of this Simple Cache File."""

        if self.type == SimpleFileType.STREAM_0_1:
            # We read backwards in the file handle (stream 0 is positioned after stream 1).

            # Stream 0
            self.fh.seek(-c_simple.kSimpleEOFSize, os.SEEK_END)
            eof = c_simple.SimpleFileEOF(self.fh)
            offset = -c_simple.kSimpleEOFSize - eof.stream_size
            if eof.flags in (2, 3):
                offset -= 32
            self.fh.seek(offset, os.SEEK_END)
            self._meta = self.fh.read(eof.stream_size)

            # Stream 1
            self.fh.seek(-(c_simple.kSimpleEOFSize * 2) - eof.stream_size, os.SEEK_END)
            if eof.flags in (2, 3):
                self.fh.seek(-32, os.SEEK_CUR)
            eof2 = c_simple.SimpleFileEOF(self.fh)
            self.fh.seek(self.header_size)
            self._data = self.fh.read(eof2.stream_size)

        elif self.type == SimpleFileType.STREAM_2:
            # Should be simple
            raise NotImplementedError

        elif self.type == SimpleFileType.STREAM_SPARSE:
            ranges = []
            while True:
                try:
                    range_header = c_simple.SimpleFileSparseRangeHeader(self.fh)
                except EOFError:
                    break

                if range_header.magic != c_simple.kSimpleSparseRangeMagicNumber:
                    break

                offset = self.fh.tell()
                ranges.append((range_header, offset))
                self.fh.seek(offset + range_header.length)

            if len(ranges) > 1:
                raise ValueError("Did not expect another range in sparse stream")

            for range_header, offset in ranges:
                self.fh.seek(offset)
                self._meta = b""
                self._data = self.fh.read(range_header.length)

    @property
    def meta(self) -> bytes:
        if not hasattr(self, "_meta"):
            self._streams()
        return self._meta

    @property
    def data(self) -> bytes:
        if not hasattr(self, "_data"):
            self._streams()

        if self._data[0:2] == b"\x1f\x8b":
            return gzip.decompress(self._data)

        if b"content-encoding:br" in self.meta:
            return brotli.decompress(self._data).read()

        if b"content-encoding:deflate" in self.meta:
            return zlib.decompress(self._data, -zlib.MAX_WBITS)

        return self._data


class SimpleFileType(IntEnum):
    """SimpleFileType enum."""

    STREAM_0_1 = 0
    STREAM_2 = 1
    STREAM_SPARSE = 2


def infer_file_type(file_name: str) -> SimpleFileType:
    """Infer the :class:`SimpleFileType` based on the name of the :class:`SimpleCacheFile`."""

    if file_name.endswith("_0"):
        return SimpleFileType.STREAM_0_1

    if file_name.endswith("_1"):
        return SimpleFileType.STREAM_2

    if file_name.endswith("_s"):
        return SimpleFileType.STREAM_SPARSE

    raise ValueError(f"Unknown SimpleFileType for filename {file_name!r}")
