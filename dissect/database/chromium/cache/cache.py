from __future__ import annotations

import gzip
import zlib
from typing import TYPE_CHECKING

from cramjam import brotli
from dissect.cstruct.utils import u32
from dissect.util.stream import RangeStream
from dissect.util.ts import webkittimestamp

from dissect.database.chromium.cache.c_cache import BlockSizeForFileType, c_cache

if TYPE_CHECKING:
    from collections.abc import Iterator
    from io import BufferedReader
    from pathlib import Path


class DiskCache:
    """Chromium Disk (Block File) Cache implementation.

    References:
        - https://www.chromium.org/developers/design-documents/network-stack/disk-cache/
        - https://github.com/libyal/dtformats/blob/main/documentation/Chrome%20Cache%20file%20format.asciidoc
    """

    def __init__(self, path: Path):
        if not path.exists():
            raise ValueError(f"Provided path does not exist: {path!r}")

        if not path.is_dir():
            raise ValueError(f"Provided path is not a directory: {path!r}")

        # Sanity check for expected directory structure.
        files = {"index", "data_0", "data_1", "data_2", "data_3"}
        self.children = set(path.iterdir())
        if not files.issubset({file.name for file in self.children}):
            raise ValueError(f"Provided directory does not contain expected disk cache files: {path!r}")

        self.path = path
        self.index = CacheIndexFile(self, path.joinpath("index"))

        if self.index.header.magic != 0xC103CAC3:
            raise ValueError(f"Provided directory contains invalid index file: {path!r}")

        if self.index.header.version != 0x30000:
            raise ValueError(f"Unsupported Disk Cache index version {self.index.header.version!r} in {path!r}")

        self.create_time = webkittimestamp(self.index.header.create_time)
        self.num_entries = self.index.header.num_entries

        self.block_files = [
            CacheBlockFile(self, path.joinpath(name)) for name in ("data_0", "data_1", "data_2", "data_3")
        ]

    def __repr__(self) -> str:
        return f"<DiskCache path='{self.path!s}' create_time={self.create_time!s} entries={self.num_entries!r}>"

    def block_file(self, id: int) -> CacheBlockFile | None:
        for block_file in self.block_files:
            if block_file.id == id:
                return block_file
        return None

    @property
    def entries(self) -> Iterator[CacheEntryStore]:
        for address in self.index.addresses:
            while address.is_initialized:
                entry = CacheEntryStore(self, address)
                yield entry

                # An EntryStore can point to a next address for another EntryStore
                if entry.next != 0:
                    address = CacheAddress(self.index, entry.next)
                else:
                    break


class CacheIndexFile:
    """Chromium Disk Cache Index file.

    References:
        - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/blockfile/disk_format.h
    """

    def __init__(self, disk_cache: DiskCache, path: Path):
        self.disk_cache = disk_cache
        self.path = path

        self.fh = path.open("rb")
        self.header = c_cache.IndexHeader(self.fh)

    def __repr__(self) -> str:
        return f"<CacheIndexFile path='{self.path!s}' addresses={len([a for a in self.addresses if a.address])!r}>"

    @property
    def addresses(self) -> Iterator[CacheAddress]:
        """Yield :class:`CacheAddress` from the index table."""

        if hasattr(self, "_addresses"):
            yield from self._addresses
            return

        self._addresses = []

        for _ in range(self.header.table_len):
            addr = CacheAddress(self, u32(self.fh.read(4)))
            self._addresses.append(addr)
            yield addr

    # TODO: get(address)?


class CacheBlockFile:
    """Chromium Disk Cache Data Block file.

    References:
        - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/blockfile/disk_format.h
    """

    def __init__(self, disk_cache: DiskCache, path: Path):
        self.disk_cache = disk_cache
        self.path = path

        self.fh = path.open("rb")
        self.header = c_cache.BlockFileHeader(self.fh)

        self.id = self.header.this_file
        self.entry_size = self.header.entry_size
        self.num_entries = self.header.num_entries

    def __repr__(self) -> str:
        return f"<CacheBlockFile path='{self.path!s}' id={self.id!r} num_entries={self.num_entries!r} entry_size={self.entry_size!r}>"  # noqa: E501

    def read(self, addr: CacheAddress) -> RangeStream:
        offset = c_cache.kBlockHeaderSize + (self.entry_size * addr.start_block)
        size = self.entry_size * addr.num_blocks
        return RangeStream(self.fh, offset, size)


class CacheAddress:
    """Chromium Disk Cache Address.

    References:
        - https://chromium.googlesource.com/chromium/src/+/HEAD/net/disk_cache/blockfile/addr.h
    """

    def __init__(self, index: CacheIndexFile, addr: int):
        self.index = index
        self.address = addr

        self.is_initialized = addr & c_cache.kInitializedMask != 0
        self.file_type = c_cache.FileType((addr & c_cache.kFileTypeMask) >> c_cache.kFileTypeOffset)
        self.is_separate_file = (addr & c_cache.kFileTypeMask) == 0
        self.is_block_file = not self.is_separate_file

        if self.is_separate_file:
            self.file_number = addr & c_cache.kFileNameMask
            self.block_size = None
            self.num_blocks = None
            self.start_block = None
        else:
            self.file_number = (addr & c_cache.kFileSelectorMask) >> c_cache.kFileSelectorOffset
            self.block_size = BlockSizeForFileType(self.file_type.value)
            self.num_blocks = 1 + ((addr & c_cache.kNumBlocksMask) >> c_cache.kNumBlocksOffset)
            self.start_block = addr & c_cache.kStartBlockMask

    def __repr__(self) -> str:
        return f"<CacheAddress address=0x{self.address:x} is_initialized={self.is_initialized!r} file_type={self.file_type.name!r} file_number={self.file_number!r} start_block={self.start_block!r} num_blocks={self.num_blocks!r} block_size={self.block_size!r}>"  # noqa: E501

    @property
    def data(self) -> BufferedReader | RangeStream:
        if not self.is_initialized:
            raise ValueError("Cannot read data from non initialized address")

        if self.file_type == c_cache.FileType.EXTERNAL:
            file_name = f"f_{self.file_number:06x}"
            path = self.index.disk_cache.path.joinpath(file_name)
            return path.open("rb")

        if self.file_type in (c_cache.FileType.BLOCK_256, c_cache.FileType.BLOCK_1K, c_cache.FileType.BLOCK_4K):
            block_file = self.index.disk_cache.block_file(self.file_number)
            if not block_file:
                raise ValueError(f"Requested block file {self.file_number!r} does not exist")
            return block_file.read(self)

        raise ValueError(f"No data for file type {self.file_type!r}")


class CacheEntryStore:
    """Represents a Cache EntryStore object."""

    def __init__(self, disk_cache: DiskCache, addr: CacheAddress):
        self.disk_cache = disk_cache
        self.address = addr

        self.header = c_cache.EntryStore(self.address.data)
        self.state = c_cache.EntryState(self.header.state)
        self.creation_time = webkittimestamp(self.header.creation_time)
        self.next = self.header.next

        if self.header.long_key:
            key_addr = CacheAddress(disk_cache.index, self.header.long_key)
            self.key = key_addr.data.read(self.header.key_len).decode()
        else:
            self.key = self.header.key.decode().strip("\x00")

    def __repr__(self):
        return f"<CacheEntryStore address=0x{self.address.address:x} state={self.state.name!r} creation_time={self.creation_time!s} key={self.key!r} next={self.next!r}>"  # noqa: E501

    @property
    def meta(self) -> bytes:
        addr = CacheAddress(self.disk_cache.index, self.header.data_addr[0])
        # TODO: Properly unpickle, contains a treasure of data.
        return addr.data.read()

    @property
    def data(self) -> bytes:
        addr = CacheAddress(self.disk_cache.index, self.header.data_addr[1])
        header = addr.data.read(4)

        if header[0:2] == b"\x1f\x8b":
            return gzip.decompress(addr.data.read())

        meta = self.meta
        if b"content-encoding:br" in meta:
            return brotli.decompress(addr.data.read()).read()

        if b"content-encoding:deflate" in meta:
            return zlib.decompress(addr.data.read(), -zlib.MAX_WBITS)

        return addr.data.read()
