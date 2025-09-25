# References:
# - https://rpm.org/docs/
from __future__ import annotations

import argparse
import posixpath
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, NamedTuple

from dissect.database.bsd import db
from dissect.database.bsd.tools.c_rpm import c_rpm

if TYPE_CHECKING:
    from collections.abc import Iterator


TYPE_SIZE_MAP = {
    c_rpm.rpmTagType.RPM_NULL_TYPE: 0,
    c_rpm.rpmTagType.RPM_CHAR_TYPE: 1,
    c_rpm.rpmTagType.RPM_INT8_TYPE: 2,
    c_rpm.rpmTagType.RPM_INT16_TYPE: 2,
    c_rpm.rpmTagType.RPM_INT32_TYPE: 4,
    c_rpm.rpmTagType.RPM_INT64_TYPE: 8,
    c_rpm.rpmTagType.RPM_STRING_TYPE: -1,
    c_rpm.rpmTagType.RPM_BIN_TYPE: 1,
    c_rpm.rpmTagType.RPM_STRING_ARRAY_TYPE: -1,
    c_rpm.rpmTagType.RPM_I18NSTRING_TYPE: -1,
}


TYPE_PARSERS = {
    c_rpm.rpmTagType.RPM_NULL_TYPE: lambda _: None,
    c_rpm.rpmTagType.RPM_CHAR_TYPE: c_rpm.char,
    c_rpm.rpmTagType.RPM_INT8_TYPE: c_rpm.uint8,
    c_rpm.rpmTagType.RPM_INT16_TYPE: c_rpm.uint16,
    c_rpm.rpmTagType.RPM_INT32_TYPE: c_rpm.uint32,
    c_rpm.rpmTagType.RPM_INT64_TYPE: c_rpm.uint64,
    c_rpm.rpmTagType.RPM_STRING_TYPE: lambda v: v.split(b"\x00")[0].decode(),
    c_rpm.rpmTagType.RPM_BIN_TYPE: lambda v: v,
    c_rpm.rpmTagType.RPM_STRING_ARRAY_TYPE: lambda v, c: [s.decode() for s in v.split(b"\x00")[:c]],
    c_rpm.rpmTagType.RPM_I18NSTRING_TYPE: lambda v: v.split(b"\x00")[0].decode(),
}

ARRAY_TYPES = (
    c_rpm.rpmTagType.RPM_CHAR_TYPE,
    c_rpm.rpmTagType.RPM_INT8_TYPE,
    c_rpm.rpmTagType.RPM_INT16_TYPE,
    c_rpm.rpmTagType.RPM_INT32_TYPE,
    c_rpm.rpmTagType.RPM_INT64_TYPE,
)


class PackageEntry(NamedTuple):
    path: str
    size: int
    mode: int
    mtime: int
    user: str
    group: str
    digest: bytes


class File(PackageEntry):
    pass


class Directory(PackageEntry):
    pass


class Package:
    """RPM Package.

    Args:
        buf: Bytes containing the RPM Package header blob.
    """

    def __init__(self, buf: bytes):
        self.blob = HeaderBlob(buf)

    def __repr__(self) -> str:
        return f"<Package name={self.name!r} version={self.version!r} release={self.release!r}>"

    def __iter__(self) -> Iterator[File | Directory]:
        return self.entries()

    @property
    def name(self) -> str:
        """Package name."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_NAME)

    @property
    def version(self) -> str:
        """Package version."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_VERSION)

    @property
    def release(self) -> str:
        """Package release."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_RELEASE)

    @property
    def summary(self) -> str:
        """Package summary."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_SUMMARY)

    @property
    def description(self) -> str:
        """Package description."""
        return self.blob.value(c_rpm.rpmTag.RPMTAG_DESCRIPTION)

    def entries(self) -> Iterator[File | Directory]:
        """Iterate over all files and directories in the package."""
        if c_rpm.rpmTag.RPMTAG_FILESIZES not in self.blob:
            return

        sizes = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILESIZES))
        modes = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEMODES))
        mtimes = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEMTIMES))
        users = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEUSERNAME))
        groups = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEGROUPNAME))
        digests = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_FILEDIGESTS))

        basenames = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_BASENAMES))
        dirnames = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_DIRNAMES))
        dirindex = _as_list(self.blob.value(c_rpm.rpmTag.RPMTAG_DIRINDEXES))

        for i, name in enumerate(basenames):
            dirname = dirnames[dirindex[i]]
            klass = Directory if stat.S_ISDIR(modes[i]) else File
            yield klass(
                posixpath.join(dirname, name),
                sizes[i],
                modes[i],
                mtimes[i],
                users[i],
                groups[i],
                digests[i],
            )


def _as_list(value: Any) -> list[Any]:
    return [value] if not isinstance(value, list) else value


class HeaderBlob:
    """RPM Header Blob.

    Args:
        buf: Bytes containing the RPM Header Blob.
    """

    def __init__(self, buf: bytes):
        self.buf = buf
        self.header = c_rpm.header_intro(self.buf)

        # sizeof(il) + sizeof(dl) + (il * sizeof(pe)) + dl
        self.pvlen = 4 + 4 + (self.header.index_length * len(c_rpm.entryInfo)) + self.header.data_length
        self.data_start = 4 + 4 + (self.header.index_length * len(c_rpm.entryInfo))
        self.data_end = self.data_start + self.header.data_length

        self.tag_map = {e.tag: idx for idx, e in enumerate(self.header.entries)}

    def __contains__(self, tag: c_rpm.rpmTag) -> bool:
        return tag.value in self.tag_map

    def entry(self, idx: int) -> tuple[c_rpm.rpmTag, int | str | bytes | list[int] | list[str] | None]:
        """Get the ``(tag, value)`` for the given index."""
        entry = self.header.entries[idx]

        tag = c_rpm.rpmTag(entry.tag)
        type = c_rpm.rpmTagType(entry.type)

        type_size = TYPE_SIZE_MAP[type]
        if type_size == -1:
            next_entry = self.header.entries[idx + 1] if idx + 1 < self.header.index_length else None
            data_size = (next_entry.offset if next_entry else len(self.buf)) - entry.offset
        else:
            data_size = entry.count * type_size

        data = self.buf[self.data_start + entry.offset : self.data_start + entry.offset + data_size]

        parser = TYPE_PARSERS[type]
        if type in ARRAY_TYPES and entry.count > 1:
            parser = parser[entry.count]

        value = parser(data, entry.count) if type == c_rpm.rpmTagType.RPM_STRING_ARRAY_TYPE else parser(data)
        return tag, value

    def entries(self) -> Iterator[tuple[c_rpm.rpmTag, int | str | bytes | list[int] | list[str] | None]]:
        """Iterate over all ``(tag, value)`` entries in the header."""
        for idx in range(self.header.index_length):
            yield self.entry(idx)

    def value(self, tag: c_rpm.rpmTag) -> int | str | bytes | list[int] | list[str] | None:
        """Get the value for the given tag."""
        if (idx := self.tag_map.get(tag.value)) is None:
            raise IndexError(f"Tag not found: {tag}")
        return self.entry(idx)[1]


class Packages:
    """RPMDB Packages database.

    Args:
        fh: File-like object containing the RPMDB Packages database (a Berkeley DB).
    """

    def __init__(self, fh: BinaryIO):
        self.db = db.DB(fh)

    def __iter__(self) -> Iterator[Package]:
        return self.entries()

    def entries(self) -> Iterator[Package]:
        """Iterate over all packages in the database."""
        for _, data in self.db.records():
            if len(data) > 4:
                yield Package(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path, help="input RPMDB Packages file")
    args = parser.parse_args()

    with args.input.open("rb") as fh:
        db = Packages(fh)
        for package in db.entries():
            print(package)
            for entry in package.entries():
                if isinstance(entry, File):
                    print(f"  FILE {entry.path} {entry.size} bytes")
                elif isinstance(entry, Directory):
                    print(f"  DIR  {entry.path}")
            print()

    return 0


if __name__ == "__main__":
    main()
