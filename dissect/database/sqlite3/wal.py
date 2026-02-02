from __future__ import annotations

import logging
import os
import struct
from functools import cached_property, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.database.sqlite3.c_sqlite3 import c_sqlite3
from dissect.database.sqlite3.exception import InvalidDatabase

if TYPE_CHECKING:
    from collections.abc import Iterator

log = logging.getLogger(__name__)
log.setLevel(os.getenv("DISSECT_LOG_SQLITE3", "CRITICAL"))

# See https://sqlite.org/fileformat2.html#wal_file_format
WAL_HEADER_MAGIC_LE = 0x377F0682
WAL_HEADER_MAGIC_BE = 0x377F0683
WAL_HEADER_MAGIC = {WAL_HEADER_MAGIC_LE, WAL_HEADER_MAGIC_BE}


class WAL:
    def __init__(self, fh: Path | BinaryIO):
        # Use the provided WAL file handle or try to open a sidecar WAL file.
        if isinstance(fh, Path):
            path = fh
            fh = path.open("rb")
        else:
            path = None

        self.fh = fh
        self.path = path
        self.header = c_sqlite3.wal_header(fh)

        if self.header.magic not in WAL_HEADER_MAGIC:
            raise InvalidDatabase("Invalid WAL header magic")

        self.checksum_endian = "<" if self.header.magic == WAL_HEADER_MAGIC_LE else ">"

        self.frame = lru_cache(1024)(self.frame)

    def close(self) -> None:
        """Close the WAL."""
        # Only close WAL handle if we opened it using a path
        if self.path is not None:
            self.fh.close()

    def frame(self, frame_idx: int) -> Frame:
        frame_size = len(c_sqlite3.wal_frame) + self.header.page_size
        offset = len(c_sqlite3.wal_header) + frame_idx * frame_size
        return Frame(self, offset)

    def frames(self) -> Iterator[Frame]:
        frame_idx = 0
        while True:
            try:
                yield self.frame(frame_idx)
                frame_idx += 1
            except EOFError:  # noqa: PERF203
                break

    @cached_property
    def commits(self) -> list[Commit]:
        """Return all commits in the WAL file.

        Commits are frames where ``header.page_count`` specifies the size of the
        database file in pages after the commit. For all other frames it is 0.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        commits = []
        frames = []

        for frame in self.frames():
            frames.append(frame)

            # A commit record has a page_count header greater than zero
            if frame.page_count > 0:
                commits.append(Commit(self, frames))
                frames = []

        if frames:
            # TODO: Do we want to track these somewhere?
            log.warning("Found leftover %d frames after the last WAL commit", len(frames))

        return commits

    @cached_property
    def checkpoints(self) -> list[Checkpoint]:
        """Return deduplicated checkpoints, oldest first.

        Deduplicate commits by the ``salt1`` value of their first frame. Later
        commits overwrite earlier ones so the returned list contains the most
        recent commit for each ``salt1``, sorted ascending.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
            - https://sqlite.org/wal.html#checkpointing
        """
        checkpoints_map: dict[int, Checkpoint] = {}
        for commit in self.commits:
            if not commit.frames:
                continue
            salt1 = commit.frames[0].header.salt1
            # Keep the most recent commit for each salt1 (later commits overwrite).
            checkpoints_map[salt1] = commit

        return [checkpoints_map[salt] for salt in sorted(checkpoints_map.keys())]


class Frame:
    def __init__(self, wal: WAL, offset: int):
        self.wal = wal
        self.offset = offset

        self.fh = wal.fh

        self.fh.seek(offset)
        self.header = c_sqlite3.wal_frame(self.fh)

    def __repr__(self) -> str:
        return f"<Frame page_number={self.page_number} page_count={self.page_count}>"

    @property
    def valid(self) -> bool:
        salt1_match = self.header.salt1 == self.wal.header.salt1
        salt2_match = self.header.salt2 == self.wal.header.salt2

        return salt1_match and salt2_match

    @property
    def data(self) -> bytes:
        self.fh.seek(self.offset + len(c_sqlite3.wal_frame))
        return self.fh.read(self.wal.header.page_size)

    @property
    def page_number(self) -> int:
        return self.header.page_number

    @property
    def page_count(self) -> int:
        return self.header.page_count


class _FrameCollection:
    """Convenience class to keep track of a collection of frames that were committed together."""

    def __init__(self, wal: WAL, frames: list[Frame]):
        self.wal = wal
        self.frames = frames

    def __contains__(self, page: int) -> bool:
        return page in self.page_map

    def __getitem__(self, page: int) -> Frame:
        return self.page_map[page]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} frames={len(self.frames)}>"

    @cached_property
    def page_map(self) -> dict[int, Frame]:
        return {frame.page_number: frame for frame in self.frames}

    def get(self, page: int, default: Any = None) -> Frame:
        return self.page_map.get(page, default)


class Checkpoint(_FrameCollection):
    """A checkpoint is an operation that transfers all committed transactions from
    the WAL file back into the main database file.

    References:
        - https://sqlite.org/fileformat2.html#wal_file_format
    """


class Commit(_FrameCollection):
    """A commit is a collection of frames that were committed together.

    References:
        - https://sqlite.org/fileformat2.html#wal_file_format
    """


def checksum(buf: bytes, endian: str = ">") -> tuple[int, int]:
    s0 = s1 = 0
    num_ints = len(buf) // 4
    arr = struct.unpack(f"{endian}{num_ints}I", buf)

    for int_num in range(0, num_ints, 2):
        s0 = (s0 + (arr[int_num] + s1)) & 0xFFFFFFFF
        s1 = (s1 + (arr[int_num + 1] + s0)) & 0xFFFFFFFF

    return s0, s1
