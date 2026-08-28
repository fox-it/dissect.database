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
        self._checksum_struct = struct.Struct(f"{self.checksum_endian}2I")

        self.frame = lru_cache(1024)(self.frame)
        self.frame_size = len(c_sqlite3.wal_frame) + self.header.page_size
        self.first_frame_offset = len(c_sqlite3.wal_header)

        # Only track the highest valid offset and its seed.
        # Meaning: all frames with offset < _highest_valid_next_offset are considered valid.
        # _highest_valid_next_offset initially points at the first frame; seed is checksum over header.
        self._highest_valid_next_offset: int = self.first_frame_offset
        self._highest_valid_seed: tuple[int, int] = self.header_checksum_seed

        # First offset that is known to fail checksum validation, or None.
        self._checksum_failed_offset: int | None = None

        self.highest_page_num = max(
            fr.page_number for commit in self.commits for fr in commit.frames if fr.is_valid_salt()
        )

    def close(self) -> None:
        """Close the WAL."""
        # Only close WAL handle if we opened it using a path
        if self.path is not None:
            self.fh.close()

    def frame(self, frame_idx: int) -> Frame:
        offset = self.first_frame_offset + frame_idx * self.frame_size
        return Frame(self, offset)

    def frames(self) -> Iterator[Frame]:
        frame_idx = 0
        while True:
            try:
                yield self.frame(frame_idx)
                frame_idx += 1
            except EOFError:  # noqa: PERF203
                break

    def seed_for_offset(self, offset: int) -> tuple[int, int] | None:
        """Return checksum seed after processing frames up to and including the frame at target_offset.

        Verify stored checksums for each frame as we walk. If a mismatch is found, update the WAL's
        highest-known-valid-next-offset and return None. On success (no mismatches) update the
        highest-known-valid-next-offset and seed and return the computed seed.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
            - https://github.com/sqlite/sqlite/blob/master/src/wal.c#L995-L1047
        """
        # If the target offset is before the first frame, return the initial seed calculated from the WAL header.
        if offset < self.first_frame_offset:
            return self.header_checksum_seed

        # If the target offset is at or beyond the first known checksum failure, return None.
        if self._checksum_failed_offset is not None and offset >= self._checksum_failed_offset:
            return None

        # Start from the highest verified offset we know (saves re-checking earlier frames).
        current_offset = self._highest_valid_next_offset
        seed = self._highest_valid_seed

        while current_offset <= offset:
            # Read frame header
            self.fh.seek(current_offset)
            frame_hdr_bytes = self.fh.read(len(c_sqlite3.wal_frame))
            if len(frame_hdr_bytes) < len(c_sqlite3.wal_frame):
                raise EOFError("Incomplete frame header while calculating checksum")

            # Checksum first 16 bytes of frame header
            seed = calculate_checksum(frame_hdr_bytes[:16], seed=seed, endian=self.checksum_endian)

            # Read and checksum page data
            page_data = self.fh.read(self.header.page_size)
            if len(page_data) < self.header.page_size:
                raise EOFError("Incomplete page data while calculating checksum")
            seed = calculate_checksum(page_data, seed=seed, endian=self.checksum_endian)

            # Compare computed seed to stored checksums in this frame header.
            checksum1, checksum2 = self._checksum_struct.unpack(frame_hdr_bytes[-8:])
            if (seed[0], seed[1]) != (checksum1, checksum2):
                self._checksum_failed_offset = current_offset
                return None

            current_offset += self.frame_size

        # Update highest-known-valid-next-offset and seed to the next offset after target.
        self._highest_valid_next_offset = current_offset
        self._highest_valid_seed = seed

        return seed

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

    @cached_property
    def header_checksum_seed(self) -> tuple[int, int]:
        """Cached initial checksum seed calculated from the WAL header first 24 bytes."""
        return calculate_checksum(self.header.dumps()[:24], endian=self.checksum_endian)


class Frame:
    def __init__(self, wal: WAL, offset: int):
        self.wal = wal
        self.offset = offset

        self.fh = wal.fh

        self.fh.seek(offset)
        self.header = c_sqlite3.wal_frame(self.fh)

    def __repr__(self) -> str:
        return f"<Frame page_number={self.page_number} page_count={self.page_count}>"

    def is_valid(self, validate_checksums: bool = True) -> bool:
        """Return whether the frame is valid by comparing its salt values and optionally verifying the checksum.

        A frame is valid if:
            - Its salt1 and salt2 values match those in the WAL header.
            - Its checksum matches the calculated checksum.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        return (self.is_valid_salt() and self.is_valid_checksum()) if validate_checksums else self.is_valid_salt()

    def is_valid_salt(self) -> bool:
        """Return whether the frame's salt values match those in the WAL header.

        References:
            - https://sqlite.org/fileformat2.html#wal_file_format
        """
        salt1_match = self.header.salt1 == self.wal.header.salt1
        salt2_match = self.header.salt2 == self.wal.header.salt2

        return salt1_match and salt2_match

    def is_valid_checksum(self) -> bool:
        """Return whether the frame's checksum matches the calculated checksum.

        Use WAL's highest valid offset to skip checks for already-verified frames.
        """
        if self.offset < self.wal._highest_valid_next_offset:
            return True

        seed = self.wal.seed_for_offset(self.offset)
        return seed is not None

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


def calculate_checksum(buf: bytes, seed: tuple[int, int] = (0, 0), endian: str = ">") -> tuple[int, int]:
    """Calculate the checksum of a WAL header or frame.

    References:
        - https://sqlite.org/fileformat2.html#checksum_algorithm
    """
    s0, s1 = seed
    num_ints = len(buf) // 4
    arr = struct.unpack(f"{endian}{num_ints}I", buf)

    for int_num in range(0, num_ints, 2):
        s0 = (s0 + (arr[int_num] + s1)) & 0xFFFFFFFF
        s1 = (s1 + (arr[int_num + 1] + s0)) & 0xFFFFFFFF

    return s0, s1
