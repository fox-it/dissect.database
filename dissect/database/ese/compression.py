from __future__ import annotations

import struct
from typing import Final

from dissect.util.compression import lz4, lzxpress, lzxpress9, sevenbit
from dissect.util.hash import crc32c as _crc32c_mod
from dissect.util.hash.crc64 import crc64 as _crc64_nvme

from dissect.database.ese.c_ese import COMPRESSION_SCHEME

_crc32c = _crc32c_mod.crc32c

# --- ESE record header sizes ---

_XPRESS9_HEADER_SIZE: Final = 5
"""Scheme byte + u32 LE plaintext CRC-32C (compression.cxx:1691)."""

_XPRESS10_HEADER_SIZE: Final = 15
"""Scheme byte + u16 LE size + u32 LE CRC-32C + u64 LE CRC-64 (compression.cxx:1940)."""

_LZ4_HEADER_SIZE: Final = 3
"""Scheme byte + u16 LE uncompressed size (compression.cxx:2083)."""

_XPRESS_HEADER_SIZE: Final = 3
"""Scheme byte + u16 LE uncompressed size (compression.cxx:1528)."""

_XPRESS10_HEADER: Final = struct.Struct("<BHIQ")
_LZ4_HEADER: Final = struct.Struct("<BH")


def decompress(buf: bytes, *, verify: bool = True) -> bytes:
    """Decompress the given bytes according to the encoded compression scheme.

    Handles all seven ESE record compression formats:
    ``COMPRESS_7BITASCII`` (0x1), ``COMPRESS_7BITUNICODE`` (0x2),
    ``COMPRESS_XPRESS`` (0x3), ``COMPRESS_SCRUB`` (0x4),
    ``COMPRESS_XPRESS9`` (0x5), ``COMPRESS_XPRESS10`` (0x6),
    and ``COMPRESS_LZ4`` (0x7).

    Args:
        buf: The compressed bytes to decompress.
        verify: When True, verify integrity checks on formats that carry them:
            decoded-size match for XPRESS, CRC-32C for XPRESS9, CRC-64 and
            CRC-32C for XPRESS10. LZ4 has no checksum. When False, skip all
            integrity checks for speed or corrupt-data recovery.

    Raises:
        ValueError: If the buffer is a SCRUB erase marker or an integrity
            check fails (when ``verify`` is True).
    """
    identifier = buf[0] >> 3

    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITASCII:
        return sevenbit.decompress(buf[1:])

    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITUNICODE:
        return sevenbit.decompress(buf[1:], wide=True)

    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS:
        return _decompress_xpress(buf, verify=verify)

    if identifier == COMPRESSION_SCHEME.COMPRESS_SCRUB:
        raise ValueError("Record is a SCRUB erase marker: no plaintext is recoverable")

    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS9:
        return _decompress_xpress9(buf, verify=verify)

    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS10:
        return _decompress_xpress10(buf, verify=verify)

    if identifier == COMPRESSION_SCHEME.COMPRESS_LZ4:
        return _decompress_lz4(buf)

    return buf


def decompress_size(buf: bytes) -> int | None:
    """Return the decompressed size of the given bytes according to the encoded compression scheme.

    Args:
        buf: The compressed bytes to return the decompressed size of.

    Raises:
        ValueError: If the buffer is a SCRUB erase marker.
    """
    identifier = buf[0] >> 3

    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITASCII:
        # Low 3 header bits hold the valid bit count of the final packed byte
        # (compression.cxx:2135-2137); the rest are full 8-bit bytes.
        return ((len(buf) - 2) * 8 + (buf[0] & 7) + 1) // 7

    if identifier == COMPRESSION_SCHEME.COMPRESS_7BITUNICODE:
        return 2 * (((len(buf) - 2) * 8 + (buf[0] & 7) + 1) // 7)

    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS:
        return struct.unpack("<H", buf[1:3])[0]

    if identifier == COMPRESSION_SCHEME.COMPRESS_SCRUB:
        raise ValueError("Record is a SCRUB erase marker: no decompressed size")

    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS9:
        return lzxpress9.decompressed_size(buf[_XPRESS9_HEADER_SIZE:])

    if identifier == COMPRESSION_SCHEME.COMPRESS_XPRESS10:
        return struct.unpack_from("<H", buf, 1)[0]

    if identifier == COMPRESSION_SCHEME.COMPRESS_LZ4:
        return struct.unpack_from("<H", buf, 1)[0]

    return None


def _decompress_xpress(buf: bytes, *, verify: bool = True) -> bytes:
    """Decompress an XPRESS (0x3) cell: 3-byte ESE header + Plain LZ77 stream.

    When ``verify`` is True, checks that the decoded length matches the
    header's declared uncompressed size (compression.cxx:2316-2322).
    """
    declared = struct.unpack("<H", buf[1:3])[0]
    plaintext = lzxpress.decompress(buf[_XPRESS_HEADER_SIZE:], max_size=declared)
    if verify and len(plaintext) != declared:
        raise ValueError(f"XPRESS decoded {len(plaintext)} bytes but header declares {declared}")
    return plaintext


def _decompress_xpress9(buf: bytes, *, verify: bool = True) -> bytes:
    """Decompress an XPRESS9 (0x5) cell: 5-byte ESE header + XPRESS9 blocks.

    When ``verify`` is True, checks the CRC-32C of the plaintext against
    the value stored in the header (compression.cxx:2461-2467).
    """
    stored_crc = struct.unpack_from("<I", buf, 1)[0]
    plaintext = lzxpress9.decompress(buf[_XPRESS9_HEADER_SIZE:])
    if verify:
        actual_crc = _crc32c(plaintext)
        if actual_crc != stored_crc:
            raise ValueError(f"XPRESS9 plaintext CRC-32C mismatch: 0x{stored_crc:08x} vs 0x{actual_crc:08x}")
    return plaintext


def _decompress_xpress10(buf: bytes, *, verify: bool = True) -> bytes:
    """Decompress an XPRESS10 (0x6) cell: 15-byte ESE header + LZ4 block.

    When ``verify`` is True, checks the CRC-64/NVME of the compressed payload
    and the CRC-32C of the plaintext (compression.cxx:2513-2530).
    """
    _, size, stored_crc32, stored_crc64 = _XPRESS10_HEADER.unpack_from(buf)
    payload = buf[_XPRESS10_HEADER_SIZE:]

    if verify:
        actual_crc64 = _crc64_nvme(payload)
        if actual_crc64 != stored_crc64:
            raise ValueError(f"XPRESS10 payload CRC-64 mismatch: 0x{stored_crc64:016x} vs 0x{actual_crc64:016x}")

    plaintext = lz4.decompress(payload, size)
    if isinstance(plaintext, tuple):
        plaintext = plaintext[0]

    if verify:
        actual_crc32 = _crc32c(plaintext)
        if actual_crc32 != stored_crc32:
            raise ValueError(f"XPRESS10 plaintext CRC-32C mismatch: 0x{stored_crc32:08x} vs 0x{actual_crc32:08x}")

    return plaintext


def _decompress_lz4(buf: bytes) -> bytes:
    """Decompress an LZ4 (0x7) cell: 3-byte ESE header + LZ4 block.

    LZ4 carries no checksum, so there is nothing to verify.
    """
    _, size = _LZ4_HEADER.unpack_from(buf)
    result = lz4.decompress(buf[_LZ4_HEADER_SIZE:], size)
    if isinstance(result, tuple):
        result = result[0]
    return result
