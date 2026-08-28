from __future__ import annotations

import struct

import pytest

from dissect.database.ese.compression import decompress, decompress_size

# Real ESE cells captured from esent.dll (Server 2022 Build 20348 for 7-bit/XPRESS,
# Win11 Build 26100 for LZ4/XPRESS10) and the MIT ESE C reference encoder (XPRESS9).
# Each cell decompresses to the paired plaintext byte-for-byte.
FOX = b"the quick brown fox jumps over the lazy dog. " * 8
PATTERN = bytes(0x41 + ((i + 1) % 26) for i in range(4096))

CELLS = [
    pytest.param("0f54741914afa7c76b9058febebb41", b"The quick brown ", id="7bit_ascii"),
    pytest.param("1700000000000000", b"\x00" * 16, id="7bit_unicode"),
    pytest.param("180004ffffff3f000007000ffffb03", b"\x00" * 1024, id="xpress"),
    pytest.param(
        "28f83ea8df2ad7864e68010000d00200001b00060000000000eeadd4ba0000000015cc7f96000000e0c28229028e5c5932668d80"
        "1127f6dcd92160c69e0702565cd972e08c803d37a69c107061c114011b86bc782260c29e39ba1addfe6d6f",
        FOX,
        id="xpress9",
    ),
    pytest.param(
        "300010dc7a8d3d64ac36a16f0def11ff0b42434445464748494a4b4c4d4e4f505152535455565758595a411a00ffffffffffffffffff"
        "ffffffffffffdd504b4c4d4e4f",
        PATTERN,
        id="xpress10",
    ),
    pytest.param("3800041f000100ffffffea500000000000", b"\x00" * 1024, id="lz4"),
]


@pytest.mark.parametrize(("cell", "plain"), CELLS)
def test_decompress(cell: str, plain: bytes) -> None:
    assert decompress(bytes.fromhex(cell)) == plain


@pytest.mark.parametrize(("cell", "plain"), CELLS)
def test_decompress_size(cell: str, plain: bytes) -> None:
    assert decompress_size(bytes.fromhex(cell)) == len(plain)


@pytest.mark.parametrize(("cell", "plain"), CELLS)
def test_decompress_no_verify(cell: str, plain: bytes) -> None:
    assert decompress(bytes.fromhex(cell), verify=False) == plain


def test_decompress_uncompressed() -> None:
    # Scheme 0x0 (COMPRESS_NONE) is returned unchanged.
    buf = b"\x00raw uncompressed data"
    assert decompress(buf) == buf
    assert decompress_size(buf) is None


def test_decompress_scrub() -> None:
    # Scheme 0x4 (COMPRESS_SCRUB) is an erase marker with no recoverable data.
    scrub = bytes([0x4 << 3]) + b"LLLL"
    with pytest.raises(ValueError, match="SCRUB"):
        decompress(scrub)
    with pytest.raises(ValueError, match="SCRUB"):
        decompress_size(scrub)


def test_xpress9_crc_mismatch() -> None:
    cell = bytearray.fromhex(
        "28f83ea8df2ad7864e68010000d00200001b00060000000000eeadd4ba0000000015cc7f96000000e0c28229028e5c5932668d80"
        "1127f6dcd92160c69e0702565cd972e08c803d37a69c107061c114011b86bc782260c29e39ba1addfe6d6f"
    )
    cell[1] ^= 0xFF  # corrupt the stored plaintext CRC-32C

    with pytest.raises(ValueError, match="XPRESS9 plaintext CRC-32C mismatch"):
        decompress(bytes(cell))

    # verify=False skips the CRC check and still returns the plaintext.
    assert decompress(bytes(cell), verify=False) == FOX


def test_xpress10_crc64_mismatch() -> None:
    cell = bytearray.fromhex(
        "300010dc7a8d3d64ac36a16f0def11ff0b42434445464748494a4b4c4d4e4f505152535455565758595a411a00ffffffffffffffffff"
        "ffffffffffffdd504b4c4d4e4f"
    )
    cell[7] ^= 0xFF  # corrupt the payload CRC-64

    with pytest.raises(ValueError, match="XPRESS10 payload CRC-64 mismatch"):
        decompress(bytes(cell))

    assert decompress(bytes(cell), verify=False) == PATTERN


def test_xpress10_crc32_mismatch() -> None:
    cell = bytearray.fromhex(
        "300010dc7a8d3d64ac36a16f0def11ff0b42434445464748494a4b4c4d4e4f505152535455565758595a411a00ffffffffffffffffff"
        "ffffffffffffdd504b4c4d4e4f"
    )
    cell[3] ^= 0xFF  # corrupt the stored plaintext CRC-32C

    with pytest.raises(ValueError, match="XPRESS10 plaintext CRC-32C mismatch"):
        decompress(bytes(cell))

    assert decompress(bytes(cell), verify=False) == PATTERN


def test_xpress_size_mismatch() -> None:
    # A header claiming more plaintext than the stream decodes to fails under verify.
    cell = bytearray.fromhex("180004ffffff3f000007000ffffb03")
    struct.pack_into("<H", cell, 1, 2048)  # header says 2048, stream yields 1024

    with pytest.raises(ValueError, match="XPRESS decoded"):
        decompress(bytes(cell))

    assert len(decompress(bytes(cell), verify=False)) == 1024
