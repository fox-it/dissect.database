from __future__ import annotations

import datetime
import struct
from typing import TYPE_CHECKING, Any, NamedTuple, TypeAlias
from uuid import UUID

from dissect.database.ese.c_ese import CODEPAGE, JET_coltyp, c_ese

if TYPE_CHECKING:
    from collections.abc import Callable

CODEPAGE_MAP = {
    CODEPAGE.UNICODE: "utf-16-le",
    CODEPAGE.WESTERN: "cp1252",
    CODEPAGE.ASCII: "ascii",
}


RecordValue: TypeAlias = int | float | str | bytes | datetime.datetime | None


def decode_bit(buf: bytes) -> bool:
    """Decode a bit into a boolean.

    Args:
        buf: The buffer to decode from.
    """
    return c_ese.uint8(buf) == 0xFF


def decode_text(buf: bytes, encoding: CODEPAGE, errors: str | None = "backslashreplace") -> str:
    """Decode text with the appropriate encoding.

    Args:
        buf: The buffer to decode from.
    """
    buf = bytes(buf)

    if encoding == CODEPAGE.UNICODE and len(buf) % 2:
        buf += b"\x00"

    return buf.decode(CODEPAGE_MAP[encoding], errors=errors).rstrip("\x00")


def decode_guid(buf: bytes) -> str:
    """Decode a GUID.

    Args:
        buf: The buffer to decode from.
    """
    return str(UUID(bytes_le=bytes(buf)))


def checksum_xor(data: bytes, initial: int = 0x89ABCDEF) -> int:
    digest = initial
    for val in struct.unpack(f"<{len(data) // 4}I", data):
        digest ^= val

    return digest


class ColumnType(NamedTuple):
    value: JET_coltyp
    name: str
    size: int | None
    parse: Callable[[bytes], Any] | None


COLUMN_TYPES = [
    ColumnType(JET_coltyp.Nil, "NULL", 0, None),
    ColumnType(JET_coltyp.Bit, "Boolean", 1, decode_bit),
    ColumnType(JET_coltyp.UnsignedByte, "Unsigned byte", 1, c_ese.uint8),
    ColumnType(JET_coltyp.Short, "Signed short", 2, c_ese.int16),
    ColumnType(JET_coltyp.Long, "Signed long", 4, c_ese.int32),
    ColumnType(JET_coltyp.Currency, "Currency", 8, c_ese.int64),
    ColumnType(JET_coltyp.IEEESingle, "Single precision FP", 4, c_ese.float),
    ColumnType(JET_coltyp.IEEEDouble, "Double precision FP", 8, c_ese.double),
    # Parse DateTime as an int64 because the actual parsing of the value can differ between databases
    # E.g. by default it's supposed to be an OA date, but the UAL stores it as a regular Windows timestamp
    ColumnType(JET_coltyp.DateTime, "DateTime", 8, c_ese.int64),
    ColumnType(JET_coltyp.Binary, "Binary", None, bytes),
    ColumnType(JET_coltyp.Text, "Text", None, decode_text),
    ColumnType(JET_coltyp.LongBinary, "Long Binary", None, bytes),
    ColumnType(JET_coltyp.LongText, "Long Text", None, decode_text),
    ColumnType(JET_coltyp.SLV, "Super Long Value", None, None),
    ColumnType(JET_coltyp.UnsignedLong, "Unsigned long", 4, c_ese.uint32),
    ColumnType(JET_coltyp.LongLong, "Signed Long long", 8, c_ese.int64),
    ColumnType(JET_coltyp.GUID, "GUID", 16, decode_guid),
    ColumnType(JET_coltyp.UnsignedShort, "Unsigned short", 2, c_ese.uint16),
    ColumnType(JET_coltyp.Max, "Max", None, None),
]
COLUMN_TYPE_MAP = {t.value.value: t for t in COLUMN_TYPES}
