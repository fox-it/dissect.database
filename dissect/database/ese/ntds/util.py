from __future__ import annotations

from enum import IntFlag
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.util.sid import read_sid, write_sid
from dissect.util.ts import wintimestamp

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.ntds import NTDS


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa
OID_TO_TYPE = {
    "2.5.5.1": "b",  # DN
    "2.5.5.2": "c",  # OID
    "2.5.5.3": "d",  # CaseExactString
    "2.5.5.4": "e",  # CaseIgnoreString
    "2.5.5.5": "f",  # IA5String
    "2.5.5.6": "g",  # NumericString
    "2.5.5.7": "h",  # DNWithBinary
    "2.5.5.8": "i",  # Boolean
    "2.5.5.9": "j",  # Integer
    "2.5.5.10": "k",  # OctetString
    "2.5.5.11": "l",  # GeneralizedTime
    "2.5.5.12": "m",  # UnicodesString
    "2.5.5.13": "n",  # PresentationAddress
    "2.5.5.14": "o",  # DNWithString
    "2.5.5.15": "p",  # NTSecurityDescriptor
    "2.5.5.16": "q",  # LargeInteger
    "2.5.5.17": "r",  # Sid
}


OID_PREFIX = {
    0x00000000: "2.5.4",
    0x00010000: "2.5.6",
    0x00020000: "1.2.840.113556.1.2",
    0x00030000: "1.2.840.113556.1.3",
    0x00080000: "2.5.5",
    0x00090000: "1.2.840.113556.1.4",
    0x000A0000: "1.2.840.113556.1.5",
    0x00140000: "2.16.840.1.113730.3",
    0x00150000: "0.9.2342.19200300.100.1",
    0x00160000: "2.16.840.1.113730.3.1",
    0x00170000: "1.2.840.113556.1.5.7000",
    0x00180000: "2.5.21",
    0x00190000: "2.5.18",
    0x001A0000: "2.5.20",
    0x001B0000: "1.3.6.1.4.1.1466.101.119",
    0x001C0000: "2.16.840.1.113730.3.2",
    0x001D0000: "1.3.6.1.4.1.250.1",
    0x001E0000: "1.2.840.113549.1.9",
    0x001F0000: "0.9.2342.19200300.100.4",
    0x00200000: "1.2.840.113556.1.6.23",
    0x00210000: "1.2.840.113556.1.6.18.1",
    0x00220000: "1.2.840.113556.1.6.18.2",
    0x00230000: "1.2.840.113556.1.6.13.3",
    0x00240000: "1.2.840.113556.1.6.13.4",
    0x00250000: "1.3.6.1.1.1.1",
    0x00260000: "1.3.6.1.1.1.2",
    0x46080000: "1.2.840.113556.1.8000.2554",  # commonly used for custom attributes
}


def attrtyp_to_oid(value: int) -> str:
    """Return the OID from an ATTRTYP 32-bit integer value.

    Example for attribute ``printShareName``::

        ATTRTYP: 590094 (hex: 0x9010e) -> 1.2.840.113556.1.4.270

    Args:
        value: The ATTRTYP 32-bit integer value to convert.

    Returns:
        The OID string representation.
    """
    return f"{OID_PREFIX[value & 0xFFFF0000]:s}.{value & 0x0000FFFF:d}"


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
class InstanceType(IntFlag):
    HeadOfNamingContext = 0x00000001
    ReplicaNotInstantiated = 0x00000002
    Writable = 0x00000004
    ParentNamingContextHeld = 0x00000008
    NamingContextUnderConstruction = 0x00000010
    NamingContextDeleting = 0x00000020


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-systemflags
class SystemFlags(IntFlag):
    NotReplicated = 0x00000001
    ReplicatedToGlobalCatalog = 0x00000002
    Constructed = 0x00000004
    BaseSchema = 0x00000010
    DeletedImmediately = 0x02000000
    CannotBeMoved = 0x04000000
    CannotBeRenamed = 0x08000000
    ConfigurationCanBeMovedWithRestrictions = 0x10000000
    ConfigurationCanBeMoved = 0x20000000
    ConfigurationCanBeRenamedWithRestrictions = 0x40000000
    CannotBeDeleted = 0x80000000


ATTRIBUTE_DECODE_MAP: dict[str, Callable[[Database, Any], Any]] = {
    "instanceType": lambda db, value: InstanceType(int(value)),
    "systemFlags": lambda db, value: SystemFlags(int(value)),
    "objectGUID": lambda db, value: UUID(bytes_le=value),
    "badPasswordTime": lambda db, value: wintimestamp(int(value)),
    "lastLogonTimestamp": lambda db, value: wintimestamp(int(value)),
    "lastLogon": lambda db, value: wintimestamp(int(value)),
    "lastLogoff": lambda db, value: wintimestamp(int(value)),
    "pwdLastSet": lambda db, value: wintimestamp(int(value)),
    "accountExpires": lambda db, value: float("inf") if int(value) == ((1 << 63) - 1) else wintimestamp(int(value)),
}


def _ldapDisplayName_to_DNT(db: Database, value: str) -> int | str:
    """Convert an LDAP display name to its corresponding DNT value.

    Args:
        value: The LDAP display name to look up.

    Returns:
        The DNT value or the original value if not found.
    """
    if (entry := db.data.schema.lookup(ldap_name=value)) is not None:
        return entry.dnt
    return value


def _DNT_to_ldapDisplayName(db: Database, value: int) -> str | int:
    """Convert a DNT value to its corresponding LDAP display name.

    Args:
        value: The Directory Number Tag to look up.

    Returns:
        The LDAP display name or the original value if not found.
    """
    if (entry := db.data.schema.lookup(dnt=value)) is not None:
        return entry.ldap_name
    return value


def _oid_to_attrtyp(db: Database, value: str) -> int | str:
    """Convert OID string or LDAP display name to ATTRTYP value.

    Supports both formats::

        objectClass=person       (LDAP display name)
        objectClass=2.5.6.6      (OID string)

    Args:
        value: Either an OID string (contains dots) or LDAP display name.

    Returns:
        ATTRTYP integer value or the original value if not found.
    """
    if (
        entry := db.data.schema.lookup(oid=value) if "." in value else db.data.schema.lookup(ldap_name=value)
    ) is not None:
        return entry.id
    return value


def _attrtyp_to_oid(db: Database, value: int) -> str | int:
    """Convert ATTRTYP integer value to OID string.

    Args:
        value: The ATTRTYP integer value.

    Returns:
        The OID string or the original value if not found.
    """
    if (entry := db.data.schema.lookup(attrtyp=value)) is not None:
        return entry.ldap_name
    return value


# To be used when parsing LDAP queries into ESE-compatible data types
OID_ENCODE_DECODE_MAP: dict[str, tuple[Callable[[NTDS, Any], Any]]] = {
    # Object(DN-DN); The fully qualified name of an object
    "2.5.5.1": (_ldapDisplayName_to_DNT, _DNT_to_ldapDisplayName),
    # String(Object-Identifier); The object identifier
    "2.5.5.2": (_oid_to_attrtyp, _attrtyp_to_oid),
    # String(Object-Identifier); The object identifier
    "2.5.5.3": (None, lambda db, value: str(value)),
    "2.5.5.4": (None, lambda db, value: str(value)),
    "2.5.5.5": (None, lambda db, value: str(value)),
    # String(Numeric); A sequence of digits
    "2.5.5.6": (None, str),
    # TODO: Object(DN-Binary); A distinguished name plus a binary large object
    "2.5.5.7": (None, None),
    # Boolean; TRUE or FALSE values
    "2.5.5.8": (lambda db, value: bool(value), lambda db, value: bool(value)),
    # Integer, Enumeration; A 32-bit number or enumeration
    "2.5.5.9": (lambda db, value: int(value), lambda db, value: int(value)),
    # String(Octet); A string of bytes
    "2.5.5.10": (None, lambda db, value: bytes(value)),
    # String(UTC-Time), String(Generalized-Time); UTC time or generalized-time
    "2.5.5.11": (None, lambda db, value: wintimestamp(value * 10000000)),
    # String(Unicode); A Unicode string
    "2.5.5.12": (None, lambda db, value: str(value)),
    # TODO: Object(Presentation-Address); Presentation address
    "2.5.5.13": (None, None),
    # TODO: Object(DN-String); A DN-String plus a Unicode string
    "2.5.5.14": (None, None),
    # NTSecurityDescriptor; A security descriptor
    "2.5.5.15": (None, lambda db, value: int.from_bytes(value, byteorder="little")),
    # LargeInteger; A 64-bit number
    "2.5.5.16": (None, lambda db, value: int(value)),
    # String(Sid); Security identifier (SID)
    "2.5.5.17": (
        lambda db, value: write_sid(value, swap_last=True),
        lambda db, value: read_sid(value, swap_last=True),
    ),
}


def encode_value(db: Database, attribute: str, value: str) -> int | bytes | str:
    """Encode a string value according to the attribute's type.

    Args:
        attribute: The LDAP attribute name.
        value: The string value to encode.

    Returns:
        The encoded value in the appropriate type for the attribute.
    """
    if (attr_entry := db.data.schema.lookup(ldap_name=attribute)) is None:
        return value

    encode, _ = OID_ENCODE_DECODE_MAP.get(attr_entry.type, (None, None))
    if encode is None:
        return value

    return encode(db, value)


def decode_value(db: Database, attribute: str, value: Any) -> Any:
    """Decode a value according to the attribute's type.

    Args:
        attribute: The LDAP attribute name.
        value: The value to decode.

    Returns:
        The decoded value in the appropriate Python type for the attribute.
    """
    if value is None:
        return value

    # First check the list of deviations
    if (decode := ATTRIBUTE_DECODE_MAP.get(attribute)) is None:
        # Next, try it using the regular OID_ENCODE_DECODE_MAP mapping
        if (attr_schema := db.data.schema.lookup(ldap_name=attribute)) is None:
            return value

        if not attr_schema.type:
            return value

        _, decode = OID_ENCODE_DECODE_MAP.get(attr_schema.type, (None, None))

    if decode is None:
        return value

    if isinstance(value, list):
        return [decode(db, v) for v in value]
    return decode(db, value)
