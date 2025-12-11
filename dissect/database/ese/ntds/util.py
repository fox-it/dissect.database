from __future__ import annotations

from typing import TYPE_CHECKING, Any

from dissect.util.sid import read_sid, write_sid
from dissect.util.ts import wintimestamp

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.ntds import NTDS


ATTRIBUTE_NORMALIZERS: dict[str, Callable[[NTDS, Any], Any]] = {
    "badPasswordTime": lambda _, value: wintimestamp(int(value)),
    "lastLogonTimestamp": lambda _, value: wintimestamp(int(value)),
    "lastLogon": lambda _, value: wintimestamp(int(value)),
    "lastLogoff": lambda _, value: wintimestamp(int(value)),
    "pwdLastSet": lambda _, value: wintimestamp(int(value)),
    "accountExpires": lambda _, value: float("inf") if int(value) == ((1 << 63) - 1) else wintimestamp(int(value)),
}


def _ldapDisplayName_to_DNT(db: Database, value: str) -> int | None:
    """Convert an LDAP display name to its corresponding DNT value.

    Args:
        value: The LDAP display name to look up.

    Returns:
        The DNT value or None if not found.
    """
    if (entry := db.data.schema.lookup(ldap_name=value)) is not None:
        return entry.dnt
    return None


def _DNT_to_ldapDisplayName(db: Database, value: int) -> str | None:
    """Convert a DNT value to its corresponding LDAP display name.

    Args:
        value: The Directory Number Tag to look up.

    Returns:
        The LDAP display name or None if not found.
    """
    if (entry := db.data.schema.lookup(dnt=value)) is not None:
        return entry.ldap_name
    return None


def _oid_to_attrtyp(db: Database, value: str) -> int | None:
    """Convert OID string or LDAP display name to ATTRTYP value.

    Supports both formats::

        objectClass=person       (LDAP display name)
        objectClass=2.5.6.6      (OID string)

    Args:
        value: Either an OID string (contains dots) or LDAP display name.

    Returns:
        ATTRTYP integer value or ``None`` if not found.
    """
    if (
        entry := db.data.schema.lookup(oid=value) if "." in value else db.data.schema.lookup(ldap_name=value)
    ) is not None:
        return entry.attrtyp
    return None


def _attrtyp_to_oid(db: Database, value: int) -> str | None:
    """Convert ATTRTYP integer value to OID string.

    Args:
        value: The ATTRTYP integer value.

    Returns:
        The OID string or ``None`` if not found.
    """
    if (entry := db.data.schema.lookup(attrtyp=value)) is not None:
        return entry.ldap_name
    return None


# To be used when parsing LDAP queries into ESE-compatible data types
OID_ENCODE_DECODE_MAP: dict[str, tuple[Callable[[NTDS, Any], Any]]] = {
    # Object(DN-DN); The fully qualified name of an object
    "2.5.5.1": (_ldapDisplayName_to_DNT, _DNT_to_ldapDisplayName),
    # String(Object-Identifier); The object identifier
    "2.5.5.2": (_oid_to_attrtyp, _attrtyp_to_oid),
    # String(Object-Identifier); The object identifier
    "2.5.5.3": (None, lambda _, value: str(value)),
    "2.5.5.4": (None, lambda _, value: str(value)),
    "2.5.5.5": (None, lambda _, value: str(value)),
    # String(Numeric); A sequence of digits
    "2.5.5.6": (None, str),
    # TODO: Object(DN-Binary); A distinguished name plus a binary large object
    "2.5.5.7": (None, None),
    # Boolean; TRUE or FALSE values
    "2.5.5.8": (lambda _, value: bool(value), lambda _, value: bool(value)),
    # Integer, Enumeration; A 32-bit number or enumeration
    "2.5.5.9": (lambda _, value: int(value), lambda _, value: int(value)),
    # String(Octet); A string of bytes
    "2.5.5.10": (None, lambda _, value: bytes(value)),
    # String(UTC-Time), String(Generalized-Time); UTC time or generalized-time
    "2.5.5.11": (None, lambda _, value: wintimestamp(value * 10000000)),
    # String(Unicode); A Unicode string
    "2.5.5.12": (None, lambda _, value: str(value)),
    # TODO: Object(Presentation-Address); Presentation address
    "2.5.5.13": (None, None),
    # TODO: Object(DN-String); A DN-String plus a Unicode string
    "2.5.5.14": (None, None),
    # NTSecurityDescriptor; A security descriptor
    "2.5.5.15": (None, lambda _, value: int.from_bytes(value, byteorder="little")),
    # LargeInteger; A 64-bit number
    "2.5.5.16": (None, lambda _, value: int(value)),
    # String(Sid); Security identifier (SID)
    "2.5.5.17": (lambda _, value: write_sid(value, swap_last=True), lambda _, value: read_sid(value, swap_last=True)),
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

    encode, _ = OID_ENCODE_DECODE_MAP.get(attr_entry.type_oid, (None, None))
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
    # First check the list of deviations
    if (decode := ATTRIBUTE_NORMALIZERS.get(attribute)) is None:
        # Next, try it using the regular OID_ENCODE_DECODE_MAP mapping
        if (attr_entry := db.data.schema.lookup(ldap_name=attribute)) is None:
            return value

        if not attr_entry.type_oid:
            return value

        _, decode = OID_ENCODE_DECODE_MAP.get(attr_entry.type_oid, (None, None))

    if decode is None:
        return value

    if isinstance(value, list):
        return [decode(db, v) for v in value]
    return decode(db, value)
