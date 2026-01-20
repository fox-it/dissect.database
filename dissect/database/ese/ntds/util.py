from __future__ import annotations

import struct
from enum import IntFlag
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.util.sid import read_sid, write_sid
from dissect.util.ts import wintimestamp

from dissect.database.ese.ntds.c_ds import c_ds

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.objects import Object


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


# https://learn.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
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


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557
class UserAccountControl(IntFlag):
    SCRIPT = 0x00000001
    ACCOUNTDISABLE = 0x00000002
    HOMEDIR_REQUIRED = 0x00000008
    LOCKOUT = 0x00000010
    PASSWD_NOTREQD = 0x00000020
    PASSWD_CANT_CHANGE = 0x00000040
    ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000080
    TEMP_DUPLICATE_ACCOUNT = 0x00000100
    NORMAL_ACCOUNT = 0x00000200
    INTERDOMAIN_TRUST_ACCOUNT = 0x00000800
    WORKSTATION_TRUST_ACCOUNT = 0x00001000
    SERVER_TRUST_ACCOUNT = 0x00002000
    DONT_EXPIRE_PASSWORD = 0x00010000
    MNS_LOGON_ACCOUNT = 0x00020000
    SMARTCARD_REQUIRED = 0x00040000
    TRUSTED_FOR_DELEGATION = 0x00080000
    NOT_DELEGATED = 0x00100000
    USE_DES_KEY_ONLY = 0x00200000
    DONT_REQUIRE_PREAUTH = 0x00400000
    PASSWORD_EXPIRED = 0x00800000
    TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000


class SearchFlags(IntFlag):
    Indexed = 0x00000001
    ContainerIndexed = 0x00000002
    Anr = 0x00000004
    PreserveTombstone = 0x00000008
    CopyWithObject = 0x00000010
    TupleIndexed = 0x00000020
    VlvIndexed = 0x00000040
    Confidential = 0x00000080


def _pek_decrypt(db: Database, value: bytes) -> bytes:
    """Decrypt a PEK-encrypted blob using the database's PEK, if it's unlocked.

    Args:
        db: The associated NTDS database instance.
        value: The PEK-encrypted data blob.

    Returns:
        The decrypted data blob, or the original value if the PEK is locked.
    """
    if db.data.pek is None or not db.data.pek.unlocked:
        return value

    return db.data.pek.decrypt(value)


def _decode_supplemental_credentials(db: Database, value: bytes) -> dict[str, bytes] | bytes:
    """Decode the ``supplementalCredentials`` attribute.

    Args:
        db: The associated NTDS database instance.
        value: The raw bytes of the ``supplementalCredentials`` attribute.

    Returns:
        A dictionary mapping credential types to their data blobs, or the original value if the PEK is locked.
    """
    if db.data.pek is None or not db.data.pek.unlocked:
        return value

    value = db.data.pek.decrypt(value)
    header = c_ds.USER_PROPERTIES_HEADER(value)

    result = {}
    if header.PropertySignature == 0x50:  # 'P' as WORD in UTF-16-LE
        for prop in c_ds.USER_PROPERTY[header.PropertyCount](value[len(header) :]):
            prop_name = prop.PropertyName
            prop_value = bytes.fromhex(prop.PropertyValue.decode())

            if prop_name == "Packages":
                prop_value = prop_value.decode("utf-16-le").split("\x00")
            elif prop_name == "Primary:CLEARTEXT":
                prop_value = prop_value.decode("utf-16-le")
            elif prop_name == "Primary:Kerberos":
                parsed = c_ds.KERB_STORED_CREDENTIAL(prop_value)
                prop_value = {
                    "DefaultSalt": prop_value[
                        parsed.DefaultSaltOffset : parsed.DefaultSaltOffset + parsed.DefaultSaltLength
                    ],
                    "Credentials": [
                        {"KeyType": cred.KeyType, "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength]}
                        for cred in parsed.Credentials
                    ],
                    "OldCredentials": [
                        {"KeyType": cred.KeyType, "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength]}
                        for cred in parsed.OldCredentials
                    ],
                }
            elif prop_name == "Primary:Kerberos-Newer-Keys":
                parsed = c_ds.KERB_STORED_CREDENTIAL_NEW(prop_value)
                prop_value = {
                    "DefaultSalt": prop_value[
                        parsed.DefaultSaltOffset : parsed.DefaultSaltOffset + parsed.DefaultSaltLength
                    ],
                    "DefaultIterationCount": parsed.DefaultIterationCount,
                    "Credentials": [
                        {
                            "KeyType": cred.KeyType,
                            "IterationCount": cred.IterationCount,
                            "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength],
                        }
                        for cred in parsed.Credentials
                    ],
                    "ServiceCredentials": [
                        {
                            "KeyType": cred.KeyType,
                            "IterationCount": cred.IterationCount,
                            "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength],
                        }
                        for cred in parsed.ServiceCredentials
                    ],
                    "OldCredentials": [
                        {
                            "KeyType": cred.KeyType,
                            "IterationCount": cred.IterationCount,
                            "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength],
                        }
                        for cred in parsed.OldCredentials
                    ],
                    "OlderCredentials": [
                        {
                            "KeyType": cred.KeyType,
                            "IterationCount": cred.IterationCount,
                            "Key": prop_value[cred.KeyOffset : cred.KeyOffset + cred.KeyLength],
                        }
                        for cred in parsed.OlderCredentials
                    ],
                }
            elif prop_name == "Primary:WDigest":
                parsed = c_ds.WDIGEST_CREDENTIALS(prop_value)
                prop_value = list(parsed.Hash)

            result[prop_name] = prop_value
    else:
        # Probably AD LDS format, check some heuristics
        # TODO: Properly research AD LDS supplementalCredentials format
        header = c_ds.ADAM_PROPERTIES_HEADER(value)
        if header.Reserved6 == len(value) - len(header) and header.Reserved3 == len(value) - len(header) + 8:
            # Looks like AD LDS format
            parsed = c_ds.WDIGEST_CREDENTIALS(value[len(header) :])

            # Make up some keys to match the other result
            result["Packages"] = ["WDigest"]
            result["Primary:WDigest"] = list(parsed.Hash)
        else:
            # Bail out, unknown format
            return value

    return result


ATTRIBUTE_ENCODE_DECODE_MAP: dict[
    str, tuple[Callable[[Database, Any], Any] | None, Callable[[Database, Any], Any] | None]
] = {
    "Ancestors": (None, lambda db, value: [v[0] for v in struct.iter_unpack("<I", value)]),
    "instanceType": (lambda db, value: int(value), lambda db, value: InstanceType(int(value))),
    "systemFlags": (lambda db, value: int(value), lambda db, value: SystemFlags(int(value))),
    "searchFlags": (lambda db, value: int(value), lambda db, value: SearchFlags(int(value))),
    "userAccountControl": (lambda db, value: int(value), lambda db, value: UserAccountControl(int(value))),
    "objectGUID": (lambda db, value: value.bytes_le, lambda db, value: UUID(bytes_le=value)),
    "badPasswordTime": (None, lambda db, value: wintimestamp(int(value))),
    "lastLogonTimestamp": (None, lambda db, value: wintimestamp(int(value))),
    "lastLogon": (None, lambda db, value: wintimestamp(int(value))),
    "lastLogoff": (None, lambda db, value: wintimestamp(int(value))),
    "pwdLastSet": (None, lambda db, value: wintimestamp(int(value))),
    "accountExpires": (
        None,
        lambda db, value: float("inf") if int(value) == ((1 << 63) - 1) else wintimestamp(int(value)),
    ),
    # Protected attributes
    "unicodePwd": (None, _pek_decrypt),
    "dBCSPwd": (None, _pek_decrypt),
    "ntPwdHistory": (None, _pek_decrypt),
    "lmPwdHistory": (None, _pek_decrypt),
    "supplementalCredentials": (None, _decode_supplemental_credentials),
    "currentValue": (None, _pek_decrypt),
    "priorValue": (None, _pek_decrypt),
    "initialAuthIncoming": (None, _pek_decrypt),
    "initialAuthOutgoing": (None, _pek_decrypt),
    "trustAuthIncoming": (None, _pek_decrypt),
    "trustAuthOutgoing": (None, _pek_decrypt),
    "msDS-ExecuteScriptPassword": (None, _pek_decrypt),
}


def _ldapDisplayName_to_DNT(db: Database, value: str) -> int | str:
    """Convert an LDAP display name to its corresponding DNT value.

    Args:
        db: The associated NTDS database instance.
        value: The LDAP display name to look up.

    Returns:
        The DNT value or the original value if not found.
    """
    if (schema := db.data.schema.lookup(name=value)) is not None:
        return schema.dnt
    return value


def _DNT_to_ldapDisplayName(db: Database, value: int) -> str | DN | int:
    """Convert a DNT value to its corresponding LDAP display name or distinguished name.

    For attributes and classes, the LDAP display name is returned. For objects, the distinguished name is returned.

    Args:
        db: The associated NTDS database instance.
        value: The Directory Number Tag to look up.

    Returns:
        The LDAP display name or the original value if not found.
    """
    if (schema := db.data.schema.lookup(dnt=value)) is not None:
        return schema.name

    try:
        return db.data._make_dn(value)
    except Exception:
        return value


class DN(str):
    """A distinguished name (DN) string wrapper. Presents the DN as a string but also retains the underlying object."""

    __slots__ = ("object", "parent")

    def __new__(cls, value: str, object: Object, parent: DN | None = None):
        instance = super().__new__(cls, value)
        instance.object = object
        instance.parent = parent
        return instance


def _oid_to_attrtyp(db: Database, value: str) -> int | str:
    """Convert OID string or LDAP display name to ATTRTYP value.

    Supports both formats::

        objectClass=person       (LDAP display name)
        objectClass=2.5.6.6      (OID string)

    Args:
        db: The associated NTDS database instance.
        value: Either an OID string (contains dots) or LDAP display name.

    Returns:
        ATTRTYP integer value.
    """
    if (schema := db.data.schema.lookup(oid=value) if "." in value else db.data.schema.lookup(name=value)) is not None:
        return schema.id

    raise ValueError(f"Attribute or class not found for value: {value!r}")


def _attrtyp_to_oid(db: Database, value: int) -> str | int:
    """Convert ATTRTYP integer value to OID string.

    Args:
        db: The associated NTDS database instance.
        value: The ATTRTYP integer value.

    Returns:
        The OID string or the original value if not found.
    """
    if (schema := db.data.schema.lookup(attrtyp=value)) is not None:
        return schema.name
    return value


def _binary_to_dn(db: Database, value: bytes) -> tuple[int, bytes]:
    """Convert DN-Binary to the separate (DN, binary) tuple.

    Args:
        db: The associated NTDS database instance.
        value: The binary DN value.

    Returns:
        A tuple of the DNT and the binary data as hex.
    """
    dnt, length = struct.unpack("<II", value[:8])
    return dnt, value[8 : 8 + length].hex()


# To be used when parsing LDAP queries into ESE-compatible data types
OID_ENCODE_DECODE_MAP: dict[
    str, tuple[Callable[[Database, Any], Any] | None, Callable[[Database, Any], Any] | None]
] = {
    # Object(DN-DN); The fully qualified name of an object
    "2.5.5.1": (_ldapDisplayName_to_DNT, _DNT_to_ldapDisplayName),
    # String(Object-Identifier); The object identifier
    "2.5.5.2": (_oid_to_attrtyp, _attrtyp_to_oid),
    # String(Object-Identifier); The object identifier
    "2.5.5.3": (None, lambda db, value: str(value)),
    "2.5.5.4": (None, lambda db, value: str(value)),
    "2.5.5.5": (None, lambda db, value: str(value)),
    # String(Numeric); A sequence of digits
    "2.5.5.6": (None, lambda db, value: str(value)),
    # Object(DN-Binary); A distinguished name plus a binary large object
    "2.5.5.7": (None, _binary_to_dn),
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
        db: The associated NTDS database instance.
        attribute: The LDAP attribute name.
        value: The string value to encode.

    Returns:
        The encoded value in the appropriate type for the attribute.
    """
    if (schema := db.data.schema.lookup_attribute(name=attribute)) is None:
        return value

    # First check the list of deviations
    encode, _ = ATTRIBUTE_ENCODE_DECODE_MAP.get(attribute, (None, None))
    if encode is None:
        encode, _ = OID_ENCODE_DECODE_MAP.get(schema.type, (None, None))

    if encode is None:
        return value

    return encode(db, value)


def decode_value(db: Database, attribute: str, value: Any) -> Any:
    """Decode a value according to the attribute's type.

    Args:
        db: The associated NTDS database instance.
        attribute: The LDAP attribute name.
        value: The value to decode.

    Returns:
        The decoded value in the appropriate Python type for the attribute.
    """
    if value is None:
        return value

    # First check the list of deviations
    _, decode = ATTRIBUTE_ENCODE_DECODE_MAP.get(attribute, (None, None))
    if decode is None:
        # Next, try it using the regular OID_ENCODE_DECODE_MAP mapping
        if (schema := db.data.schema.lookup_attribute(name=attribute)) is None:
            return value

        # TODO: handle oMSyntax/oMObjectClass deviations?
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa
        _, decode = OID_ENCODE_DECODE_MAP.get(schema.type, (None, None))

    if decode is None:
        return value

    return [decode(db, v) for v in value] if isinstance(value, list) else decode(db, value)
