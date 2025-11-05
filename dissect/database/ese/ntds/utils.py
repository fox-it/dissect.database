from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

from dissect.util.ts import wintimestamp

FIXED_OBJ_MAP = {
    "top": 0x00010000,
    "classSchema": 0x0003000D,
    "attributeSchema": 0x0003000E,
}

# These are used to bootstrap the mapping of attributes to their column names in the NTDS.dit file.
FIXED_ATTR_COLS: dict[str, str] = {
    # These are present in most objects and hardcoded in the DB schema
    "DNT": "DNT_col",
    "Pdnt": "PDNT_col",
    "Obj": "OBJ_col",
    "RdnType": "RDNtyp_col",
    "CNT": "cnt_col",
    "AB_cnt": "ab_cnt_col",
    "Time": "time_col",
    "Ncdnt": "NCDNT_col",
    "RecycleTime": "recycle_time_col",
    "Ancestors": "Ancestors_col",
    # These are hardcoded attributes, required for bootstrapping the schema
    "objectClass": "ATTc0",
    "lDAPDisplayName": "ATTm131532",
    "attributeSyntax": "ATTc131104",
    "attributeID": "ATTc131102",
    "governsID": "ATTc131094",
    "objectCategory": "ATTb590606",
    "linkId": "ATTj131122",
}

REVERSE_SPECIAL_ATTRIBUTE_MAPPING: dict[str, str] = {v: k for k, v in FIXED_ATTR_COLS.items()}

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


def convert_attrtyp_to_oid(oid_int: int) -> str:
    """Gets the OID from an ATTRTYP 32-bit integer value.

    Example for attribute printShareName:
        ATTRTYP: 590094 (hex: 0x9010e) -> 1.2.840.113556.1.4.270

    Args:
        oid_int: The ATTRTYP 32-bit integer value to convert.

    Returns:
        The OID string representation.
    """
    return f"{OID_PREFIX[oid_int & 0xFFFF0000]:s}.{oid_int & 0x0000FFFF:d}"


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa
OID_TO_TYPE: dict[str, str] = {
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


def increment_last_char(s: str) -> str | None:
    """Increment the last character in a string to find the next lexicographically sortable key.

    Used for binary tree searching to find the upper bound of a range search.

    Args:
        s: The string to increment.

    Returns:
        A new string with the last character incremented, or None if increment
        would overflow all characters.
    """
    s_list = list(s)
    i = len(s_list) - 1

    while i >= 0:
        if s_list[i] != "z" and s_list[i] != "Z":
            s_list[i] = chr(ord(s_list[i]) + 1)
            return "".join(s_list[: i + 1])
        i -= 1
    return s + "a"


WELL_KNOWN_SIDS = {
    "S-1-0": ("Null Authority", "USER"),
    "S-1-0-0": ("Nobody", "USER"),
    "S-1-1": ("World Authority", "USER"),
    "S-1-1-0": ("Everyone", "GROUP"),
    "S-1-2": ("Local Authority", "USER"),
    "S-1-2-0": ("Local", "GROUP"),
    "S-1-2-1": ("Console Logon", "GROUP"),
    "S-1-3": ("Creator Authority", "USER"),
    "S-1-3-0": ("Creator Owner", "USER"),
    "S-1-3-1": ("Creator Group", "GROUP"),
    "S-1-3-2": ("Creator Owner Server", "COMPUTER"),
    "S-1-3-3": ("Creator Group Server", "COMPUTER"),
    "S-1-3-4": ("Owner Rights", "GROUP"),
    "S-1-4": ("Non-unique Authority", "USER"),
    "S-1-5": ("NT Authority", "USER"),
    "S-1-5-1": ("Dialup", "GROUP"),
    "S-1-5-2": ("Network", "GROUP"),
    "S-1-5-3": ("Batch", "GROUP"),
    "S-1-5-4": ("Interactive", "GROUP"),
    "S-1-5-6": ("Service", "GROUP"),
    "S-1-5-7": ("Anonymous", "GROUP"),
    "S-1-5-8": ("Proxy", "GROUP"),
    "S-1-5-9": ("Enterprise Domain Controllers", "GROUP"),
    "S-1-5-10": ("Principal Self", "USER"),
    "S-1-5-11": ("Authenticated Users", "GROUP"),
    "S-1-5-12": ("Restricted Code", "GROUP"),
    "S-1-5-13": ("Terminal Server Users", "GROUP"),
    "S-1-5-14": ("Remote Interactive Logon", "GROUP"),
    "S-1-5-15": ("This Organization", "GROUP"),
    "S-1-5-17": ("IUSR", "USER"),
    "S-1-5-18": ("Local System", "USER"),
    "S-1-5-19": ("NT Authority", "USER"),
    "S-1-5-20": ("Network Service", "USER"),
    "S-1-5-80-0": ("All Services ", "GROUP"),
    "S-1-5-32-544": ("Administrators", "GROUP"),
    "S-1-5-32-545": ("Users", "GROUP"),
    "S-1-5-32-546": ("Guests", "GROUP"),
    "S-1-5-32-547": ("Power Users", "GROUP"),
    "S-1-5-32-548": ("Account Operators", "GROUP"),
    "S-1-5-32-549": ("Server Operators", "GROUP"),
    "S-1-5-32-550": ("Print Operators", "GROUP"),
    "S-1-5-32-551": ("Backup Operators", "GROUP"),
    "S-1-5-32-552": ("Replicators", "GROUP"),
    "S-1-5-32-554": ("Pre-Windows 2000 Compatible Access", "GROUP"),
    "S-1-5-32-555": ("Remote Desktop Users", "GROUP"),
    "S-1-5-32-556": ("Network Configuration Operators", "GROUP"),
    "S-1-5-32-557": ("Incoming Forest Trust Builders", "GROUP"),
    "S-1-5-32-558": ("Performance Monitor Users", "GROUP"),
    "S-1-5-32-559": ("Performance Log Users", "GROUP"),
    "S-1-5-32-560": ("Windows Authorization Access Group", "GROUP"),
    "S-1-5-32-561": ("Terminal Server License Servers", "GROUP"),
    "S-1-5-32-562": ("Distributed COM Users", "GROUP"),
    "S-1-5-32-568": ("IIS_IUSRS", "GROUP"),
    "S-1-5-32-569": ("Cryptographic Operators", "GROUP"),
    "S-1-5-32-573": ("Event Log Readers", "GROUP"),
    "S-1-5-32-574": ("Certificate Service DCOM Access", "GROUP"),
    "S-1-5-32-575": ("RDS Remote Access Servers", "GROUP"),
    "S-1-5-32-576": ("RDS Endpoint Servers", "GROUP"),
    "S-1-5-32-577": ("RDS Management Servers", "GROUP"),
    "S-1-5-32-578": ("Hyper-V Administrators", "GROUP"),
    "S-1-5-32-579": ("Access Control Assistance Operators", "GROUP"),
    "S-1-5-32-580": ("Access Control Assistance Operators", "GROUP"),
    "S-1-5-32-582": ("Storage Replica Administrators", "GROUP"),
}


ATTRIBUTE_NORMALIZERS: dict[str, Callable[[Any], Any]] = {
    "badPasswordTime": lambda x: wintimestamp(int(x)),
    "lastLogonTimestamp": lambda x: wintimestamp(int(x)),
    "lastLogon": lambda x: wintimestamp(int(x)),
    "lastLogoff": lambda x: wintimestamp(int(x)),
    "pwdLastSet": lambda x: wintimestamp(int(x)),
    "accountExpires": lambda x: float("inf") if int(x) == 9223372036854775807 else wintimestamp(int(x)),
}


def write_sid(sid_string: str, endian: str = "<") -> bytes:
    """Write a Windows SID string to bytes.

    This is the inverse of read_sid, converting a SID string back to its binary representation.

    Args:
        sid_string: A SID string in the format "S-{revision}-{authority}-{sub_authority}...".
        endian: Endianness for writing the sub authorities (default: "<").

    Returns:
        The binary representation of the SID.

    Raises:
        ValueError: If the SID string format is invalid.
    """
    if not sid_string or not sid_string.startswith("S-"):
        raise ValueError("Invalid SID string format")

    parts = sid_string.split("-")
    if len(parts) < 3:
        raise ValueError("Invalid SID string format: insufficient parts")

    # Parse the SID components
    try:
        revision = int(parts[1])
        authority = int(parts[2])
        sub_authorities = [int(part) for part in parts[3:]]
    except ValueError:
        raise ValueError("Invalid SID string format: non-numeric components")

    if revision < 0 or revision > 255:
        raise ValueError("Invalid revision value")

    sub_authority_count = len(sub_authorities)
    if sub_authority_count > 255:
        raise ValueError("Too many sub authorities")

    result = bytearray()
    result.append(revision)
    result.append(sub_authority_count)
    authority_bytes = authority.to_bytes(6, "big")
    result.extend(authority_bytes)
    if sub_authorities:
        sub_authority_buf = bytearray(struct.pack(f"{endian}{sub_authority_count}I", *sub_authorities))
        sub_authority_buf[-4:] = sub_authority_buf[-4:][::-1]
        result.extend(sub_authority_buf)
    return bytes(result)


# https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
def format_GUID(uuid: bytes) -> str:
    """Format a 16-byte GUID to its string representation.

    Args:
        uuid: 16 bytes representing the GUID.

    Returns:
        The formatted GUID string in the format XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.
    """
    uuid1, uuid2, uuid3 = struct.unpack("<LHH", uuid[:8])
    uuid4, uuid5, uuid6 = struct.unpack(">HHL", uuid[8:16])
    return f"{uuid1:08X}-{uuid2:04X}-{uuid3:04X}-{uuid4:04X}-{uuid5:04X}{uuid6:08X}"
