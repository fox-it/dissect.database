from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from dissect.database.ese.ese import ESE


FIXED_OBJ_MAP = {
    "top": 0x00010000,
    "classSchema": 0x0003000D,
    "attributeSchema": 0x0003000E,
}


# These are used to bootstrap the mapping of attributes to their column names in the NTDS.dit file.
FIXED_COLUMN_MAP = {
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


class SchemaEntry(NamedTuple):
    dnt: int
    oid: str
    attrtyp: int
    ldap_name: str
    column_name: str | None = None
    type_oid: str | None = None
    link_id: int | None = None


class Schema:
    """A unified index for schema entries providing fast lookups by various keys.

    Provides efficient lookups for schema entries by DNT, OID, ATTRTYP, LDAP display name, and column name.
    """

    def __init__(self):
        self._dnt_index: dict[int, SchemaEntry] = {}
        self._oid_index: dict[str, SchemaEntry] = {}
        self._attrtyp_index: dict[int, SchemaEntry] = {}
        self._ldap_name_index: dict[str, SchemaEntry] = {}
        self._column_name_index: dict[str, SchemaEntry] = {}

    @classmethod
    def from_database(cls, db: ESE) -> Schema:
        """Load the classes and attributes from the database into a unified index.

        Args:
            db: The ESE database instance to load the schema from.
        """
        # Hardcoded index
        cursor = db.table("datatable").index("INDEX_00000000").cursor()
        schema_index = cls()

        # Load objectClasses (e.g. "person", "user", "group", etc.)
        for record in cursor.find_all(**{FIXED_COLUMN_MAP["objectClass"]: FIXED_OBJ_MAP["classSchema"]}):
            ldap_name = record.get(FIXED_COLUMN_MAP["lDAPDisplayName"])
            attrtyp = int(record.get(FIXED_COLUMN_MAP["governsID"]))
            oid = attrtyp_to_oid(attrtyp)
            dnt = record.get(FIXED_COLUMN_MAP["DNT"])

            schema_index.add(
                SchemaEntry(
                    dnt=dnt,
                    oid=oid,
                    attrtyp=attrtyp,
                    ldap_name=ldap_name,
                )
            )

        cursor.reset()

        # Load attributes (e.g. "cn", "sAMAccountName", "memberOf", etc.)
        for record in cursor.find_all(**{FIXED_COLUMN_MAP["objectClass"]: FIXED_OBJ_MAP["attributeSchema"]}):
            attrtyp = record.get(FIXED_COLUMN_MAP["attributeID"])
            type_oid = attrtyp_to_oid(record.get(FIXED_COLUMN_MAP["attributeSyntax"]))
            link_id = record.get(FIXED_COLUMN_MAP["linkId"])
            if link_id is not None:
                link_id = link_id // 2

            ldap_name = record.get(FIXED_COLUMN_MAP["lDAPDisplayName"])
            column_name = f"ATT{OID_TO_TYPE[type_oid]}{attrtyp}"
            oid = attrtyp_to_oid(attrtyp)
            dnt = record.get(FIXED_COLUMN_MAP["DNT"])

            schema_index.add(
                SchemaEntry(
                    dnt=dnt,
                    oid=oid,
                    attrtyp=attrtyp,
                    ldap_name=ldap_name,
                    column_name=column_name,
                    type_oid=type_oid,
                    link_id=link_id,
                )
            )

        # Ensure the fixed columns are also present in the schema
        for ldap_name, column_name in FIXED_COLUMN_MAP.items():
            if schema_index.lookup(column_name=column_name) is None:
                schema_index.add(
                    SchemaEntry(
                        dnt=-1,
                        oid="",
                        attrtyp=-1,
                        ldap_name=ldap_name,
                        column_name=column_name,
                    )
                )

        return schema_index

    def add(self, entry: SchemaEntry) -> None:
        self._dnt_index[entry.dnt] = entry
        self._oid_index[entry.oid] = entry
        self._attrtyp_index[entry.attrtyp] = entry
        self._ldap_name_index[entry.ldap_name] = entry

        if entry.column_name:
            self._column_name_index[entry.column_name] = entry

    def lookup(
        self,
        *,
        dnt: int | None = None,
        oid: str | None = None,
        attrtyp: int | None = None,
        ldap_name: str | None = None,
        column_name: str | None = None,
    ) -> SchemaEntry | None:
        """Lookup a schema entry by an indexed field.

        Args:
            dnt: The DNT (Distinguished Name Tag) of the schema entry to look up.
            oid: The OID (Object Identifier) of the schema entry to look up.
            attrtyp: The ATTRTYP (attribute type) of the schema entry to look up.
            ldap_name: The LDAP display name of the schema entry to look up.
            column_name: The column name of the schema entry to look up.

        Returns:
            The matching schema entry or ``None`` if not found.
        """
        # Ensure exactly one lookup key is provided
        if sum(key is not None for key in [dnt, oid, attrtyp, ldap_name, column_name]) != 1:
            raise ValueError("Exactly one lookup key must be provided")

        if dnt is not None:
            return self._dnt_index.get(dnt)

        if oid is not None:
            return self._oid_index.get(oid)

        if attrtyp is not None:
            return self._attrtyp_index.get(attrtyp)

        if ldap_name is not None:
            return self._ldap_name_index.get(ldap_name)

        if column_name is not None:
            return self._column_name_index.get(column_name)

        return None
