from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

from dissect.database.ese.ntds.objects.object import Object
from dissect.database.ese.ntds.util import OID_TO_TYPE, attrtyp_to_oid

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.util import SearchFlags

# These are fixed columns in the NTDS database
# They do not exist in the schema, but are required for basic operation
BOOTSTRAP_COLUMNS = [
    # (lDAPDisplayName, column_name, attributeSyntax)
    ("DNT", "DNT_col", 0x00080009),
    ("Pdnt", "PDNT_col", 0x00080009),
    ("Obj", "OBJ_col", 0x00080008),
    ("RdnType", "RDNtyp_col", 0x00080002),
    ("CNT", "cnt_col", 0x00080009),
    ("AB_cnt", "ab_cnt_col", 0x00080009),
    ("Time", "time_col", 0x0008000B),
    ("Ncdnt", "NCDNT_col", 0x00080009),
    ("RecycleTime", "recycle_time_col", 0x0008000B),
    ("Ancestors", "Ancestors_col", 0x0008000A),
    ("IsVisibleInAB", "IsVisibleInAB", 0x00080009),  # TODO: Confirm syntax + what is this?
]

# These are required for bootstrapping the schema
# Most of these will be overwritten when the schema is loaded from the database
BOOTSTRAP_ATTRIBUTES = [
    # (lDAPDisplayName, attributeID, attributeSyntax, isSingleValued)
    # Essential attributes
    ("objectClass", 0, 0x00080002, False),  # ATTc0
    ("cn", 3, 0x0008000C, True),  # ATTm3
    ("isDeleted", 131120, 0x00080008, True),  # ATTi131120
    ("instanceType", 131073, 0x00080009, True),  # ATTj131073
    ("name", 589825, 0x0008000C, True),  # ATTm589825
    # Common schema
    ("lDAPDisplayName", 131532, 0x0008000C, True),  # ATTm131532
    # Attribute schema
    ("attributeID", 131102, 0x00080002, True),  # ATTc131102
    ("attributeSyntax", 131104, 0x00080002, True),  # ATTc131104
    ("oMSyntax", 131303, 0x00080009, True),  # ATTj131303
    ("oMObjectClass", 131290, 0x0008000A, True),  # ATTk131290
    ("isSingleValued", 131105, 0x00080008, True),  # ATTi131105
    ("linkId", 131122, 0x00080009, True),  # ATTj131122
    ("searchFlags", 131406, 0x00080009, True),  # ATTj131406
    # Class schema
    ("governsID", 131094, 0x00080002, True),  # ATTc131094
]

# For convenience, bootstrap some common object classes
# These will also be overwritten when the schema is loaded from the database
BOOTSTRAP_OBJECT_CLASSES = {
    "top": 0x00010000,
    "classSchema": 0x0003000D,
    "attributeSchema": 0x0003000E,
}


class ClassEntry(NamedTuple):
    dnt: int
    oid: str
    id: int
    name: str


class AttributeEntry(NamedTuple):
    dnt: int
    oid: str
    id: int
    name: str
    column: str
    type: str
    om_syntax: int | None
    om_object_class: bytes | None
    is_single_valued: bool
    link_id: int | None
    search_flags: SearchFlags | None


class Schema:
    """An index for schema entries providing fast lookups by various keys.

    Provides efficient lookups for schema entries by DNT, OID, ATTRTYP, LDAP display name, and column name.
    """

    def __init__(self):
        # Combined indices
        self._dnt_index: dict[int, ClassEntry | AttributeEntry] = {}
        self._oid_index: dict[str, ClassEntry | AttributeEntry] = {}
        self._attrtyp_index: dict[int, ClassEntry | AttributeEntry] = {}

        # Attribute specific indices
        self._attribute_id_index: dict[int, AttributeEntry] = {}
        self._attribute_name_index: dict[str, AttributeEntry] = {}
        self._attribute_link_index: dict[int, AttributeEntry] = {}
        self._attribute_column_index: dict[str, AttributeEntry] = {}

        # Class specific indices
        self._class_id_index: dict[int, ClassEntry] = {}
        self._class_name_index: dict[str, ClassEntry] = {}

        # Bootstrap fixed database columns (these do not exist in the schema)
        for ldap_name, column_name, syntax in BOOTSTRAP_COLUMNS:
            self._add(
                AttributeEntry(
                    dnt=-1,
                    oid="",
                    id=-1,
                    name=ldap_name,
                    column=column_name,
                    type=attrtyp_to_oid(syntax),
                    om_syntax=None,
                    om_object_class=None,
                    is_single_valued=True,
                    link_id=None,
                    search_flags=None,
                )
            )

        # Bootstrap initial attributes
        for name, id, attribute_syntax, is_single_valued in BOOTSTRAP_ATTRIBUTES:
            self._add_attribute(
                dnt=-1,
                id=id,
                name=name,
                syntax=attribute_syntax,
                om_syntax=None,
                om_object_class=None,
                is_single_valued=is_single_valued,
                link_id=None,
                search_flags=None,
            )

        # Bootstrap initial object classes
        for name, id in BOOTSTRAP_OBJECT_CLASSES.items():
            self._add_class(
                dnt=-1,
                id=id,
                name=name,
            )

    def load(self, db: Database) -> None:
        """Load the classes and attributes from the database into the schema index.

        Args:
            db: The database instance to load the schema from.
        """

        def _iter(id: int) -> Iterator[Object]:
            # Use the ATTc0 (objectClass) index to iterate over all objects of the given objectClass
            # TODO: In the future, maybe use `DataTable._get_index`, but that's not fully implemented yet
            cursor = db.data.table.index("INDEX_00000000").cursor()
            end = cursor.seek([id + 1]).record()

            cursor.reset()
            cursor.seek([id])

            record = cursor.record()
            while record is not None and record != end:
                yield Object.from_record(db, record)
                record = cursor.next()

        # We bootstrapped these earlier
        attribute_schema = self.lookup_class(name="attributeSchema")
        class_schema = self.lookup_class(name="classSchema")

        for obj in _iter(attribute_schema.id):
            self._add_attribute(
                dnt=obj.dnt,
                id=obj.get("attributeID", raw=True),
                name=obj.get("lDAPDisplayName"),
                syntax=obj.get("attributeSyntax", raw=True),
                om_syntax=obj.get("oMSyntax"),
                om_object_class=obj.get("oMObjectClass"),
                is_single_valued=obj.get("isSingleValued"),
                link_id=obj.get("linkId"),
                search_flags=obj.get("searchFlags"),
            )

        for obj in _iter(class_schema.id):
            self._add_class(
                dnt=obj.dnt,
                id=obj.get("governsID", raw=True),
                name=obj.get("lDAPDisplayName"),
            )

    def _add_class(self, dnt: int, id: int, name: str) -> None:
        entry = ClassEntry(
            dnt=dnt,
            oid=attrtyp_to_oid(id),
            id=id,
            name=name,
        )
        self._add(entry)

    def _add_attribute(
        self,
        dnt: int,
        id: int,
        name: str,
        syntax: int,
        om_syntax: int | None,
        om_object_class: bytes | None,
        is_single_valued: bool,
        link_id: int | None,
        search_flags: SearchFlags | None,
    ) -> None:
        type_oid = attrtyp_to_oid(syntax)
        entry = AttributeEntry(
            dnt=dnt,
            oid=attrtyp_to_oid(id),
            id=id,
            name=name,
            column=f"ATT{OID_TO_TYPE[type_oid]}{id}",
            type=type_oid,
            om_syntax=om_syntax,
            om_object_class=om_object_class,
            is_single_valued=is_single_valued,
            link_id=link_id,
            search_flags=search_flags,
        )
        self._add(entry)

    def _add(self, entry: ClassEntry | AttributeEntry) -> None:
        if entry.dnt != -1:
            self._dnt_index[entry.dnt] = entry
        if entry.oid != "":
            self._oid_index[entry.oid] = entry
        if entry.id != -1:
            self._attrtyp_index[entry.id] = entry

        if isinstance(entry, ClassEntry):
            self._class_name_index[entry.name.lower()] = entry

            if entry.id != -1:
                self._class_id_index[entry.id] = entry

        if isinstance(entry, AttributeEntry):
            self._attribute_name_index[entry.name.lower()] = entry
            self._attribute_column_index[entry.column] = entry

            if entry.id != -1:
                self._attribute_id_index[entry.id] = entry
            if entry.link_id is not None:
                self._attribute_link_index[entry.link_id] = entry

    def lookup_attribute(
        self,
        *,
        id: int | None = None,
        name: str | None = None,
        link_id: int | None = None,
        column: str | None = None,
    ) -> AttributeEntry | None:
        """Lookup an attribute schema entry by an indexed field.

        Args:
            id: The attribute ID to look up.
            name: The LDAP display name to look up.
            link_id: The link ID to look up.
            column: The column name to look up.

        Returns:
            The matching attribute schema entry or ``None`` if not found.
        """
        if sum(key is not None for key in [id, name, link_id, column]) != 1:
            raise ValueError("Exactly one lookup key must be provided")

        if id is not None:
            return self._attribute_id_index.get(id)

        if name is not None:
            return self._attribute_name_index.get(name.lower())

        if link_id is not None:
            return self._attribute_link_index.get(link_id)

        if column is not None:
            return self._attribute_column_index.get(column)

        return None

    def lookup_class(
        self,
        *,
        id: int | None = None,
        name: str | None = None,
    ) -> ClassEntry | None:
        """Lookup a class schema entry by an indexed field.

        Args:
            id: The class ID to look up.
            name: The LDAP display name to look up.

        Returns:
            The matching class schema entry or ``None`` if not found.
        """
        if sum(key is not None for key in [id, name]) != 1:
            raise ValueError("Exactly one lookup key must be provided")

        if id is not None:
            return self._class_id_index.get(id)

        if name is not None:
            return self._class_name_index.get(name.lower())

        return None

    def lookup(
        self,
        *,
        dnt: int | None = None,
        oid: str | None = None,
        attrtyp: int | None = None,
        name: str | None = None,
    ) -> ClassEntry | AttributeEntry | None:
        """Lookup a schema entry by an indexed field.

        Args:
            dnt: The DNT (Distinguished Name Tag) of the schema entry to look up.
            oid: The OID (Object Identifier) of the schema entry to look up.
            attrtyp: The ATTRTYP (attribute type) of the schema entry to look up.
            name: The LDAP display name of the schema entry to look up.

        Returns:
            The matching schema entry or ``None`` if not found.
        """
        # Ensure exactly one lookup key is provided
        if sum(key is not None for key in [dnt, oid, attrtyp, name]) != 1:
            raise ValueError("Exactly one lookup key must be provided")

        if dnt is not None:
            return self._dnt_index.get(dnt)

        if oid is not None:
            return self._oid_index.get(oid)

        if attrtyp is not None:
            return self._attrtyp_index.get(attrtyp)

        if name is not None:
            name = name.lower()
            return self._class_name_index.get(name) or self._attribute_name_index.get(name)

        return None
