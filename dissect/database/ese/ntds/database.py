from __future__ import annotations

from functools import lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from dissect.database.ese.ese import ESE
from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.ntds.objects import AttributeSchema, ClassSchema, Object
from dissect.database.ese.ntds.query import Query
from dissect.database.ese.ntds.sd import ACL, SecurityDescriptor
from dissect.database.ese.ntds.util import OID_TO_TYPE, attrtyp_to_oid, encode_value

if TYPE_CHECKING:
    from collections.abc import Iterator


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
    ("omSyntax", 131303, 0x00080009, True),  # ATTj131303
    ("oMObjectClass", 131290, 0x0008000A, True),  # ATTk131290
    ("isSingleValued", 131105, 0x00080008, True),  # ATTi131105
    ("linkId", 131122, 0x00080009, True),  # ATTj131122
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
    ldap_name: str


class AttributeEntry(NamedTuple):
    dnt: int
    oid: str
    id: int
    type: str
    is_single_valued: bool
    link_id: int | None
    ldap_name: str
    column_name: str


class Database:
    """Interact with an NTDS.dit Active Directory Domain Services (AD DS) database.

    The main purpose of this class is to group interaction with the various tables and
    remove some clutter from the NTDS class.
    """

    def __init__(self, fh: BinaryIO):
        self.ese = ESE(fh)

        self.data = DataTable(self)
        self.link = LinkTable(self)
        self.sd = SecurityDescriptorTable(self)

        self.data.schema.load(self)


class DataTable:
    """Represents the ``datatable`` in the NTDS database."""

    def __init__(self, db: Database):
        self.db = db
        self.table = self.db.ese.table("datatable")

        self.schema = Schema()

        # Cache frequently used and "expensive" methods
        self.get = lru_cache(4096)(self.get)
        self._make_dn = lru_cache(4096)(self._make_dn)

    def root(self) -> Object:
        """Return the top-level object in the NTDS database."""
        if (root := next(self.children_of(0), None)) is None:
            raise ValueError("No root object found")
        return root

    def root_domain(self) -> Object:
        """Return the root domain object in the NTDS database."""
        obj = self.root()
        while True:
            for child in obj.children():
                if child.is_deleted:
                    continue

                if child.is_head_of_naming_context:
                    return child

                obj = child
                break
            else:
                break

        raise ValueError("No root domain object found")

    def walk(self) -> Iterator[Object]:
        """Walk through all objects in the NTDS database."""
        stack = [self.root()]
        while stack:
            yield (obj := stack.pop())
            for child in obj.children():
                yield child
                stack.append(child)

    def get(self, dnt: int) -> Object:
        """Retrieve an object by its Directory Number Tag (DNT) value.

        Args:
            dnt: The DNT of the object to retrieve.
        """
        record = self.table.index("DNT_index").search([dnt])
        return Object.from_record(self.db, record)

    def lookup(self, **kwargs) -> Object:
        """Retrieve an object by a single indexed attribute.

        Args:
            **kwargs: Single keyword argument specifying the attribute and value.
        """
        if len(kwargs) != 1:
            raise ValueError("Exactly one keyword argument must be provided")

        ((key, value),) = kwargs.items()
        # TODO: Check if the attribute is indexed
        if (schema := self.schema.lookup(ldap_name=key)) is None:
            raise ValueError(f"Attribute {key!r} is not found in the schema")

        index = self.table.find_index(schema.column_name)
        record = index.search([encode_value(self.db, key, value)])
        return Object.from_record(self.db, record)

    def query(self, query: str, *, optimize: bool = True) -> Iterator[Object]:
        """Execute an LDAP query against the NTDS database.

        Args:
            query: The LDAP query string to execute.
            optimize: Whether to optimize the query, default is ``True``.

        Yields:
            Object instances matching the query. Objects are cast to more specific types when possible.
        """
        for record in Query(self.db, query, optimize=optimize).process():
            yield Object.from_record(self.db, record)

    def search(self, **kwargs: str) -> Iterator[Object]:
        """Perform an attribute-value query. If multiple attributes are provided, it will be treated as an "AND" query.

        Args:
            **kwargs: Keyword arguments specifying the attributes and values.

        Yields:
            Object instances matching the attribute-value pair.
        """
        query = "".join([f"({attr}={value})" for attr, value in kwargs.items()])
        yield from self.query(f"(&{query})")

    def child_of(self, dnt: int, name: str) -> Object | None:
        """Get a specific child object by name for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve the child object for.
            name: The name of the child object to retrieve.
        """
        cursor = self.db.data.table.index("PDNT_index").cursor()
        return Object.from_record(self.db, cursor.search([dnt, name]))

    def children_of(self, dnt: int) -> Iterator[Object]:
        """Get all child objects of a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve child objects for.
        """
        cursor = self.db.data.table.index("PDNT_index").cursor()
        cursor.seek([dnt + 1])
        end = cursor.record()

        cursor.reset()
        cursor.seek([dnt])

        record = cursor.record()
        while record is not None and record != end:
            yield Object.from_record(self.db, record)
            record = cursor.next()

    def _make_dn(self, dnt: int) -> str:
        """Construct Distinguished Name (DN) from a Directory Number Tag (DNT) value.

        This method walks up the parent hierarchy to build the full DN path.

        Args:
            dnt: The DNT to construct the DN for.
        """
        obj = self.get(dnt)

        if obj.dnt in (0, 2):  # Root object
            return ""

        rdn_key = obj.get("RdnType")
        rdn_value = obj.get("name").replace(",", "\\,")
        if not rdn_key or not rdn_value:
            return ""

        parent_dn = self._make_dn(obj.pdnt)
        return f"{rdn_key}={rdn_value}".upper() + (f",{parent_dn}" if parent_dn else "")


class Schema:
    """An index for schema entries providing fast lookups by various keys.

    Provides efficient lookups for schema entries by DNT, OID, ATTRTYP, LDAP display name, and column name.
    """

    def __init__(self):
        self._dnt_index: dict[int, ClassEntry | AttributeEntry] = {}
        self._oid_index: dict[str, ClassEntry | AttributeEntry] = {}

        self._attrtyp_index: dict[int, ClassEntry | AttributeEntry] = {}
        self._class_id_index: dict[int, ClassEntry] = {}
        self._attribute_id_index: dict[int, AttributeEntry] = {}

        self._link_id_index: dict[int, AttributeEntry] = {}
        self._link_name_index: dict[str, AttributeEntry] = {}

        self._ldap_name_index: dict[str, ClassEntry | AttributeEntry] = {}
        self._column_name_index: dict[str, AttributeEntry] = {}

        # Bootstrap fixed database columns (these do not exist in the schema)
        for ldap_name, column_name, syntax in BOOTSTRAP_COLUMNS:
            self._add(
                AttributeEntry(
                    dnt=-1,
                    oid="",
                    id=-1,
                    type=attrtyp_to_oid(syntax),
                    is_single_valued=True,
                    link_id=None,
                    ldap_name=ldap_name,
                    column_name=column_name,
                )
            )

        # Bootstrap initial attributes
        for ldap_name, attribute_id, attribute_syntax, is_single_valued in BOOTSTRAP_ATTRIBUTES:
            self._add_attribute(
                dnt=-1,
                id=attribute_id,
                syntax=attribute_syntax,
                is_single_valued=is_single_valued,
                link_id=None,
                ldap_name=ldap_name,
            )

        # Bootstrap initial object classes
        for ldap_name, class_id in BOOTSTRAP_OBJECT_CLASSES.items():
            self._add_class(
                dnt=-1,
                id=class_id,
                ldap_name=ldap_name,
            )

    def load(self, db: Database) -> None:
        """Load the classes and attributes from the database into the schema index.

        Args:
            db: The database instance to load the schema from.
        """
        root_domain = db.data.root_domain()
        for child in root_domain.child("Configuration").child("Schema").children():
            if isinstance(child, ClassSchema):
                self._add_class(
                    dnt=child.dnt,
                    id=child.get("governsID", raw=True),
                    ldap_name=child.get("lDAPDisplayName"),
                )
            elif isinstance(child, AttributeSchema):
                self._add_attribute(
                    dnt=child.dnt,
                    id=child.get("attributeID", raw=True),
                    syntax=child.get("attributeSyntax", raw=True),
                    is_single_valued=child.get("isSingleValued"),
                    link_id=child.get("linkId"),
                    ldap_name=child.get("lDAPDisplayName"),
                )

    def _add_class(self, dnt: int, id: int, ldap_name: str) -> None:
        entry = ClassEntry(
            dnt=dnt,
            oid=attrtyp_to_oid(id),
            id=id,
            ldap_name=ldap_name,
        )
        self._add(entry)

    def _add_attribute(
        self, dnt: int, id: int, syntax: int, is_single_valued: bool, link_id: int | None, ldap_name: str
    ) -> None:
        type_oid = attrtyp_to_oid(syntax)
        entry = AttributeEntry(
            dnt=dnt,
            oid=attrtyp_to_oid(id),
            id=id,
            type=type_oid,
            is_single_valued=is_single_valued,
            link_id=link_id,
            ldap_name=ldap_name,
            column_name=f"ATT{OID_TO_TYPE[type_oid]}{id}",
        )
        self._add(entry)

    def _add(self, entry: ClassEntry | AttributeEntry) -> None:
        if entry.dnt != -1:
            self._dnt_index[entry.dnt] = entry
        if entry.oid != "":
            self._oid_index[entry.oid] = entry
        if entry.id != -1:
            self._attrtyp_index[entry.id] = entry

        if isinstance(entry, ClassEntry) and entry.id != -1:
            self._class_id_index[entry.id] = entry

        if isinstance(entry, AttributeEntry):
            if entry.id != -1:
                self._attribute_id_index[entry.id] = entry

            self._column_name_index[entry.column_name] = entry

            if entry.link_id is not None:
                self._link_id_index[entry.link_id] = entry

        self._ldap_name_index[entry.ldap_name] = entry

    def lookup(
        self,
        *,
        dnt: int | None = None,
        oid: str | None = None,
        attrtyp: int | None = None,
        class_id: int | None = None,
        attribute_id: int | None = None,
        link_id: int | None = None,
        ldap_name: str | None = None,
        column_name: str | None = None,
    ) -> ClassEntry | AttributeEntry | None:
        """Lookup a schema entry by an indexed field.

        Args:
            dnt: The DNT (Distinguished Name Tag) of the schema entry to look up.
            oid: The OID (Object Identifier) of the schema entry to look up.
            attrtyp: The ATTRTYP (attribute type) of the schema entry to look up.
            class_id: The class ID of the schema entry to look up.
            attribute_id: The attribute ID of the schema entry to look up.
            link_id: The link ID of the schema entry to look up.
            ldap_name: The LDAP display name of the schema entry to look up.
            column_name: The column name of the schema entry to look up.

        Returns:
            The matching schema entry or ``None`` if not found.
        """
        # Ensure exactly one lookup key is provided
        if (
            sum(key is not None for key in [dnt, oid, attrtyp, class_id, attribute_id, link_id, ldap_name, column_name])
            != 1
        ):
            raise ValueError("Exactly one lookup key must be provided")

        if dnt is not None:
            return self._dnt_index.get(dnt)

        if oid is not None:
            return self._oid_index.get(oid)

        if attrtyp is not None:
            return self._attrtyp_index.get(attrtyp)

        if class_id is not None:
            return self._class_id_index.get(class_id)

        if attribute_id is not None:
            return self._attribute_id_index.get(attribute_id)

        if link_id is not None:
            return self._link_id_index.get(link_id)

        if ldap_name is not None:
            return self._ldap_name_index.get(ldap_name)

        if column_name is not None:
            return self._column_name_index.get(column_name)

        return None


class LinkTable:
    """Represents the ``link_table`` in the NTDS database.

    This table contains link records representing relationships between directory objects.
    """

    def __init__(self, db: Database):
        self.db = db
        self.table = self.db.ese.table("link_table")

    def links(self, dnt: int, name: str | None = None) -> Iterator[Object]:
        """Get all linked objects for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve linked objects for.
            name: An optional link name to filter the linked objects.
        """
        yield from (obj for _, obj in self._links(dnt, self._link_base(name) if name else None))

    def all_links(self, dnt: int) -> Iterator[tuple[str, Object]]:
        """Get all linked objects along with their link names for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve linked objects for.
        """
        for base, obj in self._links(dnt):
            if (entry := self.db.data.schema.lookup(link_id=base * 2)) is not None:
                yield entry.ldap_name, obj

    def backlinks(self, dnt: int, name: str | None = None) -> Iterator[Object]:
        """Get all backlink objects for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve backlink objects for.
            name: An optional link name to filter the backlink objects.
        """
        yield from (obj for _, obj in self._backlinks(dnt, self._link_base(name) if name else None))

    def all_backlinks(self, dnt: int) -> Iterator[tuple[str, Object]]:
        """Get all backlink objects along with their link names for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve backlink objects for.
        """
        for base, obj in self._backlinks(dnt):
            if (entry := self.db.data.schema.lookup(link_id=base * 2)) is not None:
                yield entry.ldap_name, obj

    def has_link(self, link_dnt: int, name: str, backlink_dnt: int) -> bool:
        """Check if a specific link exists between two DNTs and a given link name.

        Args:
            link_dnt: The DNT of the link object.
            backlink_dnt: The DNT of the backlink object.
            name: The link name to check against.
        """
        return self._has_link(link_dnt, self._link_base(name), backlink_dnt)

    def has_backlink(self, backlink_dnt: int, name: str, link_dnt: int) -> bool:
        """Check if a specific backlink exists between two DNTs and a given link name.

        Args:
            backlink_dnt: The DNT of the backlink object.
            link_dnt: The DNT of the link object.
            name: The link name to check against.
        """
        return self._has_backlink(backlink_dnt, self._link_base(name), link_dnt)

    def _link_base(self, name: str) -> int | None:
        """Get the link ID for a given link name.

        Args:
            name: The link name to retrieve the link ID for.
        """
        if (entry := self.db.data.schema.lookup(ldap_name=name)) is None:
            raise ValueError(f"Link name '{name}' not found in schema")
        return entry.link_id // 2

    def _links(self, dnt: int, base: int | None = None) -> Iterator[tuple[int, Object]]:
        """Get all linked objects for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve linked objects for.
            base: An optional base DNT to filter the linked objects.

        Returns:
            An iterator of tuples containing the link base and the linked object.
        """
        cursor = self.table.index("link_index").cursor()
        cursor.seek([dnt] if base is None else [dnt, base])

        record = cursor.record()
        while record is not None and record.get("link_DNT") == dnt:
            if base is not None and record.get("link_base") != base:
                break

            yield record.get("link_base"), self.db.data.get(dnt=record.get("backlink_DNT"))
            record = cursor.next()

    def _has_link(self, link_dnt: int, base: int, backlink_dnt: int) -> bool:
        """Check if a specific link exists between two DNTs and a given link base.

        Args:
            link_dnt: The DNT of the link object.
            backlink_dnt: The DNT of the backlink object.
            base: The link base to check against.
        """
        cursor = self.table.index("link_index").cursor()

        try:
            cursor.search([link_dnt, base, backlink_dnt])
        except KeyNotFoundError:
            return False
        else:
            return True

    def _has_backlink(self, backlink_dnt: int, base: int, link_dnt: int) -> bool:
        """Check if a specific backlink exists between two DNTs and a given link base.

        Args:
            backlink_dnt: The DNT of the backlink object.
            link_dnt: The DNT of the link object.
            base: The link base to check against.
        """
        cursor = self.table.index("backlink_index").cursor()

        try:
            cursor.search([backlink_dnt, base, link_dnt])
        except KeyNotFoundError:
            return False
        else:
            return True

    def _backlinks(self, dnt: int, base: int | None = None) -> Iterator[tuple[int, Object]]:
        """Get all backlink objects for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve backlink objects for.
            base: An optional base DNT to filter the backlink objects.

        Returns:
            An iterator of tuples containing the link base and the backlinked object.
        """
        cursor = self.table.index("backlink_index").cursor()
        cursor.seek([dnt] if base is None else [dnt, base])

        record = cursor.record()
        while record is not None and record.get("backlink_DNT") == dnt:
            if base is not None and record.get("link_base") != base:
                break

            yield record.get("link_base"), self.db.data.get(dnt=record.get("link_DNT"))
            record = cursor.next()


class SecurityDescriptorTable:
    """Represents the ``sd_table`` in the NTDS database.

    This table contains security descriptors associated with directory objects.
    """

    def __init__(self, db: Database):
        self.db = db
        self.table = self.db.ese.table("sd_table")

    def sd(self, id: int) -> ACL | None:
        """Get the Discretionary Access Control List (DACL), if available.

        Args:
            id: The ID of the security descriptor.
        """
        index = self.table.index("sd_id_index")
        cursor = index.cursor()

        # Get the SecurityDescriptor from the sd_table
        if (record := cursor.search([id])) is None:
            return None

        if (value := record.get("sd_value")) is None:
            return None

        return SecurityDescriptor(BytesIO(value))
