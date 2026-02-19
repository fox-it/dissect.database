from __future__ import annotations

from functools import cached_property, lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.ese.ese import ESE
from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.ntds.objects import DomainDNS, Object
from dissect.database.ese.ntds.pek import PEK
from dissect.database.ese.ntds.query import Query
from dissect.database.ese.ntds.schema import Schema
from dissect.database.ese.ntds.sd import SecurityDescriptor
from dissect.database.ese.ntds.util import DN, SearchFlags, encode_value

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.index import Index
    from dissect.database.ese.ntds.objects import DMD, NTDSDSA, Top


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
        self.hiddentable = self.db.ese.table("hiddentable")
        self.hiddeninfo = next(self.hiddentable.records(), None)

        self.schema = Schema()

        # Cache frequently used and "expensive" methods
        self.get = lru_cache(4096)(self.get)
        self._make_dn = lru_cache(4096)(self._make_dn)

    def dsa(self) -> NTDSDSA:
        """Return the Directory System Agent (DSA) object."""
        if not self.hiddeninfo:
            raise ValueError("No hiddentable information available")
        return self.get(self.hiddeninfo.get("dsa_col"))

    def dmd(self) -> DMD:
        """Return the Directory Management Domain (DMD) object, a.k.a. the schema container."""
        if not self.hiddeninfo:
            raise ValueError("No hiddentable information available")
        return self.get(self.dsa().get("dMDLocation", raw=True))

    def root(self) -> Top:
        """Return the top-level object in the NTDS database."""
        if (root := next(self.children_of(0), None)) is None:
            raise ValueError("No root object found")
        return root

    def root_domain(self) -> DomainDNS | None:
        """Return the root domain object in the NTDS database. For AD LDS, this will return ``None``."""
        stack = [self.root()]
        while stack:
            if (obj := stack.pop()).is_deleted:
                continue

            if isinstance(obj, DomainDNS) and obj.is_head_of_naming_context:
                return obj

            stack.extend(obj.children())

        return None

    @cached_property
    def pek(self) -> PEK | None:
        """Return the PEK."""
        if (root_domain := self.root_domain()) is None:
            # Maybe this is an AD LDS database
            if (root_pek := self.root().get("pekList")) is None:
                # It's not
                return None

            # Lookup the schema pek and permutate the boot key
            # https://www.synacktiv.com/publications/using-ntdissector-to-extract-secrets-from-adam-ntds-files
            schema_pek = self.lookup(objectClass="dMD").get("pekList")
            boot_key = bytes(
                [root_pek[i] for i in [2, 4, 25, 9, 7, 27, 5, 11]]
                + [schema_pek[i] for i in [37, 2, 17, 36, 20, 11, 22, 7]]
            )

            # Lookup the actual PEK and unlock it
            pek = PEK(self.lookup(objectClass="configuration").get("pekList"))
            pek.unlock(boot_key)
            return pek
        return root_domain.pek

    def walk(self) -> Iterator[Object]:
        """Walk through all objects in the NTDS database."""
        stack = [self.root()]
        while stack:
            yield (obj := stack.pop())
            stack.extend(obj.children())

    def iter(self) -> Iterator[Object]:
        """Iterate over all objects in the NTDS database."""
        for record in self.table.records():
            yield Object.from_record(self.db, record)

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
        # TODO: Check if the attribute is indexed, use (and expand) _get_index
        if (schema := self.schema.lookup_attribute(name=key)) is None:
            raise ValueError(f"Attribute {key!r} is not found in the schema")

        index = self.table.find_index(schema.column)
        record = index.search([encode_value(self.db, schema, value)])
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
        end = cursor.seek([dnt + 1]).record()

        cursor.reset()
        cursor.seek([dnt])

        record = cursor.record()
        while record is not None and record != end:
            yield Object.from_record(self.db, record)
            record = cursor.next()

    def _make_dn(self, dnt: int) -> DN:
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
        dn = f"{rdn_key}={rdn_value}".upper() + (f",{parent_dn}" if parent_dn else "")

        return DN(dn, obj, parent_dn if parent_dn else None)

    def _get_index(self, attribute: str) -> Index:
        """Get the index for a given attribute name.

        Args:
            attribute: The attribute name to get the index for.
        """
        if (schema := self.schema.lookup_attribute(name=attribute)) is None:
            raise ValueError(f"Attribute not found in schema: {attribute!r}")

        if schema.search_flags is None:
            raise ValueError(f"Attribute is not indexed: {attribute!r}")

        if SearchFlags.Indexed in schema.search_flags:
            name = f"INDEX_{schema.id:08x}"
        elif SearchFlags.TupleIndexed in schema.search_flags:
            name = f"INDEX_T_{schema.id:08x}"
        else:
            # TODO add ContainerIndexed
            raise ValueError(f"Attribute is not indexed: {attribute!r}")

        return self.table.index(name)


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
            if (schema := self.db.data.schema.lookup_attribute(link_id=base * 2)) is not None:
                yield schema.name, obj

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
            if (schema := self.db.data.schema.lookup_attribute(link_id=(base * 2) + 1)) is not None:
                yield schema.name, obj

    def has_link(self, link_dnt: int, name: str, backlink_dnt: int) -> bool:
        """Check if a specific link exists between two DNTs and a given link name.

        Args:
            link_dnt: The DNT of the link object.
            name: The link name to check against.
            backlink_dnt: The DNT of the backlink object.
        """
        return self._has_link(link_dnt, self._link_base(name), backlink_dnt)

    def has_backlink(self, backlink_dnt: int, name: str, link_dnt: int) -> bool:
        """Check if a specific backlink exists between two DNTs and a given link name.

        Args:
            backlink_dnt: The DNT of the backlink object.
            name: The link name to check against.
            link_dnt: The DNT of the link object.
        """
        return self._has_backlink(backlink_dnt, self._link_base(name), link_dnt)

    def _link_base(self, name: str) -> int:
        """Get the link ID for a given link name.

        Args:
            name: The link name to retrieve the link ID for.
        """
        if (schema := self.db.data.schema.lookup_attribute(name=name)) is None:
            raise ValueError(f"Link name '{name}' not found in schema")
        return schema.link_id // 2

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
            base: The link base to check against.
            backlink_dnt: The DNT of the backlink object.
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
            base: The link base to check against.
            link_dnt: The DNT of the link object.
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

    def sd(self, id: int) -> SecurityDescriptor | None:
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
