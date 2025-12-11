from __future__ import annotations

import logging
from functools import lru_cache
from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.ese.ese import ESE
from dissect.database.ese.ntds.object import Object
from dissect.database.ese.ntds.query import Query
from dissect.database.ese.ntds.schema import Schema
from dissect.database.ese.ntds.sd import ACL, SecurityDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterator


log = logging.getLogger(__name__)


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


class DataTable:
    """Represents the ``datatable`` in the NTDS database."""

    def __init__(self, db: Database):
        self.db = db
        self.table = self.db.ese.table("datatable")

        self.schema = Schema.from_database(self.db.ese)

        # Cache frequently used and "expensive" methods
        self._lookup_dnt = lru_cache(4096)(self._lookup_dnt)
        self._make_dn = lru_cache(4096)(self._make_dn)

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

    def lookup(self, **kwargs: str) -> Iterator[Object]:
        """Perform an attribute-value query. If multiple attributes are provided, it will be treated as an "AND" query.

        Args:
            **kwargs: Keyword arguments specifying the attributes and values.

        Yields:
            Object instances matching the attribute-value pair.
        """
        query = "".join([f"({attr}={value})" for attr, value in kwargs.items()])
        yield from self.query(f"(&{query})")

    def _lookup_dnt(self, dnt: int) -> Object:
        """Lookup an object by its Directory Number Tag (DNT) value.

        Args:
            dnt: The DNT to look up.
        """
        record = self.table.index("DNT_index").cursor().find(DNT_col=dnt)
        return Object.from_record(self.db, record)

    def _make_dn(self, dnt: int) -> str:
        """Construct Distinguished Name (DN) from a Directory Number Tag (DNT) value.

        This method walks up the parent hierarchy to build the full DN path.

        Args:
            dnt: The DNT to construct the DN for.
        """
        obj = self._lookup_dnt(dnt)

        components = []
        while True:
            if obj.get("DNT") in (0, 2):  # Root object
                break

            if (pdnt := obj.get("Pdnt")) is None:
                break

            rdn_key = self.schema.lookup(attrtyp=obj.get("RdnType")).ldap_name
            rdn_value = obj.get("name")

            if rdn_key and rdn_value:
                components.append(f"{rdn_key}={rdn_value}".upper())

            # Move to parent
            obj = self._lookup_dnt(pdnt)

        return ",".join(components)


class LinkTable:
    """Represents the ``link_table`` in the NTDS database.

    This table contains link records representing relationships between directory objects.
    """

    def __init__(self, db: Database):
        self.db = db
        self.table = self.db.ese.table("link_table")

    def links(self, dnt: int) -> Iterator[Object]:
        """Get all linked objects for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve linked objects for.
        """
        cursor = self.table.index("link_index").cursor()
        cursor.seek(link_DNT=dnt)

        while (record := cursor.record()).get("link_DNT") == dnt:
            linked_dnt = record.get("backlink_DNT")
            yield self.db.data._lookup_dnt(linked_dnt)
            cursor.next()

    def backlinks(self, dnt: int) -> Iterator[Object]:
        """Get all backlink objects for a given Directory Number Tag (DNT).

        Args:
            dnt: The DNT to retrieve backlink objects for.
        """
        cursor = self.table.index("backlink_index").cursor()
        cursor.seek(backlink_DNT=dnt)

        while (record := cursor.record()).get("backlink_DNT") == dnt:
            linked_dnt = record.get("link_DNT")
            yield self.db.data._lookup_dnt(linked_dnt)
            cursor.next()


class SecurityDescriptorTable:
    """Represents the ``sd_table`` in the NTDS database.

    This table contains security descriptors associated with directory objects.
    """

    def __init__(self, db: Database):
        self.db = db
        self.table = self.db.ese.table("sd_table")

    def dacl(self, id: int) -> ACL | None:
        """Get the Discretionary Access Control List (DACL), if available.

        Args:
            id: The ID of the security descriptor.
        """
        index = self.table.index("sd_id_index")
        cursor = index.cursor()

        # Get the SecurityDescriptor from the sd_table
        if (record := cursor.find(sd_id=id)) is None:
            return None

        if (value := record.get("sd_value")) is None:
            return None

        sd = SecurityDescriptor(BytesIO(value))
        return sd.dacl
