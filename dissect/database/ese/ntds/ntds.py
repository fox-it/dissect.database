from __future__ import annotations

import logging
from typing import TYPE_CHECKING, BinaryIO

from dissect.database.ese.ntds.database import Database

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.object import Computer, DomainDNS, Group, Object, Server, User


log = logging.getLogger(__name__)


class NTDS:
    """NTDS.dit Active Directory Domain Services (AD DS) database parser.

    For the curious, NTDS.dit stands for "New Technology Directory Services Directory Information Tree".

    Allows convenient querying and extraction of data from an NTDS.dit file, including users, computers, groups,
    and their relationships.

    Args:
        fh: A file-like object of the NTDS.dit database.
    """

    def __init__(self, fh: BinaryIO):
        self.db = Database(fh)

    def root(self) -> Object:
        """Return the root object of the Active Directory."""
        return self.db.data.root()

    def root_domain(self) -> DomainDNS:
        """Return the root domain object of the Active Directory."""
        return self.db.data.root_domain()

    def query(self, query: str, *, optimize: bool = True) -> Iterator[Object]:
        """Execute an LDAP query against the NTDS database.

        Args:
            query: The LDAP query string to execute.
            optimize: Whether to optimize the query, default is ``True``.

        Yields:
            Object instances matching the query. Objects are cast to more specific types when possible.
        """
        yield from self.db.data.query(query, optimize=optimize)

    def lookup(self, **kwargs: str) -> Iterator[Object]:
        """Perform an attribute-value query. If multiple attributes are provided, it will be treated as an "AND" query.

        Args:
            **kwargs: Keyword arguments specifying the attributes and values.

        Yields:
            Object instances matching the attribute-value pair.
        """
        yield from self.db.data.search(**kwargs)

    def groups(self) -> Iterator[Group]:
        """Get all group objects from the database."""
        yield from self.lookup(objectCategory="group")

    def servers(self) -> Iterator[Server]:
        """Get all server objects from the database."""
        yield from self.lookup(objectCategory="server")

    def users(self) -> Iterator[User]:
        """Get all user objects from the database."""
        yield from self.lookup(objectCategory="person")

    def computers(self) -> Iterator[Computer]:
        """Get all computer objects from the database."""
        yield from self.lookup(objectCategory="computer")
