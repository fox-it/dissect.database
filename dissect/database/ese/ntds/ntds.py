from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.database.ese.ntds.database import Database
from dissect.database.ese.ntds.objects.secret import BackupKey

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import (
        Computer,
        DomainDNS,
        Group,
        GroupPolicyContainer,
        Object,
        Secret,
        Server,
        TrustedDomain,
        User,
    )
    from dissect.database.ese.ntds.pek import PEK


class NTDS:
    """NTDS.dit Active Directory Domain Services (AD DS) database parser.

    For the curious, NTDS.dit stands for "New Technology Directory Services Directory Information Tree".

    Allows convenient querying and extraction of data from an NTDS.dit file, including users, computers, groups,
    and their relationships.

    If you're a brave soul reading this code, you're about to go past the LDAP fairy tale
    and into the "ntds internals are cursed" zone.

    Args:
        fh: A file-like object of the NTDS.dit database.
    """

    def __init__(self, fh: BinaryIO):
        self.db = Database(fh)

    def root(self) -> Object:
        """Return the root object of the Active Directory."""
        return self.db.data.root()

    def root_domain(self) -> DomainDNS | None:
        """Return the root domain object of the Active Directory."""
        return self.db.data.root_domain()

    @property
    def pek(self) -> PEK | None:
        """Return the PEK associated with the root domain."""
        return self.db.data.pek

    def walk(self) -> Iterator[Object]:
        """Walk through all objects in the NTDS database."""
        yield from self.db.data.walk()

    def query(self, query: str, *, optimize: bool = True) -> Iterator[Object]:
        """Execute an LDAP query against the NTDS database.

        Args:
            query: The LDAP query string to execute.
            optimize: Whether to optimize the query, default is ``True``.

        Yields:
            Object instances matching the query. Objects are cast to more specific types when possible.
        """
        yield from self.db.data.query(query, optimize=optimize)

    def search(self, **kwargs: str) -> Iterator[Object]:
        """Perform an attribute-value query. If multiple attributes are provided, it will be treated as an "AND" query.

        Args:
            **kwargs: Keyword arguments specifying the attributes and values.

        Yields:
            Object instances matching the attribute-value pair.
        """
        yield from self.db.data.search(**kwargs)

    def groups(self) -> Iterator[Group]:
        """Get all group objects from the database."""
        yield from self.search(objectCategory="group")

    def servers(self) -> Iterator[Server]:
        """Get all server objects from the database."""
        yield from self.search(objectCategory="server")

    def users(self) -> Iterator[User]:
        """Get all user objects from the database."""
        yield from self.search(objectCategory="person", objectClass="user")

    def computers(self) -> Iterator[Computer]:
        """Get all computer objects from the database."""
        yield from self.search(objectCategory="computer")

    def trusts(self) -> Iterator[TrustedDomain]:
        """Get all trust objects from the database."""
        yield from self.search(objectClass="trustedDomain")

    def group_policies(self) -> Iterator[GroupPolicyContainer]:
        """Get all group policy objects (GPO) objects from the database."""
        yield from self.search(objectClass="groupPolicyContainer")

    def secrets(self) -> Iterator[Secret]:
        """Get all secret objects from the database."""
        yield from self.search(objectClass="secret")

    def backup_keys(self) -> Iterator[BackupKey]:
        """Get all DPAPI backup keys from the database."""
        if not self.pek.unlocked:
            raise ValueError("PEK must be unlocked to retrieve backup keys")

        for secret in self.secrets():
            if secret.is_phantom or not secret.name.startswith("BCKUPKEY_") or secret.name.startswith("BCKUPKEY_P"):
                continue

            yield BackupKey(secret)

    def preferred_backup_keys(self) -> Iterator[BackupKey]:
        """Get preferred DPAPI backup keys from the database."""
        if not self.pek.unlocked:
            raise ValueError("PEK must be unlocked to retrieve backup keys")

        # We could do this the proper way (lookup the BCKUPKEY_P* secrets and then directly lookup the
        # corresponding BCKUPKEY_* secrets), but in practice there are only a few backup keys, so just
        # filter after the fact
        preferred_guids = []
        for secret in self.secrets():
            if secret.is_phantom or not secret.name.startswith("BCKUPKEY_P"):
                continue

            preferred_guids.append(UUID(bytes_le=secret.current_value))

        for key in self.backup_keys():
            if key.guid in preferred_guids:
                yield key
