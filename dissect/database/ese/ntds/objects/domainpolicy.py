from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.leaf import Leaf

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object


class DomainPolicy(Leaf):
    """Represents a domain policy object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-domainpolicy
    """

    __object_class__ = "domainPolicy"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this domain policy."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
