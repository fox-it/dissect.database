from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.top import Top

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object


class OrganizationalUnit(Top):
    """Represents an organizational unit object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-organizationalunit
    """

    __object_class__ = "organizationalUnit"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this organizational unit."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
