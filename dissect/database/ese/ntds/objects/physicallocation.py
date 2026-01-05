from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.locality import Locality

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object


class PhysicalLocation(Locality):
    """Represents a physical location object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-physicallocation
    """

    __object_class__ = "physicalLocation"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this physical location."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
