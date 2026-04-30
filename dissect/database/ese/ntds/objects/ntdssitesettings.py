from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.top import Top

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object


class NTDSSiteSettings(Top):
    """Represents the nTDSSiteSettings object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntdssitesettings
    """

    __object_class__ = "nTDSSiteSettings"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this NTDS-Site-Settings object."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
