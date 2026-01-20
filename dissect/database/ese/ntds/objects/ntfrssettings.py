from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.applicationsettings import ApplicationSettings

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object


class NTFRSSettings(ApplicationSettings):
    """Represents an NTFRS settings object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntfrssettings
    """

    __object_class__ = "nTFRSSettings"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this NTFRS settings object."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
