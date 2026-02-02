from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.top import Top

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object


class DnsZone(Top):
    """Represents a DNS zone object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnszone
    """

    __object_class__ = "dnsZone"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this DNS zone."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
