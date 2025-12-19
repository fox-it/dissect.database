from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class DnsZone(Top):
    """Represents a DNS zone object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnszone
    """

    __object_class__ = "dnsZone"

    def __repr__(self) -> str:
        return f"<DnsZone name={self.name!r}>"
