from __future__ import annotations

from dissect.database.ese.ntds.objects.domain import Domain


class DomainDNS(Domain):
    """Represents a domain DNS object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-domaindns
    """

    __object_class__ = "domainDNS"

    def __repr__(self) -> str:
        return f"<DomainDNS name={self.name!r}>"
