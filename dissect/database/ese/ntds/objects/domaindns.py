from __future__ import annotations

from dissect.database.ese.ntds.objects.domain import Domain
from dissect.database.ese.ntds.pek import PEK


class DomainDNS(Domain):
    """Represents a domain DNS object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-domaindns
    """

    __object_class__ = "domainDNS"

    @property
    def pek(self) -> PEK | None:
        """The PEK list associated with this domain DNS object, if any."""
        if (pek := self.get("pekList")) is not None:
            return PEK(pek)
        return None

    @property
    def behavior_version(self) -> int | None:
        """Return the msDS-Behavior-Version of this domain DNS object."""
        return self.get("msDS-Behavior-Version")
