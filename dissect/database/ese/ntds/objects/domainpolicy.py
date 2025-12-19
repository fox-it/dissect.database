from __future__ import annotations

from dissect.database.ese.ntds.objects.leaf import Leaf


class DomainPolicy(Leaf):
    """Represents a domain policy object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-domainpolicy
    """

    __object_class__ = "domainPolicy"

    def __repr__(self) -> str:
        return f"<DomainPolicy name={self.name!r}>"
