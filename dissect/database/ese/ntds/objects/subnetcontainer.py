from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class SubnetContainer(Top):
    """Represents a subnet container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-subnetcontainer
    """

    __object_class__ = "subnetContainer"

    def __repr__(self) -> str:
        return f"<SubnetContainer name={self.name!r}>"
