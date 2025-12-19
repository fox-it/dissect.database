from __future__ import annotations

from dissect.database.ese.ntds.objects.locality import Locality


class PhysicalLocation(Locality):
    """Represents a physical location object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-physicallocation
    """

    __object_class__ = "physicalLocation"

    def __repr__(self) -> str:
        return f"<PhysicalLocation name={self.name!r}>"
