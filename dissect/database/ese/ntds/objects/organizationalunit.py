from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class OrganizationalUnit(Top):
    """Represents an organizational unit object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-organizationalunit
    """

    __object_class__ = "organizationalUnit"

    def __repr__(self) -> str:
        return f"<OrganizationalUnit name={self.name!r}>"
