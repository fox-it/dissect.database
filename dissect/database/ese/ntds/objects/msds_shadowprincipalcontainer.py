from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSShadowPrincipalContainer(Top):
    """Represents the msDS-ShadowPrincipalContainer object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-shadowprincipalcontainer
    """

    __object_class__ = "msDS-ShadowPrincipalContainer"

    def __repr__(self) -> str:
        return f"<MSDSShadowPrincipalContainer name={self.name!r}>"
