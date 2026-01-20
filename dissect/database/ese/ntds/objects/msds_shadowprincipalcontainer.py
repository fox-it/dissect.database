from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSShadowPrincipalContainer(Top):
    """Represents the msDS-ShadowPrincipalContainer object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/5e4a3007-10de-479e-b0a4-3a96271e2640
    """

    __object_class__ = "msDS-ShadowPrincipalContainer"
