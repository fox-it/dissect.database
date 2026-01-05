from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class DMD(Top):
    """Represents the DMD (Directory Management Domain) object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-dmd
    """

    __object_class__ = "dMD"
