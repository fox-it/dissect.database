from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRGlobalSettings(Top):
    """Represents the MSDFSR-GlobalSettings object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-globalsettings
    """

    __object_class__ = "msDFSR-GlobalSettings"
