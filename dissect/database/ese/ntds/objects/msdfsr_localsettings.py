from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRLocalSettings(Top):
    """Represents the msDFSR-LocalSettings object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-localsettings
    """

    __object_class__ = "msDFSR-LocalSettings"
