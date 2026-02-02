from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class DSUISettings(Top):
    """Represents a DS-UI settings object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-dsuisettings
    """

    __object_class__ = "dSUISettings"
