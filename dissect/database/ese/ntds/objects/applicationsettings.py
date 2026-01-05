from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class ApplicationSettings(Top):
    """Represents an application settings object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-applicationsettings
    """

    __object_class__ = "applicationSettings"
