from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class NTDSSiteSettings(Top):
    """Represents the nTDSSiteSettings object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntdssitesettings
    """

    __object_class__ = "nTDSSiteSettings"

    def __repr__(self) -> str:
        return f"<NTDSSiteSettings name={self.name!r}>"
