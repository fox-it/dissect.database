from __future__ import annotations

from dissect.database.ese.ntds.objects.applicationsettings import ApplicationSettings


class NTRFSSettings(ApplicationSettings):
    """Represents an NTFRS settings object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntfrssettings
    """

    __object_class__ = "nTFRSSettings"

    def __repr__(self) -> str:
        return f"<NTRFSSettings name={self.name!r}>"
