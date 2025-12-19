from __future__ import annotations

from dissect.database.ese.ntds.objects.applicationsettings import ApplicationSettings


class NTDSDSA(ApplicationSettings):
    """Represents an NTDS DSA object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntdsdsa
    """

    __object_class__ = "nTDSDSA"

    def __repr__(self) -> str:
        return f"<NTDSDSA name={self.name!r}>"
