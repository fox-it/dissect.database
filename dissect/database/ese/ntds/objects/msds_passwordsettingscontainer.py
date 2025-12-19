from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSPasswordSettingsContainer(Top):
    """Represents the MSDS-PasswordSettingsContainer object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-passwordsettingscontainer
    """

    __object_class__ = "msDS-PasswordSettingsContainer"

    def __repr__(self) -> str:
        return f"<MSDSPasswordSettingsContainer name={self.name!r}>"
