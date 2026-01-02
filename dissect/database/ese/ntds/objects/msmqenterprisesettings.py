from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSMQEnterpriseSettings(Top):
    """Represents the mSMQEnterpriseSettings object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msmqenterprisesettings
    """

    __object_class__ = "mSMQEnterpriseSettings"

    def __repr__(self) -> str:
        return f"<MSMQEnterpriseSettings name={self.name!r}>"
