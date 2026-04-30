from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSKDSProvServerConfiguration(Top):
    """Represents the msKds-ProvServerConfiguration object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-mskds-provserverconfiguration
    """

    __object_class__ = "msKds-ProvServerConfiguration"
