from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSResourceProperties(Top):
    """Represents the msDS-ResourceProperties object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-resourceproperties
    """

    __object_class__ = "msDS-ResourceProperties"
