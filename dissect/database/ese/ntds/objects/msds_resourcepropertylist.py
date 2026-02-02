from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSResourcePropertyList(Top):
    """Represents the msDS-ResourcePropertyList object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-resourcepropertylist
    """

    __object_class__ = "msDS-ResourcePropertyList"
