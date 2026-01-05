from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSValueType(Top):
    """Represents a value type object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-valuetype
    """

    __object_class__ = "msDS-ValueType"
