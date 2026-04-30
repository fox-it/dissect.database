from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class QueryPolicy(Top):
    """Represents a query policy object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-querypolicy
    """

    __object_class__ = "queryPolicy"
