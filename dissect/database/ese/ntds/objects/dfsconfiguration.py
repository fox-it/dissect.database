from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class DfsConfiguration(Top):
    """Represents a DFS configuration object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-dfsconfiguration
    """

    __object_class__ = "dfsConfiguration"
