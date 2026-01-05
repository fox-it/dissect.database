from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class RIDSet(Top):
    """Represents the RID Set object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ridset
    """

    __object_class__ = "rIDSet"
