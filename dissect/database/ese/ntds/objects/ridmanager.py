from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class RIDManager(Top):
    """Represents the RID Manager object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ridmanager
    """

    __object_class__ = "rIDManager"
