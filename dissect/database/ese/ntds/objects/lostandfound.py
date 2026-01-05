from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class LostAndFound(Top):
    """Represents a lost and found object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-lostandfound
    """

    __object_class__ = "lostAndFound"
