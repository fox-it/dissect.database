from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class Leaf(Top):
    """Base class for leaf objects in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-leaf
    """

    __object_class__ = "leaf"
