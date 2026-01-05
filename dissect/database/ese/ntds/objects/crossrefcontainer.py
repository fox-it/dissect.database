from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class CrossRefContainer(Top):
    """Represents a cross-reference container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-crossrefcontainer
    """

    __object_class__ = "crossRefContainer"
