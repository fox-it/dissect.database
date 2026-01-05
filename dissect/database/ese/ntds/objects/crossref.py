from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class CrossRef(Top):
    """Represents a cross-reference object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-crossref
    """

    __object_class__ = "crossRef"
