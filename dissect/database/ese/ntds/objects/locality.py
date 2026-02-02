from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class Locality(Top):
    """Represents a locality object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-locality
    """

    __object_class__ = "locality"
