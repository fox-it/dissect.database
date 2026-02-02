from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class Container(Top):
    """Represents a container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-container
    """

    __object_class__ = "container"
