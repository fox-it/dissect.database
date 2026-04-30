from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class ClassStore(Top):
    """Represents a class store object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-classstore
    """

    __object_class__ = "classStore"
