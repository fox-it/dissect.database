from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class SubSchema(Top):
    """Represents a sub-schema object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-subschema
    """

    __object_class__ = "subSchema"
