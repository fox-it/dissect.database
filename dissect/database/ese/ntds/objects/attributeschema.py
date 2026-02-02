from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class AttributeSchema(Top):
    """Represents an attribute schema object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-attributeschema
    """

    __object_class__ = "attributeSchema"
