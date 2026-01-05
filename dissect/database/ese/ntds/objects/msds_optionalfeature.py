from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSOptionalFeature(Top):
    """Represents the msDS-OptionalFeature object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-optionalfeature
    """

    __object_class__ = "msDS-OptionalFeature"
