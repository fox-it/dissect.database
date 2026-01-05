from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class ForeignSecurityPrincipal(Top):
    """Represents a foreign security principal object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-foreignsecurityprincipal
    """

    __object_class__ = "foreignSecurityPrincipal"
