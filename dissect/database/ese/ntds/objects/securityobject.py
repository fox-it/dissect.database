from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class SecurityObject(Top):
    """Represents a security object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-securityobject
    """

    __object_class__ = "securityObject"
