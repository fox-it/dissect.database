from __future__ import annotations

from dissect.database.ese.ntds.objects.securityobject import SecurityObject


class SamServer(SecurityObject):
    """Represents the Sam-Server object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-samserver
    """

    __object_class__ = "samServer"
