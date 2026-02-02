from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class InfrastructureUpdate(Top):
    """Represents an infrastructure update object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-infrastructureupdate
    """

    __object_class__ = "infrastructureUpdate"
