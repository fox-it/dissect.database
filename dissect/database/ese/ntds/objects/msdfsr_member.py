from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRMember(Top):
    """Represents the msDFSR-Member object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-member
    """

    __object_class__ = "msDFSR-Member"
