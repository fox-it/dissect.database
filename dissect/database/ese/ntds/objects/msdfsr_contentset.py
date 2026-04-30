from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRContentSet(Top):
    """Represents the msDFSR-ContentSet object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-contentset
    """

    __object_class__ = "msDFSR-ContentSet"
