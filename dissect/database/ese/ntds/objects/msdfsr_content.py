from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRContent(Top):
    """Represents the msDFSR-Content object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-content
    """

    __object_class__ = "msDFSR-Content"
