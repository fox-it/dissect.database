from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class FileLinkTracking(Top):
    """Represents a file link tracking object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-filelinktracking
    """

    __object_class__ = "fileLinkTracking"
