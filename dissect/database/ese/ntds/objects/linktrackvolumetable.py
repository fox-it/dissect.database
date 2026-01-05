from __future__ import annotations

from dissect.database.ese.ntds.objects.filelinktracking import FileLinkTracking


class LinkTrackVolumeTable(FileLinkTracking):
    """Represents a Link Track Volume Table in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-linktrackvolumetable
    """

    __object_class__ = "linkTrackVolumeTable"
