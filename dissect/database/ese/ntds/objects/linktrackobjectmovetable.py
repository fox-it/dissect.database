from __future__ import annotations

from dissect.database.ese.ntds.objects.filelinktracking import FileLinkTracking


class LinkTrackObjectMoveTable(FileLinkTracking):
    """Represents a link track object move table in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-linktrackobjectmovetable
    """

    __object_class__ = "linkTrackObjectMoveTable"
