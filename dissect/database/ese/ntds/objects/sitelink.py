from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class SiteLink(Top):
    """Represents a site link object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-sitelink
    """

    __object_class__ = "siteLink"
