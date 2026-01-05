from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class InterSiteTransport(Top):
    """Represents an inter-site transport object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-intersitetransport
    """

    __object_class__ = "interSiteTransport"
