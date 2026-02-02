from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class InterSiteTransportContainer(Top):
    """Represents the interSiteTransportContainer object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-intersitetransportcontainer
    """

    __object_class__ = "interSiteTransportContainer"
