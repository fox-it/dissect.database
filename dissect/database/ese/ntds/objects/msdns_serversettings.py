from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDNSServerSettings(Top):
    """Represents a DNS server settings object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdns-serversettings
    """

    __object_class__ = "msDNS-ServerSettings"
