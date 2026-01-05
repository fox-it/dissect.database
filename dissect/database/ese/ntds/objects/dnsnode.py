from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class DnsNode(Top):
    """Represents a DNS node object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnsnode
    """

    __object_class__ = "dnsNode"
