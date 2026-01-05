from __future__ import annotations

from dissect.database.ese.ntds.objects.ipsecbase import IpsecBase


class IpsecFilter(IpsecBase):
    """Represents an IPsec filter object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ipsecfilter
    """

    __object_class__ = "ipsecFilter"
