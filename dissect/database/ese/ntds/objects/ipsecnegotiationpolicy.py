from __future__ import annotations

from dissect.database.ese.ntds.objects.ipsecbase import IpsecBase


class IpsecNegotiationPolicy(IpsecBase):
    """Represents an IPsec negotiation policy object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ipsecnegotiationpolicy
    """

    __object_class__ = "ipsecNegotiationPolicy"
