from __future__ import annotations

from dissect.database.ese.ntds.objects.ipsecbase import IpsecBase


class IpsecISAKMPPolicy(IpsecBase):
    """Represents an IPsec ISAKMP policy object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ipsecisakmppolicy
    """

    __object_class__ = "ipsecISAKMPPolicy"
