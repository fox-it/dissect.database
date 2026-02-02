from __future__ import annotations

from dissect.database.ese.ntds.objects.ipsecbase import IpsecBase


class IpsecNFA(IpsecBase):
    """Represents an IPsec NFA (Network Filter Action) object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ipsecnfa
    """

    __object_class__ = "ipsecNFA"
