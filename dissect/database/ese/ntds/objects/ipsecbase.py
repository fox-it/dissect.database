from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class IpsecBase(Top):
    """Base class for IPsec objects in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ipsecbase
    """

    __object_class__ = "ipsecBase"
