from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSClaimTypePropertyBase(Top):
    """Base class for claim type property objects in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-claimtypepropertybase
    """

    __object_class__ = "msDS-ClaimTypePropertyBase"
