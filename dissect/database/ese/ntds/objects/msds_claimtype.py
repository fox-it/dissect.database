from __future__ import annotations

from dissect.database.ese.ntds.objects.msds_claimtypepropertybase import MSDSClaimTypePropertyBase


class MSDSClaimType(MSDSClaimTypePropertyBase):
    """Represents a claim type object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-claimtype
    """

    __object_class__ = "msDS-ClaimType"
