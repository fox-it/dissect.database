from __future__ import annotations

from dissect.database.ese.ntds.objects.msds_claimtypepropertybase import MSDSClaimTypePropertyBase


class MSDSClaimTypes(MSDSClaimTypePropertyBase):
    """Represents a claim types object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-claimtypes
    """

    __object_class__ = "msDS-ClaimTypes"
