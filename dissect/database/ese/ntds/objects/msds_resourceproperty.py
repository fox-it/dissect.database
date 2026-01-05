from __future__ import annotations

from dissect.database.ese.ntds.objects.msds_claimtypepropertybase import MSDSClaimTypePropertyBase


class MSDSResourceProperty(MSDSClaimTypePropertyBase):
    """Represents a resource property object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-resourceproperty
    """

    __object_class__ = "msDS-ResourceProperty"
