from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class CRLDistributionPoint(Top):
    """Represents the cRLDistributionPoint object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-crldistributionpoint
    """

    __object_class__ = "cRLDistributionPoint"
