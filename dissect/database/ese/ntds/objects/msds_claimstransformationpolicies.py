from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSClaimsTransformationPolicies(Top):
    """Represents the msDS-ClaimsTransformationPolicies object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-claimstransformationpolicies
    """

    __object_class__ = "msDS-ClaimsTransformationPolicies"
