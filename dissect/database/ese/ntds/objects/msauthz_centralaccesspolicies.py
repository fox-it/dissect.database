from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSAuthzCentralAccessPolicies(Top):
    """Represents the msAuthz-CentralAccessPolicies object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msauthz-centralaccesspolicies
    """

    __object_class__ = "msAuthz-CentralAccessPolicies"
