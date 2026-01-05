from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSAuthNPolicies(Top):
    """Represents the msDS-AuthNPolicies object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-authnpolicies
    """

    __object_class__ = "msDS-AuthNPolicies"
