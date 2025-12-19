from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSAuthNPolicySilos(Top):
    """Represents the msDS-AuthNPolicySilos object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-authnpolicysilos
    """

    __object_class__ = "msDS-AuthNPolicySilos"

    def __repr__(self) -> str:
        return f"<MSDSAuthNPolicySilos name={self.name!r}>"
