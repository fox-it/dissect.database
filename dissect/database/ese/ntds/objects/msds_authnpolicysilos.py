from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSAuthNPolicySilos(Top):
    """Represents the msDS-AuthNPolicySilos object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/997a1ead-e7b6-4b20-8aa0-3e1e9e0f2bf2
    """

    __object_class__ = "msDS-AuthNPolicySilos"
