from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSAuthNPolicies(Top):
    """Represents the msDS-AuthNPolicies object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/619b9625-a57b-4591-8689-ee5bdf6bbb93
    """

    __object_class__ = "msDS-AuthNPolicies"
