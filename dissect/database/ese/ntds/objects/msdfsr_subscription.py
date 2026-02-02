from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRSubscription(Top):
    """Represents the msDFSR-Subscription object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-subscription
    """

    __object_class__ = "msDFSR-Subscription"
