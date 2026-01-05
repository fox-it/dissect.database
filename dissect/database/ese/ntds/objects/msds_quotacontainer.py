from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDSQuotaContainer(Top):
    """Represents a quota container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-quotacontainer
    """

    __object_class__ = "msDS-QuotaContainer"
