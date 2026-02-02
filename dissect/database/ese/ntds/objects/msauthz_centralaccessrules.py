from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSAuthzCentralAccessRules(Top):
    """Represents the msAuthz-CentralAccessRules object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msauthz-centralaccessrules
    """

    __object_class__ = "msAuthz-CentralAccessRules"
