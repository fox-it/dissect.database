from __future__ import annotations

from dissect.database.ese.ntds.objects.container import Container


class GroupPolicyContainer(Container):
    """Represents a group policy container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-grouppolicycontainer
    """

    __object_class__ = "groupPolicyContainer"
