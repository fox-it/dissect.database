from __future__ import annotations

from dissect.database.ese.ntds.objects.leaf import Leaf


class Secret(Leaf):
    """Represents a secret object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-secret
    """

    __object_class__ = "secret"
