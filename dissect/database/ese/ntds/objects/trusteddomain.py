from __future__ import annotations

from dissect.database.ese.ntds.objects.leaf import Leaf


class TrustedDomain(Leaf):
    """Represents a trusted domain object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-trusteddomain
    """

    __object_class__ = "trustedDomain"
