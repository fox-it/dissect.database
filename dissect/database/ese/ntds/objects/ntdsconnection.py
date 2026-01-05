from __future__ import annotations

from dissect.database.ese.ntds.objects.leaf import Leaf


class NTDSConnection(Leaf):
    """Represents an NTDS connection object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntdsconnection
    """

    __object_class__ = "nTDSConnection"
