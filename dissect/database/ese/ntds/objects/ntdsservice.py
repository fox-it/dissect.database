from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class NTDSService(Top):
    """Represents an NTDS service object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntdsservice
    """

    __object_class__ = "nTDSService"
