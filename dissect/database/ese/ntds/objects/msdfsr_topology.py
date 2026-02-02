from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRTopology(Top):
    """Represents the msDFSR-Topology object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-topology
    """

    __object_class__ = "msDFSR-Topology"
