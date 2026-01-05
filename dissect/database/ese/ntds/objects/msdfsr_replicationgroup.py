from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRReplicationGroup(Top):
    """Represents the msDFSR-ReplicationGroup object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-replicationgroup
    """

    __object_class__ = "msDFSR-ReplicationGroup"
