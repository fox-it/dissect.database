from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class ServersContainer(Top):
    """Represents a servers container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-serverscontainer
    """

    __object_class__ = "serversContainer"
