from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class Server(Top):
    """Represents a server object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-server
    """

    __object_class__ = "server"

    def __repr__(self) -> str:
        return f"<Server name={self.name!r}>"
