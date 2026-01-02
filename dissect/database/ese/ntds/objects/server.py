from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.top import Top

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object


class Server(Top):
    """Represents a server object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-server
    """

    __object_class__ = "server"

    def __repr__(self) -> str:
        return f"<Server name={self.name!r}>"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this server."""
        yield from self.db.link.links(self.dnt, "managedBy")
