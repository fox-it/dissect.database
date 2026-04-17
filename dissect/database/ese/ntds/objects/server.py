from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.top import Top

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Computer, Object


class Server(Top):
    """Represents a server object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-server
    """

    __object_class__ = "server"

    @property
    def dns_host_name(self) -> str | None:
        """Return the dNSHostName of this server."""
        return self.get("dNSHostName")

    def computer(self) -> Computer | None:
        """Return the computer object associated with this server, if any."""
        self._assert_local()

        return next(self.db.link.links(self.dnt, "serverReference"), None)

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this server."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
