from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.user import User

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects.object import Object


class Computer(User):
    """Represents a computer object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-computer
    """

    __object_class__ = "computer"

    def __repr__(self) -> str:
        return f"<Computer name={self.name!r}>"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this computer."""
        yield from self.db.link.links(self.dnt, "managedBy")
