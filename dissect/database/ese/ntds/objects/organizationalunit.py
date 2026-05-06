from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from dissect.database.ese.ntds.objects.top import Top
from dissect.database.ese.ntds.util import GroupPolicyOption

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object
    from dissect.database.ese.ntds.objects.object import DecoderMap


class OrganizationalUnit(Top):
    """Represents an organizational unit object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-organizationalunit
    """

    __object_class__ = "organizationalUnit"
    __decoders__: ClassVar[DecoderMap] = {
        "gPOptions": lambda db, value: GroupPolicyOption(value),
    }

    @property
    def gp_link(self) -> str | None:
        """Return the group policy link of the organizational unit."""
        return self.get("gPLink")

    @property
    def gp_options(self) -> int | None:
        """Return the group policy options of the organizational unit."""
        return self.get("gPOptions")

    @property
    def telephone_number(self) -> str | None:
        """Return the telephone number of this organizational unit."""
        return self.get("telephoneNumber")

    @property
    def user_password(self) -> str | None:
        """Return the userPassword of this organizational unit."""
        return self.get("userPassword")

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this organizational unit."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
