from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from dissect.database.ese.ntds.objects.top import Top
from dissect.database.ese.ntds.util import GroupPolicyOption

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object
    from dissect.database.ese.ntds.objects.object import DecoderMap


class Site(Top):
    """Represents the site object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-site
    """

    __object_class__ = "site"
    __decoders__: ClassVar[DecoderMap] = {
        "gPOptions": lambda db, value: GroupPolicyOption(value),
    }

    @property
    def gp_link(self) -> str:
        """Return the group policy link of the site."""
        return self.get("gPLink")

    @property
    def gp_options(self) -> int:
        """Return the group policy options of the site."""
        return self.get("gPOptions", 0)

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this site."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")
