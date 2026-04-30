from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.top import Top

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Object, User


class Group(Top):
    """Represents a group object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-group
    """

    __object_class__ = "group"

    @property
    def sam_account_name(self) -> str:
        """Return the group's sAMAccountName."""
        return self.get("sAMAccountName")

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this group."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "managedBy")

    def members(self) -> Iterator[User]:
        """Yield all members of this group."""
        self._assert_local()

        yield from self.db.link.links(self.dnt, "member")

        # We also need to include users with primaryGroupID matching the group's RID
        yield from self.db.data.search(primaryGroupID=self.rid)

    def is_member(self, user: User) -> bool:
        """Return whether the given user is a member of this group.

        Args:
            user: The :class:`User` to check membership for.
        """
        return any(u.dnt == user.dnt for u in self.members())
