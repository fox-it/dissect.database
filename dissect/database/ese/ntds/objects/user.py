from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects.organizationalperson import OrganizationalPerson
from dissect.database.ese.ntds.util import UserAccountControl

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects.group import Group
    from dissect.database.ese.ntds.objects.object import Object


class User(OrganizationalPerson):
    """Represents a user object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-user
    """

    __object_class__ = "user"

    def __repr_body__(self) -> str:
        return f"name={self.name!r} sam_account_name={self.sam_account_name!r} is_machine_account={self.is_machine_account()}"  # noqa: E501

    @property
    def sam_account_name(self) -> str:
        """Return the user's sAMAccountName."""
        return self.get("sAMAccountName")

    @property
    def primary_group_id(self) -> str | None:
        """Return the user's primaryGroupID."""
        return self.get("primaryGroupID")

    @property
    def user_account_control(self) -> UserAccountControl:
        """Return the user's userAccountControl flags."""
        return self.get("userAccountControl")

    def is_machine_account(self) -> bool:
        """Return whether this user is a machine account."""
        return UserAccountControl.WORKSTATION_TRUST_ACCOUNT in self.user_account_control

    def groups(self) -> Iterator[Group]:
        """Yield all groups this user is a member of."""
        self._assert_local()

        yield from self.db.link.backlinks(self.dnt, "memberOf")

        # We also need to include the group with primaryGroupID matching the user's primaryGroupID
        if self.primary_group_id is not None:
            yield from self.db.data.search(objectSid=f"{self.sid.rsplit('-', 1)[0]}-{self.primary_group_id}")

    def is_member_of(self, group: Group) -> bool:
        """Return whether the user is a member of the given group.

        Args:
            group: The :class:`Group` to check membership for.
        """
        return any(g.dnt == group.dnt for g in self.groups())

    def managed_objects(self) -> Iterator[Object]:
        """Yield all objects managed by this user."""
        self._assert_local()

        yield from self.db.link.backlinks(self.dnt, "managedObjects")
