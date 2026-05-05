from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from dissect.util.ts import wintimestamp

from dissect.database.ese.ntds.objects.organizationalperson import OrganizationalPerson
from dissect.database.ese.ntds.util import SAMAccountType, UserAccountControl

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.database.ese.ntds.objects.group import Group
    from dissect.database.ese.ntds.objects.object import DecoderMap, Object


class User(OrganizationalPerson):
    """Represents a user object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-user
    """

    __object_class__ = "user"
    __decoders__: ClassVar[DecoderMap] = {
        "sAMAccountType": lambda db, value: SAMAccountType(value),
        "userAccountControl": lambda db, value: UserAccountControl(value),
        "badPasswordTime": lambda db, value: None if value == 0 else wintimestamp(value),
        "lastLogonTimestamp": lambda db, value: None if value == 0 else wintimestamp(value),
        "lastLogon": lambda db, value: None if value == 0 else wintimestamp(value),
        "lastLogoff": lambda db, value: None if value == 0 else wintimestamp(value),
        "pwdLastSet": lambda db, value: None if value == 0 else wintimestamp(value),
        "accountExpires": lambda db, value: None if value in (0, ((1 << 63) - 1)) else wintimestamp(value),
    }

    def __repr_body__(self) -> str:
        return f"name={self.name!r} sam_account_name={self.sam_account_name!r} is_machine_account={self.is_machine_account()}"  # noqa: E501

    @property
    def sam_account_name(self) -> str:
        """Return the user's sAMAccountName."""
        return self.get("sAMAccountName")

    @property
    def sam_account_type(self) -> SAMAccountType:
        """Return the user's sAMAccountType."""
        return self.get("sAMAccountType")

    @property
    def primary_group_id(self) -> str | None:
        """Return the user's primaryGroupID."""
        return self.get("primaryGroupID")

    @property
    def user_account_control(self) -> UserAccountControl:
        """Return the user's userAccountControl flags."""
        return self.get("userAccountControl")

    @property
    def user_principal_name(self) -> str | None:
        """Return the user's userPrincipalName."""
        return self.get("userPrincipalName")

    @property
    def service_principal_name(self) -> list[str]:
        """Return the user's servicePrincipalName."""
        return self.get("servicePrincipalName") or []

    @property
    def home_directory(self) -> str | None:
        """Return the user's home directory."""
        return self.get("homeDirectory")

    @property
    def home_drive(self) -> str | None:
        """Return the user's home drive."""
        return self.get("homeDrive")

    @property
    def script_path(self) -> str | None:
        """Return the user's script path."""
        return self.get("scriptPath")

    @property
    def password_last_set(self) -> datetime | None:
        """Return the last time the user's password was set."""
        return self.get("pwdLastSet")

    @property
    def logon_last_failed(self) -> datetime | None:
        """Return the last time the user had a failed logon attempt."""
        return self.get("badPasswordTime")

    @property
    def logon_last_local(self) -> datetime | None:
        """Return the last time the user had a successful local logon."""
        return self.get("lastLogon")

    @property
    def logon_last_replicated(self) -> datetime | None:
        """Return the last time the user had a successful logon replicated across domain controllers."""
        return self.get("lastLogonTimestamp")

    @property
    def account_expires(self) -> datetime | None:
        """Return the time the user's account expires."""
        return self.get("accountExpires")

    @property
    def admin_count(self) -> int | None:
        """Return the user's adminCount."""
        return self.get("adminCount")

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
