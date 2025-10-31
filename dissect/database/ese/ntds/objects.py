from collections.abc import Generator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS

from dissect.database.ese.ntds.secd import ACL


class Object:
    """Base class for all objects in the NTDS database."""

    def __init__(self, record: "Object | dict", ntds: "NTDS" = None):
        if isinstance(record, Object):
            self.record = record.record
            self.ntds = record.ntds
        else:
            self.record = record
            self.ntds = ntds

    def __getitem__(self, key: str) -> Any:
        return self.record[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.record[key] = value

    def __getattr__(self, name: str) -> Any:
        return self.record[name]

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("record", "ntds"):
            super().__setattr__(name, value)
        else:
            self.record[name] = value

    @property
    def distinguishedName(self) -> str:
        return self.ntds.construct_distinguished_name(self.record)

    @property
    def DN(self) -> int:
        return self.distinguishedName

    @property
    def dacl(self) -> ACL:
        return self.ntds.dacl(self)

    def __repr__(self):
        return f"Object(name={self.name}, objectCategory={self.objectCategory}, objectClass={self.objectClass})"


class User(Object):
    def __init__(self, obj: Object):
        super().__init__(obj)

    def is_machine_account(self) -> bool:
        return (self.userAccountControl & 0x1000) == 0x1000

    def groups(self) -> Generator["Group"]:
        """Returns the groups this user is a member of."""
        yield from self.ntds.get_groups_for_member(self)

    def is_member_of(self, group: "Group") -> bool:
        """Check if the user is a member of the specified group."""
        return any(g.DNT == group.DNT for g in self.groups())

    def __repr__(self):
        return (
            f"User(name={self.name}, sAMAccountName={self.sAMAccountName}, "
            f"is_machine_account={self.is_machine_account()})"
        )


class Computer(Object):
    def __init__(self, obj: Object):
        super().__init__(obj)

    def __repr__(self):
        return f"Computer(name={self.displayName})"


class Group(Object):
    def __init__(self, obj: Object):
        super().__init__(obj)

    def members(self) -> Generator[User]:
        """Returns the members of the group."""
        yield from self.ntds.get_members_from_group(self)

    def is_member(self, user: User) -> bool:
        """Check if the specified user is a member of this group."""
        return any(u.DNT == user.DNT for u in self.members())

    def __repr__(self):
        return f"Group(name={self.sAMAccountName})"


# Define which objectClass maps to which class
# The order is of importance here; computers are also users, so the most
# specific classes should come first.
OBJECTCLASS_MAPPING = {
    "computer": Computer,
    "group": Group,
    "user": User,
}
