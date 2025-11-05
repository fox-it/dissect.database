from collections.abc import Generator
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS

from dissect.database.ese.ntds.secd import ACL


class Object:
    """Base class for all objects in the NTDS database."""

    def __init__(self, record: "Object | dict", ntds: "NTDS" = None):
        """Initialize an Object instance.

        Args:
            record: Either an existing Object instance to copy or a dict containing record data.
            ntds: The NTDS instance associated with this object (optional if copying from Object).
        """
        if isinstance(record, Object):
            self.record = record.record
            self.ntds = record.ntds
        else:
            self.record = record
            self.ntds = ntds

    def __getattr__(self, name: str) -> Any:
        """Get an attribute value by name.

        Args:
            name: The attribute name to retrieve.

        Returns:
            The value of the specified attribute.
        """
        return self.record[name]

    def __setattr__(self, name: str, value: Any) -> None:
        """Set an attribute value by name.

        Args:
            name: The attribute name to set.
            value: The value to assign to the attribute.
        """
        if name in ("record", "ntds"):
            super().__setattr__(name, value)
        else:
            self.record[name] = value

    @property
    def distinguishedName(self) -> str:
        """Get the Distinguished Name (DN) for this object.

        Returns:
            The fully qualified Distinguished Name as a string.
        """
        return self.ntds.construct_distinguished_name(self.record)

    @property
    def DN(self) -> int:
        """Get the Distinguished Name (DN) for this object.

        Returns:
            The fully qualified Distinguished Name as a string.
        """
        return self.distinguishedName

    @property
    def dacl(self) -> ACL:
        """Get the Discretionary Access Control List (DACL) for this object.

        Returns:
            The ACL object containing access control entries.
        """
        return self.ntds.dacl(self)

    def __repr__(self):
        return f"<Object name={self.name} objectCategory={self.objectCategory} objectClass={self.objectClass}>"


class User(Object):
    """Represents a user object in the Active Directory."""

    def __init__(self, obj: Object):
        """Initialize a User instance from an Object.

        Args:
            obj: The generic Object to convert to a User.
        """
        super().__init__(obj)

    def is_machine_account(self) -> bool:
        """Check if this user is a machine account.

        Returns:
            True if this is a machine account, False otherwise.
        """
        return (self.userAccountControl & 0x1000) == 0x1000

    def groups(self) -> Generator["Group"]:
        """Get all groups this user is a member of.

        Yields:
            Group objects that this user belongs to.
        """
        yield from self.ntds.get_groups_for_member(self)

    def is_member_of(self, group: "Group") -> bool:
        """Check if the user is a member of the specified group.

        Args:
            group: The Group to check membership for.

        Returns:
            True if the user is a member of the group, False otherwise.
        """
        return any(g.DNT == group.DNT for g in self.groups())

    def __repr__(self):
        return (
            f"<User name={self.name} sAMAccountName={self.sAMAccountName} "
            f"is_machine_account={self.is_machine_account()}>"
        )


class Computer(Object):
    """Represents a computer object in the Active Directory."""

    def __init__(self, obj: Object):
        """Initialize a Computer instance from an Object.

        Args:
            obj: The generic Object to convert to a Computer.
        """
        super().__init__(obj)

    def __repr__(self):
        return f"<Computer name={self.name}>"


class Group(Object):
    """Represents a group object in the Active Directory."""

    def __init__(self, obj: Object):
        """Initialize a Group instance from an Object.

        Args:
            obj: The generic Object to convert to a Group.
        """
        super().__init__(obj)

    def members(self) -> Generator[User]:
        """Get all members of this group.

        Yields:
            User objects that are members of this group.
        """
        yield from self.ntds.get_members_from_group(self)

    def is_member(self, user: User) -> bool:
        """Check if the specified user is a member of this group.

        Args:
            user: The User to check membership for.

        Returns:
            True if the user is a member of this group, False otherwise.
        """
        return any(u.DNT == user.DNT for u in self.members())

    def __repr__(self):
        return f"<Group name={self.sAMAccountName}>"


# Define which objectClass maps to which class
# The order is of importance here; computers are also users, so the most
# specific classes should come first.
OBJECTCLASS_MAPPING = {
    "computer": Computer,
    "group": Group,
    "user": User,
}
