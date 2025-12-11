from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from dissect.database.ese.ntds.schema import FIXED_COLUMN_MAP
from dissect.database.ese.ntds.util import decode_value

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.sd import ACL
    from dissect.database.ese.record import Record


class Object:
    """Base class for all objects in the NTDS database.

    Args:
        db: The database instance associated with this object.
        record: The :class:`Record` instance representing this object.
    """

    __object_class__ = "top"
    __known_classes__: ClassVar[dict[str, type[Object]]] = {}

    def __init__(self, db: Database, record: Record):
        self.db = db
        self.record = record

    def __init_subclass__(cls):
        cls.__known_classes__[cls.__object_class__] = cls

    def __repr__(self) -> str:
        return f"<Object name={self.name} objectCategory={self.objectCategory} objectClass={self.objectClass}>"

    def __getattr__(self, name: str) -> Any:
        return self.get(name)

    @classmethod
    def from_record(cls, db: Database, record: Record) -> Object | Group | Server | User | Computer:
        """Create an Object instance from a database record.

        Args:
            db: The database instance associated with this object.
            record: The :class:`Record` instance representing this object.
        """
        if (object_classes := record.get(FIXED_COLUMN_MAP["objectClass"])) is not None:
            for obj_cls in decode_value(db, "objectClass", object_classes):
                if (known_cls := cls.__known_classes__.get(obj_cls)) is not None:
                    return known_cls(db, record)

        return cls(db, record)

    def get(self, name: str) -> Any:
        """Get an attribute value by name. Will decode the value based on the schema.

        Args:
            name: The attribute name to retrieve.
        """
        if name in self.record:
            column_name = name
        elif (entry := self.db.data.schema.lookup(ldap_name=name)) is not None:
            column_name = entry.column_name
        else:
            raise ValueError(f"Attribute {name!r} not found in the NTDS database")

        return decode_value(self.db, name, self.record.get(column_name))

    def as_dict(self) -> dict[str, Any]:
        """Return the object's attributes as a dictionary."""
        result = {}
        for key, value in self.record.as_dict().items():
            if (schema_entry := self.db.data.schema.lookup(column_name=key)) is not None:
                key = schema_entry.ldap_name
            result[key] = decode_value(self.db, key, value)

        return result

    @property
    def distinguishedName(self) -> str | None:
        """Return the fully qualified Distinguished Name (DN) for this object."""
        if (dnt := self.get("DNT")) is not None:
            return self.db.data._make_dn(dnt)
        return None

    DN = distinguishedName

    @property
    def dacl(self) -> ACL | None:
        """Get the Discretionary Access Control List (DACL) for this object.

        Returns:
            The ACL object containing access control entries.
        """
        if (sd_id := self.get("nTSecurityDescriptor")) is not None:
            return self.db.sd.dacl(sd_id)
        return None


class Group(Object):
    """Represents a group object in the Active Directory."""

    __object_class__ = "group"

    def __repr__(self) -> str:
        return f"<Group name={self.sAMAccountName}>"

    def members(self) -> Iterator[User]:
        """Yield all members of this group."""
        yield from self.db.link.links(self.DNT)

        # We also need to include users with primaryGroupID matching the group's RID
        yield from self.db.data.lookup(primaryGroupID=self.objectSid.rsplit("-", 1)[1])

    def is_member(self, user: User) -> bool:
        """Return whether the given user is a member of this group.

        Args:
            user: The :class:`User` to check membership for.
        """
        return any(u.DNT == user.DNT for u in self.members())


class Server(Object):
    """Represents a server object in the Active Directory."""

    __object_class__ = "server"

    def __repr__(self) -> str:
        return f"<Server name={self.name}>"


class User(Object):
    """Represents a user object in the Active Directory."""

    __object_class__ = "user"

    def __repr__(self) -> str:
        return (
            f"<User name={self.name} sAMAccountName={self.sAMAccountName} "
            f"is_machine_account={self.is_machine_account()}>"
        )

    def is_machine_account(self) -> bool:
        """Return whether this user is a machine account."""
        return (self.userAccountControl & 0x1000) == 0x1000

    def groups(self) -> Iterator[Group]:
        """Yield all groups this user is a member of."""
        yield from self.db.link.backlinks(self.DNT)

        # We also need to include the group with primaryGroupID matching the user's primaryGroupID
        if self.primaryGroupID is not None:
            yield from self.db.data.lookup(objectSid=f"{self.objectSid.rsplit('-', 1)[0]}-{self.primaryGroupID}")

    def is_member_of(self, group: Group) -> bool:
        """Return whether the user is a member of the given group.

        Args:
            group: The :class:`Group` to check membership for.
        """
        return any(g.DNT == group.DNT for g in self.groups())


class Computer(User):
    """Represents a computer object in the Active Directory."""

    __object_class__ = "computer"

    def __repr__(self) -> str:
        return f"<Computer name={self.name}>"
