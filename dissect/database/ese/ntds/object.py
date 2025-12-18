from __future__ import annotations

import struct
from functools import cached_property
from typing import TYPE_CHECKING, Any, ClassVar

from dissect.database.ese.ntds.util import InstanceType, SystemFlags, UserAccountControl, decode_value

if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime

    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.sd import SecurityDescriptor
    from dissect.database.ese.record import Record


class Object:
    """Base class for all objects in the NTDS database.

    Within NTDS, this would be the "top" class, but we just call it "Object" here for clarity.

    Args:
        db: The database instance associated with this object.
        record: The :class:`Record` instance representing this object.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/041c6068-c710-4c74-968f-3040e4208701
    """

    __object_class__ = "top"
    __known_classes__: ClassVar[dict[str, type[Object]]] = {}

    def __init__(self, db: Database, record: Record):
        self.db = db
        self.record = record

    def __init_subclass__(cls):
        cls.__known_classes__[cls.__object_class__] = cls

    def __repr__(self) -> str:
        return f"<Object name={self.name!r} objectCategory={self.objectCategory} objectClass={self.objectClass}>"

    def __getattr__(self, name: str) -> Any:
        return self.get(name)

    @classmethod
    def from_record(cls, db: Database, record: Record) -> Object | Group | Server | User | Computer:
        """Create an Object instance from a database record.

        Args:
            db: The database instance associated with this object.
            record: The :class:`Record` instance representing this object.
        """
        if (object_classes := _get_attribute(db, record, "objectClass")) is not None:
            for obj_cls in object_classes:
                if (known_cls := cls.__known_classes__.get(obj_cls)) is not None:
                    return known_cls(db, record)

        return cls(db, record)

    def get(self, name: str, *, raw: bool = False) -> Any:
        """Get an attribute value by name. Decodes the value based on the schema.

        Args:
            name: The attribute name to retrieve.
        """
        return _get_attribute(self.db, self.record, name, raw=raw)

    def as_dict(self) -> dict[str, Any]:
        """Return the object's attributes as a dictionary."""
        result = {}
        for key, value in self.record.as_dict().items():
            if (schema_entry := self.db.data.schema.lookup(column_name=key)) is not None:
                key = schema_entry.ldap_name
            result[key] = decode_value(self.db, key, value)
        return result

    def parent(self) -> Object | None:
        """Return the parent object of this object, if any."""
        return self.db.data.get(self.pdnt) if self.pdnt != 0 else None

    def partition(self) -> Object | None:
        """Return the naming context (partition) object of this object, if any."""
        return self.db.data.get(self.ncdnt) if self.ncdnt is not None else None

    def ancestors(self) -> Iterator[Object]:
        """Yield all ancestor objects of this object."""
        for (dnt,) in list(struct.iter_unpack("<I", self.get("Ancestors")))[::-1]:
            yield self.db.data.get(dnt)

    def child(self, name: str) -> Object | None:
        """Return a child object by name, if it exists.

        Args:
            name: The name of the child object to retrieve.
        """
        return self.db.data.child_of(self.dnt, name)

    def children(self) -> Iterator[Object]:
        """Yield all child objects of this object."""
        yield from self.db.data.children_of(self.dnt)

    def links(self) -> Iterator[tuple[str, Object]]:
        """Yield all objects linked to this object."""
        yield from self.db.link.all_links(self.dnt)

    def backlinks(self) -> Iterator[tuple[str, Object]]:
        """Yield all objects that link to this object."""
        yield from self.db.link.all_backlinks(self.dnt)

    # Some commonly used properties, for convenience and type hinting
    @property
    def dnt(self) -> int:
        """Return the object's Directory Number Tag (DNT)."""
        return self.get("DNT")

    @property
    def pdnt(self) -> int:
        """Return the object's Parent Directory Number Tag (PDNT)."""
        return self.get("Pdnt")

    @property
    def ncdnt(self) -> int | None:
        """Return the object's Naming Context Directory Number Tag (NCDNT)."""
        return self.get("Ncdnt")

    @property
    def name(self) -> str | None:
        """Return the object's name."""
        return self.get("name")

    @property
    def sid(self) -> str | None:
        """Return the object's Security Identifier (SID)."""
        return self.get("objectSid")

    @property
    def guid(self) -> str | None:
        """Return the object's GUID."""
        return self.get("objectGUID")

    @property
    def is_deleted(self) -> bool:
        """Return whether the object is marked as deleted."""
        return bool(self.get("isDeleted"))

    @property
    def instance_type(self) -> InstanceType | None:
        """Return the object's instance type."""
        return self.get("instanceType")

    @property
    def system_flags(self) -> SystemFlags | None:
        """Return the object's system flags."""
        return self.get("systemFlags")

    @property
    def is_head_of_naming_context(self) -> bool:
        """Return whether the object is a head of naming context."""
        return self.instance_type is not None and bool(self.instance_type & InstanceType.HeadOfNamingContext)

    @property
    def distinguishedName(self) -> str | None:
        """Return the fully qualified Distinguished Name (DN) for this object."""
        return self.db.data._make_dn(self.dnt)

    DN = distinguishedName

    @cached_property
    def sd(self) -> SecurityDescriptor | None:
        """Return the Security Descriptor for this object."""
        if (sd_id := self.get("nTSecurityDescriptor")) is not None:
            return self.db.sd.sd(sd_id)
        return None

    @property
    def when_created(self) -> datetime | None:
        """Return the object's creation time."""
        return self.get("whenCreated")

    @property
    def when_changed(self) -> datetime | None:
        """Return the object's last modification time."""
        return self.get("whenChanged")


def _get_attribute(db: Database, record: Record, name: str, *, raw: bool = False) -> Any:
    """Get an attribute value by name. Decodes the value based on the schema.

    Args:
        db: The database instance.
        record: The :class:`Record` instance representing the object.
        name: The attribute name to retrieve.
        raw: Whether to return the raw value without decoding.
    """
    if (entry := db.data.schema.lookup(ldap_name=name)) is not None:
        column_name = entry.column_name
    else:
        raise KeyError(f"Attribute not found: {name!r}")

    value = record.get(column_name)

    if raw:
        return value

    return decode_value(db, name, value)


class ClassSchema(Object):
    """Represents a class schema object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/6354fe66-74ee-4132-81c6-7d9a9e229070
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ccd55373-2fa6-4237-9f66-0d90fbd866f5
    """

    __object_class__ = "classSchema"

    def __repr__(self) -> str:
        return f"<ClassSchema name={self.name!r}>"

    @property
    def system_must_contain(self) -> list[str]:
        """Return a list of LDAP display names of attributes this class system must contain."""
        if (system_must_contain := self.get("systemMustContain")) is not None:
            return system_must_contain
        return []

    @property
    def system_may_contain(self) -> list[str]:
        """Return a list of LDAP display names of attributes this class system may contain."""
        if (system_may_contain := self.get("systemMayContain")) is not None:
            return system_may_contain
        return []

    @property
    def must_contain(self) -> list[str]:
        """Return a list of LDAP display names of attributes this class must contain."""
        if (must_contain := self.get("mustContain")) is not None:
            return must_contain
        return []

    @property
    def may_contain(self) -> list[str]:
        """Return a list of LDAP display names of attributes this class may contain."""
        if (may_contain := self.get("mayContain")) is not None:
            return may_contain
        return []


class AttributeSchema(Object):
    """Represents an attribute schema object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/72960960-8b48-4bf9-b7e4-c6b5ee6fd706
    """

    __object_class__ = "attributeSchema"

    def __repr__(self) -> str:
        return f"<AttributeSchema name={self.name!r}>"


class Domain(Object):
    """Represents a domain object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/cdd6335e-d3a1-48e4-bbda-d429f645e124
    """

    __object_class__ = "domain"

    def __repr__(self) -> str:
        return f"<Domain name={self.name!r}>"


class DomainDNS(Domain):
    """Represents a domain DNS object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/27d3b2b1-63b9-4e3d-b23b-e24c137ef73e
    """

    __object_class__ = "domainDNS"

    def __repr__(self) -> str:
        return f"<DomainDNS name={self.name!r}>"


class BuiltinDomain(Object):
    """Represents a built-in domain object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/662b0c28-589b-431e-9524-9ae3faf365ed
    """

    __object_class__ = "builtinDomain"

    def __repr__(self) -> str:
        return f"<BuiltinDomain name={self.name!r}>"


class Configuration(Object):
    """Represents a configuration object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/1d5bfd62-ee0e-4d43-b222-59e7787d27f0
    """

    __object_class__ = "configuration"

    def __repr__(self) -> str:
        return f"<Configuration name={self.name!r}>"


class QuotaContainer(Object):
    """Represents a quota container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/2b4fcfbf-747e-4532-a6fc-a20b6ec373b0
    """

    __object_class__ = "msDS-QuotaContainer"

    def __repr__(self) -> str:
        return f"<QuotaContainer name={self.name!r}>"


class CrossRefContainer(Object):
    """Represents a cross-reference container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/f5167b3d-5692-4c48-b675-f2cd7445bcfd
    """

    __object_class__ = "crossRefContainer"

    def __repr__(self) -> str:
        return f"<CrossRefContainer name={self.name!r}>"


class SitesContainer(Object):
    """Represents a sites container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/b955bd22-3fc0-4c91-b848-a254133f340f
    """

    __object_class__ = "sitesContainer"

    def __repr__(self) -> str:
        return f"<SitesContainer name={self.name!r}>"


class Locality(Object):
    """Represents a locality object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/2b633113-787e-4127-90e9-d38cc7830afa
    """

    __object_class__ = "locality"

    def __repr__(self) -> str:
        return f"<Locality name={self.name!r}>"


class PhysicalLocation(Object):
    """Represents a physical location object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/4fc57ea7-ea66-4337-8c4e-14a00ea6ca61
    """

    __object_class__ = "physicalLocation"

    def __repr__(self) -> str:
        return f"<PhysicalLocation name={self.name!r}>"


class Container(Object):
    """Represents a container object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/d95e1c0b-0aab-4308-ab09-63058583881c
    """

    __object_class__ = "container"

    def __repr__(self) -> str:
        return f"<Container name={self.name!r}>"


class OrganizationalUnit(Object):
    """Represents an organizational unit object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/deb49741-d386-443a-b242-2f914e8f0405
    """

    __object_class__ = "organizationalUnit"

    def __repr__(self) -> str:
        return f"<OrganizationalUnit name={self.name!r}>"


class LostAndFound(Object):
    """Represents a lost and found object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/2c557634-1cb3-40c9-8722-ef6dbb389aad
    """

    __object_class__ = "lostAndFound"

    def __repr__(self) -> str:
        return f"<LostAndFound name={self.name!r}>"


class Group(Object):
    """Represents a group object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/2d27d2b1-8820-475b-85fd-c528b6e12a5d
    """

    __object_class__ = "group"

    def __repr__(self) -> str:
        return f"<Group name={self.sAMAccountName!r}>"

    def members(self) -> Iterator[User]:
        """Yield all members of this group."""
        yield from self.db.link.links(self.dnt, "member")

        # We also need to include users with primaryGroupID matching the group's RID
        yield from self.db.data.lookup(primaryGroupID=self.sid.rsplit("-", 1)[1])

    def is_member(self, user: User) -> bool:
        """Return whether the given user is a member of this group.

        Args:
            user: The :class:`User` to check membership for.
        """
        return any(u.dnt == user.dnt for u in self.members())


class Server(Object):
    """Represents a server object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/96cab7b4-83eb-4879-b352-56ad8d19f1ac
    """

    __object_class__ = "server"

    def __repr__(self) -> str:
        return f"<Server name={self.name!r}>"


class Person(Object):
    """Represents a person object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/3e601b82-f94c-4148-a471-284e695a661e
    """

    __object_class__ = "person"

    def __repr__(self) -> str:
        return f"<Person name={self.name!r}>"


class OrganizationalPerson(Person):
    """Represents an organizational person object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/092b4460-3e6f-4ce4-b548-cf81a6876957
    """

    __object_class__ = "organizationalPerson"

    def __repr__(self) -> str:
        return f"<OrganizationalPerson name={self.name!r}>"


class User(OrganizationalPerson):
    """Represents a user object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/719c0035-2aa4-4ca6-b763-41a758bd2410
    """

    __object_class__ = "user"

    def __repr__(self) -> str:
        return (
            f"<User name={self.name!r} sAMAccountName={self.sam_account_name!r} "
            f"is_machine_account={self.is_machine_account()}>"
        )

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
        yield from self.db.link.backlinks(self.dnt, "memberOf")

        # We also need to include the group with primaryGroupID matching the user's primaryGroupID
        if self.primary_group_id is not None:
            yield from self.db.data.lookup(objectSid=f"{self.sid.rsplit('-', 1)[0]}-{self.primary_group_id}")

    def is_member_of(self, group: Group) -> bool:
        """Return whether the user is a member of the given group.

        Args:
            group: The :class:`Group` to check membership for.
        """
        return any(g.dnt == group.dnt for g in self.groups())

    def managed_objects(self) -> Iterator[Object]:
        """Yield all objects managed by this user."""
        yield from self.db.link.backlinks(self.dnt, "managedObjects")


class Computer(User):
    """Represents a computer object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/142185a8-2e23-4628-b002-cf31d57bb37a
    """

    __object_class__ = "computer"

    def __repr__(self) -> str:
        return f"<Computer name={self.name!r}>"

    def managed_by(self) -> Iterator[Object]:
        """Return the objects that manage this computer."""
        yield from self.db.link.links(self.dnt, "managedBy")
