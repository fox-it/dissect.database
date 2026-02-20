from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING, Any, ClassVar

from dissect.database.ese.ntds.util import DN, InstanceType, SystemFlags, decode_value

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
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-top
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adsc/041c6068-c710-4c74-968f-3040e4208701
    """

    __object_class__: str
    __known_classes__: ClassVar[dict[str, type[Object]]] = {}

    def __init__(self, db: Database, record: Record):
        self.db = db
        self.record = record

    def __init_subclass__(cls):
        cls.__known_classes__[cls.__object_class__] = cls

    def __repr__(self) -> str:
        suffix = self.__repr_suffix__()
        return f"<{self.__class__.__name__} {self.__repr_body__()}{' ' + suffix if suffix else ''}>"

    def __repr_body__(self) -> str:
        return f"name={self.name!r} objectCategory={self.object_category!r} objectClass={self.object_class}"

    def __repr_suffix__(self) -> str:
        suffix = []
        if self.is_deleted:
            suffix.append("(deleted)")
        if self.is_phantom:
            suffix.append("(phantom)")
        return " ".join(suffix)

    def __getattr__(self, name: str) -> Any:
        return self.get(name)

    @classmethod
    def from_record(cls, db: Database, record: Record) -> Object:
        """Create an Object instance from a database record.

        Args:
            db: The database instance associated with this object.
            record: The :class:`Record` instance representing this object.
        """
        try:
            if (object_classes := _get_attribute(db, record, "objectClass")) and (
                known_cls := cls.__known_classes__.get(object_classes[0])
            ) is not None:
                return known_cls(db, record)
        except ValueError:
            # Resolving the objectClass values can fail if the schema is not loaded yet (or is malformed)
            # Fallback to a generic Object in that case
            pass

        return cls(db, record)

    def get(self, name: str, *, raw: bool = False) -> Any:
        """Get an attribute value by name. Decodes the value based on the schema.

        Args:
            name: The attribute name to retrieve.
            raw: Whether to return the raw value without decoding.
        """
        return _get_attribute(self.db, self.record, name, raw=raw)

    def as_dict(self) -> dict[str, Any]:
        """Return the object's attributes as a dictionary."""
        result = {}
        for key in self.record.as_dict():
            if (schema := self.db.data.schema.lookup_attribute(column=key)) is not None:
                key = schema.name
                result[key] = _get_attribute(self.db, self.record, key)
        return result

    def parent(self) -> Object | None:
        """Return the parent object of this object, if any."""
        return self.db.data.get(dnt=self.pdnt) if self.pdnt != 0 else None

    def partition(self) -> Object | None:
        """Return the naming context (partition) object of this object, if any."""
        return self.db.data.get(dnt=self.ncdnt) if self.ncdnt is not None else None

    def ancestors(self) -> Iterator[Object]:
        for dnt in (self.get("Ancestors") or [])[::-1]:
            yield self.db.data.get(dnt=dnt)

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
    def object_category(self) -> str | None:
        """Return the object's objectCategory."""
        return self.get("objectCategory")

    @property
    def object_class(self) -> list[str] | None:
        """Return the object's objectClass."""
        return self.get("objectClass")

    @property
    def sid(self) -> str | None:
        """Return the object's Security Identifier (SID)."""
        return self.get("objectSid")

    @property
    def rid(self) -> int | None:
        """Return the object's Relative Identifier (RID)."""
        if (sid := self.sid) is not None:
            return int(sid.rsplit("-", 1)[-1])
        return None

    @property
    def guid(self) -> str | None:
        """Return the object's GUID."""
        return self.get("objectGUID")

    @property
    def is_deleted(self) -> bool:
        """Return whether the object is marked as deleted."""
        return bool(self.get("isDeleted"))

    @property
    def is_local(self) -> bool:
        """Return whether the object is local to this domain."""
        return self.instance_type is not None and InstanceType.Writable in self.instance_type

    @property
    def is_phantom(self) -> bool:
        """Return whether the object is a phantom (cross-domain reference)."""
        return self.instance_type is not None and InstanceType.Writable not in self.instance_type

    def _assert_local(self) -> None:
        """Raise an error if the object is a phantom."""
        if self.is_phantom:
            raise ValueError("Operation not supported for phantom (non-local) objects")

    @property
    def when_created(self) -> datetime | None:
        """Return the object's creation time."""
        return self.get("whenCreated")

    @property
    def when_changed(self) -> datetime | None:
        """Return the object's last modification time."""
        return self.get("whenChanged")

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
    def distinguished_name(self) -> DN | None:
        """Return the fully qualified Distinguished Name (DN) for this object."""
        return self.get("distinguishedName")

    dn = distinguished_name

    @cached_property
    def sd(self) -> SecurityDescriptor | None:
        """Return the Security Descriptor for this object."""
        if (sd_id := self.get("nTSecurityDescriptor")) is not None:
            return self.db.sd.sd(sd_id)
        return None

    @cached_property
    def well_known_objects(self) -> list[Object]:
        """Return the list of well-known objects."""
        if (wko := self.get("wellKnownObjects")) is not None:
            return [self.db.data.get(dnt=dnt) for dnt, _ in wko]
        return []

    @cached_property
    def other_well_known_objects(self) -> list[Object]:
        """Return the list of other well-known objects."""
        if (owko := self.get("otherWellKnownObjects")) is not None:
            return [self.db.data.get(dnt=dnt) for dnt, _ in owko]
        return []


def _get_attribute(db: Database, record: Record, name: str, *, raw: bool = False) -> Any:
    """Get an attribute value by name. Decodes the value based on the schema.

    Args:
        db: The database instance.
        record: The :class:`Record` instance representing the object.
        name: The attribute name to retrieve.
        raw: Whether to return the raw value without decoding.
    """
    if (schema := db.data.schema.lookup_attribute(name=name)) is None:
        raise AttributeError(f"Attribute not found: {name!r}")

    value = record.get(schema.column)

    if schema.is_single_valued and isinstance(value, list):
        # There are a few attributes that have the flag IsSingleValued but are marked as MultiValue in ESE
        value = value[0]

    if not schema.is_single_valued and value is None:
        # Return an empty list for multi-valued attributes that are not set
        value = []

    if raw:
        return value

    return decode_value(db, schema, value)
