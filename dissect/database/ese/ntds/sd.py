from __future__ import annotations

import io
from typing import BinaryIO
from uuid import UUID

from dissect.util.sid import read_sid

from dissect.database.ese.ntds.c_sd import c_sd

ACE_TYPE = c_sd.ACE_TYPE
ACE_FLAGS = c_sd.ACE_FLAGS
ACE_OBJECT_FLAGS = c_sd.ACE_OBJECT_FLAGS
ACCESS_MASK = c_sd.ACCESS_MASK
COMPOUND_ACE_TYPE = c_sd.COMPOUND_ACE_TYPE


class SecurityDescriptor:
    """Parse a security descriptor from a file-like object.

    Args:
        fh: The file-like object to parse a security descriptor from.
    """

    def __init__(self, fh: BinaryIO):
        offset = fh.tell()
        self.header = c_sd._SECURITY_DESCRIPTOR_RELATIVE(fh)

        self.owner = None
        self.group = None
        self.sacl = None
        self.dacl = None

        if self.header.Owner:
            fh.seek(offset + self.header.Owner)
            self.owner = read_sid(fh)

        if self.header.Group:
            fh.seek(offset + self.header.Group)
            self.group = read_sid(fh)

        if self.header.Sacl:
            fh.seek(offset + self.header.Sacl)
            self.sacl = ACL(fh)

        if self.header.Dacl:
            fh.seek(offset + self.header.Dacl)
            self.dacl = ACL(fh)

    def __repr__(self) -> str:
        return f"<SecurityDescriptor owner={self.owner!r} group={self.group!r} sacl={self.sacl} dacl={self.dacl}>"


class ACL:
    """Parse an ACL from a file-like object.

    Args:
        fh: The file-like object to parse an ACL from.
    """

    def __init__(self, fh: BinaryIO):
        self.header = c_sd._ACL(fh)
        self.ace = [ACE(fh) for _ in range(self.header.AceCount)]

    def __repr__(self) -> str:
        return f"<ACL revision={self.revision} count={self.header.AceCount}>"

    @property
    def revision(self) -> int:
        """Return the ACL revision."""
        return self.header.AclRevision

    @property
    def size(self) -> int:
        """Return the ACL size."""
        return self.header.AclSize


class ACE:
    """Parse an ACE from a file-like object.

    Args:
        fh: The file-like object to parse an ACE from.
    """

    def __init__(self, fh: BinaryIO):
        self.header = c_sd._ACE_HEADER(fh)
        self.data = fh.read(self.header.AceSize - len(c_sd._ACE_HEADER))

        self.mask: ACCESS_MASK | None = None
        self.sid: str | None = None

        self.object_flags: ACE_OBJECT_FLAGS | None = None
        self.object_type: UUID | None = None
        self.inherited_object_type: UUID | None = None

        self.compound_type: COMPOUND_ACE_TYPE | None = None
        self.server_sid: str | None = None

        buf = io.BytesIO(self.data)
        if self.is_standard_ace:
            self.mask = ACCESS_MASK(buf)
            self.sid = read_sid(buf)

        elif self.is_compound_ace:
            self.mask = ACCESS_MASK(buf)
            self.compound_type = COMPOUND_ACE_TYPE(buf)
            c_sd.USHORT(buf)  # Reserved
            self.server_sid = read_sid(buf)
            self.sid = read_sid(buf)

        elif self.is_object_ace:
            self.mask = ACCESS_MASK(buf)
            self.object_flags = ACE_OBJECT_FLAGS(buf)

            if self.object_flags & ACE_OBJECT_FLAGS.ACE_OBJECT_TYPE_PRESENT:
                self.object_type = UUID(bytes_le=buf.read(16))
            if self.object_flags & ACE_OBJECT_FLAGS.ACE_INHERITED_OBJECT_TYPE_PRESENT:
                self.inherited_object_type = UUID(bytes_le=buf.read(16))

            self.sid = read_sid(buf)

        self.application_data = buf.read() or None

    def __repr__(self) -> str:
        if self.is_standard_ace:
            return f"<{self.type.name} mask={self.mask} sid={self.sid}>"
        if self.is_compound_ace:
            return (
                f"<{self.type.name} mask={self.mask} type={self.compound_type.name}"
                f" server_sid={self.server_sid} client_sid={self.sid}>"
            )
        if self.is_object_ace:
            return (
                f"<{self.type.name} mask={self.mask} object_type={self.object_type}"
                f" inherited_object_type={self.inherited_object_type} sid={self.sid}>"
            )
        return f"<ACE type={self.type} flags={self.flags} size={self.size}>"

    @property
    def type(self) -> ACE_TYPE:
        """Return the ACE type."""
        return self.header.AceType

    @property
    def flags(self) -> ACE_FLAGS:
        """Return the ACE flags."""
        return self.header.AceFlags

    @property
    def size(self) -> int:
        """Return the ACE size."""
        return self.header.AceSize

    @property
    def is_standard_ace(self) -> bool:
        """Return whether this ACE is a standard ACE."""
        return self.header.AceType in (
            ACE_TYPE.ACCESS_ALLOWED,
            ACE_TYPE.ACCESS_DENIED,
            ACE_TYPE.SYSTEM_AUDIT,
            ACE_TYPE.SYSTEM_ALARM,
            ACE_TYPE.ACCESS_ALLOWED_CALLBACK,
            ACE_TYPE.ACCESS_DENIED_CALLBACK,
            ACE_TYPE.SYSTEM_AUDIT_CALLBACK,
            ACE_TYPE.SYSTEM_ALARM_CALLBACK,
            ACE_TYPE.SYSTEM_MANDATORY_LABEL,
            ACE_TYPE.SYSTEM_RESOURCE_ATTRIBUTE,
            ACE_TYPE.SYSTEM_SCOPED_POLICY_ID,
            ACE_TYPE.SYSTEM_PROCESS_TRUST_LABEL,
            ACE_TYPE.SYSTEM_ACCESS_FILTER,
        )

    @property
    def is_compound_ace(self) -> bool:
        """Return whether this ACE is a compound ACE."""
        return self.header.AceType in (ACE_TYPE.ACCESS_ALLOWED_COMPOUND,)

    @property
    def is_object_ace(self) -> bool:
        """Return whether this ACE is an object ACE."""
        return self.header.AceType in (
            ACE_TYPE.ACCESS_ALLOWED_OBJECT,
            ACE_TYPE.ACCESS_DENIED_OBJECT,
            ACE_TYPE.SYSTEM_AUDIT_OBJECT,
            ACE_TYPE.SYSTEM_ALARM_OBJECT,
            ACE_TYPE.ACCESS_ALLOWED_CALLBACK_OBJECT,
            ACE_TYPE.ACCESS_DENIED_CALLBACK_OBJECT,
            ACE_TYPE.SYSTEM_AUDIT_CALLBACK_OBJECT,
            ACE_TYPE.SYSTEM_ALARM_CALLBACK_OBJECT,
        )
