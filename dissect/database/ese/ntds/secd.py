from __future__ import annotations

import logging
from enum import IntFlag
from io import BytesIO

from dissect import cstruct

from dissect.database.ese.ntds.utils import format_GUID

log = logging.getLogger(__name__)


secd_def = """
struct SECURITY_DESCRIPTOR {
    uint8   Revision;
    uint8   Sbz1;
    uint16  Control;
    uint32  OffsetOwner;
    uint32  OffsetGroup;
    uint32  OffsetSacl;
    uint32  OffsetDacl;
};

// Similar to read_sid from dissect.util.sid
// However, we need to account for these bytes in the other structures,
// so we define it anyway.
struct LDAP_SID {
    BYTE        Revision;
    BYTE        SubAuthorityCount;
    CHAR        IdentifierAuthority[6];
    DWORD       SubAuthority[SubAuthorityCount];
};

struct ACL {
    uint8   AclRevision;
    uint8   Sbz1;
    uint16  AclSize;
    uint16  AceCount;
    uint16  Sbz2;
    char    Data[AclSize - 8];
};

struct ACE {
    uint8   AceType;
    uint8   AceFlags;
    uint16  AceSize;
    char    Data[AceSize - 4];
};

struct ACCESS_ALLOWED_ACE {
    uint32  Mask;
    LDAP_SID Sid;
};

struct ACCESS_ALLOWED_OBJECT_ACE {
    uint32  Mask;
    uint32  Flags;
    char    ObjectType[(Flags & 1) * 16];
    char    InheritedObjectType[(Flags & 2) * 8];
    LDAP_SID Sid;
};
"""

c_secd = cstruct.cstruct()
c_secd.load(secd_def)


class SecurityDescriptor:
    """Represents a Windows Security Descriptor.

    Parses and provides access to the components of a security descriptor
    including owner SID, group SID, SACL, and DACL.
    """

    # Control indexes in bit field
    SR = 0  # Self-Relative
    RM = 1  # RM Control Valid
    PS = 2  # SACL Protected
    PD = 3  # DACL Protected
    SI = 4  # SACL Auto-Inherited
    DI = 5  # DACL Auto-Inherited
    SC = 6  # SACL Computed Inheritance Required
    DC = 7  # DACL Computed Inheritance Required
    SS = 8  # Server Security
    DT = 9  # DACL Trusted
    SD = 10  # SACL Defaulted
    SP = 11  # SACL Present
    DD = 12  # DACL Defaulted
    DP = 13  # DACL Present
    GD = 14  # Group Defaulted
    OD = 15  # Owner Defaulted

    def has_control(self, control: int) -> bool:
        """Check if the n-th bit is set in the control field.

        Args:
            control: The control bit index to check.

        Returns:
            True if the control bit is set, False otherwise.
        """
        return (self.control >> control) & 1 == 1

    def __init__(self, fh: BytesIO) -> None:
        """Initialize a SecurityDescriptor from binary data.

        Args:
            fh: Binary file handle containing the security descriptor data.
        """
        self.fh = fh
        self.descriptor = c_secd.SECURITY_DESCRIPTOR(fh)

        self.control = self.descriptor.Control
        self.owner_sid: LdapSid | None = None
        self.group_sid: LdapSid | None = None
        self.sacl: ACL | None = None
        self.dacl: ACL | None = None

        if self.descriptor.OffsetOwner != 0:
            fh.seek(self.descriptor.OffsetOwner)
            self.owner_sid = LdapSid(fh=fh)

        if self.descriptor.OffsetGroup != 0:
            fh.seek(self.descriptor.OffsetGroup)
            self.group_sid = LdapSid(fh=fh)

        if self.descriptor.OffsetSacl != 0:
            fh.seek(self.descriptor.OffsetSacl)
            self.sacl = ACL(fh)

        if self.descriptor.OffsetDacl != 0:
            fh.seek(self.descriptor.OffsetDacl)
            self.dacl = ACL(fh)


class LdapSid:
    """Represents an LDAP Security Identifier (SID)."""

    def __init__(self, fh: BytesIO | None = None, in_obj: object | None = None) -> None:
        """Initialize an LdapSid from binary data or existing object.

        Args:
            fh: Binary file handle to parse SID from (optional).
            in_obj: Existing SID object to wrap (optional).
        """
        if fh:
            self.fh = fh
            self.ldap_sid = c_secd.LDAP_SID(fh)
        else:
            self.ldap_sid = in_obj

    def __repr__(self) -> str:
        return "S-{}-{}-{}".format(
            self.ldap_sid.Revision,
            bytearray(self.ldap_sid.IdentifierAuthority)[5],
            "-".join([f"{v:d}" for v in self.ldap_sid.SubAuthority]),
        )


class AceFlag(IntFlag):
    """https://learn.microsoft.com/en-us/windows/win32/wmisdk/namespace-ace-flag-constants"""

    CONTAINER_INHERIT_ACE = 0x02
    FAILED_ACCESS_ACE_FLAG = 0x80
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10
    NO_PROPAGATE_INHERIT_ACE = 0x04
    OBJECT_INHERIT_ACE = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x04


class AceType(IntFlag):
    """https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.acetype?view=net-9.0"""

    ACCESS_ALLOWED_ACE_TYPE = 0x00
    ACCESS_DENIED_ACE_TYPE = 0x01
    SYSTEM_AUDIT_ACE_TYPE = 0x02
    SYSTEM_ALARM_ACE_TYPE = 0x03
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10


class AccessMaskFlag(IntFlag):
    """https://msdn.microsoft.com/en-us/library/cc230294.aspx"""

    SET_GENERIC_READ = 0x80000000
    SET_GENERIC_WRITE = 0x04000000
    SET_GENERIC_EXECUTE = 0x20000000
    SET_GENERIC_ALL = 0x10000000

    GENERIC_READ = 0x00020094
    GENERIC_WRITE = 0x00020028
    GENERIC_EXECUTE = 0x00020004
    GENERIC_ALL = 0x000F01FF

    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    SYNCHRONIZE = 0x00100000
    WRITE_OWNER = 0x00080000
    WRITE_DACL = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000

    ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
    ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
    ADS_RIGHT_DS_DELETE_CHILD = 0x00000002
    ADS_RIGHT_DS_READ_PROP = 0x00000010
    ADS_RIGHT_DS_WRITE_PROP = 0x00000020
    ADS_RIGHT_DS_SELF = 0x00000008


class ObjectAceFlag(IntFlag):
    ACE_OBJECT_TYPE_PRESENT = 0x01
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02


class ACL:
    """Represents an Access Control List containing Access Control Entries."""

    def __init__(self, fh: BytesIO) -> None:
        """Initialize an ACL from binary data.

        Args:
            fh: Binary file handle containing the ACL data.
        """
        self.fh = fh
        self.acl = c_secd.ACL(fh)
        self.aces: list[ACE] = []

        buf = BytesIO(self.acl.Data)
        for _ in range(self.acl.AceCount):
            self.aces.append(ACE.parse(buf))


class ACE:
    """Base ACE class that handles common ACE functionality."""

    def __init__(self, fh: BytesIO) -> None:
        """Initialize an ACE from binary data.

        Args:
            fh: Binary file handle containing the ACE data.
        """
        self.fh = fh
        self.ace = c_secd.ACE(fh)

    @classmethod
    def parse(cls, fh: BytesIO) -> ACE:
        """Factory method to create the appropriate ACE subclass based on ACE type.

        Args:
            fh: Binary file handle containing the ACE data.

        Returns:
            The appropriate ACE subclass instance.
        """
        # Save current position to reset after reading the type
        pos = fh.tell()
        ace_header = c_secd.ACE(fh)
        fh.seek(pos)  # Reset to start for the actual parsing

        ace_type = AceType(ace_header.AceType)

        match ace_type:
            case AceType.ACCESS_ALLOWED_ACE_TYPE:
                return ACCESS_ALLOWED_ACE(fh)
            case AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                return ACCESS_ALLOWED_OBJECT_ACE(fh)
            case AceType.ACCESS_DENIED_ACE_TYPE:
                return ACCESS_DENIED_ACE(fh)
            case AceType.ACCESS_DENIED_OBJECT_ACE_TYPE:
                return ACCESS_DENIED_OBJECT_ACE(fh)
            case _:
                log.debug("AceType %s not yet supported", ace_type.name)
                return UnsupportedACE(fh)

    def has_flag(self, flag: AceFlag | int) -> bool:
        """Check if the ACE has a specific flag.

        Args:
            flag: The AceFlag or integer flag value to check.

        Returns:
            True if the flag is set, False otherwise.
        """
        if isinstance(flag, AceFlag):
            return self.ace.AceFlags & flag.value == flag.value
        return self.ace.AceFlags & flag == flag

    def __repr__(self) -> str:
        active_flags = [flag.name for flag in AceFlag if self.has_flag(flag)]
        return (
            f"<{self.__class__.__name__} Type={self.ace.AceType} "
            f"Flags={' | '.join(active_flags)} RawFlags={self.ace.AceFlags}>"
        )


class ACCESS_ALLOWED_ACE(ACE):
    """Represents an ACCESS_ALLOWED_ACE entry."""

    def __init__(self, fh: BytesIO) -> None:
        """Initialize an ACCESS_ALLOWED_ACE from binary data.

        Args:
            fh: Binary file handle containing the ACE data.
        """
        super().__init__(fh)
        self.data = c_secd.ACCESS_ALLOWED_ACE(BytesIO(self.ace.Data))
        self.sid = LdapSid(in_obj=self.data.Sid)
        self.mask = ACCESS_MASK(self.data.Mask)

    def __repr__(self) -> str:
        active_flags = [flag.name for flag in AceFlag if self.has_flag(flag)]
        return (
            f"<ACCESS_ALLOWED_ACE Type={self.ace.AceType} Flags={' | '.join(active_flags)} "
            f"RawFlags={self.ace.AceFlags} Sid={self.sid} Mask={self.mask}>"
        )


class ACCESS_DENIED_ACE(ACCESS_ALLOWED_ACE):
    def __repr__(self) -> str:
        active_flags = [flag.name for flag in AceFlag if self.has_flag(flag)]
        return (
            f"<ACCESS_DENIED_ACE Type={self.ace.AceType} Flags={' | '.join(active_flags)} "
            f"RawFlags={self.ace.AceFlags} Sid={self.sid} Mask={self.mask}>"
        )


class UnsupportedACE(ACE):
    """ACE class for unsupported ACE types."""

    def __init__(self, fh: BytesIO) -> None:
        """Initialize an UnsupportedACE from binary data.

        Args:
            fh: Binary file handle containing the ACE data.
        """
        super().__init__(fh)
        self.data = None
        self.sid = None
        self.mask = None

    def __repr__(self) -> str:
        active_flags = [flag.name for flag in AceFlag if self.has_flag(flag)]
        return f"<UnsupportedACE Type={self.ace.AceType} Flags={' | '.join(active_flags)} RawFlags={self.ace.AceFlags}>"


class ACCESS_ALLOWED_OBJECT_ACE(ACE):
    """Represents an ACCESS_ALLOWED_OBJECT_ACE entry."""

    # Flag constants (kept for backward compatibility)
    ACE_OBJECT_TYPE_PRESENT = ObjectAceFlag.ACE_OBJECT_TYPE_PRESENT
    ACE_INHERITED_OBJECT_TYPE_PRESENT = ObjectAceFlag.ACE_INHERITED_OBJECT_TYPE_PRESENT

    def __init__(self, fh: BytesIO) -> None:
        """Initialize an ACCESS_ALLOWED_OBJECT_ACE from binary data.

        Args:
            fh: Binary file handle containing the ACE data.
        """
        super().__init__(fh)
        self.data = c_secd.ACCESS_ALLOWED_OBJECT_ACE(BytesIO(self.ace.Data))
        self.sid = LdapSid(in_obj=self.data.Sid)
        self.mask = ACCESS_MASK(self.data.Mask)

    def has_flag(self, flag: ObjectAceFlag | int) -> bool:
        """Check if the ACE has a specific object flag.

        Args:
            flag: The ObjectAceFlag or integer flag value to check.

        Returns:
            True if the flag is set, False otherwise.
        """
        if isinstance(flag, ObjectAceFlag):
            return self.data.Flags & flag.value == flag.value
        return self.data.Flags & flag == flag

    def get_object_type(self) -> str | None:
        """Get the object type GUID if present.

        Returns:
            The object type GUID as a string, or None if not present.
        """
        if self.has_flag(ObjectAceFlag.ACE_OBJECT_TYPE_PRESENT):
            return format_GUID(self.data.ObjectType)
        return None

    def get_inherited_object_type(self) -> str | None:
        """Get the inherited object type GUID if present.

        Returns:
            The inherited object type GUID as a string, or None if not present.
        """
        if self.has_flag(ObjectAceFlag.ACE_INHERITED_OBJECT_TYPE_PRESENT):
            return format_GUID(self.data.InheritedObjectType)
        return None

    def __repr__(self) -> str:
        ace_flags = [flag.name for flag in AceFlag if self.has_flag(flag)]
        object_flags = [flag.name for flag in ObjectAceFlag if self.has_flag(flag)]
        data = (
            " | ".join(object_flags),
            str(self.sid),
            str(self.mask),
            self.get_object_type() or "",
            self.get_inherited_object_type() or "",
        )
        return (
            f"<ACCESS_ALLOWED_OBJECT_ACE Type={self.ace.AceType} AceFlags={' | '.join(ace_flags)} "
            f"ObjectFlags={data[0]} Sid={data[1]} \n\t\t"
            f"Mask={data[2]} \n\t\tObjectType={data[3]} InheritedObjectType={data[4]}>"
        )


class ACCESS_DENIED_OBJECT_ACE(ACCESS_ALLOWED_OBJECT_ACE):
    def __repr__(self) -> str:
        ace_flags = [flag.name for flag in AceFlag if self.has_flag(flag)]
        object_flags = [flag.name for flag in ObjectAceFlag if self.has_flag(flag)]
        data = (
            " | ".join(object_flags),
            str(self.sid),
            str(self.mask),
            self.get_object_type() or "",
            self.get_inherited_object_type() or "",
        )
        return (
            f"<ACCESS_DENIED_OBJECT_ACE Type={self.ace.AceType} AceFlags={' | '.join(ace_flags)} "
            f"ObjectFlags={data[0]} Sid={data[1]} Mask={data[2]} ObjectType={data[3]} InheritedObjectType={data[4]}>"
        )


class ACCESS_MASK:
    """Access mask wrapper that uses AccessMaskFlag enum for better type safety."""

    def __init__(self, mask: int) -> None:
        """Initialize an ACCESS_MASK with the given mask value.

        Args:
            mask: The integer mask value.
        """
        self.mask = mask

    def has_priv(self, priv: AccessMaskFlag | int) -> bool:
        """Check if the mask has a specific privilege.

        Args:
            priv: The AccessMaskFlag or integer privilege to check.

        Returns:
            True if the privilege is set, False otherwise.
        """
        if isinstance(priv, AccessMaskFlag):
            return self.mask & priv.value == priv.value
        return self.mask & priv == priv

    def __repr__(self) -> str:
        active_flags = [flag.name for flag in AccessMaskFlag if self.has_priv(flag)]
        return f"<ACCESS_MASK RawMask={self.mask} Flags={' | '.join(active_flags)}>"
