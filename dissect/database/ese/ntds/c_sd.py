from __future__ import annotations

from dissect.cstruct import cstruct

# Largely copied from dissect.ntfs
sd_def = """
flag SECURITY_DESCRIPTOR_CONTROL : WORD {
    SE_OWNER_DEFAULTED                  = 0x0001,
    SE_GROUP_DEFAULTED                  = 0x0002,
    SE_DACL_PRESENT                     = 0x0004,
    SE_DACL_DEFAULTED                   = 0x0008,
    SE_SACL_PRESENT                     = 0x0010,
    SE_SACL_DEFAULTED                   = 0x0020,
    SE_DACL_AUTO_INHERIT_REQ            = 0x0100,
    SE_SACL_AUTO_INHERIT_REQ            = 0x0200,
    SE_DACL_AUTO_INHERITED              = 0x0400,
    SE_SACL_AUTO_INHERITED              = 0x0800,
    SE_DACL_PROTECTED                   = 0x1000,
    SE_SACL_PROTECTED                   = 0x2000,
    SE_RM_CONTROL_VALID                 = 0x4000,
    SE_SELF_RELATIVE                    = 0x8000,
};

flag ACCESS_MASK : DWORD {
    ADS_RIGHT_DS_CREATE_CHILD           = 0x00000001,
    ADS_RIGHT_DS_DELETE_CHILD           = 0x00000002,
    ADS_RIGHT_DS_LIST_CONTENTS          = 0x00000004,       // Undocumented?
    ADS_RIGHT_DS_SELF                   = 0x00000008,
    ADS_RIGHT_DS_READ_PROP              = 0x00000010,
    ADS_RIGHT_DS_WRITE_PROP             = 0x00000020,
    ADS_RIGHT_DS_CONTROL_ACCESS         = 0x00000100,

    DELETE                              = 0x00010000,
    READ_CONTROL                        = 0x00020000,
    WRITE_DACL                          = 0x00040000,
    WRITE_OWNER                         = 0x00080000,
    SYNCHRONIZE                         = 0x00100000,
    ACCESS_SYSTEM_SECURITY              = 0x01000000,
    MAXIMUM_ALLOWED                     = 0x02000000,
    GENERIC_ALL                         = 0x10000000,
    GENERIC_EXECUTE                     = 0x20000000,
    GENERIC_WRITE                       = 0x40000000,
    GENERIC_READ                        = 0x80000000,
};

enum ACE_TYPE : BYTE {
    ACCESS_ALLOWED                      = 0x00,
    ACCESS_DENIED                       = 0x01,
    SYSTEM_AUDIT                        = 0x02,
    SYSTEM_ALARM                        = 0x03,
    ACCESS_ALLOWED_COMPOUND             = 0x04,
    ACCESS_ALLOWED_OBJECT               = 0x05,
    ACCESS_DENIED_OBJECT                = 0x06,
    SYSTEM_AUDIT_OBJECT                 = 0x07,
    SYSTEM_ALARM_OBJECT                 = 0x08,
    ACCESS_ALLOWED_CALLBACK             = 0x09,
    ACCESS_DENIED_CALLBACK              = 0x0A,
    ACCESS_ALLOWED_CALLBACK_OBJECT      = 0x0B,
    ACCESS_DENIED_CALLBACK_OBJECT       = 0x0C,
    SYSTEM_AUDIT_CALLBACK               = 0x0D,
    SYSTEM_ALARM_CALLBACK               = 0x0E,
    SYSTEM_AUDIT_CALLBACK_OBJECT        = 0x0F,
    SYSTEM_ALARM_CALLBACK_OBJECT        = 0x10,
    SYSTEM_MANDATORY_LABEL              = 0x11,
    SYSTEM_RESOURCE_ATTRIBUTE           = 0x12,
    SYSTEM_SCOPED_POLICY_ID             = 0x13,
    SYSTEM_PROCESS_TRUST_LABEL          = 0x14,
    SYSTEM_ACCESS_FILTER                = 0x15,
};

flag ACE_FLAGS : BYTE {
    OBJECT_INHERIT_ACE                  = 0x01,
    CONTAINER_INHERIT_ACE               = 0x02,
    NO_PROPAGATE_INHERIT_ACE            = 0x04,
    INHERIT_ONLY_ACE                    = 0x08,
    INHERITED_ACE                       = 0x10,
    SUCCESSFUL_ACCESS_ACE_FLAG          = 0x40,
    FAILED_ACCESS_ACE_FLAG              = 0x80,
};

flag ACE_OBJECT_FLAGS : DWORD {
    ACE_OBJECT_TYPE_PRESENT             = 0x01,
    ACE_INHERITED_OBJECT_TYPE_PRESENT   = 0x02,
};

enum COMPOUND_ACE_TYPE : USHORT {
    COMPOUND_ACE_IMPERSONATION          = 0x01,
};

typedef struct _ACL {
    BYTE        AclRevision;
    BYTE        Sbz1;
    WORD        AclSize;
    WORD        AceCount;
    WORD        Sbz2;
} ACL;

typedef struct _ACE_HEADER {
    ACE_TYPE    AceType;
    ACE_FLAGS   AceFlags;
    WORD        AceSize;
} ACE_HEADER;

typedef struct _SECURITY_DESCRIPTOR_HEADER {
    ULONG       HashId;
    ULONG       SecurityId;
    ULONG64     Offset;
    ULONG       Length;
} SECURITY_DESCRIPTOR_HEADER;

typedef struct _SECURITY_DESCRIPTOR_RELATIVE {
    BYTE        Revision;
    BYTE        Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    ULONG       Owner;
    ULONG       Group;
    ULONG       Sacl;
    ULONG       Dacl;
} SECURITY_DESCRIPTOR_RELATIVE;
"""
c_sd = cstruct(sd_def)
