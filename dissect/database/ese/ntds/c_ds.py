from __future__ import annotations

from dissect.cstruct import cstruct

ds_def = """
typedef struct _USER_PROPERTY {
    WORD            NameLength;
    WORD            ValueLength;
    WORD            PropertyFlag;
    WCHAR           PropertyName[NameLength / 2];
    CHAR            PropertyValue[ValueLength];
} USER_PROPERTY;

typedef struct _USER_PROPERTIES_HEADER {
    DWORD           Reserved1;
    DWORD           Length;
    WORD            Reserved2;
    WORD            Reserved3;
    CHAR            Reserved4[96];
    WORD            PropertySignature;
    WORD            PropertyCount;
} USER_PROPERTIES_HEADER;

typedef struct _ADAM_PROPERTIES_HEADER {    // For lack of a better name
    DWORD           Reserved1;
    DWORD           Reserved2;
    DWORD           Reserved3;
    DWORD           Reserved4;
    DWORD           Reserved5;
    DWORD           Reserved6;
} ADAM_PROPERTIES_HEADER;

typedef struct _KERB_KEY_DATA {
    WORD            Reserved1;
    WORD            Reserved2;
    DWORD           Reserved3;
    DWORD           KeyType;
    DWORD           KeyLength;
    DWORD           KeyOffset;
} KERB_KEY_DATA;

typedef struct _KERB_STORED_CREDENTIAL {
    WORD            Revision;
    WORD            Flags;
    WORD            CredentialCount;
    WORD            OldCredentialCount;
    WORD            DefaultSaltLength;
    WORD            DefaultSaltMaximumLength;
    DWORD           DefaultSaltOffset;
    KERB_KEY_DATA   Credentials[CredentialCount];
    KERB_KEY_DATA   OldCredentials[OldCredentialCount];
    // CHAR         DefaultSalt[DefaultSaltLength];
    // CHAR         KeyValues[...];
} KERB_STORED_CREDENTIAL;

typedef struct _KERB_KEY_DATA_NEW {
    WORD            Reserved1;
    WORD            Reserved2;
    DWORD           Reserved3;
    DWORD           IterationCount;
    DWORD           KeyType;
    DWORD           KeyLength;
    DWORD           KeyOffset;
} KERB_KEY_DATA_NEW;

typedef struct _KERB_STORED_CREDENTIAL_NEW {
    WORD            Revision;
    WORD            Flags;
    WORD            CredentialCount;
    WORD            ServiceCredentialCount;
    WORD            OldCredentialCount;
    WORD            OlderCredentialCount;
    WORD            DefaultSaltLength;
    WORD            DefaultSaltMaximumLength;
    DWORD           DefaultSaltOffset;
    DWORD           DefaultIterationCount;
    KERB_KEY_DATA_NEW   Credentials[CredentialCount];
    KERB_KEY_DATA_NEW   ServiceCredentials[ServiceCredentialCount];
    KERB_KEY_DATA_NEW   OldCredentials[OldCredentialCount];
    KERB_KEY_DATA_NEW   OlderCredentials[OlderCredentialCount];
    // CHAR         DefaultSalt[DefaultSaltLength];
    // CHAR         KeyValues[...];
} KERB_STORED_CREDENTIAL_NEW;

typedef struct _WDIGEST_CREDENTIALS {
    BYTE    Reserved1;
    BYTE    Reserved2;
    BYTE    Version;
    BYTE    NumberOfHashes;
    CHAR    Reserved3[12];
    CHAR    Hash[29][16];                   // The formal definition has Hash1, Hash2, ..., Hash29
} WDIGEST_CREDENTIALS;
"""
c_ds = cstruct(ds_def)
