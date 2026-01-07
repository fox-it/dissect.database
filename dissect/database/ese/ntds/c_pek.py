from __future__ import annotations

from dissect.cstruct import cstruct

pek_def = """
typedef QWORD FILETIME;

#define PEK_PRE_2012R2_VERSION          2
#define PEK_2016_TP4_VERSION            3

#define PEK_ENCRYPTION                  0x10
#define PEK_ENCRYPTION_WITH_SALT        0x11
#define PEK_ENCRYPTION_WITH_AES         0x13

typedef struct _ENCRYPTED_PEK_LIST {
    ULONG       Version;
    ULONG       BootOption;
    CHAR        Salt[16];
    CHAR        EncryptedData[EOF];
} ENCRYPTED_PEK_LIST;

typedef struct _PEK {
    ULONG       KeyId;
    CHAR        Key[16];
} PEK;

typedef struct _CLEAR_PEK_LIST {
    CHAR        Authenticator[16];
    FILETIME    LastKeyGenerationTime;
    ULONG       CurrentKey;
    ULONG       CountOfKeys;
    PEK         PekArray[CountOfKeys];
} CLEAR_PEK_LIST;

typedef struct _ENCRYPTED_DATA {
    USHORT      AlgorithmId;
    USHORT      Flags;
    ULONG       KeyId;
    CHAR        EncryptedData[EOF];
} ENCRYPTED_DATA;

typedef struct _ENCRYPTED_DATA_WITH_SALT {
    USHORT      AlgorithmId;
    USHORT      Flags;
    ULONG       KeyId;
    CHAR        Salt[16];
    CHAR        EncryptedData[EOF];
} ENCRYPTED_DATA_WITH_SALT;

typedef struct _ENCRYPTED_DATA_WITH_AES {
    USHORT      AlgorithmId;
    USHORT      Flags;
    ULONG       KeyId;
    CHAR        IV[16];
    ULONG       Length;
    CHAR        EncryptedData[EOF];
} ENCRYPTED_DATA_WITH_AES;
"""
c_pek = cstruct(pek_def)
