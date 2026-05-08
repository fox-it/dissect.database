from __future__ import annotations

from dissect.cstruct import cstruct

dns_record_def = """

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/39b03b89-2264-4063-8198-d62f62a6441a
enum DNS_RECORD_TYPE : WORD {
    ZERO        = 0x0000,   // An empty record type ([RFC1034] section 3.6 and [RFC1035] section 3.2.2).
    A           = 0x0001,   // An A record type, used for storing an IP address ([RFC1035] section 3.2.2).
    NS          = 0x0002,   // An authoritative name-server
                            // record type ([RFC1034] section 3.6 and [RFC1035] section 3.2.2).
    MD          = 0x0003,   // A mail-destination record type ([RFC1035] section 3.2.2).
    MF          = 0x0004,   // A mail forwarder record type ([RFC1035] section 3.2.2).
    CNAME       = 0x0005,   // A record type that contains the canonical name of a DNS alias ([RFC1035] section 3.2.2).
    SOA         = 0x0006,   // A Start of Authority (SOA) record type ([RFC1035] section 3.2.2).
    MB          = 0x0007,   // A mailbox record type ([RFC1035] section 3.2.2).
    MG          = 0x0008,   // A mail group member record type ([RFC1035] section 3.2.2).
    MR          = 0x0009,   // A mail-rename record type ([RFC1035] section 3.2.2).
    NULL        = 0x000A,   // A record type for completion queries ([RFC1035] section 3.2.2).
    WKS         = 0x000B,   // A record type for a well-known service ([RFC1035] section 3.2.2).
    PTR         = 0x000C,   // A record type containing FQDN pointer ([RFC1035] section 3.2.2).
    HINFO       = 0x000D,   // A host information record type ([RFC1035] section 3.2.2).
    MINFO       = 0x000E,   // A mailbox or mailing list information record type ([RFC1035] section 3.2.2).
    MX          = 0x000F,   // A mail-exchanger record type ([RFC1035] section 3.2.2).
    TXT         = 0x0010,   // A record type containing a text string ([RFC1035] section 3.2.2).
    RP          = 0x0011,   // A responsible-person record type [RFC1183].
    AFSDB       = 0x0012,   // A record type containing AFS database location [RFC1183].
    X25         = 0x0013,   // An X25 PSDN address record type [RFC1183].
    ISDN        = 0x0014,   // An ISDN address record type [RFC1183].
    RT          = 0x0015,   // A route through record type [RFC1183].
    SIG         = 0x0018,   // A cryptographic public key signature record type [RFC2931].
    KEY         = 0x0019,   // A record type containing public key used in DNSSEC [RFC2535].
    AAAA        = 0x001C,   // An IPv6 address record type [RFC3596].
    LOC         = 0x001D,   // A location information record type [RFC1876].
    NXT         = 0x001E,   // A next-domain record type [RFC2065].
    SRV         = 0x0021,   // A server selection record type [RFC2782].
    ATMA        = 0x0022,   // An Asynchronous Transfer Mode (ATM) address record type [ATMA].
    NAPTR       = 0x0023,   // An NAPTR record type [RFC2915].
    DNAME       = 0x0027,   // A DNAME record type [RFC2672].
    DS          = 0x002B,   // A DS record type [RFC4034].
    RRSIG       = 0x002E,   // An RRSIG record type [RFC4034].
    NSEC        = 0x002F,   // An NSEC record type [RFC4034].
    DNSKEY      = 0x0030,   // A DNSKEY record type [RFC4034].
    DHCID       = 0x0031,   // A DHCID record type [RFC4701].
    NSEC3       = 0x0032,   // An NSEC3 record type [RFC5155].
    NSEC3PARAM  = 0x0033,   // An NSEC3PARAM record type [RFC5155].
    TLSA        = 0x0034,   // A TLSA record type [RFC6698].
    ALL         = 0x00FF,   // A query-only type requesting all records [RFC1035].
    WINS        = 0xFF01,   // A record type containing Windows Internet Name Service (WINS)
                            // forward lookup data [MS-WINSRADNS_TYPE_WINSR].
    WINSR       = 0xFF02    // A record type containing WINS reverse lookup data [MS-WINSRA].
};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8
typedef struct DNS_RECORD_HEADER {
    WORD                DataLength;
    DNS_RECORD_TYPE     Type;
    BYTE                Version;            // Must be 0x05
    BYTE                Rank;
    WORD                Flags;              // Must be 0x00
    DWORD               Serial;
    DWORD               TtlSeconds;         // Big Endian
    DWORD               Reserved;           // MUST be 0x00000000.
    DWORD               TimeStamp;
    CHAR                Data[DataLength];
};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/3fd41adc-c69e-407b-979e-721251403132
// MS docs indicate that structure is 4 byte aligned, and that the string MUST NOT be null-terminated.
// But observed reality is a null terminated string (null char not counted in NameLength)
typedef struct DNS_RPC_NAME{
    BYTE                NameLength;
    CHAR                dnsName[NameLength];
};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/db37cab7-f121-43ba-81c5-ca0e198d4b9a
typedef struct DNS_RPC_RECORD_SRV {
    WORD                Priority;
    WORD                Weight;
    WORD                Port;
    DNS_RPC_NAME        nameTarget;
};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f647d391-6614-4c3e-b38b-4df971590eb6
typedef struct DNS_RPC_RECORD_NAME_PREFERENCE {
    WORD                Preference;
    DNS_RPC_NAME        nameExchange;
};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/dcd3ec16-d6bf-4bb4-9128-6172f9e5f066
typedef struct DNS_RPC_RECORD_SOA {
    DWORD               Serial;
    DWORD               Refresh;
    DWORD               Retry;
    DWORD               Expire;
    DWORD               MinimumTtl;
    DNS_RPC_NAME        namePrimaryServer;
    BYTE                _pad;
    DNS_RPC_NAME        ZoneAdministratorEmail;
};

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/def7736a-dd09-4b4a-b8d6-6a702a7ecde0
typedef struct DNS_RPC_RECORD_TS {
    QWORD               EntombedTime;
};
"""
c_dns_record = cstruct(dns_record_def)
DNS_RECORD_TYPE = c_dns_record.DNS_RECORD_TYPE
