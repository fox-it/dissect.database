from __future__ import annotations

import datetime
import logging
import socket
from functools import cached_property
from typing import Any, NamedTuple

from dissect.cstruct.utils import swap16, swap32

from dissect.database.ese.ntds.objects.c_dns_record import DNS_RECORD_TYPE, c_dns_record
from dissect.database.ese.ntds.objects.top import Top

log = logging.getLogger(__name__)


def parse_rfc1035_dns_name(data: bytes) -> str:
    """Parse DNS name as specified in rfc1035#section-3.1 format.

    References:
        - https://datatracker.ietf.org/doc/html/rfc1035#section-3.1
    """
    if not data:
        return ""
    _nb_segment = data[0]
    name_parts = []
    offset = 1
    # Domain names in messages are expressed in terms of a sequence of labels.
    # Each label is represented as a one octet length field followed by that
    # number of octets.  Since every domain name ends with the null label of
    # the root, a domain name is terminated by a length byte of zero.
    while offset < len(data):
        length = data[offset]
        if length == 0:
            name_parts.append("")
            break
        # The high order two bits of every length octet must be zero, and the
        # remaining six bits of the length field limit the label to 63 octets or
        # less.
        if length > 63:  # Compression pointer
            return "<error>"

        offset += 1
        if offset + length > len(data):
            return "<error>"

        part = data[offset : offset + length].decode("utf-8", errors="backslashreplace")
        name_parts.append(part)
        offset += length
    return ".".join(name_parts) if name_parts else ""


class DnsARecord(NamedTuple):
    ipv4_address: str

    @property
    def ip_address(self) -> str:
        return self.ipv4_address

    @classmethod
    def from_bytes(cls, data: bytes) -> DnsARecord | None:
        """Parse ``A`` record (IPv4 address).

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/117c2ff9-9094-45b2-83c2-5e44518e0bac
        """
        if len(data) >= 4:
            ip = socket.inet_ntop(socket.AF_INET, data[:4])
            return cls(ipv4_address=ip)
        return None


class DnsAAAARecord(NamedTuple):
    ipv6_address: str

    @property
    def ip_address(self) -> str:
        return self.ipv6_address

    @classmethod
    def from_bytes(cls, data: bytes) -> DnsAAAARecord | None:
        """Parse ``AAAA`` record (IPv4 address).

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ee33fef1-6e82-42d0-8107-0f6d21be072a
        """
        if len(data) >= 16:
            ip = socket.inet_ntop(socket.AF_INET6, data[:16])
            return cls(ipv6_address=ip)
        return None


class SOARecord(NamedTuple):
    """The DNS_RPC_RECORD_SOA structure contains information about an SOA record."""

    name_primary_server: str
    # Serial does not match value seen using DNS request/management interface
    # As this is not the most important field, we simply ignore it instead a showing a errored value
    # serial: int
    refresh: int
    retry: int
    minimum_ttl: int
    zone_administrator_email: str

    @classmethod
    def from_bytes(cls, data: bytes) -> SOARecord | None:
        """Parse SOA records.

        References:
            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/dcd3ec16-d6bf-4bb4-9128-6172f9e5f066
        """
        try:
            dns_rpc_record_soa = c_dns_record.DNS_RPC_RECORD_SOA(data)
            return cls(
                name_primary_server=parse_rfc1035_dns_name(dns_rpc_record_soa.namePrimaryServer.dnsName),
                # Serial does not match value seen using DNS request/management interface
                # As this is not the most important field, we simply ignore it instead a showing an errored value
                # serial=swap_endianess(dns_rpc_record_soa.Serial, int_len=4),
                refresh=swap32(dns_rpc_record_soa.Refresh),
                retry=swap32(dns_rpc_record_soa.Retry),
                minimum_ttl=swap32(dns_rpc_record_soa.MinimumTtl),
                zone_administrator_email=parse_rfc1035_dns_name(dns_rpc_record_soa.ZoneAdministratorEmail.dnsName),
            )
        except EOFError:
            log.warning("Error parsing SOA record %s", data)
            return None


class NodeNameRecord(NamedTuple):
    """The DNS_RPC_RECORD_NODE_NAME structure contains information about a DNS record of any of the following types.

    - DNS_TYPE_PTR
    - DNS_TYPE_NS
    - DNS_TYPE_CNAME
    - DNS_TYPE_DNAME
    - DNS_TYPE_MB
    - DNS_TYPE_MR,
    - DNS_TYPE_MG
    - DNS_TYPE_MD
    - DNS_TYPE_MF
    """

    name_node: str

    @classmethod
    def from_bytes(cls, data: bytes) -> NodeNameRecord | None:
        """Parse Node Name type record (E.g CNAME, PTR).

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/8f986756-f151-4f5b-bfcf-0d85be8b0d7e
        """
        try:
            return NodeNameRecord(parse_rfc1035_dns_name(c_dns_record.DNS_RPC_NAME(data).dnsName))
        except EOFError:
            log.warning("Error parsing node name record %s", data)
            return None


class StringRecord(NamedTuple):
    """The DNS_RPC_RECORD_STRING structure contains information about a DNS record of any of the following types.

    - DNS_TYPE_HINFO
    - DNS_TYPE_ISDN
    - DNS_TYPE_TXT
    - DNS_TYPE_X25
    - DNS_TYPE_LOC
    """

    stringData: str

    @classmethod
    def from_bytes(cls, data: bytes) -> StringRecord | None:
        """Parse Node Name type record (E.g TXT).

        Test using GUI does not allow to create record with a line length > 255 char.

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/69166ff5-36c1-4542-9243-13b8931fa447
        """
        records = []
        try:
            data_consumed = 0

            while data_consumed < len(data):
                rpc_name = c_dns_record.DNS_RPC_NAME(data[data_consumed:])
                data_consumed += len(rpc_name)

                records.append(rpc_name.dnsName.decode("utf-8", errors="backslashreplace"))
            return cls("\n".join(records))
        except EOFError:
            log.warning("Error while processing node name record %s : %s", data, records, exc_info=True)
            return None


class NamePreferenceRecord(NamedTuple):
    """The DNS_RPC_RECORD_NAME_PREFERENCE structure specifies information about a DNS
    record of any of the following types.

    - DNS_TYPE_MX
    - DNS_TYPE_AFSDB
    - DNS_TYPE_RT
    """

    name_exchange: str
    preference: int

    @classmethod
    def from_bytes(cls, data: bytes) -> NamePreferenceRecord | None:
        """Parse DNS_RPC_RECORD_NAME_PREFERENCE record (E.g Mx).

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f647d391-6614-4c3e-b38b-4df971590eb6
        """
        try:
            dns_rpc_record_name_preference = c_dns_record.DNS_RPC_RECORD_NAME_PREFERENCE(data)
            return cls(
                preference=swap16(dns_rpc_record_name_preference.Preference),
                name_exchange=parse_rfc1035_dns_name(dns_rpc_record_name_preference.nameExchange.dnsName),
            )
        except EOFError:
            log.warning("Error while processing name preference record %s", data)
            return None


class SRVRecord(NamedTuple):
    """SRV ressource records."""

    name_target: str
    port: int
    weight: int
    priority: int

    @classmethod
    def from_bytes(cls, data: bytes) -> SRVRecord | None:
        """Parse SRV record.

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/db37cab7-f121-43ba-81c5-ca0e198d4b9a
        """
        try:
            dns_rpc_record_srv = c_dns_record.DNS_RPC_RECORD_SRV(data)
            target = parse_rfc1035_dns_name(dns_rpc_record_srv.nameTarget.dnsName)
            return SRVRecord(
                priority=dns_rpc_record_srv.Priority,
                weight=swap16(dns_rpc_record_srv.Weight),
                port=swap16(dns_rpc_record_srv.Port),
                name_target=target,
            )
        except EOFError:
            log.warning("Error while processing SRV record %s", data)
            return None


class TombStonedRecord(NamedTuple):
    """ZERO ressource records."""

    entombed_time: datetime.datetime

    @classmethod
    def from_bytes(cls, data: bytes) -> TombStonedRecord | None:
        """The DNS_RPC_RECORD_TS specifies information for a node that has been tombstoned,
        used for following record type : DNS_TYPE_ZERO.

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/69166ff5-36c1-4542-9243-13b8931fa447
        """
        try:
            ts_hundred_nano_seconds = c_dns_record.DNS_RPC_RECORD_TS(data).EntombedTime
            if ts_hundred_nano_seconds == 0:
                return None
            base_date = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
            return TombStonedRecord(base_date + datetime.timedelta(microseconds=ts_hundred_nano_seconds / 10))
        except EOFError:
            log.warning("Error while processing node name record%s", data)
            return None


class DnsRecord:
    """The dnsRecord attribute is used to store DNS resource record definitions.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8
    """

    def __init__(self, dns_records_bytes: bytes):
        self.raw: bytes = dns_records_bytes
        self.header = c_dns_record.DNS_RECORD_HEADER(dns_records_bytes)
        self.type: c_dns_record.DNS_RECORD_TYPE = self.header.Type
        self.ttl_seconds: int = swap32(self.header.TtlSeconds)
        self.timestamp: datetime.datetime | None = self.get_timestamp_as_datetime()

    def __repr__(self):
        return (
            f"<DnsRecord type={self.type.name!r} ttl_seconds={self.ttl_seconds!r} "
            f"timestamp={self.timestamp} data={self.data}>"
        )

    def get_timestamp_as_datetime(self) -> datetime.datetime | None:
        """Timestamp is stored in hours."""
        if self.header.TimeStamp == 0:
            return None
        try:
            # Windows timestamp is hours since 1601-01-01
            base_date = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
            return base_date + datetime.timedelta(hours=self.header.TimeStamp)
        except OverflowError:
            log.warning("Overflow error will trying to parse dns node timestamp")
            return None

    @property
    def data(
        self,
    ) -> (
        bytes
        | DnsARecord
        | DnsAAAARecord
        | NodeNameRecord
        | NamePreferenceRecord
        | StringRecord
        | TombStonedRecord
        | None
    ):
        data = bytearray(self.header.Data)

        # Process most common DNS records types
        match self.type:
            case DNS_RECORD_TYPE.A:
                return DnsARecord.from_bytes(data)
            case c_dns_record.DNS_RECORD_TYPE.AAAA:
                return DnsAAAARecord.from_bytes(data)
            case (
                DNS_RECORD_TYPE.PTR
                | DNS_RECORD_TYPE.NS
                | DNS_RECORD_TYPE.CNAME
                | DNS_RECORD_TYPE.DNAME
                | DNS_RECORD_TYPE.MB
                | DNS_RECORD_TYPE.MR
                | DNS_RECORD_TYPE.MG
                | DNS_RECORD_TYPE.MD
                | DNS_RECORD_TYPE.MF
            ):
                return NodeNameRecord.from_bytes(data)
            case DNS_RECORD_TYPE.MX | DNS_RECORD_TYPE.AFSDB | DNS_RECORD_TYPE.RT:
                return NamePreferenceRecord.from_bytes(data)
            case DNS_RECORD_TYPE.SRV:
                return SRVRecord.from_bytes(data)
            case DNS_RECORD_TYPE.SOA:
                return SOARecord.from_bytes(data)
            case (
                DNS_RECORD_TYPE.HINFO
                | DNS_RECORD_TYPE.ISDN
                | DNS_RECORD_TYPE.TXT
                | DNS_RECORD_TYPE.X25
                | DNS_RECORD_TYPE.LOC
            ):
                return StringRecord.from_bytes(data)
            case DNS_RECORD_TYPE.ZERO:
                return TombStonedRecord.from_bytes(data)
        return data

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": str(self.type.name),
            "ttl_seconds": self.ttl_seconds,
            "timestamp": self.timestamp,
            # isinstance(X, NamedTuple) does not work, but NamedTuple are subtype of tuple
            "data": self.data._asdict() if isinstance(self.data, tuple) else self.data,
        }


class DnsNode(Top):
    """Represents a DNS node object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnsnode
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8
    """

    __object_class__ = "dnsNode"

    def __repr_body__(self) -> str:
        return f"dns_name={self.distinguished_name_as_dns_name} records=|{'|'.join(repr(d) for d in self.dns_record)}|"

    @property
    def dns_record(self) -> list[DnsRecord]:
        dns_record = self.get("dnsRecord")
        if dns_record is None:
            return []
        return [DnsRecord(x) for x in dns_record]

    @cached_property
    def distinguished_name_as_dns_name(self) -> str:
        """Create a DNS name from node and parent names.

        Examples:
            DC=NORTH,DC=SEVENKINGDOMS.LOCAL,CN=MICROSOFTDNS,DC=DOMAINDNSZONES,DC=SEVENKINGDOMS,DC=LOCAL ->
                north.sevenkingdoms.local
        """
        node = self.distinguished_name
        ret = [self.name] if self.name != "@" else []  # @ means same as parent folder
        while (i := node.parent).object.__object_class__ in ["dnsNode", "dnsZone"]:
            ret.append(i.object.name)
            node = i
        return ".".join(ret).replace("\n", "\\n")

    def as_dict(self) -> dict[str, Any]:
        ret = super().as_dict()
        ret["distinguished_name_as_dns_name"] = self.distinguished_name_as_dns_name
        ret["parsed_dns_records"] = [r.as_dict() for r in self.dns_record]
        return ret
