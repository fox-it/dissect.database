from __future__ import annotations

import datetime
import logging
import socket
import typing
from functools import cached_property
from typing import Any, ClassVar, NamedTuple

from dissect.cstruct.utils import swap16, swap32

from dissect.database.ese.ntds.objects.c_dnsnode import DNS_RECORD_TYPE, c_dns_record
from dissect.database.ese.ntds.objects.top import Top

if typing.TYPE_CHECKING:
    from dissect.database.ese.ntds.objects.object import DecoderMap
log = logging.getLogger(__name__)


def parse_rfc1035_dns_name(data: bytes) -> str:
    """Parse DNS name as specified in ``rfc1035#section-3.1`` format.

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
    """``A`` resource records."""

    ipv4_address: str

    @property
    def ip_address(self) -> str:
        return self.ipv4_address

    @classmethod
    def from_bytes(cls, data: bytes) -> DnsARecord:
        """Parse ``A`` record (IPv4 address).

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/117c2ff9-9094-45b2-83c2-5e44518e0bac

        Raises:
            EOFError: Issue while unpacking structure.
        """
        if len(data) >= 4:
            ip = socket.inet_ntop(socket.AF_INET, data[:4])
            return cls(ipv4_address=ip)
        raise EOFError("A records with less than 4 bytes")


class DnsAAAARecord(NamedTuple):
    """``AAAA`` resource records."""

    ipv6_address: str

    @property
    def ip_address(self) -> str:
        return self.ipv6_address

    @classmethod
    def from_bytes(cls, data: bytes) -> DnsAAAARecord:
        """Parse ``AAAA`` record (IPv6 address).

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ee33fef1-6e82-42d0-8107-0f6d21be072a

        Raises:
            EOFError: Issue while unpacking structure.
        """
        if len(data) >= 16:
            ip = socket.inet_ntop(socket.AF_INET6, data[:16])
            return cls(ipv6_address=ip)
        raise EOFError("AAAA records with less than 16 bytes")


class SOARecord(NamedTuple):
    """The ``DNS_RPC_RECORD_SOA`` structure contains information about a ``SOA`` record."""

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
        """Parse ``SOA`` records.

        References:
            https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/dcd3ec16-d6bf-4bb4-9128-6172f9e5f066

        Raises:
            EOFError: Issue while unpacking structure.
        """
        record = c_dns_record.DNS_RPC_RECORD_SOA(data)
        return cls(
            name_primary_server=parse_rfc1035_dns_name(record.namePrimaryServer.dnsName),
            # Serial does not match value seen using DNS request/management interface
            # As this is not the most important field, we simply ignore it instead a showing an errored value
            # serial=swap32(dns_rpc_record_soa.Serial, int_len=4),
            refresh=swap32(record.Refresh),
            retry=swap32(record.Retry),
            minimum_ttl=swap32(record.MinimumTtl),
            zone_administrator_email=parse_rfc1035_dns_name(record.ZoneAdministratorEmail.dnsName),
        )


class NodeNameRecord(NamedTuple):
    """The ``DNS_RPC_RECORD_NODE_NAME`` structure contains information about a DNS record referring to another DNS name.

    This corresponds to the following types:
        - ``DNS_TYPE_PTR``
        - ``DNS_TYPE_NS``
        - ``DNS_TYPE_CNAME``
        - ``DNS_TYPE_DNAME``
        - ``DNS_TYPE_MB``
        - ``DNS_TYPE_MR``
        - ``DNS_TYPE_MG``
        - ``DNS_TYPE_MD``
        - ``DNS_TYPE_MF``
    """

    name_node: str

    @classmethod
    def from_bytes(cls, data: bytes) -> NodeNameRecord | None:
        """Parse Node Name type record (e.g. ``CNAME``, ``PTR``).

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/8f986756-f151-4f5b-bfcf-0d85be8b0d7e

        Raises:
            EOFError: Issue while unpacking structure.
        """
        return NodeNameRecord(parse_rfc1035_dns_name(c_dns_record.DNS_RPC_NAME(data).dnsName))


class StringRecord(NamedTuple):
    """The ``DNS_RPC_RECORD_STRING`` structure contains information about a DNS record containing text data.

    This corresponds to the following types:
        - ``DNS_TYPE_HINFO``
        - ``DNS_TYPE_ISDN``
        - ``DNS_TYPE_TXT``
        - ``DNS_TYPE_X25``
        - ``DNS_TYPE_LOC``
    """

    string_data: str

    @classmethod
    def from_bytes(cls, data: bytes) -> StringRecord | None:
        """Parse Node Name type record (e.g. ``TXT``).

        Test using GUI does not allow to create record with a line length > 255 char.

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/69166ff5-36c1-4542-9243-13b8931fa447

        Raises:
            EOFError: Issue while unpacking structure.
        """
        records = []
        data_consumed = 0

        while data_consumed < len(data):
            rpc_name = c_dns_record.DNS_RPC_NAME(data[data_consumed:])
            data_consumed += len(rpc_name)

            records.append(rpc_name.dnsName.decode("utf-8", errors="backslashreplace"))
        return cls("\n".join(records))


class NamePreferenceRecord(NamedTuple):
    """The ``DNS_RPC_RECORD_NAME_PREFERENCE`` structure specifies information about a DNS
    record referring to another DNS name with a preference.

    This corresponds to the following types:
        - ``DNS_TYPE_MX``
        - ``DNS_TYPE_AFSDB``
        - ``DNS_TYPE_RT``
    """

    name_exchange: str
    preference: int

    @classmethod
    def from_bytes(cls, data: bytes) -> NamePreferenceRecord | None:
        """Parse ``DNS_RPC_RECORD_NAME_PREFERENCE`` record (e.g. ``MX``).

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f647d391-6614-4c3e-b38b-4df971590eb6

        Raises:
            EOFError: Issue while unpacking structure.
        """
        record = c_dns_record.DNS_RPC_RECORD_NAME_PREFERENCE(data)
        return cls(
            preference=swap16(record.Preference),
            name_exchange=parse_rfc1035_dns_name(record.nameExchange.dnsName),
        )


class SRVRecord(NamedTuple):
    """``SRV`` resource records."""

    name_target: str
    port: int
    weight: int
    priority: int

    @classmethod
    def from_bytes(cls, data: bytes) -> SRVRecord | None:
        """Parse ``SRV`` record.

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/db37cab7-f121-43ba-81c5-ca0e198d4b9a

        Raises:
            EOFError: Issue while unpacking structure.
        """
        record = c_dns_record.DNS_RPC_RECORD_SRV(data)
        target = parse_rfc1035_dns_name(record.nameTarget.dnsName)
        return SRVRecord(
            priority=record.Priority,
            weight=swap16(record.Weight),
            port=swap16(record.Port),
            name_target=target,
        )


class TombStonedRecord(NamedTuple):
    """``ZERO`` resource records."""

    entombed_time: datetime.datetime

    @classmethod
    def from_bytes(cls, data: bytes) -> TombStonedRecord | None:
        """The ``DNS_RPC_RECORD_TS`` specifies information for a node that has been tombstoned,
        used for record type ``DNS_TYPE_ZERO``.

        References:
            - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/69166ff5-36c1-4542-9243-13b8931fa447

        Raises:
            EOFError: Issue while unpacking structure.
        """
        record = c_dns_record.DNS_RPC_RECORD_TS(data).EntombedTime
        if record == 0:
            return None
        base_date = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return TombStonedRecord(base_date + datetime.timedelta(microseconds=record / 10))


class DnsRecord:
    """DNS resource record definitions.

    References:
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8
    """

    def __init__(self, data: bytes):
        self.raw = data
        self.header = c_dns_record.DNS_RECORD_HEADER(data)
        self.type = self.header.Type
        self.ttl_seconds = swap32(self.header.TtlSeconds)

    def __repr__(self) -> str:
        return (
            f"<DnsRecord type={self.type.name!r} ttl_seconds={self.ttl_seconds!r} "
            f"timestamp={self.timestamp} data={self.data}>"
        )

    @property
    def timestamp(self) -> datetime.datetime | None:
        """Timestamp is stored in hours since 1601-01-01.

        Raises:
            OverflowError: Number of hours cause an overflow.
        """
        if self.header.TimeStamp == 0:
            return None
        # Windows timestamp is hours since 1601-01-01
        base_date = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return base_date + datetime.timedelta(hours=self.header.TimeStamp)

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
        | SRVRecord
        | SOARecord
        | None
    ):
        """Parse the data part of a record, which contains a structure that depends on the record type.

        Raises:
            EOFError: Issue while unpacking structure.
        """
        header_data = self.header.Data

        # Process most common DNS records types
        match self.type:
            case DNS_RECORD_TYPE.A:
                return DnsARecord.from_bytes(header_data)
            case c_dns_record.DNS_RECORD_TYPE.AAAA:
                return DnsAAAARecord.from_bytes(header_data)
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
                return NodeNameRecord.from_bytes(header_data)
            case DNS_RECORD_TYPE.MX | DNS_RECORD_TYPE.AFSDB | DNS_RECORD_TYPE.RT:
                return NamePreferenceRecord.from_bytes(header_data)
            case DNS_RECORD_TYPE.SRV:
                return SRVRecord.from_bytes(header_data)
            case DNS_RECORD_TYPE.SOA:
                return SOARecord.from_bytes(header_data)
            case (
                DNS_RECORD_TYPE.HINFO
                | DNS_RECORD_TYPE.ISDN
                | DNS_RECORD_TYPE.TXT
                | DNS_RECORD_TYPE.X25
                | DNS_RECORD_TYPE.LOC
            ):
                return StringRecord.from_bytes(header_data)
            case DNS_RECORD_TYPE.ZERO:
                return TombStonedRecord.from_bytes(header_data)
        return header_data

    def as_dict(self) -> dict[str, Any]:
        """Return a dictionary representation of the record, with parsed data if possible."""
        try:
            data = self.data
        except EOFError:
            log.warning("Error processing DNS record: failed to parse data (record type: %s)", self.type.name)
            data = None

        try:
            timestamp = self.timestamp
        except OverflowError:
            log.warning("Error processing DNS record: invalid record timestamp")
            timestamp = None
        return {
            "type": self.type.name,
            "ttl_seconds": self.ttl_seconds,
            "timestamp": timestamp,
            # isinstance(X, NamedTuple) does not work, but NamedTuple are subtype of tuple
            "data": data._asdict() if isinstance(data, tuple) else data,
        }


class DnsNode(Top):
    """Represents a DNS node object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnsnode
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6912b338-5472-4f59-b912-0edb536b6ed8
    """

    __object_class__ = "dnsNode"
    __decoders__: ClassVar[DecoderMap] = {"dnsRecord": lambda x, value: [DnsRecord(x) for x in value] if value else []}

    def __repr_body__(self) -> str:
        return f"dns_name={self.dns_name} dns_record={self.dns_record}"

    @property
    def dns_record(self) -> list[DnsRecord]:
        """Return DNS records as objects.

        Raises:
            EOFError: Issue while unpacking structure.
        """
        return self.get("dnsRecord")

    @cached_property
    def dns_name(self) -> str:
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
        result = super().as_dict()
        result["dns_name"] = self.dns_name
        if "dnsRecord" in result:
            result["dnsRecord"] = [r.as_dict() for r in result.get("dnsRecord", [])]
        return result
