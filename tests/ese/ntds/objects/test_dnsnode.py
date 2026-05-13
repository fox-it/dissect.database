from __future__ import annotations

import datetime
import logging
import typing

import pytest

from dissect.database.ese.ntds.objects.c_dnsnode import DNS_RECORD_TYPE
from dissect.database.ese.ntds.objects.dnsnode import (
    DnsAAAARecord,
    DnsARecord,
    DnsRecord,
    NamePreferenceRecord,
    NodeNameRecord,
    SOARecord,
    SRVRecord,
    StringRecord,
    TombStonedRecord,
    parse_rfc1035_dns_name,
)

if typing.TYPE_CHECKING:
    from dissect.database.ese.ntds import NTDS


def test_parse_dns_name() -> None:
    """Test DNS name as specified in rfc1035#section-3.1 format."""
    assert parse_rfc1035_dns_name(b"\x03\x0ckingslanding\rsevenkingdoms\x05local") == "kingslanding.sevenkingdoms.local"

    assert (
        parse_rfc1035_dns_name(b"\x06\x04test\x04with\x08multiple\x06secion\rsevenkingdoms\x05local")
        == "test.with.multiple.secion.sevenkingdoms.local"
    )


def test_parse_dns_node_name_record() -> None:
    """Test a NodeName records (CNAME, PTR etc...)."""
    assert (
        NodeNameRecord.from_bytes(b"\x11\x03\x06dc2-eu\x04test\x03lan\x00").name_node == "dc2-eu.test.lan"
    )  # odd length

    assert (
        NodeNameRecord.from_bytes(b"&\x04\nWINTERFELL\x05north\rsevenkingdoms\x05local\x00").name_node
        == "WINTERFELL.north.sevenkingdoms.local"
    )

    assert (
        NodeNameRecord.from_bytes(b"/\x06\x04test\x04with\x08multiple\x06secion\rsevenkingdoms\x05local\x00").name_node
        == "test.with.multiple.secion.sevenkingdoms.local"
    )


def test_parse_dns_tombstoned_record() -> None:
    assert TombStonedRecord.from_bytes(b"\xf1\xba\x0c\xa5\xc8 \xdc\x01").entombed_time == datetime.datetime(
        2025, 9, 8, 13, 58, 24, 889522, tzinfo=datetime.timezone.utc
    )


def test_parse_dns_string_record() -> None:
    assert StringRecord.from_bytes(
        b"|TXT record made for dissect. Quite long to test if there is some limit size, "
        b"like over 64 characters or something like that.\x004Two new line above, "
        b"and an special char (euro) : \xe2\x82\xac"
    ).string_data == (
        "TXT record made for dissect. Quite long to test if there is some limit size, "
        "like over 64 characters or something like that.\n\n"
        "Two new line above, and an special char (euro) : €"
    )

    assert StringRecord.from_bytes(
        b"\xd6this is a very long record, with a size over 255, as string size is stored on a unint."
        b" Very vey very very very very very very very very vey very very very very very very very very vey very very"
        b" very very very veryg\x00\x00\nA new line\x17And we continue tthis i"
    ).string_data == (
        "this is a very long record, with a size over 255, as string size is stored on a unint. Very vey"
        " very very very very very very very very vey very very very very very very very very vey very"
        " very very very very veryg\n\n\nA new line\nAnd we continue tthis i"
    )
    assert StringRecord.from_bytes(b"\x01q\x02qw\x03qwe\x04qwer\x05qwert\x06qwerty\x08qwertyui").string_data == (
        "q\nqw\nqwe\nqwer\nqwert\nqwerty\nqwertyui"
    )


def test_parse_dns_string_null_record() -> None:
    """Test an empty TXT record."""
    assert StringRecord.from_bytes(b"\x00").string_data == ""


def test_parse_name_preference_record() -> None:
    """Test with MX records, with two different preferences."""
    mx_record: NamePreferenceRecord = NamePreferenceRecord.from_bytes(b"\x00\x14\x0b\x01\tmailhost2\x00")
    assert mx_record.name_exchange == "mailhost2"
    assert mx_record.preference == 20

    mx_record: NamePreferenceRecord = NamePreferenceRecord.from_bytes(b"\x00\n\x0b\x01\tmailhost1\x00")
    assert mx_record.name_exchange == "mailhost1"
    assert mx_record.preference == 10


def test_parse_dns_srv_record() -> None:
    """Parse an SRV record related to LDAP."""
    srv_record: SRVRecord = SRVRecord.from_bytes(
        b"\x00\x00\x00d\x01\x85&\x04\nwinterfell\x05north\rsevenkingdoms\x05local\x00"
    )
    assert srv_record.priority == 0
    assert srv_record.weight == 100
    assert srv_record.port == 389  # LDAP
    assert srv_record.name_target == "winterfell.north.sevenkingdoms.local"


def test_parse_dns_soa_record() -> None:
    soa_record: SOARecord = SOARecord.from_bytes(
        b'\x00\x00\x00#\x00\x00\x03\x84\x00\x00\x02X\x00\x01Q\x80\x00\x00\x0e\x10"\x03\x0ckingslanding\r'
        b"sevenkingdoms\x05local\x00 \x03\nhostmaster\rsevenkingdoms\x05local\x00"
    )
    assert soa_record.name_primary_server == "kingslanding.sevenkingdoms.local"
    # assert soa_record.serial == 35 -> UI shows 58 but hex is (00 00 00 23)
    assert soa_record.refresh == 900
    assert soa_record.retry == 600
    assert soa_record.minimum_ttl == 3600
    assert soa_record.zone_administrator_email == "hostmaster.sevenkingdoms.local"


def test_parse_name_aaaa_record() -> None:
    """Test multiple AAAA (IPv6) records."""
    assert (
        DnsAAAARecord.from_bytes(b" \x01\r\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00").ipv6_address
        == "2001:db8::1:0"
    )
    assert (
        DnsAAAARecord.from_bytes(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01").ipv6_address
        == "::1"
    )
    assert (
        DnsAAAARecord.from_bytes(b"\xfd\x17b\\\xf07\x00\x020\x84\x07n\x83\xeb\xab\x1b").ipv6_address
        == "fd17:625c:f037:2:3084:76e:83eb:ab1b"
    )


def test_parse_name_a_record() -> None:
    """Test an A (IpV4) record."""
    assert DnsARecord.from_bytes(b"\xc0\xa8d\x1d").ipv4_address == "192.168.100.29"
    # Error
    with pytest.raises(EOFError):
        DnsARecord.from_bytes(b"\xc0")


def test_dns_nodes(goad: NTDS) -> None:
    """Test multiple DNS records from GOAD NTDS. Also test repr and as dict."""
    dns_nodes = list(goad.dns_nodes())
    assert len(dns_nodes) == 113
    # there is no really guaranty regarding record order, thus we select them using name
    a_record = next(node for node in dns_nodes if node.name == "WINTERFELL.north").dns_record[0]
    assert repr(a_record) == (
        "<DnsRecord type='A' ttl_seconds=3600 timestamp=None data=DnsARecord(ipv4_address='10.0.2.15')>"
    )
    assert isinstance(a_record.data, DnsARecord)
    assert a_record.data.ipv4_address == "10.0.2.15"
    assert a_record.data.ip_address == "10.0.2.15"
    assert a_record.timestamp is None
    assert a_record.ttl_seconds == 3600

    srv_record = next(
        node
        for node in dns_nodes
        if node.dns_name == "_ldap._tcp.3c45e4c9-7d10-44d6-ba1f-6177134e58fd.domains._msdcs.sevenkingdoms.local"
    ).dns_record[0]
    assert isinstance(srv_record.data, SRVRecord)
    assert srv_record.data.name_target == "winterfell.north.sevenkingdoms.local"
    assert srv_record.data.port == 389
    assert srv_record.data.weight == 100
    assert srv_record.data.priority == 0
    assert srv_record.timestamp == datetime.datetime.fromisoformat("2025-12-18 17:00:00+00:00")
    assert srv_record.ttl_seconds == 600

    assert (
        repr(srv_record) == "<DnsRecord type='SRV' ttl_seconds=600 timestamp=2025-12-18 17:00:00+00:00 "
        "data=SRVRecord(name_target='winterfell.north.sevenkingdoms.local', port=389, weight=100, priority=0)>"
    )

    assert srv_record.as_dict() == {
        "data": {"name_target": "winterfell.north.sevenkingdoms.local", "port": 389, "priority": 0, "weight": 100},
        "timestamp": datetime.datetime(2025, 12, 18, 17, 0, tzinfo=datetime.timezone.utc),
        "ttl_seconds": 600,
        "type": "SRV",
    }

    _msdcs = next(node for node in dns_nodes if node.dns_name == "_msdcs.sevenkingdoms.local")
    # Test using the DecoderMap
    soa_record: DnsRecord = next(record for record in _msdcs.get("dnsRecord") if record.type == DNS_RECORD_TYPE.SOA)
    assert isinstance(soa_record.data, SOARecord)
    assert soa_record.data.name_primary_server == "winterfell.north.sevenkingdoms.local"
    assert soa_record.data.refresh == 900
    assert soa_record.data.retry == 600
    assert soa_record.data.minimum_ttl == 3600
    assert soa_record.data.zone_administrator_email == "hostmaster.sevenkingdoms.local"
    assert soa_record.timestamp is None
    assert srv_record.ttl_seconds == 600

    ns_records = sorted(
        (record for record in _msdcs.dns_record if record.type == DNS_RECORD_TYPE.NS), key=lambda x: x.data.name_node
    )[0]
    assert isinstance(ns_records.data, NodeNameRecord)
    assert ns_records.data.name_node == "kingslanding.sevenkingdoms.local"
    assert ns_records.timestamp is None
    assert ns_records.ttl_seconds == 3600

    aaaa_record = next(node for node in dns_nodes if node.dns_name == "l.root-servers.net.RootDNSServers").dns_record[0]
    assert isinstance(aaaa_record.data, DnsAAAARecord)
    assert aaaa_record.data.ipv6_address == "2001:500:9f::42"
    assert aaaa_record.data.ip_address == "2001:500:9f::42"
    assert aaaa_record.timestamp is None
    assert aaaa_record.ttl_seconds == 0

    assert repr(aaaa_record) == (
        "<DnsRecord type='AAAA' ttl_seconds=0 timestamp=None data=DnsAAAARecord(ipv6_address='2001:500:9f::42')>"
    )
    assert aaaa_record.as_dict() == {
        "data": {
            "ipv6_address": "2001:500:9f::42",
        },
        "timestamp": None,
        "ttl_seconds": 0,
        "type": "AAAA",
    }


def test_errored_dns_node(caplog: pytest.LogCaptureFixture) -> None:
    errored_record = (
        b"\x04\x00\x01\x00\x05\x80\x00\x00\x19\x00\x00\x00\x00\x00\x0e\x10\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x02"
    )
    with pytest.raises(EOFError):
        _ = DnsRecord(errored_record)

    a_record = DnsRecord(
        b"\x03\x00\x01\x00\x05\x80\x00\x00\x19\x00\x00\x00\x00\x00\x0e\x10\x00\x00\x00\x00\x00\x00\x00\x00\n\x00\x02"
    )
    with pytest.raises(EOFError):
        _ = a_record.data
    with caplog.at_level(logging.WARNING):
        assert a_record.as_dict() == {"data": None, "timestamp": None, "ttl_seconds": 3600, "type": "A"}
        assert "Error processing DNS record: failed to parse data (record type: A)" in caplog.text
    overflow_timestamp_record = DnsRecord(
        b"\x04\x00\x01\x00\x05\x80\x00\x00\x19\x00\x00\x00\x00\x00\x0e"
        b"\x10\x00\x00\x00\x00\xff\xff\xff\xff\n\x00\x02\x02"
    )

    with pytest.raises(OverflowError):
        _ = overflow_timestamp_record.timestamp

    caplog.clear()
    with caplog.at_level(logging.WARNING):
        assert overflow_timestamp_record.as_dict() == {
            "data": {"ipv4_address": "10.0.2.2"},
            "timestamp": None,
            "ttl_seconds": 3600,
            "type": "A",
        }
        assert "Error processing DNS record: invalid record timestamp" in caplog.text
