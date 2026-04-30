from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from dissect.database.ese.ntds.util import _ldapDisplayName_to_DNT, _oid_to_attrtyp, decode_value, encode_value

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS


@pytest.mark.parametrize(
    ("attribute", "decoded", "encoded"),
    [
        ("cn", "test_value", "test_value"),
        (
            "objectSid",
            "S-1-5-21-1957882089-4252948412-2360614479-1134",
            bytes.fromhex("010500000000000515000000e9e8b274bcd77efd4f1eb48c0000046e"),
        ),
    ],
)
def test_encode_decode_value(goad: NTDS, attribute: str, decoded: Any, encoded: Any) -> None:
    """Test ``encode_value`` and ``decode_value`` coverage."""
    schema = goad.db.data.schema.lookup_attribute(name=attribute)
    assert encode_value(goad.db, schema, decoded) == encoded
    assert decode_value(goad.db, schema, encoded) == decoded


def test_oid_to_attrtyp_with_oid_string(goad: NTDS) -> None:
    """Test ``_oid_to_attrtyp`` with OID string format."""
    person_entry = goad.db.data.schema.lookup(name="person")

    oid = goad.db.data.schema.attrtyp_to_oid(person_entry.id)

    result = _oid_to_attrtyp(goad.db, oid)
    assert isinstance(result, int)
    assert result == person_entry.id


def test_oid_string_to_attrtyp_with_class_name(goad: NTDS) -> None:
    """Test ``_oid_to_attrtyp`` with class name (normal case)."""
    person_entry = goad.db.data.schema.lookup(name="person")

    result = _oid_to_attrtyp(goad.db, "person")
    assert isinstance(result, int)
    assert result == person_entry.id


def test_get_dnt_coverage(goad: NTDS) -> None:
    """Test DNT method coverage."""
    # Test with an attribute
    dnt = _ldapDisplayName_to_DNT(goad.db, "cn")
    assert isinstance(dnt, int)
    assert dnt == 132

    # Test with a class
    dnt = _ldapDisplayName_to_DNT(goad.db, "person")
    assert isinstance(dnt, int)
    assert dnt == 1554


def test_supplemental_credentials(goad: NTDS) -> None:
    """Test decoding of supplementalCredentials attribute."""
    user = next(u for u in goad.users() if u.name == "maester.pycelle")

    assert isinstance(user.get("supplementalCredentials")[0], bytes)

    syskey = bytes.fromhex("079f95655b66f16deb28aa1ab3a81eb0")
    goad.pek.unlock(syskey)
    assert goad.pek.unlocked

    value = user.get("supplementalCredentials")[0]
    assert isinstance(value, dict)

    assert value["Packages"] == ["NTLM-Strong-NTOWF", "Kerberos-Newer-Keys", "Kerberos", "WDigest"]

    assert value["Primary:NTLM-Strong-NTOWF"].hex() == "c63d40b2713f0c0916eeab6e522abef5"

    assert len(value["Primary:WDigest"]) == 29

    assert value["Primary:Kerberos"]["DefaultSalt"] == "SEVENKINGDOMS.LOCALmaester.pycelle".encode("utf-16-le")
    assert value["Primary:Kerberos"]["Credentials"][0]["KeyType"] == 3
    assert value["Primary:Kerberos"]["Credentials"][0]["Key"].hex() == "89379167f87f0b5b"

    assert value["Primary:Kerberos-Newer-Keys"]["DefaultSalt"] == "SEVENKINGDOMS.LOCALmaester.pycelle".encode(
        "utf-16-le"
    )
    assert value["Primary:Kerberos-Newer-Keys"]["DefaultIterationCount"] == 4096
    assert value["Primary:Kerberos-Newer-Keys"]["Credentials"][0]["KeyType"] == 18
    assert value["Primary:Kerberos-Newer-Keys"]["Credentials"][0]["IterationCount"] == 4096
    assert (
        value["Primary:Kerberos-Newer-Keys"]["Credentials"][0]["Key"].hex()
        == "25370ba431b262bdf7ca279e88d824cd59b4ce280bbef537a96fe51c8d790042"
    )
    assert value["Primary:Kerberos-Newer-Keys"]["Credentials"][1]["KeyType"] == 17
    assert value["Primary:Kerberos-Newer-Keys"]["Credentials"][1]["IterationCount"] == 4096
    assert value["Primary:Kerberos-Newer-Keys"]["Credentials"][1]["Key"].hex() == "7d375f265062643302a4827719ea541d"
    assert value["Primary:Kerberos-Newer-Keys"]["Credentials"][2]["KeyType"] == 3
    assert value["Primary:Kerberos-Newer-Keys"]["Credentials"][2]["IterationCount"] == 4096
    assert value["Primary:Kerberos-Newer-Keys"]["Credentials"][2]["Key"].hex() == "89379167f87f0b5b"


def test_supplemental_credentials_adam(adam: NTDS) -> None:
    """Test decoding of supplementalCredentials attribute in AD LDS NTDS.dit."""
    user = next(adam.users(), None)

    value = user.get("supplementalCredentials")[0]
    assert isinstance(value, dict)

    assert value["Packages"] == ["WDigest"]
    assert len(value["Primary:WDigest"]) == 29
