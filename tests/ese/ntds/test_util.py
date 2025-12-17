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
def test_encode_decode_value(ntds_small: NTDS, attribute: str, decoded: Any, encoded: Any) -> None:
    """Test ``encode_value`` and ``decode_value`` coverage."""
    assert encode_value(ntds_small.db, attribute, decoded) == encoded
    assert decode_value(ntds_small.db, attribute, encoded) == decoded


def test_oid_to_attrtyp_with_oid_string(ntds_small: NTDS) -> None:
    """Test ``_oid_to_attrtyp`` with OID string format."""
    person_entry = ntds_small.db.data.schema.lookup(ldap_name="person")

    result = _oid_to_attrtyp(ntds_small.db, person_entry.oid)
    assert isinstance(result, int)
    assert result == person_entry.id


def test_oid_string_to_attrtyp_with_class_name(ntds_small: NTDS) -> None:
    """Test ``_oid_to_attrtyp`` with class name (normal case)."""
    person_entry = ntds_small.db.data.schema.lookup(ldap_name="person")

    result = _oid_to_attrtyp(ntds_small.db, "person")
    assert isinstance(result, int)
    assert result == person_entry.id


def test_get_dnt_coverage(ntds_small: NTDS) -> None:
    """Test _get_DNT method coverage."""
    # Test with an attribute
    dnt = _ldapDisplayName_to_DNT(ntds_small.db, "cn")
    assert isinstance(dnt, int)
    assert dnt == 132

    # Test with a class
    dnt = _ldapDisplayName_to_DNT(ntds_small.db, "person")
    assert isinstance(dnt, int)
    assert dnt == 1554
