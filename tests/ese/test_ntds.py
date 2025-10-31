from __future__ import annotations

from typing import BinaryIO
from unittest.mock import patch

import pytest
from dissect.util.ldap import SearchFilter
from dissect.util.sid import read_sid

from dissect.database.ese.ntds import NTDS, Computer, Group, User
from dissect.database.ese.ntds.secd import ACCESS_ALLOWED_ACE, AccessMaskFlag, AceFlag
from dissect.database.ese.ntds.utils import format_GUID, increment_last_char


@pytest.fixture(scope="module")
def ntds(ntds_dit: BinaryIO) -> NTDS:
    return NTDS(ntds_dit)


def test_groups_api(ntds: NTDS) -> None:
    group_records = sorted(ntds.groups(), key=lambda x: x.sAMAccountName)
    assert len(group_records) == 54
    assert isinstance(group_records[0], Group)
    assert all(isinstance(x, Group) for x in group_records)
    domain_admins = next(x for x in group_records if x.sAMAccountName == "Domain Admins")
    assert isinstance(domain_admins, Group)
    assert sorted([x.sAMAccountName for x in domain_admins.members()]) == [
        "Administrator",
        "ERNESTO_RAMOS",
        "Guest",
        "OTTO_STEELE",
    ]


def test_users_api(ntds: NTDS) -> None:
    user_records = sorted(ntds.users(), key=lambda x: x.sAMAccountName)
    assert len(user_records) == 15
    assert isinstance(user_records[0], User)
    assert [x.sAMAccountName for x in user_records] == [
        "Administrator",
        "BRANDY_CALDERON",
        "CORRINE_GARRISON",
        "ERNESTO_RAMOS",
        "FORREST_NIXON",
        "Guest",
        "JERI_KEMP",
        "JOCELYN_MCMAHON",
        "JUDY_RICH",
        "MALINDA_PATE",
        "OTTO_STEELE",
        "RACHELLE_LYNN",
        "beau.terham",
        "henk.devries",
        "krbtgt",
    ]
    assert user_records[3].distinguishedName == "CN=ERNESTO_RAMOS,OU=TST,OU=PEOPLE,DC=DISSECT,DC=LOCAL"
    assert user_records[3].cn == "ERNESTO_RAMOS"
    assert user_records[4].distinguishedName == "CN=FORREST_NIXON,OU=GROUPS,OU=AZR,OU=TIER 1,DC=DISSECT,DC=LOCAL"
    assert user_records[12].displayName == "Beau ter Ham"
    assert user_records[12].objectSid == "S-1-5-21-1957882089-4252948412-2360614479-1134"
    assert user_records[12].distinguishedName == "CN=BEAU TER HAM,OU=TST,OU=PEOPLE,DC=DISSECT,DC=LOCAL"
    assert user_records[12].description == "My password might be related to the summer"
    assert user_records[13].displayName == "Henk de Vries"
    assert user_records[13].mail == "henk@henk.com"
    assert user_records[13].description == "Da real Dissect MVP"


def test_group_membership(ntds: NTDS) -> None:
    # Prepare objects
    domain_admins = next(ntds.lookup(sAMAccountName="Domain Admins"))
    domain_users = next(ntds.lookup(sAMAccountName="Domain Users"))
    assert isinstance(domain_admins, Group)
    ernesto = next(ntds.lookup(sAMAccountName="ERNESTO_RAMOS"))
    assert isinstance(ernesto, User)

    # Test membership of ERNESTO_RAMOS
    assert len(list(ernesto.groups())) == 12
    assert sorted([g.sAMAccountName for g in ernesto.groups()]) == [
        "Ad-231085liz-distlist1",
        "Ad-apavad281-distlist1",
        "CO-hocicodep-distlist1",
        "Denied RODC Password Replication Group",
        "Domain Admins",
        "Domain Computers",
        "Domain Users",
        "Gu-ababariba-distlist1",
        "JO-pec-distlist1",
        "MA-anz-admingroup1",
        "TSTWWEBS1000000$",
        "Users",
    ]
    assert ernesto.is_member_of(domain_admins)
    assert ernesto.is_member_of(domain_users)

    # Check the members of the Domain Admins group
    assert len(list(domain_admins.members())) == 4
    assert sorted([u.sAMAccountName for u in domain_admins.members()]) == [
        "Administrator",
        "ERNESTO_RAMOS",
        "Guest",
        "OTTO_STEELE",
    ]
    assert domain_admins.is_member(ernesto)

    # Check the members of the Domain Users group
    assert len(list(domain_users.members())) == 14  # ALl users except Guest
    assert sorted([u.sAMAccountName for u in domain_users.members()]) == [
        "Administrator",
        "BRANDY_CALDERON",
        "CORRINE_GARRISON",
        "ERNESTO_RAMOS",
        "FORREST_NIXON",
        "JERI_KEMP",
        "JOCELYN_MCMAHON",
        "JUDY_RICH",
        "MALINDA_PATE",
        "OTTO_STEELE",
        "RACHELLE_LYNN",
        "beau.terham",
        "henk.devries",
        "krbtgt",
    ]
    assert domain_users.is_member(ernesto)
    assert not domain_users.is_member(next(ntds.lookup(sAMAccountName="Guest")))


def test_query_specific_users(ntds: NTDS) -> None:
    specific_records = sorted(
        ntds.query("(&(objectClass=user)(|(cn=Henk de Vries)(cn=Administrator)))"), key=lambda x: x.sAMAccountName
    )
    assert len(specific_records) == 2
    assert specific_records[0].sAMAccountName == "Administrator"
    assert specific_records[1].sAMAccountName == "henk.devries"


def test_db_fetch_calls_simple_AND(ntds: NTDS) -> None:
    query = "(&(objectClass=user)(cn=Henk de Vries))"
    with patch.object(ntds, "_query_database", wraps=ntds._query_database) as mock_fetch:
        records = list(ntds.query(query))
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_db_fetch_calls_simple_OR(ntds: NTDS) -> None:
    query = "(|(objectClass=group)(cn=ERNESTO_RAMOS))"

    with patch.object(ntds, "_query_database", wraps=ntds._query_database) as mock_fetch:
        records = list(ntds.query(query))
        assert len(records) == 55  # 54 groups + 1 user
        assert mock_fetch.call_count == 2


def test_db_fetch_calls_nested_OR(ntds: NTDS) -> None:
    query = (
        "(|(objectClass=container)(objectClass=organizationalUnit)"
        "(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))"
    )
    with patch.object(ntds, "_query_database", wraps=ntds._query_database) as mock_fetch:
        records = list(ntds.query(query))
        assert len(records) == 615
        assert mock_fetch.call_count == 5


def test_db_fetch_calls_nested_AND(ntds: NTDS) -> None:
    first_query = "(&(objectClass=user)(&(cn=ERNESTO_RAMOS)(sAMAccountName=ERNESTO_RAMOS)))"
    with (
        patch.object(ntds, "_query_database", wraps=ntds._query_database) as mock_fetch,
        patch.object(ntds, "_process_query", wraps=ntds._process_query) as mock_execute,
    ):
        records = list(ntds.query(first_query, optimize=False))
        # only the first part of the AND should be fetched, so objectClass=user
        assert len(records) == 1
        assert mock_fetch.call_count == 1
        assert mock_execute.call_count == 65
        first_run_queries = mock_execute.call_count

    second_query = "(&(&(cn=ERNESTO_RAMOS)(sAMAccountName=ERNESTO_RAMOS))(objectClass=user))"
    with (
        patch.object(ntds, "_query_database", wraps=ntds._query_database) as mock_fetch,
        patch.object(ntds, "_process_query", wraps=ntds._process_query) as mock_execute,
    ):
        records = list(ntds.query(second_query, optimize=False))
        assert len(records) == 1
        assert mock_fetch.call_count == 1
        assert mock_execute.call_count == 5
        second_run_queries = mock_execute.call_count
        assert second_run_queries < first_run_queries, "The second query should have fewer calls than the first one."

    # When we allow query optimization, the first query should be similar to the second one,
    # that was manuall optimized
    with (
        patch.object(ntds, "_query_database", wraps=ntds._query_database) as mock_fetch,
        patch.object(ntds, "_process_query", wraps=ntds._process_query) as mock_execute,
    ):
        records = list(ntds.query(first_query, optimize=True))
        assert len(records) == 1
        assert mock_fetch.call_count == 1
        assert mock_execute.call_count == 5
        assert mock_execute.call_count == second_run_queries


def test_db_fetch_calls_simple_wildcard(ntds: NTDS) -> None:
    query = "(&(sAMAccountName=Adm*)(objectCategory=person))"
    with patch.object(ntds, "_query_database", wraps=ntds._query_database) as mock_fetch:
        records = list(ntds.query(query))
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_db_fetch_calls_simple_wildcard_in_AND(ntds: NTDS) -> None:
    query = "(&(objectCategory=person)(sAMAccountName=Adm*))"
    with patch.object(ntds, "_query_database", wraps=ntds._query_database) as mock_fetch:
        records = list(ntds.query(query))
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_computers_api(ntds: NTDS) -> None:
    computer_records = sorted(ntds.computers(), key=lambda x: x.name)
    assert len(computer_records) == 15
    assert computer_records[0].name == "AZRWAPPS1000000"
    assert computer_records[1].name == "DC01"
    assert computer_records[13].name == "SECWWKS1000000"
    assert computer_records[14].name == "TSTWWEBS1000000"


def test_oid_string_to_attrtyp_with_oid_string(ntds: NTDS) -> None:
    """Test _oid_string_to_attrtyp with OID string format (line 59)"""
    # Find the person class entry using the new schema index
    person_entry = ntds.schema_index.lookup(ldap="person")
    result = ntds._oid_string_to_attrtyp(person_entry.oid)
    assert isinstance(result, int)
    assert result == person_entry.attrtyp


def test_oid_string_to_attrtyp_with_class_name(ntds: NTDS) -> None:
    """Test _oid_string_to_attrtyp with class name (normal case)"""
    result = ntds._oid_string_to_attrtyp("person")
    assert isinstance(result, int)
    person_entry = ntds.schema_index.lookup(ldap="person")
    assert result == person_entry.attrtyp


def test_query_database_keyerror_case(ntds: NTDS) -> None:
    """Test KeyError case when attribute not found in attribute_map"""
    # Test case: attribute not found in attribute_map - this will cause ValueError (improved error handling)
    filter_obj = SearchFilter.__new__(SearchFilter)
    filter_obj.attribute = "nonexistent_attribute"
    filter_obj.value = "test_value"
    filter_obj.operator = SearchFilter.parse("(test=value)").operator

    with pytest.raises(ValueError, match="Attribute 'nonexistent_attribute' not found in the NTDS database"):
        list(ntds._query_database(filter_obj))


def test_query_database_with_mock_errors(ntds: NTDS) -> None:
    """Test error conditions in _query_database using mocks"""
    filter_obj = SearchFilter.parse("(cn=ThisIsNotExistingInTheDB)")

    with (
        patch.object(ntds.data_table, "find_index", return_value=None),
        pytest.raises(ValueError, match=r"Index for attribute.*not found in the NTDS database"),
    ):
        list(ntds._query_database(filter_obj))


def test_record_to_object_coverage(ntds: NTDS) -> None:
    """Test _record_to_object method coverage"""
    # Get a real record from the database
    users = list(ntds.users())
    assert len(users) > 0

    # This ensures _record_to_object is called and covered
    user = users[0]
    assert hasattr(user, "sAMAccountName")
    assert isinstance(user, User)


def test_encode_value_coverage(ntds: NTDS) -> None:
    """Test _encode_value method with different scenarios"""
    # Test with a string attribute that doesn't have special encoding
    encoded = ntds._encode_value("cn", "test_value")
    assert encoded == "test_value"

    # Test with sAMAccountName (should be string type)
    encoded = ntds._encode_value("sAMAccountName", "testuser")
    assert encoded == "testuser"


def test_get_dnt_coverage(ntds: NTDS) -> None:
    """Test _get_DNT method coverage"""
    # Test with an attribute
    dnt = ntds._ldapDisplayName_to_DNT("cn")
    assert isinstance(dnt, int)
    assert dnt == 132

    # Test with a class
    dnt = ntds._ldapDisplayName_to_DNT("person")
    assert isinstance(dnt, int)
    assert dnt == 1554


def test_query_database_no_column_error(ntds: NTDS) -> None:
    """Test error case when attribute is not found in schema index"""
    # Test with a nonexistent attribute
    filter_obj = SearchFilter.parse("(nonexistent_attribute_test=test)")
    with pytest.raises(ValueError, match="Attribute 'nonexistent_attribute_test' not found in the NTDS database"):
        list(ntds._query_database(filter_obj))


def test_increment_last_char() -> None:
    """Test incrementing the last character of a string"""

    assert increment_last_char("test") == "tesu"
    assert increment_last_char("tesz") == "tet"
    assert increment_last_char("a") == "b"
    assert increment_last_char("z") == "za"
    assert increment_last_char("") == "a"


def test_write_sid(ntds: NTDS) -> None:
    """Test writing and reading SIDs"""
    sid_str = "S-1-5-21-1957882089-4252948412-2360614479-1134"
    sid_bytes = ntds._encode_value("objectSid", sid_str)
    assert sid_bytes == bytes.fromhex("010500000000000515000000e9e8b274bcd77efd4f1eb48c0000046e")
    sid_reconstructed = read_sid(sid_bytes, swap_last=True)
    assert sid_reconstructed == sid_str


def test_sid_lookup(ntds: NTDS) -> None:
    """Test SID lookup functionality"""
    sid_str = "S-1-5-21-1957882089-4252948412-2360614479-1134"
    user = next(ntds.lookup(objectSid=sid_str))
    assert isinstance(user, User)
    assert user.sAMAccountName == "beau.terham"


def test_dacl_specific_user(ntds: NTDS) -> None:
    """Test that DACLs can be retrieved from user objects"""
    computers = list(ntds.computers())
    # Get one sample computer
    esm = next(c for c in computers if c.name == "ESMWVIR1000000")
    assert isinstance(esm, Computer)

    # Checked using Active Directory User and Computers (ADUC) GUI for user RACHELLE_LYNN
    ace = next(ace for ace in esm.dacl.aces if next(ntds.lookup(objectSid=str(ace.sid))).name == "RACHELLE_LYNN")
    assert isinstance(ace, ACCESS_ALLOWED_ACE)
    assert ace.has_flag(AceFlag.CONTAINER_INHERIT_ACE)
    assert ace.has_flag(AceFlag.INHERITED_ACE)

    assert ace.mask.has_priv(AccessMaskFlag.WRITE_OWNER)
    assert ace.mask.has_priv(AccessMaskFlag.WRITE_DACL)
    assert ace.mask.has_priv(AccessMaskFlag.READ_CONTROL)
    assert ace.mask.has_priv(AccessMaskFlag.DELETE)
    assert ace.mask.has_priv(AccessMaskFlag.ADS_RIGHT_DS_CONTROL_ACCESS)
    assert ace.mask.has_priv(AccessMaskFlag.ADS_RIGHT_DS_CREATE_CHILD)
    assert ace.mask.has_priv(AccessMaskFlag.ADS_RIGHT_DS_DELETE_CHILD)
    assert ace.mask.has_priv(AccessMaskFlag.ADS_RIGHT_DS_READ_PROP)
    assert ace.mask.has_priv(AccessMaskFlag.ADS_RIGHT_DS_WRITE_PROP)
    assert ace.mask.has_priv(AccessMaskFlag.ADS_RIGHT_DS_SELF)


def test_format_guid() -> None:
    """Test the format_GUID function for correctness."""

    test_bytes = bytes.fromhex("6F414B9DFB178945A3641E40BC2A4AAB")
    expected_guid_str = "9D4B416F-17FB-4589-A364-1E40BC2A4AAB"

    result = format_GUID(test_bytes)
    assert result == expected_guid_str, f"Expected {expected_guid_str}, got {result}"
