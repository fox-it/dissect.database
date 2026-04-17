from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from dissect.database.ese.ntds.objects import Computer, Group, GroupPolicyContainer, Server, SubSchema, User
from dissect.database.ese.ntds.util import (
    SAMAccountType,
    SystemFlagAttribute,
    SystemFlagCrossRef,
    TrustAttribute,
    TrustDirection,
    TrustType,
    UserAccountControl,
)

if TYPE_CHECKING:
    from dissect.database.ese.ntds import NTDS


def test_dsa(goad: NTDS) -> None:
    """Test retrieval of the NTDS DSA object and its associated domain and features."""
    dsa = goad.db.dsa()
    assert dsa is not None
    assert dsa.domain() is not None
    assert dsa.domain().name == "sevenkingdoms"
    assert [f.name for f in dsa.features()] == ["Recycle Bin Feature"]


def test_dc(goad: NTDS) -> None:
    """Test retrieval of the domain controller objects and their associated computer and managedBy links."""
    dc = goad.db.dc()
    assert dc.name == "KINGSLANDING"
    assert dc.computer() is not None
    assert dc.computer().name == "KINGSLANDING"


def test_groups(goad: NTDS) -> None:
    groups = sorted(goad.groups(), key=lambda x: x.distinguished_name)

    assert len(groups) == 102
    assert isinstance(groups[0], Group)
    assert all(isinstance(x, Group) for x in groups)

    north_domain_admins = next(
        x for x in groups if x.distinguished_name == "CN=DOMAIN ADMINS,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL"
    )
    assert isinstance(north_domain_admins, Group)

    assert north_domain_admins.is_phantom
    with pytest.raises(ValueError, match="Operation not supported for phantom \\(non-local\\) objects"):
        list(north_domain_admins.members())

    domain_admins = next(
        x for x in groups if x.distinguished_name == "CN=DOMAIN ADMINS,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL"
    )
    assert isinstance(domain_admins, Group)
    assert sorted([x.sam_account_name for x in domain_admins.members()]) == [
        "Administrator",
        "cersei.lannister",
    ]


def test_servers(goad: NTDS) -> None:
    servers = sorted(goad.servers(), key=lambda x: x.name)
    assert len(servers) == 2
    assert isinstance(servers[0], Server)
    assert [x.name for x in servers] == [
        "KINGSLANDING",
        "WINTERFELL",
    ]


def test_users(goad: NTDS) -> None:
    users: list[User] = sorted(goad.users(), key=lambda x: x.distinguished_name)
    assert len(users) == 33
    assert isinstance(users[0], User)
    assert [x.distinguished_name for x in users] == [
        "CN=ADMINISTRATOR,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=ADMINISTRATOR,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=ARYA.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=BRANDON.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=CATELYN.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=CERSEI.LANNISTER,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=EDDARD.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=ESSOS$,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=GUEST,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=GUEST,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=HODOR,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=JAIME.LANNISTER,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=JEOR.MORMONT,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=JOFFREY.BARATHEON,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=JON.SNOW,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=KRBTGT,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=KRBTGT,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=LORD.VARYS,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=MAESTER.PYCELLE,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=NORTH$,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=PETYER.BAELISH,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=RENLY.BARATHEON,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=RICKON.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=ROBB.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=SAMWELL.TARLY,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=SANSA.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=SEVENKINGDOMS$,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=SQL_SVC,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=STANNIS.BARATHEON,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=TYRON.LANNISTER,OU=WESTERLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=TYWIN.LANNISTER,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=VAGRANT,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=VAGRANT,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
    ]

    assert users[3].distinguished_name == "CN=BRANDON.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL"
    assert users[3].sam_account_type == SAMAccountType.SAM_USER_OBJECT
    assert users[3].cn == "brandon.stark"
    assert users[3].city == "Winterfell"

    assert users[4].distinguished_name == "CN=CATELYN.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL"

    assert users[-1].displayName == "Vagrant"

    assert users[12].objectSid == "S-1-5-21-459184689-3312531310-188885708-1120"
    assert users[12].distinguished_name == "CN=JEOR.MORMONT,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL"
    assert users[12].description == ["Jeor Mormont"]

    assert users[10].description == ["Brainless Giant"]


def test_computers(goad: NTDS) -> None:
    computers: list[Computer] = sorted(goad.computers(), key=lambda x: x.name)
    assert len(computers) == 3
    assert computers[0].name == "CASTELBLACK"
    assert computers[0].sam_account_type == SAMAccountType.SAM_MACHINE_ACCOUNT
    assert computers[1].name == "KINGSLANDING"
    assert computers[2].name == "WINTERFELL"

    assert [g.name for g in computers[1].groups()] == [
        "Cert Publishers",
        "Pre-Windows 2000 Compatible Access",
        "Domain Controllers",
    ]


def test_group_membership(goad: NTDS) -> None:
    # Prepare objects
    domain_admins = next(goad.search(sAMAccountName="Domain Admins"))
    domain_users = next(goad.search(sAMAccountName="Domain Users"))
    assert isinstance(domain_admins, Group)
    assert isinstance(domain_users, Group)

    shame = next(goad.search(sAMAccountName="cersei.lannister"))
    assert isinstance(shame, User)

    # Test membership of Cersei Lannister
    assert len(list(shame.groups())) == 6
    assert sorted([g.sam_account_name for g in shame.groups()]) == [
        "Administrators",
        "Baratheon",
        "Domain Admins",
        "Domain Users",
        "Lannister",
        "Small Council",
    ]
    assert shame.is_member_of(domain_admins)
    assert shame.is_member_of(domain_users)

    # Check the members of the Domain Admins group
    assert len(list(domain_admins.members())) == 2
    assert sorted([u.sAMAccountName for u in domain_admins.members()]) == [
        "Administrator",
        "cersei.lannister",
    ]
    assert domain_admins.is_member(shame)

    # Check the members of the Domain Users group
    assert len(list(domain_users.members())) == 31  # All users except Guest
    assert sorted([u.dn for u in domain_users.members()]) == [
        "CN=ADMINISTRATOR,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=ADMINISTRATOR,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=ARYA.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=BRANDON.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=CATELYN.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=CERSEI.LANNISTER,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=EDDARD.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=ESSOS$,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=HODOR,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=JAIME.LANNISTER,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=JEOR.MORMONT,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=JOFFREY.BARATHEON,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=JON.SNOW,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=KRBTGT,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=KRBTGT,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=LORD.VARYS,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=MAESTER.PYCELLE,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=NORTH$,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=PETYER.BAELISH,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=RENLY.BARATHEON,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=RICKON.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=ROBB.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=SAMWELL.TARLY,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=SANSA.STARK,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=SEVENKINGDOMS$,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=SQL_SVC,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=STANNIS.BARATHEON,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=TYRON.LANNISTER,OU=WESTERLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=TYWIN.LANNISTER,OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=VAGRANT,CN=USERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN=VAGRANT,CN=USERS,DC=SEVENKINGDOMS,DC=LOCAL",
    ]
    assert domain_users.is_member(shame)
    assert not domain_users.is_member(next(goad.search(sAMAccountName="Guest")))


def test_managed_by(goad: NTDS) -> None:
    lannister = next(g for g in goad.groups() if g.sam_account_name == "Lannister")
    managed_by = list(lannister.managed_by())

    assert len(managed_by) == 1
    assert managed_by[0].sam_account_name == "tywin.lannister"
    assert next(iter(managed_by[0].managed_objects())).dn == lannister.dn


def test_query_specific_users(goad: NTDS) -> None:
    specific_records = sorted(
        goad.query("(&(objectClass=user)(|(cn=jon.snow)(cn=hodor)))"), key=lambda x: x.sAMAccountName
    )
    assert len(specific_records) == 2
    assert specific_records[0].sam_account_name == "hodor"
    assert specific_records[1].sam_account_name == "jon.snow"


def test_record_to_object_coverage(goad: NTDS) -> None:
    """Test _record_to_object method coverage."""
    # Get a real record from the database
    users = list(goad.users())
    assert len(users) == 33

    user = users[0]
    assert hasattr(user, "sAMAccountName")
    assert isinstance(user, User)


def test_sid_lookup(goad: NTDS) -> None:
    """Test SID lookup functionality."""
    sid_str = "S-1-5-21-459184689-3312531310-188885708-1120"
    user = next(goad.search(objectSid=sid_str))
    assert isinstance(user, User)
    assert user.sam_account_name == "jeor.mormont"


def test_object_repr(goad: NTDS) -> None:
    """Test the ``__repr__`` methods of User, Computer, Object and Group classes."""
    object = next(goad.search(sAMAccountName="Administrator"))
    assert isinstance(object, User)
    assert repr(object) == "<User name='Administrator' sam_account_name='Administrator' is_machine_account=False>"

    object = next(goad.search(sAMAccountName="KINGSL*"))
    assert isinstance(object, Computer)
    assert repr(object) == "<Computer name='KINGSLANDING'>"

    object = next(goad.search(sAMAccountName="Domain Admins"))
    assert isinstance(object, Group)
    assert repr(object) == "<Group name='Domain Admins'>"

    object = next(goad.search(objectCategory="subSchema"))
    assert isinstance(object, SubSchema)
    assert repr(object) == "<SubSchema name='Aggregate'>"

    object = next(goad.search(sAMAccountName="eddard.stark"))
    assert isinstance(object, User)
    assert (
        repr(object) == "<User name='eddard.stark' sam_account_name='eddard.stark' is_machine_account=False (phantom)>"
    )

    object = next(goad.search(sAMAccountName="robert.baratheon"))
    assert isinstance(object, User)
    assert (
        repr(object)
        == "<User name='robert.baratheon\\nDEL:dbe3c0f1-88dc-4355-b2b0-78499dbd4522' sam_account_name='robert.baratheon' is_machine_account=False (deleted)>"  # noqa: E501
    )


def test_object_as_dict(goad: NTDS) -> None:
    """Test the as_dict method of the Object class."""
    user = next(goad.search(sAMAccountName="jon.snow"))
    assert isinstance(user, User)

    user_dict = user.as_dict()
    assert isinstance(user_dict, dict)
    assert user_dict["sAMAccountName"] == "jon.snow"
    assert user_dict["cn"] == "jon.snow"
    assert user_dict["l"] == "Castel Black"
    assert user_dict["objectSid"] == "S-1-5-21-459184689-3312531310-188885708-1118"

    # Specifically test that the decoders are applied when using as_dict
    assert (
        user_dict["userAccountControl"]
        == UserAccountControl.NORMAL_ACCOUNT
        | UserAccountControl.DONT_EXPIRE_PASSWORD
        | UserAccountControl.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
    )


def test_all_memberships(large: NTDS) -> None:
    """Test all memberships of all users."""
    for user in large.users():
        # Just iterate all memberships to see if any errors occur
        list(user.groups())


def test_group_policies(goad: NTDS) -> None:
    """Test retrieval of group policies."""
    gpos: list[GroupPolicyContainer] = sorted(goad.group_policies(), key=lambda x: x.distinguished_name)
    assert len(gpos) == 5
    assert isinstance(gpos[0], GroupPolicyContainer)
    assert [x.distinguished_name for x in gpos] == [
        "CN={117DC7AC-6832-4B21-ABFD-C56679BC3626},CN=POLICIES,CN=SYSTEM,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=POLICIES,CN=SYSTEM,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=POLICIES,CN=SYSTEM,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=POLICIES,CN=SYSTEM,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "CN={6AC1786C-016F-11D2-945F-00C04FB984F9},CN=POLICIES,CN=SYSTEM,DC=SEVENKINGDOMS,DC=LOCAL",
    ]


def test_backup_keys(goad: NTDS) -> None:
    """Test retrieval of DPAPI backup keys."""
    with pytest.raises(ValueError, match="PEK must be unlocked to retrieve backup keys"):
        list(goad.backup_keys())

    goad.pek.unlock(bytes.fromhex("079f95655b66f16deb28aa1ab3a81eb0"))

    keys = list(goad.backup_keys())
    assert len(keys) == 2
    assert keys[0].guid == UUID("dbea00d0-005f-4233-b140-41a9961da100")
    assert keys[0].version == 1
    assert hashlib.sha256(keys[0].key).hexdigest() == "bae7b058f277922b75d63d9803b85fca40a95a3cc9d47c0ef0a644a203009562"

    assert keys[1].guid == UUID("b7d3c47b-2efe-4cad-b37a-bb2f8b18bd87")
    assert keys[1].version == 2  # Current key version
    assert (
        hashlib.sha256(keys[1].private_key).hexdigest()
        == "e7317dfe5f962121afead04e0dbb4249aa395ef281e2332f6179f940b54f202f"
    )
    assert (
        hashlib.sha256(keys[1].public_key).hexdigest()
        == "398fef9281677096b18785d0ad000251d41f76b82e28687718d6a9812ddaca8a"
    )


def test_domains(goad: NTDS) -> None:
    """Test retrieval of domain objects."""
    domains = sorted(goad.domains(), key=lambda x: x.distinguished_name)
    assert len(domains) == 5
    assert [x.distinguished_name for x in domains] == [
        "DC=DOMAINDNSZONES,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "DC=DOMAINDNSZONES,DC=SEVENKINGDOMS,DC=LOCAL",
        "DC=FORESTDNSZONES,DC=SEVENKINGDOMS,DC=LOCAL",
        "DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "DC=SEVENKINGDOMS,DC=LOCAL",
    ]

    domain = domains[-1]
    assert domain.behavior_version == 7


def test_trusts(goad: NTDS) -> None:
    """Test retrieval of trust objects."""
    trusts = sorted(goad.trusts(), key=lambda x: x.distinguished_name)
    assert len(trusts) == 3
    assert trusts[0].distinguished_name == "CN=ESSOS.LOCAL,CN=SYSTEM,DC=SEVENKINGDOMS,DC=LOCAL"
    assert trusts[0].trust_type == TrustType.UPLEVEL
    assert trusts[0].trust_direction == TrustDirection.BIDIRECTIONAL
    assert trusts[0].trust_attributes == TrustAttribute.FOREST_TRANSITIVE | TrustAttribute.TREAT_AS_EXTERNAL
    assert trusts[0].trust_partner == "essos.local"
    assert trusts[0].security_identifier == "S-1-5-21-1398578290-1256418943-189470967"


def test_organizational_units(goad: NTDS) -> None:
    ous = sorted(goad.organizational_units(), key=lambda x: x.distinguished_name)
    assert len(ous) == 10
    assert [x.distinguished_name for x in ous] == [
        "OU=CROWNLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=DOMAIN CONTROLLERS,DC=NORTH,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=DOMAIN CONTROLLERS,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=DORNE,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=IRONISLANDS\nDEL:D58E6F7A-DA60-40AE-88C1-27A4FCEE1190,CN=DELETED OBJECTS,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=REACH,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=RIVERLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=STORMLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=VALE,DC=SEVENKINGDOMS,DC=LOCAL",
        "OU=WESTERLANDS,DC=SEVENKINGDOMS,DC=LOCAL",
    ]

    dc_ou = ous[2]
    assert (
        dc_ou.gp_link
        == "[LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=sevenkingdoms,DC=local;0]"
    )
    assert dc_ou.gp_options is None


def test_system_flags(goad: NTDS) -> None:
    """Test the difference between system flags on attributeSchema and crossRef objects."""
    crossref = next(goad.search(objectClass="crossRef"))
    assert crossref.system_flags == SystemFlagCrossRef.CR_NTDS_NC

    attribute = next(goad.search(objectClass="attributeSchema", name="ANR"))
    assert (
        attribute.system_flags
        == SystemFlagAttribute.ATTR_IS_CONSTRUCTED
        | SystemFlagAttribute.SCHEMA_BASE_OBJECT
        | SystemFlagAttribute.DOMAIN_DISALLOW_RENAME
    )


def test_fve_recovery_information(fve: NTDS) -> None:
    """Test retrieval of BitLocker recovery information."""
    computer = next(c for c in fve.computers() if c.name == "WIN11")
    assert isinstance(computer, Computer)

    recovery_info = list(computer.fve_recovery_information())
    assert len(recovery_info) == 1
    assert recovery_info[0].volume_guid == UUID("616127c1-403a-4bdf-9213-42c285cf9ee7")
    assert recovery_info[0].recovery_guid == UUID("1d3184e4-ff3f-44f8-9255-32d1728f6172")
    assert recovery_info[0].recovery_password == "197307-494857-485111-648725-619432-662057-360844-079310"
    assert recovery_info[0].key_package == bytes.fromhex(
        "d40100000100000030000000d4010000c12761613a40df4b921342c285cf9ee7"
        "0100000000000000a0bad003caa5dc015000030005000100a039ebd4c8a5dc01"
        "090000003a621f05e8ca419a50af679b12eef8b0dba5cef0249ab9a509164767"
        "2ff5d3ea058671c43643fbc6f503f5fb966f6e61acda9b5d44ad4730ca200fe9"
        "3c01020008000100e484311d3ffff844925532d1728f61721040cdd6c8a5dc01"
        "00000008ac0000000300010000100000b351f88395b15fc67a7bcbf9132ba131"
        "4000120005000100a039ebd4c8a5dc0105000000373c16060ab99c0619679931"
        "1b2f3cfccb4ca31f6ae9dbd41c5c67a605674db0b96512e4184c815bc4d38ad1"
        "5000130005000100a039ebd4c8a5dc01060000002ee39c79df7a782cead1fb91"
        "73b073b5d512e054c9700c69076cf7a374e066b13b56fec03e12fa623acaaab0"
        "702141d694cb726163f5b4da002a5cc85000000005000100a039ebd4c8a5dc01"
        "07000000df655b5d65e9a8d969c990083a846ca8c34708334d4710b5fb532887"
        "a9689ff9e1191521f5abe368cf5476e82cd2ecad01ba90b6065cd7e87447a8ad"
        "1c00000015000100f06475dec8a5dc01f06475dec8a5dc011000020018000f00"
        "0f00010000400e04000000000020000000000000"
    )

    assert recovery_info[0].computer() == computer
