from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.database.ese.ntds.objects import Computer, Group, GroupPolicyContainer, Server, SubSchema, User
from dissect.database.ese.ntds.util import SAMAccountType

if TYPE_CHECKING:
    from dissect.database.ese.ntds import NTDS


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


def test_all_memberships(large: NTDS) -> None:
    """Test all memberships of all users."""
    for user in large.users():
        # Just iterate all memberships to see if any errors occur
        list(user.groups())


def test_group_policies(goad: NTDS) -> None:
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
