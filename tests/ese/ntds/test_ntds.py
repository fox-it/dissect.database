from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.objects import Computer, Group, Server, SubSchema, User

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
    # TODO this doesn't work yet?
    assert sorted([x.sam_account_name for x in north_domain_admins.members()]) == [
        "Administrator",
        "eddard.stark",
    ]

    domain_admins = next(x for x in groups if x.distinguished_name == "CN=DOMAIN ADMINS,CN=USERS,DC=DISSECT,DC=LOCAL")
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
    assert computers[1].name == "KINGSLANDING"
    assert computers[2].name == "WINTERFELL"

    assert [g.name for g in computers[1].groups()] == [
        "Cert Publishers",
        "Pre-Windows 2000 Compatible Access",
        "Domain Controllers",
    ]


def test_group_membership(ntds_small: NTDS) -> None:
    # Prepare objects
    domain_admins = next(ntds_small.search(sAMAccountName="Domain Admins"))
    domain_users = next(ntds_small.search(sAMAccountName="Domain Users"))
    assert isinstance(domain_admins, Group)
    assert isinstance(domain_users, Group)

    ernesto = next(ntds_small.search(sAMAccountName="ERNESTO_RAMOS"))
    assert isinstance(ernesto, User)

    # Test membership of ERNESTO_RAMOS
    assert len(list(ernesto.groups())) == 11
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
        "Users",
    ]
    assert ernesto.is_member_of(domain_admins)
    assert ernesto.is_member_of(domain_users)

    # Test managed objects by ERNESTO_RAMOS
    assert len(list(ernesto.managed_objects())) == 1
    assert isinstance(next(ernesto.managed_objects()), Computer)
    assert next(next(ernesto.managed_objects()).managed_by()).dnt == ernesto.dnt

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
    assert not domain_users.is_member(next(ntds_small.search(sAMAccountName="Guest")))


def test_query_specific_users(ntds_small: NTDS) -> None:
    specific_records = sorted(
        ntds_small.query("(&(objectClass=user)(|(cn=Henk de Vries)(cn=Administrator)))"), key=lambda x: x.sAMAccountName
    )
    assert len(specific_records) == 2
    assert specific_records[0].sAMAccountName == "Administrator"
    assert specific_records[1].sAMAccountName == "henk.devries"


def test_record_to_object_coverage(ntds_small: NTDS) -> None:
    """Test _record_to_object method coverage."""
    # Get a real record from the database
    users = list(ntds_small.users())
    assert len(users) == 15

    user = users[0]
    assert hasattr(user, "sAMAccountName")
    assert isinstance(user, User)


def test_sid_lookup(ntds_small: NTDS) -> None:
    """Test SID lookup functionality."""
    sid_str = "S-1-5-21-1957882089-4252948412-2360614479-1134"
    user = next(ntds_small.search(objectSid=sid_str))
    assert isinstance(user, User)
    assert user.sAMAccountName == "beau.terham"


def test_object_repr(ntds_small: NTDS) -> None:
    """Test the __repr__ methods of User, Computer, Object and Group classes."""
    user = next(ntds_small.search(sAMAccountName="Administrator"))
    assert isinstance(user, User)
    assert repr(user) == "<User name='Administrator' sAMAccountName='Administrator' is_machine_account=False>"

    computer = next(ntds_small.search(sAMAccountName="DC*"))
    assert isinstance(computer, Computer)
    assert repr(computer) == "<Computer name='DC01'>"

    group = next(ntds_small.search(sAMAccountName="Domain Admins"))
    assert isinstance(group, Group)
    assert repr(group) == "<Group name='Domain Admins'>"

    object = next(ntds_small.search(objectCategory="subSchema"))
    assert isinstance(object, SubSchema)
    assert repr(object) == "<SubSchema name='Aggregate'>"
