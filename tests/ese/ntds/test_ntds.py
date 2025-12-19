from __future__ import annotations

from dissect.database.ese.ntds import NTDS, Computer, Group, User
from dissect.database.ese.ntds.objects import Server
from dissect.database.ese.ntds.objects.subschema import SubSchema


def test_groups(ntds_small: NTDS) -> None:
    groups = sorted(ntds_small.groups(), key=lambda x: x.sAMAccountName)
    assert len(groups) == 54
    assert isinstance(groups[0], Group)
    assert all(isinstance(x, Group) for x in groups)

    domain_admins = next(x for x in groups if x.sAMAccountName == "Domain Admins")
    assert isinstance(domain_admins, Group)
    assert sorted([x.sAMAccountName for x in domain_admins.members()]) == [
        "Administrator",
        "ERNESTO_RAMOS",
        "Guest",
        "OTTO_STEELE",
    ]


def test_servers(ntds_small: NTDS) -> None:
    servers = sorted(ntds_small.servers(), key=lambda x: x.name)
    assert len(servers) == 1
    assert isinstance(servers[0], Server)
    assert [x.name for x in servers] == [
        "DC01",
    ]


def test_users(ntds_small: NTDS) -> None:
    user_records = sorted(ntds_small.users(), key=lambda x: x.sAMAccountName)
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
    assert user_records[3].distinguished_name == "CN=ERNESTO_RAMOS,OU=TST,OU=PEOPLE,DC=DISSECT,DC=LOCAL"
    assert user_records[3].cn == "ERNESTO_RAMOS"
    assert user_records[4].distinguished_name == "CN=FORREST_NIXON,OU=GROUPS,OU=AZR,OU=TIER 1,DC=DISSECT,DC=LOCAL"
    assert user_records[12].displayName == "Beau ter Ham"
    assert user_records[12].objectSid == "S-1-5-21-1957882089-4252948412-2360614479-1134"
    assert user_records[12].distinguished_name == "CN=BEAU TER HAM,OU=TST,OU=PEOPLE,DC=DISSECT,DC=LOCAL"
    assert user_records[12].description == ["My password might be related to the summer"]
    assert user_records[13].displayName == "Henk de Vries"
    assert user_records[13].mail == "henk@henk.com"
    assert user_records[13].description == ["Da real Dissect MVP"]


def test_computers(ntds_small: NTDS) -> None:
    computer_records = sorted(ntds_small.computers(), key=lambda x: x.name)
    assert len(computer_records) == 15
    assert computer_records[0].name == "AZRWAPPS1000000"
    assert computer_records[1].name == "DC01"
    assert computer_records[13].name == "SECWWKS1000000"
    assert computer_records[14].name == "TSTWWEBS1000000"

    assert len(list(computer_records[1].groups())) == 1


def test_group_membership(ntds_small: NTDS) -> None:
    # Prepare objects
    domain_admins = next(ntds_small.lookup(sAMAccountName="Domain Admins"))
    domain_users = next(ntds_small.lookup(sAMAccountName="Domain Users"))
    assert isinstance(domain_admins, Group)
    assert isinstance(domain_users, Group)

    ernesto = next(ntds_small.lookup(sAMAccountName="ERNESTO_RAMOS"))
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
    assert not domain_users.is_member(next(ntds_small.lookup(sAMAccountName="Guest")))


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
    user = next(ntds_small.lookup(objectSid=sid_str))
    assert isinstance(user, User)
    assert user.sAMAccountName == "beau.terham"


def test_object_repr(ntds_small: NTDS) -> None:
    """Test the __repr__ methods of User, Computer, Object and Group classes."""
    user = next(ntds_small.lookup(sAMAccountName="Administrator"))
    assert isinstance(user, User)
    assert repr(user) == "<User name='Administrator' sAMAccountName='Administrator' is_machine_account=False>"

    computer = next(ntds_small.lookup(sAMAccountName="DC*"))
    assert isinstance(computer, Computer)
    assert repr(computer) == "<Computer name='DC01'>"

    group = next(ntds_small.lookup(sAMAccountName="Domain Admins"))
    assert isinstance(group, Group)
    assert repr(group) == "<Group name='Domain Admins'>"

    object = next(ntds_small.lookup(objectCategory="subSchema"))
    assert isinstance(object, SubSchema)
    assert repr(object) == "<SubSchema name='Aggregate'>"
