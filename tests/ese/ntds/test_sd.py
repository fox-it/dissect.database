from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.sd import ACCESS_MASK, ACE_FLAGS

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS


def test_dacl_specific_user(ntds_small: NTDS) -> None:
    """Test that DACLs can be retrieved from user objects."""
    computers = list(ntds_small.computers())
    # Get one sample computer
    esm = next(c for c in computers if c.name == "ESMWVIR1000000")
    # And one sample user
    user = next(u for u in ntds_small.users() if u.name == "RACHELLE_LYNN")

    # Checked using Active Directory User and Computers (ADUC) GUI for user RACHELLE_LYNN
    ace = next(ace for ace in esm.sd.dacl.ace if ace.sid == user.sid)
    assert ACE_FLAGS.CONTAINER_INHERIT_ACE in ace.flags
    assert ACE_FLAGS.INHERITED_ACE in ace.flags

    assert ACCESS_MASK.WRITE_OWNER in ace.mask
    assert ACCESS_MASK.WRITE_DACL in ace.mask
    assert ACCESS_MASK.READ_CONTROL in ace.mask
    assert ACCESS_MASK.DELETE in ace.mask
    assert ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS in ace.mask
    assert ACCESS_MASK.ADS_RIGHT_DS_CREATE_CHILD in ace.mask
    assert ACCESS_MASK.ADS_RIGHT_DS_DELETE_CHILD in ace.mask
    assert ACCESS_MASK.ADS_RIGHT_DS_READ_PROP in ace.mask
    assert ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP in ace.mask
    assert ACCESS_MASK.ADS_RIGHT_DS_SELF in ace.mask
