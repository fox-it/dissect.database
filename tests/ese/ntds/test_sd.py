from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.object import Computer
from dissect.database.ese.ntds.sd import ACCESS_ALLOWED_ACE, AccessMaskFlag, AceFlag

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS


def test_dacl_specific_user(ntds_small: NTDS) -> None:
    """Test that DACLs can be retrieved from user objects."""
    computers = list(ntds_small.computers())
    # Get one sample computer
    esm = next(c for c in computers if c.name == "ESMWVIR1000000")
    assert isinstance(esm, Computer)

    # Checked using Active Directory User and Computers (ADUC) GUI for user RACHELLE_LYNN
    ace = next(ace for ace in esm.dacl.aces if next(ntds_small.lookup(objectSid=str(ace.sid))).name == "RACHELLE_LYNN")
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
