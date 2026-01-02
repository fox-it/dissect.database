from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.ntds.sd import ACCESS_MASK

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS


def test_dacl_specific_user(goad: NTDS) -> None:
    """Test that DACLs can be retrieved from user objects."""
    jaime = next(u for u in goad.users() if u.name == "jaime.lannister")
    joffrey = next(u for u in goad.users() if u.name == "joffrey.baratheon")

    ace = next(ace for ace in joffrey.sd.dacl.ace if ace.sid == jaime.sid)
    assert ACCESS_MASK.READ_CONTROL in ace.mask
    assert ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP in ace.mask
    assert ACCESS_MASK.ADS_RIGHT_DS_SELF in ace.mask
