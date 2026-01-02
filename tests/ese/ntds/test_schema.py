from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS


def test_lookup_multiple_keys(goad: NTDS) -> None:
    """Test error handling in schema index lookup with multiple keys."""
    with pytest.raises(ValueError, match="Exactly one lookup key must be provided"):
        goad.db.data.schema.lookup(name="person", attrtyp=1234)

    goad.db.data.schema.lookup(name="person")  # This should work without error
