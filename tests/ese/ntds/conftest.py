from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.database.ese.ntds.ntds import NTDS
from tests._util import open_file_gz

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(scope="module")
def goad() -> Iterator[NTDS]:
    """NTDS file from a GOAD lab environment.

    Notes:
        - robert.baratheon was deleted BEFORE the recycle bin was enabled
        - IronIslands OA was deleted AFTER the recycle bin was enabled
        - stannis.baratheon has password history and is disabled
        - robb.stark has password history
    """
    for fh in open_file_gz("_data/ese/ntds/goad/ntds.dit.gz"):
        yield NTDS(fh)


@pytest.fixture(scope="module")
def large() -> Iterator[NTDS]:
    for fh in open_file_gz("_data/ese/ntds/large/ntds.dit.gz"):
        # Keep this one decompressed in memory (~110MB) as it is a large file,
        # and performing I/O through the gzip layer is too slow
        yield NTDS(BytesIO(fh.read()))
