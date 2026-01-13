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
        - syskey: 079f95655b66f16deb28aa1ab3a81eb0
    """
    for fh in open_file_gz("_data/ese/ntds/goad/ntds.dit.gz"):
        yield NTDS(fh)


@pytest.fixture(scope="module")
def adam() -> Iterator[NTDS]:
    """AD LDS NTDS.dit file."""
    for fh in open_file_gz("_data/ese/ntds/adam/adamntds.dit.gz"):
        yield NTDS(fh)


@pytest.fixture(scope="module")
def large() -> Iterator[NTDS]:
    """Large NTDS file for performance testing.

    Notes:
        - syskey: d9cf57f38072d3153f42524516e7ac3d
    """
    for fh in open_file_gz("_data/ese/ntds/large/ntds.dit.gz"):
        # Keep this one decompressed in memory (~110MB) as it is a large file,
        # and performing I/O through the gzip layer is too slow
        yield NTDS(BytesIO(fh.read()))
