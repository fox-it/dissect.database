from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.database.ese.ntds.ntds import NTDS
from tests._util import open_file_gz

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(scope="module")
def ntds_small() -> Iterator[NTDS]:
    for fh in open_file_gz("_data/ese/ntds/small/NTDS.dit.gz"):
        yield NTDS(fh)


@pytest.fixture(scope="module")
def ntds_large() -> Iterator[NTDS]:
    for fh in open_file_gz("_data/ese/ntds/large/NTDS.dit.gz"):
        # Keep this one decompressed in memory (~110MB) as it is a large file,
        # and performing I/O through the gzip layer is too slow
        yield NTDS(BytesIO(fh.read()))


@pytest.fixture
def system_hive() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/ntds/SYSTEM.gz")
