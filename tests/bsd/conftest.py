from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import pytest

from tests._util import open_file_gz

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def btree_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bsd/btree.db.gz")


@pytest.fixture
def hash_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bsd/hash.db.gz")


@pytest.fixture
def recno_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bsd/recno.db.gz")


@pytest.fixture
def rpm_packages() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/bsd/rpm/Packages.gz")
