from __future__ import annotations

from typing import TYPE_CHECKING, BinaryIO

import pytest

from tests._util import open_file

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def sqlite_db() -> Iterator[BinaryIO]:
    yield from open_file("_data/sqlite3/test.sqlite")


@pytest.fixture
def empty_db() -> Iterator[BinaryIO]:
    yield from open_file("_data/sqlite3/empty.sqlite")
