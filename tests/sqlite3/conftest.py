from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from tests._util import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def sqlite_db() -> Path:
    return absolute_path("_data/sqlite3/test.sqlite")


@pytest.fixture
def sqlite_wal() -> Path:
    return absolute_path("_data/sqlite3/test.sqlite-wal")


@pytest.fixture
def empty_db() -> Path:
    return absolute_path("_data/sqlite3/empty.sqlite")
