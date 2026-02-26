from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3 import sqlite3
from tests._util import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("db_as_path"),
    [pytest.param(True, id="db_as_path"), pytest.param(False, id="db_as_fh")],
)
@pytest.mark.parametrize(
    ("wal_as_path"),
    [pytest.param(True, id="wal_as_path"), pytest.param(False, id="wal_as_fh")],
)
def test_sqlite_wal(sqlite_db: Path, sqlite_wal: Path, db_as_path: bool, wal_as_path: bool) -> None:
    db = sqlite3.SQLite3(
        sqlite_db if db_as_path else sqlite_db.open("rb"),
        sqlite_wal if wal_as_path else sqlite_wal.open("rb"),
        checkpoint=1,
    )
    _assert_checkpoint_1(db)

    db.close()

    db = sqlite3.SQLite3(
        sqlite_db if db_as_path else sqlite_db.open("rb"),
        sqlite_wal if wal_as_path else sqlite_wal.open("rb"),
        checkpoint=2,
    )
    _assert_checkpoint_2(db)

    db.close()

    db = sqlite3.SQLite3(
        sqlite_db if db_as_path else sqlite_db.open("rb"),
        sqlite_wal if wal_as_path else sqlite_wal.open("rb"),
        checkpoint=3,
    )
    _assert_checkpoint_3(db)

    db.close()


def _assert_checkpoint_1(s: sqlite3.SQLite3) -> None:
    # After the first checkpoint the "after checkpoint" entries are present
    table = next(iter(s.tables()))

    rows = list(table.rows())
    assert len(rows) == 9

    assert rows[0].id == 1
    assert rows[0].name == "testing"
    assert rows[0].value == 1337
    assert rows[1].id == 2
    assert rows[1].name == "omg"
    assert rows[1].value == 7331
    assert rows[2].id == 3
    assert rows[2].name == "A" * 4100
    assert rows[2].value == 4100
    assert rows[3].id == 4
    assert rows[3].name == "B" * 4100
    assert rows[3].value == 4100
    assert rows[4].id == 5
    assert rows[4].name == "negative"
    assert rows[4].value == -11644473429
    assert rows[5].id == 6
    assert rows[5].name == "after checkpoint"
    assert rows[5].value == 42
    assert rows[6].id == 7
    assert rows[6].name == "after checkpoint"
    assert rows[6].value == 43
    assert rows[7].id == 8
    assert rows[7].name == "after checkpoint"
    assert rows[7].value == 44
    assert rows[8].id == 9
    assert rows[8].name == "after checkpoint"
    assert rows[8].value == 45


def _assert_checkpoint_2(s: sqlite3.SQLite3) -> None:
    # After the second checkpoint two more entries are present ("second checkpoint")
    table = next(iter(s.tables()))

    rows = list(table.rows())
    assert len(rows) == 11

    assert rows[0].id == 1
    assert rows[0].name == "testing"
    assert rows[0].value == 1337
    assert rows[1].id == 2
    assert rows[1].name == "omg"
    assert rows[1].value == 7331
    assert rows[2].id == 3
    assert rows[2].name == "A" * 4100
    assert rows[2].value == 4100
    assert rows[3].id == 4
    assert rows[3].name == "B" * 4100
    assert rows[3].value == 4100
    assert rows[4].id == 5
    assert rows[4].name == "negative"
    assert rows[4].value == -11644473429
    assert rows[5].id == 6
    assert rows[5].name == "after checkpoint"
    assert rows[5].value == 42
    assert rows[6].id == 7
    assert rows[6].name == "after checkpoint"
    assert rows[6].value == 43
    assert rows[7].id == 8
    assert rows[7].name == "after checkpoint"
    assert rows[7].value == 44
    assert rows[8].id == 9
    assert rows[8].name == "after checkpoint"
    assert rows[8].value == 45
    assert rows[9].id == 10
    assert rows[9].name == "second checkpoint"
    assert rows[9].value == 100
    assert rows[10].id == 11
    assert rows[10].name == "second checkpoint"
    assert rows[10].value == 101


def _assert_checkpoint_3(s: sqlite3.SQLite3) -> None:
    # After the third checkpoint the deletion and update of one "after checkpoint" are reflected
    table = next(iter(s.tables()))
    rows = list(table.rows())

    assert len(rows) == 10

    assert rows[0].id == 1
    assert rows[0].name == "testing"
    assert rows[0].value == 1337
    assert rows[1].id == 2
    assert rows[1].name == "omg"
    assert rows[1].value == 7331
    assert rows[2].id == 3
    assert rows[2].name == "A" * 4100
    assert rows[2].value == 4100
    assert rows[3].id == 4
    assert rows[3].name == "B" * 4100
    assert rows[3].value == 4100
    assert rows[4].id == 5
    assert rows[4].name == "negative"
    assert rows[4].value == -11644473429
    assert rows[5].id == 6
    assert rows[5].name == "after checkpoint"
    assert rows[5].value == 42
    assert rows[6].id == 8
    assert rows[6].name == "after checkpoint"
    assert rows[6].value == 44
    assert rows[7].id == 9
    assert rows[7].name == "wow"
    assert rows[7].value == 1234
    assert rows[8].id == 10
    assert rows[8].name == "second checkpoint"
    assert rows[8].value == 100
    assert rows[9].id == 11
    assert rows[9].name == "second checkpoint"
    assert rows[9].value == 101


def test_wal_page_count() -> None:
    """Test if we count the page numbers in the SQLite3 and WAL correctly.

    Test data generated using:

        $ sqlite3 tests/_data/sqlite3/page_count.db
        SQLite version 3.45.1 2024-01-30 16:01:20
        Enter ".help" for usage hints.
        sqlite> PRAGMA journal_mode = WAL;
        wal
        sqlite> CREATE TABLE t1 (a, b);
        sqlite> .quit  # commits wal

        $ python
        >>> import sqlite3
        >>> con = sqlite3.connect("tests/_data/sqlite3/page_count.db")
        ... cur = con.cursor()
        >>> cur.execute("INSERT INTO t1 VALUES (1, ?)", ("A" * 8192,))
        >>> con.commit()
        # Copy page_count.db* files before closing
    """

    db = sqlite3.SQLite3(absolute_path("_data/sqlite3/page_count.db"))
    table = db.table("t1")
    assert table.sql == "CREATE TABLE t1 (a, b)"

    row = next(table.rows())
    assert row.a == 1
    assert row.b == "A" * 8192

    assert db.wal
    assert db.wal.highest_page_num == 4
    assert db.header.page_count == 2
    assert db.page_count == 4
