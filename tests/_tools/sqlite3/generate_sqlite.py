from __future__ import annotations

import sqlite3
from pathlib import Path

conn = sqlite3.connect("db.sqlite", isolation_level=None)

# Set WAL mode
conn.execute("PRAGMA journal_mode=WAL;")

# Disable automatic checkpoints to keep all data in WAL for testing
conn.execute("PRAGMA wal_autocheckpoint=-1;")


def create_table() -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS test (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            value INTEGER NOT NULL
        )
    """
    )


def insert_data(name: str, value: str | int) -> None:
    conn.execute("INSERT INTO test (name, value) VALUES (?, ?)", (name, value))


def delete_data(name: str, value: str | int) -> None:
    conn.execute("DELETE FROM test WHERE name = ? AND value = ?", (name, value))


def update_data(old_name: str, old_value: str | int, new_name: str, new_value: str | int) -> None:
    conn.execute(
        "UPDATE test SET name = ?, value = ? WHERE name = ? AND value = ?",
        (new_name, new_value, old_name, old_value),
    )


def create_checkpoint() -> None:
    conn.execute("PRAGMA wal_checkpoint(FULL);")


def move_files() -> None:
    destination_dir = (Path(__file__).parent / "../../_data/sqlite3/").resolve()

    Path("db.sqlite").rename(destination_dir / "test.sqlite")
    Path("db.sqlite-wal").rename(destination_dir / "test.sqlite-wal")
    Path("db.sqlite-shm").rename(destination_dir / "test.sqlite-shm")

    # Remove this line if the shm file is needed as well
    Path(destination_dir / "test.sqlite-shm").unlink()


if __name__ == "__main__":
    create_table()

    # Initial data
    insert_data("testing", 1337)
    insert_data("omg", 7331)
    insert_data("A" * 4100, 4100)
    insert_data("B" * 4100, 4100)
    insert_data("negative", -11644473429)

    create_checkpoint()

    # Insert extra data after the first checkpoint
    insert_data("after checkpoint", 42)
    insert_data("after checkpoint", 43)
    insert_data("after checkpoint", 44)
    insert_data("after checkpoint", 45)

    create_checkpoint()

    # More data after second checkpoint, fewer entries to ensure both checkpoints will be in WAL
    insert_data("second checkpoint", 100)
    insert_data("second checkpoint", 101)

    create_checkpoint()

    # Modify some data after third checkpoint
    delete_data("after checkpoint", 43)
    update_data("after checkpoint", 45, "wow", 1234)

    # Rename files to prevent automatic cleanup
    move_files()

    conn.close()
