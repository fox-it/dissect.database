from __future__ import annotations

from typing import BinaryIO

from dissect.database.ese.tools.ual import UAL


def test_ual(ual_db: BinaryIO) -> None:
    db = UAL(ual_db)

    assert len(list(db.get_table_records("CLIENTS"))) == 19
    assert len(list(db.get_table_records("ROLE_ACCESS"))) == 3
    assert len(list(db.get_table_records("VIRTUALMACHINES"))) == 0
    assert len(list(db.get_table_records("DNS"))) == 12
    assert len(list(db.get_table_records("SYSTEM_IDENTITY"))) == 0


def test_ual_skip_bad_entries(ual_bad_entries_db: BinaryIO) -> None:
    ual = UAL(ual_bad_entries_db)

    # CLIENTS have 24 entries (5 are empty (tombstones))
    # DNS have 17 (3 empty and 2 with schema mismatch)
    # They should be skipped
    clients = list(ual.get_table_records("CLIENTS"))
    dns = list(ual.get_table_records("DNS"))

    assert len(clients) == 19
    assert len(dns) == 12
