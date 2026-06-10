from __future__ import annotations

from typing import BinaryIO
from unittest.mock import MagicMock

from dissect.database.ese.ese import ESE
from dissect.database.ese.record import RecordData
from dissect.database.ese.table import Table


def test_find_index() -> None:
    mock_column_id = MagicMock()
    mock_column_id.name = "Id"
    mock_column_bit = MagicMock()
    mock_column_bit.name = "Bit"
    mock_column_unsigned_byte = MagicMock()
    mock_column_unsigned_byte.name = "UnsignedByte"

    mock_idx_id = MagicMock(name="IxId")
    mock_idx_id.is_primary = True
    mock_idx_id.columns = [mock_column_id]
    mock_idx_bit = MagicMock(name="IxBit")
    mock_idx_bit.is_primary = False
    mock_idx_bit.columns = [mock_column_bit]
    mock_idx_multiple = MagicMock(name="IxMultiple")
    mock_idx_multiple.is_primary = False
    mock_idx_multiple.columns = [mock_column_bit, mock_column_unsigned_byte]

    table = Table(MagicMock(), 69, "index", indexes=[mock_idx_id, mock_idx_bit, mock_idx_multiple])

    assert table.find_index(["Id"]) == mock_idx_id
    assert table.find_index(["Bit"]) == mock_idx_bit
    assert table.find_index(["Bit", "UnsignedByte"]) == mock_idx_multiple
    assert table.find_index(["UnsignedByte", "Bit"]) == mock_idx_multiple
    assert table.find_index(["UnsignedByte"]) is None
    assert table.find_index(["Id", "Bit"]) == mock_idx_id
    assert table.find_index(["Bit", "SomethingElse"]) == mock_idx_bit


def test_record_data_bad_entries(ual_bad_entries_db: BinaryIO) -> None:
    db = ESE(ual_bad_entries_db)

    clients = db.table("CLIENTS")
    assert len(list(clients.records())) == 24

    dns = db.table("DNS")
    assert len(list(dns.records())) == 17

    all_clients_nodes = list(clients.root.iter_leaf_nodes())
    tombstones = sum(1 for n in all_clients_nodes if RecordData(clients, n).is_empty)
    assert tombstones == 5

    dns_tombstones = 0
    dns_mismatch = 0
    for node in dns.root.iter_leaf_nodes():
        rd = RecordData(dns, node)
        if rd.is_empty:
            dns_tombstones += 1
        elif not rd.matches_schema():
            dns_mismatch += 1

    assert dns_tombstones == 3
    assert dns_mismatch == 2
