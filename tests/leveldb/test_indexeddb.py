from __future__ import annotations

from dissect.database.leveldb.c_leveldb import c_leveldb
from dissect.database.leveldb.leveldb import LdbFile, LevelDB, LogFile
from tests._util import absolute_path


def test_leveldb_log_file_full() -> None:
    """Test if we can parse a Google Chrome LevelDB log file with a single full block,
    created by an IndexedDB serializer."""

    file = absolute_path("_data/leveldb/indexeddb/simple/https_mdn.github.io_0.indexeddb.leveldb/000003.log")
    log_file = LogFile(fh=file.open("rb"))

    blocks = log_file.blocks
    records = list(log_file.records)

    assert len(blocks) == 34
    assert len(records) == 284

    assert records[0].state == 1
    assert records[0].key == bytes.fromhex("000000003200")
    assert records[0].value == bytes.fromhex("0801")

    assert records[-1].state == 0
    assert records[-1].key == bytes.fromhex("00000000320127")
    assert records[-1].value == b""


def test_leveldb_log_file_start_middle_end() -> None:
    """Test if we can parse a larger LevelDB log file with segmented blocks (start-middle-end)."""

    file = absolute_path("_data/leveldb/indexeddb/segmented/https_mdn.github.io_0.indexeddb.leveldb/000003.log")
    log_file = LogFile(fh=file.open("rb"))

    records = list(log_file.records)
    num_records = len(records)

    assert num_records == 1057


def test_leveldb_ldb_file() -> None:
    """Test if we can parse a LevelDB ldb file."""

    file = absolute_path("_data/leveldb/indexeddb/larger/file__0.indexeddb.leveldb/000005.ldb")
    ldb = LdbFile(fh=file.open("rb"))
    records = list(ldb.records)

    assert len(records) == 42983

    assert records[-1].state == c_leveldb.RecordState.LIVE
    assert records[-1].sequence == 29241
    assert records[-1].key == bytes.fromhex(
        "0001011f0402011e00560061006e002d0077006f007200740068006c00650079"
        "00560061006e002d0077006f007200740068006c00650079004d00610063004c"
        "0065002d011500430068007200690073002d0061006e00740068006f006e0079"
        "00530061006d002d00420065006e002d00037c96d958cf957942"
    )
    assert records[-1].metadata == bytes.fromhex("0139720000000000")
    assert records[-1].value == bytes.fromhex("c11c037c96d958cf957942")


def test_leveldb_dir_parsing() -> None:
    """Test if we find all LevelDB log files and ldb files in a directory."""

    leveldb = LevelDB(absolute_path("_data/leveldb/indexeddb/larger/file__0.indexeddb.leveldb"))

    assert len(leveldb.manifests) == 1
    assert len(leveldb.ldb_files) == 2
    assert len(leveldb.log_files) == 1

    records = list(leveldb.records)
    num_records = len(records)
    assert num_records == 120085
