from __future__ import annotations

from dissect.database.indexeddb.indexeddb import IndexedDB
from tests._util import absolute_path


def test_indexeddb_basic_example() -> None:
    """Test if we can serialize a basic IndexedDB example.

    References:
        - https://mdn.github.io/dom-examples/indexeddb-api/index.html
    """

    path = absolute_path("_data/leveldb/indexeddb/simple/https_mdn.github.io_0.indexeddb.leveldb")
    indexeddb = IndexedDB(path)

    assert len(indexeddb.databases) == 1

    database = indexeddb.database(1)

    assert database.id == 1
    assert database.origin == "https_mdn.github.io_0@1"
    assert database.name == "mdn-demo-indexeddb-epublications"
    assert database._maximum_object_store_id == 1
    assert len(database.object_stores) == 1

    object_store = database.object_store(1)
    assert object_store.name == "publications"

    assert len(object_store.records) == 5

    # This record was deleted (a marker exists but is currently not parsed)
    record = object_store.get(4)
    assert record.value["biblioid"] == "978-0141036144"
    assert record.value["title"] == "1984"
    assert record.value["year"] == 1949
    assert record.value["blob"].index_id == 0

    # This is the next regular record
    record = object_store.get(5)
    assert record.value["biblioid"] == "978-0007532278"
    assert record.value["title"] == "I, Robot"
    assert record.value["year"] == 1950
    assert record.value["blob"].index_id == 0
