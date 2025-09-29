from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.database import IndexedDB
from tests._util import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


@pytest.mark.benchmark
def test_benchmark_indexeddb(benchmark: BenchmarkFixture) -> None:
    """Test if we can parse a medium sized IndexedDB."""

    path = absolute_path("_data/leveldb/indexeddb/larger/file__0.indexeddb.leveldb")
    records = benchmark(lambda: IndexedDB(path).database("ExampleDatabase").object_store("MyObjectStore").records)

    assert len(records) == 10_002
    assert records[-1].key == 1
    assert records[-1].value == {"id": 1, "name": {"first": "John", "last": "Doe"}, "age": 42}
