from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, BinaryIO

import pytest

from tests._util import open_file_gz

if TYPE_CHECKING:
    from collections.abc import Iterator

HAS_BENCHMARK = importlib.util.find_spec("pytest_benchmark") is not None


def pytest_configure(config: pytest.Config) -> None:
    if not HAS_BENCHMARK:
        # If we don't have pytest-benchmark (or pytest-codspeed) installed, register the benchmark marker ourselves
        # to avoid pytest warnings
        config.addinivalue_line("markers", "benchmark: mark test for benchmarking (requires pytest-benchmark)")


@pytest.fixture
def basic_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/basic.edb.gz")


@pytest.fixture
def binary_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/binary.edb.gz")


@pytest.fixture
def text_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/text.edb.gz")


@pytest.fixture
def multi_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/multi.edb.gz")


@pytest.fixture
def default_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/default.edb.gz")


@pytest.fixture
def index_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/index.edb.gz")


@pytest.fixture
def large_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/large.edb.gz")


@pytest.fixture
def windows_search_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/Windows.edb.gz")


@pytest.fixture
def sru_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/tools/SRUDB.dat.gz")


@pytest.fixture
def ual_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/tools/Current.mdb.gz")


@pytest.fixture
def certlog_db() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/tools/CertLog.edb.gz")


@pytest.fixture(scope="module")
def ntds_dit() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/ntds.dit.gz")


@pytest.fixture(scope="module")
def large_ntds_dit() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/large_ntds.dit.gz")


@pytest.fixture(scope="module")
def system_hive() -> Iterator[BinaryIO]:
    yield from open_file_gz("_data/ese/SYSTEM.gz")
