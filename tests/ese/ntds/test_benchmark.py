from __future__ import annotations

import gzip
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.database.ese.ntds.ntds import NTDS
from tests._util import absolute_path

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    "path",
    [
        pytest.param("_data/ese/ntds/goad/ntds.dit.gz", id="goad"),
        pytest.param("_data/ese/ntds/large/ntds.dit.gz", id="large"),
    ],
)


def open_ntds(path: str) -> NTDS:
    # Reopen the NTDS file for each benchmark run to prevent caching effects
    with gzip.GzipFile(absolute_path(path), "rb") as fh:
        return NTDS(BytesIO(fh.read()))


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_users(path: str, benchmark: BenchmarkFixture) -> None:
    ntds = open_ntds(path)
    benchmark(lambda: list(ntds.users()))


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_groups(path: str, benchmark: BenchmarkFixture) -> None:
    ntds = open_ntds(path)
    benchmark(lambda: list(ntds.groups()))


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_computers(path: str, benchmark: BenchmarkFixture) -> None:
    ntds = open_ntds(path)
    benchmark(lambda: list(ntds.computers()))
