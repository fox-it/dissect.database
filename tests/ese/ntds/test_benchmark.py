from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.database.ese.ntds import NTDS


@pytest.mark.benchmark
def test_benchmark_small_ntds_users(ntds_small: NTDS, benchmark: BenchmarkFixture) -> None:
    benchmark(lambda: list(ntds_small.users()))


@pytest.mark.benchmark
def test_benchmark_large_ntds_users(ntds_large: NTDS, benchmark: BenchmarkFixture) -> None:
    users = benchmark(lambda: list(ntds_large.users()))
    assert len(users) == 8985


@pytest.mark.benchmark
def test_benchmark_small_ntds_groups(ntds_small: NTDS, benchmark: BenchmarkFixture) -> None:
    benchmark(lambda: list(ntds_small.groups()))


@pytest.mark.benchmark
def test_benchmark_large_ntds_groups(ntds_large: NTDS, benchmark: BenchmarkFixture) -> None:
    groups = benchmark(lambda: list(ntds_large.groups()))
    assert len(groups) == 253


@pytest.mark.benchmark
def test_benchmark_small_ntds_computers(ntds_small: NTDS, benchmark: BenchmarkFixture) -> None:
    benchmark(lambda: list(ntds_small.computers()))


@pytest.mark.benchmark
def test_benchmark_large_ntds_computers(ntds_large: NTDS, benchmark: BenchmarkFixture) -> None:
    computers = benchmark(lambda: list(ntds_large.computers()))
    assert len(computers) == 3014
