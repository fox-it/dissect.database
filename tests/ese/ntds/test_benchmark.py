from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture

    from dissect.database.ese.ntds import NTDS


@pytest.mark.benchmark
def test_benchmark_goad_users(goad: NTDS, benchmark: BenchmarkFixture) -> None:
    benchmark(lambda: list(goad.users()))


@pytest.mark.benchmark
def test_benchmark_large_users(large: NTDS, benchmark: BenchmarkFixture) -> None:
    users = benchmark(lambda: list(large.users()))
    assert len(users) == 8985


@pytest.mark.benchmark
def test_benchmark_goad_groups(goad: NTDS, benchmark: BenchmarkFixture) -> None:
    benchmark(lambda: list(goad.groups()))


@pytest.mark.benchmark
def test_benchmark_large_groups(large: NTDS, benchmark: BenchmarkFixture) -> None:
    groups = benchmark(lambda: list(large.groups()))
    assert len(groups) == 253


@pytest.mark.benchmark
def test_benchmark_goad_computers(goad: NTDS, benchmark: BenchmarkFixture) -> None:
    benchmark(lambda: list(goad.computers()))


@pytest.mark.benchmark
def test_benchmark_large_computers(large: NTDS, benchmark: BenchmarkFixture) -> None:
    computers = benchmark(lambda: list(large.computers()))
    assert len(computers) == 3014
