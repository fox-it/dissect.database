from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


PARAMS = (
    "fixture",
    [
        pytest.param("goad", id="goad"),
        pytest.param("large", id="large"),
    ],
)


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_users(fixture: str, benchmark: BenchmarkFixture, request: pytest.FixtureRequest) -> None:
    ntds = request.getfixturevalue(fixture)
    benchmark(lambda: list(ntds.users()))


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_groups(fixture: str, benchmark: BenchmarkFixture, request: pytest.FixtureRequest) -> None:
    ntds = request.getfixturevalue(fixture)
    benchmark(lambda: list(ntds.groups()))


@pytest.mark.benchmark
@pytest.mark.parametrize(*PARAMS)
def test_benchmark_computers(fixture: str, benchmark: BenchmarkFixture, request: pytest.FixtureRequest) -> None:
    ntds = request.getfixturevalue(fixture)
    benchmark(lambda: list(ntds.computers()))
