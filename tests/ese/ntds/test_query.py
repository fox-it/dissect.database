from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.database.ese.ntds.query import Query, _increment_last_char

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS


def test_simple_AND(ntds_small: NTDS) -> None:
    query = Query(ntds_small.db, "(&(objectClass=user)(cn=Henk de Vries))")
    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_simple_OR(ntds_small: NTDS) -> None:
    query = Query(ntds_small.db, "(|(objectClass=group)(cn=ERNESTO_RAMOS))")

    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 55  # 54 groups + 1 user
        assert mock_fetch.call_count == 2


def test_nested_OR(ntds_small: NTDS) -> None:
    query = Query(
        ntds_small.db,
        "(|(objectClass=container)(objectClass=organizationalUnit)"
        "(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))",
    )
    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 615
        assert mock_fetch.call_count == 5


def test_nested_AND(ntds_small: NTDS) -> None:
    first_query = Query(
        ntds_small.db, "(&(objectClass=user)(&(cn=ERNESTO_RAMOS)(sAMAccountName=ERNESTO_RAMOS)))", optimize=False
    )
    with (
        patch.object(first_query, "_query_database", wraps=first_query._query_database) as mock_fetch,
        patch.object(first_query, "_process_query", wraps=first_query._process_query) as mock_execute,
    ):
        records = list(first_query.process())
        # only the first part of the AND should be fetched, so objectClass=user
        assert len(records) == 1
        assert mock_fetch.call_count == 1
        assert mock_execute.call_count == 65
        first_run_queries = mock_execute.call_count

    second_query = Query(
        ntds_small.db, "(&(&(cn=ERNESTO_RAMOS)(sAMAccountName=ERNESTO_RAMOS))(objectClass=user))", optimize=False
    )
    with (
        patch.object(second_query, "_query_database", wraps=second_query._query_database) as mock_fetch,
        patch.object(second_query, "_process_query", wraps=second_query._process_query) as mock_execute,
    ):
        records = list(second_query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1
        assert mock_execute.call_count == 5
        second_run_queries = mock_execute.call_count
        assert second_run_queries < first_run_queries, "The second query should have fewer calls than the first one."

    # When we allow query optimization, the first query should be similar to the second one,
    # that was manuall optimized
    third_query = Query(
        ntds_small.db, "(&(objectClass=user)(&(cn=ERNESTO_RAMOS)(sAMAccountName=ERNESTO_RAMOS)))", optimize=True
    )
    with (
        patch.object(third_query, "_query_database", wraps=third_query._query_database) as mock_fetch,
        patch.object(third_query, "_process_query", wraps=third_query._process_query) as mock_execute,
    ):
        records = list(third_query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1
        assert mock_execute.call_count == 5
        assert mock_execute.call_count == second_run_queries


def test_simple_wildcard(ntds_small: NTDS) -> None:
    query = Query(ntds_small.db, "(&(sAMAccountName=Adm*)(objectCategory=person))")
    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_simple_wildcard_in_AND(ntds_small: NTDS) -> None:
    query = Query(ntds_small.db, "(&(objectCategory=person)(sAMAccountName=Adm*))")
    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_invalid_attribute(ntds_small: NTDS) -> None:
    """Test attribute not found in schema."""
    query = Query(ntds_small.db, "(nonexistent_attribute=test_value)")
    with pytest.raises(ValueError, match="Attribute 'nonexistent_attribute' not found in the NTDS database"):
        list(query.process())


def test_invalid_index(ntds_small: NTDS) -> None:
    """Test index not found for attribute."""
    query = Query(ntds_small.db, "(cn=ThisIsNotExistingInTheDB)")
    with (
        patch.object(ntds_small.db.data.table, "find_index", return_value=None),
        pytest.raises(ValueError, match=r"Index for attribute.*not found in the NTDS database"),
    ):
        list(query.process())


def test_increment_last_char() -> None:
    """Test incrementing the last character of a string."""
    assert _increment_last_char("test") == "tesu"
    assert _increment_last_char("tesz") == "tet"
    assert _increment_last_char("a") == "b"
    assert _increment_last_char("z") == "za"
    assert _increment_last_char("") == "a"
