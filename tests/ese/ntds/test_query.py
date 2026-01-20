from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.database.ese.ntds.query import Query, _increment_last_char

if TYPE_CHECKING:
    from dissect.database.ese.ntds.ntds import NTDS


def test_simple_AND(goad: NTDS) -> None:
    query = Query(goad.db, "(&(objectClass=user)(cn=hodor))")
    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_simple_OR(goad: NTDS) -> None:
    query = Query(goad.db, "(|(objectClass=group)(cn=hodor))")

    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 103  # 102 groups + 1 user
        assert mock_fetch.call_count == 2


def test_nested_OR(goad: NTDS) -> None:
    query = Query(
        goad.db,
        "(|(objectClass=container)(objectClass=organizationalUnit)"
        "(sAMAccountType=805306369)(objectClass=group)(&(objectCategory=person)(objectClass=user)))",
    )
    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 582
        assert mock_fetch.call_count == 5


def test_nested_AND(goad: NTDS) -> None:
    first_query = Query(goad.db, "(&(objectClass=user)(&(cn=hodor)(sAMAccountName=hodor)))", optimize=False)
    with (
        patch.object(first_query, "_query_database", wraps=first_query._query_database) as mock_fetch,
        patch.object(first_query, "_process_query", wraps=first_query._process_query) as mock_execute,
    ):
        records = list(first_query.process())
        # only the first part of the AND should be fetched, so objectClass=user
        assert len(records) == 1
        assert mock_fetch.call_count == 1
        assert mock_execute.call_count == 77
        first_run_queries = mock_execute.call_count

    second_query = Query(goad.db, "(&(&(cn=hodor)(sAMAccountName=hodor))(objectClass=user))", optimize=False)
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
    # that was manually optimized
    third_query = Query(goad.db, "(&(objectClass=user)(&(cn=hodor)(sAMAccountName=hodor)))", optimize=True)
    with (
        patch.object(third_query, "_query_database", wraps=third_query._query_database) as mock_fetch,
        patch.object(third_query, "_process_query", wraps=third_query._process_query) as mock_execute,
    ):
        records = list(third_query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1
        assert mock_execute.call_count == 5
        assert mock_execute.call_count == second_run_queries


def test_simple_wildcard(goad: NTDS) -> None:
    query = Query(goad.db, "(&(sAMAccountName=hod*)(objectCategory=person))")
    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_simple_wildcard_in_AND(goad: NTDS) -> None:
    query = Query(goad.db, "(&(objectCategory=person)(sAMAccountName=hod*))")
    with patch.object(query, "_query_database", wraps=query._query_database) as mock_fetch:
        records = list(query.process())
        assert len(records) == 1
        assert mock_fetch.call_count == 1


def test_invalid_attribute(goad: NTDS) -> None:
    """Test attribute not found in schema."""
    query = Query(goad.db, "(nonexistent_attribute=test_value)")
    with pytest.raises(ValueError, match="Attribute 'nonexistent_attribute' not found in the NTDS database"):
        list(query.process())


def test_invalid_index(goad: NTDS) -> None:
    """Test index not found for attribute."""
    query = Query(goad.db, "(cn=ThisIsNotExistingInTheDB)")
    with (
        patch.object(goad.db.data.table, "find_index", return_value=None),
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
