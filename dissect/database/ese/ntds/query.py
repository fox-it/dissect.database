from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from dissect.util.ldap import LogicalOperator, SearchFilter

from dissect.database.ese.ntds.util import encode_value

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.index import Index
    from dissect.database.ese.ntds.database import Database
    from dissect.database.ese.ntds.object import Object
    from dissect.database.ese.record import Record


log = logging.getLogger(__name__)


class Query:
    def __init__(self, db: Database, query: str, *, optimize: bool = True) -> None:
        self.db = db
        self.query = query
        self._filter = SearchFilter.parse(query, optimize=optimize)

    def process(self) -> Iterator[Object]:
        """Process the LDAP query against the NTDS database.

        Args:
            ntds: The NTDS database instance.

        Yields:
            Matching records from the NTDS database.
        """
        yield from self._process_query(self._filter)

    def _process_query(self, filter: SearchFilter, records: list[Record] | None = None) -> Iterator[Record]:
        """Process LDAP query recursively, handling nested logical operations.

        Args:
            filter: The LDAP search filter to process.
            records: Optional list of records to filter instead of querying the database.

        Yields:
            Records matching the search filter.
        """
        if not filter.is_nested():
            if records is None:
                try:
                    yield from self._query_database(filter)
                except IndexError:
                    log.debug("No records found for filter: %s", filter)
            else:
                yield from self._filter_records(filter, records)
            return

        if filter.operator == LogicalOperator.AND:
            yield from self._process_and_operation(filter, records)
        elif filter.operator == LogicalOperator.OR:
            yield from self._process_or_operation(filter, records)

    def _query_database(self, filter: SearchFilter) -> Iterator[Record]:
        """Execute a simple LDAP filter against the database.

        Args:
            filter: The LDAP search filter to execute.

        Yields:
            Records matching the filter.
        """
        # Validate attribute exists and get column mapping
        if (attr_entry := self.db.data.schema.lookup(ldap_name=filter.attribute)) is None:
            raise ValueError(f"Attribute {filter.attribute!r} not found in the NTDS database")

        if (column_name := attr_entry.column_name) is None:
            raise ValueError(f"No column mapping found for attribute {filter.attribute!r}")

        # Get the database index for this attribute
        if (index := self.db.data.table.find_index([column_name])) is None:
            raise ValueError(f"Index for attribute {column_name!r} not found in the NTDS database")

        if "*" in filter.value:
            # Handle wildcard searches differently
            if filter.value.endswith("*"):
                yield from _process_wildcard_tail(index, filter.value)
            else:
                raise NotImplementedError("Wildcards in the middle or start of the value are not yet supported")
        else:
            # Exact match query
            encoded_value = encode_value(self.db, filter.attribute, filter.value)
            yield from index.cursor().find_all(**{column_name: encoded_value})

    def _process_and_operation(self, filter: SearchFilter, records: list[Record] | None) -> Iterator[Record]:
        """Process AND logical operation.

        Args:
            ldap: The LDAP search filter with AND operator.
            records: Optional list of records to filter.

        Yields:
            Records matching all conditions in the AND operation.
        """
        if records is not None:
            records_to_process = records
            children_to_check = filter.children
        else:
            # Use the first child as base query, then filter with remaining children
            base_query, *remaining_children = filter.children
            records_to_process = list(self._process_query(base_query))
            children_to_check = remaining_children

        for record in records_to_process:
            if all(any(self._process_query(child, records=[record])) for child in children_to_check):
                yield record

    def _process_or_operation(self, filter: SearchFilter, records: list[Record] | None) -> Iterator[Record]:
        """Process OR logical operation.

        Args:
            filter: The LDAP search filter with OR operator.
            records: Optional list of records to filter.

        Yields:
            Records matching any condition in the OR operation.
        """
        for child in filter.children:
            yield from self._process_query(child, records=records)

    def _filter_records(self, filter: SearchFilter, records: list[Record]) -> Iterator[Record]:
        """Filter a list of records against a simple LDAP filter.

        Args:
            ldap: The LDAP search filter to apply.
            records: The list of records to filter.

        Yields:
            Records that match the filter criteria.
        """
        encoded_value = encode_value(self.db, filter.attribute, filter.value)
        attr_entry = self.db.data.schema.lookup(ldap_name=filter.attribute)

        if attr_entry is None or attr_entry.column_name is None:
            return

        column_name = attr_entry.column_name
        has_wildcard = "*" in filter.value
        wildcard_prefix = filter.value.replace("*", "").lower() if has_wildcard else None

        for record in records:
            record_value = record.get(column_name)

            if _value_matches_filter(record_value, encoded_value, has_wildcard, wildcard_prefix):
                yield record


def _process_wildcard_tail(index: Index, filter_value: str) -> Iterator[Record]:
    """Handle wildcard queries using range searches.

    Args:
        index: The database index to search.
        filter_value: The filter value containing wildcards.

    Yields:
        Records matching the wildcard pattern.
    """
    cursor = index.cursor()

    # Create search bounds
    value = filter_value.replace("*", "")
    cursor.seek([_increment_last_char(value)])
    end = cursor.record()

    # Seek back to the start
    cursor.reset()
    cursor.seek([value])

    # Yield all records in range
    record = cursor.record()
    while record != end:
        yield record
        record = cursor.next()


def _value_matches_filter(
    record_value: Any, encoded_value: Any, has_wildcard: bool, wildcard_prefix: str | None
) -> bool:
    """Return whether a record value matches the filter criteria.

    Args:
        record_value: The value from the database record.
        encoded_value: The encoded filter value to match against.
        has_wildcard: Whether the filter contains wildcard characters.
        wildcard_prefix: The prefix to match for wildcard searches.
    """
    if isinstance(record_value, list):
        return encoded_value in record_value

    if has_wildcard and wildcard_prefix and isinstance(record_value, str):
        return record_value.lower().startswith(wildcard_prefix)

    return encoded_value == record_value


def _increment_last_char(value: str) -> str | None:
    """Increment the last character in a string to find the next lexicographically sortable key.

    Used for binary tree searching to find the upper bound of a range search.

    Args:
        value: The string to increment.

    Returns:
        A new string with the last character incremented, or ``None`` if increment would overflow all characters.
    """
    characters = list(value)
    i = len(characters) - 1

    while i >= 0:
        if characters[i] != "z" and characters[i] != "Z":
            characters[i] = chr(ord(characters[i]) + 1)
            return "".join(characters[: i + 1])
        i -= 1
    return value + "a"
