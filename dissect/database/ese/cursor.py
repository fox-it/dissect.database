from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.exception import KeyNotFoundError
from dissect.database.ese.record import Record

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.database.ese.ese import ESE
    from dissect.database.ese.index import Index
    from dissect.database.ese.page import Node, Page
    from dissect.database.ese.util import RecordValue


class Cursor:
    """A simple cursor implementation for searching the ESE indexes on their records.

    Args:
        index: The :class:`~dissect.database.ese.index.Index` to create the cursor for.
    """

    def __init__(self, index: Index):
        self.index = index
        self.table = index.table
        self.db = index.db

        self._primary = RawCursor(self.db, index.root)
        self._secondary = None if index.is_primary else RawCursor(self.db, self.table.root)

    def __iter__(self) -> Iterator[Record]:
        if self._primary._page.is_branch:
            self._primary.first()

        record = self.record()
        while record is not None:
            yield record
            record = self.next()

    def _node(self) -> Node:
        """Return the node the cursor is currently on. Resolves the secondary index if needed.

        Returns:
            A :class:`~dissect.database.ese.page.Node` object of the current node.
        """
        node = self._primary.node()
        if self._secondary is not None:
            node = self._secondary.search(node.data.tobytes(), exact=True).node()
        return node

    def record(self) -> Record:
        """Return the record the cursor is currently on.

        Returns:
            A :class:`~dissect.database.ese.record.Record` object of the current record.
        """
        return Record(self.table, self._node())

    def reset(self) -> Self:
        """Reset the internal state."""
        self._primary.reset()
        if self._secondary:
            self._secondary.reset()
        return self

    def next(self) -> Record | None:
        """Move the cursor to the next record and return it.

        Returns:
            A :class:`~dissect.database.ese.record.Record` object of the next record.
        """
        if self._primary.next():
            return self.record()
        return None

    def prev(self) -> Record | None:
        """Move the cursor to the previous node and return it.

        Returns:
            A :class:`~dissect.database.ese.record.Record` object of the previous record.
        """
        if self._primary.prev():
            return self.record()
        return None

    def make_key(self, *args: RecordValue, **kwargs: RecordValue) -> bytes:
        """Generate a key for this index from the given values.

        Args:
            *args: The values to generate a key for.
            **kwargs: The columns and values to generate a key for.

        Returns:
            The generated key as bytes.
        """
        if not args and not kwargs:
            raise ValueError("At least one value must be provided")

        if args and kwargs:
            raise ValueError("Cannot mix positional and keyword arguments in make_key")

        if args and not len(args) == 1 and not isinstance(args[0], list):
            raise ValueError("When using positional arguments, provide a single list of values")

        return self.index.make_key(args[0] if args else kwargs)

    def search(self, *args: RecordValue, **kwargs: RecordValue) -> Record:
        """Search the index for the requested values.

        Searching modifies the cursor state. Searching again will search from the current position.
        Reset the cursor with :meth:`reset` to start from the beginning.

        Args:
            *args: The values to search for.
            **kwargs: The columns and values to search for.

        Returns:
            A :class:`~dissect.database.ese.record.Record` object of the found record.
        """
        key = self.make_key(*args, **kwargs)
        return self.search_key(key, exact=True)

    def search_key(self, key: bytes, exact: bool = True) -> Record:
        """Search for a record with the given ``key``.

        Args:
            key: The key to search for.
            exact: If ``True``, search for an exact match. If ``False``, sets the cursor on the
                   next record that is greater than or equal to the key.
        """
        self._primary.search(key, exact=exact)
        return self.record()

    def seek(self, *args: RecordValue, **kwargs: RecordValue) -> Self:
        """Seek to the record with the given values.

        Args:
            *args: The values to seek to.
            **kwargs: The columns and values to seek to.
        """
        key = self.make_key(*args, **kwargs)
        self.search_key(key, exact=False)
        return self

    def seek_key(self, key: bytes) -> Self:
        """Seek to the record with the given ``key``.

        Args:
            key: The key to seek to.
        """
        self._primary.search(key, exact=False)
        return self

    def find(self, **kwargs: RecordValue) -> Record | None:
        """Find a record in the index.

        This differs from :meth:`search` in that it will allow additional filtering on non-indexed columns.

        Args:
            **kwargs: The columns and values to search for.
        """
        return next(self.find_all(**kwargs), None)

    def find_all(self, **kwargs: RecordValue) -> Iterator[Record]:
        """Find all records in the index that match the given values.

        This differs from :meth:`search` in that it will allows additional filtering on non-indexed columns.
        If you only search on indexed columns, this will yield all records that match the indexed columns.

        Args:
            **kwargs: The columns and values to search for.
        """
        indexed_columns = {c.name: kwargs.pop(c.name) for c in self.index.columns}
        other_columns = kwargs

        # We need at least an exact match on the indexed columns
        try:
            self.search(**indexed_columns)
        except KeyNotFoundError:
            return

        current_key = self._primary.node().key
        while True:
            # Entries with the same indexed columns are guaranteed to be adjacent
            if current_key != self._primary.node().key:
                break

            record = self.record()
            for k, v in other_columns.items():
                value = record.get(k)
                # If the record value is a list, we do a check based on the queried value
                if isinstance(value, list):
                    # If the queried value is also a list, we check if they are equal
                    if isinstance(v, list):
                        if value != v:
                            break
                    # Otherwise we check if the queried value is in the record value
                    elif v not in value:
                        break
                else:
                    if value != v:
                        break
            else:
                yield record

            if not self._primary.next():
                break


class RawCursor:
    """A simple cursor implementation for searching the ESE B+Trees on their raw nodes.

    Args:
        db: An instance of :class:`~dissect.database.ese.ese.ESE`.
        root: The page to open the raw cursor on.
    """

    def __init__(self, db: ESE, root: Page | int):
        self.db = db
        self.root = db.page(root) if isinstance(root, int) else root

        self._page = self.root
        self._idx = 0

        # Stack of (page, idx, stack[:]) for traversing back up the tree when doing in-order traversal
        self._stack = []

    @property
    def state(self) -> tuple[Page, int, list[tuple[Page, int]]]:
        """Get the current cursor state."""
        return self._page, self._idx, self._stack[:]

    @state.setter
    def state(self, value: tuple[Page, int, list[tuple[Page, int]]]) -> None:
        """Set the current cursor state."""
        self._page, self._idx, self._stack = value[0], value[1], value[2][:]

    def reset(self) -> Self:
        """Reset the cursor to the root of the B+Tree."""
        self._page = self.root
        self._idx = 0
        self._stack = []

        return self

    def node(self) -> Node:
        """Return the node the cursor is currently on.

        Returns:
            A :class:`~dissect.database.ese.page.Node` object of the current node.
        """
        return self._page.node(self._idx)

    def first(self) -> bool:
        """Move the cursor to the first leaf node in the B+Tree."""
        self.reset()
        while self._page.is_branch and self._page.node_count > 0:
            self.push()

        return self._page.node_count != 0

    def last(self) -> bool:
        """Move the cursor to the last leaf node in the B+Tree."""
        self.reset()
        while self._page.is_branch and self._page.node_count > 0:
            self._idx = self._page.node_count - 1
            self.push()

        self._idx = self._page.node_count - 1
        return self._page.node_count != 0

    def next(self) -> bool:
        """Move the cursor to the next leaf node."""
        if self._page.is_branch:
            # Treat as if we were at the first node
            self.first()
            return self._page.node_count != 0

        if self._idx + 1 < self._page.node_count:
            self._idx += 1
        elif self._stack:
            # End of current page, traverse to the next leaf page

            # First pop until we find a page with unvisited nodes
            while self._idx + 1 >= self._page.node_count:
                if not self._stack:
                    return False
                self.pop()

            self._idx += 1

            # Then push down to the next page
            while self._page.is_branch:
                self.push()
        else:
            return False

        return True

    def prev(self) -> bool:
        """Move the cursor to the previous leaf node."""
        if self._page.is_branch:
            # Treat as if we were at the last node
            self.last()
            return self._page.node_count != 0

        if self._idx - 1 >= 0:
            self._idx -= 1
        elif self._stack:
            # Start of current page, traverse to the previous leaf page

            # First pop until we find a page with unvisited nodes
            while self._idx - 1 < 0:
                if not self._stack:
                    # Start of B+Tree reached
                    return False
                self.pop()

            self._idx -= 1

            # Then push down to the rightmost leaf
            while self._page.is_branch:
                self._idx = self._page.node_count - 1
                self.push()
        else:
            # Start of B+Tree reached
            return False

        return True

    def push(self) -> Self:
        """Push down to the child page at the current index."""
        child_page = self.db.page(self._page.node(self._idx).child)

        self._stack.append((self._page, self._idx))
        self._page = child_page
        self._idx = 0

        return self

    def pop(self) -> Self:
        """Pop back to the parent page."""
        if not self._stack:
            raise IndexError("Cannot pop from an empty stack")

        self._page, self._idx = self._stack.pop()

        return self

    def walk(self) -> Iterator[Node]:
        """Walk the B+Tree in order, yielding nodes."""
        if self.first():
            yield self.node()

            while self.next():
                yield self.node()

    def search(self, key: bytes, *, exact: bool = True) -> Self:
        """Search the tree for the given ``key``.

        Moves the cursor to the matching node, or on the last node that is less than the requested key.

        Args:
            key: The key to search for.
            exact: Whether to only return successfully on an exact match.

        Raises:
            KeyNotFoundError: If an ``exact`` match was requested but not found.
        """
        self.reset()

        while self._page.is_branch:
            self._idx = find_node(self._page, key, exact=False)
            self.push()

        self._idx = find_node(self._page, key, exact=exact)
        if self._idx >= self._page.node_count or self._idx == -1:
            raise KeyNotFoundError(f"Key not found: {key!r}")

        return self


def find_node(page: Page, key: bytes, *, exact: bool) -> int:
    """Search a page for a node matching the given key.

    Referencing Extensible-Storage-Engine source, they bail out early if they find an exact match.
    However, we prefer to always find the _first_ node that is greater than or equal to the key,
    so we can handle cases where there are duplicate index keys. This is important for "range" searches
    where we want to find all keys matching a certain prefix, and not end up somewhere in the middle of the range.

    Args:
        page: The page to search.
        key: The key to search.
        exact: Whether to only return successfully on an exact match.

    Returns:
        The node number of the first node that's greater than or equal to the key, or the last node on the page if
        the key is larger than all nodes. If ``exact`` is ``True`` and an exact match is not found, returns -1.
    """
    if page.node_count == 0:
        return -1

    lo, hi = 0, page.node_count - 1

    node = None
    while lo < hi:
        mid = (lo + hi) // 2
        node = page.node(mid)

        # It turns out that the way BTree keys are compared matches 1:1 with how Python compares bytes
        # First compare data, then length
        if key > node.key:
            lo = mid + 1
        else:
            hi = mid

    # Final comparison on the last node
    node = page.node(lo)

    if key == node.key:
        if page.is_branch:
            # If there's an exact match on a key on a branch page, the actual leaf nodes are in the next branch
            # Page keys for branch pages appear to be non-inclusive upper bounds
            lo = min(lo + 1, page.node_count - 1)

    # key != node.key
    elif exact:
        return -1

    return lo
