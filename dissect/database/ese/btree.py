from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.ese.exception import KeyNotFoundError, NoNeighbourPageError

if TYPE_CHECKING:
    from dissect.database.ese.ese import ESE
    from dissect.database.ese.page import Node, Page


class BTree:
    """A simple implementation for searching the ESE B+Trees.

    This is a stateful interactive class that moves an internal cursor to a position within the BTree.

    Args:
        db: An instance of :class:`~dissect.database.ese.ese.ESE`.
        page: The page to open the :class:`BTree` on.
    """

    def __init__(self, db: ESE, root: int | Page):
        self.db = db

        if isinstance(root, int):
            page_num = root
            root = db.page(page_num)
        else:
            page_num = root.num

        self.root = root

        self._page = root
        self._page_num = page_num
        self._node_num = 0

    def reset(self) -> None:
        """Reset the internal state to the root of the BTree."""
        self._page = self.root
        self._page_num = self._page.num
        self._node_num = 0

    def node(self) -> Node:
        """Return the node the BTree is currently on.

        Returns:
            A :class:`~dissect.database.ese.page.Node` object of the current node.
        """
        return self._page.node(self._node_num)

    def next(self) -> Node:
        """Move the BTree to the next node and return it.

        Can move the BTree to the next page as a side effect.

        Returns:
            A :class:`~dissect.database.ese.page.Node` object of the next node.
        """
        if self._node_num + 1 > self._page.node_count - 1:
            self.next_page()
        else:
            self._node_num += 1

        return self.node()

    def next_page(self) -> None:
        """Move the BTree to the next page in the tree.

        Raises:
            NoNeighbourPageError: If the current page has no next page.
        """
        if self._page.next_page:
            self._page = self.db.page(self._page.next_page)
            self._node_num = 0
        else:
            raise NoNeighbourPageError(f"{self._page} has no next page")

    def prev(self) -> Node:
        """Move the BTree to the previous node and return it.

        Can move the BTree to the previous page as a side effect.

        Returns:
            A :class:`~dissect.database.ese.page.Node` object of the previous node.
        """
        if self._node_num - 1 < 0:
            self.prev_page()
        else:
            self._node_num -= 1

        return self.node()

    def prev_page(self) -> None:
        """Move the BTree to the previous page in the tree.

        Raises:
            NoNeighbourPageError: If the current page has no previous page.
        """
        if self._page.previous_page:
            self._page = self.db.page(self._page.previous_page)
            self._node_num = self._page.node_count - 1
        else:
            raise NoNeighbourPageError(f"{self._page} has no previous page")

    def search(self, key: bytes, exact: bool = True) -> Node:
        """Search the tree for the given ``key``.

        Moves the BTree to the matching node, or on the last node that is less than the requested key.

        Args:
            key: The key to search for.
            exact: Whether to only return successfully on an exact match.

        Raises:
            KeyNotFoundError: If an ``exact`` match was requested but not found.
        """
        page = self._page
        while True:
            num = find_node(page, key)
            node = page.node(num)

            if page.is_branch:
                page = self.db.page(node.child)
            else:
                self._page = page
                self._page_num = page.num
                self._node_num = node.num
                break

        if exact and key != node.key:
            raise KeyNotFoundError(f"Can't find key: {key}")

        return self.node()


def find_node(page: Page, key: bytes) -> int:
    """Search a page for a node matching ``key``.

    Referencing Extensible-Storage-Engine source, they bail out early if they find an exact match.
    However, we prefer to always find the _first_ node that is greater than or equal to the key,
    so we can handle cases where there are duplicate index keys. This is important for "range" searches
    where we want to find all keys matching a certain prefix, and not end up somewhere in the middle of the range.

    Args:
        page: The page to search.
        key: The key to search.

    Returns:
        The node number of the first node that's greater than or equal to the key.
    """
    lo, hi = 0, page.node_count - 1
    res = 0

    node = None
    while lo < hi:
        mid = (lo + hi) // 2
        node = page.node(mid)

        # It turns out that the way BTree keys are compared matches 1:1 with how Python compares bytes
        # First compare data, then length
        res = (key < node.key) - (key > node.key)

        if res < 0:
            lo = mid + 1
        else:
            hi = mid

    # Final comparison on the last node
    node = page.node(lo)
    res = (key < node.key) - (key > node.key)

    if page.is_branch and res == 0:
        # If there's an exact match on a key on a branch page, the actual leaf nodes are in the next branch
        # Page keys for branch pages appear to be non-inclusive upper bounds
        lo = min(lo + 1, page.node_count - 1)

    return lo
