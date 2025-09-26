from __future__ import annotations

from dissect.database.exception import Error


class InvalidDatabase(Error):
    pass


class KeyNotFoundError(Error):
    pass


class NoNeighbourPageError(Error):
    pass
