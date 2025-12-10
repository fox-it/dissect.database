from __future__ import annotations

from dissect.database.exception import Error


class LevelDBError(Error, ValueError):
    pass
