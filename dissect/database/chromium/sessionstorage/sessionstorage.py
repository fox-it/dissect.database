from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.leveldb.leveldb import LevelDB

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.database.leveldb.leveldb import Record as LevelDBRecord


class SessionStorage:
    """Google SessionStorage implementation.

    References:
        - https://www.cclsolutionsgroup.com/post/chromium-session-storage-and-local-storage
    """

    def __init__(self, path: Path):
        self.path = path
        self.leveldb = LevelDB(path)

        self.namespaces = [
            Namespace(self, record)
            for record in self.leveldb.records
            if record.key[0:10] == b"namespace-" and len(record.key) > 10 and record.value
        ]

    def __repr__(self):
        return f"<SessionStorage path='{self.path!s}' namespaces={len(self.namespaces)!r}>"

    def namespace(self, key: int | str) -> Iterator[Namespace] | None:
        """Yield namespaces by the given id or hostname."""
        for namespace in self.namespaces:
            if namespace.id == key or namespace.host == key:
                yield namespace


class Namespace:
    """Represents a single Session Storage namespace."""

    uuid: str
    id: int
    host: str

    def __init__(self, session_storage: SessionStorage, record: LevelDBRecord):
        self.session_storage = session_storage
        self.record = record

        if not record.value:
            raise ValueError(f"Namespace record does not have a value: {record!r}")

        _, self.uuid, self.host = record.key.decode().split("-", 2)

        self.id = int(record.value.decode())

        self.prefix = b"map-" + str(self.id).encode() + b"-"
        self.records = [
            Record(self, record, self.prefix)
            for record in self.session_storage.leveldb.records
            if record.key[0 : len(self.prefix)] == self.prefix
        ]

    def __repr__(self):
        return f"<SessionStorageNamespace host={self.host!r} uuid={self.uuid!r} id={self.id!r} records={len(self.records)!r}>"  # noqa: E501


class Record:
    """Represents a single Session Storage key and value pair."""

    namespace: Namespace

    key: str
    value: str

    def __init__(self, namespace: Namespace, record: LevelDBRecord, prefix: bytes):
        self.namespace = namespace
        self.record = record

        self.key = record.key.removeprefix(prefix).decode()
        self.value = record.value.decode("utf-16-le")

    def __repr__(self):
        return f"<SessionStorageRecord key={self.key!r} value={self.value!r}>"
