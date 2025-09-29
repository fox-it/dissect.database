from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING

from dissect.util.ts import webkittimestamp

from dissect.database.chromium.localstorage import c_localstorage
from dissect.database.leveldb.c_leveldb import c_leveldb
from dissect.database.leveldb.leveldb import LevelDB

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


class LocalStorage:
    """Google LocalStorage implementation.

    References:
        - https://www.cclsolutionsgroup.com/post/chromium-session-storage-and-local-storage
    """

    stores: list[Store]

    def __init__(self, path: Path):
        if not path.exists():
            raise FileNotFoundError(f"Provided path does not exist: {path!r}")

        if not path.is_dir():
            raise NotADirectoryError(f"Provided path is not a directory: {path!r}")

        self._leveldb = LevelDB(path)

        self.path = path
        self.stores = list(self._get_stores())

    def __repr__(self) -> str:
        return f"<LocalStorage path='{self.path!s}' stores={len(self.stores)!r}>"

    def _get_stores(self) -> Iterator[Store]:
        """Iterate over LevelDB records for store meta information."""

        meta_keys = {}

        for record in self._leveldb.records:
            if record.state == c_leveldb.RecordState.LIVE and (
                record.key[0:5] == b"META:" or record.key[0:11] == b"METAACCESS:"
            ):
                cls = MetaKey if record.key[0:5] == b"META:" else MetaAccessKey
                meta_key = cls(record.key, record.value, record.state, record.sequence)
                meta_keys.setdefault(meta_key.key, [])
                meta_keys[meta_key.key].append(meta_key)

        for meta in meta_keys.values():
            yield Store(self, meta)

    def store(self, key: str) -> Store | None:
        """Get a single store by host name."""
        for store in self.stores:
            if store.host == key:
                return store
        return None


class Store:
    """Represents a single store of keys."""

    host: str
    records: list[Key]
    meta: list[MetaKey]

    def __init__(self, local_storage: LocalStorage, meta: list[MetaKey]):
        self._local_storage = local_storage
        self._records: list[Key] = []

        self.host = meta[0].key
        self.meta = sorted(meta, key=lambda m: m.sequence)

    def __repr__(self) -> str:
        return f"<Store host={self.host!r} records={len(self._records)!r}>"

    @property
    def records(self) -> Iterator[RecordKey]:
        """Yield all records related to this store."""

        if self._records:
            yield from self._records

        # e.g. with "_https://google.com\x00\x01MyKey", the prefix would be "_https://google.com\x00"
        prefix = RecordKey.prefix + self.host.encode("iso-8859-1") + b"\x00"
        prefix_len = len(prefix)

        for record in self._local_storage._leveldb.records:
            if record.key[:prefix_len] == prefix:
                key = RecordKey(self, record.key, record.value, record.state, record.sequence)
                self._records.append(key)
                yield key

    def get(self, key: str) -> RecordKey | None:
        """Get a single :class:`RecordKey` by the given string identifier."""
        for record in self.records:
            if record.key == key:
                return record
        return None


class Key:
    """Abstract LocalStorage key class."""

    prefix: bytes
    state: c_leveldb.RecordState
    sequence: int
    key: str
    value: str

    def __init__(self, raw_key: bytes, raw_value: bytes, state: c_leveldb.RecordState, sequence: int):
        self._raw_key = raw_key
        self._raw_value = raw_value

        self.state = state
        self.sequence = sequence

        if not raw_key.startswith(self.prefix):
            raise ValueError(
                f"Invalid key prefix {raw_key[: len(self.prefix)]!r} for {self.__class__.__name__}: expected {self.prefix!r}"  # noqa: E501
            )

        self._decode_key()
        self._decode_value()

    def __repr__(self):
        return f"<{self.__class__.__name__} state={self.state!r} sequence={self.sequence!r} key={self.key!r} value={self.value!r}>"  # noqa: E501

    def _decode_key(self) -> None:
        raise NotImplementedError

    def _decode_value(self) -> None:
        raise NotImplementedError


class MetaKey(Key):
    """Represents a LocalStorage meta key."""

    prefix: bytes = b"META:"
    value: c_localstorage.LocalStorageAreaWriteMetaData

    def _decode_key(self) -> None:
        self.key = self._raw_key.removeprefix(self.prefix).decode("iso-8859-1")

    def _decode_value(self) -> None:
        self.value = c_localstorage.LocalStorageAreaWriteMetaData(self._raw_value)


class MetaAccessKey(MetaKey):
    """Represents a LocalStorage meta access key.

    References:
        - https://chromium-review.googlesource.com/c/chromium/src/+/5585301
    """

    prefix: bytes = b"METAACCESS:"
    value: c_localstorage.LocalStorageAreaAccessMetaData

    def _decode_value(self) -> None:
        self.value = c_localstorage.LocalStorageAreaAccessMetaData(self._raw_value)


class RecordKey(Key):
    """Represents a LocalStorage record key."""

    prefix: bytes = b"_"

    def __init__(self, store: Store, raw_key: bytes, raw_value: bytes, state: c_leveldb.RecordState, sequence: int):
        super().__init__(raw_key, raw_value, state, sequence)
        self.store = store

    @cached_property
    def meta(self) -> dict:
        """Calculate the metadata that likely belongs to this key.

        In a batch write action, meta keys are written first, followed by the records belonging to that batch.
        To identify a candidate meta key for this record key, we iterate over the meta keys for the store that
        this record key belongs to and choose the meta key(s) with the closest sequence number that is lower than
        the record key sequence number. This introduces a possible inaccuracy for the matched timestamp(s).

        The accuracy of these timestamps should be taken with a grain of salt when interpreting them. A latency of
        5 to 60 seconds was observed between a script requesting a write and the key data ending up on disk. The
        latency depends on several factors, such as how many write actions are happening at the time of write and
        the amount of writes per host (website) happening (this is limited to 60 per hour).

        The reader (you!) is invited to invent a smarter method to efficiently find metadata belonging to a record key.

        References:
            - local_storage_impl.cc
        """
        meta = {"created": None, "last_modified": None, "last_accessed": None}

        for meta_key in self.store.meta:
            if meta_key.sequence < self.sequence:
                if hasattr(meta_key.value, "last_modified"):
                    meta["last_modified"] = webkittimestamp(meta_key.value.last_modified)
                    if not meta["created"]:
                        meta["created"] = meta["last_modified"]
                if hasattr(meta_key.value, "last_accessed"):
                    meta["last_accessed"] = webkittimestamp(meta_key.value.last_accessed)
                    if not meta["created"] or meta["created"] > meta["last_accessed"]:
                        meta["created"] = meta["last_accessed"]

            elif meta_key.sequence > self.sequence:
                break

        return meta

    def _decode_key(self) -> None:
        _, _, buf = self._raw_key.removeprefix(self.prefix).partition(b"\x00")

        if buf[0] == 0x00:
            self.key = buf[1:].decode("utf-16-le")

        if buf[0] == 0x01:
            self.key = buf[1:].decode("iso-8859-1")

    def _decode_value(self) -> None:
        buf = self._raw_value

        if not buf:
            self.value = None
            return

        if buf[0] == 0x00:
            self.value = buf[1:].decode("utf-16-le")

        if buf[0] == 0x01:
            self.value = buf[1:].decode("iso-8859-1")
