from __future__ import annotations

from datetime import datetime, timedelta, timezone
from io import BytesIO
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.database.indexeddb.c_indexeddb import c_indexeddb
from dissect.database.leveldb.c_leveldb import c_leveldb
from dissect.database.leveldb.leveldb import LevelDB
from dissect.database.leveldb.leveldb import Record as LevelDBRecord
from dissect.database.util.blink import deserialize_blink_host_object
from dissect.database.util.protobuf import decode_varint

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

try:
    import v8serialize

    HAS_V8 = True

except ImportError:
    HAS_V8 = False


class IndexedDB:
    """Google IndexedDB implementation.

    References:
        - https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/docs/leveldb_coding_scheme.md
        - https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/docs/README.md
        - https://github.com/google/dfindexeddb
        - https://www.cclsolutionsgroup.com/post/indexeddb-on-chromium
    """

    databases: list[Database]

    def __init__(self, path: Path):
        self.path = path
        self.databases = []

        if not HAS_V8:
            raise ImportError(
                "Missing required dependency 'v8serialize', install with pip install dissect.database[indexeddb]"
            )

        if not path.exists():
            raise FileNotFoundError(f"Provided path does not exist: {path!r}")

        if not path.is_dir():
            raise NotADirectoryError(f"Provided path is not a directory: {path!r}")

        self._leveldb = LevelDB(path)
        self._records = list(self._get_records())
        self._metadata = self._get_metadata()

        # TODO: Check for schema version, we only support up to version 5.

    def __repr__(self) -> str:
        return f"<IndexedDB path='{self.path!s}' databases={len(self.databases)!r}>"

    def _get_records(self) -> Iterator[IndexedDBRecord]:
        for record in self._leveldb.records:
            yield IndexedDBRecord(record)

    def _get_metadata(self) -> dict[bytes, c_leveldb.Record]:
        """Returns a dictionary of the current global metadata of this IndexedDB.
        Populates ``self.databases`` found along the way."""

        metadata = {}

        for record in reversed(self._records):
            if (
                record.database_id == 0
                and record.object_store_id == 0
                and record.index_id == 0
                and record.state == c_leveldb.RecordState.LIVE
                and (record.key not in metadata or metadata[record.key].sequence < record.sequence)
            ):
                metadata[record.key] = record

                if record.key[0] == c_indexeddb.GlobalMetaDataType.DatabaseNameKey:
                    buf = BytesIO(record.key[1:])
                    origin = read_varint_value(buf)
                    name = read_varint_value(buf)
                    id = read_truncated_int(record.value)
                    self.databases.append(Database(self, origin, name, id))

        return metadata

    def database(self, key: int | str) -> Database | None:
        """Get a database by id or name, returns on first match."""

        for database in self.databases:
            if (isinstance(key, int) and database.id == key) or (isinstance(key, str) and database.name == key):
                return database
        return None


class Database:
    """Represents a single IndexedDB Database."""

    def __init__(self, indexeddb: IndexedDB, origin: str, name: str, id: int):
        self._indexeddb = indexeddb

        self.origin = origin
        self.name = name
        self.id = id

        self._metadata, self._object_store_metadata = self._get_metadata()
        self.object_stores = list(self._get_object_stores())

    def __repr__(self) -> str:
        return f"<Database id={self.id!r} name={self.name!r} origin={self.origin!r} object_stores={len(self.object_stores)!r}>"  # noqa: E501

    def _get_metadata(self) -> tuple[dict, dict]:
        """Return metadata dictionary of this database."""

        metadata = {}
        object_store_metadata = {}

        for record in reversed(self._indexeddb._records):
            if (
                record.database_id == self.id
                and record.object_store_id == 0
                and record.index_id == 0
                and record.state == c_leveldb.RecordState.LIVE
                and (record.key not in metadata or metadata[record.key].sequence < record.sequence)
            ):
                metadata[record.key] = record

                if record.key[0] == c_indexeddb.DatabaseMetaDataType.MAX_OBJECT_STORE_ID:
                    self._maximum_object_store_id = read_truncated_int(record.value)

                elif record.key[0] == c_indexeddb.DatabaseMetaDataType.ObjectStoreMetaData:
                    buf = BytesIO(record.key[1:])
                    object_store_id = decode_varint(buf, 10)
                    object_store_metadata.setdefault(object_store_id, {})
                    metadata_type = buf.read(1)
                    object_store_metadata[object_store_id][metadata_type] = record

        return metadata, object_store_metadata

    def _get_object_stores(self) -> Iterator[ObjectStore]:
        for object_store_id, object_store_metadata in self._object_store_metadata.items():
            yield ObjectStore(self, object_store_id, object_store_metadata)

    def object_store(self, key: int | str) -> ObjectStore | None:
        """Return an object store based on the given key."""

        for object_store in self.object_stores:
            if (isinstance(key, int) and object_store.id == key) or (isinstance(key, str) and object_store.name == key):
                return object_store
        return None


class ObjectStore:
    """Represents a single IndexedDB object store."""

    id: int
    name: str

    def __init__(self, database: Database, id: int, metadata: dict):
        self.id = id
        self._database = database
        self._metadata = metadata

        self.name = self._metadata.get(int.to_bytes(0)).value.decode("utf-16-be")
        # TODO: Research if num of records is stored in metadata.

        self.records = list(self._get_records())

    def __repr__(self) -> str:
        return f"<ObjectStore id={self.id!r} name={self.name!r} records={len(self.records)!r}>"

    def _get_records(self) -> Iterator[IndexedDBKey]:
        """Yield stored records in the object store. Currently does not mark deleted records as such."""

        for record in reversed(self._database._indexeddb._records):
            if (
                record.database_id == self._database.id
                and record.object_store_id == self.id
                and record.index_id == c_indexeddb.IndexIdType.ObjectStoreData
                and record.state == c_leveldb.RecordState.LIVE
            ):
                yield IndexedDBKey(self, record)

    def get(self, key: Any) -> IndexedDBKey | None:
        """Return a single record based on the id or an arbitrary key value."""

        for record in self.records:
            if record.key == key:
                return record
        return None

    def keys(self) -> tuple | None:
        """Return a tuple of record keys in this object store."""

        return tuple(record.key for record in self.records)


class IndexedDBKey:
    """Represents a single decoded IndexDB key.

    References:
        - https://chromium.googlesource.com/chromium/src/+/main/content/browser/indexed_db/indexed_db_leveldb_coding.cc
        - https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/public/common/indexeddb/indexeddb_key.h
        - https://github.com/v8/v8/blob/master/src/objects/value-serializer.cc
        - https://chromium.googlesource.com/chromium/src/third_party/+/master/blink/renderer/bindings/core/v8/serialization
    """

    def __init__(self, object_store: ObjectStore, record: IndexedDBRecord):
        self.object_store = object_store
        self._record = record

        self.type = None
        self.key = None
        self.value = None

        self.type, self.key, _ = self._decode_key(self._record.key)
        self._decode_value()

    @classmethod
    def _decode_key(cls, key_value: bytes) -> tuple[c_indexeddb.IdbKeyType, Any, int]:
        """Decode the :class:`IndexedDBRecord` key value."""

        key_buf = BytesIO(key_value)
        type = c_indexeddb.IdbKeyType(key_buf.read(1)[0])
        offset = None

        if type == c_indexeddb.IdbKeyType.Null:
            key = None

        elif type == c_indexeddb.IdbKeyType.String:
            key = read_varint_value(key_buf)

        elif type == c_indexeddb.IdbKeyType.Date:
            ms = c_indexeddb.double(key_buf.read(8))
            key = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=ms)

        elif type == c_indexeddb.IdbKeyType.Number:
            key = c_indexeddb.double(key_buf.read(8))

        elif type == c_indexeddb.IdbKeyType.Array:
            key = []
            size = decode_varint(key_buf, 10)
            offset = key_buf.tell()

            for _ in range(size):
                _, nkey, nsize = cls._decode_key(key_value[offset:])
                offset += nsize
                key.append(nkey)

        elif type == c_indexeddb.IdbKeyType.MinKey:
            key = None

        elif type == c_indexeddb.IdbKeyType.Binary:
            size = decode_varint(key_buf, 10)
            key = key_buf.read(size)

        else:
            raise ValueError(f"Unknown IndexedDBKey type {type!r}")

        return type, key, offset if offset else key_buf.tell()

    def _decode_value(self) -> None:
        """Decode the :class:`IndexedDBRecord` value using Blink and V8.

        Currently does not handle ``kReplaceWithBlob`` IDB value unwrapping. When deserializing fails,
        the value of the key is set to the raw bytes instead.

        References:
            - https://chromium.googlesource.com/chromium/src/+/refs/heads/main/third_party/blink/renderer/modules/indexeddb/idb_value_wrapping.cc
            - https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/bindings/core/v8/serialization/trailer_reader.h
            - https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/modules/indexeddb/idb_value_wrapping.cc
        """

        if not self._record.value:
            return

        value_buf = BytesIO(self._record.value)
        value_header = c_indexeddb.IdbValueHeader(value_buf)

        if value_header.blink_tag != 0xFF:
            raise ValueError(f"Invalid Blink tag {value_header.blink_tag!r}")

        # Determine if a Blink trailer is present
        if value_header.blink_version >= c_indexeddb.kMinWireFormatVersion:
            self._value_blink_trailer = value_buf.read(13)
        self._raw_object = value_buf.read()

        try:
            self.value = v8serialize.loads(
                data=self._raw_object,
                jsmap_type=dict,
                js_object_type=dict,
                js_array_type=dict,
                default_timezone=timezone.utc,
                host_object_deserializer=deserialize_blink_host_object,
            )
        except Exception:
            self.value = self._raw_object

    def __repr__(self) -> str:
        return f"<IndexedDBKey type={self.type.name!r} key={self.key!r} value={self.value!r}>"


class IndexedDBRecord:
    """A single IndexedDB record constructed from a LevelDB record."""

    def __init__(self, record: LevelDBRecord):
        self._record = record
        self._prefix = c_indexeddb.KeyPrefix(record.key)

        self.key = record.key[len(self._prefix.dumps()) :]
        self.value = record.value
        self.state = record.state
        self.sequence = record.sequence

        self.database_id = int.from_bytes(self._prefix.database_id, "little")
        self.object_store_id = int.from_bytes(self._prefix.object_store_id, "little")
        self.index_id = int.from_bytes(self._prefix.index_id, "little")

    def __repr__(self) -> str:
        return f"<IndexedDBRecord database_id={self.database_id!r} object_store_id={self.object_store_id!r} index_id={self.index_id!r} key={self.key.hex()!r} state={self.state.name!r} value={self.value.hex()!r}>"  # noqa: E501


def read_varint_value(buf: BinaryIO) -> str:
    """Read the database name from a DatabaseNameKey buffer.

    References:
        - https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/docs/leveldb_coding_scheme.md
    """

    length = decode_varint(buf, 10)
    return buf.read(length * 2).decode("utf-16-be")


def read_truncated_int(input: bytes) -> int:
    """Read a truncated integer from the given byte(s).

    References:
        - https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_leveldb_coding.h#EncodeInt
    """

    result = 0
    for i, b in enumerate(input):
        result |= b << (i * 8)
    return result
