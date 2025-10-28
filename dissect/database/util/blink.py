from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

try:
    import v8serialize

    HAS_V8 = True

except ImportError:
    HAS_V8 = False


class BlinkTagTypes(Enum):
    """Blink tag types."""

    BlobIndexTag = b"i"
    FileIndexTag = b"e"
    # NativeFileSystemFileHandleTag = b"n"
    # NativeFileSystemDirectoryHandleTag = b"N"
    FileListIndexTag = b"L"
    # CryptoKeyTag = b"K"


@dataclass
class BlinkBlobIndex:
    index_id: int


@dataclass
class BlinkFileIndex:
    index_id: int


BlinkType = BlinkBlobIndex, BlinkFileIndex, list[BlinkFileIndex]


def deserialize_blink_host_object(*, stream: v8serialize.decode.ReadableTagStream) -> BlinkType:
    """Support for deserializing Blink tags in V8.

    HostObject tags are the V8 serialization format's way to allow an application to insert
    their own custom data into the serialized data.

    Currently does not support ``CryptoKeyTag``, ``NativeFileSystemFileHandleTag``
    and ``NativeFileSystemDirectoryHandleTag`` tags.

    References:
        - https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/bindings/core/v8/serialization/v8_script_value_deserializer.cc
    """

    if not HAS_V8:
        raise ImportError(
            "Unable to deserialize Blink object: missing dependency v8serialize, install with 'pip install dissect.database[indexeddb]"  # noqa: E501
        )

    tag = BlinkTagTypes(stream.read_bytes(1))

    if tag == BlinkTagTypes.BlobIndexTag:
        return BlinkBlobIndex(stream.read_varint())

    if tag == BlinkTagTypes.FileIndexTag:
        return BlinkFileIndex(stream.read_varint())

    if tag == BlinkTagTypes.FileListIndexTag:
        len = stream.read_varint()
        return [BlinkFileIndex(stream.read_varint()) for _ in range(len)]

    raise BlinkHostObjectHandlerDecodeError(
        f"Unable to deserialize Blink object: unknown BlinkTagType {tag!r}",
        position=stream.pos - 1,
        data=stream.data,
    )


class BlinkHostObjectHandlerDecodeError(v8serialize.DecodeV8SerializeError):
    """Raised when decoding a HostObject as a Blink buffer fails."""
