from __future__ import annotations

from datetime import datetime, timezone

from v8serialize.jstypes import JSRegExp, JSUndefined

from dissect.database.indexeddb.indexeddb import IndexedDB
from dissect.database.util.blink import BlinkBlobIndex
from tests._util import absolute_path


def test_indexeddb_different_types() -> None:
    """Test if we can parse different IndexedDB value types.

    References:
        - https://github.com/cclgroupltd/ccl_chromium_reader/blob/master/tools_and_utilities/extras/make_test_indexeddb.html
    """

    path = absolute_path("_data/leveldb/indexeddb/types/file__0.indexeddb.leveldb")

    indexeddb = IndexedDB(path)
    database = indexeddb.database("MyTestDatabase")
    object_store = database.object_store("store")

    assert len(object_store.records) == 19

    # Basics
    record = object_store.get("basics")
    assert record.value == {
        "id": "basics",
        "true": True,
        "false": False,
        "null": None,
        "undefined": JSUndefined,
        "string_1a": "this string literal is repeated",
        "string_1b": "this string literal is repeated",
        "string_2a": "this string object is repeated",
        "string_2b": "this string object is repeated",
        "the_number_100": 100,
        "the_number_1000000000": 1000000000,
        "the_number_1.5": 1.5,
        "aRegex": JSRegExp("[A-z]{3}", 0),
        "date": datetime(2022, 11, 21, 16, 0, tzinfo=timezone.utc),
    }

    # Big integers
    record = object_store.get("the_one_with_bigints")
    assert record.value == {
        "id": "the_one_with_bigints",
        "a_BigInt": 1000,
        "a_neg_bigInt": -1000,
        "a_hugeInt": 100000000000000000000000,
        "beeegInt": 605951652385920480004291274127545002769392376323959195201050263810007255232559947887954882812532343572574055983,  # noqa: E501
    }

    # Collections
    record = object_store.get("the_one_with_collections")
    assert record.value["id"] == "the_one_with_collections"
    assert record.value["dense_array"] == {0: "one", 1: "two", 2: "three", 3: "four"}
    assert record.value["sparse_array"][32] == "ELEMENT AT INDEX 32"
    assert record.value["sparse_array"][92] == "ELEMENT AT INDEX 92"
    assert record.value["inner_object"] == {"key1": "value1", "key2": "value2", "key3": "value3"}
    assert record.value["map"] == {"map_key1": "map_value1", "map_key2": "map_value2", "map_key3": "map_value3"}
    assert record.value["set"] == {"set_value2", "set_value1", "set_value3", "set_value4"}

    # Array buffers
    record = object_store.get("the_one_with_array_buffers")
    assert record.value["id"] == "the_one_with_array_buffers"
    assert bytes(record.value["array_buffer"]) == bytes.fromhex(
        "0100000002000000030000000400000005000000060000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    assert tuple(record.value["int32_buffer"].get_buffer()) == (1, 2, 3, 4, 5, 6, *tuple(0 for _ in range(26)))

    # Cyclic references
    record = object_store.get("the_one_with_cyclic_references")
    assert record.value["id"] == "the_one_with_cyclic_references"
    assert record.value["one_layer"]["parent"] is None
    assert record.value["one_layer"]["children"][0]["parent"] == record.value["one_layer"]  # recursion, baby!
    assert record.value["one_layer"]["children"][0]["children"] == {}
    assert (
        record.value["three_item_cyclic_linked_list"]["next1"]["prev2"]
        == record.value["three_item_cyclic_linked_list"]["prev1"]["prev3"]["prev2"]
    )

    # Strings
    record = object_store.get("the_one_with_unicode")
    assert record.value["id"] == "the_one_with_unicode"
    assert record.value["all_ascii"] == "hello world"
    assert record.value["ascii_plus_latin1"] == "hélló wórld"
    assert record.value["ascii_plus_emoji"] == "hell😮 world"
    assert record.value["all_unicode"] == "😛😫😋😎"

    # Primitives and objects
    record = object_store.get("the_one_with_primitives_and_objects")
    assert record.value["id"] == "the_one_with_primitives_and_objects"
    assert record.value["string_primitive"] == "hello primitive"
    assert record.value["string_object"] == "hello object"
    assert record.value["bool_primitive_true"] is True
    assert record.value["bool_object_true"] is True
    assert record.value["number_primitive_1000"] == 1000
    assert record.value["number_object_1000"] == 1000
    assert record.value["bigint_primitive_abcdefabcdefabcdefabcdef"] == 53170898287292916380478459375
    assert record.value["bigint_object_abcdefabcdefabcdefabcdef"] == 53170898287292916380478459375

    # Different types in primary keys
    record = object_store.get(["an", "array", "of", "text"])
    assert record.value["text"] == "primary key is an array of text"

    record = object_store.get(1000)
    assert record.value["id"] == 1000
    assert record.value["text"] == "primary key is the integer 1000"

    record = object_store.get(["an", "array", "of", "text", "and", "an", "integer", 1000])
    assert record.value["text"] == "primary is an array of text with a number at the end"

    # TODO: Big record for kIDBWrapThreshold
    record = object_store.get("a_big_record_to_test_kIDBWrapThreshold_in_chrome")
    assert record.value == b"\x01\x9e\xc0\x0f\x00"
    record = object_store.get(
        "a_big_record_to_test_kIDBWrapThreshold_in_chrome_plus_a_file_to_check_how_mozilla_does_that"
    )
    assert record.value == b"\x01\xd2\xc0\x0f\x00"

    # TODO: Cryptography objects
    record = object_store.get("the_one_with_crypto_objects")
    record.value.startswith(b'\xff\x0fo"\x02id"\x1bthe_one_with_crypto_objects"\x03rsa')
    assert len(record.value) == 3572

    # TODO: File blobs
    record = object_store.get("the_one_with_a_blob")
    assert record.value["id"] == "the_one_with_a_blob"
    assert record.value["blob"] == BlinkBlobIndex(index_id=0)

    # Key is a nested array with a string
    record = object_store.get([["foo"]])
    assert record.value["id"] == {0: {0: "foo"}}
    assert record.value["desc"] == 'key is [["foo"]]'

    # Key is a nested array without values
    record = object_store.get([[]])
    assert record.value["id"] == {0: {}}
    assert record.value["desc"] == "key is [[]]"

    # Key is a datetime object
    record = object_store.get(datetime(2024, 4, 30, 22, 0, tzinfo=timezone.utc))
    assert record.value["id"] == datetime(2024, 4, 30, 22, 0, tzinfo=timezone.utc)
    assert record.value["desc"] == "key is new Date(2024, 4, 1)"

    # Key is a nested array with integers
    record = object_store.get([[[1, 2], 3, [[4], 5, 6], [7, [8, 9]]], 10])
    assert record.value["id"] == {
        0: {0: {0: 1, 1: 2}, 1: 3, 2: {0: {0: 4}, 1: 5, 2: 6}, 3: {0: 7, 1: {0: 8, 1: 9}}},
        1: 10,
    }
    assert record.value["desc"] == "key is [[[1,2], 3, [[4], 5, 6], [7, [8, 9]]], 10]"
