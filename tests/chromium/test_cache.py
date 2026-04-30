from __future__ import annotations

from datetime import datetime, timezone

from dissect.database.chromium.cache.c_cache import c_cache
from dissect.database.chromium.cache.cache import DiskCache
from tests._util import absolute_path


def test_chromium_cache() -> None:
    """Test if we can parse Chromium Cache Data from Google Chrome 148 on Windows 11 (24H2)."""
    path = absolute_path("_data/chromium/cache/Cache_Data")
    disk_cache = DiskCache(path)

    assert disk_cache.create_time == datetime(2026, 4, 30, 12, 10, 45, 77412, tzinfo=timezone.utc)
    assert disk_cache.num_entries == 1
    assert len(disk_cache.block_files) == 4

    entry_store = next(disk_cache.entries)
    assert entry_store.address.address == 0xa0010002
    assert entry_store.state == c_cache.EntryState.ENTRY_NORMAL
    assert entry_store.creation_time == datetime(2026, 4, 30, 12, 11, 48, 207695, tzinfo=timezone.utc)
    assert entry_store.key == "1/0/_dk_http://172.16.82.1 http://172.16.82.1 http://172.16.82.1:8000/"
    assert entry_store.next == 0

    assert entry_store.data.startswith(b"<!doctype html>\n\n")
    assert b"HTTP/1.0 200 OK\00" in entry_store.meta
