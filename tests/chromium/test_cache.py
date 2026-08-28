from __future__ import annotations

import tarfile
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.database.chromium.cache.c_cache import c_cache
from dissect.database.chromium.cache.cache import DiskCache
from tests._util import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def test_chromium_cache(tmp_path: Path) -> None:
    """Test if we can parse Chromium Cache Data from Google Chrome 148 on Windows 11 (24H2)."""
    path = absolute_path("_data/chromium/cache/Windows_Cache_Data.tgz")
    with tarfile.open(path) as tf:
        tf.extractall(tmp_path, filter="data")

    disk_cache = DiskCache(tmp_path)
    assert [entry.resource_url for entry in disk_cache.entries()] == [
        "http://172.16.82.1:8000/",
        "http://172.16.82.1:8000/webfiles/1750011834072/presentation/responsive.css",
        "http://172.16.82.1:8000/webfiles/1750011834072/presentation/themes/logoblauw.css",
        "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/core.js",
        "http://172.16.82.1:8000/binaries/content/gallery/rijksoverheid/channel-afbeeldingen/logos/beeldmerk-rijksoverheid-desktop.svg",
        "http://172.16.82.1:8000/binaries/content/assets/rijksoverheid/behaviour/rop-page-feedback.min-20230526.js",
        "http://172.16.82.1:8000/binaries/widescreen/content/gallery/rijksoverheid/content-afbeeldingen/home/evergreens/header-meivakantie.jpg",
        "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/home/2026/douane-koraal-1.jpg",
        "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/home/2026/energiemaatregelen-anp-556197185.jpg",
        "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/onderwerpen/fiets/campagne-fietshelm.jpg",
        "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SansWebText-Regular.woff2",
        "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/rijks-sans-regular.woff2",
        "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SansWebText-Bold.woff2",
        "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/icons/ro-icons-2.4.woff2",
        "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SerifWeb-Italic.woff2",
        "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/shared-ro/jquery-ui.js",
        "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/shared-ro/img-helpers.js",
        "http://172.16.82.1:8000/binaries/content/assets/rijksoverheid/iconen/favicon.ico",
    ]

    assert disk_cache.create_time == datetime(2026, 4, 30, 12, 10, 45, 77412, tzinfo=timezone.utc)
    assert disk_cache.num_entries == 1
    assert len(disk_cache.block_files) == 4

    entry_store = next(disk_cache.entries())
    assert entry_store.address.address == 0xA0010002
    assert entry_store.state == c_cache.EntryState.ENTRY_NORMAL
    assert entry_store.creation_time == datetime(2026, 4, 30, 12, 11, 48, 207695, tzinfo=timezone.utc)
    assert entry_store.key == "1/0/_dk_http://172.16.82.1 http://172.16.82.1 http://172.16.82.1:8000/"
    assert entry_store.next == 0

    assert entry_store.data.startswith(b"<!doctype html>\n\n")
    assert b"HTTP/1.0 200 OK\00" in entry_store.meta

    assert disk_cache.get_key("1/0/_dk_http://172.16.82.1 http://172.16.82.1 http://172.16.82.1:8000/")
    assert disk_cache.get_url("http://172.16.82.1:8000/")
    assert next(disk_cache.get_host("172.16.82.1"))
