from __future__ import annotations

import tarfile
from typing import TYPE_CHECKING

from dissect.database.chromium.cache.simple import SimpleDiskCache
from tests._util import absolute_path

if TYPE_CHECKING:
    from pathlib import Path


def test_chromium_simple_cache(tmp_path: Path) -> None:
    """Test if we can parse Chromium Cache Data from Google Chrome 147 on Ubuntu 24.04 LTS."""
    path = absolute_path("_data/chromium/cache/Linux_Cache_Data.tgz")

    with tarfile.open(path) as tf:
        tf.extractall(tmp_path, filter="data")

    simple_disk_cache = SimpleDiskCache(tmp_path)

    assert len(simple_disk_cache.cache_files) == 19
    assert len(list(simple_disk_cache.get_host("172.16.82.1"))) == 19

    assert sorted(cache_file.resource_url for cache_file in simple_disk_cache.entries()) == sorted(
        [
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SerifWeb-Italic.woff2",
            "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/home/2026/energiemaatregelen-anp-556197185.jpg",
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/responsive.css",
            "http://172.16.82.1:8000/binaries/content/assets/rijksoverheid/iconen/favicon.ico",
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SansWebText-Regular.woff2",
            "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/shared-ro/jquery-ui.js",
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/icons/ro-icons-2.4.woff2",
            "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/home/2026/douane-koraal-1.jpg",
            "http://172.16.82.1:8000/binaries/content/gallery/rijksoverheid/channel-afbeeldingen/logos/beeldmerk-rijksoverheid-desktop.svg",
            "http://172.16.82.1:8000/binaries/content/assets/rijksoverheid/behaviour/rop-page-feedback.min-20230526.js",
            "http://172.16.82.1:8000/binaries/widescreen/content/gallery/rijksoverheid/content-afbeeldingen/home/evergreens/header-meivakantie.jpg",
            "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/core.js",
            "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/onderwerpen/fiets/campagne-fietshelm.jpg",
            "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/shared-ro/img-helpers.js",
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/themes/logoblauw.css",
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/rijks-sans-regular.woff2",
            "http://172.16.82.1:8000/",
            "http://172.16.82.1:8000/binaries/large/content/gallery/rijksoverheid/content-afbeeldingen/home/evergreens/header-meivakantie.jpg",
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SansWebText-Bold.woff2",
        ]
    )

    cache_file = simple_disk_cache.get_url("http://172.16.82.1:8000/")
    assert b"HTTP/1.0 200 OK\x00" in cache_file.meta
    assert cache_file.data.startswith(b"<!doctype html>")
    assert cache_file.data.endswith(b"\n</body>\n</html>\n")
    assert len(cache_file.data) == 25451

    assert simple_disk_cache.get_key("1/0/_dk_http://172.16.82.1 http://172.16.82.1 http://172.16.82.1:8000/")
