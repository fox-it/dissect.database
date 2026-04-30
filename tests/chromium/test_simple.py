from __future__ import annotations

from dissect.database.chromium.cache.simple import SimpleDiskCache
from tests._util import absolute_path


def test_chromium_simple_cache() -> None:
    """Test if we can parse Chromium Cache Data from Google Chrome 147 on Ubuntu 24.04 LTS."""
    path = absolute_path("_data/chromium/cache/Linux_Cache_Data")
    simple_disk_cache = SimpleDiskCache(path)

    assert len(simple_disk_cache.cache_files) == 19

    assert sorted([cache_file.key for cache_file in simple_disk_cache.cache_files]) == sorted(
        [
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SerifWeb-Italic.woff2",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/home/2026/energiemaatregelen-anp-556197185.jpg",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/responsive.css",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/binaries/content/assets/rijksoverheid/iconen/favicon.ico",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SansWebText-Regular.woff2",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/shared-ro/jquery-ui.js",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/icons/ro-icons-2.4.woff2",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/home/2026/douane-koraal-1.jpg",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/binaries/content/gallery/rijksoverheid/channel-afbeeldingen/logos/beeldmerk-rijksoverheid-desktop.svg",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/binaries/content/assets/rijksoverheid/behaviour/rop-page-feedback.min-20230526.js",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/binaries/widescreen/content/gallery/rijksoverheid/content-afbeeldingen/home/evergreens/header-meivakantie.jpg",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/core.js",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/binaries/medium/content/gallery/rijksoverheid/content-afbeeldingen/onderwerpen/fiets/campagne-fietshelm.jpg",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/shared-ro/img-helpers.js",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/themes/logoblauw.css",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/rijks-sans-regular.woff2",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 http://172.16.82.1:8000/",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/binaries/large/content/gallery/rijksoverheid/content-afbeeldingen/home/evergreens/header-meivakantie.jpg",
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 "
            "http://172.16.82.1:8000/webfiles/1750011834072/presentation/shared-ro/webfonts/RO-SansWebText-Bold.woff2",
        ]
    )

    cache_file = simple_disk_cache.get("1/0/_dk_http://172.16.82.1 http://172.16.82.1 http://172.16.82.1:8000/")
    assert b"HTTP/1.0 200 OK\x00" in cache_file.meta
    assert b"<!doctype html>" in cache_file.data
