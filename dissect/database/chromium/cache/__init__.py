from __future__ import annotations

from dissect.database.chromium.cache.c_cache import c_cache
from dissect.database.chromium.cache.c_simple import c_simple
from dissect.database.chromium.cache.cache import DiskCache
from dissect.database.chromium.cache.simple import SimpleDiskCache

__all__ = [
    "DiskCache",
    "SimpleDiskCache",
    "c_cache",
    "c_simple",
]
