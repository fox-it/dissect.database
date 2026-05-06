from __future__ import annotations

import re


def parse_cache_key(key: str) -> tuple[int | None, int | None, bool, str]:
    """Parse a Cache or Simple Cache key to a standardized tuple.

    Arguments:
        key: string in the format 'credential_key/upload_data_identifier/[isolation_key]url'

    Returns: Tuple of ``credential_key``, ``upload_data_identifier``, ``isolation_key`` and ``resource_url``

    References:
        - GenerateCacheKey
        - GetResourceURLFromHttpCacheKey
        - https://chromium.googlesource.com/chromium/src/+/main/net/http/http_cache.cc
    """
    kDoubleKeyPrefix = "_dk_"
    kDoubleKeySeparator = " "

    credential_key = None
    upload_data_identifier = None
    isolation_key = False
    url = None

    if not isinstance(key, str):
        raise TypeError("Input key is not a string")

    # Key looks like 'credential_key/upload_data_identifier/...', after 2021-09
    if match := re.match(r"^(\d+)/(\d+)/(.+)", key):
        credential_key = int(match.group(1))
        upload_data_identifier = int(match.group(2))
        url = match.group(3)

    # Key looks like 'upload_data_identifier/...', before 2021-09
    elif match := re.match(r"^(\d+)/(.+)", key):
        upload_data_identifier = int(match.group(1))
        url = match.group(2)

    # Key could be a regular URL
    else:
        url = key

    # Check for double key presence in url. The last part is the resource url
    if url.startswith(kDoubleKeyPrefix):
        isolation_key = True
        _, _, resource_url = url.rpartition(kDoubleKeySeparator)
    else:
        resource_url = url

    return credential_key, upload_data_identifier, isolation_key, resource_url
