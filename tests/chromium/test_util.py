from __future__ import annotations

import pytest

from dissect.database.chromium.cache.util import parse_cache_key


@pytest.mark.parametrize(
    ("input_key", "expected_output"),
    [
        pytest.param(
            "http://172.16.82.1",
            (None, None, False, "http://172.16.82.1"),
            id="regular_url",
        ),
        pytest.param(
            "1/0/_dk_http://172.16.82.1 http://172.16.82.1 http://172.16.82.1:8000/webfiles/1750011834072/behaviour/shared-ro/jquery-ui.js",
            (1, 0, True, "http://172.16.82.1:8000/webfiles/1750011834072/behaviour/shared-ro/jquery-ui.js"),
            id="double_keyed_key",
        ),
        pytest.param(
            "0/http://172.16.82.1",
            (None, 0, False, "http://172.16.82.1"),
            id="old_format",
        ),
    ],
)
def test_cache_key_parsing(input_key: str, expected_output: tuple) -> None:
    """Test if we parse Chromium cache keys correctly."""
    assert parse_cache_key(input_key) == expected_output
