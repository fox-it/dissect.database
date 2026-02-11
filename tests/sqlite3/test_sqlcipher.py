from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.database.sqlite3.encryption.sqlcipher.exception import SQLCipherError
from dissect.database.sqlite3.encryption.sqlcipher.sqlcipher import SQLCipher1, SQLCipher2, SQLCipher3, SQLCipher4
from tests._util import absolute_path

if TYPE_CHECKING:
    from collections.abc import Callable

    from dissect.database.sqlite3.sqlite3 import SQLite3


def _assert_sqlite_db(sqlite: SQLite3) -> None:
    table = sqlite.table("Movies")
    assert table.sql == (
        'CREATE TABLE "Movies" (\n'
        '\t"ID"\tINTEGER,\n'
        '\t"Title"\tTEXT NOT NULL,\n'
        '\t"Year"\tINTEGER NOT NULL,\n'
        '\t"Director"\tTEXT NOT NULL,\n'
        '\t"Rating"\tINTEGER,\n'
        '\tPRIMARY KEY("ID" AUTOINCREMENT)\n'
        ")"
    )

    movies = list(table.rows())
    assert len(movies) == 11

    assert movies[-1].ID == 11
    assert movies[-1].Title == "The Good, the Bad and the Ugly"
    assert movies[-1].Year == 1966
    assert movies[-1].Director == "Sergio Leone"
    assert movies[-1].Rating == 8.8


@pytest.mark.parametrize(
    ("cipher", "kwargs", "path_str"),
    [
        # Defaults per major version
        pytest.param(SQLCipher4, {"verify_hmac": True}, "aes256_hmac_sha512_kdf_256000.sqlite", id="version-4-default"),
        pytest.param(SQLCipher3, {"verify_hmac": True}, "aes256_hmac_sha1_kdf_64000.sqlite", id="version-3-default"),
        pytest.param(SQLCipher2, {"verify_hmac": True}, "aes256_hmac_sha1_kdf_4000.sqlite", id="version-2-default"),
        pytest.param(SQLCipher1, {}, "aes256_hmac_none_kdf_4000.sqlite", id="version-1-default"),
        # Custom parameters
        pytest.param(
            SQLCipher4,
            {
                "page_size": 8192,
                "hmac_algo": "sha256",
                "kdf_algo": "sha1",
                "kdf_iter": 1337,
            },
            "aes256_hmac_sha256_kdf_sha1_1337_page_8kb.sqlite",
            id="version-4-custom-hmac-sha256-kdf-sha1-1337-page-8kb",
        ),
    ],
)
def test_decrypt_community(cipher: Callable, path_str: str, kwargs: dict) -> None:
    """Test if we can parse a SQLCipher (4.5.6 community) encrypted database."""

    path = absolute_path("_data/sqlite3/encryption/sqlcipher/" + path_str)

    with pytest.raises(SQLCipherError, match="Decryption of SQLCipher database failed"):
        cipher(path, "invalid passphrase", **kwargs)

    # Test context manager
    with cipher(path, "passphrase", **kwargs) as sqlcipher:
        assert sqlcipher.stream().read(20) in (
            b"SQLite format 3\x00\x04\x00\x01\x01",  # 1024
            b"SQLite format 3\x00\x10\x00\x01\x01",  # 4096
            b"SQLite format 3\x00\x20\x00\x01\x01",  # 8192
        )
        _assert_sqlite_db(sqlcipher)


def test_decrypt_community_plaintext_header() -> None:
    """Test if we can parse and decrypt a SQLCipher 4.5.6 database with a 32-byte plaintext header."""

    path = absolute_path("_data/sqlite3/encryption/sqlcipher/aes256_hmac_sha512_kdf_256000_plain_header.sqlite")
    salt = bytes.fromhex("01010101010101010101010101010101")

    with pytest.raises(SQLCipherError, match="No passphrase provided"):
        SQLCipher4(path, "")

    with pytest.raises(SQLCipherError, match="Plaintext header has no salt, please provide salt manually"):
        SQLCipher4(path, "invalid passphrase")

    with pytest.raises(SQLCipherError, match="Decryption of SQLCipher database failed"):
        SQLCipher4(path, "invalid passphrase", salt=salt)

    sqlcipher = SQLCipher4(path, "passphrase", salt=salt, verify_hmac=True)
    _assert_sqlite_db(sqlcipher)
