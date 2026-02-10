from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO

from dissect.database.sqlite3.encryption.sqlcipher.exception import SQLCipherError
from dissect.database.sqlite3.exception import InvalidDatabase
from dissect.database.sqlite3.sqlite3 import SQLITE3_HEADER_MAGIC, SQLite3
from dissect.util.stream import AlignedStream

try:
    from Crypto.Cipher import AES

    HAS_CRYPTO = True

except ImportError:
    HAS_CRYPTO = False


class SQLCipher(SQLite3):
    """SQLCipher Community Edition implementation.

    Instantiate with a subclass from :class:`SQLCipher4`, :class:`SQLCipher3`, :class:`SQLCipher2`
    or :class:`SQLCipher1`.

    Decrypts a SQLCipher database from the given path or file-like oject.
    HMAC key derivation and tag verification is currently not implemented.

    Example usage:
        >>> from dissect.database.sqlite3.encryption import SQLCipher4
        >>> db = SQLCipher4(Path("file.db"), "passphrase")
        >>> row = db.table("MyTable").row(0)

    Args:
        fh (Path | BinaryIO): The path or file-like object to open.
        passphrase (str | bytes): String or bytes passphrase.
        salt (bytes): Optionally provide the 16-byte salt directly.
        plaintext_header_size (int): Size of plaintext header to use.
        page_size (int): Override size of each page.
        kdf_iter (int): Override amount of KDF iterations.
        kdf_algo (str | Crypto.Hash): Override KDF digest alrorithm.
        hmac_algo (str | Crypto.Hash): Override HMAC digest algorithm.
        no_kdf (bool): Disable KDF from passphrase, use as raw key.

    Raises:
        SQLCipherError: If decryption failed using the provided arguments.

    References:
        - https://www.zetetic.net/sqlcipher/design/
        - https://github.com/sqlcipher/sqlcipher
    """

    DEFAULT_PAGE_SIZE: int
    DEFAULT_KDF_ITER: int
    DEFAULT_KDF_ALGO: str
    DEFAULT_HMAC_ALGO: str | None

    def __init__(
        self,
        fh: Path | BinaryIO,
        passphrase: str | bytes,
        *,
        salt: bytes | None = None,
        plaintext_header_size: int | None = None,
        page_size: int | None = None,
        kdf_iter: int | None = None,
        kdf_algo: str | None = None,
        hmac_algo: str | None = None,
        no_kdf: bool = False,
    ):
        if not HAS_CRYPTO:
            raise RuntimeError("Missing dependency pycryptodome")

        if isinstance(fh, Path):
            cipher_fh = fh.open("rb")
            cipher_path = fh
        else:
            cipher_fh = fh
            cipher_path = None

        self.cipher_fh = cipher_fh
        self.cipher_path = cipher_path
        self.cipher_page_size = page_size or self.DEFAULT_PAGE_SIZE
        self.kdf_iter = kdf_iter or self.DEFAULT_KDF_ITER
        self.kdf_algo = kdf_algo or self.DEFAULT_KDF_ALGO
        self.hmac_algo = hmac_algo or self.DEFAULT_HMAC_ALGO

        if not hasattr(self.cipher_fh, "read"):
            raise ValueError("Provided file handle cannot be read from")

        if isinstance(passphrase, str):
            passphrase = passphrase.encode()

        if not passphrase:
            raise SQLCipherError("No passphrase provided")

        if isinstance(self.hmac_algo, str):
            self.hmac_algo = hashlib.new(self.hmac_algo)

        if isinstance(self.kdf_algo, str):
            self.kdf_algo = hashlib.new(self.kdf_algo)

        # Part of the header can be plaintext. We can infer that or it can be passed upon initialization.
        # https://www.zetetic.net/sqlcipher/sqlcipher-api/#cipher_plaintext_header_size
        if plaintext_header_size:
            self.plaintext_header_size = plaintext_header_size

        # The default and recommended plaintext header size is 32 bytes.
        elif (header_or_salt := self.cipher_fh.read(16)) == SQLITE3_HEADER_MAGIC:
            self.plaintext_header_size = 32
        else:
            self.plaintext_header_size = None

        if self.plaintext_header_size and not salt:
            raise SQLCipherError("Plaintext header has no salt, please provide salt manually")

        self.salt = salt or header_or_salt
        self.passphrase = passphrase

        if no_kdf:
            self.key = self.passphrase
        else:
            self.key = derive_key(
                self.passphrase, self.salt, self.kdf_iter, self.kdf_algo.name if self.kdf_algo else None
            )

        # Initialize the decrypted SQLite3 stream as a file-like object and see if that works.
        try:
            super().__init__(self.stream(), wal=None, checkpoint=None)
        except InvalidDatabase as e:
            raise SQLCipherError("Decryption of SQLCipher database failed or is not a database") from e

        # Sanity check to prevent further issues down the line.
        if self.header.page_size != self.cipher_page_size or self.header.schema_format_number not in (1, 2, 3, 4):
            raise SQLCipherError("Decryption of SQLCipher database failed or is not a database")

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"fh={self.cipher_path or self.cipher_fh} "
            f"wal={self.wal} "
            f"checkpoint={bool(self.checkpoint)} "
            f"pages={self.header.page_count}>"
        )

    def close(self) -> None:
        """Close the database."""
        super().close()
        # Only close DB handle if we opened it using a path
        if self.cipher_path is not None:
            self.cipher_fh.close()

    def stream(self) -> SQLCipherStream:
        """Create an aligned stream of :class:`SQLCipherPage` instances."""
        return SQLCipherStream(self)


class SQLCipherStream(AlignedStream):
    def __init__(self, sqlcipher: SQLCipher):
        super().__init__(None, sqlcipher.cipher_page_size)
        self.fh = sqlcipher.cipher_fh
        self.sqlcipher = sqlcipher
        self._read_page = lru_cache(4096)(self._read_page)

    def _read(self, offset: int, length: int) -> bytes:
        pages_offset = offset // self.align
        num_pages = length // self.align
        return b"".join(self._read_page(num + 1) for num in range(pages_offset, pages_offset + num_pages))

    def _read_page(self, page_num: int) -> bytes:
        return SQLCipherPage(self.sqlcipher, page_num).read()


class SQLCipher4(SQLCipher):
    DEFAULT_PAGE_SIZE = 4096
    DEFAULT_KDF_ITER = 256_000
    DEFAULT_KDF_ALGO = "SHA512"
    DEFAULT_HMAC_ALGO = "SHA512"


class SQLCipher3(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 64_000
    DEFAULT_KDF_ALGO = "SHA1"
    DEFAULT_HMAC_ALGO = "SHA1"


class SQLCipher2(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 4000
    DEFAULT_KDF_ALGO = "SHA1"
    DEFAULT_HMAC_ALGO = "SHA1"


class SQLCipher1(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 4000
    DEFAULT_KDF_ALGO = "SHA1"
    DEFAULT_HMAC_ALGO = None


class SQLCipherPage:
    """Represents a single SQLCipher page. Acts as if it is a BytesIO object to read from."""

    def __init__(self, sqlcipher: SQLCipher, page_num: int) -> None:
        self.sqlcipher = sqlcipher
        self.page_num = page_num
        self.offset = (page_num - 1) * sqlcipher.cipher_page_size

        # Calculate size of page iv (always 16 bytes) plus hmac digest size
        self.align = 16 + (sqlcipher.hmac_algo.digest_size if sqlcipher.hmac_algo else 0)

        # Calculate the size of the encrypted data by substracting the iv+hmac size
        # from the page size. The iv+hmac size needs to be adjusted to 16 byte blocks.
        if self.align % 16 != 0:
            self.align = (self.align + 15) & ~15
        self.enc_size = sqlcipher.cipher_page_size - self.align

        # The first page 'contains' the database salt so substract those first 16 bytes
        # from the page size and set the file handle forward accordingly.
        if page_num == 1:
            self.header_offset = sqlcipher.plaintext_header_size or 16
            self.enc_size -= self.header_offset
            self.offset += self.header_offset
        else:
            self.header_offset = 0

        # The last part of the page contains the iv and optionally hmac.
        sqlcipher.cipher_fh.seek(self.offset + self.enc_size)
        self.iv = sqlcipher.cipher_fh.read(16)
        self.mac = sqlcipher.cipher_fh.read(sqlcipher.hmac_algo.digest_size) if sqlcipher.hmac_algo else None

        if len(self.iv) != 16:
            raise EOFError

        self._pos = 0

    def __repr__(self) -> str:
        return f"<SQLCipherPage page_num={self.page_num!r} size={self.sqlcipher.cipher_page_size}>"

    def seek(self, pos: int, whence: int = 0) -> None:
        self._pos = pos

    def tell(self) -> int:
        return self._pos

    def read(self, size: int | None = None) -> bytes:
        """Plaintext reader of this page."""

        if size == -1:
            size = None

        self.sqlcipher.cipher_fh.seek(self.offset)
        encrypted = self.sqlcipher.cipher_fh.read(self.enc_size)

        # We could have reached the end of the database if no more pages are left to read.
        if not encrypted:
            raise EOFError

        cipher = AES.new(self.sqlcipher.key, AES.MODE_CBC, self.iv)

        # Append null bytes so the plaintext aligns with the page size.
        # https://github.com/sqlcipher/sqlcipher-tools/blob/master/decrypt.c
        plaintext = cipher.decrypt(encrypted) + (self.align * b"\x00")

        # Prepend the plaintext header of the SQLite3 database if this is the first page.
        if self.header_offset == 16:
            header = SQLITE3_HEADER_MAGIC
        elif self.header_offset:
            self.sqlcipher.cipher_fh.seek(0)
            header = self.sqlcipher.cipher_fh.read(self.header_offset)
        else:
            header = b""

        return (header + plaintext)[self._pos : size]


def derive_key(passphrase: bytes, salt: bytes, kdf_iter: int, kdf_algo: str | None) -> bytes:
    """Derive the database key as SQLCipher would using PBKDF2."""

    if not kdf_iter or not kdf_algo:
        return passphrase

    return hashlib.pbkdf2_hmac(kdf_algo, passphrase, salt, kdf_iter, 32)
