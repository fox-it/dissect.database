from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import BinaryIO

from dissect.util.stream import MappingStream

from dissect.database.sqlite3.encryption.sqlcipher.exception import SQLCipherError
from dissect.database.sqlite3.exception import InvalidDatabase
from dissect.database.sqlite3.sqlite3 import SQLite3

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA1, SHA256, SHA512
    from Crypto.Hash import new as new_hash
    from Crypto.Protocol.KDF import PBKDF2

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
    DEFAULT_KDF_ALGO: object
    DEFAULT_HMAC_ALGO: object

    def __init__(
        self,
        fh: Path | BinaryIO,
        passphrase: str | bytes,
        *,
        salt: bytes | None = None,
        plaintext_header_size: int | None = None,
        page_size: int | None = None,
        kdf_iter: int | None = None,
        kdf_algo: object | None = None,
        hmac_algo: object | None = None,
        no_kdf: bool = False,
    ):
        self.cipher_fh = fh
        self.cipher_path = None
        self.cipher_page_size = page_size or self.DEFAULT_PAGE_SIZE
        self.kdf_iter = kdf_iter or self.DEFAULT_KDF_ITER
        self.kdf_algo = kdf_algo or self.DEFAULT_KDF_ALGO
        self.hmac_algo = hmac_algo or self.DEFAULT_HMAC_ALGO

        if not HAS_CRYPTO:
            raise RuntimeError("Missing dependency pycryptodome")

        if isinstance(fh, Path):
            self.cipher_path = fh
            self.cipher_fh = fh.open("rb")

        if not hasattr(self.cipher_fh, "read"):
            raise ValueError("Provided file handle cannot be read from")

        if isinstance(passphrase, str):
            passphrase = passphrase.encode()

        if not passphrase:
            raise SQLCipherError("No passphrase provided")

        if isinstance(self.hmac_algo, str):
            self.hmac_algo = new_hash(self.hmac_algo)

        if isinstance(self.kdf_algo, str):
            self.kdf_algo = new_hash(self.kdf_algo)

        # Part of the header can be plaintext. We can infer that or it can be passed upon initialization.
        # https://www.zetetic.net/sqlcipher/sqlcipher-api/#cipher_plaintext_header_size
        if plaintext_header_size:
            self.plaintext_header_size = plaintext_header_size

        # The default and recommended plaintext header size is 32 bytes.
        elif (header_or_salt := self.cipher_fh.read(16)) == b"SQLite format 3\x00":
            self.plaintext_header_size = 32
        else:
            self.plaintext_header_size = None

        if self.plaintext_header_size and not salt:
            raise SQLCipherError("Plaintext header has no salt, please provide salt manually")

        self.salt = salt or header_or_salt
        self.passphrase = passphrase
        self.key = self.passphrase if no_kdf else derive_key(self.passphrase, self.salt, self.kdf_iter, self.kdf_algo)

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
            f"fh='{self.cipher_path or self.cipher_fh!s}' "
            f"wal='{self.wal!s}' "
            f"checkpoint={bool(self.checkpoint)!r} "
            f"pages={self.header.page_count!r}>"
        )

    def close(self) -> None:
        """Close the database."""
        super().close()
        # Only close DB handle if we opened it using a path
        if self.cipher_path is not None:
            self.cipher_fh.close()

    def stream(self) -> MappingStream:
        """Create a mapped stream of ``SQLCipherPage`` instances."""
        stream = MappingStream()

        # Add an appropriate plaintext SQLite3 header.
        self.cipher_fh.seek(0)
        offset = self.plaintext_header_size or 16
        header = BytesIO(self.cipher_fh.read(offset) if self.plaintext_header_size else b"SQLite format 3\x00")
        stream.add(0, offset, header)

        # Creates SQLCipherPage objects which can be lazily read from. No page reading or decrypting happens
        # until a specific page is accessed by the reader of the MappingStream.
        page_num = 1
        while True:
            try:
                page = SQLCipherPage(self, page_num)
                size = self.cipher_page_size - ((self.plaintext_header_size or 16) if page_num == 1 else 0)
                stream.add(offset, size, page)
                offset += size
                page_num += 1
            except EOFError:  # noqa: PERF203
                break

        return stream


class SQLCipher4(SQLCipher):
    DEFAULT_PAGE_SIZE = 4096
    DEFAULT_KDF_ITER = 256_000
    DEFAULT_KDF_ALGO = SHA512
    DEFAULT_HMAC_ALGO = SHA512


class SQLCipher3(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 64_000
    DEFAULT_KDF_ALGO = SHA1
    DEFAULT_HMAC_ALGO = SHA1


class SQLCipher2(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 4000
    DEFAULT_KDF_ALGO = SHA1
    DEFAULT_HMAC_ALGO = SHA1


class SQLCipher1(SQLCipher):
    DEFAULT_PAGE_SIZE = 1024
    DEFAULT_KDF_ITER = 4000
    DEFAULT_KDF_ALGO = SHA1
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
            header_offset = sqlcipher.plaintext_header or 16
            self.enc_size -= header_offset
            self.offset += header_offset

        # Data is only read from the cipher file handle when ``.read()`` is called.
        self.plaintext = None
        self.encrypted = None

        # The last part of the page contains the iv and optionally hmac.
        sqlcipher.cipher_fh.seek(self.offset + self.enc_size)
        self.iv = sqlcipher.cipher_fh.read(16)
        self.mac = sqlcipher.cipher_fh.read(sqlcipher.hmac_algo.digest_size) if sqlcipher.hmac_algo else None

        if len(self.iv) != 16:
            raise EOFError

        self._pos = 0

    def __repr__(self) -> str:
        return (
            f"<SQLCipherPage page_num={self.page_num!r} "
            f"size={self.sqlcipher.cipher_page_size} "
            f"decrypted={self.decrypted!r}>"
        )

    @property
    def decrypted(self) -> bool:
        return bool(self.plaintext)

    def seek(self, pos: int, whence: int = 0) -> None:
        self._pos = pos

    def tell(self) -> int:
        return self._pos

    def read(self, size: int | None = None) -> bytes:
        """Cached plaintext reader of this page."""

        if size == -1:
            size = None

        if self.plaintext:
            return self.plaintext[self._pos : size]

        self.sqlcipher.cipher_fh.seek(self.offset)
        self.encrypted = self.sqlcipher.cipher_fh.read(self.enc_size)

        # We could have reached the end of the database if no more pages are left to read.
        if not self.encrypted:
            raise EOFError

        cipher = AES.new(self.sqlcipher.key, AES.MODE_CBC, self.iv)

        # Append null bytes so the plaintext aligns with the page size.
        # https://github.com/sqlcipher/sqlcipher-tools/blob/master/decrypt.c
        self.plaintext = cipher.decrypt(self.encrypted) + (self.align * b"\x00")
        return self.plaintext[self._pos : size]


def derive_key(passphrase: bytes, salt: bytes, kdf_iter: int, kdf_algo: SHA1 | SHA256 | SHA512) -> bytes:
    """Derive the database key as SQLCipher would using PBKDF2."""

    if not kdf_iter and not kdf_algo:
        return passphrase

    return PBKDF2(passphrase, salt, 32, count=kdf_iter, hmac_hash_module=kdf_algo)
