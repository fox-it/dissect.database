from __future__ import annotations

import hashlib
from functools import cached_property
from uuid import UUID

from dissect.database.ese.ntds.c_pek import c_pek

try:
    from Crypto.Cipher import AES, ARC4

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


AUTHENTICATOR = UUID("4881d956-91ec-11d1-905a-00c04fc2d4cf")


class PEK:
    """Password Encryption Key (PEK) handler.

    Args:
        pek: The raw PEK blob from the NTDS database.
    """

    def __init__(self, pek: bytes):
        self.pek = pek
        self.encrypted = c_pek.ENCRYPTED_PEK_LIST(pek)
        self.decrypted = None

    @property
    def version(self) -> int:
        """PEK version."""
        return self.encrypted.Version

    @property
    def unlocked(self) -> bool:
        """Indicates whether the PEK has been unlocked."""
        return self.decrypted is not None

    @cached_property
    def keys(self) -> dict[int, bytes]:
        """Dictionary of PEK keys by their key ID."""
        if not self.unlocked:
            raise RuntimeError("PEK is not unlocked")

        return {pek.KeyId: pek.Key for pek in self.decrypted.PekArray}

    def unlock(self, key: bytes) -> None:
        """Unlock the PEK list using the provided "syskey".

        Args:
            key: The syskey of the domain controller.
        """
        if not HAS_CRYPTO:
            raise RuntimeError("Missing pycryptodome dependency")

        if self.unlocked:
            return

        if self.version == c_pek.PEK_PRE_2012R2_VERSION:
            decrypted = _rc4_decrypt(self.encrypted.EncryptedData, key, self.encrypted.Salt, 1000)

        elif self.version == c_pek.PEK_2016_TP4_VERSION:
            decrypted = _aes_decrypt(self.encrypted.EncryptedData, key, self.encrypted.Salt)

        else:
            raise NotImplementedError(f"Unsupported PEK version: {self.version}")

        if decrypted[:16] != AUTHENTICATOR.bytes_le:
            raise ValueError("Invalid PEK authenticator after unlocking")

        self.decrypted = c_pek.CLEAR_PEK_LIST(decrypted)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using the PEK list.

        Args:
            data: The encrypted data blob.
        """
        if not self.unlocked:
            raise RuntimeError("PEK is not unlocked")

        encrypted_data = c_pek.ENCRYPTED_DATA(data)
        if (key := self.keys.get(encrypted_data.KeyId)) is None:
            raise KeyError(f"PEK key ID {encrypted_data.KeyId} not found")

        if encrypted_data.AlgorithmId == c_pek.PEK_ENCRYPTION:
            return _rc4_decrypt(encrypted_data.EncryptedData, key, None, 0)

        if encrypted_data.AlgorithmId == c_pek.PEK_ENCRYPTION_WITH_SALT:
            encrypted_data = c_pek.ENCRYPTED_DATA_WITH_SALT(data)
            return _rc4_decrypt(encrypted_data.EncryptedData, key, encrypted_data.Salt, 1)

        if encrypted_data.AlgorithmId == c_pek.PEK_ENCRYPTION_WITH_AES:
            encrypted_data_aes = c_pek.ENCRYPTED_DATA_WITH_AES(data)
            return _aes_decrypt(encrypted_data_aes.EncryptedData, key, encrypted_data_aes.IV)[
                : encrypted_data_aes.Length
            ]

        raise NotImplementedError(f"Unsupported PEK encryption algorithm: {encrypted_data.AlgorithmId}")


def _rc4_decrypt(data: bytes, key: bytes, salt: bytes | None, iterations: int) -> bytes:
    """Decrypt data using RC4.

    Args:
        data: Encrypted data.
        key: RC4 encryption key.
        salt: Optional salt to use in key derivation.
        iterations: Number of hash iterations to perform if salt is provided.
    """
    ctx = hashlib.md5(key)
    if salt is not None:
        for _ in range(iterations):
            ctx.update(salt)

    cipher = ARC4.new(ctx.digest())
    return cipher.decrypt(data)


def _aes_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt data using AES-CBC.

    Args:
        data: Encrypted data.
        key: AES encryption key.
        iv: Initialization vector.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    if (align := -len(data) % 16) != 0:
        data += b"\x00" * align
    return cipher.decrypt(data)
