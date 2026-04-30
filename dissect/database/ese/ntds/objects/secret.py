from __future__ import annotations

from functools import cached_property
from typing import TYPE_CHECKING
from uuid import UUID

from dissect.util.ts import wintimestamp

from dissect.database.ese.ntds.c_ds import c_ds
from dissect.database.ese.ntds.objects.leaf import Leaf

if TYPE_CHECKING:
    from datetime import datetime


class Secret(Leaf):
    """Represents a secret object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-secret
    """

    __object_class__ = "secret"

    def __repr_body__(self) -> str:
        return f"name={self.name!r} last_set_time={self.last_set_time} prior_set_time={self.prior_set_time}"

    @property
    def current_value(self) -> bytes:
        """Return the current value of the secret."""
        return self.get("currentValue")

    @property
    def last_set_time(self) -> datetime | None:
        """Return the last set time of the secret."""
        if (ts := self.get("lastSetTime")) is not None:
            return wintimestamp(ts)
        return None

    @property
    def prior_value(self) -> bytes:
        """Return the prior value of the secret."""
        return self.get("priorValue")

    @property
    def prior_set_time(self) -> datetime | None:
        """Return the prior set time of the secret."""
        if (ts := self.get("priorSetTime")) is not None:
            return wintimestamp(ts)
        return None


class BackupKey:
    """Represents a DPAPI backup key object in the Active Directory."""

    def __init__(self, secret: Secret):
        self.secret = secret

    def __repr__(self) -> str:
        return f"<BackupKey guid={self.guid} version={self.version}>"

    @cached_property
    def guid(self) -> UUID:
        """The GUID of the backup key."""
        return UUID(self.secret.name.removeprefix("BCKUPKEY_").removesuffix(" Secret"))

    @cached_property
    def version(self) -> int:
        """The version of the backup key."""
        return c_ds.DWORD(self.secret.current_value)

    @cached_property
    def is_legacy(self) -> bool:
        """Whether the backup key is a legacy key (version 1)."""
        return self.version == 1

    @cached_property
    def key(self) -> bytes:
        """The key bytes of the backup key, for legacy keys (version 1)."""
        if self.version == 1:
            return self.secret.current_value[4:]
        raise TypeError(f"Backup key version {self.version} does not have a single key value")

    @cached_property
    def private_key(self) -> bytes:
        """The private key bytes of the backup key, for version 2 keys."""
        if self.version == 2:
            private_length = c_ds.DWORD(self.secret.current_value[4:8])
            return self.secret.current_value[12 : 12 + private_length]
        raise TypeError(f"Backup key version {self.version} does not have a private key value")

    @cached_property
    def public_key(self) -> bytes:
        """The public key bytes of the backup key, for version 2 keys."""
        if self.version == 2:
            private_length = c_ds.DWORD(self.secret.current_value[4:8])
            public_length = c_ds.DWORD(self.secret.current_value[8:12])
            return self.secret.current_value[12 + private_length : 12 + private_length + public_length]
        raise TypeError(f"Backup key version {self.version} does not have a public key value")
