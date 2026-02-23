from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.util.ts import wintimestamp

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
