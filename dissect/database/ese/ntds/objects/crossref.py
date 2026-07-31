from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from dissect.database.ese.ntds.objects.top import Top
from dissect.database.ese.ntds.util import SystemFlagCrossRef

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects.object import DecoderMap


class CrossRef(Top):
    """Represents a cross-reference object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-crossref
    """

    __object_class__ = "crossRef"
    __decoders__: ClassVar[DecoderMap] = {
        "systemFlags": lambda db, value: SystemFlagCrossRef(value),
    }

    @property
    def behavior_version(self) -> int | None:
        """Return the msDS-Behavior-Version of this cross-reference."""
        return self.get("msDS-Behavior-Version")
