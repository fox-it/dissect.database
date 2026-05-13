from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from dissect.database.ese.ntds.objects.top import Top
from dissect.database.ese.ntds.util import SearchFlag, SystemFlagAttribute

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects.object import DecoderMap


class AttributeSchema(Top):
    """Represents an attribute schema object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-attributeschema
    """

    __object_class__ = "attributeSchema"
    __decoders__: ClassVar[DecoderMap] = {
        "searchFlags": lambda db, value: SearchFlag(value),
        "systemFlags": lambda db, value: SystemFlagAttribute(value),
    }

    @property
    def search_flags(self) -> SearchFlag | None:
        """Return the searchFlags of this attribute schema."""
        return self.get("searchFlags")
