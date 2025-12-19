from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class DisplaySpecifier(Top):
    """Represents a display specifier object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-displayspecifier
    """

    __object_class__ = "displaySpecifier"

    def __repr__(self) -> str:
        return f"<DisplaySpecifier name={self.name!r}>"
