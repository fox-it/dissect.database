from __future__ import annotations

from dissect.database.ese.ntds.objects.object import Object


class Top(Object):
    """Represents the top object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-top
    """

    __object_class__ = "top"

    def __repr_body__(self) -> str:
        return f"name={self.name!r}"
