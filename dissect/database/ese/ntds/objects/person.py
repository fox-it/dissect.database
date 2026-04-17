from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class Person(Top):
    """Represents a person object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-person
    """

    __object_class__ = "person"

    @property
    def telephone_number(self) -> str | None:
        """Return the telephone number of this person."""
        return self.get("telephoneNumber")

    @property
    def user_password(self) -> str | None:
        """Return the userPassword attribute of this person."""
        return self.get("userPassword")
