from __future__ import annotations

from dissect.database.ese.ntds.objects.person import Person


class OrganizationalPerson(Person):
    """Represents an organizational person object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-organizationalperson
    """

    __object_class__ = "organizationalPerson"

    @property
    def city(self) -> str:
        """Return the city (l) of this organizational person."""
        return self.get("l")  # "l" (localityName) represents the city/locality.
