from __future__ import annotations

from dissect.database.ese.ntds.objects.person import Person


class OrganizationalPerson(Person):
    """Represents an organizational person object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-organizationalperson
    """

    __object_class__ = "organizationalPerson"

    @property
    def city(self) -> str | None:
        """Return the city (l) of this organizational person."""
        return self.get("l")  # "l" (localityName) represents the city/locality.

    @property
    def mail(self) -> str | None:
        """Return the mail address of this organizational person."""
        return self.get("mail")

    @property
    def title(self) -> str | None:
        """Return the title of this organizational person."""
        return self.get("title")

    @property
    def allowed_to_act_on_behalf_of_other_identity(self) -> str | None:
        """Return the msDS-AllowedToActOnBehalfOfOtherIdentity attribute of this organizational person."""
        return self.get("msDS-AllowedToActOnBehalfOfOtherIdentity")
