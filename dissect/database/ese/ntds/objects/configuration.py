from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class Configuration(Top):
    """Represents a configuration object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-configuration
    """

    __object_class__ = "configuration"

    @property
    def gp_link(self) -> str | None:
        """Return the group policy link of the configuration."""
        return self.get("gPLink")
