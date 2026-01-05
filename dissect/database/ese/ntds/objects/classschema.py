from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class ClassSchema(Top):
    """Represents a class schema object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-classschema
        - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/ccd55373-2fa6-4237-9f66-0d90fbd866f5
    """

    __object_class__ = "classSchema"

    @property
    def system_must_contain(self) -> list[str]:
        """Return a list of LDAP display names of attributes this class system must contain."""
        if (system_must_contain := self.get("systemMustContain")) is not None:
            return system_must_contain
        return []

    @property
    def system_may_contain(self) -> list[str]:
        """Return a list of LDAP display names of attributes this class system may contain."""
        if (system_may_contain := self.get("systemMayContain")) is not None:
            return system_may_contain
        return []

    @property
    def must_contain(self) -> list[str]:
        """Return a list of LDAP display names of attributes this class must contain."""
        if (must_contain := self.get("mustContain")) is not None:
            return must_contain
        return []

    @property
    def may_contain(self) -> list[str]:
        """Return a list of LDAP display names of attributes this class may contain."""
        if (may_contain := self.get("mayContain")) is not None:
            return may_contain
        return []
