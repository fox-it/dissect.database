from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class RRASAdministrationDictionary(Top):
    """Represents the rRASAdministrationDictionary object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-rrasadministrationdictionary
    """

    __object_class__ = "rRASAdministrationDictionary"
