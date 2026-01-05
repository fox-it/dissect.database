from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class Domain(Top):
    """Represents a domain object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-domain
    """

    __object_class__ = "domain"
