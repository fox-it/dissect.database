from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class Site(Top):
    """Represents the site object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-site
    """

    __object_class__ = "site"

    def __repr__(self) -> str:
        return f"<Site name={self.name!r}>"
