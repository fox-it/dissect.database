from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class BuiltinDomain(Top):
    """Represents a built-in domain object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-builtindomain
    """

    __object_class__ = "builtinDomain"
