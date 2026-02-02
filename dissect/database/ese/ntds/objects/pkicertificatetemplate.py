from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class PKICertificateTemplate(Top):
    """Represents a PKI certificate template object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-pkicertificatetemplate
    """

    __object_class__ = "pKICertificateTemplate"
