from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class CertificationAuthority(Top):
    """Represents a Certification Authority object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-certificationauthority
    """

    __object_class__ = "certificationAuthority"
