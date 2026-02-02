from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSPKIEnterpriseOID(Top):
    """Represents the msPKI-Enterprise-Oid object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-mspki-enterprise-oid
    """

    __object_class__ = "msPKI-Enterprise-Oid"
