from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSPKIPrivateKeyRecoveryAgent(Top):
    """Represents the msPKI-PrivateKeyRecoveryAgent object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-mspki-privatekeyrecoveryagent
    """

    __object_class__ = "msPKI-PrivateKeyRecoveryAgent"
