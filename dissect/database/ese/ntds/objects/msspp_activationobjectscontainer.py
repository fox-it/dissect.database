from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSSPPActivationObjectsContainer(Top):
    """Represents the msSPP-ActivationObjectsContainer object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msspp-activationobjectscontainer
    """

    __object_class__ = "msSPP-ActivationObjectsContainer"
