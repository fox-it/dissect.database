from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSTPMInformationObjectsContainer(Top):
    """Represents a TPM information objects container in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-mstpm-informationobjectscontainer
    """

    __object_class__ = "msTPM-InformationObjectsContainer"
