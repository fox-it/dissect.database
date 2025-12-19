from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class MSDFSRSubscriber(Top):
    """Represents the MSDFSR Subscriber object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsrsubscriber
    """

    __object_class__ = "msDFSR-Subscriber"

    def __repr__(self) -> str:
        return f"<MSDFSRSubscriber name={self.name!r}>"
