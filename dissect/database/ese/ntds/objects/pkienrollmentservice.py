from __future__ import annotations

from dissect.database.ese.ntds.objects.top import Top


class PKIEnrollmentService(Top):
    """Represents the pKIEnrollmentService object in Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-pkienrollmentservice
    """

    __object_class__ = "pKIEnrollmentService"

    def __repr__(self) -> str:
        return f"<PKIEnrollmentService name={self.name!r}>"
