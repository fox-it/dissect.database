from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from dissect.database.ese.ntds.objects.top import Top

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects import Computer


class MSFVERecoveryInformation(Top):
    """Represents a msFVE-RecoveryInformation object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-msfve-recoveryinformation
    """

    __object_class__ = "msFVE-RecoveryInformation"

    @property
    def volume_guid(self) -> UUID:
        """Return the volume GUID associated with this recovery information."""
        return UUID(bytes_le=self.get("msFVE-VolumeGuid"))

    @property
    def recovery_guid(self) -> UUID:
        """Return the recovery GUID associated with this recovery information."""
        return UUID(bytes_le=self.get("msFVE-RecoveryGuid"))

    @property
    def recovery_password(self) -> str | None:
        """Return the recovery password associated with this recovery information."""
        return self.get("msFVE-RecoveryPassword")

    @property
    def key_package(self) -> bytes | None:
        """Return the key package associated with this recovery information, if any."""
        return self.get("msFVE-KeyPackage")

    def computer(self) -> Computer:
        """Return the computer object associated with this recovery information."""
        if (parent := self.parent()) is None:
            raise ValueError("msFVE-RecoveryInformation object has no parent computer")
        return parent
