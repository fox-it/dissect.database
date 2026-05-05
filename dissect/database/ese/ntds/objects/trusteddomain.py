from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from dissect.database.ese.ntds.objects.leaf import Leaf
from dissect.database.ese.ntds.util import TrustAttribute, TrustDirection, TrustType

if TYPE_CHECKING:
    from dissect.database.ese.ntds.objects.object import DecoderMap


class TrustedDomain(Leaf):
    """Represents a trusted domain object in the Active Directory.

    References:
        - https://learn.microsoft.com/en-us/windows/win32/adschema/c-trusteddomain
    """

    __object_class__ = "trustedDomain"
    __decoders__: ClassVar[DecoderMap] = {
        "trustType": lambda db, value: TrustType(value),
        "trustDirection": lambda db, value: TrustDirection(value),
        "trustAttributes": lambda db, value: TrustAttribute(value),
    }

    @property
    def trust_type(self) -> TrustType | None:
        """Return the trustType of this trusted domain."""
        return self.get("trustType")

    @property
    def trust_direction(self) -> TrustDirection | None:
        """Return the trustDirection of this trusted domain."""
        return self.get("trustDirection")

    @property
    def trust_attributes(self) -> TrustAttribute | None:
        """Return the trustAttributes of this trusted domain."""
        return self.get("trustAttributes")

    @property
    def trust_partner(self) -> str | None:
        """Return the trustPartner of this trusted domain."""
        return self.get("trustPartner")

    @property
    def security_identifier(self) -> str | None:
        """Return the securityIdentifier of this trusted domain."""
        return self.get("securityIdentifier")
