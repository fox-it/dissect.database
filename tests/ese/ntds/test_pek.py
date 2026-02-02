from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.database.ese.ntds import NTDS


def test_pek(goad: NTDS) -> None:
    """Test PEK unlocking and decryption."""
    syskey = bytes.fromhex("079f95655b66f16deb28aa1ab3a81eb0")

    user = next(goad.users(), None)
    assert user is not None

    encrypted = user.unicodePwd
    # Verify encrypted value
    assert encrypted == bytes.fromhex(
        "130000000000000029fbdaafb52bf724a51052f668152ac5100000006d06616d95c026064fff245bd256f3d4990f7bffb546f76de566723da4855227"
    )

    goad.pek.unlock(syskey)
    assert goad.pek.unlocked

    # Test decryption of the user's password
    assert goad.pek.decrypt(encrypted) == bytes.fromhex("06bb564317712dc60761a32914e4048c")
    # Should work transparently now too
    assert user.unicodePwd == bytes.fromhex("06bb564317712dc60761a32914e4048c")


def test_pek_adam(adam: NTDS) -> None:
    """Test PEK unlocking and decryption for AD LDS NTDS.dit."""
    # The PEK in AD LDS is derived within the database itself
    assert adam.pek.unlocked

    user = next(adam.users(), None)
    assert user.unicodePwd == bytes.fromhex("8846f7eaee8fb117ad06bdd830b7586c")
