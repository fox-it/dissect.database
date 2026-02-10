from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dissect.database.ese.ntds import NTDS


def test_pek(goad: NTDS) -> None:
    """Test PEK unlocking and decryption."""
    syskey = bytes.fromhex("079f95655b66f16deb28aa1ab3a81eb0")

    user = next((u for u in goad.users() if u.name == "ESSOS$"), None)
    assert user is not None

    encrypted = user.unicodePwd
    # Verify encrypted value
    assert encrypted == bytes.fromhex(
        "1300000000000000248a47921aa22e6886017494709f23bb10000000708afcb8360cfb0b4a972c5bc65b2864540436aad24654c2e037c83eafe70d43"
    )

    assert user.lmPwdHistory == [
        bytes.fromhex(
            "1300000000000000771e30dbd13e7f1a641ecd8e3ec85765200000005e5c46e1eb6ffaff7bee7fa75a092215e5c9bc34e1223a09322f9c15260310b98b30a2045e2f1bc8dcab1ad8b8ce13c3"
        )
    ]

    goad.pek.unlock(syskey)
    assert goad.pek.unlocked

    # Test decryption of the user's password
    assert goad.pek.decrypt(encrypted) == bytes.fromhex("909e2178d8b7944d60a5cd2053fef570")
    # Should work transparently now too
    assert user.unicodePwd == bytes.fromhex("909e2178d8b7944d60a5cd2053fef570")
    assert user.lmPwdHistory == [
        bytes.fromhex("f4badffd76f158087909e33b4e4b40c1"),
        bytes.fromhex("4383d43a2d9bbc9bda43c5a3d0e4f38c"),
    ]
    assert user.ntPwdHistory == [
        bytes.fromhex("909e2178d8b7944d60a5cd2053fef570"),
        bytes.fromhex("909e2178d8b7944d60a5cd2053fef570"),
    ]


def test_pek_adam(adam: NTDS) -> None:
    """Test PEK unlocking and decryption for AD LDS NTDS.dit."""
    # The PEK in AD LDS is derived within the database itself
    assert adam.pek.unlocked

    user = next(adam.users(), None)
    assert user.unicodePwd == bytes.fromhex("8846f7eaee8fb117ad06bdd830b7586c")
