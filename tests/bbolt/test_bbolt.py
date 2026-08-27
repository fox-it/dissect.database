from __future__ import annotations

from dissect.database.bbolt import Bbolt, BoltDB
from tests._util import absolute_path

container_id = "5fc9c48c9ee7a72c4e733a19c0388e6d7b26413fd0949f855067bfb8dd2d2181"


def test_bbolt_meta_db() -> None:
    """Test if we can parse a containerd meta.db file. Created on amd64 Debian 13.6.0 with Docker 29.7.2."""
    path = absolute_path("_data/bbolt/meta.db")
    db = Bbolt(path)

    assert db.version == 2
    assert db.page_size == 4096

    assert db.keys() == ["v1"]
    assert db.keys("v1") == ["moby", "version"]
    assert db.get("v1 version") == "\x08"
    assert db.keys("v1 moby") == [
        "containers",
        "content",
        "images",
        "leases",
        "snapshots",
    ]

    assert db.keys("v1\\moby", sep="\\") == [
        "containers",
        "content",
        "images",
        "leases",
        "snapshots",
    ]

    assert db.keys(f"v1 moby snapshots overlayfs {container_id}") == [
        "createdat",
        "name",
        "parent",
        "updatedat",
    ]

    name = db.get(f"v1 moby snapshots overlayfs {container_id} name")
    assert name == f"moby/18/{container_id}"

    assert db.keys("v1 moby containers") == [container_id]

    assert db.keys(f"v1 moby containers {container_id}") == [
        "createdat",
        "image",
        "labels",
        "runtime",
        "sandboxid",
        "snapshotKey",
        "snapshotter",
        "spec",
        "updatedat",
    ]
    assert db.keys(f"v1 moby containers {container_id} labels") == ["com.docker/engine.bundle.path"]
    assert (
        db.get(f"v1 moby containers {container_id} labels com.docker/engine.bundle.path")
        == f"/var/run/docker/containerd/{container_id}"
    )


def test_bbolt_metadata_db() -> None:
    """Test if we can parse a containerd metadata.db file. Created on amd64 Debian 13.6.0 with Docker 29.7.2."""
    path = absolute_path("_data/bbolt/metadata.db")
    db = BoltDB(path)

    assert db.keys() == ["v1"]
    assert db.keys("v1") == ["parents", "snapshots"]
    assert db.keys("v1 snapshots") == [
        "moby/10/36cd9d816e2c23639eee0d4cb933d76ddc482761dd07cddb64a3f9f83c7fbb3f-init",
        "moby/11/36cd9d816e2c23639eee0d4cb933d76ddc482761dd07cddb64a3f9f83c7fbb3f",
        "moby/13/sha256:b577adbc0b589bb7c1d3be98cc4b703e8228ab4413156754445e8b20a001c5d3",
        "moby/15/sha256:82198e809c0011c54f98a18f72fcb1db9d563c8835cff6d37126dbb030a8302c",
        f"moby/17/{container_id}-init",
        f"moby/18/{container_id}",
        "moby/2/sha256:897b3f2a7c1bc2f3d02432f7892fe31c6272c521ad4d70257df624504a3238b4",
        "moby/4/13553351c913076aa74e1ef76519aa82127cf85121413eb5fe5002731d97556c-init",
        "moby/5/13553351c913076aa74e1ef76519aa82127cf85121413eb5fe5002731d97556c",
        "moby/7/abf09ccc5e9d25015bd042a3139f9ecd387c711f81ff5fde20093515b9825a5b-init",
        "moby/8/abf09ccc5e9d25015bd042a3139f9ecd387c711f81ff5fde20093515b9825a5b",
    ]

    assert db.keys(f"v1 snapshots moby/18/{container_id}") == [
        "createdat",
        "id",
        "kind",
        "parent",
        "updatedat",
    ]

    id = db.get(f"v1 snapshots moby/18/{container_id} id", decode=False)
    assert id == b"\x0b"

    assert db.get(
        f"v1 snapshots moby/18/{container_id} createdat",
        decode=False,
    ) == bytes.fromhex("010000000ee2221c201f08a2f6ffff")
