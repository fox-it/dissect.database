from __future__ import annotations

from typing import BinaryIO

from dissect.database.ese.tools.certlog import CertLog


def test_certlog(certlog_db: BinaryIO) -> None:
    db = CertLog(certlog_db)
    assert len(list(db.records("Certificates"))) == 11
    assert len(list(db.records("Requests"))) == 11
    assert len(list(db.records("RequestAttributes"))) == 26
    assert len(list(db.records("CertificateExtensions"))) == 92
    assert len(list(db.records("CRLs"))) == 2
