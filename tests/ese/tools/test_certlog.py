from __future__ import annotations

from typing import BinaryIO

from dissect.database.ese.tools.certlog import CertLog


def test_certlog(certlog_db: BinaryIO) -> None:
    db = CertLog(certlog_db)
    assert len(list(db.get_table_records("Certificates"))) == 11
    assert len(list(db.get_table_records("Requests"))) == 11
    assert len(list(db.get_table_records("RequestAttributes"))) == 26
    assert len(list(db.get_table_records("CertificateExtensions"))) == 92
    assert len(list(db.get_table_records("CRLs"))) == 2
