from __future__ import annotations

import argparse
import datetime
import json
import typing
from pathlib import Path
from typing import BinaryIO

from dissect.util.ts import wintimestamp

from dissect.database.ese import ESE
from dissect.database.ese.c_ese import JET_coltyp
from dissect.database.ese.util import RecordValue

if typing.TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.table import Table

CertLogValue = RecordValue | datetime.datetime

SKIP_TABLES = [
    "MSysObjects",
    "MSysObjectsShadow",
    "MSysObjids",
    "MSysLocales",
]

# Value from certutil -view -restrict "RequestID=XX"
REQUEST_TYPE = {0x100: "PKCS10", 0x40100: "PKCS10, Full Response"}
REQUEST_DISPOSITION = {0x14: "Issued", 0x1F: "Denied", 0xF: "Ca cert"}

REQUEST_STATUS_CODE = {
    0x0: "The operation completed successfully",
    0x80094001: "CERTSRV_E_BAD_REQUESTSUBJECT",
    0x80094002: "CERTSRV_E_NO_REQUEST",
    0x80094003: "CERTSRV_E_BAD_REQUESTSTATUS",
    0x80094004: "CERTSRV_E_PROPERTY_EMPTY",
    0x80094005: "CERTSRV_E_INVALID_CA_CERTIFICATE",
    0x80094006: "CERTSRV_E_SERVER_SUSPENDED",
    0x80094007: "CERTSRV_E_ENCODING_LENGTH",
    0x80094008: "CERTSRV_E_ROLECONFLICT",
    0x80094009: "CERTSRV_E_RESTRICTEDOFFICER",
    0x8009400A: "CERTSRV_E_KEY_ARCHIVAL_NOT_CONFIGURED",
    0x8009400B: "CERTSRV_E_NO_VALID_KRA",
    0x8009400C: "CERTSRV_E_BAD_REQUEST_KEY_ARCHIVAL",
    0x8009400D: "CERTSRV_E_NO_CAADMIN_DEFINED",
    0x8009400E: "CERTSRV_E_BAD_RENEWAL_CERT_ATTRIBUTE",
    0x8009400F: "CERTSRV_E_NO_DB_SESSIONS",
    0x80094010: "CERTSRV_E_ALIGNMENT_FAULT",
    0x80094011: "CERTSRV_E_ENROLL_DENIED",
    0x80094012: "CERTSRV_E_TEMPLATE_DENIED",
    0x80094013: "CERTSRV_E_DOWNLEVEL_DC_SSL_OR_UPGRADE",
    0x80094014: "CERTSRV_E_ADMIN_DENIED_REQUEST",
    0x80094015: "CERTSRV_E_NO_POLICY_SERVER",
    0x80094016: "CERTSRV_E_WEAK_SIGNATURE_OR_KEY",
    0x80094017: "CERTSRV_E_KEY_ATTESTATION_NOT_SUPPORTED",
    0x80094018: "CERTSRV_E_ENCRYPTION_CERT_REQUIRED",
    0x80094800: "CERTSRV_E_UNSUPPORTED_CERT_TYPE",
    0x80094801: "CERTSRV_E_NO_CERT_TYPE",
    0x80094802: "CERTSRV_E_TEMPLATE_CONFLICT",
    0x80094803: "CERTSRV_E_SUBJECT_ALT_NAME_REQUIRED",
    0x80094804: "CERTSRV_E_ARCHIVED_KEY_REQUIRED",
    0x80094805: "CERTSRV_E_SMIME_REQUIRED",
    0x80094806: "CERTSRV_E_BAD_RENEWAL_SUBJECT",
    0x80094807: "CERTSRV_E_BAD_TEMPLATE_VERSION",
    0x80094808: "CERTSRV_E_TEMPLATE_POLICY_REQUIRED",
    0x80094809: "CERTSRV_E_SIGNATURE_POLICY_REQUIRED",
    0x8009480A: "CERTSRV_E_SIGNATURE_COUNT",
    0x8009480B: "CERTSRV_E_SIGNATURE_REJECTED",
    0x8009480C: "CERTSRV_E_ISSUANCE_POLICY_REQUIRED",
    0x8009480D: "CERTSRV_E_SUBJECT_UPN_REQUIRED",
    0x8009480E: "CERTSRV_E_SUBJECT_DIRECTORY_GUID_REQUIRED",
    0x8009480F: "CERTSRV_E_SUBJECT_DNS_REQUIRED",
    0x80094810: "CERTSRV_E_ARCHIVED_KEY_UNEXPECTED",
    0x80094811: "CERTSRV_E_KEY_LENGTH",
    0x80094812: "CERTSRV_E_SUBJECT_EMAIL_REQUIRED",
    0x80094813: "CERTSRV_E_UNKNOWN_CERT_TYPE",
    0x80094814: "CERTSRV_E_CERT_TYPE_OVERLAP",
    0x80094815: "CERTSRV_E_TOO_MANY_SIGNATURES",
    0x80094816: "CERTSRV_E_RENEWAL_BAD_PUBLIC_KEY",
    0x80094817: "CERTSRV_E_INVALID_EK",
    0x80094818: "CERTSRV_E_INVALID_IDBINDING",
    0x80094819: "CERTSRV_E_INVALID_ATTESTATION",
    0x8009481A: "CERTSRV_E_KEY_ATTESTATION",
    0x8009481B: "CERTSRV_E_CORRUPT_KEY_ATTESTATION",
    0x8009481C: "CERTSRV_E_EXPIRED_CHALLENGE",
    0x8009481D: "CERTSRV_E_INVALID_RESPONSE",
    0x8009481E: "CERTSRV_E_INVALID_REQUESTID",
    0x8009481F: "CERTSRV_E_REQUEST_PRECERTIFICATE_MISMATCH",
    0x80094820: "CERTSRV_E_PENDING_CLIENT_RESPONSE",
    0x80094821: "CERTSRV_E_SEC_EXT_DIRECTORY_SID_REQUIRED",
}


class CertLog:
    def __init__(self, fh: BinaryIO):
        self.db = ESE(fh)

    def tables(self) -> list[Table]:
        return [table for table in self.db.tables() if table.name not in SKIP_TABLES]

    def records(self, table_name: str) -> Iterator[dict[str, CertLogValue]]:
        try:
            table = self.db.table(table_name)
        except KeyError:
            return None

        for record in table.records():
            record_data = {"TableName": table.name}

            for column in table.columns:
                value = record.get(column.name)

                if column.type == JET_coltyp.DateTime and value:
                    value = wintimestamp(value)

                if table.name == "Requests":
                    if column.name == "StatusCode":
                        value = REQUEST_STATUS_CODE.get(value & 0xFFFFFFFF, value & 0xFFFFFFFF)
                    if column.name == "Disposition":
                        value = REQUEST_DISPOSITION.get(value, value)
                    if column.name == "RequestType":
                        value = REQUEST_TYPE.get(value, value)

                record_data[column.name] = value

            yield record_data

    def entries(self) -> Iterator[dict[str, CertLogValue]]:
        for table in self.tables():
            yield from self.records(table.name)


def main() -> None:
    parser = argparse.ArgumentParser(description="dissect.database.ese Certlog parser")
    parser.add_argument("input", help="certlog database to read")
    parser.add_argument("-t", "--table", metavar="TABLE", help="show only content of TABLE (case sensitive)")
    parser.add_argument("-j", "--json", help="output in JSON format", action="store_true", default=False)
    args = parser.parse_args()

    with Path(args.input).open("rb") as fh:
        parser = CertLog(fh)

        for table in parser.tables():
            if args.table and table.name != args.table:
                continue
            for record in parser.records(table.name):
                if args.json:
                    print(json.dumps(record, default=str))
                else:
                    print(record)


if __name__ == "__main__":
    main()
