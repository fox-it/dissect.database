from __future__ import annotations

import argparse
import json
from pathlib import Path

from dissect.database.ese.ntds import NTDS


def main() -> None:
    parser = argparse.ArgumentParser(description="dissect.database.ese.ntds NTDS parser")
    parser.add_argument("input", help="NTDS database to read")
    parser.add_argument("-c", "--objectClass", help="show only objects of this class", required=True)
    parser.add_argument("-j", "--json", action="store_true", default=False, help="output in JSON format")
    args = parser.parse_args()

    with Path(args.input).open("rb") as fh:
        ntds = NTDS(fh)

        for record in ntds.search(objectClass=args.objectClass):
            if args.json:
                print(json.dumps(record.as_dict(), default=str))
            else:
                print(record)


if __name__ == "__main__":
    main()
