"""Package splunk_app/agentgate/ as agentgate.spl (a tarball)."""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE = REPO_ROOT / "splunk_app" / "agentgate"
OUT = REPO_ROOT / "dist" / "agentgate.spl"


def main() -> int:
    if not SOURCE.is_dir():
        print(f"missing: {SOURCE}")
        return 2
    OUT.parent.mkdir(parents=True, exist_ok=True)

    with tarfile.open(OUT, "w:gz") as tar:
        for path in sorted(SOURCE.rglob("*")):
            if path.is_file():
                arcname = "agentgate/" + str(path.relative_to(SOURCE)).replace("\\", "/")
                tar.add(path, arcname=arcname)
                print(f"  + {arcname}")
    print(f"\nwrote {OUT}  ({OUT.stat().st_size} bytes)")
    print(f"install: Splunk Web -> Apps -> Manage Apps -> Install app from file -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
