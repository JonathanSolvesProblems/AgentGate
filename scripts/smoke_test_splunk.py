"""End-to-end smoke test: env loads, Splunk SDK auths via bearer token, a search runs."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import urllib3
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")

import splunklib.client as splunk_client  # noqa: E402  (load_dotenv must run first)
import splunklib.results as splunk_results  # noqa: E402

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main() -> int:
    host = os.environ["SPLUNK_HOST"]
    port = int(os.environ.get("SPLUNK_MGMT_PORT", "8089"))
    token = os.environ["SPLUNK_TOKEN"]
    verify_ssl = os.environ.get("SPLUNK_VERIFY_SSL", "false").lower() == "true"

    svc = splunk_client.connect(
        host=host,
        port=port,
        splunkToken=token,
        scheme="https",
        verify=verify_ssl,
    )

    info = svc.info
    print(f"connected: Splunk {info['version']} build {info['build']} on {info['host']}")
    print(f"license: {info['licenseState']} ({info['license_labels'][0]})")
    print(f"kvstore: {info['kvStoreStatus']}")

    job = svc.jobs.oneshot(
        'search index=_internal | head 1 | table _time host source',
        output_mode='json',
    )
    rows = list(splunk_results.JSONResultsReader(job))
    if rows:
        print(f"sample event: {rows[0]}")
    else:
        print("no events returned from _internal (unusual but not fatal)")

    print("\nOK: Splunk SDK auth + search round-trip works.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
