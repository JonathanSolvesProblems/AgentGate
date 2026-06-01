"""Centralised Splunk SDK client + thin REST helper for endpoints the SDK doesn't model cleanly."""

from __future__ import annotations

from functools import cache
from typing import Any

import httpx
import splunklib.client as splunk_client
import urllib3

from .config import get_settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@cache
def get_service() -> splunk_client.Service:
    s = get_settings()
    return splunk_client.connect(
        host=s.splunk_host,
        port=s.splunk_mgmt_port,
        splunkToken=s.splunk_token,
        scheme="https",
        verify=s.splunk_verify_ssl,
    )


@cache
def get_rest_client() -> httpx.Client:
    s = get_settings()
    return httpx.Client(
        base_url=s.splunk_mgmt_base,
        headers={"Authorization": f"Bearer {s.splunk_token}"},
        verify=s.splunk_verify_ssl,
        timeout=30.0,
    )


def rest(method: str, path: str, **kwargs: Any) -> httpx.Response:
    client = get_rest_client()
    params = kwargs.pop("params", {}) or {}
    params.setdefault("output_mode", "json")
    return client.request(method, path, params=params, **kwargs)
