"""Centralised settings loaded once from .env, used everywhere."""

from __future__ import annotations

import os
from functools import cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel

REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env")


class Settings(BaseModel):
    splunk_host: str
    splunk_mgmt_port: int
    splunk_web_port: int
    splunk_token: str
    splunk_verify_ssl: bool

    ollama_host: str
    ollama_model: str
    ollama_fallback_model: str

    splunk_mcp_url: str
    splunk_mcp_token: str

    audit_index: str
    hec_url: str
    hec_token: str

    @property
    def splunk_mgmt_base(self) -> str:
        return f"https://{self.splunk_host}:{self.splunk_mgmt_port}"


@cache
def get_settings() -> Settings:
    return Settings(
        splunk_host=os.environ.get("SPLUNK_HOST", "localhost"),
        splunk_mgmt_port=int(os.environ.get("SPLUNK_MGMT_PORT", "8089")),
        splunk_web_port=int(os.environ.get("SPLUNK_WEB_PORT", "8000")),
        splunk_token=os.environ["SPLUNK_TOKEN"],
        splunk_verify_ssl=os.environ.get("SPLUNK_VERIFY_SSL", "false").lower() == "true",
        ollama_host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        ollama_model=os.environ["OLLAMA_MODEL"],
        ollama_fallback_model=os.environ.get("OLLAMA_FALLBACK_MODEL", "llama3.1:8b"),
        splunk_mcp_url=os.environ.get("SPLUNK_MCP_URL", ""),
        splunk_mcp_token=os.environ.get("SPLUNK_MCP_TOKEN", ""),
        audit_index=os.environ.get("AGENTGATE_AUDIT_INDEX", "agentgate_audit"),
        hec_url=os.environ.get("AGENTGATE_HEC_URL", "https://localhost:8088/services/collector/event"),
        hec_token=os.environ.get("AGENTGATE_HEC_TOKEN", ""),
    )
