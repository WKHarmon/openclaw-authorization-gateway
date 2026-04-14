"""Configuration loading and constants.

Config file resolution order (first match wins):
  1. ``GATEWAY_CONFIG`` env var (absolute or relative path)
  2. ``<repo root>/config.json``

If neither exists the module still imports with an empty ``CONFIG`` dict — this
is deliberate so tests / tooling can import gateway modules without a real
production config on disk. Production deployments should always provide one of
the above.
"""

import json
import logging
import os
from pathlib import Path

log = logging.getLogger("gateway")

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = BASE_DIR / "config.json"
DATA_DIR = BASE_DIR / "data"
AUDIT_LOG_PATH = DATA_DIR / "audit.jsonl"
GRANTS_DB_PATH = DATA_DIR / "grants.db"

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_ROLE_ID = os.environ.get("VAULT_ROLE_ID", "")
VAULT_SECRET_ID = os.environ.get("VAULT_SECRET_ID", "")
VAULT_ENABLED = bool(VAULT_ROLE_ID and VAULT_SECRET_ID)

MAX_GRANT_DURATION_MINUTES = 1440  # 24 hours


def _resolve_config_path() -> Path | None:
    """Return the Path to load config from, or None if nothing is available."""
    override = os.environ.get("GATEWAY_CONFIG", "").strip()
    if override:
        p = Path(override).expanduser()
        if not p.is_absolute():
            p = (BASE_DIR / p).resolve()
        return p
    if DEFAULT_CONFIG_PATH.exists():
        return DEFAULT_CONFIG_PATH
    return None


# Exposed for backward compat — tests that set it directly still work, but
# prefer the ``GATEWAY_CONFIG`` env var for new code.
CONFIG_PATH = _resolve_config_path() or DEFAULT_CONFIG_PATH


def load_config() -> dict:
    """Load the resolved config file. Returns ``{}`` when no config file is
    available (e.g. in a fresh checkout used only for tests)."""
    path = _resolve_config_path()
    if path is None:
        log.warning(
            "No config.json found at %s and GATEWAY_CONFIG is unset — "
            "loading with empty config.",
            DEFAULT_CONFIG_PATH,
        )
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        log.warning("Config file %s not found — loading with empty config.", path)
        return {}


def load_sensitive_patterns(config: dict) -> dict:
    path = BASE_DIR / config.get("sensitive_patterns_file", "sensitive_patterns.json")
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {"redact_subjects": [], "redact_senders": []}


CONFIG = load_config()
SENSITIVE = load_sensitive_patterns(CONFIG)


def get_requestors() -> dict[str, dict]:
    """Return the requestors map, normalizing from legacy single-agent config if needed.

    New format (config.json has "requestors" key):
        {"Lisa": {"api_key_vault_path": "...", "callback": {...}}, ...}

    Legacy format (config.json has "agent_name" + "vault_api_key_path" + "callback"):
        Auto-generates a single-entry requestors map.
    """
    if "requestors" in CONFIG:
        return CONFIG["requestors"]

    # Legacy single-agent config
    name = CONFIG.get("agent_name", "Agent")
    return {
        name: {
            "api_key_vault_path": CONFIG.get("vault_api_key_path", ""),
            "callback": CONFIG.get("callback"),
        }
    }
