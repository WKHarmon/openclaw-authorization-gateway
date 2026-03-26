#!/usr/bin/env python3
"""One-time OAuth setup for Gmail API access.

Run this on a machine with a browser. It reads client_id/client_secret from
vault, runs the OAuth consent flow, and stores the resulting refresh_token
back in vault.

Requires: VAULT_ADDR, VAULT_ROLE_ID, and VAULT_SECRET_ID environment variables.
"""

import json
import os
import sys

import httpx
from google_auth_oauthlib.flow import InstalledAppFlow

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Default config — override via command-line or environment
VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_ROLE_ID = os.environ.get("VAULT_ROLE_ID", "")
VAULT_SECRET_ID = os.environ.get("VAULT_SECRET_ID", "")
VAULT_PATH = os.environ.get("VAULT_SECRET_PATH", "secret/gmail-proxy")

_vault_token: str = ""


def vault_login():
    """Authenticate to Vault via AppRole and cache the client token."""
    global _vault_token
    resp = httpx.post(
        f"{VAULT_ADDR}/v1/auth/approle/login",
        json={"role_id": VAULT_ROLE_ID, "secret_id": VAULT_SECRET_ID},
        timeout=10.0,
    )
    resp.raise_for_status()
    _vault_token = resp.json()["auth"]["client_token"]


def vault_api_path() -> str:
    parts = VAULT_PATH.split("/", 1)
    return f"{parts[0]}/data/{parts[1]}" if len(parts) > 1 else f"{parts[0]}/data"


def vault_read_all() -> dict:
    resp = httpx.get(
        f"{VAULT_ADDR}/v1/{vault_api_path()}",
        headers={"X-Vault-Token": _vault_token},
        timeout=10.0,
    )
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    return resp.json().get("data", {}).get("data", {})


def vault_write(data: dict):
    # Read existing, merge, write back
    current = vault_read_all()
    current.update(data)
    resp = httpx.post(
        f"{VAULT_ADDR}/v1/{vault_api_path()}",
        headers={"X-Vault-Token": _vault_token},
        json={"data": current},
        timeout=10.0,
    )
    resp.raise_for_status()


def main():
    if not VAULT_ROLE_ID or not VAULT_SECRET_ID:
        print("ERROR: VAULT_ROLE_ID and VAULT_SECRET_ID environment variables must be set.")
        print("  export VAULT_ADDR=... VAULT_ROLE_ID=... VAULT_SECRET_ID=...")
        sys.exit(1)

    print(f"Vault: {VAULT_ADDR}")
    print(f"Secret path: {VAULT_PATH}")
    print()

    print("Authenticating to Vault via AppRole...")
    vault_login()
    print("  Vault login successful.")
    print()

    # Read client credentials from vault
    print("Reading OAuth client credentials from vault...")
    secrets = vault_read_all()
    client_id = secrets.get("client_id", "")
    client_secret = secrets.get("client_secret", "")

    if not client_id or not client_secret:
        print("ERROR: client_id and client_secret must be stored in vault first:")
        print(f"  bao kv put {VAULT_PATH} client_id=YOUR_ID client_secret=YOUR_SECRET")
        sys.exit(1)

    print(f"  client_id: {client_id[:20]}...")
    print()

    # Run OAuth flow
    client_config = {
        "installed": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": ["http://localhost:8090"],
        }
    }

    flow = InstalledAppFlow.from_client_config(client_config, SCOPES)

    print("Starting OAuth flow on port 8090...")
    print("If running on a remote server, tunnel port 8090 first:")
    print("  ssh -L 8090:localhost:8090 user@your-server.example.com")
    print()

    creds = flow.run_local_server(
        port=8090, prompt="consent", access_type="offline",
        open_browser=False,
    )

    if not creds.refresh_token:
        print("WARNING: No refresh_token received. You may need to revoke access")
        print("  at https://myaccount.google.com/permissions and try again.")
        sys.exit(1)

    # Store tokens in vault
    print("Storing tokens in vault...")
    vault_write(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": creds.refresh_token,
            "access_token": creds.token,
        }
    )

    print()
    print("OAuth setup complete. Tokens stored in vault.")
    print(f"  Vault path: {VAULT_PATH}")
    print(f"  Scopes: {SCOPES}")


if __name__ == "__main__":
    main()
