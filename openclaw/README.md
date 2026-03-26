# OpenClaw Integration

This directory contains the OpenClaw-side integration for the Gmail proxy.

## Files

- **`SKILL.md`** — OpenClaw skill file. Drop this into your workspace skills directory (e.g. `~/.openclaw/workspace/skills/gmail-proxy/SKILL.md`). The agent reads this to understand the API, auth, access tiers, and usage patterns.
- **`gmail-grant.js`** — Hook transform. Drop this into your OpenClaw hooks transforms directory (e.g. `~/.openclaw/hooks/transforms/gmail-grant.js`). Handles approval/denial callbacks from the proxy and resumes the agent session automatically.

## Setup

### 1. Install the skill

```bash
mkdir -p ~/.openclaw/workspace/skills/gmail-proxy
cp openclaw/SKILL.md ~/.openclaw/workspace/skills/gmail-proxy/SKILL.md
```

### 2. Install the hook transform

```bash
cp openclaw/gmail-grant.js ~/.openclaw/hooks/transforms/gmail-grant.js
```

### 3. Register the hook in `openclaw.json`

Add an entry to the `hooks.mappings` array in your OpenClaw config (`~/.openclaw/openclaw.json`):

```json
{
  "id": "gmail-grant",
  "match": { "path": "/gmail-grant" },
  "deliver": false,
  "transform": { "module": "gmail-grant.js" }
}
```

**Important:** `deliver: false` is required. The transform uses `action: 'wake'` to inject a system event directly into the main session. Without `deliver: false`, OpenClaw will also spawn an agent run that produces a confusing response on your messaging channel.

Then restart the OpenClaw gateway for the new mapping to take effect.

### 4. Configure callback credentials in the proxy (optional)

If your OpenClaw instance is behind Cloudflare Access, the proxy needs CF Access credentials to reach your OpenClaw hooks endpoint when firing grant callbacks. Store them in the proxy's own Vault path (`secret/gmail-proxy`):

```bash
bao kv patch secret/gmail-proxy \
  CF-Access-Client-Id="<your-cf-service-token-client-id>" \
  CF-Access-Client-Secret="<your-cf-service-token-client-secret>"
```

The service token needs access to the Cloudflare Access application protecting your OpenClaw instance.

If your OpenClaw instance is not behind Cloudflare Access, you can skip this step.

### 5. Verify

Make a grant request with `callbackUrl` pointing to your hooks endpoint:

```json
{
  "level": 1,
  "messageId": "...",
  "description": "Test callback",
  "callbackUrl": "https://your-openclaw-host/hooks/gmail-grant",
  "callbackCfAuth": true
}
```

Approve it on the approver's phone — your OpenClaw session should wake automatically.

## How It Works

```
Agent requests grant
  → Proxy sends Signal notification to the approver
    → The approver approves on phone
      → Proxy POSTs to /hooks/gmail-grant
        → OpenClaw transform wakes agent session
          → Agent resumes task with active grant
```

No polling required. The callback is fire-and-forget from the proxy's perspective; OpenClaw handles routing to the right session.
