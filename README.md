# openclaw-security-audit-skill

A cross-platform **diagnostic** security audit skill for OpenClaw deployments (Windows / macOS / Linux).

This skill is intentionally **non-destructive**: it focuses on *detection, evidence collection, and neutral assessment*, then provides prioritized recommendations **with risks/trade-offs**, and asks the user what to do next.

## What it does

- Detects OpenClaw exposure risks (e.g., public listening ports, reverse-proxy re-exposure, URL credential leakage patterns).
- Collects evidence (command output snippets, matched config lines) into a Markdown report.
- Produces **neutral findings**: “possible risk” + “why it matters” + “how to verify” + “recommended next steps”.

## What it does NOT do

- Does **not** automatically change firewall/proxy/system settings.
- Does **not** log into servers, rotate credentials, or run destructive commands.

## Output

- A Markdown report written to:
  - `reports/security/openclaw-audit-YYYY-MM-DD.md`

## Usage

Run the audit script:

```bash
python3 skills/openclaw-security-audit/scripts/audit.py
```

Specify output:

```bash
python3 skills/openclaw-security-audit/scripts/audit.py \
  --out reports/security/openclaw-audit-YYYY-MM-DD.md
```

## Optional configuration (advanced)

Default mode is **zero-config auto-detect**.

If you want stricter “unexpected public ports” judgments, provide an optional config YAML (example in `references/config.example.yaml`).

## Security notes

This skill runs read-only checks that may include:

- Listing listening ports / processes
- Reading proxy configuration files (Caddy/Nginx/Apache)
- Inspecting Docker published ports
- Reading OpenClaw status output

Some evidence collection may attempt commands that require elevated privileges (e.g., `sudo -n ufw status`). If not permitted, the report will note the limitation.

## Operational risk warnings

Even though this skill is diagnostic-only, follow-up remediation can be risky:

- Firewall / reverse-proxy changes can lock you out (especially SSH) if done incorrectly.
- Always keep an out-of-band access method (cloud console / KVM / provider rescue mode) before making networking changes.

---

License: see repository license.
