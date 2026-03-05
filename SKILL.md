---
name: openclaw-security-audit
description: Cross-platform (Windows/macOS/Linux) diagnostic security audit for OpenClaw deployments. Use when the user wants to check whether an OpenClaw instance is exposed (ports, bind addresses, reverse proxy), assess common risk patterns (URL token leakage, leaked secrets, outdated versions/CVEs checklist), and generate a human-readable Markdown report with evidence and prioritized recommendations. Focus on diagnostics and reporting (no auto-remediation).
---

# openclaw-security-audit

## Output
- Primary: Markdown report saved under `reports/security/openclaw-audit-<YYYY-MM-DD>.md`

## Operating mode
- **Diagnostics only** by default (do not change firewall/proxy/system settings).
- Include **evidence snippets** for each finding (command output summaries, file excerpts).

## Required sections in report
1) Executive summary (risk counts + top 3)
2) Exposure surface (listening ports + bind addresses)
3) Reverse proxy/public entrypoints (Caddy/Nginx/Apache) and **URL credential leakage** checks
4) Version/patch checklist for known OpenClaw exposure patterns (checklist + local evidence only)
5) Secrets hygiene (tokens in env/config; file permissions; obvious leaks in proxy configs)
6) Docker/networking (published ports)
7) Baseline host hardening quick checks (non-invasive: SSH exposure, updates signal)
8) Recommendations by priority (P0/P1/P2) with “how to verify fixed”

## Removed on purpose
- **Auth/session policy checks** are intentionally omitted for generality (varies by deployment).

## Optional section (only if detected or enabled in config)
- Proxy/tunnel services exposure (xray/sing-box/tailscale/cloudflared/frp/etc.)

## Platform notes
- Prefer Python scripts in `scripts/` and shell out to native tools when present.
- If a tool is missing (e.g., `ss` on macOS), degrade gracefully and record the limitation.

## Bundled scripts
- `scripts/audit.py`: main entry
- `scripts/collectors.py`: platform-specific collectors (optional)

## Default checks (minimum viable)
- Detect OpenClaw gateway port + bind address from `openclaw gateway status` when available
- Enumerate listening ports/processes
- Detect Caddy/Nginx config files and search for patterns:
  - reverse_proxy to OpenClaw port
  - token in URL / query injection (e.g., `token=`)
- Docker published ports (`docker ps` + `docker port` where available)
- UFW status (Linux) when available

