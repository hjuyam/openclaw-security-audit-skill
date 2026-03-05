#!/usr/bin/env python3
"""OpenClaw Security Audit (diagnostic-only).

Generates a Markdown report with evidence snippets.

Usage:
  python3 audit.py --out reports/security/openclaw-audit-YYYY-MM-DD.md

Safe by design:
- Reads system state and configs.
- Does NOT modify firewall/proxy/system settings.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import shlex
import subprocess
from pathlib import Path

WORKSPACE = Path(os.environ.get("OPENCLAW_WORKSPACE", "/root/.openclaw/workspace"))
DEFAULT_OUT_DIR = WORKSPACE / "reports" / "security"


def run(cmd: str, timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        out = p.stdout or ""
        return p.returncode, out.strip()
    except subprocess.TimeoutExpired:
        return 124, f"[timeout after {timeout}s] {cmd}"


def clip(s: str, max_chars: int = 1200) -> str:
    s = (s or "").strip()
    if len(s) <= max_chars:
        return s
    return s[: max_chars - 20] + "\n…[truncated]…"


def md_codeblock(s: str) -> str:
    return "```\n" + (s or "") + "\n```\n"


def find_files(globs: list[str], base: Path = Path("/")) -> list[Path]:
    hits: list[Path] = []
    for g in globs:
        hits.extend(base.glob(g))
    # unique + existing
    out = []
    seen = set()
    for p in hits:
        if p.exists() and str(p) not in seen:
            seen.add(str(p))
            out.append(p)
    return out


def scan_text_for_patterns(text: str, patterns: dict[str, list[str]] | None = None) -> dict[str, list[str]]:
    patterns = patterns or {
        "url_credentials": [r"token=", r"gatewayUrl=", r"key=", r"secret=", r"Authorization"],
        "reverse_proxy_18789": [r"reverse_proxy\s+127\.0\.0\.1:18789", r"reverse_proxy\s+localhost:18789"],
    }
    findings: dict[str, list[str]] = {k: [] for k in patterns}
    lines = (text or "").splitlines()
    for i, line in enumerate(lines, 1):
        for k, ps in patterns.items():
            for p in ps:
                if re.search(p, line, re.IGNORECASE):
                    findings[k].append(f"L{i}: {line.strip()}")
    return {k: v for k, v in findings.items() if v}


def main():
    ap = argparse.ArgumentParser()
    today = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    ap.add_argument("--out", default=str(DEFAULT_OUT_DIR / f"openclaw-audit-{today}.md"))
    args = ap.parse_args()

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    host = platform.node()
    os_name = platform.platform()
    now = dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00','Z')

    # Collect: openclaw gateway status (best-effort)
    # Some environments can be slow; use a longer timeout.
    rc_gw, gw_status = run("openclaw gateway status", timeout=25)

    # Collect: listeners
    rc_ss, ss_out = run("ss -lntup", timeout=10)
    if rc_ss != 0:
        rc_ss, ss_out = run("netstat -an", timeout=10)

    # Collect: ufw
    rc_ufw, ufw_out = run("sudo -n ufw status verbose", timeout=10)

    # Config scan: Caddy/Nginx/Apache (best-effort)
    scan_targets: list[tuple[str, list[Path]]] = []

    if Path("/etc/caddy").exists():
        files = list(Path("/etc/caddy").rglob("*.conf")) + [Path("/etc/caddy/Caddyfile")]
        scan_targets.append(("Caddy", [p for p in files if p.exists()]))

    if Path("/etc/nginx").exists():
        files = list(Path("/etc/nginx").rglob("*.conf"))
        scan_targets.append(("Nginx", [p for p in files if p.exists()]))

    if Path("/etc/apache2").exists():
        files = list(Path("/etc/apache2").rglob("*.conf")) + list(Path("/etc/apache2").rglob("*.load"))
        scan_targets.append(("Apache", [p for p in files if p.exists()]))

    cfg_findings: dict[str, dict[str, dict[str, list[str]]]] = {}
    cfg_evidence: list[str] = []

    patterns = {
        "url_credentials": [r"token=", r"gatewayUrl=", r"key=", r"secret=", r"Authorization"],
        "reverse_proxy_18789": [r"reverse_proxy\s+127\.0\.0\.1:18789", r"reverse_proxy\s+localhost:18789"],
        "proxy_pass_18789": [r"proxy_pass\s+http://127\.0\.0\.1:18789", r"proxy_pass\s+http://localhost:18789"],
    }

    for label, files in scan_targets:
        per_file: dict[str, dict[str, list[str]]] = {}
        for p in sorted(set(files)):
            try:
                txt = p.read_text("utf-8", errors="ignore")
            except Exception:
                continue
            f = scan_text_for_patterns(txt, patterns=patterns)
            if f:
                per_file[str(p)] = f
                lines = []
                for k, arr in f.items():
                    lines.append(f"# {k}")
                    lines.extend(arr[:30])
                cfg_evidence.append(f"### {label}: {p}\n" + md_codeblock("\n".join(lines)))
        if per_file:
            cfg_findings[label] = per_file

    # Docker published ports (best effort)
    rc_docker, docker_ps = run("docker ps --format '{{.Names}}\t{{.Ports}}'", timeout=10)

    # Basic conclusions
    risks = []
    if "0.0.0.0:18789" in ss_out or ":::18789" in ss_out:
        risks.append(("P0", "Gateway appears to listen on a public interface (0.0.0.0/::) on 18789."))
    # URL credential leakage patterns
    url_leak = any(
        "url_credentials" in finding
        for per in cfg_findings.values()
        for finding in [k for f in per.values() for k in f.keys()]
    )
    if url_leak:
        risks.append(("P0", "Reverse proxy config contains URL credential leakage patterns (token=/gatewayUrl=/key=/secret=)."))

    proxy_to_gw = any(
        ("reverse_proxy_18789" in finding or "proxy_pass_18789" in finding)
        for per in cfg_findings.values()
        for finding in [k for f in per.values() for k in f.keys()]
    )
    if proxy_to_gw:
        risks.append(("P1", "Reverse proxy routes traffic to OpenClaw gateway (18789). Ensure strong access control."))

    # Render report
    lines: list[str] = []
    lines.append(f"# OpenClaw Security Audit Report\n")
    lines.append(f"- Generated at (UTC): **{now}**")
    lines.append(f"- Host: **{host}**")
    lines.append(f"- OS: **{os_name}**\n")

    lines.append("## Executive Summary")
    if not risks:
        lines.append("- No high-confidence P0/P1 issues detected by automated checks. (This is not a guarantee.)\n")
    else:
        for sev, msg in risks[:10]:
            lines.append(f"- **{sev}**: {msg}")
        lines.append("")

    lines.append("## Assessment Style (Neutral)")
    lines.append("- This report is **neutral** by design: it highlights *possible* risks, provides evidence snippets, and suggests verification steps.")
    lines.append("- Final decisions depend on your environment (cloud security groups/WAF, internal network topology, and your threat model).\n")

    lines.append("## 1) Exposure Surface (Listening Ports)")
    lines.append(md_codeblock(clip(ss_out)))

    lines.append("## 2) OpenClaw Gateway Status")
    lines.append(md_codeblock(clip(gw_status)))

    lines.append("## 3) Reverse Proxy / Public Entrypoints (Caddy/Nginx/Apache)")
    if not cfg_findings:
        lines.append("No suspicious patterns detected in proxy configs under /etc/{caddy,nginx,apache2} (best-effort scan).\n")
    else:
        lines.append("Findings (matched patterns):\n")
        for label, per in cfg_findings.items():
            keys = sorted({k for f in per.values() for k in f.keys()})
            lines.append(f"- **{label}**: {', '.join(keys)}")
        lines.append("")
        lines.extend(cfg_evidence)

    lines.append("## 4) Firewall Snapshot (UFW, best effort)")
    lines.append(md_codeblock(clip(ufw_out)))

    lines.append("## 5) Docker Published Ports (best effort)")
    if rc_docker != 0:
        lines.append("Docker not available or not permitted.\n")
    else:
        lines.append(md_codeblock(clip(docker_ps)))

    lines.append("## 6) Recommendations (Prioritized)")
    lines.append("### P0 (Fix first)")
    lines.append("- Remove any **long-lived credentials** from URLs/redirect rules/logs.")
    lines.append("  - Why: URLs leak via browser history, referrers, screenshots, and proxy logs.")
    lines.append("  - Operational risk: Changing proxy rules can break access; keep a rollback plan.")
    lines.append("- Ensure OpenClaw gateway is not directly reachable from the public internet.")
    lines.append("  - Why: public reachability + known/unknown bugs = high takeover risk.")
    lines.append("  - Operational risk: Tightening firewall/proxy rules can lock you out if you also block SSH.")

    lines.append("### P1 (Hardening)")
    lines.append("- Minimize open ports; prefer allowlist for SSH/admin surfaces.")
    lines.append("  - Operational risk: Port/ACL changes can interrupt legitimate services.")
    lines.append("- Keep OpenClaw updated; verify configs don’t reintroduce insecure defaults.")

    lines.append("## Next step")
    lines.append("Reply with what you want to do next:")
    lines.append("1) Create a remediation plan for the P0/P1 findings")
    lines.append("2) Reduce exposure (ports/proxy) with a step-by-step, reversible procedure")
    lines.append("3) Re-run the audit after changes to validate improvements")

    out_path.write_text("\n".join(lines), "utf-8")
    print(str(out_path))


if __name__ == "__main__":
    main()
