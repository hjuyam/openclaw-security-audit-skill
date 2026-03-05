# openclaw-security-audit-skill

> 默认显示中文。English version is available below.

## 使用方法（第一步就这么用）

1. **把本项目链接丢给你的「小龙虾」（OpenClaw）**，让它按本 Skill 对当前环境进行安全检查并输出报告：
   - Repo: https://github.com/hjuyam/openclaw-security-audit-skill
2. 在 OpenClaw 所在机器上运行审计脚本（零配置、自动侦测）：

```bash
python3 skills/openclaw-security-audit/scripts/audit.py
```

3. 指定输出路径（可选）：

```bash
python3 skills/openclaw-security-audit/scripts/audit.py \
  --out reports/security/openclaw-audit-YYYY-MM-DD.md
```

## 这个 Skill 做什么

- 跨平台（Windows / macOS / Linux）的 **诊断型** OpenClaw 安全审计
- 侦测常见暴露风险（监听端口、公网入口、反代二次暴露、URL 凭证泄露模式等）
- 收集证据片段（命令输出摘要、配置命中行），生成 Markdown 报告
- 采用 **中性评估**：说明“可能风险 / 为什么重要 / 建议动作 / 建议动作带来的风险”，并询问用户下一步操作

## 它不会做什么

- **不会** 自动修改防火墙/反代/系统配置
- **不会** 自动 SSH 登录到其他机器、轮换密钥、执行破坏性命令

## 输出

- Markdown 报告默认写入：
  - `reports/security/openclaw-audit-YYYY-MM-DD.md`

## 可选配置（高级用法）

默认是 **零配置自动侦测**。

如果你希望对“哪些公网端口属于异常”做更严格判断，可以提供一个可选 YAML 配置（示例见 `references/config.example.yaml`）。

## Skill 自身的安全行为说明

本 Skill 默认只做“读取/侦测”，可能包含：

- 枚举监听端口与进程
- 读取反向代理配置（Caddy/Nginx/Apache）并匹配风险模式
- 检查 Docker 对外暴露端口
- 调用 OpenClaw 状态命令

部分证据收集会尝试执行需要更高权限的命令（例如 `sudo -n ufw status`）。若无权限，会在报告里明确写出“缺失项/限制”。

## 重要风险提示（面向后续修复动作）

虽然本 Skill 不会自动修复，但你在按建议手工修复时要注意：

- 防火墙/反代/端口收口这类操作如果做错，**可能把 SSH 也一并封死**，导致把自己锁在门外。
- 做网络相关修改前，务必确保你有云厂商控制台/KVM/救援模式等“兜底入口”。

---

<details>
<summary><b>English (click to expand)</b></summary>

# openclaw-security-audit-skill

## Usage (recommended first step)

1. **Send this repository link to your OpenClaw agent**, and ask it to run this skill to generate a security audit report.
   - Repo: https://github.com/hjuyam/openclaw-security-audit-skill
2. Run the audit script on the machine where OpenClaw is deployed (zero-config, auto-detect):

```bash
python3 skills/openclaw-security-audit/scripts/audit.py
```

3. Optional: specify output path:

```bash
python3 skills/openclaw-security-audit/scripts/audit.py \
  --out reports/security/openclaw-audit-YYYY-MM-DD.md
```

## What it does

- Cross-platform (Windows/macOS/Linux) diagnostic security audit for OpenClaw deployments
- Detects common exposure risks (listening ports, public entrypoints, reverse-proxy re-exposure, URL credential leakage patterns)
- Collects evidence snippets and generates a Markdown report
- Uses a **neutral assessment** style: possible risk / why it matters / suggested action / operational risks, then asks what to do next

## What it does NOT do

- Does NOT automatically change firewall/proxy/system settings
- Does NOT SSH into machines, rotate secrets, or run destructive commands

## Output

- Markdown report written to:
  - `reports/security/openclaw-audit-YYYY-MM-DD.md`

## Optional configuration

Default mode is **zero-config auto-detect**.

If you want stricter “unexpected public ports” judgments, provide an optional YAML config (see `references/config.example.yaml`).

## Security behavior of this skill

This skill is read-only by default. It may:

- List listening ports/processes
- Read reverse proxy configs (Caddy/Nginx/Apache) and match risky patterns
- Inspect Docker published ports
- Read OpenClaw status output

Some evidence collection may try privileged commands (e.g., `sudo -n ufw status`). If not permitted, the report will note the limitation.

## Operational risk warnings (for remediation)

Even though this skill is diagnostic-only, remediation can be risky:

- Firewall / reverse-proxy changes can lock you out (especially SSH) if done incorrectly.
- Keep an out-of-band access method (cloud console/KVM/rescue mode) before making networking changes.

</details>
