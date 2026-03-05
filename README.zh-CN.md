# openclaw-security-audit-skill

一个面向 OpenClaw 部署环境的 **跨平台诊断型** 安全审计 Skill（Windows / macOS / Linux）。

这个 Skill 的设计原则是 **不做自动修复（non-destructive）**：专注于 *侦测风险 + 收集证据 + 中性评估*，然后给出分级建议（包含操作的副作用/风险），并询问用户下一步要怎么处理。

## 它能做什么

- 侦测常见 OpenClaw 暴露风险（例如：公网监听端口、反向代理“二次暴露”、URL 凭证泄露模式等）
- 将证据片段（命令输出摘要、配置命中行）写入 Markdown 报告
- 输出“中性结论”：**可能风险** + **为什么重要** + **如何验证** + **建议下一步**

## 它不会做什么

- **不会** 自动修改防火墙/反代/系统配置
- **不会** 自动 SSH 登录到其他机器、轮换密钥、执行破坏性命令

## 输出

- Markdown 报告默认写入：
  - `reports/security/openclaw-audit-YYYY-MM-DD.md`

## 使用方法

直接运行审计脚本：

```bash
python3 skills/openclaw-security-audit/scripts/audit.py
```

指定输出路径：

```bash
python3 skills/openclaw-security-audit/scripts/audit.py \
  --out reports/security/openclaw-audit-YYYY-MM-DD.md
```

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

许可证见仓库 License。
