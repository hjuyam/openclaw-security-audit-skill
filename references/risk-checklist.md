# OpenClaw Exposure Risk Checklist (Diagnostic)

This checklist is used for **diagnosis** and report generation. It is intentionally conservative.

## R1 Public exposure of gateway
- Gateway binds to `0.0.0.0` or `::` on a public host
- Or gateway is loopback-only but exposed via reverse proxy without strong access control

## R2 URL credential leakage
- Any long-lived credential in URL query (`token=...`, `key=...`, etc.)
- Redirect rules that inject `gatewayUrl` and `token` into the browser address bar

## R3 Localhost is not automatically safe
- Web pages can attempt to connect to localhost WebSocket endpoints
- Lack of rate limiting / short sessions increases brute-force risk

## R4 Secrets hygiene
- Tokens in world-readable files
- Secrets committed to git
- Logs containing secrets

## R5 Patch hygiene (checklist only)
- Verify the deployment is updated to a version that includes security fixes
- Verify configs are not reintroducing old insecure defaults

