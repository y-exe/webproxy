# Cloudflare deployment folders

Use these paths in Cloudflare Git integrations.

```txt
Pages build command: pnpm pages:build:cloudflare
Pages output directory: cloudflare/pages
Pages root directory: /
Worker name: webproxy
Worker root directory: /
Worker build command: leave empty
Worker deploy command: npx wrangler deploy
```

Public endpoints:

```txt
Frontend: https://yproxy.pages.dev
Worker: https://webproxy.yexe.workers.dev
VPS bridge (Worker-facing only): https://papi.yexe.xyz
```

`papi.yexe.xyz` is only the Worker-facing bridge. The frontend never references
it; all traffic flows through the `webproxy` Worker. Outbound fetching from the
backend egresses via the VPS IP (SOCKS5), never from the home IP.

Recommended Pages environment variables:

```txt
NODE_VERSION=22
PNPM_VERSION=10.12.1
```
