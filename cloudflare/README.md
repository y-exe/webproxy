# Cloudflare deployment folders

The Pages project `yproxy` and the Worker `webproxy` are connected to this
GitHub repository (`y-exe/webproxy`) through Cloudflare Git integrations.
Pushes to `main` build and deploy automatically.

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
Frontend: https://yproxy.pages.dev (+ https://proxy.yexe.xyz)
Worker: https://webproxy.yexe.workers.dev
VPS bridge (Worker-facing only): https://papi.yexe.xyz
```

`papi.yexe.xyz` is only the Worker-facing bridge. The frontend never references
it; all traffic flows through the `webproxy` Worker. Outbound fetching from the
backend egresses via the VPS IP (SOCKS5), never from the home IP.

The Pages build image (v3) provides Node 22 and picks pnpm 10.12.1 up from
`packageManager`, so no extra build environment variables are needed.
