# Pages + Worker + VPS deployment

This setup makes the public site look like it is served by Cloudflare Pages and
Workers, while the actual Scramjet Wisp server and cookie API stay behind your
VPS reverse proxy.

## Traffic path

```txt
browser
  -> https://yproxy.pages.dev          static frontend (Cloudflare Pages)
  -> https://webproxy.yexe.workers.dev thin reverse proxy Worker (no business logic)
  -> https://papi.yexe.xyz             VPS nginx (Cloudflare-only ingress)
  -> k3s Traefik on yexeserver         proxy-edge-backend pod (the real backend)
  -> outbound fetching                 via SOCKS5 on the VPS (egress IP = VPS)
```

`papi.yexe.xyz` is only the Worker-facing bridge. Do not present it as the
public user URL. Nothing in the frontend or the Worker's public surface may
reference `papi.yexe.xyz` directly; the only place it appears is the Worker's
`VPS_ORIGIN` variable (server-side, not exposed to visitors).

## Frontend on Cloudflare Pages

Build the frontend and required Scramjet assets for Pages locally:

```sh
pnpm pages:build
```

Use this Cloudflare Pages Git configuration:

```txt
Framework preset: None
Production branch: main
Build command: pnpm pages:build:cloudflare
Build output directory: cloudflare/pages
Root directory: /
```

Add these Pages build environment variables:

```txt
NODE_VERSION=22
PNPM_VERSION=10.12.1
```

The Pages output generator writes a Cloudflare `_headers` file that keeps the
service worker scope at `/`.

The committed production env points the Pages frontend at the Worker:

```env
VITE_API_ORIGIN=https://webproxy.yexe.workers.dev
VITE_WISP_URL=wss://webproxy.yexe.workers.dev/wisp/
```

Because `yproxy.pages.dev` and `webproxy.yexe.workers.dev` are
separate origins, the Worker must allow `https://yproxy.pages.dev` through CORS.

## Worker Git deploy

Connect the existing Worker named `webproxy` to the same GitHub
repository. Use the repository root so Wrangler can read the root
`wrangler.toml`:

```txt
Root directory: /
Build command: leave empty
Deploy command: npx wrangler deploy
```

If you want to target the nested config explicitly, this also works:

```txt
Root directory: /
Build command: leave empty
Deploy command: pnpm worker:deploy:cloudflare
```

It is already configured for the current VPS bridge:

```toml
VPS_ORIGIN = "https://papi.yexe.xyz"
ALLOWED_ORIGIN = "https://yproxy.pages.dev"
```

If the Worker is on a different origin than Pages, set `ALLOWED_ORIGIN` too.
Same-host routes are strongly preferred because browser credentials and service
worker behavior stay simpler.

With the current `workers.dev` / `pages.dev` split, no custom route is required
yet. The Worker is directly available at:

```txt
https://webproxy.yexe.workers.dev
```

If a custom domain is added later, route `/api/*`, `/wisp/*`, and `/healthz` to
the Worker and let Pages own every other path.

## Backend (yexeserver / k3s)

The production backend (`proxy-edge-backend`) runs as a k3s Deployment on
`yexeserver` and is managed by the GitOps repo (`y-exe/vps`, Argo auto-sync).
The image is built by GH Actions from this repo's `Dockerfile.edge-backend` and
pushed to `ghcr.io/y-exe/proxy-edge-backend` (tags: `latest` + `sha-<short>`).

To roll out a backend change:

1. Commit + push to `main` (paths `server/**`, `pnpm-lock.yaml`, etc. trigger the
   GHCR build).
2. Update `newTag` in `apps/proxy-edge-backend/kustomization.yaml` of the vps
   repo and push. Argo syncs the Deployment.

The pod listens on port 4143 and exposes:

```txt
/api/cookies/*
/wisp/*          (WebSocket)
/healthz
```

Hardening for public proxy operation:

```txt
Wisp destination ports: 80, 443 only
Wisp UDP: disabled
Direct IP destinations: disabled
Private and loopback IP destinations: disabled
Per-host stream limit: WISP_STREAM_LIMIT_PER_HOST, default 8
Total stream limit: WISP_STREAM_LIMIT_TOTAL, default 64
```

### VPS-IP egress (SOCKS5)

All outbound fetching (viewing proxied sites) leaves through the VPS so the
home IP is never exposed to target sites, even under abuse:

```txt
EGRESS_SOCKS=10.77.0.1:1080   (set in apps/proxy-edge-backend/app.yaml)
```

- `10.77.0.1:1080` is `socks-egress.service` (microsocks) on the VPS, bound to
  the WireGuard interface only.
- `server/egressSocks.ts` patches `net`/`tls` at the prototype level: public
  TCP/TLS connects are routed through SOCKS5; the proxy is unreachable ->
  connection fails (fail-closed, never falls back to a direct connect).
- While `EGRESS_SOCKS` is set, wisp hands hostnames to the proxy
  (`ATYP_DOMAIN`) so DNS is resolved on the VPS as well — no DNS leaks from the
  home network.
- The k3s NetworkPolicy `allow-wg-egress-socks` opens only `10.77.0.1:1080/tcp`
  for this pod; UFW on the VPS allows 1080 only from the WireGuard subnet.

### Local development (legacy)

Run the backend-only server directly on the host:

```sh
pnpm backend:edge
```

`scripts/redeploy-edge-backend.ps1` predates the k3s cutover and only rebuilds
the local Windows Docker container; it is not part of production anymore.

## papi.yexe.xyz (VPS ingress)

nginx on the VPS terminates TLS for `papi.yexe.xyz` and forwards to the k3s
Traefik ingress (`10.77.0.2:80`), which routes to the backend Service. The
server block includes the `cloudflare-only` snippet: direct requests not coming
from Cloudflare edge IPs receive `403`, so `papi.yexe.xyz` can only be reached
through the `webproxy` Worker.

Keep the Worker transparent: do not rewrite HTML or buffer response bodies at
the Worker layer.
