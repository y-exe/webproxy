import http from "node:http";
import "dotenv/config";
import { server as wisp } from "@mercuryworkshop/wisp-js/server";
import { createPersistentCookieMiddleware } from "./persistentCookies.ts";
import { installEgressSocks } from "./egressSocks.ts";

const PORT = Number(process.env.EDGE_BACKEND_PORT || process.env.PORT || 4143);
const EDGE_SHARED_SECRET = process.env.EDGE_SHARED_SECRET || "";

// 外向き TCP を SOCKS5 (VPS) 経由にする。未設定なら従来どおり直掘り。
installEgressSocks();

wisp.options.allow_private_ips = false;
wisp.options.allow_loopback_ips = false;
wisp.options.allow_direct_ip = false;
wisp.options.allow_udp_streams = false;
wisp.options.port_whitelist = [80, 443];
wisp.options.stream_limit_per_host = Number(
  process.env.WISP_STREAM_LIMIT_PER_HOST || 8,
);
wisp.options.stream_limit_total = Number(process.env.WISP_STREAM_LIMIT_TOTAL || 64);

// SOCKS5 (VPS) 経由のエグレス時は、名前解決も VPS 側に任せる。
// ローカルで解決すると DNS クエリが自宅回線から漏れるため、
// カスタム dns_method でホスト名をそのまま返し、SOCKS5 の ATYP_DOMAIN で
// プロキシ側 (VPS) に解決させる。
if (process.env.EGRESS_SOCKS) {
  wisp.options.dns_method = async (hostname: string) => hostname;
} else {
  wisp.options.dns_method = "resolve";
  wisp.options.dns_servers = (process.env.WISP_DNS_SERVERS || "1.1.1.1,1.0.0.1")
    .split(",")
    .map((server) => server.trim())
    .filter(Boolean);
  wisp.options.dns_result_order = "ipv4first";
}
wisp.options.hostname_blacklist = [
  /^localhost$/i,
  /\.local$/i,
  /\.internal$/i,
  /\.lan$/i,
  /\.home$/i,
];

const cookieMiddleware = createPersistentCookieMiddleware();

function isAuthorized(req: http.IncomingMessage) {
  if (!EDGE_SHARED_SECRET) return true;
  return req.headers["x-edge-secret"] === EDGE_SHARED_SECRET;
}

const server = http.createServer((req, res) => {
  if (!isAuthorized(req)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("forbidden");
    return;
  }

  if (req.url?.startsWith("/api/cookies")) {
    cookieMiddleware(req, res, () => {
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Cookie API route not found." }));
    });
    return;
  }

  if (req.url === "/healthz") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("backend route not found");
});

server.on("upgrade", (req, socket, head) => {
  if (!isAuthorized(req)) {
    socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    socket.destroy();
    return;
  }

  if (req.url?.startsWith("/wisp/")) {
    wisp.routeRequest(req, socket, head);
    return;
  }

  socket.destroy();
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Scramjet edge backend listening on http://0.0.0.0:${PORT}`);
});
