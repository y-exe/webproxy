import net from "node:net";
import tls from "node:tls";

// Wisp 等の外向き TCP/TLS を SOCKS5 経由に差し替える。
// 目的: プロキシ対象サイトへの接続の送信元 IP を VPS にし、自宅回線の IP を
// 外部に露出させない。SOCKS プロキシ (WireGuard 経由の VPS) に到達できない
// 場合は接続を失敗させ、直掘りでのフォールバックは行わない (fail-closed)。
//
// 使い方: EGRESS_SOCKS=10.77.0.1:1080 のように host:port を設定すると有効化。
// 未設定または空の場合は何もせず従来どおり直掘りになる。
//
// 実装上の注意:
// - Node 22 では connect 発火中に emit を握りつぶすとストリームのデータフローが
//   開始されないため、ユーザーの connect/data リスナーを一時退避し、SOCKS5
//   ハンドシェイク完了後に復元する。
// - TLSSocket 自身が connect した場合、greeting の socket.write が TLS 暗号化層に
//   吸われて消失する。そのため tls.connect もパッチし、生 net.Socket を
//   「接続前の既存ソケット」として TLS に渡した上で、net 側パッチでトンネルする。

const PROXY_ADDR = (process.env.EGRESS_SOCKS || "").trim();
const HANDSHAKE_TIMEOUT_MS = Number(
	process.env.EGRESS_SOCKS_TIMEOUT_MS || 15000,
);

const SOCKS_VERSION = 0x05;
const CMD_CONNECT = 0x01;
const ATYP_IPV4 = 0x01;
const ATYP_DOMAIN = 0x03;

function isPrivateIPv4(host: string): boolean {
	const parts = host.split(".").map((p) => Number(p));
	if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) {
		return false;
	}
	const [a, b] = parts;
	if (a === 10 || a === 127 || a === 0 || a >= 224) return true; // private/loopback/link-local/multicast
	if (a === 169 && b === 254) return true; // link-local
	if (a === 172 && b >= 16 && b <= 31) return true; // private
	if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT (Tailscale)
	return false;
}

function isPrivateIPv6(host: string): boolean {
	const h = host.toLowerCase();
	if (h === "::1" || h === "::") return true;
	if (h.startsWith("::ffff:")) {
		const mapped = h.slice(7);
		if (net.isIPv4(mapped)) return isPrivateIPv4(mapped);
	}
	// fc00::/7 (ULA), fe80::/10 (link-local), ff00::/8 (multicast)
	const first = h.split(":")[0] || "";
	const b0 = parseInt(first.slice(0, 2), 16);
	const b1 = parseInt(first.slice(2, 4), 16);
	if (Number.isInteger(b0) && Number.isInteger(b1)) {
		if ((b0 & 0xfe) === 0xfc) return true;
		if (b0 === 0xfe && (b1 & 0xc0) === 0x80) return true;
		if (b0 === 0xff) return true;
	}
	return false;
}

function isInternalHostname(host: string): boolean {
	return (
		host === "localhost" ||
		host.endsWith(".cluster.local") ||
		host.endsWith(".svc") ||
		host.endsWith(".internal") ||
		host.endsWith(".lan") ||
		host.endsWith(".local")
	);
}

// 自ノード/クラスタ内や SOCKS プロキシ自体宛ては直掘り。それ以外はトンネル。
function shouldBypass(host: string | undefined): boolean {
	if (!host) return true;
	if (net.isIPv4(host)) return isPrivateIPv4(host);
	if (net.isIPv6(host)) return isPrivateIPv6(host);
	if (isInternalHostname(host)) return true;
	return false;
}

function socks5Request(targetHost: string, targetPort: number): Buffer {
	const port = Buffer.alloc(2);
	port.writeUInt16BE(targetPort);
	if (net.isIPv4(targetHost)) {
		// [ver, cmd, rsv, atyp, 4octet IPv4, port]
		return Buffer.concat([
			Buffer.from([SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_IPV4]),
			Buffer.from(targetHost.split(".").map((p) => Number(p))),
			port,
		]);
	}
	// ドメイン形式 (IPv6 リテラル含む) はプロキシ側で解決させる
	const addr = Buffer.from(targetHost, "utf8");
	if (addr.length > 255) {
		throw new Error(`hostname too long for SOCKS5: ${targetHost}`);
	}
	// [ver, cmd, rsv, atyp, len, domain, port]
	return Buffer.concat([
		Buffer.from([SOCKS_VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, addr.length]),
		addr,
		port,
	]);
}

// プロキシに接続済みのソケット上で SOCKS5 CONNECT を完了させる。
// resolve 時に、SOCKS 応答に続いて届いていた残バイトを返す。
function performSocks5Handshake(
	socket: net.Socket,
	targetHost: string,
	targetPort: number,
): Promise<Buffer> {
	return new Promise<Buffer>((resolve, reject) => {
		let buf = Buffer.alloc(0);
		let stage: 0 | 1 = 0;
		let settled = false;

		const cleanup = () => {
			socket.removeListener("data", onData);
			socket.removeListener("close", onClose);
			socket.removeListener("error", onError);
			clearTimeout(timer);
		};
		const fail = (err: Error) => {
			if (settled) return;
			settled = true;
			cleanup();
			socket.destroy(err);
			reject(err);
		};
		const succeed = (rest: Buffer) => {
			if (settled) return;
			settled = true;
			cleanup();
			resolve(rest);
		};

		const timer = setTimeout(
			() =>
				fail(
					new Error(`SOCKS5 handshake timeout (${targetHost}:${targetPort})`),
				),
			HANDSHAKE_TIMEOUT_MS,
		);

		const onData = (chunk: Buffer) => {
			buf = Buffer.concat([buf, chunk]);
			if (stage === 0) {
				if (buf.length < 2) return;
				if (buf[0] !== SOCKS_VERSION || buf[1] !== 0x00) {
					fail(new Error(`SOCKS5 greeting rejected (code=${buf[1]})`));
					return;
				}
				buf = buf.subarray(2);
				socket.write(socks5Request(targetHost, targetPort));
				stage = 1;
				if (!buf.length) return;
			}
			if (buf.length < 5) return;
			const ver = buf[0];
			const rep = buf[1];
			const atyp = buf[3];
			const addrLen =
				atyp === ATYP_IPV4
					? 4
					: atyp === 0x04
						? 16
						: atyp === ATYP_DOMAIN
							? buf[4]
							: -1;
			if (addrLen < 0) {
				fail(new Error(`SOCKS5 reply with unknown ATYP=${atyp}`));
				return;
			}
			const need = 4 + addrLen + 2;
			if (buf.length < need) return;
			if (ver !== SOCKS_VERSION) {
				fail(new Error(`SOCKS5 reply with unexpected version=${ver}`));
				return;
			}
			if (rep !== 0x00) {
				fail(
					new Error(
						`SOCKS5 CONNECT failed (rep=${rep}) to ${targetHost}:${targetPort}`,
					),
				);
				return;
			}
			succeed(buf.subarray(need));
		};

		const onClose = () =>
			fail(
				new Error(
					`SOCKS5 tunnel to ${targetHost}:${targetPort} closed during handshake`,
				),
			);
		const onError = (err: Error) => fail(err);

		socket.on("data", onData);
		socket.on("close", onClose);
		socket.on("error", onError);

		socket.write(Buffer.from([SOCKS_VERSION, 0x01, 0x00]));
	});
}

export function installEgressSocks(): void {
	if (!PROXY_ADDR) return;
	const idx = PROXY_ADDR.lastIndexOf(":");
	if (idx < 0) throw new Error(`EGRESS_SOCKS must be host:port, got: ${PROXY_ADDR}`);
	const proxyHost = PROXY_ADDR.slice(0, idx).replace(/^\[|\]$/g, "");
	const proxyPort = Number(PROXY_ADDR.slice(idx + 1));
	if (!proxyHost || !Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
		throw new Error(`EGRESS_SOCKS must be host:port, got: ${PROXY_ADDR}`);
	}

	const origConnect = net.Socket.prototype.connect;
	// Node のオーバーロード (options / port / path) をそのまま透過させるため緩い型で受ける
	type ConnectArgs = unknown[];
	(net.Socket.prototype as { connect: (...args: ConnectArgs[]) => net.Socket }).connect =
		function patchedConnect(this: net.Socket, ...args: ConnectArgs) {
			const first = args[0];
			let targetHost: string | undefined;
			let targetPort: number | undefined;
			let bypass = false;

			if (typeof first === "object" && first !== null) {
				const opts = first as {
					path?: string;
					host?: string;
					port?: number | string;
				};
				if (typeof opts.path === "string") bypass = true;
				targetHost = opts.host;
				const parsedPort = Number(opts.port);
				if (Number.isInteger(parsedPort)) targetPort = parsedPort;
			} else if (typeof first === "number") {
				targetPort = first;
				const second = args[1];
				if (typeof second === "string") targetHost = second;
			} else {
				bypass = true;
			}

			if (
				bypass ||
				!targetHost ||
				!Number.isInteger(targetPort) ||
				shouldBypass(targetHost)
			) {
				return origConnect.apply(this, args as never);
			}

			// --- SOCKS5 トンネル ---
			// ユーザーのリスナー/コールバックを退避してからプロキシに接続し、
			// ハンドシェイク完了後に復元する。
			const savedConnect = this.listeners("connect");
			const savedData = this.listeners("data");
			const savedCallbacks = args.slice(1).filter((a) => typeof a === "function");
			const keptArgs = args.filter(
				(a, i) => i === 0 || typeof a !== "function",
			);

			const rewritten = [...keptArgs] as unknown[];
			if (typeof first === "object" && first !== null) {
				rewritten[0] = {
					...(first as object),
					host: proxyHost,
					port: proxyPort,
				};
			} else {
				// connect(port, host, ...) 形式
				rewritten[0] = proxyPort;
				rewritten[1] = proxyHost;
			}

			this.removeAllListeners("connect");
			this.removeAllListeners("data");

			let origError: unknown;
			try {
				origConnect.apply(this, rewritten as never);
			} catch (err) {
				origError = err;
			}

			if (origError !== undefined) {
				// 復元してからエラーを握りつぶさず投げ直す
				for (const l of savedConnect) this.addListener("connect", l);
				for (const l of savedData) this.addListener("data", l);
				throw origError;
			}

			this.once("connect", () => {
				performSocks5Handshake(this, targetHost as string, targetPort as number)
					.then((rest) => {
						for (const l of savedConnect) this.addListener("connect", l);
						for (const l of savedData) this.addListener("data", l);
						for (const cb of savedCallbacks) {
							this.once("connect", cb as (...cbArgs: unknown[]) => void);
						}
						if (rest.length) this.unshift(rest);
						this.emit("connect");
					})
					.catch((err) => {
						// 失敗時は destroy(err) 済み。ユーザーの error/close リスナーに
						// 流れ、直掘りへのフォールバックは意図的に行わない (fail-closed)。
						this.destroy(err as Error);
					});
			});

			return this;
		};

	// TLSSocket 自身が connect すると greeting が TLS 層に吸われるため、
	// 生ソケットを「既存ソケット」として渡し、net 側パッチでトンネルさせる。
	const origTlsConnect = tls.connect;
	(tls as { connect: typeof tls.connect }).connect = function patchedTlsConnect(
		this: unknown,
		...args: unknown[]
	) {
		const options = args[0] as
			| { socket?: unknown; host?: string; port?: number | string }
			| undefined;
		if (
			!options ||
			typeof options !== "object" ||
			options.socket ||
			typeof options.port === "undefined" && !options.host
		) {
			return origTlsConnect.apply(tls, args as never);
		}
		const host = options.host ?? "localhost";
		const port = Number(options.port ?? 443);
		if (!Number.isInteger(port) || shouldBypass(host)) {
			return origTlsConnect.apply(tls, args as never);
		}

		const callbacks = args.slice(1).filter((a) => typeof a === "function");
		const sock = new net.Socket();
		const tlsSocket = origTlsConnect.apply(tls, [
			{ ...(options as object), socket: sock },
			...callbacks,
		] as never);
		// net 側パッチが SOCKS トンネルを確立し、完了後に 'connect' を発火して
		// TLS ハンドシェイクが始まる。
		sock.connect({ host, port });
		return tlsSocket;
	} as typeof tls.connect;

	console.log(
		`egress: routing outbound TCP/TLS via SOCKS5 ${proxyHost}:${proxyPort} (fail-closed)`,
	);
}
