/**
 * Callback oracle: a local HTTP listener that proves out-of-band effect,
 * rather than inferring exploitability from response text. A unique nonce
 * is embedded in a payload; if the target (or something the target's shell
 * command reaches) makes an HTTP request bearing that nonce back to this
 * listener before the timeout, the vulnerability is CONFIRMED, not just
 * suspected from static schema inspection.
 *
 * Scope limitation (intentional, not deferred silently): this is a
 * same-host loopback listener, not external DNS/HTTP collaborator
 * infrastructure (interactsh-style). It proves:
 *   - command injection that can reach the scanning host's own network
 *   - SSRF that can reach the scanning host's own network
 * It does NOT prove SSRF/exfil reaching genuine external infrastructure
 * (e.g. a real cloud metadata endpoint reachable only from inside someone
 * else's VPC). That requires real external collaborator infrastructure,
 * which is a separate, larger build.
 *
 * It binds to 127.0.0.1 by default, sufficient when there's no container
 * network namespace in the way (SSE targets; anything not routed through
 * sandbox.ts). For containerized stdio targets, liveScan.ts constructs
 * this with whichever bind host sandbox.ts's TargetSandbox determines is
 * actually reachable on this Docker backend (`oracleBindHost`) — plain
 * host loopback on Docker Desktop (verified empirically, and the backend
 * these claims were measured on: the gateway address Docker reports is
 * real only *inside* Desktop's VM, not bindable from this host process at
 * all, and a loopback bind is what a callback actually reaches via
 * Desktop's own host-proxy plumbing), or the scan's sandbox network's own
 * gateway address on native Linux Engine (where a container is not
 * expected to reach a host listener bound to 127.0.0.1 at all, since a
 * loopback-bound socket only accepts loopback-origin connections — that
 * path follows documented behavior and is not verified end-to-end here;
 * see sandbox.ts's header). `advertisedHost` lets the *embedded* callback URL
 * differ from the bind host: the payload a container-side process sees
 * needs `host.docker.internal` (mapped by sandbox.ts to whichever address
 * containers on that network actually reach the host through), since
 * `127.0.0.1` inside the container means the container itself, not this
 * listener.
 */
import { createServer, type IncomingMessage, type Server } from "node:http";
import { randomBytes } from "node:crypto";

export interface CallbackEvent {
  nonce: string;
  receivedAt: string;
  remoteAddress: string | undefined;
  method: string;
  path: string;
}

export interface CallbackOracleOptions {
  /** Host to embed in callbackUrl()'s payload URLs. Defaults to the bind host. */
  advertisedHost?: string;
}

export class CallbackOracle {
  private server: Server | null = null;
  private host: string;
  private advertisedHost: string;
  private boundPort = 0;
  private events = new Map<string, CallbackEvent[]>();
  private waiters = new Map<string, ((event: CallbackEvent) => void)[]>();

  constructor(host = "127.0.0.1", opts: CallbackOracleOptions = {}) {
    this.host = host;
    this.advertisedHost = opts.advertisedHost ?? host;
  }

  async start(): Promise<void> {
    if (this.server) throw new Error("CallbackOracle already started");
    this.server = createServer((req, res) => this.handle(req, res));
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(0, this.host, () => resolve());
    });
    const address = this.server.address();
    if (address === null || typeof address === "string") {
      throw new Error("CallbackOracle: expected an AddressInfo from listen()");
    }
    this.boundPort = address.port;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
  }

  /** The actual bound port. Throws if start() hasn't completed yet. */
  get port(): number {
    if (this.boundPort === 0) throw new Error("CallbackOracle not started");
    return this.boundPort;
  }

  get baseUrl(): string {
    // A literal IPv6 host would need bracketing; loopback/bridge IPv4 is
    // the supported case for this pass (see class docstring).
    return `http://${this.host}:${this.port}`;
  }

  /** A fresh, unguessable nonce, prefixed for readability in logs/reports. */
  newNonce(label: string): string {
    const safeLabel = label.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 24) || "probe";
    return `${safeLabel}-${randomBytes(8).toString("hex")}`;
  }

  /**
   * The callback URL to embed in a crafted payload for this nonce. Uses
   * advertisedHost, not the bind host — see class docstring for why those
   * two differ for containerized targets.
   */
  callbackUrl(nonce: string): string {
    return `http://${this.advertisedHost}:${this.port}/cb/${nonce}`;
  }

  private handle(req: IncomingMessage, res: import("node:http").ServerResponse): void {
    const path = req.url ?? "/";
    const match = /^\/cb\/([a-zA-Z0-9_-]+)/.exec(path);
    res.writeHead(200, { "content-type": "text/plain" }).end("ok");
    if (!match) return;
    const nonce = match[1]!;
    const event: CallbackEvent = {
      nonce,
      receivedAt: new Date().toISOString(),
      remoteAddress: req.socket.remoteAddress,
      method: req.method ?? "GET",
      path,
    };
    const list = this.events.get(nonce) ?? [];
    list.push(event);
    this.events.set(nonce, list);
    const pending = this.waiters.get(nonce);
    if (pending) {
      this.waiters.delete(nonce);
      for (const resolve of pending) resolve(event);
    }
  }

  /**
   * Resolves with the first callback bearing this nonce, or null if none
   * arrives within timeoutMs. A null result means "no callback observed" —
   * it does NOT mean "not vulnerable" (egress could be blocked, the
   * payload could have failed for an unrelated reason, etc.). Callers must
   * report this as unconfirmed, never silently upgrade it.
   */
  async waitForCallback(nonce: string, timeoutMs: number): Promise<CallbackEvent | null> {
    const existing = this.events.get(nonce);
    if (existing && existing.length > 0) return existing[0]!;

    return new Promise<CallbackEvent | null>((resolve) => {
      const timer = setTimeout(() => {
        const list = this.waiters.get(nonce);
        if (list) {
          const idx = list.indexOf(onEvent);
          if (idx >= 0) list.splice(idx, 1);
          if (list.length === 0) this.waiters.delete(nonce);
        }
        resolve(null);
      }, timeoutMs);

      const onEvent = (event: CallbackEvent): void => {
        clearTimeout(timer);
        resolve(event);
      };

      const list = this.waiters.get(nonce) ?? [];
      list.push(onEvent);
      this.waiters.set(nonce, list);
    });
  }
}
