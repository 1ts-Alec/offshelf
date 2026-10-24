// Talks to oshelfd on the page's own origin. Every request is signed with
// this browser's device key, and every buffered answer must carry the Pi's
// signature over it, checked against the key pinned at pairing.

import { Signer } from "../wasm/oshelf_web.js";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly detail: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

/** The Pi could not be reached at all. */
export class Offline extends Error {}

export interface Reply {
  status: number;
  headers: Headers;
  body: Uint8Array;
}

const EMPTY = new Uint8Array(0);

export function json<T = any>(r: Reply): T {
  return JSON.parse(new TextDecoder().decode(r.body));
}

function errorOf(r: Reply): ApiError {
  let msg = `The Pi answered ${r.status}`;
  let detail: Record<string, unknown> = {};
  try {
    const v = json(r);
    if (typeof v.error === "string") msg = v.error;
    detail = v;
  } catch {
    /* not JSON */
  }
  return new ApiError(r.status, msg, detail);
}

export interface CallOptions {
  body?: Uint8Array | string;
  headers?: Record<string, string>;
  /** Statuses that come back as a reply instead of throwing. */
  allow?: number[];
  signal?: AbortSignal;
}

export class Api {
  private lastTs = 0;
  /** Server clock minus ours, learned when the Pi says we're off. */
  private skew = 0;

  constructor(private signer: Signer) {}

  private ts(): number {
    // Unique and increasing, so two identical requests never share a signature.
    this.lastTs = Math.max(Date.now() + this.skew, this.lastTs + 1);
    return this.lastTs;
  }

  private async send(method: string, path: string, o: CallOptions): Promise<{ res: Response; sig: Uint8Array }> {
    const body = typeof o.body === "string" ? new TextEncoder().encode(o.body) : (o.body ?? EMPTY);
    for (let attempt = 0; ; attempt++) {
      const signed = this.signer.sign(method, path, this.ts(), body);
      const sig = signed.sig;
      const authorization = signed.authorization;
      signed.free();
      let res: Response;
      try {
        res = await fetch(path, {
          method,
          headers: { ...o.headers, authorization },
          body: body.length || method === "PUT" || method === "POST" ? (body as BufferSource) : undefined,
          signal: o.signal,
          cache: "no-store",
        });
      } catch (e) {
        if ((e as Error).name === "AbortError") throw e;
        throw new Offline("Can't reach your shelf.");
      }
      if (res.status === 401 && attempt === 0) {
        // A browser clock more than a minute off fails every request; line
        // up with the Pi's Date header once and try again.
        const date = Date.parse(res.headers.get("date") ?? "");
        if (!Number.isNaN(date) && Math.abs(date - (Date.now() + this.skew)) > 30_000) {
          this.skew = date - Date.now();
          continue;
        }
      }
      return { res, sig };
    }
  }

  /** A buffered call whose answer must be signed by the Pi. */
  async call(method: string, path: string, o: CallOptions = {}): Promise<Reply> {
    const { res, sig } = await this.send(method, path, o);
    const body = new Uint8Array(await res.arrayBuffer());
    const r: Reply = { status: res.status, headers: res.headers, body };
    const header = res.headers.get("x-oshelf-sig");
    if (!header || !this.signer.verify(sig, res.status, body, header)) {
      // Unsigned errors can come from a proxy or tunnel in front of the Pi;
      // they carry nothing we act on beyond "it failed".
      if (res.ok) throw new ApiError(res.status, "The answer wasn't signed by your Pi.");
      throw errorOf(r);
    }
    if (res.ok || o.allow?.includes(res.status)) return r;
    throw errorOf(r);
  }

  /**
   * Ranged chunk reads aren't signed (every chunk is checked against its id
   * in the manifest instead), so this returns the raw framed body.
   */
  async frames(object: string, first: number, last: number, signal?: AbortSignal): Promise<Uint8Array> {
    const path = `/v1/objects/${object}/chunks?first=${first}&last=${last}`;
    const { res } = await this.send("GET", path, { signal });
    const body = new Uint8Array(await res.arrayBuffer());
    if (!res.ok) throw errorOf({ status: res.status, headers: res.headers, body });
    return body;
  }

  /** The revision event stream. Its events are checked against the hash chain. */
  async events(signal: AbortSignal): Promise<Response> {
    const { res } = await this.send("GET", "/v1/events", { signal, headers: { accept: "text/event-stream" } });
    if (!res.ok || !res.body) throw new ApiError(res.status, "Event stream refused");
    return res;
  }
}

/** Unsigned: pairing happens before this browser has a key the Pi knows. */
export async function pairRequest(body: unknown): Promise<any> {
  let res: Response;
  try {
    res = await fetch("/v1/pair", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Offline("Can't reach your shelf.");
  }
  const text = await res.text();
  let v: any = {};
  try {
    v = JSON.parse(text);
  } catch {
    /* empty */
  }
  if (!res.ok) throw new ApiError(res.status, v.error ?? `The Pi answered ${res.status}`);
  return v;
}
