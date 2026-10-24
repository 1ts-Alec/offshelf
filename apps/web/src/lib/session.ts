// An unlocked shelf in this tab: the verified tree (held in the wasm core),
// kept live by the revision event stream, plus reads and commits.
//
// Freshness follows the spec: the tree is either live (stream connected) or
// verified (head checked after a reconnect or when the tab comes back). If
// the Pi can't be reached the UI says the listing may be out of date.

import { Shelf, type Upload } from "../wasm/oshelf_web.js";
import { Api, ApiError, Offline, json } from "./api";
import * as store from "./store";
import { mimeOf } from "./format";

export type Status = "live" | "connecting" | "offline";

export interface NodeView {
  id: string;
  parent: string;
  name: string;
  kind: "file" | "dir" | "symlink";
  size: number;
  mtime_ms: number;
  chunks: number;
  total: number;
}

export interface Crumb {
  id: string;
  name: string;
}

/** The Pi offered an older or different history than this browser verified. */
export class TamperError extends Error {}

const READ_BATCH = 16;
const COMMIT_RETRIES = 8;
const PARALLEL_UPLOADS = 4;
const CHUNK = 1 << 20;

export interface UploadProgress {
  files: number;
  done: number;
  bytes: number;
  total: number;
  failed: { name: string; error: string }[];
}

export class Session {
  /** Bumped on every tree change; views re-read the tree when it moves. */
  version = 0;
  status: Status = "connecting";
  lastVerified = 0;
  private listeners = new Set<() => void>();
  private queue: Promise<unknown> = Promise.resolve();
  private stream?: AbortController;
  private stopped = false;

  private constructor(
    readonly api: Api,
    readonly shelf: Shelf,
    readonly device: store.Device,
  ) {}

  /** Loads the snapshot and log and verifies the head. */
  static async open(
    api: Api,
    device: store.Device,
    masterKey: Uint8Array,
    vault: Uint8Array,
    onProgress?: (loaded: number, total: number) => void,
  ): Promise<Session> {
    const shelf = new Shelf(masterKey, vault, device.id, device.name);
    const s = new Session(api, shelf, device);
    await s.loadSnapshot(onProgress);
    await s.catchUp();
    return s;
  }

  subscribe(fn: () => void): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  private changed() {
    this.version++;
    this.listeners.forEach((f) => f());
  }

  private setStatus(s: Status) {
    if (s === "live") this.lastVerified = Date.now();
    if (s !== this.status) {
      this.status = s;
      this.listeners.forEach((f) => f());
    }
  }

  /** Runs `fn` with nothing else touching the tree. */
  private exclusive<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async loadSnapshot(onProgress?: (loaded: number, total: number) => void) {
    const r = await this.api.call("GET", "/v1/manifest/snapshot", { allow: [404] });
    if (r.status === 404) return;
    const revision = Number(r.headers.get("x-oshelf-revision"));
    const object = r.headers.get("x-oshelf-object") ?? "";
    const count = this.shelf.open_snapshot_header(revision, r.body);
    const parts: Uint8Array[] = [];
    for (let first = 0; first < count; first += READ_BATCH) {
      const last = Math.min(first + READ_BATCH, count) - 1;
      parts.push(await this.api.frames(object, first, last));
      onProgress?.(last + 1, count);
    }
    this.shelf.load_snapshot(concat(parts));
  }

  /** Applies every entry after our position, then checks the Pi's head. */
  private async catchUpLocked() {
    for (;;) {
      const r = await this.api.call("GET", `/v1/manifest/log?since=${this.shelf.revision()}`, { allow: [410] });
      if (r.status === 410) {
        // Compacted past us: start over from the latest snapshot.
        this.shelf.reset();
        await this.loadSnapshot();
        continue;
      }
      if (this.shelf.apply_log(r.body) === 0) break;
      this.changed();
    }
    const head = json<{ revision: number; hash: string }>(await this.api.call("GET", "/v1/manifest/head"));
    if (!this.shelf.matches_head(head.revision, head.hash)) {
      throw new TamperError("Your Pi's history doesn't match what it sent. Stopped to be safe.");
    }
    await this.advanceSeen();
    this.lastVerified = Date.now();
  }

  catchUp(): Promise<void> {
    return this.exclusive(() => this.catchUpLocked());
  }

  private async advanceSeen() {
    const revision = this.shelf.revision();
    const hash = this.shelf.head_hash();
    const seen = await store.loadSeen();
    if (seen && revision < seen.revision) {
      throw new TamperError(
        `Your Pi went back in time (revision ${revision}, this browser saw ${seen.revision}). Stopped to be safe.`,
      );
    }
    if (seen && revision === seen.revision && seen.hash && seen.hash !== hash) {
      throw new TamperError("Your Pi changed history this browser already verified. Stopped to be safe.");
    }
    await store.saveSeen({ revision, hash });
  }

  // ---- live updates --------------------------------------------------------

  /** Keeps the tree live from the event stream until `stop()`. */
  start(onFatal: (e: Error) => void) {
    const loop = async () => {
      let delay = 1000;
      while (!this.stopped) {
        this.stream = new AbortController();
        try {
          const res = await this.api.events(this.stream.signal);
          delay = 1000;
          await this.readEvents(res);
        } catch (e) {
          if (this.stopped) return;
          if (e instanceof TamperError) return onFatal(e);
          this.setStatus(e instanceof Offline ? "offline" : "connecting");
        }
        if (this.stopped) return;
        if (this.status === "live") this.setStatus("connecting");
        await sleep(delay);
        delay = Math.min(delay * 2, 30_000);
      }
    };
    void loop();
    document.addEventListener("visibilitychange", this.onVisible);
  }

  stop() {
    this.stopped = true;
    this.stream?.abort();
    document.removeEventListener("visibilitychange", this.onVisible);
  }

  /** Coming back to the tab: one cheap round trip to re-verify. */
  private onVisible = () => {
    if (document.visibilityState !== "visible" || this.stopped) return;
    this.verify().catch(() => this.setStatus("offline"));
  };

  /** Checks the head and fetches whatever is missing. */
  async verify() {
    await this.exclusive(async () => {
      const head = json(await this.api.call("GET", "/v1/manifest/head"));
      if (!this.shelf.matches_head(head.revision, head.hash)) await this.catchUpLocked();
    });
    if (this.status !== "live") this.setStatus(this.status === "offline" ? "connecting" : this.status);
  }

  private async readEvents(res: Response) {
    const reader = res.body!.pipeThrough(new TextDecoderStream()).getReader();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return;
      buf += value;
      let cut: number;
      while ((cut = buf.indexOf("\n\n")) >= 0) {
        const block = buf.slice(0, cut);
        buf = buf.slice(cut + 2);
        let event = "message";
        let data = "";
        for (const line of block.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) data += line.slice(5).trim();
        }
        if (event !== "revision" || !data) continue;
        const ev = JSON.parse(data) as { revision: number; hash: string };
        // The first event is the current head: this is the revision check
        // on (re)connect. Later ones announce new entries.
        await this.exclusive(async () => {
          if (!this.shelf.matches_head(ev.revision, ev.hash)) await this.catchUpLocked();
        });
        this.setStatus("live");
      }
    }
  }

  // ---- reading ---------------------------------------------------------------

  list(dir: string): NodeView[] {
    return this.shelf.list(dir);
  }

  node(id: string): NodeView | null {
    return this.shelf.node(id);
  }

  crumbs(id: string): Crumb[] {
    return this.shelf.crumbs(id);
  }

  /** Decrypts a whole file, verifying every chunk against the manifest. */
  async readFile(id: string, onProgress?: (bytes: number) => void, signal?: AbortSignal): Promise<Blob> {
    const n = this.shelf.node(id) as NodeView;
    const object = this.shelf.object_of(id);
    const parts: BlobPart[] = [];
    let bytes = 0;
    for (let first = 0; first < n.chunks; first += READ_BATCH) {
      const last = Math.min(first + READ_BATCH, n.chunks) - 1;
      const frames = await this.api.frames(object, first, last, signal);
      const pt = this.shelf.open_frames(id, first, frames);
      bytes += pt.length;
      parts.push(pt as BlobPart);
      onProgress?.(bytes);
    }
    return new Blob(parts, { type: mimeOf(n.name) });
  }

  /** Decrypts bytes `[start, end)` of a file. */
  async readRange(id: string, start: number, end: number, signal?: AbortSignal): Promise<Uint8Array> {
    const span = this.shelf.span(id, start, end);
    if (!span) return new Uint8Array(0);
    const object = this.shelf.object_of(id);
    const parts: Uint8Array[] = [];
    for (let first = span.first; first <= span.last; first += READ_BATCH) {
      const last = Math.min(first + READ_BATCH - 1, span.last);
      parts.push(this.shelf.open_frames(id, first, await this.api.frames(object, first, last, signal)));
    }
    return concat(parts).subarray(span.skip, span.skip + span.len);
  }

  // ---- writing ---------------------------------------------------------------

  /**
   * Commits whatever `stage` builds against the newest head. A lost race
   * fetches the entries we missed and stages again on the fresh tree.
   * Returns the node the commit was about, if any.
   */
  private commit(stage: () => Uint8Array | undefined): Promise<string | undefined> {
    return this.exclusive(async () => {
      for (let i = 0; i < COMMIT_RETRIES; i++) {
        const sealed = stage();
        if (!sealed) return undefined;
        const subject = this.shelf.staged_subject() ?? undefined;
        const r = await this.api.call("POST", "/v1/manifest/log", {
          body: sealed,
          headers: { "if-match": String(this.shelf.base_revision()) },
          allow: [409],
        });
        if (r.status === 409) {
          await this.catchUpLocked();
          continue;
        }
        const head = json<{ revision: number; hash: string }>(r);
        const drops: string[] = this.shelf.confirm(head.revision, head.hash);
        await this.advanceSeen();
        this.changed();
        // Best effort: an object left behind only costs space.
        for (const o of drops) this.api.call("DELETE", `/v1/objects/${o}`).catch(() => undefined);
        return subject;
      }
      throw new Error("The shelf kept changing underneath. Try again.");
    });
  }

  mkdir(parent: string, name: string) {
    return this.commit(() => this.shelf.stage_mkdir(parent, name));
  }

  move(id: string, parent: string, name: string) {
    return this.commit(() => this.shelf.stage_move(id, parent, name));
  }

  rename(id: string, name: string) {
    const n = this.node(id);
    if (!n) throw new Error("That item is no longer on the shelf.");
    return this.move(id, n.parent === ZERO ? "" : n.parent, name);
  }

  remove(ids: string[]) {
    return this.commit(() => this.shelf.stage_delete(ids));
  }

  /**
   * Seals and uploads files into `parent`, one at a time, several chunks in
   * flight. Failures are collected so the rest still go up.
   */
  async upload(parent: string, files: File[], onProgress: (p: UploadProgress) => void): Promise<UploadProgress> {
    const p: UploadProgress = {
      files: files.length,
      done: 0,
      bytes: 0,
      total: files.reduce((a, f) => a + f.size, 0),
      failed: [],
    };
    onProgress({ ...p });
    for (const f of files) {
      const before = p.bytes;
      try {
        await this.uploadOne(parent, f, (n) => {
          p.bytes = before + n;
          onProgress({ ...p });
        });
        p.done++;
      } catch (e) {
        p.failed.push({ name: f.name, error: (e as Error).message });
        p.bytes = before + f.size;
      }
      onProgress({ ...p, failed: [...p.failed] });
    }
    return p;
  }

  private async uploadOne(parent: string, file: File, onBytes: (n: number) => void) {
    const up: Upload = this.shelf.begin_upload(parent, file.name);
    try {
      const inflight = new Set<Promise<void>>();
      let sent = 0;
      let failure: unknown;
      for (let off = 0; off < file.size; off += CHUNK) {
        const pt = new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer());
        const stored = up.seal_next(pt);
        const id = up.last_chunk_id()!;
        const job = this.api
          .call("PUT", `/v1/chunks/${id}`, { body: stored })
          .then(() => {
            sent += pt.length;
            onBytes(sent);
          })
          .catch((e) => {
            failure ??= e;
          })
          .finally(() => inflight.delete(job));
        inflight.add(job);
        if (inflight.size >= PARALLEL_UPLOADS) await Promise.race(inflight);
        if (failure) throw failure;
      }
      await Promise.all(inflight);
      if (failure) throw failure;
      await this.api.call("POST", "/v1/objects", {
        body: up.object_json(),
        headers: { "content-type": "application/json" },
      });
      await this.commit(() => this.shelf.stage_upload(up, parent, file.name, file.lastModified || Date.now()));
    } finally {
      up.free();
    }
  }
}

export const ZERO = "0".repeat(32);

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export { ApiError, Offline };
