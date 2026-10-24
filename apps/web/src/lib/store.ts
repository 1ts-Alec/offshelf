// Local state in IndexedDB: this browser's device identity, the highest
// verified revision, and (only if asked) the master key for 7 days.
//
// Secrets are sealed under a local wrap key. In a secure context (HTTPS or
// localhost) that is a non-extractable WebCrypto key page scripts can use but
// never read. Over plain LAN HTTP WebCrypto is unavailable, so the wrap key is
// stored as bytes and secrets are sealed with XChaCha20 in the wasm core.

import { open_local, random_bytes, seal_local } from "../wasm/oshelf_web.js";

const DB = "offshelf";
const STORE = "kv";

let dbp: Promise<IDBDatabase> | undefined;

function db(): Promise<IDBDatabase> {
  dbp ??= new Promise((resolve, reject) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(STORE);
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  return dbp;
}

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

export async function get<T>(key: string): Promise<T | undefined> {
  const d = await db();
  return req(d.transaction(STORE).objectStore(STORE).get(key)) as Promise<T | undefined>;
}

export async function put(key: string, value: unknown): Promise<void> {
  const d = await db();
  await req(d.transaction(STORE, "readwrite").objectStore(STORE).put(value, key));
}

export async function del(key: string): Promise<void> {
  const d = await db();
  await req(d.transaction(STORE, "readwrite").objectStore(STORE).delete(key));
}

type WrapKey = CryptoKey | Uint8Array;

let wrapKeyP: Promise<WrapKey> | undefined;

function subtle(): SubtleCrypto | undefined {
  return globalThis.isSecureContext ? globalThis.crypto?.subtle : undefined;
}

// CryptoKey isn't even defined outside a secure context.
const isCryptoKey = (k: unknown): k is CryptoKey => typeof CryptoKey !== "undefined" && k instanceof CryptoKey;

async function wrapKey(): Promise<WrapKey> {
  wrapKeyP ??= (async () => {
    const existing = await get<WrapKey>("wrap-key");
    const s = subtle();
    if (isCryptoKey(existing) && s) return existing;
    if (existing instanceof Uint8Array && !s) return existing;
    if (existing) {
      // The page moved between HTTP and HTTPS; what the old key sealed is
      // unreadable now, so start this browser over.
      await clearAll();
    }
    const fresh: WrapKey = s
      ? await s.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"])
      : random_bytes(32);
    await put("wrap-key", fresh);
    return fresh;
  })();
  return wrapKeyP;
}

export async function seal(label: string, data: Uint8Array): Promise<Uint8Array> {
  const k = await wrapKey();
  if (k instanceof Uint8Array) return seal_local(k, label, data);
  const iv = random_bytes(12);
  const ct = await subtle()!.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource, additionalData: new TextEncoder().encode(label) },
    k,
    data as BufferSource,
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), 12);
  return out;
}

export async function unseal(label: string, sealed: Uint8Array): Promise<Uint8Array> {
  const k = await wrapKey();
  if (k instanceof Uint8Array) return open_local(k, label, sealed);
  const pt = await subtle()!.decrypt(
    { name: "AES-GCM", iv: sealed.slice(0, 12), additionalData: new TextEncoder().encode(label) },
    k,
    sealed.slice(12) as BufferSource,
  );
  return new Uint8Array(pt);
}

export async function clearAll(): Promise<void> {
  const d = await db();
  await req(d.transaction(STORE, "readwrite").objectStore(STORE).clear());
  wrapKeyP = undefined;
}

// ---- typed records ---------------------------------------------------------

export interface Device {
  id: string;
  name: string;
  serverPub: string;
  /** The Ed25519 seed, sealed under the wrap key. */
  seed: Uint8Array;
}

export interface Seen {
  revision: number;
  hash: string;
}

export interface Stay {
  mk: Uint8Array;
  expires: number;
}

export const loadDevice = () => get<Device>("device");
export const saveDevice = (d: Device) => put("device", d);
export const loadSeen = () => get<Seen>("seen");
export const saveSeen = (s: Seen) => put("seen", s);
export const loadStay = () => get<Stay>("stay");
export const saveStay = (s: Stay) => put("stay", s);
export const forgetStay = () => del("stay");
