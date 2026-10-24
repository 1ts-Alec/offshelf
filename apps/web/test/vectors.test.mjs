// The WebAssembly build against spec/vectors, as the spec requires of every
// implementation. Run `npm run wasm` first.

import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as w from "../src/wasm/oshelf_web.js";

w.initSync({ module: readFileSync(new URL("../src/wasm/oshelf_web_bg.wasm", import.meta.url)) });

const vec = (name) => JSON.parse(readFileSync(new URL(`../../../spec/vectors/${name}`, import.meta.url), "utf8"));
const unhex = (h) => Uint8Array.from(h.match(/../g) ?? [], (b) => parseInt(b, 16));
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const plaintext = (n) => Uint8Array.from({ length: n }, (_, i) => i % 251);

test("chunk: seal and open", () => {
  const v = vec("chunk.json");
  const key = unhex(v.key);
  const fileId = unhex(v.file_id);
  for (const s of v.seal) {
    const pt = plaintext(s.plaintext_len);
    const stored = w.vector_seal_chunk(key, fileId, s.chunk_index, pt, unhex(v.nonce));
    assert.equal(stored.length, s.stored_len);
    assert.equal(w.vector_chunk_id(stored), s.chunk_id);
    if (s.stored_hex) assert.equal(hex(stored), s.stored_hex);
    if (s.stored_prefix_hex) assert.equal(hex(stored.subarray(0, s.stored_prefix_hex.length / 2)), s.stored_prefix_hex);
    if (s.tag_hex) assert.equal(hex(stored.subarray(stored.length - 16)), s.tag_hex);
    assert.deepEqual(w.vector_open_chunk(key, fileId, s.chunk_index, stored), pt);
  }
});

test("chunk: rejects tampering", () => {
  const v = vec("chunk.json").reject;
  for (const c of v.cases) {
    assert.throws(
      () => w.vector_open_chunk(unhex(v.key), unhex(c.file_id), c.chunk_index, unhex(c.stored_hex)),
      (e) => e.message.startsWith(c.error.replace(/\(.*$/, "")),
      c.name,
    );
  }
});

test("range", () => {
  const v = vec("range.json");
  for (const c of v.cases) {
    assert.deepEqual(w.vector_span(c.start, c.end, c.file_size, v.chunk_size), c.span, JSON.stringify(c));
  }
});

test("auth: request, response and pairing", () => {
  const v = vec("auth.json");
  const r = v.request;
  assert.equal(w.device_pubkey(unhex(r.device_seed)), r.device_pubkey);
  assert.equal(w.vector_sign_request(unhex(r.device_seed), r.method, r.path_and_query, r.ts_ms, unhex(r.body_hex)), r.sig);
  const p = v.pairing;
  const signer = new w.Signer(unhex(r.device_seed), p.device_id, v.response.server_pubkey);
  const sigB64 = Buffer.from(unhex(v.response.sig)).toString("base64");
  assert.ok(signer.verify(unhex(v.response.request_sig), v.response.status, unhex(v.response.body_hex), sigB64));
  assert.ok(!signer.verify(unhex(v.response.request_sig), v.response.status + 1, unhex(v.response.body_hex), sigB64));
  assert.equal(w.pairing_client_mac(p.code, p.device_pubkey, p.client_nonce), p.client_mac);
  assert.ok(w.pairing_server_ok(p.code, p.server_pubkey, p.device_id, p.client_nonce, p.server_mac));
  assert.ok(!w.pairing_server_ok("0000-0000", p.server_pubkey, p.device_id, p.client_nonce, p.server_mac));
});

test("vault: passphrase, recovery words, tampering", () => {
  const v = vec("vault.json");
  const header = unhex(v.header_hex);
  assert.equal(hex(w.unlock_passphrase(header, v.passphrase)), v.master_key);
  assert.equal(hex(w.unlock_recovery(header, v.recovery_words)), v.master_key);
  assert.throws(() => w.unlock_passphrase(header, "wrong"));
  assert.throws(() => w.unlock_passphrase(unhex(v.tampered_header_hex), v.passphrase));
});

test("manifest: chain, skipped and replayed entries", () => {
  const v = vec("manifest.json");
  const km = unhex(v.manifest_key);
  let rev = 0;
  let hash = "0".repeat(64);
  for (const e of v.entries) {
    assert.equal(e.prev_hash, hash);
    hash = w.vector_open_entry(km, rev, hash, unhex(e.sealed_hex));
    rev++;
    assert.equal(hash, e.entry_hash);
  }
  for (const f of v.must_fail) {
    const before = f.chain_after === 0 ? "0".repeat(64) : v.entries[f.chain_after - 1].entry_hash;
    assert.throws(() => w.vector_open_entry(km, f.chain_after, before, unhex(v.entries[f.open - 1].sealed_hex)), f.name);
  }
});
