// Argon2id (256 MiB) blocks for seconds, so unlocking runs here, off the
// page's thread. The worker is thrown away after each job to free its memory.

import init, { change_passphrase, unlock_passphrase, unlock_recovery } from "../wasm/oshelf_web.js";

export type Job =
  | { op: "passphrase"; vault: Uint8Array; passphrase: string }
  | { op: "recovery"; vault: Uint8Array; words: string }
  | { op: "rewrap"; vault: Uint8Array; mk: Uint8Array; passphrase: string };

self.onmessage = async (e: MessageEvent<Job>) => {
  try {
    await init();
    const j = e.data;
    const out =
      j.op === "passphrase"
        ? unlock_passphrase(j.vault, j.passphrase)
        : j.op === "recovery"
          ? unlock_recovery(j.vault, j.words)
          : change_passphrase(j.vault, j.mk, j.passphrase);
    postMessage({ ok: out });
  } catch (err) {
    postMessage({ error: String((err as Error).message ?? err) });
  }
};
