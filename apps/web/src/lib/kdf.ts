import type { Job } from "./kdf.worker";

/** Runs one key derivation job in a fresh worker. */
export function runKdf(job: Job): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const w = new Worker(new URL("./kdf.worker.ts", import.meta.url), { type: "module" });
    w.onmessage = (e) => {
      w.terminate();
      if (e.data.ok) resolve(e.data.ok);
      else reject(new Error(e.data.error));
    };
    w.onerror = (e) => {
      w.terminate();
      reject(new Error(e.message || "Unlocking failed"));
    };
    w.postMessage(job);
  });
}

/** A new shelf: the vault header to upload, the master key, the recovery words. */
export interface NewVault {
  header: Uint8Array;
  mk: Uint8Array;
  words: string;
}

export async function createVault(passphrase: string): Promise<NewVault> {
  const out = await runKdf({ op: "create", passphrase });
  const len = new DataView(out.buffer, out.byteOffset, 4).getUint32(0, true);
  return {
    header: out.slice(4, 4 + len),
    mk: out.slice(4 + len, 4 + len + 32),
    words: new TextDecoder().decode(out.slice(4 + len + 32)),
  };
}
