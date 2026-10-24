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
